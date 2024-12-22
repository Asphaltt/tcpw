// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang tcpw ./bpf/tcpw.c -- -g -D__TARGET_ARCH_x86 -I./bpf/headers -Wall -Wno-address-of-packed-member
package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/Asphaltt/tcpw/internal/assert"
	"github.com/Asphaltt/tcpw/internal/tcpw"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sync/errgroup"
)

func main() {
	flags := tcpw.NewFlags()
	if len(flags.Args) == 0 {
		fmt.Println("Usage: tcpw <telnet|nc|ncat|socat|curl...>")
		os.Exit(1)
	}

	exitCode := 0
	defer func() { os.Exit(exitCode) }()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	assert.NoErr(rlimit.RemoveMemlock(), "Failed to remove memlock limit: %v")

	btfSpec, err := btf.LoadKernelSpec()
	assert.NoErr(err, "Failed to load kernel btf spec: %v")

	connectFuncs, acceptFuncs, err := tcpw.FindFuncs(btfSpec)
	assert.NoErr(err, "Failed to find connect/accept functions: %v")

	numCPU, err := ebpf.PossibleCPU()
	assert.NoErr(err, "Failed to get number of CPUs: %v")

	spec, err := loadTcpw()
	assert.NoErr(err, "Failed to load bpf spec: %v")

	spec.Maps["events"].MaxEntries = 4096 * uint32(numCPU)
	events, err := ebpf.NewMap(spec.Maps["events"])
	assert.NoErr(err, "Failed to create events map: %v")
	defer events.Close()

	ready, err := ebpf.NewMap(spec.Maps[".data.ready"])
	assert.NoErr(err, "Failed to create ready map: %v")
	defer ready.Close()

	pids, err := ebpf.NewMap(spec.Maps["tcpw_pids"])
	assert.NoErr(err, "Failed to create pids map: %v")
	defer pids.Close()

	var opts ebpf.CollectionOptions
	opts.MapReplacements = map[string]*ebpf.Map{
		"events":      events,
		".data.ready": ready,
		"tcpw_pids":   pids,
	}

	tracing, err := tcpw.TraceFuncs(ctx, spec, &opts, connectFuncs, acceptFuncs)
	assert.NoVerifierErr(err, "Failed to trace connect/accept functions: %v")
	defer tracing.Close()

	pid := os.Getpid()
	err = pids.Put(uint32(pid), uint32(pid))
	assert.NoErr(err, "Failed to put pid: %v")

	tp, err := tcpw.TraceFork(spec, &opts)
	assert.NoVerifierErr(err, "Failed to trace fork: %v")
	defer tp.Close()

	reader, err := ringbuf.NewReader(events)
	assert.NoErr(err, "Failed to create ringbuf reader: %v")
	defer reader.Close()

	err = ready.Put(uint32(0), uint32(1))
	assert.NoErr(err, "Failed to put ready: %v")
	defer ready.Put(uint32(0), uint32(0))

	errg, ctx := errgroup.WithContext(ctx)

	_, err = exec.LookPath(flags.Args[0])
	assert.NoErr(err, "Failed to find command: %v")

	cmd := tcpw.Process(ctx, flags.Args)
	errg.Go(func() error {
		err := cmd.Run()
		stop()
		return err
	})
	errg.Go(func() error {
		<-ctx.Done()
		if cmd.Process != nil {
			_ = cmd.Cancel()
		}
		return nil
	})

	errg.Go(func() error {
		<-ctx.Done()
		_ = reader.Close()
		return nil
	})
	errg.Go(func() error {
		return tcpw.Run(reader, flags)
	})

	_ = errg.Wait()

	exitCode = cmd.ProcessState.ExitCode()
}
