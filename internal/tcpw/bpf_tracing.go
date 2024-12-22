// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package tcpw

import (
	"context"
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sync/errgroup"
)

const (
	progNameFexitConnect = "fexit_connect"
	progNameFexitAccept  = "fexit_accept"
	progNameTpFork       = "tp_sched_process_fork"
)

type BpfTracing struct {
	llock sync.Mutex
	links []link.Link
}

func (t *BpfTracing) Close() {
	t.llock.Lock()
	defer t.llock.Unlock()

	var errg errgroup.Group

	for _, l := range t.links {
		l := l
		errg.Go(func() error {
			_ = l.Close()
			return nil
		})
	}

	_ = errg.Wait()
}

func (t *BpfTracing) traceFunc(spec *ebpf.CollectionSpec, opts *ebpf.CollectionOptions, fnName, progName, otherProgName string) error {
	spec = spec.Copy()
	delete(spec.Programs, otherProgName)

	spec.Programs[progName].AttachTo = fnName

	coll, err := ebpf.NewCollectionWithOptions(spec, *opts)
	if err != nil {
		return fmt.Errorf("failed to create collection for target connect func %s: %w", fnName, err)
	}
	defer coll.Close()

	l, err := link.AttachTracing(link.TracingOptions{
		Program:    coll.Programs[progName],
		AttachType: ebpf.AttachTraceFExit,
	})
	if err != nil {
		return fmt.Errorf("failed to attach tracing to connect func %s: %w", fnName, err)
	}

	t.llock.Lock()
	t.links = append(t.links, l)
	t.llock.Unlock()

	return nil
}

func TraceFuncs(ctx context.Context, spec *ebpf.CollectionSpec, opts *ebpf.CollectionOptions, connectFuncs, acceptFuncs []string) (*BpfTracing, error) {
	var t BpfTracing

	spec = spec.Copy()
	delete(spec.Programs, progNameTpFork)

	errg, ctx := errgroup.WithContext(ctx)

	for _, fnName := range connectFuncs {
		fnName := fnName
		errg.Go(func() error {
			return t.traceFunc(spec, opts, fnName, progNameFexitConnect, progNameFexitAccept)
		})
	}

	for _, fnName := range acceptFuncs {
		fnName := fnName
		errg.Go(func() error {
			return t.traceFunc(spec, opts, fnName, progNameFexitAccept, progNameFexitConnect)
		})
	}

	return &t, errg.Wait()
}

func TraceFork(spec *ebpf.CollectionSpec, opts *ebpf.CollectionOptions) (link.Link, error) {
	spec = spec.Copy()
	delete(spec.Programs, progNameFexitConnect)
	delete(spec.Programs, progNameFexitAccept)

	coll, err := ebpf.NewCollectionWithOptions(spec, *opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create collection for tracepoint fork: %w", err)
	}
	defer coll.Close()

	tp, err := link.Tracepoint("sched", "sched_process_fork", coll.Programs[progNameTpFork], nil)
	if err != nil {
		return nil, fmt.Errorf("failed to attach tracepoint fork: %w", err)
	}

	return tp, nil
}
