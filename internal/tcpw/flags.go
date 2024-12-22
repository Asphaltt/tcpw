// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package tcpw

import (
	"os"
)

type TcpwFlags struct {
	UDP        bool
	UnixSocket bool

	Args []string
}

func NewFlags() *TcpwFlags {
	var f TcpwFlags

	args := os.Args[1:]
	for i, arg := range args {
		switch arg {
		case "--udp", "-U":
			f.UDP = true
		case "--unix", "-X":
			f.UnixSocket = true
		case "--help", "-h":
			PrintUsage()
		default:
			f.Args = args[i:]
			return &f
		}
	}

	return &f
}

func PrintUsage() {
	println("Usage: tcpw [options] <command args...>")
	println("Options:")
	println("  --udp, -U       Trace UDP sockets")
	println("  --unix, -X      Trace Unix domain sockets")
	println("  --help, -h      Print this help message")
	os.Exit(0)
}
