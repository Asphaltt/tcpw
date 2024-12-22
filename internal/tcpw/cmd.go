// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package tcpw

import (
	"context"
	"os"
	"os/exec"
)

func Process(ctx context.Context, args []string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd
}
