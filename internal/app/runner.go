package app

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) (string, error)
}

type OSCommandRunner struct {
	Timeout time.Duration
}

type CommandError struct {
	Name   string
	Args   []string
	Output string
	Err    error
}

func (e *CommandError) Error() string {
	return fmt.Sprintf("%s 执行失败: %v; %s", e.Name, e.Err, sanitizeDetail(e.Output))
}

func (e *CommandError) Unwrap() error { return e.Err }

func (r OSCommandRunner) Run(parent context.Context, name string, args ...string) (string, error) {
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	text := strings.ToValidUTF8(string(out), "?")
	if err != nil {
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		return text, &CommandError{Name: name, Args: append([]string(nil), args...), Output: text, Err: err}
	}
	return text, nil
}
