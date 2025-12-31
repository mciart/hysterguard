// Package tunnel - 钩子脚本执行器
package tunnel

import (
	"log/slog"
	"os/exec"
	"strings"
)

// ExecuteHooks 执行钩子脚本列表
func ExecuteHooks(hooks []string, logger *slog.Logger, hookType string) {
	if len(hooks) == 0 {
		return
	}

	logger.Info("Executing hooks", "type", hookType, "count", len(hooks))

	for i, cmd := range hooks {
		if cmd == "" {
			continue
		}

		logger.Debug("Executing hook", "type", hookType, "index", i+1, "command", cmd)

		// 使用 shell 执行命令，以支持管道和复杂命令
		if err := executeShellCommand(cmd); err != nil {
			logger.Warn("Hook execution failed",
				"type", hookType,
				"index", i+1,
				"command", cmd,
				"error", err,
			)
		} else {
			logger.Debug("Hook executed successfully", "type", hookType, "index", i+1)
		}
	}

	logger.Info("Hooks executed", "type", hookType)
}

// executeShellCommand 使用 shell 执行命令
func executeShellCommand(command string) error {
	// 去除首尾空白
	command = strings.TrimSpace(command)
	if command == "" {
		return nil
	}

	// 使用 sh -c 执行，支持管道、重定向等
	cmd := exec.Command("sh", "-c", command)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return &HookError{
			Command: command,
			Output:  string(output),
			Err:     err,
		}
	}
	return nil
}

// HookError 钩子执行错误
type HookError struct {
	Command string
	Output  string
	Err     error
}

func (e *HookError) Error() string {
	if e.Output != "" {
		return e.Err.Error() + ": " + e.Output
	}
	return e.Err.Error()
}
