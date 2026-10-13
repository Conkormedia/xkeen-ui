//go:build linux

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// childDiesWithParent: временный xray умрёт вместе с панелью (иначе он остаётся сиротой
// и держит ~40 МБ памяти — следующий запуск xray на роутере падает с Segmentation fault).
func childDiesWithParent(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}

// killStalePingXray — добить временные xray замера, оставшиеся от прошлых запусков панели.
func killStalePingXray() {
	dirs, _ := filepath.Glob("/proc/[0-9]*")
	for _, d := range dirs {
		b, err := os.ReadFile(filepath.Join(d, "cmdline"))
		if err != nil || !strings.Contains(string(b), "xkui-ping-") {
			continue
		}
		if pid, err := strconv.Atoi(filepath.Base(d)); err == nil && pid != os.Getpid() {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	}
	old, _ := filepath.Glob(filepath.Join(cfg.TmpDir, "xkui-ping-*"))
	for _, o := range old {
		_ = os.RemoveAll(o)
	}
}
