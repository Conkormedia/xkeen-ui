//go:build !linux

package main

import "os/exec"

func childDiesWithParent(cmd *exec.Cmd) {}

func killStalePingXray() {}

func memAvailableKB() int { return -1 }
