//go:build !linux

package main

import "os/exec"

func childDiesWithParent(cmd *exec.Cmd) {}

func killStalePingXray() {}
