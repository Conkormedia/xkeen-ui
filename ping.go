package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	pingMu  sync.Mutex   // один временный xray за раз: памяти на роутере немного
	pingPID atomic.Int64 // pid временного xray — чтобы статус не путал его с рабочим
)

// pingKeys меряет реальную задержку через каждый сервер (HTTP через временный xray).
// Результат: id -> мс, либо nil (не ответил).
func pingKeys(keys []Key) map[string]*int {
	pingMu.Lock()
	defer pingMu.Unlock()
	res := map[string]*int{}
	for i := 0; i < len(keys); i += cfg.PingBatch {
		end := min(i+cfg.PingBatch, len(keys))
		for id, v := range pingBatch(keys[i:end]) {
			res[id] = v
		}
	}
	return res
}

func pingBatch(keys []Key) map[string]*int {
	res := map[string]*int{}
	const base = 21000
	var inbounds, outbounds, rules []any
	var idx []int
	for i, k := range keys {
		ob, err := parseVless(k.URL)
		res[k.ID] = nil
		if err != nil {
			continue
		}
		ob["tag"] = fmt.Sprintf("o%d", i)
		outbounds = append(outbounds, ob)
		inbounds = append(inbounds, map[string]any{"tag": fmt.Sprintf("i%d", i), "listen": "127.0.0.1",
			"port": base + i, "protocol": "socks", "settings": map[string]any{"udp": false}})
		rules = append(rules, map[string]any{"type": "field", "inboundTag": []string{fmt.Sprintf("i%d", i)},
			"outboundTag": fmt.Sprintf("o%d", i)})
		idx = append(idx, i)
	}
	if len(idx) == 0 {
		return res
	}
	conf := map[string]any{"log": map[string]any{"loglevel": "none"}, "inbounds": inbounds,
		"outbounds": append(outbounds, map[string]any{"tag": "direct", "protocol": "freedom"}),
		"routing":   map[string]any{"rules": rules}}
	dir, err := os.MkdirTemp(cfg.TmpDir, "xkui-ping-")
	if err != nil {
		return res
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "ping.json")
	b, _ := json.Marshal(conf)
	if os.WriteFile(path, b, 0o600) != nil {
		return res
	}
	cmd := exec.Command(cfg.Xray, "run", "-c", path)
	if err := cmd.Start(); err != nil {
		return res
	}
	pingPID.Store(int64(cmd.Process.Pid))
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		pingPID.Store(0)
	}()
	// ждём, пока поднимется последний вход (на MIPS + UPX старт занимает секунды)
	last := fmt.Sprintf("127.0.0.1:%d", base+idx[len(idx)-1])
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); {
		if c, err := net.DialTimeout("tcp", last, 300*time.Millisecond); err == nil {
			c.Close()
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.PingWorkers)
	for _, i := range idx {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			v := socksHTTPProbe(base+i, cfg.PingTimeout)
			mu.Lock()
			res[keys[i].ID] = v
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	return res
}

// socksHTTPProbe — HTTP GET через локальный SOCKS5, время до первого ответа сервера.
func socksHTTPProbe(port int, timeout time.Duration) *int {
	t0 := time.Now()
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), timeout)
	if err != nil {
		return nil
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	buf := make([]byte, 64)
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		return nil
	}
	if n, err := c.Read(buf[:2]); err != nil || n != 2 || buf[0] != 5 || buf[1] != 0 {
		return nil
	}
	host := cfg.PingHost
	req := append([]byte{5, 1, 0, 3, byte(len(host))}, host...)
	req = append(req, 0, 80)
	if _, err := c.Write(req); err != nil {
		return nil
	}
	if n, err := c.Read(buf[:10]); err != nil || n < 2 || buf[1] != 0 {
		return nil
	}
	if _, err := fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", cfg.PingPath, host); err != nil {
		return nil
	}
	n, err := c.Read(buf)
	if err != nil || !strings.HasPrefix(string(buf[:n]), "HTTP/") {
		return nil
	}
	ms := int(time.Since(t0).Milliseconds())
	return &ms
}
