package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

var (
	// xrayMu — все запуски xray из панели строго по одному. Сжатый UPX xray при старте
	// распаковывается в память (~35–40 МБ), и на роутере с 256 МБ третья копия рядом с рабочей
	// и временной падает с Segmentation fault: проверка конфига «проваливается», а перезапуск
	// XKeen может не поднять рабочий xray.
	xrayMu  sync.Mutex
	pingPID atomic.Int64 // pid временного xray — чтобы статус не путал его с рабочим
)

// pingErr — почему последний замер не состоялся (не хватило памяти, xray не стартовал).
var pingErr string

// pingKeys меряет реальную задержку через каждый сервер (HTTP через временный xray).
// Результат: id -> мс, либо nil (не ответил).
func pingKeys(keys []Key) map[string]*int {
	xrayMu.Lock()
	defer xrayMu.Unlock()
	pingErr = ""
	res := map[string]*int{}
	if avail := memAvailableKB(); avail >= 0 && avail < 45000 {
		pingErr = fmt.Sprintf("мало свободной памяти на роутере (%d МБ, нужно ~45): замер отложен", avail/1024)
		return res
	}
	for i := 0; i < len(keys); i += cfg.PingBatch {
		end := min(i+cfg.PingBatch, len(keys))
		for id, v := range pingBatch(keys[i:end]) {
			res[id] = v
		}
		if pingErr != "" { // не мучаем роутер остальными порциями
			break
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
	childDiesWithParent(cmd)
	if err := cmd.Start(); err != nil {
		return res
	}
	pingPID.Store(int64(cmd.Process.Pid))
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }()
	defer func() {
		_ = cmd.Process.Kill()
		<-exited
		pingPID.Store(0)
	}()
	// ждём, пока поднимется последний вход (на MIPS + UPX старт занимает секунды)
	last := fmt.Sprintf("127.0.0.1:%d", base+idx[len(idx)-1])
	up := false
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline) && !up; {
		select {
		case <-exited: // упал при старте — обычно нехватка памяти (распаковка UPX)
			pingErr = "xray для замера не запустился — вероятно, мало свободной памяти на роутере"
			return res
		default:
		}
		if c, err := net.DialTimeout("tcp", last, 300*time.Millisecond); err == nil {
			c.Close()
			up = true
		} else {
			time.Sleep(300 * time.Millisecond)
		}
	}
	if !up {
		pingErr = "xray для замера не успел запуститься за 20 с"
		return res
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

// socksHTTPProbe — задержка канала через сервер: два HTTP-запроса по одному соединению,
// результат — время второго. Первый включает шифрованное рукопожатие (на слабом MIPS +~90 мс
// и сильно растёт, когда замеры идут параллельно), второй — чистая задержка, которую видно в работе.
// Не прошёл даже первый запрос — сервер мёртв (nil).
func socksHTTPProbe(port int, timeout time.Duration) *int {
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), timeout)
	if err != nil {
		return nil
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * timeout))
	buf := make([]byte, 512)
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		return nil
	}
	if n, err := io.ReadFull(c, buf[:2]); err != nil || n != 2 || buf[0] != 5 || buf[1] != 0 {
		return nil
	}
	host := cfg.PingHost
	req := append([]byte{5, 1, 0, 3, byte(len(host))}, host...)
	req = append(req, 0, 80)
	if _, err := c.Write(req); err != nil {
		return nil
	}
	if _, err := io.ReadFull(c, buf[:10]); err != nil || buf[1] != 0 {
		return nil
	}
	get := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", cfg.PingPath, host)
	var ms [2]int
	for i := range 2 {
		t0 := time.Now()
		if _, err := io.WriteString(c, get); err != nil {
			break
		}
		if !readHTTPHead(c, buf) {
			break
		}
		ms[i] = int(time.Since(t0).Milliseconds())
		if ms[i] == 0 {
			ms[i] = 1
		}
	}
	switch {
	case ms[1] > 0:
		return &ms[1]
	case ms[0] > 0: // сервер закрыл соединение после первого ответа — берём первый
		return &ms[0]
	}
	return nil
}

// readHTTPHead читает заголовки ответа (у generate_204 тела нет). true — пришёл ответ HTTP.
func readHTTPHead(c net.Conn, buf []byte) bool {
	var head []byte
	for len(head) < 4096 {
		n, err := c.Read(buf)
		if n > 0 {
			head = append(head, buf[:n]...)
			if bytes.Contains(head, []byte("\r\n\r\n")) {
				return bytes.HasPrefix(head, []byte("HTTP/"))
			}
		}
		if err != nil {
			return false
		}
	}
	return false
}
