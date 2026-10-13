package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

func clean(lst []string) []string {
	out := []string{}
	for _, x := range lst {
		x = strings.TrimSpace(x)
		if x != "" && !strings.HasPrefix(x, "#") {
			out = append(out, x)
		}
	}
	return out
}

func buildOutbounds(st *State) (map[string]any, error) {
	k := st.key(st.ActiveKey)
	if k == nil {
		return nil, errors.New("не выбран активный сервер")
	}
	proxy, err := parseVless(k.URL)
	if err != nil {
		return nil, err
	}
	return map[string]any{"outbounds": []any{
		proxy,
		map[string]any{"tag": "direct", "protocol": "freedom"},
		map[string]any{"tag": "block", "protocol": "blackhole", "settings": map[string]any{"response": map[string]any{"type": "http"}}},
	}}, nil
}

func buildRouting(st *State) map[string]any {
	field := func(k string, v any, tag string) map[string]any {
		return map[string]any{"type": "field", k: v, "outboundTag": tag}
	}
	// входы XKeen с портом 1191 (политика xkeen_full) — всегда через прокси
	rules := []any{field("inboundTag", []string{"force-proxy-redirect", "force-proxy-tproxy", probeTag}, "proxy")}
	if st.BlockQUIC {
		rules = append(rules, map[string]any{"type": "field", "network": "udp", "port": "443", "outboundTag": "block"})
	}
	if l := clean(st.BlockDomains); len(l) > 0 {
		rules = append(rules, field("domain", l, "block"))
	}
	if l := clean(st.DirectIPs); len(l) > 0 {
		rules = append(rules, field("ip", l, "direct"))
	}
	if l := clean(st.DirectDomains); len(l) > 0 {
		rules = append(rules, field("domain", l, "direct"))
	}
	if st.Mode == "all" {
		rules = append(rules, field("network", "tcp,udp", "proxy"))
	} else {
		if l := clean(st.ProxyDomains); len(l) > 0 {
			rules = append(rules, field("domain", l, "proxy"))
		}
		if l := clean(st.ProxyIPs); len(l) > 0 {
			rules = append(rules, field("ip", l, "proxy"))
		}
		if st.Mode == "blocked" { // + всё, что заблокировано в РФ (Re:filter)
			rules = append(rules, field("domain", []string{refilterRules.Domain}, "proxy"))
			rules = append(rules, field("ip", []string{refilterRules.IP}, "proxy"))
		}
		rules = append(rules, field("network", "tcp,udp", "direct"))
	}
	return map[string]any{"routing": map[string]any{"domainStrategy": "IPIfNonMatch", "rules": rules}}
}

func runCmd(timeout time.Duration, env []string, name string, args ...string) (int, string) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), env...)
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err := cmd.Run()
	code := 0
	if err != nil {
		code = 1
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else {
			buf.WriteString(err.Error())
		}
	}
	return code, stripANSI(buf.String())
}

func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) && (s[j] < '@' || s[j] > '~') {
				j++
			}
			i = j
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// confDir — каталог конфигов XKeen (в разных версиях configs/ или config/).
func confDir() (string, error) {
	if cfg.XrayConfDir != "" && cfg.XrayConfDir != "auto" {
		return cfg.XrayConfDir, nil
	}
	for _, d := range []string{"/opt/etc/xray/configs", "/opt/etc/xray/config"} {
		if _, err := os.Stat(filepath.Join(d, "04_outbounds.json")); err == nil {
			return d, nil
		}
	}
	return "", errors.New("не нашёл конфиги XKeen (04_outbounds.json). XKeen установлен?")
}

func writeAtomic(path string, data []byte) error {
	tmp := path + ".new"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

var applyMu sync.Mutex // одновременно — только одно применение

// applyToRouter пишет конфиги, проверяет их xray -test (при ошибке — откат) и перезапускает XKeen.
// stop=true — остановить XKeen (трафик напрямую), не меняя st.Enabled.
func applyToRouter(st *State, stop bool) (string, error) {
	applyMu.Lock()
	defer applyMu.Unlock()
	xrayMu.Lock() // не запускать xray параллельно с замером пинга (память)
	defer xrayMu.Unlock()
	var log []string
	if stop || !st.Enabled {
		_, out := runCmd(120*time.Second, nil, cfg.XKeen, "-stop")
		return "$ xkeen -stop\n" + out, nil
	}
	dir, err := confDir()
	if err != nil {
		return "", err
	}
	ob, err := buildOutbounds(st)
	if err != nil {
		return "", err
	}
	if st.Mode == "blocked" && !refilterPresent() {
		return "", errors.New("база блокировок Re:filter не загружена — нажмите «Обновить базу»")
	}
	obB, _ := json.MarshalIndent(ob, "", "  ")
	rtB, _ := json.MarshalIndent(buildRouting(st), "", "  ")

	bdir := filepath.Join(filepath.Dir(dir), "panel-backup")
	_ = os.MkdirAll(bdir, 0o755)
	ts := time.Now().Format("20060102-150405")
	backups := map[string]string{}
	for _, f := range []string{"04_outbounds", "05_routing"} {
		if b, err := os.ReadFile(filepath.Join(dir, f+".json")); err == nil {
			bp := filepath.Join(bdir, fmt.Sprintf("%s.%s.json", f, ts))
			if os.WriteFile(bp, b, 0o644) == nil {
				backups[f] = bp
			}
		}
	}
	pruneBackups(bdir, 20)
	if err := writeAtomic(filepath.Join(dir, "04_outbounds.json"), obB); err != nil {
		return "", err
	}
	if err := writeAtomic(filepath.Join(dir, "05_routing.json"), rtB); err != nil {
		return "", err
	}
	if err := writeAtomic(filepath.Join(dir, probeFile), probeInbound()); err != nil {
		return "", err
	}
	code, out := runCmd(90*time.Second, []string{"XRAY_LOCATION_ASSET=" + cfg.XrayAssetDir}, cfg.Xray, "run", "-test", "-confdir", dir)
	log = append(log, "$ xray -test\n"+tail(out, 1500))
	if code != 0 {
		for f, bp := range backups {
			if b, err := os.ReadFile(bp); err == nil {
				_ = writeAtomic(filepath.Join(dir, f+".json"), b)
			}
		}
		return strings.Join(log, "\n"), errors.New("Xray отклонил конфиг, откатил прежний.\n" + tail(out, 1500))
	}
	_, out = runCmd(180*time.Second, nil, cfg.XKeen, "-restart")
	log = append(log, "$ xkeen -restart\n"+out)
	// XKeen запускает xray в фоне; ждём, пока рабочий xray поднимется, прежде чем отпускать xrayMu
	for deadline := time.Now().Add(90 * time.Second); time.Now().Before(deadline); time.Sleep(2 * time.Second) {
		if xrayRunning() {
			time.Sleep(5 * time.Second) // распаковка UPX и старт
			break
		}
	}
	st.AppliedURL = st.key(st.ActiveKey).URL
	return strings.Join(log, "\n"), nil
}

func pruneBackups(dir string, keep int) {
	m, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	if len(m) <= keep {
		return
	}
	sort.Slice(m, func(i, j int) bool {
		a, _ := os.Stat(m[i])
		b, _ := os.Stat(m[j])
		return a.ModTime().After(b.ModTime())
	})
	for _, f := range m[keep:] {
		_ = os.Remove(f)
	}
}

func tail(s string, n int) string {
	if len(s) > n {
		return "…" + s[len(s)-n:]
	}
	return s
}

var (
	xrayVerMu sync.Mutex
	xrayVer   string
)

// routerStatus — запущен ли xray и его версия (версию кэшируем: запуск xray на MIPS не бесплатный).
func xrayRunning() bool {
	_, out := runCmd(5*time.Second, nil, "pidof", "xray")
	for _, p := range strings.Fields(out) {
		if strings.Trim(p, "0123456789") == "" && p != fmt.Sprint(pingPID.Load()) { // временный xray замера пинга не считаем
			return true
		}
	}
	return false
}

func routerStatus() map[string]any {
	running := xrayRunning()
	xrayVerMu.Lock()
	if xrayVer == "" && xrayMu.TryLock() { // версию узнаём, только когда никто не запускает xray
		defer xrayMu.Unlock()
		if c, out := runCmd(20*time.Second, nil, cfg.Xray, "version"); c == 0 {
			xrayVer = strings.TrimSpace(strings.SplitN(out, "\n", 2)[0])
		}
	}
	v := xrayVer
	xrayVerMu.Unlock()
	return map[string]any{"ok": true, "running": running, "xray": v}
}

// ---------- служебный вход для проверки активного сервера через рабочий xray ----------
const (
	probeTag  = "panel-probe"
	probeFile = "07_panel_probe.json"
)

func probeInbound() []byte {
	b, _ := json.MarshalIndent(map[string]any{"inbounds": []any{map[string]any{
		"tag": probeTag, "listen": "127.0.0.1", "port": cfg.ProbePort, "protocol": "socks",
		"settings": map[string]any{"udp": false},
	}}}, "", "  ")
	return b
}

// mainProbeReady — служебный вход уже применён (файл есть) и рабочий xray запущен.
func mainProbeReady() bool {
	dir, err := confDir()
	if err != nil {
		return false
	}
	if _, err := os.Stat(filepath.Join(dir, probeFile)); err != nil {
		return false
	}
	return xrayRunning()
}

// probeMain — задержка через рабочий xray XKeen (то есть ровно через то, что применено на роутере).
func probeMain() *int {
	return socksHTTPProbe(cfg.ProbePort, cfg.PingTimeout)
}
