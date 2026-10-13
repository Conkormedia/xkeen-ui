package main

// База заблокированных в РФ ресурсов Re:filter (github.com/1andrevich/Re-filter-lists):
// режим «Списки + блокировки РФ» отправляет через VPN всё, что в ней есть, остальное — напрямую.
// Файлы кладутся рядом с базами XKeen: geosite_refilter.dat, geoip_refilter.dat (тег refilter).

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const (
	refilterSite = "geosite_refilter.dat"
	refilterIP   = "geoip_refilter.dat"
	refilterBase = "https://github.com/1andrevich/Re-filter-lists/releases/latest/download/"
)

var refilterRules = struct{ Domain, IP string }{
	Domain: "ext:" + refilterSite + ":refilter",
	IP:     "ext:" + refilterIP + ":refilter",
}

func refilterPath(name string) string { return filepath.Join(cfg.XrayAssetDir, name) }

func refilterPresent() bool {
	for _, f := range []string{refilterSite, refilterIP} {
		if st, err := os.Stat(refilterPath(f)); err != nil || st.Size() < 50<<10 {
			return false
		}
	}
	return true
}

// refilterInfo — для страницы: когда обновлена база и сколько весит.
func refilterInfo() map[string]any {
	st, err := os.Stat(refilterPath(refilterSite))
	if err != nil || !refilterPresent() {
		return map[string]any{"present": false}
	}
	size := st.Size()
	if ip, err := os.Stat(refilterPath(refilterIP)); err == nil {
		size += ip.Size()
	}
	return map[string]any{"present": true, "updated": st.ModTime().Format("2006-01-02 15:04"), "size_kb": size / 1024}
}

func download(url string, limit int64) ([]byte, error) {
	var lastErr error
	for _, u := range []string{url, "https://gh-proxy.com/" + url, "https://ghfast.top/" + url} {
		client := &http.Client{Timeout: 120 * time.Second}
		resp, err := client.Get(u)
		if err != nil {
			lastErr = err
			continue
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, limit))
		resp.Body.Close()
		if err != nil || resp.StatusCode != 200 {
			lastErr = fmt.Errorf("%s: %d %v", u, resp.StatusCode, err)
			continue
		}
		return b, nil
	}
	return nil, lastErr
}

// updateRefilter скачивает базу. changed — содержимое отличается от того, что было.
// Прежние файлы сохраняются как *.prev (для отката, если xray не примет новые).
func updateRefilter() (changed bool, err error) {
	if err := os.MkdirAll(cfg.XrayAssetDir, 0o755); err != nil {
		return false, err
	}
	fresh := map[string][]byte{}
	for name, remote := range map[string]string{refilterSite: "geosite.dat", refilterIP: "geoip.dat"} {
		b, err := download(refilterBase+remote, 16<<20)
		if err != nil {
			return false, fmt.Errorf("Re:filter %s: %w", remote, err)
		}
		if len(b) < 50<<10 {
			return false, errors.New("Re:filter: подозрительно маленький файл " + remote)
		}
		fresh[name] = b
	}
	for name, b := range fresh {
		path := refilterPath(name)
		old, _ := os.ReadFile(path)
		if bytes.Equal(sha256sum(old), sha256sum(b)) {
			continue
		}
		changed = true
		if len(old) > 0 {
			_ = os.WriteFile(path+".prev", old, 0o644)
		}
		if err := writeAtomic(path, b); err != nil {
			return changed, err
		}
	}
	return changed, nil
}

// rollbackRefilter — вернуть прежнюю базу (если новая сломала конфиг).
func rollbackRefilter() {
	for _, name := range []string{refilterSite, refilterIP} {
		if b, err := os.ReadFile(refilterPath(name) + ".prev"); err == nil {
			_ = writeAtomic(refilterPath(name), b)
		}
	}
}

func sha256sum(b []byte) []byte { h := sha256.Sum256(b); return h[:] }

// refilterTick — раз в сутки (в 4 утра по времени роутера) обновить базу, если режим её использует.
// После обновления xray нужно перезапустить (базы читаются при старте) — отсюда ночное окно.
func refilterTick() {
	store.mu.Lock()
	mode, enabled, direct, last := store.st.Mode, store.st.Enabled, store.st.Auto.Mode == "direct", store.st.RefilterUpdated
	store.mu.Unlock()
	if mode != "blocked" {
		return
	}
	now := time.Now()
	due := !refilterPresent()
	if !due {
		t, err := time.ParseInLocation("2006-01-02 15:04:05", last, time.Local)
		due = (err != nil || now.Sub(t) > 20*time.Hour) && now.Hour() == 4
	}
	if !due {
		return
	}
	changed, err := updateRefilter()
	store.mu.Lock()
	defer store.mu.Unlock()
	st := &store.st
	if err != nil {
		st.RefilterError = err.Error()
		_ = store.save()
		return
	}
	st.RefilterUpdated, st.RefilterError = nowStr(), ""
	if changed && enabled && !direct && st.Mode == "blocked" {
		if out, err := applyFn(st, false); err != nil {
			rollbackRefilter()
			st.RefilterError = "новая база не прошла проверку xray, оставлена прежняя"
			st.LastLog = tail("Re:filter: "+err.Error(), 4000)
		} else {
			st.LastApply, st.LastLog = nowStr(), tail("Re:filter обновлён — применено\n"+out, 4000)
		}
	}
	_ = store.save()
}
