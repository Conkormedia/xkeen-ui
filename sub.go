package main

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type subInfo struct {
	Links     []string
	Skipped   int
	Title     string
	IntervalH int
	Userinfo  string
}

func decodeB64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.NewReplacer("\n", "", "\r", "", " ", "").Replace(s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("не base64")
}

// fetchSubscription скачивает подписку (base64 или текст со ссылками).
func fetchSubscription(rawURL string) (*subInfo, error) {
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", cfg.SubUserAgent)
	client := &http.Client{Timeout: 25 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("сервер подписки ответил %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
	if err != nil {
		return nil, err
	}
	text := strings.TrimSpace(string(body))
	if !strings.Contains(text, "://") {
		b, err := decodeB64(text)
		if err != nil {
			return nil, errors.New("не удалось разобрать подписку (не base64 и не список ссылок)")
		}
		text = string(b)
	}
	info := &subInfo{IntervalH: 12, Userinfo: resp.Header.Get("subscription-userinfo")}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if _, err := parseVless(line); err == nil {
			info.Links = append(info.Links, line)
		} else {
			info.Skipped++
		}
	}
	if len(info.Links) == 0 {
		return nil, errors.New("в подписке нет поддерживаемых ключей vless://")
	}
	if t := resp.Header.Get("profile-title"); strings.HasPrefix(t, "base64:") {
		if b, err := decodeB64(t[7:]); err == nil {
			info.Title = string(b)
		}
	} else {
		info.Title = t
	}
	if h, err := strconv.Atoi(strings.TrimSpace(resp.Header.Get("profile-update-interval"))); err == nil && h >= 1 {
		info.IntervalH = h
	}
	return info, nil
}

// syncSubscription обновляет ключи подписки в st (под s.mu).
// true — если изменились параметры активного сервера.
func syncSubscription(st *State, sub *Sub) (bool, error) {
	info, err := fetchSubscription(sub.URL)
	if err != nil {
		return false, err
	}
	old := map[string]Key{}
	for _, k := range st.Keys {
		if k.Sub == sub.ID {
			old[k.ID] = k
		}
	}
	var fresh []Key
	seen := map[string]int{}
	for _, link := range info.Links {
		name := keyName(link)
		h := sha1.Sum([]byte(sub.ID + "|" + name))
		base := hex.EncodeToString(h[:])[:8]
		id := base
		if n := seen[base]; n > 0 {
			id = fmt.Sprintf("%s%d", base, n)
		}
		seen[base]++
		fresh = append(fresh, Key{ID: id, Name: name, URL: link, Sub: sub.ID})
	}
	changed := false
	if o, ok := old[st.ActiveKey]; ok {
		found := false
		for _, k := range fresh {
			if k.ID == st.ActiveKey {
				found = true
				changed = coreSig(k.URL) != coreSig(o.URL)
			}
		}
		if !found { // сервер пропал из подписки — оставляем, чтобы не ломать работающий VPN
			o.Stale = true
			fresh = append(fresh, o)
		}
	}
	keys := []Key{}
	for _, k := range st.Keys {
		if k.Sub != sub.ID {
			keys = append(keys, k)
		}
	}
	st.Keys = append(keys, fresh...)
	if info.Title != "" {
		sub.Title = info.Title
	} else if sub.Title == "" {
		if u, err := url.Parse(sub.URL); err == nil {
			sub.Title = u.Hostname()
		}
	}
	sub.IntervalH, sub.Userinfo, sub.Count, sub.Skipped = info.IntervalH, info.Userinfo, len(info.Links), info.Skipped
	sub.Updated, sub.UpdatedTS, sub.Error = nowStr(), float64(time.Now().Unix()), ""
	if st.ActiveKey == "" && len(fresh) > 0 {
		st.ActiveKey = fresh[0].ID
	}
	return changed, nil
}

func nowStr() string { return time.Now().Format("2006-01-02 15:04:05") }
