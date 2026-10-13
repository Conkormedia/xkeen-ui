package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

// Key — один сервер (vless-ссылка), из подписки или добавленный вручную.
type Key struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	URL   string `json:"url"`
	Sub   string `json:"sub,omitempty"`
	Stale bool   `json:"stale,omitempty"`
}

// Sub — подписка. URL содержит личный токен и наружу (в браузер) не отдаётся.
type Sub struct {
	ID        string  `json:"id"`
	URL       string  `json:"url"`
	Title     string  `json:"title"`
	IntervalH int     `json:"interval_h"`
	Updated   string  `json:"updated,omitempty"`
	UpdatedTS float64 `json:"updated_ts,omitempty"`
	Count     int     `json:"count,omitempty"`
	Skipped   int     `json:"skipped,omitempty"`
	Userinfo  string  `json:"userinfo,omitempty"`
	Error     string  `json:"error,omitempty"`
}

// Auto — состояние автовыбора сервера.
type Auto struct {
	Mode      string   `json:"mode,omitempty"` // preferred | fallback | direct
	Fails     int      `json:"fails"`
	PrefOK    int      `json:"pref_ok"`
	FullTS    float64  `json:"full_ts,omitempty"`
	LastCheck string   `json:"last_check,omitempty"`
	Events    []string `json:"events,omitempty"`
}

// State — всё, что хранится на диске. Схема совместима с прежней панелью на Python.
type State struct {
	Keys            []Key    `json:"keys"`
	ActiveKey       string   `json:"active_key"`
	PreferredKey    string   `json:"preferred_key"`
	Subs            []Sub    `json:"subs"`
	Enabled         bool     `json:"enabled"`
	Mode            string   `json:"mode"` // split — только списки | blocked — списки + Re:filter | all — весь трафик
	ProxyDomains    []string `json:"proxy_domains"`
	ProxyIPs        []string `json:"proxy_ips"`
	DirectDomains   []string `json:"direct_domains"`
	DirectIPs       []string `json:"direct_ips"`
	BlockDomains    []string `json:"block_domains"`
	BlockQUIC       bool     `json:"block_quic"`
	AutoEnabled     bool     `json:"auto_enabled"`
	Auto            Auto     `json:"auto"`
	LastApply       string   `json:"last_apply"`
	AppliedURL      string   `json:"applied_url,omitempty"` // ссылка, реально применённая на роутере
	RefilterUpdated string   `json:"refilter_updated,omitempty"`
	RefilterError   string   `json:"refilter_error,omitempty"`
	AppliedSig      string   `json:"applied_sig,omitempty"` // отпечаток применённой конфигурации — для «есть изменения»
	LastLog         string   `json:"last_log"`
}

func defaultState() State {
	return State{
		Keys: []Key{}, Subs: []Sub{}, Enabled: true, Mode: "split", BlockQUIC: true, AutoEnabled: true,
		ProxyDomains: []string{
			"geosite:youtube", "geosite:google", "geosite:meta", "geosite:twitter",
			"geosite:telegram", "geosite:openai", "geosite:anthropic", "geosite:netflix",
			"domain:instagram.com", "domain:discord.com", "domain:linkedin.com",
		},
		ProxyIPs:      []string{"geoip:telegram"},
		DirectDomains: []string{"geosite:category-ru", "domain:yandex.net", "domain:vk.com"},
		DirectIPs:     []string{"geoip:private", "geoip:ru"},
		BlockDomains:  []string{"geosite:category-ads-all"},
	}
}

// Store — состояние в памяти + запись на диск только при изменениях
// (флеш-память роутера: никаких записей «раз в минуту»).
type Store struct {
	mu   sync.Mutex
	path string
	st   State
}

func openStore(path string) (*Store, error) {
	s := &Store{path: path, st: defaultState()}
	b, err := os.ReadFile(path)
	if err == nil {
		if err := json.Unmarshal(b, &s.st); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if s.st.Keys == nil {
		s.st.Keys = []Key{}
	}
	if s.st.Subs == nil {
		s.st.Subs = []Sub{}
	}
	if s.st.Mode == "" {
		s.st.Mode = "split"
	}
	return s, nil
}

// save — атомарная запись (вызывать под s.mu).
func (s *Store) save() error {
	b, err := json.MarshalIndent(s.st, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (st *State) key(id string) *Key {
	for i := range st.Keys {
		if st.Keys[i].ID == id {
			return &st.Keys[i]
		}
	}
	return nil
}

func (st *State) preferred() string {
	if st.PreferredKey != "" {
		return st.PreferredKey
	}
	return st.ActiveKey
}
