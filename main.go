// xkeen-ui — веб-панель управления XKeen (Xray) прямо на роутере Keenetic.
//
// Один исполняемый файл: страница встроена, состояние — /opt/etc/xkeen-ui/state.json.
// Подписки, реальный пинг серверов, автовыбор с откатом на «напрямую»,
// списки маршрутизации, применение конфига с проверкой xray -test и откатом.
package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var version = "dev"

//go:embed web/index.html web/login.html
var webFS embed.FS

// Config — /opt/etc/xkeen-ui/config.json
type Config struct {
	Listen        string `json:"listen"` // "" — авто: адрес br0 (домашняя сеть) :8088
	Port          int    `json:"port"`
	PasswordHash  string `json:"password_hash"`
	Secret        string `json:"secret"`
	ExportToken   string `json:"export_token"` // для внешних клиентов в домашней сети (например, xray на сервере) — /api/export
	StatePath     string `json:"state_path"`
	XKeen         string `json:"xkeen"`
	Xray          string `json:"xray"`
	XrayConfDir   string `json:"xray_conf_dir"`
	XrayAssetDir  string `json:"xray_asset_dir"`
	TmpDir        string `json:"tmp_dir"`
	SubUserAgent  string `json:"sub_user_agent"`
	PingHost      string `json:"ping_host"`
	PingPath      string `json:"ping_path"`
	PingTimeoutS  int    `json:"ping_timeout_s"`
	PingBatch     int    `json:"ping_batch"`
	PingWorkers   int    `json:"ping_workers"`
	AutoIntervalS int    `json:"auto_interval_s"`
	AutoFails     int    `json:"auto_fails"`
	AutoRecover   int    `json:"auto_recover"`
	AutoFullPingS int    `json:"auto_full_ping_s"` // в режиме «напрямую»: как часто искать живые серверы
	ProbePort     int    `json:"probe_port"`       // служебный socks-вход в рабочем xray (127.0.0.1)

	PingTimeout  time.Duration `json:"-"`
	AutoInterval time.Duration `json:"-"`
	AutoFullPing time.Duration `json:"-"`
}

var (
	cfg     Config
	cfgPath string
	store   *Store
)

func loadConfig(path string) error {
	cfg = Config{Port: 8088, StatePath: "/opt/etc/xkeen-ui/state.json", XKeen: "/opt/sbin/xkeen",
		Xray: "/opt/sbin/xray", XrayConfDir: "auto", XrayAssetDir: "/opt/etc/xray/dat", TmpDir: "/tmp",
		SubUserAgent: "v2rayN/7.0", PingHost: "www.gstatic.com", PingPath: "/generate_204",
		PingTimeoutS: 6, PingBatch: 15, PingWorkers: 8, AutoIntervalS: 60, AutoFails: 2, AutoRecover: 3,
		AutoFullPingS: 180, ProbePort: 17890}
	b, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil {
		if err := json.Unmarshal(b, &cfg); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
	}
	changed := false
	if cfg.Secret == "" {
		cfg.Secret, changed = randHex(32), true
	}
	if cfg.ExportToken == "" {
		cfg.ExportToken, changed = randHex(16), true
	}
	cfg.PingTimeout = time.Duration(cfg.PingTimeoutS) * time.Second
	cfg.AutoInterval = time.Duration(cfg.AutoIntervalS) * time.Second
	cfg.AutoFullPing = time.Duration(cfg.AutoFullPingS) * time.Second
	if cfg.PingBatch < 1 {
		cfg.PingBatch = 15
	}
	if cfg.PingWorkers < 1 {
		cfg.PingWorkers = 8
	}
	if changed {
		return saveConfig()
	}
	return nil
}

func saveConfig() error {
	b, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o700); err != nil {
		return err
	}
	return os.WriteFile(cfgPath, b, 0o600)
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ---------- пароль: PBKDF2-SHA256 ----------
func hashPassword(p string) string {
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	k, _ := pbkdf2.Key(sha256.New, p, salt, 100000, 32)
	return "pbkdf2$100000$" + hex.EncodeToString(salt) + "$" + hex.EncodeToString(k)
}

func checkPassword(p, h string) bool {
	parts := strings.Split(h, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2" {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil {
		return false
	}
	salt, err1 := hex.DecodeString(parts[2])
	want, err2 := hex.DecodeString(parts[3])
	if err1 != nil || err2 != nil {
		return false
	}
	k, err := pbkdf2.Key(sha256.New, p, salt, iter, len(want))
	return err == nil && subtle.ConstantTimeCompare(k, want) == 1
}

// ---------- сессия: подписанная cookie ----------
const sessionTTL = 30 * 24 * time.Hour

func sign(v string) string {
	m := hmac.New(sha256.New, []byte(cfg.Secret))
	m.Write([]byte(v))
	return hex.EncodeToString(m.Sum(nil))
}

func newSession() string {
	exp := strconv.FormatInt(time.Now().Add(sessionTTL).Unix(), 10)
	return exp + "." + sign(exp)
}

func validSession(r *http.Request) bool {
	c, err := r.Cookie("xkui")
	if err != nil {
		return false
	}
	exp, sig, ok := strings.Cut(c.Value, ".")
	if !ok || !hmac.Equal([]byte(sig), []byte(sign(exp))) {
		return false
	}
	t, err := strconv.ParseInt(exp, 10, 64)
	return err == nil && time.Now().Unix() < t
}

func auth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !validSession(r) {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				writeJSON(w, 401, map[string]any{"error": "unauthorized"})
				return
			}
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		h(w, r)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func readJSON(r *http.Request) map[string]any {
	m := map[string]any{}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&m)
	return m
}

// ---------- публичное состояние (для браузера) ----------
func publicState(st *State) map[string]any {
	keys := []map[string]any{}
	for _, k := range st.Keys {
		host, port, network, sec := keyMeta(k.URL)
		keys = append(keys, map[string]any{"id": k.ID, "name": k.Name, "host": host, "port": port,
			"net": network, "sec": sec, "sub": nilIfEmpty(k.Sub), "stale": k.Stale})
	}
	subs := []map[string]any{}
	for _, s := range st.Subs {
		host := ""
		if u, err := url.Parse(s.URL); err == nil {
			host = u.Hostname()
		}
		// адрес подписки содержит личный токен — наружу отдаём только хост
		subs = append(subs, map[string]any{"id": s.ID, "title": s.Title, "host": host, "interval_h": s.IntervalH,
			"updated": s.Updated, "count": s.Count, "skipped": s.Skipped, "userinfo": s.Userinfo, "error": s.Error})
	}
	rtMu.Lock()
	p := map[string]*int{}
	for k, v := range pings {
		p[k] = v
	}
	pa := pingsAt
	rtMu.Unlock()
	return map[string]any{
		"keys": keys, "subs": subs, "active_key": nilIfEmpty(st.ActiveKey), "preferred_key": nilIfEmpty(st.PreferredKey),
		"enabled": st.Enabled, "mode": st.Mode, "block_quic": st.BlockQUIC,
		"proxy_domains": st.ProxyDomains, "proxy_ips": st.ProxyIPs, "direct_domains": st.DirectDomains,
		"direct_ips": st.DirectIPs, "block_domains": st.BlockDomains,
		"auto_enabled": st.AutoEnabled, "auto": st.Auto, "pings": p, "pings_at": nilIfEmpty(pa),
		"last_apply": nilIfEmpty(st.LastApply), "last_log": st.LastLog, "version": version,
		"refilter": refilterInfo(), "refilter_updated": nilIfEmpty(st.RefilterUpdated),
		"pending":        pendingChanges(st),
		"refilter_error": nilIfEmpty(st.RefilterError),
	}
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// ---------- обработчики ----------
func hLogin(w http.ResponseWriter, r *http.Request) {
	errMsg := ""
	if r.Method == http.MethodPost {
		if cfg.PasswordHash != "" && checkPassword(r.FormValue("p"), cfg.PasswordHash) {
			http.SetCookie(w, &http.Cookie{Name: "xkui", Value: newSession(), Path: "/", HttpOnly: true,
				SameSite: http.SameSiteLaxMode, MaxAge: int(sessionTTL.Seconds())})
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		errMsg = "Неверный пароль"
		if cfg.PasswordHash == "" {
			errMsg = "Пароль не задан: выполните на роутере  xkeen-ui passwd"
		}
		time.Sleep(time.Second)
	}
	b, _ := webFS.ReadFile("web/login.html")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(strings.Replace(string(b), "{{ERR}}", htmlEscape(errMsg), 1)))
}

func htmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(s)
}

func hLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "xkui", Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusFound)
}

func hIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	b, _ := webFS.ReadFile("web/index.html")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(b)
}

func withState(w http.ResponseWriter, fn func(st *State) (int, any)) {
	store.mu.Lock()
	defer store.mu.Unlock()
	code, v := fn(&store.st)
	writeJSON(w, code, v)
}

func hState(w http.ResponseWriter, r *http.Request) {
	withState(w, func(st *State) (int, any) { return 200, publicState(st) })
}

func hStatus(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, routerStatus()) }

func hAddKey(w http.ResponseWriter, r *http.Request) {
	raw := strings.TrimSpace(fmt.Sprint(readJSON(r)["url"]))
	withState(w, func(st *State) (int, any) {
		if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
			for _, s := range st.Subs {
				if s.URL == raw {
					return 400, map[string]any{"error": "Эта подписка уже добавлена"}
				}
			}
			sub := Sub{ID: randHex(4), URL: raw, IntervalH: 12}
			if _, err := syncSubscription(st, &sub); err != nil {
				return 400, map[string]any{"error": "Подписка: " + err.Error()}
			}
			st.Subs = append(st.Subs, sub)
		} else {
			if _, err := parseVless(raw); err != nil {
				return 400, map[string]any{"error": err.Error()}
			}
			k := Key{ID: randHex(4), Name: keyName(raw), URL: raw}
			st.Keys = append(st.Keys, k)
			if st.ActiveKey == "" {
				st.ActiveKey = k.ID
			}
		}
		_ = store.save()
		return 200, publicState(st)
	})
}

func fixActive(st *State) {
	if st.key(st.ActiveKey) == nil {
		st.ActiveKey = ""
		if len(st.Keys) > 0 {
			st.ActiveKey = st.Keys[0].ID
		}
	}
	if st.PreferredKey != "" && st.key(st.PreferredKey) == nil {
		st.PreferredKey = st.ActiveKey
	}
}

func hDelKey(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	withState(w, func(st *State) (int, any) {
		keys := []Key{}
		for _, k := range st.Keys {
			if k.ID != id {
				keys = append(keys, k)
			}
		}
		st.Keys = keys
		fixActive(st)
		_ = store.save()
		return 200, publicState(st)
	})
}

func hSubRefresh(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	withState(w, func(st *State) (int, any) {
		for i := range st.Subs {
			if st.Subs[i].ID == id {
				changed, err := syncSubscription(st, &st.Subs[i])
				if err != nil {
					st.Subs[i].Error = err.Error()
					_ = store.save()
					return 502, map[string]any{"error": "Подписка: " + err.Error()}
				}
				_ = store.save()
				return 200, map[string]any{"state": publicState(st), "active_changed": changed}
			}
		}
		return 404, map[string]any{"error": "Подписка не найдена"}
	})
}

func hSubDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	withState(w, func(st *State) (int, any) {
		subs := []Sub{}
		for _, s := range st.Subs {
			if s.ID != id {
				subs = append(subs, s)
			}
		}
		st.Subs = subs
		keys := []Key{}
		for _, k := range st.Keys {
			if k.Sub != id {
				keys = append(keys, k)
			}
		}
		st.Keys = keys
		fixActive(st)
		_ = store.save()
		return 200, publicState(st)
	})
}

func hPing(w http.ResponseWriter, r *http.Request) {
	want := map[string]bool{}
	if ids, ok := readJSON(r)["ids"].([]any); ok {
		for _, id := range ids {
			want[fmt.Sprint(id)] = true
		}
	}
	store.mu.Lock()
	var keys []Key
	for _, k := range store.st.Keys {
		if len(want) == 0 || want[k.ID] {
			keys = append(keys, k)
		}
	}
	store.mu.Unlock()
	res := pingKeys(keys)
	xrayMu.Lock()
	perr := pingErr
	xrayMu.Unlock()
	if perr != "" {
		writeJSON(w, 503, map[string]any{"error": perr})
		return
	}
	mergePings(res, len(want) == 0)
	withState(w, func(st *State) (int, any) { return 200, publicState(st) })
}

func strList(v any) ([]string, bool) {
	arr, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		out = append(out, fmt.Sprint(x))
	}
	return out, true
}

func hSettings(w http.ResponseWriter, r *http.Request) {
	d := readJSON(r)
	withState(w, func(st *State) (int, any) {
		if v, ok := d["block_quic"].(bool); ok {
			st.BlockQUIC = v
		}
		if v, ok := d["enabled"].(bool); ok {
			st.Enabled = v
			if v { // ручное включение VPN выводит автовыбор из режима «напрямую»
				if st.ActiveKey == st.preferred() {
					st.Auto.Mode = "preferred"
				} else {
					st.Auto.Mode = "fallback"
				}
			}
		}
		if v, ok := d["mode"].(string); ok && (v == "split" || v == "blocked" || v == "all") {
			st.Mode = v
		}
		if v, ok := d["active_key"].(string); ok && st.key(v) != nil {
			// выбор пользователя = «ваш» сервер; автовыбор начинает с него
			st.ActiveKey, st.PreferredKey = v, v
			st.Auto.Mode, st.Auto.Fails, st.Auto.PrefOK = "preferred", 0, 0
		}
		if v, ok := d["auto_enabled"].(bool); ok {
			st.AutoEnabled = v
			st.Auto.Fails, st.Auto.PrefOK = 0, 0
		}
		lists := map[string]*[]string{"proxy_domains": &st.ProxyDomains, "proxy_ips": &st.ProxyIPs,
			"direct_domains": &st.DirectDomains, "direct_ips": &st.DirectIPs, "block_domains": &st.BlockDomains}
		for name, dst := range lists {
			if l, ok := strList(d[name]); ok {
				*dst = l
			}
		}
		_ = store.save()
		return 200, publicState(st)
	})
}

func hApply(w http.ResponseWriter, r *http.Request) {
	// Применение идёт 20–40 с (xray -test, перезапуск XKeen). Работаем с копией настроек, чтобы
	// остальные запросы (статус, состояние, обновление страницы) не ждали всё это время.
	store.mu.Lock()
	snap := store.st
	snap.Keys = append([]Key(nil), store.st.Keys...)
	store.mu.Unlock()
	out, err := applyToRouter(&snap, false)
	withState(w, func(st *State) (int, any) {
		if err == nil {
			st.AppliedURL, st.AppliedSig = snap.AppliedURL, snap.AppliedSig
		}
		if err != nil {
			st.LastLog = tail(out+"\n"+err.Error(), 4000)
			_ = store.save()
			return 500, map[string]any{"ok": false, "error": err.Error()}
		}
		st.LastApply, st.LastLog = nowStr(), tail(out, 4000)
		if st.Enabled && st.Auto.Mode == "direct" {
			st.Auto.Mode = "preferred"
			if st.ActiveKey != st.preferred() {
				st.Auto.Mode = "fallback"
			}
		}
		_ = store.save()
		return 200, map[string]any{"ok": true, "log": out, "state": publicState(st)}
	})
}

func hPreview(w http.ResponseWriter, r *http.Request) {
	withState(w, func(st *State) (int, any) {
		ob, err := buildOutbounds(st)
		if err != nil {
			return 400, map[string]any{"error": err.Error()}
		}
		return 200, map[string]any{"outbounds": ob, "routing": buildRouting(st)}
	})
}

// hRefilterUpdate — скачать базу блокировок сейчас; если режим её использует — применить.
func hRefilterUpdate(w http.ResponseWriter, r *http.Request) {
	changed, err := updateRefilter()
	withState(w, func(st *State) (int, any) {
		if err != nil {
			st.RefilterError = err.Error()
			_ = store.save()
			return 502, map[string]any{"error": err.Error()}
		}
		st.RefilterUpdated, st.RefilterError = nowStr(), ""
		applied := false
		if changed && st.Mode == "blocked" && st.Enabled && st.Auto.Mode != "direct" {
			if out, err := applyToRouter(st, false); err != nil {
				rollbackRefilter()
				st.RefilterError = "новая база не прошла проверку xray, оставлена прежняя"
				st.LastLog = tail(err.Error(), 4000)
			} else {
				st.LastApply, st.LastLog, applied = nowStr(), tail("Re:filter обновлён — применено\n"+out, 4000), true
			}
		}
		_ = store.save()
		return 200, map[string]any{"state": publicState(st), "changed": changed, "applied": applied}
	})
}

// hExport — для внешних клиентов в домашней сети (например, отдельный xray на домашнем сервере):
// текущий сервер и списки. Защищено токеном из config.json.
func hExport(w http.ResponseWriter, r *http.Request) {
	tok := r.URL.Query().Get("token")
	if cfg.ExportToken == "" || !hmac.Equal([]byte(tok), []byte(cfg.ExportToken)) {
		writeJSON(w, 403, map[string]any{"error": "forbidden"})
		return
	}
	withState(w, func(st *State) (int, any) {
		active, name := "", ""
		if k := st.key(st.ActiveKey); k != nil {
			active, name = k.URL, k.Name
			if st.AppliedURL != "" && coreSig(st.AppliedURL) == coreSig(k.URL) {
				active = st.AppliedURL // ровно то, что применено на роутере
			}
		}
		direct := st.Auto.Mode == "direct" || !st.Enabled
		return 200, map[string]any{"active_url": active, "active_name": name, "direct": direct, "direct_domains": clean(st.DirectDomains),
			"direct_ips": clean(st.DirectIPs), "block_domains": clean(st.BlockDomains)}
	})
}

// ---------- адрес прослушивания ----------
func listenAddr() string {
	if cfg.Listen != "" {
		if strings.Contains(cfg.Listen, ":") {
			return cfg.Listen
		}
		return net.JoinHostPort(cfg.Listen, strconv.Itoa(cfg.Port))
	}
	// по умолчанию — только домашняя сеть (br0), чтобы панель не торчала наружу
	if ifc, err := net.InterfaceByName("br0"); err == nil {
		if addrs, err := ifc.Addrs(); err == nil {
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
					return net.JoinHostPort(ipn.IP.String(), strconv.Itoa(cfg.Port))
				}
			}
		}
	}
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.Port))
}

// ---------- команды ----------
func cmdPasswd() error {
	var p string
	if len(flag.Args()) > 1 {
		p = flag.Args()[1]
	} else {
		fmt.Print("Новый пароль панели: ")
		sc := bufio.NewScanner(os.Stdin)
		if sc.Scan() {
			p = strings.TrimSpace(sc.Text())
		}
	}
	if len(p) < 6 {
		return errors.New("пароль слишком короткий (минимум 6 символов)")
	}
	cfg.PasswordHash = hashPassword(p)
	if err := saveConfig(); err != nil {
		return err
	}
	fmt.Println("Пароль сохранён. Перезапустите панель: /opt/etc/init.d/S99xkeen-ui restart")
	return nil
}

// cmdImport — перенос состояния из прежней панели (state.json той же схемы).
func cmdImport(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	st := defaultState()
	if err := json.Unmarshal(b, &st); err != nil {
		return err
	}
	if st.PreferredKey == "" {
		st.PreferredKey = st.ActiveKey
	}
	st.Auto = Auto{Mode: "preferred"}
	store = &Store{path: cfg.StatePath, st: st}
	if err := store.save(); err != nil {
		return err
	}
	fmt.Printf("Импортировано: %d серверов, %d подписок → %s\n", len(st.Keys), len(st.Subs), cfg.StatePath)
	return nil
}

func setupEnv() {
	// сертификаты Entware — для https-подписок
	for _, f := range []string{"/opt/etc/ssl/certs/ca-certificates.crt", "/opt/etc/ssl/cert.pem"} {
		if _, err := os.Stat(f); err == nil && os.Getenv("SSL_CERT_FILE") == "" {
			_ = os.Setenv("SSL_CERT_FILE", f)
			break
		}
	}
	// часовой пояс роутера (Entware ставит /opt/etc/localtime)
	if b, err := os.ReadFile("/opt/etc/localtime"); err == nil {
		if loc, err := time.LoadLocationFromTZData("Local", b); err == nil {
			time.Local = loc
		}
	}
	p := os.Getenv("PATH")
	if !strings.Contains(p, "/opt/sbin") {
		_ = os.Setenv("PATH", "/opt/sbin:/opt/bin:/opt/usr/sbin:/opt/usr/bin:"+p)
	}
}

func main() {
	flag.StringVar(&cfgPath, "config", "/opt/etc/xkeen-ui/config.json", "файл настроек")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "xkeen-ui %s — веб-панель XKeen\n\n"+
			"  xkeen-ui [-config путь]            запустить панель\n"+
			"  xkeen-ui passwd [пароль]           задать пароль входа\n"+
			"  xkeen-ui import <state.json>       перенести настройки из прежней панели\n"+
			"  xkeen-ui version\n", version)
	}
	flag.Parse()
	setupEnv()
	if err := loadConfig(cfgPath); err != nil {
		log.Fatal(err)
	}
	switch flag.Arg(0) {
	case "passwd":
		if err := cmdPasswd(); err != nil {
			log.Fatal(err)
		}
		return
	case "import":
		if err := cmdImport(flag.Arg(1)); err != nil {
			log.Fatal(err)
		}
		return
	case "version":
		fmt.Println(version)
		return
	case "":
	default:
		flag.Usage()
		os.Exit(2)
	}

	var err error
	if store, err = openStore(cfg.StatePath); err != nil {
		log.Fatal("state: ", err)
	}
	if store.st.AppliedSig == "" && store.st.LastApply != "" {
		// переход со старой версии: считаем, что на роутере применено текущее
		store.st.AppliedSig = configSig(&store.st)
		_ = store.save()
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", hLogin)
	mux.HandleFunc("POST /login", hLogin)
	mux.HandleFunc("GET /logout", hLogout)
	mux.HandleFunc("GET /", auth(hIndex))
	mux.HandleFunc("GET /api/state", auth(hState))
	mux.HandleFunc("GET /api/status", auth(hStatus))
	mux.HandleFunc("POST /api/keys", auth(hAddKey))
	mux.HandleFunc("DELETE /api/keys/{id}", auth(hDelKey))
	mux.HandleFunc("POST /api/subs/{id}/refresh", auth(hSubRefresh))
	mux.HandleFunc("DELETE /api/subs/{id}", auth(hSubDelete))
	mux.HandleFunc("POST /api/ping", auth(hPing))
	mux.HandleFunc("POST /api/settings", auth(hSettings))
	mux.HandleFunc("POST /api/apply", auth(hApply))
	mux.HandleFunc("GET /api/preview", auth(hPreview))
	mux.HandleFunc("POST /api/refilter/update", auth(hRefilterUpdate))
	mux.HandleFunc("GET /api/export", hExport)

	killStalePingXray()
	go autoLoop()
	go subLoop()

	addr := listenAddr()
	log.Printf("xkeen-ui %s: http://%s", version, addr)
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
