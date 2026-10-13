package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// Сценарии автовыбора: падение «вашего», возврат, «все мертвы» → напрямую, оживание,
// ротация sid/sni подпиской (устаревшие параметры на роутере).
func TestAutoFailover(t *testing.T) {
	cfg = Config{AutoFails: 2, AutoRecover: 3, AutoFullPing: 0}
	store = &Store{path: filepath.Join(t.TempDir(), "state.json"), st: defaultState()}
	u := func(host, sid string) string {
		return "vless://11111111-2222-3333-4444-555555555555@" + host + ":443?type=tcp&security=reality&pbk=k&sid=" + sid + "#" + host
	}
	store.st.Keys = []Key{{ID: "A", Name: "A", URL: u("a", "1")}, {ID: "B", Name: "B", URL: u("b", "1")}, {ID: "C", Name: "C", URL: u("c", "1")}}
	store.st.ActiveKey, store.st.PreferredKey, store.st.LastApply = "A", "A", "x"
	store.st.AppliedURL = store.st.Keys[0].URL
	running := true // XKeen запущен

	alive := map[string]int{}    // id -> мс
	deadURL := map[string]bool{} // ссылки, которые «не работают»
	var applied []string
	pingFn = func(keys []Key) map[string]*int {
		r := map[string]*int{}
		for _, k := range keys {
			r[k.ID] = nil
			if deadURL[k.URL] {
				continue
			}
			id := k.ID
			if v, ok := alive[id]; ok {
				r[k.ID] = &v
			}
		}
		return r
	}
	applyFn = func(st *State, stop bool) (string, error) {
		if stop {
			applied, running = append(applied, "STOP"), false
		} else {
			applied, running = append(applied, st.ActiveKey), true
			st.AppliedURL = st.key(st.ActiveKey).URL
		}
		return "ok", nil
	}
	mainProbeReadyFn = func() bool { return running }
	probeMainFn = func() *int { // рабочий xray: жив, если жив сервер применённой ссылки и ссылка не «протухла»
		if !running || deadURL[store.st.AppliedURL] {
			return nil
		}
		for _, k := range store.st.Keys {
			if coreSig(k.URL) == coreSig(store.st.AppliedURL) {
				if v, ok := alive[k.ID]; ok {
					return &v
				}
			}
		}
		return nil
	}
	steps := []struct {
		name       string
		alive      map[string]int
		wantActive string
		wantMode   string
	}{
		{"все живы", map[string]int{"A": 100, "B": 200, "C": 50}, "A", ""},
		{"A мёртв (1)", map[string]int{"B": 200, "C": 50}, "A", ""},
		{"A мёртв (2) → самый быстрый C", map[string]int{"B": 200, "C": 50}, "C", "fallback"},
		{"A ожил (1)", map[string]int{"A": 100, "B": 200, "C": 50}, "C", "fallback"},
		{"A ожил (2)", map[string]int{"A": 100, "B": 200, "C": 50}, "C", "fallback"},
		{"A ожил (3) → назад на A", map[string]int{"A": 100, "B": 200, "C": 50}, "A", "preferred"},
		{"A мёртв", map[string]int{"C": 50}, "A", "preferred"},
		{"A мёртв → C", map[string]int{"C": 50}, "C", "fallback"},
		{"C мёртв (1)", map[string]int{}, "C", "fallback"},
		{"все мертвы (2) → напрямую", map[string]int{}, "C", "direct"},
		{"всё ещё мертвы", map[string]int{}, "C", "direct"},
		{"ожил B → B", map[string]int{"B": 300}, "B", "fallback"},
		{"A ожил (1)", map[string]int{"A": 90, "B": 300}, "B", "fallback"},
		{"A (2)", map[string]int{"A": 90, "B": 300}, "B", "fallback"},
		{"A (3) → A", map[string]int{"A": 90, "B": 300}, "A", "preferred"},
		{"все мертвы (1)", map[string]int{}, "A", "preferred"},
		{"все мертвы (2) → напрямую", map[string]int{}, "A", "direct"},
		{"ожил A → сразу A", map[string]int{"A": 80}, "A", "preferred"},
	}
	for i, s := range steps {
		alive = s.alive
		autoTick()
		st := store.st
		if st.ActiveKey != s.wantActive || st.Auto.Mode != s.wantMode {
			t.Fatalf("шаг %d «%s»: active=%s mode=%q, ждали %s %q (applied=%v)", i+1, s.name,
				st.ActiveKey, st.Auto.Mode, s.wantActive, s.wantMode, applied)
		}
	}
	want := "C A C STOP B A STOP A"
	if got := strings.Join(applied, " "); got != want {
		t.Fatalf("применения: %s, ждали %s", got, want)
	}

	// ротация: подписка выдала A новые sid, старые параметры на роутере перестали работать
	old := store.st.AppliedURL
	store.st.Keys[0].URL = u("a", "2")
	deadURL[old] = true
	alive = map[string]int{"A": 80, "B": 300}
	autoTick() // 1-й провал через рабочий xray
	autoTick() // 2-й — переприменить свежие параметры
	if store.st.AppliedURL != u("a", "2") || applied[len(applied)-1] != "A" {
		t.Fatalf("ротация: applied=%s (%v)", store.st.AppliedURL, applied)
	}
	if !strings.Contains(store.st.Auto.Events[0], "свежие") {
		t.Fatalf("нет события о свежих параметрах: %v", store.st.Auto.Events)
	}
	// после переприменения — тишина
	n := len(applied)
	autoTick()
	if len(applied) != n {
		t.Fatalf("лишнее применение: %v", applied)
	}
}

func TestCoreSigIgnoresRotation(t *testing.T) {
	a := "vless://u@h:443?type=tcp&security=reality&pbk=K&sid=1&sni=x.ru&flow=xtls-rprx-vision#n"
	b := "vless://u@h:443?type=tcp&security=reality&pbk=K&sid=2&sni=y.ru&flow=xtls-rprx-vision#n"
	c := "vless://u@h2:443?type=tcp&security=reality&pbk=K&sid=2&sni=y.ru&flow=xtls-rprx-vision#n"
	if coreSig(a) != coreSig(b) {
		t.Fatal("ротация sid/sni не должна считаться сменой сервера")
	}
	if coreSig(a) == coreSig(c) {
		t.Fatal("смена адреса — это смена сервера")
	}
}

func TestParseVless(t *testing.T) {
	ob, err := parseVless("vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?type=ws&security=tls&sni=s.example&path=%2Fws&host=h.example#%F0%9F%87%A9%F0%9F%87%AA%20DE")
	if err != nil {
		t.Fatal(err)
	}
	ss := ob["streamSettings"].(map[string]any)
	if ss["network"] != "ws" || ss["wsSettings"].(map[string]any)["path"] != "/ws" {
		t.Fatalf("ws: %v", ss)
	}
	if keyName("vless://u@h:1#%F0%9F%87%A9%F0%9F%87%AA%20DE") != "🇩🇪 DE" {
		t.Fatal("имя из фрагмента")
	}
	if _, err := parseVless("vless://u@h:443?security=reality"); err == nil {
		t.Fatal("reality без pbk должен отклоняться")
	}
}

// В нормальном режиме (ваш сервер жив через рабочий xray) временный xray не запускается вовсе.
func TestAutoHealthyNoTempXray(t *testing.T) {
	cfg = Config{AutoFails: 2, AutoRecover: 3}
	store = &Store{path: filepath.Join(t.TempDir(), "state.json"), st: defaultState()}
	store.st.Keys = []Key{{ID: "A", Name: "A", URL: "vless://u@a:443?security=reality&pbk=k#A"}}
	store.st.ActiveKey, store.st.PreferredKey, store.st.AppliedURL = "A", "A", store.st.Keys[0].URL
	calls := 0
	pingFn = func(keys []Key) map[string]*int { calls++; return map[string]*int{} }
	applyFn = func(st *State, stop bool) (string, error) {
		t.Fatal("лишнее применение")
		return "", nil
	}
	mainProbeReadyFn = func() bool { return true }
	ms := 60
	probeMainFn = func() *int { return &ms }
	for range 5 {
		autoTick()
	}
	if calls != 0 {
		t.Fatalf("временный xray запускался %d раз — должно быть 0", calls)
	}
}
