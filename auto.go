package main

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// подменяются в тестах
var (
	refreshSubsFn    = refreshSubs
	pingFn           = pingKeys
	applyFn          = applyToRouter
	probeMainFn      = probeMain
	mainProbeReadyFn = mainProbeReady
)

// Результаты пинга — только в памяти (не изнашиваем флеш роутера).
var (
	rtMu    sync.Mutex
	pings   = map[string]*int{}
	pingsAt string
)

func mergePings(p map[string]*int, full bool) {
	rtMu.Lock()
	defer rtMu.Unlock()
	for k, v := range p {
		pings[k] = v
	}
	if full {
		pingsAt = nowStr()
	}
}

func pingOf(id string) *int {
	rtMu.Lock()
	defer rtMu.Unlock()
	return pings[id]
}

func autoEvent(a *Auto, msg string) {
	a.Events = append([]string{time.Now().Format("02.01 15:04") + " " + msg}, a.Events...)
	if len(a.Events) > 30 {
		a.Events = a.Events[:30]
	}
}

func keyNameOf(st *State, id string) string {
	if k := st.key(id); k != nil {
		return k.Name
	}
	if id == "" {
		return "—"
	}
	return id
}

// fastest — самый быстрый живой сервер (без пропавших из подписки и без exclude).
func fastest(st *State, p map[string]*int, exclude map[string]bool) string {
	best, bestMs := "", 1<<30
	for _, k := range st.Keys {
		if k.Stale || exclude[k.ID] {
			continue
		}
		if v := p[k.ID]; v != nil && *v < bestMs {
			best, bestMs = k.ID, *v
		}
	}
	return best
}

// autoTick — одна проверка: держим «ваш» сервер; при отказе — самый быстрый; если никто не жив — напрямую.
//
// Экономия процессора роутера: активный сервер проверяется через рабочий xray XKeen (служебный
// socks-вход panel-probe), без запуска временного xray. Временный xray (распаковка UPX ~35 МБ и
// пара секунд CPU) нужен только для «вашего» сервера, пока работает резервный, и для поиска живых при отказе.
func autoTick() {
	store.mu.Lock()
	if !store.st.AutoEnabled || !store.st.Enabled || len(store.st.Keys) == 0 {
		store.mu.Unlock()
		return
	}
	snap := store.st // копия значений для замера вне блокировки
	snap.Keys = append([]Key(nil), store.st.Keys...)
	au := store.st.Auto
	store.mu.Unlock()

	mode := au.Mode
	if mode == "" {
		mode = "preferred"
	}
	pref, act := snap.preferred(), snap.ActiveKey
	now := float64(time.Now().Unix())
	p := map[string]*int{}

	// 1) путь через роутер — рабочий xray (если служебный вход уже есть в конфиге)
	viaMain := mode != "direct" && mainProbeReadyFn()
	mainOK := false
	if viaMain {
		if v := probeMainFn(); v != nil {
			mainOK, p[act] = true, v
		}
	}
	// 2) временный xray — только для того, что через рабочий не проверить
	full := mode == "direct" && now-au.FullTS >= cfg.AutoFullPing.Seconds()
	var need []Key
	add := func(id string) {
		if k := snap.key(id); k != nil && p[id] == nil {
			for _, n := range need {
				if n.ID == id {
					return
				}
			}
			need = append(need, *k)
		}
	}
	switch {
	case full:
		if now-lastSubRefresh(&snap) > 600 {
			if keys, ok := refreshSubsFn(); ok {
				snap.Keys = keys
			}
		}
		need = snap.Keys
	default:
		if pref != act || mode == "direct" {
			add(pref)
		}
		if !mainOK && mode != "direct" {
			add(act) // свежие параметры активного из подписки — живы?
		}
	}
	if len(need) > 0 {
		for k, v := range pingFn(need) {
			if p[k] == nil {
				p[k] = v
			}
		}
		if pingFailed() { // замер не состоялся (память) — это не отказ серверов, ждём следующую проверку
			return
		}
	}
	if full {
		au.FullTS = now
	}

	prefOK := p[pref] != nil
	routerOK := mainOK || (!viaMain && p[act] != nil) // без служебного входа — как раньше, по временному
	freshActOK := p[act] != nil
	if prefOK {
		au.PrefOK++
	} else {
		au.PrefOK = 0
	}
	target, stop, refresh := "", false, false
	switch {
	case mode == "direct":
		if prefOK {
			target = pref
		} else {
			target = fastest(&snap, p, nil)
		}
	case mode == "fallback" && prefOK && au.PrefOK >= cfg.AutoRecover:
		target = pref
	default:
		if routerOK {
			au.Fails = 0
		} else {
			au.Fails++
		}
		if au.Fails >= cfg.AutoFails {
			if viaMain && freshActOK {
				// рабочий xray не проходит, а тот же сервер со свежими параметрами из подписки отвечает:
				// подписка сменила sid/sni (или xray завис) — переприменить тот же сервер
				target, refresh = act, true
				break
			}
			for k, v := range pingFn(snap.Keys) { // полная картина, чтобы выбрать самый быстрый
				if p[k] == nil {
					p[k] = v
				}
			}
			if pingFailed() { // замер не состоялся — не останавливать VPN по ложному «все мертвы»
				return
			}
			full = true
			excl := map[string]bool{act: true}
			if !prefOK {
				excl[pref] = true
			}
			if target = fastest(&snap, p, excl); target == "" {
				// никто не отвечает: сначала обновить подписку и перемерить, и только потом — напрямую
				if t, p2, done := retryAfterRefresh(&snap, &au); done && t != "" {
					target = t
					for k, v := range p2 {
						p[k] = v
					}
				} else if pingFailed() {
					return
				} else {
					stop = true
				}
			}
		}
	}
	au.LastCheck = nowStr()
	mergePings(p, full)

	store.mu.Lock()
	defer store.mu.Unlock()
	st := &store.st
	// пользователь мог за это время сменить сервер или выключить автовыбор — не вмешиваемся
	if !st.AutoEnabled || !st.Enabled || st.ActiveKey != act {
		st.Auto.LastCheck = au.LastCheck
		return
	}
	switched := false
	if stop {
		if _, err := applyFn(st, true); err != nil {
			autoEvent(&au, "ошибка остановки: "+err.Error())
		} else {
			autoEvent(&au, "ни один сервер не отвечает — трафик напрямую (XKeen остановлен)")
		}
		au.Mode, au.Fails, switched = "direct", 0, true
	} else if refresh && target == act {
		if _, err := applyFn(st, false); err != nil {
			autoEvent(&au, "ошибка применения: "+err.Error())
		} else {
			st.LastApply = nowStr()
			autoEvent(&au, keyNameOf(st, act)+": старые параметры перестали работать — применены свежие из подписки")
		}
		au.Fails, switched = 0, true
	} else if target != "" && (target != act || mode == "direct") {
		st.ActiveKey = target
		if _, err := applyFn(st, false); err != nil {
			st.ActiveKey = act
			autoEvent(&au, "ошибка применения: "+err.Error())
		} else {
			st.LastApply = nowStr()
			name, ms := keyNameOf(st, target), "—"
			if v := p[target]; v != nil {
				ms = fmt.Sprintf("%d мс", *v)
			}
			newMode := "fallback"
			if target == pref {
				newMode = "preferred"
			}
			switch {
			case newMode == "preferred" && mode == "direct":
				autoEvent(&au, "вернулся на ваш сервер: "+name+" — серверы снова отвечают")
			case newMode == "preferred":
				autoEvent(&au, "вернулся на ваш сервер: "+name)
			case mode == "direct":
				autoEvent(&au, fmt.Sprintf("серверы снова отвечают → %s (%s)", name, ms))
			default:
				autoEvent(&au, fmt.Sprintf("%s не отвечает → %s (%s)", keyNameOf(st, act), name, ms))
			}
			au.Mode, au.Fails = newMode, 0
		}
		switched = true
	}
	st.Auto = au
	if switched { // на диск — только переключения
		if err := store.save(); err != nil {
			log.Println("save:", err)
		}
	}
}

func autoLoop() {
	for {
		time.Sleep(cfg.AutoInterval)
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Println("auto panic:", r)
				}
			}()
			autoTick()
		}()
	}
}

// subLoop — автообновление подписок по их интервалу.
func subLoop() {
	for {
		time.Sleep(time.Minute)
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Println("sub panic:", r)
				}
			}()
			subTick()
			refilterTick()
		}()
	}
}

func subTick() {
	store.mu.Lock()
	defer store.mu.Unlock()
	st := &store.st
	now := float64(time.Now().Unix())
	changed, needApply := false, false
	for i := range st.Subs {
		sub := &st.Subs[i]
		if now-sub.UpdatedTS < float64(sub.IntervalH*3600) {
			continue
		}
		changed = true
		c, err := syncSubscription(st, sub)
		if err != nil {
			sub.Error = err.Error()
			sub.UpdatedTS = now - float64(sub.IntervalH*3600) + 600 // повтор через 10 минут
			continue
		}
		needApply = needApply || c
	}
	if needApply && st.Enabled && st.LastApply != "" && st.Auto.Mode != "direct" {
		if out, err := applyFn(st, false); err != nil {
			st.LastLog = tail("Автообновление подписки: ошибка применения\n"+err.Error(), 4000)
		} else {
			st.LastApply = nowStr()
			st.LastLog = tail("Подписка обновилась, параметры активного сервера изменились — применено автоматически\n"+out, 4000)
		}
	}
	if changed {
		_ = store.save()
	}
}

// pingFailed — последний замер не состоялся (в тестах pingFn подменён, pingErr пуст).
func pingFailed() bool {
	xrayMu.Lock()
	defer xrayMu.Unlock()
	return pingErr != ""
}

// refreshSubs — обновить все подписки сейчас (провайдер мог сменить адреса серверов).
// Возвращает свежий список ключей; ok=false — обновить не удалось.
func refreshSubs() ([]Key, bool) {
	store.mu.Lock()
	defer store.mu.Unlock()
	st := &store.st
	ok := false
	for i := range st.Subs {
		if _, err := syncSubscription(st, &st.Subs[i]); err != nil {
			st.Subs[i].Error = err.Error()
		} else {
			ok = true
		}
	}
	if len(st.Subs) > 0 {
		_ = store.save()
	}
	return append([]Key(nil), st.Keys...), ok
}

// lastSubRefresh — когда последний раз обновлялась любая подписка (unix).
func lastSubRefresh(st *State) float64 {
	var t float64
	for _, s := range st.Subs {
		if s.UpdatedTS > t {
			t = s.UpdatedTS
		}
	}
	return t
}

// retryAfterRefresh — «никто не отвечает»: обновить подписки и перемерить все серверы.
// Возвращает самый быстрый живой сервер (или "") и свежие замеры.
func retryAfterRefresh(snap *State, au *Auto) (string, map[string]*int, bool) {
	keys, ok := refreshSubsFn()
	if !ok {
		return "", nil, false
	}
	snap.Keys = keys
	p := pingFn(keys)
	if pingFailed() {
		return "", nil, false
	}
	autoEvent(au, "серверы не отвечали — обновил подписку и перемерил")
	return fastest(snap, p, nil), p, true
}
