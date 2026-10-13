package main

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// подменяются в тестах
var (
	pingFn  = pingKeys
	applyFn = applyToRouter
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
	full := mode == "direct" || float64(time.Now().Unix())-au.FullTS > cfg.AutoFullPing.Seconds()
	var probe []Key
	if full {
		probe = snap.Keys
	} else {
		for _, id := range []string{pref, act} {
			if k := snap.key(id); k != nil && (len(probe) == 0 || probe[0].ID != id) {
				probe = append(probe, *k)
			}
		}
	}
	// подписки ротируют sid/sni: если на роутере применена старая ссылка, проверяем именно её
	appliedDiffers := false
	if k := snap.key(act); k != nil && snap.AppliedURL != "" && snap.AppliedURL != k.URL && mode != "direct" {
		appliedDiffers = true
		probe = append(probe, Key{ID: "__applied", URL: snap.AppliedURL})
	}
	p := pingFn(probe)
	if full {
		au.FullTS = float64(time.Now().Unix())
	}
	prefOK, actOK := p[pref] != nil, p[act] != nil
	refresh := false // применённые параметры устарели, свежие из подписки работают — переприменить тот же сервер
	if appliedDiffers && p["__applied"] == nil && actOK {
		refresh = true
	}
	delete(p, "__applied")
	if prefOK {
		au.PrefOK++
	} else {
		au.PrefOK = 0
	}
	target, stop := "", false
	switch {
	case refresh:
		target = act
	case mode == "direct":
		if prefOK {
			target = pref
		} else {
			target = fastest(&snap, p, nil)
		}
	case mode == "fallback" && prefOK && au.PrefOK >= cfg.AutoRecover:
		target = pref
	default:
		ok := actOK
		if mode == "preferred" {
			ok = prefOK
		}
		if ok {
			au.Fails = 0
		} else {
			au.Fails++
		}
		if au.Fails >= cfg.AutoFails {
			if !full { // для выбора самого быстрого нужна полная картина
				for k, v := range pingFn(snap.Keys) {
					p[k] = v
				}
				au.FullTS, full = float64(time.Now().Unix()), true
			}
			excl := map[string]bool{}
			for _, id := range []string{pref, act} {
				if p[id] == nil {
					excl[id] = true
				}
			}
			if target = fastest(&snap, p, excl); target == "" {
				stop = true
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
