package main

import (
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
	"strings"
)

// parseVless: vless://uuid@host:port?params#name -> outbound Xray (tag "proxy").
func parseVless(raw string) (map[string]any, error) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "vless://") {
		return nil, errors.New("поддерживаются ключи vless:// (VLESS + Reality/TLS)")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("не удалось разобрать ключ")
	}
	host, portS := u.Hostname(), u.Port()
	port, _ := strconv.Atoi(portS)
	if u.User == nil || u.User.Username() == "" || host == "" || port == 0 {
		return nil, errors.New("в ключе нет uuid, адреса или порта")
	}
	q := u.Query()
	get := func(k, def string) string {
		if v := q.Get(k); v != "" {
			return v
		}
		return def
	}
	network, security := get("type", "tcp"), get("security", "none")

	user := map[string]any{"id": u.User.Username(), "encryption": get("encryption", "none")}
	if f := q.Get("flow"); f != "" {
		user["flow"] = f
	}
	stream := map[string]any{"network": network, "security": security}
	switch security {
	case "reality":
		if q.Get("pbk") == "" {
			return nil, errors.New("для Reality нужен параметр pbk (публичный ключ)")
		}
		stream["realitySettings"] = map[string]any{
			"serverName": q.Get("sni"), "fingerprint": get("fp", "chrome"),
			"publicKey": q.Get("pbk"), "shortId": q.Get("sid"), "spiderX": get("spx", "/"),
		}
	case "tls":
		tls := map[string]any{"serverName": get("sni", host), "fingerprint": get("fp", "chrome")}
		if a := q.Get("alpn"); a != "" {
			tls["alpn"] = strings.Split(a, ",")
		}
		stream["tlsSettings"] = tls
	}
	switch network {
	case "xhttp", "splithttp":
		stream["network"] = "xhttp"
		x := map[string]any{"path": get("path", "/"), "mode": get("mode", "auto")}
		if h := q.Get("host"); h != "" {
			x["host"] = h
		}
		if e := q.Get("extra"); e != "" {
			var extra any
			if json.Unmarshal([]byte(e), &extra) == nil {
				x["extra"] = extra
			}
		}
		stream["xhttpSettings"] = x
	case "ws":
		headers := map[string]any{}
		if h := q.Get("host"); h != "" {
			headers["Host"] = h
		}
		stream["wsSettings"] = map[string]any{"path": get("path", "/"), "headers": headers}
	case "grpc":
		stream["grpcSettings"] = map[string]any{"serviceName": q.Get("serviceName")}
	case "tcp":
		if q.Get("headerType") == "http" {
			stream["tcpSettings"] = map[string]any{"header": map[string]any{"type": "http"}}
		}
	}
	return map[string]any{
		"tag":      "proxy",
		"protocol": "vless",
		"settings": map[string]any{"vnext": []any{map[string]any{
			"address": host, "port": port, "users": []any{user},
		}}},
		"streamSettings": stream,
	}, nil
}

// coreSig — «личность» сервера без параметров, которые подписки ротируют при каждой выдаче
// (sid, sni, spx, fp): адрес, порт, uuid, ключ Reality, защита, транспорт, flow, путь.
func coreSig(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return raw
	}
	q := u.Query()
	user := ""
	if u.User != nil {
		user = u.User.Username()
	}
	return strings.Join([]string{u.Hostname(), u.Port(), user, q.Get("pbk"), q.Get("security"),
		q.Get("type"), q.Get("flow"), q.Get("path"), q.Get("serviceName"), q.Get("mode")}, "|")
}

func keyName(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "ключ"
	}
	if u.Fragment != "" {
		return u.Fragment
	}
	if h := u.Hostname(); h != "" {
		return h
	}
	return "ключ"
}

// keyMeta — что показываем в списке: адрес, порт, транспорт, защита.
func keyMeta(raw string) (host string, port int, network, security string) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", 0, "", ""
	}
	port, _ = strconv.Atoi(u.Port())
	q := u.Query()
	network, security = q.Get("type"), q.Get("security")
	if network == "" {
		network = "tcp"
	}
	if security == "" {
		security = "none"
	}
	return u.Hostname(), port, network, security
}
