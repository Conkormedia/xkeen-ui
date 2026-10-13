#!/bin/sh
# xkeen-ui — установка XKeen + Xray (сжатый, под слабые роутеры) + веб-панель на роутер Keenetic.
#
# Запуск на роутере (Entware, SSH root@<роутер> -p 222):
#   curl -fsSL https://raw.githubusercontent.com/Conkormedia/xkeen-ui/main/install.sh | sh
#
# Ключи:
#   --panel-only   только панель (XKeen уже стоит и настроен)
#   --uninstall    удалить панель (XKeen и Xray не трогает)
#   --version X    поставить конкретный релиз xkeen-ui (по умолчанию — последний)
set -u

REPO="Conkormedia/xkeen-ui"
VERSION="latest"
MODE="full"
WORK="/opt/tmp/xkeen-ui-install"
LOG="/opt/var/log/xkeen-ui-install.log"
UI_DIR="/opt/etc/xkeen-ui"
GEO_DIR="/opt/etc/xray/dat"
CONF_DIR="/opt/etc/xray/configs"
MIRROR="http://mirrors.nju.edu.cn/entware"
GH_PROXIES="https://gh-proxy.com https://ghfast.top"

while [ $# -gt 0 ]; do
  case "$1" in
    --panel-only) MODE="panel" ;;
    --uninstall) MODE="uninstall" ;;
    --version) VERSION="$2"; shift ;;
    *) echo "Неизвестный ключ: $1"; exit 2 ;;
  esac
  shift
done

if [ -t 1 ]; then G="$(printf '\033[32m')"; Y="$(printf '\033[33m')"; R="$(printf '\033[31m')"; B="$(printf '\033[1m')"; N="$(printf '\033[0m')"
else G=""; Y=""; R=""; B=""; N=""; fi
mkdir -p "$(dirname "$LOG")" 2>/dev/null
log()  { echo "$(date '+%F %T') $*" >>"$LOG" 2>/dev/null; }
step() { echo; echo "${B}== $*${N}"; log "== $*"; }
ok()   { echo "   ${G}✔${N} $*"; log "ok: $*"; }
warn() { echo "   ${Y}!${N} $*"; log "warn: $*"; }
die()  { echo; echo "${R}✘ $*${N}"; echo "   Подробности: $LOG"; log "FAIL: $*"; exit 1; }
# вопросы — с терминала, даже если скрипт пришёл через  curl | sh
ask()  { printf '%s' "$1" >/dev/tty; IFS= read -r REPLY </dev/tty || REPLY=""; }
ask_secret() { printf '%s' "$1" >/dev/tty; stty -echo </dev/tty 2>/dev/null; IFS= read -r REPLY </dev/tty || REPLY=""; stty echo </dev/tty 2>/dev/null; echo >/dev/tty; }

# ---------- проверки ----------
[ "$(id -u)" = 0 ] || die "Запустите от root (Entware SSH: ssh root@192.168.1.1 -p 222)"
[ -d /opt/etc ] && command -v opkg >/dev/null || die "Не найден Entware (/opt). Сначала установите Entware — см. README."
export PATH="/opt/sbin:/opt/bin:/opt/usr/sbin:/opt/usr/bin:$PATH"

ARCH=""
for a in $(opkg print-architecture 2>/dev/null | awk '{print $2}'); do
  case "$a" in
    mipsel-3.4*) ARCH=mipsel ;;
    mips-3.4*)   ARCH=mips ;;
    aarch64-3.10*) ARCH=aarch64 ;;
  esac
done
[ -n "$ARCH" ] || die "Архитектура Entware не поддерживается: $(opkg print-architecture | tr '\n' ' ')"

if [ "$MODE" = "uninstall" ]; then
  step "Удаление панели xkeen-ui"
  [ -x /opt/etc/init.d/S99xkeen-ui ] && /opt/etc/init.d/S99xkeen-ui stop >/dev/null 2>&1
  rm -f /opt/etc/init.d/S99xkeen-ui /opt/sbin/xkeen-ui
  ok "Панель удалена. Настройки остались в $UI_DIR (удалите вручную, если не нужны)."
  echo "   XKeen и Xray не тронуты. Удалить их: xkeen -remove"
  exit 0
fi

echo "${B}xkeen-ui: установка${N} (Entware $ARCH, режим: $MODE)"
log "start mode=$MODE arch=$ARCH version=$VERSION kernel=$(uname -r)"

FREE_KB=$(df -k /opt | awk 'NR==2{print $4}')
NEED_KB=14000; [ "$MODE" = "panel" ] && NEED_KB=4000
[ "${FREE_KB:-0}" -ge "$NEED_KB" ] || die "Мало места на /opt: свободно $((FREE_KB/1024)) МБ, нужно ~$((NEED_KB/1024)) МБ"
ok "Свободно на /opt: $((FREE_KB/1024)) МБ"

# ---------- opkg: зеркало и базовые пакеты ----------
step "Пакеты Entware"
opkg_ok() { opkg update >/dev/null 2>&1; }
if grep -q "bin.entware.net" /opt/etc/opkg.conf 2>/dev/null; then
  # bin.entware.net у части провайдеров тормозит до 1–2 КБ/с — проверяем и при необходимости ставим зеркало
  T0=$(date +%s)
  SRC="$(awk '/^src/{print $3; exit}' /opt/etc/opkg.conf)/Packages.gz"
  if command -v curl >/dev/null; then GETOK="curl -fsS -m 20 -o /tmp/.pk.gz $SRC"; else GETOK="wget -q -T 20 -O /tmp/.pk.gz $SRC"; fi
  if ! $GETOK >/dev/null 2>&1 || [ $(( $(date +%s) - T0 )) -gt 15 ]; then
    cp /opt/etc/opkg.conf /opt/etc/opkg.conf.bak-xkeen-ui
    sed -i "s#http://bin.entware.net#$MIRROR#" /opt/etc/opkg.conf
    warn "bin.entware.net медленный — переключил opkg на зеркало $MIRROR (копия: opkg.conf.bak-xkeen-ui)"
  fi
  rm -f /tmp/.pk.gz
fi
opkg_ok || die "opkg update не прошёл. Проверьте интернет на роутере и /opt/etc/opkg.conf"
opkg install curl tar ca-bundle >>"$LOG" 2>&1 || die "Не удалось установить curl/tar/ca-bundle"
ok "curl, tar, сертификаты"

# ---------- загрузка файлов релиза ----------
step "Загрузка файлов xkeen-ui ($VERSION)"
rm -rf "$WORK" && mkdir -p "$WORK" || die "Не создать $WORK"
if [ "$VERSION" = "latest" ]; then BASE="https://github.com/$REPO/releases/latest/download"
else BASE="https://github.com/$REPO/releases/download/v$VERSION"; fi

fetch() { # fetch <имя> — с GitHub, при неудаче — через прокси-зеркала GitHub
  for pre in "" $GH_PROXIES; do
    if [ -z "$pre" ]; then url="$BASE/$1"; else url="$pre/$BASE/$1"; fi
    if curl -fsSL --connect-timeout 10 -m 300 -o "$WORK/$1" "$url" 2>>"$LOG"; then
      [ -s "$WORK/$1" ] && return 0
    fi
    log "fetch fail: $url"
  done
  return 1
}
FILES="SHA256SUMS xkeen-ui-$ARCH"
[ "$MODE" = "full" ] && FILES="$FILES xray-$ARCH geosite.dat geoip.dat xkeen.tar.gz"
for f in $FILES; do
  fetch "$f" || die "Не удалось скачать $f (GitHub недоступен?)"
done
cd "$WORK" || die "нет $WORK"
for f in $FILES; do
  [ "$f" = SHA256SUMS ] && continue
  want=$(awk -v f="$f" '$2==f || $2=="*"f {print $1}' SHA256SUMS)
  got=$(sha256sum "$f" | cut -d' ' -f1)
  [ -n "$want" ] && [ "$want" = "$got" ] || die "Контрольная сумма $f не совпала — файл повреждён или подменён"
done
ok "Скачано и проверено: $(echo "$FILES" | wc -w) файлов"

# ---------- XKeen + Xray ----------
if [ "$MODE" = "full" ]; then
  step "Xray (сжатый, собран под ядра Keenetic)"
  chmod 755 "xray-$ARCH"
  ./"xray-$ARCH" version >"$WORK/xv" 2>&1 || die "Xray не запускается на этом роутере: $(head -3 "$WORK/xv")"
  ok "$(head -1 "$WORK/xv")"

  step "XKeen"
  if command -v xkeen >/dev/null 2>&1 && [ -d "$CONF_DIR" ]; then
    ok "XKeen уже установлен — только обновлю Xray и базы"
    xkeen -stop >/dev/null 2>&1
    [ -f /opt/sbin/xray ] && cp /opt/sbin/xray "/opt/sbin/xray.bak-xkeen-ui" 2>/dev/null
    cp "xray-$ARCH" /opt/sbin/xray && chmod 755 /opt/sbin/xray
  else
    cp "xray-$ARCH" /opt/sbin/xray && chmod 755 /opt/sbin/xray
    cp xkeen.tar.gz /opt/sbin/xkeen.tar.gz
    ( cd /opt/sbin && tar -xzf xkeen.tar.gz && rm -f xkeen.tar.gz ) || die "Не распаковать xkeen.tar.gz"
    echo "   Офлайн-установка XKeen (несколько минут, ставит нужные пакеты)…"
    /opt/sbin/xkeen -io </dev/null >>"$LOG" 2>&1
    [ -d "$CONF_DIR" ] || die "XKeen не установился — смотрите $LOG"
    ok "XKeen установлен"
  fi
  mkdir -p "$GEO_DIR"
  cp geosite.dat geoip.dat "$GEO_DIR/" && ok "Базы: geosite (v2fly, $(( $(wc -c <geosite.dat)/1024 )) КБ), geoip (ru/private/telegram, $(( $(wc -c <geoip.dat)/1024 )) КБ)"

  step "Режим перехвата TProxy"
  # Hybrid (REDIRECT для TCP) на ряде прошивок Keenetic ломает сеть: Xray получает адрес роутера
  # вместо адреса назначения («loopback connection detected»). TProxy этой проблемы не имеет.
  [ -f "$CONF_DIR/03_inbounds.json" ] && cp "$CONF_DIR/03_inbounds.json" "/opt/etc/xray/03_inbounds.bak-xkeen-ui"
  cat >"$CONF_DIR/03_inbounds.json" <<'EOF'
{
  "inbounds": [
    {
      "protocol": "tunnel",
      "port": 1181,
      "settings": { "allowedNetwork": "tcp,udp", "followRedirect": true },
      "streamSettings": { "sockopt": { "tproxy": "tproxy" } },
      "sniffing": { "enabled": true, "routeOnly": true, "destOverride": ["http", "tls", "quic"] },
      "tag": "tproxy"
    },
    {
      "protocol": "tunnel",
      "port": 1191,
      "settings": { "allowedNetwork": "tcp,udp", "followRedirect": true },
      "streamSettings": { "sockopt": { "tproxy": "tproxy" } },
      "tag": "force-proxy-tproxy"
    }
  ]
}
EOF
  # лог Xray выключен: он пишет каждое соединение во флеш-память
  [ -f "$CONF_DIR/01_log.json" ] && sed -i 's/"loglevel": *"[a-z]*"/"loglevel": "none"/' "$CONF_DIR/01_log.json"
  ok "TProxy (порты 1181/1191), лог Xray выключен"

  step "Российские подсети мимо Xray (GeoIPSET)"
  if xkeen -gips </dev/null >>"$LOG" 2>&1; then ok "GeoIPSET установлен — RU-трафик не нагружает процессор"
  else warn "GeoIPSET не установился (GitHub недоступен?) — позже: xkeen -gips"; fi
fi

# ---------- панель ----------
step "Панель xkeen-ui"
[ -x /opt/etc/init.d/S99xkeen-ui ] && /opt/etc/init.d/S99xkeen-ui stop >/dev/null 2>&1
cp "xkeen-ui-$ARCH" /opt/sbin/xkeen-ui && chmod 755 /opt/sbin/xkeen-ui || die "Не скопировать панель"
/opt/sbin/xkeen-ui version >/dev/null 2>&1 || die "Панель не запускается на этом роутере"
mkdir -p "$UI_DIR" && chmod 700 "$UI_DIR"
cat >/opt/etc/init.d/S99xkeen-ui <<'EOF'
#!/bin/sh
# xkeen-ui — веб-панель XKeen (http://<адрес роутера>:8088, только домашняя сеть)
ENABLED=yes
PROCS=xkeen-ui
ARGS="-config /opt/etc/xkeen-ui/config.json"
PREARGS=""
DESC=$PROCS
PATH=/opt/sbin:/opt/bin:/opt/usr/sbin:/opt/usr/bin:/usr/sbin:/usr/bin:/sbin:/bin

. /opt/etc/init.d/rc.func
EOF
chmod 755 /opt/etc/init.d/S99xkeen-ui

if ! grep -q '"password_hash": *"pbkdf2' "$UI_DIR/config.json" 2>/dev/null; then
  while :; do
    ask_secret "   Придумайте пароль для входа в панель (от 6 символов): "; P1="$REPLY"
    ask_secret "   Повторите пароль: "; P2="$REPLY"
    [ "$P1" = "$P2" ] && [ ${#P1} -ge 6 ] && break
    echo "   ${Y}Пароли не совпадают или короче 6 символов — ещё раз${N}"
  done
  printf '%s\n' "$P1" | /opt/sbin/xkeen-ui passwd >/dev/null || die "Не удалось сохранить пароль"
  unset P1 P2 REPLY
  ok "Пароль сохранён (сменить: xkeen-ui passwd)"
else
  ok "Пароль уже задан ранее (сменить: xkeen-ui passwd)"
fi
/opt/etc/init.d/S99xkeen-ui start >/dev/null 2>&1
sleep 2
ADDR=$(netstat -tln 2>/dev/null | awk '/:8088 /{print $4; exit}')
[ -n "$ADDR" ] || die "Панель не запустилась — смотрите: /opt/sbin/xkeen-ui -config $UI_DIR/config.json"
ok "Панель работает: http://$ADDR  ($(/opt/sbin/xkeen-ui version))"
rm -rf "$WORK"

# ---------- что осталось сделать в веб-интерфейсе Keenetic ----------
BUSY443=""
netstat -tln 2>/dev/null | grep -qE ':443 ' && BUSY443=1
echo
echo "${B}Готово. Осталось в веб-интерфейсе роутера:${N}"
I=1
if [ -n "$BUSY443" ]; then
  echo "  $I. ${Y}Порт 443 занят веб-интерфейсом роутера${N} — без этого XKeen в режиме TProxy не запустится."
  echo "     «Пользователи и доступ» → порт HTTPS веб-интерфейса: 443 → 8443."; I=$((I+1))
fi
echo "  $I. «Интернет» → «Приоритеты подключений» → «Политики доступа в интернет» → добавить политику"
echo "     с именем ${B}xkeen${N} (те же подключения, что в основной) и перенести в неё устройства или весь"
echo "     сегмент «Домашняя сеть». ${Y}Без политики xkeen XKeen проксирует ВСЮ сеть.${N}"; I=$((I+1))
echo "  $I. Серверы в доме (NAS, медиасервер и т.п.), которым VPN не нужен, — в отдельную политику, например ${B}direct${N}."; I=$((I+1))
echo "  $I. Откройте http://$ADDR → вставьте подписку или ключ vless:// → «Пинг всех» → «Выбрать» → «Применить на роутере»."
echo
echo "Подробности и решение проблем: https://github.com/$REPO#readme"
log "done"
