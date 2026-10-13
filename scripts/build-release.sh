#!/usr/bin/env bash
# Сборка релиза xkeen-ui: Xray и панель под роутеры Keenetic + базы + установщики Entware.
#
# Нужно: Go >= 1.27 (рантайм, который на ядрах < 5.1 не зовёт futex_time64), upx, git, curl, shasum/sha256sum.
# Запуск:  scripts/build-release.sh 1.0.1      → всё в dist/release/
set -euo pipefail

VERSION="${1:?укажите версию, например 1.0.1}"
XRAY_VERSION="${XRAY_VERSION:-v26.3.27}"
XKEEN_VERSION="${XKEEN_VERSION:-2.1}"
XKEEN_SHA256="${XKEEN_SHA256:-4b9350b11fab7fd3e4973db609db0fb780994f4b5ab0096f0549bc52acac8c73}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/dist/release"
WORK="$ROOT/dist/work"

need() { command -v "$1" >/dev/null || { echo "нужен $1" >&2; exit 1; }; }
need go; need upx; need git; need curl
GOV=$(go env GOVERSION | sed 's/go//'); case "$GOV" in 1.2[7-9]*|1.[3-9]*|[2-9]*) ;; *) echo "нужен Go >= 1.27 (сейчас $GOV)" >&2; exit 1;; esac
sha() { if command -v sha256sum >/dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }

rm -rf "$OUT" && mkdir -p "$OUT" "$WORK"

# Архитектуры Entware на Keenetic → Go
#   mipsel-3.4  (MT7621/MT7628 …) → mipsle softfloat   (у MT7621 нет FPU)
#   mips-3.4                       → mips   softfloat
#   aarch64-3.10                   → arm64
TARGETS="mipsel:mipsle:softfloat mips:mips:softfloat aarch64:arm64:"

echo "== Xray $XRAY_VERSION из исходников XTLS"
if [ ! -d "$WORK/xray-src/.git" ] || [ "$(git -C "$WORK/xray-src" describe --tags 2>/dev/null)" != "$XRAY_VERSION" ]; then
  rm -rf "$WORK/xray-src"
  git -c advice.detachedHead=false clone -q --depth 1 --branch "$XRAY_VERSION" https://github.com/XTLS/Xray-core.git "$WORK/xray-src"
fi
for t in $TARGETS; do
  IFS=: read -r ent goarch gomips <<<"$t"
  ( cd "$WORK/xray-src" && CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" GOMIPS="$gomips" GOTOOLCHAIN=local \
      go build -trimpath -buildvcs=false -ldflags "-s -w -buildid=" -o "$OUT/xray-$ent" ./main )
  upx --best --lzma -q "$OUT/xray-$ent" >/dev/null
  echo "   xray-$ent  $(wc -c <"$OUT/xray-$ent") байт"
done

echo "== панель xkeen-ui $VERSION"
( cd "$ROOT" && go test ./... >/dev/null )
for t in $TARGETS; do
  IFS=: read -r ent goarch gomips <<<"$t"
  ( cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" GOMIPS="$gomips" \
      go build -trimpath -ldflags "-s -w -buildid= -X main.version=$VERSION" -o "$OUT/xkeen-ui-$ent" . )
  upx --best --lzma -q "$OUT/xkeen-ui-$ent" >/dev/null
  echo "   xkeen-ui-$ent  $(wc -c <"$OUT/xkeen-ui-$ent") байт"
done

echo "== базы"
# geosite — свежая v2fly dlc.dat (2,3 МБ) с проверкой суммы
curl -fsSL -o "$OUT/geosite.dat" https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat
want=$(curl -fsSL https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat.sha256sum | cut -d' ' -f1)
[ "$(sha "$OUT/geosite.dat" | cut -d' ' -f1)" = "$want" ] || { echo "geosite: сумма не совпала" >&2; exit 1; }
# geoip — компактная (~350 КБ): ru и private из v2fly, telegram из Loyalsoldier (полные базы ~20 МБ не влезают)
GOBIN="$WORK/bin" go install github.com/v2fly/geoip@latest
curl -fsSL -o "$WORK/v2fly-geoip.dat" https://github.com/v2fly/geoip/releases/latest/download/geoip.dat
curl -fsSL -o "$WORK/ls-geoip.dat" https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat
cat >"$WORK/geoip.json" <<EOF
{"input":[
  {"type":"v2rayGeoIPDat","action":"add","args":{"uri":"$WORK/v2fly-geoip.dat","wantedList":["ru","private"]}},
  {"type":"v2rayGeoIPDat","action":"add","args":{"uri":"$WORK/ls-geoip.dat","wantedList":["telegram"]}}],
 "output":[{"type":"v2rayGeoIPDat","action":"output","args":{"outputDir":"$OUT","outputName":"geoip.dat","wantedList":["ru","private","telegram"]}}]}
EOF
( cd "$WORK" && "$WORK/bin/geoip" -c "$WORK/geoip.json" >/dev/null )
echo "   geosite.dat $(wc -c <"$OUT/geosite.dat") · geoip.dat $(wc -c <"$OUT/geoip.dat")"

echo "== XKeen $XKEEN_VERSION (офлайн-установка)"
curl -fsSL -o "$OUT/xkeen.tar.gz" "https://github.com/jameszeroX/XKeen/releases/download/$XKEEN_VERSION/xkeen.tar.gz"
[ "$(sha "$OUT/xkeen.tar.gz" | cut -d' ' -f1)" = "$XKEEN_SHA256" ] || { echo "xkeen.tar.gz: сумма не совпала" >&2; exit 1; }

echo "== установщики Entware с зеркалом (bin.entware.net в РФ часто душат)"
MIRROR="http://mirrors.nju.edu.cn/entware"
for pair in mipsel:mipselsf-k3.4 mips:mipssf-k3.4 aarch64:aarch64-k3.10; do
  ent=${pair%%:*}; feed=${pair#*:}
  d="$WORK/inst-$ent"; rm -rf "$d" && mkdir -p "$d/root"
  curl -fsSL -o "$d/orig.tar.gz" "$MIRROR/$feed/installer/${ent}-installer.tar.gz"
  tar xzpf "$d/orig.tar.gz" -C "$d/root"
  sed -i.bak "s#http://bin.entware.net#$MIRROR#" "$d/root/etc/opkg.conf" && rm -f "$d/root/etc/opkg.conf.bak"
  grep -q "$MIRROR" "$d/root/etc/opkg.conf"
  ( cd "$d/root" && COPYFILE_DISABLE=1 tar --uid 0 --gid 0 -czf "$OUT/entware-installer-$ent-mirror.tar.gz" * 2>/dev/null \
    || tar --owner=0 --group=0 -czf "$OUT/entware-installer-$ent-mirror.tar.gz" * )
done

cp "$ROOT/install.sh" "$OUT/install.sh"
( cd "$OUT" && sha * 2>/dev/null | grep -v SHA256SUMS > SHA256SUMS )
echo "== готово: $OUT"
ls -la "$OUT"
