#!/usr/bin/env bash
# 差分对拍：同一批输入分别喂给旧版（1.8.2）与新版（2.0.0）的字节码，逐字节比较输出。
#
#   tools/fuzz/run.sh [旧版源码根] [新版源码根]
#
# 默认旧版取 ../../orig（与本仓库同级），新版取本仓库根。两边都只编译
# model / xray / inject / link 四个包（UI 与 android 无关的部分不需要）。
# 需要 ANDROID_SDK_ROOT 指向带 android-34 的 SDK（只用其中的 android.jar 做类路径）。
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
NEW="${2:-$(cd "$HERE/../.." && pwd)}"
OLD="${1:-$NEW/orig}"
SDK="${ANDROID_SDK_ROOT:-/root/android-sdk}"
AJAR="$SDK/platforms/android-34/android.jar"
JSON="$HERE/../../test/lib/json.jar"
OUT="${TMPDIR:-/tmp}/tpx-fuzz"
CP="$AJAR:$JSON"

for f in "$AJAR" "$JSON"; do
  [ -f "$f" ] || { echo "缺少 $f"; exit 2; }
done
# 两版的源码根不同：新版是 <根>/src/src，旧版是 <根>/src
jroot() { if [ -d "$1/src/com/lcs/tproxy" ]; then echo "$1/src"; else echo "$1/src/src"; fi; }
[ -d "$(jroot "$OLD")/com/lcs/tproxy" ] || { echo "找不到旧版源码：$OLD"; exit 2; }

rm -rf "$OUT"
mkdir -p "$OUT"

compile() {          # compile <源码根> <输出目录>
  local root="$1" dst="$2"
  local j
  j="$(jroot "$root")"
  javac -encoding UTF-8 -nowarn -Xlint:-options --release 11 -cp "$CP" -d "$dst" \
    $(find "$j/com/lcs/tproxy/model" "$j/com/lcs/tproxy/xray" \
           "$j/com/lcs/tproxy/inject" "$j/com/lcs/tproxy/link" \
           -name '*.java') \
    $(find "$HERE" -maxdepth 1 -name '*Diff.java' -o -maxdepth 1 -name '*Fuzz.java') \
    || return 1
}

echo "== 编译旧版 $OLD"
compile "$OLD" "$OUT/old" || exit 1
echo "== 编译新版 $NEW"
compile "$NEW" "$OUT/new" || exit 1

run() {              # run <类名> <输出文件后缀>
  local cls="com.lcs.tproxy.inject.$1" tag="$2"
  java -cp "$OUT/old:$CP" "$cls" > "$OUT/$tag.old" 2>"$OUT/$tag.old.err"
  java -cp "$OUT/new:$CP" "$cls" > "$OUT/$tag.new" 2>"$OUT/$tag.new.err"
  local d
  d=$(diff "$OUT/$tag.old" "$OUT/$tag.new" | grep -c '^[<>]' || true)
  printf '%-12s 行数 %-7s 差异 %s\n' "$1" "$(wc -l < "$OUT/$tag.new")" "$d"
  if [ "$d" != "0" ]; then diff "$OUT/$tag.old" "$OUT/$tag.new" | head -40; fi
}

echo "== 对拍（差异行数应为 0）"
run ConfDiff   conf
run ModelDiff  model
run IniFuzz    ini
run ReqFuzz    req
run InjectDiff inject

echo "== 输出留在 $OUT"
