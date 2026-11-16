#!/bin/bash
# Build the Kleinia kernel (Linux 7.2.11 stable + Kleinia patch line) from a
# Fedora distro config baseline, with ccache (outer) + icecc cluster (inner)
# acceleration. Out-of-tree build (O=).
# Usage: kbuild.sh [fedora-config-file] [jobs]
#        (config defaults to configs/fedora-7.2.11-base.config in this repo)
# KTREE/O/CCWRAP are overridable via environment (transitional defaults
# point at the pre-migration workspace; the in-tree packaging in
# kleinia-os/linux supersedes this). FRAG defaults to
# configs/kleinia-7211.fragment in this repo.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FEDCFG="${1:-$SCRIPT_DIR/../configs/fedora-7.2.11-base.config}"
JOBS="${2:-24}"

: "${KTREE:=/srv/kleinia-ws/os_ext-7.2.11}"
: "${O:=/srv/kleinia-ws/acb/dist/kbuild-7211}"
: "${FRAG:=$SCRIPT_DIR/../configs/kleinia-7211.fragment}"
: "${CCWRAP:=/srv/kleinia-ws/acb/dist/tools/cc-gcc}"
export CCACHE_DIR="${CCACHE_DIR:-/home/builder/.cache/ccache-kernel}"
CCACHE_MAXSIZE=25G ccache -M 25G >/dev/null 2>&1 || true

mkdir -p "$O" "$CCACHE_DIR"
cd "$KTREE"

# 1) config: Fedora baseline + our fragment -> olddefconfig
cp -f "$FEDCFG" "$O/.config"
./scripts/kconfig/merge_config.sh -m -O "$O" "$FEDCFG" "$FRAG" >/dev/null
make O="$O" olddefconfig >/dev/null

# 2) hard-verify the options that must not silently drop (renamed symbols etc.)
need() { grep -q "^$1=$2" "$O/.config" || { echo "FATAL: $1 != $2 after olddefconfig"; grep "^$1" "$O/.config" || true; exit 1; }; }
need CONFIG_AGENT y
need CONFIG_AGENT_FS y
need CONFIG_AF_AGENT y
need CONFIG_IOSCHED_EXT y
need CONFIG_SCHED_CLASS_EXT y
need CONFIG_DEBUG_INFO_BTF y
need CONFIG_MEMCG y
need CONFIG_EXT4_FS y
grep -q '^CONFIG_LOCALVERSION="-kleinia"' "$O/.config" || { echo "FATAL: LOCALVERSION wrong"; exit 1; }
need CONFIG_MODULE_SIG_ALL y
grep -q '^CONFIG_MODULE_SIG_KEY="certs/module-signing.pem"' "$O/.config" || { echo "FATAL: MODULE_SIG_KEY wrong"; exit 1; }
[ -s "$KTREE/certs/module-signing.pem" ] || { echo "FATAL: certs/module-signing.pem missing (fetch from 1Password KleiniaOS vault)"; exit 1; }
echo "== config OK, KVER=$(make O="$O" -s kernelrelease 2>/dev/null | tail -1) =="

# 3) build: CC wrapper = ccache -> icecc -> real gcc; HOSTCC stays local
echo "== building with -j$JOBS (ccache dir $CCACHE_DIR) =="
time make -j"$JOBS" O="$O" CC="$CCWRAP" 2>&1 | grep -vE "^  (CC|AR|LD|BTF|OBJCOPY|MODPOST|SIGN|UPD|WRAP|SYSHDR|HOSTCC|DTC|GZIP|MKELF|SOR)" | tail -40
KVER=$(sed -n 's/#define UTS_RELEASE "\(.*\)"/\1/p' "$O/include/generated/utsrelease.h")
test -s "$O/arch/x86/boot/bzImage" || { echo "FATAL: no bzImage"; exit 1; }
echo "== BUILD OK: $O/arch/x86/boot/bzImage (kernel $KVER) =="
ccache -s | head -12
