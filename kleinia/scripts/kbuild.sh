#!/bin/bash
# In-tree Kleinia kernel packaging (this repo = the kernel source line).
# Builds the kleinia kernel from the Fedora distro config baseline in
# kleinia/configs/, with ccache acceleration (icecc cluster when the
# wrapper is available, plain ccache otherwise). Out-of-tree build (O=).
# Usage: kleinia/scripts/kbuild.sh [fedora-config-file] [jobs]
# KTREE/O/FRAG/CCWRAP/BB/STAGE/REG are overridable via environment.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FEDCFG="${1:-$SCRIPT_DIR/../configs/fedora-7.2.11-base.config}"
JOBS="${2:-24}"

: "${KTREE:=$SCRIPT_DIR/../..}"
: "${O:=$KTREE/.build/kbuild-7211}"
: "${FRAG:=$SCRIPT_DIR/../configs/kleinia-7211.fragment}"
: "${CCWRAP:=/srv/kleinia-ws/acb/dist/tools/cc-gcc}"
# fall back to "ccache gcc": a bare `ccache` is not a compiler command —
# the kernel's Kconfig probe dies "ccache: unknown C compiler / Sorry,
# this C compiler is not supported" before any real compile (run 43074824048)
[ -x "$CCWRAP" ] || CCWRAP="ccache gcc"
export CCACHE_DIR="${CCACHE_DIR:-/home/builder/.cache/ccache-kernel}"
CCACHE_MAXSIZE=25G ccache -M 25G >/dev/null 2>&1 || true

mkdir -p "$O" "$CCACHE_DIR"
cd "$KTREE"

# 1) config: Fedora baseline + our fragment -> olddefconfig
cp -f "$FEDCFG" "$O/.config"
# merge_config.sh writes its scratch (mktemp ./.tmp.config.XXX) into the
# CWD, violating the O= "source tree stays pristine" contract — with a
# read-only tree (CI mounts /ws:ro) that mktemp dies. Run it from the
# writable O= dir instead (config paths are absolute).
( cd "$O" && "$KTREE/scripts/kconfig/merge_config.sh" -m -O "$O" "$FEDCFG" "$FRAG" >/dev/null )
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
# The 1Password item carries the PRIVATE KEY ONLY (bare PEM, no cert
# block — forensics run 43082507078; the dev tree's copy is key+cert).
# The build needs key+cert in one file (CONFIG_MODULE_SIG_KEY extraction)
# AND the public cert as a tree-local file (CONFIG_SYSTEM_TRUSTED_KEYS ->
# certs/module-signing.x509 — now COMMITTED: public material, same pair as
# every previous build, fingerprint sha256 D9:7D:D2:80…33:94). Splice the
# committed cert into the staged key when the cert block is missing.
[ -s "$KTREE/certs/module-signing.x509" ] || { echo "FATAL: certs/module-signing.x509 missing (committed public cert)"; exit 1; }
if ! grep -q 'BEGIN CERTIFICATE' "$KTREE/certs/module-signing.pem"; then
  cat "$KTREE/certs/module-signing.x509" >> "$KTREE/certs/module-signing.pem"
  echo "spliced the committed public cert into the staged private key"
fi
# modinst-phase signing anchors a non-./-relative CONFIG_MODULE_SIG_KEY at
# the OBJTREE: scripts/Makefile.modinst runs sign-file with cwd=O=, the
# cert comes from $(objtree)/certs/signing_key.x509 but the KEY is the raw
# config path (run 43083658099 died here on an SSL file error). Put the
# key where sign-file looks. O= is tmpfs and kartifact's devel tar excludes
# certs/*.pem + guards private keys, so this copy never reaches artifacts.
mkdir -p "$O/certs"
if ! cmp -s "$KTREE/certs/module-signing.pem" "$O/certs/module-signing.pem"; then
  install -m 600 "$KTREE/certs/module-signing.pem" "$O/certs/module-signing.pem"
  echo "staged the signing key into O=/certs for module signing"
fi
echo "== config OK, KVER=$(make O="$O" -s kernelrelease 2>/dev/null | tail -1) =="

# 3) build: CC wrapper = ccache -> icecc -> real gcc; HOSTCC stays local
echo "== building with -j$JOBS (ccache dir $CCACHE_DIR) =="
time make -j"$JOBS" O="$O" CC="$CCWRAP" 2>&1 | grep -vE "^  (CC|AR|LD|BTF|OBJCOPY|MODPOST|SIGN|UPD|WRAP|SYSHDR|HOSTCC|DTC|GZIP|MKELF|SOR)" | tail -40
KVER=$(sed -n 's/#define UTS_RELEASE "\(.*\)"/\1/p' "$O/include/generated/utsrelease.h")
test -s "$O/arch/x86/boot/bzImage" || { echo "FATAL: no bzImage"; exit 1; }
echo "== BUILD OK: $O/arch/x86/boot/bzImage (kernel $KVER) =="
ccache -s | head -12
