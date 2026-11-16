#!/bin/bash
# After kbuild.sh: produce
#  (a) OCI artifact kleinia-kernel:<KVER> (kernel + modules tree, bootc
#      layout), plus :<KVER>.<SEQ> when SEQ is set (CI sequence tags)
#  (b) OCI artifact kleinia-kernel-devel:<KVER> (same tags) — the prepared
#      out-of-tree build dir (Module.symvers, .config, scripts, headers)
#      so external modules compile against exactly this kernel, plus the
#      kernel-bits header set (vmlinux.h + tools headers + UAPI acb.h) at
#      /usr/src/kleinia-kernel-bits for agent userspace/BPF builds
# Uses rootless podman on the dev box. CI (kleinia-os/linux
# .github/workflows/kernel-build.yml) runs it natively on the VM in
# KARTIFACT_STAGE_ONLY=1 mode (staging only); the workflow's rootful
# podman does the OCI build + push.
# KTREE/O/STAGE/REG/SEQ are overridable via environment. REG
# follows the registry contract: KLN_REGISTRY first (repo variable — zot
# direct endpoint internally), then REG, else the public ghcr.io form.
set -euo pipefail
: "${KTREE:=$(cd "$(dirname "$0")/../.." && pwd)}"
: "${O:=$KTREE/.build/kbuild-7211}"
: "${STAGE:=$KTREE/.build/kartifact-stage}"
: "${KLN_REGISTRY:=ghcr.io/kleinia-os}"
: "${REG:=$KLN_REGISTRY}"
REG_HOST="${REG%%/*}"; REG_OPTS=()
if [ "$REG_HOST" != ghcr.io ]; then REG_OPTS=(--tls-verify=false); fi
: "${SEQ:=}"
KVER="$(sed -n 's/#define UTS_RELEASE "\(.*\)"/\1/p' "$O/include/generated/utsrelease.h")"
TAG="kleinia-kernel:$KVER"
echo "== kernel $KVER -> $REG (seq tag: ${SEQ:-none}) =="

# ---- (a) kernel OCI artifact ----
rm -rf "$STAGE"; mkdir -p "$STAGE"
make -C "$KTREE" O="$O" INSTALL_MOD_PATH="$STAGE" INSTALL_MOD_STRIP=1 modules_install >/dev/null
rm -f "$STAGE/lib/modules/$KVER/build" "$STAGE/lib/modules/$KVER/source"
cp "$O/arch/x86/boot/bzImage"  "$STAGE/lib/modules/$KVER/vmlinuz"
cp "$O/System.map"             "$STAGE/lib/modules/$KVER/System.map"
cp "$O/.config"                "$STAGE/lib/modules/$KVER/config"
du -sh "$STAGE/lib/modules/$KVER"

# assert module signing: every sampled .ko must carry the KleiniaOS signer
SIGNER_EXPECT="KleiniaOS Module Signing"
N_SIGNED=0; N_MOD=0
while IFS= read -r -d '' ko; do
  N_MOD=$((N_MOD+1))
  s="$(modinfo -F signer "$ko" 2>/dev/null || true)"
  [ "$s" = "$SIGNER_EXPECT" ] || { echo "FATAL: unsigned/badly-signed module: $ko (signer='$s')"; exit 3; }
  N_SIGNED=$((N_SIGNED+1))
done < <(find "$STAGE/lib/modules/$KVER" -name '*.ko*' -print0)
[ "$N_MOD" -gt 0 ] || { echo "FATAL: no modules found to verify"; exit 3; }
echo "== module signing verified: $N_SIGNED/$N_MOD modules signed by '$SIGNER_EXPECT' =="

cat > "$STAGE/Dockerfile" <<'EOF'
FROM scratch
COPY lib/modules/ /usr/lib/modules/
EOF
# KARTIFACT_STAGE_ONLY=1 (CI native packaging): prepare both
# stage dirs incl. Dockerfiles, then stop — the workflow's rootful podman
# on the VM builds and pushes from these dirs (no privileged nested
# podman). Dev-box runs leave it unset and get the full build+push.
if [ "${KARTIFACT_STAGE_ONLY:-0}" != "1" ]; then
  podman build -q -t "localhost/$TAG" "$STAGE"
fi

# ---- (b) kernel-devel OCI artifact ----
# Everything an out-of-tree `make -C /usr/lib/modules/$KVER/build M=...`
# needs, minus the giant vmlinux binaries (not used by module builds).
# SECURITY: the module signing private key lives in $O/certs/ during the
# build (CONFIG_MODULE_SIG_KEY="certs/module-signing.pem") and must never
# enter this artifact — the registry serves anonymous reads.
STAGE_DEV="$STAGE-devel"; rm -rf "$STAGE_DEV"
mkdir -p "$STAGE_DEV/lib/modules/$KVER/build"
tar -C "$O" \
    --exclude='vmlinux*' --exclude='.tmp_vmlinux*' \
    --exclude='certs/*.pem' --exclude='*.pem' \
    -cf - . | tar -C "$STAGE_DEV/lib/modules/$KVER/build" -xf -
ln -s build "$STAGE_DEV/lib/modules/$KVER/source"

# kernel-bits: the header set agent userspace/BPF builds compile against.
# Shipped INSIDE the devel artifact (single source of truth, always
# version-locked to this kernel) at /usr/src/kleinia-kernel-bits; the
# image assembly pipeline extracts them at build time instead of keeping
# a committed copy in the image repo.
KBITS_DIR="$STAGE_DEV/usr/src/kleinia-kernel-bits"
mkdir -p "$KBITS_DIR/tools/include" "$KBITS_DIR/tools/arch/x86"
cp -a "$KTREE/tools/include/."          "$KBITS_DIR/tools/include/"
cp -a "$KTREE/tools/arch/x86/include/." "$KBITS_DIR/tools/arch/x86/include/"
echo "== generating vmlinux.h from BTF =="
bpftool btf dump file "$O/vmlinux" format c > "$KBITS_DIR/vmlinux.h"
cp "$KTREE/include/uapi/linux/acb.h"    "$KBITS_DIR/acb.h"
wc -l "$KBITS_DIR/vmlinux.h"

if grep -rlq 'BEGIN .*PRIVATE KEY' "$STAGE_DEV"; then
  echo "FATAL: private key material in kernel-devel stage — aborting" >&2
  exit 2
fi
du -sh "$STAGE_DEV/lib/modules/$KVER/build"
cat > "$STAGE_DEV/Dockerfile" <<'EOF'
FROM scratch
COPY lib/modules/ /usr/lib/modules/
COPY usr/src/ /usr/src/
EOF
if [ "${KARTIFACT_STAGE_ONLY:-0}" = "1" ]; then
  echo "== stage-only: kernel=$STAGE devel=$STAGE_DEV prepared; native CI builds + pushes =="
  exit 0
fi
podman build -q -t "localhost/kleinia-kernel-devel:$KVER" "$STAGE_DEV"

# ---- push: floating $KVER + sequenced $KVER.$SEQ ----
push_tags() { # push_tags <local-image> [extra-tag...]
  local img="$1" t; shift
  for t in "$KVER" "$@"; do
    podman tag "localhost/$img:$KVER" "localhost/$img:$t"
    podman push "${REG_OPTS[@]}" "localhost/$img:$t" "$REG/$img:$t"
    echo "== pushed $REG/$img:$t =="
  done
}
EXTRA=(); [ -n "$SEQ" ] && EXTRA+=("$KVER.$SEQ")
push_tags "kleinia-kernel" "${EXTRA[@]}"
push_tags "kleinia-kernel-devel" "${EXTRA[@]}"

echo "== done =="
