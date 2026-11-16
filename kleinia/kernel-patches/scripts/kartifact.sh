#!/bin/bash
# After kbuild.sh: produce
#  (a) OCI artifact kleinia-kernel:<KVER>  (kernel + modules tree, bootc layout),
#      pushed to the internal registry for the image-build CI to consume
#  (b) bluebuild/build-context/kernel-bits  (vmlinux.h + tools headers for scx_acb build)
# Uses rootless podman (no sudo needed on the dev box).
# KTREE/O/BB/STAGE/REG are overridable via environment (transitional defaults
# point at the pre-migration workspace).
set -euo pipefail
: "${KTREE:=/srv/kleinia-ws/os_ext-7.2.11}"
: "${O:=/srv/kleinia-ws/acb/dist/kbuild-7211}"
: "${BB:=/srv/kleinia-ws/acb/bluebuild}"
: "${STAGE:=/srv/kleinia-ws/acb/dist/kartifact-stage}"
: "${REG:=10.0.0.1:5000}"
KVER="$(sed -n 's/#define UTS_RELEASE "\(.*\)"/\1/p' "$O/include/generated/utsrelease.h")"
TAG="kleinia-kernel:$KVER"
echo "== kernel $KVER =="

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
podman build -q -t "localhost/$TAG" "$STAGE"
podman push --tls-verify=false "localhost/$TAG" "$REG/$TAG"
echo "== pushed $REG/$TAG =="

# ---- (b) kernel-bits for the agent-builder stage ----
rm -rf "$BB/files/build-context/kernel-bits"
mkdir -p "$BB/files/build-context/kernel-bits/tools/include" "$BB/files/build-context/kernel-bits/tools/arch/x86"
cp -a "$KTREE/tools/include/."            "$BB/files/build-context/kernel-bits/tools/include/"
cp -a "$KTREE/tools/arch/x86/include/."   "$BB/files/build-context/kernel-bits/tools/arch/x86/include/"
echo "== generating vmlinux.h from BTF =="
bpftool btf dump file "$O/vmlinux" format c > "$BB/files/build-context/kernel-bits/vmlinux.h"
cp "$KTREE/include/uapi/linux/acb.h"      "$BB/files/build-context/kernel-bits/acb.h"
wc -l "$BB/files/build-context/kernel-bits/vmlinux.h"
echo "== done: artifact $REG/$TAG + kernel-bits staged =="
