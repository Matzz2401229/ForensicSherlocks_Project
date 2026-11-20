#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"
for tool in clang bpftool gcc pkg-config mktemp; do
    command -v "$tool" >/dev/null 2>&1 || { echo "Missing tool: $tool" >&2; exit 1; }
done
pkg-config --exists libbpf json-c || {
    echo 'Install libbpf-dev, libelf-dev, libjson-c-dev and pkg-config.' >&2; exit 1;
}
[[ -r /sys/kernel/btf/vmlinux ]] || { echo 'Kernel BTF is unavailable.' >&2; exit 1; }
case "$(uname -m)" in
    x86_64) TARGET_ARCH=x86 ;;
    aarch64) TARGET_ARCH=arm64 ;;
    *) echo 'Unsupported architecture.' >&2; exit 1 ;;
esac
mkdir -p -- "$BUILD_DIR"
TMP_DIR="$(mktemp -d "${BUILD_DIR}/.build.XXXXXX")"
trap 'rm -f -- "$TMP_DIR/vmlinux.h" "$TMP_DIR/lsm_guard.bpf.o" "$TMP_DIR/lsm_guard.skel.h" "$TMP_DIR/lsm_controller"; rmdir -- "$TMP_DIR"' EXIT
MULTIARCH="$(gcc -print-multiarch)"
ARCH_INCLUDE=()
[[ -z "$MULTIARCH" || ! -d "/usr/include/$MULTIARCH" ]] || ARCH_INCLUDE=(-I"/usr/include/$MULTIARCH")
read -r -a LIB_FLAGS <<< "$(pkg-config --cflags --libs libbpf json-c)"
echo '[1/4] Generating vmlinux.h from this kernel...'
bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$TMP_DIR/vmlinux.h"
echo '[2/4] Compiling BPF guard...'
clang -g -O2 -target bpf -D"__TARGET_ARCH_${TARGET_ARCH}" \
    -I"$TMP_DIR" -I"$SCRIPT_DIR" "${ARCH_INCLUDE[@]}" \
    -c "$SCRIPT_DIR/lsm_guard.bpf.c" -o "$TMP_DIR/lsm_guard.bpf.o"
echo '[3/4] Generating skeleton...'
bpftool gen skeleton "$TMP_DIR/lsm_guard.bpf.o" name lsm_guard_bpf > "$TMP_DIR/lsm_guard.skel.h"
echo '[4/4] Compiling controller...'
gcc -std=gnu11 -g -O2 -Wall -Wextra -Werror -I"$TMP_DIR" -I"$SCRIPT_DIR" \
    "$SCRIPT_DIR/lsm_controller.c" "$SCRIPT_DIR/lsm_targets.c" "$SCRIPT_DIR/lsm_socket.c" \
    -o "$TMP_DIR/lsm_controller" "${LIB_FLAGS[@]}"
for artifact in vmlinux.h lsm_guard.bpf.o lsm_guard.skel.h lsm_controller; do
    mv -f -- "$TMP_DIR/$artifact" "$BUILD_DIR/$artifact"
done
echo "Built: $BUILD_DIR/lsm_controller (enforcement has not been started)"
