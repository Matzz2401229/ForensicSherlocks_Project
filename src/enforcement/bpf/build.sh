#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"

BPF_SOURCE="${SCRIPT_DIR}/lsm_guard.bpf.c"
CONTROLLER_SOURCE="${SCRIPT_DIR}/lsm_controller.c"

BPF_OBJECT="${BUILD_DIR}/lsm_guard.bpf.o"
SKELETON="${BUILD_DIR}/lsm_guard.skel.h"
CONTROLLER="${BUILD_DIR}/lsm_controller"

echo "=== PortWatchman BPF-LSM Build ==="

# Check required commands.
for tool in clang bpftool gcc pkg-config; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "ERROR: Required tool not found: $tool" >&2
        exit 1
    fi
done

# Check libbpf development files.
if ! pkg-config --exists libbpf; then
    echo "ERROR: libbpf development package not found." >&2
    exit 1
fi

# Check json-c development files.
if ! pkg-config --exists json-c; then
    echo "ERROR: json-c development package not found." >&2
    exit 1
fi

# Check kernel BTF and project headers.
if [[ ! -r /sys/kernel/btf/vmlinux ]]; then
    echo "ERROR: Kernel BTF is unavailable." >&2
    exit 1
fi

if [[ ! -f "${BUILD_DIR}/vmlinux.h" ]]; then
    echo "ERROR: build/vmlinux.h is missing." >&2
    exit 1
fi

mkdir -p "$BUILD_DIR"

# Map the machine architecture to the BPF target architecture.
case "$(uname -m)" in
    x86_64)
        TARGET_ARCH="x86"
        ;;
    aarch64)
        TARGET_ARCH="arm64"
        ;;
    *)
        echo "ERROR: Unsupported architecture: $(uname -m)" >&2
        exit 1
        ;;
esac

MULTIARCH="$(gcc -print-multiarch)"
ARCH_INCLUDE=()

if [[ -n "$MULTIARCH" && -d "/usr/include/${MULTIARCH}" ]]; then
    ARCH_INCLUDE=(-I"/usr/include/${MULTIARCH}")
fi

echo
echo "[1/3] Compiling BPF program..."

clang -g -O2 -target bpf \
    -D"__TARGET_ARCH_${TARGET_ARCH}" \
    -I"${BUILD_DIR}" \
    "${ARCH_INCLUDE[@]}" \
    -c "$BPF_SOURCE" \
    -o "$BPF_OBJECT"

echo
echo "[2/3] Generating libbpf skeleton..."

bpftool gen skeleton "$BPF_OBJECT" > "${SKELETON}.tmp"
mv "${SKELETON}.tmp" "$SKELETON"

echo
echo "[3/3] Compiling userspace controller..."

gcc -Wall -Wextra -O2 \
    "$CONTROLLER_SOURCE" \
    -o "${CONTROLLER}.tmp" \
    $(pkg-config --cflags --libs libbpf json-c)

mv "${CONTROLLER}.tmp" "$CONTROLLER"

echo
echo "=== Build completed successfully ==="
echo "BPF object : $BPF_OBJECT"
echo "Skeleton   : $SKELETON"
echo "Controller : $CONTROLLER"
echo
echo "To test loopback enforcement:"
echo "sudo \"$CONTROLLER\" --test-loopback <target-file-path>"