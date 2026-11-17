#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

CONTROLLER="${REPO_ROOT}/src/enforcement/bpf/build/lsm_controller"

TEST_MOUNT="/mnt/portwatchman-test"
RESTRICTED_FILE="${TEST_MOUNT}/restricted.txt"
NORMAL_FILE="${TEST_MOUNT}/normal.txt"

CONTROLLER_PID=""
LOG_FILE=""

fail() {
    echo "FAIL: $1" >&2
    exit 1
}

cleanup() {
    if [[ -n "${CONTROLLER_PID}" ]] &&
       kill -0 "${CONTROLLER_PID}" 2>/dev/null; then
        kill -TERM "${CONTROLLER_PID}" 2>/dev/null || true
        wait "${CONTROLLER_PID}" 2>/dev/null || true
    fi

    if [[ -n "${LOG_FILE}" ]]; then
        rm -f "${LOG_FILE}"
    fi
}

trap cleanup EXIT

echo "=== PortWatchman BPF-LSM Integration Test ==="

# Require root privileges.
if [[ "${EUID}" -ne 0 ]]; then
    fail "Run this script with sudo."
fi

# Check required commands.
for tool in findmnt stat cat grep sleep stdbuf seq; do
    command -v "${tool}" >/dev/null 2>&1 ||
        fail "Required command not found: ${tool}"
done

# Check controller and test files.
[[ -x "${CONTROLLER}" ]] ||
    fail "Controller is missing or not executable: ${CONTROLLER}"

[[ -f "${RESTRICTED_FILE}" ]] ||
    fail "Restricted test file is missing."

[[ -f "${NORMAL_FILE}" ]] ||
    fail "Normal test file is missing."
    
# Test rejection of invalid controller targets.
echo
echo "[1/4] Testing invalid target rejection..."

# Missing file must be rejected.
if "${CONTROLLER}" --test-loopback \
    "/tmp/portwatchman-missing-test-file" \
    >/dev/null 2>&1; then
    fail "Controller accepted a missing target file."
fi

echo "PASS: Missing target file was rejected."

# Directory must be rejected.
if "${CONTROLLER}" --test-loopback \
    "/tmp" >/dev/null 2>&1; then
    fail "Controller accepted a directory as the target."
fi

echo "PASS: Directory target was rejected."

# Non-loopback file must be rejected.
if "${CONTROLLER}" --test-loopback \
    "/etc/hostname" >/dev/null 2>&1; then
    fail "Controller accepted a non-loopback target."
fi

echo "PASS: Non-loopback target was rejected."

# Confirm that the target filesystem is loopback-backed.
SOURCE="$(findmnt -n -o SOURCE --target "${RESTRICTED_FILE}" || true)"

case "${SOURCE}" in
    /dev/loop[0-9]*)
        echo "Test device: ${SOURCE}"
        ;;
    *)
        fail "Test files are not on a recognised loopback device: ${SOURCE}"
        ;;
esac

NORMAL_SOURCE="$(findmnt -n -o SOURCE --target "${NORMAL_FILE}" || true)"

[[ "${NORMAL_SOURCE}" == "${SOURCE}" ]] ||
    fail "Normal and restricted files are not on the same loopback device."

# Ensure both files belong to the same filesystem.
RESTRICTED_DEVICE="$(stat -c '%d' "${RESTRICTED_FILE}")"
NORMAL_DEVICE="$(stat -c '%d' "${NORMAL_FILE}")"

[[ "${RESTRICTED_DEVICE}" == "${NORMAL_DEVICE}" ]] ||
    fail "Test files are not on the same filesystem."

# Establish baseline access before enforcement.
echo
echo "[1/3] Checking baseline file access..."

cat "${RESTRICTED_FILE}" >/dev/null ||
    fail "Restricted file is not readable before enforcement."

cat "${NORMAL_FILE}" >/dev/null ||
    fail "Normal file is not readable before enforcement."

echo "PASS: Both files are readable before enforcement."

# Start the BPF-LSM controller.
echo
echo "[2/3] Starting BPF-LSM enforcement..."

LOG_FILE="$(mktemp)"

stdbuf -oL "${CONTROLLER}" --test-loopback \
    "${RESTRICTED_FILE}" >"${LOG_FILE}" 2>&1 &

CONTROLLER_PID=$!

# Wait for confirmation that the hook has attached.
ACTIVE=0

for attempt in $(seq 1 15); do
    if grep -Fq "PortWatchman BPF-LSM enforcement is active." \
        "${LOG_FILE}"; then
        ACTIVE=1
        break
    fi

    if ! kill -0 "${CONTROLLER_PID}" 2>/dev/null; then
        break
    fi

    sleep 1
done

if [[ "${ACTIVE}" -ne 1 ]]; then
    cat "${LOG_FILE}" >&2
    fail "Controller did not confirm active enforcement."
fi

echo "PASS: BPF-LSM enforcement is active."

# Restricted file must be denied.
if cat "${RESTRICTED_FILE}" >/dev/null 2>&1; then
    fail "Restricted file remained accessible during enforcement."
else
    echo "PASS: Restricted file access was denied."
fi

# Normal file must remain accessible.
cat "${NORMAL_FILE}" >/dev/null ||
    fail "Normal file was denied during enforcement."

echo "PASS: Normal file remains accessible."

# Stop the controller and detach the BPF-LSM program.
echo
echo "[3/3] Stopping BPF-LSM enforcement..."

kill -TERM "${CONTROLLER_PID}"

if wait "${CONTROLLER_PID}"; then
    echo "PASS: Controller stopped successfully."
else
    cat "${LOG_FILE}" >&2
    fail "Controller did not shut down successfully."
fi

CONTROLLER_PID=""

# Restricted file must become accessible again.
cat "${RESTRICTED_FILE}" >/dev/null ||
    fail "Restricted file remains inaccessible after enforcement stopped."

echo "PASS: Restricted file access was restored."

echo
echo "=== All BPF-LSM integration tests passed ==="
