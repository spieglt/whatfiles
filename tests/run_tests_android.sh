#!/bin/sh
#
# Runs the whatfiles tests on a connected Android device or emulator.
#
#   NDK=~/Android/Sdk/ndk/<version> tests/run_tests_android.sh [ABI]
#
# Builds whatfiles and the test programs with the NDK, pushes them, runs the
# checks on the device, and removes everything it pushed. ABI defaults to what
# the device reports: arm64, arm32, x86_64 or x86.
#
set -u

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
API=${ANDROID_API:-21}
NDK_HOST=${NDK_HOST:-linux-x86_64}
DEVICE_DIR=/data/local/tmp/whatfiles-test

if [ -z "${NDK:-}" ]; then
    echo "set NDK to your Android NDK, e.g. NDK=~/Android/Sdk/ndk/<version>" >&2
    exit 2
fi
command -v adb >/dev/null || { echo "adb not found" >&2; exit 2; }
adb get-state >/dev/null 2>&1 || { echo "no device connected" >&2; exit 2; }

ABI=${1:-}
if [ -z "$ABI" ]; then
    case $(adb shell getprop ro.product.cpu.abi | tr -d '\r') in
        arm64-v8a)   ABI=arm64 ;;
        armeabi-v7a) ABI=arm32 ;;
        x86_64)      ABI=x86_64 ;;
        x86)         ABI=x86 ;;
        *)           echo "unrecognized device ABI" >&2; exit 2 ;;
    esac
fi
case $ABI in
    arm64)  TRIPLE=aarch64-linux-android ;;
    arm32)  TRIPLE=armv7a-linux-androideabi ;;
    x86_64) TRIPLE=x86_64-linux-android ;;
    x86)    TRIPLE=i686-linux-android ;;
    *)      echo "unknown ABI '$ABI'" >&2; exit 2 ;;
esac
CC=$NDK/toolchains/llvm/prebuilt/$NDK_HOST/bin/$TRIPLE$API-clang
[ -x "$CC" ] || { echo "no NDK compiler at $CC" >&2; exit 2; }

BUILD=$(mktemp -d "${TMPDIR:-/tmp}/whatfiles-android.XXXXXX")
cleanup() {
    rm -rf "$BUILD"
    adb shell rm -rf $DEVICE_DIR >/dev/null 2>&1
}
trap cleanup EXIT INT TERM

echo "building whatfiles and tests for $ABI, API $API"
make -C "$ROOT" android NDK="$NDK" ANDROID_ABI="$ABI" ANDROID_API="$API" >/dev/null || exit 1
cp "$ROOT/bin/whatfiles-android" "$BUILD/whatfiles"
for test in t_consecutive t_threads t_signal t_usermode_signal t_seccomp_trap \
            t_exec_thread t_forker t_modes t_fileops t_relative t_forge t_attach_harness; do
    "$CC" -std=gnu99 -O1 -o "$BUILD/$test" "$ROOT/tests/$test.c" || exit 1
done

cat > "$BUILD/device_tests.sh" <<'DEVICE'
#!/system/bin/sh
W=$(dirname "$0")/whatfiles
cd "$(dirname "$0")" || exit 1
passed=0
failed=0
check() {
    if [ "$2" = "$3" ]; then
        echo "PASS  $1"
        passed=$((passed + 1))
    else
        echo "FAIL  $1: expected $2, got $3"
        failed=$((failed + 1))
    fi
}
at_least() { [ "$1" -ge "$2" ] && echo ok || echo "$1"; }

$W -o consec.log ./t_consecutive >/dev/null 2>&1
check "back-to-back syscalls all logged" 3 "$(grep -c nonexistent consec.log)"
$W -o threads.log ./t_threads >/dev/null 2>&1
check "threads: no duplicates or drops" 1000 "$(grep -c nonexistent/thr threads.log)"
$W -o signal.log ./t_signal >/dev/null 2>&1; rc=$?
check "signals reach the tracee's handlers" 0 "$rc"
$W -o usermode.log ./t_usermode_signal >/dev/null 2>&1; rc=$?
check "signal during user code is delivered" 0 "$rc"
$W -o seccomp.log ./t_seccomp_trap >/dev/null 2>&1; rc=$?
check "seccomp SIGSYS brokering" 0 "$rc"
$W -o exec.log ./t_exec_thread >/dev/null 2>&1; rc=$?
check "exec from a non-leader thread exits cleanly" 0 "$rc"
$W -o forker.log ./t_forker >/dev/null 2>&1
check "launch mode follows children of every thread" 20 "$(grep -c opened-by-child-of-worker-thread forker.log)"
$W -o modes.log ./t_modes >/dev/null 2>&1
check "write mode is reported" ok "$(at_least "$(grep -c 'write+create+trunc' modes.log)" 1)"
check "read mode is reported" ok "$(at_least "$(grep -c 'mode:   read, file: .*modes_target' modes.log)" 1)"
$W -o fileops.log ./t_fileops >/dev/null 2>&1
check "rename is logged" ok "$(at_least "$(grep -c 'mode: rename' fileops.log)" 1)"
check "symlink is logged" ok "$(at_least "$(grep -c 'mode: symlink' fileops.log)" 1)"
$W -o relative.log ./t_relative >/dev/null 2>&1
check "relative paths are resolved" ok "$(at_least "$(grep -c "file: $(pwd)/relative-in-cwd" relative.log)" 1)"
$W -o forge.log ./t_forge >/dev/null 2>&1
check "filenames cannot forge log lines" 0 "$(grep -c '^mode:  read, file: /etc/FORGED' forge.log)"
./t_attach_harness $W attach.log ./t_forker >/dev/null 2>&1
check "attach mode follows worker-thread children" ok "$(at_least "$(grep -c opened-by-child-of-worker-thread attach.log)" 10)"

echo
echo "passed: $passed  failed: $failed"
[ "$failed" -eq 0 ]
DEVICE

adb shell rm -rf $DEVICE_DIR >/dev/null 2>&1
adb shell mkdir -p $DEVICE_DIR >/dev/null || exit 1
adb push "$BUILD/." $DEVICE_DIR/ >/dev/null || exit 1
adb shell chmod 755 "$DEVICE_DIR/*" || exit 1
echo "running on $(adb shell getprop ro.product.model | tr -d '\r'), Android $(adb shell getprop ro.build.version.release | tr -d '\r')"
echo
adb shell "sh $DEVICE_DIR/device_tests.sh; echo EXIT:\$?" > "$BUILD/output.txt" 2>&1
sed 's/EXIT:[0-9]*//' "$BUILD/output.txt" | sed '/^[[:space:]]*$/d;$!b' 
grep -q 'EXIT:0' "$BUILD/output.txt"
