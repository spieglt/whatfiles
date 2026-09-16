#!/bin/sh
#
# Regression tests for whatfiles. Run them with `make test`, or directly.
# Each test builds a small program, runs it under whatfiles, and checks the log.
#
set -u

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
WHATFILES=${WHATFILES:-$ROOT/bin/whatfiles}
CC=${CC:-gcc}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/whatfiles-tests.XXXXXX")
PASSED=0
FAILED=0

cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT INT TERM

if [ ! -x "$WHATFILES" ]; then
    echo "no whatfiles binary at $WHATFILES: run make first" >&2
    exit 2
fi

pass() { PASSED=$((PASSED + 1)); printf 'PASS  %s\n' "$1"; }
fail() { FAILED=$((FAILED + 1)); printf 'FAIL  %s\n      %s\n' "$1" "$2"; }
skip() { printf 'SKIP  %s (%s)\n' "$1" "$2"; }

build() {
    name=$1
    shift
    $CC -std=gnu99 -O1 -o "$WORK/$name" "$ROOT/tests/$name.c" "$@" >"$WORK/$name.build" 2>&1
}

# check <test name> <description> <expected count> <pattern> <file>
count_is() {
    got=$(grep -c -- "$4" "$5" 2>/dev/null || true)
    if [ "$got" = "$3" ]; then pass "$1"; else fail "$1" "$2: expected $3, got $got"; fi
}

has() {
    if grep -q -- "$3" "$4" 2>/dev/null; then pass "$1"; else fail "$1" "$2"; fi
}

lacks() {
    if grep -q -- "$3" "$4" 2>/dev/null; then fail "$1" "$2"; else pass "$1"; fi
}

echo "whatfiles: $WHATFILES"
echo

# ---------------------------------------------------------------- open modes
if build t_modes; then
    (cd "$WORK" && "$WHATFILES" -o modes.log ./t_modes >/dev/null 2>&1)
    L=$WORK/modes.log
    has "modes: create for writing"  "O_WRONLY|O_CREAT|O_TRUNC should read write+create+trunc" "write+create+trunc" "$L"
    has "modes: truncate existing"   "O_WRONLY|O_TRUNC should read write+trunc"                "write+trunc"        "$L"
    has "modes: append"              "O_WRONLY|O_APPEND should read write+append"              "write+append"       "$L"
    has "modes: read/write"          "O_RDWR should read rd/wr"                                "rd/wr"              "$L"
    has "modes: read only"           "O_RDONLY should read read"                               "mode:   read, file: .*modes_target" "$L"
    has "modes: delete"              "unlink() should read delete"                             "mode: delete"       "$L"
    has "results recorded"           "log should carry syscall results"                        "result: "           "$L"
else
    skip "modes" "build failed"
fi

# ------------------------------------------------- one line per syscall, no drops
if build t_consecutive; then
    (cd "$WORK" && "$WHATFILES" -o consec.log ./t_consecutive >/dev/null 2>&1)
    count_is "back-to-back syscalls all logged" "three identical opens" 3 "nonexistent/" "$WORK/consec.log"
    has "failed open reports the error" "ENOENT should be visible" "result: -1 (No such file or directory)" "$WORK/consec.log"
else
    skip "back-to-back syscalls" "build failed"
fi

if build t_threads -pthread; then
    (cd "$WORK" && "$WHATFILES" -o threads.log ./t_threads >/dev/null 2>&1)
    count_is "threads: no duplicates or drops" "4 threads x 250 opens" 1000 "nonexistent/thr" "$WORK/threads.log"
else
    skip "threads" "build failed"
fi

# -------------------------------------------------------------------- signals
if build t_signal; then
    (cd "$WORK" && "$WHATFILES" -o signal.log ./t_signal >/dev/null 2>&1)
    if [ $? -eq 0 ]; then pass "signals reach the tracee's handlers"
    else fail "signals reach the tracee's handlers" "handlers did not run under tracing"; fi
else
    skip "signals" "build failed"
fi

if build t_usermode_signal; then
    (cd "$WORK" && "$WHATFILES" -o usermode.log ./t_usermode_signal >/dev/null 2>&1)
    status=$?
    if [ $status -eq 0 ]; then pass "signal during user code is delivered"
    else fail "signal during user code is delivered" "handler never ran (exit $status)"; fi
    has "tracing continues after a signal" "the open after the signal should still be logged" \
        "nonexistent/after-signal" "$WORK/usermode.log"
else
    skip "user-mode signal" "build failed"
fi

if build t_seccomp_trap; then
    (cd "$WORK" && "$WHATFILES" -o seccomp.log ./t_seccomp_trap >"$WORK/seccomp.out" 2>&1)
    status=$?
    if [ $status -eq 77 ]; then skip "seccomp SIGSYS brokering" "$(cat "$WORK/seccomp.out")"
    elif [ $status -eq 0 ]; then pass "seccomp SIGSYS brokering (the Firefox tab crash)"
    else fail "seccomp SIGSYS brokering (the Firefox tab crash)" "$(cat "$WORK/seccomp.out")"; fi
else
    skip "seccomp SIGSYS brokering" "build failed"
fi

# ------------------------------------------------------------ process tracking
if build t_exec_thread -pthread; then
    (cd "$WORK" && timeout 20 "$WHATFILES" -o exec.log ./t_exec_thread >/dev/null 2>&1)
    status=$?
    if [ $status -eq 0 ]; then pass "exec from a non-leader thread exits cleanly"
    else fail "exec from a non-leader thread exits cleanly" "whatfiles exited with $status"; fi
else
    skip "exec from a thread" "build failed"
fi

if build t_forker -pthread; then
    (cd "$WORK" && "$WHATFILES" -o launch.log ./t_forker >/dev/null 2>&1)
    count_is "launch mode follows children of every thread" "20 forks from a worker thread" \
        20 "opened-by-child-of-worker-thread" "$WORK/launch.log"

    if build t_attach_harness; then
        (cd "$WORK" && timeout 30 ./t_attach_harness "$WHATFILES" "$WORK/attach.log" "$WORK/t_forker" >/dev/null 2>&1)
        got=$(grep -c "opened-by-child-of-worker-thread" "$WORK/attach.log" 2>/dev/null || true)
        if [ "${got:-0}" -ge 10 ]; then
            pass "attach mode follows children of every thread"
        else
            fail "attach mode follows children of every thread" \
                 "expected at least 10 child opens, got ${got:-0} (ptrace may be restricted here)"
        fi
    else
        skip "attach mode coverage" "build failed"
    fi
else
    skip "child process coverage" "build failed"
fi

# ------------------------------------------------------------------ log safety
if build t_forge; then
    (cd "$WORK" && "$WHATFILES" -o forge.log ./t_forge >/dev/null 2>&1)
    count_is "filenames cannot forge log lines" "the forged text must stay on one line" \
        1 "FORGED" "$WORK/forge.log"
    lacks "forged text cannot start a line" "a newline in a filename produced a second log line" \
        "^mode:  read, file: /etc/FORGED" "$WORK/forge.log"
    has "control characters are escaped" "the newline should appear as an escape" \
        'x\\nmode' "$WORK/forge.log"
else
    skip "log forgery" "build failed"
fi

# --------------------------------------------------------------- path handling
if build t_relative; then
    (cd "$WORK" && "$WHATFILES" -o relative.log ./t_relative >/dev/null 2>&1)
    has "relative paths resolved against the working directory" "cwd-relative path should be absolute" \
        "file: $WORK/relative-in-cwd" "$WORK/relative.log"
    has "paths resolved against a directory descriptor" "openat() path should be absolute" \
        "file: $WORK/subdir/relative-to-dirfd" "$WORK/relative.log"
else
    skip "path resolution" "build failed"
fi

# ---------------------------------------------------- syscalls beyond open/unlink
if build t_fileops; then
    (cd "$WORK" && "$WHATFILES" -o fileops.log ./t_fileops >/dev/null 2>&1)
    for pair in "rename:rename" "link:link" "symlink:symlink" "trunc:truncate" "chmod:chmod" "mkdir:mkdir" "rmdir:rmdir"; do
        mode=${pair%%:*}
        what=${pair##*:}
        has "$what is logged" "no $mode line in the log" "mode: *$mode," "$WORK/fileops.log"
    done
else
    skip "other file syscalls" "build failed"
fi

# ------------------------------------------------------------ 32-bit syscalls
# The register fallback used on kernels before 5.3 cannot tell that a 64-bit
# program entered the kernel through int $0x80, so skip this there.
decoding=$("$WHATFILES" -d -s true 2>/dev/null | sed -n 's/^syscall decoding: //p')
if [ "${decoding:-}" = "registers" ]; then
    skip "32-bit syscalls" "kernel is too old for PTRACE_GET_SYSCALL_INFO"
elif [ "$(uname -m)" = "x86_64" ] && build t_int80 -no-pie; then
    (cd "$WORK" && "$WHATFILES" -o int80.log ./t_int80 >/dev/null 2>&1)
    has "32-bit syscalls are decoded" "int 0x80 open() should be logged" "/etc/hostname" "$WORK/int80.log"
    lacks "32-bit syscall numbers are not misread" "a syscall that opened nothing was logged as openat()" \
        "phantom/never-opened" "$WORK/int80.log"
else
    skip "32-bit syscalls" "x86-64 only"
fi

# ---------------------------------------------------------------- interruption
(cd "$WORK" && "$WHATFILES" -o interrupted.log sh -c 'cat /etc/hostname >/dev/null; sleep 5' >/dev/null 2>&1) &
runner=$!
sleep 1
# Signal whatfiles itself, the way Ctrl-C would.
pkill -INT -P $runner -x whatfiles 2>/dev/null || kill -INT $runner 2>/dev/null
wait $runner 2>/dev/null
if [ -s "$WORK/interrupted.log" ]; then pass "log survives an interrupt"
else fail "log survives an interrupt" "the log was empty after SIGINT"; fi

# ------------------------------- an interrupt must be noticed even when idle
if build t_attach_harness; then
    (cd "$WORK" && ./t_attach_harness "$WHATFILES" "$WORK/idle.log" /bin/sleep 25 >/dev/null 2>&1) &
    harness=$!
    sleep 1.5
    idle_target=$(pgrep -P $harness sleep 2>/dev/null | head -1)
    kill -INT $harness 2>/dev/null
    sleep 2
    if kill -0 $harness 2>/dev/null; then
        fail "interrupt is noticed while the target is idle" "whatfiles ignored SIGINT for 2s"
        kill -9 $harness 2>/dev/null
    else
        pass "interrupt is noticed while the target is idle"
    fi
    wait $harness 2>/dev/null
    state=$(ps -o stat= -p "${idle_target:-0}" 2>/dev/null | tr -d ' ')
    case "$state" in
        T*) fail "detaching leaves the target running" "target is stopped (state $state)" ;;
        "") skip "detaching leaves the target running" "target already gone" ;;
        *)  pass "detaching leaves the target running" ;;
    esac
    kill -9 "${idle_target:-0}" 2>/dev/null
else
    skip "interrupt while idle" "build failed"
fi

# --------------------------------------------- a refused attach must not freeze
sleep 30 &
victim=$!
sleep 0.3
"$WHATFILES" -s -p $victim >/dev/null 2>&1
sleep 0.3
state=$(ps -o stat= -p $victim 2>/dev/null | tr -d ' ')
case "$state" in
    T*) fail "a refused attach leaves the target running" "target is stopped (state $state)" ;;
    "") skip "refused attach" "target vanished" ;;
    *)  pass "a refused attach leaves the target running" ;;
esac
kill $victim 2>/dev/null
wait $victim 2>/dev/null

echo
echo "passed: $PASSED  failed: $FAILED"
[ "$FAILED" -eq 0 ]
