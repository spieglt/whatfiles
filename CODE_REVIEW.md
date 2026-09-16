# whatfiles code review

Reviewed commit `a3c17cf` on `master`. Every finding was checked against the source. Findings marked **Verified** were reproduced on Ubuntu 24.04 (Linux 6.8.0, x86_64, gcc 13.3, Firefox 155.0.1) with small test programs. They now live in `tests/` and run as a suite with `make test`; the most important one is also in the appendix.

## Status: fixed

Every finding below has been fixed in the working tree. The one exception is the performance
suggestion (section 5, step 7), which was deliberately not implemented; the reason is at the end
of section 3.

`tests/run_tests.sh` turns the reproducers into a regression suite: 35 checks, all passing.
Headless Firefox now runs three times out of three under whatfiles with all sandboxed processes
traced, no crashes and no minidumps, where the old build crashed whenever it managed to trace them.

| # | Finding | Where it was fixed |
|---|---------|--------------------|
| 1 | Signals discarded | `src/trace.c`: signal-delivery-stops resume with the signal, syscall stops are identified by `PTRACE_O_TRACESYSGOOD` |
| 2 | Silent detach on a user-mode signal | `src/trace.c`: the detach branch is gone; register reads are checked instead |
| 3 | Open mode from the wrong register | `src/trace.c`, `src/utilities.c`: arguments come from `PTRACE_GET_SYSCALL_INFO` or a per-architecture reader, and the mode is decoded with `O_ACCMODE` plus `O_CREAT`/`O_TRUNC`/`O_APPEND` |
| 4 | Dropped and duplicated lines | `src/hashmap.c`, `src/trace.c`: entry and exit are tracked per thread, not in one global |
| 5 | Attach missed other threads' children | `src/attach.c`: `PTRACE_SEIZE` with options on every thread, repeated until no new threads appear |
| 6 | Failed attach froze the target | `src/attach.c`: seizing never stops the target, so a failure leaves it running |
| 7 | Ctrl-C lost the log or was ignored | `src/whatfiles.c`: handlers without `SA_RESTART`, line-buffered log, clean detach |
| 8 | 32-bit syscalls invisible and misread | `src/syscalls.c`: per-ABI syscall tables selected by the ABI the kernel reports. On kernels before 5.3 the fallback reads the code segment instead, which still identifies 32-bit programs but not a 64-bit one using `int $0x80` |
| 9 | Filenames could forge log lines | `src/wfstring.c`: control characters are escaped |
| 10 | Stale entry after exec from a thread | `src/trace.c`: the old thread ID is removed at `PTRACE_EVENT_EXEC` |
| 11 | Duplicate keys after removal | `src/hashmap.c`: tombstones, and one probe sequence for both lookup and insert |
| 12 | Log descriptor leaked to the tracee | `src/whatfiles.c`: `O_CLOEXEC` |
| 13 | Unsafe default log creation | `src/whatfiles.c`: `O_EXCL | O_NOFOLLOW`, and the name includes the PID |
| 14 | Coverage gaps | `src/trace.c`: results logged at syscall exit, paths resolved to absolute, and rename/link/symlink/mkdir/rmdir/truncate/chmod/chown/exec added |
| 15 | Lower-severity issues | Throughout: `errno`-checked memory reads, `process_vm_readv`, arm64 syscall number from `NT_ARM_SYSTEM_CALL`, bounded attach loops, leaks removed, dead code deleted, `strings.h` renamed to `wfstring.h`, Makefile dependencies, `.PHONY`, `PREFIX`/`DESTDIR`, and an error for unknown architectures |

Group-stops are handled with `PTRACE_LISTEN`, so Ctrl-Z on a traced program now stops it instead of
secretly resuming it, and `-k` was added for the `PTRACE_O_EXITKILL` question raised under finding 15.

## Summary

- **The known Firefox issue is caused by whatfiles discarding signals.** Whenever a traced process stops for a signal, whatfiles resumes it with signal 0, and the kernel drops the signal. Firefox's content-process sandbox depends on `SIGSYS` from seccomp to broker file opens. With `SIGSYS` dropped, `openat()` returns a bogus value, font loading fails, and the tab process aborts.
- **A small change that re-injects signals makes Firefox run cleanly under whatfiles.** The patched build passed 3 of 3 runs with the sandboxed processes fully traced. The unpatched build crashed and hung whenever it managed to trace them.
- **The same bug breaks any traced program that uses signal handlers.** A related "detach" code path also stops tracing a process whenever a signal arrives while it runs user code, and nothing in the log shows it.
- **Several bugs make the log wrong.** Writes are reported as reads, and syscalls are dropped or logged twice. Attach mode misses child processes, 32-bit syscalls go unseen, and filenames can forge log lines.
- **Some failure paths hurt the user or the target program.** A failed `-p` attach leaves the target frozen, and Ctrl-C in launch mode throws away the log.

| # | Finding | Severity | Status |
|---|---------|----------|--------|
| 1 | Signals to tracees are discarded (Firefox tab crash) | High | Verified |
| 2 | Tracing silently detaches on any user-mode signal | High | Verified |
| 3 | Open mode is decoded from the wrong register on every arch | High | Verified (x86_64), code reading (others) |
| 4 | Entry/exit tracking drops and duplicates log lines | High | Verified |
| 5 | Attach mode does not follow processes spawned by non-main threads | High | Verified |
| 6 | Failed attach leaves the target stopped | High | Verified |
| 7 | Ctrl-C loses the log (launch) or is ignored (attach) | Medium | Verified |
| 8 | 32-bit syscalls are invisible and misread | Medium | Verified |
| 9 | Filenames can inject fake log lines | Medium | Verified |
| 10 | `exec` from a non-main thread leaves a stale entry | Medium | Verified |
| 11 | Hash map removal creates duplicate keys | Medium | Verified (unit test) |
| 12 | Log file descriptor leaks into the traced program | Medium | Verified |
| 13 | Unsafe default log file creation | Medium | Code reading |
| 14 | Coverage gaps: results, paths, missing syscalls | Medium | Code reading |
| 15 | Lower-severity correctness, robustness, and hygiene issues | Low | Mixed |

---

## 1. The known issue: Firefox tabs crash when launched under whatfiles

### Root cause

`step_syscall()` handles every ptrace stop the same way. It reads registers and then resumes the thread with `ptrace(PTRACE_SYSCALL, pid, 0, 0)` at `src/x86_64/registers.c:111`. The same pattern appears in the other three architecture files.

The last argument of that call is the signal to deliver. Under ptrace, a signal aimed at a tracee first puts it into a *signal-delivery-stop*. The kernel delivers the signal only if the tracer passes it back when resuming. whatfiles always passes 0, so it discards every signal sent to every traced thread, except `SIGKILL`.

Firefox's Linux content sandbox installs a seccomp-bpf filter that returns `SECCOMP_RET_TRAP` for filesystem syscalls such as `openat`. The kernel skips the syscall and raises `SIGSYS`. Firefox's `SIGSYS` handler forwards the request to a broker in the parent process and writes the result into the saved registers. Under whatfiles the chain of events is:

1. whatfiles resumes the `SIGSYS` stop with signal 0, so the handler never runs.
2. seccomp had rolled `RAX` back to the syscall number, so `openat()` "returns" 257 as if it were a file descriptor.
3. Reads from fd 257 fail, and fontconfig finds no usable font.
4. Firefox calls `MOZ_CRASH("unable to find a usable font (serif)")`, and the process dies with `SIGSEGV`.
5. whatfiles sees that fault stop with `orig_rax == -1`, prints `can't get registers, detaching`, and detaches. See finding 2.
6. Firefox respawns the tab process, which crashes the same way.

### Evidence

**Firefox itself.** Each run used `firefox --headless --no-remote --profile <fresh> --screenshot out.png file:///…/page.html` with a 90 second timeout. A "sandboxed process" is one whose log name is `forkserver` or `Sandbox Forked`.

| Tracer | Run | Result | Sandboxed PIDs traced | Crash minidumps |
|--------|-----|--------|----------------------|-----------------|
| none | – | screenshot written in 1 s | – | 0 |
| `strace -f` | – | screenshot written in 2 s | all | 0 |
| whatfiles (original) | 1 | screenshot written in 1 s | 0 | 0 |
| whatfiles (original) | 2 | **hung, killed at 90 s, no screenshot** | 53 | **9** |
| whatfiles (original) | 3 | screenshot written in 1 s | 0 | 0 |
| whatfiles (signal fix) | 1–3 | screenshot written in 1–2 s | 13, 13, 12 | 0 |

The crash annotations in the minidumps from the failed run show the cause:

```
6 × {'ProcessType': 'content', 'RemoteType': 'extension',
     'MozCrashReason': 'unable to find a usable font (serif)',
     'GraphicsCriticalError': '|[C0][GFX1]: no fonts - init: 1 fonts: 424 loader: 0 ...'}
3 × {'ProcessType': 'rdd'}
```

A separate run with `-d` showed Firefox's parent reporting `process 36183 exited on signal 11`, plus five more like it. The whatfiles debug log for that PID ends with font probing followed by the detach:

```
mode:  read, file: /usr/share/fonts/truetype/noto/NotoSans-Regular.ttf, syscall: openat(), PID: 36183, process: forkserver
mode:  read, file: /usr/share/fonts/truetype/noto/._NotoSans-Regular.ttf, syscall: openat(), PID: 36183, process: forkserver
...
can't get registers, detaching from 36183
```

`strace -f` of a normal Firefox run confirms that the sandboxed processes really receive `SIGSYS`. It recorded 31 deliveries in one screenshot run, for example 16 in the `file:// Content` process and 9 in `WebExtensions`.

**Minimal reproducer.** The first program in Appendix A copies Firefox's pattern: a `SECCOMP_RET_TRAP` filter on `openat` plus a `SIGSYS` handler that supplies a file descriptor.

```
native:                 sandboxed open() returned 4,   SIGSYS handler ran 1 time(s), read() returned 13
whatfiles (original):   sandboxed open() returned 257, SIGSYS handler ran 0 time(s), read() returned -1: Bad file descriptor
whatfiles (signal fix): sandboxed open() returned 5,   SIGSYS handler ran 1 time(s), read() returned 13
```

A simpler test that raises `SIGUSR1` and `SIGCHLD` at itself printed `handler invocations: 0` under whatfiles, versus 2 natively.

### Why `-p` and "open a second window" appear to work

- **Attach mode never traces the tab processes.** `attach_to_process()` attaches to every thread but calls `PTRACE_SETOPTIONS` only on the PID given at `src/attach.c:128`. ptrace options are per thread, so a `fork` or `clone` from any other thread is not followed. `strace` shows Firefox creating child processes from its `IPC Launch` thread. In current versions, tabs are then forked by a separate `forkserver` process. Neither is traced after `-p`, so the sandbox's `SIGSYS` signals never pass through whatfiles. The tabs survive only because whatfiles isn't watching them, as finding 5 shows.
- **A second `firefox` command doesn't create the tabs.** It finds the running instance, asks that instance to open a window, and exits. The new window's tabs belong to the original instance, which isn't traced. This follows from how Firefox reuses a running instance and was not tested here.

### Why it is intermittent with current Firefox

Commit `931b513` added the detach branch while debugging this crash. Its message reads: "detach from processes that don't let us inspect registers … firefox tabs crashing". The branch treats `orig_rax == -1` as a failure to read registers. It actually means the thread stopped outside a syscall, for example on a fault or on a signal that arrived during user code. The `SIGSEGV` from the crashing tab is exactly such a stop.

With `-d`, two of three runs showed exactly one detach, from the main Firefox process during startup. After that nothing Firefox spawned was traced. The screenshot succeeded and the log held no tab activity at all. In the third run the main process stayed traced, so the tabs were traced too, and they crashed in a loop with 25 detaches.

### Fix

This minimal change to `step_syscall()` in `src/x86_64/registers.c` produced the passing Firefox runs above. It is a proof of the diagnosis, not the final design.

```c
bool step_syscall(pid_t current_pid, int proc_status, HashMap map)
{
    long res;
    struct user_regs_struct regs;
    int stopsig = WSTOPSIG(proc_status);
    bool event_stop = (proc_status >> 16) != 0;

    // Signal-delivery-stop: hand the signal back to the tracee. SIGSTOP stays suppressed
    // because it is the initial stop of every auto-attached child/thread.
    if (!event_stop && stopsig != SIGTRAP && stopsig != SIGSTOP) {
        res = ptrace(PTRACE_SYSCALL, current_pid, 0, stopsig);
        if (res == -1L) DEBUG("ptrace() failed to resume %d with signal %d\n", current_pid, stopsig);
        return true;
    }

    res = ptrace(PTRACE_GETREGS, current_pid, &regs, &regs);
    if (res == -1L) {
        DEBUG("CURRENT PID: %d, failed to get registers\n", current_pid);
        return false;
    }
    if (!is_exiting(current_pid, regs.orig_rax)) {
        check_syscall(current_pid, (void*)&regs, map);
    }
    LastSyscall.pid = current_pid;
    LastSyscall.syscall = regs.orig_rax;
    if (event_stop) check_ptrace_event(current_pid, proc_status, map);
    res = ptrace(PTRACE_SYSCALL, current_pid, 0, 0);
    if (res == -1L) DEBUG("ptrace() failed to resume");
    return true;
}
```

A complete fix should also do the following:

- **Mark syscall stops.** Set `PTRACE_O_TRACESYSGOOD` so syscall stops report `SIGTRAP | 0x80`. Without it, a real `SIGTRAP` sent to the tracee is still swallowed.
- **Suppress `SIGSTOP` only once.** Swallow only the first `SIGSTOP` of each newly attached thread. Handle group-stops properly, ideally by attaching with `PTRACE_SEIZE` and using `PTRACE_LISTEN`.
- **Remove the detach branch.** Check the return value of `PTRACE_GETREGS` instead.
- **Fix all four architectures.** `step_syscall()` is copied into each registers file, so it should move into shared code.

---

## 2. Other findings

### High

#### 2. Tracing silently stops on any user-mode signal

**Code:** `src/x86_64/registers.c:98-116`, with the same logic in the x86, arm32, and arm64 files.

When a signal arrives while a thread runs user code, `orig_rax` is -1. whatfiles then calls `PTRACE_DETACH` with signal 0, which loses the signal. It also stops following that thread and anything it spawns later. The log shows nothing unless `-d` is on. The detached PID also stays in the hash map, so the main loop can only end through the `wait()` failure path.

**Verified.** A program set a 200 ms `SIGALRM` timer and busy-looped until the handler ran, then opened a file. Under whatfiles:

```
SIGALRM handler ran: NO (waited 3.00s)
```

The open after the loop was not logged. For a tool meant to watch untrusted software, this is also a trivial way to escape monitoring.

#### 3. Open mode comes from the wrong register, so writes are logged as reads

**Code:** `src/x86_64/registers.c:50,56,62`, `src/x86/registers.c:50,57,62`, `src/arm32/registers.c:51,58,63`, `src/arm64/registers.c:50-51`, and `get_mode()` in `src/utilities.c:51-61`.

Every architecture passes the `mode` argument (the permission bits) to `get_mode()` instead of `flags`.

| Syscall | flags register | Register the code reads |
|---------|---------------|-------------------|
| x86_64 `open` | `rsi` | `rdx` (mode) |
| x86_64 `openat` | `rdx` | `r10` (mode) |
| x86 `open` / `openat` | `ecx` / `edx` | `edx` / `esi` |
| arm32 `open` / `openat` | `r1` / `r2` | `r2` / `r3` |
| arm64 `openat` | `x2` | `x3` for the mode label, but `x2` for the raw value |
| `creat` (all) | none; always write+create+truncate | treats the mode as flags |

glibc passes a mode of 0 whenever `O_CREAT` is absent, so every open without it is labeled `read`.

**Verified on x86_64:**

| Call | Logged mode |
|------|-------------|
| `openat(..., O_WRONLY\|O_CREAT\|O_TRUNC, 0644)` | `0x1A4` |
| `open(f, O_WRONLY\|O_TRUNC)` | `read` |
| `open(f, O_WRONLY\|O_APPEND)` | `read` |
| `open(f, O_RDWR)` | `read` |
| raw `open(2)` with `O_WRONLY\|O_TRUNC` | `read` |
| raw `creat(2)` with `0600` | `0x180` |

The repo's own `scraps/syscall_test.c` shows the bug too: `open(O_RDWR)` and `openat(O_RDWR|O_APPEND)` are both logged as `read`. Its `creat` shows `create` only because `S_IRWXU` happens to include bit `0100`, which has the same value as `O_CREAT`.

`get_mode()` has problems of its own once it reads the right register:

- **Access mode isn't masked.** It never masks with `O_ACCMODE`, so `O_RDONLY|O_CLOEXEC` would print a raw hex value.
- **Only the last match survives.** It overwrites earlier matches, so `O_RDWR|O_CREAT` becomes just `create`.
- **Key flags are ignored.** It ignores `O_TRUNC` and `O_APPEND`, which also mean the file is modified.

#### 4. Syscall entry/exit tracking drops and duplicates lines

**Code:** `is_exiting()` in `src/utilities.c:113-116` and the global `LastSyscall` in `src/whatfiles.c:19`.

A stop counts as an exit if it has the same PID and syscall number as the previous stop from *any* thread.

- **Same syscall twice in a row.** A thread that makes the same syscall twice has its second entry treated as an exit. **Verified:** three back-to-back `open()` calls logged only the first. The same thing hid one case in the mode test above.
- **Interleaved threads.** When threads interleave, an exit looks like a fresh entry and is logged again. **Verified:** 4 threads × 250 opens gave **1983** log lines for 1000 unique paths. Launch mode also logged 21 main-thread opens for 20 real ones.

The fix is per-thread state. The hash map already has an unused `status` field for this. Alternatively, `PTRACE_GET_SYSCALL_INFO` (Linux 5.3+) reports whether a stop is an entry or an exit directly.

#### 5. Attach mode doesn't follow processes spawned by other threads

**Code:** `src/attach.c:128`.

Options are set only on the thread whose ID equals the PID. Other existing threads get no fork, clone, or exec tracking. The README's claim that whatfiles "traces any new processes and threads" is only true in launch mode.

**Verified.** A test program's main thread opens one marker path, and a worker thread forks children that open another.

| Mode | Main-thread opens logged | Opens from the worker's children logged |
|------|----------------------|-------------------------------------|
| launch | 21 / 20 | 20 / 20 |
| `-p` attach | 16 / 20 (attached about 0.5 s in) | **0 / 20** |

To test attach without root, a small harness forked the target and then exec'd `whatfiles -p` from the parent process.

**Fix:** set options on every attached thread. `PTRACE_SEIZE` accepts options at attach time.

#### 6. A failed attach leaves the target process stopped

**Code:** `src/attach.c:78` and `src/attach.c:104-115`.

`attach_to_process()` sends `SIGSTOP` before calling `PTRACE_ATTACH`. If attaching fails, it returns without sending `SIGCONT`. This happens for a non-root user under Yama `ptrace_scope=1`, which is the Ubuntu default. It also happens when a debugger is already attached.

**Verified:**

```
$ sleep 60 &            # state S
$ whatfiles -s -p $!
error attaching to process: Operation not permitted     (exit code 22)
$ ps -o stat= -p <pid>
T
```

Other attach-path loops can also hang (not reproduced):

- **Waiting for a stop.** The loop at `src/attach.c:80-86` waits forever for state `T` if the target never stops, for example a zombie.
- **Retrying on `ESRCH`.** The loops at `src/attach.c:101-103` and `163-165` retry forever on that error, which is returned for a thread that exited or is no longer traced. The detach loop runs after its own `SIGSTOP` and before `SIGCONT`, so hanging there leaves the target frozen.

### Medium

#### 7. Ctrl-C loses the log in launch mode and is ignored in attach mode

- **Launch mode.** No signal handler is installed, and the log is a fully buffered `FILE*`. On `SIGINT` the process dies without flushing. **Verified:** an interrupted run left a **0-line** log. The same command left 13 lines when allowed to finish.
- **Attach mode.** `SIGINT` and `SIGTERM` are blocked and only checked between `wait()` calls at `src/whatfiles.c:183-199`. If the target is idle, `wait()` never returns. **Verified:** attached to `sleep 25`, whatfiles was still running 3 s after `SIGINT`.

**Fix options:** flush the log per line, or call `fflush()` in a handler. For attach mode, use `signalfd` or `sigtimedwait`, or a `waitpid(WNOHANG)` loop.

#### 8. 32-bit syscalls are invisible and misread on x86_64

`check_syscall()` always interprets `orig_rax` with the 64-bit syscall table. Syscalls made through `int $0x80`, by any 32-bit program or by a 64-bit program on purpose, use different numbers.

**Verified.** One test program made two 32-bit syscalls:

- **A real open is missed.** It opened `/etc/hostname` with 32-bit syscall 5 and read 13 bytes. Nothing was logged.
- **A fake open is logged.** It called 32-bit syscall 257 (`remap_file_pages`, which failed with `EINVAL`). whatfiles logged `mode: read, file: /phantom/never-opened, syscall: openat()` because 257 is `openat` on x86_64.

**Fix:** find the syscall ABI using `PTRACE_GET_SYSCALL_INFO`'s `arch` field or the `cs` register, and decode accordingly.

#### 9. Filenames can inject fake log lines

Filenames are written to the log unescaped. **Verified:** opening the path `"/tmp/x\nmode:  read, file: /etc/FORGED-ENTRY, syscall: openat(), PID: 1, process: init"` produced two log lines. The second one is attributed to PID 1:

```
mode:  read, file: /tmp/x
mode:  read, file: /etc/FORGED-ENTRY, syscall: openat(), PID: 1, process: init, syscall: openat(), PID: 39289, process: ./t_forge
```

**Fix:** escape control characters and non-UTF-8 bytes, or switch to a structured format.

#### 10. `exec` from a non-main thread leaves a stale hash map entry

**Code:** `src/whatfiles.c:57-77`.

When a non-main thread calls `execve`, the kernel gives it the process ID. It reports the old thread ID in the event message, and that ID never produces an exit notification. whatfiles inserts the new ID but never removes the old one, so `used` never reaches 0. The name is also wrong: `execve` sets the name on the calling thread's ID, so the new program keeps the old name.

**Verified.** A thread exec'd `/bin/true`. Its loader's opens were logged under the old program name. whatfiles ended with `whatfiles exiting: No child processes` and exit code 22 instead of a clean exit.

#### 11. Removing a hash map entry lets duplicate keys be inserted

**Code:** `src/hashmap.c:47-73` and `176-189`.

- **Duplicates.** `remove_pid()` empties a slot without leaving a tombstone. `insert()` stops at the first empty slot on its probe path without checking the rest of the chain. A key that had been pushed past a now-empty slot gets inserted a second time.
- **Slow lookups.** `find_index()` probes linearly while `insert()` probes quadratically. `find_index()` also never stops at an empty slot, so every lookup of an unknown PID scans the whole table.

**Verified with a unit test on `src/hashmap.c`:**

```
used after re-inserting existing pid: 2 (expected 1)
used after pid exits: 1 (expected 0); pid still found: yes
```

In whatfiles this happens when `check_ptrace_event()` re-inserts an existing PID on exec, after an earlier process with the same home slot has exited. Once it happens, whatfiles can't reach the "all children exited" exit.

#### 12. The log file descriptor leaks into the traced program

The log is opened with `fopen(..., "w")` before `fork()`, without close-on-exec. **Verified:** the traced shell had `3 -> …/fd.log` open for writing. A traced program can write to or truncate the log, and every descendant inherits the descriptor.

**Fix:** open with `"we"`, or set `O_CLOEXEC`.

#### 13. Unsafe default log file creation

**Code:** `src/whatfiles.c:110-119`.

- **Predictable name.** The default name `./whatfiles<unix-time>.log` is predictable, and `fopen("w")` follows symlinks and truncates. The README and usage text encourage `sudo whatfiles ...`. Run as root in a directory other users can write to, whatfiles can be made to truncate an arbitrary file. Protected symlinks prevent this in sticky directories like `/tmp`, but not everywhere.
- **Name collisions.** Two runs started in the same second overwrite each other's log.
- **Format mismatch.** `time()` is printed with `%lu`, which is a format mismatch on systems with a 32-bit `long` but a 64-bit `time_t`.

**Fix:** use `O_CREAT|O_EXCL|O_NOFOLLOW` or `mkstemps`.

#### 14. Coverage gaps

These are limitations more than bugs, but they matter for the stated goal of knowing what a program "reads/writes/creates/deletes":

- **Attempts, not results.** The log records attempts at syscall entry. A failed `open` (`ENOENT`, `EACCES`) looks the same as a successful one. Logging at exit with the return value would fix this.
- **Unresolved paths.** Relative paths are logged as given. For `openat` and `unlinkat`, the directory descriptor isn't resolved, even though `/proc/<pid>/cwd` and `/proc/<pid>/fd/<dirfd>` could resolve them.
- **Missing syscalls.** These are not tracked:
  - `rename`, `renameat`, `renameat2`
  - `mkdir`, `mkdirat`, and `rmdir`
  - `unlinkat` with `AT_REMOVEDIR`, which is labeled "delete"
  - `link` and `symlink`
  - `truncate`
  - `chmod` and `chown`
  - `openat2`
  - `execveat`, and `execve` is never logged as file access
  - `io_uring` file operations, which bypass syscalls entirely
- **Racy path reads.** The path is read from tracee memory at entry, so another thread can change it before the kernel uses it.
- **Detectable tracing.** The tracer is visible to the traced program through `TracerPid` in `/proc/self/status`.

The README could say plainly that whatfiles is not a security boundary against hostile software.

### Low

**Correctness and robustness:**

- **Filename truncation.** `peek_filename()` treats a data word equal to -1 as an error (`src/utilities.c:82`). A path whose first 8 bytes are `0xFF` is logged with an empty filename (**verified**). Check `errno` instead, or use `process_vm_readv`.
- **Uninitialized registers.** `step_syscall()` reads `regs` even when `PTRACE_GETREGS` fails (`src/x86_64/registers.c:88-98`, and the x86 and arm32 files). The struct is uninitialized, so this is undefined behavior.
- **Wrong syscall-number source on arm64.** arm64 uses `x8` as the syscall number and `x8 != -1` as its "registers readable" test (`src/arm64/registers.c:82`). At a non-syscall stop, `x8` holds arbitrary data. `NT_ARM_SYSTEM_CALL` or `PTRACE_GET_SYSCALL_INFO` gives the real value.
- **Out-of-bounds read.** `read_task()` reads `str->data[str->len-1]` when `len` is 0 (`src/attach.c:63`), and `delete_char()` would underflow.
- **Misleading exit codes.** `SYS_ERR` calls `exit(errno)` after `perror()`, which can change `errno`. Observed exit codes were 22 for both `EPERM` and `ECHILD` failures.
- **Failed exec returns 0.** If the command fails to execute, whatfiles exits with 0 (`src/whatfiles.c:158`) and leaves an empty log.
- **Wrong signal target.** `detach_from_process()` calls `kill()` with thread IDs (`src/attach.c:149,168`), which signals the whole process. `tgkill()` targets one thread.
- **Weak `-p` parsing.** `-p` uses `atoi`, which accepts `12abc`. A command given together with `-p` is silently ignored.
- **Tracer can be killed.** Launch mode doesn't set `PTRACE_O_EXITKILL`. If whatfiles is killed, the program keeps running untraced.

**Leaks and wasted work:**

- **Memory leaks.** `read_status()` leaks its buffer when `fopen` fails (`src/attach.c:35-37`). `check_ptrace_event()` leaks on its early return (`src/whatfiles.c:26-32`). The thread-ID list from `get_tids()` is never freed.
- **Extra work per stop.** `check_ptrace_event()` is called for every stop. That means a `PTRACE_GETEVENTMSG` call and a 128-byte `malloc`/`free` per stop, even though only event stops need it.

**Code hygiene:**

- **Dead code.** `get_command()` calls `getline()` on a caller-supplied buffer that wasn't allocated with `malloc`, which is undefined behavior if it is ever used. `get_name()` assigns to its own parameter and has no effect. `get_status`, `increment`, and `decrement` are unused.
- **Confusing includes.** `src/utilities.c:7` includes `"string.h"`, which resolves to libc's `<string.h>` only because no local file has that name. The local header `strings.h` shares its name with the POSIX `<strings.h>` header.
- **Unsafe macros.** `DEBUG` and `HASH_ERR_CHECK` expand to bare `if` statements, which invites dangling-`else` bugs. They should be wrapped in `do { … } while (0)`.
- **Duplication.** The four `registers.c` files duplicate `step_syscall()` and most of `check_syscall()`. The architecture layer only needs to supply the syscall number, the arguments, and the syscall table.
- **Compiler warnings.** `-Wextra` reports 7 warnings: 6 sign comparisons and 1 unused parameter.

**Makefile:**

- **Missing rebuild dependencies.** `bin/whatfiles` doesn't depend on the headers or on `src/$(ARCH_DIR)/registers.c`, so editing those doesn't trigger a rebuild.
- **Wrong architecture fallback.** Unknown architectures such as riscv64 and ppc64le silently fall back to the x86_64 file, which fails to compile with confusing errors.
- **Install and target issues.** There is no `.PHONY`, and `install` ignores `PREFIX` and `DESTDIR`.

---

## 3. Performance

whatfiles stops every thread twice for *every* syscall, then reads registers and makes more ptrace calls on each stop. The benchmark workload was `find /usr/share/doc -type f -exec head -c1 {} +`, which produced 18,355 logged opens.

| Configuration | Wall time |
|---------------|-----------|
| native | 0.13 s |
| whatfiles (before) | 2.25 s |
| whatfiles (after these fixes) | 1.99 s |
| `strace -f -e trace=open,openat,creat,unlink,unlinkat` | 2.07 s |
| `strace -f --seccomp-bpf` (same filter) | 0.57 s |

A seccomp filter installed in the child before `exec` can return `SECCOMP_RET_TRACE` only for the syscalls of interest, which avoids most stops. This is how `strace --seccomp-bpf` works, and the table shows it is about four times faster. Reading paths with `process_vm_readv` instead of word-by-word `PTRACE_PEEKDATA` also helps, and that part was done.

**The seccomp filter was deliberately not implemented.** Two problems make it a bad default for this tool:

- **It breaks the traced program if whatfiles goes away.** A `SECCOMP_RET_TRACE` syscall with no tracer attached does not run: the kernel skips it and returns `ENOSYS`. The filter cannot be removed once installed, so every `open()` in the program would fail from the moment whatfiles is interrupted or crashes. For a tool people point at installers, that is worse than being slow.
- **It blocks setuid programs.** The filter requires `PR_SET_NO_NEW_PRIVS`, which the traced program inherits, so `whatfiles sudo ...` would stop working.

The other caveat still stands as well: when several filters apply, seccomp uses the most restrictive result, so Firefox's `SECCOMP_RET_TRAP` would override `SECCOMP_RET_TRACE` and brokered opens would appear in the broker process rather than the tab process. Worth revisiting as an opt-in flag paired with `-k`, where killing the program on exit removes the first objection.

---

## 4. Checked and found fine

- **Probe coverage.** For table sizes 1024, 2048, and 4096, the quadratic probe sequence reaches every slot, so `insert()` cannot loop forever at the 25% load limit.
- **Sanitizers.** An AddressSanitizer and UndefinedBehaviorSanitizer build traced several workloads without reports: the thread test, `scraps/syscall_test`, the fork test, and `ls -la /`.
- **Static analysis.** `gcc -fanalyzer` reported nothing.
- **Launch-mode children.** Launch mode correctly follows children spawned by any thread, because traced children inherit their parent's ptrace options.

---

## 5. Suggested order of work

1. **Rework stop handling (fixes the known issue).**
   - Set `PTRACE_O_TRACESYSGOOD`.
   - Re-inject signals.
   - Delete the detach branch.
   - Track syscall entry and exit per thread, or use `PTRACE_GET_SYSCALL_INFO`.
   - Share the logic across architectures.
2. **Decode `flags` from the right register**, and mask with `O_ACCMODE`.
3. **Fix attach mode.**
   - Attach with `PTRACE_SEIZE` and set options on every thread.
   - Send `SIGCONT` on every failure path.
   - Make Ctrl-C responsive.
4. **Make the log trustworthy.**
   - Flush it on exit and interruption.
   - Open it with close-on-exec and exclusive creation.
   - Escape filenames.
5. **Fix the process table.** Remove the old thread ID on exec, and either add tombstones or replace the hash map with something simpler.
6. **Widen coverage.**
   - Log return values and resolve relative paths.
   - Add the missing syscalls.
   - Handle 32-bit syscalls.
7. **Improve performance** with a seccomp-bpf `SECCOMP_RET_TRACE` filter.

---

## Appendix A: reproducers

### Firefox sandbox pattern (`SECCOMP_RET_TRAP` + `SIGSYS` broker)

```c
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucontext.h>
#include <unistd.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

static int brokered_fd = -1;
static volatile sig_atomic_t sigsys_count = 0;

static void sigsys_handler(int sig, siginfo_t *info, void *vctx)
{
    ucontext_t *ctx = vctx;
    sigsys_count++;
    ctx->uc_mcontext.gregs[REG_RAX] = dup(brokered_fd); // "broker" the open
}

int main(void)
{
    brokered_fd = open("/etc/hostname", O_RDONLY);
    struct sigaction sa = { .sa_sigaction = sigsys_handler, .sa_flags = SA_SIGINFO };
    sigaction(SIGSYS, &sa, NULL);

    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = { sizeof(filter) / sizeof(filter[0]), filter };
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);

    int fd = open("/etc/hostname", O_RDONLY);
    char buf[256];
    ssize_t n = read(fd, buf, sizeof buf);
    fprintf(stderr, "sandboxed open() returned %d, SIGSYS handler ran %d time(s), read() returned %zd%s%s\n",
            fd, (int)sigsys_count, n, n < 0 ? ": " : "", n < 0 ? strerror(errno) : "");
    if (n < 0) abort(); // where Firefox would MOZ_CRASH
    return 0;
}
```

Run it as `whatfiles -o log ./t_seccomp_trap`.

### Other tests used

- **Signal delivery:** `raise(SIGUSR1)` and `raise(SIGCHLD)` with a counting handler.
- **User-mode signal:** a one-shot `setitimer` `SIGALRM` during a busy loop, followed by `open()`.
- **Open modes:** the calls in the table under finding 3.
- **Back-to-back syscalls:** three `open()` calls with nothing in between.
- **Threads:** 4 threads × 250 `open()` calls, with `getppid()` between opens.
- **Attach coverage:** a main thread opening a marker path while a worker thread forks children that open another. A harness forks the target and then execs `whatfiles -p <child>`, which satisfies Yama `ptrace_scope=1` without root.
- **32-bit syscalls:** a non-PIE x86_64 binary calling `int $0x80` with syscall 5 (`open`) and 257.
- **Hash map:** insert A, insert B with the same home slot, remove A, re-insert B, remove B.
- **Firefox:** `firefox --headless --no-remote --profile <fresh dir> --screenshot out.png file:///…/page.html`, run with `DISPLAY` unset and `MOZ_CRASHREPORTER_NO_REPORT=1`.

## Appendix B: environment

- **System:** Ubuntu 24.04, kernel 6.8.0-139-generic, x86_64.
- **Kernel settings:** `CONFIG_IA32_EMULATION=y`, Yama `ptrace_scope=1`.
- **Tools:** gcc 13.3.0 and strace, with Firefox 155.0.1 from `/usr/lib/firefox`, not the snap.
- **Build:** whatfiles was built from `a3c17cf` with the Makefile's flags (`-Wall -std=gnu99`). The signal-fix build replaced only `step_syscall()` in `src/x86_64/registers.c`.
