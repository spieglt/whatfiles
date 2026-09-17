# whatfiles 2.0

A correctness release. Signals reach the programs being traced, the log tells you whether each
operation succeeded, attaching no longer risks freezing the target, and Android is supported and
tested.

**If you script against the log, read the breaking changes below.** The line format gained a
field and paths are now absolute.

## Why this is 2.0

The previous version resumed every traced process with signal 0, which discards every signal the
kernel was trying to deliver. Any program that relies on a signal handler misbehaves under
tracing. The visible case was Firefox: its tab processes ask the parent to open files for them by
way of `SIGSYS`, and with that signal dropped the handler never ran, `openat()` appeared to return
the syscall number as a file descriptor, font loading failed, and the tab aborted. That was the
long-standing "known issue" in the README. It is fixed, and the browser now runs under whatfiles
with every sandboxed process traced.

The same class of bug ran through the rest: writes reported as reads, lines dropped or duplicated,
child processes missed when attaching, and a failed attach that left its target stopped.

## Breaking changes

- **Log lines carry a result.** Every line now ends with `result: <value>`, so a failed open is
  distinguishable from a successful one. Anything parsing the old format needs updating.
- **Paths are absolute.** Relative paths are resolved against the process's working directory, or
  against the directory passed to an `*at()` syscall.
- **Modes are more precise.** The `mode:` column now reads `write+create+trunc`, `write+append`,
  `rd/wr` and so on, where the old version usually said `read` regardless, because it decoded the
  wrong argument.
- **Filenames are escaped.** Control characters appear as `\n`, `\t` or `\xNN`, so a crafted
  filename can no longer forge a log line.
- **Exit status mirrors the traced program.** whatfiles exits with the program's own status, or
  127 if it could not be run.
- **The default log name includes the process ID**, and is created with `O_EXCL` and `O_NOFOLLOW`.

## Fixed

- Signals are passed through to the traced program instead of being discarded.
- Tracing no longer stops silently when a signal arrives while the program is running user code.
  The old build detached at that point and said nothing unless `-d` was given.
- Open modes are decoded from the flags argument rather than the mode argument, on every
  architecture.
- Syscall entry and exit are tracked per thread, so repeated syscalls are no longer dropped and
  interleaved threads no longer produce duplicate lines.
- Attaching sets tracing options on every thread, so child processes started by any thread are
  followed. Previously only the main thread's children were.
- A refused attach leaves the target running. It used to leave it stopped by a `SIGSTOP` that was
  never undone.
- Ctrl-C keeps the log and detaches cleanly, and is noticed even while every traced process is
  idle. Previously it discarded the log in launch mode and was ignored in attach mode.
- 32-bit syscalls are decoded with the right table, so they are neither missed nor mistaken for
  unrelated 64-bit ones.
- `exec` from a non-main thread no longer leaves a stale entry that kept whatfiles from finishing.
- The task map no longer creates duplicate entries after a removal.
- The log file descriptor no longer leaks into the traced program.
- Job-control stops are handled properly: Ctrl-Z on a traced program stops it rather than secretly
  resuming it.

## New

- **More syscalls**: `rename`, `link`, `symlink`, `mkdir`, `rmdir`, `truncate`, `chmod`, `chown`,
  `openat2` and `exec`, alongside the open and delete family.
- **Android**: `make android NDK=...` builds for arm64, arm32, x86_64 or x86, and
  `make test-android` runs the test suite on a connected device.
- **`-k`** kills the traced program if whatfiles itself is killed, instead of letting it continue
  untraced.
- **A test suite**: `make test` runs 35 checks covering signal delivery, thread and child-process
  coverage, path resolution, log escaping and interrupt handling.

## Verified

- 35 checks pass on x86_64, and again on a build forced onto the pre-5.3 kernel path.
- 14 checks pass on an Android 14 emulator as the ordinary shell user with SELinux enforcing.
  Attaching to a running app as root logs its file access and leaves it running.
- All four Android ABIs compile without warnings.
- Address and undefined-behavior sanitizers are clean across launch, attach and interrupt.
- Headless Firefox runs three times out of three with every sandboxed process traced, no crashes
  and no crash dumps.

## Requirements

Linux 3.4 or newer. On Linux 5.3 and newer, whatfiles asks the kernel directly about each syscall
stop, which is what makes 32-bit syscalls decode correctly; on older kernels it reads registers
instead.

## Known limitations

- A program that does not want to be watched can tell that it is being traced, and `io_uring`
  performs file operations without the syscalls whatfiles watches.
- Programs that hand off to an already-running instance, browsers especially, exit immediately, so
  there is nothing left to trace. Start a separate instance instead.
- Tracing a 32-bit app from an arm64 build is implemented but has not been exercised on hardware.
