# whatfiles
[![build and test](https://github.com/spieglt/whatfiles/actions/workflows/ci.yml/badge.svg)](https://github.com/spieglt/whatfiles/actions/workflows/ci.yml)

Whatfiles is a Linux utility that logs what files another program reads/writes/creates/deletes on your system. It traces any new processes and threads that are created by the targeted process as well, and records whether each operation succeeded.

## Rationale:
I've long been frustrated at the lack of a simple utility to see which files a process touches from `main()` to exit. Whether you don't trust a software vendor or are concerned about malware, it's important to be able to know what a program or installer does to your system. `lsof` only observes a moment in time and `strace` is large and somewhat complicated.

## Sample output:
```
mode:   exec, file: /usr/bin/cp, syscall: execve(), PID: 17004, process: sh, result: 0
mode:   read, file: /tmp/demo/copy.txt, syscall: openat(), PID: 17004, process: /usr/bin/cp, result: -1 (No such file or directory)
mode:   read, file: /etc/hostname, syscall: openat(), PID: 17004, process: /usr/bin/cp, result: 3
mode: write+create, file: /tmp/demo/copy.txt, syscall: openat(), PID: 17004, process: /usr/bin/cp, result: 4
mode:  chmod, file: /tmp/demo/copy.txt, syscall: fchmodat(), PID: 17005, process: /usr/bin/chmod, result: 0
mode: rename, file: /tmp/demo/copy.txt, to: /tmp/demo/renamed.txt, syscall: renameat2(), PID: 17006, process: /usr/bin/mv, result: 0
mode:   read, file: /tmp/demo/missing.txt, syscall: openat(), PID: 17007, process: /usr/bin/cat, result: -1 (No such file or directory)
mode: delete, file: /tmp/demo/renamed.txt, syscall: unlinkat(), PID: 17008, process: /usr/bin/rm, result: 0
```

Each line says what was done to the file, the file itself, which syscall did it, which process and thread, and what the kernel returned. Paths are always absolute: relative paths are resolved against the process's working directory, or against the directory it passed to an `*at()` syscall. `result` is the syscall's return value, so failed and successful access can be told apart.

Besides opening, creating and deleting, whatfiles reports `rename`, `link`, `symlink`, `mkdir`, `rmdir`, `truncate`, `chmod`, `chown` and `exec` of a program. [SYSCALLS.md](SYSCALLS.md) covers what is not reported yet and why each addition would be worth making.

## Use:

- basic use, launches `ls` and writes output to a log file in the current directory:

    `$ whatfiles ls -lah ~/Documents`

- specify output file location with `-o`:

    `$ whatfiles -o MyLogFile cd ..`

- include debug output, print to stdout rather than log file:

    `$ whatfiles -d -s apt install zoom`

- attach to currently running process (requires root privileges):

    `$ sudo whatfiles -p 1234`

- kill the traced program if whatfiles itself is killed, instead of letting it continue untraced:

    `$ whatfiles -k ./installer.sh`

Press Ctrl-C at any time: whatfiles detaches from everything it is tracing, leaves those processes running, and finishes writing the log.

## Distribution
Ready-to-use binaries are on the [releases](https://github.com/spieglt/whatfiles/releases) page! Someone also kindly added it to the [Arch](https://aur.archlinux.org/packages/whatfiles-git/) repository, and [letompouce](https://github.com/letompouce) set up a [GitLab](https://gitlab.com/l3tompouce/builders/whatfiles) pipeline as well.

## Compilation (requires `gcc` and `make`):
```
$ cd whatfiles
$ make
$ sudo make install
```
Supports x86, x86_64, ARM32, and ARM64 architectures. `make install` honors `PREFIX` and `DESTDIR`.

Linux 3.4 or newer is required. On Linux 5.3 and newer, whatfiles asks the kernel directly about each syscall stop, which is what makes 32-bit syscalls on a 64-bit machine decode correctly; on older kernels it falls back to reading registers.

### Android

Cross-compile with the NDK, then push the binary to the device:

```
$ make android NDK=~/Android/Sdk/ndk/<version>
$ adb push bin/whatfiles-android /data/local/tmp/whatfiles
$ adb shell chmod 755 /data/local/tmp/whatfiles
$ adb shell /data/local/tmp/whatfiles -o /data/local/tmp/ls.log ls /sdcard
```

`ANDROID_ABI` selects `arm64`, the default, or `arm32`, `x86_64` or `x86`. `ANDROID_API` sets the
minimum API level and defaults to 21.

A few things differ on a device:

- Put the binary in `/data/local/tmp`. `/sdcard` is mounted without execute permission.
- The working directory in `adb shell` is not writable, so pass `-o` with a path under
  `/data/local/tmp`, or `-s` to write to stdout.
- Running a command under whatfiles works as the ordinary shell user, and so does attaching to a
  process that user started. Attaching to anything else, an app for instance, needs root, so
  `adb root` on a userdebug build. On an Android 14 emulator that worked with SELinux enforcing;
  a production device's policy may still refuse.
- `make test-android NDK=~/Android/Sdk/ndk/<version>` builds whatfiles and the test programs for
  the connected device, runs the checks there, and removes what it pushed.
- A 32-bit app traced from an arm64 build is read with the 32-bit syscall numbers and argument
  registers rather than being taken for a 64-bit one. That path has not been exercised on real
  hardware: the emulator used for testing here has no 32-bit ABI.

`make test` builds the programs in `tests/` and runs them under whatfiles to check its behavior, including signal delivery, thread and child-process coverage, and interrupt handling.

## Questions that could be asked at some point:

- _Isn't this just a reimplementation of `strace -fe trace=creat,open,openat,unlink,unlinkat ./program`?_

  Yes. Though it aims to be simpler and more user friendly.

- _Are there Mac and Windows versions?_

  No. Tracing syscalls on Mac requires `task_for_pid()`, which requires code signing, which I can't get to work, and anyway I have no interest in paying Apple $100/year to write free software. `dtruss` on Mac can be used to follow a single process and its children, though the `-t` flag seems to only accept a single syscall to filter on. `fs_usage` does something similar though I'm not sure if it follows child processes/threads. Process Monitor for Windows is pretty great.

## Limitations:

- **Programs that hand off to a copy of themselves.** Browsers especially: if an instance is already
running, the one you launch passes your request to it and exits, so whatfiles has nothing left to
trace and stops, while the window you asked for comes from the untraced copy. Trace a separate
instance instead, with something like `whatfiles firefox --no-remote --profile ~/ff-trace-profile`
and a profile directory that does not exist yet, or quit the running copy first.

- **Not a security boundary.** A program that doesn't want to be watched can tell that it is being traced, and `io_uring` performs file operations without the syscalls whatfiles watches. Treat the log as a description of what a program did, not as proof of everything it could have done.

- **Speed.** Every syscall stops the traced process twice, so syscall-heavy programs run several times slower than usual. This is the same cost `strace` pays when following all syscalls.

- **Attaching needs privileges.** `-p` generally requires root, or a relaxed `/proc/sys/kernel/yama/ptrace_scope`. A refused attach leaves the target running normally.

- **If whatfiles is killed outright** with `SIGKILL`, the program it was tracing keeps running, untraced, unless it was started with `-k`.

## Planned features:

- None currently, open to requests and PRs.

Thank you for your interest, and please also check out [Cloaker](https://github.com/spieglt/cloaker), [Nestur](https://github.com/spieglt/nestur), and [Flying Carpet](https://github.com/spieglt/flyingcarpet)!
