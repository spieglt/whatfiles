# Syscall coverage

What whatfiles reports today, what it does not, and what each addition would buy.

## Reported today

| Group | Syscalls |
|-------|----------|
| Open | `open`, `openat`, `openat2`, `creat` |
| Remove | `unlink`, `unlinkat`, `rmdir` |
| Create directories | `mkdir`, `mkdirat` |
| Move | `rename`, `renameat`, `renameat2` |
| Link | `link`, `linkat`, `symlink`, `symlinkat` |
| Size and metadata | `truncate`, `chmod`, `fchmodat`, `chown`, `lchown`, `fchownat` |
| Run a program | `execve`, `execveat` |

Each is logged at syscall exit with its result, and paths are resolved to absolute ones.

## The test for adding a syscall

A syscall earns a line in the log if it changes a file's **contents**, **existence**, **name**, or
**metadata**, or if it reveals **which file a program read**. Anything else is noise, and noise has
a real cost here: every logged line is a path read out of the traced process, and the log is meant
to be something a person reads to the end.

Two further rules follow from experience with the current set. A syscall that takes a descriptor
instead of a path needs `/proc/[pid]/fd/[n]` resolved at the time of the call, because the
descriptor tells the reader nothing. And a syscall that changes what later paths *mean* matters
even though it touches no file itself.

## Worth adding, in order

### 1. Descriptor-based changes

`ftruncate`, `fchmod`, `fchown`, `fallocate`

Today the log says a file was opened for writing. These say it was actually changed. This is the
largest gap between what whatfiles reports and what it claims to report, since a program that
opens a file for writing and then does nothing looks identical to one that empties it.

Each takes a descriptor as its first argument, so each needs a `readlink` of `/proc/[pid]/fd/[n]`
while the descriptor is still open, which means at syscall entry. `read_tracee_path` already does
exactly this lookup for the directory descriptor of the `*at` calls.

`write` and `pwrite` belong to this family too, but they are far too frequent to log by default:
a single `cp` produces thousands. If they are ever added, the useful form is one line for the
first write to a descriptor, not one line per call, or a flag that the user turns on deliberately.

### 2. `mknod`, `mknodat`

Creates device nodes, FIFOs and sockets. Installers and package managers do this, it is
privilege-relevant, and it is currently invisible: a program can create a device node and the log
stays silent.

### 3. The extended attribute family

`setxattr`, `lsetxattr`, `fsetxattr`, `removexattr`, `lremovexattr`, `fremovexattr`

This is how SELinux labels, POSIX capabilities and ACL data are written. On Android it is close to
the whole point, since labels decide what an app may touch. `fsetxattr` needs descriptor
resolution as above.

### 4. Timestamps

`utimensat`, `futimesat`, `utimes`

Archive extraction and installers set timestamps, and a changed timestamp is a change to the file.
Cheap to add: the path arguments are shaped like the ones already handled.

### 5. What later paths mean

`mount`, `umount2`, `pivot_root`, `chroot`, and `unshare`/`clone` with `CLONE_NEWNS`

None of these touch a file. All of them change which file a later path refers to. Without them a
log can be quietly wrong: `/etc/passwd` after a `chroot` is not the `/etc/passwd` the reader
assumes. Logging the call is enough to warn the reader; resolving paths through the new root is a
much larger job and probably not worth it.

### 6. Data that moves without a write

`copy_file_range`, `sendfile`, `memfd_create`

`copy_file_range` and `sendfile` move file contents entirely inside the kernel, so a file can be
duplicated with no `write` and no second `open` in sight. `memfd_create` makes an anonymous file
that later shows up as a descriptor with no path, which is worth naming when it appears.

## Deliberately not added by default

**The `stat` family**: `stat`, `lstat`, `fstatat`, `statx`, `access`, `faccessat`, `readlink`,
`readlinkat`. These say what a program looked at rather than what it touched, which is genuinely
useful when chasing a configuration search path, and overwhelming otherwise. A single process
start produces hundreds. If added, this belongs behind a flag.

**`io_uring`**: `io_uring_setup`, `io_uring_enter`. File operations submitted through a ring do not
appear as syscalls at all, so a program using it can open and write files with nothing in the log.
Decoding the ring means reading the submission queue out of the traced process's memory and
tracking it across submissions, which is a project of its own. The cheap, honest step is to notice
the setup call and warn once that the log may be incomplete. The README already says whatfiles is
not a security boundary; this is the concrete reason.

## Where the code changes

Adding one means touching four places:

1. `src/syscalls.h`: a new `SC_*` value.
2. `src/syscalls.c`: the native table, guarded with `#ifdef SYS_name` since not every architecture
   has every syscall, and the compat tables for 32-bit callers. Note that syscalls added to Linux
   since about 2019 share one number across architectures, while older ones do not.
3. `src/trace.c`, in `record_entry`: which arguments hold the paths, the flags, or a descriptor.
4. `src/utilities.c`, in `format_mode`: the word that appears in the `mode:` column.

A test in `tests/` should accompany each, in the shape of `tests/t_fileops.c`, which performs the
operation and lets the suite assert that the line appears.
