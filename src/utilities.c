#define _GNU_SOURCE

#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <unistd.h>

#include "whatfiles.h"

#define MAX_PATH_BYTES 4096

// Word-at-a-time fallback for kernels or configurations where
// process_vm_readv() is unavailable. errno distinguishes a real failure from a
// word whose value happens to be -1, which the old code could not do.
static bool peek_data(pid_t pid, unsigned long long addr, void *buf, size_t len)
{
    size_t done = 0;
    while (done < len) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid, (void *)(uintptr_t)(addr + done), NULL);
        if (word == -1 && errno) return false;
        size_t chunk = (len - done < sizeof word) ? len - done : sizeof word;
        memcpy((char *)buf + done, &word, chunk);
        done += chunk;
    }
    return true;
}

bool read_tracee_data(pid_t pid, unsigned long long addr, void *buf, size_t len)
{
    struct iovec local = { buf, len };
    struct iovec remote = { (void *)(uintptr_t)addr, len };
    if (process_vm_readv(pid, &local, 1, &remote, 1, 0) == (ssize_t)len) return true;
    return peek_data(pid, addr, buf, len);
}

bool read_tracee_string(pid_t pid, unsigned long long addr, struct String *out)
{
    char chunk[256];
    unsigned long long pos = addr;

    str_clear(out);
    if (!addr) {
        str_append_cstr(out, "(null)");
        return true;
    }
    while (out->len < MAX_PATH_BYTES) {
        // Never read past a page boundary: the next page may not be mapped.
        size_t to_page = 4096 - (size_t)(pos & 4095);
        size_t want = sizeof chunk;
        if (want > to_page) want = to_page;
        if (want > MAX_PATH_BYTES - out->len) want = MAX_PATH_BYTES - out->len;
        if (!read_tracee_data(pid, pos, chunk, want)) return out->len > 0;
        char *end = memchr(chunk, '\0', want);
        str_append(out, chunk, end ? (size_t)(end - chunk) : want);
        if (end) return true;
        pos += want;
    }
    str_append_cstr(out, "...");
    return true;
}

/*
Reads a path argument and makes it absolute. A relative path means nothing on
its own in a log: it is resolved against the directory the tracee passed, or
against its working directory for AT_FDCWD and the plain (non-*at) syscalls.
*/
void read_tracee_path(pid_t pid, int dirfd, unsigned long long addr, struct String *out)
{
    struct String raw = {0};
    char link[64];
    char target[PATH_MAX];

    str_init(&raw, 256);
    read_tracee_string(pid, addr, &raw);
    str_clear(out);

    if (raw.len == 0 || raw.data[0] == '/' || strcmp(raw.data, "(null)") == 0) {
        str_append(out, raw.data, raw.len);
        str_free(&raw);
        return;
    }
    if (dirfd == AT_FDCWD) snprintf(link, sizeof link, "/proc/%d/cwd", (int)pid);
    else snprintf(link, sizeof link, "/proc/%d/fd/%d", (int)pid, dirfd);

    ssize_t len = readlink(link, target, sizeof target - 1);
    if (len <= 0 || target[0] != '/') {
        str_append(out, raw.data, raw.len);   // best effort: report what was passed
        str_free(&raw);
        return;
    }
    target[len] = '\0';
    str_append_cstr(out, target);
    if (out->len && out->data[out->len - 1] != '/') str_append_char(out, '/');
    // "./name" and "name" name the same file; keep the log readable.
    {
        const char *rest = raw.data;
        size_t remaining = raw.len;
        while (remaining >= 2 && rest[0] == '.' && rest[1] == '/') {
            rest += 2;
            remaining -= 2;
        }
        str_append(out, rest, remaining);
    }
    str_free(&raw);
}

static void append_flag(char *buf, size_t len, const char *flag)
{
    size_t used = strlen(buf);
    if (used + 1 < len) snprintf(buf + used, len - used, "%s", flag);
}

/*
Describes what a syscall does to the file. For the open family this is decoded
from the `flags` argument: the access mode lives in the low two bits, and
O_CREAT, O_TRUNC and O_APPEND say the file is written even when the access mode
alone would not.
*/
void format_mode(SyscallKind kind, unsigned long long flags, char *out, size_t len)
{
    const char *base;

    switch (kind) {
    case SC_OPEN:
    case SC_OPENAT:
    case SC_OPENAT2:
    case SC_CREAT:
        switch (flags & O_ACCMODE) {
        case O_RDONLY: base = "read"; break;
        case O_WRONLY: base = "write"; break;
        case O_RDWR:   base = "rd/wr"; break;
        default:
            snprintf(out, len, "0x%llX", flags);
            return;
        }
        snprintf(out, len, "%s", base);
        if (flags & O_CREAT) append_flag(out, len, "+create");
        if (flags & O_TRUNC) append_flag(out, len, "+trunc");
        if (flags & O_APPEND) append_flag(out, len, "+append");
#ifdef O_TMPFILE
        if ((flags & O_TMPFILE) == O_TMPFILE) append_flag(out, len, "+tmpfile");
#endif
        return;

    case SC_UNLINK:    base = "delete"; break;
    case SC_UNLINKAT:  base = (flags & AT_REMOVEDIR) ? "rmdir" : "delete"; break;
    case SC_RMDIR:     base = "rmdir"; break;
    case SC_MKDIR:
    case SC_MKDIRAT:   base = "mkdir"; break;
    case SC_RENAME:
    case SC_RENAMEAT:
    case SC_RENAMEAT2: base = "rename"; break;
    case SC_LINK:
    case SC_LINKAT:    base = "link"; break;
    case SC_SYMLINK:
    case SC_SYMLINKAT: base = "symlink"; break;
    case SC_TRUNCATE:  base = "trunc"; break;
    case SC_CHMOD:
    case SC_FCHMODAT:  base = "chmod"; break;
    case SC_CHOWN:
    case SC_LCHOWN:
    case SC_FCHOWNAT:  base = "chown"; break;
    case SC_EXECVE:
    case SC_EXECVEAT:  base = "exec"; break;
    default:           base = "?"; break;
    }
    snprintf(out, len, "%s", base);
}

char *parse_flags(int argc, char *argv[], pid_t *pid, bool *stdout_override,
                  bool *attach, bool *kill_on_exit)
{
    char *filename = NULL;
    int c;

    // The leading '+' stops option parsing at the first non-option argument, so
    // optind is left pointing at the start of the traced program's command line.
    while ((c = getopt(argc, argv, "+ado:p:sk")) != -1) {
        switch (c) {
        case 'a':
            about();
            break;
        case 'd':
            Debug = 1;
            break;
        case 'k':
            *kill_on_exit = true;
            break;
        case 'o':
            filename = optarg;
            break;
        case 'p': {
            char *end = NULL;
            long value;
            errno = 0;
            value = strtol(optarg, &end, 10);
            if (errno || !end || *end != '\0' || value < 1 || value > INT_MAX) {
                FATAL("bad PID '%s': expected a positive integer\n", optarg);
            }
            if (getpgid((pid_t)value) < 0) {
                FATAL("bad PID '%s': %s\n", optarg, strerror(errno));
            }
            *pid = (pid_t)value;
            *attach = true;
            break; }
        case 's':
            *stdout_override = true;
            break;
        case '?':
            if (optopt == 'o') {
                fprintf(stderr, "Option -o requires the desired location of the output file as argument.\n");
            } else if (optopt == 'p') {
                fprintf(stderr, "Option -p requires the PID of the process to be tracked as argument.\n");
            } else if (isprint(optopt)) {
                fprintf(stderr, "Unknown option `-%c'.\n", optopt);
            } else {
                fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
            }
            usage();
            break;
        default:
            usage();
            break;
        }
    }
    return filename;
}

void usage(void)
{
    fprintf(stderr, "\n                ======== Usage ========\n");
    fprintf(stderr, "Whatfiles logs what files a process accesses, in what mode, and whether it succeeded.\n");
    fprintf(stderr, "To follow a program for its whole life, put it (and its arguments) after whatfiles' flags.\n");
    fprintf(stderr, "You can also attach to a running program, which usually requires root privileges.\n");
    fprintf(stderr, "\n                ======== Flags ========\n");
    fprintf(stderr, "    -o ./output.log : specify log file location\n");
    fprintf(stderr, "    -p [PID]        : attach to currently running process (usually requires sudo)\n");
    fprintf(stderr, "    -s              : output to stdout rather than log file\n");
    fprintf(stderr, "    -d              : include debug output\n");
    fprintf(stderr, "    -k              : kill the traced program if whatfiles is killed\n");
    fprintf(stderr, "    -a              : print about/license\n");
    fprintf(stderr, "\n               ======== Examples ========\n");
    fprintf(stderr, "Basic use, write what files the calendar uses to log:\n");
    fprintf(stderr, "    $ whatfiles cal\n");
    fprintf(stderr, "Run `ls`, include debug output, and log to stdout:\n");
    fprintf(stderr, "    $ whatfiles -ds ls -lah /var/log\n");
    fprintf(stderr, "Attach to currently open process with PID 1234:\n");
    fprintf(stderr, "    $ sudo whatfiles -p 1234\n");
    fprintf(stderr, "Watch what files an installation creates and name the log:\n");
    fprintf(stderr, "    $ sudo whatfiles -o ./firefox.log apt install firefox\n");
    exit(EXIT_FAILURE);
}

void about(void)
{
    char *about_message =
"https://github.com/spieglt/whatfiles\n"
"Copyright (C) 2020 Theron Spiegl. All rights reserved.\n\n"

"Whatfiles is a Linux utility used to log what files another program accesses and in what mode, "
"as well as that program's child processes and threads.\n\n"

"    This program is free software: you can redistribute it and/or modify\n"
"    it under the terms of the GNU General Public License as published by\n"
"    the Free Software Foundation, either version 3 of the License, or\n"
"    (at your option) any later version.\n\n"
"    This program is distributed in the hope that it will be useful,\n"
"    but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
"    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
"    GNU General Public License for more details.\n\n"
"    You should have received a copy of the GNU General Public License\n"
"    along with this program.  If not, see <https://www.gnu.org/licenses/>.\n";
    printf("%s\n", about_message);
    exit(EXIT_SUCCESS);
}
