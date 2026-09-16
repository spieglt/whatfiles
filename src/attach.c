#define _GNU_SOURCE

#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "whatfiles.h"

#ifndef PTRACE_SEIZE
#define PTRACE_SEIZE 0x4206
#endif
#ifndef PTRACE_INTERRUPT
#define PTRACE_INTERRUPT 0x4207
#endif
#ifndef __WALL
#define __WALL 0x40000000
#endif

bool read_comm(pid_t tid, struct String *out)
{
    char path[64];
    char buf[256];
    ssize_t n;
    int fd;

    snprintf(path, sizeof path, "/proc/%d/comm", (int)tid);
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0) return false;
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\0')) n--;
    if (n <= 0) return false;
    str_clear(out);
    str_append(out, buf, (size_t)n);
    return true;
}

// Reads the thread IDs of a process from /proc/[pid]/task.
static size_t list_tids(pid_t pid, pid_t **list, size_t *cap)
{
    char dirname[64];
    struct dirent *entry;
    size_t used = 0;
    DIR *dir;

    snprintf(dirname, sizeof dirname, "/proc/%d/task", (int)pid);
    dir = opendir(dirname);
    if (!dir) return 0;

    while ((entry = readdir(dir)) != NULL) {
        char *end = NULL;
        long value = strtol(entry->d_name, &end, 10);
        if (!end || *end != '\0' || value < 1) continue;
        if (used == *cap) {
            size_t next = *cap ? *cap * 2 : 64;
            pid_t *grown = realloc(*list, next * sizeof **list);
            if (!grown) break;
            *list = grown;
            *cap = next;
        }
        (*list)[used++] = (pid_t)value;
    }
    closedir(dir);
    return used;
}

/*
Attaches to a running process and all of its threads.

PTRACE_SEIZE attaches without stopping anything, so a failure part-way through
leaves the target running as it was, rather than frozen by a SIGSTOP that was
never undone. Options are set on every thread, not just the thread group leader:
ptrace options are per thread, and a child process is only followed if the
thread that created it carries PTRACE_O_TRACEFORK and its siblings. Threads that
appear while attaching are picked up by re-reading the task list.
*/
int seize_process(pid_t pid, HashMap map, int options)
{
    pid_t *tids = NULL;
    size_t cap = 0;
    int err = 0;

    for (int round = 0; round < 8; round++) {
        size_t count = list_tids(pid, &tids, &cap);
        size_t added = 0;

        if (!count) {
            if (round == 0) err = ESRCH;
            break;
        }
        for (size_t i = 0; i < count; i++) {
            Task *task;
            if (map_find(map, tids[i])) continue;
            if (ptrace(PTRACE_SEIZE, tids[i], NULL, (void *)(long)options) == -1) {
                if (errno == ESRCH) continue;   // thread exited while we listed
                err = errno;
                goto done;
            }
            task = map_insert(map, tids[i]);
            if (task) read_comm(tids[i], &task->name);
            // Stop each thread once, so the main loop can put it into syscall tracing.
            if (ptrace(PTRACE_INTERRUPT, tids[i], 0, 0) == -1) {
                DEBUG("PID %d: PTRACE_INTERRUPT failed: %s\n", (int)tids[i], strerror(errno));
            }
            added++;
        }
        if (!added) break;   // no new threads since the previous pass
    }
done:
    free(tids);
    if (err) {
        detach_all(map);
        errno = err;
    } else {
        DEBUG("attached to %zu thread(s) of PID %d\n", map_count(map), (int)pid);
    }
    return err;
}

static bool past_deadline(const struct timespec *deadline)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return now.tv_sec > deadline->tv_sec
        || (now.tv_sec == deadline->tv_sec && now.tv_nsec >= deadline->tv_nsec);
}

/*
Detaches from everything whatfiles is tracing, leaving each process running.
Every tracee is interrupted, and detached once it reports the resulting stop;
anything that has not stopped within the deadline gets a detach attempt anyway.
*/
void detach_all(HashMap map)
{
    struct timespec deadline;
    size_t iter = 0;
    pid_t pid;

    if (!map_count(map)) return;

    while (map_next(map, &iter, &pid, NULL)) {
        if (ptrace(PTRACE_INTERRUPT, pid, 0, 0) == -1) {
            DEBUG("PID %d: PTRACE_INTERRUPT failed: %s\n", (int)pid, strerror(errno));
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec += 2;

    while (map_count(map) > 0 && !past_deadline(&deadline)) {
        struct timespec pause = { 0, 5 * 1000 * 1000 };
        unsigned int event;
        int status, sig;
        pid_t stopped = waitpid(-1, &status, __WALL | WNOHANG);

        if (stopped == 0) {
            nanosleep(&pause, NULL);
            continue;
        }
        if (stopped == -1) {
            if (errno == EINTR) continue;
            break;
        }
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            map_remove(map, stopped);
            continue;
        }
        sig = WSTOPSIG(status);
        event = ((unsigned int)status >> 16) & 0xFFFF;
        // Our own interrupt and syscall stops carry nothing for the tracee.
        if (event || sig == SIGTRAP || sig == (SIGTRAP | 0x80)) sig = 0;
        if (ptrace(PTRACE_DETACH, stopped, 0, (void *)(long)sig) == -1) {
            DEBUG("PID %d: detach failed: %s\n", (int)stopped, strerror(errno));
        } else {
            DEBUG("detached from PID %d\n", (int)stopped);
        }
        map_remove(map, stopped);
    }

    iter = 0;
    while (map_next(map, &iter, &pid, NULL)) {
        if (ptrace(PTRACE_DETACH, pid, 0, 0) == -1) {
            DEBUG("PID %d: could not detach: %s\n", (int)pid, strerror(errno));
        }
    }
}
