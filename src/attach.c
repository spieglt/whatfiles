#include <dirent.h>
#include <regex.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>

#include "whatfiles.h"

// Most of this file gratefully adapted from Nominal Animal's answer at
// https://stackoverflow.com/questions/18577956/how-to-use-ptrace-to-get-a-consistent-view-of-multiple-threads

void read_file(struct String *str, size_t size, FILE *file)
{
    char c;
    for (size_t read = 0; read < size && (c = fgetc(file)) != EOF; read++) {
        append_char(c, str);
    }
}

// returns 0 if status file couldn't be read, character of status otherwise
char read_status(pid_t pid)
{
    char c = 0;
    char path[128] = {0};
    sprintf(path, "/proc/%d/status", pid);

    struct String string = {0};
    struct String *str = &string;

    init_string(str, 4096);
    FILE *h_status = fopen(path, "rb");
    if (!h_status) return 0;
    read_file(str, 4096, h_status);

    regex_t regex;
    int err;
    regmatch_t pmatch[2];
    if (regcomp(&regex, "State:\\W+([A-Za-z])", REG_EXTENDED) != 0)
        SYS_ERR("regex compilation error");
    err = regexec(&regex, str->data, 2, pmatch, 0);
    regfree(&regex);
    if (err) {
        DEBUG("failed to find regex match in /proc/%d/status file\n", pid);
    } else {
        c = *(str->data + pmatch[1].rm_so);
    }
    free(str->data);
    return c;
}

void read_task(pid_t tid, struct String *str)
{
    char path[128] = {0};
    sprintf(path, "/proc/%d/comm", tid);
    FILE *h_comm = fopen(path, "rb");
    if (!h_comm) {
        fprintf(stderr, "tried to read nonexistent /proc/%d/comm\n", tid);
        exit(1);
    }
    read_file(str, 4096, h_comm);
    if (str->data[str->len-1] == '\n') delete_char(str); // remove newline if present
}

int attach_to_process(pid_t pid, HashMap map)
{

    pid_t *tid = 0;
    size_t tids = 0;
    size_t tids_max = 0;
    size_t t;
    long r, sys_err;

    // stop the process and its threads
    kill(pid, SIGSTOP);
    // can't wait() on a process that's not a child
    while (1) {
        char status = read_status(pid);
        if (status == 'T' || status  == 't') break;
        struct timespec ts = {0, 1000000 * 250}; // quarter second
        nanosleep(&ts, &ts);
        DEBUG("waiting for PID %d to stop\n", pid);
    }

    // get thread IDs from /proc/[PID]/task/
    tids = get_tids(&tid, &tids_max, pid);
    if (!tids)
    {
        DEBUG("process %d has no threads\n", pid);
        // kill(pid, SIGCONT);
        // return 0;
    } else {
        DEBUG("Process %d has %d tasks\n", (int)pid, (int)tids);
    }

    /* Attach to all tasks. */
    for (t = 0; t < tids; t++) {
        do {
            r = ptrace(PTRACE_ATTACH, tid[t], (void *)0, (void *)0);
        } while (r == -1L && (errno == EBUSY || errno == EFAULT || errno == ESRCH));
        if (r == -1L) {
            DEBUG("ptrace attach error\n");
            const int saved_errno = errno;
            while (t-- > 0) {
                do {
                    r = ptrace(PTRACE_DETACH, tid[t], (void *)0, (void *)0);
                } while (r == -1L && (errno == EBUSY || errno == EFAULT || errno == ESRCH));
            }
            tids = 0;
            errno = saved_errno;
            return errno;
        }
        // if successfully attached, add to map
        insert(tid[t], 0, map);
        struct String str = {0};
        init_string(&str, 4096);
        read_task(tid[t], &str);
        set_name(tid[t], str.data, map);
        free(str.data);
    }

    // set ptrace options
    // register for the ptrace events we want to catch
    sys_err = ptrace(PTRACE_SETOPTIONS, pid, (char*)0, PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC);
    if (sys_err == -1) SYS_ERR("ptrace() failed to set options");

    for (t = 0; t < tids; t++) {
        sys_err = ptrace(PTRACE_SYSCALL, tid[t], 0, 0);
        if (sys_err == -1) SYS_ERR("ptrace() failed to resume thread");
    }
    kill(pid, SIGCONT);
    return 0;
}

// used upon exit as signal handler when whatfiles was used to attach to a process already in progress
void detatch_from_process(HashMap map)
{
    for (int i = 0; i < map->size; i++) {
        pid_t pid = map->keys[i];
        if (pid) {
            int r;
            int counter = 0;
            char status = 0;
            // make sure the thread is stopped
            kill(pid, SIGSTOP);
            while (1) {
                status = read_status(pid);
                if (status == 'T' || status == 't') break; // thread stopped, due to kill(SIGSTOP) above or ptrace syscall SIGTRAP 
                struct timespec ts = {0, 100000000}; // 100 million nanoseconds = tenth of a second
                nanosleep(&ts, &ts);
                DEBUG("waiting for PID %d to stop\n", pid);
                if (counter > 9) {
                    DEBUG("could not detatch from PID %d\n", pid);
                    break;
                }
                counter++;
            }
            if (counter > 9) continue; // if we weren't able to detatch from this process, move on
            do {
                r = ptrace(PTRACE_DETACH, pid, (void *)0, (void *)0);
            } while (r == -1L && (errno == EBUSY || errno == EFAULT || errno == ESRCH));
            if (r == -1) fprintf(stderr, "error detatching from PID %d\n", pid);
            else DEBUG("detatched from process %d\n", pid);
            kill(pid, SIGCONT);
        }
    }
}

size_t get_tids(pid_t **const listptr, size_t *const sizeptr, const pid_t pid)
{
    char dirname[64];
    DIR *dir;
    pid_t *list;
    size_t size, used = 0;

    // make sure we've been given non-null pointers and a valid pid
    if (!listptr || !sizeptr || pid < (pid_t)1) {
        errno = EINVAL;
        return (size_t)0;
    }

    // if sizeptr points to 0 or less, null contents of listptr and sizeptr
    if (*sizeptr > 0) {
        list = *listptr;
        size = *sizeptr;
    } else {
        list = *listptr = NULL;
        size = *sizeptr = 0;
    }

    if (snprintf(dirname, sizeof dirname, "/proc/%d/task/", (int)pid) >= (int)sizeof dirname) {
        errno = ENOTSUP;
        return (size_t)0;
    }

    dir = opendir(dirname);
    if (!dir) {
        errno = ESRCH;
        return (size_t)0;
    }

    while (1) {
        struct dirent *ent;
        int value;
        char dummy;

        errno = 0;
        ent = readdir(dir);
        if (!ent) break;

        /* Parse TIDs. Ignore non-numeric entries. */
        if (sscanf(ent->d_name, "%d%c", &value, &dummy) != 1) continue;

        /* Ignore obviously invalid entries. */
        if (value < 1) continue;

        /* Make sure there is room for another TID. */
        if (used >= size) {
            size = (used | 127) + 128;
            list = realloc(list, size * sizeof list[0]);
            if (!list) {
                closedir(dir);
                errno = ENOMEM;
                return (size_t)0;
            }
            *listptr = list;
            *sizeptr = size;
        }

        /* Add to list. */
        list[used++] = (pid_t)value;
    }

    if (errno) {
        const int saved_errno = errno;
        closedir(dir);
        errno = saved_errno;
        return (size_t)0;
    }
    if (closedir(dir)) {
        errno = EIO;
        return (size_t)0;
    }

    /* None? */
    if (used < 1) {
        errno = ESRCH;
        return (size_t)0;
    }

    /* Make sure there is room for a terminating (pid_t)0. */
    if (used >= size) {
        size = used + 1;
        list = realloc(list, size * sizeof list[0]);
        if (!list) {
            errno = ENOMEM;
            return (size_t)0;
        }
        *listptr = list;
        *sizeptr = size;
    }

    /* Terminate list; done. */
    list[used] = (pid_t)0;
    errno = 0;
    return used;
}
