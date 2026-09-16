#ifndef WF_HASHMAP_H
#define WF_HASHMAP_H

#include <stdbool.h>
#include <sys/types.h>

#include "syscalls.h"
#include "wfstring.h"

#define INITIAL_SIZE 1024

/*
Everything whatfiles tracks about one traced thread. `kind` and the paths hold
the syscall a thread entered but has not yet returned from, so that the log line
can report the result. Entry and exit are tracked per thread, because several
threads of one process interleave freely.
*/
typedef struct {
    struct String name;         // process or thread name
    struct String path;         // path argument of the pending syscall
    struct String path2;        // second path, for rename()/link()
    SyscallKind kind;           // pending syscall, SC_NONE when not in one we log
    unsigned long long flags;   // open flags or *at() flags of the pending syscall
    bool in_syscall;            // only used when PTRACE_GET_SYSCALL_INFO is unavailable
} Task;

/*
Open-addressed map from thread ID to Task, with quadratic probing. Removal
leaves a tombstone so that it cannot break the probe chain of another key.
*/
struct HashMap {
    size_t size;
    size_t used;
    size_t tombstones;
    pid_t *keys;
    Task *tasks;
};
typedef struct HashMap* HashMap;

void map_init(HashMap map);
void map_destroy(HashMap map);
Task *map_find(HashMap map, pid_t pid);
Task *map_insert(HashMap map, pid_t pid);   // existing entry, or a new zeroed one
bool map_remove(HashMap map, pid_t pid);
size_t map_count(HashMap map);
// Iterates live entries: size_t i = 0; while (map_next(map, &i, &pid, &task)) ...
bool map_next(HashMap map, size_t *iter, pid_t *pid, Task **task);

#endif /* !WF_HASHMAP_H */
