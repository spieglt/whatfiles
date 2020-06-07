#ifndef HASHMAP_H
#define HASHMAP_H

#include "strings.h"

#define INITIAL_SIZE 1024

// tracks whether the process is entering or exiting the current syscall
typedef enum {
    ENTRY = 0,
    EXIT = 1,
} Status;

typedef enum {
    OK = 0,
    KEY_NOT_FOUND,
    NULL_PTR_IN_MAP,
} HashError;

struct HashMap {
    size_t size;
    size_t used;
    pid_t *keys;
    Status *status;
    struct String *names;
};
typedef struct HashMap* HashMap;

void init_hashmap(HashMap map);
void resize_hashmap(HashMap map);

HashError destroy(HashMap map);
HashError find_index(pid_t key, HashMap map, size_t *result);
HashError insert(pid_t key, Status status, HashMap map);
HashError get_status(pid_t key, HashMap map, size_t *result);
HashError remove_pid(pid_t key, HashMap map);
HashError increment(pid_t key, HashMap map);
HashError decrement(pid_t key, HashMap map);
HashError set_name(pid_t key, char *name, HashMap map);
HashError get_name(pid_t key, HashMap map, struct String *name);

struct {
    int collisions;
    int steps;
} DebugStats;

#endif /* !HASHMAP_H */
