#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>

#include "hashmap.h"
#include "strings.h"

/*
Not the best hash map. Open addressing, quadratic probing
(which doesn't seem to perform much better than linear for random int inputs),
and wastes three quarters of its space to minimize collisions.
Would benefit from separate chaining with linked lists. But good enough for now.
Also not using all of the functionality in whatfiles, but keeping so that it can
be easily modified and reused as a generic hashmap later.
*/

void init_hashmap(HashMap map)
{
    map->size = INITIAL_SIZE;
    map->used = 0;
    map->keys = calloc(INITIAL_SIZE, sizeof(pid_t));
    map->status = calloc(INITIAL_SIZE, sizeof(size_t));
    map->names = calloc(INITIAL_SIZE, sizeof(struct String));
    if (!(map->keys && map->status && map->names)) {
        perror("calloc() error");
        exit(errno);
    }
}

HashError set_name(pid_t pid, char *name, HashMap map)
{
    size_t index;
    HashError err = find_index(pid, map, &index);
    if (err == OK) {
        init_string(&map->names[index], 64);
        append_str(name, strlen(name), &map->names[index]);
    }
    return err;
}

// also changes status value if pid already present
HashError insert(pid_t pid, Status status, HashMap map)
{
    if (map->used >= map->size / 4) {
        resize_hashmap(map);
    } 
    size_t index = pid % map->size;
    int base = 1;
    int c = 0;

    while (map->keys[index] != 0) {
        if (map->keys[index] == pid) {
            map->status[index] = status;
            return OK;
        }
        c++; DebugStats.steps++;
        // index = (index+1) % map->size; // linear probe
        index = (index + base * base) % map->size; // quadratic probe
        base++;
    }

    if (c) DebugStats.collisions++;

    map->keys[index] = pid;
    map->status[index] = status;
    map->used++;
    return OK;
}

HashError find_index(pid_t pid, HashMap map, size_t *result)
{
    size_t index = pid % map->size;
    size_t start = index;
    while (map->keys[index] != pid) {
        index = (index + 1) % map->size;
        if (index == start) {
            return KEY_NOT_FOUND;
        }
    }
    *result = index;
    return OK;
}

HashError destroy(HashMap map)
{
    if (!(map->keys && map->status && map->names)) {
        return NULL_PTR_IN_MAP;
    }
    // this loop never fired because I had map->size = 0 at the top. I'm an idiot.
    for (int i = 0; i < map->size; i++) {
        if (map->names[i].data) {
            free(map->names[i].data);
        }
    }
    free(map->keys);
    free(map->status);
    free(map->names);
    map->size = 0;
    map->used = 0;
    return OK;
}

void resize_hashmap(HashMap map)
{
    pid_t *orig_pids = map->keys;
    Status *orig_status = map->status;
    struct String *orig_names = map->names;
    size_t orig_size = map->size;

    map->used = 0;
    map->size *= 2;
    map->keys = calloc(map->size, sizeof(pid_t));
    map->status = calloc(map->size, sizeof(Status));
    map->names = calloc(map->size, sizeof(struct String));
    if (!(map->keys && map->status && map->names)) {
        perror("calloc() error");
        exit(errno);
    }

    for (int i = 0; i < orig_size; i++) {
        if (!orig_pids[i]) continue;
        insert(orig_pids[i], orig_status[i], map);
        if (orig_names[i].data) {
            set_name(orig_pids[i], orig_names[i].data, map);
            free(orig_names[i].data);
        }
    }
    free(orig_pids);
    free(orig_status);
    free(orig_names);
}

HashError get_name(pid_t pid, HashMap map, struct String *name)
{
    size_t index;
    HashError err = find_index(pid, map, &index);
    if (err == OK) {
        name = &map->names[index];
    }
    return err;
}

HashError get_status(pid_t pid, HashMap map, size_t *result)
{
    size_t idx = 0;
    HashError res = find_index(pid, map, &idx);
    if (res == OK) {
        *result = map->status[idx];
    }
    return res;
}

HashError increment(pid_t pid, HashMap map)
{
    size_t idx = 0;
    HashError res = find_index(pid, map, &idx);
    if (res == OK && map->status[idx] < __INT_MAX__) {
        map->status[idx]++;
    }
    return res;
}

HashError decrement(pid_t pid, HashMap map)
{
    size_t idx = 0;
    HashError res = find_index(pid, map, &idx);
    if (res == OK && map->status[idx] > 0) {
        map->status[idx]--;
    }
    return res;
}

HashError remove_pid(pid_t pid, HashMap map)
{
    size_t idx = 0;
    HashError res = find_index(pid, map, &idx);
    if (res == OK) {
        map->keys[idx] = 0;
        map->status[idx] = 0;
        if (map->names[idx].data) {
            free(map->names[idx].data);
        }
        struct String zeroed = {0};
        map->names[idx] = zeroed;
        map->used--;
    }
    return res;
}
