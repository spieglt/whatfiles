#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hashmap.h"

#define TOMBSTONE ((pid_t)-1)

static void *alloc_zeroed(size_t count, size_t size)
{
    void *mem = calloc(count, size);
    if (!mem) {
        perror("calloc() error");
        exit(ENOMEM);
    }
    return mem;
}

/*
Finds the slot a PID belongs in. Probing stops at an empty slot, since no key
can live past one, but continues through tombstones, which may still have live
keys behind them. The first tombstone seen is reused for an insert.
*/
static bool locate(HashMap map, pid_t pid, size_t *slot, bool *found)
{
    size_t index = (size_t)pid % map->size;
    size_t tombstone = map->size;
    for (size_t probe = 1; probe <= map->size; probe++) {
        pid_t key = map->keys[index];
        if (key == pid) {
            *slot = index;
            *found = true;
            return true;
        }
        if (key == 0) {
            *slot = tombstone < map->size ? tombstone : index;
            *found = false;
            return true;
        }
        if (key == TOMBSTONE && tombstone == map->size) tombstone = index;
        index = (index + probe * probe) % map->size;
    }
    if (tombstone < map->size) {
        *slot = tombstone;
        *found = false;
        return true;
    }
    return false;   // table full: only possible if the load factor check failed
}

static void task_release(Task *task)
{
    str_free(&task->name);
    str_free(&task->path);
    str_free(&task->path2);
    memset(task, 0, sizeof *task);
}

static void resize(HashMap map)
{
    pid_t *old_keys = map->keys;
    Task *old_tasks = map->tasks;
    size_t old_size = map->size;

    map->size = old_size * 2;
    map->used = 0;
    map->tombstones = 0;
    map->keys = alloc_zeroed(map->size, sizeof(pid_t));
    map->tasks = alloc_zeroed(map->size, sizeof(Task));

    for (size_t i = 0; i < old_size; i++) {
        if (old_keys[i] == 0 || old_keys[i] == TOMBSTONE) continue;
        size_t slot;
        bool found;
        if (!locate(map, old_keys[i], &slot, &found) || found) continue;
        map->keys[slot] = old_keys[i];
        map->tasks[slot] = old_tasks[i];   // moves the strings, no copying
        map->used++;
    }
    free(old_keys);
    free(old_tasks);
}

void map_init(HashMap map)
{
    map->size = INITIAL_SIZE;
    map->used = 0;
    map->tombstones = 0;
    map->keys = alloc_zeroed(INITIAL_SIZE, sizeof(pid_t));
    map->tasks = alloc_zeroed(INITIAL_SIZE, sizeof(Task));
}

void map_destroy(HashMap map)
{
    if (map->tasks) {
        for (size_t i = 0; i < map->size; i++) task_release(&map->tasks[i]);
    }
    free(map->keys);
    free(map->tasks);
    map->keys = NULL;
    map->tasks = NULL;
    map->size = 0;
    map->used = 0;
    map->tombstones = 0;
}

Task *map_find(HashMap map, pid_t pid)
{
    size_t slot;
    bool found;
    if (pid <= 0) return NULL;
    if (!locate(map, pid, &slot, &found) || !found) return NULL;
    return &map->tasks[slot];
}

Task *map_insert(HashMap map, pid_t pid)
{
    size_t slot;
    bool found;
    if (pid <= 0) return NULL;
    // Keep the table at most half full, tombstones included, so probing stays short.
    if ((map->used + map->tombstones + 1) * 2 >= map->size) resize(map);
    if (!locate(map, pid, &slot, &found)) {
        resize(map);
        if (!locate(map, pid, &slot, &found)) return NULL;
    }
    if (found) return &map->tasks[slot];
    if (map->keys[slot] == TOMBSTONE) map->tombstones--;
    map->keys[slot] = pid;
    memset(&map->tasks[slot], 0, sizeof(Task));
    map->used++;
    return &map->tasks[slot];
}

bool map_remove(HashMap map, pid_t pid)
{
    size_t slot;
    bool found;
    if (pid <= 0) return false;
    if (!locate(map, pid, &slot, &found) || !found) return false;
    task_release(&map->tasks[slot]);
    map->keys[slot] = TOMBSTONE;
    map->tombstones++;
    map->used--;
    return true;
}

size_t map_count(HashMap map)
{
    return map->used;
}

bool map_next(HashMap map, size_t *iter, pid_t *pid, Task **task)
{
    for (size_t i = *iter; i < map->size; i++) {
        if (map->keys[i] == 0 || map->keys[i] == TOMBSTONE) continue;
        *iter = i + 1;
        if (pid) *pid = map->keys[i];
        if (task) *task = &map->tasks[i];
        return true;
    }
    *iter = map->size;
    return false;
}
