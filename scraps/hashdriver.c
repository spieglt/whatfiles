// Exercises the task map in src/hashmap.c on its own.
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "../src/hashmap.h"

#define INSERT_NUM 5000

static void insert_test(HashMap map, bool with_names)
{
    int num = 100000;
    for (int i = 0; i < num; i++) {
        pid_t pid = (pid_t)(rand() % 4000000 + 1);
        Task *task = map_insert(map, pid);
        assert(task != NULL);
        assert(map_find(map, pid) == task);
        if (with_names && !task->name.len) str_append_cstr(&task->name, "yeah what's up");
    }
    printf("live entries: %zu\n", map_count(map));
}

static void delete_test(HashMap map)
{
    size_t iter = 0;
    pid_t pid;
    // Collect first: removing entries while iterating would skip some.
    pid_t *pids = malloc(map_count(map) * sizeof *pids);
    size_t n = 0;
    while (map_next(map, &iter, &pid, NULL)) pids[n++] = pid;
    for (size_t i = 0; i < n; i++) assert(map_remove(map, pids[i]));
    assert(map_count(map) == 0);
    free(pids);
}

// A key that probed past another one must still be findable, and insertable,
// after that other key is removed.
static void tombstone_test(void)
{
    struct HashMap hm = {0};
    HashMap map = &hm;
    pid_t first = 5000, second = 5000 + INITIAL_SIZE;   // same home slot

    map_init(map);
    map_insert(map, first);
    map_insert(map, second);
    assert(map_count(map) == 2);
    assert(map_remove(map, first));
    assert(map_find(map, second) != NULL);
    map_insert(map, second);            // must not create a second copy
    assert(map_count(map) == 1);
    assert(map_remove(map, second));
    assert(map_count(map) == 0);
    assert(map_find(map, second) == NULL);
    map_destroy(map);
    printf("tombstone test passed\n");
}

static void memory_leak_test(void)
{
    struct HashMap hm = {0};
    HashMap map = &hm;
    for (int i = 0; i < 5; i++) {
        map_init(map);
        insert_test(map, true);
        delete_test(map);
        insert_test(map, false);
        delete_test(map);
        map_destroy(map);
    }
}

int main(void)
{
    struct HashMap hm = {0};
    HashMap map = &hm;

    srand((unsigned)time(0));
    tombstone_test();

    map_init(map);
    insert_test(map, true);
    map_destroy(map);

    map_init(map);
    pid_t *pids = malloc(INSERT_NUM * sizeof *pids);
    for (int i = 0; i < INSERT_NUM; i++) {
        pids[i] = (pid_t)(i + 1);
        Task *task = map_insert(map, pids[i]);
        task->flags = (unsigned long long)i;
    }
    for (int i = 0; i < INSERT_NUM; i++) {
        Task *task = map_find(map, pids[i]);
        assert(task && task->flags == (unsigned long long)i);
    }
    free(pids);
    map_destroy(map);

    memory_leak_test();
    printf("done\n");
    return 0;
}
