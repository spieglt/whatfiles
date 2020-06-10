#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <assert.h>
#include <wait.h>

#include "../src/hashmap.h"

#define INSERT_NUM 5000

#define RESET(map)         \
    {                      \
        destroy(map);      \
        init_hashmap(map); \
    }

DebugStats_t DebugStats = {0};

void insert_test(HashMap map, bool with_names) {
    int num = 100000;
    for (int i = 0; i < num; i++) {
        int r = rand();
        insert(r, 1, map);
        size_t idx = 0;
        find_index(r, map, &idx);
        if (!map->names[idx].data && with_names) {
            set_name(r, "yeah what's up", map);
        }
    }
    printf("collisions: %d\nsteps: %d\n", DebugStats.collisions, DebugStats.steps);
    printf("used: %ld\n", map->used);
    // there will be duplicates so this will fail. should pass on mac which doesn't repeat randoms till MAX_RAND-1
    // assert(map->used == num);
}

void delete_test(HashMap map)
{
    for (int i = 0; i < map->size; i++) {
        if (map->keys[i]) {
            remove_pid(map->keys[i], map);
        }
    }
}

void memory_leak_test()
{
    struct HashMap hashmap;
    HashMap m = &hashmap;
    for (int i = 0; i < 5; i++) {
        init_hashmap(m);
        insert_test(m, true);
        delete_test(m);
        insert_test(m, false);
        delete_test(m);
        HashError err = destroy(m);
        if (err) {
            printf("could not destroy\n");
            exit(1);
        }
    }
}

int main()
{
    srand(time(0));

    struct HashMap m;
    HashMap map = &m;
    init_hashmap(map);
    insert_test(map, true);
    
    RESET(map);
    // destroy(map);

    int pids[INSERT_NUM] = {0};
    int counts[INSERT_NUM] = {0};
    for (int i = 0; i < INSERT_NUM; i++) {
        pids[i] = rand();
        counts[i] = rand();
        insert(pids[i], counts[i], map);
    }
    for (int i = 0; i < INSERT_NUM; i++) {
        size_t res = 0;
        get_status(pids[i], map, &res);
        assert(res == counts[i]);
    }
    destroy(map);
    printf("done\n");
    memory_leak_test();
}
