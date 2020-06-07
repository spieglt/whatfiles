#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int main() {
    size_t size = ((size_t)RAND_MAX) + 1;
    char *randoms = calloc(size, sizeof(char));
    int dups = 0;
    srand(time(0));
    for (int i = 0; i < RAND_MAX; i++) {
        int r = rand();
        if (randoms[r]) {
            // printf("duplicate at %d\n", r);
            dups++;
        }
        randoms[r] = 1;
    }
    printf("duplicates: %d\n", dups);
}
