#ifndef WHATFILES_H
#define WHATFILES_H

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>

#include "hashmap.h"

int Debug;
FILE *Handle;

#define MODE_LEN 32
#define OUTPUT(...) fprintf(Handle, __VA_ARGS__)
#define DEBUG(...) if (Debug) { OUTPUT(__VA_ARGS__); }
#define SYS_ERR(msg) { \
        perror(msg);   \
        exit(errno);   \
    }
#define HASH_ERR_CHECK(err, msg)             \
    if (err) {                               \
        fprintf(stderr, "Error: %s\n", msg); \
        exit(err);                           \
    }

struct {
    pid_t pid;
    unsigned long long syscall;
} LastSyscall;

// utilities.c
void build_output(
    char *mode,
    char *syscall_name,
    unsigned long long reg,
    pid_t pid,
    struct String *filename,
    struct String *result,
    HashMap map
);
void get_mode(unsigned long long m, char *mode);
void get_command(pid_t current_pid, char *command, size_t len);
bool peek_filename(pid_t pid, unsigned long long p_reg, struct String *str);
// void toggle_status(pid_t current_pid, HashMap map);
bool is_exiting(pid_t pid, unsigned long long syscall);
char *parse_flags(int argc, char *argv[], pid_t *pid, bool *stdout_override, bool *attach);
int discover_flags(int argc, char *argv[]);
void usage();
void about();

// attach.c
size_t get_tids(pid_t **const listptr, size_t *const sizeptr, const pid_t pid);
int attach_to_process(pid_t pid, HashMap map);
void detatch_from_process(HashMap map);
void read_file(struct String *str, size_t size, FILE *file);
char read_status(pid_t pid);
void read_task(pid_t tid, struct String *str);

#endif /* !WHATFILES_H */
