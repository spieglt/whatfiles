#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ptrace.h>

#include "string.h"
#include "whatfiles.h"

char *FLAGS = "ado:p:s";

void build_output(
    char *mode,
    char *syscall_name,
    unsigned long long reg,
    pid_t pid,
    struct String *filename,
    struct String *result,
    HashMap map
)
{
    size_t index;
    HashError err = find_index(pid, map, &index); // find_index() returns OK = 0 or NOT_FOUND = 1
    struct String *proc_string = err ? NULL : &map->names[index];

    char mode_str[MODE_LEN] = {0};
    // grab detected mode or the raw number
    *mode ? sprintf(mode_str, "%5s", mode) : sprintf(mode_str, "0x%llX", reg);
    append_str("mode: ", strlen("mode: "), result);
    append_str(mode_str, strlen(mode_str), result);

    append_str(", file: ", strlen(", file: "), result);
    append_str(filename->data, strlen(filename->data), result);

    append_str(", syscall: ", strlen(", syscall: "), result);
    append_str(syscall_name, strlen(syscall_name), result);

    char pid_str[MODE_LEN] = {0};
    sprintf(pid_str, ", PID: %d", pid);
    append_str(pid_str, strlen(pid_str), result);

    // make sure proc_string points to a `struct String`, that the String has been initialized, and that the first char isn't just a null byte
    char *proc_name = proc_string && proc_string->data && *proc_string->data
        ? proc_string->data
        : "[unknown]";
    append_str(", process: ", strlen(", process: "), result);
    append_str(proc_name, strlen(proc_name), result);
    append_str("\n", strlen("\n"), result);
}

void get_mode(unsigned long long m, char *mode)
{
    char *strings[] = {"read", "write", "rd/wr", "create"};
    int modes[] = {O_RDONLY, O_WRONLY, O_RDWR, O_CREAT};
    for (int i=0; i<4; i++) {
        if (m & modes[i] || m == modes[i]) {
            assert(strlen(strings[i]) < MODE_LEN);
            strcpy(mode, strings[i]);
        }
    }
}

void get_command(pid_t current_pid, char *command, size_t len)
{
    char proc_str[64] = {0};
    FILE *proc_file;
    sprintf(proc_str, "/proc/%d/cmdline", current_pid);
    proc_file = fopen(proc_str, "r");
    if (proc_file) {
        getline(&command, &len, proc_file);
    }
    fclose(proc_file);
}

bool peek_filename(pid_t pid, unsigned long long p_reg, struct String *str)
{
    char get_next_word = 1;
    long *addr = (long*)p_reg;
    do {
        // get next long-sized chunk of data from the address
        long res = ptrace(PTRACE_PEEKDATA, pid, (void*)addr, 0);
        if (res == -1) return 0;
        // iterate over it, appending to our filepath string, bailing if we encounter a null character
        for (int i = 0; i < sizeof(res); i++) {
            char current_byte = (char)(res >> (8*i) & 0xFF);
            if (current_byte) {
                append_char(current_byte, str);
            } else {
                get_next_word = 0;
                break;
            }
        }
        addr++;
    } while (get_next_word);
    return 1;
}

// void toggle_status(pid_t current_pid, HashMap map)
// {
//     size_t index;
//     HashError err = find_index(current_pid, map, &index);
//     HASH_ERR_CHECK(err, "index not found in map when trying to change syscall status");
//     // if (map->status[index]) decrement(current_pid, map);
//     // else increment(current_pid, map);
//     if (map->status[index] == ENTRY) err = insert(current_pid, EXIT, map);
//     else if (map->status[index] == EXIT) err = insert(current_pid, ENTRY, map);
//     else SYS_ERR("syscall status not 0 or 1");
// }

// Returns whether the current ptrace stop is an entry to a syscall or exit from one, which we track by comparing it to the previous one.
// Can return false positives, if multiple threads of a single process/PID enter the same syscall before either exits; can also return false negatives,
// if multiple threads of a single process/PID enter different syscalls before either exits.
bool is_exiting(pid_t pid, unsigned long long syscall)
{
    return pid == LastSyscall.pid && syscall == LastSyscall.syscall;
}

// return index within argv of the beginning of the user's command and end of whatfiles' flags
// no: now that we're attaching to processes, we aren't necessarily going to have a beginning of command
// so need to return index of last whatfiles arg.
int discover_flags(int argc, char *argv[])
{
    int i;
    for (i = 1; i < argc; i++) {
        char *current_arg = argv[i];
        char *last_arg = argv[i-1];
        char last_char = last_arg[strlen(last_arg)-1];
        if (*current_arg == '-') {
            continue; // in an option
        } else if (*last_arg == '-' && (last_char == 'o' || last_char == 'p')) {
            continue; // not in an option, but in argument to option
        }
        return i; // if still here, we're at the user's command
    }
    return i;
}

char *parse_flags(int argc, char *argv[], pid_t *pid, bool *stdout_override, bool *attach)
{
    int c;
    char *filename = NULL;
    while ((c = getopt(argc, argv, FLAGS)) != -1) {
        switch(c)
        {
        case 'a':
            about();
            break;
        case 'd':
            Debug = 1;
            break;
        case 'o':
            filename = optarg;
            break;
        case 'p':
            *attach = true;
            *pid = atoi(optarg);
            if (!*pid || *pid < 1) {
                fprintf(stderr, "Bad PID %s given, must be integer.\n", optarg);
                exit(1);
            }
            break;
        case 's':
            *stdout_override = true;
            break;
        case '?':
            if (optopt == 'o') {
                fprintf(stderr, "Option -o requires the desired location of the output file as argument.\n");
            } else if (optopt == 'p') {
                fprintf(stderr, "Option -p requires the PID of the process to be tracked as argument.\n");
            } else if (isprint(optopt)) {
                fprintf(stderr, "Unknown option `-%c'.\n", optopt);
            } else {
                fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
            }
            usage();
            break;
        default:
            usage();
            break;
        }
    }
    return filename;
}

void usage()
{
    fprintf(stderr, "\n                ======== Usage ========\n");
    fprintf(stderr, "Whatfiles can be used to log what files a process accesses, and in what mode.\n");
    fprintf(stderr, "To track the entire lifetime of a program, use it (and whatever arguments) after whatfiles flags.\n");
    fprintf(stderr, "You can also attach to a currently-running program, though this requires root privileges.\n");
    fprintf(stderr, "\n                ======== Flags ========\n");
    fprintf(stderr, "    -o ./output.log : specify log file location\n");
    fprintf(stderr, "    -p [PID]        : attach to currently running process (requires sudo)\n");
    fprintf(stderr, "    -s              : output to stdout rather than log file\n");
    fprintf(stderr, "    -d              : include debug output\n");
    fprintf(stderr, "    -a              : print about/license\n");
    fprintf(stderr, "\n               ======== Examples ========\n");
    fprintf(stderr, "Basic use, write what files the calendar uses to log:\n");
    fprintf(stderr, "    $ whatfiles cal\n");
    fprintf(stderr, "Run `ls`, include debug output, and log to stdout:\n");
    fprintf(stderr, "    $ whatfiles -ds ls -lah /var/log\n");
    fprintf(stderr, "Attach to currently open process with PID 1234:\n");
    fprintf(stderr, "    $ sudo whatfiles -p 1234\n");
    fprintf(stderr, "Watch what files an installation creates and name the log:\n");
    fprintf(stderr, "    $ sudo whatfiles -o ./firefox.log apt install firefox\n");
    exit(1);
}

void about()
{
    char *about_message = 
"https://github.com/spieglt/whatfiles\n"
"Copyright (C) 2020 Theron Spiegl. All rights reserved.\n\n"

"Whatfiles is a Linux utility used to log what files another program accesses and in what mode, "
"as well as that program's child processes and threads.\n\n"

"    This program is free software: you can redistribute it and/or modify\n"
"    it under the terms of the GNU General Public License as published by\n"
"    the Free Software Foundation, either version 3 of the License, or\n"
"    (at your option) any later version.\n\n"
"    This program is distributed in the hope that it will be useful,\n"
"    but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
"    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
"    GNU General Public License for more details.\n\n"
"    You should have received a copy of the GNU General Public License\n"
"    along with this program.  If not, see <https://www.gnu.org/licenses/>.\n";
    printf("%s\n", about_message);
    exit(0);
}
