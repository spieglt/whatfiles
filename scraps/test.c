
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <regex.h>
#include <sys/wait.h>
#include "src/strings.h"

#define SYS_ERR(msg) { \
        perror(msg);   \
        exit(errno);   \
    }

void read_file(struct String *str, size_t size, FILE *file)
{
    char c;
    for (size_t read = 0; read < size && (c = fgetc(file)) != EOF; read++) {
        append_char(c, str);
    }
}

char read_status(pid_t pid)
{
    char path[128] = {0};
    sprintf(path, "/proc/%d/status", pid);

    struct String string = {0};
    struct String *str = &string;

    init_string(str, 4096);
    FILE *h_status = fopen(path, "rb");
    read_file(str, 4096, h_status);

    // find status line, grab value after colon and spaces
    regex_t regex;
    int err;
    regmatch_t pmatch[2];
    if (regcomp(&regex, "State:\\W+([A-Z])", REG_EXTENDED) != 0)
        SYS_ERR("regex compilation error");
    err = regexec(&regex, str->data, 2, pmatch, 0);
    regfree(&regex);
    if (err) SYS_ERR("failed to find regex match in /proc/[PID]/status file");
    // printf("%s\n", str->data + pmatch[1].rm_so);
    return *(str->data + pmatch[1].rm_so);
}

int main()
{
    char x = read_status(2909);
    printf("%c\n", x);
}
