#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "strings.h"

// new String pointers must be zeroed before being handed to this function
void init_string(struct String *str, size_t initial_capacity)
{
    if (str->data) free(str->data);
    str->data = malloc(initial_capacity);
    if (str->data == NULL) {
        perror("malloc() failed");
        exit(errno);
    }
    str->cap = initial_capacity;
    str->len = 0;
    *(str->data) = 0;
}

void resize_string(struct String *str)
{
    str->data = realloc((void*)str->data, str->cap * 2);
    if (str->data == NULL) {
        perror("realloc() failed");
        exit(errno);
    }
    str->cap = str->cap * 2;
}

void append_str(char *input_str, size_t len, struct String *str)
{
    while (str->len + len >= str->cap - 1) {
        resize_string(str);
    }
    strcpy(str->data + str->len, input_str);
    str->len += len;
}

void append_char(char c, struct String *str)
{
    if (str->len >= str->cap - 1) {
        resize_string(str);
    }
    str->data[str->len] = c;
    str->len += 1;
    str->data[str->len] = '\0';
}

void delete_char(struct String *str)
{
    str->len -= 1;
    str->data[str->len] = '\0';
}
