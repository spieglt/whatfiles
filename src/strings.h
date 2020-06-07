#ifndef STRINGS_H
#define STRINGS_H

#include <stdio.h>

struct String {
    size_t cap;
    size_t len;
    char* data;
};

void init_string(struct String *str, size_t initial_capacity);
void append_str(char *input_str, size_t len, struct String *str);
void append_char(char c, struct String *str);
void delete_char(struct String *str);

#endif /* !STRINGS_H */
