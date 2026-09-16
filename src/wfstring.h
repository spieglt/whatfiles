#ifndef WF_WFSTRING_H
#define WF_WFSTRING_H

#include <stddef.h>

/*
Growable byte string. A String must be zeroed before first use; str_init() may
also be called on an already-initialized String to reset it. Every function
keeps the buffer NUL-terminated, and `len` is the length without the NUL.
*/
struct String {
    size_t cap;
    size_t len;
    char *data;
};

void str_init(struct String *str, size_t initial_capacity);
void str_free(struct String *str);
void str_clear(struct String *str);
void str_append(struct String *str, const char *data, size_t len);
void str_append_cstr(struct String *str, const char *cstr);
void str_append_char(struct String *str, char c);
void str_appendf(struct String *str, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
/*
Appends `data` with anything that could corrupt or forge a log line replaced by
a C-style escape: control characters, DEL, and the backslash itself.
*/
void str_append_escaped(struct String *str, const char *data, size_t len);

#endif /* !WF_WFSTRING_H */
