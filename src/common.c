#include <ctype.h>
#include <string.h>

#include "../include/common.h"

void remove_suffix(char *str, const char *suffix) {
    u64 str_len = strlen(str);
    u64 suffix_len = strlen(suffix);
    
    if (str_len >= suffix_len && !strcmp(str + str_len - suffix_len, suffix)) {
        str[str_len - suffix_len] = '\0';
    }
}

void get_str_line(char *dest, char **src) {
    while (**src && isspace(*src)) (*src)++;

    while (**src && !(*src == '\n')) {
        *dest = **src;
        dest++;
        (*src)++;    
    }
    
    *dest-- = '\0';
}