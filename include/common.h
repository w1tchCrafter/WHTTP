#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stdio.h>

#define DEBUG_MACRO

#define format(buffer, size, format, ...) snprintf(buffer, size, format, ## __VA_ARGS__)

typedef uint8_t u8;
typedef uint16_t u16;
typedef int32_t i32;
typedef uint32_t u32;
typedef int64_t i64;
typedef uint64_t u64;

void remove_suffix(char *str, const char *suffix);
void get_str_line(char *dest, char **src);

#endif