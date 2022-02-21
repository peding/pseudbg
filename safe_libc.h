#ifndef __SAFE_LIBC_H__
#define __SAFE_LIBC_H__

#define _GNU_SOURCE
#include <dlfcn.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/mman.h>

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>


// init libc (and libdl) funcs
extern void init_libc();

// libc funcs/variable used by pseudbg
extern void *(*safe_malloc)(size_t);
extern void *(*safe_calloc)(size_t, size_t);
extern void *(*safe_realloc)(void *, size_t);
extern void (*safe_free)(void *);
extern void *(*safe_mmap)(void *, size_t, int, int, int, off_t);
extern int (*safe_mprotect)(void *, size_t, int);

extern void (*safe_memcpy)(void *, const void *, size_t);
extern void (*safe_memset)(void *, int, size_t);
extern int (*safe_memcmp)(const void *, const void *, size_t);
extern size_t (*safe_strlen)(const char *);

extern void (*safe_puts)(const char *);
extern int (*safe_printf)(const char *, ...);
extern int (*safe_scanf)(const char *, ...);
extern int (*safe_getchar)();

extern int (*safe_tcgetattr)(int, struct termios *);
extern int (*safe_tcsetattr)(int, int, const struct termios *);
extern void (*safe_cfmakeraw)(struct termios *);

extern FILE *(*safe_fopen)(const char *, const char *);
extern int (*safe_fclose)(FILE *);
extern ssize_t (*safe_getline)(char **, size_t *, FILE *);
extern int (*safe_snprintf)(char *, size_t, const char *, ...);
extern int (*safe_vsnprintf)(char *restrict, size_t, const char *restrict, va_list);
extern int (*safe_sscanf)(const char *, const char *, ...);

extern pid_t (*safe_getpid)();
extern void (*safe_exit)(int);

// libdl stuff
extern int (*safe_dladdr)(void *addr, Dl_info *info);

#endif
