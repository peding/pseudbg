// calling libc funcs and other lib funcs as well
// is unsafe while the breakpoint is applied inside the libc, because the breakpoint handler
// itself calls a bunch of libc funcs,
// resulting in breakpoint handler hitting the breakpoint and causing
// infitnity loop until the process crashes.
// this issue is avoided by loading extra libc into memory that pseudbg/capstone uses

#define _GNU_SOURCE
#include <link.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>

#include "safe_libc.h"


char *libc_name = "libc.so.6";
char *libdl_name = "libdl.so.2";

// libc stuff
void *libc = 0;

void *(*safe_malloc)(size_t);
void *(*safe_calloc)(size_t, size_t);
void *(*safe_realloc)(void *, size_t);
void (*safe_free)(void *);
void *(*safe_mmap)(void *, size_t, int, int, int, off_t);
int (*safe_mprotect)(void *, size_t, int);

void (*safe_memcpy)(void *, const void *, size_t);
void (*safe_memset)(void *, int, size_t);
int (*safe_memcmp)(const void *, const void *, size_t);
size_t (*safe_strlen)(const char *);

void (*safe_puts)(const char *);
int (*safe_printf)(const char *, ...);
int (*safe_scanf)(const char *, ...);
int (*safe_getchar)();

int (*safe_tcgetattr)(int, struct termios *);
int (*safe_tcsetattr)(int, int, const struct termios *);
void (*safe_cfmakeraw)(struct termios *);

FILE *(*safe_fopen)(const char *, const char *);
int (*safe_fclose)(FILE *);
ssize_t (*safe_getline)(char **, size_t *, FILE *);
int (*safe_snprintf)(char *, size_t, const char *, ...);
int (*safe_vsnprintf)(char *restrict, size_t, const char *restrict, va_list);
int (*safe_sscanf)(const char *, const char *, ...);

pid_t (*safe_getpid)();
void (*safe_exit)(int);

// libdl
void *libdl = 0;

int (*safe_dladdr)(void *addr, Dl_info *info);


void init_libc()
{
	libc = dlmopen(LM_ID_NEWLM, libc_name, RTLD_LAZY | RTLD_DEEPBIND);
	if (!libc) {
		printf("error: failed to load %s\n", libc_name);
		exit(1);
	}

	libdl = dlmopen(LM_ID_NEWLM, libdl_name, RTLD_LAZY | RTLD_DEEPBIND);
	if (!libdl) {
		printf("error: failed to load %s\n", libdl_name);
		exit(1);
	}

	*(void **)(&safe_malloc) = dlsym(libc, "malloc");
	*(void **)(&safe_calloc) = dlsym(libc, "calloc");
	*(void **)(&safe_realloc) = dlsym(libc, "realloc");
	*(void **)(&safe_free) = dlsym(libc, "free");
	*(void **)(&safe_free) = dlsym(libc, "free");
	*(void **)(&safe_mmap) = dlsym(libc, "mmap");
	*(void **)(&safe_mprotect) = dlsym(libc, "mprotect");

	*(void **)(&safe_memcpy) = dlsym(libc, "memcpy");
	*(void **)(&safe_memset) = dlsym(libc, "memset");
	*(void **)(&safe_memcmp) = dlsym(libc, "memcmp");
	*(void **)(&safe_strlen) = dlsym(libc, "strlen");

	*(void **)(&safe_puts) = dlsym(libc, "puts");
	*(void **)(&safe_printf) = dlsym(libc, "printf");
	*(void **)(&safe_scanf) = dlsym(libc, "scanf");
	*(void **)(&safe_getchar) = dlsym(libc, "getchar");

	*(void **)(&safe_tcgetattr) = dlsym(libc, "tcgetattr");
	*(void **)(&safe_tcsetattr) = dlsym(libc, "tcsetattr");
	*(void **)(&safe_cfmakeraw) = dlsym(libc, "cfmakeraw");

	*(void **)(&safe_fopen) = dlsym(libc, "fopen");
	*(void **)(&safe_fclose) = dlsym(libc, "fclose");
	*(void **)(&safe_getline) = dlsym(libc, "getline");
	*(void **)(&safe_snprintf) = dlsym(libc, "snprintf");
	*(void **)(&safe_vsnprintf) = dlsym(libc, "vsnprintf");
	*(void **)(&safe_sscanf) = dlsym(libc, "sscanf");

	*(void **)(&safe_getpid) = dlsym(libc, "getpid");
	*(void **)(&safe_exit) = dlsym(libc, "exit");

	*(void **)(&safe_dladdr) = dlsym(libdl, "dladdr");
}
