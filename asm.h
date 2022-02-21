#ifndef __ASM_H__
#define __ASM_H__

#include <stdint.h>
#include <stddef.h>

// maximum number of configurable breakpoints
#define MAX_BREAKPOINT 32

// x64 cpu registers
struct regs_x64
{
	size_t rip_next; // set and used by breakpoint handler to evaluate branch address
	size_t r15;
	size_t r14;
	size_t r13;
	size_t r12;
	size_t r11;
	size_t r10;
	size_t r9;
	size_t r8;
	size_t rdi;
	size_t rsi;
	size_t rdx;
	size_t rcx;
	size_t rbx;
	size_t rax;
	size_t rsp;
	size_t rbp;
	size_t eflags;
	size_t rip;
};

// storing info about a breakpoint
struct breakpoint_info
{
	void *addr; // breakpoint address
	void *shellcode_addr; // where to jump when the breakpoint is hit, only used for 64-bit range address
	int patch_len; // length of the breakpoint
	uint8_t patch[15]; // original bytes
};

// allocated with mmap, storing code
extern struct asm_code_mmap
{
	uint8_t bp_shellcode[MAX_BREAKPOINT][16];
	uint8_t shellcode[1024]; // common shellcode executed after bp_shellcode
} *asm_code;
#define ASM_CODE_SIZE ((sizeof(*asm_code) + 0xfff) & ~0xfffull)

// allocated with mmap, storing breakpoint info
extern struct asm_data_mmap
{
	struct breakpoint_info bp_info[MAX_BREAKPOINT];
} *asm_data;
#define ASM_DATA_SIZE ((sizeof(*asm_data) + 0xfff) & ~0xfffull)


extern uint8_t asm_bp[16];
extern uint8_t shellcode[];
extern const size_t shellcode_size;

extern void breakpoint_handler(struct regs_x64 *);
extern void init_mmap();

#endif
