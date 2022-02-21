// low level stuff

#define _GNU_SOURCE
#include <sys/mman.h>

#include "asm.h"
#include "safe_libc.h"

// the first instructions to execute when a breakpoint is hit
// each breakpoint will have own version of this in order to know where to return from the debugger
uint8_t asm_bp[16] =
		// lea rsp, [rsp-0x80] - avoid red zone
		"\x48\x8d\x64\x24\x80"
		// push [rip+asm_data->bp_info[x].addr]
		"\xff\x35\x00\x00\x00\x00"
		// jmp asm_code->shellcode
		"\xe9\x00\x00\x00\x00"
		;

// builds the regs_x64 struct and calls the breakpoint handler, this shellcode is called by asm_bp
uint8_t shellcode[] =
		// pushf
		"\x9c"
		// push rbp
		"\x55"
		// mov rbp, rsp
		"\x48\x89\xe5"
		// add rbp, 0x98 # point to the real rsp value
		"\x48\x81\xc5\x98\x00\x00\x00"
		// push rbp # rsp
		"\x55"
		// push r[abcd]x, r[sd]i, r<8-15>
		"\x50\x53\x51\x52\x56\x57\x41\x50\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57"
		// push rax # placeholder for rip_next
		"\x50"
		// mov rdi, rsp
		"\x48\x89\xe7"
		// mov rbx, rsp # backup rsp
		"\x48\x89\xe3"
		// and rsp, 0xffffffffffffffe0 # the stack has to be 32 byte or you suck
		"\x48\x83\xe4\xe0"
		// push all xmm
		"\x48\x83\xec\x10\xf3\x0f\x7f\x84\x24\x00\x00\x00\x00\x48\x83\xec\x10\xf3\x0f\x7f\x8c\x24\x00\x00\x00\x00\x48\x83\xec\x10\xf3\x0f\x7f\x94\x24\x00\x00\x00\x00\x48\x83\xec\x10\xf3\x0f\x7f\x9c\x24\x00\x00\x00\x00\x48\x83\xec\x10\xf3\x0f\x7f\xa4\x24\x00\x00\x00\x00\x48\x83\xec\x10\xf3\x0f\x7f\xac\x24\x00\x00\x00\x00\x48\x83\xec\x10\xf3\x0f\x7f\xb4\x24\x00\x00\x00\x00\x48\x83\xec\x10\xf3\x0f\x7f\xbc\x24\x00\x00\x00\x00\x48\x83\xec\x10\xf3\x44\x0f\x7f\x84\x24\x00\x00\x00\x00\x48\x83\xec\x10\xf3\x44\x0f\x7f\x8c\x24\x00\x00\x00\x00\x48\x83\xec\x10\xf3\x44\x0f\x7f\x94\x24\x00\x00\x00\x00\x48\x83\xec\x10\xf3\x44\x0f\x7f\x9c\x24\x00\x00\x00\x00\x48\x83\xec\x10\xf3\x44\x0f\x7f\xa4\x24\x00\x00\x00\x00\x48\x83\xec\x10\xf3\x44\x0f\x7f\xac\x24\x00\x00\x00\x00\x48\x83\xec\x10\xf3\x44\x0f\x7f\xb4\x24\x00\x00\x00\x00\x48\x83\xec\x10\xf3\x44\x0f\x7f\xbc\x24\x00\x00\x00\x00"
		// push all ymm
		"\x48\x83\xec\x20\xc5\xfd\x7f\x04\x24\x48\x83\xec\x20\xc5\xfd\x7f\x0c\x24\x48\x83\xec\x20\xc5\xfd\x7f\x14\x24\x48\x83\xec\x20\xc5\xfd\x7f\x1c\x24\x48\x83\xec\x20\xc5\xfd\x7f\x24\x24\x48\x83\xec\x20\xc5\xfd\x7f\x2c\x24\x48\x83\xec\x20\xc5\xfd\x7f\x34\x24\x48\x83\xec\x20\xc5\xfd\x7f\x3c\x24\x48\x83\xec\x20\xc5\x7d\x7f\x04\x24\x48\x83\xec\x20\xc5\x7d\x7f\x0c\x24\x48\x83\xec\x20\xc5\x7d\x7f\x14\x24\x48\x83\xec\x20\xc5\x7d\x7f\x1c\x24\x48\x83\xec\x20\xc5\x7d\x7f\x24\x24\x48\x83\xec\x20\xc5\x7d\x7f\x2c\x24\x48\x83\xec\x20\xc5\x7d\x7f\x34\x24\x48\x83\xec\x20\xc5\x7d\x7f\x3c\x24"
		// movabs rax, address-to-breakpoint-handler
		"\x48\xb8\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		// call rax
		"\xff\xd0"
		// pop all ymm
		"\xc5\xfd\x6f\x04\x24\x48\x83\xc4\x20\xc5\xfd\x6f\x0c\x24\x48\x83\xc4\x20\xc5\xfd\x6f\x14\x24\x48\x83\xc4\x20\xc5\xfd\x6f\x1c\x24\x48\x83\xc4\x20\xc5\xfd\x6f\x24\x24\x48\x83\xc4\x20\xc5\xfd\x6f\x2c\x24\x48\x83\xc4\x20\xc5\xfd\x6f\x34\x24\x48\x83\xc4\x20\xc5\xfd\x6f\x3c\x24\x48\x83\xc4\x20\xc5\x7d\x6f\x04\x24\x48\x83\xc4\x20\xc5\x7d\x6f\x0c\x24\x48\x83\xc4\x20\xc5\x7d\x6f\x14\x24\x48\x83\xc4\x20\xc5\x7d\x6f\x1c\x24\x48\x83\xc4\x20\xc5\x7d\x6f\x24\x24\x48\x83\xc4\x20\xc5\x7d\x6f\x2c\x24\x48\x83\xc4\x20\xc5\x7d\x6f\x34\x24\x48\x83\xc4\x20\xc5\x7d\x6f\x3c\x24\x48\x83\xc4\x20"
		// pop all xmm
		"\xf3\x44\x0f\x6f\xbc\x24\x00\x00\x00\x00\x48\x83\xc4\x10\xf3\x44\x0f\x6f\xb4\x24\x00\x00\x00\x00\x48\x83\xc4\x10\xf3\x44\x0f\x6f\xac\x24\x00\x00\x00\x00\x48\x83\xc4\x10\xf3\x44\x0f\x6f\xa4\x24\x00\x00\x00\x00\x48\x83\xc4\x10\xf3\x44\x0f\x6f\x9c\x24\x00\x00\x00\x00\x48\x83\xc4\x10\xf3\x44\x0f\x6f\x94\x24\x00\x00\x00\x00\x48\x83\xc4\x10\xf3\x44\x0f\x6f\x8c\x24\x00\x00\x00\x00\x48\x83\xc4\x10\xf3\x44\x0f\x6f\x84\x24\x00\x00\x00\x00\x48\x83\xc4\x10\xf3\x0f\x6f\xbc\x24\x00\x00\x00\x00\x48\x83\xc4\x10\xf3\x0f\x6f\xb4\x24\x00\x00\x00\x00\x48\x83\xc4\x10\xf3\x0f\x6f\xac\x24\x00\x00\x00\x00\x48\x83\xc4\x10\xf3\x0f\x6f\xa4\x24\x00\x00\x00\x00\x48\x83\xc4\x10\xf3\x0f\x6f\x9c\x24\x00\x00\x00\x00\x48\x83\xc4\x10\xf3\x0f\x6f\x94\x24\x00\x00\x00\x00\x48\x83\xc4\x10\xf3\x0f\x6f\x8c\x24\x00\x00\x00\x00\x48\x83\xc4\x10\xf3\x0f\x6f\x84\x24\x00\x00\x00\x00\x48\x83\xc4\x10"
		// mov rsp, rbx
		"\x48\x89\xdc"
		// pop rax # remove rip_next
		"\x58"
		// pop r<15-8>, r[ds]i, r[dcba]x
		"\x41\x5f\x41\x5e\x41\x5d\x41\x5c\x41\x5b\x41\x5a\x41\x59\x41\x58\x5f\x5e\x5a\x59\x5b\x58"
		// sub rbp, 0x98
		"\x48\x81\xed\x98\x00\x00\x00"
		// leave
		"\xc9"
		// popf
		"\x9d"
		// ret 0x80
		"\xc2\x80\x00";
const size_t shellcode_size = sizeof(shellcode) - 1; // -1 for null

struct asm_code_mmap *asm_code;
struct asm_data_mmap *asm_data;


// initialize memory region used by breakpoints
void init_mmap()
{
	// mmap code/data at address of lower 32 bit range
	asm_code = (void *)0x10000;
	while (safe_mmap(asm_code, ASM_CODE_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON|MAP_FIXED, 0, 0) == (void *)-1)
		asm_code = (void *)((uint8_t *)asm_code + 0x1000);
	safe_memset(asm_code, 0, sizeof(*asm_code));

	// why does mmap success when mmaping same address twice?
	asm_data = (void *)((uint8_t *)asm_code + ASM_CODE_SIZE);
	while (safe_mmap(asm_data, ASM_DATA_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON|MAP_FIXED, 0, 0) == (void *)-1)
		asm_data = (void *)((uint8_t *)asm_data + 0x1000);
	safe_memset(asm_data, 0, sizeof(*asm_data));

	if ((size_t)asm_code + ASM_CODE_SIZE > 0xffffffff || (size_t)asm_data + ASM_DATA_SIZE > 0xffffffff) {
		safe_printf("error: failed to mmap at 32 bit range");
		safe_exit(1);
	}

	// find aa... pattern and replace with breakpoint handler address
	for (size_t i = 0; i < shellcode_size - 8; i++) {
		if (!safe_memcmp(shellcode + i, "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 8)) {
			*(size_t *)(shellcode + i) = (size_t)&breakpoint_handler;
			break;
		} else if (i == shellcode_size - 8 - 1) {
			safe_printf("error: could not find operand pattern\n");
			safe_exit(1);
		}
	}
	// copy to mmap
	safe_memcpy(asm_code->shellcode, shellcode, shellcode_size);

	// init the breakpoint shellcode
	for (int i = 0; i < MAX_BREAKPOINT; i++) {
		void *bp_shellcode_addr = asm_code->bp_shellcode + i;
		// point at the variable that will hold the breakpoint address for the current breakpoint
		*(uint32_t *)(asm_bp + 7) = (size_t)&asm_data->bp_info[i].addr - (size_t)bp_shellcode_addr - 11;
		// fix the jmp instruction to jump to common shellcode
		*(uint32_t *)(asm_bp + 12) = (size_t)asm_code->shellcode - (size_t)bp_shellcode_addr - 16;
		// copy to mmap
		safe_memcpy(bp_shellcode_addr, asm_bp, sizeof(asm_bp));

		// point at the current breakpoint shellcode, used by breakpoints at 64-bit range
		asm_data->bp_info[i].shellcode_addr = bp_shellcode_addr;
	}

	// finish with making code executable
	safe_mprotect(asm_code, ASM_CODE_SIZE, PROT_READ|PROT_EXEC);

	safe_printf("asm code mmap: %p (size: %ld bytes)\n", asm_code, sizeof(*asm_code));
	safe_printf("asm data mmap: %p (size: %ld bytes)\n", asm_data, sizeof(*asm_data));
	safe_printf("common shellcode size: %ld bytes\n", shellcode_size);
}
