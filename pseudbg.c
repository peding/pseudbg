// TODO: improve xmm/ymm backup asm
// TODO: support symbols?

#define _GNU_SOURCE
#include <unistd.h>
#include <link.h>
#include <elf.h>
#include <signal.h>
#include <fcntl.h>

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include <capstone/capstone.h>

#include "asm.h"
#include "safe_libc.h"

#if __x86_64__
#define CPU_64
#define ElfN_Ehdr Elf64_Ehdr
#else
#error "32-bit not supported"
#endif


// capstone handle
csh handle = 0;

enum eflags_const
{
	EFLAGS_CF = 0x1,
	EFLAGS_PF = 0x4,
	EFLAGS_AF = 0x10,
	EFLAGS_ZF = 0x40,
	EFLAGS_SF = 0x80,
	EFLAGS_TF = 0x100,
	EFLAGS_IF = 0x200,
	EFLAGS_DF = 0x400,
	EFLAGS_OF = 0x800,
};

// extract register value from regs specified by capstone register id
size_t get_register_value(struct regs_x64 *regs, int cs_reg)
{
	switch (cs_reg) {
	case X86_REG_RAX:
		return regs->rax;
		break;
	case X86_REG_RBX:
		return regs->rbx;
		break;
	case X86_REG_RCX:
		return regs->rcx;
		break;
	case X86_REG_RDX:
		return regs->rdx;
		break;
	case X86_REG_RSI:
		return regs->rsi;
		break;
	case X86_REG_RDI:
		return regs->rdi;
		break;
	case X86_REG_R8:
		return regs->r8;
		break;
	case X86_REG_R9:
		return regs->r9;
		break;
	case X86_REG_R10:
		return regs->r10;
		break;
	case X86_REG_R11:
		return regs->r11;
		break;
	case X86_REG_R12:
		return regs->r12;
		break;
	case X86_REG_R13:
		return regs->r13;
		break;
	case X86_REG_R14:
		return regs->r14;
		break;
	case X86_REG_R15:
		return regs->r15;
		break;
	case X86_REG_RSP:
		return regs->rsp;
		break;
	case X86_REG_RBP:
		return regs->rbp;
		break;
	case X86_REG_RIP:
		return regs->rip_next;
		break;
	default:
		safe_printf("error: unsupported register\n");
		safe_exit(1);
		return 0;
	}
}

// check whether if the branch is taken or not
bool is_cond_true(struct regs_x64 *regs, cs_insn *insn)
{
	// am i really supposed to do like this?
	switch (insn->id) {
	case X86_INS_JB:
		return (regs->eflags & EFLAGS_CF);
	case X86_INS_JAE:
		return !(regs->eflags & EFLAGS_CF);
	case X86_INS_JBE:
		return (regs->eflags & EFLAGS_CF) || (regs->eflags & EFLAGS_ZF);
	case X86_INS_JA:
		return !(regs->eflags & EFLAGS_CF) && !(regs->eflags & EFLAGS_ZF);
	case X86_INS_JCXZ:
		return (regs->rcx & 0xffff) == 0;
	case X86_INS_JECXZ:
		return (regs->rcx & 0xffffffff) == 0;
	case X86_INS_JRCXZ:
		return regs->rcx == 0;
	case X86_INS_JL:
		// secret trick to convert int to bool
		return !(regs->eflags & EFLAGS_SF) != !(regs->eflags & EFLAGS_OF);
	case X86_INS_JGE:
		return !(regs->eflags & EFLAGS_SF) == !(regs->eflags & EFLAGS_OF);
	case X86_INS_JLE:
		return (regs->eflags & EFLAGS_ZF) || (!(regs->eflags & EFLAGS_SF) != !(regs->eflags & EFLAGS_OF));
	case X86_INS_JG:
		return !(regs->eflags & EFLAGS_ZF) && (!(regs->eflags & EFLAGS_SF) == !(regs->eflags & EFLAGS_OF));
	case X86_INS_JE:
		return (regs->eflags & EFLAGS_ZF);
	case X86_INS_JNE:
		return !(regs->eflags & EFLAGS_ZF);
	case X86_INS_JO:
		return (regs->eflags & EFLAGS_OF);
	case X86_INS_JNO:
		return !(regs->eflags & EFLAGS_OF);
	case X86_INS_JP:
		return (regs->eflags & EFLAGS_PF);
	case X86_INS_JNP:
		return !(regs->eflags & EFLAGS_PF);
	case X86_INS_JS:
		return (regs->eflags & EFLAGS_SF);
	case X86_INS_JNS:
		return !(regs->eflags & EFLAGS_SF);
	case X86_INS_JMP:
		return true;
	case X86_INS_LOOP:
		return regs->rcx - 1;
	case X86_INS_LOOPE:
		return regs->rcx - 1 && (regs->eflags & EFLAGS_ZF);
	case X86_INS_LOOPNE:
		return regs->rcx - 1 && !(regs->eflags & EFLAGS_ZF);
	default:
		safe_printf("error: not supported type of conditional instruction\n");
		safe_exit(1);
	}
	return false;
}

// get memory permission of an address
int get_mem_perm(void *addr)
{
	char maps_path[128];
	safe_snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", safe_getpid());
	FILE *maps = safe_fopen(maps_path, "r");
	if (!maps) {
		safe_puts("error: failed to open memory map file\n");
		safe_exit(1);
	}

	char buf[128];
	char perm_str[8];
	char *line = 0;
	size_t len = 0;

	size_t start = 0;
	size_t end = 0;
	int perm = -1;

	while (safe_getline(&line, &len, maps) != -1) {
		safe_sscanf(line, "%lx-%lx %s %s %s %s %s", &start, &end, perm_str, buf, buf, buf, buf);
		if (start <= (size_t)addr && (size_t)addr < end) {
			perm = 0;
			perm |= (perm_str[0] != '-' ? PROT_READ : 0);
			perm |= (perm_str[1] != '-' ? PROT_WRITE : 0);
			perm |= (perm_str[2] != '-' ? PROT_EXEC : 0);
			break;
		}
	}

	safe_free(line);
	safe_fclose(maps);

	return perm;
}

// print memory maps
void print_maps()
{
	char maps_path[128];
	safe_snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", safe_getpid());
	FILE *maps = safe_fopen(maps_path, "r");
	if (!maps) {
		safe_puts("error: failed to open memory map file\n");
		safe_exit(1);
	}

	safe_printf("memory map: %s\n", maps_path);

	char *line = 0;
	size_t len = 0;
	while (safe_getline(&line, &len, maps) != -1)
		safe_printf("%s", line);

	safe_free(line);
	safe_fclose(maps);
}

// write bytes to the specified address
int write_mem(void *dest, void *src, size_t size)
{
	// kinda support multiple page, not working properly if all pages do not have same memory permission
	size_t page_size = (((uint64_t)dest + size + 0xfff) & ~0xfffull) - ((uint64_t)dest & ~0xfffull);

	int perm = get_mem_perm(dest);
	if ((perm & (PROT_READ|PROT_WRITE)) != (PROT_READ|PROT_WRITE))
		safe_mprotect((void *)((size_t)dest & (~0xfffull)), page_size, PROT_READ|PROT_WRITE);

	safe_memcpy(dest, src, size);

	if ((perm & (PROT_READ|PROT_WRITE)) != (PROT_READ|PROT_WRITE))
		safe_mprotect((void *)((size_t)dest & (~0xfffull)), page_size, perm);

	return 0;
}

// read_mem and write_mem is pretty much the same shit
int read_mem(void *dest, void *src, size_t size)
{
	size_t page_size = (((uint64_t)dest + size + 0xfff) & ~0xfffull) - ((uint64_t)dest & ~0xfffull);

	// how often is a page not readable?
	int perm = get_mem_perm(src);
	if (!(perm & PROT_READ))
		safe_mprotect((void *)((size_t)src & (~0xfffull)), page_size, PROT_READ);

	safe_memcpy(dest, src, size);

	if (!(perm & PROT_READ))
		safe_mprotect((void *)((size_t)src & (~0xfffull)), page_size, perm);

	return 0;
}

// check whether if the address is in pseudbg
bool addr_in_pseudbg(void *addr)
{
	// lazy low effort check
	Dl_info pseudbg_info = {0};
	Dl_info addr_info = {0};
	// get dl_info for pseudbg lib, just passing random function that belongs to pseudbg
	safe_dladdr(addr_in_pseudbg, &pseudbg_info);
	// get dl_info for addr
	safe_dladdr(addr, &addr_info);

	// if both have the same base address, it means it is in pseudbg
	return pseudbg_info.dli_fbase == addr_info.dli_fbase;
}

// get breakpoint id from an address
// use intersect to check if the address intersects with the breakpoint instruction
int get_breakpoint_id(void *addr, bool intersect)
{
	int bp_id = -1;

	for (int i = 0; i < MAX_BREAKPOINT; i++) {
		struct breakpoint_info *bi = asm_data->bp_info + i;
		if (bi->addr == addr || (intersect && bi->addr <= addr && addr < bi->addr + bi->patch_len))
			return i;
	}

	return bp_id;
}

// set breakpoint at specified address
// breakpoint id 0 is used for single step (and step over)
void set_breakpoint(void *addr, bool single_step)
{
	struct breakpoint_info *bp_info = 0;
	int bp_id = 0;

	if (!single_step) {
		for (int i = 1; i < MAX_BREAKPOINT; i++) {
			if (!asm_data->bp_info[i].addr) {
				bp_id = i;
				break;
			}
		}

		if (bp_id == 0) {
			safe_printf("error: no breakpoint slot left, unable to set breakpoint\n");
			return;
		}
	}

	bp_info = asm_data->bp_info + bp_id;

	safe_printf("setting breakpoint: %p\n", addr);

	if (get_breakpoint_id(addr, false) != -1) {
		safe_printf("breakpoint already set: %p\n", addr);
		return;
	}

	if (get_breakpoint_id(addr, true) != -1) {
		safe_printf("breakpoint intersecting with other breakpoint, disabling breakpoint\n", addr);
		return;
	}

	if (addr_in_pseudbg(addr)) {
		// never try to debug a debugger.
		// this happens because some fucker (rtld)
		// calls some kind of function inside pseudbg, probably fini stuff, when exiting the debuggee.
		safe_printf("breakpoint inside pseudbg, disabling breakpoint\n");
		return;
	}

	if ((size_t)addr <= 0xffffffff) {
		// jmp asm_code->bp_shellcode[bp_id]
		uint8_t bp[5] = "\xe9\x00\x00\x00\x00";
		*(uint32_t *)(bp + 1) = (size_t)&asm_code->bp_shellcode[bp_id] - (size_t)addr - 5; // relative

		read_mem(bp_info->patch, addr, sizeof(bp));
		bp_info->patch_len = sizeof(bp);
		write_mem(addr, bp, sizeof(bp));
	} else {
		// jmp [asm_data->bp_info[bp_id].shellcode_addr] -> jmp asm_code->bp_shellcode[bp_id]
		uint8_t bp[7] = "\xff\x24\x25\x00\x00\x00\x00";
		*(uint32_t *)(bp + 3) = (size_t)&bp_info->shellcode_addr; // absolute

		read_mem(bp_info->patch, addr, sizeof(bp));
		bp_info->patch_len = sizeof(bp);
		write_mem(addr, bp, sizeof(bp));
	}

	bp_info->addr = addr;
}

void remove_breakpoint(int bp_id)
{
	struct breakpoint_info *bp_info = asm_data->bp_info + bp_id;

	safe_printf("removing breakpoint: %p\n", bp_info->addr);
	write_mem(bp_info->addr, bp_info->patch, bp_info->patch_len);

	bp_info->patch_len = 0;
	bp_info->addr = 0;
}

// get the next rip value it becomes when step over/into is done
size_t get_next_rip(struct regs_x64 *regs, uint8_t code[15], bool step_over)
{
	size_t next = -1;
	cs_insn *insn;

	int count = cs_disasm(handle, code, 15, regs->rip, 1, &insn);
	if (count == 0) {
		safe_printf("error: failed to disassemble current instruction\n");
		safe_exit(1);
	}

	// the next rip address for step over
	next = insn->address + insn->size;

	if (!cs_insn_group(handle, insn, X86_GRP_CALL) && !cs_insn_group(handle, insn, X86_GRP_JUMP) &&
			!cs_insn_group(handle, insn, X86_GRP_RET) && !cs_insn_group(handle, insn, X86_GRP_BRANCH_RELATIVE)) {
		// not a branch instruction, return address to next instruction
		cs_free(insn, count);
		return next;
	}

	// detail has a lot of details
	cs_detail *detail = insn->detail;

	// evaluate expression used for branch address
	size_t branch_addr = -1;
	for (int i = 0; i < detail->x86.op_count; i++) {
		cs_x86_op *op = detail->x86.operands + i;

		if (op->access == CS_AC_WRITE)
			continue;

		switch((int)op->type) {
		case X86_OP_REG:
			branch_addr = get_register_value(regs, op->reg);
			break;
		case X86_OP_IMM:
			branch_addr = op->imm;
			break;
		case X86_OP_MEM:
		{
			// segment register? who is that?
			size_t base = 0, index = 0;
			if (op->mem.base != X86_REG_INVALID)
				base = get_register_value(regs, op->mem.base);
			if (op->mem.index != X86_REG_INVALID)
				index = get_register_value(regs, op->mem.index);

			branch_addr = *(size_t *)(base + index * op->mem.scale + op->mem.disp);
			break;
		}
		default:
			safe_printf("error: unsupported operand type");
			safe_exit(1);
			break;
		}
	}

	if (cs_insn_group(handle, insn, X86_GRP_CALL)) {
		if (!step_over)
			next = branch_addr;
	} else if (cs_insn_group(handle, insn, X86_GRP_RET)) {
		next = *(size_t *)(regs->rsp);
	} else if ((cs_insn_group(handle, insn, X86_GRP_JUMP) || cs_insn_group(handle, insn, X86_GRP_BRANCH_RELATIVE)) && is_cond_true(regs, insn)) {
		next = branch_addr;
	}

	cs_free(insn, count);

	return next;
}

// read single input without printing the key input and not waiting for newline
char read_char()
{
	// read single character
	struct termios oldt, newt;
	safe_tcgetattr(STDIN_FILENO, &oldt);
	newt = oldt;
	// do not print the input
	safe_cfmakeraw(&newt);
	// do not wait for newline
	newt.c_lflag &= ~(ICANON);

	safe_tcsetattr(STDIN_FILENO, TCSANOW, &newt);
	char c = safe_getchar();
	safe_tcsetattr(STDIN_FILENO, TCSANOW, &oldt);

	return c;
}

// gets a command and do the needful
void get_command(struct regs_x64 *regs, uint8_t code[15], int bp_id)
{
	static size_t repeat_step_into = 0;

	// stop repeating step into when a breakpoint is hit
	if (bp_id != 0)
		repeat_step_into = false;

	bool exit_loop = false;
	while (!exit_loop) {
		char c = 0;
		if (!repeat_step_into) {
			c = read_char();
		} else {
			c = 'i';
			repeat_step_into--;
		}

		switch (c) {
		case 's':
		{
			// step over
			safe_printf("step over\n");

			uint64_t next = get_next_rip(regs, code, true);
			if ((next > 0xffffffff ? -7 : -5) < (int64_t)(next - regs->rip)
					&& (int64_t)(next - regs->rip) < 0)
				safe_printf("warning: branching to address behind that is very close to current instruction will result in a crash\n", next - regs->rip);
			set_breakpoint((void *)next, true);

			exit_loop = true;
			break;
		}
		case 'i':
		{
			// step into
			safe_printf("step into\n");

			uint64_t next = get_next_rip(regs, code, false);
			if ((next > 0xffffffff ? -7 : -5) < (int64_t)(next - regs->rip)
					&& (int64_t)(next - regs->rip) < 0)
				safe_printf("warning: branching to address behind that is very close to current instruction will result in a crash\n", next - regs->rip);
			set_breakpoint((void *)next, true);

			exit_loop = true;
			break;
		}
		case 'r':
		{
			// repeat step into until breakpoint hit or nr of specified instructions executed
			repeat_step_into = 0;
			safe_printf("# of times to repeat step into:\n");
			safe_scanf("%d", &repeat_step_into);

			break;
		}
		case 'l':
		{
			// list active breakpoints
			safe_printf("active breakpoints:\n");
			for (int i = 0; i < MAX_BREAKPOINT; i++) {
				struct breakpoint_info *bi = asm_data->bp_info + i;
				if (!bi->addr)
					continue;

				safe_printf("%016lx: ", (size_t)bi->addr);
				for (int i = 0; i < bi->patch_len; i++)
					safe_printf("%02x ", bi->patch[i]);

				safe_printf("(breakpoint size: %d)\n", bi->patch_len);
			}
			break;
		}
		case 'b':
		{
			// set breakpoint
			void *addr = 0;
			safe_printf("set breakpoint at:\n");
			safe_scanf("%p", &addr);

			if (addr)
				set_breakpoint(addr, false);
			break;
		}
		case 'e':
			// remove breakpoint
			void *addr = 0;
			safe_printf("remove breakpoint at:\n");
			safe_scanf("%p", &addr);

			if (!addr)
				break;

			int bp_id = get_breakpoint_id(addr, false);
			if (bp_id == -1) {
				safe_printf("error: breakpoint not found\n");
				break;
			}

			remove_breakpoint(bp_id);

			break;
		case 'c':
			// continue
			safe_printf("continue\n");
			exit_loop = true;
			break;
		case 'p':
		{
			// print data at specified address
			void *addr = 0;
			safe_printf("print memory at address:\n");
			safe_scanf("%p", &addr);

			if (!addr)
				break;

			// TODO: recover original bytes that are written by breakpoints
			uint8_t bytes[16] = {0};
			read_mem(bytes, addr, 16);
			safe_printf("%016lx: ", addr);
			for (size_t i = 0; i < sizeof(bytes); i++)
				safe_printf("%02x ", bytes[i]);
			safe_printf("\n");

			break;
		}
		case 'w':
		{
			// write to memory, limited to 32 bytes because im lazy
			uint8_t bytes[32] = {0};

			void *addr = 0;
			safe_printf("write at address:\n");
			safe_scanf("%p", &addr);

			if (!addr)
				break;

			int size = 0;
			safe_printf("size (max %d bytes):\n", sizeof(bytes));
			safe_scanf("%d", &size);

			if (size > (int)sizeof(bytes)) {
				size = sizeof(bytes);
				safe_scanf("too large, changing the size to %d bytes", size);
			} else if (!size) {
				break;
			}

			safe_printf("data:\n");

			for (int i = 0; i < size; i++)
				safe_scanf("%02x", bytes + i);

			// TODO: take breakpoints into consideration when writing to memory
			write_mem(addr, bytes, size);

			safe_printf("written %d bytes at %016lx: ", size, addr);
			for (int i = 0; i < size; i++)
				safe_printf("%02x ", bytes[i]);
			safe_printf("\n");

			break;
		}
		case 'd':
		{
			// disassemble single instruction at specified address
			void *addr = 0;
			safe_printf("disassemble instruction at address:\n");
			safe_scanf("%p", &addr);

			if (!addr)
				break;

			// TODO: recover original bytes that are written by breakpoints
			uint8_t bytes[16] = {0};
			read_mem(bytes, addr, 15);

			cs_insn *insn = 0;
			int count = cs_disasm(handle, bytes, 15, (size_t)addr, 1, &insn);
			if (count > 0) {
				safe_printf("%016lx: ", addr);
				for (int i = 0; i < insn[0].size; i++) {
					safe_printf(" %02x", insn[0].bytes[i]);
				}
				safe_printf("  %s %s\n", insn[0].mnemonic, insn[0].op_str);

				cs_free(insn, count);
			} else {
				safe_printf("failed to disassemble\n");
			}
			break;
		}
		case 'm':
			// print memory map
			print_maps();
			break;
		case 'q':
			// quit
			safe_printf("exit debugging\n");
			safe_exit(1);
			break;
		case 'h':
			// print help
			safe_printf("s: step over\n");
			safe_printf("i: step into\n");
			safe_printf("r: repeat step into N times\n");
			safe_printf("l: list active breakpoints\n");
			safe_printf("b: set breakpoint\n");
			safe_printf("e: remove breakpoint\n");
			safe_printf("c: continue\n");
			safe_printf("p: print memory\n");
			safe_printf("w: write memory\n");
			safe_printf("d: disassemble\n");
			safe_printf("m: print memory mappings\n");
			safe_printf("q: quit\n");
			safe_printf("h: this.\n");
		default:
			break;
		}
	}
}

// called by debuggee when it hits fake breakpoint
void breakpoint_handler(struct regs_x64 *regs)
{
	static size_t cycle = 0;
	cs_insn *insn = 0;

	// get breakpoint that hit
	int bp_id = get_breakpoint_id((void *)regs->rip, false);

	remove_breakpoint(bp_id);

	// get bytes at breakpoint
	uint8_t code[15] = {0};
	read_mem(code, (void *)regs->rip, 15);

	// disassemble and print stuff
	int count = cs_disasm(handle, code, 15, regs->rip, 1, &insn);
	if (count > 0) {
		safe_printf("breakpoint hit: %016lx (%ld cycle)", regs->rip, cycle);
		for (int i = 0; i < insn[0].size; i++) {
			safe_printf(" %02x", insn[0].bytes[i]);
		}
		safe_printf("  %s %s\n", insn[0].mnemonic, insn[0].op_str);

		// set rip_next to next instruction address, used for evaluating some expressions
		regs->rip_next = regs->rip + insn[0].size;

		cs_free(insn, count);
	} else {
		safe_printf("breakpoint hit: %016lx  ???\n", regs->rip);
		safe_printf("error: unknown instruction\n");
		safe_exit(1);
	}

	safe_printf("rax: %016lx ", regs->rax);
	safe_printf("rbx: %016lx ", regs->rbx);
	safe_printf("rcx: %016lx ", regs->rcx);
	safe_printf("rdx: %016lx\n", regs->rdx);
	safe_printf("rsi: %016lx ", regs->rsi);
	safe_printf("rdi: %016lx ", regs->rdi);
	safe_printf("rsp: %016lx ", regs->rsp);
	safe_printf("rbp: %016lx\n", regs->rbp);
	safe_printf("r8:  %016lx ", regs->r8);
	safe_printf("r9:  %016lx ", regs->r9);
	safe_printf("r10: %016lx ", regs->r10);
	safe_printf("r11: %016lx\n", regs->r11);
	safe_printf("r12: %016lx ", regs->r12);
	safe_printf("r13: %016lx ", regs->r13);
	safe_printf("r14: %016lx ", regs->r14);
	safe_printf("r15: %016lx\n", regs->r15);
	safe_printf("rip: %016lx ", regs->rip);
	safe_printf("eflags: ");
	safe_printf("%c", "C-"[!(regs->eflags & EFLAGS_CF)]);
	safe_printf("%c", "P-"[!(regs->eflags & EFLAGS_PF)]);
	safe_printf("%c", "A-"[!(regs->eflags & EFLAGS_AF)]);
	safe_printf("%c", "Z-"[!(regs->eflags & EFLAGS_ZF)]);
	safe_printf("%c", "S-"[!(regs->eflags & EFLAGS_SF)]);
	safe_printf("%c", "T-"[!(regs->eflags & EFLAGS_TF)]);
	safe_printf("%c", "I-"[!(regs->eflags & EFLAGS_IF)]);
	safe_printf("%c", "D-"[!(regs->eflags & EFLAGS_DF)]);
	safe_printf("%c\n", "O-"[!(regs->eflags & EFLAGS_OF)]);
	safe_printf("stack: %016lx %016lx %016lx %016lx\n", *(uint64_t *)regs->rsp, ((uint64_t *)regs->rsp)[1], ((uint64_t *)regs->rsp)[2], ((uint64_t *)regs->rsp)[3]);

	get_command(regs, code, bp_id);

	cycle++;
}

int dl_iterate_phdr_callback(struct dl_phdr_info *info, size_t size, void *data)
{
	(void)size; (void)data;

	// the first callback is always for the main executable, probably
	static bool is_main = true;
	if (!is_main)
		return 0;
	is_main = false;

	ElfN_Ehdr *elf = 0;
	size_t pi_addr = 0; // non zero for pie

	// find the first load segment
	// the first load segment is always pointing at base address, probably
	for (int i = 0; i < info->dlpi_phnum; i++) {
		if (info->dlpi_phdr[i].p_type == PT_LOAD) {
			pi_addr = info->dlpi_addr;
			elf = (ElfN_Ehdr *)(info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);
			break;
		}
	}

	safe_printf("base address: %p\n", (void *)elf);
	safe_printf("entry point: %p\n", (void *)(pi_addr + elf->e_entry));

	init_mmap();

	// break at entry point
	set_breakpoint((void *)(pi_addr + elf->e_entry), true);

	return 0;
}

__attribute__((constructor))
int main(int argc, char **argv)
{
	(void)argc; (void)argv;

	printf(" ----- init pseudbg -----\n");

	// pseudbg has to use own libc to avoid interference that occurs when the breakpoint is placed inside libc
	// i.e. breakpoint handler itself hits the fake breakpoint when it calls libc funcs,
	// resulting in infinity loop until it crashes
	init_libc();

	// init capstone
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
		safe_printf("error: failed to initialize capstone\n");
		safe_exit(1);
	}
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

	// tell capstone to use the pseudbg loaded libc
	cs_opt_mem setup;

	setup.malloc = safe_malloc;
	setup.calloc = safe_calloc;
	setup.realloc = safe_realloc;
	setup.free = safe_free;
	setup.vsnprintf = safe_vsnprintf;

	if (cs_option(0, CS_OPT_MEM, (size_t)&setup) != CS_ERR_OK) {
		safe_printf("error: failed to setup custom memory management functions for capstone\n");
		safe_exit(1);
	}

	// main init stuff occurs here
	dl_iterate_phdr(dl_iterate_phdr_callback, NULL);

	safe_printf(" ----- init complete -----\n");

	return 0;
}
