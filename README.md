# pseudbg
A shitty linux x64 debugger-ish thing that does not use ptrace and int3 breakpoint.

Turn any application into a self-debugging program and debug them without using an external debugger.

This shit is made as a joke/PoC and not intended to be used for any practical in the slightest possible way.
It is also written in an insecure way (mapping stuff to predictable address and etc),
so never use this for important stuff!

## Demo

https://asciinema.org/a/3uYUTIqCJRp5gBLynbLSL0zdg

## How it works

pseudbg is a shared library that uses LD_PRELOAD to inject itself into the debug target application.

Since pseudbg is not a debugger, it is designed to not use ptrace and int3 breakpoint.
Instead, pseudbg uses jmp instruction as a breakpoint which will redirect the execution to the breakpoint handler.

To step over/into instructions, it simply moves the jmp instruction
to the next instruction that are going to be executed. This jmp instruction is written to the entry point at startup
so the debugging begins immediately as soon as the control flow is passed to the program.

## Build

Nothing special, just:

```bash
make
```

Depencendy: `capstone`

## Usage

### Debug a program

```bash
LD_PRELOAD=./pseudbg.so <program-to-debug>
```

### Commands

The following commands can be used when a breakpoint is hit:

```
s: step over
i: step into
r: repeat step into N times
l: list active breakpoints
b: set breakpoint
e: remove breakpoint
c: continue
p: print memory
w: write memory
d: disassemble
m: print memory mappings
q: quit
h: this.
```

Press `h` to show this commands.


## Bugs and limitations

### Cannot attach to an active process

By design, pseudbg has to use LD_PRELOAD to inject the library into a process.
Using ptrace to inject the library would make pseudbg become a debugger, which it is not supposed to be!

AFAIK, there is no way to inject a shared library to an active process.

### Cannot pause the execution to debug current instruction

pseudbg runs inside the program and can therefore not be paused because it will stop the pseudbg as well.
Technically it should be possible to do this by registering a SIGINT handler, but pseudbg is not a debugger so no.

### Not thread-safe

pseudbg is not designed with thread/fork/knife/spoon in consideration,
and should not work with applications that uses any of them.

### Breakpoint disappears when it is hit

It's a feature.

The breakpoint disappears because it has to be able to execute the instruction.

In a real debugger, this is done in the following steps:
 * A breakpoint is hit
 * Disable the breakpoint
 * Perform a single step using trap flag
 * Re-enable the breakpoint
 * Resume the execution

For pseudbg, this becomes more complicated because:
 * pseudbg is not a debugger, so trap flag (and SIGTRAP handler) cannot be used
 * A breakpoint is 5/7 bytes long, requirng multiple "single-step"
(depending on what instructions are behind the breakpoint) before it can re-enable the breakpoint.

these makes it painful to implement breakpoint properly without introducing any bugs

### Repeating step into never ends/freezes

Not sure why but some libc version and some libc functions do not seem to like pseudbg,
so avoid digging deep into libc.

### Stdin/stdout dependant

pseudbg uses the program's stdin/stdout and will therefore not work for daemons and programs that closes stdin/stdout.
For similar reason, pipe and redirection becomes messy when using pseudbg.

### It crashes

It's a feature.

If the debuggee program (or pseudbg) causes segfault and other shits, then there is no
way for pseudbg to prevent the program from dying. SIGSEGV handler could be used to prevent
but that sounds like a debugger, which pseudbg is definitely not.

### It prints only one instruction at once

I'm too lazy to write the loop.
