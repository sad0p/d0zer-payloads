/*
 * gcc -nostdlib -fno-stack-protector -fPIC d0zercron.c -o d0zercron
 */

#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <elf.h>
#include <linux/limits.h>


#define DEBUG
#ifdef DEBUG
	#include <stdbool.h>
	#include <stdarg.h>
	#define __UNSIGNED_INT 0xa
	#define __INT 0xb
	#define __UNSIGNED_LONG 0xc
	#define __LONG 0xd
	#define NUM_CONV_BUF_SIZE 70
	int __printf(char *format, ...);
	char *itoa(void *data_num, int base, int var_type);
	char *itoa_final(long n, int base, char *output);
#endif


#define XOR_KEY 0x890c6d01
#define PROC_SELF_EXE ".qsnb.rdmg.dyd"
#define STDOUT STDOUT_FILENO


long __open(const char *pathname, int flags, int mode);
long __write(int fd, const void *buf, size_t count);
long __read(int fd, void *buf, size_t count);
long __close(int fd);
void *__mmap(void *addr, size_t len, int prot, int flags, int fildes, off_t off);
long __munmap(void *addr, size_t len);
long __stat(const char *path, struct stat *f_info);
long __readlink(const char *path, const char *buf, size_t size);

char *get_self_path();
size_t __strlen(const char *s);
void *__malloc(size_t len);
void __strncpy(char *restrict dest, const char *src, size_t n);
void *__memset(void *s, int c, size_t n);

extern unsigned long end_vx;
void real_start();

void decrypt_xor(char *encrypted_str, char *decrypted_str);

void __attribute__((naked)) _start()
{
	real_start();
	__asm__ __volatile__("jmp end_code");
}


void real_start()
{
	int self_fd;
	uint64_t filesz = 0;
	struct stat f_info;
	char *self_path = get_self_path();
	if(!self_path)
		return;

	if((self_fd = __open(self_path, O_RDONLY,0)) < 0 )
		return;

	if(__stat(self_path, &f_info) < 0)
		return;
	/*
	__write(STDOUT, self_path, __strlen(self_path));
	__write(STDOUT, "\n", 1);
	__write(STDOUT, &f_info.st_size, );
	__write(STDOUT, "\n", 1);
	*/
	__printf("self_path = %s\n", self_path);
	__printf("f_info.st_size = %d\n", f_info.st_size);
	__munmap(self_path, PATH_MAX);
	__close(self_fd);
}

void decrypt_xor(char *encrypted_str, char *decrypted_str)
{
	char *d_ptr = decrypted_str;
	unsigned int key = XOR_KEY;

	while(*encrypted_str != '\0')
		*d_ptr++ = *encrypted_str++ ^ key;
	*d_ptr = '\0';
}

#ifdef DEBUG
int __printf(char *format, ...)
{
	char *string, *ptr, *str_integer;
	int count = 0, base = 0;


	int var_num_int;
	unsigned int var_num_u_int;

	long var_num_long;
	unsigned long var_num_u_long;

	void *var_ptr;
	int var_type;

	va_list arg;
	va_start(arg, format);

	char long_spec[] = "%l";

	for(ptr = format; *ptr != '\0'; ptr++) {
		while(*ptr != '%' && *ptr != '\0') {
			count += __write(1, ptr, 1);
			ptr++;
		}

		if(*ptr == '\0')
			break;
keep_parsing:
		ptr++;
		switch(*ptr) {
		case 'b':
			base = 2;
			goto keep_parsing;
		case 'l':
			if (*(ptr + 1) == ' ') {
				var_ptr =  &var_num_long;
				var_type = __LONG;
				*(long *)var_ptr = va_arg(arg, long);
				str_integer =  itoa(var_ptr, base, var_type);
				count += __write(STDOUT, str_integer, __strlen(str_integer));
				__munmap(str_integer, __strlen((str_integer)));
				break;
			}

			if(*(ptr + 1) == 'u' || *(ptr + 1) == 'x') {
				var_ptr = &var_num_u_long;
				goto keep_parsing;
			}

			__write(STDOUT, long_spec, 2);
			__write(STDOUT, ptr + 1, 1);
			break;

		case 'u':

			if(var_ptr == &var_num_u_long) {
				*(unsigned long *)var_ptr = va_arg(arg, unsigned long);
				var_type = __UNSIGNED_LONG;
			}else{
				var_ptr = &var_num_int;
				*(int *)var_ptr = va_arg(arg, int);
				var_type = __INT;
			}

			str_integer = itoa(var_ptr, (base == 0 ? 10 : base), var_type);
			count += __write(STDOUT, str_integer, __strlen(str_integer));
			__munmap(str_integer, __strlen((str_integer)));
			var_ptr = NULL;
			base = 0;
			break;

		case 'x':
			if(var_ptr == &var_num_u_long) {
				*(unsigned long *)var_ptr = va_arg(arg, unsigned long);
				var_type = __UNSIGNED_LONG;
			}else {
				var_ptr = &var_num_u_int;
				*(unsigned int *)var_ptr = va_arg(arg, unsigned int);
				var_type = __UNSIGNED_INT;
			}


			str_integer = itoa(var_ptr, 16, var_type);
			count += __write(STDOUT, str_integer, __strlen(str_integer));
			__munmap(str_integer, __strlen((str_integer)));
			var_ptr = NULL;
			break;

		case 'd':
			var_ptr = &var_num_int;
			*(int *)var_ptr = va_arg(arg, int);
			var_type =  __INT;
			str_integer = itoa(var_ptr,(base == 0 ? 10 : base), var_type);
			count += __write(STDOUT, str_integer, __strlen(str_integer));
			__munmap(str_integer, __strlen((str_integer)));
			var_ptr = NULL;
			base = 0;
			break;

		case 's':
			string = va_arg(arg, char *);
			count += __write(STDOUT, string, __strlen(string));
			break;
		}
	}

	return count;
}

char *itoa(void *data_num, int base, int var_type) {
	char *output = (char *)__malloc(NUM_CONV_BUF_SIZE);

	__memset(output, 0, NUM_CONV_BUF_SIZE);

	if(var_type == __UNSIGNED_INT)
		return itoa_final(*(unsigned int *)data_num, base, output);
	if(var_type == __INT)
		return itoa_final(*(int *)data_num, base, output);
	if(var_type == __UNSIGNED_LONG)
		return itoa_final(*(unsigned long *)data_num, base, output);
	else
		return itoa_final(*(long *)data_num, base, output);
}

char *itoa_final(long n, int base, char *output) {
	char buf[NUM_CONV_BUF_SIZE];
	char conv[] = "0123456789abcdef";
	char hex_symbol[] = "0x";
	bool neg = false;
	int index = 0;
	char *ptr;

	if (n < 0) {
		neg = true;
		n = -(n);
	}

	while(n >= base) {
		buf[index++] = conv[n % base];
		n = n / base;
	}

	buf[index++] = conv[n % base];
	buf[index] = '\0';

	ptr = output;
	if(neg)
		*(ptr++) = '-';

	if(base == 16) {
		__strncpy(ptr, hex_symbol, 2);
		ptr += 2;
	}

	if(base == 8)
		*(ptr++) = 'o';

	for(int i = index - 1; i >= 0 && ptr < (output + NUM_CONV_BUF_SIZE - 1); i--, ptr++) {
		*ptr = buf[i];
	}

	*ptr = '\0';
	return output;
}
#endif

size_t __strlen(const char *s)
{
	size_t len = 0;
	while(*s++ != '\0')
		len++;

	return len;
}

void *__malloc(size_t len)
{
	void *mem;
	mem = __mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	return mem;
}

void __strncpy(char *restrict dest, const char *src, size_t n)
{
	while(n-- && *src != '\0')
		*dest++ = *src++;
	*dest  = '\0';
}

void *__memset(void *s, int c, size_t n)
{
	uint8_t *ptr = (uint8_t *)s;
	while(n--)
		*ptr++ = c & 0xff;

	return s;
}

char *get_self_path()
{
	size_t path_len;
	char encrypted_proc_slash_self_exe[] = PROC_SELF_EXE;
	char *proc_slash_self_exe = __malloc(__strlen(encrypted_proc_slash_self_exe));
	char *self_path_buf = __malloc(PATH_MAX);

	if(self_path_buf) {
		decrypt_xor(encrypted_proc_slash_self_exe, proc_slash_self_exe);
		path_len = __readlink(proc_slash_self_exe, self_path_buf, PATH_MAX);
		self_path_buf[path_len] = '\0';
	}

	return self_path_buf;
}

#define __load_syscall_ret(var) __asm__ __volatile__ ("mov %%rax, %0" : "=r" (var));

#define __open_syscall(type, name, arg1, arg1_type, arg2, arg2_type, arg3, arg3_type) \
        type name(arg1_type arg1, arg2_type arg2, arg3_type arg3) \
		{ \
                type ret; \
                __asm__ __volatile__(\
                                "movq $2, %%rax\n" \
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

#define __write_syscall(type, name, arg1, arg1_type, arg2, arg2_type, arg3, arg3_type) \
	type name(arg1_type arg1, arg2_type arg2, arg3_type arg3) \
	{ \
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

#define __read_syscall(type, name, arg1, arg1_type, arg2, arg2_type, arg3, arg3_type) \
	type name(arg1_type arg1, arg2_type arg2, arg3_type arg3) \
	{ \
		type ret; \
		__asm__ __volatile__ (\
				"movq $0, %%rax\n" \
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

#define __close_syscall(type, name, arg1, arg1_type) \
        type name(arg1_type arg1) \
		{ \
                type ret; \
                __asm__ __volatile__(\
                                "movq $3, %%rax\n" \
                                "movq %0, %%rdi\n" \
                                "syscall" \
                                        : \
                                        : "g" (arg1) \
                                        : "%rax", "%rdi" \
                ); \
                __load_syscall_ret(ret); \
                return ret; \
        }

#define __mmap_syscall(type, name, arg1, arg1_type, arg2,  arg2_type, arg3, arg3_type, arg4, arg4_type, arg5, arg5_type, arg6, arg6_type) \
        type name(arg1_type arg1, arg2_type arg2, arg3_type arg3, arg4_type arg4, arg5_type arg5, arg6_type arg6) \
		{ \
                type ret; \
                __asm__ __volatile__(\
                                "movq $9, %%rax\n" \
                                "movq %0, %%rdi\n" \
                                "movq %1, %%rsi\n" \
                                "movq %2, %%rdx\n" \
                                "movq %3, %%r10\n" \
                                "movq %4, %%r8\n" \
                                "movq %5, %%r9\n" \
                                "syscall" \
                                        : \
                                        : "g" (arg1), "g" (arg2), "g" (arg3), "g" (arg4), "g" (arg5), "g" (arg6) \
                                        : "%rax", "%rdi", "%rsi", "%rdx", "%r10", "%r8", "%r9" \
                ); \
                __load_syscall_ret(ret); \
                return ret; \
        }

#define __munmap_syscall(type, name, arg1, arg1_type, arg2, arg2_type) \
        type name(arg1_type arg1, arg2_type arg2) \
		{ \
                type ret; \
                __asm__ __volatile__(\
                                "movq $11, %%rax\n" \
                                "movq %0, %%rdi\n" \
                                "movq %1, %%rsi\n" \
                                "syscall" \
                                        : \
                                        : "g" (arg1), "g" (arg2) \
                                        : "%rax", "%rdi", "%rsi" \
                ); \
                __load_syscall_ret(ret); \
                return ret; \
        }

#define __stat_syscall(type, name, arg1, arg1_type, arg2, arg2_type) \
        type name(arg1_type arg1, arg2_type arg2) { \
                type ret; \
                __asm__ __volatile__(\
                                "movq $4, %%rax\n" \
                                "movq %0, %%rdi\n" \
                                "movq %1, %%rsi\n" \
                                "syscall" \
                                        : \
                                        : "g" (arg1), "g" (arg2) \
                                        : "%rax", "%rdi", "%rsi" \
                ); \
                __load_syscall_ret(ret); \
                return ret; \
        }

#define __readlink_syscall(type, name, arg1, arg1_type, arg2, arg2_type, arg3, arg3_type) \
		type name(arg1_type arg1, arg2_type arg2, arg3_type arg3) { \
                type ret; \
                __asm__ __volatile__( \
                "movq $89, %%rax\n" \
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

__open_syscall(long, __open, pathname, const char *, flags, int, mode, int);
__write_syscall(long, __write, fd, int, buf, const void *, count, size_t);
__read_syscall(long, __read, fd, int, buf, void *, count, size_t);
__close_syscall(long, __close, fd, int);
__mmap_syscall(void *, __mmap, addr, void *, len, size_t, prot, int, flags, int, fildes, int, off, off_t);
__munmap_syscall(long, __munmap, addr, void *, len, size_t);
__stat_syscall(long, __stat, path, const char *, f_info, struct stat *);
__readlink_syscall(long, __readlink, pathname, const char *restrict, buf, const char *restrict, size, size_t);




/*
 * No additional code beyond end_code(), d0zer appends a restoration stub here, unless you handle restoration
 * (transfering execution back to the non-parasitic code) with -noRestoration flag in d0zer.
 */
__attribute__((naked)) void end_code() {}