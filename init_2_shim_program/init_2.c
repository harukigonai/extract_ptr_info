#include <unistd.h>
#include <sys/auxv.h>

int main(void) {
	syscall(543);
	syscall(666, getauxval(AT_SYSINFO_EHDR) - sysconf(_SC_PAGESIZE));
	syscall(777);

	syscall(891, "/root/extract_ptr_info/hardcoded_wrappers_temp/wrapper_library/libssl_wrapper.so",
			2,
			"/opt/openssl/lib/libcrypto.so.1.0.0",
			"/opt/openssl/lib/libssl.so.1.0.0");

	char *argv[] = { "/root/apache/bin/apachectl", "-X", "-D", "FOREGROUND", 0 };
	char *envp[] = {
		"LD_PRELOAD=/root/extract_ptr_info/hardcoded_wrappers_temp/wrapper_library/libssl_wrapper.so ./lib_free/libfree.so",
		"LD_LIBRARY_PATH=/opt/openssl/lib",
		"MALLOC_MMAP_THRESHOLD=0",
		0
	};
	execve(argv[0], argv, envp);
}
