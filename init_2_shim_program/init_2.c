#include <unistd.h>
#include <sys/auxv.h>

int main(void) {
        syscall(543);
        syscall(666, getauxval(AT_SYSINFO_EHDR) - sysconf(_SC_PAGESIZE));
        syscall(777);

	char *argv[] = { "/root/apache/bin/apachectl", "-D", "FOREGROUND", 0 };
	char *envp[] = {
		"LD_PRELOAD=/root/extract_ptr_info/hardcoded_wrappers_temp/wrapper_library/libssl_wrapper.so",
		"LD_LIBRARY_PATH=/opt/openssl/lib",
	     	0
	};
        execve(argv[0], argv, envp);
}
