#define _GNU_SOURCE

#include <stdio.h>
#include <dlfcn.h>

static void *(*trusted_free_ptr)(size_t) = NULL;

static void trusted_free_init()
{
    trusted_free_ptr = dlsym(RTLD_NEXT, "free");
}

void *free(void *ptr)
{
    if (!trusted_free_ptr) {
        trusted_free_init();
    }

    int in_untrusted_lib = syscall(890);
    if (!in_untrusted_lib) {
        trusted_free_ptr(ptr);
    } else {
        /* do nothing */
    }
}
