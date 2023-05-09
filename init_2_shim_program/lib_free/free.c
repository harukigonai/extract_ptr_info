#define _GNU_SOURCE

#include <stdio.h>
#include <dlfcn.h>

//static void *mallocd_regions[44096] = {0};

static void *(*trusted_free_ptr)(size_t) = NULL;

static int setting_up_untrusted_malloc = 0;

static void *(*trusted_malloc_ptr)(size_t) = NULL;
static void *(*untrusted_malloc_ptr)(size_t) = NULL;

static void trusted_free_init()
{
    trusted_free_ptr = dlsym(RTLD_NEXT, "free");
}

void *free(void *ptr)
{
    return;
    if (!trusted_free_ptr) {
        trusted_free_init();
    }

/*
    int found_ptr = 0;
    for (int i = 0; i < 4096; i++) {
        if (mallocd_regions[i] == ptr) {
            mallocd_regions[i] = 0;
            found_ptr = 1;
            break;
        }
    }

    if (!found_ptr)
        return;
*/

    int in_untrusted_lib = syscall(890);
    if (!in_untrusted_lib) { 
        trusted_free_ptr(ptr);
    } else {
        /* do nothing */
    }
}

/*
static void trusted_malloc_init()
{
    trusted_malloc_ptr = dlsym(RTLD_NEXT, "malloc");
}

static void untrusted_malloc_init()
{
    setting_up_untrusted_malloc = 1;
    void *new_libc = dlmopen(LM_ID_NEWLM, "/lib/aarch64-linux-gnu/libc.so.6", RTLD_NOW);
    untrusted_malloc_ptr = dlsym(new_libc, "malloc");
    setting_up_untrusted_malloc = 0;
}

void *malloc(size_t size)
{
    if (!trusted_malloc_ptr) {
        trusted_malloc_init();
    }
    void *res;
    
    if (!untrusted_malloc_ptr && !setting_up_untrusted_malloc) {
        untrusted_malloc_init();
    }

    int in_untrusted_lib = syscall(890);
    void *res;
    if (!in_untrusted_lib || setting_up_untrusted_malloc) {
        res = trusted_malloc_ptr(size);
    } else {
        res = untrusted_malloc_ptr(size);
    }
    
    res = trusted_malloc_ptr(size);

    for (int i = 0; i < 4096; i++) {
        if (mallocd_regions[i] == 0) {
            mallocd_regions[i] = res;
            break;
        }
    }

    return res;
}
*/

