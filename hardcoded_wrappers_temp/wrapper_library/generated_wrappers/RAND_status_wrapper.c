#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/ui.h>
#include <openssl/safestack.h>
#include <openssl/ssl.h>
#include <openssl/e_os2.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/x509v3.h>
#include <openssl/ocsp.h>
#include <openssl/srp.h>

#include "../arg_struct.h"

int bb_RAND_status(void);

int RAND_status(void) 
{
    unsigned long in_lib = syscall(890);
    printf("RAND_status called %lu\n", in_lib);
    if (!in_lib)
        return bb_RAND_status();
    else {
        int (*orig_RAND_status)(void);
        orig_RAND_status = dlsym(RTLD_NEXT, "RAND_status");
        return orig_RAND_status();
    }
}

int bb_RAND_status(void) 
{
    int ret;

    struct lib_enter_args *args_addr = malloc(sizeof(struct lib_enter_args));
    args_addr->num_args = 0;
    uint32_t *em = args_addr->entity_metadata;
    em[0] = 0; em[1] = 4; em[2] = 0; /* 0: int */
    args_addr->ret_entity_index = 0;
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_RAND_status)(void);
    orig_RAND_status = dlsym(RTLD_NEXT, "RAND_status");
    *new_ret_ptr = (*orig_RAND_status)();

    syscall(889);

    free(args_addr);

    return ret;
}

