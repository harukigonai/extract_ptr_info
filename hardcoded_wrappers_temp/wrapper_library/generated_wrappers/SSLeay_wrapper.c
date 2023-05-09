#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
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

unsigned long bb_SSLeay(void);

unsigned long SSLeay(void) 
{
    unsigned long in_lib = syscall(890);
    printf("SSLeay called %lu\n", in_lib);
    if (!in_lib)
        return bb_SSLeay();
    else {
        unsigned long (*orig_SSLeay)(void);
        orig_SSLeay = dlsym(RTLD_NEXT, "SSLeay");
        return orig_SSLeay();
    }
}

unsigned long bb_SSLeay(void) 
{
    unsigned long ret;

    struct lib_enter_args *args_addr = malloc(sizeof(struct lib_enter_args));
    memset(args_addr, 0, sizeof(struct lib_enter_args));
    args_addr->num_args = 0;
    uint32_t *em = args_addr->entity_metadata;
    em[0] = 0; em[1] = 8; em[2] = 0; /* 0: long unsigned int */
    args_addr->ret_entity_index = 0;
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    unsigned long *new_ret_ptr = (unsigned long *)new_args->ret;

    unsigned long (*orig_SSLeay)(void);
    orig_SSLeay = dlsym(RTLD_NEXT, "SSLeay");
    *new_ret_ptr = (*orig_SSLeay)();

    syscall(889);

    free(args_addr);

    return ret;
}

