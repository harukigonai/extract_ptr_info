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

const char * bb_SSLeay_version(int arg_a);

const char * SSLeay_version(int arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("SSLeay_version called %lu\n", in_lib);
    if (!in_lib)
        return bb_SSLeay_version(arg_a);
    else {
        const char * (*orig_SSLeay_version)(int);
        orig_SSLeay_version = dlsym(RTLD_NEXT, "SSLeay_version");
        return orig_SSLeay_version(arg_a);
    }
}

const char * bb_SSLeay_version(int arg_a) 
{
    const char * ret;

    struct lib_enter_args *args_addr = malloc(sizeof(struct lib_enter_args));
    args_addr->num_args = 0;
    uint32_t *em = args_addr->entity_metadata;
    em[0] = 1; em[1] = 8; em[2] = 1; /* 0: pointer.char */
    	em[3] = 8884096; em[4] = 0; 
    em[5] = 0; em[6] = 1; em[7] = 0; /* 5: char */
    em[8] = 0; em[9] = 4; em[10] = 0; /* 8: int */
    args_addr->arg_entity_index[0] = 8;
    args_addr->ret_entity_index = 0;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    int new_arg_a = *((int *)new_args->args[0]);

    const char * *new_ret_ptr = (const char * *)new_args->ret;

    const char * (*orig_SSLeay_version)(int);
    orig_SSLeay_version = dlsym(RTLD_NEXT, "SSLeay_version");
    *new_ret_ptr = (*orig_SSLeay_version)(new_arg_a);

    syscall(889);

    free(args_addr);

    return ret;
}

