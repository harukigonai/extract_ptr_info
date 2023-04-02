#define _GNU_SOURCE

#include <stdio.h>
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

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 8, 0, /* 0: pointer.void */
            0, 4, 0, /* 3: int */
            0, 1, 0, /* 6: char */
            0, 8, 1, /* 9: pointer.char */
            	4096, 0,
        },
        .arg_entity_index = { 3, },
        .ret_entity_index = 9,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    int new_arg_a = *((int *)new_args->args[0]);

    const char * *new_ret_ptr = (const char * *)new_args->ret;

    const char * (*orig_SSLeay_version)(int);
    orig_SSLeay_version = dlsym(RTLD_NEXT, "SSLeay_version");
    *new_ret_ptr = (*orig_SSLeay_version)(new_arg_a);

    syscall(889);

    return ret;
}

