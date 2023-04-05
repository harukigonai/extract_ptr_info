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

int bb_EVP_DigestInit_ex(EVP_MD_CTX * arg_a,const EVP_MD * arg_b,ENGINE * arg_c);

int EVP_DigestInit_ex(EVP_MD_CTX * arg_a,const EVP_MD * arg_b,ENGINE * arg_c) 
{
    unsigned long in_lib = syscall(890);
    printf("EVP_DigestInit_ex called %lu\n", in_lib);
    if (!in_lib)
        return bb_EVP_DigestInit_ex(arg_a,arg_b,arg_c);
    else {
        int (*orig_EVP_DigestInit_ex)(EVP_MD_CTX *,const EVP_MD *,ENGINE *);
        orig_EVP_DigestInit_ex = dlsym(RTLD_NEXT, "EVP_DigestInit_ex");
        return orig_EVP_DigestInit_ex(arg_a,arg_b,arg_c);
    }
}

int bb_EVP_DigestInit_ex(EVP_MD_CTX * arg_a,const EVP_MD * arg_b,ENGINE * arg_c) 
{
    int ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 0, 0, /* 0: struct.evp_pkey_ctx_st */
            1, 8, 1, /* 3: pointer.struct.evp_pkey_ctx_st */
            	0, 0,
            64097, 8, 0, /* 8: pointer.func */
            0, 4, 0, /* 11: int */
            64097, 8, 0, /* 14: pointer.func */
            1, 8, 1, /* 17: pointer.struct.engine_st */
            	22, 0,
            0, 0, 0, /* 22: struct.engine_st */
            1, 8, 1, /* 25: pointer.struct.env_md_ctx_st */
            	30, 0,
            0, 48, 5, /* 30: struct.env_md_ctx_st */
            	43, 0,
            	17, 8,
            	82, 24,
            	3, 32,
            	70, 40,
            1, 8, 1, /* 43: pointer.struct.env_md_st */
            	48, 0,
            0, 120, 8, /* 48: struct.env_md_st */
            	67, 24,
            	70, 32,
            	73, 40,
            	76, 48,
            	67, 56,
            	14, 64,
            	79, 72,
            	8, 112,
            64097, 8, 0, /* 67: pointer.func */
            64097, 8, 0, /* 70: pointer.func */
            64097, 8, 0, /* 73: pointer.func */
            64097, 8, 0, /* 76: pointer.func */
            64097, 8, 0, /* 79: pointer.func */
            0, 8, 0, /* 82: pointer.void */
        },
        .arg_entity_index = { 25, 43, 17, },
        .ret_entity_index = 11,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    EVP_MD_CTX * new_arg_a = *((EVP_MD_CTX * *)new_args->args[0]);

    const EVP_MD * new_arg_b = *((const EVP_MD * *)new_args->args[1]);

    ENGINE * new_arg_c = *((ENGINE * *)new_args->args[2]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_EVP_DigestInit_ex)(EVP_MD_CTX *,const EVP_MD *,ENGINE *);
    orig_EVP_DigestInit_ex = dlsym(RTLD_NEXT, "EVP_DigestInit_ex");
    *new_ret_ptr = (*orig_EVP_DigestInit_ex)(new_arg_a,new_arg_b,new_arg_c);

    syscall(889);

    return ret;
}

