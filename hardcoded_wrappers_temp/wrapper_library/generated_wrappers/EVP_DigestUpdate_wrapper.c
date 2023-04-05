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

int bb_EVP_DigestUpdate(EVP_MD_CTX * arg_a, const void * arg_b,size_t arg_c);

int EVP_DigestUpdate(EVP_MD_CTX * arg_a, const void * arg_b,size_t arg_c) 
{
    unsigned long in_lib = syscall(890);
    printf("EVP_DigestUpdate called %lu\n", in_lib);
    if (!in_lib)
        return bb_EVP_DigestUpdate(arg_a,arg_b,arg_c);
    else {
        int (*orig_EVP_DigestUpdate)(EVP_MD_CTX *, const void *,size_t);
        orig_EVP_DigestUpdate = dlsym(RTLD_NEXT, "EVP_DigestUpdate");
        return orig_EVP_DigestUpdate(arg_a,arg_b,arg_c);
    }
}

int bb_EVP_DigestUpdate(EVP_MD_CTX * arg_a, const void * arg_b,size_t arg_c) 
{
    int ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 0, 0, /* 0: struct.evp_pkey_ctx_st */
            1, 8, 1, /* 3: pointer.struct.evp_pkey_ctx_st */
            	0, 0,
            0, 0, 0, /* 8: struct.engine_st */
            1, 8, 1, /* 11: pointer.struct.engine_st */
            	8, 0,
            4097, 8, 0, /* 16: pointer.func */
            0, 4, 0, /* 19: int */
            4097, 8, 0, /* 22: pointer.func */
            0, 8, 0, /* 25: pointer.void */
            1, 8, 1, /* 28: pointer.struct.env_md_ctx_st */
            	33, 0,
            0, 48, 5, /* 33: struct.env_md_ctx_st */
            	46, 0,
            	11, 8,
            	25, 24,
            	3, 32,
            	73, 40,
            1, 8, 1, /* 46: pointer.struct.env_md_st */
            	51, 0,
            0, 120, 8, /* 51: struct.env_md_st */
            	70, 24,
            	73, 32,
            	76, 40,
            	79, 48,
            	70, 56,
            	22, 64,
            	82, 72,
            	16, 112,
            4097, 8, 0, /* 70: pointer.func */
            4097, 8, 0, /* 73: pointer.func */
            4097, 8, 0, /* 76: pointer.func */
            4097, 8, 0, /* 79: pointer.func */
            4097, 8, 0, /* 82: pointer.func */
            0, 0, 0, /* 85: size_t */
        },
        .arg_entity_index = { 28, 25, 85, },
        .ret_entity_index = 19,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    EVP_MD_CTX * new_arg_a = *((EVP_MD_CTX * *)new_args->args[0]);

     const void * new_arg_b = *(( const void * *)new_args->args[1]);

    size_t new_arg_c = *((size_t *)new_args->args[2]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_EVP_DigestUpdate)(EVP_MD_CTX *, const void *,size_t);
    orig_EVP_DigestUpdate = dlsym(RTLD_NEXT, "EVP_DigestUpdate");
    *new_ret_ptr = (*orig_EVP_DigestUpdate)(new_arg_a,new_arg_b,new_arg_c);

    syscall(889);

    return ret;
}

