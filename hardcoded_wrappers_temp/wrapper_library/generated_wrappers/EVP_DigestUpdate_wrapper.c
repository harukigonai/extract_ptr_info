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
            64097, 8, 0, /* 16: pointer.func */
            0, 4, 0, /* 19: int */
            64097, 8, 0, /* 22: pointer.func */
            0, 48, 5, /* 25: struct.env_md_ctx_st */
            	38, 0,
            	11, 8,
            	77, 24,
            	3, 32,
            	65, 40,
            1, 8, 1, /* 38: pointer.struct.env_md_st */
            	43, 0,
            0, 120, 8, /* 43: struct.env_md_st */
            	62, 24,
            	65, 32,
            	68, 40,
            	71, 48,
            	62, 56,
            	22, 64,
            	74, 72,
            	16, 112,
            64097, 8, 0, /* 62: pointer.func */
            64097, 8, 0, /* 65: pointer.func */
            64097, 8, 0, /* 68: pointer.func */
            64097, 8, 0, /* 71: pointer.func */
            64097, 8, 0, /* 74: pointer.func */
            0, 8, 0, /* 77: pointer.void */
            0, 0, 0, /* 80: size_t */
            1, 8, 1, /* 83: pointer.struct.env_md_ctx_st */
            	25, 0,
        },
        .arg_entity_index = { 83, 77, 80, },
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

