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

EVP_MD_CTX * bb_EVP_MD_CTX_create(void);

EVP_MD_CTX * EVP_MD_CTX_create(void) 
{
    unsigned long in_lib = syscall(890);
    printf("EVP_MD_CTX_create called %lu\n", in_lib);
    if (!in_lib)
        return bb_EVP_MD_CTX_create();
    else {
        EVP_MD_CTX * (*orig_EVP_MD_CTX_create)(void);
        orig_EVP_MD_CTX_create = dlsym(RTLD_NEXT, "EVP_MD_CTX_create");
        return orig_EVP_MD_CTX_create();
    }
}

EVP_MD_CTX * bb_EVP_MD_CTX_create(void) 
{
    EVP_MD_CTX * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 0, 0, /* 0: struct.evp_pkey_ctx_st */
            1, 8, 1, /* 3: pointer.struct.evp_pkey_ctx_st */
            	0, 0,
            0, 8, 0, /* 8: pointer.void */
            1, 8, 1, /* 11: pointer.struct.env_md_ctx_st */
            	16, 0,
            0, 48, 5, /* 16: struct.env_md_ctx_st */
            	29, 0,
            	74, 8,
            	8, 24,
            	3, 32,
            	56, 40,
            1, 8, 1, /* 29: pointer.struct.env_md_st */
            	34, 0,
            0, 120, 8, /* 34: struct.env_md_st */
            	53, 24,
            	56, 32,
            	59, 40,
            	62, 48,
            	53, 56,
            	65, 64,
            	68, 72,
            	71, 112,
            8884097, 8, 0, /* 53: pointer.func */
            8884097, 8, 0, /* 56: pointer.func */
            8884097, 8, 0, /* 59: pointer.func */
            8884097, 8, 0, /* 62: pointer.func */
            8884097, 8, 0, /* 65: pointer.func */
            8884097, 8, 0, /* 68: pointer.func */
            8884097, 8, 0, /* 71: pointer.func */
            1, 8, 1, /* 74: pointer.struct.engine_st */
            	79, 0,
            0, 0, 0, /* 79: struct.engine_st */
        },
        .arg_entity_index = { -1 },
        .ret_entity_index = 11,
    };
    struct lib_enter_args *args_addr = &args;
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    EVP_MD_CTX * *new_ret_ptr = (EVP_MD_CTX * *)new_args->ret;

    EVP_MD_CTX * (*orig_EVP_MD_CTX_create)(void);
    orig_EVP_MD_CTX_create = dlsym(RTLD_NEXT, "EVP_MD_CTX_create");
    *new_ret_ptr = (*orig_EVP_MD_CTX_create)();

    syscall(889);

    return ret;
}

