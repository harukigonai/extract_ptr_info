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

void bb_EVP_MD_CTX_destroy(EVP_MD_CTX * arg_a);

void EVP_MD_CTX_destroy(EVP_MD_CTX * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("EVP_MD_CTX_destroy called %lu\n", in_lib);
    if (!in_lib)
        bb_EVP_MD_CTX_destroy(arg_a);
    else {
        void (*orig_EVP_MD_CTX_destroy)(EVP_MD_CTX *);
        orig_EVP_MD_CTX_destroy = dlsym(RTLD_NEXT, "EVP_MD_CTX_destroy");
        orig_EVP_MD_CTX_destroy(arg_a);
    }
}

void bb_EVP_MD_CTX_destroy(EVP_MD_CTX * arg_a) 
{
    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 0, 0, /* 0: struct.evp_pkey_ctx_st */
            1, 8, 1, /* 3: pointer.struct.evp_pkey_ctx_st */
            	0, 0,
            1, 8, 1, /* 8: pointer.struct.env_md_ctx_st */
            	13, 0,
            0, 48, 5, /* 13: struct.env_md_ctx_st */
            	26, 0,
            	71, 8,
            	79, 24,
            	3, 32,
            	53, 40,
            1, 8, 1, /* 26: pointer.struct.env_md_st */
            	31, 0,
            0, 120, 8, /* 31: struct.env_md_st */
            	50, 24,
            	53, 32,
            	56, 40,
            	59, 48,
            	50, 56,
            	62, 64,
            	65, 72,
            	68, 112,
            64097, 8, 0, /* 50: pointer.func */
            64097, 8, 0, /* 53: pointer.func */
            64097, 8, 0, /* 56: pointer.func */
            64097, 8, 0, /* 59: pointer.func */
            64097, 8, 0, /* 62: pointer.func */
            64097, 8, 0, /* 65: pointer.func */
            64097, 8, 0, /* 68: pointer.func */
            1, 8, 1, /* 71: pointer.struct.engine_st */
            	76, 0,
            0, 0, 0, /* 76: struct.engine_st */
            0, 8, 0, /* 79: pointer.void */
        },
        .arg_entity_index = { 8, },
        .ret_entity_index = -1,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    EVP_MD_CTX * new_arg_a = *((EVP_MD_CTX * *)new_args->args[0]);

    void (*orig_EVP_MD_CTX_destroy)(EVP_MD_CTX *);
    orig_EVP_MD_CTX_destroy = dlsym(RTLD_NEXT, "EVP_MD_CTX_destroy");
    (*orig_EVP_MD_CTX_destroy)(new_arg_a);

    syscall(889);

}

