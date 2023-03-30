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

void bb_BIO_free_all(BIO * arg_a);

void BIO_free_all(BIO * arg_a) 
{
    printf("BIO_free_all called\n");
    if (!syscall(890))
        bb_BIO_free_all(arg_a);
    else {
        void (*orig_BIO_free_all)(BIO *);
        orig_BIO_free_all = dlsym(RTLD_NEXT, "BIO_free_all");
        orig_BIO_free_all(arg_a);
    }
}

void bb_BIO_free_all(BIO * arg_a) 
{
    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 32, 1, /* 0: struct.stack_st */
            	5, 8,
            1, 8, 1, /* 5: pointer.pointer.char */
            	10, 0,
            1, 8, 1, /* 10: pointer.char */
            	15, 0,
            0, 1, 0, /* 15: char */
            0, 32, 1, /* 18: struct.stack_st_OPENSSL_STRING */
            	0, 0,
            0, 16, 1, /* 23: struct.crypto_ex_data_st */
            	28, 0,
            1, 8, 1, /* 28: pointer.struct.stack_st_OPENSSL_STRING */
            	18, 0,
            0, 8, 0, /* 33: pointer.func */
            0, 8, 0, /* 36: long */
            0, 0, 0, /* 39: func */
            0, 0, 0, /* 42: func */
            0, 0, 0, /* 45: func */
            1, 8, 1, /* 48: pointer.struct.bio_st */
            	53, 0,
            0, 112, 6, /* 53: struct.bio_st */
            	68, 0,
            	10, 16,
            	10, 48,
            	48, 56,
            	48, 64,
            	23, 96,
            1, 8, 1, /* 68: pointer.struct.bio_method_st */
            	73, 0,
            0, 80, 1, /* 73: struct.bio_method_st */
            	10, 8,
            0, 0, 0, /* 78: func */
            0, 0, 0, /* 81: func */
            0, 8, 0, /* 84: pointer.func */
            0, 8, 0, /* 87: pointer.func */
            0, 8, 0, /* 90: pointer.func */
            0, 4, 0, /* 93: int */
            0, 8, 0, /* 96: pointer.func */
            0, 0, 0, /* 99: func */
            0, 8, 0, /* 102: pointer.func */
            0, 0, 0, /* 105: func */
            0, 8, 0, /* 108: pointer.func */
        },
        .arg_entity_index = { 48, },
        .ret_entity_index = -1,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    BIO * new_arg_a = *((BIO * *)new_args->args[0]);

    void (*orig_BIO_free_all)(BIO *);
    orig_BIO_free_all = dlsym(RTLD_NEXT, "BIO_free_all");
    (*orig_BIO_free_all)(new_arg_a);

    syscall(889);

}

