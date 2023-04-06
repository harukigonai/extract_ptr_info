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
    unsigned long in_lib = syscall(890);
    printf("BIO_free_all called %lu\n", in_lib);
    if (!in_lib)
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
            8884097, 8, 0, /* 0: pointer.func */
            1, 8, 1, /* 3: pointer.pointer.char */
            	8, 0,
            1, 8, 1, /* 8: pointer.char */
            	8884096, 0,
            0, 32, 1, /* 13: struct.stack_st_void */
            	18, 0,
            0, 32, 2, /* 18: struct.stack_st */
            	3, 8,
            	0, 24,
            0, 16, 1, /* 25: struct.crypto_ex_data_st */
            	30, 0,
            1, 8, 1, /* 30: pointer.struct.stack_st_void */
            	13, 0,
            1, 8, 1, /* 35: pointer.struct.bio_st */
            	40, 0,
            0, 112, 7, /* 40: struct.bio_st */
            	57, 0,
            	106, 8,
            	8, 16,
            	109, 48,
            	35, 56,
            	35, 64,
            	25, 96,
            1, 8, 1, /* 57: pointer.struct.bio_method_st */
            	62, 0,
            0, 80, 9, /* 62: struct.bio_method_st */
            	83, 8,
            	88, 16,
            	91, 24,
            	94, 32,
            	91, 40,
            	97, 48,
            	100, 56,
            	100, 64,
            	103, 72,
            1, 8, 1, /* 83: pointer.char */
            	8884096, 0,
            8884097, 8, 0, /* 88: pointer.func */
            8884097, 8, 0, /* 91: pointer.func */
            8884097, 8, 0, /* 94: pointer.func */
            8884097, 8, 0, /* 97: pointer.func */
            8884097, 8, 0, /* 100: pointer.func */
            8884097, 8, 0, /* 103: pointer.func */
            8884097, 8, 0, /* 106: pointer.func */
            0, 8, 0, /* 109: pointer.void */
            1, 8, 1, /* 112: pointer.struct.bio_st */
            	40, 0,
            0, 1, 0, /* 117: char */
        },
        .arg_entity_index = { 112, },
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

