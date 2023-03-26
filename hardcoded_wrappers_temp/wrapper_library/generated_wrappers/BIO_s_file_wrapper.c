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

BIO_METHOD * BIO_s_file(void) 
{
    BIO_METHOD * ret;

    struct lib_enter_args args = {
        .entity_metadata = {
            0, 0, 0, /* 0: func */
            0, 80, 10, /* 3: struct.bio_method_st */
            	26, 0,
            	29, 8,
            	37, 16,
            	37, 24,
            	45, 32,
            	37, 40,
            	53, 48,
            	61, 56,
            	61, 64,
            	69, 72,
            0, 4, 0, /* 26: int */
            1, 8, 1, /* 29: pointer.char */
            	34, 0,
            0, 1, 0, /* 34: char */
            1, 8, 1, /* 37: pointer.func */
            	42, 0,
            0, 0, 0, /* 42: func */
            1, 8, 1, /* 45: pointer.func */
            	50, 0,
            0, 0, 0, /* 50: func */
            1, 8, 1, /* 53: pointer.func */
            	58, 0,
            0, 0, 0, /* 58: func */
            1, 8, 1, /* 61: pointer.func */
            	66, 0,
            0, 0, 0, /* 66: func */
            1, 8, 1, /* 69: pointer.func */
            	0, 0,
            1, 8, 1, /* 74: pointer.struct.bio_method_st */
            	3, 0,
        },
        .arg_entity_index = { -1 },
        .ret_entity_index = 74,
    };
    struct lib_enter_args *args_addr = &args;
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    BIO_METHOD * *new_ret_ptr = (BIO_METHOD * *)new_args->ret;

    BIO_METHOD * (*orig_BIO_s_file)(void);
    orig_BIO_s_file = dlsym(RTLD_NEXT, "BIO_s_file");
    *new_ret_ptr = (*orig_BIO_s_file)();

    syscall(889);

    return ret;
}

