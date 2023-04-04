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

BIO_METHOD * bb_BIO_s_file(void);

BIO_METHOD * BIO_s_file(void) 
{
    unsigned long in_lib = syscall(890);
    printf("BIO_s_file called %lu\n", in_lib);
    if (!in_lib)
        return bb_BIO_s_file();
    else {
        BIO_METHOD * (*orig_BIO_s_file)(void);
        orig_BIO_s_file = dlsym(RTLD_NEXT, "BIO_s_file");
        return orig_BIO_s_file();
    }
}

BIO_METHOD * bb_BIO_s_file(void) 
{
    BIO_METHOD * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            4097, 8, 0, /* 0: pointer.func */
            4097, 8, 0, /* 3: pointer.func */
            4097, 8, 0, /* 6: pointer.func */
            4097, 8, 0, /* 9: pointer.func */
            0, 1, 0, /* 12: char */
            1, 8, 1, /* 15: pointer.char */
            	4096, 0,
            4097, 8, 0, /* 20: pointer.func */
            0, 80, 9, /* 23: struct.bio_method_st */
            	15, 8,
            	9, 16,
            	9, 24,
            	20, 32,
            	9, 40,
            	6, 48,
            	3, 56,
            	3, 64,
            	0, 72,
            1, 8, 1, /* 44: pointer.struct.bio_method_st */
            	23, 0,
            0, 8, 0, /* 49: pointer.void */
        },
        .arg_entity_index = { -1 },
        .ret_entity_index = 44,
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

