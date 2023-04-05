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
            8884097, 8, 0, /* 0: pointer.func */
            8884097, 8, 0, /* 3: pointer.func */
            8884097, 8, 0, /* 6: pointer.func */
            8884097, 8, 0, /* 9: pointer.func */
            8884097, 8, 0, /* 12: pointer.func */
            0, 1, 0, /* 15: char */
            8884097, 8, 0, /* 18: pointer.func */
            1, 8, 1, /* 21: pointer.char */
            	8884096, 0,
            0, 80, 9, /* 26: struct.bio_method_st */
            	21, 8,
            	12, 16,
            	9, 24,
            	6, 32,
            	9, 40,
            	18, 48,
            	0, 56,
            	0, 64,
            	3, 72,
            1, 8, 1, /* 47: pointer.struct.bio_method_st */
            	26, 0,
        },
        .arg_entity_index = { -1 },
        .ret_entity_index = 47,
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

