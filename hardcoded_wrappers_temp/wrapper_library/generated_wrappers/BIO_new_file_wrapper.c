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

BIO * bb_BIO_new_file(const char * arg_a,const char * arg_b);

BIO * BIO_new_file(const char * arg_a,const char * arg_b) 
{
    unsigned long in_lib = syscall(890);
    printf("BIO_new_file called %lu\n", in_lib);
    if (!in_lib)
        return bb_BIO_new_file(arg_a,arg_b);
    else {
        BIO * (*orig_BIO_new_file)(const char *,const char *);
        orig_BIO_new_file = dlsym(RTLD_NEXT, "BIO_new_file");
        return orig_BIO_new_file(arg_a,arg_b);
    }
}

BIO * bb_BIO_new_file(const char * arg_a,const char * arg_b) 
{
    BIO * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            8884097, 8, 0, /* 0: pointer.func */
            1, 8, 1, /* 3: pointer.pointer.char */
            	8, 0,
            1, 8, 1, /* 8: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 13: pointer.struct.bio_st */
            	18, 0,
            0, 112, 7, /* 18: struct.bio_st */
            	35, 0,
            	84, 8,
            	8, 16,
            	87, 48,
            	13, 56,
            	13, 64,
            	90, 96,
            1, 8, 1, /* 35: pointer.struct.bio_method_st */
            	40, 0,
            0, 80, 9, /* 40: struct.bio_method_st */
            	61, 8,
            	66, 16,
            	69, 24,
            	72, 32,
            	69, 40,
            	75, 48,
            	78, 56,
            	78, 64,
            	81, 72,
            1, 8, 1, /* 61: pointer.char */
            	8884096, 0,
            8884097, 8, 0, /* 66: pointer.func */
            8884097, 8, 0, /* 69: pointer.func */
            8884097, 8, 0, /* 72: pointer.func */
            8884097, 8, 0, /* 75: pointer.func */
            8884097, 8, 0, /* 78: pointer.func */
            8884097, 8, 0, /* 81: pointer.func */
            8884097, 8, 0, /* 84: pointer.func */
            0, 8, 0, /* 87: pointer.void */
            0, 16, 1, /* 90: struct.crypto_ex_data_st */
            	95, 0,
            1, 8, 1, /* 95: pointer.struct.stack_st_void */
            	100, 0,
            0, 32, 1, /* 100: struct.stack_st_void */
            	105, 0,
            0, 32, 2, /* 105: struct.stack_st */
            	3, 8,
            	0, 24,
            1, 8, 1, /* 112: pointer.struct.bio_st */
            	18, 0,
            0, 1, 0, /* 117: char */
        },
        .arg_entity_index = { 61, 61, },
        .ret_entity_index = 112,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    const char * new_arg_a = *((const char * *)new_args->args[0]);

    const char * new_arg_b = *((const char * *)new_args->args[1]);

    BIO * *new_ret_ptr = (BIO * *)new_args->ret;

    BIO * (*orig_BIO_new_file)(const char *,const char *);
    orig_BIO_new_file = dlsym(RTLD_NEXT, "BIO_new_file");
    *new_ret_ptr = (*orig_BIO_new_file)(new_arg_a,new_arg_b);

    syscall(889);

    return ret;
}

