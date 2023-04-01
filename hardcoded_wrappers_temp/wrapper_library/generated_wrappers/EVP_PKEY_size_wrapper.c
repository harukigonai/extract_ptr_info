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

int bb_EVP_PKEY_size(EVP_PKEY * arg_a);

int EVP_PKEY_size(EVP_PKEY * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("EVP_PKEY_size called %lu\n", in_lib);
    if (!in_lib)
        return bb_EVP_PKEY_size(arg_a);
    else {
        int (*orig_EVP_PKEY_size)(EVP_PKEY *);
        orig_EVP_PKEY_size = dlsym(RTLD_NEXT, "EVP_PKEY_size");
        return orig_EVP_PKEY_size(arg_a);
    }
}

int bb_EVP_PKEY_size(EVP_PKEY * arg_a) 
{
    int ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 8, 1, /* 0: struct.fnames */
            	5, 0,
            1, 8, 1, /* 5: pointer.char */
            	4096, 0,
            0, 0, 0, /* 10: func */
            4097, 32, 32, /* 13: pointer.func */
            	1, 8,
            	1, 5,
            	0, 0,
            	0, 0,
            	1, 8,
            	1, 29,
            	0, 0,
            	96, 2,
            	5, 0,
            	5, 72,
            	4097, 94396182569552,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	94416522645331, 94396182581056,
            	0, 112,
            	2, 5,
            	0, 5,
            	80, 4097,
            	23045943011, 94396182568832,
            	0, 0,
            	0, 0,
            	0, 0,
            	1, 8,
            	1, 69,
            	0, 0,
            	32, 2,
            	5, 8,
            	5, 16,
            	4097, 94396182576592,
            	94396182576192, 0,
            0, 0, 0, /* 80: Unnamed */
            0, 0, 4097, /* 83: Unnamed */
            	94416522647971, 94396182576592,
            	0, 0,
            	0, 0,
            	48, 2,
            	5, 0,
            	5, 40,
            	4097, 94396181230448,
            	94396182570176, 4097,
            	94396181673968, 193,
            	1, 8,
            	1, 109,
            	0, 0,
            	216, 13,
            	5, 0,
            	5, 8,
            	138, 16,
            	24, 24,
            	143, 32,
            	155, 40,
            	167, 48,
            	172, 56,
            	180, 64,
            	64, 160,
            	188, 184,
            	104, 200,
            	104, 208,
            	1, 8,
            	1, 48,
            	0, 1,
            	8, 1,
            	148, 0,
            	0, 72,
            	2, 5,
            	0, 5,
            	56, 1,
            	8, 1,
            	160, 0,
            	0, 32,
            	2, 5,
            	0, 5,
            	24, 1,
            	8, 1,
            	91, 0,
            	1, 8,
            	1, 177,
            	0, 0,
            	48, 0,
            	1, 8,
            	1, 185,
            	0, 0,
            	0, 0,
            	0, 16,
            	1, 193,
            	0, 1,
            	8, 1,
            	198, 0,
            	0, 32,
            	1, 203,
            	0, 0,
            	32, 1,
            	16, 8,
            	0, 0,
            	0, 4097,
            	94396182016592, 897,
            	0, 0,
            	0, 4097,
            	94416522641475, 94396181265024,
            	0, 0,
            	0, 4097,
            	96, 48,
            	4097, 94396182576192,
            	0, 4097,
            	94396181607920, 193,
            	4097, 94396182577104,
            	32, 1,
            	8, 1,
            	240, 0,
            	0, 208,
            	2, 5,
            	16, 5,
            	24, 0,
            	0, 0,
            	4097, 33,
            	94396182574544, 4097,
            	336, 48,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 94396182575680,
            	416, 0,
            	0, 0,
            	4097, 0,
            	94396181657456, 0,
            	0, 0,
            	4097, 48,
            	94416522647331, 0,
            	0, 0,
            	4097, 353,
            	94396182575200, 4097,
            	32, 48,
            	0, 8,
            	0, 4097,
            	94396181326944, 33,
            	0, 0,
            	0, 0,
            	56, 4,
            	235, 16,
            	104, 24,
            	0, 32,
            	193, 48,
            	1, 8,
            	1, 295,
            	0, 4097,
            	94396182577904, 94396182578224,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 33,
            	94396182576784, 0,
            	0, 0,
            	4097, 94396182574928,
            	94396182576352, 0,
            	0, 0,
            	4097, 94396182575680,
            	2192, 0,
            	0, 0,
            	4097, 94396182568832,
            	94396182405040, 4097,
            	94396182569056, 94396182571360,
            	4097, 0,
            	94416522647443, 0,
            	0, 0,
            	4097, 33,
            	94396182576784, 4097,
            	112, 48,
            	4097, 94396182575408,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	94416522642611, 94396182570416,
            	0, 0,
            	0, 4097,
            	94396182573600, 140425329646816,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 33,
            	94396182577584, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	94416522644948, 94396182569792,
            	0, 0,
            	0, 4097,
            	94396182569824, 94396182577104,
            	4097, 48,
            	94416522645780, 0,
            	0, 0,
            	4097, 113,
            	94396182575984, 0,
            	0, 0,
            	0, 1,
            	0, 0,
            	0, 0,
            	4097, 94396182577184,
            	272, 0,
            	0, 0,
            	4097, 94396182577792,
            	94396181434272, 4097,
            	94396182578064, 94396182576784,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 33,
            	94396182573840, 4097,
            	432, 48,
            	4097, 94396182578672,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	94416522647812, 94396182577552,
            	0, 0,
            	0, 4097,
            	94396182575600, 94396182575200,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 513,
            	94396182578816, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	94396181392992, 33,
            	0, 4,
            	0, 0,
            	0, 0,
            	4097, 94396182571280,
            	94396181834960, 0,
            	0, 0,
        },
        .arg_entity_index = { 306, },
        .ret_entity_index = 482,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    EVP_PKEY * new_arg_a = *((EVP_PKEY * *)new_args->args[0]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_EVP_PKEY_size)(EVP_PKEY *);
    orig_EVP_PKEY_size = dlsym(RTLD_NEXT, "EVP_PKEY_size");
    *new_ret_ptr = (*orig_EVP_PKEY_size)(new_arg_a);

    syscall(889);

    return ret;
}

