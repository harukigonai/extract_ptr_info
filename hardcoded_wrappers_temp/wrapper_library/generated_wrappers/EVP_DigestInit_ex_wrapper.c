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

int bb_EVP_DigestInit_ex(EVP_MD_CTX * arg_a,const EVP_MD * arg_b,ENGINE * arg_c);

int EVP_DigestInit_ex(EVP_MD_CTX * arg_a,const EVP_MD * arg_b,ENGINE * arg_c) 
{
    unsigned long in_lib = syscall(890);
    printf("EVP_DigestInit_ex called %lu\n", in_lib);
    if (!in_lib)
        return bb_EVP_DigestInit_ex(arg_a,arg_b,arg_c);
    else {
        int (*orig_EVP_DigestInit_ex)(EVP_MD_CTX *,const EVP_MD *,ENGINE *);
        orig_EVP_DigestInit_ex = dlsym(RTLD_NEXT, "EVP_DigestInit_ex");
        return orig_EVP_DigestInit_ex(arg_a,arg_b,arg_c);
    }
}

int bb_EVP_DigestInit_ex(EVP_MD_CTX * arg_a,const EVP_MD * arg_b,ENGINE * arg_c) 
{
    int ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            1, 8, 1, /* 0: pointer.int */
            	5, 0,
            0, 4, 0, /* 5: int */
            0, 8, 1, /* 8: struct.fnames */
            	13, 0,
            1, 8, 1, /* 13: pointer.char */
            	4096, 0,
            4097, 193, 94396174867872, /* 18: pointer.func */
            	4097, 0,
            	161, 0,
            	0, 0,
            	4097, 94396174864080,
            	94396174866672, 0,
            	0, 0,
            	4097, 0,
            	65, 4097,
            	94396174866672, 0,
            	4097, 94396174864656,
            	94396174864784, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	33, 94396174865264,
            	0, 0,
            	0, 0,
            	56, 4,
            	71, 16,
            	93, 24,
            	8, 32,
            	220, 48,
            	1, 8,
            	1, 76,
            	0, 0,
            	208, 3,
            	13, 16,
            	13, 24,
            	85, 32,
            	1, 8,
            	1, 90,
            	0, 0,
            	0, 0,
            	1, 8,
            	1, 98,
            	0, 0,
            	216, 13,
            	13, 0,
            	13, 8,
            	127, 16,
            	139, 24,
            	151, 32,
            	163, 40,
            	175, 48,
            	187, 56,
            	195, 64,
            	203, 160,
            	215, 184,
            	93, 200,
            	93, 208,
            	1, 8,
            	1, 132,
            	0, 0,
            	112, 2,
            	13, 0,
            	13, 80,
            	1, 8,
            	1, 144,
            	0, 0,
            	96, 2,
            	13, 0,
            	13, 72,
            	1, 8,
            	1, 156,
            	0, 0,
            	72, 2,
            	13, 0,
            	13, 56,
            	1, 8,
            	1, 168,
            	0, 0,
            	32, 2,
            	13, 0,
            	13, 24,
            	1, 8,
            	1, 180,
            	0, 0,
            	48, 2,
            	13, 0,
            	13, 40,
            	1, 8,
            	1, 192,
            	0, 0,
            	48, 0,
            	1, 8,
            	1, 200,
            	0, 0,
            	0, 0,
            	1, 8,
            	1, 208,
            	0, 0,
            	32, 2,
            	13, 8,
            	13, 16,
            	0, 16,
            	1, 220,
            	0, 1,
            	8, 1,
            	225, 0,
            	0, 32,
            	1, 230,
            	0, 0,
            	32, 1,
            	235, 8,
            	1, 8,
            	1, 13,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	32, 94416532252889,
            	0, 0,
            	0, 4097,
            	94396174863856, 32,
            	0, 0,
            	0, 4097,
            	32, 94416532253273,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 0,
            	33, 4097,
            	140425329646816, 128,
            	0, 0,
            	0, 4097,
            	33, 94396174866128,
            	4097, 448,
            	32, 0,
            	0, 0,
            	4097, 94396174865072,
            	94396174871856, 0,
            	0, 0,
            	4097, 1,
            	33, 4097,
            	140425329646816, 576,
            	4097, 94416532245625,
            	94396174402832, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	94396174864464, 0,
            	0, 0,
            	0, 1,
            	8, 1,
            	323, 0,
            	0, 48,
            	4, 334,
            	0, 93,
            	8, 13,
            	24, 342,
            	32, 1,
            	8, 1,
            	339, 0,
            	0, 120,
            	0, 1,
            	8, 1,
            	347, 0,
            	0, 80,
            	8, 366,
            	0, 93,
            	8, 392,
            	16, 392,
            	24, 13,
            	40, 13,
            	48, 85,
            	56, 0,
            	64, 1,
            	8, 1,
            	371, 0,
            	0, 208,
            	9, 85,
            	8, 85,
            	32, 85,
            	48, 85,
            	64, 85,
            	80, 85,
            	96, 85,
            	144, 85,
            	160, 85,
            	176, 1,
            	8, 1,
            	60, 0,
            	4097, 0,
            	33, 4097,
            	140425329646816, 1824,
            	4097, 94416532242921,
            	94396173110768, 4097,
            	48, 94416532244761,
            	0, 0,
            	0, 4097,
            	225, 94396174872576,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 94396173379088,
            	145, 0,
            	0, 0,
            	4097, 94396174872176,
            	94396174867520, 4097,
            	32, 94416532253241,
            	0, 0,
            	0, 4097,
            	94396174871104, 94396174858800,
            	4097, 3536,
            	48, 4097,
            	94396174858224, 94396174859616,
            	0, 0,
            	0, 4097,
            	94396174861248, 94396174872064,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 3680,
            	48, 4097,
            	94396174861248, 94396174857840,
            	4097, 94396173783632,
            	417, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	0, 94396173168560,
            	0, 0,
            	0, 4097,
            	48, 94416532230361,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 94416532233257,
            	94396174871184, 4097,
            	94396174859184, 94396173725840,
            	0, 0,
            	0, 4097,
            	65, 94396174864880,
            	4097, 32,
            	32, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 94396174863104,
            	94396174870576, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 8,
            	0, 4097,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 0,
            	0, 4097,
            	0, 0,
            	4097, 0,
            	0, 4097,
            	0, 0,
            	0, 1,
            	0, 0,
            	20, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	0, 0,
            	0, 0,
            	0, 4097,
            	0, 0,
            	4097, 0,
            	0, 0,
            	0, 0,
            	4097, 0,
            	0, 4097,
            	0, 0,
            	0, 0,
            	0, 4097,
            	0, 0,
            	4097, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	0, 0,
            	4097, 0,
            	0, 4097,
            	0, 0,
            	0, 0,
            	0, 4097,
            	0, 0,
            	0, 0,
            	0, 4097,
            	0, 0,
            	0, 0,
            	0, 4097,
            	0, 0,
            	4097, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	0, 0,
            	0, 0,
            	0, 4097,
            	0, 0,
            	0, 0,
            	0, 4097,
            	0, 0,
            	0, 0,
            	0, 4097,
            	0, 0,
            	0, 0,
            	0, 4097,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 0,
            	0, 0,
        },
        .arg_entity_index = { 318, 334, 93, },
        .ret_entity_index = 5,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    EVP_MD_CTX * new_arg_a = *((EVP_MD_CTX * *)new_args->args[0]);

    const EVP_MD * new_arg_b = *((const EVP_MD * *)new_args->args[1]);

    ENGINE * new_arg_c = *((ENGINE * *)new_args->args[2]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_EVP_DigestInit_ex)(EVP_MD_CTX *,const EVP_MD *,ENGINE *);
    orig_EVP_DigestInit_ex = dlsym(RTLD_NEXT, "EVP_DigestInit_ex");
    *new_ret_ptr = (*orig_EVP_DigestInit_ex)(new_arg_a,new_arg_b,new_arg_c);

    syscall(889);

    return ret;
}

