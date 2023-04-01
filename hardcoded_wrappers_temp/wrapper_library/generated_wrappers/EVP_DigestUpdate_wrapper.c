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

int bb_EVP_DigestUpdate(EVP_MD_CTX * arg_a, const void * arg_b,size_t arg_c);

int EVP_DigestUpdate(EVP_MD_CTX * arg_a, const void * arg_b,size_t arg_c) 
{
    unsigned long in_lib = syscall(890);
    printf("EVP_DigestUpdate called %lu\n", in_lib);
    if (!in_lib)
        return bb_EVP_DigestUpdate(arg_a,arg_b,arg_c);
    else {
        int (*orig_EVP_DigestUpdate)(EVP_MD_CTX *, const void *,size_t);
        orig_EVP_DigestUpdate = dlsym(RTLD_NEXT, "EVP_DigestUpdate");
        return orig_EVP_DigestUpdate(arg_a,arg_b,arg_c);
    }
}

int bb_EVP_DigestUpdate(EVP_MD_CTX * arg_a, const void * arg_b,size_t arg_c) 
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
            4097, 94396176761152, 0, /* 18: pointer.func */
            4097, 94396176318304, 49, /* 21: pointer.func */
            	0, 0,
            	0, 4097,
            	240, 48,
            	0, 0,
            	0, 4097,
            	288, 48,
            	4097, 94396176761536,
            	94396176763792, 4097,
            	94396176574240, 7425,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 140425329646816,
            	0, 0,
            	0, 0,
            	0, 56,
            	4, 71,
            	16, 93,
            	24, 8,
            	32, 220,
            	48, 1,
            	8, 1,
            	76, 0,
            	0, 208,
            	3, 13,
            	16, 13,
            	24, 85,
            	32, 1,
            	8, 1,
            	90, 0,
            	0, 0,
            	0, 1,
            	8, 1,
            	98, 0,
            	0, 216,
            	13, 13,
            	0, 13,
            	8, 127,
            	16, 139,
            	24, 151,
            	32, 163,
            	40, 175,
            	48, 187,
            	56, 195,
            	64, 203,
            	160, 215,
            184, 93, 200, /* 122: Unnamed */
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
            	94396176768112, 0,
            	0, 0,
            	0, 4097,
            	65, 94396176765936,
            	0, 0,
            	0, 4097,
            	94396176766992, 608,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 94416520920969,
            	94396175461744, 4097,
            	97, 94396174862448,
            	0, 0,
            	0, 4097,
            	94396175511280, 64,
            	4097, 94416520920361,
            	94396175436976, 0,
            	0, 0,
            	4097, 1728,
            	32, 0,
            	0, 0,
            	4097, 94416520920585,
            	94396175540176, 4097,
            	33, 94396174871744,
            	4097, 1824,
            	32, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	0, 94396176767760,
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
            	4097, 94396174871744,
            	94396176765456, 4097,
            	161, 94396176768464,
            	4097, 1,
            	129, 4097,
            	94396176765296, 0,
            	0, 0,
            	0, 4097,
            	65, 94396176768464,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 94416520920937,
            	94396175969488, 0,
            	0, 0,
            	4097, 1,
            	33, 4097,
            	140425329646816, 64,
            	0, 0,
            	0, 4097,
            	129, 94396176767088,
            	4097, 0,
            	97, 4097,
            	94396176768560, 32,
            	0, 0,
            	0, 4097,
            	33, 94396176768560,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 94396176768816,
            	94396174871744, 4097,
            	32, 94416520917961,
            	4097, 320,
            	32, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	65, 94396176765392,
            	0, 0,
            	0, 4097,
            	94396176768816, 96,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 0,
            	33, 4097,
            	94396176766832, 288,
            	0, 0,
            	0, 4097,
            	257, 94396099704672,
            	4097, 0,
            	225, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 0,
            97, 0, 0, /* 525: Unnamed */
            0, 0, 0, /* 528: Unnamed */
            0, 4097, 32, /* 531: Unnamed */
            	94416520917545, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	8, 0,
            	4097, 94396176764608,
            	94396176367840, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	94396176761728, 94396176760624,
            	4097, 3057,
            	94396176763632, 4097,
            	0, 0,
            	4097, 94396176769152,
            	64, 0,
            	1, 0,
            	0, 20,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 97,
            	94396176769232, 0,
            	0, 0,
            	4097, 48,
            	94416520916394, 4097,
            	0, 0,
            	0, 0,
            	0, 4097,
            	0, 0,
            4097, 33, 94396176771920, /* 598: pointer.func */
            	0, 0,
            	0, 4097,
            	94396099704464, 94396099704272,
            	4097, 94396175779600,
            	465, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	94396176769072, 94396175309008,
            	4097, 94396176772240,
            	94396099704640, 4097,
            	48, 94416520912938,
            	0, 0,
            	0, 4097,
            	33, 94396176770704,
            	0, 0,
            	0, 4097,
            	94396176773088, 94396176770000,
            	0, 0,
            	0, 4097,
            	94396176771760, 0,
            	4097, 94396176770704,
            	94396176769392, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	94396176773488, 0,
            	0, 0,
            	0, 4097,
            	94396174886592, 416,
            	0, 0,
            	0, 4097,
            	94396176770624, 880,
            	0, 0,
            	0, 4097,
            	94396176770432, 928,
            	0, 0,
            	0, 4097,
            	0, 94396176010768,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 94416540311418,
            	94396176762256, 94396176769808,
        },
        .arg_entity_index = { 318, 13, 541, },
        .ret_entity_index = 5,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    EVP_MD_CTX * new_arg_a = *((EVP_MD_CTX * *)new_args->args[0]);

     const void * new_arg_b = *(( const void * *)new_args->args[1]);

    size_t new_arg_c = *((size_t *)new_args->args[2]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_EVP_DigestUpdate)(EVP_MD_CTX *, const void *,size_t);
    orig_EVP_DigestUpdate = dlsym(RTLD_NEXT, "EVP_DigestUpdate");
    *new_ret_ptr = (*orig_EVP_DigestUpdate)(new_arg_a,new_arg_b,new_arg_c);

    syscall(889);

    return ret;
}

