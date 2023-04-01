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

int bb_EVP_SignFinal(EVP_MD_CTX * arg_a,unsigned char * arg_b,unsigned int * arg_c,EVP_PKEY * arg_d);

int EVP_SignFinal(EVP_MD_CTX * arg_a,unsigned char * arg_b,unsigned int * arg_c,EVP_PKEY * arg_d) 
{
    unsigned long in_lib = syscall(890);
    printf("EVP_SignFinal called %lu\n", in_lib);
    if (!in_lib)
        return bb_EVP_SignFinal(arg_a,arg_b,arg_c,arg_d);
    else {
        int (*orig_EVP_SignFinal)(EVP_MD_CTX *,unsigned char *,unsigned int *,EVP_PKEY *);
        orig_EVP_SignFinal = dlsym(RTLD_NEXT, "EVP_SignFinal");
        return orig_EVP_SignFinal(arg_a,arg_b,arg_c,arg_d);
    }
}

int bb_EVP_SignFinal(EVP_MD_CTX * arg_a,unsigned char * arg_b,unsigned int * arg_c,EVP_PKEY * arg_d) 
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
            4097, 94396194074160, 0, /* 18: pointer.func */
            4097, 94396193606752, 193, /* 21: pointer.func */
            	0, 0,
            	0, 4097,
            	48, 48,
            	0, 0,
            	0, 4097,
            	94396193290960, 97,
            	4097, 94396194061056,
            	0, 4097,
            	94396192680016, 49,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 94396194073120,
            	94396194074480, 0,
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
            	184, 93,
            	200, 93,
            	208, 1,
            	8, 1,
            	132, 0,
            	0, 112,
            	2, 13,
            	0, 13,
            	80, 1,
            	8, 1,
            	144, 0,
            	0, 96,
            	2, 13,
            	0, 13,
            	72, 1,
            	8, 1,
            	156, 0,
            	0, 72,
            	2, 13,
            	0, 13,
            	56, 1,
            	8, 1,
            	168, 0,
            	0, 32,
            	2, 13,
            	0, 13,
            	24, 1,
            	8, 1,
            	180, 0,
            	0, 48,
            	2, 13,
            	0, 13,
            	40, 1,
            	8, 1,
            	192, 0,
            	0, 48,
            	0, 1,
            	8, 1,
            	200, 0,
            	0, 0,
            	0, 1,
            	8, 1,
            	208, 0,
            	0, 32,
            	2, 13,
            	8, 13,
            	16, 0,
            	16, 1,
            	220, 0,
            	1, 8,
            	1, 225,
            	0, 0,
            	32, 1,
            	230, 0,
            	0, 32,
            	1, 235,
            	8, 1,
            	8, 1,
            	13, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 225,
            	94396194072592, 0,
            	0, 0,
            	4097, 94396192609840,
            	64, 0,
            	0, 0,
            	4097, 129,
            	94396194068512, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	608, 32,
            	4097, 94396192585072,
            	1472, 0,
            	0, 0,
            	4097, 33,
            	94396194072592, 4097,
            	1536, 32,
            	0, 0,
            	0, 4097,
            	94396194072672, 94396194067584,
            	0, 0,
            	0, 4097,
            	64, 32,
            	4097, 94396192737808,
            	1664, 4097,
            	94416504661769, 94396192733680,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 94396192841008,
            	1, 0,
            	0, 0,
            	1, 8,
            	1, 323,
            	0, 0,
            	48, 4,
            	334, 0,
            	93, 8,
            	13, 24,
            	342, 32,
            	1, 8,
            	1, 339,
            	0, 0,
            	120, 0,
            	1, 8,
            	1, 347,
            	0, 0,
            	80, 8,
            	366, 0,
            	93, 8,
            	392, 16,
            	392, 24,
            	13, 40,
            	13, 48,
            	85, 56,
            	0, 64,
            	1, 8,
            	1, 371,
            	0, 0,
            	208, 9,
            	85, 8,
            	85, 32,
            	85, 48,
            	85, 64,
            	85, 80,
            	85, 96,
            	85, 144,
            	85, 160,
            	85, 176,
            	1, 8,
            	1, 60,
            	0, 4097,
            	0, 65,
            	4097, 94396194066432,
            	0, 4097,
            	94396194068288, 94396194066208,
            	4097, 32,
            	94416504662841, 0,
            0, 0, 4097, /* 410: Unnamed */
            	94396194066208, 1,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 0,
            	97, 0,
            	0, 0,
            	4097, 94396194069216,
            	94396194066112, 4097,
            	32, 94416504665881,
            	0, 0,
            	0, 4097,
            	94396193270320, 1,
            	4097, 94396194066976,
            	94396194067584, 4097,
            	33, 94396194068608,
            	0, 0,
            	0, 4097,
            	94396193668672, 1,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 32,
            	32, 4097,
            	94396193602624, 0,
            	4097, 94396194069312,
            	94396194067840, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	94396194073312, 32,
            	0, 0,
            	0, 4097,
            	32, 94416504663193,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 94396194073312,
            	94396194068288, 4097,
            	65, 94396194067616,
            	0, 0,
            	0, 4097,
            	94396194067616, 224,
            	4097, 94416504665113,
            	94396193454016, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 94396192185824,
            	94396194067520, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	94396192225936, 64,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 8,
            	0, 4097,
            	94396194069488, 64,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 3728,
            	48, 4097,
            	94396194063616, 0,
            	4097, 94396193402416,
            	1249, 4097,
            	94396191484704, 0,
            	0, 1,
            	0, 0,
            	20, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	94396192197040, 176,
            	0, 0,
            	0, 4097,
            	94396194072560, 94396193134096,
            	4097, 94396194075104,
            	94396194074352, 0,
            	0, 0,
            	4097, 94396194062592,
            	94396194065328, 4097,
            	94396194065344, 320,
            	0, 0,
            	0, 4097,
            	94396194070560, 94396193146480,
            	4097, 94396194063984,
            	94396194073872, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	48, 94416504664825,
            	4097, 94396194070512,
            	0, 4097,
            	753, 94396194072512,
            	0, 0,
            	0, 4097,
            	94396194065056, 94396194073040,
            	0, 0,
            	0, 4097,
            	94396192185792, 112,
            	0, 0,
            	0, 4097,
            	0, 94396192329136,
            	4097, 94396194070880,
            	94396194073632, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	177, 94396194062928,
            	0, 0,
            	0, 4097,
            	94396194070144, 1,
            	0, 0,
            	0, 4097,
            	48, 94416514781833,
            	0, 0,
            	0, 4097,
            	33, 94396194065760,
            	0, 0,
            	0, 4097,
            	94396194072560, 94396194069824,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 512,
            	48, 94416504661097,
        },
        .arg_entity_index = { 318, 13, 0, 392, },
        .ret_entity_index = 5,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_arg(args_addr, arg_d);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    EVP_MD_CTX * new_arg_a = *((EVP_MD_CTX * *)new_args->args[0]);

    unsigned char * new_arg_b = *((unsigned char * *)new_args->args[1]);

    unsigned int * new_arg_c = *((unsigned int * *)new_args->args[2]);

    EVP_PKEY * new_arg_d = *((EVP_PKEY * *)new_args->args[3]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_EVP_SignFinal)(EVP_MD_CTX *,unsigned char *,unsigned int *,EVP_PKEY *);
    orig_EVP_SignFinal = dlsym(RTLD_NEXT, "EVP_SignFinal");
    *new_ret_ptr = (*orig_EVP_SignFinal)(new_arg_a,new_arg_b,new_arg_c,new_arg_d);

    syscall(889);

    return ret;
}

