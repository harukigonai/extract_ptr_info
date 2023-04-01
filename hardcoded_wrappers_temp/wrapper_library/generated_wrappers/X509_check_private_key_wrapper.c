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

int bb_X509_check_private_key(X509 * arg_a,EVP_PKEY * arg_b);

int X509_check_private_key(X509 * arg_a,EVP_PKEY * arg_b) 
{
    unsigned long in_lib = syscall(890);
    printf("X509_check_private_key called %lu\n", in_lib);
    if (!in_lib)
        return bb_X509_check_private_key(arg_a,arg_b);
    else {
        int (*orig_X509_check_private_key)(X509 *,EVP_PKEY *);
        orig_X509_check_private_key = dlsym(RTLD_NEXT, "X509_check_private_key");
        return orig_X509_check_private_key(arg_a,arg_b);
    }
}

int bb_X509_check_private_key(X509 * arg_a,EVP_PKEY * arg_b) 
{
    int ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            1, 8, 1, /* 0: pointer.struct.x509_cert_aux_st */
            	5, 0,
            0, 40, 5, /* 5: struct.x509_cert_aux_st */
            	18, 0,
            	18, 8,
            	43, 16,
            	43, 24,
            	18, 32,
            1, 8, 1, /* 18: pointer.struct.stack_st_OPENSSL_STRING */
            	23, 0,
            0, 32, 1, /* 23: struct.stack_st_OPENSSL_STRING */
            	28, 0,
            0, 32, 1, /* 28: struct.stack_st */
            	33, 8,
            1, 8, 1, /* 33: pointer.pointer.char */
            	38, 0,
            1, 8, 1, /* 38: pointer.char */
            	4096, 0,
            1, 8, 1, /* 43: pointer.struct.asn1_string_st */
            	48, 0,
            0, 24, 1, /* 48: struct.asn1_string_st */
            	38, 8,
            0, 20, 0, /* 53: array[20].char */
            1, 8, 1, /* 56: pointer.struct.NAME_CONSTRAINTS_st */
            	61, 0,
            0, 16, 2, /* 61: struct.NAME_CONSTRAINTS_st */
            	18, 0,
            	18, 8,
            1, 8, 1, /* 68: pointer.struct.X509_POLICY_CACHE_st */
            	73, 0,
            0, 40, 2, /* 73: struct.X509_POLICY_CACHE_st */
            	80, 0,
            	18, 8,
            1, 8, 1, /* 80: pointer.struct.X509_POLICY_DATA_st */
            	85, 0,
            0, 32, 3, /* 85: struct.X509_POLICY_DATA_st */
            	94, 8,
            	18, 16,
            	18, 24,
            1, 8, 1, /* 94: pointer.struct.asn1_object_st */
            	99, 0,
            0, 40, 3, /* 99: struct.asn1_object_st */
            	38, 0,
            	38, 8,
            	38, 24,
            0, 24, 1, /* 108: struct.ASN1_ENCODING_st */
            	38, 0,
            0, 32, 2, /* 113: struct.ENGINE_CMD_DEFN_st */
            	38, 8,
            	38, 16,
            1, 8, 1, /* 120: pointer.struct.ENGINE_CMD_DEFN_st */
            	113, 0,
            0, 0, 0, /* 125: func */
            4097, 94396205273808, 32, /* 128: pointer.func */
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	16, 1,
            	18, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 94416432651480,
            	94396203401040, 0,
            	0, 0,
            	1, 8,
            	1, 154,
            	0, 0,
            	0, 0,
            	4097, 96,
            	32, 4097,
            	94396205032112, 1,
            	0, 0,
            	0, 4097,
            	32, 94416432646744,
            	4097, 64,
            	32, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 96,
            	2, 38,
            	0, 38,
            72, 4097, 94396205270704, /* 195: Unnamed */
            	352, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	992, 32,
            	4097, 94396204675024,
            	0, 4097,
            	94396205279104, 94396205273904,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 94396204641792,
            	96, 0,
            	0, 0,
            	4097, 161,
            	94396205279664, 4097,
            	0, 97,
            	0, 0,
            	0, 0,
            	24, 3,
            	244, 0,
            	43, 8,
            	271, 16,
            	1, 8,
            	1, 249,
            	0, 0,
            	16, 2,
            	94, 0,
            	256, 8,
            	1, 8,
            	1, 261,
            	0, 0,
            	16, 1,
            	266, 8,
            	0, 8,
            	1, 38,
            	0, 1,
            	8, 1,
            	276, 0,
            	0, 56,
            	4, 287,
            	16, 299,
            	24, 266,
            	32, 18,
            	48, 1,
            	8, 1,
            	292, 0,
            	0, 208,
            	2, 38,
            	16, 38,
            	24, 1,
            	8, 1,
            	304, 0,
            	0, 216,
            	13, 38,
            	0, 38,
            	8, 333,
            	16, 345,
            	24, 350,
            	32, 362,
            	40, 374,
            	48, 386,
            	56, 157,
            	64, 120,
            	160, 140,
            	184, 299,
            	200, 299,
            	208, 1,
            	8, 1,
            	338, 0,
            	0, 112,
            	2, 38,
            	0, 38,
            	80, 1,
            	8, 1,
            	189, 0,
            	1, 8,
            	1, 355,
            	0, 0,
            	72, 2,
            	38, 0,
            	38, 56,
            	1, 8,
            	1, 367,
            	0, 0,
            	32, 2,
            	38, 0,
            	38, 24,
            	1, 8,
            	1, 379,
            	0, 0,
            	48, 2,
            	38, 0,
            	38, 40,
            	1, 8,
            	1, 391,
            	0, 0,
            	48, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 8,
            	0, 1,
            	8, 1,
            	408, 0,
            	0, 16,
            	2, 43,
            	0, 43,
            	8, 4097,
            	94396205274736, 140425329646816,
            	4097, 32,
            	94416432649433, 4097,
            	0, 257,
            	4097, 94396205270704,
            	0, 0,
            	0, 0,
            	0, 4,
            	0, 1,
            	8, 1,
            	438, 0,
            	0, 104,
            	11, 43,
            	0, 43,
            	8, 244,
            	16, 463,
            	24, 403,
            	32, 463,
            	40, 487,
            	48, 43,
            	56, 43,
            	64, 18,
            	72, 108,
            	80, 1,
            	8, 1,
            	468, 0,
            	0, 40,
            	3, 18,
            	0, 477,
            	16, 38,
            	24, 1,
            	8, 1,
            	482, 0,
            	0, 24,
            	1, 38,
            	8, 1,
            	8, 1,
            	235, 0,
            	4097, 94396204540656,
            	1408, 0,
            	0, 0,
            	4097, 737,
            	94396205272016, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	1, 8,
            	1, 515,
            	0, 0,
            	184, 12,
            	433, 0,
            	244, 8,
            	43, 16,
            	38, 32,
            	140, 40,
            	43, 104,
            	542, 112,
            	68, 120,
            	18, 128,
            	18, 136,
            	56, 144,
            	0, 176,
            	1, 8,
            	1, 547,
            	0, 0,
            	24, 3,
            	43, 0,
            	18, 8,
            	43, 16,
            	4097, 94396205279424,
            	96, 4097,
            	94416432649401, 94396204131696,
            	4097, 225,
            	94396205273040, 0,
            	0, 0,
            	4097, 94396203607440,
            	1, 4097,
            	94396205273040, 140425329646816,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	94396205276112, 140425329646816,
            	4097, 32,
            	94416432655849, 0,
            	0, 0,
            	4097, 94396203636336,
            	1, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 0,
            	0, 4097,
            	0, 0,
            	4097, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	0, 0,
            	4097, 0,
            	0, 0,
            	0, 0,
            	4097, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 0,
            	0, 4097,
            	0, 0,
            	4097, 0,
            	0, 0,
            	0, 0,
            	4097, 0,
            	0, 4097,
            	0, 0,
            	4097, 0,
            	0, 0,
            	0, 0,
            	4097, 0,
            	0, 0,
            	0, 0,
            	4097, 0,
            	0, 4097,
            	0, 0,
            	4097, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 0,
            	0, 4097,
            	0, 0,
            	0, 0,
            	0, 0,
            	1, 0,
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
            	0, 0,
            	0, 0,
        },
        .arg_entity_index = { 510, 271, },
        .ret_entity_index = 430,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    X509 * new_arg_a = *((X509 * *)new_args->args[0]);

    EVP_PKEY * new_arg_b = *((EVP_PKEY * *)new_args->args[1]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_X509_check_private_key)(X509 *,EVP_PKEY *);
    orig_X509_check_private_key = dlsym(RTLD_NEXT, "X509_check_private_key");
    *new_ret_ptr = (*orig_X509_check_private_key)(new_arg_a,new_arg_b);

    syscall(889);

    return ret;
}

