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

X509_NAME * bb_X509_get_subject_name(X509 * arg_a);

X509_NAME * X509_get_subject_name(X509 * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("X509_get_subject_name called %lu\n", in_lib);
    if (!in_lib)
        return bb_X509_get_subject_name(arg_a);
    else {
        X509_NAME * (*orig_X509_get_subject_name)(X509 *);
        orig_X509_get_subject_name = dlsym(RTLD_NEXT, "X509_get_subject_name");
        return orig_X509_get_subject_name(arg_a);
    }
}

X509_NAME * bb_X509_get_subject_name(X509 * arg_a) 
{
    X509_NAME * ret;

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
            4097, 94396189616640, 128, /* 128: pointer.func */
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
            	4097, 94396189620080,
            	94396189619360, 0,
            	0, 0,
            	1, 8,
            	1, 154,
            	0, 0,
            	0, 0,
            	4097, 1,
            	33, 4097,
            	94396189615072, 96,
            	0, 0,
            	0, 4097,
            	65, 94396189614048,
            	4097, 32,
            	32, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 96,
            	2, 38,
            	0, 38,
            	72, 4097,
            	94396189129568, 96,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 0,
            	33, 4097,
            	94396189613152, 416,
            	4097, 94416517501338,
            	94396189034624, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	94396189613152, 0,
            	0, 0,
            	0, 4097,
            	32, 94416517507226,
            	4097, 0,
            	33, 0,
            	24, 1,
            	38, 8,
            	1, 8,
            	1, 242,
            	0, 0,
            	208, 2,
            	38, 16,
            	38, 24,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 112,
            	2, 38,
            	0, 38,
            	80, 4097,
            	32, 94416517503418,
            	1, 8,
            	1, 270,
            	0, 0,
            	16, 1,
            	275, 8,
            	0, 8,
            	1, 38,
            	0, 1,
            	8, 1,
            	285, 0,
            	0, 56,
            	4, 237,
            	16, 296,
            	24, 275,
            	32, 18,
            	48, 1,
            	8, 1,
            	301, 0,
            	0, 216,
            	13, 38,
            	0, 38,
            	8, 330,
            	16, 335,
            	24, 340,
            	32, 352,
            	40, 364,
            	48, 376,
            	56, 157,
            	64, 120,
            	160, 140,
            	184, 296,
            	200, 296,
            	208, 1,
            	8, 1,
            	255, 0,
            	1, 8,
            	1, 189,
            	0, 1,
            	8, 1,
            	345, 0,
            	0, 72,
            	2, 38,
            	0, 38,
            	56, 1,
            	8, 1,
            	357, 0,
            	0, 32,
            	2, 38,
            	0, 38,
            	24, 1,
            	8, 1,
            	369, 0,
            	0, 48,
            	2, 38,
            	0, 38,
            	40, 1,
            	8, 1,
            	381, 0,
            	0, 48,
            	0, 4097,
            	94396189613408, 192,
            1, 8, 1, /* 387: pointer.struct.buf_mem_st */
            	232, 0,
            0, 0, 0, /* 392: func */
            4097, 94396189613536, 94396189614400, /* 395: pointer.func */
            	4097, 97,
            	94396189613536, 0,
            	0, 0,
            	0, 4,
            	0, 1,
            	8, 1,
            	412, 0,
            	0, 104,
            	11, 43,
            	0, 43,
            	8, 437,
            	16, 449,
            	24, 463,
            	32, 449,
            	40, 475,
            	48, 43,
            	56, 43,
            	64, 18,
            	72, 108,
            	80, 1,
            	8, 1,
            	442, 0,
            	0, 16,
            	2, 94,
            	0, 265,
            	8, 1,
            	8, 1,
            	454, 0,
            	0, 40,
            	3, 18,
            	0, 387,
            	16, 38,
            	24, 1,
            	8, 1,
            	468, 0,
            	0, 16,
            	2, 43,
            	0, 43,
            	8, 1,
            	8, 1,
            	480, 0,
            	0, 24,
            	3, 437,
            	0, 43,
            	8, 280,
            	16, 4097,
            	0, 33,
            	4097, 94396189616704,
            	128, 4097,
            	94416517501146, 94396188801392,
            	4097, 33,
            	94396189616864, 4097,
            	192, 32,
            	1, 8,
            	1, 509,
            	0, 0,
            	24, 3,
            	43, 0,
            	18, 8,
            	43, 16,
            	4097, 65,
            	94396189614688, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 94396189063520,
            	0, 0,
            	0, 0,
            	4097, 33,
            	94396189616800, 0,
            	0, 0,
            	4097, 94396188322544,
            	1, 0,
            	8, 0,
            	1, 8,
            	1, 559,
            	0, 0,
            	184, 12,
            	407, 0,
            	437, 8,
            	43, 16,
            	38, 32,
            	140, 40,
            	43, 104,
            	504, 112,
            	68, 120,
            	18, 128,
            	18, 136,
            	56, 144,
            	0, 176,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	94416517507930, 94396187951024,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 94396187979920,
            	1, 4097,
            	140425329646816, 94396189613008,
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
        .arg_entity_index = { 554, },
        .ret_entity_index = 449,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    X509 * new_arg_a = *((X509 * *)new_args->args[0]);

    X509_NAME * *new_ret_ptr = (X509_NAME * *)new_args->ret;

    X509_NAME * (*orig_X509_get_subject_name)(X509 *);
    orig_X509_get_subject_name = dlsym(RTLD_NEXT, "X509_get_subject_name");
    *new_ret_ptr = (*orig_X509_get_subject_name)(new_arg_a);

    syscall(889);

    return ret;
}

