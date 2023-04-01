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

void * bb_X509_get_ext_d2i(X509 * arg_a,int arg_b,int * arg_c,int * arg_d);

void * X509_get_ext_d2i(X509 * arg_a,int arg_b,int * arg_c,int * arg_d) 
{
    unsigned long in_lib = syscall(890);
    printf("X509_get_ext_d2i called %lu\n", in_lib);
    if (!in_lib)
        return bb_X509_get_ext_d2i(arg_a,arg_b,arg_c,arg_d);
    else {
        void * (*orig_X509_get_ext_d2i)(X509 *,int,int *,int *);
        orig_X509_get_ext_d2i = dlsym(RTLD_NEXT, "X509_get_ext_d2i");
        return orig_X509_get_ext_d2i(arg_a,arg_b,arg_c,arg_d);
    }
}

void * bb_X509_get_ext_d2i(X509 * arg_a,int arg_b,int * arg_c,int * arg_d) 
{
    void * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            1, 8, 1, /* 0: pointer.int */
            	5, 0,
            0, 4, 0, /* 5: int */
            1, 8, 1, /* 8: pointer.struct.x509_cert_aux_st */
            	13, 0,
            0, 40, 5, /* 13: struct.x509_cert_aux_st */
            	26, 0,
            	26, 8,
            	51, 16,
            	51, 24,
            	26, 32,
            1, 8, 1, /* 26: pointer.struct.stack_st_OPENSSL_STRING */
            	31, 0,
            0, 32, 1, /* 31: struct.stack_st_OPENSSL_STRING */
            	36, 0,
            0, 32, 1, /* 36: struct.stack_st */
            	41, 8,
            1, 8, 1, /* 41: pointer.pointer.char */
            	46, 0,
            1, 8, 1, /* 46: pointer.char */
            	4096, 0,
            1, 8, 1, /* 51: pointer.struct.asn1_string_st */
            	56, 0,
            0, 24, 1, /* 56: struct.asn1_string_st */
            	46, 8,
            1, 8, 1, /* 61: pointer.struct.NAME_CONSTRAINTS_st */
            	66, 0,
            0, 16, 2, /* 66: struct.NAME_CONSTRAINTS_st */
            	26, 0,
            	26, 8,
            1, 8, 1, /* 73: pointer.struct.X509_POLICY_CACHE_st */
            	78, 0,
            0, 40, 2, /* 78: struct.X509_POLICY_CACHE_st */
            	85, 0,
            	26, 8,
            1, 8, 1, /* 85: pointer.struct.X509_POLICY_DATA_st */
            	90, 0,
            0, 32, 3, /* 90: struct.X509_POLICY_DATA_st */
            	99, 8,
            	26, 16,
            	26, 24,
            1, 8, 1, /* 99: pointer.struct.asn1_object_st */
            	104, 0,
            0, 40, 3, /* 104: struct.asn1_object_st */
            	46, 0,
            	46, 8,
            	46, 24,
            0, 24, 1, /* 113: struct.ASN1_ENCODING_st */
            	46, 0,
            0, 32, 2, /* 118: struct.ENGINE_CMD_DEFN_st */
            	46, 8,
            	46, 16,
            1, 8, 1, /* 125: pointer.struct.ENGINE_CMD_DEFN_st */
            	118, 0,
            0, 0, 0, /* 130: func */
            4097, 1, 225, /* 133: pointer.func */
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	16, 1,
            	26, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	4097, 94396191931808,
            	1, 0,
            	0, 0,
            	1, 8,
            	1, 159,
            	0, 0,
            	0, 0,
            	4097, 33,
            	94396192168608, 4097,
            	736, 32,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 96,
            	2, 46,
            	0, 46,
            	72, 4097,
            	0, 65,
            	4097, 140425329646816,
            	32, 0,
            	20, 0,
            	4097, 32,
            	94416503418857, 0,
            	56, 4,
            	212, 16,
            	234, 24,
            	329, 32,
            	26, 48,
            	1, 8,
            	1, 217,
            	0, 0,
            	208, 3,
            	46, 16,
            	46, 24,
            	226, 32,
            	1, 8,
            	1, 231,
            	0, 0,
            	0, 0,
            	1, 8,
            	1, 239,
            	0, 0,
            	216, 13,
            	46, 0,
            	46, 8,
            	268, 16,
            	280, 24,
            	285, 32,
            	297, 40,
            	309, 48,
            	321, 56,
            	162, 64,
            	125, 160,
            	145, 184,
            	234, 200,
            	234, 208,
            	1, 8,
            	1, 273,
            	0, 0,
            	112, 2,
            	46, 0,
            	46, 80,
            	1, 8,
            	1, 182,
            	0, 1,
            	8, 1,
            	290, 0,
            	0, 72,
            	2, 46,
            	0, 46,
            	56, 1,
            	8, 1,
            	302, 0,
            	0, 32,
            	2, 46,
            	0, 46,
            	24, 1,
            	8, 1,
            	314, 0,
            	0, 48,
            	2, 46,
            	0, 46,
            	40, 1,
            	8, 1,
            	326, 0,
            	0, 48,
            	0, 0,
            	8, 1,
            	46, 0,
            	4097, 33,
            	94396192168224, 0,
            	0, 0,
            	4097, 94396190839216,
            	0, 0,
            	0, 0,
            	4097, 32,
            	94416503415753, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	94416503418601, 94396190921776,
            	4097, 321,
            	94396192167280, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	24, 3,
            	382, 0,
            	51, 8,
            	404, 16,
            	1, 8,
            	1, 387,
            	0, 0,
            	16, 2,
            	99, 0,
            	394, 8,
            	1, 8,
            	1, 399,
            	0, 0,
            	16, 1,
            	329, 8,
            	1, 8,
            	1, 201,
            	0, 4097,
            	1, 33,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 8,
            	0, 1,
            	8, 1,
            	426, 0,
            	0, 16,
            	2, 51,
            	0, 51,
            	8, 4097,
            	0, 33,
            	0, 0,
            	0, 4097,
            	94416503413994, 94396191346960,
            	0, 24,
            	1, 46,
            	8, 0,
            	0, 0,
            	4097, 417,
            	94396192169664, 4097,
            	0, 33,
            	4097, 94396192169664,
            	64, 0,
            	0, 0,
            	4097, 321,
            	94396192168000, 4097,
            	32, 32,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	32, 32,
            	0, 0,
            	0, 0,
            	40, 3,
            	26, 0,
            	492, 16,
            	46, 24,
            	1, 8,
            	1, 442,
            	0, 1,
            	8, 1,
            	502, 0,
            	0, 104,
            	11, 51,
            	0, 51,
            	8, 382,
            	16, 527,
            	24, 421,
            	32, 527,
            	40, 532,
            	48, 51,
            	56, 51,
            	64, 26,
            	72, 113,
            	80, 1,
            	8, 1,
            	483, 0,
            	1, 8,
            	1, 373,
            	0, 4097,
            	0, 161,
            	1, 8,
            	1, 545,
            	0, 0,
            	24, 3,
            	51, 0,
            	26, 8,
            	51, 16,
            	4097, 33,
            	94396192171360, 1,
            	8, 1,
            	562, 0,
            	0, 184,
            	12, 497,
            	0, 382,
            	8, 51,
            	16, 46,
            	32, 145,
            	40, 51,
            	104, 540,
            	112, 73,
            	120, 26,
            	128, 26,
            	136, 61,
            144, 8, 176, /* 586: Unnamed */
            	4097, 160,
            	32, 0,
            	0, 0,
            	4097, 140425329646816,
            	94396192171360, 0,
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
            	4097, 0,
            	0, 4097,
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
            	0, 0,
            	0, 0,
            	4097, 0,
            	0, 0,
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
            	0, 0,
            	0, 0,
            	0, 0,
            	0, 4097,
            	0, 0,
            	0, 0,
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
        .arg_entity_index = { 557, 5, 0, 0, },
        .ret_entity_index = 46,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_arg(args_addr, arg_d);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    X509 * new_arg_a = *((X509 * *)new_args->args[0]);

    int new_arg_b = *((int *)new_args->args[1]);

    int * new_arg_c = *((int * *)new_args->args[2]);

    int * new_arg_d = *((int * *)new_args->args[3]);

    void * *new_ret_ptr = (void * *)new_args->ret;

    void * (*orig_X509_get_ext_d2i)(X509 *,int,int *,int *);
    orig_X509_get_ext_d2i = dlsym(RTLD_NEXT, "X509_get_ext_d2i");
    *new_ret_ptr = (*orig_X509_get_ext_d2i)(new_arg_a,new_arg_b,new_arg_c,new_arg_d);

    syscall(889);

    return ret;
}

