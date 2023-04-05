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
            0, 32, 1, /* 0: struct.stack_st_X509_ATTRIBUTE */
            	5, 0,
            0, 32, 2, /* 5: struct.stack_st */
            	12, 8,
            	22, 24,
            1, 8, 1, /* 12: pointer.pointer.char */
            	17, 0,
            1, 8, 1, /* 17: pointer.char */
            	4096, 0,
            4097, 8, 0, /* 22: pointer.func */
            0, 0, 0, /* 25: struct.ec_key_st */
            1, 8, 1, /* 28: pointer.struct.ec_key_st */
            	25, 0,
            4097, 8, 0, /* 33: pointer.func */
            4097, 8, 0, /* 36: pointer.func */
            4097, 8, 0, /* 39: pointer.func */
            0, 72, 8, /* 42: struct.dh_method */
            	61, 0,
            	39, 8,
            	66, 16,
            	36, 24,
            	39, 32,
            	39, 40,
            	17, 56,
            	33, 64,
            1, 8, 1, /* 61: pointer.char */
            	4096, 0,
            4097, 8, 0, /* 66: pointer.func */
            0, 1, 0, /* 69: unsigned char */
            1, 8, 1, /* 72: pointer.unsigned char */
            	69, 0,
            1, 8, 1, /* 77: pointer.struct.stack_st_X509_ATTRIBUTE */
            	0, 0,
            0, 144, 12, /* 82: struct.dh_st */
            	109, 8,
            	109, 16,
            	109, 32,
            	109, 40,
            	127, 56,
            	109, 64,
            	109, 72,
            	72, 80,
            	109, 96,
            	141, 112,
            	156, 128,
            	161, 136,
            1, 8, 1, /* 109: pointer.struct.bignum_st */
            	114, 0,
            0, 24, 1, /* 114: struct.bignum_st */
            	119, 0,
            1, 8, 1, /* 119: pointer.unsigned int */
            	124, 0,
            0, 4, 0, /* 124: unsigned int */
            1, 8, 1, /* 127: pointer.struct.bn_mont_ctx_st */
            	132, 0,
            0, 96, 3, /* 132: struct.bn_mont_ctx_st */
            	114, 8,
            	114, 32,
            	114, 56,
            0, 16, 1, /* 141: struct.crypto_ex_data_st */
            	146, 0,
            1, 8, 1, /* 146: pointer.struct.stack_st_void */
            	151, 0,
            0, 32, 1, /* 151: struct.stack_st_void */
            	5, 0,
            1, 8, 1, /* 156: pointer.struct.dh_method */
            	42, 0,
            1, 8, 1, /* 161: pointer.struct.engine_st */
            	166, 0,
            0, 0, 0, /* 166: struct.engine_st */
            4097, 8, 0, /* 169: pointer.func */
            0, 112, 13, /* 172: struct.rsa_meth_st */
            	61, 0,
            	201, 8,
            	201, 16,
            	201, 24,
            	201, 32,
            	204, 40,
            	207, 48,
            	210, 56,
            	210, 64,
            	17, 80,
            	213, 88,
            	216, 96,
            	219, 104,
            4097, 8, 0, /* 201: pointer.func */
            4097, 8, 0, /* 204: pointer.func */
            4097, 8, 0, /* 207: pointer.func */
            4097, 8, 0, /* 210: pointer.func */
            4097, 8, 0, /* 213: pointer.func */
            4097, 8, 0, /* 216: pointer.func */
            4097, 8, 0, /* 219: pointer.func */
            0, 0, 0, /* 222: struct.bn_blinding_st */
            1, 8, 1, /* 225: pointer.struct.rsa_st */
            	230, 0,
            0, 168, 17, /* 230: struct.rsa_st */
            	267, 16,
            	161, 24,
            	109, 32,
            	109, 40,
            	109, 48,
            	109, 56,
            	109, 64,
            	109, 72,
            	109, 80,
            	109, 88,
            	141, 96,
            	127, 120,
            	127, 128,
            	127, 136,
            	17, 144,
            	272, 152,
            	272, 160,
            1, 8, 1, /* 267: pointer.struct.rsa_meth_st */
            	172, 0,
            1, 8, 1, /* 272: pointer.struct.bn_blinding_st */
            	222, 0,
            1, 8, 1, /* 277: pointer.struct.dsa_method */
            	282, 0,
            0, 96, 11, /* 282: struct.dsa_method */
            	61, 0,
            	307, 8,
            	310, 16,
            	313, 24,
            	316, 32,
            	169, 40,
            	319, 48,
            	319, 56,
            	17, 72,
            	322, 80,
            	319, 88,
            4097, 8, 0, /* 307: pointer.func */
            4097, 8, 0, /* 310: pointer.func */
            4097, 8, 0, /* 313: pointer.func */
            4097, 8, 0, /* 316: pointer.func */
            4097, 8, 0, /* 319: pointer.func */
            4097, 8, 0, /* 322: pointer.func */
            4097, 8, 0, /* 325: pointer.func */
            4097, 8, 0, /* 328: pointer.func */
            4097, 8, 0, /* 331: pointer.func */
            4097, 8, 0, /* 334: pointer.func */
            4097, 8, 0, /* 337: pointer.func */
            4097, 8, 0, /* 340: pointer.func */
            0, 8, 5, /* 343: union.unknown */
            	17, 0,
            	225, 0,
            	356, 0,
            	386, 0,
            	28, 0,
            1, 8, 1, /* 356: pointer.struct.dsa_st */
            	361, 0,
            0, 136, 11, /* 361: struct.dsa_st */
            	109, 24,
            	109, 32,
            	109, 40,
            	109, 48,
            	109, 56,
            	109, 64,
            	109, 72,
            	127, 88,
            	141, 104,
            	277, 120,
            	161, 128,
            1, 8, 1, /* 386: pointer.struct.dh_st */
            	82, 0,
            4097, 8, 0, /* 391: pointer.func */
            0, 4, 0, /* 394: int */
            4097, 8, 0, /* 397: pointer.func */
            0, 1, 0, /* 400: char */
            4097, 8, 0, /* 403: pointer.func */
            1, 8, 1, /* 406: pointer.struct.evp_pkey_st */
            	411, 0,
            0, 56, 4, /* 411: struct.evp_pkey_st */
            	422, 16,
            	161, 24,
            	343, 32,
            	77, 48,
            1, 8, 1, /* 422: pointer.struct.evp_pkey_asn1_method_st */
            	427, 0,
            0, 208, 24, /* 427: struct.evp_pkey_asn1_method_st */
            	17, 16,
            	17, 24,
            	334, 32,
            	478, 40,
            	397, 48,
            	481, 56,
            	340, 64,
            	484, 72,
            	481, 80,
            	337, 88,
            	337, 96,
            	391, 104,
            	328, 112,
            	337, 120,
            	487, 128,
            	397, 136,
            	481, 144,
            	325, 152,
            	490, 160,
            	331, 168,
            	391, 176,
            	328, 184,
            	493, 192,
            	403, 200,
            4097, 8, 0, /* 478: pointer.func */
            4097, 8, 0, /* 481: pointer.func */
            4097, 8, 0, /* 484: pointer.func */
            4097, 8, 0, /* 487: pointer.func */
            4097, 8, 0, /* 490: pointer.func */
            4097, 8, 0, /* 493: pointer.func */
        },
        .arg_entity_index = { 406, },
        .ret_entity_index = 394,
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

