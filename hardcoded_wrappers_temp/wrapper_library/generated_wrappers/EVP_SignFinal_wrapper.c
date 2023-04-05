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
            1, 8, 1, /* 25: pointer.struct.stack_st_X509_ATTRIBUTE */
            	0, 0,
            0, 0, 0, /* 30: struct.ec_key_st */
            1, 8, 1, /* 33: pointer.struct.ec_key_st */
            	30, 0,
            4097, 8, 0, /* 38: pointer.func */
            4097, 8, 0, /* 41: pointer.func */
            0, 72, 8, /* 44: struct.dh_method */
            	63, 0,
            	68, 8,
            	71, 16,
            	41, 24,
            	68, 32,
            	68, 40,
            	17, 56,
            	38, 64,
            1, 8, 1, /* 63: pointer.char */
            	4096, 0,
            4097, 8, 0, /* 68: pointer.func */
            4097, 8, 0, /* 71: pointer.func */
            1, 8, 1, /* 74: pointer.struct.dh_st */
            	79, 0,
            0, 144, 12, /* 79: struct.dh_st */
            	106, 8,
            	106, 16,
            	106, 32,
            	106, 40,
            	124, 56,
            	106, 64,
            	106, 72,
            	138, 80,
            	106, 96,
            	146, 112,
            	161, 128,
            	166, 136,
            1, 8, 1, /* 106: pointer.struct.bignum_st */
            	111, 0,
            0, 24, 1, /* 111: struct.bignum_st */
            	116, 0,
            1, 8, 1, /* 116: pointer.unsigned int */
            	121, 0,
            0, 4, 0, /* 121: unsigned int */
            1, 8, 1, /* 124: pointer.struct.bn_mont_ctx_st */
            	129, 0,
            0, 96, 3, /* 129: struct.bn_mont_ctx_st */
            	111, 8,
            	111, 32,
            	111, 56,
            1, 8, 1, /* 138: pointer.unsigned char */
            	143, 0,
            0, 1, 0, /* 143: unsigned char */
            0, 16, 1, /* 146: struct.crypto_ex_data_st */
            	151, 0,
            1, 8, 1, /* 151: pointer.struct.stack_st_void */
            	156, 0,
            0, 32, 1, /* 156: struct.stack_st_void */
            	5, 0,
            1, 8, 1, /* 161: pointer.struct.dh_method */
            	44, 0,
            1, 8, 1, /* 166: pointer.struct.engine_st */
            	171, 0,
            0, 0, 0, /* 171: struct.engine_st */
            4097, 8, 0, /* 174: pointer.func */
            4097, 8, 0, /* 177: pointer.func */
            4097, 8, 0, /* 180: pointer.func */
            0, 1, 0, /* 183: char */
            0, 8, 5, /* 186: union.unknown */
            	17, 0,
            	199, 0,
            	304, 0,
            	74, 0,
            	33, 0,
            1, 8, 1, /* 199: pointer.struct.rsa_st */
            	204, 0,
            0, 168, 17, /* 204: struct.rsa_st */
            	241, 16,
            	166, 24,
            	106, 32,
            	106, 40,
            	106, 48,
            	106, 56,
            	106, 64,
            	106, 72,
            	106, 80,
            	106, 88,
            	146, 96,
            	124, 120,
            	124, 128,
            	124, 136,
            	17, 144,
            	296, 152,
            	296, 160,
            1, 8, 1, /* 241: pointer.struct.rsa_meth_st */
            	246, 0,
            0, 112, 13, /* 246: struct.rsa_meth_st */
            	63, 0,
            	275, 8,
            	275, 16,
            	275, 24,
            	275, 32,
            	278, 40,
            	281, 48,
            	284, 56,
            	284, 64,
            	17, 80,
            	287, 88,
            	290, 96,
            	293, 104,
            4097, 8, 0, /* 275: pointer.func */
            4097, 8, 0, /* 278: pointer.func */
            4097, 8, 0, /* 281: pointer.func */
            4097, 8, 0, /* 284: pointer.func */
            4097, 8, 0, /* 287: pointer.func */
            4097, 8, 0, /* 290: pointer.func */
            4097, 8, 0, /* 293: pointer.func */
            1, 8, 1, /* 296: pointer.struct.bn_blinding_st */
            	301, 0,
            0, 0, 0, /* 301: struct.bn_blinding_st */
            1, 8, 1, /* 304: pointer.struct.dsa_st */
            	309, 0,
            0, 136, 11, /* 309: struct.dsa_st */
            	106, 24,
            	106, 32,
            	106, 40,
            	106, 48,
            	106, 56,
            	106, 64,
            	106, 72,
            	124, 88,
            	146, 104,
            	334, 120,
            	166, 128,
            1, 8, 1, /* 334: pointer.struct.dsa_method */
            	339, 0,
            0, 96, 11, /* 339: struct.dsa_method */
            	63, 0,
            	364, 8,
            	367, 16,
            	370, 24,
            	180, 32,
            	373, 40,
            	177, 48,
            	177, 56,
            	17, 72,
            	174, 80,
            	177, 88,
            4097, 8, 0, /* 364: pointer.func */
            4097, 8, 0, /* 367: pointer.func */
            4097, 8, 0, /* 370: pointer.func */
            4097, 8, 0, /* 373: pointer.func */
            0, 0, 0, /* 376: struct.evp_pkey_ctx_st */
            0, 56, 4, /* 379: struct.evp_pkey_st */
            	390, 16,
            	166, 24,
            	186, 32,
            	25, 48,
            1, 8, 1, /* 390: pointer.struct.evp_pkey_asn1_method_st */
            	395, 0,
            0, 0, 0, /* 395: struct.evp_pkey_asn1_method_st */
            0, 4, 0, /* 398: int */
            4097, 8, 0, /* 401: pointer.func */
            1, 8, 1, /* 404: pointer.struct.env_md_ctx_st */
            	409, 0,
            0, 48, 5, /* 409: struct.env_md_ctx_st */
            	422, 0,
            	166, 8,
            	464, 24,
            	467, 32,
            	449, 40,
            1, 8, 1, /* 422: pointer.struct.env_md_st */
            	427, 0,
            0, 120, 8, /* 427: struct.env_md_st */
            	446, 24,
            	449, 32,
            	401, 40,
            	452, 48,
            	446, 56,
            	455, 64,
            	458, 72,
            	461, 112,
            4097, 8, 0, /* 446: pointer.func */
            4097, 8, 0, /* 449: pointer.func */
            4097, 8, 0, /* 452: pointer.func */
            4097, 8, 0, /* 455: pointer.func */
            4097, 8, 0, /* 458: pointer.func */
            4097, 8, 0, /* 461: pointer.func */
            0, 8, 0, /* 464: pointer.void */
            1, 8, 1, /* 467: pointer.struct.evp_pkey_ctx_st */
            	376, 0,
            1, 8, 1, /* 472: pointer.struct.evp_pkey_st */
            	379, 0,
        },
        .arg_entity_index = { 404, 138, 116, 472, },
        .ret_entity_index = 398,
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

