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
            4097, 8, 0, /* 18: pointer.func */
            4097, 8, 0, /* 21: pointer.func */
            4097, 8, 0, /* 24: pointer.func */
            4097, 8, 0, /* 27: pointer.func */
            4097, 8, 0, /* 30: pointer.func */
            4097, 8, 0, /* 33: pointer.func */
            4097, 8, 0, /* 36: pointer.func */
            0, 208, 24, /* 39: struct.evp_pkey_asn1_method_st */
            	13, 16,
            	13, 24,
            	90, 32,
            	98, 40,
            	36, 48,
            	30, 56,
            	101, 64,
            	104, 72,
            	30, 80,
            	27, 88,
            	27, 96,
            	24, 104,
            	107, 112,
            	27, 120,
            	36, 128,
            	36, 136,
            	30, 144,
            	21, 152,
            	18, 160,
            	33, 168,
            	24, 176,
            	107, 184,
            	110, 192,
            	113, 200,
            1, 8, 1, /* 90: pointer.struct.unnamed */
            	95, 0,
            0, 0, 0, /* 95: struct.unnamed */
            4097, 8, 0, /* 98: pointer.func */
            4097, 8, 0, /* 101: pointer.func */
            4097, 8, 0, /* 104: pointer.func */
            4097, 8, 0, /* 107: pointer.func */
            4097, 8, 0, /* 110: pointer.func */
            4097, 8, 0, /* 113: pointer.func */
            0, 56, 4, /* 116: struct.evp_pkey_st */
            	127, 16,
            	132, 24,
            	8, 32,
            	458, 48,
            1, 8, 1, /* 127: pointer.struct.evp_pkey_asn1_method_st */
            	39, 0,
            1, 8, 1, /* 132: pointer.struct.engine_st */
            	137, 0,
            0, 216, 24, /* 137: struct.engine_st */
            	13, 0,
            	13, 8,
            	188, 16,
            	243, 24,
            	294, 32,
            	330, 40,
            	347, 48,
            	374, 56,
            	409, 64,
            	417, 72,
            	420, 80,
            	423, 88,
            	426, 96,
            	429, 104,
            	429, 112,
            	429, 120,
            	432, 128,
            	435, 136,
            	435, 144,
            	438, 152,
            	441, 160,
            	453, 184,
            	132, 200,
            	132, 208,
            1, 8, 1, /* 188: pointer.struct.rsa_meth_st */
            	193, 0,
            0, 112, 13, /* 193: struct.rsa_meth_st */
            	13, 0,
            	222, 8,
            	222, 16,
            	222, 24,
            	222, 32,
            	225, 40,
            	228, 48,
            	231, 56,
            	231, 64,
            	13, 80,
            	234, 88,
            	237, 96,
            	240, 104,
            4097, 8, 0, /* 222: pointer.func */
            4097, 8, 0, /* 225: pointer.func */
            4097, 8, 0, /* 228: pointer.func */
            4097, 8, 0, /* 231: pointer.func */
            4097, 8, 0, /* 234: pointer.func */
            4097, 8, 0, /* 237: pointer.func */
            4097, 8, 0, /* 240: pointer.func */
            1, 8, 1, /* 243: pointer.struct.dsa_method */
            	248, 0,
            0, 96, 11, /* 248: struct.dsa_method */
            	13, 0,
            	273, 8,
            	276, 16,
            	279, 24,
            	282, 32,
            	285, 40,
            	288, 48,
            	288, 56,
            	13, 72,
            	291, 80,
            	288, 88,
            4097, 8, 0, /* 273: pointer.func */
            4097, 8, 0, /* 276: pointer.func */
            4097, 8, 0, /* 279: pointer.func */
            4097, 8, 0, /* 282: pointer.func */
            4097, 8, 0, /* 285: pointer.func */
            4097, 8, 0, /* 288: pointer.func */
            4097, 8, 0, /* 291: pointer.func */
            1, 8, 1, /* 294: pointer.struct.dh_method */
            	299, 0,
            0, 72, 8, /* 299: struct.dh_method */
            	13, 0,
            	318, 8,
            	321, 16,
            	324, 24,
            	318, 32,
            	318, 40,
            	13, 56,
            	327, 64,
            4097, 8, 0, /* 318: pointer.func */
            4097, 8, 0, /* 321: pointer.func */
            4097, 8, 0, /* 324: pointer.func */
            4097, 8, 0, /* 327: pointer.func */
            1, 8, 1, /* 330: pointer.struct.ecdh_method */
            	335, 0,
            0, 32, 3, /* 335: struct.ecdh_method */
            	13, 0,
            	344, 8,
            	13, 24,
            4097, 8, 0, /* 344: pointer.func */
            1, 8, 1, /* 347: pointer.struct.ecdsa_method */
            	352, 0,
            0, 48, 5, /* 352: struct.ecdsa_method */
            	13, 0,
            	365, 8,
            	368, 16,
            	371, 24,
            	13, 40,
            4097, 8, 0, /* 365: pointer.func */
            4097, 8, 0, /* 368: pointer.func */
            4097, 8, 0, /* 371: pointer.func */
            1, 8, 1, /* 374: pointer.struct.rand_meth_st */
            	379, 0,
            0, 48, 6, /* 379: struct.rand_meth_st */
            	394, 0,
            	397, 8,
            	400, 16,
            	403, 24,
            	397, 32,
            	406, 40,
            4097, 8, 0, /* 394: pointer.func */
            4097, 8, 0, /* 397: pointer.func */
            4097, 8, 0, /* 400: pointer.func */
            4097, 8, 0, /* 403: pointer.func */
            4097, 8, 0, /* 406: pointer.func */
            1, 8, 1, /* 409: pointer.struct.store_method_st */
            	414, 0,
            0, 0, 0, /* 414: struct.store_method_st */
            4097, 8, 0, /* 417: pointer.func */
            4097, 8, 0, /* 420: pointer.func */
            4097, 8, 0, /* 423: pointer.func */
            4097, 8, 0, /* 426: pointer.func */
            4097, 8, 0, /* 429: pointer.func */
            4097, 8, 0, /* 432: pointer.func */
            4097, 8, 0, /* 435: pointer.func */
            4097, 8, 0, /* 438: pointer.func */
            1, 8, 1, /* 441: pointer.struct.ENGINE_CMD_DEFN_st */
            	446, 0,
            0, 32, 2, /* 446: struct.ENGINE_CMD_DEFN_st */
            	13, 8,
            	13, 16,
            0, 16, 1, /* 453: struct.crypto_ex_data_st */
            	458, 0,
            1, 8, 1, /* 458: pointer.struct.stack_st_OPENSSL_STRING */
            	463, 0,
            0, 32, 1, /* 463: struct.stack_st_OPENSSL_STRING */
            	468, 0,
            0, 32, 2, /* 468: struct.stack_st */
            	475, 8,
            	480, 24,
            1, 8, 1, /* 475: pointer.pointer.char */
            	13, 0,
            4097, 8, 0, /* 480: pointer.func */
            1, 8, 1, /* 483: pointer.struct.evp_pkey_st */
            	116, 0,
            4097, 8, 0, /* 488: pointer.func */
            4097, 8, 0, /* 491: pointer.func */
            4097, 8, 0, /* 494: pointer.func */
            4097, 8, 0, /* 497: pointer.func */
            4097, 8, 0, /* 500: pointer.func */
            4097, 8, 0, /* 503: pointer.func */
            4097, 8, 0, /* 506: pointer.func */
            1, 8, 1, /* 509: pointer.struct.evp_pkey_method_st */
            	514, 0,
            0, 208, 25, /* 514: struct.evp_pkey_method_st */
            	90, 8,
            	506, 16,
            	503, 24,
            	90, 32,
            	500, 40,
            	90, 48,
            	500, 56,
            	90, 64,
            	567, 72,
            	90, 80,
            	497, 88,
            	90, 96,
            	567, 104,
            	570, 112,
            	573, 120,
            	570, 128,
            	494, 136,
            	90, 144,
            	567, 152,
            	90, 160,
            	567, 168,
            	90, 176,
            	576, 184,
            	491, 192,
            	488, 200,
            4097, 8, 0, /* 567: pointer.func */
            4097, 8, 0, /* 570: pointer.func */
            4097, 8, 0, /* 573: pointer.func */
            4097, 8, 0, /* 576: pointer.func */
            0, 80, 8, /* 579: struct.evp_pkey_ctx_st */
            	509, 0,
            	132, 8,
            	483, 16,
            	483, 24,
            	13, 40,
            	13, 48,
            	90, 56,
            	0, 64,
            1, 8, 1, /* 598: pointer.struct.evp_pkey_ctx_st */
            	579, 0,
            4097, 8, 0, /* 603: pointer.func */
            0, 8, 0, /* 606: long */
            0, 1, 0, /* 609: char */
            4097, 8, 0, /* 612: pointer.func */
            1, 8, 1, /* 615: pointer.struct.env_md_ctx_st */
            	620, 0,
            0, 48, 5, /* 620: struct.env_md_ctx_st */
            	633, 0,
            	132, 8,
            	13, 24,
            	598, 32,
            	660, 40,
            1, 8, 1, /* 633: pointer.struct.env_md_st */
            	638, 0,
            0, 120, 8, /* 638: struct.env_md_st */
            	657, 24,
            	660, 32,
            	663, 40,
            	666, 48,
            	657, 56,
            	669, 64,
            	603, 72,
            	612, 112,
            4097, 8, 0, /* 657: pointer.func */
            4097, 8, 0, /* 660: pointer.func */
            4097, 8, 0, /* 663: pointer.func */
            4097, 8, 0, /* 666: pointer.func */
            4097, 8, 0, /* 669: pointer.func */
            0, 8, 0, /* 672: pointer.void */
        },
        .arg_entity_index = { 615, 672, 606, },
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

