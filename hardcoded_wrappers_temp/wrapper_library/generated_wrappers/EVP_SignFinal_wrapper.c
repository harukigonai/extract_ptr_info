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
            4097, 8, 0, /* 0: pointer.func */
            4097, 8, 0, /* 3: pointer.func */
            4097, 8, 0, /* 6: pointer.func */
            4097, 8, 0, /* 9: pointer.func */
            4097, 8, 0, /* 12: pointer.func */
            4097, 8, 0, /* 15: pointer.func */
            4097, 8, 0, /* 18: pointer.func */
            1, 8, 1, /* 21: pointer.struct.evp_pkey_method_st */
            	26, 0,
            0, 208, 25, /* 26: struct.evp_pkey_method_st */
            	79, 8,
            	18, 16,
            	15, 24,
            	79, 32,
            	12, 40,
            	79, 48,
            	12, 56,
            	79, 64,
            	87, 72,
            	79, 80,
            	9, 88,
            	79, 96,
            	87, 104,
            	90, 112,
            	93, 120,
            	90, 128,
            	6, 136,
            	79, 144,
            	87, 152,
            	79, 160,
            	87, 168,
            	79, 176,
            	96, 184,
            	3, 192,
            	0, 200,
            1, 8, 1, /* 79: pointer.struct.unnamed */
            	84, 0,
            0, 0, 0, /* 84: struct.unnamed */
            4097, 8, 0, /* 87: pointer.func */
            4097, 8, 0, /* 90: pointer.func */
            4097, 8, 0, /* 93: pointer.func */
            4097, 8, 0, /* 96: pointer.func */
            0, 80, 8, /* 99: struct.evp_pkey_ctx_st */
            	21, 0,
            	118, 8,
            	474, 16,
            	474, 24,
            	174, 40,
            	174, 48,
            	79, 56,
            	590, 64,
            1, 8, 1, /* 118: pointer.struct.engine_st */
            	123, 0,
            0, 216, 24, /* 123: struct.engine_st */
            	174, 0,
            	174, 8,
            	179, 16,
            	234, 24,
            	285, 32,
            	321, 40,
            	338, 48,
            	365, 56,
            	400, 64,
            	408, 72,
            	411, 80,
            	414, 88,
            	417, 96,
            	420, 104,
            	420, 112,
            	420, 120,
            	423, 128,
            	426, 136,
            	426, 144,
            	429, 152,
            	432, 160,
            	444, 184,
            	118, 200,
            	118, 208,
            1, 8, 1, /* 174: pointer.char */
            	4096, 0,
            1, 8, 1, /* 179: pointer.struct.rsa_meth_st */
            	184, 0,
            0, 112, 13, /* 184: struct.rsa_meth_st */
            	174, 0,
            	213, 8,
            	213, 16,
            	213, 24,
            	213, 32,
            	216, 40,
            	219, 48,
            	222, 56,
            	222, 64,
            	174, 80,
            	225, 88,
            	228, 96,
            	231, 104,
            4097, 8, 0, /* 213: pointer.func */
            4097, 8, 0, /* 216: pointer.func */
            4097, 8, 0, /* 219: pointer.func */
            4097, 8, 0, /* 222: pointer.func */
            4097, 8, 0, /* 225: pointer.func */
            4097, 8, 0, /* 228: pointer.func */
            4097, 8, 0, /* 231: pointer.func */
            1, 8, 1, /* 234: pointer.struct.dsa_method */
            	239, 0,
            0, 96, 11, /* 239: struct.dsa_method */
            	174, 0,
            	264, 8,
            	267, 16,
            	270, 24,
            	273, 32,
            	276, 40,
            	279, 48,
            	279, 56,
            	174, 72,
            	282, 80,
            	279, 88,
            4097, 8, 0, /* 264: pointer.func */
            4097, 8, 0, /* 267: pointer.func */
            4097, 8, 0, /* 270: pointer.func */
            4097, 8, 0, /* 273: pointer.func */
            4097, 8, 0, /* 276: pointer.func */
            4097, 8, 0, /* 279: pointer.func */
            4097, 8, 0, /* 282: pointer.func */
            1, 8, 1, /* 285: pointer.struct.dh_method */
            	290, 0,
            0, 72, 8, /* 290: struct.dh_method */
            	174, 0,
            	309, 8,
            	312, 16,
            	315, 24,
            	309, 32,
            	309, 40,
            	174, 56,
            	318, 64,
            4097, 8, 0, /* 309: pointer.func */
            4097, 8, 0, /* 312: pointer.func */
            4097, 8, 0, /* 315: pointer.func */
            4097, 8, 0, /* 318: pointer.func */
            1, 8, 1, /* 321: pointer.struct.ecdh_method */
            	326, 0,
            0, 32, 3, /* 326: struct.ecdh_method */
            	174, 0,
            	335, 8,
            	174, 24,
            4097, 8, 0, /* 335: pointer.func */
            1, 8, 1, /* 338: pointer.struct.ecdsa_method */
            	343, 0,
            0, 48, 5, /* 343: struct.ecdsa_method */
            	174, 0,
            	356, 8,
            	359, 16,
            	362, 24,
            	174, 40,
            4097, 8, 0, /* 356: pointer.func */
            4097, 8, 0, /* 359: pointer.func */
            4097, 8, 0, /* 362: pointer.func */
            1, 8, 1, /* 365: pointer.struct.rand_meth_st */
            	370, 0,
            0, 48, 6, /* 370: struct.rand_meth_st */
            	385, 0,
            	388, 8,
            	391, 16,
            	394, 24,
            	388, 32,
            	397, 40,
            4097, 8, 0, /* 385: pointer.func */
            4097, 8, 0, /* 388: pointer.func */
            4097, 8, 0, /* 391: pointer.func */
            4097, 8, 0, /* 394: pointer.func */
            4097, 8, 0, /* 397: pointer.func */
            1, 8, 1, /* 400: pointer.struct.store_method_st */
            	405, 0,
            0, 0, 0, /* 405: struct.store_method_st */
            4097, 8, 0, /* 408: pointer.func */
            4097, 8, 0, /* 411: pointer.func */
            4097, 8, 0, /* 414: pointer.func */
            4097, 8, 0, /* 417: pointer.func */
            4097, 8, 0, /* 420: pointer.func */
            4097, 8, 0, /* 423: pointer.func */
            4097, 8, 0, /* 426: pointer.func */
            4097, 8, 0, /* 429: pointer.func */
            1, 8, 1, /* 432: pointer.struct.ENGINE_CMD_DEFN_st */
            	437, 0,
            0, 32, 2, /* 437: struct.ENGINE_CMD_DEFN_st */
            	174, 8,
            	174, 16,
            0, 16, 1, /* 444: struct.crypto_ex_data_st */
            	449, 0,
            1, 8, 1, /* 449: pointer.struct.stack_st_OPENSSL_STRING */
            	454, 0,
            0, 32, 1, /* 454: struct.stack_st_OPENSSL_STRING */
            	459, 0,
            0, 32, 2, /* 459: struct.stack_st */
            	466, 8,
            	471, 24,
            1, 8, 1, /* 466: pointer.pointer.char */
            	174, 0,
            4097, 8, 0, /* 471: pointer.func */
            1, 8, 1, /* 474: pointer.struct.evp_pkey_st */
            	479, 0,
            0, 56, 4, /* 479: struct.evp_pkey_st */
            	490, 16,
            	118, 24,
            	585, 32,
            	449, 48,
            1, 8, 1, /* 490: pointer.struct.evp_pkey_asn1_method_st */
            	495, 0,
            0, 208, 24, /* 495: struct.evp_pkey_asn1_method_st */
            	174, 16,
            	174, 24,
            	79, 32,
            	546, 40,
            	549, 48,
            	552, 56,
            	555, 64,
            	558, 72,
            	552, 80,
            	561, 88,
            	561, 96,
            	564, 104,
            	567, 112,
            	561, 120,
            	549, 128,
            	549, 136,
            	552, 144,
            	570, 152,
            	573, 160,
            	576, 168,
            	564, 176,
            	567, 184,
            	579, 192,
            	582, 200,
            4097, 8, 0, /* 546: pointer.func */
            4097, 8, 0, /* 549: pointer.func */
            4097, 8, 0, /* 552: pointer.func */
            4097, 8, 0, /* 555: pointer.func */
            4097, 8, 0, /* 558: pointer.func */
            4097, 8, 0, /* 561: pointer.func */
            4097, 8, 0, /* 564: pointer.func */
            4097, 8, 0, /* 567: pointer.func */
            4097, 8, 0, /* 570: pointer.func */
            4097, 8, 0, /* 573: pointer.func */
            4097, 8, 0, /* 576: pointer.func */
            4097, 8, 0, /* 579: pointer.func */
            4097, 8, 0, /* 582: pointer.func */
            0, 8, 1, /* 585: struct.fnames */
            	174, 0,
            1, 8, 1, /* 590: pointer.int */
            	595, 0,
            0, 4, 0, /* 595: int */
            1, 8, 1, /* 598: pointer.struct.evp_pkey_ctx_st */
            	99, 0,
            4097, 8, 0, /* 603: pointer.func */
            4097, 8, 0, /* 606: pointer.func */
            4097, 8, 0, /* 609: pointer.func */
            1, 8, 1, /* 612: pointer.struct.env_md_st */
            	617, 0,
            0, 120, 8, /* 617: struct.env_md_st */
            	636, 24,
            	609, 32,
            	639, 40,
            	642, 48,
            	636, 56,
            	606, 64,
            	645, 72,
            	603, 112,
            4097, 8, 0, /* 636: pointer.func */
            4097, 8, 0, /* 639: pointer.func */
            4097, 8, 0, /* 642: pointer.func */
            4097, 8, 0, /* 645: pointer.func */
            0, 48, 5, /* 648: struct.env_md_ctx_st */
            	612, 0,
            	118, 8,
            	174, 24,
            	598, 32,
            	609, 40,
            1, 8, 1, /* 661: pointer.struct.env_md_ctx_st */
            	648, 0,
            0, 1, 0, /* 666: char */
            0, 8, 0, /* 669: pointer.void */
        },
        .arg_entity_index = { 661, 174, 590, 474, },
        .ret_entity_index = 595,
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

