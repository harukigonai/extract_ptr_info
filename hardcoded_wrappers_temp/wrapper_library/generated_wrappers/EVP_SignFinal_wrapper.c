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
            0, 0, 0, /* 0: struct.ASN1_VALUE_st */
            1, 8, 1, /* 3: pointer.struct.asn1_string_st */
            	8, 0,
            0, 24, 1, /* 8: struct.asn1_string_st */
            	13, 8,
            1, 8, 1, /* 13: pointer.unsigned char */
            	18, 0,
            0, 1, 0, /* 18: unsigned char */
            0, 136, 11, /* 21: struct.dsa_st */
            	46, 24,
            	46, 32,
            	46, 40,
            	46, 48,
            	46, 56,
            	46, 64,
            	46, 72,
            	64, 88,
            	78, 104,
            	113, 120,
            	169, 128,
            1, 8, 1, /* 46: pointer.struct.bignum_st */
            	51, 0,
            0, 24, 1, /* 51: struct.bignum_st */
            	56, 0,
            1, 8, 1, /* 56: pointer.unsigned int */
            	61, 0,
            0, 4, 0, /* 61: unsigned int */
            1, 8, 1, /* 64: pointer.struct.bn_mont_ctx_st */
            	69, 0,
            0, 96, 3, /* 69: struct.bn_mont_ctx_st */
            	51, 8,
            	51, 32,
            	51, 56,
            0, 16, 1, /* 78: struct.crypto_ex_data_st */
            	83, 0,
            1, 8, 1, /* 83: pointer.struct.stack_st_void */
            	88, 0,
            0, 32, 1, /* 88: struct.stack_st_void */
            	93, 0,
            0, 32, 2, /* 93: struct.stack_st */
            	100, 8,
            	110, 24,
            1, 8, 1, /* 100: pointer.pointer.char */
            	105, 0,
            1, 8, 1, /* 105: pointer.char */
            	8884096, 0,
            8884097, 8, 0, /* 110: pointer.func */
            1, 8, 1, /* 113: pointer.struct.dsa_method */
            	118, 0,
            0, 96, 11, /* 118: struct.dsa_method */
            	143, 0,
            	148, 8,
            	151, 16,
            	154, 24,
            	157, 32,
            	160, 40,
            	163, 48,
            	163, 56,
            	105, 72,
            	166, 80,
            	163, 88,
            1, 8, 1, /* 143: pointer.char */
            	8884096, 0,
            8884097, 8, 0, /* 148: pointer.func */
            8884097, 8, 0, /* 151: pointer.func */
            8884097, 8, 0, /* 154: pointer.func */
            8884097, 8, 0, /* 157: pointer.func */
            8884097, 8, 0, /* 160: pointer.func */
            8884097, 8, 0, /* 163: pointer.func */
            8884097, 8, 0, /* 166: pointer.func */
            1, 8, 1, /* 169: pointer.struct.engine_st */
            	174, 0,
            0, 0, 0, /* 174: struct.engine_st */
            0, 56, 4, /* 177: struct.evp_pkey_st */
            	188, 16,
            	169, 24,
            	196, 32,
            	395, 48,
            1, 8, 1, /* 188: pointer.struct.evp_pkey_asn1_method_st */
            	193, 0,
            0, 0, 0, /* 193: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 196: union.unknown */
            	105, 0,
            	209, 0,
            	314, 0,
            	319, 0,
            	387, 0,
            1, 8, 1, /* 209: pointer.struct.rsa_st */
            	214, 0,
            0, 168, 17, /* 214: struct.rsa_st */
            	251, 16,
            	169, 24,
            	46, 32,
            	46, 40,
            	46, 48,
            	46, 56,
            	46, 64,
            	46, 72,
            	46, 80,
            	46, 88,
            	78, 96,
            	64, 120,
            	64, 128,
            	64, 136,
            	105, 144,
            	306, 152,
            	306, 160,
            1, 8, 1, /* 251: pointer.struct.rsa_meth_st */
            	256, 0,
            0, 112, 13, /* 256: struct.rsa_meth_st */
            	143, 0,
            	285, 8,
            	285, 16,
            	285, 24,
            	285, 32,
            	288, 40,
            	291, 48,
            	294, 56,
            	294, 64,
            	105, 80,
            	297, 88,
            	300, 96,
            	303, 104,
            8884097, 8, 0, /* 285: pointer.func */
            8884097, 8, 0, /* 288: pointer.func */
            8884097, 8, 0, /* 291: pointer.func */
            8884097, 8, 0, /* 294: pointer.func */
            8884097, 8, 0, /* 297: pointer.func */
            8884097, 8, 0, /* 300: pointer.func */
            8884097, 8, 0, /* 303: pointer.func */
            1, 8, 1, /* 306: pointer.struct.bn_blinding_st */
            	311, 0,
            0, 0, 0, /* 311: struct.bn_blinding_st */
            1, 8, 1, /* 314: pointer.struct.dsa_st */
            	21, 0,
            1, 8, 1, /* 319: pointer.struct.dh_st */
            	324, 0,
            0, 144, 12, /* 324: struct.dh_st */
            	46, 8,
            	46, 16,
            	46, 32,
            	46, 40,
            	64, 56,
            	46, 64,
            	46, 72,
            	13, 80,
            	46, 96,
            	78, 112,
            	351, 128,
            	169, 136,
            1, 8, 1, /* 351: pointer.struct.dh_method */
            	356, 0,
            0, 72, 8, /* 356: struct.dh_method */
            	143, 0,
            	375, 8,
            	378, 16,
            	381, 24,
            	375, 32,
            	375, 40,
            	105, 56,
            	384, 64,
            8884097, 8, 0, /* 375: pointer.func */
            8884097, 8, 0, /* 378: pointer.func */
            8884097, 8, 0, /* 381: pointer.func */
            8884097, 8, 0, /* 384: pointer.func */
            1, 8, 1, /* 387: pointer.struct.ec_key_st */
            	392, 0,
            0, 0, 0, /* 392: struct.ec_key_st */
            1, 8, 1, /* 395: pointer.struct.stack_st_X509_ATTRIBUTE */
            	400, 0,
            0, 32, 2, /* 400: struct.stack_st_fake_X509_ATTRIBUTE */
            	407, 8,
            	110, 24,
            8884099, 8, 2, /* 407: pointer_to_array_of_pointers_to_stack */
            	414, 0,
            	628, 20,
            0, 8, 1, /* 414: pointer.X509_ATTRIBUTE */
            	419, 0,
            0, 0, 1, /* 419: X509_ATTRIBUTE */
            	424, 0,
            0, 24, 2, /* 424: struct.x509_attributes_st */
            	431, 0,
            	450, 16,
            1, 8, 1, /* 431: pointer.struct.asn1_object_st */
            	436, 0,
            0, 40, 3, /* 436: struct.asn1_object_st */
            	143, 0,
            	143, 8,
            	445, 24,
            1, 8, 1, /* 445: pointer.unsigned char */
            	18, 0,
            0, 8, 3, /* 450: union.unknown */
            	105, 0,
            	459, 0,
            	631, 0,
            1, 8, 1, /* 459: pointer.struct.stack_st_ASN1_TYPE */
            	464, 0,
            0, 32, 2, /* 464: struct.stack_st_fake_ASN1_TYPE */
            	471, 8,
            	110, 24,
            8884099, 8, 2, /* 471: pointer_to_array_of_pointers_to_stack */
            	478, 0,
            	628, 20,
            0, 8, 1, /* 478: pointer.ASN1_TYPE */
            	483, 0,
            0, 0, 1, /* 483: ASN1_TYPE */
            	488, 0,
            0, 16, 1, /* 488: struct.asn1_type_st */
            	493, 8,
            0, 8, 20, /* 493: union.unknown */
            	105, 0,
            	536, 0,
            	541, 0,
            	555, 0,
            	560, 0,
            	565, 0,
            	570, 0,
            	575, 0,
            	3, 0,
            	580, 0,
            	585, 0,
            	590, 0,
            	595, 0,
            	600, 0,
            	605, 0,
            	610, 0,
            	615, 0,
            	536, 0,
            	536, 0,
            	620, 0,
            1, 8, 1, /* 536: pointer.struct.asn1_string_st */
            	8, 0,
            1, 8, 1, /* 541: pointer.struct.asn1_object_st */
            	546, 0,
            0, 40, 3, /* 546: struct.asn1_object_st */
            	143, 0,
            	143, 8,
            	445, 24,
            1, 8, 1, /* 555: pointer.struct.asn1_string_st */
            	8, 0,
            1, 8, 1, /* 560: pointer.struct.asn1_string_st */
            	8, 0,
            1, 8, 1, /* 565: pointer.struct.asn1_string_st */
            	8, 0,
            1, 8, 1, /* 570: pointer.struct.asn1_string_st */
            	8, 0,
            1, 8, 1, /* 575: pointer.struct.asn1_string_st */
            	8, 0,
            1, 8, 1, /* 580: pointer.struct.asn1_string_st */
            	8, 0,
            1, 8, 1, /* 585: pointer.struct.asn1_string_st */
            	8, 0,
            1, 8, 1, /* 590: pointer.struct.asn1_string_st */
            	8, 0,
            1, 8, 1, /* 595: pointer.struct.asn1_string_st */
            	8, 0,
            1, 8, 1, /* 600: pointer.struct.asn1_string_st */
            	8, 0,
            1, 8, 1, /* 605: pointer.struct.asn1_string_st */
            	8, 0,
            1, 8, 1, /* 610: pointer.struct.asn1_string_st */
            	8, 0,
            1, 8, 1, /* 615: pointer.struct.asn1_string_st */
            	8, 0,
            1, 8, 1, /* 620: pointer.struct.ASN1_VALUE_st */
            	625, 0,
            0, 0, 0, /* 625: struct.ASN1_VALUE_st */
            0, 4, 0, /* 628: int */
            1, 8, 1, /* 631: pointer.struct.asn1_type_st */
            	636, 0,
            0, 16, 1, /* 636: struct.asn1_type_st */
            	641, 8,
            0, 8, 20, /* 641: union.unknown */
            	105, 0,
            	684, 0,
            	431, 0,
            	694, 0,
            	699, 0,
            	704, 0,
            	709, 0,
            	714, 0,
            	719, 0,
            	724, 0,
            	729, 0,
            	734, 0,
            	739, 0,
            	744, 0,
            	749, 0,
            	754, 0,
            	759, 0,
            	684, 0,
            	684, 0,
            	764, 0,
            1, 8, 1, /* 684: pointer.struct.asn1_string_st */
            	689, 0,
            0, 24, 1, /* 689: struct.asn1_string_st */
            	13, 8,
            1, 8, 1, /* 694: pointer.struct.asn1_string_st */
            	689, 0,
            1, 8, 1, /* 699: pointer.struct.asn1_string_st */
            	689, 0,
            1, 8, 1, /* 704: pointer.struct.asn1_string_st */
            	689, 0,
            1, 8, 1, /* 709: pointer.struct.asn1_string_st */
            	689, 0,
            1, 8, 1, /* 714: pointer.struct.asn1_string_st */
            	689, 0,
            1, 8, 1, /* 719: pointer.struct.asn1_string_st */
            	689, 0,
            1, 8, 1, /* 724: pointer.struct.asn1_string_st */
            	689, 0,
            1, 8, 1, /* 729: pointer.struct.asn1_string_st */
            	689, 0,
            1, 8, 1, /* 734: pointer.struct.asn1_string_st */
            	689, 0,
            1, 8, 1, /* 739: pointer.struct.asn1_string_st */
            	689, 0,
            1, 8, 1, /* 744: pointer.struct.asn1_string_st */
            	689, 0,
            1, 8, 1, /* 749: pointer.struct.asn1_string_st */
            	689, 0,
            1, 8, 1, /* 754: pointer.struct.asn1_string_st */
            	689, 0,
            1, 8, 1, /* 759: pointer.struct.asn1_string_st */
            	689, 0,
            1, 8, 1, /* 764: pointer.struct.ASN1_VALUE_st */
            	0, 0,
            8884097, 8, 0, /* 769: pointer.func */
            1, 8, 1, /* 772: pointer.struct.env_md_ctx_st */
            	777, 0,
            0, 48, 5, /* 777: struct.env_md_ctx_st */
            	790, 0,
            	169, 8,
            	832, 24,
            	835, 32,
            	817, 40,
            1, 8, 1, /* 790: pointer.struct.env_md_st */
            	795, 0,
            0, 120, 8, /* 795: struct.env_md_st */
            	814, 24,
            	817, 32,
            	820, 40,
            	769, 48,
            	814, 56,
            	823, 64,
            	826, 72,
            	829, 112,
            8884097, 8, 0, /* 814: pointer.func */
            8884097, 8, 0, /* 817: pointer.func */
            8884097, 8, 0, /* 820: pointer.func */
            8884097, 8, 0, /* 823: pointer.func */
            8884097, 8, 0, /* 826: pointer.func */
            8884097, 8, 0, /* 829: pointer.func */
            0, 8, 0, /* 832: pointer.void */
            1, 8, 1, /* 835: pointer.struct.evp_pkey_ctx_st */
            	840, 0,
            0, 0, 0, /* 840: struct.evp_pkey_ctx_st */
            1, 8, 1, /* 843: pointer.struct.evp_pkey_st */
            	177, 0,
            0, 1, 0, /* 848: char */
        },
        .arg_entity_index = { 772, 13, 56, 843, },
        .ret_entity_index = 628,
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

