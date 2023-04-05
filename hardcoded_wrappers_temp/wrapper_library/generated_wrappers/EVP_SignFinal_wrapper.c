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
            64097, 8, 0, /* 3: pointer.func */
            0, 56, 4, /* 6: struct.evp_pkey_st */
            	17, 16,
            	25, 24,
            	33, 32,
            	385, 48,
            1, 8, 1, /* 17: pointer.struct.evp_pkey_asn1_method_st */
            	22, 0,
            0, 0, 0, /* 22: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 25: pointer.struct.engine_st */
            	30, 0,
            0, 0, 0, /* 30: struct.engine_st */
            0, 8, 5, /* 33: union.unknown */
            	46, 0,
            	51, 0,
            	223, 0,
            	301, 0,
            	377, 0,
            1, 8, 1, /* 46: pointer.char */
            	64096, 0,
            1, 8, 1, /* 51: pointer.struct.rsa_st */
            	56, 0,
            0, 168, 17, /* 56: struct.rsa_st */
            	93, 16,
            	25, 24,
            	153, 32,
            	153, 40,
            	153, 48,
            	153, 56,
            	153, 64,
            	153, 72,
            	153, 80,
            	153, 88,
            	171, 96,
            	201, 120,
            	201, 128,
            	201, 136,
            	46, 144,
            	215, 152,
            	215, 160,
            1, 8, 1, /* 93: pointer.struct.rsa_meth_st */
            	98, 0,
            0, 112, 13, /* 98: struct.rsa_meth_st */
            	127, 0,
            	132, 8,
            	132, 16,
            	132, 24,
            	132, 32,
            	135, 40,
            	138, 48,
            	141, 56,
            	141, 64,
            	46, 80,
            	144, 88,
            	147, 96,
            	150, 104,
            1, 8, 1, /* 127: pointer.char */
            	64096, 0,
            64097, 8, 0, /* 132: pointer.func */
            64097, 8, 0, /* 135: pointer.func */
            64097, 8, 0, /* 138: pointer.func */
            64097, 8, 0, /* 141: pointer.func */
            64097, 8, 0, /* 144: pointer.func */
            64097, 8, 0, /* 147: pointer.func */
            64097, 8, 0, /* 150: pointer.func */
            1, 8, 1, /* 153: pointer.struct.bignum_st */
            	158, 0,
            0, 24, 1, /* 158: struct.bignum_st */
            	163, 0,
            1, 8, 1, /* 163: pointer.unsigned int */
            	168, 0,
            0, 4, 0, /* 168: unsigned int */
            0, 16, 1, /* 171: struct.crypto_ex_data_st */
            	176, 0,
            1, 8, 1, /* 176: pointer.struct.stack_st_void */
            	181, 0,
            0, 32, 1, /* 181: struct.stack_st_void */
            	186, 0,
            0, 32, 2, /* 186: struct.stack_st */
            	193, 8,
            	198, 24,
            1, 8, 1, /* 193: pointer.pointer.char */
            	46, 0,
            64097, 8, 0, /* 198: pointer.func */
            1, 8, 1, /* 201: pointer.struct.bn_mont_ctx_st */
            	206, 0,
            0, 96, 3, /* 206: struct.bn_mont_ctx_st */
            	158, 8,
            	158, 32,
            	158, 56,
            1, 8, 1, /* 215: pointer.struct.bn_blinding_st */
            	220, 0,
            0, 0, 0, /* 220: struct.bn_blinding_st */
            1, 8, 1, /* 223: pointer.struct.dsa_st */
            	228, 0,
            0, 136, 11, /* 228: struct.dsa_st */
            	153, 24,
            	153, 32,
            	153, 40,
            	153, 48,
            	153, 56,
            	153, 64,
            	153, 72,
            	201, 88,
            	171, 104,
            	253, 120,
            	25, 128,
            1, 8, 1, /* 253: pointer.struct.dsa_method */
            	258, 0,
            0, 96, 11, /* 258: struct.dsa_method */
            	127, 0,
            	283, 8,
            	3, 16,
            	286, 24,
            	289, 32,
            	292, 40,
            	295, 48,
            	295, 56,
            	46, 72,
            	298, 80,
            	295, 88,
            64097, 8, 0, /* 283: pointer.func */
            64097, 8, 0, /* 286: pointer.func */
            64097, 8, 0, /* 289: pointer.func */
            64097, 8, 0, /* 292: pointer.func */
            64097, 8, 0, /* 295: pointer.func */
            64097, 8, 0, /* 298: pointer.func */
            1, 8, 1, /* 301: pointer.struct.dh_st */
            	306, 0,
            0, 144, 12, /* 306: struct.dh_st */
            	153, 8,
            	153, 16,
            	153, 32,
            	153, 40,
            	201, 56,
            	153, 64,
            	153, 72,
            	333, 80,
            	153, 96,
            	171, 112,
            	341, 128,
            	25, 136,
            1, 8, 1, /* 333: pointer.unsigned char */
            	338, 0,
            0, 1, 0, /* 338: unsigned char */
            1, 8, 1, /* 341: pointer.struct.dh_method */
            	346, 0,
            0, 72, 8, /* 346: struct.dh_method */
            	127, 0,
            	365, 8,
            	368, 16,
            	371, 24,
            	365, 32,
            	365, 40,
            	46, 56,
            	374, 64,
            64097, 8, 0, /* 365: pointer.func */
            64097, 8, 0, /* 368: pointer.func */
            64097, 8, 0, /* 371: pointer.func */
            64097, 8, 0, /* 374: pointer.func */
            1, 8, 1, /* 377: pointer.struct.ec_key_st */
            	382, 0,
            0, 0, 0, /* 382: struct.ec_key_st */
            1, 8, 1, /* 385: pointer.struct.stack_st_X509_ATTRIBUTE */
            	390, 0,
            0, 32, 2, /* 390: struct.stack_st_fake_X509_ATTRIBUTE */
            	397, 8,
            	198, 24,
            64099, 8, 2, /* 397: pointer_to_array_of_pointers_to_stack */
            	404, 0,
            	628, 20,
            0, 8, 1, /* 404: pointer.X509_ATTRIBUTE */
            	409, 0,
            0, 0, 1, /* 409: X509_ATTRIBUTE */
            	414, 0,
            0, 24, 2, /* 414: struct.x509_attributes_st */
            	421, 0,
            	440, 16,
            1, 8, 1, /* 421: pointer.struct.asn1_object_st */
            	426, 0,
            0, 40, 3, /* 426: struct.asn1_object_st */
            	127, 0,
            	127, 8,
            	435, 24,
            1, 8, 1, /* 435: pointer.unsigned char */
            	338, 0,
            0, 8, 3, /* 440: union.unknown */
            	46, 0,
            	449, 0,
            	631, 0,
            1, 8, 1, /* 449: pointer.struct.stack_st_ASN1_TYPE */
            	454, 0,
            0, 32, 2, /* 454: struct.stack_st_fake_ASN1_TYPE */
            	461, 8,
            	198, 24,
            64099, 8, 2, /* 461: pointer_to_array_of_pointers_to_stack */
            	468, 0,
            	628, 20,
            0, 8, 1, /* 468: pointer.ASN1_TYPE */
            	473, 0,
            0, 0, 1, /* 473: ASN1_TYPE */
            	478, 0,
            0, 16, 1, /* 478: struct.asn1_type_st */
            	483, 8,
            0, 8, 20, /* 483: union.unknown */
            	46, 0,
            	526, 0,
            	536, 0,
            	550, 0,
            	555, 0,
            	560, 0,
            	565, 0,
            	570, 0,
            	575, 0,
            	580, 0,
            	585, 0,
            	590, 0,
            	595, 0,
            	600, 0,
            	605, 0,
            	610, 0,
            	615, 0,
            	526, 0,
            	526, 0,
            	620, 0,
            1, 8, 1, /* 526: pointer.struct.asn1_string_st */
            	531, 0,
            0, 24, 1, /* 531: struct.asn1_string_st */
            	333, 8,
            1, 8, 1, /* 536: pointer.struct.asn1_object_st */
            	541, 0,
            0, 40, 3, /* 541: struct.asn1_object_st */
            	127, 0,
            	127, 8,
            	435, 24,
            1, 8, 1, /* 550: pointer.struct.asn1_string_st */
            	531, 0,
            1, 8, 1, /* 555: pointer.struct.asn1_string_st */
            	531, 0,
            1, 8, 1, /* 560: pointer.struct.asn1_string_st */
            	531, 0,
            1, 8, 1, /* 565: pointer.struct.asn1_string_st */
            	531, 0,
            1, 8, 1, /* 570: pointer.struct.asn1_string_st */
            	531, 0,
            1, 8, 1, /* 575: pointer.struct.asn1_string_st */
            	531, 0,
            1, 8, 1, /* 580: pointer.struct.asn1_string_st */
            	531, 0,
            1, 8, 1, /* 585: pointer.struct.asn1_string_st */
            	531, 0,
            1, 8, 1, /* 590: pointer.struct.asn1_string_st */
            	531, 0,
            1, 8, 1, /* 595: pointer.struct.asn1_string_st */
            	531, 0,
            1, 8, 1, /* 600: pointer.struct.asn1_string_st */
            	531, 0,
            1, 8, 1, /* 605: pointer.struct.asn1_string_st */
            	531, 0,
            1, 8, 1, /* 610: pointer.struct.asn1_string_st */
            	531, 0,
            1, 8, 1, /* 615: pointer.struct.asn1_string_st */
            	531, 0,
            1, 8, 1, /* 620: pointer.struct.ASN1_VALUE_st */
            	625, 0,
            0, 0, 0, /* 625: struct.ASN1_VALUE_st */
            0, 4, 0, /* 628: int */
            1, 8, 1, /* 631: pointer.struct.asn1_type_st */
            	636, 0,
            0, 16, 1, /* 636: struct.asn1_type_st */
            	641, 8,
            0, 8, 20, /* 641: union.unknown */
            	46, 0,
            	684, 0,
            	421, 0,
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
            	333, 8,
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
            64097, 8, 0, /* 769: pointer.func */
            0, 8, 0, /* 772: pointer.void */
            1, 8, 1, /* 775: pointer.struct.env_md_ctx_st */
            	780, 0,
            0, 48, 5, /* 780: struct.env_md_ctx_st */
            	793, 0,
            	25, 8,
            	772, 24,
            	835, 32,
            	820, 40,
            1, 8, 1, /* 793: pointer.struct.env_md_st */
            	798, 0,
            0, 120, 8, /* 798: struct.env_md_st */
            	817, 24,
            	820, 32,
            	823, 40,
            	769, 48,
            	817, 56,
            	826, 64,
            	829, 72,
            	832, 112,
            64097, 8, 0, /* 817: pointer.func */
            64097, 8, 0, /* 820: pointer.func */
            64097, 8, 0, /* 823: pointer.func */
            64097, 8, 0, /* 826: pointer.func */
            64097, 8, 0, /* 829: pointer.func */
            64097, 8, 0, /* 832: pointer.func */
            1, 8, 1, /* 835: pointer.struct.evp_pkey_ctx_st */
            	840, 0,
            0, 0, 0, /* 840: struct.evp_pkey_ctx_st */
            1, 8, 1, /* 843: pointer.struct.evp_pkey_st */
            	6, 0,
            0, 1, 0, /* 848: char */
        },
        .arg_entity_index = { 775, 333, 163, 843, },
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

