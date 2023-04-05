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
            0, 32, 1, /* 0: struct.stack_st_X509_ALGOR */
            	5, 0,
            0, 32, 2, /* 5: struct.stack_st */
            	12, 8,
            	22, 24,
            1, 8, 1, /* 12: pointer.pointer.char */
            	17, 0,
            1, 8, 1, /* 17: pointer.char */
            	4096, 0,
            4097, 8, 0, /* 22: pointer.func */
            1, 8, 1, /* 25: pointer.struct.stack_st_ASN1_OBJECT */
            	30, 0,
            0, 32, 1, /* 30: struct.stack_st_ASN1_OBJECT */
            	5, 0,
            0, 32, 1, /* 35: struct.stack_st_DIST_POINT */
            	5, 0,
            1, 8, 1, /* 40: pointer.struct.stack_st_DIST_POINT */
            	35, 0,
            0, 0, 0, /* 45: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 48: pointer.struct.X509_POLICY_CACHE_st */
            	45, 0,
            1, 8, 1, /* 53: pointer.struct.NAME_CONSTRAINTS_st */
            	58, 0,
            0, 16, 2, /* 58: struct.NAME_CONSTRAINTS_st */
            	65, 0,
            	65, 8,
            1, 8, 1, /* 65: pointer.struct.stack_st_GENERAL_SUBTREE */
            	70, 0,
            0, 32, 1, /* 70: struct.stack_st_GENERAL_SUBTREE */
            	5, 0,
            1, 8, 1, /* 75: pointer.struct.stack_st_GENERAL_NAME */
            	80, 0,
            0, 32, 1, /* 80: struct.stack_st_GENERAL_NAME */
            	5, 0,
            1, 8, 1, /* 85: pointer.struct.stack_st_X509_EXTENSION */
            	90, 0,
            0, 32, 1, /* 90: struct.stack_st_X509_EXTENSION */
            	5, 0,
            0, 32, 1, /* 95: struct.stack_st_X509_ATTRIBUTE */
            	5, 0,
            1, 8, 1, /* 100: pointer.struct.stack_st_X509_ATTRIBUTE */
            	95, 0,
            1, 8, 1, /* 105: pointer.struct.ec_key_st */
            	110, 0,
            0, 0, 0, /* 110: struct.ec_key_st */
            4097, 8, 0, /* 113: pointer.func */
            4097, 8, 0, /* 116: pointer.func */
            0, 72, 8, /* 119: struct.dh_method */
            	138, 0,
            	143, 8,
            	116, 16,
            	113, 24,
            	143, 32,
            	143, 40,
            	17, 56,
            	146, 64,
            1, 8, 1, /* 138: pointer.char */
            	4096, 0,
            4097, 8, 0, /* 143: pointer.func */
            4097, 8, 0, /* 146: pointer.func */
            1, 8, 1, /* 149: pointer.struct.dh_method */
            	119, 0,
            0, 144, 12, /* 154: struct.dh_st */
            	181, 8,
            	181, 16,
            	181, 32,
            	181, 40,
            	199, 56,
            	181, 64,
            	181, 72,
            	213, 80,
            	181, 96,
            	221, 112,
            	149, 128,
            	236, 136,
            1, 8, 1, /* 181: pointer.struct.bignum_st */
            	186, 0,
            0, 24, 1, /* 186: struct.bignum_st */
            	191, 0,
            1, 8, 1, /* 191: pointer.unsigned int */
            	196, 0,
            0, 4, 0, /* 196: unsigned int */
            1, 8, 1, /* 199: pointer.struct.bn_mont_ctx_st */
            	204, 0,
            0, 96, 3, /* 204: struct.bn_mont_ctx_st */
            	186, 8,
            	186, 32,
            	186, 56,
            1, 8, 1, /* 213: pointer.unsigned char */
            	218, 0,
            0, 1, 0, /* 218: unsigned char */
            0, 16, 1, /* 221: struct.crypto_ex_data_st */
            	226, 0,
            1, 8, 1, /* 226: pointer.struct.stack_st_void */
            	231, 0,
            0, 32, 1, /* 231: struct.stack_st_void */
            	5, 0,
            1, 8, 1, /* 236: pointer.struct.engine_st */
            	241, 0,
            0, 0, 0, /* 241: struct.engine_st */
            4097, 8, 0, /* 244: pointer.func */
            4097, 8, 0, /* 247: pointer.func */
            0, 136, 11, /* 250: struct.dsa_st */
            	181, 24,
            	181, 32,
            	181, 40,
            	181, 48,
            	181, 56,
            	181, 64,
            	181, 72,
            	199, 88,
            	221, 104,
            	275, 120,
            	236, 128,
            1, 8, 1, /* 275: pointer.struct.dsa_method */
            	280, 0,
            0, 96, 11, /* 280: struct.dsa_method */
            	138, 0,
            	247, 8,
            	305, 16,
            	244, 24,
            	308, 32,
            	311, 40,
            	314, 48,
            	314, 56,
            	17, 72,
            	317, 80,
            	314, 88,
            4097, 8, 0, /* 305: pointer.func */
            4097, 8, 0, /* 308: pointer.func */
            4097, 8, 0, /* 311: pointer.func */
            4097, 8, 0, /* 314: pointer.func */
            4097, 8, 0, /* 317: pointer.func */
            0, 0, 0, /* 320: struct.bn_blinding_st */
            4097, 8, 0, /* 323: pointer.func */
            1, 8, 1, /* 326: pointer.struct.stack_st_GENERAL_NAME */
            	80, 0,
            4097, 8, 0, /* 331: pointer.func */
            4097, 8, 0, /* 334: pointer.func */
            4097, 8, 0, /* 337: pointer.func */
            0, 112, 13, /* 340: struct.rsa_meth_st */
            	138, 0,
            	369, 8,
            	369, 16,
            	369, 24,
            	369, 32,
            	372, 40,
            	375, 48,
            	337, 56,
            	337, 64,
            	17, 80,
            	334, 88,
            	331, 96,
            	323, 104,
            4097, 8, 0, /* 369: pointer.func */
            4097, 8, 0, /* 372: pointer.func */
            4097, 8, 0, /* 375: pointer.func */
            1, 8, 1, /* 378: pointer.struct.rsa_meth_st */
            	340, 0,
            1, 8, 1, /* 383: pointer.struct.dsa_st */
            	250, 0,
            1, 8, 1, /* 388: pointer.struct.asn1_string_st */
            	393, 0,
            0, 24, 1, /* 393: struct.asn1_string_st */
            	213, 8,
            0, 16, 1, /* 398: struct.asn1_type_st */
            	403, 8,
            0, 8, 20, /* 403: union.unknown */
            	17, 0,
            	446, 0,
            	451, 0,
            	470, 0,
            	475, 0,
            	480, 0,
            	485, 0,
            	490, 0,
            	495, 0,
            	500, 0,
            	505, 0,
            	388, 0,
            	510, 0,
            	515, 0,
            	520, 0,
            	525, 0,
            	530, 0,
            	446, 0,
            	446, 0,
            	535, 0,
            1, 8, 1, /* 446: pointer.struct.asn1_string_st */
            	393, 0,
            1, 8, 1, /* 451: pointer.struct.asn1_object_st */
            	456, 0,
            0, 40, 3, /* 456: struct.asn1_object_st */
            	138, 0,
            	138, 8,
            	465, 24,
            1, 8, 1, /* 465: pointer.unsigned char */
            	218, 0,
            1, 8, 1, /* 470: pointer.struct.asn1_string_st */
            	393, 0,
            1, 8, 1, /* 475: pointer.struct.asn1_string_st */
            	393, 0,
            1, 8, 1, /* 480: pointer.struct.asn1_string_st */
            	393, 0,
            1, 8, 1, /* 485: pointer.struct.asn1_string_st */
            	393, 0,
            1, 8, 1, /* 490: pointer.struct.asn1_string_st */
            	393, 0,
            1, 8, 1, /* 495: pointer.struct.asn1_string_st */
            	393, 0,
            1, 8, 1, /* 500: pointer.struct.asn1_string_st */
            	393, 0,
            1, 8, 1, /* 505: pointer.struct.asn1_string_st */
            	393, 0,
            1, 8, 1, /* 510: pointer.struct.asn1_string_st */
            	393, 0,
            1, 8, 1, /* 515: pointer.struct.asn1_string_st */
            	393, 0,
            1, 8, 1, /* 520: pointer.struct.asn1_string_st */
            	393, 0,
            1, 8, 1, /* 525: pointer.struct.asn1_string_st */
            	393, 0,
            1, 8, 1, /* 530: pointer.struct.asn1_string_st */
            	393, 0,
            1, 8, 1, /* 535: pointer.struct.ASN1_VALUE_st */
            	540, 0,
            0, 0, 0, /* 540: struct.ASN1_VALUE_st */
            0, 0, 0, /* 543: struct.evp_pkey_asn1_method_st */
            0, 16, 2, /* 546: struct.X509_val_st */
            	553, 0,
            	553, 8,
            1, 8, 1, /* 553: pointer.struct.asn1_string_st */
            	393, 0,
            1, 8, 1, /* 558: pointer.struct.stack_st_X509_ALGOR */
            	0, 0,
            1, 8, 1, /* 563: pointer.struct.X509_val_st */
            	546, 0,
            0, 1, 0, /* 568: char */
            0, 24, 1, /* 571: struct.ASN1_ENCODING_st */
            	213, 0,
            1, 8, 1, /* 576: pointer.struct.buf_mem_st */
            	581, 0,
            0, 24, 1, /* 581: struct.buf_mem_st */
            	17, 8,
            0, 8, 5, /* 586: union.unknown */
            	17, 0,
            	599, 0,
            	383, 0,
            	646, 0,
            	105, 0,
            1, 8, 1, /* 599: pointer.struct.rsa_st */
            	604, 0,
            0, 168, 17, /* 604: struct.rsa_st */
            	378, 16,
            	236, 24,
            	181, 32,
            	181, 40,
            	181, 48,
            	181, 56,
            	181, 64,
            	181, 72,
            	181, 80,
            	181, 88,
            	221, 96,
            	199, 120,
            	199, 128,
            	199, 136,
            	17, 144,
            	641, 152,
            	641, 160,
            1, 8, 1, /* 641: pointer.struct.bn_blinding_st */
            	320, 0,
            1, 8, 1, /* 646: pointer.struct.dh_st */
            	154, 0,
            1, 8, 1, /* 651: pointer.struct.AUTHORITY_KEYID_st */
            	656, 0,
            0, 24, 3, /* 656: struct.AUTHORITY_KEYID_st */
            	485, 0,
            	75, 8,
            	470, 16,
            0, 4, 0, /* 665: int */
            1, 8, 1, /* 668: pointer.struct.x509_st */
            	673, 0,
            0, 184, 12, /* 673: struct.x509_st */
            	700, 0,
            	730, 8,
            	480, 16,
            	17, 32,
            	221, 40,
            	485, 104,
            	651, 112,
            	48, 120,
            	40, 128,
            	326, 136,
            	53, 144,
            	806, 176,
            1, 8, 1, /* 700: pointer.struct.x509_cinf_st */
            	705, 0,
            0, 104, 11, /* 705: struct.x509_cinf_st */
            	470, 0,
            	470, 8,
            	730, 16,
            	747, 24,
            	563, 32,
            	747, 40,
            	771, 48,
            	480, 56,
            	480, 64,
            	85, 72,
            	571, 80,
            1, 8, 1, /* 730: pointer.struct.X509_algor_st */
            	735, 0,
            0, 16, 2, /* 735: struct.X509_algor_st */
            	451, 0,
            	742, 8,
            1, 8, 1, /* 742: pointer.struct.asn1_type_st */
            	398, 0,
            1, 8, 1, /* 747: pointer.struct.X509_name_st */
            	752, 0,
            0, 40, 3, /* 752: struct.X509_name_st */
            	761, 0,
            	576, 16,
            	213, 24,
            1, 8, 1, /* 761: pointer.struct.stack_st_X509_NAME_ENTRY */
            	766, 0,
            0, 32, 1, /* 766: struct.stack_st_X509_NAME_ENTRY */
            	5, 0,
            1, 8, 1, /* 771: pointer.struct.X509_pubkey_st */
            	776, 0,
            0, 24, 3, /* 776: struct.X509_pubkey_st */
            	730, 0,
            	480, 8,
            	785, 16,
            1, 8, 1, /* 785: pointer.struct.evp_pkey_st */
            	790, 0,
            0, 56, 4, /* 790: struct.evp_pkey_st */
            	801, 16,
            	236, 24,
            	586, 32,
            	100, 48,
            1, 8, 1, /* 801: pointer.struct.evp_pkey_asn1_method_st */
            	543, 0,
            1, 8, 1, /* 806: pointer.struct.x509_cert_aux_st */
            	811, 0,
            0, 40, 5, /* 811: struct.x509_cert_aux_st */
            	25, 0,
            	25, 8,
            	530, 16,
            	485, 24,
            	558, 32,
        },
        .arg_entity_index = { 668, 785, },
        .ret_entity_index = 665,
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

