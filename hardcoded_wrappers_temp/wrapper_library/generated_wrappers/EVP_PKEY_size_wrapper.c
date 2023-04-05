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
            1, 8, 1, /* 0: pointer.struct.ASN1_VALUE_st */
            	5, 0,
            0, 0, 0, /* 5: struct.ASN1_VALUE_st */
            8884097, 8, 0, /* 8: pointer.func */
            8884097, 8, 0, /* 11: pointer.func */
            0, 16, 1, /* 14: struct.crypto_ex_data_st */
            	19, 0,
            1, 8, 1, /* 19: pointer.struct.stack_st_void */
            	24, 0,
            0, 32, 1, /* 24: struct.stack_st_void */
            	29, 0,
            0, 32, 2, /* 29: struct.stack_st */
            	36, 8,
            	46, 24,
            1, 8, 1, /* 36: pointer.pointer.char */
            	41, 0,
            1, 8, 1, /* 41: pointer.char */
            	8884096, 0,
            8884097, 8, 0, /* 46: pointer.func */
            1, 8, 1, /* 49: pointer.struct.asn1_string_st */
            	54, 0,
            0, 24, 1, /* 54: struct.asn1_string_st */
            	59, 8,
            1, 8, 1, /* 59: pointer.unsigned char */
            	64, 0,
            0, 1, 0, /* 64: unsigned char */
            0, 24, 1, /* 67: struct.asn1_string_st */
            	59, 8,
            0, 24, 1, /* 72: struct.bignum_st */
            	77, 0,
            1, 8, 1, /* 77: pointer.unsigned int */
            	82, 0,
            0, 4, 0, /* 82: unsigned int */
            1, 8, 1, /* 85: pointer.struct.bignum_st */
            	72, 0,
            8884097, 8, 0, /* 90: pointer.func */
            8884097, 8, 0, /* 93: pointer.func */
            8884097, 8, 0, /* 96: pointer.func */
            1, 8, 1, /* 99: pointer.struct.asn1_string_st */
            	54, 0,
            1, 8, 1, /* 104: pointer.struct.asn1_string_st */
            	67, 0,
            1, 8, 1, /* 109: pointer.struct.asn1_string_st */
            	54, 0,
            0, 96, 3, /* 114: struct.bn_mont_ctx_st */
            	72, 8,
            	72, 32,
            	72, 56,
            1, 8, 1, /* 123: pointer.struct.dh_st */
            	128, 0,
            0, 144, 12, /* 128: struct.dh_st */
            	85, 8,
            	85, 16,
            	85, 32,
            	85, 40,
            	155, 56,
            	85, 64,
            	85, 72,
            	59, 80,
            	85, 96,
            	14, 112,
            	160, 128,
            	198, 136,
            1, 8, 1, /* 155: pointer.struct.bn_mont_ctx_st */
            	114, 0,
            1, 8, 1, /* 160: pointer.struct.dh_method */
            	165, 0,
            0, 72, 8, /* 165: struct.dh_method */
            	184, 0,
            	189, 8,
            	93, 16,
            	192, 24,
            	189, 32,
            	189, 40,
            	41, 56,
            	195, 64,
            1, 8, 1, /* 184: pointer.char */
            	8884096, 0,
            8884097, 8, 0, /* 189: pointer.func */
            8884097, 8, 0, /* 192: pointer.func */
            8884097, 8, 0, /* 195: pointer.func */
            1, 8, 1, /* 198: pointer.struct.engine_st */
            	203, 0,
            0, 0, 0, /* 203: struct.engine_st */
            8884097, 8, 0, /* 206: pointer.func */
            8884097, 8, 0, /* 209: pointer.func */
            8884097, 8, 0, /* 212: pointer.func */
            1, 8, 1, /* 215: pointer.struct.asn1_string_st */
            	54, 0,
            0, 56, 4, /* 220: struct.evp_pkey_st */
            	231, 16,
            	198, 24,
            	323, 32,
            	518, 48,
            1, 8, 1, /* 231: pointer.struct.evp_pkey_asn1_method_st */
            	236, 0,
            0, 208, 24, /* 236: struct.evp_pkey_asn1_method_st */
            	41, 16,
            	41, 24,
            	287, 32,
            	290, 40,
            	293, 48,
            	206, 56,
            	296, 64,
            	209, 72,
            	206, 80,
            	299, 88,
            	299, 96,
            	302, 104,
            	305, 112,
            	299, 120,
            	308, 128,
            	293, 136,
            	206, 144,
            	311, 152,
            	212, 160,
            	314, 168,
            	302, 176,
            	305, 184,
            	317, 192,
            	320, 200,
            8884097, 8, 0, /* 287: pointer.func */
            8884097, 8, 0, /* 290: pointer.func */
            8884097, 8, 0, /* 293: pointer.func */
            8884097, 8, 0, /* 296: pointer.func */
            8884097, 8, 0, /* 299: pointer.func */
            8884097, 8, 0, /* 302: pointer.func */
            8884097, 8, 0, /* 305: pointer.func */
            8884097, 8, 0, /* 308: pointer.func */
            8884097, 8, 0, /* 311: pointer.func */
            8884097, 8, 0, /* 314: pointer.func */
            8884097, 8, 0, /* 317: pointer.func */
            8884097, 8, 0, /* 320: pointer.func */
            0, 8, 5, /* 323: union.unknown */
            	41, 0,
            	336, 0,
            	432, 0,
            	123, 0,
            	510, 0,
            1, 8, 1, /* 336: pointer.struct.rsa_st */
            	341, 0,
            0, 168, 17, /* 341: struct.rsa_st */
            	378, 16,
            	198, 24,
            	85, 32,
            	85, 40,
            	85, 48,
            	85, 56,
            	85, 64,
            	85, 72,
            	85, 80,
            	85, 88,
            	14, 96,
            	155, 120,
            	155, 128,
            	155, 136,
            	41, 144,
            	424, 152,
            	424, 160,
            1, 8, 1, /* 378: pointer.struct.rsa_meth_st */
            	383, 0,
            0, 112, 13, /* 383: struct.rsa_meth_st */
            	184, 0,
            	412, 8,
            	412, 16,
            	412, 24,
            	412, 32,
            	415, 40,
            	418, 48,
            	421, 56,
            	421, 64,
            	41, 80,
            	8, 88,
            	96, 96,
            	90, 104,
            8884097, 8, 0, /* 412: pointer.func */
            8884097, 8, 0, /* 415: pointer.func */
            8884097, 8, 0, /* 418: pointer.func */
            8884097, 8, 0, /* 421: pointer.func */
            1, 8, 1, /* 424: pointer.struct.bn_blinding_st */
            	429, 0,
            0, 0, 0, /* 429: struct.bn_blinding_st */
            1, 8, 1, /* 432: pointer.struct.dsa_st */
            	437, 0,
            0, 136, 11, /* 437: struct.dsa_st */
            	85, 24,
            	85, 32,
            	85, 40,
            	85, 48,
            	85, 56,
            	85, 64,
            	85, 72,
            	155, 88,
            	14, 104,
            	462, 120,
            	198, 128,
            1, 8, 1, /* 462: pointer.struct.dsa_method */
            	467, 0,
            0, 96, 11, /* 467: struct.dsa_method */
            	184, 0,
            	492, 8,
            	495, 16,
            	498, 24,
            	11, 32,
            	501, 40,
            	504, 48,
            	504, 56,
            	41, 72,
            	507, 80,
            	504, 88,
            8884097, 8, 0, /* 492: pointer.func */
            8884097, 8, 0, /* 495: pointer.func */
            8884097, 8, 0, /* 498: pointer.func */
            8884097, 8, 0, /* 501: pointer.func */
            8884097, 8, 0, /* 504: pointer.func */
            8884097, 8, 0, /* 507: pointer.func */
            1, 8, 1, /* 510: pointer.struct.ec_key_st */
            	515, 0,
            0, 0, 0, /* 515: struct.ec_key_st */
            1, 8, 1, /* 518: pointer.struct.stack_st_X509_ATTRIBUTE */
            	523, 0,
            0, 32, 2, /* 523: struct.stack_st_fake_X509_ATTRIBUTE */
            	530, 8,
            	46, 24,
            8884099, 8, 2, /* 530: pointer_to_array_of_pointers_to_stack */
            	537, 0,
            	736, 20,
            0, 8, 1, /* 537: pointer.X509_ATTRIBUTE */
            	542, 0,
            0, 0, 1, /* 542: X509_ATTRIBUTE */
            	547, 0,
            0, 24, 2, /* 547: struct.x509_attributes_st */
            	554, 0,
            	573, 16,
            1, 8, 1, /* 554: pointer.struct.asn1_object_st */
            	559, 0,
            0, 40, 3, /* 559: struct.asn1_object_st */
            	184, 0,
            	184, 8,
            	568, 24,
            1, 8, 1, /* 568: pointer.unsigned char */
            	64, 0,
            0, 8, 3, /* 573: union.unknown */
            	41, 0,
            	582, 0,
            	739, 0,
            1, 8, 1, /* 582: pointer.struct.stack_st_ASN1_TYPE */
            	587, 0,
            0, 32, 2, /* 587: struct.stack_st_fake_ASN1_TYPE */
            	594, 8,
            	46, 24,
            8884099, 8, 2, /* 594: pointer_to_array_of_pointers_to_stack */
            	601, 0,
            	736, 20,
            0, 8, 1, /* 601: pointer.ASN1_TYPE */
            	606, 0,
            0, 0, 1, /* 606: ASN1_TYPE */
            	611, 0,
            0, 16, 1, /* 611: struct.asn1_type_st */
            	616, 8,
            0, 8, 20, /* 616: union.unknown */
            	41, 0,
            	215, 0,
            	659, 0,
            	673, 0,
            	678, 0,
            	683, 0,
            	688, 0,
            	109, 0,
            	693, 0,
            	698, 0,
            	49, 0,
            	99, 0,
            	703, 0,
            	708, 0,
            	713, 0,
            	718, 0,
            	723, 0,
            	215, 0,
            	215, 0,
            	728, 0,
            1, 8, 1, /* 659: pointer.struct.asn1_object_st */
            	664, 0,
            0, 40, 3, /* 664: struct.asn1_object_st */
            	184, 0,
            	184, 8,
            	568, 24,
            1, 8, 1, /* 673: pointer.struct.asn1_string_st */
            	54, 0,
            1, 8, 1, /* 678: pointer.struct.asn1_string_st */
            	54, 0,
            1, 8, 1, /* 683: pointer.struct.asn1_string_st */
            	54, 0,
            1, 8, 1, /* 688: pointer.struct.asn1_string_st */
            	54, 0,
            1, 8, 1, /* 693: pointer.struct.asn1_string_st */
            	54, 0,
            1, 8, 1, /* 698: pointer.struct.asn1_string_st */
            	54, 0,
            1, 8, 1, /* 703: pointer.struct.asn1_string_st */
            	54, 0,
            1, 8, 1, /* 708: pointer.struct.asn1_string_st */
            	54, 0,
            1, 8, 1, /* 713: pointer.struct.asn1_string_st */
            	54, 0,
            1, 8, 1, /* 718: pointer.struct.asn1_string_st */
            	54, 0,
            1, 8, 1, /* 723: pointer.struct.asn1_string_st */
            	54, 0,
            1, 8, 1, /* 728: pointer.struct.ASN1_VALUE_st */
            	733, 0,
            0, 0, 0, /* 733: struct.ASN1_VALUE_st */
            0, 4, 0, /* 736: int */
            1, 8, 1, /* 739: pointer.struct.asn1_type_st */
            	744, 0,
            0, 16, 1, /* 744: struct.asn1_type_st */
            	749, 8,
            0, 8, 20, /* 749: union.unknown */
            	41, 0,
            	792, 0,
            	554, 0,
            	797, 0,
            	802, 0,
            	807, 0,
            	812, 0,
            	104, 0,
            	817, 0,
            	822, 0,
            	827, 0,
            	832, 0,
            	837, 0,
            	842, 0,
            	847, 0,
            	852, 0,
            	857, 0,
            	792, 0,
            	792, 0,
            	0, 0,
            1, 8, 1, /* 792: pointer.struct.asn1_string_st */
            	67, 0,
            1, 8, 1, /* 797: pointer.struct.asn1_string_st */
            	67, 0,
            1, 8, 1, /* 802: pointer.struct.asn1_string_st */
            	67, 0,
            1, 8, 1, /* 807: pointer.struct.asn1_string_st */
            	67, 0,
            1, 8, 1, /* 812: pointer.struct.asn1_string_st */
            	67, 0,
            1, 8, 1, /* 817: pointer.struct.asn1_string_st */
            	67, 0,
            1, 8, 1, /* 822: pointer.struct.asn1_string_st */
            	67, 0,
            1, 8, 1, /* 827: pointer.struct.asn1_string_st */
            	67, 0,
            1, 8, 1, /* 832: pointer.struct.asn1_string_st */
            	67, 0,
            1, 8, 1, /* 837: pointer.struct.asn1_string_st */
            	67, 0,
            1, 8, 1, /* 842: pointer.struct.asn1_string_st */
            	67, 0,
            1, 8, 1, /* 847: pointer.struct.asn1_string_st */
            	67, 0,
            1, 8, 1, /* 852: pointer.struct.asn1_string_st */
            	67, 0,
            1, 8, 1, /* 857: pointer.struct.asn1_string_st */
            	67, 0,
            0, 1, 0, /* 862: char */
            1, 8, 1, /* 865: pointer.struct.evp_pkey_st */
            	220, 0,
        },
        .arg_entity_index = { 865, },
        .ret_entity_index = 736,
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

