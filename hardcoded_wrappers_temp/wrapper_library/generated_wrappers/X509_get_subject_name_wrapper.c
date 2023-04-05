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
            1, 8, 1, /* 250: pointer.struct.AUTHORITY_KEYID_st */
            	255, 0,
            0, 24, 3, /* 255: struct.AUTHORITY_KEYID_st */
            	264, 0,
            	75, 8,
            	274, 16,
            1, 8, 1, /* 264: pointer.struct.asn1_string_st */
            	269, 0,
            0, 24, 1, /* 269: struct.asn1_string_st */
            	213, 8,
            1, 8, 1, /* 274: pointer.struct.asn1_string_st */
            	269, 0,
            0, 96, 11, /* 279: struct.dsa_method */
            	138, 0,
            	247, 8,
            	304, 16,
            	244, 24,
            	307, 32,
            	310, 40,
            	313, 48,
            	313, 56,
            	17, 72,
            	316, 80,
            	313, 88,
            4097, 8, 0, /* 304: pointer.func */
            4097, 8, 0, /* 307: pointer.func */
            4097, 8, 0, /* 310: pointer.func */
            4097, 8, 0, /* 313: pointer.func */
            4097, 8, 0, /* 316: pointer.func */
            0, 136, 11, /* 319: struct.dsa_st */
            	181, 24,
            	181, 32,
            	181, 40,
            	181, 48,
            	181, 56,
            	181, 64,
            	181, 72,
            	199, 88,
            	221, 104,
            	344, 120,
            	236, 128,
            1, 8, 1, /* 344: pointer.struct.dsa_method */
            	279, 0,
            0, 0, 0, /* 349: struct.bn_blinding_st */
            4097, 8, 0, /* 352: pointer.func */
            1, 8, 1, /* 355: pointer.struct.stack_st_GENERAL_NAME */
            	80, 0,
            4097, 8, 0, /* 360: pointer.func */
            4097, 8, 0, /* 363: pointer.func */
            4097, 8, 0, /* 366: pointer.func */
            0, 112, 13, /* 369: struct.rsa_meth_st */
            	138, 0,
            	398, 8,
            	398, 16,
            	398, 24,
            	398, 32,
            	401, 40,
            	404, 48,
            	366, 56,
            	366, 64,
            	17, 80,
            	363, 88,
            	360, 96,
            	352, 104,
            4097, 8, 0, /* 398: pointer.func */
            4097, 8, 0, /* 401: pointer.func */
            4097, 8, 0, /* 404: pointer.func */
            1, 8, 1, /* 407: pointer.struct.asn1_string_st */
            	269, 0,
            1, 8, 1, /* 412: pointer.struct.dsa_st */
            	319, 0,
            1, 8, 1, /* 417: pointer.struct.asn1_string_st */
            	269, 0,
            0, 16, 1, /* 422: struct.asn1_type_st */
            	427, 8,
            0, 8, 20, /* 427: union.unknown */
            	17, 0,
            	470, 0,
            	475, 0,
            	274, 0,
            	494, 0,
            	499, 0,
            	264, 0,
            	504, 0,
            	509, 0,
            	514, 0,
            	519, 0,
            	417, 0,
            	407, 0,
            	524, 0,
            	529, 0,
            	534, 0,
            	539, 0,
            	470, 0,
            	470, 0,
            	544, 0,
            1, 8, 1, /* 470: pointer.struct.asn1_string_st */
            	269, 0,
            1, 8, 1, /* 475: pointer.struct.asn1_object_st */
            	480, 0,
            0, 40, 3, /* 480: struct.asn1_object_st */
            	138, 0,
            	138, 8,
            	489, 24,
            1, 8, 1, /* 489: pointer.unsigned char */
            	218, 0,
            1, 8, 1, /* 494: pointer.struct.asn1_string_st */
            	269, 0,
            1, 8, 1, /* 499: pointer.struct.asn1_string_st */
            	269, 0,
            1, 8, 1, /* 504: pointer.struct.asn1_string_st */
            	269, 0,
            1, 8, 1, /* 509: pointer.struct.asn1_string_st */
            	269, 0,
            1, 8, 1, /* 514: pointer.struct.asn1_string_st */
            	269, 0,
            1, 8, 1, /* 519: pointer.struct.asn1_string_st */
            	269, 0,
            1, 8, 1, /* 524: pointer.struct.asn1_string_st */
            	269, 0,
            1, 8, 1, /* 529: pointer.struct.asn1_string_st */
            	269, 0,
            1, 8, 1, /* 534: pointer.struct.asn1_string_st */
            	269, 0,
            1, 8, 1, /* 539: pointer.struct.asn1_string_st */
            	269, 0,
            1, 8, 1, /* 544: pointer.struct.ASN1_VALUE_st */
            	549, 0,
            0, 0, 0, /* 549: struct.ASN1_VALUE_st */
            0, 0, 0, /* 552: struct.evp_pkey_asn1_method_st */
            0, 16, 2, /* 555: struct.X509_val_st */
            	562, 0,
            	562, 8,
            1, 8, 1, /* 562: pointer.struct.asn1_string_st */
            	269, 0,
            1, 8, 1, /* 567: pointer.struct.stack_st_X509_ALGOR */
            	0, 0,
            1, 8, 1, /* 572: pointer.struct.X509_val_st */
            	555, 0,
            0, 1, 0, /* 577: char */
            0, 24, 1, /* 580: struct.ASN1_ENCODING_st */
            	213, 0,
            1, 8, 1, /* 585: pointer.struct.buf_mem_st */
            	590, 0,
            0, 24, 1, /* 590: struct.buf_mem_st */
            	17, 8,
            0, 8, 5, /* 595: union.unknown */
            	17, 0,
            	608, 0,
            	412, 0,
            	660, 0,
            	105, 0,
            1, 8, 1, /* 608: pointer.struct.rsa_st */
            	613, 0,
            0, 168, 17, /* 613: struct.rsa_st */
            	650, 16,
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
            	655, 152,
            	655, 160,
            1, 8, 1, /* 650: pointer.struct.rsa_meth_st */
            	369, 0,
            1, 8, 1, /* 655: pointer.struct.bn_blinding_st */
            	349, 0,
            1, 8, 1, /* 660: pointer.struct.dh_st */
            	154, 0,
            0, 40, 5, /* 665: struct.x509_cert_aux_st */
            	25, 0,
            	25, 8,
            	539, 16,
            	264, 24,
            	567, 32,
            1, 8, 1, /* 678: pointer.struct.x509_st */
            	683, 0,
            0, 184, 12, /* 683: struct.x509_st */
            	710, 0,
            	740, 8,
            	499, 16,
            	17, 32,
            	221, 40,
            	264, 104,
            	250, 112,
            	48, 120,
            	40, 128,
            	355, 136,
            	53, 144,
            	816, 176,
            1, 8, 1, /* 710: pointer.struct.x509_cinf_st */
            	715, 0,
            0, 104, 11, /* 715: struct.x509_cinf_st */
            	274, 0,
            	274, 8,
            	740, 16,
            	757, 24,
            	572, 32,
            	757, 40,
            	781, 48,
            	499, 56,
            	499, 64,
            	85, 72,
            	580, 80,
            1, 8, 1, /* 740: pointer.struct.X509_algor_st */
            	745, 0,
            0, 16, 2, /* 745: struct.X509_algor_st */
            	475, 0,
            	752, 8,
            1, 8, 1, /* 752: pointer.struct.asn1_type_st */
            	422, 0,
            1, 8, 1, /* 757: pointer.struct.X509_name_st */
            	762, 0,
            0, 40, 3, /* 762: struct.X509_name_st */
            	771, 0,
            	585, 16,
            	213, 24,
            1, 8, 1, /* 771: pointer.struct.stack_st_X509_NAME_ENTRY */
            	776, 0,
            0, 32, 1, /* 776: struct.stack_st_X509_NAME_ENTRY */
            	5, 0,
            1, 8, 1, /* 781: pointer.struct.X509_pubkey_st */
            	786, 0,
            0, 24, 3, /* 786: struct.X509_pubkey_st */
            	740, 0,
            	499, 8,
            	795, 16,
            1, 8, 1, /* 795: pointer.struct.evp_pkey_st */
            	800, 0,
            0, 56, 4, /* 800: struct.evp_pkey_st */
            	811, 16,
            	236, 24,
            	595, 32,
            	100, 48,
            1, 8, 1, /* 811: pointer.struct.evp_pkey_asn1_method_st */
            	552, 0,
            1, 8, 1, /* 816: pointer.struct.x509_cert_aux_st */
            	665, 0,
        },
        .arg_entity_index = { 678, },
        .ret_entity_index = 757,
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

