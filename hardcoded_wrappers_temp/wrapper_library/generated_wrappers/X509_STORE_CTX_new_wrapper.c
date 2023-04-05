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

X509_STORE_CTX * bb_X509_STORE_CTX_new(void);

X509_STORE_CTX * X509_STORE_CTX_new(void) 
{
    unsigned long in_lib = syscall(890);
    printf("X509_STORE_CTX_new called %lu\n", in_lib);
    if (!in_lib)
        return bb_X509_STORE_CTX_new();
    else {
        X509_STORE_CTX * (*orig_X509_STORE_CTX_new)(void);
        orig_X509_STORE_CTX_new = dlsym(RTLD_NEXT, "X509_STORE_CTX_new");
        return orig_X509_STORE_CTX_new();
    }
}

X509_STORE_CTX * bb_X509_STORE_CTX_new(void) 
{
    X509_STORE_CTX * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            1, 8, 1, /* 0: pointer.struct.x509_crl_method_st */
            	5, 0,
            0, 0, 0, /* 5: struct.x509_crl_method_st */
            1, 8, 1, /* 8: pointer.struct.stack_st_GENERAL_NAMES */
            	13, 0,
            0, 0, 0, /* 13: struct.stack_st_GENERAL_NAMES */
            0, 8, 2, /* 16: union.unknown */
            	23, 0,
            	53, 0,
            1, 8, 1, /* 23: pointer.struct.stack_st_GENERAL_NAME */
            	28, 0,
            0, 32, 1, /* 28: struct.stack_st_GENERAL_NAME */
            	33, 0,
            0, 32, 2, /* 33: struct.stack_st */
            	40, 8,
            	50, 24,
            1, 8, 1, /* 40: pointer.pointer.char */
            	45, 0,
            1, 8, 1, /* 45: pointer.char */
            	4096, 0,
            4097, 8, 0, /* 50: pointer.func */
            1, 8, 1, /* 53: pointer.struct.stack_st_X509_NAME_ENTRY */
            	58, 0,
            0, 32, 1, /* 58: struct.stack_st_X509_NAME_ENTRY */
            	33, 0,
            0, 24, 2, /* 63: struct.DIST_POINT_NAME_st */
            	16, 8,
            	70, 16,
            1, 8, 1, /* 70: pointer.struct.X509_name_st */
            	75, 0,
            0, 40, 3, /* 75: struct.X509_name_st */
            	53, 0,
            	84, 16,
            	94, 24,
            1, 8, 1, /* 84: pointer.struct.buf_mem_st */
            	89, 0,
            0, 24, 1, /* 89: struct.buf_mem_st */
            	45, 8,
            1, 8, 1, /* 94: pointer.unsigned char */
            	99, 0,
            0, 1, 0, /* 99: unsigned char */
            1, 8, 1, /* 102: pointer.struct.DIST_POINT_NAME_st */
            	63, 0,
            0, 32, 2, /* 107: struct.ISSUING_DIST_POINT_st */
            	102, 0,
            	114, 16,
            1, 8, 1, /* 114: pointer.struct.asn1_string_st */
            	119, 0,
            0, 24, 1, /* 119: struct.asn1_string_st */
            	94, 8,
            0, 32, 1, /* 124: struct.stack_st_X509_REVOKED */
            	33, 0,
            1, 8, 1, /* 129: pointer.struct.stack_st_X509_REVOKED */
            	124, 0,
            0, 80, 8, /* 134: struct.X509_crl_info_st */
            	153, 0,
            	158, 8,
            	70, 16,
            	320, 24,
            	320, 32,
            	129, 40,
            	325, 48,
            	335, 56,
            1, 8, 1, /* 153: pointer.struct.asn1_string_st */
            	119, 0,
            1, 8, 1, /* 158: pointer.struct.X509_algor_st */
            	163, 0,
            0, 16, 2, /* 163: struct.X509_algor_st */
            	170, 0,
            	194, 8,
            1, 8, 1, /* 170: pointer.struct.asn1_object_st */
            	175, 0,
            0, 40, 3, /* 175: struct.asn1_object_st */
            	184, 0,
            	184, 8,
            	189, 24,
            1, 8, 1, /* 184: pointer.char */
            	4096, 0,
            1, 8, 1, /* 189: pointer.unsigned char */
            	99, 0,
            1, 8, 1, /* 194: pointer.struct.asn1_type_st */
            	199, 0,
            0, 16, 1, /* 199: struct.asn1_type_st */
            	204, 8,
            0, 8, 20, /* 204: union.unknown */
            	45, 0,
            	247, 0,
            	170, 0,
            	153, 0,
            	252, 0,
            	114, 0,
            	257, 0,
            	262, 0,
            	267, 0,
            	272, 0,
            	277, 0,
            	282, 0,
            	287, 0,
            	292, 0,
            	297, 0,
            	302, 0,
            	307, 0,
            	247, 0,
            	247, 0,
            	312, 0,
            1, 8, 1, /* 247: pointer.struct.asn1_string_st */
            	119, 0,
            1, 8, 1, /* 252: pointer.struct.asn1_string_st */
            	119, 0,
            1, 8, 1, /* 257: pointer.struct.asn1_string_st */
            	119, 0,
            1, 8, 1, /* 262: pointer.struct.asn1_string_st */
            	119, 0,
            1, 8, 1, /* 267: pointer.struct.asn1_string_st */
            	119, 0,
            1, 8, 1, /* 272: pointer.struct.asn1_string_st */
            	119, 0,
            1, 8, 1, /* 277: pointer.struct.asn1_string_st */
            	119, 0,
            1, 8, 1, /* 282: pointer.struct.asn1_string_st */
            	119, 0,
            1, 8, 1, /* 287: pointer.struct.asn1_string_st */
            	119, 0,
            1, 8, 1, /* 292: pointer.struct.asn1_string_st */
            	119, 0,
            1, 8, 1, /* 297: pointer.struct.asn1_string_st */
            	119, 0,
            1, 8, 1, /* 302: pointer.struct.asn1_string_st */
            	119, 0,
            1, 8, 1, /* 307: pointer.struct.asn1_string_st */
            	119, 0,
            1, 8, 1, /* 312: pointer.struct.ASN1_VALUE_st */
            	317, 0,
            0, 0, 0, /* 317: struct.ASN1_VALUE_st */
            1, 8, 1, /* 320: pointer.struct.asn1_string_st */
            	119, 0,
            1, 8, 1, /* 325: pointer.struct.stack_st_X509_EXTENSION */
            	330, 0,
            0, 32, 1, /* 330: struct.stack_st_X509_EXTENSION */
            	33, 0,
            0, 24, 1, /* 335: struct.ASN1_ENCODING_st */
            	94, 0,
            1, 8, 1, /* 340: pointer.struct.X509_crl_st */
            	345, 0,
            0, 120, 10, /* 345: struct.X509_crl_st */
            	368, 0,
            	158, 8,
            	114, 16,
            	373, 32,
            	387, 40,
            	153, 56,
            	153, 64,
            	8, 96,
            	0, 104,
            	392, 112,
            1, 8, 1, /* 368: pointer.struct.X509_crl_info_st */
            	134, 0,
            1, 8, 1, /* 373: pointer.struct.AUTHORITY_KEYID_st */
            	378, 0,
            0, 24, 3, /* 378: struct.AUTHORITY_KEYID_st */
            	257, 0,
            	23, 8,
            	153, 16,
            1, 8, 1, /* 387: pointer.struct.ISSUING_DIST_POINT_st */
            	107, 0,
            0, 8, 0, /* 392: pointer.void */
            0, 0, 0, /* 395: struct.X509_POLICY_TREE_st */
            1, 8, 1, /* 398: pointer.struct.X509_POLICY_TREE_st */
            	395, 0,
            0, 32, 1, /* 403: struct.stack_st_X509_CRL */
            	33, 0,
            1, 8, 1, /* 408: pointer.struct.stack_st_X509_CRL */
            	403, 0,
            0, 32, 1, /* 413: struct.stack_st_X509 */
            	33, 0,
            1, 8, 1, /* 418: pointer.struct.stack_st_X509 */
            	413, 0,
            1, 8, 1, /* 423: pointer.struct.stack_st_X509_ALGOR */
            	428, 0,
            0, 32, 1, /* 428: struct.stack_st_X509_ALGOR */
            	33, 0,
            0, 40, 5, /* 433: struct.x509_cert_aux_st */
            	446, 0,
            	446, 8,
            	307, 16,
            	257, 24,
            	423, 32,
            1, 8, 1, /* 446: pointer.struct.stack_st_ASN1_OBJECT */
            	451, 0,
            0, 32, 1, /* 451: struct.stack_st_ASN1_OBJECT */
            	33, 0,
            0, 32, 1, /* 456: struct.stack_st_GENERAL_SUBTREE */
            	33, 0,
            1, 8, 1, /* 461: pointer.struct.stack_st_GENERAL_SUBTREE */
            	456, 0,
            0, 16, 2, /* 466: struct.NAME_CONSTRAINTS_st */
            	461, 0,
            	461, 8,
            1, 8, 1, /* 473: pointer.struct.stack_st_GENERAL_NAME */
            	28, 0,
            1, 8, 1, /* 478: pointer.struct.stack_st_DIST_POINT */
            	483, 0,
            0, 32, 1, /* 483: struct.stack_st_DIST_POINT */
            	33, 0,
            0, 0, 0, /* 488: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 491: pointer.struct.X509_POLICY_CACHE_st */
            	488, 0,
            4097, 8, 0, /* 496: pointer.func */
            1, 8, 1, /* 499: pointer.unsigned int */
            	504, 0,
            0, 4, 0, /* 504: unsigned int */
            1, 8, 1, /* 507: pointer.struct.X509_val_st */
            	512, 0,
            0, 16, 2, /* 512: struct.X509_val_st */
            	320, 0,
            	320, 8,
            0, 56, 4, /* 519: struct.evp_pkey_st */
            	530, 16,
            	538, 24,
            	546, 32,
            	857, 48,
            1, 8, 1, /* 530: pointer.struct.evp_pkey_asn1_method_st */
            	535, 0,
            0, 0, 0, /* 535: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 538: pointer.struct.engine_st */
            	543, 0,
            0, 0, 0, /* 543: struct.engine_st */
            0, 8, 5, /* 546: union.unknown */
            	45, 0,
            	559, 0,
            	703, 0,
            	781, 0,
            	849, 0,
            1, 8, 1, /* 559: pointer.struct.rsa_st */
            	564, 0,
            0, 168, 17, /* 564: struct.rsa_st */
            	601, 16,
            	538, 24,
            	656, 32,
            	656, 40,
            	656, 48,
            	656, 56,
            	656, 64,
            	656, 72,
            	656, 80,
            	656, 88,
            	666, 96,
            	681, 120,
            	681, 128,
            	681, 136,
            	45, 144,
            	695, 152,
            	695, 160,
            1, 8, 1, /* 601: pointer.struct.rsa_meth_st */
            	606, 0,
            0, 112, 13, /* 606: struct.rsa_meth_st */
            	184, 0,
            	635, 8,
            	635, 16,
            	635, 24,
            	635, 32,
            	638, 40,
            	641, 48,
            	644, 56,
            	644, 64,
            	45, 80,
            	647, 88,
            	650, 96,
            	653, 104,
            4097, 8, 0, /* 635: pointer.func */
            4097, 8, 0, /* 638: pointer.func */
            4097, 8, 0, /* 641: pointer.func */
            4097, 8, 0, /* 644: pointer.func */
            4097, 8, 0, /* 647: pointer.func */
            4097, 8, 0, /* 650: pointer.func */
            4097, 8, 0, /* 653: pointer.func */
            1, 8, 1, /* 656: pointer.struct.bignum_st */
            	661, 0,
            0, 24, 1, /* 661: struct.bignum_st */
            	499, 0,
            0, 16, 1, /* 666: struct.crypto_ex_data_st */
            	671, 0,
            1, 8, 1, /* 671: pointer.struct.stack_st_void */
            	676, 0,
            0, 32, 1, /* 676: struct.stack_st_void */
            	33, 0,
            1, 8, 1, /* 681: pointer.struct.bn_mont_ctx_st */
            	686, 0,
            0, 96, 3, /* 686: struct.bn_mont_ctx_st */
            	661, 8,
            	661, 32,
            	661, 56,
            1, 8, 1, /* 695: pointer.struct.bn_blinding_st */
            	700, 0,
            0, 0, 0, /* 700: struct.bn_blinding_st */
            1, 8, 1, /* 703: pointer.struct.dsa_st */
            	708, 0,
            0, 136, 11, /* 708: struct.dsa_st */
            	656, 24,
            	656, 32,
            	656, 40,
            	656, 48,
            	656, 56,
            	656, 64,
            	656, 72,
            	681, 88,
            	666, 104,
            	733, 120,
            	538, 128,
            1, 8, 1, /* 733: pointer.struct.dsa_method */
            	738, 0,
            0, 96, 11, /* 738: struct.dsa_method */
            	184, 0,
            	763, 8,
            	766, 16,
            	496, 24,
            	769, 32,
            	772, 40,
            	775, 48,
            	775, 56,
            	45, 72,
            	778, 80,
            	775, 88,
            4097, 8, 0, /* 763: pointer.func */
            4097, 8, 0, /* 766: pointer.func */
            4097, 8, 0, /* 769: pointer.func */
            4097, 8, 0, /* 772: pointer.func */
            4097, 8, 0, /* 775: pointer.func */
            4097, 8, 0, /* 778: pointer.func */
            1, 8, 1, /* 781: pointer.struct.dh_st */
            	786, 0,
            0, 144, 12, /* 786: struct.dh_st */
            	656, 8,
            	656, 16,
            	656, 32,
            	656, 40,
            	681, 56,
            	656, 64,
            	656, 72,
            	94, 80,
            	656, 96,
            	666, 112,
            	813, 128,
            	538, 136,
            1, 8, 1, /* 813: pointer.struct.dh_method */
            	818, 0,
            0, 72, 8, /* 818: struct.dh_method */
            	184, 0,
            	837, 8,
            	840, 16,
            	843, 24,
            	837, 32,
            	837, 40,
            	45, 56,
            	846, 64,
            4097, 8, 0, /* 837: pointer.func */
            4097, 8, 0, /* 840: pointer.func */
            4097, 8, 0, /* 843: pointer.func */
            4097, 8, 0, /* 846: pointer.func */
            1, 8, 1, /* 849: pointer.struct.ec_key_st */
            	854, 0,
            0, 0, 0, /* 854: struct.ec_key_st */
            1, 8, 1, /* 857: pointer.struct.stack_st_X509_ATTRIBUTE */
            	862, 0,
            0, 32, 1, /* 862: struct.stack_st_X509_ATTRIBUTE */
            	33, 0,
            1, 8, 1, /* 867: pointer.struct.x509_cert_aux_st */
            	433, 0,
            1, 8, 1, /* 872: pointer.struct.x509_cinf_st */
            	877, 0,
            0, 104, 11, /* 877: struct.x509_cinf_st */
            	153, 0,
            	153, 8,
            	158, 16,
            	70, 24,
            	507, 32,
            	70, 40,
            	902, 48,
            	114, 56,
            	114, 64,
            	325, 72,
            	335, 80,
            1, 8, 1, /* 902: pointer.struct.X509_pubkey_st */
            	907, 0,
            0, 24, 3, /* 907: struct.X509_pubkey_st */
            	158, 0,
            	114, 8,
            	916, 16,
            1, 8, 1, /* 916: pointer.struct.evp_pkey_st */
            	519, 0,
            0, 184, 12, /* 921: struct.x509_st */
            	872, 0,
            	158, 8,
            	114, 16,
            	45, 32,
            	666, 40,
            	257, 104,
            	373, 112,
            	491, 120,
            	478, 128,
            	473, 136,
            	948, 144,
            	867, 176,
            1, 8, 1, /* 948: pointer.struct.NAME_CONSTRAINTS_st */
            	466, 0,
            1, 8, 1, /* 953: pointer.struct.x509_st */
            	921, 0,
            0, 32, 1, /* 958: struct.stack_st_X509_LOOKUP */
            	33, 0,
            1, 8, 1, /* 963: pointer.struct.x509_store_ctx_st */
            	968, 0,
            0, 248, 25, /* 968: struct.x509_store_ctx_st */
            	1021, 0,
            	953, 16,
            	418, 24,
            	408, 32,
            	1074, 40,
            	392, 48,
            	1086, 56,
            	1089, 64,
            	1092, 72,
            	1095, 80,
            	1086, 88,
            	1098, 96,
            	1101, 104,
            	1104, 112,
            	1086, 120,
            	1107, 128,
            	1110, 136,
            	1086, 144,
            	418, 160,
            	398, 168,
            	953, 192,
            	953, 200,
            	340, 208,
            	963, 224,
            	666, 232,
            1, 8, 1, /* 1021: pointer.struct.x509_store_st */
            	1026, 0,
            0, 144, 15, /* 1026: struct.x509_store_st */
            	1059, 8,
            	1069, 16,
            	1074, 24,
            	1086, 32,
            	1089, 40,
            	1092, 48,
            	1095, 56,
            	1086, 64,
            	1098, 72,
            	1101, 80,
            	1104, 88,
            	1107, 96,
            	1110, 104,
            	1086, 112,
            	666, 120,
            1, 8, 1, /* 1059: pointer.struct.stack_st_X509_OBJECT */
            	1064, 0,
            0, 32, 1, /* 1064: struct.stack_st_X509_OBJECT */
            	33, 0,
            1, 8, 1, /* 1069: pointer.struct.stack_st_X509_LOOKUP */
            	958, 0,
            1, 8, 1, /* 1074: pointer.struct.X509_VERIFY_PARAM_st */
            	1079, 0,
            0, 56, 2, /* 1079: struct.X509_VERIFY_PARAM_st */
            	45, 0,
            	446, 48,
            4097, 8, 0, /* 1086: pointer.func */
            4097, 8, 0, /* 1089: pointer.func */
            4097, 8, 0, /* 1092: pointer.func */
            4097, 8, 0, /* 1095: pointer.func */
            4097, 8, 0, /* 1098: pointer.func */
            4097, 8, 0, /* 1101: pointer.func */
            4097, 8, 0, /* 1104: pointer.func */
            4097, 8, 0, /* 1107: pointer.func */
            4097, 8, 0, /* 1110: pointer.func */
            0, 1, 0, /* 1113: char */
        },
        .arg_entity_index = { -1 },
        .ret_entity_index = 963,
    };
    struct lib_enter_args *args_addr = &args;
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    X509_STORE_CTX * *new_ret_ptr = (X509_STORE_CTX * *)new_args->ret;

    X509_STORE_CTX * (*orig_X509_STORE_CTX_new)(void);
    orig_X509_STORE_CTX_new = dlsym(RTLD_NEXT, "X509_STORE_CTX_new");
    *new_ret_ptr = (*orig_X509_STORE_CTX_new)();

    syscall(889);

    return ret;
}

