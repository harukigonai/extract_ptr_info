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

void bb_SSL_CTX_sess_set_remove_cb(SSL_CTX * arg_a,void (*arg_b)(struct ssl_ctx_st *,SSL_SESSION *));

void SSL_CTX_sess_set_remove_cb(SSL_CTX * arg_a,void (*arg_b)(struct ssl_ctx_st *,SSL_SESSION *)) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_CTX_sess_set_remove_cb called %lu\n", in_lib);
    if (!in_lib)
        bb_SSL_CTX_sess_set_remove_cb(arg_a,arg_b);
    else {
        void (*orig_SSL_CTX_sess_set_remove_cb)(SSL_CTX *,void (*)(struct ssl_ctx_st *,SSL_SESSION *));
        orig_SSL_CTX_sess_set_remove_cb = dlsym(RTLD_NEXT, "SSL_CTX_sess_set_remove_cb");
        orig_SSL_CTX_sess_set_remove_cb(arg_a,arg_b);
    }
}

void bb_SSL_CTX_sess_set_remove_cb(SSL_CTX * arg_a,void (*arg_b)(struct ssl_ctx_st *,SSL_SESSION *)) 
{
    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            8884097, 8, 0, /* 0: pointer.func */
            0, 0, 1, /* 3: SRTP_PROTECTION_PROFILE */
            	8, 0,
            0, 16, 1, /* 8: struct.srtp_protection_profile_st */
            	13, 0,
            1, 8, 1, /* 13: pointer.char */
            	8884096, 0,
            8884097, 8, 0, /* 18: pointer.func */
            0, 24, 1, /* 21: struct.bignum_st */
            	26, 0,
            8884099, 8, 2, /* 26: pointer_to_array_of_pointers_to_stack */
            	33, 0,
            	36, 12,
            0, 4, 0, /* 33: unsigned int */
            0, 4, 0, /* 36: int */
            1, 8, 1, /* 39: pointer.struct.ssl3_buf_freelist_st */
            	44, 0,
            0, 24, 1, /* 44: struct.ssl3_buf_freelist_st */
            	49, 16,
            1, 8, 1, /* 49: pointer.struct.ssl3_buf_freelist_entry_st */
            	54, 0,
            0, 8, 1, /* 54: struct.ssl3_buf_freelist_entry_st */
            	49, 0,
            8884097, 8, 0, /* 59: pointer.func */
            8884097, 8, 0, /* 62: pointer.func */
            8884097, 8, 0, /* 65: pointer.func */
            8884097, 8, 0, /* 68: pointer.func */
            8884097, 8, 0, /* 71: pointer.func */
            1, 8, 1, /* 74: pointer.struct.dh_st */
            	79, 0,
            0, 144, 12, /* 79: struct.dh_st */
            	106, 8,
            	106, 16,
            	106, 32,
            	106, 40,
            	123, 56,
            	106, 64,
            	106, 72,
            	137, 80,
            	106, 96,
            	145, 112,
            	180, 128,
            	216, 136,
            1, 8, 1, /* 106: pointer.struct.bignum_st */
            	111, 0,
            0, 24, 1, /* 111: struct.bignum_st */
            	116, 0,
            8884099, 8, 2, /* 116: pointer_to_array_of_pointers_to_stack */
            	33, 0,
            	36, 12,
            1, 8, 1, /* 123: pointer.struct.bn_mont_ctx_st */
            	128, 0,
            0, 96, 3, /* 128: struct.bn_mont_ctx_st */
            	111, 8,
            	111, 32,
            	111, 56,
            1, 8, 1, /* 137: pointer.unsigned char */
            	142, 0,
            0, 1, 0, /* 142: unsigned char */
            0, 16, 1, /* 145: struct.crypto_ex_data_st */
            	150, 0,
            1, 8, 1, /* 150: pointer.struct.stack_st_void */
            	155, 0,
            0, 32, 1, /* 155: struct.stack_st_void */
            	160, 0,
            0, 32, 2, /* 160: struct.stack_st */
            	167, 8,
            	177, 24,
            1, 8, 1, /* 167: pointer.pointer.char */
            	172, 0,
            1, 8, 1, /* 172: pointer.char */
            	8884096, 0,
            8884097, 8, 0, /* 177: pointer.func */
            1, 8, 1, /* 180: pointer.struct.dh_method */
            	185, 0,
            0, 72, 8, /* 185: struct.dh_method */
            	13, 0,
            	204, 8,
            	207, 16,
            	210, 24,
            	204, 32,
            	204, 40,
            	172, 56,
            	213, 64,
            8884097, 8, 0, /* 204: pointer.func */
            8884097, 8, 0, /* 207: pointer.func */
            8884097, 8, 0, /* 210: pointer.func */
            8884097, 8, 0, /* 213: pointer.func */
            1, 8, 1, /* 216: pointer.struct.engine_st */
            	221, 0,
            0, 216, 24, /* 221: struct.engine_st */
            	13, 0,
            	13, 8,
            	272, 16,
            	327, 24,
            	378, 32,
            	414, 40,
            	431, 48,
            	458, 56,
            	493, 64,
            	501, 72,
            	504, 80,
            	507, 88,
            	510, 96,
            	513, 104,
            	513, 112,
            	513, 120,
            	516, 128,
            	519, 136,
            	519, 144,
            	522, 152,
            	525, 160,
            	537, 184,
            	559, 200,
            	559, 208,
            1, 8, 1, /* 272: pointer.struct.rsa_meth_st */
            	277, 0,
            0, 112, 13, /* 277: struct.rsa_meth_st */
            	13, 0,
            	306, 8,
            	306, 16,
            	306, 24,
            	306, 32,
            	309, 40,
            	312, 48,
            	315, 56,
            	315, 64,
            	172, 80,
            	318, 88,
            	321, 96,
            	324, 104,
            8884097, 8, 0, /* 306: pointer.func */
            8884097, 8, 0, /* 309: pointer.func */
            8884097, 8, 0, /* 312: pointer.func */
            8884097, 8, 0, /* 315: pointer.func */
            8884097, 8, 0, /* 318: pointer.func */
            8884097, 8, 0, /* 321: pointer.func */
            8884097, 8, 0, /* 324: pointer.func */
            1, 8, 1, /* 327: pointer.struct.dsa_method */
            	332, 0,
            0, 96, 11, /* 332: struct.dsa_method */
            	13, 0,
            	357, 8,
            	360, 16,
            	363, 24,
            	366, 32,
            	369, 40,
            	372, 48,
            	372, 56,
            	172, 72,
            	375, 80,
            	372, 88,
            8884097, 8, 0, /* 357: pointer.func */
            8884097, 8, 0, /* 360: pointer.func */
            8884097, 8, 0, /* 363: pointer.func */
            8884097, 8, 0, /* 366: pointer.func */
            8884097, 8, 0, /* 369: pointer.func */
            8884097, 8, 0, /* 372: pointer.func */
            8884097, 8, 0, /* 375: pointer.func */
            1, 8, 1, /* 378: pointer.struct.dh_method */
            	383, 0,
            0, 72, 8, /* 383: struct.dh_method */
            	13, 0,
            	402, 8,
            	405, 16,
            	408, 24,
            	402, 32,
            	402, 40,
            	172, 56,
            	411, 64,
            8884097, 8, 0, /* 402: pointer.func */
            8884097, 8, 0, /* 405: pointer.func */
            8884097, 8, 0, /* 408: pointer.func */
            8884097, 8, 0, /* 411: pointer.func */
            1, 8, 1, /* 414: pointer.struct.ecdh_method */
            	419, 0,
            0, 32, 3, /* 419: struct.ecdh_method */
            	13, 0,
            	428, 8,
            	172, 24,
            8884097, 8, 0, /* 428: pointer.func */
            1, 8, 1, /* 431: pointer.struct.ecdsa_method */
            	436, 0,
            0, 48, 5, /* 436: struct.ecdsa_method */
            	13, 0,
            	449, 8,
            	452, 16,
            	455, 24,
            	172, 40,
            8884097, 8, 0, /* 449: pointer.func */
            8884097, 8, 0, /* 452: pointer.func */
            8884097, 8, 0, /* 455: pointer.func */
            1, 8, 1, /* 458: pointer.struct.rand_meth_st */
            	463, 0,
            0, 48, 6, /* 463: struct.rand_meth_st */
            	478, 0,
            	481, 8,
            	484, 16,
            	487, 24,
            	481, 32,
            	490, 40,
            8884097, 8, 0, /* 478: pointer.func */
            8884097, 8, 0, /* 481: pointer.func */
            8884097, 8, 0, /* 484: pointer.func */
            8884097, 8, 0, /* 487: pointer.func */
            8884097, 8, 0, /* 490: pointer.func */
            1, 8, 1, /* 493: pointer.struct.store_method_st */
            	498, 0,
            0, 0, 0, /* 498: struct.store_method_st */
            8884097, 8, 0, /* 501: pointer.func */
            8884097, 8, 0, /* 504: pointer.func */
            8884097, 8, 0, /* 507: pointer.func */
            8884097, 8, 0, /* 510: pointer.func */
            8884097, 8, 0, /* 513: pointer.func */
            8884097, 8, 0, /* 516: pointer.func */
            8884097, 8, 0, /* 519: pointer.func */
            8884097, 8, 0, /* 522: pointer.func */
            1, 8, 1, /* 525: pointer.struct.ENGINE_CMD_DEFN_st */
            	530, 0,
            0, 32, 2, /* 530: struct.ENGINE_CMD_DEFN_st */
            	13, 8,
            	13, 16,
            0, 16, 1, /* 537: struct.crypto_ex_data_st */
            	542, 0,
            1, 8, 1, /* 542: pointer.struct.stack_st_void */
            	547, 0,
            0, 32, 1, /* 547: struct.stack_st_void */
            	552, 0,
            0, 32, 2, /* 552: struct.stack_st */
            	167, 8,
            	177, 24,
            1, 8, 1, /* 559: pointer.struct.engine_st */
            	221, 0,
            1, 8, 1, /* 564: pointer.struct.rsa_st */
            	569, 0,
            0, 168, 17, /* 569: struct.rsa_st */
            	606, 16,
            	661, 24,
            	666, 32,
            	666, 40,
            	666, 48,
            	666, 56,
            	666, 64,
            	666, 72,
            	666, 80,
            	666, 88,
            	683, 96,
            	705, 120,
            	705, 128,
            	705, 136,
            	172, 144,
            	719, 152,
            	719, 160,
            1, 8, 1, /* 606: pointer.struct.rsa_meth_st */
            	611, 0,
            0, 112, 13, /* 611: struct.rsa_meth_st */
            	13, 0,
            	640, 8,
            	640, 16,
            	640, 24,
            	640, 32,
            	643, 40,
            	646, 48,
            	649, 56,
            	649, 64,
            	172, 80,
            	652, 88,
            	655, 96,
            	658, 104,
            8884097, 8, 0, /* 640: pointer.func */
            8884097, 8, 0, /* 643: pointer.func */
            8884097, 8, 0, /* 646: pointer.func */
            8884097, 8, 0, /* 649: pointer.func */
            8884097, 8, 0, /* 652: pointer.func */
            8884097, 8, 0, /* 655: pointer.func */
            8884097, 8, 0, /* 658: pointer.func */
            1, 8, 1, /* 661: pointer.struct.engine_st */
            	221, 0,
            1, 8, 1, /* 666: pointer.struct.bignum_st */
            	671, 0,
            0, 24, 1, /* 671: struct.bignum_st */
            	676, 0,
            8884099, 8, 2, /* 676: pointer_to_array_of_pointers_to_stack */
            	33, 0,
            	36, 12,
            0, 16, 1, /* 683: struct.crypto_ex_data_st */
            	688, 0,
            1, 8, 1, /* 688: pointer.struct.stack_st_void */
            	693, 0,
            0, 32, 1, /* 693: struct.stack_st_void */
            	698, 0,
            0, 32, 2, /* 698: struct.stack_st */
            	167, 8,
            	177, 24,
            1, 8, 1, /* 705: pointer.struct.bn_mont_ctx_st */
            	710, 0,
            0, 96, 3, /* 710: struct.bn_mont_ctx_st */
            	671, 8,
            	671, 32,
            	671, 56,
            1, 8, 1, /* 719: pointer.struct.bn_blinding_st */
            	724, 0,
            0, 88, 7, /* 724: struct.bn_blinding_st */
            	741, 0,
            	741, 8,
            	741, 16,
            	741, 24,
            	758, 40,
            	766, 72,
            	780, 80,
            1, 8, 1, /* 741: pointer.struct.bignum_st */
            	746, 0,
            0, 24, 1, /* 746: struct.bignum_st */
            	751, 0,
            8884099, 8, 2, /* 751: pointer_to_array_of_pointers_to_stack */
            	33, 0,
            	36, 12,
            0, 16, 1, /* 758: struct.crypto_threadid_st */
            	763, 0,
            0, 8, 0, /* 763: pointer.void */
            1, 8, 1, /* 766: pointer.struct.bn_mont_ctx_st */
            	771, 0,
            0, 96, 3, /* 771: struct.bn_mont_ctx_st */
            	746, 8,
            	746, 32,
            	746, 56,
            8884097, 8, 0, /* 780: pointer.func */
            8884097, 8, 0, /* 783: pointer.func */
            8884097, 8, 0, /* 786: pointer.func */
            1, 8, 1, /* 789: pointer.struct.env_md_st */
            	794, 0,
            0, 120, 8, /* 794: struct.env_md_st */
            	813, 24,
            	786, 32,
            	783, 40,
            	816, 48,
            	813, 56,
            	819, 64,
            	822, 72,
            	825, 112,
            8884097, 8, 0, /* 813: pointer.func */
            8884097, 8, 0, /* 816: pointer.func */
            8884097, 8, 0, /* 819: pointer.func */
            8884097, 8, 0, /* 822: pointer.func */
            8884097, 8, 0, /* 825: pointer.func */
            1, 8, 1, /* 828: pointer.struct.stack_st_X509_ATTRIBUTE */
            	833, 0,
            0, 32, 2, /* 833: struct.stack_st_fake_X509_ATTRIBUTE */
            	840, 8,
            	177, 24,
            8884099, 8, 2, /* 840: pointer_to_array_of_pointers_to_stack */
            	847, 0,
            	36, 20,
            0, 8, 1, /* 847: pointer.X509_ATTRIBUTE */
            	852, 0,
            0, 0, 1, /* 852: X509_ATTRIBUTE */
            	857, 0,
            0, 24, 2, /* 857: struct.x509_attributes_st */
            	864, 0,
            	883, 16,
            1, 8, 1, /* 864: pointer.struct.asn1_object_st */
            	869, 0,
            0, 40, 3, /* 869: struct.asn1_object_st */
            	13, 0,
            	13, 8,
            	878, 24,
            1, 8, 1, /* 878: pointer.unsigned char */
            	142, 0,
            0, 8, 3, /* 883: union.unknown */
            	172, 0,
            	892, 0,
            	1071, 0,
            1, 8, 1, /* 892: pointer.struct.stack_st_ASN1_TYPE */
            	897, 0,
            0, 32, 2, /* 897: struct.stack_st_fake_ASN1_TYPE */
            	904, 8,
            	177, 24,
            8884099, 8, 2, /* 904: pointer_to_array_of_pointers_to_stack */
            	911, 0,
            	36, 20,
            0, 8, 1, /* 911: pointer.ASN1_TYPE */
            	916, 0,
            0, 0, 1, /* 916: ASN1_TYPE */
            	921, 0,
            0, 16, 1, /* 921: struct.asn1_type_st */
            	926, 8,
            0, 8, 20, /* 926: union.unknown */
            	172, 0,
            	969, 0,
            	979, 0,
            	993, 0,
            	998, 0,
            	1003, 0,
            	1008, 0,
            	1013, 0,
            	1018, 0,
            	1023, 0,
            	1028, 0,
            	1033, 0,
            	1038, 0,
            	1043, 0,
            	1048, 0,
            	1053, 0,
            	1058, 0,
            	969, 0,
            	969, 0,
            	1063, 0,
            1, 8, 1, /* 969: pointer.struct.asn1_string_st */
            	974, 0,
            0, 24, 1, /* 974: struct.asn1_string_st */
            	137, 8,
            1, 8, 1, /* 979: pointer.struct.asn1_object_st */
            	984, 0,
            0, 40, 3, /* 984: struct.asn1_object_st */
            	13, 0,
            	13, 8,
            	878, 24,
            1, 8, 1, /* 993: pointer.struct.asn1_string_st */
            	974, 0,
            1, 8, 1, /* 998: pointer.struct.asn1_string_st */
            	974, 0,
            1, 8, 1, /* 1003: pointer.struct.asn1_string_st */
            	974, 0,
            1, 8, 1, /* 1008: pointer.struct.asn1_string_st */
            	974, 0,
            1, 8, 1, /* 1013: pointer.struct.asn1_string_st */
            	974, 0,
            1, 8, 1, /* 1018: pointer.struct.asn1_string_st */
            	974, 0,
            1, 8, 1, /* 1023: pointer.struct.asn1_string_st */
            	974, 0,
            1, 8, 1, /* 1028: pointer.struct.asn1_string_st */
            	974, 0,
            1, 8, 1, /* 1033: pointer.struct.asn1_string_st */
            	974, 0,
            1, 8, 1, /* 1038: pointer.struct.asn1_string_st */
            	974, 0,
            1, 8, 1, /* 1043: pointer.struct.asn1_string_st */
            	974, 0,
            1, 8, 1, /* 1048: pointer.struct.asn1_string_st */
            	974, 0,
            1, 8, 1, /* 1053: pointer.struct.asn1_string_st */
            	974, 0,
            1, 8, 1, /* 1058: pointer.struct.asn1_string_st */
            	974, 0,
            1, 8, 1, /* 1063: pointer.struct.ASN1_VALUE_st */
            	1068, 0,
            0, 0, 0, /* 1068: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1071: pointer.struct.asn1_type_st */
            	1076, 0,
            0, 16, 1, /* 1076: struct.asn1_type_st */
            	1081, 8,
            0, 8, 20, /* 1081: union.unknown */
            	172, 0,
            	1124, 0,
            	864, 0,
            	1134, 0,
            	1139, 0,
            	1144, 0,
            	1149, 0,
            	1154, 0,
            	1159, 0,
            	1164, 0,
            	1169, 0,
            	1174, 0,
            	1179, 0,
            	1184, 0,
            	1189, 0,
            	1194, 0,
            	1199, 0,
            	1124, 0,
            	1124, 0,
            	1204, 0,
            1, 8, 1, /* 1124: pointer.struct.asn1_string_st */
            	1129, 0,
            0, 24, 1, /* 1129: struct.asn1_string_st */
            	137, 8,
            1, 8, 1, /* 1134: pointer.struct.asn1_string_st */
            	1129, 0,
            1, 8, 1, /* 1139: pointer.struct.asn1_string_st */
            	1129, 0,
            1, 8, 1, /* 1144: pointer.struct.asn1_string_st */
            	1129, 0,
            1, 8, 1, /* 1149: pointer.struct.asn1_string_st */
            	1129, 0,
            1, 8, 1, /* 1154: pointer.struct.asn1_string_st */
            	1129, 0,
            1, 8, 1, /* 1159: pointer.struct.asn1_string_st */
            	1129, 0,
            1, 8, 1, /* 1164: pointer.struct.asn1_string_st */
            	1129, 0,
            1, 8, 1, /* 1169: pointer.struct.asn1_string_st */
            	1129, 0,
            1, 8, 1, /* 1174: pointer.struct.asn1_string_st */
            	1129, 0,
            1, 8, 1, /* 1179: pointer.struct.asn1_string_st */
            	1129, 0,
            1, 8, 1, /* 1184: pointer.struct.asn1_string_st */
            	1129, 0,
            1, 8, 1, /* 1189: pointer.struct.asn1_string_st */
            	1129, 0,
            1, 8, 1, /* 1194: pointer.struct.asn1_string_st */
            	1129, 0,
            1, 8, 1, /* 1199: pointer.struct.asn1_string_st */
            	1129, 0,
            1, 8, 1, /* 1204: pointer.struct.ASN1_VALUE_st */
            	1209, 0,
            0, 0, 0, /* 1209: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1212: pointer.struct.dh_st */
            	79, 0,
            1, 8, 1, /* 1217: pointer.struct.dsa_st */
            	1222, 0,
            0, 136, 11, /* 1222: struct.dsa_st */
            	1247, 24,
            	1247, 32,
            	1247, 40,
            	1247, 48,
            	1247, 56,
            	1247, 64,
            	1247, 72,
            	1264, 88,
            	1278, 104,
            	1300, 120,
            	1351, 128,
            1, 8, 1, /* 1247: pointer.struct.bignum_st */
            	1252, 0,
            0, 24, 1, /* 1252: struct.bignum_st */
            	1257, 0,
            8884099, 8, 2, /* 1257: pointer_to_array_of_pointers_to_stack */
            	33, 0,
            	36, 12,
            1, 8, 1, /* 1264: pointer.struct.bn_mont_ctx_st */
            	1269, 0,
            0, 96, 3, /* 1269: struct.bn_mont_ctx_st */
            	1252, 8,
            	1252, 32,
            	1252, 56,
            0, 16, 1, /* 1278: struct.crypto_ex_data_st */
            	1283, 0,
            1, 8, 1, /* 1283: pointer.struct.stack_st_void */
            	1288, 0,
            0, 32, 1, /* 1288: struct.stack_st_void */
            	1293, 0,
            0, 32, 2, /* 1293: struct.stack_st */
            	167, 8,
            	177, 24,
            1, 8, 1, /* 1300: pointer.struct.dsa_method */
            	1305, 0,
            0, 96, 11, /* 1305: struct.dsa_method */
            	13, 0,
            	1330, 8,
            	1333, 16,
            	1336, 24,
            	1339, 32,
            	1342, 40,
            	1345, 48,
            	1345, 56,
            	172, 72,
            	1348, 80,
            	1345, 88,
            8884097, 8, 0, /* 1330: pointer.func */
            8884097, 8, 0, /* 1333: pointer.func */
            8884097, 8, 0, /* 1336: pointer.func */
            8884097, 8, 0, /* 1339: pointer.func */
            8884097, 8, 0, /* 1342: pointer.func */
            8884097, 8, 0, /* 1345: pointer.func */
            8884097, 8, 0, /* 1348: pointer.func */
            1, 8, 1, /* 1351: pointer.struct.engine_st */
            	221, 0,
            1, 8, 1, /* 1356: pointer.struct.rsa_st */
            	569, 0,
            0, 8, 5, /* 1361: union.unknown */
            	172, 0,
            	1356, 0,
            	1217, 0,
            	1212, 0,
            	1374, 0,
            1, 8, 1, /* 1374: pointer.struct.ec_key_st */
            	1379, 0,
            0, 56, 4, /* 1379: struct.ec_key_st */
            	1390, 8,
            	1838, 16,
            	1843, 24,
            	1860, 48,
            1, 8, 1, /* 1390: pointer.struct.ec_group_st */
            	1395, 0,
            0, 232, 12, /* 1395: struct.ec_group_st */
            	1422, 0,
            	1594, 8,
            	1794, 16,
            	1794, 40,
            	137, 80,
            	1806, 96,
            	1794, 104,
            	1794, 152,
            	1794, 176,
            	763, 208,
            	763, 216,
            	1835, 224,
            1, 8, 1, /* 1422: pointer.struct.ec_method_st */
            	1427, 0,
            0, 304, 37, /* 1427: struct.ec_method_st */
            	1504, 8,
            	1507, 16,
            	1507, 24,
            	1510, 32,
            	1513, 40,
            	1516, 48,
            	1519, 56,
            	1522, 64,
            	1525, 72,
            	1528, 80,
            	1528, 88,
            	1531, 96,
            	1534, 104,
            	1537, 112,
            	1540, 120,
            	1543, 128,
            	1546, 136,
            	1549, 144,
            	1552, 152,
            	1555, 160,
            	1558, 168,
            	1561, 176,
            	1564, 184,
            	1567, 192,
            	1570, 200,
            	1573, 208,
            	1564, 216,
            	1576, 224,
            	1579, 232,
            	1582, 240,
            	1519, 248,
            	1585, 256,
            	1588, 264,
            	1585, 272,
            	1588, 280,
            	1588, 288,
            	1591, 296,
            8884097, 8, 0, /* 1504: pointer.func */
            8884097, 8, 0, /* 1507: pointer.func */
            8884097, 8, 0, /* 1510: pointer.func */
            8884097, 8, 0, /* 1513: pointer.func */
            8884097, 8, 0, /* 1516: pointer.func */
            8884097, 8, 0, /* 1519: pointer.func */
            8884097, 8, 0, /* 1522: pointer.func */
            8884097, 8, 0, /* 1525: pointer.func */
            8884097, 8, 0, /* 1528: pointer.func */
            8884097, 8, 0, /* 1531: pointer.func */
            8884097, 8, 0, /* 1534: pointer.func */
            8884097, 8, 0, /* 1537: pointer.func */
            8884097, 8, 0, /* 1540: pointer.func */
            8884097, 8, 0, /* 1543: pointer.func */
            8884097, 8, 0, /* 1546: pointer.func */
            8884097, 8, 0, /* 1549: pointer.func */
            8884097, 8, 0, /* 1552: pointer.func */
            8884097, 8, 0, /* 1555: pointer.func */
            8884097, 8, 0, /* 1558: pointer.func */
            8884097, 8, 0, /* 1561: pointer.func */
            8884097, 8, 0, /* 1564: pointer.func */
            8884097, 8, 0, /* 1567: pointer.func */
            8884097, 8, 0, /* 1570: pointer.func */
            8884097, 8, 0, /* 1573: pointer.func */
            8884097, 8, 0, /* 1576: pointer.func */
            8884097, 8, 0, /* 1579: pointer.func */
            8884097, 8, 0, /* 1582: pointer.func */
            8884097, 8, 0, /* 1585: pointer.func */
            8884097, 8, 0, /* 1588: pointer.func */
            8884097, 8, 0, /* 1591: pointer.func */
            1, 8, 1, /* 1594: pointer.struct.ec_point_st */
            	1599, 0,
            0, 88, 4, /* 1599: struct.ec_point_st */
            	1610, 0,
            	1782, 8,
            	1782, 32,
            	1782, 56,
            1, 8, 1, /* 1610: pointer.struct.ec_method_st */
            	1615, 0,
            0, 304, 37, /* 1615: struct.ec_method_st */
            	1692, 8,
            	1695, 16,
            	1695, 24,
            	1698, 32,
            	1701, 40,
            	1704, 48,
            	1707, 56,
            	1710, 64,
            	1713, 72,
            	1716, 80,
            	1716, 88,
            	1719, 96,
            	1722, 104,
            	1725, 112,
            	1728, 120,
            	1731, 128,
            	1734, 136,
            	1737, 144,
            	1740, 152,
            	1743, 160,
            	1746, 168,
            	1749, 176,
            	1752, 184,
            	1755, 192,
            	1758, 200,
            	1761, 208,
            	1752, 216,
            	1764, 224,
            	1767, 232,
            	1770, 240,
            	1707, 248,
            	1773, 256,
            	1776, 264,
            	1773, 272,
            	1776, 280,
            	1776, 288,
            	1779, 296,
            8884097, 8, 0, /* 1692: pointer.func */
            8884097, 8, 0, /* 1695: pointer.func */
            8884097, 8, 0, /* 1698: pointer.func */
            8884097, 8, 0, /* 1701: pointer.func */
            8884097, 8, 0, /* 1704: pointer.func */
            8884097, 8, 0, /* 1707: pointer.func */
            8884097, 8, 0, /* 1710: pointer.func */
            8884097, 8, 0, /* 1713: pointer.func */
            8884097, 8, 0, /* 1716: pointer.func */
            8884097, 8, 0, /* 1719: pointer.func */
            8884097, 8, 0, /* 1722: pointer.func */
            8884097, 8, 0, /* 1725: pointer.func */
            8884097, 8, 0, /* 1728: pointer.func */
            8884097, 8, 0, /* 1731: pointer.func */
            8884097, 8, 0, /* 1734: pointer.func */
            8884097, 8, 0, /* 1737: pointer.func */
            8884097, 8, 0, /* 1740: pointer.func */
            8884097, 8, 0, /* 1743: pointer.func */
            8884097, 8, 0, /* 1746: pointer.func */
            8884097, 8, 0, /* 1749: pointer.func */
            8884097, 8, 0, /* 1752: pointer.func */
            8884097, 8, 0, /* 1755: pointer.func */
            8884097, 8, 0, /* 1758: pointer.func */
            8884097, 8, 0, /* 1761: pointer.func */
            8884097, 8, 0, /* 1764: pointer.func */
            8884097, 8, 0, /* 1767: pointer.func */
            8884097, 8, 0, /* 1770: pointer.func */
            8884097, 8, 0, /* 1773: pointer.func */
            8884097, 8, 0, /* 1776: pointer.func */
            8884097, 8, 0, /* 1779: pointer.func */
            0, 24, 1, /* 1782: struct.bignum_st */
            	1787, 0,
            8884099, 8, 2, /* 1787: pointer_to_array_of_pointers_to_stack */
            	33, 0,
            	36, 12,
            0, 24, 1, /* 1794: struct.bignum_st */
            	1799, 0,
            8884099, 8, 2, /* 1799: pointer_to_array_of_pointers_to_stack */
            	33, 0,
            	36, 12,
            1, 8, 1, /* 1806: pointer.struct.ec_extra_data_st */
            	1811, 0,
            0, 40, 5, /* 1811: struct.ec_extra_data_st */
            	1824, 0,
            	763, 8,
            	1829, 16,
            	1832, 24,
            	1832, 32,
            1, 8, 1, /* 1824: pointer.struct.ec_extra_data_st */
            	1811, 0,
            8884097, 8, 0, /* 1829: pointer.func */
            8884097, 8, 0, /* 1832: pointer.func */
            8884097, 8, 0, /* 1835: pointer.func */
            1, 8, 1, /* 1838: pointer.struct.ec_point_st */
            	1599, 0,
            1, 8, 1, /* 1843: pointer.struct.bignum_st */
            	1848, 0,
            0, 24, 1, /* 1848: struct.bignum_st */
            	1853, 0,
            8884099, 8, 2, /* 1853: pointer_to_array_of_pointers_to_stack */
            	33, 0,
            	36, 12,
            1, 8, 1, /* 1860: pointer.struct.ec_extra_data_st */
            	1865, 0,
            0, 40, 5, /* 1865: struct.ec_extra_data_st */
            	1878, 0,
            	763, 8,
            	1829, 16,
            	1832, 24,
            	1832, 32,
            1, 8, 1, /* 1878: pointer.struct.ec_extra_data_st */
            	1865, 0,
            0, 56, 4, /* 1883: struct.evp_pkey_st */
            	1894, 16,
            	1995, 24,
            	1361, 32,
            	828, 48,
            1, 8, 1, /* 1894: pointer.struct.evp_pkey_asn1_method_st */
            	1899, 0,
            0, 208, 24, /* 1899: struct.evp_pkey_asn1_method_st */
            	172, 16,
            	172, 24,
            	1950, 32,
            	1953, 40,
            	1956, 48,
            	1959, 56,
            	1962, 64,
            	1965, 72,
            	1959, 80,
            	1968, 88,
            	1968, 96,
            	1971, 104,
            	1974, 112,
            	1968, 120,
            	1977, 128,
            	1956, 136,
            	1959, 144,
            	1980, 152,
            	1983, 160,
            	1986, 168,
            	1971, 176,
            	1974, 184,
            	1989, 192,
            	1992, 200,
            8884097, 8, 0, /* 1950: pointer.func */
            8884097, 8, 0, /* 1953: pointer.func */
            8884097, 8, 0, /* 1956: pointer.func */
            8884097, 8, 0, /* 1959: pointer.func */
            8884097, 8, 0, /* 1962: pointer.func */
            8884097, 8, 0, /* 1965: pointer.func */
            8884097, 8, 0, /* 1968: pointer.func */
            8884097, 8, 0, /* 1971: pointer.func */
            8884097, 8, 0, /* 1974: pointer.func */
            8884097, 8, 0, /* 1977: pointer.func */
            8884097, 8, 0, /* 1980: pointer.func */
            8884097, 8, 0, /* 1983: pointer.func */
            8884097, 8, 0, /* 1986: pointer.func */
            8884097, 8, 0, /* 1989: pointer.func */
            8884097, 8, 0, /* 1992: pointer.func */
            1, 8, 1, /* 1995: pointer.struct.engine_st */
            	221, 0,
            1, 8, 1, /* 2000: pointer.struct.stack_st_X509_ALGOR */
            	2005, 0,
            0, 32, 2, /* 2005: struct.stack_st_fake_X509_ALGOR */
            	2012, 8,
            	177, 24,
            8884099, 8, 2, /* 2012: pointer_to_array_of_pointers_to_stack */
            	2019, 0,
            	36, 20,
            0, 8, 1, /* 2019: pointer.X509_ALGOR */
            	2024, 0,
            0, 0, 1, /* 2024: X509_ALGOR */
            	2029, 0,
            0, 16, 2, /* 2029: struct.X509_algor_st */
            	2036, 0,
            	2050, 8,
            1, 8, 1, /* 2036: pointer.struct.asn1_object_st */
            	2041, 0,
            0, 40, 3, /* 2041: struct.asn1_object_st */
            	13, 0,
            	13, 8,
            	878, 24,
            1, 8, 1, /* 2050: pointer.struct.asn1_type_st */
            	2055, 0,
            0, 16, 1, /* 2055: struct.asn1_type_st */
            	2060, 8,
            0, 8, 20, /* 2060: union.unknown */
            	172, 0,
            	2103, 0,
            	2036, 0,
            	2113, 0,
            	2118, 0,
            	2123, 0,
            	2128, 0,
            	2133, 0,
            	2138, 0,
            	2143, 0,
            	2148, 0,
            	2153, 0,
            	2158, 0,
            	2163, 0,
            	2168, 0,
            	2173, 0,
            	2178, 0,
            	2103, 0,
            	2103, 0,
            	1204, 0,
            1, 8, 1, /* 2103: pointer.struct.asn1_string_st */
            	2108, 0,
            0, 24, 1, /* 2108: struct.asn1_string_st */
            	137, 8,
            1, 8, 1, /* 2113: pointer.struct.asn1_string_st */
            	2108, 0,
            1, 8, 1, /* 2118: pointer.struct.asn1_string_st */
            	2108, 0,
            1, 8, 1, /* 2123: pointer.struct.asn1_string_st */
            	2108, 0,
            1, 8, 1, /* 2128: pointer.struct.asn1_string_st */
            	2108, 0,
            1, 8, 1, /* 2133: pointer.struct.asn1_string_st */
            	2108, 0,
            1, 8, 1, /* 2138: pointer.struct.asn1_string_st */
            	2108, 0,
            1, 8, 1, /* 2143: pointer.struct.asn1_string_st */
            	2108, 0,
            1, 8, 1, /* 2148: pointer.struct.asn1_string_st */
            	2108, 0,
            1, 8, 1, /* 2153: pointer.struct.asn1_string_st */
            	2108, 0,
            1, 8, 1, /* 2158: pointer.struct.asn1_string_st */
            	2108, 0,
            1, 8, 1, /* 2163: pointer.struct.asn1_string_st */
            	2108, 0,
            1, 8, 1, /* 2168: pointer.struct.asn1_string_st */
            	2108, 0,
            1, 8, 1, /* 2173: pointer.struct.asn1_string_st */
            	2108, 0,
            1, 8, 1, /* 2178: pointer.struct.asn1_string_st */
            	2108, 0,
            1, 8, 1, /* 2183: pointer.struct.asn1_string_st */
            	2188, 0,
            0, 24, 1, /* 2188: struct.asn1_string_st */
            	137, 8,
            0, 32, 1, /* 2193: struct.stack_st_void */
            	2198, 0,
            0, 32, 2, /* 2198: struct.stack_st */
            	167, 8,
            	177, 24,
            0, 24, 1, /* 2205: struct.ASN1_ENCODING_st */
            	137, 0,
            1, 8, 1, /* 2210: pointer.struct.stack_st_X509_EXTENSION */
            	2215, 0,
            0, 32, 2, /* 2215: struct.stack_st_fake_X509_EXTENSION */
            	2222, 8,
            	177, 24,
            8884099, 8, 2, /* 2222: pointer_to_array_of_pointers_to_stack */
            	2229, 0,
            	36, 20,
            0, 8, 1, /* 2229: pointer.X509_EXTENSION */
            	2234, 0,
            0, 0, 1, /* 2234: X509_EXTENSION */
            	2239, 0,
            0, 24, 2, /* 2239: struct.X509_extension_st */
            	2246, 0,
            	2260, 16,
            1, 8, 1, /* 2246: pointer.struct.asn1_object_st */
            	2251, 0,
            0, 40, 3, /* 2251: struct.asn1_object_st */
            	13, 0,
            	13, 8,
            	878, 24,
            1, 8, 1, /* 2260: pointer.struct.asn1_string_st */
            	2265, 0,
            0, 24, 1, /* 2265: struct.asn1_string_st */
            	137, 8,
            1, 8, 1, /* 2270: pointer.struct.X509_pubkey_st */
            	2275, 0,
            0, 24, 3, /* 2275: struct.X509_pubkey_st */
            	2284, 0,
            	2289, 8,
            	2299, 16,
            1, 8, 1, /* 2284: pointer.struct.X509_algor_st */
            	2029, 0,
            1, 8, 1, /* 2289: pointer.struct.asn1_string_st */
            	2294, 0,
            0, 24, 1, /* 2294: struct.asn1_string_st */
            	137, 8,
            1, 8, 1, /* 2299: pointer.struct.evp_pkey_st */
            	2304, 0,
            0, 56, 4, /* 2304: struct.evp_pkey_st */
            	2315, 16,
            	2320, 24,
            	2325, 32,
            	2358, 48,
            1, 8, 1, /* 2315: pointer.struct.evp_pkey_asn1_method_st */
            	1899, 0,
            1, 8, 1, /* 2320: pointer.struct.engine_st */
            	221, 0,
            0, 8, 5, /* 2325: union.unknown */
            	172, 0,
            	2338, 0,
            	2343, 0,
            	2348, 0,
            	2353, 0,
            1, 8, 1, /* 2338: pointer.struct.rsa_st */
            	569, 0,
            1, 8, 1, /* 2343: pointer.struct.dsa_st */
            	1222, 0,
            1, 8, 1, /* 2348: pointer.struct.dh_st */
            	79, 0,
            1, 8, 1, /* 2353: pointer.struct.ec_key_st */
            	1379, 0,
            1, 8, 1, /* 2358: pointer.struct.stack_st_X509_ATTRIBUTE */
            	2363, 0,
            0, 32, 2, /* 2363: struct.stack_st_fake_X509_ATTRIBUTE */
            	2370, 8,
            	177, 24,
            8884099, 8, 2, /* 2370: pointer_to_array_of_pointers_to_stack */
            	2377, 0,
            	36, 20,
            0, 8, 1, /* 2377: pointer.X509_ATTRIBUTE */
            	852, 0,
            1, 8, 1, /* 2382: pointer.struct.buf_mem_st */
            	2387, 0,
            0, 24, 1, /* 2387: struct.buf_mem_st */
            	172, 8,
            1, 8, 1, /* 2392: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2397, 0,
            0, 32, 2, /* 2397: struct.stack_st_fake_X509_NAME_ENTRY */
            	2404, 8,
            	177, 24,
            8884099, 8, 2, /* 2404: pointer_to_array_of_pointers_to_stack */
            	2411, 0,
            	36, 20,
            0, 8, 1, /* 2411: pointer.X509_NAME_ENTRY */
            	2416, 0,
            0, 0, 1, /* 2416: X509_NAME_ENTRY */
            	2421, 0,
            0, 24, 2, /* 2421: struct.X509_name_entry_st */
            	2428, 0,
            	2442, 8,
            1, 8, 1, /* 2428: pointer.struct.asn1_object_st */
            	2433, 0,
            0, 40, 3, /* 2433: struct.asn1_object_st */
            	13, 0,
            	13, 8,
            	878, 24,
            1, 8, 1, /* 2442: pointer.struct.asn1_string_st */
            	2447, 0,
            0, 24, 1, /* 2447: struct.asn1_string_st */
            	137, 8,
            1, 8, 1, /* 2452: pointer.struct.asn1_string_st */
            	2188, 0,
            0, 104, 11, /* 2457: struct.x509_cinf_st */
            	2452, 0,
            	2452, 8,
            	2482, 16,
            	2487, 24,
            	2501, 32,
            	2487, 40,
            	2270, 48,
            	2518, 56,
            	2518, 64,
            	2210, 72,
            	2205, 80,
            1, 8, 1, /* 2482: pointer.struct.X509_algor_st */
            	2029, 0,
            1, 8, 1, /* 2487: pointer.struct.X509_name_st */
            	2492, 0,
            0, 40, 3, /* 2492: struct.X509_name_st */
            	2392, 0,
            	2382, 16,
            	137, 24,
            1, 8, 1, /* 2501: pointer.struct.X509_val_st */
            	2506, 0,
            0, 16, 2, /* 2506: struct.X509_val_st */
            	2513, 0,
            	2513, 8,
            1, 8, 1, /* 2513: pointer.struct.asn1_string_st */
            	2188, 0,
            1, 8, 1, /* 2518: pointer.struct.asn1_string_st */
            	2188, 0,
            0, 296, 7, /* 2523: struct.cert_st */
            	2540, 0,
            	564, 48,
            	3882, 56,
            	74, 64,
            	71, 72,
            	3885, 80,
            	3890, 88,
            1, 8, 1, /* 2540: pointer.struct.cert_pkey_st */
            	2545, 0,
            0, 24, 3, /* 2545: struct.cert_pkey_st */
            	2554, 0,
            	3877, 8,
            	789, 16,
            1, 8, 1, /* 2554: pointer.struct.x509_st */
            	2559, 0,
            0, 184, 12, /* 2559: struct.x509_st */
            	2586, 0,
            	2482, 8,
            	2518, 16,
            	172, 32,
            	2591, 40,
            	2601, 104,
            	2606, 112,
            	2929, 120,
            	3360, 128,
            	3499, 136,
            	3523, 144,
            	3835, 176,
            1, 8, 1, /* 2586: pointer.struct.x509_cinf_st */
            	2457, 0,
            0, 16, 1, /* 2591: struct.crypto_ex_data_st */
            	2596, 0,
            1, 8, 1, /* 2596: pointer.struct.stack_st_void */
            	2193, 0,
            1, 8, 1, /* 2601: pointer.struct.asn1_string_st */
            	2188, 0,
            1, 8, 1, /* 2606: pointer.struct.AUTHORITY_KEYID_st */
            	2611, 0,
            0, 24, 3, /* 2611: struct.AUTHORITY_KEYID_st */
            	2620, 0,
            	2630, 8,
            	2924, 16,
            1, 8, 1, /* 2620: pointer.struct.asn1_string_st */
            	2625, 0,
            0, 24, 1, /* 2625: struct.asn1_string_st */
            	137, 8,
            1, 8, 1, /* 2630: pointer.struct.stack_st_GENERAL_NAME */
            	2635, 0,
            0, 32, 2, /* 2635: struct.stack_st_fake_GENERAL_NAME */
            	2642, 8,
            	177, 24,
            8884099, 8, 2, /* 2642: pointer_to_array_of_pointers_to_stack */
            	2649, 0,
            	36, 20,
            0, 8, 1, /* 2649: pointer.GENERAL_NAME */
            	2654, 0,
            0, 0, 1, /* 2654: GENERAL_NAME */
            	2659, 0,
            0, 16, 1, /* 2659: struct.GENERAL_NAME_st */
            	2664, 8,
            0, 8, 15, /* 2664: union.unknown */
            	172, 0,
            	2697, 0,
            	2816, 0,
            	2816, 0,
            	2723, 0,
            	2864, 0,
            	2912, 0,
            	2816, 0,
            	2801, 0,
            	2709, 0,
            	2801, 0,
            	2864, 0,
            	2816, 0,
            	2709, 0,
            	2723, 0,
            1, 8, 1, /* 2697: pointer.struct.otherName_st */
            	2702, 0,
            0, 16, 2, /* 2702: struct.otherName_st */
            	2709, 0,
            	2723, 8,
            1, 8, 1, /* 2709: pointer.struct.asn1_object_st */
            	2714, 0,
            0, 40, 3, /* 2714: struct.asn1_object_st */
            	13, 0,
            	13, 8,
            	878, 24,
            1, 8, 1, /* 2723: pointer.struct.asn1_type_st */
            	2728, 0,
            0, 16, 1, /* 2728: struct.asn1_type_st */
            	2733, 8,
            0, 8, 20, /* 2733: union.unknown */
            	172, 0,
            	2776, 0,
            	2709, 0,
            	2786, 0,
            	2791, 0,
            	2796, 0,
            	2801, 0,
            	2806, 0,
            	2811, 0,
            	2816, 0,
            	2821, 0,
            	2826, 0,
            	2831, 0,
            	2836, 0,
            	2841, 0,
            	2846, 0,
            	2851, 0,
            	2776, 0,
            	2776, 0,
            	2856, 0,
            1, 8, 1, /* 2776: pointer.struct.asn1_string_st */
            	2781, 0,
            0, 24, 1, /* 2781: struct.asn1_string_st */
            	137, 8,
            1, 8, 1, /* 2786: pointer.struct.asn1_string_st */
            	2781, 0,
            1, 8, 1, /* 2791: pointer.struct.asn1_string_st */
            	2781, 0,
            1, 8, 1, /* 2796: pointer.struct.asn1_string_st */
            	2781, 0,
            1, 8, 1, /* 2801: pointer.struct.asn1_string_st */
            	2781, 0,
            1, 8, 1, /* 2806: pointer.struct.asn1_string_st */
            	2781, 0,
            1, 8, 1, /* 2811: pointer.struct.asn1_string_st */
            	2781, 0,
            1, 8, 1, /* 2816: pointer.struct.asn1_string_st */
            	2781, 0,
            1, 8, 1, /* 2821: pointer.struct.asn1_string_st */
            	2781, 0,
            1, 8, 1, /* 2826: pointer.struct.asn1_string_st */
            	2781, 0,
            1, 8, 1, /* 2831: pointer.struct.asn1_string_st */
            	2781, 0,
            1, 8, 1, /* 2836: pointer.struct.asn1_string_st */
            	2781, 0,
            1, 8, 1, /* 2841: pointer.struct.asn1_string_st */
            	2781, 0,
            1, 8, 1, /* 2846: pointer.struct.asn1_string_st */
            	2781, 0,
            1, 8, 1, /* 2851: pointer.struct.asn1_string_st */
            	2781, 0,
            1, 8, 1, /* 2856: pointer.struct.ASN1_VALUE_st */
            	2861, 0,
            0, 0, 0, /* 2861: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2864: pointer.struct.X509_name_st */
            	2869, 0,
            0, 40, 3, /* 2869: struct.X509_name_st */
            	2878, 0,
            	2902, 16,
            	137, 24,
            1, 8, 1, /* 2878: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2883, 0,
            0, 32, 2, /* 2883: struct.stack_st_fake_X509_NAME_ENTRY */
            	2890, 8,
            	177, 24,
            8884099, 8, 2, /* 2890: pointer_to_array_of_pointers_to_stack */
            	2897, 0,
            	36, 20,
            0, 8, 1, /* 2897: pointer.X509_NAME_ENTRY */
            	2416, 0,
            1, 8, 1, /* 2902: pointer.struct.buf_mem_st */
            	2907, 0,
            0, 24, 1, /* 2907: struct.buf_mem_st */
            	172, 8,
            1, 8, 1, /* 2912: pointer.struct.EDIPartyName_st */
            	2917, 0,
            0, 16, 2, /* 2917: struct.EDIPartyName_st */
            	2776, 0,
            	2776, 8,
            1, 8, 1, /* 2924: pointer.struct.asn1_string_st */
            	2625, 0,
            1, 8, 1, /* 2929: pointer.struct.X509_POLICY_CACHE_st */
            	2934, 0,
            0, 40, 2, /* 2934: struct.X509_POLICY_CACHE_st */
            	2941, 0,
            	3260, 8,
            1, 8, 1, /* 2941: pointer.struct.X509_POLICY_DATA_st */
            	2946, 0,
            0, 32, 3, /* 2946: struct.X509_POLICY_DATA_st */
            	2955, 8,
            	2969, 16,
            	3222, 24,
            1, 8, 1, /* 2955: pointer.struct.asn1_object_st */
            	2960, 0,
            0, 40, 3, /* 2960: struct.asn1_object_st */
            	13, 0,
            	13, 8,
            	878, 24,
            1, 8, 1, /* 2969: pointer.struct.stack_st_POLICYQUALINFO */
            	2974, 0,
            0, 32, 2, /* 2974: struct.stack_st_fake_POLICYQUALINFO */
            	2981, 8,
            	177, 24,
            8884099, 8, 2, /* 2981: pointer_to_array_of_pointers_to_stack */
            	2988, 0,
            	36, 20,
            0, 8, 1, /* 2988: pointer.POLICYQUALINFO */
            	2993, 0,
            0, 0, 1, /* 2993: POLICYQUALINFO */
            	2998, 0,
            0, 16, 2, /* 2998: struct.POLICYQUALINFO_st */
            	3005, 0,
            	3019, 8,
            1, 8, 1, /* 3005: pointer.struct.asn1_object_st */
            	3010, 0,
            0, 40, 3, /* 3010: struct.asn1_object_st */
            	13, 0,
            	13, 8,
            	878, 24,
            0, 8, 3, /* 3019: union.unknown */
            	3028, 0,
            	3038, 0,
            	3096, 0,
            1, 8, 1, /* 3028: pointer.struct.asn1_string_st */
            	3033, 0,
            0, 24, 1, /* 3033: struct.asn1_string_st */
            	137, 8,
            1, 8, 1, /* 3038: pointer.struct.USERNOTICE_st */
            	3043, 0,
            0, 16, 2, /* 3043: struct.USERNOTICE_st */
            	3050, 0,
            	3062, 8,
            1, 8, 1, /* 3050: pointer.struct.NOTICEREF_st */
            	3055, 0,
            0, 16, 2, /* 3055: struct.NOTICEREF_st */
            	3062, 0,
            	3067, 8,
            1, 8, 1, /* 3062: pointer.struct.asn1_string_st */
            	3033, 0,
            1, 8, 1, /* 3067: pointer.struct.stack_st_ASN1_INTEGER */
            	3072, 0,
            0, 32, 2, /* 3072: struct.stack_st_fake_ASN1_INTEGER */
            	3079, 8,
            	177, 24,
            8884099, 8, 2, /* 3079: pointer_to_array_of_pointers_to_stack */
            	3086, 0,
            	36, 20,
            0, 8, 1, /* 3086: pointer.ASN1_INTEGER */
            	3091, 0,
            0, 0, 1, /* 3091: ASN1_INTEGER */
            	2108, 0,
            1, 8, 1, /* 3096: pointer.struct.asn1_type_st */
            	3101, 0,
            0, 16, 1, /* 3101: struct.asn1_type_st */
            	3106, 8,
            0, 8, 20, /* 3106: union.unknown */
            	172, 0,
            	3062, 0,
            	3005, 0,
            	3149, 0,
            	3154, 0,
            	3159, 0,
            	3164, 0,
            	3169, 0,
            	3174, 0,
            	3028, 0,
            	3179, 0,
            	3184, 0,
            	3189, 0,
            	3194, 0,
            	3199, 0,
            	3204, 0,
            	3209, 0,
            	3062, 0,
            	3062, 0,
            	3214, 0,
            1, 8, 1, /* 3149: pointer.struct.asn1_string_st */
            	3033, 0,
            1, 8, 1, /* 3154: pointer.struct.asn1_string_st */
            	3033, 0,
            1, 8, 1, /* 3159: pointer.struct.asn1_string_st */
            	3033, 0,
            1, 8, 1, /* 3164: pointer.struct.asn1_string_st */
            	3033, 0,
            1, 8, 1, /* 3169: pointer.struct.asn1_string_st */
            	3033, 0,
            1, 8, 1, /* 3174: pointer.struct.asn1_string_st */
            	3033, 0,
            1, 8, 1, /* 3179: pointer.struct.asn1_string_st */
            	3033, 0,
            1, 8, 1, /* 3184: pointer.struct.asn1_string_st */
            	3033, 0,
            1, 8, 1, /* 3189: pointer.struct.asn1_string_st */
            	3033, 0,
            1, 8, 1, /* 3194: pointer.struct.asn1_string_st */
            	3033, 0,
            1, 8, 1, /* 3199: pointer.struct.asn1_string_st */
            	3033, 0,
            1, 8, 1, /* 3204: pointer.struct.asn1_string_st */
            	3033, 0,
            1, 8, 1, /* 3209: pointer.struct.asn1_string_st */
            	3033, 0,
            1, 8, 1, /* 3214: pointer.struct.ASN1_VALUE_st */
            	3219, 0,
            0, 0, 0, /* 3219: struct.ASN1_VALUE_st */
            1, 8, 1, /* 3222: pointer.struct.stack_st_ASN1_OBJECT */
            	3227, 0,
            0, 32, 2, /* 3227: struct.stack_st_fake_ASN1_OBJECT */
            	3234, 8,
            	177, 24,
            8884099, 8, 2, /* 3234: pointer_to_array_of_pointers_to_stack */
            	3241, 0,
            	36, 20,
            0, 8, 1, /* 3241: pointer.ASN1_OBJECT */
            	3246, 0,
            0, 0, 1, /* 3246: ASN1_OBJECT */
            	3251, 0,
            0, 40, 3, /* 3251: struct.asn1_object_st */
            	13, 0,
            	13, 8,
            	878, 24,
            1, 8, 1, /* 3260: pointer.struct.stack_st_X509_POLICY_DATA */
            	3265, 0,
            0, 32, 2, /* 3265: struct.stack_st_fake_X509_POLICY_DATA */
            	3272, 8,
            	177, 24,
            8884099, 8, 2, /* 3272: pointer_to_array_of_pointers_to_stack */
            	3279, 0,
            	36, 20,
            0, 8, 1, /* 3279: pointer.X509_POLICY_DATA */
            	3284, 0,
            0, 0, 1, /* 3284: X509_POLICY_DATA */
            	3289, 0,
            0, 32, 3, /* 3289: struct.X509_POLICY_DATA_st */
            	3298, 8,
            	3312, 16,
            	3336, 24,
            1, 8, 1, /* 3298: pointer.struct.asn1_object_st */
            	3303, 0,
            0, 40, 3, /* 3303: struct.asn1_object_st */
            	13, 0,
            	13, 8,
            	878, 24,
            1, 8, 1, /* 3312: pointer.struct.stack_st_POLICYQUALINFO */
            	3317, 0,
            0, 32, 2, /* 3317: struct.stack_st_fake_POLICYQUALINFO */
            	3324, 8,
            	177, 24,
            8884099, 8, 2, /* 3324: pointer_to_array_of_pointers_to_stack */
            	3331, 0,
            	36, 20,
            0, 8, 1, /* 3331: pointer.POLICYQUALINFO */
            	2993, 0,
            1, 8, 1, /* 3336: pointer.struct.stack_st_ASN1_OBJECT */
            	3341, 0,
            0, 32, 2, /* 3341: struct.stack_st_fake_ASN1_OBJECT */
            	3348, 8,
            	177, 24,
            8884099, 8, 2, /* 3348: pointer_to_array_of_pointers_to_stack */
            	3355, 0,
            	36, 20,
            0, 8, 1, /* 3355: pointer.ASN1_OBJECT */
            	3246, 0,
            1, 8, 1, /* 3360: pointer.struct.stack_st_DIST_POINT */
            	3365, 0,
            0, 32, 2, /* 3365: struct.stack_st_fake_DIST_POINT */
            	3372, 8,
            	177, 24,
            8884099, 8, 2, /* 3372: pointer_to_array_of_pointers_to_stack */
            	3379, 0,
            	36, 20,
            0, 8, 1, /* 3379: pointer.DIST_POINT */
            	3384, 0,
            0, 0, 1, /* 3384: DIST_POINT */
            	3389, 0,
            0, 32, 3, /* 3389: struct.DIST_POINT_st */
            	3398, 0,
            	3489, 8,
            	3417, 16,
            1, 8, 1, /* 3398: pointer.struct.DIST_POINT_NAME_st */
            	3403, 0,
            0, 24, 2, /* 3403: struct.DIST_POINT_NAME_st */
            	3410, 8,
            	3465, 16,
            0, 8, 2, /* 3410: union.unknown */
            	3417, 0,
            	3441, 0,
            1, 8, 1, /* 3417: pointer.struct.stack_st_GENERAL_NAME */
            	3422, 0,
            0, 32, 2, /* 3422: struct.stack_st_fake_GENERAL_NAME */
            	3429, 8,
            	177, 24,
            8884099, 8, 2, /* 3429: pointer_to_array_of_pointers_to_stack */
            	3436, 0,
            	36, 20,
            0, 8, 1, /* 3436: pointer.GENERAL_NAME */
            	2654, 0,
            1, 8, 1, /* 3441: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3446, 0,
            0, 32, 2, /* 3446: struct.stack_st_fake_X509_NAME_ENTRY */
            	3453, 8,
            	177, 24,
            8884099, 8, 2, /* 3453: pointer_to_array_of_pointers_to_stack */
            	3460, 0,
            	36, 20,
            0, 8, 1, /* 3460: pointer.X509_NAME_ENTRY */
            	2416, 0,
            1, 8, 1, /* 3465: pointer.struct.X509_name_st */
            	3470, 0,
            0, 40, 3, /* 3470: struct.X509_name_st */
            	3441, 0,
            	3479, 16,
            	137, 24,
            1, 8, 1, /* 3479: pointer.struct.buf_mem_st */
            	3484, 0,
            0, 24, 1, /* 3484: struct.buf_mem_st */
            	172, 8,
            1, 8, 1, /* 3489: pointer.struct.asn1_string_st */
            	3494, 0,
            0, 24, 1, /* 3494: struct.asn1_string_st */
            	137, 8,
            1, 8, 1, /* 3499: pointer.struct.stack_st_GENERAL_NAME */
            	3504, 0,
            0, 32, 2, /* 3504: struct.stack_st_fake_GENERAL_NAME */
            	3511, 8,
            	177, 24,
            8884099, 8, 2, /* 3511: pointer_to_array_of_pointers_to_stack */
            	3518, 0,
            	36, 20,
            0, 8, 1, /* 3518: pointer.GENERAL_NAME */
            	2654, 0,
            1, 8, 1, /* 3523: pointer.struct.NAME_CONSTRAINTS_st */
            	3528, 0,
            0, 16, 2, /* 3528: struct.NAME_CONSTRAINTS_st */
            	3535, 0,
            	3535, 8,
            1, 8, 1, /* 3535: pointer.struct.stack_st_GENERAL_SUBTREE */
            	3540, 0,
            0, 32, 2, /* 3540: struct.stack_st_fake_GENERAL_SUBTREE */
            	3547, 8,
            	177, 24,
            8884099, 8, 2, /* 3547: pointer_to_array_of_pointers_to_stack */
            	3554, 0,
            	36, 20,
            0, 8, 1, /* 3554: pointer.GENERAL_SUBTREE */
            	3559, 0,
            0, 0, 1, /* 3559: GENERAL_SUBTREE */
            	3564, 0,
            0, 24, 3, /* 3564: struct.GENERAL_SUBTREE_st */
            	3573, 0,
            	3705, 8,
            	3705, 16,
            1, 8, 1, /* 3573: pointer.struct.GENERAL_NAME_st */
            	3578, 0,
            0, 16, 1, /* 3578: struct.GENERAL_NAME_st */
            	3583, 8,
            0, 8, 15, /* 3583: union.unknown */
            	172, 0,
            	3616, 0,
            	3735, 0,
            	3735, 0,
            	3642, 0,
            	3775, 0,
            	3823, 0,
            	3735, 0,
            	3720, 0,
            	3628, 0,
            	3720, 0,
            	3775, 0,
            	3735, 0,
            	3628, 0,
            	3642, 0,
            1, 8, 1, /* 3616: pointer.struct.otherName_st */
            	3621, 0,
            0, 16, 2, /* 3621: struct.otherName_st */
            	3628, 0,
            	3642, 8,
            1, 8, 1, /* 3628: pointer.struct.asn1_object_st */
            	3633, 0,
            0, 40, 3, /* 3633: struct.asn1_object_st */
            	13, 0,
            	13, 8,
            	878, 24,
            1, 8, 1, /* 3642: pointer.struct.asn1_type_st */
            	3647, 0,
            0, 16, 1, /* 3647: struct.asn1_type_st */
            	3652, 8,
            0, 8, 20, /* 3652: union.unknown */
            	172, 0,
            	3695, 0,
            	3628, 0,
            	3705, 0,
            	3710, 0,
            	3715, 0,
            	3720, 0,
            	3725, 0,
            	3730, 0,
            	3735, 0,
            	3740, 0,
            	3745, 0,
            	3750, 0,
            	3755, 0,
            	3760, 0,
            	3765, 0,
            	3770, 0,
            	3695, 0,
            	3695, 0,
            	3214, 0,
            1, 8, 1, /* 3695: pointer.struct.asn1_string_st */
            	3700, 0,
            0, 24, 1, /* 3700: struct.asn1_string_st */
            	137, 8,
            1, 8, 1, /* 3705: pointer.struct.asn1_string_st */
            	3700, 0,
            1, 8, 1, /* 3710: pointer.struct.asn1_string_st */
            	3700, 0,
            1, 8, 1, /* 3715: pointer.struct.asn1_string_st */
            	3700, 0,
            1, 8, 1, /* 3720: pointer.struct.asn1_string_st */
            	3700, 0,
            1, 8, 1, /* 3725: pointer.struct.asn1_string_st */
            	3700, 0,
            1, 8, 1, /* 3730: pointer.struct.asn1_string_st */
            	3700, 0,
            1, 8, 1, /* 3735: pointer.struct.asn1_string_st */
            	3700, 0,
            1, 8, 1, /* 3740: pointer.struct.asn1_string_st */
            	3700, 0,
            1, 8, 1, /* 3745: pointer.struct.asn1_string_st */
            	3700, 0,
            1, 8, 1, /* 3750: pointer.struct.asn1_string_st */
            	3700, 0,
            1, 8, 1, /* 3755: pointer.struct.asn1_string_st */
            	3700, 0,
            1, 8, 1, /* 3760: pointer.struct.asn1_string_st */
            	3700, 0,
            1, 8, 1, /* 3765: pointer.struct.asn1_string_st */
            	3700, 0,
            1, 8, 1, /* 3770: pointer.struct.asn1_string_st */
            	3700, 0,
            1, 8, 1, /* 3775: pointer.struct.X509_name_st */
            	3780, 0,
            0, 40, 3, /* 3780: struct.X509_name_st */
            	3789, 0,
            	3813, 16,
            	137, 24,
            1, 8, 1, /* 3789: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3794, 0,
            0, 32, 2, /* 3794: struct.stack_st_fake_X509_NAME_ENTRY */
            	3801, 8,
            	177, 24,
            8884099, 8, 2, /* 3801: pointer_to_array_of_pointers_to_stack */
            	3808, 0,
            	36, 20,
            0, 8, 1, /* 3808: pointer.X509_NAME_ENTRY */
            	2416, 0,
            1, 8, 1, /* 3813: pointer.struct.buf_mem_st */
            	3818, 0,
            0, 24, 1, /* 3818: struct.buf_mem_st */
            	172, 8,
            1, 8, 1, /* 3823: pointer.struct.EDIPartyName_st */
            	3828, 0,
            0, 16, 2, /* 3828: struct.EDIPartyName_st */
            	3695, 0,
            	3695, 8,
            1, 8, 1, /* 3835: pointer.struct.x509_cert_aux_st */
            	3840, 0,
            0, 40, 5, /* 3840: struct.x509_cert_aux_st */
            	3853, 0,
            	3853, 8,
            	2183, 16,
            	2601, 24,
            	2000, 32,
            1, 8, 1, /* 3853: pointer.struct.stack_st_ASN1_OBJECT */
            	3858, 0,
            0, 32, 2, /* 3858: struct.stack_st_fake_ASN1_OBJECT */
            	3865, 8,
            	177, 24,
            8884099, 8, 2, /* 3865: pointer_to_array_of_pointers_to_stack */
            	3872, 0,
            	36, 20,
            0, 8, 1, /* 3872: pointer.ASN1_OBJECT */
            	3246, 0,
            1, 8, 1, /* 3877: pointer.struct.evp_pkey_st */
            	1883, 0,
            8884097, 8, 0, /* 3882: pointer.func */
            1, 8, 1, /* 3885: pointer.struct.ec_key_st */
            	1379, 0,
            8884097, 8, 0, /* 3890: pointer.func */
            0, 24, 1, /* 3893: struct.buf_mem_st */
            	172, 8,
            1, 8, 1, /* 3898: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3903, 0,
            0, 32, 2, /* 3903: struct.stack_st_fake_X509_NAME_ENTRY */
            	3910, 8,
            	177, 24,
            8884099, 8, 2, /* 3910: pointer_to_array_of_pointers_to_stack */
            	3917, 0,
            	36, 20,
            0, 8, 1, /* 3917: pointer.X509_NAME_ENTRY */
            	2416, 0,
            0, 0, 1, /* 3922: X509_NAME */
            	3927, 0,
            0, 40, 3, /* 3927: struct.X509_name_st */
            	3898, 0,
            	3936, 16,
            	137, 24,
            1, 8, 1, /* 3936: pointer.struct.buf_mem_st */
            	3893, 0,
            1, 8, 1, /* 3941: pointer.struct.stack_st_X509_NAME */
            	3946, 0,
            0, 32, 2, /* 3946: struct.stack_st_fake_X509_NAME */
            	3953, 8,
            	177, 24,
            8884099, 8, 2, /* 3953: pointer_to_array_of_pointers_to_stack */
            	3960, 0,
            	36, 20,
            0, 8, 1, /* 3960: pointer.X509_NAME */
            	3922, 0,
            8884097, 8, 0, /* 3965: pointer.func */
            8884097, 8, 0, /* 3968: pointer.func */
            8884097, 8, 0, /* 3971: pointer.func */
            8884097, 8, 0, /* 3974: pointer.func */
            0, 64, 7, /* 3977: struct.comp_method_st */
            	13, 8,
            	3974, 16,
            	3971, 24,
            	3968, 32,
            	3968, 40,
            	3994, 48,
            	3994, 56,
            8884097, 8, 0, /* 3994: pointer.func */
            1, 8, 1, /* 3997: pointer.struct.comp_method_st */
            	3977, 0,
            0, 0, 1, /* 4002: SSL_COMP */
            	4007, 0,
            0, 24, 2, /* 4007: struct.ssl_comp_st */
            	13, 8,
            	3997, 16,
            1, 8, 1, /* 4014: pointer.struct.stack_st_SSL_COMP */
            	4019, 0,
            0, 32, 2, /* 4019: struct.stack_st_fake_SSL_COMP */
            	4026, 8,
            	177, 24,
            8884099, 8, 2, /* 4026: pointer_to_array_of_pointers_to_stack */
            	4033, 0,
            	36, 20,
            0, 8, 1, /* 4033: pointer.SSL_COMP */
            	4002, 0,
            8884097, 8, 0, /* 4038: pointer.func */
            8884097, 8, 0, /* 4041: pointer.func */
            8884097, 8, 0, /* 4044: pointer.func */
            0, 120, 8, /* 4047: struct.env_md_st */
            	4044, 24,
            	4041, 32,
            	4066, 40,
            	4038, 48,
            	4044, 56,
            	819, 64,
            	822, 72,
            	4069, 112,
            8884097, 8, 0, /* 4066: pointer.func */
            8884097, 8, 0, /* 4069: pointer.func */
            1, 8, 1, /* 4072: pointer.struct.env_md_st */
            	4047, 0,
            8884097, 8, 0, /* 4077: pointer.func */
            8884097, 8, 0, /* 4080: pointer.func */
            8884097, 8, 0, /* 4083: pointer.func */
            8884097, 8, 0, /* 4086: pointer.func */
            8884097, 8, 0, /* 4089: pointer.func */
            0, 88, 1, /* 4092: struct.ssl_cipher_st */
            	13, 8,
            1, 8, 1, /* 4097: pointer.struct.ssl_cipher_st */
            	4092, 0,
            1, 8, 1, /* 4102: pointer.struct.stack_st_X509_ALGOR */
            	4107, 0,
            0, 32, 2, /* 4107: struct.stack_st_fake_X509_ALGOR */
            	4114, 8,
            	177, 24,
            8884099, 8, 2, /* 4114: pointer_to_array_of_pointers_to_stack */
            	4121, 0,
            	36, 20,
            0, 8, 1, /* 4121: pointer.X509_ALGOR */
            	2024, 0,
            1, 8, 1, /* 4126: pointer.struct.asn1_string_st */
            	4131, 0,
            0, 24, 1, /* 4131: struct.asn1_string_st */
            	137, 8,
            1, 8, 1, /* 4136: pointer.struct.x509_cert_aux_st */
            	4141, 0,
            0, 40, 5, /* 4141: struct.x509_cert_aux_st */
            	4154, 0,
            	4154, 8,
            	4126, 16,
            	4178, 24,
            	4102, 32,
            1, 8, 1, /* 4154: pointer.struct.stack_st_ASN1_OBJECT */
            	4159, 0,
            0, 32, 2, /* 4159: struct.stack_st_fake_ASN1_OBJECT */
            	4166, 8,
            	177, 24,
            8884099, 8, 2, /* 4166: pointer_to_array_of_pointers_to_stack */
            	4173, 0,
            	36, 20,
            0, 8, 1, /* 4173: pointer.ASN1_OBJECT */
            	3246, 0,
            1, 8, 1, /* 4178: pointer.struct.asn1_string_st */
            	4131, 0,
            0, 24, 1, /* 4183: struct.ASN1_ENCODING_st */
            	137, 0,
            1, 8, 1, /* 4188: pointer.struct.stack_st_X509_EXTENSION */
            	4193, 0,
            0, 32, 2, /* 4193: struct.stack_st_fake_X509_EXTENSION */
            	4200, 8,
            	177, 24,
            8884099, 8, 2, /* 4200: pointer_to_array_of_pointers_to_stack */
            	4207, 0,
            	36, 20,
            0, 8, 1, /* 4207: pointer.X509_EXTENSION */
            	2234, 0,
            1, 8, 1, /* 4212: pointer.struct.asn1_string_st */
            	4131, 0,
            1, 8, 1, /* 4217: pointer.struct.X509_pubkey_st */
            	2275, 0,
            0, 16, 2, /* 4222: struct.X509_val_st */
            	4229, 0,
            	4229, 8,
            1, 8, 1, /* 4229: pointer.struct.asn1_string_st */
            	4131, 0,
            1, 8, 1, /* 4234: pointer.struct.X509_val_st */
            	4222, 0,
            0, 24, 1, /* 4239: struct.buf_mem_st */
            	172, 8,
            0, 40, 3, /* 4244: struct.X509_name_st */
            	4253, 0,
            	4277, 16,
            	137, 24,
            1, 8, 1, /* 4253: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4258, 0,
            0, 32, 2, /* 4258: struct.stack_st_fake_X509_NAME_ENTRY */
            	4265, 8,
            	177, 24,
            8884099, 8, 2, /* 4265: pointer_to_array_of_pointers_to_stack */
            	4272, 0,
            	36, 20,
            0, 8, 1, /* 4272: pointer.X509_NAME_ENTRY */
            	2416, 0,
            1, 8, 1, /* 4277: pointer.struct.buf_mem_st */
            	4239, 0,
            1, 8, 1, /* 4282: pointer.struct.X509_name_st */
            	4244, 0,
            1, 8, 1, /* 4287: pointer.struct.X509_algor_st */
            	2029, 0,
            0, 104, 11, /* 4292: struct.x509_cinf_st */
            	4317, 0,
            	4317, 8,
            	4287, 16,
            	4282, 24,
            	4234, 32,
            	4282, 40,
            	4217, 48,
            	4212, 56,
            	4212, 64,
            	4188, 72,
            	4183, 80,
            1, 8, 1, /* 4317: pointer.struct.asn1_string_st */
            	4131, 0,
            1, 8, 1, /* 4322: pointer.struct.x509_cinf_st */
            	4292, 0,
            1, 8, 1, /* 4327: pointer.struct.dh_st */
            	79, 0,
            8884097, 8, 0, /* 4332: pointer.func */
            8884097, 8, 0, /* 4335: pointer.func */
            0, 120, 8, /* 4338: struct.env_md_st */
            	4357, 24,
            	4360, 32,
            	4335, 40,
            	4363, 48,
            	4357, 56,
            	819, 64,
            	822, 72,
            	4332, 112,
            8884097, 8, 0, /* 4357: pointer.func */
            8884097, 8, 0, /* 4360: pointer.func */
            8884097, 8, 0, /* 4363: pointer.func */
            1, 8, 1, /* 4366: pointer.struct.dsa_st */
            	1222, 0,
            1, 8, 1, /* 4371: pointer.struct.rsa_st */
            	569, 0,
            0, 8, 5, /* 4376: union.unknown */
            	172, 0,
            	4371, 0,
            	4366, 0,
            	4389, 0,
            	1374, 0,
            1, 8, 1, /* 4389: pointer.struct.dh_st */
            	79, 0,
            0, 56, 4, /* 4394: struct.evp_pkey_st */
            	1894, 16,
            	1995, 24,
            	4376, 32,
            	4405, 48,
            1, 8, 1, /* 4405: pointer.struct.stack_st_X509_ATTRIBUTE */
            	4410, 0,
            0, 32, 2, /* 4410: struct.stack_st_fake_X509_ATTRIBUTE */
            	4417, 8,
            	177, 24,
            8884099, 8, 2, /* 4417: pointer_to_array_of_pointers_to_stack */
            	4424, 0,
            	36, 20,
            0, 8, 1, /* 4424: pointer.X509_ATTRIBUTE */
            	852, 0,
            1, 8, 1, /* 4429: pointer.struct.asn1_string_st */
            	4434, 0,
            0, 24, 1, /* 4434: struct.asn1_string_st */
            	137, 8,
            0, 40, 5, /* 4439: struct.x509_cert_aux_st */
            	4452, 0,
            	4452, 8,
            	4429, 16,
            	4476, 24,
            	4481, 32,
            1, 8, 1, /* 4452: pointer.struct.stack_st_ASN1_OBJECT */
            	4457, 0,
            0, 32, 2, /* 4457: struct.stack_st_fake_ASN1_OBJECT */
            	4464, 8,
            	177, 24,
            8884099, 8, 2, /* 4464: pointer_to_array_of_pointers_to_stack */
            	4471, 0,
            	36, 20,
            0, 8, 1, /* 4471: pointer.ASN1_OBJECT */
            	3246, 0,
            1, 8, 1, /* 4476: pointer.struct.asn1_string_st */
            	4434, 0,
            1, 8, 1, /* 4481: pointer.struct.stack_st_X509_ALGOR */
            	4486, 0,
            0, 32, 2, /* 4486: struct.stack_st_fake_X509_ALGOR */
            	4493, 8,
            	177, 24,
            8884099, 8, 2, /* 4493: pointer_to_array_of_pointers_to_stack */
            	4500, 0,
            	36, 20,
            0, 8, 1, /* 4500: pointer.X509_ALGOR */
            	2024, 0,
            0, 32, 1, /* 4505: struct.stack_st_void */
            	4510, 0,
            0, 32, 2, /* 4510: struct.stack_st */
            	167, 8,
            	177, 24,
            0, 16, 1, /* 4517: struct.crypto_ex_data_st */
            	4522, 0,
            1, 8, 1, /* 4522: pointer.struct.stack_st_void */
            	4505, 0,
            0, 24, 1, /* 4527: struct.ASN1_ENCODING_st */
            	137, 0,
            1, 8, 1, /* 4532: pointer.struct.stack_st_X509_EXTENSION */
            	4537, 0,
            0, 32, 2, /* 4537: struct.stack_st_fake_X509_EXTENSION */
            	4544, 8,
            	177, 24,
            8884099, 8, 2, /* 4544: pointer_to_array_of_pointers_to_stack */
            	4551, 0,
            	36, 20,
            0, 8, 1, /* 4551: pointer.X509_EXTENSION */
            	2234, 0,
            1, 8, 1, /* 4556: pointer.struct.asn1_string_st */
            	4434, 0,
            1, 8, 1, /* 4561: pointer.struct.X509_pubkey_st */
            	2275, 0,
            0, 16, 2, /* 4566: struct.X509_val_st */
            	4573, 0,
            	4573, 8,
            1, 8, 1, /* 4573: pointer.struct.asn1_string_st */
            	4434, 0,
            0, 24, 1, /* 4578: struct.buf_mem_st */
            	172, 8,
            1, 8, 1, /* 4583: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4588, 0,
            0, 32, 2, /* 4588: struct.stack_st_fake_X509_NAME_ENTRY */
            	4595, 8,
            	177, 24,
            8884099, 8, 2, /* 4595: pointer_to_array_of_pointers_to_stack */
            	4602, 0,
            	36, 20,
            0, 8, 1, /* 4602: pointer.X509_NAME_ENTRY */
            	2416, 0,
            1, 8, 1, /* 4607: pointer.struct.X509_algor_st */
            	2029, 0,
            1, 8, 1, /* 4612: pointer.struct.asn1_string_st */
            	4434, 0,
            1, 8, 1, /* 4617: pointer.struct.x509_cinf_st */
            	4622, 0,
            0, 104, 11, /* 4622: struct.x509_cinf_st */
            	4612, 0,
            	4612, 8,
            	4607, 16,
            	4647, 24,
            	4666, 32,
            	4647, 40,
            	4561, 48,
            	4556, 56,
            	4556, 64,
            	4532, 72,
            	4527, 80,
            1, 8, 1, /* 4647: pointer.struct.X509_name_st */
            	4652, 0,
            0, 40, 3, /* 4652: struct.X509_name_st */
            	4583, 0,
            	4661, 16,
            	137, 24,
            1, 8, 1, /* 4661: pointer.struct.buf_mem_st */
            	4578, 0,
            1, 8, 1, /* 4666: pointer.struct.X509_val_st */
            	4566, 0,
            1, 8, 1, /* 4671: pointer.struct.cert_pkey_st */
            	4676, 0,
            0, 24, 3, /* 4676: struct.cert_pkey_st */
            	4685, 0,
            	4722, 8,
            	4727, 16,
            1, 8, 1, /* 4685: pointer.struct.x509_st */
            	4690, 0,
            0, 184, 12, /* 4690: struct.x509_st */
            	4617, 0,
            	4607, 8,
            	4556, 16,
            	172, 32,
            	4517, 40,
            	4476, 104,
            	2606, 112,
            	2929, 120,
            	3360, 128,
            	3499, 136,
            	3523, 144,
            	4717, 176,
            1, 8, 1, /* 4717: pointer.struct.x509_cert_aux_st */
            	4439, 0,
            1, 8, 1, /* 4722: pointer.struct.evp_pkey_st */
            	4394, 0,
            1, 8, 1, /* 4727: pointer.struct.env_md_st */
            	4338, 0,
            1, 8, 1, /* 4732: pointer.struct.stack_st_X509_ALGOR */
            	4737, 0,
            0, 32, 2, /* 4737: struct.stack_st_fake_X509_ALGOR */
            	4744, 8,
            	177, 24,
            8884099, 8, 2, /* 4744: pointer_to_array_of_pointers_to_stack */
            	4751, 0,
            	36, 20,
            0, 8, 1, /* 4751: pointer.X509_ALGOR */
            	2024, 0,
            1, 8, 1, /* 4756: pointer.struct.stack_st_ASN1_OBJECT */
            	4761, 0,
            0, 32, 2, /* 4761: struct.stack_st_fake_ASN1_OBJECT */
            	4768, 8,
            	177, 24,
            8884099, 8, 2, /* 4768: pointer_to_array_of_pointers_to_stack */
            	4775, 0,
            	36, 20,
            0, 8, 1, /* 4775: pointer.ASN1_OBJECT */
            	3246, 0,
            0, 40, 5, /* 4780: struct.x509_cert_aux_st */
            	4756, 0,
            	4756, 8,
            	4793, 16,
            	4803, 24,
            	4732, 32,
            1, 8, 1, /* 4793: pointer.struct.asn1_string_st */
            	4798, 0,
            0, 24, 1, /* 4798: struct.asn1_string_st */
            	137, 8,
            1, 8, 1, /* 4803: pointer.struct.asn1_string_st */
            	4798, 0,
            1, 8, 1, /* 4808: pointer.struct.x509_cert_aux_st */
            	4780, 0,
            1, 8, 1, /* 4813: pointer.struct.NAME_CONSTRAINTS_st */
            	3528, 0,
            1, 8, 1, /* 4818: pointer.struct.stack_st_GENERAL_NAME */
            	4823, 0,
            0, 32, 2, /* 4823: struct.stack_st_fake_GENERAL_NAME */
            	4830, 8,
            	177, 24,
            8884099, 8, 2, /* 4830: pointer_to_array_of_pointers_to_stack */
            	4837, 0,
            	36, 20,
            0, 8, 1, /* 4837: pointer.GENERAL_NAME */
            	2654, 0,
            1, 8, 1, /* 4842: pointer.struct.bignum_st */
            	21, 0,
            1, 8, 1, /* 4847: pointer.struct.X509_POLICY_CACHE_st */
            	2934, 0,
            1, 8, 1, /* 4852: pointer.struct.AUTHORITY_KEYID_st */
            	2611, 0,
            1, 8, 1, /* 4857: pointer.struct.stack_st_X509_EXTENSION */
            	4862, 0,
            0, 32, 2, /* 4862: struct.stack_st_fake_X509_EXTENSION */
            	4869, 8,
            	177, 24,
            8884099, 8, 2, /* 4869: pointer_to_array_of_pointers_to_stack */
            	4876, 0,
            	36, 20,
            0, 8, 1, /* 4876: pointer.X509_EXTENSION */
            	2234, 0,
            1, 8, 1, /* 4881: pointer.struct.asn1_string_st */
            	4798, 0,
            1, 8, 1, /* 4886: pointer.struct.X509_pubkey_st */
            	2275, 0,
            1, 8, 1, /* 4891: pointer.struct.asn1_string_st */
            	4798, 0,
            0, 24, 1, /* 4896: struct.buf_mem_st */
            	172, 8,
            1, 8, 1, /* 4901: pointer.struct.buf_mem_st */
            	4896, 0,
            1, 8, 1, /* 4906: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4911, 0,
            0, 32, 2, /* 4911: struct.stack_st_fake_X509_NAME_ENTRY */
            	4918, 8,
            	177, 24,
            8884099, 8, 2, /* 4918: pointer_to_array_of_pointers_to_stack */
            	4925, 0,
            	36, 20,
            0, 8, 1, /* 4925: pointer.X509_NAME_ENTRY */
            	2416, 0,
            0, 40, 3, /* 4930: struct.X509_name_st */
            	4906, 0,
            	4901, 16,
            	137, 24,
            1, 8, 1, /* 4939: pointer.struct.X509_name_st */
            	4930, 0,
            1, 8, 1, /* 4944: pointer.struct.asn1_string_st */
            	4798, 0,
            0, 104, 11, /* 4949: struct.x509_cinf_st */
            	4944, 0,
            	4944, 8,
            	4974, 16,
            	4939, 24,
            	4979, 32,
            	4939, 40,
            	4886, 48,
            	4881, 56,
            	4881, 64,
            	4857, 72,
            	4991, 80,
            1, 8, 1, /* 4974: pointer.struct.X509_algor_st */
            	2029, 0,
            1, 8, 1, /* 4979: pointer.struct.X509_val_st */
            	4984, 0,
            0, 16, 2, /* 4984: struct.X509_val_st */
            	4891, 0,
            	4891, 8,
            0, 24, 1, /* 4991: struct.ASN1_ENCODING_st */
            	137, 0,
            1, 8, 1, /* 4996: pointer.struct.x509_cinf_st */
            	4949, 0,
            0, 352, 14, /* 5001: struct.ssl_session_st */
            	172, 144,
            	172, 152,
            	5032, 168,
            	5157, 176,
            	4097, 224,
            	5211, 240,
            	5189, 248,
            	5245, 264,
            	5245, 272,
            	172, 280,
            	137, 296,
            	137, 312,
            	137, 320,
            	172, 344,
            1, 8, 1, /* 5032: pointer.struct.sess_cert_st */
            	5037, 0,
            0, 248, 5, /* 5037: struct.sess_cert_st */
            	5050, 0,
            	4671, 16,
            	5152, 216,
            	4327, 224,
            	3885, 232,
            1, 8, 1, /* 5050: pointer.struct.stack_st_X509 */
            	5055, 0,
            0, 32, 2, /* 5055: struct.stack_st_fake_X509 */
            	5062, 8,
            	177, 24,
            8884099, 8, 2, /* 5062: pointer_to_array_of_pointers_to_stack */
            	5069, 0,
            	36, 20,
            0, 8, 1, /* 5069: pointer.X509 */
            	5074, 0,
            0, 0, 1, /* 5074: X509 */
            	5079, 0,
            0, 184, 12, /* 5079: struct.x509_st */
            	4996, 0,
            	4974, 8,
            	4881, 16,
            	172, 32,
            	5106, 40,
            	4803, 104,
            	4852, 112,
            	4847, 120,
            	5128, 128,
            	4818, 136,
            	4813, 144,
            	4808, 176,
            0, 16, 1, /* 5106: struct.crypto_ex_data_st */
            	5111, 0,
            1, 8, 1, /* 5111: pointer.struct.stack_st_void */
            	5116, 0,
            0, 32, 1, /* 5116: struct.stack_st_void */
            	5121, 0,
            0, 32, 2, /* 5121: struct.stack_st */
            	167, 8,
            	177, 24,
            1, 8, 1, /* 5128: pointer.struct.stack_st_DIST_POINT */
            	5133, 0,
            0, 32, 2, /* 5133: struct.stack_st_fake_DIST_POINT */
            	5140, 8,
            	177, 24,
            8884099, 8, 2, /* 5140: pointer_to_array_of_pointers_to_stack */
            	5147, 0,
            	36, 20,
            0, 8, 1, /* 5147: pointer.DIST_POINT */
            	3384, 0,
            1, 8, 1, /* 5152: pointer.struct.rsa_st */
            	569, 0,
            1, 8, 1, /* 5157: pointer.struct.x509_st */
            	5162, 0,
            0, 184, 12, /* 5162: struct.x509_st */
            	4322, 0,
            	4287, 8,
            	4212, 16,
            	172, 32,
            	5189, 40,
            	4178, 104,
            	2606, 112,
            	2929, 120,
            	3360, 128,
            	3499, 136,
            	3523, 144,
            	4136, 176,
            0, 16, 1, /* 5189: struct.crypto_ex_data_st */
            	5194, 0,
            1, 8, 1, /* 5194: pointer.struct.stack_st_void */
            	5199, 0,
            0, 32, 1, /* 5199: struct.stack_st_void */
            	5204, 0,
            0, 32, 2, /* 5204: struct.stack_st */
            	167, 8,
            	177, 24,
            1, 8, 1, /* 5211: pointer.struct.stack_st_SSL_CIPHER */
            	5216, 0,
            0, 32, 2, /* 5216: struct.stack_st_fake_SSL_CIPHER */
            	5223, 8,
            	177, 24,
            8884099, 8, 2, /* 5223: pointer_to_array_of_pointers_to_stack */
            	5230, 0,
            	36, 20,
            0, 8, 1, /* 5230: pointer.SSL_CIPHER */
            	5235, 0,
            0, 0, 1, /* 5235: SSL_CIPHER */
            	5240, 0,
            0, 88, 1, /* 5240: struct.ssl_cipher_st */
            	13, 8,
            1, 8, 1, /* 5245: pointer.struct.ssl_session_st */
            	5001, 0,
            1, 8, 1, /* 5250: pointer.struct.lhash_node_st */
            	5255, 0,
            0, 24, 2, /* 5255: struct.lhash_node_st */
            	763, 0,
            	5250, 8,
            0, 176, 3, /* 5262: struct.lhash_st */
            	5271, 0,
            	177, 8,
            	5278, 16,
            8884099, 8, 2, /* 5271: pointer_to_array_of_pointers_to_stack */
            	5250, 0,
            	33, 28,
            8884097, 8, 0, /* 5278: pointer.func */
            1, 8, 1, /* 5281: pointer.struct.lhash_st */
            	5262, 0,
            8884097, 8, 0, /* 5286: pointer.func */
            8884097, 8, 0, /* 5289: pointer.func */
            8884097, 8, 0, /* 5292: pointer.func */
            8884097, 8, 0, /* 5295: pointer.func */
            8884097, 8, 0, /* 5298: pointer.func */
            0, 56, 2, /* 5301: struct.X509_VERIFY_PARAM_st */
            	172, 0,
            	4154, 48,
            1, 8, 1, /* 5308: pointer.struct.X509_VERIFY_PARAM_st */
            	5301, 0,
            8884097, 8, 0, /* 5313: pointer.func */
            8884097, 8, 0, /* 5316: pointer.func */
            8884097, 8, 0, /* 5319: pointer.func */
            1, 8, 1, /* 5322: pointer.struct.X509_VERIFY_PARAM_st */
            	5327, 0,
            0, 56, 2, /* 5327: struct.X509_VERIFY_PARAM_st */
            	172, 0,
            	5334, 48,
            1, 8, 1, /* 5334: pointer.struct.stack_st_ASN1_OBJECT */
            	5339, 0,
            0, 32, 2, /* 5339: struct.stack_st_fake_ASN1_OBJECT */
            	5346, 8,
            	177, 24,
            8884099, 8, 2, /* 5346: pointer_to_array_of_pointers_to_stack */
            	5353, 0,
            	36, 20,
            0, 8, 1, /* 5353: pointer.ASN1_OBJECT */
            	3246, 0,
            1, 8, 1, /* 5358: pointer.struct.stack_st_X509_LOOKUP */
            	5363, 0,
            0, 32, 2, /* 5363: struct.stack_st_fake_X509_LOOKUP */
            	5370, 8,
            	177, 24,
            8884099, 8, 2, /* 5370: pointer_to_array_of_pointers_to_stack */
            	5377, 0,
            	36, 20,
            0, 8, 1, /* 5377: pointer.X509_LOOKUP */
            	5382, 0,
            0, 0, 1, /* 5382: X509_LOOKUP */
            	5387, 0,
            0, 32, 3, /* 5387: struct.x509_lookup_st */
            	5396, 8,
            	172, 16,
            	5445, 24,
            1, 8, 1, /* 5396: pointer.struct.x509_lookup_method_st */
            	5401, 0,
            0, 80, 10, /* 5401: struct.x509_lookup_method_st */
            	13, 0,
            	5424, 8,
            	5427, 16,
            	5424, 24,
            	5424, 32,
            	5430, 40,
            	5433, 48,
            	5436, 56,
            	5439, 64,
            	5442, 72,
            8884097, 8, 0, /* 5424: pointer.func */
            8884097, 8, 0, /* 5427: pointer.func */
            8884097, 8, 0, /* 5430: pointer.func */
            8884097, 8, 0, /* 5433: pointer.func */
            8884097, 8, 0, /* 5436: pointer.func */
            8884097, 8, 0, /* 5439: pointer.func */
            8884097, 8, 0, /* 5442: pointer.func */
            1, 8, 1, /* 5445: pointer.struct.x509_store_st */
            	5450, 0,
            0, 144, 15, /* 5450: struct.x509_store_st */
            	5483, 8,
            	5358, 16,
            	5322, 24,
            	5319, 32,
            	5316, 40,
            	6263, 48,
            	6266, 56,
            	5319, 64,
            	6269, 72,
            	6272, 80,
            	6275, 88,
            	5313, 96,
            	6278, 104,
            	5319, 112,
            	5709, 120,
            1, 8, 1, /* 5483: pointer.struct.stack_st_X509_OBJECT */
            	5488, 0,
            0, 32, 2, /* 5488: struct.stack_st_fake_X509_OBJECT */
            	5495, 8,
            	177, 24,
            8884099, 8, 2, /* 5495: pointer_to_array_of_pointers_to_stack */
            	5502, 0,
            	36, 20,
            0, 8, 1, /* 5502: pointer.X509_OBJECT */
            	5507, 0,
            0, 0, 1, /* 5507: X509_OBJECT */
            	5512, 0,
            0, 16, 1, /* 5512: struct.x509_object_st */
            	5517, 8,
            0, 8, 4, /* 5517: union.unknown */
            	172, 0,
            	5528, 0,
            	5846, 0,
            	6180, 0,
            1, 8, 1, /* 5528: pointer.struct.x509_st */
            	5533, 0,
            0, 184, 12, /* 5533: struct.x509_st */
            	5560, 0,
            	5600, 8,
            	5675, 16,
            	172, 32,
            	5709, 40,
            	5731, 104,
            	5736, 112,
            	5741, 120,
            	5746, 128,
            	5770, 136,
            	5794, 144,
            	5799, 176,
            1, 8, 1, /* 5560: pointer.struct.x509_cinf_st */
            	5565, 0,
            0, 104, 11, /* 5565: struct.x509_cinf_st */
            	5590, 0,
            	5590, 8,
            	5600, 16,
            	5605, 24,
            	5653, 32,
            	5605, 40,
            	5670, 48,
            	5675, 56,
            	5675, 64,
            	5680, 72,
            	5704, 80,
            1, 8, 1, /* 5590: pointer.struct.asn1_string_st */
            	5595, 0,
            0, 24, 1, /* 5595: struct.asn1_string_st */
            	137, 8,
            1, 8, 1, /* 5600: pointer.struct.X509_algor_st */
            	2029, 0,
            1, 8, 1, /* 5605: pointer.struct.X509_name_st */
            	5610, 0,
            0, 40, 3, /* 5610: struct.X509_name_st */
            	5619, 0,
            	5643, 16,
            	137, 24,
            1, 8, 1, /* 5619: pointer.struct.stack_st_X509_NAME_ENTRY */
            	5624, 0,
            0, 32, 2, /* 5624: struct.stack_st_fake_X509_NAME_ENTRY */
            	5631, 8,
            	177, 24,
            8884099, 8, 2, /* 5631: pointer_to_array_of_pointers_to_stack */
            	5638, 0,
            	36, 20,
            0, 8, 1, /* 5638: pointer.X509_NAME_ENTRY */
            	2416, 0,
            1, 8, 1, /* 5643: pointer.struct.buf_mem_st */
            	5648, 0,
            0, 24, 1, /* 5648: struct.buf_mem_st */
            	172, 8,
            1, 8, 1, /* 5653: pointer.struct.X509_val_st */
            	5658, 0,
            0, 16, 2, /* 5658: struct.X509_val_st */
            	5665, 0,
            	5665, 8,
            1, 8, 1, /* 5665: pointer.struct.asn1_string_st */
            	5595, 0,
            1, 8, 1, /* 5670: pointer.struct.X509_pubkey_st */
            	2275, 0,
            1, 8, 1, /* 5675: pointer.struct.asn1_string_st */
            	5595, 0,
            1, 8, 1, /* 5680: pointer.struct.stack_st_X509_EXTENSION */
            	5685, 0,
            0, 32, 2, /* 5685: struct.stack_st_fake_X509_EXTENSION */
            	5692, 8,
            	177, 24,
            8884099, 8, 2, /* 5692: pointer_to_array_of_pointers_to_stack */
            	5699, 0,
            	36, 20,
            0, 8, 1, /* 5699: pointer.X509_EXTENSION */
            	2234, 0,
            0, 24, 1, /* 5704: struct.ASN1_ENCODING_st */
            	137, 0,
            0, 16, 1, /* 5709: struct.crypto_ex_data_st */
            	5714, 0,
            1, 8, 1, /* 5714: pointer.struct.stack_st_void */
            	5719, 0,
            0, 32, 1, /* 5719: struct.stack_st_void */
            	5724, 0,
            0, 32, 2, /* 5724: struct.stack_st */
            	167, 8,
            	177, 24,
            1, 8, 1, /* 5731: pointer.struct.asn1_string_st */
            	5595, 0,
            1, 8, 1, /* 5736: pointer.struct.AUTHORITY_KEYID_st */
            	2611, 0,
            1, 8, 1, /* 5741: pointer.struct.X509_POLICY_CACHE_st */
            	2934, 0,
            1, 8, 1, /* 5746: pointer.struct.stack_st_DIST_POINT */
            	5751, 0,
            0, 32, 2, /* 5751: struct.stack_st_fake_DIST_POINT */
            	5758, 8,
            	177, 24,
            8884099, 8, 2, /* 5758: pointer_to_array_of_pointers_to_stack */
            	5765, 0,
            	36, 20,
            0, 8, 1, /* 5765: pointer.DIST_POINT */
            	3384, 0,
            1, 8, 1, /* 5770: pointer.struct.stack_st_GENERAL_NAME */
            	5775, 0,
            0, 32, 2, /* 5775: struct.stack_st_fake_GENERAL_NAME */
            	5782, 8,
            	177, 24,
            8884099, 8, 2, /* 5782: pointer_to_array_of_pointers_to_stack */
            	5789, 0,
            	36, 20,
            0, 8, 1, /* 5789: pointer.GENERAL_NAME */
            	2654, 0,
            1, 8, 1, /* 5794: pointer.struct.NAME_CONSTRAINTS_st */
            	3528, 0,
            1, 8, 1, /* 5799: pointer.struct.x509_cert_aux_st */
            	5804, 0,
            0, 40, 5, /* 5804: struct.x509_cert_aux_st */
            	5334, 0,
            	5334, 8,
            	5817, 16,
            	5731, 24,
            	5822, 32,
            1, 8, 1, /* 5817: pointer.struct.asn1_string_st */
            	5595, 0,
            1, 8, 1, /* 5822: pointer.struct.stack_st_X509_ALGOR */
            	5827, 0,
            0, 32, 2, /* 5827: struct.stack_st_fake_X509_ALGOR */
            	5834, 8,
            	177, 24,
            8884099, 8, 2, /* 5834: pointer_to_array_of_pointers_to_stack */
            	5841, 0,
            	36, 20,
            0, 8, 1, /* 5841: pointer.X509_ALGOR */
            	2024, 0,
            1, 8, 1, /* 5846: pointer.struct.X509_crl_st */
            	5851, 0,
            0, 120, 10, /* 5851: struct.X509_crl_st */
            	5874, 0,
            	5600, 8,
            	5675, 16,
            	5736, 32,
            	6001, 40,
            	5590, 56,
            	5590, 64,
            	6114, 96,
            	6155, 104,
            	763, 112,
            1, 8, 1, /* 5874: pointer.struct.X509_crl_info_st */
            	5879, 0,
            0, 80, 8, /* 5879: struct.X509_crl_info_st */
            	5590, 0,
            	5600, 8,
            	5605, 16,
            	5665, 24,
            	5665, 32,
            	5898, 40,
            	5680, 48,
            	5704, 56,
            1, 8, 1, /* 5898: pointer.struct.stack_st_X509_REVOKED */
            	5903, 0,
            0, 32, 2, /* 5903: struct.stack_st_fake_X509_REVOKED */
            	5910, 8,
            	177, 24,
            8884099, 8, 2, /* 5910: pointer_to_array_of_pointers_to_stack */
            	5917, 0,
            	36, 20,
            0, 8, 1, /* 5917: pointer.X509_REVOKED */
            	5922, 0,
            0, 0, 1, /* 5922: X509_REVOKED */
            	5927, 0,
            0, 40, 4, /* 5927: struct.x509_revoked_st */
            	5938, 0,
            	5948, 8,
            	5953, 16,
            	5977, 24,
            1, 8, 1, /* 5938: pointer.struct.asn1_string_st */
            	5943, 0,
            0, 24, 1, /* 5943: struct.asn1_string_st */
            	137, 8,
            1, 8, 1, /* 5948: pointer.struct.asn1_string_st */
            	5943, 0,
            1, 8, 1, /* 5953: pointer.struct.stack_st_X509_EXTENSION */
            	5958, 0,
            0, 32, 2, /* 5958: struct.stack_st_fake_X509_EXTENSION */
            	5965, 8,
            	177, 24,
            8884099, 8, 2, /* 5965: pointer_to_array_of_pointers_to_stack */
            	5972, 0,
            	36, 20,
            0, 8, 1, /* 5972: pointer.X509_EXTENSION */
            	2234, 0,
            1, 8, 1, /* 5977: pointer.struct.stack_st_GENERAL_NAME */
            	5982, 0,
            0, 32, 2, /* 5982: struct.stack_st_fake_GENERAL_NAME */
            	5989, 8,
            	177, 24,
            8884099, 8, 2, /* 5989: pointer_to_array_of_pointers_to_stack */
            	5996, 0,
            	36, 20,
            0, 8, 1, /* 5996: pointer.GENERAL_NAME */
            	2654, 0,
            1, 8, 1, /* 6001: pointer.struct.ISSUING_DIST_POINT_st */
            	6006, 0,
            0, 32, 2, /* 6006: struct.ISSUING_DIST_POINT_st */
            	6013, 0,
            	6104, 16,
            1, 8, 1, /* 6013: pointer.struct.DIST_POINT_NAME_st */
            	6018, 0,
            0, 24, 2, /* 6018: struct.DIST_POINT_NAME_st */
            	6025, 8,
            	6080, 16,
            0, 8, 2, /* 6025: union.unknown */
            	6032, 0,
            	6056, 0,
            1, 8, 1, /* 6032: pointer.struct.stack_st_GENERAL_NAME */
            	6037, 0,
            0, 32, 2, /* 6037: struct.stack_st_fake_GENERAL_NAME */
            	6044, 8,
            	177, 24,
            8884099, 8, 2, /* 6044: pointer_to_array_of_pointers_to_stack */
            	6051, 0,
            	36, 20,
            0, 8, 1, /* 6051: pointer.GENERAL_NAME */
            	2654, 0,
            1, 8, 1, /* 6056: pointer.struct.stack_st_X509_NAME_ENTRY */
            	6061, 0,
            0, 32, 2, /* 6061: struct.stack_st_fake_X509_NAME_ENTRY */
            	6068, 8,
            	177, 24,
            8884099, 8, 2, /* 6068: pointer_to_array_of_pointers_to_stack */
            	6075, 0,
            	36, 20,
            0, 8, 1, /* 6075: pointer.X509_NAME_ENTRY */
            	2416, 0,
            1, 8, 1, /* 6080: pointer.struct.X509_name_st */
            	6085, 0,
            0, 40, 3, /* 6085: struct.X509_name_st */
            	6056, 0,
            	6094, 16,
            	137, 24,
            1, 8, 1, /* 6094: pointer.struct.buf_mem_st */
            	6099, 0,
            0, 24, 1, /* 6099: struct.buf_mem_st */
            	172, 8,
            1, 8, 1, /* 6104: pointer.struct.asn1_string_st */
            	6109, 0,
            0, 24, 1, /* 6109: struct.asn1_string_st */
            	137, 8,
            1, 8, 1, /* 6114: pointer.struct.stack_st_GENERAL_NAMES */
            	6119, 0,
            0, 32, 2, /* 6119: struct.stack_st_fake_GENERAL_NAMES */
            	6126, 8,
            	177, 24,
            8884099, 8, 2, /* 6126: pointer_to_array_of_pointers_to_stack */
            	6133, 0,
            	36, 20,
            0, 8, 1, /* 6133: pointer.GENERAL_NAMES */
            	6138, 0,
            0, 0, 1, /* 6138: GENERAL_NAMES */
            	6143, 0,
            0, 32, 1, /* 6143: struct.stack_st_GENERAL_NAME */
            	6148, 0,
            0, 32, 2, /* 6148: struct.stack_st */
            	167, 8,
            	177, 24,
            1, 8, 1, /* 6155: pointer.struct.x509_crl_method_st */
            	6160, 0,
            0, 40, 4, /* 6160: struct.x509_crl_method_st */
            	6171, 8,
            	6171, 16,
            	6174, 24,
            	6177, 32,
            8884097, 8, 0, /* 6171: pointer.func */
            8884097, 8, 0, /* 6174: pointer.func */
            8884097, 8, 0, /* 6177: pointer.func */
            1, 8, 1, /* 6180: pointer.struct.evp_pkey_st */
            	6185, 0,
            0, 56, 4, /* 6185: struct.evp_pkey_st */
            	6196, 16,
            	6201, 24,
            	6206, 32,
            	6239, 48,
            1, 8, 1, /* 6196: pointer.struct.evp_pkey_asn1_method_st */
            	1899, 0,
            1, 8, 1, /* 6201: pointer.struct.engine_st */
            	221, 0,
            0, 8, 5, /* 6206: union.unknown */
            	172, 0,
            	6219, 0,
            	6224, 0,
            	6229, 0,
            	6234, 0,
            1, 8, 1, /* 6219: pointer.struct.rsa_st */
            	569, 0,
            1, 8, 1, /* 6224: pointer.struct.dsa_st */
            	1222, 0,
            1, 8, 1, /* 6229: pointer.struct.dh_st */
            	79, 0,
            1, 8, 1, /* 6234: pointer.struct.ec_key_st */
            	1379, 0,
            1, 8, 1, /* 6239: pointer.struct.stack_st_X509_ATTRIBUTE */
            	6244, 0,
            0, 32, 2, /* 6244: struct.stack_st_fake_X509_ATTRIBUTE */
            	6251, 8,
            	177, 24,
            8884099, 8, 2, /* 6251: pointer_to_array_of_pointers_to_stack */
            	6258, 0,
            	36, 20,
            0, 8, 1, /* 6258: pointer.X509_ATTRIBUTE */
            	852, 0,
            8884097, 8, 0, /* 6263: pointer.func */
            8884097, 8, 0, /* 6266: pointer.func */
            8884097, 8, 0, /* 6269: pointer.func */
            8884097, 8, 0, /* 6272: pointer.func */
            8884097, 8, 0, /* 6275: pointer.func */
            8884097, 8, 0, /* 6278: pointer.func */
            1, 8, 1, /* 6281: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	6286, 0,
            0, 32, 2, /* 6286: struct.stack_st_fake_SRTP_PROTECTION_PROFILE */
            	6293, 8,
            	177, 24,
            8884099, 8, 2, /* 6293: pointer_to_array_of_pointers_to_stack */
            	6300, 0,
            	36, 20,
            0, 8, 1, /* 6300: pointer.SRTP_PROTECTION_PROFILE */
            	3, 0,
            1, 8, 1, /* 6305: pointer.struct.stack_st_X509 */
            	6310, 0,
            0, 32, 2, /* 6310: struct.stack_st_fake_X509 */
            	6317, 8,
            	177, 24,
            8884099, 8, 2, /* 6317: pointer_to_array_of_pointers_to_stack */
            	6324, 0,
            	36, 20,
            0, 8, 1, /* 6324: pointer.X509 */
            	5074, 0,
            8884097, 8, 0, /* 6329: pointer.func */
            1, 8, 1, /* 6332: pointer.struct.ssl_ctx_st */
            	6337, 0,
            0, 736, 50, /* 6337: struct.ssl_ctx_st */
            	6440, 0,
            	5211, 8,
            	5211, 16,
            	6606, 24,
            	5281, 32,
            	5245, 48,
            	5245, 56,
            	4089, 80,
            	6701, 88,
            	6704, 96,
            	6707, 152,
            	763, 160,
            	4086, 168,
            	763, 176,
            	4083, 184,
            	4080, 192,
            	4077, 200,
            	5189, 208,
            	4072, 224,
            	4072, 232,
            	4072, 240,
            	6305, 248,
            	4014, 256,
            	3965, 264,
            	3941, 272,
            	6710, 304,
            	6715, 320,
            	763, 328,
            	5295, 376,
            	68, 384,
            	5308, 392,
            	1995, 408,
            	6718, 416,
            	763, 424,
            	6721, 480,
            	65, 488,
            	763, 496,
            	62, 504,
            	763, 512,
            	172, 520,
            	59, 528,
            	6724, 536,
            	39, 552,
            	39, 560,
            	6727, 568,
            	6761, 696,
            	763, 704,
            	18, 712,
            	763, 720,
            	6281, 728,
            1, 8, 1, /* 6440: pointer.struct.ssl_method_st */
            	6445, 0,
            0, 232, 28, /* 6445: struct.ssl_method_st */
            	6504, 8,
            	6507, 16,
            	6507, 24,
            	6504, 32,
            	6504, 40,
            	6510, 48,
            	6510, 56,
            	6513, 64,
            	6504, 72,
            	6504, 80,
            	6504, 88,
            	6516, 96,
            	6519, 104,
            	6522, 112,
            	6504, 120,
            	6525, 128,
            	6528, 136,
            	6531, 144,
            	6534, 152,
            	6537, 160,
            	490, 168,
            	6540, 176,
            	6543, 184,
            	3994, 192,
            	6546, 200,
            	490, 208,
            	6600, 216,
            	6603, 224,
            8884097, 8, 0, /* 6504: pointer.func */
            8884097, 8, 0, /* 6507: pointer.func */
            8884097, 8, 0, /* 6510: pointer.func */
            8884097, 8, 0, /* 6513: pointer.func */
            8884097, 8, 0, /* 6516: pointer.func */
            8884097, 8, 0, /* 6519: pointer.func */
            8884097, 8, 0, /* 6522: pointer.func */
            8884097, 8, 0, /* 6525: pointer.func */
            8884097, 8, 0, /* 6528: pointer.func */
            8884097, 8, 0, /* 6531: pointer.func */
            8884097, 8, 0, /* 6534: pointer.func */
            8884097, 8, 0, /* 6537: pointer.func */
            8884097, 8, 0, /* 6540: pointer.func */
            8884097, 8, 0, /* 6543: pointer.func */
            1, 8, 1, /* 6546: pointer.struct.ssl3_enc_method */
            	6551, 0,
            0, 112, 11, /* 6551: struct.ssl3_enc_method */
            	6576, 0,
            	6579, 8,
            	6582, 16,
            	6585, 24,
            	6576, 32,
            	6588, 40,
            	6591, 56,
            	13, 64,
            	13, 80,
            	6594, 96,
            	6597, 104,
            8884097, 8, 0, /* 6576: pointer.func */
            8884097, 8, 0, /* 6579: pointer.func */
            8884097, 8, 0, /* 6582: pointer.func */
            8884097, 8, 0, /* 6585: pointer.func */
            8884097, 8, 0, /* 6588: pointer.func */
            8884097, 8, 0, /* 6591: pointer.func */
            8884097, 8, 0, /* 6594: pointer.func */
            8884097, 8, 0, /* 6597: pointer.func */
            8884097, 8, 0, /* 6600: pointer.func */
            8884097, 8, 0, /* 6603: pointer.func */
            1, 8, 1, /* 6606: pointer.struct.x509_store_st */
            	6611, 0,
            0, 144, 15, /* 6611: struct.x509_store_st */
            	6644, 8,
            	6668, 16,
            	5308, 24,
            	5298, 32,
            	5295, 40,
            	5292, 48,
            	6329, 56,
            	5298, 64,
            	6692, 72,
            	6695, 80,
            	5289, 88,
            	6698, 96,
            	5286, 104,
            	5298, 112,
            	5189, 120,
            1, 8, 1, /* 6644: pointer.struct.stack_st_X509_OBJECT */
            	6649, 0,
            0, 32, 2, /* 6649: struct.stack_st_fake_X509_OBJECT */
            	6656, 8,
            	177, 24,
            8884099, 8, 2, /* 6656: pointer_to_array_of_pointers_to_stack */
            	6663, 0,
            	36, 20,
            0, 8, 1, /* 6663: pointer.X509_OBJECT */
            	5507, 0,
            1, 8, 1, /* 6668: pointer.struct.stack_st_X509_LOOKUP */
            	6673, 0,
            0, 32, 2, /* 6673: struct.stack_st_fake_X509_LOOKUP */
            	6680, 8,
            	177, 24,
            8884099, 8, 2, /* 6680: pointer_to_array_of_pointers_to_stack */
            	6687, 0,
            	36, 20,
            0, 8, 1, /* 6687: pointer.X509_LOOKUP */
            	5382, 0,
            8884097, 8, 0, /* 6692: pointer.func */
            8884097, 8, 0, /* 6695: pointer.func */
            8884097, 8, 0, /* 6698: pointer.func */
            8884097, 8, 0, /* 6701: pointer.func */
            8884097, 8, 0, /* 6704: pointer.func */
            8884097, 8, 0, /* 6707: pointer.func */
            1, 8, 1, /* 6710: pointer.struct.cert_st */
            	2523, 0,
            8884097, 8, 0, /* 6715: pointer.func */
            8884097, 8, 0, /* 6718: pointer.func */
            8884097, 8, 0, /* 6721: pointer.func */
            8884097, 8, 0, /* 6724: pointer.func */
            0, 128, 14, /* 6727: struct.srp_ctx_st */
            	763, 0,
            	6718, 8,
            	65, 16,
            	6758, 24,
            	172, 32,
            	4842, 40,
            	4842, 48,
            	4842, 56,
            	4842, 64,
            	4842, 72,
            	4842, 80,
            	4842, 88,
            	4842, 96,
            	172, 104,
            8884097, 8, 0, /* 6758: pointer.func */
            8884097, 8, 0, /* 6761: pointer.func */
            0, 1, 0, /* 6764: char */
        },
        .arg_entity_index = { 6332, 0, },
        .ret_entity_index = -1,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    SSL_CTX * new_arg_a = *((SSL_CTX * *)new_args->args[0]);

    void (*new_arg_b)(struct ssl_ctx_st *,SSL_SESSION *) = *((void (**)(struct ssl_ctx_st *,SSL_SESSION *))new_args->args[1]);

    void (*orig_SSL_CTX_sess_set_remove_cb)(SSL_CTX *,void (*)(struct ssl_ctx_st *,SSL_SESSION *));
    orig_SSL_CTX_sess_set_remove_cb = dlsym(RTLD_NEXT, "SSL_CTX_sess_set_remove_cb");
    (*orig_SSL_CTX_sess_set_remove_cb)(new_arg_a,new_arg_b);

    syscall(889);

}

