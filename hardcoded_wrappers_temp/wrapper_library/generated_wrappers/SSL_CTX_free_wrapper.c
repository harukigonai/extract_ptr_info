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

void bb_SSL_CTX_free(SSL_CTX * arg_a);

void SSL_CTX_free(SSL_CTX * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_CTX_free called %lu\n", in_lib);
    if (!in_lib)
        bb_SSL_CTX_free(arg_a);
    else {
        void (*orig_SSL_CTX_free)(SSL_CTX *);
        orig_SSL_CTX_free = dlsym(RTLD_NEXT, "SSL_CTX_free");
        orig_SSL_CTX_free(arg_a);
    }
}

void bb_SSL_CTX_free(SSL_CTX * arg_a) 
{
    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 0, 1, /* 0: SRTP_PROTECTION_PROFILE */
            	5, 0,
            0, 16, 1, /* 5: struct.srtp_protection_profile_st */
            	10, 0,
            1, 8, 1, /* 10: pointer.char */
            	8884096, 0,
            8884097, 8, 0, /* 15: pointer.func */
            0, 128, 14, /* 18: struct.srp_ctx_st */
            	49, 0,
            	52, 8,
            	55, 16,
            	58, 24,
            	61, 32,
            	66, 40,
            	66, 48,
            	66, 56,
            	66, 64,
            	66, 72,
            	66, 80,
            	66, 88,
            	66, 96,
            	61, 104,
            0, 8, 0, /* 49: pointer.void */
            8884097, 8, 0, /* 52: pointer.func */
            8884097, 8, 0, /* 55: pointer.func */
            8884097, 8, 0, /* 58: pointer.func */
            1, 8, 1, /* 61: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 66: pointer.struct.bignum_st */
            	71, 0,
            0, 24, 1, /* 71: struct.bignum_st */
            	76, 0,
            1, 8, 1, /* 76: pointer.unsigned int */
            	81, 0,
            0, 4, 0, /* 81: unsigned int */
            1, 8, 1, /* 84: pointer.struct.ssl3_buf_freelist_entry_st */
            	89, 0,
            0, 8, 1, /* 89: struct.ssl3_buf_freelist_entry_st */
            	84, 0,
            8884097, 8, 0, /* 94: pointer.func */
            8884097, 8, 0, /* 97: pointer.func */
            8884097, 8, 0, /* 100: pointer.func */
            8884097, 8, 0, /* 103: pointer.func */
            0, 296, 7, /* 106: struct.cert_st */
            	123, 0,
            	2367, 48,
            	2372, 56,
            	2375, 64,
            	103, 72,
            	2380, 80,
            	100, 88,
            1, 8, 1, /* 123: pointer.struct.cert_pkey_st */
            	128, 0,
            0, 24, 3, /* 128: struct.cert_pkey_st */
            	137, 0,
            	500, 8,
            	2322, 16,
            1, 8, 1, /* 137: pointer.struct.x509_st */
            	142, 0,
            0, 184, 12, /* 142: struct.x509_st */
            	169, 0,
            	217, 8,
            	311, 16,
            	61, 32,
            	642, 40,
            	316, 104,
            	1292, 112,
            	1600, 120,
            	1608, 128,
            	1747, 136,
            	1771, 144,
            	2083, 176,
            1, 8, 1, /* 169: pointer.struct.x509_cinf_st */
            	174, 0,
            0, 104, 11, /* 174: struct.x509_cinf_st */
            	199, 0,
            	199, 8,
            	217, 16,
            	379, 24,
            	469, 32,
            	379, 40,
            	486, 48,
            	311, 56,
            	311, 64,
            	1227, 72,
            	1287, 80,
            1, 8, 1, /* 199: pointer.struct.asn1_string_st */
            	204, 0,
            0, 24, 1, /* 204: struct.asn1_string_st */
            	209, 8,
            1, 8, 1, /* 209: pointer.unsigned char */
            	214, 0,
            0, 1, 0, /* 214: unsigned char */
            1, 8, 1, /* 217: pointer.struct.X509_algor_st */
            	222, 0,
            0, 16, 2, /* 222: struct.X509_algor_st */
            	229, 0,
            	248, 8,
            1, 8, 1, /* 229: pointer.struct.asn1_object_st */
            	234, 0,
            0, 40, 3, /* 234: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	243, 24,
            1, 8, 1, /* 243: pointer.unsigned char */
            	214, 0,
            1, 8, 1, /* 248: pointer.struct.asn1_type_st */
            	253, 0,
            0, 16, 1, /* 253: struct.asn1_type_st */
            	258, 8,
            0, 8, 20, /* 258: union.unknown */
            	61, 0,
            	301, 0,
            	229, 0,
            	199, 0,
            	306, 0,
            	311, 0,
            	316, 0,
            	321, 0,
            	326, 0,
            	331, 0,
            	336, 0,
            	341, 0,
            	346, 0,
            	351, 0,
            	356, 0,
            	361, 0,
            	366, 0,
            	301, 0,
            	301, 0,
            	371, 0,
            1, 8, 1, /* 301: pointer.struct.asn1_string_st */
            	204, 0,
            1, 8, 1, /* 306: pointer.struct.asn1_string_st */
            	204, 0,
            1, 8, 1, /* 311: pointer.struct.asn1_string_st */
            	204, 0,
            1, 8, 1, /* 316: pointer.struct.asn1_string_st */
            	204, 0,
            1, 8, 1, /* 321: pointer.struct.asn1_string_st */
            	204, 0,
            1, 8, 1, /* 326: pointer.struct.asn1_string_st */
            	204, 0,
            1, 8, 1, /* 331: pointer.struct.asn1_string_st */
            	204, 0,
            1, 8, 1, /* 336: pointer.struct.asn1_string_st */
            	204, 0,
            1, 8, 1, /* 341: pointer.struct.asn1_string_st */
            	204, 0,
            1, 8, 1, /* 346: pointer.struct.asn1_string_st */
            	204, 0,
            1, 8, 1, /* 351: pointer.struct.asn1_string_st */
            	204, 0,
            1, 8, 1, /* 356: pointer.struct.asn1_string_st */
            	204, 0,
            1, 8, 1, /* 361: pointer.struct.asn1_string_st */
            	204, 0,
            1, 8, 1, /* 366: pointer.struct.asn1_string_st */
            	204, 0,
            1, 8, 1, /* 371: pointer.struct.ASN1_VALUE_st */
            	376, 0,
            0, 0, 0, /* 376: struct.ASN1_VALUE_st */
            1, 8, 1, /* 379: pointer.struct.X509_name_st */
            	384, 0,
            0, 40, 3, /* 384: struct.X509_name_st */
            	393, 0,
            	459, 16,
            	209, 24,
            1, 8, 1, /* 393: pointer.struct.stack_st_X509_NAME_ENTRY */
            	398, 0,
            0, 32, 2, /* 398: struct.stack_st_fake_X509_NAME_ENTRY */
            	405, 8,
            	456, 24,
            8884099, 8, 2, /* 405: pointer_to_array_of_pointers_to_stack */
            	412, 0,
            	453, 20,
            0, 8, 1, /* 412: pointer.X509_NAME_ENTRY */
            	417, 0,
            0, 0, 1, /* 417: X509_NAME_ENTRY */
            	422, 0,
            0, 24, 2, /* 422: struct.X509_name_entry_st */
            	429, 0,
            	443, 8,
            1, 8, 1, /* 429: pointer.struct.asn1_object_st */
            	434, 0,
            0, 40, 3, /* 434: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	243, 24,
            1, 8, 1, /* 443: pointer.struct.asn1_string_st */
            	448, 0,
            0, 24, 1, /* 448: struct.asn1_string_st */
            	209, 8,
            0, 4, 0, /* 453: int */
            8884097, 8, 0, /* 456: pointer.func */
            1, 8, 1, /* 459: pointer.struct.buf_mem_st */
            	464, 0,
            0, 24, 1, /* 464: struct.buf_mem_st */
            	61, 8,
            1, 8, 1, /* 469: pointer.struct.X509_val_st */
            	474, 0,
            0, 16, 2, /* 474: struct.X509_val_st */
            	481, 0,
            	481, 8,
            1, 8, 1, /* 481: pointer.struct.asn1_string_st */
            	204, 0,
            1, 8, 1, /* 486: pointer.struct.X509_pubkey_st */
            	491, 0,
            0, 24, 3, /* 491: struct.X509_pubkey_st */
            	217, 0,
            	311, 8,
            	500, 16,
            1, 8, 1, /* 500: pointer.struct.evp_pkey_st */
            	505, 0,
            0, 56, 4, /* 505: struct.evp_pkey_st */
            	516, 16,
            	524, 24,
            	532, 32,
            	848, 48,
            1, 8, 1, /* 516: pointer.struct.evp_pkey_asn1_method_st */
            	521, 0,
            0, 0, 0, /* 521: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 524: pointer.struct.engine_st */
            	529, 0,
            0, 0, 0, /* 529: struct.engine_st */
            0, 8, 5, /* 532: union.unknown */
            	61, 0,
            	545, 0,
            	691, 0,
            	772, 0,
            	840, 0,
            1, 8, 1, /* 545: pointer.struct.rsa_st */
            	550, 0,
            0, 168, 17, /* 550: struct.rsa_st */
            	587, 16,
            	524, 24,
            	66, 32,
            	66, 40,
            	66, 48,
            	66, 56,
            	66, 64,
            	66, 72,
            	66, 80,
            	66, 88,
            	642, 96,
            	669, 120,
            	669, 128,
            	669, 136,
            	61, 144,
            	683, 152,
            	683, 160,
            1, 8, 1, /* 587: pointer.struct.rsa_meth_st */
            	592, 0,
            0, 112, 13, /* 592: struct.rsa_meth_st */
            	10, 0,
            	621, 8,
            	621, 16,
            	621, 24,
            	621, 32,
            	624, 40,
            	627, 48,
            	630, 56,
            	630, 64,
            	61, 80,
            	633, 88,
            	636, 96,
            	639, 104,
            8884097, 8, 0, /* 621: pointer.func */
            8884097, 8, 0, /* 624: pointer.func */
            8884097, 8, 0, /* 627: pointer.func */
            8884097, 8, 0, /* 630: pointer.func */
            8884097, 8, 0, /* 633: pointer.func */
            8884097, 8, 0, /* 636: pointer.func */
            8884097, 8, 0, /* 639: pointer.func */
            0, 16, 1, /* 642: struct.crypto_ex_data_st */
            	647, 0,
            1, 8, 1, /* 647: pointer.struct.stack_st_void */
            	652, 0,
            0, 32, 1, /* 652: struct.stack_st_void */
            	657, 0,
            0, 32, 2, /* 657: struct.stack_st */
            	664, 8,
            	456, 24,
            1, 8, 1, /* 664: pointer.pointer.char */
            	61, 0,
            1, 8, 1, /* 669: pointer.struct.bn_mont_ctx_st */
            	674, 0,
            0, 96, 3, /* 674: struct.bn_mont_ctx_st */
            	71, 8,
            	71, 32,
            	71, 56,
            1, 8, 1, /* 683: pointer.struct.bn_blinding_st */
            	688, 0,
            0, 0, 0, /* 688: struct.bn_blinding_st */
            1, 8, 1, /* 691: pointer.struct.dsa_st */
            	696, 0,
            0, 136, 11, /* 696: struct.dsa_st */
            	66, 24,
            	66, 32,
            	66, 40,
            	66, 48,
            	66, 56,
            	66, 64,
            	66, 72,
            	669, 88,
            	642, 104,
            	721, 120,
            	524, 128,
            1, 8, 1, /* 721: pointer.struct.dsa_method */
            	726, 0,
            0, 96, 11, /* 726: struct.dsa_method */
            	10, 0,
            	751, 8,
            	754, 16,
            	757, 24,
            	760, 32,
            	763, 40,
            	766, 48,
            	766, 56,
            	61, 72,
            	769, 80,
            	766, 88,
            8884097, 8, 0, /* 751: pointer.func */
            8884097, 8, 0, /* 754: pointer.func */
            8884097, 8, 0, /* 757: pointer.func */
            8884097, 8, 0, /* 760: pointer.func */
            8884097, 8, 0, /* 763: pointer.func */
            8884097, 8, 0, /* 766: pointer.func */
            8884097, 8, 0, /* 769: pointer.func */
            1, 8, 1, /* 772: pointer.struct.dh_st */
            	777, 0,
            0, 144, 12, /* 777: struct.dh_st */
            	66, 8,
            	66, 16,
            	66, 32,
            	66, 40,
            	669, 56,
            	66, 64,
            	66, 72,
            	209, 80,
            	66, 96,
            	642, 112,
            	804, 128,
            	524, 136,
            1, 8, 1, /* 804: pointer.struct.dh_method */
            	809, 0,
            0, 72, 8, /* 809: struct.dh_method */
            	10, 0,
            	828, 8,
            	831, 16,
            	834, 24,
            	828, 32,
            	828, 40,
            	61, 56,
            	837, 64,
            8884097, 8, 0, /* 828: pointer.func */
            8884097, 8, 0, /* 831: pointer.func */
            8884097, 8, 0, /* 834: pointer.func */
            8884097, 8, 0, /* 837: pointer.func */
            1, 8, 1, /* 840: pointer.struct.ec_key_st */
            	845, 0,
            0, 0, 0, /* 845: struct.ec_key_st */
            1, 8, 1, /* 848: pointer.struct.stack_st_X509_ATTRIBUTE */
            	853, 0,
            0, 32, 2, /* 853: struct.stack_st_fake_X509_ATTRIBUTE */
            	860, 8,
            	456, 24,
            8884099, 8, 2, /* 860: pointer_to_array_of_pointers_to_stack */
            	867, 0,
            	453, 20,
            0, 8, 1, /* 867: pointer.X509_ATTRIBUTE */
            	872, 0,
            0, 0, 1, /* 872: X509_ATTRIBUTE */
            	877, 0,
            0, 24, 2, /* 877: struct.x509_attributes_st */
            	884, 0,
            	898, 16,
            1, 8, 1, /* 884: pointer.struct.asn1_object_st */
            	889, 0,
            0, 40, 3, /* 889: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	243, 24,
            0, 8, 3, /* 898: union.unknown */
            	61, 0,
            	907, 0,
            	1086, 0,
            1, 8, 1, /* 907: pointer.struct.stack_st_ASN1_TYPE */
            	912, 0,
            0, 32, 2, /* 912: struct.stack_st_fake_ASN1_TYPE */
            	919, 8,
            	456, 24,
            8884099, 8, 2, /* 919: pointer_to_array_of_pointers_to_stack */
            	926, 0,
            	453, 20,
            0, 8, 1, /* 926: pointer.ASN1_TYPE */
            	931, 0,
            0, 0, 1, /* 931: ASN1_TYPE */
            	936, 0,
            0, 16, 1, /* 936: struct.asn1_type_st */
            	941, 8,
            0, 8, 20, /* 941: union.unknown */
            	61, 0,
            	984, 0,
            	994, 0,
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
            	1063, 0,
            	1068, 0,
            	1073, 0,
            	984, 0,
            	984, 0,
            	1078, 0,
            1, 8, 1, /* 984: pointer.struct.asn1_string_st */
            	989, 0,
            0, 24, 1, /* 989: struct.asn1_string_st */
            	209, 8,
            1, 8, 1, /* 994: pointer.struct.asn1_object_st */
            	999, 0,
            0, 40, 3, /* 999: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	243, 24,
            1, 8, 1, /* 1008: pointer.struct.asn1_string_st */
            	989, 0,
            1, 8, 1, /* 1013: pointer.struct.asn1_string_st */
            	989, 0,
            1, 8, 1, /* 1018: pointer.struct.asn1_string_st */
            	989, 0,
            1, 8, 1, /* 1023: pointer.struct.asn1_string_st */
            	989, 0,
            1, 8, 1, /* 1028: pointer.struct.asn1_string_st */
            	989, 0,
            1, 8, 1, /* 1033: pointer.struct.asn1_string_st */
            	989, 0,
            1, 8, 1, /* 1038: pointer.struct.asn1_string_st */
            	989, 0,
            1, 8, 1, /* 1043: pointer.struct.asn1_string_st */
            	989, 0,
            1, 8, 1, /* 1048: pointer.struct.asn1_string_st */
            	989, 0,
            1, 8, 1, /* 1053: pointer.struct.asn1_string_st */
            	989, 0,
            1, 8, 1, /* 1058: pointer.struct.asn1_string_st */
            	989, 0,
            1, 8, 1, /* 1063: pointer.struct.asn1_string_st */
            	989, 0,
            1, 8, 1, /* 1068: pointer.struct.asn1_string_st */
            	989, 0,
            1, 8, 1, /* 1073: pointer.struct.asn1_string_st */
            	989, 0,
            1, 8, 1, /* 1078: pointer.struct.ASN1_VALUE_st */
            	1083, 0,
            0, 0, 0, /* 1083: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1086: pointer.struct.asn1_type_st */
            	1091, 0,
            0, 16, 1, /* 1091: struct.asn1_type_st */
            	1096, 8,
            0, 8, 20, /* 1096: union.unknown */
            	61, 0,
            	1139, 0,
            	884, 0,
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
            	1204, 0,
            	1209, 0,
            	1214, 0,
            	1139, 0,
            	1139, 0,
            	1219, 0,
            1, 8, 1, /* 1139: pointer.struct.asn1_string_st */
            	1144, 0,
            0, 24, 1, /* 1144: struct.asn1_string_st */
            	209, 8,
            1, 8, 1, /* 1149: pointer.struct.asn1_string_st */
            	1144, 0,
            1, 8, 1, /* 1154: pointer.struct.asn1_string_st */
            	1144, 0,
            1, 8, 1, /* 1159: pointer.struct.asn1_string_st */
            	1144, 0,
            1, 8, 1, /* 1164: pointer.struct.asn1_string_st */
            	1144, 0,
            1, 8, 1, /* 1169: pointer.struct.asn1_string_st */
            	1144, 0,
            1, 8, 1, /* 1174: pointer.struct.asn1_string_st */
            	1144, 0,
            1, 8, 1, /* 1179: pointer.struct.asn1_string_st */
            	1144, 0,
            1, 8, 1, /* 1184: pointer.struct.asn1_string_st */
            	1144, 0,
            1, 8, 1, /* 1189: pointer.struct.asn1_string_st */
            	1144, 0,
            1, 8, 1, /* 1194: pointer.struct.asn1_string_st */
            	1144, 0,
            1, 8, 1, /* 1199: pointer.struct.asn1_string_st */
            	1144, 0,
            1, 8, 1, /* 1204: pointer.struct.asn1_string_st */
            	1144, 0,
            1, 8, 1, /* 1209: pointer.struct.asn1_string_st */
            	1144, 0,
            1, 8, 1, /* 1214: pointer.struct.asn1_string_st */
            	1144, 0,
            1, 8, 1, /* 1219: pointer.struct.ASN1_VALUE_st */
            	1224, 0,
            0, 0, 0, /* 1224: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1227: pointer.struct.stack_st_X509_EXTENSION */
            	1232, 0,
            0, 32, 2, /* 1232: struct.stack_st_fake_X509_EXTENSION */
            	1239, 8,
            	456, 24,
            8884099, 8, 2, /* 1239: pointer_to_array_of_pointers_to_stack */
            	1246, 0,
            	453, 20,
            0, 8, 1, /* 1246: pointer.X509_EXTENSION */
            	1251, 0,
            0, 0, 1, /* 1251: X509_EXTENSION */
            	1256, 0,
            0, 24, 2, /* 1256: struct.X509_extension_st */
            	1263, 0,
            	1277, 16,
            1, 8, 1, /* 1263: pointer.struct.asn1_object_st */
            	1268, 0,
            0, 40, 3, /* 1268: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	243, 24,
            1, 8, 1, /* 1277: pointer.struct.asn1_string_st */
            	1282, 0,
            0, 24, 1, /* 1282: struct.asn1_string_st */
            	209, 8,
            0, 24, 1, /* 1287: struct.ASN1_ENCODING_st */
            	209, 0,
            1, 8, 1, /* 1292: pointer.struct.AUTHORITY_KEYID_st */
            	1297, 0,
            0, 24, 3, /* 1297: struct.AUTHORITY_KEYID_st */
            	316, 0,
            	1306, 8,
            	199, 16,
            1, 8, 1, /* 1306: pointer.struct.stack_st_GENERAL_NAME */
            	1311, 0,
            0, 32, 2, /* 1311: struct.stack_st_fake_GENERAL_NAME */
            	1318, 8,
            	456, 24,
            8884099, 8, 2, /* 1318: pointer_to_array_of_pointers_to_stack */
            	1325, 0,
            	453, 20,
            0, 8, 1, /* 1325: pointer.GENERAL_NAME */
            	1330, 0,
            0, 0, 1, /* 1330: GENERAL_NAME */
            	1335, 0,
            0, 16, 1, /* 1335: struct.GENERAL_NAME_st */
            	1340, 8,
            0, 8, 15, /* 1340: union.unknown */
            	61, 0,
            	1373, 0,
            	1492, 0,
            	1492, 0,
            	1399, 0,
            	1540, 0,
            	1588, 0,
            	1492, 0,
            	1477, 0,
            	1385, 0,
            	1477, 0,
            	1540, 0,
            	1492, 0,
            	1385, 0,
            	1399, 0,
            1, 8, 1, /* 1373: pointer.struct.otherName_st */
            	1378, 0,
            0, 16, 2, /* 1378: struct.otherName_st */
            	1385, 0,
            	1399, 8,
            1, 8, 1, /* 1385: pointer.struct.asn1_object_st */
            	1390, 0,
            0, 40, 3, /* 1390: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	243, 24,
            1, 8, 1, /* 1399: pointer.struct.asn1_type_st */
            	1404, 0,
            0, 16, 1, /* 1404: struct.asn1_type_st */
            	1409, 8,
            0, 8, 20, /* 1409: union.unknown */
            	61, 0,
            	1452, 0,
            	1385, 0,
            	1462, 0,
            	1467, 0,
            	1472, 0,
            	1477, 0,
            	1482, 0,
            	1487, 0,
            	1492, 0,
            	1497, 0,
            	1502, 0,
            	1507, 0,
            	1512, 0,
            	1517, 0,
            	1522, 0,
            	1527, 0,
            	1452, 0,
            	1452, 0,
            	1532, 0,
            1, 8, 1, /* 1452: pointer.struct.asn1_string_st */
            	1457, 0,
            0, 24, 1, /* 1457: struct.asn1_string_st */
            	209, 8,
            1, 8, 1, /* 1462: pointer.struct.asn1_string_st */
            	1457, 0,
            1, 8, 1, /* 1467: pointer.struct.asn1_string_st */
            	1457, 0,
            1, 8, 1, /* 1472: pointer.struct.asn1_string_st */
            	1457, 0,
            1, 8, 1, /* 1477: pointer.struct.asn1_string_st */
            	1457, 0,
            1, 8, 1, /* 1482: pointer.struct.asn1_string_st */
            	1457, 0,
            1, 8, 1, /* 1487: pointer.struct.asn1_string_st */
            	1457, 0,
            1, 8, 1, /* 1492: pointer.struct.asn1_string_st */
            	1457, 0,
            1, 8, 1, /* 1497: pointer.struct.asn1_string_st */
            	1457, 0,
            1, 8, 1, /* 1502: pointer.struct.asn1_string_st */
            	1457, 0,
            1, 8, 1, /* 1507: pointer.struct.asn1_string_st */
            	1457, 0,
            1, 8, 1, /* 1512: pointer.struct.asn1_string_st */
            	1457, 0,
            1, 8, 1, /* 1517: pointer.struct.asn1_string_st */
            	1457, 0,
            1, 8, 1, /* 1522: pointer.struct.asn1_string_st */
            	1457, 0,
            1, 8, 1, /* 1527: pointer.struct.asn1_string_st */
            	1457, 0,
            1, 8, 1, /* 1532: pointer.struct.ASN1_VALUE_st */
            	1537, 0,
            0, 0, 0, /* 1537: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1540: pointer.struct.X509_name_st */
            	1545, 0,
            0, 40, 3, /* 1545: struct.X509_name_st */
            	1554, 0,
            	1578, 16,
            	209, 24,
            1, 8, 1, /* 1554: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1559, 0,
            0, 32, 2, /* 1559: struct.stack_st_fake_X509_NAME_ENTRY */
            	1566, 8,
            	456, 24,
            8884099, 8, 2, /* 1566: pointer_to_array_of_pointers_to_stack */
            	1573, 0,
            	453, 20,
            0, 8, 1, /* 1573: pointer.X509_NAME_ENTRY */
            	417, 0,
            1, 8, 1, /* 1578: pointer.struct.buf_mem_st */
            	1583, 0,
            0, 24, 1, /* 1583: struct.buf_mem_st */
            	61, 8,
            1, 8, 1, /* 1588: pointer.struct.EDIPartyName_st */
            	1593, 0,
            0, 16, 2, /* 1593: struct.EDIPartyName_st */
            	1452, 0,
            	1452, 8,
            1, 8, 1, /* 1600: pointer.struct.X509_POLICY_CACHE_st */
            	1605, 0,
            0, 0, 0, /* 1605: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 1608: pointer.struct.stack_st_DIST_POINT */
            	1613, 0,
            0, 32, 2, /* 1613: struct.stack_st_fake_DIST_POINT */
            	1620, 8,
            	456, 24,
            8884099, 8, 2, /* 1620: pointer_to_array_of_pointers_to_stack */
            	1627, 0,
            	453, 20,
            0, 8, 1, /* 1627: pointer.DIST_POINT */
            	1632, 0,
            0, 0, 1, /* 1632: DIST_POINT */
            	1637, 0,
            0, 32, 3, /* 1637: struct.DIST_POINT_st */
            	1646, 0,
            	1737, 8,
            	1665, 16,
            1, 8, 1, /* 1646: pointer.struct.DIST_POINT_NAME_st */
            	1651, 0,
            0, 24, 2, /* 1651: struct.DIST_POINT_NAME_st */
            	1658, 8,
            	1713, 16,
            0, 8, 2, /* 1658: union.unknown */
            	1665, 0,
            	1689, 0,
            1, 8, 1, /* 1665: pointer.struct.stack_st_GENERAL_NAME */
            	1670, 0,
            0, 32, 2, /* 1670: struct.stack_st_fake_GENERAL_NAME */
            	1677, 8,
            	456, 24,
            8884099, 8, 2, /* 1677: pointer_to_array_of_pointers_to_stack */
            	1684, 0,
            	453, 20,
            0, 8, 1, /* 1684: pointer.GENERAL_NAME */
            	1330, 0,
            1, 8, 1, /* 1689: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1694, 0,
            0, 32, 2, /* 1694: struct.stack_st_fake_X509_NAME_ENTRY */
            	1701, 8,
            	456, 24,
            8884099, 8, 2, /* 1701: pointer_to_array_of_pointers_to_stack */
            	1708, 0,
            	453, 20,
            0, 8, 1, /* 1708: pointer.X509_NAME_ENTRY */
            	417, 0,
            1, 8, 1, /* 1713: pointer.struct.X509_name_st */
            	1718, 0,
            0, 40, 3, /* 1718: struct.X509_name_st */
            	1689, 0,
            	1727, 16,
            	209, 24,
            1, 8, 1, /* 1727: pointer.struct.buf_mem_st */
            	1732, 0,
            0, 24, 1, /* 1732: struct.buf_mem_st */
            	61, 8,
            1, 8, 1, /* 1737: pointer.struct.asn1_string_st */
            	1742, 0,
            0, 24, 1, /* 1742: struct.asn1_string_st */
            	209, 8,
            1, 8, 1, /* 1747: pointer.struct.stack_st_GENERAL_NAME */
            	1752, 0,
            0, 32, 2, /* 1752: struct.stack_st_fake_GENERAL_NAME */
            	1759, 8,
            	456, 24,
            8884099, 8, 2, /* 1759: pointer_to_array_of_pointers_to_stack */
            	1766, 0,
            	453, 20,
            0, 8, 1, /* 1766: pointer.GENERAL_NAME */
            	1330, 0,
            1, 8, 1, /* 1771: pointer.struct.NAME_CONSTRAINTS_st */
            	1776, 0,
            0, 16, 2, /* 1776: struct.NAME_CONSTRAINTS_st */
            	1783, 0,
            	1783, 8,
            1, 8, 1, /* 1783: pointer.struct.stack_st_GENERAL_SUBTREE */
            	1788, 0,
            0, 32, 2, /* 1788: struct.stack_st_fake_GENERAL_SUBTREE */
            	1795, 8,
            	456, 24,
            8884099, 8, 2, /* 1795: pointer_to_array_of_pointers_to_stack */
            	1802, 0,
            	453, 20,
            0, 8, 1, /* 1802: pointer.GENERAL_SUBTREE */
            	1807, 0,
            0, 0, 1, /* 1807: GENERAL_SUBTREE */
            	1812, 0,
            0, 24, 3, /* 1812: struct.GENERAL_SUBTREE_st */
            	1821, 0,
            	1953, 8,
            	1953, 16,
            1, 8, 1, /* 1821: pointer.struct.GENERAL_NAME_st */
            	1826, 0,
            0, 16, 1, /* 1826: struct.GENERAL_NAME_st */
            	1831, 8,
            0, 8, 15, /* 1831: union.unknown */
            	61, 0,
            	1864, 0,
            	1983, 0,
            	1983, 0,
            	1890, 0,
            	2023, 0,
            	2071, 0,
            	1983, 0,
            	1968, 0,
            	1876, 0,
            	1968, 0,
            	2023, 0,
            	1983, 0,
            	1876, 0,
            	1890, 0,
            1, 8, 1, /* 1864: pointer.struct.otherName_st */
            	1869, 0,
            0, 16, 2, /* 1869: struct.otherName_st */
            	1876, 0,
            	1890, 8,
            1, 8, 1, /* 1876: pointer.struct.asn1_object_st */
            	1881, 0,
            0, 40, 3, /* 1881: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	243, 24,
            1, 8, 1, /* 1890: pointer.struct.asn1_type_st */
            	1895, 0,
            0, 16, 1, /* 1895: struct.asn1_type_st */
            	1900, 8,
            0, 8, 20, /* 1900: union.unknown */
            	61, 0,
            	1943, 0,
            	1876, 0,
            	1953, 0,
            	1958, 0,
            	1963, 0,
            	1968, 0,
            	1973, 0,
            	1978, 0,
            	1983, 0,
            	1988, 0,
            	1993, 0,
            	1998, 0,
            	2003, 0,
            	2008, 0,
            	2013, 0,
            	2018, 0,
            	1943, 0,
            	1943, 0,
            	1532, 0,
            1, 8, 1, /* 1943: pointer.struct.asn1_string_st */
            	1948, 0,
            0, 24, 1, /* 1948: struct.asn1_string_st */
            	209, 8,
            1, 8, 1, /* 1953: pointer.struct.asn1_string_st */
            	1948, 0,
            1, 8, 1, /* 1958: pointer.struct.asn1_string_st */
            	1948, 0,
            1, 8, 1, /* 1963: pointer.struct.asn1_string_st */
            	1948, 0,
            1, 8, 1, /* 1968: pointer.struct.asn1_string_st */
            	1948, 0,
            1, 8, 1, /* 1973: pointer.struct.asn1_string_st */
            	1948, 0,
            1, 8, 1, /* 1978: pointer.struct.asn1_string_st */
            	1948, 0,
            1, 8, 1, /* 1983: pointer.struct.asn1_string_st */
            	1948, 0,
            1, 8, 1, /* 1988: pointer.struct.asn1_string_st */
            	1948, 0,
            1, 8, 1, /* 1993: pointer.struct.asn1_string_st */
            	1948, 0,
            1, 8, 1, /* 1998: pointer.struct.asn1_string_st */
            	1948, 0,
            1, 8, 1, /* 2003: pointer.struct.asn1_string_st */
            	1948, 0,
            1, 8, 1, /* 2008: pointer.struct.asn1_string_st */
            	1948, 0,
            1, 8, 1, /* 2013: pointer.struct.asn1_string_st */
            	1948, 0,
            1, 8, 1, /* 2018: pointer.struct.asn1_string_st */
            	1948, 0,
            1, 8, 1, /* 2023: pointer.struct.X509_name_st */
            	2028, 0,
            0, 40, 3, /* 2028: struct.X509_name_st */
            	2037, 0,
            	2061, 16,
            	209, 24,
            1, 8, 1, /* 2037: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2042, 0,
            0, 32, 2, /* 2042: struct.stack_st_fake_X509_NAME_ENTRY */
            	2049, 8,
            	456, 24,
            8884099, 8, 2, /* 2049: pointer_to_array_of_pointers_to_stack */
            	2056, 0,
            	453, 20,
            0, 8, 1, /* 2056: pointer.X509_NAME_ENTRY */
            	417, 0,
            1, 8, 1, /* 2061: pointer.struct.buf_mem_st */
            	2066, 0,
            0, 24, 1, /* 2066: struct.buf_mem_st */
            	61, 8,
            1, 8, 1, /* 2071: pointer.struct.EDIPartyName_st */
            	2076, 0,
            0, 16, 2, /* 2076: struct.EDIPartyName_st */
            	1943, 0,
            	1943, 8,
            1, 8, 1, /* 2083: pointer.struct.x509_cert_aux_st */
            	2088, 0,
            0, 40, 5, /* 2088: struct.x509_cert_aux_st */
            	2101, 0,
            	2101, 8,
            	366, 16,
            	316, 24,
            	2139, 32,
            1, 8, 1, /* 2101: pointer.struct.stack_st_ASN1_OBJECT */
            	2106, 0,
            0, 32, 2, /* 2106: struct.stack_st_fake_ASN1_OBJECT */
            	2113, 8,
            	456, 24,
            8884099, 8, 2, /* 2113: pointer_to_array_of_pointers_to_stack */
            	2120, 0,
            	453, 20,
            0, 8, 1, /* 2120: pointer.ASN1_OBJECT */
            	2125, 0,
            0, 0, 1, /* 2125: ASN1_OBJECT */
            	2130, 0,
            0, 40, 3, /* 2130: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	243, 24,
            1, 8, 1, /* 2139: pointer.struct.stack_st_X509_ALGOR */
            	2144, 0,
            0, 32, 2, /* 2144: struct.stack_st_fake_X509_ALGOR */
            	2151, 8,
            	456, 24,
            8884099, 8, 2, /* 2151: pointer_to_array_of_pointers_to_stack */
            	2158, 0,
            	453, 20,
            0, 8, 1, /* 2158: pointer.X509_ALGOR */
            	2163, 0,
            0, 0, 1, /* 2163: X509_ALGOR */
            	2168, 0,
            0, 16, 2, /* 2168: struct.X509_algor_st */
            	2175, 0,
            	2189, 8,
            1, 8, 1, /* 2175: pointer.struct.asn1_object_st */
            	2180, 0,
            0, 40, 3, /* 2180: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	243, 24,
            1, 8, 1, /* 2189: pointer.struct.asn1_type_st */
            	2194, 0,
            0, 16, 1, /* 2194: struct.asn1_type_st */
            	2199, 8,
            0, 8, 20, /* 2199: union.unknown */
            	61, 0,
            	2242, 0,
            	2175, 0,
            	2252, 0,
            	2257, 0,
            	2262, 0,
            	2267, 0,
            	2272, 0,
            	2277, 0,
            	2282, 0,
            	2287, 0,
            	2292, 0,
            	2297, 0,
            	2302, 0,
            	2307, 0,
            	2312, 0,
            	2317, 0,
            	2242, 0,
            	2242, 0,
            	1219, 0,
            1, 8, 1, /* 2242: pointer.struct.asn1_string_st */
            	2247, 0,
            0, 24, 1, /* 2247: struct.asn1_string_st */
            	209, 8,
            1, 8, 1, /* 2252: pointer.struct.asn1_string_st */
            	2247, 0,
            1, 8, 1, /* 2257: pointer.struct.asn1_string_st */
            	2247, 0,
            1, 8, 1, /* 2262: pointer.struct.asn1_string_st */
            	2247, 0,
            1, 8, 1, /* 2267: pointer.struct.asn1_string_st */
            	2247, 0,
            1, 8, 1, /* 2272: pointer.struct.asn1_string_st */
            	2247, 0,
            1, 8, 1, /* 2277: pointer.struct.asn1_string_st */
            	2247, 0,
            1, 8, 1, /* 2282: pointer.struct.asn1_string_st */
            	2247, 0,
            1, 8, 1, /* 2287: pointer.struct.asn1_string_st */
            	2247, 0,
            1, 8, 1, /* 2292: pointer.struct.asn1_string_st */
            	2247, 0,
            1, 8, 1, /* 2297: pointer.struct.asn1_string_st */
            	2247, 0,
            1, 8, 1, /* 2302: pointer.struct.asn1_string_st */
            	2247, 0,
            1, 8, 1, /* 2307: pointer.struct.asn1_string_st */
            	2247, 0,
            1, 8, 1, /* 2312: pointer.struct.asn1_string_st */
            	2247, 0,
            1, 8, 1, /* 2317: pointer.struct.asn1_string_st */
            	2247, 0,
            1, 8, 1, /* 2322: pointer.struct.env_md_st */
            	2327, 0,
            0, 120, 8, /* 2327: struct.env_md_st */
            	2346, 24,
            	2349, 32,
            	2352, 40,
            	2355, 48,
            	2346, 56,
            	2358, 64,
            	2361, 72,
            	2364, 112,
            8884097, 8, 0, /* 2346: pointer.func */
            8884097, 8, 0, /* 2349: pointer.func */
            8884097, 8, 0, /* 2352: pointer.func */
            8884097, 8, 0, /* 2355: pointer.func */
            8884097, 8, 0, /* 2358: pointer.func */
            8884097, 8, 0, /* 2361: pointer.func */
            8884097, 8, 0, /* 2364: pointer.func */
            1, 8, 1, /* 2367: pointer.struct.rsa_st */
            	550, 0,
            8884097, 8, 0, /* 2372: pointer.func */
            1, 8, 1, /* 2375: pointer.struct.dh_st */
            	777, 0,
            1, 8, 1, /* 2380: pointer.struct.ec_key_st */
            	845, 0,
            1, 8, 1, /* 2385: pointer.struct.cert_st */
            	106, 0,
            1, 8, 1, /* 2390: pointer.struct.buf_mem_st */
            	2395, 0,
            0, 24, 1, /* 2395: struct.buf_mem_st */
            	61, 8,
            1, 8, 1, /* 2400: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2405, 0,
            0, 32, 2, /* 2405: struct.stack_st_fake_X509_NAME_ENTRY */
            	2412, 8,
            	456, 24,
            8884099, 8, 2, /* 2412: pointer_to_array_of_pointers_to_stack */
            	2419, 0,
            	453, 20,
            0, 8, 1, /* 2419: pointer.X509_NAME_ENTRY */
            	417, 0,
            0, 40, 3, /* 2424: struct.X509_name_st */
            	2400, 0,
            	2390, 16,
            	209, 24,
            8884097, 8, 0, /* 2433: pointer.func */
            8884097, 8, 0, /* 2436: pointer.func */
            8884097, 8, 0, /* 2439: pointer.func */
            8884097, 8, 0, /* 2442: pointer.func */
            0, 64, 7, /* 2445: struct.comp_method_st */
            	10, 8,
            	2442, 16,
            	2439, 24,
            	2436, 32,
            	2436, 40,
            	2462, 48,
            	2462, 56,
            8884097, 8, 0, /* 2462: pointer.func */
            1, 8, 1, /* 2465: pointer.struct.comp_method_st */
            	2445, 0,
            1, 8, 1, /* 2470: pointer.struct.stack_st_SSL_COMP */
            	2475, 0,
            0, 32, 2, /* 2475: struct.stack_st_fake_SSL_COMP */
            	2482, 8,
            	456, 24,
            8884099, 8, 2, /* 2482: pointer_to_array_of_pointers_to_stack */
            	2489, 0,
            	453, 20,
            0, 8, 1, /* 2489: pointer.SSL_COMP */
            	2494, 0,
            0, 0, 1, /* 2494: SSL_COMP */
            	2499, 0,
            0, 24, 2, /* 2499: struct.ssl_comp_st */
            	10, 8,
            	2465, 16,
            8884097, 8, 0, /* 2506: pointer.func */
            8884097, 8, 0, /* 2509: pointer.func */
            8884097, 8, 0, /* 2512: pointer.func */
            0, 88, 1, /* 2515: struct.ssl_cipher_st */
            	10, 8,
            0, 0, 1, /* 2520: X509_NAME */
            	2424, 0,
            1, 8, 1, /* 2525: pointer.struct.ssl_cipher_st */
            	2515, 0,
            8884097, 8, 0, /* 2530: pointer.func */
            0, 16, 1, /* 2533: struct.crypto_ex_data_st */
            	2538, 0,
            1, 8, 1, /* 2538: pointer.struct.stack_st_void */
            	2543, 0,
            0, 32, 1, /* 2543: struct.stack_st_void */
            	2548, 0,
            0, 32, 2, /* 2548: struct.stack_st */
            	664, 8,
            	456, 24,
            0, 136, 11, /* 2555: struct.dsa_st */
            	2580, 24,
            	2580, 32,
            	2580, 40,
            	2580, 48,
            	2580, 56,
            	2580, 64,
            	2580, 72,
            	2590, 88,
            	2533, 104,
            	2604, 120,
            	2655, 128,
            1, 8, 1, /* 2580: pointer.struct.bignum_st */
            	2585, 0,
            0, 24, 1, /* 2585: struct.bignum_st */
            	76, 0,
            1, 8, 1, /* 2590: pointer.struct.bn_mont_ctx_st */
            	2595, 0,
            0, 96, 3, /* 2595: struct.bn_mont_ctx_st */
            	2585, 8,
            	2585, 32,
            	2585, 56,
            1, 8, 1, /* 2604: pointer.struct.dsa_method */
            	2609, 0,
            0, 96, 11, /* 2609: struct.dsa_method */
            	10, 0,
            	2634, 8,
            	2637, 16,
            	2640, 24,
            	2643, 32,
            	2646, 40,
            	2649, 48,
            	2649, 56,
            	61, 72,
            	2652, 80,
            	2649, 88,
            8884097, 8, 0, /* 2634: pointer.func */
            8884097, 8, 0, /* 2637: pointer.func */
            8884097, 8, 0, /* 2640: pointer.func */
            8884097, 8, 0, /* 2643: pointer.func */
            8884097, 8, 0, /* 2646: pointer.func */
            8884097, 8, 0, /* 2649: pointer.func */
            8884097, 8, 0, /* 2652: pointer.func */
            1, 8, 1, /* 2655: pointer.struct.engine_st */
            	2660, 0,
            0, 0, 0, /* 2660: struct.engine_st */
            8884097, 8, 0, /* 2663: pointer.func */
            1, 8, 1, /* 2666: pointer.struct.X509_algor_st */
            	2671, 0,
            0, 16, 2, /* 2671: struct.X509_algor_st */
            	2678, 0,
            	2692, 8,
            1, 8, 1, /* 2678: pointer.struct.asn1_object_st */
            	2683, 0,
            0, 40, 3, /* 2683: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	243, 24,
            1, 8, 1, /* 2692: pointer.struct.asn1_type_st */
            	2697, 0,
            0, 16, 1, /* 2697: struct.asn1_type_st */
            	2702, 8,
            0, 8, 20, /* 2702: union.unknown */
            	61, 0,
            	2745, 0,
            	2678, 0,
            	2755, 0,
            	2760, 0,
            	2765, 0,
            	2770, 0,
            	2775, 0,
            	2780, 0,
            	2785, 0,
            	2790, 0,
            	2795, 0,
            	2800, 0,
            	2805, 0,
            	2810, 0,
            	2815, 0,
            	2820, 0,
            	2745, 0,
            	2745, 0,
            	1219, 0,
            1, 8, 1, /* 2745: pointer.struct.asn1_string_st */
            	2750, 0,
            0, 24, 1, /* 2750: struct.asn1_string_st */
            	209, 8,
            1, 8, 1, /* 2755: pointer.struct.asn1_string_st */
            	2750, 0,
            1, 8, 1, /* 2760: pointer.struct.asn1_string_st */
            	2750, 0,
            1, 8, 1, /* 2765: pointer.struct.asn1_string_st */
            	2750, 0,
            1, 8, 1, /* 2770: pointer.struct.asn1_string_st */
            	2750, 0,
            1, 8, 1, /* 2775: pointer.struct.asn1_string_st */
            	2750, 0,
            1, 8, 1, /* 2780: pointer.struct.asn1_string_st */
            	2750, 0,
            1, 8, 1, /* 2785: pointer.struct.asn1_string_st */
            	2750, 0,
            1, 8, 1, /* 2790: pointer.struct.asn1_string_st */
            	2750, 0,
            1, 8, 1, /* 2795: pointer.struct.asn1_string_st */
            	2750, 0,
            1, 8, 1, /* 2800: pointer.struct.asn1_string_st */
            	2750, 0,
            1, 8, 1, /* 2805: pointer.struct.asn1_string_st */
            	2750, 0,
            1, 8, 1, /* 2810: pointer.struct.asn1_string_st */
            	2750, 0,
            1, 8, 1, /* 2815: pointer.struct.asn1_string_st */
            	2750, 0,
            1, 8, 1, /* 2820: pointer.struct.asn1_string_st */
            	2750, 0,
            1, 8, 1, /* 2825: pointer.struct.stack_st_DIST_POINT */
            	2830, 0,
            0, 32, 2, /* 2830: struct.stack_st_fake_DIST_POINT */
            	2837, 8,
            	456, 24,
            8884099, 8, 2, /* 2837: pointer_to_array_of_pointers_to_stack */
            	2844, 0,
            	453, 20,
            0, 8, 1, /* 2844: pointer.DIST_POINT */
            	1632, 0,
            1, 8, 1, /* 2849: pointer.struct.X509_POLICY_CACHE_st */
            	2854, 0,
            0, 0, 0, /* 2854: struct.X509_POLICY_CACHE_st */
            0, 0, 0, /* 2857: struct.AUTHORITY_KEYID_st */
            0, 0, 0, /* 2860: struct.ec_key_st */
            1, 8, 1, /* 2863: pointer.struct.AUTHORITY_KEYID_st */
            	2857, 0,
            8884097, 8, 0, /* 2868: pointer.func */
            8884097, 8, 0, /* 2871: pointer.func */
            0, 112, 11, /* 2874: struct.ssl3_enc_method */
            	2899, 0,
            	2902, 8,
            	2905, 16,
            	2908, 24,
            	2899, 32,
            	2911, 40,
            	2914, 56,
            	10, 64,
            	10, 80,
            	2917, 96,
            	2920, 104,
            8884097, 8, 0, /* 2899: pointer.func */
            8884097, 8, 0, /* 2902: pointer.func */
            8884097, 8, 0, /* 2905: pointer.func */
            8884097, 8, 0, /* 2908: pointer.func */
            8884097, 8, 0, /* 2911: pointer.func */
            8884097, 8, 0, /* 2914: pointer.func */
            8884097, 8, 0, /* 2917: pointer.func */
            8884097, 8, 0, /* 2920: pointer.func */
            8884097, 8, 0, /* 2923: pointer.func */
            0, 104, 11, /* 2926: struct.x509_cinf_st */
            	2951, 0,
            	2951, 8,
            	2961, 16,
            	3118, 24,
            	3166, 32,
            	3118, 40,
            	3183, 48,
            	3050, 56,
            	3050, 64,
            	3571, 72,
            	3595, 80,
            1, 8, 1, /* 2951: pointer.struct.asn1_string_st */
            	2956, 0,
            0, 24, 1, /* 2956: struct.asn1_string_st */
            	209, 8,
            1, 8, 1, /* 2961: pointer.struct.X509_algor_st */
            	2966, 0,
            0, 16, 2, /* 2966: struct.X509_algor_st */
            	2973, 0,
            	2987, 8,
            1, 8, 1, /* 2973: pointer.struct.asn1_object_st */
            	2978, 0,
            0, 40, 3, /* 2978: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	243, 24,
            1, 8, 1, /* 2987: pointer.struct.asn1_type_st */
            	2992, 0,
            0, 16, 1, /* 2992: struct.asn1_type_st */
            	2997, 8,
            0, 8, 20, /* 2997: union.unknown */
            	61, 0,
            	3040, 0,
            	2973, 0,
            	2951, 0,
            	3045, 0,
            	3050, 0,
            	3055, 0,
            	3060, 0,
            	3065, 0,
            	3070, 0,
            	3075, 0,
            	3080, 0,
            	3085, 0,
            	3090, 0,
            	3095, 0,
            	3100, 0,
            	3105, 0,
            	3040, 0,
            	3040, 0,
            	3110, 0,
            1, 8, 1, /* 3040: pointer.struct.asn1_string_st */
            	2956, 0,
            1, 8, 1, /* 3045: pointer.struct.asn1_string_st */
            	2956, 0,
            1, 8, 1, /* 3050: pointer.struct.asn1_string_st */
            	2956, 0,
            1, 8, 1, /* 3055: pointer.struct.asn1_string_st */
            	2956, 0,
            1, 8, 1, /* 3060: pointer.struct.asn1_string_st */
            	2956, 0,
            1, 8, 1, /* 3065: pointer.struct.asn1_string_st */
            	2956, 0,
            1, 8, 1, /* 3070: pointer.struct.asn1_string_st */
            	2956, 0,
            1, 8, 1, /* 3075: pointer.struct.asn1_string_st */
            	2956, 0,
            1, 8, 1, /* 3080: pointer.struct.asn1_string_st */
            	2956, 0,
            1, 8, 1, /* 3085: pointer.struct.asn1_string_st */
            	2956, 0,
            1, 8, 1, /* 3090: pointer.struct.asn1_string_st */
            	2956, 0,
            1, 8, 1, /* 3095: pointer.struct.asn1_string_st */
            	2956, 0,
            1, 8, 1, /* 3100: pointer.struct.asn1_string_st */
            	2956, 0,
            1, 8, 1, /* 3105: pointer.struct.asn1_string_st */
            	2956, 0,
            1, 8, 1, /* 3110: pointer.struct.ASN1_VALUE_st */
            	3115, 0,
            0, 0, 0, /* 3115: struct.ASN1_VALUE_st */
            1, 8, 1, /* 3118: pointer.struct.X509_name_st */
            	3123, 0,
            0, 40, 3, /* 3123: struct.X509_name_st */
            	3132, 0,
            	3156, 16,
            	209, 24,
            1, 8, 1, /* 3132: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3137, 0,
            0, 32, 2, /* 3137: struct.stack_st_fake_X509_NAME_ENTRY */
            	3144, 8,
            	456, 24,
            8884099, 8, 2, /* 3144: pointer_to_array_of_pointers_to_stack */
            	3151, 0,
            	453, 20,
            0, 8, 1, /* 3151: pointer.X509_NAME_ENTRY */
            	417, 0,
            1, 8, 1, /* 3156: pointer.struct.buf_mem_st */
            	3161, 0,
            0, 24, 1, /* 3161: struct.buf_mem_st */
            	61, 8,
            1, 8, 1, /* 3166: pointer.struct.X509_val_st */
            	3171, 0,
            0, 16, 2, /* 3171: struct.X509_val_st */
            	3178, 0,
            	3178, 8,
            1, 8, 1, /* 3178: pointer.struct.asn1_string_st */
            	2956, 0,
            1, 8, 1, /* 3183: pointer.struct.X509_pubkey_st */
            	3188, 0,
            0, 24, 3, /* 3188: struct.X509_pubkey_st */
            	2961, 0,
            	3050, 8,
            	3197, 16,
            1, 8, 1, /* 3197: pointer.struct.evp_pkey_st */
            	3202, 0,
            0, 56, 4, /* 3202: struct.evp_pkey_st */
            	3213, 16,
            	3221, 24,
            	3229, 32,
            	3547, 48,
            1, 8, 1, /* 3213: pointer.struct.evp_pkey_asn1_method_st */
            	3218, 0,
            0, 0, 0, /* 3218: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 3221: pointer.struct.engine_st */
            	3226, 0,
            0, 0, 0, /* 3226: struct.engine_st */
            0, 8, 5, /* 3229: union.unknown */
            	61, 0,
            	3242, 0,
            	3393, 0,
            	3471, 0,
            	3539, 0,
            1, 8, 1, /* 3242: pointer.struct.rsa_st */
            	3247, 0,
            0, 168, 17, /* 3247: struct.rsa_st */
            	3284, 16,
            	3221, 24,
            	3339, 32,
            	3339, 40,
            	3339, 48,
            	3339, 56,
            	3339, 64,
            	3339, 72,
            	3339, 80,
            	3339, 88,
            	3349, 96,
            	3371, 120,
            	3371, 128,
            	3371, 136,
            	61, 144,
            	3385, 152,
            	3385, 160,
            1, 8, 1, /* 3284: pointer.struct.rsa_meth_st */
            	3289, 0,
            0, 112, 13, /* 3289: struct.rsa_meth_st */
            	10, 0,
            	3318, 8,
            	3318, 16,
            	3318, 24,
            	3318, 32,
            	3321, 40,
            	3324, 48,
            	3327, 56,
            	3327, 64,
            	61, 80,
            	3330, 88,
            	3333, 96,
            	3336, 104,
            8884097, 8, 0, /* 3318: pointer.func */
            8884097, 8, 0, /* 3321: pointer.func */
            8884097, 8, 0, /* 3324: pointer.func */
            8884097, 8, 0, /* 3327: pointer.func */
            8884097, 8, 0, /* 3330: pointer.func */
            8884097, 8, 0, /* 3333: pointer.func */
            8884097, 8, 0, /* 3336: pointer.func */
            1, 8, 1, /* 3339: pointer.struct.bignum_st */
            	3344, 0,
            0, 24, 1, /* 3344: struct.bignum_st */
            	76, 0,
            0, 16, 1, /* 3349: struct.crypto_ex_data_st */
            	3354, 0,
            1, 8, 1, /* 3354: pointer.struct.stack_st_void */
            	3359, 0,
            0, 32, 1, /* 3359: struct.stack_st_void */
            	3364, 0,
            0, 32, 2, /* 3364: struct.stack_st */
            	664, 8,
            	456, 24,
            1, 8, 1, /* 3371: pointer.struct.bn_mont_ctx_st */
            	3376, 0,
            0, 96, 3, /* 3376: struct.bn_mont_ctx_st */
            	3344, 8,
            	3344, 32,
            	3344, 56,
            1, 8, 1, /* 3385: pointer.struct.bn_blinding_st */
            	3390, 0,
            0, 0, 0, /* 3390: struct.bn_blinding_st */
            1, 8, 1, /* 3393: pointer.struct.dsa_st */
            	3398, 0,
            0, 136, 11, /* 3398: struct.dsa_st */
            	3339, 24,
            	3339, 32,
            	3339, 40,
            	3339, 48,
            	3339, 56,
            	3339, 64,
            	3339, 72,
            	3371, 88,
            	3349, 104,
            	3423, 120,
            	3221, 128,
            1, 8, 1, /* 3423: pointer.struct.dsa_method */
            	3428, 0,
            0, 96, 11, /* 3428: struct.dsa_method */
            	10, 0,
            	3453, 8,
            	3456, 16,
            	3459, 24,
            	2923, 32,
            	3462, 40,
            	3465, 48,
            	3465, 56,
            	61, 72,
            	3468, 80,
            	3465, 88,
            8884097, 8, 0, /* 3453: pointer.func */
            8884097, 8, 0, /* 3456: pointer.func */
            8884097, 8, 0, /* 3459: pointer.func */
            8884097, 8, 0, /* 3462: pointer.func */
            8884097, 8, 0, /* 3465: pointer.func */
            8884097, 8, 0, /* 3468: pointer.func */
            1, 8, 1, /* 3471: pointer.struct.dh_st */
            	3476, 0,
            0, 144, 12, /* 3476: struct.dh_st */
            	3339, 8,
            	3339, 16,
            	3339, 32,
            	3339, 40,
            	3371, 56,
            	3339, 64,
            	3339, 72,
            	209, 80,
            	3339, 96,
            	3349, 112,
            	3503, 128,
            	3221, 136,
            1, 8, 1, /* 3503: pointer.struct.dh_method */
            	3508, 0,
            0, 72, 8, /* 3508: struct.dh_method */
            	10, 0,
            	3527, 8,
            	3530, 16,
            	3533, 24,
            	3527, 32,
            	3527, 40,
            	61, 56,
            	3536, 64,
            8884097, 8, 0, /* 3527: pointer.func */
            8884097, 8, 0, /* 3530: pointer.func */
            8884097, 8, 0, /* 3533: pointer.func */
            8884097, 8, 0, /* 3536: pointer.func */
            1, 8, 1, /* 3539: pointer.struct.ec_key_st */
            	3544, 0,
            0, 0, 0, /* 3544: struct.ec_key_st */
            1, 8, 1, /* 3547: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3552, 0,
            0, 32, 2, /* 3552: struct.stack_st_fake_X509_ATTRIBUTE */
            	3559, 8,
            	456, 24,
            8884099, 8, 2, /* 3559: pointer_to_array_of_pointers_to_stack */
            	3566, 0,
            	453, 20,
            0, 8, 1, /* 3566: pointer.X509_ATTRIBUTE */
            	872, 0,
            1, 8, 1, /* 3571: pointer.struct.stack_st_X509_EXTENSION */
            	3576, 0,
            0, 32, 2, /* 3576: struct.stack_st_fake_X509_EXTENSION */
            	3583, 8,
            	456, 24,
            8884099, 8, 2, /* 3583: pointer_to_array_of_pointers_to_stack */
            	3590, 0,
            	453, 20,
            0, 8, 1, /* 3590: pointer.X509_EXTENSION */
            	1251, 0,
            0, 24, 1, /* 3595: struct.ASN1_ENCODING_st */
            	209, 0,
            0, 0, 0, /* 3600: struct.X509_POLICY_CACHE_st */
            8884097, 8, 0, /* 3603: pointer.func */
            1, 8, 1, /* 3606: pointer.struct.stack_st_X509_REVOKED */
            	3611, 0,
            0, 32, 2, /* 3611: struct.stack_st_fake_X509_REVOKED */
            	3618, 8,
            	456, 24,
            8884099, 8, 2, /* 3618: pointer_to_array_of_pointers_to_stack */
            	3625, 0,
            	453, 20,
            0, 8, 1, /* 3625: pointer.X509_REVOKED */
            	3630, 0,
            0, 0, 1, /* 3630: X509_REVOKED */
            	3635, 0,
            0, 40, 4, /* 3635: struct.x509_revoked_st */
            	3646, 0,
            	3656, 8,
            	3661, 16,
            	3685, 24,
            1, 8, 1, /* 3646: pointer.struct.asn1_string_st */
            	3651, 0,
            0, 24, 1, /* 3651: struct.asn1_string_st */
            	209, 8,
            1, 8, 1, /* 3656: pointer.struct.asn1_string_st */
            	3651, 0,
            1, 8, 1, /* 3661: pointer.struct.stack_st_X509_EXTENSION */
            	3666, 0,
            0, 32, 2, /* 3666: struct.stack_st_fake_X509_EXTENSION */
            	3673, 8,
            	456, 24,
            8884099, 8, 2, /* 3673: pointer_to_array_of_pointers_to_stack */
            	3680, 0,
            	453, 20,
            0, 8, 1, /* 3680: pointer.X509_EXTENSION */
            	1251, 0,
            1, 8, 1, /* 3685: pointer.struct.stack_st_GENERAL_NAME */
            	3690, 0,
            0, 32, 2, /* 3690: struct.stack_st_fake_GENERAL_NAME */
            	3697, 8,
            	456, 24,
            8884099, 8, 2, /* 3697: pointer_to_array_of_pointers_to_stack */
            	3704, 0,
            	453, 20,
            0, 8, 1, /* 3704: pointer.GENERAL_NAME */
            	1330, 0,
            8884097, 8, 0, /* 3709: pointer.func */
            0, 184, 12, /* 3712: struct.x509_st */
            	3739, 0,
            	2666, 8,
            	2765, 16,
            	61, 32,
            	2533, 40,
            	2770, 104,
            	2863, 112,
            	2849, 120,
            	2825, 128,
            	4118, 136,
            	4142, 144,
            	4150, 176,
            1, 8, 1, /* 3739: pointer.struct.x509_cinf_st */
            	3744, 0,
            0, 104, 11, /* 3744: struct.x509_cinf_st */
            	2755, 0,
            	2755, 8,
            	2666, 16,
            	3769, 24,
            	3817, 32,
            	3769, 40,
            	3834, 48,
            	2765, 56,
            	2765, 64,
            	4089, 72,
            	4113, 80,
            1, 8, 1, /* 3769: pointer.struct.X509_name_st */
            	3774, 0,
            0, 40, 3, /* 3774: struct.X509_name_st */
            	3783, 0,
            	3807, 16,
            	209, 24,
            1, 8, 1, /* 3783: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3788, 0,
            0, 32, 2, /* 3788: struct.stack_st_fake_X509_NAME_ENTRY */
            	3795, 8,
            	456, 24,
            8884099, 8, 2, /* 3795: pointer_to_array_of_pointers_to_stack */
            	3802, 0,
            	453, 20,
            0, 8, 1, /* 3802: pointer.X509_NAME_ENTRY */
            	417, 0,
            1, 8, 1, /* 3807: pointer.struct.buf_mem_st */
            	3812, 0,
            0, 24, 1, /* 3812: struct.buf_mem_st */
            	61, 8,
            1, 8, 1, /* 3817: pointer.struct.X509_val_st */
            	3822, 0,
            0, 16, 2, /* 3822: struct.X509_val_st */
            	3829, 0,
            	3829, 8,
            1, 8, 1, /* 3829: pointer.struct.asn1_string_st */
            	2750, 0,
            1, 8, 1, /* 3834: pointer.struct.X509_pubkey_st */
            	3839, 0,
            0, 24, 3, /* 3839: struct.X509_pubkey_st */
            	2666, 0,
            	2765, 8,
            	3848, 16,
            1, 8, 1, /* 3848: pointer.struct.evp_pkey_st */
            	3853, 0,
            0, 56, 4, /* 3853: struct.evp_pkey_st */
            	3864, 16,
            	2655, 24,
            	3872, 32,
            	4065, 48,
            1, 8, 1, /* 3864: pointer.struct.evp_pkey_asn1_method_st */
            	3869, 0,
            0, 0, 0, /* 3869: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 3872: union.unknown */
            	61, 0,
            	3885, 0,
            	3987, 0,
            	3992, 0,
            	4060, 0,
            1, 8, 1, /* 3885: pointer.struct.rsa_st */
            	3890, 0,
            0, 168, 17, /* 3890: struct.rsa_st */
            	3927, 16,
            	2655, 24,
            	2580, 32,
            	2580, 40,
            	2580, 48,
            	2580, 56,
            	2580, 64,
            	2580, 72,
            	2580, 80,
            	2580, 88,
            	2533, 96,
            	2590, 120,
            	2590, 128,
            	2590, 136,
            	61, 144,
            	3979, 152,
            	3979, 160,
            1, 8, 1, /* 3927: pointer.struct.rsa_meth_st */
            	3932, 0,
            0, 112, 13, /* 3932: struct.rsa_meth_st */
            	10, 0,
            	3961, 8,
            	3961, 16,
            	3961, 24,
            	3961, 32,
            	3964, 40,
            	3967, 48,
            	3709, 56,
            	3709, 64,
            	61, 80,
            	3970, 88,
            	3973, 96,
            	3976, 104,
            8884097, 8, 0, /* 3961: pointer.func */
            8884097, 8, 0, /* 3964: pointer.func */
            8884097, 8, 0, /* 3967: pointer.func */
            8884097, 8, 0, /* 3970: pointer.func */
            8884097, 8, 0, /* 3973: pointer.func */
            8884097, 8, 0, /* 3976: pointer.func */
            1, 8, 1, /* 3979: pointer.struct.bn_blinding_st */
            	3984, 0,
            0, 0, 0, /* 3984: struct.bn_blinding_st */
            1, 8, 1, /* 3987: pointer.struct.dsa_st */
            	2555, 0,
            1, 8, 1, /* 3992: pointer.struct.dh_st */
            	3997, 0,
            0, 144, 12, /* 3997: struct.dh_st */
            	2580, 8,
            	2580, 16,
            	2580, 32,
            	2580, 40,
            	2590, 56,
            	2580, 64,
            	2580, 72,
            	209, 80,
            	2580, 96,
            	2533, 112,
            	4024, 128,
            	2655, 136,
            1, 8, 1, /* 4024: pointer.struct.dh_method */
            	4029, 0,
            0, 72, 8, /* 4029: struct.dh_method */
            	10, 0,
            	4048, 8,
            	4051, 16,
            	4054, 24,
            	4048, 32,
            	4048, 40,
            	61, 56,
            	4057, 64,
            8884097, 8, 0, /* 4048: pointer.func */
            8884097, 8, 0, /* 4051: pointer.func */
            8884097, 8, 0, /* 4054: pointer.func */
            8884097, 8, 0, /* 4057: pointer.func */
            1, 8, 1, /* 4060: pointer.struct.ec_key_st */
            	2860, 0,
            1, 8, 1, /* 4065: pointer.struct.stack_st_X509_ATTRIBUTE */
            	4070, 0,
            0, 32, 2, /* 4070: struct.stack_st_fake_X509_ATTRIBUTE */
            	4077, 8,
            	456, 24,
            8884099, 8, 2, /* 4077: pointer_to_array_of_pointers_to_stack */
            	4084, 0,
            	453, 20,
            0, 8, 1, /* 4084: pointer.X509_ATTRIBUTE */
            	872, 0,
            1, 8, 1, /* 4089: pointer.struct.stack_st_X509_EXTENSION */
            	4094, 0,
            0, 32, 2, /* 4094: struct.stack_st_fake_X509_EXTENSION */
            	4101, 8,
            	456, 24,
            8884099, 8, 2, /* 4101: pointer_to_array_of_pointers_to_stack */
            	4108, 0,
            	453, 20,
            0, 8, 1, /* 4108: pointer.X509_EXTENSION */
            	1251, 0,
            0, 24, 1, /* 4113: struct.ASN1_ENCODING_st */
            	209, 0,
            1, 8, 1, /* 4118: pointer.struct.stack_st_GENERAL_NAME */
            	4123, 0,
            0, 32, 2, /* 4123: struct.stack_st_fake_GENERAL_NAME */
            	4130, 8,
            	456, 24,
            8884099, 8, 2, /* 4130: pointer_to_array_of_pointers_to_stack */
            	4137, 0,
            	453, 20,
            0, 8, 1, /* 4137: pointer.GENERAL_NAME */
            	1330, 0,
            1, 8, 1, /* 4142: pointer.struct.NAME_CONSTRAINTS_st */
            	4147, 0,
            0, 0, 0, /* 4147: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 4150: pointer.struct.x509_cert_aux_st */
            	4155, 0,
            0, 40, 5, /* 4155: struct.x509_cert_aux_st */
            	4168, 0,
            	4168, 8,
            	2820, 16,
            	2770, 24,
            	4192, 32,
            1, 8, 1, /* 4168: pointer.struct.stack_st_ASN1_OBJECT */
            	4173, 0,
            0, 32, 2, /* 4173: struct.stack_st_fake_ASN1_OBJECT */
            	4180, 8,
            	456, 24,
            8884099, 8, 2, /* 4180: pointer_to_array_of_pointers_to_stack */
            	4187, 0,
            	453, 20,
            0, 8, 1, /* 4187: pointer.ASN1_OBJECT */
            	2125, 0,
            1, 8, 1, /* 4192: pointer.struct.stack_st_X509_ALGOR */
            	4197, 0,
            0, 32, 2, /* 4197: struct.stack_st_fake_X509_ALGOR */
            	4204, 8,
            	456, 24,
            8884099, 8, 2, /* 4204: pointer_to_array_of_pointers_to_stack */
            	4211, 0,
            	453, 20,
            0, 8, 1, /* 4211: pointer.X509_ALGOR */
            	2163, 0,
            8884097, 8, 0, /* 4216: pointer.func */
            8884097, 8, 0, /* 4219: pointer.func */
            0, 0, 0, /* 4222: struct.NAME_CONSTRAINTS_st */
            0, 32, 1, /* 4225: struct.stack_st_GENERAL_NAME */
            	4230, 0,
            0, 32, 2, /* 4230: struct.stack_st */
            	664, 8,
            	456, 24,
            8884097, 8, 0, /* 4237: pointer.func */
            1, 8, 1, /* 4240: pointer.struct.x509_st */
            	3712, 0,
            8884097, 8, 0, /* 4245: pointer.func */
            0, 0, 1, /* 4248: X509_OBJECT */
            	4253, 0,
            0, 16, 1, /* 4253: struct.x509_object_st */
            	4258, 8,
            0, 8, 4, /* 4258: union.unknown */
            	61, 0,
            	4240, 0,
            	4269, 0,
            	3848, 0,
            1, 8, 1, /* 4269: pointer.struct.X509_crl_st */
            	4274, 0,
            0, 120, 10, /* 4274: struct.X509_crl_st */
            	4297, 0,
            	2666, 8,
            	2765, 16,
            	2863, 32,
            	4321, 40,
            	2755, 56,
            	2755, 64,
            	4329, 96,
            	4358, 104,
            	49, 112,
            1, 8, 1, /* 4297: pointer.struct.X509_crl_info_st */
            	4302, 0,
            0, 80, 8, /* 4302: struct.X509_crl_info_st */
            	2755, 0,
            	2666, 8,
            	3769, 16,
            	3829, 24,
            	3829, 32,
            	3606, 40,
            	4089, 48,
            	4113, 56,
            1, 8, 1, /* 4321: pointer.struct.ISSUING_DIST_POINT_st */
            	4326, 0,
            0, 0, 0, /* 4326: struct.ISSUING_DIST_POINT_st */
            1, 8, 1, /* 4329: pointer.struct.stack_st_GENERAL_NAMES */
            	4334, 0,
            0, 32, 2, /* 4334: struct.stack_st_fake_GENERAL_NAMES */
            	4341, 8,
            	456, 24,
            8884099, 8, 2, /* 4341: pointer_to_array_of_pointers_to_stack */
            	4348, 0,
            	453, 20,
            0, 8, 1, /* 4348: pointer.GENERAL_NAMES */
            	4353, 0,
            0, 0, 1, /* 4353: GENERAL_NAMES */
            	4225, 0,
            1, 8, 1, /* 4358: pointer.struct.x509_crl_method_st */
            	4363, 0,
            0, 0, 0, /* 4363: struct.x509_crl_method_st */
            1, 8, 1, /* 4366: pointer.struct.stack_st_X509_OBJECT */
            	4371, 0,
            0, 32, 2, /* 4371: struct.stack_st_fake_X509_OBJECT */
            	4378, 8,
            	456, 24,
            8884099, 8, 2, /* 4378: pointer_to_array_of_pointers_to_stack */
            	4385, 0,
            	453, 20,
            0, 8, 1, /* 4385: pointer.X509_OBJECT */
            	4248, 0,
            1, 8, 1, /* 4390: pointer.struct.ssl_method_st */
            	4395, 0,
            0, 232, 28, /* 4395: struct.ssl_method_st */
            	2905, 8,
            	4216, 16,
            	4216, 24,
            	2905, 32,
            	2905, 40,
            	4454, 48,
            	4454, 56,
            	4457, 64,
            	2905, 72,
            	2905, 80,
            	2905, 88,
            	4460, 96,
            	4245, 104,
            	4463, 112,
            	2905, 120,
            	4466, 128,
            	4469, 136,
            	4472, 144,
            	4475, 152,
            	4478, 160,
            	4481, 168,
            	4484, 176,
            	4487, 184,
            	2462, 192,
            	4490, 200,
            	4481, 208,
            	4495, 216,
            	4498, 224,
            8884097, 8, 0, /* 4454: pointer.func */
            8884097, 8, 0, /* 4457: pointer.func */
            8884097, 8, 0, /* 4460: pointer.func */
            8884097, 8, 0, /* 4463: pointer.func */
            8884097, 8, 0, /* 4466: pointer.func */
            8884097, 8, 0, /* 4469: pointer.func */
            8884097, 8, 0, /* 4472: pointer.func */
            8884097, 8, 0, /* 4475: pointer.func */
            8884097, 8, 0, /* 4478: pointer.func */
            8884097, 8, 0, /* 4481: pointer.func */
            8884097, 8, 0, /* 4484: pointer.func */
            8884097, 8, 0, /* 4487: pointer.func */
            1, 8, 1, /* 4490: pointer.struct.ssl3_enc_method */
            	2874, 0,
            8884097, 8, 0, /* 4495: pointer.func */
            8884097, 8, 0, /* 4498: pointer.func */
            8884097, 8, 0, /* 4501: pointer.func */
            0, 144, 15, /* 4504: struct.x509_store_st */
            	4366, 8,
            	4537, 16,
            	4743, 24,
            	4755, 32,
            	4758, 40,
            	4761, 48,
            	4764, 56,
            	4755, 64,
            	4767, 72,
            	2663, 80,
            	4770, 88,
            	2871, 96,
            	4773, 104,
            	4755, 112,
            	642, 120,
            1, 8, 1, /* 4537: pointer.struct.stack_st_X509_LOOKUP */
            	4542, 0,
            0, 32, 2, /* 4542: struct.stack_st_fake_X509_LOOKUP */
            	4549, 8,
            	456, 24,
            8884099, 8, 2, /* 4549: pointer_to_array_of_pointers_to_stack */
            	4556, 0,
            	453, 20,
            0, 8, 1, /* 4556: pointer.X509_LOOKUP */
            	4561, 0,
            0, 0, 1, /* 4561: X509_LOOKUP */
            	4566, 0,
            0, 32, 3, /* 4566: struct.x509_lookup_st */
            	4575, 8,
            	61, 16,
            	4621, 24,
            1, 8, 1, /* 4575: pointer.struct.x509_lookup_method_st */
            	4580, 0,
            0, 80, 10, /* 4580: struct.x509_lookup_method_st */
            	10, 0,
            	4603, 8,
            	2868, 16,
            	4603, 24,
            	4603, 32,
            	4606, 40,
            	4609, 48,
            	4612, 56,
            	4615, 64,
            	4618, 72,
            8884097, 8, 0, /* 4603: pointer.func */
            8884097, 8, 0, /* 4606: pointer.func */
            8884097, 8, 0, /* 4609: pointer.func */
            8884097, 8, 0, /* 4612: pointer.func */
            8884097, 8, 0, /* 4615: pointer.func */
            8884097, 8, 0, /* 4618: pointer.func */
            1, 8, 1, /* 4621: pointer.struct.x509_store_st */
            	4626, 0,
            0, 144, 15, /* 4626: struct.x509_store_st */
            	4659, 8,
            	4683, 16,
            	4707, 24,
            	4719, 32,
            	4722, 40,
            	4725, 48,
            	4728, 56,
            	4719, 64,
            	4731, 72,
            	4734, 80,
            	4737, 88,
            	4740, 96,
            	4501, 104,
            	4719, 112,
            	2533, 120,
            1, 8, 1, /* 4659: pointer.struct.stack_st_X509_OBJECT */
            	4664, 0,
            0, 32, 2, /* 4664: struct.stack_st_fake_X509_OBJECT */
            	4671, 8,
            	456, 24,
            8884099, 8, 2, /* 4671: pointer_to_array_of_pointers_to_stack */
            	4678, 0,
            	453, 20,
            0, 8, 1, /* 4678: pointer.X509_OBJECT */
            	4248, 0,
            1, 8, 1, /* 4683: pointer.struct.stack_st_X509_LOOKUP */
            	4688, 0,
            0, 32, 2, /* 4688: struct.stack_st_fake_X509_LOOKUP */
            	4695, 8,
            	456, 24,
            8884099, 8, 2, /* 4695: pointer_to_array_of_pointers_to_stack */
            	4702, 0,
            	453, 20,
            0, 8, 1, /* 4702: pointer.X509_LOOKUP */
            	4561, 0,
            1, 8, 1, /* 4707: pointer.struct.X509_VERIFY_PARAM_st */
            	4712, 0,
            0, 56, 2, /* 4712: struct.X509_VERIFY_PARAM_st */
            	61, 0,
            	4168, 48,
            8884097, 8, 0, /* 4719: pointer.func */
            8884097, 8, 0, /* 4722: pointer.func */
            8884097, 8, 0, /* 4725: pointer.func */
            8884097, 8, 0, /* 4728: pointer.func */
            8884097, 8, 0, /* 4731: pointer.func */
            8884097, 8, 0, /* 4734: pointer.func */
            8884097, 8, 0, /* 4737: pointer.func */
            8884097, 8, 0, /* 4740: pointer.func */
            1, 8, 1, /* 4743: pointer.struct.X509_VERIFY_PARAM_st */
            	4748, 0,
            0, 56, 2, /* 4748: struct.X509_VERIFY_PARAM_st */
            	61, 0,
            	2101, 48,
            8884097, 8, 0, /* 4755: pointer.func */
            8884097, 8, 0, /* 4758: pointer.func */
            8884097, 8, 0, /* 4761: pointer.func */
            8884097, 8, 0, /* 4764: pointer.func */
            8884097, 8, 0, /* 4767: pointer.func */
            8884097, 8, 0, /* 4770: pointer.func */
            8884097, 8, 0, /* 4773: pointer.func */
            8884099, 8, 2, /* 4776: pointer_to_array_of_pointers_to_stack */
            	4783, 0,
            	453, 20,
            0, 8, 1, /* 4783: pointer.SRTP_PROTECTION_PROFILE */
            	0, 0,
            1, 8, 1, /* 4788: pointer.struct.x509_store_st */
            	4504, 0,
            1, 8, 1, /* 4793: pointer.struct.stack_st_SSL_CIPHER */
            	4798, 0,
            0, 32, 2, /* 4798: struct.stack_st_fake_SSL_CIPHER */
            	4805, 8,
            	456, 24,
            8884099, 8, 2, /* 4805: pointer_to_array_of_pointers_to_stack */
            	4812, 0,
            	453, 20,
            0, 8, 1, /* 4812: pointer.SSL_CIPHER */
            	4817, 0,
            0, 0, 1, /* 4817: SSL_CIPHER */
            	4822, 0,
            0, 88, 1, /* 4822: struct.ssl_cipher_st */
            	10, 8,
            1, 8, 1, /* 4827: pointer.struct.lhash_node_st */
            	4832, 0,
            0, 24, 2, /* 4832: struct.lhash_node_st */
            	49, 0,
            	4839, 8,
            1, 8, 1, /* 4839: pointer.struct.lhash_node_st */
            	4832, 0,
            1, 8, 1, /* 4844: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	4849, 0,
            0, 32, 2, /* 4849: struct.stack_st_fake_SRTP_PROTECTION_PROFILE */
            	4776, 8,
            	456, 24,
            8884097, 8, 0, /* 4856: pointer.func */
            1, 8, 1, /* 4859: pointer.struct.ssl_ctx_st */
            	4864, 0,
            0, 736, 50, /* 4864: struct.ssl_ctx_st */
            	4390, 0,
            	4793, 8,
            	4793, 16,
            	4788, 24,
            	4967, 32,
            	4989, 48,
            	4989, 56,
            	5236, 80,
            	5239, 88,
            	2512, 96,
            	4219, 152,
            	49, 160,
            	5242, 168,
            	49, 176,
            	2509, 184,
            	5245, 192,
            	2506, 200,
            	642, 208,
            	2322, 224,
            	2322, 232,
            	2322, 240,
            	5043, 248,
            	2470, 256,
            	2433, 264,
            	5248, 272,
            	2385, 304,
            	2530, 320,
            	49, 328,
            	4758, 376,
            	5272, 384,
            	4743, 392,
            	524, 408,
            	52, 416,
            	49, 424,
            	4237, 480,
            	55, 488,
            	49, 496,
            	97, 504,
            	49, 512,
            	61, 520,
            	94, 528,
            	4856, 536,
            	5275, 552,
            	5275, 560,
            	18, 568,
            	15, 696,
            	49, 704,
            	3603, 712,
            	49, 720,
            	4844, 728,
            1, 8, 1, /* 4967: pointer.struct.lhash_st */
            	4972, 0,
            0, 176, 3, /* 4972: struct.lhash_st */
            	4981, 0,
            	456, 8,
            	4986, 16,
            1, 8, 1, /* 4981: pointer.pointer.struct.lhash_node_st */
            	4827, 0,
            8884097, 8, 0, /* 4986: pointer.func */
            1, 8, 1, /* 4989: pointer.struct.ssl_session_st */
            	4994, 0,
            0, 352, 14, /* 4994: struct.ssl_session_st */
            	61, 144,
            	61, 152,
            	5025, 168,
            	137, 176,
            	2525, 224,
            	4793, 240,
            	642, 248,
            	4989, 264,
            	4989, 272,
            	61, 280,
            	209, 296,
            	209, 312,
            	209, 320,
            	61, 344,
            1, 8, 1, /* 5025: pointer.struct.sess_cert_st */
            	5030, 0,
            0, 248, 5, /* 5030: struct.sess_cert_st */
            	5043, 0,
            	123, 16,
            	2367, 216,
            	2375, 224,
            	2380, 232,
            1, 8, 1, /* 5043: pointer.struct.stack_st_X509 */
            	5048, 0,
            0, 32, 2, /* 5048: struct.stack_st_fake_X509 */
            	5055, 8,
            	456, 24,
            8884099, 8, 2, /* 5055: pointer_to_array_of_pointers_to_stack */
            	5062, 0,
            	453, 20,
            0, 8, 1, /* 5062: pointer.X509 */
            	5067, 0,
            0, 0, 1, /* 5067: X509 */
            	5072, 0,
            0, 184, 12, /* 5072: struct.x509_st */
            	5099, 0,
            	2961, 8,
            	3050, 16,
            	61, 32,
            	3349, 40,
            	3055, 104,
            	5104, 112,
            	5112, 120,
            	5117, 128,
            	5141, 136,
            	5165, 144,
            	5170, 176,
            1, 8, 1, /* 5099: pointer.struct.x509_cinf_st */
            	2926, 0,
            1, 8, 1, /* 5104: pointer.struct.AUTHORITY_KEYID_st */
            	5109, 0,
            0, 0, 0, /* 5109: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 5112: pointer.struct.X509_POLICY_CACHE_st */
            	3600, 0,
            1, 8, 1, /* 5117: pointer.struct.stack_st_DIST_POINT */
            	5122, 0,
            0, 32, 2, /* 5122: struct.stack_st_fake_DIST_POINT */
            	5129, 8,
            	456, 24,
            8884099, 8, 2, /* 5129: pointer_to_array_of_pointers_to_stack */
            	5136, 0,
            	453, 20,
            0, 8, 1, /* 5136: pointer.DIST_POINT */
            	1632, 0,
            1, 8, 1, /* 5141: pointer.struct.stack_st_GENERAL_NAME */
            	5146, 0,
            0, 32, 2, /* 5146: struct.stack_st_fake_GENERAL_NAME */
            	5153, 8,
            	456, 24,
            8884099, 8, 2, /* 5153: pointer_to_array_of_pointers_to_stack */
            	5160, 0,
            	453, 20,
            0, 8, 1, /* 5160: pointer.GENERAL_NAME */
            	1330, 0,
            1, 8, 1, /* 5165: pointer.struct.NAME_CONSTRAINTS_st */
            	4222, 0,
            1, 8, 1, /* 5170: pointer.struct.x509_cert_aux_st */
            	5175, 0,
            0, 40, 5, /* 5175: struct.x509_cert_aux_st */
            	5188, 0,
            	5188, 8,
            	3105, 16,
            	3055, 24,
            	5212, 32,
            1, 8, 1, /* 5188: pointer.struct.stack_st_ASN1_OBJECT */
            	5193, 0,
            0, 32, 2, /* 5193: struct.stack_st_fake_ASN1_OBJECT */
            	5200, 8,
            	456, 24,
            8884099, 8, 2, /* 5200: pointer_to_array_of_pointers_to_stack */
            	5207, 0,
            	453, 20,
            0, 8, 1, /* 5207: pointer.ASN1_OBJECT */
            	2125, 0,
            1, 8, 1, /* 5212: pointer.struct.stack_st_X509_ALGOR */
            	5217, 0,
            0, 32, 2, /* 5217: struct.stack_st_fake_X509_ALGOR */
            	5224, 8,
            	456, 24,
            8884099, 8, 2, /* 5224: pointer_to_array_of_pointers_to_stack */
            	5231, 0,
            	453, 20,
            0, 8, 1, /* 5231: pointer.X509_ALGOR */
            	2163, 0,
            8884097, 8, 0, /* 5236: pointer.func */
            8884097, 8, 0, /* 5239: pointer.func */
            8884097, 8, 0, /* 5242: pointer.func */
            8884097, 8, 0, /* 5245: pointer.func */
            1, 8, 1, /* 5248: pointer.struct.stack_st_X509_NAME */
            	5253, 0,
            0, 32, 2, /* 5253: struct.stack_st_fake_X509_NAME */
            	5260, 8,
            	456, 24,
            8884099, 8, 2, /* 5260: pointer_to_array_of_pointers_to_stack */
            	5267, 0,
            	453, 20,
            0, 8, 1, /* 5267: pointer.X509_NAME */
            	2520, 0,
            8884097, 8, 0, /* 5272: pointer.func */
            1, 8, 1, /* 5275: pointer.struct.ssl3_buf_freelist_st */
            	5280, 0,
            0, 24, 1, /* 5280: struct.ssl3_buf_freelist_st */
            	84, 16,
            0, 1, 0, /* 5285: char */
        },
        .arg_entity_index = { 4859, },
        .ret_entity_index = -1,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    SSL_CTX * new_arg_a = *((SSL_CTX * *)new_args->args[0]);

    void (*orig_SSL_CTX_free)(SSL_CTX *);
    orig_SSL_CTX_free = dlsym(RTLD_NEXT, "SSL_CTX_free");
    (*orig_SSL_CTX_free)(new_arg_a);

    syscall(889);

}

