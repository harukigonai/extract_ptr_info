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

X509_STORE * bb_SSL_CTX_get_cert_store(const SSL_CTX * arg_a);

X509_STORE * SSL_CTX_get_cert_store(const SSL_CTX * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_CTX_get_cert_store called %lu\n", in_lib);
    if (!in_lib)
        return bb_SSL_CTX_get_cert_store(arg_a);
    else {
        X509_STORE * (*orig_SSL_CTX_get_cert_store)(const SSL_CTX *);
        orig_SSL_CTX_get_cert_store = dlsym(RTLD_NEXT, "SSL_CTX_get_cert_store");
        return orig_SSL_CTX_get_cert_store(arg_a);
    }
}

X509_STORE * bb_SSL_CTX_get_cert_store(const SSL_CTX * arg_a) 
{
    X509_STORE * ret;

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
            1, 8, 1, /* 2530: pointer.struct.X509_crl_st */
            	2535, 0,
            0, 120, 10, /* 2535: struct.X509_crl_st */
            	2558, 0,
            	2592, 8,
            	2681, 16,
            	2926, 32,
            	2934, 40,
            	2582, 56,
            	2582, 64,
            	2942, 96,
            	2983, 104,
            	49, 112,
            1, 8, 1, /* 2558: pointer.struct.X509_crl_info_st */
            	2563, 0,
            0, 80, 8, /* 2563: struct.X509_crl_info_st */
            	2582, 0,
            	2592, 8,
            	2741, 16,
            	2789, 24,
            	2789, 32,
            	2794, 40,
            	2897, 48,
            	2921, 56,
            1, 8, 1, /* 2582: pointer.struct.asn1_string_st */
            	2587, 0,
            0, 24, 1, /* 2587: struct.asn1_string_st */
            	209, 8,
            1, 8, 1, /* 2592: pointer.struct.X509_algor_st */
            	2597, 0,
            0, 16, 2, /* 2597: struct.X509_algor_st */
            	2604, 0,
            	2618, 8,
            1, 8, 1, /* 2604: pointer.struct.asn1_object_st */
            	2609, 0,
            0, 40, 3, /* 2609: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	243, 24,
            1, 8, 1, /* 2618: pointer.struct.asn1_type_st */
            	2623, 0,
            0, 16, 1, /* 2623: struct.asn1_type_st */
            	2628, 8,
            0, 8, 20, /* 2628: union.unknown */
            	61, 0,
            	2671, 0,
            	2604, 0,
            	2582, 0,
            	2676, 0,
            	2681, 0,
            	2686, 0,
            	2691, 0,
            	2696, 0,
            	2701, 0,
            	2706, 0,
            	2711, 0,
            	2716, 0,
            	2721, 0,
            	2726, 0,
            	2731, 0,
            	2736, 0,
            	2671, 0,
            	2671, 0,
            	1219, 0,
            1, 8, 1, /* 2671: pointer.struct.asn1_string_st */
            	2587, 0,
            1, 8, 1, /* 2676: pointer.struct.asn1_string_st */
            	2587, 0,
            1, 8, 1, /* 2681: pointer.struct.asn1_string_st */
            	2587, 0,
            1, 8, 1, /* 2686: pointer.struct.asn1_string_st */
            	2587, 0,
            1, 8, 1, /* 2691: pointer.struct.asn1_string_st */
            	2587, 0,
            1, 8, 1, /* 2696: pointer.struct.asn1_string_st */
            	2587, 0,
            1, 8, 1, /* 2701: pointer.struct.asn1_string_st */
            	2587, 0,
            1, 8, 1, /* 2706: pointer.struct.asn1_string_st */
            	2587, 0,
            1, 8, 1, /* 2711: pointer.struct.asn1_string_st */
            	2587, 0,
            1, 8, 1, /* 2716: pointer.struct.asn1_string_st */
            	2587, 0,
            1, 8, 1, /* 2721: pointer.struct.asn1_string_st */
            	2587, 0,
            1, 8, 1, /* 2726: pointer.struct.asn1_string_st */
            	2587, 0,
            1, 8, 1, /* 2731: pointer.struct.asn1_string_st */
            	2587, 0,
            1, 8, 1, /* 2736: pointer.struct.asn1_string_st */
            	2587, 0,
            1, 8, 1, /* 2741: pointer.struct.X509_name_st */
            	2746, 0,
            0, 40, 3, /* 2746: struct.X509_name_st */
            	2755, 0,
            	2779, 16,
            	209, 24,
            1, 8, 1, /* 2755: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2760, 0,
            0, 32, 2, /* 2760: struct.stack_st_fake_X509_NAME_ENTRY */
            	2767, 8,
            	456, 24,
            8884099, 8, 2, /* 2767: pointer_to_array_of_pointers_to_stack */
            	2774, 0,
            	453, 20,
            0, 8, 1, /* 2774: pointer.X509_NAME_ENTRY */
            	417, 0,
            1, 8, 1, /* 2779: pointer.struct.buf_mem_st */
            	2784, 0,
            0, 24, 1, /* 2784: struct.buf_mem_st */
            	61, 8,
            1, 8, 1, /* 2789: pointer.struct.asn1_string_st */
            	2587, 0,
            1, 8, 1, /* 2794: pointer.struct.stack_st_X509_REVOKED */
            	2799, 0,
            0, 32, 2, /* 2799: struct.stack_st_fake_X509_REVOKED */
            	2806, 8,
            	456, 24,
            8884099, 8, 2, /* 2806: pointer_to_array_of_pointers_to_stack */
            	2813, 0,
            	453, 20,
            0, 8, 1, /* 2813: pointer.X509_REVOKED */
            	2818, 0,
            0, 0, 1, /* 2818: X509_REVOKED */
            	2823, 0,
            0, 40, 4, /* 2823: struct.x509_revoked_st */
            	2834, 0,
            	2844, 8,
            	2849, 16,
            	2873, 24,
            1, 8, 1, /* 2834: pointer.struct.asn1_string_st */
            	2839, 0,
            0, 24, 1, /* 2839: struct.asn1_string_st */
            	209, 8,
            1, 8, 1, /* 2844: pointer.struct.asn1_string_st */
            	2839, 0,
            1, 8, 1, /* 2849: pointer.struct.stack_st_X509_EXTENSION */
            	2854, 0,
            0, 32, 2, /* 2854: struct.stack_st_fake_X509_EXTENSION */
            	2861, 8,
            	456, 24,
            8884099, 8, 2, /* 2861: pointer_to_array_of_pointers_to_stack */
            	2868, 0,
            	453, 20,
            0, 8, 1, /* 2868: pointer.X509_EXTENSION */
            	1251, 0,
            1, 8, 1, /* 2873: pointer.struct.stack_st_GENERAL_NAME */
            	2878, 0,
            0, 32, 2, /* 2878: struct.stack_st_fake_GENERAL_NAME */
            	2885, 8,
            	456, 24,
            8884099, 8, 2, /* 2885: pointer_to_array_of_pointers_to_stack */
            	2892, 0,
            	453, 20,
            0, 8, 1, /* 2892: pointer.GENERAL_NAME */
            	1330, 0,
            1, 8, 1, /* 2897: pointer.struct.stack_st_X509_EXTENSION */
            	2902, 0,
            0, 32, 2, /* 2902: struct.stack_st_fake_X509_EXTENSION */
            	2909, 8,
            	456, 24,
            8884099, 8, 2, /* 2909: pointer_to_array_of_pointers_to_stack */
            	2916, 0,
            	453, 20,
            0, 8, 1, /* 2916: pointer.X509_EXTENSION */
            	1251, 0,
            0, 24, 1, /* 2921: struct.ASN1_ENCODING_st */
            	209, 0,
            1, 8, 1, /* 2926: pointer.struct.AUTHORITY_KEYID_st */
            	2931, 0,
            0, 0, 0, /* 2931: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 2934: pointer.struct.ISSUING_DIST_POINT_st */
            	2939, 0,
            0, 0, 0, /* 2939: struct.ISSUING_DIST_POINT_st */
            1, 8, 1, /* 2942: pointer.struct.stack_st_GENERAL_NAMES */
            	2947, 0,
            0, 32, 2, /* 2947: struct.stack_st_fake_GENERAL_NAMES */
            	2954, 8,
            	456, 24,
            8884099, 8, 2, /* 2954: pointer_to_array_of_pointers_to_stack */
            	2961, 0,
            	453, 20,
            0, 8, 1, /* 2961: pointer.GENERAL_NAMES */
            	2966, 0,
            0, 0, 1, /* 2966: GENERAL_NAMES */
            	2971, 0,
            0, 32, 1, /* 2971: struct.stack_st_GENERAL_NAME */
            	2976, 0,
            0, 32, 2, /* 2976: struct.stack_st */
            	664, 8,
            	456, 24,
            1, 8, 1, /* 2983: pointer.struct.x509_crl_method_st */
            	2988, 0,
            0, 0, 0, /* 2988: struct.x509_crl_method_st */
            8884097, 8, 0, /* 2991: pointer.func */
            1, 8, 1, /* 2994: pointer.struct.NAME_CONSTRAINTS_st */
            	2999, 0,
            0, 0, 0, /* 2999: struct.NAME_CONSTRAINTS_st */
            8884097, 8, 0, /* 3002: pointer.func */
            1, 8, 1, /* 3005: pointer.struct.ASN1_VALUE_st */
            	3010, 0,
            0, 0, 0, /* 3010: struct.ASN1_VALUE_st */
            8884097, 8, 0, /* 3013: pointer.func */
            0, 16, 1, /* 3016: struct.crypto_ex_data_st */
            	3021, 0,
            1, 8, 1, /* 3021: pointer.struct.stack_st_void */
            	3026, 0,
            0, 32, 1, /* 3026: struct.stack_st_void */
            	3031, 0,
            0, 32, 2, /* 3031: struct.stack_st */
            	664, 8,
            	456, 24,
            0, 32, 3, /* 3038: struct.x509_lookup_st */
            	3047, 8,
            	61, 16,
            	3096, 24,
            1, 8, 1, /* 3047: pointer.struct.x509_lookup_method_st */
            	3052, 0,
            0, 80, 10, /* 3052: struct.x509_lookup_method_st */
            	10, 0,
            	3075, 8,
            	3078, 16,
            	3075, 24,
            	3075, 32,
            	3081, 40,
            	3084, 48,
            	3087, 56,
            	3090, 64,
            	3093, 72,
            8884097, 8, 0, /* 3075: pointer.func */
            8884097, 8, 0, /* 3078: pointer.func */
            8884097, 8, 0, /* 3081: pointer.func */
            8884097, 8, 0, /* 3084: pointer.func */
            8884097, 8, 0, /* 3087: pointer.func */
            8884097, 8, 0, /* 3090: pointer.func */
            8884097, 8, 0, /* 3093: pointer.func */
            1, 8, 1, /* 3096: pointer.struct.x509_store_st */
            	3101, 0,
            0, 144, 15, /* 3101: struct.x509_store_st */
            	3134, 8,
            	3741, 16,
            	3770, 24,
            	3782, 32,
            	3785, 40,
            	3788, 48,
            	3791, 56,
            	3782, 64,
            	2991, 72,
            	3794, 80,
            	3797, 88,
            	3800, 96,
            	3803, 104,
            	3782, 112,
            	3016, 120,
            1, 8, 1, /* 3134: pointer.struct.stack_st_X509_OBJECT */
            	3139, 0,
            0, 32, 2, /* 3139: struct.stack_st_fake_X509_OBJECT */
            	3146, 8,
            	456, 24,
            8884099, 8, 2, /* 3146: pointer_to_array_of_pointers_to_stack */
            	3153, 0,
            	453, 20,
            0, 8, 1, /* 3153: pointer.X509_OBJECT */
            	3158, 0,
            0, 0, 1, /* 3158: X509_OBJECT */
            	3163, 0,
            0, 16, 1, /* 3163: struct.x509_object_st */
            	3168, 8,
            0, 8, 4, /* 3168: union.unknown */
            	61, 0,
            	3179, 0,
            	2530, 0,
            	3267, 0,
            1, 8, 1, /* 3179: pointer.struct.x509_st */
            	3184, 0,
            0, 184, 12, /* 3184: struct.x509_st */
            	3211, 0,
            	2592, 8,
            	2681, 16,
            	61, 32,
            	3016, 40,
            	2686, 104,
            	2926, 112,
            	3619, 120,
            	3627, 128,
            	3651, 136,
            	2994, 144,
            	3675, 176,
            1, 8, 1, /* 3211: pointer.struct.x509_cinf_st */
            	3216, 0,
            0, 104, 11, /* 3216: struct.x509_cinf_st */
            	2582, 0,
            	2582, 8,
            	2592, 16,
            	2741, 24,
            	3241, 32,
            	2741, 40,
            	3253, 48,
            	2681, 56,
            	2681, 64,
            	2897, 72,
            	2921, 80,
            1, 8, 1, /* 3241: pointer.struct.X509_val_st */
            	3246, 0,
            0, 16, 2, /* 3246: struct.X509_val_st */
            	2789, 0,
            	2789, 8,
            1, 8, 1, /* 3253: pointer.struct.X509_pubkey_st */
            	3258, 0,
            0, 24, 3, /* 3258: struct.X509_pubkey_st */
            	2592, 0,
            	2681, 8,
            	3267, 16,
            1, 8, 1, /* 3267: pointer.struct.evp_pkey_st */
            	3272, 0,
            0, 56, 4, /* 3272: struct.evp_pkey_st */
            	3283, 16,
            	3291, 24,
            	3299, 32,
            	3595, 48,
            1, 8, 1, /* 3283: pointer.struct.evp_pkey_asn1_method_st */
            	3288, 0,
            0, 0, 0, /* 3288: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 3291: pointer.struct.engine_st */
            	3296, 0,
            0, 0, 0, /* 3296: struct.engine_st */
            0, 8, 5, /* 3299: union.unknown */
            	61, 0,
            	3312, 0,
            	3438, 0,
            	3519, 0,
            	3587, 0,
            1, 8, 1, /* 3312: pointer.struct.rsa_st */
            	3317, 0,
            0, 168, 17, /* 3317: struct.rsa_st */
            	3354, 16,
            	3291, 24,
            	3406, 32,
            	3406, 40,
            	3406, 48,
            	3406, 56,
            	3406, 64,
            	3406, 72,
            	3406, 80,
            	3406, 88,
            	3016, 96,
            	3416, 120,
            	3416, 128,
            	3416, 136,
            	61, 144,
            	3430, 152,
            	3430, 160,
            1, 8, 1, /* 3354: pointer.struct.rsa_meth_st */
            	3359, 0,
            0, 112, 13, /* 3359: struct.rsa_meth_st */
            	10, 0,
            	3388, 8,
            	3388, 16,
            	3388, 24,
            	3388, 32,
            	3391, 40,
            	3394, 48,
            	3397, 56,
            	3397, 64,
            	61, 80,
            	3002, 88,
            	3400, 96,
            	3403, 104,
            8884097, 8, 0, /* 3388: pointer.func */
            8884097, 8, 0, /* 3391: pointer.func */
            8884097, 8, 0, /* 3394: pointer.func */
            8884097, 8, 0, /* 3397: pointer.func */
            8884097, 8, 0, /* 3400: pointer.func */
            8884097, 8, 0, /* 3403: pointer.func */
            1, 8, 1, /* 3406: pointer.struct.bignum_st */
            	3411, 0,
            0, 24, 1, /* 3411: struct.bignum_st */
            	76, 0,
            1, 8, 1, /* 3416: pointer.struct.bn_mont_ctx_st */
            	3421, 0,
            0, 96, 3, /* 3421: struct.bn_mont_ctx_st */
            	3411, 8,
            	3411, 32,
            	3411, 56,
            1, 8, 1, /* 3430: pointer.struct.bn_blinding_st */
            	3435, 0,
            0, 0, 0, /* 3435: struct.bn_blinding_st */
            1, 8, 1, /* 3438: pointer.struct.dsa_st */
            	3443, 0,
            0, 136, 11, /* 3443: struct.dsa_st */
            	3406, 24,
            	3406, 32,
            	3406, 40,
            	3406, 48,
            	3406, 56,
            	3406, 64,
            	3406, 72,
            	3416, 88,
            	3016, 104,
            	3468, 120,
            	3291, 128,
            1, 8, 1, /* 3468: pointer.struct.dsa_method */
            	3473, 0,
            0, 96, 11, /* 3473: struct.dsa_method */
            	10, 0,
            	3498, 8,
            	3501, 16,
            	3504, 24,
            	3507, 32,
            	3510, 40,
            	3513, 48,
            	3513, 56,
            	61, 72,
            	3516, 80,
            	3513, 88,
            8884097, 8, 0, /* 3498: pointer.func */
            8884097, 8, 0, /* 3501: pointer.func */
            8884097, 8, 0, /* 3504: pointer.func */
            8884097, 8, 0, /* 3507: pointer.func */
            8884097, 8, 0, /* 3510: pointer.func */
            8884097, 8, 0, /* 3513: pointer.func */
            8884097, 8, 0, /* 3516: pointer.func */
            1, 8, 1, /* 3519: pointer.struct.dh_st */
            	3524, 0,
            0, 144, 12, /* 3524: struct.dh_st */
            	3406, 8,
            	3406, 16,
            	3406, 32,
            	3406, 40,
            	3416, 56,
            	3406, 64,
            	3406, 72,
            	209, 80,
            	3406, 96,
            	3016, 112,
            	3551, 128,
            	3291, 136,
            1, 8, 1, /* 3551: pointer.struct.dh_method */
            	3556, 0,
            0, 72, 8, /* 3556: struct.dh_method */
            	10, 0,
            	3575, 8,
            	3578, 16,
            	3581, 24,
            	3575, 32,
            	3575, 40,
            	61, 56,
            	3584, 64,
            8884097, 8, 0, /* 3575: pointer.func */
            8884097, 8, 0, /* 3578: pointer.func */
            8884097, 8, 0, /* 3581: pointer.func */
            8884097, 8, 0, /* 3584: pointer.func */
            1, 8, 1, /* 3587: pointer.struct.ec_key_st */
            	3592, 0,
            0, 0, 0, /* 3592: struct.ec_key_st */
            1, 8, 1, /* 3595: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3600, 0,
            0, 32, 2, /* 3600: struct.stack_st_fake_X509_ATTRIBUTE */
            	3607, 8,
            	456, 24,
            8884099, 8, 2, /* 3607: pointer_to_array_of_pointers_to_stack */
            	3614, 0,
            	453, 20,
            0, 8, 1, /* 3614: pointer.X509_ATTRIBUTE */
            	872, 0,
            1, 8, 1, /* 3619: pointer.struct.X509_POLICY_CACHE_st */
            	3624, 0,
            0, 0, 0, /* 3624: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 3627: pointer.struct.stack_st_DIST_POINT */
            	3632, 0,
            0, 32, 2, /* 3632: struct.stack_st_fake_DIST_POINT */
            	3639, 8,
            	456, 24,
            8884099, 8, 2, /* 3639: pointer_to_array_of_pointers_to_stack */
            	3646, 0,
            	453, 20,
            0, 8, 1, /* 3646: pointer.DIST_POINT */
            	1632, 0,
            1, 8, 1, /* 3651: pointer.struct.stack_st_GENERAL_NAME */
            	3656, 0,
            0, 32, 2, /* 3656: struct.stack_st_fake_GENERAL_NAME */
            	3663, 8,
            	456, 24,
            8884099, 8, 2, /* 3663: pointer_to_array_of_pointers_to_stack */
            	3670, 0,
            	453, 20,
            0, 8, 1, /* 3670: pointer.GENERAL_NAME */
            	1330, 0,
            1, 8, 1, /* 3675: pointer.struct.x509_cert_aux_st */
            	3680, 0,
            0, 40, 5, /* 3680: struct.x509_cert_aux_st */
            	3693, 0,
            	3693, 8,
            	2736, 16,
            	2686, 24,
            	3717, 32,
            1, 8, 1, /* 3693: pointer.struct.stack_st_ASN1_OBJECT */
            	3698, 0,
            0, 32, 2, /* 3698: struct.stack_st_fake_ASN1_OBJECT */
            	3705, 8,
            	456, 24,
            8884099, 8, 2, /* 3705: pointer_to_array_of_pointers_to_stack */
            	3712, 0,
            	453, 20,
            0, 8, 1, /* 3712: pointer.ASN1_OBJECT */
            	2125, 0,
            1, 8, 1, /* 3717: pointer.struct.stack_st_X509_ALGOR */
            	3722, 0,
            0, 32, 2, /* 3722: struct.stack_st_fake_X509_ALGOR */
            	3729, 8,
            	456, 24,
            8884099, 8, 2, /* 3729: pointer_to_array_of_pointers_to_stack */
            	3736, 0,
            	453, 20,
            0, 8, 1, /* 3736: pointer.X509_ALGOR */
            	2163, 0,
            1, 8, 1, /* 3741: pointer.struct.stack_st_X509_LOOKUP */
            	3746, 0,
            0, 32, 2, /* 3746: struct.stack_st_fake_X509_LOOKUP */
            	3753, 8,
            	456, 24,
            8884099, 8, 2, /* 3753: pointer_to_array_of_pointers_to_stack */
            	3760, 0,
            	453, 20,
            0, 8, 1, /* 3760: pointer.X509_LOOKUP */
            	3765, 0,
            0, 0, 1, /* 3765: X509_LOOKUP */
            	3038, 0,
            1, 8, 1, /* 3770: pointer.struct.X509_VERIFY_PARAM_st */
            	3775, 0,
            0, 56, 2, /* 3775: struct.X509_VERIFY_PARAM_st */
            	61, 0,
            	3693, 48,
            8884097, 8, 0, /* 3782: pointer.func */
            8884097, 8, 0, /* 3785: pointer.func */
            8884097, 8, 0, /* 3788: pointer.func */
            8884097, 8, 0, /* 3791: pointer.func */
            8884097, 8, 0, /* 3794: pointer.func */
            8884097, 8, 0, /* 3797: pointer.func */
            8884097, 8, 0, /* 3800: pointer.func */
            8884097, 8, 0, /* 3803: pointer.func */
            1, 8, 1, /* 3806: pointer.struct.asn1_string_st */
            	3811, 0,
            0, 24, 1, /* 3811: struct.asn1_string_st */
            	209, 8,
            8884097, 8, 0, /* 3816: pointer.func */
            1, 8, 1, /* 3819: pointer.struct.asn1_string_st */
            	3811, 0,
            8884097, 8, 0, /* 3824: pointer.func */
            8884097, 8, 0, /* 3827: pointer.func */
            0, 112, 11, /* 3830: struct.ssl3_enc_method */
            	3855, 0,
            	3858, 8,
            	3861, 16,
            	3864, 24,
            	3855, 32,
            	3867, 40,
            	3870, 56,
            	10, 64,
            	10, 80,
            	3873, 96,
            	3876, 104,
            8884097, 8, 0, /* 3855: pointer.func */
            8884097, 8, 0, /* 3858: pointer.func */
            8884097, 8, 0, /* 3861: pointer.func */
            8884097, 8, 0, /* 3864: pointer.func */
            8884097, 8, 0, /* 3867: pointer.func */
            8884097, 8, 0, /* 3870: pointer.func */
            8884097, 8, 0, /* 3873: pointer.func */
            8884097, 8, 0, /* 3876: pointer.func */
            8884097, 8, 0, /* 3879: pointer.func */
            0, 104, 11, /* 3882: struct.x509_cinf_st */
            	3907, 0,
            	3907, 8,
            	3912, 16,
            	4051, 24,
            	4099, 32,
            	4051, 40,
            	4116, 48,
            	4001, 56,
            	4001, 64,
            	4504, 72,
            	4528, 80,
            1, 8, 1, /* 3907: pointer.struct.asn1_string_st */
            	3811, 0,
            1, 8, 1, /* 3912: pointer.struct.X509_algor_st */
            	3917, 0,
            0, 16, 2, /* 3917: struct.X509_algor_st */
            	3924, 0,
            	3938, 8,
            1, 8, 1, /* 3924: pointer.struct.asn1_object_st */
            	3929, 0,
            0, 40, 3, /* 3929: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	243, 24,
            1, 8, 1, /* 3938: pointer.struct.asn1_type_st */
            	3943, 0,
            0, 16, 1, /* 3943: struct.asn1_type_st */
            	3948, 8,
            0, 8, 20, /* 3948: union.unknown */
            	61, 0,
            	3991, 0,
            	3924, 0,
            	3907, 0,
            	3996, 0,
            	4001, 0,
            	4006, 0,
            	4011, 0,
            	4016, 0,
            	4021, 0,
            	4026, 0,
            	4031, 0,
            	4036, 0,
            	4041, 0,
            	4046, 0,
            	3819, 0,
            	3806, 0,
            	3991, 0,
            	3991, 0,
            	3005, 0,
            1, 8, 1, /* 3991: pointer.struct.asn1_string_st */
            	3811, 0,
            1, 8, 1, /* 3996: pointer.struct.asn1_string_st */
            	3811, 0,
            1, 8, 1, /* 4001: pointer.struct.asn1_string_st */
            	3811, 0,
            1, 8, 1, /* 4006: pointer.struct.asn1_string_st */
            	3811, 0,
            1, 8, 1, /* 4011: pointer.struct.asn1_string_st */
            	3811, 0,
            1, 8, 1, /* 4016: pointer.struct.asn1_string_st */
            	3811, 0,
            1, 8, 1, /* 4021: pointer.struct.asn1_string_st */
            	3811, 0,
            1, 8, 1, /* 4026: pointer.struct.asn1_string_st */
            	3811, 0,
            1, 8, 1, /* 4031: pointer.struct.asn1_string_st */
            	3811, 0,
            1, 8, 1, /* 4036: pointer.struct.asn1_string_st */
            	3811, 0,
            1, 8, 1, /* 4041: pointer.struct.asn1_string_st */
            	3811, 0,
            1, 8, 1, /* 4046: pointer.struct.asn1_string_st */
            	3811, 0,
            1, 8, 1, /* 4051: pointer.struct.X509_name_st */
            	4056, 0,
            0, 40, 3, /* 4056: struct.X509_name_st */
            	4065, 0,
            	4089, 16,
            	209, 24,
            1, 8, 1, /* 4065: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4070, 0,
            0, 32, 2, /* 4070: struct.stack_st_fake_X509_NAME_ENTRY */
            	4077, 8,
            	456, 24,
            8884099, 8, 2, /* 4077: pointer_to_array_of_pointers_to_stack */
            	4084, 0,
            	453, 20,
            0, 8, 1, /* 4084: pointer.X509_NAME_ENTRY */
            	417, 0,
            1, 8, 1, /* 4089: pointer.struct.buf_mem_st */
            	4094, 0,
            0, 24, 1, /* 4094: struct.buf_mem_st */
            	61, 8,
            1, 8, 1, /* 4099: pointer.struct.X509_val_st */
            	4104, 0,
            0, 16, 2, /* 4104: struct.X509_val_st */
            	4111, 0,
            	4111, 8,
            1, 8, 1, /* 4111: pointer.struct.asn1_string_st */
            	3811, 0,
            1, 8, 1, /* 4116: pointer.struct.X509_pubkey_st */
            	4121, 0,
            0, 24, 3, /* 4121: struct.X509_pubkey_st */
            	3912, 0,
            	4001, 8,
            	4130, 16,
            1, 8, 1, /* 4130: pointer.struct.evp_pkey_st */
            	4135, 0,
            0, 56, 4, /* 4135: struct.evp_pkey_st */
            	4146, 16,
            	4154, 24,
            	4162, 32,
            	4480, 48,
            1, 8, 1, /* 4146: pointer.struct.evp_pkey_asn1_method_st */
            	4151, 0,
            0, 0, 0, /* 4151: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 4154: pointer.struct.engine_st */
            	4159, 0,
            0, 0, 0, /* 4159: struct.engine_st */
            0, 8, 5, /* 4162: union.unknown */
            	61, 0,
            	4175, 0,
            	4326, 0,
            	4404, 0,
            	4472, 0,
            1, 8, 1, /* 4175: pointer.struct.rsa_st */
            	4180, 0,
            0, 168, 17, /* 4180: struct.rsa_st */
            	4217, 16,
            	4154, 24,
            	4272, 32,
            	4272, 40,
            	4272, 48,
            	4272, 56,
            	4272, 64,
            	4272, 72,
            	4272, 80,
            	4272, 88,
            	4282, 96,
            	4304, 120,
            	4304, 128,
            	4304, 136,
            	61, 144,
            	4318, 152,
            	4318, 160,
            1, 8, 1, /* 4217: pointer.struct.rsa_meth_st */
            	4222, 0,
            0, 112, 13, /* 4222: struct.rsa_meth_st */
            	10, 0,
            	4251, 8,
            	4251, 16,
            	4251, 24,
            	4251, 32,
            	4254, 40,
            	4257, 48,
            	4260, 56,
            	4260, 64,
            	61, 80,
            	4263, 88,
            	4266, 96,
            	4269, 104,
            8884097, 8, 0, /* 4251: pointer.func */
            8884097, 8, 0, /* 4254: pointer.func */
            8884097, 8, 0, /* 4257: pointer.func */
            8884097, 8, 0, /* 4260: pointer.func */
            8884097, 8, 0, /* 4263: pointer.func */
            8884097, 8, 0, /* 4266: pointer.func */
            8884097, 8, 0, /* 4269: pointer.func */
            1, 8, 1, /* 4272: pointer.struct.bignum_st */
            	4277, 0,
            0, 24, 1, /* 4277: struct.bignum_st */
            	76, 0,
            0, 16, 1, /* 4282: struct.crypto_ex_data_st */
            	4287, 0,
            1, 8, 1, /* 4287: pointer.struct.stack_st_void */
            	4292, 0,
            0, 32, 1, /* 4292: struct.stack_st_void */
            	4297, 0,
            0, 32, 2, /* 4297: struct.stack_st */
            	664, 8,
            	456, 24,
            1, 8, 1, /* 4304: pointer.struct.bn_mont_ctx_st */
            	4309, 0,
            0, 96, 3, /* 4309: struct.bn_mont_ctx_st */
            	4277, 8,
            	4277, 32,
            	4277, 56,
            1, 8, 1, /* 4318: pointer.struct.bn_blinding_st */
            	4323, 0,
            0, 0, 0, /* 4323: struct.bn_blinding_st */
            1, 8, 1, /* 4326: pointer.struct.dsa_st */
            	4331, 0,
            0, 136, 11, /* 4331: struct.dsa_st */
            	4272, 24,
            	4272, 32,
            	4272, 40,
            	4272, 48,
            	4272, 56,
            	4272, 64,
            	4272, 72,
            	4304, 88,
            	4282, 104,
            	4356, 120,
            	4154, 128,
            1, 8, 1, /* 4356: pointer.struct.dsa_method */
            	4361, 0,
            0, 96, 11, /* 4361: struct.dsa_method */
            	10, 0,
            	4386, 8,
            	4389, 16,
            	4392, 24,
            	3879, 32,
            	4395, 40,
            	4398, 48,
            	4398, 56,
            	61, 72,
            	4401, 80,
            	4398, 88,
            8884097, 8, 0, /* 4386: pointer.func */
            8884097, 8, 0, /* 4389: pointer.func */
            8884097, 8, 0, /* 4392: pointer.func */
            8884097, 8, 0, /* 4395: pointer.func */
            8884097, 8, 0, /* 4398: pointer.func */
            8884097, 8, 0, /* 4401: pointer.func */
            1, 8, 1, /* 4404: pointer.struct.dh_st */
            	4409, 0,
            0, 144, 12, /* 4409: struct.dh_st */
            	4272, 8,
            	4272, 16,
            	4272, 32,
            	4272, 40,
            	4304, 56,
            	4272, 64,
            	4272, 72,
            	209, 80,
            	4272, 96,
            	4282, 112,
            	4436, 128,
            	4154, 136,
            1, 8, 1, /* 4436: pointer.struct.dh_method */
            	4441, 0,
            0, 72, 8, /* 4441: struct.dh_method */
            	10, 0,
            	4460, 8,
            	4463, 16,
            	4466, 24,
            	4460, 32,
            	4460, 40,
            	61, 56,
            	4469, 64,
            8884097, 8, 0, /* 4460: pointer.func */
            8884097, 8, 0, /* 4463: pointer.func */
            8884097, 8, 0, /* 4466: pointer.func */
            8884097, 8, 0, /* 4469: pointer.func */
            1, 8, 1, /* 4472: pointer.struct.ec_key_st */
            	4477, 0,
            0, 0, 0, /* 4477: struct.ec_key_st */
            1, 8, 1, /* 4480: pointer.struct.stack_st_X509_ATTRIBUTE */
            	4485, 0,
            0, 32, 2, /* 4485: struct.stack_st_fake_X509_ATTRIBUTE */
            	4492, 8,
            	456, 24,
            8884099, 8, 2, /* 4492: pointer_to_array_of_pointers_to_stack */
            	4499, 0,
            	453, 20,
            0, 8, 1, /* 4499: pointer.X509_ATTRIBUTE */
            	872, 0,
            1, 8, 1, /* 4504: pointer.struct.stack_st_X509_EXTENSION */
            	4509, 0,
            0, 32, 2, /* 4509: struct.stack_st_fake_X509_EXTENSION */
            	4516, 8,
            	456, 24,
            8884099, 8, 2, /* 4516: pointer_to_array_of_pointers_to_stack */
            	4523, 0,
            	453, 20,
            0, 8, 1, /* 4523: pointer.X509_EXTENSION */
            	1251, 0,
            0, 24, 1, /* 4528: struct.ASN1_ENCODING_st */
            	209, 0,
            0, 0, 0, /* 4533: struct.X509_POLICY_CACHE_st */
            8884097, 8, 0, /* 4536: pointer.func */
            8884097, 8, 0, /* 4539: pointer.func */
            8884097, 8, 0, /* 4542: pointer.func */
            8884097, 8, 0, /* 4545: pointer.func */
            1, 8, 1, /* 4548: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	4553, 0,
            0, 32, 2, /* 4553: struct.stack_st_fake_SRTP_PROTECTION_PROFILE */
            	4560, 8,
            	456, 24,
            8884099, 8, 2, /* 4560: pointer_to_array_of_pointers_to_stack */
            	4567, 0,
            	453, 20,
            0, 8, 1, /* 4567: pointer.SRTP_PROTECTION_PROFILE */
            	0, 0,
            8884097, 8, 0, /* 4572: pointer.func */
            0, 144, 15, /* 4575: struct.x509_store_st */
            	4608, 8,
            	4632, 16,
            	4656, 24,
            	4668, 32,
            	4671, 40,
            	4674, 48,
            	4677, 56,
            	4668, 64,
            	4680, 72,
            	3824, 80,
            	4539, 88,
            	3827, 96,
            	4683, 104,
            	4668, 112,
            	642, 120,
            1, 8, 1, /* 4608: pointer.struct.stack_st_X509_OBJECT */
            	4613, 0,
            0, 32, 2, /* 4613: struct.stack_st_fake_X509_OBJECT */
            	4620, 8,
            	456, 24,
            8884099, 8, 2, /* 4620: pointer_to_array_of_pointers_to_stack */
            	4627, 0,
            	453, 20,
            0, 8, 1, /* 4627: pointer.X509_OBJECT */
            	3158, 0,
            1, 8, 1, /* 4632: pointer.struct.stack_st_X509_LOOKUP */
            	4637, 0,
            0, 32, 2, /* 4637: struct.stack_st_fake_X509_LOOKUP */
            	4644, 8,
            	456, 24,
            8884099, 8, 2, /* 4644: pointer_to_array_of_pointers_to_stack */
            	4651, 0,
            	453, 20,
            0, 8, 1, /* 4651: pointer.X509_LOOKUP */
            	3765, 0,
            1, 8, 1, /* 4656: pointer.struct.X509_VERIFY_PARAM_st */
            	4661, 0,
            0, 56, 2, /* 4661: struct.X509_VERIFY_PARAM_st */
            	61, 0,
            	2101, 48,
            8884097, 8, 0, /* 4668: pointer.func */
            8884097, 8, 0, /* 4671: pointer.func */
            8884097, 8, 0, /* 4674: pointer.func */
            8884097, 8, 0, /* 4677: pointer.func */
            8884097, 8, 0, /* 4680: pointer.func */
            8884097, 8, 0, /* 4683: pointer.func */
            1, 8, 1, /* 4686: pointer.struct.x509_store_st */
            	4575, 0,
            0, 1, 0, /* 4691: char */
            1, 8, 1, /* 4694: pointer.struct.ssl_method_st */
            	4699, 0,
            0, 232, 28, /* 4699: struct.ssl_method_st */
            	3861, 8,
            	4758, 16,
            	4758, 24,
            	3861, 32,
            	3861, 40,
            	4761, 48,
            	4761, 56,
            	4764, 64,
            	3861, 72,
            	3861, 80,
            	3861, 88,
            	4767, 96,
            	4770, 104,
            	4773, 112,
            	3861, 120,
            	4776, 128,
            	4779, 136,
            	4782, 144,
            	4785, 152,
            	4788, 160,
            	4791, 168,
            	4572, 176,
            	4794, 184,
            	2462, 192,
            	4797, 200,
            	4791, 208,
            	4802, 216,
            	4542, 224,
            8884097, 8, 0, /* 4758: pointer.func */
            8884097, 8, 0, /* 4761: pointer.func */
            8884097, 8, 0, /* 4764: pointer.func */
            8884097, 8, 0, /* 4767: pointer.func */
            8884097, 8, 0, /* 4770: pointer.func */
            8884097, 8, 0, /* 4773: pointer.func */
            8884097, 8, 0, /* 4776: pointer.func */
            8884097, 8, 0, /* 4779: pointer.func */
            8884097, 8, 0, /* 4782: pointer.func */
            8884097, 8, 0, /* 4785: pointer.func */
            8884097, 8, 0, /* 4788: pointer.func */
            8884097, 8, 0, /* 4791: pointer.func */
            8884097, 8, 0, /* 4794: pointer.func */
            1, 8, 1, /* 4797: pointer.struct.ssl3_enc_method */
            	3830, 0,
            8884097, 8, 0, /* 4802: pointer.func */
            8884097, 8, 0, /* 4805: pointer.func */
            1, 8, 1, /* 4808: pointer.struct.NAME_CONSTRAINTS_st */
            	4813, 0,
            0, 0, 0, /* 4813: struct.NAME_CONSTRAINTS_st */
            8884097, 8, 0, /* 4816: pointer.func */
            1, 8, 1, /* 4819: pointer.struct.x509_store_st */
            	4575, 0,
            8884097, 8, 0, /* 4824: pointer.func */
            1, 8, 1, /* 4827: pointer.pointer.struct.lhash_node_st */
            	4832, 0,
            1, 8, 1, /* 4832: pointer.struct.lhash_node_st */
            	4837, 0,
            0, 24, 2, /* 4837: struct.lhash_node_st */
            	49, 0,
            	4844, 8,
            1, 8, 1, /* 4844: pointer.struct.lhash_node_st */
            	4837, 0,
            1, 8, 1, /* 4849: pointer.struct.sess_cert_st */
            	4854, 0,
            0, 248, 5, /* 4854: struct.sess_cert_st */
            	4867, 0,
            	123, 16,
            	2367, 216,
            	2375, 224,
            	2380, 232,
            1, 8, 1, /* 4867: pointer.struct.stack_st_X509 */
            	4872, 0,
            0, 32, 2, /* 4872: struct.stack_st_fake_X509 */
            	4879, 8,
            	456, 24,
            8884099, 8, 2, /* 4879: pointer_to_array_of_pointers_to_stack */
            	4886, 0,
            	453, 20,
            0, 8, 1, /* 4886: pointer.X509 */
            	4891, 0,
            0, 0, 1, /* 4891: X509 */
            	4896, 0,
            0, 184, 12, /* 4896: struct.x509_st */
            	4923, 0,
            	3912, 8,
            	4001, 16,
            	61, 32,
            	4282, 40,
            	4006, 104,
            	4928, 112,
            	4936, 120,
            	4941, 128,
            	4965, 136,
            	4808, 144,
            	4989, 176,
            1, 8, 1, /* 4923: pointer.struct.x509_cinf_st */
            	3882, 0,
            1, 8, 1, /* 4928: pointer.struct.AUTHORITY_KEYID_st */
            	4933, 0,
            0, 0, 0, /* 4933: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 4936: pointer.struct.X509_POLICY_CACHE_st */
            	4533, 0,
            1, 8, 1, /* 4941: pointer.struct.stack_st_DIST_POINT */
            	4946, 0,
            0, 32, 2, /* 4946: struct.stack_st_fake_DIST_POINT */
            	4953, 8,
            	456, 24,
            8884099, 8, 2, /* 4953: pointer_to_array_of_pointers_to_stack */
            	4960, 0,
            	453, 20,
            0, 8, 1, /* 4960: pointer.DIST_POINT */
            	1632, 0,
            1, 8, 1, /* 4965: pointer.struct.stack_st_GENERAL_NAME */
            	4970, 0,
            0, 32, 2, /* 4970: struct.stack_st_fake_GENERAL_NAME */
            	4977, 8,
            	456, 24,
            8884099, 8, 2, /* 4977: pointer_to_array_of_pointers_to_stack */
            	4984, 0,
            	453, 20,
            0, 8, 1, /* 4984: pointer.GENERAL_NAME */
            	1330, 0,
            1, 8, 1, /* 4989: pointer.struct.x509_cert_aux_st */
            	4994, 0,
            0, 40, 5, /* 4994: struct.x509_cert_aux_st */
            	5007, 0,
            	5007, 8,
            	3806, 16,
            	4006, 24,
            	5031, 32,
            1, 8, 1, /* 5007: pointer.struct.stack_st_ASN1_OBJECT */
            	5012, 0,
            0, 32, 2, /* 5012: struct.stack_st_fake_ASN1_OBJECT */
            	5019, 8,
            	456, 24,
            8884099, 8, 2, /* 5019: pointer_to_array_of_pointers_to_stack */
            	5026, 0,
            	453, 20,
            0, 8, 1, /* 5026: pointer.ASN1_OBJECT */
            	2125, 0,
            1, 8, 1, /* 5031: pointer.struct.stack_st_X509_ALGOR */
            	5036, 0,
            0, 32, 2, /* 5036: struct.stack_st_fake_X509_ALGOR */
            	5043, 8,
            	456, 24,
            8884099, 8, 2, /* 5043: pointer_to_array_of_pointers_to_stack */
            	5050, 0,
            	453, 20,
            0, 8, 1, /* 5050: pointer.X509_ALGOR */
            	2163, 0,
            1, 8, 1, /* 5055: pointer.struct.ssl_ctx_st */
            	5060, 0,
            0, 736, 50, /* 5060: struct.ssl_ctx_st */
            	4694, 0,
            	5163, 8,
            	5163, 16,
            	4686, 24,
            	5197, 32,
            	5214, 48,
            	5214, 56,
            	3816, 80,
            	5250, 88,
            	2512, 96,
            	4824, 152,
            	49, 160,
            	5253, 168,
            	49, 176,
            	2509, 184,
            	5256, 192,
            	2506, 200,
            	642, 208,
            	2322, 224,
            	2322, 232,
            	2322, 240,
            	4867, 248,
            	2470, 256,
            	2433, 264,
            	5259, 272,
            	2385, 304,
            	3013, 320,
            	49, 328,
            	4671, 376,
            	4805, 384,
            	4656, 392,
            	524, 408,
            	52, 416,
            	49, 424,
            	4545, 480,
            	55, 488,
            	49, 496,
            	97, 504,
            	49, 512,
            	61, 520,
            	94, 528,
            	4816, 536,
            	5283, 552,
            	5283, 560,
            	18, 568,
            	15, 696,
            	49, 704,
            	4536, 712,
            	49, 720,
            	4548, 728,
            1, 8, 1, /* 5163: pointer.struct.stack_st_SSL_CIPHER */
            	5168, 0,
            0, 32, 2, /* 5168: struct.stack_st_fake_SSL_CIPHER */
            	5175, 8,
            	456, 24,
            8884099, 8, 2, /* 5175: pointer_to_array_of_pointers_to_stack */
            	5182, 0,
            	453, 20,
            0, 8, 1, /* 5182: pointer.SSL_CIPHER */
            	5187, 0,
            0, 0, 1, /* 5187: SSL_CIPHER */
            	5192, 0,
            0, 88, 1, /* 5192: struct.ssl_cipher_st */
            	10, 8,
            1, 8, 1, /* 5197: pointer.struct.lhash_st */
            	5202, 0,
            0, 176, 3, /* 5202: struct.lhash_st */
            	4827, 0,
            	456, 8,
            	5211, 16,
            8884097, 8, 0, /* 5211: pointer.func */
            1, 8, 1, /* 5214: pointer.struct.ssl_session_st */
            	5219, 0,
            0, 352, 14, /* 5219: struct.ssl_session_st */
            	61, 144,
            	61, 152,
            	4849, 168,
            	137, 176,
            	2525, 224,
            	5163, 240,
            	642, 248,
            	5214, 264,
            	5214, 272,
            	61, 280,
            	209, 296,
            	209, 312,
            	209, 320,
            	61, 344,
            8884097, 8, 0, /* 5250: pointer.func */
            8884097, 8, 0, /* 5253: pointer.func */
            8884097, 8, 0, /* 5256: pointer.func */
            1, 8, 1, /* 5259: pointer.struct.stack_st_X509_NAME */
            	5264, 0,
            0, 32, 2, /* 5264: struct.stack_st_fake_X509_NAME */
            	5271, 8,
            	456, 24,
            8884099, 8, 2, /* 5271: pointer_to_array_of_pointers_to_stack */
            	5278, 0,
            	453, 20,
            0, 8, 1, /* 5278: pointer.X509_NAME */
            	2520, 0,
            1, 8, 1, /* 5283: pointer.struct.ssl3_buf_freelist_st */
            	5288, 0,
            0, 24, 1, /* 5288: struct.ssl3_buf_freelist_st */
            	84, 16,
        },
        .arg_entity_index = { 5055, },
        .ret_entity_index = 4819,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    const SSL_CTX * new_arg_a = *((const SSL_CTX * *)new_args->args[0]);

    X509_STORE * *new_ret_ptr = (X509_STORE * *)new_args->ret;

    X509_STORE * (*orig_SSL_CTX_get_cert_store)(const SSL_CTX *);
    orig_SSL_CTX_get_cert_store = dlsym(RTLD_NEXT, "SSL_CTX_get_cert_store");
    *new_ret_ptr = (*orig_SSL_CTX_get_cert_store)(new_arg_a);

    syscall(889);

    return ret;
}

