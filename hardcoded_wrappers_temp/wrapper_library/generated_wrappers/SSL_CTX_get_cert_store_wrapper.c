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
            	2101, 48,
            	2106, 56,
            	2109, 64,
            	103, 72,
            	2114, 80,
            	100, 88,
            1, 8, 1, /* 123: pointer.struct.cert_pkey_st */
            	128, 0,
            0, 24, 3, /* 128: struct.cert_pkey_st */
            	137, 0,
            	500, 8,
            	2056, 16,
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
            	1826, 176,
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
            	1462, 8,
            	1462, 16,
            1, 8, 1, /* 1821: pointer.struct.GENERAL_NAME_st */
            	1335, 0,
            1, 8, 1, /* 1826: pointer.struct.x509_cert_aux_st */
            	1831, 0,
            0, 40, 5, /* 1831: struct.x509_cert_aux_st */
            	1844, 0,
            	1844, 8,
            	366, 16,
            	316, 24,
            	1873, 32,
            1, 8, 1, /* 1844: pointer.struct.stack_st_ASN1_OBJECT */
            	1849, 0,
            0, 32, 2, /* 1849: struct.stack_st_fake_ASN1_OBJECT */
            	1856, 8,
            	456, 24,
            8884099, 8, 2, /* 1856: pointer_to_array_of_pointers_to_stack */
            	1863, 0,
            	453, 20,
            0, 8, 1, /* 1863: pointer.ASN1_OBJECT */
            	1868, 0,
            0, 0, 1, /* 1868: ASN1_OBJECT */
            	999, 0,
            1, 8, 1, /* 1873: pointer.struct.stack_st_X509_ALGOR */
            	1878, 0,
            0, 32, 2, /* 1878: struct.stack_st_fake_X509_ALGOR */
            	1885, 8,
            	456, 24,
            8884099, 8, 2, /* 1885: pointer_to_array_of_pointers_to_stack */
            	1892, 0,
            	453, 20,
            0, 8, 1, /* 1892: pointer.X509_ALGOR */
            	1897, 0,
            0, 0, 1, /* 1897: X509_ALGOR */
            	1902, 0,
            0, 16, 2, /* 1902: struct.X509_algor_st */
            	1909, 0,
            	1923, 8,
            1, 8, 1, /* 1909: pointer.struct.asn1_object_st */
            	1914, 0,
            0, 40, 3, /* 1914: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	243, 24,
            1, 8, 1, /* 1923: pointer.struct.asn1_type_st */
            	1928, 0,
            0, 16, 1, /* 1928: struct.asn1_type_st */
            	1933, 8,
            0, 8, 20, /* 1933: union.unknown */
            	61, 0,
            	1976, 0,
            	1909, 0,
            	1986, 0,
            	1991, 0,
            	1996, 0,
            	2001, 0,
            	2006, 0,
            	2011, 0,
            	2016, 0,
            	2021, 0,
            	2026, 0,
            	2031, 0,
            	2036, 0,
            	2041, 0,
            	2046, 0,
            	2051, 0,
            	1976, 0,
            	1976, 0,
            	1219, 0,
            1, 8, 1, /* 1976: pointer.struct.asn1_string_st */
            	1981, 0,
            0, 24, 1, /* 1981: struct.asn1_string_st */
            	209, 8,
            1, 8, 1, /* 1986: pointer.struct.asn1_string_st */
            	1981, 0,
            1, 8, 1, /* 1991: pointer.struct.asn1_string_st */
            	1981, 0,
            1, 8, 1, /* 1996: pointer.struct.asn1_string_st */
            	1981, 0,
            1, 8, 1, /* 2001: pointer.struct.asn1_string_st */
            	1981, 0,
            1, 8, 1, /* 2006: pointer.struct.asn1_string_st */
            	1981, 0,
            1, 8, 1, /* 2011: pointer.struct.asn1_string_st */
            	1981, 0,
            1, 8, 1, /* 2016: pointer.struct.asn1_string_st */
            	1981, 0,
            1, 8, 1, /* 2021: pointer.struct.asn1_string_st */
            	1981, 0,
            1, 8, 1, /* 2026: pointer.struct.asn1_string_st */
            	1981, 0,
            1, 8, 1, /* 2031: pointer.struct.asn1_string_st */
            	1981, 0,
            1, 8, 1, /* 2036: pointer.struct.asn1_string_st */
            	1981, 0,
            1, 8, 1, /* 2041: pointer.struct.asn1_string_st */
            	1981, 0,
            1, 8, 1, /* 2046: pointer.struct.asn1_string_st */
            	1981, 0,
            1, 8, 1, /* 2051: pointer.struct.asn1_string_st */
            	1981, 0,
            1, 8, 1, /* 2056: pointer.struct.env_md_st */
            	2061, 0,
            0, 120, 8, /* 2061: struct.env_md_st */
            	2080, 24,
            	2083, 32,
            	2086, 40,
            	2089, 48,
            	2080, 56,
            	2092, 64,
            	2095, 72,
            	2098, 112,
            8884097, 8, 0, /* 2080: pointer.func */
            8884097, 8, 0, /* 2083: pointer.func */
            8884097, 8, 0, /* 2086: pointer.func */
            8884097, 8, 0, /* 2089: pointer.func */
            8884097, 8, 0, /* 2092: pointer.func */
            8884097, 8, 0, /* 2095: pointer.func */
            8884097, 8, 0, /* 2098: pointer.func */
            1, 8, 1, /* 2101: pointer.struct.rsa_st */
            	550, 0,
            8884097, 8, 0, /* 2106: pointer.func */
            1, 8, 1, /* 2109: pointer.struct.dh_st */
            	777, 0,
            1, 8, 1, /* 2114: pointer.struct.ec_key_st */
            	845, 0,
            1, 8, 1, /* 2119: pointer.struct.cert_st */
            	106, 0,
            0, 24, 1, /* 2124: struct.buf_mem_st */
            	61, 8,
            1, 8, 1, /* 2129: pointer.struct.buf_mem_st */
            	2124, 0,
            8884097, 8, 0, /* 2134: pointer.func */
            8884097, 8, 0, /* 2137: pointer.func */
            8884097, 8, 0, /* 2140: pointer.func */
            0, 64, 7, /* 2143: struct.comp_method_st */
            	10, 8,
            	2160, 16,
            	2140, 24,
            	2137, 32,
            	2137, 40,
            	2163, 48,
            	2163, 56,
            8884097, 8, 0, /* 2160: pointer.func */
            8884097, 8, 0, /* 2163: pointer.func */
            1, 8, 1, /* 2166: pointer.struct.comp_method_st */
            	2143, 0,
            0, 0, 1, /* 2171: SSL_COMP */
            	2176, 0,
            0, 24, 2, /* 2176: struct.ssl_comp_st */
            	10, 8,
            	2166, 16,
            1, 8, 1, /* 2183: pointer.struct.stack_st_SSL_COMP */
            	2188, 0,
            0, 32, 2, /* 2188: struct.stack_st_fake_SSL_COMP */
            	2195, 8,
            	456, 24,
            8884099, 8, 2, /* 2195: pointer_to_array_of_pointers_to_stack */
            	2202, 0,
            	453, 20,
            0, 8, 1, /* 2202: pointer.SSL_COMP */
            	2171, 0,
            8884097, 8, 0, /* 2207: pointer.func */
            0, 40, 3, /* 2210: struct.X509_name_st */
            	2219, 0,
            	2129, 16,
            	209, 24,
            1, 8, 1, /* 2219: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2224, 0,
            0, 32, 2, /* 2224: struct.stack_st_fake_X509_NAME_ENTRY */
            	2231, 8,
            	456, 24,
            8884099, 8, 2, /* 2231: pointer_to_array_of_pointers_to_stack */
            	2238, 0,
            	453, 20,
            0, 8, 1, /* 2238: pointer.X509_NAME_ENTRY */
            	417, 0,
            8884097, 8, 0, /* 2243: pointer.func */
            8884097, 8, 0, /* 2246: pointer.func */
            0, 88, 1, /* 2249: struct.ssl_cipher_st */
            	10, 8,
            8884097, 8, 0, /* 2254: pointer.func */
            1, 8, 1, /* 2257: pointer.struct.X509_crl_st */
            	2262, 0,
            0, 120, 10, /* 2262: struct.X509_crl_st */
            	2285, 0,
            	2319, 8,
            	2408, 16,
            	2653, 32,
            	2661, 40,
            	2309, 56,
            	2309, 64,
            	2669, 96,
            	2710, 104,
            	49, 112,
            1, 8, 1, /* 2285: pointer.struct.X509_crl_info_st */
            	2290, 0,
            0, 80, 8, /* 2290: struct.X509_crl_info_st */
            	2309, 0,
            	2319, 8,
            	2468, 16,
            	2516, 24,
            	2516, 32,
            	2521, 40,
            	2624, 48,
            	2648, 56,
            1, 8, 1, /* 2309: pointer.struct.asn1_string_st */
            	2314, 0,
            0, 24, 1, /* 2314: struct.asn1_string_st */
            	209, 8,
            1, 8, 1, /* 2319: pointer.struct.X509_algor_st */
            	2324, 0,
            0, 16, 2, /* 2324: struct.X509_algor_st */
            	2331, 0,
            	2345, 8,
            1, 8, 1, /* 2331: pointer.struct.asn1_object_st */
            	2336, 0,
            0, 40, 3, /* 2336: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	243, 24,
            1, 8, 1, /* 2345: pointer.struct.asn1_type_st */
            	2350, 0,
            0, 16, 1, /* 2350: struct.asn1_type_st */
            	2355, 8,
            0, 8, 20, /* 2355: union.unknown */
            	61, 0,
            	2398, 0,
            	2331, 0,
            	2309, 0,
            	2403, 0,
            	2408, 0,
            	2413, 0,
            	2418, 0,
            	2423, 0,
            	2428, 0,
            	2433, 0,
            	2438, 0,
            	2443, 0,
            	2448, 0,
            	2453, 0,
            	2458, 0,
            	2463, 0,
            	2398, 0,
            	2398, 0,
            	1219, 0,
            1, 8, 1, /* 2398: pointer.struct.asn1_string_st */
            	2314, 0,
            1, 8, 1, /* 2403: pointer.struct.asn1_string_st */
            	2314, 0,
            1, 8, 1, /* 2408: pointer.struct.asn1_string_st */
            	2314, 0,
            1, 8, 1, /* 2413: pointer.struct.asn1_string_st */
            	2314, 0,
            1, 8, 1, /* 2418: pointer.struct.asn1_string_st */
            	2314, 0,
            1, 8, 1, /* 2423: pointer.struct.asn1_string_st */
            	2314, 0,
            1, 8, 1, /* 2428: pointer.struct.asn1_string_st */
            	2314, 0,
            1, 8, 1, /* 2433: pointer.struct.asn1_string_st */
            	2314, 0,
            1, 8, 1, /* 2438: pointer.struct.asn1_string_st */
            	2314, 0,
            1, 8, 1, /* 2443: pointer.struct.asn1_string_st */
            	2314, 0,
            1, 8, 1, /* 2448: pointer.struct.asn1_string_st */
            	2314, 0,
            1, 8, 1, /* 2453: pointer.struct.asn1_string_st */
            	2314, 0,
            1, 8, 1, /* 2458: pointer.struct.asn1_string_st */
            	2314, 0,
            1, 8, 1, /* 2463: pointer.struct.asn1_string_st */
            	2314, 0,
            1, 8, 1, /* 2468: pointer.struct.X509_name_st */
            	2473, 0,
            0, 40, 3, /* 2473: struct.X509_name_st */
            	2482, 0,
            	2506, 16,
            	209, 24,
            1, 8, 1, /* 2482: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2487, 0,
            0, 32, 2, /* 2487: struct.stack_st_fake_X509_NAME_ENTRY */
            	2494, 8,
            	456, 24,
            8884099, 8, 2, /* 2494: pointer_to_array_of_pointers_to_stack */
            	2501, 0,
            	453, 20,
            0, 8, 1, /* 2501: pointer.X509_NAME_ENTRY */
            	417, 0,
            1, 8, 1, /* 2506: pointer.struct.buf_mem_st */
            	2511, 0,
            0, 24, 1, /* 2511: struct.buf_mem_st */
            	61, 8,
            1, 8, 1, /* 2516: pointer.struct.asn1_string_st */
            	2314, 0,
            1, 8, 1, /* 2521: pointer.struct.stack_st_X509_REVOKED */
            	2526, 0,
            0, 32, 2, /* 2526: struct.stack_st_fake_X509_REVOKED */
            	2533, 8,
            	456, 24,
            8884099, 8, 2, /* 2533: pointer_to_array_of_pointers_to_stack */
            	2540, 0,
            	453, 20,
            0, 8, 1, /* 2540: pointer.X509_REVOKED */
            	2545, 0,
            0, 0, 1, /* 2545: X509_REVOKED */
            	2550, 0,
            0, 40, 4, /* 2550: struct.x509_revoked_st */
            	2561, 0,
            	2571, 8,
            	2576, 16,
            	2600, 24,
            1, 8, 1, /* 2561: pointer.struct.asn1_string_st */
            	2566, 0,
            0, 24, 1, /* 2566: struct.asn1_string_st */
            	209, 8,
            1, 8, 1, /* 2571: pointer.struct.asn1_string_st */
            	2566, 0,
            1, 8, 1, /* 2576: pointer.struct.stack_st_X509_EXTENSION */
            	2581, 0,
            0, 32, 2, /* 2581: struct.stack_st_fake_X509_EXTENSION */
            	2588, 8,
            	456, 24,
            8884099, 8, 2, /* 2588: pointer_to_array_of_pointers_to_stack */
            	2595, 0,
            	453, 20,
            0, 8, 1, /* 2595: pointer.X509_EXTENSION */
            	1251, 0,
            1, 8, 1, /* 2600: pointer.struct.stack_st_GENERAL_NAME */
            	2605, 0,
            0, 32, 2, /* 2605: struct.stack_st_fake_GENERAL_NAME */
            	2612, 8,
            	456, 24,
            8884099, 8, 2, /* 2612: pointer_to_array_of_pointers_to_stack */
            	2619, 0,
            	453, 20,
            0, 8, 1, /* 2619: pointer.GENERAL_NAME */
            	1330, 0,
            1, 8, 1, /* 2624: pointer.struct.stack_st_X509_EXTENSION */
            	2629, 0,
            0, 32, 2, /* 2629: struct.stack_st_fake_X509_EXTENSION */
            	2636, 8,
            	456, 24,
            8884099, 8, 2, /* 2636: pointer_to_array_of_pointers_to_stack */
            	2643, 0,
            	453, 20,
            0, 8, 1, /* 2643: pointer.X509_EXTENSION */
            	1251, 0,
            0, 24, 1, /* 2648: struct.ASN1_ENCODING_st */
            	209, 0,
            1, 8, 1, /* 2653: pointer.struct.AUTHORITY_KEYID_st */
            	2658, 0,
            0, 0, 0, /* 2658: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 2661: pointer.struct.ISSUING_DIST_POINT_st */
            	2666, 0,
            0, 0, 0, /* 2666: struct.ISSUING_DIST_POINT_st */
            1, 8, 1, /* 2669: pointer.struct.stack_st_GENERAL_NAMES */
            	2674, 0,
            0, 32, 2, /* 2674: struct.stack_st_fake_GENERAL_NAMES */
            	2681, 8,
            	456, 24,
            8884099, 8, 2, /* 2681: pointer_to_array_of_pointers_to_stack */
            	2688, 0,
            	453, 20,
            0, 8, 1, /* 2688: pointer.GENERAL_NAMES */
            	2693, 0,
            0, 0, 1, /* 2693: GENERAL_NAMES */
            	2698, 0,
            0, 32, 1, /* 2698: struct.stack_st_GENERAL_NAME */
            	2703, 0,
            0, 32, 2, /* 2703: struct.stack_st */
            	664, 8,
            	456, 24,
            1, 8, 1, /* 2710: pointer.struct.x509_crl_method_st */
            	2715, 0,
            0, 0, 0, /* 2715: struct.x509_crl_method_st */
            0, 0, 1, /* 2718: X509_NAME */
            	2210, 0,
            8884097, 8, 0, /* 2723: pointer.func */
            8884097, 8, 0, /* 2726: pointer.func */
            1, 8, 1, /* 2729: pointer.struct.stack_st_X509_LOOKUP */
            	2734, 0,
            0, 32, 2, /* 2734: struct.stack_st_fake_X509_LOOKUP */
            	2741, 8,
            	456, 24,
            8884099, 8, 2, /* 2741: pointer_to_array_of_pointers_to_stack */
            	2748, 0,
            	453, 20,
            0, 8, 1, /* 2748: pointer.X509_LOOKUP */
            	2753, 0,
            0, 0, 1, /* 2753: X509_LOOKUP */
            	2758, 0,
            0, 32, 3, /* 2758: struct.x509_lookup_st */
            	2767, 8,
            	61, 16,
            	2816, 24,
            1, 8, 1, /* 2767: pointer.struct.x509_lookup_method_st */
            	2772, 0,
            0, 80, 10, /* 2772: struct.x509_lookup_method_st */
            	10, 0,
            	2795, 8,
            	2798, 16,
            	2795, 24,
            	2795, 32,
            	2801, 40,
            	2804, 48,
            	2807, 56,
            	2810, 64,
            	2813, 72,
            8884097, 8, 0, /* 2795: pointer.func */
            8884097, 8, 0, /* 2798: pointer.func */
            8884097, 8, 0, /* 2801: pointer.func */
            8884097, 8, 0, /* 2804: pointer.func */
            8884097, 8, 0, /* 2807: pointer.func */
            8884097, 8, 0, /* 2810: pointer.func */
            8884097, 8, 0, /* 2813: pointer.func */
            1, 8, 1, /* 2816: pointer.struct.x509_store_st */
            	2821, 0,
            0, 144, 15, /* 2821: struct.x509_store_st */
            	2854, 8,
            	2729, 16,
            	3494, 24,
            	3506, 32,
            	3509, 40,
            	3512, 48,
            	3515, 56,
            	3506, 64,
            	2723, 72,
            	3518, 80,
            	3521, 88,
            	2254, 96,
            	3524, 104,
            	3506, 112,
            	3139, 120,
            1, 8, 1, /* 2854: pointer.struct.stack_st_X509_OBJECT */
            	2859, 0,
            0, 32, 2, /* 2859: struct.stack_st_fake_X509_OBJECT */
            	2866, 8,
            	456, 24,
            8884099, 8, 2, /* 2866: pointer_to_array_of_pointers_to_stack */
            	2873, 0,
            	453, 20,
            0, 8, 1, /* 2873: pointer.X509_OBJECT */
            	2878, 0,
            0, 0, 1, /* 2878: X509_OBJECT */
            	2883, 0,
            0, 16, 1, /* 2883: struct.x509_object_st */
            	2888, 8,
            0, 8, 4, /* 2888: union.unknown */
            	61, 0,
            	2899, 0,
            	2257, 0,
            	2987, 0,
            1, 8, 1, /* 2899: pointer.struct.x509_st */
            	2904, 0,
            0, 184, 12, /* 2904: struct.x509_st */
            	2931, 0,
            	2319, 8,
            	2408, 16,
            	61, 32,
            	3139, 40,
            	2413, 104,
            	2653, 112,
            	3364, 120,
            	3372, 128,
            	3396, 136,
            	3420, 144,
            	3428, 176,
            1, 8, 1, /* 2931: pointer.struct.x509_cinf_st */
            	2936, 0,
            0, 104, 11, /* 2936: struct.x509_cinf_st */
            	2309, 0,
            	2309, 8,
            	2319, 16,
            	2468, 24,
            	2961, 32,
            	2468, 40,
            	2973, 48,
            	2408, 56,
            	2408, 64,
            	2624, 72,
            	2648, 80,
            1, 8, 1, /* 2961: pointer.struct.X509_val_st */
            	2966, 0,
            0, 16, 2, /* 2966: struct.X509_val_st */
            	2516, 0,
            	2516, 8,
            1, 8, 1, /* 2973: pointer.struct.X509_pubkey_st */
            	2978, 0,
            0, 24, 3, /* 2978: struct.X509_pubkey_st */
            	2319, 0,
            	2408, 8,
            	2987, 16,
            1, 8, 1, /* 2987: pointer.struct.evp_pkey_st */
            	2992, 0,
            0, 56, 4, /* 2992: struct.evp_pkey_st */
            	3003, 16,
            	3011, 24,
            	3019, 32,
            	3340, 48,
            1, 8, 1, /* 3003: pointer.struct.evp_pkey_asn1_method_st */
            	3008, 0,
            0, 0, 0, /* 3008: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 3011: pointer.struct.engine_st */
            	3016, 0,
            0, 0, 0, /* 3016: struct.engine_st */
            0, 8, 5, /* 3019: union.unknown */
            	61, 0,
            	3032, 0,
            	3183, 0,
            	3264, 0,
            	3332, 0,
            1, 8, 1, /* 3032: pointer.struct.rsa_st */
            	3037, 0,
            0, 168, 17, /* 3037: struct.rsa_st */
            	3074, 16,
            	3011, 24,
            	3129, 32,
            	3129, 40,
            	3129, 48,
            	3129, 56,
            	3129, 64,
            	3129, 72,
            	3129, 80,
            	3129, 88,
            	3139, 96,
            	3161, 120,
            	3161, 128,
            	3161, 136,
            	61, 144,
            	3175, 152,
            	3175, 160,
            1, 8, 1, /* 3074: pointer.struct.rsa_meth_st */
            	3079, 0,
            0, 112, 13, /* 3079: struct.rsa_meth_st */
            	10, 0,
            	3108, 8,
            	3108, 16,
            	3108, 24,
            	3108, 32,
            	3111, 40,
            	3114, 48,
            	3117, 56,
            	3117, 64,
            	61, 80,
            	3120, 88,
            	3123, 96,
            	3126, 104,
            8884097, 8, 0, /* 3108: pointer.func */
            8884097, 8, 0, /* 3111: pointer.func */
            8884097, 8, 0, /* 3114: pointer.func */
            8884097, 8, 0, /* 3117: pointer.func */
            8884097, 8, 0, /* 3120: pointer.func */
            8884097, 8, 0, /* 3123: pointer.func */
            8884097, 8, 0, /* 3126: pointer.func */
            1, 8, 1, /* 3129: pointer.struct.bignum_st */
            	3134, 0,
            0, 24, 1, /* 3134: struct.bignum_st */
            	76, 0,
            0, 16, 1, /* 3139: struct.crypto_ex_data_st */
            	3144, 0,
            1, 8, 1, /* 3144: pointer.struct.stack_st_void */
            	3149, 0,
            0, 32, 1, /* 3149: struct.stack_st_void */
            	3154, 0,
            0, 32, 2, /* 3154: struct.stack_st */
            	664, 8,
            	456, 24,
            1, 8, 1, /* 3161: pointer.struct.bn_mont_ctx_st */
            	3166, 0,
            0, 96, 3, /* 3166: struct.bn_mont_ctx_st */
            	3134, 8,
            	3134, 32,
            	3134, 56,
            1, 8, 1, /* 3175: pointer.struct.bn_blinding_st */
            	3180, 0,
            0, 0, 0, /* 3180: struct.bn_blinding_st */
            1, 8, 1, /* 3183: pointer.struct.dsa_st */
            	3188, 0,
            0, 136, 11, /* 3188: struct.dsa_st */
            	3129, 24,
            	3129, 32,
            	3129, 40,
            	3129, 48,
            	3129, 56,
            	3129, 64,
            	3129, 72,
            	3161, 88,
            	3139, 104,
            	3213, 120,
            	3011, 128,
            1, 8, 1, /* 3213: pointer.struct.dsa_method */
            	3218, 0,
            0, 96, 11, /* 3218: struct.dsa_method */
            	10, 0,
            	3243, 8,
            	3246, 16,
            	3249, 24,
            	3252, 32,
            	3255, 40,
            	3258, 48,
            	3258, 56,
            	61, 72,
            	3261, 80,
            	3258, 88,
            8884097, 8, 0, /* 3243: pointer.func */
            8884097, 8, 0, /* 3246: pointer.func */
            8884097, 8, 0, /* 3249: pointer.func */
            8884097, 8, 0, /* 3252: pointer.func */
            8884097, 8, 0, /* 3255: pointer.func */
            8884097, 8, 0, /* 3258: pointer.func */
            8884097, 8, 0, /* 3261: pointer.func */
            1, 8, 1, /* 3264: pointer.struct.dh_st */
            	3269, 0,
            0, 144, 12, /* 3269: struct.dh_st */
            	3129, 8,
            	3129, 16,
            	3129, 32,
            	3129, 40,
            	3161, 56,
            	3129, 64,
            	3129, 72,
            	209, 80,
            	3129, 96,
            	3139, 112,
            	3296, 128,
            	3011, 136,
            1, 8, 1, /* 3296: pointer.struct.dh_method */
            	3301, 0,
            0, 72, 8, /* 3301: struct.dh_method */
            	10, 0,
            	3320, 8,
            	3323, 16,
            	3326, 24,
            	3320, 32,
            	3320, 40,
            	61, 56,
            	3329, 64,
            8884097, 8, 0, /* 3320: pointer.func */
            8884097, 8, 0, /* 3323: pointer.func */
            8884097, 8, 0, /* 3326: pointer.func */
            8884097, 8, 0, /* 3329: pointer.func */
            1, 8, 1, /* 3332: pointer.struct.ec_key_st */
            	3337, 0,
            0, 0, 0, /* 3337: struct.ec_key_st */
            1, 8, 1, /* 3340: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3345, 0,
            0, 32, 2, /* 3345: struct.stack_st_fake_X509_ATTRIBUTE */
            	3352, 8,
            	456, 24,
            8884099, 8, 2, /* 3352: pointer_to_array_of_pointers_to_stack */
            	3359, 0,
            	453, 20,
            0, 8, 1, /* 3359: pointer.X509_ATTRIBUTE */
            	872, 0,
            1, 8, 1, /* 3364: pointer.struct.X509_POLICY_CACHE_st */
            	3369, 0,
            0, 0, 0, /* 3369: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 3372: pointer.struct.stack_st_DIST_POINT */
            	3377, 0,
            0, 32, 2, /* 3377: struct.stack_st_fake_DIST_POINT */
            	3384, 8,
            	456, 24,
            8884099, 8, 2, /* 3384: pointer_to_array_of_pointers_to_stack */
            	3391, 0,
            	453, 20,
            0, 8, 1, /* 3391: pointer.DIST_POINT */
            	1632, 0,
            1, 8, 1, /* 3396: pointer.struct.stack_st_GENERAL_NAME */
            	3401, 0,
            0, 32, 2, /* 3401: struct.stack_st_fake_GENERAL_NAME */
            	3408, 8,
            	456, 24,
            8884099, 8, 2, /* 3408: pointer_to_array_of_pointers_to_stack */
            	3415, 0,
            	453, 20,
            0, 8, 1, /* 3415: pointer.GENERAL_NAME */
            	1330, 0,
            1, 8, 1, /* 3420: pointer.struct.NAME_CONSTRAINTS_st */
            	3425, 0,
            0, 0, 0, /* 3425: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 3428: pointer.struct.x509_cert_aux_st */
            	3433, 0,
            0, 40, 5, /* 3433: struct.x509_cert_aux_st */
            	3446, 0,
            	3446, 8,
            	2463, 16,
            	2413, 24,
            	3470, 32,
            1, 8, 1, /* 3446: pointer.struct.stack_st_ASN1_OBJECT */
            	3451, 0,
            0, 32, 2, /* 3451: struct.stack_st_fake_ASN1_OBJECT */
            	3458, 8,
            	456, 24,
            8884099, 8, 2, /* 3458: pointer_to_array_of_pointers_to_stack */
            	3465, 0,
            	453, 20,
            0, 8, 1, /* 3465: pointer.ASN1_OBJECT */
            	1868, 0,
            1, 8, 1, /* 3470: pointer.struct.stack_st_X509_ALGOR */
            	3475, 0,
            0, 32, 2, /* 3475: struct.stack_st_fake_X509_ALGOR */
            	3482, 8,
            	456, 24,
            8884099, 8, 2, /* 3482: pointer_to_array_of_pointers_to_stack */
            	3489, 0,
            	453, 20,
            0, 8, 1, /* 3489: pointer.X509_ALGOR */
            	1897, 0,
            1, 8, 1, /* 3494: pointer.struct.X509_VERIFY_PARAM_st */
            	3499, 0,
            0, 56, 2, /* 3499: struct.X509_VERIFY_PARAM_st */
            	61, 0,
            	3446, 48,
            8884097, 8, 0, /* 3506: pointer.func */
            8884097, 8, 0, /* 3509: pointer.func */
            8884097, 8, 0, /* 3512: pointer.func */
            8884097, 8, 0, /* 3515: pointer.func */
            8884097, 8, 0, /* 3518: pointer.func */
            8884097, 8, 0, /* 3521: pointer.func */
            8884097, 8, 0, /* 3524: pointer.func */
            1, 8, 1, /* 3527: pointer.struct.asn1_string_st */
            	3532, 0,
            0, 24, 1, /* 3532: struct.asn1_string_st */
            	209, 8,
            1, 8, 1, /* 3537: pointer.struct.ASN1_VALUE_st */
            	3542, 0,
            0, 0, 0, /* 3542: struct.ASN1_VALUE_st */
            1, 8, 1, /* 3545: pointer.struct.ssl_cipher_st */
            	2249, 0,
            1, 8, 1, /* 3550: pointer.struct.asn1_string_st */
            	3532, 0,
            8884097, 8, 0, /* 3555: pointer.func */
            0, 144, 12, /* 3558: struct.dh_st */
            	3585, 8,
            	3585, 16,
            	3585, 32,
            	3585, 40,
            	3595, 56,
            	3585, 64,
            	3585, 72,
            	209, 80,
            	3585, 96,
            	3609, 112,
            	3631, 128,
            	3667, 136,
            1, 8, 1, /* 3585: pointer.struct.bignum_st */
            	3590, 0,
            0, 24, 1, /* 3590: struct.bignum_st */
            	76, 0,
            1, 8, 1, /* 3595: pointer.struct.bn_mont_ctx_st */
            	3600, 0,
            0, 96, 3, /* 3600: struct.bn_mont_ctx_st */
            	3590, 8,
            	3590, 32,
            	3590, 56,
            0, 16, 1, /* 3609: struct.crypto_ex_data_st */
            	3614, 0,
            1, 8, 1, /* 3614: pointer.struct.stack_st_void */
            	3619, 0,
            0, 32, 1, /* 3619: struct.stack_st_void */
            	3624, 0,
            0, 32, 2, /* 3624: struct.stack_st */
            	664, 8,
            	456, 24,
            1, 8, 1, /* 3631: pointer.struct.dh_method */
            	3636, 0,
            0, 72, 8, /* 3636: struct.dh_method */
            	10, 0,
            	3655, 8,
            	3658, 16,
            	3661, 24,
            	3655, 32,
            	3655, 40,
            	61, 56,
            	3664, 64,
            8884097, 8, 0, /* 3655: pointer.func */
            8884097, 8, 0, /* 3658: pointer.func */
            8884097, 8, 0, /* 3661: pointer.func */
            8884097, 8, 0, /* 3664: pointer.func */
            1, 8, 1, /* 3667: pointer.struct.engine_st */
            	3672, 0,
            0, 0, 0, /* 3672: struct.engine_st */
            8884097, 8, 0, /* 3675: pointer.func */
            0, 112, 11, /* 3678: struct.ssl3_enc_method */
            	3703, 0,
            	3706, 8,
            	3709, 16,
            	3712, 24,
            	3703, 32,
            	3715, 40,
            	3718, 56,
            	10, 64,
            	10, 80,
            	3721, 96,
            	3724, 104,
            8884097, 8, 0, /* 3703: pointer.func */
            8884097, 8, 0, /* 3706: pointer.func */
            8884097, 8, 0, /* 3709: pointer.func */
            8884097, 8, 0, /* 3712: pointer.func */
            8884097, 8, 0, /* 3715: pointer.func */
            8884097, 8, 0, /* 3718: pointer.func */
            8884097, 8, 0, /* 3721: pointer.func */
            8884097, 8, 0, /* 3724: pointer.func */
            8884097, 8, 0, /* 3727: pointer.func */
            8884097, 8, 0, /* 3730: pointer.func */
            0, 104, 11, /* 3733: struct.x509_cinf_st */
            	3758, 0,
            	3758, 8,
            	3763, 16,
            	3902, 24,
            	3950, 32,
            	3902, 40,
            	3967, 48,
            	3852, 56,
            	3852, 64,
            	4238, 72,
            	4262, 80,
            1, 8, 1, /* 3758: pointer.struct.asn1_string_st */
            	3532, 0,
            1, 8, 1, /* 3763: pointer.struct.X509_algor_st */
            	3768, 0,
            0, 16, 2, /* 3768: struct.X509_algor_st */
            	3775, 0,
            	3789, 8,
            1, 8, 1, /* 3775: pointer.struct.asn1_object_st */
            	3780, 0,
            0, 40, 3, /* 3780: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	243, 24,
            1, 8, 1, /* 3789: pointer.struct.asn1_type_st */
            	3794, 0,
            0, 16, 1, /* 3794: struct.asn1_type_st */
            	3799, 8,
            0, 8, 20, /* 3799: union.unknown */
            	61, 0,
            	3842, 0,
            	3775, 0,
            	3758, 0,
            	3847, 0,
            	3852, 0,
            	3857, 0,
            	3862, 0,
            	3867, 0,
            	3872, 0,
            	3877, 0,
            	3882, 0,
            	3887, 0,
            	3892, 0,
            	3897, 0,
            	3527, 0,
            	3550, 0,
            	3842, 0,
            	3842, 0,
            	3537, 0,
            1, 8, 1, /* 3842: pointer.struct.asn1_string_st */
            	3532, 0,
            1, 8, 1, /* 3847: pointer.struct.asn1_string_st */
            	3532, 0,
            1, 8, 1, /* 3852: pointer.struct.asn1_string_st */
            	3532, 0,
            1, 8, 1, /* 3857: pointer.struct.asn1_string_st */
            	3532, 0,
            1, 8, 1, /* 3862: pointer.struct.asn1_string_st */
            	3532, 0,
            1, 8, 1, /* 3867: pointer.struct.asn1_string_st */
            	3532, 0,
            1, 8, 1, /* 3872: pointer.struct.asn1_string_st */
            	3532, 0,
            1, 8, 1, /* 3877: pointer.struct.asn1_string_st */
            	3532, 0,
            1, 8, 1, /* 3882: pointer.struct.asn1_string_st */
            	3532, 0,
            1, 8, 1, /* 3887: pointer.struct.asn1_string_st */
            	3532, 0,
            1, 8, 1, /* 3892: pointer.struct.asn1_string_st */
            	3532, 0,
            1, 8, 1, /* 3897: pointer.struct.asn1_string_st */
            	3532, 0,
            1, 8, 1, /* 3902: pointer.struct.X509_name_st */
            	3907, 0,
            0, 40, 3, /* 3907: struct.X509_name_st */
            	3916, 0,
            	3940, 16,
            	209, 24,
            1, 8, 1, /* 3916: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3921, 0,
            0, 32, 2, /* 3921: struct.stack_st_fake_X509_NAME_ENTRY */
            	3928, 8,
            	456, 24,
            8884099, 8, 2, /* 3928: pointer_to_array_of_pointers_to_stack */
            	3935, 0,
            	453, 20,
            0, 8, 1, /* 3935: pointer.X509_NAME_ENTRY */
            	417, 0,
            1, 8, 1, /* 3940: pointer.struct.buf_mem_st */
            	3945, 0,
            0, 24, 1, /* 3945: struct.buf_mem_st */
            	61, 8,
            1, 8, 1, /* 3950: pointer.struct.X509_val_st */
            	3955, 0,
            0, 16, 2, /* 3955: struct.X509_val_st */
            	3962, 0,
            	3962, 8,
            1, 8, 1, /* 3962: pointer.struct.asn1_string_st */
            	3532, 0,
            1, 8, 1, /* 3967: pointer.struct.X509_pubkey_st */
            	3972, 0,
            0, 24, 3, /* 3972: struct.X509_pubkey_st */
            	3763, 0,
            	3852, 8,
            	3981, 16,
            1, 8, 1, /* 3981: pointer.struct.evp_pkey_st */
            	3986, 0,
            0, 56, 4, /* 3986: struct.evp_pkey_st */
            	3997, 16,
            	3667, 24,
            	4005, 32,
            	4214, 48,
            1, 8, 1, /* 3997: pointer.struct.evp_pkey_asn1_method_st */
            	4002, 0,
            0, 0, 0, /* 4002: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 4005: union.unknown */
            	61, 0,
            	4018, 0,
            	4123, 0,
            	4201, 0,
            	4206, 0,
            1, 8, 1, /* 4018: pointer.struct.rsa_st */
            	4023, 0,
            0, 168, 17, /* 4023: struct.rsa_st */
            	4060, 16,
            	3667, 24,
            	3585, 32,
            	3585, 40,
            	3585, 48,
            	3585, 56,
            	3585, 64,
            	3585, 72,
            	3585, 80,
            	3585, 88,
            	3609, 96,
            	3595, 120,
            	3595, 128,
            	3595, 136,
            	61, 144,
            	4115, 152,
            	4115, 160,
            1, 8, 1, /* 4060: pointer.struct.rsa_meth_st */
            	4065, 0,
            0, 112, 13, /* 4065: struct.rsa_meth_st */
            	10, 0,
            	4094, 8,
            	4094, 16,
            	4094, 24,
            	4094, 32,
            	4097, 40,
            	4100, 48,
            	4103, 56,
            	4103, 64,
            	61, 80,
            	4106, 88,
            	4109, 96,
            	4112, 104,
            8884097, 8, 0, /* 4094: pointer.func */
            8884097, 8, 0, /* 4097: pointer.func */
            8884097, 8, 0, /* 4100: pointer.func */
            8884097, 8, 0, /* 4103: pointer.func */
            8884097, 8, 0, /* 4106: pointer.func */
            8884097, 8, 0, /* 4109: pointer.func */
            8884097, 8, 0, /* 4112: pointer.func */
            1, 8, 1, /* 4115: pointer.struct.bn_blinding_st */
            	4120, 0,
            0, 0, 0, /* 4120: struct.bn_blinding_st */
            1, 8, 1, /* 4123: pointer.struct.dsa_st */
            	4128, 0,
            0, 136, 11, /* 4128: struct.dsa_st */
            	3585, 24,
            	3585, 32,
            	3585, 40,
            	3585, 48,
            	3585, 56,
            	3585, 64,
            	3585, 72,
            	3595, 88,
            	3609, 104,
            	4153, 120,
            	3667, 128,
            1, 8, 1, /* 4153: pointer.struct.dsa_method */
            	4158, 0,
            0, 96, 11, /* 4158: struct.dsa_method */
            	10, 0,
            	4183, 8,
            	4186, 16,
            	4189, 24,
            	3727, 32,
            	4192, 40,
            	4195, 48,
            	4195, 56,
            	61, 72,
            	4198, 80,
            	4195, 88,
            8884097, 8, 0, /* 4183: pointer.func */
            8884097, 8, 0, /* 4186: pointer.func */
            8884097, 8, 0, /* 4189: pointer.func */
            8884097, 8, 0, /* 4192: pointer.func */
            8884097, 8, 0, /* 4195: pointer.func */
            8884097, 8, 0, /* 4198: pointer.func */
            1, 8, 1, /* 4201: pointer.struct.dh_st */
            	3558, 0,
            1, 8, 1, /* 4206: pointer.struct.ec_key_st */
            	4211, 0,
            0, 0, 0, /* 4211: struct.ec_key_st */
            1, 8, 1, /* 4214: pointer.struct.stack_st_X509_ATTRIBUTE */
            	4219, 0,
            0, 32, 2, /* 4219: struct.stack_st_fake_X509_ATTRIBUTE */
            	4226, 8,
            	456, 24,
            8884099, 8, 2, /* 4226: pointer_to_array_of_pointers_to_stack */
            	4233, 0,
            	453, 20,
            0, 8, 1, /* 4233: pointer.X509_ATTRIBUTE */
            	872, 0,
            1, 8, 1, /* 4238: pointer.struct.stack_st_X509_EXTENSION */
            	4243, 0,
            0, 32, 2, /* 4243: struct.stack_st_fake_X509_EXTENSION */
            	4250, 8,
            	456, 24,
            8884099, 8, 2, /* 4250: pointer_to_array_of_pointers_to_stack */
            	4257, 0,
            	453, 20,
            0, 8, 1, /* 4257: pointer.X509_EXTENSION */
            	1251, 0,
            0, 24, 1, /* 4262: struct.ASN1_ENCODING_st */
            	209, 0,
            0, 0, 0, /* 4267: struct.X509_POLICY_CACHE_st */
            8884097, 8, 0, /* 4270: pointer.func */
            0, 184, 12, /* 4273: struct.x509_st */
            	4300, 0,
            	3763, 8,
            	3852, 16,
            	61, 32,
            	3609, 40,
            	3857, 104,
            	4305, 112,
            	4313, 120,
            	4318, 128,
            	4342, 136,
            	4366, 144,
            	4374, 176,
            1, 8, 1, /* 4300: pointer.struct.x509_cinf_st */
            	3733, 0,
            1, 8, 1, /* 4305: pointer.struct.AUTHORITY_KEYID_st */
            	4310, 0,
            0, 0, 0, /* 4310: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 4313: pointer.struct.X509_POLICY_CACHE_st */
            	4267, 0,
            1, 8, 1, /* 4318: pointer.struct.stack_st_DIST_POINT */
            	4323, 0,
            0, 32, 2, /* 4323: struct.stack_st_fake_DIST_POINT */
            	4330, 8,
            	456, 24,
            8884099, 8, 2, /* 4330: pointer_to_array_of_pointers_to_stack */
            	4337, 0,
            	453, 20,
            0, 8, 1, /* 4337: pointer.DIST_POINT */
            	1632, 0,
            1, 8, 1, /* 4342: pointer.struct.stack_st_GENERAL_NAME */
            	4347, 0,
            0, 32, 2, /* 4347: struct.stack_st_fake_GENERAL_NAME */
            	4354, 8,
            	456, 24,
            8884099, 8, 2, /* 4354: pointer_to_array_of_pointers_to_stack */
            	4361, 0,
            	453, 20,
            0, 8, 1, /* 4361: pointer.GENERAL_NAME */
            	1330, 0,
            1, 8, 1, /* 4366: pointer.struct.NAME_CONSTRAINTS_st */
            	4371, 0,
            0, 0, 0, /* 4371: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 4374: pointer.struct.x509_cert_aux_st */
            	4379, 0,
            0, 40, 5, /* 4379: struct.x509_cert_aux_st */
            	4392, 0,
            	4392, 8,
            	3550, 16,
            	3857, 24,
            	4416, 32,
            1, 8, 1, /* 4392: pointer.struct.stack_st_ASN1_OBJECT */
            	4397, 0,
            0, 32, 2, /* 4397: struct.stack_st_fake_ASN1_OBJECT */
            	4404, 8,
            	456, 24,
            8884099, 8, 2, /* 4404: pointer_to_array_of_pointers_to_stack */
            	4411, 0,
            	453, 20,
            0, 8, 1, /* 4411: pointer.ASN1_OBJECT */
            	1868, 0,
            1, 8, 1, /* 4416: pointer.struct.stack_st_X509_ALGOR */
            	4421, 0,
            0, 32, 2, /* 4421: struct.stack_st_fake_X509_ALGOR */
            	4428, 8,
            	456, 24,
            8884099, 8, 2, /* 4428: pointer_to_array_of_pointers_to_stack */
            	4435, 0,
            	453, 20,
            0, 8, 1, /* 4435: pointer.X509_ALGOR */
            	1897, 0,
            8884097, 8, 0, /* 4440: pointer.func */
            8884097, 8, 0, /* 4443: pointer.func */
            1, 8, 1, /* 4446: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	4451, 0,
            0, 32, 2, /* 4451: struct.stack_st_fake_SRTP_PROTECTION_PROFILE */
            	4458, 8,
            	456, 24,
            8884099, 8, 2, /* 4458: pointer_to_array_of_pointers_to_stack */
            	4465, 0,
            	453, 20,
            0, 8, 1, /* 4465: pointer.SRTP_PROTECTION_PROFILE */
            	0, 0,
            8884097, 8, 0, /* 4470: pointer.func */
            8884097, 8, 0, /* 4473: pointer.func */
            0, 144, 15, /* 4476: struct.x509_store_st */
            	4509, 8,
            	4533, 16,
            	4557, 24,
            	4569, 32,
            	4572, 40,
            	4575, 48,
            	4578, 56,
            	4569, 64,
            	4581, 72,
            	4584, 80,
            	4587, 88,
            	3675, 96,
            	4590, 104,
            	4569, 112,
            	642, 120,
            1, 8, 1, /* 4509: pointer.struct.stack_st_X509_OBJECT */
            	4514, 0,
            0, 32, 2, /* 4514: struct.stack_st_fake_X509_OBJECT */
            	4521, 8,
            	456, 24,
            8884099, 8, 2, /* 4521: pointer_to_array_of_pointers_to_stack */
            	4528, 0,
            	453, 20,
            0, 8, 1, /* 4528: pointer.X509_OBJECT */
            	2878, 0,
            1, 8, 1, /* 4533: pointer.struct.stack_st_X509_LOOKUP */
            	4538, 0,
            0, 32, 2, /* 4538: struct.stack_st_fake_X509_LOOKUP */
            	4545, 8,
            	456, 24,
            8884099, 8, 2, /* 4545: pointer_to_array_of_pointers_to_stack */
            	4552, 0,
            	453, 20,
            0, 8, 1, /* 4552: pointer.X509_LOOKUP */
            	2753, 0,
            1, 8, 1, /* 4557: pointer.struct.X509_VERIFY_PARAM_st */
            	4562, 0,
            0, 56, 2, /* 4562: struct.X509_VERIFY_PARAM_st */
            	61, 0,
            	1844, 48,
            8884097, 8, 0, /* 4569: pointer.func */
            8884097, 8, 0, /* 4572: pointer.func */
            8884097, 8, 0, /* 4575: pointer.func */
            8884097, 8, 0, /* 4578: pointer.func */
            8884097, 8, 0, /* 4581: pointer.func */
            8884097, 8, 0, /* 4584: pointer.func */
            8884097, 8, 0, /* 4587: pointer.func */
            8884097, 8, 0, /* 4590: pointer.func */
            1, 8, 1, /* 4593: pointer.struct.x509_store_st */
            	4476, 0,
            1, 8, 1, /* 4598: pointer.struct.ssl_method_st */
            	4603, 0,
            0, 232, 28, /* 4603: struct.ssl_method_st */
            	3709, 8,
            	4662, 16,
            	4662, 24,
            	3709, 32,
            	3709, 40,
            	4473, 48,
            	4473, 56,
            	4665, 64,
            	3709, 72,
            	3709, 80,
            	3709, 88,
            	4668, 96,
            	4671, 104,
            	4674, 112,
            	3709, 120,
            	4677, 128,
            	4680, 136,
            	4683, 144,
            	4686, 152,
            	4689, 160,
            	4692, 168,
            	4470, 176,
            	4695, 184,
            	2163, 192,
            	4698, 200,
            	4692, 208,
            	4703, 216,
            	4440, 224,
            8884097, 8, 0, /* 4662: pointer.func */
            8884097, 8, 0, /* 4665: pointer.func */
            8884097, 8, 0, /* 4668: pointer.func */
            8884097, 8, 0, /* 4671: pointer.func */
            8884097, 8, 0, /* 4674: pointer.func */
            8884097, 8, 0, /* 4677: pointer.func */
            8884097, 8, 0, /* 4680: pointer.func */
            8884097, 8, 0, /* 4683: pointer.func */
            8884097, 8, 0, /* 4686: pointer.func */
            8884097, 8, 0, /* 4689: pointer.func */
            8884097, 8, 0, /* 4692: pointer.func */
            8884097, 8, 0, /* 4695: pointer.func */
            1, 8, 1, /* 4698: pointer.struct.ssl3_enc_method */
            	3678, 0,
            8884097, 8, 0, /* 4703: pointer.func */
            0, 1, 0, /* 4706: char */
            8884097, 8, 0, /* 4709: pointer.func */
            8884097, 8, 0, /* 4712: pointer.func */
            1, 8, 1, /* 4715: pointer.struct.x509_store_st */
            	4476, 0,
            8884097, 8, 0, /* 4720: pointer.func */
            1, 8, 1, /* 4723: pointer.struct.sess_cert_st */
            	4728, 0,
            0, 248, 5, /* 4728: struct.sess_cert_st */
            	4741, 0,
            	123, 16,
            	2101, 216,
            	2109, 224,
            	2114, 232,
            1, 8, 1, /* 4741: pointer.struct.stack_st_X509 */
            	4746, 0,
            0, 32, 2, /* 4746: struct.stack_st_fake_X509 */
            	4753, 8,
            	456, 24,
            8884099, 8, 2, /* 4753: pointer_to_array_of_pointers_to_stack */
            	4760, 0,
            	453, 20,
            0, 8, 1, /* 4760: pointer.X509 */
            	4765, 0,
            0, 0, 1, /* 4765: X509 */
            	4273, 0,
            1, 8, 1, /* 4770: pointer.struct.ssl_ctx_st */
            	4775, 0,
            0, 736, 50, /* 4775: struct.ssl_ctx_st */
            	4598, 0,
            	4878, 8,
            	4878, 16,
            	4593, 24,
            	4912, 32,
            	4945, 48,
            	4945, 56,
            	2726, 80,
            	4981, 88,
            	2246, 96,
            	4720, 152,
            	49, 160,
            	4984, 168,
            	49, 176,
            	2243, 184,
            	4987, 192,
            	2207, 200,
            	642, 208,
            	2056, 224,
            	2056, 232,
            	2056, 240,
            	4741, 248,
            	2183, 256,
            	2134, 264,
            	4990, 272,
            	2119, 304,
            	3555, 320,
            	49, 328,
            	4572, 376,
            	4709, 384,
            	4557, 392,
            	524, 408,
            	52, 416,
            	49, 424,
            	4443, 480,
            	55, 488,
            	49, 496,
            	97, 504,
            	49, 512,
            	61, 520,
            	94, 528,
            	4712, 536,
            	5014, 552,
            	5014, 560,
            	18, 568,
            	15, 696,
            	49, 704,
            	4270, 712,
            	49, 720,
            	4446, 728,
            1, 8, 1, /* 4878: pointer.struct.stack_st_SSL_CIPHER */
            	4883, 0,
            0, 32, 2, /* 4883: struct.stack_st_fake_SSL_CIPHER */
            	4890, 8,
            	456, 24,
            8884099, 8, 2, /* 4890: pointer_to_array_of_pointers_to_stack */
            	4897, 0,
            	453, 20,
            0, 8, 1, /* 4897: pointer.SSL_CIPHER */
            	4902, 0,
            0, 0, 1, /* 4902: SSL_CIPHER */
            	4907, 0,
            0, 88, 1, /* 4907: struct.ssl_cipher_st */
            	10, 8,
            1, 8, 1, /* 4912: pointer.struct.lhash_st */
            	4917, 0,
            0, 176, 3, /* 4917: struct.lhash_st */
            	4926, 0,
            	456, 8,
            	3730, 16,
            8884099, 8, 2, /* 4926: pointer_to_array_of_pointers_to_stack */
            	4933, 0,
            	81, 28,
            1, 8, 1, /* 4933: pointer.struct.lhash_node_st */
            	4938, 0,
            0, 24, 2, /* 4938: struct.lhash_node_st */
            	49, 0,
            	4933, 8,
            1, 8, 1, /* 4945: pointer.struct.ssl_session_st */
            	4950, 0,
            0, 352, 14, /* 4950: struct.ssl_session_st */
            	61, 144,
            	61, 152,
            	4723, 168,
            	137, 176,
            	3545, 224,
            	4878, 240,
            	642, 248,
            	4945, 264,
            	4945, 272,
            	61, 280,
            	209, 296,
            	209, 312,
            	209, 320,
            	61, 344,
            8884097, 8, 0, /* 4981: pointer.func */
            8884097, 8, 0, /* 4984: pointer.func */
            8884097, 8, 0, /* 4987: pointer.func */
            1, 8, 1, /* 4990: pointer.struct.stack_st_X509_NAME */
            	4995, 0,
            0, 32, 2, /* 4995: struct.stack_st_fake_X509_NAME */
            	5002, 8,
            	456, 24,
            8884099, 8, 2, /* 5002: pointer_to_array_of_pointers_to_stack */
            	5009, 0,
            	453, 20,
            0, 8, 1, /* 5009: pointer.X509_NAME */
            	2718, 0,
            1, 8, 1, /* 5014: pointer.struct.ssl3_buf_freelist_st */
            	5019, 0,
            0, 24, 1, /* 5019: struct.ssl3_buf_freelist_st */
            	84, 16,
        },
        .arg_entity_index = { 4770, },
        .ret_entity_index = 4715,
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

