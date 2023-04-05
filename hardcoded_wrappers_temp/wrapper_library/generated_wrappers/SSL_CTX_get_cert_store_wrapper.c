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
            	64096, 0,
            64097, 8, 0, /* 15: pointer.func */
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
            64097, 8, 0, /* 52: pointer.func */
            64097, 8, 0, /* 55: pointer.func */
            64097, 8, 0, /* 58: pointer.func */
            1, 8, 1, /* 61: pointer.char */
            	64096, 0,
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
            64097, 8, 0, /* 94: pointer.func */
            64097, 8, 0, /* 97: pointer.func */
            64097, 8, 0, /* 100: pointer.func */
            64097, 8, 0, /* 103: pointer.func */
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
            64099, 8, 2, /* 405: pointer_to_array_of_pointers_to_stack */
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
            64097, 8, 0, /* 456: pointer.func */
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
            64097, 8, 0, /* 621: pointer.func */
            64097, 8, 0, /* 624: pointer.func */
            64097, 8, 0, /* 627: pointer.func */
            64097, 8, 0, /* 630: pointer.func */
            64097, 8, 0, /* 633: pointer.func */
            64097, 8, 0, /* 636: pointer.func */
            64097, 8, 0, /* 639: pointer.func */
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
            64097, 8, 0, /* 751: pointer.func */
            64097, 8, 0, /* 754: pointer.func */
            64097, 8, 0, /* 757: pointer.func */
            64097, 8, 0, /* 760: pointer.func */
            64097, 8, 0, /* 763: pointer.func */
            64097, 8, 0, /* 766: pointer.func */
            64097, 8, 0, /* 769: pointer.func */
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
            64097, 8, 0, /* 828: pointer.func */
            64097, 8, 0, /* 831: pointer.func */
            64097, 8, 0, /* 834: pointer.func */
            64097, 8, 0, /* 837: pointer.func */
            1, 8, 1, /* 840: pointer.struct.ec_key_st */
            	845, 0,
            0, 0, 0, /* 845: struct.ec_key_st */
            1, 8, 1, /* 848: pointer.struct.stack_st_X509_ATTRIBUTE */
            	853, 0,
            0, 32, 2, /* 853: struct.stack_st_fake_X509_ATTRIBUTE */
            	860, 8,
            	456, 24,
            64099, 8, 2, /* 860: pointer_to_array_of_pointers_to_stack */
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
            64099, 8, 2, /* 919: pointer_to_array_of_pointers_to_stack */
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
            64099, 8, 2, /* 1239: pointer_to_array_of_pointers_to_stack */
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
            64099, 8, 2, /* 1318: pointer_to_array_of_pointers_to_stack */
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
            64099, 8, 2, /* 1566: pointer_to_array_of_pointers_to_stack */
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
            64099, 8, 2, /* 1620: pointer_to_array_of_pointers_to_stack */
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
            64099, 8, 2, /* 1677: pointer_to_array_of_pointers_to_stack */
            	1684, 0,
            	453, 20,
            0, 8, 1, /* 1684: pointer.GENERAL_NAME */
            	1330, 0,
            1, 8, 1, /* 1689: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1694, 0,
            0, 32, 2, /* 1694: struct.stack_st_fake_X509_NAME_ENTRY */
            	1701, 8,
            	456, 24,
            64099, 8, 2, /* 1701: pointer_to_array_of_pointers_to_stack */
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
            64099, 8, 2, /* 1759: pointer_to_array_of_pointers_to_stack */
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
            64099, 8, 2, /* 1795: pointer_to_array_of_pointers_to_stack */
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
            64099, 8, 2, /* 2049: pointer_to_array_of_pointers_to_stack */
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
            64099, 8, 2, /* 2113: pointer_to_array_of_pointers_to_stack */
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
            64099, 8, 2, /* 2151: pointer_to_array_of_pointers_to_stack */
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
            64097, 8, 0, /* 2346: pointer.func */
            64097, 8, 0, /* 2349: pointer.func */
            64097, 8, 0, /* 2352: pointer.func */
            64097, 8, 0, /* 2355: pointer.func */
            64097, 8, 0, /* 2358: pointer.func */
            64097, 8, 0, /* 2361: pointer.func */
            64097, 8, 0, /* 2364: pointer.func */
            1, 8, 1, /* 2367: pointer.struct.rsa_st */
            	550, 0,
            64097, 8, 0, /* 2372: pointer.func */
            1, 8, 1, /* 2375: pointer.struct.dh_st */
            	777, 0,
            1, 8, 1, /* 2380: pointer.struct.ec_key_st */
            	845, 0,
            0, 40, 3, /* 2385: struct.X509_name_st */
            	2394, 0,
            	2418, 16,
            	209, 24,
            1, 8, 1, /* 2394: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2399, 0,
            0, 32, 2, /* 2399: struct.stack_st_fake_X509_NAME_ENTRY */
            	2406, 8,
            	456, 24,
            64099, 8, 2, /* 2406: pointer_to_array_of_pointers_to_stack */
            	2413, 0,
            	453, 20,
            0, 8, 1, /* 2413: pointer.X509_NAME_ENTRY */
            	417, 0,
            1, 8, 1, /* 2418: pointer.struct.buf_mem_st */
            	2423, 0,
            0, 24, 1, /* 2423: struct.buf_mem_st */
            	61, 8,
            64097, 8, 0, /* 2428: pointer.func */
            64097, 8, 0, /* 2431: pointer.func */
            64097, 8, 0, /* 2434: pointer.func */
            0, 24, 2, /* 2437: struct.ssl_comp_st */
            	10, 8,
            	2444, 16,
            1, 8, 1, /* 2444: pointer.struct.comp_method_st */
            	2449, 0,
            0, 64, 7, /* 2449: struct.comp_method_st */
            	10, 8,
            	2434, 16,
            	2466, 24,
            	2431, 32,
            	2431, 40,
            	2469, 48,
            	2469, 56,
            64097, 8, 0, /* 2466: pointer.func */
            64097, 8, 0, /* 2469: pointer.func */
            1, 8, 1, /* 2472: pointer.struct.stack_st_SSL_COMP */
            	2477, 0,
            0, 32, 2, /* 2477: struct.stack_st_fake_SSL_COMP */
            	2484, 8,
            	456, 24,
            64099, 8, 2, /* 2484: pointer_to_array_of_pointers_to_stack */
            	2491, 0,
            	453, 20,
            0, 8, 1, /* 2491: pointer.SSL_COMP */
            	2496, 0,
            0, 0, 1, /* 2496: SSL_COMP */
            	2437, 0,
            64097, 8, 0, /* 2501: pointer.func */
            64097, 8, 0, /* 2504: pointer.func */
            64097, 8, 0, /* 2507: pointer.func */
            0, 88, 1, /* 2510: struct.ssl_cipher_st */
            	10, 8,
            1, 8, 1, /* 2515: pointer.struct.ssl_cipher_st */
            	2510, 0,
            1, 8, 1, /* 2520: pointer.struct.X509_crl_st */
            	2525, 0,
            0, 120, 10, /* 2525: struct.X509_crl_st */
            	2548, 0,
            	2582, 8,
            	2671, 16,
            	2916, 32,
            	2924, 40,
            	2572, 56,
            	2572, 64,
            	2932, 96,
            	2973, 104,
            	49, 112,
            1, 8, 1, /* 2548: pointer.struct.X509_crl_info_st */
            	2553, 0,
            0, 80, 8, /* 2553: struct.X509_crl_info_st */
            	2572, 0,
            	2582, 8,
            	2731, 16,
            	2779, 24,
            	2779, 32,
            	2784, 40,
            	2887, 48,
            	2911, 56,
            1, 8, 1, /* 2572: pointer.struct.asn1_string_st */
            	2577, 0,
            0, 24, 1, /* 2577: struct.asn1_string_st */
            	209, 8,
            1, 8, 1, /* 2582: pointer.struct.X509_algor_st */
            	2587, 0,
            0, 16, 2, /* 2587: struct.X509_algor_st */
            	2594, 0,
            	2608, 8,
            1, 8, 1, /* 2594: pointer.struct.asn1_object_st */
            	2599, 0,
            0, 40, 3, /* 2599: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	243, 24,
            1, 8, 1, /* 2608: pointer.struct.asn1_type_st */
            	2613, 0,
            0, 16, 1, /* 2613: struct.asn1_type_st */
            	2618, 8,
            0, 8, 20, /* 2618: union.unknown */
            	61, 0,
            	2661, 0,
            	2594, 0,
            	2572, 0,
            	2666, 0,
            	2671, 0,
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
            	2661, 0,
            	2661, 0,
            	1219, 0,
            1, 8, 1, /* 2661: pointer.struct.asn1_string_st */
            	2577, 0,
            1, 8, 1, /* 2666: pointer.struct.asn1_string_st */
            	2577, 0,
            1, 8, 1, /* 2671: pointer.struct.asn1_string_st */
            	2577, 0,
            1, 8, 1, /* 2676: pointer.struct.asn1_string_st */
            	2577, 0,
            1, 8, 1, /* 2681: pointer.struct.asn1_string_st */
            	2577, 0,
            1, 8, 1, /* 2686: pointer.struct.asn1_string_st */
            	2577, 0,
            1, 8, 1, /* 2691: pointer.struct.asn1_string_st */
            	2577, 0,
            1, 8, 1, /* 2696: pointer.struct.asn1_string_st */
            	2577, 0,
            1, 8, 1, /* 2701: pointer.struct.asn1_string_st */
            	2577, 0,
            1, 8, 1, /* 2706: pointer.struct.asn1_string_st */
            	2577, 0,
            1, 8, 1, /* 2711: pointer.struct.asn1_string_st */
            	2577, 0,
            1, 8, 1, /* 2716: pointer.struct.asn1_string_st */
            	2577, 0,
            1, 8, 1, /* 2721: pointer.struct.asn1_string_st */
            	2577, 0,
            1, 8, 1, /* 2726: pointer.struct.asn1_string_st */
            	2577, 0,
            1, 8, 1, /* 2731: pointer.struct.X509_name_st */
            	2736, 0,
            0, 40, 3, /* 2736: struct.X509_name_st */
            	2745, 0,
            	2769, 16,
            	209, 24,
            1, 8, 1, /* 2745: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2750, 0,
            0, 32, 2, /* 2750: struct.stack_st_fake_X509_NAME_ENTRY */
            	2757, 8,
            	456, 24,
            64099, 8, 2, /* 2757: pointer_to_array_of_pointers_to_stack */
            	2764, 0,
            	453, 20,
            0, 8, 1, /* 2764: pointer.X509_NAME_ENTRY */
            	417, 0,
            1, 8, 1, /* 2769: pointer.struct.buf_mem_st */
            	2774, 0,
            0, 24, 1, /* 2774: struct.buf_mem_st */
            	61, 8,
            1, 8, 1, /* 2779: pointer.struct.asn1_string_st */
            	2577, 0,
            1, 8, 1, /* 2784: pointer.struct.stack_st_X509_REVOKED */
            	2789, 0,
            0, 32, 2, /* 2789: struct.stack_st_fake_X509_REVOKED */
            	2796, 8,
            	456, 24,
            64099, 8, 2, /* 2796: pointer_to_array_of_pointers_to_stack */
            	2803, 0,
            	453, 20,
            0, 8, 1, /* 2803: pointer.X509_REVOKED */
            	2808, 0,
            0, 0, 1, /* 2808: X509_REVOKED */
            	2813, 0,
            0, 40, 4, /* 2813: struct.x509_revoked_st */
            	2824, 0,
            	2834, 8,
            	2839, 16,
            	2863, 24,
            1, 8, 1, /* 2824: pointer.struct.asn1_string_st */
            	2829, 0,
            0, 24, 1, /* 2829: struct.asn1_string_st */
            	209, 8,
            1, 8, 1, /* 2834: pointer.struct.asn1_string_st */
            	2829, 0,
            1, 8, 1, /* 2839: pointer.struct.stack_st_X509_EXTENSION */
            	2844, 0,
            0, 32, 2, /* 2844: struct.stack_st_fake_X509_EXTENSION */
            	2851, 8,
            	456, 24,
            64099, 8, 2, /* 2851: pointer_to_array_of_pointers_to_stack */
            	2858, 0,
            	453, 20,
            0, 8, 1, /* 2858: pointer.X509_EXTENSION */
            	1251, 0,
            1, 8, 1, /* 2863: pointer.struct.stack_st_GENERAL_NAME */
            	2868, 0,
            0, 32, 2, /* 2868: struct.stack_st_fake_GENERAL_NAME */
            	2875, 8,
            	456, 24,
            64099, 8, 2, /* 2875: pointer_to_array_of_pointers_to_stack */
            	2882, 0,
            	453, 20,
            0, 8, 1, /* 2882: pointer.GENERAL_NAME */
            	1330, 0,
            1, 8, 1, /* 2887: pointer.struct.stack_st_X509_EXTENSION */
            	2892, 0,
            0, 32, 2, /* 2892: struct.stack_st_fake_X509_EXTENSION */
            	2899, 8,
            	456, 24,
            64099, 8, 2, /* 2899: pointer_to_array_of_pointers_to_stack */
            	2906, 0,
            	453, 20,
            0, 8, 1, /* 2906: pointer.X509_EXTENSION */
            	1251, 0,
            0, 24, 1, /* 2911: struct.ASN1_ENCODING_st */
            	209, 0,
            1, 8, 1, /* 2916: pointer.struct.AUTHORITY_KEYID_st */
            	2921, 0,
            0, 0, 0, /* 2921: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 2924: pointer.struct.ISSUING_DIST_POINT_st */
            	2929, 0,
            0, 0, 0, /* 2929: struct.ISSUING_DIST_POINT_st */
            1, 8, 1, /* 2932: pointer.struct.stack_st_GENERAL_NAMES */
            	2937, 0,
            0, 32, 2, /* 2937: struct.stack_st_fake_GENERAL_NAMES */
            	2944, 8,
            	456, 24,
            64099, 8, 2, /* 2944: pointer_to_array_of_pointers_to_stack */
            	2951, 0,
            	453, 20,
            0, 8, 1, /* 2951: pointer.GENERAL_NAMES */
            	2956, 0,
            0, 0, 1, /* 2956: GENERAL_NAMES */
            	2961, 0,
            0, 32, 1, /* 2961: struct.stack_st_GENERAL_NAME */
            	2966, 0,
            0, 32, 2, /* 2966: struct.stack_st */
            	664, 8,
            	456, 24,
            1, 8, 1, /* 2973: pointer.struct.x509_crl_method_st */
            	2978, 0,
            0, 0, 0, /* 2978: struct.x509_crl_method_st */
            1, 8, 1, /* 2981: pointer.struct.cert_st */
            	106, 0,
            1, 8, 1, /* 2986: pointer.struct.stack_st_X509_LOOKUP */
            	2991, 0,
            0, 32, 2, /* 2991: struct.stack_st_fake_X509_LOOKUP */
            	2998, 8,
            	456, 24,
            64099, 8, 2, /* 2998: pointer_to_array_of_pointers_to_stack */
            	3005, 0,
            	453, 20,
            0, 8, 1, /* 3005: pointer.X509_LOOKUP */
            	3010, 0,
            0, 0, 1, /* 3010: X509_LOOKUP */
            	3015, 0,
            0, 32, 3, /* 3015: struct.x509_lookup_st */
            	3024, 8,
            	61, 16,
            	3073, 24,
            1, 8, 1, /* 3024: pointer.struct.x509_lookup_method_st */
            	3029, 0,
            0, 80, 10, /* 3029: struct.x509_lookup_method_st */
            	10, 0,
            	3052, 8,
            	3055, 16,
            	3052, 24,
            	3052, 32,
            	3058, 40,
            	3061, 48,
            	3064, 56,
            	3067, 64,
            	3070, 72,
            64097, 8, 0, /* 3052: pointer.func */
            64097, 8, 0, /* 3055: pointer.func */
            64097, 8, 0, /* 3058: pointer.func */
            64097, 8, 0, /* 3061: pointer.func */
            64097, 8, 0, /* 3064: pointer.func */
            64097, 8, 0, /* 3067: pointer.func */
            64097, 8, 0, /* 3070: pointer.func */
            1, 8, 1, /* 3073: pointer.struct.x509_store_st */
            	3078, 0,
            0, 144, 15, /* 3078: struct.x509_store_st */
            	3111, 8,
            	3751, 16,
            	3775, 24,
            	3787, 32,
            	3790, 40,
            	3793, 48,
            	3796, 56,
            	3787, 64,
            	3799, 72,
            	3802, 80,
            	3805, 88,
            	3808, 96,
            	3811, 104,
            	3787, 112,
            	3396, 120,
            1, 8, 1, /* 3111: pointer.struct.stack_st_X509_OBJECT */
            	3116, 0,
            0, 32, 2, /* 3116: struct.stack_st_fake_X509_OBJECT */
            	3123, 8,
            	456, 24,
            64099, 8, 2, /* 3123: pointer_to_array_of_pointers_to_stack */
            	3130, 0,
            	453, 20,
            0, 8, 1, /* 3130: pointer.X509_OBJECT */
            	3135, 0,
            0, 0, 1, /* 3135: X509_OBJECT */
            	3140, 0,
            0, 16, 1, /* 3140: struct.x509_object_st */
            	3145, 8,
            0, 8, 4, /* 3145: union.unknown */
            	61, 0,
            	3156, 0,
            	2520, 0,
            	3244, 0,
            1, 8, 1, /* 3156: pointer.struct.x509_st */
            	3161, 0,
            0, 184, 12, /* 3161: struct.x509_st */
            	3188, 0,
            	2582, 8,
            	2671, 16,
            	61, 32,
            	3396, 40,
            	2676, 104,
            	2916, 112,
            	3621, 120,
            	3629, 128,
            	3653, 136,
            	3677, 144,
            	3685, 176,
            1, 8, 1, /* 3188: pointer.struct.x509_cinf_st */
            	3193, 0,
            0, 104, 11, /* 3193: struct.x509_cinf_st */
            	2572, 0,
            	2572, 8,
            	2582, 16,
            	2731, 24,
            	3218, 32,
            	2731, 40,
            	3230, 48,
            	2671, 56,
            	2671, 64,
            	2887, 72,
            	2911, 80,
            1, 8, 1, /* 3218: pointer.struct.X509_val_st */
            	3223, 0,
            0, 16, 2, /* 3223: struct.X509_val_st */
            	2779, 0,
            	2779, 8,
            1, 8, 1, /* 3230: pointer.struct.X509_pubkey_st */
            	3235, 0,
            0, 24, 3, /* 3235: struct.X509_pubkey_st */
            	2582, 0,
            	2671, 8,
            	3244, 16,
            1, 8, 1, /* 3244: pointer.struct.evp_pkey_st */
            	3249, 0,
            0, 56, 4, /* 3249: struct.evp_pkey_st */
            	3260, 16,
            	3268, 24,
            	3276, 32,
            	3597, 48,
            1, 8, 1, /* 3260: pointer.struct.evp_pkey_asn1_method_st */
            	3265, 0,
            0, 0, 0, /* 3265: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 3268: pointer.struct.engine_st */
            	3273, 0,
            0, 0, 0, /* 3273: struct.engine_st */
            0, 8, 5, /* 3276: union.unknown */
            	61, 0,
            	3289, 0,
            	3440, 0,
            	3521, 0,
            	3589, 0,
            1, 8, 1, /* 3289: pointer.struct.rsa_st */
            	3294, 0,
            0, 168, 17, /* 3294: struct.rsa_st */
            	3331, 16,
            	3268, 24,
            	3386, 32,
            	3386, 40,
            	3386, 48,
            	3386, 56,
            	3386, 64,
            	3386, 72,
            	3386, 80,
            	3386, 88,
            	3396, 96,
            	3418, 120,
            	3418, 128,
            	3418, 136,
            	61, 144,
            	3432, 152,
            	3432, 160,
            1, 8, 1, /* 3331: pointer.struct.rsa_meth_st */
            	3336, 0,
            0, 112, 13, /* 3336: struct.rsa_meth_st */
            	10, 0,
            	3365, 8,
            	3365, 16,
            	3365, 24,
            	3365, 32,
            	3368, 40,
            	3371, 48,
            	3374, 56,
            	3374, 64,
            	61, 80,
            	3377, 88,
            	3380, 96,
            	3383, 104,
            64097, 8, 0, /* 3365: pointer.func */
            64097, 8, 0, /* 3368: pointer.func */
            64097, 8, 0, /* 3371: pointer.func */
            64097, 8, 0, /* 3374: pointer.func */
            64097, 8, 0, /* 3377: pointer.func */
            64097, 8, 0, /* 3380: pointer.func */
            64097, 8, 0, /* 3383: pointer.func */
            1, 8, 1, /* 3386: pointer.struct.bignum_st */
            	3391, 0,
            0, 24, 1, /* 3391: struct.bignum_st */
            	76, 0,
            0, 16, 1, /* 3396: struct.crypto_ex_data_st */
            	3401, 0,
            1, 8, 1, /* 3401: pointer.struct.stack_st_void */
            	3406, 0,
            0, 32, 1, /* 3406: struct.stack_st_void */
            	3411, 0,
            0, 32, 2, /* 3411: struct.stack_st */
            	664, 8,
            	456, 24,
            1, 8, 1, /* 3418: pointer.struct.bn_mont_ctx_st */
            	3423, 0,
            0, 96, 3, /* 3423: struct.bn_mont_ctx_st */
            	3391, 8,
            	3391, 32,
            	3391, 56,
            1, 8, 1, /* 3432: pointer.struct.bn_blinding_st */
            	3437, 0,
            0, 0, 0, /* 3437: struct.bn_blinding_st */
            1, 8, 1, /* 3440: pointer.struct.dsa_st */
            	3445, 0,
            0, 136, 11, /* 3445: struct.dsa_st */
            	3386, 24,
            	3386, 32,
            	3386, 40,
            	3386, 48,
            	3386, 56,
            	3386, 64,
            	3386, 72,
            	3418, 88,
            	3396, 104,
            	3470, 120,
            	3268, 128,
            1, 8, 1, /* 3470: pointer.struct.dsa_method */
            	3475, 0,
            0, 96, 11, /* 3475: struct.dsa_method */
            	10, 0,
            	3500, 8,
            	3503, 16,
            	3506, 24,
            	3509, 32,
            	3512, 40,
            	3515, 48,
            	3515, 56,
            	61, 72,
            	3518, 80,
            	3515, 88,
            64097, 8, 0, /* 3500: pointer.func */
            64097, 8, 0, /* 3503: pointer.func */
            64097, 8, 0, /* 3506: pointer.func */
            64097, 8, 0, /* 3509: pointer.func */
            64097, 8, 0, /* 3512: pointer.func */
            64097, 8, 0, /* 3515: pointer.func */
            64097, 8, 0, /* 3518: pointer.func */
            1, 8, 1, /* 3521: pointer.struct.dh_st */
            	3526, 0,
            0, 144, 12, /* 3526: struct.dh_st */
            	3386, 8,
            	3386, 16,
            	3386, 32,
            	3386, 40,
            	3418, 56,
            	3386, 64,
            	3386, 72,
            	209, 80,
            	3386, 96,
            	3396, 112,
            	3553, 128,
            	3268, 136,
            1, 8, 1, /* 3553: pointer.struct.dh_method */
            	3558, 0,
            0, 72, 8, /* 3558: struct.dh_method */
            	10, 0,
            	3577, 8,
            	3580, 16,
            	3583, 24,
            	3577, 32,
            	3577, 40,
            	61, 56,
            	3586, 64,
            64097, 8, 0, /* 3577: pointer.func */
            64097, 8, 0, /* 3580: pointer.func */
            64097, 8, 0, /* 3583: pointer.func */
            64097, 8, 0, /* 3586: pointer.func */
            1, 8, 1, /* 3589: pointer.struct.ec_key_st */
            	3594, 0,
            0, 0, 0, /* 3594: struct.ec_key_st */
            1, 8, 1, /* 3597: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3602, 0,
            0, 32, 2, /* 3602: struct.stack_st_fake_X509_ATTRIBUTE */
            	3609, 8,
            	456, 24,
            64099, 8, 2, /* 3609: pointer_to_array_of_pointers_to_stack */
            	3616, 0,
            	453, 20,
            0, 8, 1, /* 3616: pointer.X509_ATTRIBUTE */
            	872, 0,
            1, 8, 1, /* 3621: pointer.struct.X509_POLICY_CACHE_st */
            	3626, 0,
            0, 0, 0, /* 3626: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 3629: pointer.struct.stack_st_DIST_POINT */
            	3634, 0,
            0, 32, 2, /* 3634: struct.stack_st_fake_DIST_POINT */
            	3641, 8,
            	456, 24,
            64099, 8, 2, /* 3641: pointer_to_array_of_pointers_to_stack */
            	3648, 0,
            	453, 20,
            0, 8, 1, /* 3648: pointer.DIST_POINT */
            	1632, 0,
            1, 8, 1, /* 3653: pointer.struct.stack_st_GENERAL_NAME */
            	3658, 0,
            0, 32, 2, /* 3658: struct.stack_st_fake_GENERAL_NAME */
            	3665, 8,
            	456, 24,
            64099, 8, 2, /* 3665: pointer_to_array_of_pointers_to_stack */
            	3672, 0,
            	453, 20,
            0, 8, 1, /* 3672: pointer.GENERAL_NAME */
            	1330, 0,
            1, 8, 1, /* 3677: pointer.struct.NAME_CONSTRAINTS_st */
            	3682, 0,
            0, 0, 0, /* 3682: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 3685: pointer.struct.x509_cert_aux_st */
            	3690, 0,
            0, 40, 5, /* 3690: struct.x509_cert_aux_st */
            	3703, 0,
            	3703, 8,
            	2726, 16,
            	2676, 24,
            	3727, 32,
            1, 8, 1, /* 3703: pointer.struct.stack_st_ASN1_OBJECT */
            	3708, 0,
            0, 32, 2, /* 3708: struct.stack_st_fake_ASN1_OBJECT */
            	3715, 8,
            	456, 24,
            64099, 8, 2, /* 3715: pointer_to_array_of_pointers_to_stack */
            	3722, 0,
            	453, 20,
            0, 8, 1, /* 3722: pointer.ASN1_OBJECT */
            	2125, 0,
            1, 8, 1, /* 3727: pointer.struct.stack_st_X509_ALGOR */
            	3732, 0,
            0, 32, 2, /* 3732: struct.stack_st_fake_X509_ALGOR */
            	3739, 8,
            	456, 24,
            64099, 8, 2, /* 3739: pointer_to_array_of_pointers_to_stack */
            	3746, 0,
            	453, 20,
            0, 8, 1, /* 3746: pointer.X509_ALGOR */
            	2163, 0,
            1, 8, 1, /* 3751: pointer.struct.stack_st_X509_LOOKUP */
            	3756, 0,
            0, 32, 2, /* 3756: struct.stack_st_fake_X509_LOOKUP */
            	3763, 8,
            	456, 24,
            64099, 8, 2, /* 3763: pointer_to_array_of_pointers_to_stack */
            	3770, 0,
            	453, 20,
            0, 8, 1, /* 3770: pointer.X509_LOOKUP */
            	3010, 0,
            1, 8, 1, /* 3775: pointer.struct.X509_VERIFY_PARAM_st */
            	3780, 0,
            0, 56, 2, /* 3780: struct.X509_VERIFY_PARAM_st */
            	61, 0,
            	3703, 48,
            64097, 8, 0, /* 3787: pointer.func */
            64097, 8, 0, /* 3790: pointer.func */
            64097, 8, 0, /* 3793: pointer.func */
            64097, 8, 0, /* 3796: pointer.func */
            64097, 8, 0, /* 3799: pointer.func */
            64097, 8, 0, /* 3802: pointer.func */
            64097, 8, 0, /* 3805: pointer.func */
            64097, 8, 0, /* 3808: pointer.func */
            64097, 8, 0, /* 3811: pointer.func */
            0, 0, 1, /* 3814: X509_NAME */
            	2385, 0,
            64097, 8, 0, /* 3819: pointer.func */
            1, 8, 1, /* 3822: pointer.struct.ASN1_VALUE_st */
            	3827, 0,
            0, 0, 0, /* 3827: struct.ASN1_VALUE_st */
            64097, 8, 0, /* 3830: pointer.func */
            64097, 8, 0, /* 3833: pointer.func */
            64097, 8, 0, /* 3836: pointer.func */
            0, 112, 11, /* 3839: struct.ssl3_enc_method */
            	3864, 0,
            	3867, 8,
            	3870, 16,
            	3873, 24,
            	3864, 32,
            	3876, 40,
            	3879, 56,
            	10, 64,
            	10, 80,
            	3882, 96,
            	3885, 104,
            64097, 8, 0, /* 3864: pointer.func */
            64097, 8, 0, /* 3867: pointer.func */
            64097, 8, 0, /* 3870: pointer.func */
            64097, 8, 0, /* 3873: pointer.func */
            64097, 8, 0, /* 3876: pointer.func */
            64097, 8, 0, /* 3879: pointer.func */
            64097, 8, 0, /* 3882: pointer.func */
            64097, 8, 0, /* 3885: pointer.func */
            64097, 8, 0, /* 3888: pointer.func */
            64097, 8, 0, /* 3891: pointer.func */
            1, 8, 1, /* 3894: pointer.struct.X509_pubkey_st */
            	3899, 0,
            0, 24, 3, /* 3899: struct.X509_pubkey_st */
            	3908, 0,
            	4007, 8,
            	4067, 16,
            1, 8, 1, /* 3908: pointer.struct.X509_algor_st */
            	3913, 0,
            0, 16, 2, /* 3913: struct.X509_algor_st */
            	3920, 0,
            	3934, 8,
            1, 8, 1, /* 3920: pointer.struct.asn1_object_st */
            	3925, 0,
            0, 40, 3, /* 3925: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	243, 24,
            1, 8, 1, /* 3934: pointer.struct.asn1_type_st */
            	3939, 0,
            0, 16, 1, /* 3939: struct.asn1_type_st */
            	3944, 8,
            0, 8, 20, /* 3944: union.unknown */
            	61, 0,
            	3987, 0,
            	3920, 0,
            	3997, 0,
            	4002, 0,
            	4007, 0,
            	4012, 0,
            	4017, 0,
            	4022, 0,
            	4027, 0,
            	4032, 0,
            	4037, 0,
            	4042, 0,
            	4047, 0,
            	4052, 0,
            	4057, 0,
            	4062, 0,
            	3987, 0,
            	3987, 0,
            	3822, 0,
            1, 8, 1, /* 3987: pointer.struct.asn1_string_st */
            	3992, 0,
            0, 24, 1, /* 3992: struct.asn1_string_st */
            	209, 8,
            1, 8, 1, /* 3997: pointer.struct.asn1_string_st */
            	3992, 0,
            1, 8, 1, /* 4002: pointer.struct.asn1_string_st */
            	3992, 0,
            1, 8, 1, /* 4007: pointer.struct.asn1_string_st */
            	3992, 0,
            1, 8, 1, /* 4012: pointer.struct.asn1_string_st */
            	3992, 0,
            1, 8, 1, /* 4017: pointer.struct.asn1_string_st */
            	3992, 0,
            1, 8, 1, /* 4022: pointer.struct.asn1_string_st */
            	3992, 0,
            1, 8, 1, /* 4027: pointer.struct.asn1_string_st */
            	3992, 0,
            1, 8, 1, /* 4032: pointer.struct.asn1_string_st */
            	3992, 0,
            1, 8, 1, /* 4037: pointer.struct.asn1_string_st */
            	3992, 0,
            1, 8, 1, /* 4042: pointer.struct.asn1_string_st */
            	3992, 0,
            1, 8, 1, /* 4047: pointer.struct.asn1_string_st */
            	3992, 0,
            1, 8, 1, /* 4052: pointer.struct.asn1_string_st */
            	3992, 0,
            1, 8, 1, /* 4057: pointer.struct.asn1_string_st */
            	3992, 0,
            1, 8, 1, /* 4062: pointer.struct.asn1_string_st */
            	3992, 0,
            1, 8, 1, /* 4067: pointer.struct.evp_pkey_st */
            	4072, 0,
            0, 56, 4, /* 4072: struct.evp_pkey_st */
            	4083, 16,
            	4091, 24,
            	4099, 32,
            	4417, 48,
            1, 8, 1, /* 4083: pointer.struct.evp_pkey_asn1_method_st */
            	4088, 0,
            0, 0, 0, /* 4088: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 4091: pointer.struct.engine_st */
            	4096, 0,
            0, 0, 0, /* 4096: struct.engine_st */
            0, 8, 5, /* 4099: union.unknown */
            	61, 0,
            	4112, 0,
            	4263, 0,
            	4341, 0,
            	4409, 0,
            1, 8, 1, /* 4112: pointer.struct.rsa_st */
            	4117, 0,
            0, 168, 17, /* 4117: struct.rsa_st */
            	4154, 16,
            	4091, 24,
            	4209, 32,
            	4209, 40,
            	4209, 48,
            	4209, 56,
            	4209, 64,
            	4209, 72,
            	4209, 80,
            	4209, 88,
            	4219, 96,
            	4241, 120,
            	4241, 128,
            	4241, 136,
            	61, 144,
            	4255, 152,
            	4255, 160,
            1, 8, 1, /* 4154: pointer.struct.rsa_meth_st */
            	4159, 0,
            0, 112, 13, /* 4159: struct.rsa_meth_st */
            	10, 0,
            	4188, 8,
            	4188, 16,
            	4188, 24,
            	4188, 32,
            	4191, 40,
            	4194, 48,
            	4197, 56,
            	4197, 64,
            	61, 80,
            	4200, 88,
            	4203, 96,
            	4206, 104,
            64097, 8, 0, /* 4188: pointer.func */
            64097, 8, 0, /* 4191: pointer.func */
            64097, 8, 0, /* 4194: pointer.func */
            64097, 8, 0, /* 4197: pointer.func */
            64097, 8, 0, /* 4200: pointer.func */
            64097, 8, 0, /* 4203: pointer.func */
            64097, 8, 0, /* 4206: pointer.func */
            1, 8, 1, /* 4209: pointer.struct.bignum_st */
            	4214, 0,
            0, 24, 1, /* 4214: struct.bignum_st */
            	76, 0,
            0, 16, 1, /* 4219: struct.crypto_ex_data_st */
            	4224, 0,
            1, 8, 1, /* 4224: pointer.struct.stack_st_void */
            	4229, 0,
            0, 32, 1, /* 4229: struct.stack_st_void */
            	4234, 0,
            0, 32, 2, /* 4234: struct.stack_st */
            	664, 8,
            	456, 24,
            1, 8, 1, /* 4241: pointer.struct.bn_mont_ctx_st */
            	4246, 0,
            0, 96, 3, /* 4246: struct.bn_mont_ctx_st */
            	4214, 8,
            	4214, 32,
            	4214, 56,
            1, 8, 1, /* 4255: pointer.struct.bn_blinding_st */
            	4260, 0,
            0, 0, 0, /* 4260: struct.bn_blinding_st */
            1, 8, 1, /* 4263: pointer.struct.dsa_st */
            	4268, 0,
            0, 136, 11, /* 4268: struct.dsa_st */
            	4209, 24,
            	4209, 32,
            	4209, 40,
            	4209, 48,
            	4209, 56,
            	4209, 64,
            	4209, 72,
            	4241, 88,
            	4219, 104,
            	4293, 120,
            	4091, 128,
            1, 8, 1, /* 4293: pointer.struct.dsa_method */
            	4298, 0,
            0, 96, 11, /* 4298: struct.dsa_method */
            	10, 0,
            	4323, 8,
            	4326, 16,
            	4329, 24,
            	3888, 32,
            	4332, 40,
            	4335, 48,
            	4335, 56,
            	61, 72,
            	4338, 80,
            	4335, 88,
            64097, 8, 0, /* 4323: pointer.func */
            64097, 8, 0, /* 4326: pointer.func */
            64097, 8, 0, /* 4329: pointer.func */
            64097, 8, 0, /* 4332: pointer.func */
            64097, 8, 0, /* 4335: pointer.func */
            64097, 8, 0, /* 4338: pointer.func */
            1, 8, 1, /* 4341: pointer.struct.dh_st */
            	4346, 0,
            0, 144, 12, /* 4346: struct.dh_st */
            	4209, 8,
            	4209, 16,
            	4209, 32,
            	4209, 40,
            	4241, 56,
            	4209, 64,
            	4209, 72,
            	209, 80,
            	4209, 96,
            	4219, 112,
            	4373, 128,
            	4091, 136,
            1, 8, 1, /* 4373: pointer.struct.dh_method */
            	4378, 0,
            0, 72, 8, /* 4378: struct.dh_method */
            	10, 0,
            	4397, 8,
            	4400, 16,
            	4403, 24,
            	4397, 32,
            	4397, 40,
            	61, 56,
            	4406, 64,
            64097, 8, 0, /* 4397: pointer.func */
            64097, 8, 0, /* 4400: pointer.func */
            64097, 8, 0, /* 4403: pointer.func */
            64097, 8, 0, /* 4406: pointer.func */
            1, 8, 1, /* 4409: pointer.struct.ec_key_st */
            	4414, 0,
            0, 0, 0, /* 4414: struct.ec_key_st */
            1, 8, 1, /* 4417: pointer.struct.stack_st_X509_ATTRIBUTE */
            	4422, 0,
            0, 32, 2, /* 4422: struct.stack_st_fake_X509_ATTRIBUTE */
            	4429, 8,
            	456, 24,
            64099, 8, 2, /* 4429: pointer_to_array_of_pointers_to_stack */
            	4436, 0,
            	453, 20,
            0, 8, 1, /* 4436: pointer.X509_ATTRIBUTE */
            	872, 0,
            64097, 8, 0, /* 4441: pointer.func */
            64097, 8, 0, /* 4444: pointer.func */
            64097, 8, 0, /* 4447: pointer.func */
            1, 8, 1, /* 4450: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	4455, 0,
            0, 32, 2, /* 4455: struct.stack_st_fake_SRTP_PROTECTION_PROFILE */
            	4462, 8,
            	456, 24,
            64099, 8, 2, /* 4462: pointer_to_array_of_pointers_to_stack */
            	4469, 0,
            	453, 20,
            0, 8, 1, /* 4469: pointer.SRTP_PROTECTION_PROFILE */
            	0, 0,
            64097, 8, 0, /* 4474: pointer.func */
            64097, 8, 0, /* 4477: pointer.func */
            0, 144, 15, /* 4480: struct.x509_store_st */
            	4513, 8,
            	2986, 16,
            	4537, 24,
            	4549, 32,
            	4552, 40,
            	4555, 48,
            	4558, 56,
            	4549, 64,
            	4561, 72,
            	3833, 80,
            	3819, 88,
            	3836, 96,
            	4564, 104,
            	4549, 112,
            	642, 120,
            1, 8, 1, /* 4513: pointer.struct.stack_st_X509_OBJECT */
            	4518, 0,
            0, 32, 2, /* 4518: struct.stack_st_fake_X509_OBJECT */
            	4525, 8,
            	456, 24,
            64099, 8, 2, /* 4525: pointer_to_array_of_pointers_to_stack */
            	4532, 0,
            	453, 20,
            0, 8, 1, /* 4532: pointer.X509_OBJECT */
            	3135, 0,
            1, 8, 1, /* 4537: pointer.struct.X509_VERIFY_PARAM_st */
            	4542, 0,
            0, 56, 2, /* 4542: struct.X509_VERIFY_PARAM_st */
            	61, 0,
            	2101, 48,
            64097, 8, 0, /* 4549: pointer.func */
            64097, 8, 0, /* 4552: pointer.func */
            64097, 8, 0, /* 4555: pointer.func */
            64097, 8, 0, /* 4558: pointer.func */
            64097, 8, 0, /* 4561: pointer.func */
            64097, 8, 0, /* 4564: pointer.func */
            1, 8, 1, /* 4567: pointer.struct.x509_store_st */
            	4480, 0,
            0, 1, 0, /* 4572: char */
            1, 8, 1, /* 4575: pointer.struct.stack_st_X509_ALGOR */
            	4580, 0,
            0, 32, 2, /* 4580: struct.stack_st_fake_X509_ALGOR */
            	4587, 8,
            	456, 24,
            64099, 8, 2, /* 4587: pointer_to_array_of_pointers_to_stack */
            	4594, 0,
            	453, 20,
            0, 8, 1, /* 4594: pointer.X509_ALGOR */
            	2163, 0,
            1, 8, 1, /* 4599: pointer.struct.ssl_method_st */
            	4604, 0,
            0, 232, 28, /* 4604: struct.ssl_method_st */
            	3870, 8,
            	4663, 16,
            	4663, 24,
            	3870, 32,
            	3870, 40,
            	4666, 48,
            	4666, 56,
            	4669, 64,
            	3870, 72,
            	3870, 80,
            	3870, 88,
            	4672, 96,
            	4675, 104,
            	4678, 112,
            	3870, 120,
            	4681, 128,
            	4684, 136,
            	4477, 144,
            	4687, 152,
            	4690, 160,
            	4693, 168,
            	4474, 176,
            	4441, 184,
            	2469, 192,
            	4696, 200,
            	4693, 208,
            	4701, 216,
            	4444, 224,
            64097, 8, 0, /* 4663: pointer.func */
            64097, 8, 0, /* 4666: pointer.func */
            64097, 8, 0, /* 4669: pointer.func */
            64097, 8, 0, /* 4672: pointer.func */
            64097, 8, 0, /* 4675: pointer.func */
            64097, 8, 0, /* 4678: pointer.func */
            64097, 8, 0, /* 4681: pointer.func */
            64097, 8, 0, /* 4684: pointer.func */
            64097, 8, 0, /* 4687: pointer.func */
            64097, 8, 0, /* 4690: pointer.func */
            64097, 8, 0, /* 4693: pointer.func */
            1, 8, 1, /* 4696: pointer.struct.ssl3_enc_method */
            	3839, 0,
            64097, 8, 0, /* 4701: pointer.func */
            64097, 8, 0, /* 4704: pointer.func */
            1, 8, 1, /* 4707: pointer.struct.NAME_CONSTRAINTS_st */
            	4712, 0,
            0, 0, 0, /* 4712: struct.NAME_CONSTRAINTS_st */
            64097, 8, 0, /* 4715: pointer.func */
            1, 8, 1, /* 4718: pointer.struct.x509_store_st */
            	4480, 0,
            1, 8, 1, /* 4723: pointer.struct.X509_name_st */
            	4728, 0,
            0, 40, 3, /* 4728: struct.X509_name_st */
            	4737, 0,
            	4761, 16,
            	209, 24,
            1, 8, 1, /* 4737: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4742, 0,
            0, 32, 2, /* 4742: struct.stack_st_fake_X509_NAME_ENTRY */
            	4749, 8,
            	456, 24,
            64099, 8, 2, /* 4749: pointer_to_array_of_pointers_to_stack */
            	4756, 0,
            	453, 20,
            0, 8, 1, /* 4756: pointer.X509_NAME_ENTRY */
            	417, 0,
            1, 8, 1, /* 4761: pointer.struct.buf_mem_st */
            	4766, 0,
            0, 24, 1, /* 4766: struct.buf_mem_st */
            	61, 8,
            64097, 8, 0, /* 4771: pointer.func */
            64097, 8, 0, /* 4774: pointer.func */
            0, 104, 11, /* 4777: struct.x509_cinf_st */
            	3997, 0,
            	3997, 8,
            	3908, 16,
            	4723, 24,
            	4802, 32,
            	4723, 40,
            	3894, 48,
            	4007, 56,
            	4007, 64,
            	4819, 72,
            	4843, 80,
            1, 8, 1, /* 4802: pointer.struct.X509_val_st */
            	4807, 0,
            0, 16, 2, /* 4807: struct.X509_val_st */
            	4814, 0,
            	4814, 8,
            1, 8, 1, /* 4814: pointer.struct.asn1_string_st */
            	3992, 0,
            1, 8, 1, /* 4819: pointer.struct.stack_st_X509_EXTENSION */
            	4824, 0,
            0, 32, 2, /* 4824: struct.stack_st_fake_X509_EXTENSION */
            	4831, 8,
            	456, 24,
            64099, 8, 2, /* 4831: pointer_to_array_of_pointers_to_stack */
            	4838, 0,
            	453, 20,
            0, 8, 1, /* 4838: pointer.X509_EXTENSION */
            	1251, 0,
            0, 24, 1, /* 4843: struct.ASN1_ENCODING_st */
            	209, 0,
            0, 0, 0, /* 4848: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 4851: pointer.pointer.struct.lhash_node_st */
            	4856, 0,
            1, 8, 1, /* 4856: pointer.struct.lhash_node_st */
            	4861, 0,
            0, 24, 2, /* 4861: struct.lhash_node_st */
            	49, 0,
            	4868, 8,
            1, 8, 1, /* 4868: pointer.struct.lhash_node_st */
            	4861, 0,
            64097, 8, 0, /* 4873: pointer.func */
            1, 8, 1, /* 4876: pointer.struct.sess_cert_st */
            	4881, 0,
            0, 248, 5, /* 4881: struct.sess_cert_st */
            	4894, 0,
            	123, 16,
            	2367, 216,
            	2375, 224,
            	2380, 232,
            1, 8, 1, /* 4894: pointer.struct.stack_st_X509 */
            	4899, 0,
            0, 32, 2, /* 4899: struct.stack_st_fake_X509 */
            	4906, 8,
            	456, 24,
            64099, 8, 2, /* 4906: pointer_to_array_of_pointers_to_stack */
            	4913, 0,
            	453, 20,
            0, 8, 1, /* 4913: pointer.X509 */
            	4918, 0,
            0, 0, 1, /* 4918: X509 */
            	4923, 0,
            0, 184, 12, /* 4923: struct.x509_st */
            	4950, 0,
            	3908, 8,
            	4007, 16,
            	61, 32,
            	4219, 40,
            	4012, 104,
            	4955, 112,
            	4963, 120,
            	4968, 128,
            	4992, 136,
            	4707, 144,
            	5016, 176,
            1, 8, 1, /* 4950: pointer.struct.x509_cinf_st */
            	4777, 0,
            1, 8, 1, /* 4955: pointer.struct.AUTHORITY_KEYID_st */
            	4960, 0,
            0, 0, 0, /* 4960: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 4963: pointer.struct.X509_POLICY_CACHE_st */
            	4848, 0,
            1, 8, 1, /* 4968: pointer.struct.stack_st_DIST_POINT */
            	4973, 0,
            0, 32, 2, /* 4973: struct.stack_st_fake_DIST_POINT */
            	4980, 8,
            	456, 24,
            64099, 8, 2, /* 4980: pointer_to_array_of_pointers_to_stack */
            	4987, 0,
            	453, 20,
            0, 8, 1, /* 4987: pointer.DIST_POINT */
            	1632, 0,
            1, 8, 1, /* 4992: pointer.struct.stack_st_GENERAL_NAME */
            	4997, 0,
            0, 32, 2, /* 4997: struct.stack_st_fake_GENERAL_NAME */
            	5004, 8,
            	456, 24,
            64099, 8, 2, /* 5004: pointer_to_array_of_pointers_to_stack */
            	5011, 0,
            	453, 20,
            0, 8, 1, /* 5011: pointer.GENERAL_NAME */
            	1330, 0,
            1, 8, 1, /* 5016: pointer.struct.x509_cert_aux_st */
            	5021, 0,
            0, 40, 5, /* 5021: struct.x509_cert_aux_st */
            	5034, 0,
            	5034, 8,
            	4062, 16,
            	4012, 24,
            	4575, 32,
            1, 8, 1, /* 5034: pointer.struct.stack_st_ASN1_OBJECT */
            	5039, 0,
            0, 32, 2, /* 5039: struct.stack_st_fake_ASN1_OBJECT */
            	5046, 8,
            	456, 24,
            64099, 8, 2, /* 5046: pointer_to_array_of_pointers_to_stack */
            	5053, 0,
            	453, 20,
            0, 8, 1, /* 5053: pointer.ASN1_OBJECT */
            	2125, 0,
            1, 8, 1, /* 5058: pointer.struct.ssl_ctx_st */
            	5063, 0,
            0, 736, 50, /* 5063: struct.ssl_ctx_st */
            	4599, 0,
            	5166, 8,
            	5166, 16,
            	4567, 24,
            	5200, 32,
            	5214, 48,
            	5214, 56,
            	4873, 80,
            	5250, 88,
            	2507, 96,
            	4774, 152,
            	49, 160,
            	5253, 168,
            	49, 176,
            	2504, 184,
            	5256, 192,
            	2501, 200,
            	642, 208,
            	2322, 224,
            	2322, 232,
            	2322, 240,
            	4894, 248,
            	2472, 256,
            	2428, 264,
            	5259, 272,
            	2981, 304,
            	3830, 320,
            	49, 328,
            	4552, 376,
            	4704, 384,
            	4537, 392,
            	524, 408,
            	52, 416,
            	49, 424,
            	4447, 480,
            	55, 488,
            	49, 496,
            	97, 504,
            	49, 512,
            	61, 520,
            	94, 528,
            	4715, 536,
            	5283, 552,
            	5283, 560,
            	18, 568,
            	15, 696,
            	49, 704,
            	3891, 712,
            	49, 720,
            	4450, 728,
            1, 8, 1, /* 5166: pointer.struct.stack_st_SSL_CIPHER */
            	5171, 0,
            0, 32, 2, /* 5171: struct.stack_st_fake_SSL_CIPHER */
            	5178, 8,
            	456, 24,
            64099, 8, 2, /* 5178: pointer_to_array_of_pointers_to_stack */
            	5185, 0,
            	453, 20,
            0, 8, 1, /* 5185: pointer.SSL_CIPHER */
            	5190, 0,
            0, 0, 1, /* 5190: SSL_CIPHER */
            	5195, 0,
            0, 88, 1, /* 5195: struct.ssl_cipher_st */
            	10, 8,
            1, 8, 1, /* 5200: pointer.struct.lhash_st */
            	5205, 0,
            0, 176, 3, /* 5205: struct.lhash_st */
            	4851, 0,
            	456, 8,
            	4771, 16,
            1, 8, 1, /* 5214: pointer.struct.ssl_session_st */
            	5219, 0,
            0, 352, 14, /* 5219: struct.ssl_session_st */
            	61, 144,
            	61, 152,
            	4876, 168,
            	137, 176,
            	2515, 224,
            	5166, 240,
            	642, 248,
            	5214, 264,
            	5214, 272,
            	61, 280,
            	209, 296,
            	209, 312,
            	209, 320,
            	61, 344,
            64097, 8, 0, /* 5250: pointer.func */
            64097, 8, 0, /* 5253: pointer.func */
            64097, 8, 0, /* 5256: pointer.func */
            1, 8, 1, /* 5259: pointer.struct.stack_st_X509_NAME */
            	5264, 0,
            0, 32, 2, /* 5264: struct.stack_st_fake_X509_NAME */
            	5271, 8,
            	456, 24,
            64099, 8, 2, /* 5271: pointer_to_array_of_pointers_to_stack */
            	5278, 0,
            	453, 20,
            0, 8, 1, /* 5278: pointer.X509_NAME */
            	3814, 0,
            1, 8, 1, /* 5283: pointer.struct.ssl3_buf_freelist_st */
            	5288, 0,
            0, 24, 1, /* 5288: struct.ssl3_buf_freelist_st */
            	84, 16,
        },
        .arg_entity_index = { 5058, },
        .ret_entity_index = 4718,
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

