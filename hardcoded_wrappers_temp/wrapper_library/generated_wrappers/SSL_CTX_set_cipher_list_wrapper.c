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

int bb_SSL_CTX_set_cipher_list(SSL_CTX * arg_a,const char * arg_b);

int SSL_CTX_set_cipher_list(SSL_CTX * arg_a,const char * arg_b) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_CTX_set_cipher_list called %lu\n", in_lib);
    if (!in_lib)
        return bb_SSL_CTX_set_cipher_list(arg_a,arg_b);
    else {
        int (*orig_SSL_CTX_set_cipher_list)(SSL_CTX *,const char *);
        orig_SSL_CTX_set_cipher_list = dlsym(RTLD_NEXT, "SSL_CTX_set_cipher_list");
        return orig_SSL_CTX_set_cipher_list(arg_a,arg_b);
    }
}

int bb_SSL_CTX_set_cipher_list(SSL_CTX * arg_a,const char * arg_b) 
{
    int ret;

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
            64097, 8, 0, /* 2520: pointer.func */
            0, 16, 1, /* 2523: struct.crypto_ex_data_st */
            	2528, 0,
            1, 8, 1, /* 2528: pointer.struct.stack_st_void */
            	2533, 0,
            0, 32, 1, /* 2533: struct.stack_st_void */
            	2538, 0,
            0, 32, 2, /* 2538: struct.stack_st */
            	664, 8,
            	456, 24,
            0, 136, 11, /* 2545: struct.dsa_st */
            	2570, 24,
            	2570, 32,
            	2570, 40,
            	2570, 48,
            	2570, 56,
            	2570, 64,
            	2570, 72,
            	2580, 88,
            	2523, 104,
            	2594, 120,
            	2645, 128,
            1, 8, 1, /* 2570: pointer.struct.bignum_st */
            	2575, 0,
            0, 24, 1, /* 2575: struct.bignum_st */
            	76, 0,
            1, 8, 1, /* 2580: pointer.struct.bn_mont_ctx_st */
            	2585, 0,
            0, 96, 3, /* 2585: struct.bn_mont_ctx_st */
            	2575, 8,
            	2575, 32,
            	2575, 56,
            1, 8, 1, /* 2594: pointer.struct.dsa_method */
            	2599, 0,
            0, 96, 11, /* 2599: struct.dsa_method */
            	10, 0,
            	2624, 8,
            	2627, 16,
            	2630, 24,
            	2633, 32,
            	2636, 40,
            	2639, 48,
            	2639, 56,
            	61, 72,
            	2642, 80,
            	2639, 88,
            64097, 8, 0, /* 2624: pointer.func */
            64097, 8, 0, /* 2627: pointer.func */
            64097, 8, 0, /* 2630: pointer.func */
            64097, 8, 0, /* 2633: pointer.func */
            64097, 8, 0, /* 2636: pointer.func */
            64097, 8, 0, /* 2639: pointer.func */
            64097, 8, 0, /* 2642: pointer.func */
            1, 8, 1, /* 2645: pointer.struct.engine_st */
            	2650, 0,
            0, 0, 0, /* 2650: struct.engine_st */
            64097, 8, 0, /* 2653: pointer.func */
            1, 8, 1, /* 2656: pointer.struct.X509_algor_st */
            	2661, 0,
            0, 16, 2, /* 2661: struct.X509_algor_st */
            	2668, 0,
            	2682, 8,
            1, 8, 1, /* 2668: pointer.struct.asn1_object_st */
            	2673, 0,
            0, 40, 3, /* 2673: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	243, 24,
            1, 8, 1, /* 2682: pointer.struct.asn1_type_st */
            	2687, 0,
            0, 16, 1, /* 2687: struct.asn1_type_st */
            	2692, 8,
            0, 8, 20, /* 2692: union.unknown */
            	61, 0,
            	2735, 0,
            	2668, 0,
            	2745, 0,
            	2750, 0,
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
            	2735, 0,
            	2735, 0,
            	1219, 0,
            1, 8, 1, /* 2735: pointer.struct.asn1_string_st */
            	2740, 0,
            0, 24, 1, /* 2740: struct.asn1_string_st */
            	209, 8,
            1, 8, 1, /* 2745: pointer.struct.asn1_string_st */
            	2740, 0,
            1, 8, 1, /* 2750: pointer.struct.asn1_string_st */
            	2740, 0,
            1, 8, 1, /* 2755: pointer.struct.asn1_string_st */
            	2740, 0,
            1, 8, 1, /* 2760: pointer.struct.asn1_string_st */
            	2740, 0,
            1, 8, 1, /* 2765: pointer.struct.asn1_string_st */
            	2740, 0,
            1, 8, 1, /* 2770: pointer.struct.asn1_string_st */
            	2740, 0,
            1, 8, 1, /* 2775: pointer.struct.asn1_string_st */
            	2740, 0,
            1, 8, 1, /* 2780: pointer.struct.asn1_string_st */
            	2740, 0,
            1, 8, 1, /* 2785: pointer.struct.asn1_string_st */
            	2740, 0,
            1, 8, 1, /* 2790: pointer.struct.asn1_string_st */
            	2740, 0,
            1, 8, 1, /* 2795: pointer.struct.asn1_string_st */
            	2740, 0,
            1, 8, 1, /* 2800: pointer.struct.asn1_string_st */
            	2740, 0,
            1, 8, 1, /* 2805: pointer.struct.asn1_string_st */
            	2740, 0,
            1, 8, 1, /* 2810: pointer.struct.asn1_string_st */
            	2740, 0,
            1, 8, 1, /* 2815: pointer.struct.stack_st_DIST_POINT */
            	2820, 0,
            0, 32, 2, /* 2820: struct.stack_st_fake_DIST_POINT */
            	2827, 8,
            	456, 24,
            64099, 8, 2, /* 2827: pointer_to_array_of_pointers_to_stack */
            	2834, 0,
            	453, 20,
            0, 8, 1, /* 2834: pointer.DIST_POINT */
            	1632, 0,
            1, 8, 1, /* 2839: pointer.struct.X509_POLICY_CACHE_st */
            	2844, 0,
            0, 0, 0, /* 2844: struct.X509_POLICY_CACHE_st */
            0, 0, 0, /* 2847: struct.ec_key_st */
            1, 8, 1, /* 2850: pointer.struct.AUTHORITY_KEYID_st */
            	2855, 0,
            0, 0, 0, /* 2855: struct.AUTHORITY_KEYID_st */
            64097, 8, 0, /* 2858: pointer.func */
            64097, 8, 0, /* 2861: pointer.func */
            0, 112, 11, /* 2864: struct.ssl3_enc_method */
            	2889, 0,
            	2892, 8,
            	2895, 16,
            	2898, 24,
            	2889, 32,
            	2901, 40,
            	2904, 56,
            	10, 64,
            	10, 80,
            	2907, 96,
            	2910, 104,
            64097, 8, 0, /* 2889: pointer.func */
            64097, 8, 0, /* 2892: pointer.func */
            64097, 8, 0, /* 2895: pointer.func */
            64097, 8, 0, /* 2898: pointer.func */
            64097, 8, 0, /* 2901: pointer.func */
            64097, 8, 0, /* 2904: pointer.func */
            64097, 8, 0, /* 2907: pointer.func */
            64097, 8, 0, /* 2910: pointer.func */
            64097, 8, 0, /* 2913: pointer.func */
            64097, 8, 0, /* 2916: pointer.func */
            64097, 8, 0, /* 2919: pointer.func */
            0, 16, 1, /* 2922: struct.x509_object_st */
            	2927, 8,
            0, 8, 4, /* 2927: union.unknown */
            	61, 0,
            	2938, 0,
            	3450, 0,
            	3079, 0,
            1, 8, 1, /* 2938: pointer.struct.x509_st */
            	2943, 0,
            0, 184, 12, /* 2943: struct.x509_st */
            	2970, 0,
            	2656, 8,
            	2755, 16,
            	61, 32,
            	2523, 40,
            	2760, 104,
            	2850, 112,
            	2839, 120,
            	2815, 128,
            	3352, 136,
            	3376, 144,
            	3384, 176,
            1, 8, 1, /* 2970: pointer.struct.x509_cinf_st */
            	2975, 0,
            0, 104, 11, /* 2975: struct.x509_cinf_st */
            	2745, 0,
            	2745, 8,
            	2656, 16,
            	3000, 24,
            	3048, 32,
            	3000, 40,
            	3065, 48,
            	2755, 56,
            	2755, 64,
            	3323, 72,
            	3347, 80,
            1, 8, 1, /* 3000: pointer.struct.X509_name_st */
            	3005, 0,
            0, 40, 3, /* 3005: struct.X509_name_st */
            	3014, 0,
            	3038, 16,
            	209, 24,
            1, 8, 1, /* 3014: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3019, 0,
            0, 32, 2, /* 3019: struct.stack_st_fake_X509_NAME_ENTRY */
            	3026, 8,
            	456, 24,
            64099, 8, 2, /* 3026: pointer_to_array_of_pointers_to_stack */
            	3033, 0,
            	453, 20,
            0, 8, 1, /* 3033: pointer.X509_NAME_ENTRY */
            	417, 0,
            1, 8, 1, /* 3038: pointer.struct.buf_mem_st */
            	3043, 0,
            0, 24, 1, /* 3043: struct.buf_mem_st */
            	61, 8,
            1, 8, 1, /* 3048: pointer.struct.X509_val_st */
            	3053, 0,
            0, 16, 2, /* 3053: struct.X509_val_st */
            	3060, 0,
            	3060, 8,
            1, 8, 1, /* 3060: pointer.struct.asn1_string_st */
            	2740, 0,
            1, 8, 1, /* 3065: pointer.struct.X509_pubkey_st */
            	3070, 0,
            0, 24, 3, /* 3070: struct.X509_pubkey_st */
            	2656, 0,
            	2755, 8,
            	3079, 16,
            1, 8, 1, /* 3079: pointer.struct.evp_pkey_st */
            	3084, 0,
            0, 56, 4, /* 3084: struct.evp_pkey_st */
            	3095, 16,
            	2645, 24,
            	3103, 32,
            	3299, 48,
            1, 8, 1, /* 3095: pointer.struct.evp_pkey_asn1_method_st */
            	3100, 0,
            0, 0, 0, /* 3100: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 3103: union.unknown */
            	61, 0,
            	3116, 0,
            	3221, 0,
            	3226, 0,
            	3294, 0,
            1, 8, 1, /* 3116: pointer.struct.rsa_st */
            	3121, 0,
            0, 168, 17, /* 3121: struct.rsa_st */
            	3158, 16,
            	2645, 24,
            	2570, 32,
            	2570, 40,
            	2570, 48,
            	2570, 56,
            	2570, 64,
            	2570, 72,
            	2570, 80,
            	2570, 88,
            	2523, 96,
            	2580, 120,
            	2580, 128,
            	2580, 136,
            	61, 144,
            	3213, 152,
            	3213, 160,
            1, 8, 1, /* 3158: pointer.struct.rsa_meth_st */
            	3163, 0,
            0, 112, 13, /* 3163: struct.rsa_meth_st */
            	10, 0,
            	3192, 8,
            	3192, 16,
            	3192, 24,
            	3192, 32,
            	3195, 40,
            	3198, 48,
            	3201, 56,
            	3201, 64,
            	61, 80,
            	3204, 88,
            	3207, 96,
            	3210, 104,
            64097, 8, 0, /* 3192: pointer.func */
            64097, 8, 0, /* 3195: pointer.func */
            64097, 8, 0, /* 3198: pointer.func */
            64097, 8, 0, /* 3201: pointer.func */
            64097, 8, 0, /* 3204: pointer.func */
            64097, 8, 0, /* 3207: pointer.func */
            64097, 8, 0, /* 3210: pointer.func */
            1, 8, 1, /* 3213: pointer.struct.bn_blinding_st */
            	3218, 0,
            0, 0, 0, /* 3218: struct.bn_blinding_st */
            1, 8, 1, /* 3221: pointer.struct.dsa_st */
            	2545, 0,
            1, 8, 1, /* 3226: pointer.struct.dh_st */
            	3231, 0,
            0, 144, 12, /* 3231: struct.dh_st */
            	2570, 8,
            	2570, 16,
            	2570, 32,
            	2570, 40,
            	2580, 56,
            	2570, 64,
            	2570, 72,
            	209, 80,
            	2570, 96,
            	2523, 112,
            	3258, 128,
            	2645, 136,
            1, 8, 1, /* 3258: pointer.struct.dh_method */
            	3263, 0,
            0, 72, 8, /* 3263: struct.dh_method */
            	10, 0,
            	3282, 8,
            	3285, 16,
            	3288, 24,
            	3282, 32,
            	3282, 40,
            	61, 56,
            	3291, 64,
            64097, 8, 0, /* 3282: pointer.func */
            64097, 8, 0, /* 3285: pointer.func */
            64097, 8, 0, /* 3288: pointer.func */
            64097, 8, 0, /* 3291: pointer.func */
            1, 8, 1, /* 3294: pointer.struct.ec_key_st */
            	2847, 0,
            1, 8, 1, /* 3299: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3304, 0,
            0, 32, 2, /* 3304: struct.stack_st_fake_X509_ATTRIBUTE */
            	3311, 8,
            	456, 24,
            64099, 8, 2, /* 3311: pointer_to_array_of_pointers_to_stack */
            	3318, 0,
            	453, 20,
            0, 8, 1, /* 3318: pointer.X509_ATTRIBUTE */
            	872, 0,
            1, 8, 1, /* 3323: pointer.struct.stack_st_X509_EXTENSION */
            	3328, 0,
            0, 32, 2, /* 3328: struct.stack_st_fake_X509_EXTENSION */
            	3335, 8,
            	456, 24,
            64099, 8, 2, /* 3335: pointer_to_array_of_pointers_to_stack */
            	3342, 0,
            	453, 20,
            0, 8, 1, /* 3342: pointer.X509_EXTENSION */
            	1251, 0,
            0, 24, 1, /* 3347: struct.ASN1_ENCODING_st */
            	209, 0,
            1, 8, 1, /* 3352: pointer.struct.stack_st_GENERAL_NAME */
            	3357, 0,
            0, 32, 2, /* 3357: struct.stack_st_fake_GENERAL_NAME */
            	3364, 8,
            	456, 24,
            64099, 8, 2, /* 3364: pointer_to_array_of_pointers_to_stack */
            	3371, 0,
            	453, 20,
            0, 8, 1, /* 3371: pointer.GENERAL_NAME */
            	1330, 0,
            1, 8, 1, /* 3376: pointer.struct.NAME_CONSTRAINTS_st */
            	3381, 0,
            0, 0, 0, /* 3381: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 3384: pointer.struct.x509_cert_aux_st */
            	3389, 0,
            0, 40, 5, /* 3389: struct.x509_cert_aux_st */
            	3402, 0,
            	3402, 8,
            	2810, 16,
            	2760, 24,
            	3426, 32,
            1, 8, 1, /* 3402: pointer.struct.stack_st_ASN1_OBJECT */
            	3407, 0,
            0, 32, 2, /* 3407: struct.stack_st_fake_ASN1_OBJECT */
            	3414, 8,
            	456, 24,
            64099, 8, 2, /* 3414: pointer_to_array_of_pointers_to_stack */
            	3421, 0,
            	453, 20,
            0, 8, 1, /* 3421: pointer.ASN1_OBJECT */
            	2125, 0,
            1, 8, 1, /* 3426: pointer.struct.stack_st_X509_ALGOR */
            	3431, 0,
            0, 32, 2, /* 3431: struct.stack_st_fake_X509_ALGOR */
            	3438, 8,
            	456, 24,
            64099, 8, 2, /* 3438: pointer_to_array_of_pointers_to_stack */
            	3445, 0,
            	453, 20,
            0, 8, 1, /* 3445: pointer.X509_ALGOR */
            	2163, 0,
            1, 8, 1, /* 3450: pointer.struct.X509_crl_st */
            	3455, 0,
            0, 120, 10, /* 3455: struct.X509_crl_st */
            	3478, 0,
            	2656, 8,
            	2755, 16,
            	2850, 32,
            	3605, 40,
            	2745, 56,
            	2745, 64,
            	3613, 96,
            	3654, 104,
            	49, 112,
            1, 8, 1, /* 3478: pointer.struct.X509_crl_info_st */
            	3483, 0,
            0, 80, 8, /* 3483: struct.X509_crl_info_st */
            	2745, 0,
            	2656, 8,
            	3000, 16,
            	3060, 24,
            	3060, 32,
            	3502, 40,
            	3323, 48,
            	3347, 56,
            1, 8, 1, /* 3502: pointer.struct.stack_st_X509_REVOKED */
            	3507, 0,
            0, 32, 2, /* 3507: struct.stack_st_fake_X509_REVOKED */
            	3514, 8,
            	456, 24,
            64099, 8, 2, /* 3514: pointer_to_array_of_pointers_to_stack */
            	3521, 0,
            	453, 20,
            0, 8, 1, /* 3521: pointer.X509_REVOKED */
            	3526, 0,
            0, 0, 1, /* 3526: X509_REVOKED */
            	3531, 0,
            0, 40, 4, /* 3531: struct.x509_revoked_st */
            	3542, 0,
            	3552, 8,
            	3557, 16,
            	3581, 24,
            1, 8, 1, /* 3542: pointer.struct.asn1_string_st */
            	3547, 0,
            0, 24, 1, /* 3547: struct.asn1_string_st */
            	209, 8,
            1, 8, 1, /* 3552: pointer.struct.asn1_string_st */
            	3547, 0,
            1, 8, 1, /* 3557: pointer.struct.stack_st_X509_EXTENSION */
            	3562, 0,
            0, 32, 2, /* 3562: struct.stack_st_fake_X509_EXTENSION */
            	3569, 8,
            	456, 24,
            64099, 8, 2, /* 3569: pointer_to_array_of_pointers_to_stack */
            	3576, 0,
            	453, 20,
            0, 8, 1, /* 3576: pointer.X509_EXTENSION */
            	1251, 0,
            1, 8, 1, /* 3581: pointer.struct.stack_st_GENERAL_NAME */
            	3586, 0,
            0, 32, 2, /* 3586: struct.stack_st_fake_GENERAL_NAME */
            	3593, 8,
            	456, 24,
            64099, 8, 2, /* 3593: pointer_to_array_of_pointers_to_stack */
            	3600, 0,
            	453, 20,
            0, 8, 1, /* 3600: pointer.GENERAL_NAME */
            	1330, 0,
            1, 8, 1, /* 3605: pointer.struct.ISSUING_DIST_POINT_st */
            	3610, 0,
            0, 0, 0, /* 3610: struct.ISSUING_DIST_POINT_st */
            1, 8, 1, /* 3613: pointer.struct.stack_st_GENERAL_NAMES */
            	3618, 0,
            0, 32, 2, /* 3618: struct.stack_st_fake_GENERAL_NAMES */
            	3625, 8,
            	456, 24,
            64099, 8, 2, /* 3625: pointer_to_array_of_pointers_to_stack */
            	3632, 0,
            	453, 20,
            0, 8, 1, /* 3632: pointer.GENERAL_NAMES */
            	3637, 0,
            0, 0, 1, /* 3637: GENERAL_NAMES */
            	3642, 0,
            0, 32, 1, /* 3642: struct.stack_st_GENERAL_NAME */
            	3647, 0,
            0, 32, 2, /* 3647: struct.stack_st */
            	664, 8,
            	456, 24,
            1, 8, 1, /* 3654: pointer.struct.x509_crl_method_st */
            	3659, 0,
            0, 0, 0, /* 3659: struct.x509_crl_method_st */
            0, 104, 11, /* 3662: struct.x509_cinf_st */
            	3687, 0,
            	3687, 8,
            	3697, 16,
            	3854, 24,
            	3902, 32,
            	3854, 40,
            	3919, 48,
            	3786, 56,
            	3786, 64,
            	4304, 72,
            	4328, 80,
            1, 8, 1, /* 3687: pointer.struct.asn1_string_st */
            	3692, 0,
            0, 24, 1, /* 3692: struct.asn1_string_st */
            	209, 8,
            1, 8, 1, /* 3697: pointer.struct.X509_algor_st */
            	3702, 0,
            0, 16, 2, /* 3702: struct.X509_algor_st */
            	3709, 0,
            	3723, 8,
            1, 8, 1, /* 3709: pointer.struct.asn1_object_st */
            	3714, 0,
            0, 40, 3, /* 3714: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	243, 24,
            1, 8, 1, /* 3723: pointer.struct.asn1_type_st */
            	3728, 0,
            0, 16, 1, /* 3728: struct.asn1_type_st */
            	3733, 8,
            0, 8, 20, /* 3733: union.unknown */
            	61, 0,
            	3776, 0,
            	3709, 0,
            	3687, 0,
            	3781, 0,
            	3786, 0,
            	3791, 0,
            	3796, 0,
            	3801, 0,
            	3806, 0,
            	3811, 0,
            	3816, 0,
            	3821, 0,
            	3826, 0,
            	3831, 0,
            	3836, 0,
            	3841, 0,
            	3776, 0,
            	3776, 0,
            	3846, 0,
            1, 8, 1, /* 3776: pointer.struct.asn1_string_st */
            	3692, 0,
            1, 8, 1, /* 3781: pointer.struct.asn1_string_st */
            	3692, 0,
            1, 8, 1, /* 3786: pointer.struct.asn1_string_st */
            	3692, 0,
            1, 8, 1, /* 3791: pointer.struct.asn1_string_st */
            	3692, 0,
            1, 8, 1, /* 3796: pointer.struct.asn1_string_st */
            	3692, 0,
            1, 8, 1, /* 3801: pointer.struct.asn1_string_st */
            	3692, 0,
            1, 8, 1, /* 3806: pointer.struct.asn1_string_st */
            	3692, 0,
            1, 8, 1, /* 3811: pointer.struct.asn1_string_st */
            	3692, 0,
            1, 8, 1, /* 3816: pointer.struct.asn1_string_st */
            	3692, 0,
            1, 8, 1, /* 3821: pointer.struct.asn1_string_st */
            	3692, 0,
            1, 8, 1, /* 3826: pointer.struct.asn1_string_st */
            	3692, 0,
            1, 8, 1, /* 3831: pointer.struct.asn1_string_st */
            	3692, 0,
            1, 8, 1, /* 3836: pointer.struct.asn1_string_st */
            	3692, 0,
            1, 8, 1, /* 3841: pointer.struct.asn1_string_st */
            	3692, 0,
            1, 8, 1, /* 3846: pointer.struct.ASN1_VALUE_st */
            	3851, 0,
            0, 0, 0, /* 3851: struct.ASN1_VALUE_st */
            1, 8, 1, /* 3854: pointer.struct.X509_name_st */
            	3859, 0,
            0, 40, 3, /* 3859: struct.X509_name_st */
            	3868, 0,
            	3892, 16,
            	209, 24,
            1, 8, 1, /* 3868: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3873, 0,
            0, 32, 2, /* 3873: struct.stack_st_fake_X509_NAME_ENTRY */
            	3880, 8,
            	456, 24,
            64099, 8, 2, /* 3880: pointer_to_array_of_pointers_to_stack */
            	3887, 0,
            	453, 20,
            0, 8, 1, /* 3887: pointer.X509_NAME_ENTRY */
            	417, 0,
            1, 8, 1, /* 3892: pointer.struct.buf_mem_st */
            	3897, 0,
            0, 24, 1, /* 3897: struct.buf_mem_st */
            	61, 8,
            1, 8, 1, /* 3902: pointer.struct.X509_val_st */
            	3907, 0,
            0, 16, 2, /* 3907: struct.X509_val_st */
            	3914, 0,
            	3914, 8,
            1, 8, 1, /* 3914: pointer.struct.asn1_string_st */
            	3692, 0,
            1, 8, 1, /* 3919: pointer.struct.X509_pubkey_st */
            	3924, 0,
            0, 24, 3, /* 3924: struct.X509_pubkey_st */
            	3697, 0,
            	3786, 8,
            	3933, 16,
            1, 8, 1, /* 3933: pointer.struct.evp_pkey_st */
            	3938, 0,
            0, 56, 4, /* 3938: struct.evp_pkey_st */
            	3949, 16,
            	3957, 24,
            	3965, 32,
            	4280, 48,
            1, 8, 1, /* 3949: pointer.struct.evp_pkey_asn1_method_st */
            	3954, 0,
            0, 0, 0, /* 3954: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 3957: pointer.struct.engine_st */
            	3962, 0,
            0, 0, 0, /* 3962: struct.engine_st */
            0, 8, 5, /* 3965: union.unknown */
            	61, 0,
            	3978, 0,
            	4126, 0,
            	4204, 0,
            	4272, 0,
            1, 8, 1, /* 3978: pointer.struct.rsa_st */
            	3983, 0,
            0, 168, 17, /* 3983: struct.rsa_st */
            	4020, 16,
            	3957, 24,
            	4072, 32,
            	4072, 40,
            	4072, 48,
            	4072, 56,
            	4072, 64,
            	4072, 72,
            	4072, 80,
            	4072, 88,
            	4082, 96,
            	4104, 120,
            	4104, 128,
            	4104, 136,
            	61, 144,
            	4118, 152,
            	4118, 160,
            1, 8, 1, /* 4020: pointer.struct.rsa_meth_st */
            	4025, 0,
            0, 112, 13, /* 4025: struct.rsa_meth_st */
            	10, 0,
            	2919, 8,
            	2919, 16,
            	2919, 24,
            	2919, 32,
            	4054, 40,
            	4057, 48,
            	4060, 56,
            	4060, 64,
            	61, 80,
            	4063, 88,
            	4066, 96,
            	4069, 104,
            64097, 8, 0, /* 4054: pointer.func */
            64097, 8, 0, /* 4057: pointer.func */
            64097, 8, 0, /* 4060: pointer.func */
            64097, 8, 0, /* 4063: pointer.func */
            64097, 8, 0, /* 4066: pointer.func */
            64097, 8, 0, /* 4069: pointer.func */
            1, 8, 1, /* 4072: pointer.struct.bignum_st */
            	4077, 0,
            0, 24, 1, /* 4077: struct.bignum_st */
            	76, 0,
            0, 16, 1, /* 4082: struct.crypto_ex_data_st */
            	4087, 0,
            1, 8, 1, /* 4087: pointer.struct.stack_st_void */
            	4092, 0,
            0, 32, 1, /* 4092: struct.stack_st_void */
            	4097, 0,
            0, 32, 2, /* 4097: struct.stack_st */
            	664, 8,
            	456, 24,
            1, 8, 1, /* 4104: pointer.struct.bn_mont_ctx_st */
            	4109, 0,
            0, 96, 3, /* 4109: struct.bn_mont_ctx_st */
            	4077, 8,
            	4077, 32,
            	4077, 56,
            1, 8, 1, /* 4118: pointer.struct.bn_blinding_st */
            	4123, 0,
            0, 0, 0, /* 4123: struct.bn_blinding_st */
            1, 8, 1, /* 4126: pointer.struct.dsa_st */
            	4131, 0,
            0, 136, 11, /* 4131: struct.dsa_st */
            	4072, 24,
            	4072, 32,
            	4072, 40,
            	4072, 48,
            	4072, 56,
            	4072, 64,
            	4072, 72,
            	4104, 88,
            	4082, 104,
            	4156, 120,
            	3957, 128,
            1, 8, 1, /* 4156: pointer.struct.dsa_method */
            	4161, 0,
            0, 96, 11, /* 4161: struct.dsa_method */
            	10, 0,
            	4186, 8,
            	4189, 16,
            	4192, 24,
            	2913, 32,
            	4195, 40,
            	4198, 48,
            	4198, 56,
            	61, 72,
            	4201, 80,
            	4198, 88,
            64097, 8, 0, /* 4186: pointer.func */
            64097, 8, 0, /* 4189: pointer.func */
            64097, 8, 0, /* 4192: pointer.func */
            64097, 8, 0, /* 4195: pointer.func */
            64097, 8, 0, /* 4198: pointer.func */
            64097, 8, 0, /* 4201: pointer.func */
            1, 8, 1, /* 4204: pointer.struct.dh_st */
            	4209, 0,
            0, 144, 12, /* 4209: struct.dh_st */
            	4072, 8,
            	4072, 16,
            	4072, 32,
            	4072, 40,
            	4104, 56,
            	4072, 64,
            	4072, 72,
            	209, 80,
            	4072, 96,
            	4082, 112,
            	4236, 128,
            	3957, 136,
            1, 8, 1, /* 4236: pointer.struct.dh_method */
            	4241, 0,
            0, 72, 8, /* 4241: struct.dh_method */
            	10, 0,
            	4260, 8,
            	4263, 16,
            	4266, 24,
            	4260, 32,
            	4260, 40,
            	61, 56,
            	4269, 64,
            64097, 8, 0, /* 4260: pointer.func */
            64097, 8, 0, /* 4263: pointer.func */
            64097, 8, 0, /* 4266: pointer.func */
            64097, 8, 0, /* 4269: pointer.func */
            1, 8, 1, /* 4272: pointer.struct.ec_key_st */
            	4277, 0,
            0, 0, 0, /* 4277: struct.ec_key_st */
            1, 8, 1, /* 4280: pointer.struct.stack_st_X509_ATTRIBUTE */
            	4285, 0,
            0, 32, 2, /* 4285: struct.stack_st_fake_X509_ATTRIBUTE */
            	4292, 8,
            	456, 24,
            64099, 8, 2, /* 4292: pointer_to_array_of_pointers_to_stack */
            	4299, 0,
            	453, 20,
            0, 8, 1, /* 4299: pointer.X509_ATTRIBUTE */
            	872, 0,
            1, 8, 1, /* 4304: pointer.struct.stack_st_X509_EXTENSION */
            	4309, 0,
            0, 32, 2, /* 4309: struct.stack_st_fake_X509_EXTENSION */
            	4316, 8,
            	456, 24,
            64099, 8, 2, /* 4316: pointer_to_array_of_pointers_to_stack */
            	4323, 0,
            	453, 20,
            0, 8, 1, /* 4323: pointer.X509_EXTENSION */
            	1251, 0,
            0, 24, 1, /* 4328: struct.ASN1_ENCODING_st */
            	209, 0,
            0, 0, 0, /* 4333: struct.X509_POLICY_CACHE_st */
            64097, 8, 0, /* 4336: pointer.func */
            0, 8, 1, /* 4339: pointer.SRTP_PROTECTION_PROFILE */
            	0, 0,
            0, 0, 0, /* 4344: struct.NAME_CONSTRAINTS_st */
            64097, 8, 0, /* 4347: pointer.func */
            64097, 8, 0, /* 4350: pointer.func */
            64097, 8, 0, /* 4353: pointer.func */
            0, 0, 1, /* 4356: X509_OBJECT */
            	2922, 0,
            1, 8, 1, /* 4361: pointer.struct.stack_st_X509_OBJECT */
            	4366, 0,
            0, 32, 2, /* 4366: struct.stack_st_fake_X509_OBJECT */
            	4373, 8,
            	456, 24,
            64099, 8, 2, /* 4373: pointer_to_array_of_pointers_to_stack */
            	4380, 0,
            	453, 20,
            0, 8, 1, /* 4380: pointer.X509_OBJECT */
            	4356, 0,
            1, 8, 1, /* 4385: pointer.struct.ssl_method_st */
            	4390, 0,
            0, 232, 28, /* 4390: struct.ssl_method_st */
            	2895, 8,
            	4449, 16,
            	4449, 24,
            	2895, 32,
            	2895, 40,
            	4452, 48,
            	4452, 56,
            	4455, 64,
            	2895, 72,
            	2895, 80,
            	2895, 88,
            	4458, 96,
            	4353, 104,
            	4461, 112,
            	2895, 120,
            	4464, 128,
            	4467, 136,
            	4470, 144,
            	4473, 152,
            	4476, 160,
            	4479, 168,
            	4482, 176,
            	4485, 184,
            	2469, 192,
            	4488, 200,
            	4479, 208,
            	4493, 216,
            	4496, 224,
            64097, 8, 0, /* 4449: pointer.func */
            64097, 8, 0, /* 4452: pointer.func */
            64097, 8, 0, /* 4455: pointer.func */
            64097, 8, 0, /* 4458: pointer.func */
            64097, 8, 0, /* 4461: pointer.func */
            64097, 8, 0, /* 4464: pointer.func */
            64097, 8, 0, /* 4467: pointer.func */
            64097, 8, 0, /* 4470: pointer.func */
            64097, 8, 0, /* 4473: pointer.func */
            64097, 8, 0, /* 4476: pointer.func */
            64097, 8, 0, /* 4479: pointer.func */
            64097, 8, 0, /* 4482: pointer.func */
            64097, 8, 0, /* 4485: pointer.func */
            1, 8, 1, /* 4488: pointer.struct.ssl3_enc_method */
            	2864, 0,
            64097, 8, 0, /* 4493: pointer.func */
            64097, 8, 0, /* 4496: pointer.func */
            64097, 8, 0, /* 4499: pointer.func */
            0, 144, 15, /* 4502: struct.x509_store_st */
            	4361, 8,
            	4535, 16,
            	4741, 24,
            	4753, 32,
            	4756, 40,
            	4759, 48,
            	4762, 56,
            	4753, 64,
            	4765, 72,
            	2653, 80,
            	4768, 88,
            	2861, 96,
            	4771, 104,
            	4753, 112,
            	642, 120,
            1, 8, 1, /* 4535: pointer.struct.stack_st_X509_LOOKUP */
            	4540, 0,
            0, 32, 2, /* 4540: struct.stack_st_fake_X509_LOOKUP */
            	4547, 8,
            	456, 24,
            64099, 8, 2, /* 4547: pointer_to_array_of_pointers_to_stack */
            	4554, 0,
            	453, 20,
            0, 8, 1, /* 4554: pointer.X509_LOOKUP */
            	4559, 0,
            0, 0, 1, /* 4559: X509_LOOKUP */
            	4564, 0,
            0, 32, 3, /* 4564: struct.x509_lookup_st */
            	4573, 8,
            	61, 16,
            	4619, 24,
            1, 8, 1, /* 4573: pointer.struct.x509_lookup_method_st */
            	4578, 0,
            0, 80, 10, /* 4578: struct.x509_lookup_method_st */
            	10, 0,
            	4601, 8,
            	2858, 16,
            	4601, 24,
            	4601, 32,
            	4604, 40,
            	4607, 48,
            	4610, 56,
            	4613, 64,
            	4616, 72,
            64097, 8, 0, /* 4601: pointer.func */
            64097, 8, 0, /* 4604: pointer.func */
            64097, 8, 0, /* 4607: pointer.func */
            64097, 8, 0, /* 4610: pointer.func */
            64097, 8, 0, /* 4613: pointer.func */
            64097, 8, 0, /* 4616: pointer.func */
            1, 8, 1, /* 4619: pointer.struct.x509_store_st */
            	4624, 0,
            0, 144, 15, /* 4624: struct.x509_store_st */
            	4657, 8,
            	4681, 16,
            	4705, 24,
            	4717, 32,
            	4720, 40,
            	4723, 48,
            	4726, 56,
            	4717, 64,
            	4729, 72,
            	4732, 80,
            	4735, 88,
            	4738, 96,
            	4499, 104,
            	4717, 112,
            	2523, 120,
            1, 8, 1, /* 4657: pointer.struct.stack_st_X509_OBJECT */
            	4662, 0,
            0, 32, 2, /* 4662: struct.stack_st_fake_X509_OBJECT */
            	4669, 8,
            	456, 24,
            64099, 8, 2, /* 4669: pointer_to_array_of_pointers_to_stack */
            	4676, 0,
            	453, 20,
            0, 8, 1, /* 4676: pointer.X509_OBJECT */
            	4356, 0,
            1, 8, 1, /* 4681: pointer.struct.stack_st_X509_LOOKUP */
            	4686, 0,
            0, 32, 2, /* 4686: struct.stack_st_fake_X509_LOOKUP */
            	4693, 8,
            	456, 24,
            64099, 8, 2, /* 4693: pointer_to_array_of_pointers_to_stack */
            	4700, 0,
            	453, 20,
            0, 8, 1, /* 4700: pointer.X509_LOOKUP */
            	4559, 0,
            1, 8, 1, /* 4705: pointer.struct.X509_VERIFY_PARAM_st */
            	4710, 0,
            0, 56, 2, /* 4710: struct.X509_VERIFY_PARAM_st */
            	61, 0,
            	3402, 48,
            64097, 8, 0, /* 4717: pointer.func */
            64097, 8, 0, /* 4720: pointer.func */
            64097, 8, 0, /* 4723: pointer.func */
            64097, 8, 0, /* 4726: pointer.func */
            64097, 8, 0, /* 4729: pointer.func */
            64097, 8, 0, /* 4732: pointer.func */
            64097, 8, 0, /* 4735: pointer.func */
            64097, 8, 0, /* 4738: pointer.func */
            1, 8, 1, /* 4741: pointer.struct.X509_VERIFY_PARAM_st */
            	4746, 0,
            0, 56, 2, /* 4746: struct.X509_VERIFY_PARAM_st */
            	61, 0,
            	2101, 48,
            64097, 8, 0, /* 4753: pointer.func */
            64097, 8, 0, /* 4756: pointer.func */
            64097, 8, 0, /* 4759: pointer.func */
            64097, 8, 0, /* 4762: pointer.func */
            64097, 8, 0, /* 4765: pointer.func */
            64097, 8, 0, /* 4768: pointer.func */
            64097, 8, 0, /* 4771: pointer.func */
            0, 32, 2, /* 4774: struct.stack_st_fake_SRTP_PROTECTION_PROFILE */
            	4781, 8,
            	456, 24,
            64099, 8, 2, /* 4781: pointer_to_array_of_pointers_to_stack */
            	4339, 0,
            	453, 20,
            1, 8, 1, /* 4788: pointer.struct.stack_st_X509_ALGOR */
            	4793, 0,
            0, 32, 2, /* 4793: struct.stack_st_fake_X509_ALGOR */
            	4800, 8,
            	456, 24,
            64099, 8, 2, /* 4800: pointer_to_array_of_pointers_to_stack */
            	4807, 0,
            	453, 20,
            0, 8, 1, /* 4807: pointer.X509_ALGOR */
            	2163, 0,
            1, 8, 1, /* 4812: pointer.struct.x509_store_st */
            	4502, 0,
            1, 8, 1, /* 4817: pointer.struct.stack_st_SSL_CIPHER */
            	4822, 0,
            0, 32, 2, /* 4822: struct.stack_st_fake_SSL_CIPHER */
            	4829, 8,
            	456, 24,
            64099, 8, 2, /* 4829: pointer_to_array_of_pointers_to_stack */
            	4836, 0,
            	453, 20,
            0, 8, 1, /* 4836: pointer.SSL_CIPHER */
            	4841, 0,
            0, 0, 1, /* 4841: SSL_CIPHER */
            	4846, 0,
            0, 88, 1, /* 4846: struct.ssl_cipher_st */
            	10, 8,
            1, 8, 1, /* 4851: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	4774, 0,
            64097, 8, 0, /* 4856: pointer.func */
            1, 8, 1, /* 4859: pointer.struct.lhash_node_st */
            	4864, 0,
            0, 24, 2, /* 4864: struct.lhash_node_st */
            	49, 0,
            	4871, 8,
            1, 8, 1, /* 4871: pointer.struct.lhash_node_st */
            	4864, 0,
            0, 736, 50, /* 4876: struct.ssl_ctx_st */
            	4385, 0,
            	4817, 8,
            	4817, 16,
            	4812, 24,
            	4979, 32,
            	4998, 48,
            	4998, 56,
            	5221, 80,
            	5224, 88,
            	2507, 96,
            	4336, 152,
            	49, 160,
            	5227, 168,
            	49, 176,
            	2504, 184,
            	5230, 192,
            	2501, 200,
            	642, 208,
            	2322, 224,
            	2322, 232,
            	2322, 240,
            	5052, 248,
            	2472, 256,
            	2428, 264,
            	5233, 272,
            	5262, 304,
            	2520, 320,
            	49, 328,
            	4756, 376,
            	5267, 384,
            	4741, 392,
            	524, 408,
            	52, 416,
            	49, 424,
            	4350, 480,
            	55, 488,
            	49, 496,
            	97, 504,
            	49, 512,
            	61, 520,
            	94, 528,
            	4856, 536,
            	5270, 552,
            	5270, 560,
            	18, 568,
            	15, 696,
            	49, 704,
            	2916, 712,
            	49, 720,
            	4851, 728,
            1, 8, 1, /* 4979: pointer.struct.lhash_st */
            	4984, 0,
            0, 176, 3, /* 4984: struct.lhash_st */
            	4993, 0,
            	456, 8,
            	4347, 16,
            1, 8, 1, /* 4993: pointer.pointer.struct.lhash_node_st */
            	4859, 0,
            1, 8, 1, /* 4998: pointer.struct.ssl_session_st */
            	5003, 0,
            0, 352, 14, /* 5003: struct.ssl_session_st */
            	61, 144,
            	61, 152,
            	5034, 168,
            	137, 176,
            	2515, 224,
            	4817, 240,
            	642, 248,
            	4998, 264,
            	4998, 272,
            	61, 280,
            	209, 296,
            	209, 312,
            	209, 320,
            	61, 344,
            1, 8, 1, /* 5034: pointer.struct.sess_cert_st */
            	5039, 0,
            0, 248, 5, /* 5039: struct.sess_cert_st */
            	5052, 0,
            	123, 16,
            	2367, 216,
            	2375, 224,
            	2380, 232,
            1, 8, 1, /* 5052: pointer.struct.stack_st_X509 */
            	5057, 0,
            0, 32, 2, /* 5057: struct.stack_st_fake_X509 */
            	5064, 8,
            	456, 24,
            64099, 8, 2, /* 5064: pointer_to_array_of_pointers_to_stack */
            	5071, 0,
            	453, 20,
            0, 8, 1, /* 5071: pointer.X509 */
            	5076, 0,
            0, 0, 1, /* 5076: X509 */
            	5081, 0,
            0, 184, 12, /* 5081: struct.x509_st */
            	5108, 0,
            	3697, 8,
            	3786, 16,
            	61, 32,
            	4082, 40,
            	3791, 104,
            	5113, 112,
            	5121, 120,
            	5126, 128,
            	5150, 136,
            	5174, 144,
            	5179, 176,
            1, 8, 1, /* 5108: pointer.struct.x509_cinf_st */
            	3662, 0,
            1, 8, 1, /* 5113: pointer.struct.AUTHORITY_KEYID_st */
            	5118, 0,
            0, 0, 0, /* 5118: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 5121: pointer.struct.X509_POLICY_CACHE_st */
            	4333, 0,
            1, 8, 1, /* 5126: pointer.struct.stack_st_DIST_POINT */
            	5131, 0,
            0, 32, 2, /* 5131: struct.stack_st_fake_DIST_POINT */
            	5138, 8,
            	456, 24,
            64099, 8, 2, /* 5138: pointer_to_array_of_pointers_to_stack */
            	5145, 0,
            	453, 20,
            0, 8, 1, /* 5145: pointer.DIST_POINT */
            	1632, 0,
            1, 8, 1, /* 5150: pointer.struct.stack_st_GENERAL_NAME */
            	5155, 0,
            0, 32, 2, /* 5155: struct.stack_st_fake_GENERAL_NAME */
            	5162, 8,
            	456, 24,
            64099, 8, 2, /* 5162: pointer_to_array_of_pointers_to_stack */
            	5169, 0,
            	453, 20,
            0, 8, 1, /* 5169: pointer.GENERAL_NAME */
            	1330, 0,
            1, 8, 1, /* 5174: pointer.struct.NAME_CONSTRAINTS_st */
            	4344, 0,
            1, 8, 1, /* 5179: pointer.struct.x509_cert_aux_st */
            	5184, 0,
            0, 40, 5, /* 5184: struct.x509_cert_aux_st */
            	5197, 0,
            	5197, 8,
            	3841, 16,
            	3791, 24,
            	4788, 32,
            1, 8, 1, /* 5197: pointer.struct.stack_st_ASN1_OBJECT */
            	5202, 0,
            0, 32, 2, /* 5202: struct.stack_st_fake_ASN1_OBJECT */
            	5209, 8,
            	456, 24,
            64099, 8, 2, /* 5209: pointer_to_array_of_pointers_to_stack */
            	5216, 0,
            	453, 20,
            0, 8, 1, /* 5216: pointer.ASN1_OBJECT */
            	2125, 0,
            64097, 8, 0, /* 5221: pointer.func */
            64097, 8, 0, /* 5224: pointer.func */
            64097, 8, 0, /* 5227: pointer.func */
            64097, 8, 0, /* 5230: pointer.func */
            1, 8, 1, /* 5233: pointer.struct.stack_st_X509_NAME */
            	5238, 0,
            0, 32, 2, /* 5238: struct.stack_st_fake_X509_NAME */
            	5245, 8,
            	456, 24,
            64099, 8, 2, /* 5245: pointer_to_array_of_pointers_to_stack */
            	5252, 0,
            	453, 20,
            0, 8, 1, /* 5252: pointer.X509_NAME */
            	5257, 0,
            0, 0, 1, /* 5257: X509_NAME */
            	2385, 0,
            1, 8, 1, /* 5262: pointer.struct.cert_st */
            	106, 0,
            64097, 8, 0, /* 5267: pointer.func */
            1, 8, 1, /* 5270: pointer.struct.ssl3_buf_freelist_st */
            	5275, 0,
            0, 24, 1, /* 5275: struct.ssl3_buf_freelist_st */
            	84, 16,
            1, 8, 1, /* 5280: pointer.struct.ssl_ctx_st */
            	4876, 0,
            0, 1, 0, /* 5285: char */
        },
        .arg_entity_index = { 5280, 10, },
        .ret_entity_index = 453,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    SSL_CTX * new_arg_a = *((SSL_CTX * *)new_args->args[0]);

    const char * new_arg_b = *((const char * *)new_args->args[1]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_SSL_CTX_set_cipher_list)(SSL_CTX *,const char *);
    orig_SSL_CTX_set_cipher_list = dlsym(RTLD_NEXT, "SSL_CTX_set_cipher_list");
    *new_ret_ptr = (*orig_SSL_CTX_set_cipher_list)(new_arg_a,new_arg_b);

    syscall(889);

    return ret;
}

