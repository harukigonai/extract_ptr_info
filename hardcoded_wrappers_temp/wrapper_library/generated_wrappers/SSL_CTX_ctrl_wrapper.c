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

long bb_SSL_CTX_ctrl(SSL_CTX * arg_a,int arg_b,long arg_c,void * arg_d);

long SSL_CTX_ctrl(SSL_CTX * arg_a,int arg_b,long arg_c,void * arg_d) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_CTX_ctrl called %lu\n", in_lib);
    if (!in_lib)
        return bb_SSL_CTX_ctrl(arg_a,arg_b,arg_c,arg_d);
    else {
        long (*orig_SSL_CTX_ctrl)(SSL_CTX *,int,long,void *);
        orig_SSL_CTX_ctrl = dlsym(RTLD_NEXT, "SSL_CTX_ctrl");
        return orig_SSL_CTX_ctrl(arg_a,arg_b,arg_c,arg_d);
    }
}

long bb_SSL_CTX_ctrl(SSL_CTX * arg_a,int arg_b,long arg_c,void * arg_d) 
{
    long ret;

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
            0, 16, 1, /* 2254: struct.crypto_ex_data_st */
            	2259, 0,
            1, 8, 1, /* 2259: pointer.struct.stack_st_void */
            	2264, 0,
            0, 32, 1, /* 2264: struct.stack_st_void */
            	2269, 0,
            0, 32, 2, /* 2269: struct.stack_st */
            	664, 8,
            	456, 24,
            1, 8, 1, /* 2276: pointer.struct.asn1_string_st */
            	2281, 0,
            0, 24, 1, /* 2281: struct.asn1_string_st */
            	209, 8,
            0, 24, 1, /* 2286: struct.buf_mem_st */
            	61, 8,
            0, 24, 1, /* 2291: struct.ASN1_ENCODING_st */
            	209, 0,
            1, 8, 1, /* 2296: pointer.struct.ssl_cipher_st */
            	2249, 0,
            8884097, 8, 0, /* 2301: pointer.func */
            0, 144, 12, /* 2304: struct.dh_st */
            	2331, 8,
            	2331, 16,
            	2331, 32,
            	2331, 40,
            	2341, 56,
            	2331, 64,
            	2331, 72,
            	209, 80,
            	2331, 96,
            	2355, 112,
            	2377, 128,
            	2413, 136,
            1, 8, 1, /* 2331: pointer.struct.bignum_st */
            	2336, 0,
            0, 24, 1, /* 2336: struct.bignum_st */
            	76, 0,
            1, 8, 1, /* 2341: pointer.struct.bn_mont_ctx_st */
            	2346, 0,
            0, 96, 3, /* 2346: struct.bn_mont_ctx_st */
            	2336, 8,
            	2336, 32,
            	2336, 56,
            0, 16, 1, /* 2355: struct.crypto_ex_data_st */
            	2360, 0,
            1, 8, 1, /* 2360: pointer.struct.stack_st_void */
            	2365, 0,
            0, 32, 1, /* 2365: struct.stack_st_void */
            	2370, 0,
            0, 32, 2, /* 2370: struct.stack_st */
            	664, 8,
            	456, 24,
            1, 8, 1, /* 2377: pointer.struct.dh_method */
            	2382, 0,
            0, 72, 8, /* 2382: struct.dh_method */
            	10, 0,
            	2401, 8,
            	2404, 16,
            	2407, 24,
            	2401, 32,
            	2401, 40,
            	61, 56,
            	2410, 64,
            8884097, 8, 0, /* 2401: pointer.func */
            8884097, 8, 0, /* 2404: pointer.func */
            8884097, 8, 0, /* 2407: pointer.func */
            8884097, 8, 0, /* 2410: pointer.func */
            1, 8, 1, /* 2413: pointer.struct.engine_st */
            	2418, 0,
            0, 0, 0, /* 2418: struct.engine_st */
            0, 0, 1, /* 2421: X509_LOOKUP */
            	2426, 0,
            0, 32, 3, /* 2426: struct.x509_lookup_st */
            	2435, 8,
            	61, 16,
            	2484, 24,
            1, 8, 1, /* 2435: pointer.struct.x509_lookup_method_st */
            	2440, 0,
            0, 80, 10, /* 2440: struct.x509_lookup_method_st */
            	10, 0,
            	2463, 8,
            	2466, 16,
            	2463, 24,
            	2463, 32,
            	2469, 40,
            	2472, 48,
            	2475, 56,
            	2478, 64,
            	2481, 72,
            8884097, 8, 0, /* 2463: pointer.func */
            8884097, 8, 0, /* 2466: pointer.func */
            8884097, 8, 0, /* 2469: pointer.func */
            8884097, 8, 0, /* 2472: pointer.func */
            8884097, 8, 0, /* 2475: pointer.func */
            8884097, 8, 0, /* 2478: pointer.func */
            8884097, 8, 0, /* 2481: pointer.func */
            1, 8, 1, /* 2484: pointer.struct.x509_store_st */
            	2489, 0,
            0, 144, 15, /* 2489: struct.x509_store_st */
            	2522, 8,
            	3581, 16,
            	3605, 24,
            	3617, 32,
            	3620, 40,
            	3623, 48,
            	3626, 56,
            	3617, 64,
            	3629, 72,
            	3632, 80,
            	3635, 88,
            	3638, 96,
            	3641, 104,
            	3617, 112,
            	2254, 120,
            1, 8, 1, /* 2522: pointer.struct.stack_st_X509_OBJECT */
            	2527, 0,
            0, 32, 2, /* 2527: struct.stack_st_fake_X509_OBJECT */
            	2534, 8,
            	456, 24,
            8884099, 8, 2, /* 2534: pointer_to_array_of_pointers_to_stack */
            	2541, 0,
            	453, 20,
            0, 8, 1, /* 2541: pointer.X509_OBJECT */
            	2546, 0,
            0, 0, 1, /* 2546: X509_OBJECT */
            	2551, 0,
            0, 16, 1, /* 2551: struct.x509_object_st */
            	2556, 8,
            0, 8, 4, /* 2556: union.unknown */
            	61, 0,
            	2567, 0,
            	3369, 0,
            	2852, 0,
            1, 8, 1, /* 2567: pointer.struct.x509_st */
            	2572, 0,
            0, 184, 12, /* 2572: struct.x509_st */
            	2599, 0,
            	2634, 8,
            	2723, 16,
            	61, 32,
            	2254, 40,
            	2276, 104,
            	3231, 112,
            	3239, 120,
            	3247, 128,
            	3271, 136,
            	3295, 144,
            	3303, 176,
            1, 8, 1, /* 2599: pointer.struct.x509_cinf_st */
            	2604, 0,
            0, 104, 11, /* 2604: struct.x509_cinf_st */
            	2629, 0,
            	2629, 8,
            	2634, 16,
            	2778, 24,
            	2821, 32,
            	2778, 40,
            	2838, 48,
            	2723, 56,
            	2723, 64,
            	3207, 72,
            	2291, 80,
            1, 8, 1, /* 2629: pointer.struct.asn1_string_st */
            	2281, 0,
            1, 8, 1, /* 2634: pointer.struct.X509_algor_st */
            	2639, 0,
            0, 16, 2, /* 2639: struct.X509_algor_st */
            	2646, 0,
            	2660, 8,
            1, 8, 1, /* 2646: pointer.struct.asn1_object_st */
            	2651, 0,
            0, 40, 3, /* 2651: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	243, 24,
            1, 8, 1, /* 2660: pointer.struct.asn1_type_st */
            	2665, 0,
            0, 16, 1, /* 2665: struct.asn1_type_st */
            	2670, 8,
            0, 8, 20, /* 2670: union.unknown */
            	61, 0,
            	2713, 0,
            	2646, 0,
            	2629, 0,
            	2718, 0,
            	2723, 0,
            	2276, 0,
            	2728, 0,
            	2733, 0,
            	2738, 0,
            	2743, 0,
            	2748, 0,
            	2753, 0,
            	2758, 0,
            	2763, 0,
            	2768, 0,
            	2773, 0,
            	2713, 0,
            	2713, 0,
            	1219, 0,
            1, 8, 1, /* 2713: pointer.struct.asn1_string_st */
            	2281, 0,
            1, 8, 1, /* 2718: pointer.struct.asn1_string_st */
            	2281, 0,
            1, 8, 1, /* 2723: pointer.struct.asn1_string_st */
            	2281, 0,
            1, 8, 1, /* 2728: pointer.struct.asn1_string_st */
            	2281, 0,
            1, 8, 1, /* 2733: pointer.struct.asn1_string_st */
            	2281, 0,
            1, 8, 1, /* 2738: pointer.struct.asn1_string_st */
            	2281, 0,
            1, 8, 1, /* 2743: pointer.struct.asn1_string_st */
            	2281, 0,
            1, 8, 1, /* 2748: pointer.struct.asn1_string_st */
            	2281, 0,
            1, 8, 1, /* 2753: pointer.struct.asn1_string_st */
            	2281, 0,
            1, 8, 1, /* 2758: pointer.struct.asn1_string_st */
            	2281, 0,
            1, 8, 1, /* 2763: pointer.struct.asn1_string_st */
            	2281, 0,
            1, 8, 1, /* 2768: pointer.struct.asn1_string_st */
            	2281, 0,
            1, 8, 1, /* 2773: pointer.struct.asn1_string_st */
            	2281, 0,
            1, 8, 1, /* 2778: pointer.struct.X509_name_st */
            	2783, 0,
            0, 40, 3, /* 2783: struct.X509_name_st */
            	2792, 0,
            	2816, 16,
            	209, 24,
            1, 8, 1, /* 2792: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2797, 0,
            0, 32, 2, /* 2797: struct.stack_st_fake_X509_NAME_ENTRY */
            	2804, 8,
            	456, 24,
            8884099, 8, 2, /* 2804: pointer_to_array_of_pointers_to_stack */
            	2811, 0,
            	453, 20,
            0, 8, 1, /* 2811: pointer.X509_NAME_ENTRY */
            	417, 0,
            1, 8, 1, /* 2816: pointer.struct.buf_mem_st */
            	2286, 0,
            1, 8, 1, /* 2821: pointer.struct.X509_val_st */
            	2826, 0,
            0, 16, 2, /* 2826: struct.X509_val_st */
            	2833, 0,
            	2833, 8,
            1, 8, 1, /* 2833: pointer.struct.asn1_string_st */
            	2281, 0,
            1, 8, 1, /* 2838: pointer.struct.X509_pubkey_st */
            	2843, 0,
            0, 24, 3, /* 2843: struct.X509_pubkey_st */
            	2634, 0,
            	2723, 8,
            	2852, 16,
            1, 8, 1, /* 2852: pointer.struct.evp_pkey_st */
            	2857, 0,
            0, 56, 4, /* 2857: struct.evp_pkey_st */
            	2868, 16,
            	2876, 24,
            	2884, 32,
            	3183, 48,
            1, 8, 1, /* 2868: pointer.struct.evp_pkey_asn1_method_st */
            	2873, 0,
            0, 0, 0, /* 2873: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 2876: pointer.struct.engine_st */
            	2881, 0,
            0, 0, 0, /* 2881: struct.engine_st */
            0, 8, 5, /* 2884: union.unknown */
            	61, 0,
            	2897, 0,
            	3026, 0,
            	3107, 0,
            	3175, 0,
            1, 8, 1, /* 2897: pointer.struct.rsa_st */
            	2902, 0,
            0, 168, 17, /* 2902: struct.rsa_st */
            	2939, 16,
            	2876, 24,
            	2994, 32,
            	2994, 40,
            	2994, 48,
            	2994, 56,
            	2994, 64,
            	2994, 72,
            	2994, 80,
            	2994, 88,
            	2254, 96,
            	3004, 120,
            	3004, 128,
            	3004, 136,
            	61, 144,
            	3018, 152,
            	3018, 160,
            1, 8, 1, /* 2939: pointer.struct.rsa_meth_st */
            	2944, 0,
            0, 112, 13, /* 2944: struct.rsa_meth_st */
            	10, 0,
            	2973, 8,
            	2973, 16,
            	2973, 24,
            	2973, 32,
            	2976, 40,
            	2979, 48,
            	2982, 56,
            	2982, 64,
            	61, 80,
            	2985, 88,
            	2988, 96,
            	2991, 104,
            8884097, 8, 0, /* 2973: pointer.func */
            8884097, 8, 0, /* 2976: pointer.func */
            8884097, 8, 0, /* 2979: pointer.func */
            8884097, 8, 0, /* 2982: pointer.func */
            8884097, 8, 0, /* 2985: pointer.func */
            8884097, 8, 0, /* 2988: pointer.func */
            8884097, 8, 0, /* 2991: pointer.func */
            1, 8, 1, /* 2994: pointer.struct.bignum_st */
            	2999, 0,
            0, 24, 1, /* 2999: struct.bignum_st */
            	76, 0,
            1, 8, 1, /* 3004: pointer.struct.bn_mont_ctx_st */
            	3009, 0,
            0, 96, 3, /* 3009: struct.bn_mont_ctx_st */
            	2999, 8,
            	2999, 32,
            	2999, 56,
            1, 8, 1, /* 3018: pointer.struct.bn_blinding_st */
            	3023, 0,
            0, 0, 0, /* 3023: struct.bn_blinding_st */
            1, 8, 1, /* 3026: pointer.struct.dsa_st */
            	3031, 0,
            0, 136, 11, /* 3031: struct.dsa_st */
            	2994, 24,
            	2994, 32,
            	2994, 40,
            	2994, 48,
            	2994, 56,
            	2994, 64,
            	2994, 72,
            	3004, 88,
            	2254, 104,
            	3056, 120,
            	2876, 128,
            1, 8, 1, /* 3056: pointer.struct.dsa_method */
            	3061, 0,
            0, 96, 11, /* 3061: struct.dsa_method */
            	10, 0,
            	3086, 8,
            	3089, 16,
            	3092, 24,
            	3095, 32,
            	3098, 40,
            	3101, 48,
            	3101, 56,
            	61, 72,
            	3104, 80,
            	3101, 88,
            8884097, 8, 0, /* 3086: pointer.func */
            8884097, 8, 0, /* 3089: pointer.func */
            8884097, 8, 0, /* 3092: pointer.func */
            8884097, 8, 0, /* 3095: pointer.func */
            8884097, 8, 0, /* 3098: pointer.func */
            8884097, 8, 0, /* 3101: pointer.func */
            8884097, 8, 0, /* 3104: pointer.func */
            1, 8, 1, /* 3107: pointer.struct.dh_st */
            	3112, 0,
            0, 144, 12, /* 3112: struct.dh_st */
            	2994, 8,
            	2994, 16,
            	2994, 32,
            	2994, 40,
            	3004, 56,
            	2994, 64,
            	2994, 72,
            	209, 80,
            	2994, 96,
            	2254, 112,
            	3139, 128,
            	2876, 136,
            1, 8, 1, /* 3139: pointer.struct.dh_method */
            	3144, 0,
            0, 72, 8, /* 3144: struct.dh_method */
            	10, 0,
            	3163, 8,
            	3166, 16,
            	3169, 24,
            	3163, 32,
            	3163, 40,
            	61, 56,
            	3172, 64,
            8884097, 8, 0, /* 3163: pointer.func */
            8884097, 8, 0, /* 3166: pointer.func */
            8884097, 8, 0, /* 3169: pointer.func */
            8884097, 8, 0, /* 3172: pointer.func */
            1, 8, 1, /* 3175: pointer.struct.ec_key_st */
            	3180, 0,
            0, 0, 0, /* 3180: struct.ec_key_st */
            1, 8, 1, /* 3183: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3188, 0,
            0, 32, 2, /* 3188: struct.stack_st_fake_X509_ATTRIBUTE */
            	3195, 8,
            	456, 24,
            8884099, 8, 2, /* 3195: pointer_to_array_of_pointers_to_stack */
            	3202, 0,
            	453, 20,
            0, 8, 1, /* 3202: pointer.X509_ATTRIBUTE */
            	872, 0,
            1, 8, 1, /* 3207: pointer.struct.stack_st_X509_EXTENSION */
            	3212, 0,
            0, 32, 2, /* 3212: struct.stack_st_fake_X509_EXTENSION */
            	3219, 8,
            	456, 24,
            8884099, 8, 2, /* 3219: pointer_to_array_of_pointers_to_stack */
            	3226, 0,
            	453, 20,
            0, 8, 1, /* 3226: pointer.X509_EXTENSION */
            	1251, 0,
            1, 8, 1, /* 3231: pointer.struct.AUTHORITY_KEYID_st */
            	3236, 0,
            0, 0, 0, /* 3236: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 3239: pointer.struct.X509_POLICY_CACHE_st */
            	3244, 0,
            0, 0, 0, /* 3244: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 3247: pointer.struct.stack_st_DIST_POINT */
            	3252, 0,
            0, 32, 2, /* 3252: struct.stack_st_fake_DIST_POINT */
            	3259, 8,
            	456, 24,
            8884099, 8, 2, /* 3259: pointer_to_array_of_pointers_to_stack */
            	3266, 0,
            	453, 20,
            0, 8, 1, /* 3266: pointer.DIST_POINT */
            	1632, 0,
            1, 8, 1, /* 3271: pointer.struct.stack_st_GENERAL_NAME */
            	3276, 0,
            0, 32, 2, /* 3276: struct.stack_st_fake_GENERAL_NAME */
            	3283, 8,
            	456, 24,
            8884099, 8, 2, /* 3283: pointer_to_array_of_pointers_to_stack */
            	3290, 0,
            	453, 20,
            0, 8, 1, /* 3290: pointer.GENERAL_NAME */
            	1330, 0,
            1, 8, 1, /* 3295: pointer.struct.NAME_CONSTRAINTS_st */
            	3300, 0,
            0, 0, 0, /* 3300: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 3303: pointer.struct.x509_cert_aux_st */
            	3308, 0,
            0, 40, 5, /* 3308: struct.x509_cert_aux_st */
            	3321, 0,
            	3321, 8,
            	2773, 16,
            	2276, 24,
            	3345, 32,
            1, 8, 1, /* 3321: pointer.struct.stack_st_ASN1_OBJECT */
            	3326, 0,
            0, 32, 2, /* 3326: struct.stack_st_fake_ASN1_OBJECT */
            	3333, 8,
            	456, 24,
            8884099, 8, 2, /* 3333: pointer_to_array_of_pointers_to_stack */
            	3340, 0,
            	453, 20,
            0, 8, 1, /* 3340: pointer.ASN1_OBJECT */
            	1868, 0,
            1, 8, 1, /* 3345: pointer.struct.stack_st_X509_ALGOR */
            	3350, 0,
            0, 32, 2, /* 3350: struct.stack_st_fake_X509_ALGOR */
            	3357, 8,
            	456, 24,
            8884099, 8, 2, /* 3357: pointer_to_array_of_pointers_to_stack */
            	3364, 0,
            	453, 20,
            0, 8, 1, /* 3364: pointer.X509_ALGOR */
            	1897, 0,
            1, 8, 1, /* 3369: pointer.struct.X509_crl_st */
            	3374, 0,
            0, 120, 10, /* 3374: struct.X509_crl_st */
            	3397, 0,
            	2634, 8,
            	2723, 16,
            	3231, 32,
            	3524, 40,
            	2629, 56,
            	2629, 64,
            	3532, 96,
            	3573, 104,
            	49, 112,
            1, 8, 1, /* 3397: pointer.struct.X509_crl_info_st */
            	3402, 0,
            0, 80, 8, /* 3402: struct.X509_crl_info_st */
            	2629, 0,
            	2634, 8,
            	2778, 16,
            	2833, 24,
            	2833, 32,
            	3421, 40,
            	3207, 48,
            	2291, 56,
            1, 8, 1, /* 3421: pointer.struct.stack_st_X509_REVOKED */
            	3426, 0,
            0, 32, 2, /* 3426: struct.stack_st_fake_X509_REVOKED */
            	3433, 8,
            	456, 24,
            8884099, 8, 2, /* 3433: pointer_to_array_of_pointers_to_stack */
            	3440, 0,
            	453, 20,
            0, 8, 1, /* 3440: pointer.X509_REVOKED */
            	3445, 0,
            0, 0, 1, /* 3445: X509_REVOKED */
            	3450, 0,
            0, 40, 4, /* 3450: struct.x509_revoked_st */
            	3461, 0,
            	3471, 8,
            	3476, 16,
            	3500, 24,
            1, 8, 1, /* 3461: pointer.struct.asn1_string_st */
            	3466, 0,
            0, 24, 1, /* 3466: struct.asn1_string_st */
            	209, 8,
            1, 8, 1, /* 3471: pointer.struct.asn1_string_st */
            	3466, 0,
            1, 8, 1, /* 3476: pointer.struct.stack_st_X509_EXTENSION */
            	3481, 0,
            0, 32, 2, /* 3481: struct.stack_st_fake_X509_EXTENSION */
            	3488, 8,
            	456, 24,
            8884099, 8, 2, /* 3488: pointer_to_array_of_pointers_to_stack */
            	3495, 0,
            	453, 20,
            0, 8, 1, /* 3495: pointer.X509_EXTENSION */
            	1251, 0,
            1, 8, 1, /* 3500: pointer.struct.stack_st_GENERAL_NAME */
            	3505, 0,
            0, 32, 2, /* 3505: struct.stack_st_fake_GENERAL_NAME */
            	3512, 8,
            	456, 24,
            8884099, 8, 2, /* 3512: pointer_to_array_of_pointers_to_stack */
            	3519, 0,
            	453, 20,
            0, 8, 1, /* 3519: pointer.GENERAL_NAME */
            	1330, 0,
            1, 8, 1, /* 3524: pointer.struct.ISSUING_DIST_POINT_st */
            	3529, 0,
            0, 0, 0, /* 3529: struct.ISSUING_DIST_POINT_st */
            1, 8, 1, /* 3532: pointer.struct.stack_st_GENERAL_NAMES */
            	3537, 0,
            0, 32, 2, /* 3537: struct.stack_st_fake_GENERAL_NAMES */
            	3544, 8,
            	456, 24,
            8884099, 8, 2, /* 3544: pointer_to_array_of_pointers_to_stack */
            	3551, 0,
            	453, 20,
            0, 8, 1, /* 3551: pointer.GENERAL_NAMES */
            	3556, 0,
            0, 0, 1, /* 3556: GENERAL_NAMES */
            	3561, 0,
            0, 32, 1, /* 3561: struct.stack_st_GENERAL_NAME */
            	3566, 0,
            0, 32, 2, /* 3566: struct.stack_st */
            	664, 8,
            	456, 24,
            1, 8, 1, /* 3573: pointer.struct.x509_crl_method_st */
            	3578, 0,
            0, 0, 0, /* 3578: struct.x509_crl_method_st */
            1, 8, 1, /* 3581: pointer.struct.stack_st_X509_LOOKUP */
            	3586, 0,
            0, 32, 2, /* 3586: struct.stack_st_fake_X509_LOOKUP */
            	3593, 8,
            	456, 24,
            8884099, 8, 2, /* 3593: pointer_to_array_of_pointers_to_stack */
            	3600, 0,
            	453, 20,
            0, 8, 1, /* 3600: pointer.X509_LOOKUP */
            	2421, 0,
            1, 8, 1, /* 3605: pointer.struct.X509_VERIFY_PARAM_st */
            	3610, 0,
            0, 56, 2, /* 3610: struct.X509_VERIFY_PARAM_st */
            	61, 0,
            	3321, 48,
            8884097, 8, 0, /* 3617: pointer.func */
            8884097, 8, 0, /* 3620: pointer.func */
            8884097, 8, 0, /* 3623: pointer.func */
            8884097, 8, 0, /* 3626: pointer.func */
            8884097, 8, 0, /* 3629: pointer.func */
            8884097, 8, 0, /* 3632: pointer.func */
            8884097, 8, 0, /* 3635: pointer.func */
            8884097, 8, 0, /* 3638: pointer.func */
            8884097, 8, 0, /* 3641: pointer.func */
            8884097, 8, 0, /* 3644: pointer.func */
            0, 112, 11, /* 3647: struct.ssl3_enc_method */
            	3672, 0,
            	3675, 8,
            	3678, 16,
            	3681, 24,
            	3672, 32,
            	3684, 40,
            	3687, 56,
            	10, 64,
            	10, 80,
            	3690, 96,
            	3693, 104,
            8884097, 8, 0, /* 3672: pointer.func */
            8884097, 8, 0, /* 3675: pointer.func */
            8884097, 8, 0, /* 3678: pointer.func */
            8884097, 8, 0, /* 3681: pointer.func */
            8884097, 8, 0, /* 3684: pointer.func */
            8884097, 8, 0, /* 3687: pointer.func */
            8884097, 8, 0, /* 3690: pointer.func */
            8884097, 8, 0, /* 3693: pointer.func */
            8884097, 8, 0, /* 3696: pointer.func */
            0, 104, 11, /* 3699: struct.x509_cinf_st */
            	3724, 0,
            	3724, 8,
            	3734, 16,
            	3891, 24,
            	3939, 32,
            	3891, 40,
            	3956, 48,
            	3823, 56,
            	3823, 64,
            	4227, 72,
            	4251, 80,
            1, 8, 1, /* 3724: pointer.struct.asn1_string_st */
            	3729, 0,
            0, 24, 1, /* 3729: struct.asn1_string_st */
            	209, 8,
            1, 8, 1, /* 3734: pointer.struct.X509_algor_st */
            	3739, 0,
            0, 16, 2, /* 3739: struct.X509_algor_st */
            	3746, 0,
            	3760, 8,
            1, 8, 1, /* 3746: pointer.struct.asn1_object_st */
            	3751, 0,
            0, 40, 3, /* 3751: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	243, 24,
            1, 8, 1, /* 3760: pointer.struct.asn1_type_st */
            	3765, 0,
            0, 16, 1, /* 3765: struct.asn1_type_st */
            	3770, 8,
            0, 8, 20, /* 3770: union.unknown */
            	61, 0,
            	3813, 0,
            	3746, 0,
            	3724, 0,
            	3818, 0,
            	3823, 0,
            	3828, 0,
            	3833, 0,
            	3838, 0,
            	3843, 0,
            	3848, 0,
            	3853, 0,
            	3858, 0,
            	3863, 0,
            	3868, 0,
            	3873, 0,
            	3878, 0,
            	3813, 0,
            	3813, 0,
            	3883, 0,
            1, 8, 1, /* 3813: pointer.struct.asn1_string_st */
            	3729, 0,
            1, 8, 1, /* 3818: pointer.struct.asn1_string_st */
            	3729, 0,
            1, 8, 1, /* 3823: pointer.struct.asn1_string_st */
            	3729, 0,
            1, 8, 1, /* 3828: pointer.struct.asn1_string_st */
            	3729, 0,
            1, 8, 1, /* 3833: pointer.struct.asn1_string_st */
            	3729, 0,
            1, 8, 1, /* 3838: pointer.struct.asn1_string_st */
            	3729, 0,
            1, 8, 1, /* 3843: pointer.struct.asn1_string_st */
            	3729, 0,
            1, 8, 1, /* 3848: pointer.struct.asn1_string_st */
            	3729, 0,
            1, 8, 1, /* 3853: pointer.struct.asn1_string_st */
            	3729, 0,
            1, 8, 1, /* 3858: pointer.struct.asn1_string_st */
            	3729, 0,
            1, 8, 1, /* 3863: pointer.struct.asn1_string_st */
            	3729, 0,
            1, 8, 1, /* 3868: pointer.struct.asn1_string_st */
            	3729, 0,
            1, 8, 1, /* 3873: pointer.struct.asn1_string_st */
            	3729, 0,
            1, 8, 1, /* 3878: pointer.struct.asn1_string_st */
            	3729, 0,
            1, 8, 1, /* 3883: pointer.struct.ASN1_VALUE_st */
            	3888, 0,
            0, 0, 0, /* 3888: struct.ASN1_VALUE_st */
            1, 8, 1, /* 3891: pointer.struct.X509_name_st */
            	3896, 0,
            0, 40, 3, /* 3896: struct.X509_name_st */
            	3905, 0,
            	3929, 16,
            	209, 24,
            1, 8, 1, /* 3905: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3910, 0,
            0, 32, 2, /* 3910: struct.stack_st_fake_X509_NAME_ENTRY */
            	3917, 8,
            	456, 24,
            8884099, 8, 2, /* 3917: pointer_to_array_of_pointers_to_stack */
            	3924, 0,
            	453, 20,
            0, 8, 1, /* 3924: pointer.X509_NAME_ENTRY */
            	417, 0,
            1, 8, 1, /* 3929: pointer.struct.buf_mem_st */
            	3934, 0,
            0, 24, 1, /* 3934: struct.buf_mem_st */
            	61, 8,
            1, 8, 1, /* 3939: pointer.struct.X509_val_st */
            	3944, 0,
            0, 16, 2, /* 3944: struct.X509_val_st */
            	3951, 0,
            	3951, 8,
            1, 8, 1, /* 3951: pointer.struct.asn1_string_st */
            	3729, 0,
            1, 8, 1, /* 3956: pointer.struct.X509_pubkey_st */
            	3961, 0,
            0, 24, 3, /* 3961: struct.X509_pubkey_st */
            	3734, 0,
            	3823, 8,
            	3970, 16,
            1, 8, 1, /* 3970: pointer.struct.evp_pkey_st */
            	3975, 0,
            0, 56, 4, /* 3975: struct.evp_pkey_st */
            	3986, 16,
            	2413, 24,
            	3994, 32,
            	4203, 48,
            1, 8, 1, /* 3986: pointer.struct.evp_pkey_asn1_method_st */
            	3991, 0,
            0, 0, 0, /* 3991: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 3994: union.unknown */
            	61, 0,
            	4007, 0,
            	4112, 0,
            	4190, 0,
            	4195, 0,
            1, 8, 1, /* 4007: pointer.struct.rsa_st */
            	4012, 0,
            0, 168, 17, /* 4012: struct.rsa_st */
            	4049, 16,
            	2413, 24,
            	2331, 32,
            	2331, 40,
            	2331, 48,
            	2331, 56,
            	2331, 64,
            	2331, 72,
            	2331, 80,
            	2331, 88,
            	2355, 96,
            	2341, 120,
            	2341, 128,
            	2341, 136,
            	61, 144,
            	4104, 152,
            	4104, 160,
            1, 8, 1, /* 4049: pointer.struct.rsa_meth_st */
            	4054, 0,
            0, 112, 13, /* 4054: struct.rsa_meth_st */
            	10, 0,
            	4083, 8,
            	4083, 16,
            	4083, 24,
            	4083, 32,
            	4086, 40,
            	4089, 48,
            	4092, 56,
            	4092, 64,
            	61, 80,
            	4095, 88,
            	4098, 96,
            	4101, 104,
            8884097, 8, 0, /* 4083: pointer.func */
            8884097, 8, 0, /* 4086: pointer.func */
            8884097, 8, 0, /* 4089: pointer.func */
            8884097, 8, 0, /* 4092: pointer.func */
            8884097, 8, 0, /* 4095: pointer.func */
            8884097, 8, 0, /* 4098: pointer.func */
            8884097, 8, 0, /* 4101: pointer.func */
            1, 8, 1, /* 4104: pointer.struct.bn_blinding_st */
            	4109, 0,
            0, 0, 0, /* 4109: struct.bn_blinding_st */
            1, 8, 1, /* 4112: pointer.struct.dsa_st */
            	4117, 0,
            0, 136, 11, /* 4117: struct.dsa_st */
            	2331, 24,
            	2331, 32,
            	2331, 40,
            	2331, 48,
            	2331, 56,
            	2331, 64,
            	2331, 72,
            	2341, 88,
            	2355, 104,
            	4142, 120,
            	2413, 128,
            1, 8, 1, /* 4142: pointer.struct.dsa_method */
            	4147, 0,
            0, 96, 11, /* 4147: struct.dsa_method */
            	10, 0,
            	4172, 8,
            	4175, 16,
            	4178, 24,
            	3696, 32,
            	4181, 40,
            	4184, 48,
            	4184, 56,
            	61, 72,
            	4187, 80,
            	4184, 88,
            8884097, 8, 0, /* 4172: pointer.func */
            8884097, 8, 0, /* 4175: pointer.func */
            8884097, 8, 0, /* 4178: pointer.func */
            8884097, 8, 0, /* 4181: pointer.func */
            8884097, 8, 0, /* 4184: pointer.func */
            8884097, 8, 0, /* 4187: pointer.func */
            1, 8, 1, /* 4190: pointer.struct.dh_st */
            	2304, 0,
            1, 8, 1, /* 4195: pointer.struct.ec_key_st */
            	4200, 0,
            0, 0, 0, /* 4200: struct.ec_key_st */
            1, 8, 1, /* 4203: pointer.struct.stack_st_X509_ATTRIBUTE */
            	4208, 0,
            0, 32, 2, /* 4208: struct.stack_st_fake_X509_ATTRIBUTE */
            	4215, 8,
            	456, 24,
            8884099, 8, 2, /* 4215: pointer_to_array_of_pointers_to_stack */
            	4222, 0,
            	453, 20,
            0, 8, 1, /* 4222: pointer.X509_ATTRIBUTE */
            	872, 0,
            1, 8, 1, /* 4227: pointer.struct.stack_st_X509_EXTENSION */
            	4232, 0,
            0, 32, 2, /* 4232: struct.stack_st_fake_X509_EXTENSION */
            	4239, 8,
            	456, 24,
            8884099, 8, 2, /* 4239: pointer_to_array_of_pointers_to_stack */
            	4246, 0,
            	453, 20,
            0, 8, 1, /* 4246: pointer.X509_EXTENSION */
            	1251, 0,
            0, 24, 1, /* 4251: struct.ASN1_ENCODING_st */
            	209, 0,
            0, 0, 0, /* 4256: struct.X509_POLICY_CACHE_st */
            8884097, 8, 0, /* 4259: pointer.func */
            8884097, 8, 0, /* 4262: pointer.func */
            1, 8, 1, /* 4265: pointer.struct.stack_st_X509_OBJECT */
            	4270, 0,
            0, 32, 2, /* 4270: struct.stack_st_fake_X509_OBJECT */
            	4277, 8,
            	456, 24,
            8884099, 8, 2, /* 4277: pointer_to_array_of_pointers_to_stack */
            	4284, 0,
            	453, 20,
            0, 8, 1, /* 4284: pointer.X509_OBJECT */
            	2546, 0,
            8884097, 8, 0, /* 4289: pointer.func */
            0, 0, 0, /* 4292: struct.NAME_CONSTRAINTS_st */
            8884097, 8, 0, /* 4295: pointer.func */
            8884097, 8, 0, /* 4298: pointer.func */
            1, 8, 1, /* 4301: pointer.struct.ssl_method_st */
            	4306, 0,
            0, 232, 28, /* 4306: struct.ssl_method_st */
            	3678, 8,
            	4262, 16,
            	4262, 24,
            	3678, 32,
            	3678, 40,
            	4365, 48,
            	4365, 56,
            	4368, 64,
            	3678, 72,
            	3678, 80,
            	3678, 88,
            	4371, 96,
            	4298, 104,
            	4374, 112,
            	3678, 120,
            	4377, 128,
            	4380, 136,
            	4383, 144,
            	4386, 152,
            	4389, 160,
            	4392, 168,
            	4395, 176,
            	4398, 184,
            	2163, 192,
            	4401, 200,
            	4392, 208,
            	4406, 216,
            	4409, 224,
            8884097, 8, 0, /* 4365: pointer.func */
            8884097, 8, 0, /* 4368: pointer.func */
            8884097, 8, 0, /* 4371: pointer.func */
            8884097, 8, 0, /* 4374: pointer.func */
            8884097, 8, 0, /* 4377: pointer.func */
            8884097, 8, 0, /* 4380: pointer.func */
            8884097, 8, 0, /* 4383: pointer.func */
            8884097, 8, 0, /* 4386: pointer.func */
            8884097, 8, 0, /* 4389: pointer.func */
            8884097, 8, 0, /* 4392: pointer.func */
            8884097, 8, 0, /* 4395: pointer.func */
            8884097, 8, 0, /* 4398: pointer.func */
            1, 8, 1, /* 4401: pointer.struct.ssl3_enc_method */
            	3647, 0,
            8884097, 8, 0, /* 4406: pointer.func */
            8884097, 8, 0, /* 4409: pointer.func */
            0, 144, 15, /* 4412: struct.x509_store_st */
            	4265, 8,
            	4445, 16,
            	4469, 24,
            	4481, 32,
            	4484, 40,
            	4487, 48,
            	4490, 56,
            	4481, 64,
            	4493, 72,
            	4496, 80,
            	4499, 88,
            	3644, 96,
            	4502, 104,
            	4481, 112,
            	642, 120,
            1, 8, 1, /* 4445: pointer.struct.stack_st_X509_LOOKUP */
            	4450, 0,
            0, 32, 2, /* 4450: struct.stack_st_fake_X509_LOOKUP */
            	4457, 8,
            	456, 24,
            8884099, 8, 2, /* 4457: pointer_to_array_of_pointers_to_stack */
            	4464, 0,
            	453, 20,
            0, 8, 1, /* 4464: pointer.X509_LOOKUP */
            	2421, 0,
            1, 8, 1, /* 4469: pointer.struct.X509_VERIFY_PARAM_st */
            	4474, 0,
            0, 56, 2, /* 4474: struct.X509_VERIFY_PARAM_st */
            	61, 0,
            	1844, 48,
            8884097, 8, 0, /* 4481: pointer.func */
            8884097, 8, 0, /* 4484: pointer.func */
            8884097, 8, 0, /* 4487: pointer.func */
            8884097, 8, 0, /* 4490: pointer.func */
            8884097, 8, 0, /* 4493: pointer.func */
            8884097, 8, 0, /* 4496: pointer.func */
            8884097, 8, 0, /* 4499: pointer.func */
            8884097, 8, 0, /* 4502: pointer.func */
            1, 8, 1, /* 4505: pointer.struct.x509_store_st */
            	4412, 0,
            1, 8, 1, /* 4510: pointer.struct.stack_st_SSL_CIPHER */
            	4515, 0,
            0, 32, 2, /* 4515: struct.stack_st_fake_SSL_CIPHER */
            	4522, 8,
            	456, 24,
            8884099, 8, 2, /* 4522: pointer_to_array_of_pointers_to_stack */
            	4529, 0,
            	453, 20,
            0, 8, 1, /* 4529: pointer.SSL_CIPHER */
            	4534, 0,
            0, 0, 1, /* 4534: SSL_CIPHER */
            	4539, 0,
            0, 88, 1, /* 4539: struct.ssl_cipher_st */
            	10, 8,
            0, 32, 2, /* 4544: struct.stack_st_fake_SRTP_PROTECTION_PROFILE */
            	4551, 8,
            	456, 24,
            8884099, 8, 2, /* 4551: pointer_to_array_of_pointers_to_stack */
            	4558, 0,
            	453, 20,
            0, 8, 1, /* 4558: pointer.SRTP_PROTECTION_PROFILE */
            	0, 0,
            1, 8, 1, /* 4563: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	4544, 0,
            0, 184, 12, /* 4568: struct.x509_st */
            	4595, 0,
            	3734, 8,
            	3823, 16,
            	61, 32,
            	2355, 40,
            	3828, 104,
            	4600, 112,
            	4608, 120,
            	4613, 128,
            	4637, 136,
            	4661, 144,
            	4666, 176,
            1, 8, 1, /* 4595: pointer.struct.x509_cinf_st */
            	3699, 0,
            1, 8, 1, /* 4600: pointer.struct.AUTHORITY_KEYID_st */
            	4605, 0,
            0, 0, 0, /* 4605: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 4608: pointer.struct.X509_POLICY_CACHE_st */
            	4256, 0,
            1, 8, 1, /* 4613: pointer.struct.stack_st_DIST_POINT */
            	4618, 0,
            0, 32, 2, /* 4618: struct.stack_st_fake_DIST_POINT */
            	4625, 8,
            	456, 24,
            8884099, 8, 2, /* 4625: pointer_to_array_of_pointers_to_stack */
            	4632, 0,
            	453, 20,
            0, 8, 1, /* 4632: pointer.DIST_POINT */
            	1632, 0,
            1, 8, 1, /* 4637: pointer.struct.stack_st_GENERAL_NAME */
            	4642, 0,
            0, 32, 2, /* 4642: struct.stack_st_fake_GENERAL_NAME */
            	4649, 8,
            	456, 24,
            8884099, 8, 2, /* 4649: pointer_to_array_of_pointers_to_stack */
            	4656, 0,
            	453, 20,
            0, 8, 1, /* 4656: pointer.GENERAL_NAME */
            	1330, 0,
            1, 8, 1, /* 4661: pointer.struct.NAME_CONSTRAINTS_st */
            	4292, 0,
            1, 8, 1, /* 4666: pointer.struct.x509_cert_aux_st */
            	4671, 0,
            0, 40, 5, /* 4671: struct.x509_cert_aux_st */
            	4684, 0,
            	4684, 8,
            	3878, 16,
            	3828, 24,
            	4708, 32,
            1, 8, 1, /* 4684: pointer.struct.stack_st_ASN1_OBJECT */
            	4689, 0,
            0, 32, 2, /* 4689: struct.stack_st_fake_ASN1_OBJECT */
            	4696, 8,
            	456, 24,
            8884099, 8, 2, /* 4696: pointer_to_array_of_pointers_to_stack */
            	4703, 0,
            	453, 20,
            0, 8, 1, /* 4703: pointer.ASN1_OBJECT */
            	1868, 0,
            1, 8, 1, /* 4708: pointer.struct.stack_st_X509_ALGOR */
            	4713, 0,
            0, 32, 2, /* 4713: struct.stack_st_fake_X509_ALGOR */
            	4720, 8,
            	456, 24,
            8884099, 8, 2, /* 4720: pointer_to_array_of_pointers_to_stack */
            	4727, 0,
            	453, 20,
            0, 8, 1, /* 4727: pointer.X509_ALGOR */
            	1897, 0,
            0, 8, 0, /* 4732: long int */
            8884097, 8, 0, /* 4735: pointer.func */
            0, 736, 50, /* 4738: struct.ssl_ctx_st */
            	4301, 0,
            	4510, 8,
            	4510, 16,
            	4505, 24,
            	4841, 32,
            	4877, 48,
            	4877, 56,
            	4960, 80,
            	4963, 88,
            	2246, 96,
            	4289, 152,
            	49, 160,
            	4966, 168,
            	49, 176,
            	2243, 184,
            	4969, 192,
            	2207, 200,
            	642, 208,
            	2056, 224,
            	2056, 232,
            	2056, 240,
            	4931, 248,
            	2183, 256,
            	2134, 264,
            	4972, 272,
            	2119, 304,
            	2301, 320,
            	49, 328,
            	4484, 376,
            	5001, 384,
            	4469, 392,
            	524, 408,
            	52, 416,
            	49, 424,
            	4295, 480,
            	55, 488,
            	49, 496,
            	97, 504,
            	49, 512,
            	61, 520,
            	94, 528,
            	4735, 536,
            	5004, 552,
            	5004, 560,
            	18, 568,
            	15, 696,
            	49, 704,
            	4259, 712,
            	49, 720,
            	4563, 728,
            1, 8, 1, /* 4841: pointer.struct.lhash_st */
            	4846, 0,
            0, 176, 3, /* 4846: struct.lhash_st */
            	4855, 0,
            	456, 8,
            	4874, 16,
            8884099, 8, 2, /* 4855: pointer_to_array_of_pointers_to_stack */
            	4862, 0,
            	81, 28,
            1, 8, 1, /* 4862: pointer.struct.lhash_node_st */
            	4867, 0,
            0, 24, 2, /* 4867: struct.lhash_node_st */
            	49, 0,
            	4862, 8,
            8884097, 8, 0, /* 4874: pointer.func */
            1, 8, 1, /* 4877: pointer.struct.ssl_session_st */
            	4882, 0,
            0, 352, 14, /* 4882: struct.ssl_session_st */
            	61, 144,
            	61, 152,
            	4913, 168,
            	137, 176,
            	2296, 224,
            	4510, 240,
            	642, 248,
            	4877, 264,
            	4877, 272,
            	61, 280,
            	209, 296,
            	209, 312,
            	209, 320,
            	61, 344,
            1, 8, 1, /* 4913: pointer.struct.sess_cert_st */
            	4918, 0,
            0, 248, 5, /* 4918: struct.sess_cert_st */
            	4931, 0,
            	123, 16,
            	2101, 216,
            	2109, 224,
            	2114, 232,
            1, 8, 1, /* 4931: pointer.struct.stack_st_X509 */
            	4936, 0,
            0, 32, 2, /* 4936: struct.stack_st_fake_X509 */
            	4943, 8,
            	456, 24,
            8884099, 8, 2, /* 4943: pointer_to_array_of_pointers_to_stack */
            	4950, 0,
            	453, 20,
            0, 8, 1, /* 4950: pointer.X509 */
            	4955, 0,
            0, 0, 1, /* 4955: X509 */
            	4568, 0,
            8884097, 8, 0, /* 4960: pointer.func */
            8884097, 8, 0, /* 4963: pointer.func */
            8884097, 8, 0, /* 4966: pointer.func */
            8884097, 8, 0, /* 4969: pointer.func */
            1, 8, 1, /* 4972: pointer.struct.stack_st_X509_NAME */
            	4977, 0,
            0, 32, 2, /* 4977: struct.stack_st_fake_X509_NAME */
            	4984, 8,
            	456, 24,
            8884099, 8, 2, /* 4984: pointer_to_array_of_pointers_to_stack */
            	4991, 0,
            	453, 20,
            0, 8, 1, /* 4991: pointer.X509_NAME */
            	4996, 0,
            0, 0, 1, /* 4996: X509_NAME */
            	2210, 0,
            8884097, 8, 0, /* 5001: pointer.func */
            1, 8, 1, /* 5004: pointer.struct.ssl3_buf_freelist_st */
            	5009, 0,
            0, 24, 1, /* 5009: struct.ssl3_buf_freelist_st */
            	84, 16,
            1, 8, 1, /* 5014: pointer.struct.ssl_ctx_st */
            	4738, 0,
            0, 1, 0, /* 5019: char */
        },
        .arg_entity_index = { 5014, 453, 4732, 49, },
        .ret_entity_index = 4732,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_arg(args_addr, arg_d);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    SSL_CTX * new_arg_a = *((SSL_CTX * *)new_args->args[0]);

    int new_arg_b = *((int *)new_args->args[1]);

    long new_arg_c = *((long *)new_args->args[2]);

    void * new_arg_d = *((void * *)new_args->args[3]);

    long *new_ret_ptr = (long *)new_args->ret;

    long (*orig_SSL_CTX_ctrl)(SSL_CTX *,int,long,void *);
    orig_SSL_CTX_ctrl = dlsym(RTLD_NEXT, "SSL_CTX_ctrl");
    *new_ret_ptr = (*orig_SSL_CTX_ctrl)(new_arg_a,new_arg_b,new_arg_c,new_arg_d);

    syscall(889);

    return ret;
}

