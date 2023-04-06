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

EVP_MD_CTX * bb_EVP_MD_CTX_create(void);

EVP_MD_CTX * EVP_MD_CTX_create(void) 
{
    unsigned long in_lib = syscall(890);
    printf("EVP_MD_CTX_create called %lu\n", in_lib);
    if (!in_lib)
        return bb_EVP_MD_CTX_create();
    else {
        EVP_MD_CTX * (*orig_EVP_MD_CTX_create)(void);
        orig_EVP_MD_CTX_create = dlsym(RTLD_NEXT, "EVP_MD_CTX_create");
        return orig_EVP_MD_CTX_create();
    }
}

EVP_MD_CTX * bb_EVP_MD_CTX_create(void) 
{
    EVP_MD_CTX * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            1, 8, 1, /* 0: pointer.int */
            	5, 0,
            0, 4, 0, /* 5: int */
            1, 8, 1, /* 8: pointer.struct.ASN1_VALUE_st */
            	13, 0,
            0, 0, 0, /* 13: struct.ASN1_VALUE_st */
            1, 8, 1, /* 16: pointer.struct.asn1_string_st */
            	21, 0,
            0, 24, 1, /* 21: struct.asn1_string_st */
            	26, 8,
            1, 8, 1, /* 26: pointer.unsigned char */
            	31, 0,
            0, 1, 0, /* 31: unsigned char */
            1, 8, 1, /* 34: pointer.struct.asn1_string_st */
            	21, 0,
            1, 8, 1, /* 39: pointer.struct.asn1_string_st */
            	21, 0,
            1, 8, 1, /* 44: pointer.struct.asn1_string_st */
            	21, 0,
            1, 8, 1, /* 49: pointer.struct.asn1_string_st */
            	21, 0,
            1, 8, 1, /* 54: pointer.struct.asn1_string_st */
            	21, 0,
            1, 8, 1, /* 59: pointer.struct.asn1_string_st */
            	21, 0,
            1, 8, 1, /* 64: pointer.struct.asn1_string_st */
            	21, 0,
            1, 8, 1, /* 69: pointer.struct.asn1_string_st */
            	21, 0,
            1, 8, 1, /* 74: pointer.struct.asn1_string_st */
            	21, 0,
            1, 8, 1, /* 79: pointer.struct.asn1_string_st */
            	21, 0,
            1, 8, 1, /* 84: pointer.struct.asn1_string_st */
            	21, 0,
            1, 8, 1, /* 89: pointer.struct.asn1_string_st */
            	21, 0,
            0, 16, 1, /* 94: struct.asn1_type_st */
            	99, 8,
            0, 8, 20, /* 99: union.unknown */
            	142, 0,
            	89, 0,
            	147, 0,
            	171, 0,
            	84, 0,
            	79, 0,
            	74, 0,
            	69, 0,
            	64, 0,
            	59, 0,
            	54, 0,
            	49, 0,
            	44, 0,
            	39, 0,
            	34, 0,
            	176, 0,
            	16, 0,
            	89, 0,
            	89, 0,
            	8, 0,
            1, 8, 1, /* 142: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 147: pointer.struct.asn1_object_st */
            	152, 0,
            0, 40, 3, /* 152: struct.asn1_object_st */
            	161, 0,
            	161, 8,
            	166, 24,
            1, 8, 1, /* 161: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 166: pointer.unsigned char */
            	31, 0,
            1, 8, 1, /* 171: pointer.struct.asn1_string_st */
            	21, 0,
            1, 8, 1, /* 176: pointer.struct.asn1_string_st */
            	21, 0,
            1, 8, 1, /* 181: pointer.struct.ASN1_VALUE_st */
            	186, 0,
            0, 0, 0, /* 186: struct.ASN1_VALUE_st */
            1, 8, 1, /* 189: pointer.struct.asn1_string_st */
            	194, 0,
            0, 24, 1, /* 194: struct.asn1_string_st */
            	26, 8,
            1, 8, 1, /* 199: pointer.struct.asn1_string_st */
            	194, 0,
            1, 8, 1, /* 204: pointer.struct.asn1_string_st */
            	194, 0,
            1, 8, 1, /* 209: pointer.struct.asn1_string_st */
            	194, 0,
            1, 8, 1, /* 214: pointer.struct.asn1_string_st */
            	194, 0,
            1, 8, 1, /* 219: pointer.struct.asn1_string_st */
            	194, 0,
            1, 8, 1, /* 224: pointer.struct.asn1_string_st */
            	194, 0,
            1, 8, 1, /* 229: pointer.struct.asn1_string_st */
            	194, 0,
            0, 40, 3, /* 234: struct.asn1_object_st */
            	161, 0,
            	161, 8,
            	166, 24,
            1, 8, 1, /* 243: pointer.struct.asn1_object_st */
            	234, 0,
            1, 8, 1, /* 248: pointer.struct.asn1_string_st */
            	194, 0,
            0, 8, 20, /* 253: union.unknown */
            	142, 0,
            	248, 0,
            	243, 0,
            	229, 0,
            	224, 0,
            	296, 0,
            	219, 0,
            	301, 0,
            	306, 0,
            	214, 0,
            	209, 0,
            	311, 0,
            	204, 0,
            	199, 0,
            	316, 0,
            	321, 0,
            	189, 0,
            	248, 0,
            	248, 0,
            	181, 0,
            1, 8, 1, /* 296: pointer.struct.asn1_string_st */
            	194, 0,
            1, 8, 1, /* 301: pointer.struct.asn1_string_st */
            	194, 0,
            1, 8, 1, /* 306: pointer.struct.asn1_string_st */
            	194, 0,
            1, 8, 1, /* 311: pointer.struct.asn1_string_st */
            	194, 0,
            1, 8, 1, /* 316: pointer.struct.asn1_string_st */
            	194, 0,
            1, 8, 1, /* 321: pointer.struct.asn1_string_st */
            	194, 0,
            0, 16, 1, /* 326: struct.asn1_type_st */
            	253, 8,
            0, 0, 1, /* 331: ASN1_TYPE */
            	326, 0,
            1, 8, 1, /* 336: pointer.struct.stack_st_ASN1_TYPE */
            	341, 0,
            0, 32, 2, /* 341: struct.stack_st_fake_ASN1_TYPE */
            	348, 8,
            	360, 24,
            8884099, 8, 2, /* 348: pointer_to_array_of_pointers_to_stack */
            	355, 0,
            	5, 20,
            0, 8, 1, /* 355: pointer.ASN1_TYPE */
            	331, 0,
            8884097, 8, 0, /* 360: pointer.func */
            0, 8, 3, /* 363: union.unknown */
            	142, 0,
            	336, 0,
            	372, 0,
            1, 8, 1, /* 372: pointer.struct.asn1_type_st */
            	94, 0,
            1, 8, 1, /* 377: pointer.struct.stack_st_X509_ATTRIBUTE */
            	382, 0,
            0, 32, 2, /* 382: struct.stack_st_fake_X509_ATTRIBUTE */
            	389, 8,
            	360, 24,
            8884099, 8, 2, /* 389: pointer_to_array_of_pointers_to_stack */
            	396, 0,
            	5, 20,
            0, 8, 1, /* 396: pointer.X509_ATTRIBUTE */
            	401, 0,
            0, 0, 1, /* 401: X509_ATTRIBUTE */
            	406, 0,
            0, 24, 2, /* 406: struct.x509_attributes_st */
            	147, 0,
            	363, 16,
            0, 24, 1, /* 413: struct.bignum_st */
            	418, 0,
            1, 8, 1, /* 418: pointer.unsigned int */
            	423, 0,
            0, 4, 0, /* 423: unsigned int */
            1, 8, 1, /* 426: pointer.struct.ec_point_st */
            	431, 0,
            0, 88, 4, /* 431: struct.ec_point_st */
            	442, 0,
            	614, 8,
            	614, 32,
            	614, 56,
            1, 8, 1, /* 442: pointer.struct.ec_method_st */
            	447, 0,
            0, 304, 37, /* 447: struct.ec_method_st */
            	524, 8,
            	527, 16,
            	527, 24,
            	530, 32,
            	533, 40,
            	536, 48,
            	539, 56,
            	542, 64,
            	545, 72,
            	548, 80,
            	548, 88,
            	551, 96,
            	554, 104,
            	557, 112,
            	560, 120,
            	563, 128,
            	566, 136,
            	569, 144,
            	572, 152,
            	575, 160,
            	578, 168,
            	581, 176,
            	584, 184,
            	587, 192,
            	590, 200,
            	593, 208,
            	584, 216,
            	596, 224,
            	599, 232,
            	602, 240,
            	539, 248,
            	605, 256,
            	608, 264,
            	605, 272,
            	608, 280,
            	608, 288,
            	611, 296,
            8884097, 8, 0, /* 524: pointer.func */
            8884097, 8, 0, /* 527: pointer.func */
            8884097, 8, 0, /* 530: pointer.func */
            8884097, 8, 0, /* 533: pointer.func */
            8884097, 8, 0, /* 536: pointer.func */
            8884097, 8, 0, /* 539: pointer.func */
            8884097, 8, 0, /* 542: pointer.func */
            8884097, 8, 0, /* 545: pointer.func */
            8884097, 8, 0, /* 548: pointer.func */
            8884097, 8, 0, /* 551: pointer.func */
            8884097, 8, 0, /* 554: pointer.func */
            8884097, 8, 0, /* 557: pointer.func */
            8884097, 8, 0, /* 560: pointer.func */
            8884097, 8, 0, /* 563: pointer.func */
            8884097, 8, 0, /* 566: pointer.func */
            8884097, 8, 0, /* 569: pointer.func */
            8884097, 8, 0, /* 572: pointer.func */
            8884097, 8, 0, /* 575: pointer.func */
            8884097, 8, 0, /* 578: pointer.func */
            8884097, 8, 0, /* 581: pointer.func */
            8884097, 8, 0, /* 584: pointer.func */
            8884097, 8, 0, /* 587: pointer.func */
            8884097, 8, 0, /* 590: pointer.func */
            8884097, 8, 0, /* 593: pointer.func */
            8884097, 8, 0, /* 596: pointer.func */
            8884097, 8, 0, /* 599: pointer.func */
            8884097, 8, 0, /* 602: pointer.func */
            8884097, 8, 0, /* 605: pointer.func */
            8884097, 8, 0, /* 608: pointer.func */
            8884097, 8, 0, /* 611: pointer.func */
            0, 24, 1, /* 614: struct.bignum_st */
            	418, 0,
            8884097, 8, 0, /* 619: pointer.func */
            8884097, 8, 0, /* 622: pointer.func */
            1, 8, 1, /* 625: pointer.struct.dh_st */
            	630, 0,
            0, 144, 12, /* 630: struct.dh_st */
            	657, 8,
            	657, 16,
            	657, 32,
            	657, 40,
            	667, 56,
            	657, 64,
            	657, 72,
            	26, 80,
            	657, 96,
            	681, 112,
            	708, 128,
            	744, 136,
            1, 8, 1, /* 657: pointer.struct.bignum_st */
            	662, 0,
            0, 24, 1, /* 662: struct.bignum_st */
            	418, 0,
            1, 8, 1, /* 667: pointer.struct.bn_mont_ctx_st */
            	672, 0,
            0, 96, 3, /* 672: struct.bn_mont_ctx_st */
            	662, 8,
            	662, 32,
            	662, 56,
            0, 16, 1, /* 681: struct.crypto_ex_data_st */
            	686, 0,
            1, 8, 1, /* 686: pointer.struct.stack_st_void */
            	691, 0,
            0, 32, 1, /* 691: struct.stack_st_void */
            	696, 0,
            0, 32, 2, /* 696: struct.stack_st */
            	703, 8,
            	360, 24,
            1, 8, 1, /* 703: pointer.pointer.char */
            	142, 0,
            1, 8, 1, /* 708: pointer.struct.dh_method */
            	713, 0,
            0, 72, 8, /* 713: struct.dh_method */
            	161, 0,
            	732, 8,
            	735, 16,
            	738, 24,
            	732, 32,
            	732, 40,
            	142, 56,
            	741, 64,
            8884097, 8, 0, /* 732: pointer.func */
            8884097, 8, 0, /* 735: pointer.func */
            8884097, 8, 0, /* 738: pointer.func */
            8884097, 8, 0, /* 741: pointer.func */
            1, 8, 1, /* 744: pointer.struct.engine_st */
            	749, 0,
            0, 216, 24, /* 749: struct.engine_st */
            	161, 0,
            	161, 8,
            	800, 16,
            	855, 24,
            	906, 32,
            	942, 40,
            	959, 48,
            	983, 56,
            	1018, 64,
            	1026, 72,
            	1029, 80,
            	1032, 88,
            	1035, 96,
            	1038, 104,
            	1038, 112,
            	1038, 120,
            	1041, 128,
            	1044, 136,
            	1044, 144,
            	1047, 152,
            	1050, 160,
            	1062, 184,
            	1084, 200,
            	1084, 208,
            1, 8, 1, /* 800: pointer.struct.rsa_meth_st */
            	805, 0,
            0, 112, 13, /* 805: struct.rsa_meth_st */
            	161, 0,
            	834, 8,
            	834, 16,
            	834, 24,
            	834, 32,
            	837, 40,
            	840, 48,
            	843, 56,
            	843, 64,
            	142, 80,
            	846, 88,
            	849, 96,
            	852, 104,
            8884097, 8, 0, /* 834: pointer.func */
            8884097, 8, 0, /* 837: pointer.func */
            8884097, 8, 0, /* 840: pointer.func */
            8884097, 8, 0, /* 843: pointer.func */
            8884097, 8, 0, /* 846: pointer.func */
            8884097, 8, 0, /* 849: pointer.func */
            8884097, 8, 0, /* 852: pointer.func */
            1, 8, 1, /* 855: pointer.struct.dsa_method */
            	860, 0,
            0, 96, 11, /* 860: struct.dsa_method */
            	161, 0,
            	885, 8,
            	888, 16,
            	891, 24,
            	894, 32,
            	897, 40,
            	900, 48,
            	900, 56,
            	142, 72,
            	903, 80,
            	900, 88,
            8884097, 8, 0, /* 885: pointer.func */
            8884097, 8, 0, /* 888: pointer.func */
            8884097, 8, 0, /* 891: pointer.func */
            8884097, 8, 0, /* 894: pointer.func */
            8884097, 8, 0, /* 897: pointer.func */
            8884097, 8, 0, /* 900: pointer.func */
            8884097, 8, 0, /* 903: pointer.func */
            1, 8, 1, /* 906: pointer.struct.dh_method */
            	911, 0,
            0, 72, 8, /* 911: struct.dh_method */
            	161, 0,
            	930, 8,
            	933, 16,
            	936, 24,
            	930, 32,
            	930, 40,
            	142, 56,
            	939, 64,
            8884097, 8, 0, /* 930: pointer.func */
            8884097, 8, 0, /* 933: pointer.func */
            8884097, 8, 0, /* 936: pointer.func */
            8884097, 8, 0, /* 939: pointer.func */
            1, 8, 1, /* 942: pointer.struct.ecdh_method */
            	947, 0,
            0, 32, 3, /* 947: struct.ecdh_method */
            	161, 0,
            	956, 8,
            	142, 24,
            8884097, 8, 0, /* 956: pointer.func */
            1, 8, 1, /* 959: pointer.struct.ecdsa_method */
            	964, 0,
            0, 48, 5, /* 964: struct.ecdsa_method */
            	161, 0,
            	977, 8,
            	980, 16,
            	622, 24,
            	142, 40,
            8884097, 8, 0, /* 977: pointer.func */
            8884097, 8, 0, /* 980: pointer.func */
            1, 8, 1, /* 983: pointer.struct.rand_meth_st */
            	988, 0,
            0, 48, 6, /* 988: struct.rand_meth_st */
            	1003, 0,
            	1006, 8,
            	1009, 16,
            	1012, 24,
            	1006, 32,
            	1015, 40,
            8884097, 8, 0, /* 1003: pointer.func */
            8884097, 8, 0, /* 1006: pointer.func */
            8884097, 8, 0, /* 1009: pointer.func */
            8884097, 8, 0, /* 1012: pointer.func */
            8884097, 8, 0, /* 1015: pointer.func */
            1, 8, 1, /* 1018: pointer.struct.store_method_st */
            	1023, 0,
            0, 0, 0, /* 1023: struct.store_method_st */
            8884097, 8, 0, /* 1026: pointer.func */
            8884097, 8, 0, /* 1029: pointer.func */
            8884097, 8, 0, /* 1032: pointer.func */
            8884097, 8, 0, /* 1035: pointer.func */
            8884097, 8, 0, /* 1038: pointer.func */
            8884097, 8, 0, /* 1041: pointer.func */
            8884097, 8, 0, /* 1044: pointer.func */
            8884097, 8, 0, /* 1047: pointer.func */
            1, 8, 1, /* 1050: pointer.struct.ENGINE_CMD_DEFN_st */
            	1055, 0,
            0, 32, 2, /* 1055: struct.ENGINE_CMD_DEFN_st */
            	161, 8,
            	161, 16,
            0, 16, 1, /* 1062: struct.crypto_ex_data_st */
            	1067, 0,
            1, 8, 1, /* 1067: pointer.struct.stack_st_void */
            	1072, 0,
            0, 32, 1, /* 1072: struct.stack_st_void */
            	1077, 0,
            0, 32, 2, /* 1077: struct.stack_st */
            	703, 8,
            	360, 24,
            1, 8, 1, /* 1084: pointer.struct.engine_st */
            	749, 0,
            0, 112, 13, /* 1089: struct.rsa_meth_st */
            	161, 0,
            	1118, 8,
            	1118, 16,
            	1118, 24,
            	1118, 32,
            	1121, 40,
            	1124, 48,
            	1127, 56,
            	1127, 64,
            	142, 80,
            	1130, 88,
            	1133, 96,
            	1136, 104,
            8884097, 8, 0, /* 1118: pointer.func */
            8884097, 8, 0, /* 1121: pointer.func */
            8884097, 8, 0, /* 1124: pointer.func */
            8884097, 8, 0, /* 1127: pointer.func */
            8884097, 8, 0, /* 1130: pointer.func */
            8884097, 8, 0, /* 1133: pointer.func */
            8884097, 8, 0, /* 1136: pointer.func */
            0, 168, 17, /* 1139: struct.rsa_st */
            	1176, 16,
            	744, 24,
            	1181, 32,
            	1181, 40,
            	1181, 48,
            	1181, 56,
            	1181, 64,
            	1181, 72,
            	1181, 80,
            	1181, 88,
            	1191, 96,
            	1213, 120,
            	1213, 128,
            	1213, 136,
            	142, 144,
            	1227, 152,
            	1227, 160,
            1, 8, 1, /* 1176: pointer.struct.rsa_meth_st */
            	1089, 0,
            1, 8, 1, /* 1181: pointer.struct.bignum_st */
            	1186, 0,
            0, 24, 1, /* 1186: struct.bignum_st */
            	418, 0,
            0, 16, 1, /* 1191: struct.crypto_ex_data_st */
            	1196, 0,
            1, 8, 1, /* 1196: pointer.struct.stack_st_void */
            	1201, 0,
            0, 32, 1, /* 1201: struct.stack_st_void */
            	1206, 0,
            0, 32, 2, /* 1206: struct.stack_st */
            	703, 8,
            	360, 24,
            1, 8, 1, /* 1213: pointer.struct.bn_mont_ctx_st */
            	1218, 0,
            0, 96, 3, /* 1218: struct.bn_mont_ctx_st */
            	1186, 8,
            	1186, 32,
            	1186, 56,
            1, 8, 1, /* 1227: pointer.struct.bn_blinding_st */
            	1232, 0,
            0, 88, 7, /* 1232: struct.bn_blinding_st */
            	1249, 0,
            	1249, 8,
            	1249, 16,
            	1249, 24,
            	1259, 40,
            	1267, 72,
            	1281, 80,
            1, 8, 1, /* 1249: pointer.struct.bignum_st */
            	1254, 0,
            0, 24, 1, /* 1254: struct.bignum_st */
            	418, 0,
            0, 16, 1, /* 1259: struct.crypto_threadid_st */
            	1264, 0,
            0, 8, 0, /* 1264: pointer.void */
            1, 8, 1, /* 1267: pointer.struct.bn_mont_ctx_st */
            	1272, 0,
            0, 96, 3, /* 1272: struct.bn_mont_ctx_st */
            	1254, 8,
            	1254, 32,
            	1254, 56,
            8884097, 8, 0, /* 1281: pointer.func */
            1, 8, 1, /* 1284: pointer.struct.evp_pkey_ctx_st */
            	1289, 0,
            0, 80, 8, /* 1289: struct.evp_pkey_ctx_st */
            	1308, 0,
            	1402, 8,
            	1407, 16,
            	1407, 24,
            	1264, 40,
            	1264, 48,
            	1961, 56,
            	0, 64,
            1, 8, 1, /* 1308: pointer.struct.evp_pkey_method_st */
            	1313, 0,
            0, 208, 25, /* 1313: struct.evp_pkey_method_st */
            	1366, 8,
            	1369, 16,
            	1372, 24,
            	1366, 32,
            	1375, 40,
            	1366, 48,
            	1375, 56,
            	1366, 64,
            	1378, 72,
            	1366, 80,
            	1381, 88,
            	1366, 96,
            	1378, 104,
            	1384, 112,
            	1387, 120,
            	1384, 128,
            	1390, 136,
            	1366, 144,
            	1378, 152,
            	1366, 160,
            	1378, 168,
            	1366, 176,
            	1393, 184,
            	1396, 192,
            	1399, 200,
            8884097, 8, 0, /* 1366: pointer.func */
            8884097, 8, 0, /* 1369: pointer.func */
            8884097, 8, 0, /* 1372: pointer.func */
            8884097, 8, 0, /* 1375: pointer.func */
            8884097, 8, 0, /* 1378: pointer.func */
            8884097, 8, 0, /* 1381: pointer.func */
            8884097, 8, 0, /* 1384: pointer.func */
            8884097, 8, 0, /* 1387: pointer.func */
            8884097, 8, 0, /* 1390: pointer.func */
            8884097, 8, 0, /* 1393: pointer.func */
            8884097, 8, 0, /* 1396: pointer.func */
            8884097, 8, 0, /* 1399: pointer.func */
            1, 8, 1, /* 1402: pointer.struct.engine_st */
            	749, 0,
            1, 8, 1, /* 1407: pointer.struct.evp_pkey_st */
            	1412, 0,
            0, 56, 4, /* 1412: struct.evp_pkey_st */
            	1423, 16,
            	1402, 24,
            	1524, 32,
            	377, 48,
            1, 8, 1, /* 1423: pointer.struct.evp_pkey_asn1_method_st */
            	1428, 0,
            0, 208, 24, /* 1428: struct.evp_pkey_asn1_method_st */
            	142, 16,
            	142, 24,
            	1479, 32,
            	1482, 40,
            	1485, 48,
            	1488, 56,
            	1491, 64,
            	1494, 72,
            	1488, 80,
            	1497, 88,
            	1497, 96,
            	1500, 104,
            	1503, 112,
            	1497, 120,
            	1506, 128,
            	1485, 136,
            	1488, 144,
            	1509, 152,
            	1512, 160,
            	1515, 168,
            	1500, 176,
            	1503, 184,
            	1518, 192,
            	1521, 200,
            8884097, 8, 0, /* 1479: pointer.func */
            8884097, 8, 0, /* 1482: pointer.func */
            8884097, 8, 0, /* 1485: pointer.func */
            8884097, 8, 0, /* 1488: pointer.func */
            8884097, 8, 0, /* 1491: pointer.func */
            8884097, 8, 0, /* 1494: pointer.func */
            8884097, 8, 0, /* 1497: pointer.func */
            8884097, 8, 0, /* 1500: pointer.func */
            8884097, 8, 0, /* 1503: pointer.func */
            8884097, 8, 0, /* 1506: pointer.func */
            8884097, 8, 0, /* 1509: pointer.func */
            8884097, 8, 0, /* 1512: pointer.func */
            8884097, 8, 0, /* 1515: pointer.func */
            8884097, 8, 0, /* 1518: pointer.func */
            8884097, 8, 0, /* 1521: pointer.func */
            0, 8, 5, /* 1524: union.unknown */
            	142, 0,
            	1537, 0,
            	1542, 0,
            	625, 0,
            	1674, 0,
            1, 8, 1, /* 1537: pointer.struct.rsa_st */
            	1139, 0,
            1, 8, 1, /* 1542: pointer.struct.dsa_st */
            	1547, 0,
            0, 136, 11, /* 1547: struct.dsa_st */
            	1572, 24,
            	1572, 32,
            	1572, 40,
            	1572, 48,
            	1572, 56,
            	1572, 64,
            	1572, 72,
            	1582, 88,
            	1596, 104,
            	1618, 120,
            	1669, 128,
            1, 8, 1, /* 1572: pointer.struct.bignum_st */
            	1577, 0,
            0, 24, 1, /* 1577: struct.bignum_st */
            	418, 0,
            1, 8, 1, /* 1582: pointer.struct.bn_mont_ctx_st */
            	1587, 0,
            0, 96, 3, /* 1587: struct.bn_mont_ctx_st */
            	1577, 8,
            	1577, 32,
            	1577, 56,
            0, 16, 1, /* 1596: struct.crypto_ex_data_st */
            	1601, 0,
            1, 8, 1, /* 1601: pointer.struct.stack_st_void */
            	1606, 0,
            0, 32, 1, /* 1606: struct.stack_st_void */
            	1611, 0,
            0, 32, 2, /* 1611: struct.stack_st */
            	703, 8,
            	360, 24,
            1, 8, 1, /* 1618: pointer.struct.dsa_method */
            	1623, 0,
            0, 96, 11, /* 1623: struct.dsa_method */
            	161, 0,
            	1648, 8,
            	1651, 16,
            	1654, 24,
            	1657, 32,
            	1660, 40,
            	1663, 48,
            	1663, 56,
            	142, 72,
            	1666, 80,
            	1663, 88,
            8884097, 8, 0, /* 1648: pointer.func */
            8884097, 8, 0, /* 1651: pointer.func */
            8884097, 8, 0, /* 1654: pointer.func */
            8884097, 8, 0, /* 1657: pointer.func */
            8884097, 8, 0, /* 1660: pointer.func */
            8884097, 8, 0, /* 1663: pointer.func */
            8884097, 8, 0, /* 1666: pointer.func */
            1, 8, 1, /* 1669: pointer.struct.engine_st */
            	749, 0,
            1, 8, 1, /* 1674: pointer.struct.ec_key_st */
            	1679, 0,
            0, 56, 4, /* 1679: struct.ec_key_st */
            	1690, 8,
            	426, 16,
            	1933, 24,
            	1938, 48,
            1, 8, 1, /* 1690: pointer.struct.ec_group_st */
            	1695, 0,
            0, 232, 12, /* 1695: struct.ec_group_st */
            	1722, 0,
            	1894, 8,
            	1899, 16,
            	1899, 40,
            	26, 80,
            	1904, 96,
            	1899, 104,
            	1899, 152,
            	1899, 176,
            	1264, 208,
            	1264, 216,
            	619, 224,
            1, 8, 1, /* 1722: pointer.struct.ec_method_st */
            	1727, 0,
            0, 304, 37, /* 1727: struct.ec_method_st */
            	1804, 8,
            	1807, 16,
            	1807, 24,
            	1810, 32,
            	1813, 40,
            	1816, 48,
            	1819, 56,
            	1822, 64,
            	1825, 72,
            	1828, 80,
            	1828, 88,
            	1831, 96,
            	1834, 104,
            	1837, 112,
            	1840, 120,
            	1843, 128,
            	1846, 136,
            	1849, 144,
            	1852, 152,
            	1855, 160,
            	1858, 168,
            	1861, 176,
            	1864, 184,
            	1867, 192,
            	1870, 200,
            	1873, 208,
            	1864, 216,
            	1876, 224,
            	1879, 232,
            	1882, 240,
            	1819, 248,
            	1885, 256,
            	1888, 264,
            	1885, 272,
            	1888, 280,
            	1888, 288,
            	1891, 296,
            8884097, 8, 0, /* 1804: pointer.func */
            8884097, 8, 0, /* 1807: pointer.func */
            8884097, 8, 0, /* 1810: pointer.func */
            8884097, 8, 0, /* 1813: pointer.func */
            8884097, 8, 0, /* 1816: pointer.func */
            8884097, 8, 0, /* 1819: pointer.func */
            8884097, 8, 0, /* 1822: pointer.func */
            8884097, 8, 0, /* 1825: pointer.func */
            8884097, 8, 0, /* 1828: pointer.func */
            8884097, 8, 0, /* 1831: pointer.func */
            8884097, 8, 0, /* 1834: pointer.func */
            8884097, 8, 0, /* 1837: pointer.func */
            8884097, 8, 0, /* 1840: pointer.func */
            8884097, 8, 0, /* 1843: pointer.func */
            8884097, 8, 0, /* 1846: pointer.func */
            8884097, 8, 0, /* 1849: pointer.func */
            8884097, 8, 0, /* 1852: pointer.func */
            8884097, 8, 0, /* 1855: pointer.func */
            8884097, 8, 0, /* 1858: pointer.func */
            8884097, 8, 0, /* 1861: pointer.func */
            8884097, 8, 0, /* 1864: pointer.func */
            8884097, 8, 0, /* 1867: pointer.func */
            8884097, 8, 0, /* 1870: pointer.func */
            8884097, 8, 0, /* 1873: pointer.func */
            8884097, 8, 0, /* 1876: pointer.func */
            8884097, 8, 0, /* 1879: pointer.func */
            8884097, 8, 0, /* 1882: pointer.func */
            8884097, 8, 0, /* 1885: pointer.func */
            8884097, 8, 0, /* 1888: pointer.func */
            8884097, 8, 0, /* 1891: pointer.func */
            1, 8, 1, /* 1894: pointer.struct.ec_point_st */
            	431, 0,
            0, 24, 1, /* 1899: struct.bignum_st */
            	418, 0,
            1, 8, 1, /* 1904: pointer.struct.ec_extra_data_st */
            	1909, 0,
            0, 40, 5, /* 1909: struct.ec_extra_data_st */
            	1922, 0,
            	1264, 8,
            	1927, 16,
            	1930, 24,
            	1930, 32,
            1, 8, 1, /* 1922: pointer.struct.ec_extra_data_st */
            	1909, 0,
            8884097, 8, 0, /* 1927: pointer.func */
            8884097, 8, 0, /* 1930: pointer.func */
            1, 8, 1, /* 1933: pointer.struct.bignum_st */
            	413, 0,
            1, 8, 1, /* 1938: pointer.struct.ec_extra_data_st */
            	1943, 0,
            0, 40, 5, /* 1943: struct.ec_extra_data_st */
            	1956, 0,
            	1264, 8,
            	1927, 16,
            	1930, 24,
            	1930, 32,
            1, 8, 1, /* 1956: pointer.struct.ec_extra_data_st */
            	1943, 0,
            8884097, 8, 0, /* 1961: pointer.func */
            1, 8, 1, /* 1964: pointer.struct.engine_st */
            	749, 0,
            8884097, 8, 0, /* 1969: pointer.func */
            8884097, 8, 0, /* 1972: pointer.func */
            0, 1, 0, /* 1975: char */
            0, 48, 5, /* 1978: struct.env_md_ctx_st */
            	1991, 0,
            	1964, 8,
            	1264, 24,
            	1284, 32,
            	2015, 40,
            1, 8, 1, /* 1991: pointer.struct.env_md_st */
            	1996, 0,
            0, 120, 8, /* 1996: struct.env_md_st */
            	1972, 24,
            	2015, 32,
            	2018, 40,
            	2021, 48,
            	1972, 56,
            	2024, 64,
            	1969, 72,
            	2027, 112,
            8884097, 8, 0, /* 2015: pointer.func */
            8884097, 8, 0, /* 2018: pointer.func */
            8884097, 8, 0, /* 2021: pointer.func */
            8884097, 8, 0, /* 2024: pointer.func */
            8884097, 8, 0, /* 2027: pointer.func */
            1, 8, 1, /* 2030: pointer.struct.env_md_ctx_st */
            	1978, 0,
        },
        .arg_entity_index = { -1 },
        .ret_entity_index = 2030,
    };
    struct lib_enter_args *args_addr = &args;
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    EVP_MD_CTX * *new_ret_ptr = (EVP_MD_CTX * *)new_args->ret;

    EVP_MD_CTX * (*orig_EVP_MD_CTX_create)(void);
    orig_EVP_MD_CTX_create = dlsym(RTLD_NEXT, "EVP_MD_CTX_create");
    *new_ret_ptr = (*orig_EVP_MD_CTX_create)();

    syscall(889);

    return ret;
}

