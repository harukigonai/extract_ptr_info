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

int bb_EVP_DigestUpdate(EVP_MD_CTX * arg_a, const void * arg_b,size_t arg_c);

int EVP_DigestUpdate(EVP_MD_CTX * arg_a, const void * arg_b,size_t arg_c) 
{
    unsigned long in_lib = syscall(890);
    printf("EVP_DigestUpdate called %lu\n", in_lib);
    if (!in_lib)
        return bb_EVP_DigestUpdate(arg_a,arg_b,arg_c);
    else {
        int (*orig_EVP_DigestUpdate)(EVP_MD_CTX *, const void *,size_t);
        orig_EVP_DigestUpdate = dlsym(RTLD_NEXT, "EVP_DigestUpdate");
        return orig_EVP_DigestUpdate(arg_a,arg_b,arg_c);
    }
}

int bb_EVP_DigestUpdate(EVP_MD_CTX * arg_a, const void * arg_b,size_t arg_c) 
{
    int ret;

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
            8884097, 8, 0, /* 625: pointer.func */
            1, 8, 1, /* 628: pointer.struct.dh_st */
            	633, 0,
            0, 144, 12, /* 633: struct.dh_st */
            	660, 8,
            	660, 16,
            	660, 32,
            	660, 40,
            	670, 56,
            	660, 64,
            	660, 72,
            	26, 80,
            	660, 96,
            	684, 112,
            	711, 128,
            	747, 136,
            1, 8, 1, /* 660: pointer.struct.bignum_st */
            	665, 0,
            0, 24, 1, /* 665: struct.bignum_st */
            	418, 0,
            1, 8, 1, /* 670: pointer.struct.bn_mont_ctx_st */
            	675, 0,
            0, 96, 3, /* 675: struct.bn_mont_ctx_st */
            	665, 8,
            	665, 32,
            	665, 56,
            0, 16, 1, /* 684: struct.crypto_ex_data_st */
            	689, 0,
            1, 8, 1, /* 689: pointer.struct.stack_st_void */
            	694, 0,
            0, 32, 1, /* 694: struct.stack_st_void */
            	699, 0,
            0, 32, 2, /* 699: struct.stack_st */
            	706, 8,
            	360, 24,
            1, 8, 1, /* 706: pointer.pointer.char */
            	142, 0,
            1, 8, 1, /* 711: pointer.struct.dh_method */
            	716, 0,
            0, 72, 8, /* 716: struct.dh_method */
            	161, 0,
            	735, 8,
            	738, 16,
            	741, 24,
            	735, 32,
            	735, 40,
            	142, 56,
            	744, 64,
            8884097, 8, 0, /* 735: pointer.func */
            8884097, 8, 0, /* 738: pointer.func */
            8884097, 8, 0, /* 741: pointer.func */
            8884097, 8, 0, /* 744: pointer.func */
            1, 8, 1, /* 747: pointer.struct.engine_st */
            	752, 0,
            0, 216, 24, /* 752: struct.engine_st */
            	161, 0,
            	161, 8,
            	803, 16,
            	858, 24,
            	909, 32,
            	945, 40,
            	962, 48,
            	986, 56,
            	1021, 64,
            	1029, 72,
            	1032, 80,
            	1035, 88,
            	1038, 96,
            	1041, 104,
            	1041, 112,
            	1041, 120,
            	1044, 128,
            	1047, 136,
            	1047, 144,
            	1050, 152,
            	1053, 160,
            	1065, 184,
            	1087, 200,
            	1087, 208,
            1, 8, 1, /* 803: pointer.struct.rsa_meth_st */
            	808, 0,
            0, 112, 13, /* 808: struct.rsa_meth_st */
            	161, 0,
            	837, 8,
            	837, 16,
            	837, 24,
            	837, 32,
            	840, 40,
            	843, 48,
            	846, 56,
            	846, 64,
            	142, 80,
            	849, 88,
            	852, 96,
            	855, 104,
            8884097, 8, 0, /* 837: pointer.func */
            8884097, 8, 0, /* 840: pointer.func */
            8884097, 8, 0, /* 843: pointer.func */
            8884097, 8, 0, /* 846: pointer.func */
            8884097, 8, 0, /* 849: pointer.func */
            8884097, 8, 0, /* 852: pointer.func */
            8884097, 8, 0, /* 855: pointer.func */
            1, 8, 1, /* 858: pointer.struct.dsa_method */
            	863, 0,
            0, 96, 11, /* 863: struct.dsa_method */
            	161, 0,
            	888, 8,
            	891, 16,
            	894, 24,
            	897, 32,
            	900, 40,
            	903, 48,
            	903, 56,
            	142, 72,
            	906, 80,
            	903, 88,
            8884097, 8, 0, /* 888: pointer.func */
            8884097, 8, 0, /* 891: pointer.func */
            8884097, 8, 0, /* 894: pointer.func */
            8884097, 8, 0, /* 897: pointer.func */
            8884097, 8, 0, /* 900: pointer.func */
            8884097, 8, 0, /* 903: pointer.func */
            8884097, 8, 0, /* 906: pointer.func */
            1, 8, 1, /* 909: pointer.struct.dh_method */
            	914, 0,
            0, 72, 8, /* 914: struct.dh_method */
            	161, 0,
            	933, 8,
            	936, 16,
            	939, 24,
            	933, 32,
            	933, 40,
            	142, 56,
            	942, 64,
            8884097, 8, 0, /* 933: pointer.func */
            8884097, 8, 0, /* 936: pointer.func */
            8884097, 8, 0, /* 939: pointer.func */
            8884097, 8, 0, /* 942: pointer.func */
            1, 8, 1, /* 945: pointer.struct.ecdh_method */
            	950, 0,
            0, 32, 3, /* 950: struct.ecdh_method */
            	161, 0,
            	959, 8,
            	142, 24,
            8884097, 8, 0, /* 959: pointer.func */
            1, 8, 1, /* 962: pointer.struct.ecdsa_method */
            	967, 0,
            0, 48, 5, /* 967: struct.ecdsa_method */
            	161, 0,
            	980, 8,
            	983, 16,
            	625, 24,
            	142, 40,
            8884097, 8, 0, /* 980: pointer.func */
            8884097, 8, 0, /* 983: pointer.func */
            1, 8, 1, /* 986: pointer.struct.rand_meth_st */
            	991, 0,
            0, 48, 6, /* 991: struct.rand_meth_st */
            	1006, 0,
            	1009, 8,
            	1012, 16,
            	1015, 24,
            	1009, 32,
            	1018, 40,
            8884097, 8, 0, /* 1006: pointer.func */
            8884097, 8, 0, /* 1009: pointer.func */
            8884097, 8, 0, /* 1012: pointer.func */
            8884097, 8, 0, /* 1015: pointer.func */
            8884097, 8, 0, /* 1018: pointer.func */
            1, 8, 1, /* 1021: pointer.struct.store_method_st */
            	1026, 0,
            0, 0, 0, /* 1026: struct.store_method_st */
            8884097, 8, 0, /* 1029: pointer.func */
            8884097, 8, 0, /* 1032: pointer.func */
            8884097, 8, 0, /* 1035: pointer.func */
            8884097, 8, 0, /* 1038: pointer.func */
            8884097, 8, 0, /* 1041: pointer.func */
            8884097, 8, 0, /* 1044: pointer.func */
            8884097, 8, 0, /* 1047: pointer.func */
            8884097, 8, 0, /* 1050: pointer.func */
            1, 8, 1, /* 1053: pointer.struct.ENGINE_CMD_DEFN_st */
            	1058, 0,
            0, 32, 2, /* 1058: struct.ENGINE_CMD_DEFN_st */
            	161, 8,
            	161, 16,
            0, 16, 1, /* 1065: struct.crypto_ex_data_st */
            	1070, 0,
            1, 8, 1, /* 1070: pointer.struct.stack_st_void */
            	1075, 0,
            0, 32, 1, /* 1075: struct.stack_st_void */
            	1080, 0,
            0, 32, 2, /* 1080: struct.stack_st */
            	706, 8,
            	360, 24,
            1, 8, 1, /* 1087: pointer.struct.engine_st */
            	752, 0,
            0, 112, 13, /* 1092: struct.rsa_meth_st */
            	161, 0,
            	1121, 8,
            	1121, 16,
            	1121, 24,
            	1121, 32,
            	1124, 40,
            	1127, 48,
            	1130, 56,
            	1130, 64,
            	142, 80,
            	1133, 88,
            	1136, 96,
            	1139, 104,
            8884097, 8, 0, /* 1121: pointer.func */
            8884097, 8, 0, /* 1124: pointer.func */
            8884097, 8, 0, /* 1127: pointer.func */
            8884097, 8, 0, /* 1130: pointer.func */
            8884097, 8, 0, /* 1133: pointer.func */
            8884097, 8, 0, /* 1136: pointer.func */
            8884097, 8, 0, /* 1139: pointer.func */
            0, 168, 17, /* 1142: struct.rsa_st */
            	1179, 16,
            	747, 24,
            	1184, 32,
            	1184, 40,
            	1184, 48,
            	1184, 56,
            	1184, 64,
            	1184, 72,
            	1184, 80,
            	1184, 88,
            	1194, 96,
            	1216, 120,
            	1216, 128,
            	1216, 136,
            	142, 144,
            	1230, 152,
            	1230, 160,
            1, 8, 1, /* 1179: pointer.struct.rsa_meth_st */
            	1092, 0,
            1, 8, 1, /* 1184: pointer.struct.bignum_st */
            	1189, 0,
            0, 24, 1, /* 1189: struct.bignum_st */
            	418, 0,
            0, 16, 1, /* 1194: struct.crypto_ex_data_st */
            	1199, 0,
            1, 8, 1, /* 1199: pointer.struct.stack_st_void */
            	1204, 0,
            0, 32, 1, /* 1204: struct.stack_st_void */
            	1209, 0,
            0, 32, 2, /* 1209: struct.stack_st */
            	706, 8,
            	360, 24,
            1, 8, 1, /* 1216: pointer.struct.bn_mont_ctx_st */
            	1221, 0,
            0, 96, 3, /* 1221: struct.bn_mont_ctx_st */
            	1189, 8,
            	1189, 32,
            	1189, 56,
            1, 8, 1, /* 1230: pointer.struct.bn_blinding_st */
            	1235, 0,
            0, 88, 7, /* 1235: struct.bn_blinding_st */
            	1252, 0,
            	1252, 8,
            	1252, 16,
            	1252, 24,
            	1262, 40,
            	1270, 72,
            	1284, 80,
            1, 8, 1, /* 1252: pointer.struct.bignum_st */
            	1257, 0,
            0, 24, 1, /* 1257: struct.bignum_st */
            	418, 0,
            0, 16, 1, /* 1262: struct.crypto_threadid_st */
            	1267, 0,
            0, 8, 0, /* 1267: pointer.void */
            1, 8, 1, /* 1270: pointer.struct.bn_mont_ctx_st */
            	1275, 0,
            0, 96, 3, /* 1275: struct.bn_mont_ctx_st */
            	1257, 8,
            	1257, 32,
            	1257, 56,
            8884097, 8, 0, /* 1284: pointer.func */
            1, 8, 1, /* 1287: pointer.struct.evp_pkey_ctx_st */
            	1292, 0,
            0, 80, 8, /* 1292: struct.evp_pkey_ctx_st */
            	1311, 0,
            	1405, 8,
            	1410, 16,
            	1410, 24,
            	1267, 40,
            	1267, 48,
            	1961, 56,
            	0, 64,
            1, 8, 1, /* 1311: pointer.struct.evp_pkey_method_st */
            	1316, 0,
            0, 208, 25, /* 1316: struct.evp_pkey_method_st */
            	1369, 8,
            	1372, 16,
            	1375, 24,
            	1369, 32,
            	1378, 40,
            	1369, 48,
            	1378, 56,
            	1369, 64,
            	1381, 72,
            	1369, 80,
            	1384, 88,
            	1369, 96,
            	1381, 104,
            	1387, 112,
            	1390, 120,
            	1387, 128,
            	1393, 136,
            	1369, 144,
            	1381, 152,
            	1369, 160,
            	1381, 168,
            	1369, 176,
            	1396, 184,
            	1399, 192,
            	1402, 200,
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
            8884097, 8, 0, /* 1402: pointer.func */
            1, 8, 1, /* 1405: pointer.struct.engine_st */
            	752, 0,
            1, 8, 1, /* 1410: pointer.struct.evp_pkey_st */
            	1415, 0,
            0, 56, 4, /* 1415: struct.evp_pkey_st */
            	1426, 16,
            	1405, 24,
            	1527, 32,
            	377, 48,
            1, 8, 1, /* 1426: pointer.struct.evp_pkey_asn1_method_st */
            	1431, 0,
            0, 208, 24, /* 1431: struct.evp_pkey_asn1_method_st */
            	142, 16,
            	142, 24,
            	1482, 32,
            	1485, 40,
            	1488, 48,
            	1491, 56,
            	1494, 64,
            	1497, 72,
            	1491, 80,
            	1500, 88,
            	1500, 96,
            	1503, 104,
            	1506, 112,
            	1500, 120,
            	1509, 128,
            	1488, 136,
            	1491, 144,
            	1512, 152,
            	1515, 160,
            	1518, 168,
            	1503, 176,
            	1506, 184,
            	1521, 192,
            	1524, 200,
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
            8884097, 8, 0, /* 1524: pointer.func */
            0, 8, 5, /* 1527: union.unknown */
            	142, 0,
            	1540, 0,
            	1545, 0,
            	628, 0,
            	1677, 0,
            1, 8, 1, /* 1540: pointer.struct.rsa_st */
            	1142, 0,
            1, 8, 1, /* 1545: pointer.struct.dsa_st */
            	1550, 0,
            0, 136, 11, /* 1550: struct.dsa_st */
            	1575, 24,
            	1575, 32,
            	1575, 40,
            	1575, 48,
            	1575, 56,
            	1575, 64,
            	1575, 72,
            	1585, 88,
            	1599, 104,
            	1621, 120,
            	1672, 128,
            1, 8, 1, /* 1575: pointer.struct.bignum_st */
            	1580, 0,
            0, 24, 1, /* 1580: struct.bignum_st */
            	418, 0,
            1, 8, 1, /* 1585: pointer.struct.bn_mont_ctx_st */
            	1590, 0,
            0, 96, 3, /* 1590: struct.bn_mont_ctx_st */
            	1580, 8,
            	1580, 32,
            	1580, 56,
            0, 16, 1, /* 1599: struct.crypto_ex_data_st */
            	1604, 0,
            1, 8, 1, /* 1604: pointer.struct.stack_st_void */
            	1609, 0,
            0, 32, 1, /* 1609: struct.stack_st_void */
            	1614, 0,
            0, 32, 2, /* 1614: struct.stack_st */
            	706, 8,
            	360, 24,
            1, 8, 1, /* 1621: pointer.struct.dsa_method */
            	1626, 0,
            0, 96, 11, /* 1626: struct.dsa_method */
            	161, 0,
            	1651, 8,
            	1654, 16,
            	1657, 24,
            	1660, 32,
            	1663, 40,
            	1666, 48,
            	1666, 56,
            	142, 72,
            	1669, 80,
            	1666, 88,
            8884097, 8, 0, /* 1651: pointer.func */
            8884097, 8, 0, /* 1654: pointer.func */
            8884097, 8, 0, /* 1657: pointer.func */
            8884097, 8, 0, /* 1660: pointer.func */
            8884097, 8, 0, /* 1663: pointer.func */
            8884097, 8, 0, /* 1666: pointer.func */
            8884097, 8, 0, /* 1669: pointer.func */
            1, 8, 1, /* 1672: pointer.struct.engine_st */
            	752, 0,
            1, 8, 1, /* 1677: pointer.struct.ec_key_st */
            	1682, 0,
            0, 56, 4, /* 1682: struct.ec_key_st */
            	1693, 8,
            	426, 16,
            	1933, 24,
            	1938, 48,
            1, 8, 1, /* 1693: pointer.struct.ec_group_st */
            	1698, 0,
            0, 232, 12, /* 1698: struct.ec_group_st */
            	1725, 0,
            	1897, 8,
            	1902, 16,
            	1902, 40,
            	26, 80,
            	1907, 96,
            	1902, 104,
            	1902, 152,
            	1902, 176,
            	1267, 208,
            	1267, 216,
            	619, 224,
            1, 8, 1, /* 1725: pointer.struct.ec_method_st */
            	1730, 0,
            0, 304, 37, /* 1730: struct.ec_method_st */
            	1807, 8,
            	1810, 16,
            	1810, 24,
            	1813, 32,
            	1816, 40,
            	1819, 48,
            	1822, 56,
            	1825, 64,
            	1828, 72,
            	1831, 80,
            	1831, 88,
            	1834, 96,
            	1837, 104,
            	1840, 112,
            	1843, 120,
            	1846, 128,
            	1849, 136,
            	1852, 144,
            	1855, 152,
            	1858, 160,
            	1861, 168,
            	1864, 176,
            	1867, 184,
            	1870, 192,
            	1873, 200,
            	1876, 208,
            	1867, 216,
            	1879, 224,
            	1882, 232,
            	1885, 240,
            	1822, 248,
            	1888, 256,
            	1891, 264,
            	1888, 272,
            	1891, 280,
            	1891, 288,
            	1894, 296,
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
            8884097, 8, 0, /* 1894: pointer.func */
            1, 8, 1, /* 1897: pointer.struct.ec_point_st */
            	431, 0,
            0, 24, 1, /* 1902: struct.bignum_st */
            	418, 0,
            1, 8, 1, /* 1907: pointer.struct.ec_extra_data_st */
            	1912, 0,
            0, 40, 5, /* 1912: struct.ec_extra_data_st */
            	1925, 0,
            	1267, 8,
            	622, 16,
            	1930, 24,
            	1930, 32,
            1, 8, 1, /* 1925: pointer.struct.ec_extra_data_st */
            	1912, 0,
            8884097, 8, 0, /* 1930: pointer.func */
            1, 8, 1, /* 1933: pointer.struct.bignum_st */
            	413, 0,
            1, 8, 1, /* 1938: pointer.struct.ec_extra_data_st */
            	1943, 0,
            0, 40, 5, /* 1943: struct.ec_extra_data_st */
            	1956, 0,
            	1267, 8,
            	622, 16,
            	1930, 24,
            	1930, 32,
            1, 8, 1, /* 1956: pointer.struct.ec_extra_data_st */
            	1943, 0,
            8884097, 8, 0, /* 1961: pointer.func */
            1, 8, 1, /* 1964: pointer.struct.engine_st */
            	752, 0,
            8884097, 8, 0, /* 1969: pointer.func */
            0, 1, 0, /* 1972: char */
            8884097, 8, 0, /* 1975: pointer.func */
            0, 0, 0, /* 1978: size_t */
            0, 120, 8, /* 1981: struct.env_md_st */
            	1975, 24,
            	2000, 32,
            	2003, 40,
            	2006, 48,
            	1975, 56,
            	2009, 64,
            	1969, 72,
            	2012, 112,
            8884097, 8, 0, /* 2000: pointer.func */
            8884097, 8, 0, /* 2003: pointer.func */
            8884097, 8, 0, /* 2006: pointer.func */
            8884097, 8, 0, /* 2009: pointer.func */
            8884097, 8, 0, /* 2012: pointer.func */
            0, 48, 5, /* 2015: struct.env_md_ctx_st */
            	2028, 0,
            	1964, 8,
            	1267, 24,
            	1287, 32,
            	2000, 40,
            1, 8, 1, /* 2028: pointer.struct.env_md_st */
            	1981, 0,
            1, 8, 1, /* 2033: pointer.struct.env_md_ctx_st */
            	2015, 0,
        },
        .arg_entity_index = { 2033, 1267, 1978, },
        .ret_entity_index = 5,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    EVP_MD_CTX * new_arg_a = *((EVP_MD_CTX * *)new_args->args[0]);

     const void * new_arg_b = *(( const void * *)new_args->args[1]);

    size_t new_arg_c = *((size_t *)new_args->args[2]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_EVP_DigestUpdate)(EVP_MD_CTX *, const void *,size_t);
    orig_EVP_DigestUpdate = dlsym(RTLD_NEXT, "EVP_DigestUpdate");
    *new_ret_ptr = (*orig_EVP_DigestUpdate)(new_arg_a,new_arg_b,new_arg_c);

    syscall(889);

    return ret;
}

