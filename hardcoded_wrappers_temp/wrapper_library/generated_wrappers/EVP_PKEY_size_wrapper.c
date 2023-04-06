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

int bb_EVP_PKEY_size(EVP_PKEY * arg_a);

int EVP_PKEY_size(EVP_PKEY * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("EVP_PKEY_size called %lu\n", in_lib);
    if (!in_lib)
        return bb_EVP_PKEY_size(arg_a);
    else {
        int (*orig_EVP_PKEY_size)(EVP_PKEY *);
        orig_EVP_PKEY_size = dlsym(RTLD_NEXT, "EVP_PKEY_size");
        return orig_EVP_PKEY_size(arg_a);
    }
}

int bb_EVP_PKEY_size(EVP_PKEY * arg_a) 
{
    int ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            1, 8, 1, /* 0: pointer.struct.ASN1_VALUE_st */
            	5, 0,
            0, 0, 0, /* 5: struct.ASN1_VALUE_st */
            1, 8, 1, /* 8: pointer.struct.asn1_string_st */
            	13, 0,
            0, 24, 1, /* 13: struct.asn1_string_st */
            	18, 8,
            1, 8, 1, /* 18: pointer.unsigned char */
            	23, 0,
            0, 1, 0, /* 23: unsigned char */
            1, 8, 1, /* 26: pointer.struct.asn1_string_st */
            	13, 0,
            1, 8, 1, /* 31: pointer.struct.asn1_string_st */
            	13, 0,
            1, 8, 1, /* 36: pointer.struct.asn1_string_st */
            	13, 0,
            1, 8, 1, /* 41: pointer.struct.asn1_string_st */
            	13, 0,
            1, 8, 1, /* 46: pointer.struct.asn1_string_st */
            	13, 0,
            1, 8, 1, /* 51: pointer.struct.asn1_string_st */
            	13, 0,
            1, 8, 1, /* 56: pointer.struct.asn1_string_st */
            	13, 0,
            1, 8, 1, /* 61: pointer.struct.asn1_string_st */
            	13, 0,
            1, 8, 1, /* 66: pointer.struct.asn1_string_st */
            	13, 0,
            1, 8, 1, /* 71: pointer.struct.asn1_string_st */
            	13, 0,
            1, 8, 1, /* 76: pointer.struct.asn1_string_st */
            	13, 0,
            1, 8, 1, /* 81: pointer.struct.asn1_string_st */
            	13, 0,
            0, 16, 1, /* 86: struct.asn1_type_st */
            	91, 8,
            0, 8, 20, /* 91: union.unknown */
            	134, 0,
            	81, 0,
            	139, 0,
            	163, 0,
            	76, 0,
            	71, 0,
            	66, 0,
            	61, 0,
            	56, 0,
            	51, 0,
            	46, 0,
            	41, 0,
            	36, 0,
            	31, 0,
            	26, 0,
            	168, 0,
            	8, 0,
            	81, 0,
            	81, 0,
            	0, 0,
            1, 8, 1, /* 134: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 139: pointer.struct.asn1_object_st */
            	144, 0,
            0, 40, 3, /* 144: struct.asn1_object_st */
            	153, 0,
            	153, 8,
            	158, 24,
            1, 8, 1, /* 153: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 158: pointer.unsigned char */
            	23, 0,
            1, 8, 1, /* 163: pointer.struct.asn1_string_st */
            	13, 0,
            1, 8, 1, /* 168: pointer.struct.asn1_string_st */
            	13, 0,
            1, 8, 1, /* 173: pointer.struct.ASN1_VALUE_st */
            	178, 0,
            0, 0, 0, /* 178: struct.ASN1_VALUE_st */
            1, 8, 1, /* 181: pointer.struct.asn1_string_st */
            	186, 0,
            0, 24, 1, /* 186: struct.asn1_string_st */
            	18, 8,
            1, 8, 1, /* 191: pointer.struct.asn1_string_st */
            	186, 0,
            1, 8, 1, /* 196: pointer.struct.asn1_string_st */
            	186, 0,
            1, 8, 1, /* 201: pointer.struct.asn1_string_st */
            	186, 0,
            1, 8, 1, /* 206: pointer.struct.asn1_string_st */
            	186, 0,
            1, 8, 1, /* 211: pointer.struct.asn1_string_st */
            	186, 0,
            1, 8, 1, /* 216: pointer.struct.asn1_string_st */
            	186, 0,
            1, 8, 1, /* 221: pointer.struct.dsa_method */
            	226, 0,
            0, 96, 11, /* 226: struct.dsa_method */
            	153, 0,
            	251, 8,
            	254, 16,
            	257, 24,
            	260, 32,
            	263, 40,
            	266, 48,
            	266, 56,
            	134, 72,
            	269, 80,
            	266, 88,
            8884097, 8, 0, /* 251: pointer.func */
            8884097, 8, 0, /* 254: pointer.func */
            8884097, 8, 0, /* 257: pointer.func */
            8884097, 8, 0, /* 260: pointer.func */
            8884097, 8, 0, /* 263: pointer.func */
            8884097, 8, 0, /* 266: pointer.func */
            8884097, 8, 0, /* 269: pointer.func */
            1, 8, 1, /* 272: pointer.struct.stack_st_void */
            	277, 0,
            0, 32, 1, /* 277: struct.stack_st_void */
            	282, 0,
            0, 32, 2, /* 282: struct.stack_st */
            	289, 8,
            	294, 24,
            1, 8, 1, /* 289: pointer.pointer.char */
            	134, 0,
            8884097, 8, 0, /* 294: pointer.func */
            0, 24, 1, /* 297: struct.bignum_st */
            	302, 0,
            1, 8, 1, /* 302: pointer.unsigned int */
            	307, 0,
            0, 4, 0, /* 307: unsigned int */
            1, 8, 1, /* 310: pointer.struct.bn_mont_ctx_st */
            	315, 0,
            0, 96, 3, /* 315: struct.bn_mont_ctx_st */
            	324, 8,
            	324, 32,
            	324, 56,
            0, 24, 1, /* 324: struct.bignum_st */
            	302, 0,
            8884097, 8, 0, /* 329: pointer.func */
            0, 8, 0, /* 332: pointer.void */
            1, 8, 1, /* 335: pointer.struct.stack_st_ASN1_TYPE */
            	340, 0,
            0, 32, 2, /* 340: struct.stack_st_fake_ASN1_TYPE */
            	347, 8,
            	294, 24,
            8884099, 8, 2, /* 347: pointer_to_array_of_pointers_to_stack */
            	354, 0,
            	466, 20,
            0, 8, 1, /* 354: pointer.ASN1_TYPE */
            	359, 0,
            0, 0, 1, /* 359: ASN1_TYPE */
            	364, 0,
            0, 16, 1, /* 364: struct.asn1_type_st */
            	369, 8,
            0, 8, 20, /* 369: union.unknown */
            	134, 0,
            	412, 0,
            	417, 0,
            	431, 0,
            	436, 0,
            	441, 0,
            	216, 0,
            	446, 0,
            	451, 0,
            	211, 0,
            	206, 0,
            	456, 0,
            	201, 0,
            	196, 0,
            	191, 0,
            	461, 0,
            	181, 0,
            	412, 0,
            	412, 0,
            	173, 0,
            1, 8, 1, /* 412: pointer.struct.asn1_string_st */
            	186, 0,
            1, 8, 1, /* 417: pointer.struct.asn1_object_st */
            	422, 0,
            0, 40, 3, /* 422: struct.asn1_object_st */
            	153, 0,
            	153, 8,
            	158, 24,
            1, 8, 1, /* 431: pointer.struct.asn1_string_st */
            	186, 0,
            1, 8, 1, /* 436: pointer.struct.asn1_string_st */
            	186, 0,
            1, 8, 1, /* 441: pointer.struct.asn1_string_st */
            	186, 0,
            1, 8, 1, /* 446: pointer.struct.asn1_string_st */
            	186, 0,
            1, 8, 1, /* 451: pointer.struct.asn1_string_st */
            	186, 0,
            1, 8, 1, /* 456: pointer.struct.asn1_string_st */
            	186, 0,
            1, 8, 1, /* 461: pointer.struct.asn1_string_st */
            	186, 0,
            0, 4, 0, /* 466: int */
            0, 88, 7, /* 469: struct.bn_blinding_st */
            	486, 0,
            	486, 8,
            	486, 16,
            	486, 24,
            	496, 40,
            	501, 72,
            	515, 80,
            1, 8, 1, /* 486: pointer.struct.bignum_st */
            	491, 0,
            0, 24, 1, /* 491: struct.bignum_st */
            	302, 0,
            0, 16, 1, /* 496: struct.crypto_threadid_st */
            	332, 0,
            1, 8, 1, /* 501: pointer.struct.bn_mont_ctx_st */
            	506, 0,
            0, 96, 3, /* 506: struct.bn_mont_ctx_st */
            	491, 8,
            	491, 32,
            	491, 56,
            8884097, 8, 0, /* 515: pointer.func */
            1, 8, 1, /* 518: pointer.struct.bn_mont_ctx_st */
            	523, 0,
            0, 96, 3, /* 523: struct.bn_mont_ctx_st */
            	297, 8,
            	297, 32,
            	297, 56,
            0, 96, 3, /* 532: struct.bn_mont_ctx_st */
            	541, 8,
            	541, 32,
            	541, 56,
            0, 24, 1, /* 541: struct.bignum_st */
            	302, 0,
            8884097, 8, 0, /* 546: pointer.func */
            1, 8, 1, /* 549: pointer.struct.bn_mont_ctx_st */
            	532, 0,
            0, 32, 1, /* 554: struct.stack_st_void */
            	559, 0,
            0, 32, 2, /* 559: struct.stack_st */
            	289, 8,
            	294, 24,
            8884097, 8, 0, /* 566: pointer.func */
            1, 8, 1, /* 569: pointer.struct.stack_st_void */
            	554, 0,
            0, 16, 1, /* 574: struct.crypto_ex_data_st */
            	569, 0,
            0, 0, 0, /* 579: struct.store_method_st */
            1, 8, 1, /* 582: pointer.struct.bignum_st */
            	324, 0,
            8884097, 8, 0, /* 587: pointer.func */
            0, 48, 6, /* 590: struct.rand_meth_st */
            	605, 0,
            	608, 8,
            	611, 16,
            	614, 24,
            	608, 32,
            	617, 40,
            8884097, 8, 0, /* 605: pointer.func */
            8884097, 8, 0, /* 608: pointer.func */
            8884097, 8, 0, /* 611: pointer.func */
            8884097, 8, 0, /* 614: pointer.func */
            8884097, 8, 0, /* 617: pointer.func */
            8884097, 8, 0, /* 620: pointer.func */
            0, 112, 13, /* 623: struct.rsa_meth_st */
            	153, 0,
            	652, 8,
            	652, 16,
            	652, 24,
            	652, 32,
            	655, 40,
            	658, 48,
            	566, 56,
            	566, 64,
            	134, 80,
            	661, 88,
            	664, 96,
            	667, 104,
            8884097, 8, 0, /* 652: pointer.func */
            8884097, 8, 0, /* 655: pointer.func */
            8884097, 8, 0, /* 658: pointer.func */
            8884097, 8, 0, /* 661: pointer.func */
            8884097, 8, 0, /* 664: pointer.func */
            8884097, 8, 0, /* 667: pointer.func */
            0, 32, 2, /* 670: struct.stack_st */
            	289, 8,
            	294, 24,
            0, 168, 17, /* 677: struct.rsa_st */
            	714, 16,
            	719, 24,
            	1025, 32,
            	1025, 40,
            	1025, 48,
            	1025, 56,
            	1025, 64,
            	1025, 72,
            	1025, 80,
            	1025, 88,
            	574, 96,
            	549, 120,
            	549, 128,
            	549, 136,
            	134, 144,
            	1030, 152,
            	1030, 160,
            1, 8, 1, /* 714: pointer.struct.rsa_meth_st */
            	623, 0,
            1, 8, 1, /* 719: pointer.struct.engine_st */
            	724, 0,
            0, 216, 24, /* 724: struct.engine_st */
            	153, 0,
            	153, 8,
            	775, 16,
            	824, 24,
            	875, 32,
            	911, 40,
            	928, 48,
            	952, 56,
            	957, 64,
            	962, 72,
            	965, 80,
            	968, 88,
            	971, 96,
            	974, 104,
            	974, 112,
            	974, 120,
            	977, 128,
            	980, 136,
            	980, 144,
            	983, 152,
            	986, 160,
            	998, 184,
            	1020, 200,
            	1020, 208,
            1, 8, 1, /* 775: pointer.struct.rsa_meth_st */
            	780, 0,
            0, 112, 13, /* 780: struct.rsa_meth_st */
            	153, 0,
            	809, 8,
            	809, 16,
            	809, 24,
            	809, 32,
            	812, 40,
            	546, 48,
            	815, 56,
            	815, 64,
            	134, 80,
            	818, 88,
            	821, 96,
            	329, 104,
            8884097, 8, 0, /* 809: pointer.func */
            8884097, 8, 0, /* 812: pointer.func */
            8884097, 8, 0, /* 815: pointer.func */
            8884097, 8, 0, /* 818: pointer.func */
            8884097, 8, 0, /* 821: pointer.func */
            1, 8, 1, /* 824: pointer.struct.dsa_method */
            	829, 0,
            0, 96, 11, /* 829: struct.dsa_method */
            	153, 0,
            	854, 8,
            	857, 16,
            	860, 24,
            	863, 32,
            	866, 40,
            	869, 48,
            	869, 56,
            	134, 72,
            	872, 80,
            	869, 88,
            8884097, 8, 0, /* 854: pointer.func */
            8884097, 8, 0, /* 857: pointer.func */
            8884097, 8, 0, /* 860: pointer.func */
            8884097, 8, 0, /* 863: pointer.func */
            8884097, 8, 0, /* 866: pointer.func */
            8884097, 8, 0, /* 869: pointer.func */
            8884097, 8, 0, /* 872: pointer.func */
            1, 8, 1, /* 875: pointer.struct.dh_method */
            	880, 0,
            0, 72, 8, /* 880: struct.dh_method */
            	153, 0,
            	899, 8,
            	902, 16,
            	905, 24,
            	899, 32,
            	899, 40,
            	134, 56,
            	908, 64,
            8884097, 8, 0, /* 899: pointer.func */
            8884097, 8, 0, /* 902: pointer.func */
            8884097, 8, 0, /* 905: pointer.func */
            8884097, 8, 0, /* 908: pointer.func */
            1, 8, 1, /* 911: pointer.struct.ecdh_method */
            	916, 0,
            0, 32, 3, /* 916: struct.ecdh_method */
            	153, 0,
            	925, 8,
            	134, 24,
            8884097, 8, 0, /* 925: pointer.func */
            1, 8, 1, /* 928: pointer.struct.ecdsa_method */
            	933, 0,
            0, 48, 5, /* 933: struct.ecdsa_method */
            	153, 0,
            	946, 8,
            	949, 16,
            	620, 24,
            	134, 40,
            8884097, 8, 0, /* 946: pointer.func */
            8884097, 8, 0, /* 949: pointer.func */
            1, 8, 1, /* 952: pointer.struct.rand_meth_st */
            	590, 0,
            1, 8, 1, /* 957: pointer.struct.store_method_st */
            	579, 0,
            8884097, 8, 0, /* 962: pointer.func */
            8884097, 8, 0, /* 965: pointer.func */
            8884097, 8, 0, /* 968: pointer.func */
            8884097, 8, 0, /* 971: pointer.func */
            8884097, 8, 0, /* 974: pointer.func */
            8884097, 8, 0, /* 977: pointer.func */
            8884097, 8, 0, /* 980: pointer.func */
            8884097, 8, 0, /* 983: pointer.func */
            1, 8, 1, /* 986: pointer.struct.ENGINE_CMD_DEFN_st */
            	991, 0,
            0, 32, 2, /* 991: struct.ENGINE_CMD_DEFN_st */
            	153, 8,
            	153, 16,
            0, 16, 1, /* 998: struct.crypto_ex_data_st */
            	1003, 0,
            1, 8, 1, /* 1003: pointer.struct.stack_st_void */
            	1008, 0,
            0, 32, 1, /* 1008: struct.stack_st_void */
            	1013, 0,
            0, 32, 2, /* 1013: struct.stack_st */
            	289, 8,
            	294, 24,
            1, 8, 1, /* 1020: pointer.struct.engine_st */
            	724, 0,
            1, 8, 1, /* 1025: pointer.struct.bignum_st */
            	541, 0,
            1, 8, 1, /* 1030: pointer.struct.bn_blinding_st */
            	469, 0,
            0, 136, 11, /* 1035: struct.dsa_st */
            	582, 24,
            	582, 32,
            	582, 40,
            	582, 48,
            	582, 56,
            	582, 64,
            	582, 72,
            	310, 88,
            	1060, 104,
            	221, 120,
            	1065, 128,
            0, 16, 1, /* 1060: struct.crypto_ex_data_st */
            	272, 0,
            1, 8, 1, /* 1065: pointer.struct.engine_st */
            	724, 0,
            1, 8, 1, /* 1070: pointer.struct.rsa_st */
            	677, 0,
            8884097, 8, 0, /* 1075: pointer.func */
            0, 8, 5, /* 1078: union.unknown */
            	134, 0,
            	1070, 0,
            	1091, 0,
            	1096, 0,
            	1184, 0,
            1, 8, 1, /* 1091: pointer.struct.dsa_st */
            	1035, 0,
            1, 8, 1, /* 1096: pointer.struct.dh_st */
            	1101, 0,
            0, 144, 12, /* 1101: struct.dh_st */
            	1128, 8,
            	1128, 16,
            	1128, 32,
            	1128, 40,
            	518, 56,
            	1128, 64,
            	1128, 72,
            	18, 80,
            	1128, 96,
            	1133, 112,
            	1148, 128,
            	719, 136,
            1, 8, 1, /* 1128: pointer.struct.bignum_st */
            	297, 0,
            0, 16, 1, /* 1133: struct.crypto_ex_data_st */
            	1138, 0,
            1, 8, 1, /* 1138: pointer.struct.stack_st_void */
            	1143, 0,
            0, 32, 1, /* 1143: struct.stack_st_void */
            	670, 0,
            1, 8, 1, /* 1148: pointer.struct.dh_method */
            	1153, 0,
            0, 72, 8, /* 1153: struct.dh_method */
            	153, 0,
            	1172, 8,
            	1175, 16,
            	1178, 24,
            	1172, 32,
            	1172, 40,
            	134, 56,
            	1181, 64,
            8884097, 8, 0, /* 1172: pointer.func */
            8884097, 8, 0, /* 1175: pointer.func */
            8884097, 8, 0, /* 1178: pointer.func */
            8884097, 8, 0, /* 1181: pointer.func */
            1, 8, 1, /* 1184: pointer.struct.ec_key_st */
            	1189, 0,
            0, 56, 4, /* 1189: struct.ec_key_st */
            	1200, 8,
            	1631, 16,
            	1636, 24,
            	1646, 48,
            1, 8, 1, /* 1200: pointer.struct.ec_group_st */
            	1205, 0,
            0, 232, 12, /* 1205: struct.ec_group_st */
            	1232, 0,
            	1401, 8,
            	1594, 16,
            	1594, 40,
            	18, 80,
            	1599, 96,
            	1594, 104,
            	1594, 152,
            	1594, 176,
            	332, 208,
            	332, 216,
            	1628, 224,
            1, 8, 1, /* 1232: pointer.struct.ec_method_st */
            	1237, 0,
            0, 304, 37, /* 1237: struct.ec_method_st */
            	1314, 8,
            	1317, 16,
            	1317, 24,
            	1320, 32,
            	1323, 40,
            	1326, 48,
            	1329, 56,
            	1332, 64,
            	1335, 72,
            	1338, 80,
            	1338, 88,
            	1341, 96,
            	1344, 104,
            	1347, 112,
            	1350, 120,
            	1353, 128,
            	1356, 136,
            	1359, 144,
            	1362, 152,
            	1075, 160,
            	1365, 168,
            	1368, 176,
            	1371, 184,
            	1374, 192,
            	1377, 200,
            	1380, 208,
            	1371, 216,
            	1383, 224,
            	1386, 232,
            	1389, 240,
            	1329, 248,
            	1392, 256,
            	1395, 264,
            	1392, 272,
            	1395, 280,
            	1395, 288,
            	1398, 296,
            8884097, 8, 0, /* 1314: pointer.func */
            8884097, 8, 0, /* 1317: pointer.func */
            8884097, 8, 0, /* 1320: pointer.func */
            8884097, 8, 0, /* 1323: pointer.func */
            8884097, 8, 0, /* 1326: pointer.func */
            8884097, 8, 0, /* 1329: pointer.func */
            8884097, 8, 0, /* 1332: pointer.func */
            8884097, 8, 0, /* 1335: pointer.func */
            8884097, 8, 0, /* 1338: pointer.func */
            8884097, 8, 0, /* 1341: pointer.func */
            8884097, 8, 0, /* 1344: pointer.func */
            8884097, 8, 0, /* 1347: pointer.func */
            8884097, 8, 0, /* 1350: pointer.func */
            8884097, 8, 0, /* 1353: pointer.func */
            8884097, 8, 0, /* 1356: pointer.func */
            8884097, 8, 0, /* 1359: pointer.func */
            8884097, 8, 0, /* 1362: pointer.func */
            8884097, 8, 0, /* 1365: pointer.func */
            8884097, 8, 0, /* 1368: pointer.func */
            8884097, 8, 0, /* 1371: pointer.func */
            8884097, 8, 0, /* 1374: pointer.func */
            8884097, 8, 0, /* 1377: pointer.func */
            8884097, 8, 0, /* 1380: pointer.func */
            8884097, 8, 0, /* 1383: pointer.func */
            8884097, 8, 0, /* 1386: pointer.func */
            8884097, 8, 0, /* 1389: pointer.func */
            8884097, 8, 0, /* 1392: pointer.func */
            8884097, 8, 0, /* 1395: pointer.func */
            8884097, 8, 0, /* 1398: pointer.func */
            1, 8, 1, /* 1401: pointer.struct.ec_point_st */
            	1406, 0,
            0, 88, 4, /* 1406: struct.ec_point_st */
            	1417, 0,
            	1589, 8,
            	1589, 32,
            	1589, 56,
            1, 8, 1, /* 1417: pointer.struct.ec_method_st */
            	1422, 0,
            0, 304, 37, /* 1422: struct.ec_method_st */
            	1499, 8,
            	1502, 16,
            	1502, 24,
            	1505, 32,
            	1508, 40,
            	1511, 48,
            	1514, 56,
            	1517, 64,
            	1520, 72,
            	1523, 80,
            	1523, 88,
            	1526, 96,
            	1529, 104,
            	1532, 112,
            	1535, 120,
            	1538, 128,
            	1541, 136,
            	1544, 144,
            	1547, 152,
            	1550, 160,
            	1553, 168,
            	1556, 176,
            	1559, 184,
            	1562, 192,
            	1565, 200,
            	1568, 208,
            	1559, 216,
            	1571, 224,
            	1574, 232,
            	1577, 240,
            	1514, 248,
            	1580, 256,
            	1583, 264,
            	1580, 272,
            	1583, 280,
            	1583, 288,
            	1586, 296,
            8884097, 8, 0, /* 1499: pointer.func */
            8884097, 8, 0, /* 1502: pointer.func */
            8884097, 8, 0, /* 1505: pointer.func */
            8884097, 8, 0, /* 1508: pointer.func */
            8884097, 8, 0, /* 1511: pointer.func */
            8884097, 8, 0, /* 1514: pointer.func */
            8884097, 8, 0, /* 1517: pointer.func */
            8884097, 8, 0, /* 1520: pointer.func */
            8884097, 8, 0, /* 1523: pointer.func */
            8884097, 8, 0, /* 1526: pointer.func */
            8884097, 8, 0, /* 1529: pointer.func */
            8884097, 8, 0, /* 1532: pointer.func */
            8884097, 8, 0, /* 1535: pointer.func */
            8884097, 8, 0, /* 1538: pointer.func */
            8884097, 8, 0, /* 1541: pointer.func */
            8884097, 8, 0, /* 1544: pointer.func */
            8884097, 8, 0, /* 1547: pointer.func */
            8884097, 8, 0, /* 1550: pointer.func */
            8884097, 8, 0, /* 1553: pointer.func */
            8884097, 8, 0, /* 1556: pointer.func */
            8884097, 8, 0, /* 1559: pointer.func */
            8884097, 8, 0, /* 1562: pointer.func */
            8884097, 8, 0, /* 1565: pointer.func */
            8884097, 8, 0, /* 1568: pointer.func */
            8884097, 8, 0, /* 1571: pointer.func */
            8884097, 8, 0, /* 1574: pointer.func */
            8884097, 8, 0, /* 1577: pointer.func */
            8884097, 8, 0, /* 1580: pointer.func */
            8884097, 8, 0, /* 1583: pointer.func */
            8884097, 8, 0, /* 1586: pointer.func */
            0, 24, 1, /* 1589: struct.bignum_st */
            	302, 0,
            0, 24, 1, /* 1594: struct.bignum_st */
            	302, 0,
            1, 8, 1, /* 1599: pointer.struct.ec_extra_data_st */
            	1604, 0,
            0, 40, 5, /* 1604: struct.ec_extra_data_st */
            	1617, 0,
            	332, 8,
            	1622, 16,
            	1625, 24,
            	1625, 32,
            1, 8, 1, /* 1617: pointer.struct.ec_extra_data_st */
            	1604, 0,
            8884097, 8, 0, /* 1622: pointer.func */
            8884097, 8, 0, /* 1625: pointer.func */
            8884097, 8, 0, /* 1628: pointer.func */
            1, 8, 1, /* 1631: pointer.struct.ec_point_st */
            	1406, 0,
            1, 8, 1, /* 1636: pointer.struct.bignum_st */
            	1641, 0,
            0, 24, 1, /* 1641: struct.bignum_st */
            	302, 0,
            1, 8, 1, /* 1646: pointer.struct.ec_extra_data_st */
            	1651, 0,
            0, 40, 5, /* 1651: struct.ec_extra_data_st */
            	1664, 0,
            	332, 8,
            	1622, 16,
            	1625, 24,
            	1625, 32,
            1, 8, 1, /* 1664: pointer.struct.ec_extra_data_st */
            	1651, 0,
            0, 208, 24, /* 1669: struct.evp_pkey_asn1_method_st */
            	134, 16,
            	134, 24,
            	1720, 32,
            	1723, 40,
            	1726, 48,
            	1729, 56,
            	1732, 64,
            	1735, 72,
            	1729, 80,
            	1738, 88,
            	1738, 96,
            	1741, 104,
            	1744, 112,
            	1738, 120,
            	1747, 128,
            	1726, 136,
            	1729, 144,
            	587, 152,
            	1750, 160,
            	1753, 168,
            	1741, 176,
            	1744, 184,
            	1756, 192,
            	1759, 200,
            8884097, 8, 0, /* 1720: pointer.func */
            8884097, 8, 0, /* 1723: pointer.func */
            8884097, 8, 0, /* 1726: pointer.func */
            8884097, 8, 0, /* 1729: pointer.func */
            8884097, 8, 0, /* 1732: pointer.func */
            8884097, 8, 0, /* 1735: pointer.func */
            8884097, 8, 0, /* 1738: pointer.func */
            8884097, 8, 0, /* 1741: pointer.func */
            8884097, 8, 0, /* 1744: pointer.func */
            8884097, 8, 0, /* 1747: pointer.func */
            8884097, 8, 0, /* 1750: pointer.func */
            8884097, 8, 0, /* 1753: pointer.func */
            8884097, 8, 0, /* 1756: pointer.func */
            8884097, 8, 0, /* 1759: pointer.func */
            1, 8, 1, /* 1762: pointer.struct.evp_pkey_asn1_method_st */
            	1669, 0,
            1, 8, 1, /* 1767: pointer.struct.asn1_type_st */
            	86, 0,
            1, 8, 1, /* 1772: pointer.struct.engine_st */
            	724, 0,
            1, 8, 1, /* 1777: pointer.struct.evp_pkey_st */
            	1782, 0,
            0, 56, 4, /* 1782: struct.evp_pkey_st */
            	1762, 16,
            	1772, 24,
            	1078, 32,
            	1793, 48,
            1, 8, 1, /* 1793: pointer.struct.stack_st_X509_ATTRIBUTE */
            	1798, 0,
            0, 32, 2, /* 1798: struct.stack_st_fake_X509_ATTRIBUTE */
            	1805, 8,
            	294, 24,
            8884099, 8, 2, /* 1805: pointer_to_array_of_pointers_to_stack */
            	1812, 0,
            	466, 20,
            0, 8, 1, /* 1812: pointer.X509_ATTRIBUTE */
            	1817, 0,
            0, 0, 1, /* 1817: X509_ATTRIBUTE */
            	1822, 0,
            0, 24, 2, /* 1822: struct.x509_attributes_st */
            	139, 0,
            	1829, 16,
            0, 8, 3, /* 1829: union.unknown */
            	134, 0,
            	335, 0,
            	1767, 0,
            0, 1, 0, /* 1838: char */
        },
        .arg_entity_index = { 1777, },
        .ret_entity_index = 466,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    EVP_PKEY * new_arg_a = *((EVP_PKEY * *)new_args->args[0]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_EVP_PKEY_size)(EVP_PKEY *);
    orig_EVP_PKEY_size = dlsym(RTLD_NEXT, "EVP_PKEY_size");
    *new_ret_ptr = (*orig_EVP_PKEY_size)(new_arg_a);

    syscall(889);

    return ret;
}

