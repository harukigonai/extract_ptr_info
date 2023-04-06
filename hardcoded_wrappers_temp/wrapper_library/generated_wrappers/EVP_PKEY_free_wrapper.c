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

void bb_EVP_PKEY_free(EVP_PKEY * arg_a);

void EVP_PKEY_free(EVP_PKEY * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("EVP_PKEY_free called %lu\n", in_lib);
    if (!in_lib)
        bb_EVP_PKEY_free(arg_a);
    else {
        void (*orig_EVP_PKEY_free)(EVP_PKEY *);
        orig_EVP_PKEY_free = dlsym(RTLD_NEXT, "EVP_PKEY_free");
        orig_EVP_PKEY_free(arg_a);
    }
}

void bb_EVP_PKEY_free(EVP_PKEY * arg_a) 
{
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
            0, 168, 17, /* 670: struct.rsa_st */
            	707, 16,
            	712, 24,
            	1018, 32,
            	1018, 40,
            	1018, 48,
            	1018, 56,
            	1018, 64,
            	1018, 72,
            	1018, 80,
            	1018, 88,
            	574, 96,
            	549, 120,
            	549, 128,
            	549, 136,
            	134, 144,
            	1023, 152,
            	1023, 160,
            1, 8, 1, /* 707: pointer.struct.rsa_meth_st */
            	623, 0,
            1, 8, 1, /* 712: pointer.struct.engine_st */
            	717, 0,
            0, 216, 24, /* 717: struct.engine_st */
            	153, 0,
            	153, 8,
            	768, 16,
            	817, 24,
            	868, 32,
            	904, 40,
            	921, 48,
            	945, 56,
            	950, 64,
            	955, 72,
            	958, 80,
            	961, 88,
            	964, 96,
            	967, 104,
            	967, 112,
            	967, 120,
            	970, 128,
            	973, 136,
            	973, 144,
            	976, 152,
            	979, 160,
            	991, 184,
            	1013, 200,
            	1013, 208,
            1, 8, 1, /* 768: pointer.struct.rsa_meth_st */
            	773, 0,
            0, 112, 13, /* 773: struct.rsa_meth_st */
            	153, 0,
            	802, 8,
            	802, 16,
            	802, 24,
            	802, 32,
            	805, 40,
            	546, 48,
            	808, 56,
            	808, 64,
            	134, 80,
            	811, 88,
            	814, 96,
            	329, 104,
            8884097, 8, 0, /* 802: pointer.func */
            8884097, 8, 0, /* 805: pointer.func */
            8884097, 8, 0, /* 808: pointer.func */
            8884097, 8, 0, /* 811: pointer.func */
            8884097, 8, 0, /* 814: pointer.func */
            1, 8, 1, /* 817: pointer.struct.dsa_method */
            	822, 0,
            0, 96, 11, /* 822: struct.dsa_method */
            	153, 0,
            	847, 8,
            	850, 16,
            	853, 24,
            	856, 32,
            	859, 40,
            	862, 48,
            	862, 56,
            	134, 72,
            	865, 80,
            	862, 88,
            8884097, 8, 0, /* 847: pointer.func */
            8884097, 8, 0, /* 850: pointer.func */
            8884097, 8, 0, /* 853: pointer.func */
            8884097, 8, 0, /* 856: pointer.func */
            8884097, 8, 0, /* 859: pointer.func */
            8884097, 8, 0, /* 862: pointer.func */
            8884097, 8, 0, /* 865: pointer.func */
            1, 8, 1, /* 868: pointer.struct.dh_method */
            	873, 0,
            0, 72, 8, /* 873: struct.dh_method */
            	153, 0,
            	892, 8,
            	895, 16,
            	898, 24,
            	892, 32,
            	892, 40,
            	134, 56,
            	901, 64,
            8884097, 8, 0, /* 892: pointer.func */
            8884097, 8, 0, /* 895: pointer.func */
            8884097, 8, 0, /* 898: pointer.func */
            8884097, 8, 0, /* 901: pointer.func */
            1, 8, 1, /* 904: pointer.struct.ecdh_method */
            	909, 0,
            0, 32, 3, /* 909: struct.ecdh_method */
            	153, 0,
            	918, 8,
            	134, 24,
            8884097, 8, 0, /* 918: pointer.func */
            1, 8, 1, /* 921: pointer.struct.ecdsa_method */
            	926, 0,
            0, 48, 5, /* 926: struct.ecdsa_method */
            	153, 0,
            	939, 8,
            	942, 16,
            	620, 24,
            	134, 40,
            8884097, 8, 0, /* 939: pointer.func */
            8884097, 8, 0, /* 942: pointer.func */
            1, 8, 1, /* 945: pointer.struct.rand_meth_st */
            	590, 0,
            1, 8, 1, /* 950: pointer.struct.store_method_st */
            	579, 0,
            8884097, 8, 0, /* 955: pointer.func */
            8884097, 8, 0, /* 958: pointer.func */
            8884097, 8, 0, /* 961: pointer.func */
            8884097, 8, 0, /* 964: pointer.func */
            8884097, 8, 0, /* 967: pointer.func */
            8884097, 8, 0, /* 970: pointer.func */
            8884097, 8, 0, /* 973: pointer.func */
            8884097, 8, 0, /* 976: pointer.func */
            1, 8, 1, /* 979: pointer.struct.ENGINE_CMD_DEFN_st */
            	984, 0,
            0, 32, 2, /* 984: struct.ENGINE_CMD_DEFN_st */
            	153, 8,
            	153, 16,
            0, 16, 1, /* 991: struct.crypto_ex_data_st */
            	996, 0,
            1, 8, 1, /* 996: pointer.struct.stack_st_void */
            	1001, 0,
            0, 32, 1, /* 1001: struct.stack_st_void */
            	1006, 0,
            0, 32, 2, /* 1006: struct.stack_st */
            	289, 8,
            	294, 24,
            1, 8, 1, /* 1013: pointer.struct.engine_st */
            	717, 0,
            1, 8, 1, /* 1018: pointer.struct.bignum_st */
            	541, 0,
            1, 8, 1, /* 1023: pointer.struct.bn_blinding_st */
            	469, 0,
            0, 136, 11, /* 1028: struct.dsa_st */
            	582, 24,
            	582, 32,
            	582, 40,
            	582, 48,
            	582, 56,
            	582, 64,
            	582, 72,
            	310, 88,
            	1053, 104,
            	221, 120,
            	1058, 128,
            0, 16, 1, /* 1053: struct.crypto_ex_data_st */
            	272, 0,
            1, 8, 1, /* 1058: pointer.struct.engine_st */
            	717, 0,
            1, 8, 1, /* 1063: pointer.struct.rsa_st */
            	670, 0,
            8884097, 8, 0, /* 1068: pointer.func */
            0, 8, 5, /* 1071: union.unknown */
            	134, 0,
            	1063, 0,
            	1084, 0,
            	1089, 0,
            	1184, 0,
            1, 8, 1, /* 1084: pointer.struct.dsa_st */
            	1028, 0,
            1, 8, 1, /* 1089: pointer.struct.dh_st */
            	1094, 0,
            0, 144, 12, /* 1094: struct.dh_st */
            	1121, 8,
            	1121, 16,
            	1121, 32,
            	1121, 40,
            	518, 56,
            	1121, 64,
            	1121, 72,
            	18, 80,
            	1121, 96,
            	1126, 112,
            	1148, 128,
            	712, 136,
            1, 8, 1, /* 1121: pointer.struct.bignum_st */
            	297, 0,
            0, 16, 1, /* 1126: struct.crypto_ex_data_st */
            	1131, 0,
            1, 8, 1, /* 1131: pointer.struct.stack_st_void */
            	1136, 0,
            0, 32, 1, /* 1136: struct.stack_st_void */
            	1141, 0,
            0, 32, 2, /* 1141: struct.stack_st */
            	289, 8,
            	294, 24,
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
            	1068, 160,
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
            1, 8, 1, /* 1767: pointer.struct.engine_st */
            	717, 0,
            1, 8, 1, /* 1772: pointer.struct.evp_pkey_st */
            	1777, 0,
            0, 56, 4, /* 1777: struct.evp_pkey_st */
            	1762, 16,
            	1767, 24,
            	1071, 32,
            	1788, 48,
            1, 8, 1, /* 1788: pointer.struct.stack_st_X509_ATTRIBUTE */
            	1793, 0,
            0, 32, 2, /* 1793: struct.stack_st_fake_X509_ATTRIBUTE */
            	1800, 8,
            	294, 24,
            8884099, 8, 2, /* 1800: pointer_to_array_of_pointers_to_stack */
            	1807, 0,
            	466, 20,
            0, 8, 1, /* 1807: pointer.X509_ATTRIBUTE */
            	1812, 0,
            0, 0, 1, /* 1812: X509_ATTRIBUTE */
            	1817, 0,
            0, 24, 2, /* 1817: struct.x509_attributes_st */
            	139, 0,
            	1824, 16,
            0, 8, 3, /* 1824: union.unknown */
            	134, 0,
            	335, 0,
            	1833, 0,
            1, 8, 1, /* 1833: pointer.struct.asn1_type_st */
            	86, 0,
            0, 1, 0, /* 1838: char */
        },
        .arg_entity_index = { 1772, },
        .ret_entity_index = -1,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    EVP_PKEY * new_arg_a = *((EVP_PKEY * *)new_args->args[0]);

    void (*orig_EVP_PKEY_free)(EVP_PKEY *);
    orig_EVP_PKEY_free = dlsym(RTLD_NEXT, "EVP_PKEY_free");
    (*orig_EVP_PKEY_free)(new_arg_a);

    syscall(889);

}

