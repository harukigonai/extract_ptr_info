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
            8884097, 8, 0, /* 8: pointer.func */
            0, 0, 0, /* 11: struct.ASN1_VALUE_st */
            1, 8, 1, /* 14: pointer.struct.ASN1_VALUE_st */
            	11, 0,
            1, 8, 1, /* 19: pointer.struct.asn1_string_st */
            	24, 0,
            0, 24, 1, /* 24: struct.asn1_string_st */
            	29, 8,
            1, 8, 1, /* 29: pointer.unsigned char */
            	34, 0,
            0, 1, 0, /* 34: unsigned char */
            1, 8, 1, /* 37: pointer.struct.asn1_string_st */
            	24, 0,
            1, 8, 1, /* 42: pointer.struct.asn1_string_st */
            	24, 0,
            1, 8, 1, /* 47: pointer.struct.asn1_string_st */
            	24, 0,
            1, 8, 1, /* 52: pointer.struct.asn1_string_st */
            	24, 0,
            1, 8, 1, /* 57: pointer.struct.asn1_string_st */
            	24, 0,
            1, 8, 1, /* 62: pointer.struct.asn1_string_st */
            	24, 0,
            1, 8, 1, /* 67: pointer.struct.asn1_string_st */
            	24, 0,
            0, 16, 1, /* 72: struct.asn1_type_st */
            	77, 8,
            0, 8, 20, /* 77: union.unknown */
            	120, 0,
            	67, 0,
            	125, 0,
            	149, 0,
            	62, 0,
            	154, 0,
            	57, 0,
            	159, 0,
            	52, 0,
            	47, 0,
            	42, 0,
            	37, 0,
            	164, 0,
            	169, 0,
            	174, 0,
            	179, 0,
            	19, 0,
            	67, 0,
            	67, 0,
            	14, 0,
            1, 8, 1, /* 120: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 125: pointer.struct.asn1_object_st */
            	130, 0,
            0, 40, 3, /* 130: struct.asn1_object_st */
            	139, 0,
            	139, 8,
            	144, 24,
            1, 8, 1, /* 139: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 144: pointer.unsigned char */
            	34, 0,
            1, 8, 1, /* 149: pointer.struct.asn1_string_st */
            	24, 0,
            1, 8, 1, /* 154: pointer.struct.asn1_string_st */
            	24, 0,
            1, 8, 1, /* 159: pointer.struct.asn1_string_st */
            	24, 0,
            1, 8, 1, /* 164: pointer.struct.asn1_string_st */
            	24, 0,
            1, 8, 1, /* 169: pointer.struct.asn1_string_st */
            	24, 0,
            1, 8, 1, /* 174: pointer.struct.asn1_string_st */
            	24, 0,
            1, 8, 1, /* 179: pointer.struct.asn1_string_st */
            	24, 0,
            0, 0, 0, /* 184: struct.ASN1_VALUE_st */
            1, 8, 1, /* 187: pointer.struct.asn1_string_st */
            	192, 0,
            0, 24, 1, /* 192: struct.asn1_string_st */
            	29, 8,
            1, 8, 1, /* 197: pointer.struct.asn1_string_st */
            	192, 0,
            1, 8, 1, /* 202: pointer.struct.asn1_string_st */
            	192, 0,
            1, 8, 1, /* 207: pointer.struct.asn1_string_st */
            	192, 0,
            1, 8, 1, /* 212: pointer.struct.asn1_string_st */
            	192, 0,
            1, 8, 1, /* 217: pointer.struct.asn1_string_st */
            	192, 0,
            1, 8, 1, /* 222: pointer.struct.asn1_string_st */
            	192, 0,
            1, 8, 1, /* 227: pointer.struct.asn1_string_st */
            	192, 0,
            0, 0, 1, /* 232: ASN1_TYPE */
            	237, 0,
            0, 16, 1, /* 237: struct.asn1_type_st */
            	242, 8,
            0, 8, 20, /* 242: union.unknown */
            	120, 0,
            	227, 0,
            	285, 0,
            	222, 0,
            	299, 0,
            	217, 0,
            	304, 0,
            	212, 0,
            	309, 0,
            	207, 0,
            	314, 0,
            	319, 0,
            	324, 0,
            	329, 0,
            	202, 0,
            	197, 0,
            	187, 0,
            	227, 0,
            	227, 0,
            	334, 0,
            1, 8, 1, /* 285: pointer.struct.asn1_object_st */
            	290, 0,
            0, 40, 3, /* 290: struct.asn1_object_st */
            	139, 0,
            	139, 8,
            	144, 24,
            1, 8, 1, /* 299: pointer.struct.asn1_string_st */
            	192, 0,
            1, 8, 1, /* 304: pointer.struct.asn1_string_st */
            	192, 0,
            1, 8, 1, /* 309: pointer.struct.asn1_string_st */
            	192, 0,
            1, 8, 1, /* 314: pointer.struct.asn1_string_st */
            	192, 0,
            1, 8, 1, /* 319: pointer.struct.asn1_string_st */
            	192, 0,
            1, 8, 1, /* 324: pointer.struct.asn1_string_st */
            	192, 0,
            1, 8, 1, /* 329: pointer.struct.asn1_string_st */
            	192, 0,
            1, 8, 1, /* 334: pointer.struct.ASN1_VALUE_st */
            	184, 0,
            1, 8, 1, /* 339: pointer.struct.stack_st_ASN1_TYPE */
            	344, 0,
            0, 32, 2, /* 344: struct.stack_st_fake_ASN1_TYPE */
            	351, 8,
            	363, 24,
            8884099, 8, 2, /* 351: pointer_to_array_of_pointers_to_stack */
            	358, 0,
            	5, 20,
            0, 8, 1, /* 358: pointer.ASN1_TYPE */
            	232, 0,
            8884097, 8, 0, /* 363: pointer.func */
            0, 24, 2, /* 366: struct.x509_attributes_st */
            	125, 0,
            	373, 16,
            0, 8, 3, /* 373: union.unknown */
            	120, 0,
            	339, 0,
            	382, 0,
            1, 8, 1, /* 382: pointer.struct.asn1_type_st */
            	72, 0,
            1, 8, 1, /* 387: pointer.struct.ec_extra_data_st */
            	392, 0,
            0, 40, 5, /* 392: struct.ec_extra_data_st */
            	387, 0,
            	405, 8,
            	408, 16,
            	411, 24,
            	411, 32,
            0, 8, 0, /* 405: pointer.void */
            8884097, 8, 0, /* 408: pointer.func */
            8884097, 8, 0, /* 411: pointer.func */
            1, 8, 1, /* 414: pointer.struct.ec_extra_data_st */
            	392, 0,
            0, 24, 1, /* 419: struct.bignum_st */
            	424, 0,
            8884099, 8, 2, /* 424: pointer_to_array_of_pointers_to_stack */
            	431, 0,
            	5, 12,
            0, 4, 0, /* 431: unsigned int */
            1, 8, 1, /* 434: pointer.struct.bignum_st */
            	419, 0,
            1, 8, 1, /* 439: pointer.struct.ec_point_st */
            	444, 0,
            0, 88, 4, /* 444: struct.ec_point_st */
            	455, 0,
            	627, 8,
            	627, 32,
            	627, 56,
            1, 8, 1, /* 455: pointer.struct.ec_method_st */
            	460, 0,
            0, 304, 37, /* 460: struct.ec_method_st */
            	537, 8,
            	540, 16,
            	540, 24,
            	543, 32,
            	546, 40,
            	549, 48,
            	552, 56,
            	555, 64,
            	558, 72,
            	561, 80,
            	561, 88,
            	564, 96,
            	567, 104,
            	570, 112,
            	573, 120,
            	576, 128,
            	579, 136,
            	582, 144,
            	585, 152,
            	588, 160,
            	591, 168,
            	594, 176,
            	597, 184,
            	600, 192,
            	603, 200,
            	606, 208,
            	597, 216,
            	609, 224,
            	612, 232,
            	615, 240,
            	552, 248,
            	618, 256,
            	621, 264,
            	618, 272,
            	621, 280,
            	621, 288,
            	624, 296,
            8884097, 8, 0, /* 537: pointer.func */
            8884097, 8, 0, /* 540: pointer.func */
            8884097, 8, 0, /* 543: pointer.func */
            8884097, 8, 0, /* 546: pointer.func */
            8884097, 8, 0, /* 549: pointer.func */
            8884097, 8, 0, /* 552: pointer.func */
            8884097, 8, 0, /* 555: pointer.func */
            8884097, 8, 0, /* 558: pointer.func */
            8884097, 8, 0, /* 561: pointer.func */
            8884097, 8, 0, /* 564: pointer.func */
            8884097, 8, 0, /* 567: pointer.func */
            8884097, 8, 0, /* 570: pointer.func */
            8884097, 8, 0, /* 573: pointer.func */
            8884097, 8, 0, /* 576: pointer.func */
            8884097, 8, 0, /* 579: pointer.func */
            8884097, 8, 0, /* 582: pointer.func */
            8884097, 8, 0, /* 585: pointer.func */
            8884097, 8, 0, /* 588: pointer.func */
            8884097, 8, 0, /* 591: pointer.func */
            8884097, 8, 0, /* 594: pointer.func */
            8884097, 8, 0, /* 597: pointer.func */
            8884097, 8, 0, /* 600: pointer.func */
            8884097, 8, 0, /* 603: pointer.func */
            8884097, 8, 0, /* 606: pointer.func */
            8884097, 8, 0, /* 609: pointer.func */
            8884097, 8, 0, /* 612: pointer.func */
            8884097, 8, 0, /* 615: pointer.func */
            8884097, 8, 0, /* 618: pointer.func */
            8884097, 8, 0, /* 621: pointer.func */
            8884097, 8, 0, /* 624: pointer.func */
            0, 24, 1, /* 627: struct.bignum_st */
            	632, 0,
            8884099, 8, 2, /* 632: pointer_to_array_of_pointers_to_stack */
            	431, 0,
            	5, 12,
            8884097, 8, 0, /* 639: pointer.func */
            8884097, 8, 0, /* 642: pointer.func */
            0, 24, 1, /* 645: struct.bignum_st */
            	650, 0,
            8884099, 8, 2, /* 650: pointer_to_array_of_pointers_to_stack */
            	431, 0,
            	5, 12,
            0, 208, 24, /* 657: struct.evp_pkey_asn1_method_st */
            	120, 16,
            	120, 24,
            	708, 32,
            	711, 40,
            	714, 48,
            	717, 56,
            	720, 64,
            	723, 72,
            	717, 80,
            	726, 88,
            	726, 96,
            	729, 104,
            	732, 112,
            	726, 120,
            	735, 128,
            	714, 136,
            	717, 144,
            	738, 152,
            	741, 160,
            	744, 168,
            	729, 176,
            	732, 184,
            	747, 192,
            	750, 200,
            8884097, 8, 0, /* 708: pointer.func */
            8884097, 8, 0, /* 711: pointer.func */
            8884097, 8, 0, /* 714: pointer.func */
            8884097, 8, 0, /* 717: pointer.func */
            8884097, 8, 0, /* 720: pointer.func */
            8884097, 8, 0, /* 723: pointer.func */
            8884097, 8, 0, /* 726: pointer.func */
            8884097, 8, 0, /* 729: pointer.func */
            8884097, 8, 0, /* 732: pointer.func */
            8884097, 8, 0, /* 735: pointer.func */
            8884097, 8, 0, /* 738: pointer.func */
            8884097, 8, 0, /* 741: pointer.func */
            8884097, 8, 0, /* 744: pointer.func */
            8884097, 8, 0, /* 747: pointer.func */
            8884097, 8, 0, /* 750: pointer.func */
            8884097, 8, 0, /* 753: pointer.func */
            8884097, 8, 0, /* 756: pointer.func */
            8884097, 8, 0, /* 759: pointer.func */
            8884097, 8, 0, /* 762: pointer.func */
            0, 32, 2, /* 765: struct.stack_st */
            	772, 8,
            	363, 24,
            1, 8, 1, /* 772: pointer.pointer.char */
            	120, 0,
            8884097, 8, 0, /* 777: pointer.func */
            8884097, 8, 0, /* 780: pointer.func */
            0, 112, 13, /* 783: struct.rsa_meth_st */
            	139, 0,
            	812, 8,
            	812, 16,
            	812, 24,
            	812, 32,
            	815, 40,
            	818, 48,
            	753, 56,
            	753, 64,
            	120, 80,
            	821, 88,
            	824, 96,
            	642, 104,
            8884097, 8, 0, /* 812: pointer.func */
            8884097, 8, 0, /* 815: pointer.func */
            8884097, 8, 0, /* 818: pointer.func */
            8884097, 8, 0, /* 821: pointer.func */
            8884097, 8, 0, /* 824: pointer.func */
            1, 8, 1, /* 827: pointer.struct.rsa_meth_st */
            	783, 0,
            8884097, 8, 0, /* 832: pointer.func */
            0, 168, 17, /* 835: struct.rsa_st */
            	827, 16,
            	872, 24,
            	1211, 32,
            	1211, 40,
            	1211, 48,
            	1211, 56,
            	1211, 64,
            	1211, 72,
            	1211, 80,
            	1211, 88,
            	1216, 96,
            	1231, 120,
            	1231, 128,
            	1231, 136,
            	120, 144,
            	1245, 152,
            	1245, 160,
            1, 8, 1, /* 872: pointer.struct.engine_st */
            	877, 0,
            0, 216, 24, /* 877: struct.engine_st */
            	139, 0,
            	139, 8,
            	928, 16,
            	980, 24,
            	1028, 32,
            	1064, 40,
            	1081, 48,
            	1108, 56,
            	1143, 64,
            	1151, 72,
            	1154, 80,
            	1157, 88,
            	1160, 96,
            	1163, 104,
            	1163, 112,
            	1163, 120,
            	1166, 128,
            	832, 136,
            	832, 144,
            	1169, 152,
            	1172, 160,
            	1184, 184,
            	1206, 200,
            	1206, 208,
            1, 8, 1, /* 928: pointer.struct.rsa_meth_st */
            	933, 0,
            0, 112, 13, /* 933: struct.rsa_meth_st */
            	139, 0,
            	756, 8,
            	756, 16,
            	756, 24,
            	756, 32,
            	962, 40,
            	965, 48,
            	968, 56,
            	968, 64,
            	120, 80,
            	971, 88,
            	974, 96,
            	977, 104,
            8884097, 8, 0, /* 962: pointer.func */
            8884097, 8, 0, /* 965: pointer.func */
            8884097, 8, 0, /* 968: pointer.func */
            8884097, 8, 0, /* 971: pointer.func */
            8884097, 8, 0, /* 974: pointer.func */
            8884097, 8, 0, /* 977: pointer.func */
            1, 8, 1, /* 980: pointer.struct.dsa_method */
            	985, 0,
            0, 96, 11, /* 985: struct.dsa_method */
            	139, 0,
            	759, 8,
            	1010, 16,
            	1013, 24,
            	1016, 32,
            	1019, 40,
            	1022, 48,
            	1022, 56,
            	120, 72,
            	1025, 80,
            	1022, 88,
            8884097, 8, 0, /* 1010: pointer.func */
            8884097, 8, 0, /* 1013: pointer.func */
            8884097, 8, 0, /* 1016: pointer.func */
            8884097, 8, 0, /* 1019: pointer.func */
            8884097, 8, 0, /* 1022: pointer.func */
            8884097, 8, 0, /* 1025: pointer.func */
            1, 8, 1, /* 1028: pointer.struct.dh_method */
            	1033, 0,
            0, 72, 8, /* 1033: struct.dh_method */
            	139, 0,
            	1052, 8,
            	1055, 16,
            	1058, 24,
            	1052, 32,
            	1052, 40,
            	120, 56,
            	1061, 64,
            8884097, 8, 0, /* 1052: pointer.func */
            8884097, 8, 0, /* 1055: pointer.func */
            8884097, 8, 0, /* 1058: pointer.func */
            8884097, 8, 0, /* 1061: pointer.func */
            1, 8, 1, /* 1064: pointer.struct.ecdh_method */
            	1069, 0,
            0, 32, 3, /* 1069: struct.ecdh_method */
            	139, 0,
            	1078, 8,
            	120, 24,
            8884097, 8, 0, /* 1078: pointer.func */
            1, 8, 1, /* 1081: pointer.struct.ecdsa_method */
            	1086, 0,
            0, 48, 5, /* 1086: struct.ecdsa_method */
            	139, 0,
            	1099, 8,
            	1102, 16,
            	1105, 24,
            	120, 40,
            8884097, 8, 0, /* 1099: pointer.func */
            8884097, 8, 0, /* 1102: pointer.func */
            8884097, 8, 0, /* 1105: pointer.func */
            1, 8, 1, /* 1108: pointer.struct.rand_meth_st */
            	1113, 0,
            0, 48, 6, /* 1113: struct.rand_meth_st */
            	1128, 0,
            	1131, 8,
            	1134, 16,
            	1137, 24,
            	1131, 32,
            	1140, 40,
            8884097, 8, 0, /* 1128: pointer.func */
            8884097, 8, 0, /* 1131: pointer.func */
            8884097, 8, 0, /* 1134: pointer.func */
            8884097, 8, 0, /* 1137: pointer.func */
            8884097, 8, 0, /* 1140: pointer.func */
            1, 8, 1, /* 1143: pointer.struct.store_method_st */
            	1148, 0,
            0, 0, 0, /* 1148: struct.store_method_st */
            8884097, 8, 0, /* 1151: pointer.func */
            8884097, 8, 0, /* 1154: pointer.func */
            8884097, 8, 0, /* 1157: pointer.func */
            8884097, 8, 0, /* 1160: pointer.func */
            8884097, 8, 0, /* 1163: pointer.func */
            8884097, 8, 0, /* 1166: pointer.func */
            8884097, 8, 0, /* 1169: pointer.func */
            1, 8, 1, /* 1172: pointer.struct.ENGINE_CMD_DEFN_st */
            	1177, 0,
            0, 32, 2, /* 1177: struct.ENGINE_CMD_DEFN_st */
            	139, 8,
            	139, 16,
            0, 16, 1, /* 1184: struct.crypto_ex_data_st */
            	1189, 0,
            1, 8, 1, /* 1189: pointer.struct.stack_st_void */
            	1194, 0,
            0, 32, 1, /* 1194: struct.stack_st_void */
            	1199, 0,
            0, 32, 2, /* 1199: struct.stack_st */
            	772, 8,
            	363, 24,
            1, 8, 1, /* 1206: pointer.struct.engine_st */
            	877, 0,
            1, 8, 1, /* 1211: pointer.struct.bignum_st */
            	645, 0,
            0, 16, 1, /* 1216: struct.crypto_ex_data_st */
            	1221, 0,
            1, 8, 1, /* 1221: pointer.struct.stack_st_void */
            	1226, 0,
            0, 32, 1, /* 1226: struct.stack_st_void */
            	765, 0,
            1, 8, 1, /* 1231: pointer.struct.bn_mont_ctx_st */
            	1236, 0,
            0, 96, 3, /* 1236: struct.bn_mont_ctx_st */
            	645, 8,
            	645, 32,
            	645, 56,
            1, 8, 1, /* 1245: pointer.struct.bn_blinding_st */
            	1250, 0,
            0, 88, 7, /* 1250: struct.bn_blinding_st */
            	1267, 0,
            	1267, 8,
            	1267, 16,
            	1267, 24,
            	1284, 40,
            	1289, 72,
            	1303, 80,
            1, 8, 1, /* 1267: pointer.struct.bignum_st */
            	1272, 0,
            0, 24, 1, /* 1272: struct.bignum_st */
            	1277, 0,
            8884099, 8, 2, /* 1277: pointer_to_array_of_pointers_to_stack */
            	431, 0,
            	5, 12,
            0, 16, 1, /* 1284: struct.crypto_threadid_st */
            	405, 0,
            1, 8, 1, /* 1289: pointer.struct.bn_mont_ctx_st */
            	1294, 0,
            0, 96, 3, /* 1294: struct.bn_mont_ctx_st */
            	1272, 8,
            	1272, 32,
            	1272, 56,
            8884097, 8, 0, /* 1303: pointer.func */
            8884097, 8, 0, /* 1306: pointer.func */
            8884097, 8, 0, /* 1309: pointer.func */
            1, 8, 1, /* 1312: pointer.struct.dh_method */
            	1317, 0,
            0, 72, 8, /* 1317: struct.dh_method */
            	139, 0,
            	1336, 8,
            	1339, 16,
            	1342, 24,
            	1336, 32,
            	1336, 40,
            	120, 56,
            	1345, 64,
            8884097, 8, 0, /* 1336: pointer.func */
            8884097, 8, 0, /* 1339: pointer.func */
            8884097, 8, 0, /* 1342: pointer.func */
            8884097, 8, 0, /* 1345: pointer.func */
            0, 56, 4, /* 1348: struct.evp_pkey_st */
            	1359, 16,
            	1364, 24,
            	1369, 32,
            	1862, 48,
            1, 8, 1, /* 1359: pointer.struct.evp_pkey_asn1_method_st */
            	657, 0,
            1, 8, 1, /* 1364: pointer.struct.engine_st */
            	877, 0,
            0, 8, 5, /* 1369: union.unknown */
            	120, 0,
            	1382, 0,
            	1387, 0,
            	1526, 0,
            	1611, 0,
            1, 8, 1, /* 1382: pointer.struct.rsa_st */
            	835, 0,
            1, 8, 1, /* 1387: pointer.struct.dsa_st */
            	1392, 0,
            0, 136, 11, /* 1392: struct.dsa_st */
            	1417, 24,
            	1417, 32,
            	1417, 40,
            	1417, 48,
            	1417, 56,
            	1417, 64,
            	1417, 72,
            	1434, 88,
            	1448, 104,
            	1470, 120,
            	1521, 128,
            1, 8, 1, /* 1417: pointer.struct.bignum_st */
            	1422, 0,
            0, 24, 1, /* 1422: struct.bignum_st */
            	1427, 0,
            8884099, 8, 2, /* 1427: pointer_to_array_of_pointers_to_stack */
            	431, 0,
            	5, 12,
            1, 8, 1, /* 1434: pointer.struct.bn_mont_ctx_st */
            	1439, 0,
            0, 96, 3, /* 1439: struct.bn_mont_ctx_st */
            	1422, 8,
            	1422, 32,
            	1422, 56,
            0, 16, 1, /* 1448: struct.crypto_ex_data_st */
            	1453, 0,
            1, 8, 1, /* 1453: pointer.struct.stack_st_void */
            	1458, 0,
            0, 32, 1, /* 1458: struct.stack_st_void */
            	1463, 0,
            0, 32, 2, /* 1463: struct.stack_st */
            	772, 8,
            	363, 24,
            1, 8, 1, /* 1470: pointer.struct.dsa_method */
            	1475, 0,
            0, 96, 11, /* 1475: struct.dsa_method */
            	139, 0,
            	1500, 8,
            	1503, 16,
            	1506, 24,
            	1509, 32,
            	1512, 40,
            	1515, 48,
            	1515, 56,
            	120, 72,
            	1518, 80,
            	1515, 88,
            8884097, 8, 0, /* 1500: pointer.func */
            8884097, 8, 0, /* 1503: pointer.func */
            8884097, 8, 0, /* 1506: pointer.func */
            8884097, 8, 0, /* 1509: pointer.func */
            8884097, 8, 0, /* 1512: pointer.func */
            8884097, 8, 0, /* 1515: pointer.func */
            8884097, 8, 0, /* 1518: pointer.func */
            1, 8, 1, /* 1521: pointer.struct.engine_st */
            	877, 0,
            1, 8, 1, /* 1526: pointer.struct.dh_st */
            	1531, 0,
            0, 144, 12, /* 1531: struct.dh_st */
            	1558, 8,
            	1558, 16,
            	1558, 32,
            	1558, 40,
            	1575, 56,
            	1558, 64,
            	1558, 72,
            	29, 80,
            	1558, 96,
            	1589, 112,
            	1312, 128,
            	1364, 136,
            1, 8, 1, /* 1558: pointer.struct.bignum_st */
            	1563, 0,
            0, 24, 1, /* 1563: struct.bignum_st */
            	1568, 0,
            8884099, 8, 2, /* 1568: pointer_to_array_of_pointers_to_stack */
            	431, 0,
            	5, 12,
            1, 8, 1, /* 1575: pointer.struct.bn_mont_ctx_st */
            	1580, 0,
            0, 96, 3, /* 1580: struct.bn_mont_ctx_st */
            	1563, 8,
            	1563, 32,
            	1563, 56,
            0, 16, 1, /* 1589: struct.crypto_ex_data_st */
            	1594, 0,
            1, 8, 1, /* 1594: pointer.struct.stack_st_void */
            	1599, 0,
            0, 32, 1, /* 1599: struct.stack_st_void */
            	1604, 0,
            0, 32, 2, /* 1604: struct.stack_st */
            	772, 8,
            	363, 24,
            1, 8, 1, /* 1611: pointer.struct.ec_key_st */
            	1616, 0,
            0, 56, 4, /* 1616: struct.ec_key_st */
            	1627, 8,
            	439, 16,
            	434, 24,
            	414, 48,
            1, 8, 1, /* 1627: pointer.struct.ec_group_st */
            	1632, 0,
            0, 232, 12, /* 1632: struct.ec_group_st */
            	1659, 0,
            	1822, 8,
            	1827, 16,
            	1827, 40,
            	29, 80,
            	1839, 96,
            	1827, 104,
            	1827, 152,
            	1827, 176,
            	405, 208,
            	405, 216,
            	639, 224,
            1, 8, 1, /* 1659: pointer.struct.ec_method_st */
            	1664, 0,
            0, 304, 37, /* 1664: struct.ec_method_st */
            	1741, 8,
            	1744, 16,
            	1744, 24,
            	1747, 32,
            	1309, 40,
            	1750, 48,
            	1753, 56,
            	1756, 64,
            	1759, 72,
            	1762, 80,
            	1762, 88,
            	1765, 96,
            	1768, 104,
            	1771, 112,
            	1774, 120,
            	1777, 128,
            	1780, 136,
            	777, 144,
            	1783, 152,
            	1786, 160,
            	1789, 168,
            	1792, 176,
            	1795, 184,
            	1798, 192,
            	1801, 200,
            	1804, 208,
            	1795, 216,
            	780, 224,
            	1807, 232,
            	1810, 240,
            	1753, 248,
            	1813, 256,
            	1816, 264,
            	1813, 272,
            	1816, 280,
            	1816, 288,
            	1819, 296,
            8884097, 8, 0, /* 1741: pointer.func */
            8884097, 8, 0, /* 1744: pointer.func */
            8884097, 8, 0, /* 1747: pointer.func */
            8884097, 8, 0, /* 1750: pointer.func */
            8884097, 8, 0, /* 1753: pointer.func */
            8884097, 8, 0, /* 1756: pointer.func */
            8884097, 8, 0, /* 1759: pointer.func */
            8884097, 8, 0, /* 1762: pointer.func */
            8884097, 8, 0, /* 1765: pointer.func */
            8884097, 8, 0, /* 1768: pointer.func */
            8884097, 8, 0, /* 1771: pointer.func */
            8884097, 8, 0, /* 1774: pointer.func */
            8884097, 8, 0, /* 1777: pointer.func */
            8884097, 8, 0, /* 1780: pointer.func */
            8884097, 8, 0, /* 1783: pointer.func */
            8884097, 8, 0, /* 1786: pointer.func */
            8884097, 8, 0, /* 1789: pointer.func */
            8884097, 8, 0, /* 1792: pointer.func */
            8884097, 8, 0, /* 1795: pointer.func */
            8884097, 8, 0, /* 1798: pointer.func */
            8884097, 8, 0, /* 1801: pointer.func */
            8884097, 8, 0, /* 1804: pointer.func */
            8884097, 8, 0, /* 1807: pointer.func */
            8884097, 8, 0, /* 1810: pointer.func */
            8884097, 8, 0, /* 1813: pointer.func */
            8884097, 8, 0, /* 1816: pointer.func */
            8884097, 8, 0, /* 1819: pointer.func */
            1, 8, 1, /* 1822: pointer.struct.ec_point_st */
            	444, 0,
            0, 24, 1, /* 1827: struct.bignum_st */
            	1832, 0,
            8884099, 8, 2, /* 1832: pointer_to_array_of_pointers_to_stack */
            	431, 0,
            	5, 12,
            1, 8, 1, /* 1839: pointer.struct.ec_extra_data_st */
            	1844, 0,
            0, 40, 5, /* 1844: struct.ec_extra_data_st */
            	1857, 0,
            	405, 8,
            	408, 16,
            	411, 24,
            	411, 32,
            1, 8, 1, /* 1857: pointer.struct.ec_extra_data_st */
            	1844, 0,
            1, 8, 1, /* 1862: pointer.struct.stack_st_X509_ATTRIBUTE */
            	1867, 0,
            0, 32, 2, /* 1867: struct.stack_st_fake_X509_ATTRIBUTE */
            	1874, 8,
            	363, 24,
            8884099, 8, 2, /* 1874: pointer_to_array_of_pointers_to_stack */
            	1881, 0,
            	5, 20,
            0, 8, 1, /* 1881: pointer.X509_ATTRIBUTE */
            	1886, 0,
            0, 0, 1, /* 1886: X509_ATTRIBUTE */
            	366, 0,
            1, 8, 1, /* 1891: pointer.struct.evp_pkey_st */
            	1348, 0,
            8884097, 8, 0, /* 1896: pointer.func */
            8884097, 8, 0, /* 1899: pointer.func */
            8884097, 8, 0, /* 1902: pointer.func */
            0, 1, 0, /* 1905: char */
            8884097, 8, 0, /* 1908: pointer.func */
            8884097, 8, 0, /* 1911: pointer.func */
            8884097, 8, 0, /* 1914: pointer.func */
            1, 8, 1, /* 1917: pointer.struct.evp_pkey_ctx_st */
            	1922, 0,
            0, 80, 8, /* 1922: struct.evp_pkey_ctx_st */
            	1941, 0,
            	1364, 8,
            	1891, 16,
            	1891, 24,
            	405, 40,
            	405, 48,
            	8, 56,
            	0, 64,
            1, 8, 1, /* 1941: pointer.struct.evp_pkey_method_st */
            	1946, 0,
            0, 208, 25, /* 1946: struct.evp_pkey_method_st */
            	1914, 8,
            	1999, 16,
            	2002, 24,
            	1914, 32,
            	1902, 40,
            	1914, 48,
            	1902, 56,
            	1914, 64,
            	2005, 72,
            	1914, 80,
            	2008, 88,
            	1914, 96,
            	2005, 104,
            	2011, 112,
            	1911, 120,
            	2011, 128,
            	2014, 136,
            	1914, 144,
            	2005, 152,
            	1914, 160,
            	2005, 168,
            	1914, 176,
            	1908, 184,
            	1899, 192,
            	1896, 200,
            8884097, 8, 0, /* 1999: pointer.func */
            8884097, 8, 0, /* 2002: pointer.func */
            8884097, 8, 0, /* 2005: pointer.func */
            8884097, 8, 0, /* 2008: pointer.func */
            8884097, 8, 0, /* 2011: pointer.func */
            8884097, 8, 0, /* 2014: pointer.func */
            8884097, 8, 0, /* 2017: pointer.func */
            8884097, 8, 0, /* 2020: pointer.func */
            8884097, 8, 0, /* 2023: pointer.func */
            8884097, 8, 0, /* 2026: pointer.func */
            0, 120, 8, /* 2029: struct.env_md_st */
            	2048, 24,
            	2026, 32,
            	2017, 40,
            	762, 48,
            	2048, 56,
            	2023, 64,
            	1306, 72,
            	2020, 112,
            8884097, 8, 0, /* 2048: pointer.func */
            1, 8, 1, /* 2051: pointer.struct.env_md_ctx_st */
            	2056, 0,
            0, 48, 5, /* 2056: struct.env_md_ctx_st */
            	2069, 0,
            	1364, 8,
            	405, 24,
            	1917, 32,
            	2026, 40,
            1, 8, 1, /* 2069: pointer.struct.env_md_st */
            	2029, 0,
            0, 0, 0, /* 2074: size_t */
        },
        .arg_entity_index = { 2051, 405, 2074, },
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

