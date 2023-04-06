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
            0, 0, 0, /* 0: struct.ASN1_VALUE_st */
            1, 8, 1, /* 3: pointer.struct.ASN1_VALUE_st */
            	0, 0,
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
            0, 16, 1, /* 66: struct.asn1_type_st */
            	71, 8,
            0, 8, 20, /* 71: union.unknown */
            	114, 0,
            	61, 0,
            	119, 0,
            	143, 0,
            	56, 0,
            	51, 0,
            	46, 0,
            	148, 0,
            	41, 0,
            	36, 0,
            	31, 0,
            	26, 0,
            	153, 0,
            	158, 0,
            	163, 0,
            	168, 0,
            	8, 0,
            	61, 0,
            	61, 0,
            	3, 0,
            1, 8, 1, /* 114: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 119: pointer.struct.asn1_object_st */
            	124, 0,
            0, 40, 3, /* 124: struct.asn1_object_st */
            	133, 0,
            	133, 8,
            	138, 24,
            1, 8, 1, /* 133: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 138: pointer.unsigned char */
            	23, 0,
            1, 8, 1, /* 143: pointer.struct.asn1_string_st */
            	13, 0,
            1, 8, 1, /* 148: pointer.struct.asn1_string_st */
            	13, 0,
            1, 8, 1, /* 153: pointer.struct.asn1_string_st */
            	13, 0,
            1, 8, 1, /* 158: pointer.struct.asn1_string_st */
            	13, 0,
            1, 8, 1, /* 163: pointer.struct.asn1_string_st */
            	13, 0,
            1, 8, 1, /* 168: pointer.struct.asn1_string_st */
            	13, 0,
            0, 0, 0, /* 173: struct.ASN1_VALUE_st */
            1, 8, 1, /* 176: pointer.struct.asn1_string_st */
            	181, 0,
            0, 24, 1, /* 181: struct.asn1_string_st */
            	18, 8,
            1, 8, 1, /* 186: pointer.struct.asn1_string_st */
            	181, 0,
            1, 8, 1, /* 191: pointer.struct.asn1_string_st */
            	181, 0,
            1, 8, 1, /* 196: pointer.struct.asn1_string_st */
            	181, 0,
            1, 8, 1, /* 201: pointer.struct.asn1_string_st */
            	181, 0,
            1, 8, 1, /* 206: pointer.struct.dsa_method */
            	211, 0,
            0, 96, 11, /* 211: struct.dsa_method */
            	133, 0,
            	236, 8,
            	239, 16,
            	242, 24,
            	245, 32,
            	248, 40,
            	251, 48,
            	251, 56,
            	114, 72,
            	254, 80,
            	251, 88,
            8884097, 8, 0, /* 236: pointer.func */
            8884097, 8, 0, /* 239: pointer.func */
            8884097, 8, 0, /* 242: pointer.func */
            8884097, 8, 0, /* 245: pointer.func */
            8884097, 8, 0, /* 248: pointer.func */
            8884097, 8, 0, /* 251: pointer.func */
            8884097, 8, 0, /* 254: pointer.func */
            1, 8, 1, /* 257: pointer.struct.dsa_st */
            	262, 0,
            0, 136, 11, /* 262: struct.dsa_st */
            	287, 24,
            	287, 32,
            	287, 40,
            	287, 48,
            	287, 56,
            	287, 64,
            	287, 72,
            	310, 88,
            	324, 104,
            	206, 120,
            	354, 128,
            1, 8, 1, /* 287: pointer.struct.bignum_st */
            	292, 0,
            0, 24, 1, /* 292: struct.bignum_st */
            	297, 0,
            8884099, 8, 2, /* 297: pointer_to_array_of_pointers_to_stack */
            	304, 0,
            	307, 12,
            0, 4, 0, /* 304: unsigned int */
            0, 4, 0, /* 307: int */
            1, 8, 1, /* 310: pointer.struct.bn_mont_ctx_st */
            	315, 0,
            0, 96, 3, /* 315: struct.bn_mont_ctx_st */
            	292, 8,
            	292, 32,
            	292, 56,
            0, 16, 1, /* 324: struct.crypto_ex_data_st */
            	329, 0,
            1, 8, 1, /* 329: pointer.struct.stack_st_void */
            	334, 0,
            0, 32, 1, /* 334: struct.stack_st_void */
            	339, 0,
            0, 32, 2, /* 339: struct.stack_st */
            	346, 8,
            	351, 24,
            1, 8, 1, /* 346: pointer.pointer.char */
            	114, 0,
            8884097, 8, 0, /* 351: pointer.func */
            1, 8, 1, /* 354: pointer.struct.engine_st */
            	359, 0,
            0, 216, 24, /* 359: struct.engine_st */
            	133, 0,
            	133, 8,
            	410, 16,
            	465, 24,
            	516, 32,
            	552, 40,
            	569, 48,
            	596, 56,
            	631, 64,
            	639, 72,
            	642, 80,
            	645, 88,
            	648, 96,
            	651, 104,
            	651, 112,
            	651, 120,
            	654, 128,
            	657, 136,
            	657, 144,
            	660, 152,
            	663, 160,
            	675, 184,
            	697, 200,
            	697, 208,
            1, 8, 1, /* 410: pointer.struct.rsa_meth_st */
            	415, 0,
            0, 112, 13, /* 415: struct.rsa_meth_st */
            	133, 0,
            	444, 8,
            	444, 16,
            	444, 24,
            	444, 32,
            	447, 40,
            	450, 48,
            	453, 56,
            	453, 64,
            	114, 80,
            	456, 88,
            	459, 96,
            	462, 104,
            8884097, 8, 0, /* 444: pointer.func */
            8884097, 8, 0, /* 447: pointer.func */
            8884097, 8, 0, /* 450: pointer.func */
            8884097, 8, 0, /* 453: pointer.func */
            8884097, 8, 0, /* 456: pointer.func */
            8884097, 8, 0, /* 459: pointer.func */
            8884097, 8, 0, /* 462: pointer.func */
            1, 8, 1, /* 465: pointer.struct.dsa_method */
            	470, 0,
            0, 96, 11, /* 470: struct.dsa_method */
            	133, 0,
            	495, 8,
            	498, 16,
            	501, 24,
            	504, 32,
            	507, 40,
            	510, 48,
            	510, 56,
            	114, 72,
            	513, 80,
            	510, 88,
            8884097, 8, 0, /* 495: pointer.func */
            8884097, 8, 0, /* 498: pointer.func */
            8884097, 8, 0, /* 501: pointer.func */
            8884097, 8, 0, /* 504: pointer.func */
            8884097, 8, 0, /* 507: pointer.func */
            8884097, 8, 0, /* 510: pointer.func */
            8884097, 8, 0, /* 513: pointer.func */
            1, 8, 1, /* 516: pointer.struct.dh_method */
            	521, 0,
            0, 72, 8, /* 521: struct.dh_method */
            	133, 0,
            	540, 8,
            	543, 16,
            	546, 24,
            	540, 32,
            	540, 40,
            	114, 56,
            	549, 64,
            8884097, 8, 0, /* 540: pointer.func */
            8884097, 8, 0, /* 543: pointer.func */
            8884097, 8, 0, /* 546: pointer.func */
            8884097, 8, 0, /* 549: pointer.func */
            1, 8, 1, /* 552: pointer.struct.ecdh_method */
            	557, 0,
            0, 32, 3, /* 557: struct.ecdh_method */
            	133, 0,
            	566, 8,
            	114, 24,
            8884097, 8, 0, /* 566: pointer.func */
            1, 8, 1, /* 569: pointer.struct.ecdsa_method */
            	574, 0,
            0, 48, 5, /* 574: struct.ecdsa_method */
            	133, 0,
            	587, 8,
            	590, 16,
            	593, 24,
            	114, 40,
            8884097, 8, 0, /* 587: pointer.func */
            8884097, 8, 0, /* 590: pointer.func */
            8884097, 8, 0, /* 593: pointer.func */
            1, 8, 1, /* 596: pointer.struct.rand_meth_st */
            	601, 0,
            0, 48, 6, /* 601: struct.rand_meth_st */
            	616, 0,
            	619, 8,
            	622, 16,
            	625, 24,
            	619, 32,
            	628, 40,
            8884097, 8, 0, /* 616: pointer.func */
            8884097, 8, 0, /* 619: pointer.func */
            8884097, 8, 0, /* 622: pointer.func */
            8884097, 8, 0, /* 625: pointer.func */
            8884097, 8, 0, /* 628: pointer.func */
            1, 8, 1, /* 631: pointer.struct.store_method_st */
            	636, 0,
            0, 0, 0, /* 636: struct.store_method_st */
            8884097, 8, 0, /* 639: pointer.func */
            8884097, 8, 0, /* 642: pointer.func */
            8884097, 8, 0, /* 645: pointer.func */
            8884097, 8, 0, /* 648: pointer.func */
            8884097, 8, 0, /* 651: pointer.func */
            8884097, 8, 0, /* 654: pointer.func */
            8884097, 8, 0, /* 657: pointer.func */
            8884097, 8, 0, /* 660: pointer.func */
            1, 8, 1, /* 663: pointer.struct.ENGINE_CMD_DEFN_st */
            	668, 0,
            0, 32, 2, /* 668: struct.ENGINE_CMD_DEFN_st */
            	133, 8,
            	133, 16,
            0, 16, 1, /* 675: struct.crypto_ex_data_st */
            	680, 0,
            1, 8, 1, /* 680: pointer.struct.stack_st_void */
            	685, 0,
            0, 32, 1, /* 685: struct.stack_st_void */
            	690, 0,
            0, 32, 2, /* 690: struct.stack_st */
            	346, 8,
            	351, 24,
            1, 8, 1, /* 697: pointer.struct.engine_st */
            	359, 0,
            0, 8, 0, /* 702: pointer.void */
            0, 88, 7, /* 705: struct.bn_blinding_st */
            	722, 0,
            	722, 8,
            	722, 16,
            	722, 24,
            	739, 40,
            	744, 72,
            	758, 80,
            1, 8, 1, /* 722: pointer.struct.bignum_st */
            	727, 0,
            0, 24, 1, /* 727: struct.bignum_st */
            	732, 0,
            8884099, 8, 2, /* 732: pointer_to_array_of_pointers_to_stack */
            	304, 0,
            	307, 12,
            0, 16, 1, /* 739: struct.crypto_threadid_st */
            	702, 0,
            1, 8, 1, /* 744: pointer.struct.bn_mont_ctx_st */
            	749, 0,
            0, 96, 3, /* 749: struct.bn_mont_ctx_st */
            	727, 8,
            	727, 32,
            	727, 56,
            8884097, 8, 0, /* 758: pointer.func */
            0, 96, 3, /* 761: struct.bn_mont_ctx_st */
            	770, 8,
            	770, 32,
            	770, 56,
            0, 24, 1, /* 770: struct.bignum_st */
            	775, 0,
            8884099, 8, 2, /* 775: pointer_to_array_of_pointers_to_stack */
            	304, 0,
            	307, 12,
            1, 8, 1, /* 782: pointer.struct.stack_st_void */
            	787, 0,
            0, 32, 1, /* 787: struct.stack_st_void */
            	792, 0,
            0, 32, 2, /* 792: struct.stack_st */
            	346, 8,
            	351, 24,
            8884097, 8, 0, /* 799: pointer.func */
            8884097, 8, 0, /* 802: pointer.func */
            1, 8, 1, /* 805: pointer.struct.asn1_string_st */
            	181, 0,
            8884097, 8, 0, /* 810: pointer.func */
            0, 88, 4, /* 813: struct.ec_point_st */
            	824, 0,
            	993, 8,
            	993, 32,
            	993, 56,
            1, 8, 1, /* 824: pointer.struct.ec_method_st */
            	829, 0,
            0, 304, 37, /* 829: struct.ec_method_st */
            	906, 8,
            	909, 16,
            	909, 24,
            	912, 32,
            	915, 40,
            	918, 48,
            	921, 56,
            	924, 64,
            	927, 72,
            	930, 80,
            	930, 88,
            	933, 96,
            	936, 104,
            	939, 112,
            	942, 120,
            	945, 128,
            	948, 136,
            	951, 144,
            	954, 152,
            	957, 160,
            	960, 168,
            	799, 176,
            	963, 184,
            	966, 192,
            	969, 200,
            	972, 208,
            	963, 216,
            	975, 224,
            	978, 232,
            	981, 240,
            	921, 248,
            	984, 256,
            	987, 264,
            	984, 272,
            	987, 280,
            	987, 288,
            	990, 296,
            8884097, 8, 0, /* 906: pointer.func */
            8884097, 8, 0, /* 909: pointer.func */
            8884097, 8, 0, /* 912: pointer.func */
            8884097, 8, 0, /* 915: pointer.func */
            8884097, 8, 0, /* 918: pointer.func */
            8884097, 8, 0, /* 921: pointer.func */
            8884097, 8, 0, /* 924: pointer.func */
            8884097, 8, 0, /* 927: pointer.func */
            8884097, 8, 0, /* 930: pointer.func */
            8884097, 8, 0, /* 933: pointer.func */
            8884097, 8, 0, /* 936: pointer.func */
            8884097, 8, 0, /* 939: pointer.func */
            8884097, 8, 0, /* 942: pointer.func */
            8884097, 8, 0, /* 945: pointer.func */
            8884097, 8, 0, /* 948: pointer.func */
            8884097, 8, 0, /* 951: pointer.func */
            8884097, 8, 0, /* 954: pointer.func */
            8884097, 8, 0, /* 957: pointer.func */
            8884097, 8, 0, /* 960: pointer.func */
            8884097, 8, 0, /* 963: pointer.func */
            8884097, 8, 0, /* 966: pointer.func */
            8884097, 8, 0, /* 969: pointer.func */
            8884097, 8, 0, /* 972: pointer.func */
            8884097, 8, 0, /* 975: pointer.func */
            8884097, 8, 0, /* 978: pointer.func */
            8884097, 8, 0, /* 981: pointer.func */
            8884097, 8, 0, /* 984: pointer.func */
            8884097, 8, 0, /* 987: pointer.func */
            8884097, 8, 0, /* 990: pointer.func */
            0, 24, 1, /* 993: struct.bignum_st */
            	998, 0,
            8884099, 8, 2, /* 998: pointer_to_array_of_pointers_to_stack */
            	304, 0,
            	307, 12,
            1, 8, 1, /* 1005: pointer.struct.ASN1_VALUE_st */
            	173, 0,
            0, 16, 1, /* 1010: struct.crypto_ex_data_st */
            	782, 0,
            8884097, 8, 0, /* 1015: pointer.func */
            8884097, 8, 0, /* 1018: pointer.func */
            8884097, 8, 0, /* 1021: pointer.func */
            1, 8, 1, /* 1024: pointer.struct.bignum_st */
            	770, 0,
            8884097, 8, 0, /* 1029: pointer.func */
            0, 1, 0, /* 1032: char */
            1, 8, 1, /* 1035: pointer.struct.asn1_object_st */
            	1040, 0,
            0, 40, 3, /* 1040: struct.asn1_object_st */
            	133, 0,
            	133, 8,
            	138, 24,
            1, 8, 1, /* 1049: pointer.struct.asn1_string_st */
            	181, 0,
            0, 208, 24, /* 1054: struct.evp_pkey_asn1_method_st */
            	114, 16,
            	114, 24,
            	1105, 32,
            	1108, 40,
            	1111, 48,
            	1114, 56,
            	1117, 64,
            	1120, 72,
            	1114, 80,
            	1123, 88,
            	1123, 96,
            	1126, 104,
            	1129, 112,
            	1123, 120,
            	1132, 128,
            	1111, 136,
            	1114, 144,
            	1015, 152,
            	1135, 160,
            	1138, 168,
            	1126, 176,
            	1129, 184,
            	1141, 192,
            	1144, 200,
            8884097, 8, 0, /* 1105: pointer.func */
            8884097, 8, 0, /* 1108: pointer.func */
            8884097, 8, 0, /* 1111: pointer.func */
            8884097, 8, 0, /* 1114: pointer.func */
            8884097, 8, 0, /* 1117: pointer.func */
            8884097, 8, 0, /* 1120: pointer.func */
            8884097, 8, 0, /* 1123: pointer.func */
            8884097, 8, 0, /* 1126: pointer.func */
            8884097, 8, 0, /* 1129: pointer.func */
            8884097, 8, 0, /* 1132: pointer.func */
            8884097, 8, 0, /* 1135: pointer.func */
            8884097, 8, 0, /* 1138: pointer.func */
            8884097, 8, 0, /* 1141: pointer.func */
            8884097, 8, 0, /* 1144: pointer.func */
            0, 8, 1, /* 1147: pointer.ASN1_TYPE */
            	1152, 0,
            0, 0, 1, /* 1152: ASN1_TYPE */
            	1157, 0,
            0, 16, 1, /* 1157: struct.asn1_type_st */
            	1162, 8,
            0, 8, 20, /* 1162: union.unknown */
            	114, 0,
            	1205, 0,
            	1035, 0,
            	1210, 0,
            	1215, 0,
            	1220, 0,
            	805, 0,
            	201, 0,
            	1049, 0,
            	196, 0,
            	1225, 0,
            	1230, 0,
            	1235, 0,
            	1240, 0,
            	191, 0,
            	186, 0,
            	176, 0,
            	1205, 0,
            	1205, 0,
            	1005, 0,
            1, 8, 1, /* 1205: pointer.struct.asn1_string_st */
            	181, 0,
            1, 8, 1, /* 1210: pointer.struct.asn1_string_st */
            	181, 0,
            1, 8, 1, /* 1215: pointer.struct.asn1_string_st */
            	181, 0,
            1, 8, 1, /* 1220: pointer.struct.asn1_string_st */
            	181, 0,
            1, 8, 1, /* 1225: pointer.struct.asn1_string_st */
            	181, 0,
            1, 8, 1, /* 1230: pointer.struct.asn1_string_st */
            	181, 0,
            1, 8, 1, /* 1235: pointer.struct.asn1_string_st */
            	181, 0,
            1, 8, 1, /* 1240: pointer.struct.asn1_string_st */
            	181, 0,
            8884097, 8, 0, /* 1245: pointer.func */
            0, 112, 13, /* 1248: struct.rsa_meth_st */
            	133, 0,
            	1277, 8,
            	1277, 16,
            	1277, 24,
            	1277, 32,
            	1280, 40,
            	1283, 48,
            	1245, 56,
            	1245, 64,
            	114, 80,
            	1029, 88,
            	1286, 96,
            	1021, 104,
            8884097, 8, 0, /* 1277: pointer.func */
            8884097, 8, 0, /* 1280: pointer.func */
            8884097, 8, 0, /* 1283: pointer.func */
            8884097, 8, 0, /* 1286: pointer.func */
            1, 8, 1, /* 1289: pointer.struct.rsa_meth_st */
            	1248, 0,
            0, 168, 17, /* 1294: struct.rsa_st */
            	1289, 16,
            	1331, 24,
            	1024, 32,
            	1024, 40,
            	1024, 48,
            	1024, 56,
            	1024, 64,
            	1024, 72,
            	1024, 80,
            	1024, 88,
            	1010, 96,
            	1336, 120,
            	1336, 128,
            	1336, 136,
            	114, 144,
            	1341, 152,
            	1341, 160,
            1, 8, 1, /* 1331: pointer.struct.engine_st */
            	359, 0,
            1, 8, 1, /* 1336: pointer.struct.bn_mont_ctx_st */
            	761, 0,
            1, 8, 1, /* 1341: pointer.struct.bn_blinding_st */
            	705, 0,
            0, 8, 5, /* 1346: union.unknown */
            	114, 0,
            	1359, 0,
            	257, 0,
            	1364, 0,
            	1490, 0,
            1, 8, 1, /* 1359: pointer.struct.rsa_st */
            	1294, 0,
            1, 8, 1, /* 1364: pointer.struct.dh_st */
            	1369, 0,
            0, 144, 12, /* 1369: struct.dh_st */
            	1396, 8,
            	1396, 16,
            	1396, 32,
            	1396, 40,
            	1413, 56,
            	1396, 64,
            	1396, 72,
            	18, 80,
            	1396, 96,
            	1427, 112,
            	1449, 128,
            	1485, 136,
            1, 8, 1, /* 1396: pointer.struct.bignum_st */
            	1401, 0,
            0, 24, 1, /* 1401: struct.bignum_st */
            	1406, 0,
            8884099, 8, 2, /* 1406: pointer_to_array_of_pointers_to_stack */
            	304, 0,
            	307, 12,
            1, 8, 1, /* 1413: pointer.struct.bn_mont_ctx_st */
            	1418, 0,
            0, 96, 3, /* 1418: struct.bn_mont_ctx_st */
            	1401, 8,
            	1401, 32,
            	1401, 56,
            0, 16, 1, /* 1427: struct.crypto_ex_data_st */
            	1432, 0,
            1, 8, 1, /* 1432: pointer.struct.stack_st_void */
            	1437, 0,
            0, 32, 1, /* 1437: struct.stack_st_void */
            	1442, 0,
            0, 32, 2, /* 1442: struct.stack_st */
            	346, 8,
            	351, 24,
            1, 8, 1, /* 1449: pointer.struct.dh_method */
            	1454, 0,
            0, 72, 8, /* 1454: struct.dh_method */
            	133, 0,
            	1473, 8,
            	1476, 16,
            	1479, 24,
            	1473, 32,
            	1473, 40,
            	114, 56,
            	1482, 64,
            8884097, 8, 0, /* 1473: pointer.func */
            8884097, 8, 0, /* 1476: pointer.func */
            8884097, 8, 0, /* 1479: pointer.func */
            8884097, 8, 0, /* 1482: pointer.func */
            1, 8, 1, /* 1485: pointer.struct.engine_st */
            	359, 0,
            1, 8, 1, /* 1490: pointer.struct.ec_key_st */
            	1495, 0,
            0, 56, 4, /* 1495: struct.ec_key_st */
            	1506, 8,
            	1750, 16,
            	1755, 24,
            	1772, 48,
            1, 8, 1, /* 1506: pointer.struct.ec_group_st */
            	1511, 0,
            0, 232, 12, /* 1511: struct.ec_group_st */
            	1538, 0,
            	1701, 8,
            	1706, 16,
            	1706, 40,
            	18, 80,
            	1718, 96,
            	1706, 104,
            	1706, 152,
            	1706, 176,
            	702, 208,
            	702, 216,
            	1747, 224,
            1, 8, 1, /* 1538: pointer.struct.ec_method_st */
            	1543, 0,
            0, 304, 37, /* 1543: struct.ec_method_st */
            	1620, 8,
            	1623, 16,
            	1623, 24,
            	1626, 32,
            	1018, 40,
            	1629, 48,
            	1632, 56,
            	1635, 64,
            	1638, 72,
            	1641, 80,
            	1641, 88,
            	1644, 96,
            	1647, 104,
            	1650, 112,
            	1653, 120,
            	1656, 128,
            	1659, 136,
            	802, 144,
            	1662, 152,
            	1665, 160,
            	1668, 168,
            	1671, 176,
            	1674, 184,
            	1677, 192,
            	1680, 200,
            	1683, 208,
            	1674, 216,
            	810, 224,
            	1686, 232,
            	1689, 240,
            	1632, 248,
            	1692, 256,
            	1695, 264,
            	1692, 272,
            	1695, 280,
            	1695, 288,
            	1698, 296,
            8884097, 8, 0, /* 1620: pointer.func */
            8884097, 8, 0, /* 1623: pointer.func */
            8884097, 8, 0, /* 1626: pointer.func */
            8884097, 8, 0, /* 1629: pointer.func */
            8884097, 8, 0, /* 1632: pointer.func */
            8884097, 8, 0, /* 1635: pointer.func */
            8884097, 8, 0, /* 1638: pointer.func */
            8884097, 8, 0, /* 1641: pointer.func */
            8884097, 8, 0, /* 1644: pointer.func */
            8884097, 8, 0, /* 1647: pointer.func */
            8884097, 8, 0, /* 1650: pointer.func */
            8884097, 8, 0, /* 1653: pointer.func */
            8884097, 8, 0, /* 1656: pointer.func */
            8884097, 8, 0, /* 1659: pointer.func */
            8884097, 8, 0, /* 1662: pointer.func */
            8884097, 8, 0, /* 1665: pointer.func */
            8884097, 8, 0, /* 1668: pointer.func */
            8884097, 8, 0, /* 1671: pointer.func */
            8884097, 8, 0, /* 1674: pointer.func */
            8884097, 8, 0, /* 1677: pointer.func */
            8884097, 8, 0, /* 1680: pointer.func */
            8884097, 8, 0, /* 1683: pointer.func */
            8884097, 8, 0, /* 1686: pointer.func */
            8884097, 8, 0, /* 1689: pointer.func */
            8884097, 8, 0, /* 1692: pointer.func */
            8884097, 8, 0, /* 1695: pointer.func */
            8884097, 8, 0, /* 1698: pointer.func */
            1, 8, 1, /* 1701: pointer.struct.ec_point_st */
            	813, 0,
            0, 24, 1, /* 1706: struct.bignum_st */
            	1711, 0,
            8884099, 8, 2, /* 1711: pointer_to_array_of_pointers_to_stack */
            	304, 0,
            	307, 12,
            1, 8, 1, /* 1718: pointer.struct.ec_extra_data_st */
            	1723, 0,
            0, 40, 5, /* 1723: struct.ec_extra_data_st */
            	1736, 0,
            	702, 8,
            	1741, 16,
            	1744, 24,
            	1744, 32,
            1, 8, 1, /* 1736: pointer.struct.ec_extra_data_st */
            	1723, 0,
            8884097, 8, 0, /* 1741: pointer.func */
            8884097, 8, 0, /* 1744: pointer.func */
            8884097, 8, 0, /* 1747: pointer.func */
            1, 8, 1, /* 1750: pointer.struct.ec_point_st */
            	813, 0,
            1, 8, 1, /* 1755: pointer.struct.bignum_st */
            	1760, 0,
            0, 24, 1, /* 1760: struct.bignum_st */
            	1765, 0,
            8884099, 8, 2, /* 1765: pointer_to_array_of_pointers_to_stack */
            	304, 0,
            	307, 12,
            1, 8, 1, /* 1772: pointer.struct.ec_extra_data_st */
            	1777, 0,
            0, 40, 5, /* 1777: struct.ec_extra_data_st */
            	1790, 0,
            	702, 8,
            	1741, 16,
            	1744, 24,
            	1744, 32,
            1, 8, 1, /* 1790: pointer.struct.ec_extra_data_st */
            	1777, 0,
            1, 8, 1, /* 1795: pointer.struct.evp_pkey_asn1_method_st */
            	1054, 0,
            8884099, 8, 2, /* 1800: pointer_to_array_of_pointers_to_stack */
            	1147, 0,
            	307, 20,
            0, 24, 2, /* 1807: struct.x509_attributes_st */
            	119, 0,
            	1814, 16,
            0, 8, 3, /* 1814: union.unknown */
            	114, 0,
            	1823, 0,
            	1835, 0,
            1, 8, 1, /* 1823: pointer.struct.stack_st_ASN1_TYPE */
            	1828, 0,
            0, 32, 2, /* 1828: struct.stack_st_fake_ASN1_TYPE */
            	1800, 8,
            	351, 24,
            1, 8, 1, /* 1835: pointer.struct.asn1_type_st */
            	66, 0,
            0, 56, 4, /* 1840: struct.evp_pkey_st */
            	1795, 16,
            	1485, 24,
            	1346, 32,
            	1851, 48,
            1, 8, 1, /* 1851: pointer.struct.stack_st_X509_ATTRIBUTE */
            	1856, 0,
            0, 32, 2, /* 1856: struct.stack_st_fake_X509_ATTRIBUTE */
            	1863, 8,
            	351, 24,
            8884099, 8, 2, /* 1863: pointer_to_array_of_pointers_to_stack */
            	1870, 0,
            	307, 20,
            0, 8, 1, /* 1870: pointer.X509_ATTRIBUTE */
            	1875, 0,
            0, 0, 1, /* 1875: X509_ATTRIBUTE */
            	1807, 0,
            1, 8, 1, /* 1880: pointer.struct.evp_pkey_st */
            	1840, 0,
        },
        .arg_entity_index = { 1880, },
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

