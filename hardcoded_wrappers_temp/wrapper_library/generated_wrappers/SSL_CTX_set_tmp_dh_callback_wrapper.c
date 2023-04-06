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

void bb_SSL_CTX_set_tmp_dh_callback(SSL_CTX * arg_a,DH *(*arg_b)(SSL *, int, int));

void SSL_CTX_set_tmp_dh_callback(SSL_CTX * arg_a,DH *(*arg_b)(SSL *, int, int)) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_CTX_set_tmp_dh_callback called %lu\n", in_lib);
    if (!in_lib)
        bb_SSL_CTX_set_tmp_dh_callback(arg_a,arg_b);
    else {
        void (*orig_SSL_CTX_set_tmp_dh_callback)(SSL_CTX *,DH *(*)(SSL *, int, int));
        orig_SSL_CTX_set_tmp_dh_callback = dlsym(RTLD_NEXT, "SSL_CTX_set_tmp_dh_callback");
        orig_SSL_CTX_set_tmp_dh_callback(arg_a,arg_b);
    }
}

void bb_SSL_CTX_set_tmp_dh_callback(SSL_CTX * arg_a,DH *(*arg_b)(SSL *, int, int)) 
{
    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 16, 1, /* 0: struct.srtp_protection_profile_st */
            	5, 0,
            1, 8, 1, /* 5: pointer.char */
            	8884096, 0,
            0, 0, 1, /* 10: SRTP_PROTECTION_PROFILE */
            	0, 0,
            8884097, 8, 0, /* 15: pointer.func */
            0, 24, 1, /* 18: struct.bignum_st */
            	23, 0,
            8884099, 8, 2, /* 23: pointer_to_array_of_pointers_to_stack */
            	30, 0,
            	33, 12,
            0, 4, 0, /* 30: unsigned int */
            0, 4, 0, /* 33: int */
            1, 8, 1, /* 36: pointer.struct.bignum_st */
            	18, 0,
            0, 128, 14, /* 41: struct.srp_ctx_st */
            	72, 0,
            	75, 8,
            	78, 16,
            	81, 24,
            	84, 32,
            	36, 40,
            	36, 48,
            	36, 56,
            	36, 64,
            	36, 72,
            	36, 80,
            	36, 88,
            	36, 96,
            	84, 104,
            0, 8, 0, /* 72: pointer.void */
            8884097, 8, 0, /* 75: pointer.func */
            8884097, 8, 0, /* 78: pointer.func */
            8884097, 8, 0, /* 81: pointer.func */
            1, 8, 1, /* 84: pointer.char */
            	8884096, 0,
            8884097, 8, 0, /* 89: pointer.func */
            8884097, 8, 0, /* 92: pointer.func */
            1, 8, 1, /* 95: pointer.struct.dh_st */
            	100, 0,
            0, 144, 12, /* 100: struct.dh_st */
            	127, 8,
            	127, 16,
            	127, 32,
            	127, 40,
            	144, 56,
            	127, 64,
            	127, 72,
            	158, 80,
            	127, 96,
            	166, 112,
            	196, 128,
            	232, 136,
            1, 8, 1, /* 127: pointer.struct.bignum_st */
            	132, 0,
            0, 24, 1, /* 132: struct.bignum_st */
            	137, 0,
            8884099, 8, 2, /* 137: pointer_to_array_of_pointers_to_stack */
            	30, 0,
            	33, 12,
            1, 8, 1, /* 144: pointer.struct.bn_mont_ctx_st */
            	149, 0,
            0, 96, 3, /* 149: struct.bn_mont_ctx_st */
            	132, 8,
            	132, 32,
            	132, 56,
            1, 8, 1, /* 158: pointer.unsigned char */
            	163, 0,
            0, 1, 0, /* 163: unsigned char */
            0, 16, 1, /* 166: struct.crypto_ex_data_st */
            	171, 0,
            1, 8, 1, /* 171: pointer.struct.stack_st_void */
            	176, 0,
            0, 32, 1, /* 176: struct.stack_st_void */
            	181, 0,
            0, 32, 2, /* 181: struct.stack_st */
            	188, 8,
            	193, 24,
            1, 8, 1, /* 188: pointer.pointer.char */
            	84, 0,
            8884097, 8, 0, /* 193: pointer.func */
            1, 8, 1, /* 196: pointer.struct.dh_method */
            	201, 0,
            0, 72, 8, /* 201: struct.dh_method */
            	5, 0,
            	220, 8,
            	223, 16,
            	226, 24,
            	220, 32,
            	220, 40,
            	84, 56,
            	229, 64,
            8884097, 8, 0, /* 220: pointer.func */
            8884097, 8, 0, /* 223: pointer.func */
            8884097, 8, 0, /* 226: pointer.func */
            8884097, 8, 0, /* 229: pointer.func */
            1, 8, 1, /* 232: pointer.struct.engine_st */
            	237, 0,
            0, 216, 24, /* 237: struct.engine_st */
            	5, 0,
            	5, 8,
            	288, 16,
            	343, 24,
            	394, 32,
            	430, 40,
            	447, 48,
            	474, 56,
            	509, 64,
            	517, 72,
            	520, 80,
            	523, 88,
            	526, 96,
            	529, 104,
            	529, 112,
            	529, 120,
            	532, 128,
            	535, 136,
            	535, 144,
            	538, 152,
            	541, 160,
            	553, 184,
            	575, 200,
            	575, 208,
            1, 8, 1, /* 288: pointer.struct.rsa_meth_st */
            	293, 0,
            0, 112, 13, /* 293: struct.rsa_meth_st */
            	5, 0,
            	322, 8,
            	322, 16,
            	322, 24,
            	322, 32,
            	325, 40,
            	328, 48,
            	331, 56,
            	331, 64,
            	84, 80,
            	334, 88,
            	337, 96,
            	340, 104,
            8884097, 8, 0, /* 322: pointer.func */
            8884097, 8, 0, /* 325: pointer.func */
            8884097, 8, 0, /* 328: pointer.func */
            8884097, 8, 0, /* 331: pointer.func */
            8884097, 8, 0, /* 334: pointer.func */
            8884097, 8, 0, /* 337: pointer.func */
            8884097, 8, 0, /* 340: pointer.func */
            1, 8, 1, /* 343: pointer.struct.dsa_method */
            	348, 0,
            0, 96, 11, /* 348: struct.dsa_method */
            	5, 0,
            	373, 8,
            	376, 16,
            	379, 24,
            	382, 32,
            	385, 40,
            	388, 48,
            	388, 56,
            	84, 72,
            	391, 80,
            	388, 88,
            8884097, 8, 0, /* 373: pointer.func */
            8884097, 8, 0, /* 376: pointer.func */
            8884097, 8, 0, /* 379: pointer.func */
            8884097, 8, 0, /* 382: pointer.func */
            8884097, 8, 0, /* 385: pointer.func */
            8884097, 8, 0, /* 388: pointer.func */
            8884097, 8, 0, /* 391: pointer.func */
            1, 8, 1, /* 394: pointer.struct.dh_method */
            	399, 0,
            0, 72, 8, /* 399: struct.dh_method */
            	5, 0,
            	418, 8,
            	421, 16,
            	424, 24,
            	418, 32,
            	418, 40,
            	84, 56,
            	427, 64,
            8884097, 8, 0, /* 418: pointer.func */
            8884097, 8, 0, /* 421: pointer.func */
            8884097, 8, 0, /* 424: pointer.func */
            8884097, 8, 0, /* 427: pointer.func */
            1, 8, 1, /* 430: pointer.struct.ecdh_method */
            	435, 0,
            0, 32, 3, /* 435: struct.ecdh_method */
            	5, 0,
            	444, 8,
            	84, 24,
            8884097, 8, 0, /* 444: pointer.func */
            1, 8, 1, /* 447: pointer.struct.ecdsa_method */
            	452, 0,
            0, 48, 5, /* 452: struct.ecdsa_method */
            	5, 0,
            	465, 8,
            	468, 16,
            	471, 24,
            	84, 40,
            8884097, 8, 0, /* 465: pointer.func */
            8884097, 8, 0, /* 468: pointer.func */
            8884097, 8, 0, /* 471: pointer.func */
            1, 8, 1, /* 474: pointer.struct.rand_meth_st */
            	479, 0,
            0, 48, 6, /* 479: struct.rand_meth_st */
            	494, 0,
            	497, 8,
            	500, 16,
            	503, 24,
            	497, 32,
            	506, 40,
            8884097, 8, 0, /* 494: pointer.func */
            8884097, 8, 0, /* 497: pointer.func */
            8884097, 8, 0, /* 500: pointer.func */
            8884097, 8, 0, /* 503: pointer.func */
            8884097, 8, 0, /* 506: pointer.func */
            1, 8, 1, /* 509: pointer.struct.store_method_st */
            	514, 0,
            0, 0, 0, /* 514: struct.store_method_st */
            8884097, 8, 0, /* 517: pointer.func */
            8884097, 8, 0, /* 520: pointer.func */
            8884097, 8, 0, /* 523: pointer.func */
            8884097, 8, 0, /* 526: pointer.func */
            8884097, 8, 0, /* 529: pointer.func */
            8884097, 8, 0, /* 532: pointer.func */
            8884097, 8, 0, /* 535: pointer.func */
            8884097, 8, 0, /* 538: pointer.func */
            1, 8, 1, /* 541: pointer.struct.ENGINE_CMD_DEFN_st */
            	546, 0,
            0, 32, 2, /* 546: struct.ENGINE_CMD_DEFN_st */
            	5, 8,
            	5, 16,
            0, 16, 1, /* 553: struct.crypto_ex_data_st */
            	558, 0,
            1, 8, 1, /* 558: pointer.struct.stack_st_void */
            	563, 0,
            0, 32, 1, /* 563: struct.stack_st_void */
            	568, 0,
            0, 32, 2, /* 568: struct.stack_st */
            	188, 8,
            	193, 24,
            1, 8, 1, /* 575: pointer.struct.engine_st */
            	237, 0,
            1, 8, 1, /* 580: pointer.struct.rsa_st */
            	585, 0,
            0, 168, 17, /* 585: struct.rsa_st */
            	622, 16,
            	677, 24,
            	682, 32,
            	682, 40,
            	682, 48,
            	682, 56,
            	682, 64,
            	682, 72,
            	682, 80,
            	682, 88,
            	699, 96,
            	721, 120,
            	721, 128,
            	721, 136,
            	84, 144,
            	735, 152,
            	735, 160,
            1, 8, 1, /* 622: pointer.struct.rsa_meth_st */
            	627, 0,
            0, 112, 13, /* 627: struct.rsa_meth_st */
            	5, 0,
            	656, 8,
            	656, 16,
            	656, 24,
            	656, 32,
            	659, 40,
            	662, 48,
            	665, 56,
            	665, 64,
            	84, 80,
            	668, 88,
            	671, 96,
            	674, 104,
            8884097, 8, 0, /* 656: pointer.func */
            8884097, 8, 0, /* 659: pointer.func */
            8884097, 8, 0, /* 662: pointer.func */
            8884097, 8, 0, /* 665: pointer.func */
            8884097, 8, 0, /* 668: pointer.func */
            8884097, 8, 0, /* 671: pointer.func */
            8884097, 8, 0, /* 674: pointer.func */
            1, 8, 1, /* 677: pointer.struct.engine_st */
            	237, 0,
            1, 8, 1, /* 682: pointer.struct.bignum_st */
            	687, 0,
            0, 24, 1, /* 687: struct.bignum_st */
            	692, 0,
            8884099, 8, 2, /* 692: pointer_to_array_of_pointers_to_stack */
            	30, 0,
            	33, 12,
            0, 16, 1, /* 699: struct.crypto_ex_data_st */
            	704, 0,
            1, 8, 1, /* 704: pointer.struct.stack_st_void */
            	709, 0,
            0, 32, 1, /* 709: struct.stack_st_void */
            	714, 0,
            0, 32, 2, /* 714: struct.stack_st */
            	188, 8,
            	193, 24,
            1, 8, 1, /* 721: pointer.struct.bn_mont_ctx_st */
            	726, 0,
            0, 96, 3, /* 726: struct.bn_mont_ctx_st */
            	687, 8,
            	687, 32,
            	687, 56,
            1, 8, 1, /* 735: pointer.struct.bn_blinding_st */
            	740, 0,
            0, 88, 7, /* 740: struct.bn_blinding_st */
            	757, 0,
            	757, 8,
            	757, 16,
            	757, 24,
            	774, 40,
            	779, 72,
            	793, 80,
            1, 8, 1, /* 757: pointer.struct.bignum_st */
            	762, 0,
            0, 24, 1, /* 762: struct.bignum_st */
            	767, 0,
            8884099, 8, 2, /* 767: pointer_to_array_of_pointers_to_stack */
            	30, 0,
            	33, 12,
            0, 16, 1, /* 774: struct.crypto_threadid_st */
            	72, 0,
            1, 8, 1, /* 779: pointer.struct.bn_mont_ctx_st */
            	784, 0,
            0, 96, 3, /* 784: struct.bn_mont_ctx_st */
            	762, 8,
            	762, 32,
            	762, 56,
            8884097, 8, 0, /* 793: pointer.func */
            8884097, 8, 0, /* 796: pointer.func */
            8884097, 8, 0, /* 799: pointer.func */
            1, 8, 1, /* 802: pointer.struct.env_md_st */
            	807, 0,
            0, 120, 8, /* 807: struct.env_md_st */
            	826, 24,
            	799, 32,
            	829, 40,
            	796, 48,
            	826, 56,
            	832, 64,
            	835, 72,
            	838, 112,
            8884097, 8, 0, /* 826: pointer.func */
            8884097, 8, 0, /* 829: pointer.func */
            8884097, 8, 0, /* 832: pointer.func */
            8884097, 8, 0, /* 835: pointer.func */
            8884097, 8, 0, /* 838: pointer.func */
            1, 8, 1, /* 841: pointer.struct.stack_st_X509_ATTRIBUTE */
            	846, 0,
            0, 32, 2, /* 846: struct.stack_st_fake_X509_ATTRIBUTE */
            	853, 8,
            	193, 24,
            8884099, 8, 2, /* 853: pointer_to_array_of_pointers_to_stack */
            	860, 0,
            	33, 20,
            0, 8, 1, /* 860: pointer.X509_ATTRIBUTE */
            	865, 0,
            0, 0, 1, /* 865: X509_ATTRIBUTE */
            	870, 0,
            0, 24, 2, /* 870: struct.x509_attributes_st */
            	877, 0,
            	896, 16,
            1, 8, 1, /* 877: pointer.struct.asn1_object_st */
            	882, 0,
            0, 40, 3, /* 882: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	891, 24,
            1, 8, 1, /* 891: pointer.unsigned char */
            	163, 0,
            0, 8, 3, /* 896: union.unknown */
            	84, 0,
            	905, 0,
            	1084, 0,
            1, 8, 1, /* 905: pointer.struct.stack_st_ASN1_TYPE */
            	910, 0,
            0, 32, 2, /* 910: struct.stack_st_fake_ASN1_TYPE */
            	917, 8,
            	193, 24,
            8884099, 8, 2, /* 917: pointer_to_array_of_pointers_to_stack */
            	924, 0,
            	33, 20,
            0, 8, 1, /* 924: pointer.ASN1_TYPE */
            	929, 0,
            0, 0, 1, /* 929: ASN1_TYPE */
            	934, 0,
            0, 16, 1, /* 934: struct.asn1_type_st */
            	939, 8,
            0, 8, 20, /* 939: union.unknown */
            	84, 0,
            	982, 0,
            	992, 0,
            	1006, 0,
            	1011, 0,
            	1016, 0,
            	1021, 0,
            	1026, 0,
            	1031, 0,
            	1036, 0,
            	1041, 0,
            	1046, 0,
            	1051, 0,
            	1056, 0,
            	1061, 0,
            	1066, 0,
            	1071, 0,
            	982, 0,
            	982, 0,
            	1076, 0,
            1, 8, 1, /* 982: pointer.struct.asn1_string_st */
            	987, 0,
            0, 24, 1, /* 987: struct.asn1_string_st */
            	158, 8,
            1, 8, 1, /* 992: pointer.struct.asn1_object_st */
            	997, 0,
            0, 40, 3, /* 997: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	891, 24,
            1, 8, 1, /* 1006: pointer.struct.asn1_string_st */
            	987, 0,
            1, 8, 1, /* 1011: pointer.struct.asn1_string_st */
            	987, 0,
            1, 8, 1, /* 1016: pointer.struct.asn1_string_st */
            	987, 0,
            1, 8, 1, /* 1021: pointer.struct.asn1_string_st */
            	987, 0,
            1, 8, 1, /* 1026: pointer.struct.asn1_string_st */
            	987, 0,
            1, 8, 1, /* 1031: pointer.struct.asn1_string_st */
            	987, 0,
            1, 8, 1, /* 1036: pointer.struct.asn1_string_st */
            	987, 0,
            1, 8, 1, /* 1041: pointer.struct.asn1_string_st */
            	987, 0,
            1, 8, 1, /* 1046: pointer.struct.asn1_string_st */
            	987, 0,
            1, 8, 1, /* 1051: pointer.struct.asn1_string_st */
            	987, 0,
            1, 8, 1, /* 1056: pointer.struct.asn1_string_st */
            	987, 0,
            1, 8, 1, /* 1061: pointer.struct.asn1_string_st */
            	987, 0,
            1, 8, 1, /* 1066: pointer.struct.asn1_string_st */
            	987, 0,
            1, 8, 1, /* 1071: pointer.struct.asn1_string_st */
            	987, 0,
            1, 8, 1, /* 1076: pointer.struct.ASN1_VALUE_st */
            	1081, 0,
            0, 0, 0, /* 1081: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1084: pointer.struct.asn1_type_st */
            	1089, 0,
            0, 16, 1, /* 1089: struct.asn1_type_st */
            	1094, 8,
            0, 8, 20, /* 1094: union.unknown */
            	84, 0,
            	1137, 0,
            	877, 0,
            	1147, 0,
            	1152, 0,
            	1157, 0,
            	1162, 0,
            	1167, 0,
            	1172, 0,
            	1177, 0,
            	1182, 0,
            	1187, 0,
            	1192, 0,
            	1197, 0,
            	1202, 0,
            	1207, 0,
            	1212, 0,
            	1137, 0,
            	1137, 0,
            	1217, 0,
            1, 8, 1, /* 1137: pointer.struct.asn1_string_st */
            	1142, 0,
            0, 24, 1, /* 1142: struct.asn1_string_st */
            	158, 8,
            1, 8, 1, /* 1147: pointer.struct.asn1_string_st */
            	1142, 0,
            1, 8, 1, /* 1152: pointer.struct.asn1_string_st */
            	1142, 0,
            1, 8, 1, /* 1157: pointer.struct.asn1_string_st */
            	1142, 0,
            1, 8, 1, /* 1162: pointer.struct.asn1_string_st */
            	1142, 0,
            1, 8, 1, /* 1167: pointer.struct.asn1_string_st */
            	1142, 0,
            1, 8, 1, /* 1172: pointer.struct.asn1_string_st */
            	1142, 0,
            1, 8, 1, /* 1177: pointer.struct.asn1_string_st */
            	1142, 0,
            1, 8, 1, /* 1182: pointer.struct.asn1_string_st */
            	1142, 0,
            1, 8, 1, /* 1187: pointer.struct.asn1_string_st */
            	1142, 0,
            1, 8, 1, /* 1192: pointer.struct.asn1_string_st */
            	1142, 0,
            1, 8, 1, /* 1197: pointer.struct.asn1_string_st */
            	1142, 0,
            1, 8, 1, /* 1202: pointer.struct.asn1_string_st */
            	1142, 0,
            1, 8, 1, /* 1207: pointer.struct.asn1_string_st */
            	1142, 0,
            1, 8, 1, /* 1212: pointer.struct.asn1_string_st */
            	1142, 0,
            1, 8, 1, /* 1217: pointer.struct.ASN1_VALUE_st */
            	1222, 0,
            0, 0, 0, /* 1222: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1225: pointer.struct.dh_st */
            	100, 0,
            1, 8, 1, /* 1230: pointer.struct.rsa_st */
            	585, 0,
            0, 8, 5, /* 1235: union.unknown */
            	84, 0,
            	1230, 0,
            	1248, 0,
            	1225, 0,
            	1387, 0,
            1, 8, 1, /* 1248: pointer.struct.dsa_st */
            	1253, 0,
            0, 136, 11, /* 1253: struct.dsa_st */
            	1278, 24,
            	1278, 32,
            	1278, 40,
            	1278, 48,
            	1278, 56,
            	1278, 64,
            	1278, 72,
            	1295, 88,
            	1309, 104,
            	1331, 120,
            	1382, 128,
            1, 8, 1, /* 1278: pointer.struct.bignum_st */
            	1283, 0,
            0, 24, 1, /* 1283: struct.bignum_st */
            	1288, 0,
            8884099, 8, 2, /* 1288: pointer_to_array_of_pointers_to_stack */
            	30, 0,
            	33, 12,
            1, 8, 1, /* 1295: pointer.struct.bn_mont_ctx_st */
            	1300, 0,
            0, 96, 3, /* 1300: struct.bn_mont_ctx_st */
            	1283, 8,
            	1283, 32,
            	1283, 56,
            0, 16, 1, /* 1309: struct.crypto_ex_data_st */
            	1314, 0,
            1, 8, 1, /* 1314: pointer.struct.stack_st_void */
            	1319, 0,
            0, 32, 1, /* 1319: struct.stack_st_void */
            	1324, 0,
            0, 32, 2, /* 1324: struct.stack_st */
            	188, 8,
            	193, 24,
            1, 8, 1, /* 1331: pointer.struct.dsa_method */
            	1336, 0,
            0, 96, 11, /* 1336: struct.dsa_method */
            	5, 0,
            	1361, 8,
            	1364, 16,
            	1367, 24,
            	1370, 32,
            	1373, 40,
            	1376, 48,
            	1376, 56,
            	84, 72,
            	1379, 80,
            	1376, 88,
            8884097, 8, 0, /* 1361: pointer.func */
            8884097, 8, 0, /* 1364: pointer.func */
            8884097, 8, 0, /* 1367: pointer.func */
            8884097, 8, 0, /* 1370: pointer.func */
            8884097, 8, 0, /* 1373: pointer.func */
            8884097, 8, 0, /* 1376: pointer.func */
            8884097, 8, 0, /* 1379: pointer.func */
            1, 8, 1, /* 1382: pointer.struct.engine_st */
            	237, 0,
            1, 8, 1, /* 1387: pointer.struct.ec_key_st */
            	1392, 0,
            0, 56, 4, /* 1392: struct.ec_key_st */
            	1403, 8,
            	1851, 16,
            	1856, 24,
            	1873, 48,
            1, 8, 1, /* 1403: pointer.struct.ec_group_st */
            	1408, 0,
            0, 232, 12, /* 1408: struct.ec_group_st */
            	1435, 0,
            	1607, 8,
            	1807, 16,
            	1807, 40,
            	158, 80,
            	1819, 96,
            	1807, 104,
            	1807, 152,
            	1807, 176,
            	72, 208,
            	72, 216,
            	1848, 224,
            1, 8, 1, /* 1435: pointer.struct.ec_method_st */
            	1440, 0,
            0, 304, 37, /* 1440: struct.ec_method_st */
            	1517, 8,
            	1520, 16,
            	1520, 24,
            	1523, 32,
            	1526, 40,
            	1529, 48,
            	1532, 56,
            	1535, 64,
            	1538, 72,
            	1541, 80,
            	1541, 88,
            	1544, 96,
            	1547, 104,
            	1550, 112,
            	1553, 120,
            	1556, 128,
            	1559, 136,
            	1562, 144,
            	1565, 152,
            	1568, 160,
            	1571, 168,
            	1574, 176,
            	1577, 184,
            	1580, 192,
            	1583, 200,
            	1586, 208,
            	1577, 216,
            	1589, 224,
            	1592, 232,
            	1595, 240,
            	1532, 248,
            	1598, 256,
            	1601, 264,
            	1598, 272,
            	1601, 280,
            	1601, 288,
            	1604, 296,
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
            8884097, 8, 0, /* 1589: pointer.func */
            8884097, 8, 0, /* 1592: pointer.func */
            8884097, 8, 0, /* 1595: pointer.func */
            8884097, 8, 0, /* 1598: pointer.func */
            8884097, 8, 0, /* 1601: pointer.func */
            8884097, 8, 0, /* 1604: pointer.func */
            1, 8, 1, /* 1607: pointer.struct.ec_point_st */
            	1612, 0,
            0, 88, 4, /* 1612: struct.ec_point_st */
            	1623, 0,
            	1795, 8,
            	1795, 32,
            	1795, 56,
            1, 8, 1, /* 1623: pointer.struct.ec_method_st */
            	1628, 0,
            0, 304, 37, /* 1628: struct.ec_method_st */
            	1705, 8,
            	1708, 16,
            	1708, 24,
            	1711, 32,
            	1714, 40,
            	1717, 48,
            	1720, 56,
            	1723, 64,
            	1726, 72,
            	1729, 80,
            	1729, 88,
            	1732, 96,
            	1735, 104,
            	1738, 112,
            	1741, 120,
            	1744, 128,
            	1747, 136,
            	1750, 144,
            	1753, 152,
            	1756, 160,
            	1759, 168,
            	1762, 176,
            	1765, 184,
            	1768, 192,
            	1771, 200,
            	1774, 208,
            	1765, 216,
            	1777, 224,
            	1780, 232,
            	1783, 240,
            	1720, 248,
            	1786, 256,
            	1789, 264,
            	1786, 272,
            	1789, 280,
            	1789, 288,
            	1792, 296,
            8884097, 8, 0, /* 1705: pointer.func */
            8884097, 8, 0, /* 1708: pointer.func */
            8884097, 8, 0, /* 1711: pointer.func */
            8884097, 8, 0, /* 1714: pointer.func */
            8884097, 8, 0, /* 1717: pointer.func */
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
            0, 24, 1, /* 1795: struct.bignum_st */
            	1800, 0,
            8884099, 8, 2, /* 1800: pointer_to_array_of_pointers_to_stack */
            	30, 0,
            	33, 12,
            0, 24, 1, /* 1807: struct.bignum_st */
            	1812, 0,
            8884099, 8, 2, /* 1812: pointer_to_array_of_pointers_to_stack */
            	30, 0,
            	33, 12,
            1, 8, 1, /* 1819: pointer.struct.ec_extra_data_st */
            	1824, 0,
            0, 40, 5, /* 1824: struct.ec_extra_data_st */
            	1837, 0,
            	72, 8,
            	1842, 16,
            	1845, 24,
            	1845, 32,
            1, 8, 1, /* 1837: pointer.struct.ec_extra_data_st */
            	1824, 0,
            8884097, 8, 0, /* 1842: pointer.func */
            8884097, 8, 0, /* 1845: pointer.func */
            8884097, 8, 0, /* 1848: pointer.func */
            1, 8, 1, /* 1851: pointer.struct.ec_point_st */
            	1612, 0,
            1, 8, 1, /* 1856: pointer.struct.bignum_st */
            	1861, 0,
            0, 24, 1, /* 1861: struct.bignum_st */
            	1866, 0,
            8884099, 8, 2, /* 1866: pointer_to_array_of_pointers_to_stack */
            	30, 0,
            	33, 12,
            1, 8, 1, /* 1873: pointer.struct.ec_extra_data_st */
            	1878, 0,
            0, 40, 5, /* 1878: struct.ec_extra_data_st */
            	1891, 0,
            	72, 8,
            	1842, 16,
            	1845, 24,
            	1845, 32,
            1, 8, 1, /* 1891: pointer.struct.ec_extra_data_st */
            	1878, 0,
            8884097, 8, 0, /* 1896: pointer.func */
            0, 56, 4, /* 1899: struct.evp_pkey_st */
            	1910, 16,
            	2011, 24,
            	1235, 32,
            	841, 48,
            1, 8, 1, /* 1910: pointer.struct.evp_pkey_asn1_method_st */
            	1915, 0,
            0, 208, 24, /* 1915: struct.evp_pkey_asn1_method_st */
            	84, 16,
            	84, 24,
            	1966, 32,
            	1969, 40,
            	1972, 48,
            	1975, 56,
            	1978, 64,
            	1981, 72,
            	1975, 80,
            	1984, 88,
            	1984, 96,
            	1987, 104,
            	1990, 112,
            	1984, 120,
            	1993, 128,
            	1972, 136,
            	1975, 144,
            	1996, 152,
            	1999, 160,
            	2002, 168,
            	1987, 176,
            	1990, 184,
            	2005, 192,
            	2008, 200,
            8884097, 8, 0, /* 1966: pointer.func */
            8884097, 8, 0, /* 1969: pointer.func */
            8884097, 8, 0, /* 1972: pointer.func */
            8884097, 8, 0, /* 1975: pointer.func */
            8884097, 8, 0, /* 1978: pointer.func */
            8884097, 8, 0, /* 1981: pointer.func */
            8884097, 8, 0, /* 1984: pointer.func */
            8884097, 8, 0, /* 1987: pointer.func */
            8884097, 8, 0, /* 1990: pointer.func */
            8884097, 8, 0, /* 1993: pointer.func */
            8884097, 8, 0, /* 1996: pointer.func */
            8884097, 8, 0, /* 1999: pointer.func */
            8884097, 8, 0, /* 2002: pointer.func */
            8884097, 8, 0, /* 2005: pointer.func */
            8884097, 8, 0, /* 2008: pointer.func */
            1, 8, 1, /* 2011: pointer.struct.engine_st */
            	237, 0,
            1, 8, 1, /* 2016: pointer.struct.stack_st_X509_ALGOR */
            	2021, 0,
            0, 32, 2, /* 2021: struct.stack_st_fake_X509_ALGOR */
            	2028, 8,
            	193, 24,
            8884099, 8, 2, /* 2028: pointer_to_array_of_pointers_to_stack */
            	2035, 0,
            	33, 20,
            0, 8, 1, /* 2035: pointer.X509_ALGOR */
            	2040, 0,
            0, 0, 1, /* 2040: X509_ALGOR */
            	2045, 0,
            0, 16, 2, /* 2045: struct.X509_algor_st */
            	2052, 0,
            	2066, 8,
            1, 8, 1, /* 2052: pointer.struct.asn1_object_st */
            	2057, 0,
            0, 40, 3, /* 2057: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	891, 24,
            1, 8, 1, /* 2066: pointer.struct.asn1_type_st */
            	2071, 0,
            0, 16, 1, /* 2071: struct.asn1_type_st */
            	2076, 8,
            0, 8, 20, /* 2076: union.unknown */
            	84, 0,
            	2119, 0,
            	2052, 0,
            	2129, 0,
            	2134, 0,
            	2139, 0,
            	2144, 0,
            	2149, 0,
            	2154, 0,
            	2159, 0,
            	2164, 0,
            	2169, 0,
            	2174, 0,
            	2179, 0,
            	2184, 0,
            	2189, 0,
            	2194, 0,
            	2119, 0,
            	2119, 0,
            	1217, 0,
            1, 8, 1, /* 2119: pointer.struct.asn1_string_st */
            	2124, 0,
            0, 24, 1, /* 2124: struct.asn1_string_st */
            	158, 8,
            1, 8, 1, /* 2129: pointer.struct.asn1_string_st */
            	2124, 0,
            1, 8, 1, /* 2134: pointer.struct.asn1_string_st */
            	2124, 0,
            1, 8, 1, /* 2139: pointer.struct.asn1_string_st */
            	2124, 0,
            1, 8, 1, /* 2144: pointer.struct.asn1_string_st */
            	2124, 0,
            1, 8, 1, /* 2149: pointer.struct.asn1_string_st */
            	2124, 0,
            1, 8, 1, /* 2154: pointer.struct.asn1_string_st */
            	2124, 0,
            1, 8, 1, /* 2159: pointer.struct.asn1_string_st */
            	2124, 0,
            1, 8, 1, /* 2164: pointer.struct.asn1_string_st */
            	2124, 0,
            1, 8, 1, /* 2169: pointer.struct.asn1_string_st */
            	2124, 0,
            1, 8, 1, /* 2174: pointer.struct.asn1_string_st */
            	2124, 0,
            1, 8, 1, /* 2179: pointer.struct.asn1_string_st */
            	2124, 0,
            1, 8, 1, /* 2184: pointer.struct.asn1_string_st */
            	2124, 0,
            1, 8, 1, /* 2189: pointer.struct.asn1_string_st */
            	2124, 0,
            1, 8, 1, /* 2194: pointer.struct.asn1_string_st */
            	2124, 0,
            1, 8, 1, /* 2199: pointer.struct.asn1_string_st */
            	2204, 0,
            0, 24, 1, /* 2204: struct.asn1_string_st */
            	158, 8,
            1, 8, 1, /* 2209: pointer.struct.x509_cert_aux_st */
            	2214, 0,
            0, 40, 5, /* 2214: struct.x509_cert_aux_st */
            	2227, 0,
            	2227, 8,
            	2199, 16,
            	2265, 24,
            	2016, 32,
            1, 8, 1, /* 2227: pointer.struct.stack_st_ASN1_OBJECT */
            	2232, 0,
            0, 32, 2, /* 2232: struct.stack_st_fake_ASN1_OBJECT */
            	2239, 8,
            	193, 24,
            8884099, 8, 2, /* 2239: pointer_to_array_of_pointers_to_stack */
            	2246, 0,
            	33, 20,
            0, 8, 1, /* 2246: pointer.ASN1_OBJECT */
            	2251, 0,
            0, 0, 1, /* 2251: ASN1_OBJECT */
            	2256, 0,
            0, 40, 3, /* 2256: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	891, 24,
            1, 8, 1, /* 2265: pointer.struct.asn1_string_st */
            	2204, 0,
            0, 32, 1, /* 2270: struct.stack_st_void */
            	2275, 0,
            0, 32, 2, /* 2275: struct.stack_st */
            	188, 8,
            	193, 24,
            0, 24, 1, /* 2282: struct.ASN1_ENCODING_st */
            	158, 0,
            1, 8, 1, /* 2287: pointer.struct.stack_st_X509_EXTENSION */
            	2292, 0,
            0, 32, 2, /* 2292: struct.stack_st_fake_X509_EXTENSION */
            	2299, 8,
            	193, 24,
            8884099, 8, 2, /* 2299: pointer_to_array_of_pointers_to_stack */
            	2306, 0,
            	33, 20,
            0, 8, 1, /* 2306: pointer.X509_EXTENSION */
            	2311, 0,
            0, 0, 1, /* 2311: X509_EXTENSION */
            	2316, 0,
            0, 24, 2, /* 2316: struct.X509_extension_st */
            	2323, 0,
            	2337, 16,
            1, 8, 1, /* 2323: pointer.struct.asn1_object_st */
            	2328, 0,
            0, 40, 3, /* 2328: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	891, 24,
            1, 8, 1, /* 2337: pointer.struct.asn1_string_st */
            	2342, 0,
            0, 24, 1, /* 2342: struct.asn1_string_st */
            	158, 8,
            1, 8, 1, /* 2347: pointer.struct.X509_pubkey_st */
            	2352, 0,
            0, 24, 3, /* 2352: struct.X509_pubkey_st */
            	2361, 0,
            	2366, 8,
            	2376, 16,
            1, 8, 1, /* 2361: pointer.struct.X509_algor_st */
            	2045, 0,
            1, 8, 1, /* 2366: pointer.struct.asn1_string_st */
            	2371, 0,
            0, 24, 1, /* 2371: struct.asn1_string_st */
            	158, 8,
            1, 8, 1, /* 2376: pointer.struct.evp_pkey_st */
            	2381, 0,
            0, 56, 4, /* 2381: struct.evp_pkey_st */
            	2392, 16,
            	2397, 24,
            	2402, 32,
            	2435, 48,
            1, 8, 1, /* 2392: pointer.struct.evp_pkey_asn1_method_st */
            	1915, 0,
            1, 8, 1, /* 2397: pointer.struct.engine_st */
            	237, 0,
            0, 8, 5, /* 2402: union.unknown */
            	84, 0,
            	2415, 0,
            	2420, 0,
            	2425, 0,
            	2430, 0,
            1, 8, 1, /* 2415: pointer.struct.rsa_st */
            	585, 0,
            1, 8, 1, /* 2420: pointer.struct.dsa_st */
            	1253, 0,
            1, 8, 1, /* 2425: pointer.struct.dh_st */
            	100, 0,
            1, 8, 1, /* 2430: pointer.struct.ec_key_st */
            	1392, 0,
            1, 8, 1, /* 2435: pointer.struct.stack_st_X509_ATTRIBUTE */
            	2440, 0,
            0, 32, 2, /* 2440: struct.stack_st_fake_X509_ATTRIBUTE */
            	2447, 8,
            	193, 24,
            8884099, 8, 2, /* 2447: pointer_to_array_of_pointers_to_stack */
            	2454, 0,
            	33, 20,
            0, 8, 1, /* 2454: pointer.X509_ATTRIBUTE */
            	865, 0,
            1, 8, 1, /* 2459: pointer.struct.X509_val_st */
            	2464, 0,
            0, 16, 2, /* 2464: struct.X509_val_st */
            	2471, 0,
            	2471, 8,
            1, 8, 1, /* 2471: pointer.struct.asn1_string_st */
            	2204, 0,
            1, 8, 1, /* 2476: pointer.struct.buf_mem_st */
            	2481, 0,
            0, 24, 1, /* 2481: struct.buf_mem_st */
            	84, 8,
            1, 8, 1, /* 2486: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2491, 0,
            0, 32, 2, /* 2491: struct.stack_st_fake_X509_NAME_ENTRY */
            	2498, 8,
            	193, 24,
            8884099, 8, 2, /* 2498: pointer_to_array_of_pointers_to_stack */
            	2505, 0,
            	33, 20,
            0, 8, 1, /* 2505: pointer.X509_NAME_ENTRY */
            	2510, 0,
            0, 0, 1, /* 2510: X509_NAME_ENTRY */
            	2515, 0,
            0, 24, 2, /* 2515: struct.X509_name_entry_st */
            	2522, 0,
            	2536, 8,
            1, 8, 1, /* 2522: pointer.struct.asn1_object_st */
            	2527, 0,
            0, 40, 3, /* 2527: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	891, 24,
            1, 8, 1, /* 2536: pointer.struct.asn1_string_st */
            	2541, 0,
            0, 24, 1, /* 2541: struct.asn1_string_st */
            	158, 8,
            0, 24, 1, /* 2546: struct.ssl3_buf_freelist_st */
            	2551, 16,
            1, 8, 1, /* 2551: pointer.struct.ssl3_buf_freelist_entry_st */
            	2556, 0,
            0, 8, 1, /* 2556: struct.ssl3_buf_freelist_entry_st */
            	2551, 0,
            1, 8, 1, /* 2561: pointer.struct.X509_name_st */
            	2566, 0,
            0, 40, 3, /* 2566: struct.X509_name_st */
            	2486, 0,
            	2476, 16,
            	158, 24,
            8884097, 8, 0, /* 2575: pointer.func */
            1, 8, 1, /* 2578: pointer.struct.asn1_string_st */
            	2204, 0,
            0, 104, 11, /* 2583: struct.x509_cinf_st */
            	2578, 0,
            	2578, 8,
            	2608, 16,
            	2561, 24,
            	2459, 32,
            	2561, 40,
            	2347, 48,
            	2613, 56,
            	2613, 64,
            	2287, 72,
            	2282, 80,
            1, 8, 1, /* 2608: pointer.struct.X509_algor_st */
            	2045, 0,
            1, 8, 1, /* 2613: pointer.struct.asn1_string_st */
            	2204, 0,
            1, 8, 1, /* 2618: pointer.struct.cert_st */
            	2623, 0,
            0, 296, 7, /* 2623: struct.cert_st */
            	2640, 0,
            	580, 48,
            	3921, 56,
            	95, 64,
            	92, 72,
            	3924, 80,
            	3929, 88,
            1, 8, 1, /* 2640: pointer.struct.cert_pkey_st */
            	2645, 0,
            0, 24, 3, /* 2645: struct.cert_pkey_st */
            	2654, 0,
            	3916, 8,
            	802, 16,
            1, 8, 1, /* 2654: pointer.struct.x509_st */
            	2659, 0,
            0, 184, 12, /* 2659: struct.x509_st */
            	2686, 0,
            	2608, 8,
            	2613, 16,
            	84, 32,
            	2691, 40,
            	2265, 104,
            	2701, 112,
            	3024, 120,
            	3441, 128,
            	3580, 136,
            	3604, 144,
            	2209, 176,
            1, 8, 1, /* 2686: pointer.struct.x509_cinf_st */
            	2583, 0,
            0, 16, 1, /* 2691: struct.crypto_ex_data_st */
            	2696, 0,
            1, 8, 1, /* 2696: pointer.struct.stack_st_void */
            	2270, 0,
            1, 8, 1, /* 2701: pointer.struct.AUTHORITY_KEYID_st */
            	2706, 0,
            0, 24, 3, /* 2706: struct.AUTHORITY_KEYID_st */
            	2715, 0,
            	2725, 8,
            	3019, 16,
            1, 8, 1, /* 2715: pointer.struct.asn1_string_st */
            	2720, 0,
            0, 24, 1, /* 2720: struct.asn1_string_st */
            	158, 8,
            1, 8, 1, /* 2725: pointer.struct.stack_st_GENERAL_NAME */
            	2730, 0,
            0, 32, 2, /* 2730: struct.stack_st_fake_GENERAL_NAME */
            	2737, 8,
            	193, 24,
            8884099, 8, 2, /* 2737: pointer_to_array_of_pointers_to_stack */
            	2744, 0,
            	33, 20,
            0, 8, 1, /* 2744: pointer.GENERAL_NAME */
            	2749, 0,
            0, 0, 1, /* 2749: GENERAL_NAME */
            	2754, 0,
            0, 16, 1, /* 2754: struct.GENERAL_NAME_st */
            	2759, 8,
            0, 8, 15, /* 2759: union.unknown */
            	84, 0,
            	2792, 0,
            	2911, 0,
            	2911, 0,
            	2818, 0,
            	2959, 0,
            	3007, 0,
            	2911, 0,
            	2896, 0,
            	2804, 0,
            	2896, 0,
            	2959, 0,
            	2911, 0,
            	2804, 0,
            	2818, 0,
            1, 8, 1, /* 2792: pointer.struct.otherName_st */
            	2797, 0,
            0, 16, 2, /* 2797: struct.otherName_st */
            	2804, 0,
            	2818, 8,
            1, 8, 1, /* 2804: pointer.struct.asn1_object_st */
            	2809, 0,
            0, 40, 3, /* 2809: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	891, 24,
            1, 8, 1, /* 2818: pointer.struct.asn1_type_st */
            	2823, 0,
            0, 16, 1, /* 2823: struct.asn1_type_st */
            	2828, 8,
            0, 8, 20, /* 2828: union.unknown */
            	84, 0,
            	2871, 0,
            	2804, 0,
            	2881, 0,
            	2886, 0,
            	2891, 0,
            	2896, 0,
            	2901, 0,
            	2906, 0,
            	2911, 0,
            	2916, 0,
            	2921, 0,
            	2926, 0,
            	2931, 0,
            	2936, 0,
            	2941, 0,
            	2946, 0,
            	2871, 0,
            	2871, 0,
            	2951, 0,
            1, 8, 1, /* 2871: pointer.struct.asn1_string_st */
            	2876, 0,
            0, 24, 1, /* 2876: struct.asn1_string_st */
            	158, 8,
            1, 8, 1, /* 2881: pointer.struct.asn1_string_st */
            	2876, 0,
            1, 8, 1, /* 2886: pointer.struct.asn1_string_st */
            	2876, 0,
            1, 8, 1, /* 2891: pointer.struct.asn1_string_st */
            	2876, 0,
            1, 8, 1, /* 2896: pointer.struct.asn1_string_st */
            	2876, 0,
            1, 8, 1, /* 2901: pointer.struct.asn1_string_st */
            	2876, 0,
            1, 8, 1, /* 2906: pointer.struct.asn1_string_st */
            	2876, 0,
            1, 8, 1, /* 2911: pointer.struct.asn1_string_st */
            	2876, 0,
            1, 8, 1, /* 2916: pointer.struct.asn1_string_st */
            	2876, 0,
            1, 8, 1, /* 2921: pointer.struct.asn1_string_st */
            	2876, 0,
            1, 8, 1, /* 2926: pointer.struct.asn1_string_st */
            	2876, 0,
            1, 8, 1, /* 2931: pointer.struct.asn1_string_st */
            	2876, 0,
            1, 8, 1, /* 2936: pointer.struct.asn1_string_st */
            	2876, 0,
            1, 8, 1, /* 2941: pointer.struct.asn1_string_st */
            	2876, 0,
            1, 8, 1, /* 2946: pointer.struct.asn1_string_st */
            	2876, 0,
            1, 8, 1, /* 2951: pointer.struct.ASN1_VALUE_st */
            	2956, 0,
            0, 0, 0, /* 2956: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2959: pointer.struct.X509_name_st */
            	2964, 0,
            0, 40, 3, /* 2964: struct.X509_name_st */
            	2973, 0,
            	2997, 16,
            	158, 24,
            1, 8, 1, /* 2973: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2978, 0,
            0, 32, 2, /* 2978: struct.stack_st_fake_X509_NAME_ENTRY */
            	2985, 8,
            	193, 24,
            8884099, 8, 2, /* 2985: pointer_to_array_of_pointers_to_stack */
            	2992, 0,
            	33, 20,
            0, 8, 1, /* 2992: pointer.X509_NAME_ENTRY */
            	2510, 0,
            1, 8, 1, /* 2997: pointer.struct.buf_mem_st */
            	3002, 0,
            0, 24, 1, /* 3002: struct.buf_mem_st */
            	84, 8,
            1, 8, 1, /* 3007: pointer.struct.EDIPartyName_st */
            	3012, 0,
            0, 16, 2, /* 3012: struct.EDIPartyName_st */
            	2871, 0,
            	2871, 8,
            1, 8, 1, /* 3019: pointer.struct.asn1_string_st */
            	2720, 0,
            1, 8, 1, /* 3024: pointer.struct.X509_POLICY_CACHE_st */
            	3029, 0,
            0, 40, 2, /* 3029: struct.X509_POLICY_CACHE_st */
            	3036, 0,
            	3341, 8,
            1, 8, 1, /* 3036: pointer.struct.X509_POLICY_DATA_st */
            	3041, 0,
            0, 32, 3, /* 3041: struct.X509_POLICY_DATA_st */
            	3050, 8,
            	3064, 16,
            	3317, 24,
            1, 8, 1, /* 3050: pointer.struct.asn1_object_st */
            	3055, 0,
            0, 40, 3, /* 3055: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	891, 24,
            1, 8, 1, /* 3064: pointer.struct.stack_st_POLICYQUALINFO */
            	3069, 0,
            0, 32, 2, /* 3069: struct.stack_st_fake_POLICYQUALINFO */
            	3076, 8,
            	193, 24,
            8884099, 8, 2, /* 3076: pointer_to_array_of_pointers_to_stack */
            	3083, 0,
            	33, 20,
            0, 8, 1, /* 3083: pointer.POLICYQUALINFO */
            	3088, 0,
            0, 0, 1, /* 3088: POLICYQUALINFO */
            	3093, 0,
            0, 16, 2, /* 3093: struct.POLICYQUALINFO_st */
            	3100, 0,
            	3114, 8,
            1, 8, 1, /* 3100: pointer.struct.asn1_object_st */
            	3105, 0,
            0, 40, 3, /* 3105: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	891, 24,
            0, 8, 3, /* 3114: union.unknown */
            	3123, 0,
            	3133, 0,
            	3191, 0,
            1, 8, 1, /* 3123: pointer.struct.asn1_string_st */
            	3128, 0,
            0, 24, 1, /* 3128: struct.asn1_string_st */
            	158, 8,
            1, 8, 1, /* 3133: pointer.struct.USERNOTICE_st */
            	3138, 0,
            0, 16, 2, /* 3138: struct.USERNOTICE_st */
            	3145, 0,
            	3157, 8,
            1, 8, 1, /* 3145: pointer.struct.NOTICEREF_st */
            	3150, 0,
            0, 16, 2, /* 3150: struct.NOTICEREF_st */
            	3157, 0,
            	3162, 8,
            1, 8, 1, /* 3157: pointer.struct.asn1_string_st */
            	3128, 0,
            1, 8, 1, /* 3162: pointer.struct.stack_st_ASN1_INTEGER */
            	3167, 0,
            0, 32, 2, /* 3167: struct.stack_st_fake_ASN1_INTEGER */
            	3174, 8,
            	193, 24,
            8884099, 8, 2, /* 3174: pointer_to_array_of_pointers_to_stack */
            	3181, 0,
            	33, 20,
            0, 8, 1, /* 3181: pointer.ASN1_INTEGER */
            	3186, 0,
            0, 0, 1, /* 3186: ASN1_INTEGER */
            	2124, 0,
            1, 8, 1, /* 3191: pointer.struct.asn1_type_st */
            	3196, 0,
            0, 16, 1, /* 3196: struct.asn1_type_st */
            	3201, 8,
            0, 8, 20, /* 3201: union.unknown */
            	84, 0,
            	3157, 0,
            	3100, 0,
            	3244, 0,
            	3249, 0,
            	3254, 0,
            	3259, 0,
            	3264, 0,
            	3269, 0,
            	3123, 0,
            	3274, 0,
            	3279, 0,
            	3284, 0,
            	3289, 0,
            	3294, 0,
            	3299, 0,
            	3304, 0,
            	3157, 0,
            	3157, 0,
            	3309, 0,
            1, 8, 1, /* 3244: pointer.struct.asn1_string_st */
            	3128, 0,
            1, 8, 1, /* 3249: pointer.struct.asn1_string_st */
            	3128, 0,
            1, 8, 1, /* 3254: pointer.struct.asn1_string_st */
            	3128, 0,
            1, 8, 1, /* 3259: pointer.struct.asn1_string_st */
            	3128, 0,
            1, 8, 1, /* 3264: pointer.struct.asn1_string_st */
            	3128, 0,
            1, 8, 1, /* 3269: pointer.struct.asn1_string_st */
            	3128, 0,
            1, 8, 1, /* 3274: pointer.struct.asn1_string_st */
            	3128, 0,
            1, 8, 1, /* 3279: pointer.struct.asn1_string_st */
            	3128, 0,
            1, 8, 1, /* 3284: pointer.struct.asn1_string_st */
            	3128, 0,
            1, 8, 1, /* 3289: pointer.struct.asn1_string_st */
            	3128, 0,
            1, 8, 1, /* 3294: pointer.struct.asn1_string_st */
            	3128, 0,
            1, 8, 1, /* 3299: pointer.struct.asn1_string_st */
            	3128, 0,
            1, 8, 1, /* 3304: pointer.struct.asn1_string_st */
            	3128, 0,
            1, 8, 1, /* 3309: pointer.struct.ASN1_VALUE_st */
            	3314, 0,
            0, 0, 0, /* 3314: struct.ASN1_VALUE_st */
            1, 8, 1, /* 3317: pointer.struct.stack_st_ASN1_OBJECT */
            	3322, 0,
            0, 32, 2, /* 3322: struct.stack_st_fake_ASN1_OBJECT */
            	3329, 8,
            	193, 24,
            8884099, 8, 2, /* 3329: pointer_to_array_of_pointers_to_stack */
            	3336, 0,
            	33, 20,
            0, 8, 1, /* 3336: pointer.ASN1_OBJECT */
            	2251, 0,
            1, 8, 1, /* 3341: pointer.struct.stack_st_X509_POLICY_DATA */
            	3346, 0,
            0, 32, 2, /* 3346: struct.stack_st_fake_X509_POLICY_DATA */
            	3353, 8,
            	193, 24,
            8884099, 8, 2, /* 3353: pointer_to_array_of_pointers_to_stack */
            	3360, 0,
            	33, 20,
            0, 8, 1, /* 3360: pointer.X509_POLICY_DATA */
            	3365, 0,
            0, 0, 1, /* 3365: X509_POLICY_DATA */
            	3370, 0,
            0, 32, 3, /* 3370: struct.X509_POLICY_DATA_st */
            	3379, 8,
            	3393, 16,
            	3417, 24,
            1, 8, 1, /* 3379: pointer.struct.asn1_object_st */
            	3384, 0,
            0, 40, 3, /* 3384: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	891, 24,
            1, 8, 1, /* 3393: pointer.struct.stack_st_POLICYQUALINFO */
            	3398, 0,
            0, 32, 2, /* 3398: struct.stack_st_fake_POLICYQUALINFO */
            	3405, 8,
            	193, 24,
            8884099, 8, 2, /* 3405: pointer_to_array_of_pointers_to_stack */
            	3412, 0,
            	33, 20,
            0, 8, 1, /* 3412: pointer.POLICYQUALINFO */
            	3088, 0,
            1, 8, 1, /* 3417: pointer.struct.stack_st_ASN1_OBJECT */
            	3422, 0,
            0, 32, 2, /* 3422: struct.stack_st_fake_ASN1_OBJECT */
            	3429, 8,
            	193, 24,
            8884099, 8, 2, /* 3429: pointer_to_array_of_pointers_to_stack */
            	3436, 0,
            	33, 20,
            0, 8, 1, /* 3436: pointer.ASN1_OBJECT */
            	2251, 0,
            1, 8, 1, /* 3441: pointer.struct.stack_st_DIST_POINT */
            	3446, 0,
            0, 32, 2, /* 3446: struct.stack_st_fake_DIST_POINT */
            	3453, 8,
            	193, 24,
            8884099, 8, 2, /* 3453: pointer_to_array_of_pointers_to_stack */
            	3460, 0,
            	33, 20,
            0, 8, 1, /* 3460: pointer.DIST_POINT */
            	3465, 0,
            0, 0, 1, /* 3465: DIST_POINT */
            	3470, 0,
            0, 32, 3, /* 3470: struct.DIST_POINT_st */
            	3479, 0,
            	3570, 8,
            	3498, 16,
            1, 8, 1, /* 3479: pointer.struct.DIST_POINT_NAME_st */
            	3484, 0,
            0, 24, 2, /* 3484: struct.DIST_POINT_NAME_st */
            	3491, 8,
            	3546, 16,
            0, 8, 2, /* 3491: union.unknown */
            	3498, 0,
            	3522, 0,
            1, 8, 1, /* 3498: pointer.struct.stack_st_GENERAL_NAME */
            	3503, 0,
            0, 32, 2, /* 3503: struct.stack_st_fake_GENERAL_NAME */
            	3510, 8,
            	193, 24,
            8884099, 8, 2, /* 3510: pointer_to_array_of_pointers_to_stack */
            	3517, 0,
            	33, 20,
            0, 8, 1, /* 3517: pointer.GENERAL_NAME */
            	2749, 0,
            1, 8, 1, /* 3522: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3527, 0,
            0, 32, 2, /* 3527: struct.stack_st_fake_X509_NAME_ENTRY */
            	3534, 8,
            	193, 24,
            8884099, 8, 2, /* 3534: pointer_to_array_of_pointers_to_stack */
            	3541, 0,
            	33, 20,
            0, 8, 1, /* 3541: pointer.X509_NAME_ENTRY */
            	2510, 0,
            1, 8, 1, /* 3546: pointer.struct.X509_name_st */
            	3551, 0,
            0, 40, 3, /* 3551: struct.X509_name_st */
            	3522, 0,
            	3560, 16,
            	158, 24,
            1, 8, 1, /* 3560: pointer.struct.buf_mem_st */
            	3565, 0,
            0, 24, 1, /* 3565: struct.buf_mem_st */
            	84, 8,
            1, 8, 1, /* 3570: pointer.struct.asn1_string_st */
            	3575, 0,
            0, 24, 1, /* 3575: struct.asn1_string_st */
            	158, 8,
            1, 8, 1, /* 3580: pointer.struct.stack_st_GENERAL_NAME */
            	3585, 0,
            0, 32, 2, /* 3585: struct.stack_st_fake_GENERAL_NAME */
            	3592, 8,
            	193, 24,
            8884099, 8, 2, /* 3592: pointer_to_array_of_pointers_to_stack */
            	3599, 0,
            	33, 20,
            0, 8, 1, /* 3599: pointer.GENERAL_NAME */
            	2749, 0,
            1, 8, 1, /* 3604: pointer.struct.NAME_CONSTRAINTS_st */
            	3609, 0,
            0, 16, 2, /* 3609: struct.NAME_CONSTRAINTS_st */
            	3616, 0,
            	3616, 8,
            1, 8, 1, /* 3616: pointer.struct.stack_st_GENERAL_SUBTREE */
            	3621, 0,
            0, 32, 2, /* 3621: struct.stack_st_fake_GENERAL_SUBTREE */
            	3628, 8,
            	193, 24,
            8884099, 8, 2, /* 3628: pointer_to_array_of_pointers_to_stack */
            	3635, 0,
            	33, 20,
            0, 8, 1, /* 3635: pointer.GENERAL_SUBTREE */
            	3640, 0,
            0, 0, 1, /* 3640: GENERAL_SUBTREE */
            	3645, 0,
            0, 24, 3, /* 3645: struct.GENERAL_SUBTREE_st */
            	3654, 0,
            	3786, 8,
            	3786, 16,
            1, 8, 1, /* 3654: pointer.struct.GENERAL_NAME_st */
            	3659, 0,
            0, 16, 1, /* 3659: struct.GENERAL_NAME_st */
            	3664, 8,
            0, 8, 15, /* 3664: union.unknown */
            	84, 0,
            	3697, 0,
            	3816, 0,
            	3816, 0,
            	3723, 0,
            	3856, 0,
            	3904, 0,
            	3816, 0,
            	3801, 0,
            	3709, 0,
            	3801, 0,
            	3856, 0,
            	3816, 0,
            	3709, 0,
            	3723, 0,
            1, 8, 1, /* 3697: pointer.struct.otherName_st */
            	3702, 0,
            0, 16, 2, /* 3702: struct.otherName_st */
            	3709, 0,
            	3723, 8,
            1, 8, 1, /* 3709: pointer.struct.asn1_object_st */
            	3714, 0,
            0, 40, 3, /* 3714: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	891, 24,
            1, 8, 1, /* 3723: pointer.struct.asn1_type_st */
            	3728, 0,
            0, 16, 1, /* 3728: struct.asn1_type_st */
            	3733, 8,
            0, 8, 20, /* 3733: union.unknown */
            	84, 0,
            	3776, 0,
            	3709, 0,
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
            	3846, 0,
            	3851, 0,
            	3776, 0,
            	3776, 0,
            	3309, 0,
            1, 8, 1, /* 3776: pointer.struct.asn1_string_st */
            	3781, 0,
            0, 24, 1, /* 3781: struct.asn1_string_st */
            	158, 8,
            1, 8, 1, /* 3786: pointer.struct.asn1_string_st */
            	3781, 0,
            1, 8, 1, /* 3791: pointer.struct.asn1_string_st */
            	3781, 0,
            1, 8, 1, /* 3796: pointer.struct.asn1_string_st */
            	3781, 0,
            1, 8, 1, /* 3801: pointer.struct.asn1_string_st */
            	3781, 0,
            1, 8, 1, /* 3806: pointer.struct.asn1_string_st */
            	3781, 0,
            1, 8, 1, /* 3811: pointer.struct.asn1_string_st */
            	3781, 0,
            1, 8, 1, /* 3816: pointer.struct.asn1_string_st */
            	3781, 0,
            1, 8, 1, /* 3821: pointer.struct.asn1_string_st */
            	3781, 0,
            1, 8, 1, /* 3826: pointer.struct.asn1_string_st */
            	3781, 0,
            1, 8, 1, /* 3831: pointer.struct.asn1_string_st */
            	3781, 0,
            1, 8, 1, /* 3836: pointer.struct.asn1_string_st */
            	3781, 0,
            1, 8, 1, /* 3841: pointer.struct.asn1_string_st */
            	3781, 0,
            1, 8, 1, /* 3846: pointer.struct.asn1_string_st */
            	3781, 0,
            1, 8, 1, /* 3851: pointer.struct.asn1_string_st */
            	3781, 0,
            1, 8, 1, /* 3856: pointer.struct.X509_name_st */
            	3861, 0,
            0, 40, 3, /* 3861: struct.X509_name_st */
            	3870, 0,
            	3894, 16,
            	158, 24,
            1, 8, 1, /* 3870: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3875, 0,
            0, 32, 2, /* 3875: struct.stack_st_fake_X509_NAME_ENTRY */
            	3882, 8,
            	193, 24,
            8884099, 8, 2, /* 3882: pointer_to_array_of_pointers_to_stack */
            	3889, 0,
            	33, 20,
            0, 8, 1, /* 3889: pointer.X509_NAME_ENTRY */
            	2510, 0,
            1, 8, 1, /* 3894: pointer.struct.buf_mem_st */
            	3899, 0,
            0, 24, 1, /* 3899: struct.buf_mem_st */
            	84, 8,
            1, 8, 1, /* 3904: pointer.struct.EDIPartyName_st */
            	3909, 0,
            0, 16, 2, /* 3909: struct.EDIPartyName_st */
            	3776, 0,
            	3776, 8,
            1, 8, 1, /* 3916: pointer.struct.evp_pkey_st */
            	1899, 0,
            8884097, 8, 0, /* 3921: pointer.func */
            1, 8, 1, /* 3924: pointer.struct.ec_key_st */
            	1392, 0,
            8884097, 8, 0, /* 3929: pointer.func */
            0, 24, 1, /* 3932: struct.buf_mem_st */
            	84, 8,
            1, 8, 1, /* 3937: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3942, 0,
            0, 32, 2, /* 3942: struct.stack_st_fake_X509_NAME_ENTRY */
            	3949, 8,
            	193, 24,
            8884099, 8, 2, /* 3949: pointer_to_array_of_pointers_to_stack */
            	3956, 0,
            	33, 20,
            0, 8, 1, /* 3956: pointer.X509_NAME_ENTRY */
            	2510, 0,
            0, 0, 1, /* 3961: X509_NAME */
            	3966, 0,
            0, 40, 3, /* 3966: struct.X509_name_st */
            	3937, 0,
            	3975, 16,
            	158, 24,
            1, 8, 1, /* 3975: pointer.struct.buf_mem_st */
            	3932, 0,
            1, 8, 1, /* 3980: pointer.struct.stack_st_X509_NAME */
            	3985, 0,
            0, 32, 2, /* 3985: struct.stack_st_fake_X509_NAME */
            	3992, 8,
            	193, 24,
            8884099, 8, 2, /* 3992: pointer_to_array_of_pointers_to_stack */
            	3999, 0,
            	33, 20,
            0, 8, 1, /* 3999: pointer.X509_NAME */
            	3961, 0,
            8884097, 8, 0, /* 4004: pointer.func */
            8884097, 8, 0, /* 4007: pointer.func */
            8884097, 8, 0, /* 4010: pointer.func */
            8884097, 8, 0, /* 4013: pointer.func */
            0, 64, 7, /* 4016: struct.comp_method_st */
            	5, 8,
            	4013, 16,
            	4010, 24,
            	4007, 32,
            	4007, 40,
            	4033, 48,
            	4033, 56,
            8884097, 8, 0, /* 4033: pointer.func */
            1, 8, 1, /* 4036: pointer.struct.comp_method_st */
            	4016, 0,
            0, 0, 1, /* 4041: SSL_COMP */
            	4046, 0,
            0, 24, 2, /* 4046: struct.ssl_comp_st */
            	5, 8,
            	4036, 16,
            1, 8, 1, /* 4053: pointer.struct.stack_st_SSL_COMP */
            	4058, 0,
            0, 32, 2, /* 4058: struct.stack_st_fake_SSL_COMP */
            	4065, 8,
            	193, 24,
            8884099, 8, 2, /* 4065: pointer_to_array_of_pointers_to_stack */
            	4072, 0,
            	33, 20,
            0, 8, 1, /* 4072: pointer.SSL_COMP */
            	4041, 0,
            1, 8, 1, /* 4077: pointer.struct.stack_st_X509 */
            	4082, 0,
            0, 32, 2, /* 4082: struct.stack_st_fake_X509 */
            	4089, 8,
            	193, 24,
            8884099, 8, 2, /* 4089: pointer_to_array_of_pointers_to_stack */
            	4096, 0,
            	33, 20,
            0, 8, 1, /* 4096: pointer.X509 */
            	4101, 0,
            0, 0, 1, /* 4101: X509 */
            	4106, 0,
            0, 184, 12, /* 4106: struct.x509_st */
            	4133, 0,
            	4173, 8,
            	4248, 16,
            	84, 32,
            	4282, 40,
            	4304, 104,
            	4309, 112,
            	4314, 120,
            	4319, 128,
            	4343, 136,
            	4367, 144,
            	4372, 176,
            1, 8, 1, /* 4133: pointer.struct.x509_cinf_st */
            	4138, 0,
            0, 104, 11, /* 4138: struct.x509_cinf_st */
            	4163, 0,
            	4163, 8,
            	4173, 16,
            	4178, 24,
            	4226, 32,
            	4178, 40,
            	4243, 48,
            	4248, 56,
            	4248, 64,
            	4253, 72,
            	4277, 80,
            1, 8, 1, /* 4163: pointer.struct.asn1_string_st */
            	4168, 0,
            0, 24, 1, /* 4168: struct.asn1_string_st */
            	158, 8,
            1, 8, 1, /* 4173: pointer.struct.X509_algor_st */
            	2045, 0,
            1, 8, 1, /* 4178: pointer.struct.X509_name_st */
            	4183, 0,
            0, 40, 3, /* 4183: struct.X509_name_st */
            	4192, 0,
            	4216, 16,
            	158, 24,
            1, 8, 1, /* 4192: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4197, 0,
            0, 32, 2, /* 4197: struct.stack_st_fake_X509_NAME_ENTRY */
            	4204, 8,
            	193, 24,
            8884099, 8, 2, /* 4204: pointer_to_array_of_pointers_to_stack */
            	4211, 0,
            	33, 20,
            0, 8, 1, /* 4211: pointer.X509_NAME_ENTRY */
            	2510, 0,
            1, 8, 1, /* 4216: pointer.struct.buf_mem_st */
            	4221, 0,
            0, 24, 1, /* 4221: struct.buf_mem_st */
            	84, 8,
            1, 8, 1, /* 4226: pointer.struct.X509_val_st */
            	4231, 0,
            0, 16, 2, /* 4231: struct.X509_val_st */
            	4238, 0,
            	4238, 8,
            1, 8, 1, /* 4238: pointer.struct.asn1_string_st */
            	4168, 0,
            1, 8, 1, /* 4243: pointer.struct.X509_pubkey_st */
            	2352, 0,
            1, 8, 1, /* 4248: pointer.struct.asn1_string_st */
            	4168, 0,
            1, 8, 1, /* 4253: pointer.struct.stack_st_X509_EXTENSION */
            	4258, 0,
            0, 32, 2, /* 4258: struct.stack_st_fake_X509_EXTENSION */
            	4265, 8,
            	193, 24,
            8884099, 8, 2, /* 4265: pointer_to_array_of_pointers_to_stack */
            	4272, 0,
            	33, 20,
            0, 8, 1, /* 4272: pointer.X509_EXTENSION */
            	2311, 0,
            0, 24, 1, /* 4277: struct.ASN1_ENCODING_st */
            	158, 0,
            0, 16, 1, /* 4282: struct.crypto_ex_data_st */
            	4287, 0,
            1, 8, 1, /* 4287: pointer.struct.stack_st_void */
            	4292, 0,
            0, 32, 1, /* 4292: struct.stack_st_void */
            	4297, 0,
            0, 32, 2, /* 4297: struct.stack_st */
            	188, 8,
            	193, 24,
            1, 8, 1, /* 4304: pointer.struct.asn1_string_st */
            	4168, 0,
            1, 8, 1, /* 4309: pointer.struct.AUTHORITY_KEYID_st */
            	2706, 0,
            1, 8, 1, /* 4314: pointer.struct.X509_POLICY_CACHE_st */
            	3029, 0,
            1, 8, 1, /* 4319: pointer.struct.stack_st_DIST_POINT */
            	4324, 0,
            0, 32, 2, /* 4324: struct.stack_st_fake_DIST_POINT */
            	4331, 8,
            	193, 24,
            8884099, 8, 2, /* 4331: pointer_to_array_of_pointers_to_stack */
            	4338, 0,
            	33, 20,
            0, 8, 1, /* 4338: pointer.DIST_POINT */
            	3465, 0,
            1, 8, 1, /* 4343: pointer.struct.stack_st_GENERAL_NAME */
            	4348, 0,
            0, 32, 2, /* 4348: struct.stack_st_fake_GENERAL_NAME */
            	4355, 8,
            	193, 24,
            8884099, 8, 2, /* 4355: pointer_to_array_of_pointers_to_stack */
            	4362, 0,
            	33, 20,
            0, 8, 1, /* 4362: pointer.GENERAL_NAME */
            	2749, 0,
            1, 8, 1, /* 4367: pointer.struct.NAME_CONSTRAINTS_st */
            	3609, 0,
            1, 8, 1, /* 4372: pointer.struct.x509_cert_aux_st */
            	4377, 0,
            0, 40, 5, /* 4377: struct.x509_cert_aux_st */
            	4390, 0,
            	4390, 8,
            	4414, 16,
            	4304, 24,
            	4419, 32,
            1, 8, 1, /* 4390: pointer.struct.stack_st_ASN1_OBJECT */
            	4395, 0,
            0, 32, 2, /* 4395: struct.stack_st_fake_ASN1_OBJECT */
            	4402, 8,
            	193, 24,
            8884099, 8, 2, /* 4402: pointer_to_array_of_pointers_to_stack */
            	4409, 0,
            	33, 20,
            0, 8, 1, /* 4409: pointer.ASN1_OBJECT */
            	2251, 0,
            1, 8, 1, /* 4414: pointer.struct.asn1_string_st */
            	4168, 0,
            1, 8, 1, /* 4419: pointer.struct.stack_st_X509_ALGOR */
            	4424, 0,
            0, 32, 2, /* 4424: struct.stack_st_fake_X509_ALGOR */
            	4431, 8,
            	193, 24,
            8884099, 8, 2, /* 4431: pointer_to_array_of_pointers_to_stack */
            	4438, 0,
            	33, 20,
            0, 8, 1, /* 4438: pointer.X509_ALGOR */
            	2040, 0,
            8884097, 8, 0, /* 4443: pointer.func */
            8884097, 8, 0, /* 4446: pointer.func */
            8884097, 8, 0, /* 4449: pointer.func */
            0, 120, 8, /* 4452: struct.env_md_st */
            	4449, 24,
            	4471, 32,
            	4446, 40,
            	4443, 48,
            	4449, 56,
            	832, 64,
            	835, 72,
            	4474, 112,
            8884097, 8, 0, /* 4471: pointer.func */
            8884097, 8, 0, /* 4474: pointer.func */
            8884097, 8, 0, /* 4477: pointer.func */
            8884097, 8, 0, /* 4480: pointer.func */
            8884097, 8, 0, /* 4483: pointer.func */
            8884097, 8, 0, /* 4486: pointer.func */
            0, 88, 1, /* 4489: struct.ssl_cipher_st */
            	5, 8,
            0, 40, 5, /* 4494: struct.x509_cert_aux_st */
            	4507, 0,
            	4507, 8,
            	4531, 16,
            	4541, 24,
            	4546, 32,
            1, 8, 1, /* 4507: pointer.struct.stack_st_ASN1_OBJECT */
            	4512, 0,
            0, 32, 2, /* 4512: struct.stack_st_fake_ASN1_OBJECT */
            	4519, 8,
            	193, 24,
            8884099, 8, 2, /* 4519: pointer_to_array_of_pointers_to_stack */
            	4526, 0,
            	33, 20,
            0, 8, 1, /* 4526: pointer.ASN1_OBJECT */
            	2251, 0,
            1, 8, 1, /* 4531: pointer.struct.asn1_string_st */
            	4536, 0,
            0, 24, 1, /* 4536: struct.asn1_string_st */
            	158, 8,
            1, 8, 1, /* 4541: pointer.struct.asn1_string_st */
            	4536, 0,
            1, 8, 1, /* 4546: pointer.struct.stack_st_X509_ALGOR */
            	4551, 0,
            0, 32, 2, /* 4551: struct.stack_st_fake_X509_ALGOR */
            	4558, 8,
            	193, 24,
            8884099, 8, 2, /* 4558: pointer_to_array_of_pointers_to_stack */
            	4565, 0,
            	33, 20,
            0, 8, 1, /* 4565: pointer.X509_ALGOR */
            	2040, 0,
            1, 8, 1, /* 4570: pointer.struct.x509_cert_aux_st */
            	4494, 0,
            1, 8, 1, /* 4575: pointer.struct.NAME_CONSTRAINTS_st */
            	3609, 0,
            1, 8, 1, /* 4580: pointer.struct.stack_st_GENERAL_NAME */
            	4585, 0,
            0, 32, 2, /* 4585: struct.stack_st_fake_GENERAL_NAME */
            	4592, 8,
            	193, 24,
            8884099, 8, 2, /* 4592: pointer_to_array_of_pointers_to_stack */
            	4599, 0,
            	33, 20,
            0, 8, 1, /* 4599: pointer.GENERAL_NAME */
            	2749, 0,
            1, 8, 1, /* 4604: pointer.struct.stack_st_DIST_POINT */
            	4609, 0,
            0, 32, 2, /* 4609: struct.stack_st_fake_DIST_POINT */
            	4616, 8,
            	193, 24,
            8884099, 8, 2, /* 4616: pointer_to_array_of_pointers_to_stack */
            	4623, 0,
            	33, 20,
            0, 8, 1, /* 4623: pointer.DIST_POINT */
            	3465, 0,
            0, 24, 1, /* 4628: struct.ASN1_ENCODING_st */
            	158, 0,
            1, 8, 1, /* 4633: pointer.struct.stack_st_X509_EXTENSION */
            	4638, 0,
            0, 32, 2, /* 4638: struct.stack_st_fake_X509_EXTENSION */
            	4645, 8,
            	193, 24,
            8884099, 8, 2, /* 4645: pointer_to_array_of_pointers_to_stack */
            	4652, 0,
            	33, 20,
            0, 8, 1, /* 4652: pointer.X509_EXTENSION */
            	2311, 0,
            1, 8, 1, /* 4657: pointer.struct.X509_pubkey_st */
            	2352, 0,
            1, 8, 1, /* 4662: pointer.struct.asn1_string_st */
            	4536, 0,
            0, 16, 2, /* 4667: struct.X509_val_st */
            	4662, 0,
            	4662, 8,
            1, 8, 1, /* 4674: pointer.struct.X509_val_st */
            	4667, 0,
            1, 8, 1, /* 4679: pointer.struct.X509_algor_st */
            	2045, 0,
            1, 8, 1, /* 4684: pointer.struct.asn1_string_st */
            	4536, 0,
            0, 104, 11, /* 4689: struct.x509_cinf_st */
            	4684, 0,
            	4684, 8,
            	4679, 16,
            	4714, 24,
            	4674, 32,
            	4714, 40,
            	4657, 48,
            	4762, 56,
            	4762, 64,
            	4633, 72,
            	4628, 80,
            1, 8, 1, /* 4714: pointer.struct.X509_name_st */
            	4719, 0,
            0, 40, 3, /* 4719: struct.X509_name_st */
            	4728, 0,
            	4752, 16,
            	158, 24,
            1, 8, 1, /* 4728: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4733, 0,
            0, 32, 2, /* 4733: struct.stack_st_fake_X509_NAME_ENTRY */
            	4740, 8,
            	193, 24,
            8884099, 8, 2, /* 4740: pointer_to_array_of_pointers_to_stack */
            	4747, 0,
            	33, 20,
            0, 8, 1, /* 4747: pointer.X509_NAME_ENTRY */
            	2510, 0,
            1, 8, 1, /* 4752: pointer.struct.buf_mem_st */
            	4757, 0,
            0, 24, 1, /* 4757: struct.buf_mem_st */
            	84, 8,
            1, 8, 1, /* 4762: pointer.struct.asn1_string_st */
            	4536, 0,
            1, 8, 1, /* 4767: pointer.struct.dh_st */
            	100, 0,
            8884097, 8, 0, /* 4772: pointer.func */
            8884097, 8, 0, /* 4775: pointer.func */
            0, 120, 8, /* 4778: struct.env_md_st */
            	4797, 24,
            	4800, 32,
            	4775, 40,
            	4803, 48,
            	4797, 56,
            	832, 64,
            	835, 72,
            	4772, 112,
            8884097, 8, 0, /* 4797: pointer.func */
            8884097, 8, 0, /* 4800: pointer.func */
            8884097, 8, 0, /* 4803: pointer.func */
            1, 8, 1, /* 4806: pointer.struct.dsa_st */
            	1253, 0,
            1, 8, 1, /* 4811: pointer.struct.rsa_st */
            	585, 0,
            0, 8, 5, /* 4816: union.unknown */
            	84, 0,
            	4811, 0,
            	4806, 0,
            	4829, 0,
            	1387, 0,
            1, 8, 1, /* 4829: pointer.struct.dh_st */
            	100, 0,
            0, 56, 4, /* 4834: struct.evp_pkey_st */
            	1910, 16,
            	2011, 24,
            	4816, 32,
            	4845, 48,
            1, 8, 1, /* 4845: pointer.struct.stack_st_X509_ATTRIBUTE */
            	4850, 0,
            0, 32, 2, /* 4850: struct.stack_st_fake_X509_ATTRIBUTE */
            	4857, 8,
            	193, 24,
            8884099, 8, 2, /* 4857: pointer_to_array_of_pointers_to_stack */
            	4864, 0,
            	33, 20,
            0, 8, 1, /* 4864: pointer.X509_ATTRIBUTE */
            	865, 0,
            1, 8, 1, /* 4869: pointer.struct.asn1_string_st */
            	4874, 0,
            0, 24, 1, /* 4874: struct.asn1_string_st */
            	158, 8,
            0, 40, 5, /* 4879: struct.x509_cert_aux_st */
            	4892, 0,
            	4892, 8,
            	4869, 16,
            	4916, 24,
            	4921, 32,
            1, 8, 1, /* 4892: pointer.struct.stack_st_ASN1_OBJECT */
            	4897, 0,
            0, 32, 2, /* 4897: struct.stack_st_fake_ASN1_OBJECT */
            	4904, 8,
            	193, 24,
            8884099, 8, 2, /* 4904: pointer_to_array_of_pointers_to_stack */
            	4911, 0,
            	33, 20,
            0, 8, 1, /* 4911: pointer.ASN1_OBJECT */
            	2251, 0,
            1, 8, 1, /* 4916: pointer.struct.asn1_string_st */
            	4874, 0,
            1, 8, 1, /* 4921: pointer.struct.stack_st_X509_ALGOR */
            	4926, 0,
            0, 32, 2, /* 4926: struct.stack_st_fake_X509_ALGOR */
            	4933, 8,
            	193, 24,
            8884099, 8, 2, /* 4933: pointer_to_array_of_pointers_to_stack */
            	4940, 0,
            	33, 20,
            0, 8, 1, /* 4940: pointer.X509_ALGOR */
            	2040, 0,
            0, 32, 2, /* 4945: struct.stack_st */
            	188, 8,
            	193, 24,
            0, 32, 1, /* 4952: struct.stack_st_void */
            	4945, 0,
            0, 16, 1, /* 4957: struct.crypto_ex_data_st */
            	4962, 0,
            1, 8, 1, /* 4962: pointer.struct.stack_st_void */
            	4952, 0,
            0, 24, 1, /* 4967: struct.ASN1_ENCODING_st */
            	158, 0,
            1, 8, 1, /* 4972: pointer.struct.stack_st_X509_EXTENSION */
            	4977, 0,
            0, 32, 2, /* 4977: struct.stack_st_fake_X509_EXTENSION */
            	4984, 8,
            	193, 24,
            8884099, 8, 2, /* 4984: pointer_to_array_of_pointers_to_stack */
            	4991, 0,
            	33, 20,
            0, 8, 1, /* 4991: pointer.X509_EXTENSION */
            	2311, 0,
            1, 8, 1, /* 4996: pointer.struct.asn1_string_st */
            	4874, 0,
            1, 8, 1, /* 5001: pointer.struct.X509_pubkey_st */
            	2352, 0,
            0, 16, 2, /* 5006: struct.X509_val_st */
            	5013, 0,
            	5013, 8,
            1, 8, 1, /* 5013: pointer.struct.asn1_string_st */
            	4874, 0,
            0, 24, 1, /* 5018: struct.buf_mem_st */
            	84, 8,
            1, 8, 1, /* 5023: pointer.struct.stack_st_X509_NAME_ENTRY */
            	5028, 0,
            0, 32, 2, /* 5028: struct.stack_st_fake_X509_NAME_ENTRY */
            	5035, 8,
            	193, 24,
            8884099, 8, 2, /* 5035: pointer_to_array_of_pointers_to_stack */
            	5042, 0,
            	33, 20,
            0, 8, 1, /* 5042: pointer.X509_NAME_ENTRY */
            	2510, 0,
            1, 8, 1, /* 5047: pointer.struct.X509_algor_st */
            	2045, 0,
            1, 8, 1, /* 5052: pointer.struct.asn1_string_st */
            	4874, 0,
            1, 8, 1, /* 5057: pointer.struct.x509_cinf_st */
            	5062, 0,
            0, 104, 11, /* 5062: struct.x509_cinf_st */
            	5052, 0,
            	5052, 8,
            	5047, 16,
            	5087, 24,
            	5106, 32,
            	5087, 40,
            	5001, 48,
            	4996, 56,
            	4996, 64,
            	4972, 72,
            	4967, 80,
            1, 8, 1, /* 5087: pointer.struct.X509_name_st */
            	5092, 0,
            0, 40, 3, /* 5092: struct.X509_name_st */
            	5023, 0,
            	5101, 16,
            	158, 24,
            1, 8, 1, /* 5101: pointer.struct.buf_mem_st */
            	5018, 0,
            1, 8, 1, /* 5106: pointer.struct.X509_val_st */
            	5006, 0,
            1, 8, 1, /* 5111: pointer.struct.cert_pkey_st */
            	5116, 0,
            0, 24, 3, /* 5116: struct.cert_pkey_st */
            	5125, 0,
            	5162, 8,
            	5167, 16,
            1, 8, 1, /* 5125: pointer.struct.x509_st */
            	5130, 0,
            0, 184, 12, /* 5130: struct.x509_st */
            	5057, 0,
            	5047, 8,
            	4996, 16,
            	84, 32,
            	4957, 40,
            	4916, 104,
            	2701, 112,
            	3024, 120,
            	3441, 128,
            	3580, 136,
            	3604, 144,
            	5157, 176,
            1, 8, 1, /* 5157: pointer.struct.x509_cert_aux_st */
            	4879, 0,
            1, 8, 1, /* 5162: pointer.struct.evp_pkey_st */
            	4834, 0,
            1, 8, 1, /* 5167: pointer.struct.env_md_st */
            	4778, 0,
            8884097, 8, 0, /* 5172: pointer.func */
            1, 8, 1, /* 5175: pointer.struct.lhash_node_st */
            	5180, 0,
            0, 24, 2, /* 5180: struct.lhash_node_st */
            	72, 0,
            	5175, 8,
            0, 176, 3, /* 5187: struct.lhash_st */
            	5196, 0,
            	193, 8,
            	5203, 16,
            8884099, 8, 2, /* 5196: pointer_to_array_of_pointers_to_stack */
            	5175, 0,
            	30, 28,
            8884097, 8, 0, /* 5203: pointer.func */
            1, 8, 1, /* 5206: pointer.struct.lhash_st */
            	5187, 0,
            0, 32, 1, /* 5211: struct.stack_st_void */
            	5216, 0,
            0, 32, 2, /* 5216: struct.stack_st */
            	188, 8,
            	193, 24,
            0, 16, 1, /* 5223: struct.crypto_ex_data_st */
            	5228, 0,
            1, 8, 1, /* 5228: pointer.struct.stack_st_void */
            	5211, 0,
            8884097, 8, 0, /* 5233: pointer.func */
            8884097, 8, 0, /* 5236: pointer.func */
            1, 8, 1, /* 5239: pointer.struct.sess_cert_st */
            	5244, 0,
            0, 248, 5, /* 5244: struct.sess_cert_st */
            	5257, 0,
            	5111, 16,
            	5281, 216,
            	4767, 224,
            	3924, 232,
            1, 8, 1, /* 5257: pointer.struct.stack_st_X509 */
            	5262, 0,
            0, 32, 2, /* 5262: struct.stack_st_fake_X509 */
            	5269, 8,
            	193, 24,
            8884099, 8, 2, /* 5269: pointer_to_array_of_pointers_to_stack */
            	5276, 0,
            	33, 20,
            0, 8, 1, /* 5276: pointer.X509 */
            	4101, 0,
            1, 8, 1, /* 5281: pointer.struct.rsa_st */
            	585, 0,
            8884097, 8, 0, /* 5286: pointer.func */
            8884097, 8, 0, /* 5289: pointer.func */
            0, 56, 2, /* 5292: struct.X509_VERIFY_PARAM_st */
            	84, 0,
            	4507, 48,
            8884097, 8, 0, /* 5299: pointer.func */
            8884097, 8, 0, /* 5302: pointer.func */
            8884097, 8, 0, /* 5305: pointer.func */
            1, 8, 1, /* 5308: pointer.struct.X509_VERIFY_PARAM_st */
            	5313, 0,
            0, 56, 2, /* 5313: struct.X509_VERIFY_PARAM_st */
            	84, 0,
            	5320, 48,
            1, 8, 1, /* 5320: pointer.struct.stack_st_ASN1_OBJECT */
            	5325, 0,
            0, 32, 2, /* 5325: struct.stack_st_fake_ASN1_OBJECT */
            	5332, 8,
            	193, 24,
            8884099, 8, 2, /* 5332: pointer_to_array_of_pointers_to_stack */
            	5339, 0,
            	33, 20,
            0, 8, 1, /* 5339: pointer.ASN1_OBJECT */
            	2251, 0,
            8884097, 8, 0, /* 5344: pointer.func */
            1, 8, 1, /* 5347: pointer.struct.stack_st_X509_LOOKUP */
            	5352, 0,
            0, 32, 2, /* 5352: struct.stack_st_fake_X509_LOOKUP */
            	5359, 8,
            	193, 24,
            8884099, 8, 2, /* 5359: pointer_to_array_of_pointers_to_stack */
            	5366, 0,
            	33, 20,
            0, 8, 1, /* 5366: pointer.X509_LOOKUP */
            	5371, 0,
            0, 0, 1, /* 5371: X509_LOOKUP */
            	5376, 0,
            0, 32, 3, /* 5376: struct.x509_lookup_st */
            	5385, 8,
            	84, 16,
            	5434, 24,
            1, 8, 1, /* 5385: pointer.struct.x509_lookup_method_st */
            	5390, 0,
            0, 80, 10, /* 5390: struct.x509_lookup_method_st */
            	5, 0,
            	5413, 8,
            	5416, 16,
            	5413, 24,
            	5413, 32,
            	5419, 40,
            	5422, 48,
            	5425, 56,
            	5428, 64,
            	5431, 72,
            8884097, 8, 0, /* 5413: pointer.func */
            8884097, 8, 0, /* 5416: pointer.func */
            8884097, 8, 0, /* 5419: pointer.func */
            8884097, 8, 0, /* 5422: pointer.func */
            8884097, 8, 0, /* 5425: pointer.func */
            8884097, 8, 0, /* 5428: pointer.func */
            8884097, 8, 0, /* 5431: pointer.func */
            1, 8, 1, /* 5434: pointer.struct.x509_store_st */
            	5439, 0,
            0, 144, 15, /* 5439: struct.x509_store_st */
            	5472, 8,
            	5347, 16,
            	5308, 24,
            	5305, 32,
            	5302, 40,
            	6252, 48,
            	6255, 56,
            	5305, 64,
            	6258, 72,
            	6261, 80,
            	6264, 88,
            	5299, 96,
            	6267, 104,
            	5305, 112,
            	5698, 120,
            1, 8, 1, /* 5472: pointer.struct.stack_st_X509_OBJECT */
            	5477, 0,
            0, 32, 2, /* 5477: struct.stack_st_fake_X509_OBJECT */
            	5484, 8,
            	193, 24,
            8884099, 8, 2, /* 5484: pointer_to_array_of_pointers_to_stack */
            	5491, 0,
            	33, 20,
            0, 8, 1, /* 5491: pointer.X509_OBJECT */
            	5496, 0,
            0, 0, 1, /* 5496: X509_OBJECT */
            	5501, 0,
            0, 16, 1, /* 5501: struct.x509_object_st */
            	5506, 8,
            0, 8, 4, /* 5506: union.unknown */
            	84, 0,
            	5517, 0,
            	5835, 0,
            	6169, 0,
            1, 8, 1, /* 5517: pointer.struct.x509_st */
            	5522, 0,
            0, 184, 12, /* 5522: struct.x509_st */
            	5549, 0,
            	5589, 8,
            	5664, 16,
            	84, 32,
            	5698, 40,
            	5720, 104,
            	5725, 112,
            	5730, 120,
            	5735, 128,
            	5759, 136,
            	5783, 144,
            	5788, 176,
            1, 8, 1, /* 5549: pointer.struct.x509_cinf_st */
            	5554, 0,
            0, 104, 11, /* 5554: struct.x509_cinf_st */
            	5579, 0,
            	5579, 8,
            	5589, 16,
            	5594, 24,
            	5642, 32,
            	5594, 40,
            	5659, 48,
            	5664, 56,
            	5664, 64,
            	5669, 72,
            	5693, 80,
            1, 8, 1, /* 5579: pointer.struct.asn1_string_st */
            	5584, 0,
            0, 24, 1, /* 5584: struct.asn1_string_st */
            	158, 8,
            1, 8, 1, /* 5589: pointer.struct.X509_algor_st */
            	2045, 0,
            1, 8, 1, /* 5594: pointer.struct.X509_name_st */
            	5599, 0,
            0, 40, 3, /* 5599: struct.X509_name_st */
            	5608, 0,
            	5632, 16,
            	158, 24,
            1, 8, 1, /* 5608: pointer.struct.stack_st_X509_NAME_ENTRY */
            	5613, 0,
            0, 32, 2, /* 5613: struct.stack_st_fake_X509_NAME_ENTRY */
            	5620, 8,
            	193, 24,
            8884099, 8, 2, /* 5620: pointer_to_array_of_pointers_to_stack */
            	5627, 0,
            	33, 20,
            0, 8, 1, /* 5627: pointer.X509_NAME_ENTRY */
            	2510, 0,
            1, 8, 1, /* 5632: pointer.struct.buf_mem_st */
            	5637, 0,
            0, 24, 1, /* 5637: struct.buf_mem_st */
            	84, 8,
            1, 8, 1, /* 5642: pointer.struct.X509_val_st */
            	5647, 0,
            0, 16, 2, /* 5647: struct.X509_val_st */
            	5654, 0,
            	5654, 8,
            1, 8, 1, /* 5654: pointer.struct.asn1_string_st */
            	5584, 0,
            1, 8, 1, /* 5659: pointer.struct.X509_pubkey_st */
            	2352, 0,
            1, 8, 1, /* 5664: pointer.struct.asn1_string_st */
            	5584, 0,
            1, 8, 1, /* 5669: pointer.struct.stack_st_X509_EXTENSION */
            	5674, 0,
            0, 32, 2, /* 5674: struct.stack_st_fake_X509_EXTENSION */
            	5681, 8,
            	193, 24,
            8884099, 8, 2, /* 5681: pointer_to_array_of_pointers_to_stack */
            	5688, 0,
            	33, 20,
            0, 8, 1, /* 5688: pointer.X509_EXTENSION */
            	2311, 0,
            0, 24, 1, /* 5693: struct.ASN1_ENCODING_st */
            	158, 0,
            0, 16, 1, /* 5698: struct.crypto_ex_data_st */
            	5703, 0,
            1, 8, 1, /* 5703: pointer.struct.stack_st_void */
            	5708, 0,
            0, 32, 1, /* 5708: struct.stack_st_void */
            	5713, 0,
            0, 32, 2, /* 5713: struct.stack_st */
            	188, 8,
            	193, 24,
            1, 8, 1, /* 5720: pointer.struct.asn1_string_st */
            	5584, 0,
            1, 8, 1, /* 5725: pointer.struct.AUTHORITY_KEYID_st */
            	2706, 0,
            1, 8, 1, /* 5730: pointer.struct.X509_POLICY_CACHE_st */
            	3029, 0,
            1, 8, 1, /* 5735: pointer.struct.stack_st_DIST_POINT */
            	5740, 0,
            0, 32, 2, /* 5740: struct.stack_st_fake_DIST_POINT */
            	5747, 8,
            	193, 24,
            8884099, 8, 2, /* 5747: pointer_to_array_of_pointers_to_stack */
            	5754, 0,
            	33, 20,
            0, 8, 1, /* 5754: pointer.DIST_POINT */
            	3465, 0,
            1, 8, 1, /* 5759: pointer.struct.stack_st_GENERAL_NAME */
            	5764, 0,
            0, 32, 2, /* 5764: struct.stack_st_fake_GENERAL_NAME */
            	5771, 8,
            	193, 24,
            8884099, 8, 2, /* 5771: pointer_to_array_of_pointers_to_stack */
            	5778, 0,
            	33, 20,
            0, 8, 1, /* 5778: pointer.GENERAL_NAME */
            	2749, 0,
            1, 8, 1, /* 5783: pointer.struct.NAME_CONSTRAINTS_st */
            	3609, 0,
            1, 8, 1, /* 5788: pointer.struct.x509_cert_aux_st */
            	5793, 0,
            0, 40, 5, /* 5793: struct.x509_cert_aux_st */
            	5320, 0,
            	5320, 8,
            	5806, 16,
            	5720, 24,
            	5811, 32,
            1, 8, 1, /* 5806: pointer.struct.asn1_string_st */
            	5584, 0,
            1, 8, 1, /* 5811: pointer.struct.stack_st_X509_ALGOR */
            	5816, 0,
            0, 32, 2, /* 5816: struct.stack_st_fake_X509_ALGOR */
            	5823, 8,
            	193, 24,
            8884099, 8, 2, /* 5823: pointer_to_array_of_pointers_to_stack */
            	5830, 0,
            	33, 20,
            0, 8, 1, /* 5830: pointer.X509_ALGOR */
            	2040, 0,
            1, 8, 1, /* 5835: pointer.struct.X509_crl_st */
            	5840, 0,
            0, 120, 10, /* 5840: struct.X509_crl_st */
            	5863, 0,
            	5589, 8,
            	5664, 16,
            	5725, 32,
            	5990, 40,
            	5579, 56,
            	5579, 64,
            	6103, 96,
            	6144, 104,
            	72, 112,
            1, 8, 1, /* 5863: pointer.struct.X509_crl_info_st */
            	5868, 0,
            0, 80, 8, /* 5868: struct.X509_crl_info_st */
            	5579, 0,
            	5589, 8,
            	5594, 16,
            	5654, 24,
            	5654, 32,
            	5887, 40,
            	5669, 48,
            	5693, 56,
            1, 8, 1, /* 5887: pointer.struct.stack_st_X509_REVOKED */
            	5892, 0,
            0, 32, 2, /* 5892: struct.stack_st_fake_X509_REVOKED */
            	5899, 8,
            	193, 24,
            8884099, 8, 2, /* 5899: pointer_to_array_of_pointers_to_stack */
            	5906, 0,
            	33, 20,
            0, 8, 1, /* 5906: pointer.X509_REVOKED */
            	5911, 0,
            0, 0, 1, /* 5911: X509_REVOKED */
            	5916, 0,
            0, 40, 4, /* 5916: struct.x509_revoked_st */
            	5927, 0,
            	5937, 8,
            	5942, 16,
            	5966, 24,
            1, 8, 1, /* 5927: pointer.struct.asn1_string_st */
            	5932, 0,
            0, 24, 1, /* 5932: struct.asn1_string_st */
            	158, 8,
            1, 8, 1, /* 5937: pointer.struct.asn1_string_st */
            	5932, 0,
            1, 8, 1, /* 5942: pointer.struct.stack_st_X509_EXTENSION */
            	5947, 0,
            0, 32, 2, /* 5947: struct.stack_st_fake_X509_EXTENSION */
            	5954, 8,
            	193, 24,
            8884099, 8, 2, /* 5954: pointer_to_array_of_pointers_to_stack */
            	5961, 0,
            	33, 20,
            0, 8, 1, /* 5961: pointer.X509_EXTENSION */
            	2311, 0,
            1, 8, 1, /* 5966: pointer.struct.stack_st_GENERAL_NAME */
            	5971, 0,
            0, 32, 2, /* 5971: struct.stack_st_fake_GENERAL_NAME */
            	5978, 8,
            	193, 24,
            8884099, 8, 2, /* 5978: pointer_to_array_of_pointers_to_stack */
            	5985, 0,
            	33, 20,
            0, 8, 1, /* 5985: pointer.GENERAL_NAME */
            	2749, 0,
            1, 8, 1, /* 5990: pointer.struct.ISSUING_DIST_POINT_st */
            	5995, 0,
            0, 32, 2, /* 5995: struct.ISSUING_DIST_POINT_st */
            	6002, 0,
            	6093, 16,
            1, 8, 1, /* 6002: pointer.struct.DIST_POINT_NAME_st */
            	6007, 0,
            0, 24, 2, /* 6007: struct.DIST_POINT_NAME_st */
            	6014, 8,
            	6069, 16,
            0, 8, 2, /* 6014: union.unknown */
            	6021, 0,
            	6045, 0,
            1, 8, 1, /* 6021: pointer.struct.stack_st_GENERAL_NAME */
            	6026, 0,
            0, 32, 2, /* 6026: struct.stack_st_fake_GENERAL_NAME */
            	6033, 8,
            	193, 24,
            8884099, 8, 2, /* 6033: pointer_to_array_of_pointers_to_stack */
            	6040, 0,
            	33, 20,
            0, 8, 1, /* 6040: pointer.GENERAL_NAME */
            	2749, 0,
            1, 8, 1, /* 6045: pointer.struct.stack_st_X509_NAME_ENTRY */
            	6050, 0,
            0, 32, 2, /* 6050: struct.stack_st_fake_X509_NAME_ENTRY */
            	6057, 8,
            	193, 24,
            8884099, 8, 2, /* 6057: pointer_to_array_of_pointers_to_stack */
            	6064, 0,
            	33, 20,
            0, 8, 1, /* 6064: pointer.X509_NAME_ENTRY */
            	2510, 0,
            1, 8, 1, /* 6069: pointer.struct.X509_name_st */
            	6074, 0,
            0, 40, 3, /* 6074: struct.X509_name_st */
            	6045, 0,
            	6083, 16,
            	158, 24,
            1, 8, 1, /* 6083: pointer.struct.buf_mem_st */
            	6088, 0,
            0, 24, 1, /* 6088: struct.buf_mem_st */
            	84, 8,
            1, 8, 1, /* 6093: pointer.struct.asn1_string_st */
            	6098, 0,
            0, 24, 1, /* 6098: struct.asn1_string_st */
            	158, 8,
            1, 8, 1, /* 6103: pointer.struct.stack_st_GENERAL_NAMES */
            	6108, 0,
            0, 32, 2, /* 6108: struct.stack_st_fake_GENERAL_NAMES */
            	6115, 8,
            	193, 24,
            8884099, 8, 2, /* 6115: pointer_to_array_of_pointers_to_stack */
            	6122, 0,
            	33, 20,
            0, 8, 1, /* 6122: pointer.GENERAL_NAMES */
            	6127, 0,
            0, 0, 1, /* 6127: GENERAL_NAMES */
            	6132, 0,
            0, 32, 1, /* 6132: struct.stack_st_GENERAL_NAME */
            	6137, 0,
            0, 32, 2, /* 6137: struct.stack_st */
            	188, 8,
            	193, 24,
            1, 8, 1, /* 6144: pointer.struct.x509_crl_method_st */
            	6149, 0,
            0, 40, 4, /* 6149: struct.x509_crl_method_st */
            	6160, 8,
            	6160, 16,
            	6163, 24,
            	6166, 32,
            8884097, 8, 0, /* 6160: pointer.func */
            8884097, 8, 0, /* 6163: pointer.func */
            8884097, 8, 0, /* 6166: pointer.func */
            1, 8, 1, /* 6169: pointer.struct.evp_pkey_st */
            	6174, 0,
            0, 56, 4, /* 6174: struct.evp_pkey_st */
            	6185, 16,
            	6190, 24,
            	6195, 32,
            	6228, 48,
            1, 8, 1, /* 6185: pointer.struct.evp_pkey_asn1_method_st */
            	1915, 0,
            1, 8, 1, /* 6190: pointer.struct.engine_st */
            	237, 0,
            0, 8, 5, /* 6195: union.unknown */
            	84, 0,
            	6208, 0,
            	6213, 0,
            	6218, 0,
            	6223, 0,
            1, 8, 1, /* 6208: pointer.struct.rsa_st */
            	585, 0,
            1, 8, 1, /* 6213: pointer.struct.dsa_st */
            	1253, 0,
            1, 8, 1, /* 6218: pointer.struct.dh_st */
            	100, 0,
            1, 8, 1, /* 6223: pointer.struct.ec_key_st */
            	1392, 0,
            1, 8, 1, /* 6228: pointer.struct.stack_st_X509_ATTRIBUTE */
            	6233, 0,
            0, 32, 2, /* 6233: struct.stack_st_fake_X509_ATTRIBUTE */
            	6240, 8,
            	193, 24,
            8884099, 8, 2, /* 6240: pointer_to_array_of_pointers_to_stack */
            	6247, 0,
            	33, 20,
            0, 8, 1, /* 6247: pointer.X509_ATTRIBUTE */
            	865, 0,
            8884097, 8, 0, /* 6252: pointer.func */
            8884097, 8, 0, /* 6255: pointer.func */
            8884097, 8, 0, /* 6258: pointer.func */
            8884097, 8, 0, /* 6261: pointer.func */
            8884097, 8, 0, /* 6264: pointer.func */
            8884097, 8, 0, /* 6267: pointer.func */
            1, 8, 1, /* 6270: pointer.struct.stack_st_X509_LOOKUP */
            	6275, 0,
            0, 32, 2, /* 6275: struct.stack_st_fake_X509_LOOKUP */
            	6282, 8,
            	193, 24,
            8884099, 8, 2, /* 6282: pointer_to_array_of_pointers_to_stack */
            	6289, 0,
            	33, 20,
            0, 8, 1, /* 6289: pointer.X509_LOOKUP */
            	5371, 0,
            8884097, 8, 0, /* 6294: pointer.func */
            1, 8, 1, /* 6297: pointer.struct.AUTHORITY_KEYID_st */
            	2706, 0,
            1, 8, 1, /* 6302: pointer.struct.x509_st */
            	6307, 0,
            0, 184, 12, /* 6307: struct.x509_st */
            	6334, 0,
            	4679, 8,
            	4762, 16,
            	84, 32,
            	5223, 40,
            	4541, 104,
            	6297, 112,
            	3024, 120,
            	4604, 128,
            	4580, 136,
            	4575, 144,
            	4570, 176,
            1, 8, 1, /* 6334: pointer.struct.x509_cinf_st */
            	4689, 0,
            8884097, 8, 0, /* 6339: pointer.func */
            8884097, 8, 0, /* 6342: pointer.func */
            8884097, 8, 0, /* 6345: pointer.func */
            0, 0, 1, /* 6348: SSL_CIPHER */
            	6353, 0,
            0, 88, 1, /* 6353: struct.ssl_cipher_st */
            	5, 8,
            0, 144, 15, /* 6358: struct.x509_store_st */
            	6391, 8,
            	6270, 16,
            	6415, 24,
            	5289, 32,
            	6345, 40,
            	6420, 48,
            	6423, 56,
            	5289, 64,
            	5286, 72,
            	5236, 80,
            	6426, 88,
            	5233, 96,
            	6429, 104,
            	5289, 112,
            	5223, 120,
            1, 8, 1, /* 6391: pointer.struct.stack_st_X509_OBJECT */
            	6396, 0,
            0, 32, 2, /* 6396: struct.stack_st_fake_X509_OBJECT */
            	6403, 8,
            	193, 24,
            8884099, 8, 2, /* 6403: pointer_to_array_of_pointers_to_stack */
            	6410, 0,
            	33, 20,
            0, 8, 1, /* 6410: pointer.X509_OBJECT */
            	5496, 0,
            1, 8, 1, /* 6415: pointer.struct.X509_VERIFY_PARAM_st */
            	5292, 0,
            8884097, 8, 0, /* 6420: pointer.func */
            8884097, 8, 0, /* 6423: pointer.func */
            8884097, 8, 0, /* 6426: pointer.func */
            8884097, 8, 0, /* 6429: pointer.func */
            8884097, 8, 0, /* 6432: pointer.func */
            0, 8, 1, /* 6435: pointer.SRTP_PROTECTION_PROFILE */
            	10, 0,
            0, 32, 2, /* 6440: struct.stack_st_fake_SRTP_PROTECTION_PROFILE */
            	6447, 8,
            	193, 24,
            8884099, 8, 2, /* 6447: pointer_to_array_of_pointers_to_stack */
            	6435, 0,
            	33, 20,
            8884097, 8, 0, /* 6454: pointer.func */
            8884097, 8, 0, /* 6457: pointer.func */
            8884097, 8, 0, /* 6460: pointer.func */
            8884097, 8, 0, /* 6463: pointer.func */
            8884097, 8, 0, /* 6466: pointer.func */
            1, 8, 1, /* 6469: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	6440, 0,
            1, 8, 1, /* 6474: pointer.struct.x509_store_st */
            	6358, 0,
            1, 8, 1, /* 6479: pointer.struct.stack_st_SSL_CIPHER */
            	6484, 0,
            0, 32, 2, /* 6484: struct.stack_st_fake_SSL_CIPHER */
            	6491, 8,
            	193, 24,
            8884099, 8, 2, /* 6491: pointer_to_array_of_pointers_to_stack */
            	6498, 0,
            	33, 20,
            0, 8, 1, /* 6498: pointer.SSL_CIPHER */
            	6348, 0,
            8884097, 8, 0, /* 6503: pointer.func */
            8884097, 8, 0, /* 6506: pointer.func */
            0, 1, 0, /* 6509: char */
            0, 232, 28, /* 6512: struct.ssl_method_st */
            	6339, 8,
            	6571, 16,
            	6571, 24,
            	6339, 32,
            	6339, 40,
            	6574, 48,
            	6574, 56,
            	6577, 64,
            	6339, 72,
            	6339, 80,
            	6339, 88,
            	6503, 96,
            	6460, 104,
            	6580, 112,
            	6339, 120,
            	6583, 128,
            	6457, 136,
            	6586, 144,
            	6463, 152,
            	6589, 160,
            	506, 168,
            	6466, 176,
            	6342, 184,
            	4033, 192,
            	6592, 200,
            	506, 208,
            	6637, 216,
            	6640, 224,
            8884097, 8, 0, /* 6571: pointer.func */
            8884097, 8, 0, /* 6574: pointer.func */
            8884097, 8, 0, /* 6577: pointer.func */
            8884097, 8, 0, /* 6580: pointer.func */
            8884097, 8, 0, /* 6583: pointer.func */
            8884097, 8, 0, /* 6586: pointer.func */
            8884097, 8, 0, /* 6589: pointer.func */
            1, 8, 1, /* 6592: pointer.struct.ssl3_enc_method */
            	6597, 0,
            0, 112, 11, /* 6597: struct.ssl3_enc_method */
            	6622, 0,
            	6625, 8,
            	6628, 16,
            	6506, 24,
            	6622, 32,
            	6454, 40,
            	6631, 56,
            	5, 64,
            	5, 80,
            	6432, 96,
            	6634, 104,
            8884097, 8, 0, /* 6622: pointer.func */
            8884097, 8, 0, /* 6625: pointer.func */
            8884097, 8, 0, /* 6628: pointer.func */
            8884097, 8, 0, /* 6631: pointer.func */
            8884097, 8, 0, /* 6634: pointer.func */
            8884097, 8, 0, /* 6637: pointer.func */
            8884097, 8, 0, /* 6640: pointer.func */
            0, 736, 50, /* 6643: struct.ssl_ctx_st */
            	6746, 0,
            	6479, 8,
            	6479, 16,
            	6474, 24,
            	5206, 32,
            	6751, 48,
            	6751, 56,
            	5344, 80,
            	5172, 88,
            	4486, 96,
            	6294, 152,
            	72, 160,
            	4483, 168,
            	72, 176,
            	6792, 184,
            	4480, 192,
            	4477, 200,
            	5223, 208,
            	6795, 224,
            	6795, 232,
            	6795, 240,
            	4077, 248,
            	4053, 256,
            	4004, 264,
            	3980, 272,
            	2618, 304,
            	6800, 320,
            	72, 328,
            	6345, 376,
            	6803, 384,
            	6415, 392,
            	2011, 408,
            	75, 416,
            	72, 424,
            	89, 480,
            	78, 488,
            	72, 496,
            	1896, 504,
            	72, 512,
            	84, 520,
            	2575, 528,
            	6806, 536,
            	6809, 552,
            	6809, 560,
            	41, 568,
            	15, 696,
            	72, 704,
            	6814, 712,
            	72, 720,
            	6469, 728,
            1, 8, 1, /* 6746: pointer.struct.ssl_method_st */
            	6512, 0,
            1, 8, 1, /* 6751: pointer.struct.ssl_session_st */
            	6756, 0,
            0, 352, 14, /* 6756: struct.ssl_session_st */
            	84, 144,
            	84, 152,
            	5239, 168,
            	6302, 176,
            	6787, 224,
            	6479, 240,
            	5223, 248,
            	6751, 264,
            	6751, 272,
            	84, 280,
            	158, 296,
            	158, 312,
            	158, 320,
            	84, 344,
            1, 8, 1, /* 6787: pointer.struct.ssl_cipher_st */
            	4489, 0,
            8884097, 8, 0, /* 6792: pointer.func */
            1, 8, 1, /* 6795: pointer.struct.env_md_st */
            	4452, 0,
            8884097, 8, 0, /* 6800: pointer.func */
            8884097, 8, 0, /* 6803: pointer.func */
            8884097, 8, 0, /* 6806: pointer.func */
            1, 8, 1, /* 6809: pointer.struct.ssl3_buf_freelist_st */
            	2546, 0,
            8884097, 8, 0, /* 6814: pointer.func */
            1, 8, 1, /* 6817: pointer.struct.ssl_ctx_st */
            	6643, 0,
            8884097, 8, 0, /* 6822: pointer.func */
        },
        .arg_entity_index = { 6817, 6822, },
        .ret_entity_index = -1,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    SSL_CTX * new_arg_a = *((SSL_CTX * *)new_args->args[0]);

    DH *(*new_arg_b)(SSL *, int, int) = *((DH *(**)(SSL *, int, int))new_args->args[1]);

    void (*orig_SSL_CTX_set_tmp_dh_callback)(SSL_CTX *,DH *(*)(SSL *, int, int));
    orig_SSL_CTX_set_tmp_dh_callback = dlsym(RTLD_NEXT, "SSL_CTX_set_tmp_dh_callback");
    (*orig_SSL_CTX_set_tmp_dh_callback)(new_arg_a,new_arg_b);

    syscall(889);

}

