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

void bb_SSL_CTX_sess_set_remove_cb(SSL_CTX * arg_a,void (*arg_b)(struct ssl_ctx_st *,SSL_SESSION *));

void SSL_CTX_sess_set_remove_cb(SSL_CTX * arg_a,void (*arg_b)(struct ssl_ctx_st *,SSL_SESSION *)) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_CTX_sess_set_remove_cb called %lu\n", in_lib);
    if (!in_lib)
        bb_SSL_CTX_sess_set_remove_cb(arg_a,arg_b);
    else {
        void (*orig_SSL_CTX_sess_set_remove_cb)(SSL_CTX *,void (*)(struct ssl_ctx_st *,SSL_SESSION *));
        orig_SSL_CTX_sess_set_remove_cb = dlsym(RTLD_NEXT, "SSL_CTX_sess_set_remove_cb");
        orig_SSL_CTX_sess_set_remove_cb(arg_a,arg_b);
    }
}

void bb_SSL_CTX_sess_set_remove_cb(SSL_CTX * arg_a,void (*arg_b)(struct ssl_ctx_st *,SSL_SESSION *)) 
{
    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            8884097, 8, 0, /* 0: pointer.func */
            8884097, 8, 0, /* 3: pointer.func */
            8884097, 8, 0, /* 6: pointer.func */
            0, 24, 1, /* 9: struct.bignum_st */
            	14, 0,
            1, 8, 1, /* 14: pointer.unsigned int */
            	19, 0,
            0, 4, 0, /* 19: unsigned int */
            1, 8, 1, /* 22: pointer.struct.bignum_st */
            	9, 0,
            0, 128, 14, /* 27: struct.srp_ctx_st */
            	58, 0,
            	61, 8,
            	64, 16,
            	67, 24,
            	70, 32,
            	22, 40,
            	22, 48,
            	22, 56,
            	22, 64,
            	22, 72,
            	22, 80,
            	22, 88,
            	22, 96,
            	70, 104,
            0, 8, 0, /* 58: pointer.void */
            8884097, 8, 0, /* 61: pointer.func */
            8884097, 8, 0, /* 64: pointer.func */
            8884097, 8, 0, /* 67: pointer.func */
            1, 8, 1, /* 70: pointer.char */
            	8884096, 0,
            0, 8, 1, /* 75: struct.ssl3_buf_freelist_entry_st */
            	80, 0,
            1, 8, 1, /* 80: pointer.struct.ssl3_buf_freelist_entry_st */
            	75, 0,
            0, 24, 1, /* 85: struct.ssl3_buf_freelist_st */
            	80, 16,
            1, 8, 1, /* 90: pointer.struct.ssl3_buf_freelist_st */
            	85, 0,
            8884097, 8, 0, /* 95: pointer.func */
            8884097, 8, 0, /* 98: pointer.func */
            8884097, 8, 0, /* 101: pointer.func */
            1, 8, 1, /* 104: pointer.struct.dh_st */
            	109, 0,
            0, 144, 12, /* 109: struct.dh_st */
            	136, 8,
            	136, 16,
            	136, 32,
            	136, 40,
            	146, 56,
            	136, 64,
            	136, 72,
            	160, 80,
            	136, 96,
            	168, 112,
            	198, 128,
            	239, 136,
            1, 8, 1, /* 136: pointer.struct.bignum_st */
            	141, 0,
            0, 24, 1, /* 141: struct.bignum_st */
            	14, 0,
            1, 8, 1, /* 146: pointer.struct.bn_mont_ctx_st */
            	151, 0,
            0, 96, 3, /* 151: struct.bn_mont_ctx_st */
            	141, 8,
            	141, 32,
            	141, 56,
            1, 8, 1, /* 160: pointer.unsigned char */
            	165, 0,
            0, 1, 0, /* 165: unsigned char */
            0, 16, 1, /* 168: struct.crypto_ex_data_st */
            	173, 0,
            1, 8, 1, /* 173: pointer.struct.stack_st_void */
            	178, 0,
            0, 32, 1, /* 178: struct.stack_st_void */
            	183, 0,
            0, 32, 2, /* 183: struct.stack_st */
            	190, 8,
            	195, 24,
            1, 8, 1, /* 190: pointer.pointer.char */
            	70, 0,
            8884097, 8, 0, /* 195: pointer.func */
            1, 8, 1, /* 198: pointer.struct.dh_method */
            	203, 0,
            0, 72, 8, /* 203: struct.dh_method */
            	222, 0,
            	227, 8,
            	230, 16,
            	233, 24,
            	227, 32,
            	227, 40,
            	70, 56,
            	236, 64,
            1, 8, 1, /* 222: pointer.char */
            	8884096, 0,
            8884097, 8, 0, /* 227: pointer.func */
            8884097, 8, 0, /* 230: pointer.func */
            8884097, 8, 0, /* 233: pointer.func */
            8884097, 8, 0, /* 236: pointer.func */
            1, 8, 1, /* 239: pointer.struct.engine_st */
            	244, 0,
            0, 216, 24, /* 244: struct.engine_st */
            	222, 0,
            	222, 8,
            	295, 16,
            	350, 24,
            	401, 32,
            	437, 40,
            	454, 48,
            	481, 56,
            	516, 64,
            	524, 72,
            	527, 80,
            	530, 88,
            	533, 96,
            	536, 104,
            	536, 112,
            	536, 120,
            	539, 128,
            	542, 136,
            	542, 144,
            	545, 152,
            	548, 160,
            	560, 184,
            	582, 200,
            	582, 208,
            1, 8, 1, /* 295: pointer.struct.rsa_meth_st */
            	300, 0,
            0, 112, 13, /* 300: struct.rsa_meth_st */
            	222, 0,
            	329, 8,
            	329, 16,
            	329, 24,
            	329, 32,
            	332, 40,
            	335, 48,
            	338, 56,
            	338, 64,
            	70, 80,
            	341, 88,
            	344, 96,
            	347, 104,
            8884097, 8, 0, /* 329: pointer.func */
            8884097, 8, 0, /* 332: pointer.func */
            8884097, 8, 0, /* 335: pointer.func */
            8884097, 8, 0, /* 338: pointer.func */
            8884097, 8, 0, /* 341: pointer.func */
            8884097, 8, 0, /* 344: pointer.func */
            8884097, 8, 0, /* 347: pointer.func */
            1, 8, 1, /* 350: pointer.struct.dsa_method */
            	355, 0,
            0, 96, 11, /* 355: struct.dsa_method */
            	222, 0,
            	380, 8,
            	383, 16,
            	386, 24,
            	389, 32,
            	392, 40,
            	395, 48,
            	395, 56,
            	70, 72,
            	398, 80,
            	395, 88,
            8884097, 8, 0, /* 380: pointer.func */
            8884097, 8, 0, /* 383: pointer.func */
            8884097, 8, 0, /* 386: pointer.func */
            8884097, 8, 0, /* 389: pointer.func */
            8884097, 8, 0, /* 392: pointer.func */
            8884097, 8, 0, /* 395: pointer.func */
            8884097, 8, 0, /* 398: pointer.func */
            1, 8, 1, /* 401: pointer.struct.dh_method */
            	406, 0,
            0, 72, 8, /* 406: struct.dh_method */
            	222, 0,
            	425, 8,
            	428, 16,
            	431, 24,
            	425, 32,
            	425, 40,
            	70, 56,
            	434, 64,
            8884097, 8, 0, /* 425: pointer.func */
            8884097, 8, 0, /* 428: pointer.func */
            8884097, 8, 0, /* 431: pointer.func */
            8884097, 8, 0, /* 434: pointer.func */
            1, 8, 1, /* 437: pointer.struct.ecdh_method */
            	442, 0,
            0, 32, 3, /* 442: struct.ecdh_method */
            	222, 0,
            	451, 8,
            	70, 24,
            8884097, 8, 0, /* 451: pointer.func */
            1, 8, 1, /* 454: pointer.struct.ecdsa_method */
            	459, 0,
            0, 48, 5, /* 459: struct.ecdsa_method */
            	222, 0,
            	472, 8,
            	475, 16,
            	478, 24,
            	70, 40,
            8884097, 8, 0, /* 472: pointer.func */
            8884097, 8, 0, /* 475: pointer.func */
            8884097, 8, 0, /* 478: pointer.func */
            1, 8, 1, /* 481: pointer.struct.rand_meth_st */
            	486, 0,
            0, 48, 6, /* 486: struct.rand_meth_st */
            	501, 0,
            	504, 8,
            	507, 16,
            	510, 24,
            	504, 32,
            	513, 40,
            8884097, 8, 0, /* 501: pointer.func */
            8884097, 8, 0, /* 504: pointer.func */
            8884097, 8, 0, /* 507: pointer.func */
            8884097, 8, 0, /* 510: pointer.func */
            8884097, 8, 0, /* 513: pointer.func */
            1, 8, 1, /* 516: pointer.struct.store_method_st */
            	521, 0,
            0, 0, 0, /* 521: struct.store_method_st */
            8884097, 8, 0, /* 524: pointer.func */
            8884097, 8, 0, /* 527: pointer.func */
            8884097, 8, 0, /* 530: pointer.func */
            8884097, 8, 0, /* 533: pointer.func */
            8884097, 8, 0, /* 536: pointer.func */
            8884097, 8, 0, /* 539: pointer.func */
            8884097, 8, 0, /* 542: pointer.func */
            8884097, 8, 0, /* 545: pointer.func */
            1, 8, 1, /* 548: pointer.struct.ENGINE_CMD_DEFN_st */
            	553, 0,
            0, 32, 2, /* 553: struct.ENGINE_CMD_DEFN_st */
            	222, 8,
            	222, 16,
            0, 16, 1, /* 560: struct.crypto_ex_data_st */
            	565, 0,
            1, 8, 1, /* 565: pointer.struct.stack_st_void */
            	570, 0,
            0, 32, 1, /* 570: struct.stack_st_void */
            	575, 0,
            0, 32, 2, /* 575: struct.stack_st */
            	190, 8,
            	195, 24,
            1, 8, 1, /* 582: pointer.struct.engine_st */
            	244, 0,
            1, 8, 1, /* 587: pointer.struct.rsa_st */
            	592, 0,
            0, 168, 17, /* 592: struct.rsa_st */
            	629, 16,
            	239, 24,
            	684, 32,
            	684, 40,
            	684, 48,
            	684, 56,
            	684, 64,
            	684, 72,
            	684, 80,
            	684, 88,
            	694, 96,
            	716, 120,
            	716, 128,
            	716, 136,
            	70, 144,
            	730, 152,
            	730, 160,
            1, 8, 1, /* 629: pointer.struct.rsa_meth_st */
            	634, 0,
            0, 112, 13, /* 634: struct.rsa_meth_st */
            	222, 0,
            	663, 8,
            	663, 16,
            	663, 24,
            	663, 32,
            	666, 40,
            	669, 48,
            	672, 56,
            	672, 64,
            	70, 80,
            	675, 88,
            	678, 96,
            	681, 104,
            8884097, 8, 0, /* 663: pointer.func */
            8884097, 8, 0, /* 666: pointer.func */
            8884097, 8, 0, /* 669: pointer.func */
            8884097, 8, 0, /* 672: pointer.func */
            8884097, 8, 0, /* 675: pointer.func */
            8884097, 8, 0, /* 678: pointer.func */
            8884097, 8, 0, /* 681: pointer.func */
            1, 8, 1, /* 684: pointer.struct.bignum_st */
            	689, 0,
            0, 24, 1, /* 689: struct.bignum_st */
            	14, 0,
            0, 16, 1, /* 694: struct.crypto_ex_data_st */
            	699, 0,
            1, 8, 1, /* 699: pointer.struct.stack_st_void */
            	704, 0,
            0, 32, 1, /* 704: struct.stack_st_void */
            	709, 0,
            0, 32, 2, /* 709: struct.stack_st */
            	190, 8,
            	195, 24,
            1, 8, 1, /* 716: pointer.struct.bn_mont_ctx_st */
            	721, 0,
            0, 96, 3, /* 721: struct.bn_mont_ctx_st */
            	689, 8,
            	689, 32,
            	689, 56,
            1, 8, 1, /* 730: pointer.struct.bn_blinding_st */
            	735, 0,
            0, 88, 7, /* 735: struct.bn_blinding_st */
            	752, 0,
            	752, 8,
            	752, 16,
            	752, 24,
            	762, 40,
            	767, 72,
            	781, 80,
            1, 8, 1, /* 752: pointer.struct.bignum_st */
            	757, 0,
            0, 24, 1, /* 757: struct.bignum_st */
            	14, 0,
            0, 16, 1, /* 762: struct.crypto_threadid_st */
            	58, 0,
            1, 8, 1, /* 767: pointer.struct.bn_mont_ctx_st */
            	772, 0,
            0, 96, 3, /* 772: struct.bn_mont_ctx_st */
            	757, 8,
            	757, 32,
            	757, 56,
            8884097, 8, 0, /* 781: pointer.func */
            8884097, 8, 0, /* 784: pointer.func */
            8884097, 8, 0, /* 787: pointer.func */
            1, 8, 1, /* 790: pointer.struct.env_md_st */
            	795, 0,
            0, 120, 8, /* 795: struct.env_md_st */
            	814, 24,
            	787, 32,
            	784, 40,
            	817, 48,
            	814, 56,
            	820, 64,
            	823, 72,
            	826, 112,
            8884097, 8, 0, /* 814: pointer.func */
            8884097, 8, 0, /* 817: pointer.func */
            8884097, 8, 0, /* 820: pointer.func */
            8884097, 8, 0, /* 823: pointer.func */
            8884097, 8, 0, /* 826: pointer.func */
            1, 8, 1, /* 829: pointer.struct.stack_st_X509_ATTRIBUTE */
            	834, 0,
            0, 32, 2, /* 834: struct.stack_st_fake_X509_ATTRIBUTE */
            	841, 8,
            	195, 24,
            8884099, 8, 2, /* 841: pointer_to_array_of_pointers_to_stack */
            	848, 0,
            	1072, 20,
            0, 8, 1, /* 848: pointer.X509_ATTRIBUTE */
            	853, 0,
            0, 0, 1, /* 853: X509_ATTRIBUTE */
            	858, 0,
            0, 24, 2, /* 858: struct.x509_attributes_st */
            	865, 0,
            	884, 16,
            1, 8, 1, /* 865: pointer.struct.asn1_object_st */
            	870, 0,
            0, 40, 3, /* 870: struct.asn1_object_st */
            	222, 0,
            	222, 8,
            	879, 24,
            1, 8, 1, /* 879: pointer.unsigned char */
            	165, 0,
            0, 8, 3, /* 884: union.unknown */
            	70, 0,
            	893, 0,
            	1075, 0,
            1, 8, 1, /* 893: pointer.struct.stack_st_ASN1_TYPE */
            	898, 0,
            0, 32, 2, /* 898: struct.stack_st_fake_ASN1_TYPE */
            	905, 8,
            	195, 24,
            8884099, 8, 2, /* 905: pointer_to_array_of_pointers_to_stack */
            	912, 0,
            	1072, 20,
            0, 8, 1, /* 912: pointer.ASN1_TYPE */
            	917, 0,
            0, 0, 1, /* 917: ASN1_TYPE */
            	922, 0,
            0, 16, 1, /* 922: struct.asn1_type_st */
            	927, 8,
            0, 8, 20, /* 927: union.unknown */
            	70, 0,
            	970, 0,
            	980, 0,
            	994, 0,
            	999, 0,
            	1004, 0,
            	1009, 0,
            	1014, 0,
            	1019, 0,
            	1024, 0,
            	1029, 0,
            	1034, 0,
            	1039, 0,
            	1044, 0,
            	1049, 0,
            	1054, 0,
            	1059, 0,
            	970, 0,
            	970, 0,
            	1064, 0,
            1, 8, 1, /* 970: pointer.struct.asn1_string_st */
            	975, 0,
            0, 24, 1, /* 975: struct.asn1_string_st */
            	160, 8,
            1, 8, 1, /* 980: pointer.struct.asn1_object_st */
            	985, 0,
            0, 40, 3, /* 985: struct.asn1_object_st */
            	222, 0,
            	222, 8,
            	879, 24,
            1, 8, 1, /* 994: pointer.struct.asn1_string_st */
            	975, 0,
            1, 8, 1, /* 999: pointer.struct.asn1_string_st */
            	975, 0,
            1, 8, 1, /* 1004: pointer.struct.asn1_string_st */
            	975, 0,
            1, 8, 1, /* 1009: pointer.struct.asn1_string_st */
            	975, 0,
            1, 8, 1, /* 1014: pointer.struct.asn1_string_st */
            	975, 0,
            1, 8, 1, /* 1019: pointer.struct.asn1_string_st */
            	975, 0,
            1, 8, 1, /* 1024: pointer.struct.asn1_string_st */
            	975, 0,
            1, 8, 1, /* 1029: pointer.struct.asn1_string_st */
            	975, 0,
            1, 8, 1, /* 1034: pointer.struct.asn1_string_st */
            	975, 0,
            1, 8, 1, /* 1039: pointer.struct.asn1_string_st */
            	975, 0,
            1, 8, 1, /* 1044: pointer.struct.asn1_string_st */
            	975, 0,
            1, 8, 1, /* 1049: pointer.struct.asn1_string_st */
            	975, 0,
            1, 8, 1, /* 1054: pointer.struct.asn1_string_st */
            	975, 0,
            1, 8, 1, /* 1059: pointer.struct.asn1_string_st */
            	975, 0,
            1, 8, 1, /* 1064: pointer.struct.ASN1_VALUE_st */
            	1069, 0,
            0, 0, 0, /* 1069: struct.ASN1_VALUE_st */
            0, 4, 0, /* 1072: int */
            1, 8, 1, /* 1075: pointer.struct.asn1_type_st */
            	1080, 0,
            0, 16, 1, /* 1080: struct.asn1_type_st */
            	1085, 8,
            0, 8, 20, /* 1085: union.unknown */
            	70, 0,
            	1128, 0,
            	865, 0,
            	1138, 0,
            	1143, 0,
            	1148, 0,
            	1153, 0,
            	1158, 0,
            	1163, 0,
            	1168, 0,
            	1173, 0,
            	1178, 0,
            	1183, 0,
            	1188, 0,
            	1193, 0,
            	1198, 0,
            	1203, 0,
            	1128, 0,
            	1128, 0,
            	1208, 0,
            1, 8, 1, /* 1128: pointer.struct.asn1_string_st */
            	1133, 0,
            0, 24, 1, /* 1133: struct.asn1_string_st */
            	160, 8,
            1, 8, 1, /* 1138: pointer.struct.asn1_string_st */
            	1133, 0,
            1, 8, 1, /* 1143: pointer.struct.asn1_string_st */
            	1133, 0,
            1, 8, 1, /* 1148: pointer.struct.asn1_string_st */
            	1133, 0,
            1, 8, 1, /* 1153: pointer.struct.asn1_string_st */
            	1133, 0,
            1, 8, 1, /* 1158: pointer.struct.asn1_string_st */
            	1133, 0,
            1, 8, 1, /* 1163: pointer.struct.asn1_string_st */
            	1133, 0,
            1, 8, 1, /* 1168: pointer.struct.asn1_string_st */
            	1133, 0,
            1, 8, 1, /* 1173: pointer.struct.asn1_string_st */
            	1133, 0,
            1, 8, 1, /* 1178: pointer.struct.asn1_string_st */
            	1133, 0,
            1, 8, 1, /* 1183: pointer.struct.asn1_string_st */
            	1133, 0,
            1, 8, 1, /* 1188: pointer.struct.asn1_string_st */
            	1133, 0,
            1, 8, 1, /* 1193: pointer.struct.asn1_string_st */
            	1133, 0,
            1, 8, 1, /* 1198: pointer.struct.asn1_string_st */
            	1133, 0,
            1, 8, 1, /* 1203: pointer.struct.asn1_string_st */
            	1133, 0,
            1, 8, 1, /* 1208: pointer.struct.ASN1_VALUE_st */
            	1213, 0,
            0, 0, 0, /* 1213: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1216: pointer.struct.dh_st */
            	109, 0,
            1, 8, 1, /* 1221: pointer.struct.rsa_st */
            	592, 0,
            0, 8, 5, /* 1226: union.unknown */
            	70, 0,
            	1221, 0,
            	1239, 0,
            	1216, 0,
            	1371, 0,
            1, 8, 1, /* 1239: pointer.struct.dsa_st */
            	1244, 0,
            0, 136, 11, /* 1244: struct.dsa_st */
            	1269, 24,
            	1269, 32,
            	1269, 40,
            	1269, 48,
            	1269, 56,
            	1269, 64,
            	1269, 72,
            	1279, 88,
            	1293, 104,
            	1315, 120,
            	1366, 128,
            1, 8, 1, /* 1269: pointer.struct.bignum_st */
            	1274, 0,
            0, 24, 1, /* 1274: struct.bignum_st */
            	14, 0,
            1, 8, 1, /* 1279: pointer.struct.bn_mont_ctx_st */
            	1284, 0,
            0, 96, 3, /* 1284: struct.bn_mont_ctx_st */
            	1274, 8,
            	1274, 32,
            	1274, 56,
            0, 16, 1, /* 1293: struct.crypto_ex_data_st */
            	1298, 0,
            1, 8, 1, /* 1298: pointer.struct.stack_st_void */
            	1303, 0,
            0, 32, 1, /* 1303: struct.stack_st_void */
            	1308, 0,
            0, 32, 2, /* 1308: struct.stack_st */
            	190, 8,
            	195, 24,
            1, 8, 1, /* 1315: pointer.struct.dsa_method */
            	1320, 0,
            0, 96, 11, /* 1320: struct.dsa_method */
            	222, 0,
            	1345, 8,
            	1348, 16,
            	1351, 24,
            	1354, 32,
            	1357, 40,
            	1360, 48,
            	1360, 56,
            	70, 72,
            	1363, 80,
            	1360, 88,
            8884097, 8, 0, /* 1345: pointer.func */
            8884097, 8, 0, /* 1348: pointer.func */
            8884097, 8, 0, /* 1351: pointer.func */
            8884097, 8, 0, /* 1354: pointer.func */
            8884097, 8, 0, /* 1357: pointer.func */
            8884097, 8, 0, /* 1360: pointer.func */
            8884097, 8, 0, /* 1363: pointer.func */
            1, 8, 1, /* 1366: pointer.struct.engine_st */
            	244, 0,
            1, 8, 1, /* 1371: pointer.struct.ec_key_st */
            	1376, 0,
            0, 56, 4, /* 1376: struct.ec_key_st */
            	1387, 8,
            	1821, 16,
            	1826, 24,
            	1836, 48,
            1, 8, 1, /* 1387: pointer.struct.ec_group_st */
            	1392, 0,
            0, 232, 12, /* 1392: struct.ec_group_st */
            	1419, 0,
            	1591, 8,
            	1784, 16,
            	1784, 40,
            	160, 80,
            	1789, 96,
            	1784, 104,
            	1784, 152,
            	1784, 176,
            	58, 208,
            	58, 216,
            	1818, 224,
            1, 8, 1, /* 1419: pointer.struct.ec_method_st */
            	1424, 0,
            0, 304, 37, /* 1424: struct.ec_method_st */
            	1501, 8,
            	1504, 16,
            	1504, 24,
            	1507, 32,
            	1510, 40,
            	1513, 48,
            	1516, 56,
            	1519, 64,
            	1522, 72,
            	1525, 80,
            	1525, 88,
            	1528, 96,
            	1531, 104,
            	1534, 112,
            	1537, 120,
            	1540, 128,
            	1543, 136,
            	1546, 144,
            	1549, 152,
            	1552, 160,
            	1555, 168,
            	1558, 176,
            	1561, 184,
            	1564, 192,
            	1567, 200,
            	1570, 208,
            	1561, 216,
            	1573, 224,
            	1576, 232,
            	1579, 240,
            	1516, 248,
            	1582, 256,
            	1585, 264,
            	1582, 272,
            	1585, 280,
            	1585, 288,
            	1588, 296,
            8884097, 8, 0, /* 1501: pointer.func */
            8884097, 8, 0, /* 1504: pointer.func */
            8884097, 8, 0, /* 1507: pointer.func */
            8884097, 8, 0, /* 1510: pointer.func */
            8884097, 8, 0, /* 1513: pointer.func */
            8884097, 8, 0, /* 1516: pointer.func */
            8884097, 8, 0, /* 1519: pointer.func */
            8884097, 8, 0, /* 1522: pointer.func */
            8884097, 8, 0, /* 1525: pointer.func */
            8884097, 8, 0, /* 1528: pointer.func */
            8884097, 8, 0, /* 1531: pointer.func */
            8884097, 8, 0, /* 1534: pointer.func */
            8884097, 8, 0, /* 1537: pointer.func */
            8884097, 8, 0, /* 1540: pointer.func */
            8884097, 8, 0, /* 1543: pointer.func */
            8884097, 8, 0, /* 1546: pointer.func */
            8884097, 8, 0, /* 1549: pointer.func */
            8884097, 8, 0, /* 1552: pointer.func */
            8884097, 8, 0, /* 1555: pointer.func */
            8884097, 8, 0, /* 1558: pointer.func */
            8884097, 8, 0, /* 1561: pointer.func */
            8884097, 8, 0, /* 1564: pointer.func */
            8884097, 8, 0, /* 1567: pointer.func */
            8884097, 8, 0, /* 1570: pointer.func */
            8884097, 8, 0, /* 1573: pointer.func */
            8884097, 8, 0, /* 1576: pointer.func */
            8884097, 8, 0, /* 1579: pointer.func */
            8884097, 8, 0, /* 1582: pointer.func */
            8884097, 8, 0, /* 1585: pointer.func */
            8884097, 8, 0, /* 1588: pointer.func */
            1, 8, 1, /* 1591: pointer.struct.ec_point_st */
            	1596, 0,
            0, 88, 4, /* 1596: struct.ec_point_st */
            	1607, 0,
            	1779, 8,
            	1779, 32,
            	1779, 56,
            1, 8, 1, /* 1607: pointer.struct.ec_method_st */
            	1612, 0,
            0, 304, 37, /* 1612: struct.ec_method_st */
            	1689, 8,
            	1692, 16,
            	1692, 24,
            	1695, 32,
            	1698, 40,
            	1701, 48,
            	1704, 56,
            	1707, 64,
            	1710, 72,
            	1713, 80,
            	1713, 88,
            	1716, 96,
            	1719, 104,
            	1722, 112,
            	1725, 120,
            	1728, 128,
            	1731, 136,
            	1734, 144,
            	1737, 152,
            	1740, 160,
            	1743, 168,
            	1746, 176,
            	1749, 184,
            	1752, 192,
            	1755, 200,
            	1758, 208,
            	1749, 216,
            	1761, 224,
            	1764, 232,
            	1767, 240,
            	1704, 248,
            	1770, 256,
            	1773, 264,
            	1770, 272,
            	1773, 280,
            	1773, 288,
            	1776, 296,
            8884097, 8, 0, /* 1689: pointer.func */
            8884097, 8, 0, /* 1692: pointer.func */
            8884097, 8, 0, /* 1695: pointer.func */
            8884097, 8, 0, /* 1698: pointer.func */
            8884097, 8, 0, /* 1701: pointer.func */
            8884097, 8, 0, /* 1704: pointer.func */
            8884097, 8, 0, /* 1707: pointer.func */
            8884097, 8, 0, /* 1710: pointer.func */
            8884097, 8, 0, /* 1713: pointer.func */
            8884097, 8, 0, /* 1716: pointer.func */
            8884097, 8, 0, /* 1719: pointer.func */
            8884097, 8, 0, /* 1722: pointer.func */
            8884097, 8, 0, /* 1725: pointer.func */
            8884097, 8, 0, /* 1728: pointer.func */
            8884097, 8, 0, /* 1731: pointer.func */
            8884097, 8, 0, /* 1734: pointer.func */
            8884097, 8, 0, /* 1737: pointer.func */
            8884097, 8, 0, /* 1740: pointer.func */
            8884097, 8, 0, /* 1743: pointer.func */
            8884097, 8, 0, /* 1746: pointer.func */
            8884097, 8, 0, /* 1749: pointer.func */
            8884097, 8, 0, /* 1752: pointer.func */
            8884097, 8, 0, /* 1755: pointer.func */
            8884097, 8, 0, /* 1758: pointer.func */
            8884097, 8, 0, /* 1761: pointer.func */
            8884097, 8, 0, /* 1764: pointer.func */
            8884097, 8, 0, /* 1767: pointer.func */
            8884097, 8, 0, /* 1770: pointer.func */
            8884097, 8, 0, /* 1773: pointer.func */
            8884097, 8, 0, /* 1776: pointer.func */
            0, 24, 1, /* 1779: struct.bignum_st */
            	14, 0,
            0, 24, 1, /* 1784: struct.bignum_st */
            	14, 0,
            1, 8, 1, /* 1789: pointer.struct.ec_extra_data_st */
            	1794, 0,
            0, 40, 5, /* 1794: struct.ec_extra_data_st */
            	1807, 0,
            	58, 8,
            	1812, 16,
            	1815, 24,
            	1815, 32,
            1, 8, 1, /* 1807: pointer.struct.ec_extra_data_st */
            	1794, 0,
            8884097, 8, 0, /* 1812: pointer.func */
            8884097, 8, 0, /* 1815: pointer.func */
            8884097, 8, 0, /* 1818: pointer.func */
            1, 8, 1, /* 1821: pointer.struct.ec_point_st */
            	1596, 0,
            1, 8, 1, /* 1826: pointer.struct.bignum_st */
            	1831, 0,
            0, 24, 1, /* 1831: struct.bignum_st */
            	14, 0,
            1, 8, 1, /* 1836: pointer.struct.ec_extra_data_st */
            	1841, 0,
            0, 40, 5, /* 1841: struct.ec_extra_data_st */
            	1854, 0,
            	58, 8,
            	1812, 16,
            	1815, 24,
            	1815, 32,
            1, 8, 1, /* 1854: pointer.struct.ec_extra_data_st */
            	1841, 0,
            0, 56, 4, /* 1859: struct.evp_pkey_st */
            	1870, 16,
            	1971, 24,
            	1226, 32,
            	829, 48,
            1, 8, 1, /* 1870: pointer.struct.evp_pkey_asn1_method_st */
            	1875, 0,
            0, 208, 24, /* 1875: struct.evp_pkey_asn1_method_st */
            	70, 16,
            	70, 24,
            	1926, 32,
            	1929, 40,
            	1932, 48,
            	1935, 56,
            	1938, 64,
            	1941, 72,
            	1935, 80,
            	1944, 88,
            	1944, 96,
            	1947, 104,
            	1950, 112,
            	1944, 120,
            	1953, 128,
            	1932, 136,
            	1935, 144,
            	1956, 152,
            	1959, 160,
            	1962, 168,
            	1947, 176,
            	1950, 184,
            	1965, 192,
            	1968, 200,
            8884097, 8, 0, /* 1926: pointer.func */
            8884097, 8, 0, /* 1929: pointer.func */
            8884097, 8, 0, /* 1932: pointer.func */
            8884097, 8, 0, /* 1935: pointer.func */
            8884097, 8, 0, /* 1938: pointer.func */
            8884097, 8, 0, /* 1941: pointer.func */
            8884097, 8, 0, /* 1944: pointer.func */
            8884097, 8, 0, /* 1947: pointer.func */
            8884097, 8, 0, /* 1950: pointer.func */
            8884097, 8, 0, /* 1953: pointer.func */
            8884097, 8, 0, /* 1956: pointer.func */
            8884097, 8, 0, /* 1959: pointer.func */
            8884097, 8, 0, /* 1962: pointer.func */
            8884097, 8, 0, /* 1965: pointer.func */
            8884097, 8, 0, /* 1968: pointer.func */
            1, 8, 1, /* 1971: pointer.struct.engine_st */
            	244, 0,
            1, 8, 1, /* 1976: pointer.struct.asn1_string_st */
            	1981, 0,
            0, 24, 1, /* 1981: struct.asn1_string_st */
            	160, 8,
            1, 8, 1, /* 1986: pointer.struct.stack_st_ASN1_OBJECT */
            	1991, 0,
            0, 32, 2, /* 1991: struct.stack_st_fake_ASN1_OBJECT */
            	1998, 8,
            	195, 24,
            8884099, 8, 2, /* 1998: pointer_to_array_of_pointers_to_stack */
            	2005, 0,
            	1072, 20,
            0, 8, 1, /* 2005: pointer.ASN1_OBJECT */
            	2010, 0,
            0, 0, 1, /* 2010: ASN1_OBJECT */
            	2015, 0,
            0, 40, 3, /* 2015: struct.asn1_object_st */
            	222, 0,
            	222, 8,
            	879, 24,
            1, 8, 1, /* 2024: pointer.struct.asn1_string_st */
            	1981, 0,
            0, 32, 2, /* 2029: struct.stack_st */
            	190, 8,
            	195, 24,
            0, 32, 1, /* 2036: struct.stack_st_void */
            	2029, 0,
            0, 24, 1, /* 2041: struct.ASN1_ENCODING_st */
            	160, 0,
            1, 8, 1, /* 2046: pointer.struct.stack_st_X509_EXTENSION */
            	2051, 0,
            0, 32, 2, /* 2051: struct.stack_st_fake_X509_EXTENSION */
            	2058, 8,
            	195, 24,
            8884099, 8, 2, /* 2058: pointer_to_array_of_pointers_to_stack */
            	2065, 0,
            	1072, 20,
            0, 8, 1, /* 2065: pointer.X509_EXTENSION */
            	2070, 0,
            0, 0, 1, /* 2070: X509_EXTENSION */
            	2075, 0,
            0, 24, 2, /* 2075: struct.X509_extension_st */
            	2082, 0,
            	2096, 16,
            1, 8, 1, /* 2082: pointer.struct.asn1_object_st */
            	2087, 0,
            0, 40, 3, /* 2087: struct.asn1_object_st */
            	222, 0,
            	222, 8,
            	879, 24,
            1, 8, 1, /* 2096: pointer.struct.asn1_string_st */
            	2101, 0,
            0, 24, 1, /* 2101: struct.asn1_string_st */
            	160, 8,
            1, 8, 1, /* 2106: pointer.struct.X509_pubkey_st */
            	2111, 0,
            0, 24, 3, /* 2111: struct.X509_pubkey_st */
            	2120, 0,
            	2287, 8,
            	2297, 16,
            1, 8, 1, /* 2120: pointer.struct.X509_algor_st */
            	2125, 0,
            0, 16, 2, /* 2125: struct.X509_algor_st */
            	2132, 0,
            	2146, 8,
            1, 8, 1, /* 2132: pointer.struct.asn1_object_st */
            	2137, 0,
            0, 40, 3, /* 2137: struct.asn1_object_st */
            	222, 0,
            	222, 8,
            	879, 24,
            1, 8, 1, /* 2146: pointer.struct.asn1_type_st */
            	2151, 0,
            0, 16, 1, /* 2151: struct.asn1_type_st */
            	2156, 8,
            0, 8, 20, /* 2156: union.unknown */
            	70, 0,
            	2199, 0,
            	2132, 0,
            	2209, 0,
            	2214, 0,
            	2219, 0,
            	2224, 0,
            	2229, 0,
            	2234, 0,
            	2239, 0,
            	2244, 0,
            	2249, 0,
            	2254, 0,
            	2259, 0,
            	2264, 0,
            	2269, 0,
            	2274, 0,
            	2199, 0,
            	2199, 0,
            	2279, 0,
            1, 8, 1, /* 2199: pointer.struct.asn1_string_st */
            	2204, 0,
            0, 24, 1, /* 2204: struct.asn1_string_st */
            	160, 8,
            1, 8, 1, /* 2209: pointer.struct.asn1_string_st */
            	2204, 0,
            1, 8, 1, /* 2214: pointer.struct.asn1_string_st */
            	2204, 0,
            1, 8, 1, /* 2219: pointer.struct.asn1_string_st */
            	2204, 0,
            1, 8, 1, /* 2224: pointer.struct.asn1_string_st */
            	2204, 0,
            1, 8, 1, /* 2229: pointer.struct.asn1_string_st */
            	2204, 0,
            1, 8, 1, /* 2234: pointer.struct.asn1_string_st */
            	2204, 0,
            1, 8, 1, /* 2239: pointer.struct.asn1_string_st */
            	2204, 0,
            1, 8, 1, /* 2244: pointer.struct.asn1_string_st */
            	2204, 0,
            1, 8, 1, /* 2249: pointer.struct.asn1_string_st */
            	2204, 0,
            1, 8, 1, /* 2254: pointer.struct.asn1_string_st */
            	2204, 0,
            1, 8, 1, /* 2259: pointer.struct.asn1_string_st */
            	2204, 0,
            1, 8, 1, /* 2264: pointer.struct.asn1_string_st */
            	2204, 0,
            1, 8, 1, /* 2269: pointer.struct.asn1_string_st */
            	2204, 0,
            1, 8, 1, /* 2274: pointer.struct.asn1_string_st */
            	2204, 0,
            1, 8, 1, /* 2279: pointer.struct.ASN1_VALUE_st */
            	2284, 0,
            0, 0, 0, /* 2284: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2287: pointer.struct.asn1_string_st */
            	2292, 0,
            0, 24, 1, /* 2292: struct.asn1_string_st */
            	160, 8,
            1, 8, 1, /* 2297: pointer.struct.evp_pkey_st */
            	2302, 0,
            0, 56, 4, /* 2302: struct.evp_pkey_st */
            	2313, 16,
            	1366, 24,
            	2318, 32,
            	2351, 48,
            1, 8, 1, /* 2313: pointer.struct.evp_pkey_asn1_method_st */
            	1875, 0,
            0, 8, 5, /* 2318: union.unknown */
            	70, 0,
            	2331, 0,
            	2336, 0,
            	2341, 0,
            	2346, 0,
            1, 8, 1, /* 2331: pointer.struct.rsa_st */
            	592, 0,
            1, 8, 1, /* 2336: pointer.struct.dsa_st */
            	1244, 0,
            1, 8, 1, /* 2341: pointer.struct.dh_st */
            	109, 0,
            1, 8, 1, /* 2346: pointer.struct.ec_key_st */
            	1376, 0,
            1, 8, 1, /* 2351: pointer.struct.stack_st_X509_ATTRIBUTE */
            	2356, 0,
            0, 32, 2, /* 2356: struct.stack_st_fake_X509_ATTRIBUTE */
            	2363, 8,
            	195, 24,
            8884099, 8, 2, /* 2363: pointer_to_array_of_pointers_to_stack */
            	2370, 0,
            	1072, 20,
            0, 8, 1, /* 2370: pointer.X509_ATTRIBUTE */
            	853, 0,
            1, 8, 1, /* 2375: pointer.struct.buf_mem_st */
            	2380, 0,
            0, 24, 1, /* 2380: struct.buf_mem_st */
            	70, 8,
            0, 104, 11, /* 2385: struct.x509_cinf_st */
            	2410, 0,
            	2410, 8,
            	2415, 16,
            	2420, 24,
            	2494, 32,
            	2420, 40,
            	2106, 48,
            	2511, 56,
            	2511, 64,
            	2046, 72,
            	2041, 80,
            1, 8, 1, /* 2410: pointer.struct.asn1_string_st */
            	1981, 0,
            1, 8, 1, /* 2415: pointer.struct.X509_algor_st */
            	2125, 0,
            1, 8, 1, /* 2420: pointer.struct.X509_name_st */
            	2425, 0,
            0, 40, 3, /* 2425: struct.X509_name_st */
            	2434, 0,
            	2375, 16,
            	160, 24,
            1, 8, 1, /* 2434: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2439, 0,
            0, 32, 2, /* 2439: struct.stack_st_fake_X509_NAME_ENTRY */
            	2446, 8,
            	195, 24,
            8884099, 8, 2, /* 2446: pointer_to_array_of_pointers_to_stack */
            	2453, 0,
            	1072, 20,
            0, 8, 1, /* 2453: pointer.X509_NAME_ENTRY */
            	2458, 0,
            0, 0, 1, /* 2458: X509_NAME_ENTRY */
            	2463, 0,
            0, 24, 2, /* 2463: struct.X509_name_entry_st */
            	2470, 0,
            	2484, 8,
            1, 8, 1, /* 2470: pointer.struct.asn1_object_st */
            	2475, 0,
            0, 40, 3, /* 2475: struct.asn1_object_st */
            	222, 0,
            	222, 8,
            	879, 24,
            1, 8, 1, /* 2484: pointer.struct.asn1_string_st */
            	2489, 0,
            0, 24, 1, /* 2489: struct.asn1_string_st */
            	160, 8,
            1, 8, 1, /* 2494: pointer.struct.X509_val_st */
            	2499, 0,
            0, 16, 2, /* 2499: struct.X509_val_st */
            	2506, 0,
            	2506, 8,
            1, 8, 1, /* 2506: pointer.struct.asn1_string_st */
            	1981, 0,
            1, 8, 1, /* 2511: pointer.struct.asn1_string_st */
            	1981, 0,
            0, 184, 12, /* 2516: struct.x509_st */
            	2543, 0,
            	2415, 8,
            	2511, 16,
            	70, 32,
            	2548, 40,
            	2024, 104,
            	2558, 112,
            	2881, 120,
            	3303, 128,
            	3442, 136,
            	3466, 144,
            	3778, 176,
            1, 8, 1, /* 2543: pointer.struct.x509_cinf_st */
            	2385, 0,
            0, 16, 1, /* 2548: struct.crypto_ex_data_st */
            	2553, 0,
            1, 8, 1, /* 2553: pointer.struct.stack_st_void */
            	2036, 0,
            1, 8, 1, /* 2558: pointer.struct.AUTHORITY_KEYID_st */
            	2563, 0,
            0, 24, 3, /* 2563: struct.AUTHORITY_KEYID_st */
            	2572, 0,
            	2582, 8,
            	2876, 16,
            1, 8, 1, /* 2572: pointer.struct.asn1_string_st */
            	2577, 0,
            0, 24, 1, /* 2577: struct.asn1_string_st */
            	160, 8,
            1, 8, 1, /* 2582: pointer.struct.stack_st_GENERAL_NAME */
            	2587, 0,
            0, 32, 2, /* 2587: struct.stack_st_fake_GENERAL_NAME */
            	2594, 8,
            	195, 24,
            8884099, 8, 2, /* 2594: pointer_to_array_of_pointers_to_stack */
            	2601, 0,
            	1072, 20,
            0, 8, 1, /* 2601: pointer.GENERAL_NAME */
            	2606, 0,
            0, 0, 1, /* 2606: GENERAL_NAME */
            	2611, 0,
            0, 16, 1, /* 2611: struct.GENERAL_NAME_st */
            	2616, 8,
            0, 8, 15, /* 2616: union.unknown */
            	70, 0,
            	2649, 0,
            	2768, 0,
            	2768, 0,
            	2675, 0,
            	2816, 0,
            	2864, 0,
            	2768, 0,
            	2753, 0,
            	2661, 0,
            	2753, 0,
            	2816, 0,
            	2768, 0,
            	2661, 0,
            	2675, 0,
            1, 8, 1, /* 2649: pointer.struct.otherName_st */
            	2654, 0,
            0, 16, 2, /* 2654: struct.otherName_st */
            	2661, 0,
            	2675, 8,
            1, 8, 1, /* 2661: pointer.struct.asn1_object_st */
            	2666, 0,
            0, 40, 3, /* 2666: struct.asn1_object_st */
            	222, 0,
            	222, 8,
            	879, 24,
            1, 8, 1, /* 2675: pointer.struct.asn1_type_st */
            	2680, 0,
            0, 16, 1, /* 2680: struct.asn1_type_st */
            	2685, 8,
            0, 8, 20, /* 2685: union.unknown */
            	70, 0,
            	2728, 0,
            	2661, 0,
            	2738, 0,
            	2743, 0,
            	2748, 0,
            	2753, 0,
            	2758, 0,
            	2763, 0,
            	2768, 0,
            	2773, 0,
            	2778, 0,
            	2783, 0,
            	2788, 0,
            	2793, 0,
            	2798, 0,
            	2803, 0,
            	2728, 0,
            	2728, 0,
            	2808, 0,
            1, 8, 1, /* 2728: pointer.struct.asn1_string_st */
            	2733, 0,
            0, 24, 1, /* 2733: struct.asn1_string_st */
            	160, 8,
            1, 8, 1, /* 2738: pointer.struct.asn1_string_st */
            	2733, 0,
            1, 8, 1, /* 2743: pointer.struct.asn1_string_st */
            	2733, 0,
            1, 8, 1, /* 2748: pointer.struct.asn1_string_st */
            	2733, 0,
            1, 8, 1, /* 2753: pointer.struct.asn1_string_st */
            	2733, 0,
            1, 8, 1, /* 2758: pointer.struct.asn1_string_st */
            	2733, 0,
            1, 8, 1, /* 2763: pointer.struct.asn1_string_st */
            	2733, 0,
            1, 8, 1, /* 2768: pointer.struct.asn1_string_st */
            	2733, 0,
            1, 8, 1, /* 2773: pointer.struct.asn1_string_st */
            	2733, 0,
            1, 8, 1, /* 2778: pointer.struct.asn1_string_st */
            	2733, 0,
            1, 8, 1, /* 2783: pointer.struct.asn1_string_st */
            	2733, 0,
            1, 8, 1, /* 2788: pointer.struct.asn1_string_st */
            	2733, 0,
            1, 8, 1, /* 2793: pointer.struct.asn1_string_st */
            	2733, 0,
            1, 8, 1, /* 2798: pointer.struct.asn1_string_st */
            	2733, 0,
            1, 8, 1, /* 2803: pointer.struct.asn1_string_st */
            	2733, 0,
            1, 8, 1, /* 2808: pointer.struct.ASN1_VALUE_st */
            	2813, 0,
            0, 0, 0, /* 2813: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2816: pointer.struct.X509_name_st */
            	2821, 0,
            0, 40, 3, /* 2821: struct.X509_name_st */
            	2830, 0,
            	2854, 16,
            	160, 24,
            1, 8, 1, /* 2830: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2835, 0,
            0, 32, 2, /* 2835: struct.stack_st_fake_X509_NAME_ENTRY */
            	2842, 8,
            	195, 24,
            8884099, 8, 2, /* 2842: pointer_to_array_of_pointers_to_stack */
            	2849, 0,
            	1072, 20,
            0, 8, 1, /* 2849: pointer.X509_NAME_ENTRY */
            	2458, 0,
            1, 8, 1, /* 2854: pointer.struct.buf_mem_st */
            	2859, 0,
            0, 24, 1, /* 2859: struct.buf_mem_st */
            	70, 8,
            1, 8, 1, /* 2864: pointer.struct.EDIPartyName_st */
            	2869, 0,
            0, 16, 2, /* 2869: struct.EDIPartyName_st */
            	2728, 0,
            	2728, 8,
            1, 8, 1, /* 2876: pointer.struct.asn1_string_st */
            	2577, 0,
            1, 8, 1, /* 2881: pointer.struct.X509_POLICY_CACHE_st */
            	2886, 0,
            0, 40, 2, /* 2886: struct.X509_POLICY_CACHE_st */
            	2893, 0,
            	3203, 8,
            1, 8, 1, /* 2893: pointer.struct.X509_POLICY_DATA_st */
            	2898, 0,
            0, 32, 3, /* 2898: struct.X509_POLICY_DATA_st */
            	2907, 8,
            	2921, 16,
            	3179, 24,
            1, 8, 1, /* 2907: pointer.struct.asn1_object_st */
            	2912, 0,
            0, 40, 3, /* 2912: struct.asn1_object_st */
            	222, 0,
            	222, 8,
            	879, 24,
            1, 8, 1, /* 2921: pointer.struct.stack_st_POLICYQUALINFO */
            	2926, 0,
            0, 32, 2, /* 2926: struct.stack_st_fake_POLICYQUALINFO */
            	2933, 8,
            	195, 24,
            8884099, 8, 2, /* 2933: pointer_to_array_of_pointers_to_stack */
            	2940, 0,
            	1072, 20,
            0, 8, 1, /* 2940: pointer.POLICYQUALINFO */
            	2945, 0,
            0, 0, 1, /* 2945: POLICYQUALINFO */
            	2950, 0,
            0, 16, 2, /* 2950: struct.POLICYQUALINFO_st */
            	2957, 0,
            	2971, 8,
            1, 8, 1, /* 2957: pointer.struct.asn1_object_st */
            	2962, 0,
            0, 40, 3, /* 2962: struct.asn1_object_st */
            	222, 0,
            	222, 8,
            	879, 24,
            0, 8, 3, /* 2971: union.unknown */
            	2980, 0,
            	2990, 0,
            	3053, 0,
            1, 8, 1, /* 2980: pointer.struct.asn1_string_st */
            	2985, 0,
            0, 24, 1, /* 2985: struct.asn1_string_st */
            	160, 8,
            1, 8, 1, /* 2990: pointer.struct.USERNOTICE_st */
            	2995, 0,
            0, 16, 2, /* 2995: struct.USERNOTICE_st */
            	3002, 0,
            	3014, 8,
            1, 8, 1, /* 3002: pointer.struct.NOTICEREF_st */
            	3007, 0,
            0, 16, 2, /* 3007: struct.NOTICEREF_st */
            	3014, 0,
            	3019, 8,
            1, 8, 1, /* 3014: pointer.struct.asn1_string_st */
            	2985, 0,
            1, 8, 1, /* 3019: pointer.struct.stack_st_ASN1_INTEGER */
            	3024, 0,
            0, 32, 2, /* 3024: struct.stack_st_fake_ASN1_INTEGER */
            	3031, 8,
            	195, 24,
            8884099, 8, 2, /* 3031: pointer_to_array_of_pointers_to_stack */
            	3038, 0,
            	1072, 20,
            0, 8, 1, /* 3038: pointer.ASN1_INTEGER */
            	3043, 0,
            0, 0, 1, /* 3043: ASN1_INTEGER */
            	3048, 0,
            0, 24, 1, /* 3048: struct.asn1_string_st */
            	160, 8,
            1, 8, 1, /* 3053: pointer.struct.asn1_type_st */
            	3058, 0,
            0, 16, 1, /* 3058: struct.asn1_type_st */
            	3063, 8,
            0, 8, 20, /* 3063: union.unknown */
            	70, 0,
            	3014, 0,
            	2957, 0,
            	3106, 0,
            	3111, 0,
            	3116, 0,
            	3121, 0,
            	3126, 0,
            	3131, 0,
            	2980, 0,
            	3136, 0,
            	3141, 0,
            	3146, 0,
            	3151, 0,
            	3156, 0,
            	3161, 0,
            	3166, 0,
            	3014, 0,
            	3014, 0,
            	3171, 0,
            1, 8, 1, /* 3106: pointer.struct.asn1_string_st */
            	2985, 0,
            1, 8, 1, /* 3111: pointer.struct.asn1_string_st */
            	2985, 0,
            1, 8, 1, /* 3116: pointer.struct.asn1_string_st */
            	2985, 0,
            1, 8, 1, /* 3121: pointer.struct.asn1_string_st */
            	2985, 0,
            1, 8, 1, /* 3126: pointer.struct.asn1_string_st */
            	2985, 0,
            1, 8, 1, /* 3131: pointer.struct.asn1_string_st */
            	2985, 0,
            1, 8, 1, /* 3136: pointer.struct.asn1_string_st */
            	2985, 0,
            1, 8, 1, /* 3141: pointer.struct.asn1_string_st */
            	2985, 0,
            1, 8, 1, /* 3146: pointer.struct.asn1_string_st */
            	2985, 0,
            1, 8, 1, /* 3151: pointer.struct.asn1_string_st */
            	2985, 0,
            1, 8, 1, /* 3156: pointer.struct.asn1_string_st */
            	2985, 0,
            1, 8, 1, /* 3161: pointer.struct.asn1_string_st */
            	2985, 0,
            1, 8, 1, /* 3166: pointer.struct.asn1_string_st */
            	2985, 0,
            1, 8, 1, /* 3171: pointer.struct.ASN1_VALUE_st */
            	3176, 0,
            0, 0, 0, /* 3176: struct.ASN1_VALUE_st */
            1, 8, 1, /* 3179: pointer.struct.stack_st_ASN1_OBJECT */
            	3184, 0,
            0, 32, 2, /* 3184: struct.stack_st_fake_ASN1_OBJECT */
            	3191, 8,
            	195, 24,
            8884099, 8, 2, /* 3191: pointer_to_array_of_pointers_to_stack */
            	3198, 0,
            	1072, 20,
            0, 8, 1, /* 3198: pointer.ASN1_OBJECT */
            	2010, 0,
            1, 8, 1, /* 3203: pointer.struct.stack_st_X509_POLICY_DATA */
            	3208, 0,
            0, 32, 2, /* 3208: struct.stack_st_fake_X509_POLICY_DATA */
            	3215, 8,
            	195, 24,
            8884099, 8, 2, /* 3215: pointer_to_array_of_pointers_to_stack */
            	3222, 0,
            	1072, 20,
            0, 8, 1, /* 3222: pointer.X509_POLICY_DATA */
            	3227, 0,
            0, 0, 1, /* 3227: X509_POLICY_DATA */
            	3232, 0,
            0, 32, 3, /* 3232: struct.X509_POLICY_DATA_st */
            	3241, 8,
            	3255, 16,
            	3279, 24,
            1, 8, 1, /* 3241: pointer.struct.asn1_object_st */
            	3246, 0,
            0, 40, 3, /* 3246: struct.asn1_object_st */
            	222, 0,
            	222, 8,
            	879, 24,
            1, 8, 1, /* 3255: pointer.struct.stack_st_POLICYQUALINFO */
            	3260, 0,
            0, 32, 2, /* 3260: struct.stack_st_fake_POLICYQUALINFO */
            	3267, 8,
            	195, 24,
            8884099, 8, 2, /* 3267: pointer_to_array_of_pointers_to_stack */
            	3274, 0,
            	1072, 20,
            0, 8, 1, /* 3274: pointer.POLICYQUALINFO */
            	2945, 0,
            1, 8, 1, /* 3279: pointer.struct.stack_st_ASN1_OBJECT */
            	3284, 0,
            0, 32, 2, /* 3284: struct.stack_st_fake_ASN1_OBJECT */
            	3291, 8,
            	195, 24,
            8884099, 8, 2, /* 3291: pointer_to_array_of_pointers_to_stack */
            	3298, 0,
            	1072, 20,
            0, 8, 1, /* 3298: pointer.ASN1_OBJECT */
            	2010, 0,
            1, 8, 1, /* 3303: pointer.struct.stack_st_DIST_POINT */
            	3308, 0,
            0, 32, 2, /* 3308: struct.stack_st_fake_DIST_POINT */
            	3315, 8,
            	195, 24,
            8884099, 8, 2, /* 3315: pointer_to_array_of_pointers_to_stack */
            	3322, 0,
            	1072, 20,
            0, 8, 1, /* 3322: pointer.DIST_POINT */
            	3327, 0,
            0, 0, 1, /* 3327: DIST_POINT */
            	3332, 0,
            0, 32, 3, /* 3332: struct.DIST_POINT_st */
            	3341, 0,
            	3432, 8,
            	3360, 16,
            1, 8, 1, /* 3341: pointer.struct.DIST_POINT_NAME_st */
            	3346, 0,
            0, 24, 2, /* 3346: struct.DIST_POINT_NAME_st */
            	3353, 8,
            	3408, 16,
            0, 8, 2, /* 3353: union.unknown */
            	3360, 0,
            	3384, 0,
            1, 8, 1, /* 3360: pointer.struct.stack_st_GENERAL_NAME */
            	3365, 0,
            0, 32, 2, /* 3365: struct.stack_st_fake_GENERAL_NAME */
            	3372, 8,
            	195, 24,
            8884099, 8, 2, /* 3372: pointer_to_array_of_pointers_to_stack */
            	3379, 0,
            	1072, 20,
            0, 8, 1, /* 3379: pointer.GENERAL_NAME */
            	2606, 0,
            1, 8, 1, /* 3384: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3389, 0,
            0, 32, 2, /* 3389: struct.stack_st_fake_X509_NAME_ENTRY */
            	3396, 8,
            	195, 24,
            8884099, 8, 2, /* 3396: pointer_to_array_of_pointers_to_stack */
            	3403, 0,
            	1072, 20,
            0, 8, 1, /* 3403: pointer.X509_NAME_ENTRY */
            	2458, 0,
            1, 8, 1, /* 3408: pointer.struct.X509_name_st */
            	3413, 0,
            0, 40, 3, /* 3413: struct.X509_name_st */
            	3384, 0,
            	3422, 16,
            	160, 24,
            1, 8, 1, /* 3422: pointer.struct.buf_mem_st */
            	3427, 0,
            0, 24, 1, /* 3427: struct.buf_mem_st */
            	70, 8,
            1, 8, 1, /* 3432: pointer.struct.asn1_string_st */
            	3437, 0,
            0, 24, 1, /* 3437: struct.asn1_string_st */
            	160, 8,
            1, 8, 1, /* 3442: pointer.struct.stack_st_GENERAL_NAME */
            	3447, 0,
            0, 32, 2, /* 3447: struct.stack_st_fake_GENERAL_NAME */
            	3454, 8,
            	195, 24,
            8884099, 8, 2, /* 3454: pointer_to_array_of_pointers_to_stack */
            	3461, 0,
            	1072, 20,
            0, 8, 1, /* 3461: pointer.GENERAL_NAME */
            	2606, 0,
            1, 8, 1, /* 3466: pointer.struct.NAME_CONSTRAINTS_st */
            	3471, 0,
            0, 16, 2, /* 3471: struct.NAME_CONSTRAINTS_st */
            	3478, 0,
            	3478, 8,
            1, 8, 1, /* 3478: pointer.struct.stack_st_GENERAL_SUBTREE */
            	3483, 0,
            0, 32, 2, /* 3483: struct.stack_st_fake_GENERAL_SUBTREE */
            	3490, 8,
            	195, 24,
            8884099, 8, 2, /* 3490: pointer_to_array_of_pointers_to_stack */
            	3497, 0,
            	1072, 20,
            0, 8, 1, /* 3497: pointer.GENERAL_SUBTREE */
            	3502, 0,
            0, 0, 1, /* 3502: GENERAL_SUBTREE */
            	3507, 0,
            0, 24, 3, /* 3507: struct.GENERAL_SUBTREE_st */
            	3516, 0,
            	3648, 8,
            	3648, 16,
            1, 8, 1, /* 3516: pointer.struct.GENERAL_NAME_st */
            	3521, 0,
            0, 16, 1, /* 3521: struct.GENERAL_NAME_st */
            	3526, 8,
            0, 8, 15, /* 3526: union.unknown */
            	70, 0,
            	3559, 0,
            	3678, 0,
            	3678, 0,
            	3585, 0,
            	3718, 0,
            	3766, 0,
            	3678, 0,
            	3663, 0,
            	3571, 0,
            	3663, 0,
            	3718, 0,
            	3678, 0,
            	3571, 0,
            	3585, 0,
            1, 8, 1, /* 3559: pointer.struct.otherName_st */
            	3564, 0,
            0, 16, 2, /* 3564: struct.otherName_st */
            	3571, 0,
            	3585, 8,
            1, 8, 1, /* 3571: pointer.struct.asn1_object_st */
            	3576, 0,
            0, 40, 3, /* 3576: struct.asn1_object_st */
            	222, 0,
            	222, 8,
            	879, 24,
            1, 8, 1, /* 3585: pointer.struct.asn1_type_st */
            	3590, 0,
            0, 16, 1, /* 3590: struct.asn1_type_st */
            	3595, 8,
            0, 8, 20, /* 3595: union.unknown */
            	70, 0,
            	3638, 0,
            	3571, 0,
            	3648, 0,
            	3653, 0,
            	3658, 0,
            	3663, 0,
            	3668, 0,
            	3673, 0,
            	3678, 0,
            	3683, 0,
            	3688, 0,
            	3693, 0,
            	3698, 0,
            	3703, 0,
            	3708, 0,
            	3713, 0,
            	3638, 0,
            	3638, 0,
            	3171, 0,
            1, 8, 1, /* 3638: pointer.struct.asn1_string_st */
            	3643, 0,
            0, 24, 1, /* 3643: struct.asn1_string_st */
            	160, 8,
            1, 8, 1, /* 3648: pointer.struct.asn1_string_st */
            	3643, 0,
            1, 8, 1, /* 3653: pointer.struct.asn1_string_st */
            	3643, 0,
            1, 8, 1, /* 3658: pointer.struct.asn1_string_st */
            	3643, 0,
            1, 8, 1, /* 3663: pointer.struct.asn1_string_st */
            	3643, 0,
            1, 8, 1, /* 3668: pointer.struct.asn1_string_st */
            	3643, 0,
            1, 8, 1, /* 3673: pointer.struct.asn1_string_st */
            	3643, 0,
            1, 8, 1, /* 3678: pointer.struct.asn1_string_st */
            	3643, 0,
            1, 8, 1, /* 3683: pointer.struct.asn1_string_st */
            	3643, 0,
            1, 8, 1, /* 3688: pointer.struct.asn1_string_st */
            	3643, 0,
            1, 8, 1, /* 3693: pointer.struct.asn1_string_st */
            	3643, 0,
            1, 8, 1, /* 3698: pointer.struct.asn1_string_st */
            	3643, 0,
            1, 8, 1, /* 3703: pointer.struct.asn1_string_st */
            	3643, 0,
            1, 8, 1, /* 3708: pointer.struct.asn1_string_st */
            	3643, 0,
            1, 8, 1, /* 3713: pointer.struct.asn1_string_st */
            	3643, 0,
            1, 8, 1, /* 3718: pointer.struct.X509_name_st */
            	3723, 0,
            0, 40, 3, /* 3723: struct.X509_name_st */
            	3732, 0,
            	3756, 16,
            	160, 24,
            1, 8, 1, /* 3732: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3737, 0,
            0, 32, 2, /* 3737: struct.stack_st_fake_X509_NAME_ENTRY */
            	3744, 8,
            	195, 24,
            8884099, 8, 2, /* 3744: pointer_to_array_of_pointers_to_stack */
            	3751, 0,
            	1072, 20,
            0, 8, 1, /* 3751: pointer.X509_NAME_ENTRY */
            	2458, 0,
            1, 8, 1, /* 3756: pointer.struct.buf_mem_st */
            	3761, 0,
            0, 24, 1, /* 3761: struct.buf_mem_st */
            	70, 8,
            1, 8, 1, /* 3766: pointer.struct.EDIPartyName_st */
            	3771, 0,
            0, 16, 2, /* 3771: struct.EDIPartyName_st */
            	3638, 0,
            	3638, 8,
            1, 8, 1, /* 3778: pointer.struct.x509_cert_aux_st */
            	3783, 0,
            0, 40, 5, /* 3783: struct.x509_cert_aux_st */
            	1986, 0,
            	1986, 8,
            	1976, 16,
            	2024, 24,
            	3796, 32,
            1, 8, 1, /* 3796: pointer.struct.stack_st_X509_ALGOR */
            	3801, 0,
            0, 32, 2, /* 3801: struct.stack_st_fake_X509_ALGOR */
            	3808, 8,
            	195, 24,
            8884099, 8, 2, /* 3808: pointer_to_array_of_pointers_to_stack */
            	3815, 0,
            	1072, 20,
            0, 8, 1, /* 3815: pointer.X509_ALGOR */
            	3820, 0,
            0, 0, 1, /* 3820: X509_ALGOR */
            	2125, 0,
            0, 24, 3, /* 3825: struct.cert_pkey_st */
            	3834, 0,
            	3839, 8,
            	790, 16,
            1, 8, 1, /* 3834: pointer.struct.x509_st */
            	2516, 0,
            1, 8, 1, /* 3839: pointer.struct.evp_pkey_st */
            	1859, 0,
            8884097, 8, 0, /* 3844: pointer.func */
            0, 0, 1, /* 3847: X509_NAME */
            	3852, 0,
            0, 40, 3, /* 3852: struct.X509_name_st */
            	3861, 0,
            	3885, 16,
            	160, 24,
            1, 8, 1, /* 3861: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3866, 0,
            0, 32, 2, /* 3866: struct.stack_st_fake_X509_NAME_ENTRY */
            	3873, 8,
            	195, 24,
            8884099, 8, 2, /* 3873: pointer_to_array_of_pointers_to_stack */
            	3880, 0,
            	1072, 20,
            0, 8, 1, /* 3880: pointer.X509_NAME_ENTRY */
            	2458, 0,
            1, 8, 1, /* 3885: pointer.struct.buf_mem_st */
            	3890, 0,
            0, 24, 1, /* 3890: struct.buf_mem_st */
            	70, 8,
            8884097, 8, 0, /* 3895: pointer.func */
            8884097, 8, 0, /* 3898: pointer.func */
            0, 64, 7, /* 3901: struct.comp_method_st */
            	222, 8,
            	3918, 16,
            	3898, 24,
            	3895, 32,
            	3895, 40,
            	3921, 48,
            	3921, 56,
            8884097, 8, 0, /* 3918: pointer.func */
            8884097, 8, 0, /* 3921: pointer.func */
            1, 8, 1, /* 3924: pointer.struct.comp_method_st */
            	3901, 0,
            0, 0, 1, /* 3929: SSL_COMP */
            	3934, 0,
            0, 24, 2, /* 3934: struct.ssl_comp_st */
            	222, 8,
            	3924, 16,
            1, 8, 1, /* 3941: pointer.struct.stack_st_SSL_COMP */
            	3946, 0,
            0, 32, 2, /* 3946: struct.stack_st_fake_SSL_COMP */
            	3953, 8,
            	195, 24,
            8884099, 8, 2, /* 3953: pointer_to_array_of_pointers_to_stack */
            	3960, 0,
            	1072, 20,
            0, 8, 1, /* 3960: pointer.SSL_COMP */
            	3929, 0,
            1, 8, 1, /* 3965: pointer.struct.stack_st_X509 */
            	3970, 0,
            0, 32, 2, /* 3970: struct.stack_st_fake_X509 */
            	3977, 8,
            	195, 24,
            8884099, 8, 2, /* 3977: pointer_to_array_of_pointers_to_stack */
            	3984, 0,
            	1072, 20,
            0, 8, 1, /* 3984: pointer.X509 */
            	3989, 0,
            0, 0, 1, /* 3989: X509 */
            	3994, 0,
            0, 184, 12, /* 3994: struct.x509_st */
            	4021, 0,
            	4061, 8,
            	4093, 16,
            	70, 32,
            	1293, 40,
            	4127, 104,
            	4132, 112,
            	4137, 120,
            	4142, 128,
            	4166, 136,
            	4190, 144,
            	4195, 176,
            1, 8, 1, /* 4021: pointer.struct.x509_cinf_st */
            	4026, 0,
            0, 104, 11, /* 4026: struct.x509_cinf_st */
            	4051, 0,
            	4051, 8,
            	4061, 16,
            	4066, 24,
            	4071, 32,
            	4066, 40,
            	4088, 48,
            	4093, 56,
            	4093, 64,
            	4098, 72,
            	4122, 80,
            1, 8, 1, /* 4051: pointer.struct.asn1_string_st */
            	4056, 0,
            0, 24, 1, /* 4056: struct.asn1_string_st */
            	160, 8,
            1, 8, 1, /* 4061: pointer.struct.X509_algor_st */
            	2125, 0,
            1, 8, 1, /* 4066: pointer.struct.X509_name_st */
            	3852, 0,
            1, 8, 1, /* 4071: pointer.struct.X509_val_st */
            	4076, 0,
            0, 16, 2, /* 4076: struct.X509_val_st */
            	4083, 0,
            	4083, 8,
            1, 8, 1, /* 4083: pointer.struct.asn1_string_st */
            	4056, 0,
            1, 8, 1, /* 4088: pointer.struct.X509_pubkey_st */
            	2111, 0,
            1, 8, 1, /* 4093: pointer.struct.asn1_string_st */
            	4056, 0,
            1, 8, 1, /* 4098: pointer.struct.stack_st_X509_EXTENSION */
            	4103, 0,
            0, 32, 2, /* 4103: struct.stack_st_fake_X509_EXTENSION */
            	4110, 8,
            	195, 24,
            8884099, 8, 2, /* 4110: pointer_to_array_of_pointers_to_stack */
            	4117, 0,
            	1072, 20,
            0, 8, 1, /* 4117: pointer.X509_EXTENSION */
            	2070, 0,
            0, 24, 1, /* 4122: struct.ASN1_ENCODING_st */
            	160, 0,
            1, 8, 1, /* 4127: pointer.struct.asn1_string_st */
            	4056, 0,
            1, 8, 1, /* 4132: pointer.struct.AUTHORITY_KEYID_st */
            	2563, 0,
            1, 8, 1, /* 4137: pointer.struct.X509_POLICY_CACHE_st */
            	2886, 0,
            1, 8, 1, /* 4142: pointer.struct.stack_st_DIST_POINT */
            	4147, 0,
            0, 32, 2, /* 4147: struct.stack_st_fake_DIST_POINT */
            	4154, 8,
            	195, 24,
            8884099, 8, 2, /* 4154: pointer_to_array_of_pointers_to_stack */
            	4161, 0,
            	1072, 20,
            0, 8, 1, /* 4161: pointer.DIST_POINT */
            	3327, 0,
            1, 8, 1, /* 4166: pointer.struct.stack_st_GENERAL_NAME */
            	4171, 0,
            0, 32, 2, /* 4171: struct.stack_st_fake_GENERAL_NAME */
            	4178, 8,
            	195, 24,
            8884099, 8, 2, /* 4178: pointer_to_array_of_pointers_to_stack */
            	4185, 0,
            	1072, 20,
            0, 8, 1, /* 4185: pointer.GENERAL_NAME */
            	2606, 0,
            1, 8, 1, /* 4190: pointer.struct.NAME_CONSTRAINTS_st */
            	3471, 0,
            1, 8, 1, /* 4195: pointer.struct.x509_cert_aux_st */
            	4200, 0,
            0, 40, 5, /* 4200: struct.x509_cert_aux_st */
            	4213, 0,
            	4213, 8,
            	4237, 16,
            	4127, 24,
            	4242, 32,
            1, 8, 1, /* 4213: pointer.struct.stack_st_ASN1_OBJECT */
            	4218, 0,
            0, 32, 2, /* 4218: struct.stack_st_fake_ASN1_OBJECT */
            	4225, 8,
            	195, 24,
            8884099, 8, 2, /* 4225: pointer_to_array_of_pointers_to_stack */
            	4232, 0,
            	1072, 20,
            0, 8, 1, /* 4232: pointer.ASN1_OBJECT */
            	2010, 0,
            1, 8, 1, /* 4237: pointer.struct.asn1_string_st */
            	4056, 0,
            1, 8, 1, /* 4242: pointer.struct.stack_st_X509_ALGOR */
            	4247, 0,
            0, 32, 2, /* 4247: struct.stack_st_fake_X509_ALGOR */
            	4254, 8,
            	195, 24,
            8884099, 8, 2, /* 4254: pointer_to_array_of_pointers_to_stack */
            	4261, 0,
            	1072, 20,
            0, 8, 1, /* 4261: pointer.X509_ALGOR */
            	3820, 0,
            8884097, 8, 0, /* 4266: pointer.func */
            0, 120, 8, /* 4269: struct.env_md_st */
            	4288, 24,
            	4291, 32,
            	4294, 40,
            	4266, 48,
            	4288, 56,
            	820, 64,
            	823, 72,
            	4297, 112,
            8884097, 8, 0, /* 4288: pointer.func */
            8884097, 8, 0, /* 4291: pointer.func */
            8884097, 8, 0, /* 4294: pointer.func */
            8884097, 8, 0, /* 4297: pointer.func */
            1, 8, 1, /* 4300: pointer.struct.env_md_st */
            	4269, 0,
            8884097, 8, 0, /* 4305: pointer.func */
            8884097, 8, 0, /* 4308: pointer.func */
            8884097, 8, 0, /* 4311: pointer.func */
            8884097, 8, 0, /* 4314: pointer.func */
            8884097, 8, 0, /* 4317: pointer.func */
            0, 88, 1, /* 4320: struct.ssl_cipher_st */
            	222, 8,
            1, 8, 1, /* 4325: pointer.struct.ssl_cipher_st */
            	4320, 0,
            1, 8, 1, /* 4330: pointer.struct.stack_st_X509_ALGOR */
            	4335, 0,
            0, 32, 2, /* 4335: struct.stack_st_fake_X509_ALGOR */
            	4342, 8,
            	195, 24,
            8884099, 8, 2, /* 4342: pointer_to_array_of_pointers_to_stack */
            	4349, 0,
            	1072, 20,
            0, 8, 1, /* 4349: pointer.X509_ALGOR */
            	3820, 0,
            1, 8, 1, /* 4354: pointer.struct.asn1_string_st */
            	4359, 0,
            0, 24, 1, /* 4359: struct.asn1_string_st */
            	160, 8,
            1, 8, 1, /* 4364: pointer.struct.asn1_string_st */
            	4359, 0,
            0, 24, 1, /* 4369: struct.ASN1_ENCODING_st */
            	160, 0,
            1, 8, 1, /* 4374: pointer.struct.X509_pubkey_st */
            	2111, 0,
            0, 16, 2, /* 4379: struct.X509_val_st */
            	4386, 0,
            	4386, 8,
            1, 8, 1, /* 4386: pointer.struct.asn1_string_st */
            	4359, 0,
            0, 24, 1, /* 4391: struct.buf_mem_st */
            	70, 8,
            0, 40, 3, /* 4396: struct.X509_name_st */
            	4405, 0,
            	4429, 16,
            	160, 24,
            1, 8, 1, /* 4405: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4410, 0,
            0, 32, 2, /* 4410: struct.stack_st_fake_X509_NAME_ENTRY */
            	4417, 8,
            	195, 24,
            8884099, 8, 2, /* 4417: pointer_to_array_of_pointers_to_stack */
            	4424, 0,
            	1072, 20,
            0, 8, 1, /* 4424: pointer.X509_NAME_ENTRY */
            	2458, 0,
            1, 8, 1, /* 4429: pointer.struct.buf_mem_st */
            	4391, 0,
            1, 8, 1, /* 4434: pointer.struct.X509_name_st */
            	4396, 0,
            1, 8, 1, /* 4439: pointer.struct.X509_algor_st */
            	2125, 0,
            1, 8, 1, /* 4444: pointer.struct.asn1_string_st */
            	4359, 0,
            0, 104, 11, /* 4449: struct.x509_cinf_st */
            	4444, 0,
            	4444, 8,
            	4439, 16,
            	4434, 24,
            	4474, 32,
            	4434, 40,
            	4374, 48,
            	4479, 56,
            	4479, 64,
            	4484, 72,
            	4369, 80,
            1, 8, 1, /* 4474: pointer.struct.X509_val_st */
            	4379, 0,
            1, 8, 1, /* 4479: pointer.struct.asn1_string_st */
            	4359, 0,
            1, 8, 1, /* 4484: pointer.struct.stack_st_X509_EXTENSION */
            	4489, 0,
            0, 32, 2, /* 4489: struct.stack_st_fake_X509_EXTENSION */
            	4496, 8,
            	195, 24,
            8884099, 8, 2, /* 4496: pointer_to_array_of_pointers_to_stack */
            	4503, 0,
            	1072, 20,
            0, 8, 1, /* 4503: pointer.X509_EXTENSION */
            	2070, 0,
            1, 8, 1, /* 4508: pointer.struct.x509_cinf_st */
            	4449, 0,
            1, 8, 1, /* 4513: pointer.struct.x509_st */
            	4518, 0,
            0, 184, 12, /* 4518: struct.x509_st */
            	4508, 0,
            	4439, 8,
            	4479, 16,
            	70, 32,
            	4545, 40,
            	4364, 104,
            	2558, 112,
            	2881, 120,
            	3303, 128,
            	3442, 136,
            	3466, 144,
            	4567, 176,
            0, 16, 1, /* 4545: struct.crypto_ex_data_st */
            	4550, 0,
            1, 8, 1, /* 4550: pointer.struct.stack_st_void */
            	4555, 0,
            0, 32, 1, /* 4555: struct.stack_st_void */
            	4560, 0,
            0, 32, 2, /* 4560: struct.stack_st */
            	190, 8,
            	195, 24,
            1, 8, 1, /* 4567: pointer.struct.x509_cert_aux_st */
            	4572, 0,
            0, 40, 5, /* 4572: struct.x509_cert_aux_st */
            	4585, 0,
            	4585, 8,
            	4354, 16,
            	4364, 24,
            	4330, 32,
            1, 8, 1, /* 4585: pointer.struct.stack_st_ASN1_OBJECT */
            	4590, 0,
            0, 32, 2, /* 4590: struct.stack_st_fake_ASN1_OBJECT */
            	4597, 8,
            	195, 24,
            8884099, 8, 2, /* 4597: pointer_to_array_of_pointers_to_stack */
            	4604, 0,
            	1072, 20,
            0, 8, 1, /* 4604: pointer.ASN1_OBJECT */
            	2010, 0,
            1, 8, 1, /* 4609: pointer.struct.ec_key_st */
            	1376, 0,
            1, 8, 1, /* 4614: pointer.struct.rsa_st */
            	592, 0,
            8884097, 8, 0, /* 4619: pointer.func */
            8884097, 8, 0, /* 4622: pointer.func */
            8884097, 8, 0, /* 4625: pointer.func */
            1, 8, 1, /* 4628: pointer.struct.env_md_st */
            	4633, 0,
            0, 120, 8, /* 4633: struct.env_md_st */
            	4652, 24,
            	4625, 32,
            	4655, 40,
            	4622, 48,
            	4652, 56,
            	820, 64,
            	823, 72,
            	4619, 112,
            8884097, 8, 0, /* 4652: pointer.func */
            8884097, 8, 0, /* 4655: pointer.func */
            1, 8, 1, /* 4658: pointer.struct.stack_st_X509_ATTRIBUTE */
            	4663, 0,
            0, 32, 2, /* 4663: struct.stack_st_fake_X509_ATTRIBUTE */
            	4670, 8,
            	195, 24,
            8884099, 8, 2, /* 4670: pointer_to_array_of_pointers_to_stack */
            	4677, 0,
            	1072, 20,
            0, 8, 1, /* 4677: pointer.X509_ATTRIBUTE */
            	853, 0,
            1, 8, 1, /* 4682: pointer.struct.dh_st */
            	109, 0,
            1, 8, 1, /* 4687: pointer.struct.dsa_st */
            	1244, 0,
            0, 8, 5, /* 4692: union.unknown */
            	70, 0,
            	4705, 0,
            	4687, 0,
            	4682, 0,
            	1371, 0,
            1, 8, 1, /* 4705: pointer.struct.rsa_st */
            	592, 0,
            0, 56, 4, /* 4710: struct.evp_pkey_st */
            	1870, 16,
            	1971, 24,
            	4692, 32,
            	4658, 48,
            1, 8, 1, /* 4721: pointer.struct.stack_st_X509_ALGOR */
            	4726, 0,
            0, 32, 2, /* 4726: struct.stack_st_fake_X509_ALGOR */
            	4733, 8,
            	195, 24,
            8884099, 8, 2, /* 4733: pointer_to_array_of_pointers_to_stack */
            	4740, 0,
            	1072, 20,
            0, 8, 1, /* 4740: pointer.X509_ALGOR */
            	3820, 0,
            1, 8, 1, /* 4745: pointer.struct.asn1_string_st */
            	4750, 0,
            0, 24, 1, /* 4750: struct.asn1_string_st */
            	160, 8,
            1, 8, 1, /* 4755: pointer.struct.stack_st_ASN1_OBJECT */
            	4760, 0,
            0, 32, 2, /* 4760: struct.stack_st_fake_ASN1_OBJECT */
            	4767, 8,
            	195, 24,
            8884099, 8, 2, /* 4767: pointer_to_array_of_pointers_to_stack */
            	4774, 0,
            	1072, 20,
            0, 8, 1, /* 4774: pointer.ASN1_OBJECT */
            	2010, 0,
            0, 40, 5, /* 4779: struct.x509_cert_aux_st */
            	4755, 0,
            	4755, 8,
            	4745, 16,
            	4792, 24,
            	4721, 32,
            1, 8, 1, /* 4792: pointer.struct.asn1_string_st */
            	4750, 0,
            0, 32, 2, /* 4797: struct.stack_st */
            	190, 8,
            	195, 24,
            0, 32, 1, /* 4804: struct.stack_st_void */
            	4797, 0,
            1, 8, 1, /* 4809: pointer.struct.stack_st_void */
            	4804, 0,
            0, 16, 1, /* 4814: struct.crypto_ex_data_st */
            	4809, 0,
            0, 24, 1, /* 4819: struct.ASN1_ENCODING_st */
            	160, 0,
            1, 8, 1, /* 4824: pointer.struct.stack_st_X509_EXTENSION */
            	4829, 0,
            0, 32, 2, /* 4829: struct.stack_st_fake_X509_EXTENSION */
            	4836, 8,
            	195, 24,
            8884099, 8, 2, /* 4836: pointer_to_array_of_pointers_to_stack */
            	4843, 0,
            	1072, 20,
            0, 8, 1, /* 4843: pointer.X509_EXTENSION */
            	2070, 0,
            1, 8, 1, /* 4848: pointer.struct.asn1_string_st */
            	4750, 0,
            0, 16, 2, /* 4853: struct.X509_val_st */
            	4848, 0,
            	4848, 8,
            1, 8, 1, /* 4860: pointer.struct.X509_val_st */
            	4853, 0,
            0, 24, 1, /* 4865: struct.buf_mem_st */
            	70, 8,
            1, 8, 1, /* 4870: pointer.struct.buf_mem_st */
            	4865, 0,
            1, 8, 1, /* 4875: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4880, 0,
            0, 32, 2, /* 4880: struct.stack_st_fake_X509_NAME_ENTRY */
            	4887, 8,
            	195, 24,
            8884099, 8, 2, /* 4887: pointer_to_array_of_pointers_to_stack */
            	4894, 0,
            	1072, 20,
            0, 8, 1, /* 4894: pointer.X509_NAME_ENTRY */
            	2458, 0,
            1, 8, 1, /* 4899: pointer.struct.X509_algor_st */
            	2125, 0,
            0, 104, 11, /* 4904: struct.x509_cinf_st */
            	4929, 0,
            	4929, 8,
            	4899, 16,
            	4934, 24,
            	4860, 32,
            	4934, 40,
            	4948, 48,
            	4953, 56,
            	4953, 64,
            	4824, 72,
            	4819, 80,
            1, 8, 1, /* 4929: pointer.struct.asn1_string_st */
            	4750, 0,
            1, 8, 1, /* 4934: pointer.struct.X509_name_st */
            	4939, 0,
            0, 40, 3, /* 4939: struct.X509_name_st */
            	4875, 0,
            	4870, 16,
            	160, 24,
            1, 8, 1, /* 4948: pointer.struct.X509_pubkey_st */
            	2111, 0,
            1, 8, 1, /* 4953: pointer.struct.asn1_string_st */
            	4750, 0,
            1, 8, 1, /* 4958: pointer.struct.x509_cinf_st */
            	4904, 0,
            1, 8, 1, /* 4963: pointer.struct.x509_st */
            	4968, 0,
            0, 184, 12, /* 4968: struct.x509_st */
            	4958, 0,
            	4899, 8,
            	4953, 16,
            	70, 32,
            	4814, 40,
            	4792, 104,
            	2558, 112,
            	2881, 120,
            	3303, 128,
            	3442, 136,
            	3466, 144,
            	4995, 176,
            1, 8, 1, /* 4995: pointer.struct.x509_cert_aux_st */
            	4779, 0,
            0, 24, 3, /* 5000: struct.cert_pkey_st */
            	4963, 0,
            	5009, 8,
            	4628, 16,
            1, 8, 1, /* 5009: pointer.struct.evp_pkey_st */
            	4710, 0,
            1, 8, 1, /* 5014: pointer.struct.cert_pkey_st */
            	5000, 0,
            0, 248, 5, /* 5019: struct.sess_cert_st */
            	5032, 0,
            	5014, 16,
            	4614, 216,
            	5056, 224,
            	4609, 232,
            1, 8, 1, /* 5032: pointer.struct.stack_st_X509 */
            	5037, 0,
            0, 32, 2, /* 5037: struct.stack_st_fake_X509 */
            	5044, 8,
            	195, 24,
            8884099, 8, 2, /* 5044: pointer_to_array_of_pointers_to_stack */
            	5051, 0,
            	1072, 20,
            0, 8, 1, /* 5051: pointer.X509 */
            	3989, 0,
            1, 8, 1, /* 5056: pointer.struct.dh_st */
            	109, 0,
            0, 352, 14, /* 5061: struct.ssl_session_st */
            	70, 144,
            	70, 152,
            	5092, 168,
            	4513, 176,
            	4325, 224,
            	5097, 240,
            	4545, 248,
            	5131, 264,
            	5131, 272,
            	70, 280,
            	160, 296,
            	160, 312,
            	160, 320,
            	70, 344,
            1, 8, 1, /* 5092: pointer.struct.sess_cert_st */
            	5019, 0,
            1, 8, 1, /* 5097: pointer.struct.stack_st_SSL_CIPHER */
            	5102, 0,
            0, 32, 2, /* 5102: struct.stack_st_fake_SSL_CIPHER */
            	5109, 8,
            	195, 24,
            8884099, 8, 2, /* 5109: pointer_to_array_of_pointers_to_stack */
            	5116, 0,
            	1072, 20,
            0, 8, 1, /* 5116: pointer.SSL_CIPHER */
            	5121, 0,
            0, 0, 1, /* 5121: SSL_CIPHER */
            	5126, 0,
            0, 88, 1, /* 5126: struct.ssl_cipher_st */
            	222, 8,
            1, 8, 1, /* 5131: pointer.struct.ssl_session_st */
            	5061, 0,
            1, 8, 1, /* 5136: pointer.struct.lhash_node_st */
            	5141, 0,
            0, 24, 2, /* 5141: struct.lhash_node_st */
            	58, 0,
            	5136, 8,
            1, 8, 1, /* 5148: pointer.struct.lhash_st */
            	5153, 0,
            0, 176, 3, /* 5153: struct.lhash_st */
            	5162, 0,
            	195, 8,
            	5169, 16,
            8884099, 8, 2, /* 5162: pointer_to_array_of_pointers_to_stack */
            	5136, 0,
            	19, 28,
            8884097, 8, 0, /* 5169: pointer.func */
            8884097, 8, 0, /* 5172: pointer.func */
            8884097, 8, 0, /* 5175: pointer.func */
            8884097, 8, 0, /* 5178: pointer.func */
            0, 56, 2, /* 5181: struct.X509_VERIFY_PARAM_st */
            	70, 0,
            	4585, 48,
            1, 8, 1, /* 5188: pointer.struct.X509_VERIFY_PARAM_st */
            	5181, 0,
            8884097, 8, 0, /* 5193: pointer.func */
            8884097, 8, 0, /* 5196: pointer.func */
            8884097, 8, 0, /* 5199: pointer.func */
            8884097, 8, 0, /* 5202: pointer.func */
            8884097, 8, 0, /* 5205: pointer.func */
            1, 8, 1, /* 5208: pointer.struct.X509_VERIFY_PARAM_st */
            	5213, 0,
            0, 56, 2, /* 5213: struct.X509_VERIFY_PARAM_st */
            	70, 0,
            	5220, 48,
            1, 8, 1, /* 5220: pointer.struct.stack_st_ASN1_OBJECT */
            	5225, 0,
            0, 32, 2, /* 5225: struct.stack_st_fake_ASN1_OBJECT */
            	5232, 8,
            	195, 24,
            8884099, 8, 2, /* 5232: pointer_to_array_of_pointers_to_stack */
            	5239, 0,
            	1072, 20,
            0, 8, 1, /* 5239: pointer.ASN1_OBJECT */
            	2010, 0,
            1, 8, 1, /* 5244: pointer.struct.stack_st_X509_LOOKUP */
            	5249, 0,
            0, 32, 2, /* 5249: struct.stack_st_fake_X509_LOOKUP */
            	5256, 8,
            	195, 24,
            8884099, 8, 2, /* 5256: pointer_to_array_of_pointers_to_stack */
            	5263, 0,
            	1072, 20,
            0, 8, 1, /* 5263: pointer.X509_LOOKUP */
            	5268, 0,
            0, 0, 1, /* 5268: X509_LOOKUP */
            	5273, 0,
            0, 32, 3, /* 5273: struct.x509_lookup_st */
            	5282, 8,
            	70, 16,
            	5331, 24,
            1, 8, 1, /* 5282: pointer.struct.x509_lookup_method_st */
            	5287, 0,
            0, 80, 10, /* 5287: struct.x509_lookup_method_st */
            	222, 0,
            	5310, 8,
            	5313, 16,
            	5310, 24,
            	5310, 32,
            	5316, 40,
            	5319, 48,
            	5322, 56,
            	5325, 64,
            	5328, 72,
            8884097, 8, 0, /* 5310: pointer.func */
            8884097, 8, 0, /* 5313: pointer.func */
            8884097, 8, 0, /* 5316: pointer.func */
            8884097, 8, 0, /* 5319: pointer.func */
            8884097, 8, 0, /* 5322: pointer.func */
            8884097, 8, 0, /* 5325: pointer.func */
            8884097, 8, 0, /* 5328: pointer.func */
            1, 8, 1, /* 5331: pointer.struct.x509_store_st */
            	5336, 0,
            0, 144, 15, /* 5336: struct.x509_store_st */
            	5369, 8,
            	5244, 16,
            	5208, 24,
            	5205, 32,
            	6019, 40,
            	6022, 48,
            	5202, 56,
            	5205, 64,
            	6025, 72,
            	5199, 80,
            	6028, 88,
            	5196, 96,
            	5193, 104,
            	5205, 112,
            	5595, 120,
            1, 8, 1, /* 5369: pointer.struct.stack_st_X509_OBJECT */
            	5374, 0,
            0, 32, 2, /* 5374: struct.stack_st_fake_X509_OBJECT */
            	5381, 8,
            	195, 24,
            8884099, 8, 2, /* 5381: pointer_to_array_of_pointers_to_stack */
            	5388, 0,
            	1072, 20,
            0, 8, 1, /* 5388: pointer.X509_OBJECT */
            	5393, 0,
            0, 0, 1, /* 5393: X509_OBJECT */
            	5398, 0,
            0, 16, 1, /* 5398: struct.x509_object_st */
            	5403, 8,
            0, 8, 4, /* 5403: union.unknown */
            	70, 0,
            	5414, 0,
            	5732, 0,
            	5941, 0,
            1, 8, 1, /* 5414: pointer.struct.x509_st */
            	5419, 0,
            0, 184, 12, /* 5419: struct.x509_st */
            	5446, 0,
            	5486, 8,
            	5561, 16,
            	70, 32,
            	5595, 40,
            	5617, 104,
            	5622, 112,
            	5627, 120,
            	5632, 128,
            	5656, 136,
            	5680, 144,
            	5685, 176,
            1, 8, 1, /* 5446: pointer.struct.x509_cinf_st */
            	5451, 0,
            0, 104, 11, /* 5451: struct.x509_cinf_st */
            	5476, 0,
            	5476, 8,
            	5486, 16,
            	5491, 24,
            	5539, 32,
            	5491, 40,
            	5556, 48,
            	5561, 56,
            	5561, 64,
            	5566, 72,
            	5590, 80,
            1, 8, 1, /* 5476: pointer.struct.asn1_string_st */
            	5481, 0,
            0, 24, 1, /* 5481: struct.asn1_string_st */
            	160, 8,
            1, 8, 1, /* 5486: pointer.struct.X509_algor_st */
            	2125, 0,
            1, 8, 1, /* 5491: pointer.struct.X509_name_st */
            	5496, 0,
            0, 40, 3, /* 5496: struct.X509_name_st */
            	5505, 0,
            	5529, 16,
            	160, 24,
            1, 8, 1, /* 5505: pointer.struct.stack_st_X509_NAME_ENTRY */
            	5510, 0,
            0, 32, 2, /* 5510: struct.stack_st_fake_X509_NAME_ENTRY */
            	5517, 8,
            	195, 24,
            8884099, 8, 2, /* 5517: pointer_to_array_of_pointers_to_stack */
            	5524, 0,
            	1072, 20,
            0, 8, 1, /* 5524: pointer.X509_NAME_ENTRY */
            	2458, 0,
            1, 8, 1, /* 5529: pointer.struct.buf_mem_st */
            	5534, 0,
            0, 24, 1, /* 5534: struct.buf_mem_st */
            	70, 8,
            1, 8, 1, /* 5539: pointer.struct.X509_val_st */
            	5544, 0,
            0, 16, 2, /* 5544: struct.X509_val_st */
            	5551, 0,
            	5551, 8,
            1, 8, 1, /* 5551: pointer.struct.asn1_string_st */
            	5481, 0,
            1, 8, 1, /* 5556: pointer.struct.X509_pubkey_st */
            	2111, 0,
            1, 8, 1, /* 5561: pointer.struct.asn1_string_st */
            	5481, 0,
            1, 8, 1, /* 5566: pointer.struct.stack_st_X509_EXTENSION */
            	5571, 0,
            0, 32, 2, /* 5571: struct.stack_st_fake_X509_EXTENSION */
            	5578, 8,
            	195, 24,
            8884099, 8, 2, /* 5578: pointer_to_array_of_pointers_to_stack */
            	5585, 0,
            	1072, 20,
            0, 8, 1, /* 5585: pointer.X509_EXTENSION */
            	2070, 0,
            0, 24, 1, /* 5590: struct.ASN1_ENCODING_st */
            	160, 0,
            0, 16, 1, /* 5595: struct.crypto_ex_data_st */
            	5600, 0,
            1, 8, 1, /* 5600: pointer.struct.stack_st_void */
            	5605, 0,
            0, 32, 1, /* 5605: struct.stack_st_void */
            	5610, 0,
            0, 32, 2, /* 5610: struct.stack_st */
            	190, 8,
            	195, 24,
            1, 8, 1, /* 5617: pointer.struct.asn1_string_st */
            	5481, 0,
            1, 8, 1, /* 5622: pointer.struct.AUTHORITY_KEYID_st */
            	2563, 0,
            1, 8, 1, /* 5627: pointer.struct.X509_POLICY_CACHE_st */
            	2886, 0,
            1, 8, 1, /* 5632: pointer.struct.stack_st_DIST_POINT */
            	5637, 0,
            0, 32, 2, /* 5637: struct.stack_st_fake_DIST_POINT */
            	5644, 8,
            	195, 24,
            8884099, 8, 2, /* 5644: pointer_to_array_of_pointers_to_stack */
            	5651, 0,
            	1072, 20,
            0, 8, 1, /* 5651: pointer.DIST_POINT */
            	3327, 0,
            1, 8, 1, /* 5656: pointer.struct.stack_st_GENERAL_NAME */
            	5661, 0,
            0, 32, 2, /* 5661: struct.stack_st_fake_GENERAL_NAME */
            	5668, 8,
            	195, 24,
            8884099, 8, 2, /* 5668: pointer_to_array_of_pointers_to_stack */
            	5675, 0,
            	1072, 20,
            0, 8, 1, /* 5675: pointer.GENERAL_NAME */
            	2606, 0,
            1, 8, 1, /* 5680: pointer.struct.NAME_CONSTRAINTS_st */
            	3471, 0,
            1, 8, 1, /* 5685: pointer.struct.x509_cert_aux_st */
            	5690, 0,
            0, 40, 5, /* 5690: struct.x509_cert_aux_st */
            	5220, 0,
            	5220, 8,
            	5703, 16,
            	5617, 24,
            	5708, 32,
            1, 8, 1, /* 5703: pointer.struct.asn1_string_st */
            	5481, 0,
            1, 8, 1, /* 5708: pointer.struct.stack_st_X509_ALGOR */
            	5713, 0,
            0, 32, 2, /* 5713: struct.stack_st_fake_X509_ALGOR */
            	5720, 8,
            	195, 24,
            8884099, 8, 2, /* 5720: pointer_to_array_of_pointers_to_stack */
            	5727, 0,
            	1072, 20,
            0, 8, 1, /* 5727: pointer.X509_ALGOR */
            	3820, 0,
            1, 8, 1, /* 5732: pointer.struct.X509_crl_st */
            	5737, 0,
            0, 120, 10, /* 5737: struct.X509_crl_st */
            	5760, 0,
            	5486, 8,
            	5561, 16,
            	5622, 32,
            	5863, 40,
            	5476, 56,
            	5476, 64,
            	5875, 96,
            	5916, 104,
            	58, 112,
            1, 8, 1, /* 5760: pointer.struct.X509_crl_info_st */
            	5765, 0,
            0, 80, 8, /* 5765: struct.X509_crl_info_st */
            	5476, 0,
            	5486, 8,
            	5491, 16,
            	5551, 24,
            	5551, 32,
            	5784, 40,
            	5566, 48,
            	5590, 56,
            1, 8, 1, /* 5784: pointer.struct.stack_st_X509_REVOKED */
            	5789, 0,
            0, 32, 2, /* 5789: struct.stack_st_fake_X509_REVOKED */
            	5796, 8,
            	195, 24,
            8884099, 8, 2, /* 5796: pointer_to_array_of_pointers_to_stack */
            	5803, 0,
            	1072, 20,
            0, 8, 1, /* 5803: pointer.X509_REVOKED */
            	5808, 0,
            0, 0, 1, /* 5808: X509_REVOKED */
            	5813, 0,
            0, 40, 4, /* 5813: struct.x509_revoked_st */
            	5824, 0,
            	5834, 8,
            	5839, 16,
            	4166, 24,
            1, 8, 1, /* 5824: pointer.struct.asn1_string_st */
            	5829, 0,
            0, 24, 1, /* 5829: struct.asn1_string_st */
            	160, 8,
            1, 8, 1, /* 5834: pointer.struct.asn1_string_st */
            	5829, 0,
            1, 8, 1, /* 5839: pointer.struct.stack_st_X509_EXTENSION */
            	5844, 0,
            0, 32, 2, /* 5844: struct.stack_st_fake_X509_EXTENSION */
            	5851, 8,
            	195, 24,
            8884099, 8, 2, /* 5851: pointer_to_array_of_pointers_to_stack */
            	5858, 0,
            	1072, 20,
            0, 8, 1, /* 5858: pointer.X509_EXTENSION */
            	2070, 0,
            1, 8, 1, /* 5863: pointer.struct.ISSUING_DIST_POINT_st */
            	5868, 0,
            0, 32, 2, /* 5868: struct.ISSUING_DIST_POINT_st */
            	3341, 0,
            	3432, 16,
            1, 8, 1, /* 5875: pointer.struct.stack_st_GENERAL_NAMES */
            	5880, 0,
            0, 32, 2, /* 5880: struct.stack_st_fake_GENERAL_NAMES */
            	5887, 8,
            	195, 24,
            8884099, 8, 2, /* 5887: pointer_to_array_of_pointers_to_stack */
            	5894, 0,
            	1072, 20,
            0, 8, 1, /* 5894: pointer.GENERAL_NAMES */
            	5899, 0,
            0, 0, 1, /* 5899: GENERAL_NAMES */
            	5904, 0,
            0, 32, 1, /* 5904: struct.stack_st_GENERAL_NAME */
            	5909, 0,
            0, 32, 2, /* 5909: struct.stack_st */
            	190, 8,
            	195, 24,
            1, 8, 1, /* 5916: pointer.struct.x509_crl_method_st */
            	5921, 0,
            0, 40, 4, /* 5921: struct.x509_crl_method_st */
            	5932, 8,
            	5932, 16,
            	5935, 24,
            	5938, 32,
            8884097, 8, 0, /* 5932: pointer.func */
            8884097, 8, 0, /* 5935: pointer.func */
            8884097, 8, 0, /* 5938: pointer.func */
            1, 8, 1, /* 5941: pointer.struct.evp_pkey_st */
            	5946, 0,
            0, 56, 4, /* 5946: struct.evp_pkey_st */
            	5957, 16,
            	239, 24,
            	5962, 32,
            	5995, 48,
            1, 8, 1, /* 5957: pointer.struct.evp_pkey_asn1_method_st */
            	1875, 0,
            0, 8, 5, /* 5962: union.unknown */
            	70, 0,
            	5975, 0,
            	5980, 0,
            	5985, 0,
            	5990, 0,
            1, 8, 1, /* 5975: pointer.struct.rsa_st */
            	592, 0,
            1, 8, 1, /* 5980: pointer.struct.dsa_st */
            	1244, 0,
            1, 8, 1, /* 5985: pointer.struct.dh_st */
            	109, 0,
            1, 8, 1, /* 5990: pointer.struct.ec_key_st */
            	1376, 0,
            1, 8, 1, /* 5995: pointer.struct.stack_st_X509_ATTRIBUTE */
            	6000, 0,
            0, 32, 2, /* 6000: struct.stack_st_fake_X509_ATTRIBUTE */
            	6007, 8,
            	195, 24,
            8884099, 8, 2, /* 6007: pointer_to_array_of_pointers_to_stack */
            	6014, 0,
            	1072, 20,
            0, 8, 1, /* 6014: pointer.X509_ATTRIBUTE */
            	853, 0,
            8884097, 8, 0, /* 6019: pointer.func */
            8884097, 8, 0, /* 6022: pointer.func */
            8884097, 8, 0, /* 6025: pointer.func */
            8884097, 8, 0, /* 6028: pointer.func */
            1, 8, 1, /* 6031: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	6036, 0,
            0, 32, 2, /* 6036: struct.stack_st_fake_SRTP_PROTECTION_PROFILE */
            	6043, 8,
            	195, 24,
            8884099, 8, 2, /* 6043: pointer_to_array_of_pointers_to_stack */
            	6050, 0,
            	1072, 20,
            0, 8, 1, /* 6050: pointer.SRTP_PROTECTION_PROFILE */
            	6055, 0,
            0, 0, 1, /* 6055: SRTP_PROTECTION_PROFILE */
            	6060, 0,
            0, 16, 1, /* 6060: struct.srtp_protection_profile_st */
            	222, 0,
            1, 8, 1, /* 6065: pointer.struct.stack_st_X509_LOOKUP */
            	6070, 0,
            0, 32, 2, /* 6070: struct.stack_st_fake_X509_LOOKUP */
            	6077, 8,
            	195, 24,
            8884099, 8, 2, /* 6077: pointer_to_array_of_pointers_to_stack */
            	6084, 0,
            	1072, 20,
            0, 8, 1, /* 6084: pointer.X509_LOOKUP */
            	5268, 0,
            8884097, 8, 0, /* 6089: pointer.func */
            8884097, 8, 0, /* 6092: pointer.func */
            8884097, 8, 0, /* 6095: pointer.func */
            1, 8, 1, /* 6098: pointer.struct.stack_st_X509_NAME */
            	6103, 0,
            0, 32, 2, /* 6103: struct.stack_st_fake_X509_NAME */
            	6110, 8,
            	195, 24,
            8884099, 8, 2, /* 6110: pointer_to_array_of_pointers_to_stack */
            	6117, 0,
            	1072, 20,
            0, 8, 1, /* 6117: pointer.X509_NAME */
            	3847, 0,
            8884097, 8, 0, /* 6122: pointer.func */
            1, 8, 1, /* 6125: pointer.struct.cert_st */
            	6130, 0,
            0, 296, 7, /* 6130: struct.cert_st */
            	6147, 0,
            	587, 48,
            	6089, 56,
            	104, 64,
            	6095, 72,
            	4609, 80,
            	6152, 88,
            1, 8, 1, /* 6147: pointer.struct.cert_pkey_st */
            	3825, 0,
            8884097, 8, 0, /* 6152: pointer.func */
            8884097, 8, 0, /* 6155: pointer.func */
            8884097, 8, 0, /* 6158: pointer.func */
            8884097, 8, 0, /* 6161: pointer.func */
            1, 8, 1, /* 6164: pointer.struct.stack_st_X509_OBJECT */
            	6169, 0,
            0, 32, 2, /* 6169: struct.stack_st_fake_X509_OBJECT */
            	6176, 8,
            	195, 24,
            8884099, 8, 2, /* 6176: pointer_to_array_of_pointers_to_stack */
            	6183, 0,
            	1072, 20,
            0, 8, 1, /* 6183: pointer.X509_OBJECT */
            	5393, 0,
            1, 8, 1, /* 6188: pointer.struct.x509_store_st */
            	6193, 0,
            0, 144, 15, /* 6193: struct.x509_store_st */
            	6164, 8,
            	6065, 16,
            	5188, 24,
            	6226, 32,
            	5178, 40,
            	6122, 48,
            	6229, 56,
            	6226, 64,
            	6092, 72,
            	5175, 80,
            	6232, 88,
            	6235, 96,
            	5172, 104,
            	6226, 112,
            	4545, 120,
            8884097, 8, 0, /* 6226: pointer.func */
            8884097, 8, 0, /* 6229: pointer.func */
            8884097, 8, 0, /* 6232: pointer.func */
            8884097, 8, 0, /* 6235: pointer.func */
            8884097, 8, 0, /* 6238: pointer.func */
            8884097, 8, 0, /* 6241: pointer.func */
            8884097, 8, 0, /* 6244: pointer.func */
            8884097, 8, 0, /* 6247: pointer.func */
            8884097, 8, 0, /* 6250: pointer.func */
            8884097, 8, 0, /* 6253: pointer.func */
            8884097, 8, 0, /* 6256: pointer.func */
            8884097, 8, 0, /* 6259: pointer.func */
            8884097, 8, 0, /* 6262: pointer.func */
            8884097, 8, 0, /* 6265: pointer.func */
            8884097, 8, 0, /* 6268: pointer.func */
            0, 736, 50, /* 6271: struct.ssl_ctx_st */
            	6374, 0,
            	5097, 8,
            	5097, 16,
            	6188, 24,
            	5148, 32,
            	5131, 48,
            	5131, 56,
            	4317, 80,
            	4314, 88,
            	6501, 96,
            	6504, 152,
            	58, 160,
            	4311, 168,
            	58, 176,
            	4308, 184,
            	6507, 192,
            	4305, 200,
            	4545, 208,
            	4300, 224,
            	4300, 232,
            	4300, 240,
            	3965, 248,
            	3941, 256,
            	3844, 264,
            	6098, 272,
            	6125, 304,
            	6510, 320,
            	58, 328,
            	5178, 376,
            	6155, 384,
            	5188, 392,
            	1971, 408,
            	61, 416,
            	58, 424,
            	6513, 480,
            	64, 488,
            	58, 496,
            	101, 504,
            	58, 512,
            	70, 520,
            	98, 528,
            	95, 536,
            	90, 552,
            	90, 560,
            	27, 568,
            	6, 696,
            	58, 704,
            	3, 712,
            	58, 720,
            	6031, 728,
            1, 8, 1, /* 6374: pointer.struct.ssl_method_st */
            	6379, 0,
            0, 232, 28, /* 6379: struct.ssl_method_st */
            	6438, 8,
            	6268, 16,
            	6268, 24,
            	6438, 32,
            	6438, 40,
            	6256, 48,
            	6256, 56,
            	6250, 64,
            	6438, 72,
            	6438, 80,
            	6438, 88,
            	6241, 96,
            	6441, 104,
            	6444, 112,
            	6438, 120,
            	6447, 128,
            	6450, 136,
            	6453, 144,
            	6238, 152,
            	6456, 160,
            	513, 168,
            	6247, 176,
            	6262, 184,
            	3921, 192,
            	6459, 200,
            	513, 208,
            	6244, 216,
            	6158, 224,
            8884097, 8, 0, /* 6438: pointer.func */
            8884097, 8, 0, /* 6441: pointer.func */
            8884097, 8, 0, /* 6444: pointer.func */
            8884097, 8, 0, /* 6447: pointer.func */
            8884097, 8, 0, /* 6450: pointer.func */
            8884097, 8, 0, /* 6453: pointer.func */
            8884097, 8, 0, /* 6456: pointer.func */
            1, 8, 1, /* 6459: pointer.struct.ssl3_enc_method */
            	6464, 0,
            0, 112, 11, /* 6464: struct.ssl3_enc_method */
            	6489, 0,
            	6253, 8,
            	6492, 16,
            	6495, 24,
            	6489, 32,
            	6498, 40,
            	6265, 56,
            	222, 64,
            	222, 80,
            	6161, 96,
            	6259, 104,
            8884097, 8, 0, /* 6489: pointer.func */
            8884097, 8, 0, /* 6492: pointer.func */
            8884097, 8, 0, /* 6495: pointer.func */
            8884097, 8, 0, /* 6498: pointer.func */
            8884097, 8, 0, /* 6501: pointer.func */
            8884097, 8, 0, /* 6504: pointer.func */
            8884097, 8, 0, /* 6507: pointer.func */
            8884097, 8, 0, /* 6510: pointer.func */
            8884097, 8, 0, /* 6513: pointer.func */
            1, 8, 1, /* 6516: pointer.struct.ssl_ctx_st */
            	6271, 0,
            0, 1, 0, /* 6521: char */
        },
        .arg_entity_index = { 6516, 0, },
        .ret_entity_index = -1,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    SSL_CTX * new_arg_a = *((SSL_CTX * *)new_args->args[0]);

    void (*new_arg_b)(struct ssl_ctx_st *,SSL_SESSION *) = *((void (**)(struct ssl_ctx_st *,SSL_SESSION *))new_args->args[1]);

    void (*orig_SSL_CTX_sess_set_remove_cb)(SSL_CTX *,void (*)(struct ssl_ctx_st *,SSL_SESSION *));
    orig_SSL_CTX_sess_set_remove_cb = dlsym(RTLD_NEXT, "SSL_CTX_sess_set_remove_cb");
    (*orig_SSL_CTX_sess_set_remove_cb)(new_arg_a,new_arg_b);

    syscall(889);

}

