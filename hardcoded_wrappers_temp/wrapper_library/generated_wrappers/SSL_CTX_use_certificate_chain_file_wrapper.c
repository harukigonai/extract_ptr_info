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

int SSL_CTX_use_certificate_chain_file(SSL_CTX * arg_a,const char * arg_b) 
{
    if (syscall(890))
        return _SSL_CTX_use_certificate_chain_file(arg_a,arg_b);
    else {
        int (*orig_SSL_CTX_use_certificate_chain_file)(SSL_CTX *,const char *);
        orig_SSL_CTX_use_certificate_chain_file = dlsym(RTLD_NEXT, "SSL_CTX_use_certificate_chain_file");
        return orig_SSL_CTX_use_certificate_chain_file(arg_a,arg_b);
    }
}

int _SSL_CTX_use_certificate_chain_file(SSL_CTX * arg_a,const char * arg_b) 
{
    printf("SSL_CTX_use_certificate_chain_file called\n");
    int ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 0, 0, /* 0: func */
            1, 8, 1, /* 3: pointer.func */
            	0, 0,
            1, 8, 1, /* 8: pointer.func */
            	13, 0,
            0, 0, 0, /* 13: func */
            1, 8, 1, /* 16: pointer.struct.ssl3_buf_freelist_entry_st */
            	21, 0,
            0, 8, 1, /* 21: struct.ssl3_buf_freelist_entry_st */
            	16, 0,
            1, 8, 1, /* 26: pointer.func */
            	31, 0,
            0, 0, 0, /* 31: func */
            0, 0, 0, /* 34: func */
            1, 8, 1, /* 37: pointer.func */
            	34, 0,
            1, 8, 1, /* 42: pointer.func */
            	47, 0,
            0, 0, 0, /* 47: func */
            0, 16, 0, /* 50: array[16].char */
            1, 8, 1, /* 53: pointer.func */
            	58, 0,
            0, 0, 0, /* 58: func */
            0, 0, 0, /* 61: func */
            1, 8, 1, /* 64: pointer.func */
            	61, 0,
            1, 8, 1, /* 69: pointer.func */
            	74, 0,
            0, 0, 0, /* 74: func */
            0, 0, 0, /* 77: func */
            1, 8, 1, /* 80: pointer.func */
            	85, 0,
            0, 0, 0, /* 85: func */
            0, 0, 0, /* 88: func */
            1, 8, 1, /* 91: pointer.func */
            	88, 0,
            0, 44, 0, /* 96: struct.apr_time_exp_t */
            0, 0, 0, /* 99: func */
            1, 8, 1, /* 102: pointer.struct.ssl_cipher_st */
            	107, 0,
            0, 88, 1, /* 107: struct.ssl_cipher_st */
            	112, 8,
            1, 8, 1, /* 112: pointer.char */
            	117, 0,
            0, 1, 0, /* 117: char */
            0, 24, 0, /* 120: array[6].int */
            1, 8, 1, /* 123: pointer.func */
            	128, 0,
            0, 0, 0, /* 128: func */
            0, 40, 5, /* 131: struct.ec_extra_data_st */
            	144, 0,
            	112, 8,
            	123, 16,
            	149, 24,
            	149, 32,
            1, 8, 1, /* 144: pointer.struct.ec_extra_data_st */
            	131, 0,
            1, 8, 1, /* 149: pointer.func */
            	154, 0,
            0, 0, 0, /* 154: func */
            0, 88, 4, /* 157: struct.ec_point_st */
            	168, 0,
            	418, 8,
            	418, 32,
            	418, 56,
            1, 8, 1, /* 168: pointer.struct.ec_method_st */
            	173, 0,
            0, 304, 37, /* 173: struct.ec_method_st */
            	250, 8,
            	258, 16,
            	258, 24,
            	266, 32,
            	274, 40,
            	274, 48,
            	250, 56,
            	282, 64,
            	290, 72,
            	298, 80,
            	298, 88,
            	306, 96,
            	314, 104,
            	322, 112,
            	322, 120,
            	330, 128,
            	330, 136,
            	338, 144,
            	346, 152,
            	354, 160,
            	362, 168,
            	370, 176,
            	378, 184,
            	314, 192,
            	378, 200,
            	370, 208,
            	378, 216,
            	386, 224,
            	394, 232,
            	282, 240,
            	250, 248,
            	274, 256,
            	402, 264,
            	274, 272,
            	402, 280,
            	402, 288,
            	410, 296,
            1, 8, 1, /* 250: pointer.func */
            	255, 0,
            0, 0, 0, /* 255: func */
            1, 8, 1, /* 258: pointer.func */
            	263, 0,
            0, 0, 0, /* 263: func */
            1, 8, 1, /* 266: pointer.func */
            	271, 0,
            0, 0, 0, /* 271: func */
            1, 8, 1, /* 274: pointer.func */
            	279, 0,
            0, 0, 0, /* 279: func */
            1, 8, 1, /* 282: pointer.func */
            	287, 0,
            0, 0, 0, /* 287: func */
            1, 8, 1, /* 290: pointer.func */
            	295, 0,
            0, 0, 0, /* 295: func */
            1, 8, 1, /* 298: pointer.func */
            	303, 0,
            0, 0, 0, /* 303: func */
            1, 8, 1, /* 306: pointer.func */
            	311, 0,
            0, 0, 0, /* 311: func */
            1, 8, 1, /* 314: pointer.func */
            	319, 0,
            0, 0, 0, /* 319: func */
            1, 8, 1, /* 322: pointer.func */
            	327, 0,
            0, 0, 0, /* 327: func */
            1, 8, 1, /* 330: pointer.func */
            	335, 0,
            0, 0, 0, /* 335: func */
            1, 8, 1, /* 338: pointer.func */
            	343, 0,
            0, 0, 0, /* 343: func */
            1, 8, 1, /* 346: pointer.func */
            	351, 0,
            0, 0, 0, /* 351: func */
            1, 8, 1, /* 354: pointer.func */
            	359, 0,
            0, 0, 0, /* 359: func */
            1, 8, 1, /* 362: pointer.func */
            	367, 0,
            0, 0, 0, /* 367: func */
            1, 8, 1, /* 370: pointer.func */
            	375, 0,
            0, 0, 0, /* 375: func */
            1, 8, 1, /* 378: pointer.func */
            	383, 0,
            0, 0, 0, /* 383: func */
            1, 8, 1, /* 386: pointer.func */
            	391, 0,
            0, 0, 0, /* 391: func */
            1, 8, 1, /* 394: pointer.func */
            	399, 0,
            0, 0, 0, /* 399: func */
            1, 8, 1, /* 402: pointer.func */
            	407, 0,
            0, 0, 0, /* 407: func */
            1, 8, 1, /* 410: pointer.func */
            	415, 0,
            0, 0, 0, /* 415: func */
            0, 24, 1, /* 418: struct.bignum_st */
            	423, 0,
            1, 8, 1, /* 423: pointer.int */
            	428, 0,
            0, 4, 0, /* 428: int */
            0, 232, 12, /* 431: struct.ec_group_st */
            	168, 0,
            	458, 8,
            	418, 16,
            	418, 40,
            	112, 80,
            	144, 96,
            	418, 104,
            	418, 152,
            	418, 176,
            	112, 208,
            	112, 216,
            	463, 224,
            1, 8, 1, /* 458: pointer.struct.ec_point_st */
            	157, 0,
            1, 8, 1, /* 463: pointer.func */
            	468, 0,
            0, 0, 0, /* 468: func */
            1, 8, 1, /* 471: pointer.struct.ec_group_st */
            	431, 0,
            0, 56, 4, /* 476: struct.ec_key_st.284 */
            	471, 8,
            	458, 16,
            	487, 24,
            	144, 48,
            1, 8, 1, /* 487: pointer.struct.bignum_st */
            	418, 0,
            1, 8, 1, /* 492: pointer.struct.ec_key_st.284 */
            	476, 0,
            0, 144, 12, /* 497: struct.dh_st */
            	487, 8,
            	487, 16,
            	487, 32,
            	487, 40,
            	524, 56,
            	487, 64,
            	487, 72,
            	112, 80,
            	487, 96,
            	538, 112,
            	573, 128,
            	629, 136,
            1, 8, 1, /* 524: pointer.struct.bn_mont_ctx_st */
            	529, 0,
            0, 96, 3, /* 529: struct.bn_mont_ctx_st */
            	418, 8,
            	418, 32,
            	418, 56,
            0, 16, 1, /* 538: struct.crypto_ex_data_st */
            	543, 0,
            1, 8, 1, /* 543: pointer.struct.stack_st_OPENSSL_STRING */
            	548, 0,
            0, 32, 1, /* 548: struct.stack_st_OPENSSL_STRING */
            	553, 0,
            0, 32, 2, /* 553: struct.stack_st */
            	560, 8,
            	565, 24,
            1, 8, 1, /* 560: pointer.pointer.char */
            	112, 0,
            1, 8, 1, /* 565: pointer.func */
            	570, 0,
            0, 0, 0, /* 570: func */
            1, 8, 1, /* 573: pointer.struct.dh_method */
            	578, 0,
            0, 72, 8, /* 578: struct.dh_method */
            	112, 0,
            	597, 8,
            	605, 16,
            	613, 24,
            	597, 32,
            	597, 40,
            	112, 56,
            	621, 64,
            1, 8, 1, /* 597: pointer.func */
            	602, 0,
            0, 0, 0, /* 602: func */
            1, 8, 1, /* 605: pointer.func */
            	610, 0,
            0, 0, 0, /* 610: func */
            1, 8, 1, /* 613: pointer.func */
            	618, 0,
            0, 0, 0, /* 618: func */
            1, 8, 1, /* 621: pointer.func */
            	626, 0,
            0, 0, 0, /* 626: func */
            1, 8, 1, /* 629: pointer.struct.engine_st */
            	634, 0,
            0, 216, 24, /* 634: struct.engine_st */
            	112, 0,
            	112, 8,
            	685, 16,
            	775, 24,
            	573, 32,
            	861, 40,
            	883, 48,
            	925, 56,
            	985, 64,
            	993, 72,
            	1001, 80,
            	1009, 88,
            	1017, 96,
            	1025, 104,
            	1025, 112,
            	1025, 120,
            	1033, 128,
            	1041, 136,
            	1041, 144,
            	1049, 152,
            	1057, 160,
            	538, 184,
            	629, 200,
            	629, 208,
            1, 8, 1, /* 685: pointer.struct.rsa_meth_st */
            	690, 0,
            0, 112, 13, /* 690: struct.rsa_meth_st */
            	112, 0,
            	719, 8,
            	719, 16,
            	719, 24,
            	719, 32,
            	727, 40,
            	735, 48,
            	743, 56,
            	743, 64,
            	112, 80,
            	751, 88,
            	759, 96,
            	767, 104,
            1, 8, 1, /* 719: pointer.func */
            	724, 0,
            0, 0, 0, /* 724: func */
            1, 8, 1, /* 727: pointer.func */
            	732, 0,
            0, 0, 0, /* 732: func */
            1, 8, 1, /* 735: pointer.func */
            	740, 0,
            0, 0, 0, /* 740: func */
            1, 8, 1, /* 743: pointer.func */
            	748, 0,
            0, 0, 0, /* 748: func */
            1, 8, 1, /* 751: pointer.func */
            	756, 0,
            0, 0, 0, /* 756: func */
            1, 8, 1, /* 759: pointer.func */
            	764, 0,
            0, 0, 0, /* 764: func */
            1, 8, 1, /* 767: pointer.func */
            	772, 0,
            0, 0, 0, /* 772: func */
            1, 8, 1, /* 775: pointer.struct.dsa_method.1040 */
            	780, 0,
            0, 96, 11, /* 780: struct.dsa_method.1040 */
            	112, 0,
            	805, 8,
            	813, 16,
            	821, 24,
            	829, 32,
            	837, 40,
            	845, 48,
            	845, 56,
            	112, 72,
            	853, 80,
            	845, 88,
            1, 8, 1, /* 805: pointer.func */
            	810, 0,
            0, 0, 0, /* 810: func */
            1, 8, 1, /* 813: pointer.func */
            	818, 0,
            0, 0, 0, /* 818: func */
            1, 8, 1, /* 821: pointer.func */
            	826, 0,
            0, 0, 0, /* 826: func */
            1, 8, 1, /* 829: pointer.func */
            	834, 0,
            0, 0, 0, /* 834: func */
            1, 8, 1, /* 837: pointer.func */
            	842, 0,
            0, 0, 0, /* 842: func */
            1, 8, 1, /* 845: pointer.func */
            	850, 0,
            0, 0, 0, /* 850: func */
            1, 8, 1, /* 853: pointer.func */
            	858, 0,
            0, 0, 0, /* 858: func */
            1, 8, 1, /* 861: pointer.struct.ecdh_method */
            	866, 0,
            0, 32, 3, /* 866: struct.ecdh_method */
            	112, 0,
            	875, 8,
            	112, 24,
            1, 8, 1, /* 875: pointer.func */
            	880, 0,
            0, 0, 0, /* 880: func */
            1, 8, 1, /* 883: pointer.struct.ecdsa_method */
            	888, 0,
            0, 48, 5, /* 888: struct.ecdsa_method */
            	112, 0,
            	901, 8,
            	909, 16,
            	917, 24,
            	112, 40,
            1, 8, 1, /* 901: pointer.func */
            	906, 0,
            0, 0, 0, /* 906: func */
            1, 8, 1, /* 909: pointer.func */
            	914, 0,
            0, 0, 0, /* 914: func */
            1, 8, 1, /* 917: pointer.func */
            	922, 0,
            0, 0, 0, /* 922: func */
            1, 8, 1, /* 925: pointer.struct.rand_meth_st */
            	930, 0,
            0, 48, 6, /* 930: struct.rand_meth_st */
            	945, 0,
            	953, 8,
            	961, 16,
            	969, 24,
            	953, 32,
            	977, 40,
            1, 8, 1, /* 945: pointer.func */
            	950, 0,
            0, 0, 0, /* 950: func */
            1, 8, 1, /* 953: pointer.func */
            	958, 0,
            0, 0, 0, /* 958: func */
            1, 8, 1, /* 961: pointer.func */
            	966, 0,
            0, 0, 0, /* 966: func */
            1, 8, 1, /* 969: pointer.func */
            	974, 0,
            0, 0, 0, /* 974: func */
            1, 8, 1, /* 977: pointer.func */
            	982, 0,
            0, 0, 0, /* 982: func */
            1, 8, 1, /* 985: pointer.struct.store_method_st */
            	990, 0,
            0, 0, 0, /* 990: struct.store_method_st */
            1, 8, 1, /* 993: pointer.func */
            	998, 0,
            0, 0, 0, /* 998: func */
            1, 8, 1, /* 1001: pointer.func */
            	1006, 0,
            0, 0, 0, /* 1006: func */
            1, 8, 1, /* 1009: pointer.func */
            	1014, 0,
            0, 0, 0, /* 1014: func */
            1, 8, 1, /* 1017: pointer.func */
            	1022, 0,
            0, 0, 0, /* 1022: func */
            1, 8, 1, /* 1025: pointer.func */
            	1030, 0,
            0, 0, 0, /* 1030: func */
            1, 8, 1, /* 1033: pointer.func */
            	1038, 0,
            0, 0, 0, /* 1038: func */
            1, 8, 1, /* 1041: pointer.func */
            	1046, 0,
            0, 0, 0, /* 1046: func */
            1, 8, 1, /* 1049: pointer.func */
            	1054, 0,
            0, 0, 0, /* 1054: func */
            1, 8, 1, /* 1057: pointer.struct.ENGINE_CMD_DEFN_st */
            	1062, 0,
            0, 32, 2, /* 1062: struct.ENGINE_CMD_DEFN_st */
            	112, 8,
            	112, 16,
            1, 8, 1, /* 1069: pointer.struct.dh_st */
            	497, 0,
            0, 88, 7, /* 1074: struct.bn_blinding_st */
            	487, 0,
            	487, 8,
            	487, 16,
            	487, 24,
            	1091, 40,
            	524, 72,
            	735, 80,
            0, 16, 1, /* 1091: struct.iovec */
            	112, 0,
            0, 8, 0, /* 1096: array[2].int */
            1, 8, 1, /* 1099: pointer.struct.rsa_st */
            	1104, 0,
            0, 168, 17, /* 1104: struct.rsa_st */
            	685, 16,
            	629, 24,
            	487, 32,
            	487, 40,
            	487, 48,
            	487, 56,
            	487, 64,
            	487, 72,
            	487, 80,
            	487, 88,
            	538, 96,
            	524, 120,
            	524, 128,
            	524, 136,
            	112, 144,
            	1141, 152,
            	1141, 160,
            1, 8, 1, /* 1141: pointer.struct.bn_blinding_st */
            	1074, 0,
            0, 0, 0, /* 1146: func */
            0, 0, 0, /* 1149: func */
            1, 8, 1, /* 1152: pointer.func */
            	1157, 0,
            0, 0, 0, /* 1157: func */
            0, 0, 0, /* 1160: func */
            1, 8, 1, /* 1163: pointer.func */
            	1149, 0,
            1, 8, 1, /* 1168: pointer.struct.unnamed */
            	1173, 0,
            0, 0, 0, /* 1173: struct.unnamed */
            0, 24, 3, /* 1176: struct.X509_pubkey_st */
            	1185, 0,
            	1226, 8,
            	1236, 16,
            1, 8, 1, /* 1185: pointer.struct.X509_algor_st */
            	1190, 0,
            0, 16, 2, /* 1190: struct.X509_algor_st */
            	1197, 0,
            	1211, 8,
            1, 8, 1, /* 1197: pointer.struct.asn1_object_st */
            	1202, 0,
            0, 40, 3, /* 1202: struct.asn1_object_st */
            	112, 0,
            	112, 8,
            	112, 24,
            1, 8, 1, /* 1211: pointer.struct.asn1_type_st */
            	1216, 0,
            0, 16, 1, /* 1216: struct.asn1_type_st */
            	1221, 8,
            0, 8, 1, /* 1221: struct.fnames */
            	112, 0,
            1, 8, 1, /* 1226: pointer.struct.asn1_string_st */
            	1231, 0,
            0, 24, 1, /* 1231: struct.asn1_string_st */
            	112, 8,
            1, 8, 1, /* 1236: pointer.struct.evp_pkey_st */
            	1241, 0,
            0, 56, 4, /* 1241: struct.evp_pkey_st */
            	1252, 16,
            	629, 24,
            	1221, 32,
            	543, 48,
            1, 8, 1, /* 1252: pointer.struct.evp_pkey_asn1_method_st */
            	1257, 0,
            0, 208, 24, /* 1257: struct.evp_pkey_asn1_method_st */
            	112, 16,
            	112, 24,
            	1168, 32,
            	1308, 40,
            	1152, 48,
            	1163, 56,
            	1313, 64,
            	1321, 72,
            	1163, 80,
            	1329, 88,
            	1329, 96,
            	1337, 104,
            	1345, 112,
            	1329, 120,
            	1152, 128,
            	1152, 136,
            	1163, 144,
            	1353, 152,
            	1361, 160,
            	1369, 168,
            	1337, 176,
            	1345, 184,
            	1377, 192,
            	1385, 200,
            1, 8, 1, /* 1308: pointer.func */
            	1160, 0,
            1, 8, 1, /* 1313: pointer.func */
            	1318, 0,
            0, 0, 0, /* 1318: func */
            1, 8, 1, /* 1321: pointer.func */
            	1326, 0,
            0, 0, 0, /* 1326: func */
            1, 8, 1, /* 1329: pointer.func */
            	1334, 0,
            0, 0, 0, /* 1334: func */
            1, 8, 1, /* 1337: pointer.func */
            	1342, 0,
            0, 0, 0, /* 1342: func */
            1, 8, 1, /* 1345: pointer.func */
            	1350, 0,
            0, 0, 0, /* 1350: func */
            1, 8, 1, /* 1353: pointer.func */
            	1358, 0,
            0, 0, 0, /* 1358: func */
            1, 8, 1, /* 1361: pointer.func */
            	1366, 0,
            0, 0, 0, /* 1366: func */
            1, 8, 1, /* 1369: pointer.func */
            	1374, 0,
            0, 0, 0, /* 1374: func */
            1, 8, 1, /* 1377: pointer.func */
            	1382, 0,
            0, 0, 0, /* 1382: func */
            1, 8, 1, /* 1385: pointer.func */
            	1390, 0,
            0, 0, 0, /* 1390: func */
            1, 8, 1, /* 1393: pointer.struct.X509_val_st */
            	1398, 0,
            0, 16, 2, /* 1398: struct.X509_val_st */
            	1226, 0,
            	1226, 8,
            0, 4, 0, /* 1405: struct.in_addr */
            0, 184, 12, /* 1408: struct.x509_st */
            	1435, 0,
            	1185, 8,
            	1226, 16,
            	112, 32,
            	538, 40,
            	1226, 104,
            	1499, 112,
            	1513, 120,
            	543, 128,
            	543, 136,
            	1539, 144,
            	1551, 176,
            1, 8, 1, /* 1435: pointer.struct.x509_cinf_st */
            	1440, 0,
            0, 104, 11, /* 1440: struct.x509_cinf_st */
            	1226, 0,
            	1226, 8,
            	1185, 16,
            	1465, 24,
            	1393, 32,
            	1465, 40,
            	1489, 48,
            	1226, 56,
            	1226, 64,
            	543, 72,
            	1494, 80,
            1, 8, 1, /* 1465: pointer.struct.X509_name_st */
            	1470, 0,
            0, 40, 3, /* 1470: struct.X509_name_st */
            	543, 0,
            	1479, 16,
            	112, 24,
            1, 8, 1, /* 1479: pointer.struct.buf_mem_st */
            	1484, 0,
            0, 24, 1, /* 1484: struct.buf_mem_st */
            	112, 8,
            1, 8, 1, /* 1489: pointer.struct.X509_pubkey_st */
            	1176, 0,
            0, 24, 1, /* 1494: struct.ASN1_ENCODING_st */
            	112, 0,
            1, 8, 1, /* 1499: pointer.struct.AUTHORITY_KEYID_st */
            	1504, 0,
            0, 24, 3, /* 1504: struct.AUTHORITY_KEYID_st */
            	1226, 0,
            	543, 8,
            	1226, 16,
            1, 8, 1, /* 1513: pointer.struct.X509_POLICY_CACHE_st */
            	1518, 0,
            0, 40, 2, /* 1518: struct.X509_POLICY_CACHE_st */
            	1525, 0,
            	543, 8,
            1, 8, 1, /* 1525: pointer.struct.X509_POLICY_DATA_st */
            	1530, 0,
            0, 32, 3, /* 1530: struct.X509_POLICY_DATA_st */
            	1197, 8,
            	543, 16,
            	543, 24,
            1, 8, 1, /* 1539: pointer.struct.NAME_CONSTRAINTS_st */
            	1544, 0,
            0, 16, 2, /* 1544: struct.NAME_CONSTRAINTS_st */
            	543, 0,
            	543, 8,
            1, 8, 1, /* 1551: pointer.struct.x509_cert_aux_st */
            	1556, 0,
            0, 40, 5, /* 1556: struct.x509_cert_aux_st */
            	543, 0,
            	543, 8,
            	1226, 16,
            	1226, 24,
            	543, 32,
            0, 0, 0, /* 1569: func */
            0, 248, 6, /* 1572: struct.sess_cert_st */
            	543, 0,
            	1587, 16,
            	1683, 24,
            	1099, 216,
            	1069, 224,
            	492, 232,
            1, 8, 1, /* 1587: pointer.struct.cert_pkey_st */
            	1592, 0,
            0, 24, 3, /* 1592: struct.cert_pkey_st */
            	1601, 0,
            	1236, 8,
            	1606, 16,
            1, 8, 1, /* 1601: pointer.struct.x509_st */
            	1408, 0,
            1, 8, 1, /* 1606: pointer.struct.env_md_st */
            	1611, 0,
            0, 120, 8, /* 1611: struct.env_md_st */
            	1630, 24,
            	1638, 32,
            	1646, 40,
            	1654, 48,
            	1630, 56,
            	1662, 64,
            	1670, 72,
            	1678, 112,
            1, 8, 1, /* 1630: pointer.func */
            	1635, 0,
            0, 0, 0, /* 1635: func */
            1, 8, 1, /* 1638: pointer.func */
            	1643, 0,
            0, 0, 0, /* 1643: func */
            1, 8, 1, /* 1646: pointer.func */
            	1651, 0,
            0, 0, 0, /* 1651: func */
            1, 8, 1, /* 1654: pointer.func */
            	1659, 0,
            0, 0, 0, /* 1659: func */
            1, 8, 1, /* 1662: pointer.func */
            	1667, 0,
            0, 0, 0, /* 1667: func */
            1, 8, 1, /* 1670: pointer.func */
            	1675, 0,
            0, 0, 0, /* 1675: func */
            1, 8, 1, /* 1678: pointer.func */
            	1146, 0,
            0, 192, 8, /* 1683: array[8].struct.cert_pkey_st */
            	1592, 0,
            	1592, 24,
            	1592, 48,
            	1592, 72,
            	1592, 96,
            	1592, 120,
            	1592, 144,
            	1592, 168,
            1, 8, 1, /* 1702: pointer.func */
            	1569, 0,
            0, 352, 14, /* 1707: struct.ssl_session_st */
            	112, 144,
            	112, 152,
            	1738, 168,
            	1601, 176,
            	102, 224,
            	543, 240,
            	538, 248,
            	1743, 264,
            	1743, 272,
            	112, 280,
            	112, 296,
            	112, 312,
            	112, 320,
            	112, 344,
            1, 8, 1, /* 1738: pointer.struct.sess_cert_st */
            	1572, 0,
            1, 8, 1, /* 1743: pointer.struct.ssl_session_st */
            	1707, 0,
            1, 8, 1, /* 1748: pointer.func */
            	1753, 0,
            0, 0, 0, /* 1753: func */
            1, 8, 1, /* 1756: pointer.struct.in_addr */
            	1405, 0,
            1, 8, 1, /* 1761: pointer.func */
            	1766, 0,
            0, 0, 0, /* 1766: func */
            1, 8, 1, /* 1769: pointer.func */
            	1774, 0,
            0, 0, 0, /* 1774: func */
            1, 8, 1, /* 1777: pointer.func */
            	1782, 0,
            0, 0, 0, /* 1782: func */
            0, 0, 0, /* 1785: func */
            1, 8, 1, /* 1788: pointer.func */
            	1793, 0,
            0, 0, 0, /* 1793: func */
            0, 8, 0, /* 1796: long */
            0, 0, 0, /* 1799: func */
            0, 144, 15, /* 1802: struct.x509_store_st */
            	543, 8,
            	543, 16,
            	1835, 24,
            	1847, 32,
            	1852, 40,
            	1860, 48,
            	1865, 56,
            	1847, 64,
            	1873, 72,
            	1777, 80,
            	1881, 88,
            	1761, 96,
            	1761, 104,
            	1847, 112,
            	538, 120,
            1, 8, 1, /* 1835: pointer.struct.X509_VERIFY_PARAM_st */
            	1840, 0,
            0, 56, 2, /* 1840: struct.X509_VERIFY_PARAM_st */
            	112, 0,
            	543, 48,
            1, 8, 1, /* 1847: pointer.func */
            	1799, 0,
            1, 8, 1, /* 1852: pointer.func */
            	1857, 0,
            0, 0, 0, /* 1857: func */
            1, 8, 1, /* 1860: pointer.func */
            	1785, 0,
            1, 8, 1, /* 1865: pointer.func */
            	1870, 0,
            0, 0, 0, /* 1870: func */
            1, 8, 1, /* 1873: pointer.func */
            	1878, 0,
            0, 0, 0, /* 1878: func */
            1, 8, 1, /* 1881: pointer.func */
            	1886, 0,
            0, 0, 0, /* 1886: func */
            0, 0, 0, /* 1889: func */
            1, 8, 1, /* 1892: pointer.struct.x509_store_st */
            	1802, 0,
            0, 0, 0, /* 1897: func */
            1, 8, 1, /* 1900: pointer.func */
            	1905, 0,
            0, 0, 0, /* 1905: func */
            0, 0, 0, /* 1908: func */
            1, 8, 1, /* 1911: pointer.func */
            	1916, 0,
            0, 0, 0, /* 1916: func */
            0, 0, 0, /* 1919: func */
            0, 0, 0, /* 1922: func */
            0, 0, 0, /* 1925: func */
            1, 8, 1, /* 1928: pointer.func */
            	1933, 0,
            0, 0, 0, /* 1933: func */
            0, 32, 0, /* 1936: array[32].char */
            0, 0, 0, /* 1939: func */
            1, 8, 1, /* 1942: pointer.func */
            	1919, 0,
            1, 8, 1, /* 1947: pointer.func */
            	1952, 0,
            0, 0, 0, /* 1952: func */
            1, 8, 1, /* 1955: pointer.func */
            	1960, 0,
            0, 0, 0, /* 1960: func */
            1, 8, 1, /* 1963: pointer.func */
            	1922, 0,
            1, 8, 1, /* 1968: pointer.func */
            	1973, 0,
            0, 0, 0, /* 1973: func */
            1, 8, 1, /* 1976: pointer.func */
            	1908, 0,
            0, 736, 50, /* 1981: struct.ssl_ctx_st.2836 */
            	2084, 0,
            	543, 8,
            	543, 16,
            	1892, 24,
            	1756, 32,
            	1743, 48,
            	1743, 56,
            	1928, 80,
            	1769, 88,
            	1947, 96,
            	2278, 152,
            	112, 160,
            	91, 168,
            	112, 176,
            	80, 184,
            	2286, 192,
            	2156, 200,
            	538, 208,
            	1606, 224,
            	1606, 232,
            	1606, 240,
            	543, 248,
            	543, 256,
            	69, 264,
            	543, 272,
            	2291, 304,
            	53, 320,
            	112, 328,
            	1852, 376,
            	2286, 384,
            	1835, 392,
            	629, 408,
            	2315, 416,
            	112, 424,
            	1702, 480,
            	42, 488,
            	112, 496,
            	37, 504,
            	112, 512,
            	112, 520,
            	26, 528,
            	2225, 536,
            	2320, 552,
            	2320, 560,
            	2330, 568,
            	8, 696,
            	112, 704,
            	3, 712,
            	112, 720,
            	543, 728,
            1, 8, 1, /* 2084: pointer.struct.ssl_method_st.2838 */
            	2089, 0,
            0, 232, 28, /* 2089: struct.ssl_method_st.2838 */
            	1911, 8,
            	2148, 16,
            	2148, 24,
            	1911, 32,
            	1911, 40,
            	2156, 48,
            	2156, 56,
            	2156, 64,
            	1911, 72,
            	1911, 80,
            	1911, 88,
            	2164, 96,
            	1955, 104,
            	2169, 112,
            	1911, 120,
            	1942, 128,
            	2174, 136,
            	1963, 144,
            	1976, 152,
            	1911, 160,
            	977, 168,
            	1900, 176,
            	2182, 184,
            	2190, 192,
            	2195, 200,
            	977, 208,
            	2265, 216,
            	2273, 224,
            1, 8, 1, /* 2148: pointer.func */
            	2153, 0,
            0, 0, 0, /* 2153: func */
            1, 8, 1, /* 2156: pointer.func */
            	2161, 0,
            0, 0, 0, /* 2161: func */
            1, 8, 1, /* 2164: pointer.func */
            	1889, 0,
            1, 8, 1, /* 2169: pointer.func */
            	1925, 0,
            1, 8, 1, /* 2174: pointer.func */
            	2179, 0,
            0, 0, 0, /* 2179: func */
            1, 8, 1, /* 2182: pointer.func */
            	2187, 0,
            0, 0, 0, /* 2187: func */
            1, 8, 1, /* 2190: pointer.func */
            	1897, 0,
            1, 8, 1, /* 2195: pointer.struct.ssl3_enc_method.2837 */
            	2200, 0,
            0, 112, 11, /* 2200: struct.ssl3_enc_method.2837 */
            	1968, 0,
            	2156, 8,
            	1911, 16,
            	2225, 24,
            	1968, 32,
            	2233, 40,
            	2241, 56,
            	112, 64,
            	112, 80,
            	2249, 96,
            	2257, 104,
            1, 8, 1, /* 2225: pointer.func */
            	2230, 0,
            0, 0, 0, /* 2230: func */
            1, 8, 1, /* 2233: pointer.func */
            	2238, 0,
            0, 0, 0, /* 2238: func */
            1, 8, 1, /* 2241: pointer.func */
            	2246, 0,
            0, 0, 0, /* 2246: func */
            1, 8, 1, /* 2249: pointer.func */
            	2254, 0,
            0, 0, 0, /* 2254: func */
            1, 8, 1, /* 2257: pointer.func */
            	2262, 0,
            0, 0, 0, /* 2262: func */
            1, 8, 1, /* 2265: pointer.func */
            	2270, 0,
            0, 0, 0, /* 2270: func */
            1, 8, 1, /* 2273: pointer.func */
            	1939, 0,
            1, 8, 1, /* 2278: pointer.func */
            	2283, 0,
            0, 0, 0, /* 2283: func */
            1, 8, 1, /* 2286: pointer.func */
            	77, 0,
            1, 8, 1, /* 2291: pointer.struct.cert_st.2861 */
            	2296, 0,
            0, 296, 8, /* 2296: struct.cert_st.2861 */
            	1587, 0,
            	1099, 48,
            	64, 56,
            	1069, 64,
            	1748, 72,
            	492, 80,
            	1788, 88,
            	1683, 96,
            1, 8, 1, /* 2315: pointer.func */
            	99, 0,
            1, 8, 1, /* 2320: pointer.struct.ssl3_buf_freelist_st */
            	2325, 0,
            0, 24, 1, /* 2325: struct.ssl3_buf_freelist_st */
            	16, 16,
            0, 128, 14, /* 2330: struct.srp_ctx_st.2835 */
            	112, 0,
            	2315, 8,
            	42, 16,
            	2361, 24,
            	112, 32,
            	487, 40,
            	487, 48,
            	487, 56,
            	487, 64,
            	487, 72,
            	487, 80,
            	487, 88,
            	487, 96,
            	112, 104,
            1, 8, 1, /* 2361: pointer.func */
            	2366, 0,
            0, 0, 0, /* 2366: func */
            1, 8, 1, /* 2369: pointer.struct.ssl_ctx_st.2836 */
            	1981, 0,
            0, 8, 0, /* 2374: array[8].char */
            0, 20, 0, /* 2377: array[5].int */
            0, 48, 0, /* 2380: array[48].char */
            0, 20, 0, /* 2383: array[20].char */
        },
        .arg_entity_index = { 2369, 112, },
        .ret_entity_index = 428,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    SSL_CTX * new_arg_a = *((SSL_CTX * *)new_args->args[0]);

    const char * new_arg_b = *((const char * *)new_args->args[1]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_SSL_CTX_use_certificate_chain_file)(SSL_CTX *,const char *);
    orig_SSL_CTX_use_certificate_chain_file = dlsym(RTLD_NEXT, "SSL_CTX_use_certificate_chain_file");
    *new_ret_ptr = (*orig_SSL_CTX_use_certificate_chain_file)(new_arg_a,new_arg_b);

    syscall(889);

    return ret;
}

