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

const SSL_CIPHER * SSL_get_current_cipher(const SSL * arg_a) 
{
    const SSL_CIPHER * ret;

    struct lib_enter_args args = {
        .entity_metadata = {
            0, 0, 0, /* 0: func */
            1, 8, 1, /* 3: pointer.func */
            	0, 0,
            0, 16, 1, /* 8: struct.tls_session_ticket_ext_st */
            	13, 8,
            1, 8, 1, /* 13: pointer.char */
            	18, 0,
            0, 1, 0, /* 18: char */
            1, 8, 1, /* 21: pointer.func */
            	26, 0,
            0, 0, 0, /* 26: func */
            0, 0, 0, /* 29: func */
            1, 8, 1, /* 32: pointer.func */
            	29, 0,
            0, 0, 0, /* 37: func */
            1, 8, 1, /* 40: pointer.func */
            	45, 0,
            0, 0, 0, /* 45: func */
            0, 0, 0, /* 48: func */
            1, 8, 1, /* 51: pointer.func */
            	48, 0,
            0, 0, 0, /* 56: func */
            1, 8, 1, /* 59: pointer.func */
            	56, 0,
            0, 0, 0, /* 64: func */
            1, 8, 1, /* 67: pointer.func */
            	64, 0,
            0, 0, 0, /* 72: func */
            0, 0, 0, /* 75: func */
            1, 8, 1, /* 78: pointer.func */
            	75, 0,
            0, 0, 0, /* 83: func */
            1, 8, 1, /* 86: pointer.func */
            	83, 0,
            0, 44, 0, /* 91: struct.apr_time_exp_t */
            0, 0, 0, /* 94: func */
            1, 8, 1, /* 97: pointer.func */
            	94, 0,
            0, 4, 0, /* 102: struct.in_addr */
            0, 0, 0, /* 105: func */
            1, 8, 1, /* 108: pointer.func */
            	113, 0,
            0, 0, 0, /* 113: func */
            1, 8, 1, /* 116: pointer.func */
            	121, 0,
            0, 0, 0, /* 121: func */
            1, 8, 1, /* 124: pointer.func */
            	129, 0,
            0, 0, 0, /* 129: func */
            1, 8, 1, /* 132: pointer.func */
            	137, 0,
            0, 0, 0, /* 137: func */
            0, 0, 0, /* 140: func */
            1, 8, 1, /* 143: pointer.func */
            	140, 0,
            0, 0, 0, /* 148: func */
            0, 736, 50, /* 151: struct.ssl_ctx_st.752 */
            	254, 0,
            	524, 8,
            	524, 16,
            	554, 24,
            	627, 32,
            	632, 48,
            	632, 56,
            	97, 80,
            	2202, 88,
            	2210, 96,
            	2218, 152,
            	13, 160,
            	86, 168,
            	13, 176,
            	78, 184,
            	2226, 192,
            	334, 200,
            	622, 208,
            	1604, 224,
            	1604, 232,
            	1604, 240,
            	524, 248,
            	524, 256,
            	2234, 264,
            	524, 272,
            	2242, 304,
            	2290, 320,
            	13, 328,
            	609, 376,
            	2226, 384,
            	592, 392,
            	1041, 408,
            	2298, 416,
            	13, 424,
            	67, 480,
            	59, 488,
            	13, 496,
            	51, 504,
            	13, 512,
            	13, 520,
            	2303, 528,
            	468, 536,
            	2311, 552,
            	2311, 560,
            	2331, 568,
            	2362, 696,
            	13, 704,
            	32, 712,
            	13, 720,
            	524, 728,
            1, 8, 1, /* 254: pointer.struct.ssl_method_st.754 */
            	259, 0,
            0, 232, 28, /* 259: struct.ssl_method_st.754 */
            	318, 8,
            	326, 16,
            	326, 24,
            	318, 32,
            	318, 40,
            	334, 48,
            	334, 56,
            	334, 64,
            	318, 72,
            	318, 80,
            	318, 88,
            	342, 96,
            	350, 104,
            	358, 112,
            	318, 120,
            	366, 128,
            	374, 136,
            	382, 144,
            	390, 152,
            	318, 160,
            	398, 168,
            	406, 176,
            	414, 184,
            	422, 192,
            	430, 200,
            	398, 208,
            	508, 216,
            	516, 224,
            1, 8, 1, /* 318: pointer.func */
            	323, 0,
            0, 0, 0, /* 323: func */
            1, 8, 1, /* 326: pointer.func */
            	331, 0,
            0, 0, 0, /* 331: func */
            1, 8, 1, /* 334: pointer.func */
            	339, 0,
            0, 0, 0, /* 339: func */
            1, 8, 1, /* 342: pointer.func */
            	347, 0,
            0, 0, 0, /* 347: func */
            1, 8, 1, /* 350: pointer.func */
            	355, 0,
            0, 0, 0, /* 355: func */
            1, 8, 1, /* 358: pointer.func */
            	363, 0,
            0, 0, 0, /* 363: func */
            1, 8, 1, /* 366: pointer.func */
            	371, 0,
            0, 0, 0, /* 371: func */
            1, 8, 1, /* 374: pointer.func */
            	379, 0,
            0, 0, 0, /* 379: func */
            1, 8, 1, /* 382: pointer.func */
            	387, 0,
            0, 0, 0, /* 387: func */
            1, 8, 1, /* 390: pointer.func */
            	395, 0,
            0, 0, 0, /* 395: func */
            1, 8, 1, /* 398: pointer.func */
            	403, 0,
            0, 0, 0, /* 403: func */
            1, 8, 1, /* 406: pointer.func */
            	411, 0,
            0, 0, 0, /* 411: func */
            1, 8, 1, /* 414: pointer.func */
            	419, 0,
            0, 0, 0, /* 419: func */
            1, 8, 1, /* 422: pointer.func */
            	427, 0,
            0, 0, 0, /* 427: func */
            1, 8, 1, /* 430: pointer.struct.ssl3_enc_method.753 */
            	435, 0,
            0, 112, 11, /* 435: struct.ssl3_enc_method.753 */
            	460, 0,
            	334, 8,
            	318, 16,
            	468, 24,
            	460, 32,
            	476, 40,
            	484, 56,
            	13, 64,
            	13, 80,
            	492, 96,
            	500, 104,
            1, 8, 1, /* 460: pointer.struct.unnamed */
            	465, 0,
            0, 0, 0, /* 465: struct.unnamed */
            1, 8, 1, /* 468: pointer.func */
            	473, 0,
            0, 0, 0, /* 473: func */
            1, 8, 1, /* 476: pointer.func */
            	481, 0,
            0, 0, 0, /* 481: func */
            1, 8, 1, /* 484: pointer.func */
            	489, 0,
            0, 0, 0, /* 489: func */
            1, 8, 1, /* 492: pointer.func */
            	497, 0,
            0, 0, 0, /* 497: func */
            1, 8, 1, /* 500: pointer.func */
            	505, 0,
            0, 0, 0, /* 505: func */
            1, 8, 1, /* 508: pointer.func */
            	513, 0,
            0, 0, 0, /* 513: func */
            1, 8, 1, /* 516: pointer.func */
            	521, 0,
            0, 0, 0, /* 521: func */
            1, 8, 1, /* 524: pointer.struct.stack_st_OPENSSL_STRING */
            	529, 0,
            0, 32, 1, /* 529: struct.stack_st_OPENSSL_STRING */
            	534, 0,
            0, 32, 2, /* 534: struct.stack_st */
            	541, 8,
            	546, 24,
            1, 8, 1, /* 541: pointer.pointer.char */
            	13, 0,
            1, 8, 1, /* 546: pointer.func */
            	551, 0,
            0, 0, 0, /* 551: func */
            1, 8, 1, /* 554: pointer.struct.x509_store_st */
            	559, 0,
            0, 144, 15, /* 559: struct.x509_store_st */
            	524, 8,
            	524, 16,
            	592, 24,
            	604, 32,
            	609, 40,
            	143, 48,
            	132, 56,
            	604, 64,
            	124, 72,
            	116, 80,
            	108, 88,
            	617, 96,
            	617, 104,
            	604, 112,
            	622, 120,
            1, 8, 1, /* 592: pointer.struct.X509_VERIFY_PARAM_st */
            	597, 0,
            0, 56, 2, /* 597: struct.X509_VERIFY_PARAM_st */
            	13, 0,
            	524, 48,
            1, 8, 1, /* 604: pointer.func */
            	148, 0,
            1, 8, 1, /* 609: pointer.func */
            	614, 0,
            0, 0, 0, /* 614: func */
            1, 8, 1, /* 617: pointer.func */
            	105, 0,
            0, 16, 1, /* 622: struct.crypto_ex_data_st */
            	524, 0,
            1, 8, 1, /* 627: pointer.struct.in_addr */
            	102, 0,
            1, 8, 1, /* 632: pointer.struct.ssl_session_st */
            	637, 0,
            0, 352, 14, /* 637: struct.ssl_session_st */
            	13, 144,
            	13, 152,
            	668, 168,
            	702, 176,
            	2192, 224,
            	524, 240,
            	622, 248,
            	632, 264,
            	632, 272,
            	13, 280,
            	13, 296,
            	13, 312,
            	13, 320,
            	13, 344,
            1, 8, 1, /* 668: pointer.struct.sess_cert_st */
            	673, 0,
            0, 248, 6, /* 673: struct.sess_cert_st */
            	524, 0,
            	688, 16,
            	1684, 24,
            	1703, 216,
            	1804, 224,
            	1836, 232,
            1, 8, 1, /* 688: pointer.struct.cert_pkey_st */
            	693, 0,
            0, 24, 3, /* 693: struct.cert_pkey_st */
            	702, 0,
            	865, 8,
            	1604, 16,
            1, 8, 1, /* 702: pointer.struct.x509_st */
            	707, 0,
            0, 184, 12, /* 707: struct.x509_st */
            	734, 0,
            	774, 8,
            	764, 16,
            	13, 32,
            	622, 40,
            	764, 104,
            	1534, 112,
            	1548, 120,
            	524, 128,
            	524, 136,
            	1574, 144,
            	1586, 176,
            1, 8, 1, /* 734: pointer.struct.x509_cinf_st */
            	739, 0,
            0, 104, 11, /* 739: struct.x509_cinf_st */
            	764, 0,
            	764, 8,
            	774, 16,
            	815, 24,
            	839, 32,
            	815, 40,
            	851, 48,
            	764, 56,
            	764, 64,
            	524, 72,
            	1529, 80,
            1, 8, 1, /* 764: pointer.struct.asn1_string_st */
            	769, 0,
            0, 24, 1, /* 769: struct.asn1_string_st */
            	13, 8,
            1, 8, 1, /* 774: pointer.struct.X509_algor_st */
            	779, 0,
            0, 16, 2, /* 779: struct.X509_algor_st */
            	786, 0,
            	800, 8,
            1, 8, 1, /* 786: pointer.struct.asn1_object_st */
            	791, 0,
            0, 40, 3, /* 791: struct.asn1_object_st */
            	13, 0,
            	13, 8,
            	13, 24,
            1, 8, 1, /* 800: pointer.struct.asn1_type_st */
            	805, 0,
            0, 16, 1, /* 805: struct.asn1_type_st */
            	810, 8,
            0, 8, 1, /* 810: struct.fnames */
            	13, 0,
            1, 8, 1, /* 815: pointer.struct.X509_name_st */
            	820, 0,
            0, 40, 3, /* 820: struct.X509_name_st */
            	524, 0,
            	829, 16,
            	13, 24,
            1, 8, 1, /* 829: pointer.struct.buf_mem_st */
            	834, 0,
            0, 24, 1, /* 834: struct.buf_mem_st */
            	13, 8,
            1, 8, 1, /* 839: pointer.struct.X509_val_st */
            	844, 0,
            0, 16, 2, /* 844: struct.X509_val_st */
            	764, 0,
            	764, 8,
            1, 8, 1, /* 851: pointer.struct.X509_pubkey_st */
            	856, 0,
            0, 24, 3, /* 856: struct.X509_pubkey_st */
            	774, 0,
            	764, 8,
            	865, 16,
            1, 8, 1, /* 865: pointer.struct.evp_pkey_st */
            	870, 0,
            0, 56, 4, /* 870: struct.evp_pkey_st */
            	881, 16,
            	1041, 24,
            	810, 32,
            	524, 48,
            1, 8, 1, /* 881: pointer.struct.evp_pkey_asn1_method_st */
            	886, 0,
            0, 208, 24, /* 886: struct.evp_pkey_asn1_method_st */
            	13, 16,
            	13, 24,
            	460, 32,
            	937, 40,
            	945, 48,
            	953, 56,
            	961, 64,
            	969, 72,
            	953, 80,
            	977, 88,
            	977, 96,
            	985, 104,
            	993, 112,
            	977, 120,
            	945, 128,
            	945, 136,
            	953, 144,
            	1001, 152,
            	1009, 160,
            	1017, 168,
            	985, 176,
            	993, 184,
            	1025, 192,
            	1033, 200,
            1, 8, 1, /* 937: pointer.func */
            	942, 0,
            0, 0, 0, /* 942: func */
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
            1, 8, 1, /* 985: pointer.func */
            	990, 0,
            0, 0, 0, /* 990: func */
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
            1, 8, 1, /* 1041: pointer.struct.engine_st */
            	1046, 0,
            0, 216, 24, /* 1046: struct.engine_st */
            	13, 0,
            	13, 8,
            	1097, 16,
            	1187, 24,
            	1273, 32,
            	1329, 40,
            	1351, 48,
            	1393, 56,
            	1445, 64,
            	1453, 72,
            	1461, 80,
            	1469, 88,
            	1477, 96,
            	1485, 104,
            	1485, 112,
            	1485, 120,
            	1493, 128,
            	1501, 136,
            	1501, 144,
            	1509, 152,
            	1517, 160,
            	622, 184,
            	1041, 200,
            	1041, 208,
            1, 8, 1, /* 1097: pointer.struct.rsa_meth_st */
            	1102, 0,
            0, 112, 13, /* 1102: struct.rsa_meth_st */
            	13, 0,
            	1131, 8,
            	1131, 16,
            	1131, 24,
            	1131, 32,
            	1139, 40,
            	1147, 48,
            	1155, 56,
            	1155, 64,
            	13, 80,
            	1163, 88,
            	1171, 96,
            	1179, 104,
            1, 8, 1, /* 1131: pointer.func */
            	1136, 0,
            0, 0, 0, /* 1136: func */
            1, 8, 1, /* 1139: pointer.func */
            	1144, 0,
            0, 0, 0, /* 1144: func */
            1, 8, 1, /* 1147: pointer.func */
            	1152, 0,
            0, 0, 0, /* 1152: func */
            1, 8, 1, /* 1155: pointer.func */
            	1160, 0,
            0, 0, 0, /* 1160: func */
            1, 8, 1, /* 1163: pointer.func */
            	1168, 0,
            0, 0, 0, /* 1168: func */
            1, 8, 1, /* 1171: pointer.func */
            	1176, 0,
            0, 0, 0, /* 1176: func */
            1, 8, 1, /* 1179: pointer.func */
            	1184, 0,
            0, 0, 0, /* 1184: func */
            1, 8, 1, /* 1187: pointer.struct.dsa_method.1040 */
            	1192, 0,
            0, 96, 11, /* 1192: struct.dsa_method.1040 */
            	13, 0,
            	1217, 8,
            	1225, 16,
            	1233, 24,
            	1241, 32,
            	1249, 40,
            	1257, 48,
            	1257, 56,
            	13, 72,
            	1265, 80,
            	1257, 88,
            1, 8, 1, /* 1217: pointer.func */
            	1222, 0,
            0, 0, 0, /* 1222: func */
            1, 8, 1, /* 1225: pointer.func */
            	1230, 0,
            0, 0, 0, /* 1230: func */
            1, 8, 1, /* 1233: pointer.func */
            	1238, 0,
            0, 0, 0, /* 1238: func */
            1, 8, 1, /* 1241: pointer.func */
            	1246, 0,
            0, 0, 0, /* 1246: func */
            1, 8, 1, /* 1249: pointer.func */
            	1254, 0,
            0, 0, 0, /* 1254: func */
            1, 8, 1, /* 1257: pointer.func */
            	1262, 0,
            0, 0, 0, /* 1262: func */
            1, 8, 1, /* 1265: pointer.func */
            	1270, 0,
            0, 0, 0, /* 1270: func */
            1, 8, 1, /* 1273: pointer.struct.dh_method */
            	1278, 0,
            0, 72, 8, /* 1278: struct.dh_method */
            	13, 0,
            	1297, 8,
            	1305, 16,
            	1313, 24,
            	1297, 32,
            	1297, 40,
            	13, 56,
            	1321, 64,
            1, 8, 1, /* 1297: pointer.func */
            	1302, 0,
            0, 0, 0, /* 1302: func */
            1, 8, 1, /* 1305: pointer.func */
            	1310, 0,
            0, 0, 0, /* 1310: func */
            1, 8, 1, /* 1313: pointer.func */
            	1318, 0,
            0, 0, 0, /* 1318: func */
            1, 8, 1, /* 1321: pointer.func */
            	1326, 0,
            0, 0, 0, /* 1326: func */
            1, 8, 1, /* 1329: pointer.struct.ecdh_method */
            	1334, 0,
            0, 32, 3, /* 1334: struct.ecdh_method */
            	13, 0,
            	1343, 8,
            	13, 24,
            1, 8, 1, /* 1343: pointer.func */
            	1348, 0,
            0, 0, 0, /* 1348: func */
            1, 8, 1, /* 1351: pointer.struct.ecdsa_method */
            	1356, 0,
            0, 48, 5, /* 1356: struct.ecdsa_method */
            	13, 0,
            	1369, 8,
            	1377, 16,
            	1385, 24,
            	13, 40,
            1, 8, 1, /* 1369: pointer.func */
            	1374, 0,
            0, 0, 0, /* 1374: func */
            1, 8, 1, /* 1377: pointer.func */
            	1382, 0,
            0, 0, 0, /* 1382: func */
            1, 8, 1, /* 1385: pointer.func */
            	1390, 0,
            0, 0, 0, /* 1390: func */
            1, 8, 1, /* 1393: pointer.struct.rand_meth_st */
            	1398, 0,
            0, 48, 6, /* 1398: struct.rand_meth_st */
            	1413, 0,
            	1421, 8,
            	1429, 16,
            	1437, 24,
            	1421, 32,
            	398, 40,
            1, 8, 1, /* 1413: pointer.func */
            	1418, 0,
            0, 0, 0, /* 1418: func */
            1, 8, 1, /* 1421: pointer.func */
            	1426, 0,
            0, 0, 0, /* 1426: func */
            1, 8, 1, /* 1429: pointer.func */
            	1434, 0,
            0, 0, 0, /* 1434: func */
            1, 8, 1, /* 1437: pointer.func */
            	1442, 0,
            0, 0, 0, /* 1442: func */
            1, 8, 1, /* 1445: pointer.struct.store_method_st */
            	1450, 0,
            0, 0, 0, /* 1450: struct.store_method_st */
            1, 8, 1, /* 1453: pointer.func */
            	1458, 0,
            0, 0, 0, /* 1458: func */
            1, 8, 1, /* 1461: pointer.func */
            	1466, 0,
            0, 0, 0, /* 1466: func */
            1, 8, 1, /* 1469: pointer.func */
            	1474, 0,
            0, 0, 0, /* 1474: func */
            1, 8, 1, /* 1477: pointer.func */
            	1482, 0,
            0, 0, 0, /* 1482: func */
            1, 8, 1, /* 1485: pointer.func */
            	1490, 0,
            0, 0, 0, /* 1490: func */
            1, 8, 1, /* 1493: pointer.func */
            	1498, 0,
            0, 0, 0, /* 1498: func */
            1, 8, 1, /* 1501: pointer.func */
            	1506, 0,
            0, 0, 0, /* 1506: func */
            1, 8, 1, /* 1509: pointer.func */
            	1514, 0,
            0, 0, 0, /* 1514: func */
            1, 8, 1, /* 1517: pointer.struct.ENGINE_CMD_DEFN_st */
            	1522, 0,
            0, 32, 2, /* 1522: struct.ENGINE_CMD_DEFN_st */
            	13, 8,
            	13, 16,
            0, 24, 1, /* 1529: struct.ASN1_ENCODING_st */
            	13, 0,
            1, 8, 1, /* 1534: pointer.struct.AUTHORITY_KEYID_st */
            	1539, 0,
            0, 24, 3, /* 1539: struct.AUTHORITY_KEYID_st */
            	764, 0,
            	524, 8,
            	764, 16,
            1, 8, 1, /* 1548: pointer.struct.X509_POLICY_CACHE_st */
            	1553, 0,
            0, 40, 2, /* 1553: struct.X509_POLICY_CACHE_st */
            	1560, 0,
            	524, 8,
            1, 8, 1, /* 1560: pointer.struct.X509_POLICY_DATA_st */
            	1565, 0,
            0, 32, 3, /* 1565: struct.X509_POLICY_DATA_st */
            	786, 8,
            	524, 16,
            	524, 24,
            1, 8, 1, /* 1574: pointer.struct.NAME_CONSTRAINTS_st */
            	1579, 0,
            0, 16, 2, /* 1579: struct.NAME_CONSTRAINTS_st */
            	524, 0,
            	524, 8,
            1, 8, 1, /* 1586: pointer.struct.x509_cert_aux_st */
            	1591, 0,
            0, 40, 5, /* 1591: struct.x509_cert_aux_st */
            	524, 0,
            	524, 8,
            	764, 16,
            	764, 24,
            	524, 32,
            1, 8, 1, /* 1604: pointer.struct.env_md_st */
            	1609, 0,
            0, 120, 8, /* 1609: struct.env_md_st */
            	1628, 24,
            	1636, 32,
            	1644, 40,
            	1652, 48,
            	1628, 56,
            	1660, 64,
            	1668, 72,
            	1676, 112,
            1, 8, 1, /* 1628: pointer.func */
            	1633, 0,
            0, 0, 0, /* 1633: func */
            1, 8, 1, /* 1636: pointer.func */
            	1641, 0,
            0, 0, 0, /* 1641: func */
            1, 8, 1, /* 1644: pointer.func */
            	1649, 0,
            0, 0, 0, /* 1649: func */
            1, 8, 1, /* 1652: pointer.func */
            	1657, 0,
            0, 0, 0, /* 1657: func */
            1, 8, 1, /* 1660: pointer.func */
            	1665, 0,
            0, 0, 0, /* 1665: func */
            1, 8, 1, /* 1668: pointer.func */
            	1673, 0,
            0, 0, 0, /* 1673: func */
            1, 8, 1, /* 1676: pointer.func */
            	1681, 0,
            0, 0, 0, /* 1681: func */
            0, 192, 8, /* 1684: array[8].struct.cert_pkey_st */
            	693, 0,
            	693, 24,
            	693, 48,
            	693, 72,
            	693, 96,
            	693, 120,
            	693, 144,
            	693, 168,
            1, 8, 1, /* 1703: pointer.struct.rsa_st */
            	1708, 0,
            0, 168, 17, /* 1708: struct.rsa_st */
            	1097, 16,
            	1041, 24,
            	1745, 32,
            	1745, 40,
            	1745, 48,
            	1745, 56,
            	1745, 64,
            	1745, 72,
            	1745, 80,
            	1745, 88,
            	622, 96,
            	1763, 120,
            	1763, 128,
            	1763, 136,
            	13, 144,
            	1777, 152,
            	1777, 160,
            1, 8, 1, /* 1745: pointer.struct.bignum_st */
            	1750, 0,
            0, 24, 1, /* 1750: struct.bignum_st */
            	1755, 0,
            1, 8, 1, /* 1755: pointer.int */
            	1760, 0,
            0, 4, 0, /* 1760: int */
            1, 8, 1, /* 1763: pointer.struct.bn_mont_ctx_st */
            	1768, 0,
            0, 96, 3, /* 1768: struct.bn_mont_ctx_st */
            	1750, 8,
            	1750, 32,
            	1750, 56,
            1, 8, 1, /* 1777: pointer.struct.bn_blinding_st */
            	1782, 0,
            0, 88, 7, /* 1782: struct.bn_blinding_st */
            	1745, 0,
            	1745, 8,
            	1745, 16,
            	1745, 24,
            	1799, 40,
            	1763, 72,
            	1147, 80,
            0, 16, 1, /* 1799: struct.iovec */
            	13, 0,
            1, 8, 1, /* 1804: pointer.struct.dh_st */
            	1809, 0,
            0, 144, 12, /* 1809: struct.dh_st */
            	1745, 8,
            	1745, 16,
            	1745, 32,
            	1745, 40,
            	1763, 56,
            	1745, 64,
            	1745, 72,
            	13, 80,
            	1745, 96,
            	622, 112,
            	1273, 128,
            	1041, 136,
            1, 8, 1, /* 1836: pointer.struct.ec_key_st.284 */
            	1841, 0,
            0, 56, 4, /* 1841: struct.ec_key_st.284 */
            	1852, 8,
            	2134, 16,
            	1745, 24,
            	2150, 48,
            1, 8, 1, /* 1852: pointer.struct.ec_group_st */
            	1857, 0,
            0, 232, 12, /* 1857: struct.ec_group_st */
            	1884, 0,
            	2134, 8,
            	1750, 16,
            	1750, 40,
            	13, 80,
            	2150, 96,
            	1750, 104,
            	1750, 152,
            	1750, 176,
            	13, 208,
            	13, 216,
            	2184, 224,
            1, 8, 1, /* 1884: pointer.struct.ec_method_st */
            	1889, 0,
            0, 304, 37, /* 1889: struct.ec_method_st */
            	1966, 8,
            	1974, 16,
            	1974, 24,
            	1982, 32,
            	1990, 40,
            	1990, 48,
            	1966, 56,
            	1998, 64,
            	2006, 72,
            	2014, 80,
            	2014, 88,
            	2022, 96,
            	2030, 104,
            	2038, 112,
            	2038, 120,
            	2046, 128,
            	2046, 136,
            	2054, 144,
            	2062, 152,
            	2070, 160,
            	2078, 168,
            	2086, 176,
            	2094, 184,
            	2030, 192,
            	2094, 200,
            	2086, 208,
            	2094, 216,
            	2102, 224,
            	2110, 232,
            	1998, 240,
            	1966, 248,
            	1990, 256,
            	2118, 264,
            	1990, 272,
            	2118, 280,
            	2118, 288,
            	2126, 296,
            1, 8, 1, /* 1966: pointer.func */
            	1971, 0,
            0, 0, 0, /* 1971: func */
            1, 8, 1, /* 1974: pointer.func */
            	1979, 0,
            0, 0, 0, /* 1979: func */
            1, 8, 1, /* 1982: pointer.func */
            	1987, 0,
            0, 0, 0, /* 1987: func */
            1, 8, 1, /* 1990: pointer.func */
            	1995, 0,
            0, 0, 0, /* 1995: func */
            1, 8, 1, /* 1998: pointer.func */
            	2003, 0,
            0, 0, 0, /* 2003: func */
            1, 8, 1, /* 2006: pointer.func */
            	2011, 0,
            0, 0, 0, /* 2011: func */
            1, 8, 1, /* 2014: pointer.func */
            	2019, 0,
            0, 0, 0, /* 2019: func */
            1, 8, 1, /* 2022: pointer.func */
            	2027, 0,
            0, 0, 0, /* 2027: func */
            1, 8, 1, /* 2030: pointer.func */
            	2035, 0,
            0, 0, 0, /* 2035: func */
            1, 8, 1, /* 2038: pointer.func */
            	2043, 0,
            0, 0, 0, /* 2043: func */
            1, 8, 1, /* 2046: pointer.func */
            	2051, 0,
            0, 0, 0, /* 2051: func */
            1, 8, 1, /* 2054: pointer.func */
            	2059, 0,
            0, 0, 0, /* 2059: func */
            1, 8, 1, /* 2062: pointer.func */
            	2067, 0,
            0, 0, 0, /* 2067: func */
            1, 8, 1, /* 2070: pointer.func */
            	2075, 0,
            0, 0, 0, /* 2075: func */
            1, 8, 1, /* 2078: pointer.func */
            	2083, 0,
            0, 0, 0, /* 2083: func */
            1, 8, 1, /* 2086: pointer.func */
            	2091, 0,
            0, 0, 0, /* 2091: func */
            1, 8, 1, /* 2094: pointer.func */
            	2099, 0,
            0, 0, 0, /* 2099: func */
            1, 8, 1, /* 2102: pointer.func */
            	2107, 0,
            0, 0, 0, /* 2107: func */
            1, 8, 1, /* 2110: pointer.func */
            	2115, 0,
            0, 0, 0, /* 2115: func */
            1, 8, 1, /* 2118: pointer.func */
            	2123, 0,
            0, 0, 0, /* 2123: func */
            1, 8, 1, /* 2126: pointer.func */
            	2131, 0,
            0, 0, 0, /* 2131: func */
            1, 8, 1, /* 2134: pointer.struct.ec_point_st */
            	2139, 0,
            0, 88, 4, /* 2139: struct.ec_point_st */
            	1884, 0,
            	1750, 8,
            	1750, 32,
            	1750, 56,
            1, 8, 1, /* 2150: pointer.struct.ec_extra_data_st */
            	2155, 0,
            0, 40, 5, /* 2155: struct.ec_extra_data_st */
            	2150, 0,
            	13, 8,
            	2168, 16,
            	2176, 24,
            	2176, 32,
            1, 8, 1, /* 2168: pointer.func */
            	2173, 0,
            0, 0, 0, /* 2173: func */
            1, 8, 1, /* 2176: pointer.func */
            	2181, 0,
            0, 0, 0, /* 2181: func */
            1, 8, 1, /* 2184: pointer.func */
            	2189, 0,
            0, 0, 0, /* 2189: func */
            1, 8, 1, /* 2192: pointer.struct.ssl_cipher_st */
            	2197, 0,
            0, 88, 1, /* 2197: struct.ssl_cipher_st */
            	13, 8,
            1, 8, 1, /* 2202: pointer.func */
            	2207, 0,
            0, 0, 0, /* 2207: func */
            1, 8, 1, /* 2210: pointer.func */
            	2215, 0,
            0, 0, 0, /* 2215: func */
            1, 8, 1, /* 2218: pointer.func */
            	2223, 0,
            0, 0, 0, /* 2223: func */
            1, 8, 1, /* 2226: pointer.func */
            	2231, 0,
            0, 0, 0, /* 2231: func */
            1, 8, 1, /* 2234: pointer.func */
            	2239, 0,
            0, 0, 0, /* 2239: func */
            1, 8, 1, /* 2242: pointer.struct.cert_st.745 */
            	2247, 0,
            0, 296, 8, /* 2247: struct.cert_st.745 */
            	688, 0,
            	1703, 48,
            	2266, 56,
            	1804, 64,
            	2274, 72,
            	1836, 80,
            	2282, 88,
            	1684, 96,
            1, 8, 1, /* 2266: pointer.func */
            	2271, 0,
            0, 0, 0, /* 2271: func */
            1, 8, 1, /* 2274: pointer.func */
            	2279, 0,
            0, 0, 0, /* 2279: func */
            1, 8, 1, /* 2282: pointer.func */
            	2287, 0,
            0, 0, 0, /* 2287: func */
            1, 8, 1, /* 2290: pointer.func */
            	2295, 0,
            0, 0, 0, /* 2295: func */
            1, 8, 1, /* 2298: pointer.func */
            	72, 0,
            1, 8, 1, /* 2303: pointer.func */
            	2308, 0,
            0, 0, 0, /* 2308: func */
            1, 8, 1, /* 2311: pointer.struct.ssl3_buf_freelist_st */
            	2316, 0,
            0, 24, 1, /* 2316: struct.ssl3_buf_freelist_st */
            	2321, 16,
            1, 8, 1, /* 2321: pointer.struct.ssl3_buf_freelist_entry_st */
            	2326, 0,
            0, 8, 1, /* 2326: struct.ssl3_buf_freelist_entry_st */
            	2321, 0,
            0, 128, 14, /* 2331: struct.srp_ctx_st.751 */
            	13, 0,
            	2298, 8,
            	59, 16,
            	40, 24,
            	13, 32,
            	1745, 40,
            	1745, 48,
            	1745, 56,
            	1745, 64,
            	1745, 72,
            	1745, 80,
            	1745, 88,
            	1745, 96,
            	13, 104,
            1, 8, 1, /* 2362: pointer.func */
            	37, 0,
            0, 12, 0, /* 2367: array[12].char */
            0, 12, 0, /* 2370: struct.ap_unix_identity_t */
            0, 16, 0, /* 2373: struct.rlimit */
            1, 8, 1, /* 2376: pointer.struct.ssl_ctx_st.752 */
            	151, 0,
            0, 56, 2, /* 2381: struct.comp_ctx_st */
            	2388, 0,
            	622, 40,
            1, 8, 1, /* 2388: pointer.struct.comp_method_st */
            	2393, 0,
            0, 64, 7, /* 2393: struct.comp_method_st */
            	13, 8,
            	2410, 16,
            	2418, 24,
            	2426, 32,
            	2426, 40,
            	422, 48,
            	422, 56,
            1, 8, 1, /* 2410: pointer.func */
            	2415, 0,
            0, 0, 0, /* 2415: func */
            1, 8, 1, /* 2418: pointer.func */
            	2423, 0,
            0, 0, 0, /* 2423: func */
            1, 8, 1, /* 2426: pointer.func */
            	2431, 0,
            0, 0, 0, /* 2431: func */
            0, 168, 4, /* 2434: struct.evp_cipher_ctx_st */
            	2445, 0,
            	1041, 8,
            	13, 96,
            	13, 120,
            1, 8, 1, /* 2445: pointer.struct.evp_cipher_st */
            	2450, 0,
            0, 88, 7, /* 2450: struct.evp_cipher_st */
            	2467, 24,
            	2475, 32,
            	2483, 40,
            	2491, 56,
            	2491, 64,
            	2499, 72,
            	13, 80,
            1, 8, 1, /* 2467: pointer.func */
            	2472, 0,
            0, 0, 0, /* 2472: func */
            1, 8, 1, /* 2475: pointer.func */
            	2480, 0,
            0, 0, 0, /* 2480: func */
            1, 8, 1, /* 2483: pointer.func */
            	2488, 0,
            0, 0, 0, /* 2488: func */
            1, 8, 1, /* 2491: pointer.func */
            	2496, 0,
            0, 0, 0, /* 2496: func */
            1, 8, 1, /* 2499: pointer.func */
            	2504, 0,
            0, 0, 0, /* 2504: func */
            1, 8, 1, /* 2507: pointer.struct.evp_cipher_ctx_st */
            	2434, 0,
            0, 40, 4, /* 2512: struct.dtls1_retransmit_state */
            	2507, 0,
            	2523, 8,
            	2711, 16,
            	632, 24,
            1, 8, 1, /* 2523: pointer.struct.env_md_ctx_st */
            	2528, 0,
            0, 48, 5, /* 2528: struct.env_md_ctx_st */
            	1604, 0,
            	1041, 8,
            	13, 24,
            	2541, 32,
            	1636, 40,
            1, 8, 1, /* 2541: pointer.struct.evp_pkey_ctx_st */
            	2546, 0,
            0, 80, 8, /* 2546: struct.evp_pkey_ctx_st */
            	2565, 0,
            	1041, 8,
            	865, 16,
            	865, 24,
            	13, 40,
            	13, 48,
            	460, 56,
            	1755, 64,
            1, 8, 1, /* 2565: pointer.struct.evp_pkey_method_st */
            	2570, 0,
            0, 208, 25, /* 2570: struct.evp_pkey_method_st */
            	460, 8,
            	2623, 16,
            	2631, 24,
            	460, 32,
            	2639, 40,
            	460, 48,
            	2639, 56,
            	460, 64,
            	2647, 72,
            	460, 80,
            	2655, 88,
            	460, 96,
            	2647, 104,
            	2663, 112,
            	2671, 120,
            	2663, 128,
            	2679, 136,
            	460, 144,
            	2647, 152,
            	460, 160,
            	2647, 168,
            	460, 176,
            	2687, 184,
            	2695, 192,
            	2703, 200,
            1, 8, 1, /* 2623: pointer.func */
            	2628, 0,
            0, 0, 0, /* 2628: func */
            1, 8, 1, /* 2631: pointer.func */
            	2636, 0,
            0, 0, 0, /* 2636: func */
            1, 8, 1, /* 2639: pointer.func */
            	2644, 0,
            0, 0, 0, /* 2644: func */
            1, 8, 1, /* 2647: pointer.func */
            	2652, 0,
            0, 0, 0, /* 2652: func */
            1, 8, 1, /* 2655: pointer.func */
            	2660, 0,
            0, 0, 0, /* 2660: func */
            1, 8, 1, /* 2663: pointer.func */
            	2668, 0,
            0, 0, 0, /* 2668: func */
            1, 8, 1, /* 2671: pointer.func */
            	2676, 0,
            0, 0, 0, /* 2676: func */
            1, 8, 1, /* 2679: pointer.func */
            	2684, 0,
            0, 0, 0, /* 2684: func */
            1, 8, 1, /* 2687: pointer.func */
            	2692, 0,
            0, 0, 0, /* 2692: func */
            1, 8, 1, /* 2695: pointer.func */
            	2700, 0,
            0, 0, 0, /* 2700: func */
            1, 8, 1, /* 2703: pointer.func */
            	2708, 0,
            0, 0, 0, /* 2708: func */
            1, 8, 1, /* 2711: pointer.struct.comp_ctx_st */
            	2381, 0,
            0, 88, 1, /* 2716: struct.hm_header_st */
            	2512, 48,
            0, 24, 2, /* 2721: struct._pitem */
            	13, 8,
            	2728, 16,
            1, 8, 1, /* 2728: pointer.struct._pitem */
            	2721, 0,
            0, 16, 1, /* 2733: struct._pqueue */
            	2728, 0,
            1, 8, 1, /* 2738: pointer.struct._pqueue */
            	2733, 0,
            0, 16, 1, /* 2743: struct.record_pqueue_st */
            	2738, 8,
            0, 16, 0, /* 2748: union.anon.142 */
            1, 8, 1, /* 2751: pointer.struct.dtls1_state_st */
            	2756, 0,
            0, 888, 7, /* 2756: struct.dtls1_state_st */
            	2743, 576,
            	2743, 592,
            	2738, 608,
            	2738, 616,
            	2743, 624,
            	2716, 648,
            	2716, 736,
            0, 24, 2, /* 2773: struct.ssl_comp_st */
            	13, 8,
            	2388, 16,
            0, 9, 0, /* 2780: array[9].char */
            0, 24, 0, /* 2783: array[6].int */
            0, 128, 0, /* 2786: array[128].char */
            0, 20, 0, /* 2789: array[5].int */
            0, 528, 8, /* 2792: struct.anon.0 */
            	2192, 408,
            	1804, 416,
            	1836, 424,
            	524, 464,
            	13, 480,
            	2445, 488,
            	1604, 496,
            	2811, 512,
            1, 8, 1, /* 2811: pointer.struct.ssl_comp_st */
            	2773, 0,
            1, 8, 1, /* 2816: pointer.pointer.struct.env_md_ctx_st */
            	2523, 0,
            0, 8, 0, /* 2821: array[2].int */
            0, 24, 1, /* 2824: struct.ssl3_buffer_st */
            	13, 0,
            0, 64, 0, /* 2829: array[64].char */
            0, 1200, 10, /* 2832: struct.ssl3_state_st */
            	2824, 240,
            	2824, 264,
            	2855, 288,
            	2855, 344,
            	13, 432,
            	2864, 440,
            	2816, 448,
            	13, 496,
            	13, 512,
            	2792, 528,
            0, 56, 3, /* 2855: struct.ssl3_record_st */
            	13, 16,
            	13, 24,
            	13, 32,
            1, 8, 1, /* 2864: pointer.struct.bio_st */
            	2869, 0,
            0, 112, 7, /* 2869: struct.bio_st */
            	2886, 0,
            	2952, 8,
            	13, 16,
            	13, 48,
            	2864, 56,
            	2864, 64,
            	622, 96,
            1, 8, 1, /* 2886: pointer.struct.bio_method_st */
            	2891, 0,
            0, 80, 9, /* 2891: struct.bio_method_st */
            	13, 8,
            	2912, 16,
            	2912, 24,
            	2920, 32,
            	2912, 40,
            	2928, 48,
            	2936, 56,
            	2936, 64,
            	2944, 72,
            1, 8, 1, /* 2912: pointer.func */
            	2917, 0,
            0, 0, 0, /* 2917: func */
            1, 8, 1, /* 2920: pointer.func */
            	2925, 0,
            0, 0, 0, /* 2925: func */
            1, 8, 1, /* 2928: pointer.func */
            	2933, 0,
            0, 0, 0, /* 2933: func */
            1, 8, 1, /* 2936: pointer.func */
            	2941, 0,
            0, 0, 0, /* 2941: func */
            1, 8, 1, /* 2944: pointer.func */
            	2949, 0,
            0, 0, 0, /* 2949: func */
            1, 8, 1, /* 2952: pointer.func */
            	2957, 0,
            0, 0, 0, /* 2957: func */
            1, 8, 1, /* 2960: pointer.struct.ssl3_state_st */
            	2832, 0,
            0, 344, 9, /* 2965: struct.ssl2_state_st */
            	13, 24,
            	13, 56,
            	13, 64,
            	13, 72,
            	13, 104,
            	13, 112,
            	13, 120,
            	13, 128,
            	13, 136,
            1, 8, 1, /* 2986: pointer.struct.ssl2_state_st */
            	2965, 0,
            0, 4, 0, /* 2991: array[4].char */
            0, 32, 0, /* 2994: array[32].char */
            0, 2, 0, /* 2997: array[2].char */
            0, 48, 0, /* 3000: array[48].char */
            0, 8, 0, /* 3003: array[8].char */
            0, 16, 0, /* 3006: array[16].char */
            0, 808, 51, /* 3009: struct.ssl_st.776 */
            	254, 8,
            	2864, 16,
            	2864, 24,
            	2864, 32,
            	318, 48,
            	829, 80,
            	13, 88,
            	13, 104,
            	2986, 120,
            	2960, 128,
            	2751, 136,
            	2290, 152,
            	13, 160,
            	592, 176,
            	524, 184,
            	524, 192,
            	2507, 208,
            	2523, 216,
            	2711, 224,
            	2507, 232,
            	2523, 240,
            	2711, 248,
            	2242, 256,
            	632, 304,
            	2226, 312,
            	609, 328,
            	2234, 336,
            	2303, 352,
            	468, 360,
            	2376, 368,
            	622, 392,
            	524, 408,
            	21, 464,
            	13, 472,
            	13, 480,
            	524, 504,
            	524, 512,
            	13, 520,
            	13, 544,
            	13, 560,
            	13, 568,
            	3114, 584,
            	476, 592,
            	13, 600,
            	3, 608,
            	13, 616,
            	2376, 624,
            	13, 632,
            	524, 648,
            	3119, 656,
            	2331, 680,
            1, 8, 1, /* 3114: pointer.struct.tls_session_ticket_ext_st */
            	8, 0,
            1, 8, 1, /* 3119: pointer.struct.iovec */
            	1799, 0,
            0, 72, 0, /* 3124: struct.anon.25 */
            1, 8, 1, /* 3127: pointer.struct.ssl_st.776 */
            	3009, 0,
            0, 8, 0, /* 3132: long */
            0, 2, 0, /* 3135: short */
            0, 256, 0, /* 3138: array[256].char */
            0, 20, 0, /* 3141: array[20].char */
        },
        .arg_entity_index = { 3127, },
        .ret_entity_index = 2192,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    const SSL * new_arg_a = *((const SSL * *)new_args->args[0]);

    const SSL_CIPHER * *new_ret_ptr = (const SSL_CIPHER * *)new_args->ret;

    const SSL_CIPHER * (*orig_SSL_get_current_cipher)(const SSL *);
    orig_SSL_get_current_cipher = dlsym(RTLD_NEXT, "SSL_get_current_cipher");
    *new_ret_ptr = (*orig_SSL_get_current_cipher)(new_arg_a);

    syscall(889);

    return ret;
}

