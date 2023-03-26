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

int X509_verify_cert(X509_STORE_CTX * arg_a) 
{
    int ret;

    struct lib_enter_args args = {
        .entity_metadata = {
            0, 0, 0, /* 0: func */
            0, 8, 1, /* 3: union.anon.1.3070 */
            	8, 0,
            1, 8, 1, /* 8: pointer.struct.stack_st_OPENSSL_STRING */
            	13, 0,
            0, 32, 1, /* 13: struct.stack_st_OPENSSL_STRING */
            	18, 0,
            0, 32, 5, /* 18: struct.stack_st */
            	31, 0,
            	34, 8,
            	31, 16,
            	31, 20,
            	47, 24,
            0, 4, 0, /* 31: int */
            1, 8, 1, /* 34: pointer.pointer.char */
            	39, 0,
            1, 8, 1, /* 39: pointer.char */
            	44, 0,
            0, 1, 0, /* 44: char */
            1, 8, 1, /* 47: pointer.func */
            	52, 0,
            0, 0, 0, /* 52: func */
            0, 24, 3, /* 55: struct.DIST_POINT_NAME_st */
            	31, 0,
            	3, 8,
            	64, 16,
            1, 8, 1, /* 64: pointer.struct.X509_name_st */
            	69, 0,
            0, 40, 5, /* 69: struct.X509_name_st */
            	8, 0,
            	31, 8,
            	82, 16,
            	39, 24,
            	31, 32,
            1, 8, 1, /* 82: pointer.struct.buf_mem_st */
            	87, 0,
            0, 24, 3, /* 87: struct.buf_mem_st */
            	96, 0,
            	39, 8,
            	96, 16,
            0, 8, 0, /* 96: long */
            1, 8, 1, /* 99: pointer.struct.DIST_POINT_NAME_st */
            	55, 0,
            0, 32, 6, /* 104: struct.ISSUING_DIST_POINT_st */
            	99, 0,
            	31, 8,
            	31, 12,
            	119, 16,
            	31, 24,
            	31, 28,
            1, 8, 1, /* 119: pointer.struct.asn1_string_st */
            	124, 0,
            0, 24, 4, /* 124: struct.asn1_string_st */
            	31, 0,
            	31, 4,
            	39, 8,
            	96, 16,
            0, 80, 8, /* 135: struct.X509_crl_info_st */
            	119, 0,
            	154, 8,
            	64, 16,
            	119, 24,
            	119, 32,
            	8, 40,
            	8, 48,
            	203, 56,
            1, 8, 1, /* 154: pointer.struct.X509_algor_st */
            	159, 0,
            0, 16, 2, /* 159: struct.X509_algor_st */
            	166, 0,
            	186, 8,
            1, 8, 1, /* 166: pointer.struct.asn1_object_st */
            	171, 0,
            0, 40, 6, /* 171: struct.asn1_object_st */
            	39, 0,
            	39, 8,
            	31, 16,
            	31, 20,
            	39, 24,
            	31, 32,
            1, 8, 1, /* 186: pointer.struct.asn1_type_st */
            	191, 0,
            0, 16, 2, /* 191: struct.asn1_type_st */
            	31, 0,
            	198, 8,
            0, 8, 1, /* 198: struct.fnames */
            	39, 0,
            0, 24, 3, /* 203: struct.ASN1_ENCODING_st */
            	39, 0,
            	96, 8,
            	31, 16,
            1, 8, 1, /* 212: pointer.struct.X509_crl_info_st */
            	135, 0,
            0, 24, 3, /* 217: struct.X509_POLICY_NODE_st */
            	226, 0,
            	242, 8,
            	31, 16,
            1, 8, 1, /* 226: pointer.struct.X509_POLICY_DATA_st */
            	231, 0,
            0, 32, 4, /* 231: struct.X509_POLICY_DATA_st */
            	31, 0,
            	166, 8,
            	8, 16,
            	8, 24,
            1, 8, 1, /* 242: pointer.struct.X509_POLICY_NODE_st */
            	217, 0,
            1, 8, 1, /* 247: pointer.func */
            	252, 0,
            0, 0, 0, /* 252: func */
            0, 0, 0, /* 255: func */
            1, 8, 1, /* 258: pointer.func */
            	255, 0,
            1, 8, 1, /* 263: pointer.func */
            	268, 0,
            0, 0, 0, /* 268: func */
            0, 0, 0, /* 271: func */
            0, 0, 0, /* 274: func */
            0, 0, 0, /* 277: func */
            1, 8, 1, /* 280: pointer.func */
            	285, 0,
            0, 0, 0, /* 285: func */
            1, 8, 1, /* 288: pointer.func */
            	293, 0,
            0, 0, 0, /* 293: func */
            0, 0, 0, /* 296: func */
            1, 8, 1, /* 299: pointer.func */
            	304, 0,
            0, 0, 0, /* 304: func */
            0, 0, 0, /* 307: func */
            0, 208, 27, /* 310: struct.evp_pkey_asn1_method_st */
            	31, 0,
            	31, 4,
            	96, 8,
            	39, 16,
            	39, 24,
            	367, 32,
            	375, 40,
            	299, 48,
            	380, 56,
            	288, 64,
            	280, 72,
            	380, 80,
            	385, 88,
            	385, 96,
            	390, 104,
            	395, 112,
            	385, 120,
            	299, 128,
            	299, 136,
            	380, 144,
            	400, 152,
            	263, 160,
            	258, 168,
            	390, 176,
            	395, 184,
            	247, 192,
            	408, 200,
            1, 8, 1, /* 367: pointer.struct.unnamed */
            	372, 0,
            0, 0, 0, /* 372: struct.unnamed */
            1, 8, 1, /* 375: pointer.func */
            	307, 0,
            1, 8, 1, /* 380: pointer.func */
            	296, 0,
            1, 8, 1, /* 385: pointer.func */
            	277, 0,
            1, 8, 1, /* 390: pointer.func */
            	274, 0,
            1, 8, 1, /* 395: pointer.func */
            	271, 0,
            1, 8, 1, /* 400: pointer.func */
            	405, 0,
            0, 0, 0, /* 405: func */
            1, 8, 1, /* 408: pointer.func */
            	413, 0,
            0, 0, 0, /* 413: func */
            1, 8, 1, /* 416: pointer.struct.evp_pkey_asn1_method_st */
            	310, 0,
            0, 56, 8, /* 421: struct.evp_pkey_st */
            	31, 0,
            	31, 4,
            	31, 8,
            	416, 16,
            	440, 24,
            	198, 32,
            	31, 40,
            	8, 48,
            1, 8, 1, /* 440: pointer.struct.engine_st */
            	445, 0,
            0, 216, 27, /* 445: struct.engine_st */
            	39, 0,
            	39, 8,
            	502, 16,
            	594, 24,
            	682, 32,
            	740, 40,
            	764, 48,
            	808, 56,
            	868, 64,
            	876, 72,
            	884, 80,
            	892, 88,
            	900, 96,
            	908, 104,
            	908, 112,
            	908, 120,
            	916, 128,
            	924, 136,
            	924, 144,
            	932, 152,
            	940, 160,
            	31, 168,
            	31, 172,
            	31, 176,
            	956, 184,
            	440, 200,
            	440, 208,
            1, 8, 1, /* 502: pointer.struct.rsa_meth_st */
            	507, 0,
            0, 112, 14, /* 507: struct.rsa_meth_st */
            	39, 0,
            	538, 8,
            	538, 16,
            	538, 24,
            	538, 32,
            	546, 40,
            	554, 48,
            	562, 56,
            	562, 64,
            	31, 72,
            	39, 80,
            	570, 88,
            	578, 96,
            	586, 104,
            1, 8, 1, /* 538: pointer.func */
            	543, 0,
            0, 0, 0, /* 543: func */
            1, 8, 1, /* 546: pointer.func */
            	551, 0,
            0, 0, 0, /* 551: func */
            1, 8, 1, /* 554: pointer.func */
            	559, 0,
            0, 0, 0, /* 559: func */
            1, 8, 1, /* 562: pointer.func */
            	567, 0,
            0, 0, 0, /* 567: func */
            1, 8, 1, /* 570: pointer.func */
            	575, 0,
            0, 0, 0, /* 575: func */
            1, 8, 1, /* 578: pointer.func */
            	583, 0,
            0, 0, 0, /* 583: func */
            1, 8, 1, /* 586: pointer.func */
            	591, 0,
            0, 0, 0, /* 591: func */
            1, 8, 1, /* 594: pointer.struct.dsa_method.1040 */
            	599, 0,
            0, 96, 12, /* 599: struct.dsa_method.1040 */
            	39, 0,
            	626, 8,
            	634, 16,
            	642, 24,
            	650, 32,
            	658, 40,
            	666, 48,
            	666, 56,
            	31, 64,
            	39, 72,
            	674, 80,
            	666, 88,
            1, 8, 1, /* 626: pointer.func */
            	631, 0,
            0, 0, 0, /* 631: func */
            1, 8, 1, /* 634: pointer.func */
            	639, 0,
            0, 0, 0, /* 639: func */
            1, 8, 1, /* 642: pointer.func */
            	647, 0,
            0, 0, 0, /* 647: func */
            1, 8, 1, /* 650: pointer.func */
            	655, 0,
            0, 0, 0, /* 655: func */
            1, 8, 1, /* 658: pointer.func */
            	663, 0,
            0, 0, 0, /* 663: func */
            1, 8, 1, /* 666: pointer.func */
            	671, 0,
            0, 0, 0, /* 671: func */
            1, 8, 1, /* 674: pointer.func */
            	679, 0,
            0, 0, 0, /* 679: func */
            1, 8, 1, /* 682: pointer.struct.dh_method */
            	687, 0,
            0, 72, 9, /* 687: struct.dh_method */
            	39, 0,
            	708, 8,
            	716, 16,
            	724, 24,
            	708, 32,
            	708, 40,
            	31, 48,
            	39, 56,
            	732, 64,
            1, 8, 1, /* 708: pointer.func */
            	713, 0,
            0, 0, 0, /* 713: func */
            1, 8, 1, /* 716: pointer.func */
            	721, 0,
            0, 0, 0, /* 721: func */
            1, 8, 1, /* 724: pointer.func */
            	729, 0,
            0, 0, 0, /* 729: func */
            1, 8, 1, /* 732: pointer.func */
            	737, 0,
            0, 0, 0, /* 737: func */
            1, 8, 1, /* 740: pointer.struct.ecdh_method */
            	745, 0,
            0, 32, 4, /* 745: struct.ecdh_method */
            	39, 0,
            	756, 8,
            	31, 16,
            	39, 24,
            1, 8, 1, /* 756: pointer.func */
            	761, 0,
            0, 0, 0, /* 761: func */
            1, 8, 1, /* 764: pointer.struct.ecdsa_method */
            	769, 0,
            0, 48, 6, /* 769: struct.ecdsa_method */
            	39, 0,
            	784, 8,
            	792, 16,
            	800, 24,
            	31, 32,
            	39, 40,
            1, 8, 1, /* 784: pointer.func */
            	789, 0,
            0, 0, 0, /* 789: func */
            1, 8, 1, /* 792: pointer.func */
            	797, 0,
            0, 0, 0, /* 797: func */
            1, 8, 1, /* 800: pointer.func */
            	805, 0,
            0, 0, 0, /* 805: func */
            1, 8, 1, /* 808: pointer.struct.rand_meth_st */
            	813, 0,
            0, 48, 6, /* 813: struct.rand_meth_st */
            	828, 0,
            	836, 8,
            	844, 16,
            	852, 24,
            	836, 32,
            	860, 40,
            1, 8, 1, /* 828: pointer.func */
            	833, 0,
            0, 0, 0, /* 833: func */
            1, 8, 1, /* 836: pointer.func */
            	841, 0,
            0, 0, 0, /* 841: func */
            1, 8, 1, /* 844: pointer.func */
            	849, 0,
            0, 0, 0, /* 849: func */
            1, 8, 1, /* 852: pointer.func */
            	857, 0,
            0, 0, 0, /* 857: func */
            1, 8, 1, /* 860: pointer.func */
            	865, 0,
            0, 0, 0, /* 865: func */
            1, 8, 1, /* 868: pointer.struct.store_method_st */
            	873, 0,
            0, 0, 0, /* 873: struct.store_method_st */
            1, 8, 1, /* 876: pointer.func */
            	881, 0,
            0, 0, 0, /* 881: func */
            1, 8, 1, /* 884: pointer.func */
            	889, 0,
            0, 0, 0, /* 889: func */
            1, 8, 1, /* 892: pointer.func */
            	897, 0,
            0, 0, 0, /* 897: func */
            1, 8, 1, /* 900: pointer.func */
            	905, 0,
            0, 0, 0, /* 905: func */
            1, 8, 1, /* 908: pointer.func */
            	913, 0,
            0, 0, 0, /* 913: func */
            1, 8, 1, /* 916: pointer.func */
            	921, 0,
            0, 0, 0, /* 921: func */
            1, 8, 1, /* 924: pointer.func */
            	929, 0,
            0, 0, 0, /* 929: func */
            1, 8, 1, /* 932: pointer.func */
            	937, 0,
            0, 0, 0, /* 937: func */
            1, 8, 1, /* 940: pointer.struct.ENGINE_CMD_DEFN_st */
            	945, 0,
            0, 32, 4, /* 945: struct.ENGINE_CMD_DEFN_st */
            	31, 0,
            	39, 8,
            	39, 16,
            	31, 24,
            0, 16, 2, /* 956: struct.crypto_ex_data_st */
            	8, 0,
            	31, 8,
            0, 104, 11, /* 963: struct.x509_cinf_st */
            	119, 0,
            	119, 8,
            	154, 16,
            	64, 24,
            	988, 32,
            	64, 40,
            	1000, 48,
            	119, 56,
            	119, 64,
            	8, 72,
            	203, 80,
            1, 8, 1, /* 988: pointer.struct.X509_val_st */
            	993, 0,
            0, 16, 2, /* 993: struct.X509_val_st */
            	119, 0,
            	119, 8,
            1, 8, 1, /* 1000: pointer.struct.X509_pubkey_st */
            	1005, 0,
            0, 24, 3, /* 1005: struct.X509_pubkey_st */
            	154, 0,
            	119, 8,
            	1014, 16,
            1, 8, 1, /* 1014: pointer.struct.evp_pkey_st */
            	421, 0,
            1, 8, 1, /* 1019: pointer.struct.x509_cinf_st */
            	963, 0,
            0, 184, 21, /* 1024: struct.x509_st */
            	1019, 0,
            	154, 8,
            	119, 16,
            	31, 24,
            	31, 28,
            	39, 32,
            	956, 40,
            	96, 56,
            	96, 64,
            	96, 72,
            	96, 80,
            	96, 88,
            	96, 96,
            	119, 104,
            	1069, 112,
            	1083, 120,
            	8, 128,
            	8, 136,
            	1101, 144,
            	1113, 152,
            	1156, 176,
            1, 8, 1, /* 1069: pointer.struct.AUTHORITY_KEYID_st */
            	1074, 0,
            0, 24, 3, /* 1074: struct.AUTHORITY_KEYID_st */
            	119, 0,
            	8, 8,
            	119, 16,
            1, 8, 1, /* 1083: pointer.struct.X509_POLICY_CACHE_st */
            	1088, 0,
            0, 40, 5, /* 1088: struct.X509_POLICY_CACHE_st */
            	226, 0,
            	8, 8,
            	96, 16,
            	96, 24,
            	96, 32,
            1, 8, 1, /* 1101: pointer.struct.NAME_CONSTRAINTS_st */
            	1106, 0,
            0, 16, 2, /* 1106: struct.NAME_CONSTRAINTS_st */
            	8, 0,
            	8, 8,
            0, 20, 20, /* 1113: array[20].char */
            	44, 0,
            	44, 1,
            	44, 2,
            	44, 3,
            	44, 4,
            	44, 5,
            	44, 6,
            	44, 7,
            	44, 8,
            	44, 9,
            	44, 10,
            	44, 11,
            	44, 12,
            	44, 13,
            	44, 14,
            	44, 15,
            	44, 16,
            	44, 17,
            	44, 18,
            	44, 19,
            1, 8, 1, /* 1156: pointer.struct.x509_cert_aux_st */
            	1161, 0,
            0, 40, 5, /* 1161: struct.x509_cert_aux_st */
            	8, 0,
            	8, 8,
            	119, 16,
            	119, 24,
            	8, 32,
            1, 8, 1, /* 1174: pointer.struct.x509_st */
            	1024, 0,
            0, 32, 4, /* 1179: struct.X509_POLICY_LEVEL_st */
            	1174, 0,
            	8, 8,
            	242, 16,
            	31, 24,
            0, 48, 6, /* 1190: struct.X509_POLICY_TREE_st */
            	1205, 0,
            	31, 8,
            	8, 16,
            	8, 24,
            	8, 32,
            	31, 40,
            1, 8, 1, /* 1205: pointer.struct.X509_POLICY_LEVEL_st */
            	1179, 0,
            0, 0, 0, /* 1210: func */
            1, 8, 1, /* 1213: pointer.struct.X509_crl_st */
            	1218, 0,
            0, 120, 15, /* 1218: struct.X509_crl_st */
            	212, 0,
            	154, 8,
            	119, 16,
            	31, 24,
            	31, 28,
            	1069, 32,
            	1251, 40,
            	31, 48,
            	31, 52,
            	119, 56,
            	119, 64,
            	1113, 72,
            	8, 96,
            	1256, 104,
            	39, 112,
            1, 8, 1, /* 1251: pointer.struct.ISSUING_DIST_POINT_st */
            	104, 0,
            1, 8, 1, /* 1256: pointer.struct.x509_crl_method_st */
            	1261, 0,
            0, 40, 5, /* 1261: struct.x509_crl_method_st */
            	31, 0,
            	1274, 8,
            	1274, 16,
            	1279, 24,
            	1284, 32,
            1, 8, 1, /* 1274: pointer.func */
            	0, 0,
            1, 8, 1, /* 1279: pointer.func */
            	1210, 0,
            1, 8, 1, /* 1284: pointer.func */
            	1289, 0,
            0, 0, 0, /* 1289: func */
            1, 8, 1, /* 1292: pointer.struct.x509_store_ctx_st.4286 */
            	1297, 0,
            0, 248, 33, /* 1297: struct.x509_store_ctx_st.4286 */
            	1366, 0,
            	31, 8,
            	1488, 16,
            	8, 24,
            	8, 32,
            	1408, 40,
            	39, 48,
            	367, 56,
            	1432, 64,
            	1440, 72,
            	1448, 80,
            	367, 88,
            	1456, 96,
            	1464, 104,
            	1472, 112,
            	367, 120,
            	1480, 128,
            	1480, 136,
            	367, 144,
            	31, 152,
            	31, 156,
            	8, 160,
            	1764, 168,
            	31, 176,
            	31, 180,
            	31, 184,
            	1488, 192,
            	1488, 200,
            	1213, 208,
            	31, 216,
            	31, 220,
            	1292, 224,
            	956, 232,
            1, 8, 1, /* 1366: pointer.struct.x509_store_st.4284 */
            	1371, 0,
            0, 144, 17, /* 1371: struct.x509_store_st.4284 */
            	31, 0,
            	8, 8,
            	8, 16,
            	1408, 24,
            	367, 32,
            	1432, 40,
            	1440, 48,
            	1448, 56,
            	367, 64,
            	1456, 72,
            	1464, 80,
            	1472, 88,
            	1480, 96,
            	1480, 104,
            	367, 112,
            	956, 120,
            	31, 136,
            1, 8, 1, /* 1408: pointer.struct.X509_VERIFY_PARAM_st */
            	1413, 0,
            0, 56, 8, /* 1413: struct.X509_VERIFY_PARAM_st */
            	39, 0,
            	96, 8,
            	96, 16,
            	96, 24,
            	31, 32,
            	31, 36,
            	31, 40,
            	8, 48,
            1, 8, 1, /* 1432: pointer.func */
            	1437, 0,
            0, 0, 0, /* 1437: func */
            1, 8, 1, /* 1440: pointer.func */
            	1445, 0,
            0, 0, 0, /* 1445: func */
            1, 8, 1, /* 1448: pointer.func */
            	1453, 0,
            0, 0, 0, /* 1453: func */
            1, 8, 1, /* 1456: pointer.func */
            	1461, 0,
            0, 0, 0, /* 1461: func */
            1, 8, 1, /* 1464: pointer.func */
            	1469, 0,
            0, 0, 0, /* 1469: func */
            1, 8, 1, /* 1472: pointer.func */
            	1477, 0,
            0, 0, 0, /* 1477: func */
            1, 8, 1, /* 1480: pointer.func */
            	1485, 0,
            0, 0, 0, /* 1485: func */
            1, 8, 1, /* 1488: pointer.struct.x509_st.3164 */
            	1493, 0,
            0, 184, 21, /* 1493: struct.x509_st.3164 */
            	1538, 0,
            	154, 8,
            	119, 16,
            	31, 24,
            	31, 28,
            	39, 32,
            	956, 40,
            	96, 56,
            	96, 64,
            	96, 72,
            	96, 80,
            	96, 88,
            	96, 96,
            	119, 104,
            	1069, 112,
            	1083, 120,
            	8, 128,
            	8, 136,
            	1101, 144,
            	1113, 152,
            	1156, 176,
            1, 8, 1, /* 1538: pointer.struct.x509_cinf_st.3159 */
            	1543, 0,
            0, 104, 11, /* 1543: struct.x509_cinf_st.3159 */
            	119, 0,
            	119, 8,
            	154, 16,
            	64, 24,
            	988, 32,
            	64, 40,
            	1568, 48,
            	119, 56,
            	119, 64,
            	8, 72,
            	203, 80,
            1, 8, 1, /* 1568: pointer.struct.X509_pubkey_st.2915 */
            	1573, 0,
            0, 24, 3, /* 1573: struct.X509_pubkey_st.2915 */
            	154, 0,
            	119, 8,
            	1582, 16,
            1, 8, 1, /* 1582: pointer.struct.evp_pkey_st.2930 */
            	1587, 0,
            0, 56, 8, /* 1587: struct.evp_pkey_st.2930 */
            	31, 0,
            	31, 4,
            	31, 8,
            	1606, 16,
            	440, 24,
            	198, 32,
            	31, 40,
            	8, 48,
            1, 8, 1, /* 1606: pointer.struct.evp_pkey_asn1_method_st.2928 */
            	1611, 0,
            0, 208, 27, /* 1611: struct.evp_pkey_asn1_method_st.2928 */
            	31, 0,
            	31, 4,
            	96, 8,
            	39, 16,
            	39, 24,
            	1668, 32,
            	1676, 40,
            	1684, 48,
            	1692, 56,
            	1700, 64,
            	1708, 72,
            	1692, 80,
            	1716, 88,
            	1716, 96,
            	1724, 104,
            	1732, 112,
            	1716, 120,
            	1684, 128,
            	1684, 136,
            	1692, 144,
            	400, 152,
            	1740, 160,
            	1748, 168,
            	1724, 176,
            	1732, 184,
            	1756, 192,
            	408, 200,
            1, 8, 1, /* 1668: pointer.func */
            	1673, 0,
            0, 0, 0, /* 1673: func */
            1, 8, 1, /* 1676: pointer.func */
            	1681, 0,
            0, 0, 0, /* 1681: func */
            1, 8, 1, /* 1684: pointer.func */
            	1689, 0,
            0, 0, 0, /* 1689: func */
            1, 8, 1, /* 1692: pointer.func */
            	1697, 0,
            0, 0, 0, /* 1697: func */
            1, 8, 1, /* 1700: pointer.func */
            	1705, 0,
            0, 0, 0, /* 1705: func */
            1, 8, 1, /* 1708: pointer.func */
            	1713, 0,
            0, 0, 0, /* 1713: func */
            1, 8, 1, /* 1716: pointer.func */
            	1721, 0,
            0, 0, 0, /* 1721: func */
            1, 8, 1, /* 1724: pointer.func */
            	1729, 0,
            0, 0, 0, /* 1729: func */
            1, 8, 1, /* 1732: pointer.func */
            	1737, 0,
            0, 0, 0, /* 1737: func */
            1, 8, 1, /* 1740: pointer.func */
            	1745, 0,
            0, 0, 0, /* 1745: func */
            1, 8, 1, /* 1748: pointer.func */
            	1753, 0,
            0, 0, 0, /* 1753: func */
            1, 8, 1, /* 1756: pointer.func */
            	1761, 0,
            0, 0, 0, /* 1761: func */
            1, 8, 1, /* 1764: pointer.struct.X509_POLICY_TREE_st */
            	1190, 0,
        },
        .arg_entity_index = { 1292, },
        .ret_entity_index = 31,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    X509_STORE_CTX * new_arg_a = *((X509_STORE_CTX * *)new_args->args[0]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_X509_verify_cert)(X509_STORE_CTX *);
    orig_X509_verify_cert = dlsym(RTLD_NEXT, "X509_verify_cert");
    *new_ret_ptr = (*orig_X509_verify_cert)(new_arg_a);

    syscall(889);

    return ret;
}

