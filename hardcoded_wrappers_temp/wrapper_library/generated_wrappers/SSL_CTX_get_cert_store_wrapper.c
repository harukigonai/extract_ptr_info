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

X509_STORE * SSL_CTX_get_cert_store(const SSL_CTX * arg_a) 
{
    X509_STORE * ret;

    struct lib_enter_args args = {
        .entity_metadata = {
            0, 0, 0, /* 0: func */
            1, 8, 1, /* 3: pointer.func */
            	0, 0,
            0, 0, 0, /* 8: func */
            1, 8, 1, /* 11: pointer.func */
            	16, 0,
            0, 0, 0, /* 16: func */
            0, 0, 0, /* 19: func */
            1, 8, 1, /* 22: pointer.func */
            	19, 0,
            0, 0, 0, /* 27: func */
            1, 8, 1, /* 30: pointer.func */
            	27, 0,
            0, 0, 0, /* 35: func */
            1, 8, 1, /* 38: pointer.func */
            	35, 0,
            0, 0, 0, /* 43: func */
            1, 8, 1, /* 46: pointer.func */
            	43, 0,
            0, 16, 0, /* 51: array[16].char */
            0, 0, 0, /* 54: func */
            0, 0, 0, /* 57: func */
            1, 8, 1, /* 60: pointer.func */
            	57, 0,
            0, 0, 0, /* 65: func */
            1, 8, 1, /* 68: pointer.func */
            	65, 0,
            1, 8, 1, /* 73: pointer.struct.ssl3_buf_freelist_entry_st */
            	78, 0,
            0, 8, 1, /* 78: struct.ssl3_buf_freelist_entry_st */
            	73, 0,
            0, 0, 0, /* 83: func */
            1, 8, 1, /* 86: pointer.func */
            	83, 0,
            0, 296, 8, /* 91: struct.cert_st.745 */
            	110, 0,
            	1165, 48,
            	1266, 56,
            	1274, 64,
            	86, 72,
            	1306, 80,
            	68, 88,
            	1662, 96,
            1, 8, 1, /* 110: pointer.struct.cert_pkey_st */
            	115, 0,
            0, 24, 3, /* 115: struct.cert_pkey_st */
            	124, 0,
            	325, 8,
            	1085, 16,
            1, 8, 1, /* 124: pointer.struct.x509_st */
            	129, 0,
            0, 184, 12, /* 129: struct.x509_st */
            	156, 0,
            	204, 8,
            	186, 16,
            	196, 32,
            	1005, 40,
            	186, 104,
            	1015, 112,
            	1029, 120,
            	259, 128,
            	259, 136,
            	1055, 144,
            	1067, 176,
            1, 8, 1, /* 156: pointer.struct.x509_cinf_st */
            	161, 0,
            0, 104, 11, /* 161: struct.x509_cinf_st */
            	186, 0,
            	186, 8,
            	204, 16,
            	245, 24,
            	299, 32,
            	245, 40,
            	311, 48,
            	186, 56,
            	186, 64,
            	259, 72,
            	1010, 80,
            1, 8, 1, /* 186: pointer.struct.asn1_string_st */
            	191, 0,
            0, 24, 1, /* 191: struct.asn1_string_st */
            	196, 8,
            1, 8, 1, /* 196: pointer.char */
            	201, 0,
            0, 1, 0, /* 201: char */
            1, 8, 1, /* 204: pointer.struct.X509_algor_st */
            	209, 0,
            0, 16, 2, /* 209: struct.X509_algor_st */
            	216, 0,
            	230, 8,
            1, 8, 1, /* 216: pointer.struct.asn1_object_st */
            	221, 0,
            0, 40, 3, /* 221: struct.asn1_object_st */
            	196, 0,
            	196, 8,
            	196, 24,
            1, 8, 1, /* 230: pointer.struct.asn1_type_st */
            	235, 0,
            0, 16, 1, /* 235: struct.asn1_type_st */
            	240, 8,
            0, 8, 1, /* 240: struct.fnames */
            	196, 0,
            1, 8, 1, /* 245: pointer.struct.X509_name_st */
            	250, 0,
            0, 40, 3, /* 250: struct.X509_name_st */
            	259, 0,
            	289, 16,
            	196, 24,
            1, 8, 1, /* 259: pointer.struct.stack_st_OPENSSL_STRING */
            	264, 0,
            0, 32, 1, /* 264: struct.stack_st_OPENSSL_STRING */
            	269, 0,
            0, 32, 2, /* 269: struct.stack_st */
            	276, 8,
            	281, 24,
            1, 8, 1, /* 276: pointer.pointer.char */
            	196, 0,
            1, 8, 1, /* 281: pointer.func */
            	286, 0,
            0, 0, 0, /* 286: func */
            1, 8, 1, /* 289: pointer.struct.buf_mem_st */
            	294, 0,
            0, 24, 1, /* 294: struct.buf_mem_st */
            	196, 8,
            1, 8, 1, /* 299: pointer.struct.X509_val_st */
            	304, 0,
            0, 16, 2, /* 304: struct.X509_val_st */
            	186, 0,
            	186, 8,
            1, 8, 1, /* 311: pointer.struct.X509_pubkey_st */
            	316, 0,
            0, 24, 3, /* 316: struct.X509_pubkey_st */
            	204, 0,
            	186, 8,
            	325, 16,
            1, 8, 1, /* 325: pointer.struct.evp_pkey_st */
            	330, 0,
            0, 56, 4, /* 330: struct.evp_pkey_st */
            	341, 16,
            	509, 24,
            	240, 32,
            	259, 48,
            1, 8, 1, /* 341: pointer.struct.evp_pkey_asn1_method_st */
            	346, 0,
            0, 208, 24, /* 346: struct.evp_pkey_asn1_method_st */
            	196, 16,
            	196, 24,
            	397, 32,
            	405, 40,
            	413, 48,
            	421, 56,
            	429, 64,
            	437, 72,
            	421, 80,
            	445, 88,
            	445, 96,
            	453, 104,
            	461, 112,
            	445, 120,
            	413, 128,
            	413, 136,
            	421, 144,
            	469, 152,
            	477, 160,
            	485, 168,
            	453, 176,
            	461, 184,
            	493, 192,
            	501, 200,
            1, 8, 1, /* 397: pointer.struct.unnamed */
            	402, 0,
            0, 0, 0, /* 402: struct.unnamed */
            1, 8, 1, /* 405: pointer.func */
            	410, 0,
            0, 0, 0, /* 410: func */
            1, 8, 1, /* 413: pointer.func */
            	418, 0,
            0, 0, 0, /* 418: func */
            1, 8, 1, /* 421: pointer.func */
            	426, 0,
            0, 0, 0, /* 426: func */
            1, 8, 1, /* 429: pointer.func */
            	434, 0,
            0, 0, 0, /* 434: func */
            1, 8, 1, /* 437: pointer.func */
            	442, 0,
            0, 0, 0, /* 442: func */
            1, 8, 1, /* 445: pointer.func */
            	450, 0,
            0, 0, 0, /* 450: func */
            1, 8, 1, /* 453: pointer.func */
            	458, 0,
            0, 0, 0, /* 458: func */
            1, 8, 1, /* 461: pointer.func */
            	466, 0,
            0, 0, 0, /* 466: func */
            1, 8, 1, /* 469: pointer.func */
            	474, 0,
            0, 0, 0, /* 474: func */
            1, 8, 1, /* 477: pointer.func */
            	482, 0,
            0, 0, 0, /* 482: func */
            1, 8, 1, /* 485: pointer.func */
            	490, 0,
            0, 0, 0, /* 490: func */
            1, 8, 1, /* 493: pointer.func */
            	498, 0,
            0, 0, 0, /* 498: func */
            1, 8, 1, /* 501: pointer.func */
            	506, 0,
            0, 0, 0, /* 506: func */
            1, 8, 1, /* 509: pointer.struct.engine_st */
            	514, 0,
            0, 216, 24, /* 514: struct.engine_st */
            	196, 0,
            	196, 8,
            	565, 16,
            	655, 24,
            	741, 32,
            	797, 40,
            	819, 48,
            	861, 56,
            	921, 64,
            	929, 72,
            	937, 80,
            	945, 88,
            	953, 96,
            	961, 104,
            	961, 112,
            	961, 120,
            	969, 128,
            	977, 136,
            	977, 144,
            	985, 152,
            	993, 160,
            	1005, 184,
            	509, 200,
            	509, 208,
            1, 8, 1, /* 565: pointer.struct.rsa_meth_st */
            	570, 0,
            0, 112, 13, /* 570: struct.rsa_meth_st */
            	196, 0,
            	599, 8,
            	599, 16,
            	599, 24,
            	599, 32,
            	607, 40,
            	615, 48,
            	623, 56,
            	623, 64,
            	196, 80,
            	631, 88,
            	639, 96,
            	647, 104,
            1, 8, 1, /* 599: pointer.func */
            	604, 0,
            0, 0, 0, /* 604: func */
            1, 8, 1, /* 607: pointer.func */
            	612, 0,
            0, 0, 0, /* 612: func */
            1, 8, 1, /* 615: pointer.func */
            	620, 0,
            0, 0, 0, /* 620: func */
            1, 8, 1, /* 623: pointer.func */
            	628, 0,
            0, 0, 0, /* 628: func */
            1, 8, 1, /* 631: pointer.func */
            	636, 0,
            0, 0, 0, /* 636: func */
            1, 8, 1, /* 639: pointer.func */
            	644, 0,
            0, 0, 0, /* 644: func */
            1, 8, 1, /* 647: pointer.func */
            	652, 0,
            0, 0, 0, /* 652: func */
            1, 8, 1, /* 655: pointer.struct.dsa_method.1040 */
            	660, 0,
            0, 96, 11, /* 660: struct.dsa_method.1040 */
            	196, 0,
            	685, 8,
            	693, 16,
            	701, 24,
            	709, 32,
            	717, 40,
            	725, 48,
            	725, 56,
            	196, 72,
            	733, 80,
            	725, 88,
            1, 8, 1, /* 685: pointer.func */
            	690, 0,
            0, 0, 0, /* 690: func */
            1, 8, 1, /* 693: pointer.func */
            	698, 0,
            0, 0, 0, /* 698: func */
            1, 8, 1, /* 701: pointer.func */
            	706, 0,
            0, 0, 0, /* 706: func */
            1, 8, 1, /* 709: pointer.func */
            	714, 0,
            0, 0, 0, /* 714: func */
            1, 8, 1, /* 717: pointer.func */
            	722, 0,
            0, 0, 0, /* 722: func */
            1, 8, 1, /* 725: pointer.func */
            	730, 0,
            0, 0, 0, /* 730: func */
            1, 8, 1, /* 733: pointer.func */
            	738, 0,
            0, 0, 0, /* 738: func */
            1, 8, 1, /* 741: pointer.struct.dh_method */
            	746, 0,
            0, 72, 8, /* 746: struct.dh_method */
            	196, 0,
            	765, 8,
            	773, 16,
            	781, 24,
            	765, 32,
            	765, 40,
            	196, 56,
            	789, 64,
            1, 8, 1, /* 765: pointer.func */
            	770, 0,
            0, 0, 0, /* 770: func */
            1, 8, 1, /* 773: pointer.func */
            	778, 0,
            0, 0, 0, /* 778: func */
            1, 8, 1, /* 781: pointer.func */
            	786, 0,
            0, 0, 0, /* 786: func */
            1, 8, 1, /* 789: pointer.func */
            	794, 0,
            0, 0, 0, /* 794: func */
            1, 8, 1, /* 797: pointer.struct.ecdh_method */
            	802, 0,
            0, 32, 3, /* 802: struct.ecdh_method */
            	196, 0,
            	811, 8,
            	196, 24,
            1, 8, 1, /* 811: pointer.func */
            	816, 0,
            0, 0, 0, /* 816: func */
            1, 8, 1, /* 819: pointer.struct.ecdsa_method */
            	824, 0,
            0, 48, 5, /* 824: struct.ecdsa_method */
            	196, 0,
            	837, 8,
            	845, 16,
            	853, 24,
            	196, 40,
            1, 8, 1, /* 837: pointer.func */
            	842, 0,
            0, 0, 0, /* 842: func */
            1, 8, 1, /* 845: pointer.func */
            	850, 0,
            0, 0, 0, /* 850: func */
            1, 8, 1, /* 853: pointer.func */
            	858, 0,
            0, 0, 0, /* 858: func */
            1, 8, 1, /* 861: pointer.struct.rand_meth_st */
            	866, 0,
            0, 48, 6, /* 866: struct.rand_meth_st */
            	881, 0,
            	889, 8,
            	897, 16,
            	905, 24,
            	889, 32,
            	913, 40,
            1, 8, 1, /* 881: pointer.func */
            	886, 0,
            0, 0, 0, /* 886: func */
            1, 8, 1, /* 889: pointer.func */
            	894, 0,
            0, 0, 0, /* 894: func */
            1, 8, 1, /* 897: pointer.func */
            	902, 0,
            0, 0, 0, /* 902: func */
            1, 8, 1, /* 905: pointer.func */
            	910, 0,
            0, 0, 0, /* 910: func */
            1, 8, 1, /* 913: pointer.func */
            	918, 0,
            0, 0, 0, /* 918: func */
            1, 8, 1, /* 921: pointer.struct.store_method_st */
            	926, 0,
            0, 0, 0, /* 926: struct.store_method_st */
            1, 8, 1, /* 929: pointer.func */
            	934, 0,
            0, 0, 0, /* 934: func */
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
            1, 8, 1, /* 993: pointer.struct.ENGINE_CMD_DEFN_st */
            	998, 0,
            0, 32, 2, /* 998: struct.ENGINE_CMD_DEFN_st */
            	196, 8,
            	196, 16,
            0, 16, 1, /* 1005: struct.crypto_ex_data_st */
            	259, 0,
            0, 24, 1, /* 1010: struct.ASN1_ENCODING_st */
            	196, 0,
            1, 8, 1, /* 1015: pointer.struct.AUTHORITY_KEYID_st */
            	1020, 0,
            0, 24, 3, /* 1020: struct.AUTHORITY_KEYID_st */
            	186, 0,
            	259, 8,
            	186, 16,
            1, 8, 1, /* 1029: pointer.struct.X509_POLICY_CACHE_st */
            	1034, 0,
            0, 40, 2, /* 1034: struct.X509_POLICY_CACHE_st */
            	1041, 0,
            	259, 8,
            1, 8, 1, /* 1041: pointer.struct.X509_POLICY_DATA_st */
            	1046, 0,
            0, 32, 3, /* 1046: struct.X509_POLICY_DATA_st */
            	216, 8,
            	259, 16,
            	259, 24,
            1, 8, 1, /* 1055: pointer.struct.NAME_CONSTRAINTS_st */
            	1060, 0,
            0, 16, 2, /* 1060: struct.NAME_CONSTRAINTS_st */
            	259, 0,
            	259, 8,
            1, 8, 1, /* 1067: pointer.struct.x509_cert_aux_st */
            	1072, 0,
            0, 40, 5, /* 1072: struct.x509_cert_aux_st */
            	259, 0,
            	259, 8,
            	186, 16,
            	186, 24,
            	259, 32,
            1, 8, 1, /* 1085: pointer.struct.env_md_st */
            	1090, 0,
            0, 120, 8, /* 1090: struct.env_md_st */
            	1109, 24,
            	1117, 32,
            	1125, 40,
            	1133, 48,
            	1109, 56,
            	1141, 64,
            	1149, 72,
            	1157, 112,
            1, 8, 1, /* 1109: pointer.func */
            	1114, 0,
            0, 0, 0, /* 1114: func */
            1, 8, 1, /* 1117: pointer.func */
            	1122, 0,
            0, 0, 0, /* 1122: func */
            1, 8, 1, /* 1125: pointer.func */
            	1130, 0,
            0, 0, 0, /* 1130: func */
            1, 8, 1, /* 1133: pointer.func */
            	1138, 0,
            0, 0, 0, /* 1138: func */
            1, 8, 1, /* 1141: pointer.func */
            	1146, 0,
            0, 0, 0, /* 1146: func */
            1, 8, 1, /* 1149: pointer.func */
            	1154, 0,
            0, 0, 0, /* 1154: func */
            1, 8, 1, /* 1157: pointer.func */
            	1162, 0,
            0, 0, 0, /* 1162: func */
            1, 8, 1, /* 1165: pointer.struct.rsa_st */
            	1170, 0,
            0, 168, 17, /* 1170: struct.rsa_st */
            	565, 16,
            	509, 24,
            	1207, 32,
            	1207, 40,
            	1207, 48,
            	1207, 56,
            	1207, 64,
            	1207, 72,
            	1207, 80,
            	1207, 88,
            	1005, 96,
            	1225, 120,
            	1225, 128,
            	1225, 136,
            	196, 144,
            	1239, 152,
            	1239, 160,
            1, 8, 1, /* 1207: pointer.struct.bignum_st */
            	1212, 0,
            0, 24, 1, /* 1212: struct.bignum_st */
            	1217, 0,
            1, 8, 1, /* 1217: pointer.int */
            	1222, 0,
            0, 4, 0, /* 1222: int */
            1, 8, 1, /* 1225: pointer.struct.bn_mont_ctx_st */
            	1230, 0,
            0, 96, 3, /* 1230: struct.bn_mont_ctx_st */
            	1212, 8,
            	1212, 32,
            	1212, 56,
            1, 8, 1, /* 1239: pointer.struct.bn_blinding_st */
            	1244, 0,
            0, 88, 7, /* 1244: struct.bn_blinding_st */
            	1207, 0,
            	1207, 8,
            	1207, 16,
            	1207, 24,
            	1261, 40,
            	1225, 72,
            	615, 80,
            0, 16, 1, /* 1261: struct.iovec */
            	196, 0,
            1, 8, 1, /* 1266: pointer.func */
            	1271, 0,
            0, 0, 0, /* 1271: func */
            1, 8, 1, /* 1274: pointer.struct.dh_st */
            	1279, 0,
            0, 144, 12, /* 1279: struct.dh_st */
            	1207, 8,
            	1207, 16,
            	1207, 32,
            	1207, 40,
            	1225, 56,
            	1207, 64,
            	1207, 72,
            	196, 80,
            	1207, 96,
            	1005, 112,
            	741, 128,
            	509, 136,
            1, 8, 1, /* 1306: pointer.struct.ec_key_st.284 */
            	1311, 0,
            0, 56, 4, /* 1311: struct.ec_key_st.284 */
            	1322, 8,
            	1604, 16,
            	1207, 24,
            	1620, 48,
            1, 8, 1, /* 1322: pointer.struct.ec_group_st */
            	1327, 0,
            0, 232, 12, /* 1327: struct.ec_group_st */
            	1354, 0,
            	1604, 8,
            	1212, 16,
            	1212, 40,
            	196, 80,
            	1620, 96,
            	1212, 104,
            	1212, 152,
            	1212, 176,
            	196, 208,
            	196, 216,
            	1654, 224,
            1, 8, 1, /* 1354: pointer.struct.ec_method_st */
            	1359, 0,
            0, 304, 37, /* 1359: struct.ec_method_st */
            	1436, 8,
            	1444, 16,
            	1444, 24,
            	1452, 32,
            	1460, 40,
            	1460, 48,
            	1436, 56,
            	1468, 64,
            	1476, 72,
            	1484, 80,
            	1484, 88,
            	1492, 96,
            	1500, 104,
            	1508, 112,
            	1508, 120,
            	1516, 128,
            	1516, 136,
            	1524, 144,
            	1532, 152,
            	1540, 160,
            	1548, 168,
            	1556, 176,
            	1564, 184,
            	1500, 192,
            	1564, 200,
            	1556, 208,
            	1564, 216,
            	1572, 224,
            	1580, 232,
            	1468, 240,
            	1436, 248,
            	1460, 256,
            	1588, 264,
            	1460, 272,
            	1588, 280,
            	1588, 288,
            	1596, 296,
            1, 8, 1, /* 1436: pointer.func */
            	1441, 0,
            0, 0, 0, /* 1441: func */
            1, 8, 1, /* 1444: pointer.func */
            	1449, 0,
            0, 0, 0, /* 1449: func */
            1, 8, 1, /* 1452: pointer.func */
            	1457, 0,
            0, 0, 0, /* 1457: func */
            1, 8, 1, /* 1460: pointer.func */
            	1465, 0,
            0, 0, 0, /* 1465: func */
            1, 8, 1, /* 1468: pointer.func */
            	1473, 0,
            0, 0, 0, /* 1473: func */
            1, 8, 1, /* 1476: pointer.func */
            	1481, 0,
            0, 0, 0, /* 1481: func */
            1, 8, 1, /* 1484: pointer.func */
            	1489, 0,
            0, 0, 0, /* 1489: func */
            1, 8, 1, /* 1492: pointer.func */
            	1497, 0,
            0, 0, 0, /* 1497: func */
            1, 8, 1, /* 1500: pointer.func */
            	1505, 0,
            0, 0, 0, /* 1505: func */
            1, 8, 1, /* 1508: pointer.func */
            	1513, 0,
            0, 0, 0, /* 1513: func */
            1, 8, 1, /* 1516: pointer.func */
            	1521, 0,
            0, 0, 0, /* 1521: func */
            1, 8, 1, /* 1524: pointer.func */
            	1529, 0,
            0, 0, 0, /* 1529: func */
            1, 8, 1, /* 1532: pointer.func */
            	1537, 0,
            0, 0, 0, /* 1537: func */
            1, 8, 1, /* 1540: pointer.func */
            	1545, 0,
            0, 0, 0, /* 1545: func */
            1, 8, 1, /* 1548: pointer.func */
            	1553, 0,
            0, 0, 0, /* 1553: func */
            1, 8, 1, /* 1556: pointer.func */
            	1561, 0,
            0, 0, 0, /* 1561: func */
            1, 8, 1, /* 1564: pointer.func */
            	1569, 0,
            0, 0, 0, /* 1569: func */
            1, 8, 1, /* 1572: pointer.func */
            	1577, 0,
            0, 0, 0, /* 1577: func */
            1, 8, 1, /* 1580: pointer.func */
            	1585, 0,
            0, 0, 0, /* 1585: func */
            1, 8, 1, /* 1588: pointer.func */
            	1593, 0,
            0, 0, 0, /* 1593: func */
            1, 8, 1, /* 1596: pointer.func */
            	1601, 0,
            0, 0, 0, /* 1601: func */
            1, 8, 1, /* 1604: pointer.struct.ec_point_st */
            	1609, 0,
            0, 88, 4, /* 1609: struct.ec_point_st */
            	1354, 0,
            	1212, 8,
            	1212, 32,
            	1212, 56,
            1, 8, 1, /* 1620: pointer.struct.ec_extra_data_st */
            	1625, 0,
            0, 40, 5, /* 1625: struct.ec_extra_data_st */
            	1620, 0,
            	196, 8,
            	1638, 16,
            	1646, 24,
            	1646, 32,
            1, 8, 1, /* 1638: pointer.func */
            	1643, 0,
            0, 0, 0, /* 1643: func */
            1, 8, 1, /* 1646: pointer.func */
            	1651, 0,
            0, 0, 0, /* 1651: func */
            1, 8, 1, /* 1654: pointer.func */
            	1659, 0,
            0, 0, 0, /* 1659: func */
            0, 192, 8, /* 1662: array[8].struct.cert_pkey_st */
            	115, 0,
            	115, 24,
            	115, 48,
            	115, 72,
            	115, 96,
            	115, 120,
            	115, 144,
            	115, 168,
            1, 8, 1, /* 1681: pointer.struct.cert_st.745 */
            	91, 0,
            0, 0, 0, /* 1686: func */
            1, 8, 1, /* 1689: pointer.func */
            	1686, 0,
            0, 0, 0, /* 1694: func */
            1, 8, 1, /* 1697: pointer.func */
            	1694, 0,
            0, 44, 0, /* 1702: struct.apr_time_exp_t */
            0, 0, 0, /* 1705: func */
            1, 8, 1, /* 1708: pointer.func */
            	1705, 0,
            1, 8, 1, /* 1713: pointer.struct.ssl_cipher_st */
            	1718, 0,
            0, 88, 1, /* 1718: struct.ssl_cipher_st */
            	196, 8,
            0, 24, 0, /* 1723: array[6].int */
            0, 8, 0, /* 1726: array[2].int */
            0, 0, 0, /* 1729: func */
            0, 4, 0, /* 1732: struct.in_addr */
            1, 8, 1, /* 1735: pointer.func */
            	1740, 0,
            0, 0, 0, /* 1740: func */
            1, 8, 1, /* 1743: pointer.func */
            	1748, 0,
            0, 0, 0, /* 1748: func */
            0, 248, 6, /* 1751: struct.sess_cert_st */
            	259, 0,
            	110, 16,
            	1662, 24,
            	1165, 216,
            	1274, 224,
            	1306, 232,
            0, 0, 0, /* 1766: func */
            1, 8, 1, /* 1769: pointer.func */
            	1774, 0,
            0, 0, 0, /* 1774: func */
            0, 352, 14, /* 1777: struct.ssl_session_st */
            	196, 144,
            	196, 152,
            	1808, 168,
            	124, 176,
            	1713, 224,
            	259, 240,
            	1005, 248,
            	1813, 264,
            	1813, 272,
            	196, 280,
            	196, 296,
            	196, 312,
            	196, 320,
            	196, 344,
            1, 8, 1, /* 1808: pointer.struct.sess_cert_st */
            	1751, 0,
            1, 8, 1, /* 1813: pointer.struct.ssl_session_st */
            	1777, 0,
            0, 0, 0, /* 1818: func */
            1, 8, 1, /* 1821: pointer.func */
            	1826, 0,
            0, 0, 0, /* 1826: func */
            1, 8, 1, /* 1829: pointer.struct.in_addr */
            	1732, 0,
            1, 8, 1, /* 1834: pointer.func */
            	1839, 0,
            0, 0, 0, /* 1839: func */
            0, 0, 0, /* 1842: func */
            0, 0, 0, /* 1845: func */
            1, 8, 1, /* 1848: pointer.struct.x509_store_st */
            	1853, 0,
            0, 144, 15, /* 1853: struct.x509_store_st */
            	259, 8,
            	259, 16,
            	1886, 24,
            	1898, 32,
            	1906, 40,
            	1914, 48,
            	1922, 56,
            	1898, 64,
            	1930, 72,
            	1938, 80,
            	1946, 88,
            	1954, 96,
            	1954, 104,
            	1898, 112,
            	1005, 120,
            1, 8, 1, /* 1886: pointer.struct.X509_VERIFY_PARAM_st */
            	1891, 0,
            0, 56, 2, /* 1891: struct.X509_VERIFY_PARAM_st */
            	196, 0,
            	259, 48,
            1, 8, 1, /* 1898: pointer.func */
            	1903, 0,
            0, 0, 0, /* 1903: func */
            1, 8, 1, /* 1906: pointer.func */
            	1911, 0,
            0, 0, 0, /* 1911: func */
            1, 8, 1, /* 1914: pointer.func */
            	1919, 0,
            0, 0, 0, /* 1919: func */
            1, 8, 1, /* 1922: pointer.func */
            	1927, 0,
            0, 0, 0, /* 1927: func */
            1, 8, 1, /* 1930: pointer.func */
            	1935, 0,
            0, 0, 0, /* 1935: func */
            1, 8, 1, /* 1938: pointer.func */
            	1943, 0,
            0, 0, 0, /* 1943: func */
            1, 8, 1, /* 1946: pointer.func */
            	1951, 0,
            0, 0, 0, /* 1951: func */
            1, 8, 1, /* 1954: pointer.func */
            	1959, 0,
            0, 0, 0, /* 1959: func */
            1, 8, 1, /* 1962: pointer.func */
            	8, 0,
            1, 8, 1, /* 1967: pointer.func */
            	1842, 0,
            1, 8, 1, /* 1972: pointer.struct.ssl3_enc_method.753 */
            	1977, 0,
            0, 112, 11, /* 1977: struct.ssl3_enc_method.753 */
            	397, 0,
            	2002, 8,
            	1769, 16,
            	1834, 24,
            	397, 32,
            	2010, 40,
            	2018, 56,
            	196, 64,
            	196, 80,
            	1821, 96,
            	2026, 104,
            1, 8, 1, /* 2002: pointer.func */
            	2007, 0,
            0, 0, 0, /* 2007: func */
            1, 8, 1, /* 2010: pointer.func */
            	2015, 0,
            0, 0, 0, /* 2015: func */
            1, 8, 1, /* 2018: pointer.func */
            	2023, 0,
            0, 0, 0, /* 2023: func */
            1, 8, 1, /* 2026: pointer.func */
            	1845, 0,
            0, 0, 0, /* 2031: func */
            1, 8, 1, /* 2034: pointer.func */
            	2039, 0,
            0, 0, 0, /* 2039: func */
            1, 8, 1, /* 2042: pointer.func */
            	2047, 0,
            0, 0, 0, /* 2047: func */
            0, 0, 0, /* 2050: func */
            1, 8, 1, /* 2053: pointer.func */
            	1818, 0,
            1, 8, 1, /* 2058: pointer.func */
            	54, 0,
            1, 8, 1, /* 2063: pointer.func */
            	1766, 0,
            0, 32, 0, /* 2068: array[32].char */
            0, 0, 0, /* 2071: func */
            0, 8, 0, /* 2074: array[8].char */
            0, 128, 14, /* 2077: struct.srp_ctx_st.751 */
            	196, 0,
            	2058, 8,
            	38, 16,
            	11, 24,
            	196, 32,
            	1207, 40,
            	1207, 48,
            	1207, 56,
            	1207, 64,
            	1207, 72,
            	1207, 80,
            	1207, 88,
            	1207, 96,
            	196, 104,
            1, 8, 1, /* 2108: pointer.func */
            	2113, 0,
            0, 0, 0, /* 2113: func */
            0, 24, 1, /* 2116: struct.ssl3_buf_freelist_st */
            	73, 16,
            0, 8, 0, /* 2121: long */
            1, 8, 1, /* 2124: pointer.func */
            	2071, 0,
            0, 232, 28, /* 2129: struct.ssl_method_st.754 */
            	1769, 8,
            	2042, 16,
            	2042, 24,
            	1769, 32,
            	1769, 40,
            	2002, 48,
            	2002, 56,
            	2002, 64,
            	1769, 72,
            	1769, 80,
            	1769, 88,
            	2188, 96,
            	2196, 104,
            	2201, 112,
            	1769, 120,
            	2034, 128,
            	2209, 136,
            	2217, 144,
            	2108, 152,
            	1769, 160,
            	913, 168,
            	2124, 176,
            	2225, 184,
            	1967, 192,
            	1972, 200,
            	913, 208,
            	2063, 216,
            	2053, 224,
            1, 8, 1, /* 2188: pointer.func */
            	2193, 0,
            0, 0, 0, /* 2193: func */
            1, 8, 1, /* 2196: pointer.func */
            	2031, 0,
            1, 8, 1, /* 2201: pointer.func */
            	2206, 0,
            0, 0, 0, /* 2206: func */
            1, 8, 1, /* 2209: pointer.func */
            	2214, 0,
            0, 0, 0, /* 2214: func */
            1, 8, 1, /* 2217: pointer.func */
            	2222, 0,
            0, 0, 0, /* 2222: func */
            1, 8, 1, /* 2225: pointer.func */
            	2050, 0,
            0, 20, 0, /* 2230: array[5].int */
            1, 8, 1, /* 2233: pointer.struct.ssl_ctx_st.752 */
            	2238, 0,
            0, 736, 50, /* 2238: struct.ssl_ctx_st.752 */
            	2341, 0,
            	259, 8,
            	259, 16,
            	1848, 24,
            	1829, 32,
            	1813, 48,
            	1813, 56,
            	1708, 80,
            	1735, 88,
            	1743, 96,
            	2346, 152,
            	196, 160,
            	1697, 168,
            	196, 176,
            	1689, 184,
            	2351, 192,
            	2002, 200,
            	1005, 208,
            	1085, 224,
            	1085, 232,
            	1085, 240,
            	259, 248,
            	259, 256,
            	2359, 264,
            	259, 272,
            	1681, 304,
            	60, 320,
            	196, 328,
            	1906, 376,
            	2351, 384,
            	1886, 392,
            	509, 408,
            	2058, 416,
            	196, 424,
            	46, 480,
            	38, 488,
            	196, 496,
            	30, 504,
            	196, 512,
            	196, 520,
            	22, 528,
            	1834, 536,
            	2367, 552,
            	2367, 560,
            	2077, 568,
            	1962, 696,
            	196, 704,
            	3, 712,
            	196, 720,
            	259, 728,
            1, 8, 1, /* 2341: pointer.struct.ssl_method_st.754 */
            	2129, 0,
            1, 8, 1, /* 2346: pointer.func */
            	1729, 0,
            1, 8, 1, /* 2351: pointer.func */
            	2356, 0,
            0, 0, 0, /* 2356: func */
            1, 8, 1, /* 2359: pointer.func */
            	2364, 0,
            0, 0, 0, /* 2364: func */
            1, 8, 1, /* 2367: pointer.struct.ssl3_buf_freelist_st */
            	2116, 0,
            0, 48, 0, /* 2372: array[48].char */
            0, 20, 0, /* 2375: array[20].char */
        },
        .arg_entity_index = { 2233, },
        .ret_entity_index = 1848,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    const SSL_CTX * new_arg_a = *((const SSL_CTX * *)new_args->args[0]);

    X509_STORE * *new_ret_ptr = (X509_STORE * *)new_args->ret;

    X509_STORE * (*orig_SSL_CTX_get_cert_store)(const SSL_CTX *);
    orig_SSL_CTX_get_cert_store = dlsym(RTLD_NEXT, "SSL_CTX_get_cert_store");
    *new_ret_ptr = (*orig_SSL_CTX_get_cert_store)(new_arg_a);

    syscall(889);

    return ret;
}

