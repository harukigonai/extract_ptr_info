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

int X509_STORE_CTX_get1_issuer(X509 ** arg_a,X509_STORE_CTX * arg_b,X509 * arg_c) 
{
    int ret;

    struct lib_enter_args args = {
        .entity_metadata = {
            0, 0, 0, /* 0: func */
            0, 0, 0, /* 3: func */
            1, 8, 1, /* 6: pointer.struct.x509_crl_method_st */
            	11, 0,
            0, 40, 5, /* 11: struct.x509_crl_method_st */
            	24, 0,
            	27, 8,
            	27, 16,
            	32, 24,
            	40, 32,
            0, 4, 0, /* 24: int */
            1, 8, 1, /* 27: pointer.func */
            	3, 0,
            1, 8, 1, /* 32: pointer.func */
            	37, 0,
            0, 0, 0, /* 37: func */
            1, 8, 1, /* 40: pointer.func */
            	0, 0,
            0, 8, 1, /* 45: union.anon.1.3070 */
            	50, 0,
            1, 8, 1, /* 50: pointer.struct.stack_st_OPENSSL_STRING */
            	55, 0,
            0, 32, 1, /* 55: struct.stack_st_OPENSSL_STRING */
            	60, 0,
            0, 32, 5, /* 60: struct.stack_st */
            	24, 0,
            	73, 8,
            	24, 16,
            	24, 20,
            	86, 24,
            1, 8, 1, /* 73: pointer.pointer.char */
            	78, 0,
            1, 8, 1, /* 78: pointer.char */
            	83, 0,
            0, 1, 0, /* 83: char */
            1, 8, 1, /* 86: pointer.func */
            	91, 0,
            0, 0, 0, /* 91: func */
            0, 24, 3, /* 94: struct.DIST_POINT_NAME_st */
            	24, 0,
            	45, 8,
            	103, 16,
            1, 8, 1, /* 103: pointer.struct.X509_name_st */
            	108, 0,
            0, 40, 5, /* 108: struct.X509_name_st */
            	50, 0,
            	24, 8,
            	121, 16,
            	78, 24,
            	24, 32,
            1, 8, 1, /* 121: pointer.struct.buf_mem_st */
            	126, 0,
            0, 24, 3, /* 126: struct.buf_mem_st */
            	135, 0,
            	78, 8,
            	135, 16,
            0, 8, 0, /* 135: long */
            1, 8, 1, /* 138: pointer.struct.DIST_POINT_NAME_st */
            	94, 0,
            0, 32, 6, /* 143: struct.ISSUING_DIST_POINT_st */
            	138, 0,
            	24, 8,
            	24, 12,
            	158, 16,
            	24, 24,
            	24, 28,
            1, 8, 1, /* 158: pointer.struct.asn1_string_st */
            	163, 0,
            0, 24, 4, /* 163: struct.asn1_string_st */
            	24, 0,
            	24, 4,
            	78, 8,
            	135, 16,
            0, 80, 8, /* 174: struct.X509_crl_info_st */
            	158, 0,
            	193, 8,
            	103, 16,
            	158, 24,
            	158, 32,
            	50, 40,
            	50, 48,
            	242, 56,
            1, 8, 1, /* 193: pointer.struct.X509_algor_st */
            	198, 0,
            0, 16, 2, /* 198: struct.X509_algor_st */
            	205, 0,
            	225, 8,
            1, 8, 1, /* 205: pointer.struct.asn1_object_st */
            	210, 0,
            0, 40, 6, /* 210: struct.asn1_object_st */
            	78, 0,
            	78, 8,
            	24, 16,
            	24, 20,
            	78, 24,
            	24, 32,
            1, 8, 1, /* 225: pointer.struct.asn1_type_st */
            	230, 0,
            0, 16, 2, /* 230: struct.asn1_type_st */
            	24, 0,
            	237, 8,
            0, 8, 1, /* 237: struct.fnames */
            	78, 0,
            0, 24, 3, /* 242: struct.ASN1_ENCODING_st */
            	78, 0,
            	135, 8,
            	24, 16,
            1, 8, 1, /* 251: pointer.struct.X509_crl_info_st */
            	174, 0,
            0, 24, 3, /* 256: struct.X509_POLICY_NODE_st */
            	265, 0,
            	281, 8,
            	24, 16,
            1, 8, 1, /* 265: pointer.struct.X509_POLICY_DATA_st */
            	270, 0,
            0, 32, 4, /* 270: struct.X509_POLICY_DATA_st */
            	24, 0,
            	205, 8,
            	50, 16,
            	50, 24,
            1, 8, 1, /* 281: pointer.struct.X509_POLICY_NODE_st */
            	256, 0,
            0, 48, 6, /* 286: struct.X509_POLICY_TREE_st */
            	301, 0,
            	24, 8,
            	50, 16,
            	50, 24,
            	50, 32,
            	24, 40,
            1, 8, 1, /* 301: pointer.struct.X509_POLICY_LEVEL_st */
            	306, 0,
            0, 32, 4, /* 306: struct.X509_POLICY_LEVEL_st */
            	317, 0,
            	50, 8,
            	281, 16,
            	24, 24,
            1, 8, 1, /* 317: pointer.struct.x509_st */
            	322, 0,
            0, 184, 21, /* 322: struct.x509_st */
            	367, 0,
            	193, 8,
            	158, 16,
            	24, 24,
            	24, 28,
            	78, 32,
            	1137, 40,
            	135, 56,
            	135, 64,
            	135, 72,
            	135, 80,
            	135, 88,
            	135, 96,
            	158, 104,
            	1144, 112,
            	1158, 120,
            	50, 128,
            	50, 136,
            	1176, 144,
            	1188, 152,
            	1231, 176,
            1, 8, 1, /* 367: pointer.struct.x509_cinf_st */
            	372, 0,
            0, 104, 11, /* 372: struct.x509_cinf_st */
            	158, 0,
            	158, 8,
            	193, 16,
            	103, 24,
            	397, 32,
            	103, 40,
            	409, 48,
            	158, 56,
            	158, 64,
            	50, 72,
            	242, 80,
            1, 8, 1, /* 397: pointer.struct.X509_val_st */
            	402, 0,
            0, 16, 2, /* 402: struct.X509_val_st */
            	158, 0,
            	158, 8,
            1, 8, 1, /* 409: pointer.struct.X509_pubkey_st */
            	414, 0,
            0, 24, 3, /* 414: struct.X509_pubkey_st */
            	193, 0,
            	158, 8,
            	423, 16,
            1, 8, 1, /* 423: pointer.struct.evp_pkey_st */
            	428, 0,
            0, 56, 8, /* 428: struct.evp_pkey_st */
            	24, 0,
            	24, 4,
            	24, 8,
            	447, 16,
            	621, 24,
            	237, 32,
            	24, 40,
            	50, 48,
            1, 8, 1, /* 447: pointer.struct.evp_pkey_asn1_method_st */
            	452, 0,
            0, 208, 27, /* 452: struct.evp_pkey_asn1_method_st */
            	24, 0,
            	24, 4,
            	135, 8,
            	78, 16,
            	78, 24,
            	509, 32,
            	517, 40,
            	525, 48,
            	533, 56,
            	541, 64,
            	549, 72,
            	533, 80,
            	557, 88,
            	557, 96,
            	565, 104,
            	573, 112,
            	557, 120,
            	525, 128,
            	525, 136,
            	533, 144,
            	581, 152,
            	589, 160,
            	597, 168,
            	565, 176,
            	573, 184,
            	605, 192,
            	613, 200,
            1, 8, 1, /* 509: pointer.struct.unnamed */
            	514, 0,
            0, 0, 0, /* 514: struct.unnamed */
            1, 8, 1, /* 517: pointer.func */
            	522, 0,
            0, 0, 0, /* 522: func */
            1, 8, 1, /* 525: pointer.func */
            	530, 0,
            0, 0, 0, /* 530: func */
            1, 8, 1, /* 533: pointer.func */
            	538, 0,
            0, 0, 0, /* 538: func */
            1, 8, 1, /* 541: pointer.func */
            	546, 0,
            0, 0, 0, /* 546: func */
            1, 8, 1, /* 549: pointer.func */
            	554, 0,
            0, 0, 0, /* 554: func */
            1, 8, 1, /* 557: pointer.func */
            	562, 0,
            0, 0, 0, /* 562: func */
            1, 8, 1, /* 565: pointer.func */
            	570, 0,
            0, 0, 0, /* 570: func */
            1, 8, 1, /* 573: pointer.func */
            	578, 0,
            0, 0, 0, /* 578: func */
            1, 8, 1, /* 581: pointer.func */
            	586, 0,
            0, 0, 0, /* 586: func */
            1, 8, 1, /* 589: pointer.func */
            	594, 0,
            0, 0, 0, /* 594: func */
            1, 8, 1, /* 597: pointer.func */
            	602, 0,
            0, 0, 0, /* 602: func */
            1, 8, 1, /* 605: pointer.func */
            	610, 0,
            0, 0, 0, /* 610: func */
            1, 8, 1, /* 613: pointer.func */
            	618, 0,
            0, 0, 0, /* 618: func */
            1, 8, 1, /* 621: pointer.struct.engine_st */
            	626, 0,
            0, 216, 27, /* 626: struct.engine_st */
            	78, 0,
            	78, 8,
            	683, 16,
            	775, 24,
            	863, 32,
            	921, 40,
            	945, 48,
            	989, 56,
            	1049, 64,
            	1057, 72,
            	1065, 80,
            	1073, 88,
            	1081, 96,
            	1089, 104,
            	1089, 112,
            	1089, 120,
            	1097, 128,
            	1105, 136,
            	1105, 144,
            	1113, 152,
            	1121, 160,
            	24, 168,
            	24, 172,
            	24, 176,
            	1137, 184,
            	621, 200,
            	621, 208,
            1, 8, 1, /* 683: pointer.struct.rsa_meth_st */
            	688, 0,
            0, 112, 14, /* 688: struct.rsa_meth_st */
            	78, 0,
            	719, 8,
            	719, 16,
            	719, 24,
            	719, 32,
            	727, 40,
            	735, 48,
            	743, 56,
            	743, 64,
            	24, 72,
            	78, 80,
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
            0, 96, 12, /* 780: struct.dsa_method.1040 */
            	78, 0,
            	807, 8,
            	815, 16,
            	823, 24,
            	831, 32,
            	839, 40,
            	847, 48,
            	847, 56,
            	24, 64,
            	78, 72,
            	855, 80,
            	847, 88,
            1, 8, 1, /* 807: pointer.func */
            	812, 0,
            0, 0, 0, /* 812: func */
            1, 8, 1, /* 815: pointer.func */
            	820, 0,
            0, 0, 0, /* 820: func */
            1, 8, 1, /* 823: pointer.func */
            	828, 0,
            0, 0, 0, /* 828: func */
            1, 8, 1, /* 831: pointer.func */
            	836, 0,
            0, 0, 0, /* 836: func */
            1, 8, 1, /* 839: pointer.func */
            	844, 0,
            0, 0, 0, /* 844: func */
            1, 8, 1, /* 847: pointer.func */
            	852, 0,
            0, 0, 0, /* 852: func */
            1, 8, 1, /* 855: pointer.func */
            	860, 0,
            0, 0, 0, /* 860: func */
            1, 8, 1, /* 863: pointer.struct.dh_method */
            	868, 0,
            0, 72, 9, /* 868: struct.dh_method */
            	78, 0,
            	889, 8,
            	897, 16,
            	905, 24,
            	889, 32,
            	889, 40,
            	24, 48,
            	78, 56,
            	913, 64,
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
            1, 8, 1, /* 921: pointer.struct.ecdh_method */
            	926, 0,
            0, 32, 4, /* 926: struct.ecdh_method */
            	78, 0,
            	937, 8,
            	24, 16,
            	78, 24,
            1, 8, 1, /* 937: pointer.func */
            	942, 0,
            0, 0, 0, /* 942: func */
            1, 8, 1, /* 945: pointer.struct.ecdsa_method */
            	950, 0,
            0, 48, 6, /* 950: struct.ecdsa_method */
            	78, 0,
            	965, 8,
            	973, 16,
            	981, 24,
            	24, 32,
            	78, 40,
            1, 8, 1, /* 965: pointer.func */
            	970, 0,
            0, 0, 0, /* 970: func */
            1, 8, 1, /* 973: pointer.func */
            	978, 0,
            0, 0, 0, /* 978: func */
            1, 8, 1, /* 981: pointer.func */
            	986, 0,
            0, 0, 0, /* 986: func */
            1, 8, 1, /* 989: pointer.struct.rand_meth_st */
            	994, 0,
            0, 48, 6, /* 994: struct.rand_meth_st */
            	1009, 0,
            	1017, 8,
            	1025, 16,
            	1033, 24,
            	1017, 32,
            	1041, 40,
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
            1, 8, 1, /* 1049: pointer.struct.store_method_st */
            	1054, 0,
            0, 0, 0, /* 1054: struct.store_method_st */
            1, 8, 1, /* 1057: pointer.func */
            	1062, 0,
            0, 0, 0, /* 1062: func */
            1, 8, 1, /* 1065: pointer.func */
            	1070, 0,
            0, 0, 0, /* 1070: func */
            1, 8, 1, /* 1073: pointer.func */
            	1078, 0,
            0, 0, 0, /* 1078: func */
            1, 8, 1, /* 1081: pointer.func */
            	1086, 0,
            0, 0, 0, /* 1086: func */
            1, 8, 1, /* 1089: pointer.func */
            	1094, 0,
            0, 0, 0, /* 1094: func */
            1, 8, 1, /* 1097: pointer.func */
            	1102, 0,
            0, 0, 0, /* 1102: func */
            1, 8, 1, /* 1105: pointer.func */
            	1110, 0,
            0, 0, 0, /* 1110: func */
            1, 8, 1, /* 1113: pointer.func */
            	1118, 0,
            0, 0, 0, /* 1118: func */
            1, 8, 1, /* 1121: pointer.struct.ENGINE_CMD_DEFN_st */
            	1126, 0,
            0, 32, 4, /* 1126: struct.ENGINE_CMD_DEFN_st */
            	24, 0,
            	78, 8,
            	78, 16,
            	24, 24,
            0, 16, 2, /* 1137: struct.crypto_ex_data_st */
            	50, 0,
            	24, 8,
            1, 8, 1, /* 1144: pointer.struct.AUTHORITY_KEYID_st */
            	1149, 0,
            0, 24, 3, /* 1149: struct.AUTHORITY_KEYID_st */
            	158, 0,
            	50, 8,
            	158, 16,
            1, 8, 1, /* 1158: pointer.struct.X509_POLICY_CACHE_st */
            	1163, 0,
            0, 40, 5, /* 1163: struct.X509_POLICY_CACHE_st */
            	265, 0,
            	50, 8,
            	135, 16,
            	135, 24,
            	135, 32,
            1, 8, 1, /* 1176: pointer.struct.NAME_CONSTRAINTS_st */
            	1181, 0,
            0, 16, 2, /* 1181: struct.NAME_CONSTRAINTS_st */
            	50, 0,
            	50, 8,
            0, 20, 20, /* 1188: array[20].char */
            	83, 0,
            	83, 1,
            	83, 2,
            	83, 3,
            	83, 4,
            	83, 5,
            	83, 6,
            	83, 7,
            	83, 8,
            	83, 9,
            	83, 10,
            	83, 11,
            	83, 12,
            	83, 13,
            	83, 14,
            	83, 15,
            	83, 16,
            	83, 17,
            	83, 18,
            	83, 19,
            1, 8, 1, /* 1231: pointer.struct.x509_cert_aux_st */
            	1236, 0,
            0, 40, 5, /* 1236: struct.x509_cert_aux_st */
            	50, 0,
            	50, 8,
            	158, 16,
            	158, 24,
            	50, 32,
            1, 8, 1, /* 1249: pointer.struct.X509_POLICY_TREE_st */
            	286, 0,
            0, 0, 0, /* 1254: func */
            1, 8, 1, /* 1257: pointer.func */
            	1262, 0,
            0, 0, 0, /* 1262: func */
            0, 0, 0, /* 1265: func */
            0, 0, 0, /* 1268: func */
            0, 56, 8, /* 1271: struct.X509_VERIFY_PARAM_st */
            	78, 0,
            	135, 8,
            	135, 16,
            	135, 24,
            	24, 32,
            	24, 36,
            	24, 40,
            	50, 48,
            1, 8, 1, /* 1290: pointer.struct.X509_VERIFY_PARAM_st */
            	1271, 0,
            0, 144, 17, /* 1295: struct.x509_store_st */
            	24, 0,
            	50, 8,
            	50, 16,
            	1290, 24,
            	1332, 32,
            	1337, 40,
            	1257, 48,
            	1342, 56,
            	1332, 64,
            	1347, 72,
            	1355, 80,
            	1363, 88,
            	1371, 96,
            	1371, 104,
            	1332, 112,
            	1137, 120,
            	24, 136,
            1, 8, 1, /* 1332: pointer.func */
            	1268, 0,
            1, 8, 1, /* 1337: pointer.func */
            	1265, 0,
            1, 8, 1, /* 1342: pointer.func */
            	1254, 0,
            1, 8, 1, /* 1347: pointer.func */
            	1352, 0,
            0, 0, 0, /* 1352: func */
            1, 8, 1, /* 1355: pointer.func */
            	1360, 0,
            0, 0, 0, /* 1360: func */
            1, 8, 1, /* 1363: pointer.func */
            	1368, 0,
            0, 0, 0, /* 1368: func */
            1, 8, 1, /* 1371: pointer.func */
            	1376, 0,
            0, 0, 0, /* 1376: func */
            1, 8, 1, /* 1379: pointer.struct.x509_store_st */
            	1295, 0,
            0, 248, 33, /* 1384: struct.x509_store_ctx_st */
            	1379, 0,
            	24, 8,
            	317, 16,
            	50, 24,
            	50, 32,
            	1290, 40,
            	78, 48,
            	509, 56,
            	1337, 64,
            	1257, 72,
            	1342, 80,
            	509, 88,
            	1347, 96,
            	1355, 104,
            	1363, 112,
            	509, 120,
            	1371, 128,
            	1371, 136,
            	509, 144,
            	24, 152,
            	24, 156,
            	50, 160,
            	1249, 168,
            	24, 176,
            	24, 180,
            	24, 184,
            	317, 192,
            	317, 200,
            	1453, 208,
            	24, 216,
            	24, 220,
            	1496, 224,
            	1137, 232,
            1, 8, 1, /* 1453: pointer.struct.X509_crl_st */
            	1458, 0,
            0, 120, 15, /* 1458: struct.X509_crl_st */
            	251, 0,
            	193, 8,
            	158, 16,
            	24, 24,
            	24, 28,
            	1144, 32,
            	1491, 40,
            	24, 48,
            	24, 52,
            	158, 56,
            	158, 64,
            	1188, 72,
            	50, 96,
            	6, 104,
            	78, 112,
            1, 8, 1, /* 1491: pointer.struct.ISSUING_DIST_POINT_st */
            	143, 0,
            1, 8, 1, /* 1496: pointer.struct.x509_store_ctx_st */
            	1384, 0,
            1, 8, 1, /* 1501: pointer.pointer.struct.x509_st */
            	317, 0,
        },
        .arg_entity_index = { 1501, 1496, 317, },
        .ret_entity_index = 24,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    X509 ** new_arg_a = *((X509 ** *)new_args->args[0]);

    X509_STORE_CTX * new_arg_b = *((X509_STORE_CTX * *)new_args->args[1]);

    X509 * new_arg_c = *((X509 * *)new_args->args[2]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_X509_STORE_CTX_get1_issuer)(X509 **,X509_STORE_CTX *,X509 *);
    orig_X509_STORE_CTX_get1_issuer = dlsym(RTLD_NEXT, "X509_STORE_CTX_get1_issuer");
    *new_ret_ptr = (*orig_X509_STORE_CTX_get1_issuer)(new_arg_a,new_arg_b,new_arg_c);

    syscall(889);

    return ret;
}

