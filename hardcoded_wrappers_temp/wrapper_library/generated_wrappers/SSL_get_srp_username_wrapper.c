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

char * SSL_get_srp_username(SSL * arg_a) 
{
    printf("SSL_get_srp_username called\n");
    char * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 0, 0, /* 0: func */
            0, 16, 1, /* 3: struct.tls_session_ticket_ext_st */
            	8, 8,
            1, 8, 1, /* 8: pointer.char */
            	13, 0,
            0, 1, 0, /* 13: char */
            1, 8, 1, /* 16: pointer.func */
            	21, 0,
            0, 0, 0, /* 21: func */
            1, 8, 1, /* 24: pointer.func */
            	29, 0,
            0, 0, 0, /* 29: func */
            1, 8, 1, /* 32: pointer.struct.ssl3_buf_freelist_entry_st */
            	37, 0,
            0, 8, 1, /* 37: struct.ssl3_buf_freelist_entry_st */
            	32, 0,
            0, 0, 0, /* 42: func */
            0, 0, 0, /* 45: func */
            0, 0, 0, /* 48: func */
            1, 8, 1, /* 51: pointer.func */
            	56, 0,
            0, 0, 0, /* 56: func */
            1, 8, 1, /* 59: pointer.func */
            	48, 0,
            0, 0, 0, /* 64: func */
            0, 44, 0, /* 67: struct.apr_time_exp_t */
            1, 8, 1, /* 70: pointer.func */
            	75, 0,
            0, 0, 0, /* 75: func */
            1, 8, 1, /* 78: pointer.func */
            	83, 0,
            0, 0, 0, /* 83: func */
            0, 4, 0, /* 86: struct.in_addr */
            0, 0, 0, /* 89: func */
            1, 8, 1, /* 92: pointer.func */
            	97, 0,
            0, 0, 0, /* 97: func */
            0, 0, 0, /* 100: func */
            0, 144, 15, /* 103: struct.x509_store_st.74 */
            	136, 8,
            	136, 16,
            	166, 24,
            	178, 32,
            	186, 40,
            	194, 48,
            	202, 56,
            	178, 64,
            	210, 72,
            	92, 80,
            	215, 88,
            	220, 96,
            	220, 104,
            	178, 112,
            	228, 120,
            1, 8, 1, /* 136: pointer.struct.stack_st_OPENSSL_STRING */
            	141, 0,
            0, 32, 1, /* 141: struct.stack_st_OPENSSL_STRING */
            	146, 0,
            0, 32, 2, /* 146: struct.stack_st */
            	153, 8,
            	158, 24,
            1, 8, 1, /* 153: pointer.pointer.char */
            	8, 0,
            1, 8, 1, /* 158: pointer.func */
            	163, 0,
            0, 0, 0, /* 163: func */
            1, 8, 1, /* 166: pointer.struct.X509_VERIFY_PARAM_st */
            	171, 0,
            0, 56, 2, /* 171: struct.X509_VERIFY_PARAM_st */
            	8, 0,
            	136, 48,
            1, 8, 1, /* 178: pointer.func */
            	183, 0,
            0, 0, 0, /* 183: func */
            1, 8, 1, /* 186: pointer.struct.unnamed */
            	191, 0,
            0, 0, 0, /* 191: struct.unnamed */
            1, 8, 1, /* 194: pointer.func */
            	199, 0,
            0, 0, 0, /* 199: func */
            1, 8, 1, /* 202: pointer.func */
            	207, 0,
            0, 0, 0, /* 207: func */
            1, 8, 1, /* 210: pointer.func */
            	100, 0,
            1, 8, 1, /* 215: pointer.func */
            	89, 0,
            1, 8, 1, /* 220: pointer.func */
            	225, 0,
            0, 0, 0, /* 225: func */
            0, 16, 1, /* 228: struct.crypto_ex_data_st */
            	136, 0,
            1, 8, 1, /* 233: pointer.func */
            	238, 0,
            0, 0, 0, /* 238: func */
            1, 8, 1, /* 241: pointer.func */
            	246, 0,
            0, 0, 0, /* 246: func */
            1, 8, 1, /* 249: pointer.func */
            	254, 0,
            0, 0, 0, /* 254: func */
            1, 8, 1, /* 257: pointer.func */
            	0, 0,
            1, 8, 1, /* 262: pointer.func */
            	267, 0,
            0, 0, 0, /* 267: func */
            0, 0, 0, /* 270: func */
            0, 0, 0, /* 273: func */
            0, 0, 0, /* 276: func */
            1, 8, 1, /* 279: pointer.struct.in_addr */
            	86, 0,
            0, 12, 0, /* 284: array[12].char */
            0, 12, 0, /* 287: struct.ap_unix_identity_t */
            0, 88, 7, /* 290: struct.bn_blinding_st */
            	307, 0,
            	307, 8,
            	307, 16,
            	307, 24,
            	325, 40,
            	330, 72,
            	344, 80,
            1, 8, 1, /* 307: pointer.struct.bignum_st */
            	312, 0,
            0, 24, 1, /* 312: struct.bignum_st */
            	317, 0,
            1, 8, 1, /* 317: pointer.int */
            	322, 0,
            0, 4, 0, /* 322: int */
            0, 16, 1, /* 325: struct.iovec */
            	8, 0,
            1, 8, 1, /* 330: pointer.struct.bn_mont_ctx_st */
            	335, 0,
            0, 96, 3, /* 335: struct.bn_mont_ctx_st */
            	312, 8,
            	312, 32,
            	312, 56,
            1, 8, 1, /* 344: pointer.func */
            	349, 0,
            0, 0, 0, /* 349: func */
            0, 40, 5, /* 352: struct.x509_cert_aux_st */
            	136, 0,
            	136, 8,
            	365, 16,
            	365, 24,
            	136, 32,
            1, 8, 1, /* 365: pointer.struct.asn1_string_st */
            	370, 0,
            0, 24, 1, /* 370: struct.asn1_string_st */
            	8, 8,
            1, 8, 1, /* 375: pointer.func */
            	380, 0,
            0, 0, 0, /* 380: func */
            1, 8, 1, /* 383: pointer.struct.NAME_CONSTRAINTS_st */
            	388, 0,
            0, 16, 2, /* 388: struct.NAME_CONSTRAINTS_st */
            	136, 0,
            	136, 8,
            0, 32, 3, /* 395: struct.X509_POLICY_DATA_st */
            	404, 8,
            	136, 16,
            	136, 24,
            1, 8, 1, /* 404: pointer.struct.asn1_object_st */
            	409, 0,
            0, 40, 3, /* 409: struct.asn1_object_st */
            	8, 0,
            	8, 8,
            	8, 24,
            1, 8, 1, /* 418: pointer.struct.X509_POLICY_DATA_st */
            	395, 0,
            0, 16, 0, /* 423: struct.rlimit */
            0, 40, 2, /* 426: struct.X509_POLICY_CACHE_st */
            	418, 0,
            	136, 8,
            1, 8, 1, /* 433: pointer.struct.ssl_ctx_st */
            	438, 0,
            0, 736, 50, /* 438: struct.ssl_ctx_st */
            	541, 0,
            	136, 8,
            	136, 16,
            	811, 24,
            	279, 32,
            	816, 48,
            	816, 56,
            	78, 80,
            	375, 88,
            	70, 96,
            	2254, 152,
            	8, 160,
            	59, 168,
            	8, 176,
            	2259, 184,
            	262, 192,
            	621, 200,
            	228, 208,
            	1710, 224,
            	1710, 232,
            	1710, 240,
            	136, 248,
            	136, 256,
            	241, 264,
            	136, 272,
            	2264, 304,
            	2306, 320,
            	8, 328,
            	249, 376,
            	262, 384,
            	166, 392,
            	1201, 408,
            	2311, 416,
            	8, 424,
            	2316, 480,
            	2324, 488,
            	8, 496,
            	2332, 504,
            	8, 512,
            	8, 520,
            	233, 528,
            	755, 536,
            	2340, 552,
            	2340, 560,
            	2350, 568,
            	16, 696,
            	8, 704,
            	2381, 712,
            	8, 720,
            	136, 728,
            1, 8, 1, /* 541: pointer.struct.ssl_method_st */
            	546, 0,
            0, 232, 28, /* 546: struct.ssl_method_st */
            	605, 8,
            	613, 16,
            	613, 24,
            	605, 32,
            	605, 40,
            	621, 48,
            	621, 56,
            	621, 64,
            	605, 72,
            	605, 80,
            	605, 88,
            	629, 96,
            	637, 104,
            	645, 112,
            	605, 120,
            	653, 128,
            	661, 136,
            	669, 144,
            	677, 152,
            	605, 160,
            	685, 168,
            	693, 176,
            	701, 184,
            	709, 192,
            	717, 200,
            	685, 208,
            	795, 216,
            	803, 224,
            1, 8, 1, /* 605: pointer.func */
            	610, 0,
            0, 0, 0, /* 610: func */
            1, 8, 1, /* 613: pointer.func */
            	618, 0,
            0, 0, 0, /* 618: func */
            1, 8, 1, /* 621: pointer.func */
            	626, 0,
            0, 0, 0, /* 626: func */
            1, 8, 1, /* 629: pointer.func */
            	634, 0,
            0, 0, 0, /* 634: func */
            1, 8, 1, /* 637: pointer.func */
            	642, 0,
            0, 0, 0, /* 642: func */
            1, 8, 1, /* 645: pointer.func */
            	650, 0,
            0, 0, 0, /* 650: func */
            1, 8, 1, /* 653: pointer.func */
            	658, 0,
            0, 0, 0, /* 658: func */
            1, 8, 1, /* 661: pointer.func */
            	666, 0,
            0, 0, 0, /* 666: func */
            1, 8, 1, /* 669: pointer.func */
            	674, 0,
            0, 0, 0, /* 674: func */
            1, 8, 1, /* 677: pointer.func */
            	682, 0,
            0, 0, 0, /* 682: func */
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
            1, 8, 1, /* 717: pointer.struct.ssl3_enc_method */
            	722, 0,
            0, 112, 11, /* 722: struct.ssl3_enc_method */
            	747, 0,
            	621, 8,
            	605, 16,
            	755, 24,
            	747, 32,
            	763, 40,
            	771, 56,
            	8, 64,
            	8, 80,
            	779, 96,
            	787, 104,
            1, 8, 1, /* 747: pointer.func */
            	752, 0,
            0, 0, 0, /* 752: func */
            1, 8, 1, /* 755: pointer.func */
            	760, 0,
            0, 0, 0, /* 760: func */
            1, 8, 1, /* 763: pointer.func */
            	768, 0,
            0, 0, 0, /* 768: func */
            1, 8, 1, /* 771: pointer.func */
            	776, 0,
            0, 0, 0, /* 776: func */
            1, 8, 1, /* 779: pointer.func */
            	784, 0,
            0, 0, 0, /* 784: func */
            1, 8, 1, /* 787: pointer.func */
            	792, 0,
            0, 0, 0, /* 792: func */
            1, 8, 1, /* 795: pointer.func */
            	800, 0,
            0, 0, 0, /* 800: func */
            1, 8, 1, /* 803: pointer.func */
            	808, 0,
            0, 0, 0, /* 808: func */
            1, 8, 1, /* 811: pointer.struct.x509_store_st.74 */
            	103, 0,
            1, 8, 1, /* 816: pointer.struct.ssl_session_st */
            	821, 0,
            0, 352, 14, /* 821: struct.ssl_session_st */
            	8, 144,
            	8, 152,
            	852, 168,
            	886, 176,
            	2244, 224,
            	136, 240,
            	228, 248,
            	816, 264,
            	816, 272,
            	8, 280,
            	8, 296,
            	8, 312,
            	8, 320,
            	8, 344,
            1, 8, 1, /* 852: pointer.struct.sess_cert_st */
            	857, 0,
            0, 248, 6, /* 857: struct.sess_cert_st */
            	136, 0,
            	872, 16,
            	1790, 24,
            	1809, 216,
            	1856, 224,
            	1888, 232,
            1, 8, 1, /* 872: pointer.struct.cert_pkey_st */
            	877, 0,
            0, 24, 3, /* 877: struct.cert_pkey_st */
            	886, 0,
            	1025, 8,
            	1710, 16,
            1, 8, 1, /* 886: pointer.struct.x509_st */
            	891, 0,
            0, 184, 12, /* 891: struct.x509_st */
            	918, 0,
            	948, 8,
            	365, 16,
            	8, 32,
            	228, 40,
            	365, 104,
            	1686, 112,
            	1700, 120,
            	136, 128,
            	136, 136,
            	383, 144,
            	1705, 176,
            1, 8, 1, /* 918: pointer.struct.x509_cinf_st */
            	923, 0,
            0, 104, 11, /* 923: struct.x509_cinf_st */
            	365, 0,
            	365, 8,
            	948, 16,
            	975, 24,
            	999, 32,
            	975, 40,
            	1011, 48,
            	365, 56,
            	365, 64,
            	136, 72,
            	1681, 80,
            1, 8, 1, /* 948: pointer.struct.X509_algor_st */
            	953, 0,
            0, 16, 2, /* 953: struct.X509_algor_st */
            	404, 0,
            	960, 8,
            1, 8, 1, /* 960: pointer.struct.asn1_type_st */
            	965, 0,
            0, 16, 1, /* 965: struct.asn1_type_st */
            	970, 8,
            0, 8, 1, /* 970: struct.fnames */
            	8, 0,
            1, 8, 1, /* 975: pointer.struct.X509_name_st */
            	980, 0,
            0, 40, 3, /* 980: struct.X509_name_st */
            	136, 0,
            	989, 16,
            	8, 24,
            1, 8, 1, /* 989: pointer.struct.buf_mem_st */
            	994, 0,
            0, 24, 1, /* 994: struct.buf_mem_st */
            	8, 8,
            1, 8, 1, /* 999: pointer.struct.X509_val_st */
            	1004, 0,
            0, 16, 2, /* 1004: struct.X509_val_st */
            	365, 0,
            	365, 8,
            1, 8, 1, /* 1011: pointer.struct.X509_pubkey_st */
            	1016, 0,
            0, 24, 3, /* 1016: struct.X509_pubkey_st */
            	948, 0,
            	365, 8,
            	1025, 16,
            1, 8, 1, /* 1025: pointer.struct.evp_pkey_st */
            	1030, 0,
            0, 56, 4, /* 1030: struct.evp_pkey_st */
            	1041, 16,
            	1201, 24,
            	970, 32,
            	136, 48,
            1, 8, 1, /* 1041: pointer.struct.evp_pkey_asn1_method_st */
            	1046, 0,
            0, 208, 24, /* 1046: struct.evp_pkey_asn1_method_st */
            	8, 16,
            	8, 24,
            	186, 32,
            	1097, 40,
            	1105, 48,
            	1113, 56,
            	1121, 64,
            	1129, 72,
            	1113, 80,
            	1137, 88,
            	1137, 96,
            	1145, 104,
            	1153, 112,
            	1137, 120,
            	1105, 128,
            	1105, 136,
            	1113, 144,
            	1161, 152,
            	1169, 160,
            	1177, 168,
            	1145, 176,
            	1153, 184,
            	1185, 192,
            	1193, 200,
            1, 8, 1, /* 1097: pointer.func */
            	1102, 0,
            0, 0, 0, /* 1102: func */
            1, 8, 1, /* 1105: pointer.func */
            	1110, 0,
            0, 0, 0, /* 1110: func */
            1, 8, 1, /* 1113: pointer.func */
            	1118, 0,
            0, 0, 0, /* 1118: func */
            1, 8, 1, /* 1121: pointer.func */
            	1126, 0,
            0, 0, 0, /* 1126: func */
            1, 8, 1, /* 1129: pointer.func */
            	1134, 0,
            0, 0, 0, /* 1134: func */
            1, 8, 1, /* 1137: pointer.func */
            	1142, 0,
            0, 0, 0, /* 1142: func */
            1, 8, 1, /* 1145: pointer.func */
            	1150, 0,
            0, 0, 0, /* 1150: func */
            1, 8, 1, /* 1153: pointer.func */
            	1158, 0,
            0, 0, 0, /* 1158: func */
            1, 8, 1, /* 1161: pointer.func */
            	1166, 0,
            0, 0, 0, /* 1166: func */
            1, 8, 1, /* 1169: pointer.func */
            	1174, 0,
            0, 0, 0, /* 1174: func */
            1, 8, 1, /* 1177: pointer.func */
            	1182, 0,
            0, 0, 0, /* 1182: func */
            1, 8, 1, /* 1185: pointer.func */
            	1190, 0,
            0, 0, 0, /* 1190: func */
            1, 8, 1, /* 1193: pointer.func */
            	1198, 0,
            0, 0, 0, /* 1198: func */
            1, 8, 1, /* 1201: pointer.struct.engine_st */
            	1206, 0,
            0, 216, 24, /* 1206: struct.engine_st */
            	8, 0,
            	8, 8,
            	1257, 16,
            	1339, 24,
            	1425, 32,
            	1481, 40,
            	1503, 48,
            	1545, 56,
            	1597, 64,
            	1605, 72,
            	1613, 80,
            	1621, 88,
            	1629, 96,
            	1637, 104,
            	1637, 112,
            	1637, 120,
            	1645, 128,
            	1653, 136,
            	1653, 144,
            	1661, 152,
            	1669, 160,
            	228, 184,
            	1201, 200,
            	1201, 208,
            1, 8, 1, /* 1257: pointer.struct.rsa_meth_st */
            	1262, 0,
            0, 112, 13, /* 1262: struct.rsa_meth_st */
            	8, 0,
            	1291, 8,
            	1291, 16,
            	1291, 24,
            	1291, 32,
            	1299, 40,
            	344, 48,
            	1307, 56,
            	1307, 64,
            	8, 80,
            	1315, 88,
            	1323, 96,
            	1331, 104,
            1, 8, 1, /* 1291: pointer.func */
            	1296, 0,
            0, 0, 0, /* 1296: func */
            1, 8, 1, /* 1299: pointer.func */
            	1304, 0,
            0, 0, 0, /* 1304: func */
            1, 8, 1, /* 1307: pointer.func */
            	1312, 0,
            0, 0, 0, /* 1312: func */
            1, 8, 1, /* 1315: pointer.func */
            	1320, 0,
            0, 0, 0, /* 1320: func */
            1, 8, 1, /* 1323: pointer.func */
            	1328, 0,
            0, 0, 0, /* 1328: func */
            1, 8, 1, /* 1331: pointer.func */
            	1336, 0,
            0, 0, 0, /* 1336: func */
            1, 8, 1, /* 1339: pointer.struct.dsa_method.1040 */
            	1344, 0,
            0, 96, 11, /* 1344: struct.dsa_method.1040 */
            	8, 0,
            	1369, 8,
            	1377, 16,
            	1385, 24,
            	1393, 32,
            	1401, 40,
            	1409, 48,
            	1409, 56,
            	8, 72,
            	1417, 80,
            	1409, 88,
            1, 8, 1, /* 1369: pointer.func */
            	1374, 0,
            0, 0, 0, /* 1374: func */
            1, 8, 1, /* 1377: pointer.func */
            	1382, 0,
            0, 0, 0, /* 1382: func */
            1, 8, 1, /* 1385: pointer.func */
            	1390, 0,
            0, 0, 0, /* 1390: func */
            1, 8, 1, /* 1393: pointer.func */
            	1398, 0,
            0, 0, 0, /* 1398: func */
            1, 8, 1, /* 1401: pointer.func */
            	1406, 0,
            0, 0, 0, /* 1406: func */
            1, 8, 1, /* 1409: pointer.func */
            	1414, 0,
            0, 0, 0, /* 1414: func */
            1, 8, 1, /* 1417: pointer.func */
            	1422, 0,
            0, 0, 0, /* 1422: func */
            1, 8, 1, /* 1425: pointer.struct.dh_method */
            	1430, 0,
            0, 72, 8, /* 1430: struct.dh_method */
            	8, 0,
            	1449, 8,
            	1457, 16,
            	1465, 24,
            	1449, 32,
            	1449, 40,
            	8, 56,
            	1473, 64,
            1, 8, 1, /* 1449: pointer.func */
            	1454, 0,
            0, 0, 0, /* 1454: func */
            1, 8, 1, /* 1457: pointer.func */
            	1462, 0,
            0, 0, 0, /* 1462: func */
            1, 8, 1, /* 1465: pointer.func */
            	1470, 0,
            0, 0, 0, /* 1470: func */
            1, 8, 1, /* 1473: pointer.func */
            	1478, 0,
            0, 0, 0, /* 1478: func */
            1, 8, 1, /* 1481: pointer.struct.ecdh_method */
            	1486, 0,
            0, 32, 3, /* 1486: struct.ecdh_method */
            	8, 0,
            	1495, 8,
            	8, 24,
            1, 8, 1, /* 1495: pointer.func */
            	1500, 0,
            0, 0, 0, /* 1500: func */
            1, 8, 1, /* 1503: pointer.struct.ecdsa_method */
            	1508, 0,
            0, 48, 5, /* 1508: struct.ecdsa_method */
            	8, 0,
            	1521, 8,
            	1529, 16,
            	1537, 24,
            	8, 40,
            1, 8, 1, /* 1521: pointer.func */
            	1526, 0,
            0, 0, 0, /* 1526: func */
            1, 8, 1, /* 1529: pointer.func */
            	1534, 0,
            0, 0, 0, /* 1534: func */
            1, 8, 1, /* 1537: pointer.func */
            	1542, 0,
            0, 0, 0, /* 1542: func */
            1, 8, 1, /* 1545: pointer.struct.rand_meth_st */
            	1550, 0,
            0, 48, 6, /* 1550: struct.rand_meth_st */
            	1565, 0,
            	1573, 8,
            	1581, 16,
            	1589, 24,
            	1573, 32,
            	685, 40,
            1, 8, 1, /* 1565: pointer.func */
            	1570, 0,
            0, 0, 0, /* 1570: func */
            1, 8, 1, /* 1573: pointer.func */
            	1578, 0,
            0, 0, 0, /* 1578: func */
            1, 8, 1, /* 1581: pointer.func */
            	1586, 0,
            0, 0, 0, /* 1586: func */
            1, 8, 1, /* 1589: pointer.func */
            	1594, 0,
            0, 0, 0, /* 1594: func */
            1, 8, 1, /* 1597: pointer.struct.store_method_st */
            	1602, 0,
            0, 0, 0, /* 1602: struct.store_method_st */
            1, 8, 1, /* 1605: pointer.func */
            	1610, 0,
            0, 0, 0, /* 1610: func */
            1, 8, 1, /* 1613: pointer.func */
            	1618, 0,
            0, 0, 0, /* 1618: func */
            1, 8, 1, /* 1621: pointer.func */
            	1626, 0,
            0, 0, 0, /* 1626: func */
            1, 8, 1, /* 1629: pointer.func */
            	1634, 0,
            0, 0, 0, /* 1634: func */
            1, 8, 1, /* 1637: pointer.func */
            	1642, 0,
            0, 0, 0, /* 1642: func */
            1, 8, 1, /* 1645: pointer.func */
            	1650, 0,
            0, 0, 0, /* 1650: func */
            1, 8, 1, /* 1653: pointer.func */
            	1658, 0,
            0, 0, 0, /* 1658: func */
            1, 8, 1, /* 1661: pointer.func */
            	1666, 0,
            0, 0, 0, /* 1666: func */
            1, 8, 1, /* 1669: pointer.struct.ENGINE_CMD_DEFN_st */
            	1674, 0,
            0, 32, 2, /* 1674: struct.ENGINE_CMD_DEFN_st */
            	8, 8,
            	8, 16,
            0, 24, 1, /* 1681: struct.ASN1_ENCODING_st */
            	8, 0,
            1, 8, 1, /* 1686: pointer.struct.AUTHORITY_KEYID_st */
            	1691, 0,
            0, 24, 3, /* 1691: struct.AUTHORITY_KEYID_st */
            	365, 0,
            	136, 8,
            	365, 16,
            1, 8, 1, /* 1700: pointer.struct.X509_POLICY_CACHE_st */
            	426, 0,
            1, 8, 1, /* 1705: pointer.struct.x509_cert_aux_st */
            	352, 0,
            1, 8, 1, /* 1710: pointer.struct.env_md_st */
            	1715, 0,
            0, 120, 8, /* 1715: struct.env_md_st */
            	1734, 24,
            	1742, 32,
            	1750, 40,
            	1758, 48,
            	1734, 56,
            	1766, 64,
            	1774, 72,
            	1782, 112,
            1, 8, 1, /* 1734: pointer.func */
            	1739, 0,
            0, 0, 0, /* 1739: func */
            1, 8, 1, /* 1742: pointer.func */
            	1747, 0,
            0, 0, 0, /* 1747: func */
            1, 8, 1, /* 1750: pointer.func */
            	1755, 0,
            0, 0, 0, /* 1755: func */
            1, 8, 1, /* 1758: pointer.func */
            	1763, 0,
            0, 0, 0, /* 1763: func */
            1, 8, 1, /* 1766: pointer.func */
            	1771, 0,
            0, 0, 0, /* 1771: func */
            1, 8, 1, /* 1774: pointer.func */
            	1779, 0,
            0, 0, 0, /* 1779: func */
            1, 8, 1, /* 1782: pointer.func */
            	1787, 0,
            0, 0, 0, /* 1787: func */
            0, 192, 8, /* 1790: array[8].struct.cert_pkey_st */
            	877, 0,
            	877, 24,
            	877, 48,
            	877, 72,
            	877, 96,
            	877, 120,
            	877, 144,
            	877, 168,
            1, 8, 1, /* 1809: pointer.struct.rsa_st */
            	1814, 0,
            0, 168, 17, /* 1814: struct.rsa_st */
            	1257, 16,
            	1201, 24,
            	307, 32,
            	307, 40,
            	307, 48,
            	307, 56,
            	307, 64,
            	307, 72,
            	307, 80,
            	307, 88,
            	228, 96,
            	330, 120,
            	330, 128,
            	330, 136,
            	8, 144,
            	1851, 152,
            	1851, 160,
            1, 8, 1, /* 1851: pointer.struct.bn_blinding_st */
            	290, 0,
            1, 8, 1, /* 1856: pointer.struct.dh_st */
            	1861, 0,
            0, 144, 12, /* 1861: struct.dh_st */
            	307, 8,
            	307, 16,
            	307, 32,
            	307, 40,
            	330, 56,
            	307, 64,
            	307, 72,
            	8, 80,
            	307, 96,
            	228, 112,
            	1425, 128,
            	1201, 136,
            1, 8, 1, /* 1888: pointer.struct.ec_key_st.284 */
            	1893, 0,
            0, 56, 4, /* 1893: struct.ec_key_st.284 */
            	1904, 8,
            	2186, 16,
            	307, 24,
            	2202, 48,
            1, 8, 1, /* 1904: pointer.struct.ec_group_st */
            	1909, 0,
            0, 232, 12, /* 1909: struct.ec_group_st */
            	1936, 0,
            	2186, 8,
            	312, 16,
            	312, 40,
            	8, 80,
            	2202, 96,
            	312, 104,
            	312, 152,
            	312, 176,
            	8, 208,
            	8, 216,
            	2236, 224,
            1, 8, 1, /* 1936: pointer.struct.ec_method_st */
            	1941, 0,
            0, 304, 37, /* 1941: struct.ec_method_st */
            	2018, 8,
            	2026, 16,
            	2026, 24,
            	2034, 32,
            	2042, 40,
            	2042, 48,
            	2018, 56,
            	2050, 64,
            	2058, 72,
            	2066, 80,
            	2066, 88,
            	2074, 96,
            	2082, 104,
            	2090, 112,
            	2090, 120,
            	2098, 128,
            	2098, 136,
            	2106, 144,
            	2114, 152,
            	2122, 160,
            	2130, 168,
            	2138, 176,
            	2146, 184,
            	2082, 192,
            	2146, 200,
            	2138, 208,
            	2146, 216,
            	2154, 224,
            	2162, 232,
            	2050, 240,
            	2018, 248,
            	2042, 256,
            	2170, 264,
            	2042, 272,
            	2170, 280,
            	2170, 288,
            	2178, 296,
            1, 8, 1, /* 2018: pointer.func */
            	2023, 0,
            0, 0, 0, /* 2023: func */
            1, 8, 1, /* 2026: pointer.func */
            	2031, 0,
            0, 0, 0, /* 2031: func */
            1, 8, 1, /* 2034: pointer.func */
            	2039, 0,
            0, 0, 0, /* 2039: func */
            1, 8, 1, /* 2042: pointer.func */
            	2047, 0,
            0, 0, 0, /* 2047: func */
            1, 8, 1, /* 2050: pointer.func */
            	2055, 0,
            0, 0, 0, /* 2055: func */
            1, 8, 1, /* 2058: pointer.func */
            	2063, 0,
            0, 0, 0, /* 2063: func */
            1, 8, 1, /* 2066: pointer.func */
            	2071, 0,
            0, 0, 0, /* 2071: func */
            1, 8, 1, /* 2074: pointer.func */
            	2079, 0,
            0, 0, 0, /* 2079: func */
            1, 8, 1, /* 2082: pointer.func */
            	2087, 0,
            0, 0, 0, /* 2087: func */
            1, 8, 1, /* 2090: pointer.func */
            	2095, 0,
            0, 0, 0, /* 2095: func */
            1, 8, 1, /* 2098: pointer.func */
            	2103, 0,
            0, 0, 0, /* 2103: func */
            1, 8, 1, /* 2106: pointer.func */
            	2111, 0,
            0, 0, 0, /* 2111: func */
            1, 8, 1, /* 2114: pointer.func */
            	2119, 0,
            0, 0, 0, /* 2119: func */
            1, 8, 1, /* 2122: pointer.func */
            	2127, 0,
            0, 0, 0, /* 2127: func */
            1, 8, 1, /* 2130: pointer.func */
            	2135, 0,
            0, 0, 0, /* 2135: func */
            1, 8, 1, /* 2138: pointer.func */
            	2143, 0,
            0, 0, 0, /* 2143: func */
            1, 8, 1, /* 2146: pointer.func */
            	2151, 0,
            0, 0, 0, /* 2151: func */
            1, 8, 1, /* 2154: pointer.func */
            	2159, 0,
            0, 0, 0, /* 2159: func */
            1, 8, 1, /* 2162: pointer.func */
            	2167, 0,
            0, 0, 0, /* 2167: func */
            1, 8, 1, /* 2170: pointer.func */
            	2175, 0,
            0, 0, 0, /* 2175: func */
            1, 8, 1, /* 2178: pointer.func */
            	2183, 0,
            0, 0, 0, /* 2183: func */
            1, 8, 1, /* 2186: pointer.struct.ec_point_st */
            	2191, 0,
            0, 88, 4, /* 2191: struct.ec_point_st */
            	1936, 0,
            	312, 8,
            	312, 32,
            	312, 56,
            1, 8, 1, /* 2202: pointer.struct.ec_extra_data_st */
            	2207, 0,
            0, 40, 5, /* 2207: struct.ec_extra_data_st */
            	2202, 0,
            	8, 8,
            	2220, 16,
            	2228, 24,
            	2228, 32,
            1, 8, 1, /* 2220: pointer.func */
            	2225, 0,
            0, 0, 0, /* 2225: func */
            1, 8, 1, /* 2228: pointer.func */
            	2233, 0,
            0, 0, 0, /* 2233: func */
            1, 8, 1, /* 2236: pointer.func */
            	2241, 0,
            0, 0, 0, /* 2241: func */
            1, 8, 1, /* 2244: pointer.struct.ssl_cipher_st */
            	2249, 0,
            0, 88, 1, /* 2249: struct.ssl_cipher_st */
            	8, 8,
            1, 8, 1, /* 2254: pointer.func */
            	64, 0,
            1, 8, 1, /* 2259: pointer.func */
            	45, 0,
            1, 8, 1, /* 2264: pointer.struct.cert_st */
            	2269, 0,
            0, 296, 8, /* 2269: struct.cert_st */
            	872, 0,
            	1809, 48,
            	2288, 56,
            	1856, 64,
            	2293, 72,
            	1888, 80,
            	2301, 88,
            	1790, 96,
            1, 8, 1, /* 2288: pointer.func */
            	273, 0,
            1, 8, 1, /* 2293: pointer.func */
            	2298, 0,
            0, 0, 0, /* 2298: func */
            1, 8, 1, /* 2301: pointer.func */
            	270, 0,
            1, 8, 1, /* 2306: pointer.func */
            	276, 0,
            1, 8, 1, /* 2311: pointer.func */
            	42, 0,
            1, 8, 1, /* 2316: pointer.func */
            	2321, 0,
            0, 0, 0, /* 2321: func */
            1, 8, 1, /* 2324: pointer.func */
            	2329, 0,
            0, 0, 0, /* 2329: func */
            1, 8, 1, /* 2332: pointer.func */
            	2337, 0,
            0, 0, 0, /* 2337: func */
            1, 8, 1, /* 2340: pointer.struct.ssl3_buf_freelist_st */
            	2345, 0,
            0, 24, 1, /* 2345: struct.ssl3_buf_freelist_st */
            	32, 16,
            0, 128, 14, /* 2350: struct.srp_ctx_st */
            	8, 0,
            	2311, 8,
            	2324, 16,
            	24, 24,
            	8, 32,
            	307, 40,
            	307, 48,
            	307, 56,
            	307, 64,
            	307, 72,
            	307, 80,
            	307, 88,
            	307, 96,
            	8, 104,
            1, 8, 1, /* 2381: pointer.func */
            	2386, 0,
            0, 0, 0, /* 2386: func */
            0, 56, 2, /* 2389: struct.comp_ctx_st */
            	2396, 0,
            	228, 40,
            1, 8, 1, /* 2396: pointer.struct.comp_method_st */
            	2401, 0,
            0, 64, 7, /* 2401: struct.comp_method_st */
            	8, 8,
            	2418, 16,
            	2426, 24,
            	2434, 32,
            	2434, 40,
            	709, 48,
            	709, 56,
            1, 8, 1, /* 2418: pointer.func */
            	2423, 0,
            0, 0, 0, /* 2423: func */
            1, 8, 1, /* 2426: pointer.func */
            	2431, 0,
            0, 0, 0, /* 2431: func */
            1, 8, 1, /* 2434: pointer.func */
            	2439, 0,
            0, 0, 0, /* 2439: func */
            0, 168, 4, /* 2442: struct.evp_cipher_ctx_st */
            	2453, 0,
            	1201, 8,
            	8, 96,
            	8, 120,
            1, 8, 1, /* 2453: pointer.struct.evp_cipher_st */
            	2458, 0,
            0, 88, 7, /* 2458: struct.evp_cipher_st */
            	2475, 24,
            	2483, 32,
            	2491, 40,
            	2499, 56,
            	2499, 64,
            	2507, 72,
            	8, 80,
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
            1, 8, 1, /* 2507: pointer.func */
            	2512, 0,
            0, 0, 0, /* 2512: func */
            1, 8, 1, /* 2515: pointer.struct.evp_cipher_ctx_st */
            	2442, 0,
            0, 40, 4, /* 2520: struct.dtls1_retransmit_state */
            	2515, 0,
            	2531, 8,
            	2719, 16,
            	816, 24,
            1, 8, 1, /* 2531: pointer.struct.env_md_ctx_st */
            	2536, 0,
            0, 48, 5, /* 2536: struct.env_md_ctx_st */
            	1710, 0,
            	1201, 8,
            	8, 24,
            	2549, 32,
            	1742, 40,
            1, 8, 1, /* 2549: pointer.struct.evp_pkey_ctx_st */
            	2554, 0,
            0, 80, 8, /* 2554: struct.evp_pkey_ctx_st */
            	2573, 0,
            	1201, 8,
            	1025, 16,
            	1025, 24,
            	8, 40,
            	8, 48,
            	186, 56,
            	317, 64,
            1, 8, 1, /* 2573: pointer.struct.evp_pkey_method_st */
            	2578, 0,
            0, 208, 25, /* 2578: struct.evp_pkey_method_st */
            	186, 8,
            	2631, 16,
            	2639, 24,
            	186, 32,
            	2647, 40,
            	186, 48,
            	2647, 56,
            	186, 64,
            	2655, 72,
            	186, 80,
            	2663, 88,
            	186, 96,
            	2655, 104,
            	2671, 112,
            	2679, 120,
            	2671, 128,
            	2687, 136,
            	186, 144,
            	2655, 152,
            	186, 160,
            	2655, 168,
            	186, 176,
            	2695, 184,
            	2703, 192,
            	2711, 200,
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
            1, 8, 1, /* 2711: pointer.func */
            	2716, 0,
            0, 0, 0, /* 2716: func */
            1, 8, 1, /* 2719: pointer.struct.comp_ctx_st */
            	2389, 0,
            0, 88, 1, /* 2724: struct.hm_header_st */
            	2520, 48,
            0, 24, 2, /* 2729: struct._pitem */
            	8, 8,
            	2736, 16,
            1, 8, 1, /* 2736: pointer.struct._pitem */
            	2729, 0,
            0, 16, 1, /* 2741: struct._pqueue */
            	2736, 0,
            1, 8, 1, /* 2746: pointer.struct._pqueue */
            	2741, 0,
            0, 16, 1, /* 2751: struct.record_pqueue_st */
            	2746, 8,
            0, 16, 0, /* 2756: union.anon.142 */
            1, 8, 1, /* 2759: pointer.struct.dtls1_state_st */
            	2764, 0,
            0, 888, 7, /* 2764: struct.dtls1_state_st */
            	2751, 576,
            	2751, 592,
            	2746, 608,
            	2746, 616,
            	2751, 624,
            	2724, 648,
            	2724, 736,
            0, 24, 2, /* 2781: struct.ssl_comp_st */
            	8, 8,
            	2396, 16,
            0, 9, 0, /* 2788: array[9].char */
            0, 128, 0, /* 2791: array[128].char */
            0, 20, 0, /* 2794: array[5].int */
            0, 528, 8, /* 2797: struct.anon.0 */
            	2244, 408,
            	1856, 416,
            	1888, 424,
            	136, 464,
            	8, 480,
            	2453, 488,
            	1710, 496,
            	2816, 512,
            1, 8, 1, /* 2816: pointer.struct.ssl_comp_st */
            	2781, 0,
            1, 8, 1, /* 2821: pointer.pointer.struct.env_md_ctx_st */
            	2531, 0,
            0, 1200, 10, /* 2826: struct.ssl3_state_st */
            	2849, 240,
            	2849, 264,
            	2854, 288,
            	2854, 344,
            	8, 432,
            	2863, 440,
            	2821, 448,
            	8, 496,
            	8, 512,
            	2797, 528,
            0, 24, 1, /* 2849: struct.ssl3_buffer_st */
            	8, 0,
            0, 56, 3, /* 2854: struct.ssl3_record_st */
            	8, 16,
            	8, 24,
            	8, 32,
            1, 8, 1, /* 2863: pointer.struct.bio_st */
            	2868, 0,
            0, 112, 7, /* 2868: struct.bio_st */
            	2885, 0,
            	2951, 8,
            	8, 16,
            	8, 48,
            	2863, 56,
            	2863, 64,
            	228, 96,
            1, 8, 1, /* 2885: pointer.struct.bio_method_st */
            	2890, 0,
            0, 80, 9, /* 2890: struct.bio_method_st */
            	8, 8,
            	2911, 16,
            	2911, 24,
            	2919, 32,
            	2911, 40,
            	2927, 48,
            	2935, 56,
            	2935, 64,
            	2943, 72,
            1, 8, 1, /* 2911: pointer.func */
            	2916, 0,
            0, 0, 0, /* 2916: func */
            1, 8, 1, /* 2919: pointer.func */
            	2924, 0,
            0, 0, 0, /* 2924: func */
            1, 8, 1, /* 2927: pointer.func */
            	2932, 0,
            0, 0, 0, /* 2932: func */
            1, 8, 1, /* 2935: pointer.func */
            	2940, 0,
            0, 0, 0, /* 2940: func */
            1, 8, 1, /* 2943: pointer.func */
            	2948, 0,
            0, 0, 0, /* 2948: func */
            1, 8, 1, /* 2951: pointer.func */
            	2956, 0,
            0, 0, 0, /* 2956: func */
            1, 8, 1, /* 2959: pointer.struct.ssl3_state_st */
            	2826, 0,
            0, 344, 9, /* 2964: struct.ssl2_state_st */
            	8, 24,
            	8, 56,
            	8, 64,
            	8, 72,
            	8, 104,
            	8, 112,
            	8, 120,
            	8, 128,
            	8, 136,
            1, 8, 1, /* 2985: pointer.struct.ssl2_state_st */
            	2964, 0,
            0, 4, 0, /* 2990: array[4].char */
            0, 32, 0, /* 2993: array[32].char */
            0, 8, 0, /* 2996: array[8].char */
            0, 72, 0, /* 2999: struct.anon.25 */
            1, 8, 1, /* 3002: pointer.struct.ssl_st */
            	3007, 0,
            0, 808, 51, /* 3007: struct.ssl_st */
            	541, 8,
            	2863, 16,
            	2863, 24,
            	2863, 32,
            	186, 48,
            	989, 80,
            	8, 88,
            	8, 104,
            	2985, 120,
            	2959, 128,
            	2759, 136,
            	2306, 152,
            	8, 160,
            	166, 176,
            	136, 184,
            	136, 192,
            	2515, 208,
            	2531, 216,
            	2719, 224,
            	2515, 232,
            	2531, 240,
            	2719, 248,
            	2264, 256,
            	816, 304,
            	262, 312,
            	249, 328,
            	241, 336,
            	233, 352,
            	755, 360,
            	433, 368,
            	228, 392,
            	136, 408,
            	51, 464,
            	8, 472,
            	8, 480,
            	136, 504,
            	136, 512,
            	8, 520,
            	8, 544,
            	8, 560,
            	8, 568,
            	3112, 584,
            	763, 592,
            	8, 600,
            	257, 608,
            	8, 616,
            	433, 624,
            	8, 632,
            	136, 648,
            	3117, 656,
            	2350, 680,
            1, 8, 1, /* 3112: pointer.struct.tls_session_ticket_ext_st */
            	3, 0,
            1, 8, 1, /* 3117: pointer.struct.iovec */
            	325, 0,
            0, 8, 0, /* 3122: array[2].int */
            0, 24, 0, /* 3125: array[6].int */
            0, 8, 0, /* 3128: long */
            0, 2, 0, /* 3131: array[2].char */
            0, 48, 0, /* 3134: array[48].char */
            0, 16, 0, /* 3137: array[16].char */
            0, 64, 0, /* 3140: array[64].char */
            0, 256, 0, /* 3143: array[256].char */
            0, 20, 0, /* 3146: array[20].char */
            0, 2, 0, /* 3149: short */
        },
        .arg_entity_index = { 3002, },
        .ret_entity_index = 8,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    SSL * new_arg_a = *((SSL * *)new_args->args[0]);

    char * *new_ret_ptr = (char * *)new_args->ret;

    char * (*orig_SSL_get_srp_username)(SSL *);
    orig_SSL_get_srp_username = dlsym(RTLD_NEXT, "SSL_get_srp_username");
    *new_ret_ptr = (*orig_SSL_get_srp_username)(new_arg_a);

    syscall(889);

    return ret;
}

