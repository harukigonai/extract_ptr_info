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

void SSL_CTX_sess_set_remove_cb(SSL_CTX * arg_a,void (*arg_b)(struct ssl_ctx_st *,SSL_SESSION *)) 
{
    struct lib_enter_args args = {
        .entity_metadata = {
            0, 0, 0, /* 0: func */
            0, 0, 0, /* 3: func */
            1, 8, 1, /* 6: pointer.func */
            	3, 0,
            1, 8, 1, /* 11: pointer.func */
            	16, 0,
            0, 0, 0, /* 16: func */
            0, 128, 16, /* 19: struct.srp_ctx_st.921 */
            	54, 0,
            	62, 8,
            	70, 16,
            	11, 24,
            	54, 32,
            	78, 40,
            	78, 48,
            	78, 56,
            	78, 64,
            	78, 72,
            	78, 80,
            	78, 88,
            	78, 96,
            	54, 104,
            	101, 112,
            	104, 120,
            1, 8, 1, /* 54: pointer.char */
            	59, 0,
            0, 1, 0, /* 59: char */
            1, 8, 1, /* 62: pointer.func */
            	67, 0,
            0, 0, 0, /* 67: func */
            1, 8, 1, /* 70: pointer.func */
            	75, 0,
            0, 0, 0, /* 75: func */
            1, 8, 1, /* 78: pointer.struct.bignum_st */
            	83, 0,
            0, 24, 5, /* 83: struct.bignum_st */
            	96, 0,
            	101, 8,
            	101, 12,
            	101, 16,
            	101, 20,
            1, 8, 1, /* 96: pointer.int */
            	101, 0,
            0, 4, 0, /* 101: int */
            0, 8, 0, /* 104: long */
            1, 8, 1, /* 107: pointer.struct.ssl3_buf_freelist_entry_st */
            	112, 0,
            0, 8, 1, /* 112: struct.ssl3_buf_freelist_entry_st */
            	107, 0,
            0, 0, 0, /* 117: func */
            0, 16, 16, /* 120: array[16].char */
            	59, 0,
            	59, 1,
            	59, 2,
            	59, 3,
            	59, 4,
            	59, 5,
            	59, 6,
            	59, 7,
            	59, 8,
            	59, 9,
            	59, 10,
            	59, 11,
            	59, 12,
            	59, 13,
            	59, 14,
            	59, 15,
            1, 8, 1, /* 155: pointer.func */
            	160, 0,
            0, 0, 0, /* 160: func */
            0, 0, 0, /* 163: func */
            0, 0, 0, /* 166: func */
            0, 0, 0, /* 169: func */
            1, 8, 1, /* 172: pointer.func */
            	169, 0,
            0, 296, 14, /* 177: struct.cert_st.915 */
            	208, 0,
            	101, 8,
            	104, 16,
            	104, 24,
            	104, 32,
            	104, 40,
            	1419, 48,
            	172, 56,
            	1531, 64,
            	1575, 72,
            	1580, 80,
            	1979, 88,
            	1984, 96,
            	101, 288,
            1, 8, 1, /* 208: pointer.struct.cert_pkey_st */
            	213, 0,
            0, 24, 3, /* 213: struct.cert_pkey_st */
            	222, 0,
            	461, 8,
            	1312, 16,
            1, 8, 1, /* 222: pointer.struct.x509_st */
            	227, 0,
            0, 184, 21, /* 227: struct.x509_st */
            	272, 0,
            	318, 8,
            	302, 16,
            	101, 24,
            	101, 28,
            	54, 32,
            	1175, 40,
            	104, 56,
            	104, 64,
            	104, 72,
            	104, 80,
            	104, 88,
            	104, 96,
            	302, 104,
            	1191, 112,
            	1205, 120,
            	385, 128,
            	385, 136,
            	1239, 144,
            	1251, 152,
            	1294, 176,
            1, 8, 1, /* 272: pointer.struct.x509_cinf_st */
            	277, 0,
            0, 104, 11, /* 277: struct.x509_cinf_st */
            	302, 0,
            	302, 8,
            	318, 16,
            	367, 24,
            	435, 32,
            	367, 40,
            	447, 48,
            	302, 56,
            	302, 64,
            	385, 72,
            	1182, 80,
            1, 8, 1, /* 302: pointer.struct.asn1_string_st */
            	307, 0,
            0, 24, 4, /* 307: struct.asn1_string_st */
            	101, 0,
            	101, 4,
            	54, 8,
            	104, 16,
            1, 8, 1, /* 318: pointer.struct.X509_algor_st */
            	323, 0,
            0, 16, 2, /* 323: struct.X509_algor_st */
            	330, 0,
            	350, 8,
            1, 8, 1, /* 330: pointer.struct.asn1_object_st */
            	335, 0,
            0, 40, 6, /* 335: struct.asn1_object_st */
            	54, 0,
            	54, 8,
            	101, 16,
            	101, 20,
            	54, 24,
            	101, 32,
            1, 8, 1, /* 350: pointer.struct.asn1_type_st */
            	355, 0,
            0, 16, 2, /* 355: struct.asn1_type_st */
            	101, 0,
            	362, 8,
            0, 8, 1, /* 362: struct.fnames */
            	54, 0,
            1, 8, 1, /* 367: pointer.struct.X509_name_st */
            	372, 0,
            0, 40, 5, /* 372: struct.X509_name_st */
            	385, 0,
            	101, 8,
            	421, 16,
            	54, 24,
            	101, 32,
            1, 8, 1, /* 385: pointer.struct.stack_st_OPENSSL_STRING */
            	390, 0,
            0, 32, 1, /* 390: struct.stack_st_OPENSSL_STRING */
            	395, 0,
            0, 32, 5, /* 395: struct.stack_st */
            	101, 0,
            	408, 8,
            	101, 16,
            	101, 20,
            	413, 24,
            1, 8, 1, /* 408: pointer.pointer.char */
            	54, 0,
            1, 8, 1, /* 413: pointer.func */
            	418, 0,
            0, 0, 0, /* 418: func */
            1, 8, 1, /* 421: pointer.struct.buf_mem_st */
            	426, 0,
            0, 24, 3, /* 426: struct.buf_mem_st */
            	104, 0,
            	54, 8,
            	104, 16,
            1, 8, 1, /* 435: pointer.struct.X509_val_st */
            	440, 0,
            0, 16, 2, /* 440: struct.X509_val_st */
            	302, 0,
            	302, 8,
            1, 8, 1, /* 447: pointer.struct.X509_pubkey_st */
            	452, 0,
            0, 24, 3, /* 452: struct.X509_pubkey_st */
            	318, 0,
            	302, 8,
            	461, 16,
            1, 8, 1, /* 461: pointer.struct.evp_pkey_st */
            	466, 0,
            0, 56, 8, /* 466: struct.evp_pkey_st */
            	101, 0,
            	101, 4,
            	101, 8,
            	485, 16,
            	659, 24,
            	362, 32,
            	101, 40,
            	385, 48,
            1, 8, 1, /* 485: pointer.struct.evp_pkey_asn1_method_st */
            	490, 0,
            0, 208, 27, /* 490: struct.evp_pkey_asn1_method_st */
            	101, 0,
            	101, 4,
            	104, 8,
            	54, 16,
            	54, 24,
            	547, 32,
            	555, 40,
            	563, 48,
            	571, 56,
            	579, 64,
            	587, 72,
            	571, 80,
            	595, 88,
            	595, 96,
            	603, 104,
            	611, 112,
            	595, 120,
            	563, 128,
            	563, 136,
            	571, 144,
            	619, 152,
            	627, 160,
            	635, 168,
            	603, 176,
            	611, 184,
            	643, 192,
            	651, 200,
            1, 8, 1, /* 547: pointer.struct.unnamed */
            	552, 0,
            0, 0, 0, /* 552: struct.unnamed */
            1, 8, 1, /* 555: pointer.func */
            	560, 0,
            0, 0, 0, /* 560: func */
            1, 8, 1, /* 563: pointer.func */
            	568, 0,
            0, 0, 0, /* 568: func */
            1, 8, 1, /* 571: pointer.func */
            	576, 0,
            0, 0, 0, /* 576: func */
            1, 8, 1, /* 579: pointer.func */
            	584, 0,
            0, 0, 0, /* 584: func */
            1, 8, 1, /* 587: pointer.func */
            	592, 0,
            0, 0, 0, /* 592: func */
            1, 8, 1, /* 595: pointer.func */
            	600, 0,
            0, 0, 0, /* 600: func */
            1, 8, 1, /* 603: pointer.func */
            	608, 0,
            0, 0, 0, /* 608: func */
            1, 8, 1, /* 611: pointer.func */
            	616, 0,
            0, 0, 0, /* 616: func */
            1, 8, 1, /* 619: pointer.func */
            	624, 0,
            0, 0, 0, /* 624: func */
            1, 8, 1, /* 627: pointer.func */
            	632, 0,
            0, 0, 0, /* 632: func */
            1, 8, 1, /* 635: pointer.func */
            	640, 0,
            0, 0, 0, /* 640: func */
            1, 8, 1, /* 643: pointer.func */
            	648, 0,
            0, 0, 0, /* 648: func */
            1, 8, 1, /* 651: pointer.func */
            	656, 0,
            0, 0, 0, /* 656: func */
            1, 8, 1, /* 659: pointer.struct.engine_st */
            	664, 0,
            0, 216, 27, /* 664: struct.engine_st */
            	54, 0,
            	54, 8,
            	721, 16,
            	813, 24,
            	901, 32,
            	959, 40,
            	983, 48,
            	1027, 56,
            	1087, 64,
            	1095, 72,
            	1103, 80,
            	1111, 88,
            	1119, 96,
            	1127, 104,
            	1127, 112,
            	1127, 120,
            	1135, 128,
            	1143, 136,
            	1143, 144,
            	1151, 152,
            	1159, 160,
            	101, 168,
            	101, 172,
            	101, 176,
            	1175, 184,
            	659, 200,
            	659, 208,
            1, 8, 1, /* 721: pointer.struct.rsa_meth_st */
            	726, 0,
            0, 112, 14, /* 726: struct.rsa_meth_st */
            	54, 0,
            	757, 8,
            	757, 16,
            	757, 24,
            	757, 32,
            	765, 40,
            	773, 48,
            	781, 56,
            	781, 64,
            	101, 72,
            	54, 80,
            	789, 88,
            	797, 96,
            	805, 104,
            1, 8, 1, /* 757: pointer.func */
            	762, 0,
            0, 0, 0, /* 762: func */
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
            1, 8, 1, /* 797: pointer.func */
            	802, 0,
            0, 0, 0, /* 802: func */
            1, 8, 1, /* 805: pointer.func */
            	810, 0,
            0, 0, 0, /* 810: func */
            1, 8, 1, /* 813: pointer.struct.dsa_method.1040 */
            	818, 0,
            0, 96, 12, /* 818: struct.dsa_method.1040 */
            	54, 0,
            	845, 8,
            	853, 16,
            	861, 24,
            	869, 32,
            	877, 40,
            	885, 48,
            	885, 56,
            	101, 64,
            	54, 72,
            	893, 80,
            	885, 88,
            1, 8, 1, /* 845: pointer.func */
            	850, 0,
            0, 0, 0, /* 850: func */
            1, 8, 1, /* 853: pointer.func */
            	858, 0,
            0, 0, 0, /* 858: func */
            1, 8, 1, /* 861: pointer.func */
            	866, 0,
            0, 0, 0, /* 866: func */
            1, 8, 1, /* 869: pointer.func */
            	874, 0,
            0, 0, 0, /* 874: func */
            1, 8, 1, /* 877: pointer.func */
            	882, 0,
            0, 0, 0, /* 882: func */
            1, 8, 1, /* 885: pointer.func */
            	890, 0,
            0, 0, 0, /* 890: func */
            1, 8, 1, /* 893: pointer.func */
            	898, 0,
            0, 0, 0, /* 898: func */
            1, 8, 1, /* 901: pointer.struct.dh_method */
            	906, 0,
            0, 72, 9, /* 906: struct.dh_method */
            	54, 0,
            	927, 8,
            	935, 16,
            	943, 24,
            	927, 32,
            	927, 40,
            	101, 48,
            	54, 56,
            	951, 64,
            1, 8, 1, /* 927: pointer.func */
            	932, 0,
            0, 0, 0, /* 932: func */
            1, 8, 1, /* 935: pointer.func */
            	940, 0,
            0, 0, 0, /* 940: func */
            1, 8, 1, /* 943: pointer.func */
            	948, 0,
            0, 0, 0, /* 948: func */
            1, 8, 1, /* 951: pointer.func */
            	956, 0,
            0, 0, 0, /* 956: func */
            1, 8, 1, /* 959: pointer.struct.ecdh_method */
            	964, 0,
            0, 32, 4, /* 964: struct.ecdh_method */
            	54, 0,
            	975, 8,
            	101, 16,
            	54, 24,
            1, 8, 1, /* 975: pointer.func */
            	980, 0,
            0, 0, 0, /* 980: func */
            1, 8, 1, /* 983: pointer.struct.ecdsa_method */
            	988, 0,
            0, 48, 6, /* 988: struct.ecdsa_method */
            	54, 0,
            	1003, 8,
            	1011, 16,
            	1019, 24,
            	101, 32,
            	54, 40,
            1, 8, 1, /* 1003: pointer.func */
            	1008, 0,
            0, 0, 0, /* 1008: func */
            1, 8, 1, /* 1011: pointer.func */
            	1016, 0,
            0, 0, 0, /* 1016: func */
            1, 8, 1, /* 1019: pointer.func */
            	1024, 0,
            0, 0, 0, /* 1024: func */
            1, 8, 1, /* 1027: pointer.struct.rand_meth_st */
            	1032, 0,
            0, 48, 6, /* 1032: struct.rand_meth_st */
            	1047, 0,
            	1055, 8,
            	1063, 16,
            	1071, 24,
            	1055, 32,
            	1079, 40,
            1, 8, 1, /* 1047: pointer.func */
            	1052, 0,
            0, 0, 0, /* 1052: func */
            1, 8, 1, /* 1055: pointer.func */
            	1060, 0,
            0, 0, 0, /* 1060: func */
            1, 8, 1, /* 1063: pointer.func */
            	1068, 0,
            0, 0, 0, /* 1068: func */
            1, 8, 1, /* 1071: pointer.func */
            	1076, 0,
            0, 0, 0, /* 1076: func */
            1, 8, 1, /* 1079: pointer.func */
            	1084, 0,
            0, 0, 0, /* 1084: func */
            1, 8, 1, /* 1087: pointer.struct.store_method_st */
            	1092, 0,
            0, 0, 0, /* 1092: struct.store_method_st */
            1, 8, 1, /* 1095: pointer.func */
            	1100, 0,
            0, 0, 0, /* 1100: func */
            1, 8, 1, /* 1103: pointer.func */
            	1108, 0,
            0, 0, 0, /* 1108: func */
            1, 8, 1, /* 1111: pointer.func */
            	1116, 0,
            0, 0, 0, /* 1116: func */
            1, 8, 1, /* 1119: pointer.func */
            	1124, 0,
            0, 0, 0, /* 1124: func */
            1, 8, 1, /* 1127: pointer.func */
            	1132, 0,
            0, 0, 0, /* 1132: func */
            1, 8, 1, /* 1135: pointer.func */
            	1140, 0,
            0, 0, 0, /* 1140: func */
            1, 8, 1, /* 1143: pointer.func */
            	1148, 0,
            0, 0, 0, /* 1148: func */
            1, 8, 1, /* 1151: pointer.func */
            	1156, 0,
            0, 0, 0, /* 1156: func */
            1, 8, 1, /* 1159: pointer.struct.ENGINE_CMD_DEFN_st */
            	1164, 0,
            0, 32, 4, /* 1164: struct.ENGINE_CMD_DEFN_st */
            	101, 0,
            	54, 8,
            	54, 16,
            	101, 24,
            0, 16, 2, /* 1175: struct.crypto_ex_data_st */
            	385, 0,
            	101, 8,
            0, 24, 3, /* 1182: struct.ASN1_ENCODING_st */
            	54, 0,
            	104, 8,
            	101, 16,
            1, 8, 1, /* 1191: pointer.struct.AUTHORITY_KEYID_st */
            	1196, 0,
            0, 24, 3, /* 1196: struct.AUTHORITY_KEYID_st */
            	302, 0,
            	385, 8,
            	302, 16,
            1, 8, 1, /* 1205: pointer.struct.X509_POLICY_CACHE_st */
            	1210, 0,
            0, 40, 5, /* 1210: struct.X509_POLICY_CACHE_st */
            	1223, 0,
            	385, 8,
            	104, 16,
            	104, 24,
            	104, 32,
            1, 8, 1, /* 1223: pointer.struct.X509_POLICY_DATA_st */
            	1228, 0,
            0, 32, 4, /* 1228: struct.X509_POLICY_DATA_st */
            	101, 0,
            	330, 8,
            	385, 16,
            	385, 24,
            1, 8, 1, /* 1239: pointer.struct.NAME_CONSTRAINTS_st */
            	1244, 0,
            0, 16, 2, /* 1244: struct.NAME_CONSTRAINTS_st */
            	385, 0,
            	385, 8,
            0, 20, 20, /* 1251: array[20].char */
            	59, 0,
            	59, 1,
            	59, 2,
            	59, 3,
            	59, 4,
            	59, 5,
            	59, 6,
            	59, 7,
            	59, 8,
            	59, 9,
            	59, 10,
            	59, 11,
            	59, 12,
            	59, 13,
            	59, 14,
            	59, 15,
            	59, 16,
            	59, 17,
            	59, 18,
            	59, 19,
            1, 8, 1, /* 1294: pointer.struct.x509_cert_aux_st */
            	1299, 0,
            0, 40, 5, /* 1299: struct.x509_cert_aux_st */
            	385, 0,
            	385, 8,
            	302, 16,
            	302, 24,
            	385, 32,
            1, 8, 1, /* 1312: pointer.struct.env_md_st */
            	1317, 0,
            0, 120, 15, /* 1317: struct.env_md_st */
            	101, 0,
            	101, 4,
            	101, 8,
            	104, 16,
            	1350, 24,
            	1358, 32,
            	1366, 40,
            	1374, 48,
            	1350, 56,
            	1382, 64,
            	1390, 72,
            	1398, 80,
            	101, 100,
            	101, 104,
            	1411, 112,
            1, 8, 1, /* 1350: pointer.func */
            	1355, 0,
            0, 0, 0, /* 1355: func */
            1, 8, 1, /* 1358: pointer.func */
            	1363, 0,
            0, 0, 0, /* 1363: func */
            1, 8, 1, /* 1366: pointer.func */
            	1371, 0,
            0, 0, 0, /* 1371: func */
            1, 8, 1, /* 1374: pointer.func */
            	1379, 0,
            0, 0, 0, /* 1379: func */
            1, 8, 1, /* 1382: pointer.func */
            	1387, 0,
            0, 0, 0, /* 1387: func */
            1, 8, 1, /* 1390: pointer.func */
            	1395, 0,
            0, 0, 0, /* 1395: func */
            0, 20, 5, /* 1398: array[5].int */
            	101, 0,
            	101, 4,
            	101, 8,
            	101, 12,
            	101, 16,
            1, 8, 1, /* 1411: pointer.func */
            	1416, 0,
            0, 0, 0, /* 1416: func */
            1, 8, 1, /* 1419: pointer.struct.rsa_st */
            	1424, 0,
            0, 168, 21, /* 1424: struct.rsa_st */
            	101, 0,
            	104, 8,
            	721, 16,
            	659, 24,
            	78, 32,
            	78, 40,
            	78, 48,
            	78, 56,
            	78, 64,
            	78, 72,
            	78, 80,
            	78, 88,
            	1175, 96,
            	101, 112,
            	101, 116,
            	1469, 120,
            	1469, 128,
            	1469, 136,
            	54, 144,
            	1496, 152,
            	1496, 160,
            1, 8, 1, /* 1469: pointer.struct.bn_mont_ctx_st */
            	1474, 0,
            0, 96, 6, /* 1474: struct.bn_mont_ctx_st */
            	101, 0,
            	83, 8,
            	83, 32,
            	83, 56,
            	1489, 80,
            	101, 88,
            0, 8, 2, /* 1489: array[2].int */
            	101, 0,
            	101, 4,
            1, 8, 1, /* 1496: pointer.struct.bn_blinding_st */
            	1501, 0,
            0, 88, 10, /* 1501: struct.bn_blinding_st */
            	78, 0,
            	78, 8,
            	78, 16,
            	78, 24,
            	104, 32,
            	1524, 40,
            	101, 56,
            	104, 64,
            	1469, 72,
            	773, 80,
            0, 16, 2, /* 1524: struct.iovec */
            	54, 0,
            	104, 8,
            1, 8, 1, /* 1531: pointer.struct.dh_st */
            	1536, 0,
            0, 144, 18, /* 1536: struct.dh_st */
            	101, 0,
            	101, 4,
            	78, 8,
            	78, 16,
            	104, 24,
            	78, 32,
            	78, 40,
            	101, 48,
            	1469, 56,
            	78, 64,
            	78, 72,
            	54, 80,
            	101, 88,
            	78, 96,
            	101, 104,
            	1175, 112,
            	901, 128,
            	659, 136,
            1, 8, 1, /* 1575: pointer.func */
            	166, 0,
            1, 8, 1, /* 1580: pointer.struct.ec_key_st.284 */
            	1585, 0,
            0, 56, 9, /* 1585: struct.ec_key_st.284 */
            	101, 0,
            	1606, 8,
            	1904, 16,
            	78, 24,
            	101, 32,
            	101, 36,
            	101, 40,
            	101, 44,
            	1922, 48,
            1, 8, 1, /* 1606: pointer.struct.ec_group_st */
            	1611, 0,
            0, 232, 18, /* 1611: struct.ec_group_st */
            	1650, 0,
            	1904, 8,
            	83, 16,
            	83, 40,
            	101, 64,
            	101, 68,
            	101, 72,
            	54, 80,
            	104, 88,
            	1922, 96,
            	83, 104,
            	1956, 128,
            	83, 152,
            	83, 176,
            	101, 200,
            	54, 208,
            	54, 216,
            	1971, 224,
            1, 8, 1, /* 1650: pointer.struct.ec_method_st */
            	1655, 0,
            0, 304, 39, /* 1655: struct.ec_method_st */
            	101, 0,
            	101, 4,
            	1736, 8,
            	1744, 16,
            	1744, 24,
            	1752, 32,
            	1760, 40,
            	1760, 48,
            	1736, 56,
            	1768, 64,
            	1776, 72,
            	1784, 80,
            	1784, 88,
            	1792, 96,
            	1800, 104,
            	1808, 112,
            	1808, 120,
            	1816, 128,
            	1816, 136,
            	1824, 144,
            	1832, 152,
            	1840, 160,
            	1848, 168,
            	1856, 176,
            	1864, 184,
            	1800, 192,
            	1864, 200,
            	1856, 208,
            	1864, 216,
            	1872, 224,
            	1880, 232,
            	1768, 240,
            	1736, 248,
            	1760, 256,
            	1888, 264,
            	1760, 272,
            	1888, 280,
            	1888, 288,
            	1896, 296,
            1, 8, 1, /* 1736: pointer.func */
            	1741, 0,
            0, 0, 0, /* 1741: func */
            1, 8, 1, /* 1744: pointer.func */
            	1749, 0,
            0, 0, 0, /* 1749: func */
            1, 8, 1, /* 1752: pointer.func */
            	1757, 0,
            0, 0, 0, /* 1757: func */
            1, 8, 1, /* 1760: pointer.func */
            	1765, 0,
            0, 0, 0, /* 1765: func */
            1, 8, 1, /* 1768: pointer.func */
            	1773, 0,
            0, 0, 0, /* 1773: func */
            1, 8, 1, /* 1776: pointer.func */
            	1781, 0,
            0, 0, 0, /* 1781: func */
            1, 8, 1, /* 1784: pointer.func */
            	1789, 0,
            0, 0, 0, /* 1789: func */
            1, 8, 1, /* 1792: pointer.func */
            	1797, 0,
            0, 0, 0, /* 1797: func */
            1, 8, 1, /* 1800: pointer.func */
            	1805, 0,
            0, 0, 0, /* 1805: func */
            1, 8, 1, /* 1808: pointer.func */
            	1813, 0,
            0, 0, 0, /* 1813: func */
            1, 8, 1, /* 1816: pointer.func */
            	1821, 0,
            0, 0, 0, /* 1821: func */
            1, 8, 1, /* 1824: pointer.func */
            	1829, 0,
            0, 0, 0, /* 1829: func */
            1, 8, 1, /* 1832: pointer.func */
            	1837, 0,
            0, 0, 0, /* 1837: func */
            1, 8, 1, /* 1840: pointer.func */
            	1845, 0,
            0, 0, 0, /* 1845: func */
            1, 8, 1, /* 1848: pointer.func */
            	1853, 0,
            0, 0, 0, /* 1853: func */
            1, 8, 1, /* 1856: pointer.func */
            	1861, 0,
            0, 0, 0, /* 1861: func */
            1, 8, 1, /* 1864: pointer.func */
            	1869, 0,
            0, 0, 0, /* 1869: func */
            1, 8, 1, /* 1872: pointer.func */
            	1877, 0,
            0, 0, 0, /* 1877: func */
            1, 8, 1, /* 1880: pointer.func */
            	1885, 0,
            0, 0, 0, /* 1885: func */
            1, 8, 1, /* 1888: pointer.func */
            	1893, 0,
            0, 0, 0, /* 1893: func */
            1, 8, 1, /* 1896: pointer.func */
            	1901, 0,
            0, 0, 0, /* 1901: func */
            1, 8, 1, /* 1904: pointer.struct.ec_point_st */
            	1909, 0,
            0, 88, 5, /* 1909: struct.ec_point_st */
            	1650, 0,
            	83, 8,
            	83, 32,
            	83, 56,
            	101, 80,
            1, 8, 1, /* 1922: pointer.struct.ec_extra_data_st */
            	1927, 0,
            0, 40, 5, /* 1927: struct.ec_extra_data_st */
            	1922, 0,
            	54, 8,
            	1940, 16,
            	1948, 24,
            	1948, 32,
            1, 8, 1, /* 1940: pointer.func */
            	1945, 0,
            0, 0, 0, /* 1945: func */
            1, 8, 1, /* 1948: pointer.func */
            	1953, 0,
            0, 0, 0, /* 1953: func */
            0, 24, 6, /* 1956: array[6].int */
            	101, 0,
            	101, 4,
            	101, 8,
            	101, 12,
            	101, 16,
            	101, 20,
            1, 8, 1, /* 1971: pointer.func */
            	1976, 0,
            0, 0, 0, /* 1976: func */
            1, 8, 1, /* 1979: pointer.func */
            	163, 0,
            0, 192, 8, /* 1984: array[8].struct.cert_pkey_st */
            	213, 0,
            	213, 24,
            	213, 48,
            	213, 72,
            	213, 96,
            	213, 120,
            	213, 144,
            	213, 168,
            1, 8, 1, /* 2003: pointer.struct.cert_st.915 */
            	177, 0,
            1, 8, 1, /* 2008: pointer.func */
            	2013, 0,
            0, 0, 0, /* 2013: func */
            0, 0, 0, /* 2016: func */
            1, 8, 1, /* 2019: pointer.func */
            	2016, 0,
            0, 0, 0, /* 2024: func */
            1, 8, 1, /* 2027: pointer.func */
            	2024, 0,
            0, 0, 0, /* 2032: func */
            1, 8, 1, /* 2035: pointer.func */
            	2032, 0,
            0, 44, 11, /* 2040: struct.apr_time_exp_t */
            	101, 0,
            	101, 4,
            	101, 8,
            	101, 12,
            	101, 16,
            	101, 20,
            	101, 24,
            	101, 28,
            	101, 32,
            	101, 36,
            	101, 40,
            0, 0, 0, /* 2065: func */
            1, 8, 1, /* 2068: pointer.func */
            	2065, 0,
            0, 0, 0, /* 2073: func */
            1, 8, 1, /* 2076: pointer.func */
            	2073, 0,
            1, 8, 1, /* 2081: pointer.func */
            	2086, 0,
            0, 0, 0, /* 2086: func */
            1, 8, 1, /* 2089: pointer.struct.ssl_cipher_st */
            	2094, 0,
            0, 88, 12, /* 2094: struct.ssl_cipher_st */
            	101, 0,
            	54, 8,
            	104, 16,
            	104, 24,
            	104, 32,
            	104, 40,
            	104, 48,
            	104, 56,
            	104, 64,
            	104, 72,
            	101, 80,
            	101, 84,
            1, 8, 1, /* 2121: pointer.func */
            	2126, 0,
            0, 0, 0, /* 2126: func */
            1, 8, 1, /* 2129: pointer.func */
            	117, 0,
            1, 8, 1, /* 2134: pointer.func */
            	2139, 0,
            0, 0, 0, /* 2139: func */
            1, 8, 1, /* 2142: pointer.func */
            	0, 0,
            0, 0, 0, /* 2147: func */
            0, 4, 1, /* 2150: struct.in_addr */
            	101, 0,
            0, 248, 8, /* 2155: struct.sess_cert_st */
            	385, 0,
            	101, 8,
            	208, 16,
            	1984, 24,
            	1419, 216,
            	1531, 224,
            	1580, 232,
            	101, 240,
            1, 8, 1, /* 2174: pointer.struct.in_addr */
            	2150, 0,
            1, 8, 1, /* 2179: pointer.func */
            	2184, 0,
            0, 0, 0, /* 2184: func */
            0, 0, 0, /* 2187: func */
            1, 8, 1, /* 2190: pointer.func */
            	2187, 0,
            1, 8, 1, /* 2195: pointer.func */
            	2200, 0,
            0, 0, 0, /* 2200: func */
            0, 0, 0, /* 2203: func */
            1, 8, 1, /* 2206: pointer.func */
            	2203, 0,
            1, 8, 1, /* 2211: pointer.func */
            	2216, 0,
            0, 0, 0, /* 2216: func */
            0, 8, 8, /* 2219: array[8].char */
            	59, 0,
            	59, 1,
            	59, 2,
            	59, 3,
            	59, 4,
            	59, 5,
            	59, 6,
            	59, 7,
            1, 8, 1, /* 2238: pointer.func */
            	2243, 0,
            0, 0, 0, /* 2243: func */
            0, 0, 0, /* 2246: func */
            1, 8, 1, /* 2249: pointer.func */
            	2254, 0,
            0, 0, 0, /* 2254: func */
            0, 56, 8, /* 2257: struct.X509_VERIFY_PARAM_st */
            	54, 0,
            	104, 8,
            	104, 16,
            	104, 24,
            	101, 32,
            	101, 36,
            	101, 40,
            	385, 48,
            1, 8, 1, /* 2276: pointer.struct.X509_VERIFY_PARAM_st */
            	2257, 0,
            0, 144, 17, /* 2281: struct.x509_store_st */
            	101, 0,
            	385, 8,
            	385, 16,
            	2276, 24,
            	2318, 32,
            	2326, 40,
            	2249, 48,
            	2238, 56,
            	2318, 64,
            	2211, 72,
            	2206, 80,
            	2195, 88,
            	2190, 96,
            	2190, 104,
            	2318, 112,
            	1175, 120,
            	101, 136,
            1, 8, 1, /* 2318: pointer.func */
            	2323, 0,
            0, 0, 0, /* 2323: func */
            1, 8, 1, /* 2326: pointer.func */
            	2331, 0,
            0, 0, 0, /* 2331: func */
            1, 8, 1, /* 2334: pointer.struct.x509_store_st */
            	2281, 0,
            0, 0, 0, /* 2339: func */
            1, 8, 1, /* 2342: pointer.func */
            	2347, 0,
            0, 0, 0, /* 2347: func */
            0, 0, 0, /* 2350: func */
            1, 8, 1, /* 2353: pointer.func */
            	2350, 0,
            0, 0, 0, /* 2358: func */
            1, 8, 1, /* 2361: pointer.func */
            	2366, 0,
            0, 0, 0, /* 2366: func */
            0, 736, 68, /* 2369: struct.ssl_ctx_st.922 */
            	2508, 0,
            	385, 8,
            	385, 16,
            	2334, 24,
            	2174, 32,
            	104, 40,
            	2737, 48,
            	2737, 56,
            	101, 64,
            	104, 72,
            	2081, 80,
            	2076, 88,
            	2068, 96,
            	2040, 104,
            	101, 148,
            	2984, 152,
            	54, 160,
            	2035, 168,
            	54, 176,
            	2027, 184,
            	2019, 192,
            	2179, 200,
            	1175, 208,
            	1312, 224,
            	1312, 232,
            	1312, 240,
            	385, 248,
            	385, 256,
            	2008, 264,
            	385, 272,
            	104, 280,
            	104, 288,
            	104, 296,
            	2003, 304,
            	101, 312,
            	155, 320,
            	54, 328,
            	101, 336,
            	101, 340,
            	2912, 344,
            	2326, 376,
            	2019, 384,
            	2276, 392,
            	101, 400,
            	101, 404,
            	659, 408,
            	62, 416,
            	54, 424,
            	120, 432,
            	120, 448,
            	120, 464,
            	2129, 480,
            	70, 488,
            	54, 496,
            	2134, 504,
            	54, 512,
            	54, 520,
            	2121, 528,
            	2353, 536,
            	101, 544,
            	2989, 552,
            	2989, 560,
            	19, 568,
            	6, 696,
            	54, 704,
            	2142, 712,
            	54, 720,
            	385, 728,
            1, 8, 1, /* 2508: pointer.struct.ssl_method_st.924 */
            	2513, 0,
            0, 232, 29, /* 2513: struct.ssl_method_st.924 */
            	101, 0,
            	2574, 8,
            	2582, 16,
            	2582, 24,
            	2574, 32,
            	2574, 40,
            	2179, 48,
            	2179, 56,
            	2179, 64,
            	2574, 72,
            	2574, 80,
            	2574, 88,
            	2590, 96,
            	2598, 104,
            	2606, 112,
            	2574, 120,
            	2614, 128,
            	2622, 136,
            	2630, 144,
            	2342, 152,
            	2574, 160,
            	1079, 168,
            	2361, 176,
            	2635, 184,
            	2643, 192,
            	2648, 200,
            	1079, 208,
            	2721, 216,
            	2729, 224,
            1, 8, 1, /* 2574: pointer.func */
            	2579, 0,
            0, 0, 0, /* 2579: func */
            1, 8, 1, /* 2582: pointer.func */
            	2587, 0,
            0, 0, 0, /* 2587: func */
            1, 8, 1, /* 2590: pointer.func */
            	2595, 0,
            0, 0, 0, /* 2595: func */
            1, 8, 1, /* 2598: pointer.func */
            	2603, 0,
            0, 0, 0, /* 2603: func */
            1, 8, 1, /* 2606: pointer.func */
            	2611, 0,
            0, 0, 0, /* 2611: func */
            1, 8, 1, /* 2614: pointer.func */
            	2619, 0,
            0, 0, 0, /* 2619: func */
            1, 8, 1, /* 2622: pointer.func */
            	2627, 0,
            0, 0, 0, /* 2627: func */
            1, 8, 1, /* 2630: pointer.func */
            	2358, 0,
            1, 8, 1, /* 2635: pointer.func */
            	2640, 0,
            0, 0, 0, /* 2640: func */
            1, 8, 1, /* 2643: pointer.func */
            	2339, 0,
            1, 8, 1, /* 2648: pointer.struct.ssl3_enc_method.923 */
            	2653, 0,
            0, 112, 14, /* 2653: struct.ssl3_enc_method.923 */
            	2684, 0,
            	2179, 8,
            	2574, 16,
            	2353, 24,
            	2684, 32,
            	2692, 40,
            	101, 48,
            	2700, 56,
            	54, 64,
            	101, 72,
            	54, 80,
            	101, 88,
            	2708, 96,
            	2713, 104,
            1, 8, 1, /* 2684: pointer.func */
            	2689, 0,
            0, 0, 0, /* 2689: func */
            1, 8, 1, /* 2692: pointer.func */
            	2697, 0,
            0, 0, 0, /* 2697: func */
            1, 8, 1, /* 2700: pointer.func */
            	2705, 0,
            0, 0, 0, /* 2705: func */
            1, 8, 1, /* 2708: pointer.func */
            	2246, 0,
            1, 8, 1, /* 2713: pointer.func */
            	2718, 0,
            0, 0, 0, /* 2718: func */
            1, 8, 1, /* 2721: pointer.func */
            	2726, 0,
            0, 0, 0, /* 2726: func */
            1, 8, 1, /* 2729: pointer.func */
            	2734, 0,
            0, 0, 0, /* 2734: func */
            1, 8, 1, /* 2737: pointer.struct.ssl_session_st */
            	2742, 0,
            0, 352, 34, /* 2742: struct.ssl_session_st */
            	101, 0,
            	101, 4,
            	2219, 8,
            	101, 16,
            	2813, 20,
            	101, 68,
            	2912, 72,
            	101, 104,
            	2912, 108,
            	54, 144,
            	54, 152,
            	101, 160,
            	2979, 168,
            	222, 176,
            	104, 184,
            	101, 192,
            	104, 200,
            	104, 208,
            	101, 216,
            	2089, 224,
            	104, 232,
            	385, 240,
            	1175, 248,
            	2737, 264,
            	2737, 272,
            	54, 280,
            	104, 288,
            	54, 296,
            	104, 304,
            	54, 312,
            	54, 320,
            	104, 328,
            	104, 336,
            	54, 344,
            0, 48, 48, /* 2813: array[48].char */
            	59, 0,
            	59, 1,
            	59, 2,
            	59, 3,
            	59, 4,
            	59, 5,
            	59, 6,
            	59, 7,
            	59, 8,
            	59, 9,
            	59, 10,
            	59, 11,
            	59, 12,
            	59, 13,
            	59, 14,
            	59, 15,
            	59, 16,
            	59, 17,
            	59, 18,
            	59, 19,
            	59, 20,
            	59, 21,
            	59, 22,
            	59, 23,
            	59, 24,
            	59, 25,
            	59, 26,
            	59, 27,
            	59, 28,
            	59, 29,
            	59, 30,
            	59, 31,
            	59, 32,
            	59, 33,
            	59, 34,
            	59, 35,
            	59, 36,
            	59, 37,
            	59, 38,
            	59, 39,
            	59, 40,
            	59, 41,
            	59, 42,
            	59, 43,
            	59, 44,
            	59, 45,
            	59, 46,
            	59, 47,
            0, 32, 32, /* 2912: array[32].char */
            	59, 0,
            	59, 1,
            	59, 2,
            	59, 3,
            	59, 4,
            	59, 5,
            	59, 6,
            	59, 7,
            	59, 8,
            	59, 9,
            	59, 10,
            	59, 11,
            	59, 12,
            	59, 13,
            	59, 14,
            	59, 15,
            	59, 16,
            	59, 17,
            	59, 18,
            	59, 19,
            	59, 20,
            	59, 21,
            	59, 22,
            	59, 23,
            	59, 24,
            	59, 25,
            	59, 26,
            	59, 27,
            	59, 28,
            	59, 29,
            	59, 30,
            	59, 31,
            1, 8, 1, /* 2979: pointer.struct.sess_cert_st */
            	2155, 0,
            1, 8, 1, /* 2984: pointer.func */
            	2147, 0,
            1, 8, 1, /* 2989: pointer.struct.ssl3_buf_freelist_st */
            	2994, 0,
            0, 24, 3, /* 2994: struct.ssl3_buf_freelist_st */
            	104, 0,
            	101, 8,
            	107, 16,
            1, 8, 1, /* 3003: pointer.struct.ssl_ctx_st.922 */
            	2369, 0,
        },
        .arg_entity_index = { 3003, 2076, },
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

