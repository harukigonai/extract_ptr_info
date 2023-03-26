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

void SSL_CTX_set_default_passwd_cb(SSL_CTX * arg_a,pem_password_cb * arg_b) 
{
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
            0, 16, 16, /* 51: array[16].char */
            	86, 0,
            	86, 1,
            	86, 2,
            	86, 3,
            	86, 4,
            	86, 5,
            	86, 6,
            	86, 7,
            	86, 8,
            	86, 9,
            	86, 10,
            	86, 11,
            	86, 12,
            	86, 13,
            	86, 14,
            	86, 15,
            0, 1, 0, /* 86: char */
            0, 0, 0, /* 89: func */
            0, 0, 0, /* 92: func */
            1, 8, 1, /* 95: pointer.func */
            	92, 0,
            0, 0, 0, /* 100: func */
            1, 8, 1, /* 103: pointer.func */
            	100, 0,
            1, 8, 1, /* 108: pointer.struct.ssl3_buf_freelist_entry_st */
            	113, 0,
            0, 8, 1, /* 113: struct.ssl3_buf_freelist_entry_st */
            	108, 0,
            0, 0, 0, /* 118: func */
            1, 8, 1, /* 121: pointer.func */
            	118, 0,
            0, 296, 14, /* 126: struct.cert_st.745 */
            	157, 0,
            	267, 8,
            	275, 16,
            	275, 24,
            	275, 32,
            	275, 40,
            	1379, 48,
            	1514, 56,
            	1522, 64,
            	121, 72,
            	1566, 80,
            	103, 88,
            	1965, 96,
            	267, 288,
            1, 8, 1, /* 157: pointer.struct.cert_pkey_st */
            	162, 0,
            0, 24, 3, /* 162: struct.cert_pkey_st */
            	171, 0,
            	421, 8,
            	1272, 16,
            1, 8, 1, /* 171: pointer.struct.x509_st */
            	176, 0,
            0, 184, 21, /* 176: struct.x509_st */
            	221, 0,
            	278, 8,
            	251, 16,
            	267, 24,
            	267, 28,
            	270, 32,
            	1135, 40,
            	275, 56,
            	275, 64,
            	275, 72,
            	275, 80,
            	275, 88,
            	275, 96,
            	251, 104,
            	1151, 112,
            	1165, 120,
            	345, 128,
            	345, 136,
            	1199, 144,
            	1211, 152,
            	1254, 176,
            1, 8, 1, /* 221: pointer.struct.x509_cinf_st */
            	226, 0,
            0, 104, 11, /* 226: struct.x509_cinf_st */
            	251, 0,
            	251, 8,
            	278, 16,
            	327, 24,
            	395, 32,
            	327, 40,
            	407, 48,
            	251, 56,
            	251, 64,
            	345, 72,
            	1142, 80,
            1, 8, 1, /* 251: pointer.struct.asn1_string_st */
            	256, 0,
            0, 24, 4, /* 256: struct.asn1_string_st */
            	267, 0,
            	267, 4,
            	270, 8,
            	275, 16,
            0, 4, 0, /* 267: int */
            1, 8, 1, /* 270: pointer.char */
            	86, 0,
            0, 8, 0, /* 275: long */
            1, 8, 1, /* 278: pointer.struct.X509_algor_st */
            	283, 0,
            0, 16, 2, /* 283: struct.X509_algor_st */
            	290, 0,
            	310, 8,
            1, 8, 1, /* 290: pointer.struct.asn1_object_st */
            	295, 0,
            0, 40, 6, /* 295: struct.asn1_object_st */
            	270, 0,
            	270, 8,
            	267, 16,
            	267, 20,
            	270, 24,
            	267, 32,
            1, 8, 1, /* 310: pointer.struct.asn1_type_st */
            	315, 0,
            0, 16, 2, /* 315: struct.asn1_type_st */
            	267, 0,
            	322, 8,
            0, 8, 1, /* 322: struct.fnames */
            	270, 0,
            1, 8, 1, /* 327: pointer.struct.X509_name_st */
            	332, 0,
            0, 40, 5, /* 332: struct.X509_name_st */
            	345, 0,
            	267, 8,
            	381, 16,
            	270, 24,
            	267, 32,
            1, 8, 1, /* 345: pointer.struct.stack_st_OPENSSL_STRING */
            	350, 0,
            0, 32, 1, /* 350: struct.stack_st_OPENSSL_STRING */
            	355, 0,
            0, 32, 5, /* 355: struct.stack_st */
            	267, 0,
            	368, 8,
            	267, 16,
            	267, 20,
            	373, 24,
            1, 8, 1, /* 368: pointer.pointer.char */
            	270, 0,
            1, 8, 1, /* 373: pointer.func */
            	378, 0,
            0, 0, 0, /* 378: func */
            1, 8, 1, /* 381: pointer.struct.buf_mem_st */
            	386, 0,
            0, 24, 3, /* 386: struct.buf_mem_st */
            	275, 0,
            	270, 8,
            	275, 16,
            1, 8, 1, /* 395: pointer.struct.X509_val_st */
            	400, 0,
            0, 16, 2, /* 400: struct.X509_val_st */
            	251, 0,
            	251, 8,
            1, 8, 1, /* 407: pointer.struct.X509_pubkey_st */
            	412, 0,
            0, 24, 3, /* 412: struct.X509_pubkey_st */
            	278, 0,
            	251, 8,
            	421, 16,
            1, 8, 1, /* 421: pointer.struct.evp_pkey_st */
            	426, 0,
            0, 56, 8, /* 426: struct.evp_pkey_st */
            	267, 0,
            	267, 4,
            	267, 8,
            	445, 16,
            	619, 24,
            	322, 32,
            	267, 40,
            	345, 48,
            1, 8, 1, /* 445: pointer.struct.evp_pkey_asn1_method_st */
            	450, 0,
            0, 208, 27, /* 450: struct.evp_pkey_asn1_method_st */
            	267, 0,
            	267, 4,
            	275, 8,
            	270, 16,
            	270, 24,
            	507, 32,
            	515, 40,
            	523, 48,
            	531, 56,
            	539, 64,
            	547, 72,
            	531, 80,
            	555, 88,
            	555, 96,
            	563, 104,
            	571, 112,
            	555, 120,
            	523, 128,
            	523, 136,
            	531, 144,
            	579, 152,
            	587, 160,
            	595, 168,
            	563, 176,
            	571, 184,
            	603, 192,
            	611, 200,
            1, 8, 1, /* 507: pointer.struct.unnamed */
            	512, 0,
            0, 0, 0, /* 512: struct.unnamed */
            1, 8, 1, /* 515: pointer.func */
            	520, 0,
            0, 0, 0, /* 520: func */
            1, 8, 1, /* 523: pointer.func */
            	528, 0,
            0, 0, 0, /* 528: func */
            1, 8, 1, /* 531: pointer.func */
            	536, 0,
            0, 0, 0, /* 536: func */
            1, 8, 1, /* 539: pointer.func */
            	544, 0,
            0, 0, 0, /* 544: func */
            1, 8, 1, /* 547: pointer.func */
            	552, 0,
            0, 0, 0, /* 552: func */
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
            1, 8, 1, /* 619: pointer.struct.engine_st */
            	624, 0,
            0, 216, 27, /* 624: struct.engine_st */
            	270, 0,
            	270, 8,
            	681, 16,
            	773, 24,
            	861, 32,
            	919, 40,
            	943, 48,
            	987, 56,
            	1047, 64,
            	1055, 72,
            	1063, 80,
            	1071, 88,
            	1079, 96,
            	1087, 104,
            	1087, 112,
            	1087, 120,
            	1095, 128,
            	1103, 136,
            	1103, 144,
            	1111, 152,
            	1119, 160,
            	267, 168,
            	267, 172,
            	267, 176,
            	1135, 184,
            	619, 200,
            	619, 208,
            1, 8, 1, /* 681: pointer.struct.rsa_meth_st */
            	686, 0,
            0, 112, 14, /* 686: struct.rsa_meth_st */
            	270, 0,
            	717, 8,
            	717, 16,
            	717, 24,
            	717, 32,
            	725, 40,
            	733, 48,
            	741, 56,
            	741, 64,
            	267, 72,
            	270, 80,
            	749, 88,
            	757, 96,
            	765, 104,
            1, 8, 1, /* 717: pointer.func */
            	722, 0,
            0, 0, 0, /* 722: func */
            1, 8, 1, /* 725: pointer.func */
            	730, 0,
            0, 0, 0, /* 730: func */
            1, 8, 1, /* 733: pointer.func */
            	738, 0,
            0, 0, 0, /* 738: func */
            1, 8, 1, /* 741: pointer.func */
            	746, 0,
            0, 0, 0, /* 746: func */
            1, 8, 1, /* 749: pointer.func */
            	754, 0,
            0, 0, 0, /* 754: func */
            1, 8, 1, /* 757: pointer.func */
            	762, 0,
            0, 0, 0, /* 762: func */
            1, 8, 1, /* 765: pointer.func */
            	770, 0,
            0, 0, 0, /* 770: func */
            1, 8, 1, /* 773: pointer.struct.dsa_method.1040 */
            	778, 0,
            0, 96, 12, /* 778: struct.dsa_method.1040 */
            	270, 0,
            	805, 8,
            	813, 16,
            	821, 24,
            	829, 32,
            	837, 40,
            	845, 48,
            	845, 56,
            	267, 64,
            	270, 72,
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
            1, 8, 1, /* 861: pointer.struct.dh_method */
            	866, 0,
            0, 72, 9, /* 866: struct.dh_method */
            	270, 0,
            	887, 8,
            	895, 16,
            	903, 24,
            	887, 32,
            	887, 40,
            	267, 48,
            	270, 56,
            	911, 64,
            1, 8, 1, /* 887: pointer.func */
            	892, 0,
            0, 0, 0, /* 892: func */
            1, 8, 1, /* 895: pointer.func */
            	900, 0,
            0, 0, 0, /* 900: func */
            1, 8, 1, /* 903: pointer.func */
            	908, 0,
            0, 0, 0, /* 908: func */
            1, 8, 1, /* 911: pointer.func */
            	916, 0,
            0, 0, 0, /* 916: func */
            1, 8, 1, /* 919: pointer.struct.ecdh_method */
            	924, 0,
            0, 32, 4, /* 924: struct.ecdh_method */
            	270, 0,
            	935, 8,
            	267, 16,
            	270, 24,
            1, 8, 1, /* 935: pointer.func */
            	940, 0,
            0, 0, 0, /* 940: func */
            1, 8, 1, /* 943: pointer.struct.ecdsa_method */
            	948, 0,
            0, 48, 6, /* 948: struct.ecdsa_method */
            	270, 0,
            	963, 8,
            	971, 16,
            	979, 24,
            	267, 32,
            	270, 40,
            1, 8, 1, /* 963: pointer.func */
            	968, 0,
            0, 0, 0, /* 968: func */
            1, 8, 1, /* 971: pointer.func */
            	976, 0,
            0, 0, 0, /* 976: func */
            1, 8, 1, /* 979: pointer.func */
            	984, 0,
            0, 0, 0, /* 984: func */
            1, 8, 1, /* 987: pointer.struct.rand_meth_st */
            	992, 0,
            0, 48, 6, /* 992: struct.rand_meth_st */
            	1007, 0,
            	1015, 8,
            	1023, 16,
            	1031, 24,
            	1015, 32,
            	1039, 40,
            1, 8, 1, /* 1007: pointer.func */
            	1012, 0,
            0, 0, 0, /* 1012: func */
            1, 8, 1, /* 1015: pointer.func */
            	1020, 0,
            0, 0, 0, /* 1020: func */
            1, 8, 1, /* 1023: pointer.func */
            	1028, 0,
            0, 0, 0, /* 1028: func */
            1, 8, 1, /* 1031: pointer.func */
            	1036, 0,
            0, 0, 0, /* 1036: func */
            1, 8, 1, /* 1039: pointer.func */
            	1044, 0,
            0, 0, 0, /* 1044: func */
            1, 8, 1, /* 1047: pointer.struct.store_method_st */
            	1052, 0,
            0, 0, 0, /* 1052: struct.store_method_st */
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
            1, 8, 1, /* 1087: pointer.func */
            	1092, 0,
            0, 0, 0, /* 1092: func */
            1, 8, 1, /* 1095: pointer.func */
            	1100, 0,
            0, 0, 0, /* 1100: func */
            1, 8, 1, /* 1103: pointer.func */
            	1108, 0,
            0, 0, 0, /* 1108: func */
            1, 8, 1, /* 1111: pointer.func */
            	1116, 0,
            0, 0, 0, /* 1116: func */
            1, 8, 1, /* 1119: pointer.struct.ENGINE_CMD_DEFN_st */
            	1124, 0,
            0, 32, 4, /* 1124: struct.ENGINE_CMD_DEFN_st */
            	267, 0,
            	270, 8,
            	270, 16,
            	267, 24,
            0, 16, 2, /* 1135: struct.crypto_ex_data_st */
            	345, 0,
            	267, 8,
            0, 24, 3, /* 1142: struct.ASN1_ENCODING_st */
            	270, 0,
            	275, 8,
            	267, 16,
            1, 8, 1, /* 1151: pointer.struct.AUTHORITY_KEYID_st */
            	1156, 0,
            0, 24, 3, /* 1156: struct.AUTHORITY_KEYID_st */
            	251, 0,
            	345, 8,
            	251, 16,
            1, 8, 1, /* 1165: pointer.struct.X509_POLICY_CACHE_st */
            	1170, 0,
            0, 40, 5, /* 1170: struct.X509_POLICY_CACHE_st */
            	1183, 0,
            	345, 8,
            	275, 16,
            	275, 24,
            	275, 32,
            1, 8, 1, /* 1183: pointer.struct.X509_POLICY_DATA_st */
            	1188, 0,
            0, 32, 4, /* 1188: struct.X509_POLICY_DATA_st */
            	267, 0,
            	290, 8,
            	345, 16,
            	345, 24,
            1, 8, 1, /* 1199: pointer.struct.NAME_CONSTRAINTS_st */
            	1204, 0,
            0, 16, 2, /* 1204: struct.NAME_CONSTRAINTS_st */
            	345, 0,
            	345, 8,
            0, 20, 20, /* 1211: array[20].char */
            	86, 0,
            	86, 1,
            	86, 2,
            	86, 3,
            	86, 4,
            	86, 5,
            	86, 6,
            	86, 7,
            	86, 8,
            	86, 9,
            	86, 10,
            	86, 11,
            	86, 12,
            	86, 13,
            	86, 14,
            	86, 15,
            	86, 16,
            	86, 17,
            	86, 18,
            	86, 19,
            1, 8, 1, /* 1254: pointer.struct.x509_cert_aux_st */
            	1259, 0,
            0, 40, 5, /* 1259: struct.x509_cert_aux_st */
            	345, 0,
            	345, 8,
            	251, 16,
            	251, 24,
            	345, 32,
            1, 8, 1, /* 1272: pointer.struct.env_md_st */
            	1277, 0,
            0, 120, 15, /* 1277: struct.env_md_st */
            	267, 0,
            	267, 4,
            	267, 8,
            	275, 16,
            	1310, 24,
            	1318, 32,
            	1326, 40,
            	1334, 48,
            	1310, 56,
            	1342, 64,
            	1350, 72,
            	1358, 80,
            	267, 100,
            	267, 104,
            	1371, 112,
            1, 8, 1, /* 1310: pointer.func */
            	1315, 0,
            0, 0, 0, /* 1315: func */
            1, 8, 1, /* 1318: pointer.func */
            	1323, 0,
            0, 0, 0, /* 1323: func */
            1, 8, 1, /* 1326: pointer.func */
            	1331, 0,
            0, 0, 0, /* 1331: func */
            1, 8, 1, /* 1334: pointer.func */
            	1339, 0,
            0, 0, 0, /* 1339: func */
            1, 8, 1, /* 1342: pointer.func */
            	1347, 0,
            0, 0, 0, /* 1347: func */
            1, 8, 1, /* 1350: pointer.func */
            	1355, 0,
            0, 0, 0, /* 1355: func */
            0, 20, 5, /* 1358: array[5].int */
            	267, 0,
            	267, 4,
            	267, 8,
            	267, 12,
            	267, 16,
            1, 8, 1, /* 1371: pointer.func */
            	1376, 0,
            0, 0, 0, /* 1376: func */
            1, 8, 1, /* 1379: pointer.struct.rsa_st */
            	1384, 0,
            0, 168, 21, /* 1384: struct.rsa_st */
            	267, 0,
            	275, 8,
            	681, 16,
            	619, 24,
            	1429, 32,
            	1429, 40,
            	1429, 48,
            	1429, 56,
            	1429, 64,
            	1429, 72,
            	1429, 80,
            	1429, 88,
            	1135, 96,
            	267, 112,
            	267, 116,
            	1452, 120,
            	1452, 128,
            	1452, 136,
            	270, 144,
            	1479, 152,
            	1479, 160,
            1, 8, 1, /* 1429: pointer.struct.bignum_st */
            	1434, 0,
            0, 24, 5, /* 1434: struct.bignum_st */
            	1447, 0,
            	267, 8,
            	267, 12,
            	267, 16,
            	267, 20,
            1, 8, 1, /* 1447: pointer.int */
            	267, 0,
            1, 8, 1, /* 1452: pointer.struct.bn_mont_ctx_st */
            	1457, 0,
            0, 96, 6, /* 1457: struct.bn_mont_ctx_st */
            	267, 0,
            	1434, 8,
            	1434, 32,
            	1434, 56,
            	1472, 80,
            	267, 88,
            0, 8, 2, /* 1472: array[2].int */
            	267, 0,
            	267, 4,
            1, 8, 1, /* 1479: pointer.struct.bn_blinding_st */
            	1484, 0,
            0, 88, 10, /* 1484: struct.bn_blinding_st */
            	1429, 0,
            	1429, 8,
            	1429, 16,
            	1429, 24,
            	275, 32,
            	1507, 40,
            	267, 56,
            	275, 64,
            	1452, 72,
            	733, 80,
            0, 16, 2, /* 1507: struct.iovec */
            	270, 0,
            	275, 8,
            1, 8, 1, /* 1514: pointer.func */
            	1519, 0,
            0, 0, 0, /* 1519: func */
            1, 8, 1, /* 1522: pointer.struct.dh_st */
            	1527, 0,
            0, 144, 18, /* 1527: struct.dh_st */
            	267, 0,
            	267, 4,
            	1429, 8,
            	1429, 16,
            	275, 24,
            	1429, 32,
            	1429, 40,
            	267, 48,
            	1452, 56,
            	1429, 64,
            	1429, 72,
            	270, 80,
            	267, 88,
            	1429, 96,
            	267, 104,
            	1135, 112,
            	861, 128,
            	619, 136,
            1, 8, 1, /* 1566: pointer.struct.ec_key_st.284 */
            	1571, 0,
            0, 56, 9, /* 1571: struct.ec_key_st.284 */
            	267, 0,
            	1592, 8,
            	1890, 16,
            	1429, 24,
            	267, 32,
            	267, 36,
            	267, 40,
            	267, 44,
            	1908, 48,
            1, 8, 1, /* 1592: pointer.struct.ec_group_st */
            	1597, 0,
            0, 232, 18, /* 1597: struct.ec_group_st */
            	1636, 0,
            	1890, 8,
            	1434, 16,
            	1434, 40,
            	267, 64,
            	267, 68,
            	267, 72,
            	270, 80,
            	275, 88,
            	1908, 96,
            	1434, 104,
            	1942, 128,
            	1434, 152,
            	1434, 176,
            	267, 200,
            	270, 208,
            	270, 216,
            	1957, 224,
            1, 8, 1, /* 1636: pointer.struct.ec_method_st */
            	1641, 0,
            0, 304, 39, /* 1641: struct.ec_method_st */
            	267, 0,
            	267, 4,
            	1722, 8,
            	1730, 16,
            	1730, 24,
            	1738, 32,
            	1746, 40,
            	1746, 48,
            	1722, 56,
            	1754, 64,
            	1762, 72,
            	1770, 80,
            	1770, 88,
            	1778, 96,
            	1786, 104,
            	1794, 112,
            	1794, 120,
            	1802, 128,
            	1802, 136,
            	1810, 144,
            	1818, 152,
            	1826, 160,
            	1834, 168,
            	1842, 176,
            	1850, 184,
            	1786, 192,
            	1850, 200,
            	1842, 208,
            	1850, 216,
            	1858, 224,
            	1866, 232,
            	1754, 240,
            	1722, 248,
            	1746, 256,
            	1874, 264,
            	1746, 272,
            	1874, 280,
            	1874, 288,
            	1882, 296,
            1, 8, 1, /* 1722: pointer.func */
            	1727, 0,
            0, 0, 0, /* 1727: func */
            1, 8, 1, /* 1730: pointer.func */
            	1735, 0,
            0, 0, 0, /* 1735: func */
            1, 8, 1, /* 1738: pointer.func */
            	1743, 0,
            0, 0, 0, /* 1743: func */
            1, 8, 1, /* 1746: pointer.func */
            	1751, 0,
            0, 0, 0, /* 1751: func */
            1, 8, 1, /* 1754: pointer.func */
            	1759, 0,
            0, 0, 0, /* 1759: func */
            1, 8, 1, /* 1762: pointer.func */
            	1767, 0,
            0, 0, 0, /* 1767: func */
            1, 8, 1, /* 1770: pointer.func */
            	1775, 0,
            0, 0, 0, /* 1775: func */
            1, 8, 1, /* 1778: pointer.func */
            	1783, 0,
            0, 0, 0, /* 1783: func */
            1, 8, 1, /* 1786: pointer.func */
            	1791, 0,
            0, 0, 0, /* 1791: func */
            1, 8, 1, /* 1794: pointer.func */
            	1799, 0,
            0, 0, 0, /* 1799: func */
            1, 8, 1, /* 1802: pointer.func */
            	1807, 0,
            0, 0, 0, /* 1807: func */
            1, 8, 1, /* 1810: pointer.func */
            	1815, 0,
            0, 0, 0, /* 1815: func */
            1, 8, 1, /* 1818: pointer.func */
            	1823, 0,
            0, 0, 0, /* 1823: func */
            1, 8, 1, /* 1826: pointer.func */
            	1831, 0,
            0, 0, 0, /* 1831: func */
            1, 8, 1, /* 1834: pointer.func */
            	1839, 0,
            0, 0, 0, /* 1839: func */
            1, 8, 1, /* 1842: pointer.func */
            	1847, 0,
            0, 0, 0, /* 1847: func */
            1, 8, 1, /* 1850: pointer.func */
            	1855, 0,
            0, 0, 0, /* 1855: func */
            1, 8, 1, /* 1858: pointer.func */
            	1863, 0,
            0, 0, 0, /* 1863: func */
            1, 8, 1, /* 1866: pointer.func */
            	1871, 0,
            0, 0, 0, /* 1871: func */
            1, 8, 1, /* 1874: pointer.func */
            	1879, 0,
            0, 0, 0, /* 1879: func */
            1, 8, 1, /* 1882: pointer.func */
            	1887, 0,
            0, 0, 0, /* 1887: func */
            1, 8, 1, /* 1890: pointer.struct.ec_point_st */
            	1895, 0,
            0, 88, 5, /* 1895: struct.ec_point_st */
            	1636, 0,
            	1434, 8,
            	1434, 32,
            	1434, 56,
            	267, 80,
            1, 8, 1, /* 1908: pointer.struct.ec_extra_data_st */
            	1913, 0,
            0, 40, 5, /* 1913: struct.ec_extra_data_st */
            	1908, 0,
            	270, 8,
            	1926, 16,
            	1934, 24,
            	1934, 32,
            1, 8, 1, /* 1926: pointer.func */
            	1931, 0,
            0, 0, 0, /* 1931: func */
            1, 8, 1, /* 1934: pointer.func */
            	1939, 0,
            0, 0, 0, /* 1939: func */
            0, 24, 6, /* 1942: array[6].int */
            	267, 0,
            	267, 4,
            	267, 8,
            	267, 12,
            	267, 16,
            	267, 20,
            1, 8, 1, /* 1957: pointer.func */
            	1962, 0,
            0, 0, 0, /* 1962: func */
            0, 192, 8, /* 1965: array[8].struct.cert_pkey_st */
            	162, 0,
            	162, 24,
            	162, 48,
            	162, 72,
            	162, 96,
            	162, 120,
            	162, 144,
            	162, 168,
            1, 8, 1, /* 1984: pointer.struct.cert_st.745 */
            	126, 0,
            0, 0, 0, /* 1989: func */
            1, 8, 1, /* 1992: pointer.func */
            	1989, 0,
            0, 0, 0, /* 1997: func */
            1, 8, 1, /* 2000: pointer.func */
            	1997, 0,
            0, 44, 11, /* 2005: struct.apr_time_exp_t */
            	267, 0,
            	267, 4,
            	267, 8,
            	267, 12,
            	267, 16,
            	267, 20,
            	267, 24,
            	267, 28,
            	267, 32,
            	267, 36,
            	267, 40,
            0, 0, 0, /* 2030: func */
            1, 8, 1, /* 2033: pointer.func */
            	2030, 0,
            1, 8, 1, /* 2038: pointer.struct.ssl_cipher_st */
            	2043, 0,
            0, 88, 12, /* 2043: struct.ssl_cipher_st */
            	267, 0,
            	270, 8,
            	275, 16,
            	275, 24,
            	275, 32,
            	275, 40,
            	275, 48,
            	275, 56,
            	275, 64,
            	275, 72,
            	267, 80,
            	267, 84,
            0, 0, 0, /* 2070: func */
            0, 4, 1, /* 2073: struct.in_addr */
            	267, 0,
            1, 8, 1, /* 2078: pointer.func */
            	2083, 0,
            0, 0, 0, /* 2083: func */
            1, 8, 1, /* 2086: pointer.func */
            	2091, 0,
            0, 0, 0, /* 2091: func */
            0, 248, 8, /* 2094: struct.sess_cert_st */
            	345, 0,
            	267, 8,
            	157, 16,
            	1965, 24,
            	1379, 216,
            	1522, 224,
            	1566, 232,
            	267, 240,
            0, 0, 0, /* 2113: func */
            1, 8, 1, /* 2116: pointer.func */
            	2113, 0,
            1, 8, 1, /* 2121: pointer.func */
            	2126, 0,
            0, 0, 0, /* 2126: func */
            1, 8, 1, /* 2129: pointer.func */
            	2134, 0,
            0, 0, 0, /* 2134: func */
            1, 8, 1, /* 2137: pointer.func */
            	2142, 0,
            0, 0, 0, /* 2142: func */
            1, 8, 1, /* 2145: pointer.func */
            	2150, 0,
            0, 0, 0, /* 2150: func */
            0, 8, 8, /* 2153: array[8].char */
            	86, 0,
            	86, 1,
            	86, 2,
            	86, 3,
            	86, 4,
            	86, 5,
            	86, 6,
            	86, 7,
            1, 8, 1, /* 2172: pointer.func */
            	2177, 0,
            0, 0, 0, /* 2177: func */
            0, 0, 0, /* 2180: func */
            0, 0, 0, /* 2183: func */
            1, 8, 1, /* 2186: pointer.func */
            	2183, 0,
            0, 56, 8, /* 2191: struct.X509_VERIFY_PARAM_st */
            	270, 0,
            	275, 8,
            	275, 16,
            	275, 24,
            	267, 32,
            	267, 36,
            	267, 40,
            	345, 48,
            1, 8, 1, /* 2210: pointer.struct.X509_VERIFY_PARAM_st */
            	2191, 0,
            0, 24, 3, /* 2215: struct.ssl3_buf_freelist_st */
            	275, 0,
            	267, 8,
            	108, 16,
            0, 0, 0, /* 2224: func */
            1, 8, 1, /* 2227: pointer.func */
            	2232, 0,
            0, 0, 0, /* 2232: func */
            0, 0, 0, /* 2235: func */
            1, 8, 1, /* 2238: pointer.func */
            	2243, 0,
            0, 0, 0, /* 2243: func */
            1, 8, 1, /* 2246: pointer.func */
            	2251, 0,
            0, 0, 0, /* 2251: func */
            1, 8, 1, /* 2254: pointer.func */
            	2259, 0,
            0, 0, 0, /* 2259: func */
            1, 8, 1, /* 2262: pointer.struct.ssl_ctx_st.752 */
            	2267, 0,
            0, 736, 68, /* 2267: struct.ssl_ctx_st.752 */
            	2406, 0,
            	345, 8,
            	345, 16,
            	2627, 24,
            	2677, 32,
            	275, 40,
            	2682, 48,
            	2682, 56,
            	267, 64,
            	275, 72,
            	2033, 80,
            	2078, 88,
            	2086, 96,
            	2005, 104,
            	267, 148,
            	2929, 152,
            	270, 160,
            	2000, 168,
            	270, 176,
            	1992, 184,
            	2934, 192,
            	2254, 200,
            	1135, 208,
            	1272, 224,
            	1272, 232,
            	1272, 240,
            	345, 248,
            	345, 256,
            	2942, 264,
            	345, 272,
            	275, 280,
            	275, 288,
            	275, 296,
            	1984, 304,
            	267, 312,
            	95, 320,
            	270, 328,
            	267, 336,
            	267, 340,
            	2857, 344,
            	2227, 376,
            	2934, 384,
            	2210, 392,
            	267, 400,
            	267, 404,
            	619, 408,
            	2950, 416,
            	270, 424,
            	51, 432,
            	51, 448,
            	51, 464,
            	46, 480,
            	38, 488,
            	270, 496,
            	30, 504,
            	270, 512,
            	270, 520,
            	22, 528,
            	2121, 536,
            	267, 544,
            	2955, 552,
            	2955, 560,
            	2960, 568,
            	2995, 696,
            	270, 704,
            	3, 712,
            	270, 720,
            	345, 728,
            1, 8, 1, /* 2406: pointer.struct.ssl_method_st.754 */
            	2411, 0,
            0, 232, 29, /* 2411: struct.ssl_method_st.754 */
            	267, 0,
            	2472, 8,
            	2480, 16,
            	2480, 24,
            	2472, 32,
            	2472, 40,
            	2254, 48,
            	2254, 56,
            	2254, 64,
            	2472, 72,
            	2472, 80,
            	2472, 88,
            	2485, 96,
            	2493, 104,
            	2501, 112,
            	2472, 120,
            	2238, 128,
            	2509, 136,
            	2517, 144,
            	2525, 152,
            	2472, 160,
            	1039, 168,
            	2533, 176,
            	2541, 184,
            	2549, 192,
            	2554, 200,
            	1039, 208,
            	2619, 216,
            	2246, 224,
            1, 8, 1, /* 2472: pointer.func */
            	2477, 0,
            0, 0, 0, /* 2477: func */
            1, 8, 1, /* 2480: pointer.func */
            	2235, 0,
            1, 8, 1, /* 2485: pointer.func */
            	2490, 0,
            0, 0, 0, /* 2490: func */
            1, 8, 1, /* 2493: pointer.func */
            	2498, 0,
            0, 0, 0, /* 2498: func */
            1, 8, 1, /* 2501: pointer.func */
            	2506, 0,
            0, 0, 0, /* 2506: func */
            1, 8, 1, /* 2509: pointer.func */
            	2514, 0,
            0, 0, 0, /* 2514: func */
            1, 8, 1, /* 2517: pointer.func */
            	2522, 0,
            0, 0, 0, /* 2522: func */
            1, 8, 1, /* 2525: pointer.func */
            	2530, 0,
            0, 0, 0, /* 2530: func */
            1, 8, 1, /* 2533: pointer.func */
            	2538, 0,
            0, 0, 0, /* 2538: func */
            1, 8, 1, /* 2541: pointer.func */
            	2546, 0,
            0, 0, 0, /* 2546: func */
            1, 8, 1, /* 2549: pointer.func */
            	2224, 0,
            1, 8, 1, /* 2554: pointer.struct.ssl3_enc_method.753 */
            	2559, 0,
            0, 112, 14, /* 2559: struct.ssl3_enc_method.753 */
            	507, 0,
            	2254, 8,
            	2472, 16,
            	2121, 24,
            	507, 32,
            	2590, 40,
            	267, 48,
            	2598, 56,
            	270, 64,
            	267, 72,
            	270, 80,
            	267, 88,
            	2606, 96,
            	2611, 104,
            1, 8, 1, /* 2590: pointer.func */
            	2595, 0,
            0, 0, 0, /* 2595: func */
            1, 8, 1, /* 2598: pointer.func */
            	2603, 0,
            0, 0, 0, /* 2603: func */
            1, 8, 1, /* 2606: pointer.func */
            	2180, 0,
            1, 8, 1, /* 2611: pointer.func */
            	2616, 0,
            0, 0, 0, /* 2616: func */
            1, 8, 1, /* 2619: pointer.func */
            	2624, 0,
            0, 0, 0, /* 2624: func */
            1, 8, 1, /* 2627: pointer.struct.x509_store_st */
            	2632, 0,
            0, 144, 17, /* 2632: struct.x509_store_st */
            	267, 0,
            	345, 8,
            	345, 16,
            	2210, 24,
            	2669, 32,
            	2227, 40,
            	2186, 48,
            	2172, 56,
            	2669, 64,
            	2145, 72,
            	2137, 80,
            	2129, 88,
            	2116, 96,
            	2116, 104,
            	2669, 112,
            	1135, 120,
            	267, 136,
            1, 8, 1, /* 2669: pointer.func */
            	2674, 0,
            0, 0, 0, /* 2674: func */
            1, 8, 1, /* 2677: pointer.struct.in_addr */
            	2073, 0,
            1, 8, 1, /* 2682: pointer.struct.ssl_session_st */
            	2687, 0,
            0, 352, 34, /* 2687: struct.ssl_session_st */
            	267, 0,
            	267, 4,
            	2153, 8,
            	267, 16,
            	2758, 20,
            	267, 68,
            	2857, 72,
            	267, 104,
            	2857, 108,
            	270, 144,
            	270, 152,
            	267, 160,
            	2924, 168,
            	171, 176,
            	275, 184,
            	267, 192,
            	275, 200,
            	275, 208,
            	267, 216,
            	2038, 224,
            	275, 232,
            	345, 240,
            	1135, 248,
            	2682, 264,
            	2682, 272,
            	270, 280,
            	275, 288,
            	270, 296,
            	275, 304,
            	270, 312,
            	270, 320,
            	275, 328,
            	275, 336,
            	270, 344,
            0, 48, 48, /* 2758: array[48].char */
            	86, 0,
            	86, 1,
            	86, 2,
            	86, 3,
            	86, 4,
            	86, 5,
            	86, 6,
            	86, 7,
            	86, 8,
            	86, 9,
            	86, 10,
            	86, 11,
            	86, 12,
            	86, 13,
            	86, 14,
            	86, 15,
            	86, 16,
            	86, 17,
            	86, 18,
            	86, 19,
            	86, 20,
            	86, 21,
            	86, 22,
            	86, 23,
            	86, 24,
            	86, 25,
            	86, 26,
            	86, 27,
            	86, 28,
            	86, 29,
            	86, 30,
            	86, 31,
            	86, 32,
            	86, 33,
            	86, 34,
            	86, 35,
            	86, 36,
            	86, 37,
            	86, 38,
            	86, 39,
            	86, 40,
            	86, 41,
            	86, 42,
            	86, 43,
            	86, 44,
            	86, 45,
            	86, 46,
            	86, 47,
            0, 32, 32, /* 2857: array[32].char */
            	86, 0,
            	86, 1,
            	86, 2,
            	86, 3,
            	86, 4,
            	86, 5,
            	86, 6,
            	86, 7,
            	86, 8,
            	86, 9,
            	86, 10,
            	86, 11,
            	86, 12,
            	86, 13,
            	86, 14,
            	86, 15,
            	86, 16,
            	86, 17,
            	86, 18,
            	86, 19,
            	86, 20,
            	86, 21,
            	86, 22,
            	86, 23,
            	86, 24,
            	86, 25,
            	86, 26,
            	86, 27,
            	86, 28,
            	86, 29,
            	86, 30,
            	86, 31,
            1, 8, 1, /* 2924: pointer.struct.sess_cert_st */
            	2094, 0,
            1, 8, 1, /* 2929: pointer.func */
            	2070, 0,
            1, 8, 1, /* 2934: pointer.func */
            	2939, 0,
            0, 0, 0, /* 2939: func */
            1, 8, 1, /* 2942: pointer.func */
            	2947, 0,
            0, 0, 0, /* 2947: func */
            1, 8, 1, /* 2950: pointer.func */
            	89, 0,
            1, 8, 1, /* 2955: pointer.struct.ssl3_buf_freelist_st */
            	2215, 0,
            0, 128, 16, /* 2960: struct.srp_ctx_st.751 */
            	270, 0,
            	2950, 8,
            	38, 16,
            	11, 24,
            	270, 32,
            	1429, 40,
            	1429, 48,
            	1429, 56,
            	1429, 64,
            	1429, 72,
            	1429, 80,
            	1429, 88,
            	1429, 96,
            	270, 104,
            	267, 112,
            	275, 120,
            1, 8, 1, /* 2995: pointer.func */
            	8, 0,
        },
        .arg_entity_index = { 2262, 2000, },
        .ret_entity_index = -1,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    SSL_CTX * new_arg_a = *((SSL_CTX * *)new_args->args[0]);

    pem_password_cb * new_arg_b = *((pem_password_cb * *)new_args->args[1]);

    void (*orig_SSL_CTX_set_default_passwd_cb)(SSL_CTX *,pem_password_cb *);
    orig_SSL_CTX_set_default_passwd_cb = dlsym(RTLD_NEXT, "SSL_CTX_set_default_passwd_cb");
    (*orig_SSL_CTX_set_default_passwd_cb)(new_arg_a,new_arg_b);

    syscall(889);

}

