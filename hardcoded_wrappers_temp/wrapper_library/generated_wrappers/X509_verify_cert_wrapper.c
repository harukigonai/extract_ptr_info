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

int bb_X509_verify_cert(X509_STORE_CTX * arg_a);

int X509_verify_cert(X509_STORE_CTX * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("X509_verify_cert called %lu\n", in_lib);
    if (!in_lib)
        return bb_X509_verify_cert(arg_a);
    else {
        int (*orig_X509_verify_cert)(X509_STORE_CTX *);
        orig_X509_verify_cert = dlsym(RTLD_NEXT, "X509_verify_cert");
        return orig_X509_verify_cert(arg_a);
    }
}

int bb_X509_verify_cert(X509_STORE_CTX * arg_a) 
{
    int ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 8, 0, /* 0: pointer.void */
            0, 0, 0, /* 3: func */
            0, 0, 0, /* 6: func */
            0, 0, 0, /* 9: func */
            4097, 8, 0, /* 12: pointer.func */
            0, 40, 4, /* 15: struct.x509_crl_method_st */
            	12, 8,
            	12, 16,
            	26, 24,
            	29, 32,
            4097, 8, 0, /* 26: pointer.func */
            4097, 8, 0, /* 29: pointer.func */
            0, 8, 1, /* 32: union.anon.1.3127 */
            	37, 0,
            1, 8, 1, /* 37: pointer.struct.stack_st_OPENSSL_STRING */
            	42, 0,
            0, 32, 1, /* 42: struct.stack_st_OPENSSL_STRING */
            	47, 0,
            0, 32, 2, /* 47: struct.stack_st */
            	54, 8,
            	64, 24,
            1, 8, 1, /* 54: pointer.pointer.char */
            	59, 0,
            1, 8, 1, /* 59: pointer.char */
            	4096, 0,
            4097, 8, 0, /* 64: pointer.func */
            0, 32, 2, /* 67: struct.ISSUING_DIST_POINT_st */
            	74, 0,
            	110, 16,
            1, 8, 1, /* 74: pointer.struct.DIST_POINT_NAME_st */
            	79, 0,
            0, 24, 2, /* 79: struct.DIST_POINT_NAME_st */
            	32, 8,
            	86, 16,
            1, 8, 1, /* 86: pointer.struct.X509_name_st */
            	91, 0,
            0, 40, 3, /* 91: struct.X509_name_st */
            	37, 0,
            	100, 16,
            	59, 24,
            1, 8, 1, /* 100: pointer.struct.buf_mem_st */
            	105, 0,
            0, 24, 1, /* 105: struct.buf_mem_st */
            	59, 8,
            1, 8, 1, /* 110: pointer.struct.asn1_string_st */
            	115, 0,
            0, 24, 1, /* 115: struct.asn1_string_st */
            	59, 8,
            1, 8, 1, /* 120: pointer.struct.X509_crl_info_st */
            	125, 0,
            0, 80, 8, /* 125: struct.X509_crl_info_st */
            	110, 0,
            	144, 8,
            	86, 16,
            	110, 24,
            	110, 32,
            	37, 40,
            	37, 48,
            	185, 56,
            1, 8, 1, /* 144: pointer.struct.X509_algor_st */
            	149, 0,
            0, 16, 2, /* 149: struct.X509_algor_st */
            	156, 0,
            	170, 8,
            1, 8, 1, /* 156: pointer.struct.asn1_object_st */
            	161, 0,
            0, 40, 3, /* 161: struct.asn1_object_st */
            	59, 0,
            	59, 8,
            	59, 24,
            1, 8, 1, /* 170: pointer.struct.asn1_type_st */
            	175, 0,
            0, 16, 1, /* 175: struct.asn1_type_st */
            	180, 8,
            0, 8, 1, /* 180: struct.fnames */
            	59, 0,
            0, 24, 1, /* 185: struct.ASN1_ENCODING_st */
            	59, 0,
            1, 8, 1, /* 190: pointer.struct.ISSUING_DIST_POINT_st */
            	67, 0,
            1, 8, 1, /* 195: pointer.struct.X509_POLICY_NODE_st */
            	200, 0,
            0, 24, 2, /* 200: struct.X509_POLICY_NODE_st */
            	207, 0,
            	195, 8,
            1, 8, 1, /* 207: pointer.struct.X509_POLICY_DATA_st */
            	212, 0,
            0, 32, 3, /* 212: struct.X509_POLICY_DATA_st */
            	156, 8,
            	37, 16,
            	37, 24,
            0, 0, 0, /* 221: func */
            0, 0, 0, /* 224: func */
            4097, 8, 0, /* 227: pointer.func */
            0, 0, 0, /* 230: func */
            4097, 8, 0, /* 233: pointer.func */
            4097, 8, 0, /* 236: pointer.func */
            0, 0, 0, /* 239: func */
            0, 0, 0, /* 242: func */
            0, 0, 0, /* 245: func */
            0, 24, 3, /* 248: struct.X509_pubkey_st */
            	144, 0,
            	110, 8,
            	257, 16,
            1, 8, 1, /* 257: pointer.struct.evp_pkey_st */
            	262, 0,
            0, 56, 4, /* 262: struct.evp_pkey_st */
            	273, 16,
            	367, 24,
            	180, 32,
            	37, 48,
            1, 8, 1, /* 273: pointer.struct.evp_pkey_asn1_method_st */
            	278, 0,
            0, 208, 24, /* 278: struct.evp_pkey_asn1_method_st */
            	59, 16,
            	59, 24,
            	329, 32,
            	337, 40,
            	340, 48,
            	343, 56,
            	236, 64,
            	233, 72,
            	343, 80,
            	227, 88,
            	227, 96,
            	346, 104,
            	349, 112,
            	227, 120,
            	340, 128,
            	340, 136,
            	343, 144,
            	352, 152,
            	355, 160,
            	358, 168,
            	346, 176,
            	349, 184,
            	361, 192,
            	364, 200,
            1, 8, 1, /* 329: pointer.struct.unnamed */
            	334, 0,
            0, 0, 0, /* 334: struct.unnamed */
            4097, 8, 0, /* 337: pointer.func */
            4097, 8, 0, /* 340: pointer.func */
            4097, 8, 0, /* 343: pointer.func */
            4097, 8, 0, /* 346: pointer.func */
            4097, 8, 0, /* 349: pointer.func */
            4097, 8, 0, /* 352: pointer.func */
            4097, 8, 0, /* 355: pointer.func */
            4097, 8, 0, /* 358: pointer.func */
            4097, 8, 0, /* 361: pointer.func */
            4097, 8, 0, /* 364: pointer.func */
            1, 8, 1, /* 367: pointer.struct.engine_st */
            	372, 0,
            0, 216, 24, /* 372: struct.engine_st */
            	59, 0,
            	59, 8,
            	423, 16,
            	478, 24,
            	529, 32,
            	565, 40,
            	582, 48,
            	609, 56,
            	644, 64,
            	652, 72,
            	655, 80,
            	658, 88,
            	661, 96,
            	664, 104,
            	664, 112,
            	664, 120,
            	667, 128,
            	670, 136,
            	670, 144,
            	673, 152,
            	676, 160,
            	688, 184,
            	367, 200,
            	367, 208,
            1, 8, 1, /* 423: pointer.struct.rsa_meth_st */
            	428, 0,
            0, 112, 13, /* 428: struct.rsa_meth_st */
            	59, 0,
            	457, 8,
            	457, 16,
            	457, 24,
            	457, 32,
            	460, 40,
            	463, 48,
            	466, 56,
            	466, 64,
            	59, 80,
            	469, 88,
            	472, 96,
            	475, 104,
            4097, 8, 0, /* 457: pointer.func */
            4097, 8, 0, /* 460: pointer.func */
            4097, 8, 0, /* 463: pointer.func */
            4097, 8, 0, /* 466: pointer.func */
            4097, 8, 0, /* 469: pointer.func */
            4097, 8, 0, /* 472: pointer.func */
            4097, 8, 0, /* 475: pointer.func */
            1, 8, 1, /* 478: pointer.struct.dsa_method */
            	483, 0,
            0, 96, 11, /* 483: struct.dsa_method */
            	59, 0,
            	508, 8,
            	511, 16,
            	514, 24,
            	517, 32,
            	520, 40,
            	523, 48,
            	523, 56,
            	59, 72,
            	526, 80,
            	523, 88,
            4097, 8, 0, /* 508: pointer.func */
            4097, 8, 0, /* 511: pointer.func */
            4097, 8, 0, /* 514: pointer.func */
            4097, 8, 0, /* 517: pointer.func */
            4097, 8, 0, /* 520: pointer.func */
            4097, 8, 0, /* 523: pointer.func */
            4097, 8, 0, /* 526: pointer.func */
            1, 8, 1, /* 529: pointer.struct.dh_method */
            	534, 0,
            0, 72, 8, /* 534: struct.dh_method */
            	59, 0,
            	553, 8,
            	556, 16,
            	559, 24,
            	553, 32,
            	553, 40,
            	59, 56,
            	562, 64,
            4097, 8, 0, /* 553: pointer.func */
            4097, 8, 0, /* 556: pointer.func */
            4097, 8, 0, /* 559: pointer.func */
            4097, 8, 0, /* 562: pointer.func */
            1, 8, 1, /* 565: pointer.struct.ecdh_method */
            	570, 0,
            0, 32, 3, /* 570: struct.ecdh_method */
            	59, 0,
            	579, 8,
            	59, 24,
            4097, 8, 0, /* 579: pointer.func */
            1, 8, 1, /* 582: pointer.struct.ecdsa_method */
            	587, 0,
            0, 48, 5, /* 587: struct.ecdsa_method */
            	59, 0,
            	600, 8,
            	603, 16,
            	606, 24,
            	59, 40,
            4097, 8, 0, /* 600: pointer.func */
            4097, 8, 0, /* 603: pointer.func */
            4097, 8, 0, /* 606: pointer.func */
            1, 8, 1, /* 609: pointer.struct.rand_meth_st */
            	614, 0,
            0, 48, 6, /* 614: struct.rand_meth_st */
            	629, 0,
            	632, 8,
            	635, 16,
            	638, 24,
            	632, 32,
            	641, 40,
            4097, 8, 0, /* 629: pointer.func */
            4097, 8, 0, /* 632: pointer.func */
            4097, 8, 0, /* 635: pointer.func */
            4097, 8, 0, /* 638: pointer.func */
            4097, 8, 0, /* 641: pointer.func */
            1, 8, 1, /* 644: pointer.struct.store_method_st */
            	649, 0,
            0, 0, 0, /* 649: struct.store_method_st */
            4097, 8, 0, /* 652: pointer.func */
            4097, 8, 0, /* 655: pointer.func */
            4097, 8, 0, /* 658: pointer.func */
            4097, 8, 0, /* 661: pointer.func */
            4097, 8, 0, /* 664: pointer.func */
            4097, 8, 0, /* 667: pointer.func */
            4097, 8, 0, /* 670: pointer.func */
            4097, 8, 0, /* 673: pointer.func */
            1, 8, 1, /* 676: pointer.struct.ENGINE_CMD_DEFN_st */
            	681, 0,
            0, 32, 2, /* 681: struct.ENGINE_CMD_DEFN_st */
            	59, 8,
            	59, 16,
            0, 16, 1, /* 688: struct.crypto_ex_data_st */
            	37, 0,
            1, 8, 1, /* 693: pointer.struct.x509_cinf_st */
            	698, 0,
            0, 104, 11, /* 698: struct.x509_cinf_st */
            	110, 0,
            	110, 8,
            	144, 16,
            	86, 24,
            	723, 32,
            	86, 40,
            	735, 48,
            	110, 56,
            	110, 64,
            	37, 72,
            	185, 80,
            1, 8, 1, /* 723: pointer.struct.X509_val_st */
            	728, 0,
            0, 16, 2, /* 728: struct.X509_val_st */
            	110, 0,
            	110, 8,
            1, 8, 1, /* 735: pointer.struct.X509_pubkey_st */
            	248, 0,
            1, 8, 1, /* 740: pointer.struct.X509_POLICY_LEVEL_st */
            	745, 0,
            0, 32, 3, /* 745: struct.X509_POLICY_LEVEL_st */
            	754, 0,
            	37, 8,
            	195, 16,
            1, 8, 1, /* 754: pointer.struct.x509_st */
            	759, 0,
            0, 184, 12, /* 759: struct.x509_st */
            	693, 0,
            	144, 8,
            	110, 16,
            	59, 32,
            	688, 40,
            	110, 104,
            	786, 112,
            	800, 120,
            	37, 128,
            	37, 136,
            	812, 144,
            	824, 176,
            1, 8, 1, /* 786: pointer.struct.AUTHORITY_KEYID_st */
            	791, 0,
            0, 24, 3, /* 791: struct.AUTHORITY_KEYID_st */
            	110, 0,
            	37, 8,
            	110, 16,
            1, 8, 1, /* 800: pointer.struct.X509_POLICY_CACHE_st */
            	805, 0,
            0, 40, 2, /* 805: struct.X509_POLICY_CACHE_st */
            	207, 0,
            	37, 8,
            1, 8, 1, /* 812: pointer.struct.NAME_CONSTRAINTS_st */
            	817, 0,
            0, 16, 2, /* 817: struct.NAME_CONSTRAINTS_st */
            	37, 0,
            	37, 8,
            1, 8, 1, /* 824: pointer.struct.x509_cert_aux_st */
            	829, 0,
            0, 40, 5, /* 829: struct.x509_cert_aux_st */
            	37, 0,
            	37, 8,
            	110, 16,
            	110, 24,
            	37, 32,
            1, 8, 1, /* 842: pointer.struct.X509_POLICY_TREE_st */
            	847, 0,
            0, 48, 4, /* 847: struct.X509_POLICY_TREE_st */
            	740, 0,
            	37, 16,
            	37, 24,
            	37, 32,
            0, 20, 0, /* 858: array[20].char */
            0, 0, 0, /* 861: func */
            0, 0, 0, /* 864: func */
            0, 0, 0, /* 867: func */
            0, 0, 0, /* 870: func */
            0, 0, 0, /* 873: func */
            0, 0, 0, /* 876: func */
            0, 0, 0, /* 879: func */
            0, 0, 0, /* 882: func */
            0, 0, 0, /* 885: func */
            0, 0, 0, /* 888: func */
            0, 0, 0, /* 891: func */
            0, 0, 0, /* 894: func */
            0, 0, 0, /* 897: func */
            1, 8, 1, /* 900: pointer.struct.X509_crl_st */
            	905, 0,
            0, 120, 10, /* 905: struct.X509_crl_st */
            	120, 0,
            	144, 8,
            	110, 16,
            	786, 32,
            	190, 40,
            	110, 56,
            	110, 64,
            	37, 96,
            	928, 104,
            	0, 112,
            1, 8, 1, /* 928: pointer.struct.x509_crl_method_st */
            	15, 0,
            0, 0, 0, /* 933: func */
            0, 0, 0, /* 936: func */
            1, 8, 1, /* 939: pointer.struct.X509_pubkey_st */
            	944, 0,
            0, 24, 3, /* 944: struct.X509_pubkey_st */
            	144, 0,
            	110, 8,
            	953, 16,
            1, 8, 1, /* 953: pointer.struct.evp_pkey_st */
            	958, 0,
            0, 56, 4, /* 958: struct.evp_pkey_st */
            	969, 16,
            	367, 24,
            	180, 32,
            	37, 48,
            1, 8, 1, /* 969: pointer.struct.evp_pkey_asn1_method_st */
            	974, 0,
            0, 208, 24, /* 974: struct.evp_pkey_asn1_method_st */
            	59, 16,
            	59, 24,
            	1025, 32,
            	1028, 40,
            	1031, 48,
            	1034, 56,
            	1037, 64,
            	1040, 72,
            	1034, 80,
            	1043, 88,
            	1043, 96,
            	1046, 104,
            	1049, 112,
            	1043, 120,
            	1031, 128,
            	1031, 136,
            	1034, 144,
            	352, 152,
            	1052, 160,
            	1055, 168,
            	1046, 176,
            	1049, 184,
            	1058, 192,
            	364, 200,
            4097, 8, 0, /* 1025: pointer.func */
            4097, 8, 0, /* 1028: pointer.func */
            4097, 8, 0, /* 1031: pointer.func */
            4097, 8, 0, /* 1034: pointer.func */
            4097, 8, 0, /* 1037: pointer.func */
            4097, 8, 0, /* 1040: pointer.func */
            4097, 8, 0, /* 1043: pointer.func */
            4097, 8, 0, /* 1046: pointer.func */
            4097, 8, 0, /* 1049: pointer.func */
            4097, 8, 0, /* 1052: pointer.func */
            4097, 8, 0, /* 1055: pointer.func */
            4097, 8, 0, /* 1058: pointer.func */
            0, 0, 0, /* 1061: func */
            0, 104, 11, /* 1064: struct.x509_cinf_st */
            	110, 0,
            	110, 8,
            	144, 16,
            	86, 24,
            	723, 32,
            	86, 40,
            	939, 48,
            	110, 56,
            	110, 64,
            	37, 72,
            	185, 80,
            0, 0, 0, /* 1089: func */
            1, 8, 1, /* 1092: pointer.struct.x509_cinf_st */
            	1064, 0,
            0, 0, 0, /* 1097: func */
            4097, 8, 0, /* 1100: pointer.func */
            0, 0, 0, /* 1103: func */
            0, 0, 0, /* 1106: func */
            0, 1, 0, /* 1109: char */
            1, 8, 1, /* 1112: pointer.struct.x509_st */
            	1117, 0,
            0, 184, 12, /* 1117: struct.x509_st */
            	1092, 0,
            	144, 8,
            	110, 16,
            	59, 32,
            	688, 40,
            	110, 104,
            	786, 112,
            	800, 120,
            	37, 128,
            	37, 136,
            	812, 144,
            	824, 176,
            0, 0, 0, /* 1144: func */
            1, 8, 1, /* 1147: pointer.struct.x509_store_st */
            	1152, 0,
            0, 144, 15, /* 1152: struct.x509_store_st */
            	37, 8,
            	37, 16,
            	1185, 24,
            	329, 32,
            	1197, 40,
            	1200, 48,
            	1203, 56,
            	329, 64,
            	1206, 72,
            	1209, 80,
            	1212, 88,
            	1100, 96,
            	1100, 104,
            	329, 112,
            	688, 120,
            1, 8, 1, /* 1185: pointer.struct.X509_VERIFY_PARAM_st */
            	1190, 0,
            0, 56, 2, /* 1190: struct.X509_VERIFY_PARAM_st */
            	59, 0,
            	37, 48,
            4097, 8, 0, /* 1197: pointer.func */
            4097, 8, 0, /* 1200: pointer.func */
            4097, 8, 0, /* 1203: pointer.func */
            4097, 8, 0, /* 1206: pointer.func */
            4097, 8, 0, /* 1209: pointer.func */
            4097, 8, 0, /* 1212: pointer.func */
            0, 0, 0, /* 1215: func */
            0, 0, 0, /* 1218: func */
            0, 0, 0, /* 1221: func */
            0, 0, 0, /* 1224: func */
            0, 0, 0, /* 1227: func */
            0, 248, 25, /* 1230: struct.x509_store_ctx_st */
            	1147, 0,
            	1112, 16,
            	37, 24,
            	37, 32,
            	1185, 40,
            	0, 48,
            	329, 56,
            	1197, 64,
            	1200, 72,
            	1203, 80,
            	329, 88,
            	1206, 96,
            	1209, 104,
            	1212, 112,
            	329, 120,
            	1100, 128,
            	1100, 136,
            	329, 144,
            	37, 160,
            	842, 168,
            	1112, 192,
            	1112, 200,
            	900, 208,
            	1283, 224,
            	688, 232,
            1, 8, 1, /* 1283: pointer.struct.x509_store_ctx_st */
            	1230, 0,
            0, 0, 0, /* 1288: func */
            0, 0, 0, /* 1291: func */
            0, 0, 0, /* 1294: func */
            0, 4, 0, /* 1297: int */
            0, 0, 0, /* 1300: func */
            0, 8, 0, /* 1303: long */
            0, 0, 0, /* 1306: func */
            0, 0, 0, /* 1309: func */
            0, 0, 0, /* 1312: func */
            0, 0, 0, /* 1315: func */
            0, 0, 0, /* 1318: func */
            0, 0, 0, /* 1321: func */
            0, 0, 0, /* 1324: func */
            0, 0, 0, /* 1327: func */
            0, 0, 0, /* 1330: func */
            0, 0, 0, /* 1333: func */
            0, 0, 0, /* 1336: func */
            0, 0, 0, /* 1339: func */
            0, 0, 0, /* 1342: func */
            0, 0, 0, /* 1345: func */
            0, 0, 0, /* 1348: func */
            0, 0, 0, /* 1351: func */
            0, 0, 0, /* 1354: func */
            0, 0, 0, /* 1357: func */
            0, 0, 0, /* 1360: func */
            0, 0, 0, /* 1363: func */
            0, 0, 0, /* 1366: func */
            0, 0, 0, /* 1369: func */
            0, 0, 0, /* 1372: func */
            0, 0, 0, /* 1375: func */
            0, 0, 0, /* 1378: func */
            0, 0, 0, /* 1381: func */
            0, 0, 0, /* 1384: func */
            0, 0, 0, /* 1387: func */
            0, 0, 0, /* 1390: func */
            0, 0, 0, /* 1393: func */
            0, 0, 0, /* 1396: func */
            0, 0, 0, /* 1399: func */
        },
        .arg_entity_index = { 1283, },
        .ret_entity_index = 1297,
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

