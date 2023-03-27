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

void SSL_CTX_sess_set_new_cb(SSL_CTX * arg_a,int (*arg_b)(struct ssl_st *, SSL_SESSION *)) 
{
    printf("SSL_CTX_sess_set_new_cb called\n");
    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 0, 0, /* 0: func */
            0, 0, 0, /* 3: func */
            1, 8, 1, /* 6: pointer.func */
            	3, 0,
            1, 8, 1, /* 11: pointer.func */
            	16, 0,
            0, 0, 0, /* 16: func */
            0, 128, 14, /* 19: struct.srp_ctx_st.921 */
            	50, 0,
            	58, 8,
            	66, 16,
            	11, 24,
            	50, 32,
            	74, 40,
            	74, 48,
            	74, 56,
            	74, 64,
            	74, 72,
            	74, 80,
            	74, 88,
            	74, 96,
            	50, 104,
            1, 8, 1, /* 50: pointer.char */
            	55, 0,
            0, 1, 0, /* 55: char */
            1, 8, 1, /* 58: pointer.func */
            	63, 0,
            0, 0, 0, /* 63: func */
            1, 8, 1, /* 66: pointer.func */
            	71, 0,
            0, 0, 0, /* 71: func */
            1, 8, 1, /* 74: pointer.struct.bignum_st */
            	79, 0,
            0, 24, 1, /* 79: struct.bignum_st */
            	84, 0,
            1, 8, 1, /* 84: pointer.int */
            	89, 0,
            0, 4, 0, /* 89: int */
            1, 8, 1, /* 92: pointer.struct.ssl3_buf_freelist_entry_st */
            	97, 0,
            0, 8, 1, /* 97: struct.ssl3_buf_freelist_entry_st */
            	92, 0,
            0, 0, 0, /* 102: func */
            0, 16, 0, /* 105: array[16].char */
            1, 8, 1, /* 108: pointer.func */
            	113, 0,
            0, 0, 0, /* 113: func */
            0, 0, 0, /* 116: func */
            0, 0, 0, /* 119: func */
            0, 0, 0, /* 122: func */
            1, 8, 1, /* 125: pointer.func */
            	122, 0,
            0, 296, 8, /* 130: struct.cert_st.915 */
            	149, 0,
            	1196, 48,
            	125, 56,
            	1279, 64,
            	1311, 72,
            	1316, 80,
            	1672, 88,
            	1677, 96,
            1, 8, 1, /* 149: pointer.struct.cert_pkey_st */
            	154, 0,
            0, 24, 3, /* 154: struct.cert_pkey_st */
            	163, 0,
            	356, 8,
            	1116, 16,
            1, 8, 1, /* 163: pointer.struct.x509_st */
            	168, 0,
            0, 184, 12, /* 168: struct.x509_st */
            	195, 0,
            	235, 8,
            	225, 16,
            	50, 32,
            	1036, 40,
            	225, 104,
            	1046, 112,
            	1060, 120,
            	290, 128,
            	290, 136,
            	1086, 144,
            	1098, 176,
            1, 8, 1, /* 195: pointer.struct.x509_cinf_st */
            	200, 0,
            0, 104, 11, /* 200: struct.x509_cinf_st */
            	225, 0,
            	225, 8,
            	235, 16,
            	276, 24,
            	330, 32,
            	276, 40,
            	342, 48,
            	225, 56,
            	225, 64,
            	290, 72,
            	1041, 80,
            1, 8, 1, /* 225: pointer.struct.asn1_string_st */
            	230, 0,
            0, 24, 1, /* 230: struct.asn1_string_st */
            	50, 8,
            1, 8, 1, /* 235: pointer.struct.X509_algor_st */
            	240, 0,
            0, 16, 2, /* 240: struct.X509_algor_st */
            	247, 0,
            	261, 8,
            1, 8, 1, /* 247: pointer.struct.asn1_object_st */
            	252, 0,
            0, 40, 3, /* 252: struct.asn1_object_st */
            	50, 0,
            	50, 8,
            	50, 24,
            1, 8, 1, /* 261: pointer.struct.asn1_type_st */
            	266, 0,
            0, 16, 1, /* 266: struct.asn1_type_st */
            	271, 8,
            0, 8, 1, /* 271: struct.fnames */
            	50, 0,
            1, 8, 1, /* 276: pointer.struct.X509_name_st */
            	281, 0,
            0, 40, 3, /* 281: struct.X509_name_st */
            	290, 0,
            	320, 16,
            	50, 24,
            1, 8, 1, /* 290: pointer.struct.stack_st_OPENSSL_STRING */
            	295, 0,
            0, 32, 1, /* 295: struct.stack_st_OPENSSL_STRING */
            	300, 0,
            0, 32, 2, /* 300: struct.stack_st */
            	307, 8,
            	312, 24,
            1, 8, 1, /* 307: pointer.pointer.char */
            	50, 0,
            1, 8, 1, /* 312: pointer.func */
            	317, 0,
            0, 0, 0, /* 317: func */
            1, 8, 1, /* 320: pointer.struct.buf_mem_st */
            	325, 0,
            0, 24, 1, /* 325: struct.buf_mem_st */
            	50, 8,
            1, 8, 1, /* 330: pointer.struct.X509_val_st */
            	335, 0,
            0, 16, 2, /* 335: struct.X509_val_st */
            	225, 0,
            	225, 8,
            1, 8, 1, /* 342: pointer.struct.X509_pubkey_st */
            	347, 0,
            0, 24, 3, /* 347: struct.X509_pubkey_st */
            	235, 0,
            	225, 8,
            	356, 16,
            1, 8, 1, /* 356: pointer.struct.evp_pkey_st */
            	361, 0,
            0, 56, 4, /* 361: struct.evp_pkey_st */
            	372, 16,
            	540, 24,
            	271, 32,
            	290, 48,
            1, 8, 1, /* 372: pointer.struct.evp_pkey_asn1_method_st */
            	377, 0,
            0, 208, 24, /* 377: struct.evp_pkey_asn1_method_st */
            	50, 16,
            	50, 24,
            	428, 32,
            	436, 40,
            	444, 48,
            	452, 56,
            	460, 64,
            	468, 72,
            	452, 80,
            	476, 88,
            	476, 96,
            	484, 104,
            	492, 112,
            	476, 120,
            	444, 128,
            	444, 136,
            	452, 144,
            	500, 152,
            	508, 160,
            	516, 168,
            	484, 176,
            	492, 184,
            	524, 192,
            	532, 200,
            1, 8, 1, /* 428: pointer.struct.unnamed */
            	433, 0,
            0, 0, 0, /* 433: struct.unnamed */
            1, 8, 1, /* 436: pointer.func */
            	441, 0,
            0, 0, 0, /* 441: func */
            1, 8, 1, /* 444: pointer.func */
            	449, 0,
            0, 0, 0, /* 449: func */
            1, 8, 1, /* 452: pointer.func */
            	457, 0,
            0, 0, 0, /* 457: func */
            1, 8, 1, /* 460: pointer.func */
            	465, 0,
            0, 0, 0, /* 465: func */
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
            1, 8, 1, /* 524: pointer.func */
            	529, 0,
            0, 0, 0, /* 529: func */
            1, 8, 1, /* 532: pointer.func */
            	537, 0,
            0, 0, 0, /* 537: func */
            1, 8, 1, /* 540: pointer.struct.engine_st */
            	545, 0,
            0, 216, 24, /* 545: struct.engine_st */
            	50, 0,
            	50, 8,
            	596, 16,
            	686, 24,
            	772, 32,
            	828, 40,
            	850, 48,
            	892, 56,
            	952, 64,
            	960, 72,
            	968, 80,
            	976, 88,
            	984, 96,
            	992, 104,
            	992, 112,
            	992, 120,
            	1000, 128,
            	1008, 136,
            	1008, 144,
            	1016, 152,
            	1024, 160,
            	1036, 184,
            	540, 200,
            	540, 208,
            1, 8, 1, /* 596: pointer.struct.rsa_meth_st */
            	601, 0,
            0, 112, 13, /* 601: struct.rsa_meth_st */
            	50, 0,
            	630, 8,
            	630, 16,
            	630, 24,
            	630, 32,
            	638, 40,
            	646, 48,
            	654, 56,
            	654, 64,
            	50, 80,
            	662, 88,
            	670, 96,
            	678, 104,
            1, 8, 1, /* 630: pointer.func */
            	635, 0,
            0, 0, 0, /* 635: func */
            1, 8, 1, /* 638: pointer.func */
            	643, 0,
            0, 0, 0, /* 643: func */
            1, 8, 1, /* 646: pointer.func */
            	651, 0,
            0, 0, 0, /* 651: func */
            1, 8, 1, /* 654: pointer.func */
            	659, 0,
            0, 0, 0, /* 659: func */
            1, 8, 1, /* 662: pointer.func */
            	667, 0,
            0, 0, 0, /* 667: func */
            1, 8, 1, /* 670: pointer.func */
            	675, 0,
            0, 0, 0, /* 675: func */
            1, 8, 1, /* 678: pointer.func */
            	683, 0,
            0, 0, 0, /* 683: func */
            1, 8, 1, /* 686: pointer.struct.dsa_method.1040 */
            	691, 0,
            0, 96, 11, /* 691: struct.dsa_method.1040 */
            	50, 0,
            	716, 8,
            	724, 16,
            	732, 24,
            	740, 32,
            	748, 40,
            	756, 48,
            	756, 56,
            	50, 72,
            	764, 80,
            	756, 88,
            1, 8, 1, /* 716: pointer.func */
            	721, 0,
            0, 0, 0, /* 721: func */
            1, 8, 1, /* 724: pointer.func */
            	729, 0,
            0, 0, 0, /* 729: func */
            1, 8, 1, /* 732: pointer.func */
            	737, 0,
            0, 0, 0, /* 737: func */
            1, 8, 1, /* 740: pointer.func */
            	745, 0,
            0, 0, 0, /* 745: func */
            1, 8, 1, /* 748: pointer.func */
            	753, 0,
            0, 0, 0, /* 753: func */
            1, 8, 1, /* 756: pointer.func */
            	761, 0,
            0, 0, 0, /* 761: func */
            1, 8, 1, /* 764: pointer.func */
            	769, 0,
            0, 0, 0, /* 769: func */
            1, 8, 1, /* 772: pointer.struct.dh_method */
            	777, 0,
            0, 72, 8, /* 777: struct.dh_method */
            	50, 0,
            	796, 8,
            	804, 16,
            	812, 24,
            	796, 32,
            	796, 40,
            	50, 56,
            	820, 64,
            1, 8, 1, /* 796: pointer.func */
            	801, 0,
            0, 0, 0, /* 801: func */
            1, 8, 1, /* 804: pointer.func */
            	809, 0,
            0, 0, 0, /* 809: func */
            1, 8, 1, /* 812: pointer.func */
            	817, 0,
            0, 0, 0, /* 817: func */
            1, 8, 1, /* 820: pointer.func */
            	825, 0,
            0, 0, 0, /* 825: func */
            1, 8, 1, /* 828: pointer.struct.ecdh_method */
            	833, 0,
            0, 32, 3, /* 833: struct.ecdh_method */
            	50, 0,
            	842, 8,
            	50, 24,
            1, 8, 1, /* 842: pointer.func */
            	847, 0,
            0, 0, 0, /* 847: func */
            1, 8, 1, /* 850: pointer.struct.ecdsa_method */
            	855, 0,
            0, 48, 5, /* 855: struct.ecdsa_method */
            	50, 0,
            	868, 8,
            	876, 16,
            	884, 24,
            	50, 40,
            1, 8, 1, /* 868: pointer.func */
            	873, 0,
            0, 0, 0, /* 873: func */
            1, 8, 1, /* 876: pointer.func */
            	881, 0,
            0, 0, 0, /* 881: func */
            1, 8, 1, /* 884: pointer.func */
            	889, 0,
            0, 0, 0, /* 889: func */
            1, 8, 1, /* 892: pointer.struct.rand_meth_st */
            	897, 0,
            0, 48, 6, /* 897: struct.rand_meth_st */
            	912, 0,
            	920, 8,
            	928, 16,
            	936, 24,
            	920, 32,
            	944, 40,
            1, 8, 1, /* 912: pointer.func */
            	917, 0,
            0, 0, 0, /* 917: func */
            1, 8, 1, /* 920: pointer.func */
            	925, 0,
            0, 0, 0, /* 925: func */
            1, 8, 1, /* 928: pointer.func */
            	933, 0,
            0, 0, 0, /* 933: func */
            1, 8, 1, /* 936: pointer.func */
            	941, 0,
            0, 0, 0, /* 941: func */
            1, 8, 1, /* 944: pointer.func */
            	949, 0,
            0, 0, 0, /* 949: func */
            1, 8, 1, /* 952: pointer.struct.store_method_st */
            	957, 0,
            0, 0, 0, /* 957: struct.store_method_st */
            1, 8, 1, /* 960: pointer.func */
            	965, 0,
            0, 0, 0, /* 965: func */
            1, 8, 1, /* 968: pointer.func */
            	973, 0,
            0, 0, 0, /* 973: func */
            1, 8, 1, /* 976: pointer.func */
            	981, 0,
            0, 0, 0, /* 981: func */
            1, 8, 1, /* 984: pointer.func */
            	989, 0,
            0, 0, 0, /* 989: func */
            1, 8, 1, /* 992: pointer.func */
            	997, 0,
            0, 0, 0, /* 997: func */
            1, 8, 1, /* 1000: pointer.func */
            	1005, 0,
            0, 0, 0, /* 1005: func */
            1, 8, 1, /* 1008: pointer.func */
            	1013, 0,
            0, 0, 0, /* 1013: func */
            1, 8, 1, /* 1016: pointer.func */
            	1021, 0,
            0, 0, 0, /* 1021: func */
            1, 8, 1, /* 1024: pointer.struct.ENGINE_CMD_DEFN_st */
            	1029, 0,
            0, 32, 2, /* 1029: struct.ENGINE_CMD_DEFN_st */
            	50, 8,
            	50, 16,
            0, 16, 1, /* 1036: struct.crypto_ex_data_st */
            	290, 0,
            0, 24, 1, /* 1041: struct.ASN1_ENCODING_st */
            	50, 0,
            1, 8, 1, /* 1046: pointer.struct.AUTHORITY_KEYID_st */
            	1051, 0,
            0, 24, 3, /* 1051: struct.AUTHORITY_KEYID_st */
            	225, 0,
            	290, 8,
            	225, 16,
            1, 8, 1, /* 1060: pointer.struct.X509_POLICY_CACHE_st */
            	1065, 0,
            0, 40, 2, /* 1065: struct.X509_POLICY_CACHE_st */
            	1072, 0,
            	290, 8,
            1, 8, 1, /* 1072: pointer.struct.X509_POLICY_DATA_st */
            	1077, 0,
            0, 32, 3, /* 1077: struct.X509_POLICY_DATA_st */
            	247, 8,
            	290, 16,
            	290, 24,
            1, 8, 1, /* 1086: pointer.struct.NAME_CONSTRAINTS_st */
            	1091, 0,
            0, 16, 2, /* 1091: struct.NAME_CONSTRAINTS_st */
            	290, 0,
            	290, 8,
            1, 8, 1, /* 1098: pointer.struct.x509_cert_aux_st */
            	1103, 0,
            0, 40, 5, /* 1103: struct.x509_cert_aux_st */
            	290, 0,
            	290, 8,
            	225, 16,
            	225, 24,
            	290, 32,
            1, 8, 1, /* 1116: pointer.struct.env_md_st */
            	1121, 0,
            0, 120, 8, /* 1121: struct.env_md_st */
            	1140, 24,
            	1148, 32,
            	1156, 40,
            	1164, 48,
            	1140, 56,
            	1172, 64,
            	1180, 72,
            	1188, 112,
            1, 8, 1, /* 1140: pointer.func */
            	1145, 0,
            0, 0, 0, /* 1145: func */
            1, 8, 1, /* 1148: pointer.func */
            	1153, 0,
            0, 0, 0, /* 1153: func */
            1, 8, 1, /* 1156: pointer.func */
            	1161, 0,
            0, 0, 0, /* 1161: func */
            1, 8, 1, /* 1164: pointer.func */
            	1169, 0,
            0, 0, 0, /* 1169: func */
            1, 8, 1, /* 1172: pointer.func */
            	1177, 0,
            0, 0, 0, /* 1177: func */
            1, 8, 1, /* 1180: pointer.func */
            	1185, 0,
            0, 0, 0, /* 1185: func */
            1, 8, 1, /* 1188: pointer.func */
            	1193, 0,
            0, 0, 0, /* 1193: func */
            1, 8, 1, /* 1196: pointer.struct.rsa_st */
            	1201, 0,
            0, 168, 17, /* 1201: struct.rsa_st */
            	596, 16,
            	540, 24,
            	74, 32,
            	74, 40,
            	74, 48,
            	74, 56,
            	74, 64,
            	74, 72,
            	74, 80,
            	74, 88,
            	1036, 96,
            	1238, 120,
            	1238, 128,
            	1238, 136,
            	50, 144,
            	1252, 152,
            	1252, 160,
            1, 8, 1, /* 1238: pointer.struct.bn_mont_ctx_st */
            	1243, 0,
            0, 96, 3, /* 1243: struct.bn_mont_ctx_st */
            	79, 8,
            	79, 32,
            	79, 56,
            1, 8, 1, /* 1252: pointer.struct.bn_blinding_st */
            	1257, 0,
            0, 88, 7, /* 1257: struct.bn_blinding_st */
            	74, 0,
            	74, 8,
            	74, 16,
            	74, 24,
            	1274, 40,
            	1238, 72,
            	646, 80,
            0, 16, 1, /* 1274: struct.iovec */
            	50, 0,
            1, 8, 1, /* 1279: pointer.struct.dh_st */
            	1284, 0,
            0, 144, 12, /* 1284: struct.dh_st */
            	74, 8,
            	74, 16,
            	74, 32,
            	74, 40,
            	1238, 56,
            	74, 64,
            	74, 72,
            	50, 80,
            	74, 96,
            	1036, 112,
            	772, 128,
            	540, 136,
            1, 8, 1, /* 1311: pointer.func */
            	119, 0,
            1, 8, 1, /* 1316: pointer.struct.ec_key_st.284 */
            	1321, 0,
            0, 56, 4, /* 1321: struct.ec_key_st.284 */
            	1332, 8,
            	1614, 16,
            	74, 24,
            	1630, 48,
            1, 8, 1, /* 1332: pointer.struct.ec_group_st */
            	1337, 0,
            0, 232, 12, /* 1337: struct.ec_group_st */
            	1364, 0,
            	1614, 8,
            	79, 16,
            	79, 40,
            	50, 80,
            	1630, 96,
            	79, 104,
            	79, 152,
            	79, 176,
            	50, 208,
            	50, 216,
            	1664, 224,
            1, 8, 1, /* 1364: pointer.struct.ec_method_st */
            	1369, 0,
            0, 304, 37, /* 1369: struct.ec_method_st */
            	1446, 8,
            	1454, 16,
            	1454, 24,
            	1462, 32,
            	1470, 40,
            	1470, 48,
            	1446, 56,
            	1478, 64,
            	1486, 72,
            	1494, 80,
            	1494, 88,
            	1502, 96,
            	1510, 104,
            	1518, 112,
            	1518, 120,
            	1526, 128,
            	1526, 136,
            	1534, 144,
            	1542, 152,
            	1550, 160,
            	1558, 168,
            	1566, 176,
            	1574, 184,
            	1510, 192,
            	1574, 200,
            	1566, 208,
            	1574, 216,
            	1582, 224,
            	1590, 232,
            	1478, 240,
            	1446, 248,
            	1470, 256,
            	1598, 264,
            	1470, 272,
            	1598, 280,
            	1598, 288,
            	1606, 296,
            1, 8, 1, /* 1446: pointer.func */
            	1451, 0,
            0, 0, 0, /* 1451: func */
            1, 8, 1, /* 1454: pointer.func */
            	1459, 0,
            0, 0, 0, /* 1459: func */
            1, 8, 1, /* 1462: pointer.func */
            	1467, 0,
            0, 0, 0, /* 1467: func */
            1, 8, 1, /* 1470: pointer.func */
            	1475, 0,
            0, 0, 0, /* 1475: func */
            1, 8, 1, /* 1478: pointer.func */
            	1483, 0,
            0, 0, 0, /* 1483: func */
            1, 8, 1, /* 1486: pointer.func */
            	1491, 0,
            0, 0, 0, /* 1491: func */
            1, 8, 1, /* 1494: pointer.func */
            	1499, 0,
            0, 0, 0, /* 1499: func */
            1, 8, 1, /* 1502: pointer.func */
            	1507, 0,
            0, 0, 0, /* 1507: func */
            1, 8, 1, /* 1510: pointer.func */
            	1515, 0,
            0, 0, 0, /* 1515: func */
            1, 8, 1, /* 1518: pointer.func */
            	1523, 0,
            0, 0, 0, /* 1523: func */
            1, 8, 1, /* 1526: pointer.func */
            	1531, 0,
            0, 0, 0, /* 1531: func */
            1, 8, 1, /* 1534: pointer.func */
            	1539, 0,
            0, 0, 0, /* 1539: func */
            1, 8, 1, /* 1542: pointer.func */
            	1547, 0,
            0, 0, 0, /* 1547: func */
            1, 8, 1, /* 1550: pointer.func */
            	1555, 0,
            0, 0, 0, /* 1555: func */
            1, 8, 1, /* 1558: pointer.func */
            	1563, 0,
            0, 0, 0, /* 1563: func */
            1, 8, 1, /* 1566: pointer.func */
            	1571, 0,
            0, 0, 0, /* 1571: func */
            1, 8, 1, /* 1574: pointer.func */
            	1579, 0,
            0, 0, 0, /* 1579: func */
            1, 8, 1, /* 1582: pointer.func */
            	1587, 0,
            0, 0, 0, /* 1587: func */
            1, 8, 1, /* 1590: pointer.func */
            	1595, 0,
            0, 0, 0, /* 1595: func */
            1, 8, 1, /* 1598: pointer.func */
            	1603, 0,
            0, 0, 0, /* 1603: func */
            1, 8, 1, /* 1606: pointer.func */
            	1611, 0,
            0, 0, 0, /* 1611: func */
            1, 8, 1, /* 1614: pointer.struct.ec_point_st */
            	1619, 0,
            0, 88, 4, /* 1619: struct.ec_point_st */
            	1364, 0,
            	79, 8,
            	79, 32,
            	79, 56,
            1, 8, 1, /* 1630: pointer.struct.ec_extra_data_st */
            	1635, 0,
            0, 40, 5, /* 1635: struct.ec_extra_data_st */
            	1630, 0,
            	50, 8,
            	1648, 16,
            	1656, 24,
            	1656, 32,
            1, 8, 1, /* 1648: pointer.func */
            	1653, 0,
            0, 0, 0, /* 1653: func */
            1, 8, 1, /* 1656: pointer.func */
            	1661, 0,
            0, 0, 0, /* 1661: func */
            1, 8, 1, /* 1664: pointer.func */
            	1669, 0,
            0, 0, 0, /* 1669: func */
            1, 8, 1, /* 1672: pointer.func */
            	116, 0,
            0, 192, 8, /* 1677: array[8].struct.cert_pkey_st */
            	154, 0,
            	154, 24,
            	154, 48,
            	154, 72,
            	154, 96,
            	154, 120,
            	154, 144,
            	154, 168,
            1, 8, 1, /* 1696: pointer.struct.cert_st.915 */
            	130, 0,
            1, 8, 1, /* 1701: pointer.func */
            	1706, 0,
            0, 0, 0, /* 1706: func */
            0, 0, 0, /* 1709: func */
            1, 8, 1, /* 1712: pointer.func */
            	1709, 0,
            0, 0, 0, /* 1717: func */
            1, 8, 1, /* 1720: pointer.func */
            	1717, 0,
            0, 0, 0, /* 1725: func */
            1, 8, 1, /* 1728: pointer.func */
            	1725, 0,
            0, 44, 0, /* 1733: struct.apr_time_exp_t */
            1, 8, 1, /* 1736: pointer.func */
            	1741, 0,
            0, 0, 0, /* 1741: func */
            0, 0, 0, /* 1744: func */
            1, 8, 1, /* 1747: pointer.func */
            	1744, 0,
            1, 8, 1, /* 1752: pointer.func */
            	1757, 0,
            0, 0, 0, /* 1757: func */
            1, 8, 1, /* 1760: pointer.struct.ssl_cipher_st */
            	1765, 0,
            0, 88, 1, /* 1765: struct.ssl_cipher_st */
            	50, 8,
            1, 8, 1, /* 1770: pointer.func */
            	1775, 0,
            0, 0, 0, /* 1775: func */
            1, 8, 1, /* 1778: pointer.func */
            	102, 0,
            1, 8, 1, /* 1783: pointer.func */
            	1788, 0,
            0, 0, 0, /* 1788: func */
            1, 8, 1, /* 1791: pointer.func */
            	0, 0,
            0, 8, 0, /* 1796: array[2].int */
            0, 20, 0, /* 1799: array[5].int */
            0, 0, 0, /* 1802: func */
            0, 4, 0, /* 1805: struct.in_addr */
            0, 248, 6, /* 1808: struct.sess_cert_st */
            	290, 0,
            	149, 16,
            	1677, 24,
            	1196, 216,
            	1279, 224,
            	1316, 232,
            1, 8, 1, /* 1823: pointer.struct.in_addr */
            	1805, 0,
            0, 0, 0, /* 1828: func */
            1, 8, 1, /* 1831: pointer.func */
            	1828, 0,
            1, 8, 1, /* 1836: pointer.func */
            	1841, 0,
            0, 0, 0, /* 1841: func */
            0, 0, 0, /* 1844: func */
            1, 8, 1, /* 1847: pointer.func */
            	1844, 0,
            1, 8, 1, /* 1852: pointer.func */
            	1857, 0,
            0, 0, 0, /* 1857: func */
            1, 8, 1, /* 1860: pointer.func */
            	1865, 0,
            0, 0, 0, /* 1865: func */
            1, 8, 1, /* 1868: pointer.func */
            	1873, 0,
            0, 0, 0, /* 1873: func */
            0, 8, 0, /* 1876: long */
            0, 56, 2, /* 1879: struct.X509_VERIFY_PARAM_st */
            	50, 0,
            	290, 48,
            1, 8, 1, /* 1886: pointer.struct.X509_VERIFY_PARAM_st */
            	1879, 0,
            0, 144, 15, /* 1891: struct.x509_store_st */
            	290, 8,
            	290, 16,
            	1886, 24,
            	1924, 32,
            	1932, 40,
            	1860, 48,
            	1940, 56,
            	1924, 64,
            	1852, 72,
            	1847, 80,
            	1836, 88,
            	1831, 96,
            	1831, 104,
            	1924, 112,
            	1036, 120,
            1, 8, 1, /* 1924: pointer.func */
            	1929, 0,
            0, 0, 0, /* 1929: func */
            1, 8, 1, /* 1932: pointer.func */
            	1937, 0,
            0, 0, 0, /* 1937: func */
            1, 8, 1, /* 1940: pointer.func */
            	1945, 0,
            0, 0, 0, /* 1945: func */
            1, 8, 1, /* 1948: pointer.struct.x509_store_st */
            	1891, 0,
            0, 0, 0, /* 1953: func */
            1, 8, 1, /* 1956: pointer.func */
            	1961, 0,
            0, 0, 0, /* 1961: func */
            0, 0, 0, /* 1964: func */
            0, 0, 0, /* 1967: func */
            1, 8, 1, /* 1970: pointer.func */
            	1975, 0,
            0, 0, 0, /* 1975: func */
            0, 736, 50, /* 1978: struct.ssl_ctx_st.922 */
            	2081, 0,
            	290, 8,
            	290, 16,
            	1948, 24,
            	1823, 32,
            	2310, 48,
            	2310, 56,
            	1752, 80,
            	1747, 88,
            	1736, 96,
            	2351, 152,
            	50, 160,
            	1728, 168,
            	50, 176,
            	1720, 184,
            	1712, 192,
            	1868, 200,
            	1036, 208,
            	1116, 224,
            	1116, 232,
            	1116, 240,
            	290, 248,
            	290, 256,
            	1701, 264,
            	290, 272,
            	1696, 304,
            	108, 320,
            	50, 328,
            	1932, 376,
            	1712, 384,
            	1886, 392,
            	540, 408,
            	58, 416,
            	50, 424,
            	1778, 480,
            	66, 488,
            	50, 496,
            	1783, 504,
            	50, 512,
            	50, 520,
            	1770, 528,
            	2257, 536,
            	2356, 552,
            	2356, 560,
            	19, 568,
            	6, 696,
            	50, 704,
            	1791, 712,
            	50, 720,
            	290, 728,
            1, 8, 1, /* 2081: pointer.struct.ssl_method_st.924 */
            	2086, 0,
            0, 232, 28, /* 2086: struct.ssl_method_st.924 */
            	2145, 8,
            	2153, 16,
            	2153, 24,
            	2145, 32,
            	2145, 40,
            	1868, 48,
            	1868, 56,
            	1868, 64,
            	2145, 72,
            	2145, 80,
            	2145, 88,
            	2161, 96,
            	2169, 104,
            	2177, 112,
            	2145, 120,
            	2185, 128,
            	2193, 136,
            	2201, 144,
            	1956, 152,
            	2145, 160,
            	944, 168,
            	1970, 176,
            	2206, 184,
            	2214, 192,
            	2219, 200,
            	944, 208,
            	2294, 216,
            	2302, 224,
            1, 8, 1, /* 2145: pointer.func */
            	2150, 0,
            0, 0, 0, /* 2150: func */
            1, 8, 1, /* 2153: pointer.func */
            	2158, 0,
            0, 0, 0, /* 2158: func */
            1, 8, 1, /* 2161: pointer.func */
            	2166, 0,
            0, 0, 0, /* 2166: func */
            1, 8, 1, /* 2169: pointer.func */
            	2174, 0,
            0, 0, 0, /* 2174: func */
            1, 8, 1, /* 2177: pointer.func */
            	2182, 0,
            0, 0, 0, /* 2182: func */
            1, 8, 1, /* 2185: pointer.func */
            	2190, 0,
            0, 0, 0, /* 2190: func */
            1, 8, 1, /* 2193: pointer.func */
            	2198, 0,
            0, 0, 0, /* 2198: func */
            1, 8, 1, /* 2201: pointer.func */
            	1967, 0,
            1, 8, 1, /* 2206: pointer.func */
            	2211, 0,
            0, 0, 0, /* 2211: func */
            1, 8, 1, /* 2214: pointer.func */
            	1953, 0,
            1, 8, 1, /* 2219: pointer.struct.ssl3_enc_method.923 */
            	2224, 0,
            0, 112, 11, /* 2224: struct.ssl3_enc_method.923 */
            	2249, 0,
            	1868, 8,
            	2145, 16,
            	2257, 24,
            	2249, 32,
            	2262, 40,
            	2270, 56,
            	50, 64,
            	50, 80,
            	2278, 96,
            	2286, 104,
            1, 8, 1, /* 2249: pointer.func */
            	2254, 0,
            0, 0, 0, /* 2254: func */
            1, 8, 1, /* 2257: pointer.func */
            	1964, 0,
            1, 8, 1, /* 2262: pointer.func */
            	2267, 0,
            0, 0, 0, /* 2267: func */
            1, 8, 1, /* 2270: pointer.func */
            	2275, 0,
            0, 0, 0, /* 2275: func */
            1, 8, 1, /* 2278: pointer.func */
            	2283, 0,
            0, 0, 0, /* 2283: func */
            1, 8, 1, /* 2286: pointer.func */
            	2291, 0,
            0, 0, 0, /* 2291: func */
            1, 8, 1, /* 2294: pointer.func */
            	2299, 0,
            0, 0, 0, /* 2299: func */
            1, 8, 1, /* 2302: pointer.func */
            	2307, 0,
            0, 0, 0, /* 2307: func */
            1, 8, 1, /* 2310: pointer.struct.ssl_session_st */
            	2315, 0,
            0, 352, 14, /* 2315: struct.ssl_session_st */
            	50, 144,
            	50, 152,
            	2346, 168,
            	163, 176,
            	1760, 224,
            	290, 240,
            	1036, 248,
            	2310, 264,
            	2310, 272,
            	50, 280,
            	50, 296,
            	50, 312,
            	50, 320,
            	50, 344,
            1, 8, 1, /* 2346: pointer.struct.sess_cert_st */
            	1808, 0,
            1, 8, 1, /* 2351: pointer.func */
            	1802, 0,
            1, 8, 1, /* 2356: pointer.struct.ssl3_buf_freelist_st */
            	2361, 0,
            0, 24, 1, /* 2361: struct.ssl3_buf_freelist_st */
            	92, 16,
            1, 8, 1, /* 2366: pointer.struct.ssl_ctx_st.922 */
            	1978, 0,
            0, 24, 0, /* 2371: array[6].int */
            0, 32, 0, /* 2374: array[32].char */
            0, 48, 0, /* 2377: array[48].char */
            0, 8, 0, /* 2380: array[8].char */
            0, 20, 0, /* 2383: array[20].char */
        },
        .arg_entity_index = { 2366, 1752, },
        .ret_entity_index = -1,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    SSL_CTX * new_arg_a = *((SSL_CTX * *)new_args->args[0]);

    int (*new_arg_b)(struct ssl_st *, SSL_SESSION *) = *((int (**)(struct ssl_st *, SSL_SESSION *))new_args->args[1]);

    void (*orig_SSL_CTX_sess_set_new_cb)(SSL_CTX *,int (*)(struct ssl_st *, SSL_SESSION *));
    orig_SSL_CTX_sess_set_new_cb = dlsym(RTLD_NEXT, "SSL_CTX_sess_set_new_cb");
    (*orig_SSL_CTX_sess_set_new_cb)(new_arg_a,new_arg_b);

    syscall(889);

}

