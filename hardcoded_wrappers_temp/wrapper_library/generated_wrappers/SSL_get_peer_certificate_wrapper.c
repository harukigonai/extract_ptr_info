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

X509 * bb_SSL_get_peer_certificate(const SSL * arg_a);

X509 * SSL_get_peer_certificate(const SSL * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_get_peer_certificate called %lu\n", in_lib);
    if (!in_lib)
        return bb_SSL_get_peer_certificate(arg_a);
    else {
        X509 * (*orig_SSL_get_peer_certificate)(const SSL *);
        orig_SSL_get_peer_certificate = dlsym(RTLD_NEXT, "SSL_get_peer_certificate");
        return orig_SSL_get_peer_certificate(arg_a);
    }
}

X509 * bb_SSL_get_peer_certificate(const SSL * arg_a) 
{
    X509 * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 0, 0, /* 0: func */
            4097, 8, 0, /* 3: pointer.func */
            4097, 8, 0, /* 6: pointer.func */
            0, 0, 0, /* 9: func */
            0, 0, 0, /* 12: func */
            4097, 8, 0, /* 15: pointer.func */
            0, 0, 0, /* 18: func */
            0, 0, 0, /* 21: func */
            4097, 8, 0, /* 24: pointer.func */
            0, 44, 0, /* 27: struct.apr_time_exp_t */
            0, 4, 0, /* 30: struct.in_addr */
            0, 8, 1, /* 33: pointer.struct.in_addr */
            	30, 0,
            0, 0, 0, /* 38: func */
            0, 0, 0, /* 41: func */
            4097, 8, 0, /* 44: pointer.func */
            0, 0, 0, /* 47: func */
            4097, 8, 0, /* 50: pointer.func */
            0, 0, 0, /* 53: func */
            0, 8, 1, /* 56: pointer.struct.x509_store_st */
            	61, 0,
            0, 144, 15, /* 61: struct.x509_store_st */
            	94, 8,
            	94, 16,
            	124, 24,
            	50, 32,
            	136, 40,
            	139, 48,
            	142, 56,
            	50, 64,
            	145, 72,
            	44, 80,
            	148, 88,
            	151, 96,
            	151, 104,
            	50, 112,
            	154, 120,
            0, 8, 1, /* 94: pointer.struct.stack_st_OPENSSL_STRING */
            	99, 0,
            0, 32, 1, /* 99: struct.stack_st_OPENSSL_STRING */
            	104, 0,
            0, 32, 2, /* 104: struct.stack_st */
            	111, 8,
            	121, 24,
            0, 8, 1, /* 111: pointer.pointer.char */
            	116, 0,
            0, 8, 1, /* 116: pointer.char */
            	4096, 0,
            4097, 8, 0, /* 121: pointer.func */
            0, 8, 1, /* 124: pointer.struct.X509_VERIFY_PARAM_st */
            	129, 0,
            0, 56, 2, /* 129: struct.X509_VERIFY_PARAM_st */
            	116, 0,
            	94, 48,
            4097, 8, 0, /* 136: pointer.func */
            4097, 8, 0, /* 139: pointer.func */
            4097, 8, 0, /* 142: pointer.func */
            4097, 8, 0, /* 145: pointer.func */
            4097, 8, 0, /* 148: pointer.func */
            4097, 8, 0, /* 151: pointer.func */
            0, 16, 1, /* 154: struct.crypto_ex_data_st */
            	94, 0,
            4097, 8, 0, /* 159: pointer.func */
            0, 0, 0, /* 162: func */
            0, 0, 0, /* 165: func */
            0, 296, 8, /* 168: struct.cert_st */
            	187, 0,
            	924, 48,
            	1025, 56,
            	1028, 64,
            	1060, 72,
            	1063, 80,
            	159, 88,
            	1299, 96,
            0, 8, 1, /* 187: pointer.struct.cert_pkey_st */
            	192, 0,
            0, 24, 3, /* 192: struct.cert_pkey_st */
            	201, 0,
            	364, 8,
            	879, 16,
            0, 8, 1, /* 201: pointer.struct.x509_st */
            	206, 0,
            0, 184, 12, /* 206: struct.x509_st */
            	233, 0,
            	273, 8,
            	263, 16,
            	116, 32,
            	154, 40,
            	263, 104,
            	809, 112,
            	823, 120,
            	94, 128,
            	94, 136,
            	849, 144,
            	861, 176,
            0, 8, 1, /* 233: pointer.struct.x509_cinf_st */
            	238, 0,
            0, 104, 11, /* 238: struct.x509_cinf_st */
            	263, 0,
            	263, 8,
            	273, 16,
            	314, 24,
            	338, 32,
            	314, 40,
            	350, 48,
            	263, 56,
            	263, 64,
            	94, 72,
            	804, 80,
            0, 8, 1, /* 263: pointer.struct.asn1_string_st */
            	268, 0,
            0, 24, 1, /* 268: struct.asn1_string_st */
            	116, 8,
            0, 8, 1, /* 273: pointer.struct.X509_algor_st */
            	278, 0,
            0, 16, 2, /* 278: struct.X509_algor_st */
            	285, 0,
            	299, 8,
            0, 8, 1, /* 285: pointer.struct.asn1_object_st */
            	290, 0,
            0, 40, 3, /* 290: struct.asn1_object_st */
            	116, 0,
            	116, 8,
            	116, 24,
            0, 8, 1, /* 299: pointer.struct.asn1_type_st */
            	304, 0,
            0, 16, 1, /* 304: struct.asn1_type_st */
            	309, 8,
            0, 8, 1, /* 309: struct.fnames */
            	116, 0,
            0, 8, 1, /* 314: pointer.struct.X509_name_st */
            	319, 0,
            0, 40, 3, /* 319: struct.X509_name_st */
            	94, 0,
            	328, 16,
            	116, 24,
            0, 8, 1, /* 328: pointer.struct.buf_mem_st */
            	333, 0,
            0, 24, 1, /* 333: struct.buf_mem_st */
            	116, 8,
            0, 8, 1, /* 338: pointer.struct.X509_val_st */
            	343, 0,
            0, 16, 2, /* 343: struct.X509_val_st */
            	263, 0,
            	263, 8,
            0, 8, 1, /* 350: pointer.struct.X509_pubkey_st */
            	355, 0,
            0, 24, 3, /* 355: struct.X509_pubkey_st */
            	273, 0,
            	263, 8,
            	364, 16,
            0, 8, 1, /* 364: pointer.struct.evp_pkey_st */
            	369, 0,
            0, 56, 4, /* 369: struct.evp_pkey_st */
            	380, 16,
            	483, 24,
            	309, 32,
            	94, 48,
            0, 8, 1, /* 380: pointer.struct.evp_pkey_asn1_method_st */
            	385, 0,
            0, 208, 24, /* 385: struct.evp_pkey_asn1_method_st */
            	116, 16,
            	116, 24,
            	436, 32,
            	444, 40,
            	447, 48,
            	450, 56,
            	453, 64,
            	456, 72,
            	450, 80,
            	459, 88,
            	459, 96,
            	462, 104,
            	465, 112,
            	459, 120,
            	447, 128,
            	447, 136,
            	450, 144,
            	468, 152,
            	471, 160,
            	474, 168,
            	462, 176,
            	465, 184,
            	477, 192,
            	480, 200,
            0, 8, 1, /* 436: pointer.struct.unnamed */
            	441, 0,
            0, 0, 0, /* 441: struct.unnamed */
            4097, 8, 0, /* 444: pointer.func */
            4097, 8, 0, /* 447: pointer.func */
            4097, 8, 0, /* 450: pointer.func */
            4097, 8, 0, /* 453: pointer.func */
            4097, 8, 0, /* 456: pointer.func */
            4097, 8, 0, /* 459: pointer.func */
            4097, 8, 0, /* 462: pointer.func */
            4097, 8, 0, /* 465: pointer.func */
            4097, 8, 0, /* 468: pointer.func */
            4097, 8, 0, /* 471: pointer.func */
            4097, 8, 0, /* 474: pointer.func */
            4097, 8, 0, /* 477: pointer.func */
            4097, 8, 0, /* 480: pointer.func */
            0, 8, 1, /* 483: pointer.struct.engine_st */
            	488, 0,
            0, 216, 24, /* 488: struct.engine_st */
            	116, 0,
            	116, 8,
            	539, 16,
            	594, 24,
            	645, 32,
            	681, 40,
            	698, 48,
            	725, 56,
            	760, 64,
            	768, 72,
            	771, 80,
            	774, 88,
            	777, 96,
            	780, 104,
            	780, 112,
            	780, 120,
            	783, 128,
            	786, 136,
            	786, 144,
            	789, 152,
            	792, 160,
            	154, 184,
            	483, 200,
            	483, 208,
            0, 8, 1, /* 539: pointer.struct.rsa_meth_st */
            	544, 0,
            0, 112, 13, /* 544: struct.rsa_meth_st */
            	116, 0,
            	573, 8,
            	573, 16,
            	573, 24,
            	573, 32,
            	576, 40,
            	579, 48,
            	582, 56,
            	582, 64,
            	116, 80,
            	585, 88,
            	588, 96,
            	591, 104,
            4097, 8, 0, /* 573: pointer.func */
            4097, 8, 0, /* 576: pointer.func */
            4097, 8, 0, /* 579: pointer.func */
            4097, 8, 0, /* 582: pointer.func */
            4097, 8, 0, /* 585: pointer.func */
            4097, 8, 0, /* 588: pointer.func */
            4097, 8, 0, /* 591: pointer.func */
            0, 8, 1, /* 594: pointer.struct.dsa_method */
            	599, 0,
            0, 96, 11, /* 599: struct.dsa_method */
            	116, 0,
            	624, 8,
            	627, 16,
            	630, 24,
            	633, 32,
            	636, 40,
            	639, 48,
            	639, 56,
            	116, 72,
            	642, 80,
            	639, 88,
            4097, 8, 0, /* 624: pointer.func */
            4097, 8, 0, /* 627: pointer.func */
            4097, 8, 0, /* 630: pointer.func */
            4097, 8, 0, /* 633: pointer.func */
            4097, 8, 0, /* 636: pointer.func */
            4097, 8, 0, /* 639: pointer.func */
            4097, 8, 0, /* 642: pointer.func */
            0, 8, 1, /* 645: pointer.struct.dh_method */
            	650, 0,
            0, 72, 8, /* 650: struct.dh_method */
            	116, 0,
            	669, 8,
            	672, 16,
            	675, 24,
            	669, 32,
            	669, 40,
            	116, 56,
            	678, 64,
            4097, 8, 0, /* 669: pointer.func */
            4097, 8, 0, /* 672: pointer.func */
            4097, 8, 0, /* 675: pointer.func */
            4097, 8, 0, /* 678: pointer.func */
            0, 8, 1, /* 681: pointer.struct.ecdh_method */
            	686, 0,
            0, 32, 3, /* 686: struct.ecdh_method */
            	116, 0,
            	695, 8,
            	116, 24,
            4097, 8, 0, /* 695: pointer.func */
            0, 8, 1, /* 698: pointer.struct.ecdsa_method */
            	703, 0,
            0, 48, 5, /* 703: struct.ecdsa_method */
            	116, 0,
            	716, 8,
            	719, 16,
            	722, 24,
            	116, 40,
            4097, 8, 0, /* 716: pointer.func */
            4097, 8, 0, /* 719: pointer.func */
            4097, 8, 0, /* 722: pointer.func */
            0, 8, 1, /* 725: pointer.struct.rand_meth_st */
            	730, 0,
            0, 48, 6, /* 730: struct.rand_meth_st */
            	745, 0,
            	748, 8,
            	751, 16,
            	754, 24,
            	748, 32,
            	757, 40,
            4097, 8, 0, /* 745: pointer.func */
            4097, 8, 0, /* 748: pointer.func */
            4097, 8, 0, /* 751: pointer.func */
            4097, 8, 0, /* 754: pointer.func */
            4097, 8, 0, /* 757: pointer.func */
            0, 8, 1, /* 760: pointer.struct.store_method_st */
            	765, 0,
            0, 0, 0, /* 765: struct.store_method_st */
            4097, 8, 0, /* 768: pointer.func */
            4097, 8, 0, /* 771: pointer.func */
            4097, 8, 0, /* 774: pointer.func */
            4097, 8, 0, /* 777: pointer.func */
            4097, 8, 0, /* 780: pointer.func */
            4097, 8, 0, /* 783: pointer.func */
            4097, 8, 0, /* 786: pointer.func */
            4097, 8, 0, /* 789: pointer.func */
            0, 8, 1, /* 792: pointer.struct.ENGINE_CMD_DEFN_st */
            	797, 0,
            0, 32, 2, /* 797: struct.ENGINE_CMD_DEFN_st */
            	116, 8,
            	116, 16,
            0, 24, 1, /* 804: struct.ASN1_ENCODING_st */
            	116, 0,
            0, 8, 1, /* 809: pointer.struct.AUTHORITY_KEYID_st */
            	814, 0,
            0, 24, 3, /* 814: struct.AUTHORITY_KEYID_st */
            	263, 0,
            	94, 8,
            	263, 16,
            0, 8, 1, /* 823: pointer.struct.X509_POLICY_CACHE_st */
            	828, 0,
            0, 40, 2, /* 828: struct.X509_POLICY_CACHE_st */
            	835, 0,
            	94, 8,
            0, 8, 1, /* 835: pointer.struct.X509_POLICY_DATA_st */
            	840, 0,
            0, 32, 3, /* 840: struct.X509_POLICY_DATA_st */
            	285, 8,
            	94, 16,
            	94, 24,
            0, 8, 1, /* 849: pointer.struct.NAME_CONSTRAINTS_st */
            	854, 0,
            0, 16, 2, /* 854: struct.NAME_CONSTRAINTS_st */
            	94, 0,
            	94, 8,
            0, 8, 1, /* 861: pointer.struct.x509_cert_aux_st */
            	866, 0,
            0, 40, 5, /* 866: struct.x509_cert_aux_st */
            	94, 0,
            	94, 8,
            	263, 16,
            	263, 24,
            	94, 32,
            0, 8, 1, /* 879: pointer.struct.env_md_st */
            	884, 0,
            0, 120, 8, /* 884: struct.env_md_st */
            	903, 24,
            	906, 32,
            	909, 40,
            	912, 48,
            	903, 56,
            	915, 64,
            	918, 72,
            	921, 112,
            4097, 8, 0, /* 903: pointer.func */
            4097, 8, 0, /* 906: pointer.func */
            4097, 8, 0, /* 909: pointer.func */
            4097, 8, 0, /* 912: pointer.func */
            4097, 8, 0, /* 915: pointer.func */
            4097, 8, 0, /* 918: pointer.func */
            4097, 8, 0, /* 921: pointer.func */
            0, 8, 1, /* 924: pointer.struct.rsa_st */
            	929, 0,
            0, 168, 17, /* 929: struct.rsa_st */
            	539, 16,
            	483, 24,
            	966, 32,
            	966, 40,
            	966, 48,
            	966, 56,
            	966, 64,
            	966, 72,
            	966, 80,
            	966, 88,
            	154, 96,
            	984, 120,
            	984, 128,
            	984, 136,
            	116, 144,
            	998, 152,
            	998, 160,
            0, 8, 1, /* 966: pointer.struct.bignum_st */
            	971, 0,
            0, 24, 1, /* 971: struct.bignum_st */
            	976, 0,
            0, 8, 1, /* 976: pointer.int */
            	981, 0,
            0, 4, 0, /* 981: int */
            0, 8, 1, /* 984: pointer.struct.bn_mont_ctx_st */
            	989, 0,
            0, 96, 3, /* 989: struct.bn_mont_ctx_st */
            	971, 8,
            	971, 32,
            	971, 56,
            0, 8, 1, /* 998: pointer.struct.bn_blinding_st */
            	1003, 0,
            0, 88, 7, /* 1003: struct.bn_blinding_st */
            	966, 0,
            	966, 8,
            	966, 16,
            	966, 24,
            	1020, 40,
            	984, 72,
            	579, 80,
            0, 16, 1, /* 1020: struct.iovec */
            	116, 0,
            4097, 8, 0, /* 1025: pointer.func */
            0, 8, 1, /* 1028: pointer.struct.dh_st */
            	1033, 0,
            0, 144, 12, /* 1033: struct.dh_st */
            	966, 8,
            	966, 16,
            	966, 32,
            	966, 40,
            	984, 56,
            	966, 64,
            	966, 72,
            	116, 80,
            	966, 96,
            	154, 112,
            	645, 128,
            	483, 136,
            4097, 8, 0, /* 1060: pointer.func */
            0, 8, 1, /* 1063: pointer.struct.ec_key_st */
            	1068, 0,
            0, 56, 4, /* 1068: struct.ec_key_st */
            	1079, 8,
            	1256, 16,
            	966, 24,
            	1272, 48,
            0, 8, 1, /* 1079: pointer.struct.ec_group_st */
            	1084, 0,
            0, 232, 12, /* 1084: struct.ec_group_st */
            	1111, 0,
            	1256, 8,
            	971, 16,
            	971, 40,
            	116, 80,
            	1272, 96,
            	971, 104,
            	971, 152,
            	971, 176,
            	116, 208,
            	116, 216,
            	1296, 224,
            0, 8, 1, /* 1111: pointer.struct.ec_method_st */
            	1116, 0,
            0, 304, 37, /* 1116: struct.ec_method_st */
            	1193, 8,
            	1196, 16,
            	1196, 24,
            	1199, 32,
            	1202, 40,
            	1202, 48,
            	1193, 56,
            	1205, 64,
            	1208, 72,
            	1211, 80,
            	1211, 88,
            	1214, 96,
            	1217, 104,
            	1220, 112,
            	1220, 120,
            	1223, 128,
            	1223, 136,
            	1226, 144,
            	1229, 152,
            	1232, 160,
            	1235, 168,
            	1238, 176,
            	1241, 184,
            	1217, 192,
            	1241, 200,
            	1238, 208,
            	1241, 216,
            	1244, 224,
            	1247, 232,
            	1205, 240,
            	1193, 248,
            	1202, 256,
            	1250, 264,
            	1202, 272,
            	1250, 280,
            	1250, 288,
            	1253, 296,
            4097, 8, 0, /* 1193: pointer.func */
            4097, 8, 0, /* 1196: pointer.func */
            4097, 8, 0, /* 1199: pointer.func */
            4097, 8, 0, /* 1202: pointer.func */
            4097, 8, 0, /* 1205: pointer.func */
            4097, 8, 0, /* 1208: pointer.func */
            4097, 8, 0, /* 1211: pointer.func */
            4097, 8, 0, /* 1214: pointer.func */
            4097, 8, 0, /* 1217: pointer.func */
            4097, 8, 0, /* 1220: pointer.func */
            4097, 8, 0, /* 1223: pointer.func */
            4097, 8, 0, /* 1226: pointer.func */
            4097, 8, 0, /* 1229: pointer.func */
            4097, 8, 0, /* 1232: pointer.func */
            4097, 8, 0, /* 1235: pointer.func */
            4097, 8, 0, /* 1238: pointer.func */
            4097, 8, 0, /* 1241: pointer.func */
            4097, 8, 0, /* 1244: pointer.func */
            4097, 8, 0, /* 1247: pointer.func */
            4097, 8, 0, /* 1250: pointer.func */
            4097, 8, 0, /* 1253: pointer.func */
            0, 8, 1, /* 1256: pointer.struct.ec_point_st */
            	1261, 0,
            0, 88, 4, /* 1261: struct.ec_point_st */
            	1111, 0,
            	971, 8,
            	971, 32,
            	971, 56,
            0, 8, 1, /* 1272: pointer.struct.ec_extra_data_st */
            	1277, 0,
            0, 40, 5, /* 1277: struct.ec_extra_data_st */
            	1272, 0,
            	116, 8,
            	1290, 16,
            	1293, 24,
            	1293, 32,
            4097, 8, 0, /* 1290: pointer.func */
            4097, 8, 0, /* 1293: pointer.func */
            4097, 8, 0, /* 1296: pointer.func */
            0, 192, 8, /* 1299: array[8].struct.cert_pkey_st */
            	192, 0,
            	192, 24,
            	192, 48,
            	192, 72,
            	192, 96,
            	192, 120,
            	192, 144,
            	192, 168,
            0, 8, 1, /* 1318: pointer.struct.cert_st */
            	168, 0,
            4097, 8, 0, /* 1323: pointer.func */
            0, 0, 0, /* 1326: func */
            0, 16, 0, /* 1329: struct.rlimit */
            0, 8, 1, /* 1332: pointer.struct.ssl3_buf_freelist_st */
            	1337, 0,
            0, 24, 1, /* 1337: struct.ssl3_buf_freelist_st */
            	1342, 16,
            0, 8, 1, /* 1342: pointer.struct.ssl3_buf_freelist_entry_st */
            	1347, 0,
            0, 8, 1, /* 1347: struct.ssl3_buf_freelist_entry_st */
            	1342, 0,
            0, 352, 14, /* 1352: struct.ssl_session_st */
            	116, 144,
            	116, 152,
            	1383, 168,
            	201, 176,
            	1403, 224,
            	94, 240,
            	154, 248,
            	1413, 264,
            	1413, 272,
            	116, 280,
            	116, 296,
            	116, 312,
            	116, 320,
            	116, 344,
            0, 8, 1, /* 1383: pointer.struct.sess_cert_st */
            	1388, 0,
            0, 248, 6, /* 1388: struct.sess_cert_st */
            	94, 0,
            	187, 16,
            	1299, 24,
            	924, 216,
            	1028, 224,
            	1063, 232,
            0, 8, 1, /* 1403: pointer.struct.ssl_cipher_st */
            	1408, 0,
            0, 88, 1, /* 1408: struct.ssl_cipher_st */
            	116, 8,
            0, 8, 1, /* 1413: pointer.struct.ssl_session_st */
            	1352, 0,
            4097, 8, 0, /* 1418: pointer.func */
            0, 56, 2, /* 1421: struct.comp_ctx_st */
            	1428, 0,
            	154, 40,
            0, 8, 1, /* 1428: pointer.struct.comp_method_st */
            	1433, 0,
            0, 64, 7, /* 1433: struct.comp_method_st */
            	116, 8,
            	1450, 16,
            	1453, 24,
            	1456, 32,
            	1456, 40,
            	1459, 48,
            	1459, 56,
            4097, 8, 0, /* 1450: pointer.func */
            4097, 8, 0, /* 1453: pointer.func */
            4097, 8, 0, /* 1456: pointer.func */
            4097, 8, 0, /* 1459: pointer.func */
            0, 88, 1, /* 1462: struct.hm_header_st */
            	1467, 48,
            0, 40, 4, /* 1467: struct.dtls1_retransmit_state */
            	1478, 0,
            	1534, 8,
            	1667, 16,
            	1413, 24,
            0, 8, 1, /* 1478: pointer.struct.evp_cipher_ctx_st */
            	1483, 0,
            0, 168, 4, /* 1483: struct.evp_cipher_ctx_st */
            	1494, 0,
            	483, 8,
            	1531, 96,
            	1531, 120,
            0, 8, 1, /* 1494: pointer.struct.evp_cipher_st */
            	1499, 0,
            0, 88, 7, /* 1499: struct.evp_cipher_st */
            	1516, 24,
            	1519, 32,
            	1522, 40,
            	1525, 56,
            	1525, 64,
            	1528, 72,
            	1531, 80,
            4097, 8, 0, /* 1516: pointer.func */
            4097, 8, 0, /* 1519: pointer.func */
            4097, 8, 0, /* 1522: pointer.func */
            4097, 8, 0, /* 1525: pointer.func */
            4097, 8, 0, /* 1528: pointer.func */
            0, 8, 0, /* 1531: pointer.void */
            0, 8, 1, /* 1534: pointer.struct.env_md_ctx_st */
            	1539, 0,
            0, 48, 5, /* 1539: struct.env_md_ctx_st */
            	879, 0,
            	483, 8,
            	1531, 24,
            	1552, 32,
            	906, 40,
            0, 8, 1, /* 1552: pointer.struct.evp_pkey_ctx_st */
            	1557, 0,
            0, 80, 8, /* 1557: struct.evp_pkey_ctx_st */
            	1576, 0,
            	483, 8,
            	364, 16,
            	364, 24,
            	116, 40,
            	116, 48,
            	436, 56,
            	976, 64,
            0, 8, 1, /* 1576: pointer.struct.evp_pkey_method_st */
            	1581, 0,
            0, 208, 25, /* 1581: struct.evp_pkey_method_st */
            	436, 8,
            	1634, 16,
            	1637, 24,
            	436, 32,
            	1640, 40,
            	436, 48,
            	1640, 56,
            	436, 64,
            	1643, 72,
            	436, 80,
            	1646, 88,
            	436, 96,
            	1643, 104,
            	1649, 112,
            	1652, 120,
            	1649, 128,
            	1655, 136,
            	436, 144,
            	1643, 152,
            	436, 160,
            	1643, 168,
            	436, 176,
            	1658, 184,
            	1661, 192,
            	1664, 200,
            4097, 8, 0, /* 1634: pointer.func */
            4097, 8, 0, /* 1637: pointer.func */
            4097, 8, 0, /* 1640: pointer.func */
            4097, 8, 0, /* 1643: pointer.func */
            4097, 8, 0, /* 1646: pointer.func */
            4097, 8, 0, /* 1649: pointer.func */
            4097, 8, 0, /* 1652: pointer.func */
            4097, 8, 0, /* 1655: pointer.func */
            4097, 8, 0, /* 1658: pointer.func */
            4097, 8, 0, /* 1661: pointer.func */
            4097, 8, 0, /* 1664: pointer.func */
            0, 8, 1, /* 1667: pointer.struct.comp_ctx_st */
            	1421, 0,
            4097, 8, 0, /* 1672: pointer.func */
            0, 8, 1, /* 1675: pointer.struct._pitem */
            	1680, 0,
            0, 24, 2, /* 1680: struct._pitem */
            	116, 8,
            	1675, 16,
            0, 16, 1, /* 1687: struct._pqueue */
            	1675, 0,
            0, 0, 0, /* 1692: func */
            0, 16, 0, /* 1695: union.anon */
            0, 8, 1, /* 1698: pointer.struct.dtls1_state_st */
            	1703, 0,
            0, 888, 7, /* 1703: struct.dtls1_state_st */
            	1720, 576,
            	1720, 592,
            	1725, 608,
            	1725, 616,
            	1720, 624,
            	1462, 648,
            	1462, 736,
            0, 16, 1, /* 1720: struct.record_pqueue_st */
            	1725, 8,
            0, 8, 1, /* 1725: pointer.struct._pqueue */
            	1687, 0,
            0, 0, 0, /* 1730: func */
            0, 0, 0, /* 1733: func */
            0, 8, 1, /* 1736: pointer.struct.ssl_comp_st */
            	1741, 0,
            0, 24, 2, /* 1741: struct.ssl_comp_st */
            	116, 8,
            	1428, 16,
            4097, 8, 0, /* 1748: pointer.func */
            0, 0, 0, /* 1751: func */
            0, 0, 0, /* 1754: func */
            0, 0, 0, /* 1757: func */
            0, 0, 0, /* 1760: func */
            0, 0, 0, /* 1763: func */
            0, 0, 0, /* 1766: func */
            0, 9, 0, /* 1769: array[9].char */
            0, 0, 0, /* 1772: func */
            0, 0, 0, /* 1775: func */
            0, 0, 0, /* 1778: func */
            0, 0, 0, /* 1781: func */
            0, 0, 0, /* 1784: func */
            0, 0, 0, /* 1787: func */
            0, 0, 0, /* 1790: func */
            0, 0, 0, /* 1793: func */
            0, 0, 0, /* 1796: func */
            0, 0, 0, /* 1799: func */
            0, 12, 0, /* 1802: struct.ap_unix_identity_t */
            0, 0, 0, /* 1805: func */
            0, 0, 0, /* 1808: func */
            0, 0, 0, /* 1811: func */
            0, 0, 0, /* 1814: func */
            0, 0, 0, /* 1817: func */
            0, 0, 0, /* 1820: func */
            0, 0, 0, /* 1823: func */
            0, 0, 0, /* 1826: func */
            0, 0, 0, /* 1829: func */
            0, 0, 0, /* 1832: func */
            0, 0, 0, /* 1835: func */
            0, 0, 0, /* 1838: func */
            0, 8, 0, /* 1841: array[2].int */
            0, 128, 0, /* 1844: array[128].char */
            0, 528, 8, /* 1847: struct.anon */
            	1403, 408,
            	1028, 416,
            	1063, 424,
            	94, 464,
            	116, 480,
            	1494, 488,
            	879, 496,
            	1736, 512,
            0, 0, 0, /* 1866: func */
            0, 0, 0, /* 1869: func */
            0, 0, 0, /* 1872: func */
            0, 0, 0, /* 1875: func */
            0, 0, 0, /* 1878: func */
            0, 0, 0, /* 1881: func */
            0, 0, 0, /* 1884: func */
            4097, 8, 0, /* 1887: pointer.func */
            4097, 8, 0, /* 1890: pointer.func */
            0, 128, 14, /* 1893: struct.srp_ctx_st */
            	1531, 0,
            	1924, 8,
            	15, 16,
            	1890, 24,
            	116, 32,
            	966, 40,
            	966, 48,
            	966, 56,
            	966, 64,
            	966, 72,
            	966, 80,
            	966, 88,
            	966, 96,
            	116, 104,
            4097, 8, 0, /* 1924: pointer.func */
            0, 0, 0, /* 1927: func */
            0, 20, 0, /* 1930: array[5].int */
            0, 0, 0, /* 1933: func */
            0, 0, 0, /* 1936: func */
            0, 0, 0, /* 1939: func */
            0, 0, 0, /* 1942: func */
            0, 0, 0, /* 1945: func */
            4097, 8, 0, /* 1948: pointer.func */
            0, 0, 0, /* 1951: func */
            0, 0, 0, /* 1954: func */
            0, 0, 0, /* 1957: func */
            0, 8, 1, /* 1960: pointer.struct.tls_session_ticket_ext_st */
            	1965, 0,
            0, 16, 1, /* 1965: struct.tls_session_ticket_ext_st */
            	1531, 8,
            0, 0, 0, /* 1970: func */
            0, 0, 0, /* 1973: func */
            0, 0, 0, /* 1976: func */
            0, 4, 0, /* 1979: array[4].char */
            0, 0, 0, /* 1982: func */
            0, 0, 0, /* 1985: func */
            0, 0, 0, /* 1988: func */
            4097, 8, 0, /* 1991: pointer.func */
            0, 0, 0, /* 1994: func */
            0, 0, 0, /* 1997: func */
            0, 0, 0, /* 2000: func */
            0, 0, 0, /* 2003: func */
            0, 0, 0, /* 2006: func */
            0, 0, 0, /* 2009: func */
            0, 0, 0, /* 2012: func */
            0, 0, 0, /* 2015: func */
            0, 0, 0, /* 2018: func */
            0, 0, 0, /* 2021: func */
            0, 8, 1, /* 2024: pointer.struct.iovec */
            	1020, 0,
            0, 0, 0, /* 2029: func */
            0, 0, 0, /* 2032: func */
            0, 0, 0, /* 2035: func */
            0, 0, 0, /* 2038: func */
            0, 0, 0, /* 2041: func */
            0, 0, 0, /* 2044: func */
            4097, 8, 0, /* 2047: pointer.func */
            0, 0, 0, /* 2050: func */
            0, 0, 0, /* 2053: func */
            0, 0, 0, /* 2056: func */
            0, 0, 0, /* 2059: func */
            4097, 8, 0, /* 2062: pointer.func */
            0, 0, 0, /* 2065: func */
            0, 0, 0, /* 2068: func */
            4097, 8, 0, /* 2071: pointer.func */
            0, 0, 0, /* 2074: func */
            0, 0, 0, /* 2077: func */
            0, 64, 0, /* 2080: array[64].char */
            0, 0, 0, /* 2083: func */
            0, 0, 0, /* 2086: func */
            0, 0, 0, /* 2089: func */
            0, 8, 1, /* 2092: pointer.struct.ssl3_enc_method */
            	2097, 0,
            0, 112, 11, /* 2097: struct.ssl3_enc_method */
            	436, 0,
            	2122, 8,
            	2071, 16,
            	2125, 24,
            	436, 32,
            	2128, 40,
            	2131, 56,
            	116, 64,
            	116, 80,
            	2134, 96,
            	2137, 104,
            4097, 8, 0, /* 2122: pointer.func */
            4097, 8, 0, /* 2125: pointer.func */
            4097, 8, 0, /* 2128: pointer.func */
            4097, 8, 0, /* 2131: pointer.func */
            4097, 8, 0, /* 2134: pointer.func */
            4097, 8, 0, /* 2137: pointer.func */
            0, 0, 0, /* 2140: func */
            0, 0, 0, /* 2143: func */
            4097, 8, 0, /* 2146: pointer.func */
            4097, 8, 0, /* 2149: pointer.func */
            0, 72, 0, /* 2152: struct.anon */
            0, 0, 0, /* 2155: func */
            0, 0, 0, /* 2158: func */
            0, 0, 0, /* 2161: func */
            0, 1, 0, /* 2164: char */
            0, 0, 0, /* 2167: func */
            0, 0, 0, /* 2170: func */
            0, 0, 0, /* 2173: func */
            0, 0, 0, /* 2176: func */
            4097, 8, 0, /* 2179: pointer.func */
            0, 16, 0, /* 2182: array[16].char */
            0, 0, 0, /* 2185: func */
            0, 8, 1, /* 2188: pointer.struct.ssl3_state_st */
            	2193, 0,
            0, 1200, 10, /* 2193: struct.ssl3_state_st */
            	2216, 240,
            	2216, 264,
            	2221, 288,
            	2221, 344,
            	116, 432,
            	2230, 440,
            	2293, 448,
            	1531, 496,
            	1531, 512,
            	1847, 528,
            0, 24, 1, /* 2216: struct.ssl3_buffer_st */
            	116, 0,
            0, 56, 3, /* 2221: struct.ssl3_record_st */
            	116, 16,
            	116, 24,
            	116, 32,
            0, 8, 1, /* 2230: pointer.struct.bio_st */
            	2235, 0,
            0, 112, 7, /* 2235: struct.bio_st */
            	2252, 0,
            	2290, 8,
            	116, 16,
            	1531, 48,
            	2230, 56,
            	2230, 64,
            	154, 96,
            0, 8, 1, /* 2252: pointer.struct.bio_method_st */
            	2257, 0,
            0, 80, 9, /* 2257: struct.bio_method_st */
            	116, 8,
            	2062, 16,
            	2062, 24,
            	2278, 32,
            	2062, 40,
            	2281, 48,
            	2284, 56,
            	2284, 64,
            	2287, 72,
            4097, 8, 0, /* 2278: pointer.func */
            4097, 8, 0, /* 2281: pointer.func */
            4097, 8, 0, /* 2284: pointer.func */
            4097, 8, 0, /* 2287: pointer.func */
            4097, 8, 0, /* 2290: pointer.func */
            0, 8, 1, /* 2293: pointer.pointer.struct.env_md_ctx_st */
            	1534, 0,
            0, 808, 51, /* 2298: struct.ssl_st */
            	2403, 8,
            	2230, 16,
            	2230, 24,
            	2230, 32,
            	2071, 48,
            	328, 80,
            	1531, 88,
            	116, 104,
            	2488, 120,
            	2188, 128,
            	1698, 136,
            	1323, 152,
            	1531, 160,
            	124, 176,
            	94, 184,
            	94, 192,
            	1478, 208,
            	1534, 216,
            	1667, 224,
            	1478, 232,
            	1534, 240,
            	1667, 248,
            	1318, 256,
            	1413, 304,
            	2514, 312,
            	136, 328,
            	2517, 336,
            	1672, 352,
            	2125, 360,
            	2520, 368,
            	154, 392,
            	94, 408,
            	6, 464,
            	1531, 472,
            	116, 480,
            	94, 504,
            	94, 512,
            	116, 520,
            	116, 544,
            	116, 560,
            	1531, 568,
            	1960, 584,
            	2128, 592,
            	1531, 600,
            	3, 608,
            	1531, 616,
            	2520, 624,
            	116, 632,
            	94, 648,
            	2024, 656,
            	1893, 680,
            0, 8, 1, /* 2403: pointer.struct.ssl_method_st */
            	2408, 0,
            0, 232, 28, /* 2408: struct.ssl_method_st */
            	2071, 8,
            	2149, 16,
            	2149, 24,
            	2071, 32,
            	2071, 40,
            	2122, 48,
            	2122, 56,
            	2122, 64,
            	2071, 72,
            	2071, 80,
            	2071, 88,
            	2467, 96,
            	2470, 104,
            	2179, 112,
            	2071, 120,
            	2473, 128,
            	2476, 136,
            	2479, 144,
            	2047, 152,
            	2071, 160,
            	757, 168,
            	1991, 176,
            	1948, 184,
            	1459, 192,
            	2092, 200,
            	757, 208,
            	2482, 216,
            	2485, 224,
            4097, 8, 0, /* 2467: pointer.func */
            4097, 8, 0, /* 2470: pointer.func */
            4097, 8, 0, /* 2473: pointer.func */
            4097, 8, 0, /* 2476: pointer.func */
            4097, 8, 0, /* 2479: pointer.func */
            4097, 8, 0, /* 2482: pointer.func */
            4097, 8, 0, /* 2485: pointer.func */
            0, 8, 1, /* 2488: pointer.struct.ssl2_state_st */
            	2493, 0,
            0, 344, 9, /* 2493: struct.ssl2_state_st */
            	116, 24,
            	116, 56,
            	116, 64,
            	116, 72,
            	116, 104,
            	116, 112,
            	116, 120,
            	116, 128,
            	116, 136,
            4097, 8, 0, /* 2514: pointer.func */
            4097, 8, 0, /* 2517: pointer.func */
            0, 8, 1, /* 2520: pointer.struct.ssl_ctx_st */
            	2525, 0,
            0, 736, 50, /* 2525: struct.ssl_ctx_st */
            	2403, 0,
            	94, 8,
            	94, 16,
            	56, 24,
            	33, 32,
            	1413, 48,
            	1413, 56,
            	2146, 80,
            	2628, 88,
            	2631, 96,
            	1418, 152,
            	1531, 160,
            	24, 168,
            	1531, 176,
            	2634, 184,
            	2514, 192,
            	2122, 200,
            	154, 208,
            	879, 224,
            	879, 232,
            	879, 240,
            	94, 248,
            	94, 256,
            	2517, 264,
            	94, 272,
            	1318, 304,
            	1323, 320,
            	1531, 328,
            	136, 376,
            	2514, 384,
            	124, 392,
            	483, 408,
            	1924, 416,
            	1531, 424,
            	1748, 480,
            	15, 488,
            	1531, 496,
            	2637, 504,
            	1531, 512,
            	116, 520,
            	1672, 528,
            	2125, 536,
            	1332, 552,
            	1332, 560,
            	1893, 568,
            	1887, 696,
            	1531, 704,
            	2640, 712,
            	1531, 720,
            	94, 728,
            4097, 8, 0, /* 2628: pointer.func */
            4097, 8, 0, /* 2631: pointer.func */
            4097, 8, 0, /* 2634: pointer.func */
            4097, 8, 0, /* 2637: pointer.func */
            4097, 8, 0, /* 2640: pointer.func */
            0, 0, 0, /* 2643: func */
            0, 0, 0, /* 2646: func */
            0, 0, 0, /* 2649: func */
            0, 0, 0, /* 2652: func */
            0, 0, 0, /* 2655: func */
            0, 0, 0, /* 2658: func */
            0, 0, 0, /* 2661: func */
            0, 0, 0, /* 2664: func */
            0, 0, 0, /* 2667: func */
            0, 24, 0, /* 2670: array[6].int */
            0, 2, 0, /* 2673: array[2].char */
            0, 0, 0, /* 2676: func */
            0, 0, 0, /* 2679: func */
            0, 0, 0, /* 2682: func */
            0, 0, 0, /* 2685: func */
            0, 8, 0, /* 2688: long */
            0, 0, 0, /* 2691: func */
            0, 0, 0, /* 2694: func */
            0, 0, 0, /* 2697: func */
            0, 0, 0, /* 2700: func */
            0, 0, 0, /* 2703: func */
            0, 0, 0, /* 2706: func */
            0, 0, 0, /* 2709: func */
            0, 0, 0, /* 2712: func */
            0, 0, 0, /* 2715: func */
            0, 0, 0, /* 2718: func */
            0, 0, 0, /* 2721: func */
            0, 20, 0, /* 2724: array[20].char */
            0, 0, 0, /* 2727: func */
            0, 8, 1, /* 2730: pointer.struct.ssl_st */
            	2298, 0,
            0, 0, 0, /* 2735: func */
            0, 0, 0, /* 2738: func */
            0, 0, 0, /* 2741: func */
            0, 0, 0, /* 2744: func */
            0, 0, 0, /* 2747: func */
            0, 0, 0, /* 2750: func */
            0, 0, 0, /* 2753: func */
            0, 0, 0, /* 2756: func */
            0, 8, 0, /* 2759: array[8].char */
            0, 0, 0, /* 2762: func */
            0, 0, 0, /* 2765: func */
            0, 0, 0, /* 2768: func */
            0, 0, 0, /* 2771: func */
            0, 0, 0, /* 2774: func */
            0, 0, 0, /* 2777: func */
            0, 0, 0, /* 2780: func */
            0, 0, 0, /* 2783: func */
            0, 256, 0, /* 2786: array[256].char */
            0, 48, 0, /* 2789: array[48].char */
            0, 0, 0, /* 2792: func */
            0, 0, 0, /* 2795: func */
            0, 0, 0, /* 2798: func */
            0, 0, 0, /* 2801: func */
            0, 2, 0, /* 2804: short */
            0, 0, 0, /* 2807: func */
            0, 0, 0, /* 2810: func */
            0, 12, 0, /* 2813: array[12].char */
            0, 0, 0, /* 2816: func */
            0, 32, 0, /* 2819: array[32].char */
            0, 0, 0, /* 2822: func */
            0, 0, 0, /* 2825: func */
            0, 0, 0, /* 2828: func */
            0, 0, 0, /* 2831: func */
            0, 0, 0, /* 2834: func */
        },
        .arg_entity_index = { 2730, },
        .ret_entity_index = 201,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    const SSL * new_arg_a = *((const SSL * *)new_args->args[0]);

    X509 * *new_ret_ptr = (X509 * *)new_args->ret;

    X509 * (*orig_SSL_get_peer_certificate)(const SSL *);
    orig_SSL_get_peer_certificate = dlsym(RTLD_NEXT, "SSL_get_peer_certificate");
    *new_ret_ptr = (*orig_SSL_get_peer_certificate)(new_arg_a);

    syscall(889);

    return ret;
}

