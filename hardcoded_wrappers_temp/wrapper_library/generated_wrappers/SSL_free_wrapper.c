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

void bb_SSL_free(SSL * arg_a);

void SSL_free(SSL * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_free called %lu\n", in_lib);
    if (!in_lib)
        bb_SSL_free(arg_a);
    else {
        void (*orig_SSL_free)(SSL *);
        orig_SSL_free = dlsym(RTLD_NEXT, "SSL_free");
        orig_SSL_free(arg_a);
    }
}

void bb_SSL_free(SSL * arg_a) 
{
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
            1, 8, 1, /* 33: pointer.struct.in_addr */
            	30, 0,
            0, 0, 0, /* 38: func */
            0, 0, 0, /* 41: func */
            4097, 8, 0, /* 44: pointer.func */
            0, 0, 0, /* 47: func */
            4097, 8, 0, /* 50: pointer.func */
            0, 0, 0, /* 53: func */
            1, 8, 1, /* 56: pointer.struct.x509_store_st */
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
            1, 8, 1, /* 94: pointer.struct.stack_st_OPENSSL_STRING */
            	99, 0,
            0, 32, 1, /* 99: struct.stack_st_OPENSSL_STRING */
            	104, 0,
            0, 32, 2, /* 104: struct.stack_st */
            	111, 8,
            	121, 24,
            1, 8, 1, /* 111: pointer.pointer.char */
            	116, 0,
            1, 8, 1, /* 116: pointer.char */
            	4096, 0,
            4097, 8, 0, /* 121: pointer.func */
            1, 8, 1, /* 124: pointer.struct.X509_VERIFY_PARAM_st */
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
            1, 8, 1, /* 187: pointer.struct.cert_pkey_st */
            	192, 0,
            0, 24, 3, /* 192: struct.cert_pkey_st */
            	201, 0,
            	364, 8,
            	879, 16,
            1, 8, 1, /* 201: pointer.struct.x509_st */
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
            1, 8, 1, /* 233: pointer.struct.x509_cinf_st */
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
            1, 8, 1, /* 263: pointer.struct.asn1_string_st */
            	268, 0,
            0, 24, 1, /* 268: struct.asn1_string_st */
            	116, 8,
            1, 8, 1, /* 273: pointer.struct.X509_algor_st */
            	278, 0,
            0, 16, 2, /* 278: struct.X509_algor_st */
            	285, 0,
            	299, 8,
            1, 8, 1, /* 285: pointer.struct.asn1_object_st */
            	290, 0,
            0, 40, 3, /* 290: struct.asn1_object_st */
            	116, 0,
            	116, 8,
            	116, 24,
            1, 8, 1, /* 299: pointer.struct.asn1_type_st */
            	304, 0,
            0, 16, 1, /* 304: struct.asn1_type_st */
            	309, 8,
            0, 8, 1, /* 309: struct.fnames */
            	116, 0,
            1, 8, 1, /* 314: pointer.struct.X509_name_st */
            	319, 0,
            0, 40, 3, /* 319: struct.X509_name_st */
            	94, 0,
            	328, 16,
            	116, 24,
            1, 8, 1, /* 328: pointer.struct.buf_mem_st */
            	333, 0,
            0, 24, 1, /* 333: struct.buf_mem_st */
            	116, 8,
            1, 8, 1, /* 338: pointer.struct.X509_val_st */
            	343, 0,
            0, 16, 2, /* 343: struct.X509_val_st */
            	263, 0,
            	263, 8,
            1, 8, 1, /* 350: pointer.struct.X509_pubkey_st */
            	355, 0,
            0, 24, 3, /* 355: struct.X509_pubkey_st */
            	273, 0,
            	263, 8,
            	364, 16,
            1, 8, 1, /* 364: pointer.struct.evp_pkey_st */
            	369, 0,
            0, 56, 4, /* 369: struct.evp_pkey_st */
            	380, 16,
            	483, 24,
            	309, 32,
            	94, 48,
            1, 8, 1, /* 380: pointer.struct.evp_pkey_asn1_method_st */
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
            1, 8, 1, /* 436: pointer.struct.unnamed */
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
            1, 8, 1, /* 483: pointer.struct.engine_st */
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
            1, 8, 1, /* 539: pointer.struct.rsa_meth_st */
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
            1, 8, 1, /* 594: pointer.struct.dsa_method */
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
            1, 8, 1, /* 645: pointer.struct.dh_method */
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
            1, 8, 1, /* 681: pointer.struct.ecdh_method */
            	686, 0,
            0, 32, 3, /* 686: struct.ecdh_method */
            	116, 0,
            	695, 8,
            	116, 24,
            4097, 8, 0, /* 695: pointer.func */
            1, 8, 1, /* 698: pointer.struct.ecdsa_method */
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
            1, 8, 1, /* 725: pointer.struct.rand_meth_st */
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
            1, 8, 1, /* 760: pointer.struct.store_method_st */
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
            1, 8, 1, /* 792: pointer.struct.ENGINE_CMD_DEFN_st */
            	797, 0,
            0, 32, 2, /* 797: struct.ENGINE_CMD_DEFN_st */
            	116, 8,
            	116, 16,
            0, 24, 1, /* 804: struct.ASN1_ENCODING_st */
            	116, 0,
            1, 8, 1, /* 809: pointer.struct.AUTHORITY_KEYID_st */
            	814, 0,
            0, 24, 3, /* 814: struct.AUTHORITY_KEYID_st */
            	263, 0,
            	94, 8,
            	263, 16,
            1, 8, 1, /* 823: pointer.struct.X509_POLICY_CACHE_st */
            	828, 0,
            0, 40, 2, /* 828: struct.X509_POLICY_CACHE_st */
            	835, 0,
            	94, 8,
            1, 8, 1, /* 835: pointer.struct.X509_POLICY_DATA_st */
            	840, 0,
            0, 32, 3, /* 840: struct.X509_POLICY_DATA_st */
            	285, 8,
            	94, 16,
            	94, 24,
            1, 8, 1, /* 849: pointer.struct.NAME_CONSTRAINTS_st */
            	854, 0,
            0, 16, 2, /* 854: struct.NAME_CONSTRAINTS_st */
            	94, 0,
            	94, 8,
            1, 8, 1, /* 861: pointer.struct.x509_cert_aux_st */
            	866, 0,
            0, 40, 5, /* 866: struct.x509_cert_aux_st */
            	94, 0,
            	94, 8,
            	263, 16,
            	263, 24,
            	94, 32,
            1, 8, 1, /* 879: pointer.struct.env_md_st */
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
            1, 8, 1, /* 924: pointer.struct.rsa_st */
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
            1, 8, 1, /* 966: pointer.struct.bignum_st */
            	971, 0,
            0, 24, 1, /* 971: struct.bignum_st */
            	976, 0,
            1, 8, 1, /* 976: pointer.int */
            	981, 0,
            0, 4, 0, /* 981: int */
            1, 8, 1, /* 984: pointer.struct.bn_mont_ctx_st */
            	989, 0,
            0, 96, 3, /* 989: struct.bn_mont_ctx_st */
            	971, 8,
            	971, 32,
            	971, 56,
            1, 8, 1, /* 998: pointer.struct.bn_blinding_st */
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
            1, 8, 1, /* 1028: pointer.struct.dh_st */
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
            1, 8, 1, /* 1063: pointer.struct.ec_key_st */
            	1068, 0,
            0, 56, 4, /* 1068: struct.ec_key_st */
            	1079, 8,
            	1256, 16,
            	966, 24,
            	1272, 48,
            1, 8, 1, /* 1079: pointer.struct.ec_group_st */
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
            1, 8, 1, /* 1111: pointer.struct.ec_method_st */
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
            1, 8, 1, /* 1256: pointer.struct.ec_point_st */
            	1261, 0,
            0, 88, 4, /* 1261: struct.ec_point_st */
            	1111, 0,
            	971, 8,
            	971, 32,
            	971, 56,
            1, 8, 1, /* 1272: pointer.struct.ec_extra_data_st */
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
            1, 8, 1, /* 1318: pointer.struct.cert_st */
            	168, 0,
            4097, 8, 0, /* 1323: pointer.func */
            0, 0, 0, /* 1326: func */
            0, 16, 0, /* 1329: struct.rlimit */
            1, 8, 1, /* 1332: pointer.struct.ssl3_buf_freelist_st */
            	1337, 0,
            0, 24, 1, /* 1337: struct.ssl3_buf_freelist_st */
            	1342, 16,
            1, 8, 1, /* 1342: pointer.struct.ssl3_buf_freelist_entry_st */
            	1347, 0,
            0, 8, 1, /* 1347: struct.ssl3_buf_freelist_entry_st */
            	1342, 0,
            0, 20, 0, /* 1352: array[20].char */
            0, 0, 0, /* 1355: func */
            0, 0, 0, /* 1358: func */
            0, 352, 14, /* 1361: struct.ssl_session_st */
            	116, 144,
            	116, 152,
            	1392, 168,
            	201, 176,
            	1412, 224,
            	94, 240,
            	154, 248,
            	1422, 264,
            	1422, 272,
            	116, 280,
            	116, 296,
            	116, 312,
            	116, 320,
            	116, 344,
            1, 8, 1, /* 1392: pointer.struct.sess_cert_st */
            	1397, 0,
            0, 248, 6, /* 1397: struct.sess_cert_st */
            	94, 0,
            	187, 16,
            	1299, 24,
            	924, 216,
            	1028, 224,
            	1063, 232,
            1, 8, 1, /* 1412: pointer.struct.ssl_cipher_st */
            	1417, 0,
            0, 88, 1, /* 1417: struct.ssl_cipher_st */
            	116, 8,
            1, 8, 1, /* 1422: pointer.struct.ssl_session_st */
            	1361, 0,
            4097, 8, 0, /* 1427: pointer.func */
            0, 56, 2, /* 1430: struct.comp_ctx_st */
            	1437, 0,
            	154, 40,
            1, 8, 1, /* 1437: pointer.struct.comp_method_st */
            	1442, 0,
            0, 64, 7, /* 1442: struct.comp_method_st */
            	116, 8,
            	1459, 16,
            	1462, 24,
            	1465, 32,
            	1465, 40,
            	1468, 48,
            	1468, 56,
            4097, 8, 0, /* 1459: pointer.func */
            4097, 8, 0, /* 1462: pointer.func */
            4097, 8, 0, /* 1465: pointer.func */
            4097, 8, 0, /* 1468: pointer.func */
            0, 88, 1, /* 1471: struct.hm_header_st */
            	1476, 48,
            0, 40, 4, /* 1476: struct.dtls1_retransmit_state */
            	1487, 0,
            	1543, 8,
            	1676, 16,
            	1422, 24,
            1, 8, 1, /* 1487: pointer.struct.evp_cipher_ctx_st */
            	1492, 0,
            0, 168, 4, /* 1492: struct.evp_cipher_ctx_st */
            	1503, 0,
            	483, 8,
            	1540, 96,
            	1540, 120,
            1, 8, 1, /* 1503: pointer.struct.evp_cipher_st */
            	1508, 0,
            0, 88, 7, /* 1508: struct.evp_cipher_st */
            	1525, 24,
            	1528, 32,
            	1531, 40,
            	1534, 56,
            	1534, 64,
            	1537, 72,
            	1540, 80,
            4097, 8, 0, /* 1525: pointer.func */
            4097, 8, 0, /* 1528: pointer.func */
            4097, 8, 0, /* 1531: pointer.func */
            4097, 8, 0, /* 1534: pointer.func */
            4097, 8, 0, /* 1537: pointer.func */
            0, 8, 0, /* 1540: pointer.void */
            1, 8, 1, /* 1543: pointer.struct.env_md_ctx_st */
            	1548, 0,
            0, 48, 5, /* 1548: struct.env_md_ctx_st */
            	879, 0,
            	483, 8,
            	1540, 24,
            	1561, 32,
            	906, 40,
            1, 8, 1, /* 1561: pointer.struct.evp_pkey_ctx_st */
            	1566, 0,
            0, 80, 8, /* 1566: struct.evp_pkey_ctx_st */
            	1585, 0,
            	483, 8,
            	364, 16,
            	364, 24,
            	116, 40,
            	116, 48,
            	436, 56,
            	976, 64,
            1, 8, 1, /* 1585: pointer.struct.evp_pkey_method_st */
            	1590, 0,
            0, 208, 25, /* 1590: struct.evp_pkey_method_st */
            	436, 8,
            	1643, 16,
            	1646, 24,
            	436, 32,
            	1649, 40,
            	436, 48,
            	1649, 56,
            	436, 64,
            	1652, 72,
            	436, 80,
            	1655, 88,
            	436, 96,
            	1652, 104,
            	1658, 112,
            	1661, 120,
            	1658, 128,
            	1664, 136,
            	436, 144,
            	1652, 152,
            	436, 160,
            	1652, 168,
            	436, 176,
            	1667, 184,
            	1670, 192,
            	1673, 200,
            4097, 8, 0, /* 1643: pointer.func */
            4097, 8, 0, /* 1646: pointer.func */
            4097, 8, 0, /* 1649: pointer.func */
            4097, 8, 0, /* 1652: pointer.func */
            4097, 8, 0, /* 1655: pointer.func */
            4097, 8, 0, /* 1658: pointer.func */
            4097, 8, 0, /* 1661: pointer.func */
            4097, 8, 0, /* 1664: pointer.func */
            4097, 8, 0, /* 1667: pointer.func */
            4097, 8, 0, /* 1670: pointer.func */
            4097, 8, 0, /* 1673: pointer.func */
            1, 8, 1, /* 1676: pointer.struct.comp_ctx_st */
            	1430, 0,
            4097, 8, 0, /* 1681: pointer.func */
            1, 8, 1, /* 1684: pointer.struct._pitem */
            	1689, 0,
            0, 24, 2, /* 1689: struct._pitem */
            	116, 8,
            	1684, 16,
            0, 16, 1, /* 1696: struct._pqueue */
            	1684, 0,
            0, 0, 0, /* 1701: func */
            0, 16, 0, /* 1704: union.anon */
            1, 8, 1, /* 1707: pointer.struct.dtls1_state_st */
            	1712, 0,
            0, 888, 7, /* 1712: struct.dtls1_state_st */
            	1729, 576,
            	1729, 592,
            	1734, 608,
            	1734, 616,
            	1729, 624,
            	1471, 648,
            	1471, 736,
            0, 16, 1, /* 1729: struct.record_pqueue_st */
            	1734, 8,
            1, 8, 1, /* 1734: pointer.struct._pqueue */
            	1696, 0,
            0, 0, 0, /* 1739: func */
            0, 0, 0, /* 1742: func */
            1, 8, 1, /* 1745: pointer.struct.ssl_comp_st */
            	1750, 0,
            0, 24, 2, /* 1750: struct.ssl_comp_st */
            	116, 8,
            	1437, 16,
            4097, 8, 0, /* 1757: pointer.func */
            0, 0, 0, /* 1760: func */
            0, 0, 0, /* 1763: func */
            0, 0, 0, /* 1766: func */
            0, 0, 0, /* 1769: func */
            0, 0, 0, /* 1772: func */
            0, 0, 0, /* 1775: func */
            0, 9, 0, /* 1778: array[9].char */
            0, 0, 0, /* 1781: func */
            0, 0, 0, /* 1784: func */
            0, 0, 0, /* 1787: func */
            0, 0, 0, /* 1790: func */
            0, 0, 0, /* 1793: func */
            0, 0, 0, /* 1796: func */
            0, 0, 0, /* 1799: func */
            0, 0, 0, /* 1802: func */
            0, 0, 0, /* 1805: func */
            0, 0, 0, /* 1808: func */
            0, 0, 0, /* 1811: func */
            0, 0, 0, /* 1814: func */
            0, 12, 0, /* 1817: struct.ap_unix_identity_t */
            0, 0, 0, /* 1820: func */
            0, 0, 0, /* 1823: func */
            0, 0, 0, /* 1826: func */
            0, 0, 0, /* 1829: func */
            0, 0, 0, /* 1832: func */
            0, 0, 0, /* 1835: func */
            0, 0, 0, /* 1838: func */
            0, 0, 0, /* 1841: func */
            0, 0, 0, /* 1844: func */
            0, 0, 0, /* 1847: func */
            0, 0, 0, /* 1850: func */
            0, 0, 0, /* 1853: func */
            0, 8, 0, /* 1856: array[2].int */
            0, 128, 0, /* 1859: array[128].char */
            0, 528, 8, /* 1862: struct.anon */
            	1412, 408,
            	1028, 416,
            	1063, 424,
            	94, 464,
            	116, 480,
            	1503, 488,
            	879, 496,
            	1745, 512,
            0, 0, 0, /* 1881: func */
            0, 0, 0, /* 1884: func */
            0, 0, 0, /* 1887: func */
            4097, 8, 0, /* 1890: pointer.func */
            0, 0, 0, /* 1893: func */
            0, 0, 0, /* 1896: func */
            0, 0, 0, /* 1899: func */
            4097, 8, 0, /* 1902: pointer.func */
            0, 16, 1, /* 1905: struct.tls_session_ticket_ext_st */
            	1540, 8,
            0, 0, 0, /* 1910: func */
            1, 8, 1, /* 1913: pointer.struct.tls_session_ticket_ext_st */
            	1905, 0,
            0, 0, 0, /* 1918: func */
            4097, 8, 0, /* 1921: pointer.func */
            0, 24, 0, /* 1924: array[6].int */
            0, 2, 0, /* 1927: array[2].char */
            0, 0, 0, /* 1930: func */
            1, 8, 1, /* 1933: pointer.struct.ssl3_state_st */
            	1938, 0,
            0, 1200, 10, /* 1938: struct.ssl3_state_st */
            	1961, 240,
            	1961, 264,
            	1966, 288,
            	1966, 344,
            	116, 432,
            	1975, 440,
            	2041, 448,
            	1540, 496,
            	1540, 512,
            	1862, 528,
            0, 24, 1, /* 1961: struct.ssl3_buffer_st */
            	116, 0,
            0, 56, 3, /* 1966: struct.ssl3_record_st */
            	116, 16,
            	116, 24,
            	116, 32,
            1, 8, 1, /* 1975: pointer.struct.bio_st */
            	1980, 0,
            0, 112, 7, /* 1980: struct.bio_st */
            	1997, 0,
            	2038, 8,
            	116, 16,
            	1540, 48,
            	1975, 56,
            	1975, 64,
            	154, 96,
            1, 8, 1, /* 1997: pointer.struct.bio_method_st */
            	2002, 0,
            0, 80, 9, /* 2002: struct.bio_method_st */
            	116, 8,
            	2023, 16,
            	2023, 24,
            	2026, 32,
            	2023, 40,
            	2029, 48,
            	2032, 56,
            	2032, 64,
            	2035, 72,
            4097, 8, 0, /* 2023: pointer.func */
            4097, 8, 0, /* 2026: pointer.func */
            4097, 8, 0, /* 2029: pointer.func */
            4097, 8, 0, /* 2032: pointer.func */
            4097, 8, 0, /* 2035: pointer.func */
            4097, 8, 0, /* 2038: pointer.func */
            1, 8, 1, /* 2041: pointer.pointer.struct.env_md_ctx_st */
            	1543, 0,
            0, 0, 0, /* 2046: func */
            0, 72, 0, /* 2049: struct.anon */
            0, 16, 0, /* 2052: array[16].char */
            0, 0, 0, /* 2055: func */
            0, 8, 0, /* 2058: long */
            1, 8, 1, /* 2061: pointer.struct.iovec */
            	1020, 0,
            4097, 8, 0, /* 2066: pointer.func */
            0, 0, 0, /* 2069: func */
            0, 128, 14, /* 2072: struct.srp_ctx_st */
            	1540, 0,
            	2103, 8,
            	15, 16,
            	2066, 24,
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
            4097, 8, 0, /* 2103: pointer.func */
            1, 8, 1, /* 2106: pointer.struct.ssl_ctx_st */
            	2111, 0,
            0, 736, 50, /* 2111: struct.ssl_ctx_st */
            	2214, 0,
            	94, 8,
            	94, 16,
            	56, 24,
            	33, 32,
            	1422, 48,
            	1422, 56,
            	2359, 80,
            	2362, 88,
            	2365, 96,
            	1427, 152,
            	1540, 160,
            	24, 168,
            	1540, 176,
            	2368, 184,
            	2371, 192,
            	2284, 200,
            	154, 208,
            	879, 224,
            	879, 232,
            	879, 240,
            	94, 248,
            	94, 256,
            	1921, 264,
            	94, 272,
            	1318, 304,
            	1323, 320,
            	1540, 328,
            	136, 376,
            	2371, 384,
            	124, 392,
            	483, 408,
            	2103, 416,
            	1540, 424,
            	1757, 480,
            	15, 488,
            	1540, 496,
            	2374, 504,
            	1540, 512,
            	116, 520,
            	1681, 528,
            	2338, 536,
            	1332, 552,
            	1332, 560,
            	2072, 568,
            	2377, 696,
            	1540, 704,
            	2380, 712,
            	1540, 720,
            	94, 728,
            1, 8, 1, /* 2214: pointer.struct.ssl_method_st */
            	2219, 0,
            0, 232, 28, /* 2219: struct.ssl_method_st */
            	2278, 8,
            	2281, 16,
            	2281, 24,
            	2278, 32,
            	2278, 40,
            	2284, 48,
            	2284, 56,
            	2284, 64,
            	2278, 72,
            	2278, 80,
            	2278, 88,
            	2287, 96,
            	2290, 104,
            	2293, 112,
            	2278, 120,
            	2296, 128,
            	2299, 136,
            	2302, 144,
            	1890, 152,
            	2278, 160,
            	757, 168,
            	1902, 176,
            	2305, 184,
            	1468, 192,
            	2308, 200,
            	757, 208,
            	2353, 216,
            	2356, 224,
            4097, 8, 0, /* 2278: pointer.func */
            4097, 8, 0, /* 2281: pointer.func */
            4097, 8, 0, /* 2284: pointer.func */
            4097, 8, 0, /* 2287: pointer.func */
            4097, 8, 0, /* 2290: pointer.func */
            4097, 8, 0, /* 2293: pointer.func */
            4097, 8, 0, /* 2296: pointer.func */
            4097, 8, 0, /* 2299: pointer.func */
            4097, 8, 0, /* 2302: pointer.func */
            4097, 8, 0, /* 2305: pointer.func */
            1, 8, 1, /* 2308: pointer.struct.ssl3_enc_method */
            	2313, 0,
            0, 112, 11, /* 2313: struct.ssl3_enc_method */
            	436, 0,
            	2284, 8,
            	2278, 16,
            	2338, 24,
            	436, 32,
            	2341, 40,
            	2344, 56,
            	116, 64,
            	116, 80,
            	2347, 96,
            	2350, 104,
            4097, 8, 0, /* 2338: pointer.func */
            4097, 8, 0, /* 2341: pointer.func */
            4097, 8, 0, /* 2344: pointer.func */
            4097, 8, 0, /* 2347: pointer.func */
            4097, 8, 0, /* 2350: pointer.func */
            4097, 8, 0, /* 2353: pointer.func */
            4097, 8, 0, /* 2356: pointer.func */
            4097, 8, 0, /* 2359: pointer.func */
            4097, 8, 0, /* 2362: pointer.func */
            4097, 8, 0, /* 2365: pointer.func */
            4097, 8, 0, /* 2368: pointer.func */
            4097, 8, 0, /* 2371: pointer.func */
            4097, 8, 0, /* 2374: pointer.func */
            4097, 8, 0, /* 2377: pointer.func */
            4097, 8, 0, /* 2380: pointer.func */
            1, 8, 1, /* 2383: pointer.struct.ssl2_state_st */
            	2388, 0,
            0, 344, 9, /* 2388: struct.ssl2_state_st */
            	116, 24,
            	116, 56,
            	116, 64,
            	116, 72,
            	116, 104,
            	116, 112,
            	116, 120,
            	116, 128,
            	116, 136,
            0, 0, 0, /* 2409: func */
            0, 0, 0, /* 2412: func */
            0, 0, 0, /* 2415: func */
            0, 0, 0, /* 2418: func */
            0, 0, 0, /* 2421: func */
            0, 0, 0, /* 2424: func */
            0, 0, 0, /* 2427: func */
            0, 0, 0, /* 2430: func */
            0, 0, 0, /* 2433: func */
            0, 0, 0, /* 2436: func */
            0, 0, 0, /* 2439: func */
            0, 0, 0, /* 2442: func */
            0, 0, 0, /* 2445: func */
            0, 0, 0, /* 2448: func */
            0, 0, 0, /* 2451: func */
            0, 4, 0, /* 2454: array[4].char */
            0, 0, 0, /* 2457: func */
            0, 0, 0, /* 2460: func */
            0, 0, 0, /* 2463: func */
            0, 0, 0, /* 2466: func */
            0, 0, 0, /* 2469: func */
            0, 0, 0, /* 2472: func */
            0, 0, 0, /* 2475: func */
            1, 8, 1, /* 2478: pointer.struct.ssl_st */
            	2483, 0,
            0, 808, 51, /* 2483: struct.ssl_st */
            	2214, 8,
            	1975, 16,
            	1975, 24,
            	1975, 32,
            	2278, 48,
            	328, 80,
            	1540, 88,
            	116, 104,
            	2383, 120,
            	1933, 128,
            	1707, 136,
            	1323, 152,
            	1540, 160,
            	124, 176,
            	94, 184,
            	94, 192,
            	1487, 208,
            	1543, 216,
            	1676, 224,
            	1487, 232,
            	1543, 240,
            	1676, 248,
            	1318, 256,
            	1422, 304,
            	2371, 312,
            	136, 328,
            	1921, 336,
            	1681, 352,
            	2338, 360,
            	2106, 368,
            	154, 392,
            	94, 408,
            	6, 464,
            	1540, 472,
            	116, 480,
            	94, 504,
            	94, 512,
            	116, 520,
            	116, 544,
            	116, 560,
            	1540, 568,
            	1913, 584,
            	2341, 592,
            	1540, 600,
            	3, 608,
            	1540, 616,
            	2106, 624,
            	116, 632,
            	94, 648,
            	2061, 656,
            	2072, 680,
            0, 0, 0, /* 2588: func */
            0, 0, 0, /* 2591: func */
            0, 0, 0, /* 2594: func */
            0, 0, 0, /* 2597: func */
            0, 0, 0, /* 2600: func */
            0, 0, 0, /* 2603: func */
            0, 0, 0, /* 2606: func */
            0, 0, 0, /* 2609: func */
            0, 0, 0, /* 2612: func */
            0, 0, 0, /* 2615: func */
            0, 0, 0, /* 2618: func */
            0, 0, 0, /* 2621: func */
            0, 8, 0, /* 2624: array[8].char */
            0, 0, 0, /* 2627: func */
            0, 0, 0, /* 2630: func */
            0, 256, 0, /* 2633: array[256].char */
            0, 48, 0, /* 2636: array[48].char */
            0, 0, 0, /* 2639: func */
            0, 0, 0, /* 2642: func */
            0, 2, 0, /* 2645: short */
            0, 0, 0, /* 2648: func */
            0, 0, 0, /* 2651: func */
            0, 1, 0, /* 2654: char */
            0, 0, 0, /* 2657: func */
            0, 0, 0, /* 2660: func */
            0, 32, 0, /* 2663: array[32].char */
            0, 0, 0, /* 2666: func */
            0, 0, 0, /* 2669: func */
            0, 0, 0, /* 2672: func */
            0, 0, 0, /* 2675: func */
            0, 20, 0, /* 2678: array[5].int */
            0, 0, 0, /* 2681: func */
            0, 0, 0, /* 2684: func */
            0, 0, 0, /* 2687: func */
            0, 0, 0, /* 2690: func */
            0, 0, 0, /* 2693: func */
            0, 0, 0, /* 2696: func */
            0, 0, 0, /* 2699: func */
            0, 0, 0, /* 2702: func */
            0, 0, 0, /* 2705: func */
            0, 0, 0, /* 2708: func */
            0, 0, 0, /* 2711: func */
            0, 0, 0, /* 2714: func */
            0, 0, 0, /* 2717: func */
            0, 0, 0, /* 2720: func */
            0, 0, 0, /* 2723: func */
            0, 0, 0, /* 2726: func */
            0, 0, 0, /* 2729: func */
            0, 0, 0, /* 2732: func */
            0, 0, 0, /* 2735: func */
            0, 0, 0, /* 2738: func */
            0, 64, 0, /* 2741: array[64].char */
            0, 0, 0, /* 2744: func */
            0, 0, 0, /* 2747: func */
            0, 0, 0, /* 2750: func */
            0, 0, 0, /* 2753: func */
            0, 0, 0, /* 2756: func */
            0, 0, 0, /* 2759: func */
            0, 0, 0, /* 2762: func */
            0, 0, 0, /* 2765: func */
            0, 0, 0, /* 2768: func */
            0, 0, 0, /* 2771: func */
            0, 0, 0, /* 2774: func */
            0, 12, 0, /* 2777: array[12].char */
            0, 0, 0, /* 2780: func */
            0, 0, 0, /* 2783: func */
            0, 0, 0, /* 2786: func */
            0, 0, 0, /* 2789: func */
            0, 0, 0, /* 2792: func */
            0, 0, 0, /* 2795: func */
            0, 0, 0, /* 2798: func */
            0, 0, 0, /* 2801: func */
            0, 0, 0, /* 2804: func */
            0, 0, 0, /* 2807: func */
            0, 0, 0, /* 2810: func */
            0, 0, 0, /* 2813: func */
            0, 0, 0, /* 2816: func */
            0, 0, 0, /* 2819: func */
            0, 0, 0, /* 2822: func */
            0, 0, 0, /* 2825: func */
            0, 0, 0, /* 2828: func */
            0, 0, 0, /* 2831: func */
            0, 0, 0, /* 2834: func */
        },
        .arg_entity_index = { 2478, },
        .ret_entity_index = -1,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    SSL * new_arg_a = *((SSL * *)new_args->args[0]);

    void (*orig_SSL_free)(SSL *);
    orig_SSL_free = dlsym(RTLD_NEXT, "SSL_free");
    (*orig_SSL_free)(new_arg_a);

    syscall(889);

}

