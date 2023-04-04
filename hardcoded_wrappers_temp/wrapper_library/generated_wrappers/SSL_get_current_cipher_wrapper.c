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

const SSL_CIPHER * bb_SSL_get_current_cipher(const SSL * arg_a);

const SSL_CIPHER * SSL_get_current_cipher(const SSL * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_get_current_cipher called %lu\n", in_lib);
    if (!in_lib)
        return bb_SSL_get_current_cipher(arg_a);
    else {
        const SSL_CIPHER * (*orig_SSL_get_current_cipher)(const SSL *);
        orig_SSL_get_current_cipher = dlsym(RTLD_NEXT, "SSL_get_current_cipher");
        return orig_SSL_get_current_cipher(arg_a);
    }
}

const SSL_CIPHER * bb_SSL_get_current_cipher(const SSL * arg_a) 
{
    const SSL_CIPHER * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            4097, 8, 0, /* 0: pointer.func */
            0, 16, 1, /* 3: struct.tls_session_ticket_ext_st */
            	8, 8,
            0, 8, 0, /* 8: pointer.void */
            4097, 8, 0, /* 11: pointer.func */
            1, 8, 1, /* 14: pointer.struct.ssl3_buf_freelist_entry_st */
            	19, 0,
            0, 8, 1, /* 19: struct.ssl3_buf_freelist_entry_st */
            	14, 0,
            4097, 8, 0, /* 24: pointer.func */
            4097, 8, 0, /* 27: pointer.func */
            4097, 8, 0, /* 30: pointer.func */
            4097, 8, 0, /* 33: pointer.func */
            4097, 8, 0, /* 36: pointer.func */
            4097, 8, 0, /* 39: pointer.func */
            4097, 8, 0, /* 42: pointer.func */
            0, 24, 2, /* 45: struct.lhash_node_st */
            	8, 0,
            	52, 8,
            1, 8, 1, /* 52: pointer.struct.lhash_node_st */
            	45, 0,
            1, 8, 1, /* 57: pointer.pointer.struct.lhash_node_st */
            	52, 0,
            0, 176, 3, /* 62: struct.lhash_st */
            	57, 0,
            	71, 8,
            	42, 16,
            4097, 8, 0, /* 71: pointer.func */
            1, 8, 1, /* 74: pointer.struct.lhash_st */
            	62, 0,
            4097, 8, 0, /* 79: pointer.func */
            4097, 8, 0, /* 82: pointer.func */
            4097, 8, 0, /* 85: pointer.func */
            4097, 8, 0, /* 88: pointer.func */
            4097, 8, 0, /* 91: pointer.func */
            1, 8, 1, /* 94: pointer.struct.x509_store_st */
            	99, 0,
            0, 144, 15, /* 99: struct.x509_store_st */
            	132, 8,
            	132, 16,
            	159, 24,
            	91, 32,
            	171, 40,
            	88, 48,
            	85, 56,
            	91, 64,
            	174, 72,
            	82, 80,
            	79, 88,
            	177, 96,
            	177, 104,
            	91, 112,
            	180, 120,
            1, 8, 1, /* 132: pointer.struct.stack_st_OPENSSL_STRING */
            	137, 0,
            0, 32, 1, /* 137: struct.stack_st_OPENSSL_STRING */
            	142, 0,
            0, 32, 2, /* 142: struct.stack_st */
            	149, 8,
            	71, 24,
            1, 8, 1, /* 149: pointer.pointer.char */
            	154, 0,
            1, 8, 1, /* 154: pointer.char */
            	4096, 0,
            1, 8, 1, /* 159: pointer.struct.X509_VERIFY_PARAM_st */
            	164, 0,
            0, 56, 2, /* 164: struct.X509_VERIFY_PARAM_st */
            	154, 0,
            	132, 48,
            4097, 8, 0, /* 171: pointer.func */
            4097, 8, 0, /* 174: pointer.func */
            4097, 8, 0, /* 177: pointer.func */
            0, 16, 1, /* 180: struct.crypto_ex_data_st */
            	132, 0,
            4097, 8, 0, /* 185: pointer.func */
            4097, 8, 0, /* 188: pointer.func */
            4097, 8, 0, /* 191: pointer.func */
            0, 296, 8, /* 194: struct.cert_st */
            	213, 0,
            	950, 48,
            	1051, 56,
            	1054, 64,
            	1086, 72,
            	1089, 80,
            	191, 88,
            	1325, 96,
            1, 8, 1, /* 213: pointer.struct.cert_pkey_st */
            	218, 0,
            0, 24, 3, /* 218: struct.cert_pkey_st */
            	227, 0,
            	390, 8,
            	905, 16,
            1, 8, 1, /* 227: pointer.struct.x509_st */
            	232, 0,
            0, 184, 12, /* 232: struct.x509_st */
            	259, 0,
            	299, 8,
            	289, 16,
            	154, 32,
            	180, 40,
            	289, 104,
            	835, 112,
            	849, 120,
            	132, 128,
            	132, 136,
            	875, 144,
            	887, 176,
            1, 8, 1, /* 259: pointer.struct.x509_cinf_st */
            	264, 0,
            0, 104, 11, /* 264: struct.x509_cinf_st */
            	289, 0,
            	289, 8,
            	299, 16,
            	340, 24,
            	364, 32,
            	340, 40,
            	376, 48,
            	289, 56,
            	289, 64,
            	132, 72,
            	830, 80,
            1, 8, 1, /* 289: pointer.struct.asn1_string_st */
            	294, 0,
            0, 24, 1, /* 294: struct.asn1_string_st */
            	154, 8,
            1, 8, 1, /* 299: pointer.struct.X509_algor_st */
            	304, 0,
            0, 16, 2, /* 304: struct.X509_algor_st */
            	311, 0,
            	325, 8,
            1, 8, 1, /* 311: pointer.struct.asn1_object_st */
            	316, 0,
            0, 40, 3, /* 316: struct.asn1_object_st */
            	154, 0,
            	154, 8,
            	154, 24,
            1, 8, 1, /* 325: pointer.struct.asn1_type_st */
            	330, 0,
            0, 16, 1, /* 330: struct.asn1_type_st */
            	335, 8,
            0, 8, 1, /* 335: struct.fnames */
            	154, 0,
            1, 8, 1, /* 340: pointer.struct.X509_name_st */
            	345, 0,
            0, 40, 3, /* 345: struct.X509_name_st */
            	132, 0,
            	354, 16,
            	154, 24,
            1, 8, 1, /* 354: pointer.struct.buf_mem_st */
            	359, 0,
            0, 24, 1, /* 359: struct.buf_mem_st */
            	154, 8,
            1, 8, 1, /* 364: pointer.struct.X509_val_st */
            	369, 0,
            0, 16, 2, /* 369: struct.X509_val_st */
            	289, 0,
            	289, 8,
            1, 8, 1, /* 376: pointer.struct.X509_pubkey_st */
            	381, 0,
            0, 24, 3, /* 381: struct.X509_pubkey_st */
            	299, 0,
            	289, 8,
            	390, 16,
            1, 8, 1, /* 390: pointer.struct.evp_pkey_st */
            	395, 0,
            0, 56, 4, /* 395: struct.evp_pkey_st */
            	406, 16,
            	509, 24,
            	335, 32,
            	132, 48,
            1, 8, 1, /* 406: pointer.struct.evp_pkey_asn1_method_st */
            	411, 0,
            0, 208, 24, /* 411: struct.evp_pkey_asn1_method_st */
            	154, 16,
            	154, 24,
            	462, 32,
            	470, 40,
            	473, 48,
            	476, 56,
            	479, 64,
            	482, 72,
            	476, 80,
            	485, 88,
            	485, 96,
            	488, 104,
            	491, 112,
            	485, 120,
            	473, 128,
            	473, 136,
            	476, 144,
            	494, 152,
            	497, 160,
            	500, 168,
            	488, 176,
            	491, 184,
            	503, 192,
            	506, 200,
            1, 8, 1, /* 462: pointer.struct.unnamed */
            	467, 0,
            0, 0, 0, /* 467: struct.unnamed */
            4097, 8, 0, /* 470: pointer.func */
            4097, 8, 0, /* 473: pointer.func */
            4097, 8, 0, /* 476: pointer.func */
            4097, 8, 0, /* 479: pointer.func */
            4097, 8, 0, /* 482: pointer.func */
            4097, 8, 0, /* 485: pointer.func */
            4097, 8, 0, /* 488: pointer.func */
            4097, 8, 0, /* 491: pointer.func */
            4097, 8, 0, /* 494: pointer.func */
            4097, 8, 0, /* 497: pointer.func */
            4097, 8, 0, /* 500: pointer.func */
            4097, 8, 0, /* 503: pointer.func */
            4097, 8, 0, /* 506: pointer.func */
            1, 8, 1, /* 509: pointer.struct.engine_st */
            	514, 0,
            0, 216, 24, /* 514: struct.engine_st */
            	154, 0,
            	154, 8,
            	565, 16,
            	620, 24,
            	671, 32,
            	707, 40,
            	724, 48,
            	751, 56,
            	786, 64,
            	794, 72,
            	797, 80,
            	800, 88,
            	803, 96,
            	806, 104,
            	806, 112,
            	806, 120,
            	809, 128,
            	812, 136,
            	812, 144,
            	815, 152,
            	818, 160,
            	180, 184,
            	509, 200,
            	509, 208,
            1, 8, 1, /* 565: pointer.struct.rsa_meth_st */
            	570, 0,
            0, 112, 13, /* 570: struct.rsa_meth_st */
            	154, 0,
            	599, 8,
            	599, 16,
            	599, 24,
            	599, 32,
            	602, 40,
            	605, 48,
            	608, 56,
            	608, 64,
            	154, 80,
            	611, 88,
            	614, 96,
            	617, 104,
            4097, 8, 0, /* 599: pointer.func */
            4097, 8, 0, /* 602: pointer.func */
            4097, 8, 0, /* 605: pointer.func */
            4097, 8, 0, /* 608: pointer.func */
            4097, 8, 0, /* 611: pointer.func */
            4097, 8, 0, /* 614: pointer.func */
            4097, 8, 0, /* 617: pointer.func */
            1, 8, 1, /* 620: pointer.struct.dsa_method */
            	625, 0,
            0, 96, 11, /* 625: struct.dsa_method */
            	154, 0,
            	650, 8,
            	653, 16,
            	656, 24,
            	659, 32,
            	662, 40,
            	665, 48,
            	665, 56,
            	154, 72,
            	668, 80,
            	665, 88,
            4097, 8, 0, /* 650: pointer.func */
            4097, 8, 0, /* 653: pointer.func */
            4097, 8, 0, /* 656: pointer.func */
            4097, 8, 0, /* 659: pointer.func */
            4097, 8, 0, /* 662: pointer.func */
            4097, 8, 0, /* 665: pointer.func */
            4097, 8, 0, /* 668: pointer.func */
            1, 8, 1, /* 671: pointer.struct.dh_method */
            	676, 0,
            0, 72, 8, /* 676: struct.dh_method */
            	154, 0,
            	695, 8,
            	698, 16,
            	701, 24,
            	695, 32,
            	695, 40,
            	154, 56,
            	704, 64,
            4097, 8, 0, /* 695: pointer.func */
            4097, 8, 0, /* 698: pointer.func */
            4097, 8, 0, /* 701: pointer.func */
            4097, 8, 0, /* 704: pointer.func */
            1, 8, 1, /* 707: pointer.struct.ecdh_method */
            	712, 0,
            0, 32, 3, /* 712: struct.ecdh_method */
            	154, 0,
            	721, 8,
            	154, 24,
            4097, 8, 0, /* 721: pointer.func */
            1, 8, 1, /* 724: pointer.struct.ecdsa_method */
            	729, 0,
            0, 48, 5, /* 729: struct.ecdsa_method */
            	154, 0,
            	742, 8,
            	745, 16,
            	748, 24,
            	154, 40,
            4097, 8, 0, /* 742: pointer.func */
            4097, 8, 0, /* 745: pointer.func */
            4097, 8, 0, /* 748: pointer.func */
            1, 8, 1, /* 751: pointer.struct.rand_meth_st */
            	756, 0,
            0, 48, 6, /* 756: struct.rand_meth_st */
            	771, 0,
            	774, 8,
            	777, 16,
            	780, 24,
            	774, 32,
            	783, 40,
            4097, 8, 0, /* 771: pointer.func */
            4097, 8, 0, /* 774: pointer.func */
            4097, 8, 0, /* 777: pointer.func */
            4097, 8, 0, /* 780: pointer.func */
            4097, 8, 0, /* 783: pointer.func */
            1, 8, 1, /* 786: pointer.struct.store_method_st */
            	791, 0,
            0, 0, 0, /* 791: struct.store_method_st */
            4097, 8, 0, /* 794: pointer.func */
            4097, 8, 0, /* 797: pointer.func */
            4097, 8, 0, /* 800: pointer.func */
            4097, 8, 0, /* 803: pointer.func */
            4097, 8, 0, /* 806: pointer.func */
            4097, 8, 0, /* 809: pointer.func */
            4097, 8, 0, /* 812: pointer.func */
            4097, 8, 0, /* 815: pointer.func */
            1, 8, 1, /* 818: pointer.struct.ENGINE_CMD_DEFN_st */
            	823, 0,
            0, 32, 2, /* 823: struct.ENGINE_CMD_DEFN_st */
            	154, 8,
            	154, 16,
            0, 24, 1, /* 830: struct.ASN1_ENCODING_st */
            	154, 0,
            1, 8, 1, /* 835: pointer.struct.AUTHORITY_KEYID_st */
            	840, 0,
            0, 24, 3, /* 840: struct.AUTHORITY_KEYID_st */
            	289, 0,
            	132, 8,
            	289, 16,
            1, 8, 1, /* 849: pointer.struct.X509_POLICY_CACHE_st */
            	854, 0,
            0, 40, 2, /* 854: struct.X509_POLICY_CACHE_st */
            	861, 0,
            	132, 8,
            1, 8, 1, /* 861: pointer.struct.X509_POLICY_DATA_st */
            	866, 0,
            0, 32, 3, /* 866: struct.X509_POLICY_DATA_st */
            	311, 8,
            	132, 16,
            	132, 24,
            1, 8, 1, /* 875: pointer.struct.NAME_CONSTRAINTS_st */
            	880, 0,
            0, 16, 2, /* 880: struct.NAME_CONSTRAINTS_st */
            	132, 0,
            	132, 8,
            1, 8, 1, /* 887: pointer.struct.x509_cert_aux_st */
            	892, 0,
            0, 40, 5, /* 892: struct.x509_cert_aux_st */
            	132, 0,
            	132, 8,
            	289, 16,
            	289, 24,
            	132, 32,
            1, 8, 1, /* 905: pointer.struct.env_md_st */
            	910, 0,
            0, 120, 8, /* 910: struct.env_md_st */
            	929, 24,
            	932, 32,
            	935, 40,
            	938, 48,
            	929, 56,
            	941, 64,
            	944, 72,
            	947, 112,
            4097, 8, 0, /* 929: pointer.func */
            4097, 8, 0, /* 932: pointer.func */
            4097, 8, 0, /* 935: pointer.func */
            4097, 8, 0, /* 938: pointer.func */
            4097, 8, 0, /* 941: pointer.func */
            4097, 8, 0, /* 944: pointer.func */
            4097, 8, 0, /* 947: pointer.func */
            1, 8, 1, /* 950: pointer.struct.rsa_st */
            	955, 0,
            0, 168, 17, /* 955: struct.rsa_st */
            	565, 16,
            	509, 24,
            	992, 32,
            	992, 40,
            	992, 48,
            	992, 56,
            	992, 64,
            	992, 72,
            	992, 80,
            	992, 88,
            	180, 96,
            	1010, 120,
            	1010, 128,
            	1010, 136,
            	154, 144,
            	1024, 152,
            	1024, 160,
            1, 8, 1, /* 992: pointer.struct.bignum_st */
            	997, 0,
            0, 24, 1, /* 997: struct.bignum_st */
            	1002, 0,
            1, 8, 1, /* 1002: pointer.int */
            	1007, 0,
            0, 4, 0, /* 1007: int */
            1, 8, 1, /* 1010: pointer.struct.bn_mont_ctx_st */
            	1015, 0,
            0, 96, 3, /* 1015: struct.bn_mont_ctx_st */
            	997, 8,
            	997, 32,
            	997, 56,
            1, 8, 1, /* 1024: pointer.struct.bn_blinding_st */
            	1029, 0,
            0, 88, 7, /* 1029: struct.bn_blinding_st */
            	992, 0,
            	992, 8,
            	992, 16,
            	992, 24,
            	1046, 40,
            	1010, 72,
            	605, 80,
            0, 16, 1, /* 1046: struct.iovec */
            	154, 0,
            4097, 8, 0, /* 1051: pointer.func */
            1, 8, 1, /* 1054: pointer.struct.dh_st */
            	1059, 0,
            0, 144, 12, /* 1059: struct.dh_st */
            	992, 8,
            	992, 16,
            	992, 32,
            	992, 40,
            	1010, 56,
            	992, 64,
            	992, 72,
            	154, 80,
            	992, 96,
            	180, 112,
            	671, 128,
            	509, 136,
            4097, 8, 0, /* 1086: pointer.func */
            1, 8, 1, /* 1089: pointer.struct.ec_key_st */
            	1094, 0,
            0, 56, 4, /* 1094: struct.ec_key_st */
            	1105, 8,
            	1282, 16,
            	992, 24,
            	1298, 48,
            1, 8, 1, /* 1105: pointer.struct.ec_group_st */
            	1110, 0,
            0, 232, 12, /* 1110: struct.ec_group_st */
            	1137, 0,
            	1282, 8,
            	997, 16,
            	997, 40,
            	154, 80,
            	1298, 96,
            	997, 104,
            	997, 152,
            	997, 176,
            	154, 208,
            	154, 216,
            	1322, 224,
            1, 8, 1, /* 1137: pointer.struct.ec_method_st */
            	1142, 0,
            0, 304, 37, /* 1142: struct.ec_method_st */
            	1219, 8,
            	1222, 16,
            	1222, 24,
            	1225, 32,
            	1228, 40,
            	1228, 48,
            	1219, 56,
            	1231, 64,
            	1234, 72,
            	1237, 80,
            	1237, 88,
            	1240, 96,
            	1243, 104,
            	1246, 112,
            	1246, 120,
            	1249, 128,
            	1249, 136,
            	1252, 144,
            	1255, 152,
            	1258, 160,
            	1261, 168,
            	1264, 176,
            	1267, 184,
            	1243, 192,
            	1267, 200,
            	1264, 208,
            	1267, 216,
            	1270, 224,
            	1273, 232,
            	1231, 240,
            	1219, 248,
            	1228, 256,
            	1276, 264,
            	1228, 272,
            	1276, 280,
            	1276, 288,
            	1279, 296,
            4097, 8, 0, /* 1219: pointer.func */
            4097, 8, 0, /* 1222: pointer.func */
            4097, 8, 0, /* 1225: pointer.func */
            4097, 8, 0, /* 1228: pointer.func */
            4097, 8, 0, /* 1231: pointer.func */
            4097, 8, 0, /* 1234: pointer.func */
            4097, 8, 0, /* 1237: pointer.func */
            4097, 8, 0, /* 1240: pointer.func */
            4097, 8, 0, /* 1243: pointer.func */
            4097, 8, 0, /* 1246: pointer.func */
            4097, 8, 0, /* 1249: pointer.func */
            4097, 8, 0, /* 1252: pointer.func */
            4097, 8, 0, /* 1255: pointer.func */
            4097, 8, 0, /* 1258: pointer.func */
            4097, 8, 0, /* 1261: pointer.func */
            4097, 8, 0, /* 1264: pointer.func */
            4097, 8, 0, /* 1267: pointer.func */
            4097, 8, 0, /* 1270: pointer.func */
            4097, 8, 0, /* 1273: pointer.func */
            4097, 8, 0, /* 1276: pointer.func */
            4097, 8, 0, /* 1279: pointer.func */
            1, 8, 1, /* 1282: pointer.struct.ec_point_st */
            	1287, 0,
            0, 88, 4, /* 1287: struct.ec_point_st */
            	1137, 0,
            	997, 8,
            	997, 32,
            	997, 56,
            1, 8, 1, /* 1298: pointer.struct.ec_extra_data_st */
            	1303, 0,
            0, 40, 5, /* 1303: struct.ec_extra_data_st */
            	1298, 0,
            	8, 8,
            	1316, 16,
            	1319, 24,
            	1319, 32,
            4097, 8, 0, /* 1316: pointer.func */
            4097, 8, 0, /* 1319: pointer.func */
            4097, 8, 0, /* 1322: pointer.func */
            0, 192, 8, /* 1325: array[8].struct.cert_pkey_st */
            	218, 0,
            	218, 24,
            	218, 48,
            	218, 72,
            	218, 96,
            	218, 120,
            	218, 144,
            	218, 168,
            1, 8, 1, /* 1344: pointer.struct.cert_st */
            	194, 0,
            4097, 8, 0, /* 1349: pointer.func */
            1, 8, 1, /* 1352: pointer.struct.ssl3_buf_freelist_st */
            	1357, 0,
            0, 24, 1, /* 1357: struct.ssl3_buf_freelist_st */
            	14, 16,
            0, 128, 14, /* 1362: struct.srp_ctx_st */
            	154, 0,
            	1393, 8,
            	27, 16,
            	1396, 24,
            	154, 32,
            	992, 40,
            	992, 48,
            	992, 56,
            	992, 64,
            	992, 72,
            	992, 80,
            	992, 88,
            	992, 96,
            	154, 104,
            4097, 8, 0, /* 1393: pointer.func */
            4097, 8, 0, /* 1396: pointer.func */
            1, 8, 1, /* 1399: pointer.struct.evp_pkey_method_st */
            	1404, 0,
            0, 208, 25, /* 1404: struct.evp_pkey_method_st */
            	462, 8,
            	1457, 16,
            	1460, 24,
            	462, 32,
            	1463, 40,
            	462, 48,
            	1463, 56,
            	462, 64,
            	1466, 72,
            	462, 80,
            	1469, 88,
            	462, 96,
            	1466, 104,
            	1472, 112,
            	1475, 120,
            	1472, 128,
            	1478, 136,
            	462, 144,
            	1466, 152,
            	462, 160,
            	1466, 168,
            	462, 176,
            	1481, 184,
            	1484, 192,
            	1487, 200,
            4097, 8, 0, /* 1457: pointer.func */
            4097, 8, 0, /* 1460: pointer.func */
            4097, 8, 0, /* 1463: pointer.func */
            4097, 8, 0, /* 1466: pointer.func */
            4097, 8, 0, /* 1469: pointer.func */
            4097, 8, 0, /* 1472: pointer.func */
            4097, 8, 0, /* 1475: pointer.func */
            4097, 8, 0, /* 1478: pointer.func */
            4097, 8, 0, /* 1481: pointer.func */
            4097, 8, 0, /* 1484: pointer.func */
            4097, 8, 0, /* 1487: pointer.func */
            0, 80, 8, /* 1490: struct.evp_pkey_ctx_st */
            	1399, 0,
            	509, 8,
            	390, 16,
            	390, 24,
            	154, 40,
            	154, 48,
            	462, 56,
            	1002, 64,
            4097, 8, 0, /* 1509: pointer.func */
            1, 8, 1, /* 1512: pointer.struct.evp_pkey_ctx_st */
            	1490, 0,
            4097, 8, 0, /* 1517: pointer.func */
            0, 80, 9, /* 1520: struct.bio_method_st */
            	154, 8,
            	1541, 16,
            	1541, 24,
            	1544, 32,
            	1541, 40,
            	1547, 48,
            	1550, 56,
            	1550, 64,
            	1553, 72,
            4097, 8, 0, /* 1541: pointer.func */
            4097, 8, 0, /* 1544: pointer.func */
            4097, 8, 0, /* 1547: pointer.func */
            4097, 8, 0, /* 1550: pointer.func */
            4097, 8, 0, /* 1553: pointer.func */
            1, 8, 1, /* 1556: pointer.struct.iovec */
            	1046, 0,
            4097, 8, 0, /* 1561: pointer.func */
            1, 8, 1, /* 1564: pointer.struct.tls_session_ticket_ext_st */
            	3, 0,
            4097, 8, 0, /* 1569: pointer.func */
            4097, 8, 0, /* 1572: pointer.func */
            4097, 8, 0, /* 1575: pointer.func */
            1, 8, 1, /* 1578: pointer.struct.ssl_comp_st */
            	1583, 0,
            0, 24, 2, /* 1583: struct.ssl_comp_st */
            	154, 8,
            	1590, 16,
            1, 8, 1, /* 1590: pointer.struct.comp_method_st */
            	1595, 0,
            0, 64, 7, /* 1595: struct.comp_method_st */
            	154, 8,
            	1612, 16,
            	1615, 24,
            	1561, 32,
            	1561, 40,
            	1618, 48,
            	1618, 56,
            4097, 8, 0, /* 1612: pointer.func */
            4097, 8, 0, /* 1615: pointer.func */
            4097, 8, 0, /* 1618: pointer.func */
            0, 112, 11, /* 1621: struct.ssl3_enc_method */
            	462, 0,
            	1646, 8,
            	1649, 16,
            	1572, 24,
            	462, 32,
            	1569, 40,
            	1652, 56,
            	154, 64,
            	154, 80,
            	1655, 96,
            	1658, 104,
            4097, 8, 0, /* 1646: pointer.func */
            4097, 8, 0, /* 1649: pointer.func */
            4097, 8, 0, /* 1652: pointer.func */
            4097, 8, 0, /* 1655: pointer.func */
            4097, 8, 0, /* 1658: pointer.func */
            4097, 8, 0, /* 1661: pointer.func */
            4097, 8, 0, /* 1664: pointer.func */
            4097, 8, 0, /* 1667: pointer.func */
            0, 56, 2, /* 1670: struct.comp_ctx_st */
            	1590, 0,
            	180, 40,
            4097, 8, 0, /* 1677: pointer.func */
            1, 8, 1, /* 1680: pointer.struct.ssl_cipher_st */
            	1685, 0,
            0, 88, 1, /* 1685: struct.ssl_cipher_st */
            	154, 8,
            0, 24, 2, /* 1690: struct._pitem */
            	8, 8,
            	1697, 16,
            1, 8, 1, /* 1697: pointer.struct._pitem */
            	1690, 0,
            1, 8, 1, /* 1702: pointer.struct.dtls1_state_st */
            	1707, 0,
            0, 888, 7, /* 1707: struct.dtls1_state_st */
            	1724, 576,
            	1724, 592,
            	1729, 608,
            	1729, 616,
            	1724, 624,
            	1739, 648,
            	1739, 736,
            0, 16, 1, /* 1724: struct.record_pqueue_st */
            	1729, 8,
            1, 8, 1, /* 1729: pointer.struct._pqueue */
            	1734, 0,
            0, 16, 1, /* 1734: struct._pqueue */
            	1697, 0,
            0, 88, 1, /* 1739: struct.hm_header_st */
            	1744, 48,
            0, 40, 4, /* 1744: struct.dtls1_retransmit_state */
            	1755, 0,
            	1802, 8,
            	1820, 16,
            	1825, 24,
            1, 8, 1, /* 1755: pointer.struct.evp_cipher_ctx_st */
            	1760, 0,
            0, 168, 4, /* 1760: struct.evp_cipher_ctx_st */
            	1771, 0,
            	509, 8,
            	154, 96,
            	154, 120,
            1, 8, 1, /* 1771: pointer.struct.evp_cipher_st */
            	1776, 0,
            0, 88, 7, /* 1776: struct.evp_cipher_st */
            	1793, 24,
            	1661, 32,
            	1796, 40,
            	1517, 56,
            	1517, 64,
            	1799, 72,
            	154, 80,
            4097, 8, 0, /* 1793: pointer.func */
            4097, 8, 0, /* 1796: pointer.func */
            4097, 8, 0, /* 1799: pointer.func */
            1, 8, 1, /* 1802: pointer.struct.env_md_ctx_st */
            	1807, 0,
            0, 48, 5, /* 1807: struct.env_md_ctx_st */
            	905, 0,
            	509, 8,
            	154, 24,
            	1512, 32,
            	932, 40,
            1, 8, 1, /* 1820: pointer.struct.comp_ctx_st */
            	1670, 0,
            1, 8, 1, /* 1825: pointer.struct.ssl_session_st */
            	1830, 0,
            0, 352, 14, /* 1830: struct.ssl_session_st */
            	154, 144,
            	154, 152,
            	1861, 168,
            	227, 176,
            	1680, 224,
            	132, 240,
            	180, 248,
            	1825, 264,
            	1825, 272,
            	154, 280,
            	154, 296,
            	154, 312,
            	154, 320,
            	154, 344,
            1, 8, 1, /* 1861: pointer.struct.sess_cert_st */
            	1866, 0,
            0, 248, 6, /* 1866: struct.sess_cert_st */
            	132, 0,
            	213, 16,
            	1325, 24,
            	950, 216,
            	1054, 224,
            	1089, 232,
            1, 8, 1, /* 1881: pointer.struct.ssl3_state_st */
            	1886, 0,
            0, 1200, 10, /* 1886: struct.ssl3_state_st */
            	1909, 240,
            	1909, 264,
            	1914, 288,
            	1914, 344,
            	154, 432,
            	1923, 440,
            	1953, 448,
            	8, 496,
            	8, 512,
            	1958, 528,
            0, 24, 1, /* 1909: struct.ssl3_buffer_st */
            	154, 0,
            0, 56, 3, /* 1914: struct.ssl3_record_st */
            	154, 16,
            	154, 24,
            	154, 32,
            1, 8, 1, /* 1923: pointer.struct.bio_st */
            	1928, 0,
            0, 112, 7, /* 1928: struct.bio_st */
            	1945, 0,
            	1950, 8,
            	154, 16,
            	154, 48,
            	1923, 56,
            	1923, 64,
            	180, 96,
            1, 8, 1, /* 1945: pointer.struct.bio_method_st */
            	1520, 0,
            4097, 8, 0, /* 1950: pointer.func */
            1, 8, 1, /* 1953: pointer.pointer.struct.env_md_ctx_st */
            	1802, 0,
            0, 528, 8, /* 1958: struct.anon */
            	1680, 408,
            	1054, 416,
            	1089, 424,
            	132, 464,
            	154, 480,
            	1771, 488,
            	905, 496,
            	1578, 512,
            0, 1, 0, /* 1977: char */
            4097, 8, 0, /* 1980: pointer.func */
            1, 8, 1, /* 1983: pointer.struct.ssl_st */
            	1988, 0,
            0, 808, 51, /* 1988: struct.ssl_st */
            	2093, 8,
            	1923, 16,
            	1923, 24,
            	1923, 32,
            	1649, 48,
            	354, 80,
            	154, 88,
            	154, 104,
            	2189, 120,
            	1881, 128,
            	1702, 136,
            	1349, 152,
            	154, 160,
            	159, 176,
            	132, 184,
            	132, 192,
            	1755, 208,
            	1802, 216,
            	1820, 224,
            	1755, 232,
            	1802, 240,
            	1820, 248,
            	1344, 256,
            	1825, 304,
            	188, 312,
            	171, 328,
            	185, 336,
            	2215, 352,
            	1572, 360,
            	2218, 368,
            	180, 392,
            	132, 408,
            	11, 464,
            	154, 472,
            	154, 480,
            	132, 504,
            	132, 512,
            	154, 520,
            	154, 544,
            	154, 560,
            	154, 568,
            	1564, 584,
            	1569, 592,
            	154, 600,
            	0, 608,
            	154, 616,
            	2218, 624,
            	154, 632,
            	132, 648,
            	1556, 656,
            	1362, 680,
            1, 8, 1, /* 2093: pointer.struct.ssl_method_st */
            	2098, 0,
            0, 232, 28, /* 2098: struct.ssl_method_st */
            	1649, 8,
            	2157, 16,
            	2157, 24,
            	1649, 32,
            	1649, 40,
            	1646, 48,
            	1646, 56,
            	1646, 64,
            	1649, 72,
            	1649, 80,
            	1649, 88,
            	2160, 96,
            	2163, 104,
            	2166, 112,
            	1649, 120,
            	2169, 128,
            	2172, 136,
            	1664, 144,
            	2175, 152,
            	1649, 160,
            	783, 168,
            	1980, 176,
            	1677, 184,
            	1618, 192,
            	2178, 200,
            	783, 208,
            	2183, 216,
            	2186, 224,
            4097, 8, 0, /* 2157: pointer.func */
            4097, 8, 0, /* 2160: pointer.func */
            4097, 8, 0, /* 2163: pointer.func */
            4097, 8, 0, /* 2166: pointer.func */
            4097, 8, 0, /* 2169: pointer.func */
            4097, 8, 0, /* 2172: pointer.func */
            4097, 8, 0, /* 2175: pointer.func */
            1, 8, 1, /* 2178: pointer.struct.ssl3_enc_method */
            	1621, 0,
            4097, 8, 0, /* 2183: pointer.func */
            4097, 8, 0, /* 2186: pointer.func */
            1, 8, 1, /* 2189: pointer.struct.ssl2_state_st */
            	2194, 0,
            0, 344, 9, /* 2194: struct.ssl2_state_st */
            	154, 24,
            	154, 56,
            	154, 64,
            	154, 72,
            	154, 104,
            	154, 112,
            	154, 120,
            	154, 128,
            	154, 136,
            4097, 8, 0, /* 2215: pointer.func */
            1, 8, 1, /* 2218: pointer.struct.ssl_ctx_st */
            	2223, 0,
            0, 736, 50, /* 2223: struct.ssl_ctx_st */
            	2093, 0,
            	132, 8,
            	132, 16,
            	94, 24,
            	74, 32,
            	1825, 48,
            	1825, 56,
            	2326, 80,
            	1509, 88,
            	39, 96,
            	1667, 152,
            	154, 160,
            	36, 168,
            	154, 176,
            	33, 184,
            	188, 192,
            	1646, 200,
            	180, 208,
            	905, 224,
            	905, 232,
            	905, 240,
            	132, 248,
            	132, 256,
            	185, 264,
            	132, 272,
            	1344, 304,
            	1349, 320,
            	154, 328,
            	171, 376,
            	188, 384,
            	159, 392,
            	509, 408,
            	1393, 416,
            	154, 424,
            	30, 480,
            	27, 488,
            	154, 496,
            	24, 504,
            	154, 512,
            	154, 520,
            	2215, 528,
            	1572, 536,
            	1352, 552,
            	1352, 560,
            	1362, 568,
            	1575, 696,
            	154, 704,
            	2329, 712,
            	154, 720,
            	132, 728,
            4097, 8, 0, /* 2326: pointer.func */
            4097, 8, 0, /* 2329: pointer.func */
        },
        .arg_entity_index = { 1983, },
        .ret_entity_index = 1680,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    const SSL * new_arg_a = *((const SSL * *)new_args->args[0]);

    const SSL_CIPHER * *new_ret_ptr = (const SSL_CIPHER * *)new_args->ret;

    const SSL_CIPHER * (*orig_SSL_get_current_cipher)(const SSL *);
    orig_SSL_get_current_cipher = dlsym(RTLD_NEXT, "SSL_get_current_cipher");
    *new_ret_ptr = (*orig_SSL_get_current_cipher)(new_arg_a);

    syscall(889);

    return ret;
}

