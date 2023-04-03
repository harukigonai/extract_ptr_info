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

SSL_CTX * bb_SSL_get_SSL_CTX(const SSL * arg_a);

SSL_CTX * SSL_get_SSL_CTX(const SSL * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_get_SSL_CTX called %lu\n", in_lib);
    if (!in_lib)
        return bb_SSL_get_SSL_CTX(arg_a);
    else {
        SSL_CTX * (*orig_SSL_get_SSL_CTX)(const SSL *);
        orig_SSL_get_SSL_CTX = dlsym(RTLD_NEXT, "SSL_get_SSL_CTX");
        return orig_SSL_get_SSL_CTX(arg_a);
    }
}

SSL_CTX * bb_SSL_get_SSL_CTX(const SSL * arg_a) 
{
    SSL_CTX * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 0, 0, /* 0: func */
            4097, 8, 0, /* 3: pointer.func */
            4097, 8, 0, /* 6: pointer.func */
            0, 16, 1, /* 9: struct._pqueue */
            	14, 0,
            1, 8, 1, /* 14: pointer.struct._pitem */
            	19, 0,
            0, 24, 2, /* 19: struct._pitem */
            	26, 8,
            	14, 16,
            1, 8, 1, /* 26: pointer.char */
            	4096, 0,
            1, 8, 1, /* 31: pointer.struct.dtls1_state_st */
            	36, 0,
            0, 888, 7, /* 36: struct.dtls1_state_st */
            	53, 576,
            	53, 592,
            	58, 608,
            	58, 616,
            	53, 624,
            	63, 648,
            	63, 736,
            0, 16, 1, /* 53: struct.record_pqueue_st */
            	58, 8,
            1, 8, 1, /* 58: pointer.struct._pqueue */
            	9, 0,
            0, 88, 1, /* 63: struct.hm_header_st */
            	68, 48,
            0, 40, 4, /* 68: struct.dtls1_retransmit_state */
            	79, 0,
            	486, 8,
            	796, 16,
            	842, 24,
            1, 8, 1, /* 79: pointer.struct.evp_cipher_ctx_st */
            	84, 0,
            0, 168, 4, /* 84: struct.evp_cipher_ctx_st */
            	95, 0,
            	135, 8,
            	132, 96,
            	132, 120,
            1, 8, 1, /* 95: pointer.struct.evp_cipher_st */
            	100, 0,
            0, 88, 7, /* 100: struct.evp_cipher_st */
            	117, 24,
            	120, 32,
            	123, 40,
            	126, 56,
            	126, 64,
            	129, 72,
            	132, 80,
            4097, 8, 0, /* 117: pointer.func */
            4097, 8, 0, /* 120: pointer.func */
            4097, 8, 0, /* 123: pointer.func */
            4097, 8, 0, /* 126: pointer.func */
            4097, 8, 0, /* 129: pointer.func */
            0, 8, 0, /* 132: pointer.void */
            1, 8, 1, /* 135: pointer.struct.engine_st */
            	140, 0,
            0, 216, 24, /* 140: struct.engine_st */
            	26, 0,
            	26, 8,
            	191, 16,
            	246, 24,
            	297, 32,
            	333, 40,
            	350, 48,
            	377, 56,
            	412, 64,
            	420, 72,
            	423, 80,
            	426, 88,
            	429, 96,
            	432, 104,
            	432, 112,
            	432, 120,
            	435, 128,
            	438, 136,
            	438, 144,
            	441, 152,
            	444, 160,
            	456, 184,
            	135, 200,
            	135, 208,
            1, 8, 1, /* 191: pointer.struct.rsa_meth_st */
            	196, 0,
            0, 112, 13, /* 196: struct.rsa_meth_st */
            	26, 0,
            	225, 8,
            	225, 16,
            	225, 24,
            	225, 32,
            	228, 40,
            	231, 48,
            	234, 56,
            	234, 64,
            	26, 80,
            	237, 88,
            	240, 96,
            	243, 104,
            4097, 8, 0, /* 225: pointer.func */
            4097, 8, 0, /* 228: pointer.func */
            4097, 8, 0, /* 231: pointer.func */
            4097, 8, 0, /* 234: pointer.func */
            4097, 8, 0, /* 237: pointer.func */
            4097, 8, 0, /* 240: pointer.func */
            4097, 8, 0, /* 243: pointer.func */
            1, 8, 1, /* 246: pointer.struct.dsa_method */
            	251, 0,
            0, 96, 11, /* 251: struct.dsa_method */
            	26, 0,
            	276, 8,
            	279, 16,
            	282, 24,
            	285, 32,
            	288, 40,
            	291, 48,
            	291, 56,
            	26, 72,
            	294, 80,
            	291, 88,
            4097, 8, 0, /* 276: pointer.func */
            4097, 8, 0, /* 279: pointer.func */
            4097, 8, 0, /* 282: pointer.func */
            4097, 8, 0, /* 285: pointer.func */
            4097, 8, 0, /* 288: pointer.func */
            4097, 8, 0, /* 291: pointer.func */
            4097, 8, 0, /* 294: pointer.func */
            1, 8, 1, /* 297: pointer.struct.dh_method */
            	302, 0,
            0, 72, 8, /* 302: struct.dh_method */
            	26, 0,
            	321, 8,
            	324, 16,
            	327, 24,
            	321, 32,
            	321, 40,
            	26, 56,
            	330, 64,
            4097, 8, 0, /* 321: pointer.func */
            4097, 8, 0, /* 324: pointer.func */
            4097, 8, 0, /* 327: pointer.func */
            4097, 8, 0, /* 330: pointer.func */
            1, 8, 1, /* 333: pointer.struct.ecdh_method */
            	338, 0,
            0, 32, 3, /* 338: struct.ecdh_method */
            	26, 0,
            	347, 8,
            	26, 24,
            4097, 8, 0, /* 347: pointer.func */
            1, 8, 1, /* 350: pointer.struct.ecdsa_method */
            	355, 0,
            0, 48, 5, /* 355: struct.ecdsa_method */
            	26, 0,
            	368, 8,
            	371, 16,
            	374, 24,
            	26, 40,
            4097, 8, 0, /* 368: pointer.func */
            4097, 8, 0, /* 371: pointer.func */
            4097, 8, 0, /* 374: pointer.func */
            1, 8, 1, /* 377: pointer.struct.rand_meth_st */
            	382, 0,
            0, 48, 6, /* 382: struct.rand_meth_st */
            	397, 0,
            	400, 8,
            	403, 16,
            	406, 24,
            	400, 32,
            	409, 40,
            4097, 8, 0, /* 397: pointer.func */
            4097, 8, 0, /* 400: pointer.func */
            4097, 8, 0, /* 403: pointer.func */
            4097, 8, 0, /* 406: pointer.func */
            4097, 8, 0, /* 409: pointer.func */
            1, 8, 1, /* 412: pointer.struct.store_method_st */
            	417, 0,
            0, 0, 0, /* 417: struct.store_method_st */
            4097, 8, 0, /* 420: pointer.func */
            4097, 8, 0, /* 423: pointer.func */
            4097, 8, 0, /* 426: pointer.func */
            4097, 8, 0, /* 429: pointer.func */
            4097, 8, 0, /* 432: pointer.func */
            4097, 8, 0, /* 435: pointer.func */
            4097, 8, 0, /* 438: pointer.func */
            4097, 8, 0, /* 441: pointer.func */
            1, 8, 1, /* 444: pointer.struct.ENGINE_CMD_DEFN_st */
            	449, 0,
            0, 32, 2, /* 449: struct.ENGINE_CMD_DEFN_st */
            	26, 8,
            	26, 16,
            0, 16, 1, /* 456: struct.crypto_ex_data_st */
            	461, 0,
            1, 8, 1, /* 461: pointer.struct.stack_st_OPENSSL_STRING */
            	466, 0,
            0, 32, 1, /* 466: struct.stack_st_OPENSSL_STRING */
            	471, 0,
            0, 32, 2, /* 471: struct.stack_st */
            	478, 8,
            	483, 24,
            1, 8, 1, /* 478: pointer.pointer.char */
            	26, 0,
            4097, 8, 0, /* 483: pointer.func */
            1, 8, 1, /* 486: pointer.struct.env_md_ctx_st */
            	491, 0,
            0, 48, 5, /* 491: struct.env_md_ctx_st */
            	504, 0,
            	135, 8,
            	132, 24,
            	549, 32,
            	531, 40,
            1, 8, 1, /* 504: pointer.struct.env_md_st */
            	509, 0,
            0, 120, 8, /* 509: struct.env_md_st */
            	528, 24,
            	531, 32,
            	534, 40,
            	537, 48,
            	528, 56,
            	540, 64,
            	543, 72,
            	546, 112,
            4097, 8, 0, /* 528: pointer.func */
            4097, 8, 0, /* 531: pointer.func */
            4097, 8, 0, /* 534: pointer.func */
            4097, 8, 0, /* 537: pointer.func */
            4097, 8, 0, /* 540: pointer.func */
            4097, 8, 0, /* 543: pointer.func */
            4097, 8, 0, /* 546: pointer.func */
            1, 8, 1, /* 549: pointer.struct.evp_pkey_ctx_st */
            	554, 0,
            0, 80, 8, /* 554: struct.evp_pkey_ctx_st */
            	573, 0,
            	135, 8,
            	672, 16,
            	672, 24,
            	26, 40,
            	26, 48,
            	631, 56,
            	788, 64,
            1, 8, 1, /* 573: pointer.struct.evp_pkey_method_st */
            	578, 0,
            0, 208, 25, /* 578: struct.evp_pkey_method_st */
            	631, 8,
            	639, 16,
            	642, 24,
            	631, 32,
            	645, 40,
            	631, 48,
            	645, 56,
            	631, 64,
            	648, 72,
            	631, 80,
            	651, 88,
            	631, 96,
            	648, 104,
            	654, 112,
            	657, 120,
            	654, 128,
            	660, 136,
            	631, 144,
            	648, 152,
            	631, 160,
            	648, 168,
            	631, 176,
            	663, 184,
            	666, 192,
            	669, 200,
            1, 8, 1, /* 631: pointer.struct.unnamed */
            	636, 0,
            0, 0, 0, /* 636: struct.unnamed */
            4097, 8, 0, /* 639: pointer.func */
            4097, 8, 0, /* 642: pointer.func */
            4097, 8, 0, /* 645: pointer.func */
            4097, 8, 0, /* 648: pointer.func */
            4097, 8, 0, /* 651: pointer.func */
            4097, 8, 0, /* 654: pointer.func */
            4097, 8, 0, /* 657: pointer.func */
            4097, 8, 0, /* 660: pointer.func */
            4097, 8, 0, /* 663: pointer.func */
            4097, 8, 0, /* 666: pointer.func */
            4097, 8, 0, /* 669: pointer.func */
            1, 8, 1, /* 672: pointer.struct.evp_pkey_st */
            	677, 0,
            0, 56, 4, /* 677: struct.evp_pkey_st */
            	688, 16,
            	135, 24,
            	783, 32,
            	461, 48,
            1, 8, 1, /* 688: pointer.struct.evp_pkey_asn1_method_st */
            	693, 0,
            0, 208, 24, /* 693: struct.evp_pkey_asn1_method_st */
            	26, 16,
            	26, 24,
            	631, 32,
            	744, 40,
            	747, 48,
            	750, 56,
            	753, 64,
            	756, 72,
            	750, 80,
            	759, 88,
            	759, 96,
            	762, 104,
            	765, 112,
            	759, 120,
            	747, 128,
            	747, 136,
            	750, 144,
            	768, 152,
            	771, 160,
            	774, 168,
            	762, 176,
            	765, 184,
            	777, 192,
            	780, 200,
            4097, 8, 0, /* 744: pointer.func */
            4097, 8, 0, /* 747: pointer.func */
            4097, 8, 0, /* 750: pointer.func */
            4097, 8, 0, /* 753: pointer.func */
            4097, 8, 0, /* 756: pointer.func */
            4097, 8, 0, /* 759: pointer.func */
            4097, 8, 0, /* 762: pointer.func */
            4097, 8, 0, /* 765: pointer.func */
            4097, 8, 0, /* 768: pointer.func */
            4097, 8, 0, /* 771: pointer.func */
            4097, 8, 0, /* 774: pointer.func */
            4097, 8, 0, /* 777: pointer.func */
            4097, 8, 0, /* 780: pointer.func */
            0, 8, 1, /* 783: struct.fnames */
            	26, 0,
            1, 8, 1, /* 788: pointer.int */
            	793, 0,
            0, 4, 0, /* 793: int */
            1, 8, 1, /* 796: pointer.struct.comp_ctx_st */
            	801, 0,
            0, 56, 2, /* 801: struct.comp_ctx_st */
            	808, 0,
            	456, 40,
            1, 8, 1, /* 808: pointer.struct.comp_method_st */
            	813, 0,
            0, 64, 7, /* 813: struct.comp_method_st */
            	26, 8,
            	830, 16,
            	833, 24,
            	836, 32,
            	836, 40,
            	839, 48,
            	839, 56,
            4097, 8, 0, /* 830: pointer.func */
            4097, 8, 0, /* 833: pointer.func */
            4097, 8, 0, /* 836: pointer.func */
            4097, 8, 0, /* 839: pointer.func */
            1, 8, 1, /* 842: pointer.struct.ssl_session_st */
            	847, 0,
            0, 352, 14, /* 847: struct.ssl_session_st */
            	26, 144,
            	26, 152,
            	878, 168,
            	912, 176,
            	1525, 224,
            	461, 240,
            	456, 248,
            	842, 264,
            	842, 272,
            	26, 280,
            	26, 296,
            	26, 312,
            	26, 320,
            	26, 344,
            1, 8, 1, /* 878: pointer.struct.sess_cert_st */
            	883, 0,
            0, 248, 6, /* 883: struct.sess_cert_st */
            	461, 0,
            	898, 16,
            	1145, 24,
            	1164, 216,
            	1257, 224,
            	1289, 232,
            1, 8, 1, /* 898: pointer.struct.cert_pkey_st */
            	903, 0,
            0, 24, 3, /* 903: struct.cert_pkey_st */
            	912, 0,
            	672, 8,
            	504, 16,
            1, 8, 1, /* 912: pointer.struct.x509_st */
            	917, 0,
            0, 184, 12, /* 917: struct.x509_st */
            	944, 0,
            	984, 8,
            	974, 16,
            	26, 32,
            	456, 40,
            	974, 104,
            	1075, 112,
            	1089, 120,
            	461, 128,
            	461, 136,
            	1115, 144,
            	1127, 176,
            1, 8, 1, /* 944: pointer.struct.x509_cinf_st */
            	949, 0,
            0, 104, 11, /* 949: struct.x509_cinf_st */
            	974, 0,
            	974, 8,
            	984, 16,
            	1020, 24,
            	1044, 32,
            	1020, 40,
            	1056, 48,
            	974, 56,
            	974, 64,
            	461, 72,
            	1070, 80,
            1, 8, 1, /* 974: pointer.struct.asn1_string_st */
            	979, 0,
            0, 24, 1, /* 979: struct.asn1_string_st */
            	26, 8,
            1, 8, 1, /* 984: pointer.struct.X509_algor_st */
            	989, 0,
            0, 16, 2, /* 989: struct.X509_algor_st */
            	996, 0,
            	1010, 8,
            1, 8, 1, /* 996: pointer.struct.asn1_object_st */
            	1001, 0,
            0, 40, 3, /* 1001: struct.asn1_object_st */
            	26, 0,
            	26, 8,
            	26, 24,
            1, 8, 1, /* 1010: pointer.struct.asn1_type_st */
            	1015, 0,
            0, 16, 1, /* 1015: struct.asn1_type_st */
            	783, 8,
            1, 8, 1, /* 1020: pointer.struct.X509_name_st */
            	1025, 0,
            0, 40, 3, /* 1025: struct.X509_name_st */
            	461, 0,
            	1034, 16,
            	26, 24,
            1, 8, 1, /* 1034: pointer.struct.buf_mem_st */
            	1039, 0,
            0, 24, 1, /* 1039: struct.buf_mem_st */
            	26, 8,
            1, 8, 1, /* 1044: pointer.struct.X509_val_st */
            	1049, 0,
            0, 16, 2, /* 1049: struct.X509_val_st */
            	974, 0,
            	974, 8,
            1, 8, 1, /* 1056: pointer.struct.X509_pubkey_st */
            	1061, 0,
            0, 24, 3, /* 1061: struct.X509_pubkey_st */
            	984, 0,
            	974, 8,
            	672, 16,
            0, 24, 1, /* 1070: struct.ASN1_ENCODING_st */
            	26, 0,
            1, 8, 1, /* 1075: pointer.struct.AUTHORITY_KEYID_st */
            	1080, 0,
            0, 24, 3, /* 1080: struct.AUTHORITY_KEYID_st */
            	974, 0,
            	461, 8,
            	974, 16,
            1, 8, 1, /* 1089: pointer.struct.X509_POLICY_CACHE_st */
            	1094, 0,
            0, 40, 2, /* 1094: struct.X509_POLICY_CACHE_st */
            	1101, 0,
            	461, 8,
            1, 8, 1, /* 1101: pointer.struct.X509_POLICY_DATA_st */
            	1106, 0,
            0, 32, 3, /* 1106: struct.X509_POLICY_DATA_st */
            	996, 8,
            	461, 16,
            	461, 24,
            1, 8, 1, /* 1115: pointer.struct.NAME_CONSTRAINTS_st */
            	1120, 0,
            0, 16, 2, /* 1120: struct.NAME_CONSTRAINTS_st */
            	461, 0,
            	461, 8,
            1, 8, 1, /* 1127: pointer.struct.x509_cert_aux_st */
            	1132, 0,
            0, 40, 5, /* 1132: struct.x509_cert_aux_st */
            	461, 0,
            	461, 8,
            	974, 16,
            	974, 24,
            	461, 32,
            0, 192, 8, /* 1145: array[8].struct.cert_pkey_st */
            	903, 0,
            	903, 24,
            	903, 48,
            	903, 72,
            	903, 96,
            	903, 120,
            	903, 144,
            	903, 168,
            1, 8, 1, /* 1164: pointer.struct.rsa_st */
            	1169, 0,
            0, 168, 17, /* 1169: struct.rsa_st */
            	191, 16,
            	135, 24,
            	1206, 32,
            	1206, 40,
            	1206, 48,
            	1206, 56,
            	1206, 64,
            	1206, 72,
            	1206, 80,
            	1206, 88,
            	456, 96,
            	1216, 120,
            	1216, 128,
            	1216, 136,
            	26, 144,
            	1230, 152,
            	1230, 160,
            1, 8, 1, /* 1206: pointer.struct.bignum_st */
            	1211, 0,
            0, 24, 1, /* 1211: struct.bignum_st */
            	788, 0,
            1, 8, 1, /* 1216: pointer.struct.bn_mont_ctx_st */
            	1221, 0,
            0, 96, 3, /* 1221: struct.bn_mont_ctx_st */
            	1211, 8,
            	1211, 32,
            	1211, 56,
            1, 8, 1, /* 1230: pointer.struct.bn_blinding_st */
            	1235, 0,
            0, 88, 7, /* 1235: struct.bn_blinding_st */
            	1206, 0,
            	1206, 8,
            	1206, 16,
            	1206, 24,
            	1252, 40,
            	1216, 72,
            	231, 80,
            0, 16, 1, /* 1252: struct.iovec */
            	26, 0,
            1, 8, 1, /* 1257: pointer.struct.dh_st */
            	1262, 0,
            0, 144, 12, /* 1262: struct.dh_st */
            	1206, 8,
            	1206, 16,
            	1206, 32,
            	1206, 40,
            	1216, 56,
            	1206, 64,
            	1206, 72,
            	26, 80,
            	1206, 96,
            	456, 112,
            	297, 128,
            	135, 136,
            1, 8, 1, /* 1289: pointer.struct.ec_key_st */
            	1294, 0,
            0, 56, 4, /* 1294: struct.ec_key_st */
            	1305, 8,
            	1482, 16,
            	1206, 24,
            	1498, 48,
            1, 8, 1, /* 1305: pointer.struct.ec_group_st */
            	1310, 0,
            0, 232, 12, /* 1310: struct.ec_group_st */
            	1337, 0,
            	1482, 8,
            	1211, 16,
            	1211, 40,
            	26, 80,
            	1498, 96,
            	1211, 104,
            	1211, 152,
            	1211, 176,
            	26, 208,
            	26, 216,
            	1522, 224,
            1, 8, 1, /* 1337: pointer.struct.ec_method_st */
            	1342, 0,
            0, 304, 37, /* 1342: struct.ec_method_st */
            	1419, 8,
            	1422, 16,
            	1422, 24,
            	1425, 32,
            	1428, 40,
            	1428, 48,
            	1419, 56,
            	1431, 64,
            	1434, 72,
            	1437, 80,
            	1437, 88,
            	1440, 96,
            	1443, 104,
            	1446, 112,
            	1446, 120,
            	1449, 128,
            	1449, 136,
            	1452, 144,
            	1455, 152,
            	1458, 160,
            	1461, 168,
            	1464, 176,
            	1467, 184,
            	1443, 192,
            	1467, 200,
            	1464, 208,
            	1467, 216,
            	1470, 224,
            	1473, 232,
            	1431, 240,
            	1419, 248,
            	1428, 256,
            	1476, 264,
            	1428, 272,
            	1476, 280,
            	1476, 288,
            	1479, 296,
            4097, 8, 0, /* 1419: pointer.func */
            4097, 8, 0, /* 1422: pointer.func */
            4097, 8, 0, /* 1425: pointer.func */
            4097, 8, 0, /* 1428: pointer.func */
            4097, 8, 0, /* 1431: pointer.func */
            4097, 8, 0, /* 1434: pointer.func */
            4097, 8, 0, /* 1437: pointer.func */
            4097, 8, 0, /* 1440: pointer.func */
            4097, 8, 0, /* 1443: pointer.func */
            4097, 8, 0, /* 1446: pointer.func */
            4097, 8, 0, /* 1449: pointer.func */
            4097, 8, 0, /* 1452: pointer.func */
            4097, 8, 0, /* 1455: pointer.func */
            4097, 8, 0, /* 1458: pointer.func */
            4097, 8, 0, /* 1461: pointer.func */
            4097, 8, 0, /* 1464: pointer.func */
            4097, 8, 0, /* 1467: pointer.func */
            4097, 8, 0, /* 1470: pointer.func */
            4097, 8, 0, /* 1473: pointer.func */
            4097, 8, 0, /* 1476: pointer.func */
            4097, 8, 0, /* 1479: pointer.func */
            1, 8, 1, /* 1482: pointer.struct.ec_point_st */
            	1487, 0,
            0, 88, 4, /* 1487: struct.ec_point_st */
            	1337, 0,
            	1211, 8,
            	1211, 32,
            	1211, 56,
            1, 8, 1, /* 1498: pointer.struct.ec_extra_data_st */
            	1503, 0,
            0, 40, 5, /* 1503: struct.ec_extra_data_st */
            	1498, 0,
            	26, 8,
            	1516, 16,
            	1519, 24,
            	1519, 32,
            4097, 8, 0, /* 1516: pointer.func */
            4097, 8, 0, /* 1519: pointer.func */
            4097, 8, 0, /* 1522: pointer.func */
            1, 8, 1, /* 1525: pointer.struct.ssl_cipher_st */
            	1530, 0,
            0, 88, 1, /* 1530: struct.ssl_cipher_st */
            	26, 8,
            0, 0, 0, /* 1535: func */
            0, 0, 0, /* 1538: func */
            0, 0, 0, /* 1541: func */
            0, 0, 0, /* 1544: func */
            0, 9, 0, /* 1547: array[9].char */
            0, 128, 0, /* 1550: array[128].char */
            0, 528, 8, /* 1553: struct.anon */
            	1525, 408,
            	1257, 416,
            	1289, 424,
            	461, 464,
            	26, 480,
            	95, 488,
            	504, 496,
            	1572, 512,
            1, 8, 1, /* 1572: pointer.struct.ssl_comp_st */
            	1577, 0,
            0, 24, 2, /* 1577: struct.ssl_comp_st */
            	26, 8,
            	808, 16,
            0, 0, 0, /* 1584: func */
            0, 0, 0, /* 1587: func */
            0, 0, 0, /* 1590: func */
            1, 8, 1, /* 1593: pointer.struct.ssl3_state_st */
            	1598, 0,
            0, 1200, 10, /* 1598: struct.ssl3_state_st */
            	1621, 240,
            	1621, 264,
            	1626, 288,
            	1626, 344,
            	26, 432,
            	1635, 440,
            	1701, 448,
            	132, 496,
            	132, 512,
            	1553, 528,
            0, 24, 1, /* 1621: struct.ssl3_buffer_st */
            	26, 0,
            0, 56, 3, /* 1626: struct.ssl3_record_st */
            	26, 16,
            	26, 24,
            	26, 32,
            1, 8, 1, /* 1635: pointer.struct.bio_st */
            	1640, 0,
            0, 112, 7, /* 1640: struct.bio_st */
            	1657, 0,
            	1698, 8,
            	26, 16,
            	132, 48,
            	1635, 56,
            	1635, 64,
            	456, 96,
            1, 8, 1, /* 1657: pointer.struct.bio_method_st */
            	1662, 0,
            0, 80, 9, /* 1662: struct.bio_method_st */
            	26, 8,
            	1683, 16,
            	1683, 24,
            	1686, 32,
            	1683, 40,
            	1689, 48,
            	1692, 56,
            	1692, 64,
            	1695, 72,
            4097, 8, 0, /* 1683: pointer.func */
            4097, 8, 0, /* 1686: pointer.func */
            4097, 8, 0, /* 1689: pointer.func */
            4097, 8, 0, /* 1692: pointer.func */
            4097, 8, 0, /* 1695: pointer.func */
            4097, 8, 0, /* 1698: pointer.func */
            1, 8, 1, /* 1701: pointer.pointer.struct.env_md_ctx_st */
            	486, 0,
            0, 72, 0, /* 1706: struct.anon */
            0, 0, 0, /* 1709: func */
            1, 8, 1, /* 1712: pointer.struct.ssl_st */
            	1717, 0,
            0, 808, 51, /* 1717: struct.ssl_st */
            	1822, 8,
            	1635, 16,
            	1635, 24,
            	1635, 32,
            	1886, 48,
            	1034, 80,
            	132, 88,
            	26, 104,
            	1973, 120,
            	1593, 128,
            	31, 136,
            	1999, 152,
            	132, 160,
            	2002, 176,
            	461, 184,
            	461, 192,
            	79, 208,
            	486, 216,
            	796, 224,
            	79, 232,
            	486, 240,
            	796, 248,
            	2014, 256,
            	842, 304,
            	2047, 312,
            	2050, 328,
            	2053, 336,
            	2056, 352,
            	1952, 360,
            	2059, 368,
            	456, 392,
            	461, 408,
            	6, 464,
            	132, 472,
            	26, 480,
            	461, 504,
            	461, 512,
            	26, 520,
            	26, 544,
            	26, 560,
            	132, 568,
            	2324, 584,
            	1955, 592,
            	132, 600,
            	3, 608,
            	132, 616,
            	2059, 624,
            	26, 632,
            	461, 648,
            	2334, 656,
            	2284, 680,
            1, 8, 1, /* 1822: pointer.struct.ssl_method_st */
            	1827, 0,
            0, 232, 28, /* 1827: struct.ssl_method_st */
            	1886, 8,
            	1889, 16,
            	1889, 24,
            	1886, 32,
            	1886, 40,
            	1892, 48,
            	1892, 56,
            	1892, 64,
            	1886, 72,
            	1886, 80,
            	1886, 88,
            	1895, 96,
            	1898, 104,
            	1901, 112,
            	1886, 120,
            	1904, 128,
            	1907, 136,
            	1910, 144,
            	1913, 152,
            	1886, 160,
            	409, 168,
            	1916, 176,
            	1919, 184,
            	839, 192,
            	1922, 200,
            	409, 208,
            	1967, 216,
            	1970, 224,
            4097, 8, 0, /* 1886: pointer.func */
            4097, 8, 0, /* 1889: pointer.func */
            4097, 8, 0, /* 1892: pointer.func */
            4097, 8, 0, /* 1895: pointer.func */
            4097, 8, 0, /* 1898: pointer.func */
            4097, 8, 0, /* 1901: pointer.func */
            4097, 8, 0, /* 1904: pointer.func */
            4097, 8, 0, /* 1907: pointer.func */
            4097, 8, 0, /* 1910: pointer.func */
            4097, 8, 0, /* 1913: pointer.func */
            4097, 8, 0, /* 1916: pointer.func */
            4097, 8, 0, /* 1919: pointer.func */
            1, 8, 1, /* 1922: pointer.struct.ssl3_enc_method */
            	1927, 0,
            0, 112, 11, /* 1927: struct.ssl3_enc_method */
            	631, 0,
            	1892, 8,
            	1886, 16,
            	1952, 24,
            	631, 32,
            	1955, 40,
            	1958, 56,
            	26, 64,
            	26, 80,
            	1961, 96,
            	1964, 104,
            4097, 8, 0, /* 1952: pointer.func */
            4097, 8, 0, /* 1955: pointer.func */
            4097, 8, 0, /* 1958: pointer.func */
            4097, 8, 0, /* 1961: pointer.func */
            4097, 8, 0, /* 1964: pointer.func */
            4097, 8, 0, /* 1967: pointer.func */
            4097, 8, 0, /* 1970: pointer.func */
            1, 8, 1, /* 1973: pointer.struct.ssl2_state_st */
            	1978, 0,
            0, 344, 9, /* 1978: struct.ssl2_state_st */
            	26, 24,
            	26, 56,
            	26, 64,
            	26, 72,
            	26, 104,
            	26, 112,
            	26, 120,
            	26, 128,
            	26, 136,
            4097, 8, 0, /* 1999: pointer.func */
            1, 8, 1, /* 2002: pointer.struct.X509_VERIFY_PARAM_st */
            	2007, 0,
            0, 56, 2, /* 2007: struct.X509_VERIFY_PARAM_st */
            	26, 0,
            	461, 48,
            1, 8, 1, /* 2014: pointer.struct.cert_st */
            	2019, 0,
            0, 296, 8, /* 2019: struct.cert_st */
            	898, 0,
            	1164, 48,
            	2038, 56,
            	1257, 64,
            	2041, 72,
            	1289, 80,
            	2044, 88,
            	1145, 96,
            4097, 8, 0, /* 2038: pointer.func */
            4097, 8, 0, /* 2041: pointer.func */
            4097, 8, 0, /* 2044: pointer.func */
            4097, 8, 0, /* 2047: pointer.func */
            4097, 8, 0, /* 2050: pointer.func */
            4097, 8, 0, /* 2053: pointer.func */
            4097, 8, 0, /* 2056: pointer.func */
            1, 8, 1, /* 2059: pointer.struct.ssl_ctx_st */
            	2064, 0,
            0, 736, 50, /* 2064: struct.ssl_ctx_st */
            	1822, 0,
            	461, 8,
            	461, 16,
            	2167, 24,
            	2226, 32,
            	842, 48,
            	842, 56,
            	2234, 80,
            	2237, 88,
            	2240, 96,
            	2243, 152,
            	132, 160,
            	2246, 168,
            	132, 176,
            	2249, 184,
            	2047, 192,
            	1892, 200,
            	456, 208,
            	504, 224,
            	504, 232,
            	504, 240,
            	461, 248,
            	461, 256,
            	2053, 264,
            	461, 272,
            	2014, 304,
            	1999, 320,
            	132, 328,
            	2050, 376,
            	2047, 384,
            	2002, 392,
            	135, 408,
            	2252, 416,
            	132, 424,
            	2255, 480,
            	2258, 488,
            	132, 496,
            	2261, 504,
            	132, 512,
            	26, 520,
            	2056, 528,
            	1952, 536,
            	2264, 552,
            	2264, 560,
            	2284, 568,
            	2318, 696,
            	132, 704,
            	2321, 712,
            	132, 720,
            	461, 728,
            1, 8, 1, /* 2167: pointer.struct.x509_store_st */
            	2172, 0,
            0, 144, 15, /* 2172: struct.x509_store_st */
            	461, 8,
            	461, 16,
            	2002, 24,
            	2205, 32,
            	2050, 40,
            	2208, 48,
            	2211, 56,
            	2205, 64,
            	2214, 72,
            	2217, 80,
            	2220, 88,
            	2223, 96,
            	2223, 104,
            	2205, 112,
            	456, 120,
            4097, 8, 0, /* 2205: pointer.func */
            4097, 8, 0, /* 2208: pointer.func */
            4097, 8, 0, /* 2211: pointer.func */
            4097, 8, 0, /* 2214: pointer.func */
            4097, 8, 0, /* 2217: pointer.func */
            4097, 8, 0, /* 2220: pointer.func */
            4097, 8, 0, /* 2223: pointer.func */
            1, 8, 1, /* 2226: pointer.struct.in_addr */
            	2231, 0,
            0, 4, 0, /* 2231: struct.in_addr */
            4097, 8, 0, /* 2234: pointer.func */
            4097, 8, 0, /* 2237: pointer.func */
            4097, 8, 0, /* 2240: pointer.func */
            4097, 8, 0, /* 2243: pointer.func */
            4097, 8, 0, /* 2246: pointer.func */
            4097, 8, 0, /* 2249: pointer.func */
            4097, 8, 0, /* 2252: pointer.func */
            4097, 8, 0, /* 2255: pointer.func */
            4097, 8, 0, /* 2258: pointer.func */
            4097, 8, 0, /* 2261: pointer.func */
            1, 8, 1, /* 2264: pointer.struct.ssl3_buf_freelist_st */
            	2269, 0,
            0, 24, 1, /* 2269: struct.ssl3_buf_freelist_st */
            	2274, 16,
            1, 8, 1, /* 2274: pointer.struct.ssl3_buf_freelist_entry_st */
            	2279, 0,
            0, 8, 1, /* 2279: struct.ssl3_buf_freelist_entry_st */
            	2274, 0,
            0, 128, 14, /* 2284: struct.srp_ctx_st */
            	132, 0,
            	2252, 8,
            	2258, 16,
            	2315, 24,
            	26, 32,
            	1206, 40,
            	1206, 48,
            	1206, 56,
            	1206, 64,
            	1206, 72,
            	1206, 80,
            	1206, 88,
            	1206, 96,
            	26, 104,
            4097, 8, 0, /* 2315: pointer.func */
            4097, 8, 0, /* 2318: pointer.func */
            4097, 8, 0, /* 2321: pointer.func */
            1, 8, 1, /* 2324: pointer.struct.tls_session_ticket_ext_st */
            	2329, 0,
            0, 16, 1, /* 2329: struct.tls_session_ticket_ext_st */
            	132, 8,
            1, 8, 1, /* 2334: pointer.struct.iovec */
            	1252, 0,
            0, 0, 0, /* 2339: func */
            0, 16, 0, /* 2342: union.anon */
            0, 0, 0, /* 2345: func */
            0, 0, 0, /* 2348: func */
            0, 0, 0, /* 2351: func */
            0, 0, 0, /* 2354: func */
            0, 0, 0, /* 2357: func */
            0, 0, 0, /* 2360: func */
            0, 16, 0, /* 2363: array[16].char */
            0, 0, 0, /* 2366: func */
            0, 0, 0, /* 2369: func */
            0, 0, 0, /* 2372: func */
            0, 0, 0, /* 2375: func */
            0, 0, 0, /* 2378: func */
            0, 4, 0, /* 2381: array[4].char */
            0, 0, 0, /* 2384: func */
            0, 0, 0, /* 2387: func */
            0, 0, 0, /* 2390: func */
            0, 0, 0, /* 2393: func */
            0, 0, 0, /* 2396: func */
            0, 44, 0, /* 2399: struct.apr_time_exp_t */
            0, 0, 0, /* 2402: func */
            0, 0, 0, /* 2405: func */
            0, 2, 0, /* 2408: array[2].char */
            0, 24, 0, /* 2411: array[6].int */
            0, 0, 0, /* 2414: func */
            0, 0, 0, /* 2417: func */
            0, 0, 0, /* 2420: func */
            0, 0, 0, /* 2423: func */
            0, 0, 0, /* 2426: func */
            0, 0, 0, /* 2429: func */
            0, 12, 0, /* 2432: struct.ap_unix_identity_t */
            0, 0, 0, /* 2435: func */
            0, 0, 0, /* 2438: func */
            0, 0, 0, /* 2441: func */
            0, 0, 0, /* 2444: func */
            0, 0, 0, /* 2447: func */
            0, 0, 0, /* 2450: func */
            0, 0, 0, /* 2453: func */
            0, 0, 0, /* 2456: func */
            0, 0, 0, /* 2459: func */
            0, 0, 0, /* 2462: func */
            0, 0, 0, /* 2465: func */
            0, 0, 0, /* 2468: func */
            0, 0, 0, /* 2471: func */
            0, 8, 0, /* 2474: array[2].int */
            0, 0, 0, /* 2477: func */
            0, 0, 0, /* 2480: func */
            0, 0, 0, /* 2483: func */
            0, 0, 0, /* 2486: func */
            0, 0, 0, /* 2489: func */
            0, 0, 0, /* 2492: func */
            0, 0, 0, /* 2495: func */
            0, 0, 0, /* 2498: func */
            0, 0, 0, /* 2501: func */
            0, 0, 0, /* 2504: func */
            0, 2, 0, /* 2507: short */
            0, 0, 0, /* 2510: func */
            0, 0, 0, /* 2513: func */
            0, 0, 0, /* 2516: func */
            0, 0, 0, /* 2519: func */
            0, 0, 0, /* 2522: func */
            0, 0, 0, /* 2525: func */
            0, 0, 0, /* 2528: func */
            0, 0, 0, /* 2531: func */
            0, 0, 0, /* 2534: func */
            0, 16, 0, /* 2537: struct.rlimit */
            0, 0, 0, /* 2540: func */
            0, 0, 0, /* 2543: func */
            0, 0, 0, /* 2546: func */
            0, 0, 0, /* 2549: func */
            0, 0, 0, /* 2552: func */
            0, 0, 0, /* 2555: func */
            0, 0, 0, /* 2558: func */
            0, 0, 0, /* 2561: func */
            0, 0, 0, /* 2564: func */
            0, 0, 0, /* 2567: func */
            0, 0, 0, /* 2570: func */
            0, 0, 0, /* 2573: func */
            0, 0, 0, /* 2576: func */
            0, 20, 0, /* 2579: array[20].char */
            0, 0, 0, /* 2582: func */
            0, 0, 0, /* 2585: func */
            0, 0, 0, /* 2588: func */
            0, 0, 0, /* 2591: func */
            0, 0, 0, /* 2594: func */
            0, 0, 0, /* 2597: func */
            0, 0, 0, /* 2600: func */
            0, 1, 0, /* 2603: char */
            0, 0, 0, /* 2606: func */
            0, 0, 0, /* 2609: func */
            0, 0, 0, /* 2612: func */
            0, 0, 0, /* 2615: func */
            0, 0, 0, /* 2618: func */
            0, 0, 0, /* 2621: func */
            0, 0, 0, /* 2624: func */
            0, 0, 0, /* 2627: func */
            0, 0, 0, /* 2630: func */
            0, 0, 0, /* 2633: func */
            0, 0, 0, /* 2636: func */
            0, 256, 0, /* 2639: array[256].char */
            0, 48, 0, /* 2642: array[48].char */
            0, 8, 0, /* 2645: array[8].char */
            0, 0, 0, /* 2648: func */
            0, 0, 0, /* 2651: func */
            0, 0, 0, /* 2654: func */
            0, 0, 0, /* 2657: func */
            0, 0, 0, /* 2660: func */
            0, 0, 0, /* 2663: func */
            0, 0, 0, /* 2666: func */
            0, 0, 0, /* 2669: func */
            0, 0, 0, /* 2672: func */
            0, 0, 0, /* 2675: func */
            0, 0, 0, /* 2678: func */
            0, 0, 0, /* 2681: func */
            0, 0, 0, /* 2684: func */
            0, 0, 0, /* 2687: func */
            0, 0, 0, /* 2690: func */
            0, 8, 0, /* 2693: long */
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
            0, 0, 0, /* 2741: func */
            0, 0, 0, /* 2744: func */
            0, 0, 0, /* 2747: func */
            0, 0, 0, /* 2750: func */
            0, 0, 0, /* 2753: func */
            0, 20, 0, /* 2756: array[5].int */
            0, 0, 0, /* 2759: func */
            0, 0, 0, /* 2762: func */
            0, 0, 0, /* 2765: func */
            0, 0, 0, /* 2768: func */
            0, 0, 0, /* 2771: func */
            0, 0, 0, /* 2774: func */
            0, 0, 0, /* 2777: func */
            0, 0, 0, /* 2780: func */
            0, 0, 0, /* 2783: func */
            0, 64, 0, /* 2786: array[64].char */
            0, 0, 0, /* 2789: func */
            0, 0, 0, /* 2792: func */
            0, 0, 0, /* 2795: func */
            0, 0, 0, /* 2798: func */
            0, 0, 0, /* 2801: func */
            0, 0, 0, /* 2804: func */
            0, 12, 0, /* 2807: array[12].char */
            0, 0, 0, /* 2810: func */
            0, 32, 0, /* 2813: array[32].char */
            0, 0, 0, /* 2816: func */
            0, 0, 0, /* 2819: func */
            0, 0, 0, /* 2822: func */
            0, 0, 0, /* 2825: func */
            0, 0, 0, /* 2828: func */
            0, 0, 0, /* 2831: func */
            0, 0, 0, /* 2834: func */
        },
        .arg_entity_index = { 1712, },
        .ret_entity_index = 2059,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    const SSL * new_arg_a = *((const SSL * *)new_args->args[0]);

    SSL_CTX * *new_ret_ptr = (SSL_CTX * *)new_args->ret;

    SSL_CTX * (*orig_SSL_get_SSL_CTX)(const SSL *);
    orig_SSL_get_SSL_CTX = dlsym(RTLD_NEXT, "SSL_get_SSL_CTX");
    *new_ret_ptr = (*orig_SSL_get_SSL_CTX)(new_arg_a);

    syscall(889);

    return ret;
}

