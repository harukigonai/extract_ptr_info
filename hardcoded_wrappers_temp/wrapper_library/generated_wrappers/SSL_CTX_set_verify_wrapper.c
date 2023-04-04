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

void bb_SSL_CTX_set_verify(SSL_CTX * arg_a,int arg_b,int (*arg_c)(int, X509_STORE_CTX *));

void SSL_CTX_set_verify(SSL_CTX * arg_a,int arg_b,int (*arg_c)(int, X509_STORE_CTX *)) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_CTX_set_verify called %lu\n", in_lib);
    if (!in_lib)
        bb_SSL_CTX_set_verify(arg_a,arg_b,arg_c);
    else {
        void (*orig_SSL_CTX_set_verify)(SSL_CTX *,int,int (*)(int, X509_STORE_CTX *));
        orig_SSL_CTX_set_verify = dlsym(RTLD_NEXT, "SSL_CTX_set_verify");
        orig_SSL_CTX_set_verify(arg_a,arg_b,arg_c);
    }
}

void bb_SSL_CTX_set_verify(SSL_CTX * arg_a,int arg_b,int (*arg_c)(int, X509_STORE_CTX *)) 
{
    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            4097, 8, 0, /* 0: pointer.func */
            4097, 8, 0, /* 3: pointer.func */
            4097, 8, 0, /* 6: pointer.func */
            4097, 8, 0, /* 9: pointer.func */
            1, 8, 1, /* 12: pointer.struct.cert_st */
            	17, 0,
            0, 296, 8, /* 17: struct.cert_st */
            	36, 0,
            	808, 48,
            	909, 56,
            	912, 64,
            	944, 72,
            	947, 80,
            	1186, 88,
            	1189, 96,
            1, 8, 1, /* 36: pointer.struct.cert_pkey_st */
            	41, 0,
            0, 24, 3, /* 41: struct.cert_pkey_st */
            	50, 0,
            	243, 8,
            	763, 16,
            1, 8, 1, /* 50: pointer.struct.x509_st */
            	55, 0,
            0, 184, 12, /* 55: struct.x509_st */
            	82, 0,
            	127, 8,
            	112, 16,
            	122, 32,
            	683, 40,
            	112, 104,
            	693, 112,
            	707, 120,
            	182, 128,
            	182, 136,
            	733, 144,
            	745, 176,
            1, 8, 1, /* 82: pointer.struct.x509_cinf_st */
            	87, 0,
            0, 104, 11, /* 87: struct.x509_cinf_st */
            	112, 0,
            	112, 8,
            	127, 16,
            	168, 24,
            	217, 32,
            	168, 40,
            	229, 48,
            	112, 56,
            	112, 64,
            	182, 72,
            	688, 80,
            1, 8, 1, /* 112: pointer.struct.asn1_string_st */
            	117, 0,
            0, 24, 1, /* 117: struct.asn1_string_st */
            	122, 8,
            1, 8, 1, /* 122: pointer.char */
            	4096, 0,
            1, 8, 1, /* 127: pointer.struct.X509_algor_st */
            	132, 0,
            0, 16, 2, /* 132: struct.X509_algor_st */
            	139, 0,
            	153, 8,
            1, 8, 1, /* 139: pointer.struct.asn1_object_st */
            	144, 0,
            0, 40, 3, /* 144: struct.asn1_object_st */
            	122, 0,
            	122, 8,
            	122, 24,
            1, 8, 1, /* 153: pointer.struct.asn1_type_st */
            	158, 0,
            0, 16, 1, /* 158: struct.asn1_type_st */
            	163, 8,
            0, 8, 1, /* 163: struct.fnames */
            	122, 0,
            1, 8, 1, /* 168: pointer.struct.X509_name_st */
            	173, 0,
            0, 40, 3, /* 173: struct.X509_name_st */
            	182, 0,
            	207, 16,
            	122, 24,
            1, 8, 1, /* 182: pointer.struct.stack_st_OPENSSL_STRING */
            	187, 0,
            0, 32, 1, /* 187: struct.stack_st_OPENSSL_STRING */
            	192, 0,
            0, 32, 2, /* 192: struct.stack_st */
            	199, 8,
            	204, 24,
            1, 8, 1, /* 199: pointer.pointer.char */
            	122, 0,
            4097, 8, 0, /* 204: pointer.func */
            1, 8, 1, /* 207: pointer.struct.buf_mem_st */
            	212, 0,
            0, 24, 1, /* 212: struct.buf_mem_st */
            	122, 8,
            1, 8, 1, /* 217: pointer.struct.X509_val_st */
            	222, 0,
            0, 16, 2, /* 222: struct.X509_val_st */
            	112, 0,
            	112, 8,
            1, 8, 1, /* 229: pointer.struct.X509_pubkey_st */
            	234, 0,
            0, 24, 3, /* 234: struct.X509_pubkey_st */
            	127, 0,
            	112, 8,
            	243, 16,
            1, 8, 1, /* 243: pointer.struct.evp_pkey_st */
            	248, 0,
            0, 56, 4, /* 248: struct.evp_pkey_st */
            	259, 16,
            	362, 24,
            	163, 32,
            	182, 48,
            1, 8, 1, /* 259: pointer.struct.evp_pkey_asn1_method_st */
            	264, 0,
            0, 208, 24, /* 264: struct.evp_pkey_asn1_method_st */
            	122, 16,
            	122, 24,
            	315, 32,
            	323, 40,
            	326, 48,
            	329, 56,
            	332, 64,
            	335, 72,
            	329, 80,
            	338, 88,
            	338, 96,
            	341, 104,
            	344, 112,
            	338, 120,
            	326, 128,
            	326, 136,
            	329, 144,
            	347, 152,
            	350, 160,
            	353, 168,
            	341, 176,
            	344, 184,
            	356, 192,
            	359, 200,
            1, 8, 1, /* 315: pointer.struct.unnamed */
            	320, 0,
            0, 0, 0, /* 320: struct.unnamed */
            4097, 8, 0, /* 323: pointer.func */
            4097, 8, 0, /* 326: pointer.func */
            4097, 8, 0, /* 329: pointer.func */
            4097, 8, 0, /* 332: pointer.func */
            4097, 8, 0, /* 335: pointer.func */
            4097, 8, 0, /* 338: pointer.func */
            4097, 8, 0, /* 341: pointer.func */
            4097, 8, 0, /* 344: pointer.func */
            4097, 8, 0, /* 347: pointer.func */
            4097, 8, 0, /* 350: pointer.func */
            4097, 8, 0, /* 353: pointer.func */
            4097, 8, 0, /* 356: pointer.func */
            4097, 8, 0, /* 359: pointer.func */
            1, 8, 1, /* 362: pointer.struct.engine_st */
            	367, 0,
            0, 216, 24, /* 367: struct.engine_st */
            	122, 0,
            	122, 8,
            	418, 16,
            	473, 24,
            	524, 32,
            	560, 40,
            	577, 48,
            	604, 56,
            	639, 64,
            	647, 72,
            	650, 80,
            	653, 88,
            	656, 96,
            	659, 104,
            	659, 112,
            	659, 120,
            	662, 128,
            	665, 136,
            	665, 144,
            	668, 152,
            	671, 160,
            	683, 184,
            	362, 200,
            	362, 208,
            1, 8, 1, /* 418: pointer.struct.rsa_meth_st */
            	423, 0,
            0, 112, 13, /* 423: struct.rsa_meth_st */
            	122, 0,
            	452, 8,
            	452, 16,
            	452, 24,
            	452, 32,
            	455, 40,
            	458, 48,
            	461, 56,
            	461, 64,
            	122, 80,
            	464, 88,
            	467, 96,
            	470, 104,
            4097, 8, 0, /* 452: pointer.func */
            4097, 8, 0, /* 455: pointer.func */
            4097, 8, 0, /* 458: pointer.func */
            4097, 8, 0, /* 461: pointer.func */
            4097, 8, 0, /* 464: pointer.func */
            4097, 8, 0, /* 467: pointer.func */
            4097, 8, 0, /* 470: pointer.func */
            1, 8, 1, /* 473: pointer.struct.dsa_method */
            	478, 0,
            0, 96, 11, /* 478: struct.dsa_method */
            	122, 0,
            	503, 8,
            	506, 16,
            	509, 24,
            	512, 32,
            	515, 40,
            	518, 48,
            	518, 56,
            	122, 72,
            	521, 80,
            	518, 88,
            4097, 8, 0, /* 503: pointer.func */
            4097, 8, 0, /* 506: pointer.func */
            4097, 8, 0, /* 509: pointer.func */
            4097, 8, 0, /* 512: pointer.func */
            4097, 8, 0, /* 515: pointer.func */
            4097, 8, 0, /* 518: pointer.func */
            4097, 8, 0, /* 521: pointer.func */
            1, 8, 1, /* 524: pointer.struct.dh_method */
            	529, 0,
            0, 72, 8, /* 529: struct.dh_method */
            	122, 0,
            	548, 8,
            	551, 16,
            	554, 24,
            	548, 32,
            	548, 40,
            	122, 56,
            	557, 64,
            4097, 8, 0, /* 548: pointer.func */
            4097, 8, 0, /* 551: pointer.func */
            4097, 8, 0, /* 554: pointer.func */
            4097, 8, 0, /* 557: pointer.func */
            1, 8, 1, /* 560: pointer.struct.ecdh_method */
            	565, 0,
            0, 32, 3, /* 565: struct.ecdh_method */
            	122, 0,
            	574, 8,
            	122, 24,
            4097, 8, 0, /* 574: pointer.func */
            1, 8, 1, /* 577: pointer.struct.ecdsa_method */
            	582, 0,
            0, 48, 5, /* 582: struct.ecdsa_method */
            	122, 0,
            	595, 8,
            	598, 16,
            	601, 24,
            	122, 40,
            4097, 8, 0, /* 595: pointer.func */
            4097, 8, 0, /* 598: pointer.func */
            4097, 8, 0, /* 601: pointer.func */
            1, 8, 1, /* 604: pointer.struct.rand_meth_st */
            	609, 0,
            0, 48, 6, /* 609: struct.rand_meth_st */
            	624, 0,
            	627, 8,
            	630, 16,
            	633, 24,
            	627, 32,
            	636, 40,
            4097, 8, 0, /* 624: pointer.func */
            4097, 8, 0, /* 627: pointer.func */
            4097, 8, 0, /* 630: pointer.func */
            4097, 8, 0, /* 633: pointer.func */
            4097, 8, 0, /* 636: pointer.func */
            1, 8, 1, /* 639: pointer.struct.store_method_st */
            	644, 0,
            0, 0, 0, /* 644: struct.store_method_st */
            4097, 8, 0, /* 647: pointer.func */
            4097, 8, 0, /* 650: pointer.func */
            4097, 8, 0, /* 653: pointer.func */
            4097, 8, 0, /* 656: pointer.func */
            4097, 8, 0, /* 659: pointer.func */
            4097, 8, 0, /* 662: pointer.func */
            4097, 8, 0, /* 665: pointer.func */
            4097, 8, 0, /* 668: pointer.func */
            1, 8, 1, /* 671: pointer.struct.ENGINE_CMD_DEFN_st */
            	676, 0,
            0, 32, 2, /* 676: struct.ENGINE_CMD_DEFN_st */
            	122, 8,
            	122, 16,
            0, 16, 1, /* 683: struct.crypto_ex_data_st */
            	182, 0,
            0, 24, 1, /* 688: struct.ASN1_ENCODING_st */
            	122, 0,
            1, 8, 1, /* 693: pointer.struct.AUTHORITY_KEYID_st */
            	698, 0,
            0, 24, 3, /* 698: struct.AUTHORITY_KEYID_st */
            	112, 0,
            	182, 8,
            	112, 16,
            1, 8, 1, /* 707: pointer.struct.X509_POLICY_CACHE_st */
            	712, 0,
            0, 40, 2, /* 712: struct.X509_POLICY_CACHE_st */
            	719, 0,
            	182, 8,
            1, 8, 1, /* 719: pointer.struct.X509_POLICY_DATA_st */
            	724, 0,
            0, 32, 3, /* 724: struct.X509_POLICY_DATA_st */
            	139, 8,
            	182, 16,
            	182, 24,
            1, 8, 1, /* 733: pointer.struct.NAME_CONSTRAINTS_st */
            	738, 0,
            0, 16, 2, /* 738: struct.NAME_CONSTRAINTS_st */
            	182, 0,
            	182, 8,
            1, 8, 1, /* 745: pointer.struct.x509_cert_aux_st */
            	750, 0,
            0, 40, 5, /* 750: struct.x509_cert_aux_st */
            	182, 0,
            	182, 8,
            	112, 16,
            	112, 24,
            	182, 32,
            1, 8, 1, /* 763: pointer.struct.env_md_st */
            	768, 0,
            0, 120, 8, /* 768: struct.env_md_st */
            	787, 24,
            	790, 32,
            	793, 40,
            	796, 48,
            	787, 56,
            	799, 64,
            	802, 72,
            	805, 112,
            4097, 8, 0, /* 787: pointer.func */
            4097, 8, 0, /* 790: pointer.func */
            4097, 8, 0, /* 793: pointer.func */
            4097, 8, 0, /* 796: pointer.func */
            4097, 8, 0, /* 799: pointer.func */
            4097, 8, 0, /* 802: pointer.func */
            4097, 8, 0, /* 805: pointer.func */
            1, 8, 1, /* 808: pointer.struct.rsa_st */
            	813, 0,
            0, 168, 17, /* 813: struct.rsa_st */
            	418, 16,
            	362, 24,
            	850, 32,
            	850, 40,
            	850, 48,
            	850, 56,
            	850, 64,
            	850, 72,
            	850, 80,
            	850, 88,
            	683, 96,
            	868, 120,
            	868, 128,
            	868, 136,
            	122, 144,
            	882, 152,
            	882, 160,
            1, 8, 1, /* 850: pointer.struct.bignum_st */
            	855, 0,
            0, 24, 1, /* 855: struct.bignum_st */
            	860, 0,
            1, 8, 1, /* 860: pointer.int */
            	865, 0,
            0, 4, 0, /* 865: int */
            1, 8, 1, /* 868: pointer.struct.bn_mont_ctx_st */
            	873, 0,
            0, 96, 3, /* 873: struct.bn_mont_ctx_st */
            	855, 8,
            	855, 32,
            	855, 56,
            1, 8, 1, /* 882: pointer.struct.bn_blinding_st */
            	887, 0,
            0, 88, 7, /* 887: struct.bn_blinding_st */
            	850, 0,
            	850, 8,
            	850, 16,
            	850, 24,
            	904, 40,
            	868, 72,
            	458, 80,
            0, 16, 1, /* 904: struct.iovec */
            	122, 0,
            4097, 8, 0, /* 909: pointer.func */
            1, 8, 1, /* 912: pointer.struct.dh_st */
            	917, 0,
            0, 144, 12, /* 917: struct.dh_st */
            	850, 8,
            	850, 16,
            	850, 32,
            	850, 40,
            	868, 56,
            	850, 64,
            	850, 72,
            	122, 80,
            	850, 96,
            	683, 112,
            	524, 128,
            	362, 136,
            4097, 8, 0, /* 944: pointer.func */
            1, 8, 1, /* 947: pointer.struct.ec_key_st */
            	952, 0,
            0, 56, 4, /* 952: struct.ec_key_st */
            	963, 8,
            	1140, 16,
            	850, 24,
            	1156, 48,
            1, 8, 1, /* 963: pointer.struct.ec_group_st */
            	968, 0,
            0, 232, 12, /* 968: struct.ec_group_st */
            	995, 0,
            	1140, 8,
            	855, 16,
            	855, 40,
            	122, 80,
            	1156, 96,
            	855, 104,
            	855, 152,
            	855, 176,
            	122, 208,
            	122, 216,
            	1183, 224,
            1, 8, 1, /* 995: pointer.struct.ec_method_st */
            	1000, 0,
            0, 304, 37, /* 1000: struct.ec_method_st */
            	1077, 8,
            	1080, 16,
            	1080, 24,
            	1083, 32,
            	1086, 40,
            	1086, 48,
            	1077, 56,
            	1089, 64,
            	1092, 72,
            	1095, 80,
            	1095, 88,
            	1098, 96,
            	1101, 104,
            	1104, 112,
            	1104, 120,
            	1107, 128,
            	1107, 136,
            	1110, 144,
            	1113, 152,
            	1116, 160,
            	1119, 168,
            	1122, 176,
            	1125, 184,
            	1101, 192,
            	1125, 200,
            	1122, 208,
            	1125, 216,
            	1128, 224,
            	1131, 232,
            	1089, 240,
            	1077, 248,
            	1086, 256,
            	1134, 264,
            	1086, 272,
            	1134, 280,
            	1134, 288,
            	1137, 296,
            4097, 8, 0, /* 1077: pointer.func */
            4097, 8, 0, /* 1080: pointer.func */
            4097, 8, 0, /* 1083: pointer.func */
            4097, 8, 0, /* 1086: pointer.func */
            4097, 8, 0, /* 1089: pointer.func */
            4097, 8, 0, /* 1092: pointer.func */
            4097, 8, 0, /* 1095: pointer.func */
            4097, 8, 0, /* 1098: pointer.func */
            4097, 8, 0, /* 1101: pointer.func */
            4097, 8, 0, /* 1104: pointer.func */
            4097, 8, 0, /* 1107: pointer.func */
            4097, 8, 0, /* 1110: pointer.func */
            4097, 8, 0, /* 1113: pointer.func */
            4097, 8, 0, /* 1116: pointer.func */
            4097, 8, 0, /* 1119: pointer.func */
            4097, 8, 0, /* 1122: pointer.func */
            4097, 8, 0, /* 1125: pointer.func */
            4097, 8, 0, /* 1128: pointer.func */
            4097, 8, 0, /* 1131: pointer.func */
            4097, 8, 0, /* 1134: pointer.func */
            4097, 8, 0, /* 1137: pointer.func */
            1, 8, 1, /* 1140: pointer.struct.ec_point_st */
            	1145, 0,
            0, 88, 4, /* 1145: struct.ec_point_st */
            	995, 0,
            	855, 8,
            	855, 32,
            	855, 56,
            1, 8, 1, /* 1156: pointer.struct.ec_extra_data_st */
            	1161, 0,
            0, 40, 5, /* 1161: struct.ec_extra_data_st */
            	1156, 0,
            	1174, 8,
            	1177, 16,
            	1180, 24,
            	1180, 32,
            0, 8, 0, /* 1174: pointer.void */
            4097, 8, 0, /* 1177: pointer.func */
            4097, 8, 0, /* 1180: pointer.func */
            4097, 8, 0, /* 1183: pointer.func */
            4097, 8, 0, /* 1186: pointer.func */
            0, 192, 8, /* 1189: array[8].struct.cert_pkey_st */
            	41, 0,
            	41, 24,
            	41, 48,
            	41, 72,
            	41, 96,
            	41, 120,
            	41, 144,
            	41, 168,
            4097, 8, 0, /* 1208: pointer.func */
            4097, 8, 0, /* 1211: pointer.func */
            4097, 8, 0, /* 1214: pointer.func */
            4097, 8, 0, /* 1217: pointer.func */
            4097, 8, 0, /* 1220: pointer.func */
            0, 88, 1, /* 1223: struct.ssl_cipher_st */
            	122, 8,
            1, 8, 1, /* 1228: pointer.struct.ssl3_buf_freelist_st */
            	1233, 0,
            0, 24, 1, /* 1233: struct.ssl3_buf_freelist_st */
            	1238, 16,
            1, 8, 1, /* 1238: pointer.struct.ssl3_buf_freelist_entry_st */
            	1243, 0,
            0, 8, 1, /* 1243: struct.ssl3_buf_freelist_entry_st */
            	1238, 0,
            0, 128, 14, /* 1248: struct.srp_ctx_st */
            	122, 0,
            	1279, 8,
            	6, 16,
            	3, 24,
            	122, 32,
            	850, 40,
            	850, 48,
            	850, 56,
            	850, 64,
            	850, 72,
            	850, 80,
            	850, 88,
            	850, 96,
            	122, 104,
            4097, 8, 0, /* 1279: pointer.func */
            4097, 8, 0, /* 1282: pointer.func */
            0, 352, 14, /* 1285: struct.ssl_session_st */
            	122, 144,
            	122, 152,
            	1316, 168,
            	50, 176,
            	1336, 224,
            	182, 240,
            	683, 248,
            	1341, 264,
            	1341, 272,
            	122, 280,
            	122, 296,
            	122, 312,
            	122, 320,
            	122, 344,
            1, 8, 1, /* 1316: pointer.struct.sess_cert_st */
            	1321, 0,
            0, 248, 6, /* 1321: struct.sess_cert_st */
            	182, 0,
            	36, 16,
            	1189, 24,
            	808, 216,
            	912, 224,
            	947, 232,
            1, 8, 1, /* 1336: pointer.struct.ssl_cipher_st */
            	1223, 0,
            1, 8, 1, /* 1341: pointer.struct.ssl_session_st */
            	1285, 0,
            4097, 8, 0, /* 1346: pointer.func */
            4097, 8, 0, /* 1349: pointer.func */
            4097, 8, 0, /* 1352: pointer.func */
            0, 176, 3, /* 1355: struct.lhash_st */
            	1364, 0,
            	204, 8,
            	1381, 16,
            1, 8, 1, /* 1364: pointer.pointer.struct.lhash_node_st */
            	1369, 0,
            1, 8, 1, /* 1369: pointer.struct.lhash_node_st */
            	1374, 0,
            0, 24, 2, /* 1374: struct.lhash_node_st */
            	1174, 0,
            	1369, 8,
            4097, 8, 0, /* 1381: pointer.func */
            4097, 8, 0, /* 1384: pointer.func */
            0, 144, 15, /* 1387: struct.x509_store_st */
            	182, 8,
            	182, 16,
            	1420, 24,
            	1432, 32,
            	1435, 40,
            	1384, 48,
            	1438, 56,
            	1432, 64,
            	1441, 72,
            	1352, 80,
            	1444, 88,
            	1447, 96,
            	1447, 104,
            	1432, 112,
            	683, 120,
            1, 8, 1, /* 1420: pointer.struct.X509_VERIFY_PARAM_st */
            	1425, 0,
            0, 56, 2, /* 1425: struct.X509_VERIFY_PARAM_st */
            	122, 0,
            	182, 48,
            4097, 8, 0, /* 1432: pointer.func */
            4097, 8, 0, /* 1435: pointer.func */
            4097, 8, 0, /* 1438: pointer.func */
            4097, 8, 0, /* 1441: pointer.func */
            4097, 8, 0, /* 1444: pointer.func */
            4097, 8, 0, /* 1447: pointer.func */
            1, 8, 1, /* 1450: pointer.struct.x509_store_st */
            	1387, 0,
            4097, 8, 0, /* 1455: pointer.func */
            4097, 8, 0, /* 1458: pointer.func */
            4097, 8, 0, /* 1461: pointer.func */
            4097, 8, 0, /* 1464: pointer.func */
            0, 1, 0, /* 1467: char */
            0, 736, 50, /* 1470: struct.ssl_ctx_st */
            	1573, 0,
            	182, 8,
            	182, 16,
            	1450, 24,
            	1709, 32,
            	1341, 48,
            	1341, 56,
            	1220, 80,
            	1217, 88,
            	1214, 96,
            	1714, 152,
            	122, 160,
            	1717, 168,
            	122, 176,
            	1211, 184,
            	1208, 192,
            	1643, 200,
            	683, 208,
            	763, 224,
            	763, 232,
            	763, 240,
            	182, 248,
            	182, 256,
            	1720, 264,
            	182, 272,
            	12, 304,
            	9, 320,
            	122, 328,
            	1435, 376,
            	1208, 384,
            	1420, 392,
            	362, 408,
            	1279, 416,
            	122, 424,
            	1282, 480,
            	6, 488,
            	122, 496,
            	1723, 504,
            	122, 512,
            	122, 520,
            	1726, 528,
            	1697, 536,
            	1228, 552,
            	1228, 560,
            	1248, 568,
            	1729, 696,
            	122, 704,
            	0, 712,
            	122, 720,
            	182, 728,
            1, 8, 1, /* 1573: pointer.struct.ssl_method_st */
            	1578, 0,
            0, 232, 28, /* 1578: struct.ssl_method_st */
            	1637, 8,
            	1640, 16,
            	1640, 24,
            	1637, 32,
            	1637, 40,
            	1643, 48,
            	1643, 56,
            	1643, 64,
            	1637, 72,
            	1637, 80,
            	1637, 88,
            	1646, 96,
            	1464, 104,
            	1649, 112,
            	1637, 120,
            	1652, 128,
            	1349, 136,
            	1655, 144,
            	1658, 152,
            	1637, 160,
            	636, 168,
            	1661, 176,
            	1346, 184,
            	1664, 192,
            	1667, 200,
            	636, 208,
            	1706, 216,
            	1455, 224,
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
            1, 8, 1, /* 1667: pointer.struct.ssl3_enc_method */
            	1672, 0,
            0, 112, 11, /* 1672: struct.ssl3_enc_method */
            	315, 0,
            	1643, 8,
            	1637, 16,
            	1697, 24,
            	315, 32,
            	1700, 40,
            	1703, 56,
            	122, 64,
            	122, 80,
            	1461, 96,
            	1458, 104,
            4097, 8, 0, /* 1697: pointer.func */
            4097, 8, 0, /* 1700: pointer.func */
            4097, 8, 0, /* 1703: pointer.func */
            4097, 8, 0, /* 1706: pointer.func */
            1, 8, 1, /* 1709: pointer.struct.lhash_st */
            	1355, 0,
            4097, 8, 0, /* 1714: pointer.func */
            4097, 8, 0, /* 1717: pointer.func */
            4097, 8, 0, /* 1720: pointer.func */
            4097, 8, 0, /* 1723: pointer.func */
            4097, 8, 0, /* 1726: pointer.func */
            4097, 8, 0, /* 1729: pointer.func */
            1, 8, 1, /* 1732: pointer.struct.ssl_ctx_st */
            	1470, 0,
        },
        .arg_entity_index = { 1732, 865, 1435, },
        .ret_entity_index = -1,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    SSL_CTX * new_arg_a = *((SSL_CTX * *)new_args->args[0]);

    int new_arg_b = *((int *)new_args->args[1]);

    int (*new_arg_c)(int, X509_STORE_CTX *) = *((int (**)(int, X509_STORE_CTX *))new_args->args[2]);

    void (*orig_SSL_CTX_set_verify)(SSL_CTX *,int,int (*)(int, X509_STORE_CTX *));
    orig_SSL_CTX_set_verify = dlsym(RTLD_NEXT, "SSL_CTX_set_verify");
    (*orig_SSL_CTX_set_verify)(new_arg_a,new_arg_b,new_arg_c);

    syscall(889);

}

