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

void bb_SSL_CTX_sess_set_remove_cb(SSL_CTX * arg_a,void (*arg_b)(struct ssl_ctx_st *,SSL_SESSION *));

void SSL_CTX_sess_set_remove_cb(SSL_CTX * arg_a,void (*arg_b)(struct ssl_ctx_st *,SSL_SESSION *)) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_CTX_sess_set_remove_cb called %lu\n", in_lib);
    if (!in_lib)
        bb_SSL_CTX_sess_set_remove_cb(arg_a,arg_b);
    else {
        void (*orig_SSL_CTX_sess_set_remove_cb)(SSL_CTX *,void (*)(struct ssl_ctx_st *,SSL_SESSION *));
        orig_SSL_CTX_sess_set_remove_cb = dlsym(RTLD_NEXT, "SSL_CTX_sess_set_remove_cb");
        orig_SSL_CTX_sess_set_remove_cb(arg_a,arg_b);
    }
}

void bb_SSL_CTX_sess_set_remove_cb(SSL_CTX * arg_a,void (*arg_b)(struct ssl_ctx_st *,SSL_SESSION *)) 
{
    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 0, 0, /* 0: func */
            0, 0, 0, /* 3: func */
            0, 0, 0, /* 6: func */
            0, 0, 0, /* 9: func */
            0, 0, 0, /* 12: func */
            4097, 8, 0, /* 15: pointer.func */
            0, 128, 14, /* 18: struct.srp_ctx_st */
            	49, 0,
            	52, 8,
            	55, 16,
            	58, 24,
            	61, 32,
            	66, 40,
            	66, 48,
            	66, 56,
            	66, 64,
            	66, 72,
            	66, 80,
            	66, 88,
            	66, 96,
            	61, 104,
            0, 8, 0, /* 49: pointer.void */
            4097, 8, 0, /* 52: pointer.func */
            4097, 8, 0, /* 55: pointer.func */
            4097, 8, 0, /* 58: pointer.func */
            0, 8, 1, /* 61: pointer.char */
            	4096, 0,
            0, 8, 1, /* 66: pointer.struct.bignum_st */
            	71, 0,
            0, 24, 1, /* 71: struct.bignum_st */
            	76, 0,
            0, 8, 1, /* 76: pointer.int */
            	81, 0,
            0, 4, 0, /* 81: int */
            0, 16, 0, /* 84: array[16].char */
            0, 0, 0, /* 87: func */
            0, 0, 0, /* 90: func */
            4097, 8, 0, /* 93: pointer.func */
            0, 0, 0, /* 96: func */
            4097, 8, 0, /* 99: pointer.func */
            0, 0, 0, /* 102: func */
            4097, 8, 0, /* 105: pointer.func */
            0, 0, 0, /* 108: func */
            4097, 8, 0, /* 111: pointer.func */
            0, 296, 8, /* 114: struct.cert_st */
            	133, 0,
            	900, 48,
            	111, 56,
            	983, 64,
            	105, 72,
            	1015, 80,
            	99, 88,
            	1251, 96,
            0, 8, 1, /* 133: pointer.struct.cert_pkey_st */
            	138, 0,
            0, 24, 3, /* 138: struct.cert_pkey_st */
            	147, 0,
            	335, 8,
            	855, 16,
            0, 8, 1, /* 147: pointer.struct.x509_st */
            	152, 0,
            0, 184, 12, /* 152: struct.x509_st */
            	179, 0,
            	219, 8,
            	209, 16,
            	61, 32,
            	775, 40,
            	209, 104,
            	785, 112,
            	799, 120,
            	274, 128,
            	274, 136,
            	825, 144,
            	837, 176,
            0, 8, 1, /* 179: pointer.struct.x509_cinf_st */
            	184, 0,
            0, 104, 11, /* 184: struct.x509_cinf_st */
            	209, 0,
            	209, 8,
            	219, 16,
            	260, 24,
            	309, 32,
            	260, 40,
            	321, 48,
            	209, 56,
            	209, 64,
            	274, 72,
            	780, 80,
            0, 8, 1, /* 209: pointer.struct.asn1_string_st */
            	214, 0,
            0, 24, 1, /* 214: struct.asn1_string_st */
            	61, 8,
            0, 8, 1, /* 219: pointer.struct.X509_algor_st */
            	224, 0,
            0, 16, 2, /* 224: struct.X509_algor_st */
            	231, 0,
            	245, 8,
            0, 8, 1, /* 231: pointer.struct.asn1_object_st */
            	236, 0,
            0, 40, 3, /* 236: struct.asn1_object_st */
            	61, 0,
            	61, 8,
            	61, 24,
            0, 8, 1, /* 245: pointer.struct.asn1_type_st */
            	250, 0,
            0, 16, 1, /* 250: struct.asn1_type_st */
            	255, 8,
            0, 8, 1, /* 255: struct.fnames */
            	61, 0,
            0, 8, 1, /* 260: pointer.struct.X509_name_st */
            	265, 0,
            0, 40, 3, /* 265: struct.X509_name_st */
            	274, 0,
            	299, 16,
            	61, 24,
            0, 8, 1, /* 274: pointer.struct.stack_st_OPENSSL_STRING */
            	279, 0,
            0, 32, 1, /* 279: struct.stack_st_OPENSSL_STRING */
            	284, 0,
            0, 32, 2, /* 284: struct.stack_st */
            	291, 8,
            	296, 24,
            0, 8, 1, /* 291: pointer.pointer.char */
            	61, 0,
            4097, 8, 0, /* 296: pointer.func */
            0, 8, 1, /* 299: pointer.struct.buf_mem_st */
            	304, 0,
            0, 24, 1, /* 304: struct.buf_mem_st */
            	61, 8,
            0, 8, 1, /* 309: pointer.struct.X509_val_st */
            	314, 0,
            0, 16, 2, /* 314: struct.X509_val_st */
            	209, 0,
            	209, 8,
            0, 8, 1, /* 321: pointer.struct.X509_pubkey_st */
            	326, 0,
            0, 24, 3, /* 326: struct.X509_pubkey_st */
            	219, 0,
            	209, 8,
            	335, 16,
            0, 8, 1, /* 335: pointer.struct.evp_pkey_st */
            	340, 0,
            0, 56, 4, /* 340: struct.evp_pkey_st */
            	351, 16,
            	454, 24,
            	255, 32,
            	274, 48,
            0, 8, 1, /* 351: pointer.struct.evp_pkey_asn1_method_st */
            	356, 0,
            0, 208, 24, /* 356: struct.evp_pkey_asn1_method_st */
            	61, 16,
            	61, 24,
            	407, 32,
            	415, 40,
            	418, 48,
            	421, 56,
            	424, 64,
            	427, 72,
            	421, 80,
            	430, 88,
            	430, 96,
            	433, 104,
            	436, 112,
            	430, 120,
            	418, 128,
            	418, 136,
            	421, 144,
            	439, 152,
            	442, 160,
            	445, 168,
            	433, 176,
            	436, 184,
            	448, 192,
            	451, 200,
            0, 8, 1, /* 407: pointer.struct.unnamed */
            	412, 0,
            0, 0, 0, /* 412: struct.unnamed */
            4097, 8, 0, /* 415: pointer.func */
            4097, 8, 0, /* 418: pointer.func */
            4097, 8, 0, /* 421: pointer.func */
            4097, 8, 0, /* 424: pointer.func */
            4097, 8, 0, /* 427: pointer.func */
            4097, 8, 0, /* 430: pointer.func */
            4097, 8, 0, /* 433: pointer.func */
            4097, 8, 0, /* 436: pointer.func */
            4097, 8, 0, /* 439: pointer.func */
            4097, 8, 0, /* 442: pointer.func */
            4097, 8, 0, /* 445: pointer.func */
            4097, 8, 0, /* 448: pointer.func */
            4097, 8, 0, /* 451: pointer.func */
            0, 8, 1, /* 454: pointer.struct.engine_st */
            	459, 0,
            0, 216, 24, /* 459: struct.engine_st */
            	61, 0,
            	61, 8,
            	510, 16,
            	565, 24,
            	616, 32,
            	652, 40,
            	669, 48,
            	696, 56,
            	731, 64,
            	739, 72,
            	742, 80,
            	745, 88,
            	748, 96,
            	751, 104,
            	751, 112,
            	751, 120,
            	754, 128,
            	757, 136,
            	757, 144,
            	760, 152,
            	763, 160,
            	775, 184,
            	454, 200,
            	454, 208,
            0, 8, 1, /* 510: pointer.struct.rsa_meth_st */
            	515, 0,
            0, 112, 13, /* 515: struct.rsa_meth_st */
            	61, 0,
            	544, 8,
            	544, 16,
            	544, 24,
            	544, 32,
            	547, 40,
            	550, 48,
            	553, 56,
            	553, 64,
            	61, 80,
            	556, 88,
            	559, 96,
            	562, 104,
            4097, 8, 0, /* 544: pointer.func */
            4097, 8, 0, /* 547: pointer.func */
            4097, 8, 0, /* 550: pointer.func */
            4097, 8, 0, /* 553: pointer.func */
            4097, 8, 0, /* 556: pointer.func */
            4097, 8, 0, /* 559: pointer.func */
            4097, 8, 0, /* 562: pointer.func */
            0, 8, 1, /* 565: pointer.struct.dsa_method */
            	570, 0,
            0, 96, 11, /* 570: struct.dsa_method */
            	61, 0,
            	595, 8,
            	598, 16,
            	601, 24,
            	604, 32,
            	607, 40,
            	610, 48,
            	610, 56,
            	61, 72,
            	613, 80,
            	610, 88,
            4097, 8, 0, /* 595: pointer.func */
            4097, 8, 0, /* 598: pointer.func */
            4097, 8, 0, /* 601: pointer.func */
            4097, 8, 0, /* 604: pointer.func */
            4097, 8, 0, /* 607: pointer.func */
            4097, 8, 0, /* 610: pointer.func */
            4097, 8, 0, /* 613: pointer.func */
            0, 8, 1, /* 616: pointer.struct.dh_method */
            	621, 0,
            0, 72, 8, /* 621: struct.dh_method */
            	61, 0,
            	640, 8,
            	643, 16,
            	646, 24,
            	640, 32,
            	640, 40,
            	61, 56,
            	649, 64,
            4097, 8, 0, /* 640: pointer.func */
            4097, 8, 0, /* 643: pointer.func */
            4097, 8, 0, /* 646: pointer.func */
            4097, 8, 0, /* 649: pointer.func */
            0, 8, 1, /* 652: pointer.struct.ecdh_method */
            	657, 0,
            0, 32, 3, /* 657: struct.ecdh_method */
            	61, 0,
            	666, 8,
            	61, 24,
            4097, 8, 0, /* 666: pointer.func */
            0, 8, 1, /* 669: pointer.struct.ecdsa_method */
            	674, 0,
            0, 48, 5, /* 674: struct.ecdsa_method */
            	61, 0,
            	687, 8,
            	690, 16,
            	693, 24,
            	61, 40,
            4097, 8, 0, /* 687: pointer.func */
            4097, 8, 0, /* 690: pointer.func */
            4097, 8, 0, /* 693: pointer.func */
            0, 8, 1, /* 696: pointer.struct.rand_meth_st */
            	701, 0,
            0, 48, 6, /* 701: struct.rand_meth_st */
            	716, 0,
            	719, 8,
            	722, 16,
            	725, 24,
            	719, 32,
            	728, 40,
            4097, 8, 0, /* 716: pointer.func */
            4097, 8, 0, /* 719: pointer.func */
            4097, 8, 0, /* 722: pointer.func */
            4097, 8, 0, /* 725: pointer.func */
            4097, 8, 0, /* 728: pointer.func */
            0, 8, 1, /* 731: pointer.struct.store_method_st */
            	736, 0,
            0, 0, 0, /* 736: struct.store_method_st */
            4097, 8, 0, /* 739: pointer.func */
            4097, 8, 0, /* 742: pointer.func */
            4097, 8, 0, /* 745: pointer.func */
            4097, 8, 0, /* 748: pointer.func */
            4097, 8, 0, /* 751: pointer.func */
            4097, 8, 0, /* 754: pointer.func */
            4097, 8, 0, /* 757: pointer.func */
            4097, 8, 0, /* 760: pointer.func */
            0, 8, 1, /* 763: pointer.struct.ENGINE_CMD_DEFN_st */
            	768, 0,
            0, 32, 2, /* 768: struct.ENGINE_CMD_DEFN_st */
            	61, 8,
            	61, 16,
            0, 16, 1, /* 775: struct.crypto_ex_data_st */
            	274, 0,
            0, 24, 1, /* 780: struct.ASN1_ENCODING_st */
            	61, 0,
            0, 8, 1, /* 785: pointer.struct.AUTHORITY_KEYID_st */
            	790, 0,
            0, 24, 3, /* 790: struct.AUTHORITY_KEYID_st */
            	209, 0,
            	274, 8,
            	209, 16,
            0, 8, 1, /* 799: pointer.struct.X509_POLICY_CACHE_st */
            	804, 0,
            0, 40, 2, /* 804: struct.X509_POLICY_CACHE_st */
            	811, 0,
            	274, 8,
            0, 8, 1, /* 811: pointer.struct.X509_POLICY_DATA_st */
            	816, 0,
            0, 32, 3, /* 816: struct.X509_POLICY_DATA_st */
            	231, 8,
            	274, 16,
            	274, 24,
            0, 8, 1, /* 825: pointer.struct.NAME_CONSTRAINTS_st */
            	830, 0,
            0, 16, 2, /* 830: struct.NAME_CONSTRAINTS_st */
            	274, 0,
            	274, 8,
            0, 8, 1, /* 837: pointer.struct.x509_cert_aux_st */
            	842, 0,
            0, 40, 5, /* 842: struct.x509_cert_aux_st */
            	274, 0,
            	274, 8,
            	209, 16,
            	209, 24,
            	274, 32,
            0, 8, 1, /* 855: pointer.struct.env_md_st */
            	860, 0,
            0, 120, 8, /* 860: struct.env_md_st */
            	879, 24,
            	882, 32,
            	885, 40,
            	888, 48,
            	879, 56,
            	891, 64,
            	894, 72,
            	897, 112,
            4097, 8, 0, /* 879: pointer.func */
            4097, 8, 0, /* 882: pointer.func */
            4097, 8, 0, /* 885: pointer.func */
            4097, 8, 0, /* 888: pointer.func */
            4097, 8, 0, /* 891: pointer.func */
            4097, 8, 0, /* 894: pointer.func */
            4097, 8, 0, /* 897: pointer.func */
            0, 8, 1, /* 900: pointer.struct.rsa_st */
            	905, 0,
            0, 168, 17, /* 905: struct.rsa_st */
            	510, 16,
            	454, 24,
            	66, 32,
            	66, 40,
            	66, 48,
            	66, 56,
            	66, 64,
            	66, 72,
            	66, 80,
            	66, 88,
            	775, 96,
            	942, 120,
            	942, 128,
            	942, 136,
            	61, 144,
            	956, 152,
            	956, 160,
            0, 8, 1, /* 942: pointer.struct.bn_mont_ctx_st */
            	947, 0,
            0, 96, 3, /* 947: struct.bn_mont_ctx_st */
            	71, 8,
            	71, 32,
            	71, 56,
            0, 8, 1, /* 956: pointer.struct.bn_blinding_st */
            	961, 0,
            0, 88, 7, /* 961: struct.bn_blinding_st */
            	66, 0,
            	66, 8,
            	66, 16,
            	66, 24,
            	978, 40,
            	942, 72,
            	550, 80,
            0, 16, 1, /* 978: struct.iovec */
            	61, 0,
            0, 8, 1, /* 983: pointer.struct.dh_st */
            	988, 0,
            0, 144, 12, /* 988: struct.dh_st */
            	66, 8,
            	66, 16,
            	66, 32,
            	66, 40,
            	942, 56,
            	66, 64,
            	66, 72,
            	61, 80,
            	66, 96,
            	775, 112,
            	616, 128,
            	454, 136,
            0, 8, 1, /* 1015: pointer.struct.ec_key_st */
            	1020, 0,
            0, 56, 4, /* 1020: struct.ec_key_st */
            	1031, 8,
            	1208, 16,
            	66, 24,
            	1224, 48,
            0, 8, 1, /* 1031: pointer.struct.ec_group_st */
            	1036, 0,
            0, 232, 12, /* 1036: struct.ec_group_st */
            	1063, 0,
            	1208, 8,
            	71, 16,
            	71, 40,
            	61, 80,
            	1224, 96,
            	71, 104,
            	71, 152,
            	71, 176,
            	61, 208,
            	61, 216,
            	1248, 224,
            0, 8, 1, /* 1063: pointer.struct.ec_method_st */
            	1068, 0,
            0, 304, 37, /* 1068: struct.ec_method_st */
            	1145, 8,
            	1148, 16,
            	1148, 24,
            	1151, 32,
            	1154, 40,
            	1154, 48,
            	1145, 56,
            	1157, 64,
            	1160, 72,
            	1163, 80,
            	1163, 88,
            	1166, 96,
            	1169, 104,
            	1172, 112,
            	1172, 120,
            	1175, 128,
            	1175, 136,
            	1178, 144,
            	1181, 152,
            	1184, 160,
            	1187, 168,
            	1190, 176,
            	1193, 184,
            	1169, 192,
            	1193, 200,
            	1190, 208,
            	1193, 216,
            	1196, 224,
            	1199, 232,
            	1157, 240,
            	1145, 248,
            	1154, 256,
            	1202, 264,
            	1154, 272,
            	1202, 280,
            	1202, 288,
            	1205, 296,
            4097, 8, 0, /* 1145: pointer.func */
            4097, 8, 0, /* 1148: pointer.func */
            4097, 8, 0, /* 1151: pointer.func */
            4097, 8, 0, /* 1154: pointer.func */
            4097, 8, 0, /* 1157: pointer.func */
            4097, 8, 0, /* 1160: pointer.func */
            4097, 8, 0, /* 1163: pointer.func */
            4097, 8, 0, /* 1166: pointer.func */
            4097, 8, 0, /* 1169: pointer.func */
            4097, 8, 0, /* 1172: pointer.func */
            4097, 8, 0, /* 1175: pointer.func */
            4097, 8, 0, /* 1178: pointer.func */
            4097, 8, 0, /* 1181: pointer.func */
            4097, 8, 0, /* 1184: pointer.func */
            4097, 8, 0, /* 1187: pointer.func */
            4097, 8, 0, /* 1190: pointer.func */
            4097, 8, 0, /* 1193: pointer.func */
            4097, 8, 0, /* 1196: pointer.func */
            4097, 8, 0, /* 1199: pointer.func */
            4097, 8, 0, /* 1202: pointer.func */
            4097, 8, 0, /* 1205: pointer.func */
            0, 8, 1, /* 1208: pointer.struct.ec_point_st */
            	1213, 0,
            0, 88, 4, /* 1213: struct.ec_point_st */
            	1063, 0,
            	71, 8,
            	71, 32,
            	71, 56,
            0, 8, 1, /* 1224: pointer.struct.ec_extra_data_st */
            	1229, 0,
            0, 40, 5, /* 1229: struct.ec_extra_data_st */
            	1224, 0,
            	61, 8,
            	1242, 16,
            	1245, 24,
            	1245, 32,
            4097, 8, 0, /* 1242: pointer.func */
            4097, 8, 0, /* 1245: pointer.func */
            4097, 8, 0, /* 1248: pointer.func */
            0, 192, 8, /* 1251: array[8].struct.cert_pkey_st */
            	138, 0,
            	138, 24,
            	138, 48,
            	138, 72,
            	138, 96,
            	138, 120,
            	138, 144,
            	138, 168,
            0, 8, 1, /* 1270: pointer.struct.cert_st */
            	114, 0,
            0, 0, 0, /* 1275: func */
            4097, 8, 0, /* 1278: pointer.func */
            0, 0, 0, /* 1281: func */
            4097, 8, 0, /* 1284: pointer.func */
            0, 0, 0, /* 1287: func */
            4097, 8, 0, /* 1290: pointer.func */
            4097, 8, 0, /* 1293: pointer.func */
            0, 44, 0, /* 1296: struct.apr_time_exp_t */
            0, 0, 0, /* 1299: func */
            0, 0, 0, /* 1302: func */
            4097, 8, 0, /* 1305: pointer.func */
            0, 0, 0, /* 1308: func */
            4097, 8, 0, /* 1311: pointer.func */
            0, 88, 1, /* 1314: struct.ssl_cipher_st */
            	61, 8,
            0, 8, 1, /* 1319: pointer.struct.ssl_cipher_st */
            	1314, 0,
            0, 0, 0, /* 1324: func */
            0, 24, 0, /* 1327: array[6].int */
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
            4097, 8, 0, /* 1360: pointer.func */
            0, 0, 0, /* 1363: func */
            0, 0, 0, /* 1366: func */
            4097, 8, 0, /* 1369: pointer.func */
            0, 0, 0, /* 1372: func */
            0, 24, 1, /* 1375: struct.ssl3_buf_freelist_st */
            	1380, 16,
            0, 8, 1, /* 1380: pointer.struct.ssl3_buf_freelist_entry_st */
            	1385, 0,
            0, 8, 1, /* 1385: struct.ssl3_buf_freelist_entry_st */
            	1380, 0,
            0, 0, 0, /* 1390: func */
            0, 0, 0, /* 1393: func */
            0, 0, 0, /* 1396: func */
            4097, 8, 0, /* 1399: pointer.func */
            0, 0, 0, /* 1402: func */
            0, 0, 0, /* 1405: func */
            0, 8, 1, /* 1408: pointer.struct.ssl3_buf_freelist_st */
            	1375, 0,
            0, 8, 0, /* 1413: array[2].int */
            4097, 8, 0, /* 1416: pointer.func */
            0, 0, 0, /* 1419: func */
            0, 20, 0, /* 1422: array[5].int */
            4097, 8, 0, /* 1425: pointer.func */
            0, 0, 0, /* 1428: func */
            0, 0, 0, /* 1431: func */
            0, 0, 0, /* 1434: func */
            0, 0, 0, /* 1437: func */
            0, 8, 1, /* 1440: pointer.struct.sess_cert_st */
            	1445, 0,
            0, 248, 6, /* 1445: struct.sess_cert_st */
            	274, 0,
            	133, 16,
            	1251, 24,
            	900, 216,
            	983, 224,
            	1015, 232,
            0, 0, 0, /* 1460: func */
            0, 0, 0, /* 1463: func */
            0, 48, 0, /* 1466: array[48].char */
            0, 352, 14, /* 1469: struct.ssl_session_st */
            	61, 144,
            	61, 152,
            	1440, 168,
            	147, 176,
            	1319, 224,
            	274, 240,
            	775, 248,
            	1500, 264,
            	1500, 272,
            	61, 280,
            	61, 296,
            	61, 312,
            	61, 320,
            	61, 344,
            0, 8, 1, /* 1500: pointer.struct.ssl_session_st */
            	1469, 0,
            0, 0, 0, /* 1505: func */
            4097, 8, 0, /* 1508: pointer.func */
            0, 0, 0, /* 1511: func */
            4097, 8, 0, /* 1514: pointer.func */
            0, 0, 0, /* 1517: func */
            0, 0, 0, /* 1520: func */
            4097, 8, 0, /* 1523: pointer.func */
            0, 0, 0, /* 1526: func */
            4097, 8, 0, /* 1529: pointer.func */
            4097, 8, 0, /* 1532: pointer.func */
            0, 0, 0, /* 1535: func */
            0, 56, 2, /* 1538: struct.X509_VERIFY_PARAM_st */
            	61, 0,
            	274, 48,
            0, 0, 0, /* 1545: func */
            4097, 8, 0, /* 1548: pointer.func */
            0, 8, 1, /* 1551: pointer.struct.X509_VERIFY_PARAM_st */
            	1538, 0,
            0, 0, 0, /* 1556: func */
            0, 0, 0, /* 1559: func */
            4097, 8, 0, /* 1562: pointer.func */
            0, 144, 15, /* 1565: struct.x509_store_st */
            	274, 8,
            	274, 16,
            	1551, 24,
            	1598, 32,
            	1601, 40,
            	1604, 48,
            	1532, 56,
            	1598, 64,
            	1607, 72,
            	1523, 80,
            	1425, 88,
            	1514, 96,
            	1514, 104,
            	1598, 112,
            	775, 120,
            4097, 8, 0, /* 1598: pointer.func */
            4097, 8, 0, /* 1601: pointer.func */
            4097, 8, 0, /* 1604: pointer.func */
            4097, 8, 0, /* 1607: pointer.func */
            0, 0, 0, /* 1610: func */
            0, 8, 1, /* 1613: pointer.struct.x509_store_st */
            	1565, 0,
            0, 0, 0, /* 1618: func */
            0, 0, 0, /* 1621: func */
            0, 0, 0, /* 1624: func */
            0, 0, 0, /* 1627: func */
            0, 0, 0, /* 1630: func */
            0, 0, 0, /* 1633: func */
            0, 0, 0, /* 1636: func */
            0, 8, 1, /* 1639: pointer.struct.in_addr */
            	1644, 0,
            0, 4, 0, /* 1644: struct.in_addr */
            0, 8, 1, /* 1647: pointer.struct.ssl_ctx_st */
            	1652, 0,
            0, 736, 50, /* 1652: struct.ssl_ctx_st */
            	1755, 0,
            	274, 8,
            	274, 16,
            	1613, 24,
            	1639, 32,
            	1500, 48,
            	1500, 56,
            	1311, 80,
            	1305, 88,
            	1399, 96,
            	1293, 152,
            	49, 160,
            	1290, 168,
            	49, 176,
            	1284, 184,
            	1508, 192,
            	1822, 200,
            	775, 208,
            	855, 224,
            	855, 232,
            	855, 240,
            	274, 248,
            	274, 256,
            	1278, 264,
            	274, 272,
            	1270, 304,
            	93, 320,
            	49, 328,
            	1601, 376,
            	1508, 384,
            	1551, 392,
            	454, 408,
            	52, 416,
            	49, 424,
            	15, 480,
            	55, 488,
            	49, 496,
            	1369, 504,
            	49, 512,
            	61, 520,
            	1562, 528,
            	1888, 536,
            	1408, 552,
            	1408, 560,
            	18, 568,
            	1416, 696,
            	49, 704,
            	1360, 712,
            	49, 720,
            	274, 728,
            0, 8, 1, /* 1755: pointer.struct.ssl_method_st */
            	1760, 0,
            0, 232, 28, /* 1760: struct.ssl_method_st */
            	1819, 8,
            	1548, 16,
            	1548, 24,
            	1819, 32,
            	1819, 40,
            	1822, 48,
            	1822, 56,
            	1822, 64,
            	1819, 72,
            	1819, 80,
            	1819, 88,
            	1825, 96,
            	1828, 104,
            	1831, 112,
            	1819, 120,
            	1834, 128,
            	1837, 136,
            	1840, 144,
            	1843, 152,
            	1819, 160,
            	728, 168,
            	1846, 176,
            	1849, 184,
            	1852, 192,
            	1855, 200,
            	728, 208,
            	1900, 216,
            	1903, 224,
            4097, 8, 0, /* 1819: pointer.func */
            4097, 8, 0, /* 1822: pointer.func */
            4097, 8, 0, /* 1825: pointer.func */
            4097, 8, 0, /* 1828: pointer.func */
            4097, 8, 0, /* 1831: pointer.func */
            4097, 8, 0, /* 1834: pointer.func */
            4097, 8, 0, /* 1837: pointer.func */
            4097, 8, 0, /* 1840: pointer.func */
            4097, 8, 0, /* 1843: pointer.func */
            4097, 8, 0, /* 1846: pointer.func */
            4097, 8, 0, /* 1849: pointer.func */
            4097, 8, 0, /* 1852: pointer.func */
            0, 8, 1, /* 1855: pointer.struct.ssl3_enc_method */
            	1860, 0,
            0, 112, 11, /* 1860: struct.ssl3_enc_method */
            	1885, 0,
            	1822, 8,
            	1819, 16,
            	1888, 24,
            	1885, 32,
            	1529, 40,
            	1891, 56,
            	61, 64,
            	61, 80,
            	1894, 96,
            	1897, 104,
            4097, 8, 0, /* 1885: pointer.func */
            4097, 8, 0, /* 1888: pointer.func */
            4097, 8, 0, /* 1891: pointer.func */
            4097, 8, 0, /* 1894: pointer.func */
            4097, 8, 0, /* 1897: pointer.func */
            4097, 8, 0, /* 1900: pointer.func */
            4097, 8, 0, /* 1903: pointer.func */
            0, 0, 0, /* 1906: func */
            0, 0, 0, /* 1909: func */
            0, 0, 0, /* 1912: func */
            0, 0, 0, /* 1915: func */
            0, 0, 0, /* 1918: func */
            0, 0, 0, /* 1921: func */
            0, 0, 0, /* 1924: func */
            0, 0, 0, /* 1927: func */
            0, 0, 0, /* 1930: func */
            0, 0, 0, /* 1933: func */
            0, 0, 0, /* 1936: func */
            0, 0, 0, /* 1939: func */
            0, 0, 0, /* 1942: func */
            0, 0, 0, /* 1945: func */
            0, 0, 0, /* 1948: func */
            0, 0, 0, /* 1951: func */
            0, 0, 0, /* 1954: func */
            0, 0, 0, /* 1957: func */
            0, 0, 0, /* 1960: func */
            0, 0, 0, /* 1963: func */
            0, 0, 0, /* 1966: func */
            0, 0, 0, /* 1969: func */
            0, 0, 0, /* 1972: func */
            0, 0, 0, /* 1975: func */
            0, 0, 0, /* 1978: func */
            0, 20, 0, /* 1981: array[20].char */
            0, 0, 0, /* 1984: func */
            0, 0, 0, /* 1987: func */
            0, 1, 0, /* 1990: char */
            0, 0, 0, /* 1993: func */
            0, 8, 0, /* 1996: array[8].char */
            0, 32, 0, /* 1999: array[32].char */
            0, 0, 0, /* 2002: func */
            0, 0, 0, /* 2005: func */
            0, 0, 0, /* 2008: func */
            0, 0, 0, /* 2011: func */
            0, 0, 0, /* 2014: func */
            0, 0, 0, /* 2017: func */
            0, 0, 0, /* 2020: func */
            0, 0, 0, /* 2023: func */
            0, 0, 0, /* 2026: func */
            0, 8, 0, /* 2029: long */
            0, 0, 0, /* 2032: func */
            0, 0, 0, /* 2035: func */
            0, 0, 0, /* 2038: func */
            0, 0, 0, /* 2041: func */
            0, 0, 0, /* 2044: func */
            0, 0, 0, /* 2047: func */
            0, 0, 0, /* 2050: func */
            0, 0, 0, /* 2053: func */
            0, 0, 0, /* 2056: func */
            0, 0, 0, /* 2059: func */
            0, 0, 0, /* 2062: func */
            0, 0, 0, /* 2065: func */
            0, 0, 0, /* 2068: func */
            0, 0, 0, /* 2071: func */
            0, 0, 0, /* 2074: func */
            0, 0, 0, /* 2077: func */
            0, 0, 0, /* 2080: func */
            0, 0, 0, /* 2083: func */
            0, 0, 0, /* 2086: func */
            0, 0, 0, /* 2089: func */
            0, 0, 0, /* 2092: func */
            0, 0, 0, /* 2095: func */
            0, 0, 0, /* 2098: func */
            0, 0, 0, /* 2101: func */
            0, 0, 0, /* 2104: func */
            0, 0, 0, /* 2107: func */
            0, 0, 0, /* 2110: func */
            0, 0, 0, /* 2113: func */
            0, 0, 0, /* 2116: func */
            0, 0, 0, /* 2119: func */
            0, 0, 0, /* 2122: func */
            0, 0, 0, /* 2125: func */
            0, 0, 0, /* 2128: func */
        },
        .arg_entity_index = { 1647, 1305, },
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

