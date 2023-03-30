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
    printf("SSL_CTX_sess_set_remove_cb called\n");
    if (!syscall(890))
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
            0, 8, 0, /* 6: pointer.func */
            0, 8, 0, /* 9: pointer.func */
            0, 128, 11, /* 12: struct.srp_ctx_st.921 */
            	37, 0,
            	37, 32,
            	45, 40,
            	45, 48,
            	45, 56,
            	45, 64,
            	45, 72,
            	45, 80,
            	45, 88,
            	45, 96,
            	37, 104,
            1, 8, 1, /* 37: pointer.char */
            	42, 0,
            0, 1, 0, /* 42: char */
            1, 8, 1, /* 45: pointer.struct.bignum_st */
            	50, 0,
            0, 24, 1, /* 50: struct.bignum_st */
            	55, 0,
            1, 8, 1, /* 55: pointer.int */
            	60, 0,
            0, 4, 0, /* 60: int */
            1, 8, 1, /* 63: pointer.struct.ssl3_buf_freelist_entry_st */
            	68, 0,
            0, 8, 1, /* 68: struct.ssl3_buf_freelist_entry_st */
            	63, 0,
            0, 8, 0, /* 73: pointer.func */
            0, 0, 0, /* 76: func */
            0, 16, 0, /* 79: array[16].char */
            0, 8, 0, /* 82: pointer.func */
            0, 8, 0, /* 85: pointer.func */
            0, 0, 0, /* 88: func */
            0, 0, 0, /* 91: func */
            0, 0, 0, /* 94: func */
            0, 8, 0, /* 97: pointer.func */
            0, 296, 5, /* 100: struct.cert_st.915 */
            	113, 0,
            	558, 48,
            	639, 64,
            	671, 80,
            	753, 96,
            1, 8, 1, /* 113: pointer.struct.cert_pkey_st */
            	118, 0,
            0, 24, 3, /* 118: struct.cert_pkey_st */
            	127, 0,
            	310, 8,
            	550, 16,
            1, 8, 1, /* 127: pointer.struct.x509_st */
            	132, 0,
            0, 184, 12, /* 132: struct.x509_st */
            	159, 0,
            	199, 8,
            	189, 16,
            	37, 32,
            	470, 40,
            	189, 104,
            	480, 112,
            	494, 120,
            	254, 128,
            	254, 136,
            	520, 144,
            	532, 176,
            1, 8, 1, /* 159: pointer.struct.x509_cinf_st */
            	164, 0,
            0, 104, 11, /* 164: struct.x509_cinf_st */
            	189, 0,
            	189, 8,
            	199, 16,
            	240, 24,
            	284, 32,
            	240, 40,
            	296, 48,
            	189, 56,
            	189, 64,
            	254, 72,
            	475, 80,
            1, 8, 1, /* 189: pointer.struct.asn1_string_st */
            	194, 0,
            0, 24, 1, /* 194: struct.asn1_string_st */
            	37, 8,
            1, 8, 1, /* 199: pointer.struct.X509_algor_st */
            	204, 0,
            0, 16, 2, /* 204: struct.X509_algor_st */
            	211, 0,
            	225, 8,
            1, 8, 1, /* 211: pointer.struct.asn1_object_st */
            	216, 0,
            0, 40, 3, /* 216: struct.asn1_object_st */
            	37, 0,
            	37, 8,
            	37, 24,
            1, 8, 1, /* 225: pointer.struct.asn1_type_st */
            	230, 0,
            0, 16, 1, /* 230: struct.asn1_type_st */
            	235, 8,
            0, 8, 1, /* 235: struct.fnames */
            	37, 0,
            1, 8, 1, /* 240: pointer.struct.X509_name_st */
            	245, 0,
            0, 40, 3, /* 245: struct.X509_name_st */
            	254, 0,
            	274, 16,
            	37, 24,
            1, 8, 1, /* 254: pointer.struct.stack_st_OPENSSL_STRING */
            	259, 0,
            0, 32, 1, /* 259: struct.stack_st_OPENSSL_STRING */
            	264, 0,
            0, 32, 1, /* 264: struct.stack_st */
            	269, 8,
            1, 8, 1, /* 269: pointer.pointer.char */
            	37, 0,
            1, 8, 1, /* 274: pointer.struct.buf_mem_st */
            	279, 0,
            0, 24, 1, /* 279: struct.buf_mem_st */
            	37, 8,
            1, 8, 1, /* 284: pointer.struct.X509_val_st */
            	289, 0,
            0, 16, 2, /* 289: struct.X509_val_st */
            	189, 0,
            	189, 8,
            1, 8, 1, /* 296: pointer.struct.X509_pubkey_st */
            	301, 0,
            0, 24, 3, /* 301: struct.X509_pubkey_st */
            	199, 0,
            	189, 8,
            	310, 16,
            1, 8, 1, /* 310: pointer.struct.evp_pkey_st */
            	315, 0,
            0, 56, 4, /* 315: struct.evp_pkey_st */
            	326, 16,
            	348, 24,
            	235, 32,
            	254, 48,
            1, 8, 1, /* 326: pointer.struct.evp_pkey_asn1_method_st */
            	331, 0,
            0, 208, 3, /* 331: struct.evp_pkey_asn1_method_st */
            	37, 16,
            	37, 24,
            	340, 32,
            1, 8, 1, /* 340: pointer.struct.unnamed */
            	345, 0,
            0, 0, 0, /* 345: struct.unnamed */
            1, 8, 1, /* 348: pointer.struct.engine_st */
            	353, 0,
            0, 216, 13, /* 353: struct.engine_st */
            	37, 0,
            	37, 8,
            	382, 16,
            	394, 24,
            	406, 32,
            	418, 40,
            	430, 48,
            	442, 56,
            	450, 64,
            	458, 160,
            	470, 184,
            	348, 200,
            	348, 208,
            1, 8, 1, /* 382: pointer.struct.rsa_meth_st */
            	387, 0,
            0, 112, 2, /* 387: struct.rsa_meth_st */
            	37, 0,
            	37, 80,
            1, 8, 1, /* 394: pointer.struct.dsa_method.1040 */
            	399, 0,
            0, 96, 2, /* 399: struct.dsa_method.1040 */
            	37, 0,
            	37, 72,
            1, 8, 1, /* 406: pointer.struct.dh_method */
            	411, 0,
            0, 72, 2, /* 411: struct.dh_method */
            	37, 0,
            	37, 56,
            1, 8, 1, /* 418: pointer.struct.ecdh_method */
            	423, 0,
            0, 32, 2, /* 423: struct.ecdh_method */
            	37, 0,
            	37, 24,
            1, 8, 1, /* 430: pointer.struct.ecdsa_method */
            	435, 0,
            0, 48, 2, /* 435: struct.ecdsa_method */
            	37, 0,
            	37, 40,
            1, 8, 1, /* 442: pointer.struct.rand_meth_st */
            	447, 0,
            0, 48, 0, /* 447: struct.rand_meth_st */
            1, 8, 1, /* 450: pointer.struct.store_method_st */
            	455, 0,
            0, 0, 0, /* 455: struct.store_method_st */
            1, 8, 1, /* 458: pointer.struct.ENGINE_CMD_DEFN_st */
            	463, 0,
            0, 32, 2, /* 463: struct.ENGINE_CMD_DEFN_st */
            	37, 8,
            	37, 16,
            0, 16, 1, /* 470: struct.crypto_ex_data_st */
            	254, 0,
            0, 24, 1, /* 475: struct.ASN1_ENCODING_st */
            	37, 0,
            1, 8, 1, /* 480: pointer.struct.AUTHORITY_KEYID_st */
            	485, 0,
            0, 24, 3, /* 485: struct.AUTHORITY_KEYID_st */
            	189, 0,
            	254, 8,
            	189, 16,
            1, 8, 1, /* 494: pointer.struct.X509_POLICY_CACHE_st */
            	499, 0,
            0, 40, 2, /* 499: struct.X509_POLICY_CACHE_st */
            	506, 0,
            	254, 8,
            1, 8, 1, /* 506: pointer.struct.X509_POLICY_DATA_st */
            	511, 0,
            0, 32, 3, /* 511: struct.X509_POLICY_DATA_st */
            	211, 8,
            	254, 16,
            	254, 24,
            1, 8, 1, /* 520: pointer.struct.NAME_CONSTRAINTS_st */
            	525, 0,
            0, 16, 2, /* 525: struct.NAME_CONSTRAINTS_st */
            	254, 0,
            	254, 8,
            1, 8, 1, /* 532: pointer.struct.x509_cert_aux_st */
            	537, 0,
            0, 40, 5, /* 537: struct.x509_cert_aux_st */
            	254, 0,
            	254, 8,
            	189, 16,
            	189, 24,
            	254, 32,
            1, 8, 1, /* 550: pointer.struct.env_md_st */
            	555, 0,
            0, 120, 0, /* 555: struct.env_md_st */
            1, 8, 1, /* 558: pointer.struct.rsa_st */
            	563, 0,
            0, 168, 17, /* 563: struct.rsa_st */
            	382, 16,
            	348, 24,
            	45, 32,
            	45, 40,
            	45, 48,
            	45, 56,
            	45, 64,
            	45, 72,
            	45, 80,
            	45, 88,
            	470, 96,
            	600, 120,
            	600, 128,
            	600, 136,
            	37, 144,
            	614, 152,
            	614, 160,
            1, 8, 1, /* 600: pointer.struct.bn_mont_ctx_st */
            	605, 0,
            0, 96, 3, /* 605: struct.bn_mont_ctx_st */
            	50, 8,
            	50, 32,
            	50, 56,
            1, 8, 1, /* 614: pointer.struct.bn_blinding_st */
            	619, 0,
            0, 88, 6, /* 619: struct.bn_blinding_st */
            	45, 0,
            	45, 8,
            	45, 16,
            	45, 24,
            	634, 40,
            	600, 72,
            0, 16, 1, /* 634: struct.iovec */
            	37, 0,
            1, 8, 1, /* 639: pointer.struct.dh_st */
            	644, 0,
            0, 144, 12, /* 644: struct.dh_st */
            	45, 8,
            	45, 16,
            	45, 32,
            	45, 40,
            	600, 56,
            	45, 64,
            	45, 72,
            	37, 80,
            	45, 96,
            	470, 112,
            	406, 128,
            	348, 136,
            1, 8, 1, /* 671: pointer.struct.ec_key_st.284 */
            	676, 0,
            0, 56, 4, /* 676: struct.ec_key_st.284 */
            	687, 8,
            	725, 16,
            	45, 24,
            	741, 48,
            1, 8, 1, /* 687: pointer.struct.ec_group_st */
            	692, 0,
            0, 232, 11, /* 692: struct.ec_group_st */
            	717, 0,
            	725, 8,
            	50, 16,
            	50, 40,
            	37, 80,
            	741, 96,
            	50, 104,
            	50, 152,
            	50, 176,
            	37, 208,
            	37, 216,
            1, 8, 1, /* 717: pointer.struct.ec_method_st */
            	722, 0,
            0, 304, 0, /* 722: struct.ec_method_st */
            1, 8, 1, /* 725: pointer.struct.ec_point_st */
            	730, 0,
            0, 88, 4, /* 730: struct.ec_point_st */
            	717, 0,
            	50, 8,
            	50, 32,
            	50, 56,
            1, 8, 1, /* 741: pointer.struct.ec_extra_data_st */
            	746, 0,
            0, 40, 2, /* 746: struct.ec_extra_data_st */
            	741, 0,
            	37, 8,
            0, 192, 8, /* 753: array[8].struct.cert_pkey_st */
            	118, 0,
            	118, 24,
            	118, 48,
            	118, 72,
            	118, 96,
            	118, 120,
            	118, 144,
            	118, 168,
            1, 8, 1, /* 772: pointer.struct.cert_st.915 */
            	100, 0,
            0, 8, 0, /* 777: pointer.func */
            0, 0, 0, /* 780: func */
            0, 8, 0, /* 783: pointer.func */
            0, 0, 0, /* 786: func */
            0, 8, 0, /* 789: pointer.func */
            0, 0, 0, /* 792: func */
            0, 8, 0, /* 795: pointer.func */
            0, 44, 0, /* 798: struct.apr_time_exp_t */
            0, 8, 0, /* 801: pointer.func */
            0, 0, 0, /* 804: func */
            0, 8, 0, /* 807: pointer.func */
            0, 8, 0, /* 810: pointer.func */
            1, 8, 1, /* 813: pointer.struct.ssl_cipher_st */
            	818, 0,
            0, 88, 1, /* 818: struct.ssl_cipher_st */
            	37, 8,
            0, 0, 0, /* 823: func */
            0, 8, 0, /* 826: pointer.func */
            0, 8, 0, /* 829: pointer.func */
            0, 0, 0, /* 832: func */
            0, 8, 0, /* 835: pointer.func */
            0, 0, 0, /* 838: func */
            0, 0, 0, /* 841: func */
            0, 8, 0, /* 844: pointer.func */
            0, 0, 0, /* 847: func */
            0, 8, 0, /* 850: pointer.func */
            0, 0, 0, /* 853: func */
            0, 8, 0, /* 856: pointer.func */
            0, 0, 0, /* 859: func */
            0, 8, 0, /* 862: pointer.func */
            0, 0, 0, /* 865: func */
            0, 0, 0, /* 868: func */
            0, 0, 0, /* 871: func */
            0, 8, 0, /* 874: pointer.func */
            0, 0, 0, /* 877: func */
            0, 8, 0, /* 880: pointer.func */
            0, 0, 0, /* 883: func */
            0, 8, 0, /* 886: pointer.func */
            0, 0, 0, /* 889: func */
            0, 8, 0, /* 892: pointer.func */
            0, 0, 0, /* 895: func */
            0, 8, 0, /* 898: pointer.func */
            0, 8, 0, /* 901: pointer.func */
            0, 0, 0, /* 904: func */
            0, 8, 0, /* 907: pointer.func */
            0, 0, 0, /* 910: func */
            0, 8, 0, /* 913: pointer.func */
            0, 0, 0, /* 916: func */
            0, 0, 0, /* 919: func */
            0, 8, 0, /* 922: pointer.func */
            0, 0, 0, /* 925: func */
            0, 0, 0, /* 928: func */
            0, 8, 0, /* 931: pointer.func */
            0, 8, 0, /* 934: pointer.func */
            0, 8, 0, /* 937: pointer.func */
            0, 8, 0, /* 940: pointer.func */
            0, 8, 0, /* 943: pointer.func */
            0, 8, 0, /* 946: pointer.func */
            0, 8, 0, /* 949: array[2].int */
            0, 0, 0, /* 952: func */
            0, 8, 0, /* 955: pointer.func */
            0, 0, 0, /* 958: func */
            0, 8, 0, /* 961: pointer.func */
            0, 20, 0, /* 964: array[5].int */
            0, 8, 0, /* 967: pointer.func */
            0, 0, 0, /* 970: func */
            0, 8, 0, /* 973: pointer.func */
            0, 0, 0, /* 976: func */
            0, 8, 0, /* 979: pointer.func */
            0, 0, 0, /* 982: func */
            0, 0, 0, /* 985: func */
            0, 4, 0, /* 988: struct.in_addr */
            0, 8, 0, /* 991: pointer.func */
            0, 8, 0, /* 994: pointer.func */
            0, 0, 0, /* 997: func */
            0, 8, 0, /* 1000: pointer.func */
            0, 0, 0, /* 1003: func */
            0, 0, 0, /* 1006: func */
            0, 248, 6, /* 1009: struct.sess_cert_st */
            	254, 0,
            	113, 16,
            	753, 24,
            	558, 216,
            	639, 224,
            	671, 232,
            0, 0, 0, /* 1024: func */
            1, 8, 1, /* 1027: pointer.struct.in_addr */
            	988, 0,
            0, 0, 0, /* 1032: func */
            0, 0, 0, /* 1035: func */
            0, 8, 0, /* 1038: pointer.func */
            0, 8, 0, /* 1041: pointer.func */
            0, 0, 0, /* 1044: func */
            0, 8, 0, /* 1047: pointer.func */
            0, 8, 0, /* 1050: pointer.func */
            0, 0, 0, /* 1053: func */
            0, 8, 0, /* 1056: pointer.func */
            0, 8, 0, /* 1059: pointer.func */
            0, 8, 0, /* 1062: pointer.func */
            0, 8, 0, /* 1065: pointer.func */
            0, 8, 0, /* 1068: pointer.func */
            0, 0, 0, /* 1071: func */
            0, 0, 0, /* 1074: func */
            0, 0, 0, /* 1077: func */
            0, 8, 0, /* 1080: pointer.func */
            0, 8, 0, /* 1083: pointer.func */
            0, 8, 0, /* 1086: long */
            0, 56, 2, /* 1089: struct.X509_VERIFY_PARAM_st */
            	37, 0,
            	254, 48,
            1, 8, 1, /* 1096: pointer.struct.X509_VERIFY_PARAM_st */
            	1089, 0,
            0, 144, 4, /* 1101: struct.x509_store_st */
            	254, 8,
            	254, 16,
            	1096, 24,
            	470, 120,
            1, 8, 1, /* 1112: pointer.struct.x509_store_st */
            	1101, 0,
            0, 0, 0, /* 1117: func */
            0, 8, 0, /* 1120: pointer.func */
            0, 8, 0, /* 1123: pointer.func */
            0, 8, 0, /* 1126: pointer.func */
            0, 0, 0, /* 1129: func */
            0, 8, 0, /* 1132: pointer.func */
            0, 8, 0, /* 1135: pointer.func */
            0, 0, 0, /* 1138: func */
            0, 8, 0, /* 1141: pointer.func */
            0, 8, 0, /* 1144: pointer.func */
            0, 0, 0, /* 1147: func */
            0, 8, 0, /* 1150: pointer.func */
            0, 8, 0, /* 1153: pointer.func */
            0, 736, 30, /* 1156: struct.ssl_ctx_st.922 */
            	1219, 0,
            	254, 8,
            	254, 16,
            	1112, 24,
            	1027, 32,
            	1241, 48,
            	1241, 56,
            	37, 160,
            	37, 176,
            	470, 208,
            	550, 224,
            	550, 232,
            	550, 240,
            	254, 248,
            	254, 256,
            	254, 272,
            	772, 304,
            	37, 328,
            	1096, 392,
            	348, 408,
            	37, 424,
            	37, 496,
            	37, 512,
            	37, 520,
            	1282, 552,
            	1282, 560,
            	12, 568,
            	37, 704,
            	37, 720,
            	254, 728,
            1, 8, 1, /* 1219: pointer.struct.ssl_method_st.924 */
            	1224, 0,
            0, 232, 1, /* 1224: struct.ssl_method_st.924 */
            	1229, 200,
            1, 8, 1, /* 1229: pointer.struct.ssl3_enc_method.923 */
            	1234, 0,
            0, 112, 2, /* 1234: struct.ssl3_enc_method.923 */
            	37, 64,
            	37, 80,
            1, 8, 1, /* 1241: pointer.struct.ssl_session_st */
            	1246, 0,
            0, 352, 14, /* 1246: struct.ssl_session_st */
            	37, 144,
            	37, 152,
            	1277, 168,
            	127, 176,
            	813, 224,
            	254, 240,
            	470, 248,
            	1241, 264,
            	1241, 272,
            	37, 280,
            	37, 296,
            	37, 312,
            	37, 320,
            	37, 344,
            1, 8, 1, /* 1277: pointer.struct.sess_cert_st */
            	1009, 0,
            1, 8, 1, /* 1282: pointer.struct.ssl3_buf_freelist_st */
            	1287, 0,
            0, 24, 1, /* 1287: struct.ssl3_buf_freelist_st */
            	63, 16,
            0, 8, 0, /* 1292: pointer.func */
            0, 0, 0, /* 1295: func */
            1, 8, 1, /* 1298: pointer.struct.ssl_ctx_st.922 */
            	1156, 0,
            0, 0, 0, /* 1303: func */
            0, 0, 0, /* 1306: func */
            0, 8, 0, /* 1309: pointer.func */
            0, 0, 0, /* 1312: func */
            0, 0, 0, /* 1315: func */
            0, 8, 0, /* 1318: pointer.func */
            0, 8, 0, /* 1321: pointer.func */
            0, 0, 0, /* 1324: func */
            0, 0, 0, /* 1327: func */
            0, 8, 0, /* 1330: pointer.func */
            0, 8, 0, /* 1333: pointer.func */
            0, 0, 0, /* 1336: func */
            0, 24, 0, /* 1339: array[6].int */
            0, 0, 0, /* 1342: func */
            0, 8, 0, /* 1345: pointer.func */
            0, 8, 0, /* 1348: pointer.func */
            0, 8, 0, /* 1351: pointer.func */
            0, 8, 0, /* 1354: pointer.func */
            0, 0, 0, /* 1357: func */
            0, 8, 0, /* 1360: pointer.func */
            0, 8, 0, /* 1363: pointer.func */
            0, 0, 0, /* 1366: func */
            0, 0, 0, /* 1369: func */
            0, 0, 0, /* 1372: func */
            0, 0, 0, /* 1375: func */
            0, 8, 0, /* 1378: pointer.func */
            0, 0, 0, /* 1381: func */
            0, 0, 0, /* 1384: func */
            0, 0, 0, /* 1387: func */
            0, 8, 0, /* 1390: pointer.func */
            0, 0, 0, /* 1393: func */
            0, 0, 0, /* 1396: func */
            0, 0, 0, /* 1399: func */
            0, 8, 0, /* 1402: pointer.func */
            0, 0, 0, /* 1405: func */
            0, 0, 0, /* 1408: func */
            0, 0, 0, /* 1411: func */
            0, 0, 0, /* 1414: func */
            0, 0, 0, /* 1417: func */
            0, 32, 0, /* 1420: array[32].char */
            0, 0, 0, /* 1423: func */
            0, 0, 0, /* 1426: func */
            0, 8, 0, /* 1429: pointer.func */
            0, 0, 0, /* 1432: func */
            0, 0, 0, /* 1435: func */
            0, 48, 0, /* 1438: array[48].char */
            0, 8, 0, /* 1441: pointer.func */
            0, 8, 0, /* 1444: array[8].char */
            0, 8, 0, /* 1447: pointer.func */
            0, 0, 0, /* 1450: func */
            0, 0, 0, /* 1453: func */
            0, 8, 0, /* 1456: pointer.func */
            0, 0, 0, /* 1459: func */
            0, 0, 0, /* 1462: func */
            0, 8, 0, /* 1465: pointer.func */
            0, 8, 0, /* 1468: pointer.func */
            0, 8, 0, /* 1471: pointer.func */
            0, 8, 0, /* 1474: pointer.func */
            0, 0, 0, /* 1477: func */
            0, 0, 0, /* 1480: func */
            0, 0, 0, /* 1483: func */
            0, 8, 0, /* 1486: pointer.func */
            0, 0, 0, /* 1489: func */
            0, 0, 0, /* 1492: func */
            0, 8, 0, /* 1495: pointer.func */
            0, 0, 0, /* 1498: func */
            0, 0, 0, /* 1501: func */
            0, 0, 0, /* 1504: func */
            0, 8, 0, /* 1507: pointer.func */
            0, 8, 0, /* 1510: pointer.func */
            0, 0, 0, /* 1513: func */
            0, 8, 0, /* 1516: pointer.func */
            0, 8, 0, /* 1519: pointer.func */
            0, 8, 0, /* 1522: pointer.func */
            0, 8, 0, /* 1525: pointer.func */
            0, 8, 0, /* 1528: pointer.func */
            0, 0, 0, /* 1531: func */
            0, 0, 0, /* 1534: func */
            0, 20, 0, /* 1537: array[20].char */
            0, 8, 0, /* 1540: pointer.func */
            0, 8, 0, /* 1543: pointer.func */
            0, 0, 0, /* 1546: func */
            0, 0, 0, /* 1549: func */
            0, 8, 0, /* 1552: pointer.func */
            0, 8, 0, /* 1555: pointer.func */
            0, 0, 0, /* 1558: func */
            0, 0, 0, /* 1561: func */
            0, 0, 0, /* 1564: func */
            0, 8, 0, /* 1567: pointer.func */
            0, 8, 0, /* 1570: pointer.func */
            0, 0, 0, /* 1573: func */
            0, 8, 0, /* 1576: pointer.func */
            0, 0, 0, /* 1579: func */
            0, 0, 0, /* 1582: func */
            0, 0, 0, /* 1585: func */
            0, 8, 0, /* 1588: pointer.func */
            0, 8, 0, /* 1591: pointer.func */
            0, 8, 0, /* 1594: pointer.func */
            0, 0, 0, /* 1597: func */
            0, 8, 0, /* 1600: pointer.func */
            0, 8, 0, /* 1603: pointer.func */
            0, 0, 0, /* 1606: func */
            0, 8, 0, /* 1609: pointer.func */
            0, 0, 0, /* 1612: func */
            0, 0, 0, /* 1615: func */
            0, 8, 0, /* 1618: pointer.func */
            0, 0, 0, /* 1621: func */
            0, 8, 0, /* 1624: pointer.func */
            0, 0, 0, /* 1627: func */
            0, 8, 0, /* 1630: pointer.func */
            0, 8, 0, /* 1633: pointer.func */
            0, 0, 0, /* 1636: func */
            0, 8, 0, /* 1639: pointer.func */
            0, 0, 0, /* 1642: func */
            0, 0, 0, /* 1645: func */
            0, 8, 0, /* 1648: pointer.func */
            0, 0, 0, /* 1651: func */
            0, 0, 0, /* 1654: func */
            0, 0, 0, /* 1657: func */
            0, 8, 0, /* 1660: pointer.func */
            0, 8, 0, /* 1663: pointer.func */
            0, 0, 0, /* 1666: func */
            0, 0, 0, /* 1669: func */
            0, 8, 0, /* 1672: pointer.func */
            0, 0, 0, /* 1675: func */
            0, 8, 0, /* 1678: pointer.func */
            0, 0, 0, /* 1681: func */
            0, 8, 0, /* 1684: pointer.func */
            0, 0, 0, /* 1687: func */
            0, 0, 0, /* 1690: func */
            0, 0, 0, /* 1693: func */
            0, 8, 0, /* 1696: pointer.func */
            0, 8, 0, /* 1699: pointer.func */
            0, 8, 0, /* 1702: pointer.func */
            0, 8, 0, /* 1705: pointer.func */
            0, 8, 0, /* 1708: pointer.func */
            0, 8, 0, /* 1711: pointer.func */
            0, 8, 0, /* 1714: pointer.func */
            0, 0, 0, /* 1717: func */
            0, 8, 0, /* 1720: pointer.func */
            0, 0, 0, /* 1723: func */
            0, 0, 0, /* 1726: func */
            0, 0, 0, /* 1729: func */
            0, 0, 0, /* 1732: func */
            0, 0, 0, /* 1735: func */
            0, 8, 0, /* 1738: pointer.func */
            0, 8, 0, /* 1741: pointer.func */
        },
        .arg_entity_index = { 1298, 807, },
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

