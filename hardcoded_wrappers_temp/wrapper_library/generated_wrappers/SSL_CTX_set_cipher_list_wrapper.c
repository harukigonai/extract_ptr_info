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

int bb_SSL_CTX_set_cipher_list(SSL_CTX * arg_a,const char * arg_b);

int SSL_CTX_set_cipher_list(SSL_CTX * arg_a,const char * arg_b) 
{
    printf("SSL_CTX_set_cipher_list called\n");
    if (!syscall(890))
        return bb_SSL_CTX_set_cipher_list(arg_a,arg_b);
    else {
        int (*orig_SSL_CTX_set_cipher_list)(SSL_CTX *,const char *);
        orig_SSL_CTX_set_cipher_list = dlsym(RTLD_NEXT, "SSL_CTX_set_cipher_list");
        return orig_SSL_CTX_set_cipher_list(arg_a,arg_b);
    }
}

int bb_SSL_CTX_set_cipher_list(SSL_CTX * arg_a,const char * arg_b) 
{
    int ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 0, 0, /* 0: func */
            0, 8, 0, /* 3: pointer.func */
            0, 0, 0, /* 6: func */
            0, 8, 0, /* 9: pointer.func */
            0, 0, 0, /* 12: func */
            0, 8, 0, /* 15: pointer.func */
            0, 0, 0, /* 18: func */
            0, 8, 0, /* 21: pointer.func */
            0, 0, 0, /* 24: func */
            0, 8, 0, /* 27: pointer.func */
            0, 0, 0, /* 30: func */
            0, 8, 0, /* 33: pointer.func */
            0, 16, 0, /* 36: array[16].char */
            0, 0, 0, /* 39: func */
            0, 0, 0, /* 42: func */
            0, 8, 0, /* 45: pointer.func */
            0, 0, 0, /* 48: func */
            0, 8, 0, /* 51: pointer.func */
            1, 8, 1, /* 54: pointer.struct.ssl3_buf_freelist_entry_st */
            	59, 0,
            0, 8, 1, /* 59: struct.ssl3_buf_freelist_entry_st */
            	54, 0,
            0, 0, 0, /* 64: func */
            0, 8, 0, /* 67: pointer.func */
            0, 296, 5, /* 70: struct.cert_st.745 */
            	83, 0,
            	536, 48,
            	635, 64,
            	667, 80,
            	749, 96,
            1, 8, 1, /* 83: pointer.struct.cert_pkey_st */
            	88, 0,
            0, 24, 3, /* 88: struct.cert_pkey_st */
            	97, 0,
            	288, 8,
            	528, 16,
            1, 8, 1, /* 97: pointer.struct.x509_st */
            	102, 0,
            0, 184, 12, /* 102: struct.x509_st */
            	129, 0,
            	177, 8,
            	159, 16,
            	169, 32,
            	448, 40,
            	159, 104,
            	458, 112,
            	472, 120,
            	232, 128,
            	232, 136,
            	498, 144,
            	510, 176,
            1, 8, 1, /* 129: pointer.struct.x509_cinf_st */
            	134, 0,
            0, 104, 11, /* 134: struct.x509_cinf_st */
            	159, 0,
            	159, 8,
            	177, 16,
            	218, 24,
            	262, 32,
            	218, 40,
            	274, 48,
            	159, 56,
            	159, 64,
            	232, 72,
            	453, 80,
            1, 8, 1, /* 159: pointer.struct.asn1_string_st */
            	164, 0,
            0, 24, 1, /* 164: struct.asn1_string_st */
            	169, 8,
            1, 8, 1, /* 169: pointer.char */
            	174, 0,
            0, 1, 0, /* 174: char */
            1, 8, 1, /* 177: pointer.struct.X509_algor_st */
            	182, 0,
            0, 16, 2, /* 182: struct.X509_algor_st */
            	189, 0,
            	203, 8,
            1, 8, 1, /* 189: pointer.struct.asn1_object_st */
            	194, 0,
            0, 40, 3, /* 194: struct.asn1_object_st */
            	169, 0,
            	169, 8,
            	169, 24,
            1, 8, 1, /* 203: pointer.struct.asn1_type_st */
            	208, 0,
            0, 16, 1, /* 208: struct.asn1_type_st */
            	213, 8,
            0, 8, 1, /* 213: struct.fnames */
            	169, 0,
            1, 8, 1, /* 218: pointer.struct.X509_name_st */
            	223, 0,
            0, 40, 3, /* 223: struct.X509_name_st */
            	232, 0,
            	252, 16,
            	169, 24,
            1, 8, 1, /* 232: pointer.struct.stack_st_OPENSSL_STRING */
            	237, 0,
            0, 32, 1, /* 237: struct.stack_st_OPENSSL_STRING */
            	242, 0,
            0, 32, 1, /* 242: struct.stack_st */
            	247, 8,
            1, 8, 1, /* 247: pointer.pointer.char */
            	169, 0,
            1, 8, 1, /* 252: pointer.struct.buf_mem_st */
            	257, 0,
            0, 24, 1, /* 257: struct.buf_mem_st */
            	169, 8,
            1, 8, 1, /* 262: pointer.struct.X509_val_st */
            	267, 0,
            0, 16, 2, /* 267: struct.X509_val_st */
            	159, 0,
            	159, 8,
            1, 8, 1, /* 274: pointer.struct.X509_pubkey_st */
            	279, 0,
            0, 24, 3, /* 279: struct.X509_pubkey_st */
            	177, 0,
            	159, 8,
            	288, 16,
            1, 8, 1, /* 288: pointer.struct.evp_pkey_st */
            	293, 0,
            0, 56, 4, /* 293: struct.evp_pkey_st */
            	304, 16,
            	326, 24,
            	213, 32,
            	232, 48,
            1, 8, 1, /* 304: pointer.struct.evp_pkey_asn1_method_st */
            	309, 0,
            0, 208, 3, /* 309: struct.evp_pkey_asn1_method_st */
            	169, 16,
            	169, 24,
            	318, 32,
            1, 8, 1, /* 318: pointer.struct.unnamed */
            	323, 0,
            0, 0, 0, /* 323: struct.unnamed */
            1, 8, 1, /* 326: pointer.struct.engine_st */
            	331, 0,
            0, 216, 13, /* 331: struct.engine_st */
            	169, 0,
            	169, 8,
            	360, 16,
            	372, 24,
            	384, 32,
            	396, 40,
            	408, 48,
            	420, 56,
            	428, 64,
            	436, 160,
            	448, 184,
            	326, 200,
            	326, 208,
            1, 8, 1, /* 360: pointer.struct.rsa_meth_st */
            	365, 0,
            0, 112, 2, /* 365: struct.rsa_meth_st */
            	169, 0,
            	169, 80,
            1, 8, 1, /* 372: pointer.struct.dsa_method.1040 */
            	377, 0,
            0, 96, 2, /* 377: struct.dsa_method.1040 */
            	169, 0,
            	169, 72,
            1, 8, 1, /* 384: pointer.struct.dh_method */
            	389, 0,
            0, 72, 2, /* 389: struct.dh_method */
            	169, 0,
            	169, 56,
            1, 8, 1, /* 396: pointer.struct.ecdh_method */
            	401, 0,
            0, 32, 2, /* 401: struct.ecdh_method */
            	169, 0,
            	169, 24,
            1, 8, 1, /* 408: pointer.struct.ecdsa_method */
            	413, 0,
            0, 48, 2, /* 413: struct.ecdsa_method */
            	169, 0,
            	169, 40,
            1, 8, 1, /* 420: pointer.struct.rand_meth_st */
            	425, 0,
            0, 48, 0, /* 425: struct.rand_meth_st */
            1, 8, 1, /* 428: pointer.struct.store_method_st */
            	433, 0,
            0, 0, 0, /* 433: struct.store_method_st */
            1, 8, 1, /* 436: pointer.struct.ENGINE_CMD_DEFN_st */
            	441, 0,
            0, 32, 2, /* 441: struct.ENGINE_CMD_DEFN_st */
            	169, 8,
            	169, 16,
            0, 16, 1, /* 448: struct.crypto_ex_data_st */
            	232, 0,
            0, 24, 1, /* 453: struct.ASN1_ENCODING_st */
            	169, 0,
            1, 8, 1, /* 458: pointer.struct.AUTHORITY_KEYID_st */
            	463, 0,
            0, 24, 3, /* 463: struct.AUTHORITY_KEYID_st */
            	159, 0,
            	232, 8,
            	159, 16,
            1, 8, 1, /* 472: pointer.struct.X509_POLICY_CACHE_st */
            	477, 0,
            0, 40, 2, /* 477: struct.X509_POLICY_CACHE_st */
            	484, 0,
            	232, 8,
            1, 8, 1, /* 484: pointer.struct.X509_POLICY_DATA_st */
            	489, 0,
            0, 32, 3, /* 489: struct.X509_POLICY_DATA_st */
            	189, 8,
            	232, 16,
            	232, 24,
            1, 8, 1, /* 498: pointer.struct.NAME_CONSTRAINTS_st */
            	503, 0,
            0, 16, 2, /* 503: struct.NAME_CONSTRAINTS_st */
            	232, 0,
            	232, 8,
            1, 8, 1, /* 510: pointer.struct.x509_cert_aux_st */
            	515, 0,
            0, 40, 5, /* 515: struct.x509_cert_aux_st */
            	232, 0,
            	232, 8,
            	159, 16,
            	159, 24,
            	232, 32,
            1, 8, 1, /* 528: pointer.struct.env_md_st */
            	533, 0,
            0, 120, 0, /* 533: struct.env_md_st */
            1, 8, 1, /* 536: pointer.struct.rsa_st */
            	541, 0,
            0, 168, 17, /* 541: struct.rsa_st */
            	360, 16,
            	326, 24,
            	578, 32,
            	578, 40,
            	578, 48,
            	578, 56,
            	578, 64,
            	578, 72,
            	578, 80,
            	578, 88,
            	448, 96,
            	596, 120,
            	596, 128,
            	596, 136,
            	169, 144,
            	610, 152,
            	610, 160,
            1, 8, 1, /* 578: pointer.struct.bignum_st */
            	583, 0,
            0, 24, 1, /* 583: struct.bignum_st */
            	588, 0,
            1, 8, 1, /* 588: pointer.int */
            	593, 0,
            0, 4, 0, /* 593: int */
            1, 8, 1, /* 596: pointer.struct.bn_mont_ctx_st */
            	601, 0,
            0, 96, 3, /* 601: struct.bn_mont_ctx_st */
            	583, 8,
            	583, 32,
            	583, 56,
            1, 8, 1, /* 610: pointer.struct.bn_blinding_st */
            	615, 0,
            0, 88, 6, /* 615: struct.bn_blinding_st */
            	578, 0,
            	578, 8,
            	578, 16,
            	578, 24,
            	630, 40,
            	596, 72,
            0, 16, 1, /* 630: struct.iovec */
            	169, 0,
            1, 8, 1, /* 635: pointer.struct.dh_st */
            	640, 0,
            0, 144, 12, /* 640: struct.dh_st */
            	578, 8,
            	578, 16,
            	578, 32,
            	578, 40,
            	596, 56,
            	578, 64,
            	578, 72,
            	169, 80,
            	578, 96,
            	448, 112,
            	384, 128,
            	326, 136,
            1, 8, 1, /* 667: pointer.struct.ec_key_st.284 */
            	672, 0,
            0, 56, 4, /* 672: struct.ec_key_st.284 */
            	683, 8,
            	721, 16,
            	578, 24,
            	737, 48,
            1, 8, 1, /* 683: pointer.struct.ec_group_st */
            	688, 0,
            0, 232, 11, /* 688: struct.ec_group_st */
            	713, 0,
            	721, 8,
            	583, 16,
            	583, 40,
            	169, 80,
            	737, 96,
            	583, 104,
            	583, 152,
            	583, 176,
            	169, 208,
            	169, 216,
            1, 8, 1, /* 713: pointer.struct.ec_method_st */
            	718, 0,
            0, 304, 0, /* 718: struct.ec_method_st */
            1, 8, 1, /* 721: pointer.struct.ec_point_st */
            	726, 0,
            0, 88, 4, /* 726: struct.ec_point_st */
            	713, 0,
            	583, 8,
            	583, 32,
            	583, 56,
            1, 8, 1, /* 737: pointer.struct.ec_extra_data_st */
            	742, 0,
            0, 40, 2, /* 742: struct.ec_extra_data_st */
            	737, 0,
            	169, 8,
            0, 192, 8, /* 749: array[8].struct.cert_pkey_st */
            	88, 0,
            	88, 24,
            	88, 48,
            	88, 72,
            	88, 96,
            	88, 120,
            	88, 144,
            	88, 168,
            1, 8, 1, /* 768: pointer.struct.cert_st.745 */
            	70, 0,
            0, 0, 0, /* 773: func */
            0, 8, 0, /* 776: pointer.func */
            0, 0, 0, /* 779: func */
            0, 8, 0, /* 782: pointer.func */
            0, 44, 0, /* 785: struct.apr_time_exp_t */
            0, 0, 0, /* 788: func */
            0, 8, 0, /* 791: pointer.func */
            1, 8, 1, /* 794: pointer.struct.ssl_cipher_st */
            	799, 0,
            0, 88, 1, /* 799: struct.ssl_cipher_st */
            	169, 8,
            0, 24, 0, /* 804: array[6].int */
            0, 8, 0, /* 807: pointer.func */
            0, 0, 0, /* 810: func */
            0, 8, 0, /* 813: pointer.func */
            0, 0, 0, /* 816: func */
            0, 8, 0, /* 819: pointer.func */
            0, 0, 0, /* 822: func */
            0, 0, 0, /* 825: func */
            0, 8, 0, /* 828: pointer.func */
            0, 8, 0, /* 831: pointer.func */
            0, 0, 0, /* 834: func */
            0, 0, 0, /* 837: func */
            0, 8, 0, /* 840: pointer.func */
            0, 0, 0, /* 843: func */
            0, 0, 0, /* 846: func */
            0, 8, 0, /* 849: pointer.func */
            0, 0, 0, /* 852: func */
            0, 8, 0, /* 855: pointer.func */
            0, 0, 0, /* 858: func */
            0, 8, 0, /* 861: pointer.func */
            0, 8, 0, /* 864: pointer.func */
            0, 0, 0, /* 867: func */
            0, 8, 0, /* 870: pointer.func */
            0, 8, 0, /* 873: pointer.func */
            0, 0, 0, /* 876: func */
            0, 8, 0, /* 879: pointer.func */
            0, 0, 0, /* 882: func */
            0, 0, 0, /* 885: func */
            0, 0, 0, /* 888: func */
            0, 8, 0, /* 891: pointer.func */
            0, 0, 0, /* 894: func */
            0, 8, 0, /* 897: pointer.func */
            0, 8, 0, /* 900: pointer.func */
            0, 8, 0, /* 903: pointer.func */
            0, 8, 0, /* 906: array[2].int */
            0, 8, 0, /* 909: pointer.func */
            0, 0, 0, /* 912: func */
            0, 0, 0, /* 915: func */
            0, 8, 0, /* 918: pointer.func */
            0, 0, 0, /* 921: func */
            0, 0, 0, /* 924: func */
            0, 8, 0, /* 927: pointer.func */
            0, 0, 0, /* 930: func */
            0, 8, 0, /* 933: pointer.func */
            0, 0, 0, /* 936: func */
            0, 0, 0, /* 939: func */
            0, 4, 0, /* 942: struct.in_addr */
            0, 8, 0, /* 945: pointer.func */
            0, 8, 0, /* 948: pointer.func */
            0, 0, 0, /* 951: func */
            0, 8, 0, /* 954: pointer.func */
            0, 8, 0, /* 957: pointer.func */
            0, 0, 0, /* 960: func */
            0, 8, 0, /* 963: pointer.func */
            0, 8, 0, /* 966: pointer.func */
            0, 0, 0, /* 969: func */
            0, 248, 6, /* 972: struct.sess_cert_st */
            	232, 0,
            	83, 16,
            	749, 24,
            	536, 216,
            	635, 224,
            	667, 232,
            0, 0, 0, /* 987: func */
            0, 0, 0, /* 990: func */
            0, 8, 0, /* 993: pointer.func */
            0, 8, 0, /* 996: pointer.func */
            0, 8, 0, /* 999: pointer.func */
            0, 0, 0, /* 1002: func */
            0, 8, 0, /* 1005: pointer.func */
            0, 8, 0, /* 1008: pointer.func */
            0, 8, 0, /* 1011: pointer.func */
            0, 8, 0, /* 1014: pointer.func */
            0, 8, 0, /* 1017: pointer.func */
            0, 8, 0, /* 1020: pointer.func */
            0, 0, 0, /* 1023: func */
            0, 8, 0, /* 1026: pointer.func */
            0, 56, 2, /* 1029: struct.X509_VERIFY_PARAM_st */
            	169, 0,
            	232, 48,
            1, 8, 1, /* 1036: pointer.struct.X509_VERIFY_PARAM_st */
            	1029, 0,
            0, 0, 0, /* 1041: func */
            0, 24, 1, /* 1044: struct.ssl3_buf_freelist_st */
            	54, 16,
            0, 8, 0, /* 1049: long */
            0, 0, 0, /* 1052: func */
            0, 8, 0, /* 1055: pointer.func */
            0, 8, 0, /* 1058: pointer.func */
            0, 0, 0, /* 1061: func */
            0, 8, 0, /* 1064: pointer.func */
            0, 8, 0, /* 1067: pointer.func */
            0, 8, 0, /* 1070: pointer.func */
            0, 352, 14, /* 1073: struct.ssl_session_st */
            	169, 144,
            	169, 152,
            	1104, 168,
            	97, 176,
            	794, 224,
            	232, 240,
            	448, 248,
            	1109, 264,
            	1109, 272,
            	169, 280,
            	169, 296,
            	169, 312,
            	169, 320,
            	169, 344,
            1, 8, 1, /* 1104: pointer.struct.sess_cert_st */
            	972, 0,
            1, 8, 1, /* 1109: pointer.struct.ssl_session_st */
            	1073, 0,
            0, 0, 0, /* 1114: func */
            1, 8, 1, /* 1117: pointer.struct.ssl3_enc_method.753 */
            	1122, 0,
            0, 112, 4, /* 1122: struct.ssl3_enc_method.753 */
            	318, 0,
            	318, 32,
            	169, 64,
            	169, 80,
            0, 0, 0, /* 1133: func */
            0, 736, 30, /* 1136: struct.ssl_ctx_st.752 */
            	1199, 0,
            	232, 8,
            	232, 16,
            	1209, 24,
            	1225, 32,
            	1109, 48,
            	1109, 56,
            	169, 160,
            	169, 176,
            	448, 208,
            	528, 224,
            	528, 232,
            	528, 240,
            	232, 248,
            	232, 256,
            	232, 272,
            	768, 304,
            	169, 328,
            	1036, 392,
            	326, 408,
            	169, 424,
            	169, 496,
            	169, 512,
            	169, 520,
            	1230, 552,
            	1230, 560,
            	1235, 568,
            	169, 704,
            	169, 720,
            	232, 728,
            1, 8, 1, /* 1199: pointer.struct.ssl_method_st.754 */
            	1204, 0,
            0, 232, 1, /* 1204: struct.ssl_method_st.754 */
            	1117, 200,
            1, 8, 1, /* 1209: pointer.struct.x509_store_st */
            	1214, 0,
            0, 144, 4, /* 1214: struct.x509_store_st */
            	232, 8,
            	232, 16,
            	1036, 24,
            	448, 120,
            1, 8, 1, /* 1225: pointer.struct.in_addr */
            	942, 0,
            1, 8, 1, /* 1230: pointer.struct.ssl3_buf_freelist_st */
            	1044, 0,
            0, 128, 11, /* 1235: struct.srp_ctx_st.751 */
            	169, 0,
            	169, 32,
            	578, 40,
            	578, 48,
            	578, 56,
            	578, 64,
            	578, 72,
            	578, 80,
            	578, 88,
            	578, 96,
            	169, 104,
            0, 0, 0, /* 1260: func */
            0, 8, 0, /* 1263: pointer.func */
            0, 0, 0, /* 1266: func */
            1, 8, 1, /* 1269: pointer.struct.ssl_ctx_st.752 */
            	1136, 0,
            0, 0, 0, /* 1274: func */
            0, 8, 0, /* 1277: pointer.func */
            0, 8, 0, /* 1280: pointer.func */
            0, 8, 0, /* 1283: pointer.func */
            0, 0, 0, /* 1286: func */
            0, 0, 0, /* 1289: func */
            0, 8, 0, /* 1292: pointer.func */
            0, 0, 0, /* 1295: func */
            0, 8, 0, /* 1298: pointer.func */
            0, 8, 0, /* 1301: pointer.func */
            0, 0, 0, /* 1304: func */
            0, 0, 0, /* 1307: func */
            0, 8, 0, /* 1310: pointer.func */
            0, 8, 0, /* 1313: pointer.func */
            0, 8, 0, /* 1316: pointer.func */
            0, 0, 0, /* 1319: func */
            0, 20, 0, /* 1322: array[5].int */
            0, 0, 0, /* 1325: func */
            0, 8, 0, /* 1328: pointer.func */
            0, 0, 0, /* 1331: func */
            0, 0, 0, /* 1334: func */
            0, 0, 0, /* 1337: func */
            0, 8, 0, /* 1340: pointer.func */
            0, 0, 0, /* 1343: func */
            0, 8, 0, /* 1346: pointer.func */
            0, 8, 0, /* 1349: pointer.func */
            0, 8, 0, /* 1352: pointer.func */
            0, 0, 0, /* 1355: func */
            0, 8, 0, /* 1358: pointer.func */
            0, 0, 0, /* 1361: func */
            0, 8, 0, /* 1364: pointer.func */
            0, 0, 0, /* 1367: func */
            0, 0, 0, /* 1370: func */
            0, 0, 0, /* 1373: func */
            0, 8, 0, /* 1376: pointer.func */
            0, 8, 0, /* 1379: pointer.func */
            0, 0, 0, /* 1382: func */
            0, 8, 0, /* 1385: pointer.func */
            0, 0, 0, /* 1388: func */
            0, 0, 0, /* 1391: func */
            0, 0, 0, /* 1394: func */
            0, 0, 0, /* 1397: func */
            0, 8, 0, /* 1400: pointer.func */
            0, 8, 0, /* 1403: pointer.func */
            0, 0, 0, /* 1406: func */
            0, 8, 0, /* 1409: pointer.func */
            0, 0, 0, /* 1412: func */
            0, 0, 0, /* 1415: func */
            0, 8, 0, /* 1418: pointer.func */
            0, 0, 0, /* 1421: func */
            0, 0, 0, /* 1424: func */
            0, 8, 0, /* 1427: pointer.func */
            0, 0, 0, /* 1430: func */
            0, 8, 0, /* 1433: pointer.func */
            0, 8, 0, /* 1436: pointer.func */
            0, 8, 0, /* 1439: pointer.func */
            0, 0, 0, /* 1442: func */
            0, 0, 0, /* 1445: func */
            0, 8, 0, /* 1448: pointer.func */
            0, 8, 0, /* 1451: pointer.func */
            0, 8, 0, /* 1454: array[8].char */
            0, 0, 0, /* 1457: func */
            0, 32, 0, /* 1460: array[32].char */
            0, 8, 0, /* 1463: pointer.func */
            0, 8, 0, /* 1466: pointer.func */
            0, 8, 0, /* 1469: pointer.func */
            0, 8, 0, /* 1472: pointer.func */
            0, 8, 0, /* 1475: pointer.func */
            0, 8, 0, /* 1478: pointer.func */
            0, 0, 0, /* 1481: func */
            0, 8, 0, /* 1484: pointer.func */
            0, 8, 0, /* 1487: pointer.func */
            0, 8, 0, /* 1490: pointer.func */
            0, 0, 0, /* 1493: func */
            0, 0, 0, /* 1496: func */
            0, 0, 0, /* 1499: func */
            0, 8, 0, /* 1502: pointer.func */
            0, 0, 0, /* 1505: func */
            0, 0, 0, /* 1508: func */
            0, 0, 0, /* 1511: func */
            0, 0, 0, /* 1514: func */
            0, 8, 0, /* 1517: pointer.func */
            0, 0, 0, /* 1520: func */
            0, 0, 0, /* 1523: func */
            0, 0, 0, /* 1526: func */
            0, 8, 0, /* 1529: pointer.func */
            0, 48, 0, /* 1532: array[48].char */
            0, 0, 0, /* 1535: func */
            0, 0, 0, /* 1538: func */
            0, 8, 0, /* 1541: pointer.func */
            0, 8, 0, /* 1544: pointer.func */
            0, 8, 0, /* 1547: pointer.func */
            0, 0, 0, /* 1550: func */
            0, 0, 0, /* 1553: func */
            0, 20, 0, /* 1556: array[20].char */
            0, 8, 0, /* 1559: pointer.func */
            0, 8, 0, /* 1562: pointer.func */
            0, 0, 0, /* 1565: func */
            0, 0, 0, /* 1568: func */
            0, 8, 0, /* 1571: pointer.func */
            0, 8, 0, /* 1574: pointer.func */
            0, 0, 0, /* 1577: func */
            0, 0, 0, /* 1580: func */
            0, 0, 0, /* 1583: func */
            0, 8, 0, /* 1586: pointer.func */
            0, 8, 0, /* 1589: pointer.func */
            0, 0, 0, /* 1592: func */
            0, 8, 0, /* 1595: pointer.func */
            0, 0, 0, /* 1598: func */
            0, 0, 0, /* 1601: func */
            0, 0, 0, /* 1604: func */
            0, 8, 0, /* 1607: pointer.func */
            0, 8, 0, /* 1610: pointer.func */
            0, 8, 0, /* 1613: pointer.func */
            0, 0, 0, /* 1616: func */
            0, 0, 0, /* 1619: func */
            0, 8, 0, /* 1622: pointer.func */
            0, 0, 0, /* 1625: func */
            0, 8, 0, /* 1628: pointer.func */
            0, 0, 0, /* 1631: func */
            0, 8, 0, /* 1634: pointer.func */
            0, 8, 0, /* 1637: pointer.func */
            0, 0, 0, /* 1640: func */
            0, 0, 0, /* 1643: func */
            0, 8, 0, /* 1646: pointer.func */
            0, 8, 0, /* 1649: pointer.func */
            0, 0, 0, /* 1652: func */
            0, 0, 0, /* 1655: func */
            0, 0, 0, /* 1658: func */
            0, 8, 0, /* 1661: pointer.func */
            0, 8, 0, /* 1664: pointer.func */
            0, 0, 0, /* 1667: func */
            0, 8, 0, /* 1670: pointer.func */
            0, 0, 0, /* 1673: func */
            0, 8, 0, /* 1676: pointer.func */
            0, 0, 0, /* 1679: func */
            0, 0, 0, /* 1682: func */
            0, 8, 0, /* 1685: pointer.func */
            0, 8, 0, /* 1688: pointer.func */
            0, 0, 0, /* 1691: func */
            0, 8, 0, /* 1694: pointer.func */
            0, 0, 0, /* 1697: func */
            0, 8, 0, /* 1700: pointer.func */
            0, 0, 0, /* 1703: func */
            0, 8, 0, /* 1706: pointer.func */
            0, 8, 0, /* 1709: pointer.func */
            0, 0, 0, /* 1712: func */
            0, 0, 0, /* 1715: func */
            0, 0, 0, /* 1718: func */
            0, 8, 0, /* 1721: pointer.func */
            0, 8, 0, /* 1724: pointer.func */
            0, 0, 0, /* 1727: func */
            0, 8, 0, /* 1730: pointer.func */
            0, 0, 0, /* 1733: func */
            0, 0, 0, /* 1736: func */
            0, 0, 0, /* 1739: func */
        },
        .arg_entity_index = { 1269, 169, },
        .ret_entity_index = 593,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    SSL_CTX * new_arg_a = *((SSL_CTX * *)new_args->args[0]);

    const char * new_arg_b = *((const char * *)new_args->args[1]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_SSL_CTX_set_cipher_list)(SSL_CTX *,const char *);
    orig_SSL_CTX_set_cipher_list = dlsym(RTLD_NEXT, "SSL_CTX_set_cipher_list");
    *new_ret_ptr = (*orig_SSL_CTX_set_cipher_list)(new_arg_a,new_arg_b);

    syscall(889);

    return ret;
}

