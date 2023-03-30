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

X509 * bb_SSL_get_certificate(const SSL * arg_a);

X509 * SSL_get_certificate(const SSL * arg_a) 
{
    printf("SSL_get_certificate called\n");
    if (!syscall(890))
        return bb_SSL_get_certificate(arg_a);
    else {
        X509 * (*orig_SSL_get_certificate)(const SSL *);
        orig_SSL_get_certificate = dlsym(RTLD_NEXT, "SSL_get_certificate");
        return orig_SSL_get_certificate(arg_a);
    }
}

X509 * bb_SSL_get_certificate(const SSL * arg_a) 
{
    X509 * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 0, 0, /* 0: func */
            0, 8, 0, /* 3: pointer.func */
            0, 16, 1, /* 6: struct.tls_session_ticket_ext_st */
            	11, 8,
            1, 8, 1, /* 11: pointer.char */
            	16, 0,
            0, 1, 0, /* 16: char */
            0, 8, 0, /* 19: pointer.func */
            0, 0, 0, /* 22: func */
            0, 8, 0, /* 25: pointer.func */
            0, 0, 0, /* 28: func */
            0, 8, 0, /* 31: pointer.func */
            0, 0, 0, /* 34: func */
            0, 8, 0, /* 37: pointer.func */
            0, 0, 0, /* 40: func */
            0, 8, 0, /* 43: pointer.func */
            0, 0, 0, /* 46: func */
            0, 8, 0, /* 49: pointer.func */
            0, 0, 0, /* 52: func */
            0, 0, 0, /* 55: func */
            0, 8, 0, /* 58: pointer.func */
            0, 0, 0, /* 61: func */
            0, 8, 0, /* 64: pointer.func */
            0, 44, 0, /* 67: struct.apr_time_exp_t */
            0, 0, 0, /* 70: func */
            0, 8, 0, /* 73: pointer.func */
            0, 4, 0, /* 76: struct.in_addr */
            0, 0, 0, /* 79: func */
            0, 8, 0, /* 82: pointer.func */
            0, 8, 0, /* 85: pointer.func */
            0, 8, 0, /* 88: pointer.func */
            0, 8, 0, /* 91: pointer.func */
            0, 0, 0, /* 94: func */
            0, 8, 0, /* 97: pointer.func */
            0, 0, 0, /* 100: func */
            0, 736, 30, /* 103: struct.ssl_ctx_st.752 */
            	166, 0,
            	200, 8,
            	200, 16,
            	220, 24,
            	253, 32,
            	258, 48,
            	258, 56,
            	11, 160,
            	11, 176,
            	248, 208,
            	718, 224,
            	718, 232,
            	718, 240,
            	200, 248,
            	200, 256,
            	200, 272,
            	968, 304,
            	11, 328,
            	236, 392,
            	521, 408,
            	11, 424,
            	11, 496,
            	11, 512,
            	11, 520,
            	986, 552,
            	986, 560,
            	1006, 568,
            	11, 704,
            	11, 720,
            	200, 728,
            1, 8, 1, /* 166: pointer.struct.ssl_method_st.754 */
            	171, 0,
            0, 232, 1, /* 171: struct.ssl_method_st.754 */
            	176, 200,
            1, 8, 1, /* 176: pointer.struct.ssl3_enc_method.753 */
            	181, 0,
            0, 112, 4, /* 181: struct.ssl3_enc_method.753 */
            	192, 0,
            	192, 32,
            	11, 64,
            	11, 80,
            1, 8, 1, /* 192: pointer.struct.unnamed */
            	197, 0,
            0, 0, 0, /* 197: struct.unnamed */
            1, 8, 1, /* 200: pointer.struct.stack_st_OPENSSL_STRING */
            	205, 0,
            0, 32, 1, /* 205: struct.stack_st_OPENSSL_STRING */
            	210, 0,
            0, 32, 1, /* 210: struct.stack_st */
            	215, 8,
            1, 8, 1, /* 215: pointer.pointer.char */
            	11, 0,
            1, 8, 1, /* 220: pointer.struct.x509_store_st */
            	225, 0,
            0, 144, 4, /* 225: struct.x509_store_st */
            	200, 8,
            	200, 16,
            	236, 24,
            	248, 120,
            1, 8, 1, /* 236: pointer.struct.X509_VERIFY_PARAM_st */
            	241, 0,
            0, 56, 2, /* 241: struct.X509_VERIFY_PARAM_st */
            	11, 0,
            	200, 48,
            0, 16, 1, /* 248: struct.crypto_ex_data_st */
            	200, 0,
            1, 8, 1, /* 253: pointer.struct.in_addr */
            	76, 0,
            1, 8, 1, /* 258: pointer.struct.ssl_session_st */
            	263, 0,
            0, 352, 14, /* 263: struct.ssl_session_st */
            	11, 144,
            	11, 152,
            	294, 168,
            	328, 176,
            	958, 224,
            	200, 240,
            	248, 248,
            	258, 264,
            	258, 272,
            	11, 280,
            	11, 296,
            	11, 312,
            	11, 320,
            	11, 344,
            1, 8, 1, /* 294: pointer.struct.sess_cert_st */
            	299, 0,
            0, 248, 6, /* 299: struct.sess_cert_st */
            	200, 0,
            	314, 16,
            	726, 24,
            	745, 216,
            	844, 224,
            	876, 232,
            1, 8, 1, /* 314: pointer.struct.cert_pkey_st */
            	319, 0,
            0, 24, 3, /* 319: struct.cert_pkey_st */
            	328, 0,
            	491, 8,
            	718, 16,
            1, 8, 1, /* 328: pointer.struct.x509_st */
            	333, 0,
            0, 184, 12, /* 333: struct.x509_st */
            	360, 0,
            	400, 8,
            	390, 16,
            	11, 32,
            	248, 40,
            	390, 104,
            	648, 112,
            	662, 120,
            	200, 128,
            	200, 136,
            	688, 144,
            	700, 176,
            1, 8, 1, /* 360: pointer.struct.x509_cinf_st */
            	365, 0,
            0, 104, 11, /* 365: struct.x509_cinf_st */
            	390, 0,
            	390, 8,
            	400, 16,
            	441, 24,
            	465, 32,
            	441, 40,
            	477, 48,
            	390, 56,
            	390, 64,
            	200, 72,
            	643, 80,
            1, 8, 1, /* 390: pointer.struct.asn1_string_st */
            	395, 0,
            0, 24, 1, /* 395: struct.asn1_string_st */
            	11, 8,
            1, 8, 1, /* 400: pointer.struct.X509_algor_st */
            	405, 0,
            0, 16, 2, /* 405: struct.X509_algor_st */
            	412, 0,
            	426, 8,
            1, 8, 1, /* 412: pointer.struct.asn1_object_st */
            	417, 0,
            0, 40, 3, /* 417: struct.asn1_object_st */
            	11, 0,
            	11, 8,
            	11, 24,
            1, 8, 1, /* 426: pointer.struct.asn1_type_st */
            	431, 0,
            0, 16, 1, /* 431: struct.asn1_type_st */
            	436, 8,
            0, 8, 1, /* 436: struct.fnames */
            	11, 0,
            1, 8, 1, /* 441: pointer.struct.X509_name_st */
            	446, 0,
            0, 40, 3, /* 446: struct.X509_name_st */
            	200, 0,
            	455, 16,
            	11, 24,
            1, 8, 1, /* 455: pointer.struct.buf_mem_st */
            	460, 0,
            0, 24, 1, /* 460: struct.buf_mem_st */
            	11, 8,
            1, 8, 1, /* 465: pointer.struct.X509_val_st */
            	470, 0,
            0, 16, 2, /* 470: struct.X509_val_st */
            	390, 0,
            	390, 8,
            1, 8, 1, /* 477: pointer.struct.X509_pubkey_st */
            	482, 0,
            0, 24, 3, /* 482: struct.X509_pubkey_st */
            	400, 0,
            	390, 8,
            	491, 16,
            1, 8, 1, /* 491: pointer.struct.evp_pkey_st */
            	496, 0,
            0, 56, 4, /* 496: struct.evp_pkey_st */
            	507, 16,
            	521, 24,
            	436, 32,
            	200, 48,
            1, 8, 1, /* 507: pointer.struct.evp_pkey_asn1_method_st */
            	512, 0,
            0, 208, 3, /* 512: struct.evp_pkey_asn1_method_st */
            	11, 16,
            	11, 24,
            	192, 32,
            1, 8, 1, /* 521: pointer.struct.engine_st */
            	526, 0,
            0, 216, 13, /* 526: struct.engine_st */
            	11, 0,
            	11, 8,
            	555, 16,
            	567, 24,
            	579, 32,
            	591, 40,
            	603, 48,
            	615, 56,
            	623, 64,
            	631, 160,
            	248, 184,
            	521, 200,
            	521, 208,
            1, 8, 1, /* 555: pointer.struct.rsa_meth_st */
            	560, 0,
            0, 112, 2, /* 560: struct.rsa_meth_st */
            	11, 0,
            	11, 80,
            1, 8, 1, /* 567: pointer.struct.dsa_method.1040 */
            	572, 0,
            0, 96, 2, /* 572: struct.dsa_method.1040 */
            	11, 0,
            	11, 72,
            1, 8, 1, /* 579: pointer.struct.dh_method */
            	584, 0,
            0, 72, 2, /* 584: struct.dh_method */
            	11, 0,
            	11, 56,
            1, 8, 1, /* 591: pointer.struct.ecdh_method */
            	596, 0,
            0, 32, 2, /* 596: struct.ecdh_method */
            	11, 0,
            	11, 24,
            1, 8, 1, /* 603: pointer.struct.ecdsa_method */
            	608, 0,
            0, 48, 2, /* 608: struct.ecdsa_method */
            	11, 0,
            	11, 40,
            1, 8, 1, /* 615: pointer.struct.rand_meth_st */
            	620, 0,
            0, 48, 0, /* 620: struct.rand_meth_st */
            1, 8, 1, /* 623: pointer.struct.store_method_st */
            	628, 0,
            0, 0, 0, /* 628: struct.store_method_st */
            1, 8, 1, /* 631: pointer.struct.ENGINE_CMD_DEFN_st */
            	636, 0,
            0, 32, 2, /* 636: struct.ENGINE_CMD_DEFN_st */
            	11, 8,
            	11, 16,
            0, 24, 1, /* 643: struct.ASN1_ENCODING_st */
            	11, 0,
            1, 8, 1, /* 648: pointer.struct.AUTHORITY_KEYID_st */
            	653, 0,
            0, 24, 3, /* 653: struct.AUTHORITY_KEYID_st */
            	390, 0,
            	200, 8,
            	390, 16,
            1, 8, 1, /* 662: pointer.struct.X509_POLICY_CACHE_st */
            	667, 0,
            0, 40, 2, /* 667: struct.X509_POLICY_CACHE_st */
            	674, 0,
            	200, 8,
            1, 8, 1, /* 674: pointer.struct.X509_POLICY_DATA_st */
            	679, 0,
            0, 32, 3, /* 679: struct.X509_POLICY_DATA_st */
            	412, 8,
            	200, 16,
            	200, 24,
            1, 8, 1, /* 688: pointer.struct.NAME_CONSTRAINTS_st */
            	693, 0,
            0, 16, 2, /* 693: struct.NAME_CONSTRAINTS_st */
            	200, 0,
            	200, 8,
            1, 8, 1, /* 700: pointer.struct.x509_cert_aux_st */
            	705, 0,
            0, 40, 5, /* 705: struct.x509_cert_aux_st */
            	200, 0,
            	200, 8,
            	390, 16,
            	390, 24,
            	200, 32,
            1, 8, 1, /* 718: pointer.struct.env_md_st */
            	723, 0,
            0, 120, 0, /* 723: struct.env_md_st */
            0, 192, 8, /* 726: array[8].struct.cert_pkey_st */
            	319, 0,
            	319, 24,
            	319, 48,
            	319, 72,
            	319, 96,
            	319, 120,
            	319, 144,
            	319, 168,
            1, 8, 1, /* 745: pointer.struct.rsa_st */
            	750, 0,
            0, 168, 17, /* 750: struct.rsa_st */
            	555, 16,
            	521, 24,
            	787, 32,
            	787, 40,
            	787, 48,
            	787, 56,
            	787, 64,
            	787, 72,
            	787, 80,
            	787, 88,
            	248, 96,
            	805, 120,
            	805, 128,
            	805, 136,
            	11, 144,
            	819, 152,
            	819, 160,
            1, 8, 1, /* 787: pointer.struct.bignum_st */
            	792, 0,
            0, 24, 1, /* 792: struct.bignum_st */
            	797, 0,
            1, 8, 1, /* 797: pointer.int */
            	802, 0,
            0, 4, 0, /* 802: int */
            1, 8, 1, /* 805: pointer.struct.bn_mont_ctx_st */
            	810, 0,
            0, 96, 3, /* 810: struct.bn_mont_ctx_st */
            	792, 8,
            	792, 32,
            	792, 56,
            1, 8, 1, /* 819: pointer.struct.bn_blinding_st */
            	824, 0,
            0, 88, 6, /* 824: struct.bn_blinding_st */
            	787, 0,
            	787, 8,
            	787, 16,
            	787, 24,
            	839, 40,
            	805, 72,
            0, 16, 1, /* 839: struct.iovec */
            	11, 0,
            1, 8, 1, /* 844: pointer.struct.dh_st */
            	849, 0,
            0, 144, 12, /* 849: struct.dh_st */
            	787, 8,
            	787, 16,
            	787, 32,
            	787, 40,
            	805, 56,
            	787, 64,
            	787, 72,
            	11, 80,
            	787, 96,
            	248, 112,
            	579, 128,
            	521, 136,
            1, 8, 1, /* 876: pointer.struct.ec_key_st.284 */
            	881, 0,
            0, 56, 4, /* 881: struct.ec_key_st.284 */
            	892, 8,
            	930, 16,
            	787, 24,
            	946, 48,
            1, 8, 1, /* 892: pointer.struct.ec_group_st */
            	897, 0,
            0, 232, 11, /* 897: struct.ec_group_st */
            	922, 0,
            	930, 8,
            	792, 16,
            	792, 40,
            	11, 80,
            	946, 96,
            	792, 104,
            	792, 152,
            	792, 176,
            	11, 208,
            	11, 216,
            1, 8, 1, /* 922: pointer.struct.ec_method_st */
            	927, 0,
            0, 304, 0, /* 927: struct.ec_method_st */
            1, 8, 1, /* 930: pointer.struct.ec_point_st */
            	935, 0,
            0, 88, 4, /* 935: struct.ec_point_st */
            	922, 0,
            	792, 8,
            	792, 32,
            	792, 56,
            1, 8, 1, /* 946: pointer.struct.ec_extra_data_st */
            	951, 0,
            0, 40, 2, /* 951: struct.ec_extra_data_st */
            	946, 0,
            	11, 8,
            1, 8, 1, /* 958: pointer.struct.ssl_cipher_st */
            	963, 0,
            0, 88, 1, /* 963: struct.ssl_cipher_st */
            	11, 8,
            1, 8, 1, /* 968: pointer.struct.cert_st.745 */
            	973, 0,
            0, 296, 5, /* 973: struct.cert_st.745 */
            	314, 0,
            	745, 48,
            	844, 64,
            	876, 80,
            	726, 96,
            1, 8, 1, /* 986: pointer.struct.ssl3_buf_freelist_st */
            	991, 0,
            0, 24, 1, /* 991: struct.ssl3_buf_freelist_st */
            	996, 16,
            1, 8, 1, /* 996: pointer.struct.ssl3_buf_freelist_entry_st */
            	1001, 0,
            0, 8, 1, /* 1001: struct.ssl3_buf_freelist_entry_st */
            	996, 0,
            0, 128, 11, /* 1006: struct.srp_ctx_st.751 */
            	11, 0,
            	11, 32,
            	787, 40,
            	787, 48,
            	787, 56,
            	787, 64,
            	787, 72,
            	787, 80,
            	787, 88,
            	787, 96,
            	11, 104,
            0, 0, 0, /* 1031: func */
            0, 8, 0, /* 1034: pointer.func */
            0, 8, 0, /* 1037: pointer.func */
            0, 0, 0, /* 1040: func */
            0, 12, 0, /* 1043: array[12].char */
            0, 12, 0, /* 1046: struct.ap_unix_identity_t */
            0, 56, 2, /* 1049: struct.comp_ctx_st */
            	1056, 0,
            	248, 40,
            1, 8, 1, /* 1056: pointer.struct.comp_method_st */
            	1061, 0,
            0, 64, 1, /* 1061: struct.comp_method_st */
            	11, 8,
            0, 168, 4, /* 1066: struct.evp_cipher_ctx_st */
            	1077, 0,
            	521, 8,
            	11, 96,
            	11, 120,
            1, 8, 1, /* 1077: pointer.struct.evp_cipher_st */
            	1082, 0,
            0, 88, 1, /* 1082: struct.evp_cipher_st */
            	11, 80,
            1, 8, 1, /* 1087: pointer.struct.evp_cipher_ctx_st */
            	1066, 0,
            0, 40, 4, /* 1092: struct.dtls1_retransmit_state */
            	1087, 0,
            	1103, 8,
            	1169, 16,
            	258, 24,
            1, 8, 1, /* 1103: pointer.struct.env_md_ctx_st */
            	1108, 0,
            0, 48, 4, /* 1108: struct.env_md_ctx_st */
            	718, 0,
            	521, 8,
            	11, 24,
            	1119, 32,
            1, 8, 1, /* 1119: pointer.struct.evp_pkey_ctx_st */
            	1124, 0,
            0, 80, 8, /* 1124: struct.evp_pkey_ctx_st */
            	1143, 0,
            	521, 8,
            	491, 16,
            	491, 24,
            	11, 40,
            	11, 48,
            	192, 56,
            	797, 64,
            1, 8, 1, /* 1143: pointer.struct.evp_pkey_method_st */
            	1148, 0,
            0, 208, 9, /* 1148: struct.evp_pkey_method_st */
            	192, 8,
            	192, 32,
            	192, 48,
            	192, 64,
            	192, 80,
            	192, 96,
            	192, 144,
            	192, 160,
            	192, 176,
            1, 8, 1, /* 1169: pointer.struct.comp_ctx_st */
            	1049, 0,
            0, 88, 1, /* 1174: struct.hm_header_st */
            	1092, 48,
            0, 24, 2, /* 1179: struct._pitem */
            	11, 8,
            	1186, 16,
            1, 8, 1, /* 1186: pointer.struct._pitem */
            	1179, 0,
            0, 16, 1, /* 1191: struct._pqueue */
            	1186, 0,
            1, 8, 1, /* 1196: pointer.struct._pqueue */
            	1191, 0,
            0, 16, 1, /* 1201: struct.record_pqueue_st */
            	1196, 8,
            0, 16, 0, /* 1206: union.anon.142 */
            1, 8, 1, /* 1209: pointer.struct.dtls1_state_st */
            	1214, 0,
            0, 888, 7, /* 1214: struct.dtls1_state_st */
            	1201, 576,
            	1201, 592,
            	1196, 608,
            	1196, 616,
            	1201, 624,
            	1174, 648,
            	1174, 736,
            0, 0, 0, /* 1231: func */
            0, 24, 2, /* 1234: struct.ssl_comp_st */
            	11, 8,
            	1056, 16,
            0, 8, 0, /* 1241: pointer.func */
            0, 0, 0, /* 1244: func */
            0, 8, 0, /* 1247: pointer.func */
            0, 0, 0, /* 1250: func */
            0, 8, 0, /* 1253: pointer.func */
            0, 0, 0, /* 1256: func */
            0, 0, 0, /* 1259: func */
            0, 8, 0, /* 1262: pointer.func */
            0, 0, 0, /* 1265: func */
            0, 8, 0, /* 1268: pointer.func */
            0, 9, 0, /* 1271: array[9].char */
            0, 24, 0, /* 1274: array[6].int */
            0, 8, 0, /* 1277: pointer.func */
            0, 0, 0, /* 1280: func */
            0, 8, 0, /* 1283: pointer.func */
            0, 0, 0, /* 1286: func */
            0, 8, 0, /* 1289: pointer.func */
            0, 0, 0, /* 1292: func */
            0, 0, 0, /* 1295: func */
            0, 8, 0, /* 1298: pointer.func */
            0, 8, 0, /* 1301: pointer.func */
            0, 0, 0, /* 1304: func */
            0, 8, 0, /* 1307: pointer.func */
            0, 0, 0, /* 1310: func */
            0, 0, 0, /* 1313: func */
            0, 8, 0, /* 1316: pointer.func */
            0, 8, 0, /* 1319: pointer.func */
            0, 8, 0, /* 1322: pointer.func */
            0, 8, 0, /* 1325: pointer.func */
            0, 8, 0, /* 1328: pointer.func */
            0, 0, 0, /* 1331: func */
            0, 0, 0, /* 1334: func */
            0, 0, 0, /* 1337: func */
            0, 0, 0, /* 1340: func */
            0, 8, 0, /* 1343: pointer.func */
            0, 0, 0, /* 1346: func */
            0, 8, 0, /* 1349: pointer.func */
            0, 8, 0, /* 1352: pointer.func */
            0, 8, 0, /* 1355: pointer.func */
            0, 128, 0, /* 1358: array[128].char */
            0, 0, 0, /* 1361: func */
            0, 0, 0, /* 1364: func */
            0, 0, 0, /* 1367: func */
            0, 8, 0, /* 1370: pointer.func */
            0, 0, 0, /* 1373: func */
            0, 8, 0, /* 1376: pointer.func */
            0, 8, 0, /* 1379: pointer.func */
            0, 0, 0, /* 1382: func */
            0, 8, 0, /* 1385: pointer.func */
            0, 0, 0, /* 1388: func */
            0, 0, 0, /* 1391: func */
            0, 0, 0, /* 1394: func */
            0, 8, 0, /* 1397: pointer.func */
            0, 0, 0, /* 1400: func */
            0, 0, 0, /* 1403: func */
            0, 8, 0, /* 1406: pointer.func */
            0, 0, 0, /* 1409: func */
            0, 8, 0, /* 1412: pointer.func */
            0, 0, 0, /* 1415: func */
            0, 8, 0, /* 1418: pointer.func */
            0, 8, 0, /* 1421: pointer.func */
            0, 8, 0, /* 1424: pointer.func */
            0, 0, 0, /* 1427: func */
            0, 20, 0, /* 1430: array[5].int */
            0, 8, 0, /* 1433: pointer.func */
            0, 0, 0, /* 1436: func */
            0, 8, 0, /* 1439: pointer.func */
            0, 0, 0, /* 1442: func */
            0, 8, 0, /* 1445: pointer.func */
            0, 8, 0, /* 1448: pointer.func */
            0, 0, 0, /* 1451: func */
            0, 8, 0, /* 1454: pointer.func */
            0, 0, 0, /* 1457: func */
            0, 8, 0, /* 1460: pointer.func */
            0, 0, 0, /* 1463: func */
            0, 0, 0, /* 1466: func */
            0, 8, 0, /* 1469: pointer.func */
            0, 8, 0, /* 1472: pointer.func */
            0, 8, 0, /* 1475: pointer.func */
            0, 0, 0, /* 1478: func */
            0, 8, 0, /* 1481: pointer.func */
            0, 0, 0, /* 1484: func */
            0, 8, 0, /* 1487: pointer.func */
            0, 8, 0, /* 1490: pointer.func */
            0, 0, 0, /* 1493: func */
            0, 4, 0, /* 1496: array[4].char */
            0, 0, 0, /* 1499: func */
            1, 8, 1, /* 1502: pointer.struct.iovec */
            	839, 0,
            0, 8, 0, /* 1507: pointer.func */
            0, 8, 0, /* 1510: pointer.func */
            0, 0, 0, /* 1513: func */
            0, 8, 0, /* 1516: pointer.func */
            0, 8, 0, /* 1519: pointer.func */
            0, 0, 0, /* 1522: func */
            0, 0, 0, /* 1525: func */
            0, 0, 0, /* 1528: func */
            0, 8, 0, /* 1531: pointer.func */
            0, 0, 0, /* 1534: func */
            0, 8, 0, /* 1537: pointer.func */
            0, 8, 0, /* 1540: pointer.func */
            0, 8, 0, /* 1543: pointer.func */
            0, 8, 0, /* 1546: pointer.func */
            0, 0, 0, /* 1549: func */
            0, 0, 0, /* 1552: func */
            0, 8, 0, /* 1555: pointer.func */
            0, 8, 0, /* 1558: pointer.func */
            0, 8, 0, /* 1561: pointer.func */
            0, 0, 0, /* 1564: func */
            0, 8, 0, /* 1567: pointer.func */
            0, 0, 0, /* 1570: func */
            0, 0, 0, /* 1573: func */
            0, 8, 0, /* 1576: pointer.func */
            0, 8, 0, /* 1579: pointer.func */
            1, 8, 1, /* 1582: pointer.struct.ssl_comp_st */
            	1234, 0,
            0, 8, 0, /* 1587: pointer.func */
            0, 16, 0, /* 1590: struct.rlimit */
            0, 0, 0, /* 1593: func */
            0, 8, 0, /* 1596: pointer.func */
            0, 8, 0, /* 1599: pointer.func */
            0, 0, 0, /* 1602: func */
            0, 8, 0, /* 1605: pointer.func */
            0, 0, 0, /* 1608: func */
            0, 0, 0, /* 1611: func */
            0, 8, 0, /* 1614: pointer.func */
            0, 0, 0, /* 1617: func */
            0, 8, 0, /* 1620: pointer.func */
            0, 72, 0, /* 1623: struct.anon.25 */
            0, 0, 0, /* 1626: func */
            0, 0, 0, /* 1629: func */
            0, 0, 0, /* 1632: func */
            0, 0, 0, /* 1635: func */
            0, 0, 0, /* 1638: func */
            0, 0, 0, /* 1641: func */
            0, 8, 0, /* 1644: pointer.func */
            0, 8, 0, /* 1647: pointer.func */
            0, 0, 0, /* 1650: func */
            0, 8, 0, /* 1653: pointer.func */
            0, 8, 0, /* 1656: pointer.func */
            0, 64, 0, /* 1659: array[64].char */
            0, 0, 0, /* 1662: func */
            0, 0, 0, /* 1665: func */
            0, 8, 0, /* 1668: pointer.func */
            0, 8, 0, /* 1671: array[2].int */
            0, 24, 1, /* 1674: struct.ssl3_buffer_st */
            	11, 0,
            0, 8, 0, /* 1679: pointer.func */
            0, 0, 0, /* 1682: func */
            0, 8, 0, /* 1685: pointer.func */
            0, 528, 8, /* 1688: struct.anon.0 */
            	958, 408,
            	844, 416,
            	876, 424,
            	200, 464,
            	11, 480,
            	1077, 488,
            	718, 496,
            	1582, 512,
            0, 0, 0, /* 1707: func */
            0, 0, 0, /* 1710: func */
            0, 8, 0, /* 1713: pointer.func */
            0, 8, 0, /* 1716: pointer.func */
            1, 8, 1, /* 1719: pointer.struct.ssl2_state_st */
            	1724, 0,
            0, 344, 9, /* 1724: struct.ssl2_state_st */
            	11, 24,
            	11, 56,
            	11, 64,
            	11, 72,
            	11, 104,
            	11, 112,
            	11, 120,
            	11, 128,
            	11, 136,
            1, 8, 1, /* 1745: pointer.struct.ssl_ctx_st.752 */
            	103, 0,
            0, 8, 0, /* 1750: pointer.func */
            0, 0, 0, /* 1753: func */
            0, 8, 0, /* 1756: pointer.func */
            0, 8, 0, /* 1759: long */
            0, 8, 0, /* 1762: pointer.func */
            0, 8, 0, /* 1765: pointer.func */
            0, 0, 0, /* 1768: func */
            0, 0, 0, /* 1771: func */
            0, 0, 0, /* 1774: func */
            0, 20, 0, /* 1777: array[20].char */
            0, 16, 0, /* 1780: array[16].char */
            0, 0, 0, /* 1783: func */
            0, 8, 0, /* 1786: pointer.func */
            0, 8, 0, /* 1789: pointer.func */
            0, 0, 0, /* 1792: func */
            0, 0, 0, /* 1795: func */
            0, 0, 0, /* 1798: func */
            0, 0, 0, /* 1801: func */
            1, 8, 1, /* 1804: pointer.struct.bio_method_st */
            	1809, 0,
            0, 80, 1, /* 1809: struct.bio_method_st */
            	11, 8,
            0, 0, 0, /* 1814: func */
            0, 8, 0, /* 1817: pointer.func */
            0, 0, 0, /* 1820: func */
            0, 0, 0, /* 1823: func */
            0, 0, 0, /* 1826: func */
            0, 8, 0, /* 1829: pointer.func */
            0, 8, 0, /* 1832: pointer.func */
            0, 8, 0, /* 1835: pointer.func */
            0, 8, 0, /* 1838: pointer.func */
            0, 8, 0, /* 1841: pointer.func */
            0, 8, 0, /* 1844: pointer.func */
            0, 0, 0, /* 1847: func */
            0, 8, 0, /* 1850: pointer.func */
            0, 8, 0, /* 1853: pointer.func */
            1, 8, 1, /* 1856: pointer.struct.tls_session_ticket_ext_st */
            	6, 0,
            0, 0, 0, /* 1861: func */
            0, 0, 0, /* 1864: func */
            0, 0, 0, /* 1867: func */
            0, 8, 0, /* 1870: pointer.func */
            0, 0, 0, /* 1873: func */
            0, 256, 0, /* 1876: array[256].char */
            0, 8, 0, /* 1879: pointer.func */
            0, 0, 0, /* 1882: func */
            0, 0, 0, /* 1885: func */
            0, 0, 0, /* 1888: func */
            0, 0, 0, /* 1891: func */
            0, 0, 0, /* 1894: func */
            0, 8, 0, /* 1897: pointer.func */
            0, 8, 0, /* 1900: pointer.func */
            0, 0, 0, /* 1903: func */
            0, 0, 0, /* 1906: func */
            0, 0, 0, /* 1909: func */
            0, 8, 0, /* 1912: pointer.func */
            0, 0, 0, /* 1915: func */
            0, 0, 0, /* 1918: func */
            0, 8, 0, /* 1921: pointer.func */
            0, 808, 41, /* 1924: struct.ssl_st.776 */
            	166, 8,
            	2009, 16,
            	2009, 24,
            	2009, 32,
            	455, 80,
            	11, 88,
            	11, 104,
            	1719, 120,
            	2029, 128,
            	1209, 136,
            	11, 160,
            	236, 176,
            	200, 184,
            	200, 192,
            	1087, 208,
            	1103, 216,
            	1169, 224,
            	1087, 232,
            	1103, 240,
            	1169, 248,
            	968, 256,
            	258, 304,
            	1745, 368,
            	248, 392,
            	200, 408,
            	11, 472,
            	11, 480,
            	200, 504,
            	200, 512,
            	11, 520,
            	11, 544,
            	11, 560,
            	11, 568,
            	1856, 584,
            	11, 600,
            	11, 616,
            	1745, 624,
            	11, 632,
            	200, 648,
            	1502, 656,
            	1006, 680,
            1, 8, 1, /* 2009: pointer.struct.bio_st */
            	2014, 0,
            0, 112, 6, /* 2014: struct.bio_st */
            	1804, 0,
            	11, 16,
            	11, 48,
            	2009, 56,
            	2009, 64,
            	248, 96,
            1, 8, 1, /* 2029: pointer.struct.ssl3_state_st */
            	2034, 0,
            0, 1200, 10, /* 2034: struct.ssl3_state_st */
            	1674, 240,
            	1674, 264,
            	2057, 288,
            	2057, 344,
            	11, 432,
            	2009, 440,
            	2066, 448,
            	11, 496,
            	11, 512,
            	1688, 528,
            0, 56, 3, /* 2057: struct.ssl3_record_st */
            	11, 16,
            	11, 24,
            	11, 32,
            1, 8, 1, /* 2066: pointer.pointer.struct.env_md_ctx_st */
            	1103, 0,
            0, 0, 0, /* 2071: func */
            0, 8, 0, /* 2074: pointer.func */
            0, 2, 0, /* 2077: short */
            0, 0, 0, /* 2080: func */
            0, 0, 0, /* 2083: func */
            0, 0, 0, /* 2086: func */
            0, 8, 0, /* 2089: pointer.func */
            0, 0, 0, /* 2092: func */
            0, 0, 0, /* 2095: func */
            0, 8, 0, /* 2098: pointer.func */
            0, 8, 0, /* 2101: pointer.func */
            0, 0, 0, /* 2104: func */
            0, 8, 0, /* 2107: pointer.func */
            0, 0, 0, /* 2110: func */
            0, 8, 0, /* 2113: pointer.func */
            0, 0, 0, /* 2116: func */
            0, 0, 0, /* 2119: func */
            0, 0, 0, /* 2122: func */
            0, 8, 0, /* 2125: pointer.func */
            0, 8, 0, /* 2128: pointer.func */
            0, 0, 0, /* 2131: func */
            0, 0, 0, /* 2134: func */
            0, 0, 0, /* 2137: func */
            0, 0, 0, /* 2140: func */
            0, 8, 0, /* 2143: pointer.func */
            0, 8, 0, /* 2146: pointer.func */
            0, 8, 0, /* 2149: pointer.func */
            0, 8, 0, /* 2152: pointer.func */
            0, 8, 0, /* 2155: pointer.func */
            0, 8, 0, /* 2158: pointer.func */
            0, 0, 0, /* 2161: func */
            0, 8, 0, /* 2164: pointer.func */
            0, 0, 0, /* 2167: func */
            0, 32, 0, /* 2170: array[32].char */
            0, 8, 0, /* 2173: pointer.func */
            0, 8, 0, /* 2176: pointer.func */
            0, 8, 0, /* 2179: pointer.func */
            0, 0, 0, /* 2182: func */
            0, 0, 0, /* 2185: func */
            0, 8, 0, /* 2188: pointer.func */
            0, 8, 0, /* 2191: pointer.func */
            0, 0, 0, /* 2194: func */
            0, 0, 0, /* 2197: func */
            1, 8, 1, /* 2200: pointer.struct.ssl_st.776 */
            	1924, 0,
            0, 0, 0, /* 2205: func */
            0, 8, 0, /* 2208: pointer.func */
            0, 0, 0, /* 2211: func */
            0, 0, 0, /* 2214: func */
            0, 0, 0, /* 2217: func */
            0, 0, 0, /* 2220: func */
            0, 8, 0, /* 2223: pointer.func */
            0, 8, 0, /* 2226: pointer.func */
            0, 8, 0, /* 2229: pointer.func */
            0, 2, 0, /* 2232: array[2].char */
            0, 8, 0, /* 2235: pointer.func */
            0, 8, 0, /* 2238: pointer.func */
            0, 8, 0, /* 2241: pointer.func */
            0, 0, 0, /* 2244: func */
            0, 8, 0, /* 2247: pointer.func */
            0, 0, 0, /* 2250: func */
            0, 0, 0, /* 2253: func */
            0, 8, 0, /* 2256: pointer.func */
            0, 8, 0, /* 2259: pointer.func */
            0, 8, 0, /* 2262: pointer.func */
            0, 8, 0, /* 2265: pointer.func */
            0, 0, 0, /* 2268: func */
            0, 0, 0, /* 2271: func */
            0, 8, 0, /* 2274: pointer.func */
            0, 0, 0, /* 2277: func */
            0, 8, 0, /* 2280: pointer.func */
            0, 0, 0, /* 2283: func */
            0, 8, 0, /* 2286: pointer.func */
            0, 8, 0, /* 2289: pointer.func */
            0, 0, 0, /* 2292: func */
            0, 0, 0, /* 2295: func */
            0, 8, 0, /* 2298: pointer.func */
            0, 8, 0, /* 2301: pointer.func */
            0, 8, 0, /* 2304: pointer.func */
            0, 0, 0, /* 2307: func */
            0, 8, 0, /* 2310: pointer.func */
            0, 8, 0, /* 2313: pointer.func */
            0, 0, 0, /* 2316: func */
            0, 0, 0, /* 2319: func */
            0, 8, 0, /* 2322: pointer.func */
            0, 0, 0, /* 2325: func */
            0, 8, 0, /* 2328: pointer.func */
            0, 0, 0, /* 2331: func */
            0, 48, 0, /* 2334: array[48].char */
            0, 8, 0, /* 2337: array[8].char */
            0, 8, 0, /* 2340: pointer.func */
            0, 0, 0, /* 2343: func */
            0, 8, 0, /* 2346: pointer.func */
            0, 0, 0, /* 2349: func */
            0, 0, 0, /* 2352: func */
            0, 0, 0, /* 2355: func */
        },
        .arg_entity_index = { 2200, },
        .ret_entity_index = 328,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    const SSL * new_arg_a = *((const SSL * *)new_args->args[0]);

    X509 * *new_ret_ptr = (X509 * *)new_args->ret;

    X509 * (*orig_SSL_get_certificate)(const SSL *);
    orig_SSL_get_certificate = dlsym(RTLD_NEXT, "SSL_get_certificate");
    *new_ret_ptr = (*orig_SSL_get_certificate)(new_arg_a);

    syscall(889);

    return ret;
}

