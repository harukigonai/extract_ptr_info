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

void * bb_SSL_get_ex_data(const SSL * arg_a,int arg_b);

void * SSL_get_ex_data(const SSL * arg_a,int arg_b) 
{
    printf("SSL_get_ex_data called\n");
    if (!syscall(890))
        return bb_SSL_get_ex_data(arg_a,arg_b);
    else {
        void * (*orig_SSL_get_ex_data)(const SSL *,int);
        orig_SSL_get_ex_data = dlsym(RTLD_NEXT, "SSL_get_ex_data");
        return orig_SSL_get_ex_data(arg_a,arg_b);
    }
}

void * bb_SSL_get_ex_data(const SSL * arg_a,int arg_b) 
{
    void * ret;

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
            0, 16, 0, /* 1049: struct.rlimit */
            1, 8, 1, /* 1052: pointer.struct.ssl_ctx_st.752 */
            	103, 0,
            0, 0, 0, /* 1057: func */
            0, 8, 0, /* 1060: pointer.func */
            0, 8, 0, /* 1063: pointer.func */
            0, 56, 2, /* 1066: struct.comp_ctx_st */
            	1073, 0,
            	248, 40,
            1, 8, 1, /* 1073: pointer.struct.comp_method_st */
            	1078, 0,
            0, 64, 1, /* 1078: struct.comp_method_st */
            	11, 8,
            0, 168, 4, /* 1083: struct.evp_cipher_ctx_st */
            	1094, 0,
            	521, 8,
            	11, 96,
            	11, 120,
            1, 8, 1, /* 1094: pointer.struct.evp_cipher_st */
            	1099, 0,
            0, 88, 1, /* 1099: struct.evp_cipher_st */
            	11, 80,
            1, 8, 1, /* 1104: pointer.struct.evp_cipher_ctx_st */
            	1083, 0,
            0, 40, 4, /* 1109: struct.dtls1_retransmit_state */
            	1104, 0,
            	1120, 8,
            	1186, 16,
            	258, 24,
            1, 8, 1, /* 1120: pointer.struct.env_md_ctx_st */
            	1125, 0,
            0, 48, 4, /* 1125: struct.env_md_ctx_st */
            	718, 0,
            	521, 8,
            	11, 24,
            	1136, 32,
            1, 8, 1, /* 1136: pointer.struct.evp_pkey_ctx_st */
            	1141, 0,
            0, 80, 8, /* 1141: struct.evp_pkey_ctx_st */
            	1160, 0,
            	521, 8,
            	491, 16,
            	491, 24,
            	11, 40,
            	11, 48,
            	192, 56,
            	797, 64,
            1, 8, 1, /* 1160: pointer.struct.evp_pkey_method_st */
            	1165, 0,
            0, 208, 9, /* 1165: struct.evp_pkey_method_st */
            	192, 8,
            	192, 32,
            	192, 48,
            	192, 64,
            	192, 80,
            	192, 96,
            	192, 144,
            	192, 160,
            	192, 176,
            1, 8, 1, /* 1186: pointer.struct.comp_ctx_st */
            	1066, 0,
            0, 88, 1, /* 1191: struct.hm_header_st */
            	1109, 48,
            0, 24, 2, /* 1196: struct._pitem */
            	11, 8,
            	1203, 16,
            1, 8, 1, /* 1203: pointer.struct._pitem */
            	1196, 0,
            0, 16, 1, /* 1208: struct._pqueue */
            	1203, 0,
            1, 8, 1, /* 1213: pointer.struct._pqueue */
            	1208, 0,
            0, 16, 1, /* 1218: struct.record_pqueue_st */
            	1213, 8,
            0, 16, 0, /* 1223: union.anon.142 */
            1, 8, 1, /* 1226: pointer.struct.dtls1_state_st */
            	1231, 0,
            0, 888, 7, /* 1231: struct.dtls1_state_st */
            	1218, 576,
            	1218, 592,
            	1213, 608,
            	1213, 616,
            	1218, 624,
            	1191, 648,
            	1191, 736,
            0, 0, 0, /* 1248: func */
            0, 24, 2, /* 1251: struct.ssl_comp_st */
            	11, 8,
            	1073, 16,
            0, 8, 0, /* 1258: pointer.func */
            0, 0, 0, /* 1261: func */
            0, 8, 0, /* 1264: pointer.func */
            0, 0, 0, /* 1267: func */
            0, 8, 0, /* 1270: pointer.func */
            0, 0, 0, /* 1273: func */
            0, 0, 0, /* 1276: func */
            0, 8, 0, /* 1279: pointer.func */
            0, 0, 0, /* 1282: func */
            0, 8, 0, /* 1285: pointer.func */
            0, 9, 0, /* 1288: array[9].char */
            0, 24, 0, /* 1291: array[6].int */
            0, 8, 0, /* 1294: pointer.func */
            0, 0, 0, /* 1297: func */
            0, 8, 0, /* 1300: pointer.func */
            0, 0, 0, /* 1303: func */
            0, 8, 0, /* 1306: pointer.func */
            0, 0, 0, /* 1309: func */
            0, 0, 0, /* 1312: func */
            0, 8, 0, /* 1315: pointer.func */
            0, 8, 0, /* 1318: pointer.func */
            0, 0, 0, /* 1321: func */
            0, 8, 0, /* 1324: pointer.func */
            0, 0, 0, /* 1327: func */
            0, 0, 0, /* 1330: func */
            0, 8, 0, /* 1333: pointer.func */
            0, 8, 0, /* 1336: pointer.func */
            0, 8, 0, /* 1339: pointer.func */
            0, 8, 0, /* 1342: pointer.func */
            0, 8, 0, /* 1345: pointer.func */
            0, 0, 0, /* 1348: func */
            0, 0, 0, /* 1351: func */
            0, 0, 0, /* 1354: func */
            0, 0, 0, /* 1357: func */
            0, 8, 0, /* 1360: pointer.func */
            0, 0, 0, /* 1363: func */
            0, 8, 0, /* 1366: pointer.func */
            0, 8, 0, /* 1369: pointer.func */
            0, 8, 0, /* 1372: pointer.func */
            0, 128, 0, /* 1375: array[128].char */
            0, 0, 0, /* 1378: func */
            0, 0, 0, /* 1381: func */
            0, 8, 0, /* 1384: pointer.func */
            0, 0, 0, /* 1387: func */
            0, 0, 0, /* 1390: func */
            0, 0, 0, /* 1393: func */
            0, 0, 0, /* 1396: func */
            0, 8, 0, /* 1399: pointer.func */
            0, 0, 0, /* 1402: func */
            0, 0, 0, /* 1405: func */
            0, 8, 0, /* 1408: pointer.func */
            0, 8, 0, /* 1411: pointer.func */
            0, 8, 0, /* 1414: pointer.func */
            0, 0, 0, /* 1417: func */
            0, 8, 0, /* 1420: pointer.func */
            0, 0, 0, /* 1423: func */
            0, 20, 0, /* 1426: array[5].int */
            0, 8, 0, /* 1429: pointer.func */
            0, 0, 0, /* 1432: func */
            0, 0, 0, /* 1435: func */
            0, 0, 0, /* 1438: func */
            0, 528, 8, /* 1441: struct.anon.0 */
            	958, 408,
            	844, 416,
            	876, 424,
            	200, 464,
            	11, 480,
            	1094, 488,
            	718, 496,
            	1460, 512,
            1, 8, 1, /* 1460: pointer.struct.ssl_comp_st */
            	1251, 0,
            0, 0, 0, /* 1465: func */
            0, 0, 0, /* 1468: func */
            0, 0, 0, /* 1471: func */
            0, 0, 0, /* 1474: func */
            0, 8, 0, /* 1477: pointer.func */
            0, 0, 0, /* 1480: func */
            0, 8, 0, /* 1483: pointer.func */
            0, 0, 0, /* 1486: func */
            0, 8, 0, /* 1489: pointer.func */
            0, 0, 0, /* 1492: func */
            0, 8, 0, /* 1495: pointer.func */
            1, 8, 1, /* 1498: pointer.pointer.struct.env_md_ctx_st */
            	1120, 0,
            0, 8, 0, /* 1503: array[2].int */
            0, 24, 1, /* 1506: struct.ssl3_buffer_st */
            	11, 0,
            0, 8, 0, /* 1511: pointer.func */
            0, 64, 0, /* 1514: array[64].char */
            0, 8, 0, /* 1517: pointer.func */
            0, 1200, 10, /* 1520: struct.ssl3_state_st */
            	1506, 240,
            	1506, 264,
            	1543, 288,
            	1543, 344,
            	11, 432,
            	1552, 440,
            	1498, 448,
            	11, 496,
            	11, 512,
            	1441, 528,
            0, 56, 3, /* 1543: struct.ssl3_record_st */
            	11, 16,
            	11, 24,
            	11, 32,
            1, 8, 1, /* 1552: pointer.struct.bio_st */
            	1557, 0,
            0, 112, 6, /* 1557: struct.bio_st */
            	1572, 0,
            	11, 16,
            	11, 48,
            	1552, 56,
            	1552, 64,
            	248, 96,
            1, 8, 1, /* 1572: pointer.struct.bio_method_st */
            	1577, 0,
            0, 80, 1, /* 1577: struct.bio_method_st */
            	11, 8,
            0, 0, 0, /* 1582: func */
            0, 8, 0, /* 1585: pointer.func */
            0, 8, 0, /* 1588: pointer.func */
            0, 0, 0, /* 1591: func */
            1, 8, 1, /* 1594: pointer.struct.ssl3_state_st */
            	1520, 0,
            0, 8, 0, /* 1599: pointer.func */
            0, 0, 0, /* 1602: func */
            0, 344, 9, /* 1605: struct.ssl2_state_st */
            	11, 24,
            	11, 56,
            	11, 64,
            	11, 72,
            	11, 104,
            	11, 112,
            	11, 120,
            	11, 128,
            	11, 136,
            1, 8, 1, /* 1626: pointer.struct.ssl2_state_st */
            	1605, 0,
            0, 0, 0, /* 1631: func */
            0, 8, 0, /* 1634: pointer.func */
            0, 0, 0, /* 1637: func */
            0, 8, 0, /* 1640: pointer.func */
            0, 8, 0, /* 1643: pointer.func */
            0, 8, 0, /* 1646: pointer.func */
            0, 0, 0, /* 1649: func */
            0, 8, 0, /* 1652: pointer.func */
            0, 0, 0, /* 1655: func */
            0, 0, 0, /* 1658: func */
            0, 8, 0, /* 1661: pointer.func */
            0, 8, 0, /* 1664: pointer.func */
            0, 0, 0, /* 1667: func */
            0, 0, 0, /* 1670: func */
            0, 0, 0, /* 1673: func */
            0, 4, 0, /* 1676: array[4].char */
            0, 8, 0, /* 1679: pointer.func */
            0, 8, 0, /* 1682: pointer.func */
            0, 0, 0, /* 1685: func */
            0, 8, 0, /* 1688: pointer.func */
            0, 8, 0, /* 1691: pointer.func */
            0, 8, 0, /* 1694: pointer.func */
            0, 8, 0, /* 1697: pointer.func */
            0, 8, 0, /* 1700: pointer.func */
            0, 8, 0, /* 1703: pointer.func */
            0, 8, 0, /* 1706: pointer.func */
            0, 0, 0, /* 1709: func */
            0, 8, 0, /* 1712: pointer.func */
            0, 0, 0, /* 1715: func */
            0, 2, 0, /* 1718: array[2].char */
            0, 8, 0, /* 1721: pointer.func */
            0, 8, 0, /* 1724: pointer.func */
            0, 0, 0, /* 1727: func */
            0, 8, 0, /* 1730: pointer.func */
            0, 8, 0, /* 1733: pointer.func */
            0, 8, 0, /* 1736: pointer.func */
            0, 48, 0, /* 1739: array[48].char */
            0, 0, 0, /* 1742: func */
            0, 0, 0, /* 1745: func */
            0, 8, 0, /* 1748: pointer.func */
            0, 0, 0, /* 1751: func */
            0, 16, 0, /* 1754: array[16].char */
            0, 8, 0, /* 1757: pointer.func */
            0, 8, 0, /* 1760: pointer.func */
            0, 808, 41, /* 1763: struct.ssl_st.776 */
            	166, 8,
            	1552, 16,
            	1552, 24,
            	1552, 32,
            	455, 80,
            	11, 88,
            	11, 104,
            	1626, 120,
            	1594, 128,
            	1226, 136,
            	11, 160,
            	236, 176,
            	200, 184,
            	200, 192,
            	1104, 208,
            	1120, 216,
            	1186, 224,
            	1104, 232,
            	1120, 240,
            	1186, 248,
            	968, 256,
            	258, 304,
            	1052, 368,
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
            	1848, 584,
            	11, 600,
            	11, 616,
            	1052, 624,
            	11, 632,
            	200, 648,
            	1853, 656,
            	1006, 680,
            1, 8, 1, /* 1848: pointer.struct.tls_session_ticket_ext_st */
            	6, 0,
            1, 8, 1, /* 1853: pointer.struct.iovec */
            	839, 0,
            0, 8, 0, /* 1858: pointer.func */
            0, 0, 0, /* 1861: func */
            0, 72, 0, /* 1864: struct.anon.25 */
            0, 8, 0, /* 1867: pointer.func */
            0, 8, 0, /* 1870: pointer.func */
            0, 0, 0, /* 1873: func */
            0, 0, 0, /* 1876: func */
            0, 8, 0, /* 1879: pointer.func */
            0, 0, 0, /* 1882: func */
            0, 8, 0, /* 1885: pointer.func */
            0, 8, 0, /* 1888: pointer.func */
            0, 0, 0, /* 1891: func */
            1, 8, 1, /* 1894: pointer.struct.ssl_st.776 */
            	1763, 0,
            0, 0, 0, /* 1899: func */
            0, 8, 0, /* 1902: array[8].char */
            0, 0, 0, /* 1905: func */
            0, 8, 0, /* 1908: pointer.func */
            0, 0, 0, /* 1911: func */
            0, 8, 0, /* 1914: pointer.func */
            0, 0, 0, /* 1917: func */
            0, 0, 0, /* 1920: func */
            0, 0, 0, /* 1923: func */
            0, 8, 0, /* 1926: pointer.func */
            0, 0, 0, /* 1929: func */
            0, 8, 0, /* 1932: pointer.func */
            0, 0, 0, /* 1935: func */
            0, 8, 0, /* 1938: pointer.func */
            0, 0, 0, /* 1941: func */
            0, 8, 0, /* 1944: pointer.func */
            0, 0, 0, /* 1947: func */
            0, 0, 0, /* 1950: func */
            0, 0, 0, /* 1953: func */
            0, 8, 0, /* 1956: pointer.func */
            0, 0, 0, /* 1959: func */
            0, 8, 0, /* 1962: pointer.func */
            0, 8, 0, /* 1965: pointer.func */
            0, 0, 0, /* 1968: func */
            0, 0, 0, /* 1971: func */
            0, 8, 0, /* 1974: pointer.func */
            0, 0, 0, /* 1977: func */
            0, 0, 0, /* 1980: func */
            0, 8, 0, /* 1983: long */
            0, 8, 0, /* 1986: pointer.func */
            0, 0, 0, /* 1989: func */
            0, 8, 0, /* 1992: pointer.func */
            0, 32, 0, /* 1995: array[32].char */
            0, 0, 0, /* 1998: func */
            0, 0, 0, /* 2001: func */
            0, 0, 0, /* 2004: func */
            0, 8, 0, /* 2007: pointer.func */
            0, 0, 0, /* 2010: func */
            0, 8, 0, /* 2013: pointer.func */
            0, 8, 0, /* 2016: pointer.func */
            0, 8, 0, /* 2019: pointer.func */
            0, 8, 0, /* 2022: pointer.func */
            0, 0, 0, /* 2025: func */
            0, 0, 0, /* 2028: func */
            0, 8, 0, /* 2031: pointer.func */
            0, 0, 0, /* 2034: func */
            0, 2, 0, /* 2037: short */
            0, 0, 0, /* 2040: func */
            0, 0, 0, /* 2043: func */
            0, 0, 0, /* 2046: func */
            0, 0, 0, /* 2049: func */
            0, 8, 0, /* 2052: pointer.func */
            0, 8, 0, /* 2055: pointer.func */
            0, 8, 0, /* 2058: pointer.func */
            0, 8, 0, /* 2061: pointer.func */
            0, 8, 0, /* 2064: pointer.func */
            0, 8, 0, /* 2067: pointer.func */
            0, 8, 0, /* 2070: pointer.func */
            0, 8, 0, /* 2073: pointer.func */
            0, 0, 0, /* 2076: func */
            0, 256, 0, /* 2079: array[256].char */
            0, 8, 0, /* 2082: pointer.func */
            0, 0, 0, /* 2085: func */
            0, 8, 0, /* 2088: pointer.func */
            0, 0, 0, /* 2091: func */
            0, 8, 0, /* 2094: pointer.func */
            0, 8, 0, /* 2097: pointer.func */
            0, 0, 0, /* 2100: func */
            0, 8, 0, /* 2103: pointer.func */
            0, 0, 0, /* 2106: func */
            0, 8, 0, /* 2109: pointer.func */
            0, 8, 0, /* 2112: pointer.func */
            0, 0, 0, /* 2115: func */
            0, 8, 0, /* 2118: pointer.func */
            0, 8, 0, /* 2121: pointer.func */
            0, 8, 0, /* 2124: pointer.func */
            0, 0, 0, /* 2127: func */
            0, 8, 0, /* 2130: pointer.func */
            0, 8, 0, /* 2133: pointer.func */
            0, 8, 0, /* 2136: pointer.func */
            0, 0, 0, /* 2139: func */
            0, 0, 0, /* 2142: func */
            0, 8, 0, /* 2145: pointer.func */
            0, 0, 0, /* 2148: func */
            0, 0, 0, /* 2151: func */
            0, 8, 0, /* 2154: pointer.func */
            0, 20, 0, /* 2157: array[20].char */
            0, 0, 0, /* 2160: func */
            0, 8, 0, /* 2163: pointer.func */
            0, 0, 0, /* 2166: func */
            0, 0, 0, /* 2169: func */
            0, 8, 0, /* 2172: pointer.func */
            0, 0, 0, /* 2175: func */
            0, 8, 0, /* 2178: pointer.func */
            0, 8, 0, /* 2181: pointer.func */
            0, 8, 0, /* 2184: pointer.func */
            0, 0, 0, /* 2187: func */
            0, 0, 0, /* 2190: func */
            0, 8, 0, /* 2193: pointer.func */
            0, 0, 0, /* 2196: func */
            0, 8, 0, /* 2199: pointer.func */
            0, 8, 0, /* 2202: pointer.func */
            0, 0, 0, /* 2205: func */
            0, 0, 0, /* 2208: func */
            0, 0, 0, /* 2211: func */
            0, 0, 0, /* 2214: func */
            0, 0, 0, /* 2217: func */
            0, 0, 0, /* 2220: func */
            0, 0, 0, /* 2223: func */
            0, 8, 0, /* 2226: pointer.func */
            0, 0, 0, /* 2229: func */
            0, 8, 0, /* 2232: pointer.func */
            0, 0, 0, /* 2235: func */
            0, 0, 0, /* 2238: func */
            0, 8, 0, /* 2241: pointer.func */
            0, 8, 0, /* 2244: pointer.func */
            0, 0, 0, /* 2247: func */
            0, 8, 0, /* 2250: pointer.func */
            0, 0, 0, /* 2253: func */
            0, 8, 0, /* 2256: pointer.func */
            0, 0, 0, /* 2259: func */
            0, 0, 0, /* 2262: func */
            0, 0, 0, /* 2265: func */
            0, 0, 0, /* 2268: func */
            0, 8, 0, /* 2271: pointer.func */
            0, 8, 0, /* 2274: pointer.func */
            0, 8, 0, /* 2277: pointer.func */
            0, 0, 0, /* 2280: func */
            0, 8, 0, /* 2283: pointer.func */
            0, 0, 0, /* 2286: func */
            0, 0, 0, /* 2289: func */
            0, 8, 0, /* 2292: pointer.func */
            0, 0, 0, /* 2295: func */
            0, 0, 0, /* 2298: func */
            0, 8, 0, /* 2301: pointer.func */
            0, 0, 0, /* 2304: func */
            0, 8, 0, /* 2307: pointer.func */
            0, 0, 0, /* 2310: func */
            0, 0, 0, /* 2313: func */
            0, 8, 0, /* 2316: pointer.func */
            0, 0, 0, /* 2319: func */
            0, 8, 0, /* 2322: pointer.func */
            0, 8, 0, /* 2325: pointer.func */
            0, 8, 0, /* 2328: pointer.func */
            0, 0, 0, /* 2331: func */
            0, 8, 0, /* 2334: pointer.func */
            0, 0, 0, /* 2337: func */
            0, 0, 0, /* 2340: func */
            0, 8, 0, /* 2343: pointer.func */
            0, 0, 0, /* 2346: func */
            0, 0, 0, /* 2349: func */
            0, 8, 0, /* 2352: pointer.func */
            0, 0, 0, /* 2355: func */
        },
        .arg_entity_index = { 1894, 802, },
        .ret_entity_index = 11,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    const SSL * new_arg_a = *((const SSL * *)new_args->args[0]);

    int new_arg_b = *((int *)new_args->args[1]);

    void * *new_ret_ptr = (void * *)new_args->ret;

    void * (*orig_SSL_get_ex_data)(const SSL *,int);
    orig_SSL_get_ex_data = dlsym(RTLD_NEXT, "SSL_get_ex_data");
    *new_ret_ptr = (*orig_SSL_get_ex_data)(new_arg_a,new_arg_b);

    syscall(889);

    return ret;
}

