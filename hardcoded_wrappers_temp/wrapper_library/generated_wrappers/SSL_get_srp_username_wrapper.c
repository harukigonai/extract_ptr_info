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

char * bb_SSL_get_srp_username(SSL * arg_a);

char * SSL_get_srp_username(SSL * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_get_srp_username called %lu\n", in_lib);
    if (!in_lib)
        return bb_SSL_get_srp_username(arg_a);
    else {
        char * (*orig_SSL_get_srp_username)(SSL *);
        orig_SSL_get_srp_username = dlsym(RTLD_NEXT, "SSL_get_srp_username");
        return orig_SSL_get_srp_username(arg_a);
    }
}

char * bb_SSL_get_srp_username(SSL * arg_a) 
{
    char * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            4097, 0, 0, /* 0: pointer.func */
            0, 16, 1, /* 3: struct.tls_session_ticket_ext_st */
            	8, 8,
            1, 8, 1, /* 8: pointer.char */
            	4096, 0,
            4097, 0, 0, /* 13: pointer.func */
            0, 0, 0, /* 16: func */
            0, 0, 0, /* 19: func */
            0, 8, 1, /* 22: struct.ssl3_buf_freelist_entry_st */
            	27, 0,
            1, 8, 1, /* 27: pointer.struct.ssl3_buf_freelist_entry_st */
            	22, 0,
            1, 8, 1, /* 32: pointer.struct.ssl3_buf_freelist_st */
            	37, 0,
            0, 24, 1, /* 37: struct.ssl3_buf_freelist_st */
            	27, 16,
            0, 0, 0, /* 42: func */
            4097, 0, 0, /* 45: pointer.func */
            4097, 0, 0, /* 48: pointer.func */
            4097, 0, 0, /* 51: pointer.func */
            4097, 0, 0, /* 54: pointer.func */
            0, 0, 0, /* 57: func */
            4097, 0, 0, /* 60: pointer.func */
            0, 44, 0, /* 63: struct.apr_time_exp_t */
            0, 0, 0, /* 66: func */
            0, 0, 0, /* 69: func */
            4097, 0, 0, /* 72: pointer.func */
            1, 8, 1, /* 75: pointer.struct.in_addr */
            	80, 0,
            0, 4, 0, /* 80: struct.in_addr */
            4097, 0, 0, /* 83: pointer.func */
            0, 0, 0, /* 86: func */
            4097, 0, 0, /* 89: pointer.func */
            0, 736, 30, /* 92: struct.ssl_ctx_st */
            	155, 0,
            	177, 8,
            	177, 16,
            	197, 24,
            	75, 32,
            	240, 48,
            	240, 56,
            	8, 160,
            	8, 176,
            	235, 208,
            	700, 224,
            	700, 232,
            	700, 240,
            	177, 248,
            	177, 256,
            	177, 272,
            	950, 304,
            	8, 328,
            	215, 392,
            	503, 408,
            	8, 424,
            	8, 496,
            	8, 512,
            	8, 520,
            	32, 552,
            	32, 560,
            	968, 568,
            	8, 704,
            	8, 720,
            	177, 728,
            1, 8, 1, /* 155: pointer.struct.ssl_method_st */
            	160, 0,
            0, 232, 1, /* 160: struct.ssl_method_st */
            	165, 200,
            1, 8, 1, /* 165: pointer.struct.ssl3_enc_method */
            	170, 0,
            0, 112, 2, /* 170: struct.ssl3_enc_method */
            	8, 64,
            	8, 80,
            1, 8, 1, /* 177: pointer.struct.stack_st_OPENSSL_STRING */
            	182, 0,
            0, 32, 1, /* 182: struct.stack_st_OPENSSL_STRING */
            	187, 0,
            0, 32, 1, /* 187: struct.stack_st */
            	192, 8,
            1, 8, 1, /* 192: pointer.pointer.char */
            	8, 0,
            1, 8, 1, /* 197: pointer.struct.x509_store_st.74 */
            	202, 0,
            0, 144, 5, /* 202: struct.x509_store_st.74 */
            	177, 8,
            	177, 16,
            	215, 24,
            	227, 40,
            	235, 120,
            1, 8, 1, /* 215: pointer.struct.X509_VERIFY_PARAM_st */
            	220, 0,
            0, 56, 2, /* 220: struct.X509_VERIFY_PARAM_st */
            	8, 0,
            	177, 48,
            1, 8, 1, /* 227: pointer.struct.unnamed */
            	232, 0,
            0, 0, 0, /* 232: struct.unnamed */
            0, 16, 1, /* 235: struct.crypto_ex_data_st */
            	177, 0,
            1, 8, 1, /* 240: pointer.struct.ssl_session_st */
            	245, 0,
            0, 352, 14, /* 245: struct.ssl_session_st */
            	8, 144,
            	8, 152,
            	276, 168,
            	310, 176,
            	940, 224,
            	177, 240,
            	235, 248,
            	240, 264,
            	240, 272,
            	8, 280,
            	8, 296,
            	8, 312,
            	8, 320,
            	8, 344,
            1, 8, 1, /* 276: pointer.struct.sess_cert_st */
            	281, 0,
            0, 248, 6, /* 281: struct.sess_cert_st */
            	177, 0,
            	296, 16,
            	708, 24,
            	727, 216,
            	826, 224,
            	858, 232,
            1, 8, 1, /* 296: pointer.struct.cert_pkey_st */
            	301, 0,
            0, 24, 3, /* 301: struct.cert_pkey_st */
            	310, 0,
            	473, 8,
            	700, 16,
            1, 8, 1, /* 310: pointer.struct.x509_st */
            	315, 0,
            0, 184, 12, /* 315: struct.x509_st */
            	342, 0,
            	382, 8,
            	372, 16,
            	8, 32,
            	235, 40,
            	372, 104,
            	630, 112,
            	644, 120,
            	177, 128,
            	177, 136,
            	670, 144,
            	682, 176,
            1, 8, 1, /* 342: pointer.struct.x509_cinf_st */
            	347, 0,
            0, 104, 11, /* 347: struct.x509_cinf_st */
            	372, 0,
            	372, 8,
            	382, 16,
            	423, 24,
            	447, 32,
            	423, 40,
            	459, 48,
            	372, 56,
            	372, 64,
            	177, 72,
            	625, 80,
            1, 8, 1, /* 372: pointer.struct.asn1_string_st */
            	377, 0,
            0, 24, 1, /* 377: struct.asn1_string_st */
            	8, 8,
            1, 8, 1, /* 382: pointer.struct.X509_algor_st */
            	387, 0,
            0, 16, 2, /* 387: struct.X509_algor_st */
            	394, 0,
            	408, 8,
            1, 8, 1, /* 394: pointer.struct.asn1_object_st */
            	399, 0,
            0, 40, 3, /* 399: struct.asn1_object_st */
            	8, 0,
            	8, 8,
            	8, 24,
            1, 8, 1, /* 408: pointer.struct.asn1_type_st */
            	413, 0,
            0, 16, 1, /* 413: struct.asn1_type_st */
            	418, 8,
            0, 8, 1, /* 418: struct.fnames */
            	8, 0,
            1, 8, 1, /* 423: pointer.struct.X509_name_st */
            	428, 0,
            0, 40, 3, /* 428: struct.X509_name_st */
            	177, 0,
            	437, 16,
            	8, 24,
            1, 8, 1, /* 437: pointer.struct.buf_mem_st */
            	442, 0,
            0, 24, 1, /* 442: struct.buf_mem_st */
            	8, 8,
            1, 8, 1, /* 447: pointer.struct.X509_val_st */
            	452, 0,
            0, 16, 2, /* 452: struct.X509_val_st */
            	372, 0,
            	372, 8,
            1, 8, 1, /* 459: pointer.struct.X509_pubkey_st */
            	464, 0,
            0, 24, 3, /* 464: struct.X509_pubkey_st */
            	382, 0,
            	372, 8,
            	473, 16,
            1, 8, 1, /* 473: pointer.struct.evp_pkey_st */
            	478, 0,
            0, 56, 4, /* 478: struct.evp_pkey_st */
            	489, 16,
            	503, 24,
            	418, 32,
            	177, 48,
            1, 8, 1, /* 489: pointer.struct.evp_pkey_asn1_method_st */
            	494, 0,
            0, 208, 3, /* 494: struct.evp_pkey_asn1_method_st */
            	8, 16,
            	8, 24,
            	227, 32,
            1, 8, 1, /* 503: pointer.struct.engine_st */
            	508, 0,
            0, 216, 13, /* 508: struct.engine_st */
            	8, 0,
            	8, 8,
            	537, 16,
            	549, 24,
            	561, 32,
            	573, 40,
            	585, 48,
            	597, 56,
            	605, 64,
            	613, 160,
            	235, 184,
            	503, 200,
            	503, 208,
            1, 8, 1, /* 537: pointer.struct.rsa_meth_st */
            	542, 0,
            0, 112, 2, /* 542: struct.rsa_meth_st */
            	8, 0,
            	8, 80,
            1, 8, 1, /* 549: pointer.struct.dsa_method.1040 */
            	554, 0,
            0, 96, 2, /* 554: struct.dsa_method.1040 */
            	8, 0,
            	8, 72,
            1, 8, 1, /* 561: pointer.struct.dh_method */
            	566, 0,
            0, 72, 2, /* 566: struct.dh_method */
            	8, 0,
            	8, 56,
            1, 8, 1, /* 573: pointer.struct.ecdh_method */
            	578, 0,
            0, 32, 2, /* 578: struct.ecdh_method */
            	8, 0,
            	8, 24,
            1, 8, 1, /* 585: pointer.struct.ecdsa_method */
            	590, 0,
            0, 48, 2, /* 590: struct.ecdsa_method */
            	8, 0,
            	8, 40,
            1, 8, 1, /* 597: pointer.struct.rand_meth_st */
            	602, 0,
            0, 48, 0, /* 602: struct.rand_meth_st */
            1, 8, 1, /* 605: pointer.struct.store_method_st */
            	610, 0,
            0, 0, 0, /* 610: struct.store_method_st */
            1, 8, 1, /* 613: pointer.struct.ENGINE_CMD_DEFN_st */
            	618, 0,
            0, 32, 2, /* 618: struct.ENGINE_CMD_DEFN_st */
            	8, 8,
            	8, 16,
            0, 24, 1, /* 625: struct.ASN1_ENCODING_st */
            	8, 0,
            1, 8, 1, /* 630: pointer.struct.AUTHORITY_KEYID_st */
            	635, 0,
            0, 24, 3, /* 635: struct.AUTHORITY_KEYID_st */
            	372, 0,
            	177, 8,
            	372, 16,
            1, 8, 1, /* 644: pointer.struct.X509_POLICY_CACHE_st */
            	649, 0,
            0, 40, 2, /* 649: struct.X509_POLICY_CACHE_st */
            	656, 0,
            	177, 8,
            1, 8, 1, /* 656: pointer.struct.X509_POLICY_DATA_st */
            	661, 0,
            0, 32, 3, /* 661: struct.X509_POLICY_DATA_st */
            	394, 8,
            	177, 16,
            	177, 24,
            1, 8, 1, /* 670: pointer.struct.NAME_CONSTRAINTS_st */
            	675, 0,
            0, 16, 2, /* 675: struct.NAME_CONSTRAINTS_st */
            	177, 0,
            	177, 8,
            1, 8, 1, /* 682: pointer.struct.x509_cert_aux_st */
            	687, 0,
            0, 40, 5, /* 687: struct.x509_cert_aux_st */
            	177, 0,
            	177, 8,
            	372, 16,
            	372, 24,
            	177, 32,
            1, 8, 1, /* 700: pointer.struct.env_md_st */
            	705, 0,
            0, 120, 0, /* 705: struct.env_md_st */
            0, 192, 8, /* 708: array[8].struct.cert_pkey_st */
            	301, 0,
            	301, 24,
            	301, 48,
            	301, 72,
            	301, 96,
            	301, 120,
            	301, 144,
            	301, 168,
            1, 8, 1, /* 727: pointer.struct.rsa_st */
            	732, 0,
            0, 168, 17, /* 732: struct.rsa_st */
            	537, 16,
            	503, 24,
            	769, 32,
            	769, 40,
            	769, 48,
            	769, 56,
            	769, 64,
            	769, 72,
            	769, 80,
            	769, 88,
            	235, 96,
            	787, 120,
            	787, 128,
            	787, 136,
            	8, 144,
            	801, 152,
            	801, 160,
            1, 8, 1, /* 769: pointer.struct.bignum_st */
            	774, 0,
            0, 24, 1, /* 774: struct.bignum_st */
            	779, 0,
            1, 8, 1, /* 779: pointer.int */
            	784, 0,
            0, 4, 0, /* 784: int */
            1, 8, 1, /* 787: pointer.struct.bn_mont_ctx_st */
            	792, 0,
            0, 96, 3, /* 792: struct.bn_mont_ctx_st */
            	774, 8,
            	774, 32,
            	774, 56,
            1, 8, 1, /* 801: pointer.struct.bn_blinding_st */
            	806, 0,
            0, 88, 6, /* 806: struct.bn_blinding_st */
            	769, 0,
            	769, 8,
            	769, 16,
            	769, 24,
            	821, 40,
            	787, 72,
            0, 16, 1, /* 821: struct.iovec */
            	8, 0,
            1, 8, 1, /* 826: pointer.struct.dh_st */
            	831, 0,
            0, 144, 12, /* 831: struct.dh_st */
            	769, 8,
            	769, 16,
            	769, 32,
            	769, 40,
            	787, 56,
            	769, 64,
            	769, 72,
            	8, 80,
            	769, 96,
            	235, 112,
            	561, 128,
            	503, 136,
            1, 8, 1, /* 858: pointer.struct.ec_key_st.284 */
            	863, 0,
            0, 56, 4, /* 863: struct.ec_key_st.284 */
            	874, 8,
            	912, 16,
            	769, 24,
            	928, 48,
            1, 8, 1, /* 874: pointer.struct.ec_group_st */
            	879, 0,
            0, 232, 11, /* 879: struct.ec_group_st */
            	904, 0,
            	912, 8,
            	774, 16,
            	774, 40,
            	8, 80,
            	928, 96,
            	774, 104,
            	774, 152,
            	774, 176,
            	8, 208,
            	8, 216,
            1, 8, 1, /* 904: pointer.struct.ec_method_st */
            	909, 0,
            0, 304, 0, /* 909: struct.ec_method_st */
            1, 8, 1, /* 912: pointer.struct.ec_point_st */
            	917, 0,
            0, 88, 4, /* 917: struct.ec_point_st */
            	904, 0,
            	774, 8,
            	774, 32,
            	774, 56,
            1, 8, 1, /* 928: pointer.struct.ec_extra_data_st */
            	933, 0,
            0, 40, 2, /* 933: struct.ec_extra_data_st */
            	928, 0,
            	8, 8,
            1, 8, 1, /* 940: pointer.struct.ssl_cipher_st */
            	945, 0,
            0, 88, 1, /* 945: struct.ssl_cipher_st */
            	8, 8,
            1, 8, 1, /* 950: pointer.struct.cert_st */
            	955, 0,
            0, 296, 5, /* 955: struct.cert_st */
            	296, 0,
            	727, 48,
            	826, 64,
            	858, 80,
            	708, 96,
            0, 128, 11, /* 968: struct.srp_ctx_st */
            	8, 0,
            	8, 32,
            	769, 40,
            	769, 48,
            	769, 56,
            	769, 64,
            	769, 72,
            	769, 80,
            	769, 88,
            	769, 96,
            	8, 104,
            1, 8, 1, /* 993: pointer.struct.ssl_ctx_st */
            	92, 0,
            4097, 0, 0, /* 998: pointer.func */
            0, 0, 0, /* 1001: func */
            4097, 0, 0, /* 1004: pointer.func */
            4097, 0, 0, /* 1007: pointer.func */
            4097, 0, 0, /* 1010: pointer.func */
            0, 0, 0, /* 1013: func */
            4097, 0, 0, /* 1016: pointer.func */
            0, 0, 0, /* 1019: func */
            4097, 0, 0, /* 1022: pointer.func */
            0, 12, 0, /* 1025: struct.ap_unix_identity_t */
            0, 56, 2, /* 1028: struct.comp_ctx_st */
            	1035, 0,
            	235, 40,
            1, 8, 1, /* 1035: pointer.struct.comp_method_st */
            	1040, 0,
            0, 64, 1, /* 1040: struct.comp_method_st */
            	8, 8,
            0, 0, 0, /* 1045: func */
            1, 8, 1, /* 1048: pointer.struct.comp_ctx_st */
            	1028, 0,
            4097, 0, 0, /* 1053: pointer.func */
            0, 168, 4, /* 1056: struct.evp_cipher_ctx_st */
            	1067, 0,
            	503, 8,
            	8, 96,
            	8, 120,
            1, 8, 1, /* 1067: pointer.struct.evp_cipher_st */
            	1072, 0,
            0, 88, 1, /* 1072: struct.evp_cipher_st */
            	8, 80,
            1, 8, 1, /* 1077: pointer.struct._pitem */
            	1082, 0,
            0, 24, 2, /* 1082: struct._pitem */
            	8, 8,
            	1077, 16,
            0, 16, 0, /* 1089: union.anon.142 */
            0, 2, 0, /* 1092: short */
            0, 256, 0, /* 1095: array[256].char */
            1, 8, 1, /* 1098: pointer.struct.dtls1_state_st */
            	1103, 0,
            0, 888, 7, /* 1103: struct.dtls1_state_st */
            	1120, 576,
            	1120, 592,
            	1125, 608,
            	1125, 616,
            	1120, 624,
            	1135, 648,
            	1135, 736,
            0, 16, 1, /* 1120: struct.record_pqueue_st */
            	1125, 8,
            1, 8, 1, /* 1125: pointer.struct._pqueue */
            	1130, 0,
            0, 16, 1, /* 1130: struct._pqueue */
            	1077, 0,
            0, 88, 1, /* 1135: struct.hm_header_st */
            	1140, 48,
            0, 40, 4, /* 1140: struct.dtls1_retransmit_state */
            	1151, 0,
            	1156, 8,
            	1048, 16,
            	240, 24,
            1, 8, 1, /* 1151: pointer.struct.evp_cipher_ctx_st */
            	1056, 0,
            1, 8, 1, /* 1156: pointer.struct.env_md_ctx_st */
            	1161, 0,
            0, 48, 4, /* 1161: struct.env_md_ctx_st */
            	700, 0,
            	503, 8,
            	8, 24,
            	1172, 32,
            1, 8, 1, /* 1172: pointer.struct.evp_pkey_ctx_st */
            	1177, 0,
            0, 80, 8, /* 1177: struct.evp_pkey_ctx_st */
            	1196, 0,
            	503, 8,
            	473, 16,
            	473, 24,
            	8, 40,
            	8, 48,
            	227, 56,
            	779, 64,
            1, 8, 1, /* 1196: pointer.struct.evp_pkey_method_st */
            	1201, 0,
            0, 208, 9, /* 1201: struct.evp_pkey_method_st */
            	227, 8,
            	227, 32,
            	227, 48,
            	227, 64,
            	227, 80,
            	227, 96,
            	227, 144,
            	227, 160,
            	227, 176,
            0, 0, 0, /* 1222: func */
            0, 0, 0, /* 1225: func */
            4097, 0, 0, /* 1228: pointer.func */
            4097, 0, 0, /* 1231: pointer.func */
            0, 24, 2, /* 1234: struct.ssl_comp_st */
            	8, 8,
            	1035, 16,
            0, 0, 0, /* 1241: func */
            4097, 0, 0, /* 1244: pointer.func */
            4097, 0, 0, /* 1247: pointer.func */
            0, 0, 0, /* 1250: func */
            0, 0, 0, /* 1253: func */
            4097, 0, 0, /* 1256: pointer.func */
            0, 0, 0, /* 1259: func */
            4097, 0, 0, /* 1262: pointer.func */
            0, 0, 0, /* 1265: func */
            4097, 0, 0, /* 1268: pointer.func */
            0, 9, 0, /* 1271: array[9].char */
            0, 0, 0, /* 1274: func */
            4097, 0, 0, /* 1277: pointer.func */
            0, 0, 0, /* 1280: func */
            0, 0, 0, /* 1283: func */
            0, 0, 0, /* 1286: func */
            4097, 0, 0, /* 1289: pointer.func */
            4097, 0, 0, /* 1292: pointer.func */
            0, 0, 0, /* 1295: func */
            4097, 0, 0, /* 1298: pointer.func */
            0, 0, 0, /* 1301: func */
            4097, 0, 0, /* 1304: pointer.func */
            0, 0, 0, /* 1307: func */
            4097, 0, 0, /* 1310: pointer.func */
            0, 0, 0, /* 1313: func */
            4097, 0, 0, /* 1316: pointer.func */
            0, 0, 0, /* 1319: func */
            0, 0, 0, /* 1322: func */
            4097, 0, 0, /* 1325: pointer.func */
            0, 0, 0, /* 1328: func */
            4097, 0, 0, /* 1331: pointer.func */
            0, 0, 0, /* 1334: func */
            4097, 0, 0, /* 1337: pointer.func */
            0, 0, 0, /* 1340: func */
            0, 0, 0, /* 1343: func */
            4097, 0, 0, /* 1346: pointer.func */
            0, 0, 0, /* 1349: func */
            0, 0, 0, /* 1352: func */
            0, 0, 0, /* 1355: func */
            4097, 0, 0, /* 1358: pointer.func */
            0, 0, 0, /* 1361: func */
            0, 0, 0, /* 1364: func */
            0, 8, 0, /* 1367: array[2].int */
            4097, 0, 0, /* 1370: pointer.func */
            4097, 0, 0, /* 1373: pointer.func */
            0, 12, 0, /* 1376: array[12].char */
            0, 128, 0, /* 1379: array[128].char */
            0, 528, 8, /* 1382: struct.anon.0 */
            	940, 408,
            	826, 416,
            	858, 424,
            	177, 464,
            	8, 480,
            	1067, 488,
            	700, 496,
            	1401, 512,
            1, 8, 1, /* 1401: pointer.struct.ssl_comp_st */
            	1234, 0,
            0, 24, 0, /* 1406: array[6].int */
            4097, 0, 0, /* 1409: pointer.func */
            0, 0, 0, /* 1412: func */
            0, 0, 0, /* 1415: func */
            4097, 0, 0, /* 1418: pointer.func */
            0, 0, 0, /* 1421: func */
            4097, 0, 0, /* 1424: pointer.func */
            0, 0, 0, /* 1427: func */
            4097, 0, 0, /* 1430: pointer.func */
            0, 0, 0, /* 1433: func */
            4097, 0, 0, /* 1436: pointer.func */
            4097, 0, 0, /* 1439: pointer.func */
            0, 0, 0, /* 1442: func */
            4097, 0, 0, /* 1445: pointer.func */
            4097, 0, 0, /* 1448: pointer.func */
            0, 0, 0, /* 1451: func */
            0, 0, 0, /* 1454: func */
            0, 0, 0, /* 1457: func */
            0, 0, 0, /* 1460: func */
            4097, 0, 0, /* 1463: pointer.func */
            4097, 0, 0, /* 1466: pointer.func */
            0, 16, 0, /* 1469: array[16].char */
            0, 0, 0, /* 1472: func */
            1, 8, 1, /* 1475: pointer.pointer.struct.env_md_ctx_st */
            	1156, 0,
            0, 0, 0, /* 1480: func */
            0, 0, 0, /* 1483: func */
            0, 0, 0, /* 1486: func */
            0, 56, 3, /* 1489: struct.ssl3_record_st */
            	8, 16,
            	8, 24,
            	8, 32,
            0, 0, 0, /* 1498: func */
            0, 2, 0, /* 1501: array[2].char */
            0, 72, 0, /* 1504: struct.anon.25 */
            0, 48, 0, /* 1507: array[48].char */
            0, 1200, 10, /* 1510: struct.ssl3_state_st */
            	1533, 240,
            	1533, 264,
            	1489, 288,
            	1489, 344,
            	8, 432,
            	1538, 440,
            	1475, 448,
            	8, 496,
            	8, 512,
            	1382, 528,
            0, 24, 1, /* 1533: struct.ssl3_buffer_st */
            	8, 0,
            1, 8, 1, /* 1538: pointer.struct.bio_st */
            	1543, 0,
            0, 112, 6, /* 1543: struct.bio_st */
            	1558, 0,
            	8, 16,
            	8, 48,
            	1538, 56,
            	1538, 64,
            	235, 96,
            1, 8, 1, /* 1558: pointer.struct.bio_method_st */
            	1563, 0,
            0, 80, 1, /* 1563: struct.bio_method_st */
            	8, 8,
            4097, 0, 0, /* 1568: pointer.func */
            0, 0, 0, /* 1571: func */
            0, 344, 9, /* 1574: struct.ssl2_state_st */
            	8, 24,
            	8, 56,
            	8, 64,
            	8, 72,
            	8, 104,
            	8, 112,
            	8, 120,
            	8, 128,
            	8, 136,
            4097, 0, 0, /* 1595: pointer.func */
            4097, 0, 0, /* 1598: pointer.func */
            4097, 0, 0, /* 1601: pointer.func */
            0, 0, 0, /* 1604: func */
            4097, 0, 0, /* 1607: pointer.func */
            0, 0, 0, /* 1610: func */
            0, 0, 0, /* 1613: func */
            0, 8, 0, /* 1616: long */
            4097, 0, 0, /* 1619: pointer.func */
            4097, 0, 0, /* 1622: pointer.func */
            0, 0, 0, /* 1625: func */
            0, 0, 0, /* 1628: func */
            0, 0, 0, /* 1631: func */
            0, 0, 0, /* 1634: func */
            4097, 0, 0, /* 1637: pointer.func */
            0, 0, 0, /* 1640: func */
            4097, 0, 0, /* 1643: pointer.func */
            4097, 0, 0, /* 1646: pointer.func */
            0, 0, 0, /* 1649: func */
            0, 0, 0, /* 1652: func */
            0, 0, 0, /* 1655: func */
            0, 0, 0, /* 1658: func */
            4097, 0, 0, /* 1661: pointer.func */
            0, 0, 0, /* 1664: func */
            4097, 0, 0, /* 1667: pointer.func */
            4097, 0, 0, /* 1670: pointer.func */
            0, 0, 0, /* 1673: func */
            0, 0, 0, /* 1676: func */
            0, 0, 0, /* 1679: func */
            0, 0, 0, /* 1682: func */
            4097, 0, 0, /* 1685: pointer.func */
            4097, 0, 0, /* 1688: pointer.func */
            0, 0, 0, /* 1691: func */
            0, 0, 0, /* 1694: func */
            0, 4, 0, /* 1697: array[4].char */
            4097, 0, 0, /* 1700: pointer.func */
            0, 0, 0, /* 1703: func */
            0, 0, 0, /* 1706: func */
            0, 0, 0, /* 1709: func */
            0, 0, 0, /* 1712: func */
            4097, 0, 0, /* 1715: pointer.func */
            4097, 0, 0, /* 1718: pointer.func */
            0, 20, 0, /* 1721: array[5].int */
            0, 1, 0, /* 1724: char */
            0, 0, 0, /* 1727: func */
            0, 0, 0, /* 1730: func */
            0, 0, 0, /* 1733: func */
            4097, 0, 0, /* 1736: pointer.func */
            0, 0, 0, /* 1739: func */
            0, 0, 0, /* 1742: func */
            4097, 0, 0, /* 1745: pointer.func */
            4097, 0, 0, /* 1748: pointer.func */
            0, 0, 0, /* 1751: func */
            4097, 0, 0, /* 1754: pointer.func */
            0, 0, 0, /* 1757: func */
            0, 0, 0, /* 1760: func */
            0, 0, 0, /* 1763: func */
            0, 0, 0, /* 1766: func */
            4097, 0, 0, /* 1769: pointer.func */
            4097, 0, 0, /* 1772: pointer.func */
            0, 0, 0, /* 1775: func */
            0, 0, 0, /* 1778: func */
            0, 0, 0, /* 1781: func */
            0, 0, 0, /* 1784: func */
            4097, 0, 0, /* 1787: pointer.func */
            0, 0, 0, /* 1790: func */
            0, 8, 0, /* 1793: array[8].char */
            0, 0, 0, /* 1796: func */
            4097, 0, 0, /* 1799: pointer.func */
            0, 0, 0, /* 1802: func */
            4097, 0, 0, /* 1805: pointer.func */
            4097, 0, 0, /* 1808: pointer.func */
            1, 8, 1, /* 1811: pointer.struct.ssl2_state_st */
            	1574, 0,
            1, 8, 1, /* 1816: pointer.struct.ssl_st */
            	1821, 0,
            0, 808, 42, /* 1821: struct.ssl_st */
            	155, 8,
            	1538, 16,
            	1538, 24,
            	1538, 32,
            	227, 48,
            	437, 80,
            	8, 88,
            	8, 104,
            	1811, 120,
            	1908, 128,
            	1098, 136,
            	8, 160,
            	215, 176,
            	177, 184,
            	177, 192,
            	1151, 208,
            	1156, 216,
            	1048, 224,
            	1151, 232,
            	1156, 240,
            	1048, 248,
            	950, 256,
            	240, 304,
            	993, 368,
            	235, 392,
            	177, 408,
            	8, 472,
            	8, 480,
            	177, 504,
            	177, 512,
            	8, 520,
            	8, 544,
            	8, 560,
            	8, 568,
            	1913, 584,
            	8, 600,
            	8, 616,
            	993, 624,
            	8, 632,
            	177, 648,
            	1918, 656,
            	968, 680,
            1, 8, 1, /* 1908: pointer.struct.ssl3_state_st */
            	1510, 0,
            1, 8, 1, /* 1913: pointer.struct.tls_session_ticket_ext_st */
            	3, 0,
            1, 8, 1, /* 1918: pointer.struct.iovec */
            	821, 0,
            0, 0, 0, /* 1923: func */
            0, 0, 0, /* 1926: func */
            0, 32, 0, /* 1929: array[32].char */
            4097, 0, 0, /* 1932: pointer.func */
            4097, 0, 0, /* 1935: pointer.func */
            4097, 0, 0, /* 1938: pointer.func */
            4097, 0, 0, /* 1941: pointer.func */
            4097, 0, 0, /* 1944: pointer.func */
            0, 0, 0, /* 1947: func */
            4097, 0, 0, /* 1950: pointer.func */
            0, 0, 0, /* 1953: func */
            0, 0, 0, /* 1956: func */
            4097, 0, 0, /* 1959: pointer.func */
            4097, 0, 0, /* 1962: pointer.func */
            0, 0, 0, /* 1965: func */
            4097, 0, 0, /* 1968: pointer.func */
            4097, 0, 0, /* 1971: pointer.func */
            4097, 0, 0, /* 1974: pointer.func */
            4097, 0, 0, /* 1977: pointer.func */
            4097, 0, 0, /* 1980: pointer.func */
            4097, 0, 0, /* 1983: pointer.func */
            4097, 0, 0, /* 1986: pointer.func */
            4097, 0, 0, /* 1989: pointer.func */
            4097, 0, 0, /* 1992: pointer.func */
            4097, 0, 0, /* 1995: pointer.func */
            0, 0, 0, /* 1998: func */
            4097, 0, 0, /* 2001: pointer.func */
            4097, 0, 0, /* 2004: pointer.func */
            4097, 0, 0, /* 2007: pointer.func */
            4097, 0, 0, /* 2010: pointer.func */
            4097, 0, 0, /* 2013: pointer.func */
            0, 0, 0, /* 2016: func */
            0, 0, 0, /* 2019: func */
            0, 0, 0, /* 2022: func */
            4097, 0, 0, /* 2025: pointer.func */
            4097, 0, 0, /* 2028: pointer.func */
            0, 0, 0, /* 2031: func */
            4097, 0, 0, /* 2034: pointer.func */
            4097, 0, 0, /* 2037: pointer.func */
            4097, 0, 0, /* 2040: pointer.func */
            4097, 0, 0, /* 2043: pointer.func */
            4097, 0, 0, /* 2046: pointer.func */
            4097, 0, 0, /* 2049: pointer.func */
            4097, 0, 0, /* 2052: pointer.func */
            0, 0, 0, /* 2055: func */
            0, 0, 0, /* 2058: func */
            4097, 0, 0, /* 2061: pointer.func */
            0, 0, 0, /* 2064: func */
            0, 0, 0, /* 2067: func */
            4097, 0, 0, /* 2070: pointer.func */
            0, 0, 0, /* 2073: func */
            0, 0, 0, /* 2076: func */
            4097, 0, 0, /* 2079: pointer.func */
            4097, 0, 0, /* 2082: pointer.func */
            0, 0, 0, /* 2085: func */
            4097, 0, 0, /* 2088: pointer.func */
            4097, 0, 0, /* 2091: pointer.func */
            0, 0, 0, /* 2094: func */
            4097, 0, 0, /* 2097: pointer.func */
            0, 0, 0, /* 2100: func */
            4097, 0, 0, /* 2103: pointer.func */
            0, 0, 0, /* 2106: func */
            0, 0, 0, /* 2109: func */
            4097, 0, 0, /* 2112: pointer.func */
            0, 0, 0, /* 2115: func */
            0, 64, 0, /* 2118: array[64].char */
            4097, 0, 0, /* 2121: pointer.func */
            4097, 0, 0, /* 2124: pointer.func */
            4097, 0, 0, /* 2127: pointer.func */
            4097, 0, 0, /* 2130: pointer.func */
            4097, 0, 0, /* 2133: pointer.func */
            0, 0, 0, /* 2136: func */
            0, 0, 0, /* 2139: func */
            4097, 0, 0, /* 2142: pointer.func */
            0, 0, 0, /* 2145: func */
            0, 0, 0, /* 2148: func */
            4097, 0, 0, /* 2151: pointer.func */
            0, 0, 0, /* 2154: func */
            0, 0, 0, /* 2157: func */
            0, 0, 0, /* 2160: func */
            4097, 0, 0, /* 2163: pointer.func */
            0, 0, 0, /* 2166: func */
            4097, 0, 0, /* 2169: pointer.func */
            0, 20, 0, /* 2172: array[20].char */
            4097, 0, 0, /* 2175: pointer.func */
            0, 0, 0, /* 2178: func */
            4097, 0, 0, /* 2181: pointer.func */
            4097, 0, 0, /* 2184: pointer.func */
            4097, 0, 0, /* 2187: pointer.func */
            4097, 0, 0, /* 2190: pointer.func */
            0, 0, 0, /* 2193: func */
            4097, 0, 0, /* 2196: pointer.func */
            4097, 0, 0, /* 2199: pointer.func */
            0, 0, 0, /* 2202: func */
            4097, 0, 0, /* 2205: pointer.func */
            4097, 0, 0, /* 2208: pointer.func */
            0, 0, 0, /* 2211: func */
            0, 0, 0, /* 2214: func */
            4097, 0, 0, /* 2217: pointer.func */
            0, 0, 0, /* 2220: func */
            4097, 0, 0, /* 2223: pointer.func */
            0, 0, 0, /* 2226: func */
            0, 0, 0, /* 2229: func */
            4097, 0, 0, /* 2232: pointer.func */
            4097, 0, 0, /* 2235: pointer.func */
            0, 0, 0, /* 2238: func */
            4097, 0, 0, /* 2241: pointer.func */
            0, 0, 0, /* 2244: func */
            0, 0, 0, /* 2247: func */
            4097, 0, 0, /* 2250: pointer.func */
            4097, 0, 0, /* 2253: pointer.func */
            0, 0, 0, /* 2256: func */
            0, 0, 0, /* 2259: func */
            4097, 0, 0, /* 2262: pointer.func */
            0, 16, 0, /* 2265: struct.rlimit */
            0, 0, 0, /* 2268: func */
            0, 0, 0, /* 2271: func */
            4097, 0, 0, /* 2274: pointer.func */
            4097, 0, 0, /* 2277: pointer.func */
            0, 0, 0, /* 2280: func */
            4097, 0, 0, /* 2283: pointer.func */
            0, 0, 0, /* 2286: func */
            0, 0, 0, /* 2289: func */
            4097, 0, 0, /* 2292: pointer.func */
            0, 0, 0, /* 2295: func */
            0, 0, 0, /* 2298: func */
            4097, 0, 0, /* 2301: pointer.func */
            0, 0, 0, /* 2304: func */
            0, 0, 0, /* 2307: func */
            0, 0, 0, /* 2310: func */
            0, 0, 0, /* 2313: func */
            0, 0, 0, /* 2316: func */
            0, 0, 0, /* 2319: func */
            0, 0, 0, /* 2322: func */
            0, 0, 0, /* 2325: func */
            0, 0, 0, /* 2328: func */
            4097, 0, 0, /* 2331: pointer.func */
            4097, 0, 0, /* 2334: pointer.func */
            4097, 0, 0, /* 2337: pointer.func */
            4097, 0, 0, /* 2340: pointer.func */
            4097, 0, 0, /* 2343: pointer.func */
            0, 0, 0, /* 2346: func */
            0, 0, 0, /* 2349: func */
            4097, 0, 0, /* 2352: pointer.func */
            0, 0, 0, /* 2355: func */
            4097, 0, 0, /* 2358: pointer.func */
            4097, 0, 0, /* 2361: pointer.func */
        },
        .arg_entity_index = { 1816, },
        .ret_entity_index = 8,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    SSL * new_arg_a = *((SSL * *)new_args->args[0]);

    char * *new_ret_ptr = (char * *)new_args->ret;

    char * (*orig_SSL_get_srp_username)(SSL *);
    orig_SSL_get_srp_username = dlsym(RTLD_NEXT, "SSL_get_srp_username");
    *new_ret_ptr = (*orig_SSL_get_srp_username)(new_arg_a);

    syscall(889);

    return ret;
}

