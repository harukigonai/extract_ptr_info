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
    printf("SSL_get_srp_username called\n");
    if (!syscall(890))
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
            0, 0, 0, /* 0: func */
            0, 16, 1, /* 3: struct.tls_session_ticket_ext_st */
            	8, 8,
            1, 8, 1, /* 8: pointer.char */
            	13, 0,
            0, 1, 0, /* 13: char */
            0, 8, 0, /* 16: pointer.func */
            0, 8, 0, /* 19: pointer.func */
            1, 8, 1, /* 22: pointer.struct.ssl3_buf_freelist_entry_st */
            	27, 0,
            0, 8, 1, /* 27: struct.ssl3_buf_freelist_entry_st */
            	22, 0,
            0, 0, 0, /* 32: func */
            0, 0, 0, /* 35: func */
            0, 0, 0, /* 38: func */
            0, 8, 0, /* 41: pointer.func */
            0, 8, 0, /* 44: pointer.func */
            0, 0, 0, /* 47: func */
            0, 44, 0, /* 50: struct.apr_time_exp_t */
            0, 8, 0, /* 53: pointer.func */
            0, 8, 0, /* 56: pointer.func */
            0, 4, 0, /* 59: struct.in_addr */
            0, 0, 0, /* 62: func */
            0, 8, 0, /* 65: pointer.func */
            0, 0, 0, /* 68: func */
            0, 144, 5, /* 71: struct.x509_store_st.74 */
            	84, 8,
            	84, 16,
            	104, 24,
            	116, 40,
            	124, 120,
            1, 8, 1, /* 84: pointer.struct.stack_st_OPENSSL_STRING */
            	89, 0,
            0, 32, 1, /* 89: struct.stack_st_OPENSSL_STRING */
            	94, 0,
            0, 32, 1, /* 94: struct.stack_st */
            	99, 8,
            1, 8, 1, /* 99: pointer.pointer.char */
            	8, 0,
            1, 8, 1, /* 104: pointer.struct.X509_VERIFY_PARAM_st */
            	109, 0,
            0, 56, 2, /* 109: struct.X509_VERIFY_PARAM_st */
            	8, 0,
            	84, 48,
            1, 8, 1, /* 116: pointer.struct.unnamed */
            	121, 0,
            0, 0, 0, /* 121: struct.unnamed */
            0, 16, 1, /* 124: struct.crypto_ex_data_st */
            	84, 0,
            0, 8, 0, /* 129: pointer.func */
            0, 8, 0, /* 132: pointer.func */
            0, 8, 0, /* 135: pointer.func */
            0, 8, 0, /* 138: pointer.func */
            0, 8, 0, /* 141: pointer.func */
            0, 8, 0, /* 144: pointer.func */
            0, 0, 0, /* 147: func */
            0, 8, 0, /* 150: pointer.func */
            0, 0, 0, /* 153: func */
            0, 0, 0, /* 156: func */
            0, 0, 0, /* 159: func */
            1, 8, 1, /* 162: pointer.struct.in_addr */
            	59, 0,
            0, 12, 0, /* 167: array[12].char */
            0, 12, 0, /* 170: struct.ap_unix_identity_t */
            0, 88, 6, /* 173: struct.bn_blinding_st */
            	188, 0,
            	188, 8,
            	188, 16,
            	188, 24,
            	206, 40,
            	211, 72,
            1, 8, 1, /* 188: pointer.struct.bignum_st */
            	193, 0,
            0, 24, 1, /* 193: struct.bignum_st */
            	198, 0,
            1, 8, 1, /* 198: pointer.int */
            	203, 0,
            0, 4, 0, /* 203: int */
            0, 16, 1, /* 206: struct.iovec */
            	8, 0,
            1, 8, 1, /* 211: pointer.struct.bn_mont_ctx_st */
            	216, 0,
            0, 96, 3, /* 216: struct.bn_mont_ctx_st */
            	193, 8,
            	193, 32,
            	193, 56,
            0, 0, 0, /* 225: func */
            0, 40, 5, /* 228: struct.x509_cert_aux_st */
            	84, 0,
            	84, 8,
            	241, 16,
            	241, 24,
            	84, 32,
            1, 8, 1, /* 241: pointer.struct.asn1_string_st */
            	246, 0,
            0, 24, 1, /* 246: struct.asn1_string_st */
            	8, 8,
            0, 8, 0, /* 251: pointer.func */
            1, 8, 1, /* 254: pointer.struct.NAME_CONSTRAINTS_st */
            	259, 0,
            0, 16, 2, /* 259: struct.NAME_CONSTRAINTS_st */
            	84, 0,
            	84, 8,
            0, 32, 3, /* 266: struct.X509_POLICY_DATA_st */
            	275, 8,
            	84, 16,
            	84, 24,
            1, 8, 1, /* 275: pointer.struct.asn1_object_st */
            	280, 0,
            0, 40, 3, /* 280: struct.asn1_object_st */
            	8, 0,
            	8, 8,
            	8, 24,
            0, 0, 0, /* 289: func */
            1, 8, 1, /* 292: pointer.struct.X509_POLICY_DATA_st */
            	266, 0,
            0, 16, 0, /* 297: struct.rlimit */
            0, 40, 2, /* 300: struct.X509_POLICY_CACHE_st */
            	292, 0,
            	84, 8,
            1, 8, 1, /* 307: pointer.struct.ssl_ctx_st */
            	312, 0,
            0, 736, 30, /* 312: struct.ssl_ctx_st */
            	375, 0,
            	84, 8,
            	84, 16,
            	397, 24,
            	162, 32,
            	402, 48,
            	402, 56,
            	8, 160,
            	8, 176,
            	124, 208,
            	792, 224,
            	792, 232,
            	792, 240,
            	84, 248,
            	84, 256,
            	84, 272,
            	990, 304,
            	8, 328,
            	104, 392,
            	641, 408,
            	8, 424,
            	8, 496,
            	8, 512,
            	8, 520,
            	1008, 552,
            	1008, 560,
            	1018, 568,
            	8, 704,
            	8, 720,
            	84, 728,
            1, 8, 1, /* 375: pointer.struct.ssl_method_st */
            	380, 0,
            0, 232, 1, /* 380: struct.ssl_method_st */
            	385, 200,
            1, 8, 1, /* 385: pointer.struct.ssl3_enc_method */
            	390, 0,
            0, 112, 2, /* 390: struct.ssl3_enc_method */
            	8, 64,
            	8, 80,
            1, 8, 1, /* 397: pointer.struct.x509_store_st.74 */
            	71, 0,
            1, 8, 1, /* 402: pointer.struct.ssl_session_st */
            	407, 0,
            0, 352, 14, /* 407: struct.ssl_session_st */
            	8, 144,
            	8, 152,
            	438, 168,
            	472, 176,
            	980, 224,
            	84, 240,
            	124, 248,
            	402, 264,
            	402, 272,
            	8, 280,
            	8, 296,
            	8, 312,
            	8, 320,
            	8, 344,
            1, 8, 1, /* 438: pointer.struct.sess_cert_st */
            	443, 0,
            0, 248, 6, /* 443: struct.sess_cert_st */
            	84, 0,
            	458, 16,
            	800, 24,
            	819, 216,
            	866, 224,
            	898, 232,
            1, 8, 1, /* 458: pointer.struct.cert_pkey_st */
            	463, 0,
            0, 24, 3, /* 463: struct.cert_pkey_st */
            	472, 0,
            	611, 8,
            	792, 16,
            1, 8, 1, /* 472: pointer.struct.x509_st */
            	477, 0,
            0, 184, 12, /* 477: struct.x509_st */
            	504, 0,
            	534, 8,
            	241, 16,
            	8, 32,
            	124, 40,
            	241, 104,
            	768, 112,
            	782, 120,
            	84, 128,
            	84, 136,
            	254, 144,
            	787, 176,
            1, 8, 1, /* 504: pointer.struct.x509_cinf_st */
            	509, 0,
            0, 104, 11, /* 509: struct.x509_cinf_st */
            	241, 0,
            	241, 8,
            	534, 16,
            	561, 24,
            	585, 32,
            	561, 40,
            	597, 48,
            	241, 56,
            	241, 64,
            	84, 72,
            	763, 80,
            1, 8, 1, /* 534: pointer.struct.X509_algor_st */
            	539, 0,
            0, 16, 2, /* 539: struct.X509_algor_st */
            	275, 0,
            	546, 8,
            1, 8, 1, /* 546: pointer.struct.asn1_type_st */
            	551, 0,
            0, 16, 1, /* 551: struct.asn1_type_st */
            	556, 8,
            0, 8, 1, /* 556: struct.fnames */
            	8, 0,
            1, 8, 1, /* 561: pointer.struct.X509_name_st */
            	566, 0,
            0, 40, 3, /* 566: struct.X509_name_st */
            	84, 0,
            	575, 16,
            	8, 24,
            1, 8, 1, /* 575: pointer.struct.buf_mem_st */
            	580, 0,
            0, 24, 1, /* 580: struct.buf_mem_st */
            	8, 8,
            1, 8, 1, /* 585: pointer.struct.X509_val_st */
            	590, 0,
            0, 16, 2, /* 590: struct.X509_val_st */
            	241, 0,
            	241, 8,
            1, 8, 1, /* 597: pointer.struct.X509_pubkey_st */
            	602, 0,
            0, 24, 3, /* 602: struct.X509_pubkey_st */
            	534, 0,
            	241, 8,
            	611, 16,
            1, 8, 1, /* 611: pointer.struct.evp_pkey_st */
            	616, 0,
            0, 56, 4, /* 616: struct.evp_pkey_st */
            	627, 16,
            	641, 24,
            	556, 32,
            	84, 48,
            1, 8, 1, /* 627: pointer.struct.evp_pkey_asn1_method_st */
            	632, 0,
            0, 208, 3, /* 632: struct.evp_pkey_asn1_method_st */
            	8, 16,
            	8, 24,
            	116, 32,
            1, 8, 1, /* 641: pointer.struct.engine_st */
            	646, 0,
            0, 216, 13, /* 646: struct.engine_st */
            	8, 0,
            	8, 8,
            	675, 16,
            	687, 24,
            	699, 32,
            	711, 40,
            	723, 48,
            	735, 56,
            	743, 64,
            	751, 160,
            	124, 184,
            	641, 200,
            	641, 208,
            1, 8, 1, /* 675: pointer.struct.rsa_meth_st */
            	680, 0,
            0, 112, 2, /* 680: struct.rsa_meth_st */
            	8, 0,
            	8, 80,
            1, 8, 1, /* 687: pointer.struct.dsa_method.1040 */
            	692, 0,
            0, 96, 2, /* 692: struct.dsa_method.1040 */
            	8, 0,
            	8, 72,
            1, 8, 1, /* 699: pointer.struct.dh_method */
            	704, 0,
            0, 72, 2, /* 704: struct.dh_method */
            	8, 0,
            	8, 56,
            1, 8, 1, /* 711: pointer.struct.ecdh_method */
            	716, 0,
            0, 32, 2, /* 716: struct.ecdh_method */
            	8, 0,
            	8, 24,
            1, 8, 1, /* 723: pointer.struct.ecdsa_method */
            	728, 0,
            0, 48, 2, /* 728: struct.ecdsa_method */
            	8, 0,
            	8, 40,
            1, 8, 1, /* 735: pointer.struct.rand_meth_st */
            	740, 0,
            0, 48, 0, /* 740: struct.rand_meth_st */
            1, 8, 1, /* 743: pointer.struct.store_method_st */
            	748, 0,
            0, 0, 0, /* 748: struct.store_method_st */
            1, 8, 1, /* 751: pointer.struct.ENGINE_CMD_DEFN_st */
            	756, 0,
            0, 32, 2, /* 756: struct.ENGINE_CMD_DEFN_st */
            	8, 8,
            	8, 16,
            0, 24, 1, /* 763: struct.ASN1_ENCODING_st */
            	8, 0,
            1, 8, 1, /* 768: pointer.struct.AUTHORITY_KEYID_st */
            	773, 0,
            0, 24, 3, /* 773: struct.AUTHORITY_KEYID_st */
            	241, 0,
            	84, 8,
            	241, 16,
            1, 8, 1, /* 782: pointer.struct.X509_POLICY_CACHE_st */
            	300, 0,
            1, 8, 1, /* 787: pointer.struct.x509_cert_aux_st */
            	228, 0,
            1, 8, 1, /* 792: pointer.struct.env_md_st */
            	797, 0,
            0, 120, 0, /* 797: struct.env_md_st */
            0, 192, 8, /* 800: array[8].struct.cert_pkey_st */
            	463, 0,
            	463, 24,
            	463, 48,
            	463, 72,
            	463, 96,
            	463, 120,
            	463, 144,
            	463, 168,
            1, 8, 1, /* 819: pointer.struct.rsa_st */
            	824, 0,
            0, 168, 17, /* 824: struct.rsa_st */
            	675, 16,
            	641, 24,
            	188, 32,
            	188, 40,
            	188, 48,
            	188, 56,
            	188, 64,
            	188, 72,
            	188, 80,
            	188, 88,
            	124, 96,
            	211, 120,
            	211, 128,
            	211, 136,
            	8, 144,
            	861, 152,
            	861, 160,
            1, 8, 1, /* 861: pointer.struct.bn_blinding_st */
            	173, 0,
            1, 8, 1, /* 866: pointer.struct.dh_st */
            	871, 0,
            0, 144, 12, /* 871: struct.dh_st */
            	188, 8,
            	188, 16,
            	188, 32,
            	188, 40,
            	211, 56,
            	188, 64,
            	188, 72,
            	8, 80,
            	188, 96,
            	124, 112,
            	699, 128,
            	641, 136,
            1, 8, 1, /* 898: pointer.struct.ec_key_st.284 */
            	903, 0,
            0, 56, 4, /* 903: struct.ec_key_st.284 */
            	914, 8,
            	952, 16,
            	188, 24,
            	968, 48,
            1, 8, 1, /* 914: pointer.struct.ec_group_st */
            	919, 0,
            0, 232, 11, /* 919: struct.ec_group_st */
            	944, 0,
            	952, 8,
            	193, 16,
            	193, 40,
            	8, 80,
            	968, 96,
            	193, 104,
            	193, 152,
            	193, 176,
            	8, 208,
            	8, 216,
            1, 8, 1, /* 944: pointer.struct.ec_method_st */
            	949, 0,
            0, 304, 0, /* 949: struct.ec_method_st */
            1, 8, 1, /* 952: pointer.struct.ec_point_st */
            	957, 0,
            0, 88, 4, /* 957: struct.ec_point_st */
            	944, 0,
            	193, 8,
            	193, 32,
            	193, 56,
            1, 8, 1, /* 968: pointer.struct.ec_extra_data_st */
            	973, 0,
            0, 40, 2, /* 973: struct.ec_extra_data_st */
            	968, 0,
            	8, 8,
            1, 8, 1, /* 980: pointer.struct.ssl_cipher_st */
            	985, 0,
            0, 88, 1, /* 985: struct.ssl_cipher_st */
            	8, 8,
            1, 8, 1, /* 990: pointer.struct.cert_st */
            	995, 0,
            0, 296, 5, /* 995: struct.cert_st */
            	458, 0,
            	819, 48,
            	866, 64,
            	898, 80,
            	800, 96,
            1, 8, 1, /* 1008: pointer.struct.ssl3_buf_freelist_st */
            	1013, 0,
            0, 24, 1, /* 1013: struct.ssl3_buf_freelist_st */
            	22, 16,
            0, 128, 11, /* 1018: struct.srp_ctx_st */
            	8, 0,
            	8, 32,
            	188, 40,
            	188, 48,
            	188, 56,
            	188, 64,
            	188, 72,
            	188, 80,
            	188, 88,
            	188, 96,
            	8, 104,
            0, 8, 0, /* 1043: pointer.func */
            0, 56, 2, /* 1046: struct.comp_ctx_st */
            	1053, 0,
            	124, 40,
            1, 8, 1, /* 1053: pointer.struct.comp_method_st */
            	1058, 0,
            0, 64, 1, /* 1058: struct.comp_method_st */
            	8, 8,
            0, 168, 4, /* 1063: struct.evp_cipher_ctx_st */
            	1074, 0,
            	641, 8,
            	8, 96,
            	8, 120,
            1, 8, 1, /* 1074: pointer.struct.evp_cipher_st */
            	1079, 0,
            0, 88, 1, /* 1079: struct.evp_cipher_st */
            	8, 80,
            1, 8, 1, /* 1084: pointer.struct.evp_cipher_ctx_st */
            	1063, 0,
            0, 40, 4, /* 1089: struct.dtls1_retransmit_state */
            	1084, 0,
            	1100, 8,
            	1166, 16,
            	402, 24,
            1, 8, 1, /* 1100: pointer.struct.env_md_ctx_st */
            	1105, 0,
            0, 48, 4, /* 1105: struct.env_md_ctx_st */
            	792, 0,
            	641, 8,
            	8, 24,
            	1116, 32,
            1, 8, 1, /* 1116: pointer.struct.evp_pkey_ctx_st */
            	1121, 0,
            0, 80, 8, /* 1121: struct.evp_pkey_ctx_st */
            	1140, 0,
            	641, 8,
            	611, 16,
            	611, 24,
            	8, 40,
            	8, 48,
            	116, 56,
            	198, 64,
            1, 8, 1, /* 1140: pointer.struct.evp_pkey_method_st */
            	1145, 0,
            0, 208, 9, /* 1145: struct.evp_pkey_method_st */
            	116, 8,
            	116, 32,
            	116, 48,
            	116, 64,
            	116, 80,
            	116, 96,
            	116, 144,
            	116, 160,
            	116, 176,
            1, 8, 1, /* 1166: pointer.struct.comp_ctx_st */
            	1046, 0,
            0, 88, 1, /* 1171: struct.hm_header_st */
            	1089, 48,
            0, 24, 2, /* 1176: struct._pitem */
            	8, 8,
            	1183, 16,
            1, 8, 1, /* 1183: pointer.struct._pitem */
            	1176, 0,
            0, 16, 1, /* 1188: struct._pqueue */
            	1183, 0,
            1, 8, 1, /* 1193: pointer.struct._pqueue */
            	1188, 0,
            0, 16, 1, /* 1198: struct.record_pqueue_st */
            	1193, 8,
            0, 16, 0, /* 1203: union.anon.142 */
            1, 8, 1, /* 1206: pointer.struct.dtls1_state_st */
            	1211, 0,
            0, 888, 7, /* 1211: struct.dtls1_state_st */
            	1198, 576,
            	1198, 592,
            	1193, 608,
            	1193, 616,
            	1198, 624,
            	1171, 648,
            	1171, 736,
            0, 8, 0, /* 1228: pointer.func */
            0, 8, 0, /* 1231: pointer.func */
            0, 0, 0, /* 1234: func */
            0, 8, 0, /* 1237: pointer.func */
            0, 0, 0, /* 1240: func */
            0, 8, 0, /* 1243: pointer.func */
            0, 8, 0, /* 1246: pointer.func */
            0, 0, 0, /* 1249: func */
            0, 24, 2, /* 1252: struct.ssl_comp_st */
            	8, 8,
            	1053, 16,
            0, 8, 0, /* 1259: pointer.func */
            0, 0, 0, /* 1262: func */
            0, 8, 0, /* 1265: pointer.func */
            0, 0, 0, /* 1268: func */
            0, 8, 0, /* 1271: pointer.func */
            0, 0, 0, /* 1274: func */
            0, 8, 0, /* 1277: pointer.func */
            0, 8, 0, /* 1280: pointer.func */
            0, 0, 0, /* 1283: func */
            0, 8, 0, /* 1286: pointer.func */
            0, 0, 0, /* 1289: func */
            0, 9, 0, /* 1292: array[9].char */
            0, 8, 0, /* 1295: pointer.func */
            0, 0, 0, /* 1298: func */
            0, 8, 0, /* 1301: pointer.func */
            0, 0, 0, /* 1304: func */
            0, 8, 0, /* 1307: pointer.func */
            0, 0, 0, /* 1310: func */
            0, 0, 0, /* 1313: func */
            0, 8, 0, /* 1316: pointer.func */
            0, 8, 0, /* 1319: pointer.func */
            0, 0, 0, /* 1322: func */
            0, 8, 0, /* 1325: pointer.func */
            0, 8, 0, /* 1328: pointer.func */
            0, 0, 0, /* 1331: func */
            0, 0, 0, /* 1334: func */
            0, 8, 0, /* 1337: pointer.func */
            0, 8, 0, /* 1340: pointer.func */
            0, 8, 0, /* 1343: pointer.func */
            0, 0, 0, /* 1346: func */
            0, 8, 0, /* 1349: pointer.func */
            0, 0, 0, /* 1352: func */
            0, 8, 0, /* 1355: pointer.func */
            0, 8, 0, /* 1358: pointer.func */
            0, 0, 0, /* 1361: func */
            0, 8, 0, /* 1364: pointer.func */
            0, 0, 0, /* 1367: func */
            0, 0, 0, /* 1370: func */
            0, 0, 0, /* 1373: func */
            0, 8, 0, /* 1376: pointer.func */
            0, 0, 0, /* 1379: func */
            0, 8, 0, /* 1382: pointer.func */
            0, 8, 0, /* 1385: pointer.func */
            0, 8, 0, /* 1388: pointer.func */
            0, 8, 0, /* 1391: pointer.func */
            0, 0, 0, /* 1394: func */
            0, 128, 0, /* 1397: array[128].char */
            0, 0, 0, /* 1400: func */
            0, 0, 0, /* 1403: func */
            0, 0, 0, /* 1406: func */
            0, 0, 0, /* 1409: func */
            0, 20, 0, /* 1412: array[5].int */
            0, 0, 0, /* 1415: func */
            0, 0, 0, /* 1418: func */
            0, 0, 0, /* 1421: func */
            0, 528, 8, /* 1424: struct.anon.0 */
            	980, 408,
            	866, 416,
            	898, 424,
            	84, 464,
            	8, 480,
            	1074, 488,
            	792, 496,
            	1443, 512,
            1, 8, 1, /* 1443: pointer.struct.ssl_comp_st */
            	1252, 0,
            0, 0, 0, /* 1448: func */
            0, 0, 0, /* 1451: func */
            0, 0, 0, /* 1454: func */
            0, 0, 0, /* 1457: func */
            0, 8, 0, /* 1460: pointer.func */
            0, 8, 0, /* 1463: pointer.func */
            0, 0, 0, /* 1466: func */
            0, 8, 0, /* 1469: pointer.func */
            1, 8, 1, /* 1472: pointer.pointer.struct.env_md_ctx_st */
            	1100, 0,
            0, 1200, 10, /* 1477: struct.ssl3_state_st */
            	1500, 240,
            	1500, 264,
            	1505, 288,
            	1505, 344,
            	8, 432,
            	1514, 440,
            	1472, 448,
            	8, 496,
            	8, 512,
            	1424, 528,
            0, 24, 1, /* 1500: struct.ssl3_buffer_st */
            	8, 0,
            0, 56, 3, /* 1505: struct.ssl3_record_st */
            	8, 16,
            	8, 24,
            	8, 32,
            1, 8, 1, /* 1514: pointer.struct.bio_st */
            	1519, 0,
            0, 112, 6, /* 1519: struct.bio_st */
            	1534, 0,
            	8, 16,
            	8, 48,
            	1514, 56,
            	1514, 64,
            	124, 96,
            1, 8, 1, /* 1534: pointer.struct.bio_method_st */
            	1539, 0,
            0, 80, 1, /* 1539: struct.bio_method_st */
            	8, 8,
            0, 0, 0, /* 1544: func */
            0, 8, 0, /* 1547: pointer.func */
            0, 8, 0, /* 1550: pointer.func */
            0, 0, 0, /* 1553: func */
            1, 8, 1, /* 1556: pointer.struct.ssl3_state_st */
            	1477, 0,
            0, 344, 9, /* 1561: struct.ssl2_state_st */
            	8, 24,
            	8, 56,
            	8, 64,
            	8, 72,
            	8, 104,
            	8, 112,
            	8, 120,
            	8, 128,
            	8, 136,
            1, 8, 1, /* 1582: pointer.struct.ssl2_state_st */
            	1561, 0,
            0, 8, 0, /* 1587: pointer.func */
            0, 0, 0, /* 1590: func */
            0, 0, 0, /* 1593: func */
            0, 0, 0, /* 1596: func */
            0, 8, 0, /* 1599: pointer.func */
            0, 8, 0, /* 1602: pointer.func */
            0, 0, 0, /* 1605: func */
            0, 8, 0, /* 1608: pointer.func */
            0, 8, 0, /* 1611: pointer.func */
            0, 0, 0, /* 1614: func */
            0, 8, 0, /* 1617: pointer.func */
            0, 0, 0, /* 1620: func */
            0, 0, 0, /* 1623: func */
            0, 4, 0, /* 1626: array[4].char */
            0, 0, 0, /* 1629: func */
            0, 8, 0, /* 1632: pointer.func */
            0, 0, 0, /* 1635: func */
            0, 8, 0, /* 1638: pointer.func */
            0, 8, 0, /* 1641: pointer.func */
            0, 0, 0, /* 1644: func */
            0, 0, 0, /* 1647: func */
            0, 0, 0, /* 1650: func */
            0, 8, 0, /* 1653: pointer.func */
            0, 8, 0, /* 1656: pointer.func */
            0, 0, 0, /* 1659: func */
            0, 8, 0, /* 1662: pointer.func */
            0, 0, 0, /* 1665: func */
            0, 0, 0, /* 1668: func */
            0, 0, 0, /* 1671: func */
            0, 8, 0, /* 1674: pointer.func */
            0, 8, 0, /* 1677: pointer.func */
            0, 0, 0, /* 1680: func */
            0, 0, 0, /* 1683: func */
            0, 8, 0, /* 1686: pointer.func */
            0, 0, 0, /* 1689: func */
            0, 0, 0, /* 1692: func */
            0, 8, 0, /* 1695: pointer.func */
            0, 8, 0, /* 1698: pointer.func */
            0, 32, 0, /* 1701: array[32].char */
            0, 8, 0, /* 1704: pointer.func */
            0, 8, 0, /* 1707: pointer.func */
            0, 0, 0, /* 1710: func */
            0, 8, 0, /* 1713: pointer.func */
            0, 8, 0, /* 1716: pointer.func */
            0, 8, 0, /* 1719: pointer.func */
            0, 8, 0, /* 1722: pointer.func */
            0, 8, 0, /* 1725: pointer.func */
            0, 0, 0, /* 1728: func */
            0, 0, 0, /* 1731: func */
            0, 0, 0, /* 1734: func */
            0, 8, 0, /* 1737: array[8].char */
            0, 0, 0, /* 1740: func */
            0, 0, 0, /* 1743: func */
            0, 8, 0, /* 1746: pointer.func */
            0, 72, 0, /* 1749: struct.anon.25 */
            0, 0, 0, /* 1752: func */
            0, 8, 0, /* 1755: pointer.func */
            1, 8, 1, /* 1758: pointer.struct.ssl_st */
            	1763, 0,
            0, 808, 42, /* 1763: struct.ssl_st */
            	375, 8,
            	1514, 16,
            	1514, 24,
            	1514, 32,
            	116, 48,
            	575, 80,
            	8, 88,
            	8, 104,
            	1582, 120,
            	1556, 128,
            	1206, 136,
            	8, 160,
            	104, 176,
            	84, 184,
            	84, 192,
            	1084, 208,
            	1100, 216,
            	1166, 224,
            	1084, 232,
            	1100, 240,
            	1166, 248,
            	990, 256,
            	402, 304,
            	307, 368,
            	124, 392,
            	84, 408,
            	8, 472,
            	8, 480,
            	84, 504,
            	84, 512,
            	8, 520,
            	8, 544,
            	8, 560,
            	8, 568,
            	1850, 584,
            	8, 600,
            	8, 616,
            	307, 624,
            	8, 632,
            	84, 648,
            	1855, 656,
            	1018, 680,
            1, 8, 1, /* 1850: pointer.struct.tls_session_ticket_ext_st */
            	3, 0,
            1, 8, 1, /* 1855: pointer.struct.iovec */
            	206, 0,
            0, 8, 0, /* 1860: pointer.func */
            0, 8, 0, /* 1863: array[2].int */
            0, 8, 0, /* 1866: pointer.func */
            0, 0, 0, /* 1869: func */
            0, 8, 0, /* 1872: pointer.func */
            0, 0, 0, /* 1875: func */
            0, 0, 0, /* 1878: func */
            0, 0, 0, /* 1881: func */
            0, 8, 0, /* 1884: pointer.func */
            0, 24, 0, /* 1887: array[6].int */
            0, 8, 0, /* 1890: pointer.func */
            0, 0, 0, /* 1893: func */
            0, 0, 0, /* 1896: func */
            0, 0, 0, /* 1899: func */
            0, 0, 0, /* 1902: func */
            0, 0, 0, /* 1905: func */
            0, 8, 0, /* 1908: pointer.func */
            0, 8, 0, /* 1911: pointer.func */
            0, 8, 0, /* 1914: pointer.func */
            0, 0, 0, /* 1917: func */
            0, 8, 0, /* 1920: pointer.func */
            0, 0, 0, /* 1923: func */
            0, 8, 0, /* 1926: pointer.func */
            0, 0, 0, /* 1929: func */
            0, 8, 0, /* 1932: pointer.func */
            0, 0, 0, /* 1935: func */
            0, 0, 0, /* 1938: func */
            0, 8, 0, /* 1941: long */
            0, 8, 0, /* 1944: pointer.func */
            0, 8, 0, /* 1947: pointer.func */
            0, 0, 0, /* 1950: func */
            0, 0, 0, /* 1953: func */
            0, 0, 0, /* 1956: func */
            0, 8, 0, /* 1959: pointer.func */
            0, 0, 0, /* 1962: func */
            0, 0, 0, /* 1965: func */
            0, 2, 0, /* 1968: array[2].char */
            0, 8, 0, /* 1971: pointer.func */
            0, 8, 0, /* 1974: pointer.func */
            0, 8, 0, /* 1977: pointer.func */
            0, 8, 0, /* 1980: pointer.func */
            0, 0, 0, /* 1983: func */
            0, 8, 0, /* 1986: pointer.func */
            0, 0, 0, /* 1989: func */
            0, 8, 0, /* 1992: pointer.func */
            0, 0, 0, /* 1995: func */
            0, 0, 0, /* 1998: func */
            0, 8, 0, /* 2001: pointer.func */
            0, 8, 0, /* 2004: pointer.func */
            0, 8, 0, /* 2007: pointer.func */
            0, 8, 0, /* 2010: pointer.func */
            0, 8, 0, /* 2013: pointer.func */
            0, 8, 0, /* 2016: pointer.func */
            0, 8, 0, /* 2019: pointer.func */
            0, 0, 0, /* 2022: func */
            0, 8, 0, /* 2025: pointer.func */
            0, 48, 0, /* 2028: array[48].char */
            0, 0, 0, /* 2031: func */
            0, 8, 0, /* 2034: pointer.func */
            0, 8, 0, /* 2037: pointer.func */
            0, 0, 0, /* 2040: func */
            0, 0, 0, /* 2043: func */
            0, 8, 0, /* 2046: pointer.func */
            0, 0, 0, /* 2049: func */
            0, 8, 0, /* 2052: pointer.func */
            0, 16, 0, /* 2055: array[16].char */
            0, 8, 0, /* 2058: pointer.func */
            0, 8, 0, /* 2061: pointer.func */
            0, 8, 0, /* 2064: pointer.func */
            0, 8, 0, /* 2067: pointer.func */
            0, 64, 0, /* 2070: array[64].char */
            0, 8, 0, /* 2073: pointer.func */
            0, 8, 0, /* 2076: pointer.func */
            0, 0, 0, /* 2079: func */
            0, 0, 0, /* 2082: func */
            0, 8, 0, /* 2085: pointer.func */
            0, 0, 0, /* 2088: func */
            0, 0, 0, /* 2091: func */
            0, 8, 0, /* 2094: pointer.func */
            0, 0, 0, /* 2097: func */
            0, 0, 0, /* 2100: func */
            0, 256, 0, /* 2103: array[256].char */
            0, 8, 0, /* 2106: pointer.func */
            0, 0, 0, /* 2109: func */
            0, 8, 0, /* 2112: pointer.func */
            0, 0, 0, /* 2115: func */
            0, 0, 0, /* 2118: func */
            0, 8, 0, /* 2121: pointer.func */
            0, 8, 0, /* 2124: pointer.func */
            0, 0, 0, /* 2127: func */
            0, 8, 0, /* 2130: pointer.func */
            0, 8, 0, /* 2133: pointer.func */
            0, 8, 0, /* 2136: pointer.func */
            0, 8, 0, /* 2139: pointer.func */
            0, 0, 0, /* 2142: func */
            0, 0, 0, /* 2145: func */
            0, 20, 0, /* 2148: array[20].char */
            0, 0, 0, /* 2151: func */
            0, 8, 0, /* 2154: pointer.func */
            0, 0, 0, /* 2157: func */
            0, 0, 0, /* 2160: func */
            0, 0, 0, /* 2163: func */
            0, 0, 0, /* 2166: func */
            0, 8, 0, /* 2169: pointer.func */
            0, 8, 0, /* 2172: pointer.func */
            0, 8, 0, /* 2175: pointer.func */
            0, 0, 0, /* 2178: func */
            0, 8, 0, /* 2181: pointer.func */
            0, 0, 0, /* 2184: func */
            0, 0, 0, /* 2187: func */
            0, 8, 0, /* 2190: pointer.func */
            0, 0, 0, /* 2193: func */
            0, 0, 0, /* 2196: func */
            0, 0, 0, /* 2199: func */
            0, 8, 0, /* 2202: pointer.func */
            0, 8, 0, /* 2205: pointer.func */
            0, 0, 0, /* 2208: func */
            0, 0, 0, /* 2211: func */
            0, 0, 0, /* 2214: func */
            0, 0, 0, /* 2217: func */
            0, 0, 0, /* 2220: func */
            0, 8, 0, /* 2223: pointer.func */
            0, 2, 0, /* 2226: short */
            0, 0, 0, /* 2229: func */
            0, 0, 0, /* 2232: func */
            0, 8, 0, /* 2235: pointer.func */
            0, 0, 0, /* 2238: func */
            0, 0, 0, /* 2241: func */
            0, 8, 0, /* 2244: pointer.func */
            0, 8, 0, /* 2247: pointer.func */
            0, 0, 0, /* 2250: func */
            0, 8, 0, /* 2253: pointer.func */
            0, 0, 0, /* 2256: func */
            0, 0, 0, /* 2259: func */
            0, 8, 0, /* 2262: pointer.func */
            0, 8, 0, /* 2265: pointer.func */
            0, 8, 0, /* 2268: pointer.func */
            0, 0, 0, /* 2271: func */
            0, 0, 0, /* 2274: func */
            0, 8, 0, /* 2277: pointer.func */
            0, 8, 0, /* 2280: pointer.func */
            0, 8, 0, /* 2283: pointer.func */
            0, 8, 0, /* 2286: pointer.func */
            0, 0, 0, /* 2289: func */
            0, 0, 0, /* 2292: func */
            0, 8, 0, /* 2295: pointer.func */
            0, 0, 0, /* 2298: func */
            0, 0, 0, /* 2301: func */
            0, 0, 0, /* 2304: func */
            0, 8, 0, /* 2307: pointer.func */
            0, 0, 0, /* 2310: func */
            0, 8, 0, /* 2313: pointer.func */
            0, 0, 0, /* 2316: func */
            0, 8, 0, /* 2319: pointer.func */
            0, 0, 0, /* 2322: func */
            0, 8, 0, /* 2325: pointer.func */
            0, 8, 0, /* 2328: pointer.func */
            0, 0, 0, /* 2331: func */
            0, 0, 0, /* 2334: func */
            0, 0, 0, /* 2337: func */
            0, 0, 0, /* 2340: func */
            0, 8, 0, /* 2343: pointer.func */
            0, 8, 0, /* 2346: pointer.func */
            0, 0, 0, /* 2349: func */
            0, 8, 0, /* 2352: pointer.func */
            0, 8, 0, /* 2355: pointer.func */
            0, 8, 0, /* 2358: pointer.func */
            0, 0, 0, /* 2361: func */
        },
        .arg_entity_index = { 1758, },
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

