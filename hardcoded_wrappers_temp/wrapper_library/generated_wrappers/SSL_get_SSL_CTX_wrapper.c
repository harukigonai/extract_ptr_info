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
            1, 8, 1, /* 0: pointer.struct.iovec */
            	5, 0,
            0, 16, 1, /* 5: struct.iovec */
            	10, 0,
            1, 8, 1, /* 10: pointer.char */
            	4096, 0,
            0, 0, 0, /* 15: func */
            0, 16, 1, /* 18: struct.tls_session_ticket_ext_st */
            	10, 8,
            1, 8, 1, /* 23: pointer.struct.tls_session_ticket_ext_st */
            	18, 0,
            4097, 8, 0, /* 28: pointer.func */
            0, 12, 0, /* 31: struct.ap_unix_identity_t */
            0, 56, 2, /* 34: struct.comp_ctx_st */
            	41, 0,
            	51, 40,
            1, 8, 1, /* 41: pointer.struct.comp_method_st */
            	46, 0,
            0, 64, 1, /* 46: struct.comp_method_st */
            	10, 8,
            0, 16, 1, /* 51: struct.crypto_ex_data_st */
            	56, 0,
            1, 8, 1, /* 56: pointer.struct.stack_st_OPENSSL_STRING */
            	61, 0,
            0, 32, 1, /* 61: struct.stack_st_OPENSSL_STRING */
            	66, 0,
            0, 32, 1, /* 66: struct.stack_st */
            	71, 8,
            1, 8, 1, /* 71: pointer.pointer.char */
            	10, 0,
            1, 8, 1, /* 76: pointer.struct.comp_ctx_st */
            	34, 0,
            0, 168, 4, /* 81: struct.evp_cipher_ctx_st */
            	92, 0,
            	102, 8,
            	10, 96,
            	10, 120,
            1, 8, 1, /* 92: pointer.struct.evp_cipher_st */
            	97, 0,
            0, 88, 1, /* 97: struct.evp_cipher_st */
            	10, 80,
            1, 8, 1, /* 102: pointer.struct.engine_st */
            	107, 0,
            0, 216, 13, /* 107: struct.engine_st */
            	10, 0,
            	10, 8,
            	136, 16,
            	148, 24,
            	160, 32,
            	172, 40,
            	184, 48,
            	196, 56,
            	204, 64,
            	212, 160,
            	51, 184,
            	102, 200,
            	102, 208,
            1, 8, 1, /* 136: pointer.struct.rsa_meth_st */
            	141, 0,
            0, 112, 2, /* 141: struct.rsa_meth_st */
            	10, 0,
            	10, 80,
            1, 8, 1, /* 148: pointer.struct.dsa_method.1040 */
            	153, 0,
            0, 96, 2, /* 153: struct.dsa_method.1040 */
            	10, 0,
            	10, 72,
            1, 8, 1, /* 160: pointer.struct.dh_method */
            	165, 0,
            0, 72, 2, /* 165: struct.dh_method */
            	10, 0,
            	10, 56,
            1, 8, 1, /* 172: pointer.struct.ecdh_method */
            	177, 0,
            0, 32, 2, /* 177: struct.ecdh_method */
            	10, 0,
            	10, 24,
            1, 8, 1, /* 184: pointer.struct.ecdsa_method */
            	189, 0,
            0, 48, 2, /* 189: struct.ecdsa_method */
            	10, 0,
            	10, 40,
            1, 8, 1, /* 196: pointer.struct.rand_meth_st */
            	201, 0,
            0, 48, 0, /* 201: struct.rand_meth_st */
            1, 8, 1, /* 204: pointer.struct.store_method_st */
            	209, 0,
            0, 0, 0, /* 209: struct.store_method_st */
            1, 8, 1, /* 212: pointer.struct.ENGINE_CMD_DEFN_st */
            	217, 0,
            0, 32, 2, /* 217: struct.ENGINE_CMD_DEFN_st */
            	10, 8,
            	10, 16,
            0, 2, 0, /* 224: short */
            0, 256, 0, /* 227: array[256].char */
            1, 8, 1, /* 230: pointer.struct.dtls1_state_st */
            	235, 0,
            0, 888, 7, /* 235: struct.dtls1_state_st */
            	252, 576,
            	252, 592,
            	257, 608,
            	257, 616,
            	252, 624,
            	279, 648,
            	279, 736,
            0, 16, 1, /* 252: struct.record_pqueue_st */
            	257, 8,
            1, 8, 1, /* 257: pointer.struct._pqueue */
            	262, 0,
            0, 16, 1, /* 262: struct._pqueue */
            	267, 0,
            1, 8, 1, /* 267: pointer.struct._pitem */
            	272, 0,
            0, 24, 2, /* 272: struct._pitem */
            	10, 8,
            	267, 16,
            0, 88, 1, /* 279: struct.hm_header_st */
            	284, 48,
            0, 40, 4, /* 284: struct.dtls1_retransmit_state */
            	295, 0,
            	300, 8,
            	76, 16,
            	425, 24,
            1, 8, 1, /* 295: pointer.struct.evp_cipher_ctx_st */
            	81, 0,
            1, 8, 1, /* 300: pointer.struct.env_md_ctx_st */
            	305, 0,
            0, 48, 4, /* 305: struct.env_md_ctx_st */
            	316, 0,
            	102, 8,
            	10, 24,
            	324, 32,
            1, 8, 1, /* 316: pointer.struct.env_md_st */
            	321, 0,
            0, 120, 0, /* 321: struct.env_md_st */
            1, 8, 1, /* 324: pointer.struct.evp_pkey_ctx_st */
            	329, 0,
            0, 80, 8, /* 329: struct.evp_pkey_ctx_st */
            	348, 0,
            	102, 8,
            	382, 16,
            	382, 24,
            	10, 40,
            	10, 48,
            	374, 56,
            	417, 64,
            1, 8, 1, /* 348: pointer.struct.evp_pkey_method_st */
            	353, 0,
            0, 208, 9, /* 353: struct.evp_pkey_method_st */
            	374, 8,
            	374, 32,
            	374, 48,
            	374, 64,
            	374, 80,
            	374, 96,
            	374, 144,
            	374, 160,
            	374, 176,
            1, 8, 1, /* 374: pointer.struct.unnamed */
            	379, 0,
            0, 0, 0, /* 379: struct.unnamed */
            1, 8, 1, /* 382: pointer.struct.evp_pkey_st */
            	387, 0,
            0, 56, 4, /* 387: struct.evp_pkey_st */
            	398, 16,
            	102, 24,
            	412, 32,
            	56, 48,
            1, 8, 1, /* 398: pointer.struct.evp_pkey_asn1_method_st */
            	403, 0,
            0, 208, 3, /* 403: struct.evp_pkey_asn1_method_st */
            	10, 16,
            	10, 24,
            	374, 32,
            0, 8, 1, /* 412: struct.fnames */
            	10, 0,
            1, 8, 1, /* 417: pointer.int */
            	422, 0,
            0, 4, 0, /* 422: int */
            1, 8, 1, /* 425: pointer.struct.ssl_session_st */
            	430, 0,
            0, 352, 14, /* 430: struct.ssl_session_st */
            	10, 144,
            	10, 152,
            	461, 168,
            	495, 176,
            	947, 224,
            	56, 240,
            	51, 248,
            	425, 264,
            	425, 272,
            	10, 280,
            	10, 296,
            	10, 312,
            	10, 320,
            	10, 344,
            1, 8, 1, /* 461: pointer.struct.sess_cert_st */
            	466, 0,
            0, 248, 6, /* 466: struct.sess_cert_st */
            	56, 0,
            	481, 16,
            	728, 24,
            	747, 216,
            	833, 224,
            	865, 232,
            1, 8, 1, /* 481: pointer.struct.cert_pkey_st */
            	486, 0,
            0, 24, 3, /* 486: struct.cert_pkey_st */
            	495, 0,
            	382, 8,
            	316, 16,
            1, 8, 1, /* 495: pointer.struct.x509_st */
            	500, 0,
            0, 184, 12, /* 500: struct.x509_st */
            	527, 0,
            	567, 8,
            	557, 16,
            	10, 32,
            	51, 40,
            	557, 104,
            	658, 112,
            	672, 120,
            	56, 128,
            	56, 136,
            	698, 144,
            	710, 176,
            1, 8, 1, /* 527: pointer.struct.x509_cinf_st */
            	532, 0,
            0, 104, 11, /* 532: struct.x509_cinf_st */
            	557, 0,
            	557, 8,
            	567, 16,
            	603, 24,
            	627, 32,
            	603, 40,
            	639, 48,
            	557, 56,
            	557, 64,
            	56, 72,
            	653, 80,
            1, 8, 1, /* 557: pointer.struct.asn1_string_st */
            	562, 0,
            0, 24, 1, /* 562: struct.asn1_string_st */
            	10, 8,
            1, 8, 1, /* 567: pointer.struct.X509_algor_st */
            	572, 0,
            0, 16, 2, /* 572: struct.X509_algor_st */
            	579, 0,
            	593, 8,
            1, 8, 1, /* 579: pointer.struct.asn1_object_st */
            	584, 0,
            0, 40, 3, /* 584: struct.asn1_object_st */
            	10, 0,
            	10, 8,
            	10, 24,
            1, 8, 1, /* 593: pointer.struct.asn1_type_st */
            	598, 0,
            0, 16, 1, /* 598: struct.asn1_type_st */
            	412, 8,
            1, 8, 1, /* 603: pointer.struct.X509_name_st */
            	608, 0,
            0, 40, 3, /* 608: struct.X509_name_st */
            	56, 0,
            	617, 16,
            	10, 24,
            1, 8, 1, /* 617: pointer.struct.buf_mem_st */
            	622, 0,
            0, 24, 1, /* 622: struct.buf_mem_st */
            	10, 8,
            1, 8, 1, /* 627: pointer.struct.X509_val_st */
            	632, 0,
            0, 16, 2, /* 632: struct.X509_val_st */
            	557, 0,
            	557, 8,
            1, 8, 1, /* 639: pointer.struct.X509_pubkey_st */
            	644, 0,
            0, 24, 3, /* 644: struct.X509_pubkey_st */
            	567, 0,
            	557, 8,
            	382, 16,
            0, 24, 1, /* 653: struct.ASN1_ENCODING_st */
            	10, 0,
            1, 8, 1, /* 658: pointer.struct.AUTHORITY_KEYID_st */
            	663, 0,
            0, 24, 3, /* 663: struct.AUTHORITY_KEYID_st */
            	557, 0,
            	56, 8,
            	557, 16,
            1, 8, 1, /* 672: pointer.struct.X509_POLICY_CACHE_st */
            	677, 0,
            0, 40, 2, /* 677: struct.X509_POLICY_CACHE_st */
            	684, 0,
            	56, 8,
            1, 8, 1, /* 684: pointer.struct.X509_POLICY_DATA_st */
            	689, 0,
            0, 32, 3, /* 689: struct.X509_POLICY_DATA_st */
            	579, 8,
            	56, 16,
            	56, 24,
            1, 8, 1, /* 698: pointer.struct.NAME_CONSTRAINTS_st */
            	703, 0,
            0, 16, 2, /* 703: struct.NAME_CONSTRAINTS_st */
            	56, 0,
            	56, 8,
            1, 8, 1, /* 710: pointer.struct.x509_cert_aux_st */
            	715, 0,
            0, 40, 5, /* 715: struct.x509_cert_aux_st */
            	56, 0,
            	56, 8,
            	557, 16,
            	557, 24,
            	56, 32,
            0, 192, 8, /* 728: array[8].struct.cert_pkey_st */
            	486, 0,
            	486, 24,
            	486, 48,
            	486, 72,
            	486, 96,
            	486, 120,
            	486, 144,
            	486, 168,
            1, 8, 1, /* 747: pointer.struct.rsa_st */
            	752, 0,
            0, 168, 17, /* 752: struct.rsa_st */
            	136, 16,
            	102, 24,
            	789, 32,
            	789, 40,
            	789, 48,
            	789, 56,
            	789, 64,
            	789, 72,
            	789, 80,
            	789, 88,
            	51, 96,
            	799, 120,
            	799, 128,
            	799, 136,
            	10, 144,
            	813, 152,
            	813, 160,
            1, 8, 1, /* 789: pointer.struct.bignum_st */
            	794, 0,
            0, 24, 1, /* 794: struct.bignum_st */
            	417, 0,
            1, 8, 1, /* 799: pointer.struct.bn_mont_ctx_st */
            	804, 0,
            0, 96, 3, /* 804: struct.bn_mont_ctx_st */
            	794, 8,
            	794, 32,
            	794, 56,
            1, 8, 1, /* 813: pointer.struct.bn_blinding_st */
            	818, 0,
            0, 88, 6, /* 818: struct.bn_blinding_st */
            	789, 0,
            	789, 8,
            	789, 16,
            	789, 24,
            	5, 40,
            	799, 72,
            1, 8, 1, /* 833: pointer.struct.dh_st */
            	838, 0,
            0, 144, 12, /* 838: struct.dh_st */
            	789, 8,
            	789, 16,
            	789, 32,
            	789, 40,
            	799, 56,
            	789, 64,
            	789, 72,
            	10, 80,
            	789, 96,
            	51, 112,
            	160, 128,
            	102, 136,
            1, 8, 1, /* 865: pointer.struct.ec_key_st.284 */
            	870, 0,
            0, 56, 4, /* 870: struct.ec_key_st.284 */
            	881, 8,
            	919, 16,
            	789, 24,
            	935, 48,
            1, 8, 1, /* 881: pointer.struct.ec_group_st */
            	886, 0,
            0, 232, 11, /* 886: struct.ec_group_st */
            	911, 0,
            	919, 8,
            	794, 16,
            	794, 40,
            	10, 80,
            	935, 96,
            	794, 104,
            	794, 152,
            	794, 176,
            	10, 208,
            	10, 216,
            1, 8, 1, /* 911: pointer.struct.ec_method_st */
            	916, 0,
            0, 304, 0, /* 916: struct.ec_method_st */
            1, 8, 1, /* 919: pointer.struct.ec_point_st */
            	924, 0,
            0, 88, 4, /* 924: struct.ec_point_st */
            	911, 0,
            	794, 8,
            	794, 32,
            	794, 56,
            1, 8, 1, /* 935: pointer.struct.ec_extra_data_st */
            	940, 0,
            0, 40, 2, /* 940: struct.ec_extra_data_st */
            	935, 0,
            	10, 8,
            1, 8, 1, /* 947: pointer.struct.ssl_cipher_st */
            	952, 0,
            0, 88, 1, /* 952: struct.ssl_cipher_st */
            	10, 8,
            0, 0, 0, /* 957: func */
            0, 0, 0, /* 960: func */
            0, 0, 0, /* 963: func */
            4097, 8, 0, /* 966: pointer.func */
            0, 24, 2, /* 969: struct.ssl_comp_st */
            	10, 8,
            	41, 16,
            4097, 8, 0, /* 976: pointer.func */
            0, 0, 0, /* 979: func */
            4097, 8, 0, /* 982: pointer.func */
            0, 0, 0, /* 985: func */
            4097, 8, 0, /* 988: pointer.func */
            0, 0, 0, /* 991: func */
            4097, 8, 0, /* 994: pointer.func */
            0, 9, 0, /* 997: array[9].char */
            0, 528, 8, /* 1000: struct.anon.0 */
            	947, 408,
            	833, 416,
            	865, 424,
            	56, 464,
            	10, 480,
            	92, 488,
            	316, 496,
            	1019, 512,
            1, 8, 1, /* 1019: pointer.struct.ssl_comp_st */
            	969, 0,
            0, 0, 0, /* 1024: func */
            4097, 8, 0, /* 1027: pointer.func */
            4097, 8, 0, /* 1030: pointer.func */
            0, 0, 0, /* 1033: func */
            4097, 8, 0, /* 1036: pointer.func */
            0, 0, 0, /* 1039: func */
            4097, 8, 0, /* 1042: pointer.func */
            4097, 8, 0, /* 1045: pointer.func */
            0, 0, 0, /* 1048: func */
            4097, 8, 0, /* 1051: pointer.func */
            4097, 8, 0, /* 1054: pointer.func */
            4097, 8, 0, /* 1057: pointer.func */
            4097, 8, 0, /* 1060: pointer.func */
            0, 0, 0, /* 1063: func */
            4097, 8, 0, /* 1066: pointer.func */
            0, 4, 0, /* 1069: array[4].char */
            0, 56, 3, /* 1072: struct.ssl3_record_st */
            	10, 16,
            	10, 24,
            	10, 32,
            0, 24, 1, /* 1081: struct.ssl3_buffer_st */
            	10, 0,
            0, 72, 0, /* 1086: struct.anon.25 */
            0, 344, 9, /* 1089: struct.ssl2_state_st */
            	10, 24,
            	10, 56,
            	10, 64,
            	10, 72,
            	10, 104,
            	10, 112,
            	10, 120,
            	10, 128,
            	10, 136,
            0, 0, 0, /* 1110: func */
            0, 0, 0, /* 1113: func */
            0, 0, 0, /* 1116: func */
            4097, 8, 0, /* 1119: pointer.func */
            0, 0, 0, /* 1122: func */
            0, 0, 0, /* 1125: func */
            4097, 8, 0, /* 1128: pointer.func */
            0, 0, 0, /* 1131: func */
            4097, 8, 0, /* 1134: pointer.func */
            0, 808, 41, /* 1137: struct.ssl_st.776 */
            	1222, 8,
            	1248, 16,
            	1248, 24,
            	1248, 32,
            	617, 80,
            	10, 88,
            	10, 104,
            	1278, 120,
            	1283, 128,
            	230, 136,
            	10, 160,
            	1316, 176,
            	56, 184,
            	56, 192,
            	295, 208,
            	300, 216,
            	76, 224,
            	295, 232,
            	300, 240,
            	76, 248,
            	1328, 256,
            	425, 304,
            	1346, 368,
            	51, 392,
            	56, 408,
            	10, 472,
            	10, 480,
            	56, 504,
            	56, 512,
            	10, 520,
            	10, 544,
            	10, 560,
            	10, 568,
            	23, 584,
            	10, 600,
            	10, 616,
            	1346, 624,
            	10, 632,
            	56, 648,
            	0, 656,
            	1458, 680,
            1, 8, 1, /* 1222: pointer.struct.ssl_method_st.754 */
            	1227, 0,
            0, 232, 1, /* 1227: struct.ssl_method_st.754 */
            	1232, 200,
            1, 8, 1, /* 1232: pointer.struct.ssl3_enc_method.753 */
            	1237, 0,
            0, 112, 4, /* 1237: struct.ssl3_enc_method.753 */
            	374, 0,
            	374, 32,
            	10, 64,
            	10, 80,
            1, 8, 1, /* 1248: pointer.struct.bio_st */
            	1253, 0,
            0, 112, 6, /* 1253: struct.bio_st */
            	1268, 0,
            	10, 16,
            	10, 48,
            	1248, 56,
            	1248, 64,
            	51, 96,
            1, 8, 1, /* 1268: pointer.struct.bio_method_st */
            	1273, 0,
            0, 80, 1, /* 1273: struct.bio_method_st */
            	10, 8,
            1, 8, 1, /* 1278: pointer.struct.ssl2_state_st */
            	1089, 0,
            1, 8, 1, /* 1283: pointer.struct.ssl3_state_st */
            	1288, 0,
            0, 1200, 10, /* 1288: struct.ssl3_state_st */
            	1081, 240,
            	1081, 264,
            	1072, 288,
            	1072, 344,
            	10, 432,
            	1248, 440,
            	1311, 448,
            	10, 496,
            	10, 512,
            	1000, 528,
            1, 8, 1, /* 1311: pointer.pointer.struct.env_md_ctx_st */
            	300, 0,
            1, 8, 1, /* 1316: pointer.struct.X509_VERIFY_PARAM_st */
            	1321, 0,
            0, 56, 2, /* 1321: struct.X509_VERIFY_PARAM_st */
            	10, 0,
            	56, 48,
            1, 8, 1, /* 1328: pointer.struct.cert_st.745 */
            	1333, 0,
            0, 296, 5, /* 1333: struct.cert_st.745 */
            	481, 0,
            	747, 48,
            	833, 64,
            	865, 80,
            	728, 96,
            1, 8, 1, /* 1346: pointer.struct.ssl_ctx_st.752 */
            	1351, 0,
            0, 736, 30, /* 1351: struct.ssl_ctx_st.752 */
            	1222, 0,
            	56, 8,
            	56, 16,
            	1414, 24,
            	1430, 32,
            	425, 48,
            	425, 56,
            	10, 160,
            	10, 176,
            	51, 208,
            	316, 224,
            	316, 232,
            	316, 240,
            	56, 248,
            	56, 256,
            	56, 272,
            	1328, 304,
            	10, 328,
            	1316, 392,
            	102, 408,
            	10, 424,
            	10, 496,
            	10, 512,
            	10, 520,
            	1438, 552,
            	1438, 560,
            	1458, 568,
            	10, 704,
            	10, 720,
            	56, 728,
            1, 8, 1, /* 1414: pointer.struct.x509_store_st */
            	1419, 0,
            0, 144, 4, /* 1419: struct.x509_store_st */
            	56, 8,
            	56, 16,
            	1316, 24,
            	51, 120,
            1, 8, 1, /* 1430: pointer.struct.in_addr */
            	1435, 0,
            0, 4, 0, /* 1435: struct.in_addr */
            1, 8, 1, /* 1438: pointer.struct.ssl3_buf_freelist_st */
            	1443, 0,
            0, 24, 1, /* 1443: struct.ssl3_buf_freelist_st */
            	1448, 16,
            1, 8, 1, /* 1448: pointer.struct.ssl3_buf_freelist_entry_st */
            	1453, 0,
            0, 8, 1, /* 1453: struct.ssl3_buf_freelist_entry_st */
            	1448, 0,
            0, 128, 11, /* 1458: struct.srp_ctx_st.751 */
            	10, 0,
            	10, 32,
            	789, 40,
            	789, 48,
            	789, 56,
            	789, 64,
            	789, 72,
            	789, 80,
            	789, 88,
            	789, 96,
            	10, 104,
            0, 0, 0, /* 1483: func */
            4097, 8, 0, /* 1486: pointer.func */
            4097, 8, 0, /* 1489: pointer.func */
            0, 16, 0, /* 1492: array[16].char */
            0, 0, 0, /* 1495: func */
            0, 0, 0, /* 1498: func */
            4097, 8, 0, /* 1501: pointer.func */
            0, 0, 0, /* 1504: func */
            0, 0, 0, /* 1507: func */
            4097, 8, 0, /* 1510: pointer.func */
            4097, 8, 0, /* 1513: pointer.func */
            0, 0, 0, /* 1516: func */
            0, 0, 0, /* 1519: func */
            4097, 8, 0, /* 1522: pointer.func */
            0, 0, 0, /* 1525: func */
            4097, 8, 0, /* 1528: pointer.func */
            0, 0, 0, /* 1531: func */
            4097, 8, 0, /* 1534: pointer.func */
            0, 0, 0, /* 1537: func */
            0, 128, 0, /* 1540: array[128].char */
            4097, 8, 0, /* 1543: pointer.func */
            0, 44, 0, /* 1546: struct.apr_time_exp_t */
            0, 0, 0, /* 1549: func */
            4097, 8, 0, /* 1552: pointer.func */
            0, 12, 0, /* 1555: array[12].char */
            0, 0, 0, /* 1558: func */
            0, 0, 0, /* 1561: func */
            4097, 8, 0, /* 1564: pointer.func */
            0, 0, 0, /* 1567: func */
            4097, 8, 0, /* 1570: pointer.func */
            4097, 8, 0, /* 1573: pointer.func */
            0, 0, 0, /* 1576: func */
            4097, 8, 0, /* 1579: pointer.func */
            0, 0, 0, /* 1582: func */
            4097, 8, 0, /* 1585: pointer.func */
            0, 0, 0, /* 1588: func */
            4097, 8, 0, /* 1591: pointer.func */
            4097, 8, 0, /* 1594: pointer.func */
            0, 0, 0, /* 1597: func */
            0, 0, 0, /* 1600: func */
            4097, 8, 0, /* 1603: pointer.func */
            0, 0, 0, /* 1606: func */
            4097, 8, 0, /* 1609: pointer.func */
            0, 0, 0, /* 1612: func */
            4097, 8, 0, /* 1615: pointer.func */
            0, 0, 0, /* 1618: func */
            1, 8, 1, /* 1621: pointer.struct.ssl_st.776 */
            	1137, 0,
            4097, 8, 0, /* 1626: pointer.func */
            0, 0, 0, /* 1629: func */
            0, 0, 0, /* 1632: func */
            4097, 8, 0, /* 1635: pointer.func */
            0, 0, 0, /* 1638: func */
            0, 0, 0, /* 1641: func */
            0, 0, 0, /* 1644: func */
            0, 0, 0, /* 1647: func */
            4097, 8, 0, /* 1650: pointer.func */
            0, 8, 0, /* 1653: array[2].int */
            4097, 8, 0, /* 1656: pointer.func */
            0, 0, 0, /* 1659: func */
            0, 0, 0, /* 1662: func */
            4097, 8, 0, /* 1665: pointer.func */
            0, 0, 0, /* 1668: func */
            0, 0, 0, /* 1671: func */
            0, 0, 0, /* 1674: func */
            0, 0, 0, /* 1677: func */
            0, 0, 0, /* 1680: func */
            0, 0, 0, /* 1683: func */
            0, 0, 0, /* 1686: func */
            4097, 8, 0, /* 1689: pointer.func */
            4097, 8, 0, /* 1692: pointer.func */
            0, 0, 0, /* 1695: func */
            0, 0, 0, /* 1698: func */
            4097, 8, 0, /* 1701: pointer.func */
            4097, 8, 0, /* 1704: pointer.func */
            4097, 8, 0, /* 1707: pointer.func */
            4097, 8, 0, /* 1710: pointer.func */
            4097, 8, 0, /* 1713: pointer.func */
            0, 0, 0, /* 1716: func */
            4097, 8, 0, /* 1719: pointer.func */
            0, 0, 0, /* 1722: func */
            0, 0, 0, /* 1725: func */
            0, 24, 0, /* 1728: array[6].int */
            4097, 8, 0, /* 1731: pointer.func */
            0, 32, 0, /* 1734: array[32].char */
            4097, 8, 0, /* 1737: pointer.func */
            0, 48, 0, /* 1740: array[48].char */
            0, 0, 0, /* 1743: func */
            0, 0, 0, /* 1746: func */
            4097, 8, 0, /* 1749: pointer.func */
            4097, 8, 0, /* 1752: pointer.func */
            4097, 8, 0, /* 1755: pointer.func */
            0, 0, 0, /* 1758: func */
            0, 8, 0, /* 1761: array[8].char */
            0, 0, 0, /* 1764: func */
            4097, 8, 0, /* 1767: pointer.func */
            0, 0, 0, /* 1770: func */
            0, 0, 0, /* 1773: func */
            4097, 8, 0, /* 1776: pointer.func */
            0, 0, 0, /* 1779: func */
            4097, 8, 0, /* 1782: pointer.func */
            0, 0, 0, /* 1785: func */
            0, 0, 0, /* 1788: func */
            0, 8, 0, /* 1791: long */
            4097, 8, 0, /* 1794: pointer.func */
            0, 0, 0, /* 1797: func */
            0, 0, 0, /* 1800: func */
            0, 0, 0, /* 1803: func */
            0, 0, 0, /* 1806: func */
            0, 0, 0, /* 1809: func */
            4097, 8, 0, /* 1812: pointer.func */
            4097, 8, 0, /* 1815: pointer.func */
            4097, 8, 0, /* 1818: pointer.func */
            4097, 8, 0, /* 1821: pointer.func */
            4097, 8, 0, /* 1824: pointer.func */
            0, 0, 0, /* 1827: func */
            0, 0, 0, /* 1830: func */
            0, 0, 0, /* 1833: func */
            4097, 8, 0, /* 1836: pointer.func */
            0, 0, 0, /* 1839: func */
            0, 0, 0, /* 1842: func */
            0, 0, 0, /* 1845: func */
            4097, 8, 0, /* 1848: pointer.func */
            4097, 8, 0, /* 1851: pointer.func */
            4097, 8, 0, /* 1854: pointer.func */
            4097, 8, 0, /* 1857: pointer.func */
            4097, 8, 0, /* 1860: pointer.func */
            0, 0, 0, /* 1863: func */
            0, 0, 0, /* 1866: func */
            0, 1, 0, /* 1869: char */
            0, 0, 0, /* 1872: func */
            0, 0, 0, /* 1875: func */
            4097, 8, 0, /* 1878: pointer.func */
            0, 20, 0, /* 1881: array[5].int */
            0, 0, 0, /* 1884: func */
            4097, 8, 0, /* 1887: pointer.func */
            4097, 8, 0, /* 1890: pointer.func */
            4097, 8, 0, /* 1893: pointer.func */
            0, 0, 0, /* 1896: func */
            4097, 8, 0, /* 1899: pointer.func */
            0, 0, 0, /* 1902: func */
            0, 0, 0, /* 1905: func */
            4097, 8, 0, /* 1908: pointer.func */
            0, 0, 0, /* 1911: func */
            0, 0, 0, /* 1914: func */
            0, 0, 0, /* 1917: func */
            4097, 8, 0, /* 1920: pointer.func */
            0, 0, 0, /* 1923: func */
            4097, 8, 0, /* 1926: pointer.func */
            0, 0, 0, /* 1929: func */
            4097, 8, 0, /* 1932: pointer.func */
            4097, 8, 0, /* 1935: pointer.func */
            4097, 8, 0, /* 1938: pointer.func */
            4097, 8, 0, /* 1941: pointer.func */
            0, 0, 0, /* 1944: func */
            0, 0, 0, /* 1947: func */
            4097, 8, 0, /* 1950: pointer.func */
            0, 0, 0, /* 1953: func */
            0, 0, 0, /* 1956: func */
            0, 0, 0, /* 1959: func */
            0, 0, 0, /* 1962: func */
            4097, 8, 0, /* 1965: pointer.func */
            4097, 8, 0, /* 1968: pointer.func */
            4097, 8, 0, /* 1971: pointer.func */
            4097, 8, 0, /* 1974: pointer.func */
            0, 0, 0, /* 1977: func */
            4097, 8, 0, /* 1980: pointer.func */
            4097, 8, 0, /* 1983: pointer.func */
            4097, 8, 0, /* 1986: pointer.func */
            0, 0, 0, /* 1989: func */
            4097, 8, 0, /* 1992: pointer.func */
            4097, 8, 0, /* 1995: pointer.func */
            4097, 8, 0, /* 1998: pointer.func */
            0, 0, 0, /* 2001: func */
            0, 0, 0, /* 2004: func */
            0, 16, 0, /* 2007: struct.rlimit */
            0, 0, 0, /* 2010: func */
            0, 0, 0, /* 2013: func */
            0, 0, 0, /* 2016: func */
            0, 0, 0, /* 2019: func */
            0, 0, 0, /* 2022: func */
            0, 0, 0, /* 2025: func */
            0, 0, 0, /* 2028: func */
            0, 0, 0, /* 2031: func */
            0, 0, 0, /* 2034: func */
            4097, 8, 0, /* 2037: pointer.func */
            4097, 8, 0, /* 2040: pointer.func */
            4097, 8, 0, /* 2043: pointer.func */
            0, 16, 0, /* 2046: union.anon.142 */
            4097, 8, 0, /* 2049: pointer.func */
            4097, 8, 0, /* 2052: pointer.func */
            0, 0, 0, /* 2055: func */
            0, 0, 0, /* 2058: func */
            4097, 8, 0, /* 2061: pointer.func */
            4097, 8, 0, /* 2064: pointer.func */
            0, 0, 0, /* 2067: func */
            4097, 8, 0, /* 2070: pointer.func */
            0, 0, 0, /* 2073: func */
            0, 0, 0, /* 2076: func */
            0, 0, 0, /* 2079: func */
            4097, 8, 0, /* 2082: pointer.func */
            0, 0, 0, /* 2085: func */
            4097, 8, 0, /* 2088: pointer.func */
            4097, 8, 0, /* 2091: pointer.func */
            4097, 8, 0, /* 2094: pointer.func */
            4097, 8, 0, /* 2097: pointer.func */
            4097, 8, 0, /* 2100: pointer.func */
            4097, 8, 0, /* 2103: pointer.func */
            4097, 8, 0, /* 2106: pointer.func */
            4097, 8, 0, /* 2109: pointer.func */
            4097, 8, 0, /* 2112: pointer.func */
            0, 20, 0, /* 2115: array[20].char */
            4097, 8, 0, /* 2118: pointer.func */
            0, 0, 0, /* 2121: func */
            4097, 8, 0, /* 2124: pointer.func */
            4097, 8, 0, /* 2127: pointer.func */
            4097, 8, 0, /* 2130: pointer.func */
            4097, 8, 0, /* 2133: pointer.func */
            0, 0, 0, /* 2136: func */
            0, 0, 0, /* 2139: func */
            4097, 8, 0, /* 2142: pointer.func */
            4097, 8, 0, /* 2145: pointer.func */
            0, 0, 0, /* 2148: func */
            4097, 8, 0, /* 2151: pointer.func */
            0, 0, 0, /* 2154: func */
            4097, 8, 0, /* 2157: pointer.func */
            0, 0, 0, /* 2160: func */
            4097, 8, 0, /* 2163: pointer.func */
            0, 2, 0, /* 2166: array[2].char */
            0, 0, 0, /* 2169: func */
            4097, 8, 0, /* 2172: pointer.func */
            4097, 8, 0, /* 2175: pointer.func */
            0, 0, 0, /* 2178: func */
            0, 0, 0, /* 2181: func */
            0, 0, 0, /* 2184: func */
            4097, 8, 0, /* 2187: pointer.func */
            4097, 8, 0, /* 2190: pointer.func */
            0, 0, 0, /* 2193: func */
            4097, 8, 0, /* 2196: pointer.func */
            0, 0, 0, /* 2199: func */
            4097, 8, 0, /* 2202: pointer.func */
            0, 0, 0, /* 2205: func */
            0, 0, 0, /* 2208: func */
            0, 0, 0, /* 2211: func */
            0, 0, 0, /* 2214: func */
            0, 64, 0, /* 2217: array[64].char */
            4097, 8, 0, /* 2220: pointer.func */
            4097, 8, 0, /* 2223: pointer.func */
            4097, 8, 0, /* 2226: pointer.func */
            4097, 8, 0, /* 2229: pointer.func */
            4097, 8, 0, /* 2232: pointer.func */
            4097, 8, 0, /* 2235: pointer.func */
            0, 0, 0, /* 2238: func */
            0, 0, 0, /* 2241: func */
            0, 0, 0, /* 2244: func */
            4097, 8, 0, /* 2247: pointer.func */
            0, 0, 0, /* 2250: func */
            0, 0, 0, /* 2253: func */
            0, 0, 0, /* 2256: func */
            4097, 8, 0, /* 2259: pointer.func */
            0, 0, 0, /* 2262: func */
            4097, 8, 0, /* 2265: pointer.func */
            4097, 8, 0, /* 2268: pointer.func */
            4097, 8, 0, /* 2271: pointer.func */
            0, 0, 0, /* 2274: func */
            0, 0, 0, /* 2277: func */
            4097, 8, 0, /* 2280: pointer.func */
            4097, 8, 0, /* 2283: pointer.func */
            4097, 8, 0, /* 2286: pointer.func */
            0, 0, 0, /* 2289: func */
            4097, 8, 0, /* 2292: pointer.func */
            4097, 8, 0, /* 2295: pointer.func */
            4097, 8, 0, /* 2298: pointer.func */
            4097, 8, 0, /* 2301: pointer.func */
            4097, 8, 0, /* 2304: pointer.func */
            0, 0, 0, /* 2307: func */
            0, 0, 0, /* 2310: func */
            4097, 8, 0, /* 2313: pointer.func */
            4097, 8, 0, /* 2316: pointer.func */
            0, 0, 0, /* 2319: func */
            4097, 8, 0, /* 2322: pointer.func */
            4097, 8, 0, /* 2325: pointer.func */
            0, 0, 0, /* 2328: func */
            0, 0, 0, /* 2331: func */
            4097, 8, 0, /* 2334: pointer.func */
            0, 0, 0, /* 2337: func */
            0, 0, 0, /* 2340: func */
            4097, 8, 0, /* 2343: pointer.func */
            4097, 8, 0, /* 2346: pointer.func */
            0, 0, 0, /* 2349: func */
            0, 0, 0, /* 2352: func */
            0, 0, 0, /* 2355: func */
        },
        .arg_entity_index = { 1621, },
        .ret_entity_index = 1346,
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

