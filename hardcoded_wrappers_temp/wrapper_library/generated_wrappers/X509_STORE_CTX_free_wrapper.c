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

void X509_STORE_CTX_free(X509_STORE_CTX * arg_a) 
{
    if (syscall(890))
        _X509_STORE_CTX_free(arg_a);
    else {
        void (*orig_X509_STORE_CTX_free)(X509_STORE_CTX *);
        orig_X509_STORE_CTX_free = dlsym(RTLD_NEXT, "X509_STORE_CTX_free");
        orig_X509_STORE_CTX_free(arg_a);
    }
}

void _X509_STORE_CTX_free(X509_STORE_CTX * arg_a) 
{
    printf("X509_STORE_CTX_free called\n");
    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 0, 0, /* 0: func */
            0, 8, 1, /* 3: union.anon.1.3070 */
            	8, 0,
            1, 8, 1, /* 8: pointer.struct.stack_st_OPENSSL_STRING */
            	13, 0,
            0, 32, 1, /* 13: struct.stack_st_OPENSSL_STRING */
            	18, 0,
            0, 32, 2, /* 18: struct.stack_st */
            	25, 8,
            	38, 24,
            1, 8, 1, /* 25: pointer.pointer.char */
            	30, 0,
            1, 8, 1, /* 30: pointer.char */
            	35, 0,
            0, 1, 0, /* 35: char */
            1, 8, 1, /* 38: pointer.func */
            	43, 0,
            0, 0, 0, /* 43: func */
            0, 24, 2, /* 46: struct.DIST_POINT_NAME_st */
            	3, 8,
            	53, 16,
            1, 8, 1, /* 53: pointer.struct.X509_name_st */
            	58, 0,
            0, 40, 3, /* 58: struct.X509_name_st */
            	8, 0,
            	67, 16,
            	30, 24,
            1, 8, 1, /* 67: pointer.struct.buf_mem_st */
            	72, 0,
            0, 24, 1, /* 72: struct.buf_mem_st */
            	30, 8,
            1, 8, 1, /* 77: pointer.struct.DIST_POINT_NAME_st */
            	46, 0,
            0, 32, 2, /* 82: struct.ISSUING_DIST_POINT_st */
            	77, 0,
            	89, 16,
            1, 8, 1, /* 89: pointer.struct.asn1_string_st */
            	94, 0,
            0, 24, 1, /* 94: struct.asn1_string_st */
            	30, 8,
            0, 80, 8, /* 99: struct.X509_crl_info_st */
            	89, 0,
            	118, 8,
            	53, 16,
            	89, 24,
            	89, 32,
            	8, 40,
            	8, 48,
            	159, 56,
            1, 8, 1, /* 118: pointer.struct.X509_algor_st */
            	123, 0,
            0, 16, 2, /* 123: struct.X509_algor_st */
            	130, 0,
            	144, 8,
            1, 8, 1, /* 130: pointer.struct.asn1_object_st */
            	135, 0,
            0, 40, 3, /* 135: struct.asn1_object_st */
            	30, 0,
            	30, 8,
            	30, 24,
            1, 8, 1, /* 144: pointer.struct.asn1_type_st */
            	149, 0,
            0, 16, 1, /* 149: struct.asn1_type_st */
            	154, 8,
            0, 8, 1, /* 154: struct.fnames */
            	30, 0,
            0, 24, 1, /* 159: struct.ASN1_ENCODING_st */
            	30, 0,
            1, 8, 1, /* 164: pointer.struct.X509_crl_info_st */
            	99, 0,
            0, 24, 2, /* 169: struct.X509_POLICY_NODE_st */
            	176, 0,
            	190, 8,
            1, 8, 1, /* 176: pointer.struct.X509_POLICY_DATA_st */
            	181, 0,
            0, 32, 3, /* 181: struct.X509_POLICY_DATA_st */
            	130, 8,
            	8, 16,
            	8, 24,
            1, 8, 1, /* 190: pointer.struct.X509_POLICY_NODE_st */
            	169, 0,
            1, 8, 1, /* 195: pointer.func */
            	200, 0,
            0, 0, 0, /* 200: func */
            0, 0, 0, /* 203: func */
            1, 8, 1, /* 206: pointer.func */
            	203, 0,
            1, 8, 1, /* 211: pointer.func */
            	216, 0,
            0, 0, 0, /* 216: func */
            0, 0, 0, /* 219: func */
            0, 0, 0, /* 222: func */
            0, 0, 0, /* 225: func */
            1, 8, 1, /* 228: pointer.func */
            	233, 0,
            0, 0, 0, /* 233: func */
            1, 8, 1, /* 236: pointer.func */
            	241, 0,
            0, 0, 0, /* 241: func */
            0, 0, 0, /* 244: func */
            1, 8, 1, /* 247: pointer.func */
            	252, 0,
            0, 0, 0, /* 252: func */
            0, 0, 0, /* 255: func */
            0, 208, 24, /* 258: struct.evp_pkey_asn1_method_st */
            	30, 16,
            	30, 24,
            	309, 32,
            	317, 40,
            	247, 48,
            	322, 56,
            	236, 64,
            	228, 72,
            	322, 80,
            	327, 88,
            	327, 96,
            	332, 104,
            	337, 112,
            	327, 120,
            	247, 128,
            	247, 136,
            	322, 144,
            	342, 152,
            	211, 160,
            	206, 168,
            	332, 176,
            	337, 184,
            	195, 192,
            	350, 200,
            1, 8, 1, /* 309: pointer.struct.unnamed */
            	314, 0,
            0, 0, 0, /* 314: struct.unnamed */
            1, 8, 1, /* 317: pointer.func */
            	255, 0,
            1, 8, 1, /* 322: pointer.func */
            	244, 0,
            1, 8, 1, /* 327: pointer.func */
            	225, 0,
            1, 8, 1, /* 332: pointer.func */
            	222, 0,
            1, 8, 1, /* 337: pointer.func */
            	219, 0,
            1, 8, 1, /* 342: pointer.func */
            	347, 0,
            0, 0, 0, /* 347: func */
            1, 8, 1, /* 350: pointer.func */
            	355, 0,
            0, 0, 0, /* 355: func */
            1, 8, 1, /* 358: pointer.struct.evp_pkey_asn1_method_st */
            	258, 0,
            0, 56, 4, /* 363: struct.evp_pkey_st */
            	358, 16,
            	374, 24,
            	154, 32,
            	8, 48,
            1, 8, 1, /* 374: pointer.struct.engine_st */
            	379, 0,
            0, 216, 24, /* 379: struct.engine_st */
            	30, 0,
            	30, 8,
            	430, 16,
            	520, 24,
            	606, 32,
            	662, 40,
            	684, 48,
            	726, 56,
            	786, 64,
            	794, 72,
            	802, 80,
            	810, 88,
            	818, 96,
            	826, 104,
            	826, 112,
            	826, 120,
            	834, 128,
            	842, 136,
            	842, 144,
            	850, 152,
            	858, 160,
            	870, 184,
            	374, 200,
            	374, 208,
            1, 8, 1, /* 430: pointer.struct.rsa_meth_st */
            	435, 0,
            0, 112, 13, /* 435: struct.rsa_meth_st */
            	30, 0,
            	464, 8,
            	464, 16,
            	464, 24,
            	464, 32,
            	472, 40,
            	480, 48,
            	488, 56,
            	488, 64,
            	30, 80,
            	496, 88,
            	504, 96,
            	512, 104,
            1, 8, 1, /* 464: pointer.func */
            	469, 0,
            0, 0, 0, /* 469: func */
            1, 8, 1, /* 472: pointer.func */
            	477, 0,
            0, 0, 0, /* 477: func */
            1, 8, 1, /* 480: pointer.func */
            	485, 0,
            0, 0, 0, /* 485: func */
            1, 8, 1, /* 488: pointer.func */
            	493, 0,
            0, 0, 0, /* 493: func */
            1, 8, 1, /* 496: pointer.func */
            	501, 0,
            0, 0, 0, /* 501: func */
            1, 8, 1, /* 504: pointer.func */
            	509, 0,
            0, 0, 0, /* 509: func */
            1, 8, 1, /* 512: pointer.func */
            	517, 0,
            0, 0, 0, /* 517: func */
            1, 8, 1, /* 520: pointer.struct.dsa_method.1040 */
            	525, 0,
            0, 96, 11, /* 525: struct.dsa_method.1040 */
            	30, 0,
            	550, 8,
            	558, 16,
            	566, 24,
            	574, 32,
            	582, 40,
            	590, 48,
            	590, 56,
            	30, 72,
            	598, 80,
            	590, 88,
            1, 8, 1, /* 550: pointer.func */
            	555, 0,
            0, 0, 0, /* 555: func */
            1, 8, 1, /* 558: pointer.func */
            	563, 0,
            0, 0, 0, /* 563: func */
            1, 8, 1, /* 566: pointer.func */
            	571, 0,
            0, 0, 0, /* 571: func */
            1, 8, 1, /* 574: pointer.func */
            	579, 0,
            0, 0, 0, /* 579: func */
            1, 8, 1, /* 582: pointer.func */
            	587, 0,
            0, 0, 0, /* 587: func */
            1, 8, 1, /* 590: pointer.func */
            	595, 0,
            0, 0, 0, /* 595: func */
            1, 8, 1, /* 598: pointer.func */
            	603, 0,
            0, 0, 0, /* 603: func */
            1, 8, 1, /* 606: pointer.struct.dh_method */
            	611, 0,
            0, 72, 8, /* 611: struct.dh_method */
            	30, 0,
            	630, 8,
            	638, 16,
            	646, 24,
            	630, 32,
            	630, 40,
            	30, 56,
            	654, 64,
            1, 8, 1, /* 630: pointer.func */
            	635, 0,
            0, 0, 0, /* 635: func */
            1, 8, 1, /* 638: pointer.func */
            	643, 0,
            0, 0, 0, /* 643: func */
            1, 8, 1, /* 646: pointer.func */
            	651, 0,
            0, 0, 0, /* 651: func */
            1, 8, 1, /* 654: pointer.func */
            	659, 0,
            0, 0, 0, /* 659: func */
            1, 8, 1, /* 662: pointer.struct.ecdh_method */
            	667, 0,
            0, 32, 3, /* 667: struct.ecdh_method */
            	30, 0,
            	676, 8,
            	30, 24,
            1, 8, 1, /* 676: pointer.func */
            	681, 0,
            0, 0, 0, /* 681: func */
            1, 8, 1, /* 684: pointer.struct.ecdsa_method */
            	689, 0,
            0, 48, 5, /* 689: struct.ecdsa_method */
            	30, 0,
            	702, 8,
            	710, 16,
            	718, 24,
            	30, 40,
            1, 8, 1, /* 702: pointer.func */
            	707, 0,
            0, 0, 0, /* 707: func */
            1, 8, 1, /* 710: pointer.func */
            	715, 0,
            0, 0, 0, /* 715: func */
            1, 8, 1, /* 718: pointer.func */
            	723, 0,
            0, 0, 0, /* 723: func */
            1, 8, 1, /* 726: pointer.struct.rand_meth_st */
            	731, 0,
            0, 48, 6, /* 731: struct.rand_meth_st */
            	746, 0,
            	754, 8,
            	762, 16,
            	770, 24,
            	754, 32,
            	778, 40,
            1, 8, 1, /* 746: pointer.func */
            	751, 0,
            0, 0, 0, /* 751: func */
            1, 8, 1, /* 754: pointer.func */
            	759, 0,
            0, 0, 0, /* 759: func */
            1, 8, 1, /* 762: pointer.func */
            	767, 0,
            0, 0, 0, /* 767: func */
            1, 8, 1, /* 770: pointer.func */
            	775, 0,
            0, 0, 0, /* 775: func */
            1, 8, 1, /* 778: pointer.func */
            	783, 0,
            0, 0, 0, /* 783: func */
            1, 8, 1, /* 786: pointer.struct.store_method_st */
            	791, 0,
            0, 0, 0, /* 791: struct.store_method_st */
            1, 8, 1, /* 794: pointer.func */
            	799, 0,
            0, 0, 0, /* 799: func */
            1, 8, 1, /* 802: pointer.func */
            	807, 0,
            0, 0, 0, /* 807: func */
            1, 8, 1, /* 810: pointer.func */
            	815, 0,
            0, 0, 0, /* 815: func */
            1, 8, 1, /* 818: pointer.func */
            	823, 0,
            0, 0, 0, /* 823: func */
            1, 8, 1, /* 826: pointer.func */
            	831, 0,
            0, 0, 0, /* 831: func */
            1, 8, 1, /* 834: pointer.func */
            	839, 0,
            0, 0, 0, /* 839: func */
            1, 8, 1, /* 842: pointer.func */
            	847, 0,
            0, 0, 0, /* 847: func */
            1, 8, 1, /* 850: pointer.func */
            	855, 0,
            0, 0, 0, /* 855: func */
            1, 8, 1, /* 858: pointer.struct.ENGINE_CMD_DEFN_st */
            	863, 0,
            0, 32, 2, /* 863: struct.ENGINE_CMD_DEFN_st */
            	30, 8,
            	30, 16,
            0, 16, 1, /* 870: struct.crypto_ex_data_st */
            	8, 0,
            0, 104, 11, /* 875: struct.x509_cinf_st */
            	89, 0,
            	89, 8,
            	118, 16,
            	53, 24,
            	900, 32,
            	53, 40,
            	912, 48,
            	89, 56,
            	89, 64,
            	8, 72,
            	159, 80,
            1, 8, 1, /* 900: pointer.struct.X509_val_st */
            	905, 0,
            0, 16, 2, /* 905: struct.X509_val_st */
            	89, 0,
            	89, 8,
            1, 8, 1, /* 912: pointer.struct.X509_pubkey_st */
            	917, 0,
            0, 24, 3, /* 917: struct.X509_pubkey_st */
            	118, 0,
            	89, 8,
            	926, 16,
            1, 8, 1, /* 926: pointer.struct.evp_pkey_st */
            	363, 0,
            1, 8, 1, /* 931: pointer.struct.x509_cinf_st */
            	875, 0,
            0, 184, 12, /* 936: struct.x509_st */
            	931, 0,
            	118, 8,
            	89, 16,
            	30, 32,
            	870, 40,
            	89, 104,
            	963, 112,
            	977, 120,
            	8, 128,
            	8, 136,
            	989, 144,
            	1001, 176,
            1, 8, 1, /* 963: pointer.struct.AUTHORITY_KEYID_st */
            	968, 0,
            0, 24, 3, /* 968: struct.AUTHORITY_KEYID_st */
            	89, 0,
            	8, 8,
            	89, 16,
            1, 8, 1, /* 977: pointer.struct.X509_POLICY_CACHE_st */
            	982, 0,
            0, 40, 2, /* 982: struct.X509_POLICY_CACHE_st */
            	176, 0,
            	8, 8,
            1, 8, 1, /* 989: pointer.struct.NAME_CONSTRAINTS_st */
            	994, 0,
            0, 16, 2, /* 994: struct.NAME_CONSTRAINTS_st */
            	8, 0,
            	8, 8,
            1, 8, 1, /* 1001: pointer.struct.x509_cert_aux_st */
            	1006, 0,
            0, 40, 5, /* 1006: struct.x509_cert_aux_st */
            	8, 0,
            	8, 8,
            	89, 16,
            	89, 24,
            	8, 32,
            1, 8, 1, /* 1019: pointer.struct.x509_st */
            	936, 0,
            0, 32, 3, /* 1024: struct.X509_POLICY_LEVEL_st */
            	1019, 0,
            	8, 8,
            	190, 16,
            0, 48, 4, /* 1033: struct.X509_POLICY_TREE_st */
            	1044, 0,
            	8, 16,
            	8, 24,
            	8, 32,
            1, 8, 1, /* 1044: pointer.struct.X509_POLICY_LEVEL_st */
            	1024, 0,
            0, 0, 0, /* 1049: func */
            1, 8, 1, /* 1052: pointer.struct.X509_crl_st */
            	1057, 0,
            0, 120, 10, /* 1057: struct.X509_crl_st */
            	164, 0,
            	118, 8,
            	89, 16,
            	963, 32,
            	1080, 40,
            	89, 56,
            	89, 64,
            	8, 96,
            	1085, 104,
            	30, 112,
            1, 8, 1, /* 1080: pointer.struct.ISSUING_DIST_POINT_st */
            	82, 0,
            1, 8, 1, /* 1085: pointer.struct.x509_crl_method_st */
            	1090, 0,
            0, 40, 4, /* 1090: struct.x509_crl_method_st */
            	1101, 8,
            	1101, 16,
            	1106, 24,
            	1111, 32,
            1, 8, 1, /* 1101: pointer.func */
            	0, 0,
            1, 8, 1, /* 1106: pointer.func */
            	1049, 0,
            1, 8, 1, /* 1111: pointer.func */
            	1116, 0,
            0, 0, 0, /* 1116: func */
            1, 8, 1, /* 1119: pointer.struct.x509_store_ctx_st.4286 */
            	1124, 0,
            0, 248, 25, /* 1124: struct.x509_store_ctx_st.4286 */
            	1177, 0,
            	1283, 16,
            	8, 24,
            	8, 32,
            	1215, 40,
            	30, 48,
            	309, 56,
            	1227, 64,
            	1235, 72,
            	1243, 80,
            	309, 88,
            	1251, 96,
            	1259, 104,
            	1267, 112,
            	309, 120,
            	1275, 128,
            	1275, 136,
            	309, 144,
            	8, 160,
            	1527, 168,
            	1283, 192,
            	1283, 200,
            	1052, 208,
            	1119, 224,
            	870, 232,
            1, 8, 1, /* 1177: pointer.struct.x509_store_st.4284 */
            	1182, 0,
            0, 144, 15, /* 1182: struct.x509_store_st.4284 */
            	8, 8,
            	8, 16,
            	1215, 24,
            	309, 32,
            	1227, 40,
            	1235, 48,
            	1243, 56,
            	309, 64,
            	1251, 72,
            	1259, 80,
            	1267, 88,
            	1275, 96,
            	1275, 104,
            	309, 112,
            	870, 120,
            1, 8, 1, /* 1215: pointer.struct.X509_VERIFY_PARAM_st */
            	1220, 0,
            0, 56, 2, /* 1220: struct.X509_VERIFY_PARAM_st */
            	30, 0,
            	8, 48,
            1, 8, 1, /* 1227: pointer.func */
            	1232, 0,
            0, 0, 0, /* 1232: func */
            1, 8, 1, /* 1235: pointer.func */
            	1240, 0,
            0, 0, 0, /* 1240: func */
            1, 8, 1, /* 1243: pointer.func */
            	1248, 0,
            0, 0, 0, /* 1248: func */
            1, 8, 1, /* 1251: pointer.func */
            	1256, 0,
            0, 0, 0, /* 1256: func */
            1, 8, 1, /* 1259: pointer.func */
            	1264, 0,
            0, 0, 0, /* 1264: func */
            1, 8, 1, /* 1267: pointer.func */
            	1272, 0,
            0, 0, 0, /* 1272: func */
            1, 8, 1, /* 1275: pointer.func */
            	1280, 0,
            0, 0, 0, /* 1280: func */
            1, 8, 1, /* 1283: pointer.struct.x509_st.3164 */
            	1288, 0,
            0, 184, 12, /* 1288: struct.x509_st.3164 */
            	1315, 0,
            	118, 8,
            	89, 16,
            	30, 32,
            	870, 40,
            	89, 104,
            	963, 112,
            	977, 120,
            	8, 128,
            	8, 136,
            	989, 144,
            	1001, 176,
            1, 8, 1, /* 1315: pointer.struct.x509_cinf_st.3159 */
            	1320, 0,
            0, 104, 11, /* 1320: struct.x509_cinf_st.3159 */
            	89, 0,
            	89, 8,
            	118, 16,
            	53, 24,
            	900, 32,
            	53, 40,
            	1345, 48,
            	89, 56,
            	89, 64,
            	8, 72,
            	159, 80,
            1, 8, 1, /* 1345: pointer.struct.X509_pubkey_st.2915 */
            	1350, 0,
            0, 24, 3, /* 1350: struct.X509_pubkey_st.2915 */
            	118, 0,
            	89, 8,
            	1359, 16,
            1, 8, 1, /* 1359: pointer.struct.evp_pkey_st.2930 */
            	1364, 0,
            0, 56, 4, /* 1364: struct.evp_pkey_st.2930 */
            	1375, 16,
            	374, 24,
            	154, 32,
            	8, 48,
            1, 8, 1, /* 1375: pointer.struct.evp_pkey_asn1_method_st.2928 */
            	1380, 0,
            0, 208, 24, /* 1380: struct.evp_pkey_asn1_method_st.2928 */
            	30, 16,
            	30, 24,
            	1431, 32,
            	1439, 40,
            	1447, 48,
            	1455, 56,
            	1463, 64,
            	1471, 72,
            	1455, 80,
            	1479, 88,
            	1479, 96,
            	1487, 104,
            	1495, 112,
            	1479, 120,
            	1447, 128,
            	1447, 136,
            	1455, 144,
            	342, 152,
            	1503, 160,
            	1511, 168,
            	1487, 176,
            	1495, 184,
            	1519, 192,
            	350, 200,
            1, 8, 1, /* 1431: pointer.func */
            	1436, 0,
            0, 0, 0, /* 1436: func */
            1, 8, 1, /* 1439: pointer.func */
            	1444, 0,
            0, 0, 0, /* 1444: func */
            1, 8, 1, /* 1447: pointer.func */
            	1452, 0,
            0, 0, 0, /* 1452: func */
            1, 8, 1, /* 1455: pointer.func */
            	1460, 0,
            0, 0, 0, /* 1460: func */
            1, 8, 1, /* 1463: pointer.func */
            	1468, 0,
            0, 0, 0, /* 1468: func */
            1, 8, 1, /* 1471: pointer.func */
            	1476, 0,
            0, 0, 0, /* 1476: func */
            1, 8, 1, /* 1479: pointer.func */
            	1484, 0,
            0, 0, 0, /* 1484: func */
            1, 8, 1, /* 1487: pointer.func */
            	1492, 0,
            0, 0, 0, /* 1492: func */
            1, 8, 1, /* 1495: pointer.func */
            	1500, 0,
            0, 0, 0, /* 1500: func */
            1, 8, 1, /* 1503: pointer.func */
            	1508, 0,
            0, 0, 0, /* 1508: func */
            1, 8, 1, /* 1511: pointer.func */
            	1516, 0,
            0, 0, 0, /* 1516: func */
            1, 8, 1, /* 1519: pointer.func */
            	1524, 0,
            0, 0, 0, /* 1524: func */
            1, 8, 1, /* 1527: pointer.struct.X509_POLICY_TREE_st */
            	1033, 0,
            0, 20, 0, /* 1532: array[20].char */
            0, 4, 0, /* 1535: int */
            0, 8, 0, /* 1538: long */
        },
        .arg_entity_index = { 1119, },
        .ret_entity_index = -1,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    X509_STORE_CTX * new_arg_a = *((X509_STORE_CTX * *)new_args->args[0]);

    void (*orig_X509_STORE_CTX_free)(X509_STORE_CTX *);
    orig_X509_STORE_CTX_free = dlsym(RTLD_NEXT, "X509_STORE_CTX_free");
    (*orig_X509_STORE_CTX_free)(new_arg_a);

    syscall(889);

}

