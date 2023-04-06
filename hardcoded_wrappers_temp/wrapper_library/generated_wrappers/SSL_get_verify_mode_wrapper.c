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

int bb_SSL_get_verify_mode(const SSL * arg_a);

int SSL_get_verify_mode(const SSL * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_get_verify_mode called %lu\n", in_lib);
    if (!in_lib)
        return bb_SSL_get_verify_mode(arg_a);
    else {
        int (*orig_SSL_get_verify_mode)(const SSL *);
        orig_SSL_get_verify_mode = dlsym(RTLD_NEXT, "SSL_get_verify_mode");
        return orig_SSL_get_verify_mode(arg_a);
    }
}

int bb_SSL_get_verify_mode(const SSL * arg_a) 
{
    int ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 16, 1, /* 0: struct.tls_session_ticket_ext_st */
            	5, 8,
            0, 8, 0, /* 5: pointer.void */
            0, 24, 1, /* 8: struct.asn1_string_st */
            	13, 8,
            1, 8, 1, /* 13: pointer.unsigned char */
            	18, 0,
            0, 1, 0, /* 18: unsigned char */
            0, 24, 1, /* 21: struct.buf_mem_st */
            	26, 8,
            1, 8, 1, /* 26: pointer.char */
            	8884096, 0,
            0, 8, 2, /* 31: union.unknown */
            	38, 0,
            	133, 0,
            1, 8, 1, /* 38: pointer.struct.X509_name_st */
            	43, 0,
            0, 40, 3, /* 43: struct.X509_name_st */
            	52, 0,
            	128, 16,
            	13, 24,
            1, 8, 1, /* 52: pointer.struct.stack_st_X509_NAME_ENTRY */
            	57, 0,
            0, 32, 2, /* 57: struct.stack_st_fake_X509_NAME_ENTRY */
            	64, 8,
            	125, 24,
            8884099, 8, 2, /* 64: pointer_to_array_of_pointers_to_stack */
            	71, 0,
            	122, 20,
            0, 8, 1, /* 71: pointer.X509_NAME_ENTRY */
            	76, 0,
            0, 0, 1, /* 76: X509_NAME_ENTRY */
            	81, 0,
            0, 24, 2, /* 81: struct.X509_name_entry_st */
            	88, 0,
            	112, 8,
            1, 8, 1, /* 88: pointer.struct.asn1_object_st */
            	93, 0,
            0, 40, 3, /* 93: struct.asn1_object_st */
            	102, 0,
            	102, 8,
            	107, 24,
            1, 8, 1, /* 102: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 107: pointer.unsigned char */
            	18, 0,
            1, 8, 1, /* 112: pointer.struct.asn1_string_st */
            	117, 0,
            0, 24, 1, /* 117: struct.asn1_string_st */
            	13, 8,
            0, 4, 0, /* 122: int */
            8884097, 8, 0, /* 125: pointer.func */
            1, 8, 1, /* 128: pointer.struct.buf_mem_st */
            	21, 0,
            1, 8, 1, /* 133: pointer.struct.asn1_string_st */
            	8, 0,
            0, 0, 1, /* 138: OCSP_RESPID */
            	143, 0,
            0, 16, 1, /* 143: struct.ocsp_responder_id_st */
            	31, 8,
            0, 16, 1, /* 148: struct.srtp_protection_profile_st */
            	102, 0,
            8884097, 8, 0, /* 153: pointer.func */
            8884097, 8, 0, /* 156: pointer.func */
            1, 8, 1, /* 159: pointer.struct.bignum_st */
            	164, 0,
            0, 24, 1, /* 164: struct.bignum_st */
            	169, 0,
            1, 8, 1, /* 169: pointer.unsigned int */
            	174, 0,
            0, 4, 0, /* 174: unsigned int */
            0, 8, 1, /* 177: struct.ssl3_buf_freelist_entry_st */
            	182, 0,
            1, 8, 1, /* 182: pointer.struct.ssl3_buf_freelist_entry_st */
            	177, 0,
            0, 24, 1, /* 187: struct.ssl3_buf_freelist_st */
            	182, 16,
            1, 8, 1, /* 192: pointer.struct.ssl3_buf_freelist_st */
            	187, 0,
            8884097, 8, 0, /* 197: pointer.func */
            8884097, 8, 0, /* 200: pointer.func */
            0, 64, 7, /* 203: struct.comp_method_st */
            	102, 8,
            	220, 16,
            	200, 24,
            	223, 32,
            	223, 40,
            	226, 48,
            	226, 56,
            8884097, 8, 0, /* 220: pointer.func */
            8884097, 8, 0, /* 223: pointer.func */
            8884097, 8, 0, /* 226: pointer.func */
            0, 0, 1, /* 229: SSL_COMP */
            	234, 0,
            0, 24, 2, /* 234: struct.ssl_comp_st */
            	102, 8,
            	241, 16,
            1, 8, 1, /* 241: pointer.struct.comp_method_st */
            	203, 0,
            1, 8, 1, /* 246: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	251, 0,
            0, 32, 2, /* 251: struct.stack_st_fake_SRTP_PROTECTION_PROFILE */
            	258, 8,
            	125, 24,
            8884099, 8, 2, /* 258: pointer_to_array_of_pointers_to_stack */
            	265, 0,
            	122, 20,
            0, 8, 1, /* 265: pointer.SRTP_PROTECTION_PROFILE */
            	270, 0,
            0, 0, 1, /* 270: SRTP_PROTECTION_PROFILE */
            	148, 0,
            1, 8, 1, /* 275: pointer.struct.stack_st_SSL_COMP */
            	280, 0,
            0, 32, 2, /* 280: struct.stack_st_fake_SSL_COMP */
            	287, 8,
            	125, 24,
            8884099, 8, 2, /* 287: pointer_to_array_of_pointers_to_stack */
            	294, 0,
            	122, 20,
            0, 8, 1, /* 294: pointer.SSL_COMP */
            	229, 0,
            8884097, 8, 0, /* 299: pointer.func */
            8884097, 8, 0, /* 302: pointer.func */
            8884097, 8, 0, /* 305: pointer.func */
            8884097, 8, 0, /* 308: pointer.func */
            8884097, 8, 0, /* 311: pointer.func */
            1, 8, 1, /* 314: pointer.struct.lhash_node_st */
            	319, 0,
            0, 24, 2, /* 319: struct.lhash_node_st */
            	5, 0,
            	314, 8,
            1, 8, 1, /* 326: pointer.struct.lhash_st */
            	331, 0,
            0, 176, 3, /* 331: struct.lhash_st */
            	340, 0,
            	125, 8,
            	347, 16,
            8884099, 8, 2, /* 340: pointer_to_array_of_pointers_to_stack */
            	314, 0,
            	174, 28,
            8884097, 8, 0, /* 347: pointer.func */
            8884097, 8, 0, /* 350: pointer.func */
            8884097, 8, 0, /* 353: pointer.func */
            8884097, 8, 0, /* 356: pointer.func */
            8884097, 8, 0, /* 359: pointer.func */
            8884097, 8, 0, /* 362: pointer.func */
            8884097, 8, 0, /* 365: pointer.func */
            8884097, 8, 0, /* 368: pointer.func */
            8884097, 8, 0, /* 371: pointer.func */
            1, 8, 1, /* 374: pointer.struct.X509_VERIFY_PARAM_st */
            	379, 0,
            0, 56, 2, /* 379: struct.X509_VERIFY_PARAM_st */
            	26, 0,
            	386, 48,
            1, 8, 1, /* 386: pointer.struct.stack_st_ASN1_OBJECT */
            	391, 0,
            0, 32, 2, /* 391: struct.stack_st_fake_ASN1_OBJECT */
            	398, 8,
            	125, 24,
            8884099, 8, 2, /* 398: pointer_to_array_of_pointers_to_stack */
            	405, 0,
            	122, 20,
            0, 8, 1, /* 405: pointer.ASN1_OBJECT */
            	410, 0,
            0, 0, 1, /* 410: ASN1_OBJECT */
            	415, 0,
            0, 40, 3, /* 415: struct.asn1_object_st */
            	102, 0,
            	102, 8,
            	107, 24,
            1, 8, 1, /* 424: pointer.struct.stack_st_X509_OBJECT */
            	429, 0,
            0, 32, 2, /* 429: struct.stack_st_fake_X509_OBJECT */
            	436, 8,
            	125, 24,
            8884099, 8, 2, /* 436: pointer_to_array_of_pointers_to_stack */
            	443, 0,
            	122, 20,
            0, 8, 1, /* 443: pointer.X509_OBJECT */
            	448, 0,
            0, 0, 1, /* 448: X509_OBJECT */
            	453, 0,
            0, 16, 1, /* 453: struct.x509_object_st */
            	458, 8,
            0, 8, 4, /* 458: union.unknown */
            	26, 0,
            	469, 0,
            	3964, 0,
            	4197, 0,
            1, 8, 1, /* 469: pointer.struct.x509_st */
            	474, 0,
            0, 184, 12, /* 474: struct.x509_st */
            	501, 0,
            	541, 8,
            	2595, 16,
            	26, 32,
            	2665, 40,
            	2687, 104,
            	2692, 112,
            	3015, 120,
            	3437, 128,
            	3576, 136,
            	3600, 144,
            	3912, 176,
            1, 8, 1, /* 501: pointer.struct.x509_cinf_st */
            	506, 0,
            0, 104, 11, /* 506: struct.x509_cinf_st */
            	531, 0,
            	531, 8,
            	541, 16,
            	708, 24,
            	756, 32,
            	708, 40,
            	773, 48,
            	2595, 56,
            	2595, 64,
            	2600, 72,
            	2660, 80,
            1, 8, 1, /* 531: pointer.struct.asn1_string_st */
            	536, 0,
            0, 24, 1, /* 536: struct.asn1_string_st */
            	13, 8,
            1, 8, 1, /* 541: pointer.struct.X509_algor_st */
            	546, 0,
            0, 16, 2, /* 546: struct.X509_algor_st */
            	553, 0,
            	567, 8,
            1, 8, 1, /* 553: pointer.struct.asn1_object_st */
            	558, 0,
            0, 40, 3, /* 558: struct.asn1_object_st */
            	102, 0,
            	102, 8,
            	107, 24,
            1, 8, 1, /* 567: pointer.struct.asn1_type_st */
            	572, 0,
            0, 16, 1, /* 572: struct.asn1_type_st */
            	577, 8,
            0, 8, 20, /* 577: union.unknown */
            	26, 0,
            	620, 0,
            	553, 0,
            	630, 0,
            	635, 0,
            	640, 0,
            	645, 0,
            	650, 0,
            	655, 0,
            	660, 0,
            	665, 0,
            	670, 0,
            	675, 0,
            	680, 0,
            	685, 0,
            	690, 0,
            	695, 0,
            	620, 0,
            	620, 0,
            	700, 0,
            1, 8, 1, /* 620: pointer.struct.asn1_string_st */
            	625, 0,
            0, 24, 1, /* 625: struct.asn1_string_st */
            	13, 8,
            1, 8, 1, /* 630: pointer.struct.asn1_string_st */
            	625, 0,
            1, 8, 1, /* 635: pointer.struct.asn1_string_st */
            	625, 0,
            1, 8, 1, /* 640: pointer.struct.asn1_string_st */
            	625, 0,
            1, 8, 1, /* 645: pointer.struct.asn1_string_st */
            	625, 0,
            1, 8, 1, /* 650: pointer.struct.asn1_string_st */
            	625, 0,
            1, 8, 1, /* 655: pointer.struct.asn1_string_st */
            	625, 0,
            1, 8, 1, /* 660: pointer.struct.asn1_string_st */
            	625, 0,
            1, 8, 1, /* 665: pointer.struct.asn1_string_st */
            	625, 0,
            1, 8, 1, /* 670: pointer.struct.asn1_string_st */
            	625, 0,
            1, 8, 1, /* 675: pointer.struct.asn1_string_st */
            	625, 0,
            1, 8, 1, /* 680: pointer.struct.asn1_string_st */
            	625, 0,
            1, 8, 1, /* 685: pointer.struct.asn1_string_st */
            	625, 0,
            1, 8, 1, /* 690: pointer.struct.asn1_string_st */
            	625, 0,
            1, 8, 1, /* 695: pointer.struct.asn1_string_st */
            	625, 0,
            1, 8, 1, /* 700: pointer.struct.ASN1_VALUE_st */
            	705, 0,
            0, 0, 0, /* 705: struct.ASN1_VALUE_st */
            1, 8, 1, /* 708: pointer.struct.X509_name_st */
            	713, 0,
            0, 40, 3, /* 713: struct.X509_name_st */
            	722, 0,
            	746, 16,
            	13, 24,
            1, 8, 1, /* 722: pointer.struct.stack_st_X509_NAME_ENTRY */
            	727, 0,
            0, 32, 2, /* 727: struct.stack_st_fake_X509_NAME_ENTRY */
            	734, 8,
            	125, 24,
            8884099, 8, 2, /* 734: pointer_to_array_of_pointers_to_stack */
            	741, 0,
            	122, 20,
            0, 8, 1, /* 741: pointer.X509_NAME_ENTRY */
            	76, 0,
            1, 8, 1, /* 746: pointer.struct.buf_mem_st */
            	751, 0,
            0, 24, 1, /* 751: struct.buf_mem_st */
            	26, 8,
            1, 8, 1, /* 756: pointer.struct.X509_val_st */
            	761, 0,
            0, 16, 2, /* 761: struct.X509_val_st */
            	768, 0,
            	768, 8,
            1, 8, 1, /* 768: pointer.struct.asn1_string_st */
            	536, 0,
            1, 8, 1, /* 773: pointer.struct.X509_pubkey_st */
            	778, 0,
            0, 24, 3, /* 778: struct.X509_pubkey_st */
            	787, 0,
            	792, 8,
            	802, 16,
            1, 8, 1, /* 787: pointer.struct.X509_algor_st */
            	546, 0,
            1, 8, 1, /* 792: pointer.struct.asn1_string_st */
            	797, 0,
            0, 24, 1, /* 797: struct.asn1_string_st */
            	13, 8,
            1, 8, 1, /* 802: pointer.struct.evp_pkey_st */
            	807, 0,
            0, 56, 4, /* 807: struct.evp_pkey_st */
            	818, 16,
            	919, 24,
            	1272, 32,
            	2216, 48,
            1, 8, 1, /* 818: pointer.struct.evp_pkey_asn1_method_st */
            	823, 0,
            0, 208, 24, /* 823: struct.evp_pkey_asn1_method_st */
            	26, 16,
            	26, 24,
            	874, 32,
            	877, 40,
            	880, 48,
            	883, 56,
            	886, 64,
            	889, 72,
            	883, 80,
            	892, 88,
            	892, 96,
            	895, 104,
            	898, 112,
            	892, 120,
            	901, 128,
            	880, 136,
            	883, 144,
            	904, 152,
            	907, 160,
            	910, 168,
            	895, 176,
            	898, 184,
            	913, 192,
            	916, 200,
            8884097, 8, 0, /* 874: pointer.func */
            8884097, 8, 0, /* 877: pointer.func */
            8884097, 8, 0, /* 880: pointer.func */
            8884097, 8, 0, /* 883: pointer.func */
            8884097, 8, 0, /* 886: pointer.func */
            8884097, 8, 0, /* 889: pointer.func */
            8884097, 8, 0, /* 892: pointer.func */
            8884097, 8, 0, /* 895: pointer.func */
            8884097, 8, 0, /* 898: pointer.func */
            8884097, 8, 0, /* 901: pointer.func */
            8884097, 8, 0, /* 904: pointer.func */
            8884097, 8, 0, /* 907: pointer.func */
            8884097, 8, 0, /* 910: pointer.func */
            8884097, 8, 0, /* 913: pointer.func */
            8884097, 8, 0, /* 916: pointer.func */
            1, 8, 1, /* 919: pointer.struct.engine_st */
            	924, 0,
            0, 216, 24, /* 924: struct.engine_st */
            	102, 0,
            	102, 8,
            	975, 16,
            	1030, 24,
            	1081, 32,
            	1117, 40,
            	1134, 48,
            	1161, 56,
            	1196, 64,
            	1204, 72,
            	1207, 80,
            	1210, 88,
            	1213, 96,
            	1216, 104,
            	1216, 112,
            	1216, 120,
            	1219, 128,
            	1222, 136,
            	1222, 144,
            	1225, 152,
            	1228, 160,
            	1240, 184,
            	1267, 200,
            	1267, 208,
            1, 8, 1, /* 975: pointer.struct.rsa_meth_st */
            	980, 0,
            0, 112, 13, /* 980: struct.rsa_meth_st */
            	102, 0,
            	1009, 8,
            	1009, 16,
            	1009, 24,
            	1009, 32,
            	1012, 40,
            	1015, 48,
            	1018, 56,
            	1018, 64,
            	26, 80,
            	1021, 88,
            	1024, 96,
            	1027, 104,
            8884097, 8, 0, /* 1009: pointer.func */
            8884097, 8, 0, /* 1012: pointer.func */
            8884097, 8, 0, /* 1015: pointer.func */
            8884097, 8, 0, /* 1018: pointer.func */
            8884097, 8, 0, /* 1021: pointer.func */
            8884097, 8, 0, /* 1024: pointer.func */
            8884097, 8, 0, /* 1027: pointer.func */
            1, 8, 1, /* 1030: pointer.struct.dsa_method */
            	1035, 0,
            0, 96, 11, /* 1035: struct.dsa_method */
            	102, 0,
            	1060, 8,
            	1063, 16,
            	1066, 24,
            	1069, 32,
            	1072, 40,
            	1075, 48,
            	1075, 56,
            	26, 72,
            	1078, 80,
            	1075, 88,
            8884097, 8, 0, /* 1060: pointer.func */
            8884097, 8, 0, /* 1063: pointer.func */
            8884097, 8, 0, /* 1066: pointer.func */
            8884097, 8, 0, /* 1069: pointer.func */
            8884097, 8, 0, /* 1072: pointer.func */
            8884097, 8, 0, /* 1075: pointer.func */
            8884097, 8, 0, /* 1078: pointer.func */
            1, 8, 1, /* 1081: pointer.struct.dh_method */
            	1086, 0,
            0, 72, 8, /* 1086: struct.dh_method */
            	102, 0,
            	1105, 8,
            	1108, 16,
            	1111, 24,
            	1105, 32,
            	1105, 40,
            	26, 56,
            	1114, 64,
            8884097, 8, 0, /* 1105: pointer.func */
            8884097, 8, 0, /* 1108: pointer.func */
            8884097, 8, 0, /* 1111: pointer.func */
            8884097, 8, 0, /* 1114: pointer.func */
            1, 8, 1, /* 1117: pointer.struct.ecdh_method */
            	1122, 0,
            0, 32, 3, /* 1122: struct.ecdh_method */
            	102, 0,
            	1131, 8,
            	26, 24,
            8884097, 8, 0, /* 1131: pointer.func */
            1, 8, 1, /* 1134: pointer.struct.ecdsa_method */
            	1139, 0,
            0, 48, 5, /* 1139: struct.ecdsa_method */
            	102, 0,
            	1152, 8,
            	1155, 16,
            	1158, 24,
            	26, 40,
            8884097, 8, 0, /* 1152: pointer.func */
            8884097, 8, 0, /* 1155: pointer.func */
            8884097, 8, 0, /* 1158: pointer.func */
            1, 8, 1, /* 1161: pointer.struct.rand_meth_st */
            	1166, 0,
            0, 48, 6, /* 1166: struct.rand_meth_st */
            	1181, 0,
            	1184, 8,
            	1187, 16,
            	1190, 24,
            	1184, 32,
            	1193, 40,
            8884097, 8, 0, /* 1181: pointer.func */
            8884097, 8, 0, /* 1184: pointer.func */
            8884097, 8, 0, /* 1187: pointer.func */
            8884097, 8, 0, /* 1190: pointer.func */
            8884097, 8, 0, /* 1193: pointer.func */
            1, 8, 1, /* 1196: pointer.struct.store_method_st */
            	1201, 0,
            0, 0, 0, /* 1201: struct.store_method_st */
            8884097, 8, 0, /* 1204: pointer.func */
            8884097, 8, 0, /* 1207: pointer.func */
            8884097, 8, 0, /* 1210: pointer.func */
            8884097, 8, 0, /* 1213: pointer.func */
            8884097, 8, 0, /* 1216: pointer.func */
            8884097, 8, 0, /* 1219: pointer.func */
            8884097, 8, 0, /* 1222: pointer.func */
            8884097, 8, 0, /* 1225: pointer.func */
            1, 8, 1, /* 1228: pointer.struct.ENGINE_CMD_DEFN_st */
            	1233, 0,
            0, 32, 2, /* 1233: struct.ENGINE_CMD_DEFN_st */
            	102, 8,
            	102, 16,
            0, 16, 1, /* 1240: struct.crypto_ex_data_st */
            	1245, 0,
            1, 8, 1, /* 1245: pointer.struct.stack_st_void */
            	1250, 0,
            0, 32, 1, /* 1250: struct.stack_st_void */
            	1255, 0,
            0, 32, 2, /* 1255: struct.stack_st */
            	1262, 8,
            	125, 24,
            1, 8, 1, /* 1262: pointer.pointer.char */
            	26, 0,
            1, 8, 1, /* 1267: pointer.struct.engine_st */
            	924, 0,
            0, 8, 5, /* 1272: union.unknown */
            	26, 0,
            	1285, 0,
            	1487, 0,
            	1614, 0,
            	1728, 0,
            1, 8, 1, /* 1285: pointer.struct.rsa_st */
            	1290, 0,
            0, 168, 17, /* 1290: struct.rsa_st */
            	1327, 16,
            	1382, 24,
            	1387, 32,
            	1387, 40,
            	1387, 48,
            	1387, 56,
            	1387, 64,
            	1387, 72,
            	1387, 80,
            	1387, 88,
            	1397, 96,
            	1419, 120,
            	1419, 128,
            	1419, 136,
            	26, 144,
            	1433, 152,
            	1433, 160,
            1, 8, 1, /* 1327: pointer.struct.rsa_meth_st */
            	1332, 0,
            0, 112, 13, /* 1332: struct.rsa_meth_st */
            	102, 0,
            	1361, 8,
            	1361, 16,
            	1361, 24,
            	1361, 32,
            	1364, 40,
            	1367, 48,
            	1370, 56,
            	1370, 64,
            	26, 80,
            	1373, 88,
            	1376, 96,
            	1379, 104,
            8884097, 8, 0, /* 1361: pointer.func */
            8884097, 8, 0, /* 1364: pointer.func */
            8884097, 8, 0, /* 1367: pointer.func */
            8884097, 8, 0, /* 1370: pointer.func */
            8884097, 8, 0, /* 1373: pointer.func */
            8884097, 8, 0, /* 1376: pointer.func */
            8884097, 8, 0, /* 1379: pointer.func */
            1, 8, 1, /* 1382: pointer.struct.engine_st */
            	924, 0,
            1, 8, 1, /* 1387: pointer.struct.bignum_st */
            	1392, 0,
            0, 24, 1, /* 1392: struct.bignum_st */
            	169, 0,
            0, 16, 1, /* 1397: struct.crypto_ex_data_st */
            	1402, 0,
            1, 8, 1, /* 1402: pointer.struct.stack_st_void */
            	1407, 0,
            0, 32, 1, /* 1407: struct.stack_st_void */
            	1412, 0,
            0, 32, 2, /* 1412: struct.stack_st */
            	1262, 8,
            	125, 24,
            1, 8, 1, /* 1419: pointer.struct.bn_mont_ctx_st */
            	1424, 0,
            0, 96, 3, /* 1424: struct.bn_mont_ctx_st */
            	1392, 8,
            	1392, 32,
            	1392, 56,
            1, 8, 1, /* 1433: pointer.struct.bn_blinding_st */
            	1438, 0,
            0, 88, 7, /* 1438: struct.bn_blinding_st */
            	1455, 0,
            	1455, 8,
            	1455, 16,
            	1455, 24,
            	1465, 40,
            	1470, 72,
            	1484, 80,
            1, 8, 1, /* 1455: pointer.struct.bignum_st */
            	1460, 0,
            0, 24, 1, /* 1460: struct.bignum_st */
            	169, 0,
            0, 16, 1, /* 1465: struct.crypto_threadid_st */
            	5, 0,
            1, 8, 1, /* 1470: pointer.struct.bn_mont_ctx_st */
            	1475, 0,
            0, 96, 3, /* 1475: struct.bn_mont_ctx_st */
            	1460, 8,
            	1460, 32,
            	1460, 56,
            8884097, 8, 0, /* 1484: pointer.func */
            1, 8, 1, /* 1487: pointer.struct.dsa_st */
            	1492, 0,
            0, 136, 11, /* 1492: struct.dsa_st */
            	1517, 24,
            	1517, 32,
            	1517, 40,
            	1517, 48,
            	1517, 56,
            	1517, 64,
            	1517, 72,
            	1527, 88,
            	1541, 104,
            	1563, 120,
            	919, 128,
            1, 8, 1, /* 1517: pointer.struct.bignum_st */
            	1522, 0,
            0, 24, 1, /* 1522: struct.bignum_st */
            	169, 0,
            1, 8, 1, /* 1527: pointer.struct.bn_mont_ctx_st */
            	1532, 0,
            0, 96, 3, /* 1532: struct.bn_mont_ctx_st */
            	1522, 8,
            	1522, 32,
            	1522, 56,
            0, 16, 1, /* 1541: struct.crypto_ex_data_st */
            	1546, 0,
            1, 8, 1, /* 1546: pointer.struct.stack_st_void */
            	1551, 0,
            0, 32, 1, /* 1551: struct.stack_st_void */
            	1556, 0,
            0, 32, 2, /* 1556: struct.stack_st */
            	1262, 8,
            	125, 24,
            1, 8, 1, /* 1563: pointer.struct.dsa_method */
            	1568, 0,
            0, 96, 11, /* 1568: struct.dsa_method */
            	102, 0,
            	1593, 8,
            	1596, 16,
            	1599, 24,
            	1602, 32,
            	1605, 40,
            	1608, 48,
            	1608, 56,
            	26, 72,
            	1611, 80,
            	1608, 88,
            8884097, 8, 0, /* 1593: pointer.func */
            8884097, 8, 0, /* 1596: pointer.func */
            8884097, 8, 0, /* 1599: pointer.func */
            8884097, 8, 0, /* 1602: pointer.func */
            8884097, 8, 0, /* 1605: pointer.func */
            8884097, 8, 0, /* 1608: pointer.func */
            8884097, 8, 0, /* 1611: pointer.func */
            1, 8, 1, /* 1614: pointer.struct.dh_st */
            	1619, 0,
            0, 144, 12, /* 1619: struct.dh_st */
            	1646, 8,
            	1646, 16,
            	1646, 32,
            	1646, 40,
            	1656, 56,
            	1646, 64,
            	1646, 72,
            	13, 80,
            	1646, 96,
            	1670, 112,
            	1692, 128,
            	1382, 136,
            1, 8, 1, /* 1646: pointer.struct.bignum_st */
            	1651, 0,
            0, 24, 1, /* 1651: struct.bignum_st */
            	169, 0,
            1, 8, 1, /* 1656: pointer.struct.bn_mont_ctx_st */
            	1661, 0,
            0, 96, 3, /* 1661: struct.bn_mont_ctx_st */
            	1651, 8,
            	1651, 32,
            	1651, 56,
            0, 16, 1, /* 1670: struct.crypto_ex_data_st */
            	1675, 0,
            1, 8, 1, /* 1675: pointer.struct.stack_st_void */
            	1680, 0,
            0, 32, 1, /* 1680: struct.stack_st_void */
            	1685, 0,
            0, 32, 2, /* 1685: struct.stack_st */
            	1262, 8,
            	125, 24,
            1, 8, 1, /* 1692: pointer.struct.dh_method */
            	1697, 0,
            0, 72, 8, /* 1697: struct.dh_method */
            	102, 0,
            	1716, 8,
            	1719, 16,
            	1722, 24,
            	1716, 32,
            	1716, 40,
            	26, 56,
            	1725, 64,
            8884097, 8, 0, /* 1716: pointer.func */
            8884097, 8, 0, /* 1719: pointer.func */
            8884097, 8, 0, /* 1722: pointer.func */
            8884097, 8, 0, /* 1725: pointer.func */
            1, 8, 1, /* 1728: pointer.struct.ec_key_st */
            	1733, 0,
            0, 56, 4, /* 1733: struct.ec_key_st */
            	1744, 8,
            	2178, 16,
            	2183, 24,
            	2193, 48,
            1, 8, 1, /* 1744: pointer.struct.ec_group_st */
            	1749, 0,
            0, 232, 12, /* 1749: struct.ec_group_st */
            	1776, 0,
            	1948, 8,
            	2141, 16,
            	2141, 40,
            	13, 80,
            	2146, 96,
            	2141, 104,
            	2141, 152,
            	2141, 176,
            	5, 208,
            	5, 216,
            	2175, 224,
            1, 8, 1, /* 1776: pointer.struct.ec_method_st */
            	1781, 0,
            0, 304, 37, /* 1781: struct.ec_method_st */
            	1858, 8,
            	1861, 16,
            	1861, 24,
            	1864, 32,
            	1867, 40,
            	1870, 48,
            	1873, 56,
            	1876, 64,
            	1879, 72,
            	1882, 80,
            	1882, 88,
            	1885, 96,
            	1888, 104,
            	1891, 112,
            	1894, 120,
            	1897, 128,
            	1900, 136,
            	1903, 144,
            	1906, 152,
            	1909, 160,
            	1912, 168,
            	1915, 176,
            	1918, 184,
            	1921, 192,
            	1924, 200,
            	1927, 208,
            	1918, 216,
            	1930, 224,
            	1933, 232,
            	1936, 240,
            	1873, 248,
            	1939, 256,
            	1942, 264,
            	1939, 272,
            	1942, 280,
            	1942, 288,
            	1945, 296,
            8884097, 8, 0, /* 1858: pointer.func */
            8884097, 8, 0, /* 1861: pointer.func */
            8884097, 8, 0, /* 1864: pointer.func */
            8884097, 8, 0, /* 1867: pointer.func */
            8884097, 8, 0, /* 1870: pointer.func */
            8884097, 8, 0, /* 1873: pointer.func */
            8884097, 8, 0, /* 1876: pointer.func */
            8884097, 8, 0, /* 1879: pointer.func */
            8884097, 8, 0, /* 1882: pointer.func */
            8884097, 8, 0, /* 1885: pointer.func */
            8884097, 8, 0, /* 1888: pointer.func */
            8884097, 8, 0, /* 1891: pointer.func */
            8884097, 8, 0, /* 1894: pointer.func */
            8884097, 8, 0, /* 1897: pointer.func */
            8884097, 8, 0, /* 1900: pointer.func */
            8884097, 8, 0, /* 1903: pointer.func */
            8884097, 8, 0, /* 1906: pointer.func */
            8884097, 8, 0, /* 1909: pointer.func */
            8884097, 8, 0, /* 1912: pointer.func */
            8884097, 8, 0, /* 1915: pointer.func */
            8884097, 8, 0, /* 1918: pointer.func */
            8884097, 8, 0, /* 1921: pointer.func */
            8884097, 8, 0, /* 1924: pointer.func */
            8884097, 8, 0, /* 1927: pointer.func */
            8884097, 8, 0, /* 1930: pointer.func */
            8884097, 8, 0, /* 1933: pointer.func */
            8884097, 8, 0, /* 1936: pointer.func */
            8884097, 8, 0, /* 1939: pointer.func */
            8884097, 8, 0, /* 1942: pointer.func */
            8884097, 8, 0, /* 1945: pointer.func */
            1, 8, 1, /* 1948: pointer.struct.ec_point_st */
            	1953, 0,
            0, 88, 4, /* 1953: struct.ec_point_st */
            	1964, 0,
            	2136, 8,
            	2136, 32,
            	2136, 56,
            1, 8, 1, /* 1964: pointer.struct.ec_method_st */
            	1969, 0,
            0, 304, 37, /* 1969: struct.ec_method_st */
            	2046, 8,
            	2049, 16,
            	2049, 24,
            	2052, 32,
            	2055, 40,
            	2058, 48,
            	2061, 56,
            	2064, 64,
            	2067, 72,
            	2070, 80,
            	2070, 88,
            	2073, 96,
            	2076, 104,
            	2079, 112,
            	2082, 120,
            	2085, 128,
            	2088, 136,
            	2091, 144,
            	2094, 152,
            	2097, 160,
            	2100, 168,
            	2103, 176,
            	2106, 184,
            	2109, 192,
            	2112, 200,
            	2115, 208,
            	2106, 216,
            	2118, 224,
            	2121, 232,
            	2124, 240,
            	2061, 248,
            	2127, 256,
            	2130, 264,
            	2127, 272,
            	2130, 280,
            	2130, 288,
            	2133, 296,
            8884097, 8, 0, /* 2046: pointer.func */
            8884097, 8, 0, /* 2049: pointer.func */
            8884097, 8, 0, /* 2052: pointer.func */
            8884097, 8, 0, /* 2055: pointer.func */
            8884097, 8, 0, /* 2058: pointer.func */
            8884097, 8, 0, /* 2061: pointer.func */
            8884097, 8, 0, /* 2064: pointer.func */
            8884097, 8, 0, /* 2067: pointer.func */
            8884097, 8, 0, /* 2070: pointer.func */
            8884097, 8, 0, /* 2073: pointer.func */
            8884097, 8, 0, /* 2076: pointer.func */
            8884097, 8, 0, /* 2079: pointer.func */
            8884097, 8, 0, /* 2082: pointer.func */
            8884097, 8, 0, /* 2085: pointer.func */
            8884097, 8, 0, /* 2088: pointer.func */
            8884097, 8, 0, /* 2091: pointer.func */
            8884097, 8, 0, /* 2094: pointer.func */
            8884097, 8, 0, /* 2097: pointer.func */
            8884097, 8, 0, /* 2100: pointer.func */
            8884097, 8, 0, /* 2103: pointer.func */
            8884097, 8, 0, /* 2106: pointer.func */
            8884097, 8, 0, /* 2109: pointer.func */
            8884097, 8, 0, /* 2112: pointer.func */
            8884097, 8, 0, /* 2115: pointer.func */
            8884097, 8, 0, /* 2118: pointer.func */
            8884097, 8, 0, /* 2121: pointer.func */
            8884097, 8, 0, /* 2124: pointer.func */
            8884097, 8, 0, /* 2127: pointer.func */
            8884097, 8, 0, /* 2130: pointer.func */
            8884097, 8, 0, /* 2133: pointer.func */
            0, 24, 1, /* 2136: struct.bignum_st */
            	169, 0,
            0, 24, 1, /* 2141: struct.bignum_st */
            	169, 0,
            1, 8, 1, /* 2146: pointer.struct.ec_extra_data_st */
            	2151, 0,
            0, 40, 5, /* 2151: struct.ec_extra_data_st */
            	2164, 0,
            	5, 8,
            	2169, 16,
            	2172, 24,
            	2172, 32,
            1, 8, 1, /* 2164: pointer.struct.ec_extra_data_st */
            	2151, 0,
            8884097, 8, 0, /* 2169: pointer.func */
            8884097, 8, 0, /* 2172: pointer.func */
            8884097, 8, 0, /* 2175: pointer.func */
            1, 8, 1, /* 2178: pointer.struct.ec_point_st */
            	1953, 0,
            1, 8, 1, /* 2183: pointer.struct.bignum_st */
            	2188, 0,
            0, 24, 1, /* 2188: struct.bignum_st */
            	169, 0,
            1, 8, 1, /* 2193: pointer.struct.ec_extra_data_st */
            	2198, 0,
            0, 40, 5, /* 2198: struct.ec_extra_data_st */
            	2211, 0,
            	5, 8,
            	2169, 16,
            	2172, 24,
            	2172, 32,
            1, 8, 1, /* 2211: pointer.struct.ec_extra_data_st */
            	2198, 0,
            1, 8, 1, /* 2216: pointer.struct.stack_st_X509_ATTRIBUTE */
            	2221, 0,
            0, 32, 2, /* 2221: struct.stack_st_fake_X509_ATTRIBUTE */
            	2228, 8,
            	125, 24,
            8884099, 8, 2, /* 2228: pointer_to_array_of_pointers_to_stack */
            	2235, 0,
            	122, 20,
            0, 8, 1, /* 2235: pointer.X509_ATTRIBUTE */
            	2240, 0,
            0, 0, 1, /* 2240: X509_ATTRIBUTE */
            	2245, 0,
            0, 24, 2, /* 2245: struct.x509_attributes_st */
            	2252, 0,
            	2266, 16,
            1, 8, 1, /* 2252: pointer.struct.asn1_object_st */
            	2257, 0,
            0, 40, 3, /* 2257: struct.asn1_object_st */
            	102, 0,
            	102, 8,
            	107, 24,
            0, 8, 3, /* 2266: union.unknown */
            	26, 0,
            	2275, 0,
            	2454, 0,
            1, 8, 1, /* 2275: pointer.struct.stack_st_ASN1_TYPE */
            	2280, 0,
            0, 32, 2, /* 2280: struct.stack_st_fake_ASN1_TYPE */
            	2287, 8,
            	125, 24,
            8884099, 8, 2, /* 2287: pointer_to_array_of_pointers_to_stack */
            	2294, 0,
            	122, 20,
            0, 8, 1, /* 2294: pointer.ASN1_TYPE */
            	2299, 0,
            0, 0, 1, /* 2299: ASN1_TYPE */
            	2304, 0,
            0, 16, 1, /* 2304: struct.asn1_type_st */
            	2309, 8,
            0, 8, 20, /* 2309: union.unknown */
            	26, 0,
            	2352, 0,
            	2362, 0,
            	2376, 0,
            	2381, 0,
            	2386, 0,
            	2391, 0,
            	2396, 0,
            	2401, 0,
            	2406, 0,
            	2411, 0,
            	2416, 0,
            	2421, 0,
            	2426, 0,
            	2431, 0,
            	2436, 0,
            	2441, 0,
            	2352, 0,
            	2352, 0,
            	2446, 0,
            1, 8, 1, /* 2352: pointer.struct.asn1_string_st */
            	2357, 0,
            0, 24, 1, /* 2357: struct.asn1_string_st */
            	13, 8,
            1, 8, 1, /* 2362: pointer.struct.asn1_object_st */
            	2367, 0,
            0, 40, 3, /* 2367: struct.asn1_object_st */
            	102, 0,
            	102, 8,
            	107, 24,
            1, 8, 1, /* 2376: pointer.struct.asn1_string_st */
            	2357, 0,
            1, 8, 1, /* 2381: pointer.struct.asn1_string_st */
            	2357, 0,
            1, 8, 1, /* 2386: pointer.struct.asn1_string_st */
            	2357, 0,
            1, 8, 1, /* 2391: pointer.struct.asn1_string_st */
            	2357, 0,
            1, 8, 1, /* 2396: pointer.struct.asn1_string_st */
            	2357, 0,
            1, 8, 1, /* 2401: pointer.struct.asn1_string_st */
            	2357, 0,
            1, 8, 1, /* 2406: pointer.struct.asn1_string_st */
            	2357, 0,
            1, 8, 1, /* 2411: pointer.struct.asn1_string_st */
            	2357, 0,
            1, 8, 1, /* 2416: pointer.struct.asn1_string_st */
            	2357, 0,
            1, 8, 1, /* 2421: pointer.struct.asn1_string_st */
            	2357, 0,
            1, 8, 1, /* 2426: pointer.struct.asn1_string_st */
            	2357, 0,
            1, 8, 1, /* 2431: pointer.struct.asn1_string_st */
            	2357, 0,
            1, 8, 1, /* 2436: pointer.struct.asn1_string_st */
            	2357, 0,
            1, 8, 1, /* 2441: pointer.struct.asn1_string_st */
            	2357, 0,
            1, 8, 1, /* 2446: pointer.struct.ASN1_VALUE_st */
            	2451, 0,
            0, 0, 0, /* 2451: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2454: pointer.struct.asn1_type_st */
            	2459, 0,
            0, 16, 1, /* 2459: struct.asn1_type_st */
            	2464, 8,
            0, 8, 20, /* 2464: union.unknown */
            	26, 0,
            	2507, 0,
            	2252, 0,
            	2517, 0,
            	2522, 0,
            	2527, 0,
            	2532, 0,
            	2537, 0,
            	2542, 0,
            	2547, 0,
            	2552, 0,
            	2557, 0,
            	2562, 0,
            	2567, 0,
            	2572, 0,
            	2577, 0,
            	2582, 0,
            	2507, 0,
            	2507, 0,
            	2587, 0,
            1, 8, 1, /* 2507: pointer.struct.asn1_string_st */
            	2512, 0,
            0, 24, 1, /* 2512: struct.asn1_string_st */
            	13, 8,
            1, 8, 1, /* 2517: pointer.struct.asn1_string_st */
            	2512, 0,
            1, 8, 1, /* 2522: pointer.struct.asn1_string_st */
            	2512, 0,
            1, 8, 1, /* 2527: pointer.struct.asn1_string_st */
            	2512, 0,
            1, 8, 1, /* 2532: pointer.struct.asn1_string_st */
            	2512, 0,
            1, 8, 1, /* 2537: pointer.struct.asn1_string_st */
            	2512, 0,
            1, 8, 1, /* 2542: pointer.struct.asn1_string_st */
            	2512, 0,
            1, 8, 1, /* 2547: pointer.struct.asn1_string_st */
            	2512, 0,
            1, 8, 1, /* 2552: pointer.struct.asn1_string_st */
            	2512, 0,
            1, 8, 1, /* 2557: pointer.struct.asn1_string_st */
            	2512, 0,
            1, 8, 1, /* 2562: pointer.struct.asn1_string_st */
            	2512, 0,
            1, 8, 1, /* 2567: pointer.struct.asn1_string_st */
            	2512, 0,
            1, 8, 1, /* 2572: pointer.struct.asn1_string_st */
            	2512, 0,
            1, 8, 1, /* 2577: pointer.struct.asn1_string_st */
            	2512, 0,
            1, 8, 1, /* 2582: pointer.struct.asn1_string_st */
            	2512, 0,
            1, 8, 1, /* 2587: pointer.struct.ASN1_VALUE_st */
            	2592, 0,
            0, 0, 0, /* 2592: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2595: pointer.struct.asn1_string_st */
            	536, 0,
            1, 8, 1, /* 2600: pointer.struct.stack_st_X509_EXTENSION */
            	2605, 0,
            0, 32, 2, /* 2605: struct.stack_st_fake_X509_EXTENSION */
            	2612, 8,
            	125, 24,
            8884099, 8, 2, /* 2612: pointer_to_array_of_pointers_to_stack */
            	2619, 0,
            	122, 20,
            0, 8, 1, /* 2619: pointer.X509_EXTENSION */
            	2624, 0,
            0, 0, 1, /* 2624: X509_EXTENSION */
            	2629, 0,
            0, 24, 2, /* 2629: struct.X509_extension_st */
            	2636, 0,
            	2650, 16,
            1, 8, 1, /* 2636: pointer.struct.asn1_object_st */
            	2641, 0,
            0, 40, 3, /* 2641: struct.asn1_object_st */
            	102, 0,
            	102, 8,
            	107, 24,
            1, 8, 1, /* 2650: pointer.struct.asn1_string_st */
            	2655, 0,
            0, 24, 1, /* 2655: struct.asn1_string_st */
            	13, 8,
            0, 24, 1, /* 2660: struct.ASN1_ENCODING_st */
            	13, 0,
            0, 16, 1, /* 2665: struct.crypto_ex_data_st */
            	2670, 0,
            1, 8, 1, /* 2670: pointer.struct.stack_st_void */
            	2675, 0,
            0, 32, 1, /* 2675: struct.stack_st_void */
            	2680, 0,
            0, 32, 2, /* 2680: struct.stack_st */
            	1262, 8,
            	125, 24,
            1, 8, 1, /* 2687: pointer.struct.asn1_string_st */
            	536, 0,
            1, 8, 1, /* 2692: pointer.struct.AUTHORITY_KEYID_st */
            	2697, 0,
            0, 24, 3, /* 2697: struct.AUTHORITY_KEYID_st */
            	2706, 0,
            	2716, 8,
            	3010, 16,
            1, 8, 1, /* 2706: pointer.struct.asn1_string_st */
            	2711, 0,
            0, 24, 1, /* 2711: struct.asn1_string_st */
            	13, 8,
            1, 8, 1, /* 2716: pointer.struct.stack_st_GENERAL_NAME */
            	2721, 0,
            0, 32, 2, /* 2721: struct.stack_st_fake_GENERAL_NAME */
            	2728, 8,
            	125, 24,
            8884099, 8, 2, /* 2728: pointer_to_array_of_pointers_to_stack */
            	2735, 0,
            	122, 20,
            0, 8, 1, /* 2735: pointer.GENERAL_NAME */
            	2740, 0,
            0, 0, 1, /* 2740: GENERAL_NAME */
            	2745, 0,
            0, 16, 1, /* 2745: struct.GENERAL_NAME_st */
            	2750, 8,
            0, 8, 15, /* 2750: union.unknown */
            	26, 0,
            	2783, 0,
            	2902, 0,
            	2902, 0,
            	2809, 0,
            	2950, 0,
            	2998, 0,
            	2902, 0,
            	2887, 0,
            	2795, 0,
            	2887, 0,
            	2950, 0,
            	2902, 0,
            	2795, 0,
            	2809, 0,
            1, 8, 1, /* 2783: pointer.struct.otherName_st */
            	2788, 0,
            0, 16, 2, /* 2788: struct.otherName_st */
            	2795, 0,
            	2809, 8,
            1, 8, 1, /* 2795: pointer.struct.asn1_object_st */
            	2800, 0,
            0, 40, 3, /* 2800: struct.asn1_object_st */
            	102, 0,
            	102, 8,
            	107, 24,
            1, 8, 1, /* 2809: pointer.struct.asn1_type_st */
            	2814, 0,
            0, 16, 1, /* 2814: struct.asn1_type_st */
            	2819, 8,
            0, 8, 20, /* 2819: union.unknown */
            	26, 0,
            	2862, 0,
            	2795, 0,
            	2872, 0,
            	2877, 0,
            	2882, 0,
            	2887, 0,
            	2892, 0,
            	2897, 0,
            	2902, 0,
            	2907, 0,
            	2912, 0,
            	2917, 0,
            	2922, 0,
            	2927, 0,
            	2932, 0,
            	2937, 0,
            	2862, 0,
            	2862, 0,
            	2942, 0,
            1, 8, 1, /* 2862: pointer.struct.asn1_string_st */
            	2867, 0,
            0, 24, 1, /* 2867: struct.asn1_string_st */
            	13, 8,
            1, 8, 1, /* 2872: pointer.struct.asn1_string_st */
            	2867, 0,
            1, 8, 1, /* 2877: pointer.struct.asn1_string_st */
            	2867, 0,
            1, 8, 1, /* 2882: pointer.struct.asn1_string_st */
            	2867, 0,
            1, 8, 1, /* 2887: pointer.struct.asn1_string_st */
            	2867, 0,
            1, 8, 1, /* 2892: pointer.struct.asn1_string_st */
            	2867, 0,
            1, 8, 1, /* 2897: pointer.struct.asn1_string_st */
            	2867, 0,
            1, 8, 1, /* 2902: pointer.struct.asn1_string_st */
            	2867, 0,
            1, 8, 1, /* 2907: pointer.struct.asn1_string_st */
            	2867, 0,
            1, 8, 1, /* 2912: pointer.struct.asn1_string_st */
            	2867, 0,
            1, 8, 1, /* 2917: pointer.struct.asn1_string_st */
            	2867, 0,
            1, 8, 1, /* 2922: pointer.struct.asn1_string_st */
            	2867, 0,
            1, 8, 1, /* 2927: pointer.struct.asn1_string_st */
            	2867, 0,
            1, 8, 1, /* 2932: pointer.struct.asn1_string_st */
            	2867, 0,
            1, 8, 1, /* 2937: pointer.struct.asn1_string_st */
            	2867, 0,
            1, 8, 1, /* 2942: pointer.struct.ASN1_VALUE_st */
            	2947, 0,
            0, 0, 0, /* 2947: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2950: pointer.struct.X509_name_st */
            	2955, 0,
            0, 40, 3, /* 2955: struct.X509_name_st */
            	2964, 0,
            	2988, 16,
            	13, 24,
            1, 8, 1, /* 2964: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2969, 0,
            0, 32, 2, /* 2969: struct.stack_st_fake_X509_NAME_ENTRY */
            	2976, 8,
            	125, 24,
            8884099, 8, 2, /* 2976: pointer_to_array_of_pointers_to_stack */
            	2983, 0,
            	122, 20,
            0, 8, 1, /* 2983: pointer.X509_NAME_ENTRY */
            	76, 0,
            1, 8, 1, /* 2988: pointer.struct.buf_mem_st */
            	2993, 0,
            0, 24, 1, /* 2993: struct.buf_mem_st */
            	26, 8,
            1, 8, 1, /* 2998: pointer.struct.EDIPartyName_st */
            	3003, 0,
            0, 16, 2, /* 3003: struct.EDIPartyName_st */
            	2862, 0,
            	2862, 8,
            1, 8, 1, /* 3010: pointer.struct.asn1_string_st */
            	2711, 0,
            1, 8, 1, /* 3015: pointer.struct.X509_POLICY_CACHE_st */
            	3020, 0,
            0, 40, 2, /* 3020: struct.X509_POLICY_CACHE_st */
            	3027, 0,
            	3337, 8,
            1, 8, 1, /* 3027: pointer.struct.X509_POLICY_DATA_st */
            	3032, 0,
            0, 32, 3, /* 3032: struct.X509_POLICY_DATA_st */
            	3041, 8,
            	3055, 16,
            	3313, 24,
            1, 8, 1, /* 3041: pointer.struct.asn1_object_st */
            	3046, 0,
            0, 40, 3, /* 3046: struct.asn1_object_st */
            	102, 0,
            	102, 8,
            	107, 24,
            1, 8, 1, /* 3055: pointer.struct.stack_st_POLICYQUALINFO */
            	3060, 0,
            0, 32, 2, /* 3060: struct.stack_st_fake_POLICYQUALINFO */
            	3067, 8,
            	125, 24,
            8884099, 8, 2, /* 3067: pointer_to_array_of_pointers_to_stack */
            	3074, 0,
            	122, 20,
            0, 8, 1, /* 3074: pointer.POLICYQUALINFO */
            	3079, 0,
            0, 0, 1, /* 3079: POLICYQUALINFO */
            	3084, 0,
            0, 16, 2, /* 3084: struct.POLICYQUALINFO_st */
            	3091, 0,
            	3105, 8,
            1, 8, 1, /* 3091: pointer.struct.asn1_object_st */
            	3096, 0,
            0, 40, 3, /* 3096: struct.asn1_object_st */
            	102, 0,
            	102, 8,
            	107, 24,
            0, 8, 3, /* 3105: union.unknown */
            	3114, 0,
            	3124, 0,
            	3187, 0,
            1, 8, 1, /* 3114: pointer.struct.asn1_string_st */
            	3119, 0,
            0, 24, 1, /* 3119: struct.asn1_string_st */
            	13, 8,
            1, 8, 1, /* 3124: pointer.struct.USERNOTICE_st */
            	3129, 0,
            0, 16, 2, /* 3129: struct.USERNOTICE_st */
            	3136, 0,
            	3148, 8,
            1, 8, 1, /* 3136: pointer.struct.NOTICEREF_st */
            	3141, 0,
            0, 16, 2, /* 3141: struct.NOTICEREF_st */
            	3148, 0,
            	3153, 8,
            1, 8, 1, /* 3148: pointer.struct.asn1_string_st */
            	3119, 0,
            1, 8, 1, /* 3153: pointer.struct.stack_st_ASN1_INTEGER */
            	3158, 0,
            0, 32, 2, /* 3158: struct.stack_st_fake_ASN1_INTEGER */
            	3165, 8,
            	125, 24,
            8884099, 8, 2, /* 3165: pointer_to_array_of_pointers_to_stack */
            	3172, 0,
            	122, 20,
            0, 8, 1, /* 3172: pointer.ASN1_INTEGER */
            	3177, 0,
            0, 0, 1, /* 3177: ASN1_INTEGER */
            	3182, 0,
            0, 24, 1, /* 3182: struct.asn1_string_st */
            	13, 8,
            1, 8, 1, /* 3187: pointer.struct.asn1_type_st */
            	3192, 0,
            0, 16, 1, /* 3192: struct.asn1_type_st */
            	3197, 8,
            0, 8, 20, /* 3197: union.unknown */
            	26, 0,
            	3148, 0,
            	3091, 0,
            	3240, 0,
            	3245, 0,
            	3250, 0,
            	3255, 0,
            	3260, 0,
            	3265, 0,
            	3114, 0,
            	3270, 0,
            	3275, 0,
            	3280, 0,
            	3285, 0,
            	3290, 0,
            	3295, 0,
            	3300, 0,
            	3148, 0,
            	3148, 0,
            	3305, 0,
            1, 8, 1, /* 3240: pointer.struct.asn1_string_st */
            	3119, 0,
            1, 8, 1, /* 3245: pointer.struct.asn1_string_st */
            	3119, 0,
            1, 8, 1, /* 3250: pointer.struct.asn1_string_st */
            	3119, 0,
            1, 8, 1, /* 3255: pointer.struct.asn1_string_st */
            	3119, 0,
            1, 8, 1, /* 3260: pointer.struct.asn1_string_st */
            	3119, 0,
            1, 8, 1, /* 3265: pointer.struct.asn1_string_st */
            	3119, 0,
            1, 8, 1, /* 3270: pointer.struct.asn1_string_st */
            	3119, 0,
            1, 8, 1, /* 3275: pointer.struct.asn1_string_st */
            	3119, 0,
            1, 8, 1, /* 3280: pointer.struct.asn1_string_st */
            	3119, 0,
            1, 8, 1, /* 3285: pointer.struct.asn1_string_st */
            	3119, 0,
            1, 8, 1, /* 3290: pointer.struct.asn1_string_st */
            	3119, 0,
            1, 8, 1, /* 3295: pointer.struct.asn1_string_st */
            	3119, 0,
            1, 8, 1, /* 3300: pointer.struct.asn1_string_st */
            	3119, 0,
            1, 8, 1, /* 3305: pointer.struct.ASN1_VALUE_st */
            	3310, 0,
            0, 0, 0, /* 3310: struct.ASN1_VALUE_st */
            1, 8, 1, /* 3313: pointer.struct.stack_st_ASN1_OBJECT */
            	3318, 0,
            0, 32, 2, /* 3318: struct.stack_st_fake_ASN1_OBJECT */
            	3325, 8,
            	125, 24,
            8884099, 8, 2, /* 3325: pointer_to_array_of_pointers_to_stack */
            	3332, 0,
            	122, 20,
            0, 8, 1, /* 3332: pointer.ASN1_OBJECT */
            	410, 0,
            1, 8, 1, /* 3337: pointer.struct.stack_st_X509_POLICY_DATA */
            	3342, 0,
            0, 32, 2, /* 3342: struct.stack_st_fake_X509_POLICY_DATA */
            	3349, 8,
            	125, 24,
            8884099, 8, 2, /* 3349: pointer_to_array_of_pointers_to_stack */
            	3356, 0,
            	122, 20,
            0, 8, 1, /* 3356: pointer.X509_POLICY_DATA */
            	3361, 0,
            0, 0, 1, /* 3361: X509_POLICY_DATA */
            	3366, 0,
            0, 32, 3, /* 3366: struct.X509_POLICY_DATA_st */
            	3375, 8,
            	3389, 16,
            	3413, 24,
            1, 8, 1, /* 3375: pointer.struct.asn1_object_st */
            	3380, 0,
            0, 40, 3, /* 3380: struct.asn1_object_st */
            	102, 0,
            	102, 8,
            	107, 24,
            1, 8, 1, /* 3389: pointer.struct.stack_st_POLICYQUALINFO */
            	3394, 0,
            0, 32, 2, /* 3394: struct.stack_st_fake_POLICYQUALINFO */
            	3401, 8,
            	125, 24,
            8884099, 8, 2, /* 3401: pointer_to_array_of_pointers_to_stack */
            	3408, 0,
            	122, 20,
            0, 8, 1, /* 3408: pointer.POLICYQUALINFO */
            	3079, 0,
            1, 8, 1, /* 3413: pointer.struct.stack_st_ASN1_OBJECT */
            	3418, 0,
            0, 32, 2, /* 3418: struct.stack_st_fake_ASN1_OBJECT */
            	3425, 8,
            	125, 24,
            8884099, 8, 2, /* 3425: pointer_to_array_of_pointers_to_stack */
            	3432, 0,
            	122, 20,
            0, 8, 1, /* 3432: pointer.ASN1_OBJECT */
            	410, 0,
            1, 8, 1, /* 3437: pointer.struct.stack_st_DIST_POINT */
            	3442, 0,
            0, 32, 2, /* 3442: struct.stack_st_fake_DIST_POINT */
            	3449, 8,
            	125, 24,
            8884099, 8, 2, /* 3449: pointer_to_array_of_pointers_to_stack */
            	3456, 0,
            	122, 20,
            0, 8, 1, /* 3456: pointer.DIST_POINT */
            	3461, 0,
            0, 0, 1, /* 3461: DIST_POINT */
            	3466, 0,
            0, 32, 3, /* 3466: struct.DIST_POINT_st */
            	3475, 0,
            	3566, 8,
            	3494, 16,
            1, 8, 1, /* 3475: pointer.struct.DIST_POINT_NAME_st */
            	3480, 0,
            0, 24, 2, /* 3480: struct.DIST_POINT_NAME_st */
            	3487, 8,
            	3542, 16,
            0, 8, 2, /* 3487: union.unknown */
            	3494, 0,
            	3518, 0,
            1, 8, 1, /* 3494: pointer.struct.stack_st_GENERAL_NAME */
            	3499, 0,
            0, 32, 2, /* 3499: struct.stack_st_fake_GENERAL_NAME */
            	3506, 8,
            	125, 24,
            8884099, 8, 2, /* 3506: pointer_to_array_of_pointers_to_stack */
            	3513, 0,
            	122, 20,
            0, 8, 1, /* 3513: pointer.GENERAL_NAME */
            	2740, 0,
            1, 8, 1, /* 3518: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3523, 0,
            0, 32, 2, /* 3523: struct.stack_st_fake_X509_NAME_ENTRY */
            	3530, 8,
            	125, 24,
            8884099, 8, 2, /* 3530: pointer_to_array_of_pointers_to_stack */
            	3537, 0,
            	122, 20,
            0, 8, 1, /* 3537: pointer.X509_NAME_ENTRY */
            	76, 0,
            1, 8, 1, /* 3542: pointer.struct.X509_name_st */
            	3547, 0,
            0, 40, 3, /* 3547: struct.X509_name_st */
            	3518, 0,
            	3556, 16,
            	13, 24,
            1, 8, 1, /* 3556: pointer.struct.buf_mem_st */
            	3561, 0,
            0, 24, 1, /* 3561: struct.buf_mem_st */
            	26, 8,
            1, 8, 1, /* 3566: pointer.struct.asn1_string_st */
            	3571, 0,
            0, 24, 1, /* 3571: struct.asn1_string_st */
            	13, 8,
            1, 8, 1, /* 3576: pointer.struct.stack_st_GENERAL_NAME */
            	3581, 0,
            0, 32, 2, /* 3581: struct.stack_st_fake_GENERAL_NAME */
            	3588, 8,
            	125, 24,
            8884099, 8, 2, /* 3588: pointer_to_array_of_pointers_to_stack */
            	3595, 0,
            	122, 20,
            0, 8, 1, /* 3595: pointer.GENERAL_NAME */
            	2740, 0,
            1, 8, 1, /* 3600: pointer.struct.NAME_CONSTRAINTS_st */
            	3605, 0,
            0, 16, 2, /* 3605: struct.NAME_CONSTRAINTS_st */
            	3612, 0,
            	3612, 8,
            1, 8, 1, /* 3612: pointer.struct.stack_st_GENERAL_SUBTREE */
            	3617, 0,
            0, 32, 2, /* 3617: struct.stack_st_fake_GENERAL_SUBTREE */
            	3624, 8,
            	125, 24,
            8884099, 8, 2, /* 3624: pointer_to_array_of_pointers_to_stack */
            	3631, 0,
            	122, 20,
            0, 8, 1, /* 3631: pointer.GENERAL_SUBTREE */
            	3636, 0,
            0, 0, 1, /* 3636: GENERAL_SUBTREE */
            	3641, 0,
            0, 24, 3, /* 3641: struct.GENERAL_SUBTREE_st */
            	3650, 0,
            	3782, 8,
            	3782, 16,
            1, 8, 1, /* 3650: pointer.struct.GENERAL_NAME_st */
            	3655, 0,
            0, 16, 1, /* 3655: struct.GENERAL_NAME_st */
            	3660, 8,
            0, 8, 15, /* 3660: union.unknown */
            	26, 0,
            	3693, 0,
            	3812, 0,
            	3812, 0,
            	3719, 0,
            	3852, 0,
            	3900, 0,
            	3812, 0,
            	3797, 0,
            	3705, 0,
            	3797, 0,
            	3852, 0,
            	3812, 0,
            	3705, 0,
            	3719, 0,
            1, 8, 1, /* 3693: pointer.struct.otherName_st */
            	3698, 0,
            0, 16, 2, /* 3698: struct.otherName_st */
            	3705, 0,
            	3719, 8,
            1, 8, 1, /* 3705: pointer.struct.asn1_object_st */
            	3710, 0,
            0, 40, 3, /* 3710: struct.asn1_object_st */
            	102, 0,
            	102, 8,
            	107, 24,
            1, 8, 1, /* 3719: pointer.struct.asn1_type_st */
            	3724, 0,
            0, 16, 1, /* 3724: struct.asn1_type_st */
            	3729, 8,
            0, 8, 20, /* 3729: union.unknown */
            	26, 0,
            	3772, 0,
            	3705, 0,
            	3782, 0,
            	3787, 0,
            	3792, 0,
            	3797, 0,
            	3802, 0,
            	3807, 0,
            	3812, 0,
            	3817, 0,
            	3822, 0,
            	3827, 0,
            	3832, 0,
            	3837, 0,
            	3842, 0,
            	3847, 0,
            	3772, 0,
            	3772, 0,
            	3305, 0,
            1, 8, 1, /* 3772: pointer.struct.asn1_string_st */
            	3777, 0,
            0, 24, 1, /* 3777: struct.asn1_string_st */
            	13, 8,
            1, 8, 1, /* 3782: pointer.struct.asn1_string_st */
            	3777, 0,
            1, 8, 1, /* 3787: pointer.struct.asn1_string_st */
            	3777, 0,
            1, 8, 1, /* 3792: pointer.struct.asn1_string_st */
            	3777, 0,
            1, 8, 1, /* 3797: pointer.struct.asn1_string_st */
            	3777, 0,
            1, 8, 1, /* 3802: pointer.struct.asn1_string_st */
            	3777, 0,
            1, 8, 1, /* 3807: pointer.struct.asn1_string_st */
            	3777, 0,
            1, 8, 1, /* 3812: pointer.struct.asn1_string_st */
            	3777, 0,
            1, 8, 1, /* 3817: pointer.struct.asn1_string_st */
            	3777, 0,
            1, 8, 1, /* 3822: pointer.struct.asn1_string_st */
            	3777, 0,
            1, 8, 1, /* 3827: pointer.struct.asn1_string_st */
            	3777, 0,
            1, 8, 1, /* 3832: pointer.struct.asn1_string_st */
            	3777, 0,
            1, 8, 1, /* 3837: pointer.struct.asn1_string_st */
            	3777, 0,
            1, 8, 1, /* 3842: pointer.struct.asn1_string_st */
            	3777, 0,
            1, 8, 1, /* 3847: pointer.struct.asn1_string_st */
            	3777, 0,
            1, 8, 1, /* 3852: pointer.struct.X509_name_st */
            	3857, 0,
            0, 40, 3, /* 3857: struct.X509_name_st */
            	3866, 0,
            	3890, 16,
            	13, 24,
            1, 8, 1, /* 3866: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3871, 0,
            0, 32, 2, /* 3871: struct.stack_st_fake_X509_NAME_ENTRY */
            	3878, 8,
            	125, 24,
            8884099, 8, 2, /* 3878: pointer_to_array_of_pointers_to_stack */
            	3885, 0,
            	122, 20,
            0, 8, 1, /* 3885: pointer.X509_NAME_ENTRY */
            	76, 0,
            1, 8, 1, /* 3890: pointer.struct.buf_mem_st */
            	3895, 0,
            0, 24, 1, /* 3895: struct.buf_mem_st */
            	26, 8,
            1, 8, 1, /* 3900: pointer.struct.EDIPartyName_st */
            	3905, 0,
            0, 16, 2, /* 3905: struct.EDIPartyName_st */
            	3772, 0,
            	3772, 8,
            1, 8, 1, /* 3912: pointer.struct.x509_cert_aux_st */
            	3917, 0,
            0, 40, 5, /* 3917: struct.x509_cert_aux_st */
            	386, 0,
            	386, 8,
            	3930, 16,
            	2687, 24,
            	3935, 32,
            1, 8, 1, /* 3930: pointer.struct.asn1_string_st */
            	536, 0,
            1, 8, 1, /* 3935: pointer.struct.stack_st_X509_ALGOR */
            	3940, 0,
            0, 32, 2, /* 3940: struct.stack_st_fake_X509_ALGOR */
            	3947, 8,
            	125, 24,
            8884099, 8, 2, /* 3947: pointer_to_array_of_pointers_to_stack */
            	3954, 0,
            	122, 20,
            0, 8, 1, /* 3954: pointer.X509_ALGOR */
            	3959, 0,
            0, 0, 1, /* 3959: X509_ALGOR */
            	546, 0,
            1, 8, 1, /* 3964: pointer.struct.X509_crl_st */
            	3969, 0,
            0, 120, 10, /* 3969: struct.X509_crl_st */
            	3992, 0,
            	541, 8,
            	2595, 16,
            	2692, 32,
            	4119, 40,
            	531, 56,
            	531, 64,
            	4131, 96,
            	4172, 104,
            	5, 112,
            1, 8, 1, /* 3992: pointer.struct.X509_crl_info_st */
            	3997, 0,
            0, 80, 8, /* 3997: struct.X509_crl_info_st */
            	531, 0,
            	541, 8,
            	708, 16,
            	768, 24,
            	768, 32,
            	4016, 40,
            	2600, 48,
            	2660, 56,
            1, 8, 1, /* 4016: pointer.struct.stack_st_X509_REVOKED */
            	4021, 0,
            0, 32, 2, /* 4021: struct.stack_st_fake_X509_REVOKED */
            	4028, 8,
            	125, 24,
            8884099, 8, 2, /* 4028: pointer_to_array_of_pointers_to_stack */
            	4035, 0,
            	122, 20,
            0, 8, 1, /* 4035: pointer.X509_REVOKED */
            	4040, 0,
            0, 0, 1, /* 4040: X509_REVOKED */
            	4045, 0,
            0, 40, 4, /* 4045: struct.x509_revoked_st */
            	4056, 0,
            	4066, 8,
            	4071, 16,
            	4095, 24,
            1, 8, 1, /* 4056: pointer.struct.asn1_string_st */
            	4061, 0,
            0, 24, 1, /* 4061: struct.asn1_string_st */
            	13, 8,
            1, 8, 1, /* 4066: pointer.struct.asn1_string_st */
            	4061, 0,
            1, 8, 1, /* 4071: pointer.struct.stack_st_X509_EXTENSION */
            	4076, 0,
            0, 32, 2, /* 4076: struct.stack_st_fake_X509_EXTENSION */
            	4083, 8,
            	125, 24,
            8884099, 8, 2, /* 4083: pointer_to_array_of_pointers_to_stack */
            	4090, 0,
            	122, 20,
            0, 8, 1, /* 4090: pointer.X509_EXTENSION */
            	2624, 0,
            1, 8, 1, /* 4095: pointer.struct.stack_st_GENERAL_NAME */
            	4100, 0,
            0, 32, 2, /* 4100: struct.stack_st_fake_GENERAL_NAME */
            	4107, 8,
            	125, 24,
            8884099, 8, 2, /* 4107: pointer_to_array_of_pointers_to_stack */
            	4114, 0,
            	122, 20,
            0, 8, 1, /* 4114: pointer.GENERAL_NAME */
            	2740, 0,
            1, 8, 1, /* 4119: pointer.struct.ISSUING_DIST_POINT_st */
            	4124, 0,
            0, 32, 2, /* 4124: struct.ISSUING_DIST_POINT_st */
            	3475, 0,
            	3566, 16,
            1, 8, 1, /* 4131: pointer.struct.stack_st_GENERAL_NAMES */
            	4136, 0,
            0, 32, 2, /* 4136: struct.stack_st_fake_GENERAL_NAMES */
            	4143, 8,
            	125, 24,
            8884099, 8, 2, /* 4143: pointer_to_array_of_pointers_to_stack */
            	4150, 0,
            	122, 20,
            0, 8, 1, /* 4150: pointer.GENERAL_NAMES */
            	4155, 0,
            0, 0, 1, /* 4155: GENERAL_NAMES */
            	4160, 0,
            0, 32, 1, /* 4160: struct.stack_st_GENERAL_NAME */
            	4165, 0,
            0, 32, 2, /* 4165: struct.stack_st */
            	1262, 8,
            	125, 24,
            1, 8, 1, /* 4172: pointer.struct.x509_crl_method_st */
            	4177, 0,
            0, 40, 4, /* 4177: struct.x509_crl_method_st */
            	4188, 8,
            	4188, 16,
            	4191, 24,
            	4194, 32,
            8884097, 8, 0, /* 4188: pointer.func */
            8884097, 8, 0, /* 4191: pointer.func */
            8884097, 8, 0, /* 4194: pointer.func */
            1, 8, 1, /* 4197: pointer.struct.evp_pkey_st */
            	4202, 0,
            0, 56, 4, /* 4202: struct.evp_pkey_st */
            	4213, 16,
            	1382, 24,
            	4218, 32,
            	4251, 48,
            1, 8, 1, /* 4213: pointer.struct.evp_pkey_asn1_method_st */
            	823, 0,
            0, 8, 5, /* 4218: union.unknown */
            	26, 0,
            	4231, 0,
            	4236, 0,
            	4241, 0,
            	4246, 0,
            1, 8, 1, /* 4231: pointer.struct.rsa_st */
            	1290, 0,
            1, 8, 1, /* 4236: pointer.struct.dsa_st */
            	1492, 0,
            1, 8, 1, /* 4241: pointer.struct.dh_st */
            	1619, 0,
            1, 8, 1, /* 4246: pointer.struct.ec_key_st */
            	1733, 0,
            1, 8, 1, /* 4251: pointer.struct.stack_st_X509_ATTRIBUTE */
            	4256, 0,
            0, 32, 2, /* 4256: struct.stack_st_fake_X509_ATTRIBUTE */
            	4263, 8,
            	125, 24,
            8884099, 8, 2, /* 4263: pointer_to_array_of_pointers_to_stack */
            	4270, 0,
            	122, 20,
            0, 8, 1, /* 4270: pointer.X509_ATTRIBUTE */
            	2240, 0,
            8884097, 8, 0, /* 4275: pointer.func */
            8884097, 8, 0, /* 4278: pointer.func */
            8884097, 8, 0, /* 4281: pointer.func */
            0, 0, 1, /* 4284: X509_LOOKUP */
            	4289, 0,
            0, 32, 3, /* 4289: struct.x509_lookup_st */
            	4298, 8,
            	26, 16,
            	4341, 24,
            1, 8, 1, /* 4298: pointer.struct.x509_lookup_method_st */
            	4303, 0,
            0, 80, 10, /* 4303: struct.x509_lookup_method_st */
            	102, 0,
            	4326, 8,
            	4281, 16,
            	4326, 24,
            	4326, 32,
            	4329, 40,
            	4332, 48,
            	4275, 56,
            	4335, 64,
            	4338, 72,
            8884097, 8, 0, /* 4326: pointer.func */
            8884097, 8, 0, /* 4329: pointer.func */
            8884097, 8, 0, /* 4332: pointer.func */
            8884097, 8, 0, /* 4335: pointer.func */
            8884097, 8, 0, /* 4338: pointer.func */
            1, 8, 1, /* 4341: pointer.struct.x509_store_st */
            	4346, 0,
            0, 144, 15, /* 4346: struct.x509_store_st */
            	424, 8,
            	4379, 16,
            	374, 24,
            	371, 32,
            	4403, 40,
            	4406, 48,
            	368, 56,
            	371, 64,
            	4409, 72,
            	365, 80,
            	4412, 88,
            	362, 96,
            	359, 104,
            	371, 112,
            	2665, 120,
            1, 8, 1, /* 4379: pointer.struct.stack_st_X509_LOOKUP */
            	4384, 0,
            0, 32, 2, /* 4384: struct.stack_st_fake_X509_LOOKUP */
            	4391, 8,
            	125, 24,
            8884099, 8, 2, /* 4391: pointer_to_array_of_pointers_to_stack */
            	4398, 0,
            	122, 20,
            0, 8, 1, /* 4398: pointer.X509_LOOKUP */
            	4284, 0,
            8884097, 8, 0, /* 4403: pointer.func */
            8884097, 8, 0, /* 4406: pointer.func */
            8884097, 8, 0, /* 4409: pointer.func */
            8884097, 8, 0, /* 4412: pointer.func */
            1, 8, 1, /* 4415: pointer.struct.stack_st_X509_LOOKUP */
            	4420, 0,
            0, 32, 2, /* 4420: struct.stack_st_fake_X509_LOOKUP */
            	4427, 8,
            	125, 24,
            8884099, 8, 2, /* 4427: pointer_to_array_of_pointers_to_stack */
            	4434, 0,
            	122, 20,
            0, 8, 1, /* 4434: pointer.X509_LOOKUP */
            	4284, 0,
            8884097, 8, 0, /* 4439: pointer.func */
            8884097, 8, 0, /* 4442: pointer.func */
            0, 16, 1, /* 4445: struct.srtp_protection_profile_st */
            	102, 0,
            1, 8, 1, /* 4450: pointer.struct.stack_st_X509 */
            	4455, 0,
            0, 32, 2, /* 4455: struct.stack_st_fake_X509 */
            	4462, 8,
            	125, 24,
            8884099, 8, 2, /* 4462: pointer_to_array_of_pointers_to_stack */
            	4469, 0,
            	122, 20,
            0, 8, 1, /* 4469: pointer.X509 */
            	4474, 0,
            0, 0, 1, /* 4474: X509 */
            	4479, 0,
            0, 184, 12, /* 4479: struct.x509_st */
            	4506, 0,
            	4546, 8,
            	4621, 16,
            	26, 32,
            	1541, 40,
            	4655, 104,
            	4660, 112,
            	4665, 120,
            	4670, 128,
            	4095, 136,
            	4694, 144,
            	4699, 176,
            1, 8, 1, /* 4506: pointer.struct.x509_cinf_st */
            	4511, 0,
            0, 104, 11, /* 4511: struct.x509_cinf_st */
            	4536, 0,
            	4536, 8,
            	4546, 16,
            	4551, 24,
            	4599, 32,
            	4551, 40,
            	4616, 48,
            	4621, 56,
            	4621, 64,
            	4626, 72,
            	4650, 80,
            1, 8, 1, /* 4536: pointer.struct.asn1_string_st */
            	4541, 0,
            0, 24, 1, /* 4541: struct.asn1_string_st */
            	13, 8,
            1, 8, 1, /* 4546: pointer.struct.X509_algor_st */
            	546, 0,
            1, 8, 1, /* 4551: pointer.struct.X509_name_st */
            	4556, 0,
            0, 40, 3, /* 4556: struct.X509_name_st */
            	4565, 0,
            	4589, 16,
            	13, 24,
            1, 8, 1, /* 4565: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4570, 0,
            0, 32, 2, /* 4570: struct.stack_st_fake_X509_NAME_ENTRY */
            	4577, 8,
            	125, 24,
            8884099, 8, 2, /* 4577: pointer_to_array_of_pointers_to_stack */
            	4584, 0,
            	122, 20,
            0, 8, 1, /* 4584: pointer.X509_NAME_ENTRY */
            	76, 0,
            1, 8, 1, /* 4589: pointer.struct.buf_mem_st */
            	4594, 0,
            0, 24, 1, /* 4594: struct.buf_mem_st */
            	26, 8,
            1, 8, 1, /* 4599: pointer.struct.X509_val_st */
            	4604, 0,
            0, 16, 2, /* 4604: struct.X509_val_st */
            	4611, 0,
            	4611, 8,
            1, 8, 1, /* 4611: pointer.struct.asn1_string_st */
            	4541, 0,
            1, 8, 1, /* 4616: pointer.struct.X509_pubkey_st */
            	778, 0,
            1, 8, 1, /* 4621: pointer.struct.asn1_string_st */
            	4541, 0,
            1, 8, 1, /* 4626: pointer.struct.stack_st_X509_EXTENSION */
            	4631, 0,
            0, 32, 2, /* 4631: struct.stack_st_fake_X509_EXTENSION */
            	4638, 8,
            	125, 24,
            8884099, 8, 2, /* 4638: pointer_to_array_of_pointers_to_stack */
            	4645, 0,
            	122, 20,
            0, 8, 1, /* 4645: pointer.X509_EXTENSION */
            	2624, 0,
            0, 24, 1, /* 4650: struct.ASN1_ENCODING_st */
            	13, 0,
            1, 8, 1, /* 4655: pointer.struct.asn1_string_st */
            	4541, 0,
            1, 8, 1, /* 4660: pointer.struct.AUTHORITY_KEYID_st */
            	2697, 0,
            1, 8, 1, /* 4665: pointer.struct.X509_POLICY_CACHE_st */
            	3020, 0,
            1, 8, 1, /* 4670: pointer.struct.stack_st_DIST_POINT */
            	4675, 0,
            0, 32, 2, /* 4675: struct.stack_st_fake_DIST_POINT */
            	4682, 8,
            	125, 24,
            8884099, 8, 2, /* 4682: pointer_to_array_of_pointers_to_stack */
            	4689, 0,
            	122, 20,
            0, 8, 1, /* 4689: pointer.DIST_POINT */
            	3461, 0,
            1, 8, 1, /* 4694: pointer.struct.NAME_CONSTRAINTS_st */
            	3605, 0,
            1, 8, 1, /* 4699: pointer.struct.x509_cert_aux_st */
            	4704, 0,
            0, 40, 5, /* 4704: struct.x509_cert_aux_st */
            	4717, 0,
            	4717, 8,
            	4741, 16,
            	4655, 24,
            	4746, 32,
            1, 8, 1, /* 4717: pointer.struct.stack_st_ASN1_OBJECT */
            	4722, 0,
            0, 32, 2, /* 4722: struct.stack_st_fake_ASN1_OBJECT */
            	4729, 8,
            	125, 24,
            8884099, 8, 2, /* 4729: pointer_to_array_of_pointers_to_stack */
            	4736, 0,
            	122, 20,
            0, 8, 1, /* 4736: pointer.ASN1_OBJECT */
            	410, 0,
            1, 8, 1, /* 4741: pointer.struct.asn1_string_st */
            	4541, 0,
            1, 8, 1, /* 4746: pointer.struct.stack_st_X509_ALGOR */
            	4751, 0,
            0, 32, 2, /* 4751: struct.stack_st_fake_X509_ALGOR */
            	4758, 8,
            	125, 24,
            8884099, 8, 2, /* 4758: pointer_to_array_of_pointers_to_stack */
            	4765, 0,
            	122, 20,
            0, 8, 1, /* 4765: pointer.X509_ALGOR */
            	3959, 0,
            8884097, 8, 0, /* 4770: pointer.func */
            1, 8, 1, /* 4773: pointer.struct.x509_store_st */
            	4778, 0,
            0, 144, 15, /* 4778: struct.x509_store_st */
            	4811, 8,
            	4415, 16,
            	4835, 24,
            	356, 32,
            	4871, 40,
            	4874, 48,
            	4278, 56,
            	356, 64,
            	4877, 72,
            	4770, 80,
            	4880, 88,
            	353, 96,
            	350, 104,
            	356, 112,
            	4883, 120,
            1, 8, 1, /* 4811: pointer.struct.stack_st_X509_OBJECT */
            	4816, 0,
            0, 32, 2, /* 4816: struct.stack_st_fake_X509_OBJECT */
            	4823, 8,
            	125, 24,
            8884099, 8, 2, /* 4823: pointer_to_array_of_pointers_to_stack */
            	4830, 0,
            	122, 20,
            0, 8, 1, /* 4830: pointer.X509_OBJECT */
            	448, 0,
            1, 8, 1, /* 4835: pointer.struct.X509_VERIFY_PARAM_st */
            	4840, 0,
            0, 56, 2, /* 4840: struct.X509_VERIFY_PARAM_st */
            	26, 0,
            	4847, 48,
            1, 8, 1, /* 4847: pointer.struct.stack_st_ASN1_OBJECT */
            	4852, 0,
            0, 32, 2, /* 4852: struct.stack_st_fake_ASN1_OBJECT */
            	4859, 8,
            	125, 24,
            8884099, 8, 2, /* 4859: pointer_to_array_of_pointers_to_stack */
            	4866, 0,
            	122, 20,
            0, 8, 1, /* 4866: pointer.ASN1_OBJECT */
            	410, 0,
            8884097, 8, 0, /* 4871: pointer.func */
            8884097, 8, 0, /* 4874: pointer.func */
            8884097, 8, 0, /* 4877: pointer.func */
            8884097, 8, 0, /* 4880: pointer.func */
            0, 16, 1, /* 4883: struct.crypto_ex_data_st */
            	4888, 0,
            1, 8, 1, /* 4888: pointer.struct.stack_st_void */
            	4893, 0,
            0, 32, 1, /* 4893: struct.stack_st_void */
            	4898, 0,
            0, 32, 2, /* 4898: struct.stack_st */
            	1262, 8,
            	125, 24,
            0, 736, 50, /* 4905: struct.ssl_ctx_st */
            	5008, 0,
            	5174, 8,
            	5174, 16,
            	4773, 24,
            	326, 32,
            	5208, 48,
            	5208, 56,
            	6028, 80,
            	311, 88,
            	6031, 96,
            	308, 152,
            	5, 160,
            	305, 168,
            	5, 176,
            	6034, 184,
            	302, 192,
            	299, 200,
            	4883, 208,
            	6037, 224,
            	6037, 232,
            	6037, 240,
            	4450, 248,
            	275, 256,
            	6076, 264,
            	6079, 272,
            	6108, 304,
            	6549, 320,
            	5, 328,
            	4871, 376,
            	6552, 384,
            	4835, 392,
            	5663, 408,
            	197, 416,
            	5, 424,
            	4442, 480,
            	4439, 488,
            	5, 496,
            	6555, 504,
            	5, 512,
            	26, 520,
            	6558, 528,
            	6561, 536,
            	192, 552,
            	192, 560,
            	6564, 568,
            	156, 696,
            	5, 704,
            	153, 712,
            	5, 720,
            	246, 728,
            1, 8, 1, /* 5008: pointer.struct.ssl_method_st */
            	5013, 0,
            0, 232, 28, /* 5013: struct.ssl_method_st */
            	5072, 8,
            	5075, 16,
            	5075, 24,
            	5072, 32,
            	5072, 40,
            	5078, 48,
            	5078, 56,
            	5081, 64,
            	5072, 72,
            	5072, 80,
            	5072, 88,
            	5084, 96,
            	5087, 104,
            	5090, 112,
            	5072, 120,
            	5093, 128,
            	5096, 136,
            	5099, 144,
            	5102, 152,
            	5105, 160,
            	1193, 168,
            	5108, 176,
            	5111, 184,
            	226, 192,
            	5114, 200,
            	1193, 208,
            	5168, 216,
            	5171, 224,
            8884097, 8, 0, /* 5072: pointer.func */
            8884097, 8, 0, /* 5075: pointer.func */
            8884097, 8, 0, /* 5078: pointer.func */
            8884097, 8, 0, /* 5081: pointer.func */
            8884097, 8, 0, /* 5084: pointer.func */
            8884097, 8, 0, /* 5087: pointer.func */
            8884097, 8, 0, /* 5090: pointer.func */
            8884097, 8, 0, /* 5093: pointer.func */
            8884097, 8, 0, /* 5096: pointer.func */
            8884097, 8, 0, /* 5099: pointer.func */
            8884097, 8, 0, /* 5102: pointer.func */
            8884097, 8, 0, /* 5105: pointer.func */
            8884097, 8, 0, /* 5108: pointer.func */
            8884097, 8, 0, /* 5111: pointer.func */
            1, 8, 1, /* 5114: pointer.struct.ssl3_enc_method */
            	5119, 0,
            0, 112, 11, /* 5119: struct.ssl3_enc_method */
            	5144, 0,
            	5147, 8,
            	5150, 16,
            	5153, 24,
            	5144, 32,
            	5156, 40,
            	5159, 56,
            	102, 64,
            	102, 80,
            	5162, 96,
            	5165, 104,
            8884097, 8, 0, /* 5144: pointer.func */
            8884097, 8, 0, /* 5147: pointer.func */
            8884097, 8, 0, /* 5150: pointer.func */
            8884097, 8, 0, /* 5153: pointer.func */
            8884097, 8, 0, /* 5156: pointer.func */
            8884097, 8, 0, /* 5159: pointer.func */
            8884097, 8, 0, /* 5162: pointer.func */
            8884097, 8, 0, /* 5165: pointer.func */
            8884097, 8, 0, /* 5168: pointer.func */
            8884097, 8, 0, /* 5171: pointer.func */
            1, 8, 1, /* 5174: pointer.struct.stack_st_SSL_CIPHER */
            	5179, 0,
            0, 32, 2, /* 5179: struct.stack_st_fake_SSL_CIPHER */
            	5186, 8,
            	125, 24,
            8884099, 8, 2, /* 5186: pointer_to_array_of_pointers_to_stack */
            	5193, 0,
            	122, 20,
            0, 8, 1, /* 5193: pointer.SSL_CIPHER */
            	5198, 0,
            0, 0, 1, /* 5198: SSL_CIPHER */
            	5203, 0,
            0, 88, 1, /* 5203: struct.ssl_cipher_st */
            	102, 8,
            1, 8, 1, /* 5208: pointer.struct.ssl_session_st */
            	5213, 0,
            0, 352, 14, /* 5213: struct.ssl_session_st */
            	26, 144,
            	26, 152,
            	5244, 168,
            	5785, 176,
            	6018, 224,
            	5174, 240,
            	4883, 248,
            	5208, 264,
            	5208, 272,
            	26, 280,
            	13, 296,
            	13, 312,
            	13, 320,
            	26, 344,
            1, 8, 1, /* 5244: pointer.struct.sess_cert_st */
            	5249, 0,
            0, 248, 5, /* 5249: struct.sess_cert_st */
            	5262, 0,
            	5286, 16,
            	5770, 216,
            	5775, 224,
            	5780, 232,
            1, 8, 1, /* 5262: pointer.struct.stack_st_X509 */
            	5267, 0,
            0, 32, 2, /* 5267: struct.stack_st_fake_X509 */
            	5274, 8,
            	125, 24,
            8884099, 8, 2, /* 5274: pointer_to_array_of_pointers_to_stack */
            	5281, 0,
            	122, 20,
            0, 8, 1, /* 5281: pointer.X509 */
            	4474, 0,
            1, 8, 1, /* 5286: pointer.struct.cert_pkey_st */
            	5291, 0,
            0, 24, 3, /* 5291: struct.cert_pkey_st */
            	5300, 0,
            	5642, 8,
            	5725, 16,
            1, 8, 1, /* 5300: pointer.struct.x509_st */
            	5305, 0,
            0, 184, 12, /* 5305: struct.x509_st */
            	5332, 0,
            	5372, 8,
            	5447, 16,
            	26, 32,
            	5481, 40,
            	5503, 104,
            	5508, 112,
            	5513, 120,
            	5518, 128,
            	5542, 136,
            	5566, 144,
            	5571, 176,
            1, 8, 1, /* 5332: pointer.struct.x509_cinf_st */
            	5337, 0,
            0, 104, 11, /* 5337: struct.x509_cinf_st */
            	5362, 0,
            	5362, 8,
            	5372, 16,
            	5377, 24,
            	5425, 32,
            	5377, 40,
            	5442, 48,
            	5447, 56,
            	5447, 64,
            	5452, 72,
            	5476, 80,
            1, 8, 1, /* 5362: pointer.struct.asn1_string_st */
            	5367, 0,
            0, 24, 1, /* 5367: struct.asn1_string_st */
            	13, 8,
            1, 8, 1, /* 5372: pointer.struct.X509_algor_st */
            	546, 0,
            1, 8, 1, /* 5377: pointer.struct.X509_name_st */
            	5382, 0,
            0, 40, 3, /* 5382: struct.X509_name_st */
            	5391, 0,
            	5415, 16,
            	13, 24,
            1, 8, 1, /* 5391: pointer.struct.stack_st_X509_NAME_ENTRY */
            	5396, 0,
            0, 32, 2, /* 5396: struct.stack_st_fake_X509_NAME_ENTRY */
            	5403, 8,
            	125, 24,
            8884099, 8, 2, /* 5403: pointer_to_array_of_pointers_to_stack */
            	5410, 0,
            	122, 20,
            0, 8, 1, /* 5410: pointer.X509_NAME_ENTRY */
            	76, 0,
            1, 8, 1, /* 5415: pointer.struct.buf_mem_st */
            	5420, 0,
            0, 24, 1, /* 5420: struct.buf_mem_st */
            	26, 8,
            1, 8, 1, /* 5425: pointer.struct.X509_val_st */
            	5430, 0,
            0, 16, 2, /* 5430: struct.X509_val_st */
            	5437, 0,
            	5437, 8,
            1, 8, 1, /* 5437: pointer.struct.asn1_string_st */
            	5367, 0,
            1, 8, 1, /* 5442: pointer.struct.X509_pubkey_st */
            	778, 0,
            1, 8, 1, /* 5447: pointer.struct.asn1_string_st */
            	5367, 0,
            1, 8, 1, /* 5452: pointer.struct.stack_st_X509_EXTENSION */
            	5457, 0,
            0, 32, 2, /* 5457: struct.stack_st_fake_X509_EXTENSION */
            	5464, 8,
            	125, 24,
            8884099, 8, 2, /* 5464: pointer_to_array_of_pointers_to_stack */
            	5471, 0,
            	122, 20,
            0, 8, 1, /* 5471: pointer.X509_EXTENSION */
            	2624, 0,
            0, 24, 1, /* 5476: struct.ASN1_ENCODING_st */
            	13, 0,
            0, 16, 1, /* 5481: struct.crypto_ex_data_st */
            	5486, 0,
            1, 8, 1, /* 5486: pointer.struct.stack_st_void */
            	5491, 0,
            0, 32, 1, /* 5491: struct.stack_st_void */
            	5496, 0,
            0, 32, 2, /* 5496: struct.stack_st */
            	1262, 8,
            	125, 24,
            1, 8, 1, /* 5503: pointer.struct.asn1_string_st */
            	5367, 0,
            1, 8, 1, /* 5508: pointer.struct.AUTHORITY_KEYID_st */
            	2697, 0,
            1, 8, 1, /* 5513: pointer.struct.X509_POLICY_CACHE_st */
            	3020, 0,
            1, 8, 1, /* 5518: pointer.struct.stack_st_DIST_POINT */
            	5523, 0,
            0, 32, 2, /* 5523: struct.stack_st_fake_DIST_POINT */
            	5530, 8,
            	125, 24,
            8884099, 8, 2, /* 5530: pointer_to_array_of_pointers_to_stack */
            	5537, 0,
            	122, 20,
            0, 8, 1, /* 5537: pointer.DIST_POINT */
            	3461, 0,
            1, 8, 1, /* 5542: pointer.struct.stack_st_GENERAL_NAME */
            	5547, 0,
            0, 32, 2, /* 5547: struct.stack_st_fake_GENERAL_NAME */
            	5554, 8,
            	125, 24,
            8884099, 8, 2, /* 5554: pointer_to_array_of_pointers_to_stack */
            	5561, 0,
            	122, 20,
            0, 8, 1, /* 5561: pointer.GENERAL_NAME */
            	2740, 0,
            1, 8, 1, /* 5566: pointer.struct.NAME_CONSTRAINTS_st */
            	3605, 0,
            1, 8, 1, /* 5571: pointer.struct.x509_cert_aux_st */
            	5576, 0,
            0, 40, 5, /* 5576: struct.x509_cert_aux_st */
            	5589, 0,
            	5589, 8,
            	5613, 16,
            	5503, 24,
            	5618, 32,
            1, 8, 1, /* 5589: pointer.struct.stack_st_ASN1_OBJECT */
            	5594, 0,
            0, 32, 2, /* 5594: struct.stack_st_fake_ASN1_OBJECT */
            	5601, 8,
            	125, 24,
            8884099, 8, 2, /* 5601: pointer_to_array_of_pointers_to_stack */
            	5608, 0,
            	122, 20,
            0, 8, 1, /* 5608: pointer.ASN1_OBJECT */
            	410, 0,
            1, 8, 1, /* 5613: pointer.struct.asn1_string_st */
            	5367, 0,
            1, 8, 1, /* 5618: pointer.struct.stack_st_X509_ALGOR */
            	5623, 0,
            0, 32, 2, /* 5623: struct.stack_st_fake_X509_ALGOR */
            	5630, 8,
            	125, 24,
            8884099, 8, 2, /* 5630: pointer_to_array_of_pointers_to_stack */
            	5637, 0,
            	122, 20,
            0, 8, 1, /* 5637: pointer.X509_ALGOR */
            	3959, 0,
            1, 8, 1, /* 5642: pointer.struct.evp_pkey_st */
            	5647, 0,
            0, 56, 4, /* 5647: struct.evp_pkey_st */
            	5658, 16,
            	5663, 24,
            	5668, 32,
            	5701, 48,
            1, 8, 1, /* 5658: pointer.struct.evp_pkey_asn1_method_st */
            	823, 0,
            1, 8, 1, /* 5663: pointer.struct.engine_st */
            	924, 0,
            0, 8, 5, /* 5668: union.unknown */
            	26, 0,
            	5681, 0,
            	5686, 0,
            	5691, 0,
            	5696, 0,
            1, 8, 1, /* 5681: pointer.struct.rsa_st */
            	1290, 0,
            1, 8, 1, /* 5686: pointer.struct.dsa_st */
            	1492, 0,
            1, 8, 1, /* 5691: pointer.struct.dh_st */
            	1619, 0,
            1, 8, 1, /* 5696: pointer.struct.ec_key_st */
            	1733, 0,
            1, 8, 1, /* 5701: pointer.struct.stack_st_X509_ATTRIBUTE */
            	5706, 0,
            0, 32, 2, /* 5706: struct.stack_st_fake_X509_ATTRIBUTE */
            	5713, 8,
            	125, 24,
            8884099, 8, 2, /* 5713: pointer_to_array_of_pointers_to_stack */
            	5720, 0,
            	122, 20,
            0, 8, 1, /* 5720: pointer.X509_ATTRIBUTE */
            	2240, 0,
            1, 8, 1, /* 5725: pointer.struct.env_md_st */
            	5730, 0,
            0, 120, 8, /* 5730: struct.env_md_st */
            	5749, 24,
            	5752, 32,
            	5755, 40,
            	5758, 48,
            	5749, 56,
            	5761, 64,
            	5764, 72,
            	5767, 112,
            8884097, 8, 0, /* 5749: pointer.func */
            8884097, 8, 0, /* 5752: pointer.func */
            8884097, 8, 0, /* 5755: pointer.func */
            8884097, 8, 0, /* 5758: pointer.func */
            8884097, 8, 0, /* 5761: pointer.func */
            8884097, 8, 0, /* 5764: pointer.func */
            8884097, 8, 0, /* 5767: pointer.func */
            1, 8, 1, /* 5770: pointer.struct.rsa_st */
            	1290, 0,
            1, 8, 1, /* 5775: pointer.struct.dh_st */
            	1619, 0,
            1, 8, 1, /* 5780: pointer.struct.ec_key_st */
            	1733, 0,
            1, 8, 1, /* 5785: pointer.struct.x509_st */
            	5790, 0,
            0, 184, 12, /* 5790: struct.x509_st */
            	5817, 0,
            	5857, 8,
            	5932, 16,
            	26, 32,
            	4883, 40,
            	5966, 104,
            	5508, 112,
            	5513, 120,
            	5518, 128,
            	5542, 136,
            	5566, 144,
            	5971, 176,
            1, 8, 1, /* 5817: pointer.struct.x509_cinf_st */
            	5822, 0,
            0, 104, 11, /* 5822: struct.x509_cinf_st */
            	5847, 0,
            	5847, 8,
            	5857, 16,
            	5862, 24,
            	5910, 32,
            	5862, 40,
            	5927, 48,
            	5932, 56,
            	5932, 64,
            	5937, 72,
            	5961, 80,
            1, 8, 1, /* 5847: pointer.struct.asn1_string_st */
            	5852, 0,
            0, 24, 1, /* 5852: struct.asn1_string_st */
            	13, 8,
            1, 8, 1, /* 5857: pointer.struct.X509_algor_st */
            	546, 0,
            1, 8, 1, /* 5862: pointer.struct.X509_name_st */
            	5867, 0,
            0, 40, 3, /* 5867: struct.X509_name_st */
            	5876, 0,
            	5900, 16,
            	13, 24,
            1, 8, 1, /* 5876: pointer.struct.stack_st_X509_NAME_ENTRY */
            	5881, 0,
            0, 32, 2, /* 5881: struct.stack_st_fake_X509_NAME_ENTRY */
            	5888, 8,
            	125, 24,
            8884099, 8, 2, /* 5888: pointer_to_array_of_pointers_to_stack */
            	5895, 0,
            	122, 20,
            0, 8, 1, /* 5895: pointer.X509_NAME_ENTRY */
            	76, 0,
            1, 8, 1, /* 5900: pointer.struct.buf_mem_st */
            	5905, 0,
            0, 24, 1, /* 5905: struct.buf_mem_st */
            	26, 8,
            1, 8, 1, /* 5910: pointer.struct.X509_val_st */
            	5915, 0,
            0, 16, 2, /* 5915: struct.X509_val_st */
            	5922, 0,
            	5922, 8,
            1, 8, 1, /* 5922: pointer.struct.asn1_string_st */
            	5852, 0,
            1, 8, 1, /* 5927: pointer.struct.X509_pubkey_st */
            	778, 0,
            1, 8, 1, /* 5932: pointer.struct.asn1_string_st */
            	5852, 0,
            1, 8, 1, /* 5937: pointer.struct.stack_st_X509_EXTENSION */
            	5942, 0,
            0, 32, 2, /* 5942: struct.stack_st_fake_X509_EXTENSION */
            	5949, 8,
            	125, 24,
            8884099, 8, 2, /* 5949: pointer_to_array_of_pointers_to_stack */
            	5956, 0,
            	122, 20,
            0, 8, 1, /* 5956: pointer.X509_EXTENSION */
            	2624, 0,
            0, 24, 1, /* 5961: struct.ASN1_ENCODING_st */
            	13, 0,
            1, 8, 1, /* 5966: pointer.struct.asn1_string_st */
            	5852, 0,
            1, 8, 1, /* 5971: pointer.struct.x509_cert_aux_st */
            	5976, 0,
            0, 40, 5, /* 5976: struct.x509_cert_aux_st */
            	4847, 0,
            	4847, 8,
            	5989, 16,
            	5966, 24,
            	5994, 32,
            1, 8, 1, /* 5989: pointer.struct.asn1_string_st */
            	5852, 0,
            1, 8, 1, /* 5994: pointer.struct.stack_st_X509_ALGOR */
            	5999, 0,
            0, 32, 2, /* 5999: struct.stack_st_fake_X509_ALGOR */
            	6006, 8,
            	125, 24,
            8884099, 8, 2, /* 6006: pointer_to_array_of_pointers_to_stack */
            	6013, 0,
            	122, 20,
            0, 8, 1, /* 6013: pointer.X509_ALGOR */
            	3959, 0,
            1, 8, 1, /* 6018: pointer.struct.ssl_cipher_st */
            	6023, 0,
            0, 88, 1, /* 6023: struct.ssl_cipher_st */
            	102, 8,
            8884097, 8, 0, /* 6028: pointer.func */
            8884097, 8, 0, /* 6031: pointer.func */
            8884097, 8, 0, /* 6034: pointer.func */
            1, 8, 1, /* 6037: pointer.struct.env_md_st */
            	6042, 0,
            0, 120, 8, /* 6042: struct.env_md_st */
            	6061, 24,
            	6064, 32,
            	6067, 40,
            	6070, 48,
            	6061, 56,
            	5761, 64,
            	5764, 72,
            	6073, 112,
            8884097, 8, 0, /* 6061: pointer.func */
            8884097, 8, 0, /* 6064: pointer.func */
            8884097, 8, 0, /* 6067: pointer.func */
            8884097, 8, 0, /* 6070: pointer.func */
            8884097, 8, 0, /* 6073: pointer.func */
            8884097, 8, 0, /* 6076: pointer.func */
            1, 8, 1, /* 6079: pointer.struct.stack_st_X509_NAME */
            	6084, 0,
            0, 32, 2, /* 6084: struct.stack_st_fake_X509_NAME */
            	6091, 8,
            	125, 24,
            8884099, 8, 2, /* 6091: pointer_to_array_of_pointers_to_stack */
            	6098, 0,
            	122, 20,
            0, 8, 1, /* 6098: pointer.X509_NAME */
            	6103, 0,
            0, 0, 1, /* 6103: X509_NAME */
            	4556, 0,
            1, 8, 1, /* 6108: pointer.struct.cert_st */
            	6113, 0,
            0, 296, 7, /* 6113: struct.cert_st */
            	6130, 0,
            	6530, 48,
            	6535, 56,
            	6538, 64,
            	6543, 72,
            	5780, 80,
            	6546, 88,
            1, 8, 1, /* 6130: pointer.struct.cert_pkey_st */
            	6135, 0,
            0, 24, 3, /* 6135: struct.cert_pkey_st */
            	6144, 0,
            	6423, 8,
            	6491, 16,
            1, 8, 1, /* 6144: pointer.struct.x509_st */
            	6149, 0,
            0, 184, 12, /* 6149: struct.x509_st */
            	6176, 0,
            	6216, 8,
            	6291, 16,
            	26, 32,
            	6325, 40,
            	6347, 104,
            	5508, 112,
            	5513, 120,
            	5518, 128,
            	5542, 136,
            	5566, 144,
            	6352, 176,
            1, 8, 1, /* 6176: pointer.struct.x509_cinf_st */
            	6181, 0,
            0, 104, 11, /* 6181: struct.x509_cinf_st */
            	6206, 0,
            	6206, 8,
            	6216, 16,
            	6221, 24,
            	6269, 32,
            	6221, 40,
            	6286, 48,
            	6291, 56,
            	6291, 64,
            	6296, 72,
            	6320, 80,
            1, 8, 1, /* 6206: pointer.struct.asn1_string_st */
            	6211, 0,
            0, 24, 1, /* 6211: struct.asn1_string_st */
            	13, 8,
            1, 8, 1, /* 6216: pointer.struct.X509_algor_st */
            	546, 0,
            1, 8, 1, /* 6221: pointer.struct.X509_name_st */
            	6226, 0,
            0, 40, 3, /* 6226: struct.X509_name_st */
            	6235, 0,
            	6259, 16,
            	13, 24,
            1, 8, 1, /* 6235: pointer.struct.stack_st_X509_NAME_ENTRY */
            	6240, 0,
            0, 32, 2, /* 6240: struct.stack_st_fake_X509_NAME_ENTRY */
            	6247, 8,
            	125, 24,
            8884099, 8, 2, /* 6247: pointer_to_array_of_pointers_to_stack */
            	6254, 0,
            	122, 20,
            0, 8, 1, /* 6254: pointer.X509_NAME_ENTRY */
            	76, 0,
            1, 8, 1, /* 6259: pointer.struct.buf_mem_st */
            	6264, 0,
            0, 24, 1, /* 6264: struct.buf_mem_st */
            	26, 8,
            1, 8, 1, /* 6269: pointer.struct.X509_val_st */
            	6274, 0,
            0, 16, 2, /* 6274: struct.X509_val_st */
            	6281, 0,
            	6281, 8,
            1, 8, 1, /* 6281: pointer.struct.asn1_string_st */
            	6211, 0,
            1, 8, 1, /* 6286: pointer.struct.X509_pubkey_st */
            	778, 0,
            1, 8, 1, /* 6291: pointer.struct.asn1_string_st */
            	6211, 0,
            1, 8, 1, /* 6296: pointer.struct.stack_st_X509_EXTENSION */
            	6301, 0,
            0, 32, 2, /* 6301: struct.stack_st_fake_X509_EXTENSION */
            	6308, 8,
            	125, 24,
            8884099, 8, 2, /* 6308: pointer_to_array_of_pointers_to_stack */
            	6315, 0,
            	122, 20,
            0, 8, 1, /* 6315: pointer.X509_EXTENSION */
            	2624, 0,
            0, 24, 1, /* 6320: struct.ASN1_ENCODING_st */
            	13, 0,
            0, 16, 1, /* 6325: struct.crypto_ex_data_st */
            	6330, 0,
            1, 8, 1, /* 6330: pointer.struct.stack_st_void */
            	6335, 0,
            0, 32, 1, /* 6335: struct.stack_st_void */
            	6340, 0,
            0, 32, 2, /* 6340: struct.stack_st */
            	1262, 8,
            	125, 24,
            1, 8, 1, /* 6347: pointer.struct.asn1_string_st */
            	6211, 0,
            1, 8, 1, /* 6352: pointer.struct.x509_cert_aux_st */
            	6357, 0,
            0, 40, 5, /* 6357: struct.x509_cert_aux_st */
            	6370, 0,
            	6370, 8,
            	6394, 16,
            	6347, 24,
            	6399, 32,
            1, 8, 1, /* 6370: pointer.struct.stack_st_ASN1_OBJECT */
            	6375, 0,
            0, 32, 2, /* 6375: struct.stack_st_fake_ASN1_OBJECT */
            	6382, 8,
            	125, 24,
            8884099, 8, 2, /* 6382: pointer_to_array_of_pointers_to_stack */
            	6389, 0,
            	122, 20,
            0, 8, 1, /* 6389: pointer.ASN1_OBJECT */
            	410, 0,
            1, 8, 1, /* 6394: pointer.struct.asn1_string_st */
            	6211, 0,
            1, 8, 1, /* 6399: pointer.struct.stack_st_X509_ALGOR */
            	6404, 0,
            0, 32, 2, /* 6404: struct.stack_st_fake_X509_ALGOR */
            	6411, 8,
            	125, 24,
            8884099, 8, 2, /* 6411: pointer_to_array_of_pointers_to_stack */
            	6418, 0,
            	122, 20,
            0, 8, 1, /* 6418: pointer.X509_ALGOR */
            	3959, 0,
            1, 8, 1, /* 6423: pointer.struct.evp_pkey_st */
            	6428, 0,
            0, 56, 4, /* 6428: struct.evp_pkey_st */
            	5658, 16,
            	5663, 24,
            	6439, 32,
            	6467, 48,
            0, 8, 5, /* 6439: union.unknown */
            	26, 0,
            	6452, 0,
            	6457, 0,
            	6462, 0,
            	5696, 0,
            1, 8, 1, /* 6452: pointer.struct.rsa_st */
            	1290, 0,
            1, 8, 1, /* 6457: pointer.struct.dsa_st */
            	1492, 0,
            1, 8, 1, /* 6462: pointer.struct.dh_st */
            	1619, 0,
            1, 8, 1, /* 6467: pointer.struct.stack_st_X509_ATTRIBUTE */
            	6472, 0,
            0, 32, 2, /* 6472: struct.stack_st_fake_X509_ATTRIBUTE */
            	6479, 8,
            	125, 24,
            8884099, 8, 2, /* 6479: pointer_to_array_of_pointers_to_stack */
            	6486, 0,
            	122, 20,
            0, 8, 1, /* 6486: pointer.X509_ATTRIBUTE */
            	2240, 0,
            1, 8, 1, /* 6491: pointer.struct.env_md_st */
            	6496, 0,
            0, 120, 8, /* 6496: struct.env_md_st */
            	6515, 24,
            	6518, 32,
            	6521, 40,
            	6524, 48,
            	6515, 56,
            	5761, 64,
            	5764, 72,
            	6527, 112,
            8884097, 8, 0, /* 6515: pointer.func */
            8884097, 8, 0, /* 6518: pointer.func */
            8884097, 8, 0, /* 6521: pointer.func */
            8884097, 8, 0, /* 6524: pointer.func */
            8884097, 8, 0, /* 6527: pointer.func */
            1, 8, 1, /* 6530: pointer.struct.rsa_st */
            	1290, 0,
            8884097, 8, 0, /* 6535: pointer.func */
            1, 8, 1, /* 6538: pointer.struct.dh_st */
            	1619, 0,
            8884097, 8, 0, /* 6543: pointer.func */
            8884097, 8, 0, /* 6546: pointer.func */
            8884097, 8, 0, /* 6549: pointer.func */
            8884097, 8, 0, /* 6552: pointer.func */
            8884097, 8, 0, /* 6555: pointer.func */
            8884097, 8, 0, /* 6558: pointer.func */
            8884097, 8, 0, /* 6561: pointer.func */
            0, 128, 14, /* 6564: struct.srp_ctx_st */
            	5, 0,
            	197, 8,
            	4439, 16,
            	6595, 24,
            	26, 32,
            	159, 40,
            	159, 48,
            	159, 56,
            	159, 64,
            	159, 72,
            	159, 80,
            	159, 88,
            	159, 96,
            	26, 104,
            8884097, 8, 0, /* 6595: pointer.func */
            1, 8, 1, /* 6598: pointer.struct.ssl_ctx_st */
            	4905, 0,
            1, 8, 1, /* 6603: pointer.struct.stack_st_X509_EXTENSION */
            	6608, 0,
            0, 32, 2, /* 6608: struct.stack_st_fake_X509_EXTENSION */
            	6615, 8,
            	125, 24,
            8884099, 8, 2, /* 6615: pointer_to_array_of_pointers_to_stack */
            	6622, 0,
            	122, 20,
            0, 8, 1, /* 6622: pointer.X509_EXTENSION */
            	2624, 0,
            1, 8, 1, /* 6627: pointer.struct.dsa_st */
            	1492, 0,
            1, 8, 1, /* 6632: pointer.struct.engine_st */
            	924, 0,
            0, 24, 1, /* 6637: struct.ssl3_buffer_st */
            	13, 0,
            8884097, 8, 0, /* 6642: pointer.func */
            0, 8, 5, /* 6645: union.unknown */
            	26, 0,
            	6658, 0,
            	6627, 0,
            	6663, 0,
            	6668, 0,
            1, 8, 1, /* 6658: pointer.struct.rsa_st */
            	1290, 0,
            1, 8, 1, /* 6663: pointer.struct.dh_st */
            	1619, 0,
            1, 8, 1, /* 6668: pointer.struct.ec_key_st */
            	1733, 0,
            8884097, 8, 0, /* 6673: pointer.func */
            8884097, 8, 0, /* 6676: pointer.func */
            8884097, 8, 0, /* 6679: pointer.func */
            0, 56, 3, /* 6682: struct.ssl3_record_st */
            	13, 16,
            	13, 24,
            	13, 32,
            8884097, 8, 0, /* 6691: pointer.func */
            0, 208, 25, /* 6694: struct.evp_pkey_method_st */
            	6747, 8,
            	6691, 16,
            	6750, 24,
            	6747, 32,
            	6753, 40,
            	6747, 48,
            	6753, 56,
            	6747, 64,
            	6756, 72,
            	6747, 80,
            	6759, 88,
            	6747, 96,
            	6756, 104,
            	6676, 112,
            	6673, 120,
            	6676, 128,
            	6762, 136,
            	6747, 144,
            	6756, 152,
            	6747, 160,
            	6756, 168,
            	6747, 176,
            	6765, 184,
            	6768, 192,
            	6771, 200,
            8884097, 8, 0, /* 6747: pointer.func */
            8884097, 8, 0, /* 6750: pointer.func */
            8884097, 8, 0, /* 6753: pointer.func */
            8884097, 8, 0, /* 6756: pointer.func */
            8884097, 8, 0, /* 6759: pointer.func */
            8884097, 8, 0, /* 6762: pointer.func */
            8884097, 8, 0, /* 6765: pointer.func */
            8884097, 8, 0, /* 6768: pointer.func */
            8884097, 8, 0, /* 6771: pointer.func */
            8884097, 8, 0, /* 6774: pointer.func */
            1, 8, 1, /* 6777: pointer.struct.stack_st_OCSP_RESPID */
            	6782, 0,
            0, 32, 2, /* 6782: struct.stack_st_fake_OCSP_RESPID */
            	6789, 8,
            	125, 24,
            8884099, 8, 2, /* 6789: pointer_to_array_of_pointers_to_stack */
            	6796, 0,
            	122, 20,
            0, 8, 1, /* 6796: pointer.OCSP_RESPID */
            	138, 0,
            8884097, 8, 0, /* 6801: pointer.func */
            1, 8, 1, /* 6804: pointer.struct.bio_method_st */
            	6809, 0,
            0, 80, 9, /* 6809: struct.bio_method_st */
            	102, 8,
            	6774, 16,
            	6801, 24,
            	6679, 32,
            	6801, 40,
            	6830, 48,
            	6833, 56,
            	6833, 64,
            	6836, 72,
            8884097, 8, 0, /* 6830: pointer.func */
            8884097, 8, 0, /* 6833: pointer.func */
            8884097, 8, 0, /* 6836: pointer.func */
            8884097, 8, 0, /* 6839: pointer.func */
            1, 8, 1, /* 6842: pointer.struct.evp_pkey_method_st */
            	6694, 0,
            0, 112, 7, /* 6847: struct.bio_st */
            	6804, 0,
            	6864, 8,
            	26, 16,
            	5, 48,
            	6867, 56,
            	6867, 64,
            	4883, 96,
            8884097, 8, 0, /* 6864: pointer.func */
            1, 8, 1, /* 6867: pointer.struct.bio_st */
            	6847, 0,
            1, 8, 1, /* 6872: pointer.struct.bio_st */
            	6847, 0,
            1, 8, 1, /* 6877: pointer.struct.ssl_st */
            	6882, 0,
            0, 808, 51, /* 6882: struct.ssl_st */
            	5008, 8,
            	6872, 16,
            	6872, 24,
            	6872, 32,
            	5072, 48,
            	5900, 80,
            	5, 88,
            	13, 104,
            	6987, 120,
            	7013, 128,
            	7239, 136,
            	6549, 152,
            	5, 160,
            	4835, 176,
            	5174, 184,
            	5174, 192,
            	7309, 208,
            	7046, 216,
            	7325, 224,
            	7309, 232,
            	7046, 240,
            	7325, 248,
            	6108, 256,
            	7337, 304,
            	6552, 312,
            	4871, 328,
            	6076, 336,
            	6558, 352,
            	6561, 360,
            	6598, 368,
            	4883, 392,
            	6079, 408,
            	7342, 464,
            	5, 472,
            	26, 480,
            	6777, 504,
            	6603, 512,
            	13, 520,
            	13, 544,
            	13, 560,
            	5, 568,
            	7345, 584,
            	7350, 592,
            	5, 600,
            	7353, 608,
            	5, 616,
            	6598, 624,
            	13, 632,
            	246, 648,
            	7356, 656,
            	6564, 680,
            1, 8, 1, /* 6987: pointer.struct.ssl2_state_st */
            	6992, 0,
            0, 344, 9, /* 6992: struct.ssl2_state_st */
            	107, 24,
            	13, 56,
            	13, 64,
            	13, 72,
            	13, 104,
            	13, 112,
            	13, 120,
            	13, 128,
            	13, 136,
            1, 8, 1, /* 7013: pointer.struct.ssl3_state_st */
            	7018, 0,
            0, 1200, 10, /* 7018: struct.ssl3_state_st */
            	6637, 240,
            	6637, 264,
            	6682, 288,
            	6682, 344,
            	107, 432,
            	6872, 440,
            	7041, 448,
            	5, 496,
            	5, 512,
            	7138, 528,
            1, 8, 1, /* 7041: pointer.pointer.struct.env_md_ctx_st */
            	7046, 0,
            1, 8, 1, /* 7046: pointer.struct.env_md_ctx_st */
            	7051, 0,
            0, 48, 5, /* 7051: struct.env_md_ctx_st */
            	6037, 0,
            	5663, 8,
            	5, 24,
            	7064, 32,
            	6064, 40,
            1, 8, 1, /* 7064: pointer.struct.evp_pkey_ctx_st */
            	7069, 0,
            0, 80, 8, /* 7069: struct.evp_pkey_ctx_st */
            	6842, 0,
            	6632, 8,
            	7088, 16,
            	7088, 24,
            	5, 40,
            	5, 48,
            	6839, 56,
            	7133, 64,
            1, 8, 1, /* 7088: pointer.struct.evp_pkey_st */
            	7093, 0,
            0, 56, 4, /* 7093: struct.evp_pkey_st */
            	7104, 16,
            	6632, 24,
            	6645, 32,
            	7109, 48,
            1, 8, 1, /* 7104: pointer.struct.evp_pkey_asn1_method_st */
            	823, 0,
            1, 8, 1, /* 7109: pointer.struct.stack_st_X509_ATTRIBUTE */
            	7114, 0,
            0, 32, 2, /* 7114: struct.stack_st_fake_X509_ATTRIBUTE */
            	7121, 8,
            	125, 24,
            8884099, 8, 2, /* 7121: pointer_to_array_of_pointers_to_stack */
            	7128, 0,
            	122, 20,
            0, 8, 1, /* 7128: pointer.X509_ATTRIBUTE */
            	2240, 0,
            1, 8, 1, /* 7133: pointer.int */
            	122, 0,
            0, 528, 8, /* 7138: struct.unknown */
            	6018, 408,
            	7157, 416,
            	5780, 424,
            	6079, 464,
            	13, 480,
            	7162, 488,
            	6037, 496,
            	7199, 512,
            1, 8, 1, /* 7157: pointer.struct.dh_st */
            	1619, 0,
            1, 8, 1, /* 7162: pointer.struct.evp_cipher_st */
            	7167, 0,
            0, 88, 7, /* 7167: struct.evp_cipher_st */
            	7184, 24,
            	7187, 32,
            	7190, 40,
            	7193, 56,
            	7193, 64,
            	7196, 72,
            	5, 80,
            8884097, 8, 0, /* 7184: pointer.func */
            8884097, 8, 0, /* 7187: pointer.func */
            8884097, 8, 0, /* 7190: pointer.func */
            8884097, 8, 0, /* 7193: pointer.func */
            8884097, 8, 0, /* 7196: pointer.func */
            1, 8, 1, /* 7199: pointer.struct.ssl_comp_st */
            	7204, 0,
            0, 24, 2, /* 7204: struct.ssl_comp_st */
            	102, 8,
            	7211, 16,
            1, 8, 1, /* 7211: pointer.struct.comp_method_st */
            	7216, 0,
            0, 64, 7, /* 7216: struct.comp_method_st */
            	102, 8,
            	7233, 16,
            	7236, 24,
            	6642, 32,
            	6642, 40,
            	226, 48,
            	226, 56,
            8884097, 8, 0, /* 7233: pointer.func */
            8884097, 8, 0, /* 7236: pointer.func */
            1, 8, 1, /* 7239: pointer.struct.dtls1_state_st */
            	7244, 0,
            0, 888, 7, /* 7244: struct.dtls1_state_st */
            	7261, 576,
            	7261, 592,
            	7266, 608,
            	7266, 616,
            	7261, 624,
            	7293, 648,
            	7293, 736,
            0, 16, 1, /* 7261: struct.record_pqueue_st */
            	7266, 8,
            1, 8, 1, /* 7266: pointer.struct._pqueue */
            	7271, 0,
            0, 16, 1, /* 7271: struct._pqueue */
            	7276, 0,
            1, 8, 1, /* 7276: pointer.struct._pitem */
            	7281, 0,
            0, 24, 2, /* 7281: struct._pitem */
            	5, 8,
            	7288, 16,
            1, 8, 1, /* 7288: pointer.struct._pitem */
            	7281, 0,
            0, 88, 1, /* 7293: struct.hm_header_st */
            	7298, 48,
            0, 40, 4, /* 7298: struct.dtls1_retransmit_state */
            	7309, 0,
            	7046, 8,
            	7325, 16,
            	7337, 24,
            1, 8, 1, /* 7309: pointer.struct.evp_cipher_ctx_st */
            	7314, 0,
            0, 168, 4, /* 7314: struct.evp_cipher_ctx_st */
            	7162, 0,
            	5663, 8,
            	5, 96,
            	5, 120,
            1, 8, 1, /* 7325: pointer.struct.comp_ctx_st */
            	7330, 0,
            0, 56, 2, /* 7330: struct.comp_ctx_st */
            	7211, 0,
            	4883, 40,
            1, 8, 1, /* 7337: pointer.struct.ssl_session_st */
            	5213, 0,
            8884097, 8, 0, /* 7342: pointer.func */
            1, 8, 1, /* 7345: pointer.struct.tls_session_ticket_ext_st */
            	0, 0,
            8884097, 8, 0, /* 7350: pointer.func */
            8884097, 8, 0, /* 7353: pointer.func */
            1, 8, 1, /* 7356: pointer.struct.srtp_protection_profile_st */
            	4445, 0,
            0, 1, 0, /* 7361: char */
        },
        .arg_entity_index = { 6877, },
        .ret_entity_index = 122,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    const SSL * new_arg_a = *((const SSL * *)new_args->args[0]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_SSL_get_verify_mode)(const SSL *);
    orig_SSL_get_verify_mode = dlsym(RTLD_NEXT, "SSL_get_verify_mode");
    *new_ret_ptr = (*orig_SSL_get_verify_mode)(new_arg_a);

    syscall(889);

    return ret;
}

