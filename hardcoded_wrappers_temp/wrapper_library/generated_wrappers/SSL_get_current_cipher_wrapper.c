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

const SSL_CIPHER * bb_SSL_get_current_cipher(const SSL * arg_a);

const SSL_CIPHER * SSL_get_current_cipher(const SSL * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_get_current_cipher called %lu\n", in_lib);
    if (!in_lib)
        return bb_SSL_get_current_cipher(arg_a);
    else {
        const SSL_CIPHER * (*orig_SSL_get_current_cipher)(const SSL *);
        orig_SSL_get_current_cipher = dlsym(RTLD_NEXT, "SSL_get_current_cipher");
        return orig_SSL_get_current_cipher(arg_a);
    }
}

const SSL_CIPHER * bb_SSL_get_current_cipher(const SSL * arg_a) 
{
    const SSL_CIPHER * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 88, 1, /* 0: struct.ssl_cipher_st */
            	5, 8,
            1, 8, 1, /* 5: pointer.char */
            	8884096, 0,
            0, 16, 1, /* 10: struct.srtp_protection_profile_st */
            	5, 0,
            0, 16, 1, /* 15: struct.tls_session_ticket_ext_st */
            	20, 8,
            0, 8, 0, /* 20: pointer.void */
            0, 0, 1, /* 23: OCSP_RESPID */
            	28, 0,
            0, 16, 1, /* 28: struct.ocsp_responder_id_st */
            	33, 8,
            0, 8, 2, /* 33: union.unknown */
            	40, 0,
            	148, 0,
            1, 8, 1, /* 40: pointer.struct.X509_name_st */
            	45, 0,
            0, 40, 3, /* 45: struct.X509_name_st */
            	54, 0,
            	133, 16,
            	122, 24,
            1, 8, 1, /* 54: pointer.struct.stack_st_X509_NAME_ENTRY */
            	59, 0,
            0, 32, 2, /* 59: struct.stack_st_fake_X509_NAME_ENTRY */
            	66, 8,
            	130, 24,
            8884099, 8, 2, /* 66: pointer_to_array_of_pointers_to_stack */
            	73, 0,
            	127, 20,
            0, 8, 1, /* 73: pointer.X509_NAME_ENTRY */
            	78, 0,
            0, 0, 1, /* 78: X509_NAME_ENTRY */
            	83, 0,
            0, 24, 2, /* 83: struct.X509_name_entry_st */
            	90, 0,
            	112, 8,
            1, 8, 1, /* 90: pointer.struct.asn1_object_st */
            	95, 0,
            0, 40, 3, /* 95: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	104, 24,
            1, 8, 1, /* 104: pointer.unsigned char */
            	109, 0,
            0, 1, 0, /* 109: unsigned char */
            1, 8, 1, /* 112: pointer.struct.asn1_string_st */
            	117, 0,
            0, 24, 1, /* 117: struct.asn1_string_st */
            	122, 8,
            1, 8, 1, /* 122: pointer.unsigned char */
            	109, 0,
            0, 4, 0, /* 127: int */
            8884097, 8, 0, /* 130: pointer.func */
            1, 8, 1, /* 133: pointer.struct.buf_mem_st */
            	138, 0,
            0, 24, 1, /* 138: struct.buf_mem_st */
            	143, 8,
            1, 8, 1, /* 143: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 148: pointer.struct.asn1_string_st */
            	153, 0,
            0, 24, 1, /* 153: struct.asn1_string_st */
            	122, 8,
            0, 16, 1, /* 158: struct.srtp_protection_profile_st */
            	5, 0,
            0, 0, 1, /* 163: SRTP_PROTECTION_PROFILE */
            	158, 0,
            8884097, 8, 0, /* 168: pointer.func */
            0, 24, 1, /* 171: struct.bignum_st */
            	176, 0,
            8884099, 8, 2, /* 176: pointer_to_array_of_pointers_to_stack */
            	183, 0,
            	127, 12,
            0, 4, 0, /* 183: unsigned int */
            1, 8, 1, /* 186: pointer.struct.bignum_st */
            	171, 0,
            1, 8, 1, /* 191: pointer.struct.ssl3_buf_freelist_st */
            	196, 0,
            0, 24, 1, /* 196: struct.ssl3_buf_freelist_st */
            	201, 16,
            1, 8, 1, /* 201: pointer.struct.ssl3_buf_freelist_entry_st */
            	206, 0,
            0, 8, 1, /* 206: struct.ssl3_buf_freelist_entry_st */
            	201, 0,
            8884097, 8, 0, /* 211: pointer.func */
            8884097, 8, 0, /* 214: pointer.func */
            8884097, 8, 0, /* 217: pointer.func */
            8884097, 8, 0, /* 220: pointer.func */
            0, 64, 7, /* 223: struct.comp_method_st */
            	5, 8,
            	220, 16,
            	217, 24,
            	214, 32,
            	214, 40,
            	240, 48,
            	240, 56,
            8884097, 8, 0, /* 240: pointer.func */
            0, 0, 1, /* 243: SSL_COMP */
            	248, 0,
            0, 24, 2, /* 248: struct.ssl_comp_st */
            	5, 8,
            	255, 16,
            1, 8, 1, /* 255: pointer.struct.comp_method_st */
            	223, 0,
            8884097, 8, 0, /* 260: pointer.func */
            8884097, 8, 0, /* 263: pointer.func */
            8884097, 8, 0, /* 266: pointer.func */
            8884097, 8, 0, /* 269: pointer.func */
            1, 8, 1, /* 272: pointer.struct.lhash_node_st */
            	277, 0,
            0, 24, 2, /* 277: struct.lhash_node_st */
            	20, 0,
            	272, 8,
            0, 176, 3, /* 284: struct.lhash_st */
            	293, 0,
            	130, 8,
            	300, 16,
            8884099, 8, 2, /* 293: pointer_to_array_of_pointers_to_stack */
            	272, 0,
            	183, 28,
            8884097, 8, 0, /* 300: pointer.func */
            1, 8, 1, /* 303: pointer.struct.lhash_st */
            	284, 0,
            8884097, 8, 0, /* 308: pointer.func */
            8884097, 8, 0, /* 311: pointer.func */
            8884097, 8, 0, /* 314: pointer.func */
            8884097, 8, 0, /* 317: pointer.func */
            8884097, 8, 0, /* 320: pointer.func */
            8884097, 8, 0, /* 323: pointer.func */
            8884097, 8, 0, /* 326: pointer.func */
            8884097, 8, 0, /* 329: pointer.func */
            1, 8, 1, /* 332: pointer.struct.X509_VERIFY_PARAM_st */
            	337, 0,
            0, 56, 2, /* 337: struct.X509_VERIFY_PARAM_st */
            	143, 0,
            	344, 48,
            1, 8, 1, /* 344: pointer.struct.stack_st_ASN1_OBJECT */
            	349, 0,
            0, 32, 2, /* 349: struct.stack_st_fake_ASN1_OBJECT */
            	356, 8,
            	130, 24,
            8884099, 8, 2, /* 356: pointer_to_array_of_pointers_to_stack */
            	363, 0,
            	127, 20,
            0, 8, 1, /* 363: pointer.ASN1_OBJECT */
            	368, 0,
            0, 0, 1, /* 368: ASN1_OBJECT */
            	373, 0,
            0, 40, 3, /* 373: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	104, 24,
            1, 8, 1, /* 382: pointer.struct.stack_st_X509_OBJECT */
            	387, 0,
            0, 32, 2, /* 387: struct.stack_st_fake_X509_OBJECT */
            	394, 8,
            	130, 24,
            8884099, 8, 2, /* 394: pointer_to_array_of_pointers_to_stack */
            	401, 0,
            	127, 20,
            0, 8, 1, /* 401: pointer.X509_OBJECT */
            	406, 0,
            0, 0, 1, /* 406: X509_OBJECT */
            	411, 0,
            0, 16, 1, /* 411: struct.x509_object_st */
            	416, 8,
            0, 8, 4, /* 416: union.unknown */
            	143, 0,
            	427, 0,
            	3910, 0,
            	4244, 0,
            1, 8, 1, /* 427: pointer.struct.x509_st */
            	432, 0,
            0, 184, 12, /* 432: struct.x509_st */
            	459, 0,
            	499, 8,
            	2604, 16,
            	143, 32,
            	2674, 40,
            	2696, 104,
            	2701, 112,
            	2966, 120,
            	3383, 128,
            	3522, 136,
            	3546, 144,
            	3858, 176,
            1, 8, 1, /* 459: pointer.struct.x509_cinf_st */
            	464, 0,
            0, 104, 11, /* 464: struct.x509_cinf_st */
            	489, 0,
            	489, 8,
            	499, 16,
            	666, 24,
            	714, 32,
            	666, 40,
            	731, 48,
            	2604, 56,
            	2604, 64,
            	2609, 72,
            	2669, 80,
            1, 8, 1, /* 489: pointer.struct.asn1_string_st */
            	494, 0,
            0, 24, 1, /* 494: struct.asn1_string_st */
            	122, 8,
            1, 8, 1, /* 499: pointer.struct.X509_algor_st */
            	504, 0,
            0, 16, 2, /* 504: struct.X509_algor_st */
            	511, 0,
            	525, 8,
            1, 8, 1, /* 511: pointer.struct.asn1_object_st */
            	516, 0,
            0, 40, 3, /* 516: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	104, 24,
            1, 8, 1, /* 525: pointer.struct.asn1_type_st */
            	530, 0,
            0, 16, 1, /* 530: struct.asn1_type_st */
            	535, 8,
            0, 8, 20, /* 535: union.unknown */
            	143, 0,
            	578, 0,
            	511, 0,
            	588, 0,
            	593, 0,
            	598, 0,
            	603, 0,
            	608, 0,
            	613, 0,
            	618, 0,
            	623, 0,
            	628, 0,
            	633, 0,
            	638, 0,
            	643, 0,
            	648, 0,
            	653, 0,
            	578, 0,
            	578, 0,
            	658, 0,
            1, 8, 1, /* 578: pointer.struct.asn1_string_st */
            	583, 0,
            0, 24, 1, /* 583: struct.asn1_string_st */
            	122, 8,
            1, 8, 1, /* 588: pointer.struct.asn1_string_st */
            	583, 0,
            1, 8, 1, /* 593: pointer.struct.asn1_string_st */
            	583, 0,
            1, 8, 1, /* 598: pointer.struct.asn1_string_st */
            	583, 0,
            1, 8, 1, /* 603: pointer.struct.asn1_string_st */
            	583, 0,
            1, 8, 1, /* 608: pointer.struct.asn1_string_st */
            	583, 0,
            1, 8, 1, /* 613: pointer.struct.asn1_string_st */
            	583, 0,
            1, 8, 1, /* 618: pointer.struct.asn1_string_st */
            	583, 0,
            1, 8, 1, /* 623: pointer.struct.asn1_string_st */
            	583, 0,
            1, 8, 1, /* 628: pointer.struct.asn1_string_st */
            	583, 0,
            1, 8, 1, /* 633: pointer.struct.asn1_string_st */
            	583, 0,
            1, 8, 1, /* 638: pointer.struct.asn1_string_st */
            	583, 0,
            1, 8, 1, /* 643: pointer.struct.asn1_string_st */
            	583, 0,
            1, 8, 1, /* 648: pointer.struct.asn1_string_st */
            	583, 0,
            1, 8, 1, /* 653: pointer.struct.asn1_string_st */
            	583, 0,
            1, 8, 1, /* 658: pointer.struct.ASN1_VALUE_st */
            	663, 0,
            0, 0, 0, /* 663: struct.ASN1_VALUE_st */
            1, 8, 1, /* 666: pointer.struct.X509_name_st */
            	671, 0,
            0, 40, 3, /* 671: struct.X509_name_st */
            	680, 0,
            	704, 16,
            	122, 24,
            1, 8, 1, /* 680: pointer.struct.stack_st_X509_NAME_ENTRY */
            	685, 0,
            0, 32, 2, /* 685: struct.stack_st_fake_X509_NAME_ENTRY */
            	692, 8,
            	130, 24,
            8884099, 8, 2, /* 692: pointer_to_array_of_pointers_to_stack */
            	699, 0,
            	127, 20,
            0, 8, 1, /* 699: pointer.X509_NAME_ENTRY */
            	78, 0,
            1, 8, 1, /* 704: pointer.struct.buf_mem_st */
            	709, 0,
            0, 24, 1, /* 709: struct.buf_mem_st */
            	143, 8,
            1, 8, 1, /* 714: pointer.struct.X509_val_st */
            	719, 0,
            0, 16, 2, /* 719: struct.X509_val_st */
            	726, 0,
            	726, 8,
            1, 8, 1, /* 726: pointer.struct.asn1_string_st */
            	494, 0,
            1, 8, 1, /* 731: pointer.struct.X509_pubkey_st */
            	736, 0,
            0, 24, 3, /* 736: struct.X509_pubkey_st */
            	745, 0,
            	750, 8,
            	760, 16,
            1, 8, 1, /* 745: pointer.struct.X509_algor_st */
            	504, 0,
            1, 8, 1, /* 750: pointer.struct.asn1_string_st */
            	755, 0,
            0, 24, 1, /* 755: struct.asn1_string_st */
            	122, 8,
            1, 8, 1, /* 760: pointer.struct.evp_pkey_st */
            	765, 0,
            0, 56, 4, /* 765: struct.evp_pkey_st */
            	776, 16,
            	877, 24,
            	1230, 32,
            	2233, 48,
            1, 8, 1, /* 776: pointer.struct.evp_pkey_asn1_method_st */
            	781, 0,
            0, 208, 24, /* 781: struct.evp_pkey_asn1_method_st */
            	143, 16,
            	143, 24,
            	832, 32,
            	835, 40,
            	838, 48,
            	841, 56,
            	844, 64,
            	847, 72,
            	841, 80,
            	850, 88,
            	850, 96,
            	853, 104,
            	856, 112,
            	850, 120,
            	859, 128,
            	838, 136,
            	841, 144,
            	862, 152,
            	865, 160,
            	868, 168,
            	853, 176,
            	856, 184,
            	871, 192,
            	874, 200,
            8884097, 8, 0, /* 832: pointer.func */
            8884097, 8, 0, /* 835: pointer.func */
            8884097, 8, 0, /* 838: pointer.func */
            8884097, 8, 0, /* 841: pointer.func */
            8884097, 8, 0, /* 844: pointer.func */
            8884097, 8, 0, /* 847: pointer.func */
            8884097, 8, 0, /* 850: pointer.func */
            8884097, 8, 0, /* 853: pointer.func */
            8884097, 8, 0, /* 856: pointer.func */
            8884097, 8, 0, /* 859: pointer.func */
            8884097, 8, 0, /* 862: pointer.func */
            8884097, 8, 0, /* 865: pointer.func */
            8884097, 8, 0, /* 868: pointer.func */
            8884097, 8, 0, /* 871: pointer.func */
            8884097, 8, 0, /* 874: pointer.func */
            1, 8, 1, /* 877: pointer.struct.engine_st */
            	882, 0,
            0, 216, 24, /* 882: struct.engine_st */
            	5, 0,
            	5, 8,
            	933, 16,
            	988, 24,
            	1039, 32,
            	1075, 40,
            	1092, 48,
            	1119, 56,
            	1154, 64,
            	1162, 72,
            	1165, 80,
            	1168, 88,
            	1171, 96,
            	1174, 104,
            	1174, 112,
            	1174, 120,
            	1177, 128,
            	1180, 136,
            	1180, 144,
            	1183, 152,
            	1186, 160,
            	1198, 184,
            	1225, 200,
            	1225, 208,
            1, 8, 1, /* 933: pointer.struct.rsa_meth_st */
            	938, 0,
            0, 112, 13, /* 938: struct.rsa_meth_st */
            	5, 0,
            	967, 8,
            	967, 16,
            	967, 24,
            	967, 32,
            	970, 40,
            	973, 48,
            	976, 56,
            	976, 64,
            	143, 80,
            	979, 88,
            	982, 96,
            	985, 104,
            8884097, 8, 0, /* 967: pointer.func */
            8884097, 8, 0, /* 970: pointer.func */
            8884097, 8, 0, /* 973: pointer.func */
            8884097, 8, 0, /* 976: pointer.func */
            8884097, 8, 0, /* 979: pointer.func */
            8884097, 8, 0, /* 982: pointer.func */
            8884097, 8, 0, /* 985: pointer.func */
            1, 8, 1, /* 988: pointer.struct.dsa_method */
            	993, 0,
            0, 96, 11, /* 993: struct.dsa_method */
            	5, 0,
            	1018, 8,
            	1021, 16,
            	1024, 24,
            	1027, 32,
            	1030, 40,
            	1033, 48,
            	1033, 56,
            	143, 72,
            	1036, 80,
            	1033, 88,
            8884097, 8, 0, /* 1018: pointer.func */
            8884097, 8, 0, /* 1021: pointer.func */
            8884097, 8, 0, /* 1024: pointer.func */
            8884097, 8, 0, /* 1027: pointer.func */
            8884097, 8, 0, /* 1030: pointer.func */
            8884097, 8, 0, /* 1033: pointer.func */
            8884097, 8, 0, /* 1036: pointer.func */
            1, 8, 1, /* 1039: pointer.struct.dh_method */
            	1044, 0,
            0, 72, 8, /* 1044: struct.dh_method */
            	5, 0,
            	1063, 8,
            	1066, 16,
            	1069, 24,
            	1063, 32,
            	1063, 40,
            	143, 56,
            	1072, 64,
            8884097, 8, 0, /* 1063: pointer.func */
            8884097, 8, 0, /* 1066: pointer.func */
            8884097, 8, 0, /* 1069: pointer.func */
            8884097, 8, 0, /* 1072: pointer.func */
            1, 8, 1, /* 1075: pointer.struct.ecdh_method */
            	1080, 0,
            0, 32, 3, /* 1080: struct.ecdh_method */
            	5, 0,
            	1089, 8,
            	143, 24,
            8884097, 8, 0, /* 1089: pointer.func */
            1, 8, 1, /* 1092: pointer.struct.ecdsa_method */
            	1097, 0,
            0, 48, 5, /* 1097: struct.ecdsa_method */
            	5, 0,
            	1110, 8,
            	1113, 16,
            	1116, 24,
            	143, 40,
            8884097, 8, 0, /* 1110: pointer.func */
            8884097, 8, 0, /* 1113: pointer.func */
            8884097, 8, 0, /* 1116: pointer.func */
            1, 8, 1, /* 1119: pointer.struct.rand_meth_st */
            	1124, 0,
            0, 48, 6, /* 1124: struct.rand_meth_st */
            	1139, 0,
            	1142, 8,
            	1145, 16,
            	1148, 24,
            	1142, 32,
            	1151, 40,
            8884097, 8, 0, /* 1139: pointer.func */
            8884097, 8, 0, /* 1142: pointer.func */
            8884097, 8, 0, /* 1145: pointer.func */
            8884097, 8, 0, /* 1148: pointer.func */
            8884097, 8, 0, /* 1151: pointer.func */
            1, 8, 1, /* 1154: pointer.struct.store_method_st */
            	1159, 0,
            0, 0, 0, /* 1159: struct.store_method_st */
            8884097, 8, 0, /* 1162: pointer.func */
            8884097, 8, 0, /* 1165: pointer.func */
            8884097, 8, 0, /* 1168: pointer.func */
            8884097, 8, 0, /* 1171: pointer.func */
            8884097, 8, 0, /* 1174: pointer.func */
            8884097, 8, 0, /* 1177: pointer.func */
            8884097, 8, 0, /* 1180: pointer.func */
            8884097, 8, 0, /* 1183: pointer.func */
            1, 8, 1, /* 1186: pointer.struct.ENGINE_CMD_DEFN_st */
            	1191, 0,
            0, 32, 2, /* 1191: struct.ENGINE_CMD_DEFN_st */
            	5, 8,
            	5, 16,
            0, 16, 1, /* 1198: struct.crypto_ex_data_st */
            	1203, 0,
            1, 8, 1, /* 1203: pointer.struct.stack_st_void */
            	1208, 0,
            0, 32, 1, /* 1208: struct.stack_st_void */
            	1213, 0,
            0, 32, 2, /* 1213: struct.stack_st */
            	1220, 8,
            	130, 24,
            1, 8, 1, /* 1220: pointer.pointer.char */
            	143, 0,
            1, 8, 1, /* 1225: pointer.struct.engine_st */
            	882, 0,
            0, 8, 5, /* 1230: union.unknown */
            	143, 0,
            	1243, 0,
            	1459, 0,
            	1598, 0,
            	1724, 0,
            1, 8, 1, /* 1243: pointer.struct.rsa_st */
            	1248, 0,
            0, 168, 17, /* 1248: struct.rsa_st */
            	1285, 16,
            	1340, 24,
            	1345, 32,
            	1345, 40,
            	1345, 48,
            	1345, 56,
            	1345, 64,
            	1345, 72,
            	1345, 80,
            	1345, 88,
            	1362, 96,
            	1384, 120,
            	1384, 128,
            	1384, 136,
            	143, 144,
            	1398, 152,
            	1398, 160,
            1, 8, 1, /* 1285: pointer.struct.rsa_meth_st */
            	1290, 0,
            0, 112, 13, /* 1290: struct.rsa_meth_st */
            	5, 0,
            	1319, 8,
            	1319, 16,
            	1319, 24,
            	1319, 32,
            	1322, 40,
            	1325, 48,
            	1328, 56,
            	1328, 64,
            	143, 80,
            	1331, 88,
            	1334, 96,
            	1337, 104,
            8884097, 8, 0, /* 1319: pointer.func */
            8884097, 8, 0, /* 1322: pointer.func */
            8884097, 8, 0, /* 1325: pointer.func */
            8884097, 8, 0, /* 1328: pointer.func */
            8884097, 8, 0, /* 1331: pointer.func */
            8884097, 8, 0, /* 1334: pointer.func */
            8884097, 8, 0, /* 1337: pointer.func */
            1, 8, 1, /* 1340: pointer.struct.engine_st */
            	882, 0,
            1, 8, 1, /* 1345: pointer.struct.bignum_st */
            	1350, 0,
            0, 24, 1, /* 1350: struct.bignum_st */
            	1355, 0,
            8884099, 8, 2, /* 1355: pointer_to_array_of_pointers_to_stack */
            	183, 0,
            	127, 12,
            0, 16, 1, /* 1362: struct.crypto_ex_data_st */
            	1367, 0,
            1, 8, 1, /* 1367: pointer.struct.stack_st_void */
            	1372, 0,
            0, 32, 1, /* 1372: struct.stack_st_void */
            	1377, 0,
            0, 32, 2, /* 1377: struct.stack_st */
            	1220, 8,
            	130, 24,
            1, 8, 1, /* 1384: pointer.struct.bn_mont_ctx_st */
            	1389, 0,
            0, 96, 3, /* 1389: struct.bn_mont_ctx_st */
            	1350, 8,
            	1350, 32,
            	1350, 56,
            1, 8, 1, /* 1398: pointer.struct.bn_blinding_st */
            	1403, 0,
            0, 88, 7, /* 1403: struct.bn_blinding_st */
            	1420, 0,
            	1420, 8,
            	1420, 16,
            	1420, 24,
            	1437, 40,
            	1442, 72,
            	1456, 80,
            1, 8, 1, /* 1420: pointer.struct.bignum_st */
            	1425, 0,
            0, 24, 1, /* 1425: struct.bignum_st */
            	1430, 0,
            8884099, 8, 2, /* 1430: pointer_to_array_of_pointers_to_stack */
            	183, 0,
            	127, 12,
            0, 16, 1, /* 1437: struct.crypto_threadid_st */
            	20, 0,
            1, 8, 1, /* 1442: pointer.struct.bn_mont_ctx_st */
            	1447, 0,
            0, 96, 3, /* 1447: struct.bn_mont_ctx_st */
            	1425, 8,
            	1425, 32,
            	1425, 56,
            8884097, 8, 0, /* 1456: pointer.func */
            1, 8, 1, /* 1459: pointer.struct.dsa_st */
            	1464, 0,
            0, 136, 11, /* 1464: struct.dsa_st */
            	1489, 24,
            	1489, 32,
            	1489, 40,
            	1489, 48,
            	1489, 56,
            	1489, 64,
            	1489, 72,
            	1506, 88,
            	1520, 104,
            	1542, 120,
            	1593, 128,
            1, 8, 1, /* 1489: pointer.struct.bignum_st */
            	1494, 0,
            0, 24, 1, /* 1494: struct.bignum_st */
            	1499, 0,
            8884099, 8, 2, /* 1499: pointer_to_array_of_pointers_to_stack */
            	183, 0,
            	127, 12,
            1, 8, 1, /* 1506: pointer.struct.bn_mont_ctx_st */
            	1511, 0,
            0, 96, 3, /* 1511: struct.bn_mont_ctx_st */
            	1494, 8,
            	1494, 32,
            	1494, 56,
            0, 16, 1, /* 1520: struct.crypto_ex_data_st */
            	1525, 0,
            1, 8, 1, /* 1525: pointer.struct.stack_st_void */
            	1530, 0,
            0, 32, 1, /* 1530: struct.stack_st_void */
            	1535, 0,
            0, 32, 2, /* 1535: struct.stack_st */
            	1220, 8,
            	130, 24,
            1, 8, 1, /* 1542: pointer.struct.dsa_method */
            	1547, 0,
            0, 96, 11, /* 1547: struct.dsa_method */
            	5, 0,
            	1572, 8,
            	1575, 16,
            	1578, 24,
            	1581, 32,
            	1584, 40,
            	1587, 48,
            	1587, 56,
            	143, 72,
            	1590, 80,
            	1587, 88,
            8884097, 8, 0, /* 1572: pointer.func */
            8884097, 8, 0, /* 1575: pointer.func */
            8884097, 8, 0, /* 1578: pointer.func */
            8884097, 8, 0, /* 1581: pointer.func */
            8884097, 8, 0, /* 1584: pointer.func */
            8884097, 8, 0, /* 1587: pointer.func */
            8884097, 8, 0, /* 1590: pointer.func */
            1, 8, 1, /* 1593: pointer.struct.engine_st */
            	882, 0,
            1, 8, 1, /* 1598: pointer.struct.dh_st */
            	1603, 0,
            0, 144, 12, /* 1603: struct.dh_st */
            	1630, 8,
            	1630, 16,
            	1630, 32,
            	1630, 40,
            	1647, 56,
            	1630, 64,
            	1630, 72,
            	122, 80,
            	1630, 96,
            	1661, 112,
            	1683, 128,
            	1719, 136,
            1, 8, 1, /* 1630: pointer.struct.bignum_st */
            	1635, 0,
            0, 24, 1, /* 1635: struct.bignum_st */
            	1640, 0,
            8884099, 8, 2, /* 1640: pointer_to_array_of_pointers_to_stack */
            	183, 0,
            	127, 12,
            1, 8, 1, /* 1647: pointer.struct.bn_mont_ctx_st */
            	1652, 0,
            0, 96, 3, /* 1652: struct.bn_mont_ctx_st */
            	1635, 8,
            	1635, 32,
            	1635, 56,
            0, 16, 1, /* 1661: struct.crypto_ex_data_st */
            	1666, 0,
            1, 8, 1, /* 1666: pointer.struct.stack_st_void */
            	1671, 0,
            0, 32, 1, /* 1671: struct.stack_st_void */
            	1676, 0,
            0, 32, 2, /* 1676: struct.stack_st */
            	1220, 8,
            	130, 24,
            1, 8, 1, /* 1683: pointer.struct.dh_method */
            	1688, 0,
            0, 72, 8, /* 1688: struct.dh_method */
            	5, 0,
            	1707, 8,
            	1710, 16,
            	1713, 24,
            	1707, 32,
            	1707, 40,
            	143, 56,
            	1716, 64,
            8884097, 8, 0, /* 1707: pointer.func */
            8884097, 8, 0, /* 1710: pointer.func */
            8884097, 8, 0, /* 1713: pointer.func */
            8884097, 8, 0, /* 1716: pointer.func */
            1, 8, 1, /* 1719: pointer.struct.engine_st */
            	882, 0,
            1, 8, 1, /* 1724: pointer.struct.ec_key_st */
            	1729, 0,
            0, 56, 4, /* 1729: struct.ec_key_st */
            	1740, 8,
            	2188, 16,
            	2193, 24,
            	2210, 48,
            1, 8, 1, /* 1740: pointer.struct.ec_group_st */
            	1745, 0,
            0, 232, 12, /* 1745: struct.ec_group_st */
            	1772, 0,
            	1944, 8,
            	2144, 16,
            	2144, 40,
            	122, 80,
            	2156, 96,
            	2144, 104,
            	2144, 152,
            	2144, 176,
            	20, 208,
            	20, 216,
            	2185, 224,
            1, 8, 1, /* 1772: pointer.struct.ec_method_st */
            	1777, 0,
            0, 304, 37, /* 1777: struct.ec_method_st */
            	1854, 8,
            	1857, 16,
            	1857, 24,
            	1860, 32,
            	1863, 40,
            	1866, 48,
            	1869, 56,
            	1872, 64,
            	1875, 72,
            	1878, 80,
            	1878, 88,
            	1881, 96,
            	1884, 104,
            	1887, 112,
            	1890, 120,
            	1893, 128,
            	1896, 136,
            	1899, 144,
            	1902, 152,
            	1905, 160,
            	1908, 168,
            	1911, 176,
            	1914, 184,
            	1917, 192,
            	1920, 200,
            	1923, 208,
            	1914, 216,
            	1926, 224,
            	1929, 232,
            	1932, 240,
            	1869, 248,
            	1935, 256,
            	1938, 264,
            	1935, 272,
            	1938, 280,
            	1938, 288,
            	1941, 296,
            8884097, 8, 0, /* 1854: pointer.func */
            8884097, 8, 0, /* 1857: pointer.func */
            8884097, 8, 0, /* 1860: pointer.func */
            8884097, 8, 0, /* 1863: pointer.func */
            8884097, 8, 0, /* 1866: pointer.func */
            8884097, 8, 0, /* 1869: pointer.func */
            8884097, 8, 0, /* 1872: pointer.func */
            8884097, 8, 0, /* 1875: pointer.func */
            8884097, 8, 0, /* 1878: pointer.func */
            8884097, 8, 0, /* 1881: pointer.func */
            8884097, 8, 0, /* 1884: pointer.func */
            8884097, 8, 0, /* 1887: pointer.func */
            8884097, 8, 0, /* 1890: pointer.func */
            8884097, 8, 0, /* 1893: pointer.func */
            8884097, 8, 0, /* 1896: pointer.func */
            8884097, 8, 0, /* 1899: pointer.func */
            8884097, 8, 0, /* 1902: pointer.func */
            8884097, 8, 0, /* 1905: pointer.func */
            8884097, 8, 0, /* 1908: pointer.func */
            8884097, 8, 0, /* 1911: pointer.func */
            8884097, 8, 0, /* 1914: pointer.func */
            8884097, 8, 0, /* 1917: pointer.func */
            8884097, 8, 0, /* 1920: pointer.func */
            8884097, 8, 0, /* 1923: pointer.func */
            8884097, 8, 0, /* 1926: pointer.func */
            8884097, 8, 0, /* 1929: pointer.func */
            8884097, 8, 0, /* 1932: pointer.func */
            8884097, 8, 0, /* 1935: pointer.func */
            8884097, 8, 0, /* 1938: pointer.func */
            8884097, 8, 0, /* 1941: pointer.func */
            1, 8, 1, /* 1944: pointer.struct.ec_point_st */
            	1949, 0,
            0, 88, 4, /* 1949: struct.ec_point_st */
            	1960, 0,
            	2132, 8,
            	2132, 32,
            	2132, 56,
            1, 8, 1, /* 1960: pointer.struct.ec_method_st */
            	1965, 0,
            0, 304, 37, /* 1965: struct.ec_method_st */
            	2042, 8,
            	2045, 16,
            	2045, 24,
            	2048, 32,
            	2051, 40,
            	2054, 48,
            	2057, 56,
            	2060, 64,
            	2063, 72,
            	2066, 80,
            	2066, 88,
            	2069, 96,
            	2072, 104,
            	2075, 112,
            	2078, 120,
            	2081, 128,
            	2084, 136,
            	2087, 144,
            	2090, 152,
            	2093, 160,
            	2096, 168,
            	2099, 176,
            	2102, 184,
            	2105, 192,
            	2108, 200,
            	2111, 208,
            	2102, 216,
            	2114, 224,
            	2117, 232,
            	2120, 240,
            	2057, 248,
            	2123, 256,
            	2126, 264,
            	2123, 272,
            	2126, 280,
            	2126, 288,
            	2129, 296,
            8884097, 8, 0, /* 2042: pointer.func */
            8884097, 8, 0, /* 2045: pointer.func */
            8884097, 8, 0, /* 2048: pointer.func */
            8884097, 8, 0, /* 2051: pointer.func */
            8884097, 8, 0, /* 2054: pointer.func */
            8884097, 8, 0, /* 2057: pointer.func */
            8884097, 8, 0, /* 2060: pointer.func */
            8884097, 8, 0, /* 2063: pointer.func */
            8884097, 8, 0, /* 2066: pointer.func */
            8884097, 8, 0, /* 2069: pointer.func */
            8884097, 8, 0, /* 2072: pointer.func */
            8884097, 8, 0, /* 2075: pointer.func */
            8884097, 8, 0, /* 2078: pointer.func */
            8884097, 8, 0, /* 2081: pointer.func */
            8884097, 8, 0, /* 2084: pointer.func */
            8884097, 8, 0, /* 2087: pointer.func */
            8884097, 8, 0, /* 2090: pointer.func */
            8884097, 8, 0, /* 2093: pointer.func */
            8884097, 8, 0, /* 2096: pointer.func */
            8884097, 8, 0, /* 2099: pointer.func */
            8884097, 8, 0, /* 2102: pointer.func */
            8884097, 8, 0, /* 2105: pointer.func */
            8884097, 8, 0, /* 2108: pointer.func */
            8884097, 8, 0, /* 2111: pointer.func */
            8884097, 8, 0, /* 2114: pointer.func */
            8884097, 8, 0, /* 2117: pointer.func */
            8884097, 8, 0, /* 2120: pointer.func */
            8884097, 8, 0, /* 2123: pointer.func */
            8884097, 8, 0, /* 2126: pointer.func */
            8884097, 8, 0, /* 2129: pointer.func */
            0, 24, 1, /* 2132: struct.bignum_st */
            	2137, 0,
            8884099, 8, 2, /* 2137: pointer_to_array_of_pointers_to_stack */
            	183, 0,
            	127, 12,
            0, 24, 1, /* 2144: struct.bignum_st */
            	2149, 0,
            8884099, 8, 2, /* 2149: pointer_to_array_of_pointers_to_stack */
            	183, 0,
            	127, 12,
            1, 8, 1, /* 2156: pointer.struct.ec_extra_data_st */
            	2161, 0,
            0, 40, 5, /* 2161: struct.ec_extra_data_st */
            	2174, 0,
            	20, 8,
            	2179, 16,
            	2182, 24,
            	2182, 32,
            1, 8, 1, /* 2174: pointer.struct.ec_extra_data_st */
            	2161, 0,
            8884097, 8, 0, /* 2179: pointer.func */
            8884097, 8, 0, /* 2182: pointer.func */
            8884097, 8, 0, /* 2185: pointer.func */
            1, 8, 1, /* 2188: pointer.struct.ec_point_st */
            	1949, 0,
            1, 8, 1, /* 2193: pointer.struct.bignum_st */
            	2198, 0,
            0, 24, 1, /* 2198: struct.bignum_st */
            	2203, 0,
            8884099, 8, 2, /* 2203: pointer_to_array_of_pointers_to_stack */
            	183, 0,
            	127, 12,
            1, 8, 1, /* 2210: pointer.struct.ec_extra_data_st */
            	2215, 0,
            0, 40, 5, /* 2215: struct.ec_extra_data_st */
            	2228, 0,
            	20, 8,
            	2179, 16,
            	2182, 24,
            	2182, 32,
            1, 8, 1, /* 2228: pointer.struct.ec_extra_data_st */
            	2215, 0,
            1, 8, 1, /* 2233: pointer.struct.stack_st_X509_ATTRIBUTE */
            	2238, 0,
            0, 32, 2, /* 2238: struct.stack_st_fake_X509_ATTRIBUTE */
            	2245, 8,
            	130, 24,
            8884099, 8, 2, /* 2245: pointer_to_array_of_pointers_to_stack */
            	2252, 0,
            	127, 20,
            0, 8, 1, /* 2252: pointer.X509_ATTRIBUTE */
            	2257, 0,
            0, 0, 1, /* 2257: X509_ATTRIBUTE */
            	2262, 0,
            0, 24, 2, /* 2262: struct.x509_attributes_st */
            	2269, 0,
            	2283, 16,
            1, 8, 1, /* 2269: pointer.struct.asn1_object_st */
            	2274, 0,
            0, 40, 3, /* 2274: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	104, 24,
            0, 8, 3, /* 2283: union.unknown */
            	143, 0,
            	2292, 0,
            	2471, 0,
            1, 8, 1, /* 2292: pointer.struct.stack_st_ASN1_TYPE */
            	2297, 0,
            0, 32, 2, /* 2297: struct.stack_st_fake_ASN1_TYPE */
            	2304, 8,
            	130, 24,
            8884099, 8, 2, /* 2304: pointer_to_array_of_pointers_to_stack */
            	2311, 0,
            	127, 20,
            0, 8, 1, /* 2311: pointer.ASN1_TYPE */
            	2316, 0,
            0, 0, 1, /* 2316: ASN1_TYPE */
            	2321, 0,
            0, 16, 1, /* 2321: struct.asn1_type_st */
            	2326, 8,
            0, 8, 20, /* 2326: union.unknown */
            	143, 0,
            	2369, 0,
            	2379, 0,
            	2393, 0,
            	2398, 0,
            	2403, 0,
            	2408, 0,
            	2413, 0,
            	2418, 0,
            	2423, 0,
            	2428, 0,
            	2433, 0,
            	2438, 0,
            	2443, 0,
            	2448, 0,
            	2453, 0,
            	2458, 0,
            	2369, 0,
            	2369, 0,
            	2463, 0,
            1, 8, 1, /* 2369: pointer.struct.asn1_string_st */
            	2374, 0,
            0, 24, 1, /* 2374: struct.asn1_string_st */
            	122, 8,
            1, 8, 1, /* 2379: pointer.struct.asn1_object_st */
            	2384, 0,
            0, 40, 3, /* 2384: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	104, 24,
            1, 8, 1, /* 2393: pointer.struct.asn1_string_st */
            	2374, 0,
            1, 8, 1, /* 2398: pointer.struct.asn1_string_st */
            	2374, 0,
            1, 8, 1, /* 2403: pointer.struct.asn1_string_st */
            	2374, 0,
            1, 8, 1, /* 2408: pointer.struct.asn1_string_st */
            	2374, 0,
            1, 8, 1, /* 2413: pointer.struct.asn1_string_st */
            	2374, 0,
            1, 8, 1, /* 2418: pointer.struct.asn1_string_st */
            	2374, 0,
            1, 8, 1, /* 2423: pointer.struct.asn1_string_st */
            	2374, 0,
            1, 8, 1, /* 2428: pointer.struct.asn1_string_st */
            	2374, 0,
            1, 8, 1, /* 2433: pointer.struct.asn1_string_st */
            	2374, 0,
            1, 8, 1, /* 2438: pointer.struct.asn1_string_st */
            	2374, 0,
            1, 8, 1, /* 2443: pointer.struct.asn1_string_st */
            	2374, 0,
            1, 8, 1, /* 2448: pointer.struct.asn1_string_st */
            	2374, 0,
            1, 8, 1, /* 2453: pointer.struct.asn1_string_st */
            	2374, 0,
            1, 8, 1, /* 2458: pointer.struct.asn1_string_st */
            	2374, 0,
            1, 8, 1, /* 2463: pointer.struct.ASN1_VALUE_st */
            	2468, 0,
            0, 0, 0, /* 2468: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2471: pointer.struct.asn1_type_st */
            	2476, 0,
            0, 16, 1, /* 2476: struct.asn1_type_st */
            	2481, 8,
            0, 8, 20, /* 2481: union.unknown */
            	143, 0,
            	2524, 0,
            	2269, 0,
            	2534, 0,
            	2539, 0,
            	2544, 0,
            	2549, 0,
            	2554, 0,
            	2559, 0,
            	2564, 0,
            	2569, 0,
            	2574, 0,
            	2579, 0,
            	2584, 0,
            	2589, 0,
            	2594, 0,
            	2599, 0,
            	2524, 0,
            	2524, 0,
            	658, 0,
            1, 8, 1, /* 2524: pointer.struct.asn1_string_st */
            	2529, 0,
            0, 24, 1, /* 2529: struct.asn1_string_st */
            	122, 8,
            1, 8, 1, /* 2534: pointer.struct.asn1_string_st */
            	2529, 0,
            1, 8, 1, /* 2539: pointer.struct.asn1_string_st */
            	2529, 0,
            1, 8, 1, /* 2544: pointer.struct.asn1_string_st */
            	2529, 0,
            1, 8, 1, /* 2549: pointer.struct.asn1_string_st */
            	2529, 0,
            1, 8, 1, /* 2554: pointer.struct.asn1_string_st */
            	2529, 0,
            1, 8, 1, /* 2559: pointer.struct.asn1_string_st */
            	2529, 0,
            1, 8, 1, /* 2564: pointer.struct.asn1_string_st */
            	2529, 0,
            1, 8, 1, /* 2569: pointer.struct.asn1_string_st */
            	2529, 0,
            1, 8, 1, /* 2574: pointer.struct.asn1_string_st */
            	2529, 0,
            1, 8, 1, /* 2579: pointer.struct.asn1_string_st */
            	2529, 0,
            1, 8, 1, /* 2584: pointer.struct.asn1_string_st */
            	2529, 0,
            1, 8, 1, /* 2589: pointer.struct.asn1_string_st */
            	2529, 0,
            1, 8, 1, /* 2594: pointer.struct.asn1_string_st */
            	2529, 0,
            1, 8, 1, /* 2599: pointer.struct.asn1_string_st */
            	2529, 0,
            1, 8, 1, /* 2604: pointer.struct.asn1_string_st */
            	494, 0,
            1, 8, 1, /* 2609: pointer.struct.stack_st_X509_EXTENSION */
            	2614, 0,
            0, 32, 2, /* 2614: struct.stack_st_fake_X509_EXTENSION */
            	2621, 8,
            	130, 24,
            8884099, 8, 2, /* 2621: pointer_to_array_of_pointers_to_stack */
            	2628, 0,
            	127, 20,
            0, 8, 1, /* 2628: pointer.X509_EXTENSION */
            	2633, 0,
            0, 0, 1, /* 2633: X509_EXTENSION */
            	2638, 0,
            0, 24, 2, /* 2638: struct.X509_extension_st */
            	2645, 0,
            	2659, 16,
            1, 8, 1, /* 2645: pointer.struct.asn1_object_st */
            	2650, 0,
            0, 40, 3, /* 2650: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	104, 24,
            1, 8, 1, /* 2659: pointer.struct.asn1_string_st */
            	2664, 0,
            0, 24, 1, /* 2664: struct.asn1_string_st */
            	122, 8,
            0, 24, 1, /* 2669: struct.ASN1_ENCODING_st */
            	122, 0,
            0, 16, 1, /* 2674: struct.crypto_ex_data_st */
            	2679, 0,
            1, 8, 1, /* 2679: pointer.struct.stack_st_void */
            	2684, 0,
            0, 32, 1, /* 2684: struct.stack_st_void */
            	2689, 0,
            0, 32, 2, /* 2689: struct.stack_st */
            	1220, 8,
            	130, 24,
            1, 8, 1, /* 2696: pointer.struct.asn1_string_st */
            	494, 0,
            1, 8, 1, /* 2701: pointer.struct.AUTHORITY_KEYID_st */
            	2706, 0,
            0, 24, 3, /* 2706: struct.AUTHORITY_KEYID_st */
            	2715, 0,
            	2725, 8,
            	2961, 16,
            1, 8, 1, /* 2715: pointer.struct.asn1_string_st */
            	2720, 0,
            0, 24, 1, /* 2720: struct.asn1_string_st */
            	122, 8,
            1, 8, 1, /* 2725: pointer.struct.stack_st_GENERAL_NAME */
            	2730, 0,
            0, 32, 2, /* 2730: struct.stack_st_fake_GENERAL_NAME */
            	2737, 8,
            	130, 24,
            8884099, 8, 2, /* 2737: pointer_to_array_of_pointers_to_stack */
            	2744, 0,
            	127, 20,
            0, 8, 1, /* 2744: pointer.GENERAL_NAME */
            	2749, 0,
            0, 0, 1, /* 2749: GENERAL_NAME */
            	2754, 0,
            0, 16, 1, /* 2754: struct.GENERAL_NAME_st */
            	2759, 8,
            0, 8, 15, /* 2759: union.unknown */
            	143, 0,
            	2792, 0,
            	2901, 0,
            	2901, 0,
            	2818, 0,
            	40, 0,
            	2949, 0,
            	2901, 0,
            	148, 0,
            	2804, 0,
            	148, 0,
            	40, 0,
            	2901, 0,
            	2804, 0,
            	2818, 0,
            1, 8, 1, /* 2792: pointer.struct.otherName_st */
            	2797, 0,
            0, 16, 2, /* 2797: struct.otherName_st */
            	2804, 0,
            	2818, 8,
            1, 8, 1, /* 2804: pointer.struct.asn1_object_st */
            	2809, 0,
            0, 40, 3, /* 2809: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	104, 24,
            1, 8, 1, /* 2818: pointer.struct.asn1_type_st */
            	2823, 0,
            0, 16, 1, /* 2823: struct.asn1_type_st */
            	2828, 8,
            0, 8, 20, /* 2828: union.unknown */
            	143, 0,
            	2871, 0,
            	2804, 0,
            	2876, 0,
            	2881, 0,
            	2886, 0,
            	148, 0,
            	2891, 0,
            	2896, 0,
            	2901, 0,
            	2906, 0,
            	2911, 0,
            	2916, 0,
            	2921, 0,
            	2926, 0,
            	2931, 0,
            	2936, 0,
            	2871, 0,
            	2871, 0,
            	2941, 0,
            1, 8, 1, /* 2871: pointer.struct.asn1_string_st */
            	153, 0,
            1, 8, 1, /* 2876: pointer.struct.asn1_string_st */
            	153, 0,
            1, 8, 1, /* 2881: pointer.struct.asn1_string_st */
            	153, 0,
            1, 8, 1, /* 2886: pointer.struct.asn1_string_st */
            	153, 0,
            1, 8, 1, /* 2891: pointer.struct.asn1_string_st */
            	153, 0,
            1, 8, 1, /* 2896: pointer.struct.asn1_string_st */
            	153, 0,
            1, 8, 1, /* 2901: pointer.struct.asn1_string_st */
            	153, 0,
            1, 8, 1, /* 2906: pointer.struct.asn1_string_st */
            	153, 0,
            1, 8, 1, /* 2911: pointer.struct.asn1_string_st */
            	153, 0,
            1, 8, 1, /* 2916: pointer.struct.asn1_string_st */
            	153, 0,
            1, 8, 1, /* 2921: pointer.struct.asn1_string_st */
            	153, 0,
            1, 8, 1, /* 2926: pointer.struct.asn1_string_st */
            	153, 0,
            1, 8, 1, /* 2931: pointer.struct.asn1_string_st */
            	153, 0,
            1, 8, 1, /* 2936: pointer.struct.asn1_string_st */
            	153, 0,
            1, 8, 1, /* 2941: pointer.struct.ASN1_VALUE_st */
            	2946, 0,
            0, 0, 0, /* 2946: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2949: pointer.struct.EDIPartyName_st */
            	2954, 0,
            0, 16, 2, /* 2954: struct.EDIPartyName_st */
            	2871, 0,
            	2871, 8,
            1, 8, 1, /* 2961: pointer.struct.asn1_string_st */
            	2720, 0,
            1, 8, 1, /* 2966: pointer.struct.X509_POLICY_CACHE_st */
            	2971, 0,
            0, 40, 2, /* 2971: struct.X509_POLICY_CACHE_st */
            	2978, 0,
            	3283, 8,
            1, 8, 1, /* 2978: pointer.struct.X509_POLICY_DATA_st */
            	2983, 0,
            0, 32, 3, /* 2983: struct.X509_POLICY_DATA_st */
            	2992, 8,
            	3006, 16,
            	3259, 24,
            1, 8, 1, /* 2992: pointer.struct.asn1_object_st */
            	2997, 0,
            0, 40, 3, /* 2997: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	104, 24,
            1, 8, 1, /* 3006: pointer.struct.stack_st_POLICYQUALINFO */
            	3011, 0,
            0, 32, 2, /* 3011: struct.stack_st_fake_POLICYQUALINFO */
            	3018, 8,
            	130, 24,
            8884099, 8, 2, /* 3018: pointer_to_array_of_pointers_to_stack */
            	3025, 0,
            	127, 20,
            0, 8, 1, /* 3025: pointer.POLICYQUALINFO */
            	3030, 0,
            0, 0, 1, /* 3030: POLICYQUALINFO */
            	3035, 0,
            0, 16, 2, /* 3035: struct.POLICYQUALINFO_st */
            	3042, 0,
            	3056, 8,
            1, 8, 1, /* 3042: pointer.struct.asn1_object_st */
            	3047, 0,
            0, 40, 3, /* 3047: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	104, 24,
            0, 8, 3, /* 3056: union.unknown */
            	3065, 0,
            	3075, 0,
            	3133, 0,
            1, 8, 1, /* 3065: pointer.struct.asn1_string_st */
            	3070, 0,
            0, 24, 1, /* 3070: struct.asn1_string_st */
            	122, 8,
            1, 8, 1, /* 3075: pointer.struct.USERNOTICE_st */
            	3080, 0,
            0, 16, 2, /* 3080: struct.USERNOTICE_st */
            	3087, 0,
            	3099, 8,
            1, 8, 1, /* 3087: pointer.struct.NOTICEREF_st */
            	3092, 0,
            0, 16, 2, /* 3092: struct.NOTICEREF_st */
            	3099, 0,
            	3104, 8,
            1, 8, 1, /* 3099: pointer.struct.asn1_string_st */
            	3070, 0,
            1, 8, 1, /* 3104: pointer.struct.stack_st_ASN1_INTEGER */
            	3109, 0,
            0, 32, 2, /* 3109: struct.stack_st_fake_ASN1_INTEGER */
            	3116, 8,
            	130, 24,
            8884099, 8, 2, /* 3116: pointer_to_array_of_pointers_to_stack */
            	3123, 0,
            	127, 20,
            0, 8, 1, /* 3123: pointer.ASN1_INTEGER */
            	3128, 0,
            0, 0, 1, /* 3128: ASN1_INTEGER */
            	583, 0,
            1, 8, 1, /* 3133: pointer.struct.asn1_type_st */
            	3138, 0,
            0, 16, 1, /* 3138: struct.asn1_type_st */
            	3143, 8,
            0, 8, 20, /* 3143: union.unknown */
            	143, 0,
            	3099, 0,
            	3042, 0,
            	3186, 0,
            	3191, 0,
            	3196, 0,
            	3201, 0,
            	3206, 0,
            	3211, 0,
            	3065, 0,
            	3216, 0,
            	3221, 0,
            	3226, 0,
            	3231, 0,
            	3236, 0,
            	3241, 0,
            	3246, 0,
            	3099, 0,
            	3099, 0,
            	3251, 0,
            1, 8, 1, /* 3186: pointer.struct.asn1_string_st */
            	3070, 0,
            1, 8, 1, /* 3191: pointer.struct.asn1_string_st */
            	3070, 0,
            1, 8, 1, /* 3196: pointer.struct.asn1_string_st */
            	3070, 0,
            1, 8, 1, /* 3201: pointer.struct.asn1_string_st */
            	3070, 0,
            1, 8, 1, /* 3206: pointer.struct.asn1_string_st */
            	3070, 0,
            1, 8, 1, /* 3211: pointer.struct.asn1_string_st */
            	3070, 0,
            1, 8, 1, /* 3216: pointer.struct.asn1_string_st */
            	3070, 0,
            1, 8, 1, /* 3221: pointer.struct.asn1_string_st */
            	3070, 0,
            1, 8, 1, /* 3226: pointer.struct.asn1_string_st */
            	3070, 0,
            1, 8, 1, /* 3231: pointer.struct.asn1_string_st */
            	3070, 0,
            1, 8, 1, /* 3236: pointer.struct.asn1_string_st */
            	3070, 0,
            1, 8, 1, /* 3241: pointer.struct.asn1_string_st */
            	3070, 0,
            1, 8, 1, /* 3246: pointer.struct.asn1_string_st */
            	3070, 0,
            1, 8, 1, /* 3251: pointer.struct.ASN1_VALUE_st */
            	3256, 0,
            0, 0, 0, /* 3256: struct.ASN1_VALUE_st */
            1, 8, 1, /* 3259: pointer.struct.stack_st_ASN1_OBJECT */
            	3264, 0,
            0, 32, 2, /* 3264: struct.stack_st_fake_ASN1_OBJECT */
            	3271, 8,
            	130, 24,
            8884099, 8, 2, /* 3271: pointer_to_array_of_pointers_to_stack */
            	3278, 0,
            	127, 20,
            0, 8, 1, /* 3278: pointer.ASN1_OBJECT */
            	368, 0,
            1, 8, 1, /* 3283: pointer.struct.stack_st_X509_POLICY_DATA */
            	3288, 0,
            0, 32, 2, /* 3288: struct.stack_st_fake_X509_POLICY_DATA */
            	3295, 8,
            	130, 24,
            8884099, 8, 2, /* 3295: pointer_to_array_of_pointers_to_stack */
            	3302, 0,
            	127, 20,
            0, 8, 1, /* 3302: pointer.X509_POLICY_DATA */
            	3307, 0,
            0, 0, 1, /* 3307: X509_POLICY_DATA */
            	3312, 0,
            0, 32, 3, /* 3312: struct.X509_POLICY_DATA_st */
            	3321, 8,
            	3335, 16,
            	3359, 24,
            1, 8, 1, /* 3321: pointer.struct.asn1_object_st */
            	3326, 0,
            0, 40, 3, /* 3326: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	104, 24,
            1, 8, 1, /* 3335: pointer.struct.stack_st_POLICYQUALINFO */
            	3340, 0,
            0, 32, 2, /* 3340: struct.stack_st_fake_POLICYQUALINFO */
            	3347, 8,
            	130, 24,
            8884099, 8, 2, /* 3347: pointer_to_array_of_pointers_to_stack */
            	3354, 0,
            	127, 20,
            0, 8, 1, /* 3354: pointer.POLICYQUALINFO */
            	3030, 0,
            1, 8, 1, /* 3359: pointer.struct.stack_st_ASN1_OBJECT */
            	3364, 0,
            0, 32, 2, /* 3364: struct.stack_st_fake_ASN1_OBJECT */
            	3371, 8,
            	130, 24,
            8884099, 8, 2, /* 3371: pointer_to_array_of_pointers_to_stack */
            	3378, 0,
            	127, 20,
            0, 8, 1, /* 3378: pointer.ASN1_OBJECT */
            	368, 0,
            1, 8, 1, /* 3383: pointer.struct.stack_st_DIST_POINT */
            	3388, 0,
            0, 32, 2, /* 3388: struct.stack_st_fake_DIST_POINT */
            	3395, 8,
            	130, 24,
            8884099, 8, 2, /* 3395: pointer_to_array_of_pointers_to_stack */
            	3402, 0,
            	127, 20,
            0, 8, 1, /* 3402: pointer.DIST_POINT */
            	3407, 0,
            0, 0, 1, /* 3407: DIST_POINT */
            	3412, 0,
            0, 32, 3, /* 3412: struct.DIST_POINT_st */
            	3421, 0,
            	3512, 8,
            	3440, 16,
            1, 8, 1, /* 3421: pointer.struct.DIST_POINT_NAME_st */
            	3426, 0,
            0, 24, 2, /* 3426: struct.DIST_POINT_NAME_st */
            	3433, 8,
            	3488, 16,
            0, 8, 2, /* 3433: union.unknown */
            	3440, 0,
            	3464, 0,
            1, 8, 1, /* 3440: pointer.struct.stack_st_GENERAL_NAME */
            	3445, 0,
            0, 32, 2, /* 3445: struct.stack_st_fake_GENERAL_NAME */
            	3452, 8,
            	130, 24,
            8884099, 8, 2, /* 3452: pointer_to_array_of_pointers_to_stack */
            	3459, 0,
            	127, 20,
            0, 8, 1, /* 3459: pointer.GENERAL_NAME */
            	2749, 0,
            1, 8, 1, /* 3464: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3469, 0,
            0, 32, 2, /* 3469: struct.stack_st_fake_X509_NAME_ENTRY */
            	3476, 8,
            	130, 24,
            8884099, 8, 2, /* 3476: pointer_to_array_of_pointers_to_stack */
            	3483, 0,
            	127, 20,
            0, 8, 1, /* 3483: pointer.X509_NAME_ENTRY */
            	78, 0,
            1, 8, 1, /* 3488: pointer.struct.X509_name_st */
            	3493, 0,
            0, 40, 3, /* 3493: struct.X509_name_st */
            	3464, 0,
            	3502, 16,
            	122, 24,
            1, 8, 1, /* 3502: pointer.struct.buf_mem_st */
            	3507, 0,
            0, 24, 1, /* 3507: struct.buf_mem_st */
            	143, 8,
            1, 8, 1, /* 3512: pointer.struct.asn1_string_st */
            	3517, 0,
            0, 24, 1, /* 3517: struct.asn1_string_st */
            	122, 8,
            1, 8, 1, /* 3522: pointer.struct.stack_st_GENERAL_NAME */
            	3527, 0,
            0, 32, 2, /* 3527: struct.stack_st_fake_GENERAL_NAME */
            	3534, 8,
            	130, 24,
            8884099, 8, 2, /* 3534: pointer_to_array_of_pointers_to_stack */
            	3541, 0,
            	127, 20,
            0, 8, 1, /* 3541: pointer.GENERAL_NAME */
            	2749, 0,
            1, 8, 1, /* 3546: pointer.struct.NAME_CONSTRAINTS_st */
            	3551, 0,
            0, 16, 2, /* 3551: struct.NAME_CONSTRAINTS_st */
            	3558, 0,
            	3558, 8,
            1, 8, 1, /* 3558: pointer.struct.stack_st_GENERAL_SUBTREE */
            	3563, 0,
            0, 32, 2, /* 3563: struct.stack_st_fake_GENERAL_SUBTREE */
            	3570, 8,
            	130, 24,
            8884099, 8, 2, /* 3570: pointer_to_array_of_pointers_to_stack */
            	3577, 0,
            	127, 20,
            0, 8, 1, /* 3577: pointer.GENERAL_SUBTREE */
            	3582, 0,
            0, 0, 1, /* 3582: GENERAL_SUBTREE */
            	3587, 0,
            0, 24, 3, /* 3587: struct.GENERAL_SUBTREE_st */
            	3596, 0,
            	3728, 8,
            	3728, 16,
            1, 8, 1, /* 3596: pointer.struct.GENERAL_NAME_st */
            	3601, 0,
            0, 16, 1, /* 3601: struct.GENERAL_NAME_st */
            	3606, 8,
            0, 8, 15, /* 3606: union.unknown */
            	143, 0,
            	3639, 0,
            	3758, 0,
            	3758, 0,
            	3665, 0,
            	3798, 0,
            	3846, 0,
            	3758, 0,
            	3743, 0,
            	3651, 0,
            	3743, 0,
            	3798, 0,
            	3758, 0,
            	3651, 0,
            	3665, 0,
            1, 8, 1, /* 3639: pointer.struct.otherName_st */
            	3644, 0,
            0, 16, 2, /* 3644: struct.otherName_st */
            	3651, 0,
            	3665, 8,
            1, 8, 1, /* 3651: pointer.struct.asn1_object_st */
            	3656, 0,
            0, 40, 3, /* 3656: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	104, 24,
            1, 8, 1, /* 3665: pointer.struct.asn1_type_st */
            	3670, 0,
            0, 16, 1, /* 3670: struct.asn1_type_st */
            	3675, 8,
            0, 8, 20, /* 3675: union.unknown */
            	143, 0,
            	3718, 0,
            	3651, 0,
            	3728, 0,
            	3733, 0,
            	3738, 0,
            	3743, 0,
            	3748, 0,
            	3753, 0,
            	3758, 0,
            	3763, 0,
            	3768, 0,
            	3773, 0,
            	3778, 0,
            	3783, 0,
            	3788, 0,
            	3793, 0,
            	3718, 0,
            	3718, 0,
            	3251, 0,
            1, 8, 1, /* 3718: pointer.struct.asn1_string_st */
            	3723, 0,
            0, 24, 1, /* 3723: struct.asn1_string_st */
            	122, 8,
            1, 8, 1, /* 3728: pointer.struct.asn1_string_st */
            	3723, 0,
            1, 8, 1, /* 3733: pointer.struct.asn1_string_st */
            	3723, 0,
            1, 8, 1, /* 3738: pointer.struct.asn1_string_st */
            	3723, 0,
            1, 8, 1, /* 3743: pointer.struct.asn1_string_st */
            	3723, 0,
            1, 8, 1, /* 3748: pointer.struct.asn1_string_st */
            	3723, 0,
            1, 8, 1, /* 3753: pointer.struct.asn1_string_st */
            	3723, 0,
            1, 8, 1, /* 3758: pointer.struct.asn1_string_st */
            	3723, 0,
            1, 8, 1, /* 3763: pointer.struct.asn1_string_st */
            	3723, 0,
            1, 8, 1, /* 3768: pointer.struct.asn1_string_st */
            	3723, 0,
            1, 8, 1, /* 3773: pointer.struct.asn1_string_st */
            	3723, 0,
            1, 8, 1, /* 3778: pointer.struct.asn1_string_st */
            	3723, 0,
            1, 8, 1, /* 3783: pointer.struct.asn1_string_st */
            	3723, 0,
            1, 8, 1, /* 3788: pointer.struct.asn1_string_st */
            	3723, 0,
            1, 8, 1, /* 3793: pointer.struct.asn1_string_st */
            	3723, 0,
            1, 8, 1, /* 3798: pointer.struct.X509_name_st */
            	3803, 0,
            0, 40, 3, /* 3803: struct.X509_name_st */
            	3812, 0,
            	3836, 16,
            	122, 24,
            1, 8, 1, /* 3812: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3817, 0,
            0, 32, 2, /* 3817: struct.stack_st_fake_X509_NAME_ENTRY */
            	3824, 8,
            	130, 24,
            8884099, 8, 2, /* 3824: pointer_to_array_of_pointers_to_stack */
            	3831, 0,
            	127, 20,
            0, 8, 1, /* 3831: pointer.X509_NAME_ENTRY */
            	78, 0,
            1, 8, 1, /* 3836: pointer.struct.buf_mem_st */
            	3841, 0,
            0, 24, 1, /* 3841: struct.buf_mem_st */
            	143, 8,
            1, 8, 1, /* 3846: pointer.struct.EDIPartyName_st */
            	3851, 0,
            0, 16, 2, /* 3851: struct.EDIPartyName_st */
            	3718, 0,
            	3718, 8,
            1, 8, 1, /* 3858: pointer.struct.x509_cert_aux_st */
            	3863, 0,
            0, 40, 5, /* 3863: struct.x509_cert_aux_st */
            	344, 0,
            	344, 8,
            	3876, 16,
            	2696, 24,
            	3881, 32,
            1, 8, 1, /* 3876: pointer.struct.asn1_string_st */
            	494, 0,
            1, 8, 1, /* 3881: pointer.struct.stack_st_X509_ALGOR */
            	3886, 0,
            0, 32, 2, /* 3886: struct.stack_st_fake_X509_ALGOR */
            	3893, 8,
            	130, 24,
            8884099, 8, 2, /* 3893: pointer_to_array_of_pointers_to_stack */
            	3900, 0,
            	127, 20,
            0, 8, 1, /* 3900: pointer.X509_ALGOR */
            	3905, 0,
            0, 0, 1, /* 3905: X509_ALGOR */
            	504, 0,
            1, 8, 1, /* 3910: pointer.struct.X509_crl_st */
            	3915, 0,
            0, 120, 10, /* 3915: struct.X509_crl_st */
            	3938, 0,
            	499, 8,
            	2604, 16,
            	2701, 32,
            	4065, 40,
            	489, 56,
            	489, 64,
            	4178, 96,
            	4219, 104,
            	20, 112,
            1, 8, 1, /* 3938: pointer.struct.X509_crl_info_st */
            	3943, 0,
            0, 80, 8, /* 3943: struct.X509_crl_info_st */
            	489, 0,
            	499, 8,
            	666, 16,
            	726, 24,
            	726, 32,
            	3962, 40,
            	2609, 48,
            	2669, 56,
            1, 8, 1, /* 3962: pointer.struct.stack_st_X509_REVOKED */
            	3967, 0,
            0, 32, 2, /* 3967: struct.stack_st_fake_X509_REVOKED */
            	3974, 8,
            	130, 24,
            8884099, 8, 2, /* 3974: pointer_to_array_of_pointers_to_stack */
            	3981, 0,
            	127, 20,
            0, 8, 1, /* 3981: pointer.X509_REVOKED */
            	3986, 0,
            0, 0, 1, /* 3986: X509_REVOKED */
            	3991, 0,
            0, 40, 4, /* 3991: struct.x509_revoked_st */
            	4002, 0,
            	4012, 8,
            	4017, 16,
            	4041, 24,
            1, 8, 1, /* 4002: pointer.struct.asn1_string_st */
            	4007, 0,
            0, 24, 1, /* 4007: struct.asn1_string_st */
            	122, 8,
            1, 8, 1, /* 4012: pointer.struct.asn1_string_st */
            	4007, 0,
            1, 8, 1, /* 4017: pointer.struct.stack_st_X509_EXTENSION */
            	4022, 0,
            0, 32, 2, /* 4022: struct.stack_st_fake_X509_EXTENSION */
            	4029, 8,
            	130, 24,
            8884099, 8, 2, /* 4029: pointer_to_array_of_pointers_to_stack */
            	4036, 0,
            	127, 20,
            0, 8, 1, /* 4036: pointer.X509_EXTENSION */
            	2633, 0,
            1, 8, 1, /* 4041: pointer.struct.stack_st_GENERAL_NAME */
            	4046, 0,
            0, 32, 2, /* 4046: struct.stack_st_fake_GENERAL_NAME */
            	4053, 8,
            	130, 24,
            8884099, 8, 2, /* 4053: pointer_to_array_of_pointers_to_stack */
            	4060, 0,
            	127, 20,
            0, 8, 1, /* 4060: pointer.GENERAL_NAME */
            	2749, 0,
            1, 8, 1, /* 4065: pointer.struct.ISSUING_DIST_POINT_st */
            	4070, 0,
            0, 32, 2, /* 4070: struct.ISSUING_DIST_POINT_st */
            	4077, 0,
            	4168, 16,
            1, 8, 1, /* 4077: pointer.struct.DIST_POINT_NAME_st */
            	4082, 0,
            0, 24, 2, /* 4082: struct.DIST_POINT_NAME_st */
            	4089, 8,
            	4144, 16,
            0, 8, 2, /* 4089: union.unknown */
            	4096, 0,
            	4120, 0,
            1, 8, 1, /* 4096: pointer.struct.stack_st_GENERAL_NAME */
            	4101, 0,
            0, 32, 2, /* 4101: struct.stack_st_fake_GENERAL_NAME */
            	4108, 8,
            	130, 24,
            8884099, 8, 2, /* 4108: pointer_to_array_of_pointers_to_stack */
            	4115, 0,
            	127, 20,
            0, 8, 1, /* 4115: pointer.GENERAL_NAME */
            	2749, 0,
            1, 8, 1, /* 4120: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4125, 0,
            0, 32, 2, /* 4125: struct.stack_st_fake_X509_NAME_ENTRY */
            	4132, 8,
            	130, 24,
            8884099, 8, 2, /* 4132: pointer_to_array_of_pointers_to_stack */
            	4139, 0,
            	127, 20,
            0, 8, 1, /* 4139: pointer.X509_NAME_ENTRY */
            	78, 0,
            1, 8, 1, /* 4144: pointer.struct.X509_name_st */
            	4149, 0,
            0, 40, 3, /* 4149: struct.X509_name_st */
            	4120, 0,
            	4158, 16,
            	122, 24,
            1, 8, 1, /* 4158: pointer.struct.buf_mem_st */
            	4163, 0,
            0, 24, 1, /* 4163: struct.buf_mem_st */
            	143, 8,
            1, 8, 1, /* 4168: pointer.struct.asn1_string_st */
            	4173, 0,
            0, 24, 1, /* 4173: struct.asn1_string_st */
            	122, 8,
            1, 8, 1, /* 4178: pointer.struct.stack_st_GENERAL_NAMES */
            	4183, 0,
            0, 32, 2, /* 4183: struct.stack_st_fake_GENERAL_NAMES */
            	4190, 8,
            	130, 24,
            8884099, 8, 2, /* 4190: pointer_to_array_of_pointers_to_stack */
            	4197, 0,
            	127, 20,
            0, 8, 1, /* 4197: pointer.GENERAL_NAMES */
            	4202, 0,
            0, 0, 1, /* 4202: GENERAL_NAMES */
            	4207, 0,
            0, 32, 1, /* 4207: struct.stack_st_GENERAL_NAME */
            	4212, 0,
            0, 32, 2, /* 4212: struct.stack_st */
            	1220, 8,
            	130, 24,
            1, 8, 1, /* 4219: pointer.struct.x509_crl_method_st */
            	4224, 0,
            0, 40, 4, /* 4224: struct.x509_crl_method_st */
            	4235, 8,
            	4235, 16,
            	4238, 24,
            	4241, 32,
            8884097, 8, 0, /* 4235: pointer.func */
            8884097, 8, 0, /* 4238: pointer.func */
            8884097, 8, 0, /* 4241: pointer.func */
            1, 8, 1, /* 4244: pointer.struct.evp_pkey_st */
            	4249, 0,
            0, 56, 4, /* 4249: struct.evp_pkey_st */
            	4260, 16,
            	4265, 24,
            	4270, 32,
            	4303, 48,
            1, 8, 1, /* 4260: pointer.struct.evp_pkey_asn1_method_st */
            	781, 0,
            1, 8, 1, /* 4265: pointer.struct.engine_st */
            	882, 0,
            0, 8, 5, /* 4270: union.unknown */
            	143, 0,
            	4283, 0,
            	4288, 0,
            	4293, 0,
            	4298, 0,
            1, 8, 1, /* 4283: pointer.struct.rsa_st */
            	1248, 0,
            1, 8, 1, /* 4288: pointer.struct.dsa_st */
            	1464, 0,
            1, 8, 1, /* 4293: pointer.struct.dh_st */
            	1603, 0,
            1, 8, 1, /* 4298: pointer.struct.ec_key_st */
            	1729, 0,
            1, 8, 1, /* 4303: pointer.struct.stack_st_X509_ATTRIBUTE */
            	4308, 0,
            0, 32, 2, /* 4308: struct.stack_st_fake_X509_ATTRIBUTE */
            	4315, 8,
            	130, 24,
            8884099, 8, 2, /* 4315: pointer_to_array_of_pointers_to_stack */
            	4322, 0,
            	127, 20,
            0, 8, 1, /* 4322: pointer.X509_ATTRIBUTE */
            	2257, 0,
            0, 144, 15, /* 4327: struct.x509_store_st */
            	382, 8,
            	4360, 16,
            	332, 24,
            	329, 32,
            	326, 40,
            	4452, 48,
            	4455, 56,
            	329, 64,
            	4458, 72,
            	4461, 80,
            	4464, 88,
            	323, 96,
            	4467, 104,
            	329, 112,
            	2674, 120,
            1, 8, 1, /* 4360: pointer.struct.stack_st_X509_LOOKUP */
            	4365, 0,
            0, 32, 2, /* 4365: struct.stack_st_fake_X509_LOOKUP */
            	4372, 8,
            	130, 24,
            8884099, 8, 2, /* 4372: pointer_to_array_of_pointers_to_stack */
            	4379, 0,
            	127, 20,
            0, 8, 1, /* 4379: pointer.X509_LOOKUP */
            	4384, 0,
            0, 0, 1, /* 4384: X509_LOOKUP */
            	4389, 0,
            0, 32, 3, /* 4389: struct.x509_lookup_st */
            	4398, 8,
            	143, 16,
            	4447, 24,
            1, 8, 1, /* 4398: pointer.struct.x509_lookup_method_st */
            	4403, 0,
            0, 80, 10, /* 4403: struct.x509_lookup_method_st */
            	5, 0,
            	4426, 8,
            	4429, 16,
            	4426, 24,
            	4426, 32,
            	4432, 40,
            	4435, 48,
            	4438, 56,
            	4441, 64,
            	4444, 72,
            8884097, 8, 0, /* 4426: pointer.func */
            8884097, 8, 0, /* 4429: pointer.func */
            8884097, 8, 0, /* 4432: pointer.func */
            8884097, 8, 0, /* 4435: pointer.func */
            8884097, 8, 0, /* 4438: pointer.func */
            8884097, 8, 0, /* 4441: pointer.func */
            8884097, 8, 0, /* 4444: pointer.func */
            1, 8, 1, /* 4447: pointer.struct.x509_store_st */
            	4327, 0,
            8884097, 8, 0, /* 4452: pointer.func */
            8884097, 8, 0, /* 4455: pointer.func */
            8884097, 8, 0, /* 4458: pointer.func */
            8884097, 8, 0, /* 4461: pointer.func */
            8884097, 8, 0, /* 4464: pointer.func */
            8884097, 8, 0, /* 4467: pointer.func */
            1, 8, 1, /* 4470: pointer.struct.stack_st_X509_LOOKUP */
            	4475, 0,
            0, 32, 2, /* 4475: struct.stack_st_fake_X509_LOOKUP */
            	4482, 8,
            	130, 24,
            8884099, 8, 2, /* 4482: pointer_to_array_of_pointers_to_stack */
            	4489, 0,
            	127, 20,
            0, 8, 1, /* 4489: pointer.X509_LOOKUP */
            	4384, 0,
            1, 8, 1, /* 4494: pointer.struct.stack_st_X509_OBJECT */
            	4499, 0,
            0, 32, 2, /* 4499: struct.stack_st_fake_X509_OBJECT */
            	4506, 8,
            	130, 24,
            8884099, 8, 2, /* 4506: pointer_to_array_of_pointers_to_stack */
            	4513, 0,
            	127, 20,
            0, 8, 1, /* 4513: pointer.X509_OBJECT */
            	406, 0,
            1, 8, 1, /* 4518: pointer.struct.ssl_ctx_st */
            	4523, 0,
            0, 736, 50, /* 4523: struct.ssl_ctx_st */
            	4626, 0,
            	4792, 8,
            	4792, 16,
            	4826, 24,
            	303, 32,
            	4934, 48,
            	4934, 56,
            	269, 80,
            	6096, 88,
            	6099, 96,
            	266, 152,
            	20, 160,
            	263, 168,
            	20, 176,
            	260, 184,
            	6102, 192,
            	6105, 200,
            	4912, 208,
            	6108, 224,
            	6108, 232,
            	6108, 240,
            	6147, 248,
            	6171, 256,
            	6195, 264,
            	6198, 272,
            	6270, 304,
            	6711, 320,
            	20, 328,
            	4903, 376,
            	6714, 384,
            	4864, 392,
            	5731, 408,
            	6717, 416,
            	20, 424,
            	6720, 480,
            	6723, 488,
            	20, 496,
            	211, 504,
            	20, 512,
            	143, 520,
            	6726, 528,
            	6729, 536,
            	191, 552,
            	191, 560,
            	6732, 568,
            	6766, 696,
            	20, 704,
            	168, 712,
            	20, 720,
            	6769, 728,
            1, 8, 1, /* 4626: pointer.struct.ssl_method_st */
            	4631, 0,
            0, 232, 28, /* 4631: struct.ssl_method_st */
            	4690, 8,
            	4693, 16,
            	4693, 24,
            	4690, 32,
            	4690, 40,
            	4696, 48,
            	4696, 56,
            	4699, 64,
            	4690, 72,
            	4690, 80,
            	4690, 88,
            	4702, 96,
            	4705, 104,
            	4708, 112,
            	4690, 120,
            	4711, 128,
            	4714, 136,
            	4717, 144,
            	4720, 152,
            	4723, 160,
            	1151, 168,
            	4726, 176,
            	4729, 184,
            	240, 192,
            	4732, 200,
            	1151, 208,
            	4786, 216,
            	4789, 224,
            8884097, 8, 0, /* 4690: pointer.func */
            8884097, 8, 0, /* 4693: pointer.func */
            8884097, 8, 0, /* 4696: pointer.func */
            8884097, 8, 0, /* 4699: pointer.func */
            8884097, 8, 0, /* 4702: pointer.func */
            8884097, 8, 0, /* 4705: pointer.func */
            8884097, 8, 0, /* 4708: pointer.func */
            8884097, 8, 0, /* 4711: pointer.func */
            8884097, 8, 0, /* 4714: pointer.func */
            8884097, 8, 0, /* 4717: pointer.func */
            8884097, 8, 0, /* 4720: pointer.func */
            8884097, 8, 0, /* 4723: pointer.func */
            8884097, 8, 0, /* 4726: pointer.func */
            8884097, 8, 0, /* 4729: pointer.func */
            1, 8, 1, /* 4732: pointer.struct.ssl3_enc_method */
            	4737, 0,
            0, 112, 11, /* 4737: struct.ssl3_enc_method */
            	4762, 0,
            	4765, 8,
            	4768, 16,
            	4771, 24,
            	4762, 32,
            	4774, 40,
            	4777, 56,
            	5, 64,
            	5, 80,
            	4780, 96,
            	4783, 104,
            8884097, 8, 0, /* 4762: pointer.func */
            8884097, 8, 0, /* 4765: pointer.func */
            8884097, 8, 0, /* 4768: pointer.func */
            8884097, 8, 0, /* 4771: pointer.func */
            8884097, 8, 0, /* 4774: pointer.func */
            8884097, 8, 0, /* 4777: pointer.func */
            8884097, 8, 0, /* 4780: pointer.func */
            8884097, 8, 0, /* 4783: pointer.func */
            8884097, 8, 0, /* 4786: pointer.func */
            8884097, 8, 0, /* 4789: pointer.func */
            1, 8, 1, /* 4792: pointer.struct.stack_st_SSL_CIPHER */
            	4797, 0,
            0, 32, 2, /* 4797: struct.stack_st_fake_SSL_CIPHER */
            	4804, 8,
            	130, 24,
            8884099, 8, 2, /* 4804: pointer_to_array_of_pointers_to_stack */
            	4811, 0,
            	127, 20,
            0, 8, 1, /* 4811: pointer.SSL_CIPHER */
            	4816, 0,
            0, 0, 1, /* 4816: SSL_CIPHER */
            	4821, 0,
            0, 88, 1, /* 4821: struct.ssl_cipher_st */
            	5, 8,
            1, 8, 1, /* 4826: pointer.struct.x509_store_st */
            	4831, 0,
            0, 144, 15, /* 4831: struct.x509_store_st */
            	4494, 8,
            	4470, 16,
            	4864, 24,
            	4900, 32,
            	4903, 40,
            	4906, 48,
            	320, 56,
            	4900, 64,
            	317, 72,
            	314, 80,
            	311, 88,
            	308, 96,
            	4909, 104,
            	4900, 112,
            	4912, 120,
            1, 8, 1, /* 4864: pointer.struct.X509_VERIFY_PARAM_st */
            	4869, 0,
            0, 56, 2, /* 4869: struct.X509_VERIFY_PARAM_st */
            	143, 0,
            	4876, 48,
            1, 8, 1, /* 4876: pointer.struct.stack_st_ASN1_OBJECT */
            	4881, 0,
            0, 32, 2, /* 4881: struct.stack_st_fake_ASN1_OBJECT */
            	4888, 8,
            	130, 24,
            8884099, 8, 2, /* 4888: pointer_to_array_of_pointers_to_stack */
            	4895, 0,
            	127, 20,
            0, 8, 1, /* 4895: pointer.ASN1_OBJECT */
            	368, 0,
            8884097, 8, 0, /* 4900: pointer.func */
            8884097, 8, 0, /* 4903: pointer.func */
            8884097, 8, 0, /* 4906: pointer.func */
            8884097, 8, 0, /* 4909: pointer.func */
            0, 16, 1, /* 4912: struct.crypto_ex_data_st */
            	4917, 0,
            1, 8, 1, /* 4917: pointer.struct.stack_st_void */
            	4922, 0,
            0, 32, 1, /* 4922: struct.stack_st_void */
            	4927, 0,
            0, 32, 2, /* 4927: struct.stack_st */
            	1220, 8,
            	130, 24,
            1, 8, 1, /* 4934: pointer.struct.ssl_session_st */
            	4939, 0,
            0, 352, 14, /* 4939: struct.ssl_session_st */
            	143, 144,
            	143, 152,
            	4970, 168,
            	5853, 176,
            	6086, 224,
            	4792, 240,
            	4912, 248,
            	4934, 264,
            	4934, 272,
            	143, 280,
            	122, 296,
            	122, 312,
            	122, 320,
            	143, 344,
            1, 8, 1, /* 4970: pointer.struct.sess_cert_st */
            	4975, 0,
            0, 248, 5, /* 4975: struct.sess_cert_st */
            	4988, 0,
            	5354, 16,
            	5838, 216,
            	5843, 224,
            	5848, 232,
            1, 8, 1, /* 4988: pointer.struct.stack_st_X509 */
            	4993, 0,
            0, 32, 2, /* 4993: struct.stack_st_fake_X509 */
            	5000, 8,
            	130, 24,
            8884099, 8, 2, /* 5000: pointer_to_array_of_pointers_to_stack */
            	5007, 0,
            	127, 20,
            0, 8, 1, /* 5007: pointer.X509 */
            	5012, 0,
            0, 0, 1, /* 5012: X509 */
            	5017, 0,
            0, 184, 12, /* 5017: struct.x509_st */
            	5044, 0,
            	5084, 8,
            	5159, 16,
            	143, 32,
            	5193, 40,
            	5215, 104,
            	5220, 112,
            	5225, 120,
            	5230, 128,
            	5254, 136,
            	5278, 144,
            	5283, 176,
            1, 8, 1, /* 5044: pointer.struct.x509_cinf_st */
            	5049, 0,
            0, 104, 11, /* 5049: struct.x509_cinf_st */
            	5074, 0,
            	5074, 8,
            	5084, 16,
            	5089, 24,
            	5137, 32,
            	5089, 40,
            	5154, 48,
            	5159, 56,
            	5159, 64,
            	5164, 72,
            	5188, 80,
            1, 8, 1, /* 5074: pointer.struct.asn1_string_st */
            	5079, 0,
            0, 24, 1, /* 5079: struct.asn1_string_st */
            	122, 8,
            1, 8, 1, /* 5084: pointer.struct.X509_algor_st */
            	504, 0,
            1, 8, 1, /* 5089: pointer.struct.X509_name_st */
            	5094, 0,
            0, 40, 3, /* 5094: struct.X509_name_st */
            	5103, 0,
            	5127, 16,
            	122, 24,
            1, 8, 1, /* 5103: pointer.struct.stack_st_X509_NAME_ENTRY */
            	5108, 0,
            0, 32, 2, /* 5108: struct.stack_st_fake_X509_NAME_ENTRY */
            	5115, 8,
            	130, 24,
            8884099, 8, 2, /* 5115: pointer_to_array_of_pointers_to_stack */
            	5122, 0,
            	127, 20,
            0, 8, 1, /* 5122: pointer.X509_NAME_ENTRY */
            	78, 0,
            1, 8, 1, /* 5127: pointer.struct.buf_mem_st */
            	5132, 0,
            0, 24, 1, /* 5132: struct.buf_mem_st */
            	143, 8,
            1, 8, 1, /* 5137: pointer.struct.X509_val_st */
            	5142, 0,
            0, 16, 2, /* 5142: struct.X509_val_st */
            	5149, 0,
            	5149, 8,
            1, 8, 1, /* 5149: pointer.struct.asn1_string_st */
            	5079, 0,
            1, 8, 1, /* 5154: pointer.struct.X509_pubkey_st */
            	736, 0,
            1, 8, 1, /* 5159: pointer.struct.asn1_string_st */
            	5079, 0,
            1, 8, 1, /* 5164: pointer.struct.stack_st_X509_EXTENSION */
            	5169, 0,
            0, 32, 2, /* 5169: struct.stack_st_fake_X509_EXTENSION */
            	5176, 8,
            	130, 24,
            8884099, 8, 2, /* 5176: pointer_to_array_of_pointers_to_stack */
            	5183, 0,
            	127, 20,
            0, 8, 1, /* 5183: pointer.X509_EXTENSION */
            	2633, 0,
            0, 24, 1, /* 5188: struct.ASN1_ENCODING_st */
            	122, 0,
            0, 16, 1, /* 5193: struct.crypto_ex_data_st */
            	5198, 0,
            1, 8, 1, /* 5198: pointer.struct.stack_st_void */
            	5203, 0,
            0, 32, 1, /* 5203: struct.stack_st_void */
            	5208, 0,
            0, 32, 2, /* 5208: struct.stack_st */
            	1220, 8,
            	130, 24,
            1, 8, 1, /* 5215: pointer.struct.asn1_string_st */
            	5079, 0,
            1, 8, 1, /* 5220: pointer.struct.AUTHORITY_KEYID_st */
            	2706, 0,
            1, 8, 1, /* 5225: pointer.struct.X509_POLICY_CACHE_st */
            	2971, 0,
            1, 8, 1, /* 5230: pointer.struct.stack_st_DIST_POINT */
            	5235, 0,
            0, 32, 2, /* 5235: struct.stack_st_fake_DIST_POINT */
            	5242, 8,
            	130, 24,
            8884099, 8, 2, /* 5242: pointer_to_array_of_pointers_to_stack */
            	5249, 0,
            	127, 20,
            0, 8, 1, /* 5249: pointer.DIST_POINT */
            	3407, 0,
            1, 8, 1, /* 5254: pointer.struct.stack_st_GENERAL_NAME */
            	5259, 0,
            0, 32, 2, /* 5259: struct.stack_st_fake_GENERAL_NAME */
            	5266, 8,
            	130, 24,
            8884099, 8, 2, /* 5266: pointer_to_array_of_pointers_to_stack */
            	5273, 0,
            	127, 20,
            0, 8, 1, /* 5273: pointer.GENERAL_NAME */
            	2749, 0,
            1, 8, 1, /* 5278: pointer.struct.NAME_CONSTRAINTS_st */
            	3551, 0,
            1, 8, 1, /* 5283: pointer.struct.x509_cert_aux_st */
            	5288, 0,
            0, 40, 5, /* 5288: struct.x509_cert_aux_st */
            	5301, 0,
            	5301, 8,
            	5325, 16,
            	5215, 24,
            	5330, 32,
            1, 8, 1, /* 5301: pointer.struct.stack_st_ASN1_OBJECT */
            	5306, 0,
            0, 32, 2, /* 5306: struct.stack_st_fake_ASN1_OBJECT */
            	5313, 8,
            	130, 24,
            8884099, 8, 2, /* 5313: pointer_to_array_of_pointers_to_stack */
            	5320, 0,
            	127, 20,
            0, 8, 1, /* 5320: pointer.ASN1_OBJECT */
            	368, 0,
            1, 8, 1, /* 5325: pointer.struct.asn1_string_st */
            	5079, 0,
            1, 8, 1, /* 5330: pointer.struct.stack_st_X509_ALGOR */
            	5335, 0,
            0, 32, 2, /* 5335: struct.stack_st_fake_X509_ALGOR */
            	5342, 8,
            	130, 24,
            8884099, 8, 2, /* 5342: pointer_to_array_of_pointers_to_stack */
            	5349, 0,
            	127, 20,
            0, 8, 1, /* 5349: pointer.X509_ALGOR */
            	3905, 0,
            1, 8, 1, /* 5354: pointer.struct.cert_pkey_st */
            	5359, 0,
            0, 24, 3, /* 5359: struct.cert_pkey_st */
            	5368, 0,
            	5710, 8,
            	5793, 16,
            1, 8, 1, /* 5368: pointer.struct.x509_st */
            	5373, 0,
            0, 184, 12, /* 5373: struct.x509_st */
            	5400, 0,
            	5440, 8,
            	5515, 16,
            	143, 32,
            	5549, 40,
            	5571, 104,
            	5576, 112,
            	5581, 120,
            	5586, 128,
            	5610, 136,
            	5634, 144,
            	5639, 176,
            1, 8, 1, /* 5400: pointer.struct.x509_cinf_st */
            	5405, 0,
            0, 104, 11, /* 5405: struct.x509_cinf_st */
            	5430, 0,
            	5430, 8,
            	5440, 16,
            	5445, 24,
            	5493, 32,
            	5445, 40,
            	5510, 48,
            	5515, 56,
            	5515, 64,
            	5520, 72,
            	5544, 80,
            1, 8, 1, /* 5430: pointer.struct.asn1_string_st */
            	5435, 0,
            0, 24, 1, /* 5435: struct.asn1_string_st */
            	122, 8,
            1, 8, 1, /* 5440: pointer.struct.X509_algor_st */
            	504, 0,
            1, 8, 1, /* 5445: pointer.struct.X509_name_st */
            	5450, 0,
            0, 40, 3, /* 5450: struct.X509_name_st */
            	5459, 0,
            	5483, 16,
            	122, 24,
            1, 8, 1, /* 5459: pointer.struct.stack_st_X509_NAME_ENTRY */
            	5464, 0,
            0, 32, 2, /* 5464: struct.stack_st_fake_X509_NAME_ENTRY */
            	5471, 8,
            	130, 24,
            8884099, 8, 2, /* 5471: pointer_to_array_of_pointers_to_stack */
            	5478, 0,
            	127, 20,
            0, 8, 1, /* 5478: pointer.X509_NAME_ENTRY */
            	78, 0,
            1, 8, 1, /* 5483: pointer.struct.buf_mem_st */
            	5488, 0,
            0, 24, 1, /* 5488: struct.buf_mem_st */
            	143, 8,
            1, 8, 1, /* 5493: pointer.struct.X509_val_st */
            	5498, 0,
            0, 16, 2, /* 5498: struct.X509_val_st */
            	5505, 0,
            	5505, 8,
            1, 8, 1, /* 5505: pointer.struct.asn1_string_st */
            	5435, 0,
            1, 8, 1, /* 5510: pointer.struct.X509_pubkey_st */
            	736, 0,
            1, 8, 1, /* 5515: pointer.struct.asn1_string_st */
            	5435, 0,
            1, 8, 1, /* 5520: pointer.struct.stack_st_X509_EXTENSION */
            	5525, 0,
            0, 32, 2, /* 5525: struct.stack_st_fake_X509_EXTENSION */
            	5532, 8,
            	130, 24,
            8884099, 8, 2, /* 5532: pointer_to_array_of_pointers_to_stack */
            	5539, 0,
            	127, 20,
            0, 8, 1, /* 5539: pointer.X509_EXTENSION */
            	2633, 0,
            0, 24, 1, /* 5544: struct.ASN1_ENCODING_st */
            	122, 0,
            0, 16, 1, /* 5549: struct.crypto_ex_data_st */
            	5554, 0,
            1, 8, 1, /* 5554: pointer.struct.stack_st_void */
            	5559, 0,
            0, 32, 1, /* 5559: struct.stack_st_void */
            	5564, 0,
            0, 32, 2, /* 5564: struct.stack_st */
            	1220, 8,
            	130, 24,
            1, 8, 1, /* 5571: pointer.struct.asn1_string_st */
            	5435, 0,
            1, 8, 1, /* 5576: pointer.struct.AUTHORITY_KEYID_st */
            	2706, 0,
            1, 8, 1, /* 5581: pointer.struct.X509_POLICY_CACHE_st */
            	2971, 0,
            1, 8, 1, /* 5586: pointer.struct.stack_st_DIST_POINT */
            	5591, 0,
            0, 32, 2, /* 5591: struct.stack_st_fake_DIST_POINT */
            	5598, 8,
            	130, 24,
            8884099, 8, 2, /* 5598: pointer_to_array_of_pointers_to_stack */
            	5605, 0,
            	127, 20,
            0, 8, 1, /* 5605: pointer.DIST_POINT */
            	3407, 0,
            1, 8, 1, /* 5610: pointer.struct.stack_st_GENERAL_NAME */
            	5615, 0,
            0, 32, 2, /* 5615: struct.stack_st_fake_GENERAL_NAME */
            	5622, 8,
            	130, 24,
            8884099, 8, 2, /* 5622: pointer_to_array_of_pointers_to_stack */
            	5629, 0,
            	127, 20,
            0, 8, 1, /* 5629: pointer.GENERAL_NAME */
            	2749, 0,
            1, 8, 1, /* 5634: pointer.struct.NAME_CONSTRAINTS_st */
            	3551, 0,
            1, 8, 1, /* 5639: pointer.struct.x509_cert_aux_st */
            	5644, 0,
            0, 40, 5, /* 5644: struct.x509_cert_aux_st */
            	5657, 0,
            	5657, 8,
            	5681, 16,
            	5571, 24,
            	5686, 32,
            1, 8, 1, /* 5657: pointer.struct.stack_st_ASN1_OBJECT */
            	5662, 0,
            0, 32, 2, /* 5662: struct.stack_st_fake_ASN1_OBJECT */
            	5669, 8,
            	130, 24,
            8884099, 8, 2, /* 5669: pointer_to_array_of_pointers_to_stack */
            	5676, 0,
            	127, 20,
            0, 8, 1, /* 5676: pointer.ASN1_OBJECT */
            	368, 0,
            1, 8, 1, /* 5681: pointer.struct.asn1_string_st */
            	5435, 0,
            1, 8, 1, /* 5686: pointer.struct.stack_st_X509_ALGOR */
            	5691, 0,
            0, 32, 2, /* 5691: struct.stack_st_fake_X509_ALGOR */
            	5698, 8,
            	130, 24,
            8884099, 8, 2, /* 5698: pointer_to_array_of_pointers_to_stack */
            	5705, 0,
            	127, 20,
            0, 8, 1, /* 5705: pointer.X509_ALGOR */
            	3905, 0,
            1, 8, 1, /* 5710: pointer.struct.evp_pkey_st */
            	5715, 0,
            0, 56, 4, /* 5715: struct.evp_pkey_st */
            	5726, 16,
            	5731, 24,
            	5736, 32,
            	5769, 48,
            1, 8, 1, /* 5726: pointer.struct.evp_pkey_asn1_method_st */
            	781, 0,
            1, 8, 1, /* 5731: pointer.struct.engine_st */
            	882, 0,
            0, 8, 5, /* 5736: union.unknown */
            	143, 0,
            	5749, 0,
            	5754, 0,
            	5759, 0,
            	5764, 0,
            1, 8, 1, /* 5749: pointer.struct.rsa_st */
            	1248, 0,
            1, 8, 1, /* 5754: pointer.struct.dsa_st */
            	1464, 0,
            1, 8, 1, /* 5759: pointer.struct.dh_st */
            	1603, 0,
            1, 8, 1, /* 5764: pointer.struct.ec_key_st */
            	1729, 0,
            1, 8, 1, /* 5769: pointer.struct.stack_st_X509_ATTRIBUTE */
            	5774, 0,
            0, 32, 2, /* 5774: struct.stack_st_fake_X509_ATTRIBUTE */
            	5781, 8,
            	130, 24,
            8884099, 8, 2, /* 5781: pointer_to_array_of_pointers_to_stack */
            	5788, 0,
            	127, 20,
            0, 8, 1, /* 5788: pointer.X509_ATTRIBUTE */
            	2257, 0,
            1, 8, 1, /* 5793: pointer.struct.env_md_st */
            	5798, 0,
            0, 120, 8, /* 5798: struct.env_md_st */
            	5817, 24,
            	5820, 32,
            	5823, 40,
            	5826, 48,
            	5817, 56,
            	5829, 64,
            	5832, 72,
            	5835, 112,
            8884097, 8, 0, /* 5817: pointer.func */
            8884097, 8, 0, /* 5820: pointer.func */
            8884097, 8, 0, /* 5823: pointer.func */
            8884097, 8, 0, /* 5826: pointer.func */
            8884097, 8, 0, /* 5829: pointer.func */
            8884097, 8, 0, /* 5832: pointer.func */
            8884097, 8, 0, /* 5835: pointer.func */
            1, 8, 1, /* 5838: pointer.struct.rsa_st */
            	1248, 0,
            1, 8, 1, /* 5843: pointer.struct.dh_st */
            	1603, 0,
            1, 8, 1, /* 5848: pointer.struct.ec_key_st */
            	1729, 0,
            1, 8, 1, /* 5853: pointer.struct.x509_st */
            	5858, 0,
            0, 184, 12, /* 5858: struct.x509_st */
            	5885, 0,
            	5925, 8,
            	6000, 16,
            	143, 32,
            	4912, 40,
            	6034, 104,
            	5576, 112,
            	5581, 120,
            	5586, 128,
            	5610, 136,
            	5634, 144,
            	6039, 176,
            1, 8, 1, /* 5885: pointer.struct.x509_cinf_st */
            	5890, 0,
            0, 104, 11, /* 5890: struct.x509_cinf_st */
            	5915, 0,
            	5915, 8,
            	5925, 16,
            	5930, 24,
            	5978, 32,
            	5930, 40,
            	5995, 48,
            	6000, 56,
            	6000, 64,
            	6005, 72,
            	6029, 80,
            1, 8, 1, /* 5915: pointer.struct.asn1_string_st */
            	5920, 0,
            0, 24, 1, /* 5920: struct.asn1_string_st */
            	122, 8,
            1, 8, 1, /* 5925: pointer.struct.X509_algor_st */
            	504, 0,
            1, 8, 1, /* 5930: pointer.struct.X509_name_st */
            	5935, 0,
            0, 40, 3, /* 5935: struct.X509_name_st */
            	5944, 0,
            	5968, 16,
            	122, 24,
            1, 8, 1, /* 5944: pointer.struct.stack_st_X509_NAME_ENTRY */
            	5949, 0,
            0, 32, 2, /* 5949: struct.stack_st_fake_X509_NAME_ENTRY */
            	5956, 8,
            	130, 24,
            8884099, 8, 2, /* 5956: pointer_to_array_of_pointers_to_stack */
            	5963, 0,
            	127, 20,
            0, 8, 1, /* 5963: pointer.X509_NAME_ENTRY */
            	78, 0,
            1, 8, 1, /* 5968: pointer.struct.buf_mem_st */
            	5973, 0,
            0, 24, 1, /* 5973: struct.buf_mem_st */
            	143, 8,
            1, 8, 1, /* 5978: pointer.struct.X509_val_st */
            	5983, 0,
            0, 16, 2, /* 5983: struct.X509_val_st */
            	5990, 0,
            	5990, 8,
            1, 8, 1, /* 5990: pointer.struct.asn1_string_st */
            	5920, 0,
            1, 8, 1, /* 5995: pointer.struct.X509_pubkey_st */
            	736, 0,
            1, 8, 1, /* 6000: pointer.struct.asn1_string_st */
            	5920, 0,
            1, 8, 1, /* 6005: pointer.struct.stack_st_X509_EXTENSION */
            	6010, 0,
            0, 32, 2, /* 6010: struct.stack_st_fake_X509_EXTENSION */
            	6017, 8,
            	130, 24,
            8884099, 8, 2, /* 6017: pointer_to_array_of_pointers_to_stack */
            	6024, 0,
            	127, 20,
            0, 8, 1, /* 6024: pointer.X509_EXTENSION */
            	2633, 0,
            0, 24, 1, /* 6029: struct.ASN1_ENCODING_st */
            	122, 0,
            1, 8, 1, /* 6034: pointer.struct.asn1_string_st */
            	5920, 0,
            1, 8, 1, /* 6039: pointer.struct.x509_cert_aux_st */
            	6044, 0,
            0, 40, 5, /* 6044: struct.x509_cert_aux_st */
            	4876, 0,
            	4876, 8,
            	6057, 16,
            	6034, 24,
            	6062, 32,
            1, 8, 1, /* 6057: pointer.struct.asn1_string_st */
            	5920, 0,
            1, 8, 1, /* 6062: pointer.struct.stack_st_X509_ALGOR */
            	6067, 0,
            0, 32, 2, /* 6067: struct.stack_st_fake_X509_ALGOR */
            	6074, 8,
            	130, 24,
            8884099, 8, 2, /* 6074: pointer_to_array_of_pointers_to_stack */
            	6081, 0,
            	127, 20,
            0, 8, 1, /* 6081: pointer.X509_ALGOR */
            	3905, 0,
            1, 8, 1, /* 6086: pointer.struct.ssl_cipher_st */
            	6091, 0,
            0, 88, 1, /* 6091: struct.ssl_cipher_st */
            	5, 8,
            8884097, 8, 0, /* 6096: pointer.func */
            8884097, 8, 0, /* 6099: pointer.func */
            8884097, 8, 0, /* 6102: pointer.func */
            8884097, 8, 0, /* 6105: pointer.func */
            1, 8, 1, /* 6108: pointer.struct.env_md_st */
            	6113, 0,
            0, 120, 8, /* 6113: struct.env_md_st */
            	6132, 24,
            	6135, 32,
            	6138, 40,
            	6141, 48,
            	6132, 56,
            	5829, 64,
            	5832, 72,
            	6144, 112,
            8884097, 8, 0, /* 6132: pointer.func */
            8884097, 8, 0, /* 6135: pointer.func */
            8884097, 8, 0, /* 6138: pointer.func */
            8884097, 8, 0, /* 6141: pointer.func */
            8884097, 8, 0, /* 6144: pointer.func */
            1, 8, 1, /* 6147: pointer.struct.stack_st_X509 */
            	6152, 0,
            0, 32, 2, /* 6152: struct.stack_st_fake_X509 */
            	6159, 8,
            	130, 24,
            8884099, 8, 2, /* 6159: pointer_to_array_of_pointers_to_stack */
            	6166, 0,
            	127, 20,
            0, 8, 1, /* 6166: pointer.X509 */
            	5012, 0,
            1, 8, 1, /* 6171: pointer.struct.stack_st_SSL_COMP */
            	6176, 0,
            0, 32, 2, /* 6176: struct.stack_st_fake_SSL_COMP */
            	6183, 8,
            	130, 24,
            8884099, 8, 2, /* 6183: pointer_to_array_of_pointers_to_stack */
            	6190, 0,
            	127, 20,
            0, 8, 1, /* 6190: pointer.SSL_COMP */
            	243, 0,
            8884097, 8, 0, /* 6195: pointer.func */
            1, 8, 1, /* 6198: pointer.struct.stack_st_X509_NAME */
            	6203, 0,
            0, 32, 2, /* 6203: struct.stack_st_fake_X509_NAME */
            	6210, 8,
            	130, 24,
            8884099, 8, 2, /* 6210: pointer_to_array_of_pointers_to_stack */
            	6217, 0,
            	127, 20,
            0, 8, 1, /* 6217: pointer.X509_NAME */
            	6222, 0,
            0, 0, 1, /* 6222: X509_NAME */
            	6227, 0,
            0, 40, 3, /* 6227: struct.X509_name_st */
            	6236, 0,
            	6260, 16,
            	122, 24,
            1, 8, 1, /* 6236: pointer.struct.stack_st_X509_NAME_ENTRY */
            	6241, 0,
            0, 32, 2, /* 6241: struct.stack_st_fake_X509_NAME_ENTRY */
            	6248, 8,
            	130, 24,
            8884099, 8, 2, /* 6248: pointer_to_array_of_pointers_to_stack */
            	6255, 0,
            	127, 20,
            0, 8, 1, /* 6255: pointer.X509_NAME_ENTRY */
            	78, 0,
            1, 8, 1, /* 6260: pointer.struct.buf_mem_st */
            	6265, 0,
            0, 24, 1, /* 6265: struct.buf_mem_st */
            	143, 8,
            1, 8, 1, /* 6270: pointer.struct.cert_st */
            	6275, 0,
            0, 296, 7, /* 6275: struct.cert_st */
            	6292, 0,
            	6692, 48,
            	6697, 56,
            	6700, 64,
            	6705, 72,
            	5848, 80,
            	6708, 88,
            1, 8, 1, /* 6292: pointer.struct.cert_pkey_st */
            	6297, 0,
            0, 24, 3, /* 6297: struct.cert_pkey_st */
            	6306, 0,
            	6585, 8,
            	6653, 16,
            1, 8, 1, /* 6306: pointer.struct.x509_st */
            	6311, 0,
            0, 184, 12, /* 6311: struct.x509_st */
            	6338, 0,
            	6378, 8,
            	6453, 16,
            	143, 32,
            	6487, 40,
            	6509, 104,
            	5576, 112,
            	5581, 120,
            	5586, 128,
            	5610, 136,
            	5634, 144,
            	6514, 176,
            1, 8, 1, /* 6338: pointer.struct.x509_cinf_st */
            	6343, 0,
            0, 104, 11, /* 6343: struct.x509_cinf_st */
            	6368, 0,
            	6368, 8,
            	6378, 16,
            	6383, 24,
            	6431, 32,
            	6383, 40,
            	6448, 48,
            	6453, 56,
            	6453, 64,
            	6458, 72,
            	6482, 80,
            1, 8, 1, /* 6368: pointer.struct.asn1_string_st */
            	6373, 0,
            0, 24, 1, /* 6373: struct.asn1_string_st */
            	122, 8,
            1, 8, 1, /* 6378: pointer.struct.X509_algor_st */
            	504, 0,
            1, 8, 1, /* 6383: pointer.struct.X509_name_st */
            	6388, 0,
            0, 40, 3, /* 6388: struct.X509_name_st */
            	6397, 0,
            	6421, 16,
            	122, 24,
            1, 8, 1, /* 6397: pointer.struct.stack_st_X509_NAME_ENTRY */
            	6402, 0,
            0, 32, 2, /* 6402: struct.stack_st_fake_X509_NAME_ENTRY */
            	6409, 8,
            	130, 24,
            8884099, 8, 2, /* 6409: pointer_to_array_of_pointers_to_stack */
            	6416, 0,
            	127, 20,
            0, 8, 1, /* 6416: pointer.X509_NAME_ENTRY */
            	78, 0,
            1, 8, 1, /* 6421: pointer.struct.buf_mem_st */
            	6426, 0,
            0, 24, 1, /* 6426: struct.buf_mem_st */
            	143, 8,
            1, 8, 1, /* 6431: pointer.struct.X509_val_st */
            	6436, 0,
            0, 16, 2, /* 6436: struct.X509_val_st */
            	6443, 0,
            	6443, 8,
            1, 8, 1, /* 6443: pointer.struct.asn1_string_st */
            	6373, 0,
            1, 8, 1, /* 6448: pointer.struct.X509_pubkey_st */
            	736, 0,
            1, 8, 1, /* 6453: pointer.struct.asn1_string_st */
            	6373, 0,
            1, 8, 1, /* 6458: pointer.struct.stack_st_X509_EXTENSION */
            	6463, 0,
            0, 32, 2, /* 6463: struct.stack_st_fake_X509_EXTENSION */
            	6470, 8,
            	130, 24,
            8884099, 8, 2, /* 6470: pointer_to_array_of_pointers_to_stack */
            	6477, 0,
            	127, 20,
            0, 8, 1, /* 6477: pointer.X509_EXTENSION */
            	2633, 0,
            0, 24, 1, /* 6482: struct.ASN1_ENCODING_st */
            	122, 0,
            0, 16, 1, /* 6487: struct.crypto_ex_data_st */
            	6492, 0,
            1, 8, 1, /* 6492: pointer.struct.stack_st_void */
            	6497, 0,
            0, 32, 1, /* 6497: struct.stack_st_void */
            	6502, 0,
            0, 32, 2, /* 6502: struct.stack_st */
            	1220, 8,
            	130, 24,
            1, 8, 1, /* 6509: pointer.struct.asn1_string_st */
            	6373, 0,
            1, 8, 1, /* 6514: pointer.struct.x509_cert_aux_st */
            	6519, 0,
            0, 40, 5, /* 6519: struct.x509_cert_aux_st */
            	6532, 0,
            	6532, 8,
            	6556, 16,
            	6509, 24,
            	6561, 32,
            1, 8, 1, /* 6532: pointer.struct.stack_st_ASN1_OBJECT */
            	6537, 0,
            0, 32, 2, /* 6537: struct.stack_st_fake_ASN1_OBJECT */
            	6544, 8,
            	130, 24,
            8884099, 8, 2, /* 6544: pointer_to_array_of_pointers_to_stack */
            	6551, 0,
            	127, 20,
            0, 8, 1, /* 6551: pointer.ASN1_OBJECT */
            	368, 0,
            1, 8, 1, /* 6556: pointer.struct.asn1_string_st */
            	6373, 0,
            1, 8, 1, /* 6561: pointer.struct.stack_st_X509_ALGOR */
            	6566, 0,
            0, 32, 2, /* 6566: struct.stack_st_fake_X509_ALGOR */
            	6573, 8,
            	130, 24,
            8884099, 8, 2, /* 6573: pointer_to_array_of_pointers_to_stack */
            	6580, 0,
            	127, 20,
            0, 8, 1, /* 6580: pointer.X509_ALGOR */
            	3905, 0,
            1, 8, 1, /* 6585: pointer.struct.evp_pkey_st */
            	6590, 0,
            0, 56, 4, /* 6590: struct.evp_pkey_st */
            	5726, 16,
            	5731, 24,
            	6601, 32,
            	6629, 48,
            0, 8, 5, /* 6601: union.unknown */
            	143, 0,
            	6614, 0,
            	6619, 0,
            	6624, 0,
            	5764, 0,
            1, 8, 1, /* 6614: pointer.struct.rsa_st */
            	1248, 0,
            1, 8, 1, /* 6619: pointer.struct.dsa_st */
            	1464, 0,
            1, 8, 1, /* 6624: pointer.struct.dh_st */
            	1603, 0,
            1, 8, 1, /* 6629: pointer.struct.stack_st_X509_ATTRIBUTE */
            	6634, 0,
            0, 32, 2, /* 6634: struct.stack_st_fake_X509_ATTRIBUTE */
            	6641, 8,
            	130, 24,
            8884099, 8, 2, /* 6641: pointer_to_array_of_pointers_to_stack */
            	6648, 0,
            	127, 20,
            0, 8, 1, /* 6648: pointer.X509_ATTRIBUTE */
            	2257, 0,
            1, 8, 1, /* 6653: pointer.struct.env_md_st */
            	6658, 0,
            0, 120, 8, /* 6658: struct.env_md_st */
            	6677, 24,
            	6680, 32,
            	6683, 40,
            	6686, 48,
            	6677, 56,
            	5829, 64,
            	5832, 72,
            	6689, 112,
            8884097, 8, 0, /* 6677: pointer.func */
            8884097, 8, 0, /* 6680: pointer.func */
            8884097, 8, 0, /* 6683: pointer.func */
            8884097, 8, 0, /* 6686: pointer.func */
            8884097, 8, 0, /* 6689: pointer.func */
            1, 8, 1, /* 6692: pointer.struct.rsa_st */
            	1248, 0,
            8884097, 8, 0, /* 6697: pointer.func */
            1, 8, 1, /* 6700: pointer.struct.dh_st */
            	1603, 0,
            8884097, 8, 0, /* 6705: pointer.func */
            8884097, 8, 0, /* 6708: pointer.func */
            8884097, 8, 0, /* 6711: pointer.func */
            8884097, 8, 0, /* 6714: pointer.func */
            8884097, 8, 0, /* 6717: pointer.func */
            8884097, 8, 0, /* 6720: pointer.func */
            8884097, 8, 0, /* 6723: pointer.func */
            8884097, 8, 0, /* 6726: pointer.func */
            8884097, 8, 0, /* 6729: pointer.func */
            0, 128, 14, /* 6732: struct.srp_ctx_st */
            	20, 0,
            	6717, 8,
            	6723, 16,
            	6763, 24,
            	143, 32,
            	186, 40,
            	186, 48,
            	186, 56,
            	186, 64,
            	186, 72,
            	186, 80,
            	186, 88,
            	186, 96,
            	143, 104,
            8884097, 8, 0, /* 6763: pointer.func */
            8884097, 8, 0, /* 6766: pointer.func */
            1, 8, 1, /* 6769: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	6774, 0,
            0, 32, 2, /* 6774: struct.stack_st_fake_SRTP_PROTECTION_PROFILE */
            	6781, 8,
            	130, 24,
            8884099, 8, 2, /* 6781: pointer_to_array_of_pointers_to_stack */
            	6788, 0,
            	127, 20,
            0, 8, 1, /* 6788: pointer.SRTP_PROTECTION_PROFILE */
            	163, 0,
            1, 8, 1, /* 6793: pointer.struct.tls_session_ticket_ext_st */
            	15, 0,
            1, 8, 1, /* 6798: pointer.struct.srtp_protection_profile_st */
            	10, 0,
            1, 8, 1, /* 6803: pointer.struct.ssl_cipher_st */
            	0, 0,
            1, 8, 1, /* 6808: pointer.struct.ssl_st */
            	6813, 0,
            0, 808, 51, /* 6813: struct.ssl_st */
            	4626, 8,
            	6918, 16,
            	6918, 24,
            	6918, 32,
            	4690, 48,
            	5968, 80,
            	20, 88,
            	122, 104,
            	6992, 120,
            	7018, 128,
            	7391, 136,
            	6711, 152,
            	20, 160,
            	4864, 176,
            	4792, 184,
            	4792, 192,
            	7461, 208,
            	7065, 216,
            	7477, 224,
            	7461, 232,
            	7065, 240,
            	7477, 248,
            	6270, 256,
            	7489, 304,
            	6714, 312,
            	4903, 328,
            	6195, 336,
            	6726, 352,
            	6729, 360,
            	4518, 368,
            	4912, 392,
            	6198, 408,
            	7494, 464,
            	20, 472,
            	143, 480,
            	7497, 504,
            	7521, 512,
            	122, 520,
            	122, 544,
            	122, 560,
            	20, 568,
            	6793, 584,
            	7545, 592,
            	20, 600,
            	7548, 608,
            	20, 616,
            	4518, 624,
            	122, 632,
            	6769, 648,
            	6798, 656,
            	6732, 680,
            1, 8, 1, /* 6918: pointer.struct.bio_st */
            	6923, 0,
            0, 112, 7, /* 6923: struct.bio_st */
            	6940, 0,
            	6984, 8,
            	143, 16,
            	20, 48,
            	6987, 56,
            	6987, 64,
            	4912, 96,
            1, 8, 1, /* 6940: pointer.struct.bio_method_st */
            	6945, 0,
            0, 80, 9, /* 6945: struct.bio_method_st */
            	5, 8,
            	6966, 16,
            	6969, 24,
            	6972, 32,
            	6969, 40,
            	6975, 48,
            	6978, 56,
            	6978, 64,
            	6981, 72,
            8884097, 8, 0, /* 6966: pointer.func */
            8884097, 8, 0, /* 6969: pointer.func */
            8884097, 8, 0, /* 6972: pointer.func */
            8884097, 8, 0, /* 6975: pointer.func */
            8884097, 8, 0, /* 6978: pointer.func */
            8884097, 8, 0, /* 6981: pointer.func */
            8884097, 8, 0, /* 6984: pointer.func */
            1, 8, 1, /* 6987: pointer.struct.bio_st */
            	6923, 0,
            1, 8, 1, /* 6992: pointer.struct.ssl2_state_st */
            	6997, 0,
            0, 344, 9, /* 6997: struct.ssl2_state_st */
            	104, 24,
            	122, 56,
            	122, 64,
            	122, 72,
            	122, 104,
            	122, 112,
            	122, 120,
            	122, 128,
            	122, 136,
            1, 8, 1, /* 7018: pointer.struct.ssl3_state_st */
            	7023, 0,
            0, 1200, 10, /* 7023: struct.ssl3_state_st */
            	7046, 240,
            	7046, 264,
            	7051, 288,
            	7051, 344,
            	104, 432,
            	6918, 440,
            	7060, 448,
            	20, 496,
            	20, 512,
            	7287, 528,
            0, 24, 1, /* 7046: struct.ssl3_buffer_st */
            	122, 0,
            0, 56, 3, /* 7051: struct.ssl3_record_st */
            	122, 16,
            	122, 24,
            	122, 32,
            1, 8, 1, /* 7060: pointer.pointer.struct.env_md_ctx_st */
            	7065, 0,
            1, 8, 1, /* 7065: pointer.struct.env_md_ctx_st */
            	7070, 0,
            0, 48, 5, /* 7070: struct.env_md_ctx_st */
            	6108, 0,
            	5731, 8,
            	20, 24,
            	7083, 32,
            	6135, 40,
            1, 8, 1, /* 7083: pointer.struct.evp_pkey_ctx_st */
            	7088, 0,
            0, 80, 8, /* 7088: struct.evp_pkey_ctx_st */
            	7107, 0,
            	1719, 8,
            	7201, 16,
            	7201, 24,
            	20, 40,
            	20, 48,
            	7279, 56,
            	7282, 64,
            1, 8, 1, /* 7107: pointer.struct.evp_pkey_method_st */
            	7112, 0,
            0, 208, 25, /* 7112: struct.evp_pkey_method_st */
            	7165, 8,
            	7168, 16,
            	7171, 24,
            	7165, 32,
            	7174, 40,
            	7165, 48,
            	7174, 56,
            	7165, 64,
            	7177, 72,
            	7165, 80,
            	7180, 88,
            	7165, 96,
            	7177, 104,
            	7183, 112,
            	7186, 120,
            	7183, 128,
            	7189, 136,
            	7165, 144,
            	7177, 152,
            	7165, 160,
            	7177, 168,
            	7165, 176,
            	7192, 184,
            	7195, 192,
            	7198, 200,
            8884097, 8, 0, /* 7165: pointer.func */
            8884097, 8, 0, /* 7168: pointer.func */
            8884097, 8, 0, /* 7171: pointer.func */
            8884097, 8, 0, /* 7174: pointer.func */
            8884097, 8, 0, /* 7177: pointer.func */
            8884097, 8, 0, /* 7180: pointer.func */
            8884097, 8, 0, /* 7183: pointer.func */
            8884097, 8, 0, /* 7186: pointer.func */
            8884097, 8, 0, /* 7189: pointer.func */
            8884097, 8, 0, /* 7192: pointer.func */
            8884097, 8, 0, /* 7195: pointer.func */
            8884097, 8, 0, /* 7198: pointer.func */
            1, 8, 1, /* 7201: pointer.struct.evp_pkey_st */
            	7206, 0,
            0, 56, 4, /* 7206: struct.evp_pkey_st */
            	7217, 16,
            	1719, 24,
            	7222, 32,
            	7255, 48,
            1, 8, 1, /* 7217: pointer.struct.evp_pkey_asn1_method_st */
            	781, 0,
            0, 8, 5, /* 7222: union.unknown */
            	143, 0,
            	7235, 0,
            	7240, 0,
            	7245, 0,
            	7250, 0,
            1, 8, 1, /* 7235: pointer.struct.rsa_st */
            	1248, 0,
            1, 8, 1, /* 7240: pointer.struct.dsa_st */
            	1464, 0,
            1, 8, 1, /* 7245: pointer.struct.dh_st */
            	1603, 0,
            1, 8, 1, /* 7250: pointer.struct.ec_key_st */
            	1729, 0,
            1, 8, 1, /* 7255: pointer.struct.stack_st_X509_ATTRIBUTE */
            	7260, 0,
            0, 32, 2, /* 7260: struct.stack_st_fake_X509_ATTRIBUTE */
            	7267, 8,
            	130, 24,
            8884099, 8, 2, /* 7267: pointer_to_array_of_pointers_to_stack */
            	7274, 0,
            	127, 20,
            0, 8, 1, /* 7274: pointer.X509_ATTRIBUTE */
            	2257, 0,
            8884097, 8, 0, /* 7279: pointer.func */
            1, 8, 1, /* 7282: pointer.int */
            	127, 0,
            0, 528, 8, /* 7287: struct.unknown */
            	6086, 408,
            	7306, 416,
            	5848, 424,
            	6198, 464,
            	122, 480,
            	7311, 488,
            	6108, 496,
            	7348, 512,
            1, 8, 1, /* 7306: pointer.struct.dh_st */
            	1603, 0,
            1, 8, 1, /* 7311: pointer.struct.evp_cipher_st */
            	7316, 0,
            0, 88, 7, /* 7316: struct.evp_cipher_st */
            	7333, 24,
            	7336, 32,
            	7339, 40,
            	7342, 56,
            	7342, 64,
            	7345, 72,
            	20, 80,
            8884097, 8, 0, /* 7333: pointer.func */
            8884097, 8, 0, /* 7336: pointer.func */
            8884097, 8, 0, /* 7339: pointer.func */
            8884097, 8, 0, /* 7342: pointer.func */
            8884097, 8, 0, /* 7345: pointer.func */
            1, 8, 1, /* 7348: pointer.struct.ssl_comp_st */
            	7353, 0,
            0, 24, 2, /* 7353: struct.ssl_comp_st */
            	5, 8,
            	7360, 16,
            1, 8, 1, /* 7360: pointer.struct.comp_method_st */
            	7365, 0,
            0, 64, 7, /* 7365: struct.comp_method_st */
            	5, 8,
            	7382, 16,
            	7385, 24,
            	7388, 32,
            	7388, 40,
            	240, 48,
            	240, 56,
            8884097, 8, 0, /* 7382: pointer.func */
            8884097, 8, 0, /* 7385: pointer.func */
            8884097, 8, 0, /* 7388: pointer.func */
            1, 8, 1, /* 7391: pointer.struct.dtls1_state_st */
            	7396, 0,
            0, 888, 7, /* 7396: struct.dtls1_state_st */
            	7413, 576,
            	7413, 592,
            	7418, 608,
            	7418, 616,
            	7413, 624,
            	7445, 648,
            	7445, 736,
            0, 16, 1, /* 7413: struct.record_pqueue_st */
            	7418, 8,
            1, 8, 1, /* 7418: pointer.struct._pqueue */
            	7423, 0,
            0, 16, 1, /* 7423: struct._pqueue */
            	7428, 0,
            1, 8, 1, /* 7428: pointer.struct._pitem */
            	7433, 0,
            0, 24, 2, /* 7433: struct._pitem */
            	20, 8,
            	7440, 16,
            1, 8, 1, /* 7440: pointer.struct._pitem */
            	7433, 0,
            0, 88, 1, /* 7445: struct.hm_header_st */
            	7450, 48,
            0, 40, 4, /* 7450: struct.dtls1_retransmit_state */
            	7461, 0,
            	7065, 8,
            	7477, 16,
            	7489, 24,
            1, 8, 1, /* 7461: pointer.struct.evp_cipher_ctx_st */
            	7466, 0,
            0, 168, 4, /* 7466: struct.evp_cipher_ctx_st */
            	7311, 0,
            	5731, 8,
            	20, 96,
            	20, 120,
            1, 8, 1, /* 7477: pointer.struct.comp_ctx_st */
            	7482, 0,
            0, 56, 2, /* 7482: struct.comp_ctx_st */
            	7360, 0,
            	4912, 40,
            1, 8, 1, /* 7489: pointer.struct.ssl_session_st */
            	4939, 0,
            8884097, 8, 0, /* 7494: pointer.func */
            1, 8, 1, /* 7497: pointer.struct.stack_st_OCSP_RESPID */
            	7502, 0,
            0, 32, 2, /* 7502: struct.stack_st_fake_OCSP_RESPID */
            	7509, 8,
            	130, 24,
            8884099, 8, 2, /* 7509: pointer_to_array_of_pointers_to_stack */
            	7516, 0,
            	127, 20,
            0, 8, 1, /* 7516: pointer.OCSP_RESPID */
            	23, 0,
            1, 8, 1, /* 7521: pointer.struct.stack_st_X509_EXTENSION */
            	7526, 0,
            0, 32, 2, /* 7526: struct.stack_st_fake_X509_EXTENSION */
            	7533, 8,
            	130, 24,
            8884099, 8, 2, /* 7533: pointer_to_array_of_pointers_to_stack */
            	7540, 0,
            	127, 20,
            0, 8, 1, /* 7540: pointer.X509_EXTENSION */
            	2633, 0,
            8884097, 8, 0, /* 7545: pointer.func */
            8884097, 8, 0, /* 7548: pointer.func */
            0, 1, 0, /* 7551: char */
        },
        .arg_entity_index = { 6808, },
        .ret_entity_index = 6803,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    const SSL * new_arg_a = *((const SSL * *)new_args->args[0]);

    const SSL_CIPHER * *new_ret_ptr = (const SSL_CIPHER * *)new_args->ret;

    const SSL_CIPHER * (*orig_SSL_get_current_cipher)(const SSL *);
    orig_SSL_get_current_cipher = dlsym(RTLD_NEXT, "SSL_get_current_cipher");
    *new_ret_ptr = (*orig_SSL_get_current_cipher)(new_arg_a);

    syscall(889);

    return ret;
}

