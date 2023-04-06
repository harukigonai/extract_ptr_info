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

int bb_SSL_read(SSL * arg_a,void * arg_b,int arg_c);

int SSL_read(SSL * arg_a,void * arg_b,int arg_c) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_read called %lu\n", in_lib);
    if (!in_lib)
        return bb_SSL_read(arg_a,arg_b,arg_c);
    else {
        int (*orig_SSL_read)(SSL *,void *,int);
        orig_SSL_read = dlsym(RTLD_NEXT, "SSL_read");
        return orig_SSL_read(arg_a,arg_b,arg_c);
    }
}

int bb_SSL_read(SSL * arg_a,void * arg_b,int arg_c) 
{
    int ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 16, 1, /* 0: struct.srtp_protection_profile_st */
            	5, 0,
            1, 8, 1, /* 5: pointer.char */
            	8884096, 0,
            0, 16, 1, /* 10: struct.tls_session_ticket_ext_st */
            	15, 8,
            0, 8, 0, /* 15: pointer.void */
            0, 0, 1, /* 18: OCSP_RESPID */
            	23, 0,
            0, 16, 1, /* 23: struct.ocsp_responder_id_st */
            	28, 8,
            0, 8, 2, /* 28: union.unknown */
            	35, 0,
            	143, 0,
            1, 8, 1, /* 35: pointer.struct.X509_name_st */
            	40, 0,
            0, 40, 3, /* 40: struct.X509_name_st */
            	49, 0,
            	128, 16,
            	117, 24,
            1, 8, 1, /* 49: pointer.struct.stack_st_X509_NAME_ENTRY */
            	54, 0,
            0, 32, 2, /* 54: struct.stack_st_fake_X509_NAME_ENTRY */
            	61, 8,
            	125, 24,
            8884099, 8, 2, /* 61: pointer_to_array_of_pointers_to_stack */
            	68, 0,
            	122, 20,
            0, 8, 1, /* 68: pointer.X509_NAME_ENTRY */
            	73, 0,
            0, 0, 1, /* 73: X509_NAME_ENTRY */
            	78, 0,
            0, 24, 2, /* 78: struct.X509_name_entry_st */
            	85, 0,
            	107, 8,
            1, 8, 1, /* 85: pointer.struct.asn1_object_st */
            	90, 0,
            0, 40, 3, /* 90: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	99, 24,
            1, 8, 1, /* 99: pointer.unsigned char */
            	104, 0,
            0, 1, 0, /* 104: unsigned char */
            1, 8, 1, /* 107: pointer.struct.asn1_string_st */
            	112, 0,
            0, 24, 1, /* 112: struct.asn1_string_st */
            	117, 8,
            1, 8, 1, /* 117: pointer.unsigned char */
            	104, 0,
            0, 4, 0, /* 122: int */
            8884097, 8, 0, /* 125: pointer.func */
            1, 8, 1, /* 128: pointer.struct.buf_mem_st */
            	133, 0,
            0, 24, 1, /* 133: struct.buf_mem_st */
            	138, 8,
            1, 8, 1, /* 138: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 143: pointer.struct.asn1_string_st */
            	148, 0,
            0, 24, 1, /* 148: struct.asn1_string_st */
            	117, 8,
            0, 16, 1, /* 153: struct.srtp_protection_profile_st */
            	5, 0,
            0, 0, 1, /* 158: SRTP_PROTECTION_PROFILE */
            	153, 0,
            8884097, 8, 0, /* 163: pointer.func */
            0, 24, 1, /* 166: struct.bignum_st */
            	171, 0,
            8884099, 8, 2, /* 171: pointer_to_array_of_pointers_to_stack */
            	178, 0,
            	122, 12,
            0, 4, 0, /* 178: unsigned int */
            1, 8, 1, /* 181: pointer.struct.bignum_st */
            	166, 0,
            1, 8, 1, /* 186: pointer.struct.ssl3_buf_freelist_st */
            	191, 0,
            0, 24, 1, /* 191: struct.ssl3_buf_freelist_st */
            	196, 16,
            1, 8, 1, /* 196: pointer.struct.ssl3_buf_freelist_entry_st */
            	201, 0,
            0, 8, 1, /* 201: struct.ssl3_buf_freelist_entry_st */
            	196, 0,
            8884097, 8, 0, /* 206: pointer.func */
            8884097, 8, 0, /* 209: pointer.func */
            8884097, 8, 0, /* 212: pointer.func */
            8884097, 8, 0, /* 215: pointer.func */
            0, 64, 7, /* 218: struct.comp_method_st */
            	5, 8,
            	215, 16,
            	212, 24,
            	209, 32,
            	209, 40,
            	235, 48,
            	235, 56,
            8884097, 8, 0, /* 235: pointer.func */
            0, 0, 1, /* 238: SSL_COMP */
            	243, 0,
            0, 24, 2, /* 243: struct.ssl_comp_st */
            	5, 8,
            	250, 16,
            1, 8, 1, /* 250: pointer.struct.comp_method_st */
            	218, 0,
            8884097, 8, 0, /* 255: pointer.func */
            8884097, 8, 0, /* 258: pointer.func */
            8884097, 8, 0, /* 261: pointer.func */
            8884097, 8, 0, /* 264: pointer.func */
            1, 8, 1, /* 267: pointer.struct.lhash_node_st */
            	272, 0,
            0, 24, 2, /* 272: struct.lhash_node_st */
            	15, 0,
            	267, 8,
            0, 176, 3, /* 279: struct.lhash_st */
            	288, 0,
            	125, 8,
            	295, 16,
            8884099, 8, 2, /* 288: pointer_to_array_of_pointers_to_stack */
            	267, 0,
            	178, 28,
            8884097, 8, 0, /* 295: pointer.func */
            1, 8, 1, /* 298: pointer.struct.lhash_st */
            	279, 0,
            8884097, 8, 0, /* 303: pointer.func */
            8884097, 8, 0, /* 306: pointer.func */
            8884097, 8, 0, /* 309: pointer.func */
            8884097, 8, 0, /* 312: pointer.func */
            8884097, 8, 0, /* 315: pointer.func */
            8884097, 8, 0, /* 318: pointer.func */
            8884097, 8, 0, /* 321: pointer.func */
            8884097, 8, 0, /* 324: pointer.func */
            1, 8, 1, /* 327: pointer.struct.X509_VERIFY_PARAM_st */
            	332, 0,
            0, 56, 2, /* 332: struct.X509_VERIFY_PARAM_st */
            	138, 0,
            	339, 48,
            1, 8, 1, /* 339: pointer.struct.stack_st_ASN1_OBJECT */
            	344, 0,
            0, 32, 2, /* 344: struct.stack_st_fake_ASN1_OBJECT */
            	351, 8,
            	125, 24,
            8884099, 8, 2, /* 351: pointer_to_array_of_pointers_to_stack */
            	358, 0,
            	122, 20,
            0, 8, 1, /* 358: pointer.ASN1_OBJECT */
            	363, 0,
            0, 0, 1, /* 363: ASN1_OBJECT */
            	368, 0,
            0, 40, 3, /* 368: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	99, 24,
            1, 8, 1, /* 377: pointer.struct.stack_st_X509_OBJECT */
            	382, 0,
            0, 32, 2, /* 382: struct.stack_st_fake_X509_OBJECT */
            	389, 8,
            	125, 24,
            8884099, 8, 2, /* 389: pointer_to_array_of_pointers_to_stack */
            	396, 0,
            	122, 20,
            0, 8, 1, /* 396: pointer.X509_OBJECT */
            	401, 0,
            0, 0, 1, /* 401: X509_OBJECT */
            	406, 0,
            0, 16, 1, /* 406: struct.x509_object_st */
            	411, 8,
            0, 8, 4, /* 411: union.unknown */
            	138, 0,
            	422, 0,
            	3905, 0,
            	4239, 0,
            1, 8, 1, /* 422: pointer.struct.x509_st */
            	427, 0,
            0, 184, 12, /* 427: struct.x509_st */
            	454, 0,
            	494, 8,
            	2599, 16,
            	138, 32,
            	2669, 40,
            	2691, 104,
            	2696, 112,
            	2961, 120,
            	3378, 128,
            	3517, 136,
            	3541, 144,
            	3853, 176,
            1, 8, 1, /* 454: pointer.struct.x509_cinf_st */
            	459, 0,
            0, 104, 11, /* 459: struct.x509_cinf_st */
            	484, 0,
            	484, 8,
            	494, 16,
            	661, 24,
            	709, 32,
            	661, 40,
            	726, 48,
            	2599, 56,
            	2599, 64,
            	2604, 72,
            	2664, 80,
            1, 8, 1, /* 484: pointer.struct.asn1_string_st */
            	489, 0,
            0, 24, 1, /* 489: struct.asn1_string_st */
            	117, 8,
            1, 8, 1, /* 494: pointer.struct.X509_algor_st */
            	499, 0,
            0, 16, 2, /* 499: struct.X509_algor_st */
            	506, 0,
            	520, 8,
            1, 8, 1, /* 506: pointer.struct.asn1_object_st */
            	511, 0,
            0, 40, 3, /* 511: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	99, 24,
            1, 8, 1, /* 520: pointer.struct.asn1_type_st */
            	525, 0,
            0, 16, 1, /* 525: struct.asn1_type_st */
            	530, 8,
            0, 8, 20, /* 530: union.unknown */
            	138, 0,
            	573, 0,
            	506, 0,
            	583, 0,
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
            	573, 0,
            	573, 0,
            	653, 0,
            1, 8, 1, /* 573: pointer.struct.asn1_string_st */
            	578, 0,
            0, 24, 1, /* 578: struct.asn1_string_st */
            	117, 8,
            1, 8, 1, /* 583: pointer.struct.asn1_string_st */
            	578, 0,
            1, 8, 1, /* 588: pointer.struct.asn1_string_st */
            	578, 0,
            1, 8, 1, /* 593: pointer.struct.asn1_string_st */
            	578, 0,
            1, 8, 1, /* 598: pointer.struct.asn1_string_st */
            	578, 0,
            1, 8, 1, /* 603: pointer.struct.asn1_string_st */
            	578, 0,
            1, 8, 1, /* 608: pointer.struct.asn1_string_st */
            	578, 0,
            1, 8, 1, /* 613: pointer.struct.asn1_string_st */
            	578, 0,
            1, 8, 1, /* 618: pointer.struct.asn1_string_st */
            	578, 0,
            1, 8, 1, /* 623: pointer.struct.asn1_string_st */
            	578, 0,
            1, 8, 1, /* 628: pointer.struct.asn1_string_st */
            	578, 0,
            1, 8, 1, /* 633: pointer.struct.asn1_string_st */
            	578, 0,
            1, 8, 1, /* 638: pointer.struct.asn1_string_st */
            	578, 0,
            1, 8, 1, /* 643: pointer.struct.asn1_string_st */
            	578, 0,
            1, 8, 1, /* 648: pointer.struct.asn1_string_st */
            	578, 0,
            1, 8, 1, /* 653: pointer.struct.ASN1_VALUE_st */
            	658, 0,
            0, 0, 0, /* 658: struct.ASN1_VALUE_st */
            1, 8, 1, /* 661: pointer.struct.X509_name_st */
            	666, 0,
            0, 40, 3, /* 666: struct.X509_name_st */
            	675, 0,
            	699, 16,
            	117, 24,
            1, 8, 1, /* 675: pointer.struct.stack_st_X509_NAME_ENTRY */
            	680, 0,
            0, 32, 2, /* 680: struct.stack_st_fake_X509_NAME_ENTRY */
            	687, 8,
            	125, 24,
            8884099, 8, 2, /* 687: pointer_to_array_of_pointers_to_stack */
            	694, 0,
            	122, 20,
            0, 8, 1, /* 694: pointer.X509_NAME_ENTRY */
            	73, 0,
            1, 8, 1, /* 699: pointer.struct.buf_mem_st */
            	704, 0,
            0, 24, 1, /* 704: struct.buf_mem_st */
            	138, 8,
            1, 8, 1, /* 709: pointer.struct.X509_val_st */
            	714, 0,
            0, 16, 2, /* 714: struct.X509_val_st */
            	721, 0,
            	721, 8,
            1, 8, 1, /* 721: pointer.struct.asn1_string_st */
            	489, 0,
            1, 8, 1, /* 726: pointer.struct.X509_pubkey_st */
            	731, 0,
            0, 24, 3, /* 731: struct.X509_pubkey_st */
            	740, 0,
            	745, 8,
            	755, 16,
            1, 8, 1, /* 740: pointer.struct.X509_algor_st */
            	499, 0,
            1, 8, 1, /* 745: pointer.struct.asn1_string_st */
            	750, 0,
            0, 24, 1, /* 750: struct.asn1_string_st */
            	117, 8,
            1, 8, 1, /* 755: pointer.struct.evp_pkey_st */
            	760, 0,
            0, 56, 4, /* 760: struct.evp_pkey_st */
            	771, 16,
            	872, 24,
            	1225, 32,
            	2228, 48,
            1, 8, 1, /* 771: pointer.struct.evp_pkey_asn1_method_st */
            	776, 0,
            0, 208, 24, /* 776: struct.evp_pkey_asn1_method_st */
            	138, 16,
            	138, 24,
            	827, 32,
            	830, 40,
            	833, 48,
            	836, 56,
            	839, 64,
            	842, 72,
            	836, 80,
            	845, 88,
            	845, 96,
            	848, 104,
            	851, 112,
            	845, 120,
            	854, 128,
            	833, 136,
            	836, 144,
            	857, 152,
            	860, 160,
            	863, 168,
            	848, 176,
            	851, 184,
            	866, 192,
            	869, 200,
            8884097, 8, 0, /* 827: pointer.func */
            8884097, 8, 0, /* 830: pointer.func */
            8884097, 8, 0, /* 833: pointer.func */
            8884097, 8, 0, /* 836: pointer.func */
            8884097, 8, 0, /* 839: pointer.func */
            8884097, 8, 0, /* 842: pointer.func */
            8884097, 8, 0, /* 845: pointer.func */
            8884097, 8, 0, /* 848: pointer.func */
            8884097, 8, 0, /* 851: pointer.func */
            8884097, 8, 0, /* 854: pointer.func */
            8884097, 8, 0, /* 857: pointer.func */
            8884097, 8, 0, /* 860: pointer.func */
            8884097, 8, 0, /* 863: pointer.func */
            8884097, 8, 0, /* 866: pointer.func */
            8884097, 8, 0, /* 869: pointer.func */
            1, 8, 1, /* 872: pointer.struct.engine_st */
            	877, 0,
            0, 216, 24, /* 877: struct.engine_st */
            	5, 0,
            	5, 8,
            	928, 16,
            	983, 24,
            	1034, 32,
            	1070, 40,
            	1087, 48,
            	1114, 56,
            	1149, 64,
            	1157, 72,
            	1160, 80,
            	1163, 88,
            	1166, 96,
            	1169, 104,
            	1169, 112,
            	1169, 120,
            	1172, 128,
            	1175, 136,
            	1175, 144,
            	1178, 152,
            	1181, 160,
            	1193, 184,
            	1220, 200,
            	1220, 208,
            1, 8, 1, /* 928: pointer.struct.rsa_meth_st */
            	933, 0,
            0, 112, 13, /* 933: struct.rsa_meth_st */
            	5, 0,
            	962, 8,
            	962, 16,
            	962, 24,
            	962, 32,
            	965, 40,
            	968, 48,
            	971, 56,
            	971, 64,
            	138, 80,
            	974, 88,
            	977, 96,
            	980, 104,
            8884097, 8, 0, /* 962: pointer.func */
            8884097, 8, 0, /* 965: pointer.func */
            8884097, 8, 0, /* 968: pointer.func */
            8884097, 8, 0, /* 971: pointer.func */
            8884097, 8, 0, /* 974: pointer.func */
            8884097, 8, 0, /* 977: pointer.func */
            8884097, 8, 0, /* 980: pointer.func */
            1, 8, 1, /* 983: pointer.struct.dsa_method */
            	988, 0,
            0, 96, 11, /* 988: struct.dsa_method */
            	5, 0,
            	1013, 8,
            	1016, 16,
            	1019, 24,
            	1022, 32,
            	1025, 40,
            	1028, 48,
            	1028, 56,
            	138, 72,
            	1031, 80,
            	1028, 88,
            8884097, 8, 0, /* 1013: pointer.func */
            8884097, 8, 0, /* 1016: pointer.func */
            8884097, 8, 0, /* 1019: pointer.func */
            8884097, 8, 0, /* 1022: pointer.func */
            8884097, 8, 0, /* 1025: pointer.func */
            8884097, 8, 0, /* 1028: pointer.func */
            8884097, 8, 0, /* 1031: pointer.func */
            1, 8, 1, /* 1034: pointer.struct.dh_method */
            	1039, 0,
            0, 72, 8, /* 1039: struct.dh_method */
            	5, 0,
            	1058, 8,
            	1061, 16,
            	1064, 24,
            	1058, 32,
            	1058, 40,
            	138, 56,
            	1067, 64,
            8884097, 8, 0, /* 1058: pointer.func */
            8884097, 8, 0, /* 1061: pointer.func */
            8884097, 8, 0, /* 1064: pointer.func */
            8884097, 8, 0, /* 1067: pointer.func */
            1, 8, 1, /* 1070: pointer.struct.ecdh_method */
            	1075, 0,
            0, 32, 3, /* 1075: struct.ecdh_method */
            	5, 0,
            	1084, 8,
            	138, 24,
            8884097, 8, 0, /* 1084: pointer.func */
            1, 8, 1, /* 1087: pointer.struct.ecdsa_method */
            	1092, 0,
            0, 48, 5, /* 1092: struct.ecdsa_method */
            	5, 0,
            	1105, 8,
            	1108, 16,
            	1111, 24,
            	138, 40,
            8884097, 8, 0, /* 1105: pointer.func */
            8884097, 8, 0, /* 1108: pointer.func */
            8884097, 8, 0, /* 1111: pointer.func */
            1, 8, 1, /* 1114: pointer.struct.rand_meth_st */
            	1119, 0,
            0, 48, 6, /* 1119: struct.rand_meth_st */
            	1134, 0,
            	1137, 8,
            	1140, 16,
            	1143, 24,
            	1137, 32,
            	1146, 40,
            8884097, 8, 0, /* 1134: pointer.func */
            8884097, 8, 0, /* 1137: pointer.func */
            8884097, 8, 0, /* 1140: pointer.func */
            8884097, 8, 0, /* 1143: pointer.func */
            8884097, 8, 0, /* 1146: pointer.func */
            1, 8, 1, /* 1149: pointer.struct.store_method_st */
            	1154, 0,
            0, 0, 0, /* 1154: struct.store_method_st */
            8884097, 8, 0, /* 1157: pointer.func */
            8884097, 8, 0, /* 1160: pointer.func */
            8884097, 8, 0, /* 1163: pointer.func */
            8884097, 8, 0, /* 1166: pointer.func */
            8884097, 8, 0, /* 1169: pointer.func */
            8884097, 8, 0, /* 1172: pointer.func */
            8884097, 8, 0, /* 1175: pointer.func */
            8884097, 8, 0, /* 1178: pointer.func */
            1, 8, 1, /* 1181: pointer.struct.ENGINE_CMD_DEFN_st */
            	1186, 0,
            0, 32, 2, /* 1186: struct.ENGINE_CMD_DEFN_st */
            	5, 8,
            	5, 16,
            0, 16, 1, /* 1193: struct.crypto_ex_data_st */
            	1198, 0,
            1, 8, 1, /* 1198: pointer.struct.stack_st_void */
            	1203, 0,
            0, 32, 1, /* 1203: struct.stack_st_void */
            	1208, 0,
            0, 32, 2, /* 1208: struct.stack_st */
            	1215, 8,
            	125, 24,
            1, 8, 1, /* 1215: pointer.pointer.char */
            	138, 0,
            1, 8, 1, /* 1220: pointer.struct.engine_st */
            	877, 0,
            0, 8, 5, /* 1225: union.unknown */
            	138, 0,
            	1238, 0,
            	1454, 0,
            	1593, 0,
            	1719, 0,
            1, 8, 1, /* 1238: pointer.struct.rsa_st */
            	1243, 0,
            0, 168, 17, /* 1243: struct.rsa_st */
            	1280, 16,
            	1335, 24,
            	1340, 32,
            	1340, 40,
            	1340, 48,
            	1340, 56,
            	1340, 64,
            	1340, 72,
            	1340, 80,
            	1340, 88,
            	1357, 96,
            	1379, 120,
            	1379, 128,
            	1379, 136,
            	138, 144,
            	1393, 152,
            	1393, 160,
            1, 8, 1, /* 1280: pointer.struct.rsa_meth_st */
            	1285, 0,
            0, 112, 13, /* 1285: struct.rsa_meth_st */
            	5, 0,
            	1314, 8,
            	1314, 16,
            	1314, 24,
            	1314, 32,
            	1317, 40,
            	1320, 48,
            	1323, 56,
            	1323, 64,
            	138, 80,
            	1326, 88,
            	1329, 96,
            	1332, 104,
            8884097, 8, 0, /* 1314: pointer.func */
            8884097, 8, 0, /* 1317: pointer.func */
            8884097, 8, 0, /* 1320: pointer.func */
            8884097, 8, 0, /* 1323: pointer.func */
            8884097, 8, 0, /* 1326: pointer.func */
            8884097, 8, 0, /* 1329: pointer.func */
            8884097, 8, 0, /* 1332: pointer.func */
            1, 8, 1, /* 1335: pointer.struct.engine_st */
            	877, 0,
            1, 8, 1, /* 1340: pointer.struct.bignum_st */
            	1345, 0,
            0, 24, 1, /* 1345: struct.bignum_st */
            	1350, 0,
            8884099, 8, 2, /* 1350: pointer_to_array_of_pointers_to_stack */
            	178, 0,
            	122, 12,
            0, 16, 1, /* 1357: struct.crypto_ex_data_st */
            	1362, 0,
            1, 8, 1, /* 1362: pointer.struct.stack_st_void */
            	1367, 0,
            0, 32, 1, /* 1367: struct.stack_st_void */
            	1372, 0,
            0, 32, 2, /* 1372: struct.stack_st */
            	1215, 8,
            	125, 24,
            1, 8, 1, /* 1379: pointer.struct.bn_mont_ctx_st */
            	1384, 0,
            0, 96, 3, /* 1384: struct.bn_mont_ctx_st */
            	1345, 8,
            	1345, 32,
            	1345, 56,
            1, 8, 1, /* 1393: pointer.struct.bn_blinding_st */
            	1398, 0,
            0, 88, 7, /* 1398: struct.bn_blinding_st */
            	1415, 0,
            	1415, 8,
            	1415, 16,
            	1415, 24,
            	1432, 40,
            	1437, 72,
            	1451, 80,
            1, 8, 1, /* 1415: pointer.struct.bignum_st */
            	1420, 0,
            0, 24, 1, /* 1420: struct.bignum_st */
            	1425, 0,
            8884099, 8, 2, /* 1425: pointer_to_array_of_pointers_to_stack */
            	178, 0,
            	122, 12,
            0, 16, 1, /* 1432: struct.crypto_threadid_st */
            	15, 0,
            1, 8, 1, /* 1437: pointer.struct.bn_mont_ctx_st */
            	1442, 0,
            0, 96, 3, /* 1442: struct.bn_mont_ctx_st */
            	1420, 8,
            	1420, 32,
            	1420, 56,
            8884097, 8, 0, /* 1451: pointer.func */
            1, 8, 1, /* 1454: pointer.struct.dsa_st */
            	1459, 0,
            0, 136, 11, /* 1459: struct.dsa_st */
            	1484, 24,
            	1484, 32,
            	1484, 40,
            	1484, 48,
            	1484, 56,
            	1484, 64,
            	1484, 72,
            	1501, 88,
            	1515, 104,
            	1537, 120,
            	1588, 128,
            1, 8, 1, /* 1484: pointer.struct.bignum_st */
            	1489, 0,
            0, 24, 1, /* 1489: struct.bignum_st */
            	1494, 0,
            8884099, 8, 2, /* 1494: pointer_to_array_of_pointers_to_stack */
            	178, 0,
            	122, 12,
            1, 8, 1, /* 1501: pointer.struct.bn_mont_ctx_st */
            	1506, 0,
            0, 96, 3, /* 1506: struct.bn_mont_ctx_st */
            	1489, 8,
            	1489, 32,
            	1489, 56,
            0, 16, 1, /* 1515: struct.crypto_ex_data_st */
            	1520, 0,
            1, 8, 1, /* 1520: pointer.struct.stack_st_void */
            	1525, 0,
            0, 32, 1, /* 1525: struct.stack_st_void */
            	1530, 0,
            0, 32, 2, /* 1530: struct.stack_st */
            	1215, 8,
            	125, 24,
            1, 8, 1, /* 1537: pointer.struct.dsa_method */
            	1542, 0,
            0, 96, 11, /* 1542: struct.dsa_method */
            	5, 0,
            	1567, 8,
            	1570, 16,
            	1573, 24,
            	1576, 32,
            	1579, 40,
            	1582, 48,
            	1582, 56,
            	138, 72,
            	1585, 80,
            	1582, 88,
            8884097, 8, 0, /* 1567: pointer.func */
            8884097, 8, 0, /* 1570: pointer.func */
            8884097, 8, 0, /* 1573: pointer.func */
            8884097, 8, 0, /* 1576: pointer.func */
            8884097, 8, 0, /* 1579: pointer.func */
            8884097, 8, 0, /* 1582: pointer.func */
            8884097, 8, 0, /* 1585: pointer.func */
            1, 8, 1, /* 1588: pointer.struct.engine_st */
            	877, 0,
            1, 8, 1, /* 1593: pointer.struct.dh_st */
            	1598, 0,
            0, 144, 12, /* 1598: struct.dh_st */
            	1625, 8,
            	1625, 16,
            	1625, 32,
            	1625, 40,
            	1642, 56,
            	1625, 64,
            	1625, 72,
            	117, 80,
            	1625, 96,
            	1656, 112,
            	1678, 128,
            	1714, 136,
            1, 8, 1, /* 1625: pointer.struct.bignum_st */
            	1630, 0,
            0, 24, 1, /* 1630: struct.bignum_st */
            	1635, 0,
            8884099, 8, 2, /* 1635: pointer_to_array_of_pointers_to_stack */
            	178, 0,
            	122, 12,
            1, 8, 1, /* 1642: pointer.struct.bn_mont_ctx_st */
            	1647, 0,
            0, 96, 3, /* 1647: struct.bn_mont_ctx_st */
            	1630, 8,
            	1630, 32,
            	1630, 56,
            0, 16, 1, /* 1656: struct.crypto_ex_data_st */
            	1661, 0,
            1, 8, 1, /* 1661: pointer.struct.stack_st_void */
            	1666, 0,
            0, 32, 1, /* 1666: struct.stack_st_void */
            	1671, 0,
            0, 32, 2, /* 1671: struct.stack_st */
            	1215, 8,
            	125, 24,
            1, 8, 1, /* 1678: pointer.struct.dh_method */
            	1683, 0,
            0, 72, 8, /* 1683: struct.dh_method */
            	5, 0,
            	1702, 8,
            	1705, 16,
            	1708, 24,
            	1702, 32,
            	1702, 40,
            	138, 56,
            	1711, 64,
            8884097, 8, 0, /* 1702: pointer.func */
            8884097, 8, 0, /* 1705: pointer.func */
            8884097, 8, 0, /* 1708: pointer.func */
            8884097, 8, 0, /* 1711: pointer.func */
            1, 8, 1, /* 1714: pointer.struct.engine_st */
            	877, 0,
            1, 8, 1, /* 1719: pointer.struct.ec_key_st */
            	1724, 0,
            0, 56, 4, /* 1724: struct.ec_key_st */
            	1735, 8,
            	2183, 16,
            	2188, 24,
            	2205, 48,
            1, 8, 1, /* 1735: pointer.struct.ec_group_st */
            	1740, 0,
            0, 232, 12, /* 1740: struct.ec_group_st */
            	1767, 0,
            	1939, 8,
            	2139, 16,
            	2139, 40,
            	117, 80,
            	2151, 96,
            	2139, 104,
            	2139, 152,
            	2139, 176,
            	15, 208,
            	15, 216,
            	2180, 224,
            1, 8, 1, /* 1767: pointer.struct.ec_method_st */
            	1772, 0,
            0, 304, 37, /* 1772: struct.ec_method_st */
            	1849, 8,
            	1852, 16,
            	1852, 24,
            	1855, 32,
            	1858, 40,
            	1861, 48,
            	1864, 56,
            	1867, 64,
            	1870, 72,
            	1873, 80,
            	1873, 88,
            	1876, 96,
            	1879, 104,
            	1882, 112,
            	1885, 120,
            	1888, 128,
            	1891, 136,
            	1894, 144,
            	1897, 152,
            	1900, 160,
            	1903, 168,
            	1906, 176,
            	1909, 184,
            	1912, 192,
            	1915, 200,
            	1918, 208,
            	1909, 216,
            	1921, 224,
            	1924, 232,
            	1927, 240,
            	1864, 248,
            	1930, 256,
            	1933, 264,
            	1930, 272,
            	1933, 280,
            	1933, 288,
            	1936, 296,
            8884097, 8, 0, /* 1849: pointer.func */
            8884097, 8, 0, /* 1852: pointer.func */
            8884097, 8, 0, /* 1855: pointer.func */
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
            1, 8, 1, /* 1939: pointer.struct.ec_point_st */
            	1944, 0,
            0, 88, 4, /* 1944: struct.ec_point_st */
            	1955, 0,
            	2127, 8,
            	2127, 32,
            	2127, 56,
            1, 8, 1, /* 1955: pointer.struct.ec_method_st */
            	1960, 0,
            0, 304, 37, /* 1960: struct.ec_method_st */
            	2037, 8,
            	2040, 16,
            	2040, 24,
            	2043, 32,
            	2046, 40,
            	2049, 48,
            	2052, 56,
            	2055, 64,
            	2058, 72,
            	2061, 80,
            	2061, 88,
            	2064, 96,
            	2067, 104,
            	2070, 112,
            	2073, 120,
            	2076, 128,
            	2079, 136,
            	2082, 144,
            	2085, 152,
            	2088, 160,
            	2091, 168,
            	2094, 176,
            	2097, 184,
            	2100, 192,
            	2103, 200,
            	2106, 208,
            	2097, 216,
            	2109, 224,
            	2112, 232,
            	2115, 240,
            	2052, 248,
            	2118, 256,
            	2121, 264,
            	2118, 272,
            	2121, 280,
            	2121, 288,
            	2124, 296,
            8884097, 8, 0, /* 2037: pointer.func */
            8884097, 8, 0, /* 2040: pointer.func */
            8884097, 8, 0, /* 2043: pointer.func */
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
            0, 24, 1, /* 2127: struct.bignum_st */
            	2132, 0,
            8884099, 8, 2, /* 2132: pointer_to_array_of_pointers_to_stack */
            	178, 0,
            	122, 12,
            0, 24, 1, /* 2139: struct.bignum_st */
            	2144, 0,
            8884099, 8, 2, /* 2144: pointer_to_array_of_pointers_to_stack */
            	178, 0,
            	122, 12,
            1, 8, 1, /* 2151: pointer.struct.ec_extra_data_st */
            	2156, 0,
            0, 40, 5, /* 2156: struct.ec_extra_data_st */
            	2169, 0,
            	15, 8,
            	2174, 16,
            	2177, 24,
            	2177, 32,
            1, 8, 1, /* 2169: pointer.struct.ec_extra_data_st */
            	2156, 0,
            8884097, 8, 0, /* 2174: pointer.func */
            8884097, 8, 0, /* 2177: pointer.func */
            8884097, 8, 0, /* 2180: pointer.func */
            1, 8, 1, /* 2183: pointer.struct.ec_point_st */
            	1944, 0,
            1, 8, 1, /* 2188: pointer.struct.bignum_st */
            	2193, 0,
            0, 24, 1, /* 2193: struct.bignum_st */
            	2198, 0,
            8884099, 8, 2, /* 2198: pointer_to_array_of_pointers_to_stack */
            	178, 0,
            	122, 12,
            1, 8, 1, /* 2205: pointer.struct.ec_extra_data_st */
            	2210, 0,
            0, 40, 5, /* 2210: struct.ec_extra_data_st */
            	2223, 0,
            	15, 8,
            	2174, 16,
            	2177, 24,
            	2177, 32,
            1, 8, 1, /* 2223: pointer.struct.ec_extra_data_st */
            	2210, 0,
            1, 8, 1, /* 2228: pointer.struct.stack_st_X509_ATTRIBUTE */
            	2233, 0,
            0, 32, 2, /* 2233: struct.stack_st_fake_X509_ATTRIBUTE */
            	2240, 8,
            	125, 24,
            8884099, 8, 2, /* 2240: pointer_to_array_of_pointers_to_stack */
            	2247, 0,
            	122, 20,
            0, 8, 1, /* 2247: pointer.X509_ATTRIBUTE */
            	2252, 0,
            0, 0, 1, /* 2252: X509_ATTRIBUTE */
            	2257, 0,
            0, 24, 2, /* 2257: struct.x509_attributes_st */
            	2264, 0,
            	2278, 16,
            1, 8, 1, /* 2264: pointer.struct.asn1_object_st */
            	2269, 0,
            0, 40, 3, /* 2269: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	99, 24,
            0, 8, 3, /* 2278: union.unknown */
            	138, 0,
            	2287, 0,
            	2466, 0,
            1, 8, 1, /* 2287: pointer.struct.stack_st_ASN1_TYPE */
            	2292, 0,
            0, 32, 2, /* 2292: struct.stack_st_fake_ASN1_TYPE */
            	2299, 8,
            	125, 24,
            8884099, 8, 2, /* 2299: pointer_to_array_of_pointers_to_stack */
            	2306, 0,
            	122, 20,
            0, 8, 1, /* 2306: pointer.ASN1_TYPE */
            	2311, 0,
            0, 0, 1, /* 2311: ASN1_TYPE */
            	2316, 0,
            0, 16, 1, /* 2316: struct.asn1_type_st */
            	2321, 8,
            0, 8, 20, /* 2321: union.unknown */
            	138, 0,
            	2364, 0,
            	2374, 0,
            	2388, 0,
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
            	2364, 0,
            	2364, 0,
            	2458, 0,
            1, 8, 1, /* 2364: pointer.struct.asn1_string_st */
            	2369, 0,
            0, 24, 1, /* 2369: struct.asn1_string_st */
            	117, 8,
            1, 8, 1, /* 2374: pointer.struct.asn1_object_st */
            	2379, 0,
            0, 40, 3, /* 2379: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	99, 24,
            1, 8, 1, /* 2388: pointer.struct.asn1_string_st */
            	2369, 0,
            1, 8, 1, /* 2393: pointer.struct.asn1_string_st */
            	2369, 0,
            1, 8, 1, /* 2398: pointer.struct.asn1_string_st */
            	2369, 0,
            1, 8, 1, /* 2403: pointer.struct.asn1_string_st */
            	2369, 0,
            1, 8, 1, /* 2408: pointer.struct.asn1_string_st */
            	2369, 0,
            1, 8, 1, /* 2413: pointer.struct.asn1_string_st */
            	2369, 0,
            1, 8, 1, /* 2418: pointer.struct.asn1_string_st */
            	2369, 0,
            1, 8, 1, /* 2423: pointer.struct.asn1_string_st */
            	2369, 0,
            1, 8, 1, /* 2428: pointer.struct.asn1_string_st */
            	2369, 0,
            1, 8, 1, /* 2433: pointer.struct.asn1_string_st */
            	2369, 0,
            1, 8, 1, /* 2438: pointer.struct.asn1_string_st */
            	2369, 0,
            1, 8, 1, /* 2443: pointer.struct.asn1_string_st */
            	2369, 0,
            1, 8, 1, /* 2448: pointer.struct.asn1_string_st */
            	2369, 0,
            1, 8, 1, /* 2453: pointer.struct.asn1_string_st */
            	2369, 0,
            1, 8, 1, /* 2458: pointer.struct.ASN1_VALUE_st */
            	2463, 0,
            0, 0, 0, /* 2463: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2466: pointer.struct.asn1_type_st */
            	2471, 0,
            0, 16, 1, /* 2471: struct.asn1_type_st */
            	2476, 8,
            0, 8, 20, /* 2476: union.unknown */
            	138, 0,
            	2519, 0,
            	2264, 0,
            	2529, 0,
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
            	2519, 0,
            	2519, 0,
            	653, 0,
            1, 8, 1, /* 2519: pointer.struct.asn1_string_st */
            	2524, 0,
            0, 24, 1, /* 2524: struct.asn1_string_st */
            	117, 8,
            1, 8, 1, /* 2529: pointer.struct.asn1_string_st */
            	2524, 0,
            1, 8, 1, /* 2534: pointer.struct.asn1_string_st */
            	2524, 0,
            1, 8, 1, /* 2539: pointer.struct.asn1_string_st */
            	2524, 0,
            1, 8, 1, /* 2544: pointer.struct.asn1_string_st */
            	2524, 0,
            1, 8, 1, /* 2549: pointer.struct.asn1_string_st */
            	2524, 0,
            1, 8, 1, /* 2554: pointer.struct.asn1_string_st */
            	2524, 0,
            1, 8, 1, /* 2559: pointer.struct.asn1_string_st */
            	2524, 0,
            1, 8, 1, /* 2564: pointer.struct.asn1_string_st */
            	2524, 0,
            1, 8, 1, /* 2569: pointer.struct.asn1_string_st */
            	2524, 0,
            1, 8, 1, /* 2574: pointer.struct.asn1_string_st */
            	2524, 0,
            1, 8, 1, /* 2579: pointer.struct.asn1_string_st */
            	2524, 0,
            1, 8, 1, /* 2584: pointer.struct.asn1_string_st */
            	2524, 0,
            1, 8, 1, /* 2589: pointer.struct.asn1_string_st */
            	2524, 0,
            1, 8, 1, /* 2594: pointer.struct.asn1_string_st */
            	2524, 0,
            1, 8, 1, /* 2599: pointer.struct.asn1_string_st */
            	489, 0,
            1, 8, 1, /* 2604: pointer.struct.stack_st_X509_EXTENSION */
            	2609, 0,
            0, 32, 2, /* 2609: struct.stack_st_fake_X509_EXTENSION */
            	2616, 8,
            	125, 24,
            8884099, 8, 2, /* 2616: pointer_to_array_of_pointers_to_stack */
            	2623, 0,
            	122, 20,
            0, 8, 1, /* 2623: pointer.X509_EXTENSION */
            	2628, 0,
            0, 0, 1, /* 2628: X509_EXTENSION */
            	2633, 0,
            0, 24, 2, /* 2633: struct.X509_extension_st */
            	2640, 0,
            	2654, 16,
            1, 8, 1, /* 2640: pointer.struct.asn1_object_st */
            	2645, 0,
            0, 40, 3, /* 2645: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	99, 24,
            1, 8, 1, /* 2654: pointer.struct.asn1_string_st */
            	2659, 0,
            0, 24, 1, /* 2659: struct.asn1_string_st */
            	117, 8,
            0, 24, 1, /* 2664: struct.ASN1_ENCODING_st */
            	117, 0,
            0, 16, 1, /* 2669: struct.crypto_ex_data_st */
            	2674, 0,
            1, 8, 1, /* 2674: pointer.struct.stack_st_void */
            	2679, 0,
            0, 32, 1, /* 2679: struct.stack_st_void */
            	2684, 0,
            0, 32, 2, /* 2684: struct.stack_st */
            	1215, 8,
            	125, 24,
            1, 8, 1, /* 2691: pointer.struct.asn1_string_st */
            	489, 0,
            1, 8, 1, /* 2696: pointer.struct.AUTHORITY_KEYID_st */
            	2701, 0,
            0, 24, 3, /* 2701: struct.AUTHORITY_KEYID_st */
            	2710, 0,
            	2720, 8,
            	2956, 16,
            1, 8, 1, /* 2710: pointer.struct.asn1_string_st */
            	2715, 0,
            0, 24, 1, /* 2715: struct.asn1_string_st */
            	117, 8,
            1, 8, 1, /* 2720: pointer.struct.stack_st_GENERAL_NAME */
            	2725, 0,
            0, 32, 2, /* 2725: struct.stack_st_fake_GENERAL_NAME */
            	2732, 8,
            	125, 24,
            8884099, 8, 2, /* 2732: pointer_to_array_of_pointers_to_stack */
            	2739, 0,
            	122, 20,
            0, 8, 1, /* 2739: pointer.GENERAL_NAME */
            	2744, 0,
            0, 0, 1, /* 2744: GENERAL_NAME */
            	2749, 0,
            0, 16, 1, /* 2749: struct.GENERAL_NAME_st */
            	2754, 8,
            0, 8, 15, /* 2754: union.unknown */
            	138, 0,
            	2787, 0,
            	2896, 0,
            	2896, 0,
            	2813, 0,
            	35, 0,
            	2944, 0,
            	2896, 0,
            	143, 0,
            	2799, 0,
            	143, 0,
            	35, 0,
            	2896, 0,
            	2799, 0,
            	2813, 0,
            1, 8, 1, /* 2787: pointer.struct.otherName_st */
            	2792, 0,
            0, 16, 2, /* 2792: struct.otherName_st */
            	2799, 0,
            	2813, 8,
            1, 8, 1, /* 2799: pointer.struct.asn1_object_st */
            	2804, 0,
            0, 40, 3, /* 2804: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	99, 24,
            1, 8, 1, /* 2813: pointer.struct.asn1_type_st */
            	2818, 0,
            0, 16, 1, /* 2818: struct.asn1_type_st */
            	2823, 8,
            0, 8, 20, /* 2823: union.unknown */
            	138, 0,
            	2866, 0,
            	2799, 0,
            	2871, 0,
            	2876, 0,
            	2881, 0,
            	143, 0,
            	2886, 0,
            	2891, 0,
            	2896, 0,
            	2901, 0,
            	2906, 0,
            	2911, 0,
            	2916, 0,
            	2921, 0,
            	2926, 0,
            	2931, 0,
            	2866, 0,
            	2866, 0,
            	2936, 0,
            1, 8, 1, /* 2866: pointer.struct.asn1_string_st */
            	148, 0,
            1, 8, 1, /* 2871: pointer.struct.asn1_string_st */
            	148, 0,
            1, 8, 1, /* 2876: pointer.struct.asn1_string_st */
            	148, 0,
            1, 8, 1, /* 2881: pointer.struct.asn1_string_st */
            	148, 0,
            1, 8, 1, /* 2886: pointer.struct.asn1_string_st */
            	148, 0,
            1, 8, 1, /* 2891: pointer.struct.asn1_string_st */
            	148, 0,
            1, 8, 1, /* 2896: pointer.struct.asn1_string_st */
            	148, 0,
            1, 8, 1, /* 2901: pointer.struct.asn1_string_st */
            	148, 0,
            1, 8, 1, /* 2906: pointer.struct.asn1_string_st */
            	148, 0,
            1, 8, 1, /* 2911: pointer.struct.asn1_string_st */
            	148, 0,
            1, 8, 1, /* 2916: pointer.struct.asn1_string_st */
            	148, 0,
            1, 8, 1, /* 2921: pointer.struct.asn1_string_st */
            	148, 0,
            1, 8, 1, /* 2926: pointer.struct.asn1_string_st */
            	148, 0,
            1, 8, 1, /* 2931: pointer.struct.asn1_string_st */
            	148, 0,
            1, 8, 1, /* 2936: pointer.struct.ASN1_VALUE_st */
            	2941, 0,
            0, 0, 0, /* 2941: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2944: pointer.struct.EDIPartyName_st */
            	2949, 0,
            0, 16, 2, /* 2949: struct.EDIPartyName_st */
            	2866, 0,
            	2866, 8,
            1, 8, 1, /* 2956: pointer.struct.asn1_string_st */
            	2715, 0,
            1, 8, 1, /* 2961: pointer.struct.X509_POLICY_CACHE_st */
            	2966, 0,
            0, 40, 2, /* 2966: struct.X509_POLICY_CACHE_st */
            	2973, 0,
            	3278, 8,
            1, 8, 1, /* 2973: pointer.struct.X509_POLICY_DATA_st */
            	2978, 0,
            0, 32, 3, /* 2978: struct.X509_POLICY_DATA_st */
            	2987, 8,
            	3001, 16,
            	3254, 24,
            1, 8, 1, /* 2987: pointer.struct.asn1_object_st */
            	2992, 0,
            0, 40, 3, /* 2992: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	99, 24,
            1, 8, 1, /* 3001: pointer.struct.stack_st_POLICYQUALINFO */
            	3006, 0,
            0, 32, 2, /* 3006: struct.stack_st_fake_POLICYQUALINFO */
            	3013, 8,
            	125, 24,
            8884099, 8, 2, /* 3013: pointer_to_array_of_pointers_to_stack */
            	3020, 0,
            	122, 20,
            0, 8, 1, /* 3020: pointer.POLICYQUALINFO */
            	3025, 0,
            0, 0, 1, /* 3025: POLICYQUALINFO */
            	3030, 0,
            0, 16, 2, /* 3030: struct.POLICYQUALINFO_st */
            	3037, 0,
            	3051, 8,
            1, 8, 1, /* 3037: pointer.struct.asn1_object_st */
            	3042, 0,
            0, 40, 3, /* 3042: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	99, 24,
            0, 8, 3, /* 3051: union.unknown */
            	3060, 0,
            	3070, 0,
            	3128, 0,
            1, 8, 1, /* 3060: pointer.struct.asn1_string_st */
            	3065, 0,
            0, 24, 1, /* 3065: struct.asn1_string_st */
            	117, 8,
            1, 8, 1, /* 3070: pointer.struct.USERNOTICE_st */
            	3075, 0,
            0, 16, 2, /* 3075: struct.USERNOTICE_st */
            	3082, 0,
            	3094, 8,
            1, 8, 1, /* 3082: pointer.struct.NOTICEREF_st */
            	3087, 0,
            0, 16, 2, /* 3087: struct.NOTICEREF_st */
            	3094, 0,
            	3099, 8,
            1, 8, 1, /* 3094: pointer.struct.asn1_string_st */
            	3065, 0,
            1, 8, 1, /* 3099: pointer.struct.stack_st_ASN1_INTEGER */
            	3104, 0,
            0, 32, 2, /* 3104: struct.stack_st_fake_ASN1_INTEGER */
            	3111, 8,
            	125, 24,
            8884099, 8, 2, /* 3111: pointer_to_array_of_pointers_to_stack */
            	3118, 0,
            	122, 20,
            0, 8, 1, /* 3118: pointer.ASN1_INTEGER */
            	3123, 0,
            0, 0, 1, /* 3123: ASN1_INTEGER */
            	578, 0,
            1, 8, 1, /* 3128: pointer.struct.asn1_type_st */
            	3133, 0,
            0, 16, 1, /* 3133: struct.asn1_type_st */
            	3138, 8,
            0, 8, 20, /* 3138: union.unknown */
            	138, 0,
            	3094, 0,
            	3037, 0,
            	3181, 0,
            	3186, 0,
            	3191, 0,
            	3196, 0,
            	3201, 0,
            	3206, 0,
            	3060, 0,
            	3211, 0,
            	3216, 0,
            	3221, 0,
            	3226, 0,
            	3231, 0,
            	3236, 0,
            	3241, 0,
            	3094, 0,
            	3094, 0,
            	3246, 0,
            1, 8, 1, /* 3181: pointer.struct.asn1_string_st */
            	3065, 0,
            1, 8, 1, /* 3186: pointer.struct.asn1_string_st */
            	3065, 0,
            1, 8, 1, /* 3191: pointer.struct.asn1_string_st */
            	3065, 0,
            1, 8, 1, /* 3196: pointer.struct.asn1_string_st */
            	3065, 0,
            1, 8, 1, /* 3201: pointer.struct.asn1_string_st */
            	3065, 0,
            1, 8, 1, /* 3206: pointer.struct.asn1_string_st */
            	3065, 0,
            1, 8, 1, /* 3211: pointer.struct.asn1_string_st */
            	3065, 0,
            1, 8, 1, /* 3216: pointer.struct.asn1_string_st */
            	3065, 0,
            1, 8, 1, /* 3221: pointer.struct.asn1_string_st */
            	3065, 0,
            1, 8, 1, /* 3226: pointer.struct.asn1_string_st */
            	3065, 0,
            1, 8, 1, /* 3231: pointer.struct.asn1_string_st */
            	3065, 0,
            1, 8, 1, /* 3236: pointer.struct.asn1_string_st */
            	3065, 0,
            1, 8, 1, /* 3241: pointer.struct.asn1_string_st */
            	3065, 0,
            1, 8, 1, /* 3246: pointer.struct.ASN1_VALUE_st */
            	3251, 0,
            0, 0, 0, /* 3251: struct.ASN1_VALUE_st */
            1, 8, 1, /* 3254: pointer.struct.stack_st_ASN1_OBJECT */
            	3259, 0,
            0, 32, 2, /* 3259: struct.stack_st_fake_ASN1_OBJECT */
            	3266, 8,
            	125, 24,
            8884099, 8, 2, /* 3266: pointer_to_array_of_pointers_to_stack */
            	3273, 0,
            	122, 20,
            0, 8, 1, /* 3273: pointer.ASN1_OBJECT */
            	363, 0,
            1, 8, 1, /* 3278: pointer.struct.stack_st_X509_POLICY_DATA */
            	3283, 0,
            0, 32, 2, /* 3283: struct.stack_st_fake_X509_POLICY_DATA */
            	3290, 8,
            	125, 24,
            8884099, 8, 2, /* 3290: pointer_to_array_of_pointers_to_stack */
            	3297, 0,
            	122, 20,
            0, 8, 1, /* 3297: pointer.X509_POLICY_DATA */
            	3302, 0,
            0, 0, 1, /* 3302: X509_POLICY_DATA */
            	3307, 0,
            0, 32, 3, /* 3307: struct.X509_POLICY_DATA_st */
            	3316, 8,
            	3330, 16,
            	3354, 24,
            1, 8, 1, /* 3316: pointer.struct.asn1_object_st */
            	3321, 0,
            0, 40, 3, /* 3321: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	99, 24,
            1, 8, 1, /* 3330: pointer.struct.stack_st_POLICYQUALINFO */
            	3335, 0,
            0, 32, 2, /* 3335: struct.stack_st_fake_POLICYQUALINFO */
            	3342, 8,
            	125, 24,
            8884099, 8, 2, /* 3342: pointer_to_array_of_pointers_to_stack */
            	3349, 0,
            	122, 20,
            0, 8, 1, /* 3349: pointer.POLICYQUALINFO */
            	3025, 0,
            1, 8, 1, /* 3354: pointer.struct.stack_st_ASN1_OBJECT */
            	3359, 0,
            0, 32, 2, /* 3359: struct.stack_st_fake_ASN1_OBJECT */
            	3366, 8,
            	125, 24,
            8884099, 8, 2, /* 3366: pointer_to_array_of_pointers_to_stack */
            	3373, 0,
            	122, 20,
            0, 8, 1, /* 3373: pointer.ASN1_OBJECT */
            	363, 0,
            1, 8, 1, /* 3378: pointer.struct.stack_st_DIST_POINT */
            	3383, 0,
            0, 32, 2, /* 3383: struct.stack_st_fake_DIST_POINT */
            	3390, 8,
            	125, 24,
            8884099, 8, 2, /* 3390: pointer_to_array_of_pointers_to_stack */
            	3397, 0,
            	122, 20,
            0, 8, 1, /* 3397: pointer.DIST_POINT */
            	3402, 0,
            0, 0, 1, /* 3402: DIST_POINT */
            	3407, 0,
            0, 32, 3, /* 3407: struct.DIST_POINT_st */
            	3416, 0,
            	3507, 8,
            	3435, 16,
            1, 8, 1, /* 3416: pointer.struct.DIST_POINT_NAME_st */
            	3421, 0,
            0, 24, 2, /* 3421: struct.DIST_POINT_NAME_st */
            	3428, 8,
            	3483, 16,
            0, 8, 2, /* 3428: union.unknown */
            	3435, 0,
            	3459, 0,
            1, 8, 1, /* 3435: pointer.struct.stack_st_GENERAL_NAME */
            	3440, 0,
            0, 32, 2, /* 3440: struct.stack_st_fake_GENERAL_NAME */
            	3447, 8,
            	125, 24,
            8884099, 8, 2, /* 3447: pointer_to_array_of_pointers_to_stack */
            	3454, 0,
            	122, 20,
            0, 8, 1, /* 3454: pointer.GENERAL_NAME */
            	2744, 0,
            1, 8, 1, /* 3459: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3464, 0,
            0, 32, 2, /* 3464: struct.stack_st_fake_X509_NAME_ENTRY */
            	3471, 8,
            	125, 24,
            8884099, 8, 2, /* 3471: pointer_to_array_of_pointers_to_stack */
            	3478, 0,
            	122, 20,
            0, 8, 1, /* 3478: pointer.X509_NAME_ENTRY */
            	73, 0,
            1, 8, 1, /* 3483: pointer.struct.X509_name_st */
            	3488, 0,
            0, 40, 3, /* 3488: struct.X509_name_st */
            	3459, 0,
            	3497, 16,
            	117, 24,
            1, 8, 1, /* 3497: pointer.struct.buf_mem_st */
            	3502, 0,
            0, 24, 1, /* 3502: struct.buf_mem_st */
            	138, 8,
            1, 8, 1, /* 3507: pointer.struct.asn1_string_st */
            	3512, 0,
            0, 24, 1, /* 3512: struct.asn1_string_st */
            	117, 8,
            1, 8, 1, /* 3517: pointer.struct.stack_st_GENERAL_NAME */
            	3522, 0,
            0, 32, 2, /* 3522: struct.stack_st_fake_GENERAL_NAME */
            	3529, 8,
            	125, 24,
            8884099, 8, 2, /* 3529: pointer_to_array_of_pointers_to_stack */
            	3536, 0,
            	122, 20,
            0, 8, 1, /* 3536: pointer.GENERAL_NAME */
            	2744, 0,
            1, 8, 1, /* 3541: pointer.struct.NAME_CONSTRAINTS_st */
            	3546, 0,
            0, 16, 2, /* 3546: struct.NAME_CONSTRAINTS_st */
            	3553, 0,
            	3553, 8,
            1, 8, 1, /* 3553: pointer.struct.stack_st_GENERAL_SUBTREE */
            	3558, 0,
            0, 32, 2, /* 3558: struct.stack_st_fake_GENERAL_SUBTREE */
            	3565, 8,
            	125, 24,
            8884099, 8, 2, /* 3565: pointer_to_array_of_pointers_to_stack */
            	3572, 0,
            	122, 20,
            0, 8, 1, /* 3572: pointer.GENERAL_SUBTREE */
            	3577, 0,
            0, 0, 1, /* 3577: GENERAL_SUBTREE */
            	3582, 0,
            0, 24, 3, /* 3582: struct.GENERAL_SUBTREE_st */
            	3591, 0,
            	3723, 8,
            	3723, 16,
            1, 8, 1, /* 3591: pointer.struct.GENERAL_NAME_st */
            	3596, 0,
            0, 16, 1, /* 3596: struct.GENERAL_NAME_st */
            	3601, 8,
            0, 8, 15, /* 3601: union.unknown */
            	138, 0,
            	3634, 0,
            	3753, 0,
            	3753, 0,
            	3660, 0,
            	3793, 0,
            	3841, 0,
            	3753, 0,
            	3738, 0,
            	3646, 0,
            	3738, 0,
            	3793, 0,
            	3753, 0,
            	3646, 0,
            	3660, 0,
            1, 8, 1, /* 3634: pointer.struct.otherName_st */
            	3639, 0,
            0, 16, 2, /* 3639: struct.otherName_st */
            	3646, 0,
            	3660, 8,
            1, 8, 1, /* 3646: pointer.struct.asn1_object_st */
            	3651, 0,
            0, 40, 3, /* 3651: struct.asn1_object_st */
            	5, 0,
            	5, 8,
            	99, 24,
            1, 8, 1, /* 3660: pointer.struct.asn1_type_st */
            	3665, 0,
            0, 16, 1, /* 3665: struct.asn1_type_st */
            	3670, 8,
            0, 8, 20, /* 3670: union.unknown */
            	138, 0,
            	3713, 0,
            	3646, 0,
            	3723, 0,
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
            	3713, 0,
            	3713, 0,
            	3246, 0,
            1, 8, 1, /* 3713: pointer.struct.asn1_string_st */
            	3718, 0,
            0, 24, 1, /* 3718: struct.asn1_string_st */
            	117, 8,
            1, 8, 1, /* 3723: pointer.struct.asn1_string_st */
            	3718, 0,
            1, 8, 1, /* 3728: pointer.struct.asn1_string_st */
            	3718, 0,
            1, 8, 1, /* 3733: pointer.struct.asn1_string_st */
            	3718, 0,
            1, 8, 1, /* 3738: pointer.struct.asn1_string_st */
            	3718, 0,
            1, 8, 1, /* 3743: pointer.struct.asn1_string_st */
            	3718, 0,
            1, 8, 1, /* 3748: pointer.struct.asn1_string_st */
            	3718, 0,
            1, 8, 1, /* 3753: pointer.struct.asn1_string_st */
            	3718, 0,
            1, 8, 1, /* 3758: pointer.struct.asn1_string_st */
            	3718, 0,
            1, 8, 1, /* 3763: pointer.struct.asn1_string_st */
            	3718, 0,
            1, 8, 1, /* 3768: pointer.struct.asn1_string_st */
            	3718, 0,
            1, 8, 1, /* 3773: pointer.struct.asn1_string_st */
            	3718, 0,
            1, 8, 1, /* 3778: pointer.struct.asn1_string_st */
            	3718, 0,
            1, 8, 1, /* 3783: pointer.struct.asn1_string_st */
            	3718, 0,
            1, 8, 1, /* 3788: pointer.struct.asn1_string_st */
            	3718, 0,
            1, 8, 1, /* 3793: pointer.struct.X509_name_st */
            	3798, 0,
            0, 40, 3, /* 3798: struct.X509_name_st */
            	3807, 0,
            	3831, 16,
            	117, 24,
            1, 8, 1, /* 3807: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3812, 0,
            0, 32, 2, /* 3812: struct.stack_st_fake_X509_NAME_ENTRY */
            	3819, 8,
            	125, 24,
            8884099, 8, 2, /* 3819: pointer_to_array_of_pointers_to_stack */
            	3826, 0,
            	122, 20,
            0, 8, 1, /* 3826: pointer.X509_NAME_ENTRY */
            	73, 0,
            1, 8, 1, /* 3831: pointer.struct.buf_mem_st */
            	3836, 0,
            0, 24, 1, /* 3836: struct.buf_mem_st */
            	138, 8,
            1, 8, 1, /* 3841: pointer.struct.EDIPartyName_st */
            	3846, 0,
            0, 16, 2, /* 3846: struct.EDIPartyName_st */
            	3713, 0,
            	3713, 8,
            1, 8, 1, /* 3853: pointer.struct.x509_cert_aux_st */
            	3858, 0,
            0, 40, 5, /* 3858: struct.x509_cert_aux_st */
            	339, 0,
            	339, 8,
            	3871, 16,
            	2691, 24,
            	3876, 32,
            1, 8, 1, /* 3871: pointer.struct.asn1_string_st */
            	489, 0,
            1, 8, 1, /* 3876: pointer.struct.stack_st_X509_ALGOR */
            	3881, 0,
            0, 32, 2, /* 3881: struct.stack_st_fake_X509_ALGOR */
            	3888, 8,
            	125, 24,
            8884099, 8, 2, /* 3888: pointer_to_array_of_pointers_to_stack */
            	3895, 0,
            	122, 20,
            0, 8, 1, /* 3895: pointer.X509_ALGOR */
            	3900, 0,
            0, 0, 1, /* 3900: X509_ALGOR */
            	499, 0,
            1, 8, 1, /* 3905: pointer.struct.X509_crl_st */
            	3910, 0,
            0, 120, 10, /* 3910: struct.X509_crl_st */
            	3933, 0,
            	494, 8,
            	2599, 16,
            	2696, 32,
            	4060, 40,
            	484, 56,
            	484, 64,
            	4173, 96,
            	4214, 104,
            	15, 112,
            1, 8, 1, /* 3933: pointer.struct.X509_crl_info_st */
            	3938, 0,
            0, 80, 8, /* 3938: struct.X509_crl_info_st */
            	484, 0,
            	494, 8,
            	661, 16,
            	721, 24,
            	721, 32,
            	3957, 40,
            	2604, 48,
            	2664, 56,
            1, 8, 1, /* 3957: pointer.struct.stack_st_X509_REVOKED */
            	3962, 0,
            0, 32, 2, /* 3962: struct.stack_st_fake_X509_REVOKED */
            	3969, 8,
            	125, 24,
            8884099, 8, 2, /* 3969: pointer_to_array_of_pointers_to_stack */
            	3976, 0,
            	122, 20,
            0, 8, 1, /* 3976: pointer.X509_REVOKED */
            	3981, 0,
            0, 0, 1, /* 3981: X509_REVOKED */
            	3986, 0,
            0, 40, 4, /* 3986: struct.x509_revoked_st */
            	3997, 0,
            	4007, 8,
            	4012, 16,
            	4036, 24,
            1, 8, 1, /* 3997: pointer.struct.asn1_string_st */
            	4002, 0,
            0, 24, 1, /* 4002: struct.asn1_string_st */
            	117, 8,
            1, 8, 1, /* 4007: pointer.struct.asn1_string_st */
            	4002, 0,
            1, 8, 1, /* 4012: pointer.struct.stack_st_X509_EXTENSION */
            	4017, 0,
            0, 32, 2, /* 4017: struct.stack_st_fake_X509_EXTENSION */
            	4024, 8,
            	125, 24,
            8884099, 8, 2, /* 4024: pointer_to_array_of_pointers_to_stack */
            	4031, 0,
            	122, 20,
            0, 8, 1, /* 4031: pointer.X509_EXTENSION */
            	2628, 0,
            1, 8, 1, /* 4036: pointer.struct.stack_st_GENERAL_NAME */
            	4041, 0,
            0, 32, 2, /* 4041: struct.stack_st_fake_GENERAL_NAME */
            	4048, 8,
            	125, 24,
            8884099, 8, 2, /* 4048: pointer_to_array_of_pointers_to_stack */
            	4055, 0,
            	122, 20,
            0, 8, 1, /* 4055: pointer.GENERAL_NAME */
            	2744, 0,
            1, 8, 1, /* 4060: pointer.struct.ISSUING_DIST_POINT_st */
            	4065, 0,
            0, 32, 2, /* 4065: struct.ISSUING_DIST_POINT_st */
            	4072, 0,
            	4163, 16,
            1, 8, 1, /* 4072: pointer.struct.DIST_POINT_NAME_st */
            	4077, 0,
            0, 24, 2, /* 4077: struct.DIST_POINT_NAME_st */
            	4084, 8,
            	4139, 16,
            0, 8, 2, /* 4084: union.unknown */
            	4091, 0,
            	4115, 0,
            1, 8, 1, /* 4091: pointer.struct.stack_st_GENERAL_NAME */
            	4096, 0,
            0, 32, 2, /* 4096: struct.stack_st_fake_GENERAL_NAME */
            	4103, 8,
            	125, 24,
            8884099, 8, 2, /* 4103: pointer_to_array_of_pointers_to_stack */
            	4110, 0,
            	122, 20,
            0, 8, 1, /* 4110: pointer.GENERAL_NAME */
            	2744, 0,
            1, 8, 1, /* 4115: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4120, 0,
            0, 32, 2, /* 4120: struct.stack_st_fake_X509_NAME_ENTRY */
            	4127, 8,
            	125, 24,
            8884099, 8, 2, /* 4127: pointer_to_array_of_pointers_to_stack */
            	4134, 0,
            	122, 20,
            0, 8, 1, /* 4134: pointer.X509_NAME_ENTRY */
            	73, 0,
            1, 8, 1, /* 4139: pointer.struct.X509_name_st */
            	4144, 0,
            0, 40, 3, /* 4144: struct.X509_name_st */
            	4115, 0,
            	4153, 16,
            	117, 24,
            1, 8, 1, /* 4153: pointer.struct.buf_mem_st */
            	4158, 0,
            0, 24, 1, /* 4158: struct.buf_mem_st */
            	138, 8,
            1, 8, 1, /* 4163: pointer.struct.asn1_string_st */
            	4168, 0,
            0, 24, 1, /* 4168: struct.asn1_string_st */
            	117, 8,
            1, 8, 1, /* 4173: pointer.struct.stack_st_GENERAL_NAMES */
            	4178, 0,
            0, 32, 2, /* 4178: struct.stack_st_fake_GENERAL_NAMES */
            	4185, 8,
            	125, 24,
            8884099, 8, 2, /* 4185: pointer_to_array_of_pointers_to_stack */
            	4192, 0,
            	122, 20,
            0, 8, 1, /* 4192: pointer.GENERAL_NAMES */
            	4197, 0,
            0, 0, 1, /* 4197: GENERAL_NAMES */
            	4202, 0,
            0, 32, 1, /* 4202: struct.stack_st_GENERAL_NAME */
            	4207, 0,
            0, 32, 2, /* 4207: struct.stack_st */
            	1215, 8,
            	125, 24,
            1, 8, 1, /* 4214: pointer.struct.x509_crl_method_st */
            	4219, 0,
            0, 40, 4, /* 4219: struct.x509_crl_method_st */
            	4230, 8,
            	4230, 16,
            	4233, 24,
            	4236, 32,
            8884097, 8, 0, /* 4230: pointer.func */
            8884097, 8, 0, /* 4233: pointer.func */
            8884097, 8, 0, /* 4236: pointer.func */
            1, 8, 1, /* 4239: pointer.struct.evp_pkey_st */
            	4244, 0,
            0, 56, 4, /* 4244: struct.evp_pkey_st */
            	4255, 16,
            	4260, 24,
            	4265, 32,
            	4298, 48,
            1, 8, 1, /* 4255: pointer.struct.evp_pkey_asn1_method_st */
            	776, 0,
            1, 8, 1, /* 4260: pointer.struct.engine_st */
            	877, 0,
            0, 8, 5, /* 4265: union.unknown */
            	138, 0,
            	4278, 0,
            	4283, 0,
            	4288, 0,
            	4293, 0,
            1, 8, 1, /* 4278: pointer.struct.rsa_st */
            	1243, 0,
            1, 8, 1, /* 4283: pointer.struct.dsa_st */
            	1459, 0,
            1, 8, 1, /* 4288: pointer.struct.dh_st */
            	1598, 0,
            1, 8, 1, /* 4293: pointer.struct.ec_key_st */
            	1724, 0,
            1, 8, 1, /* 4298: pointer.struct.stack_st_X509_ATTRIBUTE */
            	4303, 0,
            0, 32, 2, /* 4303: struct.stack_st_fake_X509_ATTRIBUTE */
            	4310, 8,
            	125, 24,
            8884099, 8, 2, /* 4310: pointer_to_array_of_pointers_to_stack */
            	4317, 0,
            	122, 20,
            0, 8, 1, /* 4317: pointer.X509_ATTRIBUTE */
            	2252, 0,
            0, 144, 15, /* 4322: struct.x509_store_st */
            	377, 8,
            	4355, 16,
            	327, 24,
            	324, 32,
            	321, 40,
            	4447, 48,
            	4450, 56,
            	324, 64,
            	4453, 72,
            	4456, 80,
            	4459, 88,
            	318, 96,
            	4462, 104,
            	324, 112,
            	2669, 120,
            1, 8, 1, /* 4355: pointer.struct.stack_st_X509_LOOKUP */
            	4360, 0,
            0, 32, 2, /* 4360: struct.stack_st_fake_X509_LOOKUP */
            	4367, 8,
            	125, 24,
            8884099, 8, 2, /* 4367: pointer_to_array_of_pointers_to_stack */
            	4374, 0,
            	122, 20,
            0, 8, 1, /* 4374: pointer.X509_LOOKUP */
            	4379, 0,
            0, 0, 1, /* 4379: X509_LOOKUP */
            	4384, 0,
            0, 32, 3, /* 4384: struct.x509_lookup_st */
            	4393, 8,
            	138, 16,
            	4442, 24,
            1, 8, 1, /* 4393: pointer.struct.x509_lookup_method_st */
            	4398, 0,
            0, 80, 10, /* 4398: struct.x509_lookup_method_st */
            	5, 0,
            	4421, 8,
            	4424, 16,
            	4421, 24,
            	4421, 32,
            	4427, 40,
            	4430, 48,
            	4433, 56,
            	4436, 64,
            	4439, 72,
            8884097, 8, 0, /* 4421: pointer.func */
            8884097, 8, 0, /* 4424: pointer.func */
            8884097, 8, 0, /* 4427: pointer.func */
            8884097, 8, 0, /* 4430: pointer.func */
            8884097, 8, 0, /* 4433: pointer.func */
            8884097, 8, 0, /* 4436: pointer.func */
            8884097, 8, 0, /* 4439: pointer.func */
            1, 8, 1, /* 4442: pointer.struct.x509_store_st */
            	4322, 0,
            8884097, 8, 0, /* 4447: pointer.func */
            8884097, 8, 0, /* 4450: pointer.func */
            8884097, 8, 0, /* 4453: pointer.func */
            8884097, 8, 0, /* 4456: pointer.func */
            8884097, 8, 0, /* 4459: pointer.func */
            8884097, 8, 0, /* 4462: pointer.func */
            1, 8, 1, /* 4465: pointer.struct.stack_st_X509_LOOKUP */
            	4470, 0,
            0, 32, 2, /* 4470: struct.stack_st_fake_X509_LOOKUP */
            	4477, 8,
            	125, 24,
            8884099, 8, 2, /* 4477: pointer_to_array_of_pointers_to_stack */
            	4484, 0,
            	122, 20,
            0, 8, 1, /* 4484: pointer.X509_LOOKUP */
            	4379, 0,
            1, 8, 1, /* 4489: pointer.struct.stack_st_X509_OBJECT */
            	4494, 0,
            0, 32, 2, /* 4494: struct.stack_st_fake_X509_OBJECT */
            	4501, 8,
            	125, 24,
            8884099, 8, 2, /* 4501: pointer_to_array_of_pointers_to_stack */
            	4508, 0,
            	122, 20,
            0, 8, 1, /* 4508: pointer.X509_OBJECT */
            	401, 0,
            1, 8, 1, /* 4513: pointer.struct.ssl_ctx_st */
            	4518, 0,
            0, 736, 50, /* 4518: struct.ssl_ctx_st */
            	4621, 0,
            	4787, 8,
            	4787, 16,
            	4821, 24,
            	298, 32,
            	4929, 48,
            	4929, 56,
            	264, 80,
            	6091, 88,
            	6094, 96,
            	261, 152,
            	15, 160,
            	258, 168,
            	15, 176,
            	255, 184,
            	6097, 192,
            	6100, 200,
            	4907, 208,
            	6103, 224,
            	6103, 232,
            	6103, 240,
            	6142, 248,
            	6166, 256,
            	6190, 264,
            	6193, 272,
            	6265, 304,
            	6706, 320,
            	15, 328,
            	4898, 376,
            	6709, 384,
            	4859, 392,
            	5726, 408,
            	6712, 416,
            	15, 424,
            	6715, 480,
            	6718, 488,
            	15, 496,
            	206, 504,
            	15, 512,
            	138, 520,
            	6721, 528,
            	6724, 536,
            	186, 552,
            	186, 560,
            	6727, 568,
            	6761, 696,
            	15, 704,
            	163, 712,
            	15, 720,
            	6764, 728,
            1, 8, 1, /* 4621: pointer.struct.ssl_method_st */
            	4626, 0,
            0, 232, 28, /* 4626: struct.ssl_method_st */
            	4685, 8,
            	4688, 16,
            	4688, 24,
            	4685, 32,
            	4685, 40,
            	4691, 48,
            	4691, 56,
            	4694, 64,
            	4685, 72,
            	4685, 80,
            	4685, 88,
            	4697, 96,
            	4700, 104,
            	4703, 112,
            	4685, 120,
            	4706, 128,
            	4709, 136,
            	4712, 144,
            	4715, 152,
            	4718, 160,
            	1146, 168,
            	4721, 176,
            	4724, 184,
            	235, 192,
            	4727, 200,
            	1146, 208,
            	4781, 216,
            	4784, 224,
            8884097, 8, 0, /* 4685: pointer.func */
            8884097, 8, 0, /* 4688: pointer.func */
            8884097, 8, 0, /* 4691: pointer.func */
            8884097, 8, 0, /* 4694: pointer.func */
            8884097, 8, 0, /* 4697: pointer.func */
            8884097, 8, 0, /* 4700: pointer.func */
            8884097, 8, 0, /* 4703: pointer.func */
            8884097, 8, 0, /* 4706: pointer.func */
            8884097, 8, 0, /* 4709: pointer.func */
            8884097, 8, 0, /* 4712: pointer.func */
            8884097, 8, 0, /* 4715: pointer.func */
            8884097, 8, 0, /* 4718: pointer.func */
            8884097, 8, 0, /* 4721: pointer.func */
            8884097, 8, 0, /* 4724: pointer.func */
            1, 8, 1, /* 4727: pointer.struct.ssl3_enc_method */
            	4732, 0,
            0, 112, 11, /* 4732: struct.ssl3_enc_method */
            	4757, 0,
            	4760, 8,
            	4763, 16,
            	4766, 24,
            	4757, 32,
            	4769, 40,
            	4772, 56,
            	5, 64,
            	5, 80,
            	4775, 96,
            	4778, 104,
            8884097, 8, 0, /* 4757: pointer.func */
            8884097, 8, 0, /* 4760: pointer.func */
            8884097, 8, 0, /* 4763: pointer.func */
            8884097, 8, 0, /* 4766: pointer.func */
            8884097, 8, 0, /* 4769: pointer.func */
            8884097, 8, 0, /* 4772: pointer.func */
            8884097, 8, 0, /* 4775: pointer.func */
            8884097, 8, 0, /* 4778: pointer.func */
            8884097, 8, 0, /* 4781: pointer.func */
            8884097, 8, 0, /* 4784: pointer.func */
            1, 8, 1, /* 4787: pointer.struct.stack_st_SSL_CIPHER */
            	4792, 0,
            0, 32, 2, /* 4792: struct.stack_st_fake_SSL_CIPHER */
            	4799, 8,
            	125, 24,
            8884099, 8, 2, /* 4799: pointer_to_array_of_pointers_to_stack */
            	4806, 0,
            	122, 20,
            0, 8, 1, /* 4806: pointer.SSL_CIPHER */
            	4811, 0,
            0, 0, 1, /* 4811: SSL_CIPHER */
            	4816, 0,
            0, 88, 1, /* 4816: struct.ssl_cipher_st */
            	5, 8,
            1, 8, 1, /* 4821: pointer.struct.x509_store_st */
            	4826, 0,
            0, 144, 15, /* 4826: struct.x509_store_st */
            	4489, 8,
            	4465, 16,
            	4859, 24,
            	4895, 32,
            	4898, 40,
            	4901, 48,
            	315, 56,
            	4895, 64,
            	312, 72,
            	309, 80,
            	306, 88,
            	303, 96,
            	4904, 104,
            	4895, 112,
            	4907, 120,
            1, 8, 1, /* 4859: pointer.struct.X509_VERIFY_PARAM_st */
            	4864, 0,
            0, 56, 2, /* 4864: struct.X509_VERIFY_PARAM_st */
            	138, 0,
            	4871, 48,
            1, 8, 1, /* 4871: pointer.struct.stack_st_ASN1_OBJECT */
            	4876, 0,
            0, 32, 2, /* 4876: struct.stack_st_fake_ASN1_OBJECT */
            	4883, 8,
            	125, 24,
            8884099, 8, 2, /* 4883: pointer_to_array_of_pointers_to_stack */
            	4890, 0,
            	122, 20,
            0, 8, 1, /* 4890: pointer.ASN1_OBJECT */
            	363, 0,
            8884097, 8, 0, /* 4895: pointer.func */
            8884097, 8, 0, /* 4898: pointer.func */
            8884097, 8, 0, /* 4901: pointer.func */
            8884097, 8, 0, /* 4904: pointer.func */
            0, 16, 1, /* 4907: struct.crypto_ex_data_st */
            	4912, 0,
            1, 8, 1, /* 4912: pointer.struct.stack_st_void */
            	4917, 0,
            0, 32, 1, /* 4917: struct.stack_st_void */
            	4922, 0,
            0, 32, 2, /* 4922: struct.stack_st */
            	1215, 8,
            	125, 24,
            1, 8, 1, /* 4929: pointer.struct.ssl_session_st */
            	4934, 0,
            0, 352, 14, /* 4934: struct.ssl_session_st */
            	138, 144,
            	138, 152,
            	4965, 168,
            	5848, 176,
            	6081, 224,
            	4787, 240,
            	4907, 248,
            	4929, 264,
            	4929, 272,
            	138, 280,
            	117, 296,
            	117, 312,
            	117, 320,
            	138, 344,
            1, 8, 1, /* 4965: pointer.struct.sess_cert_st */
            	4970, 0,
            0, 248, 5, /* 4970: struct.sess_cert_st */
            	4983, 0,
            	5349, 16,
            	5833, 216,
            	5838, 224,
            	5843, 232,
            1, 8, 1, /* 4983: pointer.struct.stack_st_X509 */
            	4988, 0,
            0, 32, 2, /* 4988: struct.stack_st_fake_X509 */
            	4995, 8,
            	125, 24,
            8884099, 8, 2, /* 4995: pointer_to_array_of_pointers_to_stack */
            	5002, 0,
            	122, 20,
            0, 8, 1, /* 5002: pointer.X509 */
            	5007, 0,
            0, 0, 1, /* 5007: X509 */
            	5012, 0,
            0, 184, 12, /* 5012: struct.x509_st */
            	5039, 0,
            	5079, 8,
            	5154, 16,
            	138, 32,
            	5188, 40,
            	5210, 104,
            	5215, 112,
            	5220, 120,
            	5225, 128,
            	5249, 136,
            	5273, 144,
            	5278, 176,
            1, 8, 1, /* 5039: pointer.struct.x509_cinf_st */
            	5044, 0,
            0, 104, 11, /* 5044: struct.x509_cinf_st */
            	5069, 0,
            	5069, 8,
            	5079, 16,
            	5084, 24,
            	5132, 32,
            	5084, 40,
            	5149, 48,
            	5154, 56,
            	5154, 64,
            	5159, 72,
            	5183, 80,
            1, 8, 1, /* 5069: pointer.struct.asn1_string_st */
            	5074, 0,
            0, 24, 1, /* 5074: struct.asn1_string_st */
            	117, 8,
            1, 8, 1, /* 5079: pointer.struct.X509_algor_st */
            	499, 0,
            1, 8, 1, /* 5084: pointer.struct.X509_name_st */
            	5089, 0,
            0, 40, 3, /* 5089: struct.X509_name_st */
            	5098, 0,
            	5122, 16,
            	117, 24,
            1, 8, 1, /* 5098: pointer.struct.stack_st_X509_NAME_ENTRY */
            	5103, 0,
            0, 32, 2, /* 5103: struct.stack_st_fake_X509_NAME_ENTRY */
            	5110, 8,
            	125, 24,
            8884099, 8, 2, /* 5110: pointer_to_array_of_pointers_to_stack */
            	5117, 0,
            	122, 20,
            0, 8, 1, /* 5117: pointer.X509_NAME_ENTRY */
            	73, 0,
            1, 8, 1, /* 5122: pointer.struct.buf_mem_st */
            	5127, 0,
            0, 24, 1, /* 5127: struct.buf_mem_st */
            	138, 8,
            1, 8, 1, /* 5132: pointer.struct.X509_val_st */
            	5137, 0,
            0, 16, 2, /* 5137: struct.X509_val_st */
            	5144, 0,
            	5144, 8,
            1, 8, 1, /* 5144: pointer.struct.asn1_string_st */
            	5074, 0,
            1, 8, 1, /* 5149: pointer.struct.X509_pubkey_st */
            	731, 0,
            1, 8, 1, /* 5154: pointer.struct.asn1_string_st */
            	5074, 0,
            1, 8, 1, /* 5159: pointer.struct.stack_st_X509_EXTENSION */
            	5164, 0,
            0, 32, 2, /* 5164: struct.stack_st_fake_X509_EXTENSION */
            	5171, 8,
            	125, 24,
            8884099, 8, 2, /* 5171: pointer_to_array_of_pointers_to_stack */
            	5178, 0,
            	122, 20,
            0, 8, 1, /* 5178: pointer.X509_EXTENSION */
            	2628, 0,
            0, 24, 1, /* 5183: struct.ASN1_ENCODING_st */
            	117, 0,
            0, 16, 1, /* 5188: struct.crypto_ex_data_st */
            	5193, 0,
            1, 8, 1, /* 5193: pointer.struct.stack_st_void */
            	5198, 0,
            0, 32, 1, /* 5198: struct.stack_st_void */
            	5203, 0,
            0, 32, 2, /* 5203: struct.stack_st */
            	1215, 8,
            	125, 24,
            1, 8, 1, /* 5210: pointer.struct.asn1_string_st */
            	5074, 0,
            1, 8, 1, /* 5215: pointer.struct.AUTHORITY_KEYID_st */
            	2701, 0,
            1, 8, 1, /* 5220: pointer.struct.X509_POLICY_CACHE_st */
            	2966, 0,
            1, 8, 1, /* 5225: pointer.struct.stack_st_DIST_POINT */
            	5230, 0,
            0, 32, 2, /* 5230: struct.stack_st_fake_DIST_POINT */
            	5237, 8,
            	125, 24,
            8884099, 8, 2, /* 5237: pointer_to_array_of_pointers_to_stack */
            	5244, 0,
            	122, 20,
            0, 8, 1, /* 5244: pointer.DIST_POINT */
            	3402, 0,
            1, 8, 1, /* 5249: pointer.struct.stack_st_GENERAL_NAME */
            	5254, 0,
            0, 32, 2, /* 5254: struct.stack_st_fake_GENERAL_NAME */
            	5261, 8,
            	125, 24,
            8884099, 8, 2, /* 5261: pointer_to_array_of_pointers_to_stack */
            	5268, 0,
            	122, 20,
            0, 8, 1, /* 5268: pointer.GENERAL_NAME */
            	2744, 0,
            1, 8, 1, /* 5273: pointer.struct.NAME_CONSTRAINTS_st */
            	3546, 0,
            1, 8, 1, /* 5278: pointer.struct.x509_cert_aux_st */
            	5283, 0,
            0, 40, 5, /* 5283: struct.x509_cert_aux_st */
            	5296, 0,
            	5296, 8,
            	5320, 16,
            	5210, 24,
            	5325, 32,
            1, 8, 1, /* 5296: pointer.struct.stack_st_ASN1_OBJECT */
            	5301, 0,
            0, 32, 2, /* 5301: struct.stack_st_fake_ASN1_OBJECT */
            	5308, 8,
            	125, 24,
            8884099, 8, 2, /* 5308: pointer_to_array_of_pointers_to_stack */
            	5315, 0,
            	122, 20,
            0, 8, 1, /* 5315: pointer.ASN1_OBJECT */
            	363, 0,
            1, 8, 1, /* 5320: pointer.struct.asn1_string_st */
            	5074, 0,
            1, 8, 1, /* 5325: pointer.struct.stack_st_X509_ALGOR */
            	5330, 0,
            0, 32, 2, /* 5330: struct.stack_st_fake_X509_ALGOR */
            	5337, 8,
            	125, 24,
            8884099, 8, 2, /* 5337: pointer_to_array_of_pointers_to_stack */
            	5344, 0,
            	122, 20,
            0, 8, 1, /* 5344: pointer.X509_ALGOR */
            	3900, 0,
            1, 8, 1, /* 5349: pointer.struct.cert_pkey_st */
            	5354, 0,
            0, 24, 3, /* 5354: struct.cert_pkey_st */
            	5363, 0,
            	5705, 8,
            	5788, 16,
            1, 8, 1, /* 5363: pointer.struct.x509_st */
            	5368, 0,
            0, 184, 12, /* 5368: struct.x509_st */
            	5395, 0,
            	5435, 8,
            	5510, 16,
            	138, 32,
            	5544, 40,
            	5566, 104,
            	5571, 112,
            	5576, 120,
            	5581, 128,
            	5605, 136,
            	5629, 144,
            	5634, 176,
            1, 8, 1, /* 5395: pointer.struct.x509_cinf_st */
            	5400, 0,
            0, 104, 11, /* 5400: struct.x509_cinf_st */
            	5425, 0,
            	5425, 8,
            	5435, 16,
            	5440, 24,
            	5488, 32,
            	5440, 40,
            	5505, 48,
            	5510, 56,
            	5510, 64,
            	5515, 72,
            	5539, 80,
            1, 8, 1, /* 5425: pointer.struct.asn1_string_st */
            	5430, 0,
            0, 24, 1, /* 5430: struct.asn1_string_st */
            	117, 8,
            1, 8, 1, /* 5435: pointer.struct.X509_algor_st */
            	499, 0,
            1, 8, 1, /* 5440: pointer.struct.X509_name_st */
            	5445, 0,
            0, 40, 3, /* 5445: struct.X509_name_st */
            	5454, 0,
            	5478, 16,
            	117, 24,
            1, 8, 1, /* 5454: pointer.struct.stack_st_X509_NAME_ENTRY */
            	5459, 0,
            0, 32, 2, /* 5459: struct.stack_st_fake_X509_NAME_ENTRY */
            	5466, 8,
            	125, 24,
            8884099, 8, 2, /* 5466: pointer_to_array_of_pointers_to_stack */
            	5473, 0,
            	122, 20,
            0, 8, 1, /* 5473: pointer.X509_NAME_ENTRY */
            	73, 0,
            1, 8, 1, /* 5478: pointer.struct.buf_mem_st */
            	5483, 0,
            0, 24, 1, /* 5483: struct.buf_mem_st */
            	138, 8,
            1, 8, 1, /* 5488: pointer.struct.X509_val_st */
            	5493, 0,
            0, 16, 2, /* 5493: struct.X509_val_st */
            	5500, 0,
            	5500, 8,
            1, 8, 1, /* 5500: pointer.struct.asn1_string_st */
            	5430, 0,
            1, 8, 1, /* 5505: pointer.struct.X509_pubkey_st */
            	731, 0,
            1, 8, 1, /* 5510: pointer.struct.asn1_string_st */
            	5430, 0,
            1, 8, 1, /* 5515: pointer.struct.stack_st_X509_EXTENSION */
            	5520, 0,
            0, 32, 2, /* 5520: struct.stack_st_fake_X509_EXTENSION */
            	5527, 8,
            	125, 24,
            8884099, 8, 2, /* 5527: pointer_to_array_of_pointers_to_stack */
            	5534, 0,
            	122, 20,
            0, 8, 1, /* 5534: pointer.X509_EXTENSION */
            	2628, 0,
            0, 24, 1, /* 5539: struct.ASN1_ENCODING_st */
            	117, 0,
            0, 16, 1, /* 5544: struct.crypto_ex_data_st */
            	5549, 0,
            1, 8, 1, /* 5549: pointer.struct.stack_st_void */
            	5554, 0,
            0, 32, 1, /* 5554: struct.stack_st_void */
            	5559, 0,
            0, 32, 2, /* 5559: struct.stack_st */
            	1215, 8,
            	125, 24,
            1, 8, 1, /* 5566: pointer.struct.asn1_string_st */
            	5430, 0,
            1, 8, 1, /* 5571: pointer.struct.AUTHORITY_KEYID_st */
            	2701, 0,
            1, 8, 1, /* 5576: pointer.struct.X509_POLICY_CACHE_st */
            	2966, 0,
            1, 8, 1, /* 5581: pointer.struct.stack_st_DIST_POINT */
            	5586, 0,
            0, 32, 2, /* 5586: struct.stack_st_fake_DIST_POINT */
            	5593, 8,
            	125, 24,
            8884099, 8, 2, /* 5593: pointer_to_array_of_pointers_to_stack */
            	5600, 0,
            	122, 20,
            0, 8, 1, /* 5600: pointer.DIST_POINT */
            	3402, 0,
            1, 8, 1, /* 5605: pointer.struct.stack_st_GENERAL_NAME */
            	5610, 0,
            0, 32, 2, /* 5610: struct.stack_st_fake_GENERAL_NAME */
            	5617, 8,
            	125, 24,
            8884099, 8, 2, /* 5617: pointer_to_array_of_pointers_to_stack */
            	5624, 0,
            	122, 20,
            0, 8, 1, /* 5624: pointer.GENERAL_NAME */
            	2744, 0,
            1, 8, 1, /* 5629: pointer.struct.NAME_CONSTRAINTS_st */
            	3546, 0,
            1, 8, 1, /* 5634: pointer.struct.x509_cert_aux_st */
            	5639, 0,
            0, 40, 5, /* 5639: struct.x509_cert_aux_st */
            	5652, 0,
            	5652, 8,
            	5676, 16,
            	5566, 24,
            	5681, 32,
            1, 8, 1, /* 5652: pointer.struct.stack_st_ASN1_OBJECT */
            	5657, 0,
            0, 32, 2, /* 5657: struct.stack_st_fake_ASN1_OBJECT */
            	5664, 8,
            	125, 24,
            8884099, 8, 2, /* 5664: pointer_to_array_of_pointers_to_stack */
            	5671, 0,
            	122, 20,
            0, 8, 1, /* 5671: pointer.ASN1_OBJECT */
            	363, 0,
            1, 8, 1, /* 5676: pointer.struct.asn1_string_st */
            	5430, 0,
            1, 8, 1, /* 5681: pointer.struct.stack_st_X509_ALGOR */
            	5686, 0,
            0, 32, 2, /* 5686: struct.stack_st_fake_X509_ALGOR */
            	5693, 8,
            	125, 24,
            8884099, 8, 2, /* 5693: pointer_to_array_of_pointers_to_stack */
            	5700, 0,
            	122, 20,
            0, 8, 1, /* 5700: pointer.X509_ALGOR */
            	3900, 0,
            1, 8, 1, /* 5705: pointer.struct.evp_pkey_st */
            	5710, 0,
            0, 56, 4, /* 5710: struct.evp_pkey_st */
            	5721, 16,
            	5726, 24,
            	5731, 32,
            	5764, 48,
            1, 8, 1, /* 5721: pointer.struct.evp_pkey_asn1_method_st */
            	776, 0,
            1, 8, 1, /* 5726: pointer.struct.engine_st */
            	877, 0,
            0, 8, 5, /* 5731: union.unknown */
            	138, 0,
            	5744, 0,
            	5749, 0,
            	5754, 0,
            	5759, 0,
            1, 8, 1, /* 5744: pointer.struct.rsa_st */
            	1243, 0,
            1, 8, 1, /* 5749: pointer.struct.dsa_st */
            	1459, 0,
            1, 8, 1, /* 5754: pointer.struct.dh_st */
            	1598, 0,
            1, 8, 1, /* 5759: pointer.struct.ec_key_st */
            	1724, 0,
            1, 8, 1, /* 5764: pointer.struct.stack_st_X509_ATTRIBUTE */
            	5769, 0,
            0, 32, 2, /* 5769: struct.stack_st_fake_X509_ATTRIBUTE */
            	5776, 8,
            	125, 24,
            8884099, 8, 2, /* 5776: pointer_to_array_of_pointers_to_stack */
            	5783, 0,
            	122, 20,
            0, 8, 1, /* 5783: pointer.X509_ATTRIBUTE */
            	2252, 0,
            1, 8, 1, /* 5788: pointer.struct.env_md_st */
            	5793, 0,
            0, 120, 8, /* 5793: struct.env_md_st */
            	5812, 24,
            	5815, 32,
            	5818, 40,
            	5821, 48,
            	5812, 56,
            	5824, 64,
            	5827, 72,
            	5830, 112,
            8884097, 8, 0, /* 5812: pointer.func */
            8884097, 8, 0, /* 5815: pointer.func */
            8884097, 8, 0, /* 5818: pointer.func */
            8884097, 8, 0, /* 5821: pointer.func */
            8884097, 8, 0, /* 5824: pointer.func */
            8884097, 8, 0, /* 5827: pointer.func */
            8884097, 8, 0, /* 5830: pointer.func */
            1, 8, 1, /* 5833: pointer.struct.rsa_st */
            	1243, 0,
            1, 8, 1, /* 5838: pointer.struct.dh_st */
            	1598, 0,
            1, 8, 1, /* 5843: pointer.struct.ec_key_st */
            	1724, 0,
            1, 8, 1, /* 5848: pointer.struct.x509_st */
            	5853, 0,
            0, 184, 12, /* 5853: struct.x509_st */
            	5880, 0,
            	5920, 8,
            	5995, 16,
            	138, 32,
            	4907, 40,
            	6029, 104,
            	5571, 112,
            	5576, 120,
            	5581, 128,
            	5605, 136,
            	5629, 144,
            	6034, 176,
            1, 8, 1, /* 5880: pointer.struct.x509_cinf_st */
            	5885, 0,
            0, 104, 11, /* 5885: struct.x509_cinf_st */
            	5910, 0,
            	5910, 8,
            	5920, 16,
            	5925, 24,
            	5973, 32,
            	5925, 40,
            	5990, 48,
            	5995, 56,
            	5995, 64,
            	6000, 72,
            	6024, 80,
            1, 8, 1, /* 5910: pointer.struct.asn1_string_st */
            	5915, 0,
            0, 24, 1, /* 5915: struct.asn1_string_st */
            	117, 8,
            1, 8, 1, /* 5920: pointer.struct.X509_algor_st */
            	499, 0,
            1, 8, 1, /* 5925: pointer.struct.X509_name_st */
            	5930, 0,
            0, 40, 3, /* 5930: struct.X509_name_st */
            	5939, 0,
            	5963, 16,
            	117, 24,
            1, 8, 1, /* 5939: pointer.struct.stack_st_X509_NAME_ENTRY */
            	5944, 0,
            0, 32, 2, /* 5944: struct.stack_st_fake_X509_NAME_ENTRY */
            	5951, 8,
            	125, 24,
            8884099, 8, 2, /* 5951: pointer_to_array_of_pointers_to_stack */
            	5958, 0,
            	122, 20,
            0, 8, 1, /* 5958: pointer.X509_NAME_ENTRY */
            	73, 0,
            1, 8, 1, /* 5963: pointer.struct.buf_mem_st */
            	5968, 0,
            0, 24, 1, /* 5968: struct.buf_mem_st */
            	138, 8,
            1, 8, 1, /* 5973: pointer.struct.X509_val_st */
            	5978, 0,
            0, 16, 2, /* 5978: struct.X509_val_st */
            	5985, 0,
            	5985, 8,
            1, 8, 1, /* 5985: pointer.struct.asn1_string_st */
            	5915, 0,
            1, 8, 1, /* 5990: pointer.struct.X509_pubkey_st */
            	731, 0,
            1, 8, 1, /* 5995: pointer.struct.asn1_string_st */
            	5915, 0,
            1, 8, 1, /* 6000: pointer.struct.stack_st_X509_EXTENSION */
            	6005, 0,
            0, 32, 2, /* 6005: struct.stack_st_fake_X509_EXTENSION */
            	6012, 8,
            	125, 24,
            8884099, 8, 2, /* 6012: pointer_to_array_of_pointers_to_stack */
            	6019, 0,
            	122, 20,
            0, 8, 1, /* 6019: pointer.X509_EXTENSION */
            	2628, 0,
            0, 24, 1, /* 6024: struct.ASN1_ENCODING_st */
            	117, 0,
            1, 8, 1, /* 6029: pointer.struct.asn1_string_st */
            	5915, 0,
            1, 8, 1, /* 6034: pointer.struct.x509_cert_aux_st */
            	6039, 0,
            0, 40, 5, /* 6039: struct.x509_cert_aux_st */
            	4871, 0,
            	4871, 8,
            	6052, 16,
            	6029, 24,
            	6057, 32,
            1, 8, 1, /* 6052: pointer.struct.asn1_string_st */
            	5915, 0,
            1, 8, 1, /* 6057: pointer.struct.stack_st_X509_ALGOR */
            	6062, 0,
            0, 32, 2, /* 6062: struct.stack_st_fake_X509_ALGOR */
            	6069, 8,
            	125, 24,
            8884099, 8, 2, /* 6069: pointer_to_array_of_pointers_to_stack */
            	6076, 0,
            	122, 20,
            0, 8, 1, /* 6076: pointer.X509_ALGOR */
            	3900, 0,
            1, 8, 1, /* 6081: pointer.struct.ssl_cipher_st */
            	6086, 0,
            0, 88, 1, /* 6086: struct.ssl_cipher_st */
            	5, 8,
            8884097, 8, 0, /* 6091: pointer.func */
            8884097, 8, 0, /* 6094: pointer.func */
            8884097, 8, 0, /* 6097: pointer.func */
            8884097, 8, 0, /* 6100: pointer.func */
            1, 8, 1, /* 6103: pointer.struct.env_md_st */
            	6108, 0,
            0, 120, 8, /* 6108: struct.env_md_st */
            	6127, 24,
            	6130, 32,
            	6133, 40,
            	6136, 48,
            	6127, 56,
            	5824, 64,
            	5827, 72,
            	6139, 112,
            8884097, 8, 0, /* 6127: pointer.func */
            8884097, 8, 0, /* 6130: pointer.func */
            8884097, 8, 0, /* 6133: pointer.func */
            8884097, 8, 0, /* 6136: pointer.func */
            8884097, 8, 0, /* 6139: pointer.func */
            1, 8, 1, /* 6142: pointer.struct.stack_st_X509 */
            	6147, 0,
            0, 32, 2, /* 6147: struct.stack_st_fake_X509 */
            	6154, 8,
            	125, 24,
            8884099, 8, 2, /* 6154: pointer_to_array_of_pointers_to_stack */
            	6161, 0,
            	122, 20,
            0, 8, 1, /* 6161: pointer.X509 */
            	5007, 0,
            1, 8, 1, /* 6166: pointer.struct.stack_st_SSL_COMP */
            	6171, 0,
            0, 32, 2, /* 6171: struct.stack_st_fake_SSL_COMP */
            	6178, 8,
            	125, 24,
            8884099, 8, 2, /* 6178: pointer_to_array_of_pointers_to_stack */
            	6185, 0,
            	122, 20,
            0, 8, 1, /* 6185: pointer.SSL_COMP */
            	238, 0,
            8884097, 8, 0, /* 6190: pointer.func */
            1, 8, 1, /* 6193: pointer.struct.stack_st_X509_NAME */
            	6198, 0,
            0, 32, 2, /* 6198: struct.stack_st_fake_X509_NAME */
            	6205, 8,
            	125, 24,
            8884099, 8, 2, /* 6205: pointer_to_array_of_pointers_to_stack */
            	6212, 0,
            	122, 20,
            0, 8, 1, /* 6212: pointer.X509_NAME */
            	6217, 0,
            0, 0, 1, /* 6217: X509_NAME */
            	6222, 0,
            0, 40, 3, /* 6222: struct.X509_name_st */
            	6231, 0,
            	6255, 16,
            	117, 24,
            1, 8, 1, /* 6231: pointer.struct.stack_st_X509_NAME_ENTRY */
            	6236, 0,
            0, 32, 2, /* 6236: struct.stack_st_fake_X509_NAME_ENTRY */
            	6243, 8,
            	125, 24,
            8884099, 8, 2, /* 6243: pointer_to_array_of_pointers_to_stack */
            	6250, 0,
            	122, 20,
            0, 8, 1, /* 6250: pointer.X509_NAME_ENTRY */
            	73, 0,
            1, 8, 1, /* 6255: pointer.struct.buf_mem_st */
            	6260, 0,
            0, 24, 1, /* 6260: struct.buf_mem_st */
            	138, 8,
            1, 8, 1, /* 6265: pointer.struct.cert_st */
            	6270, 0,
            0, 296, 7, /* 6270: struct.cert_st */
            	6287, 0,
            	6687, 48,
            	6692, 56,
            	6695, 64,
            	6700, 72,
            	5843, 80,
            	6703, 88,
            1, 8, 1, /* 6287: pointer.struct.cert_pkey_st */
            	6292, 0,
            0, 24, 3, /* 6292: struct.cert_pkey_st */
            	6301, 0,
            	6580, 8,
            	6648, 16,
            1, 8, 1, /* 6301: pointer.struct.x509_st */
            	6306, 0,
            0, 184, 12, /* 6306: struct.x509_st */
            	6333, 0,
            	6373, 8,
            	6448, 16,
            	138, 32,
            	6482, 40,
            	6504, 104,
            	5571, 112,
            	5576, 120,
            	5581, 128,
            	5605, 136,
            	5629, 144,
            	6509, 176,
            1, 8, 1, /* 6333: pointer.struct.x509_cinf_st */
            	6338, 0,
            0, 104, 11, /* 6338: struct.x509_cinf_st */
            	6363, 0,
            	6363, 8,
            	6373, 16,
            	6378, 24,
            	6426, 32,
            	6378, 40,
            	6443, 48,
            	6448, 56,
            	6448, 64,
            	6453, 72,
            	6477, 80,
            1, 8, 1, /* 6363: pointer.struct.asn1_string_st */
            	6368, 0,
            0, 24, 1, /* 6368: struct.asn1_string_st */
            	117, 8,
            1, 8, 1, /* 6373: pointer.struct.X509_algor_st */
            	499, 0,
            1, 8, 1, /* 6378: pointer.struct.X509_name_st */
            	6383, 0,
            0, 40, 3, /* 6383: struct.X509_name_st */
            	6392, 0,
            	6416, 16,
            	117, 24,
            1, 8, 1, /* 6392: pointer.struct.stack_st_X509_NAME_ENTRY */
            	6397, 0,
            0, 32, 2, /* 6397: struct.stack_st_fake_X509_NAME_ENTRY */
            	6404, 8,
            	125, 24,
            8884099, 8, 2, /* 6404: pointer_to_array_of_pointers_to_stack */
            	6411, 0,
            	122, 20,
            0, 8, 1, /* 6411: pointer.X509_NAME_ENTRY */
            	73, 0,
            1, 8, 1, /* 6416: pointer.struct.buf_mem_st */
            	6421, 0,
            0, 24, 1, /* 6421: struct.buf_mem_st */
            	138, 8,
            1, 8, 1, /* 6426: pointer.struct.X509_val_st */
            	6431, 0,
            0, 16, 2, /* 6431: struct.X509_val_st */
            	6438, 0,
            	6438, 8,
            1, 8, 1, /* 6438: pointer.struct.asn1_string_st */
            	6368, 0,
            1, 8, 1, /* 6443: pointer.struct.X509_pubkey_st */
            	731, 0,
            1, 8, 1, /* 6448: pointer.struct.asn1_string_st */
            	6368, 0,
            1, 8, 1, /* 6453: pointer.struct.stack_st_X509_EXTENSION */
            	6458, 0,
            0, 32, 2, /* 6458: struct.stack_st_fake_X509_EXTENSION */
            	6465, 8,
            	125, 24,
            8884099, 8, 2, /* 6465: pointer_to_array_of_pointers_to_stack */
            	6472, 0,
            	122, 20,
            0, 8, 1, /* 6472: pointer.X509_EXTENSION */
            	2628, 0,
            0, 24, 1, /* 6477: struct.ASN1_ENCODING_st */
            	117, 0,
            0, 16, 1, /* 6482: struct.crypto_ex_data_st */
            	6487, 0,
            1, 8, 1, /* 6487: pointer.struct.stack_st_void */
            	6492, 0,
            0, 32, 1, /* 6492: struct.stack_st_void */
            	6497, 0,
            0, 32, 2, /* 6497: struct.stack_st */
            	1215, 8,
            	125, 24,
            1, 8, 1, /* 6504: pointer.struct.asn1_string_st */
            	6368, 0,
            1, 8, 1, /* 6509: pointer.struct.x509_cert_aux_st */
            	6514, 0,
            0, 40, 5, /* 6514: struct.x509_cert_aux_st */
            	6527, 0,
            	6527, 8,
            	6551, 16,
            	6504, 24,
            	6556, 32,
            1, 8, 1, /* 6527: pointer.struct.stack_st_ASN1_OBJECT */
            	6532, 0,
            0, 32, 2, /* 6532: struct.stack_st_fake_ASN1_OBJECT */
            	6539, 8,
            	125, 24,
            8884099, 8, 2, /* 6539: pointer_to_array_of_pointers_to_stack */
            	6546, 0,
            	122, 20,
            0, 8, 1, /* 6546: pointer.ASN1_OBJECT */
            	363, 0,
            1, 8, 1, /* 6551: pointer.struct.asn1_string_st */
            	6368, 0,
            1, 8, 1, /* 6556: pointer.struct.stack_st_X509_ALGOR */
            	6561, 0,
            0, 32, 2, /* 6561: struct.stack_st_fake_X509_ALGOR */
            	6568, 8,
            	125, 24,
            8884099, 8, 2, /* 6568: pointer_to_array_of_pointers_to_stack */
            	6575, 0,
            	122, 20,
            0, 8, 1, /* 6575: pointer.X509_ALGOR */
            	3900, 0,
            1, 8, 1, /* 6580: pointer.struct.evp_pkey_st */
            	6585, 0,
            0, 56, 4, /* 6585: struct.evp_pkey_st */
            	5721, 16,
            	5726, 24,
            	6596, 32,
            	6624, 48,
            0, 8, 5, /* 6596: union.unknown */
            	138, 0,
            	6609, 0,
            	6614, 0,
            	6619, 0,
            	5759, 0,
            1, 8, 1, /* 6609: pointer.struct.rsa_st */
            	1243, 0,
            1, 8, 1, /* 6614: pointer.struct.dsa_st */
            	1459, 0,
            1, 8, 1, /* 6619: pointer.struct.dh_st */
            	1598, 0,
            1, 8, 1, /* 6624: pointer.struct.stack_st_X509_ATTRIBUTE */
            	6629, 0,
            0, 32, 2, /* 6629: struct.stack_st_fake_X509_ATTRIBUTE */
            	6636, 8,
            	125, 24,
            8884099, 8, 2, /* 6636: pointer_to_array_of_pointers_to_stack */
            	6643, 0,
            	122, 20,
            0, 8, 1, /* 6643: pointer.X509_ATTRIBUTE */
            	2252, 0,
            1, 8, 1, /* 6648: pointer.struct.env_md_st */
            	6653, 0,
            0, 120, 8, /* 6653: struct.env_md_st */
            	6672, 24,
            	6675, 32,
            	6678, 40,
            	6681, 48,
            	6672, 56,
            	5824, 64,
            	5827, 72,
            	6684, 112,
            8884097, 8, 0, /* 6672: pointer.func */
            8884097, 8, 0, /* 6675: pointer.func */
            8884097, 8, 0, /* 6678: pointer.func */
            8884097, 8, 0, /* 6681: pointer.func */
            8884097, 8, 0, /* 6684: pointer.func */
            1, 8, 1, /* 6687: pointer.struct.rsa_st */
            	1243, 0,
            8884097, 8, 0, /* 6692: pointer.func */
            1, 8, 1, /* 6695: pointer.struct.dh_st */
            	1598, 0,
            8884097, 8, 0, /* 6700: pointer.func */
            8884097, 8, 0, /* 6703: pointer.func */
            8884097, 8, 0, /* 6706: pointer.func */
            8884097, 8, 0, /* 6709: pointer.func */
            8884097, 8, 0, /* 6712: pointer.func */
            8884097, 8, 0, /* 6715: pointer.func */
            8884097, 8, 0, /* 6718: pointer.func */
            8884097, 8, 0, /* 6721: pointer.func */
            8884097, 8, 0, /* 6724: pointer.func */
            0, 128, 14, /* 6727: struct.srp_ctx_st */
            	15, 0,
            	6712, 8,
            	6718, 16,
            	6758, 24,
            	138, 32,
            	181, 40,
            	181, 48,
            	181, 56,
            	181, 64,
            	181, 72,
            	181, 80,
            	181, 88,
            	181, 96,
            	138, 104,
            8884097, 8, 0, /* 6758: pointer.func */
            8884097, 8, 0, /* 6761: pointer.func */
            1, 8, 1, /* 6764: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	6769, 0,
            0, 32, 2, /* 6769: struct.stack_st_fake_SRTP_PROTECTION_PROFILE */
            	6776, 8,
            	125, 24,
            8884099, 8, 2, /* 6776: pointer_to_array_of_pointers_to_stack */
            	6783, 0,
            	122, 20,
            0, 8, 1, /* 6783: pointer.SRTP_PROTECTION_PROFILE */
            	158, 0,
            1, 8, 1, /* 6788: pointer.struct.tls_session_ticket_ext_st */
            	10, 0,
            1, 8, 1, /* 6793: pointer.struct.srtp_protection_profile_st */
            	0, 0,
            1, 8, 1, /* 6798: pointer.struct.stack_st_X509_ATTRIBUTE */
            	6803, 0,
            0, 32, 2, /* 6803: struct.stack_st_fake_X509_ATTRIBUTE */
            	6810, 8,
            	125, 24,
            8884099, 8, 2, /* 6810: pointer_to_array_of_pointers_to_stack */
            	6817, 0,
            	122, 20,
            0, 8, 1, /* 6817: pointer.X509_ATTRIBUTE */
            	2252, 0,
            8884097, 8, 0, /* 6822: pointer.func */
            8884097, 8, 0, /* 6825: pointer.func */
            1, 8, 1, /* 6828: pointer.struct.dh_st */
            	1598, 0,
            1, 8, 1, /* 6833: pointer.struct.ec_key_st */
            	1724, 0,
            1, 8, 1, /* 6838: pointer.struct.stack_st_X509_EXTENSION */
            	6843, 0,
            0, 32, 2, /* 6843: struct.stack_st_fake_X509_EXTENSION */
            	6850, 8,
            	125, 24,
            8884099, 8, 2, /* 6850: pointer_to_array_of_pointers_to_stack */
            	6857, 0,
            	122, 20,
            0, 8, 1, /* 6857: pointer.X509_EXTENSION */
            	2628, 0,
            8884097, 8, 0, /* 6862: pointer.func */
            1, 8, 1, /* 6865: pointer.struct.stack_st_OCSP_RESPID */
            	6870, 0,
            0, 32, 2, /* 6870: struct.stack_st_fake_OCSP_RESPID */
            	6877, 8,
            	125, 24,
            8884099, 8, 2, /* 6877: pointer_to_array_of_pointers_to_stack */
            	6884, 0,
            	122, 20,
            0, 8, 1, /* 6884: pointer.OCSP_RESPID */
            	18, 0,
            1, 8, 1, /* 6889: pointer.struct.rsa_st */
            	1243, 0,
            0, 16, 1, /* 6894: struct.record_pqueue_st */
            	6899, 8,
            1, 8, 1, /* 6899: pointer.struct._pqueue */
            	6904, 0,
            0, 16, 1, /* 6904: struct._pqueue */
            	6909, 0,
            1, 8, 1, /* 6909: pointer.struct._pitem */
            	6914, 0,
            0, 24, 2, /* 6914: struct._pitem */
            	15, 8,
            	6921, 16,
            1, 8, 1, /* 6921: pointer.struct._pitem */
            	6914, 0,
            1, 8, 1, /* 6926: pointer.struct.evp_pkey_asn1_method_st */
            	776, 0,
            1, 8, 1, /* 6931: pointer.struct.evp_pkey_st */
            	6936, 0,
            0, 56, 4, /* 6936: struct.evp_pkey_st */
            	6926, 16,
            	1714, 24,
            	6947, 32,
            	6798, 48,
            0, 8, 5, /* 6947: union.unknown */
            	138, 0,
            	6889, 0,
            	6960, 0,
            	6828, 0,
            	6833, 0,
            1, 8, 1, /* 6960: pointer.struct.dsa_st */
            	1459, 0,
            8884097, 8, 0, /* 6965: pointer.func */
            8884097, 8, 0, /* 6968: pointer.func */
            8884097, 8, 0, /* 6971: pointer.func */
            0, 80, 8, /* 6974: struct.evp_pkey_ctx_st */
            	6993, 0,
            	1714, 8,
            	6931, 16,
            	6931, 24,
            	15, 40,
            	15, 48,
            	7078, 56,
            	7081, 64,
            1, 8, 1, /* 6993: pointer.struct.evp_pkey_method_st */
            	6998, 0,
            0, 208, 25, /* 6998: struct.evp_pkey_method_st */
            	7051, 8,
            	7054, 16,
            	7057, 24,
            	7051, 32,
            	7060, 40,
            	7051, 48,
            	7060, 56,
            	7051, 64,
            	6971, 72,
            	7051, 80,
            	7063, 88,
            	7051, 96,
            	6971, 104,
            	6968, 112,
            	6965, 120,
            	6968, 128,
            	7066, 136,
            	7051, 144,
            	6971, 152,
            	7051, 160,
            	6971, 168,
            	7051, 176,
            	7069, 184,
            	7072, 192,
            	7075, 200,
            8884097, 8, 0, /* 7051: pointer.func */
            8884097, 8, 0, /* 7054: pointer.func */
            8884097, 8, 0, /* 7057: pointer.func */
            8884097, 8, 0, /* 7060: pointer.func */
            8884097, 8, 0, /* 7063: pointer.func */
            8884097, 8, 0, /* 7066: pointer.func */
            8884097, 8, 0, /* 7069: pointer.func */
            8884097, 8, 0, /* 7072: pointer.func */
            8884097, 8, 0, /* 7075: pointer.func */
            8884097, 8, 0, /* 7078: pointer.func */
            1, 8, 1, /* 7081: pointer.int */
            	122, 0,
            8884097, 8, 0, /* 7086: pointer.func */
            1, 8, 1, /* 7089: pointer.struct.bio_st */
            	7094, 0,
            0, 112, 7, /* 7094: struct.bio_st */
            	7111, 0,
            	7152, 8,
            	138, 16,
            	15, 48,
            	7089, 56,
            	7089, 64,
            	4907, 96,
            1, 8, 1, /* 7111: pointer.struct.bio_method_st */
            	7116, 0,
            0, 80, 9, /* 7116: struct.bio_method_st */
            	5, 8,
            	7137, 16,
            	7140, 24,
            	7143, 32,
            	7140, 40,
            	6825, 48,
            	7146, 56,
            	7146, 64,
            	7149, 72,
            8884097, 8, 0, /* 7137: pointer.func */
            8884097, 8, 0, /* 7140: pointer.func */
            8884097, 8, 0, /* 7143: pointer.func */
            8884097, 8, 0, /* 7146: pointer.func */
            8884097, 8, 0, /* 7149: pointer.func */
            8884097, 8, 0, /* 7152: pointer.func */
            1, 8, 1, /* 7155: pointer.struct.dh_st */
            	1598, 0,
            0, 1200, 10, /* 7160: struct.ssl3_state_st */
            	7183, 240,
            	7183, 264,
            	7188, 288,
            	7188, 344,
            	99, 432,
            	7197, 440,
            	7202, 448,
            	15, 496,
            	15, 512,
            	7230, 528,
            0, 24, 1, /* 7183: struct.ssl3_buffer_st */
            	117, 0,
            0, 56, 3, /* 7188: struct.ssl3_record_st */
            	117, 16,
            	117, 24,
            	117, 32,
            1, 8, 1, /* 7197: pointer.struct.bio_st */
            	7094, 0,
            1, 8, 1, /* 7202: pointer.pointer.struct.env_md_ctx_st */
            	7207, 0,
            1, 8, 1, /* 7207: pointer.struct.env_md_ctx_st */
            	7212, 0,
            0, 48, 5, /* 7212: struct.env_md_ctx_st */
            	6103, 0,
            	5726, 8,
            	15, 24,
            	7225, 32,
            	6130, 40,
            1, 8, 1, /* 7225: pointer.struct.evp_pkey_ctx_st */
            	6974, 0,
            0, 528, 8, /* 7230: struct.unknown */
            	6081, 408,
            	7155, 416,
            	5843, 424,
            	6193, 464,
            	117, 480,
            	7249, 488,
            	6103, 496,
            	7283, 512,
            1, 8, 1, /* 7249: pointer.struct.evp_cipher_st */
            	7254, 0,
            0, 88, 7, /* 7254: struct.evp_cipher_st */
            	7271, 24,
            	7274, 32,
            	6862, 40,
            	7277, 56,
            	7277, 64,
            	7280, 72,
            	15, 80,
            8884097, 8, 0, /* 7271: pointer.func */
            8884097, 8, 0, /* 7274: pointer.func */
            8884097, 8, 0, /* 7277: pointer.func */
            8884097, 8, 0, /* 7280: pointer.func */
            1, 8, 1, /* 7283: pointer.struct.ssl_comp_st */
            	7288, 0,
            0, 24, 2, /* 7288: struct.ssl_comp_st */
            	5, 8,
            	7295, 16,
            1, 8, 1, /* 7295: pointer.struct.comp_method_st */
            	7300, 0,
            0, 64, 7, /* 7300: struct.comp_method_st */
            	5, 8,
            	7086, 16,
            	7317, 24,
            	6822, 32,
            	6822, 40,
            	235, 48,
            	235, 56,
            8884097, 8, 0, /* 7317: pointer.func */
            0, 1, 0, /* 7320: char */
            0, 808, 51, /* 7323: struct.ssl_st */
            	4621, 8,
            	7197, 16,
            	7197, 24,
            	7197, 32,
            	4685, 48,
            	5963, 80,
            	15, 88,
            	117, 104,
            	7428, 120,
            	7454, 128,
            	7459, 136,
            	6706, 152,
            	15, 160,
            	4859, 176,
            	4787, 184,
            	4787, 192,
            	7497, 208,
            	7207, 216,
            	7513, 224,
            	7497, 232,
            	7207, 240,
            	7513, 248,
            	6265, 256,
            	7525, 304,
            	6709, 312,
            	4898, 328,
            	6190, 336,
            	6721, 352,
            	6724, 360,
            	4513, 368,
            	4907, 392,
            	6193, 408,
            	7530, 464,
            	15, 472,
            	138, 480,
            	6865, 504,
            	6838, 512,
            	117, 520,
            	117, 544,
            	117, 560,
            	15, 568,
            	6788, 584,
            	7533, 592,
            	15, 600,
            	7536, 608,
            	15, 616,
            	4513, 624,
            	117, 632,
            	6764, 648,
            	6793, 656,
            	6727, 680,
            1, 8, 1, /* 7428: pointer.struct.ssl2_state_st */
            	7433, 0,
            0, 344, 9, /* 7433: struct.ssl2_state_st */
            	99, 24,
            	117, 56,
            	117, 64,
            	117, 72,
            	117, 104,
            	117, 112,
            	117, 120,
            	117, 128,
            	117, 136,
            1, 8, 1, /* 7454: pointer.struct.ssl3_state_st */
            	7160, 0,
            1, 8, 1, /* 7459: pointer.struct.dtls1_state_st */
            	7464, 0,
            0, 888, 7, /* 7464: struct.dtls1_state_st */
            	6894, 576,
            	6894, 592,
            	6899, 608,
            	6899, 616,
            	6894, 624,
            	7481, 648,
            	7481, 736,
            0, 88, 1, /* 7481: struct.hm_header_st */
            	7486, 48,
            0, 40, 4, /* 7486: struct.dtls1_retransmit_state */
            	7497, 0,
            	7207, 8,
            	7513, 16,
            	7525, 24,
            1, 8, 1, /* 7497: pointer.struct.evp_cipher_ctx_st */
            	7502, 0,
            0, 168, 4, /* 7502: struct.evp_cipher_ctx_st */
            	7249, 0,
            	5726, 8,
            	15, 96,
            	15, 120,
            1, 8, 1, /* 7513: pointer.struct.comp_ctx_st */
            	7518, 0,
            0, 56, 2, /* 7518: struct.comp_ctx_st */
            	7295, 0,
            	4907, 40,
            1, 8, 1, /* 7525: pointer.struct.ssl_session_st */
            	4934, 0,
            8884097, 8, 0, /* 7530: pointer.func */
            8884097, 8, 0, /* 7533: pointer.func */
            8884097, 8, 0, /* 7536: pointer.func */
            1, 8, 1, /* 7539: pointer.struct.ssl_st */
            	7323, 0,
        },
        .arg_entity_index = { 7539, 15, 122, },
        .ret_entity_index = 122,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    SSL * new_arg_a = *((SSL * *)new_args->args[0]);

    void * new_arg_b = *((void * *)new_args->args[1]);

    int new_arg_c = *((int *)new_args->args[2]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_SSL_read)(SSL *,void *,int);
    orig_SSL_read = dlsym(RTLD_NEXT, "SSL_read");
    *new_ret_ptr = (*orig_SSL_read)(new_arg_a,new_arg_b,new_arg_c);

    syscall(889);

    return ret;
}

