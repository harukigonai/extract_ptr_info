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

BIO * bb_SSL_get_wbio(const SSL * arg_a);

BIO * SSL_get_wbio(const SSL * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_get_wbio called %lu\n", in_lib);
    if (!in_lib)
        return bb_SSL_get_wbio(arg_a);
    else {
        BIO * (*orig_SSL_get_wbio)(const SSL *);
        orig_SSL_get_wbio = dlsym(RTLD_NEXT, "SSL_get_wbio");
        return orig_SSL_get_wbio(arg_a);
    }
}

BIO * bb_SSL_get_wbio(const SSL * arg_a) 
{
    BIO * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 32, 1, /* 0: struct.stack_st_void */
            	5, 0,
            0, 32, 2, /* 5: struct.stack_st */
            	12, 8,
            	22, 24,
            1, 8, 1, /* 12: pointer.pointer.char */
            	17, 0,
            1, 8, 1, /* 17: pointer.char */
            	8884096, 0,
            8884097, 8, 0, /* 22: pointer.func */
            0, 16, 1, /* 25: struct.crypto_ex_data_st */
            	30, 0,
            1, 8, 1, /* 30: pointer.struct.stack_st_void */
            	0, 0,
            0, 80, 9, /* 35: struct.bio_method_st */
            	56, 8,
            	61, 16,
            	64, 24,
            	67, 32,
            	64, 40,
            	70, 48,
            	73, 56,
            	73, 64,
            	76, 72,
            1, 8, 1, /* 56: pointer.char */
            	8884096, 0,
            8884097, 8, 0, /* 61: pointer.func */
            8884097, 8, 0, /* 64: pointer.func */
            8884097, 8, 0, /* 67: pointer.func */
            8884097, 8, 0, /* 70: pointer.func */
            8884097, 8, 0, /* 73: pointer.func */
            8884097, 8, 0, /* 76: pointer.func */
            0, 112, 7, /* 79: struct.bio_st */
            	96, 0,
            	101, 8,
            	17, 16,
            	104, 48,
            	107, 56,
            	107, 64,
            	25, 96,
            1, 8, 1, /* 96: pointer.struct.bio_method_st */
            	35, 0,
            8884097, 8, 0, /* 101: pointer.func */
            0, 8, 0, /* 104: pointer.void */
            1, 8, 1, /* 107: pointer.struct.bio_st */
            	79, 0,
            0, 16, 1, /* 112: struct.srtp_protection_profile_st */
            	56, 0,
            0, 16, 1, /* 117: struct.tls_session_ticket_ext_st */
            	104, 8,
            0, 0, 1, /* 122: OCSP_RESPID */
            	127, 0,
            0, 16, 1, /* 127: struct.ocsp_responder_id_st */
            	132, 8,
            0, 8, 2, /* 132: union.unknown */
            	139, 0,
            	239, 0,
            1, 8, 1, /* 139: pointer.struct.X509_name_st */
            	144, 0,
            0, 40, 3, /* 144: struct.X509_name_st */
            	153, 0,
            	229, 16,
            	221, 24,
            1, 8, 1, /* 153: pointer.struct.stack_st_X509_NAME_ENTRY */
            	158, 0,
            0, 32, 2, /* 158: struct.stack_st_fake_X509_NAME_ENTRY */
            	165, 8,
            	22, 24,
            8884099, 8, 2, /* 165: pointer_to_array_of_pointers_to_stack */
            	172, 0,
            	226, 20,
            0, 8, 1, /* 172: pointer.X509_NAME_ENTRY */
            	177, 0,
            0, 0, 1, /* 177: X509_NAME_ENTRY */
            	182, 0,
            0, 24, 2, /* 182: struct.X509_name_entry_st */
            	189, 0,
            	211, 8,
            1, 8, 1, /* 189: pointer.struct.asn1_object_st */
            	194, 0,
            0, 40, 3, /* 194: struct.asn1_object_st */
            	56, 0,
            	56, 8,
            	203, 24,
            1, 8, 1, /* 203: pointer.unsigned char */
            	208, 0,
            0, 1, 0, /* 208: unsigned char */
            1, 8, 1, /* 211: pointer.struct.asn1_string_st */
            	216, 0,
            0, 24, 1, /* 216: struct.asn1_string_st */
            	221, 8,
            1, 8, 1, /* 221: pointer.unsigned char */
            	208, 0,
            0, 4, 0, /* 226: int */
            1, 8, 1, /* 229: pointer.struct.buf_mem_st */
            	234, 0,
            0, 24, 1, /* 234: struct.buf_mem_st */
            	17, 8,
            1, 8, 1, /* 239: pointer.struct.asn1_string_st */
            	244, 0,
            0, 24, 1, /* 244: struct.asn1_string_st */
            	221, 8,
            0, 16, 1, /* 249: struct.srtp_protection_profile_st */
            	56, 0,
            0, 0, 1, /* 254: SRTP_PROTECTION_PROFILE */
            	249, 0,
            8884097, 8, 0, /* 259: pointer.func */
            0, 24, 1, /* 262: struct.bignum_st */
            	267, 0,
            8884099, 8, 2, /* 267: pointer_to_array_of_pointers_to_stack */
            	274, 0,
            	226, 12,
            0, 4, 0, /* 274: unsigned int */
            1, 8, 1, /* 277: pointer.struct.bignum_st */
            	262, 0,
            1, 8, 1, /* 282: pointer.struct.ssl3_buf_freelist_st */
            	287, 0,
            0, 24, 1, /* 287: struct.ssl3_buf_freelist_st */
            	292, 16,
            1, 8, 1, /* 292: pointer.struct.ssl3_buf_freelist_entry_st */
            	297, 0,
            0, 8, 1, /* 297: struct.ssl3_buf_freelist_entry_st */
            	292, 0,
            8884097, 8, 0, /* 302: pointer.func */
            8884097, 8, 0, /* 305: pointer.func */
            8884097, 8, 0, /* 308: pointer.func */
            8884097, 8, 0, /* 311: pointer.func */
            0, 64, 7, /* 314: struct.comp_method_st */
            	56, 8,
            	311, 16,
            	308, 24,
            	305, 32,
            	305, 40,
            	331, 48,
            	331, 56,
            8884097, 8, 0, /* 331: pointer.func */
            0, 0, 1, /* 334: SSL_COMP */
            	339, 0,
            0, 24, 2, /* 339: struct.ssl_comp_st */
            	56, 8,
            	346, 16,
            1, 8, 1, /* 346: pointer.struct.comp_method_st */
            	314, 0,
            8884097, 8, 0, /* 351: pointer.func */
            8884097, 8, 0, /* 354: pointer.func */
            8884097, 8, 0, /* 357: pointer.func */
            8884097, 8, 0, /* 360: pointer.func */
            1, 8, 1, /* 363: pointer.struct.lhash_node_st */
            	368, 0,
            0, 24, 2, /* 368: struct.lhash_node_st */
            	104, 0,
            	363, 8,
            0, 176, 3, /* 375: struct.lhash_st */
            	384, 0,
            	22, 8,
            	391, 16,
            8884099, 8, 2, /* 384: pointer_to_array_of_pointers_to_stack */
            	363, 0,
            	274, 28,
            8884097, 8, 0, /* 391: pointer.func */
            1, 8, 1, /* 394: pointer.struct.lhash_st */
            	375, 0,
            8884097, 8, 0, /* 399: pointer.func */
            8884097, 8, 0, /* 402: pointer.func */
            8884097, 8, 0, /* 405: pointer.func */
            8884097, 8, 0, /* 408: pointer.func */
            8884097, 8, 0, /* 411: pointer.func */
            8884097, 8, 0, /* 414: pointer.func */
            8884097, 8, 0, /* 417: pointer.func */
            8884097, 8, 0, /* 420: pointer.func */
            1, 8, 1, /* 423: pointer.struct.X509_VERIFY_PARAM_st */
            	428, 0,
            0, 56, 2, /* 428: struct.X509_VERIFY_PARAM_st */
            	17, 0,
            	435, 48,
            1, 8, 1, /* 435: pointer.struct.stack_st_ASN1_OBJECT */
            	440, 0,
            0, 32, 2, /* 440: struct.stack_st_fake_ASN1_OBJECT */
            	447, 8,
            	22, 24,
            8884099, 8, 2, /* 447: pointer_to_array_of_pointers_to_stack */
            	454, 0,
            	226, 20,
            0, 8, 1, /* 454: pointer.ASN1_OBJECT */
            	459, 0,
            0, 0, 1, /* 459: ASN1_OBJECT */
            	464, 0,
            0, 40, 3, /* 464: struct.asn1_object_st */
            	56, 0,
            	56, 8,
            	203, 24,
            1, 8, 1, /* 473: pointer.struct.stack_st_X509_OBJECT */
            	478, 0,
            0, 32, 2, /* 478: struct.stack_st_fake_X509_OBJECT */
            	485, 8,
            	22, 24,
            8884099, 8, 2, /* 485: pointer_to_array_of_pointers_to_stack */
            	492, 0,
            	226, 20,
            0, 8, 1, /* 492: pointer.X509_OBJECT */
            	497, 0,
            0, 0, 1, /* 497: X509_OBJECT */
            	502, 0,
            0, 16, 1, /* 502: struct.x509_object_st */
            	507, 8,
            0, 8, 4, /* 507: union.unknown */
            	17, 0,
            	518, 0,
            	3996, 0,
            	4330, 0,
            1, 8, 1, /* 518: pointer.struct.x509_st */
            	523, 0,
            0, 184, 12, /* 523: struct.x509_st */
            	550, 0,
            	590, 8,
            	2690, 16,
            	17, 32,
            	2760, 40,
            	2782, 104,
            	2787, 112,
            	3052, 120,
            	3469, 128,
            	3608, 136,
            	3632, 144,
            	3944, 176,
            1, 8, 1, /* 550: pointer.struct.x509_cinf_st */
            	555, 0,
            0, 104, 11, /* 555: struct.x509_cinf_st */
            	580, 0,
            	580, 8,
            	590, 16,
            	757, 24,
            	805, 32,
            	757, 40,
            	822, 48,
            	2690, 56,
            	2690, 64,
            	2695, 72,
            	2755, 80,
            1, 8, 1, /* 580: pointer.struct.asn1_string_st */
            	585, 0,
            0, 24, 1, /* 585: struct.asn1_string_st */
            	221, 8,
            1, 8, 1, /* 590: pointer.struct.X509_algor_st */
            	595, 0,
            0, 16, 2, /* 595: struct.X509_algor_st */
            	602, 0,
            	616, 8,
            1, 8, 1, /* 602: pointer.struct.asn1_object_st */
            	607, 0,
            0, 40, 3, /* 607: struct.asn1_object_st */
            	56, 0,
            	56, 8,
            	203, 24,
            1, 8, 1, /* 616: pointer.struct.asn1_type_st */
            	621, 0,
            0, 16, 1, /* 621: struct.asn1_type_st */
            	626, 8,
            0, 8, 20, /* 626: union.unknown */
            	17, 0,
            	669, 0,
            	602, 0,
            	679, 0,
            	684, 0,
            	689, 0,
            	694, 0,
            	699, 0,
            	704, 0,
            	709, 0,
            	714, 0,
            	719, 0,
            	724, 0,
            	729, 0,
            	734, 0,
            	739, 0,
            	744, 0,
            	669, 0,
            	669, 0,
            	749, 0,
            1, 8, 1, /* 669: pointer.struct.asn1_string_st */
            	674, 0,
            0, 24, 1, /* 674: struct.asn1_string_st */
            	221, 8,
            1, 8, 1, /* 679: pointer.struct.asn1_string_st */
            	674, 0,
            1, 8, 1, /* 684: pointer.struct.asn1_string_st */
            	674, 0,
            1, 8, 1, /* 689: pointer.struct.asn1_string_st */
            	674, 0,
            1, 8, 1, /* 694: pointer.struct.asn1_string_st */
            	674, 0,
            1, 8, 1, /* 699: pointer.struct.asn1_string_st */
            	674, 0,
            1, 8, 1, /* 704: pointer.struct.asn1_string_st */
            	674, 0,
            1, 8, 1, /* 709: pointer.struct.asn1_string_st */
            	674, 0,
            1, 8, 1, /* 714: pointer.struct.asn1_string_st */
            	674, 0,
            1, 8, 1, /* 719: pointer.struct.asn1_string_st */
            	674, 0,
            1, 8, 1, /* 724: pointer.struct.asn1_string_st */
            	674, 0,
            1, 8, 1, /* 729: pointer.struct.asn1_string_st */
            	674, 0,
            1, 8, 1, /* 734: pointer.struct.asn1_string_st */
            	674, 0,
            1, 8, 1, /* 739: pointer.struct.asn1_string_st */
            	674, 0,
            1, 8, 1, /* 744: pointer.struct.asn1_string_st */
            	674, 0,
            1, 8, 1, /* 749: pointer.struct.ASN1_VALUE_st */
            	754, 0,
            0, 0, 0, /* 754: struct.ASN1_VALUE_st */
            1, 8, 1, /* 757: pointer.struct.X509_name_st */
            	762, 0,
            0, 40, 3, /* 762: struct.X509_name_st */
            	771, 0,
            	795, 16,
            	221, 24,
            1, 8, 1, /* 771: pointer.struct.stack_st_X509_NAME_ENTRY */
            	776, 0,
            0, 32, 2, /* 776: struct.stack_st_fake_X509_NAME_ENTRY */
            	783, 8,
            	22, 24,
            8884099, 8, 2, /* 783: pointer_to_array_of_pointers_to_stack */
            	790, 0,
            	226, 20,
            0, 8, 1, /* 790: pointer.X509_NAME_ENTRY */
            	177, 0,
            1, 8, 1, /* 795: pointer.struct.buf_mem_st */
            	800, 0,
            0, 24, 1, /* 800: struct.buf_mem_st */
            	17, 8,
            1, 8, 1, /* 805: pointer.struct.X509_val_st */
            	810, 0,
            0, 16, 2, /* 810: struct.X509_val_st */
            	817, 0,
            	817, 8,
            1, 8, 1, /* 817: pointer.struct.asn1_string_st */
            	585, 0,
            1, 8, 1, /* 822: pointer.struct.X509_pubkey_st */
            	827, 0,
            0, 24, 3, /* 827: struct.X509_pubkey_st */
            	836, 0,
            	841, 8,
            	851, 16,
            1, 8, 1, /* 836: pointer.struct.X509_algor_st */
            	595, 0,
            1, 8, 1, /* 841: pointer.struct.asn1_string_st */
            	846, 0,
            0, 24, 1, /* 846: struct.asn1_string_st */
            	221, 8,
            1, 8, 1, /* 851: pointer.struct.evp_pkey_st */
            	856, 0,
            0, 56, 4, /* 856: struct.evp_pkey_st */
            	867, 16,
            	968, 24,
            	1316, 32,
            	2319, 48,
            1, 8, 1, /* 867: pointer.struct.evp_pkey_asn1_method_st */
            	872, 0,
            0, 208, 24, /* 872: struct.evp_pkey_asn1_method_st */
            	17, 16,
            	17, 24,
            	923, 32,
            	926, 40,
            	929, 48,
            	932, 56,
            	935, 64,
            	938, 72,
            	932, 80,
            	941, 88,
            	941, 96,
            	944, 104,
            	947, 112,
            	941, 120,
            	950, 128,
            	929, 136,
            	932, 144,
            	953, 152,
            	956, 160,
            	959, 168,
            	944, 176,
            	947, 184,
            	962, 192,
            	965, 200,
            8884097, 8, 0, /* 923: pointer.func */
            8884097, 8, 0, /* 926: pointer.func */
            8884097, 8, 0, /* 929: pointer.func */
            8884097, 8, 0, /* 932: pointer.func */
            8884097, 8, 0, /* 935: pointer.func */
            8884097, 8, 0, /* 938: pointer.func */
            8884097, 8, 0, /* 941: pointer.func */
            8884097, 8, 0, /* 944: pointer.func */
            8884097, 8, 0, /* 947: pointer.func */
            8884097, 8, 0, /* 950: pointer.func */
            8884097, 8, 0, /* 953: pointer.func */
            8884097, 8, 0, /* 956: pointer.func */
            8884097, 8, 0, /* 959: pointer.func */
            8884097, 8, 0, /* 962: pointer.func */
            8884097, 8, 0, /* 965: pointer.func */
            1, 8, 1, /* 968: pointer.struct.engine_st */
            	973, 0,
            0, 216, 24, /* 973: struct.engine_st */
            	56, 0,
            	56, 8,
            	1024, 16,
            	1079, 24,
            	1130, 32,
            	1166, 40,
            	1183, 48,
            	1210, 56,
            	1245, 64,
            	1253, 72,
            	1256, 80,
            	1259, 88,
            	1262, 96,
            	1265, 104,
            	1265, 112,
            	1265, 120,
            	1268, 128,
            	1271, 136,
            	1271, 144,
            	1274, 152,
            	1277, 160,
            	1289, 184,
            	1311, 200,
            	1311, 208,
            1, 8, 1, /* 1024: pointer.struct.rsa_meth_st */
            	1029, 0,
            0, 112, 13, /* 1029: struct.rsa_meth_st */
            	56, 0,
            	1058, 8,
            	1058, 16,
            	1058, 24,
            	1058, 32,
            	1061, 40,
            	1064, 48,
            	1067, 56,
            	1067, 64,
            	17, 80,
            	1070, 88,
            	1073, 96,
            	1076, 104,
            8884097, 8, 0, /* 1058: pointer.func */
            8884097, 8, 0, /* 1061: pointer.func */
            8884097, 8, 0, /* 1064: pointer.func */
            8884097, 8, 0, /* 1067: pointer.func */
            8884097, 8, 0, /* 1070: pointer.func */
            8884097, 8, 0, /* 1073: pointer.func */
            8884097, 8, 0, /* 1076: pointer.func */
            1, 8, 1, /* 1079: pointer.struct.dsa_method */
            	1084, 0,
            0, 96, 11, /* 1084: struct.dsa_method */
            	56, 0,
            	1109, 8,
            	1112, 16,
            	1115, 24,
            	1118, 32,
            	1121, 40,
            	1124, 48,
            	1124, 56,
            	17, 72,
            	1127, 80,
            	1124, 88,
            8884097, 8, 0, /* 1109: pointer.func */
            8884097, 8, 0, /* 1112: pointer.func */
            8884097, 8, 0, /* 1115: pointer.func */
            8884097, 8, 0, /* 1118: pointer.func */
            8884097, 8, 0, /* 1121: pointer.func */
            8884097, 8, 0, /* 1124: pointer.func */
            8884097, 8, 0, /* 1127: pointer.func */
            1, 8, 1, /* 1130: pointer.struct.dh_method */
            	1135, 0,
            0, 72, 8, /* 1135: struct.dh_method */
            	56, 0,
            	1154, 8,
            	1157, 16,
            	1160, 24,
            	1154, 32,
            	1154, 40,
            	17, 56,
            	1163, 64,
            8884097, 8, 0, /* 1154: pointer.func */
            8884097, 8, 0, /* 1157: pointer.func */
            8884097, 8, 0, /* 1160: pointer.func */
            8884097, 8, 0, /* 1163: pointer.func */
            1, 8, 1, /* 1166: pointer.struct.ecdh_method */
            	1171, 0,
            0, 32, 3, /* 1171: struct.ecdh_method */
            	56, 0,
            	1180, 8,
            	17, 24,
            8884097, 8, 0, /* 1180: pointer.func */
            1, 8, 1, /* 1183: pointer.struct.ecdsa_method */
            	1188, 0,
            0, 48, 5, /* 1188: struct.ecdsa_method */
            	56, 0,
            	1201, 8,
            	1204, 16,
            	1207, 24,
            	17, 40,
            8884097, 8, 0, /* 1201: pointer.func */
            8884097, 8, 0, /* 1204: pointer.func */
            8884097, 8, 0, /* 1207: pointer.func */
            1, 8, 1, /* 1210: pointer.struct.rand_meth_st */
            	1215, 0,
            0, 48, 6, /* 1215: struct.rand_meth_st */
            	1230, 0,
            	1233, 8,
            	1236, 16,
            	1239, 24,
            	1233, 32,
            	1242, 40,
            8884097, 8, 0, /* 1230: pointer.func */
            8884097, 8, 0, /* 1233: pointer.func */
            8884097, 8, 0, /* 1236: pointer.func */
            8884097, 8, 0, /* 1239: pointer.func */
            8884097, 8, 0, /* 1242: pointer.func */
            1, 8, 1, /* 1245: pointer.struct.store_method_st */
            	1250, 0,
            0, 0, 0, /* 1250: struct.store_method_st */
            8884097, 8, 0, /* 1253: pointer.func */
            8884097, 8, 0, /* 1256: pointer.func */
            8884097, 8, 0, /* 1259: pointer.func */
            8884097, 8, 0, /* 1262: pointer.func */
            8884097, 8, 0, /* 1265: pointer.func */
            8884097, 8, 0, /* 1268: pointer.func */
            8884097, 8, 0, /* 1271: pointer.func */
            8884097, 8, 0, /* 1274: pointer.func */
            1, 8, 1, /* 1277: pointer.struct.ENGINE_CMD_DEFN_st */
            	1282, 0,
            0, 32, 2, /* 1282: struct.ENGINE_CMD_DEFN_st */
            	56, 8,
            	56, 16,
            0, 16, 1, /* 1289: struct.crypto_ex_data_st */
            	1294, 0,
            1, 8, 1, /* 1294: pointer.struct.stack_st_void */
            	1299, 0,
            0, 32, 1, /* 1299: struct.stack_st_void */
            	1304, 0,
            0, 32, 2, /* 1304: struct.stack_st */
            	12, 8,
            	22, 24,
            1, 8, 1, /* 1311: pointer.struct.engine_st */
            	973, 0,
            0, 8, 5, /* 1316: union.unknown */
            	17, 0,
            	1329, 0,
            	1545, 0,
            	1684, 0,
            	1810, 0,
            1, 8, 1, /* 1329: pointer.struct.rsa_st */
            	1334, 0,
            0, 168, 17, /* 1334: struct.rsa_st */
            	1371, 16,
            	1426, 24,
            	1431, 32,
            	1431, 40,
            	1431, 48,
            	1431, 56,
            	1431, 64,
            	1431, 72,
            	1431, 80,
            	1431, 88,
            	1448, 96,
            	1470, 120,
            	1470, 128,
            	1470, 136,
            	17, 144,
            	1484, 152,
            	1484, 160,
            1, 8, 1, /* 1371: pointer.struct.rsa_meth_st */
            	1376, 0,
            0, 112, 13, /* 1376: struct.rsa_meth_st */
            	56, 0,
            	1405, 8,
            	1405, 16,
            	1405, 24,
            	1405, 32,
            	1408, 40,
            	1411, 48,
            	1414, 56,
            	1414, 64,
            	17, 80,
            	1417, 88,
            	1420, 96,
            	1423, 104,
            8884097, 8, 0, /* 1405: pointer.func */
            8884097, 8, 0, /* 1408: pointer.func */
            8884097, 8, 0, /* 1411: pointer.func */
            8884097, 8, 0, /* 1414: pointer.func */
            8884097, 8, 0, /* 1417: pointer.func */
            8884097, 8, 0, /* 1420: pointer.func */
            8884097, 8, 0, /* 1423: pointer.func */
            1, 8, 1, /* 1426: pointer.struct.engine_st */
            	973, 0,
            1, 8, 1, /* 1431: pointer.struct.bignum_st */
            	1436, 0,
            0, 24, 1, /* 1436: struct.bignum_st */
            	1441, 0,
            8884099, 8, 2, /* 1441: pointer_to_array_of_pointers_to_stack */
            	274, 0,
            	226, 12,
            0, 16, 1, /* 1448: struct.crypto_ex_data_st */
            	1453, 0,
            1, 8, 1, /* 1453: pointer.struct.stack_st_void */
            	1458, 0,
            0, 32, 1, /* 1458: struct.stack_st_void */
            	1463, 0,
            0, 32, 2, /* 1463: struct.stack_st */
            	12, 8,
            	22, 24,
            1, 8, 1, /* 1470: pointer.struct.bn_mont_ctx_st */
            	1475, 0,
            0, 96, 3, /* 1475: struct.bn_mont_ctx_st */
            	1436, 8,
            	1436, 32,
            	1436, 56,
            1, 8, 1, /* 1484: pointer.struct.bn_blinding_st */
            	1489, 0,
            0, 88, 7, /* 1489: struct.bn_blinding_st */
            	1506, 0,
            	1506, 8,
            	1506, 16,
            	1506, 24,
            	1523, 40,
            	1528, 72,
            	1542, 80,
            1, 8, 1, /* 1506: pointer.struct.bignum_st */
            	1511, 0,
            0, 24, 1, /* 1511: struct.bignum_st */
            	1516, 0,
            8884099, 8, 2, /* 1516: pointer_to_array_of_pointers_to_stack */
            	274, 0,
            	226, 12,
            0, 16, 1, /* 1523: struct.crypto_threadid_st */
            	104, 0,
            1, 8, 1, /* 1528: pointer.struct.bn_mont_ctx_st */
            	1533, 0,
            0, 96, 3, /* 1533: struct.bn_mont_ctx_st */
            	1511, 8,
            	1511, 32,
            	1511, 56,
            8884097, 8, 0, /* 1542: pointer.func */
            1, 8, 1, /* 1545: pointer.struct.dsa_st */
            	1550, 0,
            0, 136, 11, /* 1550: struct.dsa_st */
            	1575, 24,
            	1575, 32,
            	1575, 40,
            	1575, 48,
            	1575, 56,
            	1575, 64,
            	1575, 72,
            	1592, 88,
            	1606, 104,
            	1628, 120,
            	1679, 128,
            1, 8, 1, /* 1575: pointer.struct.bignum_st */
            	1580, 0,
            0, 24, 1, /* 1580: struct.bignum_st */
            	1585, 0,
            8884099, 8, 2, /* 1585: pointer_to_array_of_pointers_to_stack */
            	274, 0,
            	226, 12,
            1, 8, 1, /* 1592: pointer.struct.bn_mont_ctx_st */
            	1597, 0,
            0, 96, 3, /* 1597: struct.bn_mont_ctx_st */
            	1580, 8,
            	1580, 32,
            	1580, 56,
            0, 16, 1, /* 1606: struct.crypto_ex_data_st */
            	1611, 0,
            1, 8, 1, /* 1611: pointer.struct.stack_st_void */
            	1616, 0,
            0, 32, 1, /* 1616: struct.stack_st_void */
            	1621, 0,
            0, 32, 2, /* 1621: struct.stack_st */
            	12, 8,
            	22, 24,
            1, 8, 1, /* 1628: pointer.struct.dsa_method */
            	1633, 0,
            0, 96, 11, /* 1633: struct.dsa_method */
            	56, 0,
            	1658, 8,
            	1661, 16,
            	1664, 24,
            	1667, 32,
            	1670, 40,
            	1673, 48,
            	1673, 56,
            	17, 72,
            	1676, 80,
            	1673, 88,
            8884097, 8, 0, /* 1658: pointer.func */
            8884097, 8, 0, /* 1661: pointer.func */
            8884097, 8, 0, /* 1664: pointer.func */
            8884097, 8, 0, /* 1667: pointer.func */
            8884097, 8, 0, /* 1670: pointer.func */
            8884097, 8, 0, /* 1673: pointer.func */
            8884097, 8, 0, /* 1676: pointer.func */
            1, 8, 1, /* 1679: pointer.struct.engine_st */
            	973, 0,
            1, 8, 1, /* 1684: pointer.struct.dh_st */
            	1689, 0,
            0, 144, 12, /* 1689: struct.dh_st */
            	1716, 8,
            	1716, 16,
            	1716, 32,
            	1716, 40,
            	1733, 56,
            	1716, 64,
            	1716, 72,
            	221, 80,
            	1716, 96,
            	1747, 112,
            	1769, 128,
            	1805, 136,
            1, 8, 1, /* 1716: pointer.struct.bignum_st */
            	1721, 0,
            0, 24, 1, /* 1721: struct.bignum_st */
            	1726, 0,
            8884099, 8, 2, /* 1726: pointer_to_array_of_pointers_to_stack */
            	274, 0,
            	226, 12,
            1, 8, 1, /* 1733: pointer.struct.bn_mont_ctx_st */
            	1738, 0,
            0, 96, 3, /* 1738: struct.bn_mont_ctx_st */
            	1721, 8,
            	1721, 32,
            	1721, 56,
            0, 16, 1, /* 1747: struct.crypto_ex_data_st */
            	1752, 0,
            1, 8, 1, /* 1752: pointer.struct.stack_st_void */
            	1757, 0,
            0, 32, 1, /* 1757: struct.stack_st_void */
            	1762, 0,
            0, 32, 2, /* 1762: struct.stack_st */
            	12, 8,
            	22, 24,
            1, 8, 1, /* 1769: pointer.struct.dh_method */
            	1774, 0,
            0, 72, 8, /* 1774: struct.dh_method */
            	56, 0,
            	1793, 8,
            	1796, 16,
            	1799, 24,
            	1793, 32,
            	1793, 40,
            	17, 56,
            	1802, 64,
            8884097, 8, 0, /* 1793: pointer.func */
            8884097, 8, 0, /* 1796: pointer.func */
            8884097, 8, 0, /* 1799: pointer.func */
            8884097, 8, 0, /* 1802: pointer.func */
            1, 8, 1, /* 1805: pointer.struct.engine_st */
            	973, 0,
            1, 8, 1, /* 1810: pointer.struct.ec_key_st */
            	1815, 0,
            0, 56, 4, /* 1815: struct.ec_key_st */
            	1826, 8,
            	2274, 16,
            	2279, 24,
            	2296, 48,
            1, 8, 1, /* 1826: pointer.struct.ec_group_st */
            	1831, 0,
            0, 232, 12, /* 1831: struct.ec_group_st */
            	1858, 0,
            	2030, 8,
            	2230, 16,
            	2230, 40,
            	221, 80,
            	2242, 96,
            	2230, 104,
            	2230, 152,
            	2230, 176,
            	104, 208,
            	104, 216,
            	2271, 224,
            1, 8, 1, /* 1858: pointer.struct.ec_method_st */
            	1863, 0,
            0, 304, 37, /* 1863: struct.ec_method_st */
            	1940, 8,
            	1943, 16,
            	1943, 24,
            	1946, 32,
            	1949, 40,
            	1952, 48,
            	1955, 56,
            	1958, 64,
            	1961, 72,
            	1964, 80,
            	1964, 88,
            	1967, 96,
            	1970, 104,
            	1973, 112,
            	1976, 120,
            	1979, 128,
            	1982, 136,
            	1985, 144,
            	1988, 152,
            	1991, 160,
            	1994, 168,
            	1997, 176,
            	2000, 184,
            	2003, 192,
            	2006, 200,
            	2009, 208,
            	2000, 216,
            	2012, 224,
            	2015, 232,
            	2018, 240,
            	1955, 248,
            	2021, 256,
            	2024, 264,
            	2021, 272,
            	2024, 280,
            	2024, 288,
            	2027, 296,
            8884097, 8, 0, /* 1940: pointer.func */
            8884097, 8, 0, /* 1943: pointer.func */
            8884097, 8, 0, /* 1946: pointer.func */
            8884097, 8, 0, /* 1949: pointer.func */
            8884097, 8, 0, /* 1952: pointer.func */
            8884097, 8, 0, /* 1955: pointer.func */
            8884097, 8, 0, /* 1958: pointer.func */
            8884097, 8, 0, /* 1961: pointer.func */
            8884097, 8, 0, /* 1964: pointer.func */
            8884097, 8, 0, /* 1967: pointer.func */
            8884097, 8, 0, /* 1970: pointer.func */
            8884097, 8, 0, /* 1973: pointer.func */
            8884097, 8, 0, /* 1976: pointer.func */
            8884097, 8, 0, /* 1979: pointer.func */
            8884097, 8, 0, /* 1982: pointer.func */
            8884097, 8, 0, /* 1985: pointer.func */
            8884097, 8, 0, /* 1988: pointer.func */
            8884097, 8, 0, /* 1991: pointer.func */
            8884097, 8, 0, /* 1994: pointer.func */
            8884097, 8, 0, /* 1997: pointer.func */
            8884097, 8, 0, /* 2000: pointer.func */
            8884097, 8, 0, /* 2003: pointer.func */
            8884097, 8, 0, /* 2006: pointer.func */
            8884097, 8, 0, /* 2009: pointer.func */
            8884097, 8, 0, /* 2012: pointer.func */
            8884097, 8, 0, /* 2015: pointer.func */
            8884097, 8, 0, /* 2018: pointer.func */
            8884097, 8, 0, /* 2021: pointer.func */
            8884097, 8, 0, /* 2024: pointer.func */
            8884097, 8, 0, /* 2027: pointer.func */
            1, 8, 1, /* 2030: pointer.struct.ec_point_st */
            	2035, 0,
            0, 88, 4, /* 2035: struct.ec_point_st */
            	2046, 0,
            	2218, 8,
            	2218, 32,
            	2218, 56,
            1, 8, 1, /* 2046: pointer.struct.ec_method_st */
            	2051, 0,
            0, 304, 37, /* 2051: struct.ec_method_st */
            	2128, 8,
            	2131, 16,
            	2131, 24,
            	2134, 32,
            	2137, 40,
            	2140, 48,
            	2143, 56,
            	2146, 64,
            	2149, 72,
            	2152, 80,
            	2152, 88,
            	2155, 96,
            	2158, 104,
            	2161, 112,
            	2164, 120,
            	2167, 128,
            	2170, 136,
            	2173, 144,
            	2176, 152,
            	2179, 160,
            	2182, 168,
            	2185, 176,
            	2188, 184,
            	2191, 192,
            	2194, 200,
            	2197, 208,
            	2188, 216,
            	2200, 224,
            	2203, 232,
            	2206, 240,
            	2143, 248,
            	2209, 256,
            	2212, 264,
            	2209, 272,
            	2212, 280,
            	2212, 288,
            	2215, 296,
            8884097, 8, 0, /* 2128: pointer.func */
            8884097, 8, 0, /* 2131: pointer.func */
            8884097, 8, 0, /* 2134: pointer.func */
            8884097, 8, 0, /* 2137: pointer.func */
            8884097, 8, 0, /* 2140: pointer.func */
            8884097, 8, 0, /* 2143: pointer.func */
            8884097, 8, 0, /* 2146: pointer.func */
            8884097, 8, 0, /* 2149: pointer.func */
            8884097, 8, 0, /* 2152: pointer.func */
            8884097, 8, 0, /* 2155: pointer.func */
            8884097, 8, 0, /* 2158: pointer.func */
            8884097, 8, 0, /* 2161: pointer.func */
            8884097, 8, 0, /* 2164: pointer.func */
            8884097, 8, 0, /* 2167: pointer.func */
            8884097, 8, 0, /* 2170: pointer.func */
            8884097, 8, 0, /* 2173: pointer.func */
            8884097, 8, 0, /* 2176: pointer.func */
            8884097, 8, 0, /* 2179: pointer.func */
            8884097, 8, 0, /* 2182: pointer.func */
            8884097, 8, 0, /* 2185: pointer.func */
            8884097, 8, 0, /* 2188: pointer.func */
            8884097, 8, 0, /* 2191: pointer.func */
            8884097, 8, 0, /* 2194: pointer.func */
            8884097, 8, 0, /* 2197: pointer.func */
            8884097, 8, 0, /* 2200: pointer.func */
            8884097, 8, 0, /* 2203: pointer.func */
            8884097, 8, 0, /* 2206: pointer.func */
            8884097, 8, 0, /* 2209: pointer.func */
            8884097, 8, 0, /* 2212: pointer.func */
            8884097, 8, 0, /* 2215: pointer.func */
            0, 24, 1, /* 2218: struct.bignum_st */
            	2223, 0,
            8884099, 8, 2, /* 2223: pointer_to_array_of_pointers_to_stack */
            	274, 0,
            	226, 12,
            0, 24, 1, /* 2230: struct.bignum_st */
            	2235, 0,
            8884099, 8, 2, /* 2235: pointer_to_array_of_pointers_to_stack */
            	274, 0,
            	226, 12,
            1, 8, 1, /* 2242: pointer.struct.ec_extra_data_st */
            	2247, 0,
            0, 40, 5, /* 2247: struct.ec_extra_data_st */
            	2260, 0,
            	104, 8,
            	2265, 16,
            	2268, 24,
            	2268, 32,
            1, 8, 1, /* 2260: pointer.struct.ec_extra_data_st */
            	2247, 0,
            8884097, 8, 0, /* 2265: pointer.func */
            8884097, 8, 0, /* 2268: pointer.func */
            8884097, 8, 0, /* 2271: pointer.func */
            1, 8, 1, /* 2274: pointer.struct.ec_point_st */
            	2035, 0,
            1, 8, 1, /* 2279: pointer.struct.bignum_st */
            	2284, 0,
            0, 24, 1, /* 2284: struct.bignum_st */
            	2289, 0,
            8884099, 8, 2, /* 2289: pointer_to_array_of_pointers_to_stack */
            	274, 0,
            	226, 12,
            1, 8, 1, /* 2296: pointer.struct.ec_extra_data_st */
            	2301, 0,
            0, 40, 5, /* 2301: struct.ec_extra_data_st */
            	2314, 0,
            	104, 8,
            	2265, 16,
            	2268, 24,
            	2268, 32,
            1, 8, 1, /* 2314: pointer.struct.ec_extra_data_st */
            	2301, 0,
            1, 8, 1, /* 2319: pointer.struct.stack_st_X509_ATTRIBUTE */
            	2324, 0,
            0, 32, 2, /* 2324: struct.stack_st_fake_X509_ATTRIBUTE */
            	2331, 8,
            	22, 24,
            8884099, 8, 2, /* 2331: pointer_to_array_of_pointers_to_stack */
            	2338, 0,
            	226, 20,
            0, 8, 1, /* 2338: pointer.X509_ATTRIBUTE */
            	2343, 0,
            0, 0, 1, /* 2343: X509_ATTRIBUTE */
            	2348, 0,
            0, 24, 2, /* 2348: struct.x509_attributes_st */
            	2355, 0,
            	2369, 16,
            1, 8, 1, /* 2355: pointer.struct.asn1_object_st */
            	2360, 0,
            0, 40, 3, /* 2360: struct.asn1_object_st */
            	56, 0,
            	56, 8,
            	203, 24,
            0, 8, 3, /* 2369: union.unknown */
            	17, 0,
            	2378, 0,
            	2557, 0,
            1, 8, 1, /* 2378: pointer.struct.stack_st_ASN1_TYPE */
            	2383, 0,
            0, 32, 2, /* 2383: struct.stack_st_fake_ASN1_TYPE */
            	2390, 8,
            	22, 24,
            8884099, 8, 2, /* 2390: pointer_to_array_of_pointers_to_stack */
            	2397, 0,
            	226, 20,
            0, 8, 1, /* 2397: pointer.ASN1_TYPE */
            	2402, 0,
            0, 0, 1, /* 2402: ASN1_TYPE */
            	2407, 0,
            0, 16, 1, /* 2407: struct.asn1_type_st */
            	2412, 8,
            0, 8, 20, /* 2412: union.unknown */
            	17, 0,
            	2455, 0,
            	2465, 0,
            	2479, 0,
            	2484, 0,
            	2489, 0,
            	2494, 0,
            	2499, 0,
            	2504, 0,
            	2509, 0,
            	2514, 0,
            	2519, 0,
            	2524, 0,
            	2529, 0,
            	2534, 0,
            	2539, 0,
            	2544, 0,
            	2455, 0,
            	2455, 0,
            	2549, 0,
            1, 8, 1, /* 2455: pointer.struct.asn1_string_st */
            	2460, 0,
            0, 24, 1, /* 2460: struct.asn1_string_st */
            	221, 8,
            1, 8, 1, /* 2465: pointer.struct.asn1_object_st */
            	2470, 0,
            0, 40, 3, /* 2470: struct.asn1_object_st */
            	56, 0,
            	56, 8,
            	203, 24,
            1, 8, 1, /* 2479: pointer.struct.asn1_string_st */
            	2460, 0,
            1, 8, 1, /* 2484: pointer.struct.asn1_string_st */
            	2460, 0,
            1, 8, 1, /* 2489: pointer.struct.asn1_string_st */
            	2460, 0,
            1, 8, 1, /* 2494: pointer.struct.asn1_string_st */
            	2460, 0,
            1, 8, 1, /* 2499: pointer.struct.asn1_string_st */
            	2460, 0,
            1, 8, 1, /* 2504: pointer.struct.asn1_string_st */
            	2460, 0,
            1, 8, 1, /* 2509: pointer.struct.asn1_string_st */
            	2460, 0,
            1, 8, 1, /* 2514: pointer.struct.asn1_string_st */
            	2460, 0,
            1, 8, 1, /* 2519: pointer.struct.asn1_string_st */
            	2460, 0,
            1, 8, 1, /* 2524: pointer.struct.asn1_string_st */
            	2460, 0,
            1, 8, 1, /* 2529: pointer.struct.asn1_string_st */
            	2460, 0,
            1, 8, 1, /* 2534: pointer.struct.asn1_string_st */
            	2460, 0,
            1, 8, 1, /* 2539: pointer.struct.asn1_string_st */
            	2460, 0,
            1, 8, 1, /* 2544: pointer.struct.asn1_string_st */
            	2460, 0,
            1, 8, 1, /* 2549: pointer.struct.ASN1_VALUE_st */
            	2554, 0,
            0, 0, 0, /* 2554: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2557: pointer.struct.asn1_type_st */
            	2562, 0,
            0, 16, 1, /* 2562: struct.asn1_type_st */
            	2567, 8,
            0, 8, 20, /* 2567: union.unknown */
            	17, 0,
            	2610, 0,
            	2355, 0,
            	2620, 0,
            	2625, 0,
            	2630, 0,
            	2635, 0,
            	2640, 0,
            	2645, 0,
            	2650, 0,
            	2655, 0,
            	2660, 0,
            	2665, 0,
            	2670, 0,
            	2675, 0,
            	2680, 0,
            	2685, 0,
            	2610, 0,
            	2610, 0,
            	749, 0,
            1, 8, 1, /* 2610: pointer.struct.asn1_string_st */
            	2615, 0,
            0, 24, 1, /* 2615: struct.asn1_string_st */
            	221, 8,
            1, 8, 1, /* 2620: pointer.struct.asn1_string_st */
            	2615, 0,
            1, 8, 1, /* 2625: pointer.struct.asn1_string_st */
            	2615, 0,
            1, 8, 1, /* 2630: pointer.struct.asn1_string_st */
            	2615, 0,
            1, 8, 1, /* 2635: pointer.struct.asn1_string_st */
            	2615, 0,
            1, 8, 1, /* 2640: pointer.struct.asn1_string_st */
            	2615, 0,
            1, 8, 1, /* 2645: pointer.struct.asn1_string_st */
            	2615, 0,
            1, 8, 1, /* 2650: pointer.struct.asn1_string_st */
            	2615, 0,
            1, 8, 1, /* 2655: pointer.struct.asn1_string_st */
            	2615, 0,
            1, 8, 1, /* 2660: pointer.struct.asn1_string_st */
            	2615, 0,
            1, 8, 1, /* 2665: pointer.struct.asn1_string_st */
            	2615, 0,
            1, 8, 1, /* 2670: pointer.struct.asn1_string_st */
            	2615, 0,
            1, 8, 1, /* 2675: pointer.struct.asn1_string_st */
            	2615, 0,
            1, 8, 1, /* 2680: pointer.struct.asn1_string_st */
            	2615, 0,
            1, 8, 1, /* 2685: pointer.struct.asn1_string_st */
            	2615, 0,
            1, 8, 1, /* 2690: pointer.struct.asn1_string_st */
            	585, 0,
            1, 8, 1, /* 2695: pointer.struct.stack_st_X509_EXTENSION */
            	2700, 0,
            0, 32, 2, /* 2700: struct.stack_st_fake_X509_EXTENSION */
            	2707, 8,
            	22, 24,
            8884099, 8, 2, /* 2707: pointer_to_array_of_pointers_to_stack */
            	2714, 0,
            	226, 20,
            0, 8, 1, /* 2714: pointer.X509_EXTENSION */
            	2719, 0,
            0, 0, 1, /* 2719: X509_EXTENSION */
            	2724, 0,
            0, 24, 2, /* 2724: struct.X509_extension_st */
            	2731, 0,
            	2745, 16,
            1, 8, 1, /* 2731: pointer.struct.asn1_object_st */
            	2736, 0,
            0, 40, 3, /* 2736: struct.asn1_object_st */
            	56, 0,
            	56, 8,
            	203, 24,
            1, 8, 1, /* 2745: pointer.struct.asn1_string_st */
            	2750, 0,
            0, 24, 1, /* 2750: struct.asn1_string_st */
            	221, 8,
            0, 24, 1, /* 2755: struct.ASN1_ENCODING_st */
            	221, 0,
            0, 16, 1, /* 2760: struct.crypto_ex_data_st */
            	2765, 0,
            1, 8, 1, /* 2765: pointer.struct.stack_st_void */
            	2770, 0,
            0, 32, 1, /* 2770: struct.stack_st_void */
            	2775, 0,
            0, 32, 2, /* 2775: struct.stack_st */
            	12, 8,
            	22, 24,
            1, 8, 1, /* 2782: pointer.struct.asn1_string_st */
            	585, 0,
            1, 8, 1, /* 2787: pointer.struct.AUTHORITY_KEYID_st */
            	2792, 0,
            0, 24, 3, /* 2792: struct.AUTHORITY_KEYID_st */
            	2801, 0,
            	2811, 8,
            	3047, 16,
            1, 8, 1, /* 2801: pointer.struct.asn1_string_st */
            	2806, 0,
            0, 24, 1, /* 2806: struct.asn1_string_st */
            	221, 8,
            1, 8, 1, /* 2811: pointer.struct.stack_st_GENERAL_NAME */
            	2816, 0,
            0, 32, 2, /* 2816: struct.stack_st_fake_GENERAL_NAME */
            	2823, 8,
            	22, 24,
            8884099, 8, 2, /* 2823: pointer_to_array_of_pointers_to_stack */
            	2830, 0,
            	226, 20,
            0, 8, 1, /* 2830: pointer.GENERAL_NAME */
            	2835, 0,
            0, 0, 1, /* 2835: GENERAL_NAME */
            	2840, 0,
            0, 16, 1, /* 2840: struct.GENERAL_NAME_st */
            	2845, 8,
            0, 8, 15, /* 2845: union.unknown */
            	17, 0,
            	2878, 0,
            	2987, 0,
            	2987, 0,
            	2904, 0,
            	139, 0,
            	3035, 0,
            	2987, 0,
            	239, 0,
            	2890, 0,
            	239, 0,
            	139, 0,
            	2987, 0,
            	2890, 0,
            	2904, 0,
            1, 8, 1, /* 2878: pointer.struct.otherName_st */
            	2883, 0,
            0, 16, 2, /* 2883: struct.otherName_st */
            	2890, 0,
            	2904, 8,
            1, 8, 1, /* 2890: pointer.struct.asn1_object_st */
            	2895, 0,
            0, 40, 3, /* 2895: struct.asn1_object_st */
            	56, 0,
            	56, 8,
            	203, 24,
            1, 8, 1, /* 2904: pointer.struct.asn1_type_st */
            	2909, 0,
            0, 16, 1, /* 2909: struct.asn1_type_st */
            	2914, 8,
            0, 8, 20, /* 2914: union.unknown */
            	17, 0,
            	2957, 0,
            	2890, 0,
            	2962, 0,
            	2967, 0,
            	2972, 0,
            	239, 0,
            	2977, 0,
            	2982, 0,
            	2987, 0,
            	2992, 0,
            	2997, 0,
            	3002, 0,
            	3007, 0,
            	3012, 0,
            	3017, 0,
            	3022, 0,
            	2957, 0,
            	2957, 0,
            	3027, 0,
            1, 8, 1, /* 2957: pointer.struct.asn1_string_st */
            	244, 0,
            1, 8, 1, /* 2962: pointer.struct.asn1_string_st */
            	244, 0,
            1, 8, 1, /* 2967: pointer.struct.asn1_string_st */
            	244, 0,
            1, 8, 1, /* 2972: pointer.struct.asn1_string_st */
            	244, 0,
            1, 8, 1, /* 2977: pointer.struct.asn1_string_st */
            	244, 0,
            1, 8, 1, /* 2982: pointer.struct.asn1_string_st */
            	244, 0,
            1, 8, 1, /* 2987: pointer.struct.asn1_string_st */
            	244, 0,
            1, 8, 1, /* 2992: pointer.struct.asn1_string_st */
            	244, 0,
            1, 8, 1, /* 2997: pointer.struct.asn1_string_st */
            	244, 0,
            1, 8, 1, /* 3002: pointer.struct.asn1_string_st */
            	244, 0,
            1, 8, 1, /* 3007: pointer.struct.asn1_string_st */
            	244, 0,
            1, 8, 1, /* 3012: pointer.struct.asn1_string_st */
            	244, 0,
            1, 8, 1, /* 3017: pointer.struct.asn1_string_st */
            	244, 0,
            1, 8, 1, /* 3022: pointer.struct.asn1_string_st */
            	244, 0,
            1, 8, 1, /* 3027: pointer.struct.ASN1_VALUE_st */
            	3032, 0,
            0, 0, 0, /* 3032: struct.ASN1_VALUE_st */
            1, 8, 1, /* 3035: pointer.struct.EDIPartyName_st */
            	3040, 0,
            0, 16, 2, /* 3040: struct.EDIPartyName_st */
            	2957, 0,
            	2957, 8,
            1, 8, 1, /* 3047: pointer.struct.asn1_string_st */
            	2806, 0,
            1, 8, 1, /* 3052: pointer.struct.X509_POLICY_CACHE_st */
            	3057, 0,
            0, 40, 2, /* 3057: struct.X509_POLICY_CACHE_st */
            	3064, 0,
            	3369, 8,
            1, 8, 1, /* 3064: pointer.struct.X509_POLICY_DATA_st */
            	3069, 0,
            0, 32, 3, /* 3069: struct.X509_POLICY_DATA_st */
            	3078, 8,
            	3092, 16,
            	3345, 24,
            1, 8, 1, /* 3078: pointer.struct.asn1_object_st */
            	3083, 0,
            0, 40, 3, /* 3083: struct.asn1_object_st */
            	56, 0,
            	56, 8,
            	203, 24,
            1, 8, 1, /* 3092: pointer.struct.stack_st_POLICYQUALINFO */
            	3097, 0,
            0, 32, 2, /* 3097: struct.stack_st_fake_POLICYQUALINFO */
            	3104, 8,
            	22, 24,
            8884099, 8, 2, /* 3104: pointer_to_array_of_pointers_to_stack */
            	3111, 0,
            	226, 20,
            0, 8, 1, /* 3111: pointer.POLICYQUALINFO */
            	3116, 0,
            0, 0, 1, /* 3116: POLICYQUALINFO */
            	3121, 0,
            0, 16, 2, /* 3121: struct.POLICYQUALINFO_st */
            	3128, 0,
            	3142, 8,
            1, 8, 1, /* 3128: pointer.struct.asn1_object_st */
            	3133, 0,
            0, 40, 3, /* 3133: struct.asn1_object_st */
            	56, 0,
            	56, 8,
            	203, 24,
            0, 8, 3, /* 3142: union.unknown */
            	3151, 0,
            	3161, 0,
            	3219, 0,
            1, 8, 1, /* 3151: pointer.struct.asn1_string_st */
            	3156, 0,
            0, 24, 1, /* 3156: struct.asn1_string_st */
            	221, 8,
            1, 8, 1, /* 3161: pointer.struct.USERNOTICE_st */
            	3166, 0,
            0, 16, 2, /* 3166: struct.USERNOTICE_st */
            	3173, 0,
            	3185, 8,
            1, 8, 1, /* 3173: pointer.struct.NOTICEREF_st */
            	3178, 0,
            0, 16, 2, /* 3178: struct.NOTICEREF_st */
            	3185, 0,
            	3190, 8,
            1, 8, 1, /* 3185: pointer.struct.asn1_string_st */
            	3156, 0,
            1, 8, 1, /* 3190: pointer.struct.stack_st_ASN1_INTEGER */
            	3195, 0,
            0, 32, 2, /* 3195: struct.stack_st_fake_ASN1_INTEGER */
            	3202, 8,
            	22, 24,
            8884099, 8, 2, /* 3202: pointer_to_array_of_pointers_to_stack */
            	3209, 0,
            	226, 20,
            0, 8, 1, /* 3209: pointer.ASN1_INTEGER */
            	3214, 0,
            0, 0, 1, /* 3214: ASN1_INTEGER */
            	674, 0,
            1, 8, 1, /* 3219: pointer.struct.asn1_type_st */
            	3224, 0,
            0, 16, 1, /* 3224: struct.asn1_type_st */
            	3229, 8,
            0, 8, 20, /* 3229: union.unknown */
            	17, 0,
            	3185, 0,
            	3128, 0,
            	3272, 0,
            	3277, 0,
            	3282, 0,
            	3287, 0,
            	3292, 0,
            	3297, 0,
            	3151, 0,
            	3302, 0,
            	3307, 0,
            	3312, 0,
            	3317, 0,
            	3322, 0,
            	3327, 0,
            	3332, 0,
            	3185, 0,
            	3185, 0,
            	3337, 0,
            1, 8, 1, /* 3272: pointer.struct.asn1_string_st */
            	3156, 0,
            1, 8, 1, /* 3277: pointer.struct.asn1_string_st */
            	3156, 0,
            1, 8, 1, /* 3282: pointer.struct.asn1_string_st */
            	3156, 0,
            1, 8, 1, /* 3287: pointer.struct.asn1_string_st */
            	3156, 0,
            1, 8, 1, /* 3292: pointer.struct.asn1_string_st */
            	3156, 0,
            1, 8, 1, /* 3297: pointer.struct.asn1_string_st */
            	3156, 0,
            1, 8, 1, /* 3302: pointer.struct.asn1_string_st */
            	3156, 0,
            1, 8, 1, /* 3307: pointer.struct.asn1_string_st */
            	3156, 0,
            1, 8, 1, /* 3312: pointer.struct.asn1_string_st */
            	3156, 0,
            1, 8, 1, /* 3317: pointer.struct.asn1_string_st */
            	3156, 0,
            1, 8, 1, /* 3322: pointer.struct.asn1_string_st */
            	3156, 0,
            1, 8, 1, /* 3327: pointer.struct.asn1_string_st */
            	3156, 0,
            1, 8, 1, /* 3332: pointer.struct.asn1_string_st */
            	3156, 0,
            1, 8, 1, /* 3337: pointer.struct.ASN1_VALUE_st */
            	3342, 0,
            0, 0, 0, /* 3342: struct.ASN1_VALUE_st */
            1, 8, 1, /* 3345: pointer.struct.stack_st_ASN1_OBJECT */
            	3350, 0,
            0, 32, 2, /* 3350: struct.stack_st_fake_ASN1_OBJECT */
            	3357, 8,
            	22, 24,
            8884099, 8, 2, /* 3357: pointer_to_array_of_pointers_to_stack */
            	3364, 0,
            	226, 20,
            0, 8, 1, /* 3364: pointer.ASN1_OBJECT */
            	459, 0,
            1, 8, 1, /* 3369: pointer.struct.stack_st_X509_POLICY_DATA */
            	3374, 0,
            0, 32, 2, /* 3374: struct.stack_st_fake_X509_POLICY_DATA */
            	3381, 8,
            	22, 24,
            8884099, 8, 2, /* 3381: pointer_to_array_of_pointers_to_stack */
            	3388, 0,
            	226, 20,
            0, 8, 1, /* 3388: pointer.X509_POLICY_DATA */
            	3393, 0,
            0, 0, 1, /* 3393: X509_POLICY_DATA */
            	3398, 0,
            0, 32, 3, /* 3398: struct.X509_POLICY_DATA_st */
            	3407, 8,
            	3421, 16,
            	3445, 24,
            1, 8, 1, /* 3407: pointer.struct.asn1_object_st */
            	3412, 0,
            0, 40, 3, /* 3412: struct.asn1_object_st */
            	56, 0,
            	56, 8,
            	203, 24,
            1, 8, 1, /* 3421: pointer.struct.stack_st_POLICYQUALINFO */
            	3426, 0,
            0, 32, 2, /* 3426: struct.stack_st_fake_POLICYQUALINFO */
            	3433, 8,
            	22, 24,
            8884099, 8, 2, /* 3433: pointer_to_array_of_pointers_to_stack */
            	3440, 0,
            	226, 20,
            0, 8, 1, /* 3440: pointer.POLICYQUALINFO */
            	3116, 0,
            1, 8, 1, /* 3445: pointer.struct.stack_st_ASN1_OBJECT */
            	3450, 0,
            0, 32, 2, /* 3450: struct.stack_st_fake_ASN1_OBJECT */
            	3457, 8,
            	22, 24,
            8884099, 8, 2, /* 3457: pointer_to_array_of_pointers_to_stack */
            	3464, 0,
            	226, 20,
            0, 8, 1, /* 3464: pointer.ASN1_OBJECT */
            	459, 0,
            1, 8, 1, /* 3469: pointer.struct.stack_st_DIST_POINT */
            	3474, 0,
            0, 32, 2, /* 3474: struct.stack_st_fake_DIST_POINT */
            	3481, 8,
            	22, 24,
            8884099, 8, 2, /* 3481: pointer_to_array_of_pointers_to_stack */
            	3488, 0,
            	226, 20,
            0, 8, 1, /* 3488: pointer.DIST_POINT */
            	3493, 0,
            0, 0, 1, /* 3493: DIST_POINT */
            	3498, 0,
            0, 32, 3, /* 3498: struct.DIST_POINT_st */
            	3507, 0,
            	3598, 8,
            	3526, 16,
            1, 8, 1, /* 3507: pointer.struct.DIST_POINT_NAME_st */
            	3512, 0,
            0, 24, 2, /* 3512: struct.DIST_POINT_NAME_st */
            	3519, 8,
            	3574, 16,
            0, 8, 2, /* 3519: union.unknown */
            	3526, 0,
            	3550, 0,
            1, 8, 1, /* 3526: pointer.struct.stack_st_GENERAL_NAME */
            	3531, 0,
            0, 32, 2, /* 3531: struct.stack_st_fake_GENERAL_NAME */
            	3538, 8,
            	22, 24,
            8884099, 8, 2, /* 3538: pointer_to_array_of_pointers_to_stack */
            	3545, 0,
            	226, 20,
            0, 8, 1, /* 3545: pointer.GENERAL_NAME */
            	2835, 0,
            1, 8, 1, /* 3550: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3555, 0,
            0, 32, 2, /* 3555: struct.stack_st_fake_X509_NAME_ENTRY */
            	3562, 8,
            	22, 24,
            8884099, 8, 2, /* 3562: pointer_to_array_of_pointers_to_stack */
            	3569, 0,
            	226, 20,
            0, 8, 1, /* 3569: pointer.X509_NAME_ENTRY */
            	177, 0,
            1, 8, 1, /* 3574: pointer.struct.X509_name_st */
            	3579, 0,
            0, 40, 3, /* 3579: struct.X509_name_st */
            	3550, 0,
            	3588, 16,
            	221, 24,
            1, 8, 1, /* 3588: pointer.struct.buf_mem_st */
            	3593, 0,
            0, 24, 1, /* 3593: struct.buf_mem_st */
            	17, 8,
            1, 8, 1, /* 3598: pointer.struct.asn1_string_st */
            	3603, 0,
            0, 24, 1, /* 3603: struct.asn1_string_st */
            	221, 8,
            1, 8, 1, /* 3608: pointer.struct.stack_st_GENERAL_NAME */
            	3613, 0,
            0, 32, 2, /* 3613: struct.stack_st_fake_GENERAL_NAME */
            	3620, 8,
            	22, 24,
            8884099, 8, 2, /* 3620: pointer_to_array_of_pointers_to_stack */
            	3627, 0,
            	226, 20,
            0, 8, 1, /* 3627: pointer.GENERAL_NAME */
            	2835, 0,
            1, 8, 1, /* 3632: pointer.struct.NAME_CONSTRAINTS_st */
            	3637, 0,
            0, 16, 2, /* 3637: struct.NAME_CONSTRAINTS_st */
            	3644, 0,
            	3644, 8,
            1, 8, 1, /* 3644: pointer.struct.stack_st_GENERAL_SUBTREE */
            	3649, 0,
            0, 32, 2, /* 3649: struct.stack_st_fake_GENERAL_SUBTREE */
            	3656, 8,
            	22, 24,
            8884099, 8, 2, /* 3656: pointer_to_array_of_pointers_to_stack */
            	3663, 0,
            	226, 20,
            0, 8, 1, /* 3663: pointer.GENERAL_SUBTREE */
            	3668, 0,
            0, 0, 1, /* 3668: GENERAL_SUBTREE */
            	3673, 0,
            0, 24, 3, /* 3673: struct.GENERAL_SUBTREE_st */
            	3682, 0,
            	3814, 8,
            	3814, 16,
            1, 8, 1, /* 3682: pointer.struct.GENERAL_NAME_st */
            	3687, 0,
            0, 16, 1, /* 3687: struct.GENERAL_NAME_st */
            	3692, 8,
            0, 8, 15, /* 3692: union.unknown */
            	17, 0,
            	3725, 0,
            	3844, 0,
            	3844, 0,
            	3751, 0,
            	3884, 0,
            	3932, 0,
            	3844, 0,
            	3829, 0,
            	3737, 0,
            	3829, 0,
            	3884, 0,
            	3844, 0,
            	3737, 0,
            	3751, 0,
            1, 8, 1, /* 3725: pointer.struct.otherName_st */
            	3730, 0,
            0, 16, 2, /* 3730: struct.otherName_st */
            	3737, 0,
            	3751, 8,
            1, 8, 1, /* 3737: pointer.struct.asn1_object_st */
            	3742, 0,
            0, 40, 3, /* 3742: struct.asn1_object_st */
            	56, 0,
            	56, 8,
            	203, 24,
            1, 8, 1, /* 3751: pointer.struct.asn1_type_st */
            	3756, 0,
            0, 16, 1, /* 3756: struct.asn1_type_st */
            	3761, 8,
            0, 8, 20, /* 3761: union.unknown */
            	17, 0,
            	3804, 0,
            	3737, 0,
            	3814, 0,
            	3819, 0,
            	3824, 0,
            	3829, 0,
            	3834, 0,
            	3839, 0,
            	3844, 0,
            	3849, 0,
            	3854, 0,
            	3859, 0,
            	3864, 0,
            	3869, 0,
            	3874, 0,
            	3879, 0,
            	3804, 0,
            	3804, 0,
            	3337, 0,
            1, 8, 1, /* 3804: pointer.struct.asn1_string_st */
            	3809, 0,
            0, 24, 1, /* 3809: struct.asn1_string_st */
            	221, 8,
            1, 8, 1, /* 3814: pointer.struct.asn1_string_st */
            	3809, 0,
            1, 8, 1, /* 3819: pointer.struct.asn1_string_st */
            	3809, 0,
            1, 8, 1, /* 3824: pointer.struct.asn1_string_st */
            	3809, 0,
            1, 8, 1, /* 3829: pointer.struct.asn1_string_st */
            	3809, 0,
            1, 8, 1, /* 3834: pointer.struct.asn1_string_st */
            	3809, 0,
            1, 8, 1, /* 3839: pointer.struct.asn1_string_st */
            	3809, 0,
            1, 8, 1, /* 3844: pointer.struct.asn1_string_st */
            	3809, 0,
            1, 8, 1, /* 3849: pointer.struct.asn1_string_st */
            	3809, 0,
            1, 8, 1, /* 3854: pointer.struct.asn1_string_st */
            	3809, 0,
            1, 8, 1, /* 3859: pointer.struct.asn1_string_st */
            	3809, 0,
            1, 8, 1, /* 3864: pointer.struct.asn1_string_st */
            	3809, 0,
            1, 8, 1, /* 3869: pointer.struct.asn1_string_st */
            	3809, 0,
            1, 8, 1, /* 3874: pointer.struct.asn1_string_st */
            	3809, 0,
            1, 8, 1, /* 3879: pointer.struct.asn1_string_st */
            	3809, 0,
            1, 8, 1, /* 3884: pointer.struct.X509_name_st */
            	3889, 0,
            0, 40, 3, /* 3889: struct.X509_name_st */
            	3898, 0,
            	3922, 16,
            	221, 24,
            1, 8, 1, /* 3898: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3903, 0,
            0, 32, 2, /* 3903: struct.stack_st_fake_X509_NAME_ENTRY */
            	3910, 8,
            	22, 24,
            8884099, 8, 2, /* 3910: pointer_to_array_of_pointers_to_stack */
            	3917, 0,
            	226, 20,
            0, 8, 1, /* 3917: pointer.X509_NAME_ENTRY */
            	177, 0,
            1, 8, 1, /* 3922: pointer.struct.buf_mem_st */
            	3927, 0,
            0, 24, 1, /* 3927: struct.buf_mem_st */
            	17, 8,
            1, 8, 1, /* 3932: pointer.struct.EDIPartyName_st */
            	3937, 0,
            0, 16, 2, /* 3937: struct.EDIPartyName_st */
            	3804, 0,
            	3804, 8,
            1, 8, 1, /* 3944: pointer.struct.x509_cert_aux_st */
            	3949, 0,
            0, 40, 5, /* 3949: struct.x509_cert_aux_st */
            	435, 0,
            	435, 8,
            	3962, 16,
            	2782, 24,
            	3967, 32,
            1, 8, 1, /* 3962: pointer.struct.asn1_string_st */
            	585, 0,
            1, 8, 1, /* 3967: pointer.struct.stack_st_X509_ALGOR */
            	3972, 0,
            0, 32, 2, /* 3972: struct.stack_st_fake_X509_ALGOR */
            	3979, 8,
            	22, 24,
            8884099, 8, 2, /* 3979: pointer_to_array_of_pointers_to_stack */
            	3986, 0,
            	226, 20,
            0, 8, 1, /* 3986: pointer.X509_ALGOR */
            	3991, 0,
            0, 0, 1, /* 3991: X509_ALGOR */
            	595, 0,
            1, 8, 1, /* 3996: pointer.struct.X509_crl_st */
            	4001, 0,
            0, 120, 10, /* 4001: struct.X509_crl_st */
            	4024, 0,
            	590, 8,
            	2690, 16,
            	2787, 32,
            	4151, 40,
            	580, 56,
            	580, 64,
            	4264, 96,
            	4305, 104,
            	104, 112,
            1, 8, 1, /* 4024: pointer.struct.X509_crl_info_st */
            	4029, 0,
            0, 80, 8, /* 4029: struct.X509_crl_info_st */
            	580, 0,
            	590, 8,
            	757, 16,
            	817, 24,
            	817, 32,
            	4048, 40,
            	2695, 48,
            	2755, 56,
            1, 8, 1, /* 4048: pointer.struct.stack_st_X509_REVOKED */
            	4053, 0,
            0, 32, 2, /* 4053: struct.stack_st_fake_X509_REVOKED */
            	4060, 8,
            	22, 24,
            8884099, 8, 2, /* 4060: pointer_to_array_of_pointers_to_stack */
            	4067, 0,
            	226, 20,
            0, 8, 1, /* 4067: pointer.X509_REVOKED */
            	4072, 0,
            0, 0, 1, /* 4072: X509_REVOKED */
            	4077, 0,
            0, 40, 4, /* 4077: struct.x509_revoked_st */
            	4088, 0,
            	4098, 8,
            	4103, 16,
            	4127, 24,
            1, 8, 1, /* 4088: pointer.struct.asn1_string_st */
            	4093, 0,
            0, 24, 1, /* 4093: struct.asn1_string_st */
            	221, 8,
            1, 8, 1, /* 4098: pointer.struct.asn1_string_st */
            	4093, 0,
            1, 8, 1, /* 4103: pointer.struct.stack_st_X509_EXTENSION */
            	4108, 0,
            0, 32, 2, /* 4108: struct.stack_st_fake_X509_EXTENSION */
            	4115, 8,
            	22, 24,
            8884099, 8, 2, /* 4115: pointer_to_array_of_pointers_to_stack */
            	4122, 0,
            	226, 20,
            0, 8, 1, /* 4122: pointer.X509_EXTENSION */
            	2719, 0,
            1, 8, 1, /* 4127: pointer.struct.stack_st_GENERAL_NAME */
            	4132, 0,
            0, 32, 2, /* 4132: struct.stack_st_fake_GENERAL_NAME */
            	4139, 8,
            	22, 24,
            8884099, 8, 2, /* 4139: pointer_to_array_of_pointers_to_stack */
            	4146, 0,
            	226, 20,
            0, 8, 1, /* 4146: pointer.GENERAL_NAME */
            	2835, 0,
            1, 8, 1, /* 4151: pointer.struct.ISSUING_DIST_POINT_st */
            	4156, 0,
            0, 32, 2, /* 4156: struct.ISSUING_DIST_POINT_st */
            	4163, 0,
            	4254, 16,
            1, 8, 1, /* 4163: pointer.struct.DIST_POINT_NAME_st */
            	4168, 0,
            0, 24, 2, /* 4168: struct.DIST_POINT_NAME_st */
            	4175, 8,
            	4230, 16,
            0, 8, 2, /* 4175: union.unknown */
            	4182, 0,
            	4206, 0,
            1, 8, 1, /* 4182: pointer.struct.stack_st_GENERAL_NAME */
            	4187, 0,
            0, 32, 2, /* 4187: struct.stack_st_fake_GENERAL_NAME */
            	4194, 8,
            	22, 24,
            8884099, 8, 2, /* 4194: pointer_to_array_of_pointers_to_stack */
            	4201, 0,
            	226, 20,
            0, 8, 1, /* 4201: pointer.GENERAL_NAME */
            	2835, 0,
            1, 8, 1, /* 4206: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4211, 0,
            0, 32, 2, /* 4211: struct.stack_st_fake_X509_NAME_ENTRY */
            	4218, 8,
            	22, 24,
            8884099, 8, 2, /* 4218: pointer_to_array_of_pointers_to_stack */
            	4225, 0,
            	226, 20,
            0, 8, 1, /* 4225: pointer.X509_NAME_ENTRY */
            	177, 0,
            1, 8, 1, /* 4230: pointer.struct.X509_name_st */
            	4235, 0,
            0, 40, 3, /* 4235: struct.X509_name_st */
            	4206, 0,
            	4244, 16,
            	221, 24,
            1, 8, 1, /* 4244: pointer.struct.buf_mem_st */
            	4249, 0,
            0, 24, 1, /* 4249: struct.buf_mem_st */
            	17, 8,
            1, 8, 1, /* 4254: pointer.struct.asn1_string_st */
            	4259, 0,
            0, 24, 1, /* 4259: struct.asn1_string_st */
            	221, 8,
            1, 8, 1, /* 4264: pointer.struct.stack_st_GENERAL_NAMES */
            	4269, 0,
            0, 32, 2, /* 4269: struct.stack_st_fake_GENERAL_NAMES */
            	4276, 8,
            	22, 24,
            8884099, 8, 2, /* 4276: pointer_to_array_of_pointers_to_stack */
            	4283, 0,
            	226, 20,
            0, 8, 1, /* 4283: pointer.GENERAL_NAMES */
            	4288, 0,
            0, 0, 1, /* 4288: GENERAL_NAMES */
            	4293, 0,
            0, 32, 1, /* 4293: struct.stack_st_GENERAL_NAME */
            	4298, 0,
            0, 32, 2, /* 4298: struct.stack_st */
            	12, 8,
            	22, 24,
            1, 8, 1, /* 4305: pointer.struct.x509_crl_method_st */
            	4310, 0,
            0, 40, 4, /* 4310: struct.x509_crl_method_st */
            	4321, 8,
            	4321, 16,
            	4324, 24,
            	4327, 32,
            8884097, 8, 0, /* 4321: pointer.func */
            8884097, 8, 0, /* 4324: pointer.func */
            8884097, 8, 0, /* 4327: pointer.func */
            1, 8, 1, /* 4330: pointer.struct.evp_pkey_st */
            	4335, 0,
            0, 56, 4, /* 4335: struct.evp_pkey_st */
            	4346, 16,
            	4351, 24,
            	4356, 32,
            	4389, 48,
            1, 8, 1, /* 4346: pointer.struct.evp_pkey_asn1_method_st */
            	872, 0,
            1, 8, 1, /* 4351: pointer.struct.engine_st */
            	973, 0,
            0, 8, 5, /* 4356: union.unknown */
            	17, 0,
            	4369, 0,
            	4374, 0,
            	4379, 0,
            	4384, 0,
            1, 8, 1, /* 4369: pointer.struct.rsa_st */
            	1334, 0,
            1, 8, 1, /* 4374: pointer.struct.dsa_st */
            	1550, 0,
            1, 8, 1, /* 4379: pointer.struct.dh_st */
            	1689, 0,
            1, 8, 1, /* 4384: pointer.struct.ec_key_st */
            	1815, 0,
            1, 8, 1, /* 4389: pointer.struct.stack_st_X509_ATTRIBUTE */
            	4394, 0,
            0, 32, 2, /* 4394: struct.stack_st_fake_X509_ATTRIBUTE */
            	4401, 8,
            	22, 24,
            8884099, 8, 2, /* 4401: pointer_to_array_of_pointers_to_stack */
            	4408, 0,
            	226, 20,
            0, 8, 1, /* 4408: pointer.X509_ATTRIBUTE */
            	2343, 0,
            0, 144, 15, /* 4413: struct.x509_store_st */
            	473, 8,
            	4446, 16,
            	423, 24,
            	420, 32,
            	417, 40,
            	4538, 48,
            	4541, 56,
            	420, 64,
            	4544, 72,
            	4547, 80,
            	4550, 88,
            	414, 96,
            	4553, 104,
            	420, 112,
            	2760, 120,
            1, 8, 1, /* 4446: pointer.struct.stack_st_X509_LOOKUP */
            	4451, 0,
            0, 32, 2, /* 4451: struct.stack_st_fake_X509_LOOKUP */
            	4458, 8,
            	22, 24,
            8884099, 8, 2, /* 4458: pointer_to_array_of_pointers_to_stack */
            	4465, 0,
            	226, 20,
            0, 8, 1, /* 4465: pointer.X509_LOOKUP */
            	4470, 0,
            0, 0, 1, /* 4470: X509_LOOKUP */
            	4475, 0,
            0, 32, 3, /* 4475: struct.x509_lookup_st */
            	4484, 8,
            	17, 16,
            	4533, 24,
            1, 8, 1, /* 4484: pointer.struct.x509_lookup_method_st */
            	4489, 0,
            0, 80, 10, /* 4489: struct.x509_lookup_method_st */
            	56, 0,
            	4512, 8,
            	4515, 16,
            	4512, 24,
            	4512, 32,
            	4518, 40,
            	4521, 48,
            	4524, 56,
            	4527, 64,
            	4530, 72,
            8884097, 8, 0, /* 4512: pointer.func */
            8884097, 8, 0, /* 4515: pointer.func */
            8884097, 8, 0, /* 4518: pointer.func */
            8884097, 8, 0, /* 4521: pointer.func */
            8884097, 8, 0, /* 4524: pointer.func */
            8884097, 8, 0, /* 4527: pointer.func */
            8884097, 8, 0, /* 4530: pointer.func */
            1, 8, 1, /* 4533: pointer.struct.x509_store_st */
            	4413, 0,
            8884097, 8, 0, /* 4538: pointer.func */
            8884097, 8, 0, /* 4541: pointer.func */
            8884097, 8, 0, /* 4544: pointer.func */
            8884097, 8, 0, /* 4547: pointer.func */
            8884097, 8, 0, /* 4550: pointer.func */
            8884097, 8, 0, /* 4553: pointer.func */
            1, 8, 1, /* 4556: pointer.struct.stack_st_X509_LOOKUP */
            	4561, 0,
            0, 32, 2, /* 4561: struct.stack_st_fake_X509_LOOKUP */
            	4568, 8,
            	22, 24,
            8884099, 8, 2, /* 4568: pointer_to_array_of_pointers_to_stack */
            	4575, 0,
            	226, 20,
            0, 8, 1, /* 4575: pointer.X509_LOOKUP */
            	4470, 0,
            1, 8, 1, /* 4580: pointer.struct.stack_st_X509_OBJECT */
            	4585, 0,
            0, 32, 2, /* 4585: struct.stack_st_fake_X509_OBJECT */
            	4592, 8,
            	22, 24,
            8884099, 8, 2, /* 4592: pointer_to_array_of_pointers_to_stack */
            	4599, 0,
            	226, 20,
            0, 8, 1, /* 4599: pointer.X509_OBJECT */
            	497, 0,
            1, 8, 1, /* 4604: pointer.struct.ssl_ctx_st */
            	4609, 0,
            0, 736, 50, /* 4609: struct.ssl_ctx_st */
            	4712, 0,
            	4878, 8,
            	4878, 16,
            	4912, 24,
            	394, 32,
            	5020, 48,
            	5020, 56,
            	360, 80,
            	6182, 88,
            	6185, 96,
            	357, 152,
            	104, 160,
            	354, 168,
            	104, 176,
            	351, 184,
            	6188, 192,
            	6191, 200,
            	4998, 208,
            	6194, 224,
            	6194, 232,
            	6194, 240,
            	6233, 248,
            	6257, 256,
            	6281, 264,
            	6284, 272,
            	6356, 304,
            	6797, 320,
            	104, 328,
            	4989, 376,
            	6800, 384,
            	4950, 392,
            	5817, 408,
            	6803, 416,
            	104, 424,
            	6806, 480,
            	6809, 488,
            	104, 496,
            	302, 504,
            	104, 512,
            	17, 520,
            	6812, 528,
            	6815, 536,
            	282, 552,
            	282, 560,
            	6818, 568,
            	6852, 696,
            	104, 704,
            	259, 712,
            	104, 720,
            	6855, 728,
            1, 8, 1, /* 4712: pointer.struct.ssl_method_st */
            	4717, 0,
            0, 232, 28, /* 4717: struct.ssl_method_st */
            	4776, 8,
            	4779, 16,
            	4779, 24,
            	4776, 32,
            	4776, 40,
            	4782, 48,
            	4782, 56,
            	4785, 64,
            	4776, 72,
            	4776, 80,
            	4776, 88,
            	4788, 96,
            	4791, 104,
            	4794, 112,
            	4776, 120,
            	4797, 128,
            	4800, 136,
            	4803, 144,
            	4806, 152,
            	4809, 160,
            	1242, 168,
            	4812, 176,
            	4815, 184,
            	331, 192,
            	4818, 200,
            	1242, 208,
            	4872, 216,
            	4875, 224,
            8884097, 8, 0, /* 4776: pointer.func */
            8884097, 8, 0, /* 4779: pointer.func */
            8884097, 8, 0, /* 4782: pointer.func */
            8884097, 8, 0, /* 4785: pointer.func */
            8884097, 8, 0, /* 4788: pointer.func */
            8884097, 8, 0, /* 4791: pointer.func */
            8884097, 8, 0, /* 4794: pointer.func */
            8884097, 8, 0, /* 4797: pointer.func */
            8884097, 8, 0, /* 4800: pointer.func */
            8884097, 8, 0, /* 4803: pointer.func */
            8884097, 8, 0, /* 4806: pointer.func */
            8884097, 8, 0, /* 4809: pointer.func */
            8884097, 8, 0, /* 4812: pointer.func */
            8884097, 8, 0, /* 4815: pointer.func */
            1, 8, 1, /* 4818: pointer.struct.ssl3_enc_method */
            	4823, 0,
            0, 112, 11, /* 4823: struct.ssl3_enc_method */
            	4848, 0,
            	4851, 8,
            	4854, 16,
            	4857, 24,
            	4848, 32,
            	4860, 40,
            	4863, 56,
            	56, 64,
            	56, 80,
            	4866, 96,
            	4869, 104,
            8884097, 8, 0, /* 4848: pointer.func */
            8884097, 8, 0, /* 4851: pointer.func */
            8884097, 8, 0, /* 4854: pointer.func */
            8884097, 8, 0, /* 4857: pointer.func */
            8884097, 8, 0, /* 4860: pointer.func */
            8884097, 8, 0, /* 4863: pointer.func */
            8884097, 8, 0, /* 4866: pointer.func */
            8884097, 8, 0, /* 4869: pointer.func */
            8884097, 8, 0, /* 4872: pointer.func */
            8884097, 8, 0, /* 4875: pointer.func */
            1, 8, 1, /* 4878: pointer.struct.stack_st_SSL_CIPHER */
            	4883, 0,
            0, 32, 2, /* 4883: struct.stack_st_fake_SSL_CIPHER */
            	4890, 8,
            	22, 24,
            8884099, 8, 2, /* 4890: pointer_to_array_of_pointers_to_stack */
            	4897, 0,
            	226, 20,
            0, 8, 1, /* 4897: pointer.SSL_CIPHER */
            	4902, 0,
            0, 0, 1, /* 4902: SSL_CIPHER */
            	4907, 0,
            0, 88, 1, /* 4907: struct.ssl_cipher_st */
            	56, 8,
            1, 8, 1, /* 4912: pointer.struct.x509_store_st */
            	4917, 0,
            0, 144, 15, /* 4917: struct.x509_store_st */
            	4580, 8,
            	4556, 16,
            	4950, 24,
            	4986, 32,
            	4989, 40,
            	4992, 48,
            	411, 56,
            	4986, 64,
            	408, 72,
            	405, 80,
            	402, 88,
            	399, 96,
            	4995, 104,
            	4986, 112,
            	4998, 120,
            1, 8, 1, /* 4950: pointer.struct.X509_VERIFY_PARAM_st */
            	4955, 0,
            0, 56, 2, /* 4955: struct.X509_VERIFY_PARAM_st */
            	17, 0,
            	4962, 48,
            1, 8, 1, /* 4962: pointer.struct.stack_st_ASN1_OBJECT */
            	4967, 0,
            0, 32, 2, /* 4967: struct.stack_st_fake_ASN1_OBJECT */
            	4974, 8,
            	22, 24,
            8884099, 8, 2, /* 4974: pointer_to_array_of_pointers_to_stack */
            	4981, 0,
            	226, 20,
            0, 8, 1, /* 4981: pointer.ASN1_OBJECT */
            	459, 0,
            8884097, 8, 0, /* 4986: pointer.func */
            8884097, 8, 0, /* 4989: pointer.func */
            8884097, 8, 0, /* 4992: pointer.func */
            8884097, 8, 0, /* 4995: pointer.func */
            0, 16, 1, /* 4998: struct.crypto_ex_data_st */
            	5003, 0,
            1, 8, 1, /* 5003: pointer.struct.stack_st_void */
            	5008, 0,
            0, 32, 1, /* 5008: struct.stack_st_void */
            	5013, 0,
            0, 32, 2, /* 5013: struct.stack_st */
            	12, 8,
            	22, 24,
            1, 8, 1, /* 5020: pointer.struct.ssl_session_st */
            	5025, 0,
            0, 352, 14, /* 5025: struct.ssl_session_st */
            	17, 144,
            	17, 152,
            	5056, 168,
            	5939, 176,
            	6172, 224,
            	4878, 240,
            	4998, 248,
            	5020, 264,
            	5020, 272,
            	17, 280,
            	221, 296,
            	221, 312,
            	221, 320,
            	17, 344,
            1, 8, 1, /* 5056: pointer.struct.sess_cert_st */
            	5061, 0,
            0, 248, 5, /* 5061: struct.sess_cert_st */
            	5074, 0,
            	5440, 16,
            	5924, 216,
            	5929, 224,
            	5934, 232,
            1, 8, 1, /* 5074: pointer.struct.stack_st_X509 */
            	5079, 0,
            0, 32, 2, /* 5079: struct.stack_st_fake_X509 */
            	5086, 8,
            	22, 24,
            8884099, 8, 2, /* 5086: pointer_to_array_of_pointers_to_stack */
            	5093, 0,
            	226, 20,
            0, 8, 1, /* 5093: pointer.X509 */
            	5098, 0,
            0, 0, 1, /* 5098: X509 */
            	5103, 0,
            0, 184, 12, /* 5103: struct.x509_st */
            	5130, 0,
            	5170, 8,
            	5245, 16,
            	17, 32,
            	5279, 40,
            	5301, 104,
            	5306, 112,
            	5311, 120,
            	5316, 128,
            	5340, 136,
            	5364, 144,
            	5369, 176,
            1, 8, 1, /* 5130: pointer.struct.x509_cinf_st */
            	5135, 0,
            0, 104, 11, /* 5135: struct.x509_cinf_st */
            	5160, 0,
            	5160, 8,
            	5170, 16,
            	5175, 24,
            	5223, 32,
            	5175, 40,
            	5240, 48,
            	5245, 56,
            	5245, 64,
            	5250, 72,
            	5274, 80,
            1, 8, 1, /* 5160: pointer.struct.asn1_string_st */
            	5165, 0,
            0, 24, 1, /* 5165: struct.asn1_string_st */
            	221, 8,
            1, 8, 1, /* 5170: pointer.struct.X509_algor_st */
            	595, 0,
            1, 8, 1, /* 5175: pointer.struct.X509_name_st */
            	5180, 0,
            0, 40, 3, /* 5180: struct.X509_name_st */
            	5189, 0,
            	5213, 16,
            	221, 24,
            1, 8, 1, /* 5189: pointer.struct.stack_st_X509_NAME_ENTRY */
            	5194, 0,
            0, 32, 2, /* 5194: struct.stack_st_fake_X509_NAME_ENTRY */
            	5201, 8,
            	22, 24,
            8884099, 8, 2, /* 5201: pointer_to_array_of_pointers_to_stack */
            	5208, 0,
            	226, 20,
            0, 8, 1, /* 5208: pointer.X509_NAME_ENTRY */
            	177, 0,
            1, 8, 1, /* 5213: pointer.struct.buf_mem_st */
            	5218, 0,
            0, 24, 1, /* 5218: struct.buf_mem_st */
            	17, 8,
            1, 8, 1, /* 5223: pointer.struct.X509_val_st */
            	5228, 0,
            0, 16, 2, /* 5228: struct.X509_val_st */
            	5235, 0,
            	5235, 8,
            1, 8, 1, /* 5235: pointer.struct.asn1_string_st */
            	5165, 0,
            1, 8, 1, /* 5240: pointer.struct.X509_pubkey_st */
            	827, 0,
            1, 8, 1, /* 5245: pointer.struct.asn1_string_st */
            	5165, 0,
            1, 8, 1, /* 5250: pointer.struct.stack_st_X509_EXTENSION */
            	5255, 0,
            0, 32, 2, /* 5255: struct.stack_st_fake_X509_EXTENSION */
            	5262, 8,
            	22, 24,
            8884099, 8, 2, /* 5262: pointer_to_array_of_pointers_to_stack */
            	5269, 0,
            	226, 20,
            0, 8, 1, /* 5269: pointer.X509_EXTENSION */
            	2719, 0,
            0, 24, 1, /* 5274: struct.ASN1_ENCODING_st */
            	221, 0,
            0, 16, 1, /* 5279: struct.crypto_ex_data_st */
            	5284, 0,
            1, 8, 1, /* 5284: pointer.struct.stack_st_void */
            	5289, 0,
            0, 32, 1, /* 5289: struct.stack_st_void */
            	5294, 0,
            0, 32, 2, /* 5294: struct.stack_st */
            	12, 8,
            	22, 24,
            1, 8, 1, /* 5301: pointer.struct.asn1_string_st */
            	5165, 0,
            1, 8, 1, /* 5306: pointer.struct.AUTHORITY_KEYID_st */
            	2792, 0,
            1, 8, 1, /* 5311: pointer.struct.X509_POLICY_CACHE_st */
            	3057, 0,
            1, 8, 1, /* 5316: pointer.struct.stack_st_DIST_POINT */
            	5321, 0,
            0, 32, 2, /* 5321: struct.stack_st_fake_DIST_POINT */
            	5328, 8,
            	22, 24,
            8884099, 8, 2, /* 5328: pointer_to_array_of_pointers_to_stack */
            	5335, 0,
            	226, 20,
            0, 8, 1, /* 5335: pointer.DIST_POINT */
            	3493, 0,
            1, 8, 1, /* 5340: pointer.struct.stack_st_GENERAL_NAME */
            	5345, 0,
            0, 32, 2, /* 5345: struct.stack_st_fake_GENERAL_NAME */
            	5352, 8,
            	22, 24,
            8884099, 8, 2, /* 5352: pointer_to_array_of_pointers_to_stack */
            	5359, 0,
            	226, 20,
            0, 8, 1, /* 5359: pointer.GENERAL_NAME */
            	2835, 0,
            1, 8, 1, /* 5364: pointer.struct.NAME_CONSTRAINTS_st */
            	3637, 0,
            1, 8, 1, /* 5369: pointer.struct.x509_cert_aux_st */
            	5374, 0,
            0, 40, 5, /* 5374: struct.x509_cert_aux_st */
            	5387, 0,
            	5387, 8,
            	5411, 16,
            	5301, 24,
            	5416, 32,
            1, 8, 1, /* 5387: pointer.struct.stack_st_ASN1_OBJECT */
            	5392, 0,
            0, 32, 2, /* 5392: struct.stack_st_fake_ASN1_OBJECT */
            	5399, 8,
            	22, 24,
            8884099, 8, 2, /* 5399: pointer_to_array_of_pointers_to_stack */
            	5406, 0,
            	226, 20,
            0, 8, 1, /* 5406: pointer.ASN1_OBJECT */
            	459, 0,
            1, 8, 1, /* 5411: pointer.struct.asn1_string_st */
            	5165, 0,
            1, 8, 1, /* 5416: pointer.struct.stack_st_X509_ALGOR */
            	5421, 0,
            0, 32, 2, /* 5421: struct.stack_st_fake_X509_ALGOR */
            	5428, 8,
            	22, 24,
            8884099, 8, 2, /* 5428: pointer_to_array_of_pointers_to_stack */
            	5435, 0,
            	226, 20,
            0, 8, 1, /* 5435: pointer.X509_ALGOR */
            	3991, 0,
            1, 8, 1, /* 5440: pointer.struct.cert_pkey_st */
            	5445, 0,
            0, 24, 3, /* 5445: struct.cert_pkey_st */
            	5454, 0,
            	5796, 8,
            	5879, 16,
            1, 8, 1, /* 5454: pointer.struct.x509_st */
            	5459, 0,
            0, 184, 12, /* 5459: struct.x509_st */
            	5486, 0,
            	5526, 8,
            	5601, 16,
            	17, 32,
            	5635, 40,
            	5657, 104,
            	5662, 112,
            	5667, 120,
            	5672, 128,
            	5696, 136,
            	5720, 144,
            	5725, 176,
            1, 8, 1, /* 5486: pointer.struct.x509_cinf_st */
            	5491, 0,
            0, 104, 11, /* 5491: struct.x509_cinf_st */
            	5516, 0,
            	5516, 8,
            	5526, 16,
            	5531, 24,
            	5579, 32,
            	5531, 40,
            	5596, 48,
            	5601, 56,
            	5601, 64,
            	5606, 72,
            	5630, 80,
            1, 8, 1, /* 5516: pointer.struct.asn1_string_st */
            	5521, 0,
            0, 24, 1, /* 5521: struct.asn1_string_st */
            	221, 8,
            1, 8, 1, /* 5526: pointer.struct.X509_algor_st */
            	595, 0,
            1, 8, 1, /* 5531: pointer.struct.X509_name_st */
            	5536, 0,
            0, 40, 3, /* 5536: struct.X509_name_st */
            	5545, 0,
            	5569, 16,
            	221, 24,
            1, 8, 1, /* 5545: pointer.struct.stack_st_X509_NAME_ENTRY */
            	5550, 0,
            0, 32, 2, /* 5550: struct.stack_st_fake_X509_NAME_ENTRY */
            	5557, 8,
            	22, 24,
            8884099, 8, 2, /* 5557: pointer_to_array_of_pointers_to_stack */
            	5564, 0,
            	226, 20,
            0, 8, 1, /* 5564: pointer.X509_NAME_ENTRY */
            	177, 0,
            1, 8, 1, /* 5569: pointer.struct.buf_mem_st */
            	5574, 0,
            0, 24, 1, /* 5574: struct.buf_mem_st */
            	17, 8,
            1, 8, 1, /* 5579: pointer.struct.X509_val_st */
            	5584, 0,
            0, 16, 2, /* 5584: struct.X509_val_st */
            	5591, 0,
            	5591, 8,
            1, 8, 1, /* 5591: pointer.struct.asn1_string_st */
            	5521, 0,
            1, 8, 1, /* 5596: pointer.struct.X509_pubkey_st */
            	827, 0,
            1, 8, 1, /* 5601: pointer.struct.asn1_string_st */
            	5521, 0,
            1, 8, 1, /* 5606: pointer.struct.stack_st_X509_EXTENSION */
            	5611, 0,
            0, 32, 2, /* 5611: struct.stack_st_fake_X509_EXTENSION */
            	5618, 8,
            	22, 24,
            8884099, 8, 2, /* 5618: pointer_to_array_of_pointers_to_stack */
            	5625, 0,
            	226, 20,
            0, 8, 1, /* 5625: pointer.X509_EXTENSION */
            	2719, 0,
            0, 24, 1, /* 5630: struct.ASN1_ENCODING_st */
            	221, 0,
            0, 16, 1, /* 5635: struct.crypto_ex_data_st */
            	5640, 0,
            1, 8, 1, /* 5640: pointer.struct.stack_st_void */
            	5645, 0,
            0, 32, 1, /* 5645: struct.stack_st_void */
            	5650, 0,
            0, 32, 2, /* 5650: struct.stack_st */
            	12, 8,
            	22, 24,
            1, 8, 1, /* 5657: pointer.struct.asn1_string_st */
            	5521, 0,
            1, 8, 1, /* 5662: pointer.struct.AUTHORITY_KEYID_st */
            	2792, 0,
            1, 8, 1, /* 5667: pointer.struct.X509_POLICY_CACHE_st */
            	3057, 0,
            1, 8, 1, /* 5672: pointer.struct.stack_st_DIST_POINT */
            	5677, 0,
            0, 32, 2, /* 5677: struct.stack_st_fake_DIST_POINT */
            	5684, 8,
            	22, 24,
            8884099, 8, 2, /* 5684: pointer_to_array_of_pointers_to_stack */
            	5691, 0,
            	226, 20,
            0, 8, 1, /* 5691: pointer.DIST_POINT */
            	3493, 0,
            1, 8, 1, /* 5696: pointer.struct.stack_st_GENERAL_NAME */
            	5701, 0,
            0, 32, 2, /* 5701: struct.stack_st_fake_GENERAL_NAME */
            	5708, 8,
            	22, 24,
            8884099, 8, 2, /* 5708: pointer_to_array_of_pointers_to_stack */
            	5715, 0,
            	226, 20,
            0, 8, 1, /* 5715: pointer.GENERAL_NAME */
            	2835, 0,
            1, 8, 1, /* 5720: pointer.struct.NAME_CONSTRAINTS_st */
            	3637, 0,
            1, 8, 1, /* 5725: pointer.struct.x509_cert_aux_st */
            	5730, 0,
            0, 40, 5, /* 5730: struct.x509_cert_aux_st */
            	5743, 0,
            	5743, 8,
            	5767, 16,
            	5657, 24,
            	5772, 32,
            1, 8, 1, /* 5743: pointer.struct.stack_st_ASN1_OBJECT */
            	5748, 0,
            0, 32, 2, /* 5748: struct.stack_st_fake_ASN1_OBJECT */
            	5755, 8,
            	22, 24,
            8884099, 8, 2, /* 5755: pointer_to_array_of_pointers_to_stack */
            	5762, 0,
            	226, 20,
            0, 8, 1, /* 5762: pointer.ASN1_OBJECT */
            	459, 0,
            1, 8, 1, /* 5767: pointer.struct.asn1_string_st */
            	5521, 0,
            1, 8, 1, /* 5772: pointer.struct.stack_st_X509_ALGOR */
            	5777, 0,
            0, 32, 2, /* 5777: struct.stack_st_fake_X509_ALGOR */
            	5784, 8,
            	22, 24,
            8884099, 8, 2, /* 5784: pointer_to_array_of_pointers_to_stack */
            	5791, 0,
            	226, 20,
            0, 8, 1, /* 5791: pointer.X509_ALGOR */
            	3991, 0,
            1, 8, 1, /* 5796: pointer.struct.evp_pkey_st */
            	5801, 0,
            0, 56, 4, /* 5801: struct.evp_pkey_st */
            	5812, 16,
            	5817, 24,
            	5822, 32,
            	5855, 48,
            1, 8, 1, /* 5812: pointer.struct.evp_pkey_asn1_method_st */
            	872, 0,
            1, 8, 1, /* 5817: pointer.struct.engine_st */
            	973, 0,
            0, 8, 5, /* 5822: union.unknown */
            	17, 0,
            	5835, 0,
            	5840, 0,
            	5845, 0,
            	5850, 0,
            1, 8, 1, /* 5835: pointer.struct.rsa_st */
            	1334, 0,
            1, 8, 1, /* 5840: pointer.struct.dsa_st */
            	1550, 0,
            1, 8, 1, /* 5845: pointer.struct.dh_st */
            	1689, 0,
            1, 8, 1, /* 5850: pointer.struct.ec_key_st */
            	1815, 0,
            1, 8, 1, /* 5855: pointer.struct.stack_st_X509_ATTRIBUTE */
            	5860, 0,
            0, 32, 2, /* 5860: struct.stack_st_fake_X509_ATTRIBUTE */
            	5867, 8,
            	22, 24,
            8884099, 8, 2, /* 5867: pointer_to_array_of_pointers_to_stack */
            	5874, 0,
            	226, 20,
            0, 8, 1, /* 5874: pointer.X509_ATTRIBUTE */
            	2343, 0,
            1, 8, 1, /* 5879: pointer.struct.env_md_st */
            	5884, 0,
            0, 120, 8, /* 5884: struct.env_md_st */
            	5903, 24,
            	5906, 32,
            	5909, 40,
            	5912, 48,
            	5903, 56,
            	5915, 64,
            	5918, 72,
            	5921, 112,
            8884097, 8, 0, /* 5903: pointer.func */
            8884097, 8, 0, /* 5906: pointer.func */
            8884097, 8, 0, /* 5909: pointer.func */
            8884097, 8, 0, /* 5912: pointer.func */
            8884097, 8, 0, /* 5915: pointer.func */
            8884097, 8, 0, /* 5918: pointer.func */
            8884097, 8, 0, /* 5921: pointer.func */
            1, 8, 1, /* 5924: pointer.struct.rsa_st */
            	1334, 0,
            1, 8, 1, /* 5929: pointer.struct.dh_st */
            	1689, 0,
            1, 8, 1, /* 5934: pointer.struct.ec_key_st */
            	1815, 0,
            1, 8, 1, /* 5939: pointer.struct.x509_st */
            	5944, 0,
            0, 184, 12, /* 5944: struct.x509_st */
            	5971, 0,
            	6011, 8,
            	6086, 16,
            	17, 32,
            	4998, 40,
            	6120, 104,
            	5662, 112,
            	5667, 120,
            	5672, 128,
            	5696, 136,
            	5720, 144,
            	6125, 176,
            1, 8, 1, /* 5971: pointer.struct.x509_cinf_st */
            	5976, 0,
            0, 104, 11, /* 5976: struct.x509_cinf_st */
            	6001, 0,
            	6001, 8,
            	6011, 16,
            	6016, 24,
            	6064, 32,
            	6016, 40,
            	6081, 48,
            	6086, 56,
            	6086, 64,
            	6091, 72,
            	6115, 80,
            1, 8, 1, /* 6001: pointer.struct.asn1_string_st */
            	6006, 0,
            0, 24, 1, /* 6006: struct.asn1_string_st */
            	221, 8,
            1, 8, 1, /* 6011: pointer.struct.X509_algor_st */
            	595, 0,
            1, 8, 1, /* 6016: pointer.struct.X509_name_st */
            	6021, 0,
            0, 40, 3, /* 6021: struct.X509_name_st */
            	6030, 0,
            	6054, 16,
            	221, 24,
            1, 8, 1, /* 6030: pointer.struct.stack_st_X509_NAME_ENTRY */
            	6035, 0,
            0, 32, 2, /* 6035: struct.stack_st_fake_X509_NAME_ENTRY */
            	6042, 8,
            	22, 24,
            8884099, 8, 2, /* 6042: pointer_to_array_of_pointers_to_stack */
            	6049, 0,
            	226, 20,
            0, 8, 1, /* 6049: pointer.X509_NAME_ENTRY */
            	177, 0,
            1, 8, 1, /* 6054: pointer.struct.buf_mem_st */
            	6059, 0,
            0, 24, 1, /* 6059: struct.buf_mem_st */
            	17, 8,
            1, 8, 1, /* 6064: pointer.struct.X509_val_st */
            	6069, 0,
            0, 16, 2, /* 6069: struct.X509_val_st */
            	6076, 0,
            	6076, 8,
            1, 8, 1, /* 6076: pointer.struct.asn1_string_st */
            	6006, 0,
            1, 8, 1, /* 6081: pointer.struct.X509_pubkey_st */
            	827, 0,
            1, 8, 1, /* 6086: pointer.struct.asn1_string_st */
            	6006, 0,
            1, 8, 1, /* 6091: pointer.struct.stack_st_X509_EXTENSION */
            	6096, 0,
            0, 32, 2, /* 6096: struct.stack_st_fake_X509_EXTENSION */
            	6103, 8,
            	22, 24,
            8884099, 8, 2, /* 6103: pointer_to_array_of_pointers_to_stack */
            	6110, 0,
            	226, 20,
            0, 8, 1, /* 6110: pointer.X509_EXTENSION */
            	2719, 0,
            0, 24, 1, /* 6115: struct.ASN1_ENCODING_st */
            	221, 0,
            1, 8, 1, /* 6120: pointer.struct.asn1_string_st */
            	6006, 0,
            1, 8, 1, /* 6125: pointer.struct.x509_cert_aux_st */
            	6130, 0,
            0, 40, 5, /* 6130: struct.x509_cert_aux_st */
            	4962, 0,
            	4962, 8,
            	6143, 16,
            	6120, 24,
            	6148, 32,
            1, 8, 1, /* 6143: pointer.struct.asn1_string_st */
            	6006, 0,
            1, 8, 1, /* 6148: pointer.struct.stack_st_X509_ALGOR */
            	6153, 0,
            0, 32, 2, /* 6153: struct.stack_st_fake_X509_ALGOR */
            	6160, 8,
            	22, 24,
            8884099, 8, 2, /* 6160: pointer_to_array_of_pointers_to_stack */
            	6167, 0,
            	226, 20,
            0, 8, 1, /* 6167: pointer.X509_ALGOR */
            	3991, 0,
            1, 8, 1, /* 6172: pointer.struct.ssl_cipher_st */
            	6177, 0,
            0, 88, 1, /* 6177: struct.ssl_cipher_st */
            	56, 8,
            8884097, 8, 0, /* 6182: pointer.func */
            8884097, 8, 0, /* 6185: pointer.func */
            8884097, 8, 0, /* 6188: pointer.func */
            8884097, 8, 0, /* 6191: pointer.func */
            1, 8, 1, /* 6194: pointer.struct.env_md_st */
            	6199, 0,
            0, 120, 8, /* 6199: struct.env_md_st */
            	6218, 24,
            	6221, 32,
            	6224, 40,
            	6227, 48,
            	6218, 56,
            	5915, 64,
            	5918, 72,
            	6230, 112,
            8884097, 8, 0, /* 6218: pointer.func */
            8884097, 8, 0, /* 6221: pointer.func */
            8884097, 8, 0, /* 6224: pointer.func */
            8884097, 8, 0, /* 6227: pointer.func */
            8884097, 8, 0, /* 6230: pointer.func */
            1, 8, 1, /* 6233: pointer.struct.stack_st_X509 */
            	6238, 0,
            0, 32, 2, /* 6238: struct.stack_st_fake_X509 */
            	6245, 8,
            	22, 24,
            8884099, 8, 2, /* 6245: pointer_to_array_of_pointers_to_stack */
            	6252, 0,
            	226, 20,
            0, 8, 1, /* 6252: pointer.X509 */
            	5098, 0,
            1, 8, 1, /* 6257: pointer.struct.stack_st_SSL_COMP */
            	6262, 0,
            0, 32, 2, /* 6262: struct.stack_st_fake_SSL_COMP */
            	6269, 8,
            	22, 24,
            8884099, 8, 2, /* 6269: pointer_to_array_of_pointers_to_stack */
            	6276, 0,
            	226, 20,
            0, 8, 1, /* 6276: pointer.SSL_COMP */
            	334, 0,
            8884097, 8, 0, /* 6281: pointer.func */
            1, 8, 1, /* 6284: pointer.struct.stack_st_X509_NAME */
            	6289, 0,
            0, 32, 2, /* 6289: struct.stack_st_fake_X509_NAME */
            	6296, 8,
            	22, 24,
            8884099, 8, 2, /* 6296: pointer_to_array_of_pointers_to_stack */
            	6303, 0,
            	226, 20,
            0, 8, 1, /* 6303: pointer.X509_NAME */
            	6308, 0,
            0, 0, 1, /* 6308: X509_NAME */
            	6313, 0,
            0, 40, 3, /* 6313: struct.X509_name_st */
            	6322, 0,
            	6346, 16,
            	221, 24,
            1, 8, 1, /* 6322: pointer.struct.stack_st_X509_NAME_ENTRY */
            	6327, 0,
            0, 32, 2, /* 6327: struct.stack_st_fake_X509_NAME_ENTRY */
            	6334, 8,
            	22, 24,
            8884099, 8, 2, /* 6334: pointer_to_array_of_pointers_to_stack */
            	6341, 0,
            	226, 20,
            0, 8, 1, /* 6341: pointer.X509_NAME_ENTRY */
            	177, 0,
            1, 8, 1, /* 6346: pointer.struct.buf_mem_st */
            	6351, 0,
            0, 24, 1, /* 6351: struct.buf_mem_st */
            	17, 8,
            1, 8, 1, /* 6356: pointer.struct.cert_st */
            	6361, 0,
            0, 296, 7, /* 6361: struct.cert_st */
            	6378, 0,
            	6778, 48,
            	6783, 56,
            	6786, 64,
            	6791, 72,
            	5934, 80,
            	6794, 88,
            1, 8, 1, /* 6378: pointer.struct.cert_pkey_st */
            	6383, 0,
            0, 24, 3, /* 6383: struct.cert_pkey_st */
            	6392, 0,
            	6671, 8,
            	6739, 16,
            1, 8, 1, /* 6392: pointer.struct.x509_st */
            	6397, 0,
            0, 184, 12, /* 6397: struct.x509_st */
            	6424, 0,
            	6464, 8,
            	6539, 16,
            	17, 32,
            	6573, 40,
            	6595, 104,
            	5662, 112,
            	5667, 120,
            	5672, 128,
            	5696, 136,
            	5720, 144,
            	6600, 176,
            1, 8, 1, /* 6424: pointer.struct.x509_cinf_st */
            	6429, 0,
            0, 104, 11, /* 6429: struct.x509_cinf_st */
            	6454, 0,
            	6454, 8,
            	6464, 16,
            	6469, 24,
            	6517, 32,
            	6469, 40,
            	6534, 48,
            	6539, 56,
            	6539, 64,
            	6544, 72,
            	6568, 80,
            1, 8, 1, /* 6454: pointer.struct.asn1_string_st */
            	6459, 0,
            0, 24, 1, /* 6459: struct.asn1_string_st */
            	221, 8,
            1, 8, 1, /* 6464: pointer.struct.X509_algor_st */
            	595, 0,
            1, 8, 1, /* 6469: pointer.struct.X509_name_st */
            	6474, 0,
            0, 40, 3, /* 6474: struct.X509_name_st */
            	6483, 0,
            	6507, 16,
            	221, 24,
            1, 8, 1, /* 6483: pointer.struct.stack_st_X509_NAME_ENTRY */
            	6488, 0,
            0, 32, 2, /* 6488: struct.stack_st_fake_X509_NAME_ENTRY */
            	6495, 8,
            	22, 24,
            8884099, 8, 2, /* 6495: pointer_to_array_of_pointers_to_stack */
            	6502, 0,
            	226, 20,
            0, 8, 1, /* 6502: pointer.X509_NAME_ENTRY */
            	177, 0,
            1, 8, 1, /* 6507: pointer.struct.buf_mem_st */
            	6512, 0,
            0, 24, 1, /* 6512: struct.buf_mem_st */
            	17, 8,
            1, 8, 1, /* 6517: pointer.struct.X509_val_st */
            	6522, 0,
            0, 16, 2, /* 6522: struct.X509_val_st */
            	6529, 0,
            	6529, 8,
            1, 8, 1, /* 6529: pointer.struct.asn1_string_st */
            	6459, 0,
            1, 8, 1, /* 6534: pointer.struct.X509_pubkey_st */
            	827, 0,
            1, 8, 1, /* 6539: pointer.struct.asn1_string_st */
            	6459, 0,
            1, 8, 1, /* 6544: pointer.struct.stack_st_X509_EXTENSION */
            	6549, 0,
            0, 32, 2, /* 6549: struct.stack_st_fake_X509_EXTENSION */
            	6556, 8,
            	22, 24,
            8884099, 8, 2, /* 6556: pointer_to_array_of_pointers_to_stack */
            	6563, 0,
            	226, 20,
            0, 8, 1, /* 6563: pointer.X509_EXTENSION */
            	2719, 0,
            0, 24, 1, /* 6568: struct.ASN1_ENCODING_st */
            	221, 0,
            0, 16, 1, /* 6573: struct.crypto_ex_data_st */
            	6578, 0,
            1, 8, 1, /* 6578: pointer.struct.stack_st_void */
            	6583, 0,
            0, 32, 1, /* 6583: struct.stack_st_void */
            	6588, 0,
            0, 32, 2, /* 6588: struct.stack_st */
            	12, 8,
            	22, 24,
            1, 8, 1, /* 6595: pointer.struct.asn1_string_st */
            	6459, 0,
            1, 8, 1, /* 6600: pointer.struct.x509_cert_aux_st */
            	6605, 0,
            0, 40, 5, /* 6605: struct.x509_cert_aux_st */
            	6618, 0,
            	6618, 8,
            	6642, 16,
            	6595, 24,
            	6647, 32,
            1, 8, 1, /* 6618: pointer.struct.stack_st_ASN1_OBJECT */
            	6623, 0,
            0, 32, 2, /* 6623: struct.stack_st_fake_ASN1_OBJECT */
            	6630, 8,
            	22, 24,
            8884099, 8, 2, /* 6630: pointer_to_array_of_pointers_to_stack */
            	6637, 0,
            	226, 20,
            0, 8, 1, /* 6637: pointer.ASN1_OBJECT */
            	459, 0,
            1, 8, 1, /* 6642: pointer.struct.asn1_string_st */
            	6459, 0,
            1, 8, 1, /* 6647: pointer.struct.stack_st_X509_ALGOR */
            	6652, 0,
            0, 32, 2, /* 6652: struct.stack_st_fake_X509_ALGOR */
            	6659, 8,
            	22, 24,
            8884099, 8, 2, /* 6659: pointer_to_array_of_pointers_to_stack */
            	6666, 0,
            	226, 20,
            0, 8, 1, /* 6666: pointer.X509_ALGOR */
            	3991, 0,
            1, 8, 1, /* 6671: pointer.struct.evp_pkey_st */
            	6676, 0,
            0, 56, 4, /* 6676: struct.evp_pkey_st */
            	5812, 16,
            	5817, 24,
            	6687, 32,
            	6715, 48,
            0, 8, 5, /* 6687: union.unknown */
            	17, 0,
            	6700, 0,
            	6705, 0,
            	6710, 0,
            	5850, 0,
            1, 8, 1, /* 6700: pointer.struct.rsa_st */
            	1334, 0,
            1, 8, 1, /* 6705: pointer.struct.dsa_st */
            	1550, 0,
            1, 8, 1, /* 6710: pointer.struct.dh_st */
            	1689, 0,
            1, 8, 1, /* 6715: pointer.struct.stack_st_X509_ATTRIBUTE */
            	6720, 0,
            0, 32, 2, /* 6720: struct.stack_st_fake_X509_ATTRIBUTE */
            	6727, 8,
            	22, 24,
            8884099, 8, 2, /* 6727: pointer_to_array_of_pointers_to_stack */
            	6734, 0,
            	226, 20,
            0, 8, 1, /* 6734: pointer.X509_ATTRIBUTE */
            	2343, 0,
            1, 8, 1, /* 6739: pointer.struct.env_md_st */
            	6744, 0,
            0, 120, 8, /* 6744: struct.env_md_st */
            	6763, 24,
            	6766, 32,
            	6769, 40,
            	6772, 48,
            	6763, 56,
            	5915, 64,
            	5918, 72,
            	6775, 112,
            8884097, 8, 0, /* 6763: pointer.func */
            8884097, 8, 0, /* 6766: pointer.func */
            8884097, 8, 0, /* 6769: pointer.func */
            8884097, 8, 0, /* 6772: pointer.func */
            8884097, 8, 0, /* 6775: pointer.func */
            1, 8, 1, /* 6778: pointer.struct.rsa_st */
            	1334, 0,
            8884097, 8, 0, /* 6783: pointer.func */
            1, 8, 1, /* 6786: pointer.struct.dh_st */
            	1689, 0,
            8884097, 8, 0, /* 6791: pointer.func */
            8884097, 8, 0, /* 6794: pointer.func */
            8884097, 8, 0, /* 6797: pointer.func */
            8884097, 8, 0, /* 6800: pointer.func */
            8884097, 8, 0, /* 6803: pointer.func */
            8884097, 8, 0, /* 6806: pointer.func */
            8884097, 8, 0, /* 6809: pointer.func */
            8884097, 8, 0, /* 6812: pointer.func */
            8884097, 8, 0, /* 6815: pointer.func */
            0, 128, 14, /* 6818: struct.srp_ctx_st */
            	104, 0,
            	6803, 8,
            	6809, 16,
            	6849, 24,
            	17, 32,
            	277, 40,
            	277, 48,
            	277, 56,
            	277, 64,
            	277, 72,
            	277, 80,
            	277, 88,
            	277, 96,
            	17, 104,
            8884097, 8, 0, /* 6849: pointer.func */
            8884097, 8, 0, /* 6852: pointer.func */
            1, 8, 1, /* 6855: pointer.struct.stack_st_SRTP_PROTECTION_PROFILE */
            	6860, 0,
            0, 32, 2, /* 6860: struct.stack_st_fake_SRTP_PROTECTION_PROFILE */
            	6867, 8,
            	22, 24,
            8884099, 8, 2, /* 6867: pointer_to_array_of_pointers_to_stack */
            	6874, 0,
            	226, 20,
            0, 8, 1, /* 6874: pointer.SRTP_PROTECTION_PROFILE */
            	254, 0,
            1, 8, 1, /* 6879: pointer.struct.tls_session_ticket_ext_st */
            	117, 0,
            1, 8, 1, /* 6884: pointer.struct.srtp_protection_profile_st */
            	112, 0,
            1, 8, 1, /* 6889: pointer.struct.ssl_st */
            	6894, 0,
            0, 808, 51, /* 6894: struct.ssl_st */
            	4712, 8,
            	6999, 16,
            	6999, 24,
            	6999, 32,
            	4776, 48,
            	6054, 80,
            	104, 88,
            	221, 104,
            	7073, 120,
            	7099, 128,
            	7472, 136,
            	6797, 152,
            	104, 160,
            	4950, 176,
            	4878, 184,
            	4878, 192,
            	7542, 208,
            	7146, 216,
            	7558, 224,
            	7542, 232,
            	7146, 240,
            	7558, 248,
            	6356, 256,
            	7570, 304,
            	6800, 312,
            	4989, 328,
            	6281, 336,
            	6812, 352,
            	6815, 360,
            	4604, 368,
            	4998, 392,
            	6284, 408,
            	7575, 464,
            	104, 472,
            	17, 480,
            	7578, 504,
            	7602, 512,
            	221, 520,
            	221, 544,
            	221, 560,
            	104, 568,
            	6879, 584,
            	7626, 592,
            	104, 600,
            	7629, 608,
            	104, 616,
            	4604, 624,
            	221, 632,
            	6855, 648,
            	6884, 656,
            	6818, 680,
            1, 8, 1, /* 6999: pointer.struct.bio_st */
            	7004, 0,
            0, 112, 7, /* 7004: struct.bio_st */
            	7021, 0,
            	7065, 8,
            	17, 16,
            	104, 48,
            	7068, 56,
            	7068, 64,
            	4998, 96,
            1, 8, 1, /* 7021: pointer.struct.bio_method_st */
            	7026, 0,
            0, 80, 9, /* 7026: struct.bio_method_st */
            	56, 8,
            	7047, 16,
            	7050, 24,
            	7053, 32,
            	7050, 40,
            	7056, 48,
            	7059, 56,
            	7059, 64,
            	7062, 72,
            8884097, 8, 0, /* 7047: pointer.func */
            8884097, 8, 0, /* 7050: pointer.func */
            8884097, 8, 0, /* 7053: pointer.func */
            8884097, 8, 0, /* 7056: pointer.func */
            8884097, 8, 0, /* 7059: pointer.func */
            8884097, 8, 0, /* 7062: pointer.func */
            8884097, 8, 0, /* 7065: pointer.func */
            1, 8, 1, /* 7068: pointer.struct.bio_st */
            	7004, 0,
            1, 8, 1, /* 7073: pointer.struct.ssl2_state_st */
            	7078, 0,
            0, 344, 9, /* 7078: struct.ssl2_state_st */
            	203, 24,
            	221, 56,
            	221, 64,
            	221, 72,
            	221, 104,
            	221, 112,
            	221, 120,
            	221, 128,
            	221, 136,
            1, 8, 1, /* 7099: pointer.struct.ssl3_state_st */
            	7104, 0,
            0, 1200, 10, /* 7104: struct.ssl3_state_st */
            	7127, 240,
            	7127, 264,
            	7132, 288,
            	7132, 344,
            	203, 432,
            	6999, 440,
            	7141, 448,
            	104, 496,
            	104, 512,
            	7368, 528,
            0, 24, 1, /* 7127: struct.ssl3_buffer_st */
            	221, 0,
            0, 56, 3, /* 7132: struct.ssl3_record_st */
            	221, 16,
            	221, 24,
            	221, 32,
            1, 8, 1, /* 7141: pointer.pointer.struct.env_md_ctx_st */
            	7146, 0,
            1, 8, 1, /* 7146: pointer.struct.env_md_ctx_st */
            	7151, 0,
            0, 48, 5, /* 7151: struct.env_md_ctx_st */
            	6194, 0,
            	5817, 8,
            	104, 24,
            	7164, 32,
            	6221, 40,
            1, 8, 1, /* 7164: pointer.struct.evp_pkey_ctx_st */
            	7169, 0,
            0, 80, 8, /* 7169: struct.evp_pkey_ctx_st */
            	7188, 0,
            	1805, 8,
            	7282, 16,
            	7282, 24,
            	104, 40,
            	104, 48,
            	7360, 56,
            	7363, 64,
            1, 8, 1, /* 7188: pointer.struct.evp_pkey_method_st */
            	7193, 0,
            0, 208, 25, /* 7193: struct.evp_pkey_method_st */
            	7246, 8,
            	7249, 16,
            	7252, 24,
            	7246, 32,
            	7255, 40,
            	7246, 48,
            	7255, 56,
            	7246, 64,
            	7258, 72,
            	7246, 80,
            	7261, 88,
            	7246, 96,
            	7258, 104,
            	7264, 112,
            	7267, 120,
            	7264, 128,
            	7270, 136,
            	7246, 144,
            	7258, 152,
            	7246, 160,
            	7258, 168,
            	7246, 176,
            	7273, 184,
            	7276, 192,
            	7279, 200,
            8884097, 8, 0, /* 7246: pointer.func */
            8884097, 8, 0, /* 7249: pointer.func */
            8884097, 8, 0, /* 7252: pointer.func */
            8884097, 8, 0, /* 7255: pointer.func */
            8884097, 8, 0, /* 7258: pointer.func */
            8884097, 8, 0, /* 7261: pointer.func */
            8884097, 8, 0, /* 7264: pointer.func */
            8884097, 8, 0, /* 7267: pointer.func */
            8884097, 8, 0, /* 7270: pointer.func */
            8884097, 8, 0, /* 7273: pointer.func */
            8884097, 8, 0, /* 7276: pointer.func */
            8884097, 8, 0, /* 7279: pointer.func */
            1, 8, 1, /* 7282: pointer.struct.evp_pkey_st */
            	7287, 0,
            0, 56, 4, /* 7287: struct.evp_pkey_st */
            	7298, 16,
            	1805, 24,
            	7303, 32,
            	7336, 48,
            1, 8, 1, /* 7298: pointer.struct.evp_pkey_asn1_method_st */
            	872, 0,
            0, 8, 5, /* 7303: union.unknown */
            	17, 0,
            	7316, 0,
            	7321, 0,
            	7326, 0,
            	7331, 0,
            1, 8, 1, /* 7316: pointer.struct.rsa_st */
            	1334, 0,
            1, 8, 1, /* 7321: pointer.struct.dsa_st */
            	1550, 0,
            1, 8, 1, /* 7326: pointer.struct.dh_st */
            	1689, 0,
            1, 8, 1, /* 7331: pointer.struct.ec_key_st */
            	1815, 0,
            1, 8, 1, /* 7336: pointer.struct.stack_st_X509_ATTRIBUTE */
            	7341, 0,
            0, 32, 2, /* 7341: struct.stack_st_fake_X509_ATTRIBUTE */
            	7348, 8,
            	22, 24,
            8884099, 8, 2, /* 7348: pointer_to_array_of_pointers_to_stack */
            	7355, 0,
            	226, 20,
            0, 8, 1, /* 7355: pointer.X509_ATTRIBUTE */
            	2343, 0,
            8884097, 8, 0, /* 7360: pointer.func */
            1, 8, 1, /* 7363: pointer.int */
            	226, 0,
            0, 528, 8, /* 7368: struct.unknown */
            	6172, 408,
            	7387, 416,
            	5934, 424,
            	6284, 464,
            	221, 480,
            	7392, 488,
            	6194, 496,
            	7429, 512,
            1, 8, 1, /* 7387: pointer.struct.dh_st */
            	1689, 0,
            1, 8, 1, /* 7392: pointer.struct.evp_cipher_st */
            	7397, 0,
            0, 88, 7, /* 7397: struct.evp_cipher_st */
            	7414, 24,
            	7417, 32,
            	7420, 40,
            	7423, 56,
            	7423, 64,
            	7426, 72,
            	104, 80,
            8884097, 8, 0, /* 7414: pointer.func */
            8884097, 8, 0, /* 7417: pointer.func */
            8884097, 8, 0, /* 7420: pointer.func */
            8884097, 8, 0, /* 7423: pointer.func */
            8884097, 8, 0, /* 7426: pointer.func */
            1, 8, 1, /* 7429: pointer.struct.ssl_comp_st */
            	7434, 0,
            0, 24, 2, /* 7434: struct.ssl_comp_st */
            	56, 8,
            	7441, 16,
            1, 8, 1, /* 7441: pointer.struct.comp_method_st */
            	7446, 0,
            0, 64, 7, /* 7446: struct.comp_method_st */
            	56, 8,
            	7463, 16,
            	7466, 24,
            	7469, 32,
            	7469, 40,
            	331, 48,
            	331, 56,
            8884097, 8, 0, /* 7463: pointer.func */
            8884097, 8, 0, /* 7466: pointer.func */
            8884097, 8, 0, /* 7469: pointer.func */
            1, 8, 1, /* 7472: pointer.struct.dtls1_state_st */
            	7477, 0,
            0, 888, 7, /* 7477: struct.dtls1_state_st */
            	7494, 576,
            	7494, 592,
            	7499, 608,
            	7499, 616,
            	7494, 624,
            	7526, 648,
            	7526, 736,
            0, 16, 1, /* 7494: struct.record_pqueue_st */
            	7499, 8,
            1, 8, 1, /* 7499: pointer.struct._pqueue */
            	7504, 0,
            0, 16, 1, /* 7504: struct._pqueue */
            	7509, 0,
            1, 8, 1, /* 7509: pointer.struct._pitem */
            	7514, 0,
            0, 24, 2, /* 7514: struct._pitem */
            	104, 8,
            	7521, 16,
            1, 8, 1, /* 7521: pointer.struct._pitem */
            	7514, 0,
            0, 88, 1, /* 7526: struct.hm_header_st */
            	7531, 48,
            0, 40, 4, /* 7531: struct.dtls1_retransmit_state */
            	7542, 0,
            	7146, 8,
            	7558, 16,
            	7570, 24,
            1, 8, 1, /* 7542: pointer.struct.evp_cipher_ctx_st */
            	7547, 0,
            0, 168, 4, /* 7547: struct.evp_cipher_ctx_st */
            	7392, 0,
            	5817, 8,
            	104, 96,
            	104, 120,
            1, 8, 1, /* 7558: pointer.struct.comp_ctx_st */
            	7563, 0,
            0, 56, 2, /* 7563: struct.comp_ctx_st */
            	7441, 0,
            	4998, 40,
            1, 8, 1, /* 7570: pointer.struct.ssl_session_st */
            	5025, 0,
            8884097, 8, 0, /* 7575: pointer.func */
            1, 8, 1, /* 7578: pointer.struct.stack_st_OCSP_RESPID */
            	7583, 0,
            0, 32, 2, /* 7583: struct.stack_st_fake_OCSP_RESPID */
            	7590, 8,
            	22, 24,
            8884099, 8, 2, /* 7590: pointer_to_array_of_pointers_to_stack */
            	7597, 0,
            	226, 20,
            0, 8, 1, /* 7597: pointer.OCSP_RESPID */
            	122, 0,
            1, 8, 1, /* 7602: pointer.struct.stack_st_X509_EXTENSION */
            	7607, 0,
            0, 32, 2, /* 7607: struct.stack_st_fake_X509_EXTENSION */
            	7614, 8,
            	22, 24,
            8884099, 8, 2, /* 7614: pointer_to_array_of_pointers_to_stack */
            	7621, 0,
            	226, 20,
            0, 8, 1, /* 7621: pointer.X509_EXTENSION */
            	2719, 0,
            8884097, 8, 0, /* 7626: pointer.func */
            8884097, 8, 0, /* 7629: pointer.func */
            1, 8, 1, /* 7632: pointer.struct.bio_st */
            	79, 0,
            0, 1, 0, /* 7637: char */
        },
        .arg_entity_index = { 6889, },
        .ret_entity_index = 7632,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    const SSL * new_arg_a = *((const SSL * *)new_args->args[0]);

    BIO * *new_ret_ptr = (BIO * *)new_args->ret;

    BIO * (*orig_SSL_get_wbio)(const SSL *);
    orig_SSL_get_wbio = dlsym(RTLD_NEXT, "SSL_get_wbio");
    *new_ret_ptr = (*orig_SSL_get_wbio)(new_arg_a);

    syscall(889);

    return ret;
}

