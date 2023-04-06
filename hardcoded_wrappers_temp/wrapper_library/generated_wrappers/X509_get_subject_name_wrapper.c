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

X509_NAME * bb_X509_get_subject_name(X509 * arg_a);

X509_NAME * X509_get_subject_name(X509 * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("X509_get_subject_name called %lu\n", in_lib);
    if (!in_lib)
        return bb_X509_get_subject_name(arg_a);
    else {
        X509_NAME * (*orig_X509_get_subject_name)(X509 *);
        orig_X509_get_subject_name = dlsym(RTLD_NEXT, "X509_get_subject_name");
        return orig_X509_get_subject_name(arg_a);
    }
}

X509_NAME * bb_X509_get_subject_name(X509 * arg_a) 
{
    X509_NAME * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 0, 1, /* 0: X509_ALGOR */
            	5, 0,
            0, 16, 2, /* 5: struct.X509_algor_st */
            	12, 0,
            	39, 8,
            1, 8, 1, /* 12: pointer.struct.asn1_object_st */
            	17, 0,
            0, 40, 3, /* 17: struct.asn1_object_st */
            	26, 0,
            	26, 8,
            	31, 24,
            1, 8, 1, /* 26: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 31: pointer.unsigned char */
            	36, 0,
            0, 1, 0, /* 36: unsigned char */
            1, 8, 1, /* 39: pointer.struct.asn1_type_st */
            	44, 0,
            0, 16, 1, /* 44: struct.asn1_type_st */
            	49, 8,
            0, 8, 20, /* 49: union.unknown */
            	92, 0,
            	97, 0,
            	12, 0,
            	112, 0,
            	117, 0,
            	122, 0,
            	127, 0,
            	132, 0,
            	137, 0,
            	142, 0,
            	147, 0,
            	152, 0,
            	157, 0,
            	162, 0,
            	167, 0,
            	172, 0,
            	177, 0,
            	97, 0,
            	97, 0,
            	182, 0,
            1, 8, 1, /* 92: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 97: pointer.struct.asn1_string_st */
            	102, 0,
            0, 24, 1, /* 102: struct.asn1_string_st */
            	107, 8,
            1, 8, 1, /* 107: pointer.unsigned char */
            	36, 0,
            1, 8, 1, /* 112: pointer.struct.asn1_string_st */
            	102, 0,
            1, 8, 1, /* 117: pointer.struct.asn1_string_st */
            	102, 0,
            1, 8, 1, /* 122: pointer.struct.asn1_string_st */
            	102, 0,
            1, 8, 1, /* 127: pointer.struct.asn1_string_st */
            	102, 0,
            1, 8, 1, /* 132: pointer.struct.asn1_string_st */
            	102, 0,
            1, 8, 1, /* 137: pointer.struct.asn1_string_st */
            	102, 0,
            1, 8, 1, /* 142: pointer.struct.asn1_string_st */
            	102, 0,
            1, 8, 1, /* 147: pointer.struct.asn1_string_st */
            	102, 0,
            1, 8, 1, /* 152: pointer.struct.asn1_string_st */
            	102, 0,
            1, 8, 1, /* 157: pointer.struct.asn1_string_st */
            	102, 0,
            1, 8, 1, /* 162: pointer.struct.asn1_string_st */
            	102, 0,
            1, 8, 1, /* 167: pointer.struct.asn1_string_st */
            	102, 0,
            1, 8, 1, /* 172: pointer.struct.asn1_string_st */
            	102, 0,
            1, 8, 1, /* 177: pointer.struct.asn1_string_st */
            	102, 0,
            1, 8, 1, /* 182: pointer.struct.ASN1_VALUE_st */
            	187, 0,
            0, 0, 0, /* 187: struct.ASN1_VALUE_st */
            1, 8, 1, /* 190: pointer.struct.asn1_string_st */
            	195, 0,
            0, 24, 1, /* 195: struct.asn1_string_st */
            	107, 8,
            0, 40, 5, /* 200: struct.x509_cert_aux_st */
            	213, 0,
            	213, 8,
            	190, 16,
            	257, 24,
            	262, 32,
            1, 8, 1, /* 213: pointer.struct.stack_st_ASN1_OBJECT */
            	218, 0,
            0, 32, 2, /* 218: struct.stack_st_fake_ASN1_OBJECT */
            	225, 8,
            	254, 24,
            8884099, 8, 2, /* 225: pointer_to_array_of_pointers_to_stack */
            	232, 0,
            	251, 20,
            0, 8, 1, /* 232: pointer.ASN1_OBJECT */
            	237, 0,
            0, 0, 1, /* 237: ASN1_OBJECT */
            	242, 0,
            0, 40, 3, /* 242: struct.asn1_object_st */
            	26, 0,
            	26, 8,
            	31, 24,
            0, 4, 0, /* 251: int */
            8884097, 8, 0, /* 254: pointer.func */
            1, 8, 1, /* 257: pointer.struct.asn1_string_st */
            	195, 0,
            1, 8, 1, /* 262: pointer.struct.stack_st_X509_ALGOR */
            	267, 0,
            0, 32, 2, /* 267: struct.stack_st_fake_X509_ALGOR */
            	274, 8,
            	254, 24,
            8884099, 8, 2, /* 274: pointer_to_array_of_pointers_to_stack */
            	281, 0,
            	251, 20,
            0, 8, 1, /* 281: pointer.X509_ALGOR */
            	0, 0,
            1, 8, 1, /* 286: pointer.struct.x509_cert_aux_st */
            	200, 0,
            1, 8, 1, /* 291: pointer.struct.EDIPartyName_st */
            	296, 0,
            0, 16, 2, /* 296: struct.EDIPartyName_st */
            	303, 0,
            	303, 8,
            1, 8, 1, /* 303: pointer.struct.asn1_string_st */
            	308, 0,
            0, 24, 1, /* 308: struct.asn1_string_st */
            	107, 8,
            1, 8, 1, /* 313: pointer.struct.stack_st_X509_NAME_ENTRY */
            	318, 0,
            0, 32, 2, /* 318: struct.stack_st_fake_X509_NAME_ENTRY */
            	325, 8,
            	254, 24,
            8884099, 8, 2, /* 325: pointer_to_array_of_pointers_to_stack */
            	332, 0,
            	251, 20,
            0, 8, 1, /* 332: pointer.X509_NAME_ENTRY */
            	337, 0,
            0, 0, 1, /* 337: X509_NAME_ENTRY */
            	342, 0,
            0, 24, 2, /* 342: struct.X509_name_entry_st */
            	349, 0,
            	363, 8,
            1, 8, 1, /* 349: pointer.struct.asn1_object_st */
            	354, 0,
            0, 40, 3, /* 354: struct.asn1_object_st */
            	26, 0,
            	26, 8,
            	31, 24,
            1, 8, 1, /* 363: pointer.struct.asn1_string_st */
            	368, 0,
            0, 24, 1, /* 368: struct.asn1_string_st */
            	107, 8,
            0, 40, 3, /* 373: struct.X509_name_st */
            	313, 0,
            	382, 16,
            	107, 24,
            1, 8, 1, /* 382: pointer.struct.buf_mem_st */
            	387, 0,
            0, 24, 1, /* 387: struct.buf_mem_st */
            	92, 8,
            1, 8, 1, /* 392: pointer.struct.X509_name_st */
            	373, 0,
            1, 8, 1, /* 397: pointer.struct.asn1_string_st */
            	308, 0,
            1, 8, 1, /* 402: pointer.struct.asn1_string_st */
            	308, 0,
            1, 8, 1, /* 407: pointer.struct.asn1_string_st */
            	308, 0,
            1, 8, 1, /* 412: pointer.struct.asn1_string_st */
            	308, 0,
            1, 8, 1, /* 417: pointer.struct.asn1_string_st */
            	308, 0,
            1, 8, 1, /* 422: pointer.struct.asn1_string_st */
            	308, 0,
            1, 8, 1, /* 427: pointer.struct.asn1_string_st */
            	308, 0,
            1, 8, 1, /* 432: pointer.struct.asn1_string_st */
            	308, 0,
            0, 8, 20, /* 437: union.unknown */
            	92, 0,
            	303, 0,
            	480, 0,
            	494, 0,
            	499, 0,
            	504, 0,
            	432, 0,
            	427, 0,
            	422, 0,
            	509, 0,
            	417, 0,
            	412, 0,
            	514, 0,
            	407, 0,
            	402, 0,
            	519, 0,
            	397, 0,
            	303, 0,
            	303, 0,
            	524, 0,
            1, 8, 1, /* 480: pointer.struct.asn1_object_st */
            	485, 0,
            0, 40, 3, /* 485: struct.asn1_object_st */
            	26, 0,
            	26, 8,
            	31, 24,
            1, 8, 1, /* 494: pointer.struct.asn1_string_st */
            	308, 0,
            1, 8, 1, /* 499: pointer.struct.asn1_string_st */
            	308, 0,
            1, 8, 1, /* 504: pointer.struct.asn1_string_st */
            	308, 0,
            1, 8, 1, /* 509: pointer.struct.asn1_string_st */
            	308, 0,
            1, 8, 1, /* 514: pointer.struct.asn1_string_st */
            	308, 0,
            1, 8, 1, /* 519: pointer.struct.asn1_string_st */
            	308, 0,
            1, 8, 1, /* 524: pointer.struct.ASN1_VALUE_st */
            	529, 0,
            0, 0, 0, /* 529: struct.ASN1_VALUE_st */
            1, 8, 1, /* 532: pointer.struct.otherName_st */
            	537, 0,
            0, 16, 2, /* 537: struct.otherName_st */
            	480, 0,
            	544, 8,
            1, 8, 1, /* 544: pointer.struct.asn1_type_st */
            	549, 0,
            0, 16, 1, /* 549: struct.asn1_type_st */
            	437, 8,
            0, 16, 1, /* 554: struct.GENERAL_NAME_st */
            	559, 8,
            0, 8, 15, /* 559: union.unknown */
            	92, 0,
            	532, 0,
            	509, 0,
            	509, 0,
            	544, 0,
            	392, 0,
            	291, 0,
            	509, 0,
            	432, 0,
            	480, 0,
            	432, 0,
            	392, 0,
            	509, 0,
            	480, 0,
            	544, 0,
            1, 8, 1, /* 592: pointer.struct.GENERAL_NAME_st */
            	554, 0,
            0, 24, 3, /* 597: struct.GENERAL_SUBTREE_st */
            	592, 0,
            	494, 8,
            	494, 16,
            1, 8, 1, /* 606: pointer.struct.stack_st_GENERAL_NAME */
            	611, 0,
            0, 32, 2, /* 611: struct.stack_st_fake_GENERAL_NAME */
            	618, 8,
            	254, 24,
            8884099, 8, 2, /* 618: pointer_to_array_of_pointers_to_stack */
            	625, 0,
            	251, 20,
            0, 8, 1, /* 625: pointer.GENERAL_NAME */
            	630, 0,
            0, 0, 1, /* 630: GENERAL_NAME */
            	635, 0,
            0, 16, 1, /* 635: struct.GENERAL_NAME_st */
            	640, 8,
            0, 8, 15, /* 640: union.unknown */
            	92, 0,
            	673, 0,
            	792, 0,
            	792, 0,
            	699, 0,
            	840, 0,
            	888, 0,
            	792, 0,
            	777, 0,
            	685, 0,
            	777, 0,
            	840, 0,
            	792, 0,
            	685, 0,
            	699, 0,
            1, 8, 1, /* 673: pointer.struct.otherName_st */
            	678, 0,
            0, 16, 2, /* 678: struct.otherName_st */
            	685, 0,
            	699, 8,
            1, 8, 1, /* 685: pointer.struct.asn1_object_st */
            	690, 0,
            0, 40, 3, /* 690: struct.asn1_object_st */
            	26, 0,
            	26, 8,
            	31, 24,
            1, 8, 1, /* 699: pointer.struct.asn1_type_st */
            	704, 0,
            0, 16, 1, /* 704: struct.asn1_type_st */
            	709, 8,
            0, 8, 20, /* 709: union.unknown */
            	92, 0,
            	752, 0,
            	685, 0,
            	762, 0,
            	767, 0,
            	772, 0,
            	777, 0,
            	782, 0,
            	787, 0,
            	792, 0,
            	797, 0,
            	802, 0,
            	807, 0,
            	812, 0,
            	817, 0,
            	822, 0,
            	827, 0,
            	752, 0,
            	752, 0,
            	832, 0,
            1, 8, 1, /* 752: pointer.struct.asn1_string_st */
            	757, 0,
            0, 24, 1, /* 757: struct.asn1_string_st */
            	107, 8,
            1, 8, 1, /* 762: pointer.struct.asn1_string_st */
            	757, 0,
            1, 8, 1, /* 767: pointer.struct.asn1_string_st */
            	757, 0,
            1, 8, 1, /* 772: pointer.struct.asn1_string_st */
            	757, 0,
            1, 8, 1, /* 777: pointer.struct.asn1_string_st */
            	757, 0,
            1, 8, 1, /* 782: pointer.struct.asn1_string_st */
            	757, 0,
            1, 8, 1, /* 787: pointer.struct.asn1_string_st */
            	757, 0,
            1, 8, 1, /* 792: pointer.struct.asn1_string_st */
            	757, 0,
            1, 8, 1, /* 797: pointer.struct.asn1_string_st */
            	757, 0,
            1, 8, 1, /* 802: pointer.struct.asn1_string_st */
            	757, 0,
            1, 8, 1, /* 807: pointer.struct.asn1_string_st */
            	757, 0,
            1, 8, 1, /* 812: pointer.struct.asn1_string_st */
            	757, 0,
            1, 8, 1, /* 817: pointer.struct.asn1_string_st */
            	757, 0,
            1, 8, 1, /* 822: pointer.struct.asn1_string_st */
            	757, 0,
            1, 8, 1, /* 827: pointer.struct.asn1_string_st */
            	757, 0,
            1, 8, 1, /* 832: pointer.struct.ASN1_VALUE_st */
            	837, 0,
            0, 0, 0, /* 837: struct.ASN1_VALUE_st */
            1, 8, 1, /* 840: pointer.struct.X509_name_st */
            	845, 0,
            0, 40, 3, /* 845: struct.X509_name_st */
            	854, 0,
            	878, 16,
            	107, 24,
            1, 8, 1, /* 854: pointer.struct.stack_st_X509_NAME_ENTRY */
            	859, 0,
            0, 32, 2, /* 859: struct.stack_st_fake_X509_NAME_ENTRY */
            	866, 8,
            	254, 24,
            8884099, 8, 2, /* 866: pointer_to_array_of_pointers_to_stack */
            	873, 0,
            	251, 20,
            0, 8, 1, /* 873: pointer.X509_NAME_ENTRY */
            	337, 0,
            1, 8, 1, /* 878: pointer.struct.buf_mem_st */
            	883, 0,
            0, 24, 1, /* 883: struct.buf_mem_st */
            	92, 8,
            1, 8, 1, /* 888: pointer.struct.EDIPartyName_st */
            	893, 0,
            0, 16, 2, /* 893: struct.EDIPartyName_st */
            	752, 0,
            	752, 8,
            0, 24, 1, /* 900: struct.asn1_string_st */
            	107, 8,
            1, 8, 1, /* 905: pointer.struct.buf_mem_st */
            	910, 0,
            0, 24, 1, /* 910: struct.buf_mem_st */
            	92, 8,
            1, 8, 1, /* 915: pointer.struct.stack_st_X509_NAME_ENTRY */
            	920, 0,
            0, 32, 2, /* 920: struct.stack_st_fake_X509_NAME_ENTRY */
            	927, 8,
            	254, 24,
            8884099, 8, 2, /* 927: pointer_to_array_of_pointers_to_stack */
            	934, 0,
            	251, 20,
            0, 8, 1, /* 934: pointer.X509_NAME_ENTRY */
            	337, 0,
            1, 8, 1, /* 939: pointer.struct.stack_st_GENERAL_NAME */
            	944, 0,
            0, 32, 2, /* 944: struct.stack_st_fake_GENERAL_NAME */
            	951, 8,
            	254, 24,
            8884099, 8, 2, /* 951: pointer_to_array_of_pointers_to_stack */
            	958, 0,
            	251, 20,
            0, 8, 1, /* 958: pointer.GENERAL_NAME */
            	630, 0,
            0, 8, 2, /* 963: union.unknown */
            	939, 0,
            	915, 0,
            0, 24, 2, /* 970: struct.DIST_POINT_NAME_st */
            	963, 8,
            	977, 16,
            1, 8, 1, /* 977: pointer.struct.X509_name_st */
            	982, 0,
            0, 40, 3, /* 982: struct.X509_name_st */
            	915, 0,
            	905, 16,
            	107, 24,
            0, 0, 1, /* 991: DIST_POINT */
            	996, 0,
            0, 32, 3, /* 996: struct.DIST_POINT_st */
            	1005, 0,
            	1010, 8,
            	939, 16,
            1, 8, 1, /* 1005: pointer.struct.DIST_POINT_NAME_st */
            	970, 0,
            1, 8, 1, /* 1010: pointer.struct.asn1_string_st */
            	900, 0,
            1, 8, 1, /* 1015: pointer.struct.stack_st_DIST_POINT */
            	1020, 0,
            0, 32, 2, /* 1020: struct.stack_st_fake_DIST_POINT */
            	1027, 8,
            	254, 24,
            8884099, 8, 2, /* 1027: pointer_to_array_of_pointers_to_stack */
            	1034, 0,
            	251, 20,
            0, 8, 1, /* 1034: pointer.DIST_POINT */
            	991, 0,
            0, 32, 3, /* 1039: struct.X509_POLICY_DATA_st */
            	1048, 8,
            	1062, 16,
            	1307, 24,
            1, 8, 1, /* 1048: pointer.struct.asn1_object_st */
            	1053, 0,
            0, 40, 3, /* 1053: struct.asn1_object_st */
            	26, 0,
            	26, 8,
            	31, 24,
            1, 8, 1, /* 1062: pointer.struct.stack_st_POLICYQUALINFO */
            	1067, 0,
            0, 32, 2, /* 1067: struct.stack_st_fake_POLICYQUALINFO */
            	1074, 8,
            	254, 24,
            8884099, 8, 2, /* 1074: pointer_to_array_of_pointers_to_stack */
            	1081, 0,
            	251, 20,
            0, 8, 1, /* 1081: pointer.POLICYQUALINFO */
            	1086, 0,
            0, 0, 1, /* 1086: POLICYQUALINFO */
            	1091, 0,
            0, 16, 2, /* 1091: struct.POLICYQUALINFO_st */
            	1098, 0,
            	1112, 8,
            1, 8, 1, /* 1098: pointer.struct.asn1_object_st */
            	1103, 0,
            0, 40, 3, /* 1103: struct.asn1_object_st */
            	26, 0,
            	26, 8,
            	31, 24,
            0, 8, 3, /* 1112: union.unknown */
            	1121, 0,
            	1131, 0,
            	1189, 0,
            1, 8, 1, /* 1121: pointer.struct.asn1_string_st */
            	1126, 0,
            0, 24, 1, /* 1126: struct.asn1_string_st */
            	107, 8,
            1, 8, 1, /* 1131: pointer.struct.USERNOTICE_st */
            	1136, 0,
            0, 16, 2, /* 1136: struct.USERNOTICE_st */
            	1143, 0,
            	1155, 8,
            1, 8, 1, /* 1143: pointer.struct.NOTICEREF_st */
            	1148, 0,
            0, 16, 2, /* 1148: struct.NOTICEREF_st */
            	1155, 0,
            	1160, 8,
            1, 8, 1, /* 1155: pointer.struct.asn1_string_st */
            	1126, 0,
            1, 8, 1, /* 1160: pointer.struct.stack_st_ASN1_INTEGER */
            	1165, 0,
            0, 32, 2, /* 1165: struct.stack_st_fake_ASN1_INTEGER */
            	1172, 8,
            	254, 24,
            8884099, 8, 2, /* 1172: pointer_to_array_of_pointers_to_stack */
            	1179, 0,
            	251, 20,
            0, 8, 1, /* 1179: pointer.ASN1_INTEGER */
            	1184, 0,
            0, 0, 1, /* 1184: ASN1_INTEGER */
            	102, 0,
            1, 8, 1, /* 1189: pointer.struct.asn1_type_st */
            	1194, 0,
            0, 16, 1, /* 1194: struct.asn1_type_st */
            	1199, 8,
            0, 8, 20, /* 1199: union.unknown */
            	92, 0,
            	1155, 0,
            	1098, 0,
            	1242, 0,
            	1247, 0,
            	1252, 0,
            	1257, 0,
            	1262, 0,
            	1267, 0,
            	1121, 0,
            	1272, 0,
            	1277, 0,
            	1282, 0,
            	1287, 0,
            	1292, 0,
            	1297, 0,
            	1302, 0,
            	1155, 0,
            	1155, 0,
            	524, 0,
            1, 8, 1, /* 1242: pointer.struct.asn1_string_st */
            	1126, 0,
            1, 8, 1, /* 1247: pointer.struct.asn1_string_st */
            	1126, 0,
            1, 8, 1, /* 1252: pointer.struct.asn1_string_st */
            	1126, 0,
            1, 8, 1, /* 1257: pointer.struct.asn1_string_st */
            	1126, 0,
            1, 8, 1, /* 1262: pointer.struct.asn1_string_st */
            	1126, 0,
            1, 8, 1, /* 1267: pointer.struct.asn1_string_st */
            	1126, 0,
            1, 8, 1, /* 1272: pointer.struct.asn1_string_st */
            	1126, 0,
            1, 8, 1, /* 1277: pointer.struct.asn1_string_st */
            	1126, 0,
            1, 8, 1, /* 1282: pointer.struct.asn1_string_st */
            	1126, 0,
            1, 8, 1, /* 1287: pointer.struct.asn1_string_st */
            	1126, 0,
            1, 8, 1, /* 1292: pointer.struct.asn1_string_st */
            	1126, 0,
            1, 8, 1, /* 1297: pointer.struct.asn1_string_st */
            	1126, 0,
            1, 8, 1, /* 1302: pointer.struct.asn1_string_st */
            	1126, 0,
            1, 8, 1, /* 1307: pointer.struct.stack_st_ASN1_OBJECT */
            	1312, 0,
            0, 32, 2, /* 1312: struct.stack_st_fake_ASN1_OBJECT */
            	1319, 8,
            	254, 24,
            8884099, 8, 2, /* 1319: pointer_to_array_of_pointers_to_stack */
            	1326, 0,
            	251, 20,
            0, 8, 1, /* 1326: pointer.ASN1_OBJECT */
            	237, 0,
            1, 8, 1, /* 1331: pointer.struct.stack_st_X509_POLICY_DATA */
            	1336, 0,
            0, 32, 2, /* 1336: struct.stack_st_fake_X509_POLICY_DATA */
            	1343, 8,
            	254, 24,
            8884099, 8, 2, /* 1343: pointer_to_array_of_pointers_to_stack */
            	1350, 0,
            	251, 20,
            0, 8, 1, /* 1350: pointer.X509_POLICY_DATA */
            	1355, 0,
            0, 0, 1, /* 1355: X509_POLICY_DATA */
            	1039, 0,
            1, 8, 1, /* 1360: pointer.struct.stack_st_ASN1_OBJECT */
            	1365, 0,
            0, 32, 2, /* 1365: struct.stack_st_fake_ASN1_OBJECT */
            	1372, 8,
            	254, 24,
            8884099, 8, 2, /* 1372: pointer_to_array_of_pointers_to_stack */
            	1379, 0,
            	251, 20,
            0, 8, 1, /* 1379: pointer.ASN1_OBJECT */
            	237, 0,
            0, 0, 1, /* 1384: GENERAL_SUBTREE */
            	597, 0,
            1, 8, 1, /* 1389: pointer.struct.stack_st_POLICYQUALINFO */
            	1394, 0,
            0, 32, 2, /* 1394: struct.stack_st_fake_POLICYQUALINFO */
            	1401, 8,
            	254, 24,
            8884099, 8, 2, /* 1401: pointer_to_array_of_pointers_to_stack */
            	1408, 0,
            	251, 20,
            0, 8, 1, /* 1408: pointer.POLICYQUALINFO */
            	1086, 0,
            0, 40, 3, /* 1413: struct.asn1_object_st */
            	26, 0,
            	26, 8,
            	31, 24,
            0, 32, 3, /* 1422: struct.X509_POLICY_DATA_st */
            	1431, 8,
            	1389, 16,
            	1360, 24,
            1, 8, 1, /* 1431: pointer.struct.asn1_object_st */
            	1413, 0,
            1, 8, 1, /* 1436: pointer.struct.X509_POLICY_DATA_st */
            	1422, 0,
            0, 40, 2, /* 1441: struct.X509_POLICY_CACHE_st */
            	1436, 0,
            	1331, 8,
            1, 8, 1, /* 1448: pointer.struct.stack_st_GENERAL_NAME */
            	1453, 0,
            0, 32, 2, /* 1453: struct.stack_st_fake_GENERAL_NAME */
            	1460, 8,
            	254, 24,
            8884099, 8, 2, /* 1460: pointer_to_array_of_pointers_to_stack */
            	1467, 0,
            	251, 20,
            0, 8, 1, /* 1467: pointer.GENERAL_NAME */
            	630, 0,
            1, 8, 1, /* 1472: pointer.struct.asn1_string_st */
            	1477, 0,
            0, 24, 1, /* 1477: struct.asn1_string_st */
            	107, 8,
            1, 8, 1, /* 1482: pointer.struct.AUTHORITY_KEYID_st */
            	1487, 0,
            0, 24, 3, /* 1487: struct.AUTHORITY_KEYID_st */
            	1472, 0,
            	1448, 8,
            	1496, 16,
            1, 8, 1, /* 1496: pointer.struct.asn1_string_st */
            	1477, 0,
            0, 32, 1, /* 1501: struct.stack_st_void */
            	1506, 0,
            0, 32, 2, /* 1506: struct.stack_st */
            	1513, 8,
            	254, 24,
            1, 8, 1, /* 1513: pointer.pointer.char */
            	92, 0,
            1, 8, 1, /* 1518: pointer.struct.stack_st_void */
            	1501, 0,
            0, 24, 1, /* 1523: struct.asn1_string_st */
            	107, 8,
            1, 8, 1, /* 1528: pointer.struct.asn1_string_st */
            	1523, 0,
            0, 40, 3, /* 1533: struct.asn1_object_st */
            	26, 0,
            	26, 8,
            	31, 24,
            1, 8, 1, /* 1542: pointer.struct.asn1_object_st */
            	1533, 0,
            0, 24, 2, /* 1547: struct.X509_extension_st */
            	1542, 0,
            	1528, 16,
            0, 0, 1, /* 1554: X509_EXTENSION */
            	1547, 0,
            1, 8, 1, /* 1559: pointer.struct.stack_st_X509_EXTENSION */
            	1564, 0,
            0, 32, 2, /* 1564: struct.stack_st_fake_X509_EXTENSION */
            	1571, 8,
            	254, 24,
            8884099, 8, 2, /* 1571: pointer_to_array_of_pointers_to_stack */
            	1578, 0,
            	251, 20,
            0, 8, 1, /* 1578: pointer.X509_EXTENSION */
            	1554, 0,
            1, 8, 1, /* 1583: pointer.struct.asn1_string_st */
            	195, 0,
            1, 8, 1, /* 1588: pointer.struct.asn1_string_st */
            	1593, 0,
            0, 24, 1, /* 1593: struct.asn1_string_st */
            	107, 8,
            1, 8, 1, /* 1598: pointer.struct.asn1_string_st */
            	1593, 0,
            1, 8, 1, /* 1603: pointer.struct.asn1_string_st */
            	1593, 0,
            1, 8, 1, /* 1608: pointer.struct.asn1_string_st */
            	1593, 0,
            1, 8, 1, /* 1613: pointer.struct.asn1_string_st */
            	1593, 0,
            1, 8, 1, /* 1618: pointer.struct.asn1_string_st */
            	1593, 0,
            1, 8, 1, /* 1623: pointer.struct.asn1_string_st */
            	1593, 0,
            1, 8, 1, /* 1628: pointer.struct.asn1_string_st */
            	1593, 0,
            0, 16, 1, /* 1633: struct.asn1_type_st */
            	1638, 8,
            0, 8, 20, /* 1638: union.unknown */
            	92, 0,
            	1628, 0,
            	1681, 0,
            	1695, 0,
            	1623, 0,
            	1700, 0,
            	1618, 0,
            	1705, 0,
            	1613, 0,
            	1608, 0,
            	1603, 0,
            	1598, 0,
            	1710, 0,
            	1715, 0,
            	1720, 0,
            	1725, 0,
            	1588, 0,
            	1628, 0,
            	1628, 0,
            	182, 0,
            1, 8, 1, /* 1681: pointer.struct.asn1_object_st */
            	1686, 0,
            0, 40, 3, /* 1686: struct.asn1_object_st */
            	26, 0,
            	26, 8,
            	31, 24,
            1, 8, 1, /* 1695: pointer.struct.asn1_string_st */
            	1593, 0,
            1, 8, 1, /* 1700: pointer.struct.asn1_string_st */
            	1593, 0,
            1, 8, 1, /* 1705: pointer.struct.asn1_string_st */
            	1593, 0,
            1, 8, 1, /* 1710: pointer.struct.asn1_string_st */
            	1593, 0,
            1, 8, 1, /* 1715: pointer.struct.asn1_string_st */
            	1593, 0,
            1, 8, 1, /* 1720: pointer.struct.asn1_string_st */
            	1593, 0,
            1, 8, 1, /* 1725: pointer.struct.asn1_string_st */
            	1593, 0,
            0, 0, 0, /* 1730: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1733: pointer.struct.asn1_string_st */
            	1738, 0,
            0, 24, 1, /* 1738: struct.asn1_string_st */
            	107, 8,
            1, 8, 1, /* 1743: pointer.struct.asn1_string_st */
            	1738, 0,
            1, 8, 1, /* 1748: pointer.struct.asn1_string_st */
            	1738, 0,
            1, 8, 1, /* 1753: pointer.struct.asn1_string_st */
            	1738, 0,
            1, 8, 1, /* 1758: pointer.struct.asn1_string_st */
            	1738, 0,
            1, 8, 1, /* 1763: pointer.struct.asn1_string_st */
            	1738, 0,
            1, 8, 1, /* 1768: pointer.struct.asn1_object_st */
            	1773, 0,
            0, 40, 3, /* 1773: struct.asn1_object_st */
            	26, 0,
            	26, 8,
            	31, 24,
            1, 8, 1, /* 1782: pointer.struct.asn1_string_st */
            	1738, 0,
            1, 8, 1, /* 1787: pointer.struct.stack_st_ASN1_TYPE */
            	1792, 0,
            0, 32, 2, /* 1792: struct.stack_st_fake_ASN1_TYPE */
            	1799, 8,
            	254, 24,
            8884099, 8, 2, /* 1799: pointer_to_array_of_pointers_to_stack */
            	1806, 0,
            	251, 20,
            0, 8, 1, /* 1806: pointer.ASN1_TYPE */
            	1811, 0,
            0, 0, 1, /* 1811: ASN1_TYPE */
            	1816, 0,
            0, 16, 1, /* 1816: struct.asn1_type_st */
            	1821, 8,
            0, 8, 20, /* 1821: union.unknown */
            	92, 0,
            	1782, 0,
            	1768, 0,
            	1763, 0,
            	1864, 0,
            	1869, 0,
            	1874, 0,
            	1758, 0,
            	1879, 0,
            	1753, 0,
            	1884, 0,
            	1889, 0,
            	1894, 0,
            	1899, 0,
            	1748, 0,
            	1743, 0,
            	1733, 0,
            	1782, 0,
            	1782, 0,
            	1904, 0,
            1, 8, 1, /* 1864: pointer.struct.asn1_string_st */
            	1738, 0,
            1, 8, 1, /* 1869: pointer.struct.asn1_string_st */
            	1738, 0,
            1, 8, 1, /* 1874: pointer.struct.asn1_string_st */
            	1738, 0,
            1, 8, 1, /* 1879: pointer.struct.asn1_string_st */
            	1738, 0,
            1, 8, 1, /* 1884: pointer.struct.asn1_string_st */
            	1738, 0,
            1, 8, 1, /* 1889: pointer.struct.asn1_string_st */
            	1738, 0,
            1, 8, 1, /* 1894: pointer.struct.asn1_string_st */
            	1738, 0,
            1, 8, 1, /* 1899: pointer.struct.asn1_string_st */
            	1738, 0,
            1, 8, 1, /* 1904: pointer.struct.ASN1_VALUE_st */
            	1730, 0,
            0, 24, 2, /* 1909: struct.x509_attributes_st */
            	1681, 0,
            	1916, 16,
            0, 8, 3, /* 1916: union.unknown */
            	92, 0,
            	1787, 0,
            	1925, 0,
            1, 8, 1, /* 1925: pointer.struct.asn1_type_st */
            	1633, 0,
            1, 8, 1, /* 1930: pointer.struct.stack_st_X509_ATTRIBUTE */
            	1935, 0,
            0, 32, 2, /* 1935: struct.stack_st_fake_X509_ATTRIBUTE */
            	1942, 8,
            	254, 24,
            8884099, 8, 2, /* 1942: pointer_to_array_of_pointers_to_stack */
            	1949, 0,
            	251, 20,
            0, 8, 1, /* 1949: pointer.X509_ATTRIBUTE */
            	1954, 0,
            0, 0, 1, /* 1954: X509_ATTRIBUTE */
            	1909, 0,
            1, 8, 1, /* 1959: pointer.struct.ec_extra_data_st */
            	1964, 0,
            0, 40, 5, /* 1964: struct.ec_extra_data_st */
            	1959, 0,
            	1977, 8,
            	1980, 16,
            	1983, 24,
            	1983, 32,
            0, 8, 0, /* 1977: pointer.void */
            8884097, 8, 0, /* 1980: pointer.func */
            8884097, 8, 0, /* 1983: pointer.func */
            1, 8, 1, /* 1986: pointer.struct.ec_extra_data_st */
            	1964, 0,
            0, 24, 1, /* 1991: struct.bignum_st */
            	1996, 0,
            8884099, 8, 2, /* 1996: pointer_to_array_of_pointers_to_stack */
            	2003, 0,
            	251, 12,
            0, 4, 0, /* 2003: unsigned int */
            1, 8, 1, /* 2006: pointer.struct.bignum_st */
            	1991, 0,
            1, 8, 1, /* 2011: pointer.struct.ec_point_st */
            	2016, 0,
            0, 88, 4, /* 2016: struct.ec_point_st */
            	2027, 0,
            	2199, 8,
            	2199, 32,
            	2199, 56,
            1, 8, 1, /* 2027: pointer.struct.ec_method_st */
            	2032, 0,
            0, 304, 37, /* 2032: struct.ec_method_st */
            	2109, 8,
            	2112, 16,
            	2112, 24,
            	2115, 32,
            	2118, 40,
            	2121, 48,
            	2124, 56,
            	2127, 64,
            	2130, 72,
            	2133, 80,
            	2133, 88,
            	2136, 96,
            	2139, 104,
            	2142, 112,
            	2145, 120,
            	2148, 128,
            	2151, 136,
            	2154, 144,
            	2157, 152,
            	2160, 160,
            	2163, 168,
            	2166, 176,
            	2169, 184,
            	2172, 192,
            	2175, 200,
            	2178, 208,
            	2169, 216,
            	2181, 224,
            	2184, 232,
            	2187, 240,
            	2124, 248,
            	2190, 256,
            	2193, 264,
            	2190, 272,
            	2193, 280,
            	2193, 288,
            	2196, 296,
            8884097, 8, 0, /* 2109: pointer.func */
            8884097, 8, 0, /* 2112: pointer.func */
            8884097, 8, 0, /* 2115: pointer.func */
            8884097, 8, 0, /* 2118: pointer.func */
            8884097, 8, 0, /* 2121: pointer.func */
            8884097, 8, 0, /* 2124: pointer.func */
            8884097, 8, 0, /* 2127: pointer.func */
            8884097, 8, 0, /* 2130: pointer.func */
            8884097, 8, 0, /* 2133: pointer.func */
            8884097, 8, 0, /* 2136: pointer.func */
            8884097, 8, 0, /* 2139: pointer.func */
            8884097, 8, 0, /* 2142: pointer.func */
            8884097, 8, 0, /* 2145: pointer.func */
            8884097, 8, 0, /* 2148: pointer.func */
            8884097, 8, 0, /* 2151: pointer.func */
            8884097, 8, 0, /* 2154: pointer.func */
            8884097, 8, 0, /* 2157: pointer.func */
            8884097, 8, 0, /* 2160: pointer.func */
            8884097, 8, 0, /* 2163: pointer.func */
            8884097, 8, 0, /* 2166: pointer.func */
            8884097, 8, 0, /* 2169: pointer.func */
            8884097, 8, 0, /* 2172: pointer.func */
            8884097, 8, 0, /* 2175: pointer.func */
            8884097, 8, 0, /* 2178: pointer.func */
            8884097, 8, 0, /* 2181: pointer.func */
            8884097, 8, 0, /* 2184: pointer.func */
            8884097, 8, 0, /* 2187: pointer.func */
            8884097, 8, 0, /* 2190: pointer.func */
            8884097, 8, 0, /* 2193: pointer.func */
            8884097, 8, 0, /* 2196: pointer.func */
            0, 24, 1, /* 2199: struct.bignum_st */
            	2204, 0,
            8884099, 8, 2, /* 2204: pointer_to_array_of_pointers_to_stack */
            	2003, 0,
            	251, 12,
            0, 16, 1, /* 2211: struct.crypto_ex_data_st */
            	1518, 0,
            8884097, 8, 0, /* 2216: pointer.func */
            1, 8, 1, /* 2219: pointer.struct.ec_extra_data_st */
            	2224, 0,
            0, 40, 5, /* 2224: struct.ec_extra_data_st */
            	2219, 0,
            	1977, 8,
            	1980, 16,
            	1983, 24,
            	1983, 32,
            1, 8, 1, /* 2237: pointer.struct.ec_extra_data_st */
            	2224, 0,
            0, 24, 1, /* 2242: struct.bignum_st */
            	2247, 0,
            8884099, 8, 2, /* 2247: pointer_to_array_of_pointers_to_stack */
            	2003, 0,
            	251, 12,
            0, 24, 1, /* 2254: struct.ASN1_ENCODING_st */
            	107, 0,
            8884097, 8, 0, /* 2259: pointer.func */
            8884097, 8, 0, /* 2262: pointer.func */
            8884097, 8, 0, /* 2265: pointer.func */
            8884097, 8, 0, /* 2268: pointer.func */
            8884097, 8, 0, /* 2271: pointer.func */
            1, 8, 1, /* 2274: pointer.struct.ecdh_method */
            	2279, 0,
            0, 32, 3, /* 2279: struct.ecdh_method */
            	26, 0,
            	2288, 8,
            	92, 24,
            8884097, 8, 0, /* 2288: pointer.func */
            8884097, 8, 0, /* 2291: pointer.func */
            8884097, 8, 0, /* 2294: pointer.func */
            1, 8, 1, /* 2297: pointer.struct.dh_method */
            	2302, 0,
            0, 72, 8, /* 2302: struct.dh_method */
            	26, 0,
            	2321, 8,
            	2324, 16,
            	2294, 24,
            	2321, 32,
            	2321, 40,
            	92, 56,
            	2327, 64,
            8884097, 8, 0, /* 2321: pointer.func */
            8884097, 8, 0, /* 2324: pointer.func */
            8884097, 8, 0, /* 2327: pointer.func */
            8884097, 8, 0, /* 2330: pointer.func */
            8884097, 8, 0, /* 2333: pointer.func */
            8884097, 8, 0, /* 2336: pointer.func */
            0, 96, 11, /* 2339: struct.dsa_method */
            	26, 0,
            	2333, 8,
            	2364, 16,
            	2367, 24,
            	2330, 32,
            	2291, 40,
            	2370, 48,
            	2370, 56,
            	92, 72,
            	2373, 80,
            	2370, 88,
            8884097, 8, 0, /* 2364: pointer.func */
            8884097, 8, 0, /* 2367: pointer.func */
            8884097, 8, 0, /* 2370: pointer.func */
            8884097, 8, 0, /* 2373: pointer.func */
            8884097, 8, 0, /* 2376: pointer.func */
            8884097, 8, 0, /* 2379: pointer.func */
            1, 8, 1, /* 2382: pointer.struct.dsa_method */
            	2339, 0,
            8884097, 8, 0, /* 2387: pointer.func */
            0, 32, 2, /* 2390: struct.stack_st */
            	1513, 8,
            	254, 24,
            1, 8, 1, /* 2397: pointer.struct.NAME_CONSTRAINTS_st */
            	2402, 0,
            0, 16, 2, /* 2402: struct.NAME_CONSTRAINTS_st */
            	2409, 0,
            	2409, 8,
            1, 8, 1, /* 2409: pointer.struct.stack_st_GENERAL_SUBTREE */
            	2414, 0,
            0, 32, 2, /* 2414: struct.stack_st_fake_GENERAL_SUBTREE */
            	2421, 8,
            	254, 24,
            8884099, 8, 2, /* 2421: pointer_to_array_of_pointers_to_stack */
            	2428, 0,
            	251, 20,
            0, 8, 1, /* 2428: pointer.GENERAL_SUBTREE */
            	1384, 0,
            8884097, 8, 0, /* 2433: pointer.func */
            8884097, 8, 0, /* 2436: pointer.func */
            0, 112, 13, /* 2439: struct.rsa_meth_st */
            	26, 0,
            	2468, 8,
            	2468, 16,
            	2468, 24,
            	2468, 32,
            	2471, 40,
            	2474, 48,
            	2477, 56,
            	2477, 64,
            	92, 80,
            	2433, 88,
            	2387, 96,
            	2480, 104,
            8884097, 8, 0, /* 2468: pointer.func */
            8884097, 8, 0, /* 2471: pointer.func */
            8884097, 8, 0, /* 2474: pointer.func */
            8884097, 8, 0, /* 2477: pointer.func */
            8884097, 8, 0, /* 2480: pointer.func */
            1, 8, 1, /* 2483: pointer.struct.rsa_meth_st */
            	2439, 0,
            1, 8, 1, /* 2488: pointer.struct.ec_method_st */
            	2493, 0,
            0, 304, 37, /* 2493: struct.ec_method_st */
            	2570, 8,
            	2573, 16,
            	2573, 24,
            	2576, 32,
            	2579, 40,
            	2582, 48,
            	2585, 56,
            	2588, 64,
            	2436, 72,
            	2591, 80,
            	2591, 88,
            	2594, 96,
            	2597, 104,
            	2600, 112,
            	2603, 120,
            	2265, 128,
            	2606, 136,
            	2609, 144,
            	2612, 152,
            	2615, 160,
            	2618, 168,
            	2621, 176,
            	2624, 184,
            	2627, 192,
            	2630, 200,
            	2633, 208,
            	2624, 216,
            	2636, 224,
            	2639, 232,
            	2642, 240,
            	2585, 248,
            	2645, 256,
            	2648, 264,
            	2645, 272,
            	2648, 280,
            	2648, 288,
            	2651, 296,
            8884097, 8, 0, /* 2570: pointer.func */
            8884097, 8, 0, /* 2573: pointer.func */
            8884097, 8, 0, /* 2576: pointer.func */
            8884097, 8, 0, /* 2579: pointer.func */
            8884097, 8, 0, /* 2582: pointer.func */
            8884097, 8, 0, /* 2585: pointer.func */
            8884097, 8, 0, /* 2588: pointer.func */
            8884097, 8, 0, /* 2591: pointer.func */
            8884097, 8, 0, /* 2594: pointer.func */
            8884097, 8, 0, /* 2597: pointer.func */
            8884097, 8, 0, /* 2600: pointer.func */
            8884097, 8, 0, /* 2603: pointer.func */
            8884097, 8, 0, /* 2606: pointer.func */
            8884097, 8, 0, /* 2609: pointer.func */
            8884097, 8, 0, /* 2612: pointer.func */
            8884097, 8, 0, /* 2615: pointer.func */
            8884097, 8, 0, /* 2618: pointer.func */
            8884097, 8, 0, /* 2621: pointer.func */
            8884097, 8, 0, /* 2624: pointer.func */
            8884097, 8, 0, /* 2627: pointer.func */
            8884097, 8, 0, /* 2630: pointer.func */
            8884097, 8, 0, /* 2633: pointer.func */
            8884097, 8, 0, /* 2636: pointer.func */
            8884097, 8, 0, /* 2639: pointer.func */
            8884097, 8, 0, /* 2642: pointer.func */
            8884097, 8, 0, /* 2645: pointer.func */
            8884097, 8, 0, /* 2648: pointer.func */
            8884097, 8, 0, /* 2651: pointer.func */
            8884097, 8, 0, /* 2654: pointer.func */
            8884097, 8, 0, /* 2657: pointer.func */
            0, 208, 24, /* 2660: struct.evp_pkey_asn1_method_st */
            	92, 16,
            	92, 24,
            	2711, 32,
            	2714, 40,
            	2717, 48,
            	2720, 56,
            	2723, 64,
            	2726, 72,
            	2720, 80,
            	2376, 88,
            	2376, 96,
            	2729, 104,
            	2732, 112,
            	2376, 120,
            	2657, 128,
            	2717, 136,
            	2720, 144,
            	2735, 152,
            	2738, 160,
            	2654, 168,
            	2729, 176,
            	2732, 184,
            	2741, 192,
            	2744, 200,
            8884097, 8, 0, /* 2711: pointer.func */
            8884097, 8, 0, /* 2714: pointer.func */
            8884097, 8, 0, /* 2717: pointer.func */
            8884097, 8, 0, /* 2720: pointer.func */
            8884097, 8, 0, /* 2723: pointer.func */
            8884097, 8, 0, /* 2726: pointer.func */
            8884097, 8, 0, /* 2729: pointer.func */
            8884097, 8, 0, /* 2732: pointer.func */
            8884097, 8, 0, /* 2735: pointer.func */
            8884097, 8, 0, /* 2738: pointer.func */
            8884097, 8, 0, /* 2741: pointer.func */
            8884097, 8, 0, /* 2744: pointer.func */
            0, 24, 1, /* 2747: struct.bignum_st */
            	2752, 0,
            8884099, 8, 2, /* 2752: pointer_to_array_of_pointers_to_stack */
            	2003, 0,
            	251, 12,
            0, 216, 24, /* 2759: struct.engine_st */
            	26, 0,
            	26, 8,
            	2483, 16,
            	2382, 24,
            	2297, 32,
            	2274, 40,
            	2810, 48,
            	2834, 56,
            	2863, 64,
            	2259, 72,
            	2871, 80,
            	2874, 88,
            	2877, 96,
            	2880, 104,
            	2880, 112,
            	2880, 120,
            	2883, 128,
            	2886, 136,
            	2886, 144,
            	2889, 152,
            	2892, 160,
            	2904, 184,
            	2926, 200,
            	2926, 208,
            1, 8, 1, /* 2810: pointer.struct.ecdsa_method */
            	2815, 0,
            0, 48, 5, /* 2815: struct.ecdsa_method */
            	26, 0,
            	2828, 8,
            	2271, 16,
            	2831, 24,
            	92, 40,
            8884097, 8, 0, /* 2828: pointer.func */
            8884097, 8, 0, /* 2831: pointer.func */
            1, 8, 1, /* 2834: pointer.struct.rand_meth_st */
            	2839, 0,
            0, 48, 6, /* 2839: struct.rand_meth_st */
            	2854, 0,
            	2268, 8,
            	2857, 16,
            	2860, 24,
            	2268, 32,
            	2262, 40,
            8884097, 8, 0, /* 2854: pointer.func */
            8884097, 8, 0, /* 2857: pointer.func */
            8884097, 8, 0, /* 2860: pointer.func */
            1, 8, 1, /* 2863: pointer.struct.store_method_st */
            	2868, 0,
            0, 0, 0, /* 2868: struct.store_method_st */
            8884097, 8, 0, /* 2871: pointer.func */
            8884097, 8, 0, /* 2874: pointer.func */
            8884097, 8, 0, /* 2877: pointer.func */
            8884097, 8, 0, /* 2880: pointer.func */
            8884097, 8, 0, /* 2883: pointer.func */
            8884097, 8, 0, /* 2886: pointer.func */
            8884097, 8, 0, /* 2889: pointer.func */
            1, 8, 1, /* 2892: pointer.struct.ENGINE_CMD_DEFN_st */
            	2897, 0,
            0, 32, 2, /* 2897: struct.ENGINE_CMD_DEFN_st */
            	26, 8,
            	26, 16,
            0, 16, 1, /* 2904: struct.crypto_ex_data_st */
            	2909, 0,
            1, 8, 1, /* 2909: pointer.struct.stack_st_void */
            	2914, 0,
            0, 32, 1, /* 2914: struct.stack_st_void */
            	2919, 0,
            0, 32, 2, /* 2919: struct.stack_st */
            	1513, 8,
            	254, 24,
            1, 8, 1, /* 2926: pointer.struct.engine_st */
            	2759, 0,
            1, 8, 1, /* 2931: pointer.struct.bignum_st */
            	2936, 0,
            0, 24, 1, /* 2936: struct.bignum_st */
            	2941, 0,
            8884099, 8, 2, /* 2941: pointer_to_array_of_pointers_to_stack */
            	2003, 0,
            	251, 12,
            1, 8, 1, /* 2948: pointer.struct.dh_method */
            	2953, 0,
            0, 72, 8, /* 2953: struct.dh_method */
            	26, 0,
            	2972, 8,
            	2975, 16,
            	2978, 24,
            	2972, 32,
            	2972, 40,
            	92, 56,
            	2981, 64,
            8884097, 8, 0, /* 2972: pointer.func */
            8884097, 8, 0, /* 2975: pointer.func */
            8884097, 8, 0, /* 2978: pointer.func */
            8884097, 8, 0, /* 2981: pointer.func */
            1, 8, 1, /* 2984: pointer.struct.evp_pkey_asn1_method_st */
            	2660, 0,
            0, 56, 4, /* 2989: struct.evp_pkey_st */
            	2984, 16,
            	3000, 24,
            	3005, 32,
            	1930, 48,
            1, 8, 1, /* 3000: pointer.struct.engine_st */
            	2759, 0,
            0, 8, 5, /* 3005: union.unknown */
            	92, 0,
            	3018, 0,
            	3216, 0,
            	3331, 0,
            	3421, 0,
            1, 8, 1, /* 3018: pointer.struct.rsa_st */
            	3023, 0,
            0, 168, 17, /* 3023: struct.rsa_st */
            	3060, 16,
            	3109, 24,
            	3114, 32,
            	3114, 40,
            	3114, 48,
            	3114, 56,
            	3114, 64,
            	3114, 72,
            	3114, 80,
            	3114, 88,
            	3119, 96,
            	3141, 120,
            	3141, 128,
            	3141, 136,
            	92, 144,
            	3155, 152,
            	3155, 160,
            1, 8, 1, /* 3060: pointer.struct.rsa_meth_st */
            	3065, 0,
            0, 112, 13, /* 3065: struct.rsa_meth_st */
            	26, 0,
            	3094, 8,
            	3094, 16,
            	3094, 24,
            	3094, 32,
            	3097, 40,
            	2336, 48,
            	3100, 56,
            	3100, 64,
            	92, 80,
            	3103, 88,
            	2379, 96,
            	3106, 104,
            8884097, 8, 0, /* 3094: pointer.func */
            8884097, 8, 0, /* 3097: pointer.func */
            8884097, 8, 0, /* 3100: pointer.func */
            8884097, 8, 0, /* 3103: pointer.func */
            8884097, 8, 0, /* 3106: pointer.func */
            1, 8, 1, /* 3109: pointer.struct.engine_st */
            	2759, 0,
            1, 8, 1, /* 3114: pointer.struct.bignum_st */
            	2747, 0,
            0, 16, 1, /* 3119: struct.crypto_ex_data_st */
            	3124, 0,
            1, 8, 1, /* 3124: pointer.struct.stack_st_void */
            	3129, 0,
            0, 32, 1, /* 3129: struct.stack_st_void */
            	3134, 0,
            0, 32, 2, /* 3134: struct.stack_st */
            	1513, 8,
            	254, 24,
            1, 8, 1, /* 3141: pointer.struct.bn_mont_ctx_st */
            	3146, 0,
            0, 96, 3, /* 3146: struct.bn_mont_ctx_st */
            	2747, 8,
            	2747, 32,
            	2747, 56,
            1, 8, 1, /* 3155: pointer.struct.bn_blinding_st */
            	3160, 0,
            0, 88, 7, /* 3160: struct.bn_blinding_st */
            	3177, 0,
            	3177, 8,
            	3177, 16,
            	3177, 24,
            	3194, 40,
            	3199, 72,
            	3213, 80,
            1, 8, 1, /* 3177: pointer.struct.bignum_st */
            	3182, 0,
            0, 24, 1, /* 3182: struct.bignum_st */
            	3187, 0,
            8884099, 8, 2, /* 3187: pointer_to_array_of_pointers_to_stack */
            	2003, 0,
            	251, 12,
            0, 16, 1, /* 3194: struct.crypto_threadid_st */
            	1977, 0,
            1, 8, 1, /* 3199: pointer.struct.bn_mont_ctx_st */
            	3204, 0,
            0, 96, 3, /* 3204: struct.bn_mont_ctx_st */
            	3182, 8,
            	3182, 32,
            	3182, 56,
            8884097, 8, 0, /* 3213: pointer.func */
            1, 8, 1, /* 3216: pointer.struct.dsa_st */
            	3221, 0,
            0, 136, 11, /* 3221: struct.dsa_st */
            	2931, 24,
            	2931, 32,
            	2931, 40,
            	2931, 48,
            	2931, 56,
            	2931, 64,
            	2931, 72,
            	3246, 88,
            	3260, 104,
            	3275, 120,
            	3326, 128,
            1, 8, 1, /* 3246: pointer.struct.bn_mont_ctx_st */
            	3251, 0,
            0, 96, 3, /* 3251: struct.bn_mont_ctx_st */
            	2936, 8,
            	2936, 32,
            	2936, 56,
            0, 16, 1, /* 3260: struct.crypto_ex_data_st */
            	3265, 0,
            1, 8, 1, /* 3265: pointer.struct.stack_st_void */
            	3270, 0,
            0, 32, 1, /* 3270: struct.stack_st_void */
            	2390, 0,
            1, 8, 1, /* 3275: pointer.struct.dsa_method */
            	3280, 0,
            0, 96, 11, /* 3280: struct.dsa_method */
            	26, 0,
            	3305, 8,
            	3308, 16,
            	3311, 24,
            	3314, 32,
            	3317, 40,
            	3320, 48,
            	3320, 56,
            	92, 72,
            	3323, 80,
            	3320, 88,
            8884097, 8, 0, /* 3305: pointer.func */
            8884097, 8, 0, /* 3308: pointer.func */
            8884097, 8, 0, /* 3311: pointer.func */
            8884097, 8, 0, /* 3314: pointer.func */
            8884097, 8, 0, /* 3317: pointer.func */
            8884097, 8, 0, /* 3320: pointer.func */
            8884097, 8, 0, /* 3323: pointer.func */
            1, 8, 1, /* 3326: pointer.struct.engine_st */
            	2759, 0,
            1, 8, 1, /* 3331: pointer.struct.dh_st */
            	3336, 0,
            0, 144, 12, /* 3336: struct.dh_st */
            	3363, 8,
            	3363, 16,
            	3363, 32,
            	3363, 40,
            	3380, 56,
            	3363, 64,
            	3363, 72,
            	107, 80,
            	3363, 96,
            	3394, 112,
            	2948, 128,
            	3416, 136,
            1, 8, 1, /* 3363: pointer.struct.bignum_st */
            	3368, 0,
            0, 24, 1, /* 3368: struct.bignum_st */
            	3373, 0,
            8884099, 8, 2, /* 3373: pointer_to_array_of_pointers_to_stack */
            	2003, 0,
            	251, 12,
            1, 8, 1, /* 3380: pointer.struct.bn_mont_ctx_st */
            	3385, 0,
            0, 96, 3, /* 3385: struct.bn_mont_ctx_st */
            	3368, 8,
            	3368, 32,
            	3368, 56,
            0, 16, 1, /* 3394: struct.crypto_ex_data_st */
            	3399, 0,
            1, 8, 1, /* 3399: pointer.struct.stack_st_void */
            	3404, 0,
            0, 32, 1, /* 3404: struct.stack_st_void */
            	3409, 0,
            0, 32, 2, /* 3409: struct.stack_st */
            	1513, 8,
            	254, 24,
            1, 8, 1, /* 3416: pointer.struct.engine_st */
            	2759, 0,
            1, 8, 1, /* 3421: pointer.struct.ec_key_st */
            	3426, 0,
            0, 56, 4, /* 3426: struct.ec_key_st */
            	3437, 8,
            	2011, 16,
            	2006, 24,
            	1986, 48,
            1, 8, 1, /* 3437: pointer.struct.ec_group_st */
            	3442, 0,
            0, 232, 12, /* 3442: struct.ec_group_st */
            	2488, 0,
            	3469, 8,
            	2242, 16,
            	2242, 40,
            	107, 80,
            	2237, 96,
            	2242, 104,
            	2242, 152,
            	2242, 176,
            	1977, 208,
            	1977, 216,
            	2216, 224,
            1, 8, 1, /* 3469: pointer.struct.ec_point_st */
            	2016, 0,
            1, 8, 1, /* 3474: pointer.struct.evp_pkey_st */
            	2989, 0,
            0, 24, 1, /* 3479: struct.asn1_string_st */
            	107, 8,
            1, 8, 1, /* 3484: pointer.struct.x509_st */
            	3489, 0,
            0, 184, 12, /* 3489: struct.x509_st */
            	3516, 0,
            	3551, 8,
            	1583, 16,
            	92, 32,
            	2211, 40,
            	257, 104,
            	1482, 112,
            	3645, 120,
            	1015, 128,
            	606, 136,
            	2397, 144,
            	286, 176,
            1, 8, 1, /* 3516: pointer.struct.x509_cinf_st */
            	3521, 0,
            0, 104, 11, /* 3521: struct.x509_cinf_st */
            	3546, 0,
            	3546, 8,
            	3551, 16,
            	3556, 24,
            	3604, 32,
            	3556, 40,
            	3621, 48,
            	1583, 56,
            	1583, 64,
            	1559, 72,
            	2254, 80,
            1, 8, 1, /* 3546: pointer.struct.asn1_string_st */
            	195, 0,
            1, 8, 1, /* 3551: pointer.struct.X509_algor_st */
            	5, 0,
            1, 8, 1, /* 3556: pointer.struct.X509_name_st */
            	3561, 0,
            0, 40, 3, /* 3561: struct.X509_name_st */
            	3570, 0,
            	3594, 16,
            	107, 24,
            1, 8, 1, /* 3570: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3575, 0,
            0, 32, 2, /* 3575: struct.stack_st_fake_X509_NAME_ENTRY */
            	3582, 8,
            	254, 24,
            8884099, 8, 2, /* 3582: pointer_to_array_of_pointers_to_stack */
            	3589, 0,
            	251, 20,
            0, 8, 1, /* 3589: pointer.X509_NAME_ENTRY */
            	337, 0,
            1, 8, 1, /* 3594: pointer.struct.buf_mem_st */
            	3599, 0,
            0, 24, 1, /* 3599: struct.buf_mem_st */
            	92, 8,
            1, 8, 1, /* 3604: pointer.struct.X509_val_st */
            	3609, 0,
            0, 16, 2, /* 3609: struct.X509_val_st */
            	3616, 0,
            	3616, 8,
            1, 8, 1, /* 3616: pointer.struct.asn1_string_st */
            	195, 0,
            1, 8, 1, /* 3621: pointer.struct.X509_pubkey_st */
            	3626, 0,
            0, 24, 3, /* 3626: struct.X509_pubkey_st */
            	3635, 0,
            	3640, 8,
            	3474, 16,
            1, 8, 1, /* 3635: pointer.struct.X509_algor_st */
            	5, 0,
            1, 8, 1, /* 3640: pointer.struct.asn1_string_st */
            	3479, 0,
            1, 8, 1, /* 3645: pointer.struct.X509_POLICY_CACHE_st */
            	1441, 0,
            0, 1, 0, /* 3650: char */
        },
        .arg_entity_index = { 3484, },
        .ret_entity_index = 3556,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    X509 * new_arg_a = *((X509 * *)new_args->args[0]);

    X509_NAME * *new_ret_ptr = (X509_NAME * *)new_args->ret;

    X509_NAME * (*orig_X509_get_subject_name)(X509 *);
    orig_X509_get_subject_name = dlsym(RTLD_NEXT, "X509_get_subject_name");
    *new_ret_ptr = (*orig_X509_get_subject_name)(new_arg_a);

    syscall(889);

    return ret;
}

