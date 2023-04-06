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
            1, 8, 1, /* 0: pointer.struct.asn1_string_st */
            	5, 0,
            0, 24, 1, /* 5: struct.asn1_string_st */
            	10, 8,
            1, 8, 1, /* 10: pointer.unsigned char */
            	15, 0,
            0, 1, 0, /* 15: unsigned char */
            1, 8, 1, /* 18: pointer.struct.stack_st_ASN1_OBJECT */
            	23, 0,
            0, 32, 2, /* 23: struct.stack_st_fake_ASN1_OBJECT */
            	30, 8,
            	69, 24,
            8884099, 8, 2, /* 30: pointer_to_array_of_pointers_to_stack */
            	37, 0,
            	66, 20,
            0, 8, 1, /* 37: pointer.ASN1_OBJECT */
            	42, 0,
            0, 0, 1, /* 42: ASN1_OBJECT */
            	47, 0,
            0, 40, 3, /* 47: struct.asn1_object_st */
            	56, 0,
            	56, 8,
            	61, 24,
            1, 8, 1, /* 56: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 61: pointer.unsigned char */
            	15, 0,
            0, 4, 0, /* 66: int */
            8884097, 8, 0, /* 69: pointer.func */
            0, 40, 5, /* 72: struct.x509_cert_aux_st */
            	18, 0,
            	18, 8,
            	0, 16,
            	85, 24,
            	90, 32,
            1, 8, 1, /* 85: pointer.struct.asn1_string_st */
            	5, 0,
            1, 8, 1, /* 90: pointer.struct.stack_st_X509_ALGOR */
            	95, 0,
            0, 32, 2, /* 95: struct.stack_st_fake_X509_ALGOR */
            	102, 8,
            	69, 24,
            8884099, 8, 2, /* 102: pointer_to_array_of_pointers_to_stack */
            	109, 0,
            	66, 20,
            0, 8, 1, /* 109: pointer.X509_ALGOR */
            	114, 0,
            0, 0, 1, /* 114: X509_ALGOR */
            	119, 0,
            0, 16, 2, /* 119: struct.X509_algor_st */
            	126, 0,
            	140, 8,
            1, 8, 1, /* 126: pointer.struct.asn1_object_st */
            	131, 0,
            0, 40, 3, /* 131: struct.asn1_object_st */
            	56, 0,
            	56, 8,
            	61, 24,
            1, 8, 1, /* 140: pointer.struct.asn1_type_st */
            	145, 0,
            0, 16, 1, /* 145: struct.asn1_type_st */
            	150, 8,
            0, 8, 20, /* 150: union.unknown */
            	193, 0,
            	198, 0,
            	126, 0,
            	208, 0,
            	213, 0,
            	218, 0,
            	223, 0,
            	228, 0,
            	233, 0,
            	238, 0,
            	243, 0,
            	248, 0,
            	253, 0,
            	258, 0,
            	263, 0,
            	268, 0,
            	273, 0,
            	198, 0,
            	198, 0,
            	278, 0,
            1, 8, 1, /* 193: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 198: pointer.struct.asn1_string_st */
            	203, 0,
            0, 24, 1, /* 203: struct.asn1_string_st */
            	10, 8,
            1, 8, 1, /* 208: pointer.struct.asn1_string_st */
            	203, 0,
            1, 8, 1, /* 213: pointer.struct.asn1_string_st */
            	203, 0,
            1, 8, 1, /* 218: pointer.struct.asn1_string_st */
            	203, 0,
            1, 8, 1, /* 223: pointer.struct.asn1_string_st */
            	203, 0,
            1, 8, 1, /* 228: pointer.struct.asn1_string_st */
            	203, 0,
            1, 8, 1, /* 233: pointer.struct.asn1_string_st */
            	203, 0,
            1, 8, 1, /* 238: pointer.struct.asn1_string_st */
            	203, 0,
            1, 8, 1, /* 243: pointer.struct.asn1_string_st */
            	203, 0,
            1, 8, 1, /* 248: pointer.struct.asn1_string_st */
            	203, 0,
            1, 8, 1, /* 253: pointer.struct.asn1_string_st */
            	203, 0,
            1, 8, 1, /* 258: pointer.struct.asn1_string_st */
            	203, 0,
            1, 8, 1, /* 263: pointer.struct.asn1_string_st */
            	203, 0,
            1, 8, 1, /* 268: pointer.struct.asn1_string_st */
            	203, 0,
            1, 8, 1, /* 273: pointer.struct.asn1_string_st */
            	203, 0,
            1, 8, 1, /* 278: pointer.struct.ASN1_VALUE_st */
            	283, 0,
            0, 0, 0, /* 283: struct.ASN1_VALUE_st */
            1, 8, 1, /* 286: pointer.struct.x509_cert_aux_st */
            	72, 0,
            0, 16, 2, /* 291: struct.EDIPartyName_st */
            	298, 0,
            	298, 8,
            1, 8, 1, /* 298: pointer.struct.asn1_string_st */
            	303, 0,
            0, 24, 1, /* 303: struct.asn1_string_st */
            	10, 8,
            1, 8, 1, /* 308: pointer.struct.EDIPartyName_st */
            	291, 0,
            0, 24, 1, /* 313: struct.buf_mem_st */
            	193, 8,
            1, 8, 1, /* 318: pointer.struct.stack_st_X509_NAME_ENTRY */
            	323, 0,
            0, 32, 2, /* 323: struct.stack_st_fake_X509_NAME_ENTRY */
            	330, 8,
            	69, 24,
            8884099, 8, 2, /* 330: pointer_to_array_of_pointers_to_stack */
            	337, 0,
            	66, 20,
            0, 8, 1, /* 337: pointer.X509_NAME_ENTRY */
            	342, 0,
            0, 0, 1, /* 342: X509_NAME_ENTRY */
            	347, 0,
            0, 24, 2, /* 347: struct.X509_name_entry_st */
            	354, 0,
            	368, 8,
            1, 8, 1, /* 354: pointer.struct.asn1_object_st */
            	359, 0,
            0, 40, 3, /* 359: struct.asn1_object_st */
            	56, 0,
            	56, 8,
            	61, 24,
            1, 8, 1, /* 368: pointer.struct.asn1_string_st */
            	373, 0,
            0, 24, 1, /* 373: struct.asn1_string_st */
            	10, 8,
            1, 8, 1, /* 378: pointer.struct.X509_name_st */
            	383, 0,
            0, 40, 3, /* 383: struct.X509_name_st */
            	318, 0,
            	392, 16,
            	10, 24,
            1, 8, 1, /* 392: pointer.struct.buf_mem_st */
            	313, 0,
            1, 8, 1, /* 397: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 402: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 407: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 412: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 417: pointer.struct.asn1_string_st */
            	303, 0,
            0, 8, 20, /* 422: union.unknown */
            	193, 0,
            	298, 0,
            	465, 0,
            	479, 0,
            	484, 0,
            	489, 0,
            	417, 0,
            	494, 0,
            	499, 0,
            	504, 0,
            	412, 0,
            	407, 0,
            	509, 0,
            	402, 0,
            	397, 0,
            	514, 0,
            	519, 0,
            	298, 0,
            	298, 0,
            	524, 0,
            1, 8, 1, /* 465: pointer.struct.asn1_object_st */
            	470, 0,
            0, 40, 3, /* 470: struct.asn1_object_st */
            	56, 0,
            	56, 8,
            	61, 24,
            1, 8, 1, /* 479: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 484: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 489: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 494: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 499: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 504: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 509: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 514: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 519: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 524: pointer.struct.ASN1_VALUE_st */
            	529, 0,
            0, 0, 0, /* 529: struct.ASN1_VALUE_st */
            0, 16, 1, /* 532: struct.GENERAL_NAME_st */
            	537, 8,
            0, 8, 15, /* 537: union.unknown */
            	193, 0,
            	570, 0,
            	504, 0,
            	504, 0,
            	582, 0,
            	378, 0,
            	308, 0,
            	504, 0,
            	417, 0,
            	465, 0,
            	417, 0,
            	378, 0,
            	504, 0,
            	465, 0,
            	582, 0,
            1, 8, 1, /* 570: pointer.struct.otherName_st */
            	575, 0,
            0, 16, 2, /* 575: struct.otherName_st */
            	465, 0,
            	582, 8,
            1, 8, 1, /* 582: pointer.struct.asn1_type_st */
            	587, 0,
            0, 16, 1, /* 587: struct.asn1_type_st */
            	422, 8,
            0, 24, 3, /* 592: struct.GENERAL_SUBTREE_st */
            	601, 0,
            	479, 8,
            	479, 16,
            1, 8, 1, /* 601: pointer.struct.GENERAL_NAME_st */
            	532, 0,
            0, 0, 1, /* 606: GENERAL_SUBTREE */
            	592, 0,
            0, 16, 2, /* 611: struct.NAME_CONSTRAINTS_st */
            	618, 0,
            	618, 8,
            1, 8, 1, /* 618: pointer.struct.stack_st_GENERAL_SUBTREE */
            	623, 0,
            0, 32, 2, /* 623: struct.stack_st_fake_GENERAL_SUBTREE */
            	630, 8,
            	69, 24,
            8884099, 8, 2, /* 630: pointer_to_array_of_pointers_to_stack */
            	637, 0,
            	66, 20,
            0, 8, 1, /* 637: pointer.GENERAL_SUBTREE */
            	606, 0,
            1, 8, 1, /* 642: pointer.struct.NAME_CONSTRAINTS_st */
            	611, 0,
            1, 8, 1, /* 647: pointer.struct.stack_st_GENERAL_NAME */
            	652, 0,
            0, 32, 2, /* 652: struct.stack_st_fake_GENERAL_NAME */
            	659, 8,
            	69, 24,
            8884099, 8, 2, /* 659: pointer_to_array_of_pointers_to_stack */
            	666, 0,
            	66, 20,
            0, 8, 1, /* 666: pointer.GENERAL_NAME */
            	671, 0,
            0, 0, 1, /* 671: GENERAL_NAME */
            	676, 0,
            0, 16, 1, /* 676: struct.GENERAL_NAME_st */
            	681, 8,
            0, 8, 15, /* 681: union.unknown */
            	193, 0,
            	714, 0,
            	833, 0,
            	833, 0,
            	740, 0,
            	881, 0,
            	929, 0,
            	833, 0,
            	818, 0,
            	726, 0,
            	818, 0,
            	881, 0,
            	833, 0,
            	726, 0,
            	740, 0,
            1, 8, 1, /* 714: pointer.struct.otherName_st */
            	719, 0,
            0, 16, 2, /* 719: struct.otherName_st */
            	726, 0,
            	740, 8,
            1, 8, 1, /* 726: pointer.struct.asn1_object_st */
            	731, 0,
            0, 40, 3, /* 731: struct.asn1_object_st */
            	56, 0,
            	56, 8,
            	61, 24,
            1, 8, 1, /* 740: pointer.struct.asn1_type_st */
            	745, 0,
            0, 16, 1, /* 745: struct.asn1_type_st */
            	750, 8,
            0, 8, 20, /* 750: union.unknown */
            	193, 0,
            	793, 0,
            	726, 0,
            	803, 0,
            	808, 0,
            	813, 0,
            	818, 0,
            	823, 0,
            	828, 0,
            	833, 0,
            	838, 0,
            	843, 0,
            	848, 0,
            	853, 0,
            	858, 0,
            	863, 0,
            	868, 0,
            	793, 0,
            	793, 0,
            	873, 0,
            1, 8, 1, /* 793: pointer.struct.asn1_string_st */
            	798, 0,
            0, 24, 1, /* 798: struct.asn1_string_st */
            	10, 8,
            1, 8, 1, /* 803: pointer.struct.asn1_string_st */
            	798, 0,
            1, 8, 1, /* 808: pointer.struct.asn1_string_st */
            	798, 0,
            1, 8, 1, /* 813: pointer.struct.asn1_string_st */
            	798, 0,
            1, 8, 1, /* 818: pointer.struct.asn1_string_st */
            	798, 0,
            1, 8, 1, /* 823: pointer.struct.asn1_string_st */
            	798, 0,
            1, 8, 1, /* 828: pointer.struct.asn1_string_st */
            	798, 0,
            1, 8, 1, /* 833: pointer.struct.asn1_string_st */
            	798, 0,
            1, 8, 1, /* 838: pointer.struct.asn1_string_st */
            	798, 0,
            1, 8, 1, /* 843: pointer.struct.asn1_string_st */
            	798, 0,
            1, 8, 1, /* 848: pointer.struct.asn1_string_st */
            	798, 0,
            1, 8, 1, /* 853: pointer.struct.asn1_string_st */
            	798, 0,
            1, 8, 1, /* 858: pointer.struct.asn1_string_st */
            	798, 0,
            1, 8, 1, /* 863: pointer.struct.asn1_string_st */
            	798, 0,
            1, 8, 1, /* 868: pointer.struct.asn1_string_st */
            	798, 0,
            1, 8, 1, /* 873: pointer.struct.ASN1_VALUE_st */
            	878, 0,
            0, 0, 0, /* 878: struct.ASN1_VALUE_st */
            1, 8, 1, /* 881: pointer.struct.X509_name_st */
            	886, 0,
            0, 40, 3, /* 886: struct.X509_name_st */
            	895, 0,
            	919, 16,
            	10, 24,
            1, 8, 1, /* 895: pointer.struct.stack_st_X509_NAME_ENTRY */
            	900, 0,
            0, 32, 2, /* 900: struct.stack_st_fake_X509_NAME_ENTRY */
            	907, 8,
            	69, 24,
            8884099, 8, 2, /* 907: pointer_to_array_of_pointers_to_stack */
            	914, 0,
            	66, 20,
            0, 8, 1, /* 914: pointer.X509_NAME_ENTRY */
            	342, 0,
            1, 8, 1, /* 919: pointer.struct.buf_mem_st */
            	924, 0,
            0, 24, 1, /* 924: struct.buf_mem_st */
            	193, 8,
            1, 8, 1, /* 929: pointer.struct.EDIPartyName_st */
            	934, 0,
            0, 16, 2, /* 934: struct.EDIPartyName_st */
            	793, 0,
            	793, 8,
            0, 24, 1, /* 941: struct.asn1_string_st */
            	10, 8,
            1, 8, 1, /* 946: pointer.struct.buf_mem_st */
            	951, 0,
            0, 24, 1, /* 951: struct.buf_mem_st */
            	193, 8,
            0, 40, 3, /* 956: struct.X509_name_st */
            	965, 0,
            	946, 16,
            	10, 24,
            1, 8, 1, /* 965: pointer.struct.stack_st_X509_NAME_ENTRY */
            	970, 0,
            0, 32, 2, /* 970: struct.stack_st_fake_X509_NAME_ENTRY */
            	977, 8,
            	69, 24,
            8884099, 8, 2, /* 977: pointer_to_array_of_pointers_to_stack */
            	984, 0,
            	66, 20,
            0, 8, 1, /* 984: pointer.X509_NAME_ENTRY */
            	342, 0,
            1, 8, 1, /* 989: pointer.struct.stack_st_ASN1_OBJECT */
            	994, 0,
            0, 32, 2, /* 994: struct.stack_st_fake_ASN1_OBJECT */
            	1001, 8,
            	69, 24,
            8884099, 8, 2, /* 1001: pointer_to_array_of_pointers_to_stack */
            	1008, 0,
            	66, 20,
            0, 8, 1, /* 1008: pointer.ASN1_OBJECT */
            	42, 0,
            1, 8, 1, /* 1013: pointer.struct.stack_st_POLICYQUALINFO */
            	1018, 0,
            0, 32, 2, /* 1018: struct.stack_st_fake_POLICYQUALINFO */
            	1025, 8,
            	69, 24,
            8884099, 8, 2, /* 1025: pointer_to_array_of_pointers_to_stack */
            	1032, 0,
            	66, 20,
            0, 8, 1, /* 1032: pointer.POLICYQUALINFO */
            	1037, 0,
            0, 0, 1, /* 1037: POLICYQUALINFO */
            	1042, 0,
            0, 16, 2, /* 1042: struct.POLICYQUALINFO_st */
            	1049, 0,
            	1063, 8,
            1, 8, 1, /* 1049: pointer.struct.asn1_object_st */
            	1054, 0,
            0, 40, 3, /* 1054: struct.asn1_object_st */
            	56, 0,
            	56, 8,
            	61, 24,
            0, 8, 3, /* 1063: union.unknown */
            	1072, 0,
            	1082, 0,
            	1145, 0,
            1, 8, 1, /* 1072: pointer.struct.asn1_string_st */
            	1077, 0,
            0, 24, 1, /* 1077: struct.asn1_string_st */
            	10, 8,
            1, 8, 1, /* 1082: pointer.struct.USERNOTICE_st */
            	1087, 0,
            0, 16, 2, /* 1087: struct.USERNOTICE_st */
            	1094, 0,
            	1106, 8,
            1, 8, 1, /* 1094: pointer.struct.NOTICEREF_st */
            	1099, 0,
            0, 16, 2, /* 1099: struct.NOTICEREF_st */
            	1106, 0,
            	1111, 8,
            1, 8, 1, /* 1106: pointer.struct.asn1_string_st */
            	1077, 0,
            1, 8, 1, /* 1111: pointer.struct.stack_st_ASN1_INTEGER */
            	1116, 0,
            0, 32, 2, /* 1116: struct.stack_st_fake_ASN1_INTEGER */
            	1123, 8,
            	69, 24,
            8884099, 8, 2, /* 1123: pointer_to_array_of_pointers_to_stack */
            	1130, 0,
            	66, 20,
            0, 8, 1, /* 1130: pointer.ASN1_INTEGER */
            	1135, 0,
            0, 0, 1, /* 1135: ASN1_INTEGER */
            	1140, 0,
            0, 24, 1, /* 1140: struct.asn1_string_st */
            	10, 8,
            1, 8, 1, /* 1145: pointer.struct.asn1_type_st */
            	1150, 0,
            0, 16, 1, /* 1150: struct.asn1_type_st */
            	1155, 8,
            0, 8, 20, /* 1155: union.unknown */
            	193, 0,
            	1106, 0,
            	1049, 0,
            	1198, 0,
            	1203, 0,
            	1208, 0,
            	1213, 0,
            	1218, 0,
            	1223, 0,
            	1072, 0,
            	1228, 0,
            	1233, 0,
            	1238, 0,
            	1243, 0,
            	1248, 0,
            	1253, 0,
            	1258, 0,
            	1106, 0,
            	1106, 0,
            	524, 0,
            1, 8, 1, /* 1198: pointer.struct.asn1_string_st */
            	1077, 0,
            1, 8, 1, /* 1203: pointer.struct.asn1_string_st */
            	1077, 0,
            1, 8, 1, /* 1208: pointer.struct.asn1_string_st */
            	1077, 0,
            1, 8, 1, /* 1213: pointer.struct.asn1_string_st */
            	1077, 0,
            1, 8, 1, /* 1218: pointer.struct.asn1_string_st */
            	1077, 0,
            1, 8, 1, /* 1223: pointer.struct.asn1_string_st */
            	1077, 0,
            1, 8, 1, /* 1228: pointer.struct.asn1_string_st */
            	1077, 0,
            1, 8, 1, /* 1233: pointer.struct.asn1_string_st */
            	1077, 0,
            1, 8, 1, /* 1238: pointer.struct.asn1_string_st */
            	1077, 0,
            1, 8, 1, /* 1243: pointer.struct.asn1_string_st */
            	1077, 0,
            1, 8, 1, /* 1248: pointer.struct.asn1_string_st */
            	1077, 0,
            1, 8, 1, /* 1253: pointer.struct.asn1_string_st */
            	1077, 0,
            1, 8, 1, /* 1258: pointer.struct.asn1_string_st */
            	1077, 0,
            1, 8, 1, /* 1263: pointer.struct.asn1_object_st */
            	1268, 0,
            0, 40, 3, /* 1268: struct.asn1_object_st */
            	56, 0,
            	56, 8,
            	61, 24,
            0, 8, 2, /* 1277: union.unknown */
            	1284, 0,
            	965, 0,
            1, 8, 1, /* 1284: pointer.struct.stack_st_GENERAL_NAME */
            	1289, 0,
            0, 32, 2, /* 1289: struct.stack_st_fake_GENERAL_NAME */
            	1296, 8,
            	69, 24,
            8884099, 8, 2, /* 1296: pointer_to_array_of_pointers_to_stack */
            	1303, 0,
            	66, 20,
            0, 8, 1, /* 1303: pointer.GENERAL_NAME */
            	671, 0,
            1, 8, 1, /* 1308: pointer.struct.stack_st_X509_POLICY_DATA */
            	1313, 0,
            0, 32, 2, /* 1313: struct.stack_st_fake_X509_POLICY_DATA */
            	1320, 8,
            	69, 24,
            8884099, 8, 2, /* 1320: pointer_to_array_of_pointers_to_stack */
            	1327, 0,
            	66, 20,
            0, 8, 1, /* 1327: pointer.X509_POLICY_DATA */
            	1332, 0,
            0, 0, 1, /* 1332: X509_POLICY_DATA */
            	1337, 0,
            0, 32, 3, /* 1337: struct.X509_POLICY_DATA_st */
            	1263, 8,
            	1013, 16,
            	989, 24,
            1, 8, 1, /* 1346: pointer.struct.asn1_object_st */
            	1351, 0,
            0, 40, 3, /* 1351: struct.asn1_object_st */
            	56, 0,
            	56, 8,
            	61, 24,
            0, 32, 3, /* 1360: struct.X509_POLICY_DATA_st */
            	1346, 8,
            	1369, 16,
            	1393, 24,
            1, 8, 1, /* 1369: pointer.struct.stack_st_POLICYQUALINFO */
            	1374, 0,
            0, 32, 2, /* 1374: struct.stack_st_fake_POLICYQUALINFO */
            	1381, 8,
            	69, 24,
            8884099, 8, 2, /* 1381: pointer_to_array_of_pointers_to_stack */
            	1388, 0,
            	66, 20,
            0, 8, 1, /* 1388: pointer.POLICYQUALINFO */
            	1037, 0,
            1, 8, 1, /* 1393: pointer.struct.stack_st_ASN1_OBJECT */
            	1398, 0,
            0, 32, 2, /* 1398: struct.stack_st_fake_ASN1_OBJECT */
            	1405, 8,
            	69, 24,
            8884099, 8, 2, /* 1405: pointer_to_array_of_pointers_to_stack */
            	1412, 0,
            	66, 20,
            0, 8, 1, /* 1412: pointer.ASN1_OBJECT */
            	42, 0,
            0, 40, 2, /* 1417: struct.X509_POLICY_CACHE_st */
            	1424, 0,
            	1308, 8,
            1, 8, 1, /* 1424: pointer.struct.X509_POLICY_DATA_st */
            	1360, 0,
            1, 8, 1, /* 1429: pointer.struct.asn1_string_st */
            	1434, 0,
            0, 24, 1, /* 1434: struct.asn1_string_st */
            	10, 8,
            1, 8, 1, /* 1439: pointer.struct.stack_st_GENERAL_NAME */
            	1444, 0,
            0, 32, 2, /* 1444: struct.stack_st_fake_GENERAL_NAME */
            	1451, 8,
            	69, 24,
            8884099, 8, 2, /* 1451: pointer_to_array_of_pointers_to_stack */
            	1458, 0,
            	66, 20,
            0, 8, 1, /* 1458: pointer.GENERAL_NAME */
            	671, 0,
            1, 8, 1, /* 1463: pointer.struct.asn1_string_st */
            	1434, 0,
            1, 8, 1, /* 1468: pointer.struct.AUTHORITY_KEYID_st */
            	1473, 0,
            0, 24, 3, /* 1473: struct.AUTHORITY_KEYID_st */
            	1463, 0,
            	1439, 8,
            	1429, 16,
            0, 32, 1, /* 1482: struct.stack_st_void */
            	1487, 0,
            0, 32, 2, /* 1487: struct.stack_st */
            	1494, 8,
            	69, 24,
            1, 8, 1, /* 1494: pointer.pointer.char */
            	193, 0,
            0, 16, 1, /* 1499: struct.crypto_ex_data_st */
            	1504, 0,
            1, 8, 1, /* 1504: pointer.struct.stack_st_void */
            	1482, 0,
            0, 40, 3, /* 1509: struct.asn1_object_st */
            	56, 0,
            	56, 8,
            	61, 24,
            0, 24, 2, /* 1518: struct.X509_extension_st */
            	1525, 0,
            	1530, 16,
            1, 8, 1, /* 1525: pointer.struct.asn1_object_st */
            	1509, 0,
            1, 8, 1, /* 1530: pointer.struct.asn1_string_st */
            	1535, 0,
            0, 24, 1, /* 1535: struct.asn1_string_st */
            	10, 8,
            0, 0, 1, /* 1540: X509_EXTENSION */
            	1518, 0,
            1, 8, 1, /* 1545: pointer.struct.stack_st_X509_EXTENSION */
            	1550, 0,
            0, 32, 2, /* 1550: struct.stack_st_fake_X509_EXTENSION */
            	1557, 8,
            	69, 24,
            8884099, 8, 2, /* 1557: pointer_to_array_of_pointers_to_stack */
            	1564, 0,
            	66, 20,
            0, 8, 1, /* 1564: pointer.X509_EXTENSION */
            	1540, 0,
            1, 8, 1, /* 1569: pointer.struct.asn1_string_st */
            	5, 0,
            1, 8, 1, /* 1574: pointer.struct.ASN1_VALUE_st */
            	1579, 0,
            0, 0, 0, /* 1579: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1582: pointer.struct.asn1_string_st */
            	1587, 0,
            0, 24, 1, /* 1587: struct.asn1_string_st */
            	10, 8,
            0, 24, 1, /* 1592: struct.ASN1_ENCODING_st */
            	10, 0,
            1, 8, 1, /* 1597: pointer.struct.asn1_string_st */
            	1587, 0,
            1, 8, 1, /* 1602: pointer.struct.asn1_string_st */
            	1587, 0,
            1, 8, 1, /* 1607: pointer.struct.asn1_string_st */
            	1587, 0,
            1, 8, 1, /* 1612: pointer.struct.asn1_string_st */
            	1587, 0,
            1, 8, 1, /* 1617: pointer.struct.asn1_string_st */
            	1587, 0,
            1, 8, 1, /* 1622: pointer.struct.asn1_string_st */
            	1587, 0,
            1, 8, 1, /* 1627: pointer.struct.asn1_string_st */
            	941, 0,
            1, 8, 1, /* 1632: pointer.struct.asn1_string_st */
            	1587, 0,
            1, 8, 1, /* 1637: pointer.struct.asn1_string_st */
            	1587, 0,
            1, 8, 1, /* 1642: pointer.struct.asn1_string_st */
            	1587, 0,
            1, 8, 1, /* 1647: pointer.struct.asn1_string_st */
            	1587, 0,
            1, 8, 1, /* 1652: pointer.struct.asn1_string_st */
            	1587, 0,
            1, 8, 1, /* 1657: pointer.struct.asn1_string_st */
            	1587, 0,
            0, 16, 1, /* 1662: struct.asn1_type_st */
            	1667, 8,
            0, 8, 20, /* 1667: union.unknown */
            	193, 0,
            	1657, 0,
            	1710, 0,
            	1724, 0,
            	1652, 0,
            	1647, 0,
            	1642, 0,
            	1637, 0,
            	1632, 0,
            	1622, 0,
            	1617, 0,
            	1612, 0,
            	1607, 0,
            	1602, 0,
            	1597, 0,
            	1729, 0,
            	1582, 0,
            	1657, 0,
            	1657, 0,
            	1574, 0,
            1, 8, 1, /* 1710: pointer.struct.asn1_object_st */
            	1715, 0,
            0, 40, 3, /* 1715: struct.asn1_object_st */
            	56, 0,
            	56, 8,
            	61, 24,
            1, 8, 1, /* 1724: pointer.struct.asn1_string_st */
            	1587, 0,
            1, 8, 1, /* 1729: pointer.struct.asn1_string_st */
            	1587, 0,
            1, 8, 1, /* 1734: pointer.struct.ASN1_VALUE_st */
            	1739, 0,
            0, 0, 0, /* 1739: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1742: pointer.struct.asn1_string_st */
            	1747, 0,
            0, 24, 1, /* 1747: struct.asn1_string_st */
            	10, 8,
            1, 8, 1, /* 1752: pointer.struct.asn1_string_st */
            	1747, 0,
            1, 8, 1, /* 1757: pointer.struct.asn1_string_st */
            	1747, 0,
            1, 8, 1, /* 1762: pointer.struct.asn1_string_st */
            	1747, 0,
            1, 8, 1, /* 1767: pointer.struct.asn1_string_st */
            	1747, 0,
            1, 8, 1, /* 1772: pointer.struct.asn1_string_st */
            	1747, 0,
            1, 8, 1, /* 1777: pointer.struct.asn1_string_st */
            	1747, 0,
            1, 8, 1, /* 1782: pointer.struct.asn1_string_st */
            	1747, 0,
            1, 8, 1, /* 1787: pointer.struct.asn1_string_st */
            	1747, 0,
            0, 40, 3, /* 1792: struct.asn1_object_st */
            	56, 0,
            	56, 8,
            	61, 24,
            1, 8, 1, /* 1801: pointer.struct.asn1_object_st */
            	1792, 0,
            1, 8, 1, /* 1806: pointer.struct.asn1_string_st */
            	1747, 0,
            0, 8, 20, /* 1811: union.unknown */
            	193, 0,
            	1806, 0,
            	1801, 0,
            	1787, 0,
            	1782, 0,
            	1854, 0,
            	1777, 0,
            	1859, 0,
            	1864, 0,
            	1772, 0,
            	1767, 0,
            	1869, 0,
            	1762, 0,
            	1757, 0,
            	1752, 0,
            	1874, 0,
            	1742, 0,
            	1806, 0,
            	1806, 0,
            	1734, 0,
            1, 8, 1, /* 1854: pointer.struct.asn1_string_st */
            	1747, 0,
            1, 8, 1, /* 1859: pointer.struct.asn1_string_st */
            	1747, 0,
            1, 8, 1, /* 1864: pointer.struct.asn1_string_st */
            	1747, 0,
            1, 8, 1, /* 1869: pointer.struct.asn1_string_st */
            	1747, 0,
            1, 8, 1, /* 1874: pointer.struct.asn1_string_st */
            	1747, 0,
            0, 16, 1, /* 1879: struct.asn1_type_st */
            	1811, 8,
            0, 0, 1, /* 1884: ASN1_TYPE */
            	1879, 0,
            1, 8, 1, /* 1889: pointer.struct.stack_st_ASN1_TYPE */
            	1894, 0,
            0, 32, 2, /* 1894: struct.stack_st_fake_ASN1_TYPE */
            	1901, 8,
            	69, 24,
            8884099, 8, 2, /* 1901: pointer_to_array_of_pointers_to_stack */
            	1908, 0,
            	66, 20,
            0, 8, 1, /* 1908: pointer.ASN1_TYPE */
            	1884, 0,
            0, 8, 3, /* 1913: union.unknown */
            	193, 0,
            	1889, 0,
            	1922, 0,
            1, 8, 1, /* 1922: pointer.struct.asn1_type_st */
            	1662, 0,
            0, 24, 2, /* 1927: struct.x509_attributes_st */
            	1710, 0,
            	1913, 16,
            0, 0, 1, /* 1934: DIST_POINT */
            	1939, 0,
            0, 32, 3, /* 1939: struct.DIST_POINT_st */
            	1948, 0,
            	1627, 8,
            	1284, 16,
            1, 8, 1, /* 1948: pointer.struct.DIST_POINT_NAME_st */
            	1953, 0,
            0, 24, 2, /* 1953: struct.DIST_POINT_NAME_st */
            	1277, 8,
            	1960, 16,
            1, 8, 1, /* 1960: pointer.struct.X509_name_st */
            	956, 0,
            1, 8, 1, /* 1965: pointer.struct.stack_st_X509_ATTRIBUTE */
            	1970, 0,
            0, 32, 2, /* 1970: struct.stack_st_fake_X509_ATTRIBUTE */
            	1977, 8,
            	69, 24,
            8884099, 8, 2, /* 1977: pointer_to_array_of_pointers_to_stack */
            	1984, 0,
            	66, 20,
            0, 8, 1, /* 1984: pointer.X509_ATTRIBUTE */
            	1989, 0,
            0, 0, 1, /* 1989: X509_ATTRIBUTE */
            	1927, 0,
            0, 24, 1, /* 1994: struct.bignum_st */
            	1999, 0,
            1, 8, 1, /* 1999: pointer.unsigned int */
            	2004, 0,
            0, 4, 0, /* 2004: unsigned int */
            1, 8, 1, /* 2007: pointer.struct.ec_point_st */
            	2012, 0,
            0, 88, 4, /* 2012: struct.ec_point_st */
            	2023, 0,
            	2195, 8,
            	2195, 32,
            	2195, 56,
            1, 8, 1, /* 2023: pointer.struct.ec_method_st */
            	2028, 0,
            0, 304, 37, /* 2028: struct.ec_method_st */
            	2105, 8,
            	2108, 16,
            	2108, 24,
            	2111, 32,
            	2114, 40,
            	2117, 48,
            	2120, 56,
            	2123, 64,
            	2126, 72,
            	2129, 80,
            	2129, 88,
            	2132, 96,
            	2135, 104,
            	2138, 112,
            	2141, 120,
            	2144, 128,
            	2147, 136,
            	2150, 144,
            	2153, 152,
            	2156, 160,
            	2159, 168,
            	2162, 176,
            	2165, 184,
            	2168, 192,
            	2171, 200,
            	2174, 208,
            	2165, 216,
            	2177, 224,
            	2180, 232,
            	2183, 240,
            	2120, 248,
            	2186, 256,
            	2189, 264,
            	2186, 272,
            	2189, 280,
            	2189, 288,
            	2192, 296,
            8884097, 8, 0, /* 2105: pointer.func */
            8884097, 8, 0, /* 2108: pointer.func */
            8884097, 8, 0, /* 2111: pointer.func */
            8884097, 8, 0, /* 2114: pointer.func */
            8884097, 8, 0, /* 2117: pointer.func */
            8884097, 8, 0, /* 2120: pointer.func */
            8884097, 8, 0, /* 2123: pointer.func */
            8884097, 8, 0, /* 2126: pointer.func */
            8884097, 8, 0, /* 2129: pointer.func */
            8884097, 8, 0, /* 2132: pointer.func */
            8884097, 8, 0, /* 2135: pointer.func */
            8884097, 8, 0, /* 2138: pointer.func */
            8884097, 8, 0, /* 2141: pointer.func */
            8884097, 8, 0, /* 2144: pointer.func */
            8884097, 8, 0, /* 2147: pointer.func */
            8884097, 8, 0, /* 2150: pointer.func */
            8884097, 8, 0, /* 2153: pointer.func */
            8884097, 8, 0, /* 2156: pointer.func */
            8884097, 8, 0, /* 2159: pointer.func */
            8884097, 8, 0, /* 2162: pointer.func */
            8884097, 8, 0, /* 2165: pointer.func */
            8884097, 8, 0, /* 2168: pointer.func */
            8884097, 8, 0, /* 2171: pointer.func */
            8884097, 8, 0, /* 2174: pointer.func */
            8884097, 8, 0, /* 2177: pointer.func */
            8884097, 8, 0, /* 2180: pointer.func */
            8884097, 8, 0, /* 2183: pointer.func */
            8884097, 8, 0, /* 2186: pointer.func */
            8884097, 8, 0, /* 2189: pointer.func */
            8884097, 8, 0, /* 2192: pointer.func */
            0, 24, 1, /* 2195: struct.bignum_st */
            	1999, 0,
            8884097, 8, 0, /* 2200: pointer.func */
            1, 8, 1, /* 2203: pointer.struct.ec_extra_data_st */
            	2208, 0,
            0, 40, 5, /* 2208: struct.ec_extra_data_st */
            	2221, 0,
            	2226, 8,
            	2200, 16,
            	2229, 24,
            	2229, 32,
            1, 8, 1, /* 2221: pointer.struct.ec_extra_data_st */
            	2208, 0,
            0, 8, 0, /* 2226: pointer.void */
            8884097, 8, 0, /* 2229: pointer.func */
            0, 24, 1, /* 2232: struct.bignum_st */
            	1999, 0,
            1, 8, 1, /* 2237: pointer.struct.ec_extra_data_st */
            	2242, 0,
            0, 40, 5, /* 2242: struct.ec_extra_data_st */
            	2237, 0,
            	2226, 8,
            	2200, 16,
            	2229, 24,
            	2229, 32,
            1, 8, 1, /* 2255: pointer.struct.stack_st_void */
            	2260, 0,
            0, 32, 1, /* 2260: struct.stack_st_void */
            	2265, 0,
            0, 32, 2, /* 2265: struct.stack_st */
            	1494, 8,
            	69, 24,
            8884097, 8, 0, /* 2272: pointer.func */
            0, 48, 6, /* 2275: struct.rand_meth_st */
            	2290, 0,
            	2293, 8,
            	2296, 16,
            	2299, 24,
            	2293, 32,
            	2302, 40,
            8884097, 8, 0, /* 2290: pointer.func */
            8884097, 8, 0, /* 2293: pointer.func */
            8884097, 8, 0, /* 2296: pointer.func */
            8884097, 8, 0, /* 2299: pointer.func */
            8884097, 8, 0, /* 2302: pointer.func */
            8884097, 8, 0, /* 2305: pointer.func */
            8884097, 8, 0, /* 2308: pointer.func */
            0, 8, 5, /* 2311: union.unknown */
            	193, 0,
            	2324, 0,
            	2816, 0,
            	2948, 0,
            	3062, 0,
            1, 8, 1, /* 2324: pointer.struct.rsa_st */
            	2329, 0,
            0, 168, 17, /* 2329: struct.rsa_st */
            	2366, 16,
            	2421, 24,
            	2716, 32,
            	2716, 40,
            	2716, 48,
            	2716, 56,
            	2716, 64,
            	2716, 72,
            	2716, 80,
            	2716, 88,
            	2726, 96,
            	2748, 120,
            	2748, 128,
            	2748, 136,
            	193, 144,
            	2762, 152,
            	2762, 160,
            1, 8, 1, /* 2366: pointer.struct.rsa_meth_st */
            	2371, 0,
            0, 112, 13, /* 2371: struct.rsa_meth_st */
            	56, 0,
            	2400, 8,
            	2400, 16,
            	2400, 24,
            	2400, 32,
            	2403, 40,
            	2406, 48,
            	2409, 56,
            	2409, 64,
            	193, 80,
            	2412, 88,
            	2415, 96,
            	2418, 104,
            8884097, 8, 0, /* 2400: pointer.func */
            8884097, 8, 0, /* 2403: pointer.func */
            8884097, 8, 0, /* 2406: pointer.func */
            8884097, 8, 0, /* 2409: pointer.func */
            8884097, 8, 0, /* 2412: pointer.func */
            8884097, 8, 0, /* 2415: pointer.func */
            8884097, 8, 0, /* 2418: pointer.func */
            1, 8, 1, /* 2421: pointer.struct.engine_st */
            	2426, 0,
            0, 216, 24, /* 2426: struct.engine_st */
            	56, 0,
            	56, 8,
            	2477, 16,
            	2532, 24,
            	2583, 32,
            	2619, 40,
            	2636, 48,
            	2660, 56,
            	2665, 64,
            	2673, 72,
            	2676, 80,
            	2679, 88,
            	2272, 96,
            	2682, 104,
            	2682, 112,
            	2682, 120,
            	2685, 128,
            	2688, 136,
            	2688, 144,
            	2691, 152,
            	2694, 160,
            	2706, 184,
            	2711, 200,
            	2711, 208,
            1, 8, 1, /* 2477: pointer.struct.rsa_meth_st */
            	2482, 0,
            0, 112, 13, /* 2482: struct.rsa_meth_st */
            	56, 0,
            	2511, 8,
            	2511, 16,
            	2511, 24,
            	2511, 32,
            	2514, 40,
            	2517, 48,
            	2520, 56,
            	2520, 64,
            	193, 80,
            	2523, 88,
            	2526, 96,
            	2529, 104,
            8884097, 8, 0, /* 2511: pointer.func */
            8884097, 8, 0, /* 2514: pointer.func */
            8884097, 8, 0, /* 2517: pointer.func */
            8884097, 8, 0, /* 2520: pointer.func */
            8884097, 8, 0, /* 2523: pointer.func */
            8884097, 8, 0, /* 2526: pointer.func */
            8884097, 8, 0, /* 2529: pointer.func */
            1, 8, 1, /* 2532: pointer.struct.dsa_method */
            	2537, 0,
            0, 96, 11, /* 2537: struct.dsa_method */
            	56, 0,
            	2562, 8,
            	2565, 16,
            	2568, 24,
            	2571, 32,
            	2574, 40,
            	2577, 48,
            	2577, 56,
            	193, 72,
            	2580, 80,
            	2577, 88,
            8884097, 8, 0, /* 2562: pointer.func */
            8884097, 8, 0, /* 2565: pointer.func */
            8884097, 8, 0, /* 2568: pointer.func */
            8884097, 8, 0, /* 2571: pointer.func */
            8884097, 8, 0, /* 2574: pointer.func */
            8884097, 8, 0, /* 2577: pointer.func */
            8884097, 8, 0, /* 2580: pointer.func */
            1, 8, 1, /* 2583: pointer.struct.dh_method */
            	2588, 0,
            0, 72, 8, /* 2588: struct.dh_method */
            	56, 0,
            	2607, 8,
            	2610, 16,
            	2613, 24,
            	2607, 32,
            	2607, 40,
            	193, 56,
            	2616, 64,
            8884097, 8, 0, /* 2607: pointer.func */
            8884097, 8, 0, /* 2610: pointer.func */
            8884097, 8, 0, /* 2613: pointer.func */
            8884097, 8, 0, /* 2616: pointer.func */
            1, 8, 1, /* 2619: pointer.struct.ecdh_method */
            	2624, 0,
            0, 32, 3, /* 2624: struct.ecdh_method */
            	56, 0,
            	2633, 8,
            	193, 24,
            8884097, 8, 0, /* 2633: pointer.func */
            1, 8, 1, /* 2636: pointer.struct.ecdsa_method */
            	2641, 0,
            0, 48, 5, /* 2641: struct.ecdsa_method */
            	56, 0,
            	2654, 8,
            	2308, 16,
            	2657, 24,
            	193, 40,
            8884097, 8, 0, /* 2654: pointer.func */
            8884097, 8, 0, /* 2657: pointer.func */
            1, 8, 1, /* 2660: pointer.struct.rand_meth_st */
            	2275, 0,
            1, 8, 1, /* 2665: pointer.struct.store_method_st */
            	2670, 0,
            0, 0, 0, /* 2670: struct.store_method_st */
            8884097, 8, 0, /* 2673: pointer.func */
            8884097, 8, 0, /* 2676: pointer.func */
            8884097, 8, 0, /* 2679: pointer.func */
            8884097, 8, 0, /* 2682: pointer.func */
            8884097, 8, 0, /* 2685: pointer.func */
            8884097, 8, 0, /* 2688: pointer.func */
            8884097, 8, 0, /* 2691: pointer.func */
            1, 8, 1, /* 2694: pointer.struct.ENGINE_CMD_DEFN_st */
            	2699, 0,
            0, 32, 2, /* 2699: struct.ENGINE_CMD_DEFN_st */
            	56, 8,
            	56, 16,
            0, 16, 1, /* 2706: struct.crypto_ex_data_st */
            	2255, 0,
            1, 8, 1, /* 2711: pointer.struct.engine_st */
            	2426, 0,
            1, 8, 1, /* 2716: pointer.struct.bignum_st */
            	2721, 0,
            0, 24, 1, /* 2721: struct.bignum_st */
            	1999, 0,
            0, 16, 1, /* 2726: struct.crypto_ex_data_st */
            	2731, 0,
            1, 8, 1, /* 2731: pointer.struct.stack_st_void */
            	2736, 0,
            0, 32, 1, /* 2736: struct.stack_st_void */
            	2741, 0,
            0, 32, 2, /* 2741: struct.stack_st */
            	1494, 8,
            	69, 24,
            1, 8, 1, /* 2748: pointer.struct.bn_mont_ctx_st */
            	2753, 0,
            0, 96, 3, /* 2753: struct.bn_mont_ctx_st */
            	2721, 8,
            	2721, 32,
            	2721, 56,
            1, 8, 1, /* 2762: pointer.struct.bn_blinding_st */
            	2767, 0,
            0, 88, 7, /* 2767: struct.bn_blinding_st */
            	2784, 0,
            	2784, 8,
            	2784, 16,
            	2784, 24,
            	2794, 40,
            	2799, 72,
            	2813, 80,
            1, 8, 1, /* 2784: pointer.struct.bignum_st */
            	2789, 0,
            0, 24, 1, /* 2789: struct.bignum_st */
            	1999, 0,
            0, 16, 1, /* 2794: struct.crypto_threadid_st */
            	2226, 0,
            1, 8, 1, /* 2799: pointer.struct.bn_mont_ctx_st */
            	2804, 0,
            0, 96, 3, /* 2804: struct.bn_mont_ctx_st */
            	2789, 8,
            	2789, 32,
            	2789, 56,
            8884097, 8, 0, /* 2813: pointer.func */
            1, 8, 1, /* 2816: pointer.struct.dsa_st */
            	2821, 0,
            0, 136, 11, /* 2821: struct.dsa_st */
            	2846, 24,
            	2846, 32,
            	2846, 40,
            	2846, 48,
            	2846, 56,
            	2846, 64,
            	2846, 72,
            	2856, 88,
            	2870, 104,
            	2892, 120,
            	2943, 128,
            1, 8, 1, /* 2846: pointer.struct.bignum_st */
            	2851, 0,
            0, 24, 1, /* 2851: struct.bignum_st */
            	1999, 0,
            1, 8, 1, /* 2856: pointer.struct.bn_mont_ctx_st */
            	2861, 0,
            0, 96, 3, /* 2861: struct.bn_mont_ctx_st */
            	2851, 8,
            	2851, 32,
            	2851, 56,
            0, 16, 1, /* 2870: struct.crypto_ex_data_st */
            	2875, 0,
            1, 8, 1, /* 2875: pointer.struct.stack_st_void */
            	2880, 0,
            0, 32, 1, /* 2880: struct.stack_st_void */
            	2885, 0,
            0, 32, 2, /* 2885: struct.stack_st */
            	1494, 8,
            	69, 24,
            1, 8, 1, /* 2892: pointer.struct.dsa_method */
            	2897, 0,
            0, 96, 11, /* 2897: struct.dsa_method */
            	56, 0,
            	2922, 8,
            	2925, 16,
            	2928, 24,
            	2931, 32,
            	2934, 40,
            	2937, 48,
            	2937, 56,
            	193, 72,
            	2940, 80,
            	2937, 88,
            8884097, 8, 0, /* 2922: pointer.func */
            8884097, 8, 0, /* 2925: pointer.func */
            8884097, 8, 0, /* 2928: pointer.func */
            8884097, 8, 0, /* 2931: pointer.func */
            8884097, 8, 0, /* 2934: pointer.func */
            8884097, 8, 0, /* 2937: pointer.func */
            8884097, 8, 0, /* 2940: pointer.func */
            1, 8, 1, /* 2943: pointer.struct.engine_st */
            	2426, 0,
            1, 8, 1, /* 2948: pointer.struct.dh_st */
            	2953, 0,
            0, 144, 12, /* 2953: struct.dh_st */
            	2980, 8,
            	2980, 16,
            	2980, 32,
            	2980, 40,
            	2990, 56,
            	2980, 64,
            	2980, 72,
            	10, 80,
            	2980, 96,
            	3004, 112,
            	3026, 128,
            	2421, 136,
            1, 8, 1, /* 2980: pointer.struct.bignum_st */
            	2985, 0,
            0, 24, 1, /* 2985: struct.bignum_st */
            	1999, 0,
            1, 8, 1, /* 2990: pointer.struct.bn_mont_ctx_st */
            	2995, 0,
            0, 96, 3, /* 2995: struct.bn_mont_ctx_st */
            	2985, 8,
            	2985, 32,
            	2985, 56,
            0, 16, 1, /* 3004: struct.crypto_ex_data_st */
            	3009, 0,
            1, 8, 1, /* 3009: pointer.struct.stack_st_void */
            	3014, 0,
            0, 32, 1, /* 3014: struct.stack_st_void */
            	3019, 0,
            0, 32, 2, /* 3019: struct.stack_st */
            	1494, 8,
            	69, 24,
            1, 8, 1, /* 3026: pointer.struct.dh_method */
            	3031, 0,
            0, 72, 8, /* 3031: struct.dh_method */
            	56, 0,
            	3050, 8,
            	3053, 16,
            	3056, 24,
            	3050, 32,
            	3050, 40,
            	193, 56,
            	3059, 64,
            8884097, 8, 0, /* 3050: pointer.func */
            8884097, 8, 0, /* 3053: pointer.func */
            8884097, 8, 0, /* 3056: pointer.func */
            8884097, 8, 0, /* 3059: pointer.func */
            1, 8, 1, /* 3062: pointer.struct.ec_key_st */
            	3067, 0,
            0, 56, 4, /* 3067: struct.ec_key_st */
            	3078, 8,
            	2007, 16,
            	3290, 24,
            	3295, 48,
            1, 8, 1, /* 3078: pointer.struct.ec_group_st */
            	3083, 0,
            0, 232, 12, /* 3083: struct.ec_group_st */
            	3110, 0,
            	3282, 8,
            	2232, 16,
            	2232, 40,
            	10, 80,
            	2203, 96,
            	2232, 104,
            	2232, 152,
            	2232, 176,
            	2226, 208,
            	2226, 216,
            	3287, 224,
            1, 8, 1, /* 3110: pointer.struct.ec_method_st */
            	3115, 0,
            0, 304, 37, /* 3115: struct.ec_method_st */
            	3192, 8,
            	3195, 16,
            	3195, 24,
            	3198, 32,
            	3201, 40,
            	3204, 48,
            	3207, 56,
            	3210, 64,
            	3213, 72,
            	3216, 80,
            	3216, 88,
            	3219, 96,
            	3222, 104,
            	3225, 112,
            	3228, 120,
            	3231, 128,
            	3234, 136,
            	3237, 144,
            	3240, 152,
            	3243, 160,
            	3246, 168,
            	3249, 176,
            	3252, 184,
            	3255, 192,
            	3258, 200,
            	3261, 208,
            	3252, 216,
            	3264, 224,
            	3267, 232,
            	3270, 240,
            	3207, 248,
            	3273, 256,
            	3276, 264,
            	3273, 272,
            	3276, 280,
            	3276, 288,
            	3279, 296,
            8884097, 8, 0, /* 3192: pointer.func */
            8884097, 8, 0, /* 3195: pointer.func */
            8884097, 8, 0, /* 3198: pointer.func */
            8884097, 8, 0, /* 3201: pointer.func */
            8884097, 8, 0, /* 3204: pointer.func */
            8884097, 8, 0, /* 3207: pointer.func */
            8884097, 8, 0, /* 3210: pointer.func */
            8884097, 8, 0, /* 3213: pointer.func */
            8884097, 8, 0, /* 3216: pointer.func */
            8884097, 8, 0, /* 3219: pointer.func */
            8884097, 8, 0, /* 3222: pointer.func */
            8884097, 8, 0, /* 3225: pointer.func */
            8884097, 8, 0, /* 3228: pointer.func */
            8884097, 8, 0, /* 3231: pointer.func */
            8884097, 8, 0, /* 3234: pointer.func */
            8884097, 8, 0, /* 3237: pointer.func */
            8884097, 8, 0, /* 3240: pointer.func */
            8884097, 8, 0, /* 3243: pointer.func */
            8884097, 8, 0, /* 3246: pointer.func */
            8884097, 8, 0, /* 3249: pointer.func */
            8884097, 8, 0, /* 3252: pointer.func */
            8884097, 8, 0, /* 3255: pointer.func */
            8884097, 8, 0, /* 3258: pointer.func */
            8884097, 8, 0, /* 3261: pointer.func */
            8884097, 8, 0, /* 3264: pointer.func */
            8884097, 8, 0, /* 3267: pointer.func */
            8884097, 8, 0, /* 3270: pointer.func */
            8884097, 8, 0, /* 3273: pointer.func */
            8884097, 8, 0, /* 3276: pointer.func */
            8884097, 8, 0, /* 3279: pointer.func */
            1, 8, 1, /* 3282: pointer.struct.ec_point_st */
            	2012, 0,
            8884097, 8, 0, /* 3287: pointer.func */
            1, 8, 1, /* 3290: pointer.struct.bignum_st */
            	1994, 0,
            1, 8, 1, /* 3295: pointer.struct.ec_extra_data_st */
            	2242, 0,
            1, 8, 1, /* 3300: pointer.struct.X509_val_st */
            	3305, 0,
            0, 16, 2, /* 3305: struct.X509_val_st */
            	3312, 0,
            	3312, 8,
            1, 8, 1, /* 3312: pointer.struct.asn1_string_st */
            	5, 0,
            8884097, 8, 0, /* 3317: pointer.func */
            1, 8, 1, /* 3320: pointer.struct.asn1_string_st */
            	3325, 0,
            0, 24, 1, /* 3325: struct.asn1_string_st */
            	10, 8,
            8884097, 8, 0, /* 3330: pointer.func */
            8884097, 8, 0, /* 3333: pointer.func */
            8884097, 8, 0, /* 3336: pointer.func */
            8884097, 8, 0, /* 3339: pointer.func */
            0, 208, 24, /* 3342: struct.evp_pkey_asn1_method_st */
            	193, 16,
            	193, 24,
            	3339, 32,
            	3393, 40,
            	3396, 48,
            	3336, 56,
            	3399, 64,
            	3402, 72,
            	3336, 80,
            	3333, 88,
            	3333, 96,
            	3405, 104,
            	3408, 112,
            	3333, 120,
            	3411, 128,
            	3396, 136,
            	3336, 144,
            	2305, 152,
            	3317, 160,
            	3414, 168,
            	3405, 176,
            	3408, 184,
            	3417, 192,
            	3330, 200,
            8884097, 8, 0, /* 3393: pointer.func */
            8884097, 8, 0, /* 3396: pointer.func */
            8884097, 8, 0, /* 3399: pointer.func */
            8884097, 8, 0, /* 3402: pointer.func */
            8884097, 8, 0, /* 3405: pointer.func */
            8884097, 8, 0, /* 3408: pointer.func */
            8884097, 8, 0, /* 3411: pointer.func */
            8884097, 8, 0, /* 3414: pointer.func */
            8884097, 8, 0, /* 3417: pointer.func */
            1, 8, 1, /* 3420: pointer.struct.evp_pkey_asn1_method_st */
            	3342, 0,
            1, 8, 1, /* 3425: pointer.struct.buf_mem_st */
            	3430, 0,
            0, 24, 1, /* 3430: struct.buf_mem_st */
            	193, 8,
            1, 8, 1, /* 3435: pointer.struct.stack_st_DIST_POINT */
            	3440, 0,
            0, 32, 2, /* 3440: struct.stack_st_fake_DIST_POINT */
            	3447, 8,
            	69, 24,
            8884099, 8, 2, /* 3447: pointer_to_array_of_pointers_to_stack */
            	3454, 0,
            	66, 20,
            0, 8, 1, /* 3454: pointer.DIST_POINT */
            	1934, 0,
            1, 8, 1, /* 3459: pointer.struct.x509_cinf_st */
            	3464, 0,
            0, 104, 11, /* 3464: struct.x509_cinf_st */
            	3489, 0,
            	3489, 8,
            	3494, 16,
            	3499, 24,
            	3300, 32,
            	3499, 40,
            	3537, 48,
            	1569, 56,
            	1569, 64,
            	1545, 72,
            	1592, 80,
            1, 8, 1, /* 3489: pointer.struct.asn1_string_st */
            	5, 0,
            1, 8, 1, /* 3494: pointer.struct.X509_algor_st */
            	119, 0,
            1, 8, 1, /* 3499: pointer.struct.X509_name_st */
            	3504, 0,
            0, 40, 3, /* 3504: struct.X509_name_st */
            	3513, 0,
            	3425, 16,
            	10, 24,
            1, 8, 1, /* 3513: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3518, 0,
            0, 32, 2, /* 3518: struct.stack_st_fake_X509_NAME_ENTRY */
            	3525, 8,
            	69, 24,
            8884099, 8, 2, /* 3525: pointer_to_array_of_pointers_to_stack */
            	3532, 0,
            	66, 20,
            0, 8, 1, /* 3532: pointer.X509_NAME_ENTRY */
            	342, 0,
            1, 8, 1, /* 3537: pointer.struct.X509_pubkey_st */
            	3542, 0,
            0, 24, 3, /* 3542: struct.X509_pubkey_st */
            	3551, 0,
            	3320, 8,
            	3556, 16,
            1, 8, 1, /* 3551: pointer.struct.X509_algor_st */
            	119, 0,
            1, 8, 1, /* 3556: pointer.struct.evp_pkey_st */
            	3561, 0,
            0, 56, 4, /* 3561: struct.evp_pkey_st */
            	3420, 16,
            	2943, 24,
            	2311, 32,
            	1965, 48,
            0, 1, 0, /* 3572: char */
            0, 184, 12, /* 3575: struct.x509_st */
            	3459, 0,
            	3494, 8,
            	1569, 16,
            	193, 32,
            	1499, 40,
            	85, 104,
            	1468, 112,
            	3602, 120,
            	3435, 128,
            	647, 136,
            	642, 144,
            	286, 176,
            1, 8, 1, /* 3602: pointer.struct.X509_POLICY_CACHE_st */
            	1417, 0,
            1, 8, 1, /* 3607: pointer.struct.x509_st */
            	3575, 0,
        },
        .arg_entity_index = { 3607, },
        .ret_entity_index = 3499,
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

