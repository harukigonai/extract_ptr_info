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

void * bb_X509_get_ext_d2i(X509 * arg_a,int arg_b,int * arg_c,int * arg_d);

void * X509_get_ext_d2i(X509 * arg_a,int arg_b,int * arg_c,int * arg_d) 
{
    unsigned long in_lib = syscall(890);
    printf("X509_get_ext_d2i called %lu\n", in_lib);
    if (!in_lib)
        return bb_X509_get_ext_d2i(arg_a,arg_b,arg_c,arg_d);
    else {
        void * (*orig_X509_get_ext_d2i)(X509 *,int,int *,int *);
        orig_X509_get_ext_d2i = dlsym(RTLD_NEXT, "X509_get_ext_d2i");
        return orig_X509_get_ext_d2i(arg_a,arg_b,arg_c,arg_d);
    }
}

void * bb_X509_get_ext_d2i(X509 * arg_a,int arg_b,int * arg_c,int * arg_d) 
{
    void * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 16, 2, /* 0: struct.EDIPartyName_st */
            	7, 0,
            	7, 8,
            1, 8, 1, /* 7: pointer.struct.asn1_string_st */
            	12, 0,
            0, 24, 1, /* 12: struct.asn1_string_st */
            	17, 8,
            1, 8, 1, /* 17: pointer.unsigned char */
            	22, 0,
            0, 1, 0, /* 22: unsigned char */
            1, 8, 1, /* 25: pointer.struct.EDIPartyName_st */
            	0, 0,
            0, 24, 1, /* 30: struct.buf_mem_st */
            	35, 8,
            1, 8, 1, /* 35: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 40: pointer.struct.stack_st_X509_NAME_ENTRY */
            	45, 0,
            0, 32, 2, /* 45: struct.stack_st_fake_X509_NAME_ENTRY */
            	52, 8,
            	113, 24,
            8884099, 8, 2, /* 52: pointer_to_array_of_pointers_to_stack */
            	59, 0,
            	110, 20,
            0, 8, 1, /* 59: pointer.X509_NAME_ENTRY */
            	64, 0,
            0, 0, 1, /* 64: X509_NAME_ENTRY */
            	69, 0,
            0, 24, 2, /* 69: struct.X509_name_entry_st */
            	76, 0,
            	100, 8,
            1, 8, 1, /* 76: pointer.struct.asn1_object_st */
            	81, 0,
            0, 40, 3, /* 81: struct.asn1_object_st */
            	90, 0,
            	90, 8,
            	95, 24,
            1, 8, 1, /* 90: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 95: pointer.unsigned char */
            	22, 0,
            1, 8, 1, /* 100: pointer.struct.asn1_string_st */
            	105, 0,
            0, 24, 1, /* 105: struct.asn1_string_st */
            	17, 8,
            0, 4, 0, /* 110: int */
            8884097, 8, 0, /* 113: pointer.func */
            1, 8, 1, /* 116: pointer.struct.X509_name_st */
            	121, 0,
            0, 40, 3, /* 121: struct.X509_name_st */
            	40, 0,
            	130, 16,
            	17, 24,
            1, 8, 1, /* 130: pointer.struct.buf_mem_st */
            	30, 0,
            1, 8, 1, /* 135: pointer.struct.asn1_string_st */
            	12, 0,
            1, 8, 1, /* 140: pointer.struct.asn1_string_st */
            	12, 0,
            1, 8, 1, /* 145: pointer.struct.asn1_string_st */
            	12, 0,
            1, 8, 1, /* 150: pointer.struct.asn1_string_st */
            	12, 0,
            0, 8, 20, /* 155: union.unknown */
            	35, 0,
            	7, 0,
            	198, 0,
            	212, 0,
            	217, 0,
            	222, 0,
            	150, 0,
            	227, 0,
            	232, 0,
            	237, 0,
            	145, 0,
            	140, 0,
            	242, 0,
            	247, 0,
            	135, 0,
            	252, 0,
            	257, 0,
            	7, 0,
            	7, 0,
            	262, 0,
            1, 8, 1, /* 198: pointer.struct.asn1_object_st */
            	203, 0,
            0, 40, 3, /* 203: struct.asn1_object_st */
            	90, 0,
            	90, 8,
            	95, 24,
            1, 8, 1, /* 212: pointer.struct.asn1_string_st */
            	12, 0,
            1, 8, 1, /* 217: pointer.struct.asn1_string_st */
            	12, 0,
            1, 8, 1, /* 222: pointer.struct.asn1_string_st */
            	12, 0,
            1, 8, 1, /* 227: pointer.struct.asn1_string_st */
            	12, 0,
            1, 8, 1, /* 232: pointer.struct.asn1_string_st */
            	12, 0,
            1, 8, 1, /* 237: pointer.struct.asn1_string_st */
            	12, 0,
            1, 8, 1, /* 242: pointer.struct.asn1_string_st */
            	12, 0,
            1, 8, 1, /* 247: pointer.struct.asn1_string_st */
            	12, 0,
            1, 8, 1, /* 252: pointer.struct.asn1_string_st */
            	12, 0,
            1, 8, 1, /* 257: pointer.struct.asn1_string_st */
            	12, 0,
            1, 8, 1, /* 262: pointer.struct.ASN1_VALUE_st */
            	267, 0,
            0, 0, 0, /* 267: struct.ASN1_VALUE_st */
            0, 16, 1, /* 270: struct.asn1_type_st */
            	155, 8,
            0, 16, 1, /* 275: struct.GENERAL_NAME_st */
            	280, 8,
            0, 8, 15, /* 280: union.unknown */
            	35, 0,
            	313, 0,
            	237, 0,
            	237, 0,
            	325, 0,
            	116, 0,
            	25, 0,
            	237, 0,
            	150, 0,
            	198, 0,
            	150, 0,
            	116, 0,
            	237, 0,
            	198, 0,
            	325, 0,
            1, 8, 1, /* 313: pointer.struct.otherName_st */
            	318, 0,
            0, 16, 2, /* 318: struct.otherName_st */
            	198, 0,
            	325, 8,
            1, 8, 1, /* 325: pointer.struct.asn1_type_st */
            	270, 0,
            1, 8, 1, /* 330: pointer.struct.asn1_string_st */
            	335, 0,
            0, 24, 1, /* 335: struct.asn1_string_st */
            	17, 8,
            0, 0, 1, /* 340: GENERAL_SUBTREE */
            	345, 0,
            0, 24, 3, /* 345: struct.GENERAL_SUBTREE_st */
            	354, 0,
            	212, 8,
            	212, 16,
            1, 8, 1, /* 354: pointer.struct.GENERAL_NAME_st */
            	275, 0,
            1, 8, 1, /* 359: pointer.struct.NAME_CONSTRAINTS_st */
            	364, 0,
            0, 16, 2, /* 364: struct.NAME_CONSTRAINTS_st */
            	371, 0,
            	371, 8,
            1, 8, 1, /* 371: pointer.struct.stack_st_GENERAL_SUBTREE */
            	376, 0,
            0, 32, 2, /* 376: struct.stack_st_fake_GENERAL_SUBTREE */
            	383, 8,
            	113, 24,
            8884099, 8, 2, /* 383: pointer_to_array_of_pointers_to_stack */
            	390, 0,
            	110, 20,
            0, 8, 1, /* 390: pointer.GENERAL_SUBTREE */
            	340, 0,
            1, 8, 1, /* 395: pointer.struct.stack_st_GENERAL_NAME */
            	400, 0,
            0, 32, 2, /* 400: struct.stack_st_fake_GENERAL_NAME */
            	407, 8,
            	113, 24,
            8884099, 8, 2, /* 407: pointer_to_array_of_pointers_to_stack */
            	414, 0,
            	110, 20,
            0, 8, 1, /* 414: pointer.GENERAL_NAME */
            	419, 0,
            0, 0, 1, /* 419: GENERAL_NAME */
            	424, 0,
            0, 16, 1, /* 424: struct.GENERAL_NAME_st */
            	429, 8,
            0, 8, 15, /* 429: union.unknown */
            	35, 0,
            	462, 0,
            	581, 0,
            	581, 0,
            	488, 0,
            	629, 0,
            	677, 0,
            	581, 0,
            	566, 0,
            	474, 0,
            	566, 0,
            	629, 0,
            	581, 0,
            	474, 0,
            	488, 0,
            1, 8, 1, /* 462: pointer.struct.otherName_st */
            	467, 0,
            0, 16, 2, /* 467: struct.otherName_st */
            	474, 0,
            	488, 8,
            1, 8, 1, /* 474: pointer.struct.asn1_object_st */
            	479, 0,
            0, 40, 3, /* 479: struct.asn1_object_st */
            	90, 0,
            	90, 8,
            	95, 24,
            1, 8, 1, /* 488: pointer.struct.asn1_type_st */
            	493, 0,
            0, 16, 1, /* 493: struct.asn1_type_st */
            	498, 8,
            0, 8, 20, /* 498: union.unknown */
            	35, 0,
            	541, 0,
            	474, 0,
            	551, 0,
            	556, 0,
            	561, 0,
            	566, 0,
            	571, 0,
            	576, 0,
            	581, 0,
            	586, 0,
            	591, 0,
            	596, 0,
            	601, 0,
            	606, 0,
            	611, 0,
            	616, 0,
            	541, 0,
            	541, 0,
            	621, 0,
            1, 8, 1, /* 541: pointer.struct.asn1_string_st */
            	546, 0,
            0, 24, 1, /* 546: struct.asn1_string_st */
            	17, 8,
            1, 8, 1, /* 551: pointer.struct.asn1_string_st */
            	546, 0,
            1, 8, 1, /* 556: pointer.struct.asn1_string_st */
            	546, 0,
            1, 8, 1, /* 561: pointer.struct.asn1_string_st */
            	546, 0,
            1, 8, 1, /* 566: pointer.struct.asn1_string_st */
            	546, 0,
            1, 8, 1, /* 571: pointer.struct.asn1_string_st */
            	546, 0,
            1, 8, 1, /* 576: pointer.struct.asn1_string_st */
            	546, 0,
            1, 8, 1, /* 581: pointer.struct.asn1_string_st */
            	546, 0,
            1, 8, 1, /* 586: pointer.struct.asn1_string_st */
            	546, 0,
            1, 8, 1, /* 591: pointer.struct.asn1_string_st */
            	546, 0,
            1, 8, 1, /* 596: pointer.struct.asn1_string_st */
            	546, 0,
            1, 8, 1, /* 601: pointer.struct.asn1_string_st */
            	546, 0,
            1, 8, 1, /* 606: pointer.struct.asn1_string_st */
            	546, 0,
            1, 8, 1, /* 611: pointer.struct.asn1_string_st */
            	546, 0,
            1, 8, 1, /* 616: pointer.struct.asn1_string_st */
            	546, 0,
            1, 8, 1, /* 621: pointer.struct.ASN1_VALUE_st */
            	626, 0,
            0, 0, 0, /* 626: struct.ASN1_VALUE_st */
            1, 8, 1, /* 629: pointer.struct.X509_name_st */
            	634, 0,
            0, 40, 3, /* 634: struct.X509_name_st */
            	643, 0,
            	667, 16,
            	17, 24,
            1, 8, 1, /* 643: pointer.struct.stack_st_X509_NAME_ENTRY */
            	648, 0,
            0, 32, 2, /* 648: struct.stack_st_fake_X509_NAME_ENTRY */
            	655, 8,
            	113, 24,
            8884099, 8, 2, /* 655: pointer_to_array_of_pointers_to_stack */
            	662, 0,
            	110, 20,
            0, 8, 1, /* 662: pointer.X509_NAME_ENTRY */
            	64, 0,
            1, 8, 1, /* 667: pointer.struct.buf_mem_st */
            	672, 0,
            0, 24, 1, /* 672: struct.buf_mem_st */
            	35, 8,
            1, 8, 1, /* 677: pointer.struct.EDIPartyName_st */
            	682, 0,
            0, 16, 2, /* 682: struct.EDIPartyName_st */
            	541, 0,
            	541, 8,
            0, 24, 1, /* 689: struct.asn1_string_st */
            	17, 8,
            1, 8, 1, /* 694: pointer.struct.buf_mem_st */
            	699, 0,
            0, 24, 1, /* 699: struct.buf_mem_st */
            	35, 8,
            0, 40, 3, /* 704: struct.X509_name_st */
            	713, 0,
            	694, 16,
            	17, 24,
            1, 8, 1, /* 713: pointer.struct.stack_st_X509_NAME_ENTRY */
            	718, 0,
            0, 32, 2, /* 718: struct.stack_st_fake_X509_NAME_ENTRY */
            	725, 8,
            	113, 24,
            8884099, 8, 2, /* 725: pointer_to_array_of_pointers_to_stack */
            	732, 0,
            	110, 20,
            0, 8, 1, /* 732: pointer.X509_NAME_ENTRY */
            	64, 0,
            1, 8, 1, /* 737: pointer.struct.stack_st_DIST_POINT */
            	742, 0,
            0, 32, 2, /* 742: struct.stack_st_fake_DIST_POINT */
            	749, 8,
            	113, 24,
            8884099, 8, 2, /* 749: pointer_to_array_of_pointers_to_stack */
            	756, 0,
            	110, 20,
            0, 8, 1, /* 756: pointer.DIST_POINT */
            	761, 0,
            0, 0, 1, /* 761: DIST_POINT */
            	766, 0,
            0, 32, 3, /* 766: struct.DIST_POINT_st */
            	775, 0,
            	823, 8,
            	794, 16,
            1, 8, 1, /* 775: pointer.struct.DIST_POINT_NAME_st */
            	780, 0,
            0, 24, 2, /* 780: struct.DIST_POINT_NAME_st */
            	787, 8,
            	818, 16,
            0, 8, 2, /* 787: union.unknown */
            	794, 0,
            	713, 0,
            1, 8, 1, /* 794: pointer.struct.stack_st_GENERAL_NAME */
            	799, 0,
            0, 32, 2, /* 799: struct.stack_st_fake_GENERAL_NAME */
            	806, 8,
            	113, 24,
            8884099, 8, 2, /* 806: pointer_to_array_of_pointers_to_stack */
            	813, 0,
            	110, 20,
            0, 8, 1, /* 813: pointer.GENERAL_NAME */
            	419, 0,
            1, 8, 1, /* 818: pointer.struct.X509_name_st */
            	704, 0,
            1, 8, 1, /* 823: pointer.struct.asn1_string_st */
            	689, 0,
            1, 8, 1, /* 828: pointer.struct.stack_st_ASN1_OBJECT */
            	833, 0,
            0, 32, 2, /* 833: struct.stack_st_fake_ASN1_OBJECT */
            	840, 8,
            	113, 24,
            8884099, 8, 2, /* 840: pointer_to_array_of_pointers_to_stack */
            	847, 0,
            	110, 20,
            0, 8, 1, /* 847: pointer.ASN1_OBJECT */
            	852, 0,
            0, 0, 1, /* 852: ASN1_OBJECT */
            	857, 0,
            0, 40, 3, /* 857: struct.asn1_object_st */
            	90, 0,
            	90, 8,
            	95, 24,
            1, 8, 1, /* 866: pointer.struct.stack_st_POLICYQUALINFO */
            	871, 0,
            0, 32, 2, /* 871: struct.stack_st_fake_POLICYQUALINFO */
            	878, 8,
            	113, 24,
            8884099, 8, 2, /* 878: pointer_to_array_of_pointers_to_stack */
            	885, 0,
            	110, 20,
            0, 8, 1, /* 885: pointer.POLICYQUALINFO */
            	890, 0,
            0, 0, 1, /* 890: POLICYQUALINFO */
            	895, 0,
            0, 16, 2, /* 895: struct.POLICYQUALINFO_st */
            	902, 0,
            	916, 8,
            1, 8, 1, /* 902: pointer.struct.asn1_object_st */
            	907, 0,
            0, 40, 3, /* 907: struct.asn1_object_st */
            	90, 0,
            	90, 8,
            	95, 24,
            0, 8, 3, /* 916: union.unknown */
            	925, 0,
            	935, 0,
            	998, 0,
            1, 8, 1, /* 925: pointer.struct.asn1_string_st */
            	930, 0,
            0, 24, 1, /* 930: struct.asn1_string_st */
            	17, 8,
            1, 8, 1, /* 935: pointer.struct.USERNOTICE_st */
            	940, 0,
            0, 16, 2, /* 940: struct.USERNOTICE_st */
            	947, 0,
            	959, 8,
            1, 8, 1, /* 947: pointer.struct.NOTICEREF_st */
            	952, 0,
            0, 16, 2, /* 952: struct.NOTICEREF_st */
            	959, 0,
            	964, 8,
            1, 8, 1, /* 959: pointer.struct.asn1_string_st */
            	930, 0,
            1, 8, 1, /* 964: pointer.struct.stack_st_ASN1_INTEGER */
            	969, 0,
            0, 32, 2, /* 969: struct.stack_st_fake_ASN1_INTEGER */
            	976, 8,
            	113, 24,
            8884099, 8, 2, /* 976: pointer_to_array_of_pointers_to_stack */
            	983, 0,
            	110, 20,
            0, 8, 1, /* 983: pointer.ASN1_INTEGER */
            	988, 0,
            0, 0, 1, /* 988: ASN1_INTEGER */
            	993, 0,
            0, 24, 1, /* 993: struct.asn1_string_st */
            	17, 8,
            1, 8, 1, /* 998: pointer.struct.asn1_type_st */
            	1003, 0,
            0, 16, 1, /* 1003: struct.asn1_type_st */
            	1008, 8,
            0, 8, 20, /* 1008: union.unknown */
            	35, 0,
            	959, 0,
            	902, 0,
            	1051, 0,
            	1056, 0,
            	1061, 0,
            	1066, 0,
            	1071, 0,
            	1076, 0,
            	925, 0,
            	1081, 0,
            	1086, 0,
            	1091, 0,
            	1096, 0,
            	1101, 0,
            	1106, 0,
            	1111, 0,
            	959, 0,
            	959, 0,
            	262, 0,
            1, 8, 1, /* 1051: pointer.struct.asn1_string_st */
            	930, 0,
            1, 8, 1, /* 1056: pointer.struct.asn1_string_st */
            	930, 0,
            1, 8, 1, /* 1061: pointer.struct.asn1_string_st */
            	930, 0,
            1, 8, 1, /* 1066: pointer.struct.asn1_string_st */
            	930, 0,
            1, 8, 1, /* 1071: pointer.struct.asn1_string_st */
            	930, 0,
            1, 8, 1, /* 1076: pointer.struct.asn1_string_st */
            	930, 0,
            1, 8, 1, /* 1081: pointer.struct.asn1_string_st */
            	930, 0,
            1, 8, 1, /* 1086: pointer.struct.asn1_string_st */
            	930, 0,
            1, 8, 1, /* 1091: pointer.struct.asn1_string_st */
            	930, 0,
            1, 8, 1, /* 1096: pointer.struct.asn1_string_st */
            	930, 0,
            1, 8, 1, /* 1101: pointer.struct.asn1_string_st */
            	930, 0,
            1, 8, 1, /* 1106: pointer.struct.asn1_string_st */
            	930, 0,
            1, 8, 1, /* 1111: pointer.struct.asn1_string_st */
            	930, 0,
            1, 8, 1, /* 1116: pointer.struct.asn1_object_st */
            	1121, 0,
            0, 40, 3, /* 1121: struct.asn1_object_st */
            	90, 0,
            	90, 8,
            	95, 24,
            1, 8, 1, /* 1130: pointer.struct.stack_st_X509_POLICY_DATA */
            	1135, 0,
            0, 32, 2, /* 1135: struct.stack_st_fake_X509_POLICY_DATA */
            	1142, 8,
            	113, 24,
            8884099, 8, 2, /* 1142: pointer_to_array_of_pointers_to_stack */
            	1149, 0,
            	110, 20,
            0, 8, 1, /* 1149: pointer.X509_POLICY_DATA */
            	1154, 0,
            0, 0, 1, /* 1154: X509_POLICY_DATA */
            	1159, 0,
            0, 32, 3, /* 1159: struct.X509_POLICY_DATA_st */
            	1116, 8,
            	866, 16,
            	828, 24,
            0, 32, 3, /* 1168: struct.X509_POLICY_DATA_st */
            	1177, 8,
            	1191, 16,
            	1215, 24,
            1, 8, 1, /* 1177: pointer.struct.asn1_object_st */
            	1182, 0,
            0, 40, 3, /* 1182: struct.asn1_object_st */
            	90, 0,
            	90, 8,
            	95, 24,
            1, 8, 1, /* 1191: pointer.struct.stack_st_POLICYQUALINFO */
            	1196, 0,
            0, 32, 2, /* 1196: struct.stack_st_fake_POLICYQUALINFO */
            	1203, 8,
            	113, 24,
            8884099, 8, 2, /* 1203: pointer_to_array_of_pointers_to_stack */
            	1210, 0,
            	110, 20,
            0, 8, 1, /* 1210: pointer.POLICYQUALINFO */
            	890, 0,
            1, 8, 1, /* 1215: pointer.struct.stack_st_ASN1_OBJECT */
            	1220, 0,
            0, 32, 2, /* 1220: struct.stack_st_fake_ASN1_OBJECT */
            	1227, 8,
            	113, 24,
            8884099, 8, 2, /* 1227: pointer_to_array_of_pointers_to_stack */
            	1234, 0,
            	110, 20,
            0, 8, 1, /* 1234: pointer.ASN1_OBJECT */
            	852, 0,
            0, 40, 2, /* 1239: struct.X509_POLICY_CACHE_st */
            	1246, 0,
            	1130, 8,
            1, 8, 1, /* 1246: pointer.struct.X509_POLICY_DATA_st */
            	1168, 0,
            1, 8, 1, /* 1251: pointer.struct.asn1_string_st */
            	1256, 0,
            0, 24, 1, /* 1256: struct.asn1_string_st */
            	17, 8,
            1, 8, 1, /* 1261: pointer.struct.stack_st_GENERAL_NAME */
            	1266, 0,
            0, 32, 2, /* 1266: struct.stack_st_fake_GENERAL_NAME */
            	1273, 8,
            	113, 24,
            8884099, 8, 2, /* 1273: pointer_to_array_of_pointers_to_stack */
            	1280, 0,
            	110, 20,
            0, 8, 1, /* 1280: pointer.GENERAL_NAME */
            	419, 0,
            1, 8, 1, /* 1285: pointer.struct.asn1_string_st */
            	1256, 0,
            0, 40, 3, /* 1290: struct.asn1_object_st */
            	90, 0,
            	90, 8,
            	95, 24,
            0, 24, 2, /* 1299: struct.X509_extension_st */
            	1306, 0,
            	1311, 16,
            1, 8, 1, /* 1306: pointer.struct.asn1_object_st */
            	1290, 0,
            1, 8, 1, /* 1311: pointer.struct.asn1_string_st */
            	1316, 0,
            0, 24, 1, /* 1316: struct.asn1_string_st */
            	17, 8,
            0, 0, 1, /* 1321: X509_EXTENSION */
            	1299, 0,
            1, 8, 1, /* 1326: pointer.struct.asn1_string_st */
            	335, 0,
            1, 8, 1, /* 1331: pointer.struct.ASN1_VALUE_st */
            	1336, 0,
            0, 0, 0, /* 1336: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1339: pointer.struct.asn1_string_st */
            	1344, 0,
            0, 24, 1, /* 1344: struct.asn1_string_st */
            	17, 8,
            1, 8, 1, /* 1349: pointer.struct.asn1_string_st */
            	1344, 0,
            1, 8, 1, /* 1354: pointer.struct.asn1_string_st */
            	1344, 0,
            1, 8, 1, /* 1359: pointer.struct.asn1_string_st */
            	1344, 0,
            1, 8, 1, /* 1364: pointer.struct.asn1_string_st */
            	1344, 0,
            1, 8, 1, /* 1369: pointer.struct.asn1_string_st */
            	1344, 0,
            1, 8, 1, /* 1374: pointer.struct.asn1_string_st */
            	1344, 0,
            1, 8, 1, /* 1379: pointer.struct.asn1_string_st */
            	1344, 0,
            1, 8, 1, /* 1384: pointer.struct.asn1_string_st */
            	1344, 0,
            1, 8, 1, /* 1389: pointer.struct.asn1_string_st */
            	1344, 0,
            1, 8, 1, /* 1394: pointer.struct.asn1_string_st */
            	1344, 0,
            1, 8, 1, /* 1399: pointer.struct.asn1_string_st */
            	1344, 0,
            0, 16, 1, /* 1404: struct.asn1_type_st */
            	1409, 8,
            0, 8, 20, /* 1409: union.unknown */
            	35, 0,
            	1399, 0,
            	1452, 0,
            	1466, 0,
            	1394, 0,
            	1389, 0,
            	1384, 0,
            	1379, 0,
            	1374, 0,
            	1369, 0,
            	1364, 0,
            	1359, 0,
            	1471, 0,
            	1354, 0,
            	1349, 0,
            	1476, 0,
            	1339, 0,
            	1399, 0,
            	1399, 0,
            	1331, 0,
            1, 8, 1, /* 1452: pointer.struct.asn1_object_st */
            	1457, 0,
            0, 40, 3, /* 1457: struct.asn1_object_st */
            	90, 0,
            	90, 8,
            	95, 24,
            1, 8, 1, /* 1466: pointer.struct.asn1_string_st */
            	1344, 0,
            1, 8, 1, /* 1471: pointer.struct.asn1_string_st */
            	1344, 0,
            1, 8, 1, /* 1476: pointer.struct.asn1_string_st */
            	1344, 0,
            1, 8, 1, /* 1481: pointer.struct.ASN1_VALUE_st */
            	1486, 0,
            0, 0, 0, /* 1486: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1489: pointer.struct.asn1_string_st */
            	1494, 0,
            0, 24, 1, /* 1494: struct.asn1_string_st */
            	17, 8,
            1, 8, 1, /* 1499: pointer.struct.asn1_string_st */
            	1494, 0,
            1, 8, 1, /* 1504: pointer.struct.asn1_string_st */
            	1494, 0,
            1, 8, 1, /* 1509: pointer.struct.asn1_string_st */
            	1494, 0,
            1, 8, 1, /* 1514: pointer.struct.asn1_string_st */
            	1494, 0,
            1, 8, 1, /* 1519: pointer.struct.asn1_string_st */
            	1494, 0,
            1, 8, 1, /* 1524: pointer.struct.asn1_string_st */
            	1494, 0,
            1, 8, 1, /* 1529: pointer.struct.asn1_string_st */
            	1494, 0,
            1, 8, 1, /* 1534: pointer.struct.asn1_string_st */
            	1494, 0,
            0, 40, 3, /* 1539: struct.asn1_object_st */
            	90, 0,
            	90, 8,
            	95, 24,
            1, 8, 1, /* 1548: pointer.struct.asn1_object_st */
            	1539, 0,
            1, 8, 1, /* 1553: pointer.struct.asn1_string_st */
            	1494, 0,
            0, 8, 20, /* 1558: union.unknown */
            	35, 0,
            	1553, 0,
            	1548, 0,
            	1534, 0,
            	1529, 0,
            	1601, 0,
            	1524, 0,
            	1606, 0,
            	1611, 0,
            	1519, 0,
            	1514, 0,
            	1616, 0,
            	1509, 0,
            	1504, 0,
            	1499, 0,
            	1621, 0,
            	1489, 0,
            	1553, 0,
            	1553, 0,
            	1481, 0,
            1, 8, 1, /* 1601: pointer.struct.asn1_string_st */
            	1494, 0,
            1, 8, 1, /* 1606: pointer.struct.asn1_string_st */
            	1494, 0,
            1, 8, 1, /* 1611: pointer.struct.asn1_string_st */
            	1494, 0,
            1, 8, 1, /* 1616: pointer.struct.asn1_string_st */
            	1494, 0,
            1, 8, 1, /* 1621: pointer.struct.asn1_string_st */
            	1494, 0,
            0, 16, 1, /* 1626: struct.asn1_type_st */
            	1558, 8,
            0, 0, 1, /* 1631: ASN1_TYPE */
            	1626, 0,
            1, 8, 1, /* 1636: pointer.struct.stack_st_ASN1_TYPE */
            	1641, 0,
            0, 32, 2, /* 1641: struct.stack_st_fake_ASN1_TYPE */
            	1648, 8,
            	113, 24,
            8884099, 8, 2, /* 1648: pointer_to_array_of_pointers_to_stack */
            	1655, 0,
            	110, 20,
            0, 8, 1, /* 1655: pointer.ASN1_TYPE */
            	1631, 0,
            0, 8, 3, /* 1660: union.unknown */
            	35, 0,
            	1636, 0,
            	1669, 0,
            1, 8, 1, /* 1669: pointer.struct.asn1_type_st */
            	1404, 0,
            0, 24, 2, /* 1674: struct.x509_attributes_st */
            	1452, 0,
            	1660, 16,
            1, 8, 1, /* 1681: pointer.struct.stack_st_X509_ATTRIBUTE */
            	1686, 0,
            0, 32, 2, /* 1686: struct.stack_st_fake_X509_ATTRIBUTE */
            	1693, 8,
            	113, 24,
            8884099, 8, 2, /* 1693: pointer_to_array_of_pointers_to_stack */
            	1700, 0,
            	110, 20,
            0, 8, 1, /* 1700: pointer.X509_ATTRIBUTE */
            	1705, 0,
            0, 0, 1, /* 1705: X509_ATTRIBUTE */
            	1674, 0,
            1, 8, 1, /* 1710: pointer.struct.stack_st_X509_ALGOR */
            	1715, 0,
            0, 32, 2, /* 1715: struct.stack_st_fake_X509_ALGOR */
            	1722, 8,
            	113, 24,
            8884099, 8, 2, /* 1722: pointer_to_array_of_pointers_to_stack */
            	1729, 0,
            	110, 20,
            0, 8, 1, /* 1729: pointer.X509_ALGOR */
            	1734, 0,
            0, 0, 1, /* 1734: X509_ALGOR */
            	1739, 0,
            0, 16, 2, /* 1739: struct.X509_algor_st */
            	1746, 0,
            	1760, 8,
            1, 8, 1, /* 1746: pointer.struct.asn1_object_st */
            	1751, 0,
            0, 40, 3, /* 1751: struct.asn1_object_st */
            	90, 0,
            	90, 8,
            	95, 24,
            1, 8, 1, /* 1760: pointer.struct.asn1_type_st */
            	1765, 0,
            0, 16, 1, /* 1765: struct.asn1_type_st */
            	1770, 8,
            0, 8, 20, /* 1770: union.unknown */
            	35, 0,
            	1813, 0,
            	1746, 0,
            	1823, 0,
            	1828, 0,
            	1833, 0,
            	1838, 0,
            	1843, 0,
            	1848, 0,
            	1853, 0,
            	1858, 0,
            	1863, 0,
            	1868, 0,
            	1873, 0,
            	1878, 0,
            	1883, 0,
            	1888, 0,
            	1813, 0,
            	1813, 0,
            	1893, 0,
            1, 8, 1, /* 1813: pointer.struct.asn1_string_st */
            	1818, 0,
            0, 24, 1, /* 1818: struct.asn1_string_st */
            	17, 8,
            1, 8, 1, /* 1823: pointer.struct.asn1_string_st */
            	1818, 0,
            1, 8, 1, /* 1828: pointer.struct.asn1_string_st */
            	1818, 0,
            1, 8, 1, /* 1833: pointer.struct.asn1_string_st */
            	1818, 0,
            1, 8, 1, /* 1838: pointer.struct.asn1_string_st */
            	1818, 0,
            1, 8, 1, /* 1843: pointer.struct.asn1_string_st */
            	1818, 0,
            1, 8, 1, /* 1848: pointer.struct.asn1_string_st */
            	1818, 0,
            1, 8, 1, /* 1853: pointer.struct.asn1_string_st */
            	1818, 0,
            1, 8, 1, /* 1858: pointer.struct.asn1_string_st */
            	1818, 0,
            1, 8, 1, /* 1863: pointer.struct.asn1_string_st */
            	1818, 0,
            1, 8, 1, /* 1868: pointer.struct.asn1_string_st */
            	1818, 0,
            1, 8, 1, /* 1873: pointer.struct.asn1_string_st */
            	1818, 0,
            1, 8, 1, /* 1878: pointer.struct.asn1_string_st */
            	1818, 0,
            1, 8, 1, /* 1883: pointer.struct.asn1_string_st */
            	1818, 0,
            1, 8, 1, /* 1888: pointer.struct.asn1_string_st */
            	1818, 0,
            1, 8, 1, /* 1893: pointer.struct.ASN1_VALUE_st */
            	1898, 0,
            0, 0, 0, /* 1898: struct.ASN1_VALUE_st */
            0, 24, 1, /* 1901: struct.bignum_st */
            	1906, 0,
            1, 8, 1, /* 1906: pointer.unsigned int */
            	1911, 0,
            0, 4, 0, /* 1911: unsigned int */
            1, 8, 1, /* 1914: pointer.struct.ec_point_st */
            	1919, 0,
            0, 88, 4, /* 1919: struct.ec_point_st */
            	1930, 0,
            	2102, 8,
            	2102, 32,
            	2102, 56,
            1, 8, 1, /* 1930: pointer.struct.ec_method_st */
            	1935, 0,
            0, 304, 37, /* 1935: struct.ec_method_st */
            	2012, 8,
            	2015, 16,
            	2015, 24,
            	2018, 32,
            	2021, 40,
            	2024, 48,
            	2027, 56,
            	2030, 64,
            	2033, 72,
            	2036, 80,
            	2036, 88,
            	2039, 96,
            	2042, 104,
            	2045, 112,
            	2048, 120,
            	2051, 128,
            	2054, 136,
            	2057, 144,
            	2060, 152,
            	2063, 160,
            	2066, 168,
            	2069, 176,
            	2072, 184,
            	2075, 192,
            	2078, 200,
            	2081, 208,
            	2072, 216,
            	2084, 224,
            	2087, 232,
            	2090, 240,
            	2027, 248,
            	2093, 256,
            	2096, 264,
            	2093, 272,
            	2096, 280,
            	2096, 288,
            	2099, 296,
            8884097, 8, 0, /* 2012: pointer.func */
            8884097, 8, 0, /* 2015: pointer.func */
            8884097, 8, 0, /* 2018: pointer.func */
            8884097, 8, 0, /* 2021: pointer.func */
            8884097, 8, 0, /* 2024: pointer.func */
            8884097, 8, 0, /* 2027: pointer.func */
            8884097, 8, 0, /* 2030: pointer.func */
            8884097, 8, 0, /* 2033: pointer.func */
            8884097, 8, 0, /* 2036: pointer.func */
            8884097, 8, 0, /* 2039: pointer.func */
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
            0, 24, 1, /* 2102: struct.bignum_st */
            	1906, 0,
            8884097, 8, 0, /* 2107: pointer.func */
            8884097, 8, 0, /* 2110: pointer.func */
            1, 8, 1, /* 2113: pointer.struct.ec_extra_data_st */
            	2118, 0,
            0, 40, 5, /* 2118: struct.ec_extra_data_st */
            	2131, 0,
            	2136, 8,
            	2110, 16,
            	2139, 24,
            	2139, 32,
            1, 8, 1, /* 2131: pointer.struct.ec_extra_data_st */
            	2118, 0,
            0, 8, 0, /* 2136: pointer.void */
            8884097, 8, 0, /* 2139: pointer.func */
            0, 24, 1, /* 2142: struct.bignum_st */
            	1906, 0,
            1, 8, 1, /* 2147: pointer.struct.ec_extra_data_st */
            	2152, 0,
            0, 40, 5, /* 2152: struct.ec_extra_data_st */
            	2147, 0,
            	2136, 8,
            	2110, 16,
            	2139, 24,
            	2139, 32,
            1, 8, 1, /* 2165: pointer.struct.stack_st_void */
            	2170, 0,
            0, 32, 1, /* 2170: struct.stack_st_void */
            	2175, 0,
            0, 32, 2, /* 2175: struct.stack_st */
            	2182, 8,
            	113, 24,
            1, 8, 1, /* 2182: pointer.pointer.char */
            	35, 0,
            8884097, 8, 0, /* 2187: pointer.func */
            1, 8, 1, /* 2190: pointer.struct.X509_val_st */
            	2195, 0,
            0, 16, 2, /* 2195: struct.X509_val_st */
            	2202, 0,
            	2202, 8,
            1, 8, 1, /* 2202: pointer.struct.asn1_string_st */
            	335, 0,
            8884097, 8, 0, /* 2207: pointer.func */
            8884097, 8, 0, /* 2210: pointer.func */
            8884097, 8, 0, /* 2213: pointer.func */
            8884097, 8, 0, /* 2216: pointer.func */
            8884097, 8, 0, /* 2219: pointer.func */
            0, 8, 5, /* 2222: union.unknown */
            	35, 0,
            	2235, 0,
            	2751, 0,
            	2880, 0,
            	2994, 0,
            1, 8, 1, /* 2235: pointer.struct.rsa_st */
            	2240, 0,
            0, 168, 17, /* 2240: struct.rsa_st */
            	2277, 16,
            	2332, 24,
            	2651, 32,
            	2651, 40,
            	2651, 48,
            	2651, 56,
            	2651, 64,
            	2651, 72,
            	2651, 80,
            	2651, 88,
            	2661, 96,
            	2683, 120,
            	2683, 128,
            	2683, 136,
            	35, 144,
            	2697, 152,
            	2697, 160,
            1, 8, 1, /* 2277: pointer.struct.rsa_meth_st */
            	2282, 0,
            0, 112, 13, /* 2282: struct.rsa_meth_st */
            	90, 0,
            	2311, 8,
            	2311, 16,
            	2311, 24,
            	2311, 32,
            	2314, 40,
            	2317, 48,
            	2320, 56,
            	2320, 64,
            	35, 80,
            	2323, 88,
            	2326, 96,
            	2329, 104,
            8884097, 8, 0, /* 2311: pointer.func */
            8884097, 8, 0, /* 2314: pointer.func */
            8884097, 8, 0, /* 2317: pointer.func */
            8884097, 8, 0, /* 2320: pointer.func */
            8884097, 8, 0, /* 2323: pointer.func */
            8884097, 8, 0, /* 2326: pointer.func */
            8884097, 8, 0, /* 2329: pointer.func */
            1, 8, 1, /* 2332: pointer.struct.engine_st */
            	2337, 0,
            0, 216, 24, /* 2337: struct.engine_st */
            	90, 0,
            	90, 8,
            	2388, 16,
            	2443, 24,
            	2494, 32,
            	2530, 40,
            	2547, 48,
            	2571, 56,
            	2597, 64,
            	2605, 72,
            	2608, 80,
            	2611, 88,
            	2614, 96,
            	2617, 104,
            	2617, 112,
            	2617, 120,
            	2620, 128,
            	2623, 136,
            	2623, 144,
            	2626, 152,
            	2629, 160,
            	2641, 184,
            	2646, 200,
            	2646, 208,
            1, 8, 1, /* 2388: pointer.struct.rsa_meth_st */
            	2393, 0,
            0, 112, 13, /* 2393: struct.rsa_meth_st */
            	90, 0,
            	2422, 8,
            	2422, 16,
            	2422, 24,
            	2422, 32,
            	2425, 40,
            	2428, 48,
            	2431, 56,
            	2431, 64,
            	35, 80,
            	2434, 88,
            	2437, 96,
            	2440, 104,
            8884097, 8, 0, /* 2422: pointer.func */
            8884097, 8, 0, /* 2425: pointer.func */
            8884097, 8, 0, /* 2428: pointer.func */
            8884097, 8, 0, /* 2431: pointer.func */
            8884097, 8, 0, /* 2434: pointer.func */
            8884097, 8, 0, /* 2437: pointer.func */
            8884097, 8, 0, /* 2440: pointer.func */
            1, 8, 1, /* 2443: pointer.struct.dsa_method */
            	2448, 0,
            0, 96, 11, /* 2448: struct.dsa_method */
            	90, 0,
            	2473, 8,
            	2476, 16,
            	2479, 24,
            	2482, 32,
            	2485, 40,
            	2488, 48,
            	2488, 56,
            	35, 72,
            	2491, 80,
            	2488, 88,
            8884097, 8, 0, /* 2473: pointer.func */
            8884097, 8, 0, /* 2476: pointer.func */
            8884097, 8, 0, /* 2479: pointer.func */
            8884097, 8, 0, /* 2482: pointer.func */
            8884097, 8, 0, /* 2485: pointer.func */
            8884097, 8, 0, /* 2488: pointer.func */
            8884097, 8, 0, /* 2491: pointer.func */
            1, 8, 1, /* 2494: pointer.struct.dh_method */
            	2499, 0,
            0, 72, 8, /* 2499: struct.dh_method */
            	90, 0,
            	2518, 8,
            	2521, 16,
            	2524, 24,
            	2518, 32,
            	2518, 40,
            	35, 56,
            	2527, 64,
            8884097, 8, 0, /* 2518: pointer.func */
            8884097, 8, 0, /* 2521: pointer.func */
            8884097, 8, 0, /* 2524: pointer.func */
            8884097, 8, 0, /* 2527: pointer.func */
            1, 8, 1, /* 2530: pointer.struct.ecdh_method */
            	2535, 0,
            0, 32, 3, /* 2535: struct.ecdh_method */
            	90, 0,
            	2544, 8,
            	35, 24,
            8884097, 8, 0, /* 2544: pointer.func */
            1, 8, 1, /* 2547: pointer.struct.ecdsa_method */
            	2552, 0,
            0, 48, 5, /* 2552: struct.ecdsa_method */
            	90, 0,
            	2565, 8,
            	2219, 16,
            	2568, 24,
            	35, 40,
            8884097, 8, 0, /* 2565: pointer.func */
            8884097, 8, 0, /* 2568: pointer.func */
            1, 8, 1, /* 2571: pointer.struct.rand_meth_st */
            	2576, 0,
            0, 48, 6, /* 2576: struct.rand_meth_st */
            	2216, 0,
            	2591, 8,
            	2213, 16,
            	2187, 24,
            	2591, 32,
            	2594, 40,
            8884097, 8, 0, /* 2591: pointer.func */
            8884097, 8, 0, /* 2594: pointer.func */
            1, 8, 1, /* 2597: pointer.struct.store_method_st */
            	2602, 0,
            0, 0, 0, /* 2602: struct.store_method_st */
            8884097, 8, 0, /* 2605: pointer.func */
            8884097, 8, 0, /* 2608: pointer.func */
            8884097, 8, 0, /* 2611: pointer.func */
            8884097, 8, 0, /* 2614: pointer.func */
            8884097, 8, 0, /* 2617: pointer.func */
            8884097, 8, 0, /* 2620: pointer.func */
            8884097, 8, 0, /* 2623: pointer.func */
            8884097, 8, 0, /* 2626: pointer.func */
            1, 8, 1, /* 2629: pointer.struct.ENGINE_CMD_DEFN_st */
            	2634, 0,
            0, 32, 2, /* 2634: struct.ENGINE_CMD_DEFN_st */
            	90, 8,
            	90, 16,
            0, 16, 1, /* 2641: struct.crypto_ex_data_st */
            	2165, 0,
            1, 8, 1, /* 2646: pointer.struct.engine_st */
            	2337, 0,
            1, 8, 1, /* 2651: pointer.struct.bignum_st */
            	2656, 0,
            0, 24, 1, /* 2656: struct.bignum_st */
            	1906, 0,
            0, 16, 1, /* 2661: struct.crypto_ex_data_st */
            	2666, 0,
            1, 8, 1, /* 2666: pointer.struct.stack_st_void */
            	2671, 0,
            0, 32, 1, /* 2671: struct.stack_st_void */
            	2676, 0,
            0, 32, 2, /* 2676: struct.stack_st */
            	2182, 8,
            	113, 24,
            1, 8, 1, /* 2683: pointer.struct.bn_mont_ctx_st */
            	2688, 0,
            0, 96, 3, /* 2688: struct.bn_mont_ctx_st */
            	2656, 8,
            	2656, 32,
            	2656, 56,
            1, 8, 1, /* 2697: pointer.struct.bn_blinding_st */
            	2702, 0,
            0, 88, 7, /* 2702: struct.bn_blinding_st */
            	2719, 0,
            	2719, 8,
            	2719, 16,
            	2719, 24,
            	2729, 40,
            	2734, 72,
            	2748, 80,
            1, 8, 1, /* 2719: pointer.struct.bignum_st */
            	2724, 0,
            0, 24, 1, /* 2724: struct.bignum_st */
            	1906, 0,
            0, 16, 1, /* 2729: struct.crypto_threadid_st */
            	2136, 0,
            1, 8, 1, /* 2734: pointer.struct.bn_mont_ctx_st */
            	2739, 0,
            0, 96, 3, /* 2739: struct.bn_mont_ctx_st */
            	2724, 8,
            	2724, 32,
            	2724, 56,
            8884097, 8, 0, /* 2748: pointer.func */
            1, 8, 1, /* 2751: pointer.struct.dsa_st */
            	2756, 0,
            0, 136, 11, /* 2756: struct.dsa_st */
            	2781, 24,
            	2781, 32,
            	2781, 40,
            	2781, 48,
            	2781, 56,
            	2781, 64,
            	2781, 72,
            	2791, 88,
            	2805, 104,
            	2827, 120,
            	2875, 128,
            1, 8, 1, /* 2781: pointer.struct.bignum_st */
            	2786, 0,
            0, 24, 1, /* 2786: struct.bignum_st */
            	1906, 0,
            1, 8, 1, /* 2791: pointer.struct.bn_mont_ctx_st */
            	2796, 0,
            0, 96, 3, /* 2796: struct.bn_mont_ctx_st */
            	2786, 8,
            	2786, 32,
            	2786, 56,
            0, 16, 1, /* 2805: struct.crypto_ex_data_st */
            	2810, 0,
            1, 8, 1, /* 2810: pointer.struct.stack_st_void */
            	2815, 0,
            0, 32, 1, /* 2815: struct.stack_st_void */
            	2820, 0,
            0, 32, 2, /* 2820: struct.stack_st */
            	2182, 8,
            	113, 24,
            1, 8, 1, /* 2827: pointer.struct.dsa_method */
            	2832, 0,
            0, 96, 11, /* 2832: struct.dsa_method */
            	90, 0,
            	2857, 8,
            	2210, 16,
            	2860, 24,
            	2863, 32,
            	2866, 40,
            	2869, 48,
            	2869, 56,
            	35, 72,
            	2872, 80,
            	2869, 88,
            8884097, 8, 0, /* 2857: pointer.func */
            8884097, 8, 0, /* 2860: pointer.func */
            8884097, 8, 0, /* 2863: pointer.func */
            8884097, 8, 0, /* 2866: pointer.func */
            8884097, 8, 0, /* 2869: pointer.func */
            8884097, 8, 0, /* 2872: pointer.func */
            1, 8, 1, /* 2875: pointer.struct.engine_st */
            	2337, 0,
            1, 8, 1, /* 2880: pointer.struct.dh_st */
            	2885, 0,
            0, 144, 12, /* 2885: struct.dh_st */
            	2912, 8,
            	2912, 16,
            	2912, 32,
            	2912, 40,
            	2922, 56,
            	2912, 64,
            	2912, 72,
            	17, 80,
            	2912, 96,
            	2936, 112,
            	2958, 128,
            	2332, 136,
            1, 8, 1, /* 2912: pointer.struct.bignum_st */
            	2917, 0,
            0, 24, 1, /* 2917: struct.bignum_st */
            	1906, 0,
            1, 8, 1, /* 2922: pointer.struct.bn_mont_ctx_st */
            	2927, 0,
            0, 96, 3, /* 2927: struct.bn_mont_ctx_st */
            	2917, 8,
            	2917, 32,
            	2917, 56,
            0, 16, 1, /* 2936: struct.crypto_ex_data_st */
            	2941, 0,
            1, 8, 1, /* 2941: pointer.struct.stack_st_void */
            	2946, 0,
            0, 32, 1, /* 2946: struct.stack_st_void */
            	2951, 0,
            0, 32, 2, /* 2951: struct.stack_st */
            	2182, 8,
            	113, 24,
            1, 8, 1, /* 2958: pointer.struct.dh_method */
            	2963, 0,
            0, 72, 8, /* 2963: struct.dh_method */
            	90, 0,
            	2982, 8,
            	2985, 16,
            	2988, 24,
            	2982, 32,
            	2982, 40,
            	35, 56,
            	2991, 64,
            8884097, 8, 0, /* 2982: pointer.func */
            8884097, 8, 0, /* 2985: pointer.func */
            8884097, 8, 0, /* 2988: pointer.func */
            8884097, 8, 0, /* 2991: pointer.func */
            1, 8, 1, /* 2994: pointer.struct.ec_key_st */
            	2999, 0,
            0, 56, 4, /* 2999: struct.ec_key_st */
            	3010, 8,
            	1914, 16,
            	3219, 24,
            	3224, 48,
            1, 8, 1, /* 3010: pointer.struct.ec_group_st */
            	3015, 0,
            0, 232, 12, /* 3015: struct.ec_group_st */
            	3042, 0,
            	3214, 8,
            	2142, 16,
            	2142, 40,
            	17, 80,
            	2113, 96,
            	2142, 104,
            	2142, 152,
            	2142, 176,
            	2136, 208,
            	2136, 216,
            	2107, 224,
            1, 8, 1, /* 3042: pointer.struct.ec_method_st */
            	3047, 0,
            0, 304, 37, /* 3047: struct.ec_method_st */
            	3124, 8,
            	3127, 16,
            	3127, 24,
            	3130, 32,
            	3133, 40,
            	3136, 48,
            	3139, 56,
            	3142, 64,
            	3145, 72,
            	3148, 80,
            	3148, 88,
            	3151, 96,
            	3154, 104,
            	3157, 112,
            	3160, 120,
            	3163, 128,
            	3166, 136,
            	3169, 144,
            	3172, 152,
            	3175, 160,
            	3178, 168,
            	3181, 176,
            	3184, 184,
            	3187, 192,
            	3190, 200,
            	3193, 208,
            	3184, 216,
            	3196, 224,
            	3199, 232,
            	3202, 240,
            	3139, 248,
            	3205, 256,
            	3208, 264,
            	3205, 272,
            	3208, 280,
            	3208, 288,
            	3211, 296,
            8884097, 8, 0, /* 3124: pointer.func */
            8884097, 8, 0, /* 3127: pointer.func */
            8884097, 8, 0, /* 3130: pointer.func */
            8884097, 8, 0, /* 3133: pointer.func */
            8884097, 8, 0, /* 3136: pointer.func */
            8884097, 8, 0, /* 3139: pointer.func */
            8884097, 8, 0, /* 3142: pointer.func */
            8884097, 8, 0, /* 3145: pointer.func */
            8884097, 8, 0, /* 3148: pointer.func */
            8884097, 8, 0, /* 3151: pointer.func */
            8884097, 8, 0, /* 3154: pointer.func */
            8884097, 8, 0, /* 3157: pointer.func */
            8884097, 8, 0, /* 3160: pointer.func */
            8884097, 8, 0, /* 3163: pointer.func */
            8884097, 8, 0, /* 3166: pointer.func */
            8884097, 8, 0, /* 3169: pointer.func */
            8884097, 8, 0, /* 3172: pointer.func */
            8884097, 8, 0, /* 3175: pointer.func */
            8884097, 8, 0, /* 3178: pointer.func */
            8884097, 8, 0, /* 3181: pointer.func */
            8884097, 8, 0, /* 3184: pointer.func */
            8884097, 8, 0, /* 3187: pointer.func */
            8884097, 8, 0, /* 3190: pointer.func */
            8884097, 8, 0, /* 3193: pointer.func */
            8884097, 8, 0, /* 3196: pointer.func */
            8884097, 8, 0, /* 3199: pointer.func */
            8884097, 8, 0, /* 3202: pointer.func */
            8884097, 8, 0, /* 3205: pointer.func */
            8884097, 8, 0, /* 3208: pointer.func */
            8884097, 8, 0, /* 3211: pointer.func */
            1, 8, 1, /* 3214: pointer.struct.ec_point_st */
            	1919, 0,
            1, 8, 1, /* 3219: pointer.struct.bignum_st */
            	1901, 0,
            1, 8, 1, /* 3224: pointer.struct.ec_extra_data_st */
            	2152, 0,
            8884097, 8, 0, /* 3229: pointer.func */
            1, 8, 1, /* 3232: pointer.struct.asn1_string_st */
            	3237, 0,
            0, 24, 1, /* 3237: struct.asn1_string_st */
            	17, 8,
            1, 8, 1, /* 3242: pointer.struct.AUTHORITY_KEYID_st */
            	3247, 0,
            0, 24, 3, /* 3247: struct.AUTHORITY_KEYID_st */
            	1285, 0,
            	1261, 8,
            	1251, 16,
            8884097, 8, 0, /* 3256: pointer.func */
            8884097, 8, 0, /* 3259: pointer.func */
            8884097, 8, 0, /* 3262: pointer.func */
            1, 8, 1, /* 3265: pointer.struct.X509_algor_st */
            	1739, 0,
            8884097, 8, 0, /* 3270: pointer.func */
            0, 208, 24, /* 3273: struct.evp_pkey_asn1_method_st */
            	35, 16,
            	35, 24,
            	3270, 32,
            	3324, 40,
            	3327, 48,
            	3262, 56,
            	3330, 64,
            	3333, 72,
            	3262, 80,
            	3256, 88,
            	3256, 96,
            	3336, 104,
            	3339, 112,
            	3256, 120,
            	3342, 128,
            	3327, 136,
            	3262, 144,
            	3259, 152,
            	3229, 160,
            	3345, 168,
            	3336, 176,
            	3339, 184,
            	2207, 192,
            	3348, 200,
            8884097, 8, 0, /* 3324: pointer.func */
            8884097, 8, 0, /* 3327: pointer.func */
            8884097, 8, 0, /* 3330: pointer.func */
            8884097, 8, 0, /* 3333: pointer.func */
            8884097, 8, 0, /* 3336: pointer.func */
            8884097, 8, 0, /* 3339: pointer.func */
            8884097, 8, 0, /* 3342: pointer.func */
            8884097, 8, 0, /* 3345: pointer.func */
            8884097, 8, 0, /* 3348: pointer.func */
            1, 8, 1, /* 3351: pointer.struct.evp_pkey_asn1_method_st */
            	3273, 0,
            1, 8, 1, /* 3356: pointer.struct.evp_pkey_st */
            	3361, 0,
            0, 56, 4, /* 3361: struct.evp_pkey_st */
            	3351, 16,
            	2875, 24,
            	2222, 32,
            	1681, 48,
            0, 1, 0, /* 3372: char */
            1, 8, 1, /* 3375: pointer.struct.asn1_string_st */
            	335, 0,
            1, 8, 1, /* 3380: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3385, 0,
            0, 32, 2, /* 3385: struct.stack_st_fake_X509_NAME_ENTRY */
            	3392, 8,
            	113, 24,
            8884099, 8, 2, /* 3392: pointer_to_array_of_pointers_to_stack */
            	3399, 0,
            	110, 20,
            0, 8, 1, /* 3399: pointer.X509_NAME_ENTRY */
            	64, 0,
            1, 8, 1, /* 3404: pointer.struct.X509_name_st */
            	3409, 0,
            0, 40, 3, /* 3409: struct.X509_name_st */
            	3380, 0,
            	3418, 16,
            	17, 24,
            1, 8, 1, /* 3418: pointer.struct.buf_mem_st */
            	3423, 0,
            0, 24, 1, /* 3423: struct.buf_mem_st */
            	35, 8,
            1, 8, 1, /* 3428: pointer.struct.x509_st */
            	3433, 0,
            0, 184, 12, /* 3433: struct.x509_st */
            	3460, 0,
            	3495, 8,
            	1326, 16,
            	35, 32,
            	2936, 40,
            	3375, 104,
            	3242, 112,
            	3543, 120,
            	737, 128,
            	395, 136,
            	359, 144,
            	3548, 176,
            1, 8, 1, /* 3460: pointer.struct.x509_cinf_st */
            	3465, 0,
            0, 104, 11, /* 3465: struct.x509_cinf_st */
            	3490, 0,
            	3490, 8,
            	3495, 16,
            	3404, 24,
            	2190, 32,
            	3404, 40,
            	3500, 48,
            	1326, 56,
            	1326, 64,
            	3514, 72,
            	3538, 80,
            1, 8, 1, /* 3490: pointer.struct.asn1_string_st */
            	335, 0,
            1, 8, 1, /* 3495: pointer.struct.X509_algor_st */
            	1739, 0,
            1, 8, 1, /* 3500: pointer.struct.X509_pubkey_st */
            	3505, 0,
            0, 24, 3, /* 3505: struct.X509_pubkey_st */
            	3265, 0,
            	3232, 8,
            	3356, 16,
            1, 8, 1, /* 3514: pointer.struct.stack_st_X509_EXTENSION */
            	3519, 0,
            0, 32, 2, /* 3519: struct.stack_st_fake_X509_EXTENSION */
            	3526, 8,
            	113, 24,
            8884099, 8, 2, /* 3526: pointer_to_array_of_pointers_to_stack */
            	3533, 0,
            	110, 20,
            0, 8, 1, /* 3533: pointer.X509_EXTENSION */
            	1321, 0,
            0, 24, 1, /* 3538: struct.ASN1_ENCODING_st */
            	17, 0,
            1, 8, 1, /* 3543: pointer.struct.X509_POLICY_CACHE_st */
            	1239, 0,
            1, 8, 1, /* 3548: pointer.struct.x509_cert_aux_st */
            	3553, 0,
            0, 40, 5, /* 3553: struct.x509_cert_aux_st */
            	3566, 0,
            	3566, 8,
            	330, 16,
            	3375, 24,
            	1710, 32,
            1, 8, 1, /* 3566: pointer.struct.stack_st_ASN1_OBJECT */
            	3571, 0,
            0, 32, 2, /* 3571: struct.stack_st_fake_ASN1_OBJECT */
            	3578, 8,
            	113, 24,
            8884099, 8, 2, /* 3578: pointer_to_array_of_pointers_to_stack */
            	3585, 0,
            	110, 20,
            0, 8, 1, /* 3585: pointer.ASN1_OBJECT */
            	852, 0,
            1, 8, 1, /* 3590: pointer.int */
            	110, 0,
        },
        .arg_entity_index = { 3428, 110, 3590, 3590, },
        .ret_entity_index = 2136,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_arg(args_addr, arg_d);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    X509 * new_arg_a = *((X509 * *)new_args->args[0]);

    int new_arg_b = *((int *)new_args->args[1]);

    int * new_arg_c = *((int * *)new_args->args[2]);

    int * new_arg_d = *((int * *)new_args->args[3]);

    void * *new_ret_ptr = (void * *)new_args->ret;

    void * (*orig_X509_get_ext_d2i)(X509 *,int,int *,int *);
    orig_X509_get_ext_d2i = dlsym(RTLD_NEXT, "X509_get_ext_d2i");
    *new_ret_ptr = (*orig_X509_get_ext_d2i)(new_arg_a,new_arg_b,new_arg_c,new_arg_d);

    syscall(889);

    return ret;
}

