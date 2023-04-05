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

int bb_X509_STORE_CTX_init(X509_STORE_CTX * arg_a,X509_STORE * arg_b,X509 * arg_c,STACK_OF(X509) * arg_d);

int X509_STORE_CTX_init(X509_STORE_CTX * arg_a,X509_STORE * arg_b,X509 * arg_c,STACK_OF(X509) * arg_d) 
{
    unsigned long in_lib = syscall(890);
    printf("X509_STORE_CTX_init called %lu\n", in_lib);
    if (!in_lib)
        return bb_X509_STORE_CTX_init(arg_a,arg_b,arg_c,arg_d);
    else {
        int (*orig_X509_STORE_CTX_init)(X509_STORE_CTX *,X509_STORE *,X509 *,STACK_OF(X509) *);
        orig_X509_STORE_CTX_init = dlsym(RTLD_NEXT, "X509_STORE_CTX_init");
        return orig_X509_STORE_CTX_init(arg_a,arg_b,arg_c,arg_d);
    }
}

int bb_X509_STORE_CTX_init(X509_STORE_CTX * arg_a,X509_STORE * arg_b,X509 * arg_c,STACK_OF(X509) * arg_d) 
{
    int ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 32, 2, /* 0: struct.ISSUING_DIST_POINT_st */
            	7, 0,
            	433, 16,
            1, 8, 1, /* 7: pointer.struct.DIST_POINT_NAME_st */
            	12, 0,
            0, 24, 2, /* 12: struct.DIST_POINT_NAME_st */
            	19, 8,
            	409, 16,
            0, 8, 2, /* 19: union.unknown */
            	26, 0,
            	385, 0,
            1, 8, 1, /* 26: pointer.struct.stack_st_GENERAL_NAME */
            	31, 0,
            0, 32, 2, /* 31: struct.stack_st_fake_GENERAL_NAME */
            	38, 8,
            	360, 24,
            64099, 8, 2, /* 38: pointer_to_array_of_pointers_to_stack */
            	45, 0,
            	357, 20,
            0, 8, 1, /* 45: pointer.GENERAL_NAME */
            	50, 0,
            0, 0, 1, /* 50: GENERAL_NAME */
            	55, 0,
            0, 16, 1, /* 55: struct.GENERAL_NAME_st */
            	60, 8,
            0, 8, 15, /* 60: union.unknown */
            	93, 0,
            	98, 0,
            	235, 0,
            	235, 0,
            	137, 0,
            	283, 0,
            	373, 0,
            	235, 0,
            	220, 0,
            	110, 0,
            	220, 0,
            	283, 0,
            	235, 0,
            	110, 0,
            	137, 0,
            1, 8, 1, /* 93: pointer.char */
            	64096, 0,
            1, 8, 1, /* 98: pointer.struct.otherName_st */
            	103, 0,
            0, 16, 2, /* 103: struct.otherName_st */
            	110, 0,
            	137, 8,
            1, 8, 1, /* 110: pointer.struct.asn1_object_st */
            	115, 0,
            0, 40, 3, /* 115: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            1, 8, 1, /* 124: pointer.char */
            	64096, 0,
            1, 8, 1, /* 129: pointer.unsigned char */
            	134, 0,
            0, 1, 0, /* 134: unsigned char */
            1, 8, 1, /* 137: pointer.struct.asn1_type_st */
            	142, 0,
            0, 16, 1, /* 142: struct.asn1_type_st */
            	147, 8,
            0, 8, 20, /* 147: union.unknown */
            	93, 0,
            	190, 0,
            	110, 0,
            	205, 0,
            	210, 0,
            	215, 0,
            	220, 0,
            	225, 0,
            	230, 0,
            	235, 0,
            	240, 0,
            	245, 0,
            	250, 0,
            	255, 0,
            	260, 0,
            	265, 0,
            	270, 0,
            	190, 0,
            	190, 0,
            	275, 0,
            1, 8, 1, /* 190: pointer.struct.asn1_string_st */
            	195, 0,
            0, 24, 1, /* 195: struct.asn1_string_st */
            	200, 8,
            1, 8, 1, /* 200: pointer.unsigned char */
            	134, 0,
            1, 8, 1, /* 205: pointer.struct.asn1_string_st */
            	195, 0,
            1, 8, 1, /* 210: pointer.struct.asn1_string_st */
            	195, 0,
            1, 8, 1, /* 215: pointer.struct.asn1_string_st */
            	195, 0,
            1, 8, 1, /* 220: pointer.struct.asn1_string_st */
            	195, 0,
            1, 8, 1, /* 225: pointer.struct.asn1_string_st */
            	195, 0,
            1, 8, 1, /* 230: pointer.struct.asn1_string_st */
            	195, 0,
            1, 8, 1, /* 235: pointer.struct.asn1_string_st */
            	195, 0,
            1, 8, 1, /* 240: pointer.struct.asn1_string_st */
            	195, 0,
            1, 8, 1, /* 245: pointer.struct.asn1_string_st */
            	195, 0,
            1, 8, 1, /* 250: pointer.struct.asn1_string_st */
            	195, 0,
            1, 8, 1, /* 255: pointer.struct.asn1_string_st */
            	195, 0,
            1, 8, 1, /* 260: pointer.struct.asn1_string_st */
            	195, 0,
            1, 8, 1, /* 265: pointer.struct.asn1_string_st */
            	195, 0,
            1, 8, 1, /* 270: pointer.struct.asn1_string_st */
            	195, 0,
            1, 8, 1, /* 275: pointer.struct.ASN1_VALUE_st */
            	280, 0,
            0, 0, 0, /* 280: struct.ASN1_VALUE_st */
            1, 8, 1, /* 283: pointer.struct.X509_name_st */
            	288, 0,
            0, 40, 3, /* 288: struct.X509_name_st */
            	297, 0,
            	363, 16,
            	200, 24,
            1, 8, 1, /* 297: pointer.struct.stack_st_X509_NAME_ENTRY */
            	302, 0,
            0, 32, 2, /* 302: struct.stack_st_fake_X509_NAME_ENTRY */
            	309, 8,
            	360, 24,
            64099, 8, 2, /* 309: pointer_to_array_of_pointers_to_stack */
            	316, 0,
            	357, 20,
            0, 8, 1, /* 316: pointer.X509_NAME_ENTRY */
            	321, 0,
            0, 0, 1, /* 321: X509_NAME_ENTRY */
            	326, 0,
            0, 24, 2, /* 326: struct.X509_name_entry_st */
            	333, 0,
            	347, 8,
            1, 8, 1, /* 333: pointer.struct.asn1_object_st */
            	338, 0,
            0, 40, 3, /* 338: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            1, 8, 1, /* 347: pointer.struct.asn1_string_st */
            	352, 0,
            0, 24, 1, /* 352: struct.asn1_string_st */
            	200, 8,
            0, 4, 0, /* 357: int */
            64097, 8, 0, /* 360: pointer.func */
            1, 8, 1, /* 363: pointer.struct.buf_mem_st */
            	368, 0,
            0, 24, 1, /* 368: struct.buf_mem_st */
            	93, 8,
            1, 8, 1, /* 373: pointer.struct.EDIPartyName_st */
            	378, 0,
            0, 16, 2, /* 378: struct.EDIPartyName_st */
            	190, 0,
            	190, 8,
            1, 8, 1, /* 385: pointer.struct.stack_st_X509_NAME_ENTRY */
            	390, 0,
            0, 32, 2, /* 390: struct.stack_st_fake_X509_NAME_ENTRY */
            	397, 8,
            	360, 24,
            64099, 8, 2, /* 397: pointer_to_array_of_pointers_to_stack */
            	404, 0,
            	357, 20,
            0, 8, 1, /* 404: pointer.X509_NAME_ENTRY */
            	321, 0,
            1, 8, 1, /* 409: pointer.struct.X509_name_st */
            	414, 0,
            0, 40, 3, /* 414: struct.X509_name_st */
            	385, 0,
            	423, 16,
            	200, 24,
            1, 8, 1, /* 423: pointer.struct.buf_mem_st */
            	428, 0,
            0, 24, 1, /* 428: struct.buf_mem_st */
            	93, 8,
            1, 8, 1, /* 433: pointer.struct.asn1_string_st */
            	438, 0,
            0, 24, 1, /* 438: struct.asn1_string_st */
            	200, 8,
            1, 8, 1, /* 443: pointer.struct.ISSUING_DIST_POINT_st */
            	0, 0,
            0, 80, 8, /* 448: struct.X509_crl_info_st */
            	467, 0,
            	472, 8,
            	409, 16,
            	624, 24,
            	624, 32,
            	629, 40,
            	768, 48,
            	792, 56,
            1, 8, 1, /* 467: pointer.struct.asn1_string_st */
            	438, 0,
            1, 8, 1, /* 472: pointer.struct.X509_algor_st */
            	477, 0,
            0, 16, 2, /* 477: struct.X509_algor_st */
            	484, 0,
            	498, 8,
            1, 8, 1, /* 484: pointer.struct.asn1_object_st */
            	489, 0,
            0, 40, 3, /* 489: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            1, 8, 1, /* 498: pointer.struct.asn1_type_st */
            	503, 0,
            0, 16, 1, /* 503: struct.asn1_type_st */
            	508, 8,
            0, 8, 20, /* 508: union.unknown */
            	93, 0,
            	551, 0,
            	484, 0,
            	467, 0,
            	556, 0,
            	433, 0,
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
            	551, 0,
            	551, 0,
            	616, 0,
            1, 8, 1, /* 551: pointer.struct.asn1_string_st */
            	438, 0,
            1, 8, 1, /* 556: pointer.struct.asn1_string_st */
            	438, 0,
            1, 8, 1, /* 561: pointer.struct.asn1_string_st */
            	438, 0,
            1, 8, 1, /* 566: pointer.struct.asn1_string_st */
            	438, 0,
            1, 8, 1, /* 571: pointer.struct.asn1_string_st */
            	438, 0,
            1, 8, 1, /* 576: pointer.struct.asn1_string_st */
            	438, 0,
            1, 8, 1, /* 581: pointer.struct.asn1_string_st */
            	438, 0,
            1, 8, 1, /* 586: pointer.struct.asn1_string_st */
            	438, 0,
            1, 8, 1, /* 591: pointer.struct.asn1_string_st */
            	438, 0,
            1, 8, 1, /* 596: pointer.struct.asn1_string_st */
            	438, 0,
            1, 8, 1, /* 601: pointer.struct.asn1_string_st */
            	438, 0,
            1, 8, 1, /* 606: pointer.struct.asn1_string_st */
            	438, 0,
            1, 8, 1, /* 611: pointer.struct.asn1_string_st */
            	438, 0,
            1, 8, 1, /* 616: pointer.struct.ASN1_VALUE_st */
            	621, 0,
            0, 0, 0, /* 621: struct.ASN1_VALUE_st */
            1, 8, 1, /* 624: pointer.struct.asn1_string_st */
            	438, 0,
            1, 8, 1, /* 629: pointer.struct.stack_st_X509_REVOKED */
            	634, 0,
            0, 32, 2, /* 634: struct.stack_st_fake_X509_REVOKED */
            	641, 8,
            	360, 24,
            64099, 8, 2, /* 641: pointer_to_array_of_pointers_to_stack */
            	648, 0,
            	357, 20,
            0, 8, 1, /* 648: pointer.X509_REVOKED */
            	653, 0,
            0, 0, 1, /* 653: X509_REVOKED */
            	658, 0,
            0, 40, 4, /* 658: struct.x509_revoked_st */
            	669, 0,
            	679, 8,
            	684, 16,
            	744, 24,
            1, 8, 1, /* 669: pointer.struct.asn1_string_st */
            	674, 0,
            0, 24, 1, /* 674: struct.asn1_string_st */
            	200, 8,
            1, 8, 1, /* 679: pointer.struct.asn1_string_st */
            	674, 0,
            1, 8, 1, /* 684: pointer.struct.stack_st_X509_EXTENSION */
            	689, 0,
            0, 32, 2, /* 689: struct.stack_st_fake_X509_EXTENSION */
            	696, 8,
            	360, 24,
            64099, 8, 2, /* 696: pointer_to_array_of_pointers_to_stack */
            	703, 0,
            	357, 20,
            0, 8, 1, /* 703: pointer.X509_EXTENSION */
            	708, 0,
            0, 0, 1, /* 708: X509_EXTENSION */
            	713, 0,
            0, 24, 2, /* 713: struct.X509_extension_st */
            	720, 0,
            	734, 16,
            1, 8, 1, /* 720: pointer.struct.asn1_object_st */
            	725, 0,
            0, 40, 3, /* 725: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            1, 8, 1, /* 734: pointer.struct.asn1_string_st */
            	739, 0,
            0, 24, 1, /* 739: struct.asn1_string_st */
            	200, 8,
            1, 8, 1, /* 744: pointer.struct.stack_st_GENERAL_NAME */
            	749, 0,
            0, 32, 2, /* 749: struct.stack_st_fake_GENERAL_NAME */
            	756, 8,
            	360, 24,
            64099, 8, 2, /* 756: pointer_to_array_of_pointers_to_stack */
            	763, 0,
            	357, 20,
            0, 8, 1, /* 763: pointer.GENERAL_NAME */
            	50, 0,
            1, 8, 1, /* 768: pointer.struct.stack_st_X509_EXTENSION */
            	773, 0,
            0, 32, 2, /* 773: struct.stack_st_fake_X509_EXTENSION */
            	780, 8,
            	360, 24,
            64099, 8, 2, /* 780: pointer_to_array_of_pointers_to_stack */
            	787, 0,
            	357, 20,
            0, 8, 1, /* 787: pointer.X509_EXTENSION */
            	708, 0,
            0, 24, 1, /* 792: struct.ASN1_ENCODING_st */
            	200, 0,
            1, 8, 1, /* 797: pointer.struct.X509_crl_st */
            	802, 0,
            0, 120, 10, /* 802: struct.X509_crl_st */
            	825, 0,
            	472, 8,
            	433, 16,
            	830, 32,
            	443, 40,
            	467, 56,
            	467, 64,
            	844, 96,
            	890, 104,
            	898, 112,
            1, 8, 1, /* 825: pointer.struct.X509_crl_info_st */
            	448, 0,
            1, 8, 1, /* 830: pointer.struct.AUTHORITY_KEYID_st */
            	835, 0,
            0, 24, 3, /* 835: struct.AUTHORITY_KEYID_st */
            	561, 0,
            	26, 8,
            	467, 16,
            1, 8, 1, /* 844: pointer.struct.stack_st_GENERAL_NAMES */
            	849, 0,
            0, 32, 2, /* 849: struct.stack_st_fake_GENERAL_NAMES */
            	856, 8,
            	360, 24,
            64099, 8, 2, /* 856: pointer_to_array_of_pointers_to_stack */
            	863, 0,
            	357, 20,
            0, 8, 1, /* 863: pointer.GENERAL_NAMES */
            	868, 0,
            0, 0, 1, /* 868: GENERAL_NAMES */
            	873, 0,
            0, 32, 1, /* 873: struct.stack_st_GENERAL_NAME */
            	878, 0,
            0, 32, 2, /* 878: struct.stack_st */
            	885, 8,
            	360, 24,
            1, 8, 1, /* 885: pointer.pointer.char */
            	93, 0,
            1, 8, 1, /* 890: pointer.struct.x509_crl_method_st */
            	895, 0,
            0, 0, 0, /* 895: struct.x509_crl_method_st */
            0, 8, 0, /* 898: pointer.void */
            0, 0, 0, /* 901: struct.X509_POLICY_TREE_st */
            1, 8, 1, /* 904: pointer.struct.X509_POLICY_TREE_st */
            	901, 0,
            1, 8, 1, /* 909: pointer.struct.x509_crl_method_st */
            	914, 0,
            0, 0, 0, /* 914: struct.x509_crl_method_st */
            1, 8, 1, /* 917: pointer.struct.stack_st_GENERAL_NAMES */
            	922, 0,
            0, 32, 2, /* 922: struct.stack_st_fake_GENERAL_NAMES */
            	929, 8,
            	360, 24,
            64099, 8, 2, /* 929: pointer_to_array_of_pointers_to_stack */
            	936, 0,
            	357, 20,
            0, 8, 1, /* 936: pointer.GENERAL_NAMES */
            	868, 0,
            0, 0, 0, /* 941: struct.ISSUING_DIST_POINT_st */
            1, 8, 1, /* 944: pointer.struct.ISSUING_DIST_POINT_st */
            	941, 0,
            0, 0, 0, /* 949: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 952: pointer.struct.AUTHORITY_KEYID_st */
            	949, 0,
            1, 8, 1, /* 957: pointer.struct.asn1_string_st */
            	962, 0,
            0, 24, 1, /* 962: struct.asn1_string_st */
            	200, 8,
            1, 8, 1, /* 967: pointer.struct.buf_mem_st */
            	972, 0,
            0, 24, 1, /* 972: struct.buf_mem_st */
            	93, 8,
            1, 8, 1, /* 977: pointer.struct.stack_st_X509_NAME_ENTRY */
            	982, 0,
            0, 32, 2, /* 982: struct.stack_st_fake_X509_NAME_ENTRY */
            	989, 8,
            	360, 24,
            64099, 8, 2, /* 989: pointer_to_array_of_pointers_to_stack */
            	996, 0,
            	357, 20,
            0, 8, 1, /* 996: pointer.X509_NAME_ENTRY */
            	321, 0,
            0, 40, 3, /* 1001: struct.X509_name_st */
            	977, 0,
            	967, 16,
            	200, 24,
            1, 8, 1, /* 1010: pointer.struct.X509_name_st */
            	1001, 0,
            0, 0, 0, /* 1015: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1018: pointer.struct.asn1_string_st */
            	962, 0,
            1, 8, 1, /* 1023: pointer.struct.asn1_string_st */
            	962, 0,
            1, 8, 1, /* 1028: pointer.struct.asn1_string_st */
            	962, 0,
            1, 8, 1, /* 1033: pointer.struct.asn1_string_st */
            	962, 0,
            1, 8, 1, /* 1038: pointer.struct.asn1_string_st */
            	962, 0,
            1, 8, 1, /* 1043: pointer.struct.asn1_string_st */
            	962, 0,
            1, 8, 1, /* 1048: pointer.struct.asn1_string_st */
            	962, 0,
            1, 8, 1, /* 1053: pointer.struct.asn1_string_st */
            	962, 0,
            1, 8, 1, /* 1058: pointer.struct.asn1_string_st */
            	962, 0,
            0, 8, 20, /* 1063: union.unknown */
            	93, 0,
            	1058, 0,
            	1106, 0,
            	1120, 0,
            	1053, 0,
            	1048, 0,
            	1043, 0,
            	1125, 0,
            	1130, 0,
            	1135, 0,
            	1038, 0,
            	1033, 0,
            	1028, 0,
            	1140, 0,
            	1023, 0,
            	1145, 0,
            	1018, 0,
            	1058, 0,
            	1058, 0,
            	1150, 0,
            1, 8, 1, /* 1106: pointer.struct.asn1_object_st */
            	1111, 0,
            0, 40, 3, /* 1111: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            1, 8, 1, /* 1120: pointer.struct.asn1_string_st */
            	962, 0,
            1, 8, 1, /* 1125: pointer.struct.asn1_string_st */
            	962, 0,
            1, 8, 1, /* 1130: pointer.struct.asn1_string_st */
            	962, 0,
            1, 8, 1, /* 1135: pointer.struct.asn1_string_st */
            	962, 0,
            1, 8, 1, /* 1140: pointer.struct.asn1_string_st */
            	962, 0,
            1, 8, 1, /* 1145: pointer.struct.asn1_string_st */
            	962, 0,
            1, 8, 1, /* 1150: pointer.struct.ASN1_VALUE_st */
            	1015, 0,
            0, 16, 1, /* 1155: struct.asn1_type_st */
            	1063, 8,
            1, 8, 1, /* 1160: pointer.struct.asn1_type_st */
            	1155, 0,
            1, 8, 1, /* 1165: pointer.struct.X509_algor_st */
            	1170, 0,
            0, 16, 2, /* 1170: struct.X509_algor_st */
            	1106, 0,
            	1160, 8,
            0, 80, 8, /* 1177: struct.X509_crl_info_st */
            	1120, 0,
            	1165, 8,
            	1010, 16,
            	957, 24,
            	957, 32,
            	1196, 40,
            	1220, 48,
            	1244, 56,
            1, 8, 1, /* 1196: pointer.struct.stack_st_X509_REVOKED */
            	1201, 0,
            0, 32, 2, /* 1201: struct.stack_st_fake_X509_REVOKED */
            	1208, 8,
            	360, 24,
            64099, 8, 2, /* 1208: pointer_to_array_of_pointers_to_stack */
            	1215, 0,
            	357, 20,
            0, 8, 1, /* 1215: pointer.X509_REVOKED */
            	653, 0,
            1, 8, 1, /* 1220: pointer.struct.stack_st_X509_EXTENSION */
            	1225, 0,
            0, 32, 2, /* 1225: struct.stack_st_fake_X509_EXTENSION */
            	1232, 8,
            	360, 24,
            64099, 8, 2, /* 1232: pointer_to_array_of_pointers_to_stack */
            	1239, 0,
            	357, 20,
            0, 8, 1, /* 1239: pointer.X509_EXTENSION */
            	708, 0,
            0, 24, 1, /* 1244: struct.ASN1_ENCODING_st */
            	200, 0,
            1, 8, 1, /* 1249: pointer.struct.X509_crl_info_st */
            	1177, 0,
            0, 120, 10, /* 1254: struct.X509_crl_st */
            	1249, 0,
            	1165, 8,
            	1048, 16,
            	952, 32,
            	944, 40,
            	1120, 56,
            	1120, 64,
            	917, 96,
            	909, 104,
            	898, 112,
            0, 0, 1, /* 1277: X509_CRL */
            	1254, 0,
            1, 8, 1, /* 1282: pointer.struct.rsa_st */
            	1287, 0,
            0, 168, 17, /* 1287: struct.rsa_st */
            	1324, 16,
            	1379, 24,
            	1387, 32,
            	1387, 40,
            	1387, 48,
            	1387, 56,
            	1387, 64,
            	1387, 72,
            	1387, 80,
            	1387, 88,
            	1405, 96,
            	1427, 120,
            	1427, 128,
            	1427, 136,
            	93, 144,
            	1441, 152,
            	1441, 160,
            1, 8, 1, /* 1324: pointer.struct.rsa_meth_st */
            	1329, 0,
            0, 112, 13, /* 1329: struct.rsa_meth_st */
            	124, 0,
            	1358, 8,
            	1358, 16,
            	1358, 24,
            	1358, 32,
            	1361, 40,
            	1364, 48,
            	1367, 56,
            	1367, 64,
            	93, 80,
            	1370, 88,
            	1373, 96,
            	1376, 104,
            64097, 8, 0, /* 1358: pointer.func */
            64097, 8, 0, /* 1361: pointer.func */
            64097, 8, 0, /* 1364: pointer.func */
            64097, 8, 0, /* 1367: pointer.func */
            64097, 8, 0, /* 1370: pointer.func */
            64097, 8, 0, /* 1373: pointer.func */
            64097, 8, 0, /* 1376: pointer.func */
            1, 8, 1, /* 1379: pointer.struct.engine_st */
            	1384, 0,
            0, 0, 0, /* 1384: struct.engine_st */
            1, 8, 1, /* 1387: pointer.struct.bignum_st */
            	1392, 0,
            0, 24, 1, /* 1392: struct.bignum_st */
            	1397, 0,
            1, 8, 1, /* 1397: pointer.unsigned int */
            	1402, 0,
            0, 4, 0, /* 1402: unsigned int */
            0, 16, 1, /* 1405: struct.crypto_ex_data_st */
            	1410, 0,
            1, 8, 1, /* 1410: pointer.struct.stack_st_void */
            	1415, 0,
            0, 32, 1, /* 1415: struct.stack_st_void */
            	1420, 0,
            0, 32, 2, /* 1420: struct.stack_st */
            	885, 8,
            	360, 24,
            1, 8, 1, /* 1427: pointer.struct.bn_mont_ctx_st */
            	1432, 0,
            0, 96, 3, /* 1432: struct.bn_mont_ctx_st */
            	1392, 8,
            	1392, 32,
            	1392, 56,
            1, 8, 1, /* 1441: pointer.struct.bn_blinding_st */
            	1446, 0,
            0, 0, 0, /* 1446: struct.bn_blinding_st */
            1, 8, 1, /* 1449: pointer.struct.x509_cinf_st */
            	1454, 0,
            0, 104, 11, /* 1454: struct.x509_cinf_st */
            	467, 0,
            	467, 8,
            	472, 16,
            	409, 24,
            	1479, 32,
            	409, 40,
            	1491, 48,
            	433, 56,
            	433, 64,
            	768, 72,
            	792, 80,
            1, 8, 1, /* 1479: pointer.struct.X509_val_st */
            	1484, 0,
            0, 16, 2, /* 1484: struct.X509_val_st */
            	624, 0,
            	624, 8,
            1, 8, 1, /* 1491: pointer.struct.X509_pubkey_st */
            	1496, 0,
            0, 24, 3, /* 1496: struct.X509_pubkey_st */
            	472, 0,
            	433, 8,
            	1505, 16,
            1, 8, 1, /* 1505: pointer.struct.evp_pkey_st */
            	1510, 0,
            0, 56, 4, /* 1510: struct.evp_pkey_st */
            	1521, 16,
            	1379, 24,
            	1529, 32,
            	1699, 48,
            1, 8, 1, /* 1521: pointer.struct.evp_pkey_asn1_method_st */
            	1526, 0,
            0, 0, 0, /* 1526: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 1529: union.unknown */
            	93, 0,
            	1282, 0,
            	1542, 0,
            	1623, 0,
            	1691, 0,
            1, 8, 1, /* 1542: pointer.struct.dsa_st */
            	1547, 0,
            0, 136, 11, /* 1547: struct.dsa_st */
            	1387, 24,
            	1387, 32,
            	1387, 40,
            	1387, 48,
            	1387, 56,
            	1387, 64,
            	1387, 72,
            	1427, 88,
            	1405, 104,
            	1572, 120,
            	1379, 128,
            1, 8, 1, /* 1572: pointer.struct.dsa_method */
            	1577, 0,
            0, 96, 11, /* 1577: struct.dsa_method */
            	124, 0,
            	1602, 8,
            	1605, 16,
            	1608, 24,
            	1611, 32,
            	1614, 40,
            	1617, 48,
            	1617, 56,
            	93, 72,
            	1620, 80,
            	1617, 88,
            64097, 8, 0, /* 1602: pointer.func */
            64097, 8, 0, /* 1605: pointer.func */
            64097, 8, 0, /* 1608: pointer.func */
            64097, 8, 0, /* 1611: pointer.func */
            64097, 8, 0, /* 1614: pointer.func */
            64097, 8, 0, /* 1617: pointer.func */
            64097, 8, 0, /* 1620: pointer.func */
            1, 8, 1, /* 1623: pointer.struct.dh_st */
            	1628, 0,
            0, 144, 12, /* 1628: struct.dh_st */
            	1387, 8,
            	1387, 16,
            	1387, 32,
            	1387, 40,
            	1427, 56,
            	1387, 64,
            	1387, 72,
            	200, 80,
            	1387, 96,
            	1405, 112,
            	1655, 128,
            	1379, 136,
            1, 8, 1, /* 1655: pointer.struct.dh_method */
            	1660, 0,
            0, 72, 8, /* 1660: struct.dh_method */
            	124, 0,
            	1679, 8,
            	1682, 16,
            	1685, 24,
            	1679, 32,
            	1679, 40,
            	93, 56,
            	1688, 64,
            64097, 8, 0, /* 1679: pointer.func */
            64097, 8, 0, /* 1682: pointer.func */
            64097, 8, 0, /* 1685: pointer.func */
            64097, 8, 0, /* 1688: pointer.func */
            1, 8, 1, /* 1691: pointer.struct.ec_key_st */
            	1696, 0,
            0, 0, 0, /* 1696: struct.ec_key_st */
            1, 8, 1, /* 1699: pointer.struct.stack_st_X509_ATTRIBUTE */
            	1704, 0,
            0, 32, 2, /* 1704: struct.stack_st_fake_X509_ATTRIBUTE */
            	1711, 8,
            	360, 24,
            64099, 8, 2, /* 1711: pointer_to_array_of_pointers_to_stack */
            	1718, 0,
            	357, 20,
            0, 8, 1, /* 1718: pointer.X509_ATTRIBUTE */
            	1723, 0,
            0, 0, 1, /* 1723: X509_ATTRIBUTE */
            	1728, 0,
            0, 24, 2, /* 1728: struct.x509_attributes_st */
            	1735, 0,
            	1749, 16,
            1, 8, 1, /* 1735: pointer.struct.asn1_object_st */
            	1740, 0,
            0, 40, 3, /* 1740: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            0, 8, 3, /* 1749: union.unknown */
            	93, 0,
            	1758, 0,
            	1937, 0,
            1, 8, 1, /* 1758: pointer.struct.stack_st_ASN1_TYPE */
            	1763, 0,
            0, 32, 2, /* 1763: struct.stack_st_fake_ASN1_TYPE */
            	1770, 8,
            	360, 24,
            64099, 8, 2, /* 1770: pointer_to_array_of_pointers_to_stack */
            	1777, 0,
            	357, 20,
            0, 8, 1, /* 1777: pointer.ASN1_TYPE */
            	1782, 0,
            0, 0, 1, /* 1782: ASN1_TYPE */
            	1787, 0,
            0, 16, 1, /* 1787: struct.asn1_type_st */
            	1792, 8,
            0, 8, 20, /* 1792: union.unknown */
            	93, 0,
            	1835, 0,
            	1845, 0,
            	1859, 0,
            	1864, 0,
            	1869, 0,
            	1874, 0,
            	1879, 0,
            	1884, 0,
            	1889, 0,
            	1894, 0,
            	1899, 0,
            	1904, 0,
            	1909, 0,
            	1914, 0,
            	1919, 0,
            	1924, 0,
            	1835, 0,
            	1835, 0,
            	1929, 0,
            1, 8, 1, /* 1835: pointer.struct.asn1_string_st */
            	1840, 0,
            0, 24, 1, /* 1840: struct.asn1_string_st */
            	200, 8,
            1, 8, 1, /* 1845: pointer.struct.asn1_object_st */
            	1850, 0,
            0, 40, 3, /* 1850: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            1, 8, 1, /* 1859: pointer.struct.asn1_string_st */
            	1840, 0,
            1, 8, 1, /* 1864: pointer.struct.asn1_string_st */
            	1840, 0,
            1, 8, 1, /* 1869: pointer.struct.asn1_string_st */
            	1840, 0,
            1, 8, 1, /* 1874: pointer.struct.asn1_string_st */
            	1840, 0,
            1, 8, 1, /* 1879: pointer.struct.asn1_string_st */
            	1840, 0,
            1, 8, 1, /* 1884: pointer.struct.asn1_string_st */
            	1840, 0,
            1, 8, 1, /* 1889: pointer.struct.asn1_string_st */
            	1840, 0,
            1, 8, 1, /* 1894: pointer.struct.asn1_string_st */
            	1840, 0,
            1, 8, 1, /* 1899: pointer.struct.asn1_string_st */
            	1840, 0,
            1, 8, 1, /* 1904: pointer.struct.asn1_string_st */
            	1840, 0,
            1, 8, 1, /* 1909: pointer.struct.asn1_string_st */
            	1840, 0,
            1, 8, 1, /* 1914: pointer.struct.asn1_string_st */
            	1840, 0,
            1, 8, 1, /* 1919: pointer.struct.asn1_string_st */
            	1840, 0,
            1, 8, 1, /* 1924: pointer.struct.asn1_string_st */
            	1840, 0,
            1, 8, 1, /* 1929: pointer.struct.ASN1_VALUE_st */
            	1934, 0,
            0, 0, 0, /* 1934: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1937: pointer.struct.asn1_type_st */
            	1942, 0,
            0, 16, 1, /* 1942: struct.asn1_type_st */
            	1947, 8,
            0, 8, 20, /* 1947: union.unknown */
            	93, 0,
            	1990, 0,
            	1735, 0,
            	2000, 0,
            	2005, 0,
            	2010, 0,
            	2015, 0,
            	2020, 0,
            	2025, 0,
            	2030, 0,
            	2035, 0,
            	2040, 0,
            	2045, 0,
            	2050, 0,
            	2055, 0,
            	2060, 0,
            	2065, 0,
            	1990, 0,
            	1990, 0,
            	616, 0,
            1, 8, 1, /* 1990: pointer.struct.asn1_string_st */
            	1995, 0,
            0, 24, 1, /* 1995: struct.asn1_string_st */
            	200, 8,
            1, 8, 1, /* 2000: pointer.struct.asn1_string_st */
            	1995, 0,
            1, 8, 1, /* 2005: pointer.struct.asn1_string_st */
            	1995, 0,
            1, 8, 1, /* 2010: pointer.struct.asn1_string_st */
            	1995, 0,
            1, 8, 1, /* 2015: pointer.struct.asn1_string_st */
            	1995, 0,
            1, 8, 1, /* 2020: pointer.struct.asn1_string_st */
            	1995, 0,
            1, 8, 1, /* 2025: pointer.struct.asn1_string_st */
            	1995, 0,
            1, 8, 1, /* 2030: pointer.struct.asn1_string_st */
            	1995, 0,
            1, 8, 1, /* 2035: pointer.struct.asn1_string_st */
            	1995, 0,
            1, 8, 1, /* 2040: pointer.struct.asn1_string_st */
            	1995, 0,
            1, 8, 1, /* 2045: pointer.struct.asn1_string_st */
            	1995, 0,
            1, 8, 1, /* 2050: pointer.struct.asn1_string_st */
            	1995, 0,
            1, 8, 1, /* 2055: pointer.struct.asn1_string_st */
            	1995, 0,
            1, 8, 1, /* 2060: pointer.struct.asn1_string_st */
            	1995, 0,
            1, 8, 1, /* 2065: pointer.struct.asn1_string_st */
            	1995, 0,
            1, 8, 1, /* 2070: pointer.struct.asn1_string_st */
            	2075, 0,
            0, 24, 1, /* 2075: struct.asn1_string_st */
            	200, 8,
            1, 8, 1, /* 2080: pointer.struct.asn1_string_st */
            	2075, 0,
            0, 184, 12, /* 2085: struct.x509_st */
            	2112, 0,
            	2152, 8,
            	2241, 16,
            	93, 32,
            	2540, 40,
            	2246, 104,
            	2794, 112,
            	2802, 120,
            	2810, 128,
            	2848, 136,
            	2872, 144,
            	2880, 176,
            1, 8, 1, /* 2112: pointer.struct.x509_cinf_st */
            	2117, 0,
            0, 104, 11, /* 2117: struct.x509_cinf_st */
            	2142, 0,
            	2142, 8,
            	2152, 16,
            	2309, 24,
            	2357, 32,
            	2309, 40,
            	2374, 48,
            	2241, 56,
            	2241, 64,
            	2765, 72,
            	2789, 80,
            1, 8, 1, /* 2142: pointer.struct.asn1_string_st */
            	2147, 0,
            0, 24, 1, /* 2147: struct.asn1_string_st */
            	200, 8,
            1, 8, 1, /* 2152: pointer.struct.X509_algor_st */
            	2157, 0,
            0, 16, 2, /* 2157: struct.X509_algor_st */
            	2164, 0,
            	2178, 8,
            1, 8, 1, /* 2164: pointer.struct.asn1_object_st */
            	2169, 0,
            0, 40, 3, /* 2169: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            1, 8, 1, /* 2178: pointer.struct.asn1_type_st */
            	2183, 0,
            0, 16, 1, /* 2183: struct.asn1_type_st */
            	2188, 8,
            0, 8, 20, /* 2188: union.unknown */
            	93, 0,
            	2231, 0,
            	2164, 0,
            	2142, 0,
            	2236, 0,
            	2241, 0,
            	2246, 0,
            	2251, 0,
            	2256, 0,
            	2261, 0,
            	2266, 0,
            	2271, 0,
            	2276, 0,
            	2281, 0,
            	2286, 0,
            	2291, 0,
            	2296, 0,
            	2231, 0,
            	2231, 0,
            	2301, 0,
            1, 8, 1, /* 2231: pointer.struct.asn1_string_st */
            	2147, 0,
            1, 8, 1, /* 2236: pointer.struct.asn1_string_st */
            	2147, 0,
            1, 8, 1, /* 2241: pointer.struct.asn1_string_st */
            	2147, 0,
            1, 8, 1, /* 2246: pointer.struct.asn1_string_st */
            	2147, 0,
            1, 8, 1, /* 2251: pointer.struct.asn1_string_st */
            	2147, 0,
            1, 8, 1, /* 2256: pointer.struct.asn1_string_st */
            	2147, 0,
            1, 8, 1, /* 2261: pointer.struct.asn1_string_st */
            	2147, 0,
            1, 8, 1, /* 2266: pointer.struct.asn1_string_st */
            	2147, 0,
            1, 8, 1, /* 2271: pointer.struct.asn1_string_st */
            	2147, 0,
            1, 8, 1, /* 2276: pointer.struct.asn1_string_st */
            	2147, 0,
            1, 8, 1, /* 2281: pointer.struct.asn1_string_st */
            	2147, 0,
            1, 8, 1, /* 2286: pointer.struct.asn1_string_st */
            	2147, 0,
            1, 8, 1, /* 2291: pointer.struct.asn1_string_st */
            	2147, 0,
            1, 8, 1, /* 2296: pointer.struct.asn1_string_st */
            	2147, 0,
            1, 8, 1, /* 2301: pointer.struct.ASN1_VALUE_st */
            	2306, 0,
            0, 0, 0, /* 2306: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2309: pointer.struct.X509_name_st */
            	2314, 0,
            0, 40, 3, /* 2314: struct.X509_name_st */
            	2323, 0,
            	2347, 16,
            	200, 24,
            1, 8, 1, /* 2323: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2328, 0,
            0, 32, 2, /* 2328: struct.stack_st_fake_X509_NAME_ENTRY */
            	2335, 8,
            	360, 24,
            64099, 8, 2, /* 2335: pointer_to_array_of_pointers_to_stack */
            	2342, 0,
            	357, 20,
            0, 8, 1, /* 2342: pointer.X509_NAME_ENTRY */
            	321, 0,
            1, 8, 1, /* 2347: pointer.struct.buf_mem_st */
            	2352, 0,
            0, 24, 1, /* 2352: struct.buf_mem_st */
            	93, 8,
            1, 8, 1, /* 2357: pointer.struct.X509_val_st */
            	2362, 0,
            0, 16, 2, /* 2362: struct.X509_val_st */
            	2369, 0,
            	2369, 8,
            1, 8, 1, /* 2369: pointer.struct.asn1_string_st */
            	2147, 0,
            1, 8, 1, /* 2374: pointer.struct.X509_pubkey_st */
            	2379, 0,
            0, 24, 3, /* 2379: struct.X509_pubkey_st */
            	2152, 0,
            	2241, 8,
            	2388, 16,
            1, 8, 1, /* 2388: pointer.struct.evp_pkey_st */
            	2393, 0,
            0, 56, 4, /* 2393: struct.evp_pkey_st */
            	2404, 16,
            	2412, 24,
            	2420, 32,
            	2741, 48,
            1, 8, 1, /* 2404: pointer.struct.evp_pkey_asn1_method_st */
            	2409, 0,
            0, 0, 0, /* 2409: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 2412: pointer.struct.engine_st */
            	2417, 0,
            0, 0, 0, /* 2417: struct.engine_st */
            0, 8, 5, /* 2420: union.unknown */
            	93, 0,
            	2433, 0,
            	2584, 0,
            	2665, 0,
            	2733, 0,
            1, 8, 1, /* 2433: pointer.struct.rsa_st */
            	2438, 0,
            0, 168, 17, /* 2438: struct.rsa_st */
            	2475, 16,
            	2412, 24,
            	2530, 32,
            	2530, 40,
            	2530, 48,
            	2530, 56,
            	2530, 64,
            	2530, 72,
            	2530, 80,
            	2530, 88,
            	2540, 96,
            	2562, 120,
            	2562, 128,
            	2562, 136,
            	93, 144,
            	2576, 152,
            	2576, 160,
            1, 8, 1, /* 2475: pointer.struct.rsa_meth_st */
            	2480, 0,
            0, 112, 13, /* 2480: struct.rsa_meth_st */
            	124, 0,
            	2509, 8,
            	2509, 16,
            	2509, 24,
            	2509, 32,
            	2512, 40,
            	2515, 48,
            	2518, 56,
            	2518, 64,
            	93, 80,
            	2521, 88,
            	2524, 96,
            	2527, 104,
            64097, 8, 0, /* 2509: pointer.func */
            64097, 8, 0, /* 2512: pointer.func */
            64097, 8, 0, /* 2515: pointer.func */
            64097, 8, 0, /* 2518: pointer.func */
            64097, 8, 0, /* 2521: pointer.func */
            64097, 8, 0, /* 2524: pointer.func */
            64097, 8, 0, /* 2527: pointer.func */
            1, 8, 1, /* 2530: pointer.struct.bignum_st */
            	2535, 0,
            0, 24, 1, /* 2535: struct.bignum_st */
            	1397, 0,
            0, 16, 1, /* 2540: struct.crypto_ex_data_st */
            	2545, 0,
            1, 8, 1, /* 2545: pointer.struct.stack_st_void */
            	2550, 0,
            0, 32, 1, /* 2550: struct.stack_st_void */
            	2555, 0,
            0, 32, 2, /* 2555: struct.stack_st */
            	885, 8,
            	360, 24,
            1, 8, 1, /* 2562: pointer.struct.bn_mont_ctx_st */
            	2567, 0,
            0, 96, 3, /* 2567: struct.bn_mont_ctx_st */
            	2535, 8,
            	2535, 32,
            	2535, 56,
            1, 8, 1, /* 2576: pointer.struct.bn_blinding_st */
            	2581, 0,
            0, 0, 0, /* 2581: struct.bn_blinding_st */
            1, 8, 1, /* 2584: pointer.struct.dsa_st */
            	2589, 0,
            0, 136, 11, /* 2589: struct.dsa_st */
            	2530, 24,
            	2530, 32,
            	2530, 40,
            	2530, 48,
            	2530, 56,
            	2530, 64,
            	2530, 72,
            	2562, 88,
            	2540, 104,
            	2614, 120,
            	2412, 128,
            1, 8, 1, /* 2614: pointer.struct.dsa_method */
            	2619, 0,
            0, 96, 11, /* 2619: struct.dsa_method */
            	124, 0,
            	2644, 8,
            	2647, 16,
            	2650, 24,
            	2653, 32,
            	2656, 40,
            	2659, 48,
            	2659, 56,
            	93, 72,
            	2662, 80,
            	2659, 88,
            64097, 8, 0, /* 2644: pointer.func */
            64097, 8, 0, /* 2647: pointer.func */
            64097, 8, 0, /* 2650: pointer.func */
            64097, 8, 0, /* 2653: pointer.func */
            64097, 8, 0, /* 2656: pointer.func */
            64097, 8, 0, /* 2659: pointer.func */
            64097, 8, 0, /* 2662: pointer.func */
            1, 8, 1, /* 2665: pointer.struct.dh_st */
            	2670, 0,
            0, 144, 12, /* 2670: struct.dh_st */
            	2530, 8,
            	2530, 16,
            	2530, 32,
            	2530, 40,
            	2562, 56,
            	2530, 64,
            	2530, 72,
            	200, 80,
            	2530, 96,
            	2540, 112,
            	2697, 128,
            	2412, 136,
            1, 8, 1, /* 2697: pointer.struct.dh_method */
            	2702, 0,
            0, 72, 8, /* 2702: struct.dh_method */
            	124, 0,
            	2721, 8,
            	2724, 16,
            	2727, 24,
            	2721, 32,
            	2721, 40,
            	93, 56,
            	2730, 64,
            64097, 8, 0, /* 2721: pointer.func */
            64097, 8, 0, /* 2724: pointer.func */
            64097, 8, 0, /* 2727: pointer.func */
            64097, 8, 0, /* 2730: pointer.func */
            1, 8, 1, /* 2733: pointer.struct.ec_key_st */
            	2738, 0,
            0, 0, 0, /* 2738: struct.ec_key_st */
            1, 8, 1, /* 2741: pointer.struct.stack_st_X509_ATTRIBUTE */
            	2746, 0,
            0, 32, 2, /* 2746: struct.stack_st_fake_X509_ATTRIBUTE */
            	2753, 8,
            	360, 24,
            64099, 8, 2, /* 2753: pointer_to_array_of_pointers_to_stack */
            	2760, 0,
            	357, 20,
            0, 8, 1, /* 2760: pointer.X509_ATTRIBUTE */
            	1723, 0,
            1, 8, 1, /* 2765: pointer.struct.stack_st_X509_EXTENSION */
            	2770, 0,
            0, 32, 2, /* 2770: struct.stack_st_fake_X509_EXTENSION */
            	2777, 8,
            	360, 24,
            64099, 8, 2, /* 2777: pointer_to_array_of_pointers_to_stack */
            	2784, 0,
            	357, 20,
            0, 8, 1, /* 2784: pointer.X509_EXTENSION */
            	708, 0,
            0, 24, 1, /* 2789: struct.ASN1_ENCODING_st */
            	200, 0,
            1, 8, 1, /* 2794: pointer.struct.AUTHORITY_KEYID_st */
            	2799, 0,
            0, 0, 0, /* 2799: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 2802: pointer.struct.X509_POLICY_CACHE_st */
            	2807, 0,
            0, 0, 0, /* 2807: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 2810: pointer.struct.stack_st_DIST_POINT */
            	2815, 0,
            0, 32, 2, /* 2815: struct.stack_st_fake_DIST_POINT */
            	2822, 8,
            	360, 24,
            64099, 8, 2, /* 2822: pointer_to_array_of_pointers_to_stack */
            	2829, 0,
            	357, 20,
            0, 8, 1, /* 2829: pointer.DIST_POINT */
            	2834, 0,
            0, 0, 1, /* 2834: DIST_POINT */
            	2839, 0,
            0, 32, 3, /* 2839: struct.DIST_POINT_st */
            	7, 0,
            	433, 8,
            	26, 16,
            1, 8, 1, /* 2848: pointer.struct.stack_st_GENERAL_NAME */
            	2853, 0,
            0, 32, 2, /* 2853: struct.stack_st_fake_GENERAL_NAME */
            	2860, 8,
            	360, 24,
            64099, 8, 2, /* 2860: pointer_to_array_of_pointers_to_stack */
            	2867, 0,
            	357, 20,
            0, 8, 1, /* 2867: pointer.GENERAL_NAME */
            	50, 0,
            1, 8, 1, /* 2872: pointer.struct.NAME_CONSTRAINTS_st */
            	2877, 0,
            0, 0, 0, /* 2877: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 2880: pointer.struct.x509_cert_aux_st */
            	2885, 0,
            0, 40, 5, /* 2885: struct.x509_cert_aux_st */
            	2898, 0,
            	2898, 8,
            	2296, 16,
            	2246, 24,
            	2936, 32,
            1, 8, 1, /* 2898: pointer.struct.stack_st_ASN1_OBJECT */
            	2903, 0,
            0, 32, 2, /* 2903: struct.stack_st_fake_ASN1_OBJECT */
            	2910, 8,
            	360, 24,
            64099, 8, 2, /* 2910: pointer_to_array_of_pointers_to_stack */
            	2917, 0,
            	357, 20,
            0, 8, 1, /* 2917: pointer.ASN1_OBJECT */
            	2922, 0,
            0, 0, 1, /* 2922: ASN1_OBJECT */
            	2927, 0,
            0, 40, 3, /* 2927: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            1, 8, 1, /* 2936: pointer.struct.stack_st_X509_ALGOR */
            	2941, 0,
            0, 32, 2, /* 2941: struct.stack_st_fake_X509_ALGOR */
            	2948, 8,
            	360, 24,
            64099, 8, 2, /* 2948: pointer_to_array_of_pointers_to_stack */
            	2955, 0,
            	357, 20,
            0, 8, 1, /* 2955: pointer.X509_ALGOR */
            	2960, 0,
            0, 0, 1, /* 2960: X509_ALGOR */
            	2965, 0,
            0, 16, 2, /* 2965: struct.X509_algor_st */
            	2972, 0,
            	2986, 8,
            1, 8, 1, /* 2972: pointer.struct.asn1_object_st */
            	2977, 0,
            0, 40, 3, /* 2977: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            1, 8, 1, /* 2986: pointer.struct.asn1_type_st */
            	2991, 0,
            0, 16, 1, /* 2991: struct.asn1_type_st */
            	2996, 8,
            0, 8, 20, /* 2996: union.unknown */
            	93, 0,
            	3039, 0,
            	2972, 0,
            	3044, 0,
            	3049, 0,
            	3054, 0,
            	3059, 0,
            	3064, 0,
            	3069, 0,
            	2080, 0,
            	3074, 0,
            	3079, 0,
            	3084, 0,
            	3089, 0,
            	3094, 0,
            	3099, 0,
            	2070, 0,
            	3039, 0,
            	3039, 0,
            	616, 0,
            1, 8, 1, /* 3039: pointer.struct.asn1_string_st */
            	2075, 0,
            1, 8, 1, /* 3044: pointer.struct.asn1_string_st */
            	2075, 0,
            1, 8, 1, /* 3049: pointer.struct.asn1_string_st */
            	2075, 0,
            1, 8, 1, /* 3054: pointer.struct.asn1_string_st */
            	2075, 0,
            1, 8, 1, /* 3059: pointer.struct.asn1_string_st */
            	2075, 0,
            1, 8, 1, /* 3064: pointer.struct.asn1_string_st */
            	2075, 0,
            1, 8, 1, /* 3069: pointer.struct.asn1_string_st */
            	2075, 0,
            1, 8, 1, /* 3074: pointer.struct.asn1_string_st */
            	2075, 0,
            1, 8, 1, /* 3079: pointer.struct.asn1_string_st */
            	2075, 0,
            1, 8, 1, /* 3084: pointer.struct.asn1_string_st */
            	2075, 0,
            1, 8, 1, /* 3089: pointer.struct.asn1_string_st */
            	2075, 0,
            1, 8, 1, /* 3094: pointer.struct.asn1_string_st */
            	2075, 0,
            1, 8, 1, /* 3099: pointer.struct.asn1_string_st */
            	2075, 0,
            64097, 8, 0, /* 3104: pointer.func */
            1, 8, 1, /* 3107: pointer.struct.buf_mem_st */
            	3112, 0,
            0, 24, 1, /* 3112: struct.buf_mem_st */
            	93, 8,
            0, 16, 1, /* 3117: struct.crypto_ex_data_st */
            	3122, 0,
            1, 8, 1, /* 3122: pointer.struct.stack_st_void */
            	3127, 0,
            0, 32, 1, /* 3127: struct.stack_st_void */
            	3132, 0,
            0, 32, 2, /* 3132: struct.stack_st */
            	885, 8,
            	360, 24,
            0, 136, 11, /* 3139: struct.dsa_st */
            	3164, 24,
            	3164, 32,
            	3164, 40,
            	3164, 48,
            	3164, 56,
            	3164, 64,
            	3164, 72,
            	3174, 88,
            	3117, 104,
            	3188, 120,
            	1379, 128,
            1, 8, 1, /* 3164: pointer.struct.bignum_st */
            	3169, 0,
            0, 24, 1, /* 3169: struct.bignum_st */
            	1397, 0,
            1, 8, 1, /* 3174: pointer.struct.bn_mont_ctx_st */
            	3179, 0,
            0, 96, 3, /* 3179: struct.bn_mont_ctx_st */
            	3169, 8,
            	3169, 32,
            	3169, 56,
            1, 8, 1, /* 3188: pointer.struct.dsa_method */
            	3193, 0,
            0, 96, 11, /* 3193: struct.dsa_method */
            	124, 0,
            	3218, 8,
            	3221, 16,
            	3224, 24,
            	3227, 32,
            	3230, 40,
            	3233, 48,
            	3233, 56,
            	93, 72,
            	3236, 80,
            	3233, 88,
            64097, 8, 0, /* 3218: pointer.func */
            64097, 8, 0, /* 3221: pointer.func */
            64097, 8, 0, /* 3224: pointer.func */
            64097, 8, 0, /* 3227: pointer.func */
            64097, 8, 0, /* 3230: pointer.func */
            64097, 8, 0, /* 3233: pointer.func */
            64097, 8, 0, /* 3236: pointer.func */
            1, 8, 1, /* 3239: pointer.struct.otherName_st */
            	3244, 0,
            0, 16, 2, /* 3244: struct.otherName_st */
            	3251, 0,
            	3265, 8,
            1, 8, 1, /* 3251: pointer.struct.asn1_object_st */
            	3256, 0,
            0, 40, 3, /* 3256: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            1, 8, 1, /* 3265: pointer.struct.asn1_type_st */
            	3270, 0,
            0, 16, 1, /* 3270: struct.asn1_type_st */
            	3275, 8,
            0, 8, 20, /* 3275: union.unknown */
            	93, 0,
            	3318, 0,
            	3251, 0,
            	3328, 0,
            	3333, 0,
            	3338, 0,
            	3343, 0,
            	3348, 0,
            	3353, 0,
            	3358, 0,
            	3363, 0,
            	3368, 0,
            	3373, 0,
            	3378, 0,
            	3383, 0,
            	3388, 0,
            	3393, 0,
            	3318, 0,
            	3318, 0,
            	275, 0,
            1, 8, 1, /* 3318: pointer.struct.asn1_string_st */
            	3323, 0,
            0, 24, 1, /* 3323: struct.asn1_string_st */
            	200, 8,
            1, 8, 1, /* 3328: pointer.struct.asn1_string_st */
            	3323, 0,
            1, 8, 1, /* 3333: pointer.struct.asn1_string_st */
            	3323, 0,
            1, 8, 1, /* 3338: pointer.struct.asn1_string_st */
            	3323, 0,
            1, 8, 1, /* 3343: pointer.struct.asn1_string_st */
            	3323, 0,
            1, 8, 1, /* 3348: pointer.struct.asn1_string_st */
            	3323, 0,
            1, 8, 1, /* 3353: pointer.struct.asn1_string_st */
            	3323, 0,
            1, 8, 1, /* 3358: pointer.struct.asn1_string_st */
            	3323, 0,
            1, 8, 1, /* 3363: pointer.struct.asn1_string_st */
            	3323, 0,
            1, 8, 1, /* 3368: pointer.struct.asn1_string_st */
            	3323, 0,
            1, 8, 1, /* 3373: pointer.struct.asn1_string_st */
            	3323, 0,
            1, 8, 1, /* 3378: pointer.struct.asn1_string_st */
            	3323, 0,
            1, 8, 1, /* 3383: pointer.struct.asn1_string_st */
            	3323, 0,
            1, 8, 1, /* 3388: pointer.struct.asn1_string_st */
            	3323, 0,
            1, 8, 1, /* 3393: pointer.struct.asn1_string_st */
            	3323, 0,
            1, 8, 1, /* 3398: pointer.struct.X509_algor_st */
            	3403, 0,
            0, 16, 2, /* 3403: struct.X509_algor_st */
            	3410, 0,
            	3424, 8,
            1, 8, 1, /* 3410: pointer.struct.asn1_object_st */
            	3415, 0,
            0, 40, 3, /* 3415: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            1, 8, 1, /* 3424: pointer.struct.asn1_type_st */
            	3429, 0,
            0, 16, 1, /* 3429: struct.asn1_type_st */
            	3434, 8,
            0, 8, 20, /* 3434: union.unknown */
            	93, 0,
            	3477, 0,
            	3410, 0,
            	3487, 0,
            	3492, 0,
            	3497, 0,
            	3502, 0,
            	3507, 0,
            	3512, 0,
            	3517, 0,
            	3522, 0,
            	3527, 0,
            	3532, 0,
            	3537, 0,
            	3542, 0,
            	3547, 0,
            	3552, 0,
            	3477, 0,
            	3477, 0,
            	616, 0,
            1, 8, 1, /* 3477: pointer.struct.asn1_string_st */
            	3482, 0,
            0, 24, 1, /* 3482: struct.asn1_string_st */
            	200, 8,
            1, 8, 1, /* 3487: pointer.struct.asn1_string_st */
            	3482, 0,
            1, 8, 1, /* 3492: pointer.struct.asn1_string_st */
            	3482, 0,
            1, 8, 1, /* 3497: pointer.struct.asn1_string_st */
            	3482, 0,
            1, 8, 1, /* 3502: pointer.struct.asn1_string_st */
            	3482, 0,
            1, 8, 1, /* 3507: pointer.struct.asn1_string_st */
            	3482, 0,
            1, 8, 1, /* 3512: pointer.struct.asn1_string_st */
            	3482, 0,
            1, 8, 1, /* 3517: pointer.struct.asn1_string_st */
            	3482, 0,
            1, 8, 1, /* 3522: pointer.struct.asn1_string_st */
            	3482, 0,
            1, 8, 1, /* 3527: pointer.struct.asn1_string_st */
            	3482, 0,
            1, 8, 1, /* 3532: pointer.struct.asn1_string_st */
            	3482, 0,
            1, 8, 1, /* 3537: pointer.struct.asn1_string_st */
            	3482, 0,
            1, 8, 1, /* 3542: pointer.struct.asn1_string_st */
            	3482, 0,
            1, 8, 1, /* 3547: pointer.struct.asn1_string_st */
            	3482, 0,
            1, 8, 1, /* 3552: pointer.struct.asn1_string_st */
            	3482, 0,
            1, 8, 1, /* 3557: pointer.struct.x509_st */
            	3562, 0,
            0, 184, 12, /* 3562: struct.x509_st */
            	1449, 0,
            	472, 8,
            	433, 16,
            	93, 32,
            	1405, 40,
            	561, 104,
            	830, 112,
            	3589, 120,
            	3597, 128,
            	3621, 136,
            	3645, 144,
            	3788, 176,
            1, 8, 1, /* 3589: pointer.struct.X509_POLICY_CACHE_st */
            	3594, 0,
            0, 0, 0, /* 3594: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 3597: pointer.struct.stack_st_DIST_POINT */
            	3602, 0,
            0, 32, 2, /* 3602: struct.stack_st_fake_DIST_POINT */
            	3609, 8,
            	360, 24,
            64099, 8, 2, /* 3609: pointer_to_array_of_pointers_to_stack */
            	3616, 0,
            	357, 20,
            0, 8, 1, /* 3616: pointer.DIST_POINT */
            	2834, 0,
            1, 8, 1, /* 3621: pointer.struct.stack_st_GENERAL_NAME */
            	3626, 0,
            0, 32, 2, /* 3626: struct.stack_st_fake_GENERAL_NAME */
            	3633, 8,
            	360, 24,
            64099, 8, 2, /* 3633: pointer_to_array_of_pointers_to_stack */
            	3640, 0,
            	357, 20,
            0, 8, 1, /* 3640: pointer.GENERAL_NAME */
            	50, 0,
            1, 8, 1, /* 3645: pointer.struct.NAME_CONSTRAINTS_st */
            	3650, 0,
            0, 16, 2, /* 3650: struct.NAME_CONSTRAINTS_st */
            	3657, 0,
            	3657, 8,
            1, 8, 1, /* 3657: pointer.struct.stack_st_GENERAL_SUBTREE */
            	3662, 0,
            0, 32, 2, /* 3662: struct.stack_st_fake_GENERAL_SUBTREE */
            	3669, 8,
            	360, 24,
            64099, 8, 2, /* 3669: pointer_to_array_of_pointers_to_stack */
            	3676, 0,
            	357, 20,
            0, 8, 1, /* 3676: pointer.GENERAL_SUBTREE */
            	3681, 0,
            0, 0, 1, /* 3681: GENERAL_SUBTREE */
            	3686, 0,
            0, 24, 3, /* 3686: struct.GENERAL_SUBTREE_st */
            	3695, 0,
            	3328, 8,
            	3328, 16,
            1, 8, 1, /* 3695: pointer.struct.GENERAL_NAME_st */
            	3700, 0,
            0, 16, 1, /* 3700: struct.GENERAL_NAME_st */
            	3705, 8,
            0, 8, 15, /* 3705: union.unknown */
            	93, 0,
            	3239, 0,
            	3358, 0,
            	3358, 0,
            	3265, 0,
            	3738, 0,
            	3776, 0,
            	3358, 0,
            	3343, 0,
            	3251, 0,
            	3343, 0,
            	3738, 0,
            	3358, 0,
            	3251, 0,
            	3265, 0,
            1, 8, 1, /* 3738: pointer.struct.X509_name_st */
            	3743, 0,
            0, 40, 3, /* 3743: struct.X509_name_st */
            	3752, 0,
            	3107, 16,
            	200, 24,
            1, 8, 1, /* 3752: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3757, 0,
            0, 32, 2, /* 3757: struct.stack_st_fake_X509_NAME_ENTRY */
            	3764, 8,
            	360, 24,
            64099, 8, 2, /* 3764: pointer_to_array_of_pointers_to_stack */
            	3771, 0,
            	357, 20,
            0, 8, 1, /* 3771: pointer.X509_NAME_ENTRY */
            	321, 0,
            1, 8, 1, /* 3776: pointer.struct.EDIPartyName_st */
            	3781, 0,
            0, 16, 2, /* 3781: struct.EDIPartyName_st */
            	3318, 0,
            	3318, 8,
            1, 8, 1, /* 3788: pointer.struct.x509_cert_aux_st */
            	3793, 0,
            0, 40, 5, /* 3793: struct.x509_cert_aux_st */
            	3806, 0,
            	3806, 8,
            	611, 16,
            	561, 24,
            	3830, 32,
            1, 8, 1, /* 3806: pointer.struct.stack_st_ASN1_OBJECT */
            	3811, 0,
            0, 32, 2, /* 3811: struct.stack_st_fake_ASN1_OBJECT */
            	3818, 8,
            	360, 24,
            64099, 8, 2, /* 3818: pointer_to_array_of_pointers_to_stack */
            	3825, 0,
            	357, 20,
            0, 8, 1, /* 3825: pointer.ASN1_OBJECT */
            	2922, 0,
            1, 8, 1, /* 3830: pointer.struct.stack_st_X509_ALGOR */
            	3835, 0,
            0, 32, 2, /* 3835: struct.stack_st_fake_X509_ALGOR */
            	3842, 8,
            	360, 24,
            64099, 8, 2, /* 3842: pointer_to_array_of_pointers_to_stack */
            	3849, 0,
            	357, 20,
            0, 8, 1, /* 3849: pointer.X509_ALGOR */
            	2960, 0,
            1, 8, 1, /* 3854: pointer.struct.ISSUING_DIST_POINT_st */
            	3859, 0,
            0, 0, 0, /* 3859: struct.ISSUING_DIST_POINT_st */
            64097, 8, 0, /* 3862: pointer.func */
            64097, 8, 0, /* 3865: pointer.func */
            0, 0, 1, /* 3868: X509_OBJECT */
            	3873, 0,
            0, 16, 1, /* 3873: struct.x509_object_st */
            	3878, 8,
            0, 8, 4, /* 3878: union.unknown */
            	93, 0,
            	3889, 0,
            	4409, 0,
            	4030, 0,
            1, 8, 1, /* 3889: pointer.struct.x509_st */
            	3894, 0,
            0, 184, 12, /* 3894: struct.x509_st */
            	3921, 0,
            	3398, 8,
            	3497, 16,
            	93, 32,
            	3117, 40,
            	3502, 104,
            	4279, 112,
            	3589, 120,
            	4287, 128,
            	4311, 136,
            	4335, 144,
            	4343, 176,
            1, 8, 1, /* 3921: pointer.struct.x509_cinf_st */
            	3926, 0,
            0, 104, 11, /* 3926: struct.x509_cinf_st */
            	3487, 0,
            	3487, 8,
            	3398, 16,
            	3951, 24,
            	3999, 32,
            	3951, 40,
            	4016, 48,
            	3497, 56,
            	3497, 64,
            	4250, 72,
            	4274, 80,
            1, 8, 1, /* 3951: pointer.struct.X509_name_st */
            	3956, 0,
            0, 40, 3, /* 3956: struct.X509_name_st */
            	3965, 0,
            	3989, 16,
            	200, 24,
            1, 8, 1, /* 3965: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3970, 0,
            0, 32, 2, /* 3970: struct.stack_st_fake_X509_NAME_ENTRY */
            	3977, 8,
            	360, 24,
            64099, 8, 2, /* 3977: pointer_to_array_of_pointers_to_stack */
            	3984, 0,
            	357, 20,
            0, 8, 1, /* 3984: pointer.X509_NAME_ENTRY */
            	321, 0,
            1, 8, 1, /* 3989: pointer.struct.buf_mem_st */
            	3994, 0,
            0, 24, 1, /* 3994: struct.buf_mem_st */
            	93, 8,
            1, 8, 1, /* 3999: pointer.struct.X509_val_st */
            	4004, 0,
            0, 16, 2, /* 4004: struct.X509_val_st */
            	4011, 0,
            	4011, 8,
            1, 8, 1, /* 4011: pointer.struct.asn1_string_st */
            	3482, 0,
            1, 8, 1, /* 4016: pointer.struct.X509_pubkey_st */
            	4021, 0,
            0, 24, 3, /* 4021: struct.X509_pubkey_st */
            	3398, 0,
            	3497, 8,
            	4030, 16,
            1, 8, 1, /* 4030: pointer.struct.evp_pkey_st */
            	4035, 0,
            0, 56, 4, /* 4035: struct.evp_pkey_st */
            	1521, 16,
            	1379, 24,
            	4046, 32,
            	4226, 48,
            0, 8, 5, /* 4046: union.unknown */
            	93, 0,
            	4059, 0,
            	4153, 0,
            	4158, 0,
            	1691, 0,
            1, 8, 1, /* 4059: pointer.struct.rsa_st */
            	4064, 0,
            0, 168, 17, /* 4064: struct.rsa_st */
            	4101, 16,
            	1379, 24,
            	3164, 32,
            	3164, 40,
            	3164, 48,
            	3164, 56,
            	3164, 64,
            	3164, 72,
            	3164, 80,
            	3164, 88,
            	3117, 96,
            	3174, 120,
            	3174, 128,
            	3174, 136,
            	93, 144,
            	1441, 152,
            	1441, 160,
            1, 8, 1, /* 4101: pointer.struct.rsa_meth_st */
            	4106, 0,
            0, 112, 13, /* 4106: struct.rsa_meth_st */
            	124, 0,
            	4135, 8,
            	4135, 16,
            	4135, 24,
            	4135, 32,
            	4138, 40,
            	4141, 48,
            	4144, 56,
            	4144, 64,
            	93, 80,
            	3104, 88,
            	4147, 96,
            	4150, 104,
            64097, 8, 0, /* 4135: pointer.func */
            64097, 8, 0, /* 4138: pointer.func */
            64097, 8, 0, /* 4141: pointer.func */
            64097, 8, 0, /* 4144: pointer.func */
            64097, 8, 0, /* 4147: pointer.func */
            64097, 8, 0, /* 4150: pointer.func */
            1, 8, 1, /* 4153: pointer.struct.dsa_st */
            	3139, 0,
            1, 8, 1, /* 4158: pointer.struct.dh_st */
            	4163, 0,
            0, 144, 12, /* 4163: struct.dh_st */
            	3164, 8,
            	3164, 16,
            	3164, 32,
            	3164, 40,
            	3174, 56,
            	3164, 64,
            	3164, 72,
            	200, 80,
            	3164, 96,
            	3117, 112,
            	4190, 128,
            	1379, 136,
            1, 8, 1, /* 4190: pointer.struct.dh_method */
            	4195, 0,
            0, 72, 8, /* 4195: struct.dh_method */
            	124, 0,
            	4214, 8,
            	4217, 16,
            	4220, 24,
            	4214, 32,
            	4214, 40,
            	93, 56,
            	4223, 64,
            64097, 8, 0, /* 4214: pointer.func */
            64097, 8, 0, /* 4217: pointer.func */
            64097, 8, 0, /* 4220: pointer.func */
            64097, 8, 0, /* 4223: pointer.func */
            1, 8, 1, /* 4226: pointer.struct.stack_st_X509_ATTRIBUTE */
            	4231, 0,
            0, 32, 2, /* 4231: struct.stack_st_fake_X509_ATTRIBUTE */
            	4238, 8,
            	360, 24,
            64099, 8, 2, /* 4238: pointer_to_array_of_pointers_to_stack */
            	4245, 0,
            	357, 20,
            0, 8, 1, /* 4245: pointer.X509_ATTRIBUTE */
            	1723, 0,
            1, 8, 1, /* 4250: pointer.struct.stack_st_X509_EXTENSION */
            	4255, 0,
            0, 32, 2, /* 4255: struct.stack_st_fake_X509_EXTENSION */
            	4262, 8,
            	360, 24,
            64099, 8, 2, /* 4262: pointer_to_array_of_pointers_to_stack */
            	4269, 0,
            	357, 20,
            0, 8, 1, /* 4269: pointer.X509_EXTENSION */
            	708, 0,
            0, 24, 1, /* 4274: struct.ASN1_ENCODING_st */
            	200, 0,
            1, 8, 1, /* 4279: pointer.struct.AUTHORITY_KEYID_st */
            	4284, 0,
            0, 0, 0, /* 4284: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 4287: pointer.struct.stack_st_DIST_POINT */
            	4292, 0,
            0, 32, 2, /* 4292: struct.stack_st_fake_DIST_POINT */
            	4299, 8,
            	360, 24,
            64099, 8, 2, /* 4299: pointer_to_array_of_pointers_to_stack */
            	4306, 0,
            	357, 20,
            0, 8, 1, /* 4306: pointer.DIST_POINT */
            	2834, 0,
            1, 8, 1, /* 4311: pointer.struct.stack_st_GENERAL_NAME */
            	4316, 0,
            0, 32, 2, /* 4316: struct.stack_st_fake_GENERAL_NAME */
            	4323, 8,
            	360, 24,
            64099, 8, 2, /* 4323: pointer_to_array_of_pointers_to_stack */
            	4330, 0,
            	357, 20,
            0, 8, 1, /* 4330: pointer.GENERAL_NAME */
            	50, 0,
            1, 8, 1, /* 4335: pointer.struct.NAME_CONSTRAINTS_st */
            	4340, 0,
            0, 0, 0, /* 4340: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 4343: pointer.struct.x509_cert_aux_st */
            	4348, 0,
            0, 40, 5, /* 4348: struct.x509_cert_aux_st */
            	4361, 0,
            	4361, 8,
            	3552, 16,
            	3502, 24,
            	4385, 32,
            1, 8, 1, /* 4361: pointer.struct.stack_st_ASN1_OBJECT */
            	4366, 0,
            0, 32, 2, /* 4366: struct.stack_st_fake_ASN1_OBJECT */
            	4373, 8,
            	360, 24,
            64099, 8, 2, /* 4373: pointer_to_array_of_pointers_to_stack */
            	4380, 0,
            	357, 20,
            0, 8, 1, /* 4380: pointer.ASN1_OBJECT */
            	2922, 0,
            1, 8, 1, /* 4385: pointer.struct.stack_st_X509_ALGOR */
            	4390, 0,
            0, 32, 2, /* 4390: struct.stack_st_fake_X509_ALGOR */
            	4397, 8,
            	360, 24,
            64099, 8, 2, /* 4397: pointer_to_array_of_pointers_to_stack */
            	4404, 0,
            	357, 20,
            0, 8, 1, /* 4404: pointer.X509_ALGOR */
            	2960, 0,
            1, 8, 1, /* 4409: pointer.struct.X509_crl_st */
            	4414, 0,
            0, 120, 10, /* 4414: struct.X509_crl_st */
            	4437, 0,
            	3398, 8,
            	3497, 16,
            	4279, 32,
            	3854, 40,
            	3487, 56,
            	3487, 64,
            	844, 96,
            	890, 104,
            	898, 112,
            1, 8, 1, /* 4437: pointer.struct.X509_crl_info_st */
            	4442, 0,
            0, 80, 8, /* 4442: struct.X509_crl_info_st */
            	3487, 0,
            	3398, 8,
            	3951, 16,
            	4011, 24,
            	4011, 32,
            	4461, 40,
            	4250, 48,
            	4274, 56,
            1, 8, 1, /* 4461: pointer.struct.stack_st_X509_REVOKED */
            	4466, 0,
            0, 32, 2, /* 4466: struct.stack_st_fake_X509_REVOKED */
            	4473, 8,
            	360, 24,
            64099, 8, 2, /* 4473: pointer_to_array_of_pointers_to_stack */
            	4480, 0,
            	357, 20,
            0, 8, 1, /* 4480: pointer.X509_REVOKED */
            	653, 0,
            0, 32, 3, /* 4485: struct.x509_lookup_st */
            	4494, 8,
            	93, 16,
            	4543, 24,
            1, 8, 1, /* 4494: pointer.struct.x509_lookup_method_st */
            	4499, 0,
            0, 80, 10, /* 4499: struct.x509_lookup_method_st */
            	124, 0,
            	4522, 8,
            	4525, 16,
            	4522, 24,
            	4522, 32,
            	4528, 40,
            	4531, 48,
            	4534, 56,
            	4537, 64,
            	4540, 72,
            64097, 8, 0, /* 4522: pointer.func */
            64097, 8, 0, /* 4525: pointer.func */
            64097, 8, 0, /* 4528: pointer.func */
            64097, 8, 0, /* 4531: pointer.func */
            64097, 8, 0, /* 4534: pointer.func */
            64097, 8, 0, /* 4537: pointer.func */
            64097, 8, 0, /* 4540: pointer.func */
            1, 8, 1, /* 4543: pointer.struct.x509_store_st */
            	4548, 0,
            0, 144, 15, /* 4548: struct.x509_store_st */
            	4581, 8,
            	4605, 16,
            	4634, 24,
            	4646, 32,
            	4649, 40,
            	4652, 48,
            	4655, 56,
            	4646, 64,
            	4658, 72,
            	4661, 80,
            	4664, 88,
            	3865, 96,
            	3862, 104,
            	4646, 112,
            	3117, 120,
            1, 8, 1, /* 4581: pointer.struct.stack_st_X509_OBJECT */
            	4586, 0,
            0, 32, 2, /* 4586: struct.stack_st_fake_X509_OBJECT */
            	4593, 8,
            	360, 24,
            64099, 8, 2, /* 4593: pointer_to_array_of_pointers_to_stack */
            	4600, 0,
            	357, 20,
            0, 8, 1, /* 4600: pointer.X509_OBJECT */
            	3868, 0,
            1, 8, 1, /* 4605: pointer.struct.stack_st_X509_LOOKUP */
            	4610, 0,
            0, 32, 2, /* 4610: struct.stack_st_fake_X509_LOOKUP */
            	4617, 8,
            	360, 24,
            64099, 8, 2, /* 4617: pointer_to_array_of_pointers_to_stack */
            	4624, 0,
            	357, 20,
            0, 8, 1, /* 4624: pointer.X509_LOOKUP */
            	4629, 0,
            0, 0, 1, /* 4629: X509_LOOKUP */
            	4485, 0,
            1, 8, 1, /* 4634: pointer.struct.X509_VERIFY_PARAM_st */
            	4639, 0,
            0, 56, 2, /* 4639: struct.X509_VERIFY_PARAM_st */
            	93, 0,
            	4361, 48,
            64097, 8, 0, /* 4646: pointer.func */
            64097, 8, 0, /* 4649: pointer.func */
            64097, 8, 0, /* 4652: pointer.func */
            64097, 8, 0, /* 4655: pointer.func */
            64097, 8, 0, /* 4658: pointer.func */
            64097, 8, 0, /* 4661: pointer.func */
            64097, 8, 0, /* 4664: pointer.func */
            0, 248, 25, /* 4667: struct.x509_store_ctx_st */
            	4720, 0,
            	3557, 16,
            	4845, 24,
            	4874, 32,
            	4806, 40,
            	898, 48,
            	4818, 56,
            	4821, 64,
            	4824, 72,
            	4827, 80,
            	4818, 88,
            	4830, 96,
            	4833, 104,
            	4836, 112,
            	4818, 120,
            	4839, 128,
            	4842, 136,
            	4818, 144,
            	4845, 160,
            	904, 168,
            	3557, 192,
            	3557, 200,
            	797, 208,
            	4898, 224,
            	1405, 232,
            1, 8, 1, /* 4720: pointer.struct.x509_store_st */
            	4725, 0,
            0, 144, 15, /* 4725: struct.x509_store_st */
            	4758, 8,
            	4782, 16,
            	4806, 24,
            	4818, 32,
            	4821, 40,
            	4824, 48,
            	4827, 56,
            	4818, 64,
            	4830, 72,
            	4833, 80,
            	4836, 88,
            	4839, 96,
            	4842, 104,
            	4818, 112,
            	1405, 120,
            1, 8, 1, /* 4758: pointer.struct.stack_st_X509_OBJECT */
            	4763, 0,
            0, 32, 2, /* 4763: struct.stack_st_fake_X509_OBJECT */
            	4770, 8,
            	360, 24,
            64099, 8, 2, /* 4770: pointer_to_array_of_pointers_to_stack */
            	4777, 0,
            	357, 20,
            0, 8, 1, /* 4777: pointer.X509_OBJECT */
            	3868, 0,
            1, 8, 1, /* 4782: pointer.struct.stack_st_X509_LOOKUP */
            	4787, 0,
            0, 32, 2, /* 4787: struct.stack_st_fake_X509_LOOKUP */
            	4794, 8,
            	360, 24,
            64099, 8, 2, /* 4794: pointer_to_array_of_pointers_to_stack */
            	4801, 0,
            	357, 20,
            0, 8, 1, /* 4801: pointer.X509_LOOKUP */
            	4629, 0,
            1, 8, 1, /* 4806: pointer.struct.X509_VERIFY_PARAM_st */
            	4811, 0,
            0, 56, 2, /* 4811: struct.X509_VERIFY_PARAM_st */
            	93, 0,
            	3806, 48,
            64097, 8, 0, /* 4818: pointer.func */
            64097, 8, 0, /* 4821: pointer.func */
            64097, 8, 0, /* 4824: pointer.func */
            64097, 8, 0, /* 4827: pointer.func */
            64097, 8, 0, /* 4830: pointer.func */
            64097, 8, 0, /* 4833: pointer.func */
            64097, 8, 0, /* 4836: pointer.func */
            64097, 8, 0, /* 4839: pointer.func */
            64097, 8, 0, /* 4842: pointer.func */
            1, 8, 1, /* 4845: pointer.struct.stack_st_X509 */
            	4850, 0,
            0, 32, 2, /* 4850: struct.stack_st_fake_X509 */
            	4857, 8,
            	360, 24,
            64099, 8, 2, /* 4857: pointer_to_array_of_pointers_to_stack */
            	4864, 0,
            	357, 20,
            0, 8, 1, /* 4864: pointer.X509 */
            	4869, 0,
            0, 0, 1, /* 4869: X509 */
            	2085, 0,
            1, 8, 1, /* 4874: pointer.struct.stack_st_X509_CRL */
            	4879, 0,
            0, 32, 2, /* 4879: struct.stack_st_fake_X509_CRL */
            	4886, 8,
            	360, 24,
            64099, 8, 2, /* 4886: pointer_to_array_of_pointers_to_stack */
            	4893, 0,
            	357, 20,
            0, 8, 1, /* 4893: pointer.X509_CRL */
            	1277, 0,
            1, 8, 1, /* 4898: pointer.struct.x509_store_ctx_st */
            	4667, 0,
            0, 1, 0, /* 4903: char */
        },
        .arg_entity_index = { 4898, 4720, 3557, 4845, },
        .ret_entity_index = 357,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_arg(args_addr, arg_d);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    X509_STORE_CTX * new_arg_a = *((X509_STORE_CTX * *)new_args->args[0]);

    X509_STORE * new_arg_b = *((X509_STORE * *)new_args->args[1]);

    X509 * new_arg_c = *((X509 * *)new_args->args[2]);

    STACK_OF(X509) * new_arg_d = *((STACK_OF(X509) * *)new_args->args[3]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_X509_STORE_CTX_init)(X509_STORE_CTX *,X509_STORE *,X509 *,STACK_OF(X509) *);
    orig_X509_STORE_CTX_init = dlsym(RTLD_NEXT, "X509_STORE_CTX_init");
    *new_ret_ptr = (*orig_X509_STORE_CTX_init)(new_arg_a,new_arg_b,new_arg_c,new_arg_d);

    syscall(889);

    return ret;
}

