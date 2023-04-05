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

void bb_X509_STORE_CTX_free(X509_STORE_CTX * arg_a);

void X509_STORE_CTX_free(X509_STORE_CTX * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("X509_STORE_CTX_free called %lu\n", in_lib);
    if (!in_lib)
        bb_X509_STORE_CTX_free(arg_a);
    else {
        void (*orig_X509_STORE_CTX_free)(X509_STORE_CTX *);
        orig_X509_STORE_CTX_free = dlsym(RTLD_NEXT, "X509_STORE_CTX_free");
        orig_X509_STORE_CTX_free(arg_a);
    }
}

void bb_X509_STORE_CTX_free(X509_STORE_CTX * arg_a) 
{
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
            1, 8, 1, /* 1282: pointer.struct.asn1_string_st */
            	1287, 0,
            0, 24, 1, /* 1287: struct.asn1_string_st */
            	200, 8,
            1, 8, 1, /* 1292: pointer.struct.rsa_meth_st */
            	1297, 0,
            0, 112, 13, /* 1297: struct.rsa_meth_st */
            	124, 0,
            	1326, 8,
            	1326, 16,
            	1326, 24,
            	1326, 32,
            	1329, 40,
            	1332, 48,
            	1335, 56,
            	1335, 64,
            	93, 80,
            	1338, 88,
            	1341, 96,
            	1344, 104,
            64097, 8, 0, /* 1326: pointer.func */
            64097, 8, 0, /* 1329: pointer.func */
            64097, 8, 0, /* 1332: pointer.func */
            64097, 8, 0, /* 1335: pointer.func */
            64097, 8, 0, /* 1338: pointer.func */
            64097, 8, 0, /* 1341: pointer.func */
            64097, 8, 0, /* 1344: pointer.func */
            1, 8, 1, /* 1347: pointer.struct.asn1_string_st */
            	1287, 0,
            0, 184, 12, /* 1352: struct.x509_st */
            	1379, 0,
            	1419, 8,
            	1508, 16,
            	93, 32,
            	1815, 40,
            	1513, 104,
            	2416, 112,
            	2424, 120,
            	2432, 128,
            	2470, 136,
            	2494, 144,
            	2502, 176,
            1, 8, 1, /* 1379: pointer.struct.x509_cinf_st */
            	1384, 0,
            0, 104, 11, /* 1384: struct.x509_cinf_st */
            	1409, 0,
            	1409, 8,
            	1419, 16,
            	1576, 24,
            	1624, 32,
            	1576, 40,
            	1641, 48,
            	1508, 56,
            	1508, 64,
            	2387, 72,
            	2411, 80,
            1, 8, 1, /* 1409: pointer.struct.asn1_string_st */
            	1414, 0,
            0, 24, 1, /* 1414: struct.asn1_string_st */
            	200, 8,
            1, 8, 1, /* 1419: pointer.struct.X509_algor_st */
            	1424, 0,
            0, 16, 2, /* 1424: struct.X509_algor_st */
            	1431, 0,
            	1445, 8,
            1, 8, 1, /* 1431: pointer.struct.asn1_object_st */
            	1436, 0,
            0, 40, 3, /* 1436: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            1, 8, 1, /* 1445: pointer.struct.asn1_type_st */
            	1450, 0,
            0, 16, 1, /* 1450: struct.asn1_type_st */
            	1455, 8,
            0, 8, 20, /* 1455: union.unknown */
            	93, 0,
            	1498, 0,
            	1431, 0,
            	1409, 0,
            	1503, 0,
            	1508, 0,
            	1513, 0,
            	1518, 0,
            	1523, 0,
            	1528, 0,
            	1533, 0,
            	1538, 0,
            	1543, 0,
            	1548, 0,
            	1553, 0,
            	1558, 0,
            	1563, 0,
            	1498, 0,
            	1498, 0,
            	1568, 0,
            1, 8, 1, /* 1498: pointer.struct.asn1_string_st */
            	1414, 0,
            1, 8, 1, /* 1503: pointer.struct.asn1_string_st */
            	1414, 0,
            1, 8, 1, /* 1508: pointer.struct.asn1_string_st */
            	1414, 0,
            1, 8, 1, /* 1513: pointer.struct.asn1_string_st */
            	1414, 0,
            1, 8, 1, /* 1518: pointer.struct.asn1_string_st */
            	1414, 0,
            1, 8, 1, /* 1523: pointer.struct.asn1_string_st */
            	1414, 0,
            1, 8, 1, /* 1528: pointer.struct.asn1_string_st */
            	1414, 0,
            1, 8, 1, /* 1533: pointer.struct.asn1_string_st */
            	1414, 0,
            1, 8, 1, /* 1538: pointer.struct.asn1_string_st */
            	1414, 0,
            1, 8, 1, /* 1543: pointer.struct.asn1_string_st */
            	1414, 0,
            1, 8, 1, /* 1548: pointer.struct.asn1_string_st */
            	1414, 0,
            1, 8, 1, /* 1553: pointer.struct.asn1_string_st */
            	1414, 0,
            1, 8, 1, /* 1558: pointer.struct.asn1_string_st */
            	1414, 0,
            1, 8, 1, /* 1563: pointer.struct.asn1_string_st */
            	1414, 0,
            1, 8, 1, /* 1568: pointer.struct.ASN1_VALUE_st */
            	1573, 0,
            0, 0, 0, /* 1573: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1576: pointer.struct.X509_name_st */
            	1581, 0,
            0, 40, 3, /* 1581: struct.X509_name_st */
            	1590, 0,
            	1614, 16,
            	200, 24,
            1, 8, 1, /* 1590: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1595, 0,
            0, 32, 2, /* 1595: struct.stack_st_fake_X509_NAME_ENTRY */
            	1602, 8,
            	360, 24,
            64099, 8, 2, /* 1602: pointer_to_array_of_pointers_to_stack */
            	1609, 0,
            	357, 20,
            0, 8, 1, /* 1609: pointer.X509_NAME_ENTRY */
            	321, 0,
            1, 8, 1, /* 1614: pointer.struct.buf_mem_st */
            	1619, 0,
            0, 24, 1, /* 1619: struct.buf_mem_st */
            	93, 8,
            1, 8, 1, /* 1624: pointer.struct.X509_val_st */
            	1629, 0,
            0, 16, 2, /* 1629: struct.X509_val_st */
            	1636, 0,
            	1636, 8,
            1, 8, 1, /* 1636: pointer.struct.asn1_string_st */
            	1414, 0,
            1, 8, 1, /* 1641: pointer.struct.X509_pubkey_st */
            	1646, 0,
            0, 24, 3, /* 1646: struct.X509_pubkey_st */
            	1419, 0,
            	1508, 8,
            	1655, 16,
            1, 8, 1, /* 1655: pointer.struct.evp_pkey_st */
            	1660, 0,
            0, 56, 4, /* 1660: struct.evp_pkey_st */
            	1671, 16,
            	1679, 24,
            	1687, 32,
            	2016, 48,
            1, 8, 1, /* 1671: pointer.struct.evp_pkey_asn1_method_st */
            	1676, 0,
            0, 0, 0, /* 1676: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 1679: pointer.struct.engine_st */
            	1684, 0,
            0, 0, 0, /* 1684: struct.engine_st */
            0, 8, 5, /* 1687: union.unknown */
            	93, 0,
            	1700, 0,
            	1859, 0,
            	1940, 0,
            	2008, 0,
            1, 8, 1, /* 1700: pointer.struct.rsa_st */
            	1705, 0,
            0, 168, 17, /* 1705: struct.rsa_st */
            	1742, 16,
            	1679, 24,
            	1797, 32,
            	1797, 40,
            	1797, 48,
            	1797, 56,
            	1797, 64,
            	1797, 72,
            	1797, 80,
            	1797, 88,
            	1815, 96,
            	1837, 120,
            	1837, 128,
            	1837, 136,
            	93, 144,
            	1851, 152,
            	1851, 160,
            1, 8, 1, /* 1742: pointer.struct.rsa_meth_st */
            	1747, 0,
            0, 112, 13, /* 1747: struct.rsa_meth_st */
            	124, 0,
            	1776, 8,
            	1776, 16,
            	1776, 24,
            	1776, 32,
            	1779, 40,
            	1782, 48,
            	1785, 56,
            	1785, 64,
            	93, 80,
            	1788, 88,
            	1791, 96,
            	1794, 104,
            64097, 8, 0, /* 1776: pointer.func */
            64097, 8, 0, /* 1779: pointer.func */
            64097, 8, 0, /* 1782: pointer.func */
            64097, 8, 0, /* 1785: pointer.func */
            64097, 8, 0, /* 1788: pointer.func */
            64097, 8, 0, /* 1791: pointer.func */
            64097, 8, 0, /* 1794: pointer.func */
            1, 8, 1, /* 1797: pointer.struct.bignum_st */
            	1802, 0,
            0, 24, 1, /* 1802: struct.bignum_st */
            	1807, 0,
            1, 8, 1, /* 1807: pointer.unsigned int */
            	1812, 0,
            0, 4, 0, /* 1812: unsigned int */
            0, 16, 1, /* 1815: struct.crypto_ex_data_st */
            	1820, 0,
            1, 8, 1, /* 1820: pointer.struct.stack_st_void */
            	1825, 0,
            0, 32, 1, /* 1825: struct.stack_st_void */
            	1830, 0,
            0, 32, 2, /* 1830: struct.stack_st */
            	885, 8,
            	360, 24,
            1, 8, 1, /* 1837: pointer.struct.bn_mont_ctx_st */
            	1842, 0,
            0, 96, 3, /* 1842: struct.bn_mont_ctx_st */
            	1802, 8,
            	1802, 32,
            	1802, 56,
            1, 8, 1, /* 1851: pointer.struct.bn_blinding_st */
            	1856, 0,
            0, 0, 0, /* 1856: struct.bn_blinding_st */
            1, 8, 1, /* 1859: pointer.struct.dsa_st */
            	1864, 0,
            0, 136, 11, /* 1864: struct.dsa_st */
            	1797, 24,
            	1797, 32,
            	1797, 40,
            	1797, 48,
            	1797, 56,
            	1797, 64,
            	1797, 72,
            	1837, 88,
            	1815, 104,
            	1889, 120,
            	1679, 128,
            1, 8, 1, /* 1889: pointer.struct.dsa_method */
            	1894, 0,
            0, 96, 11, /* 1894: struct.dsa_method */
            	124, 0,
            	1919, 8,
            	1922, 16,
            	1925, 24,
            	1928, 32,
            	1931, 40,
            	1934, 48,
            	1934, 56,
            	93, 72,
            	1937, 80,
            	1934, 88,
            64097, 8, 0, /* 1919: pointer.func */
            64097, 8, 0, /* 1922: pointer.func */
            64097, 8, 0, /* 1925: pointer.func */
            64097, 8, 0, /* 1928: pointer.func */
            64097, 8, 0, /* 1931: pointer.func */
            64097, 8, 0, /* 1934: pointer.func */
            64097, 8, 0, /* 1937: pointer.func */
            1, 8, 1, /* 1940: pointer.struct.dh_st */
            	1945, 0,
            0, 144, 12, /* 1945: struct.dh_st */
            	1797, 8,
            	1797, 16,
            	1797, 32,
            	1797, 40,
            	1837, 56,
            	1797, 64,
            	1797, 72,
            	200, 80,
            	1797, 96,
            	1815, 112,
            	1972, 128,
            	1679, 136,
            1, 8, 1, /* 1972: pointer.struct.dh_method */
            	1977, 0,
            0, 72, 8, /* 1977: struct.dh_method */
            	124, 0,
            	1996, 8,
            	1999, 16,
            	2002, 24,
            	1996, 32,
            	1996, 40,
            	93, 56,
            	2005, 64,
            64097, 8, 0, /* 1996: pointer.func */
            64097, 8, 0, /* 1999: pointer.func */
            64097, 8, 0, /* 2002: pointer.func */
            64097, 8, 0, /* 2005: pointer.func */
            1, 8, 1, /* 2008: pointer.struct.ec_key_st */
            	2013, 0,
            0, 0, 0, /* 2013: struct.ec_key_st */
            1, 8, 1, /* 2016: pointer.struct.stack_st_X509_ATTRIBUTE */
            	2021, 0,
            0, 32, 2, /* 2021: struct.stack_st_fake_X509_ATTRIBUTE */
            	2028, 8,
            	360, 24,
            64099, 8, 2, /* 2028: pointer_to_array_of_pointers_to_stack */
            	2035, 0,
            	357, 20,
            0, 8, 1, /* 2035: pointer.X509_ATTRIBUTE */
            	2040, 0,
            0, 0, 1, /* 2040: X509_ATTRIBUTE */
            	2045, 0,
            0, 24, 2, /* 2045: struct.x509_attributes_st */
            	2052, 0,
            	2066, 16,
            1, 8, 1, /* 2052: pointer.struct.asn1_object_st */
            	2057, 0,
            0, 40, 3, /* 2057: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            0, 8, 3, /* 2066: union.unknown */
            	93, 0,
            	2075, 0,
            	2254, 0,
            1, 8, 1, /* 2075: pointer.struct.stack_st_ASN1_TYPE */
            	2080, 0,
            0, 32, 2, /* 2080: struct.stack_st_fake_ASN1_TYPE */
            	2087, 8,
            	360, 24,
            64099, 8, 2, /* 2087: pointer_to_array_of_pointers_to_stack */
            	2094, 0,
            	357, 20,
            0, 8, 1, /* 2094: pointer.ASN1_TYPE */
            	2099, 0,
            0, 0, 1, /* 2099: ASN1_TYPE */
            	2104, 0,
            0, 16, 1, /* 2104: struct.asn1_type_st */
            	2109, 8,
            0, 8, 20, /* 2109: union.unknown */
            	93, 0,
            	2152, 0,
            	2162, 0,
            	2176, 0,
            	2181, 0,
            	2186, 0,
            	2191, 0,
            	2196, 0,
            	2201, 0,
            	2206, 0,
            	2211, 0,
            	2216, 0,
            	2221, 0,
            	2226, 0,
            	2231, 0,
            	2236, 0,
            	2241, 0,
            	2152, 0,
            	2152, 0,
            	2246, 0,
            1, 8, 1, /* 2152: pointer.struct.asn1_string_st */
            	2157, 0,
            0, 24, 1, /* 2157: struct.asn1_string_st */
            	200, 8,
            1, 8, 1, /* 2162: pointer.struct.asn1_object_st */
            	2167, 0,
            0, 40, 3, /* 2167: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            1, 8, 1, /* 2176: pointer.struct.asn1_string_st */
            	2157, 0,
            1, 8, 1, /* 2181: pointer.struct.asn1_string_st */
            	2157, 0,
            1, 8, 1, /* 2186: pointer.struct.asn1_string_st */
            	2157, 0,
            1, 8, 1, /* 2191: pointer.struct.asn1_string_st */
            	2157, 0,
            1, 8, 1, /* 2196: pointer.struct.asn1_string_st */
            	2157, 0,
            1, 8, 1, /* 2201: pointer.struct.asn1_string_st */
            	2157, 0,
            1, 8, 1, /* 2206: pointer.struct.asn1_string_st */
            	2157, 0,
            1, 8, 1, /* 2211: pointer.struct.asn1_string_st */
            	2157, 0,
            1, 8, 1, /* 2216: pointer.struct.asn1_string_st */
            	2157, 0,
            1, 8, 1, /* 2221: pointer.struct.asn1_string_st */
            	2157, 0,
            1, 8, 1, /* 2226: pointer.struct.asn1_string_st */
            	2157, 0,
            1, 8, 1, /* 2231: pointer.struct.asn1_string_st */
            	2157, 0,
            1, 8, 1, /* 2236: pointer.struct.asn1_string_st */
            	2157, 0,
            1, 8, 1, /* 2241: pointer.struct.asn1_string_st */
            	2157, 0,
            1, 8, 1, /* 2246: pointer.struct.ASN1_VALUE_st */
            	2251, 0,
            0, 0, 0, /* 2251: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2254: pointer.struct.asn1_type_st */
            	2259, 0,
            0, 16, 1, /* 2259: struct.asn1_type_st */
            	2264, 8,
            0, 8, 20, /* 2264: union.unknown */
            	93, 0,
            	2307, 0,
            	2052, 0,
            	2317, 0,
            	2322, 0,
            	2327, 0,
            	2332, 0,
            	2337, 0,
            	2342, 0,
            	2347, 0,
            	2352, 0,
            	2357, 0,
            	2362, 0,
            	2367, 0,
            	2372, 0,
            	2377, 0,
            	2382, 0,
            	2307, 0,
            	2307, 0,
            	616, 0,
            1, 8, 1, /* 2307: pointer.struct.asn1_string_st */
            	2312, 0,
            0, 24, 1, /* 2312: struct.asn1_string_st */
            	200, 8,
            1, 8, 1, /* 2317: pointer.struct.asn1_string_st */
            	2312, 0,
            1, 8, 1, /* 2322: pointer.struct.asn1_string_st */
            	2312, 0,
            1, 8, 1, /* 2327: pointer.struct.asn1_string_st */
            	2312, 0,
            1, 8, 1, /* 2332: pointer.struct.asn1_string_st */
            	2312, 0,
            1, 8, 1, /* 2337: pointer.struct.asn1_string_st */
            	2312, 0,
            1, 8, 1, /* 2342: pointer.struct.asn1_string_st */
            	2312, 0,
            1, 8, 1, /* 2347: pointer.struct.asn1_string_st */
            	2312, 0,
            1, 8, 1, /* 2352: pointer.struct.asn1_string_st */
            	2312, 0,
            1, 8, 1, /* 2357: pointer.struct.asn1_string_st */
            	2312, 0,
            1, 8, 1, /* 2362: pointer.struct.asn1_string_st */
            	2312, 0,
            1, 8, 1, /* 2367: pointer.struct.asn1_string_st */
            	2312, 0,
            1, 8, 1, /* 2372: pointer.struct.asn1_string_st */
            	2312, 0,
            1, 8, 1, /* 2377: pointer.struct.asn1_string_st */
            	2312, 0,
            1, 8, 1, /* 2382: pointer.struct.asn1_string_st */
            	2312, 0,
            1, 8, 1, /* 2387: pointer.struct.stack_st_X509_EXTENSION */
            	2392, 0,
            0, 32, 2, /* 2392: struct.stack_st_fake_X509_EXTENSION */
            	2399, 8,
            	360, 24,
            64099, 8, 2, /* 2399: pointer_to_array_of_pointers_to_stack */
            	2406, 0,
            	357, 20,
            0, 8, 1, /* 2406: pointer.X509_EXTENSION */
            	708, 0,
            0, 24, 1, /* 2411: struct.ASN1_ENCODING_st */
            	200, 0,
            1, 8, 1, /* 2416: pointer.struct.AUTHORITY_KEYID_st */
            	2421, 0,
            0, 0, 0, /* 2421: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 2424: pointer.struct.X509_POLICY_CACHE_st */
            	2429, 0,
            0, 0, 0, /* 2429: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 2432: pointer.struct.stack_st_DIST_POINT */
            	2437, 0,
            0, 32, 2, /* 2437: struct.stack_st_fake_DIST_POINT */
            	2444, 8,
            	360, 24,
            64099, 8, 2, /* 2444: pointer_to_array_of_pointers_to_stack */
            	2451, 0,
            	357, 20,
            0, 8, 1, /* 2451: pointer.DIST_POINT */
            	2456, 0,
            0, 0, 1, /* 2456: DIST_POINT */
            	2461, 0,
            0, 32, 3, /* 2461: struct.DIST_POINT_st */
            	7, 0,
            	433, 8,
            	26, 16,
            1, 8, 1, /* 2470: pointer.struct.stack_st_GENERAL_NAME */
            	2475, 0,
            0, 32, 2, /* 2475: struct.stack_st_fake_GENERAL_NAME */
            	2482, 8,
            	360, 24,
            64099, 8, 2, /* 2482: pointer_to_array_of_pointers_to_stack */
            	2489, 0,
            	357, 20,
            0, 8, 1, /* 2489: pointer.GENERAL_NAME */
            	50, 0,
            1, 8, 1, /* 2494: pointer.struct.NAME_CONSTRAINTS_st */
            	2499, 0,
            0, 0, 0, /* 2499: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 2502: pointer.struct.x509_cert_aux_st */
            	2507, 0,
            0, 40, 5, /* 2507: struct.x509_cert_aux_st */
            	2520, 0,
            	2520, 8,
            	1563, 16,
            	1513, 24,
            	2558, 32,
            1, 8, 1, /* 2520: pointer.struct.stack_st_ASN1_OBJECT */
            	2525, 0,
            0, 32, 2, /* 2525: struct.stack_st_fake_ASN1_OBJECT */
            	2532, 8,
            	360, 24,
            64099, 8, 2, /* 2532: pointer_to_array_of_pointers_to_stack */
            	2539, 0,
            	357, 20,
            0, 8, 1, /* 2539: pointer.ASN1_OBJECT */
            	2544, 0,
            0, 0, 1, /* 2544: ASN1_OBJECT */
            	2549, 0,
            0, 40, 3, /* 2549: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            1, 8, 1, /* 2558: pointer.struct.stack_st_X509_ALGOR */
            	2563, 0,
            0, 32, 2, /* 2563: struct.stack_st_fake_X509_ALGOR */
            	2570, 8,
            	360, 24,
            64099, 8, 2, /* 2570: pointer_to_array_of_pointers_to_stack */
            	2577, 0,
            	357, 20,
            0, 8, 1, /* 2577: pointer.X509_ALGOR */
            	2582, 0,
            0, 0, 1, /* 2582: X509_ALGOR */
            	2587, 0,
            0, 16, 2, /* 2587: struct.X509_algor_st */
            	2594, 0,
            	2608, 8,
            1, 8, 1, /* 2594: pointer.struct.asn1_object_st */
            	2599, 0,
            0, 40, 3, /* 2599: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            1, 8, 1, /* 2608: pointer.struct.asn1_type_st */
            	2613, 0,
            0, 16, 1, /* 2613: struct.asn1_type_st */
            	2618, 8,
            0, 8, 20, /* 2618: union.unknown */
            	93, 0,
            	1347, 0,
            	2594, 0,
            	2661, 0,
            	2666, 0,
            	2671, 0,
            	2676, 0,
            	2681, 0,
            	2686, 0,
            	1282, 0,
            	2691, 0,
            	2696, 0,
            	2701, 0,
            	2706, 0,
            	2711, 0,
            	2716, 0,
            	2721, 0,
            	1347, 0,
            	1347, 0,
            	616, 0,
            1, 8, 1, /* 2661: pointer.struct.asn1_string_st */
            	1287, 0,
            1, 8, 1, /* 2666: pointer.struct.asn1_string_st */
            	1287, 0,
            1, 8, 1, /* 2671: pointer.struct.asn1_string_st */
            	1287, 0,
            1, 8, 1, /* 2676: pointer.struct.asn1_string_st */
            	1287, 0,
            1, 8, 1, /* 2681: pointer.struct.asn1_string_st */
            	1287, 0,
            1, 8, 1, /* 2686: pointer.struct.asn1_string_st */
            	1287, 0,
            1, 8, 1, /* 2691: pointer.struct.asn1_string_st */
            	1287, 0,
            1, 8, 1, /* 2696: pointer.struct.asn1_string_st */
            	1287, 0,
            1, 8, 1, /* 2701: pointer.struct.asn1_string_st */
            	1287, 0,
            1, 8, 1, /* 2706: pointer.struct.asn1_string_st */
            	1287, 0,
            1, 8, 1, /* 2711: pointer.struct.asn1_string_st */
            	1287, 0,
            1, 8, 1, /* 2716: pointer.struct.asn1_string_st */
            	1287, 0,
            1, 8, 1, /* 2721: pointer.struct.asn1_string_st */
            	1287, 0,
            1, 8, 1, /* 2726: pointer.struct.NAME_CONSTRAINTS_st */
            	2731, 0,
            0, 0, 0, /* 2731: struct.NAME_CONSTRAINTS_st */
            64097, 8, 0, /* 2734: pointer.func */
            1, 8, 1, /* 2737: pointer.struct.buf_mem_st */
            	2742, 0,
            0, 24, 1, /* 2742: struct.buf_mem_st */
            	93, 8,
            0, 16, 1, /* 2747: struct.crypto_ex_data_st */
            	2752, 0,
            1, 8, 1, /* 2752: pointer.struct.stack_st_void */
            	2757, 0,
            0, 32, 1, /* 2757: struct.stack_st_void */
            	2762, 0,
            0, 32, 2, /* 2762: struct.stack_st */
            	885, 8,
            	360, 24,
            1, 8, 1, /* 2769: pointer.struct.asn1_string_st */
            	2774, 0,
            0, 24, 1, /* 2774: struct.asn1_string_st */
            	200, 8,
            0, 136, 11, /* 2779: struct.dsa_st */
            	2804, 24,
            	2804, 32,
            	2804, 40,
            	2804, 48,
            	2804, 56,
            	2804, 64,
            	2804, 72,
            	2814, 88,
            	2747, 104,
            	2828, 120,
            	2879, 128,
            1, 8, 1, /* 2804: pointer.struct.bignum_st */
            	2809, 0,
            0, 24, 1, /* 2809: struct.bignum_st */
            	1807, 0,
            1, 8, 1, /* 2814: pointer.struct.bn_mont_ctx_st */
            	2819, 0,
            0, 96, 3, /* 2819: struct.bn_mont_ctx_st */
            	2809, 8,
            	2809, 32,
            	2809, 56,
            1, 8, 1, /* 2828: pointer.struct.dsa_method */
            	2833, 0,
            0, 96, 11, /* 2833: struct.dsa_method */
            	124, 0,
            	2858, 8,
            	2861, 16,
            	2864, 24,
            	2867, 32,
            	2870, 40,
            	2873, 48,
            	2873, 56,
            	93, 72,
            	2876, 80,
            	2873, 88,
            64097, 8, 0, /* 2858: pointer.func */
            64097, 8, 0, /* 2861: pointer.func */
            64097, 8, 0, /* 2864: pointer.func */
            64097, 8, 0, /* 2867: pointer.func */
            64097, 8, 0, /* 2870: pointer.func */
            64097, 8, 0, /* 2873: pointer.func */
            64097, 8, 0, /* 2876: pointer.func */
            1, 8, 1, /* 2879: pointer.struct.engine_st */
            	2884, 0,
            0, 0, 0, /* 2884: struct.engine_st */
            1, 8, 1, /* 2887: pointer.struct.dh_method */
            	2892, 0,
            0, 72, 8, /* 2892: struct.dh_method */
            	124, 0,
            	2911, 8,
            	2914, 16,
            	2917, 24,
            	2911, 32,
            	2911, 40,
            	93, 56,
            	2920, 64,
            64097, 8, 0, /* 2911: pointer.func */
            64097, 8, 0, /* 2914: pointer.func */
            64097, 8, 0, /* 2917: pointer.func */
            64097, 8, 0, /* 2920: pointer.func */
            1, 8, 1, /* 2923: pointer.struct.otherName_st */
            	2928, 0,
            0, 16, 2, /* 2928: struct.otherName_st */
            	2935, 0,
            	2949, 8,
            1, 8, 1, /* 2935: pointer.struct.asn1_object_st */
            	2940, 0,
            0, 40, 3, /* 2940: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            1, 8, 1, /* 2949: pointer.struct.asn1_type_st */
            	2954, 0,
            0, 16, 1, /* 2954: struct.asn1_type_st */
            	2959, 8,
            0, 8, 20, /* 2959: union.unknown */
            	93, 0,
            	3002, 0,
            	2935, 0,
            	2769, 0,
            	3007, 0,
            	3012, 0,
            	3017, 0,
            	3022, 0,
            	3027, 0,
            	3032, 0,
            	3037, 0,
            	3042, 0,
            	3047, 0,
            	3052, 0,
            	3057, 0,
            	3062, 0,
            	3067, 0,
            	3002, 0,
            	3002, 0,
            	275, 0,
            1, 8, 1, /* 3002: pointer.struct.asn1_string_st */
            	2774, 0,
            1, 8, 1, /* 3007: pointer.struct.asn1_string_st */
            	2774, 0,
            1, 8, 1, /* 3012: pointer.struct.asn1_string_st */
            	2774, 0,
            1, 8, 1, /* 3017: pointer.struct.asn1_string_st */
            	2774, 0,
            1, 8, 1, /* 3022: pointer.struct.asn1_string_st */
            	2774, 0,
            1, 8, 1, /* 3027: pointer.struct.asn1_string_st */
            	2774, 0,
            1, 8, 1, /* 3032: pointer.struct.asn1_string_st */
            	2774, 0,
            1, 8, 1, /* 3037: pointer.struct.asn1_string_st */
            	2774, 0,
            1, 8, 1, /* 3042: pointer.struct.asn1_string_st */
            	2774, 0,
            1, 8, 1, /* 3047: pointer.struct.asn1_string_st */
            	2774, 0,
            1, 8, 1, /* 3052: pointer.struct.asn1_string_st */
            	2774, 0,
            1, 8, 1, /* 3057: pointer.struct.asn1_string_st */
            	2774, 0,
            1, 8, 1, /* 3062: pointer.struct.asn1_string_st */
            	2774, 0,
            1, 8, 1, /* 3067: pointer.struct.asn1_string_st */
            	2774, 0,
            1, 8, 1, /* 3072: pointer.struct.x509_cert_aux_st */
            	3077, 0,
            0, 40, 5, /* 3077: struct.x509_cert_aux_st */
            	3090, 0,
            	3090, 8,
            	3114, 16,
            	3124, 24,
            	3129, 32,
            1, 8, 1, /* 3090: pointer.struct.stack_st_ASN1_OBJECT */
            	3095, 0,
            0, 32, 2, /* 3095: struct.stack_st_fake_ASN1_OBJECT */
            	3102, 8,
            	360, 24,
            64099, 8, 2, /* 3102: pointer_to_array_of_pointers_to_stack */
            	3109, 0,
            	357, 20,
            0, 8, 1, /* 3109: pointer.ASN1_OBJECT */
            	2544, 0,
            1, 8, 1, /* 3114: pointer.struct.asn1_string_st */
            	3119, 0,
            0, 24, 1, /* 3119: struct.asn1_string_st */
            	200, 8,
            1, 8, 1, /* 3124: pointer.struct.asn1_string_st */
            	3119, 0,
            1, 8, 1, /* 3129: pointer.struct.stack_st_X509_ALGOR */
            	3134, 0,
            0, 32, 2, /* 3134: struct.stack_st_fake_X509_ALGOR */
            	3141, 8,
            	360, 24,
            64099, 8, 2, /* 3141: pointer_to_array_of_pointers_to_stack */
            	3148, 0,
            	357, 20,
            0, 8, 1, /* 3148: pointer.X509_ALGOR */
            	2582, 0,
            1, 8, 1, /* 3153: pointer.struct.asn1_string_st */
            	3119, 0,
            1, 8, 1, /* 3158: pointer.struct.X509_algor_st */
            	3163, 0,
            0, 16, 2, /* 3163: struct.X509_algor_st */
            	3170, 0,
            	3184, 8,
            1, 8, 1, /* 3170: pointer.struct.asn1_object_st */
            	3175, 0,
            0, 40, 3, /* 3175: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            1, 8, 1, /* 3184: pointer.struct.asn1_type_st */
            	3189, 0,
            0, 16, 1, /* 3189: struct.asn1_type_st */
            	3194, 8,
            0, 8, 20, /* 3194: union.unknown */
            	93, 0,
            	3237, 0,
            	3170, 0,
            	3153, 0,
            	3242, 0,
            	3247, 0,
            	3124, 0,
            	3252, 0,
            	3257, 0,
            	3262, 0,
            	3267, 0,
            	3272, 0,
            	3277, 0,
            	3282, 0,
            	3287, 0,
            	3292, 0,
            	3114, 0,
            	3237, 0,
            	3237, 0,
            	616, 0,
            1, 8, 1, /* 3237: pointer.struct.asn1_string_st */
            	3119, 0,
            1, 8, 1, /* 3242: pointer.struct.asn1_string_st */
            	3119, 0,
            1, 8, 1, /* 3247: pointer.struct.asn1_string_st */
            	3119, 0,
            1, 8, 1, /* 3252: pointer.struct.asn1_string_st */
            	3119, 0,
            1, 8, 1, /* 3257: pointer.struct.asn1_string_st */
            	3119, 0,
            1, 8, 1, /* 3262: pointer.struct.asn1_string_st */
            	3119, 0,
            1, 8, 1, /* 3267: pointer.struct.asn1_string_st */
            	3119, 0,
            1, 8, 1, /* 3272: pointer.struct.asn1_string_st */
            	3119, 0,
            1, 8, 1, /* 3277: pointer.struct.asn1_string_st */
            	3119, 0,
            1, 8, 1, /* 3282: pointer.struct.asn1_string_st */
            	3119, 0,
            1, 8, 1, /* 3287: pointer.struct.asn1_string_st */
            	3119, 0,
            1, 8, 1, /* 3292: pointer.struct.asn1_string_st */
            	3119, 0,
            1, 8, 1, /* 3297: pointer.struct.X509_POLICY_CACHE_st */
            	3302, 0,
            0, 0, 0, /* 3302: struct.X509_POLICY_CACHE_st */
            0, 0, 0, /* 3305: struct.ec_key_st */
            1, 8, 1, /* 3308: pointer.struct.AUTHORITY_KEYID_st */
            	3313, 0,
            0, 0, 0, /* 3313: struct.AUTHORITY_KEYID_st */
            64097, 8, 0, /* 3316: pointer.func */
            64097, 8, 0, /* 3319: pointer.func */
            1, 8, 1, /* 3322: pointer.struct.bignum_st */
            	3327, 0,
            0, 24, 1, /* 3327: struct.bignum_st */
            	1807, 0,
            0, 0, 1, /* 3332: X509_OBJECT */
            	3337, 0,
            0, 16, 1, /* 3337: struct.x509_object_st */
            	3342, 8,
            0, 8, 4, /* 3342: union.unknown */
            	93, 0,
            	3353, 0,
            	3812, 0,
            	3494, 0,
            1, 8, 1, /* 3353: pointer.struct.x509_st */
            	3358, 0,
            0, 184, 12, /* 3358: struct.x509_st */
            	3385, 0,
            	3158, 8,
            	3247, 16,
            	93, 32,
            	2747, 40,
            	3124, 104,
            	3308, 112,
            	3297, 120,
            	3764, 128,
            	3788, 136,
            	2726, 144,
            	3072, 176,
            1, 8, 1, /* 3385: pointer.struct.x509_cinf_st */
            	3390, 0,
            0, 104, 11, /* 3390: struct.x509_cinf_st */
            	3153, 0,
            	3153, 8,
            	3158, 16,
            	3415, 24,
            	3463, 32,
            	3415, 40,
            	3480, 48,
            	3247, 56,
            	3247, 64,
            	3735, 72,
            	3759, 80,
            1, 8, 1, /* 3415: pointer.struct.X509_name_st */
            	3420, 0,
            0, 40, 3, /* 3420: struct.X509_name_st */
            	3429, 0,
            	3453, 16,
            	200, 24,
            1, 8, 1, /* 3429: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3434, 0,
            0, 32, 2, /* 3434: struct.stack_st_fake_X509_NAME_ENTRY */
            	3441, 8,
            	360, 24,
            64099, 8, 2, /* 3441: pointer_to_array_of_pointers_to_stack */
            	3448, 0,
            	357, 20,
            0, 8, 1, /* 3448: pointer.X509_NAME_ENTRY */
            	321, 0,
            1, 8, 1, /* 3453: pointer.struct.buf_mem_st */
            	3458, 0,
            0, 24, 1, /* 3458: struct.buf_mem_st */
            	93, 8,
            1, 8, 1, /* 3463: pointer.struct.X509_val_st */
            	3468, 0,
            0, 16, 2, /* 3468: struct.X509_val_st */
            	3475, 0,
            	3475, 8,
            1, 8, 1, /* 3475: pointer.struct.asn1_string_st */
            	3119, 0,
            1, 8, 1, /* 3480: pointer.struct.X509_pubkey_st */
            	3485, 0,
            0, 24, 3, /* 3485: struct.X509_pubkey_st */
            	3158, 0,
            	3247, 8,
            	3494, 16,
            1, 8, 1, /* 3494: pointer.struct.evp_pkey_st */
            	3499, 0,
            0, 56, 4, /* 3499: struct.evp_pkey_st */
            	3510, 16,
            	2879, 24,
            	3518, 32,
            	3711, 48,
            1, 8, 1, /* 3510: pointer.struct.evp_pkey_asn1_method_st */
            	3515, 0,
            0, 0, 0, /* 3515: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 3518: union.unknown */
            	93, 0,
            	3531, 0,
            	3633, 0,
            	3638, 0,
            	3706, 0,
            1, 8, 1, /* 3531: pointer.struct.rsa_st */
            	3536, 0,
            0, 168, 17, /* 3536: struct.rsa_st */
            	3573, 16,
            	2879, 24,
            	2804, 32,
            	2804, 40,
            	2804, 48,
            	2804, 56,
            	2804, 64,
            	2804, 72,
            	2804, 80,
            	2804, 88,
            	2747, 96,
            	2814, 120,
            	2814, 128,
            	2814, 136,
            	93, 144,
            	3625, 152,
            	3625, 160,
            1, 8, 1, /* 3573: pointer.struct.rsa_meth_st */
            	3578, 0,
            0, 112, 13, /* 3578: struct.rsa_meth_st */
            	124, 0,
            	3607, 8,
            	3607, 16,
            	3607, 24,
            	3607, 32,
            	3610, 40,
            	3613, 48,
            	3616, 56,
            	3616, 64,
            	93, 80,
            	2734, 88,
            	3619, 96,
            	3622, 104,
            64097, 8, 0, /* 3607: pointer.func */
            64097, 8, 0, /* 3610: pointer.func */
            64097, 8, 0, /* 3613: pointer.func */
            64097, 8, 0, /* 3616: pointer.func */
            64097, 8, 0, /* 3619: pointer.func */
            64097, 8, 0, /* 3622: pointer.func */
            1, 8, 1, /* 3625: pointer.struct.bn_blinding_st */
            	3630, 0,
            0, 0, 0, /* 3630: struct.bn_blinding_st */
            1, 8, 1, /* 3633: pointer.struct.dsa_st */
            	2779, 0,
            1, 8, 1, /* 3638: pointer.struct.dh_st */
            	3643, 0,
            0, 144, 12, /* 3643: struct.dh_st */
            	2804, 8,
            	2804, 16,
            	2804, 32,
            	2804, 40,
            	2814, 56,
            	2804, 64,
            	2804, 72,
            	200, 80,
            	2804, 96,
            	2747, 112,
            	3670, 128,
            	2879, 136,
            1, 8, 1, /* 3670: pointer.struct.dh_method */
            	3675, 0,
            0, 72, 8, /* 3675: struct.dh_method */
            	124, 0,
            	3694, 8,
            	3697, 16,
            	3700, 24,
            	3694, 32,
            	3694, 40,
            	93, 56,
            	3703, 64,
            64097, 8, 0, /* 3694: pointer.func */
            64097, 8, 0, /* 3697: pointer.func */
            64097, 8, 0, /* 3700: pointer.func */
            64097, 8, 0, /* 3703: pointer.func */
            1, 8, 1, /* 3706: pointer.struct.ec_key_st */
            	3305, 0,
            1, 8, 1, /* 3711: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3716, 0,
            0, 32, 2, /* 3716: struct.stack_st_fake_X509_ATTRIBUTE */
            	3723, 8,
            	360, 24,
            64099, 8, 2, /* 3723: pointer_to_array_of_pointers_to_stack */
            	3730, 0,
            	357, 20,
            0, 8, 1, /* 3730: pointer.X509_ATTRIBUTE */
            	2040, 0,
            1, 8, 1, /* 3735: pointer.struct.stack_st_X509_EXTENSION */
            	3740, 0,
            0, 32, 2, /* 3740: struct.stack_st_fake_X509_EXTENSION */
            	3747, 8,
            	360, 24,
            64099, 8, 2, /* 3747: pointer_to_array_of_pointers_to_stack */
            	3754, 0,
            	357, 20,
            0, 8, 1, /* 3754: pointer.X509_EXTENSION */
            	708, 0,
            0, 24, 1, /* 3759: struct.ASN1_ENCODING_st */
            	200, 0,
            1, 8, 1, /* 3764: pointer.struct.stack_st_DIST_POINT */
            	3769, 0,
            0, 32, 2, /* 3769: struct.stack_st_fake_DIST_POINT */
            	3776, 8,
            	360, 24,
            64099, 8, 2, /* 3776: pointer_to_array_of_pointers_to_stack */
            	3783, 0,
            	357, 20,
            0, 8, 1, /* 3783: pointer.DIST_POINT */
            	2456, 0,
            1, 8, 1, /* 3788: pointer.struct.stack_st_GENERAL_NAME */
            	3793, 0,
            0, 32, 2, /* 3793: struct.stack_st_fake_GENERAL_NAME */
            	3800, 8,
            	360, 24,
            64099, 8, 2, /* 3800: pointer_to_array_of_pointers_to_stack */
            	3807, 0,
            	357, 20,
            0, 8, 1, /* 3807: pointer.GENERAL_NAME */
            	50, 0,
            1, 8, 1, /* 3812: pointer.struct.X509_crl_st */
            	3817, 0,
            0, 120, 10, /* 3817: struct.X509_crl_st */
            	3840, 0,
            	3158, 8,
            	3247, 16,
            	3308, 32,
            	3888, 40,
            	3153, 56,
            	3153, 64,
            	844, 96,
            	890, 104,
            	898, 112,
            1, 8, 1, /* 3840: pointer.struct.X509_crl_info_st */
            	3845, 0,
            0, 80, 8, /* 3845: struct.X509_crl_info_st */
            	3153, 0,
            	3158, 8,
            	3415, 16,
            	3475, 24,
            	3475, 32,
            	3864, 40,
            	3735, 48,
            	3759, 56,
            1, 8, 1, /* 3864: pointer.struct.stack_st_X509_REVOKED */
            	3869, 0,
            0, 32, 2, /* 3869: struct.stack_st_fake_X509_REVOKED */
            	3876, 8,
            	360, 24,
            64099, 8, 2, /* 3876: pointer_to_array_of_pointers_to_stack */
            	3883, 0,
            	357, 20,
            0, 8, 1, /* 3883: pointer.X509_REVOKED */
            	653, 0,
            1, 8, 1, /* 3888: pointer.struct.ISSUING_DIST_POINT_st */
            	3893, 0,
            0, 0, 0, /* 3893: struct.ISSUING_DIST_POINT_st */
            1, 8, 1, /* 3896: pointer.struct.X509_name_st */
            	3901, 0,
            0, 40, 3, /* 3901: struct.X509_name_st */
            	3910, 0,
            	2737, 16,
            	200, 24,
            1, 8, 1, /* 3910: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3915, 0,
            0, 32, 2, /* 3915: struct.stack_st_fake_X509_NAME_ENTRY */
            	3922, 8,
            	360, 24,
            64099, 8, 2, /* 3922: pointer_to_array_of_pointers_to_stack */
            	3929, 0,
            	357, 20,
            0, 8, 1, /* 3929: pointer.X509_NAME_ENTRY */
            	321, 0,
            1, 8, 1, /* 3934: pointer.struct.x509_st */
            	3939, 0,
            0, 184, 12, /* 3939: struct.x509_st */
            	3966, 0,
            	472, 8,
            	433, 16,
            	93, 32,
            	4093, 40,
            	561, 104,
            	830, 112,
            	3297, 120,
            	4266, 128,
            	4290, 136,
            	4314, 144,
            	4419, 176,
            1, 8, 1, /* 3966: pointer.struct.x509_cinf_st */
            	3971, 0,
            0, 104, 11, /* 3971: struct.x509_cinf_st */
            	467, 0,
            	467, 8,
            	472, 16,
            	409, 24,
            	3996, 32,
            	409, 40,
            	4008, 48,
            	433, 56,
            	433, 64,
            	768, 72,
            	792, 80,
            1, 8, 1, /* 3996: pointer.struct.X509_val_st */
            	4001, 0,
            0, 16, 2, /* 4001: struct.X509_val_st */
            	624, 0,
            	624, 8,
            1, 8, 1, /* 4008: pointer.struct.X509_pubkey_st */
            	4013, 0,
            0, 24, 3, /* 4013: struct.X509_pubkey_st */
            	472, 0,
            	433, 8,
            	4022, 16,
            1, 8, 1, /* 4022: pointer.struct.evp_pkey_st */
            	4027, 0,
            0, 56, 4, /* 4027: struct.evp_pkey_st */
            	3510, 16,
            	2879, 24,
            	4038, 32,
            	4242, 48,
            0, 8, 5, /* 4038: union.unknown */
            	93, 0,
            	4051, 0,
            	4129, 0,
            	4210, 0,
            	3706, 0,
            1, 8, 1, /* 4051: pointer.struct.rsa_st */
            	4056, 0,
            0, 168, 17, /* 4056: struct.rsa_st */
            	1292, 16,
            	2879, 24,
            	3322, 32,
            	3322, 40,
            	3322, 48,
            	3322, 56,
            	3322, 64,
            	3322, 72,
            	3322, 80,
            	3322, 88,
            	4093, 96,
            	4115, 120,
            	4115, 128,
            	4115, 136,
            	93, 144,
            	3625, 152,
            	3625, 160,
            0, 16, 1, /* 4093: struct.crypto_ex_data_st */
            	4098, 0,
            1, 8, 1, /* 4098: pointer.struct.stack_st_void */
            	4103, 0,
            0, 32, 1, /* 4103: struct.stack_st_void */
            	4108, 0,
            0, 32, 2, /* 4108: struct.stack_st */
            	885, 8,
            	360, 24,
            1, 8, 1, /* 4115: pointer.struct.bn_mont_ctx_st */
            	4120, 0,
            0, 96, 3, /* 4120: struct.bn_mont_ctx_st */
            	3327, 8,
            	3327, 32,
            	3327, 56,
            1, 8, 1, /* 4129: pointer.struct.dsa_st */
            	4134, 0,
            0, 136, 11, /* 4134: struct.dsa_st */
            	3322, 24,
            	3322, 32,
            	3322, 40,
            	3322, 48,
            	3322, 56,
            	3322, 64,
            	3322, 72,
            	4115, 88,
            	4093, 104,
            	4159, 120,
            	2879, 128,
            1, 8, 1, /* 4159: pointer.struct.dsa_method */
            	4164, 0,
            0, 96, 11, /* 4164: struct.dsa_method */
            	124, 0,
            	4189, 8,
            	4192, 16,
            	4195, 24,
            	4198, 32,
            	4201, 40,
            	4204, 48,
            	4204, 56,
            	93, 72,
            	4207, 80,
            	4204, 88,
            64097, 8, 0, /* 4189: pointer.func */
            64097, 8, 0, /* 4192: pointer.func */
            64097, 8, 0, /* 4195: pointer.func */
            64097, 8, 0, /* 4198: pointer.func */
            64097, 8, 0, /* 4201: pointer.func */
            64097, 8, 0, /* 4204: pointer.func */
            64097, 8, 0, /* 4207: pointer.func */
            1, 8, 1, /* 4210: pointer.struct.dh_st */
            	4215, 0,
            0, 144, 12, /* 4215: struct.dh_st */
            	3322, 8,
            	3322, 16,
            	3322, 32,
            	3322, 40,
            	4115, 56,
            	3322, 64,
            	3322, 72,
            	200, 80,
            	3322, 96,
            	4093, 112,
            	2887, 128,
            	2879, 136,
            1, 8, 1, /* 4242: pointer.struct.stack_st_X509_ATTRIBUTE */
            	4247, 0,
            0, 32, 2, /* 4247: struct.stack_st_fake_X509_ATTRIBUTE */
            	4254, 8,
            	360, 24,
            64099, 8, 2, /* 4254: pointer_to_array_of_pointers_to_stack */
            	4261, 0,
            	357, 20,
            0, 8, 1, /* 4261: pointer.X509_ATTRIBUTE */
            	2040, 0,
            1, 8, 1, /* 4266: pointer.struct.stack_st_DIST_POINT */
            	4271, 0,
            0, 32, 2, /* 4271: struct.stack_st_fake_DIST_POINT */
            	4278, 8,
            	360, 24,
            64099, 8, 2, /* 4278: pointer_to_array_of_pointers_to_stack */
            	4285, 0,
            	357, 20,
            0, 8, 1, /* 4285: pointer.DIST_POINT */
            	2456, 0,
            1, 8, 1, /* 4290: pointer.struct.stack_st_GENERAL_NAME */
            	4295, 0,
            0, 32, 2, /* 4295: struct.stack_st_fake_GENERAL_NAME */
            	4302, 8,
            	360, 24,
            64099, 8, 2, /* 4302: pointer_to_array_of_pointers_to_stack */
            	4309, 0,
            	357, 20,
            0, 8, 1, /* 4309: pointer.GENERAL_NAME */
            	50, 0,
            1, 8, 1, /* 4314: pointer.struct.NAME_CONSTRAINTS_st */
            	4319, 0,
            0, 16, 2, /* 4319: struct.NAME_CONSTRAINTS_st */
            	4326, 0,
            	4326, 8,
            1, 8, 1, /* 4326: pointer.struct.stack_st_GENERAL_SUBTREE */
            	4331, 0,
            0, 32, 2, /* 4331: struct.stack_st_fake_GENERAL_SUBTREE */
            	4338, 8,
            	360, 24,
            64099, 8, 2, /* 4338: pointer_to_array_of_pointers_to_stack */
            	4345, 0,
            	357, 20,
            0, 8, 1, /* 4345: pointer.GENERAL_SUBTREE */
            	4350, 0,
            0, 0, 1, /* 4350: GENERAL_SUBTREE */
            	4355, 0,
            0, 24, 3, /* 4355: struct.GENERAL_SUBTREE_st */
            	4364, 0,
            	2769, 8,
            	2769, 16,
            1, 8, 1, /* 4364: pointer.struct.GENERAL_NAME_st */
            	4369, 0,
            0, 16, 1, /* 4369: struct.GENERAL_NAME_st */
            	4374, 8,
            0, 8, 15, /* 4374: union.unknown */
            	93, 0,
            	2923, 0,
            	3032, 0,
            	3032, 0,
            	2949, 0,
            	3896, 0,
            	4407, 0,
            	3032, 0,
            	3017, 0,
            	2935, 0,
            	3017, 0,
            	3896, 0,
            	3032, 0,
            	2935, 0,
            	2949, 0,
            1, 8, 1, /* 4407: pointer.struct.EDIPartyName_st */
            	4412, 0,
            0, 16, 2, /* 4412: struct.EDIPartyName_st */
            	3002, 0,
            	3002, 8,
            1, 8, 1, /* 4419: pointer.struct.x509_cert_aux_st */
            	4424, 0,
            0, 40, 5, /* 4424: struct.x509_cert_aux_st */
            	4437, 0,
            	4437, 8,
            	611, 16,
            	561, 24,
            	4461, 32,
            1, 8, 1, /* 4437: pointer.struct.stack_st_ASN1_OBJECT */
            	4442, 0,
            0, 32, 2, /* 4442: struct.stack_st_fake_ASN1_OBJECT */
            	4449, 8,
            	360, 24,
            64099, 8, 2, /* 4449: pointer_to_array_of_pointers_to_stack */
            	4456, 0,
            	357, 20,
            0, 8, 1, /* 4456: pointer.ASN1_OBJECT */
            	2544, 0,
            1, 8, 1, /* 4461: pointer.struct.stack_st_X509_ALGOR */
            	4466, 0,
            0, 32, 2, /* 4466: struct.stack_st_fake_X509_ALGOR */
            	4473, 8,
            	360, 24,
            64099, 8, 2, /* 4473: pointer_to_array_of_pointers_to_stack */
            	4480, 0,
            	357, 20,
            0, 8, 1, /* 4480: pointer.X509_ALGOR */
            	2582, 0,
            0, 144, 15, /* 4485: struct.x509_store_st */
            	4518, 8,
            	4542, 16,
            	4748, 24,
            	4760, 32,
            	4763, 40,
            	4766, 48,
            	4769, 56,
            	4760, 64,
            	4772, 72,
            	4775, 80,
            	4778, 88,
            	4781, 96,
            	4784, 104,
            	4760, 112,
            	4093, 120,
            1, 8, 1, /* 4518: pointer.struct.stack_st_X509_OBJECT */
            	4523, 0,
            0, 32, 2, /* 4523: struct.stack_st_fake_X509_OBJECT */
            	4530, 8,
            	360, 24,
            64099, 8, 2, /* 4530: pointer_to_array_of_pointers_to_stack */
            	4537, 0,
            	357, 20,
            0, 8, 1, /* 4537: pointer.X509_OBJECT */
            	3332, 0,
            1, 8, 1, /* 4542: pointer.struct.stack_st_X509_LOOKUP */
            	4547, 0,
            0, 32, 2, /* 4547: struct.stack_st_fake_X509_LOOKUP */
            	4554, 8,
            	360, 24,
            64099, 8, 2, /* 4554: pointer_to_array_of_pointers_to_stack */
            	4561, 0,
            	357, 20,
            0, 8, 1, /* 4561: pointer.X509_LOOKUP */
            	4566, 0,
            0, 0, 1, /* 4566: X509_LOOKUP */
            	4571, 0,
            0, 32, 3, /* 4571: struct.x509_lookup_st */
            	4580, 8,
            	93, 16,
            	4626, 24,
            1, 8, 1, /* 4580: pointer.struct.x509_lookup_method_st */
            	4585, 0,
            0, 80, 10, /* 4585: struct.x509_lookup_method_st */
            	124, 0,
            	4608, 8,
            	3316, 16,
            	4608, 24,
            	4608, 32,
            	4611, 40,
            	4614, 48,
            	4617, 56,
            	4620, 64,
            	4623, 72,
            64097, 8, 0, /* 4608: pointer.func */
            64097, 8, 0, /* 4611: pointer.func */
            64097, 8, 0, /* 4614: pointer.func */
            64097, 8, 0, /* 4617: pointer.func */
            64097, 8, 0, /* 4620: pointer.func */
            64097, 8, 0, /* 4623: pointer.func */
            1, 8, 1, /* 4626: pointer.struct.x509_store_st */
            	4631, 0,
            0, 144, 15, /* 4631: struct.x509_store_st */
            	4664, 8,
            	4688, 16,
            	4712, 24,
            	4724, 32,
            	4727, 40,
            	4730, 48,
            	4733, 56,
            	4724, 64,
            	4736, 72,
            	4739, 80,
            	4742, 88,
            	4745, 96,
            	3319, 104,
            	4724, 112,
            	2747, 120,
            1, 8, 1, /* 4664: pointer.struct.stack_st_X509_OBJECT */
            	4669, 0,
            0, 32, 2, /* 4669: struct.stack_st_fake_X509_OBJECT */
            	4676, 8,
            	360, 24,
            64099, 8, 2, /* 4676: pointer_to_array_of_pointers_to_stack */
            	4683, 0,
            	357, 20,
            0, 8, 1, /* 4683: pointer.X509_OBJECT */
            	3332, 0,
            1, 8, 1, /* 4688: pointer.struct.stack_st_X509_LOOKUP */
            	4693, 0,
            0, 32, 2, /* 4693: struct.stack_st_fake_X509_LOOKUP */
            	4700, 8,
            	360, 24,
            64099, 8, 2, /* 4700: pointer_to_array_of_pointers_to_stack */
            	4707, 0,
            	357, 20,
            0, 8, 1, /* 4707: pointer.X509_LOOKUP */
            	4566, 0,
            1, 8, 1, /* 4712: pointer.struct.X509_VERIFY_PARAM_st */
            	4717, 0,
            0, 56, 2, /* 4717: struct.X509_VERIFY_PARAM_st */
            	93, 0,
            	3090, 48,
            64097, 8, 0, /* 4724: pointer.func */
            64097, 8, 0, /* 4727: pointer.func */
            64097, 8, 0, /* 4730: pointer.func */
            64097, 8, 0, /* 4733: pointer.func */
            64097, 8, 0, /* 4736: pointer.func */
            64097, 8, 0, /* 4739: pointer.func */
            64097, 8, 0, /* 4742: pointer.func */
            64097, 8, 0, /* 4745: pointer.func */
            1, 8, 1, /* 4748: pointer.struct.X509_VERIFY_PARAM_st */
            	4753, 0,
            0, 56, 2, /* 4753: struct.X509_VERIFY_PARAM_st */
            	93, 0,
            	4437, 48,
            64097, 8, 0, /* 4760: pointer.func */
            64097, 8, 0, /* 4763: pointer.func */
            64097, 8, 0, /* 4766: pointer.func */
            64097, 8, 0, /* 4769: pointer.func */
            64097, 8, 0, /* 4772: pointer.func */
            64097, 8, 0, /* 4775: pointer.func */
            64097, 8, 0, /* 4778: pointer.func */
            64097, 8, 0, /* 4781: pointer.func */
            64097, 8, 0, /* 4784: pointer.func */
            1, 8, 1, /* 4787: pointer.struct.x509_store_ctx_st */
            	4792, 0,
            0, 248, 25, /* 4792: struct.x509_store_ctx_st */
            	4845, 0,
            	3934, 16,
            	4850, 24,
            	4879, 32,
            	4748, 40,
            	898, 48,
            	4760, 56,
            	4763, 64,
            	4766, 72,
            	4769, 80,
            	4760, 88,
            	4772, 96,
            	4775, 104,
            	4778, 112,
            	4760, 120,
            	4781, 128,
            	4784, 136,
            	4760, 144,
            	4850, 160,
            	904, 168,
            	3934, 192,
            	3934, 200,
            	797, 208,
            	4787, 224,
            	4093, 232,
            1, 8, 1, /* 4845: pointer.struct.x509_store_st */
            	4485, 0,
            1, 8, 1, /* 4850: pointer.struct.stack_st_X509 */
            	4855, 0,
            0, 32, 2, /* 4855: struct.stack_st_fake_X509 */
            	4862, 8,
            	360, 24,
            64099, 8, 2, /* 4862: pointer_to_array_of_pointers_to_stack */
            	4869, 0,
            	357, 20,
            0, 8, 1, /* 4869: pointer.X509 */
            	4874, 0,
            0, 0, 1, /* 4874: X509 */
            	1352, 0,
            1, 8, 1, /* 4879: pointer.struct.stack_st_X509_CRL */
            	4884, 0,
            0, 32, 2, /* 4884: struct.stack_st_fake_X509_CRL */
            	4891, 8,
            	360, 24,
            64099, 8, 2, /* 4891: pointer_to_array_of_pointers_to_stack */
            	4898, 0,
            	357, 20,
            0, 8, 1, /* 4898: pointer.X509_CRL */
            	1277, 0,
            0, 1, 0, /* 4903: char */
        },
        .arg_entity_index = { 4787, },
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

