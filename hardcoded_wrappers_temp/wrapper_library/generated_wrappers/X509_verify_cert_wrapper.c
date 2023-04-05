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

int bb_X509_verify_cert(X509_STORE_CTX * arg_a);

int X509_verify_cert(X509_STORE_CTX * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("X509_verify_cert called %lu\n", in_lib);
    if (!in_lib)
        return bb_X509_verify_cert(arg_a);
    else {
        int (*orig_X509_verify_cert)(X509_STORE_CTX *);
        orig_X509_verify_cert = dlsym(RTLD_NEXT, "X509_verify_cert");
        return orig_X509_verify_cert(arg_a);
    }
}

int bb_X509_verify_cert(X509_STORE_CTX * arg_a) 
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
            8884099, 8, 2, /* 38: pointer_to_array_of_pointers_to_stack */
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
            	8884096, 0,
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
            	8884096, 0,
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
            8884099, 8, 2, /* 309: pointer_to_array_of_pointers_to_stack */
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
            8884097, 8, 0, /* 360: pointer.func */
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
            8884099, 8, 2, /* 397: pointer_to_array_of_pointers_to_stack */
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
            0, 80, 8, /* 443: struct.X509_crl_info_st */
            	462, 0,
            	467, 8,
            	409, 16,
            	619, 24,
            	619, 32,
            	624, 40,
            	763, 48,
            	787, 56,
            1, 8, 1, /* 462: pointer.struct.asn1_string_st */
            	438, 0,
            1, 8, 1, /* 467: pointer.struct.X509_algor_st */
            	472, 0,
            0, 16, 2, /* 472: struct.X509_algor_st */
            	479, 0,
            	493, 8,
            1, 8, 1, /* 479: pointer.struct.asn1_object_st */
            	484, 0,
            0, 40, 3, /* 484: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            1, 8, 1, /* 493: pointer.struct.asn1_type_st */
            	498, 0,
            0, 16, 1, /* 498: struct.asn1_type_st */
            	503, 8,
            0, 8, 20, /* 503: union.unknown */
            	93, 0,
            	546, 0,
            	479, 0,
            	462, 0,
            	551, 0,
            	433, 0,
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
            	546, 0,
            	546, 0,
            	611, 0,
            1, 8, 1, /* 546: pointer.struct.asn1_string_st */
            	438, 0,
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
            1, 8, 1, /* 611: pointer.struct.ASN1_VALUE_st */
            	616, 0,
            0, 0, 0, /* 616: struct.ASN1_VALUE_st */
            1, 8, 1, /* 619: pointer.struct.asn1_string_st */
            	438, 0,
            1, 8, 1, /* 624: pointer.struct.stack_st_X509_REVOKED */
            	629, 0,
            0, 32, 2, /* 629: struct.stack_st_fake_X509_REVOKED */
            	636, 8,
            	360, 24,
            8884099, 8, 2, /* 636: pointer_to_array_of_pointers_to_stack */
            	643, 0,
            	357, 20,
            0, 8, 1, /* 643: pointer.X509_REVOKED */
            	648, 0,
            0, 0, 1, /* 648: X509_REVOKED */
            	653, 0,
            0, 40, 4, /* 653: struct.x509_revoked_st */
            	664, 0,
            	674, 8,
            	679, 16,
            	739, 24,
            1, 8, 1, /* 664: pointer.struct.asn1_string_st */
            	669, 0,
            0, 24, 1, /* 669: struct.asn1_string_st */
            	200, 8,
            1, 8, 1, /* 674: pointer.struct.asn1_string_st */
            	669, 0,
            1, 8, 1, /* 679: pointer.struct.stack_st_X509_EXTENSION */
            	684, 0,
            0, 32, 2, /* 684: struct.stack_st_fake_X509_EXTENSION */
            	691, 8,
            	360, 24,
            8884099, 8, 2, /* 691: pointer_to_array_of_pointers_to_stack */
            	698, 0,
            	357, 20,
            0, 8, 1, /* 698: pointer.X509_EXTENSION */
            	703, 0,
            0, 0, 1, /* 703: X509_EXTENSION */
            	708, 0,
            0, 24, 2, /* 708: struct.X509_extension_st */
            	715, 0,
            	729, 16,
            1, 8, 1, /* 715: pointer.struct.asn1_object_st */
            	720, 0,
            0, 40, 3, /* 720: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            1, 8, 1, /* 729: pointer.struct.asn1_string_st */
            	734, 0,
            0, 24, 1, /* 734: struct.asn1_string_st */
            	200, 8,
            1, 8, 1, /* 739: pointer.struct.stack_st_GENERAL_NAME */
            	744, 0,
            0, 32, 2, /* 744: struct.stack_st_fake_GENERAL_NAME */
            	751, 8,
            	360, 24,
            8884099, 8, 2, /* 751: pointer_to_array_of_pointers_to_stack */
            	758, 0,
            	357, 20,
            0, 8, 1, /* 758: pointer.GENERAL_NAME */
            	50, 0,
            1, 8, 1, /* 763: pointer.struct.stack_st_X509_EXTENSION */
            	768, 0,
            0, 32, 2, /* 768: struct.stack_st_fake_X509_EXTENSION */
            	775, 8,
            	360, 24,
            8884099, 8, 2, /* 775: pointer_to_array_of_pointers_to_stack */
            	782, 0,
            	357, 20,
            0, 8, 1, /* 782: pointer.X509_EXTENSION */
            	703, 0,
            0, 24, 1, /* 787: struct.ASN1_ENCODING_st */
            	200, 0,
            1, 8, 1, /* 792: pointer.struct.X509_crl_st */
            	797, 0,
            0, 120, 10, /* 797: struct.X509_crl_st */
            	820, 0,
            	467, 8,
            	433, 16,
            	825, 32,
            	839, 40,
            	462, 56,
            	462, 64,
            	844, 96,
            	890, 104,
            	898, 112,
            1, 8, 1, /* 820: pointer.struct.X509_crl_info_st */
            	443, 0,
            1, 8, 1, /* 825: pointer.struct.AUTHORITY_KEYID_st */
            	830, 0,
            0, 24, 3, /* 830: struct.AUTHORITY_KEYID_st */
            	556, 0,
            	26, 8,
            	462, 16,
            1, 8, 1, /* 839: pointer.struct.ISSUING_DIST_POINT_st */
            	0, 0,
            1, 8, 1, /* 844: pointer.struct.stack_st_GENERAL_NAMES */
            	849, 0,
            0, 32, 2, /* 849: struct.stack_st_fake_GENERAL_NAMES */
            	856, 8,
            	360, 24,
            8884099, 8, 2, /* 856: pointer_to_array_of_pointers_to_stack */
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
            0, 24, 1, /* 909: struct.ASN1_ENCODING_st */
            	200, 0,
            1, 8, 1, /* 914: pointer.struct.stack_st_X509_EXTENSION */
            	919, 0,
            0, 32, 2, /* 919: struct.stack_st_fake_X509_EXTENSION */
            	926, 8,
            	360, 24,
            8884099, 8, 2, /* 926: pointer_to_array_of_pointers_to_stack */
            	933, 0,
            	357, 20,
            0, 8, 1, /* 933: pointer.X509_EXTENSION */
            	703, 0,
            1, 8, 1, /* 938: pointer.struct.asn1_string_st */
            	943, 0,
            0, 24, 1, /* 943: struct.asn1_string_st */
            	200, 8,
            0, 24, 1, /* 948: struct.buf_mem_st */
            	93, 8,
            1, 8, 1, /* 953: pointer.struct.buf_mem_st */
            	948, 0,
            1, 8, 1, /* 958: pointer.struct.stack_st_X509_NAME_ENTRY */
            	963, 0,
            0, 32, 2, /* 963: struct.stack_st_fake_X509_NAME_ENTRY */
            	970, 8,
            	360, 24,
            8884099, 8, 2, /* 970: pointer_to_array_of_pointers_to_stack */
            	977, 0,
            	357, 20,
            0, 8, 1, /* 977: pointer.X509_NAME_ENTRY */
            	321, 0,
            1, 8, 1, /* 982: pointer.struct.asn1_string_st */
            	943, 0,
            1, 8, 1, /* 987: pointer.struct.asn1_string_st */
            	943, 0,
            1, 8, 1, /* 992: pointer.struct.asn1_string_st */
            	943, 0,
            1, 8, 1, /* 997: pointer.struct.asn1_string_st */
            	943, 0,
            1, 8, 1, /* 1002: pointer.struct.asn1_string_st */
            	943, 0,
            1, 8, 1, /* 1007: pointer.struct.asn1_string_st */
            	943, 0,
            1, 8, 1, /* 1012: pointer.struct.asn1_string_st */
            	943, 0,
            1, 8, 1, /* 1017: pointer.struct.asn1_string_st */
            	943, 0,
            1, 8, 1, /* 1022: pointer.struct.asn1_string_st */
            	943, 0,
            0, 8, 20, /* 1027: union.unknown */
            	93, 0,
            	1070, 0,
            	1075, 0,
            	1089, 0,
            	1022, 0,
            	1017, 0,
            	1012, 0,
            	1094, 0,
            	1099, 0,
            	1007, 0,
            	1002, 0,
            	997, 0,
            	992, 0,
            	1104, 0,
            	987, 0,
            	1109, 0,
            	982, 0,
            	1070, 0,
            	1070, 0,
            	611, 0,
            1, 8, 1, /* 1070: pointer.struct.asn1_string_st */
            	943, 0,
            1, 8, 1, /* 1075: pointer.struct.asn1_object_st */
            	1080, 0,
            0, 40, 3, /* 1080: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            1, 8, 1, /* 1089: pointer.struct.asn1_string_st */
            	943, 0,
            1, 8, 1, /* 1094: pointer.struct.asn1_string_st */
            	943, 0,
            1, 8, 1, /* 1099: pointer.struct.asn1_string_st */
            	943, 0,
            1, 8, 1, /* 1104: pointer.struct.asn1_string_st */
            	943, 0,
            1, 8, 1, /* 1109: pointer.struct.asn1_string_st */
            	943, 0,
            0, 16, 1, /* 1114: struct.asn1_type_st */
            	1027, 8,
            1, 8, 1, /* 1119: pointer.struct.asn1_type_st */
            	1114, 0,
            0, 16, 2, /* 1124: struct.X509_algor_st */
            	1075, 0,
            	1119, 8,
            1, 8, 1, /* 1131: pointer.struct.X509_crl_info_st */
            	1136, 0,
            0, 80, 8, /* 1136: struct.X509_crl_info_st */
            	1089, 0,
            	1155, 8,
            	1160, 16,
            	938, 24,
            	938, 32,
            	1174, 40,
            	914, 48,
            	909, 56,
            1, 8, 1, /* 1155: pointer.struct.X509_algor_st */
            	1124, 0,
            1, 8, 1, /* 1160: pointer.struct.X509_name_st */
            	1165, 0,
            0, 40, 3, /* 1165: struct.X509_name_st */
            	958, 0,
            	953, 16,
            	200, 24,
            1, 8, 1, /* 1174: pointer.struct.stack_st_X509_REVOKED */
            	1179, 0,
            0, 32, 2, /* 1179: struct.stack_st_fake_X509_REVOKED */
            	1186, 8,
            	360, 24,
            8884099, 8, 2, /* 1186: pointer_to_array_of_pointers_to_stack */
            	1193, 0,
            	357, 20,
            0, 8, 1, /* 1193: pointer.X509_REVOKED */
            	648, 0,
            0, 0, 1, /* 1198: X509_CRL */
            	1203, 0,
            0, 120, 10, /* 1203: struct.X509_crl_st */
            	1131, 0,
            	1155, 8,
            	1017, 16,
            	1226, 32,
            	1234, 40,
            	1089, 56,
            	1089, 64,
            	844, 96,
            	890, 104,
            	898, 112,
            1, 8, 1, /* 1226: pointer.struct.AUTHORITY_KEYID_st */
            	1231, 0,
            0, 0, 0, /* 1231: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 1234: pointer.struct.ISSUING_DIST_POINT_st */
            	1239, 0,
            0, 0, 0, /* 1239: struct.ISSUING_DIST_POINT_st */
            1, 8, 1, /* 1242: pointer.struct.asn1_string_st */
            	1247, 0,
            0, 24, 1, /* 1247: struct.asn1_string_st */
            	200, 8,
            1, 8, 1, /* 1252: pointer.struct.asn1_string_st */
            	1247, 0,
            8884097, 8, 0, /* 1257: pointer.func */
            1, 8, 1, /* 1260: pointer.struct.asn1_string_st */
            	1247, 0,
            8884097, 8, 0, /* 1265: pointer.func */
            0, 16, 2, /* 1268: struct.X509_algor_st */
            	1275, 0,
            	1289, 8,
            1, 8, 1, /* 1275: pointer.struct.asn1_object_st */
            	1280, 0,
            0, 40, 3, /* 1280: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            1, 8, 1, /* 1289: pointer.struct.asn1_type_st */
            	1294, 0,
            0, 16, 1, /* 1294: struct.asn1_type_st */
            	1299, 8,
            0, 8, 20, /* 1299: union.unknown */
            	93, 0,
            	1260, 0,
            	1275, 0,
            	1342, 0,
            	1347, 0,
            	1352, 0,
            	1357, 0,
            	1252, 0,
            	1362, 0,
            	1367, 0,
            	1372, 0,
            	1242, 0,
            	1377, 0,
            	1382, 0,
            	1387, 0,
            	1392, 0,
            	1397, 0,
            	1260, 0,
            	1260, 0,
            	611, 0,
            1, 8, 1, /* 1342: pointer.struct.asn1_string_st */
            	1247, 0,
            1, 8, 1, /* 1347: pointer.struct.asn1_string_st */
            	1247, 0,
            1, 8, 1, /* 1352: pointer.struct.asn1_string_st */
            	1247, 0,
            1, 8, 1, /* 1357: pointer.struct.asn1_string_st */
            	1247, 0,
            1, 8, 1, /* 1362: pointer.struct.asn1_string_st */
            	1247, 0,
            1, 8, 1, /* 1367: pointer.struct.asn1_string_st */
            	1247, 0,
            1, 8, 1, /* 1372: pointer.struct.asn1_string_st */
            	1247, 0,
            1, 8, 1, /* 1377: pointer.struct.asn1_string_st */
            	1247, 0,
            1, 8, 1, /* 1382: pointer.struct.asn1_string_st */
            	1247, 0,
            1, 8, 1, /* 1387: pointer.struct.asn1_string_st */
            	1247, 0,
            1, 8, 1, /* 1392: pointer.struct.asn1_string_st */
            	1247, 0,
            1, 8, 1, /* 1397: pointer.struct.asn1_string_st */
            	1247, 0,
            0, 0, 0, /* 1402: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1405: pointer.struct.x509_st */
            	1410, 0,
            0, 184, 12, /* 1410: struct.x509_st */
            	1437, 0,
            	467, 8,
            	433, 16,
            	93, 32,
            	1653, 40,
            	556, 104,
            	825, 112,
            	2222, 120,
            	2230, 128,
            	2268, 136,
            	2292, 144,
            	2604, 176,
            1, 8, 1, /* 1437: pointer.struct.x509_cinf_st */
            	1442, 0,
            0, 104, 11, /* 1442: struct.x509_cinf_st */
            	462, 0,
            	462, 8,
            	467, 16,
            	409, 24,
            	1467, 32,
            	409, 40,
            	1479, 48,
            	433, 56,
            	433, 64,
            	763, 72,
            	787, 80,
            1, 8, 1, /* 1467: pointer.struct.X509_val_st */
            	1472, 0,
            0, 16, 2, /* 1472: struct.X509_val_st */
            	619, 0,
            	619, 8,
            1, 8, 1, /* 1479: pointer.struct.X509_pubkey_st */
            	1484, 0,
            0, 24, 3, /* 1484: struct.X509_pubkey_st */
            	467, 0,
            	433, 8,
            	1493, 16,
            1, 8, 1, /* 1493: pointer.struct.evp_pkey_st */
            	1498, 0,
            0, 56, 4, /* 1498: struct.evp_pkey_st */
            	1509, 16,
            	1517, 24,
            	1525, 32,
            	1854, 48,
            1, 8, 1, /* 1509: pointer.struct.evp_pkey_asn1_method_st */
            	1514, 0,
            0, 0, 0, /* 1514: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 1517: pointer.struct.engine_st */
            	1522, 0,
            0, 0, 0, /* 1522: struct.engine_st */
            0, 8, 5, /* 1525: union.unknown */
            	93, 0,
            	1538, 0,
            	1697, 0,
            	1778, 0,
            	1846, 0,
            1, 8, 1, /* 1538: pointer.struct.rsa_st */
            	1543, 0,
            0, 168, 17, /* 1543: struct.rsa_st */
            	1580, 16,
            	1517, 24,
            	1635, 32,
            	1635, 40,
            	1635, 48,
            	1635, 56,
            	1635, 64,
            	1635, 72,
            	1635, 80,
            	1635, 88,
            	1653, 96,
            	1675, 120,
            	1675, 128,
            	1675, 136,
            	93, 144,
            	1689, 152,
            	1689, 160,
            1, 8, 1, /* 1580: pointer.struct.rsa_meth_st */
            	1585, 0,
            0, 112, 13, /* 1585: struct.rsa_meth_st */
            	124, 0,
            	1614, 8,
            	1614, 16,
            	1614, 24,
            	1614, 32,
            	1617, 40,
            	1620, 48,
            	1623, 56,
            	1623, 64,
            	93, 80,
            	1626, 88,
            	1629, 96,
            	1632, 104,
            8884097, 8, 0, /* 1614: pointer.func */
            8884097, 8, 0, /* 1617: pointer.func */
            8884097, 8, 0, /* 1620: pointer.func */
            8884097, 8, 0, /* 1623: pointer.func */
            8884097, 8, 0, /* 1626: pointer.func */
            8884097, 8, 0, /* 1629: pointer.func */
            8884097, 8, 0, /* 1632: pointer.func */
            1, 8, 1, /* 1635: pointer.struct.bignum_st */
            	1640, 0,
            0, 24, 1, /* 1640: struct.bignum_st */
            	1645, 0,
            1, 8, 1, /* 1645: pointer.unsigned int */
            	1650, 0,
            0, 4, 0, /* 1650: unsigned int */
            0, 16, 1, /* 1653: struct.crypto_ex_data_st */
            	1658, 0,
            1, 8, 1, /* 1658: pointer.struct.stack_st_void */
            	1663, 0,
            0, 32, 1, /* 1663: struct.stack_st_void */
            	1668, 0,
            0, 32, 2, /* 1668: struct.stack_st */
            	885, 8,
            	360, 24,
            1, 8, 1, /* 1675: pointer.struct.bn_mont_ctx_st */
            	1680, 0,
            0, 96, 3, /* 1680: struct.bn_mont_ctx_st */
            	1640, 8,
            	1640, 32,
            	1640, 56,
            1, 8, 1, /* 1689: pointer.struct.bn_blinding_st */
            	1694, 0,
            0, 0, 0, /* 1694: struct.bn_blinding_st */
            1, 8, 1, /* 1697: pointer.struct.dsa_st */
            	1702, 0,
            0, 136, 11, /* 1702: struct.dsa_st */
            	1635, 24,
            	1635, 32,
            	1635, 40,
            	1635, 48,
            	1635, 56,
            	1635, 64,
            	1635, 72,
            	1675, 88,
            	1653, 104,
            	1727, 120,
            	1517, 128,
            1, 8, 1, /* 1727: pointer.struct.dsa_method */
            	1732, 0,
            0, 96, 11, /* 1732: struct.dsa_method */
            	124, 0,
            	1757, 8,
            	1760, 16,
            	1763, 24,
            	1766, 32,
            	1769, 40,
            	1772, 48,
            	1772, 56,
            	93, 72,
            	1775, 80,
            	1772, 88,
            8884097, 8, 0, /* 1757: pointer.func */
            8884097, 8, 0, /* 1760: pointer.func */
            8884097, 8, 0, /* 1763: pointer.func */
            8884097, 8, 0, /* 1766: pointer.func */
            8884097, 8, 0, /* 1769: pointer.func */
            8884097, 8, 0, /* 1772: pointer.func */
            8884097, 8, 0, /* 1775: pointer.func */
            1, 8, 1, /* 1778: pointer.struct.dh_st */
            	1783, 0,
            0, 144, 12, /* 1783: struct.dh_st */
            	1635, 8,
            	1635, 16,
            	1635, 32,
            	1635, 40,
            	1675, 56,
            	1635, 64,
            	1635, 72,
            	200, 80,
            	1635, 96,
            	1653, 112,
            	1810, 128,
            	1517, 136,
            1, 8, 1, /* 1810: pointer.struct.dh_method */
            	1815, 0,
            0, 72, 8, /* 1815: struct.dh_method */
            	124, 0,
            	1834, 8,
            	1837, 16,
            	1840, 24,
            	1834, 32,
            	1834, 40,
            	93, 56,
            	1843, 64,
            8884097, 8, 0, /* 1834: pointer.func */
            8884097, 8, 0, /* 1837: pointer.func */
            8884097, 8, 0, /* 1840: pointer.func */
            8884097, 8, 0, /* 1843: pointer.func */
            1, 8, 1, /* 1846: pointer.struct.ec_key_st */
            	1851, 0,
            0, 0, 0, /* 1851: struct.ec_key_st */
            1, 8, 1, /* 1854: pointer.struct.stack_st_X509_ATTRIBUTE */
            	1859, 0,
            0, 32, 2, /* 1859: struct.stack_st_fake_X509_ATTRIBUTE */
            	1866, 8,
            	360, 24,
            8884099, 8, 2, /* 1866: pointer_to_array_of_pointers_to_stack */
            	1873, 0,
            	357, 20,
            0, 8, 1, /* 1873: pointer.X509_ATTRIBUTE */
            	1878, 0,
            0, 0, 1, /* 1878: X509_ATTRIBUTE */
            	1883, 0,
            0, 24, 2, /* 1883: struct.x509_attributes_st */
            	1890, 0,
            	1904, 16,
            1, 8, 1, /* 1890: pointer.struct.asn1_object_st */
            	1895, 0,
            0, 40, 3, /* 1895: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            0, 8, 3, /* 1904: union.unknown */
            	93, 0,
            	1913, 0,
            	2089, 0,
            1, 8, 1, /* 1913: pointer.struct.stack_st_ASN1_TYPE */
            	1918, 0,
            0, 32, 2, /* 1918: struct.stack_st_fake_ASN1_TYPE */
            	1925, 8,
            	360, 24,
            8884099, 8, 2, /* 1925: pointer_to_array_of_pointers_to_stack */
            	1932, 0,
            	357, 20,
            0, 8, 1, /* 1932: pointer.ASN1_TYPE */
            	1937, 0,
            0, 0, 1, /* 1937: ASN1_TYPE */
            	1942, 0,
            0, 16, 1, /* 1942: struct.asn1_type_st */
            	1947, 8,
            0, 8, 20, /* 1947: union.unknown */
            	93, 0,
            	1990, 0,
            	2000, 0,
            	2014, 0,
            	2019, 0,
            	2024, 0,
            	2029, 0,
            	2034, 0,
            	2039, 0,
            	2044, 0,
            	2049, 0,
            	2054, 0,
            	2059, 0,
            	2064, 0,
            	2069, 0,
            	2074, 0,
            	2079, 0,
            	1990, 0,
            	1990, 0,
            	2084, 0,
            1, 8, 1, /* 1990: pointer.struct.asn1_string_st */
            	1995, 0,
            0, 24, 1, /* 1995: struct.asn1_string_st */
            	200, 8,
            1, 8, 1, /* 2000: pointer.struct.asn1_object_st */
            	2005, 0,
            0, 40, 3, /* 2005: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            1, 8, 1, /* 2014: pointer.struct.asn1_string_st */
            	1995, 0,
            1, 8, 1, /* 2019: pointer.struct.asn1_string_st */
            	1995, 0,
            1, 8, 1, /* 2024: pointer.struct.asn1_string_st */
            	1995, 0,
            1, 8, 1, /* 2029: pointer.struct.asn1_string_st */
            	1995, 0,
            1, 8, 1, /* 2034: pointer.struct.asn1_string_st */
            	1995, 0,
            1, 8, 1, /* 2039: pointer.struct.asn1_string_st */
            	1995, 0,
            1, 8, 1, /* 2044: pointer.struct.asn1_string_st */
            	1995, 0,
            1, 8, 1, /* 2049: pointer.struct.asn1_string_st */
            	1995, 0,
            1, 8, 1, /* 2054: pointer.struct.asn1_string_st */
            	1995, 0,
            1, 8, 1, /* 2059: pointer.struct.asn1_string_st */
            	1995, 0,
            1, 8, 1, /* 2064: pointer.struct.asn1_string_st */
            	1995, 0,
            1, 8, 1, /* 2069: pointer.struct.asn1_string_st */
            	1995, 0,
            1, 8, 1, /* 2074: pointer.struct.asn1_string_st */
            	1995, 0,
            1, 8, 1, /* 2079: pointer.struct.asn1_string_st */
            	1995, 0,
            1, 8, 1, /* 2084: pointer.struct.ASN1_VALUE_st */
            	1402, 0,
            1, 8, 1, /* 2089: pointer.struct.asn1_type_st */
            	2094, 0,
            0, 16, 1, /* 2094: struct.asn1_type_st */
            	2099, 8,
            0, 8, 20, /* 2099: union.unknown */
            	93, 0,
            	2142, 0,
            	1890, 0,
            	2152, 0,
            	2157, 0,
            	2162, 0,
            	2167, 0,
            	2172, 0,
            	2177, 0,
            	2182, 0,
            	2187, 0,
            	2192, 0,
            	2197, 0,
            	2202, 0,
            	2207, 0,
            	2212, 0,
            	2217, 0,
            	2142, 0,
            	2142, 0,
            	611, 0,
            1, 8, 1, /* 2142: pointer.struct.asn1_string_st */
            	2147, 0,
            0, 24, 1, /* 2147: struct.asn1_string_st */
            	200, 8,
            1, 8, 1, /* 2152: pointer.struct.asn1_string_st */
            	2147, 0,
            1, 8, 1, /* 2157: pointer.struct.asn1_string_st */
            	2147, 0,
            1, 8, 1, /* 2162: pointer.struct.asn1_string_st */
            	2147, 0,
            1, 8, 1, /* 2167: pointer.struct.asn1_string_st */
            	2147, 0,
            1, 8, 1, /* 2172: pointer.struct.asn1_string_st */
            	2147, 0,
            1, 8, 1, /* 2177: pointer.struct.asn1_string_st */
            	2147, 0,
            1, 8, 1, /* 2182: pointer.struct.asn1_string_st */
            	2147, 0,
            1, 8, 1, /* 2187: pointer.struct.asn1_string_st */
            	2147, 0,
            1, 8, 1, /* 2192: pointer.struct.asn1_string_st */
            	2147, 0,
            1, 8, 1, /* 2197: pointer.struct.asn1_string_st */
            	2147, 0,
            1, 8, 1, /* 2202: pointer.struct.asn1_string_st */
            	2147, 0,
            1, 8, 1, /* 2207: pointer.struct.asn1_string_st */
            	2147, 0,
            1, 8, 1, /* 2212: pointer.struct.asn1_string_st */
            	2147, 0,
            1, 8, 1, /* 2217: pointer.struct.asn1_string_st */
            	2147, 0,
            1, 8, 1, /* 2222: pointer.struct.X509_POLICY_CACHE_st */
            	2227, 0,
            0, 0, 0, /* 2227: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 2230: pointer.struct.stack_st_DIST_POINT */
            	2235, 0,
            0, 32, 2, /* 2235: struct.stack_st_fake_DIST_POINT */
            	2242, 8,
            	360, 24,
            8884099, 8, 2, /* 2242: pointer_to_array_of_pointers_to_stack */
            	2249, 0,
            	357, 20,
            0, 8, 1, /* 2249: pointer.DIST_POINT */
            	2254, 0,
            0, 0, 1, /* 2254: DIST_POINT */
            	2259, 0,
            0, 32, 3, /* 2259: struct.DIST_POINT_st */
            	7, 0,
            	433, 8,
            	26, 16,
            1, 8, 1, /* 2268: pointer.struct.stack_st_GENERAL_NAME */
            	2273, 0,
            0, 32, 2, /* 2273: struct.stack_st_fake_GENERAL_NAME */
            	2280, 8,
            	360, 24,
            8884099, 8, 2, /* 2280: pointer_to_array_of_pointers_to_stack */
            	2287, 0,
            	357, 20,
            0, 8, 1, /* 2287: pointer.GENERAL_NAME */
            	50, 0,
            1, 8, 1, /* 2292: pointer.struct.NAME_CONSTRAINTS_st */
            	2297, 0,
            0, 16, 2, /* 2297: struct.NAME_CONSTRAINTS_st */
            	2304, 0,
            	2304, 8,
            1, 8, 1, /* 2304: pointer.struct.stack_st_GENERAL_SUBTREE */
            	2309, 0,
            0, 32, 2, /* 2309: struct.stack_st_fake_GENERAL_SUBTREE */
            	2316, 8,
            	360, 24,
            8884099, 8, 2, /* 2316: pointer_to_array_of_pointers_to_stack */
            	2323, 0,
            	357, 20,
            0, 8, 1, /* 2323: pointer.GENERAL_SUBTREE */
            	2328, 0,
            0, 0, 1, /* 2328: GENERAL_SUBTREE */
            	2333, 0,
            0, 24, 3, /* 2333: struct.GENERAL_SUBTREE_st */
            	2342, 0,
            	2474, 8,
            	2474, 16,
            1, 8, 1, /* 2342: pointer.struct.GENERAL_NAME_st */
            	2347, 0,
            0, 16, 1, /* 2347: struct.GENERAL_NAME_st */
            	2352, 8,
            0, 8, 15, /* 2352: union.unknown */
            	93, 0,
            	2385, 0,
            	2504, 0,
            	2504, 0,
            	2411, 0,
            	2544, 0,
            	2592, 0,
            	2504, 0,
            	2489, 0,
            	2397, 0,
            	2489, 0,
            	2544, 0,
            	2504, 0,
            	2397, 0,
            	2411, 0,
            1, 8, 1, /* 2385: pointer.struct.otherName_st */
            	2390, 0,
            0, 16, 2, /* 2390: struct.otherName_st */
            	2397, 0,
            	2411, 8,
            1, 8, 1, /* 2397: pointer.struct.asn1_object_st */
            	2402, 0,
            0, 40, 3, /* 2402: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            1, 8, 1, /* 2411: pointer.struct.asn1_type_st */
            	2416, 0,
            0, 16, 1, /* 2416: struct.asn1_type_st */
            	2421, 8,
            0, 8, 20, /* 2421: union.unknown */
            	93, 0,
            	2464, 0,
            	2397, 0,
            	2474, 0,
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
            	2464, 0,
            	2464, 0,
            	275, 0,
            1, 8, 1, /* 2464: pointer.struct.asn1_string_st */
            	2469, 0,
            0, 24, 1, /* 2469: struct.asn1_string_st */
            	200, 8,
            1, 8, 1, /* 2474: pointer.struct.asn1_string_st */
            	2469, 0,
            1, 8, 1, /* 2479: pointer.struct.asn1_string_st */
            	2469, 0,
            1, 8, 1, /* 2484: pointer.struct.asn1_string_st */
            	2469, 0,
            1, 8, 1, /* 2489: pointer.struct.asn1_string_st */
            	2469, 0,
            1, 8, 1, /* 2494: pointer.struct.asn1_string_st */
            	2469, 0,
            1, 8, 1, /* 2499: pointer.struct.asn1_string_st */
            	2469, 0,
            1, 8, 1, /* 2504: pointer.struct.asn1_string_st */
            	2469, 0,
            1, 8, 1, /* 2509: pointer.struct.asn1_string_st */
            	2469, 0,
            1, 8, 1, /* 2514: pointer.struct.asn1_string_st */
            	2469, 0,
            1, 8, 1, /* 2519: pointer.struct.asn1_string_st */
            	2469, 0,
            1, 8, 1, /* 2524: pointer.struct.asn1_string_st */
            	2469, 0,
            1, 8, 1, /* 2529: pointer.struct.asn1_string_st */
            	2469, 0,
            1, 8, 1, /* 2534: pointer.struct.asn1_string_st */
            	2469, 0,
            1, 8, 1, /* 2539: pointer.struct.asn1_string_st */
            	2469, 0,
            1, 8, 1, /* 2544: pointer.struct.X509_name_st */
            	2549, 0,
            0, 40, 3, /* 2549: struct.X509_name_st */
            	2558, 0,
            	2582, 16,
            	200, 24,
            1, 8, 1, /* 2558: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2563, 0,
            0, 32, 2, /* 2563: struct.stack_st_fake_X509_NAME_ENTRY */
            	2570, 8,
            	360, 24,
            8884099, 8, 2, /* 2570: pointer_to_array_of_pointers_to_stack */
            	2577, 0,
            	357, 20,
            0, 8, 1, /* 2577: pointer.X509_NAME_ENTRY */
            	321, 0,
            1, 8, 1, /* 2582: pointer.struct.buf_mem_st */
            	2587, 0,
            0, 24, 1, /* 2587: struct.buf_mem_st */
            	93, 8,
            1, 8, 1, /* 2592: pointer.struct.EDIPartyName_st */
            	2597, 0,
            0, 16, 2, /* 2597: struct.EDIPartyName_st */
            	2464, 0,
            	2464, 8,
            1, 8, 1, /* 2604: pointer.struct.x509_cert_aux_st */
            	2609, 0,
            0, 40, 5, /* 2609: struct.x509_cert_aux_st */
            	2622, 0,
            	2622, 8,
            	606, 16,
            	556, 24,
            	2660, 32,
            1, 8, 1, /* 2622: pointer.struct.stack_st_ASN1_OBJECT */
            	2627, 0,
            0, 32, 2, /* 2627: struct.stack_st_fake_ASN1_OBJECT */
            	2634, 8,
            	360, 24,
            8884099, 8, 2, /* 2634: pointer_to_array_of_pointers_to_stack */
            	2641, 0,
            	357, 20,
            0, 8, 1, /* 2641: pointer.ASN1_OBJECT */
            	2646, 0,
            0, 0, 1, /* 2646: ASN1_OBJECT */
            	2651, 0,
            0, 40, 3, /* 2651: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            1, 8, 1, /* 2660: pointer.struct.stack_st_X509_ALGOR */
            	2665, 0,
            0, 32, 2, /* 2665: struct.stack_st_fake_X509_ALGOR */
            	2672, 8,
            	360, 24,
            8884099, 8, 2, /* 2672: pointer_to_array_of_pointers_to_stack */
            	2679, 0,
            	357, 20,
            0, 8, 1, /* 2679: pointer.X509_ALGOR */
            	2684, 0,
            0, 0, 1, /* 2684: X509_ALGOR */
            	1268, 0,
            1, 8, 1, /* 2689: pointer.struct.NAME_CONSTRAINTS_st */
            	2694, 0,
            0, 0, 0, /* 2694: struct.NAME_CONSTRAINTS_st */
            8884097, 8, 0, /* 2697: pointer.func */
            1, 8, 1, /* 2700: pointer.struct.ASN1_VALUE_st */
            	2705, 0,
            0, 0, 0, /* 2705: struct.ASN1_VALUE_st */
            0, 16, 1, /* 2708: struct.crypto_ex_data_st */
            	2713, 0,
            1, 8, 1, /* 2713: pointer.struct.stack_st_void */
            	2718, 0,
            0, 32, 1, /* 2718: struct.stack_st_void */
            	2723, 0,
            0, 32, 2, /* 2723: struct.stack_st */
            	885, 8,
            	360, 24,
            0, 32, 3, /* 2730: struct.x509_lookup_st */
            	2739, 8,
            	93, 16,
            	2788, 24,
            1, 8, 1, /* 2739: pointer.struct.x509_lookup_method_st */
            	2744, 0,
            0, 80, 10, /* 2744: struct.x509_lookup_method_st */
            	124, 0,
            	2767, 8,
            	2770, 16,
            	2767, 24,
            	2767, 32,
            	2773, 40,
            	2776, 48,
            	2779, 56,
            	2782, 64,
            	2785, 72,
            8884097, 8, 0, /* 2767: pointer.func */
            8884097, 8, 0, /* 2770: pointer.func */
            8884097, 8, 0, /* 2773: pointer.func */
            8884097, 8, 0, /* 2776: pointer.func */
            8884097, 8, 0, /* 2779: pointer.func */
            8884097, 8, 0, /* 2782: pointer.func */
            8884097, 8, 0, /* 2785: pointer.func */
            1, 8, 1, /* 2788: pointer.struct.x509_store_st */
            	2793, 0,
            0, 144, 15, /* 2793: struct.x509_store_st */
            	2826, 8,
            	3710, 16,
            	3739, 24,
            	3751, 32,
            	3754, 40,
            	3757, 48,
            	3760, 56,
            	3751, 64,
            	1257, 72,
            	3763, 80,
            	3766, 88,
            	3769, 96,
            	3772, 104,
            	3751, 112,
            	2708, 120,
            1, 8, 1, /* 2826: pointer.struct.stack_st_X509_OBJECT */
            	2831, 0,
            0, 32, 2, /* 2831: struct.stack_st_fake_X509_OBJECT */
            	2838, 8,
            	360, 24,
            8884099, 8, 2, /* 2838: pointer_to_array_of_pointers_to_stack */
            	2845, 0,
            	357, 20,
            0, 8, 1, /* 2845: pointer.X509_OBJECT */
            	2850, 0,
            0, 0, 1, /* 2850: X509_OBJECT */
            	2855, 0,
            0, 16, 1, /* 2855: struct.x509_object_st */
            	2860, 8,
            0, 8, 4, /* 2860: union.unknown */
            	93, 0,
            	2871, 0,
            	3634, 0,
            	3171, 0,
            1, 8, 1, /* 2871: pointer.struct.x509_st */
            	2876, 0,
            0, 184, 12, /* 2876: struct.x509_st */
            	2903, 0,
            	2943, 8,
            	3032, 16,
            	93, 32,
            	2708, 40,
            	3037, 104,
            	1226, 112,
            	2222, 120,
            	3520, 128,
            	3544, 136,
            	2689, 144,
            	3568, 176,
            1, 8, 1, /* 2903: pointer.struct.x509_cinf_st */
            	2908, 0,
            0, 104, 11, /* 2908: struct.x509_cinf_st */
            	2933, 0,
            	2933, 8,
            	2943, 16,
            	3092, 24,
            	3140, 32,
            	3092, 40,
            	3157, 48,
            	3032, 56,
            	3032, 64,
            	3491, 72,
            	3515, 80,
            1, 8, 1, /* 2933: pointer.struct.asn1_string_st */
            	2938, 0,
            0, 24, 1, /* 2938: struct.asn1_string_st */
            	200, 8,
            1, 8, 1, /* 2943: pointer.struct.X509_algor_st */
            	2948, 0,
            0, 16, 2, /* 2948: struct.X509_algor_st */
            	2955, 0,
            	2969, 8,
            1, 8, 1, /* 2955: pointer.struct.asn1_object_st */
            	2960, 0,
            0, 40, 3, /* 2960: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            1, 8, 1, /* 2969: pointer.struct.asn1_type_st */
            	2974, 0,
            0, 16, 1, /* 2974: struct.asn1_type_st */
            	2979, 8,
            0, 8, 20, /* 2979: union.unknown */
            	93, 0,
            	3022, 0,
            	2955, 0,
            	2933, 0,
            	3027, 0,
            	3032, 0,
            	3037, 0,
            	3042, 0,
            	3047, 0,
            	3052, 0,
            	3057, 0,
            	3062, 0,
            	3067, 0,
            	3072, 0,
            	3077, 0,
            	3082, 0,
            	3087, 0,
            	3022, 0,
            	3022, 0,
            	611, 0,
            1, 8, 1, /* 3022: pointer.struct.asn1_string_st */
            	2938, 0,
            1, 8, 1, /* 3027: pointer.struct.asn1_string_st */
            	2938, 0,
            1, 8, 1, /* 3032: pointer.struct.asn1_string_st */
            	2938, 0,
            1, 8, 1, /* 3037: pointer.struct.asn1_string_st */
            	2938, 0,
            1, 8, 1, /* 3042: pointer.struct.asn1_string_st */
            	2938, 0,
            1, 8, 1, /* 3047: pointer.struct.asn1_string_st */
            	2938, 0,
            1, 8, 1, /* 3052: pointer.struct.asn1_string_st */
            	2938, 0,
            1, 8, 1, /* 3057: pointer.struct.asn1_string_st */
            	2938, 0,
            1, 8, 1, /* 3062: pointer.struct.asn1_string_st */
            	2938, 0,
            1, 8, 1, /* 3067: pointer.struct.asn1_string_st */
            	2938, 0,
            1, 8, 1, /* 3072: pointer.struct.asn1_string_st */
            	2938, 0,
            1, 8, 1, /* 3077: pointer.struct.asn1_string_st */
            	2938, 0,
            1, 8, 1, /* 3082: pointer.struct.asn1_string_st */
            	2938, 0,
            1, 8, 1, /* 3087: pointer.struct.asn1_string_st */
            	2938, 0,
            1, 8, 1, /* 3092: pointer.struct.X509_name_st */
            	3097, 0,
            0, 40, 3, /* 3097: struct.X509_name_st */
            	3106, 0,
            	3130, 16,
            	200, 24,
            1, 8, 1, /* 3106: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3111, 0,
            0, 32, 2, /* 3111: struct.stack_st_fake_X509_NAME_ENTRY */
            	3118, 8,
            	360, 24,
            8884099, 8, 2, /* 3118: pointer_to_array_of_pointers_to_stack */
            	3125, 0,
            	357, 20,
            0, 8, 1, /* 3125: pointer.X509_NAME_ENTRY */
            	321, 0,
            1, 8, 1, /* 3130: pointer.struct.buf_mem_st */
            	3135, 0,
            0, 24, 1, /* 3135: struct.buf_mem_st */
            	93, 8,
            1, 8, 1, /* 3140: pointer.struct.X509_val_st */
            	3145, 0,
            0, 16, 2, /* 3145: struct.X509_val_st */
            	3152, 0,
            	3152, 8,
            1, 8, 1, /* 3152: pointer.struct.asn1_string_st */
            	2938, 0,
            1, 8, 1, /* 3157: pointer.struct.X509_pubkey_st */
            	3162, 0,
            0, 24, 3, /* 3162: struct.X509_pubkey_st */
            	2943, 0,
            	3032, 8,
            	3171, 16,
            1, 8, 1, /* 3171: pointer.struct.evp_pkey_st */
            	3176, 0,
            0, 56, 4, /* 3176: struct.evp_pkey_st */
            	1509, 16,
            	1517, 24,
            	3187, 32,
            	3467, 48,
            0, 8, 5, /* 3187: union.unknown */
            	93, 0,
            	3200, 0,
            	3318, 0,
            	3399, 0,
            	1846, 0,
            1, 8, 1, /* 3200: pointer.struct.rsa_st */
            	3205, 0,
            0, 168, 17, /* 3205: struct.rsa_st */
            	3242, 16,
            	1517, 24,
            	3294, 32,
            	3294, 40,
            	3294, 48,
            	3294, 56,
            	3294, 64,
            	3294, 72,
            	3294, 80,
            	3294, 88,
            	2708, 96,
            	3304, 120,
            	3304, 128,
            	3304, 136,
            	93, 144,
            	1689, 152,
            	1689, 160,
            1, 8, 1, /* 3242: pointer.struct.rsa_meth_st */
            	3247, 0,
            0, 112, 13, /* 3247: struct.rsa_meth_st */
            	124, 0,
            	3276, 8,
            	3276, 16,
            	3276, 24,
            	3276, 32,
            	3279, 40,
            	3282, 48,
            	3285, 56,
            	3285, 64,
            	93, 80,
            	2697, 88,
            	3288, 96,
            	3291, 104,
            8884097, 8, 0, /* 3276: pointer.func */
            8884097, 8, 0, /* 3279: pointer.func */
            8884097, 8, 0, /* 3282: pointer.func */
            8884097, 8, 0, /* 3285: pointer.func */
            8884097, 8, 0, /* 3288: pointer.func */
            8884097, 8, 0, /* 3291: pointer.func */
            1, 8, 1, /* 3294: pointer.struct.bignum_st */
            	3299, 0,
            0, 24, 1, /* 3299: struct.bignum_st */
            	1645, 0,
            1, 8, 1, /* 3304: pointer.struct.bn_mont_ctx_st */
            	3309, 0,
            0, 96, 3, /* 3309: struct.bn_mont_ctx_st */
            	3299, 8,
            	3299, 32,
            	3299, 56,
            1, 8, 1, /* 3318: pointer.struct.dsa_st */
            	3323, 0,
            0, 136, 11, /* 3323: struct.dsa_st */
            	3294, 24,
            	3294, 32,
            	3294, 40,
            	3294, 48,
            	3294, 56,
            	3294, 64,
            	3294, 72,
            	3304, 88,
            	2708, 104,
            	3348, 120,
            	1517, 128,
            1, 8, 1, /* 3348: pointer.struct.dsa_method */
            	3353, 0,
            0, 96, 11, /* 3353: struct.dsa_method */
            	124, 0,
            	3378, 8,
            	3381, 16,
            	3384, 24,
            	3387, 32,
            	3390, 40,
            	3393, 48,
            	3393, 56,
            	93, 72,
            	3396, 80,
            	3393, 88,
            8884097, 8, 0, /* 3378: pointer.func */
            8884097, 8, 0, /* 3381: pointer.func */
            8884097, 8, 0, /* 3384: pointer.func */
            8884097, 8, 0, /* 3387: pointer.func */
            8884097, 8, 0, /* 3390: pointer.func */
            8884097, 8, 0, /* 3393: pointer.func */
            8884097, 8, 0, /* 3396: pointer.func */
            1, 8, 1, /* 3399: pointer.struct.dh_st */
            	3404, 0,
            0, 144, 12, /* 3404: struct.dh_st */
            	3294, 8,
            	3294, 16,
            	3294, 32,
            	3294, 40,
            	3304, 56,
            	3294, 64,
            	3294, 72,
            	200, 80,
            	3294, 96,
            	2708, 112,
            	3431, 128,
            	1517, 136,
            1, 8, 1, /* 3431: pointer.struct.dh_method */
            	3436, 0,
            0, 72, 8, /* 3436: struct.dh_method */
            	124, 0,
            	3455, 8,
            	3458, 16,
            	3461, 24,
            	3455, 32,
            	3455, 40,
            	93, 56,
            	3464, 64,
            8884097, 8, 0, /* 3455: pointer.func */
            8884097, 8, 0, /* 3458: pointer.func */
            8884097, 8, 0, /* 3461: pointer.func */
            8884097, 8, 0, /* 3464: pointer.func */
            1, 8, 1, /* 3467: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3472, 0,
            0, 32, 2, /* 3472: struct.stack_st_fake_X509_ATTRIBUTE */
            	3479, 8,
            	360, 24,
            8884099, 8, 2, /* 3479: pointer_to_array_of_pointers_to_stack */
            	3486, 0,
            	357, 20,
            0, 8, 1, /* 3486: pointer.X509_ATTRIBUTE */
            	1878, 0,
            1, 8, 1, /* 3491: pointer.struct.stack_st_X509_EXTENSION */
            	3496, 0,
            0, 32, 2, /* 3496: struct.stack_st_fake_X509_EXTENSION */
            	3503, 8,
            	360, 24,
            8884099, 8, 2, /* 3503: pointer_to_array_of_pointers_to_stack */
            	3510, 0,
            	357, 20,
            0, 8, 1, /* 3510: pointer.X509_EXTENSION */
            	703, 0,
            0, 24, 1, /* 3515: struct.ASN1_ENCODING_st */
            	200, 0,
            1, 8, 1, /* 3520: pointer.struct.stack_st_DIST_POINT */
            	3525, 0,
            0, 32, 2, /* 3525: struct.stack_st_fake_DIST_POINT */
            	3532, 8,
            	360, 24,
            8884099, 8, 2, /* 3532: pointer_to_array_of_pointers_to_stack */
            	3539, 0,
            	357, 20,
            0, 8, 1, /* 3539: pointer.DIST_POINT */
            	2254, 0,
            1, 8, 1, /* 3544: pointer.struct.stack_st_GENERAL_NAME */
            	3549, 0,
            0, 32, 2, /* 3549: struct.stack_st_fake_GENERAL_NAME */
            	3556, 8,
            	360, 24,
            8884099, 8, 2, /* 3556: pointer_to_array_of_pointers_to_stack */
            	3563, 0,
            	357, 20,
            0, 8, 1, /* 3563: pointer.GENERAL_NAME */
            	50, 0,
            1, 8, 1, /* 3568: pointer.struct.x509_cert_aux_st */
            	3573, 0,
            0, 40, 5, /* 3573: struct.x509_cert_aux_st */
            	3586, 0,
            	3586, 8,
            	3087, 16,
            	3037, 24,
            	3610, 32,
            1, 8, 1, /* 3586: pointer.struct.stack_st_ASN1_OBJECT */
            	3591, 0,
            0, 32, 2, /* 3591: struct.stack_st_fake_ASN1_OBJECT */
            	3598, 8,
            	360, 24,
            8884099, 8, 2, /* 3598: pointer_to_array_of_pointers_to_stack */
            	3605, 0,
            	357, 20,
            0, 8, 1, /* 3605: pointer.ASN1_OBJECT */
            	2646, 0,
            1, 8, 1, /* 3610: pointer.struct.stack_st_X509_ALGOR */
            	3615, 0,
            0, 32, 2, /* 3615: struct.stack_st_fake_X509_ALGOR */
            	3622, 8,
            	360, 24,
            8884099, 8, 2, /* 3622: pointer_to_array_of_pointers_to_stack */
            	3629, 0,
            	357, 20,
            0, 8, 1, /* 3629: pointer.X509_ALGOR */
            	2684, 0,
            1, 8, 1, /* 3634: pointer.struct.X509_crl_st */
            	3639, 0,
            0, 120, 10, /* 3639: struct.X509_crl_st */
            	3662, 0,
            	2943, 8,
            	3032, 16,
            	1226, 32,
            	1234, 40,
            	2933, 56,
            	2933, 64,
            	844, 96,
            	890, 104,
            	898, 112,
            1, 8, 1, /* 3662: pointer.struct.X509_crl_info_st */
            	3667, 0,
            0, 80, 8, /* 3667: struct.X509_crl_info_st */
            	2933, 0,
            	2943, 8,
            	3092, 16,
            	3152, 24,
            	3152, 32,
            	3686, 40,
            	3491, 48,
            	3515, 56,
            1, 8, 1, /* 3686: pointer.struct.stack_st_X509_REVOKED */
            	3691, 0,
            0, 32, 2, /* 3691: struct.stack_st_fake_X509_REVOKED */
            	3698, 8,
            	360, 24,
            8884099, 8, 2, /* 3698: pointer_to_array_of_pointers_to_stack */
            	3705, 0,
            	357, 20,
            0, 8, 1, /* 3705: pointer.X509_REVOKED */
            	648, 0,
            1, 8, 1, /* 3710: pointer.struct.stack_st_X509_LOOKUP */
            	3715, 0,
            0, 32, 2, /* 3715: struct.stack_st_fake_X509_LOOKUP */
            	3722, 8,
            	360, 24,
            8884099, 8, 2, /* 3722: pointer_to_array_of_pointers_to_stack */
            	3729, 0,
            	357, 20,
            0, 8, 1, /* 3729: pointer.X509_LOOKUP */
            	3734, 0,
            0, 0, 1, /* 3734: X509_LOOKUP */
            	2730, 0,
            1, 8, 1, /* 3739: pointer.struct.X509_VERIFY_PARAM_st */
            	3744, 0,
            0, 56, 2, /* 3744: struct.X509_VERIFY_PARAM_st */
            	93, 0,
            	3586, 48,
            8884097, 8, 0, /* 3751: pointer.func */
            8884097, 8, 0, /* 3754: pointer.func */
            8884097, 8, 0, /* 3757: pointer.func */
            8884097, 8, 0, /* 3760: pointer.func */
            8884097, 8, 0, /* 3763: pointer.func */
            8884097, 8, 0, /* 3766: pointer.func */
            8884097, 8, 0, /* 3769: pointer.func */
            8884097, 8, 0, /* 3772: pointer.func */
            1, 8, 1, /* 3775: pointer.struct.asn1_string_st */
            	3780, 0,
            0, 24, 1, /* 3780: struct.asn1_string_st */
            	200, 8,
            8884097, 8, 0, /* 3785: pointer.func */
            1, 8, 1, /* 3788: pointer.struct.asn1_string_st */
            	3780, 0,
            8884097, 8, 0, /* 3793: pointer.func */
            0, 0, 0, /* 3796: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 3799: pointer.struct.X509_pubkey_st */
            	3804, 0,
            0, 24, 3, /* 3804: struct.X509_pubkey_st */
            	3813, 0,
            	3907, 8,
            	3957, 16,
            1, 8, 1, /* 3813: pointer.struct.X509_algor_st */
            	3818, 0,
            0, 16, 2, /* 3818: struct.X509_algor_st */
            	3825, 0,
            	3839, 8,
            1, 8, 1, /* 3825: pointer.struct.asn1_object_st */
            	3830, 0,
            0, 40, 3, /* 3830: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            1, 8, 1, /* 3839: pointer.struct.asn1_type_st */
            	3844, 0,
            0, 16, 1, /* 3844: struct.asn1_type_st */
            	3849, 8,
            0, 8, 20, /* 3849: union.unknown */
            	93, 0,
            	3892, 0,
            	3825, 0,
            	3897, 0,
            	3902, 0,
            	3907, 0,
            	3912, 0,
            	3917, 0,
            	3922, 0,
            	3927, 0,
            	3932, 0,
            	3937, 0,
            	3942, 0,
            	3947, 0,
            	3952, 0,
            	3788, 0,
            	3775, 0,
            	3892, 0,
            	3892, 0,
            	2700, 0,
            1, 8, 1, /* 3892: pointer.struct.asn1_string_st */
            	3780, 0,
            1, 8, 1, /* 3897: pointer.struct.asn1_string_st */
            	3780, 0,
            1, 8, 1, /* 3902: pointer.struct.asn1_string_st */
            	3780, 0,
            1, 8, 1, /* 3907: pointer.struct.asn1_string_st */
            	3780, 0,
            1, 8, 1, /* 3912: pointer.struct.asn1_string_st */
            	3780, 0,
            1, 8, 1, /* 3917: pointer.struct.asn1_string_st */
            	3780, 0,
            1, 8, 1, /* 3922: pointer.struct.asn1_string_st */
            	3780, 0,
            1, 8, 1, /* 3927: pointer.struct.asn1_string_st */
            	3780, 0,
            1, 8, 1, /* 3932: pointer.struct.asn1_string_st */
            	3780, 0,
            1, 8, 1, /* 3937: pointer.struct.asn1_string_st */
            	3780, 0,
            1, 8, 1, /* 3942: pointer.struct.asn1_string_st */
            	3780, 0,
            1, 8, 1, /* 3947: pointer.struct.asn1_string_st */
            	3780, 0,
            1, 8, 1, /* 3952: pointer.struct.asn1_string_st */
            	3780, 0,
            1, 8, 1, /* 3957: pointer.struct.evp_pkey_st */
            	3962, 0,
            0, 56, 4, /* 3962: struct.evp_pkey_st */
            	3973, 16,
            	3981, 24,
            	3989, 32,
            	4307, 48,
            1, 8, 1, /* 3973: pointer.struct.evp_pkey_asn1_method_st */
            	3978, 0,
            0, 0, 0, /* 3978: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 3981: pointer.struct.engine_st */
            	3986, 0,
            0, 0, 0, /* 3986: struct.engine_st */
            0, 8, 5, /* 3989: union.unknown */
            	93, 0,
            	4002, 0,
            	4153, 0,
            	4231, 0,
            	4299, 0,
            1, 8, 1, /* 4002: pointer.struct.rsa_st */
            	4007, 0,
            0, 168, 17, /* 4007: struct.rsa_st */
            	4044, 16,
            	3981, 24,
            	4099, 32,
            	4099, 40,
            	4099, 48,
            	4099, 56,
            	4099, 64,
            	4099, 72,
            	4099, 80,
            	4099, 88,
            	4109, 96,
            	4131, 120,
            	4131, 128,
            	4131, 136,
            	93, 144,
            	4145, 152,
            	4145, 160,
            1, 8, 1, /* 4044: pointer.struct.rsa_meth_st */
            	4049, 0,
            0, 112, 13, /* 4049: struct.rsa_meth_st */
            	124, 0,
            	4078, 8,
            	4078, 16,
            	4078, 24,
            	4078, 32,
            	4081, 40,
            	4084, 48,
            	4087, 56,
            	4087, 64,
            	93, 80,
            	4090, 88,
            	4093, 96,
            	4096, 104,
            8884097, 8, 0, /* 4078: pointer.func */
            8884097, 8, 0, /* 4081: pointer.func */
            8884097, 8, 0, /* 4084: pointer.func */
            8884097, 8, 0, /* 4087: pointer.func */
            8884097, 8, 0, /* 4090: pointer.func */
            8884097, 8, 0, /* 4093: pointer.func */
            8884097, 8, 0, /* 4096: pointer.func */
            1, 8, 1, /* 4099: pointer.struct.bignum_st */
            	4104, 0,
            0, 24, 1, /* 4104: struct.bignum_st */
            	1645, 0,
            0, 16, 1, /* 4109: struct.crypto_ex_data_st */
            	4114, 0,
            1, 8, 1, /* 4114: pointer.struct.stack_st_void */
            	4119, 0,
            0, 32, 1, /* 4119: struct.stack_st_void */
            	4124, 0,
            0, 32, 2, /* 4124: struct.stack_st */
            	885, 8,
            	360, 24,
            1, 8, 1, /* 4131: pointer.struct.bn_mont_ctx_st */
            	4136, 0,
            0, 96, 3, /* 4136: struct.bn_mont_ctx_st */
            	4104, 8,
            	4104, 32,
            	4104, 56,
            1, 8, 1, /* 4145: pointer.struct.bn_blinding_st */
            	4150, 0,
            0, 0, 0, /* 4150: struct.bn_blinding_st */
            1, 8, 1, /* 4153: pointer.struct.dsa_st */
            	4158, 0,
            0, 136, 11, /* 4158: struct.dsa_st */
            	4099, 24,
            	4099, 32,
            	4099, 40,
            	4099, 48,
            	4099, 56,
            	4099, 64,
            	4099, 72,
            	4131, 88,
            	4109, 104,
            	4183, 120,
            	3981, 128,
            1, 8, 1, /* 4183: pointer.struct.dsa_method */
            	4188, 0,
            0, 96, 11, /* 4188: struct.dsa_method */
            	124, 0,
            	4213, 8,
            	4216, 16,
            	4219, 24,
            	3793, 32,
            	4222, 40,
            	4225, 48,
            	4225, 56,
            	93, 72,
            	4228, 80,
            	4225, 88,
            8884097, 8, 0, /* 4213: pointer.func */
            8884097, 8, 0, /* 4216: pointer.func */
            8884097, 8, 0, /* 4219: pointer.func */
            8884097, 8, 0, /* 4222: pointer.func */
            8884097, 8, 0, /* 4225: pointer.func */
            8884097, 8, 0, /* 4228: pointer.func */
            1, 8, 1, /* 4231: pointer.struct.dh_st */
            	4236, 0,
            0, 144, 12, /* 4236: struct.dh_st */
            	4099, 8,
            	4099, 16,
            	4099, 32,
            	4099, 40,
            	4131, 56,
            	4099, 64,
            	4099, 72,
            	200, 80,
            	4099, 96,
            	4109, 112,
            	4263, 128,
            	3981, 136,
            1, 8, 1, /* 4263: pointer.struct.dh_method */
            	4268, 0,
            0, 72, 8, /* 4268: struct.dh_method */
            	124, 0,
            	4287, 8,
            	4290, 16,
            	4293, 24,
            	4287, 32,
            	4287, 40,
            	93, 56,
            	4296, 64,
            8884097, 8, 0, /* 4287: pointer.func */
            8884097, 8, 0, /* 4290: pointer.func */
            8884097, 8, 0, /* 4293: pointer.func */
            8884097, 8, 0, /* 4296: pointer.func */
            1, 8, 1, /* 4299: pointer.struct.ec_key_st */
            	4304, 0,
            0, 0, 0, /* 4304: struct.ec_key_st */
            1, 8, 1, /* 4307: pointer.struct.stack_st_X509_ATTRIBUTE */
            	4312, 0,
            0, 32, 2, /* 4312: struct.stack_st_fake_X509_ATTRIBUTE */
            	4319, 8,
            	360, 24,
            8884099, 8, 2, /* 4319: pointer_to_array_of_pointers_to_stack */
            	4326, 0,
            	357, 20,
            0, 8, 1, /* 4326: pointer.X509_ATTRIBUTE */
            	1878, 0,
            0, 184, 12, /* 4331: struct.x509_st */
            	4358, 0,
            	3813, 8,
            	3907, 16,
            	93, 32,
            	4109, 40,
            	3912, 104,
            	4482, 112,
            	4490, 120,
            	4495, 128,
            	4519, 136,
            	4543, 144,
            	4551, 176,
            1, 8, 1, /* 4358: pointer.struct.x509_cinf_st */
            	4363, 0,
            0, 104, 11, /* 4363: struct.x509_cinf_st */
            	3897, 0,
            	3897, 8,
            	3813, 16,
            	4388, 24,
            	4436, 32,
            	4388, 40,
            	3799, 48,
            	3907, 56,
            	3907, 64,
            	4453, 72,
            	4477, 80,
            1, 8, 1, /* 4388: pointer.struct.X509_name_st */
            	4393, 0,
            0, 40, 3, /* 4393: struct.X509_name_st */
            	4402, 0,
            	4426, 16,
            	200, 24,
            1, 8, 1, /* 4402: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4407, 0,
            0, 32, 2, /* 4407: struct.stack_st_fake_X509_NAME_ENTRY */
            	4414, 8,
            	360, 24,
            8884099, 8, 2, /* 4414: pointer_to_array_of_pointers_to_stack */
            	4421, 0,
            	357, 20,
            0, 8, 1, /* 4421: pointer.X509_NAME_ENTRY */
            	321, 0,
            1, 8, 1, /* 4426: pointer.struct.buf_mem_st */
            	4431, 0,
            0, 24, 1, /* 4431: struct.buf_mem_st */
            	93, 8,
            1, 8, 1, /* 4436: pointer.struct.X509_val_st */
            	4441, 0,
            0, 16, 2, /* 4441: struct.X509_val_st */
            	4448, 0,
            	4448, 8,
            1, 8, 1, /* 4448: pointer.struct.asn1_string_st */
            	3780, 0,
            1, 8, 1, /* 4453: pointer.struct.stack_st_X509_EXTENSION */
            	4458, 0,
            0, 32, 2, /* 4458: struct.stack_st_fake_X509_EXTENSION */
            	4465, 8,
            	360, 24,
            8884099, 8, 2, /* 4465: pointer_to_array_of_pointers_to_stack */
            	4472, 0,
            	357, 20,
            0, 8, 1, /* 4472: pointer.X509_EXTENSION */
            	703, 0,
            0, 24, 1, /* 4477: struct.ASN1_ENCODING_st */
            	200, 0,
            1, 8, 1, /* 4482: pointer.struct.AUTHORITY_KEYID_st */
            	4487, 0,
            0, 0, 0, /* 4487: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 4490: pointer.struct.X509_POLICY_CACHE_st */
            	3796, 0,
            1, 8, 1, /* 4495: pointer.struct.stack_st_DIST_POINT */
            	4500, 0,
            0, 32, 2, /* 4500: struct.stack_st_fake_DIST_POINT */
            	4507, 8,
            	360, 24,
            8884099, 8, 2, /* 4507: pointer_to_array_of_pointers_to_stack */
            	4514, 0,
            	357, 20,
            0, 8, 1, /* 4514: pointer.DIST_POINT */
            	2254, 0,
            1, 8, 1, /* 4519: pointer.struct.stack_st_GENERAL_NAME */
            	4524, 0,
            0, 32, 2, /* 4524: struct.stack_st_fake_GENERAL_NAME */
            	4531, 8,
            	360, 24,
            8884099, 8, 2, /* 4531: pointer_to_array_of_pointers_to_stack */
            	4538, 0,
            	357, 20,
            0, 8, 1, /* 4538: pointer.GENERAL_NAME */
            	50, 0,
            1, 8, 1, /* 4543: pointer.struct.NAME_CONSTRAINTS_st */
            	4548, 0,
            0, 0, 0, /* 4548: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 4551: pointer.struct.x509_cert_aux_st */
            	4556, 0,
            0, 40, 5, /* 4556: struct.x509_cert_aux_st */
            	4569, 0,
            	4569, 8,
            	3775, 16,
            	3912, 24,
            	4593, 32,
            1, 8, 1, /* 4569: pointer.struct.stack_st_ASN1_OBJECT */
            	4574, 0,
            0, 32, 2, /* 4574: struct.stack_st_fake_ASN1_OBJECT */
            	4581, 8,
            	360, 24,
            8884099, 8, 2, /* 4581: pointer_to_array_of_pointers_to_stack */
            	4588, 0,
            	357, 20,
            0, 8, 1, /* 4588: pointer.ASN1_OBJECT */
            	2646, 0,
            1, 8, 1, /* 4593: pointer.struct.stack_st_X509_ALGOR */
            	4598, 0,
            0, 32, 2, /* 4598: struct.stack_st_fake_X509_ALGOR */
            	4605, 8,
            	360, 24,
            8884099, 8, 2, /* 4605: pointer_to_array_of_pointers_to_stack */
            	4612, 0,
            	357, 20,
            0, 8, 1, /* 4612: pointer.X509_ALGOR */
            	2684, 0,
            0, 144, 15, /* 4617: struct.x509_store_st */
            	4650, 8,
            	4674, 16,
            	4698, 24,
            	4710, 32,
            	4713, 40,
            	4716, 48,
            	4719, 56,
            	4710, 64,
            	3785, 72,
            	4722, 80,
            	4725, 88,
            	1265, 96,
            	4728, 104,
            	4710, 112,
            	1653, 120,
            1, 8, 1, /* 4650: pointer.struct.stack_st_X509_OBJECT */
            	4655, 0,
            0, 32, 2, /* 4655: struct.stack_st_fake_X509_OBJECT */
            	4662, 8,
            	360, 24,
            8884099, 8, 2, /* 4662: pointer_to_array_of_pointers_to_stack */
            	4669, 0,
            	357, 20,
            0, 8, 1, /* 4669: pointer.X509_OBJECT */
            	2850, 0,
            1, 8, 1, /* 4674: pointer.struct.stack_st_X509_LOOKUP */
            	4679, 0,
            0, 32, 2, /* 4679: struct.stack_st_fake_X509_LOOKUP */
            	4686, 8,
            	360, 24,
            8884099, 8, 2, /* 4686: pointer_to_array_of_pointers_to_stack */
            	4693, 0,
            	357, 20,
            0, 8, 1, /* 4693: pointer.X509_LOOKUP */
            	3734, 0,
            1, 8, 1, /* 4698: pointer.struct.X509_VERIFY_PARAM_st */
            	4703, 0,
            0, 56, 2, /* 4703: struct.X509_VERIFY_PARAM_st */
            	93, 0,
            	2622, 48,
            8884097, 8, 0, /* 4710: pointer.func */
            8884097, 8, 0, /* 4713: pointer.func */
            8884097, 8, 0, /* 4716: pointer.func */
            8884097, 8, 0, /* 4719: pointer.func */
            8884097, 8, 0, /* 4722: pointer.func */
            8884097, 8, 0, /* 4725: pointer.func */
            8884097, 8, 0, /* 4728: pointer.func */
            1, 8, 1, /* 4731: pointer.struct.x509_store_ctx_st */
            	4736, 0,
            0, 248, 25, /* 4736: struct.x509_store_ctx_st */
            	4789, 0,
            	1405, 16,
            	4794, 24,
            	4823, 32,
            	4698, 40,
            	898, 48,
            	4710, 56,
            	4713, 64,
            	4716, 72,
            	4719, 80,
            	4710, 88,
            	3785, 96,
            	4722, 104,
            	4725, 112,
            	4710, 120,
            	1265, 128,
            	4728, 136,
            	4710, 144,
            	4794, 160,
            	904, 168,
            	1405, 192,
            	1405, 200,
            	792, 208,
            	4731, 224,
            	1653, 232,
            1, 8, 1, /* 4789: pointer.struct.x509_store_st */
            	4617, 0,
            1, 8, 1, /* 4794: pointer.struct.stack_st_X509 */
            	4799, 0,
            0, 32, 2, /* 4799: struct.stack_st_fake_X509 */
            	4806, 8,
            	360, 24,
            8884099, 8, 2, /* 4806: pointer_to_array_of_pointers_to_stack */
            	4813, 0,
            	357, 20,
            0, 8, 1, /* 4813: pointer.X509 */
            	4818, 0,
            0, 0, 1, /* 4818: X509 */
            	4331, 0,
            1, 8, 1, /* 4823: pointer.struct.stack_st_X509_CRL */
            	4828, 0,
            0, 32, 2, /* 4828: struct.stack_st_fake_X509_CRL */
            	4835, 8,
            	360, 24,
            8884099, 8, 2, /* 4835: pointer_to_array_of_pointers_to_stack */
            	4842, 0,
            	357, 20,
            0, 8, 1, /* 4842: pointer.X509_CRL */
            	1198, 0,
            0, 1, 0, /* 4847: char */
        },
        .arg_entity_index = { 4731, },
        .ret_entity_index = 357,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    X509_STORE_CTX * new_arg_a = *((X509_STORE_CTX * *)new_args->args[0]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_X509_verify_cert)(X509_STORE_CTX *);
    orig_X509_verify_cert = dlsym(RTLD_NEXT, "X509_verify_cert");
    *new_ret_ptr = (*orig_X509_verify_cert)(new_arg_a);

    syscall(889);

    return ret;
}

