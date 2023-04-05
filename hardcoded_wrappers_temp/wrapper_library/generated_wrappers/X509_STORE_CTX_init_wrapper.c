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
            1, 8, 1, /* 1242: pointer.struct.rsa_st */
            	1247, 0,
            0, 168, 17, /* 1247: struct.rsa_st */
            	1284, 16,
            	1339, 24,
            	1347, 32,
            	1347, 40,
            	1347, 48,
            	1347, 56,
            	1347, 64,
            	1347, 72,
            	1347, 80,
            	1347, 88,
            	1365, 96,
            	1387, 120,
            	1387, 128,
            	1387, 136,
            	93, 144,
            	1401, 152,
            	1401, 160,
            1, 8, 1, /* 1284: pointer.struct.rsa_meth_st */
            	1289, 0,
            0, 112, 13, /* 1289: struct.rsa_meth_st */
            	124, 0,
            	1318, 8,
            	1318, 16,
            	1318, 24,
            	1318, 32,
            	1321, 40,
            	1324, 48,
            	1327, 56,
            	1327, 64,
            	93, 80,
            	1330, 88,
            	1333, 96,
            	1336, 104,
            8884097, 8, 0, /* 1318: pointer.func */
            8884097, 8, 0, /* 1321: pointer.func */
            8884097, 8, 0, /* 1324: pointer.func */
            8884097, 8, 0, /* 1327: pointer.func */
            8884097, 8, 0, /* 1330: pointer.func */
            8884097, 8, 0, /* 1333: pointer.func */
            8884097, 8, 0, /* 1336: pointer.func */
            1, 8, 1, /* 1339: pointer.struct.engine_st */
            	1344, 0,
            0, 0, 0, /* 1344: struct.engine_st */
            1, 8, 1, /* 1347: pointer.struct.bignum_st */
            	1352, 0,
            0, 24, 1, /* 1352: struct.bignum_st */
            	1357, 0,
            1, 8, 1, /* 1357: pointer.unsigned int */
            	1362, 0,
            0, 4, 0, /* 1362: unsigned int */
            0, 16, 1, /* 1365: struct.crypto_ex_data_st */
            	1370, 0,
            1, 8, 1, /* 1370: pointer.struct.stack_st_void */
            	1375, 0,
            0, 32, 1, /* 1375: struct.stack_st_void */
            	1380, 0,
            0, 32, 2, /* 1380: struct.stack_st */
            	885, 8,
            	360, 24,
            1, 8, 1, /* 1387: pointer.struct.bn_mont_ctx_st */
            	1392, 0,
            0, 96, 3, /* 1392: struct.bn_mont_ctx_st */
            	1352, 8,
            	1352, 32,
            	1352, 56,
            1, 8, 1, /* 1401: pointer.struct.bn_blinding_st */
            	1406, 0,
            0, 0, 0, /* 1406: struct.bn_blinding_st */
            1, 8, 1, /* 1409: pointer.struct.x509_cinf_st */
            	1414, 0,
            0, 104, 11, /* 1414: struct.x509_cinf_st */
            	462, 0,
            	462, 8,
            	467, 16,
            	409, 24,
            	1439, 32,
            	409, 40,
            	1451, 48,
            	433, 56,
            	433, 64,
            	763, 72,
            	787, 80,
            1, 8, 1, /* 1439: pointer.struct.X509_val_st */
            	1444, 0,
            0, 16, 2, /* 1444: struct.X509_val_st */
            	619, 0,
            	619, 8,
            1, 8, 1, /* 1451: pointer.struct.X509_pubkey_st */
            	1456, 0,
            0, 24, 3, /* 1456: struct.X509_pubkey_st */
            	467, 0,
            	433, 8,
            	1465, 16,
            1, 8, 1, /* 1465: pointer.struct.evp_pkey_st */
            	1470, 0,
            0, 56, 4, /* 1470: struct.evp_pkey_st */
            	1481, 16,
            	1339, 24,
            	1489, 32,
            	1659, 48,
            1, 8, 1, /* 1481: pointer.struct.evp_pkey_asn1_method_st */
            	1486, 0,
            0, 0, 0, /* 1486: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 1489: union.unknown */
            	93, 0,
            	1242, 0,
            	1502, 0,
            	1583, 0,
            	1651, 0,
            1, 8, 1, /* 1502: pointer.struct.dsa_st */
            	1507, 0,
            0, 136, 11, /* 1507: struct.dsa_st */
            	1347, 24,
            	1347, 32,
            	1347, 40,
            	1347, 48,
            	1347, 56,
            	1347, 64,
            	1347, 72,
            	1387, 88,
            	1365, 104,
            	1532, 120,
            	1339, 128,
            1, 8, 1, /* 1532: pointer.struct.dsa_method */
            	1537, 0,
            0, 96, 11, /* 1537: struct.dsa_method */
            	124, 0,
            	1562, 8,
            	1565, 16,
            	1568, 24,
            	1571, 32,
            	1574, 40,
            	1577, 48,
            	1577, 56,
            	93, 72,
            	1580, 80,
            	1577, 88,
            8884097, 8, 0, /* 1562: pointer.func */
            8884097, 8, 0, /* 1565: pointer.func */
            8884097, 8, 0, /* 1568: pointer.func */
            8884097, 8, 0, /* 1571: pointer.func */
            8884097, 8, 0, /* 1574: pointer.func */
            8884097, 8, 0, /* 1577: pointer.func */
            8884097, 8, 0, /* 1580: pointer.func */
            1, 8, 1, /* 1583: pointer.struct.dh_st */
            	1588, 0,
            0, 144, 12, /* 1588: struct.dh_st */
            	1347, 8,
            	1347, 16,
            	1347, 32,
            	1347, 40,
            	1387, 56,
            	1347, 64,
            	1347, 72,
            	200, 80,
            	1347, 96,
            	1365, 112,
            	1615, 128,
            	1339, 136,
            1, 8, 1, /* 1615: pointer.struct.dh_method */
            	1620, 0,
            0, 72, 8, /* 1620: struct.dh_method */
            	124, 0,
            	1639, 8,
            	1642, 16,
            	1645, 24,
            	1639, 32,
            	1639, 40,
            	93, 56,
            	1648, 64,
            8884097, 8, 0, /* 1639: pointer.func */
            8884097, 8, 0, /* 1642: pointer.func */
            8884097, 8, 0, /* 1645: pointer.func */
            8884097, 8, 0, /* 1648: pointer.func */
            1, 8, 1, /* 1651: pointer.struct.ec_key_st */
            	1656, 0,
            0, 0, 0, /* 1656: struct.ec_key_st */
            1, 8, 1, /* 1659: pointer.struct.stack_st_X509_ATTRIBUTE */
            	1664, 0,
            0, 32, 2, /* 1664: struct.stack_st_fake_X509_ATTRIBUTE */
            	1671, 8,
            	360, 24,
            8884099, 8, 2, /* 1671: pointer_to_array_of_pointers_to_stack */
            	1678, 0,
            	357, 20,
            0, 8, 1, /* 1678: pointer.X509_ATTRIBUTE */
            	1683, 0,
            0, 0, 1, /* 1683: X509_ATTRIBUTE */
            	1688, 0,
            0, 24, 2, /* 1688: struct.x509_attributes_st */
            	1695, 0,
            	1709, 16,
            1, 8, 1, /* 1695: pointer.struct.asn1_object_st */
            	1700, 0,
            0, 40, 3, /* 1700: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            0, 8, 3, /* 1709: union.unknown */
            	93, 0,
            	1718, 0,
            	1897, 0,
            1, 8, 1, /* 1718: pointer.struct.stack_st_ASN1_TYPE */
            	1723, 0,
            0, 32, 2, /* 1723: struct.stack_st_fake_ASN1_TYPE */
            	1730, 8,
            	360, 24,
            8884099, 8, 2, /* 1730: pointer_to_array_of_pointers_to_stack */
            	1737, 0,
            	357, 20,
            0, 8, 1, /* 1737: pointer.ASN1_TYPE */
            	1742, 0,
            0, 0, 1, /* 1742: ASN1_TYPE */
            	1747, 0,
            0, 16, 1, /* 1747: struct.asn1_type_st */
            	1752, 8,
            0, 8, 20, /* 1752: union.unknown */
            	93, 0,
            	1795, 0,
            	1805, 0,
            	1819, 0,
            	1824, 0,
            	1829, 0,
            	1834, 0,
            	1839, 0,
            	1844, 0,
            	1849, 0,
            	1854, 0,
            	1859, 0,
            	1864, 0,
            	1869, 0,
            	1874, 0,
            	1879, 0,
            	1884, 0,
            	1795, 0,
            	1795, 0,
            	1889, 0,
            1, 8, 1, /* 1795: pointer.struct.asn1_string_st */
            	1800, 0,
            0, 24, 1, /* 1800: struct.asn1_string_st */
            	200, 8,
            1, 8, 1, /* 1805: pointer.struct.asn1_object_st */
            	1810, 0,
            0, 40, 3, /* 1810: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            1, 8, 1, /* 1819: pointer.struct.asn1_string_st */
            	1800, 0,
            1, 8, 1, /* 1824: pointer.struct.asn1_string_st */
            	1800, 0,
            1, 8, 1, /* 1829: pointer.struct.asn1_string_st */
            	1800, 0,
            1, 8, 1, /* 1834: pointer.struct.asn1_string_st */
            	1800, 0,
            1, 8, 1, /* 1839: pointer.struct.asn1_string_st */
            	1800, 0,
            1, 8, 1, /* 1844: pointer.struct.asn1_string_st */
            	1800, 0,
            1, 8, 1, /* 1849: pointer.struct.asn1_string_st */
            	1800, 0,
            1, 8, 1, /* 1854: pointer.struct.asn1_string_st */
            	1800, 0,
            1, 8, 1, /* 1859: pointer.struct.asn1_string_st */
            	1800, 0,
            1, 8, 1, /* 1864: pointer.struct.asn1_string_st */
            	1800, 0,
            1, 8, 1, /* 1869: pointer.struct.asn1_string_st */
            	1800, 0,
            1, 8, 1, /* 1874: pointer.struct.asn1_string_st */
            	1800, 0,
            1, 8, 1, /* 1879: pointer.struct.asn1_string_st */
            	1800, 0,
            1, 8, 1, /* 1884: pointer.struct.asn1_string_st */
            	1800, 0,
            1, 8, 1, /* 1889: pointer.struct.ASN1_VALUE_st */
            	1894, 0,
            0, 0, 0, /* 1894: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1897: pointer.struct.asn1_type_st */
            	1902, 0,
            0, 16, 1, /* 1902: struct.asn1_type_st */
            	1907, 8,
            0, 8, 20, /* 1907: union.unknown */
            	93, 0,
            	1950, 0,
            	1695, 0,
            	1960, 0,
            	1965, 0,
            	1970, 0,
            	1975, 0,
            	1980, 0,
            	1985, 0,
            	1990, 0,
            	1995, 0,
            	2000, 0,
            	2005, 0,
            	2010, 0,
            	2015, 0,
            	2020, 0,
            	2025, 0,
            	1950, 0,
            	1950, 0,
            	611, 0,
            1, 8, 1, /* 1950: pointer.struct.asn1_string_st */
            	1955, 0,
            0, 24, 1, /* 1955: struct.asn1_string_st */
            	200, 8,
            1, 8, 1, /* 1960: pointer.struct.asn1_string_st */
            	1955, 0,
            1, 8, 1, /* 1965: pointer.struct.asn1_string_st */
            	1955, 0,
            1, 8, 1, /* 1970: pointer.struct.asn1_string_st */
            	1955, 0,
            1, 8, 1, /* 1975: pointer.struct.asn1_string_st */
            	1955, 0,
            1, 8, 1, /* 1980: pointer.struct.asn1_string_st */
            	1955, 0,
            1, 8, 1, /* 1985: pointer.struct.asn1_string_st */
            	1955, 0,
            1, 8, 1, /* 1990: pointer.struct.asn1_string_st */
            	1955, 0,
            1, 8, 1, /* 1995: pointer.struct.asn1_string_st */
            	1955, 0,
            1, 8, 1, /* 2000: pointer.struct.asn1_string_st */
            	1955, 0,
            1, 8, 1, /* 2005: pointer.struct.asn1_string_st */
            	1955, 0,
            1, 8, 1, /* 2010: pointer.struct.asn1_string_st */
            	1955, 0,
            1, 8, 1, /* 2015: pointer.struct.asn1_string_st */
            	1955, 0,
            1, 8, 1, /* 2020: pointer.struct.asn1_string_st */
            	1955, 0,
            1, 8, 1, /* 2025: pointer.struct.asn1_string_st */
            	1955, 0,
            1, 8, 1, /* 2030: pointer.struct.asn1_string_st */
            	2035, 0,
            0, 24, 1, /* 2035: struct.asn1_string_st */
            	200, 8,
            0, 56, 4, /* 2040: struct.evp_pkey_st */
            	2051, 16,
            	2059, 24,
            	2067, 32,
            	2388, 48,
            1, 8, 1, /* 2051: pointer.struct.evp_pkey_asn1_method_st */
            	2056, 0,
            0, 0, 0, /* 2056: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 2059: pointer.struct.engine_st */
            	2064, 0,
            0, 0, 0, /* 2064: struct.engine_st */
            0, 8, 5, /* 2067: union.unknown */
            	93, 0,
            	2080, 0,
            	2231, 0,
            	2312, 0,
            	2380, 0,
            1, 8, 1, /* 2080: pointer.struct.rsa_st */
            	2085, 0,
            0, 168, 17, /* 2085: struct.rsa_st */
            	2122, 16,
            	2059, 24,
            	2177, 32,
            	2177, 40,
            	2177, 48,
            	2177, 56,
            	2177, 64,
            	2177, 72,
            	2177, 80,
            	2177, 88,
            	2187, 96,
            	2209, 120,
            	2209, 128,
            	2209, 136,
            	93, 144,
            	2223, 152,
            	2223, 160,
            1, 8, 1, /* 2122: pointer.struct.rsa_meth_st */
            	2127, 0,
            0, 112, 13, /* 2127: struct.rsa_meth_st */
            	124, 0,
            	2156, 8,
            	2156, 16,
            	2156, 24,
            	2156, 32,
            	2159, 40,
            	2162, 48,
            	2165, 56,
            	2165, 64,
            	93, 80,
            	2168, 88,
            	2171, 96,
            	2174, 104,
            8884097, 8, 0, /* 2156: pointer.func */
            8884097, 8, 0, /* 2159: pointer.func */
            8884097, 8, 0, /* 2162: pointer.func */
            8884097, 8, 0, /* 2165: pointer.func */
            8884097, 8, 0, /* 2168: pointer.func */
            8884097, 8, 0, /* 2171: pointer.func */
            8884097, 8, 0, /* 2174: pointer.func */
            1, 8, 1, /* 2177: pointer.struct.bignum_st */
            	2182, 0,
            0, 24, 1, /* 2182: struct.bignum_st */
            	1357, 0,
            0, 16, 1, /* 2187: struct.crypto_ex_data_st */
            	2192, 0,
            1, 8, 1, /* 2192: pointer.struct.stack_st_void */
            	2197, 0,
            0, 32, 1, /* 2197: struct.stack_st_void */
            	2202, 0,
            0, 32, 2, /* 2202: struct.stack_st */
            	885, 8,
            	360, 24,
            1, 8, 1, /* 2209: pointer.struct.bn_mont_ctx_st */
            	2214, 0,
            0, 96, 3, /* 2214: struct.bn_mont_ctx_st */
            	2182, 8,
            	2182, 32,
            	2182, 56,
            1, 8, 1, /* 2223: pointer.struct.bn_blinding_st */
            	2228, 0,
            0, 0, 0, /* 2228: struct.bn_blinding_st */
            1, 8, 1, /* 2231: pointer.struct.dsa_st */
            	2236, 0,
            0, 136, 11, /* 2236: struct.dsa_st */
            	2177, 24,
            	2177, 32,
            	2177, 40,
            	2177, 48,
            	2177, 56,
            	2177, 64,
            	2177, 72,
            	2209, 88,
            	2187, 104,
            	2261, 120,
            	2059, 128,
            1, 8, 1, /* 2261: pointer.struct.dsa_method */
            	2266, 0,
            0, 96, 11, /* 2266: struct.dsa_method */
            	124, 0,
            	2291, 8,
            	2294, 16,
            	2297, 24,
            	2300, 32,
            	2303, 40,
            	2306, 48,
            	2306, 56,
            	93, 72,
            	2309, 80,
            	2306, 88,
            8884097, 8, 0, /* 2291: pointer.func */
            8884097, 8, 0, /* 2294: pointer.func */
            8884097, 8, 0, /* 2297: pointer.func */
            8884097, 8, 0, /* 2300: pointer.func */
            8884097, 8, 0, /* 2303: pointer.func */
            8884097, 8, 0, /* 2306: pointer.func */
            8884097, 8, 0, /* 2309: pointer.func */
            1, 8, 1, /* 2312: pointer.struct.dh_st */
            	2317, 0,
            0, 144, 12, /* 2317: struct.dh_st */
            	2177, 8,
            	2177, 16,
            	2177, 32,
            	2177, 40,
            	2209, 56,
            	2177, 64,
            	2177, 72,
            	200, 80,
            	2177, 96,
            	2187, 112,
            	2344, 128,
            	2059, 136,
            1, 8, 1, /* 2344: pointer.struct.dh_method */
            	2349, 0,
            0, 72, 8, /* 2349: struct.dh_method */
            	124, 0,
            	2368, 8,
            	2371, 16,
            	2374, 24,
            	2368, 32,
            	2368, 40,
            	93, 56,
            	2377, 64,
            8884097, 8, 0, /* 2368: pointer.func */
            8884097, 8, 0, /* 2371: pointer.func */
            8884097, 8, 0, /* 2374: pointer.func */
            8884097, 8, 0, /* 2377: pointer.func */
            1, 8, 1, /* 2380: pointer.struct.ec_key_st */
            	2385, 0,
            0, 0, 0, /* 2385: struct.ec_key_st */
            1, 8, 1, /* 2388: pointer.struct.stack_st_X509_ATTRIBUTE */
            	2393, 0,
            0, 32, 2, /* 2393: struct.stack_st_fake_X509_ATTRIBUTE */
            	2400, 8,
            	360, 24,
            8884099, 8, 2, /* 2400: pointer_to_array_of_pointers_to_stack */
            	2407, 0,
            	357, 20,
            0, 8, 1, /* 2407: pointer.X509_ATTRIBUTE */
            	1683, 0,
            1, 8, 1, /* 2412: pointer.struct.asn1_string_st */
            	2035, 0,
            1, 8, 1, /* 2417: pointer.struct.asn1_string_st */
            	2035, 0,
            1, 8, 1, /* 2422: pointer.struct.asn1_string_st */
            	2035, 0,
            1, 8, 1, /* 2427: pointer.struct.asn1_string_st */
            	2035, 0,
            1, 8, 1, /* 2432: pointer.struct.asn1_string_st */
            	2035, 0,
            1, 8, 1, /* 2437: pointer.struct.asn1_string_st */
            	2035, 0,
            0, 16, 1, /* 2442: struct.asn1_type_st */
            	2447, 8,
            0, 8, 20, /* 2447: union.unknown */
            	93, 0,
            	2490, 0,
            	2495, 0,
            	2509, 0,
            	2514, 0,
            	2519, 0,
            	2524, 0,
            	2437, 0,
            	2432, 0,
            	2529, 0,
            	2427, 0,
            	2422, 0,
            	2534, 0,
            	2417, 0,
            	2412, 0,
            	2539, 0,
            	2030, 0,
            	2490, 0,
            	2490, 0,
            	611, 0,
            1, 8, 1, /* 2490: pointer.struct.asn1_string_st */
            	2035, 0,
            1, 8, 1, /* 2495: pointer.struct.asn1_object_st */
            	2500, 0,
            0, 40, 3, /* 2500: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            1, 8, 1, /* 2509: pointer.struct.asn1_string_st */
            	2035, 0,
            1, 8, 1, /* 2514: pointer.struct.asn1_string_st */
            	2035, 0,
            1, 8, 1, /* 2519: pointer.struct.asn1_string_st */
            	2035, 0,
            1, 8, 1, /* 2524: pointer.struct.asn1_string_st */
            	2035, 0,
            1, 8, 1, /* 2529: pointer.struct.asn1_string_st */
            	2035, 0,
            1, 8, 1, /* 2534: pointer.struct.asn1_string_st */
            	2035, 0,
            1, 8, 1, /* 2539: pointer.struct.asn1_string_st */
            	2035, 0,
            0, 16, 2, /* 2544: struct.X509_algor_st */
            	2495, 0,
            	2551, 8,
            1, 8, 1, /* 2551: pointer.struct.asn1_type_st */
            	2442, 0,
            1, 8, 1, /* 2556: pointer.struct.x509_st */
            	2561, 0,
            0, 184, 12, /* 2561: struct.x509_st */
            	1409, 0,
            	467, 8,
            	433, 16,
            	93, 32,
            	1365, 40,
            	556, 104,
            	825, 112,
            	2588, 120,
            	2596, 128,
            	2634, 136,
            	2658, 144,
            	2970, 176,
            1, 8, 1, /* 2588: pointer.struct.X509_POLICY_CACHE_st */
            	2593, 0,
            0, 0, 0, /* 2593: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 2596: pointer.struct.stack_st_DIST_POINT */
            	2601, 0,
            0, 32, 2, /* 2601: struct.stack_st_fake_DIST_POINT */
            	2608, 8,
            	360, 24,
            8884099, 8, 2, /* 2608: pointer_to_array_of_pointers_to_stack */
            	2615, 0,
            	357, 20,
            0, 8, 1, /* 2615: pointer.DIST_POINT */
            	2620, 0,
            0, 0, 1, /* 2620: DIST_POINT */
            	2625, 0,
            0, 32, 3, /* 2625: struct.DIST_POINT_st */
            	7, 0,
            	433, 8,
            	26, 16,
            1, 8, 1, /* 2634: pointer.struct.stack_st_GENERAL_NAME */
            	2639, 0,
            0, 32, 2, /* 2639: struct.stack_st_fake_GENERAL_NAME */
            	2646, 8,
            	360, 24,
            8884099, 8, 2, /* 2646: pointer_to_array_of_pointers_to_stack */
            	2653, 0,
            	357, 20,
            0, 8, 1, /* 2653: pointer.GENERAL_NAME */
            	50, 0,
            1, 8, 1, /* 2658: pointer.struct.NAME_CONSTRAINTS_st */
            	2663, 0,
            0, 16, 2, /* 2663: struct.NAME_CONSTRAINTS_st */
            	2670, 0,
            	2670, 8,
            1, 8, 1, /* 2670: pointer.struct.stack_st_GENERAL_SUBTREE */
            	2675, 0,
            0, 32, 2, /* 2675: struct.stack_st_fake_GENERAL_SUBTREE */
            	2682, 8,
            	360, 24,
            8884099, 8, 2, /* 2682: pointer_to_array_of_pointers_to_stack */
            	2689, 0,
            	357, 20,
            0, 8, 1, /* 2689: pointer.GENERAL_SUBTREE */
            	2694, 0,
            0, 0, 1, /* 2694: GENERAL_SUBTREE */
            	2699, 0,
            0, 24, 3, /* 2699: struct.GENERAL_SUBTREE_st */
            	2708, 0,
            	2840, 8,
            	2840, 16,
            1, 8, 1, /* 2708: pointer.struct.GENERAL_NAME_st */
            	2713, 0,
            0, 16, 1, /* 2713: struct.GENERAL_NAME_st */
            	2718, 8,
            0, 8, 15, /* 2718: union.unknown */
            	93, 0,
            	2751, 0,
            	2870, 0,
            	2870, 0,
            	2777, 0,
            	2910, 0,
            	2958, 0,
            	2870, 0,
            	2855, 0,
            	2763, 0,
            	2855, 0,
            	2910, 0,
            	2870, 0,
            	2763, 0,
            	2777, 0,
            1, 8, 1, /* 2751: pointer.struct.otherName_st */
            	2756, 0,
            0, 16, 2, /* 2756: struct.otherName_st */
            	2763, 0,
            	2777, 8,
            1, 8, 1, /* 2763: pointer.struct.asn1_object_st */
            	2768, 0,
            0, 40, 3, /* 2768: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            1, 8, 1, /* 2777: pointer.struct.asn1_type_st */
            	2782, 0,
            0, 16, 1, /* 2782: struct.asn1_type_st */
            	2787, 8,
            0, 8, 20, /* 2787: union.unknown */
            	93, 0,
            	2830, 0,
            	2763, 0,
            	2840, 0,
            	2845, 0,
            	2850, 0,
            	2855, 0,
            	2860, 0,
            	2865, 0,
            	2870, 0,
            	2875, 0,
            	2880, 0,
            	2885, 0,
            	2890, 0,
            	2895, 0,
            	2900, 0,
            	2905, 0,
            	2830, 0,
            	2830, 0,
            	275, 0,
            1, 8, 1, /* 2830: pointer.struct.asn1_string_st */
            	2835, 0,
            0, 24, 1, /* 2835: struct.asn1_string_st */
            	200, 8,
            1, 8, 1, /* 2840: pointer.struct.asn1_string_st */
            	2835, 0,
            1, 8, 1, /* 2845: pointer.struct.asn1_string_st */
            	2835, 0,
            1, 8, 1, /* 2850: pointer.struct.asn1_string_st */
            	2835, 0,
            1, 8, 1, /* 2855: pointer.struct.asn1_string_st */
            	2835, 0,
            1, 8, 1, /* 2860: pointer.struct.asn1_string_st */
            	2835, 0,
            1, 8, 1, /* 2865: pointer.struct.asn1_string_st */
            	2835, 0,
            1, 8, 1, /* 2870: pointer.struct.asn1_string_st */
            	2835, 0,
            1, 8, 1, /* 2875: pointer.struct.asn1_string_st */
            	2835, 0,
            1, 8, 1, /* 2880: pointer.struct.asn1_string_st */
            	2835, 0,
            1, 8, 1, /* 2885: pointer.struct.asn1_string_st */
            	2835, 0,
            1, 8, 1, /* 2890: pointer.struct.asn1_string_st */
            	2835, 0,
            1, 8, 1, /* 2895: pointer.struct.asn1_string_st */
            	2835, 0,
            1, 8, 1, /* 2900: pointer.struct.asn1_string_st */
            	2835, 0,
            1, 8, 1, /* 2905: pointer.struct.asn1_string_st */
            	2835, 0,
            1, 8, 1, /* 2910: pointer.struct.X509_name_st */
            	2915, 0,
            0, 40, 3, /* 2915: struct.X509_name_st */
            	2924, 0,
            	2948, 16,
            	200, 24,
            1, 8, 1, /* 2924: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2929, 0,
            0, 32, 2, /* 2929: struct.stack_st_fake_X509_NAME_ENTRY */
            	2936, 8,
            	360, 24,
            8884099, 8, 2, /* 2936: pointer_to_array_of_pointers_to_stack */
            	2943, 0,
            	357, 20,
            0, 8, 1, /* 2943: pointer.X509_NAME_ENTRY */
            	321, 0,
            1, 8, 1, /* 2948: pointer.struct.buf_mem_st */
            	2953, 0,
            0, 24, 1, /* 2953: struct.buf_mem_st */
            	93, 8,
            1, 8, 1, /* 2958: pointer.struct.EDIPartyName_st */
            	2963, 0,
            0, 16, 2, /* 2963: struct.EDIPartyName_st */
            	2830, 0,
            	2830, 8,
            1, 8, 1, /* 2970: pointer.struct.x509_cert_aux_st */
            	2975, 0,
            0, 40, 5, /* 2975: struct.x509_cert_aux_st */
            	2988, 0,
            	2988, 8,
            	606, 16,
            	556, 24,
            	3026, 32,
            1, 8, 1, /* 2988: pointer.struct.stack_st_ASN1_OBJECT */
            	2993, 0,
            0, 32, 2, /* 2993: struct.stack_st_fake_ASN1_OBJECT */
            	3000, 8,
            	360, 24,
            8884099, 8, 2, /* 3000: pointer_to_array_of_pointers_to_stack */
            	3007, 0,
            	357, 20,
            0, 8, 1, /* 3007: pointer.ASN1_OBJECT */
            	3012, 0,
            0, 0, 1, /* 3012: ASN1_OBJECT */
            	3017, 0,
            0, 40, 3, /* 3017: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            1, 8, 1, /* 3026: pointer.struct.stack_st_X509_ALGOR */
            	3031, 0,
            0, 32, 2, /* 3031: struct.stack_st_fake_X509_ALGOR */
            	3038, 8,
            	360, 24,
            8884099, 8, 2, /* 3038: pointer_to_array_of_pointers_to_stack */
            	3045, 0,
            	357, 20,
            0, 8, 1, /* 3045: pointer.X509_ALGOR */
            	3050, 0,
            0, 0, 1, /* 3050: X509_ALGOR */
            	2544, 0,
            1, 8, 1, /* 3055: pointer.struct.stack_st_X509_ALGOR */
            	3060, 0,
            0, 32, 2, /* 3060: struct.stack_st_fake_X509_ALGOR */
            	3067, 8,
            	360, 24,
            8884099, 8, 2, /* 3067: pointer_to_array_of_pointers_to_stack */
            	3074, 0,
            	357, 20,
            0, 8, 1, /* 3074: pointer.X509_ALGOR */
            	3050, 0,
            1, 8, 1, /* 3079: pointer.struct.stack_st_ASN1_OBJECT */
            	3084, 0,
            0, 32, 2, /* 3084: struct.stack_st_fake_ASN1_OBJECT */
            	3091, 8,
            	360, 24,
            8884099, 8, 2, /* 3091: pointer_to_array_of_pointers_to_stack */
            	3098, 0,
            	357, 20,
            0, 8, 1, /* 3098: pointer.ASN1_OBJECT */
            	3012, 0,
            0, 0, 0, /* 3103: struct.NAME_CONSTRAINTS_st */
            8884097, 8, 0, /* 3106: pointer.func */
            1, 8, 1, /* 3109: pointer.struct.ASN1_VALUE_st */
            	3114, 0,
            0, 0, 0, /* 3114: struct.ASN1_VALUE_st */
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
            	1339, 128,
            1, 8, 1, /* 3164: pointer.struct.bignum_st */
            	3169, 0,
            0, 24, 1, /* 3169: struct.bignum_st */
            	1357, 0,
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
            8884097, 8, 0, /* 3218: pointer.func */
            8884097, 8, 0, /* 3221: pointer.func */
            8884097, 8, 0, /* 3224: pointer.func */
            8884097, 8, 0, /* 3227: pointer.func */
            8884097, 8, 0, /* 3230: pointer.func */
            8884097, 8, 0, /* 3233: pointer.func */
            8884097, 8, 0, /* 3236: pointer.func */
            1, 8, 1, /* 3239: pointer.struct.X509_crl_info_st */
            	3244, 0,
            0, 80, 8, /* 3244: struct.X509_crl_info_st */
            	3263, 0,
            	3273, 8,
            	3422, 16,
            	3470, 24,
            	3470, 32,
            	3475, 40,
            	3499, 48,
            	3523, 56,
            1, 8, 1, /* 3263: pointer.struct.asn1_string_st */
            	3268, 0,
            0, 24, 1, /* 3268: struct.asn1_string_st */
            	200, 8,
            1, 8, 1, /* 3273: pointer.struct.X509_algor_st */
            	3278, 0,
            0, 16, 2, /* 3278: struct.X509_algor_st */
            	3285, 0,
            	3299, 8,
            1, 8, 1, /* 3285: pointer.struct.asn1_object_st */
            	3290, 0,
            0, 40, 3, /* 3290: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            1, 8, 1, /* 3299: pointer.struct.asn1_type_st */
            	3304, 0,
            0, 16, 1, /* 3304: struct.asn1_type_st */
            	3309, 8,
            0, 8, 20, /* 3309: union.unknown */
            	93, 0,
            	3352, 0,
            	3285, 0,
            	3263, 0,
            	3357, 0,
            	3362, 0,
            	3367, 0,
            	3372, 0,
            	3377, 0,
            	3382, 0,
            	3387, 0,
            	3392, 0,
            	3397, 0,
            	3402, 0,
            	3407, 0,
            	3412, 0,
            	3417, 0,
            	3352, 0,
            	3352, 0,
            	611, 0,
            1, 8, 1, /* 3352: pointer.struct.asn1_string_st */
            	3268, 0,
            1, 8, 1, /* 3357: pointer.struct.asn1_string_st */
            	3268, 0,
            1, 8, 1, /* 3362: pointer.struct.asn1_string_st */
            	3268, 0,
            1, 8, 1, /* 3367: pointer.struct.asn1_string_st */
            	3268, 0,
            1, 8, 1, /* 3372: pointer.struct.asn1_string_st */
            	3268, 0,
            1, 8, 1, /* 3377: pointer.struct.asn1_string_st */
            	3268, 0,
            1, 8, 1, /* 3382: pointer.struct.asn1_string_st */
            	3268, 0,
            1, 8, 1, /* 3387: pointer.struct.asn1_string_st */
            	3268, 0,
            1, 8, 1, /* 3392: pointer.struct.asn1_string_st */
            	3268, 0,
            1, 8, 1, /* 3397: pointer.struct.asn1_string_st */
            	3268, 0,
            1, 8, 1, /* 3402: pointer.struct.asn1_string_st */
            	3268, 0,
            1, 8, 1, /* 3407: pointer.struct.asn1_string_st */
            	3268, 0,
            1, 8, 1, /* 3412: pointer.struct.asn1_string_st */
            	3268, 0,
            1, 8, 1, /* 3417: pointer.struct.asn1_string_st */
            	3268, 0,
            1, 8, 1, /* 3422: pointer.struct.X509_name_st */
            	3427, 0,
            0, 40, 3, /* 3427: struct.X509_name_st */
            	3436, 0,
            	3460, 16,
            	200, 24,
            1, 8, 1, /* 3436: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3441, 0,
            0, 32, 2, /* 3441: struct.stack_st_fake_X509_NAME_ENTRY */
            	3448, 8,
            	360, 24,
            8884099, 8, 2, /* 3448: pointer_to_array_of_pointers_to_stack */
            	3455, 0,
            	357, 20,
            0, 8, 1, /* 3455: pointer.X509_NAME_ENTRY */
            	321, 0,
            1, 8, 1, /* 3460: pointer.struct.buf_mem_st */
            	3465, 0,
            0, 24, 1, /* 3465: struct.buf_mem_st */
            	93, 8,
            1, 8, 1, /* 3470: pointer.struct.asn1_string_st */
            	3268, 0,
            1, 8, 1, /* 3475: pointer.struct.stack_st_X509_REVOKED */
            	3480, 0,
            0, 32, 2, /* 3480: struct.stack_st_fake_X509_REVOKED */
            	3487, 8,
            	360, 24,
            8884099, 8, 2, /* 3487: pointer_to_array_of_pointers_to_stack */
            	3494, 0,
            	357, 20,
            0, 8, 1, /* 3494: pointer.X509_REVOKED */
            	648, 0,
            1, 8, 1, /* 3499: pointer.struct.stack_st_X509_EXTENSION */
            	3504, 0,
            0, 32, 2, /* 3504: struct.stack_st_fake_X509_EXTENSION */
            	3511, 8,
            	360, 24,
            8884099, 8, 2, /* 3511: pointer_to_array_of_pointers_to_stack */
            	3518, 0,
            	357, 20,
            0, 8, 1, /* 3518: pointer.X509_EXTENSION */
            	703, 0,
            0, 24, 1, /* 3523: struct.ASN1_ENCODING_st */
            	200, 0,
            0, 0, 0, /* 3528: struct.X509_POLICY_CACHE_st */
            0, 0, 0, /* 3531: struct.AUTHORITY_KEYID_st */
            0, 40, 5, /* 3534: struct.x509_cert_aux_st */
            	3079, 0,
            	3079, 8,
            	3547, 16,
            	3557, 24,
            	3055, 32,
            1, 8, 1, /* 3547: pointer.struct.asn1_string_st */
            	3552, 0,
            0, 24, 1, /* 3552: struct.asn1_string_st */
            	200, 8,
            1, 8, 1, /* 3557: pointer.struct.asn1_string_st */
            	3552, 0,
            1, 8, 1, /* 3562: pointer.struct.stack_st_DIST_POINT */
            	3567, 0,
            0, 32, 2, /* 3567: struct.stack_st_fake_DIST_POINT */
            	3574, 8,
            	360, 24,
            8884099, 8, 2, /* 3574: pointer_to_array_of_pointers_to_stack */
            	3581, 0,
            	357, 20,
            0, 8, 1, /* 3581: pointer.DIST_POINT */
            	2620, 0,
            8884097, 8, 0, /* 3586: pointer.func */
            8884097, 8, 0, /* 3589: pointer.func */
            0, 184, 12, /* 3592: struct.x509_st */
            	3619, 0,
            	3654, 8,
            	3743, 16,
            	93, 32,
            	2187, 40,
            	3557, 104,
            	3906, 112,
            	3911, 120,
            	3562, 128,
            	3916, 136,
            	3940, 144,
            	3945, 176,
            1, 8, 1, /* 3619: pointer.struct.x509_cinf_st */
            	3624, 0,
            0, 104, 11, /* 3624: struct.x509_cinf_st */
            	3649, 0,
            	3649, 8,
            	3654, 16,
            	3793, 24,
            	3841, 32,
            	3793, 40,
            	3858, 48,
            	3743, 56,
            	3743, 64,
            	3877, 72,
            	3901, 80,
            1, 8, 1, /* 3649: pointer.struct.asn1_string_st */
            	3552, 0,
            1, 8, 1, /* 3654: pointer.struct.X509_algor_st */
            	3659, 0,
            0, 16, 2, /* 3659: struct.X509_algor_st */
            	3666, 0,
            	3680, 8,
            1, 8, 1, /* 3666: pointer.struct.asn1_object_st */
            	3671, 0,
            0, 40, 3, /* 3671: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            1, 8, 1, /* 3680: pointer.struct.asn1_type_st */
            	3685, 0,
            0, 16, 1, /* 3685: struct.asn1_type_st */
            	3690, 8,
            0, 8, 20, /* 3690: union.unknown */
            	93, 0,
            	3733, 0,
            	3666, 0,
            	3649, 0,
            	3738, 0,
            	3743, 0,
            	3557, 0,
            	3748, 0,
            	3753, 0,
            	3758, 0,
            	3763, 0,
            	3768, 0,
            	3773, 0,
            	3778, 0,
            	3783, 0,
            	3788, 0,
            	3547, 0,
            	3733, 0,
            	3733, 0,
            	3109, 0,
            1, 8, 1, /* 3733: pointer.struct.asn1_string_st */
            	3552, 0,
            1, 8, 1, /* 3738: pointer.struct.asn1_string_st */
            	3552, 0,
            1, 8, 1, /* 3743: pointer.struct.asn1_string_st */
            	3552, 0,
            1, 8, 1, /* 3748: pointer.struct.asn1_string_st */
            	3552, 0,
            1, 8, 1, /* 3753: pointer.struct.asn1_string_st */
            	3552, 0,
            1, 8, 1, /* 3758: pointer.struct.asn1_string_st */
            	3552, 0,
            1, 8, 1, /* 3763: pointer.struct.asn1_string_st */
            	3552, 0,
            1, 8, 1, /* 3768: pointer.struct.asn1_string_st */
            	3552, 0,
            1, 8, 1, /* 3773: pointer.struct.asn1_string_st */
            	3552, 0,
            1, 8, 1, /* 3778: pointer.struct.asn1_string_st */
            	3552, 0,
            1, 8, 1, /* 3783: pointer.struct.asn1_string_st */
            	3552, 0,
            1, 8, 1, /* 3788: pointer.struct.asn1_string_st */
            	3552, 0,
            1, 8, 1, /* 3793: pointer.struct.X509_name_st */
            	3798, 0,
            0, 40, 3, /* 3798: struct.X509_name_st */
            	3807, 0,
            	3831, 16,
            	200, 24,
            1, 8, 1, /* 3807: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3812, 0,
            0, 32, 2, /* 3812: struct.stack_st_fake_X509_NAME_ENTRY */
            	3819, 8,
            	360, 24,
            8884099, 8, 2, /* 3819: pointer_to_array_of_pointers_to_stack */
            	3826, 0,
            	357, 20,
            0, 8, 1, /* 3826: pointer.X509_NAME_ENTRY */
            	321, 0,
            1, 8, 1, /* 3831: pointer.struct.buf_mem_st */
            	3836, 0,
            0, 24, 1, /* 3836: struct.buf_mem_st */
            	93, 8,
            1, 8, 1, /* 3841: pointer.struct.X509_val_st */
            	3846, 0,
            0, 16, 2, /* 3846: struct.X509_val_st */
            	3853, 0,
            	3853, 8,
            1, 8, 1, /* 3853: pointer.struct.asn1_string_st */
            	3552, 0,
            1, 8, 1, /* 3858: pointer.struct.X509_pubkey_st */
            	3863, 0,
            0, 24, 3, /* 3863: struct.X509_pubkey_st */
            	3654, 0,
            	3743, 8,
            	3872, 16,
            1, 8, 1, /* 3872: pointer.struct.evp_pkey_st */
            	2040, 0,
            1, 8, 1, /* 3877: pointer.struct.stack_st_X509_EXTENSION */
            	3882, 0,
            0, 32, 2, /* 3882: struct.stack_st_fake_X509_EXTENSION */
            	3889, 8,
            	360, 24,
            8884099, 8, 2, /* 3889: pointer_to_array_of_pointers_to_stack */
            	3896, 0,
            	357, 20,
            0, 8, 1, /* 3896: pointer.X509_EXTENSION */
            	703, 0,
            0, 24, 1, /* 3901: struct.ASN1_ENCODING_st */
            	200, 0,
            1, 8, 1, /* 3906: pointer.struct.AUTHORITY_KEYID_st */
            	3531, 0,
            1, 8, 1, /* 3911: pointer.struct.X509_POLICY_CACHE_st */
            	3528, 0,
            1, 8, 1, /* 3916: pointer.struct.stack_st_GENERAL_NAME */
            	3921, 0,
            0, 32, 2, /* 3921: struct.stack_st_fake_GENERAL_NAME */
            	3928, 8,
            	360, 24,
            8884099, 8, 2, /* 3928: pointer_to_array_of_pointers_to_stack */
            	3935, 0,
            	357, 20,
            0, 8, 1, /* 3935: pointer.GENERAL_NAME */
            	50, 0,
            1, 8, 1, /* 3940: pointer.struct.NAME_CONSTRAINTS_st */
            	3103, 0,
            1, 8, 1, /* 3945: pointer.struct.x509_cert_aux_st */
            	3534, 0,
            0, 0, 1, /* 3950: X509_OBJECT */
            	3955, 0,
            0, 16, 1, /* 3955: struct.x509_object_st */
            	3960, 8,
            0, 8, 4, /* 3960: union.unknown */
            	93, 0,
            	3971, 0,
            	4398, 0,
            	4059, 0,
            1, 8, 1, /* 3971: pointer.struct.x509_st */
            	3976, 0,
            0, 184, 12, /* 3976: struct.x509_st */
            	4003, 0,
            	3273, 8,
            	3362, 16,
            	93, 32,
            	3117, 40,
            	3367, 104,
            	1226, 112,
            	2588, 120,
            	4276, 128,
            	4300, 136,
            	4324, 144,
            	4332, 176,
            1, 8, 1, /* 4003: pointer.struct.x509_cinf_st */
            	4008, 0,
            0, 104, 11, /* 4008: struct.x509_cinf_st */
            	3263, 0,
            	3263, 8,
            	3273, 16,
            	3422, 24,
            	4033, 32,
            	3422, 40,
            	4045, 48,
            	3362, 56,
            	3362, 64,
            	3499, 72,
            	3523, 80,
            1, 8, 1, /* 4033: pointer.struct.X509_val_st */
            	4038, 0,
            0, 16, 2, /* 4038: struct.X509_val_st */
            	3470, 0,
            	3470, 8,
            1, 8, 1, /* 4045: pointer.struct.X509_pubkey_st */
            	4050, 0,
            0, 24, 3, /* 4050: struct.X509_pubkey_st */
            	3273, 0,
            	3362, 8,
            	4059, 16,
            1, 8, 1, /* 4059: pointer.struct.evp_pkey_st */
            	4064, 0,
            0, 56, 4, /* 4064: struct.evp_pkey_st */
            	1481, 16,
            	1339, 24,
            	4075, 32,
            	4252, 48,
            0, 8, 5, /* 4075: union.unknown */
            	93, 0,
            	4088, 0,
            	4179, 0,
            	4184, 0,
            	1651, 0,
            1, 8, 1, /* 4088: pointer.struct.rsa_st */
            	4093, 0,
            0, 168, 17, /* 4093: struct.rsa_st */
            	4130, 16,
            	1339, 24,
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
            	1401, 152,
            	1401, 160,
            1, 8, 1, /* 4130: pointer.struct.rsa_meth_st */
            	4135, 0,
            0, 112, 13, /* 4135: struct.rsa_meth_st */
            	124, 0,
            	4164, 8,
            	4164, 16,
            	4164, 24,
            	4164, 32,
            	4167, 40,
            	4170, 48,
            	4173, 56,
            	4173, 64,
            	93, 80,
            	3106, 88,
            	3589, 96,
            	4176, 104,
            8884097, 8, 0, /* 4164: pointer.func */
            8884097, 8, 0, /* 4167: pointer.func */
            8884097, 8, 0, /* 4170: pointer.func */
            8884097, 8, 0, /* 4173: pointer.func */
            8884097, 8, 0, /* 4176: pointer.func */
            1, 8, 1, /* 4179: pointer.struct.dsa_st */
            	3139, 0,
            1, 8, 1, /* 4184: pointer.struct.dh_st */
            	4189, 0,
            0, 144, 12, /* 4189: struct.dh_st */
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
            	4216, 128,
            	1339, 136,
            1, 8, 1, /* 4216: pointer.struct.dh_method */
            	4221, 0,
            0, 72, 8, /* 4221: struct.dh_method */
            	124, 0,
            	4240, 8,
            	4243, 16,
            	4246, 24,
            	4240, 32,
            	4240, 40,
            	93, 56,
            	4249, 64,
            8884097, 8, 0, /* 4240: pointer.func */
            8884097, 8, 0, /* 4243: pointer.func */
            8884097, 8, 0, /* 4246: pointer.func */
            8884097, 8, 0, /* 4249: pointer.func */
            1, 8, 1, /* 4252: pointer.struct.stack_st_X509_ATTRIBUTE */
            	4257, 0,
            0, 32, 2, /* 4257: struct.stack_st_fake_X509_ATTRIBUTE */
            	4264, 8,
            	360, 24,
            8884099, 8, 2, /* 4264: pointer_to_array_of_pointers_to_stack */
            	4271, 0,
            	357, 20,
            0, 8, 1, /* 4271: pointer.X509_ATTRIBUTE */
            	1683, 0,
            1, 8, 1, /* 4276: pointer.struct.stack_st_DIST_POINT */
            	4281, 0,
            0, 32, 2, /* 4281: struct.stack_st_fake_DIST_POINT */
            	4288, 8,
            	360, 24,
            8884099, 8, 2, /* 4288: pointer_to_array_of_pointers_to_stack */
            	4295, 0,
            	357, 20,
            0, 8, 1, /* 4295: pointer.DIST_POINT */
            	2620, 0,
            1, 8, 1, /* 4300: pointer.struct.stack_st_GENERAL_NAME */
            	4305, 0,
            0, 32, 2, /* 4305: struct.stack_st_fake_GENERAL_NAME */
            	4312, 8,
            	360, 24,
            8884099, 8, 2, /* 4312: pointer_to_array_of_pointers_to_stack */
            	4319, 0,
            	357, 20,
            0, 8, 1, /* 4319: pointer.GENERAL_NAME */
            	50, 0,
            1, 8, 1, /* 4324: pointer.struct.NAME_CONSTRAINTS_st */
            	4329, 0,
            0, 0, 0, /* 4329: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 4332: pointer.struct.x509_cert_aux_st */
            	4337, 0,
            0, 40, 5, /* 4337: struct.x509_cert_aux_st */
            	4350, 0,
            	4350, 8,
            	3417, 16,
            	3367, 24,
            	4374, 32,
            1, 8, 1, /* 4350: pointer.struct.stack_st_ASN1_OBJECT */
            	4355, 0,
            0, 32, 2, /* 4355: struct.stack_st_fake_ASN1_OBJECT */
            	4362, 8,
            	360, 24,
            8884099, 8, 2, /* 4362: pointer_to_array_of_pointers_to_stack */
            	4369, 0,
            	357, 20,
            0, 8, 1, /* 4369: pointer.ASN1_OBJECT */
            	3012, 0,
            1, 8, 1, /* 4374: pointer.struct.stack_st_X509_ALGOR */
            	4379, 0,
            0, 32, 2, /* 4379: struct.stack_st_fake_X509_ALGOR */
            	4386, 8,
            	360, 24,
            8884099, 8, 2, /* 4386: pointer_to_array_of_pointers_to_stack */
            	4393, 0,
            	357, 20,
            0, 8, 1, /* 4393: pointer.X509_ALGOR */
            	3050, 0,
            1, 8, 1, /* 4398: pointer.struct.X509_crl_st */
            	4403, 0,
            0, 120, 10, /* 4403: struct.X509_crl_st */
            	3239, 0,
            	3273, 8,
            	3362, 16,
            	1226, 32,
            	1234, 40,
            	3263, 56,
            	3263, 64,
            	844, 96,
            	890, 104,
            	898, 112,
            0, 32, 3, /* 4426: struct.x509_lookup_st */
            	4435, 8,
            	93, 16,
            	4484, 24,
            1, 8, 1, /* 4435: pointer.struct.x509_lookup_method_st */
            	4440, 0,
            0, 80, 10, /* 4440: struct.x509_lookup_method_st */
            	124, 0,
            	4463, 8,
            	4466, 16,
            	4463, 24,
            	4463, 32,
            	4469, 40,
            	4472, 48,
            	4475, 56,
            	4478, 64,
            	4481, 72,
            8884097, 8, 0, /* 4463: pointer.func */
            8884097, 8, 0, /* 4466: pointer.func */
            8884097, 8, 0, /* 4469: pointer.func */
            8884097, 8, 0, /* 4472: pointer.func */
            8884097, 8, 0, /* 4475: pointer.func */
            8884097, 8, 0, /* 4478: pointer.func */
            8884097, 8, 0, /* 4481: pointer.func */
            1, 8, 1, /* 4484: pointer.struct.x509_store_st */
            	4489, 0,
            0, 144, 15, /* 4489: struct.x509_store_st */
            	4522, 8,
            	4546, 16,
            	4575, 24,
            	4587, 32,
            	4590, 40,
            	4593, 48,
            	4596, 56,
            	4587, 64,
            	4599, 72,
            	4602, 80,
            	4605, 88,
            	4608, 96,
            	3586, 104,
            	4587, 112,
            	3117, 120,
            1, 8, 1, /* 4522: pointer.struct.stack_st_X509_OBJECT */
            	4527, 0,
            0, 32, 2, /* 4527: struct.stack_st_fake_X509_OBJECT */
            	4534, 8,
            	360, 24,
            8884099, 8, 2, /* 4534: pointer_to_array_of_pointers_to_stack */
            	4541, 0,
            	357, 20,
            0, 8, 1, /* 4541: pointer.X509_OBJECT */
            	3950, 0,
            1, 8, 1, /* 4546: pointer.struct.stack_st_X509_LOOKUP */
            	4551, 0,
            0, 32, 2, /* 4551: struct.stack_st_fake_X509_LOOKUP */
            	4558, 8,
            	360, 24,
            8884099, 8, 2, /* 4558: pointer_to_array_of_pointers_to_stack */
            	4565, 0,
            	357, 20,
            0, 8, 1, /* 4565: pointer.X509_LOOKUP */
            	4570, 0,
            0, 0, 1, /* 4570: X509_LOOKUP */
            	4426, 0,
            1, 8, 1, /* 4575: pointer.struct.X509_VERIFY_PARAM_st */
            	4580, 0,
            0, 56, 2, /* 4580: struct.X509_VERIFY_PARAM_st */
            	93, 0,
            	4350, 48,
            8884097, 8, 0, /* 4587: pointer.func */
            8884097, 8, 0, /* 4590: pointer.func */
            8884097, 8, 0, /* 4593: pointer.func */
            8884097, 8, 0, /* 4596: pointer.func */
            8884097, 8, 0, /* 4599: pointer.func */
            8884097, 8, 0, /* 4602: pointer.func */
            8884097, 8, 0, /* 4605: pointer.func */
            8884097, 8, 0, /* 4608: pointer.func */
            0, 248, 25, /* 4611: struct.x509_store_ctx_st */
            	4664, 0,
            	2556, 16,
            	4789, 24,
            	4818, 32,
            	4750, 40,
            	898, 48,
            	4762, 56,
            	4765, 64,
            	4768, 72,
            	4771, 80,
            	4762, 88,
            	4774, 96,
            	4777, 104,
            	4780, 112,
            	4762, 120,
            	4783, 128,
            	4786, 136,
            	4762, 144,
            	4789, 160,
            	904, 168,
            	2556, 192,
            	2556, 200,
            	792, 208,
            	4842, 224,
            	1365, 232,
            1, 8, 1, /* 4664: pointer.struct.x509_store_st */
            	4669, 0,
            0, 144, 15, /* 4669: struct.x509_store_st */
            	4702, 8,
            	4726, 16,
            	4750, 24,
            	4762, 32,
            	4765, 40,
            	4768, 48,
            	4771, 56,
            	4762, 64,
            	4774, 72,
            	4777, 80,
            	4780, 88,
            	4783, 96,
            	4786, 104,
            	4762, 112,
            	1365, 120,
            1, 8, 1, /* 4702: pointer.struct.stack_st_X509_OBJECT */
            	4707, 0,
            0, 32, 2, /* 4707: struct.stack_st_fake_X509_OBJECT */
            	4714, 8,
            	360, 24,
            8884099, 8, 2, /* 4714: pointer_to_array_of_pointers_to_stack */
            	4721, 0,
            	357, 20,
            0, 8, 1, /* 4721: pointer.X509_OBJECT */
            	3950, 0,
            1, 8, 1, /* 4726: pointer.struct.stack_st_X509_LOOKUP */
            	4731, 0,
            0, 32, 2, /* 4731: struct.stack_st_fake_X509_LOOKUP */
            	4738, 8,
            	360, 24,
            8884099, 8, 2, /* 4738: pointer_to_array_of_pointers_to_stack */
            	4745, 0,
            	357, 20,
            0, 8, 1, /* 4745: pointer.X509_LOOKUP */
            	4570, 0,
            1, 8, 1, /* 4750: pointer.struct.X509_VERIFY_PARAM_st */
            	4755, 0,
            0, 56, 2, /* 4755: struct.X509_VERIFY_PARAM_st */
            	93, 0,
            	2988, 48,
            8884097, 8, 0, /* 4762: pointer.func */
            8884097, 8, 0, /* 4765: pointer.func */
            8884097, 8, 0, /* 4768: pointer.func */
            8884097, 8, 0, /* 4771: pointer.func */
            8884097, 8, 0, /* 4774: pointer.func */
            8884097, 8, 0, /* 4777: pointer.func */
            8884097, 8, 0, /* 4780: pointer.func */
            8884097, 8, 0, /* 4783: pointer.func */
            8884097, 8, 0, /* 4786: pointer.func */
            1, 8, 1, /* 4789: pointer.struct.stack_st_X509 */
            	4794, 0,
            0, 32, 2, /* 4794: struct.stack_st_fake_X509 */
            	4801, 8,
            	360, 24,
            8884099, 8, 2, /* 4801: pointer_to_array_of_pointers_to_stack */
            	4808, 0,
            	357, 20,
            0, 8, 1, /* 4808: pointer.X509 */
            	4813, 0,
            0, 0, 1, /* 4813: X509 */
            	3592, 0,
            1, 8, 1, /* 4818: pointer.struct.stack_st_X509_CRL */
            	4823, 0,
            0, 32, 2, /* 4823: struct.stack_st_fake_X509_CRL */
            	4830, 8,
            	360, 24,
            8884099, 8, 2, /* 4830: pointer_to_array_of_pointers_to_stack */
            	4837, 0,
            	357, 20,
            0, 8, 1, /* 4837: pointer.X509_CRL */
            	1198, 0,
            1, 8, 1, /* 4842: pointer.struct.x509_store_ctx_st */
            	4611, 0,
            0, 1, 0, /* 4847: char */
        },
        .arg_entity_index = { 4842, 4664, 2556, 4789, },
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

