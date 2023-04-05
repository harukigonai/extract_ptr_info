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
            1, 8, 1, /* 938: pointer.struct.buf_mem_st */
            	943, 0,
            0, 24, 1, /* 943: struct.buf_mem_st */
            	93, 8,
            1, 8, 1, /* 948: pointer.struct.stack_st_X509_NAME_ENTRY */
            	953, 0,
            0, 32, 2, /* 953: struct.stack_st_fake_X509_NAME_ENTRY */
            	960, 8,
            	360, 24,
            8884099, 8, 2, /* 960: pointer_to_array_of_pointers_to_stack */
            	967, 0,
            	357, 20,
            0, 8, 1, /* 967: pointer.X509_NAME_ENTRY */
            	321, 0,
            1, 8, 1, /* 972: pointer.struct.asn1_string_st */
            	977, 0,
            0, 24, 1, /* 977: struct.asn1_string_st */
            	200, 8,
            1, 8, 1, /* 982: pointer.struct.asn1_string_st */
            	977, 0,
            1, 8, 1, /* 987: pointer.struct.asn1_string_st */
            	977, 0,
            1, 8, 1, /* 992: pointer.struct.asn1_string_st */
            	977, 0,
            1, 8, 1, /* 997: pointer.struct.asn1_string_st */
            	977, 0,
            1, 8, 1, /* 1002: pointer.struct.asn1_string_st */
            	977, 0,
            1, 8, 1, /* 1007: pointer.struct.asn1_string_st */
            	1012, 0,
            0, 24, 1, /* 1012: struct.asn1_string_st */
            	200, 8,
            0, 248, 25, /* 1017: struct.x509_store_ctx_st */
            	1070, 0,
            	2778, 16,
            	3599, 24,
            	4465, 32,
            	2693, 40,
            	898, 48,
            	2729, 56,
            	2732, 64,
            	2735, 72,
            	2738, 80,
            	2729, 88,
            	2741, 96,
            	2744, 104,
            	2747, 112,
            	2729, 120,
            	2750, 128,
            	2753, 136,
            	2729, 144,
            	3599, 160,
            	904, 168,
            	2778, 192,
            	2778, 200,
            	792, 208,
            	4708, 224,
            	2756, 232,
            1, 8, 1, /* 1070: pointer.struct.x509_store_st */
            	1075, 0,
            0, 144, 15, /* 1075: struct.x509_store_st */
            	1108, 8,
            	2481, 16,
            	2693, 24,
            	2729, 32,
            	2732, 40,
            	2735, 48,
            	2738, 56,
            	2729, 64,
            	2741, 72,
            	2744, 80,
            	2747, 88,
            	2750, 96,
            	2753, 104,
            	2729, 112,
            	2756, 120,
            1, 8, 1, /* 1108: pointer.struct.stack_st_X509_OBJECT */
            	1113, 0,
            0, 32, 2, /* 1113: struct.stack_st_fake_X509_OBJECT */
            	1120, 8,
            	360, 24,
            8884099, 8, 2, /* 1120: pointer_to_array_of_pointers_to_stack */
            	1127, 0,
            	357, 20,
            0, 8, 1, /* 1127: pointer.X509_OBJECT */
            	1132, 0,
            0, 0, 1, /* 1132: X509_OBJECT */
            	1137, 0,
            0, 16, 1, /* 1137: struct.x509_object_st */
            	1142, 8,
            0, 8, 4, /* 1142: union.unknown */
            	93, 0,
            	1153, 0,
            	2397, 0,
            	1453, 0,
            1, 8, 1, /* 1153: pointer.struct.x509_st */
            	1158, 0,
            0, 184, 12, /* 1158: struct.x509_st */
            	1185, 0,
            	1225, 8,
            	1314, 16,
            	93, 32,
            	1613, 40,
            	1319, 104,
            	2214, 112,
            	2222, 120,
            	2230, 128,
            	2268, 136,
            	2292, 144,
            	2300, 176,
            1, 8, 1, /* 1185: pointer.struct.x509_cinf_st */
            	1190, 0,
            0, 104, 11, /* 1190: struct.x509_cinf_st */
            	1215, 0,
            	1215, 8,
            	1225, 16,
            	1374, 24,
            	1422, 32,
            	1374, 40,
            	1439, 48,
            	1314, 56,
            	1314, 64,
            	2185, 72,
            	2209, 80,
            1, 8, 1, /* 1215: pointer.struct.asn1_string_st */
            	1220, 0,
            0, 24, 1, /* 1220: struct.asn1_string_st */
            	200, 8,
            1, 8, 1, /* 1225: pointer.struct.X509_algor_st */
            	1230, 0,
            0, 16, 2, /* 1230: struct.X509_algor_st */
            	1237, 0,
            	1251, 8,
            1, 8, 1, /* 1237: pointer.struct.asn1_object_st */
            	1242, 0,
            0, 40, 3, /* 1242: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            1, 8, 1, /* 1251: pointer.struct.asn1_type_st */
            	1256, 0,
            0, 16, 1, /* 1256: struct.asn1_type_st */
            	1261, 8,
            0, 8, 20, /* 1261: union.unknown */
            	93, 0,
            	1304, 0,
            	1237, 0,
            	1215, 0,
            	1309, 0,
            	1314, 0,
            	1319, 0,
            	1324, 0,
            	1329, 0,
            	1334, 0,
            	1339, 0,
            	1344, 0,
            	1349, 0,
            	1354, 0,
            	1359, 0,
            	1364, 0,
            	1369, 0,
            	1304, 0,
            	1304, 0,
            	611, 0,
            1, 8, 1, /* 1304: pointer.struct.asn1_string_st */
            	1220, 0,
            1, 8, 1, /* 1309: pointer.struct.asn1_string_st */
            	1220, 0,
            1, 8, 1, /* 1314: pointer.struct.asn1_string_st */
            	1220, 0,
            1, 8, 1, /* 1319: pointer.struct.asn1_string_st */
            	1220, 0,
            1, 8, 1, /* 1324: pointer.struct.asn1_string_st */
            	1220, 0,
            1, 8, 1, /* 1329: pointer.struct.asn1_string_st */
            	1220, 0,
            1, 8, 1, /* 1334: pointer.struct.asn1_string_st */
            	1220, 0,
            1, 8, 1, /* 1339: pointer.struct.asn1_string_st */
            	1220, 0,
            1, 8, 1, /* 1344: pointer.struct.asn1_string_st */
            	1220, 0,
            1, 8, 1, /* 1349: pointer.struct.asn1_string_st */
            	1220, 0,
            1, 8, 1, /* 1354: pointer.struct.asn1_string_st */
            	1220, 0,
            1, 8, 1, /* 1359: pointer.struct.asn1_string_st */
            	1220, 0,
            1, 8, 1, /* 1364: pointer.struct.asn1_string_st */
            	1220, 0,
            1, 8, 1, /* 1369: pointer.struct.asn1_string_st */
            	1220, 0,
            1, 8, 1, /* 1374: pointer.struct.X509_name_st */
            	1379, 0,
            0, 40, 3, /* 1379: struct.X509_name_st */
            	1388, 0,
            	1412, 16,
            	200, 24,
            1, 8, 1, /* 1388: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1393, 0,
            0, 32, 2, /* 1393: struct.stack_st_fake_X509_NAME_ENTRY */
            	1400, 8,
            	360, 24,
            8884099, 8, 2, /* 1400: pointer_to_array_of_pointers_to_stack */
            	1407, 0,
            	357, 20,
            0, 8, 1, /* 1407: pointer.X509_NAME_ENTRY */
            	321, 0,
            1, 8, 1, /* 1412: pointer.struct.buf_mem_st */
            	1417, 0,
            0, 24, 1, /* 1417: struct.buf_mem_st */
            	93, 8,
            1, 8, 1, /* 1422: pointer.struct.X509_val_st */
            	1427, 0,
            0, 16, 2, /* 1427: struct.X509_val_st */
            	1434, 0,
            	1434, 8,
            1, 8, 1, /* 1434: pointer.struct.asn1_string_st */
            	1220, 0,
            1, 8, 1, /* 1439: pointer.struct.X509_pubkey_st */
            	1444, 0,
            0, 24, 3, /* 1444: struct.X509_pubkey_st */
            	1225, 0,
            	1314, 8,
            	1453, 16,
            1, 8, 1, /* 1453: pointer.struct.evp_pkey_st */
            	1458, 0,
            0, 56, 4, /* 1458: struct.evp_pkey_st */
            	1469, 16,
            	1477, 24,
            	1485, 32,
            	1814, 48,
            1, 8, 1, /* 1469: pointer.struct.evp_pkey_asn1_method_st */
            	1474, 0,
            0, 0, 0, /* 1474: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 1477: pointer.struct.engine_st */
            	1482, 0,
            0, 0, 0, /* 1482: struct.engine_st */
            0, 8, 5, /* 1485: union.unknown */
            	93, 0,
            	1498, 0,
            	1657, 0,
            	1738, 0,
            	1806, 0,
            1, 8, 1, /* 1498: pointer.struct.rsa_st */
            	1503, 0,
            0, 168, 17, /* 1503: struct.rsa_st */
            	1540, 16,
            	1477, 24,
            	1595, 32,
            	1595, 40,
            	1595, 48,
            	1595, 56,
            	1595, 64,
            	1595, 72,
            	1595, 80,
            	1595, 88,
            	1613, 96,
            	1635, 120,
            	1635, 128,
            	1635, 136,
            	93, 144,
            	1649, 152,
            	1649, 160,
            1, 8, 1, /* 1540: pointer.struct.rsa_meth_st */
            	1545, 0,
            0, 112, 13, /* 1545: struct.rsa_meth_st */
            	124, 0,
            	1574, 8,
            	1574, 16,
            	1574, 24,
            	1574, 32,
            	1577, 40,
            	1580, 48,
            	1583, 56,
            	1583, 64,
            	93, 80,
            	1586, 88,
            	1589, 96,
            	1592, 104,
            8884097, 8, 0, /* 1574: pointer.func */
            8884097, 8, 0, /* 1577: pointer.func */
            8884097, 8, 0, /* 1580: pointer.func */
            8884097, 8, 0, /* 1583: pointer.func */
            8884097, 8, 0, /* 1586: pointer.func */
            8884097, 8, 0, /* 1589: pointer.func */
            8884097, 8, 0, /* 1592: pointer.func */
            1, 8, 1, /* 1595: pointer.struct.bignum_st */
            	1600, 0,
            0, 24, 1, /* 1600: struct.bignum_st */
            	1605, 0,
            1, 8, 1, /* 1605: pointer.unsigned int */
            	1610, 0,
            0, 4, 0, /* 1610: unsigned int */
            0, 16, 1, /* 1613: struct.crypto_ex_data_st */
            	1618, 0,
            1, 8, 1, /* 1618: pointer.struct.stack_st_void */
            	1623, 0,
            0, 32, 1, /* 1623: struct.stack_st_void */
            	1628, 0,
            0, 32, 2, /* 1628: struct.stack_st */
            	885, 8,
            	360, 24,
            1, 8, 1, /* 1635: pointer.struct.bn_mont_ctx_st */
            	1640, 0,
            0, 96, 3, /* 1640: struct.bn_mont_ctx_st */
            	1600, 8,
            	1600, 32,
            	1600, 56,
            1, 8, 1, /* 1649: pointer.struct.bn_blinding_st */
            	1654, 0,
            0, 0, 0, /* 1654: struct.bn_blinding_st */
            1, 8, 1, /* 1657: pointer.struct.dsa_st */
            	1662, 0,
            0, 136, 11, /* 1662: struct.dsa_st */
            	1595, 24,
            	1595, 32,
            	1595, 40,
            	1595, 48,
            	1595, 56,
            	1595, 64,
            	1595, 72,
            	1635, 88,
            	1613, 104,
            	1687, 120,
            	1477, 128,
            1, 8, 1, /* 1687: pointer.struct.dsa_method */
            	1692, 0,
            0, 96, 11, /* 1692: struct.dsa_method */
            	124, 0,
            	1717, 8,
            	1720, 16,
            	1723, 24,
            	1726, 32,
            	1729, 40,
            	1732, 48,
            	1732, 56,
            	93, 72,
            	1735, 80,
            	1732, 88,
            8884097, 8, 0, /* 1717: pointer.func */
            8884097, 8, 0, /* 1720: pointer.func */
            8884097, 8, 0, /* 1723: pointer.func */
            8884097, 8, 0, /* 1726: pointer.func */
            8884097, 8, 0, /* 1729: pointer.func */
            8884097, 8, 0, /* 1732: pointer.func */
            8884097, 8, 0, /* 1735: pointer.func */
            1, 8, 1, /* 1738: pointer.struct.dh_st */
            	1743, 0,
            0, 144, 12, /* 1743: struct.dh_st */
            	1595, 8,
            	1595, 16,
            	1595, 32,
            	1595, 40,
            	1635, 56,
            	1595, 64,
            	1595, 72,
            	200, 80,
            	1595, 96,
            	1613, 112,
            	1770, 128,
            	1477, 136,
            1, 8, 1, /* 1770: pointer.struct.dh_method */
            	1775, 0,
            0, 72, 8, /* 1775: struct.dh_method */
            	124, 0,
            	1794, 8,
            	1797, 16,
            	1800, 24,
            	1794, 32,
            	1794, 40,
            	93, 56,
            	1803, 64,
            8884097, 8, 0, /* 1794: pointer.func */
            8884097, 8, 0, /* 1797: pointer.func */
            8884097, 8, 0, /* 1800: pointer.func */
            8884097, 8, 0, /* 1803: pointer.func */
            1, 8, 1, /* 1806: pointer.struct.ec_key_st */
            	1811, 0,
            0, 0, 0, /* 1811: struct.ec_key_st */
            1, 8, 1, /* 1814: pointer.struct.stack_st_X509_ATTRIBUTE */
            	1819, 0,
            0, 32, 2, /* 1819: struct.stack_st_fake_X509_ATTRIBUTE */
            	1826, 8,
            	360, 24,
            8884099, 8, 2, /* 1826: pointer_to_array_of_pointers_to_stack */
            	1833, 0,
            	357, 20,
            0, 8, 1, /* 1833: pointer.X509_ATTRIBUTE */
            	1838, 0,
            0, 0, 1, /* 1838: X509_ATTRIBUTE */
            	1843, 0,
            0, 24, 2, /* 1843: struct.x509_attributes_st */
            	1850, 0,
            	1864, 16,
            1, 8, 1, /* 1850: pointer.struct.asn1_object_st */
            	1855, 0,
            0, 40, 3, /* 1855: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            0, 8, 3, /* 1864: union.unknown */
            	93, 0,
            	1873, 0,
            	2052, 0,
            1, 8, 1, /* 1873: pointer.struct.stack_st_ASN1_TYPE */
            	1878, 0,
            0, 32, 2, /* 1878: struct.stack_st_fake_ASN1_TYPE */
            	1885, 8,
            	360, 24,
            8884099, 8, 2, /* 1885: pointer_to_array_of_pointers_to_stack */
            	1892, 0,
            	357, 20,
            0, 8, 1, /* 1892: pointer.ASN1_TYPE */
            	1897, 0,
            0, 0, 1, /* 1897: ASN1_TYPE */
            	1902, 0,
            0, 16, 1, /* 1902: struct.asn1_type_st */
            	1907, 8,
            0, 8, 20, /* 1907: union.unknown */
            	93, 0,
            	1950, 0,
            	1960, 0,
            	1974, 0,
            	1979, 0,
            	1984, 0,
            	1989, 0,
            	1994, 0,
            	1999, 0,
            	2004, 0,
            	2009, 0,
            	2014, 0,
            	2019, 0,
            	2024, 0,
            	2029, 0,
            	2034, 0,
            	2039, 0,
            	1950, 0,
            	1950, 0,
            	2044, 0,
            1, 8, 1, /* 1950: pointer.struct.asn1_string_st */
            	1955, 0,
            0, 24, 1, /* 1955: struct.asn1_string_st */
            	200, 8,
            1, 8, 1, /* 1960: pointer.struct.asn1_object_st */
            	1965, 0,
            0, 40, 3, /* 1965: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            1, 8, 1, /* 1974: pointer.struct.asn1_string_st */
            	1955, 0,
            1, 8, 1, /* 1979: pointer.struct.asn1_string_st */
            	1955, 0,
            1, 8, 1, /* 1984: pointer.struct.asn1_string_st */
            	1955, 0,
            1, 8, 1, /* 1989: pointer.struct.asn1_string_st */
            	1955, 0,
            1, 8, 1, /* 1994: pointer.struct.asn1_string_st */
            	1955, 0,
            1, 8, 1, /* 1999: pointer.struct.asn1_string_st */
            	1955, 0,
            1, 8, 1, /* 2004: pointer.struct.asn1_string_st */
            	1955, 0,
            1, 8, 1, /* 2009: pointer.struct.asn1_string_st */
            	1955, 0,
            1, 8, 1, /* 2014: pointer.struct.asn1_string_st */
            	1955, 0,
            1, 8, 1, /* 2019: pointer.struct.asn1_string_st */
            	1955, 0,
            1, 8, 1, /* 2024: pointer.struct.asn1_string_st */
            	1955, 0,
            1, 8, 1, /* 2029: pointer.struct.asn1_string_st */
            	1955, 0,
            1, 8, 1, /* 2034: pointer.struct.asn1_string_st */
            	1955, 0,
            1, 8, 1, /* 2039: pointer.struct.asn1_string_st */
            	1955, 0,
            1, 8, 1, /* 2044: pointer.struct.ASN1_VALUE_st */
            	2049, 0,
            0, 0, 0, /* 2049: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2052: pointer.struct.asn1_type_st */
            	2057, 0,
            0, 16, 1, /* 2057: struct.asn1_type_st */
            	2062, 8,
            0, 8, 20, /* 2062: union.unknown */
            	93, 0,
            	2105, 0,
            	1850, 0,
            	2115, 0,
            	2120, 0,
            	2125, 0,
            	2130, 0,
            	2135, 0,
            	2140, 0,
            	2145, 0,
            	2150, 0,
            	2155, 0,
            	2160, 0,
            	2165, 0,
            	2170, 0,
            	2175, 0,
            	2180, 0,
            	2105, 0,
            	2105, 0,
            	611, 0,
            1, 8, 1, /* 2105: pointer.struct.asn1_string_st */
            	2110, 0,
            0, 24, 1, /* 2110: struct.asn1_string_st */
            	200, 8,
            1, 8, 1, /* 2115: pointer.struct.asn1_string_st */
            	2110, 0,
            1, 8, 1, /* 2120: pointer.struct.asn1_string_st */
            	2110, 0,
            1, 8, 1, /* 2125: pointer.struct.asn1_string_st */
            	2110, 0,
            1, 8, 1, /* 2130: pointer.struct.asn1_string_st */
            	2110, 0,
            1, 8, 1, /* 2135: pointer.struct.asn1_string_st */
            	2110, 0,
            1, 8, 1, /* 2140: pointer.struct.asn1_string_st */
            	2110, 0,
            1, 8, 1, /* 2145: pointer.struct.asn1_string_st */
            	2110, 0,
            1, 8, 1, /* 2150: pointer.struct.asn1_string_st */
            	2110, 0,
            1, 8, 1, /* 2155: pointer.struct.asn1_string_st */
            	2110, 0,
            1, 8, 1, /* 2160: pointer.struct.asn1_string_st */
            	2110, 0,
            1, 8, 1, /* 2165: pointer.struct.asn1_string_st */
            	2110, 0,
            1, 8, 1, /* 2170: pointer.struct.asn1_string_st */
            	2110, 0,
            1, 8, 1, /* 2175: pointer.struct.asn1_string_st */
            	2110, 0,
            1, 8, 1, /* 2180: pointer.struct.asn1_string_st */
            	2110, 0,
            1, 8, 1, /* 2185: pointer.struct.stack_st_X509_EXTENSION */
            	2190, 0,
            0, 32, 2, /* 2190: struct.stack_st_fake_X509_EXTENSION */
            	2197, 8,
            	360, 24,
            8884099, 8, 2, /* 2197: pointer_to_array_of_pointers_to_stack */
            	2204, 0,
            	357, 20,
            0, 8, 1, /* 2204: pointer.X509_EXTENSION */
            	703, 0,
            0, 24, 1, /* 2209: struct.ASN1_ENCODING_st */
            	200, 0,
            1, 8, 1, /* 2214: pointer.struct.AUTHORITY_KEYID_st */
            	2219, 0,
            0, 0, 0, /* 2219: struct.AUTHORITY_KEYID_st */
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
            0, 0, 0, /* 2297: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 2300: pointer.struct.x509_cert_aux_st */
            	2305, 0,
            0, 40, 5, /* 2305: struct.x509_cert_aux_st */
            	2318, 0,
            	2318, 8,
            	1369, 16,
            	1319, 24,
            	2356, 32,
            1, 8, 1, /* 2318: pointer.struct.stack_st_ASN1_OBJECT */
            	2323, 0,
            0, 32, 2, /* 2323: struct.stack_st_fake_ASN1_OBJECT */
            	2330, 8,
            	360, 24,
            8884099, 8, 2, /* 2330: pointer_to_array_of_pointers_to_stack */
            	2337, 0,
            	357, 20,
            0, 8, 1, /* 2337: pointer.ASN1_OBJECT */
            	2342, 0,
            0, 0, 1, /* 2342: ASN1_OBJECT */
            	2347, 0,
            0, 40, 3, /* 2347: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            1, 8, 1, /* 2356: pointer.struct.stack_st_X509_ALGOR */
            	2361, 0,
            0, 32, 2, /* 2361: struct.stack_st_fake_X509_ALGOR */
            	2368, 8,
            	360, 24,
            8884099, 8, 2, /* 2368: pointer_to_array_of_pointers_to_stack */
            	2375, 0,
            	357, 20,
            0, 8, 1, /* 2375: pointer.X509_ALGOR */
            	2380, 0,
            0, 0, 1, /* 2380: X509_ALGOR */
            	2385, 0,
            0, 16, 2, /* 2385: struct.X509_algor_st */
            	1960, 0,
            	2392, 8,
            1, 8, 1, /* 2392: pointer.struct.asn1_type_st */
            	1902, 0,
            1, 8, 1, /* 2397: pointer.struct.X509_crl_st */
            	2402, 0,
            0, 120, 10, /* 2402: struct.X509_crl_st */
            	2425, 0,
            	1225, 8,
            	1314, 16,
            	2214, 32,
            	2473, 40,
            	1215, 56,
            	1215, 64,
            	844, 96,
            	890, 104,
            	898, 112,
            1, 8, 1, /* 2425: pointer.struct.X509_crl_info_st */
            	2430, 0,
            0, 80, 8, /* 2430: struct.X509_crl_info_st */
            	1215, 0,
            	1225, 8,
            	1374, 16,
            	1434, 24,
            	1434, 32,
            	2449, 40,
            	2185, 48,
            	2209, 56,
            1, 8, 1, /* 2449: pointer.struct.stack_st_X509_REVOKED */
            	2454, 0,
            0, 32, 2, /* 2454: struct.stack_st_fake_X509_REVOKED */
            	2461, 8,
            	360, 24,
            8884099, 8, 2, /* 2461: pointer_to_array_of_pointers_to_stack */
            	2468, 0,
            	357, 20,
            0, 8, 1, /* 2468: pointer.X509_REVOKED */
            	648, 0,
            1, 8, 1, /* 2473: pointer.struct.ISSUING_DIST_POINT_st */
            	2478, 0,
            0, 0, 0, /* 2478: struct.ISSUING_DIST_POINT_st */
            1, 8, 1, /* 2481: pointer.struct.stack_st_X509_LOOKUP */
            	2486, 0,
            0, 32, 2, /* 2486: struct.stack_st_fake_X509_LOOKUP */
            	2493, 8,
            	360, 24,
            8884099, 8, 2, /* 2493: pointer_to_array_of_pointers_to_stack */
            	2500, 0,
            	357, 20,
            0, 8, 1, /* 2500: pointer.X509_LOOKUP */
            	2505, 0,
            0, 0, 1, /* 2505: X509_LOOKUP */
            	2510, 0,
            0, 32, 3, /* 2510: struct.x509_lookup_st */
            	2519, 8,
            	93, 16,
            	2568, 24,
            1, 8, 1, /* 2519: pointer.struct.x509_lookup_method_st */
            	2524, 0,
            0, 80, 10, /* 2524: struct.x509_lookup_method_st */
            	124, 0,
            	2547, 8,
            	2550, 16,
            	2547, 24,
            	2547, 32,
            	2553, 40,
            	2556, 48,
            	2559, 56,
            	2562, 64,
            	2565, 72,
            8884097, 8, 0, /* 2547: pointer.func */
            8884097, 8, 0, /* 2550: pointer.func */
            8884097, 8, 0, /* 2553: pointer.func */
            8884097, 8, 0, /* 2556: pointer.func */
            8884097, 8, 0, /* 2559: pointer.func */
            8884097, 8, 0, /* 2562: pointer.func */
            8884097, 8, 0, /* 2565: pointer.func */
            1, 8, 1, /* 2568: pointer.struct.x509_store_st */
            	2573, 0,
            0, 144, 15, /* 2573: struct.x509_store_st */
            	2606, 8,
            	2630, 16,
            	2654, 24,
            	2666, 32,
            	2669, 40,
            	2672, 48,
            	2675, 56,
            	2666, 64,
            	2678, 72,
            	2681, 80,
            	2684, 88,
            	2687, 96,
            	2690, 104,
            	2666, 112,
            	1613, 120,
            1, 8, 1, /* 2606: pointer.struct.stack_st_X509_OBJECT */
            	2611, 0,
            0, 32, 2, /* 2611: struct.stack_st_fake_X509_OBJECT */
            	2618, 8,
            	360, 24,
            8884099, 8, 2, /* 2618: pointer_to_array_of_pointers_to_stack */
            	2625, 0,
            	357, 20,
            0, 8, 1, /* 2625: pointer.X509_OBJECT */
            	1132, 0,
            1, 8, 1, /* 2630: pointer.struct.stack_st_X509_LOOKUP */
            	2635, 0,
            0, 32, 2, /* 2635: struct.stack_st_fake_X509_LOOKUP */
            	2642, 8,
            	360, 24,
            8884099, 8, 2, /* 2642: pointer_to_array_of_pointers_to_stack */
            	2649, 0,
            	357, 20,
            0, 8, 1, /* 2649: pointer.X509_LOOKUP */
            	2505, 0,
            1, 8, 1, /* 2654: pointer.struct.X509_VERIFY_PARAM_st */
            	2659, 0,
            0, 56, 2, /* 2659: struct.X509_VERIFY_PARAM_st */
            	93, 0,
            	2318, 48,
            8884097, 8, 0, /* 2666: pointer.func */
            8884097, 8, 0, /* 2669: pointer.func */
            8884097, 8, 0, /* 2672: pointer.func */
            8884097, 8, 0, /* 2675: pointer.func */
            8884097, 8, 0, /* 2678: pointer.func */
            8884097, 8, 0, /* 2681: pointer.func */
            8884097, 8, 0, /* 2684: pointer.func */
            8884097, 8, 0, /* 2687: pointer.func */
            8884097, 8, 0, /* 2690: pointer.func */
            1, 8, 1, /* 2693: pointer.struct.X509_VERIFY_PARAM_st */
            	2698, 0,
            0, 56, 2, /* 2698: struct.X509_VERIFY_PARAM_st */
            	93, 0,
            	2705, 48,
            1, 8, 1, /* 2705: pointer.struct.stack_st_ASN1_OBJECT */
            	2710, 0,
            0, 32, 2, /* 2710: struct.stack_st_fake_ASN1_OBJECT */
            	2717, 8,
            	360, 24,
            8884099, 8, 2, /* 2717: pointer_to_array_of_pointers_to_stack */
            	2724, 0,
            	357, 20,
            0, 8, 1, /* 2724: pointer.ASN1_OBJECT */
            	2342, 0,
            8884097, 8, 0, /* 2729: pointer.func */
            8884097, 8, 0, /* 2732: pointer.func */
            8884097, 8, 0, /* 2735: pointer.func */
            8884097, 8, 0, /* 2738: pointer.func */
            8884097, 8, 0, /* 2741: pointer.func */
            8884097, 8, 0, /* 2744: pointer.func */
            8884097, 8, 0, /* 2747: pointer.func */
            8884097, 8, 0, /* 2750: pointer.func */
            8884097, 8, 0, /* 2753: pointer.func */
            0, 16, 1, /* 2756: struct.crypto_ex_data_st */
            	2761, 0,
            1, 8, 1, /* 2761: pointer.struct.stack_st_void */
            	2766, 0,
            0, 32, 1, /* 2766: struct.stack_st_void */
            	2771, 0,
            0, 32, 2, /* 2771: struct.stack_st */
            	885, 8,
            	360, 24,
            1, 8, 1, /* 2778: pointer.struct.x509_st */
            	2783, 0,
            0, 184, 12, /* 2783: struct.x509_st */
            	2810, 0,
            	467, 8,
            	433, 16,
            	93, 32,
            	2756, 40,
            	556, 104,
            	825, 112,
            	2222, 120,
            	3189, 128,
            	3213, 136,
            	3237, 144,
            	3557, 176,
            1, 8, 1, /* 2810: pointer.struct.x509_cinf_st */
            	2815, 0,
            0, 104, 11, /* 2815: struct.x509_cinf_st */
            	462, 0,
            	462, 8,
            	467, 16,
            	409, 24,
            	2840, 32,
            	409, 40,
            	2852, 48,
            	433, 56,
            	433, 64,
            	763, 72,
            	787, 80,
            1, 8, 1, /* 2840: pointer.struct.X509_val_st */
            	2845, 0,
            0, 16, 2, /* 2845: struct.X509_val_st */
            	619, 0,
            	619, 8,
            1, 8, 1, /* 2852: pointer.struct.X509_pubkey_st */
            	2857, 0,
            0, 24, 3, /* 2857: struct.X509_pubkey_st */
            	467, 0,
            	433, 8,
            	2866, 16,
            1, 8, 1, /* 2866: pointer.struct.evp_pkey_st */
            	2871, 0,
            0, 56, 4, /* 2871: struct.evp_pkey_st */
            	1469, 16,
            	1477, 24,
            	2882, 32,
            	3165, 48,
            0, 8, 5, /* 2882: union.unknown */
            	93, 0,
            	2895, 0,
            	3016, 0,
            	3097, 0,
            	1806, 0,
            1, 8, 1, /* 2895: pointer.struct.rsa_st */
            	2900, 0,
            0, 168, 17, /* 2900: struct.rsa_st */
            	2937, 16,
            	1477, 24,
            	2992, 32,
            	2992, 40,
            	2992, 48,
            	2992, 56,
            	2992, 64,
            	2992, 72,
            	2992, 80,
            	2992, 88,
            	2756, 96,
            	3002, 120,
            	3002, 128,
            	3002, 136,
            	93, 144,
            	1649, 152,
            	1649, 160,
            1, 8, 1, /* 2937: pointer.struct.rsa_meth_st */
            	2942, 0,
            0, 112, 13, /* 2942: struct.rsa_meth_st */
            	124, 0,
            	2971, 8,
            	2971, 16,
            	2971, 24,
            	2971, 32,
            	2974, 40,
            	2977, 48,
            	2980, 56,
            	2980, 64,
            	93, 80,
            	2983, 88,
            	2986, 96,
            	2989, 104,
            8884097, 8, 0, /* 2971: pointer.func */
            8884097, 8, 0, /* 2974: pointer.func */
            8884097, 8, 0, /* 2977: pointer.func */
            8884097, 8, 0, /* 2980: pointer.func */
            8884097, 8, 0, /* 2983: pointer.func */
            8884097, 8, 0, /* 2986: pointer.func */
            8884097, 8, 0, /* 2989: pointer.func */
            1, 8, 1, /* 2992: pointer.struct.bignum_st */
            	2997, 0,
            0, 24, 1, /* 2997: struct.bignum_st */
            	1605, 0,
            1, 8, 1, /* 3002: pointer.struct.bn_mont_ctx_st */
            	3007, 0,
            0, 96, 3, /* 3007: struct.bn_mont_ctx_st */
            	2997, 8,
            	2997, 32,
            	2997, 56,
            1, 8, 1, /* 3016: pointer.struct.dsa_st */
            	3021, 0,
            0, 136, 11, /* 3021: struct.dsa_st */
            	2992, 24,
            	2992, 32,
            	2992, 40,
            	2992, 48,
            	2992, 56,
            	2992, 64,
            	2992, 72,
            	3002, 88,
            	2756, 104,
            	3046, 120,
            	1477, 128,
            1, 8, 1, /* 3046: pointer.struct.dsa_method */
            	3051, 0,
            0, 96, 11, /* 3051: struct.dsa_method */
            	124, 0,
            	3076, 8,
            	3079, 16,
            	3082, 24,
            	3085, 32,
            	3088, 40,
            	3091, 48,
            	3091, 56,
            	93, 72,
            	3094, 80,
            	3091, 88,
            8884097, 8, 0, /* 3076: pointer.func */
            8884097, 8, 0, /* 3079: pointer.func */
            8884097, 8, 0, /* 3082: pointer.func */
            8884097, 8, 0, /* 3085: pointer.func */
            8884097, 8, 0, /* 3088: pointer.func */
            8884097, 8, 0, /* 3091: pointer.func */
            8884097, 8, 0, /* 3094: pointer.func */
            1, 8, 1, /* 3097: pointer.struct.dh_st */
            	3102, 0,
            0, 144, 12, /* 3102: struct.dh_st */
            	2992, 8,
            	2992, 16,
            	2992, 32,
            	2992, 40,
            	3002, 56,
            	2992, 64,
            	2992, 72,
            	200, 80,
            	2992, 96,
            	2756, 112,
            	3129, 128,
            	1477, 136,
            1, 8, 1, /* 3129: pointer.struct.dh_method */
            	3134, 0,
            0, 72, 8, /* 3134: struct.dh_method */
            	124, 0,
            	3153, 8,
            	3156, 16,
            	3159, 24,
            	3153, 32,
            	3153, 40,
            	93, 56,
            	3162, 64,
            8884097, 8, 0, /* 3153: pointer.func */
            8884097, 8, 0, /* 3156: pointer.func */
            8884097, 8, 0, /* 3159: pointer.func */
            8884097, 8, 0, /* 3162: pointer.func */
            1, 8, 1, /* 3165: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3170, 0,
            0, 32, 2, /* 3170: struct.stack_st_fake_X509_ATTRIBUTE */
            	3177, 8,
            	360, 24,
            8884099, 8, 2, /* 3177: pointer_to_array_of_pointers_to_stack */
            	3184, 0,
            	357, 20,
            0, 8, 1, /* 3184: pointer.X509_ATTRIBUTE */
            	1838, 0,
            1, 8, 1, /* 3189: pointer.struct.stack_st_DIST_POINT */
            	3194, 0,
            0, 32, 2, /* 3194: struct.stack_st_fake_DIST_POINT */
            	3201, 8,
            	360, 24,
            8884099, 8, 2, /* 3201: pointer_to_array_of_pointers_to_stack */
            	3208, 0,
            	357, 20,
            0, 8, 1, /* 3208: pointer.DIST_POINT */
            	2254, 0,
            1, 8, 1, /* 3213: pointer.struct.stack_st_GENERAL_NAME */
            	3218, 0,
            0, 32, 2, /* 3218: struct.stack_st_fake_GENERAL_NAME */
            	3225, 8,
            	360, 24,
            8884099, 8, 2, /* 3225: pointer_to_array_of_pointers_to_stack */
            	3232, 0,
            	357, 20,
            0, 8, 1, /* 3232: pointer.GENERAL_NAME */
            	50, 0,
            1, 8, 1, /* 3237: pointer.struct.NAME_CONSTRAINTS_st */
            	3242, 0,
            0, 16, 2, /* 3242: struct.NAME_CONSTRAINTS_st */
            	3249, 0,
            	3249, 8,
            1, 8, 1, /* 3249: pointer.struct.stack_st_GENERAL_SUBTREE */
            	3254, 0,
            0, 32, 2, /* 3254: struct.stack_st_fake_GENERAL_SUBTREE */
            	3261, 8,
            	360, 24,
            8884099, 8, 2, /* 3261: pointer_to_array_of_pointers_to_stack */
            	3268, 0,
            	357, 20,
            0, 8, 1, /* 3268: pointer.GENERAL_SUBTREE */
            	3273, 0,
            0, 0, 1, /* 3273: GENERAL_SUBTREE */
            	3278, 0,
            0, 24, 3, /* 3278: struct.GENERAL_SUBTREE_st */
            	3287, 0,
            	3419, 8,
            	3419, 16,
            1, 8, 1, /* 3287: pointer.struct.GENERAL_NAME_st */
            	3292, 0,
            0, 16, 1, /* 3292: struct.GENERAL_NAME_st */
            	3297, 8,
            0, 8, 15, /* 3297: union.unknown */
            	93, 0,
            	3330, 0,
            	3449, 0,
            	3449, 0,
            	3356, 0,
            	3497, 0,
            	3545, 0,
            	3449, 0,
            	3434, 0,
            	3342, 0,
            	3434, 0,
            	3497, 0,
            	3449, 0,
            	3342, 0,
            	3356, 0,
            1, 8, 1, /* 3330: pointer.struct.otherName_st */
            	3335, 0,
            0, 16, 2, /* 3335: struct.otherName_st */
            	3342, 0,
            	3356, 8,
            1, 8, 1, /* 3342: pointer.struct.asn1_object_st */
            	3347, 0,
            0, 40, 3, /* 3347: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            1, 8, 1, /* 3356: pointer.struct.asn1_type_st */
            	3361, 0,
            0, 16, 1, /* 3361: struct.asn1_type_st */
            	3366, 8,
            0, 8, 20, /* 3366: union.unknown */
            	93, 0,
            	3409, 0,
            	3342, 0,
            	3419, 0,
            	3424, 0,
            	3429, 0,
            	3434, 0,
            	3439, 0,
            	3444, 0,
            	3449, 0,
            	3454, 0,
            	3459, 0,
            	3464, 0,
            	3469, 0,
            	3474, 0,
            	3479, 0,
            	3484, 0,
            	3409, 0,
            	3409, 0,
            	3489, 0,
            1, 8, 1, /* 3409: pointer.struct.asn1_string_st */
            	3414, 0,
            0, 24, 1, /* 3414: struct.asn1_string_st */
            	200, 8,
            1, 8, 1, /* 3419: pointer.struct.asn1_string_st */
            	3414, 0,
            1, 8, 1, /* 3424: pointer.struct.asn1_string_st */
            	3414, 0,
            1, 8, 1, /* 3429: pointer.struct.asn1_string_st */
            	3414, 0,
            1, 8, 1, /* 3434: pointer.struct.asn1_string_st */
            	3414, 0,
            1, 8, 1, /* 3439: pointer.struct.asn1_string_st */
            	3414, 0,
            1, 8, 1, /* 3444: pointer.struct.asn1_string_st */
            	3414, 0,
            1, 8, 1, /* 3449: pointer.struct.asn1_string_st */
            	3414, 0,
            1, 8, 1, /* 3454: pointer.struct.asn1_string_st */
            	3414, 0,
            1, 8, 1, /* 3459: pointer.struct.asn1_string_st */
            	3414, 0,
            1, 8, 1, /* 3464: pointer.struct.asn1_string_st */
            	3414, 0,
            1, 8, 1, /* 3469: pointer.struct.asn1_string_st */
            	3414, 0,
            1, 8, 1, /* 3474: pointer.struct.asn1_string_st */
            	3414, 0,
            1, 8, 1, /* 3479: pointer.struct.asn1_string_st */
            	3414, 0,
            1, 8, 1, /* 3484: pointer.struct.asn1_string_st */
            	3414, 0,
            1, 8, 1, /* 3489: pointer.struct.ASN1_VALUE_st */
            	3494, 0,
            0, 0, 0, /* 3494: struct.ASN1_VALUE_st */
            1, 8, 1, /* 3497: pointer.struct.X509_name_st */
            	3502, 0,
            0, 40, 3, /* 3502: struct.X509_name_st */
            	3511, 0,
            	3535, 16,
            	200, 24,
            1, 8, 1, /* 3511: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3516, 0,
            0, 32, 2, /* 3516: struct.stack_st_fake_X509_NAME_ENTRY */
            	3523, 8,
            	360, 24,
            8884099, 8, 2, /* 3523: pointer_to_array_of_pointers_to_stack */
            	3530, 0,
            	357, 20,
            0, 8, 1, /* 3530: pointer.X509_NAME_ENTRY */
            	321, 0,
            1, 8, 1, /* 3535: pointer.struct.buf_mem_st */
            	3540, 0,
            0, 24, 1, /* 3540: struct.buf_mem_st */
            	93, 8,
            1, 8, 1, /* 3545: pointer.struct.EDIPartyName_st */
            	3550, 0,
            0, 16, 2, /* 3550: struct.EDIPartyName_st */
            	3409, 0,
            	3409, 8,
            1, 8, 1, /* 3557: pointer.struct.x509_cert_aux_st */
            	3562, 0,
            0, 40, 5, /* 3562: struct.x509_cert_aux_st */
            	2705, 0,
            	2705, 8,
            	606, 16,
            	556, 24,
            	3575, 32,
            1, 8, 1, /* 3575: pointer.struct.stack_st_X509_ALGOR */
            	3580, 0,
            0, 32, 2, /* 3580: struct.stack_st_fake_X509_ALGOR */
            	3587, 8,
            	360, 24,
            8884099, 8, 2, /* 3587: pointer_to_array_of_pointers_to_stack */
            	3594, 0,
            	357, 20,
            0, 8, 1, /* 3594: pointer.X509_ALGOR */
            	2380, 0,
            1, 8, 1, /* 3599: pointer.struct.stack_st_X509 */
            	3604, 0,
            0, 32, 2, /* 3604: struct.stack_st_fake_X509 */
            	3611, 8,
            	360, 24,
            8884099, 8, 2, /* 3611: pointer_to_array_of_pointers_to_stack */
            	3618, 0,
            	357, 20,
            0, 8, 1, /* 3618: pointer.X509 */
            	3623, 0,
            0, 0, 1, /* 3623: X509 */
            	3628, 0,
            0, 184, 12, /* 3628: struct.x509_st */
            	3655, 0,
            	3690, 8,
            	3779, 16,
            	93, 32,
            	4073, 40,
            	3784, 104,
            	4327, 112,
            	4335, 120,
            	4343, 128,
            	4367, 136,
            	4391, 144,
            	4399, 176,
            1, 8, 1, /* 3655: pointer.struct.x509_cinf_st */
            	3660, 0,
            0, 104, 11, /* 3660: struct.x509_cinf_st */
            	3685, 0,
            	3685, 8,
            	3690, 16,
            	3842, 24,
            	3890, 32,
            	3842, 40,
            	3907, 48,
            	3779, 56,
            	3779, 64,
            	4298, 72,
            	4322, 80,
            1, 8, 1, /* 3685: pointer.struct.asn1_string_st */
            	1012, 0,
            1, 8, 1, /* 3690: pointer.struct.X509_algor_st */
            	3695, 0,
            0, 16, 2, /* 3695: struct.X509_algor_st */
            	3702, 0,
            	3716, 8,
            1, 8, 1, /* 3702: pointer.struct.asn1_object_st */
            	3707, 0,
            0, 40, 3, /* 3707: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            1, 8, 1, /* 3716: pointer.struct.asn1_type_st */
            	3721, 0,
            0, 16, 1, /* 3721: struct.asn1_type_st */
            	3726, 8,
            0, 8, 20, /* 3726: union.unknown */
            	93, 0,
            	3769, 0,
            	3702, 0,
            	3685, 0,
            	3774, 0,
            	3779, 0,
            	3784, 0,
            	3789, 0,
            	3794, 0,
            	3799, 0,
            	3804, 0,
            	1007, 0,
            	3809, 0,
            	3814, 0,
            	3819, 0,
            	3824, 0,
            	3829, 0,
            	3769, 0,
            	3769, 0,
            	3834, 0,
            1, 8, 1, /* 3769: pointer.struct.asn1_string_st */
            	1012, 0,
            1, 8, 1, /* 3774: pointer.struct.asn1_string_st */
            	1012, 0,
            1, 8, 1, /* 3779: pointer.struct.asn1_string_st */
            	1012, 0,
            1, 8, 1, /* 3784: pointer.struct.asn1_string_st */
            	1012, 0,
            1, 8, 1, /* 3789: pointer.struct.asn1_string_st */
            	1012, 0,
            1, 8, 1, /* 3794: pointer.struct.asn1_string_st */
            	1012, 0,
            1, 8, 1, /* 3799: pointer.struct.asn1_string_st */
            	1012, 0,
            1, 8, 1, /* 3804: pointer.struct.asn1_string_st */
            	1012, 0,
            1, 8, 1, /* 3809: pointer.struct.asn1_string_st */
            	1012, 0,
            1, 8, 1, /* 3814: pointer.struct.asn1_string_st */
            	1012, 0,
            1, 8, 1, /* 3819: pointer.struct.asn1_string_st */
            	1012, 0,
            1, 8, 1, /* 3824: pointer.struct.asn1_string_st */
            	1012, 0,
            1, 8, 1, /* 3829: pointer.struct.asn1_string_st */
            	1012, 0,
            1, 8, 1, /* 3834: pointer.struct.ASN1_VALUE_st */
            	3839, 0,
            0, 0, 0, /* 3839: struct.ASN1_VALUE_st */
            1, 8, 1, /* 3842: pointer.struct.X509_name_st */
            	3847, 0,
            0, 40, 3, /* 3847: struct.X509_name_st */
            	3856, 0,
            	3880, 16,
            	200, 24,
            1, 8, 1, /* 3856: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3861, 0,
            0, 32, 2, /* 3861: struct.stack_st_fake_X509_NAME_ENTRY */
            	3868, 8,
            	360, 24,
            8884099, 8, 2, /* 3868: pointer_to_array_of_pointers_to_stack */
            	3875, 0,
            	357, 20,
            0, 8, 1, /* 3875: pointer.X509_NAME_ENTRY */
            	321, 0,
            1, 8, 1, /* 3880: pointer.struct.buf_mem_st */
            	3885, 0,
            0, 24, 1, /* 3885: struct.buf_mem_st */
            	93, 8,
            1, 8, 1, /* 3890: pointer.struct.X509_val_st */
            	3895, 0,
            0, 16, 2, /* 3895: struct.X509_val_st */
            	3902, 0,
            	3902, 8,
            1, 8, 1, /* 3902: pointer.struct.asn1_string_st */
            	1012, 0,
            1, 8, 1, /* 3907: pointer.struct.X509_pubkey_st */
            	3912, 0,
            0, 24, 3, /* 3912: struct.X509_pubkey_st */
            	3690, 0,
            	3779, 8,
            	3921, 16,
            1, 8, 1, /* 3921: pointer.struct.evp_pkey_st */
            	3926, 0,
            0, 56, 4, /* 3926: struct.evp_pkey_st */
            	3937, 16,
            	3945, 24,
            	3953, 32,
            	4274, 48,
            1, 8, 1, /* 3937: pointer.struct.evp_pkey_asn1_method_st */
            	3942, 0,
            0, 0, 0, /* 3942: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 3945: pointer.struct.engine_st */
            	3950, 0,
            0, 0, 0, /* 3950: struct.engine_st */
            0, 8, 5, /* 3953: union.unknown */
            	93, 0,
            	3966, 0,
            	4117, 0,
            	4198, 0,
            	4266, 0,
            1, 8, 1, /* 3966: pointer.struct.rsa_st */
            	3971, 0,
            0, 168, 17, /* 3971: struct.rsa_st */
            	4008, 16,
            	3945, 24,
            	4063, 32,
            	4063, 40,
            	4063, 48,
            	4063, 56,
            	4063, 64,
            	4063, 72,
            	4063, 80,
            	4063, 88,
            	4073, 96,
            	4095, 120,
            	4095, 128,
            	4095, 136,
            	93, 144,
            	4109, 152,
            	4109, 160,
            1, 8, 1, /* 4008: pointer.struct.rsa_meth_st */
            	4013, 0,
            0, 112, 13, /* 4013: struct.rsa_meth_st */
            	124, 0,
            	4042, 8,
            	4042, 16,
            	4042, 24,
            	4042, 32,
            	4045, 40,
            	4048, 48,
            	4051, 56,
            	4051, 64,
            	93, 80,
            	4054, 88,
            	4057, 96,
            	4060, 104,
            8884097, 8, 0, /* 4042: pointer.func */
            8884097, 8, 0, /* 4045: pointer.func */
            8884097, 8, 0, /* 4048: pointer.func */
            8884097, 8, 0, /* 4051: pointer.func */
            8884097, 8, 0, /* 4054: pointer.func */
            8884097, 8, 0, /* 4057: pointer.func */
            8884097, 8, 0, /* 4060: pointer.func */
            1, 8, 1, /* 4063: pointer.struct.bignum_st */
            	4068, 0,
            0, 24, 1, /* 4068: struct.bignum_st */
            	1605, 0,
            0, 16, 1, /* 4073: struct.crypto_ex_data_st */
            	4078, 0,
            1, 8, 1, /* 4078: pointer.struct.stack_st_void */
            	4083, 0,
            0, 32, 1, /* 4083: struct.stack_st_void */
            	4088, 0,
            0, 32, 2, /* 4088: struct.stack_st */
            	885, 8,
            	360, 24,
            1, 8, 1, /* 4095: pointer.struct.bn_mont_ctx_st */
            	4100, 0,
            0, 96, 3, /* 4100: struct.bn_mont_ctx_st */
            	4068, 8,
            	4068, 32,
            	4068, 56,
            1, 8, 1, /* 4109: pointer.struct.bn_blinding_st */
            	4114, 0,
            0, 0, 0, /* 4114: struct.bn_blinding_st */
            1, 8, 1, /* 4117: pointer.struct.dsa_st */
            	4122, 0,
            0, 136, 11, /* 4122: struct.dsa_st */
            	4063, 24,
            	4063, 32,
            	4063, 40,
            	4063, 48,
            	4063, 56,
            	4063, 64,
            	4063, 72,
            	4095, 88,
            	4073, 104,
            	4147, 120,
            	3945, 128,
            1, 8, 1, /* 4147: pointer.struct.dsa_method */
            	4152, 0,
            0, 96, 11, /* 4152: struct.dsa_method */
            	124, 0,
            	4177, 8,
            	4180, 16,
            	4183, 24,
            	4186, 32,
            	4189, 40,
            	4192, 48,
            	4192, 56,
            	93, 72,
            	4195, 80,
            	4192, 88,
            8884097, 8, 0, /* 4177: pointer.func */
            8884097, 8, 0, /* 4180: pointer.func */
            8884097, 8, 0, /* 4183: pointer.func */
            8884097, 8, 0, /* 4186: pointer.func */
            8884097, 8, 0, /* 4189: pointer.func */
            8884097, 8, 0, /* 4192: pointer.func */
            8884097, 8, 0, /* 4195: pointer.func */
            1, 8, 1, /* 4198: pointer.struct.dh_st */
            	4203, 0,
            0, 144, 12, /* 4203: struct.dh_st */
            	4063, 8,
            	4063, 16,
            	4063, 32,
            	4063, 40,
            	4095, 56,
            	4063, 64,
            	4063, 72,
            	200, 80,
            	4063, 96,
            	4073, 112,
            	4230, 128,
            	3945, 136,
            1, 8, 1, /* 4230: pointer.struct.dh_method */
            	4235, 0,
            0, 72, 8, /* 4235: struct.dh_method */
            	124, 0,
            	4254, 8,
            	4257, 16,
            	4260, 24,
            	4254, 32,
            	4254, 40,
            	93, 56,
            	4263, 64,
            8884097, 8, 0, /* 4254: pointer.func */
            8884097, 8, 0, /* 4257: pointer.func */
            8884097, 8, 0, /* 4260: pointer.func */
            8884097, 8, 0, /* 4263: pointer.func */
            1, 8, 1, /* 4266: pointer.struct.ec_key_st */
            	4271, 0,
            0, 0, 0, /* 4271: struct.ec_key_st */
            1, 8, 1, /* 4274: pointer.struct.stack_st_X509_ATTRIBUTE */
            	4279, 0,
            0, 32, 2, /* 4279: struct.stack_st_fake_X509_ATTRIBUTE */
            	4286, 8,
            	360, 24,
            8884099, 8, 2, /* 4286: pointer_to_array_of_pointers_to_stack */
            	4293, 0,
            	357, 20,
            0, 8, 1, /* 4293: pointer.X509_ATTRIBUTE */
            	1838, 0,
            1, 8, 1, /* 4298: pointer.struct.stack_st_X509_EXTENSION */
            	4303, 0,
            0, 32, 2, /* 4303: struct.stack_st_fake_X509_EXTENSION */
            	4310, 8,
            	360, 24,
            8884099, 8, 2, /* 4310: pointer_to_array_of_pointers_to_stack */
            	4317, 0,
            	357, 20,
            0, 8, 1, /* 4317: pointer.X509_EXTENSION */
            	703, 0,
            0, 24, 1, /* 4322: struct.ASN1_ENCODING_st */
            	200, 0,
            1, 8, 1, /* 4327: pointer.struct.AUTHORITY_KEYID_st */
            	4332, 0,
            0, 0, 0, /* 4332: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 4335: pointer.struct.X509_POLICY_CACHE_st */
            	4340, 0,
            0, 0, 0, /* 4340: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 4343: pointer.struct.stack_st_DIST_POINT */
            	4348, 0,
            0, 32, 2, /* 4348: struct.stack_st_fake_DIST_POINT */
            	4355, 8,
            	360, 24,
            8884099, 8, 2, /* 4355: pointer_to_array_of_pointers_to_stack */
            	4362, 0,
            	357, 20,
            0, 8, 1, /* 4362: pointer.DIST_POINT */
            	2254, 0,
            1, 8, 1, /* 4367: pointer.struct.stack_st_GENERAL_NAME */
            	4372, 0,
            0, 32, 2, /* 4372: struct.stack_st_fake_GENERAL_NAME */
            	4379, 8,
            	360, 24,
            8884099, 8, 2, /* 4379: pointer_to_array_of_pointers_to_stack */
            	4386, 0,
            	357, 20,
            0, 8, 1, /* 4386: pointer.GENERAL_NAME */
            	50, 0,
            1, 8, 1, /* 4391: pointer.struct.NAME_CONSTRAINTS_st */
            	4396, 0,
            0, 0, 0, /* 4396: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 4399: pointer.struct.x509_cert_aux_st */
            	4404, 0,
            0, 40, 5, /* 4404: struct.x509_cert_aux_st */
            	4417, 0,
            	4417, 8,
            	3829, 16,
            	3784, 24,
            	4441, 32,
            1, 8, 1, /* 4417: pointer.struct.stack_st_ASN1_OBJECT */
            	4422, 0,
            0, 32, 2, /* 4422: struct.stack_st_fake_ASN1_OBJECT */
            	4429, 8,
            	360, 24,
            8884099, 8, 2, /* 4429: pointer_to_array_of_pointers_to_stack */
            	4436, 0,
            	357, 20,
            0, 8, 1, /* 4436: pointer.ASN1_OBJECT */
            	2342, 0,
            1, 8, 1, /* 4441: pointer.struct.stack_st_X509_ALGOR */
            	4446, 0,
            0, 32, 2, /* 4446: struct.stack_st_fake_X509_ALGOR */
            	4453, 8,
            	360, 24,
            8884099, 8, 2, /* 4453: pointer_to_array_of_pointers_to_stack */
            	4460, 0,
            	357, 20,
            0, 8, 1, /* 4460: pointer.X509_ALGOR */
            	2380, 0,
            1, 8, 1, /* 4465: pointer.struct.stack_st_X509_CRL */
            	4470, 0,
            0, 32, 2, /* 4470: struct.stack_st_fake_X509_CRL */
            	4477, 8,
            	360, 24,
            8884099, 8, 2, /* 4477: pointer_to_array_of_pointers_to_stack */
            	4484, 0,
            	357, 20,
            0, 8, 1, /* 4484: pointer.X509_CRL */
            	4489, 0,
            0, 0, 1, /* 4489: X509_CRL */
            	4494, 0,
            0, 120, 10, /* 4494: struct.X509_crl_st */
            	4517, 0,
            	4546, 8,
            	4635, 16,
            	2214, 32,
            	2473, 40,
            	4541, 56,
            	4541, 64,
            	844, 96,
            	890, 104,
            	898, 112,
            1, 8, 1, /* 4517: pointer.struct.X509_crl_info_st */
            	4522, 0,
            0, 80, 8, /* 4522: struct.X509_crl_info_st */
            	4541, 0,
            	4546, 8,
            	4665, 16,
            	4679, 24,
            	4679, 32,
            	4684, 40,
            	914, 48,
            	909, 56,
            1, 8, 1, /* 4541: pointer.struct.asn1_string_st */
            	977, 0,
            1, 8, 1, /* 4546: pointer.struct.X509_algor_st */
            	4551, 0,
            0, 16, 2, /* 4551: struct.X509_algor_st */
            	4558, 0,
            	4572, 8,
            1, 8, 1, /* 4558: pointer.struct.asn1_object_st */
            	4563, 0,
            0, 40, 3, /* 4563: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            1, 8, 1, /* 4572: pointer.struct.asn1_type_st */
            	4577, 0,
            0, 16, 1, /* 4577: struct.asn1_type_st */
            	4582, 8,
            0, 8, 20, /* 4582: union.unknown */
            	93, 0,
            	4625, 0,
            	4558, 0,
            	4541, 0,
            	4630, 0,
            	4635, 0,
            	4640, 0,
            	4645, 0,
            	4650, 0,
            	1002, 0,
            	997, 0,
            	992, 0,
            	987, 0,
            	4655, 0,
            	982, 0,
            	4660, 0,
            	972, 0,
            	4625, 0,
            	4625, 0,
            	611, 0,
            1, 8, 1, /* 4625: pointer.struct.asn1_string_st */
            	977, 0,
            1, 8, 1, /* 4630: pointer.struct.asn1_string_st */
            	977, 0,
            1, 8, 1, /* 4635: pointer.struct.asn1_string_st */
            	977, 0,
            1, 8, 1, /* 4640: pointer.struct.asn1_string_st */
            	977, 0,
            1, 8, 1, /* 4645: pointer.struct.asn1_string_st */
            	977, 0,
            1, 8, 1, /* 4650: pointer.struct.asn1_string_st */
            	977, 0,
            1, 8, 1, /* 4655: pointer.struct.asn1_string_st */
            	977, 0,
            1, 8, 1, /* 4660: pointer.struct.asn1_string_st */
            	977, 0,
            1, 8, 1, /* 4665: pointer.struct.X509_name_st */
            	4670, 0,
            0, 40, 3, /* 4670: struct.X509_name_st */
            	948, 0,
            	938, 16,
            	200, 24,
            1, 8, 1, /* 4679: pointer.struct.asn1_string_st */
            	977, 0,
            1, 8, 1, /* 4684: pointer.struct.stack_st_X509_REVOKED */
            	4689, 0,
            0, 32, 2, /* 4689: struct.stack_st_fake_X509_REVOKED */
            	4696, 8,
            	360, 24,
            8884099, 8, 2, /* 4696: pointer_to_array_of_pointers_to_stack */
            	4703, 0,
            	357, 20,
            0, 8, 1, /* 4703: pointer.X509_REVOKED */
            	648, 0,
            1, 8, 1, /* 4708: pointer.struct.x509_store_ctx_st */
            	1017, 0,
            0, 1, 0, /* 4713: char */
        },
        .arg_entity_index = { 4708, 1070, 2778, 3599, },
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

