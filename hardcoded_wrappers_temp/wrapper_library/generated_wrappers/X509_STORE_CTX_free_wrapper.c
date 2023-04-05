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
            1, 8, 1, /* 1007: pointer.struct.x509_store_ctx_st */
            	1012, 0,
            0, 248, 25, /* 1012: struct.x509_store_ctx_st */
            	1065, 0,
            	2773, 16,
            	3594, 24,
            	4470, 32,
            	2688, 40,
            	898, 48,
            	2724, 56,
            	2727, 64,
            	2730, 72,
            	2733, 80,
            	2724, 88,
            	2736, 96,
            	2739, 104,
            	2742, 112,
            	2724, 120,
            	2745, 128,
            	2748, 136,
            	2724, 144,
            	3594, 160,
            	904, 168,
            	2773, 192,
            	2773, 200,
            	792, 208,
            	1007, 224,
            	2751, 232,
            1, 8, 1, /* 1065: pointer.struct.x509_store_st */
            	1070, 0,
            0, 144, 15, /* 1070: struct.x509_store_st */
            	1103, 8,
            	2476, 16,
            	2688, 24,
            	2724, 32,
            	2727, 40,
            	2730, 48,
            	2733, 56,
            	2724, 64,
            	2736, 72,
            	2739, 80,
            	2742, 88,
            	2745, 96,
            	2748, 104,
            	2724, 112,
            	2751, 120,
            1, 8, 1, /* 1103: pointer.struct.stack_st_X509_OBJECT */
            	1108, 0,
            0, 32, 2, /* 1108: struct.stack_st_fake_X509_OBJECT */
            	1115, 8,
            	360, 24,
            8884099, 8, 2, /* 1115: pointer_to_array_of_pointers_to_stack */
            	1122, 0,
            	357, 20,
            0, 8, 1, /* 1122: pointer.X509_OBJECT */
            	1127, 0,
            0, 0, 1, /* 1127: X509_OBJECT */
            	1132, 0,
            0, 16, 1, /* 1132: struct.x509_object_st */
            	1137, 8,
            0, 8, 4, /* 1137: union.unknown */
            	93, 0,
            	1148, 0,
            	2392, 0,
            	1448, 0,
            1, 8, 1, /* 1148: pointer.struct.x509_st */
            	1153, 0,
            0, 184, 12, /* 1153: struct.x509_st */
            	1180, 0,
            	1220, 8,
            	1309, 16,
            	93, 32,
            	1608, 40,
            	1314, 104,
            	2209, 112,
            	2217, 120,
            	2225, 128,
            	2263, 136,
            	2287, 144,
            	2295, 176,
            1, 8, 1, /* 1180: pointer.struct.x509_cinf_st */
            	1185, 0,
            0, 104, 11, /* 1185: struct.x509_cinf_st */
            	1210, 0,
            	1210, 8,
            	1220, 16,
            	1369, 24,
            	1417, 32,
            	1369, 40,
            	1434, 48,
            	1309, 56,
            	1309, 64,
            	2180, 72,
            	2204, 80,
            1, 8, 1, /* 1210: pointer.struct.asn1_string_st */
            	1215, 0,
            0, 24, 1, /* 1215: struct.asn1_string_st */
            	200, 8,
            1, 8, 1, /* 1220: pointer.struct.X509_algor_st */
            	1225, 0,
            0, 16, 2, /* 1225: struct.X509_algor_st */
            	1232, 0,
            	1246, 8,
            1, 8, 1, /* 1232: pointer.struct.asn1_object_st */
            	1237, 0,
            0, 40, 3, /* 1237: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            1, 8, 1, /* 1246: pointer.struct.asn1_type_st */
            	1251, 0,
            0, 16, 1, /* 1251: struct.asn1_type_st */
            	1256, 8,
            0, 8, 20, /* 1256: union.unknown */
            	93, 0,
            	1299, 0,
            	1232, 0,
            	1210, 0,
            	1304, 0,
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
            	1299, 0,
            	1299, 0,
            	611, 0,
            1, 8, 1, /* 1299: pointer.struct.asn1_string_st */
            	1215, 0,
            1, 8, 1, /* 1304: pointer.struct.asn1_string_st */
            	1215, 0,
            1, 8, 1, /* 1309: pointer.struct.asn1_string_st */
            	1215, 0,
            1, 8, 1, /* 1314: pointer.struct.asn1_string_st */
            	1215, 0,
            1, 8, 1, /* 1319: pointer.struct.asn1_string_st */
            	1215, 0,
            1, 8, 1, /* 1324: pointer.struct.asn1_string_st */
            	1215, 0,
            1, 8, 1, /* 1329: pointer.struct.asn1_string_st */
            	1215, 0,
            1, 8, 1, /* 1334: pointer.struct.asn1_string_st */
            	1215, 0,
            1, 8, 1, /* 1339: pointer.struct.asn1_string_st */
            	1215, 0,
            1, 8, 1, /* 1344: pointer.struct.asn1_string_st */
            	1215, 0,
            1, 8, 1, /* 1349: pointer.struct.asn1_string_st */
            	1215, 0,
            1, 8, 1, /* 1354: pointer.struct.asn1_string_st */
            	1215, 0,
            1, 8, 1, /* 1359: pointer.struct.asn1_string_st */
            	1215, 0,
            1, 8, 1, /* 1364: pointer.struct.asn1_string_st */
            	1215, 0,
            1, 8, 1, /* 1369: pointer.struct.X509_name_st */
            	1374, 0,
            0, 40, 3, /* 1374: struct.X509_name_st */
            	1383, 0,
            	1407, 16,
            	200, 24,
            1, 8, 1, /* 1383: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1388, 0,
            0, 32, 2, /* 1388: struct.stack_st_fake_X509_NAME_ENTRY */
            	1395, 8,
            	360, 24,
            8884099, 8, 2, /* 1395: pointer_to_array_of_pointers_to_stack */
            	1402, 0,
            	357, 20,
            0, 8, 1, /* 1402: pointer.X509_NAME_ENTRY */
            	321, 0,
            1, 8, 1, /* 1407: pointer.struct.buf_mem_st */
            	1412, 0,
            0, 24, 1, /* 1412: struct.buf_mem_st */
            	93, 8,
            1, 8, 1, /* 1417: pointer.struct.X509_val_st */
            	1422, 0,
            0, 16, 2, /* 1422: struct.X509_val_st */
            	1429, 0,
            	1429, 8,
            1, 8, 1, /* 1429: pointer.struct.asn1_string_st */
            	1215, 0,
            1, 8, 1, /* 1434: pointer.struct.X509_pubkey_st */
            	1439, 0,
            0, 24, 3, /* 1439: struct.X509_pubkey_st */
            	1220, 0,
            	1309, 8,
            	1448, 16,
            1, 8, 1, /* 1448: pointer.struct.evp_pkey_st */
            	1453, 0,
            0, 56, 4, /* 1453: struct.evp_pkey_st */
            	1464, 16,
            	1472, 24,
            	1480, 32,
            	1809, 48,
            1, 8, 1, /* 1464: pointer.struct.evp_pkey_asn1_method_st */
            	1469, 0,
            0, 0, 0, /* 1469: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 1472: pointer.struct.engine_st */
            	1477, 0,
            0, 0, 0, /* 1477: struct.engine_st */
            0, 8, 5, /* 1480: union.unknown */
            	93, 0,
            	1493, 0,
            	1652, 0,
            	1733, 0,
            	1801, 0,
            1, 8, 1, /* 1493: pointer.struct.rsa_st */
            	1498, 0,
            0, 168, 17, /* 1498: struct.rsa_st */
            	1535, 16,
            	1472, 24,
            	1590, 32,
            	1590, 40,
            	1590, 48,
            	1590, 56,
            	1590, 64,
            	1590, 72,
            	1590, 80,
            	1590, 88,
            	1608, 96,
            	1630, 120,
            	1630, 128,
            	1630, 136,
            	93, 144,
            	1644, 152,
            	1644, 160,
            1, 8, 1, /* 1535: pointer.struct.rsa_meth_st */
            	1540, 0,
            0, 112, 13, /* 1540: struct.rsa_meth_st */
            	124, 0,
            	1569, 8,
            	1569, 16,
            	1569, 24,
            	1569, 32,
            	1572, 40,
            	1575, 48,
            	1578, 56,
            	1578, 64,
            	93, 80,
            	1581, 88,
            	1584, 96,
            	1587, 104,
            8884097, 8, 0, /* 1569: pointer.func */
            8884097, 8, 0, /* 1572: pointer.func */
            8884097, 8, 0, /* 1575: pointer.func */
            8884097, 8, 0, /* 1578: pointer.func */
            8884097, 8, 0, /* 1581: pointer.func */
            8884097, 8, 0, /* 1584: pointer.func */
            8884097, 8, 0, /* 1587: pointer.func */
            1, 8, 1, /* 1590: pointer.struct.bignum_st */
            	1595, 0,
            0, 24, 1, /* 1595: struct.bignum_st */
            	1600, 0,
            1, 8, 1, /* 1600: pointer.unsigned int */
            	1605, 0,
            0, 4, 0, /* 1605: unsigned int */
            0, 16, 1, /* 1608: struct.crypto_ex_data_st */
            	1613, 0,
            1, 8, 1, /* 1613: pointer.struct.stack_st_void */
            	1618, 0,
            0, 32, 1, /* 1618: struct.stack_st_void */
            	1623, 0,
            0, 32, 2, /* 1623: struct.stack_st */
            	885, 8,
            	360, 24,
            1, 8, 1, /* 1630: pointer.struct.bn_mont_ctx_st */
            	1635, 0,
            0, 96, 3, /* 1635: struct.bn_mont_ctx_st */
            	1595, 8,
            	1595, 32,
            	1595, 56,
            1, 8, 1, /* 1644: pointer.struct.bn_blinding_st */
            	1649, 0,
            0, 0, 0, /* 1649: struct.bn_blinding_st */
            1, 8, 1, /* 1652: pointer.struct.dsa_st */
            	1657, 0,
            0, 136, 11, /* 1657: struct.dsa_st */
            	1590, 24,
            	1590, 32,
            	1590, 40,
            	1590, 48,
            	1590, 56,
            	1590, 64,
            	1590, 72,
            	1630, 88,
            	1608, 104,
            	1682, 120,
            	1472, 128,
            1, 8, 1, /* 1682: pointer.struct.dsa_method */
            	1687, 0,
            0, 96, 11, /* 1687: struct.dsa_method */
            	124, 0,
            	1712, 8,
            	1715, 16,
            	1718, 24,
            	1721, 32,
            	1724, 40,
            	1727, 48,
            	1727, 56,
            	93, 72,
            	1730, 80,
            	1727, 88,
            8884097, 8, 0, /* 1712: pointer.func */
            8884097, 8, 0, /* 1715: pointer.func */
            8884097, 8, 0, /* 1718: pointer.func */
            8884097, 8, 0, /* 1721: pointer.func */
            8884097, 8, 0, /* 1724: pointer.func */
            8884097, 8, 0, /* 1727: pointer.func */
            8884097, 8, 0, /* 1730: pointer.func */
            1, 8, 1, /* 1733: pointer.struct.dh_st */
            	1738, 0,
            0, 144, 12, /* 1738: struct.dh_st */
            	1590, 8,
            	1590, 16,
            	1590, 32,
            	1590, 40,
            	1630, 56,
            	1590, 64,
            	1590, 72,
            	200, 80,
            	1590, 96,
            	1608, 112,
            	1765, 128,
            	1472, 136,
            1, 8, 1, /* 1765: pointer.struct.dh_method */
            	1770, 0,
            0, 72, 8, /* 1770: struct.dh_method */
            	124, 0,
            	1789, 8,
            	1792, 16,
            	1795, 24,
            	1789, 32,
            	1789, 40,
            	93, 56,
            	1798, 64,
            8884097, 8, 0, /* 1789: pointer.func */
            8884097, 8, 0, /* 1792: pointer.func */
            8884097, 8, 0, /* 1795: pointer.func */
            8884097, 8, 0, /* 1798: pointer.func */
            1, 8, 1, /* 1801: pointer.struct.ec_key_st */
            	1806, 0,
            0, 0, 0, /* 1806: struct.ec_key_st */
            1, 8, 1, /* 1809: pointer.struct.stack_st_X509_ATTRIBUTE */
            	1814, 0,
            0, 32, 2, /* 1814: struct.stack_st_fake_X509_ATTRIBUTE */
            	1821, 8,
            	360, 24,
            8884099, 8, 2, /* 1821: pointer_to_array_of_pointers_to_stack */
            	1828, 0,
            	357, 20,
            0, 8, 1, /* 1828: pointer.X509_ATTRIBUTE */
            	1833, 0,
            0, 0, 1, /* 1833: X509_ATTRIBUTE */
            	1838, 0,
            0, 24, 2, /* 1838: struct.x509_attributes_st */
            	1845, 0,
            	1859, 16,
            1, 8, 1, /* 1845: pointer.struct.asn1_object_st */
            	1850, 0,
            0, 40, 3, /* 1850: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            0, 8, 3, /* 1859: union.unknown */
            	93, 0,
            	1868, 0,
            	2047, 0,
            1, 8, 1, /* 1868: pointer.struct.stack_st_ASN1_TYPE */
            	1873, 0,
            0, 32, 2, /* 1873: struct.stack_st_fake_ASN1_TYPE */
            	1880, 8,
            	360, 24,
            8884099, 8, 2, /* 1880: pointer_to_array_of_pointers_to_stack */
            	1887, 0,
            	357, 20,
            0, 8, 1, /* 1887: pointer.ASN1_TYPE */
            	1892, 0,
            0, 0, 1, /* 1892: ASN1_TYPE */
            	1897, 0,
            0, 16, 1, /* 1897: struct.asn1_type_st */
            	1902, 8,
            0, 8, 20, /* 1902: union.unknown */
            	93, 0,
            	1945, 0,
            	1955, 0,
            	1969, 0,
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
            	1945, 0,
            	1945, 0,
            	2039, 0,
            1, 8, 1, /* 1945: pointer.struct.asn1_string_st */
            	1950, 0,
            0, 24, 1, /* 1950: struct.asn1_string_st */
            	200, 8,
            1, 8, 1, /* 1955: pointer.struct.asn1_object_st */
            	1960, 0,
            0, 40, 3, /* 1960: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            1, 8, 1, /* 1969: pointer.struct.asn1_string_st */
            	1950, 0,
            1, 8, 1, /* 1974: pointer.struct.asn1_string_st */
            	1950, 0,
            1, 8, 1, /* 1979: pointer.struct.asn1_string_st */
            	1950, 0,
            1, 8, 1, /* 1984: pointer.struct.asn1_string_st */
            	1950, 0,
            1, 8, 1, /* 1989: pointer.struct.asn1_string_st */
            	1950, 0,
            1, 8, 1, /* 1994: pointer.struct.asn1_string_st */
            	1950, 0,
            1, 8, 1, /* 1999: pointer.struct.asn1_string_st */
            	1950, 0,
            1, 8, 1, /* 2004: pointer.struct.asn1_string_st */
            	1950, 0,
            1, 8, 1, /* 2009: pointer.struct.asn1_string_st */
            	1950, 0,
            1, 8, 1, /* 2014: pointer.struct.asn1_string_st */
            	1950, 0,
            1, 8, 1, /* 2019: pointer.struct.asn1_string_st */
            	1950, 0,
            1, 8, 1, /* 2024: pointer.struct.asn1_string_st */
            	1950, 0,
            1, 8, 1, /* 2029: pointer.struct.asn1_string_st */
            	1950, 0,
            1, 8, 1, /* 2034: pointer.struct.asn1_string_st */
            	1950, 0,
            1, 8, 1, /* 2039: pointer.struct.ASN1_VALUE_st */
            	2044, 0,
            0, 0, 0, /* 2044: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2047: pointer.struct.asn1_type_st */
            	2052, 0,
            0, 16, 1, /* 2052: struct.asn1_type_st */
            	2057, 8,
            0, 8, 20, /* 2057: union.unknown */
            	93, 0,
            	2100, 0,
            	1845, 0,
            	2110, 0,
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
            	2100, 0,
            	2100, 0,
            	611, 0,
            1, 8, 1, /* 2100: pointer.struct.asn1_string_st */
            	2105, 0,
            0, 24, 1, /* 2105: struct.asn1_string_st */
            	200, 8,
            1, 8, 1, /* 2110: pointer.struct.asn1_string_st */
            	2105, 0,
            1, 8, 1, /* 2115: pointer.struct.asn1_string_st */
            	2105, 0,
            1, 8, 1, /* 2120: pointer.struct.asn1_string_st */
            	2105, 0,
            1, 8, 1, /* 2125: pointer.struct.asn1_string_st */
            	2105, 0,
            1, 8, 1, /* 2130: pointer.struct.asn1_string_st */
            	2105, 0,
            1, 8, 1, /* 2135: pointer.struct.asn1_string_st */
            	2105, 0,
            1, 8, 1, /* 2140: pointer.struct.asn1_string_st */
            	2105, 0,
            1, 8, 1, /* 2145: pointer.struct.asn1_string_st */
            	2105, 0,
            1, 8, 1, /* 2150: pointer.struct.asn1_string_st */
            	2105, 0,
            1, 8, 1, /* 2155: pointer.struct.asn1_string_st */
            	2105, 0,
            1, 8, 1, /* 2160: pointer.struct.asn1_string_st */
            	2105, 0,
            1, 8, 1, /* 2165: pointer.struct.asn1_string_st */
            	2105, 0,
            1, 8, 1, /* 2170: pointer.struct.asn1_string_st */
            	2105, 0,
            1, 8, 1, /* 2175: pointer.struct.asn1_string_st */
            	2105, 0,
            1, 8, 1, /* 2180: pointer.struct.stack_st_X509_EXTENSION */
            	2185, 0,
            0, 32, 2, /* 2185: struct.stack_st_fake_X509_EXTENSION */
            	2192, 8,
            	360, 24,
            8884099, 8, 2, /* 2192: pointer_to_array_of_pointers_to_stack */
            	2199, 0,
            	357, 20,
            0, 8, 1, /* 2199: pointer.X509_EXTENSION */
            	703, 0,
            0, 24, 1, /* 2204: struct.ASN1_ENCODING_st */
            	200, 0,
            1, 8, 1, /* 2209: pointer.struct.AUTHORITY_KEYID_st */
            	2214, 0,
            0, 0, 0, /* 2214: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 2217: pointer.struct.X509_POLICY_CACHE_st */
            	2222, 0,
            0, 0, 0, /* 2222: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 2225: pointer.struct.stack_st_DIST_POINT */
            	2230, 0,
            0, 32, 2, /* 2230: struct.stack_st_fake_DIST_POINT */
            	2237, 8,
            	360, 24,
            8884099, 8, 2, /* 2237: pointer_to_array_of_pointers_to_stack */
            	2244, 0,
            	357, 20,
            0, 8, 1, /* 2244: pointer.DIST_POINT */
            	2249, 0,
            0, 0, 1, /* 2249: DIST_POINT */
            	2254, 0,
            0, 32, 3, /* 2254: struct.DIST_POINT_st */
            	7, 0,
            	433, 8,
            	26, 16,
            1, 8, 1, /* 2263: pointer.struct.stack_st_GENERAL_NAME */
            	2268, 0,
            0, 32, 2, /* 2268: struct.stack_st_fake_GENERAL_NAME */
            	2275, 8,
            	360, 24,
            8884099, 8, 2, /* 2275: pointer_to_array_of_pointers_to_stack */
            	2282, 0,
            	357, 20,
            0, 8, 1, /* 2282: pointer.GENERAL_NAME */
            	50, 0,
            1, 8, 1, /* 2287: pointer.struct.NAME_CONSTRAINTS_st */
            	2292, 0,
            0, 0, 0, /* 2292: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 2295: pointer.struct.x509_cert_aux_st */
            	2300, 0,
            0, 40, 5, /* 2300: struct.x509_cert_aux_st */
            	2313, 0,
            	2313, 8,
            	1364, 16,
            	1314, 24,
            	2351, 32,
            1, 8, 1, /* 2313: pointer.struct.stack_st_ASN1_OBJECT */
            	2318, 0,
            0, 32, 2, /* 2318: struct.stack_st_fake_ASN1_OBJECT */
            	2325, 8,
            	360, 24,
            8884099, 8, 2, /* 2325: pointer_to_array_of_pointers_to_stack */
            	2332, 0,
            	357, 20,
            0, 8, 1, /* 2332: pointer.ASN1_OBJECT */
            	2337, 0,
            0, 0, 1, /* 2337: ASN1_OBJECT */
            	2342, 0,
            0, 40, 3, /* 2342: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            1, 8, 1, /* 2351: pointer.struct.stack_st_X509_ALGOR */
            	2356, 0,
            0, 32, 2, /* 2356: struct.stack_st_fake_X509_ALGOR */
            	2363, 8,
            	360, 24,
            8884099, 8, 2, /* 2363: pointer_to_array_of_pointers_to_stack */
            	2370, 0,
            	357, 20,
            0, 8, 1, /* 2370: pointer.X509_ALGOR */
            	2375, 0,
            0, 0, 1, /* 2375: X509_ALGOR */
            	2380, 0,
            0, 16, 2, /* 2380: struct.X509_algor_st */
            	1955, 0,
            	2387, 8,
            1, 8, 1, /* 2387: pointer.struct.asn1_type_st */
            	1897, 0,
            1, 8, 1, /* 2392: pointer.struct.X509_crl_st */
            	2397, 0,
            0, 120, 10, /* 2397: struct.X509_crl_st */
            	2420, 0,
            	1220, 8,
            	1309, 16,
            	2209, 32,
            	2468, 40,
            	1210, 56,
            	1210, 64,
            	844, 96,
            	890, 104,
            	898, 112,
            1, 8, 1, /* 2420: pointer.struct.X509_crl_info_st */
            	2425, 0,
            0, 80, 8, /* 2425: struct.X509_crl_info_st */
            	1210, 0,
            	1220, 8,
            	1369, 16,
            	1429, 24,
            	1429, 32,
            	2444, 40,
            	2180, 48,
            	2204, 56,
            1, 8, 1, /* 2444: pointer.struct.stack_st_X509_REVOKED */
            	2449, 0,
            0, 32, 2, /* 2449: struct.stack_st_fake_X509_REVOKED */
            	2456, 8,
            	360, 24,
            8884099, 8, 2, /* 2456: pointer_to_array_of_pointers_to_stack */
            	2463, 0,
            	357, 20,
            0, 8, 1, /* 2463: pointer.X509_REVOKED */
            	648, 0,
            1, 8, 1, /* 2468: pointer.struct.ISSUING_DIST_POINT_st */
            	2473, 0,
            0, 0, 0, /* 2473: struct.ISSUING_DIST_POINT_st */
            1, 8, 1, /* 2476: pointer.struct.stack_st_X509_LOOKUP */
            	2481, 0,
            0, 32, 2, /* 2481: struct.stack_st_fake_X509_LOOKUP */
            	2488, 8,
            	360, 24,
            8884099, 8, 2, /* 2488: pointer_to_array_of_pointers_to_stack */
            	2495, 0,
            	357, 20,
            0, 8, 1, /* 2495: pointer.X509_LOOKUP */
            	2500, 0,
            0, 0, 1, /* 2500: X509_LOOKUP */
            	2505, 0,
            0, 32, 3, /* 2505: struct.x509_lookup_st */
            	2514, 8,
            	93, 16,
            	2563, 24,
            1, 8, 1, /* 2514: pointer.struct.x509_lookup_method_st */
            	2519, 0,
            0, 80, 10, /* 2519: struct.x509_lookup_method_st */
            	124, 0,
            	2542, 8,
            	2545, 16,
            	2542, 24,
            	2542, 32,
            	2548, 40,
            	2551, 48,
            	2554, 56,
            	2557, 64,
            	2560, 72,
            8884097, 8, 0, /* 2542: pointer.func */
            8884097, 8, 0, /* 2545: pointer.func */
            8884097, 8, 0, /* 2548: pointer.func */
            8884097, 8, 0, /* 2551: pointer.func */
            8884097, 8, 0, /* 2554: pointer.func */
            8884097, 8, 0, /* 2557: pointer.func */
            8884097, 8, 0, /* 2560: pointer.func */
            1, 8, 1, /* 2563: pointer.struct.x509_store_st */
            	2568, 0,
            0, 144, 15, /* 2568: struct.x509_store_st */
            	2601, 8,
            	2625, 16,
            	2649, 24,
            	2661, 32,
            	2664, 40,
            	2667, 48,
            	2670, 56,
            	2661, 64,
            	2673, 72,
            	2676, 80,
            	2679, 88,
            	2682, 96,
            	2685, 104,
            	2661, 112,
            	1608, 120,
            1, 8, 1, /* 2601: pointer.struct.stack_st_X509_OBJECT */
            	2606, 0,
            0, 32, 2, /* 2606: struct.stack_st_fake_X509_OBJECT */
            	2613, 8,
            	360, 24,
            8884099, 8, 2, /* 2613: pointer_to_array_of_pointers_to_stack */
            	2620, 0,
            	357, 20,
            0, 8, 1, /* 2620: pointer.X509_OBJECT */
            	1127, 0,
            1, 8, 1, /* 2625: pointer.struct.stack_st_X509_LOOKUP */
            	2630, 0,
            0, 32, 2, /* 2630: struct.stack_st_fake_X509_LOOKUP */
            	2637, 8,
            	360, 24,
            8884099, 8, 2, /* 2637: pointer_to_array_of_pointers_to_stack */
            	2644, 0,
            	357, 20,
            0, 8, 1, /* 2644: pointer.X509_LOOKUP */
            	2500, 0,
            1, 8, 1, /* 2649: pointer.struct.X509_VERIFY_PARAM_st */
            	2654, 0,
            0, 56, 2, /* 2654: struct.X509_VERIFY_PARAM_st */
            	93, 0,
            	2313, 48,
            8884097, 8, 0, /* 2661: pointer.func */
            8884097, 8, 0, /* 2664: pointer.func */
            8884097, 8, 0, /* 2667: pointer.func */
            8884097, 8, 0, /* 2670: pointer.func */
            8884097, 8, 0, /* 2673: pointer.func */
            8884097, 8, 0, /* 2676: pointer.func */
            8884097, 8, 0, /* 2679: pointer.func */
            8884097, 8, 0, /* 2682: pointer.func */
            8884097, 8, 0, /* 2685: pointer.func */
            1, 8, 1, /* 2688: pointer.struct.X509_VERIFY_PARAM_st */
            	2693, 0,
            0, 56, 2, /* 2693: struct.X509_VERIFY_PARAM_st */
            	93, 0,
            	2700, 48,
            1, 8, 1, /* 2700: pointer.struct.stack_st_ASN1_OBJECT */
            	2705, 0,
            0, 32, 2, /* 2705: struct.stack_st_fake_ASN1_OBJECT */
            	2712, 8,
            	360, 24,
            8884099, 8, 2, /* 2712: pointer_to_array_of_pointers_to_stack */
            	2719, 0,
            	357, 20,
            0, 8, 1, /* 2719: pointer.ASN1_OBJECT */
            	2337, 0,
            8884097, 8, 0, /* 2724: pointer.func */
            8884097, 8, 0, /* 2727: pointer.func */
            8884097, 8, 0, /* 2730: pointer.func */
            8884097, 8, 0, /* 2733: pointer.func */
            8884097, 8, 0, /* 2736: pointer.func */
            8884097, 8, 0, /* 2739: pointer.func */
            8884097, 8, 0, /* 2742: pointer.func */
            8884097, 8, 0, /* 2745: pointer.func */
            8884097, 8, 0, /* 2748: pointer.func */
            0, 16, 1, /* 2751: struct.crypto_ex_data_st */
            	2756, 0,
            1, 8, 1, /* 2756: pointer.struct.stack_st_void */
            	2761, 0,
            0, 32, 1, /* 2761: struct.stack_st_void */
            	2766, 0,
            0, 32, 2, /* 2766: struct.stack_st */
            	885, 8,
            	360, 24,
            1, 8, 1, /* 2773: pointer.struct.x509_st */
            	2778, 0,
            0, 184, 12, /* 2778: struct.x509_st */
            	2805, 0,
            	467, 8,
            	433, 16,
            	93, 32,
            	2751, 40,
            	556, 104,
            	825, 112,
            	2217, 120,
            	3184, 128,
            	3208, 136,
            	3232, 144,
            	3552, 176,
            1, 8, 1, /* 2805: pointer.struct.x509_cinf_st */
            	2810, 0,
            0, 104, 11, /* 2810: struct.x509_cinf_st */
            	462, 0,
            	462, 8,
            	467, 16,
            	409, 24,
            	2835, 32,
            	409, 40,
            	2847, 48,
            	433, 56,
            	433, 64,
            	763, 72,
            	787, 80,
            1, 8, 1, /* 2835: pointer.struct.X509_val_st */
            	2840, 0,
            0, 16, 2, /* 2840: struct.X509_val_st */
            	619, 0,
            	619, 8,
            1, 8, 1, /* 2847: pointer.struct.X509_pubkey_st */
            	2852, 0,
            0, 24, 3, /* 2852: struct.X509_pubkey_st */
            	467, 0,
            	433, 8,
            	2861, 16,
            1, 8, 1, /* 2861: pointer.struct.evp_pkey_st */
            	2866, 0,
            0, 56, 4, /* 2866: struct.evp_pkey_st */
            	1464, 16,
            	1472, 24,
            	2877, 32,
            	3160, 48,
            0, 8, 5, /* 2877: union.unknown */
            	93, 0,
            	2890, 0,
            	3011, 0,
            	3092, 0,
            	1801, 0,
            1, 8, 1, /* 2890: pointer.struct.rsa_st */
            	2895, 0,
            0, 168, 17, /* 2895: struct.rsa_st */
            	2932, 16,
            	1472, 24,
            	2987, 32,
            	2987, 40,
            	2987, 48,
            	2987, 56,
            	2987, 64,
            	2987, 72,
            	2987, 80,
            	2987, 88,
            	2751, 96,
            	2997, 120,
            	2997, 128,
            	2997, 136,
            	93, 144,
            	1644, 152,
            	1644, 160,
            1, 8, 1, /* 2932: pointer.struct.rsa_meth_st */
            	2937, 0,
            0, 112, 13, /* 2937: struct.rsa_meth_st */
            	124, 0,
            	2966, 8,
            	2966, 16,
            	2966, 24,
            	2966, 32,
            	2969, 40,
            	2972, 48,
            	2975, 56,
            	2975, 64,
            	93, 80,
            	2978, 88,
            	2981, 96,
            	2984, 104,
            8884097, 8, 0, /* 2966: pointer.func */
            8884097, 8, 0, /* 2969: pointer.func */
            8884097, 8, 0, /* 2972: pointer.func */
            8884097, 8, 0, /* 2975: pointer.func */
            8884097, 8, 0, /* 2978: pointer.func */
            8884097, 8, 0, /* 2981: pointer.func */
            8884097, 8, 0, /* 2984: pointer.func */
            1, 8, 1, /* 2987: pointer.struct.bignum_st */
            	2992, 0,
            0, 24, 1, /* 2992: struct.bignum_st */
            	1600, 0,
            1, 8, 1, /* 2997: pointer.struct.bn_mont_ctx_st */
            	3002, 0,
            0, 96, 3, /* 3002: struct.bn_mont_ctx_st */
            	2992, 8,
            	2992, 32,
            	2992, 56,
            1, 8, 1, /* 3011: pointer.struct.dsa_st */
            	3016, 0,
            0, 136, 11, /* 3016: struct.dsa_st */
            	2987, 24,
            	2987, 32,
            	2987, 40,
            	2987, 48,
            	2987, 56,
            	2987, 64,
            	2987, 72,
            	2997, 88,
            	2751, 104,
            	3041, 120,
            	1472, 128,
            1, 8, 1, /* 3041: pointer.struct.dsa_method */
            	3046, 0,
            0, 96, 11, /* 3046: struct.dsa_method */
            	124, 0,
            	3071, 8,
            	3074, 16,
            	3077, 24,
            	3080, 32,
            	3083, 40,
            	3086, 48,
            	3086, 56,
            	93, 72,
            	3089, 80,
            	3086, 88,
            8884097, 8, 0, /* 3071: pointer.func */
            8884097, 8, 0, /* 3074: pointer.func */
            8884097, 8, 0, /* 3077: pointer.func */
            8884097, 8, 0, /* 3080: pointer.func */
            8884097, 8, 0, /* 3083: pointer.func */
            8884097, 8, 0, /* 3086: pointer.func */
            8884097, 8, 0, /* 3089: pointer.func */
            1, 8, 1, /* 3092: pointer.struct.dh_st */
            	3097, 0,
            0, 144, 12, /* 3097: struct.dh_st */
            	2987, 8,
            	2987, 16,
            	2987, 32,
            	2987, 40,
            	2997, 56,
            	2987, 64,
            	2987, 72,
            	200, 80,
            	2987, 96,
            	2751, 112,
            	3124, 128,
            	1472, 136,
            1, 8, 1, /* 3124: pointer.struct.dh_method */
            	3129, 0,
            0, 72, 8, /* 3129: struct.dh_method */
            	124, 0,
            	3148, 8,
            	3151, 16,
            	3154, 24,
            	3148, 32,
            	3148, 40,
            	93, 56,
            	3157, 64,
            8884097, 8, 0, /* 3148: pointer.func */
            8884097, 8, 0, /* 3151: pointer.func */
            8884097, 8, 0, /* 3154: pointer.func */
            8884097, 8, 0, /* 3157: pointer.func */
            1, 8, 1, /* 3160: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3165, 0,
            0, 32, 2, /* 3165: struct.stack_st_fake_X509_ATTRIBUTE */
            	3172, 8,
            	360, 24,
            8884099, 8, 2, /* 3172: pointer_to_array_of_pointers_to_stack */
            	3179, 0,
            	357, 20,
            0, 8, 1, /* 3179: pointer.X509_ATTRIBUTE */
            	1833, 0,
            1, 8, 1, /* 3184: pointer.struct.stack_st_DIST_POINT */
            	3189, 0,
            0, 32, 2, /* 3189: struct.stack_st_fake_DIST_POINT */
            	3196, 8,
            	360, 24,
            8884099, 8, 2, /* 3196: pointer_to_array_of_pointers_to_stack */
            	3203, 0,
            	357, 20,
            0, 8, 1, /* 3203: pointer.DIST_POINT */
            	2249, 0,
            1, 8, 1, /* 3208: pointer.struct.stack_st_GENERAL_NAME */
            	3213, 0,
            0, 32, 2, /* 3213: struct.stack_st_fake_GENERAL_NAME */
            	3220, 8,
            	360, 24,
            8884099, 8, 2, /* 3220: pointer_to_array_of_pointers_to_stack */
            	3227, 0,
            	357, 20,
            0, 8, 1, /* 3227: pointer.GENERAL_NAME */
            	50, 0,
            1, 8, 1, /* 3232: pointer.struct.NAME_CONSTRAINTS_st */
            	3237, 0,
            0, 16, 2, /* 3237: struct.NAME_CONSTRAINTS_st */
            	3244, 0,
            	3244, 8,
            1, 8, 1, /* 3244: pointer.struct.stack_st_GENERAL_SUBTREE */
            	3249, 0,
            0, 32, 2, /* 3249: struct.stack_st_fake_GENERAL_SUBTREE */
            	3256, 8,
            	360, 24,
            8884099, 8, 2, /* 3256: pointer_to_array_of_pointers_to_stack */
            	3263, 0,
            	357, 20,
            0, 8, 1, /* 3263: pointer.GENERAL_SUBTREE */
            	3268, 0,
            0, 0, 1, /* 3268: GENERAL_SUBTREE */
            	3273, 0,
            0, 24, 3, /* 3273: struct.GENERAL_SUBTREE_st */
            	3282, 0,
            	3414, 8,
            	3414, 16,
            1, 8, 1, /* 3282: pointer.struct.GENERAL_NAME_st */
            	3287, 0,
            0, 16, 1, /* 3287: struct.GENERAL_NAME_st */
            	3292, 8,
            0, 8, 15, /* 3292: union.unknown */
            	93, 0,
            	3325, 0,
            	3444, 0,
            	3444, 0,
            	3351, 0,
            	3492, 0,
            	3540, 0,
            	3444, 0,
            	3429, 0,
            	3337, 0,
            	3429, 0,
            	3492, 0,
            	3444, 0,
            	3337, 0,
            	3351, 0,
            1, 8, 1, /* 3325: pointer.struct.otherName_st */
            	3330, 0,
            0, 16, 2, /* 3330: struct.otherName_st */
            	3337, 0,
            	3351, 8,
            1, 8, 1, /* 3337: pointer.struct.asn1_object_st */
            	3342, 0,
            0, 40, 3, /* 3342: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            1, 8, 1, /* 3351: pointer.struct.asn1_type_st */
            	3356, 0,
            0, 16, 1, /* 3356: struct.asn1_type_st */
            	3361, 8,
            0, 8, 20, /* 3361: union.unknown */
            	93, 0,
            	3404, 0,
            	3337, 0,
            	3414, 0,
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
            	3404, 0,
            	3404, 0,
            	3484, 0,
            1, 8, 1, /* 3404: pointer.struct.asn1_string_st */
            	3409, 0,
            0, 24, 1, /* 3409: struct.asn1_string_st */
            	200, 8,
            1, 8, 1, /* 3414: pointer.struct.asn1_string_st */
            	3409, 0,
            1, 8, 1, /* 3419: pointer.struct.asn1_string_st */
            	3409, 0,
            1, 8, 1, /* 3424: pointer.struct.asn1_string_st */
            	3409, 0,
            1, 8, 1, /* 3429: pointer.struct.asn1_string_st */
            	3409, 0,
            1, 8, 1, /* 3434: pointer.struct.asn1_string_st */
            	3409, 0,
            1, 8, 1, /* 3439: pointer.struct.asn1_string_st */
            	3409, 0,
            1, 8, 1, /* 3444: pointer.struct.asn1_string_st */
            	3409, 0,
            1, 8, 1, /* 3449: pointer.struct.asn1_string_st */
            	3409, 0,
            1, 8, 1, /* 3454: pointer.struct.asn1_string_st */
            	3409, 0,
            1, 8, 1, /* 3459: pointer.struct.asn1_string_st */
            	3409, 0,
            1, 8, 1, /* 3464: pointer.struct.asn1_string_st */
            	3409, 0,
            1, 8, 1, /* 3469: pointer.struct.asn1_string_st */
            	3409, 0,
            1, 8, 1, /* 3474: pointer.struct.asn1_string_st */
            	3409, 0,
            1, 8, 1, /* 3479: pointer.struct.asn1_string_st */
            	3409, 0,
            1, 8, 1, /* 3484: pointer.struct.ASN1_VALUE_st */
            	3489, 0,
            0, 0, 0, /* 3489: struct.ASN1_VALUE_st */
            1, 8, 1, /* 3492: pointer.struct.X509_name_st */
            	3497, 0,
            0, 40, 3, /* 3497: struct.X509_name_st */
            	3506, 0,
            	3530, 16,
            	200, 24,
            1, 8, 1, /* 3506: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3511, 0,
            0, 32, 2, /* 3511: struct.stack_st_fake_X509_NAME_ENTRY */
            	3518, 8,
            	360, 24,
            8884099, 8, 2, /* 3518: pointer_to_array_of_pointers_to_stack */
            	3525, 0,
            	357, 20,
            0, 8, 1, /* 3525: pointer.X509_NAME_ENTRY */
            	321, 0,
            1, 8, 1, /* 3530: pointer.struct.buf_mem_st */
            	3535, 0,
            0, 24, 1, /* 3535: struct.buf_mem_st */
            	93, 8,
            1, 8, 1, /* 3540: pointer.struct.EDIPartyName_st */
            	3545, 0,
            0, 16, 2, /* 3545: struct.EDIPartyName_st */
            	3404, 0,
            	3404, 8,
            1, 8, 1, /* 3552: pointer.struct.x509_cert_aux_st */
            	3557, 0,
            0, 40, 5, /* 3557: struct.x509_cert_aux_st */
            	2700, 0,
            	2700, 8,
            	606, 16,
            	556, 24,
            	3570, 32,
            1, 8, 1, /* 3570: pointer.struct.stack_st_X509_ALGOR */
            	3575, 0,
            0, 32, 2, /* 3575: struct.stack_st_fake_X509_ALGOR */
            	3582, 8,
            	360, 24,
            8884099, 8, 2, /* 3582: pointer_to_array_of_pointers_to_stack */
            	3589, 0,
            	357, 20,
            0, 8, 1, /* 3589: pointer.X509_ALGOR */
            	2375, 0,
            1, 8, 1, /* 3594: pointer.struct.stack_st_X509 */
            	3599, 0,
            0, 32, 2, /* 3599: struct.stack_st_fake_X509 */
            	3606, 8,
            	360, 24,
            8884099, 8, 2, /* 3606: pointer_to_array_of_pointers_to_stack */
            	3613, 0,
            	357, 20,
            0, 8, 1, /* 3613: pointer.X509 */
            	3618, 0,
            0, 0, 1, /* 3618: X509 */
            	3623, 0,
            0, 184, 12, /* 3623: struct.x509_st */
            	3650, 0,
            	3690, 8,
            	3779, 16,
            	93, 32,
            	4078, 40,
            	3784, 104,
            	4332, 112,
            	4340, 120,
            	4348, 128,
            	4372, 136,
            	4396, 144,
            	4404, 176,
            1, 8, 1, /* 3650: pointer.struct.x509_cinf_st */
            	3655, 0,
            0, 104, 11, /* 3655: struct.x509_cinf_st */
            	3680, 0,
            	3680, 8,
            	3690, 16,
            	3847, 24,
            	3895, 32,
            	3847, 40,
            	3912, 48,
            	3779, 56,
            	3779, 64,
            	4303, 72,
            	4327, 80,
            1, 8, 1, /* 3680: pointer.struct.asn1_string_st */
            	3685, 0,
            0, 24, 1, /* 3685: struct.asn1_string_st */
            	200, 8,
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
            	3680, 0,
            	3774, 0,
            	3779, 0,
            	3784, 0,
            	3789, 0,
            	3794, 0,
            	3799, 0,
            	3804, 0,
            	3809, 0,
            	3814, 0,
            	3819, 0,
            	3824, 0,
            	3829, 0,
            	3834, 0,
            	3769, 0,
            	3769, 0,
            	3839, 0,
            1, 8, 1, /* 3769: pointer.struct.asn1_string_st */
            	3685, 0,
            1, 8, 1, /* 3774: pointer.struct.asn1_string_st */
            	3685, 0,
            1, 8, 1, /* 3779: pointer.struct.asn1_string_st */
            	3685, 0,
            1, 8, 1, /* 3784: pointer.struct.asn1_string_st */
            	3685, 0,
            1, 8, 1, /* 3789: pointer.struct.asn1_string_st */
            	3685, 0,
            1, 8, 1, /* 3794: pointer.struct.asn1_string_st */
            	3685, 0,
            1, 8, 1, /* 3799: pointer.struct.asn1_string_st */
            	3685, 0,
            1, 8, 1, /* 3804: pointer.struct.asn1_string_st */
            	3685, 0,
            1, 8, 1, /* 3809: pointer.struct.asn1_string_st */
            	3685, 0,
            1, 8, 1, /* 3814: pointer.struct.asn1_string_st */
            	3685, 0,
            1, 8, 1, /* 3819: pointer.struct.asn1_string_st */
            	3685, 0,
            1, 8, 1, /* 3824: pointer.struct.asn1_string_st */
            	3685, 0,
            1, 8, 1, /* 3829: pointer.struct.asn1_string_st */
            	3685, 0,
            1, 8, 1, /* 3834: pointer.struct.asn1_string_st */
            	3685, 0,
            1, 8, 1, /* 3839: pointer.struct.ASN1_VALUE_st */
            	3844, 0,
            0, 0, 0, /* 3844: struct.ASN1_VALUE_st */
            1, 8, 1, /* 3847: pointer.struct.X509_name_st */
            	3852, 0,
            0, 40, 3, /* 3852: struct.X509_name_st */
            	3861, 0,
            	3885, 16,
            	200, 24,
            1, 8, 1, /* 3861: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3866, 0,
            0, 32, 2, /* 3866: struct.stack_st_fake_X509_NAME_ENTRY */
            	3873, 8,
            	360, 24,
            8884099, 8, 2, /* 3873: pointer_to_array_of_pointers_to_stack */
            	3880, 0,
            	357, 20,
            0, 8, 1, /* 3880: pointer.X509_NAME_ENTRY */
            	321, 0,
            1, 8, 1, /* 3885: pointer.struct.buf_mem_st */
            	3890, 0,
            0, 24, 1, /* 3890: struct.buf_mem_st */
            	93, 8,
            1, 8, 1, /* 3895: pointer.struct.X509_val_st */
            	3900, 0,
            0, 16, 2, /* 3900: struct.X509_val_st */
            	3907, 0,
            	3907, 8,
            1, 8, 1, /* 3907: pointer.struct.asn1_string_st */
            	3685, 0,
            1, 8, 1, /* 3912: pointer.struct.X509_pubkey_st */
            	3917, 0,
            0, 24, 3, /* 3917: struct.X509_pubkey_st */
            	3690, 0,
            	3779, 8,
            	3926, 16,
            1, 8, 1, /* 3926: pointer.struct.evp_pkey_st */
            	3931, 0,
            0, 56, 4, /* 3931: struct.evp_pkey_st */
            	3942, 16,
            	3950, 24,
            	3958, 32,
            	4279, 48,
            1, 8, 1, /* 3942: pointer.struct.evp_pkey_asn1_method_st */
            	3947, 0,
            0, 0, 0, /* 3947: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 3950: pointer.struct.engine_st */
            	3955, 0,
            0, 0, 0, /* 3955: struct.engine_st */
            0, 8, 5, /* 3958: union.unknown */
            	93, 0,
            	3971, 0,
            	4122, 0,
            	4203, 0,
            	4271, 0,
            1, 8, 1, /* 3971: pointer.struct.rsa_st */
            	3976, 0,
            0, 168, 17, /* 3976: struct.rsa_st */
            	4013, 16,
            	3950, 24,
            	4068, 32,
            	4068, 40,
            	4068, 48,
            	4068, 56,
            	4068, 64,
            	4068, 72,
            	4068, 80,
            	4068, 88,
            	4078, 96,
            	4100, 120,
            	4100, 128,
            	4100, 136,
            	93, 144,
            	4114, 152,
            	4114, 160,
            1, 8, 1, /* 4013: pointer.struct.rsa_meth_st */
            	4018, 0,
            0, 112, 13, /* 4018: struct.rsa_meth_st */
            	124, 0,
            	4047, 8,
            	4047, 16,
            	4047, 24,
            	4047, 32,
            	4050, 40,
            	4053, 48,
            	4056, 56,
            	4056, 64,
            	93, 80,
            	4059, 88,
            	4062, 96,
            	4065, 104,
            8884097, 8, 0, /* 4047: pointer.func */
            8884097, 8, 0, /* 4050: pointer.func */
            8884097, 8, 0, /* 4053: pointer.func */
            8884097, 8, 0, /* 4056: pointer.func */
            8884097, 8, 0, /* 4059: pointer.func */
            8884097, 8, 0, /* 4062: pointer.func */
            8884097, 8, 0, /* 4065: pointer.func */
            1, 8, 1, /* 4068: pointer.struct.bignum_st */
            	4073, 0,
            0, 24, 1, /* 4073: struct.bignum_st */
            	1600, 0,
            0, 16, 1, /* 4078: struct.crypto_ex_data_st */
            	4083, 0,
            1, 8, 1, /* 4083: pointer.struct.stack_st_void */
            	4088, 0,
            0, 32, 1, /* 4088: struct.stack_st_void */
            	4093, 0,
            0, 32, 2, /* 4093: struct.stack_st */
            	885, 8,
            	360, 24,
            1, 8, 1, /* 4100: pointer.struct.bn_mont_ctx_st */
            	4105, 0,
            0, 96, 3, /* 4105: struct.bn_mont_ctx_st */
            	4073, 8,
            	4073, 32,
            	4073, 56,
            1, 8, 1, /* 4114: pointer.struct.bn_blinding_st */
            	4119, 0,
            0, 0, 0, /* 4119: struct.bn_blinding_st */
            1, 8, 1, /* 4122: pointer.struct.dsa_st */
            	4127, 0,
            0, 136, 11, /* 4127: struct.dsa_st */
            	4068, 24,
            	4068, 32,
            	4068, 40,
            	4068, 48,
            	4068, 56,
            	4068, 64,
            	4068, 72,
            	4100, 88,
            	4078, 104,
            	4152, 120,
            	3950, 128,
            1, 8, 1, /* 4152: pointer.struct.dsa_method */
            	4157, 0,
            0, 96, 11, /* 4157: struct.dsa_method */
            	124, 0,
            	4182, 8,
            	4185, 16,
            	4188, 24,
            	4191, 32,
            	4194, 40,
            	4197, 48,
            	4197, 56,
            	93, 72,
            	4200, 80,
            	4197, 88,
            8884097, 8, 0, /* 4182: pointer.func */
            8884097, 8, 0, /* 4185: pointer.func */
            8884097, 8, 0, /* 4188: pointer.func */
            8884097, 8, 0, /* 4191: pointer.func */
            8884097, 8, 0, /* 4194: pointer.func */
            8884097, 8, 0, /* 4197: pointer.func */
            8884097, 8, 0, /* 4200: pointer.func */
            1, 8, 1, /* 4203: pointer.struct.dh_st */
            	4208, 0,
            0, 144, 12, /* 4208: struct.dh_st */
            	4068, 8,
            	4068, 16,
            	4068, 32,
            	4068, 40,
            	4100, 56,
            	4068, 64,
            	4068, 72,
            	200, 80,
            	4068, 96,
            	4078, 112,
            	4235, 128,
            	3950, 136,
            1, 8, 1, /* 4235: pointer.struct.dh_method */
            	4240, 0,
            0, 72, 8, /* 4240: struct.dh_method */
            	124, 0,
            	4259, 8,
            	4262, 16,
            	4265, 24,
            	4259, 32,
            	4259, 40,
            	93, 56,
            	4268, 64,
            8884097, 8, 0, /* 4259: pointer.func */
            8884097, 8, 0, /* 4262: pointer.func */
            8884097, 8, 0, /* 4265: pointer.func */
            8884097, 8, 0, /* 4268: pointer.func */
            1, 8, 1, /* 4271: pointer.struct.ec_key_st */
            	4276, 0,
            0, 0, 0, /* 4276: struct.ec_key_st */
            1, 8, 1, /* 4279: pointer.struct.stack_st_X509_ATTRIBUTE */
            	4284, 0,
            0, 32, 2, /* 4284: struct.stack_st_fake_X509_ATTRIBUTE */
            	4291, 8,
            	360, 24,
            8884099, 8, 2, /* 4291: pointer_to_array_of_pointers_to_stack */
            	4298, 0,
            	357, 20,
            0, 8, 1, /* 4298: pointer.X509_ATTRIBUTE */
            	1833, 0,
            1, 8, 1, /* 4303: pointer.struct.stack_st_X509_EXTENSION */
            	4308, 0,
            0, 32, 2, /* 4308: struct.stack_st_fake_X509_EXTENSION */
            	4315, 8,
            	360, 24,
            8884099, 8, 2, /* 4315: pointer_to_array_of_pointers_to_stack */
            	4322, 0,
            	357, 20,
            0, 8, 1, /* 4322: pointer.X509_EXTENSION */
            	703, 0,
            0, 24, 1, /* 4327: struct.ASN1_ENCODING_st */
            	200, 0,
            1, 8, 1, /* 4332: pointer.struct.AUTHORITY_KEYID_st */
            	4337, 0,
            0, 0, 0, /* 4337: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 4340: pointer.struct.X509_POLICY_CACHE_st */
            	4345, 0,
            0, 0, 0, /* 4345: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 4348: pointer.struct.stack_st_DIST_POINT */
            	4353, 0,
            0, 32, 2, /* 4353: struct.stack_st_fake_DIST_POINT */
            	4360, 8,
            	360, 24,
            8884099, 8, 2, /* 4360: pointer_to_array_of_pointers_to_stack */
            	4367, 0,
            	357, 20,
            0, 8, 1, /* 4367: pointer.DIST_POINT */
            	2249, 0,
            1, 8, 1, /* 4372: pointer.struct.stack_st_GENERAL_NAME */
            	4377, 0,
            0, 32, 2, /* 4377: struct.stack_st_fake_GENERAL_NAME */
            	4384, 8,
            	360, 24,
            8884099, 8, 2, /* 4384: pointer_to_array_of_pointers_to_stack */
            	4391, 0,
            	357, 20,
            0, 8, 1, /* 4391: pointer.GENERAL_NAME */
            	50, 0,
            1, 8, 1, /* 4396: pointer.struct.NAME_CONSTRAINTS_st */
            	4401, 0,
            0, 0, 0, /* 4401: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 4404: pointer.struct.x509_cert_aux_st */
            	4409, 0,
            0, 40, 5, /* 4409: struct.x509_cert_aux_st */
            	4422, 0,
            	4422, 8,
            	3834, 16,
            	3784, 24,
            	4446, 32,
            1, 8, 1, /* 4422: pointer.struct.stack_st_ASN1_OBJECT */
            	4427, 0,
            0, 32, 2, /* 4427: struct.stack_st_fake_ASN1_OBJECT */
            	4434, 8,
            	360, 24,
            8884099, 8, 2, /* 4434: pointer_to_array_of_pointers_to_stack */
            	4441, 0,
            	357, 20,
            0, 8, 1, /* 4441: pointer.ASN1_OBJECT */
            	2337, 0,
            1, 8, 1, /* 4446: pointer.struct.stack_st_X509_ALGOR */
            	4451, 0,
            0, 32, 2, /* 4451: struct.stack_st_fake_X509_ALGOR */
            	4458, 8,
            	360, 24,
            8884099, 8, 2, /* 4458: pointer_to_array_of_pointers_to_stack */
            	4465, 0,
            	357, 20,
            0, 8, 1, /* 4465: pointer.X509_ALGOR */
            	2375, 0,
            1, 8, 1, /* 4470: pointer.struct.stack_st_X509_CRL */
            	4475, 0,
            0, 32, 2, /* 4475: struct.stack_st_fake_X509_CRL */
            	4482, 8,
            	360, 24,
            8884099, 8, 2, /* 4482: pointer_to_array_of_pointers_to_stack */
            	4489, 0,
            	357, 20,
            0, 8, 1, /* 4489: pointer.X509_CRL */
            	4494, 0,
            0, 0, 1, /* 4494: X509_CRL */
            	4499, 0,
            0, 120, 10, /* 4499: struct.X509_crl_st */
            	4522, 0,
            	4551, 8,
            	4640, 16,
            	2209, 32,
            	2468, 40,
            	4546, 56,
            	4546, 64,
            	844, 96,
            	890, 104,
            	898, 112,
            1, 8, 1, /* 4522: pointer.struct.X509_crl_info_st */
            	4527, 0,
            0, 80, 8, /* 4527: struct.X509_crl_info_st */
            	4546, 0,
            	4551, 8,
            	4670, 16,
            	4684, 24,
            	4684, 32,
            	4689, 40,
            	914, 48,
            	909, 56,
            1, 8, 1, /* 4546: pointer.struct.asn1_string_st */
            	977, 0,
            1, 8, 1, /* 4551: pointer.struct.X509_algor_st */
            	4556, 0,
            0, 16, 2, /* 4556: struct.X509_algor_st */
            	4563, 0,
            	4577, 8,
            1, 8, 1, /* 4563: pointer.struct.asn1_object_st */
            	4568, 0,
            0, 40, 3, /* 4568: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            1, 8, 1, /* 4577: pointer.struct.asn1_type_st */
            	4582, 0,
            0, 16, 1, /* 4582: struct.asn1_type_st */
            	4587, 8,
            0, 8, 20, /* 4587: union.unknown */
            	93, 0,
            	4630, 0,
            	4563, 0,
            	4546, 0,
            	4635, 0,
            	4640, 0,
            	4645, 0,
            	4650, 0,
            	4655, 0,
            	1002, 0,
            	997, 0,
            	992, 0,
            	987, 0,
            	4660, 0,
            	982, 0,
            	4665, 0,
            	972, 0,
            	4630, 0,
            	4630, 0,
            	611, 0,
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
            1, 8, 1, /* 4665: pointer.struct.asn1_string_st */
            	977, 0,
            1, 8, 1, /* 4670: pointer.struct.X509_name_st */
            	4675, 0,
            0, 40, 3, /* 4675: struct.X509_name_st */
            	948, 0,
            	938, 16,
            	200, 24,
            1, 8, 1, /* 4684: pointer.struct.asn1_string_st */
            	977, 0,
            1, 8, 1, /* 4689: pointer.struct.stack_st_X509_REVOKED */
            	4694, 0,
            0, 32, 2, /* 4694: struct.stack_st_fake_X509_REVOKED */
            	4701, 8,
            	360, 24,
            8884099, 8, 2, /* 4701: pointer_to_array_of_pointers_to_stack */
            	4708, 0,
            	357, 20,
            0, 8, 1, /* 4708: pointer.X509_REVOKED */
            	648, 0,
            0, 1, 0, /* 4713: char */
        },
        .arg_entity_index = { 1007, },
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

