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
            1, 8, 1, /* 948: pointer.struct.asn1_string_st */
            	953, 0,
            0, 24, 1, /* 953: struct.asn1_string_st */
            	200, 8,
            1, 8, 1, /* 958: pointer.struct.asn1_string_st */
            	953, 0,
            1, 8, 1, /* 963: pointer.struct.asn1_string_st */
            	953, 0,
            8884097, 8, 0, /* 968: pointer.func */
            1, 8, 1, /* 971: pointer.struct.stack_st_ASN1_TYPE */
            	976, 0,
            0, 32, 2, /* 976: struct.stack_st_fake_ASN1_TYPE */
            	983, 8,
            	360, 24,
            8884099, 8, 2, /* 983: pointer_to_array_of_pointers_to_stack */
            	990, 0,
            	357, 20,
            0, 8, 1, /* 990: pointer.ASN1_TYPE */
            	995, 0,
            0, 0, 1, /* 995: ASN1_TYPE */
            	1000, 0,
            0, 16, 1, /* 1000: struct.asn1_type_st */
            	1005, 8,
            0, 8, 20, /* 1005: union.unknown */
            	93, 0,
            	1048, 0,
            	1058, 0,
            	1072, 0,
            	1077, 0,
            	1082, 0,
            	1087, 0,
            	1092, 0,
            	1097, 0,
            	1102, 0,
            	1107, 0,
            	1112, 0,
            	1117, 0,
            	1122, 0,
            	1127, 0,
            	1132, 0,
            	1137, 0,
            	1048, 0,
            	1048, 0,
            	1142, 0,
            1, 8, 1, /* 1048: pointer.struct.asn1_string_st */
            	1053, 0,
            0, 24, 1, /* 1053: struct.asn1_string_st */
            	200, 8,
            1, 8, 1, /* 1058: pointer.struct.asn1_object_st */
            	1063, 0,
            0, 40, 3, /* 1063: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            1, 8, 1, /* 1072: pointer.struct.asn1_string_st */
            	1053, 0,
            1, 8, 1, /* 1077: pointer.struct.asn1_string_st */
            	1053, 0,
            1, 8, 1, /* 1082: pointer.struct.asn1_string_st */
            	1053, 0,
            1, 8, 1, /* 1087: pointer.struct.asn1_string_st */
            	1053, 0,
            1, 8, 1, /* 1092: pointer.struct.asn1_string_st */
            	1053, 0,
            1, 8, 1, /* 1097: pointer.struct.asn1_string_st */
            	1053, 0,
            1, 8, 1, /* 1102: pointer.struct.asn1_string_st */
            	1053, 0,
            1, 8, 1, /* 1107: pointer.struct.asn1_string_st */
            	1053, 0,
            1, 8, 1, /* 1112: pointer.struct.asn1_string_st */
            	1053, 0,
            1, 8, 1, /* 1117: pointer.struct.asn1_string_st */
            	1053, 0,
            1, 8, 1, /* 1122: pointer.struct.asn1_string_st */
            	1053, 0,
            1, 8, 1, /* 1127: pointer.struct.asn1_string_st */
            	1053, 0,
            1, 8, 1, /* 1132: pointer.struct.asn1_string_st */
            	1053, 0,
            1, 8, 1, /* 1137: pointer.struct.asn1_string_st */
            	1053, 0,
            1, 8, 1, /* 1142: pointer.struct.ASN1_VALUE_st */
            	1147, 0,
            0, 0, 0, /* 1147: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1150: pointer.struct.asn1_string_st */
            	953, 0,
            8884097, 8, 0, /* 1155: pointer.func */
            1, 8, 1, /* 1158: pointer.struct.asn1_object_st */
            	1163, 0,
            0, 40, 3, /* 1163: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            1, 8, 1, /* 1172: pointer.struct.stack_st_X509_LOOKUP */
            	1177, 0,
            0, 32, 2, /* 1177: struct.stack_st_fake_X509_LOOKUP */
            	1184, 8,
            	360, 24,
            8884099, 8, 2, /* 1184: pointer_to_array_of_pointers_to_stack */
            	1191, 0,
            	357, 20,
            0, 8, 1, /* 1191: pointer.X509_LOOKUP */
            	1196, 0,
            0, 0, 1, /* 1196: X509_LOOKUP */
            	1201, 0,
            0, 32, 3, /* 1201: struct.x509_lookup_st */
            	1210, 8,
            	93, 16,
            	1259, 24,
            1, 8, 1, /* 1210: pointer.struct.x509_lookup_method_st */
            	1215, 0,
            0, 80, 10, /* 1215: struct.x509_lookup_method_st */
            	124, 0,
            	1238, 8,
            	1241, 16,
            	1238, 24,
            	1238, 32,
            	1244, 40,
            	1247, 48,
            	1250, 56,
            	1253, 64,
            	1256, 72,
            8884097, 8, 0, /* 1238: pointer.func */
            8884097, 8, 0, /* 1241: pointer.func */
            8884097, 8, 0, /* 1244: pointer.func */
            8884097, 8, 0, /* 1247: pointer.func */
            8884097, 8, 0, /* 1250: pointer.func */
            8884097, 8, 0, /* 1253: pointer.func */
            8884097, 8, 0, /* 1256: pointer.func */
            1, 8, 1, /* 1259: pointer.struct.x509_store_st */
            	1264, 0,
            0, 144, 15, /* 1264: struct.x509_store_st */
            	1297, 8,
            	1172, 16,
            	2585, 24,
            	2597, 32,
            	2600, 40,
            	2603, 48,
            	2606, 56,
            	2597, 64,
            	968, 72,
            	2609, 80,
            	2612, 88,
            	2615, 96,
            	2618, 104,
            	2597, 112,
            	1802, 120,
            1, 8, 1, /* 1297: pointer.struct.stack_st_X509_OBJECT */
            	1302, 0,
            0, 32, 2, /* 1302: struct.stack_st_fake_X509_OBJECT */
            	1309, 8,
            	360, 24,
            8884099, 8, 2, /* 1309: pointer_to_array_of_pointers_to_stack */
            	1316, 0,
            	357, 20,
            0, 8, 1, /* 1316: pointer.X509_OBJECT */
            	1321, 0,
            0, 0, 1, /* 1321: X509_OBJECT */
            	1326, 0,
            0, 16, 1, /* 1326: struct.x509_object_st */
            	1331, 8,
            0, 8, 4, /* 1331: union.unknown */
            	93, 0,
            	1342, 0,
            	2501, 0,
            	1642, 0,
            1, 8, 1, /* 1342: pointer.struct.x509_st */
            	1347, 0,
            0, 184, 12, /* 1347: struct.x509_st */
            	1374, 0,
            	1414, 8,
            	1503, 16,
            	93, 32,
            	1802, 40,
            	1508, 104,
            	2224, 112,
            	2232, 120,
            	2240, 128,
            	2278, 136,
            	2302, 144,
            	2310, 176,
            1, 8, 1, /* 1374: pointer.struct.x509_cinf_st */
            	1379, 0,
            0, 104, 11, /* 1379: struct.x509_cinf_st */
            	1404, 0,
            	1404, 8,
            	1414, 16,
            	1563, 24,
            	1611, 32,
            	1563, 40,
            	1628, 48,
            	1503, 56,
            	1503, 64,
            	2195, 72,
            	2219, 80,
            1, 8, 1, /* 1404: pointer.struct.asn1_string_st */
            	1409, 0,
            0, 24, 1, /* 1409: struct.asn1_string_st */
            	200, 8,
            1, 8, 1, /* 1414: pointer.struct.X509_algor_st */
            	1419, 0,
            0, 16, 2, /* 1419: struct.X509_algor_st */
            	1426, 0,
            	1440, 8,
            1, 8, 1, /* 1426: pointer.struct.asn1_object_st */
            	1431, 0,
            0, 40, 3, /* 1431: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            1, 8, 1, /* 1440: pointer.struct.asn1_type_st */
            	1445, 0,
            0, 16, 1, /* 1445: struct.asn1_type_st */
            	1450, 8,
            0, 8, 20, /* 1450: union.unknown */
            	93, 0,
            	1493, 0,
            	1426, 0,
            	1404, 0,
            	1498, 0,
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
            	1493, 0,
            	1493, 0,
            	611, 0,
            1, 8, 1, /* 1493: pointer.struct.asn1_string_st */
            	1409, 0,
            1, 8, 1, /* 1498: pointer.struct.asn1_string_st */
            	1409, 0,
            1, 8, 1, /* 1503: pointer.struct.asn1_string_st */
            	1409, 0,
            1, 8, 1, /* 1508: pointer.struct.asn1_string_st */
            	1409, 0,
            1, 8, 1, /* 1513: pointer.struct.asn1_string_st */
            	1409, 0,
            1, 8, 1, /* 1518: pointer.struct.asn1_string_st */
            	1409, 0,
            1, 8, 1, /* 1523: pointer.struct.asn1_string_st */
            	1409, 0,
            1, 8, 1, /* 1528: pointer.struct.asn1_string_st */
            	1409, 0,
            1, 8, 1, /* 1533: pointer.struct.asn1_string_st */
            	1409, 0,
            1, 8, 1, /* 1538: pointer.struct.asn1_string_st */
            	1409, 0,
            1, 8, 1, /* 1543: pointer.struct.asn1_string_st */
            	1409, 0,
            1, 8, 1, /* 1548: pointer.struct.asn1_string_st */
            	1409, 0,
            1, 8, 1, /* 1553: pointer.struct.asn1_string_st */
            	1409, 0,
            1, 8, 1, /* 1558: pointer.struct.asn1_string_st */
            	1409, 0,
            1, 8, 1, /* 1563: pointer.struct.X509_name_st */
            	1568, 0,
            0, 40, 3, /* 1568: struct.X509_name_st */
            	1577, 0,
            	1601, 16,
            	200, 24,
            1, 8, 1, /* 1577: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1582, 0,
            0, 32, 2, /* 1582: struct.stack_st_fake_X509_NAME_ENTRY */
            	1589, 8,
            	360, 24,
            8884099, 8, 2, /* 1589: pointer_to_array_of_pointers_to_stack */
            	1596, 0,
            	357, 20,
            0, 8, 1, /* 1596: pointer.X509_NAME_ENTRY */
            	321, 0,
            1, 8, 1, /* 1601: pointer.struct.buf_mem_st */
            	1606, 0,
            0, 24, 1, /* 1606: struct.buf_mem_st */
            	93, 8,
            1, 8, 1, /* 1611: pointer.struct.X509_val_st */
            	1616, 0,
            0, 16, 2, /* 1616: struct.X509_val_st */
            	1623, 0,
            	1623, 8,
            1, 8, 1, /* 1623: pointer.struct.asn1_string_st */
            	1409, 0,
            1, 8, 1, /* 1628: pointer.struct.X509_pubkey_st */
            	1633, 0,
            0, 24, 3, /* 1633: struct.X509_pubkey_st */
            	1414, 0,
            	1503, 8,
            	1642, 16,
            1, 8, 1, /* 1642: pointer.struct.evp_pkey_st */
            	1647, 0,
            0, 56, 4, /* 1647: struct.evp_pkey_st */
            	1658, 16,
            	1666, 24,
            	1674, 32,
            	2003, 48,
            1, 8, 1, /* 1658: pointer.struct.evp_pkey_asn1_method_st */
            	1663, 0,
            0, 0, 0, /* 1663: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 1666: pointer.struct.engine_st */
            	1671, 0,
            0, 0, 0, /* 1671: struct.engine_st */
            0, 8, 5, /* 1674: union.unknown */
            	93, 0,
            	1687, 0,
            	1846, 0,
            	1927, 0,
            	1995, 0,
            1, 8, 1, /* 1687: pointer.struct.rsa_st */
            	1692, 0,
            0, 168, 17, /* 1692: struct.rsa_st */
            	1729, 16,
            	1666, 24,
            	1784, 32,
            	1784, 40,
            	1784, 48,
            	1784, 56,
            	1784, 64,
            	1784, 72,
            	1784, 80,
            	1784, 88,
            	1802, 96,
            	1824, 120,
            	1824, 128,
            	1824, 136,
            	93, 144,
            	1838, 152,
            	1838, 160,
            1, 8, 1, /* 1729: pointer.struct.rsa_meth_st */
            	1734, 0,
            0, 112, 13, /* 1734: struct.rsa_meth_st */
            	124, 0,
            	1763, 8,
            	1763, 16,
            	1763, 24,
            	1763, 32,
            	1766, 40,
            	1769, 48,
            	1772, 56,
            	1772, 64,
            	93, 80,
            	1775, 88,
            	1778, 96,
            	1781, 104,
            8884097, 8, 0, /* 1763: pointer.func */
            8884097, 8, 0, /* 1766: pointer.func */
            8884097, 8, 0, /* 1769: pointer.func */
            8884097, 8, 0, /* 1772: pointer.func */
            8884097, 8, 0, /* 1775: pointer.func */
            8884097, 8, 0, /* 1778: pointer.func */
            8884097, 8, 0, /* 1781: pointer.func */
            1, 8, 1, /* 1784: pointer.struct.bignum_st */
            	1789, 0,
            0, 24, 1, /* 1789: struct.bignum_st */
            	1794, 0,
            1, 8, 1, /* 1794: pointer.unsigned int */
            	1799, 0,
            0, 4, 0, /* 1799: unsigned int */
            0, 16, 1, /* 1802: struct.crypto_ex_data_st */
            	1807, 0,
            1, 8, 1, /* 1807: pointer.struct.stack_st_void */
            	1812, 0,
            0, 32, 1, /* 1812: struct.stack_st_void */
            	1817, 0,
            0, 32, 2, /* 1817: struct.stack_st */
            	885, 8,
            	360, 24,
            1, 8, 1, /* 1824: pointer.struct.bn_mont_ctx_st */
            	1829, 0,
            0, 96, 3, /* 1829: struct.bn_mont_ctx_st */
            	1789, 8,
            	1789, 32,
            	1789, 56,
            1, 8, 1, /* 1838: pointer.struct.bn_blinding_st */
            	1843, 0,
            0, 0, 0, /* 1843: struct.bn_blinding_st */
            1, 8, 1, /* 1846: pointer.struct.dsa_st */
            	1851, 0,
            0, 136, 11, /* 1851: struct.dsa_st */
            	1784, 24,
            	1784, 32,
            	1784, 40,
            	1784, 48,
            	1784, 56,
            	1784, 64,
            	1784, 72,
            	1824, 88,
            	1802, 104,
            	1876, 120,
            	1666, 128,
            1, 8, 1, /* 1876: pointer.struct.dsa_method */
            	1881, 0,
            0, 96, 11, /* 1881: struct.dsa_method */
            	124, 0,
            	1906, 8,
            	1909, 16,
            	1912, 24,
            	1915, 32,
            	1918, 40,
            	1921, 48,
            	1921, 56,
            	93, 72,
            	1924, 80,
            	1921, 88,
            8884097, 8, 0, /* 1906: pointer.func */
            8884097, 8, 0, /* 1909: pointer.func */
            8884097, 8, 0, /* 1912: pointer.func */
            8884097, 8, 0, /* 1915: pointer.func */
            8884097, 8, 0, /* 1918: pointer.func */
            8884097, 8, 0, /* 1921: pointer.func */
            8884097, 8, 0, /* 1924: pointer.func */
            1, 8, 1, /* 1927: pointer.struct.dh_st */
            	1932, 0,
            0, 144, 12, /* 1932: struct.dh_st */
            	1784, 8,
            	1784, 16,
            	1784, 32,
            	1784, 40,
            	1824, 56,
            	1784, 64,
            	1784, 72,
            	200, 80,
            	1784, 96,
            	1802, 112,
            	1959, 128,
            	1666, 136,
            1, 8, 1, /* 1959: pointer.struct.dh_method */
            	1964, 0,
            0, 72, 8, /* 1964: struct.dh_method */
            	124, 0,
            	1983, 8,
            	1986, 16,
            	1989, 24,
            	1983, 32,
            	1983, 40,
            	93, 56,
            	1992, 64,
            8884097, 8, 0, /* 1983: pointer.func */
            8884097, 8, 0, /* 1986: pointer.func */
            8884097, 8, 0, /* 1989: pointer.func */
            8884097, 8, 0, /* 1992: pointer.func */
            1, 8, 1, /* 1995: pointer.struct.ec_key_st */
            	2000, 0,
            0, 0, 0, /* 2000: struct.ec_key_st */
            1, 8, 1, /* 2003: pointer.struct.stack_st_X509_ATTRIBUTE */
            	2008, 0,
            0, 32, 2, /* 2008: struct.stack_st_fake_X509_ATTRIBUTE */
            	2015, 8,
            	360, 24,
            8884099, 8, 2, /* 2015: pointer_to_array_of_pointers_to_stack */
            	2022, 0,
            	357, 20,
            0, 8, 1, /* 2022: pointer.X509_ATTRIBUTE */
            	2027, 0,
            0, 0, 1, /* 2027: X509_ATTRIBUTE */
            	2032, 0,
            0, 24, 2, /* 2032: struct.x509_attributes_st */
            	2039, 0,
            	2053, 16,
            1, 8, 1, /* 2039: pointer.struct.asn1_object_st */
            	2044, 0,
            0, 40, 3, /* 2044: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            0, 8, 3, /* 2053: union.unknown */
            	93, 0,
            	971, 0,
            	2062, 0,
            1, 8, 1, /* 2062: pointer.struct.asn1_type_st */
            	2067, 0,
            0, 16, 1, /* 2067: struct.asn1_type_st */
            	2072, 8,
            0, 8, 20, /* 2072: union.unknown */
            	93, 0,
            	2115, 0,
            	2039, 0,
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
            	2185, 0,
            	2190, 0,
            	2115, 0,
            	2115, 0,
            	611, 0,
            1, 8, 1, /* 2115: pointer.struct.asn1_string_st */
            	2120, 0,
            0, 24, 1, /* 2120: struct.asn1_string_st */
            	200, 8,
            1, 8, 1, /* 2125: pointer.struct.asn1_string_st */
            	2120, 0,
            1, 8, 1, /* 2130: pointer.struct.asn1_string_st */
            	2120, 0,
            1, 8, 1, /* 2135: pointer.struct.asn1_string_st */
            	2120, 0,
            1, 8, 1, /* 2140: pointer.struct.asn1_string_st */
            	2120, 0,
            1, 8, 1, /* 2145: pointer.struct.asn1_string_st */
            	2120, 0,
            1, 8, 1, /* 2150: pointer.struct.asn1_string_st */
            	2120, 0,
            1, 8, 1, /* 2155: pointer.struct.asn1_string_st */
            	2120, 0,
            1, 8, 1, /* 2160: pointer.struct.asn1_string_st */
            	2120, 0,
            1, 8, 1, /* 2165: pointer.struct.asn1_string_st */
            	2120, 0,
            1, 8, 1, /* 2170: pointer.struct.asn1_string_st */
            	2120, 0,
            1, 8, 1, /* 2175: pointer.struct.asn1_string_st */
            	2120, 0,
            1, 8, 1, /* 2180: pointer.struct.asn1_string_st */
            	2120, 0,
            1, 8, 1, /* 2185: pointer.struct.asn1_string_st */
            	2120, 0,
            1, 8, 1, /* 2190: pointer.struct.asn1_string_st */
            	2120, 0,
            1, 8, 1, /* 2195: pointer.struct.stack_st_X509_EXTENSION */
            	2200, 0,
            0, 32, 2, /* 2200: struct.stack_st_fake_X509_EXTENSION */
            	2207, 8,
            	360, 24,
            8884099, 8, 2, /* 2207: pointer_to_array_of_pointers_to_stack */
            	2214, 0,
            	357, 20,
            0, 8, 1, /* 2214: pointer.X509_EXTENSION */
            	703, 0,
            0, 24, 1, /* 2219: struct.ASN1_ENCODING_st */
            	200, 0,
            1, 8, 1, /* 2224: pointer.struct.AUTHORITY_KEYID_st */
            	2229, 0,
            0, 0, 0, /* 2229: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 2232: pointer.struct.X509_POLICY_CACHE_st */
            	2237, 0,
            0, 0, 0, /* 2237: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 2240: pointer.struct.stack_st_DIST_POINT */
            	2245, 0,
            0, 32, 2, /* 2245: struct.stack_st_fake_DIST_POINT */
            	2252, 8,
            	360, 24,
            8884099, 8, 2, /* 2252: pointer_to_array_of_pointers_to_stack */
            	2259, 0,
            	357, 20,
            0, 8, 1, /* 2259: pointer.DIST_POINT */
            	2264, 0,
            0, 0, 1, /* 2264: DIST_POINT */
            	2269, 0,
            0, 32, 3, /* 2269: struct.DIST_POINT_st */
            	7, 0,
            	433, 8,
            	26, 16,
            1, 8, 1, /* 2278: pointer.struct.stack_st_GENERAL_NAME */
            	2283, 0,
            0, 32, 2, /* 2283: struct.stack_st_fake_GENERAL_NAME */
            	2290, 8,
            	360, 24,
            8884099, 8, 2, /* 2290: pointer_to_array_of_pointers_to_stack */
            	2297, 0,
            	357, 20,
            0, 8, 1, /* 2297: pointer.GENERAL_NAME */
            	50, 0,
            1, 8, 1, /* 2302: pointer.struct.NAME_CONSTRAINTS_st */
            	2307, 0,
            0, 0, 0, /* 2307: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 2310: pointer.struct.x509_cert_aux_st */
            	2315, 0,
            0, 40, 5, /* 2315: struct.x509_cert_aux_st */
            	2328, 0,
            	2328, 8,
            	1558, 16,
            	1508, 24,
            	2357, 32,
            1, 8, 1, /* 2328: pointer.struct.stack_st_ASN1_OBJECT */
            	2333, 0,
            0, 32, 2, /* 2333: struct.stack_st_fake_ASN1_OBJECT */
            	2340, 8,
            	360, 24,
            8884099, 8, 2, /* 2340: pointer_to_array_of_pointers_to_stack */
            	2347, 0,
            	357, 20,
            0, 8, 1, /* 2347: pointer.ASN1_OBJECT */
            	2352, 0,
            0, 0, 1, /* 2352: ASN1_OBJECT */
            	1063, 0,
            1, 8, 1, /* 2357: pointer.struct.stack_st_X509_ALGOR */
            	2362, 0,
            0, 32, 2, /* 2362: struct.stack_st_fake_X509_ALGOR */
            	2369, 8,
            	360, 24,
            8884099, 8, 2, /* 2369: pointer_to_array_of_pointers_to_stack */
            	2376, 0,
            	357, 20,
            0, 8, 1, /* 2376: pointer.X509_ALGOR */
            	2381, 0,
            0, 0, 1, /* 2381: X509_ALGOR */
            	2386, 0,
            0, 16, 2, /* 2386: struct.X509_algor_st */
            	1158, 0,
            	2393, 8,
            1, 8, 1, /* 2393: pointer.struct.asn1_type_st */
            	2398, 0,
            0, 16, 1, /* 2398: struct.asn1_type_st */
            	2403, 8,
            0, 8, 20, /* 2403: union.unknown */
            	93, 0,
            	1150, 0,
            	1158, 0,
            	2446, 0,
            	2451, 0,
            	2456, 0,
            	2461, 0,
            	963, 0,
            	2466, 0,
            	958, 0,
            	2471, 0,
            	948, 0,
            	2476, 0,
            	2481, 0,
            	2486, 0,
            	2491, 0,
            	2496, 0,
            	1150, 0,
            	1150, 0,
            	611, 0,
            1, 8, 1, /* 2446: pointer.struct.asn1_string_st */
            	953, 0,
            1, 8, 1, /* 2451: pointer.struct.asn1_string_st */
            	953, 0,
            1, 8, 1, /* 2456: pointer.struct.asn1_string_st */
            	953, 0,
            1, 8, 1, /* 2461: pointer.struct.asn1_string_st */
            	953, 0,
            1, 8, 1, /* 2466: pointer.struct.asn1_string_st */
            	953, 0,
            1, 8, 1, /* 2471: pointer.struct.asn1_string_st */
            	953, 0,
            1, 8, 1, /* 2476: pointer.struct.asn1_string_st */
            	953, 0,
            1, 8, 1, /* 2481: pointer.struct.asn1_string_st */
            	953, 0,
            1, 8, 1, /* 2486: pointer.struct.asn1_string_st */
            	953, 0,
            1, 8, 1, /* 2491: pointer.struct.asn1_string_st */
            	953, 0,
            1, 8, 1, /* 2496: pointer.struct.asn1_string_st */
            	953, 0,
            1, 8, 1, /* 2501: pointer.struct.X509_crl_st */
            	2506, 0,
            0, 120, 10, /* 2506: struct.X509_crl_st */
            	2529, 0,
            	1414, 8,
            	1503, 16,
            	2224, 32,
            	2577, 40,
            	1404, 56,
            	1404, 64,
            	844, 96,
            	890, 104,
            	898, 112,
            1, 8, 1, /* 2529: pointer.struct.X509_crl_info_st */
            	2534, 0,
            0, 80, 8, /* 2534: struct.X509_crl_info_st */
            	1404, 0,
            	1414, 8,
            	1563, 16,
            	1623, 24,
            	1623, 32,
            	2553, 40,
            	2195, 48,
            	2219, 56,
            1, 8, 1, /* 2553: pointer.struct.stack_st_X509_REVOKED */
            	2558, 0,
            0, 32, 2, /* 2558: struct.stack_st_fake_X509_REVOKED */
            	2565, 8,
            	360, 24,
            8884099, 8, 2, /* 2565: pointer_to_array_of_pointers_to_stack */
            	2572, 0,
            	357, 20,
            0, 8, 1, /* 2572: pointer.X509_REVOKED */
            	648, 0,
            1, 8, 1, /* 2577: pointer.struct.ISSUING_DIST_POINT_st */
            	2582, 0,
            0, 0, 0, /* 2582: struct.ISSUING_DIST_POINT_st */
            1, 8, 1, /* 2585: pointer.struct.X509_VERIFY_PARAM_st */
            	2590, 0,
            0, 56, 2, /* 2590: struct.X509_VERIFY_PARAM_st */
            	93, 0,
            	2328, 48,
            8884097, 8, 0, /* 2597: pointer.func */
            8884097, 8, 0, /* 2600: pointer.func */
            8884097, 8, 0, /* 2603: pointer.func */
            8884097, 8, 0, /* 2606: pointer.func */
            8884097, 8, 0, /* 2609: pointer.func */
            8884097, 8, 0, /* 2612: pointer.func */
            8884097, 8, 0, /* 2615: pointer.func */
            8884097, 8, 0, /* 2618: pointer.func */
            8884097, 8, 0, /* 2621: pointer.func */
            1, 8, 1, /* 2624: pointer.struct.asn1_string_st */
            	2629, 0,
            0, 24, 1, /* 2629: struct.asn1_string_st */
            	200, 8,
            1, 8, 1, /* 2634: pointer.struct.ASN1_VALUE_st */
            	2639, 0,
            0, 0, 0, /* 2639: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2642: pointer.struct.asn1_string_st */
            	2629, 0,
            1, 8, 1, /* 2647: pointer.struct.x509_st */
            	2652, 0,
            0, 184, 12, /* 2652: struct.x509_st */
            	2679, 0,
            	467, 8,
            	433, 16,
            	93, 32,
            	2871, 40,
            	556, 104,
            	825, 112,
            	2232, 120,
            	3080, 128,
            	3104, 136,
            	3128, 144,
            	3183, 176,
            1, 8, 1, /* 2679: pointer.struct.x509_cinf_st */
            	2684, 0,
            0, 104, 11, /* 2684: struct.x509_cinf_st */
            	462, 0,
            	462, 8,
            	467, 16,
            	409, 24,
            	2709, 32,
            	409, 40,
            	2721, 48,
            	433, 56,
            	433, 64,
            	763, 72,
            	787, 80,
            1, 8, 1, /* 2709: pointer.struct.X509_val_st */
            	2714, 0,
            0, 16, 2, /* 2714: struct.X509_val_st */
            	619, 0,
            	619, 8,
            1, 8, 1, /* 2721: pointer.struct.X509_pubkey_st */
            	2726, 0,
            0, 24, 3, /* 2726: struct.X509_pubkey_st */
            	467, 0,
            	433, 8,
            	2735, 16,
            1, 8, 1, /* 2735: pointer.struct.evp_pkey_st */
            	2740, 0,
            0, 56, 4, /* 2740: struct.evp_pkey_st */
            	1658, 16,
            	1666, 24,
            	2751, 32,
            	3056, 48,
            0, 8, 5, /* 2751: union.unknown */
            	93, 0,
            	2764, 0,
            	2907, 0,
            	2988, 0,
            	1995, 0,
            1, 8, 1, /* 2764: pointer.struct.rsa_st */
            	2769, 0,
            0, 168, 17, /* 2769: struct.rsa_st */
            	2806, 16,
            	1666, 24,
            	2861, 32,
            	2861, 40,
            	2861, 48,
            	2861, 56,
            	2861, 64,
            	2861, 72,
            	2861, 80,
            	2861, 88,
            	2871, 96,
            	2893, 120,
            	2893, 128,
            	2893, 136,
            	93, 144,
            	1838, 152,
            	1838, 160,
            1, 8, 1, /* 2806: pointer.struct.rsa_meth_st */
            	2811, 0,
            0, 112, 13, /* 2811: struct.rsa_meth_st */
            	124, 0,
            	2840, 8,
            	2840, 16,
            	2840, 24,
            	2840, 32,
            	2843, 40,
            	2846, 48,
            	2849, 56,
            	2849, 64,
            	93, 80,
            	2852, 88,
            	2855, 96,
            	2858, 104,
            8884097, 8, 0, /* 2840: pointer.func */
            8884097, 8, 0, /* 2843: pointer.func */
            8884097, 8, 0, /* 2846: pointer.func */
            8884097, 8, 0, /* 2849: pointer.func */
            8884097, 8, 0, /* 2852: pointer.func */
            8884097, 8, 0, /* 2855: pointer.func */
            8884097, 8, 0, /* 2858: pointer.func */
            1, 8, 1, /* 2861: pointer.struct.bignum_st */
            	2866, 0,
            0, 24, 1, /* 2866: struct.bignum_st */
            	1794, 0,
            0, 16, 1, /* 2871: struct.crypto_ex_data_st */
            	2876, 0,
            1, 8, 1, /* 2876: pointer.struct.stack_st_void */
            	2881, 0,
            0, 32, 1, /* 2881: struct.stack_st_void */
            	2886, 0,
            0, 32, 2, /* 2886: struct.stack_st */
            	885, 8,
            	360, 24,
            1, 8, 1, /* 2893: pointer.struct.bn_mont_ctx_st */
            	2898, 0,
            0, 96, 3, /* 2898: struct.bn_mont_ctx_st */
            	2866, 8,
            	2866, 32,
            	2866, 56,
            1, 8, 1, /* 2907: pointer.struct.dsa_st */
            	2912, 0,
            0, 136, 11, /* 2912: struct.dsa_st */
            	2861, 24,
            	2861, 32,
            	2861, 40,
            	2861, 48,
            	2861, 56,
            	2861, 64,
            	2861, 72,
            	2893, 88,
            	2871, 104,
            	2937, 120,
            	1666, 128,
            1, 8, 1, /* 2937: pointer.struct.dsa_method */
            	2942, 0,
            0, 96, 11, /* 2942: struct.dsa_method */
            	124, 0,
            	2967, 8,
            	2970, 16,
            	2973, 24,
            	2976, 32,
            	2979, 40,
            	2982, 48,
            	2982, 56,
            	93, 72,
            	2985, 80,
            	2982, 88,
            8884097, 8, 0, /* 2967: pointer.func */
            8884097, 8, 0, /* 2970: pointer.func */
            8884097, 8, 0, /* 2973: pointer.func */
            8884097, 8, 0, /* 2976: pointer.func */
            8884097, 8, 0, /* 2979: pointer.func */
            8884097, 8, 0, /* 2982: pointer.func */
            8884097, 8, 0, /* 2985: pointer.func */
            1, 8, 1, /* 2988: pointer.struct.dh_st */
            	2993, 0,
            0, 144, 12, /* 2993: struct.dh_st */
            	2861, 8,
            	2861, 16,
            	2861, 32,
            	2861, 40,
            	2893, 56,
            	2861, 64,
            	2861, 72,
            	200, 80,
            	2861, 96,
            	2871, 112,
            	3020, 128,
            	1666, 136,
            1, 8, 1, /* 3020: pointer.struct.dh_method */
            	3025, 0,
            0, 72, 8, /* 3025: struct.dh_method */
            	124, 0,
            	3044, 8,
            	3047, 16,
            	3050, 24,
            	3044, 32,
            	3044, 40,
            	93, 56,
            	3053, 64,
            8884097, 8, 0, /* 3044: pointer.func */
            8884097, 8, 0, /* 3047: pointer.func */
            8884097, 8, 0, /* 3050: pointer.func */
            8884097, 8, 0, /* 3053: pointer.func */
            1, 8, 1, /* 3056: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3061, 0,
            0, 32, 2, /* 3061: struct.stack_st_fake_X509_ATTRIBUTE */
            	3068, 8,
            	360, 24,
            8884099, 8, 2, /* 3068: pointer_to_array_of_pointers_to_stack */
            	3075, 0,
            	357, 20,
            0, 8, 1, /* 3075: pointer.X509_ATTRIBUTE */
            	2027, 0,
            1, 8, 1, /* 3080: pointer.struct.stack_st_DIST_POINT */
            	3085, 0,
            0, 32, 2, /* 3085: struct.stack_st_fake_DIST_POINT */
            	3092, 8,
            	360, 24,
            8884099, 8, 2, /* 3092: pointer_to_array_of_pointers_to_stack */
            	3099, 0,
            	357, 20,
            0, 8, 1, /* 3099: pointer.DIST_POINT */
            	2264, 0,
            1, 8, 1, /* 3104: pointer.struct.stack_st_GENERAL_NAME */
            	3109, 0,
            0, 32, 2, /* 3109: struct.stack_st_fake_GENERAL_NAME */
            	3116, 8,
            	360, 24,
            8884099, 8, 2, /* 3116: pointer_to_array_of_pointers_to_stack */
            	3123, 0,
            	357, 20,
            0, 8, 1, /* 3123: pointer.GENERAL_NAME */
            	50, 0,
            1, 8, 1, /* 3128: pointer.struct.NAME_CONSTRAINTS_st */
            	3133, 0,
            0, 16, 2, /* 3133: struct.NAME_CONSTRAINTS_st */
            	3140, 0,
            	3140, 8,
            1, 8, 1, /* 3140: pointer.struct.stack_st_GENERAL_SUBTREE */
            	3145, 0,
            0, 32, 2, /* 3145: struct.stack_st_fake_GENERAL_SUBTREE */
            	3152, 8,
            	360, 24,
            8884099, 8, 2, /* 3152: pointer_to_array_of_pointers_to_stack */
            	3159, 0,
            	357, 20,
            0, 8, 1, /* 3159: pointer.GENERAL_SUBTREE */
            	3164, 0,
            0, 0, 1, /* 3164: GENERAL_SUBTREE */
            	3169, 0,
            0, 24, 3, /* 3169: struct.GENERAL_SUBTREE_st */
            	3178, 0,
            	205, 8,
            	205, 16,
            1, 8, 1, /* 3178: pointer.struct.GENERAL_NAME_st */
            	55, 0,
            1, 8, 1, /* 3183: pointer.struct.x509_cert_aux_st */
            	3188, 0,
            0, 40, 5, /* 3188: struct.x509_cert_aux_st */
            	3201, 0,
            	3201, 8,
            	606, 16,
            	556, 24,
            	3225, 32,
            1, 8, 1, /* 3201: pointer.struct.stack_st_ASN1_OBJECT */
            	3206, 0,
            0, 32, 2, /* 3206: struct.stack_st_fake_ASN1_OBJECT */
            	3213, 8,
            	360, 24,
            8884099, 8, 2, /* 3213: pointer_to_array_of_pointers_to_stack */
            	3220, 0,
            	357, 20,
            0, 8, 1, /* 3220: pointer.ASN1_OBJECT */
            	2352, 0,
            1, 8, 1, /* 3225: pointer.struct.stack_st_X509_ALGOR */
            	3230, 0,
            0, 32, 2, /* 3230: struct.stack_st_fake_X509_ALGOR */
            	3237, 8,
            	360, 24,
            8884099, 8, 2, /* 3237: pointer_to_array_of_pointers_to_stack */
            	3244, 0,
            	357, 20,
            0, 8, 1, /* 3244: pointer.X509_ALGOR */
            	2381, 0,
            0, 144, 12, /* 3249: struct.dh_st */
            	3276, 8,
            	3276, 16,
            	3276, 32,
            	3276, 40,
            	3286, 56,
            	3276, 64,
            	3276, 72,
            	200, 80,
            	3276, 96,
            	3300, 112,
            	3322, 128,
            	3358, 136,
            1, 8, 1, /* 3276: pointer.struct.bignum_st */
            	3281, 0,
            0, 24, 1, /* 3281: struct.bignum_st */
            	1794, 0,
            1, 8, 1, /* 3286: pointer.struct.bn_mont_ctx_st */
            	3291, 0,
            0, 96, 3, /* 3291: struct.bn_mont_ctx_st */
            	3281, 8,
            	3281, 32,
            	3281, 56,
            0, 16, 1, /* 3300: struct.crypto_ex_data_st */
            	3305, 0,
            1, 8, 1, /* 3305: pointer.struct.stack_st_void */
            	3310, 0,
            0, 32, 1, /* 3310: struct.stack_st_void */
            	3315, 0,
            0, 32, 2, /* 3315: struct.stack_st */
            	885, 8,
            	360, 24,
            1, 8, 1, /* 3322: pointer.struct.dh_method */
            	3327, 0,
            0, 72, 8, /* 3327: struct.dh_method */
            	124, 0,
            	3346, 8,
            	3349, 16,
            	3352, 24,
            	3346, 32,
            	3346, 40,
            	93, 56,
            	3355, 64,
            8884097, 8, 0, /* 3346: pointer.func */
            8884097, 8, 0, /* 3349: pointer.func */
            8884097, 8, 0, /* 3352: pointer.func */
            8884097, 8, 0, /* 3355: pointer.func */
            1, 8, 1, /* 3358: pointer.struct.engine_st */
            	3363, 0,
            0, 0, 0, /* 3363: struct.engine_st */
            1, 8, 1, /* 3366: pointer.struct.asn1_string_st */
            	943, 0,
            8884097, 8, 0, /* 3371: pointer.func */
            0, 104, 11, /* 3374: struct.x509_cinf_st */
            	3399, 0,
            	3399, 8,
            	3404, 16,
            	3543, 24,
            	3591, 32,
            	3543, 40,
            	3608, 48,
            	3493, 56,
            	3493, 64,
            	3879, 72,
            	3903, 80,
            1, 8, 1, /* 3399: pointer.struct.asn1_string_st */
            	2629, 0,
            1, 8, 1, /* 3404: pointer.struct.X509_algor_st */
            	3409, 0,
            0, 16, 2, /* 3409: struct.X509_algor_st */
            	3416, 0,
            	3430, 8,
            1, 8, 1, /* 3416: pointer.struct.asn1_object_st */
            	3421, 0,
            0, 40, 3, /* 3421: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            1, 8, 1, /* 3430: pointer.struct.asn1_type_st */
            	3435, 0,
            0, 16, 1, /* 3435: struct.asn1_type_st */
            	3440, 8,
            0, 8, 20, /* 3440: union.unknown */
            	93, 0,
            	3483, 0,
            	3416, 0,
            	3399, 0,
            	3488, 0,
            	3493, 0,
            	3498, 0,
            	3503, 0,
            	3508, 0,
            	3513, 0,
            	3518, 0,
            	3523, 0,
            	3528, 0,
            	3533, 0,
            	3538, 0,
            	2624, 0,
            	2642, 0,
            	3483, 0,
            	3483, 0,
            	2634, 0,
            1, 8, 1, /* 3483: pointer.struct.asn1_string_st */
            	2629, 0,
            1, 8, 1, /* 3488: pointer.struct.asn1_string_st */
            	2629, 0,
            1, 8, 1, /* 3493: pointer.struct.asn1_string_st */
            	2629, 0,
            1, 8, 1, /* 3498: pointer.struct.asn1_string_st */
            	2629, 0,
            1, 8, 1, /* 3503: pointer.struct.asn1_string_st */
            	2629, 0,
            1, 8, 1, /* 3508: pointer.struct.asn1_string_st */
            	2629, 0,
            1, 8, 1, /* 3513: pointer.struct.asn1_string_st */
            	2629, 0,
            1, 8, 1, /* 3518: pointer.struct.asn1_string_st */
            	2629, 0,
            1, 8, 1, /* 3523: pointer.struct.asn1_string_st */
            	2629, 0,
            1, 8, 1, /* 3528: pointer.struct.asn1_string_st */
            	2629, 0,
            1, 8, 1, /* 3533: pointer.struct.asn1_string_st */
            	2629, 0,
            1, 8, 1, /* 3538: pointer.struct.asn1_string_st */
            	2629, 0,
            1, 8, 1, /* 3543: pointer.struct.X509_name_st */
            	3548, 0,
            0, 40, 3, /* 3548: struct.X509_name_st */
            	3557, 0,
            	3581, 16,
            	200, 24,
            1, 8, 1, /* 3557: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3562, 0,
            0, 32, 2, /* 3562: struct.stack_st_fake_X509_NAME_ENTRY */
            	3569, 8,
            	360, 24,
            8884099, 8, 2, /* 3569: pointer_to_array_of_pointers_to_stack */
            	3576, 0,
            	357, 20,
            0, 8, 1, /* 3576: pointer.X509_NAME_ENTRY */
            	321, 0,
            1, 8, 1, /* 3581: pointer.struct.buf_mem_st */
            	3586, 0,
            0, 24, 1, /* 3586: struct.buf_mem_st */
            	93, 8,
            1, 8, 1, /* 3591: pointer.struct.X509_val_st */
            	3596, 0,
            0, 16, 2, /* 3596: struct.X509_val_st */
            	3603, 0,
            	3603, 8,
            1, 8, 1, /* 3603: pointer.struct.asn1_string_st */
            	2629, 0,
            1, 8, 1, /* 3608: pointer.struct.X509_pubkey_st */
            	3613, 0,
            0, 24, 3, /* 3613: struct.X509_pubkey_st */
            	3404, 0,
            	3493, 8,
            	3622, 16,
            1, 8, 1, /* 3622: pointer.struct.evp_pkey_st */
            	3627, 0,
            0, 56, 4, /* 3627: struct.evp_pkey_st */
            	3638, 16,
            	3358, 24,
            	3646, 32,
            	3855, 48,
            1, 8, 1, /* 3638: pointer.struct.evp_pkey_asn1_method_st */
            	3643, 0,
            0, 0, 0, /* 3643: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 3646: union.unknown */
            	93, 0,
            	3659, 0,
            	3764, 0,
            	3842, 0,
            	3847, 0,
            1, 8, 1, /* 3659: pointer.struct.rsa_st */
            	3664, 0,
            0, 168, 17, /* 3664: struct.rsa_st */
            	3701, 16,
            	3358, 24,
            	3276, 32,
            	3276, 40,
            	3276, 48,
            	3276, 56,
            	3276, 64,
            	3276, 72,
            	3276, 80,
            	3276, 88,
            	3300, 96,
            	3286, 120,
            	3286, 128,
            	3286, 136,
            	93, 144,
            	3756, 152,
            	3756, 160,
            1, 8, 1, /* 3701: pointer.struct.rsa_meth_st */
            	3706, 0,
            0, 112, 13, /* 3706: struct.rsa_meth_st */
            	124, 0,
            	3735, 8,
            	3735, 16,
            	3735, 24,
            	3735, 32,
            	3738, 40,
            	3741, 48,
            	3744, 56,
            	3744, 64,
            	93, 80,
            	3747, 88,
            	3750, 96,
            	3753, 104,
            8884097, 8, 0, /* 3735: pointer.func */
            8884097, 8, 0, /* 3738: pointer.func */
            8884097, 8, 0, /* 3741: pointer.func */
            8884097, 8, 0, /* 3744: pointer.func */
            8884097, 8, 0, /* 3747: pointer.func */
            8884097, 8, 0, /* 3750: pointer.func */
            8884097, 8, 0, /* 3753: pointer.func */
            1, 8, 1, /* 3756: pointer.struct.bn_blinding_st */
            	3761, 0,
            0, 0, 0, /* 3761: struct.bn_blinding_st */
            1, 8, 1, /* 3764: pointer.struct.dsa_st */
            	3769, 0,
            0, 136, 11, /* 3769: struct.dsa_st */
            	3276, 24,
            	3276, 32,
            	3276, 40,
            	3276, 48,
            	3276, 56,
            	3276, 64,
            	3276, 72,
            	3286, 88,
            	3300, 104,
            	3794, 120,
            	3358, 128,
            1, 8, 1, /* 3794: pointer.struct.dsa_method */
            	3799, 0,
            0, 96, 11, /* 3799: struct.dsa_method */
            	124, 0,
            	3824, 8,
            	3827, 16,
            	3830, 24,
            	3371, 32,
            	3833, 40,
            	3836, 48,
            	3836, 56,
            	93, 72,
            	3839, 80,
            	3836, 88,
            8884097, 8, 0, /* 3824: pointer.func */
            8884097, 8, 0, /* 3827: pointer.func */
            8884097, 8, 0, /* 3830: pointer.func */
            8884097, 8, 0, /* 3833: pointer.func */
            8884097, 8, 0, /* 3836: pointer.func */
            8884097, 8, 0, /* 3839: pointer.func */
            1, 8, 1, /* 3842: pointer.struct.dh_st */
            	3249, 0,
            1, 8, 1, /* 3847: pointer.struct.ec_key_st */
            	3852, 0,
            0, 0, 0, /* 3852: struct.ec_key_st */
            1, 8, 1, /* 3855: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3860, 0,
            0, 32, 2, /* 3860: struct.stack_st_fake_X509_ATTRIBUTE */
            	3867, 8,
            	360, 24,
            8884099, 8, 2, /* 3867: pointer_to_array_of_pointers_to_stack */
            	3874, 0,
            	357, 20,
            0, 8, 1, /* 3874: pointer.X509_ATTRIBUTE */
            	2027, 0,
            1, 8, 1, /* 3879: pointer.struct.stack_st_X509_EXTENSION */
            	3884, 0,
            0, 32, 2, /* 3884: struct.stack_st_fake_X509_EXTENSION */
            	3891, 8,
            	360, 24,
            8884099, 8, 2, /* 3891: pointer_to_array_of_pointers_to_stack */
            	3898, 0,
            	357, 20,
            0, 8, 1, /* 3898: pointer.X509_EXTENSION */
            	703, 0,
            0, 24, 1, /* 3903: struct.ASN1_ENCODING_st */
            	200, 0,
            0, 0, 0, /* 3908: struct.X509_POLICY_CACHE_st */
            0, 184, 12, /* 3911: struct.x509_st */
            	3938, 0,
            	3404, 8,
            	3493, 16,
            	93, 32,
            	3300, 40,
            	3498, 104,
            	3943, 112,
            	3951, 120,
            	3956, 128,
            	3980, 136,
            	4004, 144,
            	4012, 176,
            1, 8, 1, /* 3938: pointer.struct.x509_cinf_st */
            	3374, 0,
            1, 8, 1, /* 3943: pointer.struct.AUTHORITY_KEYID_st */
            	3948, 0,
            0, 0, 0, /* 3948: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 3951: pointer.struct.X509_POLICY_CACHE_st */
            	3908, 0,
            1, 8, 1, /* 3956: pointer.struct.stack_st_DIST_POINT */
            	3961, 0,
            0, 32, 2, /* 3961: struct.stack_st_fake_DIST_POINT */
            	3968, 8,
            	360, 24,
            8884099, 8, 2, /* 3968: pointer_to_array_of_pointers_to_stack */
            	3975, 0,
            	357, 20,
            0, 8, 1, /* 3975: pointer.DIST_POINT */
            	2264, 0,
            1, 8, 1, /* 3980: pointer.struct.stack_st_GENERAL_NAME */
            	3985, 0,
            0, 32, 2, /* 3985: struct.stack_st_fake_GENERAL_NAME */
            	3992, 8,
            	360, 24,
            8884099, 8, 2, /* 3992: pointer_to_array_of_pointers_to_stack */
            	3999, 0,
            	357, 20,
            0, 8, 1, /* 3999: pointer.GENERAL_NAME */
            	50, 0,
            1, 8, 1, /* 4004: pointer.struct.NAME_CONSTRAINTS_st */
            	4009, 0,
            0, 0, 0, /* 4009: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 4012: pointer.struct.x509_cert_aux_st */
            	4017, 0,
            0, 40, 5, /* 4017: struct.x509_cert_aux_st */
            	4030, 0,
            	4030, 8,
            	2642, 16,
            	3498, 24,
            	4054, 32,
            1, 8, 1, /* 4030: pointer.struct.stack_st_ASN1_OBJECT */
            	4035, 0,
            0, 32, 2, /* 4035: struct.stack_st_fake_ASN1_OBJECT */
            	4042, 8,
            	360, 24,
            8884099, 8, 2, /* 4042: pointer_to_array_of_pointers_to_stack */
            	4049, 0,
            	357, 20,
            0, 8, 1, /* 4049: pointer.ASN1_OBJECT */
            	2352, 0,
            1, 8, 1, /* 4054: pointer.struct.stack_st_X509_ALGOR */
            	4059, 0,
            0, 32, 2, /* 4059: struct.stack_st_fake_X509_ALGOR */
            	4066, 8,
            	360, 24,
            8884099, 8, 2, /* 4066: pointer_to_array_of_pointers_to_stack */
            	4073, 0,
            	357, 20,
            0, 8, 1, /* 4073: pointer.X509_ALGOR */
            	2381, 0,
            0, 144, 15, /* 4078: struct.x509_store_st */
            	4111, 8,
            	4135, 16,
            	4159, 24,
            	4171, 32,
            	4174, 40,
            	4177, 48,
            	4180, 56,
            	4171, 64,
            	2621, 72,
            	4183, 80,
            	4186, 88,
            	1155, 96,
            	4189, 104,
            	4171, 112,
            	2871, 120,
            1, 8, 1, /* 4111: pointer.struct.stack_st_X509_OBJECT */
            	4116, 0,
            0, 32, 2, /* 4116: struct.stack_st_fake_X509_OBJECT */
            	4123, 8,
            	360, 24,
            8884099, 8, 2, /* 4123: pointer_to_array_of_pointers_to_stack */
            	4130, 0,
            	357, 20,
            0, 8, 1, /* 4130: pointer.X509_OBJECT */
            	1321, 0,
            1, 8, 1, /* 4135: pointer.struct.stack_st_X509_LOOKUP */
            	4140, 0,
            0, 32, 2, /* 4140: struct.stack_st_fake_X509_LOOKUP */
            	4147, 8,
            	360, 24,
            8884099, 8, 2, /* 4147: pointer_to_array_of_pointers_to_stack */
            	4154, 0,
            	357, 20,
            0, 8, 1, /* 4154: pointer.X509_LOOKUP */
            	1196, 0,
            1, 8, 1, /* 4159: pointer.struct.X509_VERIFY_PARAM_st */
            	4164, 0,
            0, 56, 2, /* 4164: struct.X509_VERIFY_PARAM_st */
            	93, 0,
            	3201, 48,
            8884097, 8, 0, /* 4171: pointer.func */
            8884097, 8, 0, /* 4174: pointer.func */
            8884097, 8, 0, /* 4177: pointer.func */
            8884097, 8, 0, /* 4180: pointer.func */
            8884097, 8, 0, /* 4183: pointer.func */
            8884097, 8, 0, /* 4186: pointer.func */
            8884097, 8, 0, /* 4189: pointer.func */
            1, 8, 1, /* 4192: pointer.struct.x509_store_ctx_st */
            	4197, 0,
            0, 248, 25, /* 4197: struct.x509_store_ctx_st */
            	4250, 0,
            	2647, 16,
            	4255, 24,
            	4284, 32,
            	4159, 40,
            	898, 48,
            	4171, 56,
            	4174, 64,
            	4177, 72,
            	4180, 80,
            	4171, 88,
            	2621, 96,
            	4183, 104,
            	4186, 112,
            	4171, 120,
            	1155, 128,
            	4189, 136,
            	4171, 144,
            	4255, 160,
            	904, 168,
            	2647, 192,
            	2647, 200,
            	792, 208,
            	4192, 224,
            	2871, 232,
            1, 8, 1, /* 4250: pointer.struct.x509_store_st */
            	4078, 0,
            1, 8, 1, /* 4255: pointer.struct.stack_st_X509 */
            	4260, 0,
            0, 32, 2, /* 4260: struct.stack_st_fake_X509 */
            	4267, 8,
            	360, 24,
            8884099, 8, 2, /* 4267: pointer_to_array_of_pointers_to_stack */
            	4274, 0,
            	357, 20,
            0, 8, 1, /* 4274: pointer.X509 */
            	4279, 0,
            0, 0, 1, /* 4279: X509 */
            	3911, 0,
            1, 8, 1, /* 4284: pointer.struct.stack_st_X509_CRL */
            	4289, 0,
            0, 32, 2, /* 4289: struct.stack_st_fake_X509_CRL */
            	4296, 8,
            	360, 24,
            8884099, 8, 2, /* 4296: pointer_to_array_of_pointers_to_stack */
            	4303, 0,
            	357, 20,
            0, 8, 1, /* 4303: pointer.X509_CRL */
            	4308, 0,
            0, 0, 1, /* 4308: X509_CRL */
            	4313, 0,
            0, 120, 10, /* 4313: struct.X509_crl_st */
            	4336, 0,
            	4365, 8,
            	4454, 16,
            	2224, 32,
            	2577, 40,
            	4360, 56,
            	4360, 64,
            	844, 96,
            	890, 104,
            	898, 112,
            1, 8, 1, /* 4336: pointer.struct.X509_crl_info_st */
            	4341, 0,
            0, 80, 8, /* 4341: struct.X509_crl_info_st */
            	4360, 0,
            	4365, 8,
            	4509, 16,
            	938, 24,
            	938, 32,
            	4557, 40,
            	914, 48,
            	909, 56,
            1, 8, 1, /* 4360: pointer.struct.asn1_string_st */
            	943, 0,
            1, 8, 1, /* 4365: pointer.struct.X509_algor_st */
            	4370, 0,
            0, 16, 2, /* 4370: struct.X509_algor_st */
            	4377, 0,
            	4391, 8,
            1, 8, 1, /* 4377: pointer.struct.asn1_object_st */
            	4382, 0,
            0, 40, 3, /* 4382: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            1, 8, 1, /* 4391: pointer.struct.asn1_type_st */
            	4396, 0,
            0, 16, 1, /* 4396: struct.asn1_type_st */
            	4401, 8,
            0, 8, 20, /* 4401: union.unknown */
            	93, 0,
            	4444, 0,
            	4377, 0,
            	4360, 0,
            	4449, 0,
            	4454, 0,
            	3366, 0,
            	4459, 0,
            	4464, 0,
            	4469, 0,
            	4474, 0,
            	4479, 0,
            	4484, 0,
            	4489, 0,
            	4494, 0,
            	4499, 0,
            	4504, 0,
            	4444, 0,
            	4444, 0,
            	611, 0,
            1, 8, 1, /* 4444: pointer.struct.asn1_string_st */
            	943, 0,
            1, 8, 1, /* 4449: pointer.struct.asn1_string_st */
            	943, 0,
            1, 8, 1, /* 4454: pointer.struct.asn1_string_st */
            	943, 0,
            1, 8, 1, /* 4459: pointer.struct.asn1_string_st */
            	943, 0,
            1, 8, 1, /* 4464: pointer.struct.asn1_string_st */
            	943, 0,
            1, 8, 1, /* 4469: pointer.struct.asn1_string_st */
            	943, 0,
            1, 8, 1, /* 4474: pointer.struct.asn1_string_st */
            	943, 0,
            1, 8, 1, /* 4479: pointer.struct.asn1_string_st */
            	943, 0,
            1, 8, 1, /* 4484: pointer.struct.asn1_string_st */
            	943, 0,
            1, 8, 1, /* 4489: pointer.struct.asn1_string_st */
            	943, 0,
            1, 8, 1, /* 4494: pointer.struct.asn1_string_st */
            	943, 0,
            1, 8, 1, /* 4499: pointer.struct.asn1_string_st */
            	943, 0,
            1, 8, 1, /* 4504: pointer.struct.asn1_string_st */
            	943, 0,
            1, 8, 1, /* 4509: pointer.struct.X509_name_st */
            	4514, 0,
            0, 40, 3, /* 4514: struct.X509_name_st */
            	4523, 0,
            	4547, 16,
            	200, 24,
            1, 8, 1, /* 4523: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4528, 0,
            0, 32, 2, /* 4528: struct.stack_st_fake_X509_NAME_ENTRY */
            	4535, 8,
            	360, 24,
            8884099, 8, 2, /* 4535: pointer_to_array_of_pointers_to_stack */
            	4542, 0,
            	357, 20,
            0, 8, 1, /* 4542: pointer.X509_NAME_ENTRY */
            	321, 0,
            1, 8, 1, /* 4547: pointer.struct.buf_mem_st */
            	4552, 0,
            0, 24, 1, /* 4552: struct.buf_mem_st */
            	93, 8,
            1, 8, 1, /* 4557: pointer.struct.stack_st_X509_REVOKED */
            	4562, 0,
            0, 32, 2, /* 4562: struct.stack_st_fake_X509_REVOKED */
            	4569, 8,
            	360, 24,
            8884099, 8, 2, /* 4569: pointer_to_array_of_pointers_to_stack */
            	4576, 0,
            	357, 20,
            0, 8, 1, /* 4576: pointer.X509_REVOKED */
            	648, 0,
            0, 1, 0, /* 4581: char */
        },
        .arg_entity_index = { 4192, },
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

