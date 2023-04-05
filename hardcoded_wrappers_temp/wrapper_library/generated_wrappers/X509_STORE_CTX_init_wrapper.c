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
            1, 8, 1, /* 948: pointer.struct.rsa_st */
            	953, 0,
            0, 168, 17, /* 953: struct.rsa_st */
            	990, 16,
            	1045, 24,
            	1053, 32,
            	1053, 40,
            	1053, 48,
            	1053, 56,
            	1053, 64,
            	1053, 72,
            	1053, 80,
            	1053, 88,
            	1071, 96,
            	1093, 120,
            	1093, 128,
            	1093, 136,
            	93, 144,
            	1107, 152,
            	1107, 160,
            1, 8, 1, /* 990: pointer.struct.rsa_meth_st */
            	995, 0,
            0, 112, 13, /* 995: struct.rsa_meth_st */
            	124, 0,
            	1024, 8,
            	1024, 16,
            	1024, 24,
            	1024, 32,
            	1027, 40,
            	1030, 48,
            	1033, 56,
            	1033, 64,
            	93, 80,
            	1036, 88,
            	1039, 96,
            	1042, 104,
            8884097, 8, 0, /* 1024: pointer.func */
            8884097, 8, 0, /* 1027: pointer.func */
            8884097, 8, 0, /* 1030: pointer.func */
            8884097, 8, 0, /* 1033: pointer.func */
            8884097, 8, 0, /* 1036: pointer.func */
            8884097, 8, 0, /* 1039: pointer.func */
            8884097, 8, 0, /* 1042: pointer.func */
            1, 8, 1, /* 1045: pointer.struct.engine_st */
            	1050, 0,
            0, 0, 0, /* 1050: struct.engine_st */
            1, 8, 1, /* 1053: pointer.struct.bignum_st */
            	1058, 0,
            0, 24, 1, /* 1058: struct.bignum_st */
            	1063, 0,
            1, 8, 1, /* 1063: pointer.unsigned int */
            	1068, 0,
            0, 4, 0, /* 1068: unsigned int */
            0, 16, 1, /* 1071: struct.crypto_ex_data_st */
            	1076, 0,
            1, 8, 1, /* 1076: pointer.struct.stack_st_void */
            	1081, 0,
            0, 32, 1, /* 1081: struct.stack_st_void */
            	1086, 0,
            0, 32, 2, /* 1086: struct.stack_st */
            	885, 8,
            	360, 24,
            1, 8, 1, /* 1093: pointer.struct.bn_mont_ctx_st */
            	1098, 0,
            0, 96, 3, /* 1098: struct.bn_mont_ctx_st */
            	1058, 8,
            	1058, 32,
            	1058, 56,
            1, 8, 1, /* 1107: pointer.struct.bn_blinding_st */
            	1112, 0,
            0, 0, 0, /* 1112: struct.bn_blinding_st */
            1, 8, 1, /* 1115: pointer.struct.x509_cinf_st */
            	1120, 0,
            0, 104, 11, /* 1120: struct.x509_cinf_st */
            	462, 0,
            	462, 8,
            	467, 16,
            	409, 24,
            	1145, 32,
            	409, 40,
            	1157, 48,
            	433, 56,
            	433, 64,
            	763, 72,
            	787, 80,
            1, 8, 1, /* 1145: pointer.struct.X509_val_st */
            	1150, 0,
            0, 16, 2, /* 1150: struct.X509_val_st */
            	619, 0,
            	619, 8,
            1, 8, 1, /* 1157: pointer.struct.X509_pubkey_st */
            	1162, 0,
            0, 24, 3, /* 1162: struct.X509_pubkey_st */
            	467, 0,
            	433, 8,
            	1171, 16,
            1, 8, 1, /* 1171: pointer.struct.evp_pkey_st */
            	1176, 0,
            0, 56, 4, /* 1176: struct.evp_pkey_st */
            	1187, 16,
            	1045, 24,
            	1195, 32,
            	1365, 48,
            1, 8, 1, /* 1187: pointer.struct.evp_pkey_asn1_method_st */
            	1192, 0,
            0, 0, 0, /* 1192: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 1195: union.unknown */
            	93, 0,
            	948, 0,
            	1208, 0,
            	1289, 0,
            	1357, 0,
            1, 8, 1, /* 1208: pointer.struct.dsa_st */
            	1213, 0,
            0, 136, 11, /* 1213: struct.dsa_st */
            	1053, 24,
            	1053, 32,
            	1053, 40,
            	1053, 48,
            	1053, 56,
            	1053, 64,
            	1053, 72,
            	1093, 88,
            	1071, 104,
            	1238, 120,
            	1045, 128,
            1, 8, 1, /* 1238: pointer.struct.dsa_method */
            	1243, 0,
            0, 96, 11, /* 1243: struct.dsa_method */
            	124, 0,
            	1268, 8,
            	1271, 16,
            	1274, 24,
            	1277, 32,
            	1280, 40,
            	1283, 48,
            	1283, 56,
            	93, 72,
            	1286, 80,
            	1283, 88,
            8884097, 8, 0, /* 1268: pointer.func */
            8884097, 8, 0, /* 1271: pointer.func */
            8884097, 8, 0, /* 1274: pointer.func */
            8884097, 8, 0, /* 1277: pointer.func */
            8884097, 8, 0, /* 1280: pointer.func */
            8884097, 8, 0, /* 1283: pointer.func */
            8884097, 8, 0, /* 1286: pointer.func */
            1, 8, 1, /* 1289: pointer.struct.dh_st */
            	1294, 0,
            0, 144, 12, /* 1294: struct.dh_st */
            	1053, 8,
            	1053, 16,
            	1053, 32,
            	1053, 40,
            	1093, 56,
            	1053, 64,
            	1053, 72,
            	200, 80,
            	1053, 96,
            	1071, 112,
            	1321, 128,
            	1045, 136,
            1, 8, 1, /* 1321: pointer.struct.dh_method */
            	1326, 0,
            0, 72, 8, /* 1326: struct.dh_method */
            	124, 0,
            	1345, 8,
            	1348, 16,
            	1351, 24,
            	1345, 32,
            	1345, 40,
            	93, 56,
            	1354, 64,
            8884097, 8, 0, /* 1345: pointer.func */
            8884097, 8, 0, /* 1348: pointer.func */
            8884097, 8, 0, /* 1351: pointer.func */
            8884097, 8, 0, /* 1354: pointer.func */
            1, 8, 1, /* 1357: pointer.struct.ec_key_st */
            	1362, 0,
            0, 0, 0, /* 1362: struct.ec_key_st */
            1, 8, 1, /* 1365: pointer.struct.stack_st_X509_ATTRIBUTE */
            	1370, 0,
            0, 32, 2, /* 1370: struct.stack_st_fake_X509_ATTRIBUTE */
            	1377, 8,
            	360, 24,
            8884099, 8, 2, /* 1377: pointer_to_array_of_pointers_to_stack */
            	1384, 0,
            	357, 20,
            0, 8, 1, /* 1384: pointer.X509_ATTRIBUTE */
            	1389, 0,
            0, 0, 1, /* 1389: X509_ATTRIBUTE */
            	1394, 0,
            0, 24, 2, /* 1394: struct.x509_attributes_st */
            	1401, 0,
            	1415, 16,
            1, 8, 1, /* 1401: pointer.struct.asn1_object_st */
            	1406, 0,
            0, 40, 3, /* 1406: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            0, 8, 3, /* 1415: union.unknown */
            	93, 0,
            	1424, 0,
            	1603, 0,
            1, 8, 1, /* 1424: pointer.struct.stack_st_ASN1_TYPE */
            	1429, 0,
            0, 32, 2, /* 1429: struct.stack_st_fake_ASN1_TYPE */
            	1436, 8,
            	360, 24,
            8884099, 8, 2, /* 1436: pointer_to_array_of_pointers_to_stack */
            	1443, 0,
            	357, 20,
            0, 8, 1, /* 1443: pointer.ASN1_TYPE */
            	1448, 0,
            0, 0, 1, /* 1448: ASN1_TYPE */
            	1453, 0,
            0, 16, 1, /* 1453: struct.asn1_type_st */
            	1458, 8,
            0, 8, 20, /* 1458: union.unknown */
            	93, 0,
            	1501, 0,
            	1511, 0,
            	1525, 0,
            	1530, 0,
            	1535, 0,
            	1540, 0,
            	1545, 0,
            	1550, 0,
            	1555, 0,
            	1560, 0,
            	1565, 0,
            	1570, 0,
            	1575, 0,
            	1580, 0,
            	1585, 0,
            	1590, 0,
            	1501, 0,
            	1501, 0,
            	1595, 0,
            1, 8, 1, /* 1501: pointer.struct.asn1_string_st */
            	1506, 0,
            0, 24, 1, /* 1506: struct.asn1_string_st */
            	200, 8,
            1, 8, 1, /* 1511: pointer.struct.asn1_object_st */
            	1516, 0,
            0, 40, 3, /* 1516: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            1, 8, 1, /* 1525: pointer.struct.asn1_string_st */
            	1506, 0,
            1, 8, 1, /* 1530: pointer.struct.asn1_string_st */
            	1506, 0,
            1, 8, 1, /* 1535: pointer.struct.asn1_string_st */
            	1506, 0,
            1, 8, 1, /* 1540: pointer.struct.asn1_string_st */
            	1506, 0,
            1, 8, 1, /* 1545: pointer.struct.asn1_string_st */
            	1506, 0,
            1, 8, 1, /* 1550: pointer.struct.asn1_string_st */
            	1506, 0,
            1, 8, 1, /* 1555: pointer.struct.asn1_string_st */
            	1506, 0,
            1, 8, 1, /* 1560: pointer.struct.asn1_string_st */
            	1506, 0,
            1, 8, 1, /* 1565: pointer.struct.asn1_string_st */
            	1506, 0,
            1, 8, 1, /* 1570: pointer.struct.asn1_string_st */
            	1506, 0,
            1, 8, 1, /* 1575: pointer.struct.asn1_string_st */
            	1506, 0,
            1, 8, 1, /* 1580: pointer.struct.asn1_string_st */
            	1506, 0,
            1, 8, 1, /* 1585: pointer.struct.asn1_string_st */
            	1506, 0,
            1, 8, 1, /* 1590: pointer.struct.asn1_string_st */
            	1506, 0,
            1, 8, 1, /* 1595: pointer.struct.ASN1_VALUE_st */
            	1600, 0,
            0, 0, 0, /* 1600: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1603: pointer.struct.asn1_type_st */
            	1608, 0,
            0, 16, 1, /* 1608: struct.asn1_type_st */
            	1613, 8,
            0, 8, 20, /* 1613: union.unknown */
            	93, 0,
            	1656, 0,
            	1401, 0,
            	1666, 0,
            	1671, 0,
            	1676, 0,
            	1681, 0,
            	1686, 0,
            	1691, 0,
            	1696, 0,
            	1701, 0,
            	1706, 0,
            	1711, 0,
            	1716, 0,
            	1721, 0,
            	1726, 0,
            	1731, 0,
            	1656, 0,
            	1656, 0,
            	611, 0,
            1, 8, 1, /* 1656: pointer.struct.asn1_string_st */
            	1661, 0,
            0, 24, 1, /* 1661: struct.asn1_string_st */
            	200, 8,
            1, 8, 1, /* 1666: pointer.struct.asn1_string_st */
            	1661, 0,
            1, 8, 1, /* 1671: pointer.struct.asn1_string_st */
            	1661, 0,
            1, 8, 1, /* 1676: pointer.struct.asn1_string_st */
            	1661, 0,
            1, 8, 1, /* 1681: pointer.struct.asn1_string_st */
            	1661, 0,
            1, 8, 1, /* 1686: pointer.struct.asn1_string_st */
            	1661, 0,
            1, 8, 1, /* 1691: pointer.struct.asn1_string_st */
            	1661, 0,
            1, 8, 1, /* 1696: pointer.struct.asn1_string_st */
            	1661, 0,
            1, 8, 1, /* 1701: pointer.struct.asn1_string_st */
            	1661, 0,
            1, 8, 1, /* 1706: pointer.struct.asn1_string_st */
            	1661, 0,
            1, 8, 1, /* 1711: pointer.struct.asn1_string_st */
            	1661, 0,
            1, 8, 1, /* 1716: pointer.struct.asn1_string_st */
            	1661, 0,
            1, 8, 1, /* 1721: pointer.struct.asn1_string_st */
            	1661, 0,
            1, 8, 1, /* 1726: pointer.struct.asn1_string_st */
            	1661, 0,
            1, 8, 1, /* 1731: pointer.struct.asn1_string_st */
            	1661, 0,
            1, 8, 1, /* 1736: pointer.struct.asn1_string_st */
            	1741, 0,
            0, 24, 1, /* 1741: struct.asn1_string_st */
            	200, 8,
            0, 56, 4, /* 1746: struct.evp_pkey_st */
            	1757, 16,
            	1765, 24,
            	1773, 32,
            	2094, 48,
            1, 8, 1, /* 1757: pointer.struct.evp_pkey_asn1_method_st */
            	1762, 0,
            0, 0, 0, /* 1762: struct.evp_pkey_asn1_method_st */
            1, 8, 1, /* 1765: pointer.struct.engine_st */
            	1770, 0,
            0, 0, 0, /* 1770: struct.engine_st */
            0, 8, 5, /* 1773: union.unknown */
            	93, 0,
            	1786, 0,
            	1937, 0,
            	2018, 0,
            	2086, 0,
            1, 8, 1, /* 1786: pointer.struct.rsa_st */
            	1791, 0,
            0, 168, 17, /* 1791: struct.rsa_st */
            	1828, 16,
            	1765, 24,
            	1883, 32,
            	1883, 40,
            	1883, 48,
            	1883, 56,
            	1883, 64,
            	1883, 72,
            	1883, 80,
            	1883, 88,
            	1893, 96,
            	1915, 120,
            	1915, 128,
            	1915, 136,
            	93, 144,
            	1929, 152,
            	1929, 160,
            1, 8, 1, /* 1828: pointer.struct.rsa_meth_st */
            	1833, 0,
            0, 112, 13, /* 1833: struct.rsa_meth_st */
            	124, 0,
            	1862, 8,
            	1862, 16,
            	1862, 24,
            	1862, 32,
            	1865, 40,
            	1868, 48,
            	1871, 56,
            	1871, 64,
            	93, 80,
            	1874, 88,
            	1877, 96,
            	1880, 104,
            8884097, 8, 0, /* 1862: pointer.func */
            8884097, 8, 0, /* 1865: pointer.func */
            8884097, 8, 0, /* 1868: pointer.func */
            8884097, 8, 0, /* 1871: pointer.func */
            8884097, 8, 0, /* 1874: pointer.func */
            8884097, 8, 0, /* 1877: pointer.func */
            8884097, 8, 0, /* 1880: pointer.func */
            1, 8, 1, /* 1883: pointer.struct.bignum_st */
            	1888, 0,
            0, 24, 1, /* 1888: struct.bignum_st */
            	1063, 0,
            0, 16, 1, /* 1893: struct.crypto_ex_data_st */
            	1898, 0,
            1, 8, 1, /* 1898: pointer.struct.stack_st_void */
            	1903, 0,
            0, 32, 1, /* 1903: struct.stack_st_void */
            	1908, 0,
            0, 32, 2, /* 1908: struct.stack_st */
            	885, 8,
            	360, 24,
            1, 8, 1, /* 1915: pointer.struct.bn_mont_ctx_st */
            	1920, 0,
            0, 96, 3, /* 1920: struct.bn_mont_ctx_st */
            	1888, 8,
            	1888, 32,
            	1888, 56,
            1, 8, 1, /* 1929: pointer.struct.bn_blinding_st */
            	1934, 0,
            0, 0, 0, /* 1934: struct.bn_blinding_st */
            1, 8, 1, /* 1937: pointer.struct.dsa_st */
            	1942, 0,
            0, 136, 11, /* 1942: struct.dsa_st */
            	1883, 24,
            	1883, 32,
            	1883, 40,
            	1883, 48,
            	1883, 56,
            	1883, 64,
            	1883, 72,
            	1915, 88,
            	1893, 104,
            	1967, 120,
            	1765, 128,
            1, 8, 1, /* 1967: pointer.struct.dsa_method */
            	1972, 0,
            0, 96, 11, /* 1972: struct.dsa_method */
            	124, 0,
            	1997, 8,
            	2000, 16,
            	2003, 24,
            	2006, 32,
            	2009, 40,
            	2012, 48,
            	2012, 56,
            	93, 72,
            	2015, 80,
            	2012, 88,
            8884097, 8, 0, /* 1997: pointer.func */
            8884097, 8, 0, /* 2000: pointer.func */
            8884097, 8, 0, /* 2003: pointer.func */
            8884097, 8, 0, /* 2006: pointer.func */
            8884097, 8, 0, /* 2009: pointer.func */
            8884097, 8, 0, /* 2012: pointer.func */
            8884097, 8, 0, /* 2015: pointer.func */
            1, 8, 1, /* 2018: pointer.struct.dh_st */
            	2023, 0,
            0, 144, 12, /* 2023: struct.dh_st */
            	1883, 8,
            	1883, 16,
            	1883, 32,
            	1883, 40,
            	1915, 56,
            	1883, 64,
            	1883, 72,
            	200, 80,
            	1883, 96,
            	1893, 112,
            	2050, 128,
            	1765, 136,
            1, 8, 1, /* 2050: pointer.struct.dh_method */
            	2055, 0,
            0, 72, 8, /* 2055: struct.dh_method */
            	124, 0,
            	2074, 8,
            	2077, 16,
            	2080, 24,
            	2074, 32,
            	2074, 40,
            	93, 56,
            	2083, 64,
            8884097, 8, 0, /* 2074: pointer.func */
            8884097, 8, 0, /* 2077: pointer.func */
            8884097, 8, 0, /* 2080: pointer.func */
            8884097, 8, 0, /* 2083: pointer.func */
            1, 8, 1, /* 2086: pointer.struct.ec_key_st */
            	2091, 0,
            0, 0, 0, /* 2091: struct.ec_key_st */
            1, 8, 1, /* 2094: pointer.struct.stack_st_X509_ATTRIBUTE */
            	2099, 0,
            0, 32, 2, /* 2099: struct.stack_st_fake_X509_ATTRIBUTE */
            	2106, 8,
            	360, 24,
            8884099, 8, 2, /* 2106: pointer_to_array_of_pointers_to_stack */
            	2113, 0,
            	357, 20,
            0, 8, 1, /* 2113: pointer.X509_ATTRIBUTE */
            	1389, 0,
            1, 8, 1, /* 2118: pointer.struct.asn1_string_st */
            	1741, 0,
            1, 8, 1, /* 2123: pointer.struct.asn1_string_st */
            	1741, 0,
            1, 8, 1, /* 2128: pointer.struct.asn1_string_st */
            	1741, 0,
            1, 8, 1, /* 2133: pointer.struct.asn1_string_st */
            	1741, 0,
            1, 8, 1, /* 2138: pointer.struct.asn1_string_st */
            	1741, 0,
            1, 8, 1, /* 2143: pointer.struct.asn1_string_st */
            	1741, 0,
            1, 8, 1, /* 2148: pointer.struct.asn1_string_st */
            	1741, 0,
            0, 16, 1, /* 2153: struct.asn1_type_st */
            	2158, 8,
            0, 8, 20, /* 2158: union.unknown */
            	93, 0,
            	2201, 0,
            	2206, 0,
            	2220, 0,
            	2225, 0,
            	2230, 0,
            	2235, 0,
            	2148, 0,
            	2143, 0,
            	2138, 0,
            	2133, 0,
            	2128, 0,
            	2240, 0,
            	2123, 0,
            	2118, 0,
            	2245, 0,
            	1736, 0,
            	2201, 0,
            	2201, 0,
            	611, 0,
            1, 8, 1, /* 2201: pointer.struct.asn1_string_st */
            	1741, 0,
            1, 8, 1, /* 2206: pointer.struct.asn1_object_st */
            	2211, 0,
            0, 40, 3, /* 2211: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            1, 8, 1, /* 2220: pointer.struct.asn1_string_st */
            	1741, 0,
            1, 8, 1, /* 2225: pointer.struct.asn1_string_st */
            	1741, 0,
            1, 8, 1, /* 2230: pointer.struct.asn1_string_st */
            	1741, 0,
            1, 8, 1, /* 2235: pointer.struct.asn1_string_st */
            	1741, 0,
            1, 8, 1, /* 2240: pointer.struct.asn1_string_st */
            	1741, 0,
            1, 8, 1, /* 2245: pointer.struct.asn1_string_st */
            	1741, 0,
            0, 0, 1, /* 2250: X509_ALGOR */
            	2255, 0,
            0, 16, 2, /* 2255: struct.X509_algor_st */
            	2206, 0,
            	2262, 8,
            1, 8, 1, /* 2262: pointer.struct.asn1_type_st */
            	2153, 0,
            1, 8, 1, /* 2267: pointer.struct.stack_st_X509_ALGOR */
            	2272, 0,
            0, 32, 2, /* 2272: struct.stack_st_fake_X509_ALGOR */
            	2279, 8,
            	360, 24,
            8884099, 8, 2, /* 2279: pointer_to_array_of_pointers_to_stack */
            	2286, 0,
            	357, 20,
            0, 8, 1, /* 2286: pointer.X509_ALGOR */
            	2250, 0,
            0, 0, 0, /* 2291: struct.NAME_CONSTRAINTS_st */
            8884097, 8, 0, /* 2294: pointer.func */
            1, 8, 1, /* 2297: pointer.struct.ASN1_VALUE_st */
            	2302, 0,
            0, 0, 0, /* 2302: struct.ASN1_VALUE_st */
            0, 16, 1, /* 2305: struct.crypto_ex_data_st */
            	2310, 0,
            1, 8, 1, /* 2310: pointer.struct.stack_st_void */
            	2315, 0,
            0, 32, 1, /* 2315: struct.stack_st_void */
            	2320, 0,
            0, 32, 2, /* 2320: struct.stack_st */
            	885, 8,
            	360, 24,
            1, 8, 1, /* 2327: pointer.struct.asn1_string_st */
            	2332, 0,
            0, 24, 1, /* 2332: struct.asn1_string_st */
            	200, 8,
            0, 24, 1, /* 2337: struct.buf_mem_st */
            	93, 8,
            0, 24, 1, /* 2342: struct.ASN1_ENCODING_st */
            	200, 0,
            1, 8, 1, /* 2347: pointer.struct.x509_st */
            	2352, 0,
            0, 184, 12, /* 2352: struct.x509_st */
            	1115, 0,
            	467, 8,
            	433, 16,
            	93, 32,
            	1071, 40,
            	556, 104,
            	825, 112,
            	2379, 120,
            	2387, 128,
            	2425, 136,
            	2449, 144,
            	2504, 176,
            1, 8, 1, /* 2379: pointer.struct.X509_POLICY_CACHE_st */
            	2384, 0,
            0, 0, 0, /* 2384: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 2387: pointer.struct.stack_st_DIST_POINT */
            	2392, 0,
            0, 32, 2, /* 2392: struct.stack_st_fake_DIST_POINT */
            	2399, 8,
            	360, 24,
            8884099, 8, 2, /* 2399: pointer_to_array_of_pointers_to_stack */
            	2406, 0,
            	357, 20,
            0, 8, 1, /* 2406: pointer.DIST_POINT */
            	2411, 0,
            0, 0, 1, /* 2411: DIST_POINT */
            	2416, 0,
            0, 32, 3, /* 2416: struct.DIST_POINT_st */
            	7, 0,
            	433, 8,
            	26, 16,
            1, 8, 1, /* 2425: pointer.struct.stack_st_GENERAL_NAME */
            	2430, 0,
            0, 32, 2, /* 2430: struct.stack_st_fake_GENERAL_NAME */
            	2437, 8,
            	360, 24,
            8884099, 8, 2, /* 2437: pointer_to_array_of_pointers_to_stack */
            	2444, 0,
            	357, 20,
            0, 8, 1, /* 2444: pointer.GENERAL_NAME */
            	50, 0,
            1, 8, 1, /* 2449: pointer.struct.NAME_CONSTRAINTS_st */
            	2454, 0,
            0, 16, 2, /* 2454: struct.NAME_CONSTRAINTS_st */
            	2461, 0,
            	2461, 8,
            1, 8, 1, /* 2461: pointer.struct.stack_st_GENERAL_SUBTREE */
            	2466, 0,
            0, 32, 2, /* 2466: struct.stack_st_fake_GENERAL_SUBTREE */
            	2473, 8,
            	360, 24,
            8884099, 8, 2, /* 2473: pointer_to_array_of_pointers_to_stack */
            	2480, 0,
            	357, 20,
            0, 8, 1, /* 2480: pointer.GENERAL_SUBTREE */
            	2485, 0,
            0, 0, 1, /* 2485: GENERAL_SUBTREE */
            	2490, 0,
            0, 24, 3, /* 2490: struct.GENERAL_SUBTREE_st */
            	2499, 0,
            	205, 8,
            	205, 16,
            1, 8, 1, /* 2499: pointer.struct.GENERAL_NAME_st */
            	55, 0,
            1, 8, 1, /* 2504: pointer.struct.x509_cert_aux_st */
            	2509, 0,
            0, 40, 5, /* 2509: struct.x509_cert_aux_st */
            	2522, 0,
            	2522, 8,
            	606, 16,
            	556, 24,
            	2551, 32,
            1, 8, 1, /* 2522: pointer.struct.stack_st_ASN1_OBJECT */
            	2527, 0,
            0, 32, 2, /* 2527: struct.stack_st_fake_ASN1_OBJECT */
            	2534, 8,
            	360, 24,
            8884099, 8, 2, /* 2534: pointer_to_array_of_pointers_to_stack */
            	2541, 0,
            	357, 20,
            0, 8, 1, /* 2541: pointer.ASN1_OBJECT */
            	2546, 0,
            0, 0, 1, /* 2546: ASN1_OBJECT */
            	1516, 0,
            1, 8, 1, /* 2551: pointer.struct.stack_st_X509_ALGOR */
            	2556, 0,
            0, 32, 2, /* 2556: struct.stack_st_fake_X509_ALGOR */
            	2563, 8,
            	360, 24,
            8884099, 8, 2, /* 2563: pointer_to_array_of_pointers_to_stack */
            	2570, 0,
            	357, 20,
            0, 8, 1, /* 2570: pointer.X509_ALGOR */
            	2250, 0,
            0, 80, 8, /* 2575: struct.X509_crl_info_st */
            	2594, 0,
            	2599, 8,
            	2748, 16,
            	938, 24,
            	938, 32,
            	2796, 40,
            	914, 48,
            	909, 56,
            1, 8, 1, /* 2594: pointer.struct.asn1_string_st */
            	943, 0,
            1, 8, 1, /* 2599: pointer.struct.X509_algor_st */
            	2604, 0,
            0, 16, 2, /* 2604: struct.X509_algor_st */
            	2611, 0,
            	2625, 8,
            1, 8, 1, /* 2611: pointer.struct.asn1_object_st */
            	2616, 0,
            0, 40, 3, /* 2616: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            1, 8, 1, /* 2625: pointer.struct.asn1_type_st */
            	2630, 0,
            0, 16, 1, /* 2630: struct.asn1_type_st */
            	2635, 8,
            0, 8, 20, /* 2635: union.unknown */
            	93, 0,
            	2678, 0,
            	2611, 0,
            	2594, 0,
            	2683, 0,
            	2688, 0,
            	2693, 0,
            	2698, 0,
            	2703, 0,
            	2708, 0,
            	2713, 0,
            	2718, 0,
            	2723, 0,
            	2728, 0,
            	2733, 0,
            	2738, 0,
            	2743, 0,
            	2678, 0,
            	2678, 0,
            	611, 0,
            1, 8, 1, /* 2678: pointer.struct.asn1_string_st */
            	943, 0,
            1, 8, 1, /* 2683: pointer.struct.asn1_string_st */
            	943, 0,
            1, 8, 1, /* 2688: pointer.struct.asn1_string_st */
            	943, 0,
            1, 8, 1, /* 2693: pointer.struct.asn1_string_st */
            	943, 0,
            1, 8, 1, /* 2698: pointer.struct.asn1_string_st */
            	943, 0,
            1, 8, 1, /* 2703: pointer.struct.asn1_string_st */
            	943, 0,
            1, 8, 1, /* 2708: pointer.struct.asn1_string_st */
            	943, 0,
            1, 8, 1, /* 2713: pointer.struct.asn1_string_st */
            	943, 0,
            1, 8, 1, /* 2718: pointer.struct.asn1_string_st */
            	943, 0,
            1, 8, 1, /* 2723: pointer.struct.asn1_string_st */
            	943, 0,
            1, 8, 1, /* 2728: pointer.struct.asn1_string_st */
            	943, 0,
            1, 8, 1, /* 2733: pointer.struct.asn1_string_st */
            	943, 0,
            1, 8, 1, /* 2738: pointer.struct.asn1_string_st */
            	943, 0,
            1, 8, 1, /* 2743: pointer.struct.asn1_string_st */
            	943, 0,
            1, 8, 1, /* 2748: pointer.struct.X509_name_st */
            	2753, 0,
            0, 40, 3, /* 2753: struct.X509_name_st */
            	2762, 0,
            	2786, 16,
            	200, 24,
            1, 8, 1, /* 2762: pointer.struct.stack_st_X509_NAME_ENTRY */
            	2767, 0,
            0, 32, 2, /* 2767: struct.stack_st_fake_X509_NAME_ENTRY */
            	2774, 8,
            	360, 24,
            8884099, 8, 2, /* 2774: pointer_to_array_of_pointers_to_stack */
            	2781, 0,
            	357, 20,
            0, 8, 1, /* 2781: pointer.X509_NAME_ENTRY */
            	321, 0,
            1, 8, 1, /* 2786: pointer.struct.buf_mem_st */
            	2791, 0,
            0, 24, 1, /* 2791: struct.buf_mem_st */
            	93, 8,
            1, 8, 1, /* 2796: pointer.struct.stack_st_X509_REVOKED */
            	2801, 0,
            0, 32, 2, /* 2801: struct.stack_st_fake_X509_REVOKED */
            	2808, 8,
            	360, 24,
            8884099, 8, 2, /* 2808: pointer_to_array_of_pointers_to_stack */
            	2815, 0,
            	357, 20,
            0, 8, 1, /* 2815: pointer.X509_REVOKED */
            	648, 0,
            8884097, 8, 0, /* 2820: pointer.func */
            0, 0, 1, /* 2823: X509_LOOKUP */
            	2828, 0,
            0, 32, 3, /* 2828: struct.x509_lookup_st */
            	2837, 8,
            	93, 16,
            	2886, 24,
            1, 8, 1, /* 2837: pointer.struct.x509_lookup_method_st */
            	2842, 0,
            0, 80, 10, /* 2842: struct.x509_lookup_method_st */
            	124, 0,
            	2865, 8,
            	2868, 16,
            	2865, 24,
            	2865, 32,
            	2871, 40,
            	2874, 48,
            	2877, 56,
            	2880, 64,
            	2883, 72,
            8884097, 8, 0, /* 2865: pointer.func */
            8884097, 8, 0, /* 2868: pointer.func */
            8884097, 8, 0, /* 2871: pointer.func */
            8884097, 8, 0, /* 2874: pointer.func */
            8884097, 8, 0, /* 2877: pointer.func */
            8884097, 8, 0, /* 2880: pointer.func */
            8884097, 8, 0, /* 2883: pointer.func */
            1, 8, 1, /* 2886: pointer.struct.x509_store_st */
            	2891, 0,
            0, 144, 15, /* 2891: struct.x509_store_st */
            	2924, 8,
            	3809, 16,
            	3833, 24,
            	3845, 32,
            	3848, 40,
            	3851, 48,
            	3854, 56,
            	3845, 64,
            	3857, 72,
            	3860, 80,
            	3863, 88,
            	3866, 96,
            	3869, 104,
            	3845, 112,
            	2305, 120,
            1, 8, 1, /* 2924: pointer.struct.stack_st_X509_OBJECT */
            	2929, 0,
            0, 32, 2, /* 2929: struct.stack_st_fake_X509_OBJECT */
            	2936, 8,
            	360, 24,
            8884099, 8, 2, /* 2936: pointer_to_array_of_pointers_to_stack */
            	2943, 0,
            	357, 20,
            0, 8, 1, /* 2943: pointer.X509_OBJECT */
            	2948, 0,
            0, 0, 1, /* 2948: X509_OBJECT */
            	2953, 0,
            0, 16, 1, /* 2953: struct.x509_object_st */
            	2958, 8,
            0, 8, 4, /* 2958: union.unknown */
            	93, 0,
            	2969, 0,
            	3725, 0,
            	3254, 0,
            1, 8, 1, /* 2969: pointer.struct.x509_st */
            	2974, 0,
            0, 184, 12, /* 2974: struct.x509_st */
            	3001, 0,
            	3036, 8,
            	3125, 16,
            	93, 32,
            	2305, 40,
            	2327, 104,
            	3595, 112,
            	2379, 120,
            	3603, 128,
            	3627, 136,
            	3651, 144,
            	3659, 176,
            1, 8, 1, /* 3001: pointer.struct.x509_cinf_st */
            	3006, 0,
            0, 104, 11, /* 3006: struct.x509_cinf_st */
            	3031, 0,
            	3031, 8,
            	3036, 16,
            	3180, 24,
            	3223, 32,
            	3180, 40,
            	3240, 48,
            	3125, 56,
            	3125, 64,
            	3571, 72,
            	2342, 80,
            1, 8, 1, /* 3031: pointer.struct.asn1_string_st */
            	2332, 0,
            1, 8, 1, /* 3036: pointer.struct.X509_algor_st */
            	3041, 0,
            0, 16, 2, /* 3041: struct.X509_algor_st */
            	3048, 0,
            	3062, 8,
            1, 8, 1, /* 3048: pointer.struct.asn1_object_st */
            	3053, 0,
            0, 40, 3, /* 3053: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            1, 8, 1, /* 3062: pointer.struct.asn1_type_st */
            	3067, 0,
            0, 16, 1, /* 3067: struct.asn1_type_st */
            	3072, 8,
            0, 8, 20, /* 3072: union.unknown */
            	93, 0,
            	3115, 0,
            	3048, 0,
            	3031, 0,
            	3120, 0,
            	3125, 0,
            	2327, 0,
            	3130, 0,
            	3135, 0,
            	3140, 0,
            	3145, 0,
            	3150, 0,
            	3155, 0,
            	3160, 0,
            	3165, 0,
            	3170, 0,
            	3175, 0,
            	3115, 0,
            	3115, 0,
            	611, 0,
            1, 8, 1, /* 3115: pointer.struct.asn1_string_st */
            	2332, 0,
            1, 8, 1, /* 3120: pointer.struct.asn1_string_st */
            	2332, 0,
            1, 8, 1, /* 3125: pointer.struct.asn1_string_st */
            	2332, 0,
            1, 8, 1, /* 3130: pointer.struct.asn1_string_st */
            	2332, 0,
            1, 8, 1, /* 3135: pointer.struct.asn1_string_st */
            	2332, 0,
            1, 8, 1, /* 3140: pointer.struct.asn1_string_st */
            	2332, 0,
            1, 8, 1, /* 3145: pointer.struct.asn1_string_st */
            	2332, 0,
            1, 8, 1, /* 3150: pointer.struct.asn1_string_st */
            	2332, 0,
            1, 8, 1, /* 3155: pointer.struct.asn1_string_st */
            	2332, 0,
            1, 8, 1, /* 3160: pointer.struct.asn1_string_st */
            	2332, 0,
            1, 8, 1, /* 3165: pointer.struct.asn1_string_st */
            	2332, 0,
            1, 8, 1, /* 3170: pointer.struct.asn1_string_st */
            	2332, 0,
            1, 8, 1, /* 3175: pointer.struct.asn1_string_st */
            	2332, 0,
            1, 8, 1, /* 3180: pointer.struct.X509_name_st */
            	3185, 0,
            0, 40, 3, /* 3185: struct.X509_name_st */
            	3194, 0,
            	3218, 16,
            	200, 24,
            1, 8, 1, /* 3194: pointer.struct.stack_st_X509_NAME_ENTRY */
            	3199, 0,
            0, 32, 2, /* 3199: struct.stack_st_fake_X509_NAME_ENTRY */
            	3206, 8,
            	360, 24,
            8884099, 8, 2, /* 3206: pointer_to_array_of_pointers_to_stack */
            	3213, 0,
            	357, 20,
            0, 8, 1, /* 3213: pointer.X509_NAME_ENTRY */
            	321, 0,
            1, 8, 1, /* 3218: pointer.struct.buf_mem_st */
            	2337, 0,
            1, 8, 1, /* 3223: pointer.struct.X509_val_st */
            	3228, 0,
            0, 16, 2, /* 3228: struct.X509_val_st */
            	3235, 0,
            	3235, 8,
            1, 8, 1, /* 3235: pointer.struct.asn1_string_st */
            	2332, 0,
            1, 8, 1, /* 3240: pointer.struct.X509_pubkey_st */
            	3245, 0,
            0, 24, 3, /* 3245: struct.X509_pubkey_st */
            	3036, 0,
            	3125, 8,
            	3254, 16,
            1, 8, 1, /* 3254: pointer.struct.evp_pkey_st */
            	3259, 0,
            0, 56, 4, /* 3259: struct.evp_pkey_st */
            	1187, 16,
            	1045, 24,
            	3270, 32,
            	3547, 48,
            0, 8, 5, /* 3270: union.unknown */
            	93, 0,
            	3283, 0,
            	3401, 0,
            	3479, 0,
            	1357, 0,
            1, 8, 1, /* 3283: pointer.struct.rsa_st */
            	3288, 0,
            0, 168, 17, /* 3288: struct.rsa_st */
            	3325, 16,
            	1045, 24,
            	3377, 32,
            	3377, 40,
            	3377, 48,
            	3377, 56,
            	3377, 64,
            	3377, 72,
            	3377, 80,
            	3377, 88,
            	2305, 96,
            	3387, 120,
            	3387, 128,
            	3387, 136,
            	93, 144,
            	1107, 152,
            	1107, 160,
            1, 8, 1, /* 3325: pointer.struct.rsa_meth_st */
            	3330, 0,
            0, 112, 13, /* 3330: struct.rsa_meth_st */
            	124, 0,
            	3359, 8,
            	3359, 16,
            	3359, 24,
            	3359, 32,
            	3362, 40,
            	3365, 48,
            	3368, 56,
            	3368, 64,
            	93, 80,
            	2294, 88,
            	3371, 96,
            	3374, 104,
            8884097, 8, 0, /* 3359: pointer.func */
            8884097, 8, 0, /* 3362: pointer.func */
            8884097, 8, 0, /* 3365: pointer.func */
            8884097, 8, 0, /* 3368: pointer.func */
            8884097, 8, 0, /* 3371: pointer.func */
            8884097, 8, 0, /* 3374: pointer.func */
            1, 8, 1, /* 3377: pointer.struct.bignum_st */
            	3382, 0,
            0, 24, 1, /* 3382: struct.bignum_st */
            	1063, 0,
            1, 8, 1, /* 3387: pointer.struct.bn_mont_ctx_st */
            	3392, 0,
            0, 96, 3, /* 3392: struct.bn_mont_ctx_st */
            	3382, 8,
            	3382, 32,
            	3382, 56,
            1, 8, 1, /* 3401: pointer.struct.dsa_st */
            	3406, 0,
            0, 136, 11, /* 3406: struct.dsa_st */
            	3377, 24,
            	3377, 32,
            	3377, 40,
            	3377, 48,
            	3377, 56,
            	3377, 64,
            	3377, 72,
            	3387, 88,
            	2305, 104,
            	3431, 120,
            	1045, 128,
            1, 8, 1, /* 3431: pointer.struct.dsa_method */
            	3436, 0,
            0, 96, 11, /* 3436: struct.dsa_method */
            	124, 0,
            	3461, 8,
            	3464, 16,
            	3467, 24,
            	2820, 32,
            	3470, 40,
            	3473, 48,
            	3473, 56,
            	93, 72,
            	3476, 80,
            	3473, 88,
            8884097, 8, 0, /* 3461: pointer.func */
            8884097, 8, 0, /* 3464: pointer.func */
            8884097, 8, 0, /* 3467: pointer.func */
            8884097, 8, 0, /* 3470: pointer.func */
            8884097, 8, 0, /* 3473: pointer.func */
            8884097, 8, 0, /* 3476: pointer.func */
            1, 8, 1, /* 3479: pointer.struct.dh_st */
            	3484, 0,
            0, 144, 12, /* 3484: struct.dh_st */
            	3377, 8,
            	3377, 16,
            	3377, 32,
            	3377, 40,
            	3387, 56,
            	3377, 64,
            	3377, 72,
            	200, 80,
            	3377, 96,
            	2305, 112,
            	3511, 128,
            	1045, 136,
            1, 8, 1, /* 3511: pointer.struct.dh_method */
            	3516, 0,
            0, 72, 8, /* 3516: struct.dh_method */
            	124, 0,
            	3535, 8,
            	3538, 16,
            	3541, 24,
            	3535, 32,
            	3535, 40,
            	93, 56,
            	3544, 64,
            8884097, 8, 0, /* 3535: pointer.func */
            8884097, 8, 0, /* 3538: pointer.func */
            8884097, 8, 0, /* 3541: pointer.func */
            8884097, 8, 0, /* 3544: pointer.func */
            1, 8, 1, /* 3547: pointer.struct.stack_st_X509_ATTRIBUTE */
            	3552, 0,
            0, 32, 2, /* 3552: struct.stack_st_fake_X509_ATTRIBUTE */
            	3559, 8,
            	360, 24,
            8884099, 8, 2, /* 3559: pointer_to_array_of_pointers_to_stack */
            	3566, 0,
            	357, 20,
            0, 8, 1, /* 3566: pointer.X509_ATTRIBUTE */
            	1389, 0,
            1, 8, 1, /* 3571: pointer.struct.stack_st_X509_EXTENSION */
            	3576, 0,
            0, 32, 2, /* 3576: struct.stack_st_fake_X509_EXTENSION */
            	3583, 8,
            	360, 24,
            8884099, 8, 2, /* 3583: pointer_to_array_of_pointers_to_stack */
            	3590, 0,
            	357, 20,
            0, 8, 1, /* 3590: pointer.X509_EXTENSION */
            	703, 0,
            1, 8, 1, /* 3595: pointer.struct.AUTHORITY_KEYID_st */
            	3600, 0,
            0, 0, 0, /* 3600: struct.AUTHORITY_KEYID_st */
            1, 8, 1, /* 3603: pointer.struct.stack_st_DIST_POINT */
            	3608, 0,
            0, 32, 2, /* 3608: struct.stack_st_fake_DIST_POINT */
            	3615, 8,
            	360, 24,
            8884099, 8, 2, /* 3615: pointer_to_array_of_pointers_to_stack */
            	3622, 0,
            	357, 20,
            0, 8, 1, /* 3622: pointer.DIST_POINT */
            	2411, 0,
            1, 8, 1, /* 3627: pointer.struct.stack_st_GENERAL_NAME */
            	3632, 0,
            0, 32, 2, /* 3632: struct.stack_st_fake_GENERAL_NAME */
            	3639, 8,
            	360, 24,
            8884099, 8, 2, /* 3639: pointer_to_array_of_pointers_to_stack */
            	3646, 0,
            	357, 20,
            0, 8, 1, /* 3646: pointer.GENERAL_NAME */
            	50, 0,
            1, 8, 1, /* 3651: pointer.struct.NAME_CONSTRAINTS_st */
            	3656, 0,
            0, 0, 0, /* 3656: struct.NAME_CONSTRAINTS_st */
            1, 8, 1, /* 3659: pointer.struct.x509_cert_aux_st */
            	3664, 0,
            0, 40, 5, /* 3664: struct.x509_cert_aux_st */
            	3677, 0,
            	3677, 8,
            	3175, 16,
            	2327, 24,
            	3701, 32,
            1, 8, 1, /* 3677: pointer.struct.stack_st_ASN1_OBJECT */
            	3682, 0,
            0, 32, 2, /* 3682: struct.stack_st_fake_ASN1_OBJECT */
            	3689, 8,
            	360, 24,
            8884099, 8, 2, /* 3689: pointer_to_array_of_pointers_to_stack */
            	3696, 0,
            	357, 20,
            0, 8, 1, /* 3696: pointer.ASN1_OBJECT */
            	2546, 0,
            1, 8, 1, /* 3701: pointer.struct.stack_st_X509_ALGOR */
            	3706, 0,
            0, 32, 2, /* 3706: struct.stack_st_fake_X509_ALGOR */
            	3713, 8,
            	360, 24,
            8884099, 8, 2, /* 3713: pointer_to_array_of_pointers_to_stack */
            	3720, 0,
            	357, 20,
            0, 8, 1, /* 3720: pointer.X509_ALGOR */
            	2250, 0,
            1, 8, 1, /* 3725: pointer.struct.X509_crl_st */
            	3730, 0,
            0, 120, 10, /* 3730: struct.X509_crl_st */
            	3753, 0,
            	3036, 8,
            	3125, 16,
            	3595, 32,
            	3801, 40,
            	3031, 56,
            	3031, 64,
            	844, 96,
            	890, 104,
            	898, 112,
            1, 8, 1, /* 3753: pointer.struct.X509_crl_info_st */
            	3758, 0,
            0, 80, 8, /* 3758: struct.X509_crl_info_st */
            	3031, 0,
            	3036, 8,
            	3180, 16,
            	3235, 24,
            	3235, 32,
            	3777, 40,
            	3571, 48,
            	2342, 56,
            1, 8, 1, /* 3777: pointer.struct.stack_st_X509_REVOKED */
            	3782, 0,
            0, 32, 2, /* 3782: struct.stack_st_fake_X509_REVOKED */
            	3789, 8,
            	360, 24,
            8884099, 8, 2, /* 3789: pointer_to_array_of_pointers_to_stack */
            	3796, 0,
            	357, 20,
            0, 8, 1, /* 3796: pointer.X509_REVOKED */
            	648, 0,
            1, 8, 1, /* 3801: pointer.struct.ISSUING_DIST_POINT_st */
            	3806, 0,
            0, 0, 0, /* 3806: struct.ISSUING_DIST_POINT_st */
            1, 8, 1, /* 3809: pointer.struct.stack_st_X509_LOOKUP */
            	3814, 0,
            0, 32, 2, /* 3814: struct.stack_st_fake_X509_LOOKUP */
            	3821, 8,
            	360, 24,
            8884099, 8, 2, /* 3821: pointer_to_array_of_pointers_to_stack */
            	3828, 0,
            	357, 20,
            0, 8, 1, /* 3828: pointer.X509_LOOKUP */
            	2823, 0,
            1, 8, 1, /* 3833: pointer.struct.X509_VERIFY_PARAM_st */
            	3838, 0,
            0, 56, 2, /* 3838: struct.X509_VERIFY_PARAM_st */
            	93, 0,
            	3677, 48,
            8884097, 8, 0, /* 3845: pointer.func */
            8884097, 8, 0, /* 3848: pointer.func */
            8884097, 8, 0, /* 3851: pointer.func */
            8884097, 8, 0, /* 3854: pointer.func */
            8884097, 8, 0, /* 3857: pointer.func */
            8884097, 8, 0, /* 3860: pointer.func */
            8884097, 8, 0, /* 3863: pointer.func */
            8884097, 8, 0, /* 3866: pointer.func */
            8884097, 8, 0, /* 3869: pointer.func */
            1, 8, 1, /* 3872: pointer.struct.stack_st_ASN1_OBJECT */
            	3877, 0,
            0, 32, 2, /* 3877: struct.stack_st_fake_ASN1_OBJECT */
            	3884, 8,
            	360, 24,
            8884099, 8, 2, /* 3884: pointer_to_array_of_pointers_to_stack */
            	3891, 0,
            	357, 20,
            0, 8, 1, /* 3891: pointer.ASN1_OBJECT */
            	2546, 0,
            0, 0, 0, /* 3896: struct.X509_POLICY_CACHE_st */
            0, 0, 0, /* 3899: struct.AUTHORITY_KEYID_st */
            0, 40, 5, /* 3902: struct.x509_cert_aux_st */
            	3872, 0,
            	3872, 8,
            	3915, 16,
            	3925, 24,
            	2267, 32,
            1, 8, 1, /* 3915: pointer.struct.asn1_string_st */
            	3920, 0,
            0, 24, 1, /* 3920: struct.asn1_string_st */
            	200, 8,
            1, 8, 1, /* 3925: pointer.struct.asn1_string_st */
            	3920, 0,
            1, 8, 1, /* 3930: pointer.struct.stack_st_DIST_POINT */
            	3935, 0,
            0, 32, 2, /* 3935: struct.stack_st_fake_DIST_POINT */
            	3942, 8,
            	360, 24,
            8884099, 8, 2, /* 3942: pointer_to_array_of_pointers_to_stack */
            	3949, 0,
            	357, 20,
            0, 8, 1, /* 3949: pointer.DIST_POINT */
            	2411, 0,
            0, 184, 12, /* 3954: struct.x509_st */
            	3981, 0,
            	4016, 8,
            	4105, 16,
            	93, 32,
            	1893, 40,
            	3925, 104,
            	4268, 112,
            	4273, 120,
            	3930, 128,
            	4278, 136,
            	4302, 144,
            	4307, 176,
            1, 8, 1, /* 3981: pointer.struct.x509_cinf_st */
            	3986, 0,
            0, 104, 11, /* 3986: struct.x509_cinf_st */
            	4011, 0,
            	4011, 8,
            	4016, 16,
            	4155, 24,
            	4203, 32,
            	4155, 40,
            	4220, 48,
            	4105, 56,
            	4105, 64,
            	4239, 72,
            	4263, 80,
            1, 8, 1, /* 4011: pointer.struct.asn1_string_st */
            	3920, 0,
            1, 8, 1, /* 4016: pointer.struct.X509_algor_st */
            	4021, 0,
            0, 16, 2, /* 4021: struct.X509_algor_st */
            	4028, 0,
            	4042, 8,
            1, 8, 1, /* 4028: pointer.struct.asn1_object_st */
            	4033, 0,
            0, 40, 3, /* 4033: struct.asn1_object_st */
            	124, 0,
            	124, 8,
            	129, 24,
            1, 8, 1, /* 4042: pointer.struct.asn1_type_st */
            	4047, 0,
            0, 16, 1, /* 4047: struct.asn1_type_st */
            	4052, 8,
            0, 8, 20, /* 4052: union.unknown */
            	93, 0,
            	4095, 0,
            	4028, 0,
            	4011, 0,
            	4100, 0,
            	4105, 0,
            	3925, 0,
            	4110, 0,
            	4115, 0,
            	4120, 0,
            	4125, 0,
            	4130, 0,
            	4135, 0,
            	4140, 0,
            	4145, 0,
            	4150, 0,
            	3915, 0,
            	4095, 0,
            	4095, 0,
            	2297, 0,
            1, 8, 1, /* 4095: pointer.struct.asn1_string_st */
            	3920, 0,
            1, 8, 1, /* 4100: pointer.struct.asn1_string_st */
            	3920, 0,
            1, 8, 1, /* 4105: pointer.struct.asn1_string_st */
            	3920, 0,
            1, 8, 1, /* 4110: pointer.struct.asn1_string_st */
            	3920, 0,
            1, 8, 1, /* 4115: pointer.struct.asn1_string_st */
            	3920, 0,
            1, 8, 1, /* 4120: pointer.struct.asn1_string_st */
            	3920, 0,
            1, 8, 1, /* 4125: pointer.struct.asn1_string_st */
            	3920, 0,
            1, 8, 1, /* 4130: pointer.struct.asn1_string_st */
            	3920, 0,
            1, 8, 1, /* 4135: pointer.struct.asn1_string_st */
            	3920, 0,
            1, 8, 1, /* 4140: pointer.struct.asn1_string_st */
            	3920, 0,
            1, 8, 1, /* 4145: pointer.struct.asn1_string_st */
            	3920, 0,
            1, 8, 1, /* 4150: pointer.struct.asn1_string_st */
            	3920, 0,
            1, 8, 1, /* 4155: pointer.struct.X509_name_st */
            	4160, 0,
            0, 40, 3, /* 4160: struct.X509_name_st */
            	4169, 0,
            	4193, 16,
            	200, 24,
            1, 8, 1, /* 4169: pointer.struct.stack_st_X509_NAME_ENTRY */
            	4174, 0,
            0, 32, 2, /* 4174: struct.stack_st_fake_X509_NAME_ENTRY */
            	4181, 8,
            	360, 24,
            8884099, 8, 2, /* 4181: pointer_to_array_of_pointers_to_stack */
            	4188, 0,
            	357, 20,
            0, 8, 1, /* 4188: pointer.X509_NAME_ENTRY */
            	321, 0,
            1, 8, 1, /* 4193: pointer.struct.buf_mem_st */
            	4198, 0,
            0, 24, 1, /* 4198: struct.buf_mem_st */
            	93, 8,
            1, 8, 1, /* 4203: pointer.struct.X509_val_st */
            	4208, 0,
            0, 16, 2, /* 4208: struct.X509_val_st */
            	4215, 0,
            	4215, 8,
            1, 8, 1, /* 4215: pointer.struct.asn1_string_st */
            	3920, 0,
            1, 8, 1, /* 4220: pointer.struct.X509_pubkey_st */
            	4225, 0,
            0, 24, 3, /* 4225: struct.X509_pubkey_st */
            	4016, 0,
            	4105, 8,
            	4234, 16,
            1, 8, 1, /* 4234: pointer.struct.evp_pkey_st */
            	1746, 0,
            1, 8, 1, /* 4239: pointer.struct.stack_st_X509_EXTENSION */
            	4244, 0,
            0, 32, 2, /* 4244: struct.stack_st_fake_X509_EXTENSION */
            	4251, 8,
            	360, 24,
            8884099, 8, 2, /* 4251: pointer_to_array_of_pointers_to_stack */
            	4258, 0,
            	357, 20,
            0, 8, 1, /* 4258: pointer.X509_EXTENSION */
            	703, 0,
            0, 24, 1, /* 4263: struct.ASN1_ENCODING_st */
            	200, 0,
            1, 8, 1, /* 4268: pointer.struct.AUTHORITY_KEYID_st */
            	3899, 0,
            1, 8, 1, /* 4273: pointer.struct.X509_POLICY_CACHE_st */
            	3896, 0,
            1, 8, 1, /* 4278: pointer.struct.stack_st_GENERAL_NAME */
            	4283, 0,
            0, 32, 2, /* 4283: struct.stack_st_fake_GENERAL_NAME */
            	4290, 8,
            	360, 24,
            8884099, 8, 2, /* 4290: pointer_to_array_of_pointers_to_stack */
            	4297, 0,
            	357, 20,
            0, 8, 1, /* 4297: pointer.GENERAL_NAME */
            	50, 0,
            1, 8, 1, /* 4302: pointer.struct.NAME_CONSTRAINTS_st */
            	2291, 0,
            1, 8, 1, /* 4307: pointer.struct.x509_cert_aux_st */
            	3902, 0,
            0, 248, 25, /* 4312: struct.x509_store_ctx_st */
            	4365, 0,
            	2347, 16,
            	4490, 24,
            	4519, 32,
            	4451, 40,
            	898, 48,
            	4463, 56,
            	4466, 64,
            	4469, 72,
            	4472, 80,
            	4463, 88,
            	4475, 96,
            	4478, 104,
            	4481, 112,
            	4463, 120,
            	4484, 128,
            	4487, 136,
            	4463, 144,
            	4490, 160,
            	904, 168,
            	2347, 192,
            	2347, 200,
            	792, 208,
            	4576, 224,
            	1071, 232,
            1, 8, 1, /* 4365: pointer.struct.x509_store_st */
            	4370, 0,
            0, 144, 15, /* 4370: struct.x509_store_st */
            	4403, 8,
            	4427, 16,
            	4451, 24,
            	4463, 32,
            	4466, 40,
            	4469, 48,
            	4472, 56,
            	4463, 64,
            	4475, 72,
            	4478, 80,
            	4481, 88,
            	4484, 96,
            	4487, 104,
            	4463, 112,
            	1071, 120,
            1, 8, 1, /* 4403: pointer.struct.stack_st_X509_OBJECT */
            	4408, 0,
            0, 32, 2, /* 4408: struct.stack_st_fake_X509_OBJECT */
            	4415, 8,
            	360, 24,
            8884099, 8, 2, /* 4415: pointer_to_array_of_pointers_to_stack */
            	4422, 0,
            	357, 20,
            0, 8, 1, /* 4422: pointer.X509_OBJECT */
            	2948, 0,
            1, 8, 1, /* 4427: pointer.struct.stack_st_X509_LOOKUP */
            	4432, 0,
            0, 32, 2, /* 4432: struct.stack_st_fake_X509_LOOKUP */
            	4439, 8,
            	360, 24,
            8884099, 8, 2, /* 4439: pointer_to_array_of_pointers_to_stack */
            	4446, 0,
            	357, 20,
            0, 8, 1, /* 4446: pointer.X509_LOOKUP */
            	2823, 0,
            1, 8, 1, /* 4451: pointer.struct.X509_VERIFY_PARAM_st */
            	4456, 0,
            0, 56, 2, /* 4456: struct.X509_VERIFY_PARAM_st */
            	93, 0,
            	2522, 48,
            8884097, 8, 0, /* 4463: pointer.func */
            8884097, 8, 0, /* 4466: pointer.func */
            8884097, 8, 0, /* 4469: pointer.func */
            8884097, 8, 0, /* 4472: pointer.func */
            8884097, 8, 0, /* 4475: pointer.func */
            8884097, 8, 0, /* 4478: pointer.func */
            8884097, 8, 0, /* 4481: pointer.func */
            8884097, 8, 0, /* 4484: pointer.func */
            8884097, 8, 0, /* 4487: pointer.func */
            1, 8, 1, /* 4490: pointer.struct.stack_st_X509 */
            	4495, 0,
            0, 32, 2, /* 4495: struct.stack_st_fake_X509 */
            	4502, 8,
            	360, 24,
            8884099, 8, 2, /* 4502: pointer_to_array_of_pointers_to_stack */
            	4509, 0,
            	357, 20,
            0, 8, 1, /* 4509: pointer.X509 */
            	4514, 0,
            0, 0, 1, /* 4514: X509 */
            	3954, 0,
            1, 8, 1, /* 4519: pointer.struct.stack_st_X509_CRL */
            	4524, 0,
            0, 32, 2, /* 4524: struct.stack_st_fake_X509_CRL */
            	4531, 8,
            	360, 24,
            8884099, 8, 2, /* 4531: pointer_to_array_of_pointers_to_stack */
            	4538, 0,
            	357, 20,
            0, 8, 1, /* 4538: pointer.X509_CRL */
            	4543, 0,
            0, 0, 1, /* 4543: X509_CRL */
            	4548, 0,
            0, 120, 10, /* 4548: struct.X509_crl_st */
            	4571, 0,
            	2599, 8,
            	2688, 16,
            	3595, 32,
            	3801, 40,
            	2594, 56,
            	2594, 64,
            	844, 96,
            	890, 104,
            	898, 112,
            1, 8, 1, /* 4571: pointer.struct.X509_crl_info_st */
            	2575, 0,
            1, 8, 1, /* 4576: pointer.struct.x509_store_ctx_st */
            	4312, 0,
            0, 1, 0, /* 4581: char */
        },
        .arg_entity_index = { 4576, 4365, 2347, 4490, },
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

