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

EVP_PKEY * bb_X509_get_pubkey(X509 * arg_a);

EVP_PKEY * X509_get_pubkey(X509 * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("X509_get_pubkey called %lu\n", in_lib);
    if (!in_lib)
        return bb_X509_get_pubkey(arg_a);
    else {
        EVP_PKEY * (*orig_X509_get_pubkey)(X509 *);
        orig_X509_get_pubkey = dlsym(RTLD_NEXT, "X509_get_pubkey");
        return orig_X509_get_pubkey(arg_a);
    }
}

EVP_PKEY * bb_X509_get_pubkey(X509 * arg_a) 
{
    EVP_PKEY * ret;

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
            1, 8, 1, /* 18: pointer.struct.asn1_string_st */
            	5, 0,
            1, 8, 1, /* 23: pointer.struct.asn1_string_st */
            	5, 0,
            1, 8, 1, /* 28: pointer.struct.asn1_string_st */
            	5, 0,
            1, 8, 1, /* 33: pointer.struct.asn1_string_st */
            	5, 0,
            1, 8, 1, /* 38: pointer.struct.asn1_string_st */
            	5, 0,
            1, 8, 1, /* 43: pointer.struct.asn1_string_st */
            	5, 0,
            1, 8, 1, /* 48: pointer.struct.asn1_string_st */
            	5, 0,
            1, 8, 1, /* 53: pointer.struct.asn1_string_st */
            	5, 0,
            0, 8, 20, /* 58: union.unknown */
            	101, 0,
            	53, 0,
            	106, 0,
            	48, 0,
            	43, 0,
            	130, 0,
            	38, 0,
            	135, 0,
            	33, 0,
            	28, 0,
            	23, 0,
            	140, 0,
            	145, 0,
            	18, 0,
            	0, 0,
            	150, 0,
            	155, 0,
            	53, 0,
            	53, 0,
            	160, 0,
            1, 8, 1, /* 101: pointer.char */
            	64096, 0,
            1, 8, 1, /* 106: pointer.struct.asn1_object_st */
            	111, 0,
            0, 40, 3, /* 111: struct.asn1_object_st */
            	120, 0,
            	120, 8,
            	125, 24,
            1, 8, 1, /* 120: pointer.char */
            	64096, 0,
            1, 8, 1, /* 125: pointer.unsigned char */
            	15, 0,
            1, 8, 1, /* 130: pointer.struct.asn1_string_st */
            	5, 0,
            1, 8, 1, /* 135: pointer.struct.asn1_string_st */
            	5, 0,
            1, 8, 1, /* 140: pointer.struct.asn1_string_st */
            	5, 0,
            1, 8, 1, /* 145: pointer.struct.asn1_string_st */
            	5, 0,
            1, 8, 1, /* 150: pointer.struct.asn1_string_st */
            	5, 0,
            1, 8, 1, /* 155: pointer.struct.asn1_string_st */
            	5, 0,
            1, 8, 1, /* 160: pointer.struct.ASN1_VALUE_st */
            	165, 0,
            0, 0, 0, /* 165: struct.ASN1_VALUE_st */
            0, 16, 2, /* 168: struct.X509_algor_st */
            	106, 0,
            	175, 8,
            1, 8, 1, /* 175: pointer.struct.asn1_type_st */
            	180, 0,
            0, 16, 1, /* 180: struct.asn1_type_st */
            	58, 8,
            0, 0, 1, /* 185: X509_ALGOR */
            	168, 0,
            1, 8, 1, /* 190: pointer.struct.stack_st_X509_ALGOR */
            	195, 0,
            0, 32, 2, /* 195: struct.stack_st_fake_X509_ALGOR */
            	202, 8,
            	217, 24,
            64099, 8, 2, /* 202: pointer_to_array_of_pointers_to_stack */
            	209, 0,
            	214, 20,
            0, 8, 1, /* 209: pointer.X509_ALGOR */
            	185, 0,
            0, 4, 0, /* 214: int */
            64097, 8, 0, /* 217: pointer.func */
            0, 0, 1, /* 220: ASN1_OBJECT */
            	225, 0,
            0, 40, 3, /* 225: struct.asn1_object_st */
            	120, 0,
            	120, 8,
            	125, 24,
            0, 40, 5, /* 234: struct.x509_cert_aux_st */
            	247, 0,
            	247, 8,
            	271, 16,
            	281, 24,
            	190, 32,
            1, 8, 1, /* 247: pointer.struct.stack_st_ASN1_OBJECT */
            	252, 0,
            0, 32, 2, /* 252: struct.stack_st_fake_ASN1_OBJECT */
            	259, 8,
            	217, 24,
            64099, 8, 2, /* 259: pointer_to_array_of_pointers_to_stack */
            	266, 0,
            	214, 20,
            0, 8, 1, /* 266: pointer.ASN1_OBJECT */
            	220, 0,
            1, 8, 1, /* 271: pointer.struct.asn1_string_st */
            	276, 0,
            0, 24, 1, /* 276: struct.asn1_string_st */
            	10, 8,
            1, 8, 1, /* 281: pointer.struct.asn1_string_st */
            	276, 0,
            1, 8, 1, /* 286: pointer.struct.x509_cert_aux_st */
            	234, 0,
            0, 16, 2, /* 291: struct.EDIPartyName_st */
            	298, 0,
            	298, 8,
            1, 8, 1, /* 298: pointer.struct.asn1_string_st */
            	303, 0,
            0, 24, 1, /* 303: struct.asn1_string_st */
            	10, 8,
            1, 8, 1, /* 308: pointer.struct.asn1_string_st */
            	313, 0,
            0, 24, 1, /* 313: struct.asn1_string_st */
            	10, 8,
            1, 8, 1, /* 318: pointer.struct.asn1_string_st */
            	313, 0,
            0, 40, 3, /* 323: struct.asn1_object_st */
            	120, 0,
            	120, 8,
            	125, 24,
            1, 8, 1, /* 332: pointer.struct.asn1_string_st */
            	337, 0,
            0, 24, 1, /* 337: struct.asn1_string_st */
            	10, 8,
            0, 0, 1, /* 342: ASN1_TYPE */
            	347, 0,
            0, 16, 1, /* 347: struct.asn1_type_st */
            	352, 8,
            0, 8, 20, /* 352: union.unknown */
            	101, 0,
            	395, 0,
            	400, 0,
            	318, 0,
            	405, 0,
            	308, 0,
            	410, 0,
            	415, 0,
            	420, 0,
            	425, 0,
            	430, 0,
            	435, 0,
            	440, 0,
            	445, 0,
            	450, 0,
            	455, 0,
            	460, 0,
            	395, 0,
            	395, 0,
            	465, 0,
            1, 8, 1, /* 395: pointer.struct.asn1_string_st */
            	313, 0,
            1, 8, 1, /* 400: pointer.struct.asn1_object_st */
            	323, 0,
            1, 8, 1, /* 405: pointer.struct.asn1_string_st */
            	313, 0,
            1, 8, 1, /* 410: pointer.struct.asn1_string_st */
            	313, 0,
            1, 8, 1, /* 415: pointer.struct.asn1_string_st */
            	313, 0,
            1, 8, 1, /* 420: pointer.struct.asn1_string_st */
            	313, 0,
            1, 8, 1, /* 425: pointer.struct.asn1_string_st */
            	313, 0,
            1, 8, 1, /* 430: pointer.struct.asn1_string_st */
            	313, 0,
            1, 8, 1, /* 435: pointer.struct.asn1_string_st */
            	313, 0,
            1, 8, 1, /* 440: pointer.struct.asn1_string_st */
            	313, 0,
            1, 8, 1, /* 445: pointer.struct.asn1_string_st */
            	313, 0,
            1, 8, 1, /* 450: pointer.struct.asn1_string_st */
            	313, 0,
            1, 8, 1, /* 455: pointer.struct.asn1_string_st */
            	313, 0,
            1, 8, 1, /* 460: pointer.struct.asn1_string_st */
            	313, 0,
            1, 8, 1, /* 465: pointer.struct.ASN1_VALUE_st */
            	470, 0,
            0, 0, 0, /* 470: struct.ASN1_VALUE_st */
            1, 8, 1, /* 473: pointer.struct.asn1_string_st */
            	276, 0,
            1, 8, 1, /* 478: pointer.struct.asn1_string_st */
            	337, 0,
            0, 40, 3, /* 483: struct.asn1_object_st */
            	120, 0,
            	120, 8,
            	125, 24,
            1, 8, 1, /* 492: pointer.struct.ec_key_st */
            	497, 0,
            0, 0, 0, /* 497: struct.ec_key_st */
            1, 8, 1, /* 500: pointer.struct.asn1_type_st */
            	505, 0,
            0, 16, 1, /* 505: struct.asn1_type_st */
            	510, 8,
            0, 8, 20, /* 510: union.unknown */
            	101, 0,
            	553, 0,
            	558, 0,
            	572, 0,
            	577, 0,
            	582, 0,
            	281, 0,
            	587, 0,
            	592, 0,
            	597, 0,
            	602, 0,
            	607, 0,
            	612, 0,
            	473, 0,
            	617, 0,
            	622, 0,
            	271, 0,
            	553, 0,
            	553, 0,
            	160, 0,
            1, 8, 1, /* 553: pointer.struct.asn1_string_st */
            	276, 0,
            1, 8, 1, /* 558: pointer.struct.asn1_object_st */
            	563, 0,
            0, 40, 3, /* 563: struct.asn1_object_st */
            	120, 0,
            	120, 8,
            	125, 24,
            1, 8, 1, /* 572: pointer.struct.asn1_string_st */
            	276, 0,
            1, 8, 1, /* 577: pointer.struct.asn1_string_st */
            	276, 0,
            1, 8, 1, /* 582: pointer.struct.asn1_string_st */
            	276, 0,
            1, 8, 1, /* 587: pointer.struct.asn1_string_st */
            	276, 0,
            1, 8, 1, /* 592: pointer.struct.asn1_string_st */
            	276, 0,
            1, 8, 1, /* 597: pointer.struct.asn1_string_st */
            	276, 0,
            1, 8, 1, /* 602: pointer.struct.asn1_string_st */
            	276, 0,
            1, 8, 1, /* 607: pointer.struct.asn1_string_st */
            	276, 0,
            1, 8, 1, /* 612: pointer.struct.asn1_string_st */
            	276, 0,
            1, 8, 1, /* 617: pointer.struct.asn1_string_st */
            	276, 0,
            1, 8, 1, /* 622: pointer.struct.asn1_string_st */
            	276, 0,
            64097, 8, 0, /* 627: pointer.func */
            0, 72, 8, /* 630: struct.dh_method */
            	120, 0,
            	649, 8,
            	627, 16,
            	652, 24,
            	649, 32,
            	649, 40,
            	101, 56,
            	655, 64,
            64097, 8, 0, /* 649: pointer.func */
            64097, 8, 0, /* 652: pointer.func */
            64097, 8, 0, /* 655: pointer.func */
            64097, 8, 0, /* 658: pointer.func */
            64097, 8, 0, /* 661: pointer.func */
            64097, 8, 0, /* 664: pointer.func */
            0, 0, 0, /* 667: struct.evp_pkey_asn1_method_st */
            0, 8, 15, /* 670: union.unknown */
            	101, 0,
            	703, 0,
            	812, 0,
            	812, 0,
            	729, 0,
            	860, 0,
            	944, 0,
            	812, 0,
            	797, 0,
            	715, 0,
            	797, 0,
            	860, 0,
            	812, 0,
            	715, 0,
            	729, 0,
            1, 8, 1, /* 703: pointer.struct.otherName_st */
            	708, 0,
            0, 16, 2, /* 708: struct.otherName_st */
            	715, 0,
            	729, 8,
            1, 8, 1, /* 715: pointer.struct.asn1_object_st */
            	720, 0,
            0, 40, 3, /* 720: struct.asn1_object_st */
            	120, 0,
            	120, 8,
            	125, 24,
            1, 8, 1, /* 729: pointer.struct.asn1_type_st */
            	734, 0,
            0, 16, 1, /* 734: struct.asn1_type_st */
            	739, 8,
            0, 8, 20, /* 739: union.unknown */
            	101, 0,
            	298, 0,
            	715, 0,
            	782, 0,
            	787, 0,
            	792, 0,
            	797, 0,
            	802, 0,
            	807, 0,
            	812, 0,
            	817, 0,
            	822, 0,
            	827, 0,
            	832, 0,
            	837, 0,
            	842, 0,
            	847, 0,
            	298, 0,
            	298, 0,
            	852, 0,
            1, 8, 1, /* 782: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 787: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 792: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 797: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 802: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 807: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 812: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 817: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 822: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 827: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 832: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 837: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 842: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 847: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 852: pointer.struct.ASN1_VALUE_st */
            	857, 0,
            0, 0, 0, /* 857: struct.ASN1_VALUE_st */
            1, 8, 1, /* 860: pointer.struct.X509_name_st */
            	865, 0,
            0, 40, 3, /* 865: struct.X509_name_st */
            	874, 0,
            	934, 16,
            	10, 24,
            1, 8, 1, /* 874: pointer.struct.stack_st_X509_NAME_ENTRY */
            	879, 0,
            0, 32, 2, /* 879: struct.stack_st_fake_X509_NAME_ENTRY */
            	886, 8,
            	217, 24,
            64099, 8, 2, /* 886: pointer_to_array_of_pointers_to_stack */
            	893, 0,
            	214, 20,
            0, 8, 1, /* 893: pointer.X509_NAME_ENTRY */
            	898, 0,
            0, 0, 1, /* 898: X509_NAME_ENTRY */
            	903, 0,
            0, 24, 2, /* 903: struct.X509_name_entry_st */
            	910, 0,
            	924, 8,
            1, 8, 1, /* 910: pointer.struct.asn1_object_st */
            	915, 0,
            0, 40, 3, /* 915: struct.asn1_object_st */
            	120, 0,
            	120, 8,
            	125, 24,
            1, 8, 1, /* 924: pointer.struct.asn1_string_st */
            	929, 0,
            0, 24, 1, /* 929: struct.asn1_string_st */
            	10, 8,
            1, 8, 1, /* 934: pointer.struct.buf_mem_st */
            	939, 0,
            0, 24, 1, /* 939: struct.buf_mem_st */
            	101, 8,
            1, 8, 1, /* 944: pointer.struct.EDIPartyName_st */
            	291, 0,
            1, 8, 1, /* 949: pointer.struct.dsa_method */
            	954, 0,
            0, 96, 11, /* 954: struct.dsa_method */
            	120, 0,
            	664, 8,
            	979, 16,
            	661, 24,
            	658, 32,
            	982, 40,
            	985, 48,
            	985, 56,
            	101, 72,
            	988, 80,
            	985, 88,
            64097, 8, 0, /* 979: pointer.func */
            64097, 8, 0, /* 982: pointer.func */
            64097, 8, 0, /* 985: pointer.func */
            64097, 8, 0, /* 988: pointer.func */
            1, 8, 1, /* 991: pointer.struct.dh_method */
            	630, 0,
            0, 24, 3, /* 996: struct.AUTHORITY_KEYID_st */
            	281, 0,
            	1005, 8,
            	572, 16,
            1, 8, 1, /* 1005: pointer.struct.stack_st_GENERAL_NAME */
            	1010, 0,
            0, 32, 2, /* 1010: struct.stack_st_fake_GENERAL_NAME */
            	1017, 8,
            	217, 24,
            64099, 8, 2, /* 1017: pointer_to_array_of_pointers_to_stack */
            	1024, 0,
            	214, 20,
            0, 8, 1, /* 1024: pointer.GENERAL_NAME */
            	1029, 0,
            0, 0, 1, /* 1029: GENERAL_NAME */
            	1034, 0,
            0, 16, 1, /* 1034: struct.GENERAL_NAME_st */
            	1039, 8,
            0, 8, 15, /* 1039: union.unknown */
            	101, 0,
            	1072, 0,
            	1181, 0,
            	1181, 0,
            	1098, 0,
            	1216, 0,
            	1264, 0,
            	1181, 0,
            	1171, 0,
            	1084, 0,
            	1171, 0,
            	1216, 0,
            	1181, 0,
            	1084, 0,
            	1098, 0,
            1, 8, 1, /* 1072: pointer.struct.otherName_st */
            	1077, 0,
            0, 16, 2, /* 1077: struct.otherName_st */
            	1084, 0,
            	1098, 8,
            1, 8, 1, /* 1084: pointer.struct.asn1_object_st */
            	1089, 0,
            0, 40, 3, /* 1089: struct.asn1_object_st */
            	120, 0,
            	120, 8,
            	125, 24,
            1, 8, 1, /* 1098: pointer.struct.asn1_type_st */
            	1103, 0,
            0, 16, 1, /* 1103: struct.asn1_type_st */
            	1108, 8,
            0, 8, 20, /* 1108: union.unknown */
            	101, 0,
            	1151, 0,
            	1084, 0,
            	1156, 0,
            	1161, 0,
            	1166, 0,
            	1171, 0,
            	1176, 0,
            	478, 0,
            	1181, 0,
            	1186, 0,
            	1191, 0,
            	332, 0,
            	1196, 0,
            	1201, 0,
            	1206, 0,
            	1211, 0,
            	1151, 0,
            	1151, 0,
            	852, 0,
            1, 8, 1, /* 1151: pointer.struct.asn1_string_st */
            	337, 0,
            1, 8, 1, /* 1156: pointer.struct.asn1_string_st */
            	337, 0,
            1, 8, 1, /* 1161: pointer.struct.asn1_string_st */
            	337, 0,
            1, 8, 1, /* 1166: pointer.struct.asn1_string_st */
            	337, 0,
            1, 8, 1, /* 1171: pointer.struct.asn1_string_st */
            	337, 0,
            1, 8, 1, /* 1176: pointer.struct.asn1_string_st */
            	337, 0,
            1, 8, 1, /* 1181: pointer.struct.asn1_string_st */
            	337, 0,
            1, 8, 1, /* 1186: pointer.struct.asn1_string_st */
            	337, 0,
            1, 8, 1, /* 1191: pointer.struct.asn1_string_st */
            	337, 0,
            1, 8, 1, /* 1196: pointer.struct.asn1_string_st */
            	337, 0,
            1, 8, 1, /* 1201: pointer.struct.asn1_string_st */
            	337, 0,
            1, 8, 1, /* 1206: pointer.struct.asn1_string_st */
            	337, 0,
            1, 8, 1, /* 1211: pointer.struct.asn1_string_st */
            	337, 0,
            1, 8, 1, /* 1216: pointer.struct.X509_name_st */
            	1221, 0,
            0, 40, 3, /* 1221: struct.X509_name_st */
            	1230, 0,
            	1254, 16,
            	10, 24,
            1, 8, 1, /* 1230: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1235, 0,
            0, 32, 2, /* 1235: struct.stack_st_fake_X509_NAME_ENTRY */
            	1242, 8,
            	217, 24,
            64099, 8, 2, /* 1242: pointer_to_array_of_pointers_to_stack */
            	1249, 0,
            	214, 20,
            0, 8, 1, /* 1249: pointer.X509_NAME_ENTRY */
            	898, 0,
            1, 8, 1, /* 1254: pointer.struct.buf_mem_st */
            	1259, 0,
            0, 24, 1, /* 1259: struct.buf_mem_st */
            	101, 8,
            1, 8, 1, /* 1264: pointer.struct.EDIPartyName_st */
            	1269, 0,
            0, 16, 2, /* 1269: struct.EDIPartyName_st */
            	1151, 0,
            	1151, 8,
            0, 0, 0, /* 1276: struct.bn_blinding_st */
            0, 32, 1, /* 1279: struct.stack_st_void */
            	1284, 0,
            0, 32, 2, /* 1284: struct.stack_st */
            	1291, 8,
            	217, 24,
            1, 8, 1, /* 1291: pointer.pointer.char */
            	101, 0,
            1, 8, 1, /* 1296: pointer.unsigned int */
            	1301, 0,
            0, 4, 0, /* 1301: unsigned int */
            1, 8, 1, /* 1304: pointer.struct.dsa_st */
            	1309, 0,
            0, 136, 11, /* 1309: struct.dsa_st */
            	1334, 24,
            	1334, 32,
            	1334, 40,
            	1334, 48,
            	1334, 56,
            	1334, 64,
            	1334, 72,
            	1344, 88,
            	1358, 104,
            	949, 120,
            	1368, 128,
            1, 8, 1, /* 1334: pointer.struct.bignum_st */
            	1339, 0,
            0, 24, 1, /* 1339: struct.bignum_st */
            	1296, 0,
            1, 8, 1, /* 1344: pointer.struct.bn_mont_ctx_st */
            	1349, 0,
            0, 96, 3, /* 1349: struct.bn_mont_ctx_st */
            	1339, 8,
            	1339, 32,
            	1339, 56,
            0, 16, 1, /* 1358: struct.crypto_ex_data_st */
            	1363, 0,
            1, 8, 1, /* 1363: pointer.struct.stack_st_void */
            	1279, 0,
            1, 8, 1, /* 1368: pointer.struct.engine_st */
            	1373, 0,
            0, 0, 0, /* 1373: struct.engine_st */
            0, 16, 2, /* 1376: struct.NAME_CONSTRAINTS_st */
            	1383, 0,
            	1383, 8,
            1, 8, 1, /* 1383: pointer.struct.stack_st_GENERAL_SUBTREE */
            	1388, 0,
            0, 32, 2, /* 1388: struct.stack_st_fake_GENERAL_SUBTREE */
            	1395, 8,
            	217, 24,
            64099, 8, 2, /* 1395: pointer_to_array_of_pointers_to_stack */
            	1402, 0,
            	214, 20,
            0, 8, 1, /* 1402: pointer.GENERAL_SUBTREE */
            	1407, 0,
            0, 0, 1, /* 1407: GENERAL_SUBTREE */
            	1412, 0,
            0, 24, 3, /* 1412: struct.GENERAL_SUBTREE_st */
            	1421, 0,
            	782, 8,
            	782, 16,
            1, 8, 1, /* 1421: pointer.struct.GENERAL_NAME_st */
            	1426, 0,
            0, 16, 1, /* 1426: struct.GENERAL_NAME_st */
            	670, 8,
            0, 24, 3, /* 1431: struct.X509_pubkey_st */
            	1440, 0,
            	582, 8,
            	1452, 16,
            1, 8, 1, /* 1440: pointer.struct.X509_algor_st */
            	1445, 0,
            0, 16, 2, /* 1445: struct.X509_algor_st */
            	558, 0,
            	500, 8,
            1, 8, 1, /* 1452: pointer.struct.evp_pkey_st */
            	1457, 0,
            0, 56, 4, /* 1457: struct.evp_pkey_st */
            	1468, 16,
            	1368, 24,
            	1473, 32,
            	1620, 48,
            1, 8, 1, /* 1468: pointer.struct.evp_pkey_asn1_method_st */
            	667, 0,
            0, 8, 5, /* 1473: union.unknown */
            	101, 0,
            	1486, 0,
            	1304, 0,
            	1588, 0,
            	492, 0,
            1, 8, 1, /* 1486: pointer.struct.rsa_st */
            	1491, 0,
            0, 168, 17, /* 1491: struct.rsa_st */
            	1528, 16,
            	1368, 24,
            	1334, 32,
            	1334, 40,
            	1334, 48,
            	1334, 56,
            	1334, 64,
            	1334, 72,
            	1334, 80,
            	1334, 88,
            	1358, 96,
            	1344, 120,
            	1344, 128,
            	1344, 136,
            	101, 144,
            	1583, 152,
            	1583, 160,
            1, 8, 1, /* 1528: pointer.struct.rsa_meth_st */
            	1533, 0,
            0, 112, 13, /* 1533: struct.rsa_meth_st */
            	120, 0,
            	1562, 8,
            	1562, 16,
            	1562, 24,
            	1562, 32,
            	1565, 40,
            	1568, 48,
            	1571, 56,
            	1571, 64,
            	101, 80,
            	1574, 88,
            	1577, 96,
            	1580, 104,
            64097, 8, 0, /* 1562: pointer.func */
            64097, 8, 0, /* 1565: pointer.func */
            64097, 8, 0, /* 1568: pointer.func */
            64097, 8, 0, /* 1571: pointer.func */
            64097, 8, 0, /* 1574: pointer.func */
            64097, 8, 0, /* 1577: pointer.func */
            64097, 8, 0, /* 1580: pointer.func */
            1, 8, 1, /* 1583: pointer.struct.bn_blinding_st */
            	1276, 0,
            1, 8, 1, /* 1588: pointer.struct.dh_st */
            	1593, 0,
            0, 144, 12, /* 1593: struct.dh_st */
            	1334, 8,
            	1334, 16,
            	1334, 32,
            	1334, 40,
            	1344, 56,
            	1334, 64,
            	1334, 72,
            	10, 80,
            	1334, 96,
            	1358, 112,
            	991, 128,
            	1368, 136,
            1, 8, 1, /* 1620: pointer.struct.stack_st_X509_ATTRIBUTE */
            	1625, 0,
            0, 32, 2, /* 1625: struct.stack_st_fake_X509_ATTRIBUTE */
            	1632, 8,
            	217, 24,
            64099, 8, 2, /* 1632: pointer_to_array_of_pointers_to_stack */
            	1639, 0,
            	214, 20,
            0, 8, 1, /* 1639: pointer.X509_ATTRIBUTE */
            	1644, 0,
            0, 0, 1, /* 1644: X509_ATTRIBUTE */
            	1649, 0,
            0, 24, 2, /* 1649: struct.x509_attributes_st */
            	1656, 0,
            	1661, 16,
            1, 8, 1, /* 1656: pointer.struct.asn1_object_st */
            	483, 0,
            0, 8, 3, /* 1661: union.unknown */
            	101, 0,
            	1670, 0,
            	1694, 0,
            1, 8, 1, /* 1670: pointer.struct.stack_st_ASN1_TYPE */
            	1675, 0,
            0, 32, 2, /* 1675: struct.stack_st_fake_ASN1_TYPE */
            	1682, 8,
            	217, 24,
            64099, 8, 2, /* 1682: pointer_to_array_of_pointers_to_stack */
            	1689, 0,
            	214, 20,
            0, 8, 1, /* 1689: pointer.ASN1_TYPE */
            	342, 0,
            1, 8, 1, /* 1694: pointer.struct.asn1_type_st */
            	1699, 0,
            0, 16, 1, /* 1699: struct.asn1_type_st */
            	1704, 8,
            0, 8, 20, /* 1704: union.unknown */
            	101, 0,
            	1747, 0,
            	1656, 0,
            	1757, 0,
            	1762, 0,
            	1767, 0,
            	1772, 0,
            	1777, 0,
            	1782, 0,
            	1787, 0,
            	1792, 0,
            	1797, 0,
            	1802, 0,
            	1807, 0,
            	1812, 0,
            	1817, 0,
            	1822, 0,
            	1747, 0,
            	1747, 0,
            	160, 0,
            1, 8, 1, /* 1747: pointer.struct.asn1_string_st */
            	1752, 0,
            0, 24, 1, /* 1752: struct.asn1_string_st */
            	10, 8,
            1, 8, 1, /* 1757: pointer.struct.asn1_string_st */
            	1752, 0,
            1, 8, 1, /* 1762: pointer.struct.asn1_string_st */
            	1752, 0,
            1, 8, 1, /* 1767: pointer.struct.asn1_string_st */
            	1752, 0,
            1, 8, 1, /* 1772: pointer.struct.asn1_string_st */
            	1752, 0,
            1, 8, 1, /* 1777: pointer.struct.asn1_string_st */
            	1752, 0,
            1, 8, 1, /* 1782: pointer.struct.asn1_string_st */
            	1752, 0,
            1, 8, 1, /* 1787: pointer.struct.asn1_string_st */
            	1752, 0,
            1, 8, 1, /* 1792: pointer.struct.asn1_string_st */
            	1752, 0,
            1, 8, 1, /* 1797: pointer.struct.asn1_string_st */
            	1752, 0,
            1, 8, 1, /* 1802: pointer.struct.asn1_string_st */
            	1752, 0,
            1, 8, 1, /* 1807: pointer.struct.asn1_string_st */
            	1752, 0,
            1, 8, 1, /* 1812: pointer.struct.asn1_string_st */
            	1752, 0,
            1, 8, 1, /* 1817: pointer.struct.asn1_string_st */
            	1752, 0,
            1, 8, 1, /* 1822: pointer.struct.asn1_string_st */
            	1752, 0,
            1, 8, 1, /* 1827: pointer.struct.DIST_POINT_NAME_st */
            	1832, 0,
            0, 24, 2, /* 1832: struct.DIST_POINT_NAME_st */
            	1839, 8,
            	1894, 16,
            0, 8, 2, /* 1839: union.unknown */
            	1846, 0,
            	1870, 0,
            1, 8, 1, /* 1846: pointer.struct.stack_st_GENERAL_NAME */
            	1851, 0,
            0, 32, 2, /* 1851: struct.stack_st_fake_GENERAL_NAME */
            	1858, 8,
            	217, 24,
            64099, 8, 2, /* 1858: pointer_to_array_of_pointers_to_stack */
            	1865, 0,
            	214, 20,
            0, 8, 1, /* 1865: pointer.GENERAL_NAME */
            	1029, 0,
            1, 8, 1, /* 1870: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1875, 0,
            0, 32, 2, /* 1875: struct.stack_st_fake_X509_NAME_ENTRY */
            	1882, 8,
            	217, 24,
            64099, 8, 2, /* 1882: pointer_to_array_of_pointers_to_stack */
            	1889, 0,
            	214, 20,
            0, 8, 1, /* 1889: pointer.X509_NAME_ENTRY */
            	898, 0,
            1, 8, 1, /* 1894: pointer.struct.X509_name_st */
            	1899, 0,
            0, 40, 3, /* 1899: struct.X509_name_st */
            	1870, 0,
            	1908, 16,
            	10, 24,
            1, 8, 1, /* 1908: pointer.struct.buf_mem_st */
            	1913, 0,
            0, 24, 1, /* 1913: struct.buf_mem_st */
            	101, 8,
            0, 16, 2, /* 1918: struct.X509_val_st */
            	1925, 0,
            	1925, 8,
            1, 8, 1, /* 1925: pointer.struct.asn1_string_st */
            	276, 0,
            1, 8, 1, /* 1930: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1935, 0,
            0, 32, 2, /* 1935: struct.stack_st_fake_X509_NAME_ENTRY */
            	1942, 8,
            	217, 24,
            64099, 8, 2, /* 1942: pointer_to_array_of_pointers_to_stack */
            	1949, 0,
            	214, 20,
            0, 8, 1, /* 1949: pointer.X509_NAME_ENTRY */
            	898, 0,
            0, 104, 11, /* 1954: struct.x509_cinf_st */
            	572, 0,
            	572, 8,
            	1440, 16,
            	1979, 24,
            	2003, 32,
            	1979, 40,
            	2008, 48,
            	582, 56,
            	582, 64,
            	2013, 72,
            	2073, 80,
            1, 8, 1, /* 1979: pointer.struct.X509_name_st */
            	1984, 0,
            0, 40, 3, /* 1984: struct.X509_name_st */
            	1930, 0,
            	1993, 16,
            	10, 24,
            1, 8, 1, /* 1993: pointer.struct.buf_mem_st */
            	1998, 0,
            0, 24, 1, /* 1998: struct.buf_mem_st */
            	101, 8,
            1, 8, 1, /* 2003: pointer.struct.X509_val_st */
            	1918, 0,
            1, 8, 1, /* 2008: pointer.struct.X509_pubkey_st */
            	1431, 0,
            1, 8, 1, /* 2013: pointer.struct.stack_st_X509_EXTENSION */
            	2018, 0,
            0, 32, 2, /* 2018: struct.stack_st_fake_X509_EXTENSION */
            	2025, 8,
            	217, 24,
            64099, 8, 2, /* 2025: pointer_to_array_of_pointers_to_stack */
            	2032, 0,
            	214, 20,
            0, 8, 1, /* 2032: pointer.X509_EXTENSION */
            	2037, 0,
            0, 0, 1, /* 2037: X509_EXTENSION */
            	2042, 0,
            0, 24, 2, /* 2042: struct.X509_extension_st */
            	2049, 0,
            	2063, 16,
            1, 8, 1, /* 2049: pointer.struct.asn1_object_st */
            	2054, 0,
            0, 40, 3, /* 2054: struct.asn1_object_st */
            	120, 0,
            	120, 8,
            	125, 24,
            1, 8, 1, /* 2063: pointer.struct.asn1_string_st */
            	2068, 0,
            0, 24, 1, /* 2068: struct.asn1_string_st */
            	10, 8,
            0, 24, 1, /* 2073: struct.ASN1_ENCODING_st */
            	10, 0,
            0, 1, 0, /* 2078: char */
            0, 184, 12, /* 2081: struct.x509_st */
            	2108, 0,
            	1440, 8,
            	582, 16,
            	101, 32,
            	1358, 40,
            	281, 104,
            	2113, 112,
            	2118, 120,
            	2126, 128,
            	2174, 136,
            	2198, 144,
            	286, 176,
            1, 8, 1, /* 2108: pointer.struct.x509_cinf_st */
            	1954, 0,
            1, 8, 1, /* 2113: pointer.struct.AUTHORITY_KEYID_st */
            	996, 0,
            1, 8, 1, /* 2118: pointer.struct.X509_POLICY_CACHE_st */
            	2123, 0,
            0, 0, 0, /* 2123: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 2126: pointer.struct.stack_st_DIST_POINT */
            	2131, 0,
            0, 32, 2, /* 2131: struct.stack_st_fake_DIST_POINT */
            	2138, 8,
            	217, 24,
            64099, 8, 2, /* 2138: pointer_to_array_of_pointers_to_stack */
            	2145, 0,
            	214, 20,
            0, 8, 1, /* 2145: pointer.DIST_POINT */
            	2150, 0,
            0, 0, 1, /* 2150: DIST_POINT */
            	2155, 0,
            0, 32, 3, /* 2155: struct.DIST_POINT_st */
            	1827, 0,
            	2164, 8,
            	1846, 16,
            1, 8, 1, /* 2164: pointer.struct.asn1_string_st */
            	2169, 0,
            0, 24, 1, /* 2169: struct.asn1_string_st */
            	10, 8,
            1, 8, 1, /* 2174: pointer.struct.stack_st_GENERAL_NAME */
            	2179, 0,
            0, 32, 2, /* 2179: struct.stack_st_fake_GENERAL_NAME */
            	2186, 8,
            	217, 24,
            64099, 8, 2, /* 2186: pointer_to_array_of_pointers_to_stack */
            	2193, 0,
            	214, 20,
            0, 8, 1, /* 2193: pointer.GENERAL_NAME */
            	1029, 0,
            1, 8, 1, /* 2198: pointer.struct.NAME_CONSTRAINTS_st */
            	1376, 0,
            1, 8, 1, /* 2203: pointer.struct.x509_st */
            	2081, 0,
        },
        .arg_entity_index = { 2203, },
        .ret_entity_index = 1452,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    X509 * new_arg_a = *((X509 * *)new_args->args[0]);

    EVP_PKEY * *new_ret_ptr = (EVP_PKEY * *)new_args->ret;

    EVP_PKEY * (*orig_X509_get_pubkey)(X509 *);
    orig_X509_get_pubkey = dlsym(RTLD_NEXT, "X509_get_pubkey");
    *new_ret_ptr = (*orig_X509_get_pubkey)(new_arg_a);

    syscall(889);

    return ret;
}

