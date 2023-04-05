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

X509_NAME * bb_X509_get_subject_name(X509 * arg_a);

X509_NAME * X509_get_subject_name(X509 * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("X509_get_subject_name called %lu\n", in_lib);
    if (!in_lib)
        return bb_X509_get_subject_name(arg_a);
    else {
        X509_NAME * (*orig_X509_get_subject_name)(X509 *);
        orig_X509_get_subject_name = dlsym(RTLD_NEXT, "X509_get_subject_name");
        return orig_X509_get_subject_name(arg_a);
    }
}

X509_NAME * bb_X509_get_subject_name(X509 * arg_a) 
{
    X509_NAME * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            1, 8, 1, /* 0: pointer.struct.asn1_type_st */
            	5, 0,
            0, 16, 1, /* 5: struct.asn1_type_st */
            	10, 8,
            0, 8, 20, /* 10: union.unknown */
            	53, 0,
            	58, 0,
            	76, 0,
            	100, 0,
            	105, 0,
            	110, 0,
            	115, 0,
            	120, 0,
            	125, 0,
            	130, 0,
            	135, 0,
            	140, 0,
            	145, 0,
            	150, 0,
            	155, 0,
            	160, 0,
            	165, 0,
            	58, 0,
            	58, 0,
            	170, 0,
            1, 8, 1, /* 53: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 58: pointer.struct.asn1_string_st */
            	63, 0,
            0, 24, 1, /* 63: struct.asn1_string_st */
            	68, 8,
            1, 8, 1, /* 68: pointer.unsigned char */
            	73, 0,
            0, 1, 0, /* 73: unsigned char */
            1, 8, 1, /* 76: pointer.struct.asn1_object_st */
            	81, 0,
            0, 40, 3, /* 81: struct.asn1_object_st */
            	90, 0,
            	90, 8,
            	95, 24,
            1, 8, 1, /* 90: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 95: pointer.unsigned char */
            	73, 0,
            1, 8, 1, /* 100: pointer.struct.asn1_string_st */
            	63, 0,
            1, 8, 1, /* 105: pointer.struct.asn1_string_st */
            	63, 0,
            1, 8, 1, /* 110: pointer.struct.asn1_string_st */
            	63, 0,
            1, 8, 1, /* 115: pointer.struct.asn1_string_st */
            	63, 0,
            1, 8, 1, /* 120: pointer.struct.asn1_string_st */
            	63, 0,
            1, 8, 1, /* 125: pointer.struct.asn1_string_st */
            	63, 0,
            1, 8, 1, /* 130: pointer.struct.asn1_string_st */
            	63, 0,
            1, 8, 1, /* 135: pointer.struct.asn1_string_st */
            	63, 0,
            1, 8, 1, /* 140: pointer.struct.asn1_string_st */
            	63, 0,
            1, 8, 1, /* 145: pointer.struct.asn1_string_st */
            	63, 0,
            1, 8, 1, /* 150: pointer.struct.asn1_string_st */
            	63, 0,
            1, 8, 1, /* 155: pointer.struct.asn1_string_st */
            	63, 0,
            1, 8, 1, /* 160: pointer.struct.asn1_string_st */
            	63, 0,
            1, 8, 1, /* 165: pointer.struct.asn1_string_st */
            	63, 0,
            1, 8, 1, /* 170: pointer.struct.ASN1_VALUE_st */
            	175, 0,
            0, 0, 0, /* 175: struct.ASN1_VALUE_st */
            0, 0, 1, /* 178: X509_ALGOR */
            	183, 0,
            0, 16, 2, /* 183: struct.X509_algor_st */
            	76, 0,
            	0, 8,
            1, 8, 1, /* 190: pointer.struct.stack_st_X509_ALGOR */
            	195, 0,
            0, 32, 2, /* 195: struct.stack_st_fake_X509_ALGOR */
            	202, 8,
            	217, 24,
            8884099, 8, 2, /* 202: pointer_to_array_of_pointers_to_stack */
            	209, 0,
            	214, 20,
            0, 8, 1, /* 209: pointer.X509_ALGOR */
            	178, 0,
            0, 4, 0, /* 214: int */
            8884097, 8, 0, /* 217: pointer.func */
            0, 0, 1, /* 220: ASN1_OBJECT */
            	225, 0,
            0, 40, 3, /* 225: struct.asn1_object_st */
            	90, 0,
            	90, 8,
            	95, 24,
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
            8884099, 8, 2, /* 259: pointer_to_array_of_pointers_to_stack */
            	266, 0,
            	214, 20,
            0, 8, 1, /* 266: pointer.ASN1_OBJECT */
            	220, 0,
            1, 8, 1, /* 271: pointer.struct.asn1_string_st */
            	276, 0,
            0, 24, 1, /* 276: struct.asn1_string_st */
            	68, 8,
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
            	68, 8,
            1, 8, 1, /* 308: pointer.struct.EDIPartyName_st */
            	291, 0,
            0, 24, 1, /* 313: struct.buf_mem_st */
            	53, 8,
            8884097, 8, 0, /* 318: pointer.func */
            0, 8, 20, /* 321: union.unknown */
            	53, 0,
            	364, 0,
            	369, 0,
            	383, 0,
            	388, 0,
            	393, 0,
            	281, 0,
            	398, 0,
            	403, 0,
            	408, 0,
            	413, 0,
            	418, 0,
            	423, 0,
            	428, 0,
            	433, 0,
            	438, 0,
            	271, 0,
            	364, 0,
            	364, 0,
            	443, 0,
            1, 8, 1, /* 364: pointer.struct.asn1_string_st */
            	276, 0,
            1, 8, 1, /* 369: pointer.struct.asn1_object_st */
            	374, 0,
            0, 40, 3, /* 374: struct.asn1_object_st */
            	90, 0,
            	90, 8,
            	95, 24,
            1, 8, 1, /* 383: pointer.struct.asn1_string_st */
            	276, 0,
            1, 8, 1, /* 388: pointer.struct.asn1_string_st */
            	276, 0,
            1, 8, 1, /* 393: pointer.struct.asn1_string_st */
            	276, 0,
            1, 8, 1, /* 398: pointer.struct.asn1_string_st */
            	276, 0,
            1, 8, 1, /* 403: pointer.struct.asn1_string_st */
            	276, 0,
            1, 8, 1, /* 408: pointer.struct.asn1_string_st */
            	276, 0,
            1, 8, 1, /* 413: pointer.struct.asn1_string_st */
            	276, 0,
            1, 8, 1, /* 418: pointer.struct.asn1_string_st */
            	276, 0,
            1, 8, 1, /* 423: pointer.struct.asn1_string_st */
            	276, 0,
            1, 8, 1, /* 428: pointer.struct.asn1_string_st */
            	276, 0,
            1, 8, 1, /* 433: pointer.struct.asn1_string_st */
            	276, 0,
            1, 8, 1, /* 438: pointer.struct.asn1_string_st */
            	276, 0,
            1, 8, 1, /* 443: pointer.struct.ASN1_VALUE_st */
            	448, 0,
            0, 0, 0, /* 448: struct.ASN1_VALUE_st */
            0, 40, 3, /* 451: struct.asn1_object_st */
            	90, 0,
            	90, 8,
            	95, 24,
            0, 24, 2, /* 460: struct.x509_attributes_st */
            	467, 0,
            	472, 16,
            1, 8, 1, /* 467: pointer.struct.asn1_object_st */
            	451, 0,
            0, 8, 3, /* 472: union.unknown */
            	53, 0,
            	481, 0,
            	510, 0,
            1, 8, 1, /* 481: pointer.struct.stack_st_ASN1_TYPE */
            	486, 0,
            0, 32, 2, /* 486: struct.stack_st_fake_ASN1_TYPE */
            	493, 8,
            	217, 24,
            8884099, 8, 2, /* 493: pointer_to_array_of_pointers_to_stack */
            	500, 0,
            	214, 20,
            0, 8, 1, /* 500: pointer.ASN1_TYPE */
            	505, 0,
            0, 0, 1, /* 505: ASN1_TYPE */
            	5, 0,
            1, 8, 1, /* 510: pointer.struct.asn1_type_st */
            	515, 0,
            0, 16, 1, /* 515: struct.asn1_type_st */
            	520, 8,
            0, 8, 20, /* 520: union.unknown */
            	53, 0,
            	563, 0,
            	467, 0,
            	573, 0,
            	578, 0,
            	583, 0,
            	588, 0,
            	593, 0,
            	598, 0,
            	603, 0,
            	608, 0,
            	613, 0,
            	618, 0,
            	623, 0,
            	628, 0,
            	633, 0,
            	638, 0,
            	563, 0,
            	563, 0,
            	443, 0,
            1, 8, 1, /* 563: pointer.struct.asn1_string_st */
            	568, 0,
            0, 24, 1, /* 568: struct.asn1_string_st */
            	68, 8,
            1, 8, 1, /* 573: pointer.struct.asn1_string_st */
            	568, 0,
            1, 8, 1, /* 578: pointer.struct.asn1_string_st */
            	568, 0,
            1, 8, 1, /* 583: pointer.struct.asn1_string_st */
            	568, 0,
            1, 8, 1, /* 588: pointer.struct.asn1_string_st */
            	568, 0,
            1, 8, 1, /* 593: pointer.struct.asn1_string_st */
            	568, 0,
            1, 8, 1, /* 598: pointer.struct.asn1_string_st */
            	568, 0,
            1, 8, 1, /* 603: pointer.struct.asn1_string_st */
            	568, 0,
            1, 8, 1, /* 608: pointer.struct.asn1_string_st */
            	568, 0,
            1, 8, 1, /* 613: pointer.struct.asn1_string_st */
            	568, 0,
            1, 8, 1, /* 618: pointer.struct.asn1_string_st */
            	568, 0,
            1, 8, 1, /* 623: pointer.struct.asn1_string_st */
            	568, 0,
            1, 8, 1, /* 628: pointer.struct.asn1_string_st */
            	568, 0,
            1, 8, 1, /* 633: pointer.struct.asn1_string_st */
            	568, 0,
            1, 8, 1, /* 638: pointer.struct.asn1_string_st */
            	568, 0,
            8884097, 8, 0, /* 643: pointer.func */
            0, 16, 1, /* 646: struct.crypto_ex_data_st */
            	651, 0,
            1, 8, 1, /* 651: pointer.struct.stack_st_void */
            	656, 0,
            0, 32, 1, /* 656: struct.stack_st_void */
            	661, 0,
            0, 32, 2, /* 661: struct.stack_st */
            	668, 8,
            	217, 24,
            1, 8, 1, /* 668: pointer.pointer.char */
            	53, 0,
            1, 8, 1, /* 673: pointer.struct.ec_key_st */
            	678, 0,
            0, 0, 0, /* 678: struct.ec_key_st */
            1, 8, 1, /* 681: pointer.struct.asn1_type_st */
            	686, 0,
            0, 16, 1, /* 686: struct.asn1_type_st */
            	321, 8,
            1, 8, 1, /* 691: pointer.struct.asn1_string_st */
            	696, 0,
            0, 24, 1, /* 696: struct.asn1_string_st */
            	68, 8,
            8884097, 8, 0, /* 701: pointer.func */
            0, 72, 8, /* 704: struct.dh_method */
            	90, 0,
            	723, 8,
            	701, 16,
            	726, 24,
            	723, 32,
            	723, 40,
            	53, 56,
            	729, 64,
            8884097, 8, 0, /* 723: pointer.func */
            8884097, 8, 0, /* 726: pointer.func */
            8884097, 8, 0, /* 729: pointer.func */
            8884097, 8, 0, /* 732: pointer.func */
            0, 0, 0, /* 735: struct.bn_blinding_st */
            8884097, 8, 0, /* 738: pointer.func */
            8884097, 8, 0, /* 741: pointer.func */
            0, 0, 0, /* 744: struct.evp_pkey_asn1_method_st */
            0, 8, 15, /* 747: union.unknown */
            	53, 0,
            	780, 0,
            	889, 0,
            	889, 0,
            	806, 0,
            	937, 0,
            	308, 0,
            	889, 0,
            	874, 0,
            	792, 0,
            	874, 0,
            	937, 0,
            	889, 0,
            	792, 0,
            	806, 0,
            1, 8, 1, /* 780: pointer.struct.otherName_st */
            	785, 0,
            0, 16, 2, /* 785: struct.otherName_st */
            	792, 0,
            	806, 8,
            1, 8, 1, /* 792: pointer.struct.asn1_object_st */
            	797, 0,
            0, 40, 3, /* 797: struct.asn1_object_st */
            	90, 0,
            	90, 8,
            	95, 24,
            1, 8, 1, /* 806: pointer.struct.asn1_type_st */
            	811, 0,
            0, 16, 1, /* 811: struct.asn1_type_st */
            	816, 8,
            0, 8, 20, /* 816: union.unknown */
            	53, 0,
            	298, 0,
            	792, 0,
            	859, 0,
            	864, 0,
            	869, 0,
            	874, 0,
            	879, 0,
            	884, 0,
            	889, 0,
            	894, 0,
            	899, 0,
            	904, 0,
            	909, 0,
            	914, 0,
            	919, 0,
            	924, 0,
            	298, 0,
            	298, 0,
            	929, 0,
            1, 8, 1, /* 859: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 864: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 869: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 874: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 879: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 884: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 889: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 894: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 899: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 904: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 909: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 914: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 919: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 924: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 929: pointer.struct.ASN1_VALUE_st */
            	934, 0,
            0, 0, 0, /* 934: struct.ASN1_VALUE_st */
            1, 8, 1, /* 937: pointer.struct.X509_name_st */
            	942, 0,
            0, 40, 3, /* 942: struct.X509_name_st */
            	951, 0,
            	1011, 16,
            	68, 24,
            1, 8, 1, /* 951: pointer.struct.stack_st_X509_NAME_ENTRY */
            	956, 0,
            0, 32, 2, /* 956: struct.stack_st_fake_X509_NAME_ENTRY */
            	963, 8,
            	217, 24,
            8884099, 8, 2, /* 963: pointer_to_array_of_pointers_to_stack */
            	970, 0,
            	214, 20,
            0, 8, 1, /* 970: pointer.X509_NAME_ENTRY */
            	975, 0,
            0, 0, 1, /* 975: X509_NAME_ENTRY */
            	980, 0,
            0, 24, 2, /* 980: struct.X509_name_entry_st */
            	987, 0,
            	1001, 8,
            1, 8, 1, /* 987: pointer.struct.asn1_object_st */
            	992, 0,
            0, 40, 3, /* 992: struct.asn1_object_st */
            	90, 0,
            	90, 8,
            	95, 24,
            1, 8, 1, /* 1001: pointer.struct.asn1_string_st */
            	1006, 0,
            0, 24, 1, /* 1006: struct.asn1_string_st */
            	68, 8,
            1, 8, 1, /* 1011: pointer.struct.buf_mem_st */
            	313, 0,
            1, 8, 1, /* 1016: pointer.struct.dsa_method */
            	1021, 0,
            0, 96, 11, /* 1021: struct.dsa_method */
            	90, 0,
            	741, 8,
            	318, 16,
            	738, 24,
            	732, 32,
            	1046, 40,
            	1049, 48,
            	1049, 56,
            	53, 72,
            	1052, 80,
            	1049, 88,
            8884097, 8, 0, /* 1046: pointer.func */
            8884097, 8, 0, /* 1049: pointer.func */
            8884097, 8, 0, /* 1052: pointer.func */
            1, 8, 1, /* 1055: pointer.struct.dh_method */
            	704, 0,
            0, 24, 3, /* 1060: struct.AUTHORITY_KEYID_st */
            	281, 0,
            	1069, 8,
            	383, 16,
            1, 8, 1, /* 1069: pointer.struct.stack_st_GENERAL_NAME */
            	1074, 0,
            0, 32, 2, /* 1074: struct.stack_st_fake_GENERAL_NAME */
            	1081, 8,
            	217, 24,
            8884099, 8, 2, /* 1081: pointer_to_array_of_pointers_to_stack */
            	1088, 0,
            	214, 20,
            0, 8, 1, /* 1088: pointer.GENERAL_NAME */
            	1093, 0,
            0, 0, 1, /* 1093: GENERAL_NAME */
            	1098, 0,
            0, 16, 1, /* 1098: struct.GENERAL_NAME_st */
            	1103, 8,
            0, 8, 15, /* 1103: union.unknown */
            	53, 0,
            	1136, 0,
            	1245, 0,
            	1245, 0,
            	1162, 0,
            	1293, 0,
            	1341, 0,
            	1245, 0,
            	1230, 0,
            	1148, 0,
            	1230, 0,
            	1293, 0,
            	1245, 0,
            	1148, 0,
            	1162, 0,
            1, 8, 1, /* 1136: pointer.struct.otherName_st */
            	1141, 0,
            0, 16, 2, /* 1141: struct.otherName_st */
            	1148, 0,
            	1162, 8,
            1, 8, 1, /* 1148: pointer.struct.asn1_object_st */
            	1153, 0,
            0, 40, 3, /* 1153: struct.asn1_object_st */
            	90, 0,
            	90, 8,
            	95, 24,
            1, 8, 1, /* 1162: pointer.struct.asn1_type_st */
            	1167, 0,
            0, 16, 1, /* 1167: struct.asn1_type_st */
            	1172, 8,
            0, 8, 20, /* 1172: union.unknown */
            	53, 0,
            	691, 0,
            	1148, 0,
            	1215, 0,
            	1220, 0,
            	1225, 0,
            	1230, 0,
            	1235, 0,
            	1240, 0,
            	1245, 0,
            	1250, 0,
            	1255, 0,
            	1260, 0,
            	1265, 0,
            	1270, 0,
            	1275, 0,
            	1280, 0,
            	691, 0,
            	691, 0,
            	1285, 0,
            1, 8, 1, /* 1215: pointer.struct.asn1_string_st */
            	696, 0,
            1, 8, 1, /* 1220: pointer.struct.asn1_string_st */
            	696, 0,
            1, 8, 1, /* 1225: pointer.struct.asn1_string_st */
            	696, 0,
            1, 8, 1, /* 1230: pointer.struct.asn1_string_st */
            	696, 0,
            1, 8, 1, /* 1235: pointer.struct.asn1_string_st */
            	696, 0,
            1, 8, 1, /* 1240: pointer.struct.asn1_string_st */
            	696, 0,
            1, 8, 1, /* 1245: pointer.struct.asn1_string_st */
            	696, 0,
            1, 8, 1, /* 1250: pointer.struct.asn1_string_st */
            	696, 0,
            1, 8, 1, /* 1255: pointer.struct.asn1_string_st */
            	696, 0,
            1, 8, 1, /* 1260: pointer.struct.asn1_string_st */
            	696, 0,
            1, 8, 1, /* 1265: pointer.struct.asn1_string_st */
            	696, 0,
            1, 8, 1, /* 1270: pointer.struct.asn1_string_st */
            	696, 0,
            1, 8, 1, /* 1275: pointer.struct.asn1_string_st */
            	696, 0,
            1, 8, 1, /* 1280: pointer.struct.asn1_string_st */
            	696, 0,
            1, 8, 1, /* 1285: pointer.struct.ASN1_VALUE_st */
            	1290, 0,
            0, 0, 0, /* 1290: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1293: pointer.struct.X509_name_st */
            	1298, 0,
            0, 40, 3, /* 1298: struct.X509_name_st */
            	1307, 0,
            	1331, 16,
            	68, 24,
            1, 8, 1, /* 1307: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1312, 0,
            0, 32, 2, /* 1312: struct.stack_st_fake_X509_NAME_ENTRY */
            	1319, 8,
            	217, 24,
            8884099, 8, 2, /* 1319: pointer_to_array_of_pointers_to_stack */
            	1326, 0,
            	214, 20,
            0, 8, 1, /* 1326: pointer.X509_NAME_ENTRY */
            	975, 0,
            1, 8, 1, /* 1331: pointer.struct.buf_mem_st */
            	1336, 0,
            0, 24, 1, /* 1336: struct.buf_mem_st */
            	53, 8,
            1, 8, 1, /* 1341: pointer.struct.EDIPartyName_st */
            	1346, 0,
            0, 16, 2, /* 1346: struct.EDIPartyName_st */
            	691, 0,
            	691, 8,
            1, 8, 1, /* 1353: pointer.unsigned int */
            	1358, 0,
            0, 4, 0, /* 1358: unsigned int */
            1, 8, 1, /* 1361: pointer.struct.dsa_st */
            	1366, 0,
            0, 136, 11, /* 1366: struct.dsa_st */
            	1391, 24,
            	1391, 32,
            	1391, 40,
            	1391, 48,
            	1391, 56,
            	1391, 64,
            	1391, 72,
            	1401, 88,
            	646, 104,
            	1016, 120,
            	1415, 128,
            1, 8, 1, /* 1391: pointer.struct.bignum_st */
            	1396, 0,
            0, 24, 1, /* 1396: struct.bignum_st */
            	1353, 0,
            1, 8, 1, /* 1401: pointer.struct.bn_mont_ctx_st */
            	1406, 0,
            0, 96, 3, /* 1406: struct.bn_mont_ctx_st */
            	1396, 8,
            	1396, 32,
            	1396, 56,
            1, 8, 1, /* 1415: pointer.struct.engine_st */
            	1420, 0,
            0, 0, 0, /* 1420: struct.engine_st */
            0, 16, 2, /* 1423: struct.NAME_CONSTRAINTS_st */
            	1430, 0,
            	1430, 8,
            1, 8, 1, /* 1430: pointer.struct.stack_st_GENERAL_SUBTREE */
            	1435, 0,
            0, 32, 2, /* 1435: struct.stack_st_fake_GENERAL_SUBTREE */
            	1442, 8,
            	217, 24,
            8884099, 8, 2, /* 1442: pointer_to_array_of_pointers_to_stack */
            	1449, 0,
            	214, 20,
            0, 8, 1, /* 1449: pointer.GENERAL_SUBTREE */
            	1454, 0,
            0, 0, 1, /* 1454: GENERAL_SUBTREE */
            	1459, 0,
            0, 24, 3, /* 1459: struct.GENERAL_SUBTREE_st */
            	1468, 0,
            	859, 8,
            	859, 16,
            1, 8, 1, /* 1468: pointer.struct.GENERAL_NAME_st */
            	1473, 0,
            0, 16, 1, /* 1473: struct.GENERAL_NAME_st */
            	747, 8,
            0, 24, 3, /* 1478: struct.X509_pubkey_st */
            	1487, 0,
            	393, 8,
            	1499, 16,
            1, 8, 1, /* 1487: pointer.struct.X509_algor_st */
            	1492, 0,
            0, 16, 2, /* 1492: struct.X509_algor_st */
            	369, 0,
            	681, 8,
            1, 8, 1, /* 1499: pointer.struct.evp_pkey_st */
            	1504, 0,
            0, 56, 4, /* 1504: struct.evp_pkey_st */
            	1515, 16,
            	1415, 24,
            	1520, 32,
            	1664, 48,
            1, 8, 1, /* 1515: pointer.struct.evp_pkey_asn1_method_st */
            	744, 0,
            0, 8, 5, /* 1520: union.unknown */
            	53, 0,
            	1533, 0,
            	1361, 0,
            	1632, 0,
            	673, 0,
            1, 8, 1, /* 1533: pointer.struct.rsa_st */
            	1538, 0,
            0, 168, 17, /* 1538: struct.rsa_st */
            	1575, 16,
            	1415, 24,
            	1391, 32,
            	1391, 40,
            	1391, 48,
            	1391, 56,
            	1391, 64,
            	1391, 72,
            	1391, 80,
            	1391, 88,
            	646, 96,
            	1401, 120,
            	1401, 128,
            	1401, 136,
            	53, 144,
            	1627, 152,
            	1627, 160,
            1, 8, 1, /* 1575: pointer.struct.rsa_meth_st */
            	1580, 0,
            0, 112, 13, /* 1580: struct.rsa_meth_st */
            	90, 0,
            	643, 8,
            	643, 16,
            	643, 24,
            	643, 32,
            	1609, 40,
            	1612, 48,
            	1615, 56,
            	1615, 64,
            	53, 80,
            	1618, 88,
            	1621, 96,
            	1624, 104,
            8884097, 8, 0, /* 1609: pointer.func */
            8884097, 8, 0, /* 1612: pointer.func */
            8884097, 8, 0, /* 1615: pointer.func */
            8884097, 8, 0, /* 1618: pointer.func */
            8884097, 8, 0, /* 1621: pointer.func */
            8884097, 8, 0, /* 1624: pointer.func */
            1, 8, 1, /* 1627: pointer.struct.bn_blinding_st */
            	735, 0,
            1, 8, 1, /* 1632: pointer.struct.dh_st */
            	1637, 0,
            0, 144, 12, /* 1637: struct.dh_st */
            	1391, 8,
            	1391, 16,
            	1391, 32,
            	1391, 40,
            	1401, 56,
            	1391, 64,
            	1391, 72,
            	68, 80,
            	1391, 96,
            	646, 112,
            	1055, 128,
            	1415, 136,
            1, 8, 1, /* 1664: pointer.struct.stack_st_X509_ATTRIBUTE */
            	1669, 0,
            0, 32, 2, /* 1669: struct.stack_st_fake_X509_ATTRIBUTE */
            	1676, 8,
            	217, 24,
            8884099, 8, 2, /* 1676: pointer_to_array_of_pointers_to_stack */
            	1683, 0,
            	214, 20,
            0, 8, 1, /* 1683: pointer.X509_ATTRIBUTE */
            	1688, 0,
            0, 0, 1, /* 1688: X509_ATTRIBUTE */
            	460, 0,
            1, 8, 1, /* 1693: pointer.struct.DIST_POINT_NAME_st */
            	1698, 0,
            0, 24, 2, /* 1698: struct.DIST_POINT_NAME_st */
            	1705, 8,
            	1760, 16,
            0, 8, 2, /* 1705: union.unknown */
            	1712, 0,
            	1736, 0,
            1, 8, 1, /* 1712: pointer.struct.stack_st_GENERAL_NAME */
            	1717, 0,
            0, 32, 2, /* 1717: struct.stack_st_fake_GENERAL_NAME */
            	1724, 8,
            	217, 24,
            8884099, 8, 2, /* 1724: pointer_to_array_of_pointers_to_stack */
            	1731, 0,
            	214, 20,
            0, 8, 1, /* 1731: pointer.GENERAL_NAME */
            	1093, 0,
            1, 8, 1, /* 1736: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1741, 0,
            0, 32, 2, /* 1741: struct.stack_st_fake_X509_NAME_ENTRY */
            	1748, 8,
            	217, 24,
            8884099, 8, 2, /* 1748: pointer_to_array_of_pointers_to_stack */
            	1755, 0,
            	214, 20,
            0, 8, 1, /* 1755: pointer.X509_NAME_ENTRY */
            	975, 0,
            1, 8, 1, /* 1760: pointer.struct.X509_name_st */
            	1765, 0,
            0, 40, 3, /* 1765: struct.X509_name_st */
            	1736, 0,
            	1774, 16,
            	68, 24,
            1, 8, 1, /* 1774: pointer.struct.buf_mem_st */
            	1779, 0,
            0, 24, 1, /* 1779: struct.buf_mem_st */
            	53, 8,
            1, 8, 1, /* 1784: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1789, 0,
            0, 32, 2, /* 1789: struct.stack_st_fake_X509_NAME_ENTRY */
            	1796, 8,
            	217, 24,
            8884099, 8, 2, /* 1796: pointer_to_array_of_pointers_to_stack */
            	1803, 0,
            	214, 20,
            0, 8, 1, /* 1803: pointer.X509_NAME_ENTRY */
            	975, 0,
            0, 16, 2, /* 1808: struct.X509_val_st */
            	1815, 0,
            	1815, 8,
            1, 8, 1, /* 1815: pointer.struct.asn1_string_st */
            	276, 0,
            0, 104, 11, /* 1820: struct.x509_cinf_st */
            	383, 0,
            	383, 8,
            	1487, 16,
            	1845, 24,
            	1869, 32,
            	1845, 40,
            	1874, 48,
            	393, 56,
            	393, 64,
            	1879, 72,
            	1939, 80,
            1, 8, 1, /* 1845: pointer.struct.X509_name_st */
            	1850, 0,
            0, 40, 3, /* 1850: struct.X509_name_st */
            	1784, 0,
            	1859, 16,
            	68, 24,
            1, 8, 1, /* 1859: pointer.struct.buf_mem_st */
            	1864, 0,
            0, 24, 1, /* 1864: struct.buf_mem_st */
            	53, 8,
            1, 8, 1, /* 1869: pointer.struct.X509_val_st */
            	1808, 0,
            1, 8, 1, /* 1874: pointer.struct.X509_pubkey_st */
            	1478, 0,
            1, 8, 1, /* 1879: pointer.struct.stack_st_X509_EXTENSION */
            	1884, 0,
            0, 32, 2, /* 1884: struct.stack_st_fake_X509_EXTENSION */
            	1891, 8,
            	217, 24,
            8884099, 8, 2, /* 1891: pointer_to_array_of_pointers_to_stack */
            	1898, 0,
            	214, 20,
            0, 8, 1, /* 1898: pointer.X509_EXTENSION */
            	1903, 0,
            0, 0, 1, /* 1903: X509_EXTENSION */
            	1908, 0,
            0, 24, 2, /* 1908: struct.X509_extension_st */
            	1915, 0,
            	1929, 16,
            1, 8, 1, /* 1915: pointer.struct.asn1_object_st */
            	1920, 0,
            0, 40, 3, /* 1920: struct.asn1_object_st */
            	90, 0,
            	90, 8,
            	95, 24,
            1, 8, 1, /* 1929: pointer.struct.asn1_string_st */
            	1934, 0,
            0, 24, 1, /* 1934: struct.asn1_string_st */
            	68, 8,
            0, 24, 1, /* 1939: struct.ASN1_ENCODING_st */
            	68, 0,
            0, 184, 12, /* 1944: struct.x509_st */
            	1971, 0,
            	1487, 8,
            	393, 16,
            	53, 32,
            	646, 40,
            	281, 104,
            	1976, 112,
            	1981, 120,
            	1989, 128,
            	2037, 136,
            	2061, 144,
            	286, 176,
            1, 8, 1, /* 1971: pointer.struct.x509_cinf_st */
            	1820, 0,
            1, 8, 1, /* 1976: pointer.struct.AUTHORITY_KEYID_st */
            	1060, 0,
            1, 8, 1, /* 1981: pointer.struct.X509_POLICY_CACHE_st */
            	1986, 0,
            0, 0, 0, /* 1986: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 1989: pointer.struct.stack_st_DIST_POINT */
            	1994, 0,
            0, 32, 2, /* 1994: struct.stack_st_fake_DIST_POINT */
            	2001, 8,
            	217, 24,
            8884099, 8, 2, /* 2001: pointer_to_array_of_pointers_to_stack */
            	2008, 0,
            	214, 20,
            0, 8, 1, /* 2008: pointer.DIST_POINT */
            	2013, 0,
            0, 0, 1, /* 2013: DIST_POINT */
            	2018, 0,
            0, 32, 3, /* 2018: struct.DIST_POINT_st */
            	1693, 0,
            	2027, 8,
            	1712, 16,
            1, 8, 1, /* 2027: pointer.struct.asn1_string_st */
            	2032, 0,
            0, 24, 1, /* 2032: struct.asn1_string_st */
            	68, 8,
            1, 8, 1, /* 2037: pointer.struct.stack_st_GENERAL_NAME */
            	2042, 0,
            0, 32, 2, /* 2042: struct.stack_st_fake_GENERAL_NAME */
            	2049, 8,
            	217, 24,
            8884099, 8, 2, /* 2049: pointer_to_array_of_pointers_to_stack */
            	2056, 0,
            	214, 20,
            0, 8, 1, /* 2056: pointer.GENERAL_NAME */
            	1093, 0,
            1, 8, 1, /* 2061: pointer.struct.NAME_CONSTRAINTS_st */
            	1423, 0,
            1, 8, 1, /* 2066: pointer.struct.x509_st */
            	1944, 0,
            0, 1, 0, /* 2071: char */
        },
        .arg_entity_index = { 2066, },
        .ret_entity_index = 1845,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    X509 * new_arg_a = *((X509 * *)new_args->args[0]);

    X509_NAME * *new_ret_ptr = (X509_NAME * *)new_args->ret;

    X509_NAME * (*orig_X509_get_subject_name)(X509 *);
    orig_X509_get_subject_name = dlsym(RTLD_NEXT, "X509_get_subject_name");
    *new_ret_ptr = (*orig_X509_get_subject_name)(new_arg_a);

    syscall(889);

    return ret;
}

