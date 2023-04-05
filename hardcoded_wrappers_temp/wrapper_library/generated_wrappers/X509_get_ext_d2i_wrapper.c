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

void * bb_X509_get_ext_d2i(X509 * arg_a,int arg_b,int * arg_c,int * arg_d);

void * X509_get_ext_d2i(X509 * arg_a,int arg_b,int * arg_c,int * arg_d) 
{
    unsigned long in_lib = syscall(890);
    printf("X509_get_ext_d2i called %lu\n", in_lib);
    if (!in_lib)
        return bb_X509_get_ext_d2i(arg_a,arg_b,arg_c,arg_d);
    else {
        void * (*orig_X509_get_ext_d2i)(X509 *,int,int *,int *);
        orig_X509_get_ext_d2i = dlsym(RTLD_NEXT, "X509_get_ext_d2i");
        return orig_X509_get_ext_d2i(arg_a,arg_b,arg_c,arg_d);
    }
}

void * bb_X509_get_ext_d2i(X509 * arg_a,int arg_b,int * arg_c,int * arg_d) 
{
    void * ret;

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
            1, 8, 1, /* 178: pointer.struct.stack_st_X509_ALGOR */
            	183, 0,
            0, 32, 2, /* 183: struct.stack_st_fake_X509_ALGOR */
            	190, 8,
            	217, 24,
            8884099, 8, 2, /* 190: pointer_to_array_of_pointers_to_stack */
            	197, 0,
            	214, 20,
            0, 8, 1, /* 197: pointer.X509_ALGOR */
            	202, 0,
            0, 0, 1, /* 202: X509_ALGOR */
            	207, 0,
            0, 16, 2, /* 207: struct.X509_algor_st */
            	76, 0,
            	0, 8,
            0, 4, 0, /* 214: int */
            8884097, 8, 0, /* 217: pointer.func */
            0, 40, 3, /* 220: struct.asn1_object_st */
            	90, 0,
            	90, 8,
            	95, 24,
            0, 0, 1, /* 229: ASN1_OBJECT */
            	220, 0,
            1, 8, 1, /* 234: pointer.struct.stack_st_ASN1_OBJECT */
            	239, 0,
            0, 32, 2, /* 239: struct.stack_st_fake_ASN1_OBJECT */
            	246, 8,
            	217, 24,
            8884099, 8, 2, /* 246: pointer_to_array_of_pointers_to_stack */
            	253, 0,
            	214, 20,
            0, 8, 1, /* 253: pointer.ASN1_OBJECT */
            	229, 0,
            1, 8, 1, /* 258: pointer.struct.x509_cert_aux_st */
            	263, 0,
            0, 40, 5, /* 263: struct.x509_cert_aux_st */
            	234, 0,
            	234, 8,
            	276, 16,
            	286, 24,
            	178, 32,
            1, 8, 1, /* 276: pointer.struct.asn1_string_st */
            	281, 0,
            0, 24, 1, /* 281: struct.asn1_string_st */
            	68, 8,
            1, 8, 1, /* 286: pointer.struct.asn1_string_st */
            	281, 0,
            0, 16, 2, /* 291: struct.EDIPartyName_st */
            	298, 0,
            	298, 8,
            1, 8, 1, /* 298: pointer.struct.asn1_string_st */
            	303, 0,
            0, 24, 1, /* 303: struct.asn1_string_st */
            	68, 8,
            0, 24, 1, /* 308: struct.buf_mem_st */
            	53, 8,
            1, 8, 1, /* 313: pointer.struct.stack_st_X509_NAME_ENTRY */
            	318, 0,
            0, 32, 2, /* 318: struct.stack_st_fake_X509_NAME_ENTRY */
            	325, 8,
            	217, 24,
            8884099, 8, 2, /* 325: pointer_to_array_of_pointers_to_stack */
            	332, 0,
            	214, 20,
            0, 8, 1, /* 332: pointer.X509_NAME_ENTRY */
            	337, 0,
            0, 0, 1, /* 337: X509_NAME_ENTRY */
            	342, 0,
            0, 24, 2, /* 342: struct.X509_name_entry_st */
            	349, 0,
            	363, 8,
            1, 8, 1, /* 349: pointer.struct.asn1_object_st */
            	354, 0,
            0, 40, 3, /* 354: struct.asn1_object_st */
            	90, 0,
            	90, 8,
            	95, 24,
            1, 8, 1, /* 363: pointer.struct.asn1_string_st */
            	368, 0,
            0, 24, 1, /* 368: struct.asn1_string_st */
            	68, 8,
            0, 8, 3, /* 373: union.unknown */
            	53, 0,
            	382, 0,
            	411, 0,
            1, 8, 1, /* 382: pointer.struct.stack_st_ASN1_TYPE */
            	387, 0,
            0, 32, 2, /* 387: struct.stack_st_fake_ASN1_TYPE */
            	394, 8,
            	217, 24,
            8884099, 8, 2, /* 394: pointer_to_array_of_pointers_to_stack */
            	401, 0,
            	214, 20,
            0, 8, 1, /* 401: pointer.ASN1_TYPE */
            	406, 0,
            0, 0, 1, /* 406: ASN1_TYPE */
            	5, 0,
            1, 8, 1, /* 411: pointer.struct.asn1_type_st */
            	416, 0,
            0, 16, 1, /* 416: struct.asn1_type_st */
            	421, 8,
            0, 8, 20, /* 421: union.unknown */
            	53, 0,
            	464, 0,
            	474, 0,
            	488, 0,
            	493, 0,
            	498, 0,
            	503, 0,
            	508, 0,
            	513, 0,
            	518, 0,
            	523, 0,
            	528, 0,
            	533, 0,
            	538, 0,
            	543, 0,
            	548, 0,
            	553, 0,
            	464, 0,
            	464, 0,
            	558, 0,
            1, 8, 1, /* 464: pointer.struct.asn1_string_st */
            	469, 0,
            0, 24, 1, /* 469: struct.asn1_string_st */
            	68, 8,
            1, 8, 1, /* 474: pointer.struct.asn1_object_st */
            	479, 0,
            0, 40, 3, /* 479: struct.asn1_object_st */
            	90, 0,
            	90, 8,
            	95, 24,
            1, 8, 1, /* 488: pointer.struct.asn1_string_st */
            	469, 0,
            1, 8, 1, /* 493: pointer.struct.asn1_string_st */
            	469, 0,
            1, 8, 1, /* 498: pointer.struct.asn1_string_st */
            	469, 0,
            1, 8, 1, /* 503: pointer.struct.asn1_string_st */
            	469, 0,
            1, 8, 1, /* 508: pointer.struct.asn1_string_st */
            	469, 0,
            1, 8, 1, /* 513: pointer.struct.asn1_string_st */
            	469, 0,
            1, 8, 1, /* 518: pointer.struct.asn1_string_st */
            	469, 0,
            1, 8, 1, /* 523: pointer.struct.asn1_string_st */
            	469, 0,
            1, 8, 1, /* 528: pointer.struct.asn1_string_st */
            	469, 0,
            1, 8, 1, /* 533: pointer.struct.asn1_string_st */
            	469, 0,
            1, 8, 1, /* 538: pointer.struct.asn1_string_st */
            	469, 0,
            1, 8, 1, /* 543: pointer.struct.asn1_string_st */
            	469, 0,
            1, 8, 1, /* 548: pointer.struct.asn1_string_st */
            	469, 0,
            1, 8, 1, /* 553: pointer.struct.asn1_string_st */
            	469, 0,
            1, 8, 1, /* 558: pointer.struct.ASN1_VALUE_st */
            	563, 0,
            0, 0, 0, /* 563: struct.ASN1_VALUE_st */
            1, 8, 1, /* 566: pointer.struct.asn1_string_st */
            	571, 0,
            0, 24, 1, /* 571: struct.asn1_string_st */
            	68, 8,
            1, 8, 1, /* 576: pointer.struct.asn1_string_st */
            	303, 0,
            0, 24, 2, /* 581: struct.x509_attributes_st */
            	474, 0,
            	373, 16,
            0, 0, 1, /* 588: X509_ATTRIBUTE */
            	581, 0,
            1, 8, 1, /* 593: pointer.struct.stack_st_X509_ATTRIBUTE */
            	598, 0,
            0, 32, 2, /* 598: struct.stack_st_fake_X509_ATTRIBUTE */
            	605, 8,
            	217, 24,
            8884099, 8, 2, /* 605: pointer_to_array_of_pointers_to_stack */
            	612, 0,
            	214, 20,
            0, 8, 1, /* 612: pointer.X509_ATTRIBUTE */
            	588, 0,
            1, 8, 1, /* 617: pointer.struct.ec_key_st */
            	622, 0,
            0, 0, 0, /* 622: struct.ec_key_st */
            8884097, 8, 0, /* 625: pointer.func */
            1, 8, 1, /* 628: pointer.struct.asn1_string_st */
            	633, 0,
            0, 24, 1, /* 633: struct.asn1_string_st */
            	68, 8,
            8884097, 8, 0, /* 638: pointer.func */
            8884097, 8, 0, /* 641: pointer.func */
            0, 96, 11, /* 644: struct.dsa_method */
            	90, 0,
            	669, 8,
            	672, 16,
            	641, 24,
            	675, 32,
            	638, 40,
            	625, 48,
            	625, 56,
            	53, 72,
            	678, 80,
            	625, 88,
            8884097, 8, 0, /* 669: pointer.func */
            8884097, 8, 0, /* 672: pointer.func */
            8884097, 8, 0, /* 675: pointer.func */
            8884097, 8, 0, /* 678: pointer.func */
            1, 8, 1, /* 681: pointer.struct.stack_st_void */
            	686, 0,
            0, 32, 1, /* 686: struct.stack_st_void */
            	691, 0,
            0, 32, 2, /* 691: struct.stack_st */
            	698, 8,
            	217, 24,
            1, 8, 1, /* 698: pointer.pointer.char */
            	53, 0,
            1, 8, 1, /* 703: pointer.struct.dsa_method */
            	644, 0,
            1, 8, 1, /* 708: pointer.struct.EDIPartyName_st */
            	291, 0,
            1, 8, 1, /* 713: pointer.struct.dsa_st */
            	718, 0,
            0, 136, 11, /* 718: struct.dsa_st */
            	743, 24,
            	743, 32,
            	743, 40,
            	743, 48,
            	743, 56,
            	743, 64,
            	743, 72,
            	761, 88,
            	775, 104,
            	703, 120,
            	780, 128,
            1, 8, 1, /* 743: pointer.struct.bignum_st */
            	748, 0,
            0, 24, 1, /* 748: struct.bignum_st */
            	753, 0,
            1, 8, 1, /* 753: pointer.unsigned int */
            	758, 0,
            0, 4, 0, /* 758: unsigned int */
            1, 8, 1, /* 761: pointer.struct.bn_mont_ctx_st */
            	766, 0,
            0, 96, 3, /* 766: struct.bn_mont_ctx_st */
            	748, 8,
            	748, 32,
            	748, 56,
            0, 16, 1, /* 775: struct.crypto_ex_data_st */
            	681, 0,
            1, 8, 1, /* 780: pointer.struct.engine_st */
            	785, 0,
            0, 0, 0, /* 785: struct.engine_st */
            1, 8, 1, /* 788: pointer.struct.bn_blinding_st */
            	793, 0,
            0, 0, 0, /* 793: struct.bn_blinding_st */
            0, 104, 11, /* 796: struct.x509_cinf_st */
            	821, 0,
            	821, 8,
            	826, 16,
            	965, 24,
            	1013, 32,
            	965, 40,
            	1030, 48,
            	915, 56,
            	915, 64,
            	1246, 72,
            	1296, 80,
            1, 8, 1, /* 821: pointer.struct.asn1_string_st */
            	281, 0,
            1, 8, 1, /* 826: pointer.struct.X509_algor_st */
            	831, 0,
            0, 16, 2, /* 831: struct.X509_algor_st */
            	838, 0,
            	852, 8,
            1, 8, 1, /* 838: pointer.struct.asn1_object_st */
            	843, 0,
            0, 40, 3, /* 843: struct.asn1_object_st */
            	90, 0,
            	90, 8,
            	95, 24,
            1, 8, 1, /* 852: pointer.struct.asn1_type_st */
            	857, 0,
            0, 16, 1, /* 857: struct.asn1_type_st */
            	862, 8,
            0, 8, 20, /* 862: union.unknown */
            	53, 0,
            	905, 0,
            	838, 0,
            	821, 0,
            	910, 0,
            	915, 0,
            	286, 0,
            	920, 0,
            	925, 0,
            	930, 0,
            	935, 0,
            	940, 0,
            	945, 0,
            	950, 0,
            	955, 0,
            	960, 0,
            	276, 0,
            	905, 0,
            	905, 0,
            	558, 0,
            1, 8, 1, /* 905: pointer.struct.asn1_string_st */
            	281, 0,
            1, 8, 1, /* 910: pointer.struct.asn1_string_st */
            	281, 0,
            1, 8, 1, /* 915: pointer.struct.asn1_string_st */
            	281, 0,
            1, 8, 1, /* 920: pointer.struct.asn1_string_st */
            	281, 0,
            1, 8, 1, /* 925: pointer.struct.asn1_string_st */
            	281, 0,
            1, 8, 1, /* 930: pointer.struct.asn1_string_st */
            	281, 0,
            1, 8, 1, /* 935: pointer.struct.asn1_string_st */
            	281, 0,
            1, 8, 1, /* 940: pointer.struct.asn1_string_st */
            	281, 0,
            1, 8, 1, /* 945: pointer.struct.asn1_string_st */
            	281, 0,
            1, 8, 1, /* 950: pointer.struct.asn1_string_st */
            	281, 0,
            1, 8, 1, /* 955: pointer.struct.asn1_string_st */
            	281, 0,
            1, 8, 1, /* 960: pointer.struct.asn1_string_st */
            	281, 0,
            1, 8, 1, /* 965: pointer.struct.X509_name_st */
            	970, 0,
            0, 40, 3, /* 970: struct.X509_name_st */
            	979, 0,
            	1003, 16,
            	68, 24,
            1, 8, 1, /* 979: pointer.struct.stack_st_X509_NAME_ENTRY */
            	984, 0,
            0, 32, 2, /* 984: struct.stack_st_fake_X509_NAME_ENTRY */
            	991, 8,
            	217, 24,
            8884099, 8, 2, /* 991: pointer_to_array_of_pointers_to_stack */
            	998, 0,
            	214, 20,
            0, 8, 1, /* 998: pointer.X509_NAME_ENTRY */
            	337, 0,
            1, 8, 1, /* 1003: pointer.struct.buf_mem_st */
            	1008, 0,
            0, 24, 1, /* 1008: struct.buf_mem_st */
            	53, 8,
            1, 8, 1, /* 1013: pointer.struct.X509_val_st */
            	1018, 0,
            0, 16, 2, /* 1018: struct.X509_val_st */
            	1025, 0,
            	1025, 8,
            1, 8, 1, /* 1025: pointer.struct.asn1_string_st */
            	281, 0,
            1, 8, 1, /* 1030: pointer.struct.X509_pubkey_st */
            	1035, 0,
            0, 24, 3, /* 1035: struct.X509_pubkey_st */
            	826, 0,
            	915, 8,
            	1044, 16,
            1, 8, 1, /* 1044: pointer.struct.evp_pkey_st */
            	1049, 0,
            0, 56, 4, /* 1049: struct.evp_pkey_st */
            	1060, 16,
            	780, 24,
            	1068, 32,
            	593, 48,
            1, 8, 1, /* 1060: pointer.struct.evp_pkey_asn1_method_st */
            	1065, 0,
            0, 0, 0, /* 1065: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 1068: union.unknown */
            	53, 0,
            	1081, 0,
            	713, 0,
            	1178, 0,
            	617, 0,
            1, 8, 1, /* 1081: pointer.struct.rsa_st */
            	1086, 0,
            0, 168, 17, /* 1086: struct.rsa_st */
            	1123, 16,
            	780, 24,
            	743, 32,
            	743, 40,
            	743, 48,
            	743, 56,
            	743, 64,
            	743, 72,
            	743, 80,
            	743, 88,
            	775, 96,
            	761, 120,
            	761, 128,
            	761, 136,
            	53, 144,
            	788, 152,
            	788, 160,
            1, 8, 1, /* 1123: pointer.struct.rsa_meth_st */
            	1128, 0,
            0, 112, 13, /* 1128: struct.rsa_meth_st */
            	90, 0,
            	1157, 8,
            	1157, 16,
            	1157, 24,
            	1157, 32,
            	1160, 40,
            	1163, 48,
            	1166, 56,
            	1166, 64,
            	53, 80,
            	1169, 88,
            	1172, 96,
            	1175, 104,
            8884097, 8, 0, /* 1157: pointer.func */
            8884097, 8, 0, /* 1160: pointer.func */
            8884097, 8, 0, /* 1163: pointer.func */
            8884097, 8, 0, /* 1166: pointer.func */
            8884097, 8, 0, /* 1169: pointer.func */
            8884097, 8, 0, /* 1172: pointer.func */
            8884097, 8, 0, /* 1175: pointer.func */
            1, 8, 1, /* 1178: pointer.struct.dh_st */
            	1183, 0,
            0, 144, 12, /* 1183: struct.dh_st */
            	743, 8,
            	743, 16,
            	743, 32,
            	743, 40,
            	761, 56,
            	743, 64,
            	743, 72,
            	68, 80,
            	743, 96,
            	775, 112,
            	1210, 128,
            	780, 136,
            1, 8, 1, /* 1210: pointer.struct.dh_method */
            	1215, 0,
            0, 72, 8, /* 1215: struct.dh_method */
            	90, 0,
            	1234, 8,
            	1237, 16,
            	1240, 24,
            	1234, 32,
            	1234, 40,
            	53, 56,
            	1243, 64,
            8884097, 8, 0, /* 1234: pointer.func */
            8884097, 8, 0, /* 1237: pointer.func */
            8884097, 8, 0, /* 1240: pointer.func */
            8884097, 8, 0, /* 1243: pointer.func */
            1, 8, 1, /* 1246: pointer.struct.stack_st_X509_EXTENSION */
            	1251, 0,
            0, 32, 2, /* 1251: struct.stack_st_fake_X509_EXTENSION */
            	1258, 8,
            	217, 24,
            8884099, 8, 2, /* 1258: pointer_to_array_of_pointers_to_stack */
            	1265, 0,
            	214, 20,
            0, 8, 1, /* 1265: pointer.X509_EXTENSION */
            	1270, 0,
            0, 0, 1, /* 1270: X509_EXTENSION */
            	1275, 0,
            0, 24, 2, /* 1275: struct.X509_extension_st */
            	1282, 0,
            	566, 16,
            1, 8, 1, /* 1282: pointer.struct.asn1_object_st */
            	1287, 0,
            0, 40, 3, /* 1287: struct.asn1_object_st */
            	90, 0,
            	90, 8,
            	95, 24,
            0, 24, 1, /* 1296: struct.ASN1_ENCODING_st */
            	68, 0,
            1, 8, 1, /* 1301: pointer.struct.asn1_string_st */
            	633, 0,
            1, 8, 1, /* 1306: pointer.struct.asn1_string_st */
            	633, 0,
            1, 8, 1, /* 1311: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 1316: pointer.struct.asn1_string_st */
            	633, 0,
            1, 8, 1, /* 1321: pointer.struct.asn1_string_st */
            	633, 0,
            1, 8, 1, /* 1326: pointer.struct.asn1_type_st */
            	1331, 0,
            0, 16, 1, /* 1331: struct.asn1_type_st */
            	1336, 8,
            0, 8, 20, /* 1336: union.unknown */
            	53, 0,
            	628, 0,
            	1379, 0,
            	1321, 0,
            	1301, 0,
            	1393, 0,
            	1316, 0,
            	1398, 0,
            	1403, 0,
            	1408, 0,
            	1413, 0,
            	1306, 0,
            	1418, 0,
            	1423, 0,
            	1428, 0,
            	1433, 0,
            	1438, 0,
            	628, 0,
            	628, 0,
            	1443, 0,
            1, 8, 1, /* 1379: pointer.struct.asn1_object_st */
            	1384, 0,
            0, 40, 3, /* 1384: struct.asn1_object_st */
            	90, 0,
            	90, 8,
            	95, 24,
            1, 8, 1, /* 1393: pointer.struct.asn1_string_st */
            	633, 0,
            1, 8, 1, /* 1398: pointer.struct.asn1_string_st */
            	633, 0,
            1, 8, 1, /* 1403: pointer.struct.asn1_string_st */
            	633, 0,
            1, 8, 1, /* 1408: pointer.struct.asn1_string_st */
            	633, 0,
            1, 8, 1, /* 1413: pointer.struct.asn1_string_st */
            	633, 0,
            1, 8, 1, /* 1418: pointer.struct.asn1_string_st */
            	633, 0,
            1, 8, 1, /* 1423: pointer.struct.asn1_string_st */
            	633, 0,
            1, 8, 1, /* 1428: pointer.struct.asn1_string_st */
            	633, 0,
            1, 8, 1, /* 1433: pointer.struct.asn1_string_st */
            	633, 0,
            1, 8, 1, /* 1438: pointer.struct.asn1_string_st */
            	633, 0,
            1, 8, 1, /* 1443: pointer.struct.ASN1_VALUE_st */
            	1448, 0,
            0, 0, 0, /* 1448: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1451: pointer.struct.x509_st */
            	1456, 0,
            0, 184, 12, /* 1456: struct.x509_st */
            	1483, 0,
            	826, 8,
            	915, 16,
            	53, 32,
            	775, 40,
            	286, 104,
            	1488, 112,
            	1641, 120,
            	1649, 128,
            	1788, 136,
            	1812, 144,
            	258, 176,
            1, 8, 1, /* 1483: pointer.struct.x509_cinf_st */
            	796, 0,
            1, 8, 1, /* 1488: pointer.struct.AUTHORITY_KEYID_st */
            	1493, 0,
            0, 24, 3, /* 1493: struct.AUTHORITY_KEYID_st */
            	286, 0,
            	1502, 8,
            	821, 16,
            1, 8, 1, /* 1502: pointer.struct.stack_st_GENERAL_NAME */
            	1507, 0,
            0, 32, 2, /* 1507: struct.stack_st_fake_GENERAL_NAME */
            	1514, 8,
            	217, 24,
            8884099, 8, 2, /* 1514: pointer_to_array_of_pointers_to_stack */
            	1521, 0,
            	214, 20,
            0, 8, 1, /* 1521: pointer.GENERAL_NAME */
            	1526, 0,
            0, 0, 1, /* 1526: GENERAL_NAME */
            	1531, 0,
            0, 16, 1, /* 1531: struct.GENERAL_NAME_st */
            	1536, 8,
            0, 8, 15, /* 1536: union.unknown */
            	53, 0,
            	1569, 0,
            	1408, 0,
            	1408, 0,
            	1326, 0,
            	1581, 0,
            	1629, 0,
            	1408, 0,
            	1316, 0,
            	1379, 0,
            	1316, 0,
            	1581, 0,
            	1408, 0,
            	1379, 0,
            	1326, 0,
            1, 8, 1, /* 1569: pointer.struct.otherName_st */
            	1574, 0,
            0, 16, 2, /* 1574: struct.otherName_st */
            	1379, 0,
            	1326, 8,
            1, 8, 1, /* 1581: pointer.struct.X509_name_st */
            	1586, 0,
            0, 40, 3, /* 1586: struct.X509_name_st */
            	1595, 0,
            	1619, 16,
            	68, 24,
            1, 8, 1, /* 1595: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1600, 0,
            0, 32, 2, /* 1600: struct.stack_st_fake_X509_NAME_ENTRY */
            	1607, 8,
            	217, 24,
            8884099, 8, 2, /* 1607: pointer_to_array_of_pointers_to_stack */
            	1614, 0,
            	214, 20,
            0, 8, 1, /* 1614: pointer.X509_NAME_ENTRY */
            	337, 0,
            1, 8, 1, /* 1619: pointer.struct.buf_mem_st */
            	1624, 0,
            0, 24, 1, /* 1624: struct.buf_mem_st */
            	53, 8,
            1, 8, 1, /* 1629: pointer.struct.EDIPartyName_st */
            	1634, 0,
            0, 16, 2, /* 1634: struct.EDIPartyName_st */
            	628, 0,
            	628, 8,
            1, 8, 1, /* 1641: pointer.struct.X509_POLICY_CACHE_st */
            	1646, 0,
            0, 0, 0, /* 1646: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 1649: pointer.struct.stack_st_DIST_POINT */
            	1654, 0,
            0, 32, 2, /* 1654: struct.stack_st_fake_DIST_POINT */
            	1661, 8,
            	217, 24,
            8884099, 8, 2, /* 1661: pointer_to_array_of_pointers_to_stack */
            	1668, 0,
            	214, 20,
            0, 8, 1, /* 1668: pointer.DIST_POINT */
            	1673, 0,
            0, 0, 1, /* 1673: DIST_POINT */
            	1678, 0,
            0, 32, 3, /* 1678: struct.DIST_POINT_st */
            	1687, 0,
            	1778, 8,
            	1706, 16,
            1, 8, 1, /* 1687: pointer.struct.DIST_POINT_NAME_st */
            	1692, 0,
            0, 24, 2, /* 1692: struct.DIST_POINT_NAME_st */
            	1699, 8,
            	1754, 16,
            0, 8, 2, /* 1699: union.unknown */
            	1706, 0,
            	1730, 0,
            1, 8, 1, /* 1706: pointer.struct.stack_st_GENERAL_NAME */
            	1711, 0,
            0, 32, 2, /* 1711: struct.stack_st_fake_GENERAL_NAME */
            	1718, 8,
            	217, 24,
            8884099, 8, 2, /* 1718: pointer_to_array_of_pointers_to_stack */
            	1725, 0,
            	214, 20,
            0, 8, 1, /* 1725: pointer.GENERAL_NAME */
            	1526, 0,
            1, 8, 1, /* 1730: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1735, 0,
            0, 32, 2, /* 1735: struct.stack_st_fake_X509_NAME_ENTRY */
            	1742, 8,
            	217, 24,
            8884099, 8, 2, /* 1742: pointer_to_array_of_pointers_to_stack */
            	1749, 0,
            	214, 20,
            0, 8, 1, /* 1749: pointer.X509_NAME_ENTRY */
            	337, 0,
            1, 8, 1, /* 1754: pointer.struct.X509_name_st */
            	1759, 0,
            0, 40, 3, /* 1759: struct.X509_name_st */
            	1730, 0,
            	1768, 16,
            	68, 24,
            1, 8, 1, /* 1768: pointer.struct.buf_mem_st */
            	1773, 0,
            0, 24, 1, /* 1773: struct.buf_mem_st */
            	53, 8,
            1, 8, 1, /* 1778: pointer.struct.asn1_string_st */
            	1783, 0,
            0, 24, 1, /* 1783: struct.asn1_string_st */
            	68, 8,
            1, 8, 1, /* 1788: pointer.struct.stack_st_GENERAL_NAME */
            	1793, 0,
            0, 32, 2, /* 1793: struct.stack_st_fake_GENERAL_NAME */
            	1800, 8,
            	217, 24,
            8884099, 8, 2, /* 1800: pointer_to_array_of_pointers_to_stack */
            	1807, 0,
            	214, 20,
            0, 8, 1, /* 1807: pointer.GENERAL_NAME */
            	1526, 0,
            1, 8, 1, /* 1812: pointer.struct.NAME_CONSTRAINTS_st */
            	1817, 0,
            0, 16, 2, /* 1817: struct.NAME_CONSTRAINTS_st */
            	1824, 0,
            	1824, 8,
            1, 8, 1, /* 1824: pointer.struct.stack_st_GENERAL_SUBTREE */
            	1829, 0,
            0, 32, 2, /* 1829: struct.stack_st_fake_GENERAL_SUBTREE */
            	1836, 8,
            	217, 24,
            8884099, 8, 2, /* 1836: pointer_to_array_of_pointers_to_stack */
            	1843, 0,
            	214, 20,
            0, 8, 1, /* 1843: pointer.GENERAL_SUBTREE */
            	1848, 0,
            0, 0, 1, /* 1848: GENERAL_SUBTREE */
            	1853, 0,
            0, 24, 3, /* 1853: struct.GENERAL_SUBTREE_st */
            	1862, 0,
            	1984, 8,
            	1984, 16,
            1, 8, 1, /* 1862: pointer.struct.GENERAL_NAME_st */
            	1867, 0,
            0, 16, 1, /* 1867: struct.GENERAL_NAME_st */
            	1872, 8,
            0, 8, 15, /* 1872: union.unknown */
            	53, 0,
            	1905, 0,
            	2009, 0,
            	2009, 0,
            	1931, 0,
            	2052, 0,
            	708, 0,
            	2009, 0,
            	576, 0,
            	1917, 0,
            	576, 0,
            	2052, 0,
            	2009, 0,
            	1917, 0,
            	1931, 0,
            1, 8, 1, /* 1905: pointer.struct.otherName_st */
            	1910, 0,
            0, 16, 2, /* 1910: struct.otherName_st */
            	1917, 0,
            	1931, 8,
            1, 8, 1, /* 1917: pointer.struct.asn1_object_st */
            	1922, 0,
            0, 40, 3, /* 1922: struct.asn1_object_st */
            	90, 0,
            	90, 8,
            	95, 24,
            1, 8, 1, /* 1931: pointer.struct.asn1_type_st */
            	1936, 0,
            0, 16, 1, /* 1936: struct.asn1_type_st */
            	1941, 8,
            0, 8, 20, /* 1941: union.unknown */
            	53, 0,
            	298, 0,
            	1917, 0,
            	1984, 0,
            	1989, 0,
            	1994, 0,
            	576, 0,
            	1999, 0,
            	2004, 0,
            	2009, 0,
            	2014, 0,
            	2019, 0,
            	2024, 0,
            	2029, 0,
            	1311, 0,
            	2034, 0,
            	2039, 0,
            	298, 0,
            	298, 0,
            	2044, 0,
            1, 8, 1, /* 1984: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 1989: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 1994: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 1999: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 2004: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 2009: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 2014: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 2019: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 2024: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 2029: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 2034: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 2039: pointer.struct.asn1_string_st */
            	303, 0,
            1, 8, 1, /* 2044: pointer.struct.ASN1_VALUE_st */
            	2049, 0,
            0, 0, 0, /* 2049: struct.ASN1_VALUE_st */
            1, 8, 1, /* 2052: pointer.struct.X509_name_st */
            	2057, 0,
            0, 40, 3, /* 2057: struct.X509_name_st */
            	313, 0,
            	2066, 16,
            	68, 24,
            1, 8, 1, /* 2066: pointer.struct.buf_mem_st */
            	308, 0,
            0, 1, 0, /* 2071: char */
            0, 8, 0, /* 2074: pointer.void */
            1, 8, 1, /* 2077: pointer.int */
            	214, 0,
        },
        .arg_entity_index = { 1451, 214, 2077, 2077, },
        .ret_entity_index = 2074,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_arg(args_addr, arg_d);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    X509 * new_arg_a = *((X509 * *)new_args->args[0]);

    int new_arg_b = *((int *)new_args->args[1]);

    int * new_arg_c = *((int * *)new_args->args[2]);

    int * new_arg_d = *((int * *)new_args->args[3]);

    void * *new_ret_ptr = (void * *)new_args->ret;

    void * (*orig_X509_get_ext_d2i)(X509 *,int,int *,int *);
    orig_X509_get_ext_d2i = dlsym(RTLD_NEXT, "X509_get_ext_d2i");
    *new_ret_ptr = (*orig_X509_get_ext_d2i)(new_arg_a,new_arg_b,new_arg_c,new_arg_d);

    syscall(889);

    return ret;
}

