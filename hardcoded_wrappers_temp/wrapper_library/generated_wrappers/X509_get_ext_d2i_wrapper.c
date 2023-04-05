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
            0, 16, 1, /* 53: struct.asn1_type_st */
            	58, 8,
            0, 8, 20, /* 58: union.unknown */
            	101, 0,
            	106, 0,
            	111, 0,
            	48, 0,
            	135, 0,
            	140, 0,
            	43, 0,
            	38, 0,
            	145, 0,
            	150, 0,
            	33, 0,
            	28, 0,
            	23, 0,
            	18, 0,
            	0, 0,
            	155, 0,
            	160, 0,
            	106, 0,
            	106, 0,
            	165, 0,
            1, 8, 1, /* 101: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 106: pointer.struct.asn1_string_st */
            	5, 0,
            1, 8, 1, /* 111: pointer.struct.asn1_object_st */
            	116, 0,
            0, 40, 3, /* 116: struct.asn1_object_st */
            	125, 0,
            	125, 8,
            	130, 24,
            1, 8, 1, /* 125: pointer.char */
            	8884096, 0,
            1, 8, 1, /* 130: pointer.unsigned char */
            	15, 0,
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
            1, 8, 1, /* 160: pointer.struct.asn1_string_st */
            	5, 0,
            1, 8, 1, /* 165: pointer.struct.ASN1_VALUE_st */
            	170, 0,
            0, 0, 0, /* 170: struct.ASN1_VALUE_st */
            0, 0, 1, /* 173: X509_ALGOR */
            	178, 0,
            0, 16, 2, /* 178: struct.X509_algor_st */
            	111, 0,
            	185, 8,
            1, 8, 1, /* 185: pointer.struct.asn1_type_st */
            	53, 0,
            1, 8, 1, /* 190: pointer.struct.stack_st_X509_ALGOR */
            	195, 0,
            0, 32, 2, /* 195: struct.stack_st_fake_X509_ALGOR */
            	202, 8,
            	217, 24,
            8884099, 8, 2, /* 202: pointer_to_array_of_pointers_to_stack */
            	209, 0,
            	214, 20,
            0, 8, 1, /* 209: pointer.X509_ALGOR */
            	173, 0,
            0, 4, 0, /* 214: int */
            8884097, 8, 0, /* 217: pointer.func */
            0, 40, 5, /* 220: struct.x509_cert_aux_st */
            	233, 0,
            	233, 8,
            	271, 16,
            	281, 24,
            	190, 32,
            1, 8, 1, /* 233: pointer.struct.stack_st_ASN1_OBJECT */
            	238, 0,
            0, 32, 2, /* 238: struct.stack_st_fake_ASN1_OBJECT */
            	245, 8,
            	217, 24,
            8884099, 8, 2, /* 245: pointer_to_array_of_pointers_to_stack */
            	252, 0,
            	214, 20,
            0, 8, 1, /* 252: pointer.ASN1_OBJECT */
            	257, 0,
            0, 0, 1, /* 257: ASN1_OBJECT */
            	262, 0,
            0, 40, 3, /* 262: struct.asn1_object_st */
            	125, 0,
            	125, 8,
            	130, 24,
            1, 8, 1, /* 271: pointer.struct.asn1_string_st */
            	276, 0,
            0, 24, 1, /* 276: struct.asn1_string_st */
            	10, 8,
            1, 8, 1, /* 281: pointer.struct.asn1_string_st */
            	276, 0,
            0, 0, 1, /* 286: GENERAL_SUBTREE */
            	291, 0,
            0, 24, 3, /* 291: struct.GENERAL_SUBTREE_st */
            	300, 0,
            	432, 8,
            	432, 16,
            1, 8, 1, /* 300: pointer.struct.GENERAL_NAME_st */
            	305, 0,
            0, 16, 1, /* 305: struct.GENERAL_NAME_st */
            	310, 8,
            0, 8, 15, /* 310: union.unknown */
            	101, 0,
            	343, 0,
            	462, 0,
            	462, 0,
            	369, 0,
            	510, 0,
            	594, 0,
            	462, 0,
            	447, 0,
            	355, 0,
            	447, 0,
            	510, 0,
            	462, 0,
            	355, 0,
            	369, 0,
            1, 8, 1, /* 343: pointer.struct.otherName_st */
            	348, 0,
            0, 16, 2, /* 348: struct.otherName_st */
            	355, 0,
            	369, 8,
            1, 8, 1, /* 355: pointer.struct.asn1_object_st */
            	360, 0,
            0, 40, 3, /* 360: struct.asn1_object_st */
            	125, 0,
            	125, 8,
            	130, 24,
            1, 8, 1, /* 369: pointer.struct.asn1_type_st */
            	374, 0,
            0, 16, 1, /* 374: struct.asn1_type_st */
            	379, 8,
            0, 8, 20, /* 379: union.unknown */
            	101, 0,
            	422, 0,
            	355, 0,
            	432, 0,
            	437, 0,
            	442, 0,
            	447, 0,
            	452, 0,
            	457, 0,
            	462, 0,
            	467, 0,
            	472, 0,
            	477, 0,
            	482, 0,
            	487, 0,
            	492, 0,
            	497, 0,
            	422, 0,
            	422, 0,
            	502, 0,
            1, 8, 1, /* 422: pointer.struct.asn1_string_st */
            	427, 0,
            0, 24, 1, /* 427: struct.asn1_string_st */
            	10, 8,
            1, 8, 1, /* 432: pointer.struct.asn1_string_st */
            	427, 0,
            1, 8, 1, /* 437: pointer.struct.asn1_string_st */
            	427, 0,
            1, 8, 1, /* 442: pointer.struct.asn1_string_st */
            	427, 0,
            1, 8, 1, /* 447: pointer.struct.asn1_string_st */
            	427, 0,
            1, 8, 1, /* 452: pointer.struct.asn1_string_st */
            	427, 0,
            1, 8, 1, /* 457: pointer.struct.asn1_string_st */
            	427, 0,
            1, 8, 1, /* 462: pointer.struct.asn1_string_st */
            	427, 0,
            1, 8, 1, /* 467: pointer.struct.asn1_string_st */
            	427, 0,
            1, 8, 1, /* 472: pointer.struct.asn1_string_st */
            	427, 0,
            1, 8, 1, /* 477: pointer.struct.asn1_string_st */
            	427, 0,
            1, 8, 1, /* 482: pointer.struct.asn1_string_st */
            	427, 0,
            1, 8, 1, /* 487: pointer.struct.asn1_string_st */
            	427, 0,
            1, 8, 1, /* 492: pointer.struct.asn1_string_st */
            	427, 0,
            1, 8, 1, /* 497: pointer.struct.asn1_string_st */
            	427, 0,
            1, 8, 1, /* 502: pointer.struct.ASN1_VALUE_st */
            	507, 0,
            0, 0, 0, /* 507: struct.ASN1_VALUE_st */
            1, 8, 1, /* 510: pointer.struct.X509_name_st */
            	515, 0,
            0, 40, 3, /* 515: struct.X509_name_st */
            	524, 0,
            	584, 16,
            	10, 24,
            1, 8, 1, /* 524: pointer.struct.stack_st_X509_NAME_ENTRY */
            	529, 0,
            0, 32, 2, /* 529: struct.stack_st_fake_X509_NAME_ENTRY */
            	536, 8,
            	217, 24,
            8884099, 8, 2, /* 536: pointer_to_array_of_pointers_to_stack */
            	543, 0,
            	214, 20,
            0, 8, 1, /* 543: pointer.X509_NAME_ENTRY */
            	548, 0,
            0, 0, 1, /* 548: X509_NAME_ENTRY */
            	553, 0,
            0, 24, 2, /* 553: struct.X509_name_entry_st */
            	560, 0,
            	574, 8,
            1, 8, 1, /* 560: pointer.struct.asn1_object_st */
            	565, 0,
            0, 40, 3, /* 565: struct.asn1_object_st */
            	125, 0,
            	125, 8,
            	130, 24,
            1, 8, 1, /* 574: pointer.struct.asn1_string_st */
            	579, 0,
            0, 24, 1, /* 579: struct.asn1_string_st */
            	10, 8,
            1, 8, 1, /* 584: pointer.struct.buf_mem_st */
            	589, 0,
            0, 24, 1, /* 589: struct.buf_mem_st */
            	101, 8,
            1, 8, 1, /* 594: pointer.struct.EDIPartyName_st */
            	599, 0,
            0, 16, 2, /* 599: struct.EDIPartyName_st */
            	422, 0,
            	422, 8,
            1, 8, 1, /* 606: pointer.struct.stack_st_GENERAL_NAME */
            	611, 0,
            0, 32, 2, /* 611: struct.stack_st_fake_GENERAL_NAME */
            	618, 8,
            	217, 24,
            8884099, 8, 2, /* 618: pointer_to_array_of_pointers_to_stack */
            	625, 0,
            	214, 20,
            0, 8, 1, /* 625: pointer.GENERAL_NAME */
            	630, 0,
            0, 0, 1, /* 630: GENERAL_NAME */
            	305, 0,
            1, 8, 1, /* 635: pointer.struct.asn1_string_st */
            	640, 0,
            0, 24, 1, /* 640: struct.asn1_string_st */
            	10, 8,
            0, 24, 1, /* 645: struct.buf_mem_st */
            	101, 8,
            0, 40, 3, /* 650: struct.X509_name_st */
            	659, 0,
            	683, 16,
            	10, 24,
            1, 8, 1, /* 659: pointer.struct.stack_st_X509_NAME_ENTRY */
            	664, 0,
            0, 32, 2, /* 664: struct.stack_st_fake_X509_NAME_ENTRY */
            	671, 8,
            	217, 24,
            8884099, 8, 2, /* 671: pointer_to_array_of_pointers_to_stack */
            	678, 0,
            	214, 20,
            0, 8, 1, /* 678: pointer.X509_NAME_ENTRY */
            	548, 0,
            1, 8, 1, /* 683: pointer.struct.buf_mem_st */
            	645, 0,
            1, 8, 1, /* 688: pointer.struct.X509_name_st */
            	650, 0,
            1, 8, 1, /* 693: pointer.struct.stack_st_GENERAL_NAME */
            	698, 0,
            0, 32, 2, /* 698: struct.stack_st_fake_GENERAL_NAME */
            	705, 8,
            	217, 24,
            8884099, 8, 2, /* 705: pointer_to_array_of_pointers_to_stack */
            	712, 0,
            	214, 20,
            0, 8, 1, /* 712: pointer.GENERAL_NAME */
            	630, 0,
            0, 8, 2, /* 717: union.unknown */
            	693, 0,
            	659, 0,
            0, 24, 2, /* 724: struct.DIST_POINT_NAME_st */
            	717, 8,
            	688, 16,
            1, 8, 1, /* 731: pointer.struct.DIST_POINT_NAME_st */
            	724, 0,
            1, 8, 1, /* 736: pointer.struct.stack_st_DIST_POINT */
            	741, 0,
            0, 32, 2, /* 741: struct.stack_st_fake_DIST_POINT */
            	748, 8,
            	217, 24,
            8884099, 8, 2, /* 748: pointer_to_array_of_pointers_to_stack */
            	755, 0,
            	214, 20,
            0, 8, 1, /* 755: pointer.DIST_POINT */
            	760, 0,
            0, 0, 1, /* 760: DIST_POINT */
            	765, 0,
            0, 32, 3, /* 765: struct.DIST_POINT_st */
            	731, 0,
            	635, 8,
            	693, 16,
            0, 0, 0, /* 774: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 777: pointer.struct.X509_POLICY_CACHE_st */
            	774, 0,
            1, 8, 1, /* 782: pointer.struct.x509_cert_aux_st */
            	220, 0,
            1, 8, 1, /* 787: pointer.struct.stack_st_GENERAL_SUBTREE */
            	792, 0,
            0, 32, 2, /* 792: struct.stack_st_fake_GENERAL_SUBTREE */
            	799, 8,
            	217, 24,
            8884099, 8, 2, /* 799: pointer_to_array_of_pointers_to_stack */
            	806, 0,
            	214, 20,
            0, 8, 1, /* 806: pointer.GENERAL_SUBTREE */
            	286, 0,
            1, 8, 1, /* 811: pointer.struct.stack_st_GENERAL_NAME */
            	816, 0,
            0, 32, 2, /* 816: struct.stack_st_fake_GENERAL_NAME */
            	823, 8,
            	217, 24,
            8884099, 8, 2, /* 823: pointer_to_array_of_pointers_to_stack */
            	830, 0,
            	214, 20,
            0, 8, 1, /* 830: pointer.GENERAL_NAME */
            	630, 0,
            0, 24, 3, /* 835: struct.AUTHORITY_KEYID_st */
            	281, 0,
            	811, 8,
            	844, 16,
            1, 8, 1, /* 844: pointer.struct.asn1_string_st */
            	276, 0,
            1, 8, 1, /* 849: pointer.struct.AUTHORITY_KEYID_st */
            	835, 0,
            0, 24, 1, /* 854: struct.ASN1_ENCODING_st */
            	10, 0,
            0, 24, 1, /* 859: struct.asn1_string_st */
            	10, 8,
            0, 40, 3, /* 864: struct.asn1_object_st */
            	125, 0,
            	125, 8,
            	130, 24,
            0, 24, 2, /* 873: struct.X509_extension_st */
            	880, 0,
            	885, 16,
            1, 8, 1, /* 880: pointer.struct.asn1_object_st */
            	864, 0,
            1, 8, 1, /* 885: pointer.struct.asn1_string_st */
            	859, 0,
            0, 0, 1, /* 890: X509_EXTENSION */
            	873, 0,
            1, 8, 1, /* 895: pointer.struct.asn1_string_st */
            	900, 0,
            0, 24, 1, /* 900: struct.asn1_string_st */
            	10, 8,
            1, 8, 1, /* 905: pointer.struct.asn1_string_st */
            	900, 0,
            1, 8, 1, /* 910: pointer.struct.asn1_string_st */
            	900, 0,
            1, 8, 1, /* 915: pointer.struct.asn1_string_st */
            	900, 0,
            1, 8, 1, /* 920: pointer.struct.asn1_string_st */
            	900, 0,
            1, 8, 1, /* 925: pointer.struct.asn1_string_st */
            	900, 0,
            1, 8, 1, /* 930: pointer.struct.asn1_string_st */
            	900, 0,
            1, 8, 1, /* 935: pointer.struct.asn1_string_st */
            	900, 0,
            1, 8, 1, /* 940: pointer.struct.asn1_string_st */
            	900, 0,
            1, 8, 1, /* 945: pointer.struct.asn1_string_st */
            	900, 0,
            1, 8, 1, /* 950: pointer.struct.asn1_type_st */
            	955, 0,
            0, 16, 1, /* 955: struct.asn1_type_st */
            	960, 8,
            0, 8, 20, /* 960: union.unknown */
            	101, 0,
            	1003, 0,
            	1008, 0,
            	945, 0,
            	940, 0,
            	935, 0,
            	930, 0,
            	925, 0,
            	1022, 0,
            	920, 0,
            	915, 0,
            	910, 0,
            	905, 0,
            	1027, 0,
            	895, 0,
            	1032, 0,
            	1037, 0,
            	1003, 0,
            	1003, 0,
            	165, 0,
            1, 8, 1, /* 1003: pointer.struct.asn1_string_st */
            	900, 0,
            1, 8, 1, /* 1008: pointer.struct.asn1_object_st */
            	1013, 0,
            0, 40, 3, /* 1013: struct.asn1_object_st */
            	125, 0,
            	125, 8,
            	130, 24,
            1, 8, 1, /* 1022: pointer.struct.asn1_string_st */
            	900, 0,
            1, 8, 1, /* 1027: pointer.struct.asn1_string_st */
            	900, 0,
            1, 8, 1, /* 1032: pointer.struct.asn1_string_st */
            	900, 0,
            1, 8, 1, /* 1037: pointer.struct.asn1_string_st */
            	900, 0,
            1, 8, 1, /* 1042: pointer.struct.ASN1_VALUE_st */
            	1047, 0,
            0, 0, 0, /* 1047: struct.ASN1_VALUE_st */
            1, 8, 1, /* 1050: pointer.struct.asn1_string_st */
            	1055, 0,
            0, 24, 1, /* 1055: struct.asn1_string_st */
            	10, 8,
            1, 8, 1, /* 1060: pointer.struct.asn1_string_st */
            	1055, 0,
            1, 8, 1, /* 1065: pointer.struct.asn1_string_st */
            	1055, 0,
            1, 8, 1, /* 1070: pointer.struct.asn1_string_st */
            	1055, 0,
            1, 8, 1, /* 1075: pointer.struct.asn1_string_st */
            	1055, 0,
            1, 8, 1, /* 1080: pointer.struct.asn1_string_st */
            	1055, 0,
            1, 8, 1, /* 1085: pointer.struct.asn1_string_st */
            	1055, 0,
            1, 8, 1, /* 1090: pointer.struct.asn1_string_st */
            	1055, 0,
            1, 8, 1, /* 1095: pointer.struct.asn1_string_st */
            	1055, 0,
            1, 8, 1, /* 1100: pointer.struct.X509_val_st */
            	1105, 0,
            0, 16, 2, /* 1105: struct.X509_val_st */
            	1112, 0,
            	1112, 8,
            1, 8, 1, /* 1112: pointer.struct.asn1_string_st */
            	276, 0,
            0, 8, 20, /* 1117: union.unknown */
            	101, 0,
            	1095, 0,
            	1160, 0,
            	1165, 0,
            	1170, 0,
            	1175, 0,
            	1090, 0,
            	1085, 0,
            	1180, 0,
            	1185, 0,
            	1080, 0,
            	1190, 0,
            	1075, 0,
            	1070, 0,
            	1065, 0,
            	1060, 0,
            	1050, 0,
            	1095, 0,
            	1095, 0,
            	1042, 0,
            1, 8, 1, /* 1160: pointer.struct.asn1_object_st */
            	262, 0,
            1, 8, 1, /* 1165: pointer.struct.asn1_string_st */
            	1055, 0,
            1, 8, 1, /* 1170: pointer.struct.asn1_string_st */
            	1055, 0,
            1, 8, 1, /* 1175: pointer.struct.asn1_string_st */
            	1055, 0,
            1, 8, 1, /* 1180: pointer.struct.asn1_string_st */
            	1055, 0,
            1, 8, 1, /* 1185: pointer.struct.asn1_string_st */
            	1055, 0,
            1, 8, 1, /* 1190: pointer.struct.asn1_string_st */
            	1055, 0,
            1, 8, 1, /* 1195: pointer.struct.asn1_string_st */
            	276, 0,
            0, 0, 0, /* 1200: struct.engine_st */
            0, 4, 0, /* 1203: unsigned int */
            1, 8, 1, /* 1206: pointer.struct.dh_st */
            	1211, 0,
            0, 144, 12, /* 1211: struct.dh_st */
            	1238, 8,
            	1238, 16,
            	1238, 32,
            	1238, 40,
            	1253, 56,
            	1238, 64,
            	1238, 72,
            	10, 80,
            	1238, 96,
            	1267, 112,
            	1294, 128,
            	1330, 136,
            1, 8, 1, /* 1238: pointer.struct.bignum_st */
            	1243, 0,
            0, 24, 1, /* 1243: struct.bignum_st */
            	1248, 0,
            1, 8, 1, /* 1248: pointer.unsigned int */
            	1203, 0,
            1, 8, 1, /* 1253: pointer.struct.bn_mont_ctx_st */
            	1258, 0,
            0, 96, 3, /* 1258: struct.bn_mont_ctx_st */
            	1243, 8,
            	1243, 32,
            	1243, 56,
            0, 16, 1, /* 1267: struct.crypto_ex_data_st */
            	1272, 0,
            1, 8, 1, /* 1272: pointer.struct.stack_st_void */
            	1277, 0,
            0, 32, 1, /* 1277: struct.stack_st_void */
            	1282, 0,
            0, 32, 2, /* 1282: struct.stack_st */
            	1289, 8,
            	217, 24,
            1, 8, 1, /* 1289: pointer.pointer.char */
            	101, 0,
            1, 8, 1, /* 1294: pointer.struct.dh_method */
            	1299, 0,
            0, 72, 8, /* 1299: struct.dh_method */
            	125, 0,
            	1318, 8,
            	1321, 16,
            	1324, 24,
            	1318, 32,
            	1318, 40,
            	101, 56,
            	1327, 64,
            8884097, 8, 0, /* 1318: pointer.func */
            8884097, 8, 0, /* 1321: pointer.func */
            8884097, 8, 0, /* 1324: pointer.func */
            8884097, 8, 0, /* 1327: pointer.func */
            1, 8, 1, /* 1330: pointer.struct.engine_st */
            	1200, 0,
            0, 16, 2, /* 1335: struct.NAME_CONSTRAINTS_st */
            	787, 0,
            	787, 8,
            1, 8, 1, /* 1342: pointer.struct.asn1_string_st */
            	276, 0,
            1, 8, 1, /* 1347: pointer.struct.NAME_CONSTRAINTS_st */
            	1335, 0,
            1, 8, 1, /* 1352: pointer.struct.asn1_string_st */
            	276, 0,
            0, 16, 2, /* 1357: struct.X509_algor_st */
            	1364, 0,
            	1378, 8,
            1, 8, 1, /* 1364: pointer.struct.asn1_object_st */
            	1369, 0,
            0, 40, 3, /* 1369: struct.asn1_object_st */
            	125, 0,
            	125, 8,
            	130, 24,
            1, 8, 1, /* 1378: pointer.struct.asn1_type_st */
            	1383, 0,
            0, 16, 1, /* 1383: struct.asn1_type_st */
            	1388, 8,
            0, 8, 20, /* 1388: union.unknown */
            	101, 0,
            	1431, 0,
            	1364, 0,
            	844, 0,
            	1436, 0,
            	1441, 0,
            	281, 0,
            	1446, 0,
            	1451, 0,
            	1456, 0,
            	1461, 0,
            	1352, 0,
            	1466, 0,
            	1471, 0,
            	1342, 0,
            	1195, 0,
            	271, 0,
            	1431, 0,
            	1431, 0,
            	165, 0,
            1, 8, 1, /* 1431: pointer.struct.asn1_string_st */
            	276, 0,
            1, 8, 1, /* 1436: pointer.struct.asn1_string_st */
            	276, 0,
            1, 8, 1, /* 1441: pointer.struct.asn1_string_st */
            	276, 0,
            1, 8, 1, /* 1446: pointer.struct.asn1_string_st */
            	276, 0,
            1, 8, 1, /* 1451: pointer.struct.asn1_string_st */
            	276, 0,
            1, 8, 1, /* 1456: pointer.struct.asn1_string_st */
            	276, 0,
            1, 8, 1, /* 1461: pointer.struct.asn1_string_st */
            	276, 0,
            1, 8, 1, /* 1466: pointer.struct.asn1_string_st */
            	276, 0,
            1, 8, 1, /* 1471: pointer.struct.asn1_string_st */
            	276, 0,
            0, 0, 0, /* 1476: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 1479: union.unknown */
            	101, 0,
            	1492, 0,
            	1597, 0,
            	1206, 0,
            	1678, 0,
            1, 8, 1, /* 1492: pointer.struct.rsa_st */
            	1497, 0,
            0, 168, 17, /* 1497: struct.rsa_st */
            	1534, 16,
            	1330, 24,
            	1238, 32,
            	1238, 40,
            	1238, 48,
            	1238, 56,
            	1238, 64,
            	1238, 72,
            	1238, 80,
            	1238, 88,
            	1267, 96,
            	1253, 120,
            	1253, 128,
            	1253, 136,
            	101, 144,
            	1589, 152,
            	1589, 160,
            1, 8, 1, /* 1534: pointer.struct.rsa_meth_st */
            	1539, 0,
            0, 112, 13, /* 1539: struct.rsa_meth_st */
            	125, 0,
            	1568, 8,
            	1568, 16,
            	1568, 24,
            	1568, 32,
            	1571, 40,
            	1574, 48,
            	1577, 56,
            	1577, 64,
            	101, 80,
            	1580, 88,
            	1583, 96,
            	1586, 104,
            8884097, 8, 0, /* 1568: pointer.func */
            8884097, 8, 0, /* 1571: pointer.func */
            8884097, 8, 0, /* 1574: pointer.func */
            8884097, 8, 0, /* 1577: pointer.func */
            8884097, 8, 0, /* 1580: pointer.func */
            8884097, 8, 0, /* 1583: pointer.func */
            8884097, 8, 0, /* 1586: pointer.func */
            1, 8, 1, /* 1589: pointer.struct.bn_blinding_st */
            	1594, 0,
            0, 0, 0, /* 1594: struct.bn_blinding_st */
            1, 8, 1, /* 1597: pointer.struct.dsa_st */
            	1602, 0,
            0, 136, 11, /* 1602: struct.dsa_st */
            	1238, 24,
            	1238, 32,
            	1238, 40,
            	1238, 48,
            	1238, 56,
            	1238, 64,
            	1238, 72,
            	1253, 88,
            	1267, 104,
            	1627, 120,
            	1330, 128,
            1, 8, 1, /* 1627: pointer.struct.dsa_method */
            	1632, 0,
            0, 96, 11, /* 1632: struct.dsa_method */
            	125, 0,
            	1657, 8,
            	1660, 16,
            	1663, 24,
            	1666, 32,
            	1669, 40,
            	1672, 48,
            	1672, 56,
            	101, 72,
            	1675, 80,
            	1672, 88,
            8884097, 8, 0, /* 1657: pointer.func */
            8884097, 8, 0, /* 1660: pointer.func */
            8884097, 8, 0, /* 1663: pointer.func */
            8884097, 8, 0, /* 1666: pointer.func */
            8884097, 8, 0, /* 1669: pointer.func */
            8884097, 8, 0, /* 1672: pointer.func */
            8884097, 8, 0, /* 1675: pointer.func */
            1, 8, 1, /* 1678: pointer.struct.ec_key_st */
            	1683, 0,
            0, 0, 0, /* 1683: struct.ec_key_st */
            1, 8, 1, /* 1686: pointer.struct.X509_algor_st */
            	1357, 0,
            1, 8, 1, /* 1691: pointer.struct.X509_pubkey_st */
            	1696, 0,
            0, 24, 3, /* 1696: struct.X509_pubkey_st */
            	1686, 0,
            	1441, 8,
            	1705, 16,
            1, 8, 1, /* 1705: pointer.struct.evp_pkey_st */
            	1710, 0,
            0, 56, 4, /* 1710: struct.evp_pkey_st */
            	1721, 16,
            	1330, 24,
            	1479, 32,
            	1726, 48,
            1, 8, 1, /* 1721: pointer.struct.evp_pkey_asn1_method_st */
            	1476, 0,
            1, 8, 1, /* 1726: pointer.struct.stack_st_X509_ATTRIBUTE */
            	1731, 0,
            0, 32, 2, /* 1731: struct.stack_st_fake_X509_ATTRIBUTE */
            	1738, 8,
            	217, 24,
            8884099, 8, 2, /* 1738: pointer_to_array_of_pointers_to_stack */
            	1745, 0,
            	214, 20,
            0, 8, 1, /* 1745: pointer.X509_ATTRIBUTE */
            	1750, 0,
            0, 0, 1, /* 1750: X509_ATTRIBUTE */
            	1755, 0,
            0, 24, 2, /* 1755: struct.x509_attributes_st */
            	1008, 0,
            	1762, 16,
            0, 8, 3, /* 1762: union.unknown */
            	101, 0,
            	1771, 0,
            	950, 0,
            1, 8, 1, /* 1771: pointer.struct.stack_st_ASN1_TYPE */
            	1776, 0,
            0, 32, 2, /* 1776: struct.stack_st_fake_ASN1_TYPE */
            	1783, 8,
            	217, 24,
            8884099, 8, 2, /* 1783: pointer_to_array_of_pointers_to_stack */
            	1790, 0,
            	214, 20,
            0, 8, 1, /* 1790: pointer.ASN1_TYPE */
            	1795, 0,
            0, 0, 1, /* 1795: ASN1_TYPE */
            	1800, 0,
            0, 16, 1, /* 1800: struct.asn1_type_st */
            	1117, 8,
            1, 8, 1, /* 1805: pointer.struct.stack_st_X509_EXTENSION */
            	1810, 0,
            0, 32, 2, /* 1810: struct.stack_st_fake_X509_EXTENSION */
            	1817, 8,
            	217, 24,
            8884099, 8, 2, /* 1817: pointer_to_array_of_pointers_to_stack */
            	1824, 0,
            	214, 20,
            0, 8, 1, /* 1824: pointer.X509_EXTENSION */
            	890, 0,
            1, 8, 1, /* 1829: pointer.struct.X509_name_st */
            	1834, 0,
            0, 40, 3, /* 1834: struct.X509_name_st */
            	1843, 0,
            	1867, 16,
            	10, 24,
            1, 8, 1, /* 1843: pointer.struct.stack_st_X509_NAME_ENTRY */
            	1848, 0,
            0, 32, 2, /* 1848: struct.stack_st_fake_X509_NAME_ENTRY */
            	1855, 8,
            	217, 24,
            8884099, 8, 2, /* 1855: pointer_to_array_of_pointers_to_stack */
            	1862, 0,
            	214, 20,
            0, 8, 1, /* 1862: pointer.X509_NAME_ENTRY */
            	548, 0,
            1, 8, 1, /* 1867: pointer.struct.buf_mem_st */
            	1872, 0,
            0, 24, 1, /* 1872: struct.buf_mem_st */
            	101, 8,
            1, 8, 1, /* 1877: pointer.struct.x509_cinf_st */
            	1882, 0,
            0, 104, 11, /* 1882: struct.x509_cinf_st */
            	844, 0,
            	844, 8,
            	1686, 16,
            	1829, 24,
            	1100, 32,
            	1829, 40,
            	1691, 48,
            	1441, 56,
            	1441, 64,
            	1805, 72,
            	854, 80,
            0, 1, 0, /* 1907: char */
            1, 8, 1, /* 1910: pointer.struct.x509_st */
            	1915, 0,
            0, 184, 12, /* 1915: struct.x509_st */
            	1877, 0,
            	1686, 8,
            	1441, 16,
            	101, 32,
            	1267, 40,
            	281, 104,
            	849, 112,
            	777, 120,
            	736, 128,
            	606, 136,
            	1347, 144,
            	782, 176,
            0, 8, 0, /* 1942: pointer.void */
            1, 8, 1, /* 1945: pointer.int */
            	214, 0,
        },
        .arg_entity_index = { 1910, 214, 1945, 1945, },
        .ret_entity_index = 1942,
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

