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
    printf("X509_STORE_CTX_free called\n");
    if (!syscall(890))
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
            0, 0, 0, /* 0: func */
            0, 8, 1, /* 3: union.anon.1.3070 */
            	8, 0,
            1, 8, 1, /* 8: pointer.struct.stack_st_OPENSSL_STRING */
            	13, 0,
            0, 32, 1, /* 13: struct.stack_st_OPENSSL_STRING */
            	18, 0,
            0, 32, 1, /* 18: struct.stack_st */
            	23, 8,
            1, 8, 1, /* 23: pointer.pointer.char */
            	28, 0,
            1, 8, 1, /* 28: pointer.char */
            	33, 0,
            0, 1, 0, /* 33: char */
            0, 24, 2, /* 36: struct.DIST_POINT_NAME_st */
            	3, 8,
            	43, 16,
            1, 8, 1, /* 43: pointer.struct.X509_name_st */
            	48, 0,
            0, 40, 3, /* 48: struct.X509_name_st */
            	8, 0,
            	57, 16,
            	28, 24,
            1, 8, 1, /* 57: pointer.struct.buf_mem_st */
            	62, 0,
            0, 24, 1, /* 62: struct.buf_mem_st */
            	28, 8,
            1, 8, 1, /* 67: pointer.struct.DIST_POINT_NAME_st */
            	36, 0,
            0, 32, 2, /* 72: struct.ISSUING_DIST_POINT_st */
            	67, 0,
            	79, 16,
            1, 8, 1, /* 79: pointer.struct.asn1_string_st */
            	84, 0,
            0, 24, 1, /* 84: struct.asn1_string_st */
            	28, 8,
            0, 80, 8, /* 89: struct.X509_crl_info_st */
            	79, 0,
            	108, 8,
            	43, 16,
            	79, 24,
            	79, 32,
            	8, 40,
            	8, 48,
            	149, 56,
            1, 8, 1, /* 108: pointer.struct.X509_algor_st */
            	113, 0,
            0, 16, 2, /* 113: struct.X509_algor_st */
            	120, 0,
            	134, 8,
            1, 8, 1, /* 120: pointer.struct.asn1_object_st */
            	125, 0,
            0, 40, 3, /* 125: struct.asn1_object_st */
            	28, 0,
            	28, 8,
            	28, 24,
            1, 8, 1, /* 134: pointer.struct.asn1_type_st */
            	139, 0,
            0, 16, 1, /* 139: struct.asn1_type_st */
            	144, 8,
            0, 8, 1, /* 144: struct.fnames */
            	28, 0,
            0, 24, 1, /* 149: struct.ASN1_ENCODING_st */
            	28, 0,
            1, 8, 1, /* 154: pointer.struct.X509_crl_info_st */
            	89, 0,
            0, 24, 2, /* 159: struct.X509_POLICY_NODE_st */
            	166, 0,
            	180, 8,
            1, 8, 1, /* 166: pointer.struct.X509_POLICY_DATA_st */
            	171, 0,
            0, 32, 3, /* 171: struct.X509_POLICY_DATA_st */
            	120, 8,
            	8, 16,
            	8, 24,
            1, 8, 1, /* 180: pointer.struct.X509_POLICY_NODE_st */
            	159, 0,
            0, 8, 0, /* 185: pointer.func */
            0, 0, 0, /* 188: func */
            0, 8, 0, /* 191: pointer.func */
            0, 8, 0, /* 194: pointer.func */
            0, 0, 0, /* 197: func */
            0, 0, 0, /* 200: func */
            0, 0, 0, /* 203: func */
            0, 8, 0, /* 206: pointer.func */
            0, 8, 0, /* 209: pointer.func */
            0, 0, 0, /* 212: func */
            0, 8, 0, /* 215: pointer.func */
            0, 0, 0, /* 218: func */
            0, 208, 3, /* 221: struct.evp_pkey_asn1_method_st */
            	28, 16,
            	28, 24,
            	230, 32,
            1, 8, 1, /* 230: pointer.struct.unnamed */
            	235, 0,
            0, 0, 0, /* 235: struct.unnamed */
            1, 8, 1, /* 238: pointer.struct.evp_pkey_asn1_method_st */
            	221, 0,
            0, 56, 4, /* 243: struct.evp_pkey_st */
            	238, 16,
            	254, 24,
            	144, 32,
            	8, 48,
            1, 8, 1, /* 254: pointer.struct.engine_st */
            	259, 0,
            0, 216, 13, /* 259: struct.engine_st */
            	28, 0,
            	28, 8,
            	288, 16,
            	300, 24,
            	312, 32,
            	324, 40,
            	336, 48,
            	348, 56,
            	356, 64,
            	364, 160,
            	376, 184,
            	254, 200,
            	254, 208,
            1, 8, 1, /* 288: pointer.struct.rsa_meth_st */
            	293, 0,
            0, 112, 2, /* 293: struct.rsa_meth_st */
            	28, 0,
            	28, 80,
            1, 8, 1, /* 300: pointer.struct.dsa_method.1040 */
            	305, 0,
            0, 96, 2, /* 305: struct.dsa_method.1040 */
            	28, 0,
            	28, 72,
            1, 8, 1, /* 312: pointer.struct.dh_method */
            	317, 0,
            0, 72, 2, /* 317: struct.dh_method */
            	28, 0,
            	28, 56,
            1, 8, 1, /* 324: pointer.struct.ecdh_method */
            	329, 0,
            0, 32, 2, /* 329: struct.ecdh_method */
            	28, 0,
            	28, 24,
            1, 8, 1, /* 336: pointer.struct.ecdsa_method */
            	341, 0,
            0, 48, 2, /* 341: struct.ecdsa_method */
            	28, 0,
            	28, 40,
            1, 8, 1, /* 348: pointer.struct.rand_meth_st */
            	353, 0,
            0, 48, 0, /* 353: struct.rand_meth_st */
            1, 8, 1, /* 356: pointer.struct.store_method_st */
            	361, 0,
            0, 0, 0, /* 361: struct.store_method_st */
            1, 8, 1, /* 364: pointer.struct.ENGINE_CMD_DEFN_st */
            	369, 0,
            0, 32, 2, /* 369: struct.ENGINE_CMD_DEFN_st */
            	28, 8,
            	28, 16,
            0, 16, 1, /* 376: struct.crypto_ex_data_st */
            	8, 0,
            0, 104, 11, /* 381: struct.x509_cinf_st */
            	79, 0,
            	79, 8,
            	108, 16,
            	43, 24,
            	406, 32,
            	43, 40,
            	418, 48,
            	79, 56,
            	79, 64,
            	8, 72,
            	149, 80,
            1, 8, 1, /* 406: pointer.struct.X509_val_st */
            	411, 0,
            0, 16, 2, /* 411: struct.X509_val_st */
            	79, 0,
            	79, 8,
            1, 8, 1, /* 418: pointer.struct.X509_pubkey_st */
            	423, 0,
            0, 24, 3, /* 423: struct.X509_pubkey_st */
            	108, 0,
            	79, 8,
            	432, 16,
            1, 8, 1, /* 432: pointer.struct.evp_pkey_st */
            	243, 0,
            1, 8, 1, /* 437: pointer.struct.x509_cinf_st */
            	381, 0,
            0, 184, 12, /* 442: struct.x509_st */
            	437, 0,
            	108, 8,
            	79, 16,
            	28, 32,
            	376, 40,
            	79, 104,
            	469, 112,
            	483, 120,
            	8, 128,
            	8, 136,
            	495, 144,
            	507, 176,
            1, 8, 1, /* 469: pointer.struct.AUTHORITY_KEYID_st */
            	474, 0,
            0, 24, 3, /* 474: struct.AUTHORITY_KEYID_st */
            	79, 0,
            	8, 8,
            	79, 16,
            1, 8, 1, /* 483: pointer.struct.X509_POLICY_CACHE_st */
            	488, 0,
            0, 40, 2, /* 488: struct.X509_POLICY_CACHE_st */
            	166, 0,
            	8, 8,
            1, 8, 1, /* 495: pointer.struct.NAME_CONSTRAINTS_st */
            	500, 0,
            0, 16, 2, /* 500: struct.NAME_CONSTRAINTS_st */
            	8, 0,
            	8, 8,
            1, 8, 1, /* 507: pointer.struct.x509_cert_aux_st */
            	512, 0,
            0, 40, 5, /* 512: struct.x509_cert_aux_st */
            	8, 0,
            	8, 8,
            	79, 16,
            	79, 24,
            	8, 32,
            1, 8, 1, /* 525: pointer.struct.x509_st */
            	442, 0,
            0, 8, 0, /* 530: pointer.func */
            0, 32, 3, /* 533: struct.X509_POLICY_LEVEL_st */
            	525, 0,
            	8, 8,
            	180, 16,
            0, 48, 4, /* 542: struct.X509_POLICY_TREE_st */
            	553, 0,
            	8, 16,
            	8, 24,
            	8, 32,
            1, 8, 1, /* 553: pointer.struct.X509_POLICY_LEVEL_st */
            	533, 0,
            0, 8, 0, /* 558: pointer.func */
            0, 0, 0, /* 561: func */
            0, 0, 0, /* 564: func */
            0, 0, 0, /* 567: func */
            0, 8, 0, /* 570: pointer.func */
            0, 0, 0, /* 573: func */
            0, 0, 0, /* 576: func */
            0, 8, 0, /* 579: pointer.func */
            1, 8, 1, /* 582: pointer.struct.X509_crl_st */
            	587, 0,
            0, 120, 10, /* 587: struct.X509_crl_st */
            	154, 0,
            	108, 8,
            	79, 16,
            	469, 32,
            	610, 40,
            	79, 56,
            	79, 64,
            	8, 96,
            	615, 104,
            	28, 112,
            1, 8, 1, /* 610: pointer.struct.ISSUING_DIST_POINT_st */
            	72, 0,
            1, 8, 1, /* 615: pointer.struct.x509_crl_method_st */
            	620, 0,
            0, 40, 0, /* 620: struct.x509_crl_method_st */
            0, 0, 0, /* 623: func */
            0, 8, 0, /* 626: pointer.func */
            0, 0, 0, /* 629: func */
            0, 8, 0, /* 632: pointer.func */
            0, 0, 0, /* 635: func */
            0, 0, 0, /* 638: func */
            0, 8, 0, /* 641: pointer.func */
            0, 0, 0, /* 644: func */
            0, 8, 0, /* 647: pointer.func */
            0, 0, 0, /* 650: func */
            0, 8, 0, /* 653: pointer.func */
            0, 0, 0, /* 656: func */
            0, 0, 0, /* 659: func */
            0, 8, 0, /* 662: pointer.func */
            0, 0, 0, /* 665: func */
            0, 8, 0, /* 668: pointer.func */
            0, 0, 0, /* 671: func */
            0, 8, 0, /* 674: pointer.func */
            0, 0, 0, /* 677: func */
            0, 0, 0, /* 680: func */
            0, 0, 0, /* 683: func */
            0, 0, 0, /* 686: func */
            0, 8, 0, /* 689: pointer.func */
            0, 0, 0, /* 692: func */
            1, 8, 1, /* 695: pointer.struct.x509_store_ctx_st.4286 */
            	700, 0,
            0, 248, 17, /* 700: struct.x509_store_ctx_st.4286 */
            	737, 0,
            	771, 16,
            	8, 24,
            	8, 32,
            	759, 40,
            	28, 48,
            	230, 56,
            	230, 88,
            	230, 120,
            	230, 144,
            	8, 160,
            	875, 168,
            	771, 192,
            	771, 200,
            	582, 208,
            	695, 224,
            	376, 232,
            1, 8, 1, /* 737: pointer.struct.x509_store_st.4284 */
            	742, 0,
            0, 144, 7, /* 742: struct.x509_store_st.4284 */
            	8, 8,
            	8, 16,
            	759, 24,
            	230, 32,
            	230, 64,
            	230, 112,
            	376, 120,
            1, 8, 1, /* 759: pointer.struct.X509_VERIFY_PARAM_st */
            	764, 0,
            0, 56, 2, /* 764: struct.X509_VERIFY_PARAM_st */
            	28, 0,
            	8, 48,
            1, 8, 1, /* 771: pointer.struct.x509_st.3164 */
            	776, 0,
            0, 184, 12, /* 776: struct.x509_st.3164 */
            	803, 0,
            	108, 8,
            	79, 16,
            	28, 32,
            	376, 40,
            	79, 104,
            	469, 112,
            	483, 120,
            	8, 128,
            	8, 136,
            	495, 144,
            	507, 176,
            1, 8, 1, /* 803: pointer.struct.x509_cinf_st.3159 */
            	808, 0,
            0, 104, 11, /* 808: struct.x509_cinf_st.3159 */
            	79, 0,
            	79, 8,
            	108, 16,
            	43, 24,
            	406, 32,
            	43, 40,
            	833, 48,
            	79, 56,
            	79, 64,
            	8, 72,
            	149, 80,
            1, 8, 1, /* 833: pointer.struct.X509_pubkey_st.2915 */
            	838, 0,
            0, 24, 3, /* 838: struct.X509_pubkey_st.2915 */
            	108, 0,
            	79, 8,
            	847, 16,
            1, 8, 1, /* 847: pointer.struct.evp_pkey_st.2930 */
            	852, 0,
            0, 56, 4, /* 852: struct.evp_pkey_st.2930 */
            	863, 16,
            	254, 24,
            	144, 32,
            	8, 48,
            1, 8, 1, /* 863: pointer.struct.evp_pkey_asn1_method_st.2928 */
            	868, 0,
            0, 208, 2, /* 868: struct.evp_pkey_asn1_method_st.2928 */
            	28, 16,
            	28, 24,
            1, 8, 1, /* 875: pointer.struct.X509_POLICY_TREE_st */
            	542, 0,
            0, 8, 0, /* 880: pointer.func */
            0, 8, 0, /* 883: pointer.func */
            0, 8, 0, /* 886: pointer.func */
            0, 20, 0, /* 889: array[20].char */
            0, 0, 0, /* 892: func */
            0, 8, 0, /* 895: pointer.func */
            0, 0, 0, /* 898: func */
            0, 8, 0, /* 901: pointer.func */
            0, 8, 0, /* 904: pointer.func */
            0, 8, 0, /* 907: pointer.func */
            0, 0, 0, /* 910: func */
            0, 8, 0, /* 913: pointer.func */
            0, 8, 0, /* 916: pointer.func */
            0, 0, 0, /* 919: func */
            0, 0, 0, /* 922: func */
            0, 8, 0, /* 925: pointer.func */
            0, 0, 0, /* 928: func */
            0, 8, 0, /* 931: pointer.func */
            0, 8, 0, /* 934: pointer.func */
            0, 8, 0, /* 937: pointer.func */
            0, 4, 0, /* 940: int */
            0, 8, 0, /* 943: long */
            0, 8, 0, /* 946: pointer.func */
            0, 8, 0, /* 949: pointer.func */
            0, 0, 0, /* 952: func */
            0, 8, 0, /* 955: pointer.func */
            0, 8, 0, /* 958: pointer.func */
            0, 8, 0, /* 961: pointer.func */
            0, 8, 0, /* 964: pointer.func */
            0, 8, 0, /* 967: pointer.func */
            0, 8, 0, /* 970: pointer.func */
            0, 8, 0, /* 973: pointer.func */
            0, 8, 0, /* 976: pointer.func */
            0, 0, 0, /* 979: func */
            0, 0, 0, /* 982: func */
            0, 8, 0, /* 985: pointer.func */
            0, 0, 0, /* 988: func */
            0, 8, 0, /* 991: pointer.func */
            0, 0, 0, /* 994: func */
            0, 8, 0, /* 997: pointer.func */
            0, 0, 0, /* 1000: func */
            0, 0, 0, /* 1003: func */
            0, 8, 0, /* 1006: pointer.func */
            0, 0, 0, /* 1009: func */
            0, 0, 0, /* 1012: func */
            0, 8, 0, /* 1015: pointer.func */
            0, 8, 0, /* 1018: pointer.func */
            0, 0, 0, /* 1021: func */
            0, 8, 0, /* 1024: pointer.func */
            0, 0, 0, /* 1027: func */
            0, 8, 0, /* 1030: pointer.func */
            0, 0, 0, /* 1033: func */
            0, 8, 0, /* 1036: pointer.func */
            0, 0, 0, /* 1039: func */
            0, 8, 0, /* 1042: pointer.func */
            0, 0, 0, /* 1045: func */
            0, 0, 0, /* 1048: func */
            0, 8, 0, /* 1051: pointer.func */
            0, 0, 0, /* 1054: func */
            0, 0, 0, /* 1057: func */
            0, 8, 0, /* 1060: pointer.func */
            0, 0, 0, /* 1063: func */
            0, 8, 0, /* 1066: pointer.func */
            0, 0, 0, /* 1069: func */
            0, 0, 0, /* 1072: func */
            0, 0, 0, /* 1075: func */
            0, 8, 0, /* 1078: pointer.func */
            0, 8, 0, /* 1081: pointer.func */
            0, 0, 0, /* 1084: func */
            0, 8, 0, /* 1087: pointer.func */
            0, 0, 0, /* 1090: func */
            0, 8, 0, /* 1093: pointer.func */
            0, 0, 0, /* 1096: func */
            0, 0, 0, /* 1099: func */
            0, 8, 0, /* 1102: pointer.func */
            0, 0, 0, /* 1105: func */
            0, 8, 0, /* 1108: pointer.func */
            0, 0, 0, /* 1111: func */
            0, 0, 0, /* 1114: func */
            0, 8, 0, /* 1117: pointer.func */
            0, 0, 0, /* 1120: func */
            0, 0, 0, /* 1123: func */
            0, 0, 0, /* 1126: func */
            0, 8, 0, /* 1129: pointer.func */
            0, 0, 0, /* 1132: func */
            0, 8, 0, /* 1135: pointer.func */
            0, 0, 0, /* 1138: func */
            0, 8, 0, /* 1141: pointer.func */
            0, 8, 0, /* 1144: pointer.func */
            0, 0, 0, /* 1147: func */
            0, 0, 0, /* 1150: func */
            0, 0, 0, /* 1153: func */
            0, 8, 0, /* 1156: pointer.func */
            0, 8, 0, /* 1159: pointer.func */
            0, 0, 0, /* 1162: func */
            0, 8, 0, /* 1165: pointer.func */
            0, 8, 0, /* 1168: pointer.func */
            0, 0, 0, /* 1171: func */
            0, 8, 0, /* 1174: pointer.func */
        },
        .arg_entity_index = { 695, },
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

