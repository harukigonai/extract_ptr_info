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
            4097, 8, 0, /* 0: pointer.func */
            4097, 8, 0, /* 3: pointer.func */
            0, 0, 0, /* 6: func */
            0, 24, 2, /* 9: struct.DIST_POINT_NAME_st */
            	16, 8,
            	46, 16,
            0, 8, 1, /* 16: union.anon.1.3070 */
            	21, 0,
            1, 8, 1, /* 21: pointer.struct.stack_st_OPENSSL_STRING */
            	26, 0,
            0, 32, 1, /* 26: struct.stack_st_OPENSSL_STRING */
            	31, 0,
            0, 32, 1, /* 31: struct.stack_st */
            	36, 8,
            1, 8, 1, /* 36: pointer.pointer.char */
            	41, 0,
            1, 8, 1, /* 41: pointer.char */
            	4096, 0,
            1, 8, 1, /* 46: pointer.struct.X509_name_st */
            	51, 0,
            0, 40, 3, /* 51: struct.X509_name_st */
            	21, 0,
            	60, 16,
            	41, 24,
            1, 8, 1, /* 60: pointer.struct.buf_mem_st */
            	65, 0,
            0, 24, 1, /* 65: struct.buf_mem_st */
            	41, 8,
            1, 8, 1, /* 70: pointer.struct.ISSUING_DIST_POINT_st */
            	75, 0,
            0, 32, 2, /* 75: struct.ISSUING_DIST_POINT_st */
            	82, 0,
            	87, 16,
            1, 8, 1, /* 82: pointer.struct.DIST_POINT_NAME_st */
            	9, 0,
            1, 8, 1, /* 87: pointer.struct.asn1_string_st */
            	92, 0,
            0, 24, 1, /* 92: struct.asn1_string_st */
            	41, 8,
            0, 80, 8, /* 97: struct.X509_crl_info_st */
            	87, 0,
            	116, 8,
            	46, 16,
            	87, 24,
            	87, 32,
            	21, 40,
            	21, 48,
            	157, 56,
            1, 8, 1, /* 116: pointer.struct.X509_algor_st */
            	121, 0,
            0, 16, 2, /* 121: struct.X509_algor_st */
            	128, 0,
            	142, 8,
            1, 8, 1, /* 128: pointer.struct.asn1_object_st */
            	133, 0,
            0, 40, 3, /* 133: struct.asn1_object_st */
            	41, 0,
            	41, 8,
            	41, 24,
            1, 8, 1, /* 142: pointer.struct.asn1_type_st */
            	147, 0,
            0, 16, 1, /* 147: struct.asn1_type_st */
            	152, 8,
            0, 8, 1, /* 152: struct.fnames */
            	41, 0,
            0, 24, 1, /* 157: struct.ASN1_ENCODING_st */
            	41, 0,
            1, 8, 1, /* 162: pointer.struct.X509_crl_info_st */
            	97, 0,
            1, 8, 1, /* 167: pointer.struct.X509_POLICY_NODE_st */
            	172, 0,
            0, 24, 2, /* 172: struct.X509_POLICY_NODE_st */
            	179, 0,
            	167, 8,
            1, 8, 1, /* 179: pointer.struct.X509_POLICY_DATA_st */
            	184, 0,
            0, 32, 3, /* 184: struct.X509_POLICY_DATA_st */
            	128, 8,
            	21, 16,
            	21, 24,
            0, 0, 0, /* 193: func */
            4097, 8, 0, /* 196: pointer.func */
            0, 0, 0, /* 199: func */
            4097, 8, 0, /* 202: pointer.func */
            0, 0, 0, /* 205: func */
            0, 0, 0, /* 208: func */
            0, 0, 0, /* 211: func */
            4097, 8, 0, /* 214: pointer.func */
            4097, 8, 0, /* 217: pointer.func */
            0, 0, 0, /* 220: func */
            1, 8, 1, /* 223: pointer.struct.x509_crl_method_st */
            	228, 0,
            0, 40, 0, /* 228: struct.x509_crl_method_st */
            4097, 8, 0, /* 231: pointer.func */
            0, 0, 0, /* 234: func */
            0, 56, 4, /* 237: struct.evp_pkey_st */
            	248, 16,
            	270, 24,
            	152, 32,
            	21, 48,
            1, 8, 1, /* 248: pointer.struct.evp_pkey_asn1_method_st */
            	253, 0,
            0, 208, 3, /* 253: struct.evp_pkey_asn1_method_st */
            	41, 16,
            	41, 24,
            	262, 32,
            1, 8, 1, /* 262: pointer.struct.unnamed */
            	267, 0,
            0, 0, 0, /* 267: struct.unnamed */
            1, 8, 1, /* 270: pointer.struct.engine_st */
            	275, 0,
            0, 216, 13, /* 275: struct.engine_st */
            	41, 0,
            	41, 8,
            	304, 16,
            	316, 24,
            	328, 32,
            	340, 40,
            	352, 48,
            	364, 56,
            	372, 64,
            	380, 160,
            	392, 184,
            	270, 200,
            	270, 208,
            1, 8, 1, /* 304: pointer.struct.rsa_meth_st */
            	309, 0,
            0, 112, 2, /* 309: struct.rsa_meth_st */
            	41, 0,
            	41, 80,
            1, 8, 1, /* 316: pointer.struct.dsa_method.1040 */
            	321, 0,
            0, 96, 2, /* 321: struct.dsa_method.1040 */
            	41, 0,
            	41, 72,
            1, 8, 1, /* 328: pointer.struct.dh_method */
            	333, 0,
            0, 72, 2, /* 333: struct.dh_method */
            	41, 0,
            	41, 56,
            1, 8, 1, /* 340: pointer.struct.ecdh_method */
            	345, 0,
            0, 32, 2, /* 345: struct.ecdh_method */
            	41, 0,
            	41, 24,
            1, 8, 1, /* 352: pointer.struct.ecdsa_method */
            	357, 0,
            0, 48, 2, /* 357: struct.ecdsa_method */
            	41, 0,
            	41, 40,
            1, 8, 1, /* 364: pointer.struct.rand_meth_st */
            	369, 0,
            0, 48, 0, /* 369: struct.rand_meth_st */
            1, 8, 1, /* 372: pointer.struct.store_method_st */
            	377, 0,
            0, 0, 0, /* 377: struct.store_method_st */
            1, 8, 1, /* 380: pointer.struct.ENGINE_CMD_DEFN_st */
            	385, 0,
            0, 32, 2, /* 385: struct.ENGINE_CMD_DEFN_st */
            	41, 8,
            	41, 16,
            0, 16, 1, /* 392: struct.crypto_ex_data_st */
            	21, 0,
            0, 24, 3, /* 397: struct.X509_pubkey_st */
            	116, 0,
            	87, 8,
            	406, 16,
            1, 8, 1, /* 406: pointer.struct.evp_pkey_st */
            	237, 0,
            0, 184, 12, /* 411: struct.x509_st */
            	438, 0,
            	116, 8,
            	87, 16,
            	41, 32,
            	392, 40,
            	87, 104,
            	485, 112,
            	499, 120,
            	21, 128,
            	21, 136,
            	511, 144,
            	523, 176,
            1, 8, 1, /* 438: pointer.struct.x509_cinf_st */
            	443, 0,
            0, 104, 11, /* 443: struct.x509_cinf_st */
            	87, 0,
            	87, 8,
            	116, 16,
            	46, 24,
            	468, 32,
            	46, 40,
            	480, 48,
            	87, 56,
            	87, 64,
            	21, 72,
            	157, 80,
            1, 8, 1, /* 468: pointer.struct.X509_val_st */
            	473, 0,
            0, 16, 2, /* 473: struct.X509_val_st */
            	87, 0,
            	87, 8,
            1, 8, 1, /* 480: pointer.struct.X509_pubkey_st */
            	397, 0,
            1, 8, 1, /* 485: pointer.struct.AUTHORITY_KEYID_st */
            	490, 0,
            0, 24, 3, /* 490: struct.AUTHORITY_KEYID_st */
            	87, 0,
            	21, 8,
            	87, 16,
            1, 8, 1, /* 499: pointer.struct.X509_POLICY_CACHE_st */
            	504, 0,
            0, 40, 2, /* 504: struct.X509_POLICY_CACHE_st */
            	179, 0,
            	21, 8,
            1, 8, 1, /* 511: pointer.struct.NAME_CONSTRAINTS_st */
            	516, 0,
            0, 16, 2, /* 516: struct.NAME_CONSTRAINTS_st */
            	21, 0,
            	21, 8,
            1, 8, 1, /* 523: pointer.struct.x509_cert_aux_st */
            	528, 0,
            0, 40, 5, /* 528: struct.x509_cert_aux_st */
            	21, 0,
            	21, 8,
            	87, 16,
            	87, 24,
            	21, 32,
            1, 8, 1, /* 541: pointer.struct.x509_st */
            	411, 0,
            1, 8, 1, /* 546: pointer.struct.X509_POLICY_LEVEL_st */
            	551, 0,
            0, 32, 3, /* 551: struct.X509_POLICY_LEVEL_st */
            	541, 0,
            	21, 8,
            	167, 16,
            0, 48, 4, /* 560: struct.X509_POLICY_TREE_st */
            	546, 0,
            	21, 16,
            	21, 24,
            	21, 32,
            4097, 8, 0, /* 571: pointer.func */
            0, 20, 0, /* 574: array[20].char */
            4097, 8, 0, /* 577: pointer.func */
            0, 0, 0, /* 580: func */
            0, 0, 0, /* 583: func */
            0, 0, 0, /* 586: func */
            1, 8, 1, /* 589: pointer.struct.X509_POLICY_TREE_st */
            	560, 0,
            0, 0, 0, /* 594: func */
            4097, 8, 0, /* 597: pointer.func */
            0, 0, 0, /* 600: func */
            4097, 8, 0, /* 603: pointer.func */
            4097, 8, 0, /* 606: pointer.func */
            4097, 8, 0, /* 609: pointer.func */
            4097, 8, 0, /* 612: pointer.func */
            0, 0, 0, /* 615: func */
            4097, 8, 0, /* 618: pointer.func */
            0, 0, 0, /* 621: func */
            4097, 8, 0, /* 624: pointer.func */
            4097, 8, 0, /* 627: pointer.func */
            0, 0, 0, /* 630: func */
            1, 8, 1, /* 633: pointer.struct.evp_pkey_asn1_method_st.2928 */
            	638, 0,
            0, 208, 2, /* 638: struct.evp_pkey_asn1_method_st.2928 */
            	41, 16,
            	41, 24,
            0, 0, 0, /* 645: func */
            4097, 8, 0, /* 648: pointer.func */
            0, 0, 0, /* 651: func */
            0, 0, 0, /* 654: func */
            0, 0, 0, /* 657: func */
            0, 0, 0, /* 660: func */
            0, 0, 0, /* 663: func */
            4097, 8, 0, /* 666: pointer.func */
            0, 0, 0, /* 669: func */
            0, 0, 0, /* 672: func */
            0, 0, 0, /* 675: func */
            0, 56, 4, /* 678: struct.evp_pkey_st.2930 */
            	633, 16,
            	270, 24,
            	152, 32,
            	21, 48,
            0, 0, 0, /* 689: func */
            0, 8, 0, /* 692: long */
            1, 8, 1, /* 695: pointer.struct.evp_pkey_st.2930 */
            	678, 0,
            1, 8, 1, /* 700: pointer.struct.x509_cinf_st.3159 */
            	705, 0,
            0, 104, 11, /* 705: struct.x509_cinf_st.3159 */
            	87, 0,
            	87, 8,
            	116, 16,
            	46, 24,
            	468, 32,
            	46, 40,
            	730, 48,
            	87, 56,
            	87, 64,
            	21, 72,
            	157, 80,
            1, 8, 1, /* 730: pointer.struct.X509_pubkey_st.2915 */
            	735, 0,
            0, 24, 3, /* 735: struct.X509_pubkey_st.2915 */
            	116, 0,
            	87, 8,
            	695, 16,
            0, 0, 0, /* 744: func */
            0, 4, 0, /* 747: int */
            4097, 8, 0, /* 750: pointer.func */
            1, 8, 1, /* 753: pointer.struct.x509_st.3164 */
            	758, 0,
            0, 184, 12, /* 758: struct.x509_st.3164 */
            	700, 0,
            	116, 8,
            	87, 16,
            	41, 32,
            	392, 40,
            	87, 104,
            	485, 112,
            	499, 120,
            	21, 128,
            	21, 136,
            	511, 144,
            	523, 176,
            0, 0, 0, /* 785: func */
            0, 0, 0, /* 788: func */
            4097, 8, 0, /* 791: pointer.func */
            0, 0, 0, /* 794: func */
            0, 0, 0, /* 797: func */
            4097, 8, 0, /* 800: pointer.func */
            0, 120, 10, /* 803: struct.X509_crl_st */
            	162, 0,
            	116, 8,
            	87, 16,
            	485, 32,
            	70, 40,
            	87, 56,
            	87, 64,
            	21, 96,
            	223, 104,
            	41, 112,
            4097, 8, 0, /* 826: pointer.func */
            0, 0, 0, /* 829: func */
            0, 0, 0, /* 832: func */
            4097, 8, 0, /* 835: pointer.func */
            0, 0, 0, /* 838: func */
            4097, 8, 0, /* 841: pointer.func */
            4097, 8, 0, /* 844: pointer.func */
            1, 8, 1, /* 847: pointer.struct.x509_store_st.4284 */
            	852, 0,
            0, 144, 7, /* 852: struct.x509_store_st.4284 */
            	21, 8,
            	21, 16,
            	869, 24,
            	262, 32,
            	262, 64,
            	262, 112,
            	392, 120,
            1, 8, 1, /* 869: pointer.struct.X509_VERIFY_PARAM_st */
            	874, 0,
            0, 56, 2, /* 874: struct.X509_VERIFY_PARAM_st */
            	41, 0,
            	21, 48,
            4097, 8, 0, /* 881: pointer.func */
            0, 0, 0, /* 884: func */
            4097, 8, 0, /* 887: pointer.func */
            0, 0, 0, /* 890: func */
            0, 1, 0, /* 893: char */
            4097, 8, 0, /* 896: pointer.func */
            0, 0, 0, /* 899: func */
            4097, 8, 0, /* 902: pointer.func */
            4097, 8, 0, /* 905: pointer.func */
            0, 0, 0, /* 908: func */
            0, 248, 17, /* 911: struct.x509_store_ctx_st.4286 */
            	847, 0,
            	753, 16,
            	21, 24,
            	21, 32,
            	869, 40,
            	41, 48,
            	262, 56,
            	262, 88,
            	262, 120,
            	262, 144,
            	21, 160,
            	589, 168,
            	753, 192,
            	753, 200,
            	948, 208,
            	953, 224,
            	392, 232,
            1, 8, 1, /* 948: pointer.struct.X509_crl_st */
            	803, 0,
            1, 8, 1, /* 953: pointer.struct.x509_store_ctx_st.4286 */
            	911, 0,
            0, 0, 0, /* 958: func */
            4097, 8, 0, /* 961: pointer.func */
            0, 0, 0, /* 964: func */
            4097, 8, 0, /* 967: pointer.func */
            4097, 8, 0, /* 970: pointer.func */
            4097, 8, 0, /* 973: pointer.func */
            4097, 8, 0, /* 976: pointer.func */
            4097, 8, 0, /* 979: pointer.func */
            4097, 8, 0, /* 982: pointer.func */
            4097, 8, 0, /* 985: pointer.func */
            4097, 8, 0, /* 988: pointer.func */
            4097, 8, 0, /* 991: pointer.func */
            0, 0, 0, /* 994: func */
            0, 0, 0, /* 997: func */
            0, 0, 0, /* 1000: func */
            0, 0, 0, /* 1003: func */
            0, 0, 0, /* 1006: func */
            0, 0, 0, /* 1009: func */
            4097, 8, 0, /* 1012: pointer.func */
            0, 0, 0, /* 1015: func */
            0, 0, 0, /* 1018: func */
            4097, 8, 0, /* 1021: pointer.func */
            0, 0, 0, /* 1024: func */
            4097, 8, 0, /* 1027: pointer.func */
            4097, 8, 0, /* 1030: pointer.func */
            0, 0, 0, /* 1033: func */
            0, 0, 0, /* 1036: func */
            4097, 8, 0, /* 1039: pointer.func */
            4097, 8, 0, /* 1042: pointer.func */
            0, 0, 0, /* 1045: func */
            4097, 8, 0, /* 1048: pointer.func */
            4097, 8, 0, /* 1051: pointer.func */
            4097, 8, 0, /* 1054: pointer.func */
            4097, 8, 0, /* 1057: pointer.func */
            0, 0, 0, /* 1060: func */
            0, 0, 0, /* 1063: func */
            4097, 8, 0, /* 1066: pointer.func */
            0, 0, 0, /* 1069: func */
            4097, 8, 0, /* 1072: pointer.func */
            4097, 8, 0, /* 1075: pointer.func */
            0, 0, 0, /* 1078: func */
            0, 0, 0, /* 1081: func */
            4097, 8, 0, /* 1084: pointer.func */
            0, 0, 0, /* 1087: func */
            0, 0, 0, /* 1090: func */
            4097, 8, 0, /* 1093: pointer.func */
            0, 0, 0, /* 1096: func */
            4097, 8, 0, /* 1099: pointer.func */
            0, 0, 0, /* 1102: func */
            4097, 8, 0, /* 1105: pointer.func */
            0, 0, 0, /* 1108: func */
            0, 0, 0, /* 1111: func */
            4097, 8, 0, /* 1114: pointer.func */
            0, 0, 0, /* 1117: func */
            0, 0, 0, /* 1120: func */
            0, 0, 0, /* 1123: func */
            0, 0, 0, /* 1126: func */
            0, 0, 0, /* 1129: func */
            4097, 8, 0, /* 1132: pointer.func */
            4097, 8, 0, /* 1135: pointer.func */
            4097, 8, 0, /* 1138: pointer.func */
            0, 0, 0, /* 1141: func */
            4097, 8, 0, /* 1144: pointer.func */
            4097, 8, 0, /* 1147: pointer.func */
            4097, 8, 0, /* 1150: pointer.func */
            0, 0, 0, /* 1153: func */
            4097, 8, 0, /* 1156: pointer.func */
            4097, 8, 0, /* 1159: pointer.func */
            4097, 8, 0, /* 1162: pointer.func */
            0, 0, 0, /* 1165: func */
            4097, 8, 0, /* 1168: pointer.func */
            4097, 8, 0, /* 1171: pointer.func */
            4097, 8, 0, /* 1174: pointer.func */
        },
        .arg_entity_index = { 953, },
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

