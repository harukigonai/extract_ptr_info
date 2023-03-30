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

int X509_STORE_CTX_get1_issuer(X509 ** arg_a,X509_STORE_CTX * arg_b,X509 * arg_c) 
{
    if (syscall(890))
        return _X509_STORE_CTX_get1_issuer(arg_a,arg_b,arg_c)
    else {
        int (*orig_X509_STORE_CTX_get1_issuer)(X509 **,X509_STORE_CTX *,X509 *);
        orig_X509_STORE_CTX_get1_issuer = dlsym(RTLD_NEXT, "X509_STORE_CTX_get1_issuer");
        return orig_X509_STORE_CTX_get1_issuer(arg_a,arg_b,arg_c);
    }
}

int _X509_STORE_CTX_get1_issuer(X509 ** arg_a,X509_STORE_CTX * arg_b,X509 * arg_c) 
{
    printf("X509_STORE_CTX_get1_issuer called\n");
    int ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 0, 0, /* 0: func */
            0, 0, 0, /* 3: func */
            1, 8, 1, /* 6: pointer.struct.x509_crl_method_st */
            	11, 0,
            0, 40, 4, /* 11: struct.x509_crl_method_st */
            	22, 8,
            	22, 16,
            	27, 24,
            	35, 32,
            1, 8, 1, /* 22: pointer.func */
            	3, 0,
            1, 8, 1, /* 27: pointer.func */
            	32, 0,
            0, 0, 0, /* 32: func */
            1, 8, 1, /* 35: pointer.func */
            	0, 0,
            0, 8, 1, /* 40: union.anon.1.3070 */
            	45, 0,
            1, 8, 1, /* 45: pointer.struct.stack_st_OPENSSL_STRING */
            	50, 0,
            0, 32, 1, /* 50: struct.stack_st_OPENSSL_STRING */
            	55, 0,
            0, 32, 2, /* 55: struct.stack_st */
            	62, 8,
            	75, 24,
            1, 8, 1, /* 62: pointer.pointer.char */
            	67, 0,
            1, 8, 1, /* 67: pointer.char */
            	72, 0,
            0, 1, 0, /* 72: char */
            1, 8, 1, /* 75: pointer.func */
            	80, 0,
            0, 0, 0, /* 80: func */
            0, 24, 2, /* 83: struct.DIST_POINT_NAME_st */
            	40, 8,
            	90, 16,
            1, 8, 1, /* 90: pointer.struct.X509_name_st */
            	95, 0,
            0, 40, 3, /* 95: struct.X509_name_st */
            	45, 0,
            	104, 16,
            	67, 24,
            1, 8, 1, /* 104: pointer.struct.buf_mem_st */
            	109, 0,
            0, 24, 1, /* 109: struct.buf_mem_st */
            	67, 8,
            1, 8, 1, /* 114: pointer.struct.DIST_POINT_NAME_st */
            	83, 0,
            0, 32, 2, /* 119: struct.ISSUING_DIST_POINT_st */
            	114, 0,
            	126, 16,
            1, 8, 1, /* 126: pointer.struct.asn1_string_st */
            	131, 0,
            0, 24, 1, /* 131: struct.asn1_string_st */
            	67, 8,
            0, 80, 8, /* 136: struct.X509_crl_info_st */
            	126, 0,
            	155, 8,
            	90, 16,
            	126, 24,
            	126, 32,
            	45, 40,
            	45, 48,
            	196, 56,
            1, 8, 1, /* 155: pointer.struct.X509_algor_st */
            	160, 0,
            0, 16, 2, /* 160: struct.X509_algor_st */
            	167, 0,
            	181, 8,
            1, 8, 1, /* 167: pointer.struct.asn1_object_st */
            	172, 0,
            0, 40, 3, /* 172: struct.asn1_object_st */
            	67, 0,
            	67, 8,
            	67, 24,
            1, 8, 1, /* 181: pointer.struct.asn1_type_st */
            	186, 0,
            0, 16, 1, /* 186: struct.asn1_type_st */
            	191, 8,
            0, 8, 1, /* 191: struct.fnames */
            	67, 0,
            0, 24, 1, /* 196: struct.ASN1_ENCODING_st */
            	67, 0,
            1, 8, 1, /* 201: pointer.struct.X509_crl_info_st */
            	136, 0,
            0, 24, 2, /* 206: struct.X509_POLICY_NODE_st */
            	213, 0,
            	227, 8,
            1, 8, 1, /* 213: pointer.struct.X509_POLICY_DATA_st */
            	218, 0,
            0, 32, 3, /* 218: struct.X509_POLICY_DATA_st */
            	167, 8,
            	45, 16,
            	45, 24,
            1, 8, 1, /* 227: pointer.struct.X509_POLICY_NODE_st */
            	206, 0,
            0, 48, 4, /* 232: struct.X509_POLICY_TREE_st */
            	243, 0,
            	45, 16,
            	45, 24,
            	45, 32,
            1, 8, 1, /* 243: pointer.struct.X509_POLICY_LEVEL_st */
            	248, 0,
            0, 32, 3, /* 248: struct.X509_POLICY_LEVEL_st */
            	257, 0,
            	45, 8,
            	227, 16,
            1, 8, 1, /* 257: pointer.struct.x509_st */
            	262, 0,
            0, 184, 12, /* 262: struct.x509_st */
            	289, 0,
            	155, 8,
            	126, 16,
            	67, 32,
            	1025, 40,
            	126, 104,
            	1030, 112,
            	1044, 120,
            	45, 128,
            	45, 136,
            	1056, 144,
            	1068, 176,
            1, 8, 1, /* 289: pointer.struct.x509_cinf_st */
            	294, 0,
            0, 104, 11, /* 294: struct.x509_cinf_st */
            	126, 0,
            	126, 8,
            	155, 16,
            	90, 24,
            	319, 32,
            	90, 40,
            	331, 48,
            	126, 56,
            	126, 64,
            	45, 72,
            	196, 80,
            1, 8, 1, /* 319: pointer.struct.X509_val_st */
            	324, 0,
            0, 16, 2, /* 324: struct.X509_val_st */
            	126, 0,
            	126, 8,
            1, 8, 1, /* 331: pointer.struct.X509_pubkey_st */
            	336, 0,
            0, 24, 3, /* 336: struct.X509_pubkey_st */
            	155, 0,
            	126, 8,
            	345, 16,
            1, 8, 1, /* 345: pointer.struct.evp_pkey_st */
            	350, 0,
            0, 56, 4, /* 350: struct.evp_pkey_st */
            	361, 16,
            	529, 24,
            	191, 32,
            	45, 48,
            1, 8, 1, /* 361: pointer.struct.evp_pkey_asn1_method_st */
            	366, 0,
            0, 208, 24, /* 366: struct.evp_pkey_asn1_method_st */
            	67, 16,
            	67, 24,
            	417, 32,
            	425, 40,
            	433, 48,
            	441, 56,
            	449, 64,
            	457, 72,
            	441, 80,
            	465, 88,
            	465, 96,
            	473, 104,
            	481, 112,
            	465, 120,
            	433, 128,
            	433, 136,
            	441, 144,
            	489, 152,
            	497, 160,
            	505, 168,
            	473, 176,
            	481, 184,
            	513, 192,
            	521, 200,
            1, 8, 1, /* 417: pointer.struct.unnamed */
            	422, 0,
            0, 0, 0, /* 422: struct.unnamed */
            1, 8, 1, /* 425: pointer.func */
            	430, 0,
            0, 0, 0, /* 430: func */
            1, 8, 1, /* 433: pointer.func */
            	438, 0,
            0, 0, 0, /* 438: func */
            1, 8, 1, /* 441: pointer.func */
            	446, 0,
            0, 0, 0, /* 446: func */
            1, 8, 1, /* 449: pointer.func */
            	454, 0,
            0, 0, 0, /* 454: func */
            1, 8, 1, /* 457: pointer.func */
            	462, 0,
            0, 0, 0, /* 462: func */
            1, 8, 1, /* 465: pointer.func */
            	470, 0,
            0, 0, 0, /* 470: func */
            1, 8, 1, /* 473: pointer.func */
            	478, 0,
            0, 0, 0, /* 478: func */
            1, 8, 1, /* 481: pointer.func */
            	486, 0,
            0, 0, 0, /* 486: func */
            1, 8, 1, /* 489: pointer.func */
            	494, 0,
            0, 0, 0, /* 494: func */
            1, 8, 1, /* 497: pointer.func */
            	502, 0,
            0, 0, 0, /* 502: func */
            1, 8, 1, /* 505: pointer.func */
            	510, 0,
            0, 0, 0, /* 510: func */
            1, 8, 1, /* 513: pointer.func */
            	518, 0,
            0, 0, 0, /* 518: func */
            1, 8, 1, /* 521: pointer.func */
            	526, 0,
            0, 0, 0, /* 526: func */
            1, 8, 1, /* 529: pointer.struct.engine_st */
            	534, 0,
            0, 216, 24, /* 534: struct.engine_st */
            	67, 0,
            	67, 8,
            	585, 16,
            	675, 24,
            	761, 32,
            	817, 40,
            	839, 48,
            	881, 56,
            	941, 64,
            	949, 72,
            	957, 80,
            	965, 88,
            	973, 96,
            	981, 104,
            	981, 112,
            	981, 120,
            	989, 128,
            	997, 136,
            	997, 144,
            	1005, 152,
            	1013, 160,
            	1025, 184,
            	529, 200,
            	529, 208,
            1, 8, 1, /* 585: pointer.struct.rsa_meth_st */
            	590, 0,
            0, 112, 13, /* 590: struct.rsa_meth_st */
            	67, 0,
            	619, 8,
            	619, 16,
            	619, 24,
            	619, 32,
            	627, 40,
            	635, 48,
            	643, 56,
            	643, 64,
            	67, 80,
            	651, 88,
            	659, 96,
            	667, 104,
            1, 8, 1, /* 619: pointer.func */
            	624, 0,
            0, 0, 0, /* 624: func */
            1, 8, 1, /* 627: pointer.func */
            	632, 0,
            0, 0, 0, /* 632: func */
            1, 8, 1, /* 635: pointer.func */
            	640, 0,
            0, 0, 0, /* 640: func */
            1, 8, 1, /* 643: pointer.func */
            	648, 0,
            0, 0, 0, /* 648: func */
            1, 8, 1, /* 651: pointer.func */
            	656, 0,
            0, 0, 0, /* 656: func */
            1, 8, 1, /* 659: pointer.func */
            	664, 0,
            0, 0, 0, /* 664: func */
            1, 8, 1, /* 667: pointer.func */
            	672, 0,
            0, 0, 0, /* 672: func */
            1, 8, 1, /* 675: pointer.struct.dsa_method.1040 */
            	680, 0,
            0, 96, 11, /* 680: struct.dsa_method.1040 */
            	67, 0,
            	705, 8,
            	713, 16,
            	721, 24,
            	729, 32,
            	737, 40,
            	745, 48,
            	745, 56,
            	67, 72,
            	753, 80,
            	745, 88,
            1, 8, 1, /* 705: pointer.func */
            	710, 0,
            0, 0, 0, /* 710: func */
            1, 8, 1, /* 713: pointer.func */
            	718, 0,
            0, 0, 0, /* 718: func */
            1, 8, 1, /* 721: pointer.func */
            	726, 0,
            0, 0, 0, /* 726: func */
            1, 8, 1, /* 729: pointer.func */
            	734, 0,
            0, 0, 0, /* 734: func */
            1, 8, 1, /* 737: pointer.func */
            	742, 0,
            0, 0, 0, /* 742: func */
            1, 8, 1, /* 745: pointer.func */
            	750, 0,
            0, 0, 0, /* 750: func */
            1, 8, 1, /* 753: pointer.func */
            	758, 0,
            0, 0, 0, /* 758: func */
            1, 8, 1, /* 761: pointer.struct.dh_method */
            	766, 0,
            0, 72, 8, /* 766: struct.dh_method */
            	67, 0,
            	785, 8,
            	793, 16,
            	801, 24,
            	785, 32,
            	785, 40,
            	67, 56,
            	809, 64,
            1, 8, 1, /* 785: pointer.func */
            	790, 0,
            0, 0, 0, /* 790: func */
            1, 8, 1, /* 793: pointer.func */
            	798, 0,
            0, 0, 0, /* 798: func */
            1, 8, 1, /* 801: pointer.func */
            	806, 0,
            0, 0, 0, /* 806: func */
            1, 8, 1, /* 809: pointer.func */
            	814, 0,
            0, 0, 0, /* 814: func */
            1, 8, 1, /* 817: pointer.struct.ecdh_method */
            	822, 0,
            0, 32, 3, /* 822: struct.ecdh_method */
            	67, 0,
            	831, 8,
            	67, 24,
            1, 8, 1, /* 831: pointer.func */
            	836, 0,
            0, 0, 0, /* 836: func */
            1, 8, 1, /* 839: pointer.struct.ecdsa_method */
            	844, 0,
            0, 48, 5, /* 844: struct.ecdsa_method */
            	67, 0,
            	857, 8,
            	865, 16,
            	873, 24,
            	67, 40,
            1, 8, 1, /* 857: pointer.func */
            	862, 0,
            0, 0, 0, /* 862: func */
            1, 8, 1, /* 865: pointer.func */
            	870, 0,
            0, 0, 0, /* 870: func */
            1, 8, 1, /* 873: pointer.func */
            	878, 0,
            0, 0, 0, /* 878: func */
            1, 8, 1, /* 881: pointer.struct.rand_meth_st */
            	886, 0,
            0, 48, 6, /* 886: struct.rand_meth_st */
            	901, 0,
            	909, 8,
            	917, 16,
            	925, 24,
            	909, 32,
            	933, 40,
            1, 8, 1, /* 901: pointer.func */
            	906, 0,
            0, 0, 0, /* 906: func */
            1, 8, 1, /* 909: pointer.func */
            	914, 0,
            0, 0, 0, /* 914: func */
            1, 8, 1, /* 917: pointer.func */
            	922, 0,
            0, 0, 0, /* 922: func */
            1, 8, 1, /* 925: pointer.func */
            	930, 0,
            0, 0, 0, /* 930: func */
            1, 8, 1, /* 933: pointer.func */
            	938, 0,
            0, 0, 0, /* 938: func */
            1, 8, 1, /* 941: pointer.struct.store_method_st */
            	946, 0,
            0, 0, 0, /* 946: struct.store_method_st */
            1, 8, 1, /* 949: pointer.func */
            	954, 0,
            0, 0, 0, /* 954: func */
            1, 8, 1, /* 957: pointer.func */
            	962, 0,
            0, 0, 0, /* 962: func */
            1, 8, 1, /* 965: pointer.func */
            	970, 0,
            0, 0, 0, /* 970: func */
            1, 8, 1, /* 973: pointer.func */
            	978, 0,
            0, 0, 0, /* 978: func */
            1, 8, 1, /* 981: pointer.func */
            	986, 0,
            0, 0, 0, /* 986: func */
            1, 8, 1, /* 989: pointer.func */
            	994, 0,
            0, 0, 0, /* 994: func */
            1, 8, 1, /* 997: pointer.func */
            	1002, 0,
            0, 0, 0, /* 1002: func */
            1, 8, 1, /* 1005: pointer.func */
            	1010, 0,
            0, 0, 0, /* 1010: func */
            1, 8, 1, /* 1013: pointer.struct.ENGINE_CMD_DEFN_st */
            	1018, 0,
            0, 32, 2, /* 1018: struct.ENGINE_CMD_DEFN_st */
            	67, 8,
            	67, 16,
            0, 16, 1, /* 1025: struct.crypto_ex_data_st */
            	45, 0,
            1, 8, 1, /* 1030: pointer.struct.AUTHORITY_KEYID_st */
            	1035, 0,
            0, 24, 3, /* 1035: struct.AUTHORITY_KEYID_st */
            	126, 0,
            	45, 8,
            	126, 16,
            1, 8, 1, /* 1044: pointer.struct.X509_POLICY_CACHE_st */
            	1049, 0,
            0, 40, 2, /* 1049: struct.X509_POLICY_CACHE_st */
            	213, 0,
            	45, 8,
            1, 8, 1, /* 1056: pointer.struct.NAME_CONSTRAINTS_st */
            	1061, 0,
            0, 16, 2, /* 1061: struct.NAME_CONSTRAINTS_st */
            	45, 0,
            	45, 8,
            1, 8, 1, /* 1068: pointer.struct.x509_cert_aux_st */
            	1073, 0,
            0, 40, 5, /* 1073: struct.x509_cert_aux_st */
            	45, 0,
            	45, 8,
            	126, 16,
            	126, 24,
            	45, 32,
            1, 8, 1, /* 1086: pointer.struct.X509_POLICY_TREE_st */
            	232, 0,
            0, 0, 0, /* 1091: func */
            1, 8, 1, /* 1094: pointer.func */
            	1099, 0,
            0, 0, 0, /* 1099: func */
            0, 0, 0, /* 1102: func */
            0, 56, 2, /* 1105: struct.X509_VERIFY_PARAM_st */
            	67, 0,
            	45, 48,
            1, 8, 1, /* 1112: pointer.struct.X509_VERIFY_PARAM_st */
            	1105, 0,
            0, 144, 15, /* 1117: struct.x509_store_st */
            	45, 8,
            	45, 16,
            	1112, 24,
            	1150, 32,
            	1158, 40,
            	1094, 48,
            	1163, 56,
            	1150, 64,
            	1168, 72,
            	1176, 80,
            	1184, 88,
            	1192, 96,
            	1192, 104,
            	1150, 112,
            	1025, 120,
            1, 8, 1, /* 1150: pointer.func */
            	1155, 0,
            0, 0, 0, /* 1155: func */
            1, 8, 1, /* 1158: pointer.func */
            	1102, 0,
            1, 8, 1, /* 1163: pointer.func */
            	1091, 0,
            1, 8, 1, /* 1168: pointer.func */
            	1173, 0,
            0, 0, 0, /* 1173: func */
            1, 8, 1, /* 1176: pointer.func */
            	1181, 0,
            0, 0, 0, /* 1181: func */
            1, 8, 1, /* 1184: pointer.func */
            	1189, 0,
            0, 0, 0, /* 1189: func */
            1, 8, 1, /* 1192: pointer.func */
            	1197, 0,
            0, 0, 0, /* 1197: func */
            1, 8, 1, /* 1200: pointer.struct.x509_store_st */
            	1117, 0,
            0, 248, 25, /* 1205: struct.x509_store_ctx_st */
            	1200, 0,
            	257, 16,
            	45, 24,
            	45, 32,
            	1112, 40,
            	67, 48,
            	417, 56,
            	1158, 64,
            	1094, 72,
            	1163, 80,
            	417, 88,
            	1168, 96,
            	1176, 104,
            	1184, 112,
            	417, 120,
            	1192, 128,
            	1192, 136,
            	417, 144,
            	45, 160,
            	1086, 168,
            	257, 192,
            	257, 200,
            	1258, 208,
            	1291, 224,
            	1025, 232,
            1, 8, 1, /* 1258: pointer.struct.X509_crl_st */
            	1263, 0,
            0, 120, 10, /* 1263: struct.X509_crl_st */
            	201, 0,
            	155, 8,
            	126, 16,
            	1030, 32,
            	1286, 40,
            	126, 56,
            	126, 64,
            	45, 96,
            	6, 104,
            	67, 112,
            1, 8, 1, /* 1286: pointer.struct.ISSUING_DIST_POINT_st */
            	119, 0,
            1, 8, 1, /* 1291: pointer.struct.x509_store_ctx_st */
            	1205, 0,
            0, 20, 0, /* 1296: array[20].char */
            0, 8, 0, /* 1299: long */
            0, 4, 0, /* 1302: int */
            1, 8, 1, /* 1305: pointer.pointer.struct.x509_st */
            	257, 0,
        },
        .arg_entity_index = { 1305, 1291, 257, },
        .ret_entity_index = 1302,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    X509 ** new_arg_a = *((X509 ** *)new_args->args[0]);

    X509_STORE_CTX * new_arg_b = *((X509_STORE_CTX * *)new_args->args[1]);

    X509 * new_arg_c = *((X509 * *)new_args->args[2]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_X509_STORE_CTX_get1_issuer)(X509 **,X509_STORE_CTX *,X509 *);
    orig_X509_STORE_CTX_get1_issuer = dlsym(RTLD_NEXT, "X509_STORE_CTX_get1_issuer");
    *new_ret_ptr = (*orig_X509_STORE_CTX_get1_issuer)(new_arg_a,new_arg_b,new_arg_c);

    syscall(889);

    return ret;
}

