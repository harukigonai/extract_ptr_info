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

int bb_X509_STORE_CTX_get1_issuer(X509 ** arg_a,X509_STORE_CTX * arg_b,X509 * arg_c);

int X509_STORE_CTX_get1_issuer(X509 ** arg_a,X509_STORE_CTX * arg_b,X509 * arg_c) 
{
    unsigned long in_lib = syscall(890);
    printf("X509_STORE_CTX_get1_issuer called %lu\n", in_lib);
    if (!in_lib)
        return bb_X509_STORE_CTX_get1_issuer(arg_a,arg_b,arg_c);
    else {
        int (*orig_X509_STORE_CTX_get1_issuer)(X509 **,X509_STORE_CTX *,X509 *);
        orig_X509_STORE_CTX_get1_issuer = dlsym(RTLD_NEXT, "X509_STORE_CTX_get1_issuer");
        return orig_X509_STORE_CTX_get1_issuer(arg_a,arg_b,arg_c);
    }
}

int bb_X509_STORE_CTX_get1_issuer(X509 ** arg_a,X509_STORE_CTX * arg_b,X509 * arg_c) 
{
    int ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 0, 0, /* 0: func */
            0, 0, 0, /* 3: func */
            4097, 8, 0, /* 6: pointer.func */
            0, 0, 0, /* 9: func */
            4097, 8, 0, /* 12: pointer.func */
            0, 40, 4, /* 15: struct.x509_crl_method_st */
            	12, 8,
            	12, 16,
            	6, 24,
            	26, 32,
            4097, 8, 0, /* 26: pointer.func */
            0, 8, 1, /* 29: union.anon.1.3127 */
            	34, 0,
            0, 8, 1, /* 34: pointer.struct.stack_st_OPENSSL_STRING */
            	39, 0,
            0, 32, 1, /* 39: struct.stack_st_OPENSSL_STRING */
            	44, 0,
            0, 32, 2, /* 44: struct.stack_st */
            	51, 8,
            	61, 24,
            0, 8, 1, /* 51: pointer.pointer.char */
            	56, 0,
            0, 8, 1, /* 56: pointer.char */
            	4096, 0,
            4097, 8, 0, /* 61: pointer.func */
            0, 32, 2, /* 64: struct.ISSUING_DIST_POINT_st */
            	71, 0,
            	107, 16,
            0, 8, 1, /* 71: pointer.struct.DIST_POINT_NAME_st */
            	76, 0,
            0, 24, 2, /* 76: struct.DIST_POINT_NAME_st */
            	29, 8,
            	83, 16,
            0, 8, 1, /* 83: pointer.struct.X509_name_st */
            	88, 0,
            0, 40, 3, /* 88: struct.X509_name_st */
            	34, 0,
            	97, 16,
            	56, 24,
            0, 8, 1, /* 97: pointer.struct.buf_mem_st */
            	102, 0,
            0, 24, 1, /* 102: struct.buf_mem_st */
            	56, 8,
            0, 8, 1, /* 107: pointer.struct.asn1_string_st */
            	112, 0,
            0, 24, 1, /* 112: struct.asn1_string_st */
            	56, 8,
            0, 8, 1, /* 117: pointer.struct.X509_crl_info_st */
            	122, 0,
            0, 80, 8, /* 122: struct.X509_crl_info_st */
            	107, 0,
            	141, 8,
            	83, 16,
            	107, 24,
            	107, 32,
            	34, 40,
            	34, 48,
            	182, 56,
            0, 8, 1, /* 141: pointer.struct.X509_algor_st */
            	146, 0,
            0, 16, 2, /* 146: struct.X509_algor_st */
            	153, 0,
            	167, 8,
            0, 8, 1, /* 153: pointer.struct.asn1_object_st */
            	158, 0,
            0, 40, 3, /* 158: struct.asn1_object_st */
            	56, 0,
            	56, 8,
            	56, 24,
            0, 8, 1, /* 167: pointer.struct.asn1_type_st */
            	172, 0,
            0, 16, 1, /* 172: struct.asn1_type_st */
            	177, 8,
            0, 8, 1, /* 177: struct.fnames */
            	56, 0,
            0, 24, 1, /* 182: struct.ASN1_ENCODING_st */
            	56, 0,
            0, 8, 1, /* 187: pointer.struct.ISSUING_DIST_POINT_st */
            	64, 0,
            0, 8, 1, /* 192: pointer.struct.X509_POLICY_NODE_st */
            	197, 0,
            0, 24, 2, /* 197: struct.X509_POLICY_NODE_st */
            	204, 0,
            	192, 8,
            0, 8, 1, /* 204: pointer.struct.X509_POLICY_DATA_st */
            	209, 0,
            0, 32, 3, /* 209: struct.X509_POLICY_DATA_st */
            	153, 8,
            	34, 16,
            	34, 24,
            0, 8, 1, /* 218: pointer.struct.X509_POLICY_LEVEL_st */
            	223, 0,
            0, 32, 3, /* 223: struct.X509_POLICY_LEVEL_st */
            	232, 0,
            	34, 8,
            	192, 16,
            0, 8, 1, /* 232: pointer.struct.x509_st */
            	237, 0,
            0, 184, 12, /* 237: struct.x509_st */
            	264, 0,
            	141, 8,
            	107, 16,
            	56, 32,
            	760, 40,
            	107, 104,
            	765, 112,
            	779, 120,
            	34, 128,
            	34, 136,
            	791, 144,
            	803, 176,
            0, 8, 1, /* 264: pointer.struct.x509_cinf_st */
            	269, 0,
            0, 104, 11, /* 269: struct.x509_cinf_st */
            	107, 0,
            	107, 8,
            	141, 16,
            	83, 24,
            	294, 32,
            	83, 40,
            	306, 48,
            	107, 56,
            	107, 64,
            	34, 72,
            	182, 80,
            0, 8, 1, /* 294: pointer.struct.X509_val_st */
            	299, 0,
            0, 16, 2, /* 299: struct.X509_val_st */
            	107, 0,
            	107, 8,
            0, 8, 1, /* 306: pointer.struct.X509_pubkey_st */
            	311, 0,
            0, 24, 3, /* 311: struct.X509_pubkey_st */
            	141, 0,
            	107, 8,
            	320, 16,
            0, 8, 1, /* 320: pointer.struct.evp_pkey_st */
            	325, 0,
            0, 56, 4, /* 325: struct.evp_pkey_st */
            	336, 16,
            	439, 24,
            	177, 32,
            	34, 48,
            0, 8, 1, /* 336: pointer.struct.evp_pkey_asn1_method_st */
            	341, 0,
            0, 208, 24, /* 341: struct.evp_pkey_asn1_method_st */
            	56, 16,
            	56, 24,
            	392, 32,
            	400, 40,
            	403, 48,
            	406, 56,
            	409, 64,
            	412, 72,
            	406, 80,
            	415, 88,
            	415, 96,
            	418, 104,
            	421, 112,
            	415, 120,
            	403, 128,
            	403, 136,
            	406, 144,
            	424, 152,
            	427, 160,
            	430, 168,
            	418, 176,
            	421, 184,
            	433, 192,
            	436, 200,
            0, 8, 1, /* 392: pointer.struct.unnamed */
            	397, 0,
            0, 0, 0, /* 397: struct.unnamed */
            4097, 8, 0, /* 400: pointer.func */
            4097, 8, 0, /* 403: pointer.func */
            4097, 8, 0, /* 406: pointer.func */
            4097, 8, 0, /* 409: pointer.func */
            4097, 8, 0, /* 412: pointer.func */
            4097, 8, 0, /* 415: pointer.func */
            4097, 8, 0, /* 418: pointer.func */
            4097, 8, 0, /* 421: pointer.func */
            4097, 8, 0, /* 424: pointer.func */
            4097, 8, 0, /* 427: pointer.func */
            4097, 8, 0, /* 430: pointer.func */
            4097, 8, 0, /* 433: pointer.func */
            4097, 8, 0, /* 436: pointer.func */
            0, 8, 1, /* 439: pointer.struct.engine_st */
            	444, 0,
            0, 216, 24, /* 444: struct.engine_st */
            	56, 0,
            	56, 8,
            	495, 16,
            	550, 24,
            	601, 32,
            	637, 40,
            	654, 48,
            	681, 56,
            	716, 64,
            	724, 72,
            	727, 80,
            	730, 88,
            	733, 96,
            	736, 104,
            	736, 112,
            	736, 120,
            	739, 128,
            	742, 136,
            	742, 144,
            	745, 152,
            	748, 160,
            	760, 184,
            	439, 200,
            	439, 208,
            0, 8, 1, /* 495: pointer.struct.rsa_meth_st */
            	500, 0,
            0, 112, 13, /* 500: struct.rsa_meth_st */
            	56, 0,
            	529, 8,
            	529, 16,
            	529, 24,
            	529, 32,
            	532, 40,
            	535, 48,
            	538, 56,
            	538, 64,
            	56, 80,
            	541, 88,
            	544, 96,
            	547, 104,
            4097, 8, 0, /* 529: pointer.func */
            4097, 8, 0, /* 532: pointer.func */
            4097, 8, 0, /* 535: pointer.func */
            4097, 8, 0, /* 538: pointer.func */
            4097, 8, 0, /* 541: pointer.func */
            4097, 8, 0, /* 544: pointer.func */
            4097, 8, 0, /* 547: pointer.func */
            0, 8, 1, /* 550: pointer.struct.dsa_method */
            	555, 0,
            0, 96, 11, /* 555: struct.dsa_method */
            	56, 0,
            	580, 8,
            	583, 16,
            	586, 24,
            	589, 32,
            	592, 40,
            	595, 48,
            	595, 56,
            	56, 72,
            	598, 80,
            	595, 88,
            4097, 8, 0, /* 580: pointer.func */
            4097, 8, 0, /* 583: pointer.func */
            4097, 8, 0, /* 586: pointer.func */
            4097, 8, 0, /* 589: pointer.func */
            4097, 8, 0, /* 592: pointer.func */
            4097, 8, 0, /* 595: pointer.func */
            4097, 8, 0, /* 598: pointer.func */
            0, 8, 1, /* 601: pointer.struct.dh_method */
            	606, 0,
            0, 72, 8, /* 606: struct.dh_method */
            	56, 0,
            	625, 8,
            	628, 16,
            	631, 24,
            	625, 32,
            	625, 40,
            	56, 56,
            	634, 64,
            4097, 8, 0, /* 625: pointer.func */
            4097, 8, 0, /* 628: pointer.func */
            4097, 8, 0, /* 631: pointer.func */
            4097, 8, 0, /* 634: pointer.func */
            0, 8, 1, /* 637: pointer.struct.ecdh_method */
            	642, 0,
            0, 32, 3, /* 642: struct.ecdh_method */
            	56, 0,
            	651, 8,
            	56, 24,
            4097, 8, 0, /* 651: pointer.func */
            0, 8, 1, /* 654: pointer.struct.ecdsa_method */
            	659, 0,
            0, 48, 5, /* 659: struct.ecdsa_method */
            	56, 0,
            	672, 8,
            	675, 16,
            	678, 24,
            	56, 40,
            4097, 8, 0, /* 672: pointer.func */
            4097, 8, 0, /* 675: pointer.func */
            4097, 8, 0, /* 678: pointer.func */
            0, 8, 1, /* 681: pointer.struct.rand_meth_st */
            	686, 0,
            0, 48, 6, /* 686: struct.rand_meth_st */
            	701, 0,
            	704, 8,
            	707, 16,
            	710, 24,
            	704, 32,
            	713, 40,
            4097, 8, 0, /* 701: pointer.func */
            4097, 8, 0, /* 704: pointer.func */
            4097, 8, 0, /* 707: pointer.func */
            4097, 8, 0, /* 710: pointer.func */
            4097, 8, 0, /* 713: pointer.func */
            0, 8, 1, /* 716: pointer.struct.store_method_st */
            	721, 0,
            0, 0, 0, /* 721: struct.store_method_st */
            4097, 8, 0, /* 724: pointer.func */
            4097, 8, 0, /* 727: pointer.func */
            4097, 8, 0, /* 730: pointer.func */
            4097, 8, 0, /* 733: pointer.func */
            4097, 8, 0, /* 736: pointer.func */
            4097, 8, 0, /* 739: pointer.func */
            4097, 8, 0, /* 742: pointer.func */
            4097, 8, 0, /* 745: pointer.func */
            0, 8, 1, /* 748: pointer.struct.ENGINE_CMD_DEFN_st */
            	753, 0,
            0, 32, 2, /* 753: struct.ENGINE_CMD_DEFN_st */
            	56, 8,
            	56, 16,
            0, 16, 1, /* 760: struct.crypto_ex_data_st */
            	34, 0,
            0, 8, 1, /* 765: pointer.struct.AUTHORITY_KEYID_st */
            	770, 0,
            0, 24, 3, /* 770: struct.AUTHORITY_KEYID_st */
            	107, 0,
            	34, 8,
            	107, 16,
            0, 8, 1, /* 779: pointer.struct.X509_POLICY_CACHE_st */
            	784, 0,
            0, 40, 2, /* 784: struct.X509_POLICY_CACHE_st */
            	204, 0,
            	34, 8,
            0, 8, 1, /* 791: pointer.struct.NAME_CONSTRAINTS_st */
            	796, 0,
            0, 16, 2, /* 796: struct.NAME_CONSTRAINTS_st */
            	34, 0,
            	34, 8,
            0, 8, 1, /* 803: pointer.struct.x509_cert_aux_st */
            	808, 0,
            0, 40, 5, /* 808: struct.x509_cert_aux_st */
            	34, 0,
            	34, 8,
            	107, 16,
            	107, 24,
            	34, 32,
            0, 8, 1, /* 821: pointer.struct.X509_POLICY_TREE_st */
            	826, 0,
            0, 48, 4, /* 826: struct.X509_POLICY_TREE_st */
            	218, 0,
            	34, 16,
            	34, 24,
            	34, 32,
            0, 0, 0, /* 837: func */
            4097, 8, 0, /* 840: pointer.func */
            4097, 8, 0, /* 843: pointer.func */
            0, 0, 0, /* 846: func */
            0, 0, 0, /* 849: func */
            0, 56, 2, /* 852: struct.X509_VERIFY_PARAM_st */
            	56, 0,
            	34, 48,
            0, 0, 0, /* 859: func */
            0, 8, 1, /* 862: pointer.struct.X509_VERIFY_PARAM_st */
            	852, 0,
            0, 20, 0, /* 867: array[20].char */
            0, 144, 15, /* 870: struct.x509_store_st */
            	34, 8,
            	34, 16,
            	862, 24,
            	903, 32,
            	906, 40,
            	843, 48,
            	909, 56,
            	903, 64,
            	912, 72,
            	840, 80,
            	915, 88,
            	918, 96,
            	918, 104,
            	903, 112,
            	760, 120,
            4097, 8, 0, /* 903: pointer.func */
            4097, 8, 0, /* 906: pointer.func */
            4097, 8, 0, /* 909: pointer.func */
            4097, 8, 0, /* 912: pointer.func */
            4097, 8, 0, /* 915: pointer.func */
            4097, 8, 0, /* 918: pointer.func */
            0, 0, 0, /* 921: func */
            0, 0, 0, /* 924: func */
            0, 0, 0, /* 927: func */
            0, 0, 0, /* 930: func */
            0, 0, 0, /* 933: func */
            0, 0, 0, /* 936: func */
            0, 0, 0, /* 939: func */
            0, 0, 0, /* 942: func */
            0, 0, 0, /* 945: func */
            0, 0, 0, /* 948: func */
            0, 0, 0, /* 951: func */
            0, 0, 0, /* 954: func */
            0, 0, 0, /* 957: func */
            0, 0, 0, /* 960: func */
            0, 0, 0, /* 963: func */
            0, 8, 0, /* 966: pointer.void */
            0, 0, 0, /* 969: func */
            0, 0, 0, /* 972: func */
            0, 8, 0, /* 975: long */
            0, 8, 1, /* 978: pointer.struct.X509_crl_st */
            	983, 0,
            0, 120, 10, /* 983: struct.X509_crl_st */
            	117, 0,
            	141, 8,
            	107, 16,
            	765, 32,
            	187, 40,
            	107, 56,
            	107, 64,
            	34, 96,
            	1006, 104,
            	966, 112,
            0, 8, 1, /* 1006: pointer.struct.x509_crl_method_st */
            	15, 0,
            0, 0, 0, /* 1011: func */
            0, 0, 0, /* 1014: func */
            0, 1, 0, /* 1017: char */
            0, 8, 1, /* 1020: pointer.pointer.struct.x509_st */
            	232, 0,
            0, 0, 0, /* 1025: func */
            0, 0, 0, /* 1028: func */
            0, 0, 0, /* 1031: func */
            0, 0, 0, /* 1034: func */
            0, 0, 0, /* 1037: func */
            0, 0, 0, /* 1040: func */
            0, 0, 0, /* 1043: func */
            0, 4, 0, /* 1046: int */
            0, 0, 0, /* 1049: func */
            0, 0, 0, /* 1052: func */
            0, 0, 0, /* 1055: func */
            0, 0, 0, /* 1058: func */
            0, 0, 0, /* 1061: func */
            0, 0, 0, /* 1064: func */
            0, 0, 0, /* 1067: func */
            0, 0, 0, /* 1070: func */
            0, 8, 1, /* 1073: pointer.struct.x509_store_st */
            	870, 0,
            0, 0, 0, /* 1078: func */
            0, 0, 0, /* 1081: func */
            0, 0, 0, /* 1084: func */
            0, 0, 0, /* 1087: func */
            0, 0, 0, /* 1090: func */
            0, 0, 0, /* 1093: func */
            0, 8, 1, /* 1096: pointer.struct.x509_store_ctx_st */
            	1101, 0,
            0, 248, 25, /* 1101: struct.x509_store_ctx_st */
            	1073, 0,
            	232, 16,
            	34, 24,
            	34, 32,
            	862, 40,
            	966, 48,
            	392, 56,
            	906, 64,
            	843, 72,
            	909, 80,
            	392, 88,
            	912, 96,
            	840, 104,
            	915, 112,
            	392, 120,
            	918, 128,
            	918, 136,
            	392, 144,
            	34, 160,
            	821, 168,
            	232, 192,
            	232, 200,
            	978, 208,
            	1096, 224,
            	760, 232,
            0, 0, 0, /* 1154: func */
            0, 0, 0, /* 1157: func */
            0, 0, 0, /* 1160: func */
            0, 0, 0, /* 1163: func */
            0, 0, 0, /* 1166: func */
            0, 0, 0, /* 1169: func */
            0, 0, 0, /* 1172: func */
            0, 0, 0, /* 1175: func */
            0, 0, 0, /* 1178: func */
            0, 0, 0, /* 1181: func */
            0, 0, 0, /* 1184: func */
            0, 0, 0, /* 1187: func */
            0, 0, 0, /* 1190: func */
        },
        .arg_entity_index = { 1020, 1096, 232, },
        .ret_entity_index = 1046,
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

