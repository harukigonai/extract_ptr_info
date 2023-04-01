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
            4097, 8, 0, /* 0: pointer.func */
            4097, 8, 0, /* 3: pointer.func */
            0, 0, 0, /* 6: func */
            0, 8, 1, /* 9: union.anon.1.3070 */
            	14, 0,
            1, 8, 1, /* 14: pointer.struct.stack_st_OPENSSL_STRING */
            	19, 0,
            0, 32, 1, /* 19: struct.stack_st_OPENSSL_STRING */
            	24, 0,
            0, 32, 1, /* 24: struct.stack_st */
            	29, 8,
            1, 8, 1, /* 29: pointer.pointer.char */
            	34, 0,
            1, 8, 1, /* 34: pointer.char */
            	4096, 0,
            0, 24, 2, /* 39: struct.DIST_POINT_NAME_st */
            	9, 8,
            	46, 16,
            1, 8, 1, /* 46: pointer.struct.X509_name_st */
            	51, 0,
            0, 40, 3, /* 51: struct.X509_name_st */
            	14, 0,
            	60, 16,
            	34, 24,
            1, 8, 1, /* 60: pointer.struct.buf_mem_st */
            	65, 0,
            0, 24, 1, /* 65: struct.buf_mem_st */
            	34, 8,
            1, 8, 1, /* 70: pointer.struct.ISSUING_DIST_POINT_st */
            	75, 0,
            0, 32, 2, /* 75: struct.ISSUING_DIST_POINT_st */
            	82, 0,
            	87, 16,
            1, 8, 1, /* 82: pointer.struct.DIST_POINT_NAME_st */
            	39, 0,
            1, 8, 1, /* 87: pointer.struct.asn1_string_st */
            	92, 0,
            0, 24, 1, /* 92: struct.asn1_string_st */
            	34, 8,
            0, 80, 8, /* 97: struct.X509_crl_info_st */
            	87, 0,
            	116, 8,
            	46, 16,
            	87, 24,
            	87, 32,
            	14, 40,
            	14, 48,
            	157, 56,
            1, 8, 1, /* 116: pointer.struct.X509_algor_st */
            	121, 0,
            0, 16, 2, /* 121: struct.X509_algor_st */
            	128, 0,
            	142, 8,
            1, 8, 1, /* 128: pointer.struct.asn1_object_st */
            	133, 0,
            0, 40, 3, /* 133: struct.asn1_object_st */
            	34, 0,
            	34, 8,
            	34, 24,
            1, 8, 1, /* 142: pointer.struct.asn1_type_st */
            	147, 0,
            0, 16, 1, /* 147: struct.asn1_type_st */
            	152, 8,
            0, 8, 1, /* 152: struct.fnames */
            	34, 0,
            0, 24, 1, /* 157: struct.ASN1_ENCODING_st */
            	34, 0,
            1, 8, 1, /* 162: pointer.struct.X509_crl_info_st */
            	97, 0,
            0, 120, 10, /* 167: struct.X509_crl_st */
            	162, 0,
            	116, 8,
            	87, 16,
            	190, 32,
            	70, 40,
            	87, 56,
            	87, 64,
            	14, 96,
            	204, 104,
            	34, 112,
            1, 8, 1, /* 190: pointer.struct.AUTHORITY_KEYID_st */
            	195, 0,
            0, 24, 3, /* 195: struct.AUTHORITY_KEYID_st */
            	87, 0,
            	14, 8,
            	87, 16,
            1, 8, 1, /* 204: pointer.struct.x509_crl_method_st */
            	209, 0,
            0, 40, 0, /* 209: struct.x509_crl_method_st */
            0, 24, 2, /* 212: struct.X509_POLICY_NODE_st */
            	219, 0,
            	233, 8,
            1, 8, 1, /* 219: pointer.struct.X509_POLICY_DATA_st */
            	224, 0,
            0, 32, 3, /* 224: struct.X509_POLICY_DATA_st */
            	128, 8,
            	14, 16,
            	14, 24,
            1, 8, 1, /* 233: pointer.struct.X509_POLICY_NODE_st */
            	212, 0,
            1, 8, 1, /* 238: pointer.struct.X509_POLICY_LEVEL_st */
            	243, 0,
            0, 32, 3, /* 243: struct.X509_POLICY_LEVEL_st */
            	252, 0,
            	14, 8,
            	233, 16,
            1, 8, 1, /* 252: pointer.struct.x509_st */
            	257, 0,
            0, 184, 12, /* 257: struct.x509_st */
            	284, 0,
            	116, 8,
            	87, 16,
            	34, 32,
            	500, 40,
            	87, 104,
            	190, 112,
            	505, 120,
            	14, 128,
            	14, 136,
            	517, 144,
            	529, 176,
            1, 8, 1, /* 284: pointer.struct.x509_cinf_st */
            	289, 0,
            0, 104, 11, /* 289: struct.x509_cinf_st */
            	87, 0,
            	87, 8,
            	116, 16,
            	46, 24,
            	314, 32,
            	46, 40,
            	326, 48,
            	87, 56,
            	87, 64,
            	14, 72,
            	157, 80,
            1, 8, 1, /* 314: pointer.struct.X509_val_st */
            	319, 0,
            0, 16, 2, /* 319: struct.X509_val_st */
            	87, 0,
            	87, 8,
            1, 8, 1, /* 326: pointer.struct.X509_pubkey_st */
            	331, 0,
            0, 24, 3, /* 331: struct.X509_pubkey_st */
            	116, 0,
            	87, 8,
            	340, 16,
            1, 8, 1, /* 340: pointer.struct.evp_pkey_st */
            	345, 0,
            0, 56, 4, /* 345: struct.evp_pkey_st */
            	356, 16,
            	378, 24,
            	152, 32,
            	14, 48,
            1, 8, 1, /* 356: pointer.struct.evp_pkey_asn1_method_st */
            	361, 0,
            0, 208, 3, /* 361: struct.evp_pkey_asn1_method_st */
            	34, 16,
            	34, 24,
            	370, 32,
            1, 8, 1, /* 370: pointer.struct.unnamed */
            	375, 0,
            0, 0, 0, /* 375: struct.unnamed */
            1, 8, 1, /* 378: pointer.struct.engine_st */
            	383, 0,
            0, 216, 13, /* 383: struct.engine_st */
            	34, 0,
            	34, 8,
            	412, 16,
            	424, 24,
            	436, 32,
            	448, 40,
            	460, 48,
            	472, 56,
            	480, 64,
            	488, 160,
            	500, 184,
            	378, 200,
            	378, 208,
            1, 8, 1, /* 412: pointer.struct.rsa_meth_st */
            	417, 0,
            0, 112, 2, /* 417: struct.rsa_meth_st */
            	34, 0,
            	34, 80,
            1, 8, 1, /* 424: pointer.struct.dsa_method.1040 */
            	429, 0,
            0, 96, 2, /* 429: struct.dsa_method.1040 */
            	34, 0,
            	34, 72,
            1, 8, 1, /* 436: pointer.struct.dh_method */
            	441, 0,
            0, 72, 2, /* 441: struct.dh_method */
            	34, 0,
            	34, 56,
            1, 8, 1, /* 448: pointer.struct.ecdh_method */
            	453, 0,
            0, 32, 2, /* 453: struct.ecdh_method */
            	34, 0,
            	34, 24,
            1, 8, 1, /* 460: pointer.struct.ecdsa_method */
            	465, 0,
            0, 48, 2, /* 465: struct.ecdsa_method */
            	34, 0,
            	34, 40,
            1, 8, 1, /* 472: pointer.struct.rand_meth_st */
            	477, 0,
            0, 48, 0, /* 477: struct.rand_meth_st */
            1, 8, 1, /* 480: pointer.struct.store_method_st */
            	485, 0,
            0, 0, 0, /* 485: struct.store_method_st */
            1, 8, 1, /* 488: pointer.struct.ENGINE_CMD_DEFN_st */
            	493, 0,
            0, 32, 2, /* 493: struct.ENGINE_CMD_DEFN_st */
            	34, 8,
            	34, 16,
            0, 16, 1, /* 500: struct.crypto_ex_data_st */
            	14, 0,
            1, 8, 1, /* 505: pointer.struct.X509_POLICY_CACHE_st */
            	510, 0,
            0, 40, 2, /* 510: struct.X509_POLICY_CACHE_st */
            	219, 0,
            	14, 8,
            1, 8, 1, /* 517: pointer.struct.NAME_CONSTRAINTS_st */
            	522, 0,
            0, 16, 2, /* 522: struct.NAME_CONSTRAINTS_st */
            	14, 0,
            	14, 8,
            1, 8, 1, /* 529: pointer.struct.x509_cert_aux_st */
            	534, 0,
            0, 40, 5, /* 534: struct.x509_cert_aux_st */
            	14, 0,
            	14, 8,
            	87, 16,
            	87, 24,
            	14, 32,
            0, 48, 4, /* 547: struct.X509_POLICY_TREE_st */
            	238, 0,
            	14, 16,
            	14, 24,
            	14, 32,
            4097, 8, 0, /* 558: pointer.func */
            0, 0, 0, /* 561: func */
            4097, 8, 0, /* 564: pointer.func */
            0, 0, 0, /* 567: func */
            4097, 8, 0, /* 570: pointer.func */
            0, 56, 2, /* 573: struct.X509_VERIFY_PARAM_st */
            	34, 0,
            	14, 48,
            1, 8, 1, /* 580: pointer.struct.X509_VERIFY_PARAM_st */
            	573, 0,
            0, 144, 4, /* 585: struct.x509_store_st */
            	14, 8,
            	14, 16,
            	580, 24,
            	500, 120,
            1, 8, 1, /* 596: pointer.struct.x509_store_st */
            	585, 0,
            0, 248, 17, /* 601: struct.x509_store_ctx_st */
            	596, 0,
            	252, 16,
            	14, 24,
            	14, 32,
            	580, 40,
            	34, 48,
            	370, 56,
            	370, 88,
            	370, 120,
            	370, 144,
            	14, 160,
            	638, 168,
            	252, 192,
            	252, 200,
            	643, 208,
            	648, 224,
            	500, 232,
            1, 8, 1, /* 638: pointer.struct.X509_POLICY_TREE_st */
            	547, 0,
            1, 8, 1, /* 643: pointer.struct.X509_crl_st */
            	167, 0,
            1, 8, 1, /* 648: pointer.struct.x509_store_ctx_st */
            	601, 0,
            4097, 8, 0, /* 653: pointer.func */
            0, 0, 0, /* 656: func */
            4097, 8, 0, /* 659: pointer.func */
            0, 0, 0, /* 662: func */
            0, 0, 0, /* 665: func */
            0, 0, 0, /* 668: func */
            0, 0, 0, /* 671: func */
            0, 0, 0, /* 674: func */
            4097, 8, 0, /* 677: pointer.func */
            0, 0, 0, /* 680: func */
            4097, 8, 0, /* 683: pointer.func */
            4097, 8, 0, /* 686: pointer.func */
            0, 0, 0, /* 689: func */
            4097, 8, 0, /* 692: pointer.func */
            4097, 8, 0, /* 695: pointer.func */
            0, 20, 0, /* 698: array[20].char */
            4097, 8, 0, /* 701: pointer.func */
            4097, 8, 0, /* 704: pointer.func */
            0, 0, 0, /* 707: func */
            4097, 8, 0, /* 710: pointer.func */
            0, 0, 0, /* 713: func */
            4097, 8, 0, /* 716: pointer.func */
            0, 0, 0, /* 719: func */
            0, 0, 0, /* 722: func */
            4097, 8, 0, /* 725: pointer.func */
            4097, 8, 0, /* 728: pointer.func */
            0, 0, 0, /* 731: func */
            0, 0, 0, /* 734: func */
            0, 0, 0, /* 737: func */
            0, 0, 0, /* 740: func */
            4097, 8, 0, /* 743: pointer.func */
            4097, 8, 0, /* 746: pointer.func */
            0, 0, 0, /* 749: func */
            0, 0, 0, /* 752: func */
            4097, 8, 0, /* 755: pointer.func */
            0, 0, 0, /* 758: func */
            0, 4, 0, /* 761: int */
            4097, 8, 0, /* 764: pointer.func */
            0, 0, 0, /* 767: func */
            0, 8, 0, /* 770: long */
            4097, 8, 0, /* 773: pointer.func */
            4097, 8, 0, /* 776: pointer.func */
            4097, 8, 0, /* 779: pointer.func */
            0, 0, 0, /* 782: func */
            4097, 8, 0, /* 785: pointer.func */
            4097, 8, 0, /* 788: pointer.func */
            0, 0, 0, /* 791: func */
            0, 0, 0, /* 794: func */
            0, 0, 0, /* 797: func */
            1, 8, 1, /* 800: pointer.pointer.struct.x509_st */
            	252, 0,
            4097, 8, 0, /* 805: pointer.func */
            0, 0, 0, /* 808: func */
            4097, 8, 0, /* 811: pointer.func */
            0, 0, 0, /* 814: func */
            0, 0, 0, /* 817: func */
            4097, 8, 0, /* 820: pointer.func */
            4097, 8, 0, /* 823: pointer.func */
            0, 0, 0, /* 826: func */
            4097, 8, 0, /* 829: pointer.func */
            0, 0, 0, /* 832: func */
            0, 0, 0, /* 835: func */
            4097, 8, 0, /* 838: pointer.func */
            0, 0, 0, /* 841: func */
            4097, 8, 0, /* 844: pointer.func */
            4097, 8, 0, /* 847: pointer.func */
            4097, 8, 0, /* 850: pointer.func */
            0, 0, 0, /* 853: func */
            4097, 8, 0, /* 856: pointer.func */
            4097, 8, 0, /* 859: pointer.func */
            0, 0, 0, /* 862: func */
            4097, 8, 0, /* 865: pointer.func */
            4097, 8, 0, /* 868: pointer.func */
            0, 0, 0, /* 871: func */
            4097, 8, 0, /* 874: pointer.func */
            4097, 8, 0, /* 877: pointer.func */
            0, 0, 0, /* 880: func */
            0, 0, 0, /* 883: func */
            0, 0, 0, /* 886: func */
            4097, 8, 0, /* 889: pointer.func */
            4097, 8, 0, /* 892: pointer.func */
            4097, 8, 0, /* 895: pointer.func */
            0, 0, 0, /* 898: func */
            0, 0, 0, /* 901: func */
            0, 0, 0, /* 904: func */
            4097, 8, 0, /* 907: pointer.func */
            0, 0, 0, /* 910: func */
            4097, 8, 0, /* 913: pointer.func */
            0, 0, 0, /* 916: func */
            0, 0, 0, /* 919: func */
            4097, 8, 0, /* 922: pointer.func */
            4097, 8, 0, /* 925: pointer.func */
            4097, 8, 0, /* 928: pointer.func */
            0, 0, 0, /* 931: func */
            0, 0, 0, /* 934: func */
            0, 0, 0, /* 937: func */
            4097, 8, 0, /* 940: pointer.func */
            4097, 8, 0, /* 943: pointer.func */
            0, 0, 0, /* 946: func */
            4097, 8, 0, /* 949: pointer.func */
            0, 0, 0, /* 952: func */
            4097, 8, 0, /* 955: pointer.func */
            4097, 8, 0, /* 958: pointer.func */
            0, 0, 0, /* 961: func */
            0, 0, 0, /* 964: func */
            0, 1, 0, /* 967: char */
            0, 0, 0, /* 970: func */
            0, 0, 0, /* 973: func */
            4097, 8, 0, /* 976: pointer.func */
            0, 0, 0, /* 979: func */
            0, 0, 0, /* 982: func */
            4097, 8, 0, /* 985: pointer.func */
            4097, 8, 0, /* 988: pointer.func */
            0, 0, 0, /* 991: func */
            4097, 8, 0, /* 994: pointer.func */
            4097, 8, 0, /* 997: pointer.func */
            0, 0, 0, /* 1000: func */
            0, 0, 0, /* 1003: func */
        },
        .arg_entity_index = { 800, 648, 252, },
        .ret_entity_index = 761,
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

