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
            0, 40, 4, /* 6: struct.x509_crl_method_st */
            	3, 8,
            	3, 16,
            	17, 24,
            	0, 32,
            4097, 8, 0, /* 17: pointer.func */
            0, 8, 1, /* 20: union.anon.1.3127 */
            	25, 0,
            1, 8, 1, /* 25: pointer.struct.stack_st_OPENSSL_STRING */
            	30, 0,
            0, 32, 1, /* 30: struct.stack_st_OPENSSL_STRING */
            	35, 0,
            0, 32, 2, /* 35: struct.stack_st */
            	42, 8,
            	52, 24,
            1, 8, 1, /* 42: pointer.pointer.char */
            	47, 0,
            1, 8, 1, /* 47: pointer.char */
            	4096, 0,
            4097, 8, 0, /* 52: pointer.func */
            1, 8, 1, /* 55: pointer.struct.DIST_POINT_NAME_st */
            	60, 0,
            0, 24, 2, /* 60: struct.DIST_POINT_NAME_st */
            	20, 8,
            	67, 16,
            1, 8, 1, /* 67: pointer.struct.X509_name_st */
            	72, 0,
            0, 40, 3, /* 72: struct.X509_name_st */
            	25, 0,
            	81, 16,
            	47, 24,
            1, 8, 1, /* 81: pointer.struct.buf_mem_st */
            	86, 0,
            0, 24, 1, /* 86: struct.buf_mem_st */
            	47, 8,
            0, 32, 2, /* 91: struct.ISSUING_DIST_POINT_st */
            	55, 0,
            	98, 16,
            1, 8, 1, /* 98: pointer.struct.asn1_string_st */
            	103, 0,
            0, 24, 1, /* 103: struct.asn1_string_st */
            	47, 8,
            1, 8, 1, /* 108: pointer.struct.X509_crl_info_st */
            	113, 0,
            0, 80, 8, /* 113: struct.X509_crl_info_st */
            	98, 0,
            	132, 8,
            	67, 16,
            	98, 24,
            	98, 32,
            	25, 40,
            	25, 48,
            	173, 56,
            1, 8, 1, /* 132: pointer.struct.X509_algor_st */
            	137, 0,
            0, 16, 2, /* 137: struct.X509_algor_st */
            	144, 0,
            	158, 8,
            1, 8, 1, /* 144: pointer.struct.asn1_object_st */
            	149, 0,
            0, 40, 3, /* 149: struct.asn1_object_st */
            	47, 0,
            	47, 8,
            	47, 24,
            1, 8, 1, /* 158: pointer.struct.asn1_type_st */
            	163, 0,
            0, 16, 1, /* 163: struct.asn1_type_st */
            	168, 8,
            0, 8, 1, /* 168: struct.fnames */
            	47, 0,
            0, 24, 1, /* 173: struct.ASN1_ENCODING_st */
            	47, 0,
            0, 24, 2, /* 178: struct.X509_POLICY_NODE_st */
            	185, 0,
            	199, 8,
            1, 8, 1, /* 185: pointer.struct.X509_POLICY_DATA_st */
            	190, 0,
            0, 32, 3, /* 190: struct.X509_POLICY_DATA_st */
            	144, 8,
            	25, 16,
            	25, 24,
            1, 8, 1, /* 199: pointer.struct.X509_POLICY_NODE_st */
            	178, 0,
            1, 8, 1, /* 204: pointer.struct.ISSUING_DIST_POINT_st */
            	91, 0,
            4097, 8, 0, /* 209: pointer.func */
            4097, 8, 0, /* 212: pointer.func */
            4097, 8, 0, /* 215: pointer.func */
            4097, 8, 0, /* 218: pointer.func */
            4097, 8, 0, /* 221: pointer.func */
            4097, 8, 0, /* 224: pointer.func */
            4097, 8, 0, /* 227: pointer.func */
            1, 8, 1, /* 230: pointer.struct.evp_pkey_asn1_method_st */
            	235, 0,
            0, 208, 24, /* 235: struct.evp_pkey_asn1_method_st */
            	47, 16,
            	47, 24,
            	286, 32,
            	227, 40,
            	224, 48,
            	221, 56,
            	218, 64,
            	215, 72,
            	221, 80,
            	212, 88,
            	212, 96,
            	294, 104,
            	297, 112,
            	212, 120,
            	224, 128,
            	224, 136,
            	221, 144,
            	300, 152,
            	303, 160,
            	306, 168,
            	294, 176,
            	297, 184,
            	209, 192,
            	309, 200,
            1, 8, 1, /* 286: pointer.struct.unnamed */
            	291, 0,
            0, 0, 0, /* 291: struct.unnamed */
            4097, 8, 0, /* 294: pointer.func */
            4097, 8, 0, /* 297: pointer.func */
            4097, 8, 0, /* 300: pointer.func */
            4097, 8, 0, /* 303: pointer.func */
            4097, 8, 0, /* 306: pointer.func */
            4097, 8, 0, /* 309: pointer.func */
            1, 8, 1, /* 312: pointer.struct.evp_pkey_st */
            	317, 0,
            0, 56, 4, /* 317: struct.evp_pkey_st */
            	230, 16,
            	328, 24,
            	168, 32,
            	25, 48,
            1, 8, 1, /* 328: pointer.struct.engine_st */
            	333, 0,
            0, 216, 24, /* 333: struct.engine_st */
            	47, 0,
            	47, 8,
            	384, 16,
            	439, 24,
            	490, 32,
            	526, 40,
            	543, 48,
            	570, 56,
            	605, 64,
            	613, 72,
            	616, 80,
            	619, 88,
            	622, 96,
            	625, 104,
            	625, 112,
            	625, 120,
            	628, 128,
            	631, 136,
            	631, 144,
            	634, 152,
            	637, 160,
            	649, 184,
            	328, 200,
            	328, 208,
            1, 8, 1, /* 384: pointer.struct.rsa_meth_st */
            	389, 0,
            0, 112, 13, /* 389: struct.rsa_meth_st */
            	47, 0,
            	418, 8,
            	418, 16,
            	418, 24,
            	418, 32,
            	421, 40,
            	424, 48,
            	427, 56,
            	427, 64,
            	47, 80,
            	430, 88,
            	433, 96,
            	436, 104,
            4097, 8, 0, /* 418: pointer.func */
            4097, 8, 0, /* 421: pointer.func */
            4097, 8, 0, /* 424: pointer.func */
            4097, 8, 0, /* 427: pointer.func */
            4097, 8, 0, /* 430: pointer.func */
            4097, 8, 0, /* 433: pointer.func */
            4097, 8, 0, /* 436: pointer.func */
            1, 8, 1, /* 439: pointer.struct.dsa_method */
            	444, 0,
            0, 96, 11, /* 444: struct.dsa_method */
            	47, 0,
            	469, 8,
            	472, 16,
            	475, 24,
            	478, 32,
            	481, 40,
            	484, 48,
            	484, 56,
            	47, 72,
            	487, 80,
            	484, 88,
            4097, 8, 0, /* 469: pointer.func */
            4097, 8, 0, /* 472: pointer.func */
            4097, 8, 0, /* 475: pointer.func */
            4097, 8, 0, /* 478: pointer.func */
            4097, 8, 0, /* 481: pointer.func */
            4097, 8, 0, /* 484: pointer.func */
            4097, 8, 0, /* 487: pointer.func */
            1, 8, 1, /* 490: pointer.struct.dh_method */
            	495, 0,
            0, 72, 8, /* 495: struct.dh_method */
            	47, 0,
            	514, 8,
            	517, 16,
            	520, 24,
            	514, 32,
            	514, 40,
            	47, 56,
            	523, 64,
            4097, 8, 0, /* 514: pointer.func */
            4097, 8, 0, /* 517: pointer.func */
            4097, 8, 0, /* 520: pointer.func */
            4097, 8, 0, /* 523: pointer.func */
            1, 8, 1, /* 526: pointer.struct.ecdh_method */
            	531, 0,
            0, 32, 3, /* 531: struct.ecdh_method */
            	47, 0,
            	540, 8,
            	47, 24,
            4097, 8, 0, /* 540: pointer.func */
            1, 8, 1, /* 543: pointer.struct.ecdsa_method */
            	548, 0,
            0, 48, 5, /* 548: struct.ecdsa_method */
            	47, 0,
            	561, 8,
            	564, 16,
            	567, 24,
            	47, 40,
            4097, 8, 0, /* 561: pointer.func */
            4097, 8, 0, /* 564: pointer.func */
            4097, 8, 0, /* 567: pointer.func */
            1, 8, 1, /* 570: pointer.struct.rand_meth_st */
            	575, 0,
            0, 48, 6, /* 575: struct.rand_meth_st */
            	590, 0,
            	593, 8,
            	596, 16,
            	599, 24,
            	593, 32,
            	602, 40,
            4097, 8, 0, /* 590: pointer.func */
            4097, 8, 0, /* 593: pointer.func */
            4097, 8, 0, /* 596: pointer.func */
            4097, 8, 0, /* 599: pointer.func */
            4097, 8, 0, /* 602: pointer.func */
            1, 8, 1, /* 605: pointer.struct.store_method_st */
            	610, 0,
            0, 0, 0, /* 610: struct.store_method_st */
            4097, 8, 0, /* 613: pointer.func */
            4097, 8, 0, /* 616: pointer.func */
            4097, 8, 0, /* 619: pointer.func */
            4097, 8, 0, /* 622: pointer.func */
            4097, 8, 0, /* 625: pointer.func */
            4097, 8, 0, /* 628: pointer.func */
            4097, 8, 0, /* 631: pointer.func */
            4097, 8, 0, /* 634: pointer.func */
            1, 8, 1, /* 637: pointer.struct.ENGINE_CMD_DEFN_st */
            	642, 0,
            0, 32, 2, /* 642: struct.ENGINE_CMD_DEFN_st */
            	47, 8,
            	47, 16,
            0, 16, 1, /* 649: struct.crypto_ex_data_st */
            	25, 0,
            0, 24, 3, /* 654: struct.X509_pubkey_st */
            	132, 0,
            	98, 8,
            	312, 16,
            1, 8, 1, /* 663: pointer.struct.X509_pubkey_st */
            	654, 0,
            0, 104, 11, /* 668: struct.x509_cinf_st */
            	98, 0,
            	98, 8,
            	132, 16,
            	67, 24,
            	693, 32,
            	67, 40,
            	663, 48,
            	98, 56,
            	98, 64,
            	25, 72,
            	173, 80,
            1, 8, 1, /* 693: pointer.struct.X509_val_st */
            	698, 0,
            0, 16, 2, /* 698: struct.X509_val_st */
            	98, 0,
            	98, 8,
            1, 8, 1, /* 705: pointer.struct.x509_cinf_st */
            	668, 0,
            0, 184, 12, /* 710: struct.x509_st */
            	705, 0,
            	132, 8,
            	98, 16,
            	47, 32,
            	649, 40,
            	98, 104,
            	737, 112,
            	751, 120,
            	25, 128,
            	25, 136,
            	763, 144,
            	775, 176,
            1, 8, 1, /* 737: pointer.struct.AUTHORITY_KEYID_st */
            	742, 0,
            0, 24, 3, /* 742: struct.AUTHORITY_KEYID_st */
            	98, 0,
            	25, 8,
            	98, 16,
            1, 8, 1, /* 751: pointer.struct.X509_POLICY_CACHE_st */
            	756, 0,
            0, 40, 2, /* 756: struct.X509_POLICY_CACHE_st */
            	185, 0,
            	25, 8,
            1, 8, 1, /* 763: pointer.struct.NAME_CONSTRAINTS_st */
            	768, 0,
            0, 16, 2, /* 768: struct.NAME_CONSTRAINTS_st */
            	25, 0,
            	25, 8,
            1, 8, 1, /* 775: pointer.struct.x509_cert_aux_st */
            	780, 0,
            0, 40, 5, /* 780: struct.x509_cert_aux_st */
            	25, 0,
            	25, 8,
            	98, 16,
            	98, 24,
            	25, 32,
            1, 8, 1, /* 793: pointer.struct.X509_crl_st */
            	798, 0,
            0, 120, 10, /* 798: struct.X509_crl_st */
            	108, 0,
            	132, 8,
            	98, 16,
            	737, 32,
            	204, 40,
            	98, 56,
            	98, 64,
            	25, 96,
            	821, 104,
            	826, 112,
            1, 8, 1, /* 821: pointer.struct.x509_crl_method_st */
            	6, 0,
            0, 8, 0, /* 826: pointer.void */
            0, 32, 3, /* 829: struct.X509_POLICY_LEVEL_st */
            	838, 0,
            	25, 8,
            	199, 16,
            1, 8, 1, /* 838: pointer.struct.x509_st */
            	710, 0,
            1, 8, 1, /* 843: pointer.struct.X509_POLICY_LEVEL_st */
            	829, 0,
            1, 8, 1, /* 848: pointer.struct.X509_POLICY_TREE_st */
            	853, 0,
            0, 48, 4, /* 853: struct.X509_POLICY_TREE_st */
            	843, 0,
            	25, 16,
            	25, 24,
            	25, 32,
            4097, 8, 0, /* 864: pointer.func */
            4097, 8, 0, /* 867: pointer.func */
            1, 8, 1, /* 870: pointer.struct.evp_pkey_asn1_method_st */
            	875, 0,
            0, 208, 24, /* 875: struct.evp_pkey_asn1_method_st */
            	47, 16,
            	47, 24,
            	926, 32,
            	867, 40,
            	929, 48,
            	932, 56,
            	935, 64,
            	938, 72,
            	932, 80,
            	941, 88,
            	941, 96,
            	864, 104,
            	944, 112,
            	941, 120,
            	929, 128,
            	929, 136,
            	932, 144,
            	300, 152,
            	947, 160,
            	950, 168,
            	864, 176,
            	944, 184,
            	953, 192,
            	309, 200,
            4097, 8, 0, /* 926: pointer.func */
            4097, 8, 0, /* 929: pointer.func */
            4097, 8, 0, /* 932: pointer.func */
            4097, 8, 0, /* 935: pointer.func */
            4097, 8, 0, /* 938: pointer.func */
            4097, 8, 0, /* 941: pointer.func */
            4097, 8, 0, /* 944: pointer.func */
            4097, 8, 0, /* 947: pointer.func */
            4097, 8, 0, /* 950: pointer.func */
            4097, 8, 0, /* 953: pointer.func */
            1, 8, 1, /* 956: pointer.struct.evp_pkey_st */
            	961, 0,
            0, 56, 4, /* 961: struct.evp_pkey_st */
            	870, 16,
            	328, 24,
            	168, 32,
            	25, 48,
            1, 8, 1, /* 972: pointer.struct.X509_pubkey_st */
            	977, 0,
            0, 24, 3, /* 977: struct.X509_pubkey_st */
            	132, 0,
            	98, 8,
            	956, 16,
            4097, 8, 0, /* 986: pointer.func */
            0, 1, 0, /* 989: char */
            1, 8, 1, /* 992: pointer.struct.x509_store_st */
            	997, 0,
            0, 144, 15, /* 997: struct.x509_store_st */
            	25, 8,
            	25, 16,
            	1030, 24,
            	286, 32,
            	1042, 40,
            	1045, 48,
            	1048, 56,
            	286, 64,
            	1051, 72,
            	1054, 80,
            	1057, 88,
            	986, 96,
            	986, 104,
            	286, 112,
            	649, 120,
            1, 8, 1, /* 1030: pointer.struct.X509_VERIFY_PARAM_st */
            	1035, 0,
            0, 56, 2, /* 1035: struct.X509_VERIFY_PARAM_st */
            	47, 0,
            	25, 48,
            4097, 8, 0, /* 1042: pointer.func */
            4097, 8, 0, /* 1045: pointer.func */
            4097, 8, 0, /* 1048: pointer.func */
            4097, 8, 0, /* 1051: pointer.func */
            4097, 8, 0, /* 1054: pointer.func */
            4097, 8, 0, /* 1057: pointer.func */
            0, 248, 25, /* 1060: struct.x509_store_ctx_st */
            	992, 0,
            	1113, 16,
            	25, 24,
            	25, 32,
            	1030, 40,
            	47, 48,
            	286, 56,
            	1042, 64,
            	1045, 72,
            	1048, 80,
            	286, 88,
            	1051, 96,
            	1054, 104,
            	1057, 112,
            	286, 120,
            	986, 128,
            	986, 136,
            	286, 144,
            	25, 160,
            	848, 168,
            	1113, 192,
            	1113, 200,
            	793, 208,
            	1175, 224,
            	649, 232,
            1, 8, 1, /* 1113: pointer.struct.x509_st */
            	1118, 0,
            0, 184, 12, /* 1118: struct.x509_st */
            	1145, 0,
            	132, 8,
            	98, 16,
            	47, 32,
            	649, 40,
            	98, 104,
            	737, 112,
            	751, 120,
            	25, 128,
            	25, 136,
            	763, 144,
            	775, 176,
            1, 8, 1, /* 1145: pointer.struct.x509_cinf_st */
            	1150, 0,
            0, 104, 11, /* 1150: struct.x509_cinf_st */
            	98, 0,
            	98, 8,
            	132, 16,
            	67, 24,
            	693, 32,
            	67, 40,
            	972, 48,
            	98, 56,
            	98, 64,
            	25, 72,
            	173, 80,
            1, 8, 1, /* 1175: pointer.struct.x509_store_ctx_st */
            	1060, 0,
        },
        .arg_entity_index = { 1175, },
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

