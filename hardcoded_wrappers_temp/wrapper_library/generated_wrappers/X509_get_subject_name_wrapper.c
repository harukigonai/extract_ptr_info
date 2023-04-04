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
            1, 8, 1, /* 0: pointer.struct.NAME_CONSTRAINTS_st */
            	5, 0,
            0, 16, 2, /* 5: struct.NAME_CONSTRAINTS_st */
            	12, 0,
            	12, 8,
            1, 8, 1, /* 12: pointer.struct.stack_st_OPENSSL_STRING */
            	17, 0,
            0, 32, 1, /* 17: struct.stack_st_OPENSSL_STRING */
            	22, 0,
            0, 32, 2, /* 22: struct.stack_st */
            	29, 8,
            	39, 24,
            1, 8, 1, /* 29: pointer.pointer.char */
            	34, 0,
            1, 8, 1, /* 34: pointer.char */
            	4096, 0,
            4097, 8, 0, /* 39: pointer.func */
            0, 32, 3, /* 42: struct.X509_POLICY_DATA_st */
            	51, 8,
            	12, 16,
            	12, 24,
            1, 8, 1, /* 51: pointer.struct.asn1_object_st */
            	56, 0,
            0, 40, 3, /* 56: struct.asn1_object_st */
            	34, 0,
            	34, 8,
            	34, 24,
            1, 8, 1, /* 65: pointer.struct.X509_POLICY_DATA_st */
            	42, 0,
            0, 24, 3, /* 70: struct.AUTHORITY_KEYID_st */
            	79, 0,
            	12, 8,
            	79, 16,
            1, 8, 1, /* 79: pointer.struct.asn1_string_st */
            	84, 0,
            0, 24, 1, /* 84: struct.asn1_string_st */
            	34, 8,
            1, 8, 1, /* 89: pointer.struct.AUTHORITY_KEYID_st */
            	70, 0,
            0, 24, 1, /* 94: struct.ASN1_ENCODING_st */
            	34, 0,
            0, 16, 1, /* 99: struct.crypto_ex_data_st */
            	12, 0,
            0, 32, 2, /* 104: struct.ENGINE_CMD_DEFN_st */
            	34, 8,
            	34, 16,
            1, 8, 1, /* 111: pointer.struct.ENGINE_CMD_DEFN_st */
            	104, 0,
            4097, 8, 0, /* 116: pointer.func */
            4097, 8, 0, /* 119: pointer.func */
            4097, 8, 0, /* 122: pointer.func */
            4097, 8, 0, /* 125: pointer.func */
            4097, 8, 0, /* 128: pointer.func */
            0, 48, 6, /* 131: struct.rand_meth_st */
            	146, 0,
            	149, 8,
            	152, 16,
            	128, 24,
            	149, 32,
            	125, 40,
            4097, 8, 0, /* 146: pointer.func */
            4097, 8, 0, /* 149: pointer.func */
            4097, 8, 0, /* 152: pointer.func */
            4097, 8, 0, /* 155: pointer.func */
            4097, 8, 0, /* 158: pointer.func */
            0, 48, 5, /* 161: struct.ecdsa_method */
            	34, 0,
            	155, 8,
            	174, 16,
            	177, 24,
            	34, 40,
            4097, 8, 0, /* 174: pointer.func */
            4097, 8, 0, /* 177: pointer.func */
            1, 8, 1, /* 180: pointer.struct.ecdsa_method */
            	161, 0,
            4097, 8, 0, /* 185: pointer.func */
            0, 32, 3, /* 188: struct.ecdh_method */
            	34, 0,
            	185, 8,
            	34, 24,
            1, 8, 1, /* 197: pointer.struct.ecdh_method */
            	188, 0,
            4097, 8, 0, /* 202: pointer.func */
            0, 72, 8, /* 205: struct.dh_method */
            	34, 0,
            	224, 8,
            	227, 16,
            	202, 24,
            	224, 32,
            	224, 40,
            	34, 56,
            	230, 64,
            4097, 8, 0, /* 224: pointer.func */
            4097, 8, 0, /* 227: pointer.func */
            4097, 8, 0, /* 230: pointer.func */
            1, 8, 1, /* 233: pointer.struct.dh_method */
            	205, 0,
            4097, 8, 0, /* 238: pointer.func */
            0, 40, 2, /* 241: struct.X509_POLICY_CACHE_st */
            	65, 0,
            	12, 8,
            4097, 8, 0, /* 248: pointer.func */
            4097, 8, 0, /* 251: pointer.func */
            4097, 8, 0, /* 254: pointer.func */
            4097, 8, 0, /* 257: pointer.func */
            0, 96, 11, /* 260: struct.dsa_method */
            	34, 0,
            	257, 8,
            	285, 16,
            	288, 24,
            	254, 32,
            	251, 40,
            	248, 48,
            	248, 56,
            	34, 72,
            	238, 80,
            	248, 88,
            4097, 8, 0, /* 285: pointer.func */
            4097, 8, 0, /* 288: pointer.func */
            0, 24, 3, /* 291: struct.X509_pubkey_st */
            	300, 0,
            	79, 8,
            	327, 16,
            1, 8, 1, /* 300: pointer.struct.X509_algor_st */
            	305, 0,
            0, 16, 2, /* 305: struct.X509_algor_st */
            	51, 0,
            	312, 8,
            1, 8, 1, /* 312: pointer.struct.asn1_type_st */
            	317, 0,
            0, 16, 1, /* 317: struct.asn1_type_st */
            	322, 8,
            0, 8, 1, /* 322: struct.fnames */
            	34, 0,
            1, 8, 1, /* 327: pointer.struct.evp_pkey_st */
            	332, 0,
            0, 56, 4, /* 332: struct.evp_pkey_st */
            	343, 16,
            	441, 24,
            	322, 32,
            	12, 48,
            1, 8, 1, /* 343: pointer.struct.evp_pkey_asn1_method_st */
            	348, 0,
            0, 208, 24, /* 348: struct.evp_pkey_asn1_method_st */
            	34, 16,
            	34, 24,
            	399, 32,
            	402, 40,
            	405, 48,
            	408, 56,
            	411, 64,
            	414, 72,
            	408, 80,
            	417, 88,
            	417, 96,
            	420, 104,
            	423, 112,
            	417, 120,
            	405, 128,
            	405, 136,
            	408, 144,
            	426, 152,
            	429, 160,
            	432, 168,
            	420, 176,
            	423, 184,
            	435, 192,
            	438, 200,
            4097, 8, 0, /* 399: pointer.func */
            4097, 8, 0, /* 402: pointer.func */
            4097, 8, 0, /* 405: pointer.func */
            4097, 8, 0, /* 408: pointer.func */
            4097, 8, 0, /* 411: pointer.func */
            4097, 8, 0, /* 414: pointer.func */
            4097, 8, 0, /* 417: pointer.func */
            4097, 8, 0, /* 420: pointer.func */
            4097, 8, 0, /* 423: pointer.func */
            4097, 8, 0, /* 426: pointer.func */
            4097, 8, 0, /* 429: pointer.func */
            4097, 8, 0, /* 432: pointer.func */
            4097, 8, 0, /* 435: pointer.func */
            4097, 8, 0, /* 438: pointer.func */
            1, 8, 1, /* 441: pointer.struct.engine_st */
            	446, 0,
            0, 216, 24, /* 446: struct.engine_st */
            	34, 0,
            	34, 8,
            	497, 16,
            	552, 24,
            	233, 32,
            	197, 40,
            	180, 48,
            	557, 56,
            	562, 64,
            	158, 72,
            	570, 80,
            	573, 88,
            	576, 96,
            	579, 104,
            	579, 112,
            	579, 120,
            	122, 128,
            	119, 136,
            	119, 144,
            	116, 152,
            	111, 160,
            	99, 184,
            	441, 200,
            	441, 208,
            1, 8, 1, /* 497: pointer.struct.rsa_meth_st */
            	502, 0,
            0, 112, 13, /* 502: struct.rsa_meth_st */
            	34, 0,
            	531, 8,
            	531, 16,
            	531, 24,
            	531, 32,
            	534, 40,
            	537, 48,
            	540, 56,
            	540, 64,
            	34, 80,
            	543, 88,
            	546, 96,
            	549, 104,
            4097, 8, 0, /* 531: pointer.func */
            4097, 8, 0, /* 534: pointer.func */
            4097, 8, 0, /* 537: pointer.func */
            4097, 8, 0, /* 540: pointer.func */
            4097, 8, 0, /* 543: pointer.func */
            4097, 8, 0, /* 546: pointer.func */
            4097, 8, 0, /* 549: pointer.func */
            1, 8, 1, /* 552: pointer.struct.dsa_method */
            	260, 0,
            1, 8, 1, /* 557: pointer.struct.rand_meth_st */
            	131, 0,
            1, 8, 1, /* 562: pointer.struct.store_method_st */
            	567, 0,
            0, 0, 0, /* 567: struct.store_method_st */
            4097, 8, 0, /* 570: pointer.func */
            4097, 8, 0, /* 573: pointer.func */
            4097, 8, 0, /* 576: pointer.func */
            4097, 8, 0, /* 579: pointer.func */
            0, 16, 2, /* 582: struct.X509_val_st */
            	79, 0,
            	79, 8,
            0, 184, 12, /* 589: struct.x509_st */
            	616, 0,
            	300, 8,
            	79, 16,
            	34, 32,
            	99, 40,
            	79, 104,
            	89, 112,
            	680, 120,
            	12, 128,
            	12, 136,
            	0, 144,
            	685, 176,
            1, 8, 1, /* 616: pointer.struct.x509_cinf_st */
            	621, 0,
            0, 104, 11, /* 621: struct.x509_cinf_st */
            	79, 0,
            	79, 8,
            	300, 16,
            	646, 24,
            	670, 32,
            	646, 40,
            	675, 48,
            	79, 56,
            	79, 64,
            	12, 72,
            	94, 80,
            1, 8, 1, /* 646: pointer.struct.X509_name_st */
            	651, 0,
            0, 40, 3, /* 651: struct.X509_name_st */
            	12, 0,
            	660, 16,
            	34, 24,
            1, 8, 1, /* 660: pointer.struct.buf_mem_st */
            	665, 0,
            0, 24, 1, /* 665: struct.buf_mem_st */
            	34, 8,
            1, 8, 1, /* 670: pointer.struct.X509_val_st */
            	582, 0,
            1, 8, 1, /* 675: pointer.struct.X509_pubkey_st */
            	291, 0,
            1, 8, 1, /* 680: pointer.struct.X509_POLICY_CACHE_st */
            	241, 0,
            1, 8, 1, /* 685: pointer.struct.x509_cert_aux_st */
            	690, 0,
            0, 40, 5, /* 690: struct.x509_cert_aux_st */
            	12, 0,
            	12, 8,
            	79, 16,
            	79, 24,
            	12, 32,
            0, 8, 0, /* 703: pointer.void */
            0, 1, 0, /* 706: char */
            1, 8, 1, /* 709: pointer.struct.x509_st */
            	589, 0,
        },
        .arg_entity_index = { 709, },
        .ret_entity_index = 646,
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

