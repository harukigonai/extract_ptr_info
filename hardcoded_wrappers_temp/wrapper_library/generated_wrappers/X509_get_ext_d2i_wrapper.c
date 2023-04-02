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
            1, 8, 1, /* 0: pointer.int */
            	5, 0,
            0, 4, 0, /* 5: int */
            0, 20, 0, /* 8: array[20].char */
            0, 32, 3, /* 11: struct.X509_POLICY_DATA_st */
            	20, 8,
            	39, 16,
            	39, 24,
            1, 8, 1, /* 20: pointer.struct.asn1_object_st */
            	25, 0,
            0, 40, 3, /* 25: struct.asn1_object_st */
            	34, 0,
            	34, 8,
            	34, 24,
            1, 8, 1, /* 34: pointer.char */
            	4096, 0,
            1, 8, 1, /* 39: pointer.struct.stack_st_OPENSSL_STRING */
            	44, 0,
            0, 32, 1, /* 44: struct.stack_st_OPENSSL_STRING */
            	49, 0,
            0, 32, 2, /* 49: struct.stack_st */
            	56, 8,
            	61, 24,
            1, 8, 1, /* 56: pointer.pointer.char */
            	34, 0,
            4097, 8, 0, /* 61: pointer.func */
            0, 24, 3, /* 64: struct.AUTHORITY_KEYID_st */
            	73, 0,
            	39, 8,
            	73, 16,
            1, 8, 1, /* 73: pointer.struct.asn1_string_st */
            	78, 0,
            0, 24, 1, /* 78: struct.asn1_string_st */
            	34, 8,
            1, 8, 1, /* 83: pointer.struct.AUTHORITY_KEYID_st */
            	64, 0,
            0, 16, 1, /* 88: struct.crypto_ex_data_st */
            	39, 0,
            0, 0, 0, /* 93: func */
            4097, 8, 0, /* 96: pointer.func */
            0, 0, 0, /* 99: func */
            0, 0, 0, /* 102: func */
            4097, 8, 0, /* 105: pointer.func */
            0, 0, 0, /* 108: func */
            4097, 8, 0, /* 111: pointer.func */
            0, 0, 0, /* 114: struct.store_method_st */
            1, 8, 1, /* 117: pointer.struct.store_method_st */
            	114, 0,
            0, 0, 0, /* 122: func */
            4097, 8, 0, /* 125: pointer.func */
            4097, 8, 0, /* 128: pointer.func */
            0, 40, 2, /* 131: struct.X509_POLICY_CACHE_st */
            	138, 0,
            	39, 8,
            1, 8, 1, /* 138: pointer.struct.X509_POLICY_DATA_st */
            	11, 0,
            0, 0, 0, /* 143: func */
            1, 8, 1, /* 146: pointer.struct.evp_pkey_st */
            	151, 0,
            0, 56, 4, /* 151: struct.evp_pkey_st */
            	162, 16,
            	265, 24,
            	563, 32,
            	39, 48,
            1, 8, 1, /* 162: pointer.struct.evp_pkey_asn1_method_st */
            	167, 0,
            0, 208, 24, /* 167: struct.evp_pkey_asn1_method_st */
            	34, 16,
            	34, 24,
            	218, 32,
            	226, 40,
            	229, 48,
            	232, 56,
            	235, 64,
            	238, 72,
            	232, 80,
            	241, 88,
            	241, 96,
            	244, 104,
            	247, 112,
            	241, 120,
            	229, 128,
            	229, 136,
            	232, 144,
            	250, 152,
            	253, 160,
            	256, 168,
            	244, 176,
            	247, 184,
            	259, 192,
            	262, 200,
            1, 8, 1, /* 218: pointer.struct.unnamed */
            	223, 0,
            0, 0, 0, /* 223: struct.unnamed */
            4097, 8, 0, /* 226: pointer.func */
            4097, 8, 0, /* 229: pointer.func */
            4097, 8, 0, /* 232: pointer.func */
            4097, 8, 0, /* 235: pointer.func */
            4097, 8, 0, /* 238: pointer.func */
            4097, 8, 0, /* 241: pointer.func */
            4097, 8, 0, /* 244: pointer.func */
            4097, 8, 0, /* 247: pointer.func */
            4097, 8, 0, /* 250: pointer.func */
            4097, 8, 0, /* 253: pointer.func */
            4097, 8, 0, /* 256: pointer.func */
            4097, 8, 0, /* 259: pointer.func */
            4097, 8, 0, /* 262: pointer.func */
            1, 8, 1, /* 265: pointer.struct.engine_st */
            	270, 0,
            0, 216, 24, /* 270: struct.engine_st */
            	34, 0,
            	34, 8,
            	321, 16,
            	376, 24,
            	427, 32,
            	463, 40,
            	480, 48,
            	507, 56,
            	117, 64,
            	111, 72,
            	536, 80,
            	539, 88,
            	105, 96,
            	542, 104,
            	542, 112,
            	542, 120,
            	96, 128,
            	545, 136,
            	545, 144,
            	548, 152,
            	551, 160,
            	88, 184,
            	265, 200,
            	265, 208,
            1, 8, 1, /* 321: pointer.struct.rsa_meth_st */
            	326, 0,
            0, 112, 13, /* 326: struct.rsa_meth_st */
            	34, 0,
            	355, 8,
            	355, 16,
            	355, 24,
            	355, 32,
            	358, 40,
            	361, 48,
            	364, 56,
            	364, 64,
            	34, 80,
            	367, 88,
            	370, 96,
            	373, 104,
            4097, 8, 0, /* 355: pointer.func */
            4097, 8, 0, /* 358: pointer.func */
            4097, 8, 0, /* 361: pointer.func */
            4097, 8, 0, /* 364: pointer.func */
            4097, 8, 0, /* 367: pointer.func */
            4097, 8, 0, /* 370: pointer.func */
            4097, 8, 0, /* 373: pointer.func */
            1, 8, 1, /* 376: pointer.struct.dsa_method */
            	381, 0,
            0, 96, 11, /* 381: struct.dsa_method */
            	34, 0,
            	406, 8,
            	409, 16,
            	412, 24,
            	415, 32,
            	418, 40,
            	421, 48,
            	421, 56,
            	34, 72,
            	424, 80,
            	421, 88,
            4097, 8, 0, /* 406: pointer.func */
            4097, 8, 0, /* 409: pointer.func */
            4097, 8, 0, /* 412: pointer.func */
            4097, 8, 0, /* 415: pointer.func */
            4097, 8, 0, /* 418: pointer.func */
            4097, 8, 0, /* 421: pointer.func */
            4097, 8, 0, /* 424: pointer.func */
            1, 8, 1, /* 427: pointer.struct.dh_method */
            	432, 0,
            0, 72, 8, /* 432: struct.dh_method */
            	34, 0,
            	451, 8,
            	454, 16,
            	457, 24,
            	451, 32,
            	451, 40,
            	34, 56,
            	460, 64,
            4097, 8, 0, /* 451: pointer.func */
            4097, 8, 0, /* 454: pointer.func */
            4097, 8, 0, /* 457: pointer.func */
            4097, 8, 0, /* 460: pointer.func */
            1, 8, 1, /* 463: pointer.struct.ecdh_method */
            	468, 0,
            0, 32, 3, /* 468: struct.ecdh_method */
            	34, 0,
            	477, 8,
            	34, 24,
            4097, 8, 0, /* 477: pointer.func */
            1, 8, 1, /* 480: pointer.struct.ecdsa_method */
            	485, 0,
            0, 48, 5, /* 485: struct.ecdsa_method */
            	34, 0,
            	498, 8,
            	501, 16,
            	504, 24,
            	34, 40,
            4097, 8, 0, /* 498: pointer.func */
            4097, 8, 0, /* 501: pointer.func */
            4097, 8, 0, /* 504: pointer.func */
            1, 8, 1, /* 507: pointer.struct.rand_meth_st */
            	512, 0,
            0, 48, 6, /* 512: struct.rand_meth_st */
            	527, 0,
            	530, 8,
            	533, 16,
            	128, 24,
            	530, 32,
            	125, 40,
            4097, 8, 0, /* 527: pointer.func */
            4097, 8, 0, /* 530: pointer.func */
            4097, 8, 0, /* 533: pointer.func */
            4097, 8, 0, /* 536: pointer.func */
            4097, 8, 0, /* 539: pointer.func */
            4097, 8, 0, /* 542: pointer.func */
            4097, 8, 0, /* 545: pointer.func */
            4097, 8, 0, /* 548: pointer.func */
            1, 8, 1, /* 551: pointer.struct.ENGINE_CMD_DEFN_st */
            	556, 0,
            0, 32, 2, /* 556: struct.ENGINE_CMD_DEFN_st */
            	34, 8,
            	34, 16,
            0, 8, 1, /* 563: struct.fnames */
            	34, 0,
            1, 8, 1, /* 568: pointer.struct.X509_POLICY_CACHE_st */
            	131, 0,
            0, 0, 0, /* 573: func */
            0, 0, 0, /* 576: func */
            0, 0, 0, /* 579: func */
            1, 8, 1, /* 582: pointer.struct.buf_mem_st */
            	587, 0,
            0, 24, 1, /* 587: struct.buf_mem_st */
            	34, 8,
            0, 0, 0, /* 592: func */
            0, 0, 0, /* 595: func */
            0, 16, 1, /* 598: struct.asn1_type_st */
            	563, 8,
            0, 24, 1, /* 603: struct.ASN1_ENCODING_st */
            	34, 0,
            0, 0, 0, /* 608: func */
            0, 0, 0, /* 611: func */
            0, 0, 0, /* 614: func */
            0, 0, 0, /* 617: func */
            0, 8, 0, /* 620: long */
            0, 0, 0, /* 623: func */
            0, 24, 3, /* 626: struct.X509_pubkey_st */
            	635, 0,
            	73, 8,
            	146, 16,
            1, 8, 1, /* 635: pointer.struct.X509_algor_st */
            	640, 0,
            0, 16, 2, /* 640: struct.X509_algor_st */
            	20, 0,
            	647, 8,
            1, 8, 1, /* 647: pointer.struct.asn1_type_st */
            	598, 0,
            1, 8, 1, /* 652: pointer.struct.x509_cert_aux_st */
            	657, 0,
            0, 40, 5, /* 657: struct.x509_cert_aux_st */
            	39, 0,
            	39, 8,
            	73, 16,
            	73, 24,
            	39, 32,
            0, 0, 0, /* 670: func */
            0, 0, 0, /* 673: func */
            0, 104, 11, /* 676: struct.x509_cinf_st */
            	73, 0,
            	73, 8,
            	635, 16,
            	701, 24,
            	715, 32,
            	701, 40,
            	727, 48,
            	73, 56,
            	73, 64,
            	39, 72,
            	603, 80,
            1, 8, 1, /* 701: pointer.struct.X509_name_st */
            	706, 0,
            0, 40, 3, /* 706: struct.X509_name_st */
            	39, 0,
            	582, 16,
            	34, 24,
            1, 8, 1, /* 715: pointer.struct.X509_val_st */
            	720, 0,
            0, 16, 2, /* 720: struct.X509_val_st */
            	73, 0,
            	73, 8,
            1, 8, 1, /* 727: pointer.struct.X509_pubkey_st */
            	626, 0,
            1, 8, 1, /* 732: pointer.struct.x509_cinf_st */
            	676, 0,
            1, 8, 1, /* 737: pointer.struct.NAME_CONSTRAINTS_st */
            	742, 0,
            0, 16, 2, /* 742: struct.NAME_CONSTRAINTS_st */
            	39, 0,
            	39, 8,
            1, 8, 1, /* 749: pointer.struct.x509_st */
            	754, 0,
            0, 184, 12, /* 754: struct.x509_st */
            	732, 0,
            	635, 8,
            	73, 16,
            	34, 32,
            	88, 40,
            	73, 104,
            	83, 112,
            	568, 120,
            	39, 128,
            	39, 136,
            	737, 144,
            	652, 176,
            0, 0, 0, /* 781: func */
            0, 1, 0, /* 784: char */
            0, 0, 0, /* 787: func */
            0, 0, 0, /* 790: func */
            0, 0, 0, /* 793: func */
            0, 0, 0, /* 796: func */
            0, 0, 0, /* 799: func */
            0, 0, 0, /* 802: func */
            0, 0, 0, /* 805: func */
            0, 0, 0, /* 808: func */
            0, 0, 0, /* 811: func */
            0, 0, 0, /* 814: func */
            0, 0, 0, /* 817: func */
            0, 0, 0, /* 820: func */
            0, 0, 0, /* 823: func */
            0, 0, 0, /* 826: func */
            0, 0, 0, /* 829: func */
            0, 0, 0, /* 832: func */
            0, 0, 0, /* 835: func */
            0, 0, 0, /* 838: func */
            0, 0, 0, /* 841: func */
            0, 0, 0, /* 844: func */
            0, 0, 0, /* 847: func */
            0, 0, 0, /* 850: func */
            0, 0, 0, /* 853: func */
            0, 0, 0, /* 856: func */
            0, 0, 0, /* 859: func */
            0, 0, 0, /* 862: func */
            0, 8, 0, /* 865: pointer.void */
            0, 0, 0, /* 868: func */
            0, 0, 0, /* 871: func */
            0, 0, 0, /* 874: func */
            0, 0, 0, /* 877: func */
        },
        .arg_entity_index = { 749, 5, 0, 0, },
        .ret_entity_index = 865,
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

