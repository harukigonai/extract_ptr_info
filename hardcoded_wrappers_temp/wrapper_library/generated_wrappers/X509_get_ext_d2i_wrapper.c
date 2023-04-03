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
            0, 8, 0, /* 0: pointer.void */
            1, 8, 1, /* 3: pointer.int */
            	8, 0,
            0, 4, 0, /* 8: int */
            0, 20, 0, /* 11: array[20].char */
            0, 32, 3, /* 14: struct.X509_POLICY_DATA_st */
            	23, 8,
            	42, 16,
            	42, 24,
            1, 8, 1, /* 23: pointer.struct.asn1_object_st */
            	28, 0,
            0, 40, 3, /* 28: struct.asn1_object_st */
            	37, 0,
            	37, 8,
            	37, 24,
            1, 8, 1, /* 37: pointer.char */
            	4096, 0,
            1, 8, 1, /* 42: pointer.struct.stack_st_OPENSSL_STRING */
            	47, 0,
            0, 32, 1, /* 47: struct.stack_st_OPENSSL_STRING */
            	52, 0,
            0, 32, 2, /* 52: struct.stack_st */
            	59, 8,
            	64, 24,
            1, 8, 1, /* 59: pointer.pointer.char */
            	37, 0,
            4097, 8, 0, /* 64: pointer.func */
            0, 24, 3, /* 67: struct.AUTHORITY_KEYID_st */
            	76, 0,
            	42, 8,
            	76, 16,
            1, 8, 1, /* 76: pointer.struct.asn1_string_st */
            	81, 0,
            0, 24, 1, /* 81: struct.asn1_string_st */
            	37, 8,
            1, 8, 1, /* 86: pointer.struct.AUTHORITY_KEYID_st */
            	67, 0,
            0, 16, 1, /* 91: struct.crypto_ex_data_st */
            	42, 0,
            0, 0, 0, /* 96: func */
            4097, 8, 0, /* 99: pointer.func */
            0, 0, 0, /* 102: func */
            0, 0, 0, /* 105: func */
            4097, 8, 0, /* 108: pointer.func */
            0, 0, 0, /* 111: func */
            4097, 8, 0, /* 114: pointer.func */
            0, 0, 0, /* 117: struct.store_method_st */
            1, 8, 1, /* 120: pointer.struct.store_method_st */
            	117, 0,
            0, 0, 0, /* 125: func */
            4097, 8, 0, /* 128: pointer.func */
            4097, 8, 0, /* 131: pointer.func */
            0, 40, 2, /* 134: struct.X509_POLICY_CACHE_st */
            	141, 0,
            	42, 8,
            1, 8, 1, /* 141: pointer.struct.X509_POLICY_DATA_st */
            	14, 0,
            0, 0, 0, /* 146: func */
            1, 8, 1, /* 149: pointer.struct.evp_pkey_st */
            	154, 0,
            0, 56, 4, /* 154: struct.evp_pkey_st */
            	165, 16,
            	268, 24,
            	566, 32,
            	42, 48,
            1, 8, 1, /* 165: pointer.struct.evp_pkey_asn1_method_st */
            	170, 0,
            0, 208, 24, /* 170: struct.evp_pkey_asn1_method_st */
            	37, 16,
            	37, 24,
            	221, 32,
            	229, 40,
            	232, 48,
            	235, 56,
            	238, 64,
            	241, 72,
            	235, 80,
            	244, 88,
            	244, 96,
            	247, 104,
            	250, 112,
            	244, 120,
            	232, 128,
            	232, 136,
            	235, 144,
            	253, 152,
            	256, 160,
            	259, 168,
            	247, 176,
            	250, 184,
            	262, 192,
            	265, 200,
            1, 8, 1, /* 221: pointer.struct.unnamed */
            	226, 0,
            0, 0, 0, /* 226: struct.unnamed */
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
            4097, 8, 0, /* 265: pointer.func */
            1, 8, 1, /* 268: pointer.struct.engine_st */
            	273, 0,
            0, 216, 24, /* 273: struct.engine_st */
            	37, 0,
            	37, 8,
            	324, 16,
            	379, 24,
            	430, 32,
            	466, 40,
            	483, 48,
            	510, 56,
            	120, 64,
            	114, 72,
            	539, 80,
            	542, 88,
            	108, 96,
            	545, 104,
            	545, 112,
            	545, 120,
            	99, 128,
            	548, 136,
            	548, 144,
            	551, 152,
            	554, 160,
            	91, 184,
            	268, 200,
            	268, 208,
            1, 8, 1, /* 324: pointer.struct.rsa_meth_st */
            	329, 0,
            0, 112, 13, /* 329: struct.rsa_meth_st */
            	37, 0,
            	358, 8,
            	358, 16,
            	358, 24,
            	358, 32,
            	361, 40,
            	364, 48,
            	367, 56,
            	367, 64,
            	37, 80,
            	370, 88,
            	373, 96,
            	376, 104,
            4097, 8, 0, /* 358: pointer.func */
            4097, 8, 0, /* 361: pointer.func */
            4097, 8, 0, /* 364: pointer.func */
            4097, 8, 0, /* 367: pointer.func */
            4097, 8, 0, /* 370: pointer.func */
            4097, 8, 0, /* 373: pointer.func */
            4097, 8, 0, /* 376: pointer.func */
            1, 8, 1, /* 379: pointer.struct.dsa_method */
            	384, 0,
            0, 96, 11, /* 384: struct.dsa_method */
            	37, 0,
            	409, 8,
            	412, 16,
            	415, 24,
            	418, 32,
            	421, 40,
            	424, 48,
            	424, 56,
            	37, 72,
            	427, 80,
            	424, 88,
            4097, 8, 0, /* 409: pointer.func */
            4097, 8, 0, /* 412: pointer.func */
            4097, 8, 0, /* 415: pointer.func */
            4097, 8, 0, /* 418: pointer.func */
            4097, 8, 0, /* 421: pointer.func */
            4097, 8, 0, /* 424: pointer.func */
            4097, 8, 0, /* 427: pointer.func */
            1, 8, 1, /* 430: pointer.struct.dh_method */
            	435, 0,
            0, 72, 8, /* 435: struct.dh_method */
            	37, 0,
            	454, 8,
            	457, 16,
            	460, 24,
            	454, 32,
            	454, 40,
            	37, 56,
            	463, 64,
            4097, 8, 0, /* 454: pointer.func */
            4097, 8, 0, /* 457: pointer.func */
            4097, 8, 0, /* 460: pointer.func */
            4097, 8, 0, /* 463: pointer.func */
            1, 8, 1, /* 466: pointer.struct.ecdh_method */
            	471, 0,
            0, 32, 3, /* 471: struct.ecdh_method */
            	37, 0,
            	480, 8,
            	37, 24,
            4097, 8, 0, /* 480: pointer.func */
            1, 8, 1, /* 483: pointer.struct.ecdsa_method */
            	488, 0,
            0, 48, 5, /* 488: struct.ecdsa_method */
            	37, 0,
            	501, 8,
            	504, 16,
            	507, 24,
            	37, 40,
            4097, 8, 0, /* 501: pointer.func */
            4097, 8, 0, /* 504: pointer.func */
            4097, 8, 0, /* 507: pointer.func */
            1, 8, 1, /* 510: pointer.struct.rand_meth_st */
            	515, 0,
            0, 48, 6, /* 515: struct.rand_meth_st */
            	530, 0,
            	533, 8,
            	536, 16,
            	131, 24,
            	533, 32,
            	128, 40,
            4097, 8, 0, /* 530: pointer.func */
            4097, 8, 0, /* 533: pointer.func */
            4097, 8, 0, /* 536: pointer.func */
            4097, 8, 0, /* 539: pointer.func */
            4097, 8, 0, /* 542: pointer.func */
            4097, 8, 0, /* 545: pointer.func */
            4097, 8, 0, /* 548: pointer.func */
            4097, 8, 0, /* 551: pointer.func */
            1, 8, 1, /* 554: pointer.struct.ENGINE_CMD_DEFN_st */
            	559, 0,
            0, 32, 2, /* 559: struct.ENGINE_CMD_DEFN_st */
            	37, 8,
            	37, 16,
            0, 8, 1, /* 566: struct.fnames */
            	37, 0,
            1, 8, 1, /* 571: pointer.struct.X509_POLICY_CACHE_st */
            	134, 0,
            0, 0, 0, /* 576: func */
            0, 0, 0, /* 579: func */
            0, 0, 0, /* 582: func */
            1, 8, 1, /* 585: pointer.struct.buf_mem_st */
            	590, 0,
            0, 24, 1, /* 590: struct.buf_mem_st */
            	37, 8,
            0, 0, 0, /* 595: func */
            0, 0, 0, /* 598: func */
            0, 16, 1, /* 601: struct.asn1_type_st */
            	566, 8,
            0, 24, 1, /* 606: struct.ASN1_ENCODING_st */
            	37, 0,
            0, 0, 0, /* 611: func */
            0, 0, 0, /* 614: func */
            0, 0, 0, /* 617: func */
            0, 0, 0, /* 620: func */
            0, 8, 0, /* 623: long */
            0, 0, 0, /* 626: func */
            0, 24, 3, /* 629: struct.X509_pubkey_st */
            	638, 0,
            	76, 8,
            	149, 16,
            1, 8, 1, /* 638: pointer.struct.X509_algor_st */
            	643, 0,
            0, 16, 2, /* 643: struct.X509_algor_st */
            	23, 0,
            	650, 8,
            1, 8, 1, /* 650: pointer.struct.asn1_type_st */
            	601, 0,
            1, 8, 1, /* 655: pointer.struct.x509_cert_aux_st */
            	660, 0,
            0, 40, 5, /* 660: struct.x509_cert_aux_st */
            	42, 0,
            	42, 8,
            	76, 16,
            	76, 24,
            	42, 32,
            0, 0, 0, /* 673: func */
            0, 0, 0, /* 676: func */
            0, 104, 11, /* 679: struct.x509_cinf_st */
            	76, 0,
            	76, 8,
            	638, 16,
            	704, 24,
            	718, 32,
            	704, 40,
            	730, 48,
            	76, 56,
            	76, 64,
            	42, 72,
            	606, 80,
            1, 8, 1, /* 704: pointer.struct.X509_name_st */
            	709, 0,
            0, 40, 3, /* 709: struct.X509_name_st */
            	42, 0,
            	585, 16,
            	37, 24,
            1, 8, 1, /* 718: pointer.struct.X509_val_st */
            	723, 0,
            0, 16, 2, /* 723: struct.X509_val_st */
            	76, 0,
            	76, 8,
            1, 8, 1, /* 730: pointer.struct.X509_pubkey_st */
            	629, 0,
            1, 8, 1, /* 735: pointer.struct.x509_cinf_st */
            	679, 0,
            1, 8, 1, /* 740: pointer.struct.NAME_CONSTRAINTS_st */
            	745, 0,
            0, 16, 2, /* 745: struct.NAME_CONSTRAINTS_st */
            	42, 0,
            	42, 8,
            1, 8, 1, /* 752: pointer.struct.x509_st */
            	757, 0,
            0, 184, 12, /* 757: struct.x509_st */
            	735, 0,
            	638, 8,
            	76, 16,
            	37, 32,
            	91, 40,
            	76, 104,
            	86, 112,
            	571, 120,
            	42, 128,
            	42, 136,
            	740, 144,
            	655, 176,
            0, 0, 0, /* 784: func */
            0, 1, 0, /* 787: char */
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
            0, 0, 0, /* 865: func */
            0, 0, 0, /* 868: func */
            0, 0, 0, /* 871: func */
            0, 0, 0, /* 874: func */
            0, 0, 0, /* 877: func */
        },
        .arg_entity_index = { 752, 8, 3, 3, },
        .ret_entity_index = 0,
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

