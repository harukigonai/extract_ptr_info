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
            0, 16, 2, /* 0: struct.NAME_CONSTRAINTS_st */
            	7, 0,
            	7, 8,
            1, 8, 1, /* 7: pointer.struct.stack_st_OPENSSL_STRING */
            	12, 0,
            0, 32, 1, /* 12: struct.stack_st_OPENSSL_STRING */
            	17, 0,
            0, 32, 2, /* 17: struct.stack_st */
            	24, 8,
            	34, 24,
            1, 8, 1, /* 24: pointer.pointer.char */
            	29, 0,
            1, 8, 1, /* 29: pointer.char */
            	4096, 0,
            4097, 8, 0, /* 34: pointer.func */
            0, 32, 3, /* 37: struct.X509_POLICY_DATA_st */
            	46, 8,
            	7, 16,
            	7, 24,
            1, 8, 1, /* 46: pointer.struct.asn1_object_st */
            	51, 0,
            0, 40, 3, /* 51: struct.asn1_object_st */
            	29, 0,
            	29, 8,
            	29, 24,
            1, 8, 1, /* 60: pointer.struct.X509_POLICY_DATA_st */
            	37, 0,
            1, 8, 1, /* 65: pointer.struct.X509_POLICY_CACHE_st */
            	70, 0,
            0, 40, 2, /* 70: struct.X509_POLICY_CACHE_st */
            	60, 0,
            	7, 8,
            0, 24, 3, /* 77: struct.AUTHORITY_KEYID_st */
            	86, 0,
            	7, 8,
            	86, 16,
            1, 8, 1, /* 86: pointer.struct.asn1_string_st */
            	91, 0,
            0, 24, 1, /* 91: struct.asn1_string_st */
            	29, 8,
            0, 16, 1, /* 96: struct.crypto_ex_data_st */
            	7, 0,
            0, 32, 2, /* 101: struct.ENGINE_CMD_DEFN_st */
            	29, 8,
            	29, 16,
            1, 8, 1, /* 108: pointer.struct.ENGINE_CMD_DEFN_st */
            	101, 0,
            4097, 8, 0, /* 113: pointer.func */
            4097, 8, 0, /* 116: pointer.func */
            4097, 8, 0, /* 119: pointer.func */
            4097, 8, 0, /* 122: pointer.func */
            4097, 8, 0, /* 125: pointer.func */
            4097, 8, 0, /* 128: pointer.func */
            4097, 8, 0, /* 131: pointer.func */
            4097, 8, 0, /* 134: pointer.func */
            4097, 8, 0, /* 137: pointer.func */
            4097, 8, 0, /* 140: pointer.func */
            0, 48, 5, /* 143: struct.ecdsa_method */
            	29, 0,
            	137, 8,
            	156, 16,
            	159, 24,
            	29, 40,
            4097, 8, 0, /* 156: pointer.func */
            4097, 8, 0, /* 159: pointer.func */
            1, 8, 1, /* 162: pointer.struct.ecdsa_method */
            	143, 0,
            4097, 8, 0, /* 167: pointer.func */
            0, 32, 3, /* 170: struct.ecdh_method */
            	29, 0,
            	167, 8,
            	29, 24,
            1, 8, 1, /* 179: pointer.struct.ecdh_method */
            	170, 0,
            4097, 8, 0, /* 184: pointer.func */
            0, 72, 8, /* 187: struct.dh_method */
            	29, 0,
            	206, 8,
            	209, 16,
            	184, 24,
            	206, 32,
            	206, 40,
            	29, 56,
            	212, 64,
            4097, 8, 0, /* 206: pointer.func */
            4097, 8, 0, /* 209: pointer.func */
            4097, 8, 0, /* 212: pointer.func */
            1, 8, 1, /* 215: pointer.struct.dh_method */
            	187, 0,
            4097, 8, 0, /* 220: pointer.func */
            4097, 8, 0, /* 223: pointer.func */
            4097, 8, 0, /* 226: pointer.func */
            4097, 8, 0, /* 229: pointer.func */
            0, 96, 11, /* 232: struct.dsa_method */
            	29, 0,
            	229, 8,
            	257, 16,
            	260, 24,
            	263, 32,
            	226, 40,
            	223, 48,
            	223, 56,
            	29, 72,
            	220, 80,
            	223, 88,
            4097, 8, 0, /* 257: pointer.func */
            4097, 8, 0, /* 260: pointer.func */
            4097, 8, 0, /* 263: pointer.func */
            1, 8, 1, /* 266: pointer.struct.dsa_method */
            	232, 0,
            4097, 8, 0, /* 271: pointer.func */
            4097, 8, 0, /* 274: pointer.func */
            4097, 8, 0, /* 277: pointer.func */
            0, 112, 13, /* 280: struct.rsa_meth_st */
            	29, 0,
            	309, 8,
            	309, 16,
            	309, 24,
            	309, 32,
            	312, 40,
            	315, 48,
            	318, 56,
            	318, 64,
            	29, 80,
            	321, 88,
            	274, 96,
            	271, 104,
            4097, 8, 0, /* 309: pointer.func */
            4097, 8, 0, /* 312: pointer.func */
            4097, 8, 0, /* 315: pointer.func */
            4097, 8, 0, /* 318: pointer.func */
            4097, 8, 0, /* 321: pointer.func */
            0, 24, 1, /* 324: struct.buf_mem_st */
            	29, 8,
            4097, 8, 0, /* 329: pointer.func */
            1, 8, 1, /* 332: pointer.struct.X509_name_st */
            	337, 0,
            0, 40, 3, /* 337: struct.X509_name_st */
            	7, 0,
            	346, 16,
            	29, 24,
            1, 8, 1, /* 346: pointer.struct.buf_mem_st */
            	324, 0,
            0, 8, 1, /* 351: struct.fnames */
            	29, 0,
            1, 8, 1, /* 356: pointer.struct.store_method_st */
            	361, 0,
            0, 0, 0, /* 361: struct.store_method_st */
            1, 8, 1, /* 364: pointer.struct.asn1_type_st */
            	369, 0,
            0, 16, 1, /* 369: struct.asn1_type_st */
            	351, 8,
            0, 184, 12, /* 374: struct.x509_st */
            	401, 0,
            	431, 8,
            	86, 16,
            	29, 32,
            	96, 40,
            	86, 104,
            	680, 112,
            	65, 120,
            	7, 128,
            	7, 136,
            	685, 144,
            	690, 176,
            1, 8, 1, /* 401: pointer.struct.x509_cinf_st */
            	406, 0,
            0, 104, 11, /* 406: struct.x509_cinf_st */
            	86, 0,
            	86, 8,
            	431, 16,
            	332, 24,
            	443, 32,
            	332, 40,
            	455, 48,
            	86, 56,
            	86, 64,
            	7, 72,
            	675, 80,
            1, 8, 1, /* 431: pointer.struct.X509_algor_st */
            	436, 0,
            0, 16, 2, /* 436: struct.X509_algor_st */
            	46, 0,
            	364, 8,
            1, 8, 1, /* 443: pointer.struct.X509_val_st */
            	448, 0,
            0, 16, 2, /* 448: struct.X509_val_st */
            	86, 0,
            	86, 8,
            1, 8, 1, /* 455: pointer.struct.X509_pubkey_st */
            	460, 0,
            0, 24, 3, /* 460: struct.X509_pubkey_st */
            	431, 0,
            	86, 8,
            	469, 16,
            1, 8, 1, /* 469: pointer.struct.evp_pkey_st */
            	474, 0,
            0, 56, 4, /* 474: struct.evp_pkey_st */
            	485, 16,
            	588, 24,
            	351, 32,
            	7, 48,
            1, 8, 1, /* 485: pointer.struct.evp_pkey_asn1_method_st */
            	490, 0,
            0, 208, 24, /* 490: struct.evp_pkey_asn1_method_st */
            	29, 16,
            	29, 24,
            	541, 32,
            	549, 40,
            	552, 48,
            	555, 56,
            	558, 64,
            	561, 72,
            	555, 80,
            	564, 88,
            	564, 96,
            	567, 104,
            	570, 112,
            	564, 120,
            	552, 128,
            	552, 136,
            	555, 144,
            	573, 152,
            	576, 160,
            	579, 168,
            	567, 176,
            	570, 184,
            	582, 192,
            	585, 200,
            1, 8, 1, /* 541: pointer.struct.unnamed */
            	546, 0,
            0, 0, 0, /* 546: struct.unnamed */
            4097, 8, 0, /* 549: pointer.func */
            4097, 8, 0, /* 552: pointer.func */
            4097, 8, 0, /* 555: pointer.func */
            4097, 8, 0, /* 558: pointer.func */
            4097, 8, 0, /* 561: pointer.func */
            4097, 8, 0, /* 564: pointer.func */
            4097, 8, 0, /* 567: pointer.func */
            4097, 8, 0, /* 570: pointer.func */
            4097, 8, 0, /* 573: pointer.func */
            4097, 8, 0, /* 576: pointer.func */
            4097, 8, 0, /* 579: pointer.func */
            4097, 8, 0, /* 582: pointer.func */
            4097, 8, 0, /* 585: pointer.func */
            1, 8, 1, /* 588: pointer.struct.engine_st */
            	593, 0,
            0, 216, 24, /* 593: struct.engine_st */
            	29, 0,
            	29, 8,
            	644, 16,
            	266, 24,
            	215, 32,
            	179, 40,
            	162, 48,
            	649, 56,
            	356, 64,
            	140, 72,
            	669, 80,
            	672, 88,
            	277, 96,
            	122, 104,
            	122, 112,
            	122, 120,
            	119, 128,
            	116, 136,
            	116, 144,
            	113, 152,
            	108, 160,
            	96, 184,
            	588, 200,
            	588, 208,
            1, 8, 1, /* 644: pointer.struct.rsa_meth_st */
            	280, 0,
            1, 8, 1, /* 649: pointer.struct.rand_meth_st */
            	654, 0,
            0, 48, 6, /* 654: struct.rand_meth_st */
            	329, 0,
            	134, 8,
            	131, 16,
            	128, 24,
            	134, 32,
            	125, 40,
            4097, 8, 0, /* 669: pointer.func */
            4097, 8, 0, /* 672: pointer.func */
            0, 24, 1, /* 675: struct.ASN1_ENCODING_st */
            	29, 0,
            1, 8, 1, /* 680: pointer.struct.AUTHORITY_KEYID_st */
            	77, 0,
            1, 8, 1, /* 685: pointer.struct.NAME_CONSTRAINTS_st */
            	0, 0,
            1, 8, 1, /* 690: pointer.struct.x509_cert_aux_st */
            	695, 0,
            0, 40, 5, /* 695: struct.x509_cert_aux_st */
            	7, 0,
            	7, 8,
            	86, 16,
            	86, 24,
            	7, 32,
            0, 8, 0, /* 708: pointer.void */
            0, 4, 0, /* 711: int */
            0, 1, 0, /* 714: char */
            1, 8, 1, /* 717: pointer.struct.x509_st */
            	374, 0,
            1, 8, 1, /* 722: pointer.int */
            	711, 0,
        },
        .arg_entity_index = { 717, 711, 722, 722, },
        .ret_entity_index = 708,
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

