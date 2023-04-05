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
            1, 8, 1, /* 0: pointer.struct.stack_st_X509_ALGOR */
            	5, 0,
            0, 32, 1, /* 5: struct.stack_st_X509_ALGOR */
            	10, 0,
            0, 32, 2, /* 10: struct.stack_st */
            	17, 8,
            	27, 24,
            1, 8, 1, /* 17: pointer.pointer.char */
            	22, 0,
            1, 8, 1, /* 22: pointer.char */
            	4096, 0,
            4097, 8, 0, /* 27: pointer.func */
            1, 8, 1, /* 30: pointer.struct.stack_st_ASN1_OBJECT */
            	35, 0,
            0, 32, 1, /* 35: struct.stack_st_ASN1_OBJECT */
            	10, 0,
            0, 40, 5, /* 40: struct.x509_cert_aux_st */
            	30, 0,
            	30, 8,
            	53, 16,
            	71, 24,
            	0, 32,
            1, 8, 1, /* 53: pointer.struct.asn1_string_st */
            	58, 0,
            0, 24, 1, /* 58: struct.asn1_string_st */
            	63, 8,
            1, 8, 1, /* 63: pointer.unsigned char */
            	68, 0,
            0, 1, 0, /* 68: unsigned char */
            1, 8, 1, /* 71: pointer.struct.asn1_string_st */
            	58, 0,
            1, 8, 1, /* 76: pointer.struct.NAME_CONSTRAINTS_st */
            	81, 0,
            0, 16, 2, /* 81: struct.NAME_CONSTRAINTS_st */
            	88, 0,
            	88, 8,
            1, 8, 1, /* 88: pointer.struct.stack_st_GENERAL_SUBTREE */
            	93, 0,
            0, 32, 1, /* 93: struct.stack_st_GENERAL_SUBTREE */
            	10, 0,
            0, 24, 3, /* 98: struct.AUTHORITY_KEYID_st */
            	71, 0,
            	107, 8,
            	117, 16,
            1, 8, 1, /* 107: pointer.struct.stack_st_GENERAL_NAME */
            	112, 0,
            0, 32, 1, /* 112: struct.stack_st_GENERAL_NAME */
            	10, 0,
            1, 8, 1, /* 117: pointer.struct.asn1_string_st */
            	58, 0,
            1, 8, 1, /* 122: pointer.struct.stack_st_X509_ATTRIBUTE */
            	127, 0,
            0, 32, 1, /* 127: struct.stack_st_X509_ATTRIBUTE */
            	10, 0,
            1, 8, 1, /* 132: pointer.struct.ec_key_st */
            	137, 0,
            0, 0, 0, /* 137: struct.ec_key_st */
            4097, 8, 0, /* 140: pointer.func */
            4097, 8, 0, /* 143: pointer.func */
            4097, 8, 0, /* 146: pointer.func */
            4097, 8, 0, /* 149: pointer.func */
            4097, 8, 0, /* 152: pointer.func */
            0, 96, 11, /* 155: struct.dsa_method */
            	180, 0,
            	185, 8,
            	188, 16,
            	152, 24,
            	149, 32,
            	146, 40,
            	143, 48,
            	143, 56,
            	22, 72,
            	191, 80,
            	143, 88,
            1, 8, 1, /* 180: pointer.char */
            	4096, 0,
            4097, 8, 0, /* 185: pointer.func */
            4097, 8, 0, /* 188: pointer.func */
            4097, 8, 0, /* 191: pointer.func */
            1, 8, 1, /* 194: pointer.struct.dsa_method */
            	155, 0,
            0, 136, 11, /* 199: struct.dsa_st */
            	224, 24,
            	224, 32,
            	224, 40,
            	224, 48,
            	224, 56,
            	224, 64,
            	224, 72,
            	242, 88,
            	256, 104,
            	194, 120,
            	271, 128,
            1, 8, 1, /* 224: pointer.struct.bignum_st */
            	229, 0,
            0, 24, 1, /* 229: struct.bignum_st */
            	234, 0,
            1, 8, 1, /* 234: pointer.unsigned int */
            	239, 0,
            0, 4, 0, /* 239: unsigned int */
            1, 8, 1, /* 242: pointer.struct.bn_mont_ctx_st */
            	247, 0,
            0, 96, 3, /* 247: struct.bn_mont_ctx_st */
            	229, 8,
            	229, 32,
            	229, 56,
            0, 16, 1, /* 256: struct.crypto_ex_data_st */
            	261, 0,
            1, 8, 1, /* 261: pointer.struct.stack_st_void */
            	266, 0,
            0, 32, 1, /* 266: struct.stack_st_void */
            	10, 0,
            1, 8, 1, /* 271: pointer.struct.engine_st */
            	276, 0,
            0, 0, 0, /* 276: struct.engine_st */
            1, 8, 1, /* 279: pointer.struct.dsa_st */
            	199, 0,
            1, 8, 1, /* 284: pointer.struct.bn_blinding_st */
            	289, 0,
            0, 0, 0, /* 289: struct.bn_blinding_st */
            0, 24, 1, /* 292: struct.ASN1_ENCODING_st */
            	63, 0,
            4097, 8, 0, /* 297: pointer.func */
            4097, 8, 0, /* 300: pointer.func */
            4097, 8, 0, /* 303: pointer.func */
            4097, 8, 0, /* 306: pointer.func */
            0, 112, 13, /* 309: struct.rsa_meth_st */
            	180, 0,
            	306, 8,
            	306, 16,
            	306, 24,
            	306, 32,
            	338, 40,
            	303, 48,
            	300, 56,
            	300, 64,
            	22, 80,
            	341, 88,
            	297, 96,
            	344, 104,
            4097, 8, 0, /* 338: pointer.func */
            4097, 8, 0, /* 341: pointer.func */
            4097, 8, 0, /* 344: pointer.func */
            0, 168, 17, /* 347: struct.rsa_st */
            	384, 16,
            	271, 24,
            	224, 32,
            	224, 40,
            	224, 48,
            	224, 56,
            	224, 64,
            	224, 72,
            	224, 80,
            	224, 88,
            	256, 96,
            	242, 120,
            	242, 128,
            	242, 136,
            	22, 144,
            	284, 152,
            	284, 160,
            1, 8, 1, /* 384: pointer.struct.rsa_meth_st */
            	309, 0,
            1, 8, 1, /* 389: pointer.struct.asn1_string_st */
            	58, 0,
            1, 8, 1, /* 394: pointer.struct.stack_st_GENERAL_NAME */
            	112, 0,
            0, 24, 1, /* 399: struct.buf_mem_st */
            	22, 8,
            1, 8, 1, /* 404: pointer.struct.asn1_string_st */
            	58, 0,
            0, 0, 0, /* 409: struct.X509_POLICY_CACHE_st */
            1, 8, 1, /* 412: pointer.struct.x509_st */
            	417, 0,
            0, 184, 12, /* 417: struct.x509_st */
            	444, 0,
            	474, 8,
            	568, 16,
            	22, 32,
            	256, 40,
            	71, 104,
            	793, 112,
            	798, 120,
            	803, 128,
            	394, 136,
            	76, 144,
            	813, 176,
            1, 8, 1, /* 444: pointer.struct.x509_cinf_st */
            	449, 0,
            0, 104, 11, /* 449: struct.x509_cinf_st */
            	117, 0,
            	117, 8,
            	474, 16,
            	616, 24,
            	645, 32,
            	616, 40,
            	662, 48,
            	568, 56,
            	568, 64,
            	783, 72,
            	292, 80,
            1, 8, 1, /* 474: pointer.struct.X509_algor_st */
            	479, 0,
            0, 16, 2, /* 479: struct.X509_algor_st */
            	486, 0,
            	505, 8,
            1, 8, 1, /* 486: pointer.struct.asn1_object_st */
            	491, 0,
            0, 40, 3, /* 491: struct.asn1_object_st */
            	180, 0,
            	180, 8,
            	500, 24,
            1, 8, 1, /* 500: pointer.unsigned char */
            	68, 0,
            1, 8, 1, /* 505: pointer.struct.asn1_type_st */
            	510, 0,
            0, 16, 1, /* 510: struct.asn1_type_st */
            	515, 8,
            0, 8, 20, /* 515: union.unknown */
            	22, 0,
            	558, 0,
            	486, 0,
            	117, 0,
            	563, 0,
            	568, 0,
            	71, 0,
            	404, 0,
            	573, 0,
            	389, 0,
            	578, 0,
            	583, 0,
            	588, 0,
            	593, 0,
            	598, 0,
            	603, 0,
            	53, 0,
            	558, 0,
            	558, 0,
            	608, 0,
            1, 8, 1, /* 558: pointer.struct.asn1_string_st */
            	58, 0,
            1, 8, 1, /* 563: pointer.struct.asn1_string_st */
            	58, 0,
            1, 8, 1, /* 568: pointer.struct.asn1_string_st */
            	58, 0,
            1, 8, 1, /* 573: pointer.struct.asn1_string_st */
            	58, 0,
            1, 8, 1, /* 578: pointer.struct.asn1_string_st */
            	58, 0,
            1, 8, 1, /* 583: pointer.struct.asn1_string_st */
            	58, 0,
            1, 8, 1, /* 588: pointer.struct.asn1_string_st */
            	58, 0,
            1, 8, 1, /* 593: pointer.struct.asn1_string_st */
            	58, 0,
            1, 8, 1, /* 598: pointer.struct.asn1_string_st */
            	58, 0,
            1, 8, 1, /* 603: pointer.struct.asn1_string_st */
            	58, 0,
            1, 8, 1, /* 608: pointer.struct.ASN1_VALUE_st */
            	613, 0,
            0, 0, 0, /* 613: struct.ASN1_VALUE_st */
            1, 8, 1, /* 616: pointer.struct.X509_name_st */
            	621, 0,
            0, 40, 3, /* 621: struct.X509_name_st */
            	630, 0,
            	640, 16,
            	63, 24,
            1, 8, 1, /* 630: pointer.struct.stack_st_X509_NAME_ENTRY */
            	635, 0,
            0, 32, 1, /* 635: struct.stack_st_X509_NAME_ENTRY */
            	10, 0,
            1, 8, 1, /* 640: pointer.struct.buf_mem_st */
            	399, 0,
            1, 8, 1, /* 645: pointer.struct.X509_val_st */
            	650, 0,
            0, 16, 2, /* 650: struct.X509_val_st */
            	657, 0,
            	657, 8,
            1, 8, 1, /* 657: pointer.struct.asn1_string_st */
            	58, 0,
            1, 8, 1, /* 662: pointer.struct.X509_pubkey_st */
            	667, 0,
            0, 24, 3, /* 667: struct.X509_pubkey_st */
            	474, 0,
            	568, 8,
            	676, 16,
            1, 8, 1, /* 676: pointer.struct.evp_pkey_st */
            	681, 0,
            0, 56, 4, /* 681: struct.evp_pkey_st */
            	692, 16,
            	271, 24,
            	700, 32,
            	122, 48,
            1, 8, 1, /* 692: pointer.struct.evp_pkey_asn1_method_st */
            	697, 0,
            0, 0, 0, /* 697: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 700: union.unknown */
            	22, 0,
            	713, 0,
            	279, 0,
            	718, 0,
            	132, 0,
            1, 8, 1, /* 713: pointer.struct.rsa_st */
            	347, 0,
            1, 8, 1, /* 718: pointer.struct.dh_st */
            	723, 0,
            0, 144, 12, /* 723: struct.dh_st */
            	224, 8,
            	224, 16,
            	224, 32,
            	224, 40,
            	242, 56,
            	224, 64,
            	224, 72,
            	63, 80,
            	224, 96,
            	256, 112,
            	750, 128,
            	271, 136,
            1, 8, 1, /* 750: pointer.struct.dh_method */
            	755, 0,
            0, 72, 8, /* 755: struct.dh_method */
            	180, 0,
            	774, 8,
            	777, 16,
            	140, 24,
            	774, 32,
            	774, 40,
            	22, 56,
            	780, 64,
            4097, 8, 0, /* 774: pointer.func */
            4097, 8, 0, /* 777: pointer.func */
            4097, 8, 0, /* 780: pointer.func */
            1, 8, 1, /* 783: pointer.struct.stack_st_X509_EXTENSION */
            	788, 0,
            0, 32, 1, /* 788: struct.stack_st_X509_EXTENSION */
            	10, 0,
            1, 8, 1, /* 793: pointer.struct.AUTHORITY_KEYID_st */
            	98, 0,
            1, 8, 1, /* 798: pointer.struct.X509_POLICY_CACHE_st */
            	409, 0,
            1, 8, 1, /* 803: pointer.struct.stack_st_DIST_POINT */
            	808, 0,
            0, 32, 1, /* 808: struct.stack_st_DIST_POINT */
            	10, 0,
            1, 8, 1, /* 813: pointer.struct.x509_cert_aux_st */
            	40, 0,
            0, 1, 0, /* 818: char */
            0, 4, 0, /* 821: int */
            1, 8, 1, /* 824: pointer.int */
            	821, 0,
            0, 8, 0, /* 829: pointer.void */
        },
        .arg_entity_index = { 412, 821, 824, 824, },
        .ret_entity_index = 829,
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

