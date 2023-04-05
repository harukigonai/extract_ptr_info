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

EVP_PKEY * bb_PEM_read_bio_PrivateKey(BIO * arg_a,EVP_PKEY ** arg_b,pem_password_cb * arg_c,void * arg_d);

EVP_PKEY * PEM_read_bio_PrivateKey(BIO * arg_a,EVP_PKEY ** arg_b,pem_password_cb * arg_c,void * arg_d) 
{
    unsigned long in_lib = syscall(890);
    printf("PEM_read_bio_PrivateKey called %lu\n", in_lib);
    if (!in_lib)
        return bb_PEM_read_bio_PrivateKey(arg_a,arg_b,arg_c,arg_d);
    else {
        EVP_PKEY * (*orig_PEM_read_bio_PrivateKey)(BIO *,EVP_PKEY **,pem_password_cb *,void *);
        orig_PEM_read_bio_PrivateKey = dlsym(RTLD_NEXT, "PEM_read_bio_PrivateKey");
        return orig_PEM_read_bio_PrivateKey(arg_a,arg_b,arg_c,arg_d);
    }
}

EVP_PKEY * bb_PEM_read_bio_PrivateKey(BIO * arg_a,EVP_PKEY ** arg_b,pem_password_cb * arg_c,void * arg_d) 
{
    EVP_PKEY * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            8884097, 8, 0, /* 0: pointer.func */
            1, 8, 1, /* 3: pointer.struct.bio_st */
            	8, 0,
            0, 112, 7, /* 8: struct.bio_st */
            	25, 0,
            	74, 8,
            	77, 16,
            	82, 48,
            	3, 56,
            	3, 64,
            	85, 96,
            1, 8, 1, /* 25: pointer.struct.bio_method_st */
            	30, 0,
            0, 80, 9, /* 30: struct.bio_method_st */
            	51, 8,
            	56, 16,
            	59, 24,
            	62, 32,
            	59, 40,
            	65, 48,
            	68, 56,
            	68, 64,
            	71, 72,
            1, 8, 1, /* 51: pointer.char */
            	8884096, 0,
            8884097, 8, 0, /* 56: pointer.func */
            8884097, 8, 0, /* 59: pointer.func */
            8884097, 8, 0, /* 62: pointer.func */
            8884097, 8, 0, /* 65: pointer.func */
            8884097, 8, 0, /* 68: pointer.func */
            8884097, 8, 0, /* 71: pointer.func */
            8884097, 8, 0, /* 74: pointer.func */
            1, 8, 1, /* 77: pointer.char */
            	8884096, 0,
            0, 8, 0, /* 82: pointer.void */
            0, 16, 1, /* 85: struct.crypto_ex_data_st */
            	90, 0,
            1, 8, 1, /* 90: pointer.struct.stack_st_void */
            	95, 0,
            0, 32, 1, /* 95: struct.stack_st_void */
            	100, 0,
            0, 32, 2, /* 100: struct.stack_st */
            	107, 8,
            	112, 24,
            1, 8, 1, /* 107: pointer.pointer.char */
            	77, 0,
            8884097, 8, 0, /* 112: pointer.func */
            1, 8, 1, /* 115: pointer.struct.bio_st */
            	8, 0,
            1, 8, 1, /* 120: pointer.struct.asn1_string_st */
            	125, 0,
            0, 24, 1, /* 125: struct.asn1_string_st */
            	130, 8,
            1, 8, 1, /* 130: pointer.unsigned char */
            	135, 0,
            0, 1, 0, /* 135: unsigned char */
            1, 8, 1, /* 138: pointer.struct.asn1_string_st */
            	125, 0,
            8884097, 8, 0, /* 143: pointer.func */
            0, 96, 11, /* 146: struct.dsa_method */
            	51, 0,
            	171, 8,
            	174, 16,
            	177, 24,
            	180, 32,
            	183, 40,
            	186, 48,
            	186, 56,
            	77, 72,
            	189, 80,
            	186, 88,
            8884097, 8, 0, /* 171: pointer.func */
            8884097, 8, 0, /* 174: pointer.func */
            8884097, 8, 0, /* 177: pointer.func */
            8884097, 8, 0, /* 180: pointer.func */
            8884097, 8, 0, /* 183: pointer.func */
            8884097, 8, 0, /* 186: pointer.func */
            8884097, 8, 0, /* 189: pointer.func */
            1, 8, 1, /* 192: pointer.struct.rsa_meth_st */
            	197, 0,
            0, 112, 13, /* 197: struct.rsa_meth_st */
            	51, 0,
            	226, 8,
            	226, 16,
            	226, 24,
            	226, 32,
            	229, 40,
            	232, 48,
            	235, 56,
            	235, 64,
            	77, 80,
            	143, 88,
            	238, 96,
            	241, 104,
            8884097, 8, 0, /* 226: pointer.func */
            8884097, 8, 0, /* 229: pointer.func */
            8884097, 8, 0, /* 232: pointer.func */
            8884097, 8, 0, /* 235: pointer.func */
            8884097, 8, 0, /* 238: pointer.func */
            8884097, 8, 0, /* 241: pointer.func */
            1, 8, 1, /* 244: pointer.struct.dsa_method */
            	146, 0,
            0, 0, 0, /* 249: struct.bn_blinding_st */
            1, 8, 1, /* 252: pointer.struct.asn1_string_st */
            	125, 0,
            1, 8, 1, /* 257: pointer.unsigned int */
            	262, 0,
            0, 4, 0, /* 262: unsigned int */
            1, 8, 1, /* 265: pointer.struct.bignum_st */
            	270, 0,
            0, 24, 1, /* 270: struct.bignum_st */
            	257, 0,
            1, 8, 1, /* 275: pointer.struct.asn1_string_st */
            	280, 0,
            0, 24, 1, /* 280: struct.asn1_string_st */
            	130, 8,
            1, 8, 1, /* 285: pointer.struct.ASN1_VALUE_st */
            	290, 0,
            0, 0, 0, /* 290: struct.ASN1_VALUE_st */
            8884097, 8, 0, /* 293: pointer.func */
            0, 16, 1, /* 296: struct.asn1_type_st */
            	301, 8,
            0, 8, 20, /* 301: union.unknown */
            	77, 0,
            	344, 0,
            	349, 0,
            	368, 0,
            	373, 0,
            	378, 0,
            	383, 0,
            	252, 0,
            	388, 0,
            	138, 0,
            	393, 0,
            	398, 0,
            	403, 0,
            	408, 0,
            	413, 0,
            	418, 0,
            	120, 0,
            	344, 0,
            	344, 0,
            	285, 0,
            1, 8, 1, /* 344: pointer.struct.asn1_string_st */
            	125, 0,
            1, 8, 1, /* 349: pointer.struct.asn1_object_st */
            	354, 0,
            0, 40, 3, /* 354: struct.asn1_object_st */
            	51, 0,
            	51, 8,
            	363, 24,
            1, 8, 1, /* 363: pointer.unsigned char */
            	135, 0,
            1, 8, 1, /* 368: pointer.struct.asn1_string_st */
            	125, 0,
            1, 8, 1, /* 373: pointer.struct.asn1_string_st */
            	125, 0,
            1, 8, 1, /* 378: pointer.struct.asn1_string_st */
            	125, 0,
            1, 8, 1, /* 383: pointer.struct.asn1_string_st */
            	125, 0,
            1, 8, 1, /* 388: pointer.struct.asn1_string_st */
            	125, 0,
            1, 8, 1, /* 393: pointer.struct.asn1_string_st */
            	125, 0,
            1, 8, 1, /* 398: pointer.struct.asn1_string_st */
            	125, 0,
            1, 8, 1, /* 403: pointer.struct.asn1_string_st */
            	125, 0,
            1, 8, 1, /* 408: pointer.struct.asn1_string_st */
            	125, 0,
            1, 8, 1, /* 413: pointer.struct.asn1_string_st */
            	125, 0,
            1, 8, 1, /* 418: pointer.struct.asn1_string_st */
            	125, 0,
            8884097, 8, 0, /* 423: pointer.func */
            8884097, 8, 0, /* 426: pointer.func */
            8884097, 8, 0, /* 429: pointer.func */
            0, 8, 1, /* 432: pointer.ASN1_TYPE */
            	437, 0,
            0, 0, 1, /* 437: ASN1_TYPE */
            	442, 0,
            0, 16, 1, /* 442: struct.asn1_type_st */
            	447, 8,
            0, 8, 20, /* 447: union.unknown */
            	77, 0,
            	275, 0,
            	490, 0,
            	504, 0,
            	509, 0,
            	514, 0,
            	519, 0,
            	524, 0,
            	529, 0,
            	534, 0,
            	539, 0,
            	544, 0,
            	549, 0,
            	554, 0,
            	559, 0,
            	564, 0,
            	569, 0,
            	275, 0,
            	275, 0,
            	574, 0,
            1, 8, 1, /* 490: pointer.struct.asn1_object_st */
            	495, 0,
            0, 40, 3, /* 495: struct.asn1_object_st */
            	51, 0,
            	51, 8,
            	363, 24,
            1, 8, 1, /* 504: pointer.struct.asn1_string_st */
            	280, 0,
            1, 8, 1, /* 509: pointer.struct.asn1_string_st */
            	280, 0,
            1, 8, 1, /* 514: pointer.struct.asn1_string_st */
            	280, 0,
            1, 8, 1, /* 519: pointer.struct.asn1_string_st */
            	280, 0,
            1, 8, 1, /* 524: pointer.struct.asn1_string_st */
            	280, 0,
            1, 8, 1, /* 529: pointer.struct.asn1_string_st */
            	280, 0,
            1, 8, 1, /* 534: pointer.struct.asn1_string_st */
            	280, 0,
            1, 8, 1, /* 539: pointer.struct.asn1_string_st */
            	280, 0,
            1, 8, 1, /* 544: pointer.struct.asn1_string_st */
            	280, 0,
            1, 8, 1, /* 549: pointer.struct.asn1_string_st */
            	280, 0,
            1, 8, 1, /* 554: pointer.struct.asn1_string_st */
            	280, 0,
            1, 8, 1, /* 559: pointer.struct.asn1_string_st */
            	280, 0,
            1, 8, 1, /* 564: pointer.struct.asn1_string_st */
            	280, 0,
            1, 8, 1, /* 569: pointer.struct.asn1_string_st */
            	280, 0,
            1, 8, 1, /* 574: pointer.struct.ASN1_VALUE_st */
            	579, 0,
            0, 0, 0, /* 579: struct.ASN1_VALUE_st */
            8884097, 8, 0, /* 582: pointer.func */
            0, 56, 4, /* 585: struct.evp_pkey_st */
            	596, 16,
            	685, 24,
            	693, 32,
            	870, 48,
            1, 8, 1, /* 596: pointer.struct.evp_pkey_asn1_method_st */
            	601, 0,
            0, 208, 24, /* 601: struct.evp_pkey_asn1_method_st */
            	77, 16,
            	77, 24,
            	652, 32,
            	655, 40,
            	429, 48,
            	582, 56,
            	658, 64,
            	423, 72,
            	582, 80,
            	661, 88,
            	661, 96,
            	664, 104,
            	667, 112,
            	661, 120,
            	670, 128,
            	429, 136,
            	582, 144,
            	673, 152,
            	676, 160,
            	679, 168,
            	664, 176,
            	667, 184,
            	682, 192,
            	426, 200,
            8884097, 8, 0, /* 652: pointer.func */
            8884097, 8, 0, /* 655: pointer.func */
            8884097, 8, 0, /* 658: pointer.func */
            8884097, 8, 0, /* 661: pointer.func */
            8884097, 8, 0, /* 664: pointer.func */
            8884097, 8, 0, /* 667: pointer.func */
            8884097, 8, 0, /* 670: pointer.func */
            8884097, 8, 0, /* 673: pointer.func */
            8884097, 8, 0, /* 676: pointer.func */
            8884097, 8, 0, /* 679: pointer.func */
            8884097, 8, 0, /* 682: pointer.func */
            1, 8, 1, /* 685: pointer.struct.engine_st */
            	690, 0,
            0, 0, 0, /* 690: struct.engine_st */
            0, 8, 5, /* 693: union.unknown */
            	77, 0,
            	706, 0,
            	767, 0,
            	797, 0,
            	862, 0,
            1, 8, 1, /* 706: pointer.struct.rsa_st */
            	711, 0,
            0, 168, 17, /* 711: struct.rsa_st */
            	192, 16,
            	685, 24,
            	265, 32,
            	265, 40,
            	265, 48,
            	265, 56,
            	265, 64,
            	265, 72,
            	265, 80,
            	265, 88,
            	85, 96,
            	748, 120,
            	748, 128,
            	748, 136,
            	77, 144,
            	762, 152,
            	762, 160,
            1, 8, 1, /* 748: pointer.struct.bn_mont_ctx_st */
            	753, 0,
            0, 96, 3, /* 753: struct.bn_mont_ctx_st */
            	270, 8,
            	270, 32,
            	270, 56,
            1, 8, 1, /* 762: pointer.struct.bn_blinding_st */
            	249, 0,
            1, 8, 1, /* 767: pointer.struct.dsa_st */
            	772, 0,
            0, 136, 11, /* 772: struct.dsa_st */
            	265, 24,
            	265, 32,
            	265, 40,
            	265, 48,
            	265, 56,
            	265, 64,
            	265, 72,
            	748, 88,
            	85, 104,
            	244, 120,
            	685, 128,
            1, 8, 1, /* 797: pointer.struct.dh_st */
            	802, 0,
            0, 144, 12, /* 802: struct.dh_st */
            	265, 8,
            	265, 16,
            	265, 32,
            	265, 40,
            	748, 56,
            	265, 64,
            	265, 72,
            	130, 80,
            	265, 96,
            	85, 112,
            	829, 128,
            	685, 136,
            1, 8, 1, /* 829: pointer.struct.dh_method */
            	834, 0,
            0, 72, 8, /* 834: struct.dh_method */
            	51, 0,
            	853, 8,
            	293, 16,
            	856, 24,
            	853, 32,
            	853, 40,
            	77, 56,
            	859, 64,
            8884097, 8, 0, /* 853: pointer.func */
            8884097, 8, 0, /* 856: pointer.func */
            8884097, 8, 0, /* 859: pointer.func */
            1, 8, 1, /* 862: pointer.struct.ec_key_st */
            	867, 0,
            0, 0, 0, /* 867: struct.ec_key_st */
            1, 8, 1, /* 870: pointer.struct.stack_st_X509_ATTRIBUTE */
            	875, 0,
            0, 32, 2, /* 875: struct.stack_st_fake_X509_ATTRIBUTE */
            	882, 8,
            	112, 24,
            8884099, 8, 2, /* 882: pointer_to_array_of_pointers_to_stack */
            	889, 0,
            	934, 20,
            0, 8, 1, /* 889: pointer.X509_ATTRIBUTE */
            	894, 0,
            0, 0, 1, /* 894: X509_ATTRIBUTE */
            	899, 0,
            0, 24, 2, /* 899: struct.x509_attributes_st */
            	349, 0,
            	906, 16,
            0, 8, 3, /* 906: union.unknown */
            	77, 0,
            	915, 0,
            	937, 0,
            1, 8, 1, /* 915: pointer.struct.stack_st_ASN1_TYPE */
            	920, 0,
            0, 32, 2, /* 920: struct.stack_st_fake_ASN1_TYPE */
            	927, 8,
            	112, 24,
            8884099, 8, 2, /* 927: pointer_to_array_of_pointers_to_stack */
            	432, 0,
            	934, 20,
            0, 4, 0, /* 934: int */
            1, 8, 1, /* 937: pointer.struct.asn1_type_st */
            	296, 0,
            0, 1, 0, /* 942: char */
            1, 8, 1, /* 945: pointer.struct.evp_pkey_st */
            	585, 0,
            1, 8, 1, /* 950: pointer.pointer.struct.evp_pkey_st */
            	945, 0,
        },
        .arg_entity_index = { 115, 950, 0, 82, },
        .ret_entity_index = 945,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_arg(args_addr, arg_d);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    BIO * new_arg_a = *((BIO * *)new_args->args[0]);

    EVP_PKEY ** new_arg_b = *((EVP_PKEY ** *)new_args->args[1]);

    pem_password_cb * new_arg_c = *((pem_password_cb * *)new_args->args[2]);

    void * new_arg_d = *((void * *)new_args->args[3]);

    EVP_PKEY * *new_ret_ptr = (EVP_PKEY * *)new_args->ret;

    EVP_PKEY * (*orig_PEM_read_bio_PrivateKey)(BIO *,EVP_PKEY **,pem_password_cb *,void *);
    orig_PEM_read_bio_PrivateKey = dlsym(RTLD_NEXT, "PEM_read_bio_PrivateKey");
    *new_ret_ptr = (*orig_PEM_read_bio_PrivateKey)(new_arg_a,new_arg_b,new_arg_c,new_arg_d);

    syscall(889);

    return ret;
}

