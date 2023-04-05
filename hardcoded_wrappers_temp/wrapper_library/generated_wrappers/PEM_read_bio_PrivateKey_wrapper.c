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
            0, 8, 20, /* 252: union.unknown */
            	77, 0,
            	295, 0,
            	305, 0,
            	324, 0,
            	329, 0,
            	334, 0,
            	339, 0,
            	344, 0,
            	349, 0,
            	354, 0,
            	359, 0,
            	364, 0,
            	369, 0,
            	374, 0,
            	379, 0,
            	384, 0,
            	389, 0,
            	295, 0,
            	295, 0,
            	394, 0,
            1, 8, 1, /* 295: pointer.struct.asn1_string_st */
            	300, 0,
            0, 24, 1, /* 300: struct.asn1_string_st */
            	130, 8,
            1, 8, 1, /* 305: pointer.struct.asn1_object_st */
            	310, 0,
            0, 40, 3, /* 310: struct.asn1_object_st */
            	51, 0,
            	51, 8,
            	319, 24,
            1, 8, 1, /* 319: pointer.unsigned char */
            	135, 0,
            1, 8, 1, /* 324: pointer.struct.asn1_string_st */
            	300, 0,
            1, 8, 1, /* 329: pointer.struct.asn1_string_st */
            	300, 0,
            1, 8, 1, /* 334: pointer.struct.asn1_string_st */
            	300, 0,
            1, 8, 1, /* 339: pointer.struct.asn1_string_st */
            	300, 0,
            1, 8, 1, /* 344: pointer.struct.asn1_string_st */
            	300, 0,
            1, 8, 1, /* 349: pointer.struct.asn1_string_st */
            	300, 0,
            1, 8, 1, /* 354: pointer.struct.asn1_string_st */
            	300, 0,
            1, 8, 1, /* 359: pointer.struct.asn1_string_st */
            	300, 0,
            1, 8, 1, /* 364: pointer.struct.asn1_string_st */
            	300, 0,
            1, 8, 1, /* 369: pointer.struct.asn1_string_st */
            	300, 0,
            1, 8, 1, /* 374: pointer.struct.asn1_string_st */
            	300, 0,
            1, 8, 1, /* 379: pointer.struct.asn1_string_st */
            	300, 0,
            1, 8, 1, /* 384: pointer.struct.asn1_string_st */
            	300, 0,
            1, 8, 1, /* 389: pointer.struct.asn1_string_st */
            	300, 0,
            1, 8, 1, /* 394: pointer.struct.ASN1_VALUE_st */
            	399, 0,
            0, 0, 0, /* 399: struct.ASN1_VALUE_st */
            1, 8, 1, /* 402: pointer.struct.asn1_string_st */
            	125, 0,
            1, 8, 1, /* 407: pointer.unsigned int */
            	412, 0,
            0, 4, 0, /* 412: unsigned int */
            1, 8, 1, /* 415: pointer.struct.bignum_st */
            	420, 0,
            0, 24, 1, /* 420: struct.bignum_st */
            	407, 0,
            0, 16, 1, /* 425: struct.asn1_type_st */
            	430, 8,
            0, 8, 20, /* 430: union.unknown */
            	77, 0,
            	473, 0,
            	478, 0,
            	492, 0,
            	497, 0,
            	502, 0,
            	507, 0,
            	402, 0,
            	512, 0,
            	138, 0,
            	517, 0,
            	522, 0,
            	527, 0,
            	532, 0,
            	537, 0,
            	542, 0,
            	120, 0,
            	473, 0,
            	473, 0,
            	547, 0,
            1, 8, 1, /* 473: pointer.struct.asn1_string_st */
            	125, 0,
            1, 8, 1, /* 478: pointer.struct.asn1_object_st */
            	483, 0,
            0, 40, 3, /* 483: struct.asn1_object_st */
            	51, 0,
            	51, 8,
            	319, 24,
            1, 8, 1, /* 492: pointer.struct.asn1_string_st */
            	125, 0,
            1, 8, 1, /* 497: pointer.struct.asn1_string_st */
            	125, 0,
            1, 8, 1, /* 502: pointer.struct.asn1_string_st */
            	125, 0,
            1, 8, 1, /* 507: pointer.struct.asn1_string_st */
            	125, 0,
            1, 8, 1, /* 512: pointer.struct.asn1_string_st */
            	125, 0,
            1, 8, 1, /* 517: pointer.struct.asn1_string_st */
            	125, 0,
            1, 8, 1, /* 522: pointer.struct.asn1_string_st */
            	125, 0,
            1, 8, 1, /* 527: pointer.struct.asn1_string_st */
            	125, 0,
            1, 8, 1, /* 532: pointer.struct.asn1_string_st */
            	125, 0,
            1, 8, 1, /* 537: pointer.struct.asn1_string_st */
            	125, 0,
            1, 8, 1, /* 542: pointer.struct.asn1_string_st */
            	125, 0,
            1, 8, 1, /* 547: pointer.struct.ASN1_VALUE_st */
            	552, 0,
            0, 0, 0, /* 552: struct.ASN1_VALUE_st */
            8884097, 8, 0, /* 555: pointer.func */
            8884097, 8, 0, /* 558: pointer.func */
            8884097, 8, 0, /* 561: pointer.func */
            0, 56, 4, /* 564: struct.evp_pkey_st */
            	575, 16,
            	667, 24,
            	675, 32,
            	855, 48,
            1, 8, 1, /* 575: pointer.struct.evp_pkey_asn1_method_st */
            	580, 0,
            0, 208, 24, /* 580: struct.evp_pkey_asn1_method_st */
            	77, 16,
            	77, 24,
            	631, 32,
            	634, 40,
            	561, 48,
            	637, 56,
            	640, 64,
            	555, 72,
            	637, 80,
            	643, 88,
            	643, 96,
            	646, 104,
            	649, 112,
            	643, 120,
            	652, 128,
            	561, 136,
            	637, 144,
            	655, 152,
            	658, 160,
            	661, 168,
            	646, 176,
            	649, 184,
            	664, 192,
            	558, 200,
            8884097, 8, 0, /* 631: pointer.func */
            8884097, 8, 0, /* 634: pointer.func */
            8884097, 8, 0, /* 637: pointer.func */
            8884097, 8, 0, /* 640: pointer.func */
            8884097, 8, 0, /* 643: pointer.func */
            8884097, 8, 0, /* 646: pointer.func */
            8884097, 8, 0, /* 649: pointer.func */
            8884097, 8, 0, /* 652: pointer.func */
            8884097, 8, 0, /* 655: pointer.func */
            8884097, 8, 0, /* 658: pointer.func */
            8884097, 8, 0, /* 661: pointer.func */
            8884097, 8, 0, /* 664: pointer.func */
            1, 8, 1, /* 667: pointer.struct.engine_st */
            	672, 0,
            0, 0, 0, /* 672: struct.engine_st */
            0, 8, 5, /* 675: union.unknown */
            	77, 0,
            	688, 0,
            	749, 0,
            	779, 0,
            	847, 0,
            1, 8, 1, /* 688: pointer.struct.rsa_st */
            	693, 0,
            0, 168, 17, /* 693: struct.rsa_st */
            	192, 16,
            	667, 24,
            	415, 32,
            	415, 40,
            	415, 48,
            	415, 56,
            	415, 64,
            	415, 72,
            	415, 80,
            	415, 88,
            	85, 96,
            	730, 120,
            	730, 128,
            	730, 136,
            	77, 144,
            	744, 152,
            	744, 160,
            1, 8, 1, /* 730: pointer.struct.bn_mont_ctx_st */
            	735, 0,
            0, 96, 3, /* 735: struct.bn_mont_ctx_st */
            	420, 8,
            	420, 32,
            	420, 56,
            1, 8, 1, /* 744: pointer.struct.bn_blinding_st */
            	249, 0,
            1, 8, 1, /* 749: pointer.struct.dsa_st */
            	754, 0,
            0, 136, 11, /* 754: struct.dsa_st */
            	415, 24,
            	415, 32,
            	415, 40,
            	415, 48,
            	415, 56,
            	415, 64,
            	415, 72,
            	730, 88,
            	85, 104,
            	244, 120,
            	667, 128,
            1, 8, 1, /* 779: pointer.struct.dh_st */
            	784, 0,
            0, 144, 12, /* 784: struct.dh_st */
            	415, 8,
            	415, 16,
            	415, 32,
            	415, 40,
            	730, 56,
            	415, 64,
            	415, 72,
            	130, 80,
            	415, 96,
            	85, 112,
            	811, 128,
            	667, 136,
            1, 8, 1, /* 811: pointer.struct.dh_method */
            	816, 0,
            0, 72, 8, /* 816: struct.dh_method */
            	51, 0,
            	835, 8,
            	838, 16,
            	841, 24,
            	835, 32,
            	835, 40,
            	77, 56,
            	844, 64,
            8884097, 8, 0, /* 835: pointer.func */
            8884097, 8, 0, /* 838: pointer.func */
            8884097, 8, 0, /* 841: pointer.func */
            8884097, 8, 0, /* 844: pointer.func */
            1, 8, 1, /* 847: pointer.struct.ec_key_st */
            	852, 0,
            0, 0, 0, /* 852: struct.ec_key_st */
            1, 8, 1, /* 855: pointer.struct.stack_st_X509_ATTRIBUTE */
            	860, 0,
            0, 32, 2, /* 860: struct.stack_st_fake_X509_ATTRIBUTE */
            	867, 8,
            	112, 24,
            8884099, 8, 2, /* 867: pointer_to_array_of_pointers_to_stack */
            	874, 0,
            	934, 20,
            0, 8, 1, /* 874: pointer.X509_ATTRIBUTE */
            	879, 0,
            0, 0, 1, /* 879: X509_ATTRIBUTE */
            	884, 0,
            0, 24, 2, /* 884: struct.x509_attributes_st */
            	478, 0,
            	891, 16,
            0, 8, 3, /* 891: union.unknown */
            	77, 0,
            	900, 0,
            	937, 0,
            1, 8, 1, /* 900: pointer.struct.stack_st_ASN1_TYPE */
            	905, 0,
            0, 32, 2, /* 905: struct.stack_st_fake_ASN1_TYPE */
            	912, 8,
            	112, 24,
            8884099, 8, 2, /* 912: pointer_to_array_of_pointers_to_stack */
            	919, 0,
            	934, 20,
            0, 8, 1, /* 919: pointer.ASN1_TYPE */
            	924, 0,
            0, 0, 1, /* 924: ASN1_TYPE */
            	929, 0,
            0, 16, 1, /* 929: struct.asn1_type_st */
            	252, 8,
            0, 4, 0, /* 934: int */
            1, 8, 1, /* 937: pointer.struct.asn1_type_st */
            	425, 0,
            0, 1, 0, /* 942: char */
            1, 8, 1, /* 945: pointer.struct.evp_pkey_st */
            	564, 0,
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

