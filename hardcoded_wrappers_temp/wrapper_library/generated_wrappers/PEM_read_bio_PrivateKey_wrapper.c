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
            64097, 8, 0, /* 0: pointer.func */
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
            	64096, 0,
            64097, 8, 0, /* 56: pointer.func */
            64097, 8, 0, /* 59: pointer.func */
            64097, 8, 0, /* 62: pointer.func */
            64097, 8, 0, /* 65: pointer.func */
            64097, 8, 0, /* 68: pointer.func */
            64097, 8, 0, /* 71: pointer.func */
            64097, 8, 0, /* 74: pointer.func */
            1, 8, 1, /* 77: pointer.char */
            	64096, 0,
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
            64097, 8, 0, /* 112: pointer.func */
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
            64097, 8, 0, /* 143: pointer.func */
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
            64097, 8, 0, /* 171: pointer.func */
            64097, 8, 0, /* 174: pointer.func */
            64097, 8, 0, /* 177: pointer.func */
            64097, 8, 0, /* 180: pointer.func */
            64097, 8, 0, /* 183: pointer.func */
            64097, 8, 0, /* 186: pointer.func */
            64097, 8, 0, /* 189: pointer.func */
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
            64097, 8, 0, /* 226: pointer.func */
            64097, 8, 0, /* 229: pointer.func */
            64097, 8, 0, /* 232: pointer.func */
            64097, 8, 0, /* 235: pointer.func */
            64097, 8, 0, /* 238: pointer.func */
            64097, 8, 0, /* 241: pointer.func */
            1, 8, 1, /* 244: pointer.struct.dsa_method */
            	146, 0,
            0, 0, 0, /* 249: struct.bn_blinding_st */
            1, 8, 1, /* 252: pointer.struct.asn1_string_st */
            	257, 0,
            0, 24, 1, /* 257: struct.asn1_string_st */
            	130, 8,
            1, 8, 1, /* 262: pointer.struct.asn1_string_st */
            	257, 0,
            1, 8, 1, /* 267: pointer.struct.asn1_string_st */
            	257, 0,
            0, 8, 20, /* 272: union.unknown */
            	77, 0,
            	315, 0,
            	320, 0,
            	339, 0,
            	344, 0,
            	262, 0,
            	349, 0,
            	354, 0,
            	359, 0,
            	364, 0,
            	369, 0,
            	252, 0,
            	374, 0,
            	267, 0,
            	379, 0,
            	384, 0,
            	389, 0,
            	315, 0,
            	315, 0,
            	394, 0,
            1, 8, 1, /* 315: pointer.struct.asn1_string_st */
            	257, 0,
            1, 8, 1, /* 320: pointer.struct.asn1_object_st */
            	325, 0,
            0, 40, 3, /* 325: struct.asn1_object_st */
            	51, 0,
            	51, 8,
            	334, 24,
            1, 8, 1, /* 334: pointer.unsigned char */
            	135, 0,
            1, 8, 1, /* 339: pointer.struct.asn1_string_st */
            	257, 0,
            1, 8, 1, /* 344: pointer.struct.asn1_string_st */
            	257, 0,
            1, 8, 1, /* 349: pointer.struct.asn1_string_st */
            	257, 0,
            1, 8, 1, /* 354: pointer.struct.asn1_string_st */
            	257, 0,
            1, 8, 1, /* 359: pointer.struct.asn1_string_st */
            	257, 0,
            1, 8, 1, /* 364: pointer.struct.asn1_string_st */
            	257, 0,
            1, 8, 1, /* 369: pointer.struct.asn1_string_st */
            	257, 0,
            1, 8, 1, /* 374: pointer.struct.asn1_string_st */
            	257, 0,
            1, 8, 1, /* 379: pointer.struct.asn1_string_st */
            	257, 0,
            1, 8, 1, /* 384: pointer.struct.asn1_string_st */
            	257, 0,
            1, 8, 1, /* 389: pointer.struct.asn1_string_st */
            	257, 0,
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
            1, 8, 1, /* 425: pointer.struct.ASN1_VALUE_st */
            	430, 0,
            0, 0, 0, /* 430: struct.ASN1_VALUE_st */
            64097, 8, 0, /* 433: pointer.func */
            0, 16, 1, /* 436: struct.asn1_type_st */
            	441, 8,
            0, 8, 20, /* 441: union.unknown */
            	77, 0,
            	484, 0,
            	489, 0,
            	503, 0,
            	508, 0,
            	513, 0,
            	518, 0,
            	402, 0,
            	523, 0,
            	138, 0,
            	528, 0,
            	533, 0,
            	538, 0,
            	543, 0,
            	548, 0,
            	553, 0,
            	120, 0,
            	484, 0,
            	484, 0,
            	425, 0,
            1, 8, 1, /* 484: pointer.struct.asn1_string_st */
            	125, 0,
            1, 8, 1, /* 489: pointer.struct.asn1_object_st */
            	494, 0,
            0, 40, 3, /* 494: struct.asn1_object_st */
            	51, 0,
            	51, 8,
            	334, 24,
            1, 8, 1, /* 503: pointer.struct.asn1_string_st */
            	125, 0,
            1, 8, 1, /* 508: pointer.struct.asn1_string_st */
            	125, 0,
            1, 8, 1, /* 513: pointer.struct.asn1_string_st */
            	125, 0,
            1, 8, 1, /* 518: pointer.struct.asn1_string_st */
            	125, 0,
            1, 8, 1, /* 523: pointer.struct.asn1_string_st */
            	125, 0,
            1, 8, 1, /* 528: pointer.struct.asn1_string_st */
            	125, 0,
            1, 8, 1, /* 533: pointer.struct.asn1_string_st */
            	125, 0,
            1, 8, 1, /* 538: pointer.struct.asn1_string_st */
            	125, 0,
            1, 8, 1, /* 543: pointer.struct.asn1_string_st */
            	125, 0,
            1, 8, 1, /* 548: pointer.struct.asn1_string_st */
            	125, 0,
            1, 8, 1, /* 553: pointer.struct.asn1_string_st */
            	125, 0,
            64097, 8, 0, /* 558: pointer.func */
            64097, 8, 0, /* 561: pointer.func */
            64097, 8, 0, /* 564: pointer.func */
            0, 56, 4, /* 567: struct.evp_pkey_st */
            	578, 16,
            	670, 24,
            	678, 32,
            	855, 48,
            1, 8, 1, /* 578: pointer.struct.evp_pkey_asn1_method_st */
            	583, 0,
            0, 208, 24, /* 583: struct.evp_pkey_asn1_method_st */
            	77, 16,
            	77, 24,
            	634, 32,
            	637, 40,
            	561, 48,
            	564, 56,
            	640, 64,
            	643, 72,
            	564, 80,
            	646, 88,
            	646, 96,
            	649, 104,
            	652, 112,
            	646, 120,
            	655, 128,
            	561, 136,
            	564, 144,
            	658, 152,
            	661, 160,
            	664, 168,
            	649, 176,
            	652, 184,
            	667, 192,
            	558, 200,
            64097, 8, 0, /* 634: pointer.func */
            64097, 8, 0, /* 637: pointer.func */
            64097, 8, 0, /* 640: pointer.func */
            64097, 8, 0, /* 643: pointer.func */
            64097, 8, 0, /* 646: pointer.func */
            64097, 8, 0, /* 649: pointer.func */
            64097, 8, 0, /* 652: pointer.func */
            64097, 8, 0, /* 655: pointer.func */
            64097, 8, 0, /* 658: pointer.func */
            64097, 8, 0, /* 661: pointer.func */
            64097, 8, 0, /* 664: pointer.func */
            64097, 8, 0, /* 667: pointer.func */
            1, 8, 1, /* 670: pointer.struct.engine_st */
            	675, 0,
            0, 0, 0, /* 675: struct.engine_st */
            0, 8, 5, /* 678: union.unknown */
            	77, 0,
            	691, 0,
            	752, 0,
            	782, 0,
            	847, 0,
            1, 8, 1, /* 691: pointer.struct.rsa_st */
            	696, 0,
            0, 168, 17, /* 696: struct.rsa_st */
            	192, 16,
            	670, 24,
            	415, 32,
            	415, 40,
            	415, 48,
            	415, 56,
            	415, 64,
            	415, 72,
            	415, 80,
            	415, 88,
            	85, 96,
            	733, 120,
            	733, 128,
            	733, 136,
            	77, 144,
            	747, 152,
            	747, 160,
            1, 8, 1, /* 733: pointer.struct.bn_mont_ctx_st */
            	738, 0,
            0, 96, 3, /* 738: struct.bn_mont_ctx_st */
            	420, 8,
            	420, 32,
            	420, 56,
            1, 8, 1, /* 747: pointer.struct.bn_blinding_st */
            	249, 0,
            1, 8, 1, /* 752: pointer.struct.dsa_st */
            	757, 0,
            0, 136, 11, /* 757: struct.dsa_st */
            	415, 24,
            	415, 32,
            	415, 40,
            	415, 48,
            	415, 56,
            	415, 64,
            	415, 72,
            	733, 88,
            	85, 104,
            	244, 120,
            	670, 128,
            1, 8, 1, /* 782: pointer.struct.dh_st */
            	787, 0,
            0, 144, 12, /* 787: struct.dh_st */
            	415, 8,
            	415, 16,
            	415, 32,
            	415, 40,
            	733, 56,
            	415, 64,
            	415, 72,
            	130, 80,
            	415, 96,
            	85, 112,
            	814, 128,
            	670, 136,
            1, 8, 1, /* 814: pointer.struct.dh_method */
            	819, 0,
            0, 72, 8, /* 819: struct.dh_method */
            	51, 0,
            	838, 8,
            	433, 16,
            	841, 24,
            	838, 32,
            	838, 40,
            	77, 56,
            	844, 64,
            64097, 8, 0, /* 838: pointer.func */
            64097, 8, 0, /* 841: pointer.func */
            64097, 8, 0, /* 844: pointer.func */
            1, 8, 1, /* 847: pointer.struct.ec_key_st */
            	852, 0,
            0, 0, 0, /* 852: struct.ec_key_st */
            1, 8, 1, /* 855: pointer.struct.stack_st_X509_ATTRIBUTE */
            	860, 0,
            0, 32, 2, /* 860: struct.stack_st_fake_X509_ATTRIBUTE */
            	867, 8,
            	112, 24,
            64099, 8, 2, /* 867: pointer_to_array_of_pointers_to_stack */
            	874, 0,
            	934, 20,
            0, 8, 1, /* 874: pointer.X509_ATTRIBUTE */
            	879, 0,
            0, 0, 1, /* 879: X509_ATTRIBUTE */
            	884, 0,
            0, 24, 2, /* 884: struct.x509_attributes_st */
            	489, 0,
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
            64099, 8, 2, /* 912: pointer_to_array_of_pointers_to_stack */
            	919, 0,
            	934, 20,
            0, 8, 1, /* 919: pointer.ASN1_TYPE */
            	924, 0,
            0, 0, 1, /* 924: ASN1_TYPE */
            	929, 0,
            0, 16, 1, /* 929: struct.asn1_type_st */
            	272, 8,
            0, 4, 0, /* 934: int */
            1, 8, 1, /* 937: pointer.struct.asn1_type_st */
            	436, 0,
            0, 1, 0, /* 942: char */
            1, 8, 1, /* 945: pointer.struct.evp_pkey_st */
            	567, 0,
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

