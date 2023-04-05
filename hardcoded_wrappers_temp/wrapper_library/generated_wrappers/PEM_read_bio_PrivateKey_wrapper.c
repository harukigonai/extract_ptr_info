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
            8884097, 8, 0, /* 138: pointer.func */
            0, 96, 11, /* 141: struct.dsa_method */
            	51, 0,
            	166, 8,
            	169, 16,
            	172, 24,
            	175, 32,
            	178, 40,
            	181, 48,
            	181, 56,
            	77, 72,
            	184, 80,
            	181, 88,
            8884097, 8, 0, /* 166: pointer.func */
            8884097, 8, 0, /* 169: pointer.func */
            8884097, 8, 0, /* 172: pointer.func */
            8884097, 8, 0, /* 175: pointer.func */
            8884097, 8, 0, /* 178: pointer.func */
            8884097, 8, 0, /* 181: pointer.func */
            8884097, 8, 0, /* 184: pointer.func */
            1, 8, 1, /* 187: pointer.struct.rsa_meth_st */
            	192, 0,
            0, 112, 13, /* 192: struct.rsa_meth_st */
            	51, 0,
            	221, 8,
            	221, 16,
            	221, 24,
            	221, 32,
            	224, 40,
            	227, 48,
            	230, 56,
            	230, 64,
            	77, 80,
            	138, 88,
            	233, 96,
            	236, 104,
            8884097, 8, 0, /* 221: pointer.func */
            8884097, 8, 0, /* 224: pointer.func */
            8884097, 8, 0, /* 227: pointer.func */
            8884097, 8, 0, /* 230: pointer.func */
            8884097, 8, 0, /* 233: pointer.func */
            8884097, 8, 0, /* 236: pointer.func */
            1, 8, 1, /* 239: pointer.struct.dsa_method */
            	141, 0,
            0, 0, 0, /* 244: struct.bn_blinding_st */
            0, 8, 20, /* 247: union.unknown */
            	77, 0,
            	290, 0,
            	300, 0,
            	319, 0,
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
            	290, 0,
            	290, 0,
            	389, 0,
            1, 8, 1, /* 290: pointer.struct.asn1_string_st */
            	295, 0,
            0, 24, 1, /* 295: struct.asn1_string_st */
            	130, 8,
            1, 8, 1, /* 300: pointer.struct.asn1_object_st */
            	305, 0,
            0, 40, 3, /* 305: struct.asn1_object_st */
            	51, 0,
            	51, 8,
            	314, 24,
            1, 8, 1, /* 314: pointer.unsigned char */
            	135, 0,
            1, 8, 1, /* 319: pointer.struct.asn1_string_st */
            	295, 0,
            1, 8, 1, /* 324: pointer.struct.asn1_string_st */
            	295, 0,
            1, 8, 1, /* 329: pointer.struct.asn1_string_st */
            	295, 0,
            1, 8, 1, /* 334: pointer.struct.asn1_string_st */
            	295, 0,
            1, 8, 1, /* 339: pointer.struct.asn1_string_st */
            	295, 0,
            1, 8, 1, /* 344: pointer.struct.asn1_string_st */
            	295, 0,
            1, 8, 1, /* 349: pointer.struct.asn1_string_st */
            	295, 0,
            1, 8, 1, /* 354: pointer.struct.asn1_string_st */
            	295, 0,
            1, 8, 1, /* 359: pointer.struct.asn1_string_st */
            	295, 0,
            1, 8, 1, /* 364: pointer.struct.asn1_string_st */
            	295, 0,
            1, 8, 1, /* 369: pointer.struct.asn1_string_st */
            	295, 0,
            1, 8, 1, /* 374: pointer.struct.asn1_string_st */
            	295, 0,
            1, 8, 1, /* 379: pointer.struct.asn1_string_st */
            	295, 0,
            1, 8, 1, /* 384: pointer.struct.asn1_string_st */
            	295, 0,
            1, 8, 1, /* 389: pointer.struct.ASN1_VALUE_st */
            	394, 0,
            0, 0, 0, /* 394: struct.ASN1_VALUE_st */
            1, 8, 1, /* 397: pointer.struct.asn1_string_st */
            	125, 0,
            1, 8, 1, /* 402: pointer.unsigned int */
            	407, 0,
            0, 4, 0, /* 407: unsigned int */
            1, 8, 1, /* 410: pointer.struct.bignum_st */
            	415, 0,
            0, 24, 1, /* 415: struct.bignum_st */
            	402, 0,
            0, 16, 1, /* 420: struct.asn1_type_st */
            	425, 8,
            0, 8, 20, /* 425: union.unknown */
            	77, 0,
            	468, 0,
            	473, 0,
            	487, 0,
            	492, 0,
            	497, 0,
            	502, 0,
            	397, 0,
            	507, 0,
            	120, 0,
            	512, 0,
            	517, 0,
            	522, 0,
            	527, 0,
            	532, 0,
            	537, 0,
            	542, 0,
            	468, 0,
            	468, 0,
            	547, 0,
            1, 8, 1, /* 468: pointer.struct.asn1_string_st */
            	125, 0,
            1, 8, 1, /* 473: pointer.struct.asn1_object_st */
            	478, 0,
            0, 40, 3, /* 478: struct.asn1_object_st */
            	51, 0,
            	51, 8,
            	314, 24,
            1, 8, 1, /* 487: pointer.struct.asn1_string_st */
            	125, 0,
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
            0, 8, 1, /* 564: pointer.ASN1_TYPE */
            	569, 0,
            0, 0, 1, /* 569: ASN1_TYPE */
            	574, 0,
            0, 16, 1, /* 574: struct.asn1_type_st */
            	247, 8,
            0, 56, 4, /* 579: struct.evp_pkey_st */
            	590, 16,
            	682, 24,
            	690, 32,
            	870, 48,
            1, 8, 1, /* 590: pointer.struct.evp_pkey_asn1_method_st */
            	595, 0,
            0, 208, 24, /* 595: struct.evp_pkey_asn1_method_st */
            	77, 16,
            	77, 24,
            	646, 32,
            	649, 40,
            	561, 48,
            	652, 56,
            	655, 64,
            	555, 72,
            	652, 80,
            	658, 88,
            	658, 96,
            	661, 104,
            	664, 112,
            	658, 120,
            	667, 128,
            	561, 136,
            	652, 144,
            	670, 152,
            	673, 160,
            	676, 168,
            	661, 176,
            	664, 184,
            	679, 192,
            	558, 200,
            8884097, 8, 0, /* 646: pointer.func */
            8884097, 8, 0, /* 649: pointer.func */
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
            1, 8, 1, /* 682: pointer.struct.engine_st */
            	687, 0,
            0, 0, 0, /* 687: struct.engine_st */
            0, 8, 5, /* 690: union.unknown */
            	77, 0,
            	703, 0,
            	764, 0,
            	794, 0,
            	862, 0,
            1, 8, 1, /* 703: pointer.struct.rsa_st */
            	708, 0,
            0, 168, 17, /* 708: struct.rsa_st */
            	187, 16,
            	682, 24,
            	410, 32,
            	410, 40,
            	410, 48,
            	410, 56,
            	410, 64,
            	410, 72,
            	410, 80,
            	410, 88,
            	85, 96,
            	745, 120,
            	745, 128,
            	745, 136,
            	77, 144,
            	759, 152,
            	759, 160,
            1, 8, 1, /* 745: pointer.struct.bn_mont_ctx_st */
            	750, 0,
            0, 96, 3, /* 750: struct.bn_mont_ctx_st */
            	415, 8,
            	415, 32,
            	415, 56,
            1, 8, 1, /* 759: pointer.struct.bn_blinding_st */
            	244, 0,
            1, 8, 1, /* 764: pointer.struct.dsa_st */
            	769, 0,
            0, 136, 11, /* 769: struct.dsa_st */
            	410, 24,
            	410, 32,
            	410, 40,
            	410, 48,
            	410, 56,
            	410, 64,
            	410, 72,
            	745, 88,
            	85, 104,
            	239, 120,
            	682, 128,
            1, 8, 1, /* 794: pointer.struct.dh_st */
            	799, 0,
            0, 144, 12, /* 799: struct.dh_st */
            	410, 8,
            	410, 16,
            	410, 32,
            	410, 40,
            	745, 56,
            	410, 64,
            	410, 72,
            	130, 80,
            	410, 96,
            	85, 112,
            	826, 128,
            	682, 136,
            1, 8, 1, /* 826: pointer.struct.dh_method */
            	831, 0,
            0, 72, 8, /* 831: struct.dh_method */
            	51, 0,
            	850, 8,
            	853, 16,
            	856, 24,
            	850, 32,
            	850, 40,
            	77, 56,
            	859, 64,
            8884097, 8, 0, /* 850: pointer.func */
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
            	473, 0,
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
            	564, 0,
            	934, 20,
            0, 4, 0, /* 934: int */
            1, 8, 1, /* 937: pointer.struct.asn1_type_st */
            	420, 0,
            1, 8, 1, /* 942: pointer.struct.evp_pkey_st */
            	579, 0,
            0, 1, 0, /* 947: char */
            1, 8, 1, /* 950: pointer.pointer.struct.evp_pkey_st */
            	942, 0,
        },
        .arg_entity_index = { 115, 950, 0, 82, },
        .ret_entity_index = 942,
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

