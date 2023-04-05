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

void bb_EVP_PKEY_free(EVP_PKEY * arg_a);

void EVP_PKEY_free(EVP_PKEY * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("EVP_PKEY_free called %lu\n", in_lib);
    if (!in_lib)
        bb_EVP_PKEY_free(arg_a);
    else {
        void (*orig_EVP_PKEY_free)(EVP_PKEY *);
        orig_EVP_PKEY_free = dlsym(RTLD_NEXT, "EVP_PKEY_free");
        orig_EVP_PKEY_free(arg_a);
    }
}

void bb_EVP_PKEY_free(EVP_PKEY * arg_a) 
{
    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            1, 8, 1, /* 0: pointer.struct.ASN1_VALUE_st */
            	5, 0,
            0, 0, 0, /* 5: struct.ASN1_VALUE_st */
            8884097, 8, 0, /* 8: pointer.func */
            8884097, 8, 0, /* 11: pointer.func */
            8884097, 8, 0, /* 14: pointer.func */
            0, 16, 1, /* 17: struct.crypto_ex_data_st */
            	22, 0,
            1, 8, 1, /* 22: pointer.struct.stack_st_void */
            	27, 0,
            0, 32, 1, /* 27: struct.stack_st_void */
            	32, 0,
            0, 32, 2, /* 32: struct.stack_st */
            	39, 8,
            	49, 24,
            1, 8, 1, /* 39: pointer.pointer.char */
            	44, 0,
            1, 8, 1, /* 44: pointer.char */
            	8884096, 0,
            8884097, 8, 0, /* 49: pointer.func */
            1, 8, 1, /* 52: pointer.struct.asn1_string_st */
            	57, 0,
            0, 24, 1, /* 57: struct.asn1_string_st */
            	62, 8,
            1, 8, 1, /* 62: pointer.unsigned char */
            	67, 0,
            0, 1, 0, /* 67: unsigned char */
            0, 24, 1, /* 70: struct.asn1_string_st */
            	62, 8,
            0, 24, 1, /* 75: struct.bignum_st */
            	80, 0,
            1, 8, 1, /* 80: pointer.unsigned int */
            	85, 0,
            0, 4, 0, /* 85: unsigned int */
            1, 8, 1, /* 88: pointer.struct.bignum_st */
            	75, 0,
            8884097, 8, 0, /* 93: pointer.func */
            8884097, 8, 0, /* 96: pointer.func */
            8884097, 8, 0, /* 99: pointer.func */
            1, 8, 1, /* 102: pointer.struct.asn1_string_st */
            	57, 0,
            1, 8, 1, /* 107: pointer.struct.asn1_string_st */
            	70, 0,
            1, 8, 1, /* 112: pointer.struct.asn1_string_st */
            	57, 0,
            0, 96, 3, /* 117: struct.bn_mont_ctx_st */
            	75, 8,
            	75, 32,
            	75, 56,
            1, 8, 1, /* 126: pointer.struct.dh_st */
            	131, 0,
            0, 144, 12, /* 131: struct.dh_st */
            	88, 8,
            	88, 16,
            	88, 32,
            	88, 40,
            	158, 56,
            	88, 64,
            	88, 72,
            	62, 80,
            	88, 96,
            	17, 112,
            	163, 128,
            	201, 136,
            1, 8, 1, /* 158: pointer.struct.bn_mont_ctx_st */
            	117, 0,
            1, 8, 1, /* 163: pointer.struct.dh_method */
            	168, 0,
            0, 72, 8, /* 168: struct.dh_method */
            	187, 0,
            	192, 8,
            	96, 16,
            	195, 24,
            	192, 32,
            	192, 40,
            	44, 56,
            	198, 64,
            1, 8, 1, /* 187: pointer.char */
            	8884096, 0,
            8884097, 8, 0, /* 192: pointer.func */
            8884097, 8, 0, /* 195: pointer.func */
            8884097, 8, 0, /* 198: pointer.func */
            1, 8, 1, /* 201: pointer.struct.engine_st */
            	206, 0,
            0, 0, 0, /* 206: struct.engine_st */
            8884097, 8, 0, /* 209: pointer.func */
            0, 8, 1, /* 212: pointer.ASN1_TYPE */
            	217, 0,
            0, 0, 1, /* 217: ASN1_TYPE */
            	222, 0,
            0, 16, 1, /* 222: struct.asn1_type_st */
            	227, 8,
            0, 8, 20, /* 227: union.unknown */
            	44, 0,
            	270, 0,
            	275, 0,
            	294, 0,
            	299, 0,
            	304, 0,
            	309, 0,
            	112, 0,
            	314, 0,
            	319, 0,
            	52, 0,
            	102, 0,
            	324, 0,
            	329, 0,
            	334, 0,
            	339, 0,
            	344, 0,
            	270, 0,
            	270, 0,
            	349, 0,
            1, 8, 1, /* 270: pointer.struct.asn1_string_st */
            	57, 0,
            1, 8, 1, /* 275: pointer.struct.asn1_object_st */
            	280, 0,
            0, 40, 3, /* 280: struct.asn1_object_st */
            	187, 0,
            	187, 8,
            	289, 24,
            1, 8, 1, /* 289: pointer.unsigned char */
            	67, 0,
            1, 8, 1, /* 294: pointer.struct.asn1_string_st */
            	57, 0,
            1, 8, 1, /* 299: pointer.struct.asn1_string_st */
            	57, 0,
            1, 8, 1, /* 304: pointer.struct.asn1_string_st */
            	57, 0,
            1, 8, 1, /* 309: pointer.struct.asn1_string_st */
            	57, 0,
            1, 8, 1, /* 314: pointer.struct.asn1_string_st */
            	57, 0,
            1, 8, 1, /* 319: pointer.struct.asn1_string_st */
            	57, 0,
            1, 8, 1, /* 324: pointer.struct.asn1_string_st */
            	57, 0,
            1, 8, 1, /* 329: pointer.struct.asn1_string_st */
            	57, 0,
            1, 8, 1, /* 334: pointer.struct.asn1_string_st */
            	57, 0,
            1, 8, 1, /* 339: pointer.struct.asn1_string_st */
            	57, 0,
            1, 8, 1, /* 344: pointer.struct.asn1_string_st */
            	57, 0,
            1, 8, 1, /* 349: pointer.struct.ASN1_VALUE_st */
            	354, 0,
            0, 0, 0, /* 354: struct.ASN1_VALUE_st */
            8884097, 8, 0, /* 357: pointer.func */
            8884097, 8, 0, /* 360: pointer.func */
            8884097, 8, 0, /* 363: pointer.func */
            0, 56, 4, /* 366: struct.evp_pkey_st */
            	377, 16,
            	201, 24,
            	469, 32,
            	658, 48,
            1, 8, 1, /* 377: pointer.struct.evp_pkey_asn1_method_st */
            	382, 0,
            0, 208, 24, /* 382: struct.evp_pkey_asn1_method_st */
            	44, 16,
            	44, 24,
            	433, 32,
            	436, 40,
            	439, 48,
            	357, 56,
            	442, 64,
            	360, 72,
            	357, 80,
            	445, 88,
            	445, 96,
            	448, 104,
            	451, 112,
            	445, 120,
            	454, 128,
            	439, 136,
            	357, 144,
            	457, 152,
            	363, 160,
            	460, 168,
            	448, 176,
            	451, 184,
            	463, 192,
            	466, 200,
            8884097, 8, 0, /* 433: pointer.func */
            8884097, 8, 0, /* 436: pointer.func */
            8884097, 8, 0, /* 439: pointer.func */
            8884097, 8, 0, /* 442: pointer.func */
            8884097, 8, 0, /* 445: pointer.func */
            8884097, 8, 0, /* 448: pointer.func */
            8884097, 8, 0, /* 451: pointer.func */
            8884097, 8, 0, /* 454: pointer.func */
            8884097, 8, 0, /* 457: pointer.func */
            8884097, 8, 0, /* 460: pointer.func */
            8884097, 8, 0, /* 463: pointer.func */
            8884097, 8, 0, /* 466: pointer.func */
            0, 8, 5, /* 469: union.unknown */
            	44, 0,
            	482, 0,
            	578, 0,
            	126, 0,
            	650, 0,
            1, 8, 1, /* 482: pointer.struct.rsa_st */
            	487, 0,
            0, 168, 17, /* 487: struct.rsa_st */
            	524, 16,
            	201, 24,
            	88, 32,
            	88, 40,
            	88, 48,
            	88, 56,
            	88, 64,
            	88, 72,
            	88, 80,
            	88, 88,
            	17, 96,
            	158, 120,
            	158, 128,
            	158, 136,
            	44, 144,
            	570, 152,
            	570, 160,
            1, 8, 1, /* 524: pointer.struct.rsa_meth_st */
            	529, 0,
            0, 112, 13, /* 529: struct.rsa_meth_st */
            	187, 0,
            	558, 8,
            	558, 16,
            	558, 24,
            	558, 32,
            	561, 40,
            	564, 48,
            	567, 56,
            	567, 64,
            	44, 80,
            	11, 88,
            	99, 96,
            	93, 104,
            8884097, 8, 0, /* 558: pointer.func */
            8884097, 8, 0, /* 561: pointer.func */
            8884097, 8, 0, /* 564: pointer.func */
            8884097, 8, 0, /* 567: pointer.func */
            1, 8, 1, /* 570: pointer.struct.bn_blinding_st */
            	575, 0,
            0, 0, 0, /* 575: struct.bn_blinding_st */
            1, 8, 1, /* 578: pointer.struct.dsa_st */
            	583, 0,
            0, 136, 11, /* 583: struct.dsa_st */
            	88, 24,
            	88, 32,
            	88, 40,
            	88, 48,
            	88, 56,
            	88, 64,
            	88, 72,
            	158, 88,
            	17, 104,
            	608, 120,
            	201, 128,
            1, 8, 1, /* 608: pointer.struct.dsa_method */
            	613, 0,
            0, 96, 11, /* 613: struct.dsa_method */
            	187, 0,
            	209, 8,
            	638, 16,
            	641, 24,
            	14, 32,
            	8, 40,
            	644, 48,
            	644, 56,
            	44, 72,
            	647, 80,
            	644, 88,
            8884097, 8, 0, /* 638: pointer.func */
            8884097, 8, 0, /* 641: pointer.func */
            8884097, 8, 0, /* 644: pointer.func */
            8884097, 8, 0, /* 647: pointer.func */
            1, 8, 1, /* 650: pointer.struct.ec_key_st */
            	655, 0,
            0, 0, 0, /* 655: struct.ec_key_st */
            1, 8, 1, /* 658: pointer.struct.stack_st_X509_ATTRIBUTE */
            	663, 0,
            0, 32, 2, /* 663: struct.stack_st_fake_X509_ATTRIBUTE */
            	670, 8,
            	49, 24,
            8884099, 8, 2, /* 670: pointer_to_array_of_pointers_to_stack */
            	677, 0,
            	736, 20,
            0, 8, 1, /* 677: pointer.X509_ATTRIBUTE */
            	682, 0,
            0, 0, 1, /* 682: X509_ATTRIBUTE */
            	687, 0,
            0, 24, 2, /* 687: struct.x509_attributes_st */
            	694, 0,
            	708, 16,
            1, 8, 1, /* 694: pointer.struct.asn1_object_st */
            	699, 0,
            0, 40, 3, /* 699: struct.asn1_object_st */
            	187, 0,
            	187, 8,
            	289, 24,
            0, 8, 3, /* 708: union.unknown */
            	44, 0,
            	717, 0,
            	739, 0,
            1, 8, 1, /* 717: pointer.struct.stack_st_ASN1_TYPE */
            	722, 0,
            0, 32, 2, /* 722: struct.stack_st_fake_ASN1_TYPE */
            	729, 8,
            	49, 24,
            8884099, 8, 2, /* 729: pointer_to_array_of_pointers_to_stack */
            	212, 0,
            	736, 20,
            0, 4, 0, /* 736: int */
            1, 8, 1, /* 739: pointer.struct.asn1_type_st */
            	744, 0,
            0, 16, 1, /* 744: struct.asn1_type_st */
            	749, 8,
            0, 8, 20, /* 749: union.unknown */
            	44, 0,
            	792, 0,
            	694, 0,
            	797, 0,
            	802, 0,
            	807, 0,
            	812, 0,
            	107, 0,
            	817, 0,
            	822, 0,
            	827, 0,
            	832, 0,
            	837, 0,
            	842, 0,
            	847, 0,
            	852, 0,
            	857, 0,
            	792, 0,
            	792, 0,
            	0, 0,
            1, 8, 1, /* 792: pointer.struct.asn1_string_st */
            	70, 0,
            1, 8, 1, /* 797: pointer.struct.asn1_string_st */
            	70, 0,
            1, 8, 1, /* 802: pointer.struct.asn1_string_st */
            	70, 0,
            1, 8, 1, /* 807: pointer.struct.asn1_string_st */
            	70, 0,
            1, 8, 1, /* 812: pointer.struct.asn1_string_st */
            	70, 0,
            1, 8, 1, /* 817: pointer.struct.asn1_string_st */
            	70, 0,
            1, 8, 1, /* 822: pointer.struct.asn1_string_st */
            	70, 0,
            1, 8, 1, /* 827: pointer.struct.asn1_string_st */
            	70, 0,
            1, 8, 1, /* 832: pointer.struct.asn1_string_st */
            	70, 0,
            1, 8, 1, /* 837: pointer.struct.asn1_string_st */
            	70, 0,
            1, 8, 1, /* 842: pointer.struct.asn1_string_st */
            	70, 0,
            1, 8, 1, /* 847: pointer.struct.asn1_string_st */
            	70, 0,
            1, 8, 1, /* 852: pointer.struct.asn1_string_st */
            	70, 0,
            1, 8, 1, /* 857: pointer.struct.asn1_string_st */
            	70, 0,
            0, 1, 0, /* 862: char */
            1, 8, 1, /* 865: pointer.struct.evp_pkey_st */
            	366, 0,
        },
        .arg_entity_index = { 865, },
        .ret_entity_index = -1,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    EVP_PKEY * new_arg_a = *((EVP_PKEY * *)new_args->args[0]);

    void (*orig_EVP_PKEY_free)(EVP_PKEY *);
    orig_EVP_PKEY_free = dlsym(RTLD_NEXT, "EVP_PKEY_free");
    (*orig_EVP_PKEY_free)(new_arg_a);

    syscall(889);

}

