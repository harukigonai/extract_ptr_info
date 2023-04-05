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

int bb_EVP_SignFinal(EVP_MD_CTX * arg_a,unsigned char * arg_b,unsigned int * arg_c,EVP_PKEY * arg_d);

int EVP_SignFinal(EVP_MD_CTX * arg_a,unsigned char * arg_b,unsigned int * arg_c,EVP_PKEY * arg_d) 
{
    unsigned long in_lib = syscall(890);
    printf("EVP_SignFinal called %lu\n", in_lib);
    if (!in_lib)
        return bb_EVP_SignFinal(arg_a,arg_b,arg_c,arg_d);
    else {
        int (*orig_EVP_SignFinal)(EVP_MD_CTX *,unsigned char *,unsigned int *,EVP_PKEY *);
        orig_EVP_SignFinal = dlsym(RTLD_NEXT, "EVP_SignFinal");
        return orig_EVP_SignFinal(arg_a,arg_b,arg_c,arg_d);
    }
}

int bb_EVP_SignFinal(EVP_MD_CTX * arg_a,unsigned char * arg_b,unsigned int * arg_c,EVP_PKEY * arg_d) 
{
    int ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 0, 0, /* 0: struct.ASN1_VALUE_st */
            8884097, 8, 0, /* 3: pointer.func */
            0, 136, 11, /* 6: struct.dsa_st */
            	31, 24,
            	31, 32,
            	31, 40,
            	31, 48,
            	31, 56,
            	31, 64,
            	31, 72,
            	49, 88,
            	63, 104,
            	98, 120,
            	151, 128,
            1, 8, 1, /* 31: pointer.struct.bignum_st */
            	36, 0,
            0, 24, 1, /* 36: struct.bignum_st */
            	41, 0,
            1, 8, 1, /* 41: pointer.unsigned int */
            	46, 0,
            0, 4, 0, /* 46: unsigned int */
            1, 8, 1, /* 49: pointer.struct.bn_mont_ctx_st */
            	54, 0,
            0, 96, 3, /* 54: struct.bn_mont_ctx_st */
            	36, 8,
            	36, 32,
            	36, 56,
            0, 16, 1, /* 63: struct.crypto_ex_data_st */
            	68, 0,
            1, 8, 1, /* 68: pointer.struct.stack_st_void */
            	73, 0,
            0, 32, 1, /* 73: struct.stack_st_void */
            	78, 0,
            0, 32, 2, /* 78: struct.stack_st */
            	85, 8,
            	95, 24,
            1, 8, 1, /* 85: pointer.pointer.char */
            	90, 0,
            1, 8, 1, /* 90: pointer.char */
            	8884096, 0,
            8884097, 8, 0, /* 95: pointer.func */
            1, 8, 1, /* 98: pointer.struct.dsa_method */
            	103, 0,
            0, 96, 11, /* 103: struct.dsa_method */
            	128, 0,
            	133, 8,
            	3, 16,
            	136, 24,
            	139, 32,
            	142, 40,
            	145, 48,
            	145, 56,
            	90, 72,
            	148, 80,
            	145, 88,
            1, 8, 1, /* 128: pointer.char */
            	8884096, 0,
            8884097, 8, 0, /* 133: pointer.func */
            8884097, 8, 0, /* 136: pointer.func */
            8884097, 8, 0, /* 139: pointer.func */
            8884097, 8, 0, /* 142: pointer.func */
            8884097, 8, 0, /* 145: pointer.func */
            8884097, 8, 0, /* 148: pointer.func */
            1, 8, 1, /* 151: pointer.struct.engine_st */
            	156, 0,
            0, 0, 0, /* 156: struct.engine_st */
            1, 8, 1, /* 159: pointer.struct.ASN1_VALUE_st */
            	164, 0,
            0, 0, 0, /* 164: struct.ASN1_VALUE_st */
            8884097, 8, 0, /* 167: pointer.func */
            1, 8, 1, /* 170: pointer.struct.asn1_string_st */
            	175, 0,
            0, 24, 1, /* 175: struct.asn1_string_st */
            	180, 8,
            1, 8, 1, /* 180: pointer.unsigned char */
            	185, 0,
            0, 1, 0, /* 185: unsigned char */
            1, 8, 1, /* 188: pointer.struct.asn1_string_st */
            	193, 0,
            0, 24, 1, /* 193: struct.asn1_string_st */
            	180, 8,
            8884097, 8, 0, /* 198: pointer.func */
            8884097, 8, 0, /* 201: pointer.func */
            1, 8, 1, /* 204: pointer.struct.asn1_string_st */
            	175, 0,
            0, 112, 13, /* 209: struct.rsa_meth_st */
            	128, 0,
            	201, 8,
            	201, 16,
            	201, 24,
            	201, 32,
            	238, 40,
            	241, 48,
            	244, 56,
            	244, 64,
            	90, 80,
            	198, 88,
            	247, 96,
            	250, 104,
            8884097, 8, 0, /* 238: pointer.func */
            8884097, 8, 0, /* 241: pointer.func */
            8884097, 8, 0, /* 244: pointer.func */
            8884097, 8, 0, /* 247: pointer.func */
            8884097, 8, 0, /* 250: pointer.func */
            1, 8, 1, /* 253: pointer.struct.asn1_string_st */
            	193, 0,
            1, 8, 1, /* 258: pointer.struct.asn1_string_st */
            	193, 0,
            1, 8, 1, /* 263: pointer.struct.asn1_string_st */
            	175, 0,
            0, 4, 0, /* 268: int */
            8884097, 8, 0, /* 271: pointer.func */
            1, 8, 1, /* 274: pointer.struct.asn1_string_st */
            	175, 0,
            1, 8, 1, /* 279: pointer.struct.env_md_st */
            	284, 0,
            0, 120, 8, /* 284: struct.env_md_st */
            	303, 24,
            	271, 32,
            	167, 40,
            	306, 48,
            	303, 56,
            	309, 64,
            	312, 72,
            	315, 112,
            8884097, 8, 0, /* 303: pointer.func */
            8884097, 8, 0, /* 306: pointer.func */
            8884097, 8, 0, /* 309: pointer.func */
            8884097, 8, 0, /* 312: pointer.func */
            8884097, 8, 0, /* 315: pointer.func */
            0, 144, 12, /* 318: struct.dh_st */
            	31, 8,
            	31, 16,
            	31, 32,
            	31, 40,
            	49, 56,
            	31, 64,
            	31, 72,
            	180, 80,
            	31, 96,
            	63, 112,
            	345, 128,
            	151, 136,
            1, 8, 1, /* 345: pointer.struct.dh_method */
            	350, 0,
            0, 72, 8, /* 350: struct.dh_method */
            	128, 0,
            	369, 8,
            	372, 16,
            	375, 24,
            	369, 32,
            	369, 40,
            	90, 56,
            	378, 64,
            8884097, 8, 0, /* 369: pointer.func */
            8884097, 8, 0, /* 372: pointer.func */
            8884097, 8, 0, /* 375: pointer.func */
            8884097, 8, 0, /* 378: pointer.func */
            0, 48, 5, /* 381: struct.env_md_ctx_st */
            	279, 0,
            	151, 8,
            	394, 24,
            	397, 32,
            	271, 40,
            0, 8, 0, /* 394: pointer.void */
            1, 8, 1, /* 397: pointer.struct.evp_pkey_ctx_st */
            	402, 0,
            0, 0, 0, /* 402: struct.evp_pkey_ctx_st */
            1, 8, 1, /* 405: pointer.struct.ec_key_st */
            	410, 0,
            0, 0, 0, /* 410: struct.ec_key_st */
            1, 8, 1, /* 413: pointer.struct.asn1_string_st */
            	193, 0,
            1, 8, 1, /* 418: pointer.struct.evp_pkey_st */
            	423, 0,
            0, 56, 4, /* 423: struct.evp_pkey_st */
            	434, 16,
            	151, 24,
            	442, 32,
            	520, 48,
            1, 8, 1, /* 434: pointer.struct.evp_pkey_asn1_method_st */
            	439, 0,
            0, 0, 0, /* 439: struct.evp_pkey_asn1_method_st */
            0, 8, 5, /* 442: union.unknown */
            	90, 0,
            	455, 0,
            	510, 0,
            	515, 0,
            	405, 0,
            1, 8, 1, /* 455: pointer.struct.rsa_st */
            	460, 0,
            0, 168, 17, /* 460: struct.rsa_st */
            	497, 16,
            	151, 24,
            	31, 32,
            	31, 40,
            	31, 48,
            	31, 56,
            	31, 64,
            	31, 72,
            	31, 80,
            	31, 88,
            	63, 96,
            	49, 120,
            	49, 128,
            	49, 136,
            	90, 144,
            	502, 152,
            	502, 160,
            1, 8, 1, /* 497: pointer.struct.rsa_meth_st */
            	209, 0,
            1, 8, 1, /* 502: pointer.struct.bn_blinding_st */
            	507, 0,
            0, 0, 0, /* 507: struct.bn_blinding_st */
            1, 8, 1, /* 510: pointer.struct.dsa_st */
            	6, 0,
            1, 8, 1, /* 515: pointer.struct.dh_st */
            	318, 0,
            1, 8, 1, /* 520: pointer.struct.stack_st_X509_ATTRIBUTE */
            	525, 0,
            0, 32, 2, /* 525: struct.stack_st_fake_X509_ATTRIBUTE */
            	532, 8,
            	95, 24,
            8884099, 8, 2, /* 532: pointer_to_array_of_pointers_to_stack */
            	539, 0,
            	268, 20,
            0, 8, 1, /* 539: pointer.X509_ATTRIBUTE */
            	544, 0,
            0, 0, 1, /* 544: X509_ATTRIBUTE */
            	549, 0,
            0, 24, 2, /* 549: struct.x509_attributes_st */
            	556, 0,
            	575, 16,
            1, 8, 1, /* 556: pointer.struct.asn1_object_st */
            	561, 0,
            0, 40, 3, /* 561: struct.asn1_object_st */
            	128, 0,
            	128, 8,
            	570, 24,
            1, 8, 1, /* 570: pointer.unsigned char */
            	185, 0,
            0, 8, 3, /* 575: union.unknown */
            	90, 0,
            	584, 0,
            	730, 0,
            1, 8, 1, /* 584: pointer.struct.stack_st_ASN1_TYPE */
            	589, 0,
            0, 32, 2, /* 589: struct.stack_st_fake_ASN1_TYPE */
            	596, 8,
            	95, 24,
            8884099, 8, 2, /* 596: pointer_to_array_of_pointers_to_stack */
            	603, 0,
            	268, 20,
            0, 8, 1, /* 603: pointer.ASN1_TYPE */
            	608, 0,
            0, 0, 1, /* 608: ASN1_TYPE */
            	613, 0,
            0, 16, 1, /* 613: struct.asn1_type_st */
            	618, 8,
            0, 8, 20, /* 618: union.unknown */
            	90, 0,
            	258, 0,
            	661, 0,
            	675, 0,
            	680, 0,
            	685, 0,
            	690, 0,
            	695, 0,
            	413, 0,
            	700, 0,
            	705, 0,
            	253, 0,
            	710, 0,
            	715, 0,
            	188, 0,
            	720, 0,
            	725, 0,
            	258, 0,
            	258, 0,
            	159, 0,
            1, 8, 1, /* 661: pointer.struct.asn1_object_st */
            	666, 0,
            0, 40, 3, /* 666: struct.asn1_object_st */
            	128, 0,
            	128, 8,
            	570, 24,
            1, 8, 1, /* 675: pointer.struct.asn1_string_st */
            	193, 0,
            1, 8, 1, /* 680: pointer.struct.asn1_string_st */
            	193, 0,
            1, 8, 1, /* 685: pointer.struct.asn1_string_st */
            	193, 0,
            1, 8, 1, /* 690: pointer.struct.asn1_string_st */
            	193, 0,
            1, 8, 1, /* 695: pointer.struct.asn1_string_st */
            	193, 0,
            1, 8, 1, /* 700: pointer.struct.asn1_string_st */
            	193, 0,
            1, 8, 1, /* 705: pointer.struct.asn1_string_st */
            	193, 0,
            1, 8, 1, /* 710: pointer.struct.asn1_string_st */
            	193, 0,
            1, 8, 1, /* 715: pointer.struct.asn1_string_st */
            	193, 0,
            1, 8, 1, /* 720: pointer.struct.asn1_string_st */
            	193, 0,
            1, 8, 1, /* 725: pointer.struct.asn1_string_st */
            	193, 0,
            1, 8, 1, /* 730: pointer.struct.asn1_type_st */
            	735, 0,
            0, 16, 1, /* 735: struct.asn1_type_st */
            	740, 8,
            0, 8, 20, /* 740: union.unknown */
            	90, 0,
            	783, 0,
            	556, 0,
            	788, 0,
            	204, 0,
            	793, 0,
            	263, 0,
            	274, 0,
            	798, 0,
            	803, 0,
            	808, 0,
            	170, 0,
            	813, 0,
            	818, 0,
            	823, 0,
            	828, 0,
            	833, 0,
            	783, 0,
            	783, 0,
            	838, 0,
            1, 8, 1, /* 783: pointer.struct.asn1_string_st */
            	175, 0,
            1, 8, 1, /* 788: pointer.struct.asn1_string_st */
            	175, 0,
            1, 8, 1, /* 793: pointer.struct.asn1_string_st */
            	175, 0,
            1, 8, 1, /* 798: pointer.struct.asn1_string_st */
            	175, 0,
            1, 8, 1, /* 803: pointer.struct.asn1_string_st */
            	175, 0,
            1, 8, 1, /* 808: pointer.struct.asn1_string_st */
            	175, 0,
            1, 8, 1, /* 813: pointer.struct.asn1_string_st */
            	175, 0,
            1, 8, 1, /* 818: pointer.struct.asn1_string_st */
            	175, 0,
            1, 8, 1, /* 823: pointer.struct.asn1_string_st */
            	175, 0,
            1, 8, 1, /* 828: pointer.struct.asn1_string_st */
            	175, 0,
            1, 8, 1, /* 833: pointer.struct.asn1_string_st */
            	175, 0,
            1, 8, 1, /* 838: pointer.struct.ASN1_VALUE_st */
            	0, 0,
            1, 8, 1, /* 843: pointer.struct.env_md_ctx_st */
            	381, 0,
            0, 1, 0, /* 848: char */
        },
        .arg_entity_index = { 843, 180, 41, 418, },
        .ret_entity_index = 268,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_arg(args_addr, arg_d);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    EVP_MD_CTX * new_arg_a = *((EVP_MD_CTX * *)new_args->args[0]);

    unsigned char * new_arg_b = *((unsigned char * *)new_args->args[1]);

    unsigned int * new_arg_c = *((unsigned int * *)new_args->args[2]);

    EVP_PKEY * new_arg_d = *((EVP_PKEY * *)new_args->args[3]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_EVP_SignFinal)(EVP_MD_CTX *,unsigned char *,unsigned int *,EVP_PKEY *);
    orig_EVP_SignFinal = dlsym(RTLD_NEXT, "EVP_SignFinal");
    *new_ret_ptr = (*orig_EVP_SignFinal)(new_arg_a,new_arg_b,new_arg_c,new_arg_d);

    syscall(889);

    return ret;
}

