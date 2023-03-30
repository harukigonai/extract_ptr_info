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

int EVP_DigestInit_ex(EVP_MD_CTX * arg_a,const EVP_MD * arg_b,ENGINE * arg_c) 
{
    if (syscall(890))
        return _EVP_DigestInit_ex(arg_a,arg_b,arg_c)
    else {
        int (*orig_EVP_DigestInit_ex)(EVP_MD_CTX *,const EVP_MD *,ENGINE *);
        orig_EVP_DigestInit_ex = dlsym(RTLD_NEXT, "EVP_DigestInit_ex");
        return orig_EVP_DigestInit_ex(arg_a,arg_b,arg_c);
    }
}

int _EVP_DigestInit_ex(EVP_MD_CTX * arg_a,const EVP_MD * arg_b,ENGINE * arg_c) 
{
    printf("EVP_DigestInit_ex called\n");
    int ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 8, 1, /* 0: struct.fnames */
            	5, 0,
            1, 8, 1, /* 5: pointer.char */
            	10, 0,
            0, 1, 0, /* 10: char */
            0, 0, 0, /* 13: func */
            1, 8, 1, /* 16: pointer.func */
            	21, 0,
            0, 0, 0, /* 21: func */
            0, 0, 0, /* 24: func */
            1, 8, 1, /* 27: pointer.func */
            	24, 0,
            1, 8, 1, /* 32: pointer.func */
            	37, 0,
            0, 0, 0, /* 37: func */
            0, 0, 0, /* 40: func */
            1, 8, 1, /* 43: pointer.func */
            	40, 0,
            0, 0, 0, /* 48: func */
            1, 8, 1, /* 51: pointer.func */
            	48, 0,
            0, 0, 0, /* 56: func */
            1, 8, 1, /* 59: pointer.func */
            	56, 0,
            0, 0, 0, /* 64: func */
            1, 8, 1, /* 67: pointer.func */
            	64, 0,
            1, 8, 1, /* 72: pointer.func */
            	77, 0,
            0, 0, 0, /* 77: func */
            1, 8, 1, /* 80: pointer.func */
            	85, 0,
            0, 0, 0, /* 85: func */
            0, 0, 0, /* 88: func */
            1, 8, 1, /* 91: pointer.func */
            	88, 0,
            0, 0, 0, /* 96: func */
            1, 8, 1, /* 99: pointer.func */
            	96, 0,
            0, 0, 0, /* 104: func */
            0, 208, 24, /* 107: struct.evp_pkey_asn1_method_st */
            	5, 16,
            	5, 24,
            	158, 32,
            	166, 40,
            	99, 48,
            	91, 56,
            	80, 64,
            	72, 72,
            	91, 80,
            	67, 88,
            	67, 96,
            	59, 104,
            	51, 112,
            	67, 120,
            	99, 128,
            	99, 136,
            	91, 144,
            	43, 152,
            	32, 160,
            	27, 168,
            	59, 176,
            	51, 184,
            	16, 192,
            	171, 200,
            1, 8, 1, /* 158: pointer.struct.unnamed */
            	163, 0,
            0, 0, 0, /* 163: struct.unnamed */
            1, 8, 1, /* 166: pointer.func */
            	104, 0,
            1, 8, 1, /* 171: pointer.func */
            	13, 0,
            1, 8, 1, /* 176: pointer.struct.evp_pkey_asn1_method_st */
            	107, 0,
            0, 56, 4, /* 181: struct.evp_pkey_st */
            	176, 16,
            	192, 24,
            	0, 32,
            	693, 48,
            1, 8, 1, /* 192: pointer.struct.engine_st */
            	197, 0,
            0, 216, 24, /* 197: struct.engine_st */
            	5, 0,
            	5, 8,
            	248, 16,
            	338, 24,
            	424, 32,
            	480, 40,
            	502, 48,
            	544, 56,
            	604, 64,
            	612, 72,
            	620, 80,
            	628, 88,
            	636, 96,
            	644, 104,
            	644, 112,
            	644, 120,
            	652, 128,
            	660, 136,
            	660, 144,
            	668, 152,
            	676, 160,
            	688, 184,
            	192, 200,
            	192, 208,
            1, 8, 1, /* 248: pointer.struct.rsa_meth_st */
            	253, 0,
            0, 112, 13, /* 253: struct.rsa_meth_st */
            	5, 0,
            	282, 8,
            	282, 16,
            	282, 24,
            	282, 32,
            	290, 40,
            	298, 48,
            	306, 56,
            	306, 64,
            	5, 80,
            	314, 88,
            	322, 96,
            	330, 104,
            1, 8, 1, /* 282: pointer.func */
            	287, 0,
            0, 0, 0, /* 287: func */
            1, 8, 1, /* 290: pointer.func */
            	295, 0,
            0, 0, 0, /* 295: func */
            1, 8, 1, /* 298: pointer.func */
            	303, 0,
            0, 0, 0, /* 303: func */
            1, 8, 1, /* 306: pointer.func */
            	311, 0,
            0, 0, 0, /* 311: func */
            1, 8, 1, /* 314: pointer.func */
            	319, 0,
            0, 0, 0, /* 319: func */
            1, 8, 1, /* 322: pointer.func */
            	327, 0,
            0, 0, 0, /* 327: func */
            1, 8, 1, /* 330: pointer.func */
            	335, 0,
            0, 0, 0, /* 335: func */
            1, 8, 1, /* 338: pointer.struct.dsa_method.1040 */
            	343, 0,
            0, 96, 11, /* 343: struct.dsa_method.1040 */
            	5, 0,
            	368, 8,
            	376, 16,
            	384, 24,
            	392, 32,
            	400, 40,
            	408, 48,
            	408, 56,
            	5, 72,
            	416, 80,
            	408, 88,
            1, 8, 1, /* 368: pointer.func */
            	373, 0,
            0, 0, 0, /* 373: func */
            1, 8, 1, /* 376: pointer.func */
            	381, 0,
            0, 0, 0, /* 381: func */
            1, 8, 1, /* 384: pointer.func */
            	389, 0,
            0, 0, 0, /* 389: func */
            1, 8, 1, /* 392: pointer.func */
            	397, 0,
            0, 0, 0, /* 397: func */
            1, 8, 1, /* 400: pointer.func */
            	405, 0,
            0, 0, 0, /* 405: func */
            1, 8, 1, /* 408: pointer.func */
            	413, 0,
            0, 0, 0, /* 413: func */
            1, 8, 1, /* 416: pointer.func */
            	421, 0,
            0, 0, 0, /* 421: func */
            1, 8, 1, /* 424: pointer.struct.dh_method */
            	429, 0,
            0, 72, 8, /* 429: struct.dh_method */
            	5, 0,
            	448, 8,
            	456, 16,
            	464, 24,
            	448, 32,
            	448, 40,
            	5, 56,
            	472, 64,
            1, 8, 1, /* 448: pointer.func */
            	453, 0,
            0, 0, 0, /* 453: func */
            1, 8, 1, /* 456: pointer.func */
            	461, 0,
            0, 0, 0, /* 461: func */
            1, 8, 1, /* 464: pointer.func */
            	469, 0,
            0, 0, 0, /* 469: func */
            1, 8, 1, /* 472: pointer.func */
            	477, 0,
            0, 0, 0, /* 477: func */
            1, 8, 1, /* 480: pointer.struct.ecdh_method */
            	485, 0,
            0, 32, 3, /* 485: struct.ecdh_method */
            	5, 0,
            	494, 8,
            	5, 24,
            1, 8, 1, /* 494: pointer.func */
            	499, 0,
            0, 0, 0, /* 499: func */
            1, 8, 1, /* 502: pointer.struct.ecdsa_method */
            	507, 0,
            0, 48, 5, /* 507: struct.ecdsa_method */
            	5, 0,
            	520, 8,
            	528, 16,
            	536, 24,
            	5, 40,
            1, 8, 1, /* 520: pointer.func */
            	525, 0,
            0, 0, 0, /* 525: func */
            1, 8, 1, /* 528: pointer.func */
            	533, 0,
            0, 0, 0, /* 533: func */
            1, 8, 1, /* 536: pointer.func */
            	541, 0,
            0, 0, 0, /* 541: func */
            1, 8, 1, /* 544: pointer.struct.rand_meth_st */
            	549, 0,
            0, 48, 6, /* 549: struct.rand_meth_st */
            	564, 0,
            	572, 8,
            	580, 16,
            	588, 24,
            	572, 32,
            	596, 40,
            1, 8, 1, /* 564: pointer.func */
            	569, 0,
            0, 0, 0, /* 569: func */
            1, 8, 1, /* 572: pointer.func */
            	577, 0,
            0, 0, 0, /* 577: func */
            1, 8, 1, /* 580: pointer.func */
            	585, 0,
            0, 0, 0, /* 585: func */
            1, 8, 1, /* 588: pointer.func */
            	593, 0,
            0, 0, 0, /* 593: func */
            1, 8, 1, /* 596: pointer.func */
            	601, 0,
            0, 0, 0, /* 601: func */
            1, 8, 1, /* 604: pointer.struct.store_method_st */
            	609, 0,
            0, 0, 0, /* 609: struct.store_method_st */
            1, 8, 1, /* 612: pointer.func */
            	617, 0,
            0, 0, 0, /* 617: func */
            1, 8, 1, /* 620: pointer.func */
            	625, 0,
            0, 0, 0, /* 625: func */
            1, 8, 1, /* 628: pointer.func */
            	633, 0,
            0, 0, 0, /* 633: func */
            1, 8, 1, /* 636: pointer.func */
            	641, 0,
            0, 0, 0, /* 641: func */
            1, 8, 1, /* 644: pointer.func */
            	649, 0,
            0, 0, 0, /* 649: func */
            1, 8, 1, /* 652: pointer.func */
            	657, 0,
            0, 0, 0, /* 657: func */
            1, 8, 1, /* 660: pointer.func */
            	665, 0,
            0, 0, 0, /* 665: func */
            1, 8, 1, /* 668: pointer.func */
            	673, 0,
            0, 0, 0, /* 673: func */
            1, 8, 1, /* 676: pointer.struct.ENGINE_CMD_DEFN_st */
            	681, 0,
            0, 32, 2, /* 681: struct.ENGINE_CMD_DEFN_st */
            	5, 8,
            	5, 16,
            0, 16, 1, /* 688: struct.crypto_ex_data_st */
            	693, 0,
            1, 8, 1, /* 693: pointer.struct.stack_st_OPENSSL_STRING */
            	698, 0,
            0, 32, 1, /* 698: struct.stack_st_OPENSSL_STRING */
            	703, 0,
            0, 32, 2, /* 703: struct.stack_st */
            	710, 8,
            	715, 24,
            1, 8, 1, /* 710: pointer.pointer.char */
            	5, 0,
            1, 8, 1, /* 715: pointer.func */
            	720, 0,
            0, 0, 0, /* 720: func */
            0, 0, 0, /* 723: func */
            1, 8, 1, /* 726: pointer.func */
            	723, 0,
            1, 8, 1, /* 731: pointer.func */
            	736, 0,
            0, 0, 0, /* 736: func */
            0, 0, 0, /* 739: func */
            1, 8, 1, /* 742: pointer.func */
            	739, 0,
            0, 0, 0, /* 747: func */
            1, 8, 1, /* 750: pointer.func */
            	755, 0,
            0, 0, 0, /* 755: func */
            1, 8, 1, /* 758: pointer.func */
            	763, 0,
            0, 0, 0, /* 763: func */
            1, 8, 1, /* 766: pointer.func */
            	771, 0,
            0, 0, 0, /* 771: func */
            0, 0, 0, /* 774: func */
            1, 8, 1, /* 777: pointer.func */
            	782, 0,
            0, 0, 0, /* 782: func */
            1, 8, 1, /* 785: pointer.func */
            	790, 0,
            0, 0, 0, /* 790: func */
            0, 0, 0, /* 793: func */
            1, 8, 1, /* 796: pointer.func */
            	801, 0,
            0, 0, 0, /* 801: func */
            1, 8, 1, /* 804: pointer.struct.env_md_st */
            	809, 0,
            0, 120, 8, /* 809: struct.env_md_st */
            	828, 24,
            	833, 32,
            	796, 40,
            	841, 48,
            	828, 56,
            	849, 64,
            	857, 72,
            	865, 112,
            1, 8, 1, /* 828: pointer.func */
            	793, 0,
            1, 8, 1, /* 833: pointer.func */
            	838, 0,
            0, 0, 0, /* 838: func */
            1, 8, 1, /* 841: pointer.func */
            	846, 0,
            0, 0, 0, /* 846: func */
            1, 8, 1, /* 849: pointer.func */
            	854, 0,
            0, 0, 0, /* 854: func */
            1, 8, 1, /* 857: pointer.func */
            	862, 0,
            0, 0, 0, /* 862: func */
            1, 8, 1, /* 865: pointer.func */
            	870, 0,
            0, 0, 0, /* 870: func */
            0, 48, 5, /* 873: struct.env_md_ctx_st */
            	804, 0,
            	192, 8,
            	5, 24,
            	886, 32,
            	833, 40,
            1, 8, 1, /* 886: pointer.struct.evp_pkey_ctx_st */
            	891, 0,
            0, 80, 8, /* 891: struct.evp_pkey_ctx_st */
            	910, 0,
            	192, 8,
            	986, 16,
            	986, 24,
            	5, 40,
            	5, 48,
            	158, 56,
            	991, 64,
            1, 8, 1, /* 910: pointer.struct.evp_pkey_method_st */
            	915, 0,
            0, 208, 25, /* 915: struct.evp_pkey_method_st */
            	158, 8,
            	968, 16,
            	976, 24,
            	158, 32,
            	766, 40,
            	158, 48,
            	766, 56,
            	158, 64,
            	758, 72,
            	158, 80,
            	750, 88,
            	158, 96,
            	758, 104,
            	981, 112,
            	742, 120,
            	981, 128,
            	785, 136,
            	158, 144,
            	758, 152,
            	158, 160,
            	758, 168,
            	158, 176,
            	777, 184,
            	731, 192,
            	726, 200,
            1, 8, 1, /* 968: pointer.func */
            	973, 0,
            0, 0, 0, /* 973: func */
            1, 8, 1, /* 976: pointer.func */
            	774, 0,
            1, 8, 1, /* 981: pointer.func */
            	747, 0,
            1, 8, 1, /* 986: pointer.struct.evp_pkey_st */
            	181, 0,
            1, 8, 1, /* 991: pointer.int */
            	996, 0,
            0, 4, 0, /* 996: int */
            1, 8, 1, /* 999: pointer.struct.env_md_ctx_st */
            	873, 0,
            0, 20, 0, /* 1004: array[5].int */
            0, 8, 0, /* 1007: long */
        },
        .arg_entity_index = { 999, 804, 192, },
        .ret_entity_index = 996,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    EVP_MD_CTX * new_arg_a = *((EVP_MD_CTX * *)new_args->args[0]);

    const EVP_MD * new_arg_b = *((const EVP_MD * *)new_args->args[1]);

    ENGINE * new_arg_c = *((ENGINE * *)new_args->args[2]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_EVP_DigestInit_ex)(EVP_MD_CTX *,const EVP_MD *,ENGINE *);
    orig_EVP_DigestInit_ex = dlsym(RTLD_NEXT, "EVP_DigestInit_ex");
    *new_ret_ptr = (*orig_EVP_DigestInit_ex)(new_arg_a,new_arg_b,new_arg_c);

    syscall(889);

    return ret;
}

