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

int EVP_DigestUpdate(EVP_MD_CTX * arg_a, const void * arg_b,size_t arg_c) 
{
    int ret;

    struct lib_enter_args args = {
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
            0, 208, 27, /* 107: struct.evp_pkey_asn1_method_st */
            	164, 0,
            	164, 4,
            	167, 8,
            	5, 16,
            	5, 24,
            	170, 32,
            	178, 40,
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
            	183, 200,
            0, 4, 0, /* 164: int */
            0, 8, 0, /* 167: long */
            1, 8, 1, /* 170: pointer.struct.unnamed */
            	175, 0,
            0, 0, 0, /* 175: struct.unnamed */
            1, 8, 1, /* 178: pointer.func */
            	104, 0,
            1, 8, 1, /* 183: pointer.func */
            	13, 0,
            1, 8, 1, /* 188: pointer.struct.evp_pkey_asn1_method_st */
            	107, 0,
            0, 56, 8, /* 193: struct.evp_pkey_st */
            	164, 0,
            	164, 4,
            	164, 8,
            	188, 16,
            	212, 24,
            	0, 32,
            	164, 40,
            	735, 48,
            1, 8, 1, /* 212: pointer.struct.engine_st */
            	217, 0,
            0, 216, 27, /* 217: struct.engine_st */
            	5, 0,
            	5, 8,
            	274, 16,
            	366, 24,
            	454, 32,
            	512, 40,
            	536, 48,
            	580, 56,
            	640, 64,
            	648, 72,
            	656, 80,
            	664, 88,
            	672, 96,
            	680, 104,
            	680, 112,
            	680, 120,
            	688, 128,
            	696, 136,
            	696, 144,
            	704, 152,
            	712, 160,
            	164, 168,
            	164, 172,
            	164, 176,
            	728, 184,
            	212, 200,
            	212, 208,
            1, 8, 1, /* 274: pointer.struct.rsa_meth_st */
            	279, 0,
            0, 112, 14, /* 279: struct.rsa_meth_st */
            	5, 0,
            	310, 8,
            	310, 16,
            	310, 24,
            	310, 32,
            	318, 40,
            	326, 48,
            	334, 56,
            	334, 64,
            	164, 72,
            	5, 80,
            	342, 88,
            	350, 96,
            	358, 104,
            1, 8, 1, /* 310: pointer.func */
            	315, 0,
            0, 0, 0, /* 315: func */
            1, 8, 1, /* 318: pointer.func */
            	323, 0,
            0, 0, 0, /* 323: func */
            1, 8, 1, /* 326: pointer.func */
            	331, 0,
            0, 0, 0, /* 331: func */
            1, 8, 1, /* 334: pointer.func */
            	339, 0,
            0, 0, 0, /* 339: func */
            1, 8, 1, /* 342: pointer.func */
            	347, 0,
            0, 0, 0, /* 347: func */
            1, 8, 1, /* 350: pointer.func */
            	355, 0,
            0, 0, 0, /* 355: func */
            1, 8, 1, /* 358: pointer.func */
            	363, 0,
            0, 0, 0, /* 363: func */
            1, 8, 1, /* 366: pointer.struct.dsa_method.1040 */
            	371, 0,
            0, 96, 12, /* 371: struct.dsa_method.1040 */
            	5, 0,
            	398, 8,
            	406, 16,
            	414, 24,
            	422, 32,
            	430, 40,
            	438, 48,
            	438, 56,
            	164, 64,
            	5, 72,
            	446, 80,
            	438, 88,
            1, 8, 1, /* 398: pointer.func */
            	403, 0,
            0, 0, 0, /* 403: func */
            1, 8, 1, /* 406: pointer.func */
            	411, 0,
            0, 0, 0, /* 411: func */
            1, 8, 1, /* 414: pointer.func */
            	419, 0,
            0, 0, 0, /* 419: func */
            1, 8, 1, /* 422: pointer.func */
            	427, 0,
            0, 0, 0, /* 427: func */
            1, 8, 1, /* 430: pointer.func */
            	435, 0,
            0, 0, 0, /* 435: func */
            1, 8, 1, /* 438: pointer.func */
            	443, 0,
            0, 0, 0, /* 443: func */
            1, 8, 1, /* 446: pointer.func */
            	451, 0,
            0, 0, 0, /* 451: func */
            1, 8, 1, /* 454: pointer.struct.dh_method */
            	459, 0,
            0, 72, 9, /* 459: struct.dh_method */
            	5, 0,
            	480, 8,
            	488, 16,
            	496, 24,
            	480, 32,
            	480, 40,
            	164, 48,
            	5, 56,
            	504, 64,
            1, 8, 1, /* 480: pointer.func */
            	485, 0,
            0, 0, 0, /* 485: func */
            1, 8, 1, /* 488: pointer.func */
            	493, 0,
            0, 0, 0, /* 493: func */
            1, 8, 1, /* 496: pointer.func */
            	501, 0,
            0, 0, 0, /* 501: func */
            1, 8, 1, /* 504: pointer.func */
            	509, 0,
            0, 0, 0, /* 509: func */
            1, 8, 1, /* 512: pointer.struct.ecdh_method */
            	517, 0,
            0, 32, 4, /* 517: struct.ecdh_method */
            	5, 0,
            	528, 8,
            	164, 16,
            	5, 24,
            1, 8, 1, /* 528: pointer.func */
            	533, 0,
            0, 0, 0, /* 533: func */
            1, 8, 1, /* 536: pointer.struct.ecdsa_method */
            	541, 0,
            0, 48, 6, /* 541: struct.ecdsa_method */
            	5, 0,
            	556, 8,
            	564, 16,
            	572, 24,
            	164, 32,
            	5, 40,
            1, 8, 1, /* 556: pointer.func */
            	561, 0,
            0, 0, 0, /* 561: func */
            1, 8, 1, /* 564: pointer.func */
            	569, 0,
            0, 0, 0, /* 569: func */
            1, 8, 1, /* 572: pointer.func */
            	577, 0,
            0, 0, 0, /* 577: func */
            1, 8, 1, /* 580: pointer.struct.rand_meth_st */
            	585, 0,
            0, 48, 6, /* 585: struct.rand_meth_st */
            	600, 0,
            	608, 8,
            	616, 16,
            	624, 24,
            	608, 32,
            	632, 40,
            1, 8, 1, /* 600: pointer.func */
            	605, 0,
            0, 0, 0, /* 605: func */
            1, 8, 1, /* 608: pointer.func */
            	613, 0,
            0, 0, 0, /* 613: func */
            1, 8, 1, /* 616: pointer.func */
            	621, 0,
            0, 0, 0, /* 621: func */
            1, 8, 1, /* 624: pointer.func */
            	629, 0,
            0, 0, 0, /* 629: func */
            1, 8, 1, /* 632: pointer.func */
            	637, 0,
            0, 0, 0, /* 637: func */
            1, 8, 1, /* 640: pointer.struct.store_method_st */
            	645, 0,
            0, 0, 0, /* 645: struct.store_method_st */
            1, 8, 1, /* 648: pointer.func */
            	653, 0,
            0, 0, 0, /* 653: func */
            1, 8, 1, /* 656: pointer.func */
            	661, 0,
            0, 0, 0, /* 661: func */
            1, 8, 1, /* 664: pointer.func */
            	669, 0,
            0, 0, 0, /* 669: func */
            1, 8, 1, /* 672: pointer.func */
            	677, 0,
            0, 0, 0, /* 677: func */
            1, 8, 1, /* 680: pointer.func */
            	685, 0,
            0, 0, 0, /* 685: func */
            1, 8, 1, /* 688: pointer.func */
            	693, 0,
            0, 0, 0, /* 693: func */
            1, 8, 1, /* 696: pointer.func */
            	701, 0,
            0, 0, 0, /* 701: func */
            1, 8, 1, /* 704: pointer.func */
            	709, 0,
            0, 0, 0, /* 709: func */
            1, 8, 1, /* 712: pointer.struct.ENGINE_CMD_DEFN_st */
            	717, 0,
            0, 32, 4, /* 717: struct.ENGINE_CMD_DEFN_st */
            	164, 0,
            	5, 8,
            	5, 16,
            	164, 24,
            0, 16, 2, /* 728: struct.crypto_ex_data_st */
            	735, 0,
            	164, 8,
            1, 8, 1, /* 735: pointer.struct.stack_st_OPENSSL_STRING */
            	740, 0,
            0, 32, 1, /* 740: struct.stack_st_OPENSSL_STRING */
            	745, 0,
            0, 32, 5, /* 745: struct.stack_st */
            	164, 0,
            	758, 8,
            	164, 16,
            	164, 20,
            	763, 24,
            1, 8, 1, /* 758: pointer.pointer.char */
            	5, 0,
            1, 8, 1, /* 763: pointer.func */
            	768, 0,
            0, 0, 0, /* 768: func */
            0, 0, 0, /* 771: func */
            1, 8, 1, /* 774: pointer.func */
            	771, 0,
            1, 8, 1, /* 779: pointer.func */
            	784, 0,
            0, 0, 0, /* 784: func */
            0, 0, 0, /* 787: func */
            1, 8, 1, /* 790: pointer.func */
            	787, 0,
            0, 0, 0, /* 795: func */
            1, 8, 1, /* 798: pointer.func */
            	803, 0,
            0, 0, 0, /* 803: func */
            1, 8, 1, /* 806: pointer.func */
            	811, 0,
            0, 0, 0, /* 811: func */
            1, 8, 1, /* 814: pointer.func */
            	819, 0,
            0, 0, 0, /* 819: func */
            0, 0, 0, /* 822: func */
            1, 8, 1, /* 825: pointer.func */
            	830, 0,
            0, 0, 0, /* 830: func */
            1, 8, 1, /* 833: pointer.func */
            	838, 0,
            0, 0, 0, /* 838: func */
            1, 8, 1, /* 841: pointer.func */
            	846, 0,
            0, 0, 0, /* 846: func */
            1, 8, 1, /* 849: pointer.struct.evp_pkey_st */
            	193, 0,
            0, 0, 0, /* 854: func */
            0, 0, 0, /* 857: func */
            1, 8, 1, /* 860: pointer.func */
            	795, 0,
            0, 120, 15, /* 865: struct.env_md_st */
            	164, 0,
            	164, 4,
            	164, 8,
            	167, 16,
            	898, 24,
            	906, 32,
            	841, 40,
            	911, 48,
            	898, 56,
            	919, 64,
            	924, 72,
            	932, 80,
            	164, 100,
            	164, 104,
            	945, 112,
            1, 8, 1, /* 898: pointer.func */
            	903, 0,
            0, 0, 0, /* 903: func */
            1, 8, 1, /* 906: pointer.func */
            	857, 0,
            1, 8, 1, /* 911: pointer.func */
            	916, 0,
            0, 0, 0, /* 916: func */
            1, 8, 1, /* 919: pointer.func */
            	854, 0,
            1, 8, 1, /* 924: pointer.func */
            	929, 0,
            0, 0, 0, /* 929: func */
            0, 20, 5, /* 932: array[5].int */
            	164, 0,
            	164, 4,
            	164, 8,
            	164, 12,
            	164, 16,
            1, 8, 1, /* 945: pointer.func */
            	950, 0,
            0, 0, 0, /* 950: func */
            1, 8, 1, /* 953: pointer.struct.env_md_st */
            	865, 0,
            0, 48, 6, /* 958: struct.env_md_ctx_st */
            	953, 0,
            	212, 8,
            	167, 16,
            	5, 24,
            	973, 32,
            	906, 40,
            1, 8, 1, /* 973: pointer.struct.evp_pkey_ctx_st */
            	978, 0,
            0, 80, 10, /* 978: struct.evp_pkey_ctx_st */
            	1001, 0,
            	212, 8,
            	849, 16,
            	849, 24,
            	164, 32,
            	5, 40,
            	5, 48,
            	170, 56,
            	1076, 64,
            	164, 72,
            1, 8, 1, /* 1001: pointer.struct.evp_pkey_method_st */
            	1006, 0,
            0, 208, 27, /* 1006: struct.evp_pkey_method_st */
            	164, 0,
            	164, 4,
            	170, 8,
            	1063, 16,
            	1071, 24,
            	170, 32,
            	814, 40,
            	170, 48,
            	814, 56,
            	170, 64,
            	806, 72,
            	170, 80,
            	798, 88,
            	170, 96,
            	806, 104,
            	860, 112,
            	790, 120,
            	860, 128,
            	833, 136,
            	170, 144,
            	806, 152,
            	170, 160,
            	806, 168,
            	170, 176,
            	825, 184,
            	779, 192,
            	774, 200,
            1, 8, 1, /* 1063: pointer.func */
            	1068, 0,
            0, 0, 0, /* 1068: func */
            1, 8, 1, /* 1071: pointer.func */
            	822, 0,
            1, 8, 1, /* 1076: pointer.int */
            	164, 0,
            1, 8, 1, /* 1081: pointer.struct.env_md_ctx_st */
            	958, 0,
        },
        .arg_entity_index = { 1081, 5, 167, },
        .ret_entity_index = 164,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    EVP_MD_CTX * new_arg_a = *((EVP_MD_CTX * *)new_args->args[0]);

     const void * new_arg_b = *(( const void * *)new_args->args[1]);

    size_t new_arg_c = *((size_t *)new_args->args[2]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_EVP_DigestUpdate)(EVP_MD_CTX *, const void *,size_t);
    orig_EVP_DigestUpdate = dlsym(RTLD_NEXT, "EVP_DigestUpdate");
    *new_ret_ptr = (*orig_EVP_DigestUpdate)(new_arg_a,new_arg_b,new_arg_c);

    syscall(889);

    return ret;
}

