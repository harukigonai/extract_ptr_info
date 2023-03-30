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

int bb_HMAC_Init_ex(HMAC_CTX * arg_a,const void * arg_b,int arg_c,const EVP_MD * arg_d,ENGINE * arg_e);

int HMAC_Init_ex(HMAC_CTX * arg_a,const void * arg_b,int arg_c,const EVP_MD * arg_d,ENGINE * arg_e) 
{
    printf("HMAC_Init_ex called\n");
    if (syscall(890))
        return bb_HMAC_Init_ex(arg_a,arg_b,arg_c,arg_d,arg_e);
    else {
        int (*orig_HMAC_Init_ex)(HMAC_CTX *,const void *,int,const EVP_MD *,ENGINE *);
        orig_HMAC_Init_ex = dlsym(RTLD_NEXT, "HMAC_Init_ex");
        return orig_HMAC_Init_ex(arg_a,arg_b,arg_c,arg_d,arg_e);
    }
}

int bb_HMAC_Init_ex(HMAC_CTX * arg_a,const void * arg_b,int arg_c,const EVP_MD * arg_d,ENGINE * arg_e) 
{
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
            0, 128, 0, /* 43: array[128].char */
            1, 8, 1, /* 46: pointer.func */
            	40, 0,
            0, 0, 0, /* 51: func */
            1, 8, 1, /* 54: pointer.func */
            	51, 0,
            0, 0, 0, /* 59: func */
            1, 8, 1, /* 62: pointer.func */
            	59, 0,
            0, 0, 0, /* 67: func */
            1, 8, 1, /* 70: pointer.func */
            	67, 0,
            1, 8, 1, /* 75: pointer.func */
            	80, 0,
            0, 0, 0, /* 80: func */
            1, 8, 1, /* 83: pointer.func */
            	88, 0,
            0, 0, 0, /* 88: func */
            0, 0, 0, /* 91: func */
            1, 8, 1, /* 94: pointer.func */
            	91, 0,
            0, 0, 0, /* 99: func */
            1, 8, 1, /* 102: pointer.func */
            	99, 0,
            0, 0, 0, /* 107: func */
            0, 208, 24, /* 110: struct.evp_pkey_asn1_method_st */
            	5, 16,
            	5, 24,
            	161, 32,
            	169, 40,
            	102, 48,
            	94, 56,
            	83, 64,
            	75, 72,
            	94, 80,
            	70, 88,
            	70, 96,
            	62, 104,
            	54, 112,
            	70, 120,
            	102, 128,
            	102, 136,
            	94, 144,
            	46, 152,
            	32, 160,
            	27, 168,
            	62, 176,
            	54, 184,
            	16, 192,
            	174, 200,
            1, 8, 1, /* 161: pointer.struct.unnamed */
            	166, 0,
            0, 0, 0, /* 166: struct.unnamed */
            1, 8, 1, /* 169: pointer.func */
            	107, 0,
            1, 8, 1, /* 174: pointer.func */
            	13, 0,
            1, 8, 1, /* 179: pointer.struct.evp_pkey_asn1_method_st */
            	110, 0,
            0, 56, 4, /* 184: struct.evp_pkey_st */
            	179, 16,
            	195, 24,
            	0, 32,
            	696, 48,
            1, 8, 1, /* 195: pointer.struct.engine_st */
            	200, 0,
            0, 216, 24, /* 200: struct.engine_st */
            	5, 0,
            	5, 8,
            	251, 16,
            	341, 24,
            	427, 32,
            	483, 40,
            	505, 48,
            	547, 56,
            	607, 64,
            	615, 72,
            	623, 80,
            	631, 88,
            	639, 96,
            	647, 104,
            	647, 112,
            	647, 120,
            	655, 128,
            	663, 136,
            	663, 144,
            	671, 152,
            	679, 160,
            	691, 184,
            	195, 200,
            	195, 208,
            1, 8, 1, /* 251: pointer.struct.rsa_meth_st */
            	256, 0,
            0, 112, 13, /* 256: struct.rsa_meth_st */
            	5, 0,
            	285, 8,
            	285, 16,
            	285, 24,
            	285, 32,
            	293, 40,
            	301, 48,
            	309, 56,
            	309, 64,
            	5, 80,
            	317, 88,
            	325, 96,
            	333, 104,
            1, 8, 1, /* 285: pointer.func */
            	290, 0,
            0, 0, 0, /* 290: func */
            1, 8, 1, /* 293: pointer.func */
            	298, 0,
            0, 0, 0, /* 298: func */
            1, 8, 1, /* 301: pointer.func */
            	306, 0,
            0, 0, 0, /* 306: func */
            1, 8, 1, /* 309: pointer.func */
            	314, 0,
            0, 0, 0, /* 314: func */
            1, 8, 1, /* 317: pointer.func */
            	322, 0,
            0, 0, 0, /* 322: func */
            1, 8, 1, /* 325: pointer.func */
            	330, 0,
            0, 0, 0, /* 330: func */
            1, 8, 1, /* 333: pointer.func */
            	338, 0,
            0, 0, 0, /* 338: func */
            1, 8, 1, /* 341: pointer.struct.dsa_method.1040 */
            	346, 0,
            0, 96, 11, /* 346: struct.dsa_method.1040 */
            	5, 0,
            	371, 8,
            	379, 16,
            	387, 24,
            	395, 32,
            	403, 40,
            	411, 48,
            	411, 56,
            	5, 72,
            	419, 80,
            	411, 88,
            1, 8, 1, /* 371: pointer.func */
            	376, 0,
            0, 0, 0, /* 376: func */
            1, 8, 1, /* 379: pointer.func */
            	384, 0,
            0, 0, 0, /* 384: func */
            1, 8, 1, /* 387: pointer.func */
            	392, 0,
            0, 0, 0, /* 392: func */
            1, 8, 1, /* 395: pointer.func */
            	400, 0,
            0, 0, 0, /* 400: func */
            1, 8, 1, /* 403: pointer.func */
            	408, 0,
            0, 0, 0, /* 408: func */
            1, 8, 1, /* 411: pointer.func */
            	416, 0,
            0, 0, 0, /* 416: func */
            1, 8, 1, /* 419: pointer.func */
            	424, 0,
            0, 0, 0, /* 424: func */
            1, 8, 1, /* 427: pointer.struct.dh_method */
            	432, 0,
            0, 72, 8, /* 432: struct.dh_method */
            	5, 0,
            	451, 8,
            	459, 16,
            	467, 24,
            	451, 32,
            	451, 40,
            	5, 56,
            	475, 64,
            1, 8, 1, /* 451: pointer.func */
            	456, 0,
            0, 0, 0, /* 456: func */
            1, 8, 1, /* 459: pointer.func */
            	464, 0,
            0, 0, 0, /* 464: func */
            1, 8, 1, /* 467: pointer.func */
            	472, 0,
            0, 0, 0, /* 472: func */
            1, 8, 1, /* 475: pointer.func */
            	480, 0,
            0, 0, 0, /* 480: func */
            1, 8, 1, /* 483: pointer.struct.ecdh_method */
            	488, 0,
            0, 32, 3, /* 488: struct.ecdh_method */
            	5, 0,
            	497, 8,
            	5, 24,
            1, 8, 1, /* 497: pointer.func */
            	502, 0,
            0, 0, 0, /* 502: func */
            1, 8, 1, /* 505: pointer.struct.ecdsa_method */
            	510, 0,
            0, 48, 5, /* 510: struct.ecdsa_method */
            	5, 0,
            	523, 8,
            	531, 16,
            	539, 24,
            	5, 40,
            1, 8, 1, /* 523: pointer.func */
            	528, 0,
            0, 0, 0, /* 528: func */
            1, 8, 1, /* 531: pointer.func */
            	536, 0,
            0, 0, 0, /* 536: func */
            1, 8, 1, /* 539: pointer.func */
            	544, 0,
            0, 0, 0, /* 544: func */
            1, 8, 1, /* 547: pointer.struct.rand_meth_st */
            	552, 0,
            0, 48, 6, /* 552: struct.rand_meth_st */
            	567, 0,
            	575, 8,
            	583, 16,
            	591, 24,
            	575, 32,
            	599, 40,
            1, 8, 1, /* 567: pointer.func */
            	572, 0,
            0, 0, 0, /* 572: func */
            1, 8, 1, /* 575: pointer.func */
            	580, 0,
            0, 0, 0, /* 580: func */
            1, 8, 1, /* 583: pointer.func */
            	588, 0,
            0, 0, 0, /* 588: func */
            1, 8, 1, /* 591: pointer.func */
            	596, 0,
            0, 0, 0, /* 596: func */
            1, 8, 1, /* 599: pointer.func */
            	604, 0,
            0, 0, 0, /* 604: func */
            1, 8, 1, /* 607: pointer.struct.store_method_st */
            	612, 0,
            0, 0, 0, /* 612: struct.store_method_st */
            1, 8, 1, /* 615: pointer.func */
            	620, 0,
            0, 0, 0, /* 620: func */
            1, 8, 1, /* 623: pointer.func */
            	628, 0,
            0, 0, 0, /* 628: func */
            1, 8, 1, /* 631: pointer.func */
            	636, 0,
            0, 0, 0, /* 636: func */
            1, 8, 1, /* 639: pointer.func */
            	644, 0,
            0, 0, 0, /* 644: func */
            1, 8, 1, /* 647: pointer.func */
            	652, 0,
            0, 0, 0, /* 652: func */
            1, 8, 1, /* 655: pointer.func */
            	660, 0,
            0, 0, 0, /* 660: func */
            1, 8, 1, /* 663: pointer.func */
            	668, 0,
            0, 0, 0, /* 668: func */
            1, 8, 1, /* 671: pointer.func */
            	676, 0,
            0, 0, 0, /* 676: func */
            1, 8, 1, /* 679: pointer.struct.ENGINE_CMD_DEFN_st */
            	684, 0,
            0, 32, 2, /* 684: struct.ENGINE_CMD_DEFN_st */
            	5, 8,
            	5, 16,
            0, 16, 1, /* 691: struct.crypto_ex_data_st */
            	696, 0,
            1, 8, 1, /* 696: pointer.struct.stack_st_OPENSSL_STRING */
            	701, 0,
            0, 32, 1, /* 701: struct.stack_st_OPENSSL_STRING */
            	706, 0,
            0, 32, 2, /* 706: struct.stack_st */
            	713, 8,
            	718, 24,
            1, 8, 1, /* 713: pointer.pointer.char */
            	5, 0,
            1, 8, 1, /* 718: pointer.func */
            	723, 0,
            0, 0, 0, /* 723: func */
            0, 0, 0, /* 726: func */
            1, 8, 1, /* 729: pointer.func */
            	726, 0,
            1, 8, 1, /* 734: pointer.func */
            	739, 0,
            0, 0, 0, /* 739: func */
            0, 0, 0, /* 742: func */
            1, 8, 1, /* 745: pointer.func */
            	742, 0,
            0, 0, 0, /* 750: func */
            1, 8, 1, /* 753: pointer.func */
            	758, 0,
            0, 0, 0, /* 758: func */
            1, 8, 1, /* 761: pointer.func */
            	766, 0,
            0, 0, 0, /* 766: func */
            1, 8, 1, /* 769: pointer.func */
            	774, 0,
            0, 0, 0, /* 774: func */
            0, 0, 0, /* 777: func */
            1, 8, 1, /* 780: pointer.func */
            	785, 0,
            0, 0, 0, /* 785: func */
            1, 8, 1, /* 788: pointer.func */
            	777, 0,
            1, 8, 1, /* 793: pointer.func */
            	798, 0,
            0, 0, 0, /* 798: func */
            1, 8, 1, /* 801: pointer.func */
            	806, 0,
            0, 0, 0, /* 806: func */
            1, 8, 1, /* 809: pointer.struct.env_md_st */
            	814, 0,
            0, 120, 8, /* 814: struct.env_md_st */
            	833, 24,
            	841, 32,
            	801, 40,
            	849, 48,
            	833, 56,
            	857, 64,
            	865, 72,
            	873, 112,
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
            1, 8, 1, /* 873: pointer.func */
            	878, 0,
            0, 0, 0, /* 878: func */
            0, 48, 5, /* 881: struct.env_md_ctx_st */
            	809, 0,
            	195, 8,
            	5, 24,
            	894, 32,
            	841, 40,
            1, 8, 1, /* 894: pointer.struct.evp_pkey_ctx_st */
            	899, 0,
            0, 80, 8, /* 899: struct.evp_pkey_ctx_st */
            	918, 0,
            	195, 8,
            	989, 16,
            	989, 24,
            	5, 40,
            	5, 48,
            	161, 56,
            	994, 64,
            1, 8, 1, /* 918: pointer.struct.evp_pkey_method_st */
            	923, 0,
            0, 208, 25, /* 923: struct.evp_pkey_method_st */
            	161, 8,
            	976, 16,
            	788, 24,
            	161, 32,
            	769, 40,
            	161, 48,
            	769, 56,
            	161, 64,
            	761, 72,
            	161, 80,
            	753, 88,
            	161, 96,
            	761, 104,
            	984, 112,
            	745, 120,
            	984, 128,
            	793, 136,
            	161, 144,
            	761, 152,
            	161, 160,
            	761, 168,
            	161, 176,
            	780, 184,
            	734, 192,
            	729, 200,
            1, 8, 1, /* 976: pointer.func */
            	981, 0,
            0, 0, 0, /* 981: func */
            1, 8, 1, /* 984: pointer.func */
            	750, 0,
            1, 8, 1, /* 989: pointer.struct.evp_pkey_st */
            	184, 0,
            1, 8, 1, /* 994: pointer.int */
            	999, 0,
            0, 4, 0, /* 999: int */
            0, 288, 4, /* 1002: struct.hmac_ctx_st */
            	809, 0,
            	881, 8,
            	881, 56,
            	881, 104,
            1, 8, 1, /* 1013: pointer.struct.hmac_ctx_st */
            	1002, 0,
            0, 20, 0, /* 1018: array[5].int */
            0, 8, 0, /* 1021: long */
        },
        .arg_entity_index = { 1013, 5, 999, 809, 195, },
        .ret_entity_index = 999,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_arg(args_addr, arg_d);
    populate_arg(args_addr, arg_e);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    HMAC_CTX * new_arg_a = *((HMAC_CTX * *)new_args->args[0]);

    const void * new_arg_b = *((const void * *)new_args->args[1]);

    int new_arg_c = *((int *)new_args->args[2]);

    const EVP_MD * new_arg_d = *((const EVP_MD * *)new_args->args[3]);

    ENGINE * new_arg_e = *((ENGINE * *)new_args->args[4]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_HMAC_Init_ex)(HMAC_CTX *,const void *,int,const EVP_MD *,ENGINE *);
    orig_HMAC_Init_ex = dlsym(RTLD_NEXT, "HMAC_Init_ex");
    *new_ret_ptr = (*orig_HMAC_Init_ex)(new_arg_a,new_arg_b,new_arg_c,new_arg_d,new_arg_e);

    syscall(889);

    return ret;
}

