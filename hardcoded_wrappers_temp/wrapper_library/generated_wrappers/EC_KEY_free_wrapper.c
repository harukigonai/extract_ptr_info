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

void bb_EC_KEY_free(EC_KEY * arg_a);

void EC_KEY_free(EC_KEY * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("EC_KEY_free called %lu\n", in_lib);
    if (!in_lib)
        bb_EC_KEY_free(arg_a);
    else {
        void (*orig_EC_KEY_free)(EC_KEY *);
        orig_EC_KEY_free = dlsym(RTLD_NEXT, "EC_KEY_free");
        orig_EC_KEY_free(arg_a);
    }
}

void bb_EC_KEY_free(EC_KEY * arg_a) 
{
    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 40, 5, /* 0: struct.ec_extra_data_st */
            	13, 0,
            	18, 8,
            	21, 16,
            	24, 24,
            	24, 32,
            1, 8, 1, /* 13: pointer.struct.ec_extra_data_st */
            	0, 0,
            0, 8, 0, /* 18: pointer.void */
            8884097, 8, 0, /* 21: pointer.func */
            8884097, 8, 0, /* 24: pointer.func */
            1, 8, 1, /* 27: pointer.struct.ec_extra_data_st */
            	0, 0,
            0, 24, 1, /* 32: struct.bignum_st */
            	37, 0,
            1, 8, 1, /* 37: pointer.unsigned int */
            	42, 0,
            0, 4, 0, /* 42: unsigned int */
            1, 8, 1, /* 45: pointer.struct.bignum_st */
            	32, 0,
            1, 8, 1, /* 50: pointer.struct.ec_extra_data_st */
            	55, 0,
            0, 40, 5, /* 55: struct.ec_extra_data_st */
            	50, 0,
            	18, 8,
            	21, 16,
            	24, 24,
            	24, 32,
            1, 8, 1, /* 68: pointer.unsigned char */
            	73, 0,
            0, 1, 0, /* 73: unsigned char */
            0, 24, 1, /* 76: struct.bignum_st */
            	37, 0,
            8884097, 8, 0, /* 81: pointer.func */
            8884097, 8, 0, /* 84: pointer.func */
            8884097, 8, 0, /* 87: pointer.func */
            8884097, 8, 0, /* 90: pointer.func */
            8884097, 8, 0, /* 93: pointer.func */
            8884097, 8, 0, /* 96: pointer.func */
            0, 304, 37, /* 99: struct.ec_method_st */
            	176, 8,
            	179, 16,
            	179, 24,
            	182, 32,
            	185, 40,
            	188, 48,
            	191, 56,
            	194, 64,
            	197, 72,
            	200, 80,
            	200, 88,
            	203, 96,
            	206, 104,
            	209, 112,
            	212, 120,
            	215, 128,
            	218, 136,
            	221, 144,
            	224, 152,
            	227, 160,
            	230, 168,
            	233, 176,
            	236, 184,
            	96, 192,
            	239, 200,
            	242, 208,
            	236, 216,
            	245, 224,
            	248, 232,
            	251, 240,
            	191, 248,
            	254, 256,
            	257, 264,
            	254, 272,
            	257, 280,
            	257, 288,
            	260, 296,
            8884097, 8, 0, /* 176: pointer.func */
            8884097, 8, 0, /* 179: pointer.func */
            8884097, 8, 0, /* 182: pointer.func */
            8884097, 8, 0, /* 185: pointer.func */
            8884097, 8, 0, /* 188: pointer.func */
            8884097, 8, 0, /* 191: pointer.func */
            8884097, 8, 0, /* 194: pointer.func */
            8884097, 8, 0, /* 197: pointer.func */
            8884097, 8, 0, /* 200: pointer.func */
            8884097, 8, 0, /* 203: pointer.func */
            8884097, 8, 0, /* 206: pointer.func */
            8884097, 8, 0, /* 209: pointer.func */
            8884097, 8, 0, /* 212: pointer.func */
            8884097, 8, 0, /* 215: pointer.func */
            8884097, 8, 0, /* 218: pointer.func */
            8884097, 8, 0, /* 221: pointer.func */
            8884097, 8, 0, /* 224: pointer.func */
            8884097, 8, 0, /* 227: pointer.func */
            8884097, 8, 0, /* 230: pointer.func */
            8884097, 8, 0, /* 233: pointer.func */
            8884097, 8, 0, /* 236: pointer.func */
            8884097, 8, 0, /* 239: pointer.func */
            8884097, 8, 0, /* 242: pointer.func */
            8884097, 8, 0, /* 245: pointer.func */
            8884097, 8, 0, /* 248: pointer.func */
            8884097, 8, 0, /* 251: pointer.func */
            8884097, 8, 0, /* 254: pointer.func */
            8884097, 8, 0, /* 257: pointer.func */
            8884097, 8, 0, /* 260: pointer.func */
            8884097, 8, 0, /* 263: pointer.func */
            1, 8, 1, /* 266: pointer.struct.ec_method_st */
            	99, 0,
            8884097, 8, 0, /* 271: pointer.func */
            8884097, 8, 0, /* 274: pointer.func */
            1, 8, 1, /* 277: pointer.struct.ec_extra_data_st */
            	55, 0,
            8884097, 8, 0, /* 282: pointer.func */
            8884097, 8, 0, /* 285: pointer.func */
            8884097, 8, 0, /* 288: pointer.func */
            1, 8, 1, /* 291: pointer.struct.ec_group_st */
            	296, 0,
            0, 232, 12, /* 296: struct.ec_group_st */
            	266, 0,
            	323, 8,
            	76, 16,
            	76, 40,
            	68, 80,
            	277, 96,
            	76, 104,
            	76, 152,
            	76, 176,
            	18, 208,
            	18, 216,
            	288, 224,
            1, 8, 1, /* 323: pointer.struct.ec_point_st */
            	328, 0,
            0, 88, 4, /* 328: struct.ec_point_st */
            	339, 0,
            	481, 8,
            	481, 32,
            	481, 56,
            1, 8, 1, /* 339: pointer.struct.ec_method_st */
            	344, 0,
            0, 304, 37, /* 344: struct.ec_method_st */
            	421, 8,
            	424, 16,
            	424, 24,
            	427, 32,
            	430, 40,
            	433, 48,
            	436, 56,
            	439, 64,
            	442, 72,
            	445, 80,
            	445, 88,
            	448, 96,
            	451, 104,
            	454, 112,
            	457, 120,
            	271, 128,
            	460, 136,
            	463, 144,
            	282, 152,
            	466, 160,
            	469, 168,
            	472, 176,
            	475, 184,
            	285, 192,
            	93, 200,
            	274, 208,
            	475, 216,
            	90, 224,
            	87, 232,
            	263, 240,
            	436, 248,
            	84, 256,
            	478, 264,
            	84, 272,
            	478, 280,
            	478, 288,
            	81, 296,
            8884097, 8, 0, /* 421: pointer.func */
            8884097, 8, 0, /* 424: pointer.func */
            8884097, 8, 0, /* 427: pointer.func */
            8884097, 8, 0, /* 430: pointer.func */
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
            8884097, 8, 0, /* 469: pointer.func */
            8884097, 8, 0, /* 472: pointer.func */
            8884097, 8, 0, /* 475: pointer.func */
            8884097, 8, 0, /* 478: pointer.func */
            0, 24, 1, /* 481: struct.bignum_st */
            	37, 0,
            1, 8, 1, /* 486: pointer.struct.ec_key_st */
            	491, 0,
            0, 56, 4, /* 491: struct.ec_key_st */
            	291, 8,
            	502, 16,
            	45, 24,
            	27, 48,
            1, 8, 1, /* 502: pointer.struct.ec_point_st */
            	328, 0,
        },
        .arg_entity_index = { 486, },
        .ret_entity_index = -1,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    EC_KEY * new_arg_a = *((EC_KEY * *)new_args->args[0]);

    void (*orig_EC_KEY_free)(EC_KEY *);
    orig_EC_KEY_free = dlsym(RTLD_NEXT, "EC_KEY_free");
    (*orig_EC_KEY_free)(new_arg_a);

    syscall(889);

}

