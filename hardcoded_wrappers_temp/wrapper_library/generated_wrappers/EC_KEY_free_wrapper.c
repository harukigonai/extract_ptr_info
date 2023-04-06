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
            8884097, 8, 0, /* 0: pointer.func */
            8884097, 8, 0, /* 3: pointer.func */
            0, 40, 5, /* 6: struct.ec_extra_data_st */
            	19, 0,
            	24, 8,
            	3, 16,
            	27, 24,
            	27, 32,
            1, 8, 1, /* 19: pointer.struct.ec_extra_data_st */
            	6, 0,
            0, 8, 0, /* 24: pointer.void */
            8884097, 8, 0, /* 27: pointer.func */
            1, 8, 1, /* 30: pointer.struct.ec_extra_data_st */
            	6, 0,
            0, 40, 5, /* 35: struct.ec_extra_data_st */
            	48, 0,
            	24, 8,
            	3, 16,
            	27, 24,
            	27, 32,
            1, 8, 1, /* 48: pointer.struct.ec_extra_data_st */
            	35, 0,
            0, 4, 0, /* 53: int */
            0, 4, 0, /* 56: unsigned int */
            8884099, 8, 2, /* 59: pointer_to_array_of_pointers_to_stack */
            	56, 0,
            	53, 12,
            0, 24, 1, /* 66: struct.bignum_st */
            	71, 0,
            8884099, 8, 2, /* 71: pointer_to_array_of_pointers_to_stack */
            	56, 0,
            	53, 12,
            8884097, 8, 0, /* 78: pointer.func */
            8884097, 8, 0, /* 81: pointer.func */
            8884097, 8, 0, /* 84: pointer.func */
            8884097, 8, 0, /* 87: pointer.func */
            8884097, 8, 0, /* 90: pointer.func */
            8884097, 8, 0, /* 93: pointer.func */
            8884097, 8, 0, /* 96: pointer.func */
            1, 8, 1, /* 99: pointer.struct.ec_extra_data_st */
            	35, 0,
            8884097, 8, 0, /* 104: pointer.func */
            1, 8, 1, /* 107: pointer.struct.ec_point_st */
            	112, 0,
            0, 88, 4, /* 112: struct.ec_point_st */
            	123, 0,
            	66, 8,
            	66, 32,
            	66, 56,
            1, 8, 1, /* 123: pointer.struct.ec_method_st */
            	128, 0,
            0, 304, 37, /* 128: struct.ec_method_st */
            	205, 8,
            	208, 16,
            	208, 24,
            	211, 32,
            	214, 40,
            	217, 48,
            	220, 56,
            	223, 64,
            	226, 72,
            	229, 80,
            	229, 88,
            	232, 96,
            	235, 104,
            	238, 112,
            	241, 120,
            	244, 128,
            	247, 136,
            	250, 144,
            	253, 152,
            	256, 160,
            	259, 168,
            	104, 176,
            	96, 184,
            	90, 192,
            	87, 200,
            	262, 208,
            	96, 216,
            	265, 224,
            	84, 232,
            	268, 240,
            	220, 248,
            	81, 256,
            	93, 264,
            	81, 272,
            	93, 280,
            	93, 288,
            	78, 296,
            8884097, 8, 0, /* 205: pointer.func */
            8884097, 8, 0, /* 208: pointer.func */
            8884097, 8, 0, /* 211: pointer.func */
            8884097, 8, 0, /* 214: pointer.func */
            8884097, 8, 0, /* 217: pointer.func */
            8884097, 8, 0, /* 220: pointer.func */
            8884097, 8, 0, /* 223: pointer.func */
            8884097, 8, 0, /* 226: pointer.func */
            8884097, 8, 0, /* 229: pointer.func */
            8884097, 8, 0, /* 232: pointer.func */
            8884097, 8, 0, /* 235: pointer.func */
            8884097, 8, 0, /* 238: pointer.func */
            8884097, 8, 0, /* 241: pointer.func */
            8884097, 8, 0, /* 244: pointer.func */
            8884097, 8, 0, /* 247: pointer.func */
            8884097, 8, 0, /* 250: pointer.func */
            8884097, 8, 0, /* 253: pointer.func */
            8884097, 8, 0, /* 256: pointer.func */
            8884097, 8, 0, /* 259: pointer.func */
            8884097, 8, 0, /* 262: pointer.func */
            8884097, 8, 0, /* 265: pointer.func */
            8884097, 8, 0, /* 268: pointer.func */
            8884097, 8, 0, /* 271: pointer.func */
            8884097, 8, 0, /* 274: pointer.func */
            0, 232, 12, /* 277: struct.ec_group_st */
            	304, 0,
            	470, 8,
            	475, 16,
            	475, 40,
            	487, 80,
            	30, 96,
            	475, 104,
            	475, 152,
            	475, 176,
            	24, 208,
            	24, 216,
            	0, 224,
            1, 8, 1, /* 304: pointer.struct.ec_method_st */
            	309, 0,
            0, 304, 37, /* 309: struct.ec_method_st */
            	386, 8,
            	389, 16,
            	389, 24,
            	392, 32,
            	395, 40,
            	398, 48,
            	401, 56,
            	404, 64,
            	407, 72,
            	410, 80,
            	410, 88,
            	413, 96,
            	416, 104,
            	419, 112,
            	422, 120,
            	425, 128,
            	428, 136,
            	431, 144,
            	434, 152,
            	437, 160,
            	274, 168,
            	440, 176,
            	443, 184,
            	271, 192,
            	446, 200,
            	449, 208,
            	443, 216,
            	452, 224,
            	455, 232,
            	458, 240,
            	401, 248,
            	461, 256,
            	464, 264,
            	461, 272,
            	464, 280,
            	464, 288,
            	467, 296,
            8884097, 8, 0, /* 386: pointer.func */
            8884097, 8, 0, /* 389: pointer.func */
            8884097, 8, 0, /* 392: pointer.func */
            8884097, 8, 0, /* 395: pointer.func */
            8884097, 8, 0, /* 398: pointer.func */
            8884097, 8, 0, /* 401: pointer.func */
            8884097, 8, 0, /* 404: pointer.func */
            8884097, 8, 0, /* 407: pointer.func */
            8884097, 8, 0, /* 410: pointer.func */
            8884097, 8, 0, /* 413: pointer.func */
            8884097, 8, 0, /* 416: pointer.func */
            8884097, 8, 0, /* 419: pointer.func */
            8884097, 8, 0, /* 422: pointer.func */
            8884097, 8, 0, /* 425: pointer.func */
            8884097, 8, 0, /* 428: pointer.func */
            8884097, 8, 0, /* 431: pointer.func */
            8884097, 8, 0, /* 434: pointer.func */
            8884097, 8, 0, /* 437: pointer.func */
            8884097, 8, 0, /* 440: pointer.func */
            8884097, 8, 0, /* 443: pointer.func */
            8884097, 8, 0, /* 446: pointer.func */
            8884097, 8, 0, /* 449: pointer.func */
            8884097, 8, 0, /* 452: pointer.func */
            8884097, 8, 0, /* 455: pointer.func */
            8884097, 8, 0, /* 458: pointer.func */
            8884097, 8, 0, /* 461: pointer.func */
            8884097, 8, 0, /* 464: pointer.func */
            8884097, 8, 0, /* 467: pointer.func */
            1, 8, 1, /* 470: pointer.struct.ec_point_st */
            	112, 0,
            0, 24, 1, /* 475: struct.bignum_st */
            	480, 0,
            8884099, 8, 2, /* 480: pointer_to_array_of_pointers_to_stack */
            	56, 0,
            	53, 12,
            1, 8, 1, /* 487: pointer.unsigned char */
            	492, 0,
            0, 1, 0, /* 492: unsigned char */
            0, 56, 4, /* 495: struct.ec_key_st */
            	506, 8,
            	107, 16,
            	511, 24,
            	99, 48,
            1, 8, 1, /* 506: pointer.struct.ec_group_st */
            	277, 0,
            1, 8, 1, /* 511: pointer.struct.bignum_st */
            	516, 0,
            0, 24, 1, /* 516: struct.bignum_st */
            	59, 0,
            1, 8, 1, /* 521: pointer.struct.ec_key_st */
            	495, 0,
        },
        .arg_entity_index = { 521, },
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

