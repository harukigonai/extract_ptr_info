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

void bb_EC_GROUP_free(EC_GROUP * arg_a);

void EC_GROUP_free(EC_GROUP * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("EC_GROUP_free called %lu\n", in_lib);
    if (!in_lib)
        bb_EC_GROUP_free(arg_a);
    else {
        void (*orig_EC_GROUP_free)(EC_GROUP *);
        orig_EC_GROUP_free = dlsym(RTLD_NEXT, "EC_GROUP_free");
        orig_EC_GROUP_free(arg_a);
    }
}

void bb_EC_GROUP_free(EC_GROUP * arg_a) 
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
            0, 4, 0, /* 35: int */
            0, 4, 0, /* 38: unsigned int */
            8884099, 8, 2, /* 41: pointer_to_array_of_pointers_to_stack */
            	38, 0,
            	35, 12,
            0, 24, 1, /* 48: struct.bignum_st */
            	53, 0,
            8884099, 8, 2, /* 53: pointer_to_array_of_pointers_to_stack */
            	38, 0,
            	35, 12,
            8884097, 8, 0, /* 60: pointer.func */
            8884097, 8, 0, /* 63: pointer.func */
            8884097, 8, 0, /* 66: pointer.func */
            8884097, 8, 0, /* 69: pointer.func */
            8884097, 8, 0, /* 72: pointer.func */
            8884097, 8, 0, /* 75: pointer.func */
            8884097, 8, 0, /* 78: pointer.func */
            8884097, 8, 0, /* 81: pointer.func */
            8884097, 8, 0, /* 84: pointer.func */
            8884097, 8, 0, /* 87: pointer.func */
            0, 232, 12, /* 90: struct.ec_group_st */
            	117, 0,
            	277, 8,
            	447, 16,
            	447, 40,
            	452, 80,
            	30, 96,
            	447, 104,
            	447, 152,
            	447, 176,
            	24, 208,
            	24, 216,
            	0, 224,
            1, 8, 1, /* 117: pointer.struct.ec_method_st */
            	122, 0,
            0, 304, 37, /* 122: struct.ec_method_st */
            	199, 8,
            	202, 16,
            	202, 24,
            	205, 32,
            	208, 40,
            	211, 48,
            	214, 56,
            	217, 64,
            	220, 72,
            	223, 80,
            	223, 88,
            	226, 96,
            	229, 104,
            	232, 112,
            	235, 120,
            	238, 128,
            	241, 136,
            	244, 144,
            	247, 152,
            	250, 160,
            	87, 168,
            	81, 176,
            	253, 184,
            	78, 192,
            	256, 200,
            	259, 208,
            	253, 216,
            	75, 224,
            	262, 232,
            	265, 240,
            	214, 248,
            	268, 256,
            	271, 264,
            	268, 272,
            	271, 280,
            	271, 288,
            	274, 296,
            8884097, 8, 0, /* 199: pointer.func */
            8884097, 8, 0, /* 202: pointer.func */
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
            1, 8, 1, /* 277: pointer.struct.ec_point_st */
            	282, 0,
            0, 88, 4, /* 282: struct.ec_point_st */
            	293, 0,
            	48, 8,
            	48, 32,
            	48, 56,
            1, 8, 1, /* 293: pointer.struct.ec_method_st */
            	298, 0,
            0, 304, 37, /* 298: struct.ec_method_st */
            	375, 8,
            	378, 16,
            	378, 24,
            	381, 32,
            	384, 40,
            	387, 48,
            	390, 56,
            	393, 64,
            	396, 72,
            	399, 80,
            	399, 88,
            	402, 96,
            	405, 104,
            	408, 112,
            	411, 120,
            	414, 128,
            	417, 136,
            	84, 144,
            	420, 152,
            	423, 160,
            	426, 168,
            	429, 176,
            	432, 184,
            	72, 192,
            	69, 200,
            	435, 208,
            	432, 216,
            	438, 224,
            	66, 232,
            	441, 240,
            	390, 248,
            	63, 256,
            	444, 264,
            	63, 272,
            	444, 280,
            	444, 288,
            	60, 296,
            8884097, 8, 0, /* 375: pointer.func */
            8884097, 8, 0, /* 378: pointer.func */
            8884097, 8, 0, /* 381: pointer.func */
            8884097, 8, 0, /* 384: pointer.func */
            8884097, 8, 0, /* 387: pointer.func */
            8884097, 8, 0, /* 390: pointer.func */
            8884097, 8, 0, /* 393: pointer.func */
            8884097, 8, 0, /* 396: pointer.func */
            8884097, 8, 0, /* 399: pointer.func */
            8884097, 8, 0, /* 402: pointer.func */
            8884097, 8, 0, /* 405: pointer.func */
            8884097, 8, 0, /* 408: pointer.func */
            8884097, 8, 0, /* 411: pointer.func */
            8884097, 8, 0, /* 414: pointer.func */
            8884097, 8, 0, /* 417: pointer.func */
            8884097, 8, 0, /* 420: pointer.func */
            8884097, 8, 0, /* 423: pointer.func */
            8884097, 8, 0, /* 426: pointer.func */
            8884097, 8, 0, /* 429: pointer.func */
            8884097, 8, 0, /* 432: pointer.func */
            8884097, 8, 0, /* 435: pointer.func */
            8884097, 8, 0, /* 438: pointer.func */
            8884097, 8, 0, /* 441: pointer.func */
            8884097, 8, 0, /* 444: pointer.func */
            0, 24, 1, /* 447: struct.bignum_st */
            	41, 0,
            1, 8, 1, /* 452: pointer.unsigned char */
            	457, 0,
            0, 1, 0, /* 457: unsigned char */
            1, 8, 1, /* 460: pointer.struct.ec_group_st */
            	90, 0,
        },
        .arg_entity_index = { 460, },
        .ret_entity_index = -1,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    EC_GROUP * new_arg_a = *((EC_GROUP * *)new_args->args[0]);

    void (*orig_EC_GROUP_free)(EC_GROUP *);
    orig_EC_GROUP_free = dlsym(RTLD_NEXT, "EC_GROUP_free");
    (*orig_EC_GROUP_free)(new_arg_a);

    syscall(889);

}

