#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
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

BIO * bb_BIO_new_file(const char * arg_a,const char * arg_b);

BIO * BIO_new_file(const char * arg_a,const char * arg_b) 
{
    unsigned long in_lib = syscall(890);
    printf("BIO_new_file called %lu\n", in_lib);
    if (!in_lib)
        return bb_BIO_new_file(arg_a,arg_b);
    else {
        BIO * (*orig_BIO_new_file)(const char *,const char *);
        orig_BIO_new_file = dlsym(RTLD_NEXT, "BIO_new_file");
        return orig_BIO_new_file(arg_a,arg_b);
    }
}

BIO * bb_BIO_new_file(const char * arg_a,const char * arg_b) 
{
    BIO * ret;

    struct lib_enter_args *args_addr = malloc(sizeof(struct lib_enter_args));
    memset(args_addr, 0, sizeof(struct lib_enter_args));
    args_addr->num_args = 0;
    uint32_t *em = args_addr->entity_metadata;
    em[0] = 8884097; em[1] = 8; em[2] = 0; /* 0: pointer.func */
    em[3] = 8884099; em[4] = 8; em[5] = 2; /* 3: pointer_to_array_of_pointers_to_stack */
    	em[6] = 10; em[7] = 0; 
    	em[8] = 13; em[9] = 20; 
    em[10] = 0; em[11] = 8; em[12] = 0; /* 10: pointer.void */
    em[13] = 0; em[14] = 4; em[15] = 0; /* 13: int */
    em[16] = 0; em[17] = 32; em[18] = 2; /* 16: struct.crypto_ex_data_st_fake */
    	em[19] = 3; em[20] = 8; 
    	em[21] = 0; em[22] = 24; 
    em[23] = 1; em[24] = 8; em[25] = 1; /* 23: pointer.struct.bio_st */
    	em[26] = 28; em[27] = 0; 
    em[28] = 0; em[29] = 112; em[30] = 7; /* 28: struct.bio_st */
    	em[31] = 45; em[32] = 0; 
    	em[33] = 94; em[34] = 8; 
    	em[35] = 97; em[36] = 16; 
    	em[37] = 10; em[38] = 48; 
    	em[39] = 23; em[40] = 56; 
    	em[41] = 23; em[42] = 64; 
    	em[43] = 16; em[44] = 96; 
    em[45] = 1; em[46] = 8; em[47] = 1; /* 45: pointer.struct.bio_method_st */
    	em[48] = 50; em[49] = 0; 
    em[50] = 0; em[51] = 80; em[52] = 9; /* 50: struct.bio_method_st */
    	em[53] = 71; em[54] = 8; 
    	em[55] = 76; em[56] = 16; 
    	em[57] = 79; em[58] = 24; 
    	em[59] = 82; em[60] = 32; 
    	em[61] = 79; em[62] = 40; 
    	em[63] = 85; em[64] = 48; 
    	em[65] = 88; em[66] = 56; 
    	em[67] = 88; em[68] = 64; 
    	em[69] = 91; em[70] = 72; 
    em[71] = 1; em[72] = 8; em[73] = 1; /* 71: pointer.char */
    	em[74] = 8884096; em[75] = 0; 
    em[76] = 8884097; em[77] = 8; em[78] = 0; /* 76: pointer.func */
    em[79] = 8884097; em[80] = 8; em[81] = 0; /* 79: pointer.func */
    em[82] = 8884097; em[83] = 8; em[84] = 0; /* 82: pointer.func */
    em[85] = 8884097; em[86] = 8; em[87] = 0; /* 85: pointer.func */
    em[88] = 8884097; em[89] = 8; em[90] = 0; /* 88: pointer.func */
    em[91] = 8884097; em[92] = 8; em[93] = 0; /* 91: pointer.func */
    em[94] = 8884097; em[95] = 8; em[96] = 0; /* 94: pointer.func */
    em[97] = 1; em[98] = 8; em[99] = 1; /* 97: pointer.char */
    	em[100] = 8884096; em[101] = 0; 
    em[102] = 1; em[103] = 8; em[104] = 1; /* 102: pointer.struct.bio_st */
    	em[105] = 28; em[106] = 0; 
    em[107] = 0; em[108] = 1; em[109] = 0; /* 107: char */
    args_addr->arg_entity_index[0] = 71;
    args_addr->arg_entity_index[1] = 71;
    args_addr->ret_entity_index = 102;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    const char * new_arg_a = *((const char * *)new_args->args[0]);

    const char * new_arg_b = *((const char * *)new_args->args[1]);

    BIO * *new_ret_ptr = (BIO * *)new_args->ret;

    BIO * (*orig_BIO_new_file)(const char *,const char *);
    orig_BIO_new_file = dlsym(RTLD_NEXT, "BIO_new_file");
    *new_ret_ptr = (*orig_BIO_new_file)(new_arg_a,new_arg_b);

    syscall(889);

    free(args_addr);

    return ret;
}

