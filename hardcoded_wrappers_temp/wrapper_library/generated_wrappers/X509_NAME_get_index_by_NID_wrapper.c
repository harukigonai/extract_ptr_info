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

int bb_X509_NAME_get_index_by_NID(X509_NAME * arg_a,int arg_b,int arg_c);

int X509_NAME_get_index_by_NID(X509_NAME * arg_a,int arg_b,int arg_c) 
{
    unsigned long in_lib = syscall(890);
    printf("X509_NAME_get_index_by_NID called %lu\n", in_lib);
    if (!in_lib)
        return bb_X509_NAME_get_index_by_NID(arg_a,arg_b,arg_c);
    else {
        int (*orig_X509_NAME_get_index_by_NID)(X509_NAME *,int,int);
        orig_X509_NAME_get_index_by_NID = dlsym(RTLD_NEXT, "X509_NAME_get_index_by_NID");
        return orig_X509_NAME_get_index_by_NID(arg_a,arg_b,arg_c);
    }
}

int bb_X509_NAME_get_index_by_NID(X509_NAME * arg_a,int arg_b,int arg_c) 
{
    int ret;

    struct lib_enter_args *args_addr = malloc(sizeof(struct lib_enter_args));
    memset(args_addr, 0, sizeof(struct lib_enter_args));
    args_addr->num_args = 0;
    uint32_t *em = args_addr->entity_metadata;
    em[0] = 0; em[1] = 24; em[2] = 1; /* 0: struct.buf_mem_st */
    	em[3] = 5; em[4] = 8; 
    em[5] = 1; em[6] = 8; em[7] = 1; /* 5: pointer.char */
    	em[8] = 8884096; em[9] = 0; 
    em[10] = 1; em[11] = 8; em[12] = 1; /* 10: pointer.struct.buf_mem_st */
    	em[13] = 0; em[14] = 0; 
    em[15] = 0; em[16] = 1; em[17] = 0; /* 15: unsigned char */
    em[18] = 1; em[19] = 8; em[20] = 1; /* 18: pointer.struct.asn1_string_st */
    	em[21] = 23; em[22] = 0; 
    em[23] = 0; em[24] = 24; em[25] = 1; /* 23: struct.asn1_string_st */
    	em[26] = 28; em[27] = 8; 
    em[28] = 1; em[29] = 8; em[30] = 1; /* 28: pointer.unsigned char */
    	em[31] = 15; em[32] = 0; 
    em[33] = 1; em[34] = 8; em[35] = 1; /* 33: pointer.unsigned char */
    	em[36] = 15; em[37] = 0; 
    em[38] = 8884099; em[39] = 8; em[40] = 2; /* 38: pointer_to_array_of_pointers_to_stack */
    	em[41] = 45; em[42] = 0; 
    	em[43] = 81; em[44] = 20; 
    em[45] = 0; em[46] = 8; em[47] = 1; /* 45: pointer.X509_NAME_ENTRY */
    	em[48] = 50; em[49] = 0; 
    em[50] = 0; em[51] = 0; em[52] = 1; /* 50: X509_NAME_ENTRY */
    	em[53] = 55; em[54] = 0; 
    em[55] = 0; em[56] = 24; em[57] = 2; /* 55: struct.X509_name_entry_st */
    	em[58] = 62; em[59] = 0; 
    	em[60] = 18; em[61] = 8; 
    em[62] = 1; em[63] = 8; em[64] = 1; /* 62: pointer.struct.asn1_object_st */
    	em[65] = 67; em[66] = 0; 
    em[67] = 0; em[68] = 40; em[69] = 3; /* 67: struct.asn1_object_st */
    	em[70] = 76; em[71] = 0; 
    	em[72] = 76; em[73] = 8; 
    	em[74] = 33; em[75] = 24; 
    em[76] = 1; em[77] = 8; em[78] = 1; /* 76: pointer.char */
    	em[79] = 8884096; em[80] = 0; 
    em[81] = 0; em[82] = 4; em[83] = 0; /* 81: int */
    em[84] = 0; em[85] = 1; em[86] = 0; /* 84: char */
    em[87] = 8884097; em[88] = 8; em[89] = 0; /* 87: pointer.func */
    em[90] = 1; em[91] = 8; em[92] = 1; /* 90: pointer.struct.X509_name_st */
    	em[93] = 95; em[94] = 0; 
    em[95] = 0; em[96] = 40; em[97] = 3; /* 95: struct.X509_name_st */
    	em[98] = 104; em[99] = 0; 
    	em[100] = 10; em[101] = 16; 
    	em[102] = 28; em[103] = 24; 
    em[104] = 1; em[105] = 8; em[106] = 1; /* 104: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[107] = 109; em[108] = 0; 
    em[109] = 0; em[110] = 32; em[111] = 2; /* 109: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[112] = 38; em[113] = 8; 
    	em[114] = 87; em[115] = 24; 
    args_addr->arg_entity_index[0] = 90;
    args_addr->arg_entity_index[1] = 81;
    args_addr->arg_entity_index[2] = 81;
    args_addr->ret_entity_index = 81;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    X509_NAME * new_arg_a = *((X509_NAME * *)new_args->args[0]);

    int new_arg_b = *((int *)new_args->args[1]);

    int new_arg_c = *((int *)new_args->args[2]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_X509_NAME_get_index_by_NID)(X509_NAME *,int,int);
    orig_X509_NAME_get_index_by_NID = dlsym(RTLD_NEXT, "X509_NAME_get_index_by_NID");
    *new_ret_ptr = (*orig_X509_NAME_get_index_by_NID)(new_arg_a,new_arg_b,new_arg_c);

    syscall(889);

    free(args_addr);

    return ret;
}

