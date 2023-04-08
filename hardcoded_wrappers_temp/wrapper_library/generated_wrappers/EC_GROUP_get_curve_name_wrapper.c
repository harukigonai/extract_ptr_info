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

int bb_EC_GROUP_get_curve_name(const EC_GROUP * arg_a);

int EC_GROUP_get_curve_name(const EC_GROUP * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("EC_GROUP_get_curve_name called %lu\n", in_lib);
    if (!in_lib)
        return bb_EC_GROUP_get_curve_name(arg_a);
    else {
        int (*orig_EC_GROUP_get_curve_name)(const EC_GROUP *);
        orig_EC_GROUP_get_curve_name = dlsym(RTLD_NEXT, "EC_GROUP_get_curve_name");
        return orig_EC_GROUP_get_curve_name(arg_a);
    }
}

int bb_EC_GROUP_get_curve_name(const EC_GROUP * arg_a) 
{
    int ret;

    struct lib_enter_args *args_addr = malloc(sizeof(struct lib_enter_args));
    memset(args_addr, 0, sizeof(struct lib_enter_args));
    args_addr->num_args = 0;
    uint32_t *em = args_addr->entity_metadata;
    em[0] = 0; em[1] = 40; em[2] = 5; /* 0: struct.ec_extra_data_st */
    	em[3] = 13; em[4] = 0; 
    	em[5] = 18; em[6] = 8; 
    	em[7] = 21; em[8] = 16; 
    	em[9] = 24; em[10] = 24; 
    	em[11] = 24; em[12] = 32; 
    em[13] = 1; em[14] = 8; em[15] = 1; /* 13: pointer.struct.ec_extra_data_st */
    	em[16] = 0; em[17] = 0; 
    em[18] = 0; em[19] = 8; em[20] = 0; /* 18: pointer.void */
    em[21] = 8884097; em[22] = 8; em[23] = 0; /* 21: pointer.func */
    em[24] = 8884097; em[25] = 8; em[26] = 0; /* 24: pointer.func */
    em[27] = 1; em[28] = 8; em[29] = 1; /* 27: pointer.struct.ec_extra_data_st */
    	em[30] = 0; em[31] = 0; 
    em[32] = 1; em[33] = 8; em[34] = 1; /* 32: pointer.unsigned char */
    	em[35] = 37; em[36] = 0; 
    em[37] = 0; em[38] = 1; em[39] = 0; /* 37: unsigned char */
    em[40] = 0; em[41] = 8; em[42] = 0; /* 40: long unsigned int */
    em[43] = 8884099; em[44] = 8; em[45] = 2; /* 43: pointer_to_array_of_pointers_to_stack */
    	em[46] = 40; em[47] = 0; 
    	em[48] = 50; em[49] = 12; 
    em[50] = 0; em[51] = 4; em[52] = 0; /* 50: int */
    em[53] = 0; em[54] = 88; em[55] = 4; /* 53: struct.ec_point_st */
    	em[56] = 64; em[57] = 0; 
    	em[58] = 236; em[59] = 8; 
    	em[60] = 236; em[61] = 32; 
    	em[62] = 236; em[63] = 56; 
    em[64] = 1; em[65] = 8; em[66] = 1; /* 64: pointer.struct.ec_method_st */
    	em[67] = 69; em[68] = 0; 
    em[69] = 0; em[70] = 304; em[71] = 37; /* 69: struct.ec_method_st */
    	em[72] = 146; em[73] = 8; 
    	em[74] = 149; em[75] = 16; 
    	em[76] = 149; em[77] = 24; 
    	em[78] = 152; em[79] = 32; 
    	em[80] = 155; em[81] = 40; 
    	em[82] = 158; em[83] = 48; 
    	em[84] = 161; em[85] = 56; 
    	em[86] = 164; em[87] = 64; 
    	em[88] = 167; em[89] = 72; 
    	em[90] = 170; em[91] = 80; 
    	em[92] = 170; em[93] = 88; 
    	em[94] = 173; em[95] = 96; 
    	em[96] = 176; em[97] = 104; 
    	em[98] = 179; em[99] = 112; 
    	em[100] = 182; em[101] = 120; 
    	em[102] = 185; em[103] = 128; 
    	em[104] = 188; em[105] = 136; 
    	em[106] = 191; em[107] = 144; 
    	em[108] = 194; em[109] = 152; 
    	em[110] = 197; em[111] = 160; 
    	em[112] = 200; em[113] = 168; 
    	em[114] = 203; em[115] = 176; 
    	em[116] = 206; em[117] = 184; 
    	em[118] = 209; em[119] = 192; 
    	em[120] = 212; em[121] = 200; 
    	em[122] = 215; em[123] = 208; 
    	em[124] = 206; em[125] = 216; 
    	em[126] = 218; em[127] = 224; 
    	em[128] = 221; em[129] = 232; 
    	em[130] = 224; em[131] = 240; 
    	em[132] = 161; em[133] = 248; 
    	em[134] = 227; em[135] = 256; 
    	em[136] = 230; em[137] = 264; 
    	em[138] = 227; em[139] = 272; 
    	em[140] = 230; em[141] = 280; 
    	em[142] = 230; em[143] = 288; 
    	em[144] = 233; em[145] = 296; 
    em[146] = 8884097; em[147] = 8; em[148] = 0; /* 146: pointer.func */
    em[149] = 8884097; em[150] = 8; em[151] = 0; /* 149: pointer.func */
    em[152] = 8884097; em[153] = 8; em[154] = 0; /* 152: pointer.func */
    em[155] = 8884097; em[156] = 8; em[157] = 0; /* 155: pointer.func */
    em[158] = 8884097; em[159] = 8; em[160] = 0; /* 158: pointer.func */
    em[161] = 8884097; em[162] = 8; em[163] = 0; /* 161: pointer.func */
    em[164] = 8884097; em[165] = 8; em[166] = 0; /* 164: pointer.func */
    em[167] = 8884097; em[168] = 8; em[169] = 0; /* 167: pointer.func */
    em[170] = 8884097; em[171] = 8; em[172] = 0; /* 170: pointer.func */
    em[173] = 8884097; em[174] = 8; em[175] = 0; /* 173: pointer.func */
    em[176] = 8884097; em[177] = 8; em[178] = 0; /* 176: pointer.func */
    em[179] = 8884097; em[180] = 8; em[181] = 0; /* 179: pointer.func */
    em[182] = 8884097; em[183] = 8; em[184] = 0; /* 182: pointer.func */
    em[185] = 8884097; em[186] = 8; em[187] = 0; /* 185: pointer.func */
    em[188] = 8884097; em[189] = 8; em[190] = 0; /* 188: pointer.func */
    em[191] = 8884097; em[192] = 8; em[193] = 0; /* 191: pointer.func */
    em[194] = 8884097; em[195] = 8; em[196] = 0; /* 194: pointer.func */
    em[197] = 8884097; em[198] = 8; em[199] = 0; /* 197: pointer.func */
    em[200] = 8884097; em[201] = 8; em[202] = 0; /* 200: pointer.func */
    em[203] = 8884097; em[204] = 8; em[205] = 0; /* 203: pointer.func */
    em[206] = 8884097; em[207] = 8; em[208] = 0; /* 206: pointer.func */
    em[209] = 8884097; em[210] = 8; em[211] = 0; /* 209: pointer.func */
    em[212] = 8884097; em[213] = 8; em[214] = 0; /* 212: pointer.func */
    em[215] = 8884097; em[216] = 8; em[217] = 0; /* 215: pointer.func */
    em[218] = 8884097; em[219] = 8; em[220] = 0; /* 218: pointer.func */
    em[221] = 8884097; em[222] = 8; em[223] = 0; /* 221: pointer.func */
    em[224] = 8884097; em[225] = 8; em[226] = 0; /* 224: pointer.func */
    em[227] = 8884097; em[228] = 8; em[229] = 0; /* 227: pointer.func */
    em[230] = 8884097; em[231] = 8; em[232] = 0; /* 230: pointer.func */
    em[233] = 8884097; em[234] = 8; em[235] = 0; /* 233: pointer.func */
    em[236] = 0; em[237] = 24; em[238] = 1; /* 236: struct.bignum_st */
    	em[239] = 43; em[240] = 0; 
    em[241] = 0; em[242] = 232; em[243] = 12; /* 241: struct.ec_group_st */
    	em[244] = 64; em[245] = 0; 
    	em[246] = 268; em[247] = 8; 
    	em[248] = 236; em[249] = 16; 
    	em[250] = 236; em[251] = 40; 
    	em[252] = 32; em[253] = 80; 
    	em[254] = 27; em[255] = 96; 
    	em[256] = 236; em[257] = 104; 
    	em[258] = 236; em[259] = 152; 
    	em[260] = 236; em[261] = 176; 
    	em[262] = 18; em[263] = 208; 
    	em[264] = 18; em[265] = 216; 
    	em[266] = 273; em[267] = 224; 
    em[268] = 1; em[269] = 8; em[270] = 1; /* 268: pointer.struct.ec_point_st */
    	em[271] = 53; em[272] = 0; 
    em[273] = 8884097; em[274] = 8; em[275] = 0; /* 273: pointer.func */
    em[276] = 1; em[277] = 8; em[278] = 1; /* 276: pointer.struct.ec_group_st */
    	em[279] = 241; em[280] = 0; 
    args_addr->arg_entity_index[0] = 276;
    args_addr->ret_entity_index = 50;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    const EC_GROUP * new_arg_a = *((const EC_GROUP * *)new_args->args[0]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_EC_GROUP_get_curve_name)(const EC_GROUP *);
    orig_EC_GROUP_get_curve_name = dlsym(RTLD_NEXT, "EC_GROUP_get_curve_name");
    *new_ret_ptr = (*orig_EC_GROUP_get_curve_name)(new_arg_a);

    syscall(889);

    free(args_addr);

    return ret;
}

