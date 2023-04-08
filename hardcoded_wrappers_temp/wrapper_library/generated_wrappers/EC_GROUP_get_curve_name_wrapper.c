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
    em[0] = 8884097; em[1] = 8; em[2] = 0; /* 0: pointer.func */
    em[3] = 8884097; em[4] = 8; em[5] = 0; /* 3: pointer.func */
    em[6] = 0; em[7] = 8; em[8] = 0; /* 6: pointer.void */
    em[9] = 1; em[10] = 8; em[11] = 1; /* 9: pointer.struct.ec_extra_data_st */
    	em[12] = 14; em[13] = 0; 
    em[14] = 0; em[15] = 40; em[16] = 5; /* 14: struct.ec_extra_data_st */
    	em[17] = 9; em[18] = 0; 
    	em[19] = 6; em[20] = 8; 
    	em[21] = 3; em[22] = 16; 
    	em[23] = 27; em[24] = 24; 
    	em[25] = 27; em[26] = 32; 
    em[27] = 8884097; em[28] = 8; em[29] = 0; /* 27: pointer.func */
    em[30] = 1; em[31] = 8; em[32] = 1; /* 30: pointer.struct.ec_extra_data_st */
    	em[33] = 14; em[34] = 0; 
    em[35] = 0; em[36] = 24; em[37] = 1; /* 35: struct.bignum_st */
    	em[38] = 40; em[39] = 0; 
    em[40] = 8884099; em[41] = 8; em[42] = 2; /* 40: pointer_to_array_of_pointers_to_stack */
    	em[43] = 47; em[44] = 0; 
    	em[45] = 50; em[46] = 12; 
    em[47] = 0; em[48] = 8; em[49] = 0; /* 47: long unsigned int */
    em[50] = 0; em[51] = 4; em[52] = 0; /* 50: int */
    em[53] = 8884097; em[54] = 8; em[55] = 0; /* 53: pointer.func */
    em[56] = 8884097; em[57] = 8; em[58] = 0; /* 56: pointer.func */
    em[59] = 8884097; em[60] = 8; em[61] = 0; /* 59: pointer.func */
    em[62] = 8884097; em[63] = 8; em[64] = 0; /* 62: pointer.func */
    em[65] = 8884097; em[66] = 8; em[67] = 0; /* 65: pointer.func */
    em[68] = 8884097; em[69] = 8; em[70] = 0; /* 68: pointer.func */
    em[71] = 8884097; em[72] = 8; em[73] = 0; /* 71: pointer.func */
    em[74] = 8884097; em[75] = 8; em[76] = 0; /* 74: pointer.func */
    em[77] = 8884097; em[78] = 8; em[79] = 0; /* 77: pointer.func */
    em[80] = 8884097; em[81] = 8; em[82] = 0; /* 80: pointer.func */
    em[83] = 8884097; em[84] = 8; em[85] = 0; /* 83: pointer.func */
    em[86] = 8884097; em[87] = 8; em[88] = 0; /* 86: pointer.func */
    em[89] = 8884097; em[90] = 8; em[91] = 0; /* 89: pointer.func */
    em[92] = 8884097; em[93] = 8; em[94] = 0; /* 92: pointer.func */
    em[95] = 8884097; em[96] = 8; em[97] = 0; /* 95: pointer.func */
    em[98] = 8884097; em[99] = 8; em[100] = 0; /* 98: pointer.func */
    em[101] = 8884097; em[102] = 8; em[103] = 0; /* 101: pointer.func */
    em[104] = 8884097; em[105] = 8; em[106] = 0; /* 104: pointer.func */
    em[107] = 1; em[108] = 8; em[109] = 1; /* 107: pointer.unsigned char */
    	em[110] = 112; em[111] = 0; 
    em[112] = 0; em[113] = 1; em[114] = 0; /* 112: unsigned char */
    em[115] = 1; em[116] = 8; em[117] = 1; /* 115: pointer.struct.ec_point_st */
    	em[118] = 120; em[119] = 0; 
    em[120] = 0; em[121] = 88; em[122] = 4; /* 120: struct.ec_point_st */
    	em[123] = 131; em[124] = 0; 
    	em[125] = 276; em[126] = 8; 
    	em[127] = 276; em[128] = 32; 
    	em[129] = 276; em[130] = 56; 
    em[131] = 1; em[132] = 8; em[133] = 1; /* 131: pointer.struct.ec_method_st */
    	em[134] = 136; em[135] = 0; 
    em[136] = 0; em[137] = 304; em[138] = 37; /* 136: struct.ec_method_st */
    	em[139] = 213; em[140] = 8; 
    	em[141] = 83; em[142] = 16; 
    	em[143] = 83; em[144] = 24; 
    	em[145] = 216; em[146] = 32; 
    	em[147] = 219; em[148] = 40; 
    	em[149] = 222; em[150] = 48; 
    	em[151] = 225; em[152] = 56; 
    	em[153] = 228; em[154] = 64; 
    	em[155] = 231; em[156] = 72; 
    	em[157] = 234; em[158] = 80; 
    	em[159] = 234; em[160] = 88; 
    	em[161] = 237; em[162] = 96; 
    	em[163] = 95; em[164] = 104; 
    	em[165] = 240; em[166] = 112; 
    	em[167] = 243; em[168] = 120; 
    	em[169] = 246; em[170] = 128; 
    	em[171] = 249; em[172] = 136; 
    	em[173] = 252; em[174] = 144; 
    	em[175] = 255; em[176] = 152; 
    	em[177] = 258; em[178] = 160; 
    	em[179] = 261; em[180] = 168; 
    	em[181] = 92; em[182] = 176; 
    	em[183] = 264; em[184] = 184; 
    	em[185] = 68; em[186] = 192; 
    	em[187] = 65; em[188] = 200; 
    	em[189] = 267; em[190] = 208; 
    	em[191] = 264; em[192] = 216; 
    	em[193] = 270; em[194] = 224; 
    	em[195] = 62; em[196] = 232; 
    	em[197] = 59; em[198] = 240; 
    	em[199] = 225; em[200] = 248; 
    	em[201] = 56; em[202] = 256; 
    	em[203] = 273; em[204] = 264; 
    	em[205] = 56; em[206] = 272; 
    	em[207] = 273; em[208] = 280; 
    	em[209] = 273; em[210] = 288; 
    	em[211] = 53; em[212] = 296; 
    em[213] = 8884097; em[214] = 8; em[215] = 0; /* 213: pointer.func */
    em[216] = 8884097; em[217] = 8; em[218] = 0; /* 216: pointer.func */
    em[219] = 8884097; em[220] = 8; em[221] = 0; /* 219: pointer.func */
    em[222] = 8884097; em[223] = 8; em[224] = 0; /* 222: pointer.func */
    em[225] = 8884097; em[226] = 8; em[227] = 0; /* 225: pointer.func */
    em[228] = 8884097; em[229] = 8; em[230] = 0; /* 228: pointer.func */
    em[231] = 8884097; em[232] = 8; em[233] = 0; /* 231: pointer.func */
    em[234] = 8884097; em[235] = 8; em[236] = 0; /* 234: pointer.func */
    em[237] = 8884097; em[238] = 8; em[239] = 0; /* 237: pointer.func */
    em[240] = 8884097; em[241] = 8; em[242] = 0; /* 240: pointer.func */
    em[243] = 8884097; em[244] = 8; em[245] = 0; /* 243: pointer.func */
    em[246] = 8884097; em[247] = 8; em[248] = 0; /* 246: pointer.func */
    em[249] = 8884097; em[250] = 8; em[251] = 0; /* 249: pointer.func */
    em[252] = 8884097; em[253] = 8; em[254] = 0; /* 252: pointer.func */
    em[255] = 8884097; em[256] = 8; em[257] = 0; /* 255: pointer.func */
    em[258] = 8884097; em[259] = 8; em[260] = 0; /* 258: pointer.func */
    em[261] = 8884097; em[262] = 8; em[263] = 0; /* 261: pointer.func */
    em[264] = 8884097; em[265] = 8; em[266] = 0; /* 264: pointer.func */
    em[267] = 8884097; em[268] = 8; em[269] = 0; /* 267: pointer.func */
    em[270] = 8884097; em[271] = 8; em[272] = 0; /* 270: pointer.func */
    em[273] = 8884097; em[274] = 8; em[275] = 0; /* 273: pointer.func */
    em[276] = 0; em[277] = 24; em[278] = 1; /* 276: struct.bignum_st */
    	em[279] = 281; em[280] = 0; 
    em[281] = 8884099; em[282] = 8; em[283] = 2; /* 281: pointer_to_array_of_pointers_to_stack */
    	em[284] = 47; em[285] = 0; 
    	em[286] = 50; em[287] = 12; 
    em[288] = 8884097; em[289] = 8; em[290] = 0; /* 288: pointer.func */
    em[291] = 8884097; em[292] = 8; em[293] = 0; /* 291: pointer.func */
    em[294] = 8884097; em[295] = 8; em[296] = 0; /* 294: pointer.func */
    em[297] = 8884097; em[298] = 8; em[299] = 0; /* 297: pointer.func */
    em[300] = 1; em[301] = 8; em[302] = 1; /* 300: pointer.struct.ec_method_st */
    	em[303] = 305; em[304] = 0; 
    em[305] = 0; em[306] = 304; em[307] = 37; /* 305: struct.ec_method_st */
    	em[308] = 104; em[309] = 8; 
    	em[310] = 382; em[311] = 16; 
    	em[312] = 382; em[313] = 24; 
    	em[314] = 385; em[315] = 32; 
    	em[316] = 388; em[317] = 40; 
    	em[318] = 391; em[319] = 48; 
    	em[320] = 394; em[321] = 56; 
    	em[322] = 397; em[323] = 64; 
    	em[324] = 400; em[325] = 72; 
    	em[326] = 80; em[327] = 80; 
    	em[328] = 80; em[329] = 88; 
    	em[330] = 403; em[331] = 96; 
    	em[332] = 101; em[333] = 104; 
    	em[334] = 98; em[335] = 112; 
    	em[336] = 291; em[337] = 120; 
    	em[338] = 406; em[339] = 128; 
    	em[340] = 297; em[341] = 136; 
    	em[342] = 89; em[343] = 144; 
    	em[344] = 86; em[345] = 152; 
    	em[346] = 409; em[347] = 160; 
    	em[348] = 77; em[349] = 168; 
    	em[350] = 74; em[351] = 176; 
    	em[352] = 412; em[353] = 184; 
    	em[354] = 71; em[355] = 192; 
    	em[356] = 288; em[357] = 200; 
    	em[358] = 294; em[359] = 208; 
    	em[360] = 412; em[361] = 216; 
    	em[362] = 415; em[363] = 224; 
    	em[364] = 418; em[365] = 232; 
    	em[366] = 421; em[367] = 240; 
    	em[368] = 394; em[369] = 248; 
    	em[370] = 424; em[371] = 256; 
    	em[372] = 427; em[373] = 264; 
    	em[374] = 424; em[375] = 272; 
    	em[376] = 427; em[377] = 280; 
    	em[378] = 427; em[379] = 288; 
    	em[380] = 430; em[381] = 296; 
    em[382] = 8884097; em[383] = 8; em[384] = 0; /* 382: pointer.func */
    em[385] = 8884097; em[386] = 8; em[387] = 0; /* 385: pointer.func */
    em[388] = 8884097; em[389] = 8; em[390] = 0; /* 388: pointer.func */
    em[391] = 8884097; em[392] = 8; em[393] = 0; /* 391: pointer.func */
    em[394] = 8884097; em[395] = 8; em[396] = 0; /* 394: pointer.func */
    em[397] = 8884097; em[398] = 8; em[399] = 0; /* 397: pointer.func */
    em[400] = 8884097; em[401] = 8; em[402] = 0; /* 400: pointer.func */
    em[403] = 8884097; em[404] = 8; em[405] = 0; /* 403: pointer.func */
    em[406] = 8884097; em[407] = 8; em[408] = 0; /* 406: pointer.func */
    em[409] = 8884097; em[410] = 8; em[411] = 0; /* 409: pointer.func */
    em[412] = 8884097; em[413] = 8; em[414] = 0; /* 412: pointer.func */
    em[415] = 8884097; em[416] = 8; em[417] = 0; /* 415: pointer.func */
    em[418] = 8884097; em[419] = 8; em[420] = 0; /* 418: pointer.func */
    em[421] = 8884097; em[422] = 8; em[423] = 0; /* 421: pointer.func */
    em[424] = 8884097; em[425] = 8; em[426] = 0; /* 424: pointer.func */
    em[427] = 8884097; em[428] = 8; em[429] = 0; /* 427: pointer.func */
    em[430] = 8884097; em[431] = 8; em[432] = 0; /* 430: pointer.func */
    em[433] = 1; em[434] = 8; em[435] = 1; /* 433: pointer.struct.ec_group_st */
    	em[436] = 438; em[437] = 0; 
    em[438] = 0; em[439] = 232; em[440] = 12; /* 438: struct.ec_group_st */
    	em[441] = 300; em[442] = 0; 
    	em[443] = 115; em[444] = 8; 
    	em[445] = 35; em[446] = 16; 
    	em[447] = 35; em[448] = 40; 
    	em[449] = 107; em[450] = 80; 
    	em[451] = 30; em[452] = 96; 
    	em[453] = 35; em[454] = 104; 
    	em[455] = 35; em[456] = 152; 
    	em[457] = 35; em[458] = 176; 
    	em[459] = 6; em[460] = 208; 
    	em[461] = 6; em[462] = 216; 
    	em[463] = 0; em[464] = 224; 
    args_addr->arg_entity_index[0] = 433;
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

