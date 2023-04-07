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
    em[6] = 0; em[7] = 40; em[8] = 5; /* 6: struct.ec_extra_data_st */
    	em[9] = 19; em[10] = 0; 
    	em[11] = 24; em[12] = 8; 
    	em[13] = 3; em[14] = 16; 
    	em[15] = 27; em[16] = 24; 
    	em[17] = 27; em[18] = 32; 
    em[19] = 1; em[20] = 8; em[21] = 1; /* 19: pointer.struct.ec_extra_data_st */
    	em[22] = 6; em[23] = 0; 
    em[24] = 0; em[25] = 8; em[26] = 0; /* 24: pointer.void */
    em[27] = 8884097; em[28] = 8; em[29] = 0; /* 27: pointer.func */
    em[30] = 1; em[31] = 8; em[32] = 1; /* 30: pointer.struct.ec_extra_data_st */
    	em[33] = 6; em[34] = 0; 
    em[35] = 0; em[36] = 4; em[37] = 0; /* 35: unsigned int */
    em[38] = 8884099; em[39] = 8; em[40] = 2; /* 38: pointer_to_array_of_pointers_to_stack */
    	em[41] = 35; em[42] = 0; 
    	em[43] = 45; em[44] = 12; 
    em[45] = 0; em[46] = 4; em[47] = 0; /* 45: int */
    em[48] = 0; em[49] = 24; em[50] = 1; /* 48: struct.bignum_st */
    	em[51] = 53; em[52] = 0; 
    em[53] = 8884099; em[54] = 8; em[55] = 2; /* 53: pointer_to_array_of_pointers_to_stack */
    	em[56] = 35; em[57] = 0; 
    	em[58] = 45; em[59] = 12; 
    em[60] = 8884097; em[61] = 8; em[62] = 0; /* 60: pointer.func */
    em[63] = 8884097; em[64] = 8; em[65] = 0; /* 63: pointer.func */
    em[66] = 8884097; em[67] = 8; em[68] = 0; /* 66: pointer.func */
    em[69] = 8884097; em[70] = 8; em[71] = 0; /* 69: pointer.func */
    em[72] = 8884097; em[73] = 8; em[74] = 0; /* 72: pointer.func */
    em[75] = 8884097; em[76] = 8; em[77] = 0; /* 75: pointer.func */
    em[78] = 8884097; em[79] = 8; em[80] = 0; /* 78: pointer.func */
    em[81] = 8884097; em[82] = 8; em[83] = 0; /* 81: pointer.func */
    em[84] = 8884097; em[85] = 8; em[86] = 0; /* 84: pointer.func */
    em[87] = 8884097; em[88] = 8; em[89] = 0; /* 87: pointer.func */
    em[90] = 8884097; em[91] = 8; em[92] = 0; /* 90: pointer.func */
    em[93] = 0; em[94] = 232; em[95] = 12; /* 93: struct.ec_group_st */
    	em[96] = 120; em[97] = 0; 
    	em[98] = 283; em[99] = 8; 
    	em[100] = 447; em[101] = 16; 
    	em[102] = 447; em[103] = 40; 
    	em[104] = 452; em[105] = 80; 
    	em[106] = 30; em[107] = 96; 
    	em[108] = 447; em[109] = 104; 
    	em[110] = 447; em[111] = 152; 
    	em[112] = 447; em[113] = 176; 
    	em[114] = 24; em[115] = 208; 
    	em[116] = 24; em[117] = 216; 
    	em[118] = 0; em[119] = 224; 
    em[120] = 1; em[121] = 8; em[122] = 1; /* 120: pointer.struct.ec_method_st */
    	em[123] = 125; em[124] = 0; 
    em[125] = 0; em[126] = 304; em[127] = 37; /* 125: struct.ec_method_st */
    	em[128] = 202; em[129] = 8; 
    	em[130] = 205; em[131] = 16; 
    	em[132] = 205; em[133] = 24; 
    	em[134] = 208; em[135] = 32; 
    	em[136] = 211; em[137] = 40; 
    	em[138] = 214; em[139] = 48; 
    	em[140] = 217; em[141] = 56; 
    	em[142] = 220; em[143] = 64; 
    	em[144] = 223; em[145] = 72; 
    	em[146] = 226; em[147] = 80; 
    	em[148] = 226; em[149] = 88; 
    	em[150] = 229; em[151] = 96; 
    	em[152] = 232; em[153] = 104; 
    	em[154] = 235; em[155] = 112; 
    	em[156] = 238; em[157] = 120; 
    	em[158] = 241; em[159] = 128; 
    	em[160] = 244; em[161] = 136; 
    	em[162] = 247; em[163] = 144; 
    	em[164] = 250; em[165] = 152; 
    	em[166] = 253; em[167] = 160; 
    	em[168] = 90; em[169] = 168; 
    	em[170] = 84; em[171] = 176; 
    	em[172] = 256; em[173] = 184; 
    	em[174] = 81; em[175] = 192; 
    	em[176] = 259; em[177] = 200; 
    	em[178] = 262; em[179] = 208; 
    	em[180] = 256; em[181] = 216; 
    	em[182] = 265; em[183] = 224; 
    	em[184] = 268; em[185] = 232; 
    	em[186] = 271; em[187] = 240; 
    	em[188] = 217; em[189] = 248; 
    	em[190] = 274; em[191] = 256; 
    	em[192] = 277; em[193] = 264; 
    	em[194] = 274; em[195] = 272; 
    	em[196] = 277; em[197] = 280; 
    	em[198] = 277; em[199] = 288; 
    	em[200] = 280; em[201] = 296; 
    em[202] = 8884097; em[203] = 8; em[204] = 0; /* 202: pointer.func */
    em[205] = 8884097; em[206] = 8; em[207] = 0; /* 205: pointer.func */
    em[208] = 8884097; em[209] = 8; em[210] = 0; /* 208: pointer.func */
    em[211] = 8884097; em[212] = 8; em[213] = 0; /* 211: pointer.func */
    em[214] = 8884097; em[215] = 8; em[216] = 0; /* 214: pointer.func */
    em[217] = 8884097; em[218] = 8; em[219] = 0; /* 217: pointer.func */
    em[220] = 8884097; em[221] = 8; em[222] = 0; /* 220: pointer.func */
    em[223] = 8884097; em[224] = 8; em[225] = 0; /* 223: pointer.func */
    em[226] = 8884097; em[227] = 8; em[228] = 0; /* 226: pointer.func */
    em[229] = 8884097; em[230] = 8; em[231] = 0; /* 229: pointer.func */
    em[232] = 8884097; em[233] = 8; em[234] = 0; /* 232: pointer.func */
    em[235] = 8884097; em[236] = 8; em[237] = 0; /* 235: pointer.func */
    em[238] = 8884097; em[239] = 8; em[240] = 0; /* 238: pointer.func */
    em[241] = 8884097; em[242] = 8; em[243] = 0; /* 241: pointer.func */
    em[244] = 8884097; em[245] = 8; em[246] = 0; /* 244: pointer.func */
    em[247] = 8884097; em[248] = 8; em[249] = 0; /* 247: pointer.func */
    em[250] = 8884097; em[251] = 8; em[252] = 0; /* 250: pointer.func */
    em[253] = 8884097; em[254] = 8; em[255] = 0; /* 253: pointer.func */
    em[256] = 8884097; em[257] = 8; em[258] = 0; /* 256: pointer.func */
    em[259] = 8884097; em[260] = 8; em[261] = 0; /* 259: pointer.func */
    em[262] = 8884097; em[263] = 8; em[264] = 0; /* 262: pointer.func */
    em[265] = 8884097; em[266] = 8; em[267] = 0; /* 265: pointer.func */
    em[268] = 8884097; em[269] = 8; em[270] = 0; /* 268: pointer.func */
    em[271] = 8884097; em[272] = 8; em[273] = 0; /* 271: pointer.func */
    em[274] = 8884097; em[275] = 8; em[276] = 0; /* 274: pointer.func */
    em[277] = 8884097; em[278] = 8; em[279] = 0; /* 277: pointer.func */
    em[280] = 8884097; em[281] = 8; em[282] = 0; /* 280: pointer.func */
    em[283] = 1; em[284] = 8; em[285] = 1; /* 283: pointer.struct.ec_point_st */
    	em[286] = 288; em[287] = 0; 
    em[288] = 0; em[289] = 88; em[290] = 4; /* 288: struct.ec_point_st */
    	em[291] = 299; em[292] = 0; 
    	em[293] = 48; em[294] = 8; 
    	em[295] = 48; em[296] = 32; 
    	em[297] = 48; em[298] = 56; 
    em[299] = 1; em[300] = 8; em[301] = 1; /* 299: pointer.struct.ec_method_st */
    	em[302] = 304; em[303] = 0; 
    em[304] = 0; em[305] = 304; em[306] = 37; /* 304: struct.ec_method_st */
    	em[307] = 381; em[308] = 8; 
    	em[309] = 384; em[310] = 16; 
    	em[311] = 384; em[312] = 24; 
    	em[313] = 387; em[314] = 32; 
    	em[315] = 390; em[316] = 40; 
    	em[317] = 393; em[318] = 48; 
    	em[319] = 396; em[320] = 56; 
    	em[321] = 399; em[322] = 64; 
    	em[323] = 402; em[324] = 72; 
    	em[325] = 405; em[326] = 80; 
    	em[327] = 405; em[328] = 88; 
    	em[329] = 408; em[330] = 96; 
    	em[331] = 411; em[332] = 104; 
    	em[333] = 414; em[334] = 112; 
    	em[335] = 417; em[336] = 120; 
    	em[337] = 420; em[338] = 128; 
    	em[339] = 423; em[340] = 136; 
    	em[341] = 87; em[342] = 144; 
    	em[343] = 426; em[344] = 152; 
    	em[345] = 429; em[346] = 160; 
    	em[347] = 432; em[348] = 168; 
    	em[349] = 435; em[350] = 176; 
    	em[351] = 78; em[352] = 184; 
    	em[353] = 72; em[354] = 192; 
    	em[355] = 69; em[356] = 200; 
    	em[357] = 438; em[358] = 208; 
    	em[359] = 78; em[360] = 216; 
    	em[361] = 441; em[362] = 224; 
    	em[363] = 66; em[364] = 232; 
    	em[365] = 444; em[366] = 240; 
    	em[367] = 396; em[368] = 248; 
    	em[369] = 63; em[370] = 256; 
    	em[371] = 75; em[372] = 264; 
    	em[373] = 63; em[374] = 272; 
    	em[375] = 75; em[376] = 280; 
    	em[377] = 75; em[378] = 288; 
    	em[379] = 60; em[380] = 296; 
    em[381] = 8884097; em[382] = 8; em[383] = 0; /* 381: pointer.func */
    em[384] = 8884097; em[385] = 8; em[386] = 0; /* 384: pointer.func */
    em[387] = 8884097; em[388] = 8; em[389] = 0; /* 387: pointer.func */
    em[390] = 8884097; em[391] = 8; em[392] = 0; /* 390: pointer.func */
    em[393] = 8884097; em[394] = 8; em[395] = 0; /* 393: pointer.func */
    em[396] = 8884097; em[397] = 8; em[398] = 0; /* 396: pointer.func */
    em[399] = 8884097; em[400] = 8; em[401] = 0; /* 399: pointer.func */
    em[402] = 8884097; em[403] = 8; em[404] = 0; /* 402: pointer.func */
    em[405] = 8884097; em[406] = 8; em[407] = 0; /* 405: pointer.func */
    em[408] = 8884097; em[409] = 8; em[410] = 0; /* 408: pointer.func */
    em[411] = 8884097; em[412] = 8; em[413] = 0; /* 411: pointer.func */
    em[414] = 8884097; em[415] = 8; em[416] = 0; /* 414: pointer.func */
    em[417] = 8884097; em[418] = 8; em[419] = 0; /* 417: pointer.func */
    em[420] = 8884097; em[421] = 8; em[422] = 0; /* 420: pointer.func */
    em[423] = 8884097; em[424] = 8; em[425] = 0; /* 423: pointer.func */
    em[426] = 8884097; em[427] = 8; em[428] = 0; /* 426: pointer.func */
    em[429] = 8884097; em[430] = 8; em[431] = 0; /* 429: pointer.func */
    em[432] = 8884097; em[433] = 8; em[434] = 0; /* 432: pointer.func */
    em[435] = 8884097; em[436] = 8; em[437] = 0; /* 435: pointer.func */
    em[438] = 8884097; em[439] = 8; em[440] = 0; /* 438: pointer.func */
    em[441] = 8884097; em[442] = 8; em[443] = 0; /* 441: pointer.func */
    em[444] = 8884097; em[445] = 8; em[446] = 0; /* 444: pointer.func */
    em[447] = 0; em[448] = 24; em[449] = 1; /* 447: struct.bignum_st */
    	em[450] = 38; em[451] = 0; 
    em[452] = 1; em[453] = 8; em[454] = 1; /* 452: pointer.unsigned char */
    	em[455] = 457; em[456] = 0; 
    em[457] = 0; em[458] = 1; em[459] = 0; /* 457: unsigned char */
    em[460] = 1; em[461] = 8; em[462] = 1; /* 460: pointer.struct.ec_group_st */
    	em[463] = 93; em[464] = 0; 
    args_addr->arg_entity_index[0] = 460;
    args_addr->ret_entity_index = 45;
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

