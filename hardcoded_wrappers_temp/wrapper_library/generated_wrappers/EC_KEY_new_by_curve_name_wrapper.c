#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
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

EC_KEY * bb_EC_KEY_new_by_curve_name(int arg_a);

EC_KEY * EC_KEY_new_by_curve_name(int arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("EC_KEY_new_by_curve_name called %lu\n", in_lib);
    if (!in_lib)
        return bb_EC_KEY_new_by_curve_name(arg_a);
    else {
        EC_KEY * (*orig_EC_KEY_new_by_curve_name)(int);
        orig_EC_KEY_new_by_curve_name = dlsym(RTLD_NEXT, "EC_KEY_new_by_curve_name");
        return orig_EC_KEY_new_by_curve_name(arg_a);
    }
}

EC_KEY * bb_EC_KEY_new_by_curve_name(int arg_a) 
{
    EC_KEY * ret;

    struct lib_enter_args *args_addr = malloc(sizeof(struct lib_enter_args));
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
    em[81] = 1; em[82] = 8; em[83] = 1; /* 81: pointer.struct.ec_extra_data_st */
    	em[84] = 86; em[85] = 0; 
    em[86] = 0; em[87] = 40; em[88] = 5; /* 86: struct.ec_extra_data_st */
    	em[89] = 99; em[90] = 0; 
    	em[91] = 24; em[92] = 8; 
    	em[93] = 3; em[94] = 16; 
    	em[95] = 27; em[96] = 24; 
    	em[97] = 27; em[98] = 32; 
    em[99] = 1; em[100] = 8; em[101] = 1; /* 99: pointer.struct.ec_extra_data_st */
    	em[102] = 86; em[103] = 0; 
    em[104] = 8884097; em[105] = 8; em[106] = 0; /* 104: pointer.func */
    em[107] = 1; em[108] = 8; em[109] = 1; /* 107: pointer.struct.ec_point_st */
    	em[110] = 112; em[111] = 0; 
    em[112] = 0; em[113] = 88; em[114] = 4; /* 112: struct.ec_point_st */
    	em[115] = 123; em[116] = 0; 
    	em[117] = 48; em[118] = 8; 
    	em[119] = 48; em[120] = 32; 
    	em[121] = 48; em[122] = 56; 
    em[123] = 1; em[124] = 8; em[125] = 1; /* 123: pointer.struct.ec_method_st */
    	em[126] = 128; em[127] = 0; 
    em[128] = 0; em[129] = 304; em[130] = 37; /* 128: struct.ec_method_st */
    	em[131] = 205; em[132] = 8; 
    	em[133] = 208; em[134] = 16; 
    	em[135] = 208; em[136] = 24; 
    	em[137] = 211; em[138] = 32; 
    	em[139] = 214; em[140] = 40; 
    	em[141] = 217; em[142] = 48; 
    	em[143] = 220; em[144] = 56; 
    	em[145] = 223; em[146] = 64; 
    	em[147] = 226; em[148] = 72; 
    	em[149] = 229; em[150] = 80; 
    	em[151] = 229; em[152] = 88; 
    	em[153] = 232; em[154] = 96; 
    	em[155] = 235; em[156] = 104; 
    	em[157] = 238; em[158] = 112; 
    	em[159] = 241; em[160] = 120; 
    	em[161] = 244; em[162] = 128; 
    	em[163] = 247; em[164] = 136; 
    	em[165] = 250; em[166] = 144; 
    	em[167] = 253; em[168] = 152; 
    	em[169] = 256; em[170] = 160; 
    	em[171] = 259; em[172] = 168; 
    	em[173] = 104; em[174] = 176; 
    	em[175] = 78; em[176] = 184; 
    	em[177] = 72; em[178] = 192; 
    	em[179] = 69; em[180] = 200; 
    	em[181] = 262; em[182] = 208; 
    	em[183] = 78; em[184] = 216; 
    	em[185] = 265; em[186] = 224; 
    	em[187] = 66; em[188] = 232; 
    	em[189] = 268; em[190] = 240; 
    	em[191] = 220; em[192] = 248; 
    	em[193] = 63; em[194] = 256; 
    	em[195] = 75; em[196] = 264; 
    	em[197] = 63; em[198] = 272; 
    	em[199] = 75; em[200] = 280; 
    	em[201] = 75; em[202] = 288; 
    	em[203] = 60; em[204] = 296; 
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
    em[277] = 0; em[278] = 232; em[279] = 12; /* 277: struct.ec_group_st */
    	em[280] = 304; em[281] = 0; 
    	em[282] = 470; em[283] = 8; 
    	em[284] = 475; em[285] = 16; 
    	em[286] = 475; em[287] = 40; 
    	em[288] = 487; em[289] = 80; 
    	em[290] = 30; em[291] = 96; 
    	em[292] = 475; em[293] = 104; 
    	em[294] = 475; em[295] = 152; 
    	em[296] = 475; em[297] = 176; 
    	em[298] = 24; em[299] = 208; 
    	em[300] = 24; em[301] = 216; 
    	em[302] = 0; em[303] = 224; 
    em[304] = 1; em[305] = 8; em[306] = 1; /* 304: pointer.struct.ec_method_st */
    	em[307] = 309; em[308] = 0; 
    em[309] = 0; em[310] = 304; em[311] = 37; /* 309: struct.ec_method_st */
    	em[312] = 386; em[313] = 8; 
    	em[314] = 389; em[315] = 16; 
    	em[316] = 389; em[317] = 24; 
    	em[318] = 392; em[319] = 32; 
    	em[320] = 395; em[321] = 40; 
    	em[322] = 398; em[323] = 48; 
    	em[324] = 401; em[325] = 56; 
    	em[326] = 404; em[327] = 64; 
    	em[328] = 407; em[329] = 72; 
    	em[330] = 410; em[331] = 80; 
    	em[332] = 410; em[333] = 88; 
    	em[334] = 413; em[335] = 96; 
    	em[336] = 416; em[337] = 104; 
    	em[338] = 419; em[339] = 112; 
    	em[340] = 422; em[341] = 120; 
    	em[342] = 425; em[343] = 128; 
    	em[344] = 428; em[345] = 136; 
    	em[346] = 431; em[347] = 144; 
    	em[348] = 434; em[349] = 152; 
    	em[350] = 437; em[351] = 160; 
    	em[352] = 274; em[353] = 168; 
    	em[354] = 440; em[355] = 176; 
    	em[356] = 443; em[357] = 184; 
    	em[358] = 271; em[359] = 192; 
    	em[360] = 446; em[361] = 200; 
    	em[362] = 449; em[363] = 208; 
    	em[364] = 443; em[365] = 216; 
    	em[366] = 452; em[367] = 224; 
    	em[368] = 455; em[369] = 232; 
    	em[370] = 458; em[371] = 240; 
    	em[372] = 401; em[373] = 248; 
    	em[374] = 461; em[375] = 256; 
    	em[376] = 464; em[377] = 264; 
    	em[378] = 461; em[379] = 272; 
    	em[380] = 464; em[381] = 280; 
    	em[382] = 464; em[383] = 288; 
    	em[384] = 467; em[385] = 296; 
    em[386] = 8884097; em[387] = 8; em[388] = 0; /* 386: pointer.func */
    em[389] = 8884097; em[390] = 8; em[391] = 0; /* 389: pointer.func */
    em[392] = 8884097; em[393] = 8; em[394] = 0; /* 392: pointer.func */
    em[395] = 8884097; em[396] = 8; em[397] = 0; /* 395: pointer.func */
    em[398] = 8884097; em[399] = 8; em[400] = 0; /* 398: pointer.func */
    em[401] = 8884097; em[402] = 8; em[403] = 0; /* 401: pointer.func */
    em[404] = 8884097; em[405] = 8; em[406] = 0; /* 404: pointer.func */
    em[407] = 8884097; em[408] = 8; em[409] = 0; /* 407: pointer.func */
    em[410] = 8884097; em[411] = 8; em[412] = 0; /* 410: pointer.func */
    em[413] = 8884097; em[414] = 8; em[415] = 0; /* 413: pointer.func */
    em[416] = 8884097; em[417] = 8; em[418] = 0; /* 416: pointer.func */
    em[419] = 8884097; em[420] = 8; em[421] = 0; /* 419: pointer.func */
    em[422] = 8884097; em[423] = 8; em[424] = 0; /* 422: pointer.func */
    em[425] = 8884097; em[426] = 8; em[427] = 0; /* 425: pointer.func */
    em[428] = 8884097; em[429] = 8; em[430] = 0; /* 428: pointer.func */
    em[431] = 8884097; em[432] = 8; em[433] = 0; /* 431: pointer.func */
    em[434] = 8884097; em[435] = 8; em[436] = 0; /* 434: pointer.func */
    em[437] = 8884097; em[438] = 8; em[439] = 0; /* 437: pointer.func */
    em[440] = 8884097; em[441] = 8; em[442] = 0; /* 440: pointer.func */
    em[443] = 8884097; em[444] = 8; em[445] = 0; /* 443: pointer.func */
    em[446] = 8884097; em[447] = 8; em[448] = 0; /* 446: pointer.func */
    em[449] = 8884097; em[450] = 8; em[451] = 0; /* 449: pointer.func */
    em[452] = 8884097; em[453] = 8; em[454] = 0; /* 452: pointer.func */
    em[455] = 8884097; em[456] = 8; em[457] = 0; /* 455: pointer.func */
    em[458] = 8884097; em[459] = 8; em[460] = 0; /* 458: pointer.func */
    em[461] = 8884097; em[462] = 8; em[463] = 0; /* 461: pointer.func */
    em[464] = 8884097; em[465] = 8; em[466] = 0; /* 464: pointer.func */
    em[467] = 8884097; em[468] = 8; em[469] = 0; /* 467: pointer.func */
    em[470] = 1; em[471] = 8; em[472] = 1; /* 470: pointer.struct.ec_point_st */
    	em[473] = 112; em[474] = 0; 
    em[475] = 0; em[476] = 24; em[477] = 1; /* 475: struct.bignum_st */
    	em[478] = 480; em[479] = 0; 
    em[480] = 8884099; em[481] = 8; em[482] = 2; /* 480: pointer_to_array_of_pointers_to_stack */
    	em[483] = 35; em[484] = 0; 
    	em[485] = 45; em[486] = 12; 
    em[487] = 1; em[488] = 8; em[489] = 1; /* 487: pointer.unsigned char */
    	em[490] = 492; em[491] = 0; 
    em[492] = 0; em[493] = 1; em[494] = 0; /* 492: unsigned char */
    em[495] = 0; em[496] = 56; em[497] = 4; /* 495: struct.ec_key_st */
    	em[498] = 506; em[499] = 8; 
    	em[500] = 107; em[501] = 16; 
    	em[502] = 511; em[503] = 24; 
    	em[504] = 81; em[505] = 48; 
    em[506] = 1; em[507] = 8; em[508] = 1; /* 506: pointer.struct.ec_group_st */
    	em[509] = 277; em[510] = 0; 
    em[511] = 1; em[512] = 8; em[513] = 1; /* 511: pointer.struct.bignum_st */
    	em[514] = 516; em[515] = 0; 
    em[516] = 0; em[517] = 24; em[518] = 1; /* 516: struct.bignum_st */
    	em[519] = 38; em[520] = 0; 
    em[521] = 1; em[522] = 8; em[523] = 1; /* 521: pointer.struct.ec_key_st */
    	em[524] = 495; em[525] = 0; 
    args_addr->arg_entity_index[0] = 45;
    args_addr->ret_entity_index = 521;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    int new_arg_a = *((int *)new_args->args[0]);

    EC_KEY * *new_ret_ptr = (EC_KEY * *)new_args->ret;

    EC_KEY * (*orig_EC_KEY_new_by_curve_name)(int);
    orig_EC_KEY_new_by_curve_name = dlsym(RTLD_NEXT, "EC_KEY_new_by_curve_name");
    *new_ret_ptr = (*orig_EC_KEY_new_by_curve_name)(new_arg_a);

    syscall(889);

    free(args_addr);

    return ret;
}

