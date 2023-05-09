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
    memset(args_addr, 0, sizeof(struct lib_enter_args));
    args_addr->num_args = 0;
    uint32_t *em = args_addr->entity_metadata;
    em[0] = 0; em[1] = 24; em[2] = 1; /* 0: struct.bignum_st */
    	em[3] = 5; em[4] = 0; 
    em[5] = 8884099; em[6] = 8; em[7] = 2; /* 5: pointer_to_array_of_pointers_to_stack */
    	em[8] = 12; em[9] = 0; 
    	em[10] = 15; em[11] = 12; 
    em[12] = 0; em[13] = 8; em[14] = 0; /* 12: long unsigned int */
    em[15] = 0; em[16] = 4; em[17] = 0; /* 15: int */
    em[18] = 8884097; em[19] = 8; em[20] = 0; /* 18: pointer.func */
    em[21] = 8884097; em[22] = 8; em[23] = 0; /* 21: pointer.func */
    em[24] = 1; em[25] = 8; em[26] = 1; /* 24: pointer.struct.ec_extra_data_st */
    	em[27] = 29; em[28] = 0; 
    em[29] = 0; em[30] = 40; em[31] = 5; /* 29: struct.ec_extra_data_st */
    	em[32] = 24; em[33] = 0; 
    	em[34] = 42; em[35] = 8; 
    	em[36] = 21; em[37] = 16; 
    	em[38] = 45; em[39] = 24; 
    	em[40] = 45; em[41] = 32; 
    em[42] = 0; em[43] = 8; em[44] = 0; /* 42: pointer.void */
    em[45] = 8884097; em[46] = 8; em[47] = 0; /* 45: pointer.func */
    em[48] = 1; em[49] = 8; em[50] = 1; /* 48: pointer.struct.ec_extra_data_st */
    	em[51] = 29; em[52] = 0; 
    em[53] = 0; em[54] = 24; em[55] = 1; /* 53: struct.bignum_st */
    	em[56] = 58; em[57] = 0; 
    em[58] = 8884099; em[59] = 8; em[60] = 2; /* 58: pointer_to_array_of_pointers_to_stack */
    	em[61] = 12; em[62] = 0; 
    	em[63] = 15; em[64] = 12; 
    em[65] = 8884097; em[66] = 8; em[67] = 0; /* 65: pointer.func */
    em[68] = 8884097; em[69] = 8; em[70] = 0; /* 68: pointer.func */
    em[71] = 8884097; em[72] = 8; em[73] = 0; /* 71: pointer.func */
    em[74] = 8884097; em[75] = 8; em[76] = 0; /* 74: pointer.func */
    em[77] = 8884097; em[78] = 8; em[79] = 0; /* 77: pointer.func */
    em[80] = 8884097; em[81] = 8; em[82] = 0; /* 80: pointer.func */
    em[83] = 1; em[84] = 8; em[85] = 1; /* 83: pointer.struct.ec_point_st */
    	em[86] = 88; em[87] = 0; 
    em[88] = 0; em[89] = 88; em[90] = 4; /* 88: struct.ec_point_st */
    	em[91] = 99; em[92] = 0; 
    	em[93] = 253; em[94] = 8; 
    	em[95] = 253; em[96] = 32; 
    	em[97] = 253; em[98] = 56; 
    em[99] = 1; em[100] = 8; em[101] = 1; /* 99: pointer.struct.ec_method_st */
    	em[102] = 104; em[103] = 0; 
    em[104] = 0; em[105] = 304; em[106] = 37; /* 104: struct.ec_method_st */
    	em[107] = 181; em[108] = 8; 
    	em[109] = 184; em[110] = 16; 
    	em[111] = 184; em[112] = 24; 
    	em[113] = 187; em[114] = 32; 
    	em[115] = 190; em[116] = 40; 
    	em[117] = 193; em[118] = 48; 
    	em[119] = 196; em[120] = 56; 
    	em[121] = 199; em[122] = 64; 
    	em[123] = 202; em[124] = 72; 
    	em[125] = 205; em[126] = 80; 
    	em[127] = 205; em[128] = 88; 
    	em[129] = 208; em[130] = 96; 
    	em[131] = 211; em[132] = 104; 
    	em[133] = 214; em[134] = 112; 
    	em[135] = 217; em[136] = 120; 
    	em[137] = 220; em[138] = 128; 
    	em[139] = 223; em[140] = 136; 
    	em[141] = 226; em[142] = 144; 
    	em[143] = 229; em[144] = 152; 
    	em[145] = 232; em[146] = 160; 
    	em[147] = 235; em[148] = 168; 
    	em[149] = 238; em[150] = 176; 
    	em[151] = 241; em[152] = 184; 
    	em[153] = 80; em[154] = 192; 
    	em[155] = 77; em[156] = 200; 
    	em[157] = 244; em[158] = 208; 
    	em[159] = 241; em[160] = 216; 
    	em[161] = 247; em[162] = 224; 
    	em[163] = 74; em[164] = 232; 
    	em[165] = 71; em[166] = 240; 
    	em[167] = 196; em[168] = 248; 
    	em[169] = 68; em[170] = 256; 
    	em[171] = 250; em[172] = 264; 
    	em[173] = 68; em[174] = 272; 
    	em[175] = 250; em[176] = 280; 
    	em[177] = 250; em[178] = 288; 
    	em[179] = 65; em[180] = 296; 
    em[181] = 8884097; em[182] = 8; em[183] = 0; /* 181: pointer.func */
    em[184] = 8884097; em[185] = 8; em[186] = 0; /* 184: pointer.func */
    em[187] = 8884097; em[188] = 8; em[189] = 0; /* 187: pointer.func */
    em[190] = 8884097; em[191] = 8; em[192] = 0; /* 190: pointer.func */
    em[193] = 8884097; em[194] = 8; em[195] = 0; /* 193: pointer.func */
    em[196] = 8884097; em[197] = 8; em[198] = 0; /* 196: pointer.func */
    em[199] = 8884097; em[200] = 8; em[201] = 0; /* 199: pointer.func */
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
    em[253] = 0; em[254] = 24; em[255] = 1; /* 253: struct.bignum_st */
    	em[256] = 258; em[257] = 0; 
    em[258] = 8884099; em[259] = 8; em[260] = 2; /* 258: pointer_to_array_of_pointers_to_stack */
    	em[261] = 12; em[262] = 0; 
    	em[263] = 15; em[264] = 12; 
    em[265] = 8884097; em[266] = 8; em[267] = 0; /* 265: pointer.func */
    em[268] = 8884097; em[269] = 8; em[270] = 0; /* 268: pointer.func */
    em[271] = 8884097; em[272] = 8; em[273] = 0; /* 271: pointer.func */
    em[274] = 8884097; em[275] = 8; em[276] = 0; /* 274: pointer.func */
    em[277] = 0; em[278] = 56; em[279] = 4; /* 277: struct.ec_key_st */
    	em[280] = 288; em[281] = 8; 
    	em[282] = 83; em[283] = 16; 
    	em[284] = 493; em[285] = 24; 
    	em[286] = 498; em[287] = 48; 
    em[288] = 1; em[289] = 8; em[290] = 1; /* 288: pointer.struct.ec_group_st */
    	em[291] = 293; em[292] = 0; 
    em[293] = 0; em[294] = 232; em[295] = 12; /* 293: struct.ec_group_st */
    	em[296] = 320; em[297] = 0; 
    	em[298] = 480; em[299] = 8; 
    	em[300] = 53; em[301] = 16; 
    	em[302] = 53; em[303] = 40; 
    	em[304] = 485; em[305] = 80; 
    	em[306] = 48; em[307] = 96; 
    	em[308] = 53; em[309] = 104; 
    	em[310] = 53; em[311] = 152; 
    	em[312] = 53; em[313] = 176; 
    	em[314] = 42; em[315] = 208; 
    	em[316] = 42; em[317] = 216; 
    	em[318] = 18; em[319] = 224; 
    em[320] = 1; em[321] = 8; em[322] = 1; /* 320: pointer.struct.ec_method_st */
    	em[323] = 325; em[324] = 0; 
    em[325] = 0; em[326] = 304; em[327] = 37; /* 325: struct.ec_method_st */
    	em[328] = 402; em[329] = 8; 
    	em[330] = 405; em[331] = 16; 
    	em[332] = 405; em[333] = 24; 
    	em[334] = 408; em[335] = 32; 
    	em[336] = 411; em[337] = 40; 
    	em[338] = 414; em[339] = 48; 
    	em[340] = 417; em[341] = 56; 
    	em[342] = 420; em[343] = 64; 
    	em[344] = 423; em[345] = 72; 
    	em[346] = 271; em[347] = 80; 
    	em[348] = 271; em[349] = 88; 
    	em[350] = 426; em[351] = 96; 
    	em[352] = 429; em[353] = 104; 
    	em[354] = 432; em[355] = 112; 
    	em[356] = 435; em[357] = 120; 
    	em[358] = 438; em[359] = 128; 
    	em[360] = 441; em[361] = 136; 
    	em[362] = 444; em[363] = 144; 
    	em[364] = 274; em[365] = 152; 
    	em[366] = 447; em[367] = 160; 
    	em[368] = 268; em[369] = 168; 
    	em[370] = 450; em[371] = 176; 
    	em[372] = 453; em[373] = 184; 
    	em[374] = 265; em[375] = 192; 
    	em[376] = 456; em[377] = 200; 
    	em[378] = 459; em[379] = 208; 
    	em[380] = 453; em[381] = 216; 
    	em[382] = 462; em[383] = 224; 
    	em[384] = 465; em[385] = 232; 
    	em[386] = 468; em[387] = 240; 
    	em[388] = 417; em[389] = 248; 
    	em[390] = 471; em[391] = 256; 
    	em[392] = 474; em[393] = 264; 
    	em[394] = 471; em[395] = 272; 
    	em[396] = 474; em[397] = 280; 
    	em[398] = 474; em[399] = 288; 
    	em[400] = 477; em[401] = 296; 
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
    em[447] = 8884097; em[448] = 8; em[449] = 0; /* 447: pointer.func */
    em[450] = 8884097; em[451] = 8; em[452] = 0; /* 450: pointer.func */
    em[453] = 8884097; em[454] = 8; em[455] = 0; /* 453: pointer.func */
    em[456] = 8884097; em[457] = 8; em[458] = 0; /* 456: pointer.func */
    em[459] = 8884097; em[460] = 8; em[461] = 0; /* 459: pointer.func */
    em[462] = 8884097; em[463] = 8; em[464] = 0; /* 462: pointer.func */
    em[465] = 8884097; em[466] = 8; em[467] = 0; /* 465: pointer.func */
    em[468] = 8884097; em[469] = 8; em[470] = 0; /* 468: pointer.func */
    em[471] = 8884097; em[472] = 8; em[473] = 0; /* 471: pointer.func */
    em[474] = 8884097; em[475] = 8; em[476] = 0; /* 474: pointer.func */
    em[477] = 8884097; em[478] = 8; em[479] = 0; /* 477: pointer.func */
    em[480] = 1; em[481] = 8; em[482] = 1; /* 480: pointer.struct.ec_point_st */
    	em[483] = 88; em[484] = 0; 
    em[485] = 1; em[486] = 8; em[487] = 1; /* 485: pointer.unsigned char */
    	em[488] = 490; em[489] = 0; 
    em[490] = 0; em[491] = 1; em[492] = 0; /* 490: unsigned char */
    em[493] = 1; em[494] = 8; em[495] = 1; /* 493: pointer.struct.bignum_st */
    	em[496] = 0; em[497] = 0; 
    em[498] = 1; em[499] = 8; em[500] = 1; /* 498: pointer.struct.ec_extra_data_st */
    	em[501] = 503; em[502] = 0; 
    em[503] = 0; em[504] = 40; em[505] = 5; /* 503: struct.ec_extra_data_st */
    	em[506] = 516; em[507] = 0; 
    	em[508] = 42; em[509] = 8; 
    	em[510] = 21; em[511] = 16; 
    	em[512] = 45; em[513] = 24; 
    	em[514] = 45; em[515] = 32; 
    em[516] = 1; em[517] = 8; em[518] = 1; /* 516: pointer.struct.ec_extra_data_st */
    	em[519] = 503; em[520] = 0; 
    em[521] = 1; em[522] = 8; em[523] = 1; /* 521: pointer.struct.ec_key_st */
    	em[524] = 277; em[525] = 0; 
    args_addr->arg_entity_index[0] = 15;
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

