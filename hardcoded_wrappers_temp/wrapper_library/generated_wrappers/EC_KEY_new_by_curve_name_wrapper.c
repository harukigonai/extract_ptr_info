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
    em[27] = 8884097; em[28] = 8; em[29] = 0; /* 27: pointer.func */
    em[30] = 1; em[31] = 8; em[32] = 1; /* 30: pointer.struct.ec_extra_data_st */
    	em[33] = 35; em[34] = 0; 
    em[35] = 0; em[36] = 40; em[37] = 5; /* 35: struct.ec_extra_data_st */
    	em[38] = 30; em[39] = 0; 
    	em[40] = 18; em[41] = 8; 
    	em[42] = 21; em[43] = 16; 
    	em[44] = 24; em[45] = 24; 
    	em[46] = 24; em[47] = 32; 
    em[48] = 8884097; em[49] = 8; em[50] = 0; /* 48: pointer.func */
    em[51] = 8884097; em[52] = 8; em[53] = 0; /* 51: pointer.func */
    em[54] = 8884097; em[55] = 8; em[56] = 0; /* 54: pointer.func */
    em[57] = 8884097; em[58] = 8; em[59] = 0; /* 57: pointer.func */
    em[60] = 8884097; em[61] = 8; em[62] = 0; /* 60: pointer.func */
    em[63] = 8884097; em[64] = 8; em[65] = 0; /* 63: pointer.func */
    em[66] = 8884097; em[67] = 8; em[68] = 0; /* 66: pointer.func */
    em[69] = 8884097; em[70] = 8; em[71] = 0; /* 69: pointer.func */
    em[72] = 0; em[73] = 24; em[74] = 1; /* 72: struct.bignum_st */
    	em[75] = 77; em[76] = 0; 
    em[77] = 8884099; em[78] = 8; em[79] = 2; /* 77: pointer_to_array_of_pointers_to_stack */
    	em[80] = 84; em[81] = 0; 
    	em[82] = 87; em[83] = 12; 
    em[84] = 0; em[85] = 8; em[86] = 0; /* 84: long unsigned int */
    em[87] = 0; em[88] = 4; em[89] = 0; /* 87: int */
    em[90] = 8884097; em[91] = 8; em[92] = 0; /* 90: pointer.func */
    em[93] = 8884097; em[94] = 8; em[95] = 0; /* 93: pointer.func */
    em[96] = 8884097; em[97] = 8; em[98] = 0; /* 96: pointer.func */
    em[99] = 8884097; em[100] = 8; em[101] = 0; /* 99: pointer.func */
    em[102] = 1; em[103] = 8; em[104] = 1; /* 102: pointer.struct.ec_point_st */
    	em[105] = 107; em[106] = 0; 
    em[107] = 0; em[108] = 88; em[109] = 4; /* 107: struct.ec_point_st */
    	em[110] = 118; em[111] = 0; 
    	em[112] = 72; em[113] = 8; 
    	em[114] = 72; em[115] = 32; 
    	em[116] = 72; em[117] = 56; 
    em[118] = 1; em[119] = 8; em[120] = 1; /* 118: pointer.struct.ec_method_st */
    	em[121] = 123; em[122] = 0; 
    em[123] = 0; em[124] = 304; em[125] = 37; /* 123: struct.ec_method_st */
    	em[126] = 200; em[127] = 8; 
    	em[128] = 203; em[129] = 16; 
    	em[130] = 203; em[131] = 24; 
    	em[132] = 206; em[133] = 32; 
    	em[134] = 209; em[135] = 40; 
    	em[136] = 212; em[137] = 48; 
    	em[138] = 215; em[139] = 56; 
    	em[140] = 218; em[141] = 64; 
    	em[142] = 221; em[143] = 72; 
    	em[144] = 224; em[145] = 80; 
    	em[146] = 224; em[147] = 88; 
    	em[148] = 227; em[149] = 96; 
    	em[150] = 230; em[151] = 104; 
    	em[152] = 233; em[153] = 112; 
    	em[154] = 236; em[155] = 120; 
    	em[156] = 239; em[157] = 128; 
    	em[158] = 242; em[159] = 136; 
    	em[160] = 245; em[161] = 144; 
    	em[162] = 248; em[163] = 152; 
    	em[164] = 251; em[165] = 160; 
    	em[166] = 90; em[167] = 168; 
    	em[168] = 254; em[169] = 176; 
    	em[170] = 257; em[171] = 184; 
    	em[172] = 69; em[173] = 192; 
    	em[174] = 66; em[175] = 200; 
    	em[176] = 63; em[177] = 208; 
    	em[178] = 257; em[179] = 216; 
    	em[180] = 60; em[181] = 224; 
    	em[182] = 57; em[183] = 232; 
    	em[184] = 54; em[185] = 240; 
    	em[186] = 215; em[187] = 248; 
    	em[188] = 51; em[189] = 256; 
    	em[190] = 260; em[191] = 264; 
    	em[192] = 51; em[193] = 272; 
    	em[194] = 260; em[195] = 280; 
    	em[196] = 260; em[197] = 288; 
    	em[198] = 48; em[199] = 296; 
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
    em[236] = 8884097; em[237] = 8; em[238] = 0; /* 236: pointer.func */
    em[239] = 8884097; em[240] = 8; em[241] = 0; /* 239: pointer.func */
    em[242] = 8884097; em[243] = 8; em[244] = 0; /* 242: pointer.func */
    em[245] = 8884097; em[246] = 8; em[247] = 0; /* 245: pointer.func */
    em[248] = 8884097; em[249] = 8; em[250] = 0; /* 248: pointer.func */
    em[251] = 8884097; em[252] = 8; em[253] = 0; /* 251: pointer.func */
    em[254] = 8884097; em[255] = 8; em[256] = 0; /* 254: pointer.func */
    em[257] = 8884097; em[258] = 8; em[259] = 0; /* 257: pointer.func */
    em[260] = 8884097; em[261] = 8; em[262] = 0; /* 260: pointer.func */
    em[263] = 1; em[264] = 8; em[265] = 1; /* 263: pointer.unsigned char */
    	em[266] = 268; em[267] = 0; 
    em[268] = 0; em[269] = 1; em[270] = 0; /* 268: unsigned char */
    em[271] = 8884097; em[272] = 8; em[273] = 0; /* 271: pointer.func */
    em[274] = 8884097; em[275] = 8; em[276] = 0; /* 274: pointer.func */
    em[277] = 8884097; em[278] = 8; em[279] = 0; /* 277: pointer.func */
    em[280] = 1; em[281] = 8; em[282] = 1; /* 280: pointer.struct.ec_extra_data_st */
    	em[283] = 0; em[284] = 0; 
    em[285] = 8884097; em[286] = 8; em[287] = 0; /* 285: pointer.func */
    em[288] = 8884099; em[289] = 8; em[290] = 2; /* 288: pointer_to_array_of_pointers_to_stack */
    	em[291] = 84; em[292] = 0; 
    	em[293] = 87; em[294] = 12; 
    em[295] = 8884097; em[296] = 8; em[297] = 0; /* 295: pointer.func */
    em[298] = 8884097; em[299] = 8; em[300] = 0; /* 298: pointer.func */
    em[301] = 8884097; em[302] = 8; em[303] = 0; /* 301: pointer.func */
    em[304] = 8884097; em[305] = 8; em[306] = 0; /* 304: pointer.func */
    em[307] = 8884097; em[308] = 8; em[309] = 0; /* 307: pointer.func */
    em[310] = 0; em[311] = 24; em[312] = 1; /* 310: struct.bignum_st */
    	em[313] = 288; em[314] = 0; 
    em[315] = 8884097; em[316] = 8; em[317] = 0; /* 315: pointer.func */
    em[318] = 0; em[319] = 24; em[320] = 1; /* 318: struct.bignum_st */
    	em[321] = 323; em[322] = 0; 
    em[323] = 8884099; em[324] = 8; em[325] = 2; /* 323: pointer_to_array_of_pointers_to_stack */
    	em[326] = 84; em[327] = 0; 
    	em[328] = 87; em[329] = 12; 
    em[330] = 8884097; em[331] = 8; em[332] = 0; /* 330: pointer.func */
    em[333] = 1; em[334] = 8; em[335] = 1; /* 333: pointer.struct.ec_key_st */
    	em[336] = 338; em[337] = 0; 
    em[338] = 0; em[339] = 56; em[340] = 4; /* 338: struct.ec_key_st */
    	em[341] = 349; em[342] = 8; 
    	em[343] = 516; em[344] = 16; 
    	em[345] = 521; em[346] = 24; 
    	em[347] = 280; em[348] = 48; 
    em[349] = 1; em[350] = 8; em[351] = 1; /* 349: pointer.struct.ec_group_st */
    	em[352] = 354; em[353] = 0; 
    em[354] = 0; em[355] = 232; em[356] = 12; /* 354: struct.ec_group_st */
    	em[357] = 381; em[358] = 0; 
    	em[359] = 102; em[360] = 8; 
    	em[361] = 318; em[362] = 16; 
    	em[363] = 318; em[364] = 40; 
    	em[365] = 263; em[366] = 80; 
    	em[367] = 511; em[368] = 96; 
    	em[369] = 318; em[370] = 104; 
    	em[371] = 318; em[372] = 152; 
    	em[373] = 318; em[374] = 176; 
    	em[375] = 18; em[376] = 208; 
    	em[377] = 18; em[378] = 216; 
    	em[379] = 27; em[380] = 224; 
    em[381] = 1; em[382] = 8; em[383] = 1; /* 381: pointer.struct.ec_method_st */
    	em[384] = 386; em[385] = 0; 
    em[386] = 0; em[387] = 304; em[388] = 37; /* 386: struct.ec_method_st */
    	em[389] = 99; em[390] = 8; 
    	em[391] = 463; em[392] = 16; 
    	em[393] = 463; em[394] = 24; 
    	em[395] = 304; em[396] = 32; 
    	em[397] = 96; em[398] = 40; 
    	em[399] = 285; em[400] = 48; 
    	em[401] = 466; em[402] = 56; 
    	em[403] = 274; em[404] = 64; 
    	em[405] = 298; em[406] = 72; 
    	em[407] = 295; em[408] = 80; 
    	em[409] = 295; em[410] = 88; 
    	em[411] = 469; em[412] = 96; 
    	em[413] = 472; em[414] = 104; 
    	em[415] = 475; em[416] = 112; 
    	em[417] = 330; em[418] = 120; 
    	em[419] = 478; em[420] = 128; 
    	em[421] = 271; em[422] = 136; 
    	em[423] = 481; em[424] = 144; 
    	em[425] = 93; em[426] = 152; 
    	em[427] = 277; em[428] = 160; 
    	em[429] = 315; em[430] = 168; 
    	em[431] = 307; em[432] = 176; 
    	em[433] = 484; em[434] = 184; 
    	em[435] = 301; em[436] = 192; 
    	em[437] = 487; em[438] = 200; 
    	em[439] = 490; em[440] = 208; 
    	em[441] = 484; em[442] = 216; 
    	em[443] = 493; em[444] = 224; 
    	em[445] = 496; em[446] = 232; 
    	em[447] = 499; em[448] = 240; 
    	em[449] = 466; em[450] = 248; 
    	em[451] = 502; em[452] = 256; 
    	em[453] = 505; em[454] = 264; 
    	em[455] = 502; em[456] = 272; 
    	em[457] = 505; em[458] = 280; 
    	em[459] = 505; em[460] = 288; 
    	em[461] = 508; em[462] = 296; 
    em[463] = 8884097; em[464] = 8; em[465] = 0; /* 463: pointer.func */
    em[466] = 8884097; em[467] = 8; em[468] = 0; /* 466: pointer.func */
    em[469] = 8884097; em[470] = 8; em[471] = 0; /* 469: pointer.func */
    em[472] = 8884097; em[473] = 8; em[474] = 0; /* 472: pointer.func */
    em[475] = 8884097; em[476] = 8; em[477] = 0; /* 475: pointer.func */
    em[478] = 8884097; em[479] = 8; em[480] = 0; /* 478: pointer.func */
    em[481] = 8884097; em[482] = 8; em[483] = 0; /* 481: pointer.func */
    em[484] = 8884097; em[485] = 8; em[486] = 0; /* 484: pointer.func */
    em[487] = 8884097; em[488] = 8; em[489] = 0; /* 487: pointer.func */
    em[490] = 8884097; em[491] = 8; em[492] = 0; /* 490: pointer.func */
    em[493] = 8884097; em[494] = 8; em[495] = 0; /* 493: pointer.func */
    em[496] = 8884097; em[497] = 8; em[498] = 0; /* 496: pointer.func */
    em[499] = 8884097; em[500] = 8; em[501] = 0; /* 499: pointer.func */
    em[502] = 8884097; em[503] = 8; em[504] = 0; /* 502: pointer.func */
    em[505] = 8884097; em[506] = 8; em[507] = 0; /* 505: pointer.func */
    em[508] = 8884097; em[509] = 8; em[510] = 0; /* 508: pointer.func */
    em[511] = 1; em[512] = 8; em[513] = 1; /* 511: pointer.struct.ec_extra_data_st */
    	em[514] = 35; em[515] = 0; 
    em[516] = 1; em[517] = 8; em[518] = 1; /* 516: pointer.struct.ec_point_st */
    	em[519] = 107; em[520] = 0; 
    em[521] = 1; em[522] = 8; em[523] = 1; /* 521: pointer.struct.bignum_st */
    	em[524] = 310; em[525] = 0; 
    args_addr->arg_entity_index[0] = 87;
    args_addr->ret_entity_index = 333;
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

