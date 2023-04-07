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
    em[27] = 1; em[28] = 8; em[29] = 1; /* 27: pointer.struct.ec_extra_data_st */
    	em[30] = 0; em[31] = 0; 
    em[32] = 0; em[33] = 24; em[34] = 1; /* 32: struct.bignum_st */
    	em[35] = 37; em[36] = 0; 
    em[37] = 8884099; em[38] = 8; em[39] = 2; /* 37: pointer_to_array_of_pointers_to_stack */
    	em[40] = 44; em[41] = 0; 
    	em[42] = 47; em[43] = 12; 
    em[44] = 0; em[45] = 8; em[46] = 0; /* 44: long unsigned int */
    em[47] = 0; em[48] = 4; em[49] = 0; /* 47: int */
    em[50] = 1; em[51] = 8; em[52] = 1; /* 50: pointer.struct.bignum_st */
    	em[53] = 32; em[54] = 0; 
    em[55] = 1; em[56] = 8; em[57] = 1; /* 55: pointer.struct.ec_extra_data_st */
    	em[58] = 60; em[59] = 0; 
    em[60] = 0; em[61] = 40; em[62] = 5; /* 60: struct.ec_extra_data_st */
    	em[63] = 55; em[64] = 0; 
    	em[65] = 18; em[66] = 8; 
    	em[67] = 21; em[68] = 16; 
    	em[69] = 24; em[70] = 24; 
    	em[71] = 24; em[72] = 32; 
    em[73] = 1; em[74] = 8; em[75] = 1; /* 73: pointer.unsigned char */
    	em[76] = 78; em[77] = 0; 
    em[78] = 0; em[79] = 1; em[80] = 0; /* 78: unsigned char */
    em[81] = 0; em[82] = 24; em[83] = 1; /* 81: struct.bignum_st */
    	em[84] = 86; em[85] = 0; 
    em[86] = 8884099; em[87] = 8; em[88] = 2; /* 86: pointer_to_array_of_pointers_to_stack */
    	em[89] = 44; em[90] = 0; 
    	em[91] = 47; em[92] = 12; 
    em[93] = 8884097; em[94] = 8; em[95] = 0; /* 93: pointer.func */
    em[96] = 8884097; em[97] = 8; em[98] = 0; /* 96: pointer.func */
    em[99] = 8884097; em[100] = 8; em[101] = 0; /* 99: pointer.func */
    em[102] = 8884097; em[103] = 8; em[104] = 0; /* 102: pointer.func */
    em[105] = 8884097; em[106] = 8; em[107] = 0; /* 105: pointer.func */
    em[108] = 0; em[109] = 24; em[110] = 1; /* 108: struct.bignum_st */
    	em[111] = 113; em[112] = 0; 
    em[113] = 8884099; em[114] = 8; em[115] = 2; /* 113: pointer_to_array_of_pointers_to_stack */
    	em[116] = 44; em[117] = 0; 
    	em[118] = 47; em[119] = 12; 
    em[120] = 8884097; em[121] = 8; em[122] = 0; /* 120: pointer.func */
    em[123] = 8884097; em[124] = 8; em[125] = 0; /* 123: pointer.func */
    em[126] = 0; em[127] = 304; em[128] = 37; /* 126: struct.ec_method_st */
    	em[129] = 203; em[130] = 8; 
    	em[131] = 206; em[132] = 16; 
    	em[133] = 206; em[134] = 24; 
    	em[135] = 209; em[136] = 32; 
    	em[137] = 212; em[138] = 40; 
    	em[139] = 215; em[140] = 48; 
    	em[141] = 218; em[142] = 56; 
    	em[143] = 221; em[144] = 64; 
    	em[145] = 224; em[146] = 72; 
    	em[147] = 227; em[148] = 80; 
    	em[149] = 227; em[150] = 88; 
    	em[151] = 230; em[152] = 96; 
    	em[153] = 233; em[154] = 104; 
    	em[155] = 236; em[156] = 112; 
    	em[157] = 239; em[158] = 120; 
    	em[159] = 242; em[160] = 128; 
    	em[161] = 245; em[162] = 136; 
    	em[163] = 248; em[164] = 144; 
    	em[165] = 251; em[166] = 152; 
    	em[167] = 254; em[168] = 160; 
    	em[169] = 257; em[170] = 168; 
    	em[171] = 260; em[172] = 176; 
    	em[173] = 263; em[174] = 184; 
    	em[175] = 123; em[176] = 192; 
    	em[177] = 266; em[178] = 200; 
    	em[179] = 269; em[180] = 208; 
    	em[181] = 263; em[182] = 216; 
    	em[183] = 272; em[184] = 224; 
    	em[185] = 275; em[186] = 232; 
    	em[187] = 278; em[188] = 240; 
    	em[189] = 218; em[190] = 248; 
    	em[191] = 281; em[192] = 256; 
    	em[193] = 284; em[194] = 264; 
    	em[195] = 281; em[196] = 272; 
    	em[197] = 284; em[198] = 280; 
    	em[199] = 284; em[200] = 288; 
    	em[201] = 287; em[202] = 296; 
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
    em[263] = 8884097; em[264] = 8; em[265] = 0; /* 263: pointer.func */
    em[266] = 8884097; em[267] = 8; em[268] = 0; /* 266: pointer.func */
    em[269] = 8884097; em[270] = 8; em[271] = 0; /* 269: pointer.func */
    em[272] = 8884097; em[273] = 8; em[274] = 0; /* 272: pointer.func */
    em[275] = 8884097; em[276] = 8; em[277] = 0; /* 275: pointer.func */
    em[278] = 8884097; em[279] = 8; em[280] = 0; /* 278: pointer.func */
    em[281] = 8884097; em[282] = 8; em[283] = 0; /* 281: pointer.func */
    em[284] = 8884097; em[285] = 8; em[286] = 0; /* 284: pointer.func */
    em[287] = 8884097; em[288] = 8; em[289] = 0; /* 287: pointer.func */
    em[290] = 8884097; em[291] = 8; em[292] = 0; /* 290: pointer.func */
    em[293] = 1; em[294] = 8; em[295] = 1; /* 293: pointer.struct.ec_method_st */
    	em[296] = 126; em[297] = 0; 
    em[298] = 8884097; em[299] = 8; em[300] = 0; /* 298: pointer.func */
    em[301] = 8884097; em[302] = 8; em[303] = 0; /* 301: pointer.func */
    em[304] = 1; em[305] = 8; em[306] = 1; /* 304: pointer.struct.ec_extra_data_st */
    	em[307] = 60; em[308] = 0; 
    em[309] = 8884097; em[310] = 8; em[311] = 0; /* 309: pointer.func */
    em[312] = 8884097; em[313] = 8; em[314] = 0; /* 312: pointer.func */
    em[315] = 8884097; em[316] = 8; em[317] = 0; /* 315: pointer.func */
    em[318] = 1; em[319] = 8; em[320] = 1; /* 318: pointer.struct.ec_group_st */
    	em[321] = 323; em[322] = 0; 
    em[323] = 0; em[324] = 232; em[325] = 12; /* 323: struct.ec_group_st */
    	em[326] = 293; em[327] = 0; 
    	em[328] = 350; em[329] = 8; 
    	em[330] = 81; em[331] = 16; 
    	em[332] = 81; em[333] = 40; 
    	em[334] = 73; em[335] = 80; 
    	em[336] = 304; em[337] = 96; 
    	em[338] = 81; em[339] = 104; 
    	em[340] = 81; em[341] = 152; 
    	em[342] = 81; em[343] = 176; 
    	em[344] = 18; em[345] = 208; 
    	em[346] = 18; em[347] = 216; 
    	em[348] = 315; em[349] = 224; 
    em[350] = 1; em[351] = 8; em[352] = 1; /* 350: pointer.struct.ec_point_st */
    	em[353] = 355; em[354] = 0; 
    em[355] = 0; em[356] = 88; em[357] = 4; /* 355: struct.ec_point_st */
    	em[358] = 366; em[359] = 0; 
    	em[360] = 108; em[361] = 8; 
    	em[362] = 108; em[363] = 32; 
    	em[364] = 108; em[365] = 56; 
    em[366] = 1; em[367] = 8; em[368] = 1; /* 366: pointer.struct.ec_method_st */
    	em[369] = 371; em[370] = 0; 
    em[371] = 0; em[372] = 304; em[373] = 37; /* 371: struct.ec_method_st */
    	em[374] = 448; em[375] = 8; 
    	em[376] = 451; em[377] = 16; 
    	em[378] = 451; em[379] = 24; 
    	em[380] = 454; em[381] = 32; 
    	em[382] = 457; em[383] = 40; 
    	em[384] = 460; em[385] = 48; 
    	em[386] = 463; em[387] = 56; 
    	em[388] = 466; em[389] = 64; 
    	em[390] = 469; em[391] = 72; 
    	em[392] = 472; em[393] = 80; 
    	em[394] = 472; em[395] = 88; 
    	em[396] = 475; em[397] = 96; 
    	em[398] = 478; em[399] = 104; 
    	em[400] = 481; em[401] = 112; 
    	em[402] = 484; em[403] = 120; 
    	em[404] = 298; em[405] = 128; 
    	em[406] = 487; em[407] = 136; 
    	em[408] = 490; em[409] = 144; 
    	em[410] = 309; em[411] = 152; 
    	em[412] = 493; em[413] = 160; 
    	em[414] = 120; em[415] = 168; 
    	em[416] = 496; em[417] = 176; 
    	em[418] = 499; em[419] = 184; 
    	em[420] = 312; em[421] = 192; 
    	em[422] = 105; em[423] = 200; 
    	em[424] = 301; em[425] = 208; 
    	em[426] = 499; em[427] = 216; 
    	em[428] = 102; em[429] = 224; 
    	em[430] = 99; em[431] = 232; 
    	em[432] = 290; em[433] = 240; 
    	em[434] = 463; em[435] = 248; 
    	em[436] = 96; em[437] = 256; 
    	em[438] = 502; em[439] = 264; 
    	em[440] = 96; em[441] = 272; 
    	em[442] = 502; em[443] = 280; 
    	em[444] = 502; em[445] = 288; 
    	em[446] = 93; em[447] = 296; 
    em[448] = 8884097; em[449] = 8; em[450] = 0; /* 448: pointer.func */
    em[451] = 8884097; em[452] = 8; em[453] = 0; /* 451: pointer.func */
    em[454] = 8884097; em[455] = 8; em[456] = 0; /* 454: pointer.func */
    em[457] = 8884097; em[458] = 8; em[459] = 0; /* 457: pointer.func */
    em[460] = 8884097; em[461] = 8; em[462] = 0; /* 460: pointer.func */
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
    em[505] = 1; em[506] = 8; em[507] = 1; /* 505: pointer.struct.ec_key_st */
    	em[508] = 510; em[509] = 0; 
    em[510] = 0; em[511] = 56; em[512] = 4; /* 510: struct.ec_key_st */
    	em[513] = 318; em[514] = 8; 
    	em[515] = 521; em[516] = 16; 
    	em[517] = 50; em[518] = 24; 
    	em[519] = 27; em[520] = 48; 
    em[521] = 1; em[522] = 8; em[523] = 1; /* 521: pointer.struct.ec_point_st */
    	em[524] = 355; em[525] = 0; 
    args_addr->arg_entity_index[0] = 47;
    args_addr->ret_entity_index = 505;
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

