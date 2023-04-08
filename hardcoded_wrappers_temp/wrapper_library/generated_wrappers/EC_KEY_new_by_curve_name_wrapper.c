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
    em[0] = 1; em[1] = 8; em[2] = 1; /* 0: pointer.struct.ec_extra_data_st */
    	em[3] = 5; em[4] = 0; 
    em[5] = 0; em[6] = 40; em[7] = 5; /* 5: struct.ec_extra_data_st */
    	em[8] = 18; em[9] = 0; 
    	em[10] = 23; em[11] = 8; 
    	em[12] = 26; em[13] = 16; 
    	em[14] = 29; em[15] = 24; 
    	em[16] = 29; em[17] = 32; 
    em[18] = 1; em[19] = 8; em[20] = 1; /* 18: pointer.struct.ec_extra_data_st */
    	em[21] = 5; em[22] = 0; 
    em[23] = 0; em[24] = 8; em[25] = 0; /* 23: pointer.void */
    em[26] = 8884097; em[27] = 8; em[28] = 0; /* 26: pointer.func */
    em[29] = 8884097; em[30] = 8; em[31] = 0; /* 29: pointer.func */
    em[32] = 0; em[33] = 24; em[34] = 1; /* 32: struct.bignum_st */
    	em[35] = 37; em[36] = 0; 
    em[37] = 8884099; em[38] = 8; em[39] = 2; /* 37: pointer_to_array_of_pointers_to_stack */
    	em[40] = 44; em[41] = 0; 
    	em[42] = 47; em[43] = 12; 
    em[44] = 0; em[45] = 8; em[46] = 0; /* 44: long unsigned int */
    em[47] = 0; em[48] = 4; em[49] = 0; /* 47: int */
    em[50] = 1; em[51] = 8; em[52] = 1; /* 50: pointer.struct.bignum_st */
    	em[53] = 32; em[54] = 0; 
    em[55] = 8884097; em[56] = 8; em[57] = 0; /* 55: pointer.func */
    em[58] = 1; em[59] = 8; em[60] = 1; /* 58: pointer.struct.ec_extra_data_st */
    	em[61] = 63; em[62] = 0; 
    em[63] = 0; em[64] = 40; em[65] = 5; /* 63: struct.ec_extra_data_st */
    	em[66] = 58; em[67] = 0; 
    	em[68] = 23; em[69] = 8; 
    	em[70] = 26; em[71] = 16; 
    	em[72] = 29; em[73] = 24; 
    	em[74] = 29; em[75] = 32; 
    em[76] = 1; em[77] = 8; em[78] = 1; /* 76: pointer.struct.ec_extra_data_st */
    	em[79] = 63; em[80] = 0; 
    em[81] = 1; em[82] = 8; em[83] = 1; /* 81: pointer.unsigned char */
    	em[84] = 86; em[85] = 0; 
    em[86] = 0; em[87] = 1; em[88] = 0; /* 86: unsigned char */
    em[89] = 0; em[90] = 24; em[91] = 1; /* 89: struct.bignum_st */
    	em[92] = 94; em[93] = 0; 
    em[94] = 8884099; em[95] = 8; em[96] = 2; /* 94: pointer_to_array_of_pointers_to_stack */
    	em[97] = 44; em[98] = 0; 
    	em[99] = 47; em[100] = 12; 
    em[101] = 8884097; em[102] = 8; em[103] = 0; /* 101: pointer.func */
    em[104] = 8884097; em[105] = 8; em[106] = 0; /* 104: pointer.func */
    em[107] = 8884097; em[108] = 8; em[109] = 0; /* 107: pointer.func */
    em[110] = 8884097; em[111] = 8; em[112] = 0; /* 110: pointer.func */
    em[113] = 8884097; em[114] = 8; em[115] = 0; /* 113: pointer.func */
    em[116] = 8884097; em[117] = 8; em[118] = 0; /* 116: pointer.func */
    em[119] = 8884097; em[120] = 8; em[121] = 0; /* 119: pointer.func */
    em[122] = 8884097; em[123] = 8; em[124] = 0; /* 122: pointer.func */
    em[125] = 0; em[126] = 24; em[127] = 1; /* 125: struct.bignum_st */
    	em[128] = 130; em[129] = 0; 
    em[130] = 8884099; em[131] = 8; em[132] = 2; /* 130: pointer_to_array_of_pointers_to_stack */
    	em[133] = 44; em[134] = 0; 
    	em[135] = 47; em[136] = 12; 
    em[137] = 8884097; em[138] = 8; em[139] = 0; /* 137: pointer.func */
    em[140] = 8884097; em[141] = 8; em[142] = 0; /* 140: pointer.func */
    em[143] = 8884097; em[144] = 8; em[145] = 0; /* 143: pointer.func */
    em[146] = 8884097; em[147] = 8; em[148] = 0; /* 146: pointer.func */
    em[149] = 0; em[150] = 304; em[151] = 37; /* 149: struct.ec_method_st */
    	em[152] = 226; em[153] = 8; 
    	em[154] = 229; em[155] = 16; 
    	em[156] = 229; em[157] = 24; 
    	em[158] = 232; em[159] = 32; 
    	em[160] = 235; em[161] = 40; 
    	em[162] = 238; em[163] = 48; 
    	em[164] = 241; em[165] = 56; 
    	em[166] = 244; em[167] = 64; 
    	em[168] = 247; em[169] = 72; 
    	em[170] = 250; em[171] = 80; 
    	em[172] = 250; em[173] = 88; 
    	em[174] = 253; em[175] = 96; 
    	em[176] = 256; em[177] = 104; 
    	em[178] = 259; em[179] = 112; 
    	em[180] = 262; em[181] = 120; 
    	em[182] = 265; em[183] = 128; 
    	em[184] = 268; em[185] = 136; 
    	em[186] = 146; em[187] = 144; 
    	em[188] = 271; em[189] = 152; 
    	em[190] = 274; em[191] = 160; 
    	em[192] = 277; em[193] = 168; 
    	em[194] = 280; em[195] = 176; 
    	em[196] = 283; em[197] = 184; 
    	em[198] = 286; em[199] = 192; 
    	em[200] = 289; em[201] = 200; 
    	em[202] = 292; em[203] = 208; 
    	em[204] = 283; em[205] = 216; 
    	em[206] = 295; em[207] = 224; 
    	em[208] = 298; em[209] = 232; 
    	em[210] = 301; em[211] = 240; 
    	em[212] = 241; em[213] = 248; 
    	em[214] = 304; em[215] = 256; 
    	em[216] = 307; em[217] = 264; 
    	em[218] = 304; em[219] = 272; 
    	em[220] = 307; em[221] = 280; 
    	em[222] = 307; em[223] = 288; 
    	em[224] = 310; em[225] = 296; 
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
    em[283] = 8884097; em[284] = 8; em[285] = 0; /* 283: pointer.func */
    em[286] = 8884097; em[287] = 8; em[288] = 0; /* 286: pointer.func */
    em[289] = 8884097; em[290] = 8; em[291] = 0; /* 289: pointer.func */
    em[292] = 8884097; em[293] = 8; em[294] = 0; /* 292: pointer.func */
    em[295] = 8884097; em[296] = 8; em[297] = 0; /* 295: pointer.func */
    em[298] = 8884097; em[299] = 8; em[300] = 0; /* 298: pointer.func */
    em[301] = 8884097; em[302] = 8; em[303] = 0; /* 301: pointer.func */
    em[304] = 8884097; em[305] = 8; em[306] = 0; /* 304: pointer.func */
    em[307] = 8884097; em[308] = 8; em[309] = 0; /* 307: pointer.func */
    em[310] = 8884097; em[311] = 8; em[312] = 0; /* 310: pointer.func */
    em[313] = 0; em[314] = 88; em[315] = 4; /* 313: struct.ec_point_st */
    	em[316] = 324; em[317] = 0; 
    	em[318] = 125; em[319] = 8; 
    	em[320] = 125; em[321] = 32; 
    	em[322] = 125; em[323] = 56; 
    em[324] = 1; em[325] = 8; em[326] = 1; /* 324: pointer.struct.ec_method_st */
    	em[327] = 329; em[328] = 0; 
    em[329] = 0; em[330] = 304; em[331] = 37; /* 329: struct.ec_method_st */
    	em[332] = 406; em[333] = 8; 
    	em[334] = 140; em[335] = 16; 
    	em[336] = 140; em[337] = 24; 
    	em[338] = 409; em[339] = 32; 
    	em[340] = 412; em[341] = 40; 
    	em[342] = 415; em[343] = 48; 
    	em[344] = 418; em[345] = 56; 
    	em[346] = 421; em[347] = 64; 
    	em[348] = 424; em[349] = 72; 
    	em[350] = 427; em[351] = 80; 
    	em[352] = 427; em[353] = 88; 
    	em[354] = 430; em[355] = 96; 
    	em[356] = 433; em[357] = 104; 
    	em[358] = 436; em[359] = 112; 
    	em[360] = 439; em[361] = 120; 
    	em[362] = 442; em[363] = 128; 
    	em[364] = 445; em[365] = 136; 
    	em[366] = 448; em[367] = 144; 
    	em[368] = 451; em[369] = 152; 
    	em[370] = 143; em[371] = 160; 
    	em[372] = 137; em[373] = 168; 
    	em[374] = 454; em[375] = 176; 
    	em[376] = 457; em[377] = 184; 
    	em[378] = 122; em[379] = 192; 
    	em[380] = 119; em[381] = 200; 
    	em[382] = 116; em[383] = 208; 
    	em[384] = 457; em[385] = 216; 
    	em[386] = 113; em[387] = 224; 
    	em[388] = 110; em[389] = 232; 
    	em[390] = 107; em[391] = 240; 
    	em[392] = 418; em[393] = 248; 
    	em[394] = 104; em[395] = 256; 
    	em[396] = 460; em[397] = 264; 
    	em[398] = 104; em[399] = 272; 
    	em[400] = 460; em[401] = 280; 
    	em[402] = 460; em[403] = 288; 
    	em[404] = 101; em[405] = 296; 
    em[406] = 8884097; em[407] = 8; em[408] = 0; /* 406: pointer.func */
    em[409] = 8884097; em[410] = 8; em[411] = 0; /* 409: pointer.func */
    em[412] = 8884097; em[413] = 8; em[414] = 0; /* 412: pointer.func */
    em[415] = 8884097; em[416] = 8; em[417] = 0; /* 415: pointer.func */
    em[418] = 8884097; em[419] = 8; em[420] = 0; /* 418: pointer.func */
    em[421] = 8884097; em[422] = 8; em[423] = 0; /* 421: pointer.func */
    em[424] = 8884097; em[425] = 8; em[426] = 0; /* 424: pointer.func */
    em[427] = 8884097; em[428] = 8; em[429] = 0; /* 427: pointer.func */
    em[430] = 8884097; em[431] = 8; em[432] = 0; /* 430: pointer.func */
    em[433] = 8884097; em[434] = 8; em[435] = 0; /* 433: pointer.func */
    em[436] = 8884097; em[437] = 8; em[438] = 0; /* 436: pointer.func */
    em[439] = 8884097; em[440] = 8; em[441] = 0; /* 439: pointer.func */
    em[442] = 8884097; em[443] = 8; em[444] = 0; /* 442: pointer.func */
    em[445] = 8884097; em[446] = 8; em[447] = 0; /* 445: pointer.func */
    em[448] = 8884097; em[449] = 8; em[450] = 0; /* 448: pointer.func */
    em[451] = 8884097; em[452] = 8; em[453] = 0; /* 451: pointer.func */
    em[454] = 8884097; em[455] = 8; em[456] = 0; /* 454: pointer.func */
    em[457] = 8884097; em[458] = 8; em[459] = 0; /* 457: pointer.func */
    em[460] = 8884097; em[461] = 8; em[462] = 0; /* 460: pointer.func */
    em[463] = 1; em[464] = 8; em[465] = 1; /* 463: pointer.struct.ec_key_st */
    	em[466] = 468; em[467] = 0; 
    em[468] = 0; em[469] = 56; em[470] = 4; /* 468: struct.ec_key_st */
    	em[471] = 479; em[472] = 8; 
    	em[473] = 521; em[474] = 16; 
    	em[475] = 50; em[476] = 24; 
    	em[477] = 0; em[478] = 48; 
    em[479] = 1; em[480] = 8; em[481] = 1; /* 479: pointer.struct.ec_group_st */
    	em[482] = 484; em[483] = 0; 
    em[484] = 0; em[485] = 232; em[486] = 12; /* 484: struct.ec_group_st */
    	em[487] = 511; em[488] = 0; 
    	em[489] = 516; em[490] = 8; 
    	em[491] = 89; em[492] = 16; 
    	em[493] = 89; em[494] = 40; 
    	em[495] = 81; em[496] = 80; 
    	em[497] = 76; em[498] = 96; 
    	em[499] = 89; em[500] = 104; 
    	em[501] = 89; em[502] = 152; 
    	em[503] = 89; em[504] = 176; 
    	em[505] = 23; em[506] = 208; 
    	em[507] = 23; em[508] = 216; 
    	em[509] = 55; em[510] = 224; 
    em[511] = 1; em[512] = 8; em[513] = 1; /* 511: pointer.struct.ec_method_st */
    	em[514] = 149; em[515] = 0; 
    em[516] = 1; em[517] = 8; em[518] = 1; /* 516: pointer.struct.ec_point_st */
    	em[519] = 313; em[520] = 0; 
    em[521] = 1; em[522] = 8; em[523] = 1; /* 521: pointer.struct.ec_point_st */
    	em[524] = 313; em[525] = 0; 
    args_addr->arg_entity_index[0] = 47;
    args_addr->ret_entity_index = 463;
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

