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
    em[0] = 1; em[1] = 8; em[2] = 1; /* 0: pointer.struct.bignum_st */
    	em[3] = 5; em[4] = 0; 
    em[5] = 0; em[6] = 24; em[7] = 1; /* 5: struct.bignum_st */
    	em[8] = 10; em[9] = 0; 
    em[10] = 8884099; em[11] = 8; em[12] = 2; /* 10: pointer_to_array_of_pointers_to_stack */
    	em[13] = 17; em[14] = 0; 
    	em[15] = 20; em[16] = 12; 
    em[17] = 0; em[18] = 8; em[19] = 0; /* 17: long unsigned int */
    em[20] = 0; em[21] = 4; em[22] = 0; /* 20: int */
    em[23] = 1; em[24] = 8; em[25] = 1; /* 23: pointer.struct.ec_point_st */
    	em[26] = 28; em[27] = 0; 
    em[28] = 0; em[29] = 88; em[30] = 4; /* 28: struct.ec_point_st */
    	em[31] = 39; em[32] = 0; 
    	em[33] = 211; em[34] = 8; 
    	em[35] = 211; em[36] = 32; 
    	em[37] = 211; em[38] = 56; 
    em[39] = 1; em[40] = 8; em[41] = 1; /* 39: pointer.struct.ec_method_st */
    	em[42] = 44; em[43] = 0; 
    em[44] = 0; em[45] = 304; em[46] = 37; /* 44: struct.ec_method_st */
    	em[47] = 121; em[48] = 8; 
    	em[49] = 124; em[50] = 16; 
    	em[51] = 124; em[52] = 24; 
    	em[53] = 127; em[54] = 32; 
    	em[55] = 130; em[56] = 40; 
    	em[57] = 133; em[58] = 48; 
    	em[59] = 136; em[60] = 56; 
    	em[61] = 139; em[62] = 64; 
    	em[63] = 142; em[64] = 72; 
    	em[65] = 145; em[66] = 80; 
    	em[67] = 145; em[68] = 88; 
    	em[69] = 148; em[70] = 96; 
    	em[71] = 151; em[72] = 104; 
    	em[73] = 154; em[74] = 112; 
    	em[75] = 157; em[76] = 120; 
    	em[77] = 160; em[78] = 128; 
    	em[79] = 163; em[80] = 136; 
    	em[81] = 166; em[82] = 144; 
    	em[83] = 169; em[84] = 152; 
    	em[85] = 172; em[86] = 160; 
    	em[87] = 175; em[88] = 168; 
    	em[89] = 178; em[90] = 176; 
    	em[91] = 181; em[92] = 184; 
    	em[93] = 184; em[94] = 192; 
    	em[95] = 187; em[96] = 200; 
    	em[97] = 190; em[98] = 208; 
    	em[99] = 181; em[100] = 216; 
    	em[101] = 193; em[102] = 224; 
    	em[103] = 196; em[104] = 232; 
    	em[105] = 199; em[106] = 240; 
    	em[107] = 136; em[108] = 248; 
    	em[109] = 202; em[110] = 256; 
    	em[111] = 205; em[112] = 264; 
    	em[113] = 202; em[114] = 272; 
    	em[115] = 205; em[116] = 280; 
    	em[117] = 205; em[118] = 288; 
    	em[119] = 208; em[120] = 296; 
    em[121] = 8884097; em[122] = 8; em[123] = 0; /* 121: pointer.func */
    em[124] = 8884097; em[125] = 8; em[126] = 0; /* 124: pointer.func */
    em[127] = 8884097; em[128] = 8; em[129] = 0; /* 127: pointer.func */
    em[130] = 8884097; em[131] = 8; em[132] = 0; /* 130: pointer.func */
    em[133] = 8884097; em[134] = 8; em[135] = 0; /* 133: pointer.func */
    em[136] = 8884097; em[137] = 8; em[138] = 0; /* 136: pointer.func */
    em[139] = 8884097; em[140] = 8; em[141] = 0; /* 139: pointer.func */
    em[142] = 8884097; em[143] = 8; em[144] = 0; /* 142: pointer.func */
    em[145] = 8884097; em[146] = 8; em[147] = 0; /* 145: pointer.func */
    em[148] = 8884097; em[149] = 8; em[150] = 0; /* 148: pointer.func */
    em[151] = 8884097; em[152] = 8; em[153] = 0; /* 151: pointer.func */
    em[154] = 8884097; em[155] = 8; em[156] = 0; /* 154: pointer.func */
    em[157] = 8884097; em[158] = 8; em[159] = 0; /* 157: pointer.func */
    em[160] = 8884097; em[161] = 8; em[162] = 0; /* 160: pointer.func */
    em[163] = 8884097; em[164] = 8; em[165] = 0; /* 163: pointer.func */
    em[166] = 8884097; em[167] = 8; em[168] = 0; /* 166: pointer.func */
    em[169] = 8884097; em[170] = 8; em[171] = 0; /* 169: pointer.func */
    em[172] = 8884097; em[173] = 8; em[174] = 0; /* 172: pointer.func */
    em[175] = 8884097; em[176] = 8; em[177] = 0; /* 175: pointer.func */
    em[178] = 8884097; em[179] = 8; em[180] = 0; /* 178: pointer.func */
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
    em[211] = 0; em[212] = 24; em[213] = 1; /* 211: struct.bignum_st */
    	em[214] = 216; em[215] = 0; 
    em[216] = 8884099; em[217] = 8; em[218] = 2; /* 216: pointer_to_array_of_pointers_to_stack */
    	em[219] = 17; em[220] = 0; 
    	em[221] = 20; em[222] = 12; 
    em[223] = 8884097; em[224] = 8; em[225] = 0; /* 223: pointer.func */
    em[226] = 8884097; em[227] = 8; em[228] = 0; /* 226: pointer.func */
    em[229] = 0; em[230] = 8; em[231] = 0; /* 229: pointer.void */
    em[232] = 1; em[233] = 8; em[234] = 1; /* 232: pointer.struct.ec_extra_data_st */
    	em[235] = 237; em[236] = 0; 
    em[237] = 0; em[238] = 40; em[239] = 5; /* 237: struct.ec_extra_data_st */
    	em[240] = 232; em[241] = 0; 
    	em[242] = 229; em[243] = 8; 
    	em[244] = 226; em[245] = 16; 
    	em[246] = 250; em[247] = 24; 
    	em[248] = 250; em[249] = 32; 
    em[250] = 8884097; em[251] = 8; em[252] = 0; /* 250: pointer.func */
    em[253] = 1; em[254] = 8; em[255] = 1; /* 253: pointer.struct.ec_extra_data_st */
    	em[256] = 237; em[257] = 0; 
    em[258] = 1; em[259] = 8; em[260] = 1; /* 258: pointer.unsigned char */
    	em[261] = 263; em[262] = 0; 
    em[263] = 0; em[264] = 1; em[265] = 0; /* 263: unsigned char */
    em[266] = 0; em[267] = 24; em[268] = 1; /* 266: struct.bignum_st */
    	em[269] = 271; em[270] = 0; 
    em[271] = 8884099; em[272] = 8; em[273] = 2; /* 271: pointer_to_array_of_pointers_to_stack */
    	em[274] = 17; em[275] = 0; 
    	em[276] = 20; em[277] = 12; 
    em[278] = 0; em[279] = 56; em[280] = 4; /* 278: struct.ec_key_st */
    	em[281] = 289; em[282] = 8; 
    	em[283] = 23; em[284] = 16; 
    	em[285] = 0; em[286] = 24; 
    	em[287] = 498; em[288] = 48; 
    em[289] = 1; em[290] = 8; em[291] = 1; /* 289: pointer.struct.ec_group_st */
    	em[292] = 294; em[293] = 0; 
    em[294] = 0; em[295] = 232; em[296] = 12; /* 294: struct.ec_group_st */
    	em[297] = 321; em[298] = 0; 
    	em[299] = 493; em[300] = 8; 
    	em[301] = 266; em[302] = 16; 
    	em[303] = 266; em[304] = 40; 
    	em[305] = 258; em[306] = 80; 
    	em[307] = 253; em[308] = 96; 
    	em[309] = 266; em[310] = 104; 
    	em[311] = 266; em[312] = 152; 
    	em[313] = 266; em[314] = 176; 
    	em[315] = 229; em[316] = 208; 
    	em[317] = 229; em[318] = 216; 
    	em[319] = 223; em[320] = 224; 
    em[321] = 1; em[322] = 8; em[323] = 1; /* 321: pointer.struct.ec_method_st */
    	em[324] = 326; em[325] = 0; 
    em[326] = 0; em[327] = 304; em[328] = 37; /* 326: struct.ec_method_st */
    	em[329] = 403; em[330] = 8; 
    	em[331] = 406; em[332] = 16; 
    	em[333] = 406; em[334] = 24; 
    	em[335] = 409; em[336] = 32; 
    	em[337] = 412; em[338] = 40; 
    	em[339] = 415; em[340] = 48; 
    	em[341] = 418; em[342] = 56; 
    	em[343] = 421; em[344] = 64; 
    	em[345] = 424; em[346] = 72; 
    	em[347] = 427; em[348] = 80; 
    	em[349] = 427; em[350] = 88; 
    	em[351] = 430; em[352] = 96; 
    	em[353] = 433; em[354] = 104; 
    	em[355] = 436; em[356] = 112; 
    	em[357] = 439; em[358] = 120; 
    	em[359] = 442; em[360] = 128; 
    	em[361] = 445; em[362] = 136; 
    	em[363] = 448; em[364] = 144; 
    	em[365] = 451; em[366] = 152; 
    	em[367] = 454; em[368] = 160; 
    	em[369] = 457; em[370] = 168; 
    	em[371] = 460; em[372] = 176; 
    	em[373] = 463; em[374] = 184; 
    	em[375] = 466; em[376] = 192; 
    	em[377] = 469; em[378] = 200; 
    	em[379] = 472; em[380] = 208; 
    	em[381] = 463; em[382] = 216; 
    	em[383] = 475; em[384] = 224; 
    	em[385] = 478; em[386] = 232; 
    	em[387] = 481; em[388] = 240; 
    	em[389] = 418; em[390] = 248; 
    	em[391] = 484; em[392] = 256; 
    	em[393] = 487; em[394] = 264; 
    	em[395] = 484; em[396] = 272; 
    	em[397] = 487; em[398] = 280; 
    	em[399] = 487; em[400] = 288; 
    	em[401] = 490; em[402] = 296; 
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
    em[493] = 1; em[494] = 8; em[495] = 1; /* 493: pointer.struct.ec_point_st */
    	em[496] = 28; em[497] = 0; 
    em[498] = 1; em[499] = 8; em[500] = 1; /* 498: pointer.struct.ec_extra_data_st */
    	em[501] = 503; em[502] = 0; 
    em[503] = 0; em[504] = 40; em[505] = 5; /* 503: struct.ec_extra_data_st */
    	em[506] = 516; em[507] = 0; 
    	em[508] = 229; em[509] = 8; 
    	em[510] = 226; em[511] = 16; 
    	em[512] = 250; em[513] = 24; 
    	em[514] = 250; em[515] = 32; 
    em[516] = 1; em[517] = 8; em[518] = 1; /* 516: pointer.struct.ec_extra_data_st */
    	em[519] = 503; em[520] = 0; 
    em[521] = 1; em[522] = 8; em[523] = 1; /* 521: pointer.struct.ec_key_st */
    	em[524] = 278; em[525] = 0; 
    args_addr->arg_entity_index[0] = 20;
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

