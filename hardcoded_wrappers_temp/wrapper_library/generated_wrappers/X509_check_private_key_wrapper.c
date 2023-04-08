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

int bb_X509_check_private_key(X509 * arg_a,EVP_PKEY * arg_b);

int X509_check_private_key(X509 * arg_a,EVP_PKEY * arg_b) 
{
    unsigned long in_lib = syscall(890);
    printf("X509_check_private_key called %lu\n", in_lib);
    if (!in_lib)
        return bb_X509_check_private_key(arg_a,arg_b);
    else {
        int (*orig_X509_check_private_key)(X509 *,EVP_PKEY *);
        orig_X509_check_private_key = dlsym(RTLD_NEXT, "X509_check_private_key");
        return orig_X509_check_private_key(arg_a,arg_b);
    }
}

int bb_X509_check_private_key(X509 * arg_a,EVP_PKEY * arg_b) 
{
    int ret;

    struct lib_enter_args *args_addr = malloc(sizeof(struct lib_enter_args));
    memset(args_addr, 0, sizeof(struct lib_enter_args));
    args_addr->num_args = 0;
    uint32_t *em = args_addr->entity_metadata;
    em[0] = 1; em[1] = 8; em[2] = 1; /* 0: pointer.struct.dh_st */
    	em[3] = 5; em[4] = 0; 
    em[5] = 0; em[6] = 144; em[7] = 12; /* 5: struct.dh_st */
    	em[8] = 32; em[9] = 8; 
    	em[10] = 32; em[11] = 16; 
    	em[12] = 32; em[13] = 32; 
    	em[14] = 32; em[15] = 40; 
    	em[16] = 55; em[17] = 56; 
    	em[18] = 32; em[19] = 64; 
    	em[20] = 32; em[21] = 72; 
    	em[22] = 69; em[23] = 80; 
    	em[24] = 32; em[25] = 96; 
    	em[26] = 77; em[27] = 112; 
    	em[28] = 97; em[29] = 128; 
    	em[30] = 143; em[31] = 136; 
    em[32] = 1; em[33] = 8; em[34] = 1; /* 32: pointer.struct.bignum_st */
    	em[35] = 37; em[36] = 0; 
    em[37] = 0; em[38] = 24; em[39] = 1; /* 37: struct.bignum_st */
    	em[40] = 42; em[41] = 0; 
    em[42] = 8884099; em[43] = 8; em[44] = 2; /* 42: pointer_to_array_of_pointers_to_stack */
    	em[45] = 49; em[46] = 0; 
    	em[47] = 52; em[48] = 12; 
    em[49] = 0; em[50] = 8; em[51] = 0; /* 49: long unsigned int */
    em[52] = 0; em[53] = 4; em[54] = 0; /* 52: int */
    em[55] = 1; em[56] = 8; em[57] = 1; /* 55: pointer.struct.bn_mont_ctx_st */
    	em[58] = 60; em[59] = 0; 
    em[60] = 0; em[61] = 96; em[62] = 3; /* 60: struct.bn_mont_ctx_st */
    	em[63] = 37; em[64] = 8; 
    	em[65] = 37; em[66] = 32; 
    	em[67] = 37; em[68] = 56; 
    em[69] = 1; em[70] = 8; em[71] = 1; /* 69: pointer.unsigned char */
    	em[72] = 74; em[73] = 0; 
    em[74] = 0; em[75] = 1; em[76] = 0; /* 74: unsigned char */
    em[77] = 0; em[78] = 32; em[79] = 2; /* 77: struct.crypto_ex_data_st_fake */
    	em[80] = 84; em[81] = 8; 
    	em[82] = 94; em[83] = 24; 
    em[84] = 8884099; em[85] = 8; em[86] = 2; /* 84: pointer_to_array_of_pointers_to_stack */
    	em[87] = 91; em[88] = 0; 
    	em[89] = 52; em[90] = 20; 
    em[91] = 0; em[92] = 8; em[93] = 0; /* 91: pointer.void */
    em[94] = 8884097; em[95] = 8; em[96] = 0; /* 94: pointer.func */
    em[97] = 1; em[98] = 8; em[99] = 1; /* 97: pointer.struct.dh_method */
    	em[100] = 102; em[101] = 0; 
    em[102] = 0; em[103] = 72; em[104] = 8; /* 102: struct.dh_method */
    	em[105] = 121; em[106] = 0; 
    	em[107] = 126; em[108] = 8; 
    	em[109] = 129; em[110] = 16; 
    	em[111] = 132; em[112] = 24; 
    	em[113] = 126; em[114] = 32; 
    	em[115] = 126; em[116] = 40; 
    	em[117] = 135; em[118] = 56; 
    	em[119] = 140; em[120] = 64; 
    em[121] = 1; em[122] = 8; em[123] = 1; /* 121: pointer.char */
    	em[124] = 8884096; em[125] = 0; 
    em[126] = 8884097; em[127] = 8; em[128] = 0; /* 126: pointer.func */
    em[129] = 8884097; em[130] = 8; em[131] = 0; /* 129: pointer.func */
    em[132] = 8884097; em[133] = 8; em[134] = 0; /* 132: pointer.func */
    em[135] = 1; em[136] = 8; em[137] = 1; /* 135: pointer.char */
    	em[138] = 8884096; em[139] = 0; 
    em[140] = 8884097; em[141] = 8; em[142] = 0; /* 140: pointer.func */
    em[143] = 1; em[144] = 8; em[145] = 1; /* 143: pointer.struct.engine_st */
    	em[146] = 148; em[147] = 0; 
    em[148] = 0; em[149] = 216; em[150] = 24; /* 148: struct.engine_st */
    	em[151] = 121; em[152] = 0; 
    	em[153] = 121; em[154] = 8; 
    	em[155] = 199; em[156] = 16; 
    	em[157] = 254; em[158] = 24; 
    	em[159] = 305; em[160] = 32; 
    	em[161] = 341; em[162] = 40; 
    	em[163] = 358; em[164] = 48; 
    	em[165] = 385; em[166] = 56; 
    	em[167] = 420; em[168] = 64; 
    	em[169] = 428; em[170] = 72; 
    	em[171] = 431; em[172] = 80; 
    	em[173] = 434; em[174] = 88; 
    	em[175] = 437; em[176] = 96; 
    	em[177] = 440; em[178] = 104; 
    	em[179] = 440; em[180] = 112; 
    	em[181] = 440; em[182] = 120; 
    	em[183] = 443; em[184] = 128; 
    	em[185] = 446; em[186] = 136; 
    	em[187] = 446; em[188] = 144; 
    	em[189] = 449; em[190] = 152; 
    	em[191] = 452; em[192] = 160; 
    	em[193] = 464; em[194] = 184; 
    	em[195] = 478; em[196] = 200; 
    	em[197] = 478; em[198] = 208; 
    em[199] = 1; em[200] = 8; em[201] = 1; /* 199: pointer.struct.rsa_meth_st */
    	em[202] = 204; em[203] = 0; 
    em[204] = 0; em[205] = 112; em[206] = 13; /* 204: struct.rsa_meth_st */
    	em[207] = 121; em[208] = 0; 
    	em[209] = 233; em[210] = 8; 
    	em[211] = 233; em[212] = 16; 
    	em[213] = 233; em[214] = 24; 
    	em[215] = 233; em[216] = 32; 
    	em[217] = 236; em[218] = 40; 
    	em[219] = 239; em[220] = 48; 
    	em[221] = 242; em[222] = 56; 
    	em[223] = 242; em[224] = 64; 
    	em[225] = 135; em[226] = 80; 
    	em[227] = 245; em[228] = 88; 
    	em[229] = 248; em[230] = 96; 
    	em[231] = 251; em[232] = 104; 
    em[233] = 8884097; em[234] = 8; em[235] = 0; /* 233: pointer.func */
    em[236] = 8884097; em[237] = 8; em[238] = 0; /* 236: pointer.func */
    em[239] = 8884097; em[240] = 8; em[241] = 0; /* 239: pointer.func */
    em[242] = 8884097; em[243] = 8; em[244] = 0; /* 242: pointer.func */
    em[245] = 8884097; em[246] = 8; em[247] = 0; /* 245: pointer.func */
    em[248] = 8884097; em[249] = 8; em[250] = 0; /* 248: pointer.func */
    em[251] = 8884097; em[252] = 8; em[253] = 0; /* 251: pointer.func */
    em[254] = 1; em[255] = 8; em[256] = 1; /* 254: pointer.struct.dsa_method */
    	em[257] = 259; em[258] = 0; 
    em[259] = 0; em[260] = 96; em[261] = 11; /* 259: struct.dsa_method */
    	em[262] = 121; em[263] = 0; 
    	em[264] = 284; em[265] = 8; 
    	em[266] = 287; em[267] = 16; 
    	em[268] = 290; em[269] = 24; 
    	em[270] = 293; em[271] = 32; 
    	em[272] = 296; em[273] = 40; 
    	em[274] = 299; em[275] = 48; 
    	em[276] = 299; em[277] = 56; 
    	em[278] = 135; em[279] = 72; 
    	em[280] = 302; em[281] = 80; 
    	em[282] = 299; em[283] = 88; 
    em[284] = 8884097; em[285] = 8; em[286] = 0; /* 284: pointer.func */
    em[287] = 8884097; em[288] = 8; em[289] = 0; /* 287: pointer.func */
    em[290] = 8884097; em[291] = 8; em[292] = 0; /* 290: pointer.func */
    em[293] = 8884097; em[294] = 8; em[295] = 0; /* 293: pointer.func */
    em[296] = 8884097; em[297] = 8; em[298] = 0; /* 296: pointer.func */
    em[299] = 8884097; em[300] = 8; em[301] = 0; /* 299: pointer.func */
    em[302] = 8884097; em[303] = 8; em[304] = 0; /* 302: pointer.func */
    em[305] = 1; em[306] = 8; em[307] = 1; /* 305: pointer.struct.dh_method */
    	em[308] = 310; em[309] = 0; 
    em[310] = 0; em[311] = 72; em[312] = 8; /* 310: struct.dh_method */
    	em[313] = 121; em[314] = 0; 
    	em[315] = 329; em[316] = 8; 
    	em[317] = 332; em[318] = 16; 
    	em[319] = 335; em[320] = 24; 
    	em[321] = 329; em[322] = 32; 
    	em[323] = 329; em[324] = 40; 
    	em[325] = 135; em[326] = 56; 
    	em[327] = 338; em[328] = 64; 
    em[329] = 8884097; em[330] = 8; em[331] = 0; /* 329: pointer.func */
    em[332] = 8884097; em[333] = 8; em[334] = 0; /* 332: pointer.func */
    em[335] = 8884097; em[336] = 8; em[337] = 0; /* 335: pointer.func */
    em[338] = 8884097; em[339] = 8; em[340] = 0; /* 338: pointer.func */
    em[341] = 1; em[342] = 8; em[343] = 1; /* 341: pointer.struct.ecdh_method */
    	em[344] = 346; em[345] = 0; 
    em[346] = 0; em[347] = 32; em[348] = 3; /* 346: struct.ecdh_method */
    	em[349] = 121; em[350] = 0; 
    	em[351] = 355; em[352] = 8; 
    	em[353] = 135; em[354] = 24; 
    em[355] = 8884097; em[356] = 8; em[357] = 0; /* 355: pointer.func */
    em[358] = 1; em[359] = 8; em[360] = 1; /* 358: pointer.struct.ecdsa_method */
    	em[361] = 363; em[362] = 0; 
    em[363] = 0; em[364] = 48; em[365] = 5; /* 363: struct.ecdsa_method */
    	em[366] = 121; em[367] = 0; 
    	em[368] = 376; em[369] = 8; 
    	em[370] = 379; em[371] = 16; 
    	em[372] = 382; em[373] = 24; 
    	em[374] = 135; em[375] = 40; 
    em[376] = 8884097; em[377] = 8; em[378] = 0; /* 376: pointer.func */
    em[379] = 8884097; em[380] = 8; em[381] = 0; /* 379: pointer.func */
    em[382] = 8884097; em[383] = 8; em[384] = 0; /* 382: pointer.func */
    em[385] = 1; em[386] = 8; em[387] = 1; /* 385: pointer.struct.rand_meth_st */
    	em[388] = 390; em[389] = 0; 
    em[390] = 0; em[391] = 48; em[392] = 6; /* 390: struct.rand_meth_st */
    	em[393] = 405; em[394] = 0; 
    	em[395] = 408; em[396] = 8; 
    	em[397] = 411; em[398] = 16; 
    	em[399] = 414; em[400] = 24; 
    	em[401] = 408; em[402] = 32; 
    	em[403] = 417; em[404] = 40; 
    em[405] = 8884097; em[406] = 8; em[407] = 0; /* 405: pointer.func */
    em[408] = 8884097; em[409] = 8; em[410] = 0; /* 408: pointer.func */
    em[411] = 8884097; em[412] = 8; em[413] = 0; /* 411: pointer.func */
    em[414] = 8884097; em[415] = 8; em[416] = 0; /* 414: pointer.func */
    em[417] = 8884097; em[418] = 8; em[419] = 0; /* 417: pointer.func */
    em[420] = 1; em[421] = 8; em[422] = 1; /* 420: pointer.struct.store_method_st */
    	em[423] = 425; em[424] = 0; 
    em[425] = 0; em[426] = 0; em[427] = 0; /* 425: struct.store_method_st */
    em[428] = 8884097; em[429] = 8; em[430] = 0; /* 428: pointer.func */
    em[431] = 8884097; em[432] = 8; em[433] = 0; /* 431: pointer.func */
    em[434] = 8884097; em[435] = 8; em[436] = 0; /* 434: pointer.func */
    em[437] = 8884097; em[438] = 8; em[439] = 0; /* 437: pointer.func */
    em[440] = 8884097; em[441] = 8; em[442] = 0; /* 440: pointer.func */
    em[443] = 8884097; em[444] = 8; em[445] = 0; /* 443: pointer.func */
    em[446] = 8884097; em[447] = 8; em[448] = 0; /* 446: pointer.func */
    em[449] = 8884097; em[450] = 8; em[451] = 0; /* 449: pointer.func */
    em[452] = 1; em[453] = 8; em[454] = 1; /* 452: pointer.struct.ENGINE_CMD_DEFN_st */
    	em[455] = 457; em[456] = 0; 
    em[457] = 0; em[458] = 32; em[459] = 2; /* 457: struct.ENGINE_CMD_DEFN_st */
    	em[460] = 121; em[461] = 8; 
    	em[462] = 121; em[463] = 16; 
    em[464] = 0; em[465] = 32; em[466] = 2; /* 464: struct.crypto_ex_data_st_fake */
    	em[467] = 471; em[468] = 8; 
    	em[469] = 94; em[470] = 24; 
    em[471] = 8884099; em[472] = 8; em[473] = 2; /* 471: pointer_to_array_of_pointers_to_stack */
    	em[474] = 91; em[475] = 0; 
    	em[476] = 52; em[477] = 20; 
    em[478] = 1; em[479] = 8; em[480] = 1; /* 478: pointer.struct.engine_st */
    	em[481] = 148; em[482] = 0; 
    em[483] = 1; em[484] = 8; em[485] = 1; /* 483: pointer.struct.dsa_st */
    	em[486] = 488; em[487] = 0; 
    em[488] = 0; em[489] = 136; em[490] = 11; /* 488: struct.dsa_st */
    	em[491] = 513; em[492] = 24; 
    	em[493] = 513; em[494] = 32; 
    	em[495] = 513; em[496] = 40; 
    	em[497] = 513; em[498] = 48; 
    	em[499] = 513; em[500] = 56; 
    	em[501] = 513; em[502] = 64; 
    	em[503] = 513; em[504] = 72; 
    	em[505] = 530; em[506] = 88; 
    	em[507] = 544; em[508] = 104; 
    	em[509] = 558; em[510] = 120; 
    	em[511] = 609; em[512] = 128; 
    em[513] = 1; em[514] = 8; em[515] = 1; /* 513: pointer.struct.bignum_st */
    	em[516] = 518; em[517] = 0; 
    em[518] = 0; em[519] = 24; em[520] = 1; /* 518: struct.bignum_st */
    	em[521] = 523; em[522] = 0; 
    em[523] = 8884099; em[524] = 8; em[525] = 2; /* 523: pointer_to_array_of_pointers_to_stack */
    	em[526] = 49; em[527] = 0; 
    	em[528] = 52; em[529] = 12; 
    em[530] = 1; em[531] = 8; em[532] = 1; /* 530: pointer.struct.bn_mont_ctx_st */
    	em[533] = 535; em[534] = 0; 
    em[535] = 0; em[536] = 96; em[537] = 3; /* 535: struct.bn_mont_ctx_st */
    	em[538] = 518; em[539] = 8; 
    	em[540] = 518; em[541] = 32; 
    	em[542] = 518; em[543] = 56; 
    em[544] = 0; em[545] = 32; em[546] = 2; /* 544: struct.crypto_ex_data_st_fake */
    	em[547] = 551; em[548] = 8; 
    	em[549] = 94; em[550] = 24; 
    em[551] = 8884099; em[552] = 8; em[553] = 2; /* 551: pointer_to_array_of_pointers_to_stack */
    	em[554] = 91; em[555] = 0; 
    	em[556] = 52; em[557] = 20; 
    em[558] = 1; em[559] = 8; em[560] = 1; /* 558: pointer.struct.dsa_method */
    	em[561] = 563; em[562] = 0; 
    em[563] = 0; em[564] = 96; em[565] = 11; /* 563: struct.dsa_method */
    	em[566] = 121; em[567] = 0; 
    	em[568] = 588; em[569] = 8; 
    	em[570] = 591; em[571] = 16; 
    	em[572] = 594; em[573] = 24; 
    	em[574] = 597; em[575] = 32; 
    	em[576] = 600; em[577] = 40; 
    	em[578] = 603; em[579] = 48; 
    	em[580] = 603; em[581] = 56; 
    	em[582] = 135; em[583] = 72; 
    	em[584] = 606; em[585] = 80; 
    	em[586] = 603; em[587] = 88; 
    em[588] = 8884097; em[589] = 8; em[590] = 0; /* 588: pointer.func */
    em[591] = 8884097; em[592] = 8; em[593] = 0; /* 591: pointer.func */
    em[594] = 8884097; em[595] = 8; em[596] = 0; /* 594: pointer.func */
    em[597] = 8884097; em[598] = 8; em[599] = 0; /* 597: pointer.func */
    em[600] = 8884097; em[601] = 8; em[602] = 0; /* 600: pointer.func */
    em[603] = 8884097; em[604] = 8; em[605] = 0; /* 603: pointer.func */
    em[606] = 8884097; em[607] = 8; em[608] = 0; /* 606: pointer.func */
    em[609] = 1; em[610] = 8; em[611] = 1; /* 609: pointer.struct.engine_st */
    	em[612] = 148; em[613] = 0; 
    em[614] = 0; em[615] = 56; em[616] = 4; /* 614: struct.evp_pkey_st */
    	em[617] = 625; em[618] = 16; 
    	em[619] = 726; em[620] = 24; 
    	em[621] = 731; em[622] = 32; 
    	em[623] = 1463; em[624] = 48; 
    em[625] = 1; em[626] = 8; em[627] = 1; /* 625: pointer.struct.evp_pkey_asn1_method_st */
    	em[628] = 630; em[629] = 0; 
    em[630] = 0; em[631] = 208; em[632] = 24; /* 630: struct.evp_pkey_asn1_method_st */
    	em[633] = 135; em[634] = 16; 
    	em[635] = 135; em[636] = 24; 
    	em[637] = 681; em[638] = 32; 
    	em[639] = 684; em[640] = 40; 
    	em[641] = 687; em[642] = 48; 
    	em[643] = 690; em[644] = 56; 
    	em[645] = 693; em[646] = 64; 
    	em[647] = 696; em[648] = 72; 
    	em[649] = 690; em[650] = 80; 
    	em[651] = 699; em[652] = 88; 
    	em[653] = 699; em[654] = 96; 
    	em[655] = 702; em[656] = 104; 
    	em[657] = 705; em[658] = 112; 
    	em[659] = 699; em[660] = 120; 
    	em[661] = 708; em[662] = 128; 
    	em[663] = 687; em[664] = 136; 
    	em[665] = 690; em[666] = 144; 
    	em[667] = 711; em[668] = 152; 
    	em[669] = 714; em[670] = 160; 
    	em[671] = 717; em[672] = 168; 
    	em[673] = 702; em[674] = 176; 
    	em[675] = 705; em[676] = 184; 
    	em[677] = 720; em[678] = 192; 
    	em[679] = 723; em[680] = 200; 
    em[681] = 8884097; em[682] = 8; em[683] = 0; /* 681: pointer.func */
    em[684] = 8884097; em[685] = 8; em[686] = 0; /* 684: pointer.func */
    em[687] = 8884097; em[688] = 8; em[689] = 0; /* 687: pointer.func */
    em[690] = 8884097; em[691] = 8; em[692] = 0; /* 690: pointer.func */
    em[693] = 8884097; em[694] = 8; em[695] = 0; /* 693: pointer.func */
    em[696] = 8884097; em[697] = 8; em[698] = 0; /* 696: pointer.func */
    em[699] = 8884097; em[700] = 8; em[701] = 0; /* 699: pointer.func */
    em[702] = 8884097; em[703] = 8; em[704] = 0; /* 702: pointer.func */
    em[705] = 8884097; em[706] = 8; em[707] = 0; /* 705: pointer.func */
    em[708] = 8884097; em[709] = 8; em[710] = 0; /* 708: pointer.func */
    em[711] = 8884097; em[712] = 8; em[713] = 0; /* 711: pointer.func */
    em[714] = 8884097; em[715] = 8; em[716] = 0; /* 714: pointer.func */
    em[717] = 8884097; em[718] = 8; em[719] = 0; /* 717: pointer.func */
    em[720] = 8884097; em[721] = 8; em[722] = 0; /* 720: pointer.func */
    em[723] = 8884097; em[724] = 8; em[725] = 0; /* 723: pointer.func */
    em[726] = 1; em[727] = 8; em[728] = 1; /* 726: pointer.struct.engine_st */
    	em[729] = 148; em[730] = 0; 
    em[731] = 8884101; em[732] = 8; em[733] = 6; /* 731: union.union_of_evp_pkey_st */
    	em[734] = 91; em[735] = 0; 
    	em[736] = 746; em[737] = 6; 
    	em[738] = 483; em[739] = 116; 
    	em[740] = 0; em[741] = 28; 
    	em[742] = 954; em[743] = 408; 
    	em[744] = 52; em[745] = 0; 
    em[746] = 1; em[747] = 8; em[748] = 1; /* 746: pointer.struct.rsa_st */
    	em[749] = 751; em[750] = 0; 
    em[751] = 0; em[752] = 168; em[753] = 17; /* 751: struct.rsa_st */
    	em[754] = 788; em[755] = 16; 
    	em[756] = 843; em[757] = 24; 
    	em[758] = 848; em[759] = 32; 
    	em[760] = 848; em[761] = 40; 
    	em[762] = 848; em[763] = 48; 
    	em[764] = 848; em[765] = 56; 
    	em[766] = 848; em[767] = 64; 
    	em[768] = 848; em[769] = 72; 
    	em[770] = 848; em[771] = 80; 
    	em[772] = 848; em[773] = 88; 
    	em[774] = 865; em[775] = 96; 
    	em[776] = 879; em[777] = 120; 
    	em[778] = 879; em[779] = 128; 
    	em[780] = 879; em[781] = 136; 
    	em[782] = 135; em[783] = 144; 
    	em[784] = 893; em[785] = 152; 
    	em[786] = 893; em[787] = 160; 
    em[788] = 1; em[789] = 8; em[790] = 1; /* 788: pointer.struct.rsa_meth_st */
    	em[791] = 793; em[792] = 0; 
    em[793] = 0; em[794] = 112; em[795] = 13; /* 793: struct.rsa_meth_st */
    	em[796] = 121; em[797] = 0; 
    	em[798] = 822; em[799] = 8; 
    	em[800] = 822; em[801] = 16; 
    	em[802] = 822; em[803] = 24; 
    	em[804] = 822; em[805] = 32; 
    	em[806] = 825; em[807] = 40; 
    	em[808] = 828; em[809] = 48; 
    	em[810] = 831; em[811] = 56; 
    	em[812] = 831; em[813] = 64; 
    	em[814] = 135; em[815] = 80; 
    	em[816] = 834; em[817] = 88; 
    	em[818] = 837; em[819] = 96; 
    	em[820] = 840; em[821] = 104; 
    em[822] = 8884097; em[823] = 8; em[824] = 0; /* 822: pointer.func */
    em[825] = 8884097; em[826] = 8; em[827] = 0; /* 825: pointer.func */
    em[828] = 8884097; em[829] = 8; em[830] = 0; /* 828: pointer.func */
    em[831] = 8884097; em[832] = 8; em[833] = 0; /* 831: pointer.func */
    em[834] = 8884097; em[835] = 8; em[836] = 0; /* 834: pointer.func */
    em[837] = 8884097; em[838] = 8; em[839] = 0; /* 837: pointer.func */
    em[840] = 8884097; em[841] = 8; em[842] = 0; /* 840: pointer.func */
    em[843] = 1; em[844] = 8; em[845] = 1; /* 843: pointer.struct.engine_st */
    	em[846] = 148; em[847] = 0; 
    em[848] = 1; em[849] = 8; em[850] = 1; /* 848: pointer.struct.bignum_st */
    	em[851] = 853; em[852] = 0; 
    em[853] = 0; em[854] = 24; em[855] = 1; /* 853: struct.bignum_st */
    	em[856] = 858; em[857] = 0; 
    em[858] = 8884099; em[859] = 8; em[860] = 2; /* 858: pointer_to_array_of_pointers_to_stack */
    	em[861] = 49; em[862] = 0; 
    	em[863] = 52; em[864] = 12; 
    em[865] = 0; em[866] = 32; em[867] = 2; /* 865: struct.crypto_ex_data_st_fake */
    	em[868] = 872; em[869] = 8; 
    	em[870] = 94; em[871] = 24; 
    em[872] = 8884099; em[873] = 8; em[874] = 2; /* 872: pointer_to_array_of_pointers_to_stack */
    	em[875] = 91; em[876] = 0; 
    	em[877] = 52; em[878] = 20; 
    em[879] = 1; em[880] = 8; em[881] = 1; /* 879: pointer.struct.bn_mont_ctx_st */
    	em[882] = 884; em[883] = 0; 
    em[884] = 0; em[885] = 96; em[886] = 3; /* 884: struct.bn_mont_ctx_st */
    	em[887] = 853; em[888] = 8; 
    	em[889] = 853; em[890] = 32; 
    	em[891] = 853; em[892] = 56; 
    em[893] = 1; em[894] = 8; em[895] = 1; /* 893: pointer.struct.bn_blinding_st */
    	em[896] = 898; em[897] = 0; 
    em[898] = 0; em[899] = 88; em[900] = 7; /* 898: struct.bn_blinding_st */
    	em[901] = 915; em[902] = 0; 
    	em[903] = 915; em[904] = 8; 
    	em[905] = 915; em[906] = 16; 
    	em[907] = 915; em[908] = 24; 
    	em[909] = 932; em[910] = 40; 
    	em[911] = 937; em[912] = 72; 
    	em[913] = 951; em[914] = 80; 
    em[915] = 1; em[916] = 8; em[917] = 1; /* 915: pointer.struct.bignum_st */
    	em[918] = 920; em[919] = 0; 
    em[920] = 0; em[921] = 24; em[922] = 1; /* 920: struct.bignum_st */
    	em[923] = 925; em[924] = 0; 
    em[925] = 8884099; em[926] = 8; em[927] = 2; /* 925: pointer_to_array_of_pointers_to_stack */
    	em[928] = 49; em[929] = 0; 
    	em[930] = 52; em[931] = 12; 
    em[932] = 0; em[933] = 16; em[934] = 1; /* 932: struct.crypto_threadid_st */
    	em[935] = 91; em[936] = 0; 
    em[937] = 1; em[938] = 8; em[939] = 1; /* 937: pointer.struct.bn_mont_ctx_st */
    	em[940] = 942; em[941] = 0; 
    em[942] = 0; em[943] = 96; em[944] = 3; /* 942: struct.bn_mont_ctx_st */
    	em[945] = 920; em[946] = 8; 
    	em[947] = 920; em[948] = 32; 
    	em[949] = 920; em[950] = 56; 
    em[951] = 8884097; em[952] = 8; em[953] = 0; /* 951: pointer.func */
    em[954] = 1; em[955] = 8; em[956] = 1; /* 954: pointer.struct.ec_key_st */
    	em[957] = 959; em[958] = 0; 
    em[959] = 0; em[960] = 56; em[961] = 4; /* 959: struct.ec_key_st */
    	em[962] = 970; em[963] = 8; 
    	em[964] = 1418; em[965] = 16; 
    	em[966] = 1423; em[967] = 24; 
    	em[968] = 1440; em[969] = 48; 
    em[970] = 1; em[971] = 8; em[972] = 1; /* 970: pointer.struct.ec_group_st */
    	em[973] = 975; em[974] = 0; 
    em[975] = 0; em[976] = 232; em[977] = 12; /* 975: struct.ec_group_st */
    	em[978] = 1002; em[979] = 0; 
    	em[980] = 1174; em[981] = 8; 
    	em[982] = 1374; em[983] = 16; 
    	em[984] = 1374; em[985] = 40; 
    	em[986] = 69; em[987] = 80; 
    	em[988] = 1386; em[989] = 96; 
    	em[990] = 1374; em[991] = 104; 
    	em[992] = 1374; em[993] = 152; 
    	em[994] = 1374; em[995] = 176; 
    	em[996] = 91; em[997] = 208; 
    	em[998] = 91; em[999] = 216; 
    	em[1000] = 1415; em[1001] = 224; 
    em[1002] = 1; em[1003] = 8; em[1004] = 1; /* 1002: pointer.struct.ec_method_st */
    	em[1005] = 1007; em[1006] = 0; 
    em[1007] = 0; em[1008] = 304; em[1009] = 37; /* 1007: struct.ec_method_st */
    	em[1010] = 1084; em[1011] = 8; 
    	em[1012] = 1087; em[1013] = 16; 
    	em[1014] = 1087; em[1015] = 24; 
    	em[1016] = 1090; em[1017] = 32; 
    	em[1018] = 1093; em[1019] = 40; 
    	em[1020] = 1096; em[1021] = 48; 
    	em[1022] = 1099; em[1023] = 56; 
    	em[1024] = 1102; em[1025] = 64; 
    	em[1026] = 1105; em[1027] = 72; 
    	em[1028] = 1108; em[1029] = 80; 
    	em[1030] = 1108; em[1031] = 88; 
    	em[1032] = 1111; em[1033] = 96; 
    	em[1034] = 1114; em[1035] = 104; 
    	em[1036] = 1117; em[1037] = 112; 
    	em[1038] = 1120; em[1039] = 120; 
    	em[1040] = 1123; em[1041] = 128; 
    	em[1042] = 1126; em[1043] = 136; 
    	em[1044] = 1129; em[1045] = 144; 
    	em[1046] = 1132; em[1047] = 152; 
    	em[1048] = 1135; em[1049] = 160; 
    	em[1050] = 1138; em[1051] = 168; 
    	em[1052] = 1141; em[1053] = 176; 
    	em[1054] = 1144; em[1055] = 184; 
    	em[1056] = 1147; em[1057] = 192; 
    	em[1058] = 1150; em[1059] = 200; 
    	em[1060] = 1153; em[1061] = 208; 
    	em[1062] = 1144; em[1063] = 216; 
    	em[1064] = 1156; em[1065] = 224; 
    	em[1066] = 1159; em[1067] = 232; 
    	em[1068] = 1162; em[1069] = 240; 
    	em[1070] = 1099; em[1071] = 248; 
    	em[1072] = 1165; em[1073] = 256; 
    	em[1074] = 1168; em[1075] = 264; 
    	em[1076] = 1165; em[1077] = 272; 
    	em[1078] = 1168; em[1079] = 280; 
    	em[1080] = 1168; em[1081] = 288; 
    	em[1082] = 1171; em[1083] = 296; 
    em[1084] = 8884097; em[1085] = 8; em[1086] = 0; /* 1084: pointer.func */
    em[1087] = 8884097; em[1088] = 8; em[1089] = 0; /* 1087: pointer.func */
    em[1090] = 8884097; em[1091] = 8; em[1092] = 0; /* 1090: pointer.func */
    em[1093] = 8884097; em[1094] = 8; em[1095] = 0; /* 1093: pointer.func */
    em[1096] = 8884097; em[1097] = 8; em[1098] = 0; /* 1096: pointer.func */
    em[1099] = 8884097; em[1100] = 8; em[1101] = 0; /* 1099: pointer.func */
    em[1102] = 8884097; em[1103] = 8; em[1104] = 0; /* 1102: pointer.func */
    em[1105] = 8884097; em[1106] = 8; em[1107] = 0; /* 1105: pointer.func */
    em[1108] = 8884097; em[1109] = 8; em[1110] = 0; /* 1108: pointer.func */
    em[1111] = 8884097; em[1112] = 8; em[1113] = 0; /* 1111: pointer.func */
    em[1114] = 8884097; em[1115] = 8; em[1116] = 0; /* 1114: pointer.func */
    em[1117] = 8884097; em[1118] = 8; em[1119] = 0; /* 1117: pointer.func */
    em[1120] = 8884097; em[1121] = 8; em[1122] = 0; /* 1120: pointer.func */
    em[1123] = 8884097; em[1124] = 8; em[1125] = 0; /* 1123: pointer.func */
    em[1126] = 8884097; em[1127] = 8; em[1128] = 0; /* 1126: pointer.func */
    em[1129] = 8884097; em[1130] = 8; em[1131] = 0; /* 1129: pointer.func */
    em[1132] = 8884097; em[1133] = 8; em[1134] = 0; /* 1132: pointer.func */
    em[1135] = 8884097; em[1136] = 8; em[1137] = 0; /* 1135: pointer.func */
    em[1138] = 8884097; em[1139] = 8; em[1140] = 0; /* 1138: pointer.func */
    em[1141] = 8884097; em[1142] = 8; em[1143] = 0; /* 1141: pointer.func */
    em[1144] = 8884097; em[1145] = 8; em[1146] = 0; /* 1144: pointer.func */
    em[1147] = 8884097; em[1148] = 8; em[1149] = 0; /* 1147: pointer.func */
    em[1150] = 8884097; em[1151] = 8; em[1152] = 0; /* 1150: pointer.func */
    em[1153] = 8884097; em[1154] = 8; em[1155] = 0; /* 1153: pointer.func */
    em[1156] = 8884097; em[1157] = 8; em[1158] = 0; /* 1156: pointer.func */
    em[1159] = 8884097; em[1160] = 8; em[1161] = 0; /* 1159: pointer.func */
    em[1162] = 8884097; em[1163] = 8; em[1164] = 0; /* 1162: pointer.func */
    em[1165] = 8884097; em[1166] = 8; em[1167] = 0; /* 1165: pointer.func */
    em[1168] = 8884097; em[1169] = 8; em[1170] = 0; /* 1168: pointer.func */
    em[1171] = 8884097; em[1172] = 8; em[1173] = 0; /* 1171: pointer.func */
    em[1174] = 1; em[1175] = 8; em[1176] = 1; /* 1174: pointer.struct.ec_point_st */
    	em[1177] = 1179; em[1178] = 0; 
    em[1179] = 0; em[1180] = 88; em[1181] = 4; /* 1179: struct.ec_point_st */
    	em[1182] = 1190; em[1183] = 0; 
    	em[1184] = 1362; em[1185] = 8; 
    	em[1186] = 1362; em[1187] = 32; 
    	em[1188] = 1362; em[1189] = 56; 
    em[1190] = 1; em[1191] = 8; em[1192] = 1; /* 1190: pointer.struct.ec_method_st */
    	em[1193] = 1195; em[1194] = 0; 
    em[1195] = 0; em[1196] = 304; em[1197] = 37; /* 1195: struct.ec_method_st */
    	em[1198] = 1272; em[1199] = 8; 
    	em[1200] = 1275; em[1201] = 16; 
    	em[1202] = 1275; em[1203] = 24; 
    	em[1204] = 1278; em[1205] = 32; 
    	em[1206] = 1281; em[1207] = 40; 
    	em[1208] = 1284; em[1209] = 48; 
    	em[1210] = 1287; em[1211] = 56; 
    	em[1212] = 1290; em[1213] = 64; 
    	em[1214] = 1293; em[1215] = 72; 
    	em[1216] = 1296; em[1217] = 80; 
    	em[1218] = 1296; em[1219] = 88; 
    	em[1220] = 1299; em[1221] = 96; 
    	em[1222] = 1302; em[1223] = 104; 
    	em[1224] = 1305; em[1225] = 112; 
    	em[1226] = 1308; em[1227] = 120; 
    	em[1228] = 1311; em[1229] = 128; 
    	em[1230] = 1314; em[1231] = 136; 
    	em[1232] = 1317; em[1233] = 144; 
    	em[1234] = 1320; em[1235] = 152; 
    	em[1236] = 1323; em[1237] = 160; 
    	em[1238] = 1326; em[1239] = 168; 
    	em[1240] = 1329; em[1241] = 176; 
    	em[1242] = 1332; em[1243] = 184; 
    	em[1244] = 1335; em[1245] = 192; 
    	em[1246] = 1338; em[1247] = 200; 
    	em[1248] = 1341; em[1249] = 208; 
    	em[1250] = 1332; em[1251] = 216; 
    	em[1252] = 1344; em[1253] = 224; 
    	em[1254] = 1347; em[1255] = 232; 
    	em[1256] = 1350; em[1257] = 240; 
    	em[1258] = 1287; em[1259] = 248; 
    	em[1260] = 1353; em[1261] = 256; 
    	em[1262] = 1356; em[1263] = 264; 
    	em[1264] = 1353; em[1265] = 272; 
    	em[1266] = 1356; em[1267] = 280; 
    	em[1268] = 1356; em[1269] = 288; 
    	em[1270] = 1359; em[1271] = 296; 
    em[1272] = 8884097; em[1273] = 8; em[1274] = 0; /* 1272: pointer.func */
    em[1275] = 8884097; em[1276] = 8; em[1277] = 0; /* 1275: pointer.func */
    em[1278] = 8884097; em[1279] = 8; em[1280] = 0; /* 1278: pointer.func */
    em[1281] = 8884097; em[1282] = 8; em[1283] = 0; /* 1281: pointer.func */
    em[1284] = 8884097; em[1285] = 8; em[1286] = 0; /* 1284: pointer.func */
    em[1287] = 8884097; em[1288] = 8; em[1289] = 0; /* 1287: pointer.func */
    em[1290] = 8884097; em[1291] = 8; em[1292] = 0; /* 1290: pointer.func */
    em[1293] = 8884097; em[1294] = 8; em[1295] = 0; /* 1293: pointer.func */
    em[1296] = 8884097; em[1297] = 8; em[1298] = 0; /* 1296: pointer.func */
    em[1299] = 8884097; em[1300] = 8; em[1301] = 0; /* 1299: pointer.func */
    em[1302] = 8884097; em[1303] = 8; em[1304] = 0; /* 1302: pointer.func */
    em[1305] = 8884097; em[1306] = 8; em[1307] = 0; /* 1305: pointer.func */
    em[1308] = 8884097; em[1309] = 8; em[1310] = 0; /* 1308: pointer.func */
    em[1311] = 8884097; em[1312] = 8; em[1313] = 0; /* 1311: pointer.func */
    em[1314] = 8884097; em[1315] = 8; em[1316] = 0; /* 1314: pointer.func */
    em[1317] = 8884097; em[1318] = 8; em[1319] = 0; /* 1317: pointer.func */
    em[1320] = 8884097; em[1321] = 8; em[1322] = 0; /* 1320: pointer.func */
    em[1323] = 8884097; em[1324] = 8; em[1325] = 0; /* 1323: pointer.func */
    em[1326] = 8884097; em[1327] = 8; em[1328] = 0; /* 1326: pointer.func */
    em[1329] = 8884097; em[1330] = 8; em[1331] = 0; /* 1329: pointer.func */
    em[1332] = 8884097; em[1333] = 8; em[1334] = 0; /* 1332: pointer.func */
    em[1335] = 8884097; em[1336] = 8; em[1337] = 0; /* 1335: pointer.func */
    em[1338] = 8884097; em[1339] = 8; em[1340] = 0; /* 1338: pointer.func */
    em[1341] = 8884097; em[1342] = 8; em[1343] = 0; /* 1341: pointer.func */
    em[1344] = 8884097; em[1345] = 8; em[1346] = 0; /* 1344: pointer.func */
    em[1347] = 8884097; em[1348] = 8; em[1349] = 0; /* 1347: pointer.func */
    em[1350] = 8884097; em[1351] = 8; em[1352] = 0; /* 1350: pointer.func */
    em[1353] = 8884097; em[1354] = 8; em[1355] = 0; /* 1353: pointer.func */
    em[1356] = 8884097; em[1357] = 8; em[1358] = 0; /* 1356: pointer.func */
    em[1359] = 8884097; em[1360] = 8; em[1361] = 0; /* 1359: pointer.func */
    em[1362] = 0; em[1363] = 24; em[1364] = 1; /* 1362: struct.bignum_st */
    	em[1365] = 1367; em[1366] = 0; 
    em[1367] = 8884099; em[1368] = 8; em[1369] = 2; /* 1367: pointer_to_array_of_pointers_to_stack */
    	em[1370] = 49; em[1371] = 0; 
    	em[1372] = 52; em[1373] = 12; 
    em[1374] = 0; em[1375] = 24; em[1376] = 1; /* 1374: struct.bignum_st */
    	em[1377] = 1379; em[1378] = 0; 
    em[1379] = 8884099; em[1380] = 8; em[1381] = 2; /* 1379: pointer_to_array_of_pointers_to_stack */
    	em[1382] = 49; em[1383] = 0; 
    	em[1384] = 52; em[1385] = 12; 
    em[1386] = 1; em[1387] = 8; em[1388] = 1; /* 1386: pointer.struct.ec_extra_data_st */
    	em[1389] = 1391; em[1390] = 0; 
    em[1391] = 0; em[1392] = 40; em[1393] = 5; /* 1391: struct.ec_extra_data_st */
    	em[1394] = 1404; em[1395] = 0; 
    	em[1396] = 91; em[1397] = 8; 
    	em[1398] = 1409; em[1399] = 16; 
    	em[1400] = 1412; em[1401] = 24; 
    	em[1402] = 1412; em[1403] = 32; 
    em[1404] = 1; em[1405] = 8; em[1406] = 1; /* 1404: pointer.struct.ec_extra_data_st */
    	em[1407] = 1391; em[1408] = 0; 
    em[1409] = 8884097; em[1410] = 8; em[1411] = 0; /* 1409: pointer.func */
    em[1412] = 8884097; em[1413] = 8; em[1414] = 0; /* 1412: pointer.func */
    em[1415] = 8884097; em[1416] = 8; em[1417] = 0; /* 1415: pointer.func */
    em[1418] = 1; em[1419] = 8; em[1420] = 1; /* 1418: pointer.struct.ec_point_st */
    	em[1421] = 1179; em[1422] = 0; 
    em[1423] = 1; em[1424] = 8; em[1425] = 1; /* 1423: pointer.struct.bignum_st */
    	em[1426] = 1428; em[1427] = 0; 
    em[1428] = 0; em[1429] = 24; em[1430] = 1; /* 1428: struct.bignum_st */
    	em[1431] = 1433; em[1432] = 0; 
    em[1433] = 8884099; em[1434] = 8; em[1435] = 2; /* 1433: pointer_to_array_of_pointers_to_stack */
    	em[1436] = 49; em[1437] = 0; 
    	em[1438] = 52; em[1439] = 12; 
    em[1440] = 1; em[1441] = 8; em[1442] = 1; /* 1440: pointer.struct.ec_extra_data_st */
    	em[1443] = 1445; em[1444] = 0; 
    em[1445] = 0; em[1446] = 40; em[1447] = 5; /* 1445: struct.ec_extra_data_st */
    	em[1448] = 1458; em[1449] = 0; 
    	em[1450] = 91; em[1451] = 8; 
    	em[1452] = 1409; em[1453] = 16; 
    	em[1454] = 1412; em[1455] = 24; 
    	em[1456] = 1412; em[1457] = 32; 
    em[1458] = 1; em[1459] = 8; em[1460] = 1; /* 1458: pointer.struct.ec_extra_data_st */
    	em[1461] = 1445; em[1462] = 0; 
    em[1463] = 1; em[1464] = 8; em[1465] = 1; /* 1463: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[1466] = 1468; em[1467] = 0; 
    em[1468] = 0; em[1469] = 32; em[1470] = 2; /* 1468: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[1471] = 1475; em[1472] = 8; 
    	em[1473] = 94; em[1474] = 24; 
    em[1475] = 8884099; em[1476] = 8; em[1477] = 2; /* 1475: pointer_to_array_of_pointers_to_stack */
    	em[1478] = 1482; em[1479] = 0; 
    	em[1480] = 52; em[1481] = 20; 
    em[1482] = 0; em[1483] = 8; em[1484] = 1; /* 1482: pointer.X509_ATTRIBUTE */
    	em[1485] = 1487; em[1486] = 0; 
    em[1487] = 0; em[1488] = 0; em[1489] = 1; /* 1487: X509_ATTRIBUTE */
    	em[1490] = 1492; em[1491] = 0; 
    em[1492] = 0; em[1493] = 24; em[1494] = 2; /* 1492: struct.x509_attributes_st */
    	em[1495] = 1499; em[1496] = 0; 
    	em[1497] = 1518; em[1498] = 16; 
    em[1499] = 1; em[1500] = 8; em[1501] = 1; /* 1499: pointer.struct.asn1_object_st */
    	em[1502] = 1504; em[1503] = 0; 
    em[1504] = 0; em[1505] = 40; em[1506] = 3; /* 1504: struct.asn1_object_st */
    	em[1507] = 121; em[1508] = 0; 
    	em[1509] = 121; em[1510] = 8; 
    	em[1511] = 1513; em[1512] = 24; 
    em[1513] = 1; em[1514] = 8; em[1515] = 1; /* 1513: pointer.unsigned char */
    	em[1516] = 74; em[1517] = 0; 
    em[1518] = 0; em[1519] = 8; em[1520] = 3; /* 1518: union.unknown */
    	em[1521] = 135; em[1522] = 0; 
    	em[1523] = 1527; em[1524] = 0; 
    	em[1525] = 1706; em[1526] = 0; 
    em[1527] = 1; em[1528] = 8; em[1529] = 1; /* 1527: pointer.struct.stack_st_ASN1_TYPE */
    	em[1530] = 1532; em[1531] = 0; 
    em[1532] = 0; em[1533] = 32; em[1534] = 2; /* 1532: struct.stack_st_fake_ASN1_TYPE */
    	em[1535] = 1539; em[1536] = 8; 
    	em[1537] = 94; em[1538] = 24; 
    em[1539] = 8884099; em[1540] = 8; em[1541] = 2; /* 1539: pointer_to_array_of_pointers_to_stack */
    	em[1542] = 1546; em[1543] = 0; 
    	em[1544] = 52; em[1545] = 20; 
    em[1546] = 0; em[1547] = 8; em[1548] = 1; /* 1546: pointer.ASN1_TYPE */
    	em[1549] = 1551; em[1550] = 0; 
    em[1551] = 0; em[1552] = 0; em[1553] = 1; /* 1551: ASN1_TYPE */
    	em[1554] = 1556; em[1555] = 0; 
    em[1556] = 0; em[1557] = 16; em[1558] = 1; /* 1556: struct.asn1_type_st */
    	em[1559] = 1561; em[1560] = 8; 
    em[1561] = 0; em[1562] = 8; em[1563] = 20; /* 1561: union.unknown */
    	em[1564] = 135; em[1565] = 0; 
    	em[1566] = 1604; em[1567] = 0; 
    	em[1568] = 1614; em[1569] = 0; 
    	em[1570] = 1628; em[1571] = 0; 
    	em[1572] = 1633; em[1573] = 0; 
    	em[1574] = 1638; em[1575] = 0; 
    	em[1576] = 1643; em[1577] = 0; 
    	em[1578] = 1648; em[1579] = 0; 
    	em[1580] = 1653; em[1581] = 0; 
    	em[1582] = 1658; em[1583] = 0; 
    	em[1584] = 1663; em[1585] = 0; 
    	em[1586] = 1668; em[1587] = 0; 
    	em[1588] = 1673; em[1589] = 0; 
    	em[1590] = 1678; em[1591] = 0; 
    	em[1592] = 1683; em[1593] = 0; 
    	em[1594] = 1688; em[1595] = 0; 
    	em[1596] = 1693; em[1597] = 0; 
    	em[1598] = 1604; em[1599] = 0; 
    	em[1600] = 1604; em[1601] = 0; 
    	em[1602] = 1698; em[1603] = 0; 
    em[1604] = 1; em[1605] = 8; em[1606] = 1; /* 1604: pointer.struct.asn1_string_st */
    	em[1607] = 1609; em[1608] = 0; 
    em[1609] = 0; em[1610] = 24; em[1611] = 1; /* 1609: struct.asn1_string_st */
    	em[1612] = 69; em[1613] = 8; 
    em[1614] = 1; em[1615] = 8; em[1616] = 1; /* 1614: pointer.struct.asn1_object_st */
    	em[1617] = 1619; em[1618] = 0; 
    em[1619] = 0; em[1620] = 40; em[1621] = 3; /* 1619: struct.asn1_object_st */
    	em[1622] = 121; em[1623] = 0; 
    	em[1624] = 121; em[1625] = 8; 
    	em[1626] = 1513; em[1627] = 24; 
    em[1628] = 1; em[1629] = 8; em[1630] = 1; /* 1628: pointer.struct.asn1_string_st */
    	em[1631] = 1609; em[1632] = 0; 
    em[1633] = 1; em[1634] = 8; em[1635] = 1; /* 1633: pointer.struct.asn1_string_st */
    	em[1636] = 1609; em[1637] = 0; 
    em[1638] = 1; em[1639] = 8; em[1640] = 1; /* 1638: pointer.struct.asn1_string_st */
    	em[1641] = 1609; em[1642] = 0; 
    em[1643] = 1; em[1644] = 8; em[1645] = 1; /* 1643: pointer.struct.asn1_string_st */
    	em[1646] = 1609; em[1647] = 0; 
    em[1648] = 1; em[1649] = 8; em[1650] = 1; /* 1648: pointer.struct.asn1_string_st */
    	em[1651] = 1609; em[1652] = 0; 
    em[1653] = 1; em[1654] = 8; em[1655] = 1; /* 1653: pointer.struct.asn1_string_st */
    	em[1656] = 1609; em[1657] = 0; 
    em[1658] = 1; em[1659] = 8; em[1660] = 1; /* 1658: pointer.struct.asn1_string_st */
    	em[1661] = 1609; em[1662] = 0; 
    em[1663] = 1; em[1664] = 8; em[1665] = 1; /* 1663: pointer.struct.asn1_string_st */
    	em[1666] = 1609; em[1667] = 0; 
    em[1668] = 1; em[1669] = 8; em[1670] = 1; /* 1668: pointer.struct.asn1_string_st */
    	em[1671] = 1609; em[1672] = 0; 
    em[1673] = 1; em[1674] = 8; em[1675] = 1; /* 1673: pointer.struct.asn1_string_st */
    	em[1676] = 1609; em[1677] = 0; 
    em[1678] = 1; em[1679] = 8; em[1680] = 1; /* 1678: pointer.struct.asn1_string_st */
    	em[1681] = 1609; em[1682] = 0; 
    em[1683] = 1; em[1684] = 8; em[1685] = 1; /* 1683: pointer.struct.asn1_string_st */
    	em[1686] = 1609; em[1687] = 0; 
    em[1688] = 1; em[1689] = 8; em[1690] = 1; /* 1688: pointer.struct.asn1_string_st */
    	em[1691] = 1609; em[1692] = 0; 
    em[1693] = 1; em[1694] = 8; em[1695] = 1; /* 1693: pointer.struct.asn1_string_st */
    	em[1696] = 1609; em[1697] = 0; 
    em[1698] = 1; em[1699] = 8; em[1700] = 1; /* 1698: pointer.struct.ASN1_VALUE_st */
    	em[1701] = 1703; em[1702] = 0; 
    em[1703] = 0; em[1704] = 0; em[1705] = 0; /* 1703: struct.ASN1_VALUE_st */
    em[1706] = 1; em[1707] = 8; em[1708] = 1; /* 1706: pointer.struct.asn1_type_st */
    	em[1709] = 1711; em[1710] = 0; 
    em[1711] = 0; em[1712] = 16; em[1713] = 1; /* 1711: struct.asn1_type_st */
    	em[1714] = 1716; em[1715] = 8; 
    em[1716] = 0; em[1717] = 8; em[1718] = 20; /* 1716: union.unknown */
    	em[1719] = 135; em[1720] = 0; 
    	em[1721] = 1759; em[1722] = 0; 
    	em[1723] = 1499; em[1724] = 0; 
    	em[1725] = 1769; em[1726] = 0; 
    	em[1727] = 1774; em[1728] = 0; 
    	em[1729] = 1779; em[1730] = 0; 
    	em[1731] = 1784; em[1732] = 0; 
    	em[1733] = 1789; em[1734] = 0; 
    	em[1735] = 1794; em[1736] = 0; 
    	em[1737] = 1799; em[1738] = 0; 
    	em[1739] = 1804; em[1740] = 0; 
    	em[1741] = 1809; em[1742] = 0; 
    	em[1743] = 1814; em[1744] = 0; 
    	em[1745] = 1819; em[1746] = 0; 
    	em[1747] = 1824; em[1748] = 0; 
    	em[1749] = 1829; em[1750] = 0; 
    	em[1751] = 1834; em[1752] = 0; 
    	em[1753] = 1759; em[1754] = 0; 
    	em[1755] = 1759; em[1756] = 0; 
    	em[1757] = 1839; em[1758] = 0; 
    em[1759] = 1; em[1760] = 8; em[1761] = 1; /* 1759: pointer.struct.asn1_string_st */
    	em[1762] = 1764; em[1763] = 0; 
    em[1764] = 0; em[1765] = 24; em[1766] = 1; /* 1764: struct.asn1_string_st */
    	em[1767] = 69; em[1768] = 8; 
    em[1769] = 1; em[1770] = 8; em[1771] = 1; /* 1769: pointer.struct.asn1_string_st */
    	em[1772] = 1764; em[1773] = 0; 
    em[1774] = 1; em[1775] = 8; em[1776] = 1; /* 1774: pointer.struct.asn1_string_st */
    	em[1777] = 1764; em[1778] = 0; 
    em[1779] = 1; em[1780] = 8; em[1781] = 1; /* 1779: pointer.struct.asn1_string_st */
    	em[1782] = 1764; em[1783] = 0; 
    em[1784] = 1; em[1785] = 8; em[1786] = 1; /* 1784: pointer.struct.asn1_string_st */
    	em[1787] = 1764; em[1788] = 0; 
    em[1789] = 1; em[1790] = 8; em[1791] = 1; /* 1789: pointer.struct.asn1_string_st */
    	em[1792] = 1764; em[1793] = 0; 
    em[1794] = 1; em[1795] = 8; em[1796] = 1; /* 1794: pointer.struct.asn1_string_st */
    	em[1797] = 1764; em[1798] = 0; 
    em[1799] = 1; em[1800] = 8; em[1801] = 1; /* 1799: pointer.struct.asn1_string_st */
    	em[1802] = 1764; em[1803] = 0; 
    em[1804] = 1; em[1805] = 8; em[1806] = 1; /* 1804: pointer.struct.asn1_string_st */
    	em[1807] = 1764; em[1808] = 0; 
    em[1809] = 1; em[1810] = 8; em[1811] = 1; /* 1809: pointer.struct.asn1_string_st */
    	em[1812] = 1764; em[1813] = 0; 
    em[1814] = 1; em[1815] = 8; em[1816] = 1; /* 1814: pointer.struct.asn1_string_st */
    	em[1817] = 1764; em[1818] = 0; 
    em[1819] = 1; em[1820] = 8; em[1821] = 1; /* 1819: pointer.struct.asn1_string_st */
    	em[1822] = 1764; em[1823] = 0; 
    em[1824] = 1; em[1825] = 8; em[1826] = 1; /* 1824: pointer.struct.asn1_string_st */
    	em[1827] = 1764; em[1828] = 0; 
    em[1829] = 1; em[1830] = 8; em[1831] = 1; /* 1829: pointer.struct.asn1_string_st */
    	em[1832] = 1764; em[1833] = 0; 
    em[1834] = 1; em[1835] = 8; em[1836] = 1; /* 1834: pointer.struct.asn1_string_st */
    	em[1837] = 1764; em[1838] = 0; 
    em[1839] = 1; em[1840] = 8; em[1841] = 1; /* 1839: pointer.struct.ASN1_VALUE_st */
    	em[1842] = 1844; em[1843] = 0; 
    em[1844] = 0; em[1845] = 0; em[1846] = 0; /* 1844: struct.ASN1_VALUE_st */
    em[1847] = 0; em[1848] = 0; em[1849] = 1; /* 1847: X509_ALGOR */
    	em[1850] = 1852; em[1851] = 0; 
    em[1852] = 0; em[1853] = 16; em[1854] = 2; /* 1852: struct.X509_algor_st */
    	em[1855] = 1859; em[1856] = 0; 
    	em[1857] = 1873; em[1858] = 8; 
    em[1859] = 1; em[1860] = 8; em[1861] = 1; /* 1859: pointer.struct.asn1_object_st */
    	em[1862] = 1864; em[1863] = 0; 
    em[1864] = 0; em[1865] = 40; em[1866] = 3; /* 1864: struct.asn1_object_st */
    	em[1867] = 121; em[1868] = 0; 
    	em[1869] = 121; em[1870] = 8; 
    	em[1871] = 1513; em[1872] = 24; 
    em[1873] = 1; em[1874] = 8; em[1875] = 1; /* 1873: pointer.struct.asn1_type_st */
    	em[1876] = 1878; em[1877] = 0; 
    em[1878] = 0; em[1879] = 16; em[1880] = 1; /* 1878: struct.asn1_type_st */
    	em[1881] = 1883; em[1882] = 8; 
    em[1883] = 0; em[1884] = 8; em[1885] = 20; /* 1883: union.unknown */
    	em[1886] = 135; em[1887] = 0; 
    	em[1888] = 1926; em[1889] = 0; 
    	em[1890] = 1859; em[1891] = 0; 
    	em[1892] = 1936; em[1893] = 0; 
    	em[1894] = 1941; em[1895] = 0; 
    	em[1896] = 1946; em[1897] = 0; 
    	em[1898] = 1951; em[1899] = 0; 
    	em[1900] = 1956; em[1901] = 0; 
    	em[1902] = 1961; em[1903] = 0; 
    	em[1904] = 1966; em[1905] = 0; 
    	em[1906] = 1971; em[1907] = 0; 
    	em[1908] = 1976; em[1909] = 0; 
    	em[1910] = 1981; em[1911] = 0; 
    	em[1912] = 1986; em[1913] = 0; 
    	em[1914] = 1991; em[1915] = 0; 
    	em[1916] = 1996; em[1917] = 0; 
    	em[1918] = 2001; em[1919] = 0; 
    	em[1920] = 1926; em[1921] = 0; 
    	em[1922] = 1926; em[1923] = 0; 
    	em[1924] = 1839; em[1925] = 0; 
    em[1926] = 1; em[1927] = 8; em[1928] = 1; /* 1926: pointer.struct.asn1_string_st */
    	em[1929] = 1931; em[1930] = 0; 
    em[1931] = 0; em[1932] = 24; em[1933] = 1; /* 1931: struct.asn1_string_st */
    	em[1934] = 69; em[1935] = 8; 
    em[1936] = 1; em[1937] = 8; em[1938] = 1; /* 1936: pointer.struct.asn1_string_st */
    	em[1939] = 1931; em[1940] = 0; 
    em[1941] = 1; em[1942] = 8; em[1943] = 1; /* 1941: pointer.struct.asn1_string_st */
    	em[1944] = 1931; em[1945] = 0; 
    em[1946] = 1; em[1947] = 8; em[1948] = 1; /* 1946: pointer.struct.asn1_string_st */
    	em[1949] = 1931; em[1950] = 0; 
    em[1951] = 1; em[1952] = 8; em[1953] = 1; /* 1951: pointer.struct.asn1_string_st */
    	em[1954] = 1931; em[1955] = 0; 
    em[1956] = 1; em[1957] = 8; em[1958] = 1; /* 1956: pointer.struct.asn1_string_st */
    	em[1959] = 1931; em[1960] = 0; 
    em[1961] = 1; em[1962] = 8; em[1963] = 1; /* 1961: pointer.struct.asn1_string_st */
    	em[1964] = 1931; em[1965] = 0; 
    em[1966] = 1; em[1967] = 8; em[1968] = 1; /* 1966: pointer.struct.asn1_string_st */
    	em[1969] = 1931; em[1970] = 0; 
    em[1971] = 1; em[1972] = 8; em[1973] = 1; /* 1971: pointer.struct.asn1_string_st */
    	em[1974] = 1931; em[1975] = 0; 
    em[1976] = 1; em[1977] = 8; em[1978] = 1; /* 1976: pointer.struct.asn1_string_st */
    	em[1979] = 1931; em[1980] = 0; 
    em[1981] = 1; em[1982] = 8; em[1983] = 1; /* 1981: pointer.struct.asn1_string_st */
    	em[1984] = 1931; em[1985] = 0; 
    em[1986] = 1; em[1987] = 8; em[1988] = 1; /* 1986: pointer.struct.asn1_string_st */
    	em[1989] = 1931; em[1990] = 0; 
    em[1991] = 1; em[1992] = 8; em[1993] = 1; /* 1991: pointer.struct.asn1_string_st */
    	em[1994] = 1931; em[1995] = 0; 
    em[1996] = 1; em[1997] = 8; em[1998] = 1; /* 1996: pointer.struct.asn1_string_st */
    	em[1999] = 1931; em[2000] = 0; 
    em[2001] = 1; em[2002] = 8; em[2003] = 1; /* 2001: pointer.struct.asn1_string_st */
    	em[2004] = 1931; em[2005] = 0; 
    em[2006] = 1; em[2007] = 8; em[2008] = 1; /* 2006: pointer.struct.stack_st_X509_ALGOR */
    	em[2009] = 2011; em[2010] = 0; 
    em[2011] = 0; em[2012] = 32; em[2013] = 2; /* 2011: struct.stack_st_fake_X509_ALGOR */
    	em[2014] = 2018; em[2015] = 8; 
    	em[2016] = 94; em[2017] = 24; 
    em[2018] = 8884099; em[2019] = 8; em[2020] = 2; /* 2018: pointer_to_array_of_pointers_to_stack */
    	em[2021] = 2025; em[2022] = 0; 
    	em[2023] = 52; em[2024] = 20; 
    em[2025] = 0; em[2026] = 8; em[2027] = 1; /* 2025: pointer.X509_ALGOR */
    	em[2028] = 1847; em[2029] = 0; 
    em[2030] = 1; em[2031] = 8; em[2032] = 1; /* 2030: pointer.struct.asn1_string_st */
    	em[2033] = 2035; em[2034] = 0; 
    em[2035] = 0; em[2036] = 24; em[2037] = 1; /* 2035: struct.asn1_string_st */
    	em[2038] = 69; em[2039] = 8; 
    em[2040] = 0; em[2041] = 40; em[2042] = 5; /* 2040: struct.x509_cert_aux_st */
    	em[2043] = 2053; em[2044] = 0; 
    	em[2045] = 2053; em[2046] = 8; 
    	em[2047] = 2030; em[2048] = 16; 
    	em[2049] = 2091; em[2050] = 24; 
    	em[2051] = 2006; em[2052] = 32; 
    em[2053] = 1; em[2054] = 8; em[2055] = 1; /* 2053: pointer.struct.stack_st_ASN1_OBJECT */
    	em[2056] = 2058; em[2057] = 0; 
    em[2058] = 0; em[2059] = 32; em[2060] = 2; /* 2058: struct.stack_st_fake_ASN1_OBJECT */
    	em[2061] = 2065; em[2062] = 8; 
    	em[2063] = 94; em[2064] = 24; 
    em[2065] = 8884099; em[2066] = 8; em[2067] = 2; /* 2065: pointer_to_array_of_pointers_to_stack */
    	em[2068] = 2072; em[2069] = 0; 
    	em[2070] = 52; em[2071] = 20; 
    em[2072] = 0; em[2073] = 8; em[2074] = 1; /* 2072: pointer.ASN1_OBJECT */
    	em[2075] = 2077; em[2076] = 0; 
    em[2077] = 0; em[2078] = 0; em[2079] = 1; /* 2077: ASN1_OBJECT */
    	em[2080] = 2082; em[2081] = 0; 
    em[2082] = 0; em[2083] = 40; em[2084] = 3; /* 2082: struct.asn1_object_st */
    	em[2085] = 121; em[2086] = 0; 
    	em[2087] = 121; em[2088] = 8; 
    	em[2089] = 1513; em[2090] = 24; 
    em[2091] = 1; em[2092] = 8; em[2093] = 1; /* 2091: pointer.struct.asn1_string_st */
    	em[2094] = 2035; em[2095] = 0; 
    em[2096] = 1; em[2097] = 8; em[2098] = 1; /* 2096: pointer.struct.x509_cert_aux_st */
    	em[2099] = 2040; em[2100] = 0; 
    em[2101] = 1; em[2102] = 8; em[2103] = 1; /* 2101: pointer.struct.EDIPartyName_st */
    	em[2104] = 2106; em[2105] = 0; 
    em[2106] = 0; em[2107] = 16; em[2108] = 2; /* 2106: struct.EDIPartyName_st */
    	em[2109] = 2113; em[2110] = 0; 
    	em[2111] = 2113; em[2112] = 8; 
    em[2113] = 1; em[2114] = 8; em[2115] = 1; /* 2113: pointer.struct.asn1_string_st */
    	em[2116] = 2118; em[2117] = 0; 
    em[2118] = 0; em[2119] = 24; em[2120] = 1; /* 2118: struct.asn1_string_st */
    	em[2121] = 69; em[2122] = 8; 
    em[2123] = 1; em[2124] = 8; em[2125] = 1; /* 2123: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[2126] = 2128; em[2127] = 0; 
    em[2128] = 0; em[2129] = 32; em[2130] = 2; /* 2128: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[2131] = 2135; em[2132] = 8; 
    	em[2133] = 94; em[2134] = 24; 
    em[2135] = 8884099; em[2136] = 8; em[2137] = 2; /* 2135: pointer_to_array_of_pointers_to_stack */
    	em[2138] = 2142; em[2139] = 0; 
    	em[2140] = 52; em[2141] = 20; 
    em[2142] = 0; em[2143] = 8; em[2144] = 1; /* 2142: pointer.X509_NAME_ENTRY */
    	em[2145] = 2147; em[2146] = 0; 
    em[2147] = 0; em[2148] = 0; em[2149] = 1; /* 2147: X509_NAME_ENTRY */
    	em[2150] = 2152; em[2151] = 0; 
    em[2152] = 0; em[2153] = 24; em[2154] = 2; /* 2152: struct.X509_name_entry_st */
    	em[2155] = 2159; em[2156] = 0; 
    	em[2157] = 2173; em[2158] = 8; 
    em[2159] = 1; em[2160] = 8; em[2161] = 1; /* 2159: pointer.struct.asn1_object_st */
    	em[2162] = 2164; em[2163] = 0; 
    em[2164] = 0; em[2165] = 40; em[2166] = 3; /* 2164: struct.asn1_object_st */
    	em[2167] = 121; em[2168] = 0; 
    	em[2169] = 121; em[2170] = 8; 
    	em[2171] = 1513; em[2172] = 24; 
    em[2173] = 1; em[2174] = 8; em[2175] = 1; /* 2173: pointer.struct.asn1_string_st */
    	em[2176] = 2178; em[2177] = 0; 
    em[2178] = 0; em[2179] = 24; em[2180] = 1; /* 2178: struct.asn1_string_st */
    	em[2181] = 69; em[2182] = 8; 
    em[2183] = 0; em[2184] = 40; em[2185] = 3; /* 2183: struct.X509_name_st */
    	em[2186] = 2123; em[2187] = 0; 
    	em[2188] = 2192; em[2189] = 16; 
    	em[2190] = 69; em[2191] = 24; 
    em[2192] = 1; em[2193] = 8; em[2194] = 1; /* 2192: pointer.struct.buf_mem_st */
    	em[2195] = 2197; em[2196] = 0; 
    em[2197] = 0; em[2198] = 24; em[2199] = 1; /* 2197: struct.buf_mem_st */
    	em[2200] = 135; em[2201] = 8; 
    em[2202] = 1; em[2203] = 8; em[2204] = 1; /* 2202: pointer.struct.X509_name_st */
    	em[2205] = 2183; em[2206] = 0; 
    em[2207] = 1; em[2208] = 8; em[2209] = 1; /* 2207: pointer.struct.asn1_string_st */
    	em[2210] = 2118; em[2211] = 0; 
    em[2212] = 1; em[2213] = 8; em[2214] = 1; /* 2212: pointer.struct.asn1_string_st */
    	em[2215] = 2118; em[2216] = 0; 
    em[2217] = 1; em[2218] = 8; em[2219] = 1; /* 2217: pointer.struct.asn1_string_st */
    	em[2220] = 2118; em[2221] = 0; 
    em[2222] = 1; em[2223] = 8; em[2224] = 1; /* 2222: pointer.struct.asn1_string_st */
    	em[2225] = 2118; em[2226] = 0; 
    em[2227] = 1; em[2228] = 8; em[2229] = 1; /* 2227: pointer.struct.asn1_string_st */
    	em[2230] = 2118; em[2231] = 0; 
    em[2232] = 1; em[2233] = 8; em[2234] = 1; /* 2232: pointer.struct.asn1_string_st */
    	em[2235] = 2118; em[2236] = 0; 
    em[2237] = 1; em[2238] = 8; em[2239] = 1; /* 2237: pointer.struct.asn1_string_st */
    	em[2240] = 2118; em[2241] = 0; 
    em[2242] = 0; em[2243] = 8; em[2244] = 20; /* 2242: union.unknown */
    	em[2245] = 135; em[2246] = 0; 
    	em[2247] = 2113; em[2248] = 0; 
    	em[2249] = 2285; em[2250] = 0; 
    	em[2251] = 2299; em[2252] = 0; 
    	em[2253] = 2304; em[2254] = 0; 
    	em[2255] = 2309; em[2256] = 0; 
    	em[2257] = 2237; em[2258] = 0; 
    	em[2259] = 2232; em[2260] = 0; 
    	em[2261] = 2227; em[2262] = 0; 
    	em[2263] = 2314; em[2264] = 0; 
    	em[2265] = 2222; em[2266] = 0; 
    	em[2267] = 2217; em[2268] = 0; 
    	em[2269] = 2319; em[2270] = 0; 
    	em[2271] = 2212; em[2272] = 0; 
    	em[2273] = 2207; em[2274] = 0; 
    	em[2275] = 2324; em[2276] = 0; 
    	em[2277] = 2329; em[2278] = 0; 
    	em[2279] = 2113; em[2280] = 0; 
    	em[2281] = 2113; em[2282] = 0; 
    	em[2283] = 2334; em[2284] = 0; 
    em[2285] = 1; em[2286] = 8; em[2287] = 1; /* 2285: pointer.struct.asn1_object_st */
    	em[2288] = 2290; em[2289] = 0; 
    em[2290] = 0; em[2291] = 40; em[2292] = 3; /* 2290: struct.asn1_object_st */
    	em[2293] = 121; em[2294] = 0; 
    	em[2295] = 121; em[2296] = 8; 
    	em[2297] = 1513; em[2298] = 24; 
    em[2299] = 1; em[2300] = 8; em[2301] = 1; /* 2299: pointer.struct.asn1_string_st */
    	em[2302] = 2118; em[2303] = 0; 
    em[2304] = 1; em[2305] = 8; em[2306] = 1; /* 2304: pointer.struct.asn1_string_st */
    	em[2307] = 2118; em[2308] = 0; 
    em[2309] = 1; em[2310] = 8; em[2311] = 1; /* 2309: pointer.struct.asn1_string_st */
    	em[2312] = 2118; em[2313] = 0; 
    em[2314] = 1; em[2315] = 8; em[2316] = 1; /* 2314: pointer.struct.asn1_string_st */
    	em[2317] = 2118; em[2318] = 0; 
    em[2319] = 1; em[2320] = 8; em[2321] = 1; /* 2319: pointer.struct.asn1_string_st */
    	em[2322] = 2118; em[2323] = 0; 
    em[2324] = 1; em[2325] = 8; em[2326] = 1; /* 2324: pointer.struct.asn1_string_st */
    	em[2327] = 2118; em[2328] = 0; 
    em[2329] = 1; em[2330] = 8; em[2331] = 1; /* 2329: pointer.struct.asn1_string_st */
    	em[2332] = 2118; em[2333] = 0; 
    em[2334] = 1; em[2335] = 8; em[2336] = 1; /* 2334: pointer.struct.ASN1_VALUE_st */
    	em[2337] = 2339; em[2338] = 0; 
    em[2339] = 0; em[2340] = 0; em[2341] = 0; /* 2339: struct.ASN1_VALUE_st */
    em[2342] = 1; em[2343] = 8; em[2344] = 1; /* 2342: pointer.struct.otherName_st */
    	em[2345] = 2347; em[2346] = 0; 
    em[2347] = 0; em[2348] = 16; em[2349] = 2; /* 2347: struct.otherName_st */
    	em[2350] = 2285; em[2351] = 0; 
    	em[2352] = 2354; em[2353] = 8; 
    em[2354] = 1; em[2355] = 8; em[2356] = 1; /* 2354: pointer.struct.asn1_type_st */
    	em[2357] = 2359; em[2358] = 0; 
    em[2359] = 0; em[2360] = 16; em[2361] = 1; /* 2359: struct.asn1_type_st */
    	em[2362] = 2242; em[2363] = 8; 
    em[2364] = 0; em[2365] = 16; em[2366] = 1; /* 2364: struct.GENERAL_NAME_st */
    	em[2367] = 2369; em[2368] = 8; 
    em[2369] = 0; em[2370] = 8; em[2371] = 15; /* 2369: union.unknown */
    	em[2372] = 135; em[2373] = 0; 
    	em[2374] = 2342; em[2375] = 0; 
    	em[2376] = 2314; em[2377] = 0; 
    	em[2378] = 2314; em[2379] = 0; 
    	em[2380] = 2354; em[2381] = 0; 
    	em[2382] = 2202; em[2383] = 0; 
    	em[2384] = 2101; em[2385] = 0; 
    	em[2386] = 2314; em[2387] = 0; 
    	em[2388] = 2237; em[2389] = 0; 
    	em[2390] = 2285; em[2391] = 0; 
    	em[2392] = 2237; em[2393] = 0; 
    	em[2394] = 2202; em[2395] = 0; 
    	em[2396] = 2314; em[2397] = 0; 
    	em[2398] = 2285; em[2399] = 0; 
    	em[2400] = 2354; em[2401] = 0; 
    em[2402] = 1; em[2403] = 8; em[2404] = 1; /* 2402: pointer.struct.GENERAL_NAME_st */
    	em[2405] = 2364; em[2406] = 0; 
    em[2407] = 0; em[2408] = 24; em[2409] = 3; /* 2407: struct.GENERAL_SUBTREE_st */
    	em[2410] = 2402; em[2411] = 0; 
    	em[2412] = 2299; em[2413] = 8; 
    	em[2414] = 2299; em[2415] = 16; 
    em[2416] = 1; em[2417] = 8; em[2418] = 1; /* 2416: pointer.struct.NAME_CONSTRAINTS_st */
    	em[2419] = 2421; em[2420] = 0; 
    em[2421] = 0; em[2422] = 16; em[2423] = 2; /* 2421: struct.NAME_CONSTRAINTS_st */
    	em[2424] = 2428; em[2425] = 0; 
    	em[2426] = 2428; em[2427] = 8; 
    em[2428] = 1; em[2429] = 8; em[2430] = 1; /* 2428: pointer.struct.stack_st_GENERAL_SUBTREE */
    	em[2431] = 2433; em[2432] = 0; 
    em[2433] = 0; em[2434] = 32; em[2435] = 2; /* 2433: struct.stack_st_fake_GENERAL_SUBTREE */
    	em[2436] = 2440; em[2437] = 8; 
    	em[2438] = 94; em[2439] = 24; 
    em[2440] = 8884099; em[2441] = 8; em[2442] = 2; /* 2440: pointer_to_array_of_pointers_to_stack */
    	em[2443] = 2447; em[2444] = 0; 
    	em[2445] = 52; em[2446] = 20; 
    em[2447] = 0; em[2448] = 8; em[2449] = 1; /* 2447: pointer.GENERAL_SUBTREE */
    	em[2450] = 2452; em[2451] = 0; 
    em[2452] = 0; em[2453] = 0; em[2454] = 1; /* 2452: GENERAL_SUBTREE */
    	em[2455] = 2407; em[2456] = 0; 
    em[2457] = 1; em[2458] = 8; em[2459] = 1; /* 2457: pointer.struct.stack_st_GENERAL_NAME */
    	em[2460] = 2462; em[2461] = 0; 
    em[2462] = 0; em[2463] = 32; em[2464] = 2; /* 2462: struct.stack_st_fake_GENERAL_NAME */
    	em[2465] = 2469; em[2466] = 8; 
    	em[2467] = 94; em[2468] = 24; 
    em[2469] = 8884099; em[2470] = 8; em[2471] = 2; /* 2469: pointer_to_array_of_pointers_to_stack */
    	em[2472] = 2476; em[2473] = 0; 
    	em[2474] = 52; em[2475] = 20; 
    em[2476] = 0; em[2477] = 8; em[2478] = 1; /* 2476: pointer.GENERAL_NAME */
    	em[2479] = 2481; em[2480] = 0; 
    em[2481] = 0; em[2482] = 0; em[2483] = 1; /* 2481: GENERAL_NAME */
    	em[2484] = 2486; em[2485] = 0; 
    em[2486] = 0; em[2487] = 16; em[2488] = 1; /* 2486: struct.GENERAL_NAME_st */
    	em[2489] = 2491; em[2490] = 8; 
    em[2491] = 0; em[2492] = 8; em[2493] = 15; /* 2491: union.unknown */
    	em[2494] = 135; em[2495] = 0; 
    	em[2496] = 2524; em[2497] = 0; 
    	em[2498] = 2643; em[2499] = 0; 
    	em[2500] = 2643; em[2501] = 0; 
    	em[2502] = 2550; em[2503] = 0; 
    	em[2504] = 2691; em[2505] = 0; 
    	em[2506] = 2739; em[2507] = 0; 
    	em[2508] = 2643; em[2509] = 0; 
    	em[2510] = 2628; em[2511] = 0; 
    	em[2512] = 2536; em[2513] = 0; 
    	em[2514] = 2628; em[2515] = 0; 
    	em[2516] = 2691; em[2517] = 0; 
    	em[2518] = 2643; em[2519] = 0; 
    	em[2520] = 2536; em[2521] = 0; 
    	em[2522] = 2550; em[2523] = 0; 
    em[2524] = 1; em[2525] = 8; em[2526] = 1; /* 2524: pointer.struct.otherName_st */
    	em[2527] = 2529; em[2528] = 0; 
    em[2529] = 0; em[2530] = 16; em[2531] = 2; /* 2529: struct.otherName_st */
    	em[2532] = 2536; em[2533] = 0; 
    	em[2534] = 2550; em[2535] = 8; 
    em[2536] = 1; em[2537] = 8; em[2538] = 1; /* 2536: pointer.struct.asn1_object_st */
    	em[2539] = 2541; em[2540] = 0; 
    em[2541] = 0; em[2542] = 40; em[2543] = 3; /* 2541: struct.asn1_object_st */
    	em[2544] = 121; em[2545] = 0; 
    	em[2546] = 121; em[2547] = 8; 
    	em[2548] = 1513; em[2549] = 24; 
    em[2550] = 1; em[2551] = 8; em[2552] = 1; /* 2550: pointer.struct.asn1_type_st */
    	em[2553] = 2555; em[2554] = 0; 
    em[2555] = 0; em[2556] = 16; em[2557] = 1; /* 2555: struct.asn1_type_st */
    	em[2558] = 2560; em[2559] = 8; 
    em[2560] = 0; em[2561] = 8; em[2562] = 20; /* 2560: union.unknown */
    	em[2563] = 135; em[2564] = 0; 
    	em[2565] = 2603; em[2566] = 0; 
    	em[2567] = 2536; em[2568] = 0; 
    	em[2569] = 2613; em[2570] = 0; 
    	em[2571] = 2618; em[2572] = 0; 
    	em[2573] = 2623; em[2574] = 0; 
    	em[2575] = 2628; em[2576] = 0; 
    	em[2577] = 2633; em[2578] = 0; 
    	em[2579] = 2638; em[2580] = 0; 
    	em[2581] = 2643; em[2582] = 0; 
    	em[2583] = 2648; em[2584] = 0; 
    	em[2585] = 2653; em[2586] = 0; 
    	em[2587] = 2658; em[2588] = 0; 
    	em[2589] = 2663; em[2590] = 0; 
    	em[2591] = 2668; em[2592] = 0; 
    	em[2593] = 2673; em[2594] = 0; 
    	em[2595] = 2678; em[2596] = 0; 
    	em[2597] = 2603; em[2598] = 0; 
    	em[2599] = 2603; em[2600] = 0; 
    	em[2601] = 2683; em[2602] = 0; 
    em[2603] = 1; em[2604] = 8; em[2605] = 1; /* 2603: pointer.struct.asn1_string_st */
    	em[2606] = 2608; em[2607] = 0; 
    em[2608] = 0; em[2609] = 24; em[2610] = 1; /* 2608: struct.asn1_string_st */
    	em[2611] = 69; em[2612] = 8; 
    em[2613] = 1; em[2614] = 8; em[2615] = 1; /* 2613: pointer.struct.asn1_string_st */
    	em[2616] = 2608; em[2617] = 0; 
    em[2618] = 1; em[2619] = 8; em[2620] = 1; /* 2618: pointer.struct.asn1_string_st */
    	em[2621] = 2608; em[2622] = 0; 
    em[2623] = 1; em[2624] = 8; em[2625] = 1; /* 2623: pointer.struct.asn1_string_st */
    	em[2626] = 2608; em[2627] = 0; 
    em[2628] = 1; em[2629] = 8; em[2630] = 1; /* 2628: pointer.struct.asn1_string_st */
    	em[2631] = 2608; em[2632] = 0; 
    em[2633] = 1; em[2634] = 8; em[2635] = 1; /* 2633: pointer.struct.asn1_string_st */
    	em[2636] = 2608; em[2637] = 0; 
    em[2638] = 1; em[2639] = 8; em[2640] = 1; /* 2638: pointer.struct.asn1_string_st */
    	em[2641] = 2608; em[2642] = 0; 
    em[2643] = 1; em[2644] = 8; em[2645] = 1; /* 2643: pointer.struct.asn1_string_st */
    	em[2646] = 2608; em[2647] = 0; 
    em[2648] = 1; em[2649] = 8; em[2650] = 1; /* 2648: pointer.struct.asn1_string_st */
    	em[2651] = 2608; em[2652] = 0; 
    em[2653] = 1; em[2654] = 8; em[2655] = 1; /* 2653: pointer.struct.asn1_string_st */
    	em[2656] = 2608; em[2657] = 0; 
    em[2658] = 1; em[2659] = 8; em[2660] = 1; /* 2658: pointer.struct.asn1_string_st */
    	em[2661] = 2608; em[2662] = 0; 
    em[2663] = 1; em[2664] = 8; em[2665] = 1; /* 2663: pointer.struct.asn1_string_st */
    	em[2666] = 2608; em[2667] = 0; 
    em[2668] = 1; em[2669] = 8; em[2670] = 1; /* 2668: pointer.struct.asn1_string_st */
    	em[2671] = 2608; em[2672] = 0; 
    em[2673] = 1; em[2674] = 8; em[2675] = 1; /* 2673: pointer.struct.asn1_string_st */
    	em[2676] = 2608; em[2677] = 0; 
    em[2678] = 1; em[2679] = 8; em[2680] = 1; /* 2678: pointer.struct.asn1_string_st */
    	em[2681] = 2608; em[2682] = 0; 
    em[2683] = 1; em[2684] = 8; em[2685] = 1; /* 2683: pointer.struct.ASN1_VALUE_st */
    	em[2686] = 2688; em[2687] = 0; 
    em[2688] = 0; em[2689] = 0; em[2690] = 0; /* 2688: struct.ASN1_VALUE_st */
    em[2691] = 1; em[2692] = 8; em[2693] = 1; /* 2691: pointer.struct.X509_name_st */
    	em[2694] = 2696; em[2695] = 0; 
    em[2696] = 0; em[2697] = 40; em[2698] = 3; /* 2696: struct.X509_name_st */
    	em[2699] = 2705; em[2700] = 0; 
    	em[2701] = 2729; em[2702] = 16; 
    	em[2703] = 69; em[2704] = 24; 
    em[2705] = 1; em[2706] = 8; em[2707] = 1; /* 2705: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[2708] = 2710; em[2709] = 0; 
    em[2710] = 0; em[2711] = 32; em[2712] = 2; /* 2710: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[2713] = 2717; em[2714] = 8; 
    	em[2715] = 94; em[2716] = 24; 
    em[2717] = 8884099; em[2718] = 8; em[2719] = 2; /* 2717: pointer_to_array_of_pointers_to_stack */
    	em[2720] = 2724; em[2721] = 0; 
    	em[2722] = 52; em[2723] = 20; 
    em[2724] = 0; em[2725] = 8; em[2726] = 1; /* 2724: pointer.X509_NAME_ENTRY */
    	em[2727] = 2147; em[2728] = 0; 
    em[2729] = 1; em[2730] = 8; em[2731] = 1; /* 2729: pointer.struct.buf_mem_st */
    	em[2732] = 2734; em[2733] = 0; 
    em[2734] = 0; em[2735] = 24; em[2736] = 1; /* 2734: struct.buf_mem_st */
    	em[2737] = 135; em[2738] = 8; 
    em[2739] = 1; em[2740] = 8; em[2741] = 1; /* 2739: pointer.struct.EDIPartyName_st */
    	em[2742] = 2744; em[2743] = 0; 
    em[2744] = 0; em[2745] = 16; em[2746] = 2; /* 2744: struct.EDIPartyName_st */
    	em[2747] = 2603; em[2748] = 0; 
    	em[2749] = 2603; em[2750] = 8; 
    em[2751] = 0; em[2752] = 24; em[2753] = 1; /* 2751: struct.asn1_string_st */
    	em[2754] = 69; em[2755] = 8; 
    em[2756] = 1; em[2757] = 8; em[2758] = 1; /* 2756: pointer.struct.buf_mem_st */
    	em[2759] = 2761; em[2760] = 0; 
    em[2761] = 0; em[2762] = 24; em[2763] = 1; /* 2761: struct.buf_mem_st */
    	em[2764] = 135; em[2765] = 8; 
    em[2766] = 0; em[2767] = 8; em[2768] = 2; /* 2766: union.unknown */
    	em[2769] = 2773; em[2770] = 0; 
    	em[2771] = 2797; em[2772] = 0; 
    em[2773] = 1; em[2774] = 8; em[2775] = 1; /* 2773: pointer.struct.stack_st_GENERAL_NAME */
    	em[2776] = 2778; em[2777] = 0; 
    em[2778] = 0; em[2779] = 32; em[2780] = 2; /* 2778: struct.stack_st_fake_GENERAL_NAME */
    	em[2781] = 2785; em[2782] = 8; 
    	em[2783] = 94; em[2784] = 24; 
    em[2785] = 8884099; em[2786] = 8; em[2787] = 2; /* 2785: pointer_to_array_of_pointers_to_stack */
    	em[2788] = 2792; em[2789] = 0; 
    	em[2790] = 52; em[2791] = 20; 
    em[2792] = 0; em[2793] = 8; em[2794] = 1; /* 2792: pointer.GENERAL_NAME */
    	em[2795] = 2481; em[2796] = 0; 
    em[2797] = 1; em[2798] = 8; em[2799] = 1; /* 2797: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[2800] = 2802; em[2801] = 0; 
    em[2802] = 0; em[2803] = 32; em[2804] = 2; /* 2802: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[2805] = 2809; em[2806] = 8; 
    	em[2807] = 94; em[2808] = 24; 
    em[2809] = 8884099; em[2810] = 8; em[2811] = 2; /* 2809: pointer_to_array_of_pointers_to_stack */
    	em[2812] = 2816; em[2813] = 0; 
    	em[2814] = 52; em[2815] = 20; 
    em[2816] = 0; em[2817] = 8; em[2818] = 1; /* 2816: pointer.X509_NAME_ENTRY */
    	em[2819] = 2147; em[2820] = 0; 
    em[2821] = 0; em[2822] = 24; em[2823] = 2; /* 2821: struct.DIST_POINT_NAME_st */
    	em[2824] = 2766; em[2825] = 8; 
    	em[2826] = 2828; em[2827] = 16; 
    em[2828] = 1; em[2829] = 8; em[2830] = 1; /* 2828: pointer.struct.X509_name_st */
    	em[2831] = 2833; em[2832] = 0; 
    em[2833] = 0; em[2834] = 40; em[2835] = 3; /* 2833: struct.X509_name_st */
    	em[2836] = 2797; em[2837] = 0; 
    	em[2838] = 2756; em[2839] = 16; 
    	em[2840] = 69; em[2841] = 24; 
    em[2842] = 1; em[2843] = 8; em[2844] = 1; /* 2842: pointer.struct.DIST_POINT_NAME_st */
    	em[2845] = 2821; em[2846] = 0; 
    em[2847] = 1; em[2848] = 8; em[2849] = 1; /* 2847: pointer.struct.stack_st_DIST_POINT */
    	em[2850] = 2852; em[2851] = 0; 
    em[2852] = 0; em[2853] = 32; em[2854] = 2; /* 2852: struct.stack_st_fake_DIST_POINT */
    	em[2855] = 2859; em[2856] = 8; 
    	em[2857] = 94; em[2858] = 24; 
    em[2859] = 8884099; em[2860] = 8; em[2861] = 2; /* 2859: pointer_to_array_of_pointers_to_stack */
    	em[2862] = 2866; em[2863] = 0; 
    	em[2864] = 52; em[2865] = 20; 
    em[2866] = 0; em[2867] = 8; em[2868] = 1; /* 2866: pointer.DIST_POINT */
    	em[2869] = 2871; em[2870] = 0; 
    em[2871] = 0; em[2872] = 0; em[2873] = 1; /* 2871: DIST_POINT */
    	em[2874] = 2876; em[2875] = 0; 
    em[2876] = 0; em[2877] = 32; em[2878] = 3; /* 2876: struct.DIST_POINT_st */
    	em[2879] = 2842; em[2880] = 0; 
    	em[2881] = 2885; em[2882] = 8; 
    	em[2883] = 2773; em[2884] = 16; 
    em[2885] = 1; em[2886] = 8; em[2887] = 1; /* 2885: pointer.struct.asn1_string_st */
    	em[2888] = 2751; em[2889] = 0; 
    em[2890] = 0; em[2891] = 32; em[2892] = 3; /* 2890: struct.X509_POLICY_DATA_st */
    	em[2893] = 2899; em[2894] = 8; 
    	em[2895] = 2913; em[2896] = 16; 
    	em[2897] = 3158; em[2898] = 24; 
    em[2899] = 1; em[2900] = 8; em[2901] = 1; /* 2899: pointer.struct.asn1_object_st */
    	em[2902] = 2904; em[2903] = 0; 
    em[2904] = 0; em[2905] = 40; em[2906] = 3; /* 2904: struct.asn1_object_st */
    	em[2907] = 121; em[2908] = 0; 
    	em[2909] = 121; em[2910] = 8; 
    	em[2911] = 1513; em[2912] = 24; 
    em[2913] = 1; em[2914] = 8; em[2915] = 1; /* 2913: pointer.struct.stack_st_POLICYQUALINFO */
    	em[2916] = 2918; em[2917] = 0; 
    em[2918] = 0; em[2919] = 32; em[2920] = 2; /* 2918: struct.stack_st_fake_POLICYQUALINFO */
    	em[2921] = 2925; em[2922] = 8; 
    	em[2923] = 94; em[2924] = 24; 
    em[2925] = 8884099; em[2926] = 8; em[2927] = 2; /* 2925: pointer_to_array_of_pointers_to_stack */
    	em[2928] = 2932; em[2929] = 0; 
    	em[2930] = 52; em[2931] = 20; 
    em[2932] = 0; em[2933] = 8; em[2934] = 1; /* 2932: pointer.POLICYQUALINFO */
    	em[2935] = 2937; em[2936] = 0; 
    em[2937] = 0; em[2938] = 0; em[2939] = 1; /* 2937: POLICYQUALINFO */
    	em[2940] = 2942; em[2941] = 0; 
    em[2942] = 0; em[2943] = 16; em[2944] = 2; /* 2942: struct.POLICYQUALINFO_st */
    	em[2945] = 2949; em[2946] = 0; 
    	em[2947] = 2963; em[2948] = 8; 
    em[2949] = 1; em[2950] = 8; em[2951] = 1; /* 2949: pointer.struct.asn1_object_st */
    	em[2952] = 2954; em[2953] = 0; 
    em[2954] = 0; em[2955] = 40; em[2956] = 3; /* 2954: struct.asn1_object_st */
    	em[2957] = 121; em[2958] = 0; 
    	em[2959] = 121; em[2960] = 8; 
    	em[2961] = 1513; em[2962] = 24; 
    em[2963] = 0; em[2964] = 8; em[2965] = 3; /* 2963: union.unknown */
    	em[2966] = 2972; em[2967] = 0; 
    	em[2968] = 2982; em[2969] = 0; 
    	em[2970] = 3040; em[2971] = 0; 
    em[2972] = 1; em[2973] = 8; em[2974] = 1; /* 2972: pointer.struct.asn1_string_st */
    	em[2975] = 2977; em[2976] = 0; 
    em[2977] = 0; em[2978] = 24; em[2979] = 1; /* 2977: struct.asn1_string_st */
    	em[2980] = 69; em[2981] = 8; 
    em[2982] = 1; em[2983] = 8; em[2984] = 1; /* 2982: pointer.struct.USERNOTICE_st */
    	em[2985] = 2987; em[2986] = 0; 
    em[2987] = 0; em[2988] = 16; em[2989] = 2; /* 2987: struct.USERNOTICE_st */
    	em[2990] = 2994; em[2991] = 0; 
    	em[2992] = 3006; em[2993] = 8; 
    em[2994] = 1; em[2995] = 8; em[2996] = 1; /* 2994: pointer.struct.NOTICEREF_st */
    	em[2997] = 2999; em[2998] = 0; 
    em[2999] = 0; em[3000] = 16; em[3001] = 2; /* 2999: struct.NOTICEREF_st */
    	em[3002] = 3006; em[3003] = 0; 
    	em[3004] = 3011; em[3005] = 8; 
    em[3006] = 1; em[3007] = 8; em[3008] = 1; /* 3006: pointer.struct.asn1_string_st */
    	em[3009] = 2977; em[3010] = 0; 
    em[3011] = 1; em[3012] = 8; em[3013] = 1; /* 3011: pointer.struct.stack_st_ASN1_INTEGER */
    	em[3014] = 3016; em[3015] = 0; 
    em[3016] = 0; em[3017] = 32; em[3018] = 2; /* 3016: struct.stack_st_fake_ASN1_INTEGER */
    	em[3019] = 3023; em[3020] = 8; 
    	em[3021] = 94; em[3022] = 24; 
    em[3023] = 8884099; em[3024] = 8; em[3025] = 2; /* 3023: pointer_to_array_of_pointers_to_stack */
    	em[3026] = 3030; em[3027] = 0; 
    	em[3028] = 52; em[3029] = 20; 
    em[3030] = 0; em[3031] = 8; em[3032] = 1; /* 3030: pointer.ASN1_INTEGER */
    	em[3033] = 3035; em[3034] = 0; 
    em[3035] = 0; em[3036] = 0; em[3037] = 1; /* 3035: ASN1_INTEGER */
    	em[3038] = 1931; em[3039] = 0; 
    em[3040] = 1; em[3041] = 8; em[3042] = 1; /* 3040: pointer.struct.asn1_type_st */
    	em[3043] = 3045; em[3044] = 0; 
    em[3045] = 0; em[3046] = 16; em[3047] = 1; /* 3045: struct.asn1_type_st */
    	em[3048] = 3050; em[3049] = 8; 
    em[3050] = 0; em[3051] = 8; em[3052] = 20; /* 3050: union.unknown */
    	em[3053] = 135; em[3054] = 0; 
    	em[3055] = 3006; em[3056] = 0; 
    	em[3057] = 2949; em[3058] = 0; 
    	em[3059] = 3093; em[3060] = 0; 
    	em[3061] = 3098; em[3062] = 0; 
    	em[3063] = 3103; em[3064] = 0; 
    	em[3065] = 3108; em[3066] = 0; 
    	em[3067] = 3113; em[3068] = 0; 
    	em[3069] = 3118; em[3070] = 0; 
    	em[3071] = 2972; em[3072] = 0; 
    	em[3073] = 3123; em[3074] = 0; 
    	em[3075] = 3128; em[3076] = 0; 
    	em[3077] = 3133; em[3078] = 0; 
    	em[3079] = 3138; em[3080] = 0; 
    	em[3081] = 3143; em[3082] = 0; 
    	em[3083] = 3148; em[3084] = 0; 
    	em[3085] = 3153; em[3086] = 0; 
    	em[3087] = 3006; em[3088] = 0; 
    	em[3089] = 3006; em[3090] = 0; 
    	em[3091] = 2334; em[3092] = 0; 
    em[3093] = 1; em[3094] = 8; em[3095] = 1; /* 3093: pointer.struct.asn1_string_st */
    	em[3096] = 2977; em[3097] = 0; 
    em[3098] = 1; em[3099] = 8; em[3100] = 1; /* 3098: pointer.struct.asn1_string_st */
    	em[3101] = 2977; em[3102] = 0; 
    em[3103] = 1; em[3104] = 8; em[3105] = 1; /* 3103: pointer.struct.asn1_string_st */
    	em[3106] = 2977; em[3107] = 0; 
    em[3108] = 1; em[3109] = 8; em[3110] = 1; /* 3108: pointer.struct.asn1_string_st */
    	em[3111] = 2977; em[3112] = 0; 
    em[3113] = 1; em[3114] = 8; em[3115] = 1; /* 3113: pointer.struct.asn1_string_st */
    	em[3116] = 2977; em[3117] = 0; 
    em[3118] = 1; em[3119] = 8; em[3120] = 1; /* 3118: pointer.struct.asn1_string_st */
    	em[3121] = 2977; em[3122] = 0; 
    em[3123] = 1; em[3124] = 8; em[3125] = 1; /* 3123: pointer.struct.asn1_string_st */
    	em[3126] = 2977; em[3127] = 0; 
    em[3128] = 1; em[3129] = 8; em[3130] = 1; /* 3128: pointer.struct.asn1_string_st */
    	em[3131] = 2977; em[3132] = 0; 
    em[3133] = 1; em[3134] = 8; em[3135] = 1; /* 3133: pointer.struct.asn1_string_st */
    	em[3136] = 2977; em[3137] = 0; 
    em[3138] = 1; em[3139] = 8; em[3140] = 1; /* 3138: pointer.struct.asn1_string_st */
    	em[3141] = 2977; em[3142] = 0; 
    em[3143] = 1; em[3144] = 8; em[3145] = 1; /* 3143: pointer.struct.asn1_string_st */
    	em[3146] = 2977; em[3147] = 0; 
    em[3148] = 1; em[3149] = 8; em[3150] = 1; /* 3148: pointer.struct.asn1_string_st */
    	em[3151] = 2977; em[3152] = 0; 
    em[3153] = 1; em[3154] = 8; em[3155] = 1; /* 3153: pointer.struct.asn1_string_st */
    	em[3156] = 2977; em[3157] = 0; 
    em[3158] = 1; em[3159] = 8; em[3160] = 1; /* 3158: pointer.struct.stack_st_ASN1_OBJECT */
    	em[3161] = 3163; em[3162] = 0; 
    em[3163] = 0; em[3164] = 32; em[3165] = 2; /* 3163: struct.stack_st_fake_ASN1_OBJECT */
    	em[3166] = 3170; em[3167] = 8; 
    	em[3168] = 94; em[3169] = 24; 
    em[3170] = 8884099; em[3171] = 8; em[3172] = 2; /* 3170: pointer_to_array_of_pointers_to_stack */
    	em[3173] = 3177; em[3174] = 0; 
    	em[3175] = 52; em[3176] = 20; 
    em[3177] = 0; em[3178] = 8; em[3179] = 1; /* 3177: pointer.ASN1_OBJECT */
    	em[3180] = 2077; em[3181] = 0; 
    em[3182] = 1; em[3183] = 8; em[3184] = 1; /* 3182: pointer.struct.stack_st_X509_POLICY_DATA */
    	em[3185] = 3187; em[3186] = 0; 
    em[3187] = 0; em[3188] = 32; em[3189] = 2; /* 3187: struct.stack_st_fake_X509_POLICY_DATA */
    	em[3190] = 3194; em[3191] = 8; 
    	em[3192] = 94; em[3193] = 24; 
    em[3194] = 8884099; em[3195] = 8; em[3196] = 2; /* 3194: pointer_to_array_of_pointers_to_stack */
    	em[3197] = 3201; em[3198] = 0; 
    	em[3199] = 52; em[3200] = 20; 
    em[3201] = 0; em[3202] = 8; em[3203] = 1; /* 3201: pointer.X509_POLICY_DATA */
    	em[3204] = 3206; em[3205] = 0; 
    em[3206] = 0; em[3207] = 0; em[3208] = 1; /* 3206: X509_POLICY_DATA */
    	em[3209] = 2890; em[3210] = 0; 
    em[3211] = 1; em[3212] = 8; em[3213] = 1; /* 3211: pointer.struct.stack_st_ASN1_OBJECT */
    	em[3214] = 3216; em[3215] = 0; 
    em[3216] = 0; em[3217] = 32; em[3218] = 2; /* 3216: struct.stack_st_fake_ASN1_OBJECT */
    	em[3219] = 3223; em[3220] = 8; 
    	em[3221] = 94; em[3222] = 24; 
    em[3223] = 8884099; em[3224] = 8; em[3225] = 2; /* 3223: pointer_to_array_of_pointers_to_stack */
    	em[3226] = 3230; em[3227] = 0; 
    	em[3228] = 52; em[3229] = 20; 
    em[3230] = 0; em[3231] = 8; em[3232] = 1; /* 3230: pointer.ASN1_OBJECT */
    	em[3233] = 2077; em[3234] = 0; 
    em[3235] = 1; em[3236] = 8; em[3237] = 1; /* 3235: pointer.struct.stack_st_POLICYQUALINFO */
    	em[3238] = 3240; em[3239] = 0; 
    em[3240] = 0; em[3241] = 32; em[3242] = 2; /* 3240: struct.stack_st_fake_POLICYQUALINFO */
    	em[3243] = 3247; em[3244] = 8; 
    	em[3245] = 94; em[3246] = 24; 
    em[3247] = 8884099; em[3248] = 8; em[3249] = 2; /* 3247: pointer_to_array_of_pointers_to_stack */
    	em[3250] = 3254; em[3251] = 0; 
    	em[3252] = 52; em[3253] = 20; 
    em[3254] = 0; em[3255] = 8; em[3256] = 1; /* 3254: pointer.POLICYQUALINFO */
    	em[3257] = 2937; em[3258] = 0; 
    em[3259] = 0; em[3260] = 40; em[3261] = 3; /* 3259: struct.asn1_object_st */
    	em[3262] = 121; em[3263] = 0; 
    	em[3264] = 121; em[3265] = 8; 
    	em[3266] = 1513; em[3267] = 24; 
    em[3268] = 0; em[3269] = 32; em[3270] = 3; /* 3268: struct.X509_POLICY_DATA_st */
    	em[3271] = 3277; em[3272] = 8; 
    	em[3273] = 3235; em[3274] = 16; 
    	em[3275] = 3211; em[3276] = 24; 
    em[3277] = 1; em[3278] = 8; em[3279] = 1; /* 3277: pointer.struct.asn1_object_st */
    	em[3280] = 3259; em[3281] = 0; 
    em[3282] = 1; em[3283] = 8; em[3284] = 1; /* 3282: pointer.struct.X509_POLICY_DATA_st */
    	em[3285] = 3268; em[3286] = 0; 
    em[3287] = 0; em[3288] = 40; em[3289] = 2; /* 3287: struct.X509_POLICY_CACHE_st */
    	em[3290] = 3282; em[3291] = 0; 
    	em[3292] = 3182; em[3293] = 8; 
    em[3294] = 1; em[3295] = 8; em[3296] = 1; /* 3294: pointer.struct.asn1_string_st */
    	em[3297] = 3299; em[3298] = 0; 
    em[3299] = 0; em[3300] = 24; em[3301] = 1; /* 3299: struct.asn1_string_st */
    	em[3302] = 69; em[3303] = 8; 
    em[3304] = 1; em[3305] = 8; em[3306] = 1; /* 3304: pointer.struct.stack_st_GENERAL_NAME */
    	em[3307] = 3309; em[3308] = 0; 
    em[3309] = 0; em[3310] = 32; em[3311] = 2; /* 3309: struct.stack_st_fake_GENERAL_NAME */
    	em[3312] = 3316; em[3313] = 8; 
    	em[3314] = 94; em[3315] = 24; 
    em[3316] = 8884099; em[3317] = 8; em[3318] = 2; /* 3316: pointer_to_array_of_pointers_to_stack */
    	em[3319] = 3323; em[3320] = 0; 
    	em[3321] = 52; em[3322] = 20; 
    em[3323] = 0; em[3324] = 8; em[3325] = 1; /* 3323: pointer.GENERAL_NAME */
    	em[3326] = 2481; em[3327] = 0; 
    em[3328] = 1; em[3329] = 8; em[3330] = 1; /* 3328: pointer.struct.asn1_string_st */
    	em[3331] = 3299; em[3332] = 0; 
    em[3333] = 1; em[3334] = 8; em[3335] = 1; /* 3333: pointer.struct.AUTHORITY_KEYID_st */
    	em[3336] = 3338; em[3337] = 0; 
    em[3338] = 0; em[3339] = 24; em[3340] = 3; /* 3338: struct.AUTHORITY_KEYID_st */
    	em[3341] = 3328; em[3342] = 0; 
    	em[3343] = 3304; em[3344] = 8; 
    	em[3345] = 3294; em[3346] = 16; 
    em[3347] = 0; em[3348] = 24; em[3349] = 1; /* 3347: struct.asn1_string_st */
    	em[3350] = 69; em[3351] = 8; 
    em[3352] = 1; em[3353] = 8; em[3354] = 1; /* 3352: pointer.struct.asn1_string_st */
    	em[3355] = 3347; em[3356] = 0; 
    em[3357] = 0; em[3358] = 40; em[3359] = 3; /* 3357: struct.asn1_object_st */
    	em[3360] = 121; em[3361] = 0; 
    	em[3362] = 121; em[3363] = 8; 
    	em[3364] = 1513; em[3365] = 24; 
    em[3366] = 1; em[3367] = 8; em[3368] = 1; /* 3366: pointer.struct.asn1_object_st */
    	em[3369] = 3357; em[3370] = 0; 
    em[3371] = 0; em[3372] = 24; em[3373] = 2; /* 3371: struct.X509_extension_st */
    	em[3374] = 3366; em[3375] = 0; 
    	em[3376] = 3352; em[3377] = 16; 
    em[3378] = 0; em[3379] = 0; em[3380] = 1; /* 3378: X509_EXTENSION */
    	em[3381] = 3371; em[3382] = 0; 
    em[3383] = 1; em[3384] = 8; em[3385] = 1; /* 3383: pointer.struct.stack_st_X509_EXTENSION */
    	em[3386] = 3388; em[3387] = 0; 
    em[3388] = 0; em[3389] = 32; em[3390] = 2; /* 3388: struct.stack_st_fake_X509_EXTENSION */
    	em[3391] = 3395; em[3392] = 8; 
    	em[3393] = 94; em[3394] = 24; 
    em[3395] = 8884099; em[3396] = 8; em[3397] = 2; /* 3395: pointer_to_array_of_pointers_to_stack */
    	em[3398] = 3402; em[3399] = 0; 
    	em[3400] = 52; em[3401] = 20; 
    em[3402] = 0; em[3403] = 8; em[3404] = 1; /* 3402: pointer.X509_EXTENSION */
    	em[3405] = 3378; em[3406] = 0; 
    em[3407] = 1; em[3408] = 8; em[3409] = 1; /* 3407: pointer.struct.asn1_string_st */
    	em[3410] = 2035; em[3411] = 0; 
    em[3412] = 0; em[3413] = 24; em[3414] = 1; /* 3412: struct.ASN1_ENCODING_st */
    	em[3415] = 69; em[3416] = 0; 
    em[3417] = 1; em[3418] = 8; em[3419] = 1; /* 3417: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[3420] = 3422; em[3421] = 0; 
    em[3422] = 0; em[3423] = 32; em[3424] = 2; /* 3422: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[3425] = 3429; em[3426] = 8; 
    	em[3427] = 94; em[3428] = 24; 
    em[3429] = 8884099; em[3430] = 8; em[3431] = 2; /* 3429: pointer_to_array_of_pointers_to_stack */
    	em[3432] = 3436; em[3433] = 0; 
    	em[3434] = 52; em[3435] = 20; 
    em[3436] = 0; em[3437] = 8; em[3438] = 1; /* 3436: pointer.X509_ATTRIBUTE */
    	em[3439] = 1487; em[3440] = 0; 
    em[3441] = 1; em[3442] = 8; em[3443] = 1; /* 3441: pointer.struct.evp_pkey_st */
    	em[3444] = 614; em[3445] = 0; 
    em[3446] = 1; em[3447] = 8; em[3448] = 1; /* 3446: pointer.struct.evp_pkey_asn1_method_st */
    	em[3449] = 630; em[3450] = 0; 
    em[3451] = 0; em[3452] = 56; em[3453] = 4; /* 3451: struct.evp_pkey_st */
    	em[3454] = 3446; em[3455] = 16; 
    	em[3456] = 3462; em[3457] = 24; 
    	em[3458] = 3467; em[3459] = 32; 
    	em[3460] = 3417; em[3461] = 48; 
    em[3462] = 1; em[3463] = 8; em[3464] = 1; /* 3462: pointer.struct.engine_st */
    	em[3465] = 148; em[3466] = 0; 
    em[3467] = 8884101; em[3468] = 8; em[3469] = 6; /* 3467: union.union_of_evp_pkey_st */
    	em[3470] = 91; em[3471] = 0; 
    	em[3472] = 3482; em[3473] = 6; 
    	em[3474] = 3487; em[3475] = 116; 
    	em[3476] = 3492; em[3477] = 28; 
    	em[3478] = 3497; em[3479] = 408; 
    	em[3480] = 52; em[3481] = 0; 
    em[3482] = 1; em[3483] = 8; em[3484] = 1; /* 3482: pointer.struct.rsa_st */
    	em[3485] = 751; em[3486] = 0; 
    em[3487] = 1; em[3488] = 8; em[3489] = 1; /* 3487: pointer.struct.dsa_st */
    	em[3490] = 488; em[3491] = 0; 
    em[3492] = 1; em[3493] = 8; em[3494] = 1; /* 3492: pointer.struct.dh_st */
    	em[3495] = 5; em[3496] = 0; 
    em[3497] = 1; em[3498] = 8; em[3499] = 1; /* 3497: pointer.struct.ec_key_st */
    	em[3500] = 959; em[3501] = 0; 
    em[3502] = 1; em[3503] = 8; em[3504] = 1; /* 3502: pointer.struct.evp_pkey_st */
    	em[3505] = 3451; em[3506] = 0; 
    em[3507] = 0; em[3508] = 24; em[3509] = 1; /* 3507: struct.asn1_string_st */
    	em[3510] = 69; em[3511] = 8; 
    em[3512] = 1; em[3513] = 8; em[3514] = 1; /* 3512: pointer.struct.x509_st */
    	em[3515] = 3517; em[3516] = 0; 
    em[3517] = 0; em[3518] = 184; em[3519] = 12; /* 3517: struct.x509_st */
    	em[3520] = 3544; em[3521] = 0; 
    	em[3522] = 3579; em[3523] = 8; 
    	em[3524] = 3407; em[3525] = 16; 
    	em[3526] = 135; em[3527] = 32; 
    	em[3528] = 3673; em[3529] = 40; 
    	em[3530] = 2091; em[3531] = 104; 
    	em[3532] = 3333; em[3533] = 112; 
    	em[3534] = 3687; em[3535] = 120; 
    	em[3536] = 2847; em[3537] = 128; 
    	em[3538] = 2457; em[3539] = 136; 
    	em[3540] = 2416; em[3541] = 144; 
    	em[3542] = 2096; em[3543] = 176; 
    em[3544] = 1; em[3545] = 8; em[3546] = 1; /* 3544: pointer.struct.x509_cinf_st */
    	em[3547] = 3549; em[3548] = 0; 
    em[3549] = 0; em[3550] = 104; em[3551] = 11; /* 3549: struct.x509_cinf_st */
    	em[3552] = 3574; em[3553] = 0; 
    	em[3554] = 3574; em[3555] = 8; 
    	em[3556] = 3579; em[3557] = 16; 
    	em[3558] = 3584; em[3559] = 24; 
    	em[3560] = 3632; em[3561] = 32; 
    	em[3562] = 3584; em[3563] = 40; 
    	em[3564] = 3649; em[3565] = 48; 
    	em[3566] = 3407; em[3567] = 56; 
    	em[3568] = 3407; em[3569] = 64; 
    	em[3570] = 3383; em[3571] = 72; 
    	em[3572] = 3412; em[3573] = 80; 
    em[3574] = 1; em[3575] = 8; em[3576] = 1; /* 3574: pointer.struct.asn1_string_st */
    	em[3577] = 2035; em[3578] = 0; 
    em[3579] = 1; em[3580] = 8; em[3581] = 1; /* 3579: pointer.struct.X509_algor_st */
    	em[3582] = 1852; em[3583] = 0; 
    em[3584] = 1; em[3585] = 8; em[3586] = 1; /* 3584: pointer.struct.X509_name_st */
    	em[3587] = 3589; em[3588] = 0; 
    em[3589] = 0; em[3590] = 40; em[3591] = 3; /* 3589: struct.X509_name_st */
    	em[3592] = 3598; em[3593] = 0; 
    	em[3594] = 3622; em[3595] = 16; 
    	em[3596] = 69; em[3597] = 24; 
    em[3598] = 1; em[3599] = 8; em[3600] = 1; /* 3598: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[3601] = 3603; em[3602] = 0; 
    em[3603] = 0; em[3604] = 32; em[3605] = 2; /* 3603: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[3606] = 3610; em[3607] = 8; 
    	em[3608] = 94; em[3609] = 24; 
    em[3610] = 8884099; em[3611] = 8; em[3612] = 2; /* 3610: pointer_to_array_of_pointers_to_stack */
    	em[3613] = 3617; em[3614] = 0; 
    	em[3615] = 52; em[3616] = 20; 
    em[3617] = 0; em[3618] = 8; em[3619] = 1; /* 3617: pointer.X509_NAME_ENTRY */
    	em[3620] = 2147; em[3621] = 0; 
    em[3622] = 1; em[3623] = 8; em[3624] = 1; /* 3622: pointer.struct.buf_mem_st */
    	em[3625] = 3627; em[3626] = 0; 
    em[3627] = 0; em[3628] = 24; em[3629] = 1; /* 3627: struct.buf_mem_st */
    	em[3630] = 135; em[3631] = 8; 
    em[3632] = 1; em[3633] = 8; em[3634] = 1; /* 3632: pointer.struct.X509_val_st */
    	em[3635] = 3637; em[3636] = 0; 
    em[3637] = 0; em[3638] = 16; em[3639] = 2; /* 3637: struct.X509_val_st */
    	em[3640] = 3644; em[3641] = 0; 
    	em[3642] = 3644; em[3643] = 8; 
    em[3644] = 1; em[3645] = 8; em[3646] = 1; /* 3644: pointer.struct.asn1_string_st */
    	em[3647] = 2035; em[3648] = 0; 
    em[3649] = 1; em[3650] = 8; em[3651] = 1; /* 3649: pointer.struct.X509_pubkey_st */
    	em[3652] = 3654; em[3653] = 0; 
    em[3654] = 0; em[3655] = 24; em[3656] = 3; /* 3654: struct.X509_pubkey_st */
    	em[3657] = 3663; em[3658] = 0; 
    	em[3659] = 3668; em[3660] = 8; 
    	em[3661] = 3502; em[3662] = 16; 
    em[3663] = 1; em[3664] = 8; em[3665] = 1; /* 3663: pointer.struct.X509_algor_st */
    	em[3666] = 1852; em[3667] = 0; 
    em[3668] = 1; em[3669] = 8; em[3670] = 1; /* 3668: pointer.struct.asn1_string_st */
    	em[3671] = 3507; em[3672] = 0; 
    em[3673] = 0; em[3674] = 32; em[3675] = 2; /* 3673: struct.crypto_ex_data_st_fake */
    	em[3676] = 3680; em[3677] = 8; 
    	em[3678] = 94; em[3679] = 24; 
    em[3680] = 8884099; em[3681] = 8; em[3682] = 2; /* 3680: pointer_to_array_of_pointers_to_stack */
    	em[3683] = 91; em[3684] = 0; 
    	em[3685] = 52; em[3686] = 20; 
    em[3687] = 1; em[3688] = 8; em[3689] = 1; /* 3687: pointer.struct.X509_POLICY_CACHE_st */
    	em[3690] = 3287; em[3691] = 0; 
    em[3692] = 0; em[3693] = 1; em[3694] = 0; /* 3692: char */
    args_addr->arg_entity_index[0] = 3512;
    args_addr->arg_entity_index[1] = 3441;
    args_addr->ret_entity_index = 52;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    X509 * new_arg_a = *((X509 * *)new_args->args[0]);

    EVP_PKEY * new_arg_b = *((EVP_PKEY * *)new_args->args[1]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_X509_check_private_key)(X509 *,EVP_PKEY *);
    orig_X509_check_private_key = dlsym(RTLD_NEXT, "X509_check_private_key");
    *new_ret_ptr = (*orig_X509_check_private_key)(new_arg_a,new_arg_b);

    syscall(889);

    free(args_addr);

    return ret;
}

