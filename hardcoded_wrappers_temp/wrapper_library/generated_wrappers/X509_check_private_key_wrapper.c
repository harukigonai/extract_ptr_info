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
    	em[619] = 609; em[620] = 24; 
    	em[621] = 726; em[622] = 32; 
    	em[623] = 1456; em[624] = 48; 
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
    em[726] = 0; em[727] = 8; em[728] = 5; /* 726: union.unknown */
    	em[729] = 135; em[730] = 0; 
    	em[731] = 739; em[732] = 0; 
    	em[733] = 483; em[734] = 0; 
    	em[735] = 0; em[736] = 0; 
    	em[737] = 947; em[738] = 0; 
    em[739] = 1; em[740] = 8; em[741] = 1; /* 739: pointer.struct.rsa_st */
    	em[742] = 744; em[743] = 0; 
    em[744] = 0; em[745] = 168; em[746] = 17; /* 744: struct.rsa_st */
    	em[747] = 781; em[748] = 16; 
    	em[749] = 836; em[750] = 24; 
    	em[751] = 841; em[752] = 32; 
    	em[753] = 841; em[754] = 40; 
    	em[755] = 841; em[756] = 48; 
    	em[757] = 841; em[758] = 56; 
    	em[759] = 841; em[760] = 64; 
    	em[761] = 841; em[762] = 72; 
    	em[763] = 841; em[764] = 80; 
    	em[765] = 841; em[766] = 88; 
    	em[767] = 858; em[768] = 96; 
    	em[769] = 872; em[770] = 120; 
    	em[771] = 872; em[772] = 128; 
    	em[773] = 872; em[774] = 136; 
    	em[775] = 135; em[776] = 144; 
    	em[777] = 886; em[778] = 152; 
    	em[779] = 886; em[780] = 160; 
    em[781] = 1; em[782] = 8; em[783] = 1; /* 781: pointer.struct.rsa_meth_st */
    	em[784] = 786; em[785] = 0; 
    em[786] = 0; em[787] = 112; em[788] = 13; /* 786: struct.rsa_meth_st */
    	em[789] = 121; em[790] = 0; 
    	em[791] = 815; em[792] = 8; 
    	em[793] = 815; em[794] = 16; 
    	em[795] = 815; em[796] = 24; 
    	em[797] = 815; em[798] = 32; 
    	em[799] = 818; em[800] = 40; 
    	em[801] = 821; em[802] = 48; 
    	em[803] = 824; em[804] = 56; 
    	em[805] = 824; em[806] = 64; 
    	em[807] = 135; em[808] = 80; 
    	em[809] = 827; em[810] = 88; 
    	em[811] = 830; em[812] = 96; 
    	em[813] = 833; em[814] = 104; 
    em[815] = 8884097; em[816] = 8; em[817] = 0; /* 815: pointer.func */
    em[818] = 8884097; em[819] = 8; em[820] = 0; /* 818: pointer.func */
    em[821] = 8884097; em[822] = 8; em[823] = 0; /* 821: pointer.func */
    em[824] = 8884097; em[825] = 8; em[826] = 0; /* 824: pointer.func */
    em[827] = 8884097; em[828] = 8; em[829] = 0; /* 827: pointer.func */
    em[830] = 8884097; em[831] = 8; em[832] = 0; /* 830: pointer.func */
    em[833] = 8884097; em[834] = 8; em[835] = 0; /* 833: pointer.func */
    em[836] = 1; em[837] = 8; em[838] = 1; /* 836: pointer.struct.engine_st */
    	em[839] = 148; em[840] = 0; 
    em[841] = 1; em[842] = 8; em[843] = 1; /* 841: pointer.struct.bignum_st */
    	em[844] = 846; em[845] = 0; 
    em[846] = 0; em[847] = 24; em[848] = 1; /* 846: struct.bignum_st */
    	em[849] = 851; em[850] = 0; 
    em[851] = 8884099; em[852] = 8; em[853] = 2; /* 851: pointer_to_array_of_pointers_to_stack */
    	em[854] = 49; em[855] = 0; 
    	em[856] = 52; em[857] = 12; 
    em[858] = 0; em[859] = 32; em[860] = 2; /* 858: struct.crypto_ex_data_st_fake */
    	em[861] = 865; em[862] = 8; 
    	em[863] = 94; em[864] = 24; 
    em[865] = 8884099; em[866] = 8; em[867] = 2; /* 865: pointer_to_array_of_pointers_to_stack */
    	em[868] = 91; em[869] = 0; 
    	em[870] = 52; em[871] = 20; 
    em[872] = 1; em[873] = 8; em[874] = 1; /* 872: pointer.struct.bn_mont_ctx_st */
    	em[875] = 877; em[876] = 0; 
    em[877] = 0; em[878] = 96; em[879] = 3; /* 877: struct.bn_mont_ctx_st */
    	em[880] = 846; em[881] = 8; 
    	em[882] = 846; em[883] = 32; 
    	em[884] = 846; em[885] = 56; 
    em[886] = 1; em[887] = 8; em[888] = 1; /* 886: pointer.struct.bn_blinding_st */
    	em[889] = 891; em[890] = 0; 
    em[891] = 0; em[892] = 88; em[893] = 7; /* 891: struct.bn_blinding_st */
    	em[894] = 908; em[895] = 0; 
    	em[896] = 908; em[897] = 8; 
    	em[898] = 908; em[899] = 16; 
    	em[900] = 908; em[901] = 24; 
    	em[902] = 925; em[903] = 40; 
    	em[904] = 930; em[905] = 72; 
    	em[906] = 944; em[907] = 80; 
    em[908] = 1; em[909] = 8; em[910] = 1; /* 908: pointer.struct.bignum_st */
    	em[911] = 913; em[912] = 0; 
    em[913] = 0; em[914] = 24; em[915] = 1; /* 913: struct.bignum_st */
    	em[916] = 918; em[917] = 0; 
    em[918] = 8884099; em[919] = 8; em[920] = 2; /* 918: pointer_to_array_of_pointers_to_stack */
    	em[921] = 49; em[922] = 0; 
    	em[923] = 52; em[924] = 12; 
    em[925] = 0; em[926] = 16; em[927] = 1; /* 925: struct.crypto_threadid_st */
    	em[928] = 91; em[929] = 0; 
    em[930] = 1; em[931] = 8; em[932] = 1; /* 930: pointer.struct.bn_mont_ctx_st */
    	em[933] = 935; em[934] = 0; 
    em[935] = 0; em[936] = 96; em[937] = 3; /* 935: struct.bn_mont_ctx_st */
    	em[938] = 913; em[939] = 8; 
    	em[940] = 913; em[941] = 32; 
    	em[942] = 913; em[943] = 56; 
    em[944] = 8884097; em[945] = 8; em[946] = 0; /* 944: pointer.func */
    em[947] = 1; em[948] = 8; em[949] = 1; /* 947: pointer.struct.ec_key_st */
    	em[950] = 952; em[951] = 0; 
    em[952] = 0; em[953] = 56; em[954] = 4; /* 952: struct.ec_key_st */
    	em[955] = 963; em[956] = 8; 
    	em[957] = 1411; em[958] = 16; 
    	em[959] = 1416; em[960] = 24; 
    	em[961] = 1433; em[962] = 48; 
    em[963] = 1; em[964] = 8; em[965] = 1; /* 963: pointer.struct.ec_group_st */
    	em[966] = 968; em[967] = 0; 
    em[968] = 0; em[969] = 232; em[970] = 12; /* 968: struct.ec_group_st */
    	em[971] = 995; em[972] = 0; 
    	em[973] = 1167; em[974] = 8; 
    	em[975] = 1367; em[976] = 16; 
    	em[977] = 1367; em[978] = 40; 
    	em[979] = 69; em[980] = 80; 
    	em[981] = 1379; em[982] = 96; 
    	em[983] = 1367; em[984] = 104; 
    	em[985] = 1367; em[986] = 152; 
    	em[987] = 1367; em[988] = 176; 
    	em[989] = 91; em[990] = 208; 
    	em[991] = 91; em[992] = 216; 
    	em[993] = 1408; em[994] = 224; 
    em[995] = 1; em[996] = 8; em[997] = 1; /* 995: pointer.struct.ec_method_st */
    	em[998] = 1000; em[999] = 0; 
    em[1000] = 0; em[1001] = 304; em[1002] = 37; /* 1000: struct.ec_method_st */
    	em[1003] = 1077; em[1004] = 8; 
    	em[1005] = 1080; em[1006] = 16; 
    	em[1007] = 1080; em[1008] = 24; 
    	em[1009] = 1083; em[1010] = 32; 
    	em[1011] = 1086; em[1012] = 40; 
    	em[1013] = 1089; em[1014] = 48; 
    	em[1015] = 1092; em[1016] = 56; 
    	em[1017] = 1095; em[1018] = 64; 
    	em[1019] = 1098; em[1020] = 72; 
    	em[1021] = 1101; em[1022] = 80; 
    	em[1023] = 1101; em[1024] = 88; 
    	em[1025] = 1104; em[1026] = 96; 
    	em[1027] = 1107; em[1028] = 104; 
    	em[1029] = 1110; em[1030] = 112; 
    	em[1031] = 1113; em[1032] = 120; 
    	em[1033] = 1116; em[1034] = 128; 
    	em[1035] = 1119; em[1036] = 136; 
    	em[1037] = 1122; em[1038] = 144; 
    	em[1039] = 1125; em[1040] = 152; 
    	em[1041] = 1128; em[1042] = 160; 
    	em[1043] = 1131; em[1044] = 168; 
    	em[1045] = 1134; em[1046] = 176; 
    	em[1047] = 1137; em[1048] = 184; 
    	em[1049] = 1140; em[1050] = 192; 
    	em[1051] = 1143; em[1052] = 200; 
    	em[1053] = 1146; em[1054] = 208; 
    	em[1055] = 1137; em[1056] = 216; 
    	em[1057] = 1149; em[1058] = 224; 
    	em[1059] = 1152; em[1060] = 232; 
    	em[1061] = 1155; em[1062] = 240; 
    	em[1063] = 1092; em[1064] = 248; 
    	em[1065] = 1158; em[1066] = 256; 
    	em[1067] = 1161; em[1068] = 264; 
    	em[1069] = 1158; em[1070] = 272; 
    	em[1071] = 1161; em[1072] = 280; 
    	em[1073] = 1161; em[1074] = 288; 
    	em[1075] = 1164; em[1076] = 296; 
    em[1077] = 8884097; em[1078] = 8; em[1079] = 0; /* 1077: pointer.func */
    em[1080] = 8884097; em[1081] = 8; em[1082] = 0; /* 1080: pointer.func */
    em[1083] = 8884097; em[1084] = 8; em[1085] = 0; /* 1083: pointer.func */
    em[1086] = 8884097; em[1087] = 8; em[1088] = 0; /* 1086: pointer.func */
    em[1089] = 8884097; em[1090] = 8; em[1091] = 0; /* 1089: pointer.func */
    em[1092] = 8884097; em[1093] = 8; em[1094] = 0; /* 1092: pointer.func */
    em[1095] = 8884097; em[1096] = 8; em[1097] = 0; /* 1095: pointer.func */
    em[1098] = 8884097; em[1099] = 8; em[1100] = 0; /* 1098: pointer.func */
    em[1101] = 8884097; em[1102] = 8; em[1103] = 0; /* 1101: pointer.func */
    em[1104] = 8884097; em[1105] = 8; em[1106] = 0; /* 1104: pointer.func */
    em[1107] = 8884097; em[1108] = 8; em[1109] = 0; /* 1107: pointer.func */
    em[1110] = 8884097; em[1111] = 8; em[1112] = 0; /* 1110: pointer.func */
    em[1113] = 8884097; em[1114] = 8; em[1115] = 0; /* 1113: pointer.func */
    em[1116] = 8884097; em[1117] = 8; em[1118] = 0; /* 1116: pointer.func */
    em[1119] = 8884097; em[1120] = 8; em[1121] = 0; /* 1119: pointer.func */
    em[1122] = 8884097; em[1123] = 8; em[1124] = 0; /* 1122: pointer.func */
    em[1125] = 8884097; em[1126] = 8; em[1127] = 0; /* 1125: pointer.func */
    em[1128] = 8884097; em[1129] = 8; em[1130] = 0; /* 1128: pointer.func */
    em[1131] = 8884097; em[1132] = 8; em[1133] = 0; /* 1131: pointer.func */
    em[1134] = 8884097; em[1135] = 8; em[1136] = 0; /* 1134: pointer.func */
    em[1137] = 8884097; em[1138] = 8; em[1139] = 0; /* 1137: pointer.func */
    em[1140] = 8884097; em[1141] = 8; em[1142] = 0; /* 1140: pointer.func */
    em[1143] = 8884097; em[1144] = 8; em[1145] = 0; /* 1143: pointer.func */
    em[1146] = 8884097; em[1147] = 8; em[1148] = 0; /* 1146: pointer.func */
    em[1149] = 8884097; em[1150] = 8; em[1151] = 0; /* 1149: pointer.func */
    em[1152] = 8884097; em[1153] = 8; em[1154] = 0; /* 1152: pointer.func */
    em[1155] = 8884097; em[1156] = 8; em[1157] = 0; /* 1155: pointer.func */
    em[1158] = 8884097; em[1159] = 8; em[1160] = 0; /* 1158: pointer.func */
    em[1161] = 8884097; em[1162] = 8; em[1163] = 0; /* 1161: pointer.func */
    em[1164] = 8884097; em[1165] = 8; em[1166] = 0; /* 1164: pointer.func */
    em[1167] = 1; em[1168] = 8; em[1169] = 1; /* 1167: pointer.struct.ec_point_st */
    	em[1170] = 1172; em[1171] = 0; 
    em[1172] = 0; em[1173] = 88; em[1174] = 4; /* 1172: struct.ec_point_st */
    	em[1175] = 1183; em[1176] = 0; 
    	em[1177] = 1355; em[1178] = 8; 
    	em[1179] = 1355; em[1180] = 32; 
    	em[1181] = 1355; em[1182] = 56; 
    em[1183] = 1; em[1184] = 8; em[1185] = 1; /* 1183: pointer.struct.ec_method_st */
    	em[1186] = 1188; em[1187] = 0; 
    em[1188] = 0; em[1189] = 304; em[1190] = 37; /* 1188: struct.ec_method_st */
    	em[1191] = 1265; em[1192] = 8; 
    	em[1193] = 1268; em[1194] = 16; 
    	em[1195] = 1268; em[1196] = 24; 
    	em[1197] = 1271; em[1198] = 32; 
    	em[1199] = 1274; em[1200] = 40; 
    	em[1201] = 1277; em[1202] = 48; 
    	em[1203] = 1280; em[1204] = 56; 
    	em[1205] = 1283; em[1206] = 64; 
    	em[1207] = 1286; em[1208] = 72; 
    	em[1209] = 1289; em[1210] = 80; 
    	em[1211] = 1289; em[1212] = 88; 
    	em[1213] = 1292; em[1214] = 96; 
    	em[1215] = 1295; em[1216] = 104; 
    	em[1217] = 1298; em[1218] = 112; 
    	em[1219] = 1301; em[1220] = 120; 
    	em[1221] = 1304; em[1222] = 128; 
    	em[1223] = 1307; em[1224] = 136; 
    	em[1225] = 1310; em[1226] = 144; 
    	em[1227] = 1313; em[1228] = 152; 
    	em[1229] = 1316; em[1230] = 160; 
    	em[1231] = 1319; em[1232] = 168; 
    	em[1233] = 1322; em[1234] = 176; 
    	em[1235] = 1325; em[1236] = 184; 
    	em[1237] = 1328; em[1238] = 192; 
    	em[1239] = 1331; em[1240] = 200; 
    	em[1241] = 1334; em[1242] = 208; 
    	em[1243] = 1325; em[1244] = 216; 
    	em[1245] = 1337; em[1246] = 224; 
    	em[1247] = 1340; em[1248] = 232; 
    	em[1249] = 1343; em[1250] = 240; 
    	em[1251] = 1280; em[1252] = 248; 
    	em[1253] = 1346; em[1254] = 256; 
    	em[1255] = 1349; em[1256] = 264; 
    	em[1257] = 1346; em[1258] = 272; 
    	em[1259] = 1349; em[1260] = 280; 
    	em[1261] = 1349; em[1262] = 288; 
    	em[1263] = 1352; em[1264] = 296; 
    em[1265] = 8884097; em[1266] = 8; em[1267] = 0; /* 1265: pointer.func */
    em[1268] = 8884097; em[1269] = 8; em[1270] = 0; /* 1268: pointer.func */
    em[1271] = 8884097; em[1272] = 8; em[1273] = 0; /* 1271: pointer.func */
    em[1274] = 8884097; em[1275] = 8; em[1276] = 0; /* 1274: pointer.func */
    em[1277] = 8884097; em[1278] = 8; em[1279] = 0; /* 1277: pointer.func */
    em[1280] = 8884097; em[1281] = 8; em[1282] = 0; /* 1280: pointer.func */
    em[1283] = 8884097; em[1284] = 8; em[1285] = 0; /* 1283: pointer.func */
    em[1286] = 8884097; em[1287] = 8; em[1288] = 0; /* 1286: pointer.func */
    em[1289] = 8884097; em[1290] = 8; em[1291] = 0; /* 1289: pointer.func */
    em[1292] = 8884097; em[1293] = 8; em[1294] = 0; /* 1292: pointer.func */
    em[1295] = 8884097; em[1296] = 8; em[1297] = 0; /* 1295: pointer.func */
    em[1298] = 8884097; em[1299] = 8; em[1300] = 0; /* 1298: pointer.func */
    em[1301] = 8884097; em[1302] = 8; em[1303] = 0; /* 1301: pointer.func */
    em[1304] = 8884097; em[1305] = 8; em[1306] = 0; /* 1304: pointer.func */
    em[1307] = 8884097; em[1308] = 8; em[1309] = 0; /* 1307: pointer.func */
    em[1310] = 8884097; em[1311] = 8; em[1312] = 0; /* 1310: pointer.func */
    em[1313] = 8884097; em[1314] = 8; em[1315] = 0; /* 1313: pointer.func */
    em[1316] = 8884097; em[1317] = 8; em[1318] = 0; /* 1316: pointer.func */
    em[1319] = 8884097; em[1320] = 8; em[1321] = 0; /* 1319: pointer.func */
    em[1322] = 8884097; em[1323] = 8; em[1324] = 0; /* 1322: pointer.func */
    em[1325] = 8884097; em[1326] = 8; em[1327] = 0; /* 1325: pointer.func */
    em[1328] = 8884097; em[1329] = 8; em[1330] = 0; /* 1328: pointer.func */
    em[1331] = 8884097; em[1332] = 8; em[1333] = 0; /* 1331: pointer.func */
    em[1334] = 8884097; em[1335] = 8; em[1336] = 0; /* 1334: pointer.func */
    em[1337] = 8884097; em[1338] = 8; em[1339] = 0; /* 1337: pointer.func */
    em[1340] = 8884097; em[1341] = 8; em[1342] = 0; /* 1340: pointer.func */
    em[1343] = 8884097; em[1344] = 8; em[1345] = 0; /* 1343: pointer.func */
    em[1346] = 8884097; em[1347] = 8; em[1348] = 0; /* 1346: pointer.func */
    em[1349] = 8884097; em[1350] = 8; em[1351] = 0; /* 1349: pointer.func */
    em[1352] = 8884097; em[1353] = 8; em[1354] = 0; /* 1352: pointer.func */
    em[1355] = 0; em[1356] = 24; em[1357] = 1; /* 1355: struct.bignum_st */
    	em[1358] = 1360; em[1359] = 0; 
    em[1360] = 8884099; em[1361] = 8; em[1362] = 2; /* 1360: pointer_to_array_of_pointers_to_stack */
    	em[1363] = 49; em[1364] = 0; 
    	em[1365] = 52; em[1366] = 12; 
    em[1367] = 0; em[1368] = 24; em[1369] = 1; /* 1367: struct.bignum_st */
    	em[1370] = 1372; em[1371] = 0; 
    em[1372] = 8884099; em[1373] = 8; em[1374] = 2; /* 1372: pointer_to_array_of_pointers_to_stack */
    	em[1375] = 49; em[1376] = 0; 
    	em[1377] = 52; em[1378] = 12; 
    em[1379] = 1; em[1380] = 8; em[1381] = 1; /* 1379: pointer.struct.ec_extra_data_st */
    	em[1382] = 1384; em[1383] = 0; 
    em[1384] = 0; em[1385] = 40; em[1386] = 5; /* 1384: struct.ec_extra_data_st */
    	em[1387] = 1397; em[1388] = 0; 
    	em[1389] = 91; em[1390] = 8; 
    	em[1391] = 1402; em[1392] = 16; 
    	em[1393] = 1405; em[1394] = 24; 
    	em[1395] = 1405; em[1396] = 32; 
    em[1397] = 1; em[1398] = 8; em[1399] = 1; /* 1397: pointer.struct.ec_extra_data_st */
    	em[1400] = 1384; em[1401] = 0; 
    em[1402] = 8884097; em[1403] = 8; em[1404] = 0; /* 1402: pointer.func */
    em[1405] = 8884097; em[1406] = 8; em[1407] = 0; /* 1405: pointer.func */
    em[1408] = 8884097; em[1409] = 8; em[1410] = 0; /* 1408: pointer.func */
    em[1411] = 1; em[1412] = 8; em[1413] = 1; /* 1411: pointer.struct.ec_point_st */
    	em[1414] = 1172; em[1415] = 0; 
    em[1416] = 1; em[1417] = 8; em[1418] = 1; /* 1416: pointer.struct.bignum_st */
    	em[1419] = 1421; em[1420] = 0; 
    em[1421] = 0; em[1422] = 24; em[1423] = 1; /* 1421: struct.bignum_st */
    	em[1424] = 1426; em[1425] = 0; 
    em[1426] = 8884099; em[1427] = 8; em[1428] = 2; /* 1426: pointer_to_array_of_pointers_to_stack */
    	em[1429] = 49; em[1430] = 0; 
    	em[1431] = 52; em[1432] = 12; 
    em[1433] = 1; em[1434] = 8; em[1435] = 1; /* 1433: pointer.struct.ec_extra_data_st */
    	em[1436] = 1438; em[1437] = 0; 
    em[1438] = 0; em[1439] = 40; em[1440] = 5; /* 1438: struct.ec_extra_data_st */
    	em[1441] = 1451; em[1442] = 0; 
    	em[1443] = 91; em[1444] = 8; 
    	em[1445] = 1402; em[1446] = 16; 
    	em[1447] = 1405; em[1448] = 24; 
    	em[1449] = 1405; em[1450] = 32; 
    em[1451] = 1; em[1452] = 8; em[1453] = 1; /* 1451: pointer.struct.ec_extra_data_st */
    	em[1454] = 1438; em[1455] = 0; 
    em[1456] = 1; em[1457] = 8; em[1458] = 1; /* 1456: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[1459] = 1461; em[1460] = 0; 
    em[1461] = 0; em[1462] = 32; em[1463] = 2; /* 1461: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[1464] = 1468; em[1465] = 8; 
    	em[1466] = 94; em[1467] = 24; 
    em[1468] = 8884099; em[1469] = 8; em[1470] = 2; /* 1468: pointer_to_array_of_pointers_to_stack */
    	em[1471] = 1475; em[1472] = 0; 
    	em[1473] = 52; em[1474] = 20; 
    em[1475] = 0; em[1476] = 8; em[1477] = 1; /* 1475: pointer.X509_ATTRIBUTE */
    	em[1478] = 1480; em[1479] = 0; 
    em[1480] = 0; em[1481] = 0; em[1482] = 1; /* 1480: X509_ATTRIBUTE */
    	em[1483] = 1485; em[1484] = 0; 
    em[1485] = 0; em[1486] = 24; em[1487] = 2; /* 1485: struct.x509_attributes_st */
    	em[1488] = 1492; em[1489] = 0; 
    	em[1490] = 1511; em[1491] = 16; 
    em[1492] = 1; em[1493] = 8; em[1494] = 1; /* 1492: pointer.struct.asn1_object_st */
    	em[1495] = 1497; em[1496] = 0; 
    em[1497] = 0; em[1498] = 40; em[1499] = 3; /* 1497: struct.asn1_object_st */
    	em[1500] = 121; em[1501] = 0; 
    	em[1502] = 121; em[1503] = 8; 
    	em[1504] = 1506; em[1505] = 24; 
    em[1506] = 1; em[1507] = 8; em[1508] = 1; /* 1506: pointer.unsigned char */
    	em[1509] = 74; em[1510] = 0; 
    em[1511] = 0; em[1512] = 8; em[1513] = 3; /* 1511: union.unknown */
    	em[1514] = 135; em[1515] = 0; 
    	em[1516] = 1520; em[1517] = 0; 
    	em[1518] = 1699; em[1519] = 0; 
    em[1520] = 1; em[1521] = 8; em[1522] = 1; /* 1520: pointer.struct.stack_st_ASN1_TYPE */
    	em[1523] = 1525; em[1524] = 0; 
    em[1525] = 0; em[1526] = 32; em[1527] = 2; /* 1525: struct.stack_st_fake_ASN1_TYPE */
    	em[1528] = 1532; em[1529] = 8; 
    	em[1530] = 94; em[1531] = 24; 
    em[1532] = 8884099; em[1533] = 8; em[1534] = 2; /* 1532: pointer_to_array_of_pointers_to_stack */
    	em[1535] = 1539; em[1536] = 0; 
    	em[1537] = 52; em[1538] = 20; 
    em[1539] = 0; em[1540] = 8; em[1541] = 1; /* 1539: pointer.ASN1_TYPE */
    	em[1542] = 1544; em[1543] = 0; 
    em[1544] = 0; em[1545] = 0; em[1546] = 1; /* 1544: ASN1_TYPE */
    	em[1547] = 1549; em[1548] = 0; 
    em[1549] = 0; em[1550] = 16; em[1551] = 1; /* 1549: struct.asn1_type_st */
    	em[1552] = 1554; em[1553] = 8; 
    em[1554] = 0; em[1555] = 8; em[1556] = 20; /* 1554: union.unknown */
    	em[1557] = 135; em[1558] = 0; 
    	em[1559] = 1597; em[1560] = 0; 
    	em[1561] = 1607; em[1562] = 0; 
    	em[1563] = 1621; em[1564] = 0; 
    	em[1565] = 1626; em[1566] = 0; 
    	em[1567] = 1631; em[1568] = 0; 
    	em[1569] = 1636; em[1570] = 0; 
    	em[1571] = 1641; em[1572] = 0; 
    	em[1573] = 1646; em[1574] = 0; 
    	em[1575] = 1651; em[1576] = 0; 
    	em[1577] = 1656; em[1578] = 0; 
    	em[1579] = 1661; em[1580] = 0; 
    	em[1581] = 1666; em[1582] = 0; 
    	em[1583] = 1671; em[1584] = 0; 
    	em[1585] = 1676; em[1586] = 0; 
    	em[1587] = 1681; em[1588] = 0; 
    	em[1589] = 1686; em[1590] = 0; 
    	em[1591] = 1597; em[1592] = 0; 
    	em[1593] = 1597; em[1594] = 0; 
    	em[1595] = 1691; em[1596] = 0; 
    em[1597] = 1; em[1598] = 8; em[1599] = 1; /* 1597: pointer.struct.asn1_string_st */
    	em[1600] = 1602; em[1601] = 0; 
    em[1602] = 0; em[1603] = 24; em[1604] = 1; /* 1602: struct.asn1_string_st */
    	em[1605] = 69; em[1606] = 8; 
    em[1607] = 1; em[1608] = 8; em[1609] = 1; /* 1607: pointer.struct.asn1_object_st */
    	em[1610] = 1612; em[1611] = 0; 
    em[1612] = 0; em[1613] = 40; em[1614] = 3; /* 1612: struct.asn1_object_st */
    	em[1615] = 121; em[1616] = 0; 
    	em[1617] = 121; em[1618] = 8; 
    	em[1619] = 1506; em[1620] = 24; 
    em[1621] = 1; em[1622] = 8; em[1623] = 1; /* 1621: pointer.struct.asn1_string_st */
    	em[1624] = 1602; em[1625] = 0; 
    em[1626] = 1; em[1627] = 8; em[1628] = 1; /* 1626: pointer.struct.asn1_string_st */
    	em[1629] = 1602; em[1630] = 0; 
    em[1631] = 1; em[1632] = 8; em[1633] = 1; /* 1631: pointer.struct.asn1_string_st */
    	em[1634] = 1602; em[1635] = 0; 
    em[1636] = 1; em[1637] = 8; em[1638] = 1; /* 1636: pointer.struct.asn1_string_st */
    	em[1639] = 1602; em[1640] = 0; 
    em[1641] = 1; em[1642] = 8; em[1643] = 1; /* 1641: pointer.struct.asn1_string_st */
    	em[1644] = 1602; em[1645] = 0; 
    em[1646] = 1; em[1647] = 8; em[1648] = 1; /* 1646: pointer.struct.asn1_string_st */
    	em[1649] = 1602; em[1650] = 0; 
    em[1651] = 1; em[1652] = 8; em[1653] = 1; /* 1651: pointer.struct.asn1_string_st */
    	em[1654] = 1602; em[1655] = 0; 
    em[1656] = 1; em[1657] = 8; em[1658] = 1; /* 1656: pointer.struct.asn1_string_st */
    	em[1659] = 1602; em[1660] = 0; 
    em[1661] = 1; em[1662] = 8; em[1663] = 1; /* 1661: pointer.struct.asn1_string_st */
    	em[1664] = 1602; em[1665] = 0; 
    em[1666] = 1; em[1667] = 8; em[1668] = 1; /* 1666: pointer.struct.asn1_string_st */
    	em[1669] = 1602; em[1670] = 0; 
    em[1671] = 1; em[1672] = 8; em[1673] = 1; /* 1671: pointer.struct.asn1_string_st */
    	em[1674] = 1602; em[1675] = 0; 
    em[1676] = 1; em[1677] = 8; em[1678] = 1; /* 1676: pointer.struct.asn1_string_st */
    	em[1679] = 1602; em[1680] = 0; 
    em[1681] = 1; em[1682] = 8; em[1683] = 1; /* 1681: pointer.struct.asn1_string_st */
    	em[1684] = 1602; em[1685] = 0; 
    em[1686] = 1; em[1687] = 8; em[1688] = 1; /* 1686: pointer.struct.asn1_string_st */
    	em[1689] = 1602; em[1690] = 0; 
    em[1691] = 1; em[1692] = 8; em[1693] = 1; /* 1691: pointer.struct.ASN1_VALUE_st */
    	em[1694] = 1696; em[1695] = 0; 
    em[1696] = 0; em[1697] = 0; em[1698] = 0; /* 1696: struct.ASN1_VALUE_st */
    em[1699] = 1; em[1700] = 8; em[1701] = 1; /* 1699: pointer.struct.asn1_type_st */
    	em[1702] = 1704; em[1703] = 0; 
    em[1704] = 0; em[1705] = 16; em[1706] = 1; /* 1704: struct.asn1_type_st */
    	em[1707] = 1709; em[1708] = 8; 
    em[1709] = 0; em[1710] = 8; em[1711] = 20; /* 1709: union.unknown */
    	em[1712] = 135; em[1713] = 0; 
    	em[1714] = 1752; em[1715] = 0; 
    	em[1716] = 1492; em[1717] = 0; 
    	em[1718] = 1762; em[1719] = 0; 
    	em[1720] = 1767; em[1721] = 0; 
    	em[1722] = 1772; em[1723] = 0; 
    	em[1724] = 1777; em[1725] = 0; 
    	em[1726] = 1782; em[1727] = 0; 
    	em[1728] = 1787; em[1729] = 0; 
    	em[1730] = 1792; em[1731] = 0; 
    	em[1732] = 1797; em[1733] = 0; 
    	em[1734] = 1802; em[1735] = 0; 
    	em[1736] = 1807; em[1737] = 0; 
    	em[1738] = 1812; em[1739] = 0; 
    	em[1740] = 1817; em[1741] = 0; 
    	em[1742] = 1822; em[1743] = 0; 
    	em[1744] = 1827; em[1745] = 0; 
    	em[1746] = 1752; em[1747] = 0; 
    	em[1748] = 1752; em[1749] = 0; 
    	em[1750] = 1832; em[1751] = 0; 
    em[1752] = 1; em[1753] = 8; em[1754] = 1; /* 1752: pointer.struct.asn1_string_st */
    	em[1755] = 1757; em[1756] = 0; 
    em[1757] = 0; em[1758] = 24; em[1759] = 1; /* 1757: struct.asn1_string_st */
    	em[1760] = 69; em[1761] = 8; 
    em[1762] = 1; em[1763] = 8; em[1764] = 1; /* 1762: pointer.struct.asn1_string_st */
    	em[1765] = 1757; em[1766] = 0; 
    em[1767] = 1; em[1768] = 8; em[1769] = 1; /* 1767: pointer.struct.asn1_string_st */
    	em[1770] = 1757; em[1771] = 0; 
    em[1772] = 1; em[1773] = 8; em[1774] = 1; /* 1772: pointer.struct.asn1_string_st */
    	em[1775] = 1757; em[1776] = 0; 
    em[1777] = 1; em[1778] = 8; em[1779] = 1; /* 1777: pointer.struct.asn1_string_st */
    	em[1780] = 1757; em[1781] = 0; 
    em[1782] = 1; em[1783] = 8; em[1784] = 1; /* 1782: pointer.struct.asn1_string_st */
    	em[1785] = 1757; em[1786] = 0; 
    em[1787] = 1; em[1788] = 8; em[1789] = 1; /* 1787: pointer.struct.asn1_string_st */
    	em[1790] = 1757; em[1791] = 0; 
    em[1792] = 1; em[1793] = 8; em[1794] = 1; /* 1792: pointer.struct.asn1_string_st */
    	em[1795] = 1757; em[1796] = 0; 
    em[1797] = 1; em[1798] = 8; em[1799] = 1; /* 1797: pointer.struct.asn1_string_st */
    	em[1800] = 1757; em[1801] = 0; 
    em[1802] = 1; em[1803] = 8; em[1804] = 1; /* 1802: pointer.struct.asn1_string_st */
    	em[1805] = 1757; em[1806] = 0; 
    em[1807] = 1; em[1808] = 8; em[1809] = 1; /* 1807: pointer.struct.asn1_string_st */
    	em[1810] = 1757; em[1811] = 0; 
    em[1812] = 1; em[1813] = 8; em[1814] = 1; /* 1812: pointer.struct.asn1_string_st */
    	em[1815] = 1757; em[1816] = 0; 
    em[1817] = 1; em[1818] = 8; em[1819] = 1; /* 1817: pointer.struct.asn1_string_st */
    	em[1820] = 1757; em[1821] = 0; 
    em[1822] = 1; em[1823] = 8; em[1824] = 1; /* 1822: pointer.struct.asn1_string_st */
    	em[1825] = 1757; em[1826] = 0; 
    em[1827] = 1; em[1828] = 8; em[1829] = 1; /* 1827: pointer.struct.asn1_string_st */
    	em[1830] = 1757; em[1831] = 0; 
    em[1832] = 1; em[1833] = 8; em[1834] = 1; /* 1832: pointer.struct.ASN1_VALUE_st */
    	em[1835] = 1837; em[1836] = 0; 
    em[1837] = 0; em[1838] = 0; em[1839] = 0; /* 1837: struct.ASN1_VALUE_st */
    em[1840] = 1; em[1841] = 8; em[1842] = 1; /* 1840: pointer.struct.evp_pkey_st */
    	em[1843] = 614; em[1844] = 0; 
    em[1845] = 0; em[1846] = 0; em[1847] = 1; /* 1845: X509_ALGOR */
    	em[1848] = 1850; em[1849] = 0; 
    em[1850] = 0; em[1851] = 16; em[1852] = 2; /* 1850: struct.X509_algor_st */
    	em[1853] = 1857; em[1854] = 0; 
    	em[1855] = 1871; em[1856] = 8; 
    em[1857] = 1; em[1858] = 8; em[1859] = 1; /* 1857: pointer.struct.asn1_object_st */
    	em[1860] = 1862; em[1861] = 0; 
    em[1862] = 0; em[1863] = 40; em[1864] = 3; /* 1862: struct.asn1_object_st */
    	em[1865] = 121; em[1866] = 0; 
    	em[1867] = 121; em[1868] = 8; 
    	em[1869] = 1506; em[1870] = 24; 
    em[1871] = 1; em[1872] = 8; em[1873] = 1; /* 1871: pointer.struct.asn1_type_st */
    	em[1874] = 1876; em[1875] = 0; 
    em[1876] = 0; em[1877] = 16; em[1878] = 1; /* 1876: struct.asn1_type_st */
    	em[1879] = 1881; em[1880] = 8; 
    em[1881] = 0; em[1882] = 8; em[1883] = 20; /* 1881: union.unknown */
    	em[1884] = 135; em[1885] = 0; 
    	em[1886] = 1924; em[1887] = 0; 
    	em[1888] = 1857; em[1889] = 0; 
    	em[1890] = 1934; em[1891] = 0; 
    	em[1892] = 1939; em[1893] = 0; 
    	em[1894] = 1944; em[1895] = 0; 
    	em[1896] = 1949; em[1897] = 0; 
    	em[1898] = 1954; em[1899] = 0; 
    	em[1900] = 1959; em[1901] = 0; 
    	em[1902] = 1964; em[1903] = 0; 
    	em[1904] = 1969; em[1905] = 0; 
    	em[1906] = 1974; em[1907] = 0; 
    	em[1908] = 1979; em[1909] = 0; 
    	em[1910] = 1984; em[1911] = 0; 
    	em[1912] = 1989; em[1913] = 0; 
    	em[1914] = 1994; em[1915] = 0; 
    	em[1916] = 1999; em[1917] = 0; 
    	em[1918] = 1924; em[1919] = 0; 
    	em[1920] = 1924; em[1921] = 0; 
    	em[1922] = 2004; em[1923] = 0; 
    em[1924] = 1; em[1925] = 8; em[1926] = 1; /* 1924: pointer.struct.asn1_string_st */
    	em[1927] = 1929; em[1928] = 0; 
    em[1929] = 0; em[1930] = 24; em[1931] = 1; /* 1929: struct.asn1_string_st */
    	em[1932] = 69; em[1933] = 8; 
    em[1934] = 1; em[1935] = 8; em[1936] = 1; /* 1934: pointer.struct.asn1_string_st */
    	em[1937] = 1929; em[1938] = 0; 
    em[1939] = 1; em[1940] = 8; em[1941] = 1; /* 1939: pointer.struct.asn1_string_st */
    	em[1942] = 1929; em[1943] = 0; 
    em[1944] = 1; em[1945] = 8; em[1946] = 1; /* 1944: pointer.struct.asn1_string_st */
    	em[1947] = 1929; em[1948] = 0; 
    em[1949] = 1; em[1950] = 8; em[1951] = 1; /* 1949: pointer.struct.asn1_string_st */
    	em[1952] = 1929; em[1953] = 0; 
    em[1954] = 1; em[1955] = 8; em[1956] = 1; /* 1954: pointer.struct.asn1_string_st */
    	em[1957] = 1929; em[1958] = 0; 
    em[1959] = 1; em[1960] = 8; em[1961] = 1; /* 1959: pointer.struct.asn1_string_st */
    	em[1962] = 1929; em[1963] = 0; 
    em[1964] = 1; em[1965] = 8; em[1966] = 1; /* 1964: pointer.struct.asn1_string_st */
    	em[1967] = 1929; em[1968] = 0; 
    em[1969] = 1; em[1970] = 8; em[1971] = 1; /* 1969: pointer.struct.asn1_string_st */
    	em[1972] = 1929; em[1973] = 0; 
    em[1974] = 1; em[1975] = 8; em[1976] = 1; /* 1974: pointer.struct.asn1_string_st */
    	em[1977] = 1929; em[1978] = 0; 
    em[1979] = 1; em[1980] = 8; em[1981] = 1; /* 1979: pointer.struct.asn1_string_st */
    	em[1982] = 1929; em[1983] = 0; 
    em[1984] = 1; em[1985] = 8; em[1986] = 1; /* 1984: pointer.struct.asn1_string_st */
    	em[1987] = 1929; em[1988] = 0; 
    em[1989] = 1; em[1990] = 8; em[1991] = 1; /* 1989: pointer.struct.asn1_string_st */
    	em[1992] = 1929; em[1993] = 0; 
    em[1994] = 1; em[1995] = 8; em[1996] = 1; /* 1994: pointer.struct.asn1_string_st */
    	em[1997] = 1929; em[1998] = 0; 
    em[1999] = 1; em[2000] = 8; em[2001] = 1; /* 1999: pointer.struct.asn1_string_st */
    	em[2002] = 1929; em[2003] = 0; 
    em[2004] = 1; em[2005] = 8; em[2006] = 1; /* 2004: pointer.struct.ASN1_VALUE_st */
    	em[2007] = 2009; em[2008] = 0; 
    em[2009] = 0; em[2010] = 0; em[2011] = 0; /* 2009: struct.ASN1_VALUE_st */
    em[2012] = 1; em[2013] = 8; em[2014] = 1; /* 2012: pointer.struct.stack_st_X509_ALGOR */
    	em[2015] = 2017; em[2016] = 0; 
    em[2017] = 0; em[2018] = 32; em[2019] = 2; /* 2017: struct.stack_st_fake_X509_ALGOR */
    	em[2020] = 2024; em[2021] = 8; 
    	em[2022] = 94; em[2023] = 24; 
    em[2024] = 8884099; em[2025] = 8; em[2026] = 2; /* 2024: pointer_to_array_of_pointers_to_stack */
    	em[2027] = 2031; em[2028] = 0; 
    	em[2029] = 52; em[2030] = 20; 
    em[2031] = 0; em[2032] = 8; em[2033] = 1; /* 2031: pointer.X509_ALGOR */
    	em[2034] = 1845; em[2035] = 0; 
    em[2036] = 1; em[2037] = 8; em[2038] = 1; /* 2036: pointer.struct.x509_cert_aux_st */
    	em[2039] = 2041; em[2040] = 0; 
    em[2041] = 0; em[2042] = 40; em[2043] = 5; /* 2041: struct.x509_cert_aux_st */
    	em[2044] = 2054; em[2045] = 0; 
    	em[2046] = 2054; em[2047] = 8; 
    	em[2048] = 2083; em[2049] = 16; 
    	em[2050] = 2093; em[2051] = 24; 
    	em[2052] = 2012; em[2053] = 32; 
    em[2054] = 1; em[2055] = 8; em[2056] = 1; /* 2054: pointer.struct.stack_st_ASN1_OBJECT */
    	em[2057] = 2059; em[2058] = 0; 
    em[2059] = 0; em[2060] = 32; em[2061] = 2; /* 2059: struct.stack_st_fake_ASN1_OBJECT */
    	em[2062] = 2066; em[2063] = 8; 
    	em[2064] = 94; em[2065] = 24; 
    em[2066] = 8884099; em[2067] = 8; em[2068] = 2; /* 2066: pointer_to_array_of_pointers_to_stack */
    	em[2069] = 2073; em[2070] = 0; 
    	em[2071] = 52; em[2072] = 20; 
    em[2073] = 0; em[2074] = 8; em[2075] = 1; /* 2073: pointer.ASN1_OBJECT */
    	em[2076] = 2078; em[2077] = 0; 
    em[2078] = 0; em[2079] = 0; em[2080] = 1; /* 2078: ASN1_OBJECT */
    	em[2081] = 1612; em[2082] = 0; 
    em[2083] = 1; em[2084] = 8; em[2085] = 1; /* 2083: pointer.struct.asn1_string_st */
    	em[2086] = 2088; em[2087] = 0; 
    em[2088] = 0; em[2089] = 24; em[2090] = 1; /* 2088: struct.asn1_string_st */
    	em[2091] = 69; em[2092] = 8; 
    em[2093] = 1; em[2094] = 8; em[2095] = 1; /* 2093: pointer.struct.asn1_string_st */
    	em[2096] = 2088; em[2097] = 0; 
    em[2098] = 0; em[2099] = 16; em[2100] = 2; /* 2098: struct.EDIPartyName_st */
    	em[2101] = 2105; em[2102] = 0; 
    	em[2103] = 2105; em[2104] = 8; 
    em[2105] = 1; em[2106] = 8; em[2107] = 1; /* 2105: pointer.struct.asn1_string_st */
    	em[2108] = 2110; em[2109] = 0; 
    em[2110] = 0; em[2111] = 24; em[2112] = 1; /* 2110: struct.asn1_string_st */
    	em[2113] = 69; em[2114] = 8; 
    em[2115] = 0; em[2116] = 24; em[2117] = 1; /* 2115: struct.buf_mem_st */
    	em[2118] = 135; em[2119] = 8; 
    em[2120] = 1; em[2121] = 8; em[2122] = 1; /* 2120: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[2123] = 2125; em[2124] = 0; 
    em[2125] = 0; em[2126] = 32; em[2127] = 2; /* 2125: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[2128] = 2132; em[2129] = 8; 
    	em[2130] = 94; em[2131] = 24; 
    em[2132] = 8884099; em[2133] = 8; em[2134] = 2; /* 2132: pointer_to_array_of_pointers_to_stack */
    	em[2135] = 2139; em[2136] = 0; 
    	em[2137] = 52; em[2138] = 20; 
    em[2139] = 0; em[2140] = 8; em[2141] = 1; /* 2139: pointer.X509_NAME_ENTRY */
    	em[2142] = 2144; em[2143] = 0; 
    em[2144] = 0; em[2145] = 0; em[2146] = 1; /* 2144: X509_NAME_ENTRY */
    	em[2147] = 2149; em[2148] = 0; 
    em[2149] = 0; em[2150] = 24; em[2151] = 2; /* 2149: struct.X509_name_entry_st */
    	em[2152] = 2156; em[2153] = 0; 
    	em[2154] = 2170; em[2155] = 8; 
    em[2156] = 1; em[2157] = 8; em[2158] = 1; /* 2156: pointer.struct.asn1_object_st */
    	em[2159] = 2161; em[2160] = 0; 
    em[2161] = 0; em[2162] = 40; em[2163] = 3; /* 2161: struct.asn1_object_st */
    	em[2164] = 121; em[2165] = 0; 
    	em[2166] = 121; em[2167] = 8; 
    	em[2168] = 1506; em[2169] = 24; 
    em[2170] = 1; em[2171] = 8; em[2172] = 1; /* 2170: pointer.struct.asn1_string_st */
    	em[2173] = 2175; em[2174] = 0; 
    em[2175] = 0; em[2176] = 24; em[2177] = 1; /* 2175: struct.asn1_string_st */
    	em[2178] = 69; em[2179] = 8; 
    em[2180] = 1; em[2181] = 8; em[2182] = 1; /* 2180: pointer.struct.asn1_string_st */
    	em[2183] = 2110; em[2184] = 0; 
    em[2185] = 1; em[2186] = 8; em[2187] = 1; /* 2185: pointer.struct.asn1_string_st */
    	em[2188] = 2110; em[2189] = 0; 
    em[2190] = 1; em[2191] = 8; em[2192] = 1; /* 2190: pointer.struct.asn1_string_st */
    	em[2193] = 2110; em[2194] = 0; 
    em[2195] = 1; em[2196] = 8; em[2197] = 1; /* 2195: pointer.struct.asn1_string_st */
    	em[2198] = 2110; em[2199] = 0; 
    em[2200] = 1; em[2201] = 8; em[2202] = 1; /* 2200: pointer.struct.asn1_string_st */
    	em[2203] = 2110; em[2204] = 0; 
    em[2205] = 1; em[2206] = 8; em[2207] = 1; /* 2205: pointer.struct.asn1_string_st */
    	em[2208] = 2110; em[2209] = 0; 
    em[2210] = 0; em[2211] = 8; em[2212] = 20; /* 2210: union.unknown */
    	em[2213] = 135; em[2214] = 0; 
    	em[2215] = 2105; em[2216] = 0; 
    	em[2217] = 2253; em[2218] = 0; 
    	em[2219] = 2267; em[2220] = 0; 
    	em[2221] = 2272; em[2222] = 0; 
    	em[2223] = 2277; em[2224] = 0; 
    	em[2225] = 2205; em[2226] = 0; 
    	em[2227] = 2200; em[2228] = 0; 
    	em[2229] = 2282; em[2230] = 0; 
    	em[2231] = 2287; em[2232] = 0; 
    	em[2233] = 2195; em[2234] = 0; 
    	em[2235] = 2190; em[2236] = 0; 
    	em[2237] = 2185; em[2238] = 0; 
    	em[2239] = 2292; em[2240] = 0; 
    	em[2241] = 2180; em[2242] = 0; 
    	em[2243] = 2297; em[2244] = 0; 
    	em[2245] = 2302; em[2246] = 0; 
    	em[2247] = 2105; em[2248] = 0; 
    	em[2249] = 2105; em[2250] = 0; 
    	em[2251] = 2307; em[2252] = 0; 
    em[2253] = 1; em[2254] = 8; em[2255] = 1; /* 2253: pointer.struct.asn1_object_st */
    	em[2256] = 2258; em[2257] = 0; 
    em[2258] = 0; em[2259] = 40; em[2260] = 3; /* 2258: struct.asn1_object_st */
    	em[2261] = 121; em[2262] = 0; 
    	em[2263] = 121; em[2264] = 8; 
    	em[2265] = 1506; em[2266] = 24; 
    em[2267] = 1; em[2268] = 8; em[2269] = 1; /* 2267: pointer.struct.asn1_string_st */
    	em[2270] = 2110; em[2271] = 0; 
    em[2272] = 1; em[2273] = 8; em[2274] = 1; /* 2272: pointer.struct.asn1_string_st */
    	em[2275] = 2110; em[2276] = 0; 
    em[2277] = 1; em[2278] = 8; em[2279] = 1; /* 2277: pointer.struct.asn1_string_st */
    	em[2280] = 2110; em[2281] = 0; 
    em[2282] = 1; em[2283] = 8; em[2284] = 1; /* 2282: pointer.struct.asn1_string_st */
    	em[2285] = 2110; em[2286] = 0; 
    em[2287] = 1; em[2288] = 8; em[2289] = 1; /* 2287: pointer.struct.asn1_string_st */
    	em[2290] = 2110; em[2291] = 0; 
    em[2292] = 1; em[2293] = 8; em[2294] = 1; /* 2292: pointer.struct.asn1_string_st */
    	em[2295] = 2110; em[2296] = 0; 
    em[2297] = 1; em[2298] = 8; em[2299] = 1; /* 2297: pointer.struct.asn1_string_st */
    	em[2300] = 2110; em[2301] = 0; 
    em[2302] = 1; em[2303] = 8; em[2304] = 1; /* 2302: pointer.struct.asn1_string_st */
    	em[2305] = 2110; em[2306] = 0; 
    em[2307] = 1; em[2308] = 8; em[2309] = 1; /* 2307: pointer.struct.ASN1_VALUE_st */
    	em[2310] = 2312; em[2311] = 0; 
    em[2312] = 0; em[2313] = 0; em[2314] = 0; /* 2312: struct.ASN1_VALUE_st */
    em[2315] = 1; em[2316] = 8; em[2317] = 1; /* 2315: pointer.struct.GENERAL_NAME_st */
    	em[2318] = 2320; em[2319] = 0; 
    em[2320] = 0; em[2321] = 16; em[2322] = 1; /* 2320: struct.GENERAL_NAME_st */
    	em[2323] = 2325; em[2324] = 8; 
    em[2325] = 0; em[2326] = 8; em[2327] = 15; /* 2325: union.unknown */
    	em[2328] = 135; em[2329] = 0; 
    	em[2330] = 2358; em[2331] = 0; 
    	em[2332] = 2287; em[2333] = 0; 
    	em[2334] = 2287; em[2335] = 0; 
    	em[2336] = 2370; em[2337] = 0; 
    	em[2338] = 2380; em[2339] = 0; 
    	em[2340] = 2399; em[2341] = 0; 
    	em[2342] = 2287; em[2343] = 0; 
    	em[2344] = 2205; em[2345] = 0; 
    	em[2346] = 2253; em[2347] = 0; 
    	em[2348] = 2205; em[2349] = 0; 
    	em[2350] = 2380; em[2351] = 0; 
    	em[2352] = 2287; em[2353] = 0; 
    	em[2354] = 2253; em[2355] = 0; 
    	em[2356] = 2370; em[2357] = 0; 
    em[2358] = 1; em[2359] = 8; em[2360] = 1; /* 2358: pointer.struct.otherName_st */
    	em[2361] = 2363; em[2362] = 0; 
    em[2363] = 0; em[2364] = 16; em[2365] = 2; /* 2363: struct.otherName_st */
    	em[2366] = 2253; em[2367] = 0; 
    	em[2368] = 2370; em[2369] = 8; 
    em[2370] = 1; em[2371] = 8; em[2372] = 1; /* 2370: pointer.struct.asn1_type_st */
    	em[2373] = 2375; em[2374] = 0; 
    em[2375] = 0; em[2376] = 16; em[2377] = 1; /* 2375: struct.asn1_type_st */
    	em[2378] = 2210; em[2379] = 8; 
    em[2380] = 1; em[2381] = 8; em[2382] = 1; /* 2380: pointer.struct.X509_name_st */
    	em[2383] = 2385; em[2384] = 0; 
    em[2385] = 0; em[2386] = 40; em[2387] = 3; /* 2385: struct.X509_name_st */
    	em[2388] = 2120; em[2389] = 0; 
    	em[2390] = 2394; em[2391] = 16; 
    	em[2392] = 69; em[2393] = 24; 
    em[2394] = 1; em[2395] = 8; em[2396] = 1; /* 2394: pointer.struct.buf_mem_st */
    	em[2397] = 2115; em[2398] = 0; 
    em[2399] = 1; em[2400] = 8; em[2401] = 1; /* 2399: pointer.struct.EDIPartyName_st */
    	em[2402] = 2098; em[2403] = 0; 
    em[2404] = 0; em[2405] = 24; em[2406] = 3; /* 2404: struct.GENERAL_SUBTREE_st */
    	em[2407] = 2315; em[2408] = 0; 
    	em[2409] = 2267; em[2410] = 8; 
    	em[2411] = 2267; em[2412] = 16; 
    em[2413] = 0; em[2414] = 0; em[2415] = 1; /* 2413: GENERAL_SUBTREE */
    	em[2416] = 2404; em[2417] = 0; 
    em[2418] = 1; em[2419] = 8; em[2420] = 1; /* 2418: pointer.struct.stack_st_GENERAL_SUBTREE */
    	em[2421] = 2423; em[2422] = 0; 
    em[2423] = 0; em[2424] = 32; em[2425] = 2; /* 2423: struct.stack_st_fake_GENERAL_SUBTREE */
    	em[2426] = 2430; em[2427] = 8; 
    	em[2428] = 94; em[2429] = 24; 
    em[2430] = 8884099; em[2431] = 8; em[2432] = 2; /* 2430: pointer_to_array_of_pointers_to_stack */
    	em[2433] = 2437; em[2434] = 0; 
    	em[2435] = 52; em[2436] = 20; 
    em[2437] = 0; em[2438] = 8; em[2439] = 1; /* 2437: pointer.GENERAL_SUBTREE */
    	em[2440] = 2413; em[2441] = 0; 
    em[2442] = 0; em[2443] = 16; em[2444] = 2; /* 2442: struct.NAME_CONSTRAINTS_st */
    	em[2445] = 2418; em[2446] = 0; 
    	em[2447] = 2418; em[2448] = 8; 
    em[2449] = 1; em[2450] = 8; em[2451] = 1; /* 2449: pointer.struct.NAME_CONSTRAINTS_st */
    	em[2452] = 2442; em[2453] = 0; 
    em[2454] = 1; em[2455] = 8; em[2456] = 1; /* 2454: pointer.struct.stack_st_GENERAL_NAME */
    	em[2457] = 2459; em[2458] = 0; 
    em[2459] = 0; em[2460] = 32; em[2461] = 2; /* 2459: struct.stack_st_fake_GENERAL_NAME */
    	em[2462] = 2466; em[2463] = 8; 
    	em[2464] = 94; em[2465] = 24; 
    em[2466] = 8884099; em[2467] = 8; em[2468] = 2; /* 2466: pointer_to_array_of_pointers_to_stack */
    	em[2469] = 2473; em[2470] = 0; 
    	em[2471] = 52; em[2472] = 20; 
    em[2473] = 0; em[2474] = 8; em[2475] = 1; /* 2473: pointer.GENERAL_NAME */
    	em[2476] = 2478; em[2477] = 0; 
    em[2478] = 0; em[2479] = 0; em[2480] = 1; /* 2478: GENERAL_NAME */
    	em[2481] = 2483; em[2482] = 0; 
    em[2483] = 0; em[2484] = 16; em[2485] = 1; /* 2483: struct.GENERAL_NAME_st */
    	em[2486] = 2488; em[2487] = 8; 
    em[2488] = 0; em[2489] = 8; em[2490] = 15; /* 2488: union.unknown */
    	em[2491] = 135; em[2492] = 0; 
    	em[2493] = 2521; em[2494] = 0; 
    	em[2495] = 2640; em[2496] = 0; 
    	em[2497] = 2640; em[2498] = 0; 
    	em[2499] = 2547; em[2500] = 0; 
    	em[2501] = 2680; em[2502] = 0; 
    	em[2503] = 2728; em[2504] = 0; 
    	em[2505] = 2640; em[2506] = 0; 
    	em[2507] = 2625; em[2508] = 0; 
    	em[2509] = 2533; em[2510] = 0; 
    	em[2511] = 2625; em[2512] = 0; 
    	em[2513] = 2680; em[2514] = 0; 
    	em[2515] = 2640; em[2516] = 0; 
    	em[2517] = 2533; em[2518] = 0; 
    	em[2519] = 2547; em[2520] = 0; 
    em[2521] = 1; em[2522] = 8; em[2523] = 1; /* 2521: pointer.struct.otherName_st */
    	em[2524] = 2526; em[2525] = 0; 
    em[2526] = 0; em[2527] = 16; em[2528] = 2; /* 2526: struct.otherName_st */
    	em[2529] = 2533; em[2530] = 0; 
    	em[2531] = 2547; em[2532] = 8; 
    em[2533] = 1; em[2534] = 8; em[2535] = 1; /* 2533: pointer.struct.asn1_object_st */
    	em[2536] = 2538; em[2537] = 0; 
    em[2538] = 0; em[2539] = 40; em[2540] = 3; /* 2538: struct.asn1_object_st */
    	em[2541] = 121; em[2542] = 0; 
    	em[2543] = 121; em[2544] = 8; 
    	em[2545] = 1506; em[2546] = 24; 
    em[2547] = 1; em[2548] = 8; em[2549] = 1; /* 2547: pointer.struct.asn1_type_st */
    	em[2550] = 2552; em[2551] = 0; 
    em[2552] = 0; em[2553] = 16; em[2554] = 1; /* 2552: struct.asn1_type_st */
    	em[2555] = 2557; em[2556] = 8; 
    em[2557] = 0; em[2558] = 8; em[2559] = 20; /* 2557: union.unknown */
    	em[2560] = 135; em[2561] = 0; 
    	em[2562] = 2600; em[2563] = 0; 
    	em[2564] = 2533; em[2565] = 0; 
    	em[2566] = 2610; em[2567] = 0; 
    	em[2568] = 2615; em[2569] = 0; 
    	em[2570] = 2620; em[2571] = 0; 
    	em[2572] = 2625; em[2573] = 0; 
    	em[2574] = 2630; em[2575] = 0; 
    	em[2576] = 2635; em[2577] = 0; 
    	em[2578] = 2640; em[2579] = 0; 
    	em[2580] = 2645; em[2581] = 0; 
    	em[2582] = 2650; em[2583] = 0; 
    	em[2584] = 2655; em[2585] = 0; 
    	em[2586] = 2660; em[2587] = 0; 
    	em[2588] = 2665; em[2589] = 0; 
    	em[2590] = 2670; em[2591] = 0; 
    	em[2592] = 2675; em[2593] = 0; 
    	em[2594] = 2600; em[2595] = 0; 
    	em[2596] = 2600; em[2597] = 0; 
    	em[2598] = 2307; em[2599] = 0; 
    em[2600] = 1; em[2601] = 8; em[2602] = 1; /* 2600: pointer.struct.asn1_string_st */
    	em[2603] = 2605; em[2604] = 0; 
    em[2605] = 0; em[2606] = 24; em[2607] = 1; /* 2605: struct.asn1_string_st */
    	em[2608] = 69; em[2609] = 8; 
    em[2610] = 1; em[2611] = 8; em[2612] = 1; /* 2610: pointer.struct.asn1_string_st */
    	em[2613] = 2605; em[2614] = 0; 
    em[2615] = 1; em[2616] = 8; em[2617] = 1; /* 2615: pointer.struct.asn1_string_st */
    	em[2618] = 2605; em[2619] = 0; 
    em[2620] = 1; em[2621] = 8; em[2622] = 1; /* 2620: pointer.struct.asn1_string_st */
    	em[2623] = 2605; em[2624] = 0; 
    em[2625] = 1; em[2626] = 8; em[2627] = 1; /* 2625: pointer.struct.asn1_string_st */
    	em[2628] = 2605; em[2629] = 0; 
    em[2630] = 1; em[2631] = 8; em[2632] = 1; /* 2630: pointer.struct.asn1_string_st */
    	em[2633] = 2605; em[2634] = 0; 
    em[2635] = 1; em[2636] = 8; em[2637] = 1; /* 2635: pointer.struct.asn1_string_st */
    	em[2638] = 2605; em[2639] = 0; 
    em[2640] = 1; em[2641] = 8; em[2642] = 1; /* 2640: pointer.struct.asn1_string_st */
    	em[2643] = 2605; em[2644] = 0; 
    em[2645] = 1; em[2646] = 8; em[2647] = 1; /* 2645: pointer.struct.asn1_string_st */
    	em[2648] = 2605; em[2649] = 0; 
    em[2650] = 1; em[2651] = 8; em[2652] = 1; /* 2650: pointer.struct.asn1_string_st */
    	em[2653] = 2605; em[2654] = 0; 
    em[2655] = 1; em[2656] = 8; em[2657] = 1; /* 2655: pointer.struct.asn1_string_st */
    	em[2658] = 2605; em[2659] = 0; 
    em[2660] = 1; em[2661] = 8; em[2662] = 1; /* 2660: pointer.struct.asn1_string_st */
    	em[2663] = 2605; em[2664] = 0; 
    em[2665] = 1; em[2666] = 8; em[2667] = 1; /* 2665: pointer.struct.asn1_string_st */
    	em[2668] = 2605; em[2669] = 0; 
    em[2670] = 1; em[2671] = 8; em[2672] = 1; /* 2670: pointer.struct.asn1_string_st */
    	em[2673] = 2605; em[2674] = 0; 
    em[2675] = 1; em[2676] = 8; em[2677] = 1; /* 2675: pointer.struct.asn1_string_st */
    	em[2678] = 2605; em[2679] = 0; 
    em[2680] = 1; em[2681] = 8; em[2682] = 1; /* 2680: pointer.struct.X509_name_st */
    	em[2683] = 2685; em[2684] = 0; 
    em[2685] = 0; em[2686] = 40; em[2687] = 3; /* 2685: struct.X509_name_st */
    	em[2688] = 2694; em[2689] = 0; 
    	em[2690] = 2718; em[2691] = 16; 
    	em[2692] = 69; em[2693] = 24; 
    em[2694] = 1; em[2695] = 8; em[2696] = 1; /* 2694: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[2697] = 2699; em[2698] = 0; 
    em[2699] = 0; em[2700] = 32; em[2701] = 2; /* 2699: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[2702] = 2706; em[2703] = 8; 
    	em[2704] = 94; em[2705] = 24; 
    em[2706] = 8884099; em[2707] = 8; em[2708] = 2; /* 2706: pointer_to_array_of_pointers_to_stack */
    	em[2709] = 2713; em[2710] = 0; 
    	em[2711] = 52; em[2712] = 20; 
    em[2713] = 0; em[2714] = 8; em[2715] = 1; /* 2713: pointer.X509_NAME_ENTRY */
    	em[2716] = 2144; em[2717] = 0; 
    em[2718] = 1; em[2719] = 8; em[2720] = 1; /* 2718: pointer.struct.buf_mem_st */
    	em[2721] = 2723; em[2722] = 0; 
    em[2723] = 0; em[2724] = 24; em[2725] = 1; /* 2723: struct.buf_mem_st */
    	em[2726] = 135; em[2727] = 8; 
    em[2728] = 1; em[2729] = 8; em[2730] = 1; /* 2728: pointer.struct.EDIPartyName_st */
    	em[2731] = 2733; em[2732] = 0; 
    em[2733] = 0; em[2734] = 16; em[2735] = 2; /* 2733: struct.EDIPartyName_st */
    	em[2736] = 2600; em[2737] = 0; 
    	em[2738] = 2600; em[2739] = 8; 
    em[2740] = 0; em[2741] = 8; em[2742] = 2; /* 2740: union.unknown */
    	em[2743] = 2747; em[2744] = 0; 
    	em[2745] = 2771; em[2746] = 0; 
    em[2747] = 1; em[2748] = 8; em[2749] = 1; /* 2747: pointer.struct.stack_st_GENERAL_NAME */
    	em[2750] = 2752; em[2751] = 0; 
    em[2752] = 0; em[2753] = 32; em[2754] = 2; /* 2752: struct.stack_st_fake_GENERAL_NAME */
    	em[2755] = 2759; em[2756] = 8; 
    	em[2757] = 94; em[2758] = 24; 
    em[2759] = 8884099; em[2760] = 8; em[2761] = 2; /* 2759: pointer_to_array_of_pointers_to_stack */
    	em[2762] = 2766; em[2763] = 0; 
    	em[2764] = 52; em[2765] = 20; 
    em[2766] = 0; em[2767] = 8; em[2768] = 1; /* 2766: pointer.GENERAL_NAME */
    	em[2769] = 2478; em[2770] = 0; 
    em[2771] = 1; em[2772] = 8; em[2773] = 1; /* 2771: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[2774] = 2776; em[2775] = 0; 
    em[2776] = 0; em[2777] = 32; em[2778] = 2; /* 2776: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[2779] = 2783; em[2780] = 8; 
    	em[2781] = 94; em[2782] = 24; 
    em[2783] = 8884099; em[2784] = 8; em[2785] = 2; /* 2783: pointer_to_array_of_pointers_to_stack */
    	em[2786] = 2790; em[2787] = 0; 
    	em[2788] = 52; em[2789] = 20; 
    em[2790] = 0; em[2791] = 8; em[2792] = 1; /* 2790: pointer.X509_NAME_ENTRY */
    	em[2793] = 2144; em[2794] = 0; 
    em[2795] = 1; em[2796] = 8; em[2797] = 1; /* 2795: pointer.struct.DIST_POINT_NAME_st */
    	em[2798] = 2800; em[2799] = 0; 
    em[2800] = 0; em[2801] = 24; em[2802] = 2; /* 2800: struct.DIST_POINT_NAME_st */
    	em[2803] = 2740; em[2804] = 8; 
    	em[2805] = 2807; em[2806] = 16; 
    em[2807] = 1; em[2808] = 8; em[2809] = 1; /* 2807: pointer.struct.X509_name_st */
    	em[2810] = 2812; em[2811] = 0; 
    em[2812] = 0; em[2813] = 40; em[2814] = 3; /* 2812: struct.X509_name_st */
    	em[2815] = 2771; em[2816] = 0; 
    	em[2817] = 2821; em[2818] = 16; 
    	em[2819] = 69; em[2820] = 24; 
    em[2821] = 1; em[2822] = 8; em[2823] = 1; /* 2821: pointer.struct.buf_mem_st */
    	em[2824] = 2826; em[2825] = 0; 
    em[2826] = 0; em[2827] = 24; em[2828] = 1; /* 2826: struct.buf_mem_st */
    	em[2829] = 135; em[2830] = 8; 
    em[2831] = 1; em[2832] = 8; em[2833] = 1; /* 2831: pointer.struct.stack_st_ASN1_OBJECT */
    	em[2834] = 2836; em[2835] = 0; 
    em[2836] = 0; em[2837] = 32; em[2838] = 2; /* 2836: struct.stack_st_fake_ASN1_OBJECT */
    	em[2839] = 2843; em[2840] = 8; 
    	em[2841] = 94; em[2842] = 24; 
    em[2843] = 8884099; em[2844] = 8; em[2845] = 2; /* 2843: pointer_to_array_of_pointers_to_stack */
    	em[2846] = 2850; em[2847] = 0; 
    	em[2848] = 52; em[2849] = 20; 
    em[2850] = 0; em[2851] = 8; em[2852] = 1; /* 2850: pointer.ASN1_OBJECT */
    	em[2853] = 2078; em[2854] = 0; 
    em[2855] = 1; em[2856] = 8; em[2857] = 1; /* 2855: pointer.struct.stack_st_POLICYQUALINFO */
    	em[2858] = 2860; em[2859] = 0; 
    em[2860] = 0; em[2861] = 32; em[2862] = 2; /* 2860: struct.stack_st_fake_POLICYQUALINFO */
    	em[2863] = 2867; em[2864] = 8; 
    	em[2865] = 94; em[2866] = 24; 
    em[2867] = 8884099; em[2868] = 8; em[2869] = 2; /* 2867: pointer_to_array_of_pointers_to_stack */
    	em[2870] = 2874; em[2871] = 0; 
    	em[2872] = 52; em[2873] = 20; 
    em[2874] = 0; em[2875] = 8; em[2876] = 1; /* 2874: pointer.POLICYQUALINFO */
    	em[2877] = 2879; em[2878] = 0; 
    em[2879] = 0; em[2880] = 0; em[2881] = 1; /* 2879: POLICYQUALINFO */
    	em[2882] = 2884; em[2883] = 0; 
    em[2884] = 0; em[2885] = 16; em[2886] = 2; /* 2884: struct.POLICYQUALINFO_st */
    	em[2887] = 2891; em[2888] = 0; 
    	em[2889] = 2905; em[2890] = 8; 
    em[2891] = 1; em[2892] = 8; em[2893] = 1; /* 2891: pointer.struct.asn1_object_st */
    	em[2894] = 2896; em[2895] = 0; 
    em[2896] = 0; em[2897] = 40; em[2898] = 3; /* 2896: struct.asn1_object_st */
    	em[2899] = 121; em[2900] = 0; 
    	em[2901] = 121; em[2902] = 8; 
    	em[2903] = 1506; em[2904] = 24; 
    em[2905] = 0; em[2906] = 8; em[2907] = 3; /* 2905: union.unknown */
    	em[2908] = 2914; em[2909] = 0; 
    	em[2910] = 2924; em[2911] = 0; 
    	em[2912] = 2987; em[2913] = 0; 
    em[2914] = 1; em[2915] = 8; em[2916] = 1; /* 2914: pointer.struct.asn1_string_st */
    	em[2917] = 2919; em[2918] = 0; 
    em[2919] = 0; em[2920] = 24; em[2921] = 1; /* 2919: struct.asn1_string_st */
    	em[2922] = 69; em[2923] = 8; 
    em[2924] = 1; em[2925] = 8; em[2926] = 1; /* 2924: pointer.struct.USERNOTICE_st */
    	em[2927] = 2929; em[2928] = 0; 
    em[2929] = 0; em[2930] = 16; em[2931] = 2; /* 2929: struct.USERNOTICE_st */
    	em[2932] = 2936; em[2933] = 0; 
    	em[2934] = 2948; em[2935] = 8; 
    em[2936] = 1; em[2937] = 8; em[2938] = 1; /* 2936: pointer.struct.NOTICEREF_st */
    	em[2939] = 2941; em[2940] = 0; 
    em[2941] = 0; em[2942] = 16; em[2943] = 2; /* 2941: struct.NOTICEREF_st */
    	em[2944] = 2948; em[2945] = 0; 
    	em[2946] = 2953; em[2947] = 8; 
    em[2948] = 1; em[2949] = 8; em[2950] = 1; /* 2948: pointer.struct.asn1_string_st */
    	em[2951] = 2919; em[2952] = 0; 
    em[2953] = 1; em[2954] = 8; em[2955] = 1; /* 2953: pointer.struct.stack_st_ASN1_INTEGER */
    	em[2956] = 2958; em[2957] = 0; 
    em[2958] = 0; em[2959] = 32; em[2960] = 2; /* 2958: struct.stack_st_fake_ASN1_INTEGER */
    	em[2961] = 2965; em[2962] = 8; 
    	em[2963] = 94; em[2964] = 24; 
    em[2965] = 8884099; em[2966] = 8; em[2967] = 2; /* 2965: pointer_to_array_of_pointers_to_stack */
    	em[2968] = 2972; em[2969] = 0; 
    	em[2970] = 52; em[2971] = 20; 
    em[2972] = 0; em[2973] = 8; em[2974] = 1; /* 2972: pointer.ASN1_INTEGER */
    	em[2975] = 2977; em[2976] = 0; 
    em[2977] = 0; em[2978] = 0; em[2979] = 1; /* 2977: ASN1_INTEGER */
    	em[2980] = 2982; em[2981] = 0; 
    em[2982] = 0; em[2983] = 24; em[2984] = 1; /* 2982: struct.asn1_string_st */
    	em[2985] = 69; em[2986] = 8; 
    em[2987] = 1; em[2988] = 8; em[2989] = 1; /* 2987: pointer.struct.asn1_type_st */
    	em[2990] = 2992; em[2991] = 0; 
    em[2992] = 0; em[2993] = 16; em[2994] = 1; /* 2992: struct.asn1_type_st */
    	em[2995] = 2997; em[2996] = 8; 
    em[2997] = 0; em[2998] = 8; em[2999] = 20; /* 2997: union.unknown */
    	em[3000] = 135; em[3001] = 0; 
    	em[3002] = 2948; em[3003] = 0; 
    	em[3004] = 2891; em[3005] = 0; 
    	em[3006] = 3040; em[3007] = 0; 
    	em[3008] = 3045; em[3009] = 0; 
    	em[3010] = 3050; em[3011] = 0; 
    	em[3012] = 3055; em[3013] = 0; 
    	em[3014] = 3060; em[3015] = 0; 
    	em[3016] = 3065; em[3017] = 0; 
    	em[3018] = 2914; em[3019] = 0; 
    	em[3020] = 3070; em[3021] = 0; 
    	em[3022] = 3075; em[3023] = 0; 
    	em[3024] = 3080; em[3025] = 0; 
    	em[3026] = 3085; em[3027] = 0; 
    	em[3028] = 3090; em[3029] = 0; 
    	em[3030] = 3095; em[3031] = 0; 
    	em[3032] = 3100; em[3033] = 0; 
    	em[3034] = 2948; em[3035] = 0; 
    	em[3036] = 2948; em[3037] = 0; 
    	em[3038] = 2307; em[3039] = 0; 
    em[3040] = 1; em[3041] = 8; em[3042] = 1; /* 3040: pointer.struct.asn1_string_st */
    	em[3043] = 2919; em[3044] = 0; 
    em[3045] = 1; em[3046] = 8; em[3047] = 1; /* 3045: pointer.struct.asn1_string_st */
    	em[3048] = 2919; em[3049] = 0; 
    em[3050] = 1; em[3051] = 8; em[3052] = 1; /* 3050: pointer.struct.asn1_string_st */
    	em[3053] = 2919; em[3054] = 0; 
    em[3055] = 1; em[3056] = 8; em[3057] = 1; /* 3055: pointer.struct.asn1_string_st */
    	em[3058] = 2919; em[3059] = 0; 
    em[3060] = 1; em[3061] = 8; em[3062] = 1; /* 3060: pointer.struct.asn1_string_st */
    	em[3063] = 2919; em[3064] = 0; 
    em[3065] = 1; em[3066] = 8; em[3067] = 1; /* 3065: pointer.struct.asn1_string_st */
    	em[3068] = 2919; em[3069] = 0; 
    em[3070] = 1; em[3071] = 8; em[3072] = 1; /* 3070: pointer.struct.asn1_string_st */
    	em[3073] = 2919; em[3074] = 0; 
    em[3075] = 1; em[3076] = 8; em[3077] = 1; /* 3075: pointer.struct.asn1_string_st */
    	em[3078] = 2919; em[3079] = 0; 
    em[3080] = 1; em[3081] = 8; em[3082] = 1; /* 3080: pointer.struct.asn1_string_st */
    	em[3083] = 2919; em[3084] = 0; 
    em[3085] = 1; em[3086] = 8; em[3087] = 1; /* 3085: pointer.struct.asn1_string_st */
    	em[3088] = 2919; em[3089] = 0; 
    em[3090] = 1; em[3091] = 8; em[3092] = 1; /* 3090: pointer.struct.asn1_string_st */
    	em[3093] = 2919; em[3094] = 0; 
    em[3095] = 1; em[3096] = 8; em[3097] = 1; /* 3095: pointer.struct.asn1_string_st */
    	em[3098] = 2919; em[3099] = 0; 
    em[3100] = 1; em[3101] = 8; em[3102] = 1; /* 3100: pointer.struct.asn1_string_st */
    	em[3103] = 2919; em[3104] = 0; 
    em[3105] = 1; em[3106] = 8; em[3107] = 1; /* 3105: pointer.struct.asn1_object_st */
    	em[3108] = 3110; em[3109] = 0; 
    em[3110] = 0; em[3111] = 40; em[3112] = 3; /* 3110: struct.asn1_object_st */
    	em[3113] = 121; em[3114] = 0; 
    	em[3115] = 121; em[3116] = 8; 
    	em[3117] = 1506; em[3118] = 24; 
    em[3119] = 0; em[3120] = 32; em[3121] = 3; /* 3119: struct.X509_POLICY_DATA_st */
    	em[3122] = 3105; em[3123] = 8; 
    	em[3124] = 2855; em[3125] = 16; 
    	em[3126] = 2831; em[3127] = 24; 
    em[3128] = 1; em[3129] = 8; em[3130] = 1; /* 3128: pointer.struct.stack_st_ASN1_OBJECT */
    	em[3131] = 3133; em[3132] = 0; 
    em[3133] = 0; em[3134] = 32; em[3135] = 2; /* 3133: struct.stack_st_fake_ASN1_OBJECT */
    	em[3136] = 3140; em[3137] = 8; 
    	em[3138] = 94; em[3139] = 24; 
    em[3140] = 8884099; em[3141] = 8; em[3142] = 2; /* 3140: pointer_to_array_of_pointers_to_stack */
    	em[3143] = 3147; em[3144] = 0; 
    	em[3145] = 52; em[3146] = 20; 
    em[3147] = 0; em[3148] = 8; em[3149] = 1; /* 3147: pointer.ASN1_OBJECT */
    	em[3150] = 2078; em[3151] = 0; 
    em[3152] = 1; em[3153] = 8; em[3154] = 1; /* 3152: pointer.struct.stack_st_POLICYQUALINFO */
    	em[3155] = 3157; em[3156] = 0; 
    em[3157] = 0; em[3158] = 32; em[3159] = 2; /* 3157: struct.stack_st_fake_POLICYQUALINFO */
    	em[3160] = 3164; em[3161] = 8; 
    	em[3162] = 94; em[3163] = 24; 
    em[3164] = 8884099; em[3165] = 8; em[3166] = 2; /* 3164: pointer_to_array_of_pointers_to_stack */
    	em[3167] = 3171; em[3168] = 0; 
    	em[3169] = 52; em[3170] = 20; 
    em[3171] = 0; em[3172] = 8; em[3173] = 1; /* 3171: pointer.POLICYQUALINFO */
    	em[3174] = 2879; em[3175] = 0; 
    em[3176] = 1; em[3177] = 8; em[3178] = 1; /* 3176: pointer.struct.asn1_object_st */
    	em[3179] = 3181; em[3180] = 0; 
    em[3181] = 0; em[3182] = 40; em[3183] = 3; /* 3181: struct.asn1_object_st */
    	em[3184] = 121; em[3185] = 0; 
    	em[3186] = 121; em[3187] = 8; 
    	em[3188] = 1506; em[3189] = 24; 
    em[3190] = 0; em[3191] = 32; em[3192] = 3; /* 3190: struct.X509_POLICY_DATA_st */
    	em[3193] = 3176; em[3194] = 8; 
    	em[3195] = 3152; em[3196] = 16; 
    	em[3197] = 3128; em[3198] = 24; 
    em[3199] = 0; em[3200] = 40; em[3201] = 2; /* 3199: struct.X509_POLICY_CACHE_st */
    	em[3202] = 3206; em[3203] = 0; 
    	em[3204] = 3211; em[3205] = 8; 
    em[3206] = 1; em[3207] = 8; em[3208] = 1; /* 3206: pointer.struct.X509_POLICY_DATA_st */
    	em[3209] = 3190; em[3210] = 0; 
    em[3211] = 1; em[3212] = 8; em[3213] = 1; /* 3211: pointer.struct.stack_st_X509_POLICY_DATA */
    	em[3214] = 3216; em[3215] = 0; 
    em[3216] = 0; em[3217] = 32; em[3218] = 2; /* 3216: struct.stack_st_fake_X509_POLICY_DATA */
    	em[3219] = 3223; em[3220] = 8; 
    	em[3221] = 94; em[3222] = 24; 
    em[3223] = 8884099; em[3224] = 8; em[3225] = 2; /* 3223: pointer_to_array_of_pointers_to_stack */
    	em[3226] = 3230; em[3227] = 0; 
    	em[3228] = 52; em[3229] = 20; 
    em[3230] = 0; em[3231] = 8; em[3232] = 1; /* 3230: pointer.X509_POLICY_DATA */
    	em[3233] = 3235; em[3234] = 0; 
    em[3235] = 0; em[3236] = 0; em[3237] = 1; /* 3235: X509_POLICY_DATA */
    	em[3238] = 3119; em[3239] = 0; 
    em[3240] = 1; em[3241] = 8; em[3242] = 1; /* 3240: pointer.struct.asn1_string_st */
    	em[3243] = 3245; em[3244] = 0; 
    em[3245] = 0; em[3246] = 24; em[3247] = 1; /* 3245: struct.asn1_string_st */
    	em[3248] = 69; em[3249] = 8; 
    em[3250] = 0; em[3251] = 0; em[3252] = 1; /* 3250: DIST_POINT */
    	em[3253] = 3255; em[3254] = 0; 
    em[3255] = 0; em[3256] = 32; em[3257] = 3; /* 3255: struct.DIST_POINT_st */
    	em[3258] = 2795; em[3259] = 0; 
    	em[3260] = 3264; em[3261] = 8; 
    	em[3262] = 2747; em[3263] = 16; 
    em[3264] = 1; em[3265] = 8; em[3266] = 1; /* 3264: pointer.struct.asn1_string_st */
    	em[3267] = 3269; em[3268] = 0; 
    em[3269] = 0; em[3270] = 24; em[3271] = 1; /* 3269: struct.asn1_string_st */
    	em[3272] = 69; em[3273] = 8; 
    em[3274] = 1; em[3275] = 8; em[3276] = 1; /* 3274: pointer.struct.stack_st_GENERAL_NAME */
    	em[3277] = 3279; em[3278] = 0; 
    em[3279] = 0; em[3280] = 32; em[3281] = 2; /* 3279: struct.stack_st_fake_GENERAL_NAME */
    	em[3282] = 3286; em[3283] = 8; 
    	em[3284] = 94; em[3285] = 24; 
    em[3286] = 8884099; em[3287] = 8; em[3288] = 2; /* 3286: pointer_to_array_of_pointers_to_stack */
    	em[3289] = 3293; em[3290] = 0; 
    	em[3291] = 52; em[3292] = 20; 
    em[3293] = 0; em[3294] = 8; em[3295] = 1; /* 3293: pointer.GENERAL_NAME */
    	em[3296] = 2478; em[3297] = 0; 
    em[3298] = 1; em[3299] = 8; em[3300] = 1; /* 3298: pointer.struct.asn1_string_st */
    	em[3301] = 3303; em[3302] = 0; 
    em[3303] = 0; em[3304] = 24; em[3305] = 1; /* 3303: struct.asn1_string_st */
    	em[3306] = 69; em[3307] = 8; 
    em[3308] = 1; em[3309] = 8; em[3310] = 1; /* 3308: pointer.struct.asn1_string_st */
    	em[3311] = 2088; em[3312] = 0; 
    em[3313] = 0; em[3314] = 0; em[3315] = 1; /* 3313: X509_EXTENSION */
    	em[3316] = 3318; em[3317] = 0; 
    em[3318] = 0; em[3319] = 24; em[3320] = 2; /* 3318: struct.X509_extension_st */
    	em[3321] = 3325; em[3322] = 0; 
    	em[3323] = 3298; em[3324] = 16; 
    em[3325] = 1; em[3326] = 8; em[3327] = 1; /* 3325: pointer.struct.asn1_object_st */
    	em[3328] = 3330; em[3329] = 0; 
    em[3330] = 0; em[3331] = 40; em[3332] = 3; /* 3330: struct.asn1_object_st */
    	em[3333] = 121; em[3334] = 0; 
    	em[3335] = 121; em[3336] = 8; 
    	em[3337] = 1506; em[3338] = 24; 
    em[3339] = 1; em[3340] = 8; em[3341] = 1; /* 3339: pointer.struct.stack_st_X509_EXTENSION */
    	em[3342] = 3344; em[3343] = 0; 
    em[3344] = 0; em[3345] = 32; em[3346] = 2; /* 3344: struct.stack_st_fake_X509_EXTENSION */
    	em[3347] = 3351; em[3348] = 8; 
    	em[3349] = 94; em[3350] = 24; 
    em[3351] = 8884099; em[3352] = 8; em[3353] = 2; /* 3351: pointer_to_array_of_pointers_to_stack */
    	em[3354] = 3358; em[3355] = 0; 
    	em[3356] = 52; em[3357] = 20; 
    em[3358] = 0; em[3359] = 8; em[3360] = 1; /* 3358: pointer.X509_EXTENSION */
    	em[3361] = 3313; em[3362] = 0; 
    em[3363] = 1; em[3364] = 8; em[3365] = 1; /* 3363: pointer.struct.X509_val_st */
    	em[3366] = 3368; em[3367] = 0; 
    em[3368] = 0; em[3369] = 16; em[3370] = 2; /* 3368: struct.X509_val_st */
    	em[3371] = 3375; em[3372] = 0; 
    	em[3373] = 3375; em[3374] = 8; 
    em[3375] = 1; em[3376] = 8; em[3377] = 1; /* 3375: pointer.struct.asn1_string_st */
    	em[3378] = 2088; em[3379] = 0; 
    em[3380] = 0; em[3381] = 1; em[3382] = 0; /* 3380: char */
    em[3383] = 1; em[3384] = 8; em[3385] = 1; /* 3383: pointer.struct.X509_name_st */
    	em[3386] = 3388; em[3387] = 0; 
    em[3388] = 0; em[3389] = 40; em[3390] = 3; /* 3388: struct.X509_name_st */
    	em[3391] = 3397; em[3392] = 0; 
    	em[3393] = 3421; em[3394] = 16; 
    	em[3395] = 69; em[3396] = 24; 
    em[3397] = 1; em[3398] = 8; em[3399] = 1; /* 3397: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[3400] = 3402; em[3401] = 0; 
    em[3402] = 0; em[3403] = 32; em[3404] = 2; /* 3402: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[3405] = 3409; em[3406] = 8; 
    	em[3407] = 94; em[3408] = 24; 
    em[3409] = 8884099; em[3410] = 8; em[3411] = 2; /* 3409: pointer_to_array_of_pointers_to_stack */
    	em[3412] = 3416; em[3413] = 0; 
    	em[3414] = 52; em[3415] = 20; 
    em[3416] = 0; em[3417] = 8; em[3418] = 1; /* 3416: pointer.X509_NAME_ENTRY */
    	em[3419] = 2144; em[3420] = 0; 
    em[3421] = 1; em[3422] = 8; em[3423] = 1; /* 3421: pointer.struct.buf_mem_st */
    	em[3424] = 3426; em[3425] = 0; 
    em[3426] = 0; em[3427] = 24; em[3428] = 1; /* 3426: struct.buf_mem_st */
    	em[3429] = 135; em[3430] = 8; 
    em[3431] = 1; em[3432] = 8; em[3433] = 1; /* 3431: pointer.struct.evp_pkey_asn1_method_st */
    	em[3434] = 630; em[3435] = 0; 
    em[3436] = 0; em[3437] = 56; em[3438] = 4; /* 3436: struct.evp_pkey_st */
    	em[3439] = 3431; em[3440] = 16; 
    	em[3441] = 3447; em[3442] = 24; 
    	em[3443] = 3452; em[3444] = 32; 
    	em[3445] = 3485; em[3446] = 48; 
    em[3447] = 1; em[3448] = 8; em[3449] = 1; /* 3447: pointer.struct.engine_st */
    	em[3450] = 148; em[3451] = 0; 
    em[3452] = 0; em[3453] = 8; em[3454] = 5; /* 3452: union.unknown */
    	em[3455] = 135; em[3456] = 0; 
    	em[3457] = 3465; em[3458] = 0; 
    	em[3459] = 3470; em[3460] = 0; 
    	em[3461] = 3475; em[3462] = 0; 
    	em[3463] = 3480; em[3464] = 0; 
    em[3465] = 1; em[3466] = 8; em[3467] = 1; /* 3465: pointer.struct.rsa_st */
    	em[3468] = 744; em[3469] = 0; 
    em[3470] = 1; em[3471] = 8; em[3472] = 1; /* 3470: pointer.struct.dsa_st */
    	em[3473] = 488; em[3474] = 0; 
    em[3475] = 1; em[3476] = 8; em[3477] = 1; /* 3475: pointer.struct.dh_st */
    	em[3478] = 5; em[3479] = 0; 
    em[3480] = 1; em[3481] = 8; em[3482] = 1; /* 3480: pointer.struct.ec_key_st */
    	em[3483] = 952; em[3484] = 0; 
    em[3485] = 1; em[3486] = 8; em[3487] = 1; /* 3485: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[3488] = 3490; em[3489] = 0; 
    em[3490] = 0; em[3491] = 32; em[3492] = 2; /* 3490: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[3493] = 3497; em[3494] = 8; 
    	em[3495] = 94; em[3496] = 24; 
    em[3497] = 8884099; em[3498] = 8; em[3499] = 2; /* 3497: pointer_to_array_of_pointers_to_stack */
    	em[3500] = 3504; em[3501] = 0; 
    	em[3502] = 52; em[3503] = 20; 
    em[3504] = 0; em[3505] = 8; em[3506] = 1; /* 3504: pointer.X509_ATTRIBUTE */
    	em[3507] = 1480; em[3508] = 0; 
    em[3509] = 1; em[3510] = 8; em[3511] = 1; /* 3509: pointer.struct.X509_pubkey_st */
    	em[3512] = 3514; em[3513] = 0; 
    em[3514] = 0; em[3515] = 24; em[3516] = 3; /* 3514: struct.X509_pubkey_st */
    	em[3517] = 3523; em[3518] = 0; 
    	em[3519] = 3528; em[3520] = 8; 
    	em[3521] = 3538; em[3522] = 16; 
    em[3523] = 1; em[3524] = 8; em[3525] = 1; /* 3523: pointer.struct.X509_algor_st */
    	em[3526] = 1850; em[3527] = 0; 
    em[3528] = 1; em[3529] = 8; em[3530] = 1; /* 3528: pointer.struct.asn1_string_st */
    	em[3531] = 3533; em[3532] = 0; 
    em[3533] = 0; em[3534] = 24; em[3535] = 1; /* 3533: struct.asn1_string_st */
    	em[3536] = 69; em[3537] = 8; 
    em[3538] = 1; em[3539] = 8; em[3540] = 1; /* 3538: pointer.struct.evp_pkey_st */
    	em[3541] = 3436; em[3542] = 0; 
    em[3543] = 1; em[3544] = 8; em[3545] = 1; /* 3543: pointer.struct.AUTHORITY_KEYID_st */
    	em[3546] = 3548; em[3547] = 0; 
    em[3548] = 0; em[3549] = 24; em[3550] = 3; /* 3548: struct.AUTHORITY_KEYID_st */
    	em[3551] = 3557; em[3552] = 0; 
    	em[3553] = 3274; em[3554] = 8; 
    	em[3555] = 3240; em[3556] = 16; 
    em[3557] = 1; em[3558] = 8; em[3559] = 1; /* 3557: pointer.struct.asn1_string_st */
    	em[3560] = 3245; em[3561] = 0; 
    em[3562] = 1; em[3563] = 8; em[3564] = 1; /* 3562: pointer.struct.X509_algor_st */
    	em[3565] = 1850; em[3566] = 0; 
    em[3567] = 1; em[3568] = 8; em[3569] = 1; /* 3567: pointer.struct.asn1_string_st */
    	em[3570] = 2088; em[3571] = 0; 
    em[3572] = 0; em[3573] = 104; em[3574] = 11; /* 3572: struct.x509_cinf_st */
    	em[3575] = 3567; em[3576] = 0; 
    	em[3577] = 3567; em[3578] = 8; 
    	em[3579] = 3562; em[3580] = 16; 
    	em[3581] = 3383; em[3582] = 24; 
    	em[3583] = 3363; em[3584] = 32; 
    	em[3585] = 3383; em[3586] = 40; 
    	em[3587] = 3509; em[3588] = 48; 
    	em[3589] = 3308; em[3590] = 56; 
    	em[3591] = 3308; em[3592] = 64; 
    	em[3593] = 3339; em[3594] = 72; 
    	em[3595] = 3597; em[3596] = 80; 
    em[3597] = 0; em[3598] = 24; em[3599] = 1; /* 3597: struct.ASN1_ENCODING_st */
    	em[3600] = 69; em[3601] = 0; 
    em[3602] = 1; em[3603] = 8; em[3604] = 1; /* 3602: pointer.struct.x509_cinf_st */
    	em[3605] = 3572; em[3606] = 0; 
    em[3607] = 1; em[3608] = 8; em[3609] = 1; /* 3607: pointer.struct.stack_st_DIST_POINT */
    	em[3610] = 3612; em[3611] = 0; 
    em[3612] = 0; em[3613] = 32; em[3614] = 2; /* 3612: struct.stack_st_fake_DIST_POINT */
    	em[3615] = 3619; em[3616] = 8; 
    	em[3617] = 94; em[3618] = 24; 
    em[3619] = 8884099; em[3620] = 8; em[3621] = 2; /* 3619: pointer_to_array_of_pointers_to_stack */
    	em[3622] = 3626; em[3623] = 0; 
    	em[3624] = 52; em[3625] = 20; 
    em[3626] = 0; em[3627] = 8; em[3628] = 1; /* 3626: pointer.DIST_POINT */
    	em[3629] = 3250; em[3630] = 0; 
    em[3631] = 1; em[3632] = 8; em[3633] = 1; /* 3631: pointer.struct.X509_POLICY_CACHE_st */
    	em[3634] = 3199; em[3635] = 0; 
    em[3636] = 0; em[3637] = 184; em[3638] = 12; /* 3636: struct.x509_st */
    	em[3639] = 3602; em[3640] = 0; 
    	em[3641] = 3562; em[3642] = 8; 
    	em[3643] = 3308; em[3644] = 16; 
    	em[3645] = 135; em[3646] = 32; 
    	em[3647] = 3663; em[3648] = 40; 
    	em[3649] = 2093; em[3650] = 104; 
    	em[3651] = 3543; em[3652] = 112; 
    	em[3653] = 3631; em[3654] = 120; 
    	em[3655] = 3607; em[3656] = 128; 
    	em[3657] = 2454; em[3658] = 136; 
    	em[3659] = 2449; em[3660] = 144; 
    	em[3661] = 2036; em[3662] = 176; 
    em[3663] = 0; em[3664] = 32; em[3665] = 2; /* 3663: struct.crypto_ex_data_st_fake */
    	em[3666] = 3670; em[3667] = 8; 
    	em[3668] = 94; em[3669] = 24; 
    em[3670] = 8884099; em[3671] = 8; em[3672] = 2; /* 3670: pointer_to_array_of_pointers_to_stack */
    	em[3673] = 91; em[3674] = 0; 
    	em[3675] = 52; em[3676] = 20; 
    em[3677] = 1; em[3678] = 8; em[3679] = 1; /* 3677: pointer.struct.x509_st */
    	em[3680] = 3636; em[3681] = 0; 
    args_addr->arg_entity_index[0] = 3677;
    args_addr->arg_entity_index[1] = 1840;
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

