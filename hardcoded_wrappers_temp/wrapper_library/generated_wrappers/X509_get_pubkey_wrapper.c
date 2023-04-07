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

EVP_PKEY * bb_X509_get_pubkey(X509 * arg_a);

EVP_PKEY * X509_get_pubkey(X509 * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("X509_get_pubkey called %lu\n", in_lib);
    if (!in_lib)
        return bb_X509_get_pubkey(arg_a);
    else {
        EVP_PKEY * (*orig_X509_get_pubkey)(X509 *);
        orig_X509_get_pubkey = dlsym(RTLD_NEXT, "X509_get_pubkey");
        return orig_X509_get_pubkey(arg_a);
    }
}

EVP_PKEY * bb_X509_get_pubkey(X509 * arg_a) 
{
    EVP_PKEY * ret;

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
    	em[28] = 112; em[29] = 128; 
    	em[30] = 153; em[31] = 136; 
    em[32] = 1; em[33] = 8; em[34] = 1; /* 32: pointer.struct.bignum_st */
    	em[35] = 37; em[36] = 0; 
    em[37] = 0; em[38] = 24; em[39] = 1; /* 37: struct.bignum_st */
    	em[40] = 42; em[41] = 0; 
    em[42] = 8884099; em[43] = 8; em[44] = 2; /* 42: pointer_to_array_of_pointers_to_stack */
    	em[45] = 49; em[46] = 0; 
    	em[47] = 52; em[48] = 12; 
    em[49] = 0; em[50] = 4; em[51] = 0; /* 49: unsigned int */
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
    em[77] = 0; em[78] = 16; em[79] = 1; /* 77: struct.crypto_ex_data_st */
    	em[80] = 82; em[81] = 0; 
    em[82] = 1; em[83] = 8; em[84] = 1; /* 82: pointer.struct.stack_st_void */
    	em[85] = 87; em[86] = 0; 
    em[87] = 0; em[88] = 32; em[89] = 1; /* 87: struct.stack_st_void */
    	em[90] = 92; em[91] = 0; 
    em[92] = 0; em[93] = 32; em[94] = 2; /* 92: struct.stack_st */
    	em[95] = 99; em[96] = 8; 
    	em[97] = 109; em[98] = 24; 
    em[99] = 1; em[100] = 8; em[101] = 1; /* 99: pointer.pointer.char */
    	em[102] = 104; em[103] = 0; 
    em[104] = 1; em[105] = 8; em[106] = 1; /* 104: pointer.char */
    	em[107] = 8884096; em[108] = 0; 
    em[109] = 8884097; em[110] = 8; em[111] = 0; /* 109: pointer.func */
    em[112] = 1; em[113] = 8; em[114] = 1; /* 112: pointer.struct.dh_method */
    	em[115] = 117; em[116] = 0; 
    em[117] = 0; em[118] = 72; em[119] = 8; /* 117: struct.dh_method */
    	em[120] = 136; em[121] = 0; 
    	em[122] = 141; em[123] = 8; 
    	em[124] = 144; em[125] = 16; 
    	em[126] = 147; em[127] = 24; 
    	em[128] = 141; em[129] = 32; 
    	em[130] = 141; em[131] = 40; 
    	em[132] = 104; em[133] = 56; 
    	em[134] = 150; em[135] = 64; 
    em[136] = 1; em[137] = 8; em[138] = 1; /* 136: pointer.char */
    	em[139] = 8884096; em[140] = 0; 
    em[141] = 8884097; em[142] = 8; em[143] = 0; /* 141: pointer.func */
    em[144] = 8884097; em[145] = 8; em[146] = 0; /* 144: pointer.func */
    em[147] = 8884097; em[148] = 8; em[149] = 0; /* 147: pointer.func */
    em[150] = 8884097; em[151] = 8; em[152] = 0; /* 150: pointer.func */
    em[153] = 1; em[154] = 8; em[155] = 1; /* 153: pointer.struct.engine_st */
    	em[156] = 158; em[157] = 0; 
    em[158] = 0; em[159] = 216; em[160] = 24; /* 158: struct.engine_st */
    	em[161] = 136; em[162] = 0; 
    	em[163] = 136; em[164] = 8; 
    	em[165] = 209; em[166] = 16; 
    	em[167] = 264; em[168] = 24; 
    	em[169] = 315; em[170] = 32; 
    	em[171] = 351; em[172] = 40; 
    	em[173] = 368; em[174] = 48; 
    	em[175] = 395; em[176] = 56; 
    	em[177] = 430; em[178] = 64; 
    	em[179] = 438; em[180] = 72; 
    	em[181] = 441; em[182] = 80; 
    	em[183] = 444; em[184] = 88; 
    	em[185] = 447; em[186] = 96; 
    	em[187] = 450; em[188] = 104; 
    	em[189] = 450; em[190] = 112; 
    	em[191] = 450; em[192] = 120; 
    	em[193] = 453; em[194] = 128; 
    	em[195] = 456; em[196] = 136; 
    	em[197] = 456; em[198] = 144; 
    	em[199] = 459; em[200] = 152; 
    	em[201] = 462; em[202] = 160; 
    	em[203] = 474; em[204] = 184; 
    	em[205] = 496; em[206] = 200; 
    	em[207] = 496; em[208] = 208; 
    em[209] = 1; em[210] = 8; em[211] = 1; /* 209: pointer.struct.rsa_meth_st */
    	em[212] = 214; em[213] = 0; 
    em[214] = 0; em[215] = 112; em[216] = 13; /* 214: struct.rsa_meth_st */
    	em[217] = 136; em[218] = 0; 
    	em[219] = 243; em[220] = 8; 
    	em[221] = 243; em[222] = 16; 
    	em[223] = 243; em[224] = 24; 
    	em[225] = 243; em[226] = 32; 
    	em[227] = 246; em[228] = 40; 
    	em[229] = 249; em[230] = 48; 
    	em[231] = 252; em[232] = 56; 
    	em[233] = 252; em[234] = 64; 
    	em[235] = 104; em[236] = 80; 
    	em[237] = 255; em[238] = 88; 
    	em[239] = 258; em[240] = 96; 
    	em[241] = 261; em[242] = 104; 
    em[243] = 8884097; em[244] = 8; em[245] = 0; /* 243: pointer.func */
    em[246] = 8884097; em[247] = 8; em[248] = 0; /* 246: pointer.func */
    em[249] = 8884097; em[250] = 8; em[251] = 0; /* 249: pointer.func */
    em[252] = 8884097; em[253] = 8; em[254] = 0; /* 252: pointer.func */
    em[255] = 8884097; em[256] = 8; em[257] = 0; /* 255: pointer.func */
    em[258] = 8884097; em[259] = 8; em[260] = 0; /* 258: pointer.func */
    em[261] = 8884097; em[262] = 8; em[263] = 0; /* 261: pointer.func */
    em[264] = 1; em[265] = 8; em[266] = 1; /* 264: pointer.struct.dsa_method */
    	em[267] = 269; em[268] = 0; 
    em[269] = 0; em[270] = 96; em[271] = 11; /* 269: struct.dsa_method */
    	em[272] = 136; em[273] = 0; 
    	em[274] = 294; em[275] = 8; 
    	em[276] = 297; em[277] = 16; 
    	em[278] = 300; em[279] = 24; 
    	em[280] = 303; em[281] = 32; 
    	em[282] = 306; em[283] = 40; 
    	em[284] = 309; em[285] = 48; 
    	em[286] = 309; em[287] = 56; 
    	em[288] = 104; em[289] = 72; 
    	em[290] = 312; em[291] = 80; 
    	em[292] = 309; em[293] = 88; 
    em[294] = 8884097; em[295] = 8; em[296] = 0; /* 294: pointer.func */
    em[297] = 8884097; em[298] = 8; em[299] = 0; /* 297: pointer.func */
    em[300] = 8884097; em[301] = 8; em[302] = 0; /* 300: pointer.func */
    em[303] = 8884097; em[304] = 8; em[305] = 0; /* 303: pointer.func */
    em[306] = 8884097; em[307] = 8; em[308] = 0; /* 306: pointer.func */
    em[309] = 8884097; em[310] = 8; em[311] = 0; /* 309: pointer.func */
    em[312] = 8884097; em[313] = 8; em[314] = 0; /* 312: pointer.func */
    em[315] = 1; em[316] = 8; em[317] = 1; /* 315: pointer.struct.dh_method */
    	em[318] = 320; em[319] = 0; 
    em[320] = 0; em[321] = 72; em[322] = 8; /* 320: struct.dh_method */
    	em[323] = 136; em[324] = 0; 
    	em[325] = 339; em[326] = 8; 
    	em[327] = 342; em[328] = 16; 
    	em[329] = 345; em[330] = 24; 
    	em[331] = 339; em[332] = 32; 
    	em[333] = 339; em[334] = 40; 
    	em[335] = 104; em[336] = 56; 
    	em[337] = 348; em[338] = 64; 
    em[339] = 8884097; em[340] = 8; em[341] = 0; /* 339: pointer.func */
    em[342] = 8884097; em[343] = 8; em[344] = 0; /* 342: pointer.func */
    em[345] = 8884097; em[346] = 8; em[347] = 0; /* 345: pointer.func */
    em[348] = 8884097; em[349] = 8; em[350] = 0; /* 348: pointer.func */
    em[351] = 1; em[352] = 8; em[353] = 1; /* 351: pointer.struct.ecdh_method */
    	em[354] = 356; em[355] = 0; 
    em[356] = 0; em[357] = 32; em[358] = 3; /* 356: struct.ecdh_method */
    	em[359] = 136; em[360] = 0; 
    	em[361] = 365; em[362] = 8; 
    	em[363] = 104; em[364] = 24; 
    em[365] = 8884097; em[366] = 8; em[367] = 0; /* 365: pointer.func */
    em[368] = 1; em[369] = 8; em[370] = 1; /* 368: pointer.struct.ecdsa_method */
    	em[371] = 373; em[372] = 0; 
    em[373] = 0; em[374] = 48; em[375] = 5; /* 373: struct.ecdsa_method */
    	em[376] = 136; em[377] = 0; 
    	em[378] = 386; em[379] = 8; 
    	em[380] = 389; em[381] = 16; 
    	em[382] = 392; em[383] = 24; 
    	em[384] = 104; em[385] = 40; 
    em[386] = 8884097; em[387] = 8; em[388] = 0; /* 386: pointer.func */
    em[389] = 8884097; em[390] = 8; em[391] = 0; /* 389: pointer.func */
    em[392] = 8884097; em[393] = 8; em[394] = 0; /* 392: pointer.func */
    em[395] = 1; em[396] = 8; em[397] = 1; /* 395: pointer.struct.rand_meth_st */
    	em[398] = 400; em[399] = 0; 
    em[400] = 0; em[401] = 48; em[402] = 6; /* 400: struct.rand_meth_st */
    	em[403] = 415; em[404] = 0; 
    	em[405] = 418; em[406] = 8; 
    	em[407] = 421; em[408] = 16; 
    	em[409] = 424; em[410] = 24; 
    	em[411] = 418; em[412] = 32; 
    	em[413] = 427; em[414] = 40; 
    em[415] = 8884097; em[416] = 8; em[417] = 0; /* 415: pointer.func */
    em[418] = 8884097; em[419] = 8; em[420] = 0; /* 418: pointer.func */
    em[421] = 8884097; em[422] = 8; em[423] = 0; /* 421: pointer.func */
    em[424] = 8884097; em[425] = 8; em[426] = 0; /* 424: pointer.func */
    em[427] = 8884097; em[428] = 8; em[429] = 0; /* 427: pointer.func */
    em[430] = 1; em[431] = 8; em[432] = 1; /* 430: pointer.struct.store_method_st */
    	em[433] = 435; em[434] = 0; 
    em[435] = 0; em[436] = 0; em[437] = 0; /* 435: struct.store_method_st */
    em[438] = 8884097; em[439] = 8; em[440] = 0; /* 438: pointer.func */
    em[441] = 8884097; em[442] = 8; em[443] = 0; /* 441: pointer.func */
    em[444] = 8884097; em[445] = 8; em[446] = 0; /* 444: pointer.func */
    em[447] = 8884097; em[448] = 8; em[449] = 0; /* 447: pointer.func */
    em[450] = 8884097; em[451] = 8; em[452] = 0; /* 450: pointer.func */
    em[453] = 8884097; em[454] = 8; em[455] = 0; /* 453: pointer.func */
    em[456] = 8884097; em[457] = 8; em[458] = 0; /* 456: pointer.func */
    em[459] = 8884097; em[460] = 8; em[461] = 0; /* 459: pointer.func */
    em[462] = 1; em[463] = 8; em[464] = 1; /* 462: pointer.struct.ENGINE_CMD_DEFN_st */
    	em[465] = 467; em[466] = 0; 
    em[467] = 0; em[468] = 32; em[469] = 2; /* 467: struct.ENGINE_CMD_DEFN_st */
    	em[470] = 136; em[471] = 8; 
    	em[472] = 136; em[473] = 16; 
    em[474] = 0; em[475] = 16; em[476] = 1; /* 474: struct.crypto_ex_data_st */
    	em[477] = 479; em[478] = 0; 
    em[479] = 1; em[480] = 8; em[481] = 1; /* 479: pointer.struct.stack_st_void */
    	em[482] = 484; em[483] = 0; 
    em[484] = 0; em[485] = 32; em[486] = 1; /* 484: struct.stack_st_void */
    	em[487] = 489; em[488] = 0; 
    em[489] = 0; em[490] = 32; em[491] = 2; /* 489: struct.stack_st */
    	em[492] = 99; em[493] = 8; 
    	em[494] = 109; em[495] = 24; 
    em[496] = 1; em[497] = 8; em[498] = 1; /* 496: pointer.struct.engine_st */
    	em[499] = 158; em[500] = 0; 
    em[501] = 1; em[502] = 8; em[503] = 1; /* 501: pointer.struct.dsa_st */
    	em[504] = 506; em[505] = 0; 
    em[506] = 0; em[507] = 136; em[508] = 11; /* 506: struct.dsa_st */
    	em[509] = 531; em[510] = 24; 
    	em[511] = 531; em[512] = 32; 
    	em[513] = 531; em[514] = 40; 
    	em[515] = 531; em[516] = 48; 
    	em[517] = 531; em[518] = 56; 
    	em[519] = 531; em[520] = 64; 
    	em[521] = 531; em[522] = 72; 
    	em[523] = 548; em[524] = 88; 
    	em[525] = 562; em[526] = 104; 
    	em[527] = 584; em[528] = 120; 
    	em[529] = 635; em[530] = 128; 
    em[531] = 1; em[532] = 8; em[533] = 1; /* 531: pointer.struct.bignum_st */
    	em[534] = 536; em[535] = 0; 
    em[536] = 0; em[537] = 24; em[538] = 1; /* 536: struct.bignum_st */
    	em[539] = 541; em[540] = 0; 
    em[541] = 8884099; em[542] = 8; em[543] = 2; /* 541: pointer_to_array_of_pointers_to_stack */
    	em[544] = 49; em[545] = 0; 
    	em[546] = 52; em[547] = 12; 
    em[548] = 1; em[549] = 8; em[550] = 1; /* 548: pointer.struct.bn_mont_ctx_st */
    	em[551] = 553; em[552] = 0; 
    em[553] = 0; em[554] = 96; em[555] = 3; /* 553: struct.bn_mont_ctx_st */
    	em[556] = 536; em[557] = 8; 
    	em[558] = 536; em[559] = 32; 
    	em[560] = 536; em[561] = 56; 
    em[562] = 0; em[563] = 16; em[564] = 1; /* 562: struct.crypto_ex_data_st */
    	em[565] = 567; em[566] = 0; 
    em[567] = 1; em[568] = 8; em[569] = 1; /* 567: pointer.struct.stack_st_void */
    	em[570] = 572; em[571] = 0; 
    em[572] = 0; em[573] = 32; em[574] = 1; /* 572: struct.stack_st_void */
    	em[575] = 577; em[576] = 0; 
    em[577] = 0; em[578] = 32; em[579] = 2; /* 577: struct.stack_st */
    	em[580] = 99; em[581] = 8; 
    	em[582] = 109; em[583] = 24; 
    em[584] = 1; em[585] = 8; em[586] = 1; /* 584: pointer.struct.dsa_method */
    	em[587] = 589; em[588] = 0; 
    em[589] = 0; em[590] = 96; em[591] = 11; /* 589: struct.dsa_method */
    	em[592] = 136; em[593] = 0; 
    	em[594] = 614; em[595] = 8; 
    	em[596] = 617; em[597] = 16; 
    	em[598] = 620; em[599] = 24; 
    	em[600] = 623; em[601] = 32; 
    	em[602] = 626; em[603] = 40; 
    	em[604] = 629; em[605] = 48; 
    	em[606] = 629; em[607] = 56; 
    	em[608] = 104; em[609] = 72; 
    	em[610] = 632; em[611] = 80; 
    	em[612] = 629; em[613] = 88; 
    em[614] = 8884097; em[615] = 8; em[616] = 0; /* 614: pointer.func */
    em[617] = 8884097; em[618] = 8; em[619] = 0; /* 617: pointer.func */
    em[620] = 8884097; em[621] = 8; em[622] = 0; /* 620: pointer.func */
    em[623] = 8884097; em[624] = 8; em[625] = 0; /* 623: pointer.func */
    em[626] = 8884097; em[627] = 8; em[628] = 0; /* 626: pointer.func */
    em[629] = 8884097; em[630] = 8; em[631] = 0; /* 629: pointer.func */
    em[632] = 8884097; em[633] = 8; em[634] = 0; /* 632: pointer.func */
    em[635] = 1; em[636] = 8; em[637] = 1; /* 635: pointer.struct.engine_st */
    	em[638] = 158; em[639] = 0; 
    em[640] = 1; em[641] = 8; em[642] = 1; /* 640: pointer.struct.rsa_st */
    	em[643] = 645; em[644] = 0; 
    em[645] = 0; em[646] = 168; em[647] = 17; /* 645: struct.rsa_st */
    	em[648] = 682; em[649] = 16; 
    	em[650] = 737; em[651] = 24; 
    	em[652] = 742; em[653] = 32; 
    	em[654] = 742; em[655] = 40; 
    	em[656] = 742; em[657] = 48; 
    	em[658] = 742; em[659] = 56; 
    	em[660] = 742; em[661] = 64; 
    	em[662] = 742; em[663] = 72; 
    	em[664] = 742; em[665] = 80; 
    	em[666] = 742; em[667] = 88; 
    	em[668] = 759; em[669] = 96; 
    	em[670] = 781; em[671] = 120; 
    	em[672] = 781; em[673] = 128; 
    	em[674] = 781; em[675] = 136; 
    	em[676] = 104; em[677] = 144; 
    	em[678] = 795; em[679] = 152; 
    	em[680] = 795; em[681] = 160; 
    em[682] = 1; em[683] = 8; em[684] = 1; /* 682: pointer.struct.rsa_meth_st */
    	em[685] = 687; em[686] = 0; 
    em[687] = 0; em[688] = 112; em[689] = 13; /* 687: struct.rsa_meth_st */
    	em[690] = 136; em[691] = 0; 
    	em[692] = 716; em[693] = 8; 
    	em[694] = 716; em[695] = 16; 
    	em[696] = 716; em[697] = 24; 
    	em[698] = 716; em[699] = 32; 
    	em[700] = 719; em[701] = 40; 
    	em[702] = 722; em[703] = 48; 
    	em[704] = 725; em[705] = 56; 
    	em[706] = 725; em[707] = 64; 
    	em[708] = 104; em[709] = 80; 
    	em[710] = 728; em[711] = 88; 
    	em[712] = 731; em[713] = 96; 
    	em[714] = 734; em[715] = 104; 
    em[716] = 8884097; em[717] = 8; em[718] = 0; /* 716: pointer.func */
    em[719] = 8884097; em[720] = 8; em[721] = 0; /* 719: pointer.func */
    em[722] = 8884097; em[723] = 8; em[724] = 0; /* 722: pointer.func */
    em[725] = 8884097; em[726] = 8; em[727] = 0; /* 725: pointer.func */
    em[728] = 8884097; em[729] = 8; em[730] = 0; /* 728: pointer.func */
    em[731] = 8884097; em[732] = 8; em[733] = 0; /* 731: pointer.func */
    em[734] = 8884097; em[735] = 8; em[736] = 0; /* 734: pointer.func */
    em[737] = 1; em[738] = 8; em[739] = 1; /* 737: pointer.struct.engine_st */
    	em[740] = 158; em[741] = 0; 
    em[742] = 1; em[743] = 8; em[744] = 1; /* 742: pointer.struct.bignum_st */
    	em[745] = 747; em[746] = 0; 
    em[747] = 0; em[748] = 24; em[749] = 1; /* 747: struct.bignum_st */
    	em[750] = 752; em[751] = 0; 
    em[752] = 8884099; em[753] = 8; em[754] = 2; /* 752: pointer_to_array_of_pointers_to_stack */
    	em[755] = 49; em[756] = 0; 
    	em[757] = 52; em[758] = 12; 
    em[759] = 0; em[760] = 16; em[761] = 1; /* 759: struct.crypto_ex_data_st */
    	em[762] = 764; em[763] = 0; 
    em[764] = 1; em[765] = 8; em[766] = 1; /* 764: pointer.struct.stack_st_void */
    	em[767] = 769; em[768] = 0; 
    em[769] = 0; em[770] = 32; em[771] = 1; /* 769: struct.stack_st_void */
    	em[772] = 774; em[773] = 0; 
    em[774] = 0; em[775] = 32; em[776] = 2; /* 774: struct.stack_st */
    	em[777] = 99; em[778] = 8; 
    	em[779] = 109; em[780] = 24; 
    em[781] = 1; em[782] = 8; em[783] = 1; /* 781: pointer.struct.bn_mont_ctx_st */
    	em[784] = 786; em[785] = 0; 
    em[786] = 0; em[787] = 96; em[788] = 3; /* 786: struct.bn_mont_ctx_st */
    	em[789] = 747; em[790] = 8; 
    	em[791] = 747; em[792] = 32; 
    	em[793] = 747; em[794] = 56; 
    em[795] = 1; em[796] = 8; em[797] = 1; /* 795: pointer.struct.bn_blinding_st */
    	em[798] = 800; em[799] = 0; 
    em[800] = 0; em[801] = 88; em[802] = 7; /* 800: struct.bn_blinding_st */
    	em[803] = 817; em[804] = 0; 
    	em[805] = 817; em[806] = 8; 
    	em[807] = 817; em[808] = 16; 
    	em[809] = 817; em[810] = 24; 
    	em[811] = 834; em[812] = 40; 
    	em[813] = 842; em[814] = 72; 
    	em[815] = 856; em[816] = 80; 
    em[817] = 1; em[818] = 8; em[819] = 1; /* 817: pointer.struct.bignum_st */
    	em[820] = 822; em[821] = 0; 
    em[822] = 0; em[823] = 24; em[824] = 1; /* 822: struct.bignum_st */
    	em[825] = 827; em[826] = 0; 
    em[827] = 8884099; em[828] = 8; em[829] = 2; /* 827: pointer_to_array_of_pointers_to_stack */
    	em[830] = 49; em[831] = 0; 
    	em[832] = 52; em[833] = 12; 
    em[834] = 0; em[835] = 16; em[836] = 1; /* 834: struct.crypto_threadid_st */
    	em[837] = 839; em[838] = 0; 
    em[839] = 0; em[840] = 8; em[841] = 0; /* 839: pointer.void */
    em[842] = 1; em[843] = 8; em[844] = 1; /* 842: pointer.struct.bn_mont_ctx_st */
    	em[845] = 847; em[846] = 0; 
    em[847] = 0; em[848] = 96; em[849] = 3; /* 847: struct.bn_mont_ctx_st */
    	em[850] = 822; em[851] = 8; 
    	em[852] = 822; em[853] = 32; 
    	em[854] = 822; em[855] = 56; 
    em[856] = 8884097; em[857] = 8; em[858] = 0; /* 856: pointer.func */
    em[859] = 0; em[860] = 0; em[861] = 1; /* 859: X509_ALGOR */
    	em[862] = 864; em[863] = 0; 
    em[864] = 0; em[865] = 16; em[866] = 2; /* 864: struct.X509_algor_st */
    	em[867] = 871; em[868] = 0; 
    	em[869] = 890; em[870] = 8; 
    em[871] = 1; em[872] = 8; em[873] = 1; /* 871: pointer.struct.asn1_object_st */
    	em[874] = 876; em[875] = 0; 
    em[876] = 0; em[877] = 40; em[878] = 3; /* 876: struct.asn1_object_st */
    	em[879] = 136; em[880] = 0; 
    	em[881] = 136; em[882] = 8; 
    	em[883] = 885; em[884] = 24; 
    em[885] = 1; em[886] = 8; em[887] = 1; /* 885: pointer.unsigned char */
    	em[888] = 74; em[889] = 0; 
    em[890] = 1; em[891] = 8; em[892] = 1; /* 890: pointer.struct.asn1_type_st */
    	em[893] = 895; em[894] = 0; 
    em[895] = 0; em[896] = 16; em[897] = 1; /* 895: struct.asn1_type_st */
    	em[898] = 900; em[899] = 8; 
    em[900] = 0; em[901] = 8; em[902] = 20; /* 900: union.unknown */
    	em[903] = 104; em[904] = 0; 
    	em[905] = 943; em[906] = 0; 
    	em[907] = 871; em[908] = 0; 
    	em[909] = 953; em[910] = 0; 
    	em[911] = 958; em[912] = 0; 
    	em[913] = 963; em[914] = 0; 
    	em[915] = 968; em[916] = 0; 
    	em[917] = 973; em[918] = 0; 
    	em[919] = 978; em[920] = 0; 
    	em[921] = 983; em[922] = 0; 
    	em[923] = 988; em[924] = 0; 
    	em[925] = 993; em[926] = 0; 
    	em[927] = 998; em[928] = 0; 
    	em[929] = 1003; em[930] = 0; 
    	em[931] = 1008; em[932] = 0; 
    	em[933] = 1013; em[934] = 0; 
    	em[935] = 1018; em[936] = 0; 
    	em[937] = 943; em[938] = 0; 
    	em[939] = 943; em[940] = 0; 
    	em[941] = 1023; em[942] = 0; 
    em[943] = 1; em[944] = 8; em[945] = 1; /* 943: pointer.struct.asn1_string_st */
    	em[946] = 948; em[947] = 0; 
    em[948] = 0; em[949] = 24; em[950] = 1; /* 948: struct.asn1_string_st */
    	em[951] = 69; em[952] = 8; 
    em[953] = 1; em[954] = 8; em[955] = 1; /* 953: pointer.struct.asn1_string_st */
    	em[956] = 948; em[957] = 0; 
    em[958] = 1; em[959] = 8; em[960] = 1; /* 958: pointer.struct.asn1_string_st */
    	em[961] = 948; em[962] = 0; 
    em[963] = 1; em[964] = 8; em[965] = 1; /* 963: pointer.struct.asn1_string_st */
    	em[966] = 948; em[967] = 0; 
    em[968] = 1; em[969] = 8; em[970] = 1; /* 968: pointer.struct.asn1_string_st */
    	em[971] = 948; em[972] = 0; 
    em[973] = 1; em[974] = 8; em[975] = 1; /* 973: pointer.struct.asn1_string_st */
    	em[976] = 948; em[977] = 0; 
    em[978] = 1; em[979] = 8; em[980] = 1; /* 978: pointer.struct.asn1_string_st */
    	em[981] = 948; em[982] = 0; 
    em[983] = 1; em[984] = 8; em[985] = 1; /* 983: pointer.struct.asn1_string_st */
    	em[986] = 948; em[987] = 0; 
    em[988] = 1; em[989] = 8; em[990] = 1; /* 988: pointer.struct.asn1_string_st */
    	em[991] = 948; em[992] = 0; 
    em[993] = 1; em[994] = 8; em[995] = 1; /* 993: pointer.struct.asn1_string_st */
    	em[996] = 948; em[997] = 0; 
    em[998] = 1; em[999] = 8; em[1000] = 1; /* 998: pointer.struct.asn1_string_st */
    	em[1001] = 948; em[1002] = 0; 
    em[1003] = 1; em[1004] = 8; em[1005] = 1; /* 1003: pointer.struct.asn1_string_st */
    	em[1006] = 948; em[1007] = 0; 
    em[1008] = 1; em[1009] = 8; em[1010] = 1; /* 1008: pointer.struct.asn1_string_st */
    	em[1011] = 948; em[1012] = 0; 
    em[1013] = 1; em[1014] = 8; em[1015] = 1; /* 1013: pointer.struct.asn1_string_st */
    	em[1016] = 948; em[1017] = 0; 
    em[1018] = 1; em[1019] = 8; em[1020] = 1; /* 1018: pointer.struct.asn1_string_st */
    	em[1021] = 948; em[1022] = 0; 
    em[1023] = 1; em[1024] = 8; em[1025] = 1; /* 1023: pointer.struct.ASN1_VALUE_st */
    	em[1026] = 1028; em[1027] = 0; 
    em[1028] = 0; em[1029] = 0; em[1030] = 0; /* 1028: struct.ASN1_VALUE_st */
    em[1031] = 1; em[1032] = 8; em[1033] = 1; /* 1031: pointer.struct.asn1_string_st */
    	em[1034] = 1036; em[1035] = 0; 
    em[1036] = 0; em[1037] = 24; em[1038] = 1; /* 1036: struct.asn1_string_st */
    	em[1039] = 69; em[1040] = 8; 
    em[1041] = 0; em[1042] = 40; em[1043] = 5; /* 1041: struct.x509_cert_aux_st */
    	em[1044] = 1054; em[1045] = 0; 
    	em[1046] = 1054; em[1047] = 8; 
    	em[1048] = 1031; em[1049] = 16; 
    	em[1050] = 1092; em[1051] = 24; 
    	em[1052] = 1097; em[1053] = 32; 
    em[1054] = 1; em[1055] = 8; em[1056] = 1; /* 1054: pointer.struct.stack_st_ASN1_OBJECT */
    	em[1057] = 1059; em[1058] = 0; 
    em[1059] = 0; em[1060] = 32; em[1061] = 2; /* 1059: struct.stack_st_fake_ASN1_OBJECT */
    	em[1062] = 1066; em[1063] = 8; 
    	em[1064] = 109; em[1065] = 24; 
    em[1066] = 8884099; em[1067] = 8; em[1068] = 2; /* 1066: pointer_to_array_of_pointers_to_stack */
    	em[1069] = 1073; em[1070] = 0; 
    	em[1071] = 52; em[1072] = 20; 
    em[1073] = 0; em[1074] = 8; em[1075] = 1; /* 1073: pointer.ASN1_OBJECT */
    	em[1076] = 1078; em[1077] = 0; 
    em[1078] = 0; em[1079] = 0; em[1080] = 1; /* 1078: ASN1_OBJECT */
    	em[1081] = 1083; em[1082] = 0; 
    em[1083] = 0; em[1084] = 40; em[1085] = 3; /* 1083: struct.asn1_object_st */
    	em[1086] = 136; em[1087] = 0; 
    	em[1088] = 136; em[1089] = 8; 
    	em[1090] = 885; em[1091] = 24; 
    em[1092] = 1; em[1093] = 8; em[1094] = 1; /* 1092: pointer.struct.asn1_string_st */
    	em[1095] = 1036; em[1096] = 0; 
    em[1097] = 1; em[1098] = 8; em[1099] = 1; /* 1097: pointer.struct.stack_st_X509_ALGOR */
    	em[1100] = 1102; em[1101] = 0; 
    em[1102] = 0; em[1103] = 32; em[1104] = 2; /* 1102: struct.stack_st_fake_X509_ALGOR */
    	em[1105] = 1109; em[1106] = 8; 
    	em[1107] = 109; em[1108] = 24; 
    em[1109] = 8884099; em[1110] = 8; em[1111] = 2; /* 1109: pointer_to_array_of_pointers_to_stack */
    	em[1112] = 1116; em[1113] = 0; 
    	em[1114] = 52; em[1115] = 20; 
    em[1116] = 0; em[1117] = 8; em[1118] = 1; /* 1116: pointer.X509_ALGOR */
    	em[1119] = 859; em[1120] = 0; 
    em[1121] = 1; em[1122] = 8; em[1123] = 1; /* 1121: pointer.struct.x509_cert_aux_st */
    	em[1124] = 1041; em[1125] = 0; 
    em[1126] = 1; em[1127] = 8; em[1128] = 1; /* 1126: pointer.struct.EDIPartyName_st */
    	em[1129] = 1131; em[1130] = 0; 
    em[1131] = 0; em[1132] = 16; em[1133] = 2; /* 1131: struct.EDIPartyName_st */
    	em[1134] = 1138; em[1135] = 0; 
    	em[1136] = 1138; em[1137] = 8; 
    em[1138] = 1; em[1139] = 8; em[1140] = 1; /* 1138: pointer.struct.asn1_string_st */
    	em[1141] = 1143; em[1142] = 0; 
    em[1143] = 0; em[1144] = 24; em[1145] = 1; /* 1143: struct.asn1_string_st */
    	em[1146] = 69; em[1147] = 8; 
    em[1148] = 1; em[1149] = 8; em[1150] = 1; /* 1148: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[1151] = 1153; em[1152] = 0; 
    em[1153] = 0; em[1154] = 32; em[1155] = 2; /* 1153: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[1156] = 1160; em[1157] = 8; 
    	em[1158] = 109; em[1159] = 24; 
    em[1160] = 8884099; em[1161] = 8; em[1162] = 2; /* 1160: pointer_to_array_of_pointers_to_stack */
    	em[1163] = 1167; em[1164] = 0; 
    	em[1165] = 52; em[1166] = 20; 
    em[1167] = 0; em[1168] = 8; em[1169] = 1; /* 1167: pointer.X509_NAME_ENTRY */
    	em[1170] = 1172; em[1171] = 0; 
    em[1172] = 0; em[1173] = 0; em[1174] = 1; /* 1172: X509_NAME_ENTRY */
    	em[1175] = 1177; em[1176] = 0; 
    em[1177] = 0; em[1178] = 24; em[1179] = 2; /* 1177: struct.X509_name_entry_st */
    	em[1180] = 1184; em[1181] = 0; 
    	em[1182] = 1198; em[1183] = 8; 
    em[1184] = 1; em[1185] = 8; em[1186] = 1; /* 1184: pointer.struct.asn1_object_st */
    	em[1187] = 1189; em[1188] = 0; 
    em[1189] = 0; em[1190] = 40; em[1191] = 3; /* 1189: struct.asn1_object_st */
    	em[1192] = 136; em[1193] = 0; 
    	em[1194] = 136; em[1195] = 8; 
    	em[1196] = 885; em[1197] = 24; 
    em[1198] = 1; em[1199] = 8; em[1200] = 1; /* 1198: pointer.struct.asn1_string_st */
    	em[1201] = 1203; em[1202] = 0; 
    em[1203] = 0; em[1204] = 24; em[1205] = 1; /* 1203: struct.asn1_string_st */
    	em[1206] = 69; em[1207] = 8; 
    em[1208] = 0; em[1209] = 40; em[1210] = 3; /* 1208: struct.X509_name_st */
    	em[1211] = 1148; em[1212] = 0; 
    	em[1213] = 1217; em[1214] = 16; 
    	em[1215] = 69; em[1216] = 24; 
    em[1217] = 1; em[1218] = 8; em[1219] = 1; /* 1217: pointer.struct.buf_mem_st */
    	em[1220] = 1222; em[1221] = 0; 
    em[1222] = 0; em[1223] = 24; em[1224] = 1; /* 1222: struct.buf_mem_st */
    	em[1225] = 104; em[1226] = 8; 
    em[1227] = 1; em[1228] = 8; em[1229] = 1; /* 1227: pointer.struct.X509_name_st */
    	em[1230] = 1208; em[1231] = 0; 
    em[1232] = 1; em[1233] = 8; em[1234] = 1; /* 1232: pointer.struct.asn1_string_st */
    	em[1235] = 1143; em[1236] = 0; 
    em[1237] = 1; em[1238] = 8; em[1239] = 1; /* 1237: pointer.struct.asn1_string_st */
    	em[1240] = 1143; em[1241] = 0; 
    em[1242] = 1; em[1243] = 8; em[1244] = 1; /* 1242: pointer.struct.asn1_string_st */
    	em[1245] = 1143; em[1246] = 0; 
    em[1247] = 1; em[1248] = 8; em[1249] = 1; /* 1247: pointer.struct.asn1_string_st */
    	em[1250] = 1143; em[1251] = 0; 
    em[1252] = 1; em[1253] = 8; em[1254] = 1; /* 1252: pointer.struct.asn1_string_st */
    	em[1255] = 1143; em[1256] = 0; 
    em[1257] = 1; em[1258] = 8; em[1259] = 1; /* 1257: pointer.struct.asn1_string_st */
    	em[1260] = 1143; em[1261] = 0; 
    em[1262] = 1; em[1263] = 8; em[1264] = 1; /* 1262: pointer.struct.asn1_string_st */
    	em[1265] = 1143; em[1266] = 0; 
    em[1267] = 1; em[1268] = 8; em[1269] = 1; /* 1267: pointer.struct.asn1_string_st */
    	em[1270] = 1143; em[1271] = 0; 
    em[1272] = 0; em[1273] = 8; em[1274] = 20; /* 1272: union.unknown */
    	em[1275] = 104; em[1276] = 0; 
    	em[1277] = 1138; em[1278] = 0; 
    	em[1279] = 1315; em[1280] = 0; 
    	em[1281] = 1329; em[1282] = 0; 
    	em[1283] = 1334; em[1284] = 0; 
    	em[1285] = 1339; em[1286] = 0; 
    	em[1287] = 1267; em[1288] = 0; 
    	em[1289] = 1262; em[1290] = 0; 
    	em[1291] = 1257; em[1292] = 0; 
    	em[1293] = 1344; em[1294] = 0; 
    	em[1295] = 1252; em[1296] = 0; 
    	em[1297] = 1247; em[1298] = 0; 
    	em[1299] = 1349; em[1300] = 0; 
    	em[1301] = 1242; em[1302] = 0; 
    	em[1303] = 1237; em[1304] = 0; 
    	em[1305] = 1354; em[1306] = 0; 
    	em[1307] = 1232; em[1308] = 0; 
    	em[1309] = 1138; em[1310] = 0; 
    	em[1311] = 1138; em[1312] = 0; 
    	em[1313] = 1359; em[1314] = 0; 
    em[1315] = 1; em[1316] = 8; em[1317] = 1; /* 1315: pointer.struct.asn1_object_st */
    	em[1318] = 1320; em[1319] = 0; 
    em[1320] = 0; em[1321] = 40; em[1322] = 3; /* 1320: struct.asn1_object_st */
    	em[1323] = 136; em[1324] = 0; 
    	em[1325] = 136; em[1326] = 8; 
    	em[1327] = 885; em[1328] = 24; 
    em[1329] = 1; em[1330] = 8; em[1331] = 1; /* 1329: pointer.struct.asn1_string_st */
    	em[1332] = 1143; em[1333] = 0; 
    em[1334] = 1; em[1335] = 8; em[1336] = 1; /* 1334: pointer.struct.asn1_string_st */
    	em[1337] = 1143; em[1338] = 0; 
    em[1339] = 1; em[1340] = 8; em[1341] = 1; /* 1339: pointer.struct.asn1_string_st */
    	em[1342] = 1143; em[1343] = 0; 
    em[1344] = 1; em[1345] = 8; em[1346] = 1; /* 1344: pointer.struct.asn1_string_st */
    	em[1347] = 1143; em[1348] = 0; 
    em[1349] = 1; em[1350] = 8; em[1351] = 1; /* 1349: pointer.struct.asn1_string_st */
    	em[1352] = 1143; em[1353] = 0; 
    em[1354] = 1; em[1355] = 8; em[1356] = 1; /* 1354: pointer.struct.asn1_string_st */
    	em[1357] = 1143; em[1358] = 0; 
    em[1359] = 1; em[1360] = 8; em[1361] = 1; /* 1359: pointer.struct.ASN1_VALUE_st */
    	em[1362] = 1364; em[1363] = 0; 
    em[1364] = 0; em[1365] = 0; em[1366] = 0; /* 1364: struct.ASN1_VALUE_st */
    em[1367] = 1; em[1368] = 8; em[1369] = 1; /* 1367: pointer.struct.otherName_st */
    	em[1370] = 1372; em[1371] = 0; 
    em[1372] = 0; em[1373] = 16; em[1374] = 2; /* 1372: struct.otherName_st */
    	em[1375] = 1315; em[1376] = 0; 
    	em[1377] = 1379; em[1378] = 8; 
    em[1379] = 1; em[1380] = 8; em[1381] = 1; /* 1379: pointer.struct.asn1_type_st */
    	em[1382] = 1384; em[1383] = 0; 
    em[1384] = 0; em[1385] = 16; em[1386] = 1; /* 1384: struct.asn1_type_st */
    	em[1387] = 1272; em[1388] = 8; 
    em[1389] = 0; em[1390] = 16; em[1391] = 1; /* 1389: struct.GENERAL_NAME_st */
    	em[1392] = 1394; em[1393] = 8; 
    em[1394] = 0; em[1395] = 8; em[1396] = 15; /* 1394: union.unknown */
    	em[1397] = 104; em[1398] = 0; 
    	em[1399] = 1367; em[1400] = 0; 
    	em[1401] = 1344; em[1402] = 0; 
    	em[1403] = 1344; em[1404] = 0; 
    	em[1405] = 1379; em[1406] = 0; 
    	em[1407] = 1227; em[1408] = 0; 
    	em[1409] = 1126; em[1410] = 0; 
    	em[1411] = 1344; em[1412] = 0; 
    	em[1413] = 1267; em[1414] = 0; 
    	em[1415] = 1315; em[1416] = 0; 
    	em[1417] = 1267; em[1418] = 0; 
    	em[1419] = 1227; em[1420] = 0; 
    	em[1421] = 1344; em[1422] = 0; 
    	em[1423] = 1315; em[1424] = 0; 
    	em[1425] = 1379; em[1426] = 0; 
    em[1427] = 1; em[1428] = 8; em[1429] = 1; /* 1427: pointer.struct.GENERAL_NAME_st */
    	em[1430] = 1389; em[1431] = 0; 
    em[1432] = 0; em[1433] = 24; em[1434] = 3; /* 1432: struct.GENERAL_SUBTREE_st */
    	em[1435] = 1427; em[1436] = 0; 
    	em[1437] = 1329; em[1438] = 8; 
    	em[1439] = 1329; em[1440] = 16; 
    em[1441] = 0; em[1442] = 8; em[1443] = 5; /* 1441: union.unknown */
    	em[1444] = 104; em[1445] = 0; 
    	em[1446] = 640; em[1447] = 0; 
    	em[1448] = 501; em[1449] = 0; 
    	em[1450] = 0; em[1451] = 0; 
    	em[1452] = 1454; em[1453] = 0; 
    em[1454] = 1; em[1455] = 8; em[1456] = 1; /* 1454: pointer.struct.ec_key_st */
    	em[1457] = 1459; em[1458] = 0; 
    em[1459] = 0; em[1460] = 56; em[1461] = 4; /* 1459: struct.ec_key_st */
    	em[1462] = 1470; em[1463] = 8; 
    	em[1464] = 1918; em[1465] = 16; 
    	em[1466] = 1923; em[1467] = 24; 
    	em[1468] = 1940; em[1469] = 48; 
    em[1470] = 1; em[1471] = 8; em[1472] = 1; /* 1470: pointer.struct.ec_group_st */
    	em[1473] = 1475; em[1474] = 0; 
    em[1475] = 0; em[1476] = 232; em[1477] = 12; /* 1475: struct.ec_group_st */
    	em[1478] = 1502; em[1479] = 0; 
    	em[1480] = 1674; em[1481] = 8; 
    	em[1482] = 1874; em[1483] = 16; 
    	em[1484] = 1874; em[1485] = 40; 
    	em[1486] = 69; em[1487] = 80; 
    	em[1488] = 1886; em[1489] = 96; 
    	em[1490] = 1874; em[1491] = 104; 
    	em[1492] = 1874; em[1493] = 152; 
    	em[1494] = 1874; em[1495] = 176; 
    	em[1496] = 839; em[1497] = 208; 
    	em[1498] = 839; em[1499] = 216; 
    	em[1500] = 1915; em[1501] = 224; 
    em[1502] = 1; em[1503] = 8; em[1504] = 1; /* 1502: pointer.struct.ec_method_st */
    	em[1505] = 1507; em[1506] = 0; 
    em[1507] = 0; em[1508] = 304; em[1509] = 37; /* 1507: struct.ec_method_st */
    	em[1510] = 1584; em[1511] = 8; 
    	em[1512] = 1587; em[1513] = 16; 
    	em[1514] = 1587; em[1515] = 24; 
    	em[1516] = 1590; em[1517] = 32; 
    	em[1518] = 1593; em[1519] = 40; 
    	em[1520] = 1596; em[1521] = 48; 
    	em[1522] = 1599; em[1523] = 56; 
    	em[1524] = 1602; em[1525] = 64; 
    	em[1526] = 1605; em[1527] = 72; 
    	em[1528] = 1608; em[1529] = 80; 
    	em[1530] = 1608; em[1531] = 88; 
    	em[1532] = 1611; em[1533] = 96; 
    	em[1534] = 1614; em[1535] = 104; 
    	em[1536] = 1617; em[1537] = 112; 
    	em[1538] = 1620; em[1539] = 120; 
    	em[1540] = 1623; em[1541] = 128; 
    	em[1542] = 1626; em[1543] = 136; 
    	em[1544] = 1629; em[1545] = 144; 
    	em[1546] = 1632; em[1547] = 152; 
    	em[1548] = 1635; em[1549] = 160; 
    	em[1550] = 1638; em[1551] = 168; 
    	em[1552] = 1641; em[1553] = 176; 
    	em[1554] = 1644; em[1555] = 184; 
    	em[1556] = 1647; em[1557] = 192; 
    	em[1558] = 1650; em[1559] = 200; 
    	em[1560] = 1653; em[1561] = 208; 
    	em[1562] = 1644; em[1563] = 216; 
    	em[1564] = 1656; em[1565] = 224; 
    	em[1566] = 1659; em[1567] = 232; 
    	em[1568] = 1662; em[1569] = 240; 
    	em[1570] = 1599; em[1571] = 248; 
    	em[1572] = 1665; em[1573] = 256; 
    	em[1574] = 1668; em[1575] = 264; 
    	em[1576] = 1665; em[1577] = 272; 
    	em[1578] = 1668; em[1579] = 280; 
    	em[1580] = 1668; em[1581] = 288; 
    	em[1582] = 1671; em[1583] = 296; 
    em[1584] = 8884097; em[1585] = 8; em[1586] = 0; /* 1584: pointer.func */
    em[1587] = 8884097; em[1588] = 8; em[1589] = 0; /* 1587: pointer.func */
    em[1590] = 8884097; em[1591] = 8; em[1592] = 0; /* 1590: pointer.func */
    em[1593] = 8884097; em[1594] = 8; em[1595] = 0; /* 1593: pointer.func */
    em[1596] = 8884097; em[1597] = 8; em[1598] = 0; /* 1596: pointer.func */
    em[1599] = 8884097; em[1600] = 8; em[1601] = 0; /* 1599: pointer.func */
    em[1602] = 8884097; em[1603] = 8; em[1604] = 0; /* 1602: pointer.func */
    em[1605] = 8884097; em[1606] = 8; em[1607] = 0; /* 1605: pointer.func */
    em[1608] = 8884097; em[1609] = 8; em[1610] = 0; /* 1608: pointer.func */
    em[1611] = 8884097; em[1612] = 8; em[1613] = 0; /* 1611: pointer.func */
    em[1614] = 8884097; em[1615] = 8; em[1616] = 0; /* 1614: pointer.func */
    em[1617] = 8884097; em[1618] = 8; em[1619] = 0; /* 1617: pointer.func */
    em[1620] = 8884097; em[1621] = 8; em[1622] = 0; /* 1620: pointer.func */
    em[1623] = 8884097; em[1624] = 8; em[1625] = 0; /* 1623: pointer.func */
    em[1626] = 8884097; em[1627] = 8; em[1628] = 0; /* 1626: pointer.func */
    em[1629] = 8884097; em[1630] = 8; em[1631] = 0; /* 1629: pointer.func */
    em[1632] = 8884097; em[1633] = 8; em[1634] = 0; /* 1632: pointer.func */
    em[1635] = 8884097; em[1636] = 8; em[1637] = 0; /* 1635: pointer.func */
    em[1638] = 8884097; em[1639] = 8; em[1640] = 0; /* 1638: pointer.func */
    em[1641] = 8884097; em[1642] = 8; em[1643] = 0; /* 1641: pointer.func */
    em[1644] = 8884097; em[1645] = 8; em[1646] = 0; /* 1644: pointer.func */
    em[1647] = 8884097; em[1648] = 8; em[1649] = 0; /* 1647: pointer.func */
    em[1650] = 8884097; em[1651] = 8; em[1652] = 0; /* 1650: pointer.func */
    em[1653] = 8884097; em[1654] = 8; em[1655] = 0; /* 1653: pointer.func */
    em[1656] = 8884097; em[1657] = 8; em[1658] = 0; /* 1656: pointer.func */
    em[1659] = 8884097; em[1660] = 8; em[1661] = 0; /* 1659: pointer.func */
    em[1662] = 8884097; em[1663] = 8; em[1664] = 0; /* 1662: pointer.func */
    em[1665] = 8884097; em[1666] = 8; em[1667] = 0; /* 1665: pointer.func */
    em[1668] = 8884097; em[1669] = 8; em[1670] = 0; /* 1668: pointer.func */
    em[1671] = 8884097; em[1672] = 8; em[1673] = 0; /* 1671: pointer.func */
    em[1674] = 1; em[1675] = 8; em[1676] = 1; /* 1674: pointer.struct.ec_point_st */
    	em[1677] = 1679; em[1678] = 0; 
    em[1679] = 0; em[1680] = 88; em[1681] = 4; /* 1679: struct.ec_point_st */
    	em[1682] = 1690; em[1683] = 0; 
    	em[1684] = 1862; em[1685] = 8; 
    	em[1686] = 1862; em[1687] = 32; 
    	em[1688] = 1862; em[1689] = 56; 
    em[1690] = 1; em[1691] = 8; em[1692] = 1; /* 1690: pointer.struct.ec_method_st */
    	em[1693] = 1695; em[1694] = 0; 
    em[1695] = 0; em[1696] = 304; em[1697] = 37; /* 1695: struct.ec_method_st */
    	em[1698] = 1772; em[1699] = 8; 
    	em[1700] = 1775; em[1701] = 16; 
    	em[1702] = 1775; em[1703] = 24; 
    	em[1704] = 1778; em[1705] = 32; 
    	em[1706] = 1781; em[1707] = 40; 
    	em[1708] = 1784; em[1709] = 48; 
    	em[1710] = 1787; em[1711] = 56; 
    	em[1712] = 1790; em[1713] = 64; 
    	em[1714] = 1793; em[1715] = 72; 
    	em[1716] = 1796; em[1717] = 80; 
    	em[1718] = 1796; em[1719] = 88; 
    	em[1720] = 1799; em[1721] = 96; 
    	em[1722] = 1802; em[1723] = 104; 
    	em[1724] = 1805; em[1725] = 112; 
    	em[1726] = 1808; em[1727] = 120; 
    	em[1728] = 1811; em[1729] = 128; 
    	em[1730] = 1814; em[1731] = 136; 
    	em[1732] = 1817; em[1733] = 144; 
    	em[1734] = 1820; em[1735] = 152; 
    	em[1736] = 1823; em[1737] = 160; 
    	em[1738] = 1826; em[1739] = 168; 
    	em[1740] = 1829; em[1741] = 176; 
    	em[1742] = 1832; em[1743] = 184; 
    	em[1744] = 1835; em[1745] = 192; 
    	em[1746] = 1838; em[1747] = 200; 
    	em[1748] = 1841; em[1749] = 208; 
    	em[1750] = 1832; em[1751] = 216; 
    	em[1752] = 1844; em[1753] = 224; 
    	em[1754] = 1847; em[1755] = 232; 
    	em[1756] = 1850; em[1757] = 240; 
    	em[1758] = 1787; em[1759] = 248; 
    	em[1760] = 1853; em[1761] = 256; 
    	em[1762] = 1856; em[1763] = 264; 
    	em[1764] = 1853; em[1765] = 272; 
    	em[1766] = 1856; em[1767] = 280; 
    	em[1768] = 1856; em[1769] = 288; 
    	em[1770] = 1859; em[1771] = 296; 
    em[1772] = 8884097; em[1773] = 8; em[1774] = 0; /* 1772: pointer.func */
    em[1775] = 8884097; em[1776] = 8; em[1777] = 0; /* 1775: pointer.func */
    em[1778] = 8884097; em[1779] = 8; em[1780] = 0; /* 1778: pointer.func */
    em[1781] = 8884097; em[1782] = 8; em[1783] = 0; /* 1781: pointer.func */
    em[1784] = 8884097; em[1785] = 8; em[1786] = 0; /* 1784: pointer.func */
    em[1787] = 8884097; em[1788] = 8; em[1789] = 0; /* 1787: pointer.func */
    em[1790] = 8884097; em[1791] = 8; em[1792] = 0; /* 1790: pointer.func */
    em[1793] = 8884097; em[1794] = 8; em[1795] = 0; /* 1793: pointer.func */
    em[1796] = 8884097; em[1797] = 8; em[1798] = 0; /* 1796: pointer.func */
    em[1799] = 8884097; em[1800] = 8; em[1801] = 0; /* 1799: pointer.func */
    em[1802] = 8884097; em[1803] = 8; em[1804] = 0; /* 1802: pointer.func */
    em[1805] = 8884097; em[1806] = 8; em[1807] = 0; /* 1805: pointer.func */
    em[1808] = 8884097; em[1809] = 8; em[1810] = 0; /* 1808: pointer.func */
    em[1811] = 8884097; em[1812] = 8; em[1813] = 0; /* 1811: pointer.func */
    em[1814] = 8884097; em[1815] = 8; em[1816] = 0; /* 1814: pointer.func */
    em[1817] = 8884097; em[1818] = 8; em[1819] = 0; /* 1817: pointer.func */
    em[1820] = 8884097; em[1821] = 8; em[1822] = 0; /* 1820: pointer.func */
    em[1823] = 8884097; em[1824] = 8; em[1825] = 0; /* 1823: pointer.func */
    em[1826] = 8884097; em[1827] = 8; em[1828] = 0; /* 1826: pointer.func */
    em[1829] = 8884097; em[1830] = 8; em[1831] = 0; /* 1829: pointer.func */
    em[1832] = 8884097; em[1833] = 8; em[1834] = 0; /* 1832: pointer.func */
    em[1835] = 8884097; em[1836] = 8; em[1837] = 0; /* 1835: pointer.func */
    em[1838] = 8884097; em[1839] = 8; em[1840] = 0; /* 1838: pointer.func */
    em[1841] = 8884097; em[1842] = 8; em[1843] = 0; /* 1841: pointer.func */
    em[1844] = 8884097; em[1845] = 8; em[1846] = 0; /* 1844: pointer.func */
    em[1847] = 8884097; em[1848] = 8; em[1849] = 0; /* 1847: pointer.func */
    em[1850] = 8884097; em[1851] = 8; em[1852] = 0; /* 1850: pointer.func */
    em[1853] = 8884097; em[1854] = 8; em[1855] = 0; /* 1853: pointer.func */
    em[1856] = 8884097; em[1857] = 8; em[1858] = 0; /* 1856: pointer.func */
    em[1859] = 8884097; em[1860] = 8; em[1861] = 0; /* 1859: pointer.func */
    em[1862] = 0; em[1863] = 24; em[1864] = 1; /* 1862: struct.bignum_st */
    	em[1865] = 1867; em[1866] = 0; 
    em[1867] = 8884099; em[1868] = 8; em[1869] = 2; /* 1867: pointer_to_array_of_pointers_to_stack */
    	em[1870] = 49; em[1871] = 0; 
    	em[1872] = 52; em[1873] = 12; 
    em[1874] = 0; em[1875] = 24; em[1876] = 1; /* 1874: struct.bignum_st */
    	em[1877] = 1879; em[1878] = 0; 
    em[1879] = 8884099; em[1880] = 8; em[1881] = 2; /* 1879: pointer_to_array_of_pointers_to_stack */
    	em[1882] = 49; em[1883] = 0; 
    	em[1884] = 52; em[1885] = 12; 
    em[1886] = 1; em[1887] = 8; em[1888] = 1; /* 1886: pointer.struct.ec_extra_data_st */
    	em[1889] = 1891; em[1890] = 0; 
    em[1891] = 0; em[1892] = 40; em[1893] = 5; /* 1891: struct.ec_extra_data_st */
    	em[1894] = 1904; em[1895] = 0; 
    	em[1896] = 839; em[1897] = 8; 
    	em[1898] = 1909; em[1899] = 16; 
    	em[1900] = 1912; em[1901] = 24; 
    	em[1902] = 1912; em[1903] = 32; 
    em[1904] = 1; em[1905] = 8; em[1906] = 1; /* 1904: pointer.struct.ec_extra_data_st */
    	em[1907] = 1891; em[1908] = 0; 
    em[1909] = 8884097; em[1910] = 8; em[1911] = 0; /* 1909: pointer.func */
    em[1912] = 8884097; em[1913] = 8; em[1914] = 0; /* 1912: pointer.func */
    em[1915] = 8884097; em[1916] = 8; em[1917] = 0; /* 1915: pointer.func */
    em[1918] = 1; em[1919] = 8; em[1920] = 1; /* 1918: pointer.struct.ec_point_st */
    	em[1921] = 1679; em[1922] = 0; 
    em[1923] = 1; em[1924] = 8; em[1925] = 1; /* 1923: pointer.struct.bignum_st */
    	em[1926] = 1928; em[1927] = 0; 
    em[1928] = 0; em[1929] = 24; em[1930] = 1; /* 1928: struct.bignum_st */
    	em[1931] = 1933; em[1932] = 0; 
    em[1933] = 8884099; em[1934] = 8; em[1935] = 2; /* 1933: pointer_to_array_of_pointers_to_stack */
    	em[1936] = 49; em[1937] = 0; 
    	em[1938] = 52; em[1939] = 12; 
    em[1940] = 1; em[1941] = 8; em[1942] = 1; /* 1940: pointer.struct.ec_extra_data_st */
    	em[1943] = 1945; em[1944] = 0; 
    em[1945] = 0; em[1946] = 40; em[1947] = 5; /* 1945: struct.ec_extra_data_st */
    	em[1948] = 1958; em[1949] = 0; 
    	em[1950] = 839; em[1951] = 8; 
    	em[1952] = 1909; em[1953] = 16; 
    	em[1954] = 1912; em[1955] = 24; 
    	em[1956] = 1912; em[1957] = 32; 
    em[1958] = 1; em[1959] = 8; em[1960] = 1; /* 1958: pointer.struct.ec_extra_data_st */
    	em[1961] = 1945; em[1962] = 0; 
    em[1963] = 1; em[1964] = 8; em[1965] = 1; /* 1963: pointer.struct.stack_st_GENERAL_NAME */
    	em[1966] = 1968; em[1967] = 0; 
    em[1968] = 0; em[1969] = 32; em[1970] = 2; /* 1968: struct.stack_st_fake_GENERAL_NAME */
    	em[1971] = 1975; em[1972] = 8; 
    	em[1973] = 109; em[1974] = 24; 
    em[1975] = 8884099; em[1976] = 8; em[1977] = 2; /* 1975: pointer_to_array_of_pointers_to_stack */
    	em[1978] = 1982; em[1979] = 0; 
    	em[1980] = 52; em[1981] = 20; 
    em[1982] = 0; em[1983] = 8; em[1984] = 1; /* 1982: pointer.GENERAL_NAME */
    	em[1985] = 1987; em[1986] = 0; 
    em[1987] = 0; em[1988] = 0; em[1989] = 1; /* 1987: GENERAL_NAME */
    	em[1990] = 1992; em[1991] = 0; 
    em[1992] = 0; em[1993] = 16; em[1994] = 1; /* 1992: struct.GENERAL_NAME_st */
    	em[1995] = 1997; em[1996] = 8; 
    em[1997] = 0; em[1998] = 8; em[1999] = 15; /* 1997: union.unknown */
    	em[2000] = 104; em[2001] = 0; 
    	em[2002] = 2030; em[2003] = 0; 
    	em[2004] = 2149; em[2005] = 0; 
    	em[2006] = 2149; em[2007] = 0; 
    	em[2008] = 2056; em[2009] = 0; 
    	em[2010] = 2197; em[2011] = 0; 
    	em[2012] = 2245; em[2013] = 0; 
    	em[2014] = 2149; em[2015] = 0; 
    	em[2016] = 2134; em[2017] = 0; 
    	em[2018] = 2042; em[2019] = 0; 
    	em[2020] = 2134; em[2021] = 0; 
    	em[2022] = 2197; em[2023] = 0; 
    	em[2024] = 2149; em[2025] = 0; 
    	em[2026] = 2042; em[2027] = 0; 
    	em[2028] = 2056; em[2029] = 0; 
    em[2030] = 1; em[2031] = 8; em[2032] = 1; /* 2030: pointer.struct.otherName_st */
    	em[2033] = 2035; em[2034] = 0; 
    em[2035] = 0; em[2036] = 16; em[2037] = 2; /* 2035: struct.otherName_st */
    	em[2038] = 2042; em[2039] = 0; 
    	em[2040] = 2056; em[2041] = 8; 
    em[2042] = 1; em[2043] = 8; em[2044] = 1; /* 2042: pointer.struct.asn1_object_st */
    	em[2045] = 2047; em[2046] = 0; 
    em[2047] = 0; em[2048] = 40; em[2049] = 3; /* 2047: struct.asn1_object_st */
    	em[2050] = 136; em[2051] = 0; 
    	em[2052] = 136; em[2053] = 8; 
    	em[2054] = 885; em[2055] = 24; 
    em[2056] = 1; em[2057] = 8; em[2058] = 1; /* 2056: pointer.struct.asn1_type_st */
    	em[2059] = 2061; em[2060] = 0; 
    em[2061] = 0; em[2062] = 16; em[2063] = 1; /* 2061: struct.asn1_type_st */
    	em[2064] = 2066; em[2065] = 8; 
    em[2066] = 0; em[2067] = 8; em[2068] = 20; /* 2066: union.unknown */
    	em[2069] = 104; em[2070] = 0; 
    	em[2071] = 2109; em[2072] = 0; 
    	em[2073] = 2042; em[2074] = 0; 
    	em[2075] = 2119; em[2076] = 0; 
    	em[2077] = 2124; em[2078] = 0; 
    	em[2079] = 2129; em[2080] = 0; 
    	em[2081] = 2134; em[2082] = 0; 
    	em[2083] = 2139; em[2084] = 0; 
    	em[2085] = 2144; em[2086] = 0; 
    	em[2087] = 2149; em[2088] = 0; 
    	em[2089] = 2154; em[2090] = 0; 
    	em[2091] = 2159; em[2092] = 0; 
    	em[2093] = 2164; em[2094] = 0; 
    	em[2095] = 2169; em[2096] = 0; 
    	em[2097] = 2174; em[2098] = 0; 
    	em[2099] = 2179; em[2100] = 0; 
    	em[2101] = 2184; em[2102] = 0; 
    	em[2103] = 2109; em[2104] = 0; 
    	em[2105] = 2109; em[2106] = 0; 
    	em[2107] = 2189; em[2108] = 0; 
    em[2109] = 1; em[2110] = 8; em[2111] = 1; /* 2109: pointer.struct.asn1_string_st */
    	em[2112] = 2114; em[2113] = 0; 
    em[2114] = 0; em[2115] = 24; em[2116] = 1; /* 2114: struct.asn1_string_st */
    	em[2117] = 69; em[2118] = 8; 
    em[2119] = 1; em[2120] = 8; em[2121] = 1; /* 2119: pointer.struct.asn1_string_st */
    	em[2122] = 2114; em[2123] = 0; 
    em[2124] = 1; em[2125] = 8; em[2126] = 1; /* 2124: pointer.struct.asn1_string_st */
    	em[2127] = 2114; em[2128] = 0; 
    em[2129] = 1; em[2130] = 8; em[2131] = 1; /* 2129: pointer.struct.asn1_string_st */
    	em[2132] = 2114; em[2133] = 0; 
    em[2134] = 1; em[2135] = 8; em[2136] = 1; /* 2134: pointer.struct.asn1_string_st */
    	em[2137] = 2114; em[2138] = 0; 
    em[2139] = 1; em[2140] = 8; em[2141] = 1; /* 2139: pointer.struct.asn1_string_st */
    	em[2142] = 2114; em[2143] = 0; 
    em[2144] = 1; em[2145] = 8; em[2146] = 1; /* 2144: pointer.struct.asn1_string_st */
    	em[2147] = 2114; em[2148] = 0; 
    em[2149] = 1; em[2150] = 8; em[2151] = 1; /* 2149: pointer.struct.asn1_string_st */
    	em[2152] = 2114; em[2153] = 0; 
    em[2154] = 1; em[2155] = 8; em[2156] = 1; /* 2154: pointer.struct.asn1_string_st */
    	em[2157] = 2114; em[2158] = 0; 
    em[2159] = 1; em[2160] = 8; em[2161] = 1; /* 2159: pointer.struct.asn1_string_st */
    	em[2162] = 2114; em[2163] = 0; 
    em[2164] = 1; em[2165] = 8; em[2166] = 1; /* 2164: pointer.struct.asn1_string_st */
    	em[2167] = 2114; em[2168] = 0; 
    em[2169] = 1; em[2170] = 8; em[2171] = 1; /* 2169: pointer.struct.asn1_string_st */
    	em[2172] = 2114; em[2173] = 0; 
    em[2174] = 1; em[2175] = 8; em[2176] = 1; /* 2174: pointer.struct.asn1_string_st */
    	em[2177] = 2114; em[2178] = 0; 
    em[2179] = 1; em[2180] = 8; em[2181] = 1; /* 2179: pointer.struct.asn1_string_st */
    	em[2182] = 2114; em[2183] = 0; 
    em[2184] = 1; em[2185] = 8; em[2186] = 1; /* 2184: pointer.struct.asn1_string_st */
    	em[2187] = 2114; em[2188] = 0; 
    em[2189] = 1; em[2190] = 8; em[2191] = 1; /* 2189: pointer.struct.ASN1_VALUE_st */
    	em[2192] = 2194; em[2193] = 0; 
    em[2194] = 0; em[2195] = 0; em[2196] = 0; /* 2194: struct.ASN1_VALUE_st */
    em[2197] = 1; em[2198] = 8; em[2199] = 1; /* 2197: pointer.struct.X509_name_st */
    	em[2200] = 2202; em[2201] = 0; 
    em[2202] = 0; em[2203] = 40; em[2204] = 3; /* 2202: struct.X509_name_st */
    	em[2205] = 2211; em[2206] = 0; 
    	em[2207] = 2235; em[2208] = 16; 
    	em[2209] = 69; em[2210] = 24; 
    em[2211] = 1; em[2212] = 8; em[2213] = 1; /* 2211: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[2214] = 2216; em[2215] = 0; 
    em[2216] = 0; em[2217] = 32; em[2218] = 2; /* 2216: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[2219] = 2223; em[2220] = 8; 
    	em[2221] = 109; em[2222] = 24; 
    em[2223] = 8884099; em[2224] = 8; em[2225] = 2; /* 2223: pointer_to_array_of_pointers_to_stack */
    	em[2226] = 2230; em[2227] = 0; 
    	em[2228] = 52; em[2229] = 20; 
    em[2230] = 0; em[2231] = 8; em[2232] = 1; /* 2230: pointer.X509_NAME_ENTRY */
    	em[2233] = 1172; em[2234] = 0; 
    em[2235] = 1; em[2236] = 8; em[2237] = 1; /* 2235: pointer.struct.buf_mem_st */
    	em[2238] = 2240; em[2239] = 0; 
    em[2240] = 0; em[2241] = 24; em[2242] = 1; /* 2240: struct.buf_mem_st */
    	em[2243] = 104; em[2244] = 8; 
    em[2245] = 1; em[2246] = 8; em[2247] = 1; /* 2245: pointer.struct.EDIPartyName_st */
    	em[2248] = 2250; em[2249] = 0; 
    em[2250] = 0; em[2251] = 16; em[2252] = 2; /* 2250: struct.EDIPartyName_st */
    	em[2253] = 2109; em[2254] = 0; 
    	em[2255] = 2109; em[2256] = 8; 
    em[2257] = 0; em[2258] = 24; em[2259] = 1; /* 2257: struct.asn1_string_st */
    	em[2260] = 69; em[2261] = 8; 
    em[2262] = 1; em[2263] = 8; em[2264] = 1; /* 2262: pointer.struct.buf_mem_st */
    	em[2265] = 2267; em[2266] = 0; 
    em[2267] = 0; em[2268] = 24; em[2269] = 1; /* 2267: struct.buf_mem_st */
    	em[2270] = 104; em[2271] = 8; 
    em[2272] = 1; em[2273] = 8; em[2274] = 1; /* 2272: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[2275] = 2277; em[2276] = 0; 
    em[2277] = 0; em[2278] = 32; em[2279] = 2; /* 2277: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[2280] = 2284; em[2281] = 8; 
    	em[2282] = 109; em[2283] = 24; 
    em[2284] = 8884099; em[2285] = 8; em[2286] = 2; /* 2284: pointer_to_array_of_pointers_to_stack */
    	em[2287] = 2291; em[2288] = 0; 
    	em[2289] = 52; em[2290] = 20; 
    em[2291] = 0; em[2292] = 8; em[2293] = 1; /* 2291: pointer.X509_NAME_ENTRY */
    	em[2294] = 1172; em[2295] = 0; 
    em[2296] = 1; em[2297] = 8; em[2298] = 1; /* 2296: pointer.struct.stack_st_GENERAL_NAME */
    	em[2299] = 2301; em[2300] = 0; 
    em[2301] = 0; em[2302] = 32; em[2303] = 2; /* 2301: struct.stack_st_fake_GENERAL_NAME */
    	em[2304] = 2308; em[2305] = 8; 
    	em[2306] = 109; em[2307] = 24; 
    em[2308] = 8884099; em[2309] = 8; em[2310] = 2; /* 2308: pointer_to_array_of_pointers_to_stack */
    	em[2311] = 2315; em[2312] = 0; 
    	em[2313] = 52; em[2314] = 20; 
    em[2315] = 0; em[2316] = 8; em[2317] = 1; /* 2315: pointer.GENERAL_NAME */
    	em[2318] = 1987; em[2319] = 0; 
    em[2320] = 0; em[2321] = 8; em[2322] = 2; /* 2320: union.unknown */
    	em[2323] = 2296; em[2324] = 0; 
    	em[2325] = 2272; em[2326] = 0; 
    em[2327] = 0; em[2328] = 24; em[2329] = 2; /* 2327: struct.DIST_POINT_NAME_st */
    	em[2330] = 2320; em[2331] = 8; 
    	em[2332] = 2334; em[2333] = 16; 
    em[2334] = 1; em[2335] = 8; em[2336] = 1; /* 2334: pointer.struct.X509_name_st */
    	em[2337] = 2339; em[2338] = 0; 
    em[2339] = 0; em[2340] = 40; em[2341] = 3; /* 2339: struct.X509_name_st */
    	em[2342] = 2272; em[2343] = 0; 
    	em[2344] = 2262; em[2345] = 16; 
    	em[2346] = 69; em[2347] = 24; 
    em[2348] = 0; em[2349] = 0; em[2350] = 1; /* 2348: DIST_POINT */
    	em[2351] = 2353; em[2352] = 0; 
    em[2353] = 0; em[2354] = 32; em[2355] = 3; /* 2353: struct.DIST_POINT_st */
    	em[2356] = 2362; em[2357] = 0; 
    	em[2358] = 2367; em[2359] = 8; 
    	em[2360] = 2296; em[2361] = 16; 
    em[2362] = 1; em[2363] = 8; em[2364] = 1; /* 2362: pointer.struct.DIST_POINT_NAME_st */
    	em[2365] = 2327; em[2366] = 0; 
    em[2367] = 1; em[2368] = 8; em[2369] = 1; /* 2367: pointer.struct.asn1_string_st */
    	em[2370] = 2257; em[2371] = 0; 
    em[2372] = 1; em[2373] = 8; em[2374] = 1; /* 2372: pointer.struct.stack_st_DIST_POINT */
    	em[2375] = 2377; em[2376] = 0; 
    em[2377] = 0; em[2378] = 32; em[2379] = 2; /* 2377: struct.stack_st_fake_DIST_POINT */
    	em[2380] = 2384; em[2381] = 8; 
    	em[2382] = 109; em[2383] = 24; 
    em[2384] = 8884099; em[2385] = 8; em[2386] = 2; /* 2384: pointer_to_array_of_pointers_to_stack */
    	em[2387] = 2391; em[2388] = 0; 
    	em[2389] = 52; em[2390] = 20; 
    em[2391] = 0; em[2392] = 8; em[2393] = 1; /* 2391: pointer.DIST_POINT */
    	em[2394] = 2348; em[2395] = 0; 
    em[2396] = 0; em[2397] = 32; em[2398] = 3; /* 2396: struct.X509_POLICY_DATA_st */
    	em[2399] = 2405; em[2400] = 8; 
    	em[2401] = 2419; em[2402] = 16; 
    	em[2403] = 2664; em[2404] = 24; 
    em[2405] = 1; em[2406] = 8; em[2407] = 1; /* 2405: pointer.struct.asn1_object_st */
    	em[2408] = 2410; em[2409] = 0; 
    em[2410] = 0; em[2411] = 40; em[2412] = 3; /* 2410: struct.asn1_object_st */
    	em[2413] = 136; em[2414] = 0; 
    	em[2415] = 136; em[2416] = 8; 
    	em[2417] = 885; em[2418] = 24; 
    em[2419] = 1; em[2420] = 8; em[2421] = 1; /* 2419: pointer.struct.stack_st_POLICYQUALINFO */
    	em[2422] = 2424; em[2423] = 0; 
    em[2424] = 0; em[2425] = 32; em[2426] = 2; /* 2424: struct.stack_st_fake_POLICYQUALINFO */
    	em[2427] = 2431; em[2428] = 8; 
    	em[2429] = 109; em[2430] = 24; 
    em[2431] = 8884099; em[2432] = 8; em[2433] = 2; /* 2431: pointer_to_array_of_pointers_to_stack */
    	em[2434] = 2438; em[2435] = 0; 
    	em[2436] = 52; em[2437] = 20; 
    em[2438] = 0; em[2439] = 8; em[2440] = 1; /* 2438: pointer.POLICYQUALINFO */
    	em[2441] = 2443; em[2442] = 0; 
    em[2443] = 0; em[2444] = 0; em[2445] = 1; /* 2443: POLICYQUALINFO */
    	em[2446] = 2448; em[2447] = 0; 
    em[2448] = 0; em[2449] = 16; em[2450] = 2; /* 2448: struct.POLICYQUALINFO_st */
    	em[2451] = 2455; em[2452] = 0; 
    	em[2453] = 2469; em[2454] = 8; 
    em[2455] = 1; em[2456] = 8; em[2457] = 1; /* 2455: pointer.struct.asn1_object_st */
    	em[2458] = 2460; em[2459] = 0; 
    em[2460] = 0; em[2461] = 40; em[2462] = 3; /* 2460: struct.asn1_object_st */
    	em[2463] = 136; em[2464] = 0; 
    	em[2465] = 136; em[2466] = 8; 
    	em[2467] = 885; em[2468] = 24; 
    em[2469] = 0; em[2470] = 8; em[2471] = 3; /* 2469: union.unknown */
    	em[2472] = 2478; em[2473] = 0; 
    	em[2474] = 2488; em[2475] = 0; 
    	em[2476] = 2546; em[2477] = 0; 
    em[2478] = 1; em[2479] = 8; em[2480] = 1; /* 2478: pointer.struct.asn1_string_st */
    	em[2481] = 2483; em[2482] = 0; 
    em[2483] = 0; em[2484] = 24; em[2485] = 1; /* 2483: struct.asn1_string_st */
    	em[2486] = 69; em[2487] = 8; 
    em[2488] = 1; em[2489] = 8; em[2490] = 1; /* 2488: pointer.struct.USERNOTICE_st */
    	em[2491] = 2493; em[2492] = 0; 
    em[2493] = 0; em[2494] = 16; em[2495] = 2; /* 2493: struct.USERNOTICE_st */
    	em[2496] = 2500; em[2497] = 0; 
    	em[2498] = 2512; em[2499] = 8; 
    em[2500] = 1; em[2501] = 8; em[2502] = 1; /* 2500: pointer.struct.NOTICEREF_st */
    	em[2503] = 2505; em[2504] = 0; 
    em[2505] = 0; em[2506] = 16; em[2507] = 2; /* 2505: struct.NOTICEREF_st */
    	em[2508] = 2512; em[2509] = 0; 
    	em[2510] = 2517; em[2511] = 8; 
    em[2512] = 1; em[2513] = 8; em[2514] = 1; /* 2512: pointer.struct.asn1_string_st */
    	em[2515] = 2483; em[2516] = 0; 
    em[2517] = 1; em[2518] = 8; em[2519] = 1; /* 2517: pointer.struct.stack_st_ASN1_INTEGER */
    	em[2520] = 2522; em[2521] = 0; 
    em[2522] = 0; em[2523] = 32; em[2524] = 2; /* 2522: struct.stack_st_fake_ASN1_INTEGER */
    	em[2525] = 2529; em[2526] = 8; 
    	em[2527] = 109; em[2528] = 24; 
    em[2529] = 8884099; em[2530] = 8; em[2531] = 2; /* 2529: pointer_to_array_of_pointers_to_stack */
    	em[2532] = 2536; em[2533] = 0; 
    	em[2534] = 52; em[2535] = 20; 
    em[2536] = 0; em[2537] = 8; em[2538] = 1; /* 2536: pointer.ASN1_INTEGER */
    	em[2539] = 2541; em[2540] = 0; 
    em[2541] = 0; em[2542] = 0; em[2543] = 1; /* 2541: ASN1_INTEGER */
    	em[2544] = 948; em[2545] = 0; 
    em[2546] = 1; em[2547] = 8; em[2548] = 1; /* 2546: pointer.struct.asn1_type_st */
    	em[2549] = 2551; em[2550] = 0; 
    em[2551] = 0; em[2552] = 16; em[2553] = 1; /* 2551: struct.asn1_type_st */
    	em[2554] = 2556; em[2555] = 8; 
    em[2556] = 0; em[2557] = 8; em[2558] = 20; /* 2556: union.unknown */
    	em[2559] = 104; em[2560] = 0; 
    	em[2561] = 2512; em[2562] = 0; 
    	em[2563] = 2455; em[2564] = 0; 
    	em[2565] = 2599; em[2566] = 0; 
    	em[2567] = 2604; em[2568] = 0; 
    	em[2569] = 2609; em[2570] = 0; 
    	em[2571] = 2614; em[2572] = 0; 
    	em[2573] = 2619; em[2574] = 0; 
    	em[2575] = 2624; em[2576] = 0; 
    	em[2577] = 2478; em[2578] = 0; 
    	em[2579] = 2629; em[2580] = 0; 
    	em[2581] = 2634; em[2582] = 0; 
    	em[2583] = 2639; em[2584] = 0; 
    	em[2585] = 2644; em[2586] = 0; 
    	em[2587] = 2649; em[2588] = 0; 
    	em[2589] = 2654; em[2590] = 0; 
    	em[2591] = 2659; em[2592] = 0; 
    	em[2593] = 2512; em[2594] = 0; 
    	em[2595] = 2512; em[2596] = 0; 
    	em[2597] = 1359; em[2598] = 0; 
    em[2599] = 1; em[2600] = 8; em[2601] = 1; /* 2599: pointer.struct.asn1_string_st */
    	em[2602] = 2483; em[2603] = 0; 
    em[2604] = 1; em[2605] = 8; em[2606] = 1; /* 2604: pointer.struct.asn1_string_st */
    	em[2607] = 2483; em[2608] = 0; 
    em[2609] = 1; em[2610] = 8; em[2611] = 1; /* 2609: pointer.struct.asn1_string_st */
    	em[2612] = 2483; em[2613] = 0; 
    em[2614] = 1; em[2615] = 8; em[2616] = 1; /* 2614: pointer.struct.asn1_string_st */
    	em[2617] = 2483; em[2618] = 0; 
    em[2619] = 1; em[2620] = 8; em[2621] = 1; /* 2619: pointer.struct.asn1_string_st */
    	em[2622] = 2483; em[2623] = 0; 
    em[2624] = 1; em[2625] = 8; em[2626] = 1; /* 2624: pointer.struct.asn1_string_st */
    	em[2627] = 2483; em[2628] = 0; 
    em[2629] = 1; em[2630] = 8; em[2631] = 1; /* 2629: pointer.struct.asn1_string_st */
    	em[2632] = 2483; em[2633] = 0; 
    em[2634] = 1; em[2635] = 8; em[2636] = 1; /* 2634: pointer.struct.asn1_string_st */
    	em[2637] = 2483; em[2638] = 0; 
    em[2639] = 1; em[2640] = 8; em[2641] = 1; /* 2639: pointer.struct.asn1_string_st */
    	em[2642] = 2483; em[2643] = 0; 
    em[2644] = 1; em[2645] = 8; em[2646] = 1; /* 2644: pointer.struct.asn1_string_st */
    	em[2647] = 2483; em[2648] = 0; 
    em[2649] = 1; em[2650] = 8; em[2651] = 1; /* 2649: pointer.struct.asn1_string_st */
    	em[2652] = 2483; em[2653] = 0; 
    em[2654] = 1; em[2655] = 8; em[2656] = 1; /* 2654: pointer.struct.asn1_string_st */
    	em[2657] = 2483; em[2658] = 0; 
    em[2659] = 1; em[2660] = 8; em[2661] = 1; /* 2659: pointer.struct.asn1_string_st */
    	em[2662] = 2483; em[2663] = 0; 
    em[2664] = 1; em[2665] = 8; em[2666] = 1; /* 2664: pointer.struct.stack_st_ASN1_OBJECT */
    	em[2667] = 2669; em[2668] = 0; 
    em[2669] = 0; em[2670] = 32; em[2671] = 2; /* 2669: struct.stack_st_fake_ASN1_OBJECT */
    	em[2672] = 2676; em[2673] = 8; 
    	em[2674] = 109; em[2675] = 24; 
    em[2676] = 8884099; em[2677] = 8; em[2678] = 2; /* 2676: pointer_to_array_of_pointers_to_stack */
    	em[2679] = 2683; em[2680] = 0; 
    	em[2681] = 52; em[2682] = 20; 
    em[2683] = 0; em[2684] = 8; em[2685] = 1; /* 2683: pointer.ASN1_OBJECT */
    	em[2686] = 1078; em[2687] = 0; 
    em[2688] = 1; em[2689] = 8; em[2690] = 1; /* 2688: pointer.struct.stack_st_X509_POLICY_DATA */
    	em[2691] = 2693; em[2692] = 0; 
    em[2693] = 0; em[2694] = 32; em[2695] = 2; /* 2693: struct.stack_st_fake_X509_POLICY_DATA */
    	em[2696] = 2700; em[2697] = 8; 
    	em[2698] = 109; em[2699] = 24; 
    em[2700] = 8884099; em[2701] = 8; em[2702] = 2; /* 2700: pointer_to_array_of_pointers_to_stack */
    	em[2703] = 2707; em[2704] = 0; 
    	em[2705] = 52; em[2706] = 20; 
    em[2707] = 0; em[2708] = 8; em[2709] = 1; /* 2707: pointer.X509_POLICY_DATA */
    	em[2710] = 2712; em[2711] = 0; 
    em[2712] = 0; em[2713] = 0; em[2714] = 1; /* 2712: X509_POLICY_DATA */
    	em[2715] = 2396; em[2716] = 0; 
    em[2717] = 1; em[2718] = 8; em[2719] = 1; /* 2717: pointer.struct.stack_st_ASN1_OBJECT */
    	em[2720] = 2722; em[2721] = 0; 
    em[2722] = 0; em[2723] = 32; em[2724] = 2; /* 2722: struct.stack_st_fake_ASN1_OBJECT */
    	em[2725] = 2729; em[2726] = 8; 
    	em[2727] = 109; em[2728] = 24; 
    em[2729] = 8884099; em[2730] = 8; em[2731] = 2; /* 2729: pointer_to_array_of_pointers_to_stack */
    	em[2732] = 2736; em[2733] = 0; 
    	em[2734] = 52; em[2735] = 20; 
    em[2736] = 0; em[2737] = 8; em[2738] = 1; /* 2736: pointer.ASN1_OBJECT */
    	em[2739] = 1078; em[2740] = 0; 
    em[2741] = 0; em[2742] = 0; em[2743] = 1; /* 2741: GENERAL_SUBTREE */
    	em[2744] = 1432; em[2745] = 0; 
    em[2746] = 1; em[2747] = 8; em[2748] = 1; /* 2746: pointer.struct.stack_st_POLICYQUALINFO */
    	em[2749] = 2751; em[2750] = 0; 
    em[2751] = 0; em[2752] = 32; em[2753] = 2; /* 2751: struct.stack_st_fake_POLICYQUALINFO */
    	em[2754] = 2758; em[2755] = 8; 
    	em[2756] = 109; em[2757] = 24; 
    em[2758] = 8884099; em[2759] = 8; em[2760] = 2; /* 2758: pointer_to_array_of_pointers_to_stack */
    	em[2761] = 2765; em[2762] = 0; 
    	em[2763] = 52; em[2764] = 20; 
    em[2765] = 0; em[2766] = 8; em[2767] = 1; /* 2765: pointer.POLICYQUALINFO */
    	em[2768] = 2443; em[2769] = 0; 
    em[2770] = 0; em[2771] = 40; em[2772] = 3; /* 2770: struct.asn1_object_st */
    	em[2773] = 136; em[2774] = 0; 
    	em[2775] = 136; em[2776] = 8; 
    	em[2777] = 885; em[2778] = 24; 
    em[2779] = 0; em[2780] = 32; em[2781] = 3; /* 2779: struct.X509_POLICY_DATA_st */
    	em[2782] = 2788; em[2783] = 8; 
    	em[2784] = 2746; em[2785] = 16; 
    	em[2786] = 2717; em[2787] = 24; 
    em[2788] = 1; em[2789] = 8; em[2790] = 1; /* 2788: pointer.struct.asn1_object_st */
    	em[2791] = 2770; em[2792] = 0; 
    em[2793] = 1; em[2794] = 8; em[2795] = 1; /* 2793: pointer.struct.X509_POLICY_DATA_st */
    	em[2796] = 2779; em[2797] = 0; 
    em[2798] = 0; em[2799] = 40; em[2800] = 2; /* 2798: struct.X509_POLICY_CACHE_st */
    	em[2801] = 2793; em[2802] = 0; 
    	em[2803] = 2688; em[2804] = 8; 
    em[2805] = 1; em[2806] = 8; em[2807] = 1; /* 2805: pointer.struct.stack_st_GENERAL_NAME */
    	em[2808] = 2810; em[2809] = 0; 
    em[2810] = 0; em[2811] = 32; em[2812] = 2; /* 2810: struct.stack_st_fake_GENERAL_NAME */
    	em[2813] = 2817; em[2814] = 8; 
    	em[2815] = 109; em[2816] = 24; 
    em[2817] = 8884099; em[2818] = 8; em[2819] = 2; /* 2817: pointer_to_array_of_pointers_to_stack */
    	em[2820] = 2824; em[2821] = 0; 
    	em[2822] = 52; em[2823] = 20; 
    em[2824] = 0; em[2825] = 8; em[2826] = 1; /* 2824: pointer.GENERAL_NAME */
    	em[2827] = 1987; em[2828] = 0; 
    em[2829] = 1; em[2830] = 8; em[2831] = 1; /* 2829: pointer.struct.asn1_string_st */
    	em[2832] = 2834; em[2833] = 0; 
    em[2834] = 0; em[2835] = 24; em[2836] = 1; /* 2834: struct.asn1_string_st */
    	em[2837] = 69; em[2838] = 8; 
    em[2839] = 1; em[2840] = 8; em[2841] = 1; /* 2839: pointer.struct.AUTHORITY_KEYID_st */
    	em[2842] = 2844; em[2843] = 0; 
    em[2844] = 0; em[2845] = 24; em[2846] = 3; /* 2844: struct.AUTHORITY_KEYID_st */
    	em[2847] = 2829; em[2848] = 0; 
    	em[2849] = 2805; em[2850] = 8; 
    	em[2851] = 2853; em[2852] = 16; 
    em[2853] = 1; em[2854] = 8; em[2855] = 1; /* 2853: pointer.struct.asn1_string_st */
    	em[2856] = 2834; em[2857] = 0; 
    em[2858] = 0; em[2859] = 32; em[2860] = 1; /* 2858: struct.stack_st_void */
    	em[2861] = 2863; em[2862] = 0; 
    em[2863] = 0; em[2864] = 32; em[2865] = 2; /* 2863: struct.stack_st */
    	em[2866] = 99; em[2867] = 8; 
    	em[2868] = 109; em[2869] = 24; 
    em[2870] = 1; em[2871] = 8; em[2872] = 1; /* 2870: pointer.struct.stack_st_void */
    	em[2873] = 2858; em[2874] = 0; 
    em[2875] = 0; em[2876] = 24; em[2877] = 1; /* 2875: struct.asn1_string_st */
    	em[2878] = 69; em[2879] = 8; 
    em[2880] = 1; em[2881] = 8; em[2882] = 1; /* 2880: pointer.struct.asn1_string_st */
    	em[2883] = 2875; em[2884] = 0; 
    em[2885] = 0; em[2886] = 40; em[2887] = 3; /* 2885: struct.asn1_object_st */
    	em[2888] = 136; em[2889] = 0; 
    	em[2890] = 136; em[2891] = 8; 
    	em[2892] = 885; em[2893] = 24; 
    em[2894] = 1; em[2895] = 8; em[2896] = 1; /* 2894: pointer.struct.asn1_object_st */
    	em[2897] = 2885; em[2898] = 0; 
    em[2899] = 0; em[2900] = 24; em[2901] = 2; /* 2899: struct.X509_extension_st */
    	em[2902] = 2894; em[2903] = 0; 
    	em[2904] = 2880; em[2905] = 16; 
    em[2906] = 0; em[2907] = 0; em[2908] = 1; /* 2906: X509_EXTENSION */
    	em[2909] = 2899; em[2910] = 0; 
    em[2911] = 1; em[2912] = 8; em[2913] = 1; /* 2911: pointer.struct.stack_st_X509_EXTENSION */
    	em[2914] = 2916; em[2915] = 0; 
    em[2916] = 0; em[2917] = 32; em[2918] = 2; /* 2916: struct.stack_st_fake_X509_EXTENSION */
    	em[2919] = 2923; em[2920] = 8; 
    	em[2921] = 109; em[2922] = 24; 
    em[2923] = 8884099; em[2924] = 8; em[2925] = 2; /* 2923: pointer_to_array_of_pointers_to_stack */
    	em[2926] = 2930; em[2927] = 0; 
    	em[2928] = 52; em[2929] = 20; 
    em[2930] = 0; em[2931] = 8; em[2932] = 1; /* 2930: pointer.X509_EXTENSION */
    	em[2933] = 2906; em[2934] = 0; 
    em[2935] = 1; em[2936] = 8; em[2937] = 1; /* 2935: pointer.struct.asn1_string_st */
    	em[2938] = 1036; em[2939] = 0; 
    em[2940] = 1; em[2941] = 8; em[2942] = 1; /* 2940: pointer.struct.asn1_string_st */
    	em[2943] = 2945; em[2944] = 0; 
    em[2945] = 0; em[2946] = 24; em[2947] = 1; /* 2945: struct.asn1_string_st */
    	em[2948] = 69; em[2949] = 8; 
    em[2950] = 1; em[2951] = 8; em[2952] = 1; /* 2950: pointer.struct.asn1_string_st */
    	em[2953] = 2945; em[2954] = 0; 
    em[2955] = 1; em[2956] = 8; em[2957] = 1; /* 2955: pointer.struct.asn1_string_st */
    	em[2958] = 2945; em[2959] = 0; 
    em[2960] = 1; em[2961] = 8; em[2962] = 1; /* 2960: pointer.struct.asn1_string_st */
    	em[2963] = 2945; em[2964] = 0; 
    em[2965] = 1; em[2966] = 8; em[2967] = 1; /* 2965: pointer.struct.asn1_string_st */
    	em[2968] = 2945; em[2969] = 0; 
    em[2970] = 1; em[2971] = 8; em[2972] = 1; /* 2970: pointer.struct.asn1_string_st */
    	em[2973] = 2945; em[2974] = 0; 
    em[2975] = 1; em[2976] = 8; em[2977] = 1; /* 2975: pointer.struct.asn1_string_st */
    	em[2978] = 2945; em[2979] = 0; 
    em[2980] = 1; em[2981] = 8; em[2982] = 1; /* 2980: pointer.struct.asn1_string_st */
    	em[2983] = 2945; em[2984] = 0; 
    em[2985] = 0; em[2986] = 16; em[2987] = 1; /* 2985: struct.asn1_type_st */
    	em[2988] = 2990; em[2989] = 8; 
    em[2990] = 0; em[2991] = 8; em[2992] = 20; /* 2990: union.unknown */
    	em[2993] = 104; em[2994] = 0; 
    	em[2995] = 2980; em[2996] = 0; 
    	em[2997] = 3033; em[2998] = 0; 
    	em[2999] = 3047; em[3000] = 0; 
    	em[3001] = 2975; em[3002] = 0; 
    	em[3003] = 3052; em[3004] = 0; 
    	em[3005] = 2970; em[3006] = 0; 
    	em[3007] = 3057; em[3008] = 0; 
    	em[3009] = 2965; em[3010] = 0; 
    	em[3011] = 2960; em[3012] = 0; 
    	em[3013] = 2955; em[3014] = 0; 
    	em[3015] = 2950; em[3016] = 0; 
    	em[3017] = 3062; em[3018] = 0; 
    	em[3019] = 3067; em[3020] = 0; 
    	em[3021] = 3072; em[3022] = 0; 
    	em[3023] = 3077; em[3024] = 0; 
    	em[3025] = 2940; em[3026] = 0; 
    	em[3027] = 2980; em[3028] = 0; 
    	em[3029] = 2980; em[3030] = 0; 
    	em[3031] = 1023; em[3032] = 0; 
    em[3033] = 1; em[3034] = 8; em[3035] = 1; /* 3033: pointer.struct.asn1_object_st */
    	em[3036] = 3038; em[3037] = 0; 
    em[3038] = 0; em[3039] = 40; em[3040] = 3; /* 3038: struct.asn1_object_st */
    	em[3041] = 136; em[3042] = 0; 
    	em[3043] = 136; em[3044] = 8; 
    	em[3045] = 885; em[3046] = 24; 
    em[3047] = 1; em[3048] = 8; em[3049] = 1; /* 3047: pointer.struct.asn1_string_st */
    	em[3050] = 2945; em[3051] = 0; 
    em[3052] = 1; em[3053] = 8; em[3054] = 1; /* 3052: pointer.struct.asn1_string_st */
    	em[3055] = 2945; em[3056] = 0; 
    em[3057] = 1; em[3058] = 8; em[3059] = 1; /* 3057: pointer.struct.asn1_string_st */
    	em[3060] = 2945; em[3061] = 0; 
    em[3062] = 1; em[3063] = 8; em[3064] = 1; /* 3062: pointer.struct.asn1_string_st */
    	em[3065] = 2945; em[3066] = 0; 
    em[3067] = 1; em[3068] = 8; em[3069] = 1; /* 3067: pointer.struct.asn1_string_st */
    	em[3070] = 2945; em[3071] = 0; 
    em[3072] = 1; em[3073] = 8; em[3074] = 1; /* 3072: pointer.struct.asn1_string_st */
    	em[3075] = 2945; em[3076] = 0; 
    em[3077] = 1; em[3078] = 8; em[3079] = 1; /* 3077: pointer.struct.asn1_string_st */
    	em[3080] = 2945; em[3081] = 0; 
    em[3082] = 0; em[3083] = 0; em[3084] = 0; /* 3082: struct.ASN1_VALUE_st */
    em[3085] = 1; em[3086] = 8; em[3087] = 1; /* 3085: pointer.struct.asn1_string_st */
    	em[3088] = 3090; em[3089] = 0; 
    em[3090] = 0; em[3091] = 24; em[3092] = 1; /* 3090: struct.asn1_string_st */
    	em[3093] = 69; em[3094] = 8; 
    em[3095] = 1; em[3096] = 8; em[3097] = 1; /* 3095: pointer.struct.asn1_string_st */
    	em[3098] = 3090; em[3099] = 0; 
    em[3100] = 1; em[3101] = 8; em[3102] = 1; /* 3100: pointer.struct.asn1_string_st */
    	em[3103] = 3090; em[3104] = 0; 
    em[3105] = 1; em[3106] = 8; em[3107] = 1; /* 3105: pointer.struct.asn1_string_st */
    	em[3108] = 3090; em[3109] = 0; 
    em[3110] = 1; em[3111] = 8; em[3112] = 1; /* 3110: pointer.struct.asn1_string_st */
    	em[3113] = 3090; em[3114] = 0; 
    em[3115] = 1; em[3116] = 8; em[3117] = 1; /* 3115: pointer.struct.asn1_string_st */
    	em[3118] = 3090; em[3119] = 0; 
    em[3120] = 1; em[3121] = 8; em[3122] = 1; /* 3120: pointer.struct.asn1_object_st */
    	em[3123] = 3125; em[3124] = 0; 
    em[3125] = 0; em[3126] = 40; em[3127] = 3; /* 3125: struct.asn1_object_st */
    	em[3128] = 136; em[3129] = 0; 
    	em[3130] = 136; em[3131] = 8; 
    	em[3132] = 885; em[3133] = 24; 
    em[3134] = 1; em[3135] = 8; em[3136] = 1; /* 3134: pointer.struct.asn1_string_st */
    	em[3137] = 3090; em[3138] = 0; 
    em[3139] = 1; em[3140] = 8; em[3141] = 1; /* 3139: pointer.struct.stack_st_ASN1_TYPE */
    	em[3142] = 3144; em[3143] = 0; 
    em[3144] = 0; em[3145] = 32; em[3146] = 2; /* 3144: struct.stack_st_fake_ASN1_TYPE */
    	em[3147] = 3151; em[3148] = 8; 
    	em[3149] = 109; em[3150] = 24; 
    em[3151] = 8884099; em[3152] = 8; em[3153] = 2; /* 3151: pointer_to_array_of_pointers_to_stack */
    	em[3154] = 3158; em[3155] = 0; 
    	em[3156] = 52; em[3157] = 20; 
    em[3158] = 0; em[3159] = 8; em[3160] = 1; /* 3158: pointer.ASN1_TYPE */
    	em[3161] = 3163; em[3162] = 0; 
    em[3163] = 0; em[3164] = 0; em[3165] = 1; /* 3163: ASN1_TYPE */
    	em[3166] = 3168; em[3167] = 0; 
    em[3168] = 0; em[3169] = 16; em[3170] = 1; /* 3168: struct.asn1_type_st */
    	em[3171] = 3173; em[3172] = 8; 
    em[3173] = 0; em[3174] = 8; em[3175] = 20; /* 3173: union.unknown */
    	em[3176] = 104; em[3177] = 0; 
    	em[3178] = 3134; em[3179] = 0; 
    	em[3180] = 3120; em[3181] = 0; 
    	em[3182] = 3115; em[3183] = 0; 
    	em[3184] = 3216; em[3185] = 0; 
    	em[3186] = 3221; em[3187] = 0; 
    	em[3188] = 3226; em[3189] = 0; 
    	em[3190] = 3110; em[3191] = 0; 
    	em[3192] = 3231; em[3193] = 0; 
    	em[3194] = 3105; em[3195] = 0; 
    	em[3196] = 3236; em[3197] = 0; 
    	em[3198] = 3241; em[3199] = 0; 
    	em[3200] = 3246; em[3201] = 0; 
    	em[3202] = 3251; em[3203] = 0; 
    	em[3204] = 3100; em[3205] = 0; 
    	em[3206] = 3095; em[3207] = 0; 
    	em[3208] = 3085; em[3209] = 0; 
    	em[3210] = 3134; em[3211] = 0; 
    	em[3212] = 3134; em[3213] = 0; 
    	em[3214] = 3256; em[3215] = 0; 
    em[3216] = 1; em[3217] = 8; em[3218] = 1; /* 3216: pointer.struct.asn1_string_st */
    	em[3219] = 3090; em[3220] = 0; 
    em[3221] = 1; em[3222] = 8; em[3223] = 1; /* 3221: pointer.struct.asn1_string_st */
    	em[3224] = 3090; em[3225] = 0; 
    em[3226] = 1; em[3227] = 8; em[3228] = 1; /* 3226: pointer.struct.asn1_string_st */
    	em[3229] = 3090; em[3230] = 0; 
    em[3231] = 1; em[3232] = 8; em[3233] = 1; /* 3231: pointer.struct.asn1_string_st */
    	em[3234] = 3090; em[3235] = 0; 
    em[3236] = 1; em[3237] = 8; em[3238] = 1; /* 3236: pointer.struct.asn1_string_st */
    	em[3239] = 3090; em[3240] = 0; 
    em[3241] = 1; em[3242] = 8; em[3243] = 1; /* 3241: pointer.struct.asn1_string_st */
    	em[3244] = 3090; em[3245] = 0; 
    em[3246] = 1; em[3247] = 8; em[3248] = 1; /* 3246: pointer.struct.asn1_string_st */
    	em[3249] = 3090; em[3250] = 0; 
    em[3251] = 1; em[3252] = 8; em[3253] = 1; /* 3251: pointer.struct.asn1_string_st */
    	em[3254] = 3090; em[3255] = 0; 
    em[3256] = 1; em[3257] = 8; em[3258] = 1; /* 3256: pointer.struct.ASN1_VALUE_st */
    	em[3259] = 3082; em[3260] = 0; 
    em[3261] = 0; em[3262] = 24; em[3263] = 2; /* 3261: struct.x509_attributes_st */
    	em[3264] = 3033; em[3265] = 0; 
    	em[3266] = 3268; em[3267] = 16; 
    em[3268] = 0; em[3269] = 8; em[3270] = 3; /* 3268: union.unknown */
    	em[3271] = 104; em[3272] = 0; 
    	em[3273] = 3139; em[3274] = 0; 
    	em[3275] = 3277; em[3276] = 0; 
    em[3277] = 1; em[3278] = 8; em[3279] = 1; /* 3277: pointer.struct.asn1_type_st */
    	em[3280] = 2985; em[3281] = 0; 
    em[3282] = 1; em[3283] = 8; em[3284] = 1; /* 3282: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[3285] = 3287; em[3286] = 0; 
    em[3287] = 0; em[3288] = 32; em[3289] = 2; /* 3287: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[3290] = 3294; em[3291] = 8; 
    	em[3292] = 109; em[3293] = 24; 
    em[3294] = 8884099; em[3295] = 8; em[3296] = 2; /* 3294: pointer_to_array_of_pointers_to_stack */
    	em[3297] = 3301; em[3298] = 0; 
    	em[3299] = 52; em[3300] = 20; 
    em[3301] = 0; em[3302] = 8; em[3303] = 1; /* 3301: pointer.X509_ATTRIBUTE */
    	em[3304] = 3306; em[3305] = 0; 
    em[3306] = 0; em[3307] = 0; em[3308] = 1; /* 3306: X509_ATTRIBUTE */
    	em[3309] = 3261; em[3310] = 0; 
    em[3311] = 0; em[3312] = 16; em[3313] = 1; /* 3311: struct.crypto_ex_data_st */
    	em[3314] = 2870; em[3315] = 0; 
    em[3316] = 0; em[3317] = 24; em[3318] = 1; /* 3316: struct.ASN1_ENCODING_st */
    	em[3319] = 69; em[3320] = 0; 
    em[3321] = 8884099; em[3322] = 8; em[3323] = 2; /* 3321: pointer_to_array_of_pointers_to_stack */
    	em[3324] = 3328; em[3325] = 0; 
    	em[3326] = 52; em[3327] = 20; 
    em[3328] = 0; em[3329] = 8; em[3330] = 1; /* 3328: pointer.X509_ATTRIBUTE */
    	em[3331] = 3306; em[3332] = 0; 
    em[3333] = 8884097; em[3334] = 8; em[3335] = 0; /* 3333: pointer.func */
    em[3336] = 1; em[3337] = 8; em[3338] = 1; /* 3336: pointer.struct.NAME_CONSTRAINTS_st */
    	em[3339] = 3341; em[3340] = 0; 
    em[3341] = 0; em[3342] = 16; em[3343] = 2; /* 3341: struct.NAME_CONSTRAINTS_st */
    	em[3344] = 3348; em[3345] = 0; 
    	em[3346] = 3348; em[3347] = 8; 
    em[3348] = 1; em[3349] = 8; em[3350] = 1; /* 3348: pointer.struct.stack_st_GENERAL_SUBTREE */
    	em[3351] = 3353; em[3352] = 0; 
    em[3353] = 0; em[3354] = 32; em[3355] = 2; /* 3353: struct.stack_st_fake_GENERAL_SUBTREE */
    	em[3356] = 3360; em[3357] = 8; 
    	em[3358] = 109; em[3359] = 24; 
    em[3360] = 8884099; em[3361] = 8; em[3362] = 2; /* 3360: pointer_to_array_of_pointers_to_stack */
    	em[3363] = 3367; em[3364] = 0; 
    	em[3365] = 52; em[3366] = 20; 
    em[3367] = 0; em[3368] = 8; em[3369] = 1; /* 3367: pointer.GENERAL_SUBTREE */
    	em[3370] = 2741; em[3371] = 0; 
    em[3372] = 8884097; em[3373] = 8; em[3374] = 0; /* 3372: pointer.func */
    em[3375] = 8884097; em[3376] = 8; em[3377] = 0; /* 3375: pointer.func */
    em[3378] = 0; em[3379] = 208; em[3380] = 24; /* 3378: struct.evp_pkey_asn1_method_st */
    	em[3381] = 104; em[3382] = 16; 
    	em[3383] = 104; em[3384] = 24; 
    	em[3385] = 3429; em[3386] = 32; 
    	em[3387] = 3432; em[3388] = 40; 
    	em[3389] = 3435; em[3390] = 48; 
    	em[3391] = 3438; em[3392] = 56; 
    	em[3393] = 3441; em[3394] = 64; 
    	em[3395] = 3444; em[3396] = 72; 
    	em[3397] = 3438; em[3398] = 80; 
    	em[3399] = 3333; em[3400] = 88; 
    	em[3401] = 3333; em[3402] = 96; 
    	em[3403] = 3447; em[3404] = 104; 
    	em[3405] = 3450; em[3406] = 112; 
    	em[3407] = 3333; em[3408] = 120; 
    	em[3409] = 3375; em[3410] = 128; 
    	em[3411] = 3435; em[3412] = 136; 
    	em[3413] = 3438; em[3414] = 144; 
    	em[3415] = 3453; em[3416] = 152; 
    	em[3417] = 3456; em[3418] = 160; 
    	em[3419] = 3372; em[3420] = 168; 
    	em[3421] = 3447; em[3422] = 176; 
    	em[3423] = 3450; em[3424] = 184; 
    	em[3425] = 3459; em[3426] = 192; 
    	em[3427] = 3462; em[3428] = 200; 
    em[3429] = 8884097; em[3430] = 8; em[3431] = 0; /* 3429: pointer.func */
    em[3432] = 8884097; em[3433] = 8; em[3434] = 0; /* 3432: pointer.func */
    em[3435] = 8884097; em[3436] = 8; em[3437] = 0; /* 3435: pointer.func */
    em[3438] = 8884097; em[3439] = 8; em[3440] = 0; /* 3438: pointer.func */
    em[3441] = 8884097; em[3442] = 8; em[3443] = 0; /* 3441: pointer.func */
    em[3444] = 8884097; em[3445] = 8; em[3446] = 0; /* 3444: pointer.func */
    em[3447] = 8884097; em[3448] = 8; em[3449] = 0; /* 3447: pointer.func */
    em[3450] = 8884097; em[3451] = 8; em[3452] = 0; /* 3450: pointer.func */
    em[3453] = 8884097; em[3454] = 8; em[3455] = 0; /* 3453: pointer.func */
    em[3456] = 8884097; em[3457] = 8; em[3458] = 0; /* 3456: pointer.func */
    em[3459] = 8884097; em[3460] = 8; em[3461] = 0; /* 3459: pointer.func */
    em[3462] = 8884097; em[3463] = 8; em[3464] = 0; /* 3462: pointer.func */
    em[3465] = 1; em[3466] = 8; em[3467] = 1; /* 3465: pointer.struct.evp_pkey_st */
    	em[3468] = 3470; em[3469] = 0; 
    em[3470] = 0; em[3471] = 56; em[3472] = 4; /* 3470: struct.evp_pkey_st */
    	em[3473] = 3481; em[3474] = 16; 
    	em[3475] = 3486; em[3476] = 24; 
    	em[3477] = 1441; em[3478] = 32; 
    	em[3479] = 3491; em[3480] = 48; 
    em[3481] = 1; em[3482] = 8; em[3483] = 1; /* 3481: pointer.struct.evp_pkey_asn1_method_st */
    	em[3484] = 3378; em[3485] = 0; 
    em[3486] = 1; em[3487] = 8; em[3488] = 1; /* 3486: pointer.struct.engine_st */
    	em[3489] = 158; em[3490] = 0; 
    em[3491] = 1; em[3492] = 8; em[3493] = 1; /* 3491: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[3494] = 3496; em[3495] = 0; 
    em[3496] = 0; em[3497] = 32; em[3498] = 2; /* 3496: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[3499] = 3321; em[3500] = 8; 
    	em[3501] = 109; em[3502] = 24; 
    em[3503] = 1; em[3504] = 8; em[3505] = 1; /* 3503: pointer.struct.evp_pkey_asn1_method_st */
    	em[3506] = 3378; em[3507] = 0; 
    em[3508] = 0; em[3509] = 56; em[3510] = 4; /* 3508: struct.evp_pkey_st */
    	em[3511] = 3503; em[3512] = 16; 
    	em[3513] = 3519; em[3514] = 24; 
    	em[3515] = 3524; em[3516] = 32; 
    	em[3517] = 3282; em[3518] = 48; 
    em[3519] = 1; em[3520] = 8; em[3521] = 1; /* 3519: pointer.struct.engine_st */
    	em[3522] = 158; em[3523] = 0; 
    em[3524] = 0; em[3525] = 8; em[3526] = 5; /* 3524: union.unknown */
    	em[3527] = 104; em[3528] = 0; 
    	em[3529] = 3537; em[3530] = 0; 
    	em[3531] = 3542; em[3532] = 0; 
    	em[3533] = 3547; em[3534] = 0; 
    	em[3535] = 3552; em[3536] = 0; 
    em[3537] = 1; em[3538] = 8; em[3539] = 1; /* 3537: pointer.struct.rsa_st */
    	em[3540] = 645; em[3541] = 0; 
    em[3542] = 1; em[3543] = 8; em[3544] = 1; /* 3542: pointer.struct.dsa_st */
    	em[3545] = 506; em[3546] = 0; 
    em[3547] = 1; em[3548] = 8; em[3549] = 1; /* 3547: pointer.struct.dh_st */
    	em[3550] = 5; em[3551] = 0; 
    em[3552] = 1; em[3553] = 8; em[3554] = 1; /* 3552: pointer.struct.ec_key_st */
    	em[3555] = 1459; em[3556] = 0; 
    em[3557] = 1; em[3558] = 8; em[3559] = 1; /* 3557: pointer.struct.evp_pkey_st */
    	em[3560] = 3508; em[3561] = 0; 
    em[3562] = 0; em[3563] = 24; em[3564] = 1; /* 3562: struct.asn1_string_st */
    	em[3565] = 69; em[3566] = 8; 
    em[3567] = 1; em[3568] = 8; em[3569] = 1; /* 3567: pointer.struct.x509_st */
    	em[3570] = 3572; em[3571] = 0; 
    em[3572] = 0; em[3573] = 184; em[3574] = 12; /* 3572: struct.x509_st */
    	em[3575] = 3599; em[3576] = 0; 
    	em[3577] = 3634; em[3578] = 8; 
    	em[3579] = 2935; em[3580] = 16; 
    	em[3581] = 104; em[3582] = 32; 
    	em[3583] = 3311; em[3584] = 40; 
    	em[3585] = 1092; em[3586] = 104; 
    	em[3587] = 2839; em[3588] = 112; 
    	em[3589] = 3728; em[3590] = 120; 
    	em[3591] = 2372; em[3592] = 128; 
    	em[3593] = 1963; em[3594] = 136; 
    	em[3595] = 3336; em[3596] = 144; 
    	em[3597] = 1121; em[3598] = 176; 
    em[3599] = 1; em[3600] = 8; em[3601] = 1; /* 3599: pointer.struct.x509_cinf_st */
    	em[3602] = 3604; em[3603] = 0; 
    em[3604] = 0; em[3605] = 104; em[3606] = 11; /* 3604: struct.x509_cinf_st */
    	em[3607] = 3629; em[3608] = 0; 
    	em[3609] = 3629; em[3610] = 8; 
    	em[3611] = 3634; em[3612] = 16; 
    	em[3613] = 3639; em[3614] = 24; 
    	em[3615] = 3687; em[3616] = 32; 
    	em[3617] = 3639; em[3618] = 40; 
    	em[3619] = 3704; em[3620] = 48; 
    	em[3621] = 2935; em[3622] = 56; 
    	em[3623] = 2935; em[3624] = 64; 
    	em[3625] = 2911; em[3626] = 72; 
    	em[3627] = 3316; em[3628] = 80; 
    em[3629] = 1; em[3630] = 8; em[3631] = 1; /* 3629: pointer.struct.asn1_string_st */
    	em[3632] = 1036; em[3633] = 0; 
    em[3634] = 1; em[3635] = 8; em[3636] = 1; /* 3634: pointer.struct.X509_algor_st */
    	em[3637] = 864; em[3638] = 0; 
    em[3639] = 1; em[3640] = 8; em[3641] = 1; /* 3639: pointer.struct.X509_name_st */
    	em[3642] = 3644; em[3643] = 0; 
    em[3644] = 0; em[3645] = 40; em[3646] = 3; /* 3644: struct.X509_name_st */
    	em[3647] = 3653; em[3648] = 0; 
    	em[3649] = 3677; em[3650] = 16; 
    	em[3651] = 69; em[3652] = 24; 
    em[3653] = 1; em[3654] = 8; em[3655] = 1; /* 3653: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[3656] = 3658; em[3657] = 0; 
    em[3658] = 0; em[3659] = 32; em[3660] = 2; /* 3658: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[3661] = 3665; em[3662] = 8; 
    	em[3663] = 109; em[3664] = 24; 
    em[3665] = 8884099; em[3666] = 8; em[3667] = 2; /* 3665: pointer_to_array_of_pointers_to_stack */
    	em[3668] = 3672; em[3669] = 0; 
    	em[3670] = 52; em[3671] = 20; 
    em[3672] = 0; em[3673] = 8; em[3674] = 1; /* 3672: pointer.X509_NAME_ENTRY */
    	em[3675] = 1172; em[3676] = 0; 
    em[3677] = 1; em[3678] = 8; em[3679] = 1; /* 3677: pointer.struct.buf_mem_st */
    	em[3680] = 3682; em[3681] = 0; 
    em[3682] = 0; em[3683] = 24; em[3684] = 1; /* 3682: struct.buf_mem_st */
    	em[3685] = 104; em[3686] = 8; 
    em[3687] = 1; em[3688] = 8; em[3689] = 1; /* 3687: pointer.struct.X509_val_st */
    	em[3690] = 3692; em[3691] = 0; 
    em[3692] = 0; em[3693] = 16; em[3694] = 2; /* 3692: struct.X509_val_st */
    	em[3695] = 3699; em[3696] = 0; 
    	em[3697] = 3699; em[3698] = 8; 
    em[3699] = 1; em[3700] = 8; em[3701] = 1; /* 3699: pointer.struct.asn1_string_st */
    	em[3702] = 1036; em[3703] = 0; 
    em[3704] = 1; em[3705] = 8; em[3706] = 1; /* 3704: pointer.struct.X509_pubkey_st */
    	em[3707] = 3709; em[3708] = 0; 
    em[3709] = 0; em[3710] = 24; em[3711] = 3; /* 3709: struct.X509_pubkey_st */
    	em[3712] = 3718; em[3713] = 0; 
    	em[3714] = 3723; em[3715] = 8; 
    	em[3716] = 3557; em[3717] = 16; 
    em[3718] = 1; em[3719] = 8; em[3720] = 1; /* 3718: pointer.struct.X509_algor_st */
    	em[3721] = 864; em[3722] = 0; 
    em[3723] = 1; em[3724] = 8; em[3725] = 1; /* 3723: pointer.struct.asn1_string_st */
    	em[3726] = 3562; em[3727] = 0; 
    em[3728] = 1; em[3729] = 8; em[3730] = 1; /* 3728: pointer.struct.X509_POLICY_CACHE_st */
    	em[3731] = 2798; em[3732] = 0; 
    em[3733] = 0; em[3734] = 1; em[3735] = 0; /* 3733: char */
    args_addr->arg_entity_index[0] = 3567;
    args_addr->ret_entity_index = 3465;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    X509 * new_arg_a = *((X509 * *)new_args->args[0]);

    EVP_PKEY * *new_ret_ptr = (EVP_PKEY * *)new_args->ret;

    EVP_PKEY * (*orig_X509_get_pubkey)(X509 *);
    orig_X509_get_pubkey = dlsym(RTLD_NEXT, "X509_get_pubkey");
    *new_ret_ptr = (*orig_X509_get_pubkey)(new_arg_a);

    syscall(889);

    free(args_addr);

    return ret;
}

