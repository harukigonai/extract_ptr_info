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

EVP_PKEY * bb_PEM_read_bio_PrivateKey(BIO * arg_a,EVP_PKEY ** arg_b,pem_password_cb * arg_c,void * arg_d);

EVP_PKEY * PEM_read_bio_PrivateKey(BIO * arg_a,EVP_PKEY ** arg_b,pem_password_cb * arg_c,void * arg_d) 
{
    unsigned long in_lib = syscall(890);
    printf("PEM_read_bio_PrivateKey called %lu\n", in_lib);
    if (!in_lib)
        return bb_PEM_read_bio_PrivateKey(arg_a,arg_b,arg_c,arg_d);
    else {
        EVP_PKEY * (*orig_PEM_read_bio_PrivateKey)(BIO *,EVP_PKEY **,pem_password_cb *,void *);
        orig_PEM_read_bio_PrivateKey = dlsym(RTLD_NEXT, "PEM_read_bio_PrivateKey");
        return orig_PEM_read_bio_PrivateKey(arg_a,arg_b,arg_c,arg_d);
    }
}

EVP_PKEY * bb_PEM_read_bio_PrivateKey(BIO * arg_a,EVP_PKEY ** arg_b,pem_password_cb * arg_c,void * arg_d) 
{
    EVP_PKEY * ret;

    struct lib_enter_args *args_addr = malloc(sizeof(struct lib_enter_args));
    memset(args_addr, 0, sizeof(struct lib_enter_args));
    args_addr->num_args = 0;
    uint32_t *em = args_addr->entity_metadata;
    em[0] = 1; em[1] = 8; em[2] = 1; /* 0: pointer.pointer.struct.evp_pkey_st */
    	em[3] = 5; em[4] = 0; 
    em[5] = 1; em[6] = 8; em[7] = 1; /* 5: pointer.struct.evp_pkey_st */
    	em[8] = 10; em[9] = 0; 
    em[10] = 0; em[11] = 56; em[12] = 4; /* 10: struct.evp_pkey_st */
    	em[13] = 21; em[14] = 16; 
    	em[15] = 127; em[16] = 24; 
    	em[17] = 481; em[18] = 32; 
    	em[19] = 1471; em[20] = 48; 
    em[21] = 1; em[22] = 8; em[23] = 1; /* 21: pointer.struct.evp_pkey_asn1_method_st */
    	em[24] = 26; em[25] = 0; 
    em[26] = 0; em[27] = 208; em[28] = 24; /* 26: struct.evp_pkey_asn1_method_st */
    	em[29] = 77; em[30] = 16; 
    	em[31] = 77; em[32] = 24; 
    	em[33] = 82; em[34] = 32; 
    	em[35] = 85; em[36] = 40; 
    	em[37] = 88; em[38] = 48; 
    	em[39] = 91; em[40] = 56; 
    	em[41] = 94; em[42] = 64; 
    	em[43] = 97; em[44] = 72; 
    	em[45] = 91; em[46] = 80; 
    	em[47] = 100; em[48] = 88; 
    	em[49] = 100; em[50] = 96; 
    	em[51] = 103; em[52] = 104; 
    	em[53] = 106; em[54] = 112; 
    	em[55] = 100; em[56] = 120; 
    	em[57] = 109; em[58] = 128; 
    	em[59] = 88; em[60] = 136; 
    	em[61] = 91; em[62] = 144; 
    	em[63] = 112; em[64] = 152; 
    	em[65] = 115; em[66] = 160; 
    	em[67] = 118; em[68] = 168; 
    	em[69] = 103; em[70] = 176; 
    	em[71] = 106; em[72] = 184; 
    	em[73] = 121; em[74] = 192; 
    	em[75] = 124; em[76] = 200; 
    em[77] = 1; em[78] = 8; em[79] = 1; /* 77: pointer.char */
    	em[80] = 8884096; em[81] = 0; 
    em[82] = 8884097; em[83] = 8; em[84] = 0; /* 82: pointer.func */
    em[85] = 8884097; em[86] = 8; em[87] = 0; /* 85: pointer.func */
    em[88] = 8884097; em[89] = 8; em[90] = 0; /* 88: pointer.func */
    em[91] = 8884097; em[92] = 8; em[93] = 0; /* 91: pointer.func */
    em[94] = 8884097; em[95] = 8; em[96] = 0; /* 94: pointer.func */
    em[97] = 8884097; em[98] = 8; em[99] = 0; /* 97: pointer.func */
    em[100] = 8884097; em[101] = 8; em[102] = 0; /* 100: pointer.func */
    em[103] = 8884097; em[104] = 8; em[105] = 0; /* 103: pointer.func */
    em[106] = 8884097; em[107] = 8; em[108] = 0; /* 106: pointer.func */
    em[109] = 8884097; em[110] = 8; em[111] = 0; /* 109: pointer.func */
    em[112] = 8884097; em[113] = 8; em[114] = 0; /* 112: pointer.func */
    em[115] = 8884097; em[116] = 8; em[117] = 0; /* 115: pointer.func */
    em[118] = 8884097; em[119] = 8; em[120] = 0; /* 118: pointer.func */
    em[121] = 8884097; em[122] = 8; em[123] = 0; /* 121: pointer.func */
    em[124] = 8884097; em[125] = 8; em[126] = 0; /* 124: pointer.func */
    em[127] = 1; em[128] = 8; em[129] = 1; /* 127: pointer.struct.engine_st */
    	em[130] = 132; em[131] = 0; 
    em[132] = 0; em[133] = 216; em[134] = 24; /* 132: struct.engine_st */
    	em[135] = 183; em[136] = 0; 
    	em[137] = 183; em[138] = 8; 
    	em[139] = 188; em[140] = 16; 
    	em[141] = 243; em[142] = 24; 
    	em[143] = 294; em[144] = 32; 
    	em[145] = 330; em[146] = 40; 
    	em[147] = 347; em[148] = 48; 
    	em[149] = 374; em[150] = 56; 
    	em[151] = 409; em[152] = 64; 
    	em[153] = 417; em[154] = 72; 
    	em[155] = 420; em[156] = 80; 
    	em[157] = 423; em[158] = 88; 
    	em[159] = 426; em[160] = 96; 
    	em[161] = 429; em[162] = 104; 
    	em[163] = 429; em[164] = 112; 
    	em[165] = 429; em[166] = 120; 
    	em[167] = 432; em[168] = 128; 
    	em[169] = 435; em[170] = 136; 
    	em[171] = 435; em[172] = 144; 
    	em[173] = 438; em[174] = 152; 
    	em[175] = 441; em[176] = 160; 
    	em[177] = 453; em[178] = 184; 
    	em[179] = 476; em[180] = 200; 
    	em[181] = 476; em[182] = 208; 
    em[183] = 1; em[184] = 8; em[185] = 1; /* 183: pointer.char */
    	em[186] = 8884096; em[187] = 0; 
    em[188] = 1; em[189] = 8; em[190] = 1; /* 188: pointer.struct.rsa_meth_st */
    	em[191] = 193; em[192] = 0; 
    em[193] = 0; em[194] = 112; em[195] = 13; /* 193: struct.rsa_meth_st */
    	em[196] = 183; em[197] = 0; 
    	em[198] = 222; em[199] = 8; 
    	em[200] = 222; em[201] = 16; 
    	em[202] = 222; em[203] = 24; 
    	em[204] = 222; em[205] = 32; 
    	em[206] = 225; em[207] = 40; 
    	em[208] = 228; em[209] = 48; 
    	em[210] = 231; em[211] = 56; 
    	em[212] = 231; em[213] = 64; 
    	em[214] = 77; em[215] = 80; 
    	em[216] = 234; em[217] = 88; 
    	em[218] = 237; em[219] = 96; 
    	em[220] = 240; em[221] = 104; 
    em[222] = 8884097; em[223] = 8; em[224] = 0; /* 222: pointer.func */
    em[225] = 8884097; em[226] = 8; em[227] = 0; /* 225: pointer.func */
    em[228] = 8884097; em[229] = 8; em[230] = 0; /* 228: pointer.func */
    em[231] = 8884097; em[232] = 8; em[233] = 0; /* 231: pointer.func */
    em[234] = 8884097; em[235] = 8; em[236] = 0; /* 234: pointer.func */
    em[237] = 8884097; em[238] = 8; em[239] = 0; /* 237: pointer.func */
    em[240] = 8884097; em[241] = 8; em[242] = 0; /* 240: pointer.func */
    em[243] = 1; em[244] = 8; em[245] = 1; /* 243: pointer.struct.dsa_method */
    	em[246] = 248; em[247] = 0; 
    em[248] = 0; em[249] = 96; em[250] = 11; /* 248: struct.dsa_method */
    	em[251] = 183; em[252] = 0; 
    	em[253] = 273; em[254] = 8; 
    	em[255] = 276; em[256] = 16; 
    	em[257] = 279; em[258] = 24; 
    	em[259] = 282; em[260] = 32; 
    	em[261] = 285; em[262] = 40; 
    	em[263] = 288; em[264] = 48; 
    	em[265] = 288; em[266] = 56; 
    	em[267] = 77; em[268] = 72; 
    	em[269] = 291; em[270] = 80; 
    	em[271] = 288; em[272] = 88; 
    em[273] = 8884097; em[274] = 8; em[275] = 0; /* 273: pointer.func */
    em[276] = 8884097; em[277] = 8; em[278] = 0; /* 276: pointer.func */
    em[279] = 8884097; em[280] = 8; em[281] = 0; /* 279: pointer.func */
    em[282] = 8884097; em[283] = 8; em[284] = 0; /* 282: pointer.func */
    em[285] = 8884097; em[286] = 8; em[287] = 0; /* 285: pointer.func */
    em[288] = 8884097; em[289] = 8; em[290] = 0; /* 288: pointer.func */
    em[291] = 8884097; em[292] = 8; em[293] = 0; /* 291: pointer.func */
    em[294] = 1; em[295] = 8; em[296] = 1; /* 294: pointer.struct.dh_method */
    	em[297] = 299; em[298] = 0; 
    em[299] = 0; em[300] = 72; em[301] = 8; /* 299: struct.dh_method */
    	em[302] = 183; em[303] = 0; 
    	em[304] = 318; em[305] = 8; 
    	em[306] = 321; em[307] = 16; 
    	em[308] = 324; em[309] = 24; 
    	em[310] = 318; em[311] = 32; 
    	em[312] = 318; em[313] = 40; 
    	em[314] = 77; em[315] = 56; 
    	em[316] = 327; em[317] = 64; 
    em[318] = 8884097; em[319] = 8; em[320] = 0; /* 318: pointer.func */
    em[321] = 8884097; em[322] = 8; em[323] = 0; /* 321: pointer.func */
    em[324] = 8884097; em[325] = 8; em[326] = 0; /* 324: pointer.func */
    em[327] = 8884097; em[328] = 8; em[329] = 0; /* 327: pointer.func */
    em[330] = 1; em[331] = 8; em[332] = 1; /* 330: pointer.struct.ecdh_method */
    	em[333] = 335; em[334] = 0; 
    em[335] = 0; em[336] = 32; em[337] = 3; /* 335: struct.ecdh_method */
    	em[338] = 183; em[339] = 0; 
    	em[340] = 344; em[341] = 8; 
    	em[342] = 77; em[343] = 24; 
    em[344] = 8884097; em[345] = 8; em[346] = 0; /* 344: pointer.func */
    em[347] = 1; em[348] = 8; em[349] = 1; /* 347: pointer.struct.ecdsa_method */
    	em[350] = 352; em[351] = 0; 
    em[352] = 0; em[353] = 48; em[354] = 5; /* 352: struct.ecdsa_method */
    	em[355] = 183; em[356] = 0; 
    	em[357] = 365; em[358] = 8; 
    	em[359] = 368; em[360] = 16; 
    	em[361] = 371; em[362] = 24; 
    	em[363] = 77; em[364] = 40; 
    em[365] = 8884097; em[366] = 8; em[367] = 0; /* 365: pointer.func */
    em[368] = 8884097; em[369] = 8; em[370] = 0; /* 368: pointer.func */
    em[371] = 8884097; em[372] = 8; em[373] = 0; /* 371: pointer.func */
    em[374] = 1; em[375] = 8; em[376] = 1; /* 374: pointer.struct.rand_meth_st */
    	em[377] = 379; em[378] = 0; 
    em[379] = 0; em[380] = 48; em[381] = 6; /* 379: struct.rand_meth_st */
    	em[382] = 394; em[383] = 0; 
    	em[384] = 397; em[385] = 8; 
    	em[386] = 400; em[387] = 16; 
    	em[388] = 403; em[389] = 24; 
    	em[390] = 397; em[391] = 32; 
    	em[392] = 406; em[393] = 40; 
    em[394] = 8884097; em[395] = 8; em[396] = 0; /* 394: pointer.func */
    em[397] = 8884097; em[398] = 8; em[399] = 0; /* 397: pointer.func */
    em[400] = 8884097; em[401] = 8; em[402] = 0; /* 400: pointer.func */
    em[403] = 8884097; em[404] = 8; em[405] = 0; /* 403: pointer.func */
    em[406] = 8884097; em[407] = 8; em[408] = 0; /* 406: pointer.func */
    em[409] = 1; em[410] = 8; em[411] = 1; /* 409: pointer.struct.store_method_st */
    	em[412] = 414; em[413] = 0; 
    em[414] = 0; em[415] = 0; em[416] = 0; /* 414: struct.store_method_st */
    em[417] = 8884097; em[418] = 8; em[419] = 0; /* 417: pointer.func */
    em[420] = 8884097; em[421] = 8; em[422] = 0; /* 420: pointer.func */
    em[423] = 8884097; em[424] = 8; em[425] = 0; /* 423: pointer.func */
    em[426] = 8884097; em[427] = 8; em[428] = 0; /* 426: pointer.func */
    em[429] = 8884097; em[430] = 8; em[431] = 0; /* 429: pointer.func */
    em[432] = 8884097; em[433] = 8; em[434] = 0; /* 432: pointer.func */
    em[435] = 8884097; em[436] = 8; em[437] = 0; /* 435: pointer.func */
    em[438] = 8884097; em[439] = 8; em[440] = 0; /* 438: pointer.func */
    em[441] = 1; em[442] = 8; em[443] = 1; /* 441: pointer.struct.ENGINE_CMD_DEFN_st */
    	em[444] = 446; em[445] = 0; 
    em[446] = 0; em[447] = 32; em[448] = 2; /* 446: struct.ENGINE_CMD_DEFN_st */
    	em[449] = 183; em[450] = 8; 
    	em[451] = 183; em[452] = 16; 
    em[453] = 0; em[454] = 32; em[455] = 2; /* 453: struct.crypto_ex_data_st_fake */
    	em[456] = 460; em[457] = 8; 
    	em[458] = 473; em[459] = 24; 
    em[460] = 8884099; em[461] = 8; em[462] = 2; /* 460: pointer_to_array_of_pointers_to_stack */
    	em[463] = 467; em[464] = 0; 
    	em[465] = 470; em[466] = 20; 
    em[467] = 0; em[468] = 8; em[469] = 0; /* 467: pointer.void */
    em[470] = 0; em[471] = 4; em[472] = 0; /* 470: int */
    em[473] = 8884097; em[474] = 8; em[475] = 0; /* 473: pointer.func */
    em[476] = 1; em[477] = 8; em[478] = 1; /* 476: pointer.struct.engine_st */
    	em[479] = 132; em[480] = 0; 
    em[481] = 0; em[482] = 8; em[483] = 5; /* 481: union.unknown */
    	em[484] = 77; em[485] = 0; 
    	em[486] = 494; em[487] = 0; 
    	em[488] = 705; em[489] = 0; 
    	em[490] = 836; em[491] = 0; 
    	em[492] = 962; em[493] = 0; 
    em[494] = 1; em[495] = 8; em[496] = 1; /* 494: pointer.struct.rsa_st */
    	em[497] = 499; em[498] = 0; 
    em[499] = 0; em[500] = 168; em[501] = 17; /* 499: struct.rsa_st */
    	em[502] = 536; em[503] = 16; 
    	em[504] = 591; em[505] = 24; 
    	em[506] = 596; em[507] = 32; 
    	em[508] = 596; em[509] = 40; 
    	em[510] = 596; em[511] = 48; 
    	em[512] = 596; em[513] = 56; 
    	em[514] = 596; em[515] = 64; 
    	em[516] = 596; em[517] = 72; 
    	em[518] = 596; em[519] = 80; 
    	em[520] = 596; em[521] = 88; 
    	em[522] = 616; em[523] = 96; 
    	em[524] = 630; em[525] = 120; 
    	em[526] = 630; em[527] = 128; 
    	em[528] = 630; em[529] = 136; 
    	em[530] = 77; em[531] = 144; 
    	em[532] = 644; em[533] = 152; 
    	em[534] = 644; em[535] = 160; 
    em[536] = 1; em[537] = 8; em[538] = 1; /* 536: pointer.struct.rsa_meth_st */
    	em[539] = 541; em[540] = 0; 
    em[541] = 0; em[542] = 112; em[543] = 13; /* 541: struct.rsa_meth_st */
    	em[544] = 183; em[545] = 0; 
    	em[546] = 570; em[547] = 8; 
    	em[548] = 570; em[549] = 16; 
    	em[550] = 570; em[551] = 24; 
    	em[552] = 570; em[553] = 32; 
    	em[554] = 573; em[555] = 40; 
    	em[556] = 576; em[557] = 48; 
    	em[558] = 579; em[559] = 56; 
    	em[560] = 579; em[561] = 64; 
    	em[562] = 77; em[563] = 80; 
    	em[564] = 582; em[565] = 88; 
    	em[566] = 585; em[567] = 96; 
    	em[568] = 588; em[569] = 104; 
    em[570] = 8884097; em[571] = 8; em[572] = 0; /* 570: pointer.func */
    em[573] = 8884097; em[574] = 8; em[575] = 0; /* 573: pointer.func */
    em[576] = 8884097; em[577] = 8; em[578] = 0; /* 576: pointer.func */
    em[579] = 8884097; em[580] = 8; em[581] = 0; /* 579: pointer.func */
    em[582] = 8884097; em[583] = 8; em[584] = 0; /* 582: pointer.func */
    em[585] = 8884097; em[586] = 8; em[587] = 0; /* 585: pointer.func */
    em[588] = 8884097; em[589] = 8; em[590] = 0; /* 588: pointer.func */
    em[591] = 1; em[592] = 8; em[593] = 1; /* 591: pointer.struct.engine_st */
    	em[594] = 132; em[595] = 0; 
    em[596] = 1; em[597] = 8; em[598] = 1; /* 596: pointer.struct.bignum_st */
    	em[599] = 601; em[600] = 0; 
    em[601] = 0; em[602] = 24; em[603] = 1; /* 601: struct.bignum_st */
    	em[604] = 606; em[605] = 0; 
    em[606] = 8884099; em[607] = 8; em[608] = 2; /* 606: pointer_to_array_of_pointers_to_stack */
    	em[609] = 613; em[610] = 0; 
    	em[611] = 470; em[612] = 12; 
    em[613] = 0; em[614] = 8; em[615] = 0; /* 613: long unsigned int */
    em[616] = 0; em[617] = 32; em[618] = 2; /* 616: struct.crypto_ex_data_st_fake */
    	em[619] = 623; em[620] = 8; 
    	em[621] = 473; em[622] = 24; 
    em[623] = 8884099; em[624] = 8; em[625] = 2; /* 623: pointer_to_array_of_pointers_to_stack */
    	em[626] = 467; em[627] = 0; 
    	em[628] = 470; em[629] = 20; 
    em[630] = 1; em[631] = 8; em[632] = 1; /* 630: pointer.struct.bn_mont_ctx_st */
    	em[633] = 635; em[634] = 0; 
    em[635] = 0; em[636] = 96; em[637] = 3; /* 635: struct.bn_mont_ctx_st */
    	em[638] = 601; em[639] = 8; 
    	em[640] = 601; em[641] = 32; 
    	em[642] = 601; em[643] = 56; 
    em[644] = 1; em[645] = 8; em[646] = 1; /* 644: pointer.struct.bn_blinding_st */
    	em[647] = 649; em[648] = 0; 
    em[649] = 0; em[650] = 88; em[651] = 7; /* 649: struct.bn_blinding_st */
    	em[652] = 666; em[653] = 0; 
    	em[654] = 666; em[655] = 8; 
    	em[656] = 666; em[657] = 16; 
    	em[658] = 666; em[659] = 24; 
    	em[660] = 683; em[661] = 40; 
    	em[662] = 688; em[663] = 72; 
    	em[664] = 702; em[665] = 80; 
    em[666] = 1; em[667] = 8; em[668] = 1; /* 666: pointer.struct.bignum_st */
    	em[669] = 671; em[670] = 0; 
    em[671] = 0; em[672] = 24; em[673] = 1; /* 671: struct.bignum_st */
    	em[674] = 676; em[675] = 0; 
    em[676] = 8884099; em[677] = 8; em[678] = 2; /* 676: pointer_to_array_of_pointers_to_stack */
    	em[679] = 613; em[680] = 0; 
    	em[681] = 470; em[682] = 12; 
    em[683] = 0; em[684] = 16; em[685] = 1; /* 683: struct.crypto_threadid_st */
    	em[686] = 467; em[687] = 0; 
    em[688] = 1; em[689] = 8; em[690] = 1; /* 688: pointer.struct.bn_mont_ctx_st */
    	em[691] = 693; em[692] = 0; 
    em[693] = 0; em[694] = 96; em[695] = 3; /* 693: struct.bn_mont_ctx_st */
    	em[696] = 671; em[697] = 8; 
    	em[698] = 671; em[699] = 32; 
    	em[700] = 671; em[701] = 56; 
    em[702] = 8884097; em[703] = 8; em[704] = 0; /* 702: pointer.func */
    em[705] = 1; em[706] = 8; em[707] = 1; /* 705: pointer.struct.dsa_st */
    	em[708] = 710; em[709] = 0; 
    em[710] = 0; em[711] = 136; em[712] = 11; /* 710: struct.dsa_st */
    	em[713] = 735; em[714] = 24; 
    	em[715] = 735; em[716] = 32; 
    	em[717] = 735; em[718] = 40; 
    	em[719] = 735; em[720] = 48; 
    	em[721] = 735; em[722] = 56; 
    	em[723] = 735; em[724] = 64; 
    	em[725] = 735; em[726] = 72; 
    	em[727] = 752; em[728] = 88; 
    	em[729] = 766; em[730] = 104; 
    	em[731] = 780; em[732] = 120; 
    	em[733] = 831; em[734] = 128; 
    em[735] = 1; em[736] = 8; em[737] = 1; /* 735: pointer.struct.bignum_st */
    	em[738] = 740; em[739] = 0; 
    em[740] = 0; em[741] = 24; em[742] = 1; /* 740: struct.bignum_st */
    	em[743] = 745; em[744] = 0; 
    em[745] = 8884099; em[746] = 8; em[747] = 2; /* 745: pointer_to_array_of_pointers_to_stack */
    	em[748] = 613; em[749] = 0; 
    	em[750] = 470; em[751] = 12; 
    em[752] = 1; em[753] = 8; em[754] = 1; /* 752: pointer.struct.bn_mont_ctx_st */
    	em[755] = 757; em[756] = 0; 
    em[757] = 0; em[758] = 96; em[759] = 3; /* 757: struct.bn_mont_ctx_st */
    	em[760] = 740; em[761] = 8; 
    	em[762] = 740; em[763] = 32; 
    	em[764] = 740; em[765] = 56; 
    em[766] = 0; em[767] = 32; em[768] = 2; /* 766: struct.crypto_ex_data_st_fake */
    	em[769] = 773; em[770] = 8; 
    	em[771] = 473; em[772] = 24; 
    em[773] = 8884099; em[774] = 8; em[775] = 2; /* 773: pointer_to_array_of_pointers_to_stack */
    	em[776] = 467; em[777] = 0; 
    	em[778] = 470; em[779] = 20; 
    em[780] = 1; em[781] = 8; em[782] = 1; /* 780: pointer.struct.dsa_method */
    	em[783] = 785; em[784] = 0; 
    em[785] = 0; em[786] = 96; em[787] = 11; /* 785: struct.dsa_method */
    	em[788] = 183; em[789] = 0; 
    	em[790] = 810; em[791] = 8; 
    	em[792] = 813; em[793] = 16; 
    	em[794] = 816; em[795] = 24; 
    	em[796] = 819; em[797] = 32; 
    	em[798] = 822; em[799] = 40; 
    	em[800] = 825; em[801] = 48; 
    	em[802] = 825; em[803] = 56; 
    	em[804] = 77; em[805] = 72; 
    	em[806] = 828; em[807] = 80; 
    	em[808] = 825; em[809] = 88; 
    em[810] = 8884097; em[811] = 8; em[812] = 0; /* 810: pointer.func */
    em[813] = 8884097; em[814] = 8; em[815] = 0; /* 813: pointer.func */
    em[816] = 8884097; em[817] = 8; em[818] = 0; /* 816: pointer.func */
    em[819] = 8884097; em[820] = 8; em[821] = 0; /* 819: pointer.func */
    em[822] = 8884097; em[823] = 8; em[824] = 0; /* 822: pointer.func */
    em[825] = 8884097; em[826] = 8; em[827] = 0; /* 825: pointer.func */
    em[828] = 8884097; em[829] = 8; em[830] = 0; /* 828: pointer.func */
    em[831] = 1; em[832] = 8; em[833] = 1; /* 831: pointer.struct.engine_st */
    	em[834] = 132; em[835] = 0; 
    em[836] = 1; em[837] = 8; em[838] = 1; /* 836: pointer.struct.dh_st */
    	em[839] = 841; em[840] = 0; 
    em[841] = 0; em[842] = 144; em[843] = 12; /* 841: struct.dh_st */
    	em[844] = 868; em[845] = 8; 
    	em[846] = 868; em[847] = 16; 
    	em[848] = 868; em[849] = 32; 
    	em[850] = 868; em[851] = 40; 
    	em[852] = 885; em[853] = 56; 
    	em[854] = 868; em[855] = 64; 
    	em[856] = 868; em[857] = 72; 
    	em[858] = 899; em[859] = 80; 
    	em[860] = 868; em[861] = 96; 
    	em[862] = 907; em[863] = 112; 
    	em[864] = 921; em[865] = 128; 
    	em[866] = 957; em[867] = 136; 
    em[868] = 1; em[869] = 8; em[870] = 1; /* 868: pointer.struct.bignum_st */
    	em[871] = 873; em[872] = 0; 
    em[873] = 0; em[874] = 24; em[875] = 1; /* 873: struct.bignum_st */
    	em[876] = 878; em[877] = 0; 
    em[878] = 8884099; em[879] = 8; em[880] = 2; /* 878: pointer_to_array_of_pointers_to_stack */
    	em[881] = 613; em[882] = 0; 
    	em[883] = 470; em[884] = 12; 
    em[885] = 1; em[886] = 8; em[887] = 1; /* 885: pointer.struct.bn_mont_ctx_st */
    	em[888] = 890; em[889] = 0; 
    em[890] = 0; em[891] = 96; em[892] = 3; /* 890: struct.bn_mont_ctx_st */
    	em[893] = 873; em[894] = 8; 
    	em[895] = 873; em[896] = 32; 
    	em[897] = 873; em[898] = 56; 
    em[899] = 1; em[900] = 8; em[901] = 1; /* 899: pointer.unsigned char */
    	em[902] = 904; em[903] = 0; 
    em[904] = 0; em[905] = 1; em[906] = 0; /* 904: unsigned char */
    em[907] = 0; em[908] = 32; em[909] = 2; /* 907: struct.crypto_ex_data_st_fake */
    	em[910] = 914; em[911] = 8; 
    	em[912] = 473; em[913] = 24; 
    em[914] = 8884099; em[915] = 8; em[916] = 2; /* 914: pointer_to_array_of_pointers_to_stack */
    	em[917] = 467; em[918] = 0; 
    	em[919] = 470; em[920] = 20; 
    em[921] = 1; em[922] = 8; em[923] = 1; /* 921: pointer.struct.dh_method */
    	em[924] = 926; em[925] = 0; 
    em[926] = 0; em[927] = 72; em[928] = 8; /* 926: struct.dh_method */
    	em[929] = 183; em[930] = 0; 
    	em[931] = 945; em[932] = 8; 
    	em[933] = 948; em[934] = 16; 
    	em[935] = 951; em[936] = 24; 
    	em[937] = 945; em[938] = 32; 
    	em[939] = 945; em[940] = 40; 
    	em[941] = 77; em[942] = 56; 
    	em[943] = 954; em[944] = 64; 
    em[945] = 8884097; em[946] = 8; em[947] = 0; /* 945: pointer.func */
    em[948] = 8884097; em[949] = 8; em[950] = 0; /* 948: pointer.func */
    em[951] = 8884097; em[952] = 8; em[953] = 0; /* 951: pointer.func */
    em[954] = 8884097; em[955] = 8; em[956] = 0; /* 954: pointer.func */
    em[957] = 1; em[958] = 8; em[959] = 1; /* 957: pointer.struct.engine_st */
    	em[960] = 132; em[961] = 0; 
    em[962] = 1; em[963] = 8; em[964] = 1; /* 962: pointer.struct.ec_key_st */
    	em[965] = 967; em[966] = 0; 
    em[967] = 0; em[968] = 56; em[969] = 4; /* 967: struct.ec_key_st */
    	em[970] = 978; em[971] = 8; 
    	em[972] = 1426; em[973] = 16; 
    	em[974] = 1431; em[975] = 24; 
    	em[976] = 1448; em[977] = 48; 
    em[978] = 1; em[979] = 8; em[980] = 1; /* 978: pointer.struct.ec_group_st */
    	em[981] = 983; em[982] = 0; 
    em[983] = 0; em[984] = 232; em[985] = 12; /* 983: struct.ec_group_st */
    	em[986] = 1010; em[987] = 0; 
    	em[988] = 1182; em[989] = 8; 
    	em[990] = 1382; em[991] = 16; 
    	em[992] = 1382; em[993] = 40; 
    	em[994] = 899; em[995] = 80; 
    	em[996] = 1394; em[997] = 96; 
    	em[998] = 1382; em[999] = 104; 
    	em[1000] = 1382; em[1001] = 152; 
    	em[1002] = 1382; em[1003] = 176; 
    	em[1004] = 467; em[1005] = 208; 
    	em[1006] = 467; em[1007] = 216; 
    	em[1008] = 1423; em[1009] = 224; 
    em[1010] = 1; em[1011] = 8; em[1012] = 1; /* 1010: pointer.struct.ec_method_st */
    	em[1013] = 1015; em[1014] = 0; 
    em[1015] = 0; em[1016] = 304; em[1017] = 37; /* 1015: struct.ec_method_st */
    	em[1018] = 1092; em[1019] = 8; 
    	em[1020] = 1095; em[1021] = 16; 
    	em[1022] = 1095; em[1023] = 24; 
    	em[1024] = 1098; em[1025] = 32; 
    	em[1026] = 1101; em[1027] = 40; 
    	em[1028] = 1104; em[1029] = 48; 
    	em[1030] = 1107; em[1031] = 56; 
    	em[1032] = 1110; em[1033] = 64; 
    	em[1034] = 1113; em[1035] = 72; 
    	em[1036] = 1116; em[1037] = 80; 
    	em[1038] = 1116; em[1039] = 88; 
    	em[1040] = 1119; em[1041] = 96; 
    	em[1042] = 1122; em[1043] = 104; 
    	em[1044] = 1125; em[1045] = 112; 
    	em[1046] = 1128; em[1047] = 120; 
    	em[1048] = 1131; em[1049] = 128; 
    	em[1050] = 1134; em[1051] = 136; 
    	em[1052] = 1137; em[1053] = 144; 
    	em[1054] = 1140; em[1055] = 152; 
    	em[1056] = 1143; em[1057] = 160; 
    	em[1058] = 1146; em[1059] = 168; 
    	em[1060] = 1149; em[1061] = 176; 
    	em[1062] = 1152; em[1063] = 184; 
    	em[1064] = 1155; em[1065] = 192; 
    	em[1066] = 1158; em[1067] = 200; 
    	em[1068] = 1161; em[1069] = 208; 
    	em[1070] = 1152; em[1071] = 216; 
    	em[1072] = 1164; em[1073] = 224; 
    	em[1074] = 1167; em[1075] = 232; 
    	em[1076] = 1170; em[1077] = 240; 
    	em[1078] = 1107; em[1079] = 248; 
    	em[1080] = 1173; em[1081] = 256; 
    	em[1082] = 1176; em[1083] = 264; 
    	em[1084] = 1173; em[1085] = 272; 
    	em[1086] = 1176; em[1087] = 280; 
    	em[1088] = 1176; em[1089] = 288; 
    	em[1090] = 1179; em[1091] = 296; 
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
    em[1167] = 8884097; em[1168] = 8; em[1169] = 0; /* 1167: pointer.func */
    em[1170] = 8884097; em[1171] = 8; em[1172] = 0; /* 1170: pointer.func */
    em[1173] = 8884097; em[1174] = 8; em[1175] = 0; /* 1173: pointer.func */
    em[1176] = 8884097; em[1177] = 8; em[1178] = 0; /* 1176: pointer.func */
    em[1179] = 8884097; em[1180] = 8; em[1181] = 0; /* 1179: pointer.func */
    em[1182] = 1; em[1183] = 8; em[1184] = 1; /* 1182: pointer.struct.ec_point_st */
    	em[1185] = 1187; em[1186] = 0; 
    em[1187] = 0; em[1188] = 88; em[1189] = 4; /* 1187: struct.ec_point_st */
    	em[1190] = 1198; em[1191] = 0; 
    	em[1192] = 1370; em[1193] = 8; 
    	em[1194] = 1370; em[1195] = 32; 
    	em[1196] = 1370; em[1197] = 56; 
    em[1198] = 1; em[1199] = 8; em[1200] = 1; /* 1198: pointer.struct.ec_method_st */
    	em[1201] = 1203; em[1202] = 0; 
    em[1203] = 0; em[1204] = 304; em[1205] = 37; /* 1203: struct.ec_method_st */
    	em[1206] = 1280; em[1207] = 8; 
    	em[1208] = 1283; em[1209] = 16; 
    	em[1210] = 1283; em[1211] = 24; 
    	em[1212] = 1286; em[1213] = 32; 
    	em[1214] = 1289; em[1215] = 40; 
    	em[1216] = 1292; em[1217] = 48; 
    	em[1218] = 1295; em[1219] = 56; 
    	em[1220] = 1298; em[1221] = 64; 
    	em[1222] = 1301; em[1223] = 72; 
    	em[1224] = 1304; em[1225] = 80; 
    	em[1226] = 1304; em[1227] = 88; 
    	em[1228] = 1307; em[1229] = 96; 
    	em[1230] = 1310; em[1231] = 104; 
    	em[1232] = 1313; em[1233] = 112; 
    	em[1234] = 1316; em[1235] = 120; 
    	em[1236] = 1319; em[1237] = 128; 
    	em[1238] = 1322; em[1239] = 136; 
    	em[1240] = 1325; em[1241] = 144; 
    	em[1242] = 1328; em[1243] = 152; 
    	em[1244] = 1331; em[1245] = 160; 
    	em[1246] = 1334; em[1247] = 168; 
    	em[1248] = 1337; em[1249] = 176; 
    	em[1250] = 1340; em[1251] = 184; 
    	em[1252] = 1343; em[1253] = 192; 
    	em[1254] = 1346; em[1255] = 200; 
    	em[1256] = 1349; em[1257] = 208; 
    	em[1258] = 1340; em[1259] = 216; 
    	em[1260] = 1352; em[1261] = 224; 
    	em[1262] = 1355; em[1263] = 232; 
    	em[1264] = 1358; em[1265] = 240; 
    	em[1266] = 1295; em[1267] = 248; 
    	em[1268] = 1361; em[1269] = 256; 
    	em[1270] = 1364; em[1271] = 264; 
    	em[1272] = 1361; em[1273] = 272; 
    	em[1274] = 1364; em[1275] = 280; 
    	em[1276] = 1364; em[1277] = 288; 
    	em[1278] = 1367; em[1279] = 296; 
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
    em[1355] = 8884097; em[1356] = 8; em[1357] = 0; /* 1355: pointer.func */
    em[1358] = 8884097; em[1359] = 8; em[1360] = 0; /* 1358: pointer.func */
    em[1361] = 8884097; em[1362] = 8; em[1363] = 0; /* 1361: pointer.func */
    em[1364] = 8884097; em[1365] = 8; em[1366] = 0; /* 1364: pointer.func */
    em[1367] = 8884097; em[1368] = 8; em[1369] = 0; /* 1367: pointer.func */
    em[1370] = 0; em[1371] = 24; em[1372] = 1; /* 1370: struct.bignum_st */
    	em[1373] = 1375; em[1374] = 0; 
    em[1375] = 8884099; em[1376] = 8; em[1377] = 2; /* 1375: pointer_to_array_of_pointers_to_stack */
    	em[1378] = 613; em[1379] = 0; 
    	em[1380] = 470; em[1381] = 12; 
    em[1382] = 0; em[1383] = 24; em[1384] = 1; /* 1382: struct.bignum_st */
    	em[1385] = 1387; em[1386] = 0; 
    em[1387] = 8884099; em[1388] = 8; em[1389] = 2; /* 1387: pointer_to_array_of_pointers_to_stack */
    	em[1390] = 613; em[1391] = 0; 
    	em[1392] = 470; em[1393] = 12; 
    em[1394] = 1; em[1395] = 8; em[1396] = 1; /* 1394: pointer.struct.ec_extra_data_st */
    	em[1397] = 1399; em[1398] = 0; 
    em[1399] = 0; em[1400] = 40; em[1401] = 5; /* 1399: struct.ec_extra_data_st */
    	em[1402] = 1412; em[1403] = 0; 
    	em[1404] = 467; em[1405] = 8; 
    	em[1406] = 1417; em[1407] = 16; 
    	em[1408] = 1420; em[1409] = 24; 
    	em[1410] = 1420; em[1411] = 32; 
    em[1412] = 1; em[1413] = 8; em[1414] = 1; /* 1412: pointer.struct.ec_extra_data_st */
    	em[1415] = 1399; em[1416] = 0; 
    em[1417] = 8884097; em[1418] = 8; em[1419] = 0; /* 1417: pointer.func */
    em[1420] = 8884097; em[1421] = 8; em[1422] = 0; /* 1420: pointer.func */
    em[1423] = 8884097; em[1424] = 8; em[1425] = 0; /* 1423: pointer.func */
    em[1426] = 1; em[1427] = 8; em[1428] = 1; /* 1426: pointer.struct.ec_point_st */
    	em[1429] = 1187; em[1430] = 0; 
    em[1431] = 1; em[1432] = 8; em[1433] = 1; /* 1431: pointer.struct.bignum_st */
    	em[1434] = 1436; em[1435] = 0; 
    em[1436] = 0; em[1437] = 24; em[1438] = 1; /* 1436: struct.bignum_st */
    	em[1439] = 1441; em[1440] = 0; 
    em[1441] = 8884099; em[1442] = 8; em[1443] = 2; /* 1441: pointer_to_array_of_pointers_to_stack */
    	em[1444] = 613; em[1445] = 0; 
    	em[1446] = 470; em[1447] = 12; 
    em[1448] = 1; em[1449] = 8; em[1450] = 1; /* 1448: pointer.struct.ec_extra_data_st */
    	em[1451] = 1453; em[1452] = 0; 
    em[1453] = 0; em[1454] = 40; em[1455] = 5; /* 1453: struct.ec_extra_data_st */
    	em[1456] = 1466; em[1457] = 0; 
    	em[1458] = 467; em[1459] = 8; 
    	em[1460] = 1417; em[1461] = 16; 
    	em[1462] = 1420; em[1463] = 24; 
    	em[1464] = 1420; em[1465] = 32; 
    em[1466] = 1; em[1467] = 8; em[1468] = 1; /* 1466: pointer.struct.ec_extra_data_st */
    	em[1469] = 1453; em[1470] = 0; 
    em[1471] = 1; em[1472] = 8; em[1473] = 1; /* 1471: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[1474] = 1476; em[1475] = 0; 
    em[1476] = 0; em[1477] = 32; em[1478] = 2; /* 1476: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[1479] = 1483; em[1480] = 8; 
    	em[1481] = 473; em[1482] = 24; 
    em[1483] = 8884099; em[1484] = 8; em[1485] = 2; /* 1483: pointer_to_array_of_pointers_to_stack */
    	em[1486] = 1490; em[1487] = 0; 
    	em[1488] = 470; em[1489] = 20; 
    em[1490] = 0; em[1491] = 8; em[1492] = 1; /* 1490: pointer.X509_ATTRIBUTE */
    	em[1493] = 1495; em[1494] = 0; 
    em[1495] = 0; em[1496] = 0; em[1497] = 1; /* 1495: X509_ATTRIBUTE */
    	em[1498] = 1500; em[1499] = 0; 
    em[1500] = 0; em[1501] = 24; em[1502] = 2; /* 1500: struct.x509_attributes_st */
    	em[1503] = 1507; em[1504] = 0; 
    	em[1505] = 1526; em[1506] = 16; 
    em[1507] = 1; em[1508] = 8; em[1509] = 1; /* 1507: pointer.struct.asn1_object_st */
    	em[1510] = 1512; em[1511] = 0; 
    em[1512] = 0; em[1513] = 40; em[1514] = 3; /* 1512: struct.asn1_object_st */
    	em[1515] = 183; em[1516] = 0; 
    	em[1517] = 183; em[1518] = 8; 
    	em[1519] = 1521; em[1520] = 24; 
    em[1521] = 1; em[1522] = 8; em[1523] = 1; /* 1521: pointer.unsigned char */
    	em[1524] = 904; em[1525] = 0; 
    em[1526] = 0; em[1527] = 8; em[1528] = 3; /* 1526: union.unknown */
    	em[1529] = 77; em[1530] = 0; 
    	em[1531] = 1535; em[1532] = 0; 
    	em[1533] = 1714; em[1534] = 0; 
    em[1535] = 1; em[1536] = 8; em[1537] = 1; /* 1535: pointer.struct.stack_st_ASN1_TYPE */
    	em[1538] = 1540; em[1539] = 0; 
    em[1540] = 0; em[1541] = 32; em[1542] = 2; /* 1540: struct.stack_st_fake_ASN1_TYPE */
    	em[1543] = 1547; em[1544] = 8; 
    	em[1545] = 473; em[1546] = 24; 
    em[1547] = 8884099; em[1548] = 8; em[1549] = 2; /* 1547: pointer_to_array_of_pointers_to_stack */
    	em[1550] = 1554; em[1551] = 0; 
    	em[1552] = 470; em[1553] = 20; 
    em[1554] = 0; em[1555] = 8; em[1556] = 1; /* 1554: pointer.ASN1_TYPE */
    	em[1557] = 1559; em[1558] = 0; 
    em[1559] = 0; em[1560] = 0; em[1561] = 1; /* 1559: ASN1_TYPE */
    	em[1562] = 1564; em[1563] = 0; 
    em[1564] = 0; em[1565] = 16; em[1566] = 1; /* 1564: struct.asn1_type_st */
    	em[1567] = 1569; em[1568] = 8; 
    em[1569] = 0; em[1570] = 8; em[1571] = 20; /* 1569: union.unknown */
    	em[1572] = 77; em[1573] = 0; 
    	em[1574] = 1612; em[1575] = 0; 
    	em[1576] = 1622; em[1577] = 0; 
    	em[1578] = 1636; em[1579] = 0; 
    	em[1580] = 1641; em[1581] = 0; 
    	em[1582] = 1646; em[1583] = 0; 
    	em[1584] = 1651; em[1585] = 0; 
    	em[1586] = 1656; em[1587] = 0; 
    	em[1588] = 1661; em[1589] = 0; 
    	em[1590] = 1666; em[1591] = 0; 
    	em[1592] = 1671; em[1593] = 0; 
    	em[1594] = 1676; em[1595] = 0; 
    	em[1596] = 1681; em[1597] = 0; 
    	em[1598] = 1686; em[1599] = 0; 
    	em[1600] = 1691; em[1601] = 0; 
    	em[1602] = 1696; em[1603] = 0; 
    	em[1604] = 1701; em[1605] = 0; 
    	em[1606] = 1612; em[1607] = 0; 
    	em[1608] = 1612; em[1609] = 0; 
    	em[1610] = 1706; em[1611] = 0; 
    em[1612] = 1; em[1613] = 8; em[1614] = 1; /* 1612: pointer.struct.asn1_string_st */
    	em[1615] = 1617; em[1616] = 0; 
    em[1617] = 0; em[1618] = 24; em[1619] = 1; /* 1617: struct.asn1_string_st */
    	em[1620] = 899; em[1621] = 8; 
    em[1622] = 1; em[1623] = 8; em[1624] = 1; /* 1622: pointer.struct.asn1_object_st */
    	em[1625] = 1627; em[1626] = 0; 
    em[1627] = 0; em[1628] = 40; em[1629] = 3; /* 1627: struct.asn1_object_st */
    	em[1630] = 183; em[1631] = 0; 
    	em[1632] = 183; em[1633] = 8; 
    	em[1634] = 1521; em[1635] = 24; 
    em[1636] = 1; em[1637] = 8; em[1638] = 1; /* 1636: pointer.struct.asn1_string_st */
    	em[1639] = 1617; em[1640] = 0; 
    em[1641] = 1; em[1642] = 8; em[1643] = 1; /* 1641: pointer.struct.asn1_string_st */
    	em[1644] = 1617; em[1645] = 0; 
    em[1646] = 1; em[1647] = 8; em[1648] = 1; /* 1646: pointer.struct.asn1_string_st */
    	em[1649] = 1617; em[1650] = 0; 
    em[1651] = 1; em[1652] = 8; em[1653] = 1; /* 1651: pointer.struct.asn1_string_st */
    	em[1654] = 1617; em[1655] = 0; 
    em[1656] = 1; em[1657] = 8; em[1658] = 1; /* 1656: pointer.struct.asn1_string_st */
    	em[1659] = 1617; em[1660] = 0; 
    em[1661] = 1; em[1662] = 8; em[1663] = 1; /* 1661: pointer.struct.asn1_string_st */
    	em[1664] = 1617; em[1665] = 0; 
    em[1666] = 1; em[1667] = 8; em[1668] = 1; /* 1666: pointer.struct.asn1_string_st */
    	em[1669] = 1617; em[1670] = 0; 
    em[1671] = 1; em[1672] = 8; em[1673] = 1; /* 1671: pointer.struct.asn1_string_st */
    	em[1674] = 1617; em[1675] = 0; 
    em[1676] = 1; em[1677] = 8; em[1678] = 1; /* 1676: pointer.struct.asn1_string_st */
    	em[1679] = 1617; em[1680] = 0; 
    em[1681] = 1; em[1682] = 8; em[1683] = 1; /* 1681: pointer.struct.asn1_string_st */
    	em[1684] = 1617; em[1685] = 0; 
    em[1686] = 1; em[1687] = 8; em[1688] = 1; /* 1686: pointer.struct.asn1_string_st */
    	em[1689] = 1617; em[1690] = 0; 
    em[1691] = 1; em[1692] = 8; em[1693] = 1; /* 1691: pointer.struct.asn1_string_st */
    	em[1694] = 1617; em[1695] = 0; 
    em[1696] = 1; em[1697] = 8; em[1698] = 1; /* 1696: pointer.struct.asn1_string_st */
    	em[1699] = 1617; em[1700] = 0; 
    em[1701] = 1; em[1702] = 8; em[1703] = 1; /* 1701: pointer.struct.asn1_string_st */
    	em[1704] = 1617; em[1705] = 0; 
    em[1706] = 1; em[1707] = 8; em[1708] = 1; /* 1706: pointer.struct.ASN1_VALUE_st */
    	em[1709] = 1711; em[1710] = 0; 
    em[1711] = 0; em[1712] = 0; em[1713] = 0; /* 1711: struct.ASN1_VALUE_st */
    em[1714] = 1; em[1715] = 8; em[1716] = 1; /* 1714: pointer.struct.asn1_type_st */
    	em[1717] = 1719; em[1718] = 0; 
    em[1719] = 0; em[1720] = 16; em[1721] = 1; /* 1719: struct.asn1_type_st */
    	em[1722] = 1724; em[1723] = 8; 
    em[1724] = 0; em[1725] = 8; em[1726] = 20; /* 1724: union.unknown */
    	em[1727] = 77; em[1728] = 0; 
    	em[1729] = 1767; em[1730] = 0; 
    	em[1731] = 1507; em[1732] = 0; 
    	em[1733] = 1777; em[1734] = 0; 
    	em[1735] = 1782; em[1736] = 0; 
    	em[1737] = 1787; em[1738] = 0; 
    	em[1739] = 1792; em[1740] = 0; 
    	em[1741] = 1797; em[1742] = 0; 
    	em[1743] = 1802; em[1744] = 0; 
    	em[1745] = 1807; em[1746] = 0; 
    	em[1747] = 1812; em[1748] = 0; 
    	em[1749] = 1817; em[1750] = 0; 
    	em[1751] = 1822; em[1752] = 0; 
    	em[1753] = 1827; em[1754] = 0; 
    	em[1755] = 1832; em[1756] = 0; 
    	em[1757] = 1837; em[1758] = 0; 
    	em[1759] = 1842; em[1760] = 0; 
    	em[1761] = 1767; em[1762] = 0; 
    	em[1763] = 1767; em[1764] = 0; 
    	em[1765] = 1847; em[1766] = 0; 
    em[1767] = 1; em[1768] = 8; em[1769] = 1; /* 1767: pointer.struct.asn1_string_st */
    	em[1770] = 1772; em[1771] = 0; 
    em[1772] = 0; em[1773] = 24; em[1774] = 1; /* 1772: struct.asn1_string_st */
    	em[1775] = 899; em[1776] = 8; 
    em[1777] = 1; em[1778] = 8; em[1779] = 1; /* 1777: pointer.struct.asn1_string_st */
    	em[1780] = 1772; em[1781] = 0; 
    em[1782] = 1; em[1783] = 8; em[1784] = 1; /* 1782: pointer.struct.asn1_string_st */
    	em[1785] = 1772; em[1786] = 0; 
    em[1787] = 1; em[1788] = 8; em[1789] = 1; /* 1787: pointer.struct.asn1_string_st */
    	em[1790] = 1772; em[1791] = 0; 
    em[1792] = 1; em[1793] = 8; em[1794] = 1; /* 1792: pointer.struct.asn1_string_st */
    	em[1795] = 1772; em[1796] = 0; 
    em[1797] = 1; em[1798] = 8; em[1799] = 1; /* 1797: pointer.struct.asn1_string_st */
    	em[1800] = 1772; em[1801] = 0; 
    em[1802] = 1; em[1803] = 8; em[1804] = 1; /* 1802: pointer.struct.asn1_string_st */
    	em[1805] = 1772; em[1806] = 0; 
    em[1807] = 1; em[1808] = 8; em[1809] = 1; /* 1807: pointer.struct.asn1_string_st */
    	em[1810] = 1772; em[1811] = 0; 
    em[1812] = 1; em[1813] = 8; em[1814] = 1; /* 1812: pointer.struct.asn1_string_st */
    	em[1815] = 1772; em[1816] = 0; 
    em[1817] = 1; em[1818] = 8; em[1819] = 1; /* 1817: pointer.struct.asn1_string_st */
    	em[1820] = 1772; em[1821] = 0; 
    em[1822] = 1; em[1823] = 8; em[1824] = 1; /* 1822: pointer.struct.asn1_string_st */
    	em[1825] = 1772; em[1826] = 0; 
    em[1827] = 1; em[1828] = 8; em[1829] = 1; /* 1827: pointer.struct.asn1_string_st */
    	em[1830] = 1772; em[1831] = 0; 
    em[1832] = 1; em[1833] = 8; em[1834] = 1; /* 1832: pointer.struct.asn1_string_st */
    	em[1835] = 1772; em[1836] = 0; 
    em[1837] = 1; em[1838] = 8; em[1839] = 1; /* 1837: pointer.struct.asn1_string_st */
    	em[1840] = 1772; em[1841] = 0; 
    em[1842] = 1; em[1843] = 8; em[1844] = 1; /* 1842: pointer.struct.asn1_string_st */
    	em[1845] = 1772; em[1846] = 0; 
    em[1847] = 1; em[1848] = 8; em[1849] = 1; /* 1847: pointer.struct.ASN1_VALUE_st */
    	em[1850] = 1852; em[1851] = 0; 
    em[1852] = 0; em[1853] = 0; em[1854] = 0; /* 1852: struct.ASN1_VALUE_st */
    em[1855] = 8884097; em[1856] = 8; em[1857] = 0; /* 1855: pointer.func */
    em[1858] = 1; em[1859] = 8; em[1860] = 1; /* 1858: pointer.struct.bio_st */
    	em[1861] = 1863; em[1862] = 0; 
    em[1863] = 0; em[1864] = 112; em[1865] = 7; /* 1863: struct.bio_st */
    	em[1866] = 1880; em[1867] = 0; 
    	em[1868] = 1924; em[1869] = 8; 
    	em[1870] = 77; em[1871] = 16; 
    	em[1872] = 467; em[1873] = 48; 
    	em[1874] = 1858; em[1875] = 56; 
    	em[1876] = 1858; em[1877] = 64; 
    	em[1878] = 1927; em[1879] = 96; 
    em[1880] = 1; em[1881] = 8; em[1882] = 1; /* 1880: pointer.struct.bio_method_st */
    	em[1883] = 1885; em[1884] = 0; 
    em[1885] = 0; em[1886] = 80; em[1887] = 9; /* 1885: struct.bio_method_st */
    	em[1888] = 183; em[1889] = 8; 
    	em[1890] = 1906; em[1891] = 16; 
    	em[1892] = 1909; em[1893] = 24; 
    	em[1894] = 1912; em[1895] = 32; 
    	em[1896] = 1909; em[1897] = 40; 
    	em[1898] = 1915; em[1899] = 48; 
    	em[1900] = 1918; em[1901] = 56; 
    	em[1902] = 1918; em[1903] = 64; 
    	em[1904] = 1921; em[1905] = 72; 
    em[1906] = 8884097; em[1907] = 8; em[1908] = 0; /* 1906: pointer.func */
    em[1909] = 8884097; em[1910] = 8; em[1911] = 0; /* 1909: pointer.func */
    em[1912] = 8884097; em[1913] = 8; em[1914] = 0; /* 1912: pointer.func */
    em[1915] = 8884097; em[1916] = 8; em[1917] = 0; /* 1915: pointer.func */
    em[1918] = 8884097; em[1919] = 8; em[1920] = 0; /* 1918: pointer.func */
    em[1921] = 8884097; em[1922] = 8; em[1923] = 0; /* 1921: pointer.func */
    em[1924] = 8884097; em[1925] = 8; em[1926] = 0; /* 1924: pointer.func */
    em[1927] = 0; em[1928] = 32; em[1929] = 2; /* 1927: struct.crypto_ex_data_st_fake */
    	em[1930] = 1934; em[1931] = 8; 
    	em[1932] = 473; em[1933] = 24; 
    em[1934] = 8884099; em[1935] = 8; em[1936] = 2; /* 1934: pointer_to_array_of_pointers_to_stack */
    	em[1937] = 467; em[1938] = 0; 
    	em[1939] = 470; em[1940] = 20; 
    em[1941] = 1; em[1942] = 8; em[1943] = 1; /* 1941: pointer.struct.bio_st */
    	em[1944] = 1863; em[1945] = 0; 
    em[1946] = 0; em[1947] = 1; em[1948] = 0; /* 1946: char */
    args_addr->arg_entity_index[0] = 1941;
    args_addr->arg_entity_index[1] = 0;
    args_addr->arg_entity_index[2] = 1855;
    args_addr->arg_entity_index[3] = 467;
    args_addr->ret_entity_index = 5;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_arg(args_addr, arg_d);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    BIO * new_arg_a = *((BIO * *)new_args->args[0]);

    EVP_PKEY ** new_arg_b = *((EVP_PKEY ** *)new_args->args[1]);

    pem_password_cb * new_arg_c = *((pem_password_cb * *)new_args->args[2]);

    void * new_arg_d = *((void * *)new_args->args[3]);

    EVP_PKEY * *new_ret_ptr = (EVP_PKEY * *)new_args->ret;

    EVP_PKEY * (*orig_PEM_read_bio_PrivateKey)(BIO *,EVP_PKEY **,pem_password_cb *,void *);
    orig_PEM_read_bio_PrivateKey = dlsym(RTLD_NEXT, "PEM_read_bio_PrivateKey");
    *new_ret_ptr = (*orig_PEM_read_bio_PrivateKey)(new_arg_a,new_arg_b,new_arg_c,new_arg_d);

    syscall(889);

    free(args_addr);

    return ret;
}

