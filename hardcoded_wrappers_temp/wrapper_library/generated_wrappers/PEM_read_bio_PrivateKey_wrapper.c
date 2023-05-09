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
    	em[19] = 1473; em[20] = 48; 
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
    em[481] = 8884101; em[482] = 8; em[483] = 6; /* 481: union.union_of_evp_pkey_st */
    	em[484] = 467; em[485] = 0; 
    	em[486] = 496; em[487] = 6; 
    	em[488] = 707; em[489] = 116; 
    	em[490] = 838; em[491] = 28; 
    	em[492] = 964; em[493] = 408; 
    	em[494] = 470; em[495] = 0; 
    em[496] = 1; em[497] = 8; em[498] = 1; /* 496: pointer.struct.rsa_st */
    	em[499] = 501; em[500] = 0; 
    em[501] = 0; em[502] = 168; em[503] = 17; /* 501: struct.rsa_st */
    	em[504] = 538; em[505] = 16; 
    	em[506] = 593; em[507] = 24; 
    	em[508] = 598; em[509] = 32; 
    	em[510] = 598; em[511] = 40; 
    	em[512] = 598; em[513] = 48; 
    	em[514] = 598; em[515] = 56; 
    	em[516] = 598; em[517] = 64; 
    	em[518] = 598; em[519] = 72; 
    	em[520] = 598; em[521] = 80; 
    	em[522] = 598; em[523] = 88; 
    	em[524] = 618; em[525] = 96; 
    	em[526] = 632; em[527] = 120; 
    	em[528] = 632; em[529] = 128; 
    	em[530] = 632; em[531] = 136; 
    	em[532] = 77; em[533] = 144; 
    	em[534] = 646; em[535] = 152; 
    	em[536] = 646; em[537] = 160; 
    em[538] = 1; em[539] = 8; em[540] = 1; /* 538: pointer.struct.rsa_meth_st */
    	em[541] = 543; em[542] = 0; 
    em[543] = 0; em[544] = 112; em[545] = 13; /* 543: struct.rsa_meth_st */
    	em[546] = 183; em[547] = 0; 
    	em[548] = 572; em[549] = 8; 
    	em[550] = 572; em[551] = 16; 
    	em[552] = 572; em[553] = 24; 
    	em[554] = 572; em[555] = 32; 
    	em[556] = 575; em[557] = 40; 
    	em[558] = 578; em[559] = 48; 
    	em[560] = 581; em[561] = 56; 
    	em[562] = 581; em[563] = 64; 
    	em[564] = 77; em[565] = 80; 
    	em[566] = 584; em[567] = 88; 
    	em[568] = 587; em[569] = 96; 
    	em[570] = 590; em[571] = 104; 
    em[572] = 8884097; em[573] = 8; em[574] = 0; /* 572: pointer.func */
    em[575] = 8884097; em[576] = 8; em[577] = 0; /* 575: pointer.func */
    em[578] = 8884097; em[579] = 8; em[580] = 0; /* 578: pointer.func */
    em[581] = 8884097; em[582] = 8; em[583] = 0; /* 581: pointer.func */
    em[584] = 8884097; em[585] = 8; em[586] = 0; /* 584: pointer.func */
    em[587] = 8884097; em[588] = 8; em[589] = 0; /* 587: pointer.func */
    em[590] = 8884097; em[591] = 8; em[592] = 0; /* 590: pointer.func */
    em[593] = 1; em[594] = 8; em[595] = 1; /* 593: pointer.struct.engine_st */
    	em[596] = 132; em[597] = 0; 
    em[598] = 1; em[599] = 8; em[600] = 1; /* 598: pointer.struct.bignum_st */
    	em[601] = 603; em[602] = 0; 
    em[603] = 0; em[604] = 24; em[605] = 1; /* 603: struct.bignum_st */
    	em[606] = 608; em[607] = 0; 
    em[608] = 8884099; em[609] = 8; em[610] = 2; /* 608: pointer_to_array_of_pointers_to_stack */
    	em[611] = 615; em[612] = 0; 
    	em[613] = 470; em[614] = 12; 
    em[615] = 0; em[616] = 8; em[617] = 0; /* 615: long unsigned int */
    em[618] = 0; em[619] = 32; em[620] = 2; /* 618: struct.crypto_ex_data_st_fake */
    	em[621] = 625; em[622] = 8; 
    	em[623] = 473; em[624] = 24; 
    em[625] = 8884099; em[626] = 8; em[627] = 2; /* 625: pointer_to_array_of_pointers_to_stack */
    	em[628] = 467; em[629] = 0; 
    	em[630] = 470; em[631] = 20; 
    em[632] = 1; em[633] = 8; em[634] = 1; /* 632: pointer.struct.bn_mont_ctx_st */
    	em[635] = 637; em[636] = 0; 
    em[637] = 0; em[638] = 96; em[639] = 3; /* 637: struct.bn_mont_ctx_st */
    	em[640] = 603; em[641] = 8; 
    	em[642] = 603; em[643] = 32; 
    	em[644] = 603; em[645] = 56; 
    em[646] = 1; em[647] = 8; em[648] = 1; /* 646: pointer.struct.bn_blinding_st */
    	em[649] = 651; em[650] = 0; 
    em[651] = 0; em[652] = 88; em[653] = 7; /* 651: struct.bn_blinding_st */
    	em[654] = 668; em[655] = 0; 
    	em[656] = 668; em[657] = 8; 
    	em[658] = 668; em[659] = 16; 
    	em[660] = 668; em[661] = 24; 
    	em[662] = 685; em[663] = 40; 
    	em[664] = 690; em[665] = 72; 
    	em[666] = 704; em[667] = 80; 
    em[668] = 1; em[669] = 8; em[670] = 1; /* 668: pointer.struct.bignum_st */
    	em[671] = 673; em[672] = 0; 
    em[673] = 0; em[674] = 24; em[675] = 1; /* 673: struct.bignum_st */
    	em[676] = 678; em[677] = 0; 
    em[678] = 8884099; em[679] = 8; em[680] = 2; /* 678: pointer_to_array_of_pointers_to_stack */
    	em[681] = 615; em[682] = 0; 
    	em[683] = 470; em[684] = 12; 
    em[685] = 0; em[686] = 16; em[687] = 1; /* 685: struct.crypto_threadid_st */
    	em[688] = 467; em[689] = 0; 
    em[690] = 1; em[691] = 8; em[692] = 1; /* 690: pointer.struct.bn_mont_ctx_st */
    	em[693] = 695; em[694] = 0; 
    em[695] = 0; em[696] = 96; em[697] = 3; /* 695: struct.bn_mont_ctx_st */
    	em[698] = 673; em[699] = 8; 
    	em[700] = 673; em[701] = 32; 
    	em[702] = 673; em[703] = 56; 
    em[704] = 8884097; em[705] = 8; em[706] = 0; /* 704: pointer.func */
    em[707] = 1; em[708] = 8; em[709] = 1; /* 707: pointer.struct.dsa_st */
    	em[710] = 712; em[711] = 0; 
    em[712] = 0; em[713] = 136; em[714] = 11; /* 712: struct.dsa_st */
    	em[715] = 737; em[716] = 24; 
    	em[717] = 737; em[718] = 32; 
    	em[719] = 737; em[720] = 40; 
    	em[721] = 737; em[722] = 48; 
    	em[723] = 737; em[724] = 56; 
    	em[725] = 737; em[726] = 64; 
    	em[727] = 737; em[728] = 72; 
    	em[729] = 754; em[730] = 88; 
    	em[731] = 768; em[732] = 104; 
    	em[733] = 782; em[734] = 120; 
    	em[735] = 833; em[736] = 128; 
    em[737] = 1; em[738] = 8; em[739] = 1; /* 737: pointer.struct.bignum_st */
    	em[740] = 742; em[741] = 0; 
    em[742] = 0; em[743] = 24; em[744] = 1; /* 742: struct.bignum_st */
    	em[745] = 747; em[746] = 0; 
    em[747] = 8884099; em[748] = 8; em[749] = 2; /* 747: pointer_to_array_of_pointers_to_stack */
    	em[750] = 615; em[751] = 0; 
    	em[752] = 470; em[753] = 12; 
    em[754] = 1; em[755] = 8; em[756] = 1; /* 754: pointer.struct.bn_mont_ctx_st */
    	em[757] = 759; em[758] = 0; 
    em[759] = 0; em[760] = 96; em[761] = 3; /* 759: struct.bn_mont_ctx_st */
    	em[762] = 742; em[763] = 8; 
    	em[764] = 742; em[765] = 32; 
    	em[766] = 742; em[767] = 56; 
    em[768] = 0; em[769] = 32; em[770] = 2; /* 768: struct.crypto_ex_data_st_fake */
    	em[771] = 775; em[772] = 8; 
    	em[773] = 473; em[774] = 24; 
    em[775] = 8884099; em[776] = 8; em[777] = 2; /* 775: pointer_to_array_of_pointers_to_stack */
    	em[778] = 467; em[779] = 0; 
    	em[780] = 470; em[781] = 20; 
    em[782] = 1; em[783] = 8; em[784] = 1; /* 782: pointer.struct.dsa_method */
    	em[785] = 787; em[786] = 0; 
    em[787] = 0; em[788] = 96; em[789] = 11; /* 787: struct.dsa_method */
    	em[790] = 183; em[791] = 0; 
    	em[792] = 812; em[793] = 8; 
    	em[794] = 815; em[795] = 16; 
    	em[796] = 818; em[797] = 24; 
    	em[798] = 821; em[799] = 32; 
    	em[800] = 824; em[801] = 40; 
    	em[802] = 827; em[803] = 48; 
    	em[804] = 827; em[805] = 56; 
    	em[806] = 77; em[807] = 72; 
    	em[808] = 830; em[809] = 80; 
    	em[810] = 827; em[811] = 88; 
    em[812] = 8884097; em[813] = 8; em[814] = 0; /* 812: pointer.func */
    em[815] = 8884097; em[816] = 8; em[817] = 0; /* 815: pointer.func */
    em[818] = 8884097; em[819] = 8; em[820] = 0; /* 818: pointer.func */
    em[821] = 8884097; em[822] = 8; em[823] = 0; /* 821: pointer.func */
    em[824] = 8884097; em[825] = 8; em[826] = 0; /* 824: pointer.func */
    em[827] = 8884097; em[828] = 8; em[829] = 0; /* 827: pointer.func */
    em[830] = 8884097; em[831] = 8; em[832] = 0; /* 830: pointer.func */
    em[833] = 1; em[834] = 8; em[835] = 1; /* 833: pointer.struct.engine_st */
    	em[836] = 132; em[837] = 0; 
    em[838] = 1; em[839] = 8; em[840] = 1; /* 838: pointer.struct.dh_st */
    	em[841] = 843; em[842] = 0; 
    em[843] = 0; em[844] = 144; em[845] = 12; /* 843: struct.dh_st */
    	em[846] = 870; em[847] = 8; 
    	em[848] = 870; em[849] = 16; 
    	em[850] = 870; em[851] = 32; 
    	em[852] = 870; em[853] = 40; 
    	em[854] = 887; em[855] = 56; 
    	em[856] = 870; em[857] = 64; 
    	em[858] = 870; em[859] = 72; 
    	em[860] = 901; em[861] = 80; 
    	em[862] = 870; em[863] = 96; 
    	em[864] = 909; em[865] = 112; 
    	em[866] = 923; em[867] = 128; 
    	em[868] = 959; em[869] = 136; 
    em[870] = 1; em[871] = 8; em[872] = 1; /* 870: pointer.struct.bignum_st */
    	em[873] = 875; em[874] = 0; 
    em[875] = 0; em[876] = 24; em[877] = 1; /* 875: struct.bignum_st */
    	em[878] = 880; em[879] = 0; 
    em[880] = 8884099; em[881] = 8; em[882] = 2; /* 880: pointer_to_array_of_pointers_to_stack */
    	em[883] = 615; em[884] = 0; 
    	em[885] = 470; em[886] = 12; 
    em[887] = 1; em[888] = 8; em[889] = 1; /* 887: pointer.struct.bn_mont_ctx_st */
    	em[890] = 892; em[891] = 0; 
    em[892] = 0; em[893] = 96; em[894] = 3; /* 892: struct.bn_mont_ctx_st */
    	em[895] = 875; em[896] = 8; 
    	em[897] = 875; em[898] = 32; 
    	em[899] = 875; em[900] = 56; 
    em[901] = 1; em[902] = 8; em[903] = 1; /* 901: pointer.unsigned char */
    	em[904] = 906; em[905] = 0; 
    em[906] = 0; em[907] = 1; em[908] = 0; /* 906: unsigned char */
    em[909] = 0; em[910] = 32; em[911] = 2; /* 909: struct.crypto_ex_data_st_fake */
    	em[912] = 916; em[913] = 8; 
    	em[914] = 473; em[915] = 24; 
    em[916] = 8884099; em[917] = 8; em[918] = 2; /* 916: pointer_to_array_of_pointers_to_stack */
    	em[919] = 467; em[920] = 0; 
    	em[921] = 470; em[922] = 20; 
    em[923] = 1; em[924] = 8; em[925] = 1; /* 923: pointer.struct.dh_method */
    	em[926] = 928; em[927] = 0; 
    em[928] = 0; em[929] = 72; em[930] = 8; /* 928: struct.dh_method */
    	em[931] = 183; em[932] = 0; 
    	em[933] = 947; em[934] = 8; 
    	em[935] = 950; em[936] = 16; 
    	em[937] = 953; em[938] = 24; 
    	em[939] = 947; em[940] = 32; 
    	em[941] = 947; em[942] = 40; 
    	em[943] = 77; em[944] = 56; 
    	em[945] = 956; em[946] = 64; 
    em[947] = 8884097; em[948] = 8; em[949] = 0; /* 947: pointer.func */
    em[950] = 8884097; em[951] = 8; em[952] = 0; /* 950: pointer.func */
    em[953] = 8884097; em[954] = 8; em[955] = 0; /* 953: pointer.func */
    em[956] = 8884097; em[957] = 8; em[958] = 0; /* 956: pointer.func */
    em[959] = 1; em[960] = 8; em[961] = 1; /* 959: pointer.struct.engine_st */
    	em[962] = 132; em[963] = 0; 
    em[964] = 1; em[965] = 8; em[966] = 1; /* 964: pointer.struct.ec_key_st */
    	em[967] = 969; em[968] = 0; 
    em[969] = 0; em[970] = 56; em[971] = 4; /* 969: struct.ec_key_st */
    	em[972] = 980; em[973] = 8; 
    	em[974] = 1428; em[975] = 16; 
    	em[976] = 1433; em[977] = 24; 
    	em[978] = 1450; em[979] = 48; 
    em[980] = 1; em[981] = 8; em[982] = 1; /* 980: pointer.struct.ec_group_st */
    	em[983] = 985; em[984] = 0; 
    em[985] = 0; em[986] = 232; em[987] = 12; /* 985: struct.ec_group_st */
    	em[988] = 1012; em[989] = 0; 
    	em[990] = 1184; em[991] = 8; 
    	em[992] = 1384; em[993] = 16; 
    	em[994] = 1384; em[995] = 40; 
    	em[996] = 901; em[997] = 80; 
    	em[998] = 1396; em[999] = 96; 
    	em[1000] = 1384; em[1001] = 104; 
    	em[1002] = 1384; em[1003] = 152; 
    	em[1004] = 1384; em[1005] = 176; 
    	em[1006] = 467; em[1007] = 208; 
    	em[1008] = 467; em[1009] = 216; 
    	em[1010] = 1425; em[1011] = 224; 
    em[1012] = 1; em[1013] = 8; em[1014] = 1; /* 1012: pointer.struct.ec_method_st */
    	em[1015] = 1017; em[1016] = 0; 
    em[1017] = 0; em[1018] = 304; em[1019] = 37; /* 1017: struct.ec_method_st */
    	em[1020] = 1094; em[1021] = 8; 
    	em[1022] = 1097; em[1023] = 16; 
    	em[1024] = 1097; em[1025] = 24; 
    	em[1026] = 1100; em[1027] = 32; 
    	em[1028] = 1103; em[1029] = 40; 
    	em[1030] = 1106; em[1031] = 48; 
    	em[1032] = 1109; em[1033] = 56; 
    	em[1034] = 1112; em[1035] = 64; 
    	em[1036] = 1115; em[1037] = 72; 
    	em[1038] = 1118; em[1039] = 80; 
    	em[1040] = 1118; em[1041] = 88; 
    	em[1042] = 1121; em[1043] = 96; 
    	em[1044] = 1124; em[1045] = 104; 
    	em[1046] = 1127; em[1047] = 112; 
    	em[1048] = 1130; em[1049] = 120; 
    	em[1050] = 1133; em[1051] = 128; 
    	em[1052] = 1136; em[1053] = 136; 
    	em[1054] = 1139; em[1055] = 144; 
    	em[1056] = 1142; em[1057] = 152; 
    	em[1058] = 1145; em[1059] = 160; 
    	em[1060] = 1148; em[1061] = 168; 
    	em[1062] = 1151; em[1063] = 176; 
    	em[1064] = 1154; em[1065] = 184; 
    	em[1066] = 1157; em[1067] = 192; 
    	em[1068] = 1160; em[1069] = 200; 
    	em[1070] = 1163; em[1071] = 208; 
    	em[1072] = 1154; em[1073] = 216; 
    	em[1074] = 1166; em[1075] = 224; 
    	em[1076] = 1169; em[1077] = 232; 
    	em[1078] = 1172; em[1079] = 240; 
    	em[1080] = 1109; em[1081] = 248; 
    	em[1082] = 1175; em[1083] = 256; 
    	em[1084] = 1178; em[1085] = 264; 
    	em[1086] = 1175; em[1087] = 272; 
    	em[1088] = 1178; em[1089] = 280; 
    	em[1090] = 1178; em[1091] = 288; 
    	em[1092] = 1181; em[1093] = 296; 
    em[1094] = 8884097; em[1095] = 8; em[1096] = 0; /* 1094: pointer.func */
    em[1097] = 8884097; em[1098] = 8; em[1099] = 0; /* 1097: pointer.func */
    em[1100] = 8884097; em[1101] = 8; em[1102] = 0; /* 1100: pointer.func */
    em[1103] = 8884097; em[1104] = 8; em[1105] = 0; /* 1103: pointer.func */
    em[1106] = 8884097; em[1107] = 8; em[1108] = 0; /* 1106: pointer.func */
    em[1109] = 8884097; em[1110] = 8; em[1111] = 0; /* 1109: pointer.func */
    em[1112] = 8884097; em[1113] = 8; em[1114] = 0; /* 1112: pointer.func */
    em[1115] = 8884097; em[1116] = 8; em[1117] = 0; /* 1115: pointer.func */
    em[1118] = 8884097; em[1119] = 8; em[1120] = 0; /* 1118: pointer.func */
    em[1121] = 8884097; em[1122] = 8; em[1123] = 0; /* 1121: pointer.func */
    em[1124] = 8884097; em[1125] = 8; em[1126] = 0; /* 1124: pointer.func */
    em[1127] = 8884097; em[1128] = 8; em[1129] = 0; /* 1127: pointer.func */
    em[1130] = 8884097; em[1131] = 8; em[1132] = 0; /* 1130: pointer.func */
    em[1133] = 8884097; em[1134] = 8; em[1135] = 0; /* 1133: pointer.func */
    em[1136] = 8884097; em[1137] = 8; em[1138] = 0; /* 1136: pointer.func */
    em[1139] = 8884097; em[1140] = 8; em[1141] = 0; /* 1139: pointer.func */
    em[1142] = 8884097; em[1143] = 8; em[1144] = 0; /* 1142: pointer.func */
    em[1145] = 8884097; em[1146] = 8; em[1147] = 0; /* 1145: pointer.func */
    em[1148] = 8884097; em[1149] = 8; em[1150] = 0; /* 1148: pointer.func */
    em[1151] = 8884097; em[1152] = 8; em[1153] = 0; /* 1151: pointer.func */
    em[1154] = 8884097; em[1155] = 8; em[1156] = 0; /* 1154: pointer.func */
    em[1157] = 8884097; em[1158] = 8; em[1159] = 0; /* 1157: pointer.func */
    em[1160] = 8884097; em[1161] = 8; em[1162] = 0; /* 1160: pointer.func */
    em[1163] = 8884097; em[1164] = 8; em[1165] = 0; /* 1163: pointer.func */
    em[1166] = 8884097; em[1167] = 8; em[1168] = 0; /* 1166: pointer.func */
    em[1169] = 8884097; em[1170] = 8; em[1171] = 0; /* 1169: pointer.func */
    em[1172] = 8884097; em[1173] = 8; em[1174] = 0; /* 1172: pointer.func */
    em[1175] = 8884097; em[1176] = 8; em[1177] = 0; /* 1175: pointer.func */
    em[1178] = 8884097; em[1179] = 8; em[1180] = 0; /* 1178: pointer.func */
    em[1181] = 8884097; em[1182] = 8; em[1183] = 0; /* 1181: pointer.func */
    em[1184] = 1; em[1185] = 8; em[1186] = 1; /* 1184: pointer.struct.ec_point_st */
    	em[1187] = 1189; em[1188] = 0; 
    em[1189] = 0; em[1190] = 88; em[1191] = 4; /* 1189: struct.ec_point_st */
    	em[1192] = 1200; em[1193] = 0; 
    	em[1194] = 1372; em[1195] = 8; 
    	em[1196] = 1372; em[1197] = 32; 
    	em[1198] = 1372; em[1199] = 56; 
    em[1200] = 1; em[1201] = 8; em[1202] = 1; /* 1200: pointer.struct.ec_method_st */
    	em[1203] = 1205; em[1204] = 0; 
    em[1205] = 0; em[1206] = 304; em[1207] = 37; /* 1205: struct.ec_method_st */
    	em[1208] = 1282; em[1209] = 8; 
    	em[1210] = 1285; em[1211] = 16; 
    	em[1212] = 1285; em[1213] = 24; 
    	em[1214] = 1288; em[1215] = 32; 
    	em[1216] = 1291; em[1217] = 40; 
    	em[1218] = 1294; em[1219] = 48; 
    	em[1220] = 1297; em[1221] = 56; 
    	em[1222] = 1300; em[1223] = 64; 
    	em[1224] = 1303; em[1225] = 72; 
    	em[1226] = 1306; em[1227] = 80; 
    	em[1228] = 1306; em[1229] = 88; 
    	em[1230] = 1309; em[1231] = 96; 
    	em[1232] = 1312; em[1233] = 104; 
    	em[1234] = 1315; em[1235] = 112; 
    	em[1236] = 1318; em[1237] = 120; 
    	em[1238] = 1321; em[1239] = 128; 
    	em[1240] = 1324; em[1241] = 136; 
    	em[1242] = 1327; em[1243] = 144; 
    	em[1244] = 1330; em[1245] = 152; 
    	em[1246] = 1333; em[1247] = 160; 
    	em[1248] = 1336; em[1249] = 168; 
    	em[1250] = 1339; em[1251] = 176; 
    	em[1252] = 1342; em[1253] = 184; 
    	em[1254] = 1345; em[1255] = 192; 
    	em[1256] = 1348; em[1257] = 200; 
    	em[1258] = 1351; em[1259] = 208; 
    	em[1260] = 1342; em[1261] = 216; 
    	em[1262] = 1354; em[1263] = 224; 
    	em[1264] = 1357; em[1265] = 232; 
    	em[1266] = 1360; em[1267] = 240; 
    	em[1268] = 1297; em[1269] = 248; 
    	em[1270] = 1363; em[1271] = 256; 
    	em[1272] = 1366; em[1273] = 264; 
    	em[1274] = 1363; em[1275] = 272; 
    	em[1276] = 1366; em[1277] = 280; 
    	em[1278] = 1366; em[1279] = 288; 
    	em[1280] = 1369; em[1281] = 296; 
    em[1282] = 8884097; em[1283] = 8; em[1284] = 0; /* 1282: pointer.func */
    em[1285] = 8884097; em[1286] = 8; em[1287] = 0; /* 1285: pointer.func */
    em[1288] = 8884097; em[1289] = 8; em[1290] = 0; /* 1288: pointer.func */
    em[1291] = 8884097; em[1292] = 8; em[1293] = 0; /* 1291: pointer.func */
    em[1294] = 8884097; em[1295] = 8; em[1296] = 0; /* 1294: pointer.func */
    em[1297] = 8884097; em[1298] = 8; em[1299] = 0; /* 1297: pointer.func */
    em[1300] = 8884097; em[1301] = 8; em[1302] = 0; /* 1300: pointer.func */
    em[1303] = 8884097; em[1304] = 8; em[1305] = 0; /* 1303: pointer.func */
    em[1306] = 8884097; em[1307] = 8; em[1308] = 0; /* 1306: pointer.func */
    em[1309] = 8884097; em[1310] = 8; em[1311] = 0; /* 1309: pointer.func */
    em[1312] = 8884097; em[1313] = 8; em[1314] = 0; /* 1312: pointer.func */
    em[1315] = 8884097; em[1316] = 8; em[1317] = 0; /* 1315: pointer.func */
    em[1318] = 8884097; em[1319] = 8; em[1320] = 0; /* 1318: pointer.func */
    em[1321] = 8884097; em[1322] = 8; em[1323] = 0; /* 1321: pointer.func */
    em[1324] = 8884097; em[1325] = 8; em[1326] = 0; /* 1324: pointer.func */
    em[1327] = 8884097; em[1328] = 8; em[1329] = 0; /* 1327: pointer.func */
    em[1330] = 8884097; em[1331] = 8; em[1332] = 0; /* 1330: pointer.func */
    em[1333] = 8884097; em[1334] = 8; em[1335] = 0; /* 1333: pointer.func */
    em[1336] = 8884097; em[1337] = 8; em[1338] = 0; /* 1336: pointer.func */
    em[1339] = 8884097; em[1340] = 8; em[1341] = 0; /* 1339: pointer.func */
    em[1342] = 8884097; em[1343] = 8; em[1344] = 0; /* 1342: pointer.func */
    em[1345] = 8884097; em[1346] = 8; em[1347] = 0; /* 1345: pointer.func */
    em[1348] = 8884097; em[1349] = 8; em[1350] = 0; /* 1348: pointer.func */
    em[1351] = 8884097; em[1352] = 8; em[1353] = 0; /* 1351: pointer.func */
    em[1354] = 8884097; em[1355] = 8; em[1356] = 0; /* 1354: pointer.func */
    em[1357] = 8884097; em[1358] = 8; em[1359] = 0; /* 1357: pointer.func */
    em[1360] = 8884097; em[1361] = 8; em[1362] = 0; /* 1360: pointer.func */
    em[1363] = 8884097; em[1364] = 8; em[1365] = 0; /* 1363: pointer.func */
    em[1366] = 8884097; em[1367] = 8; em[1368] = 0; /* 1366: pointer.func */
    em[1369] = 8884097; em[1370] = 8; em[1371] = 0; /* 1369: pointer.func */
    em[1372] = 0; em[1373] = 24; em[1374] = 1; /* 1372: struct.bignum_st */
    	em[1375] = 1377; em[1376] = 0; 
    em[1377] = 8884099; em[1378] = 8; em[1379] = 2; /* 1377: pointer_to_array_of_pointers_to_stack */
    	em[1380] = 615; em[1381] = 0; 
    	em[1382] = 470; em[1383] = 12; 
    em[1384] = 0; em[1385] = 24; em[1386] = 1; /* 1384: struct.bignum_st */
    	em[1387] = 1389; em[1388] = 0; 
    em[1389] = 8884099; em[1390] = 8; em[1391] = 2; /* 1389: pointer_to_array_of_pointers_to_stack */
    	em[1392] = 615; em[1393] = 0; 
    	em[1394] = 470; em[1395] = 12; 
    em[1396] = 1; em[1397] = 8; em[1398] = 1; /* 1396: pointer.struct.ec_extra_data_st */
    	em[1399] = 1401; em[1400] = 0; 
    em[1401] = 0; em[1402] = 40; em[1403] = 5; /* 1401: struct.ec_extra_data_st */
    	em[1404] = 1414; em[1405] = 0; 
    	em[1406] = 467; em[1407] = 8; 
    	em[1408] = 1419; em[1409] = 16; 
    	em[1410] = 1422; em[1411] = 24; 
    	em[1412] = 1422; em[1413] = 32; 
    em[1414] = 1; em[1415] = 8; em[1416] = 1; /* 1414: pointer.struct.ec_extra_data_st */
    	em[1417] = 1401; em[1418] = 0; 
    em[1419] = 8884097; em[1420] = 8; em[1421] = 0; /* 1419: pointer.func */
    em[1422] = 8884097; em[1423] = 8; em[1424] = 0; /* 1422: pointer.func */
    em[1425] = 8884097; em[1426] = 8; em[1427] = 0; /* 1425: pointer.func */
    em[1428] = 1; em[1429] = 8; em[1430] = 1; /* 1428: pointer.struct.ec_point_st */
    	em[1431] = 1189; em[1432] = 0; 
    em[1433] = 1; em[1434] = 8; em[1435] = 1; /* 1433: pointer.struct.bignum_st */
    	em[1436] = 1438; em[1437] = 0; 
    em[1438] = 0; em[1439] = 24; em[1440] = 1; /* 1438: struct.bignum_st */
    	em[1441] = 1443; em[1442] = 0; 
    em[1443] = 8884099; em[1444] = 8; em[1445] = 2; /* 1443: pointer_to_array_of_pointers_to_stack */
    	em[1446] = 615; em[1447] = 0; 
    	em[1448] = 470; em[1449] = 12; 
    em[1450] = 1; em[1451] = 8; em[1452] = 1; /* 1450: pointer.struct.ec_extra_data_st */
    	em[1453] = 1455; em[1454] = 0; 
    em[1455] = 0; em[1456] = 40; em[1457] = 5; /* 1455: struct.ec_extra_data_st */
    	em[1458] = 1468; em[1459] = 0; 
    	em[1460] = 467; em[1461] = 8; 
    	em[1462] = 1419; em[1463] = 16; 
    	em[1464] = 1422; em[1465] = 24; 
    	em[1466] = 1422; em[1467] = 32; 
    em[1468] = 1; em[1469] = 8; em[1470] = 1; /* 1468: pointer.struct.ec_extra_data_st */
    	em[1471] = 1455; em[1472] = 0; 
    em[1473] = 1; em[1474] = 8; em[1475] = 1; /* 1473: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[1476] = 1478; em[1477] = 0; 
    em[1478] = 0; em[1479] = 32; em[1480] = 2; /* 1478: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[1481] = 1485; em[1482] = 8; 
    	em[1483] = 473; em[1484] = 24; 
    em[1485] = 8884099; em[1486] = 8; em[1487] = 2; /* 1485: pointer_to_array_of_pointers_to_stack */
    	em[1488] = 1492; em[1489] = 0; 
    	em[1490] = 470; em[1491] = 20; 
    em[1492] = 0; em[1493] = 8; em[1494] = 1; /* 1492: pointer.X509_ATTRIBUTE */
    	em[1495] = 1497; em[1496] = 0; 
    em[1497] = 0; em[1498] = 0; em[1499] = 1; /* 1497: X509_ATTRIBUTE */
    	em[1500] = 1502; em[1501] = 0; 
    em[1502] = 0; em[1503] = 24; em[1504] = 2; /* 1502: struct.x509_attributes_st */
    	em[1505] = 1509; em[1506] = 0; 
    	em[1507] = 1528; em[1508] = 16; 
    em[1509] = 1; em[1510] = 8; em[1511] = 1; /* 1509: pointer.struct.asn1_object_st */
    	em[1512] = 1514; em[1513] = 0; 
    em[1514] = 0; em[1515] = 40; em[1516] = 3; /* 1514: struct.asn1_object_st */
    	em[1517] = 183; em[1518] = 0; 
    	em[1519] = 183; em[1520] = 8; 
    	em[1521] = 1523; em[1522] = 24; 
    em[1523] = 1; em[1524] = 8; em[1525] = 1; /* 1523: pointer.unsigned char */
    	em[1526] = 906; em[1527] = 0; 
    em[1528] = 0; em[1529] = 8; em[1530] = 3; /* 1528: union.unknown */
    	em[1531] = 77; em[1532] = 0; 
    	em[1533] = 1537; em[1534] = 0; 
    	em[1535] = 1716; em[1536] = 0; 
    em[1537] = 1; em[1538] = 8; em[1539] = 1; /* 1537: pointer.struct.stack_st_ASN1_TYPE */
    	em[1540] = 1542; em[1541] = 0; 
    em[1542] = 0; em[1543] = 32; em[1544] = 2; /* 1542: struct.stack_st_fake_ASN1_TYPE */
    	em[1545] = 1549; em[1546] = 8; 
    	em[1547] = 473; em[1548] = 24; 
    em[1549] = 8884099; em[1550] = 8; em[1551] = 2; /* 1549: pointer_to_array_of_pointers_to_stack */
    	em[1552] = 1556; em[1553] = 0; 
    	em[1554] = 470; em[1555] = 20; 
    em[1556] = 0; em[1557] = 8; em[1558] = 1; /* 1556: pointer.ASN1_TYPE */
    	em[1559] = 1561; em[1560] = 0; 
    em[1561] = 0; em[1562] = 0; em[1563] = 1; /* 1561: ASN1_TYPE */
    	em[1564] = 1566; em[1565] = 0; 
    em[1566] = 0; em[1567] = 16; em[1568] = 1; /* 1566: struct.asn1_type_st */
    	em[1569] = 1571; em[1570] = 8; 
    em[1571] = 0; em[1572] = 8; em[1573] = 20; /* 1571: union.unknown */
    	em[1574] = 77; em[1575] = 0; 
    	em[1576] = 1614; em[1577] = 0; 
    	em[1578] = 1624; em[1579] = 0; 
    	em[1580] = 1638; em[1581] = 0; 
    	em[1582] = 1643; em[1583] = 0; 
    	em[1584] = 1648; em[1585] = 0; 
    	em[1586] = 1653; em[1587] = 0; 
    	em[1588] = 1658; em[1589] = 0; 
    	em[1590] = 1663; em[1591] = 0; 
    	em[1592] = 1668; em[1593] = 0; 
    	em[1594] = 1673; em[1595] = 0; 
    	em[1596] = 1678; em[1597] = 0; 
    	em[1598] = 1683; em[1599] = 0; 
    	em[1600] = 1688; em[1601] = 0; 
    	em[1602] = 1693; em[1603] = 0; 
    	em[1604] = 1698; em[1605] = 0; 
    	em[1606] = 1703; em[1607] = 0; 
    	em[1608] = 1614; em[1609] = 0; 
    	em[1610] = 1614; em[1611] = 0; 
    	em[1612] = 1708; em[1613] = 0; 
    em[1614] = 1; em[1615] = 8; em[1616] = 1; /* 1614: pointer.struct.asn1_string_st */
    	em[1617] = 1619; em[1618] = 0; 
    em[1619] = 0; em[1620] = 24; em[1621] = 1; /* 1619: struct.asn1_string_st */
    	em[1622] = 901; em[1623] = 8; 
    em[1624] = 1; em[1625] = 8; em[1626] = 1; /* 1624: pointer.struct.asn1_object_st */
    	em[1627] = 1629; em[1628] = 0; 
    em[1629] = 0; em[1630] = 40; em[1631] = 3; /* 1629: struct.asn1_object_st */
    	em[1632] = 183; em[1633] = 0; 
    	em[1634] = 183; em[1635] = 8; 
    	em[1636] = 1523; em[1637] = 24; 
    em[1638] = 1; em[1639] = 8; em[1640] = 1; /* 1638: pointer.struct.asn1_string_st */
    	em[1641] = 1619; em[1642] = 0; 
    em[1643] = 1; em[1644] = 8; em[1645] = 1; /* 1643: pointer.struct.asn1_string_st */
    	em[1646] = 1619; em[1647] = 0; 
    em[1648] = 1; em[1649] = 8; em[1650] = 1; /* 1648: pointer.struct.asn1_string_st */
    	em[1651] = 1619; em[1652] = 0; 
    em[1653] = 1; em[1654] = 8; em[1655] = 1; /* 1653: pointer.struct.asn1_string_st */
    	em[1656] = 1619; em[1657] = 0; 
    em[1658] = 1; em[1659] = 8; em[1660] = 1; /* 1658: pointer.struct.asn1_string_st */
    	em[1661] = 1619; em[1662] = 0; 
    em[1663] = 1; em[1664] = 8; em[1665] = 1; /* 1663: pointer.struct.asn1_string_st */
    	em[1666] = 1619; em[1667] = 0; 
    em[1668] = 1; em[1669] = 8; em[1670] = 1; /* 1668: pointer.struct.asn1_string_st */
    	em[1671] = 1619; em[1672] = 0; 
    em[1673] = 1; em[1674] = 8; em[1675] = 1; /* 1673: pointer.struct.asn1_string_st */
    	em[1676] = 1619; em[1677] = 0; 
    em[1678] = 1; em[1679] = 8; em[1680] = 1; /* 1678: pointer.struct.asn1_string_st */
    	em[1681] = 1619; em[1682] = 0; 
    em[1683] = 1; em[1684] = 8; em[1685] = 1; /* 1683: pointer.struct.asn1_string_st */
    	em[1686] = 1619; em[1687] = 0; 
    em[1688] = 1; em[1689] = 8; em[1690] = 1; /* 1688: pointer.struct.asn1_string_st */
    	em[1691] = 1619; em[1692] = 0; 
    em[1693] = 1; em[1694] = 8; em[1695] = 1; /* 1693: pointer.struct.asn1_string_st */
    	em[1696] = 1619; em[1697] = 0; 
    em[1698] = 1; em[1699] = 8; em[1700] = 1; /* 1698: pointer.struct.asn1_string_st */
    	em[1701] = 1619; em[1702] = 0; 
    em[1703] = 1; em[1704] = 8; em[1705] = 1; /* 1703: pointer.struct.asn1_string_st */
    	em[1706] = 1619; em[1707] = 0; 
    em[1708] = 1; em[1709] = 8; em[1710] = 1; /* 1708: pointer.struct.ASN1_VALUE_st */
    	em[1711] = 1713; em[1712] = 0; 
    em[1713] = 0; em[1714] = 0; em[1715] = 0; /* 1713: struct.ASN1_VALUE_st */
    em[1716] = 1; em[1717] = 8; em[1718] = 1; /* 1716: pointer.struct.asn1_type_st */
    	em[1719] = 1721; em[1720] = 0; 
    em[1721] = 0; em[1722] = 16; em[1723] = 1; /* 1721: struct.asn1_type_st */
    	em[1724] = 1726; em[1725] = 8; 
    em[1726] = 0; em[1727] = 8; em[1728] = 20; /* 1726: union.unknown */
    	em[1729] = 77; em[1730] = 0; 
    	em[1731] = 1769; em[1732] = 0; 
    	em[1733] = 1509; em[1734] = 0; 
    	em[1735] = 1779; em[1736] = 0; 
    	em[1737] = 1784; em[1738] = 0; 
    	em[1739] = 1789; em[1740] = 0; 
    	em[1741] = 1794; em[1742] = 0; 
    	em[1743] = 1799; em[1744] = 0; 
    	em[1745] = 1804; em[1746] = 0; 
    	em[1747] = 1809; em[1748] = 0; 
    	em[1749] = 1814; em[1750] = 0; 
    	em[1751] = 1819; em[1752] = 0; 
    	em[1753] = 1824; em[1754] = 0; 
    	em[1755] = 1829; em[1756] = 0; 
    	em[1757] = 1834; em[1758] = 0; 
    	em[1759] = 1839; em[1760] = 0; 
    	em[1761] = 1844; em[1762] = 0; 
    	em[1763] = 1769; em[1764] = 0; 
    	em[1765] = 1769; em[1766] = 0; 
    	em[1767] = 1849; em[1768] = 0; 
    em[1769] = 1; em[1770] = 8; em[1771] = 1; /* 1769: pointer.struct.asn1_string_st */
    	em[1772] = 1774; em[1773] = 0; 
    em[1774] = 0; em[1775] = 24; em[1776] = 1; /* 1774: struct.asn1_string_st */
    	em[1777] = 901; em[1778] = 8; 
    em[1779] = 1; em[1780] = 8; em[1781] = 1; /* 1779: pointer.struct.asn1_string_st */
    	em[1782] = 1774; em[1783] = 0; 
    em[1784] = 1; em[1785] = 8; em[1786] = 1; /* 1784: pointer.struct.asn1_string_st */
    	em[1787] = 1774; em[1788] = 0; 
    em[1789] = 1; em[1790] = 8; em[1791] = 1; /* 1789: pointer.struct.asn1_string_st */
    	em[1792] = 1774; em[1793] = 0; 
    em[1794] = 1; em[1795] = 8; em[1796] = 1; /* 1794: pointer.struct.asn1_string_st */
    	em[1797] = 1774; em[1798] = 0; 
    em[1799] = 1; em[1800] = 8; em[1801] = 1; /* 1799: pointer.struct.asn1_string_st */
    	em[1802] = 1774; em[1803] = 0; 
    em[1804] = 1; em[1805] = 8; em[1806] = 1; /* 1804: pointer.struct.asn1_string_st */
    	em[1807] = 1774; em[1808] = 0; 
    em[1809] = 1; em[1810] = 8; em[1811] = 1; /* 1809: pointer.struct.asn1_string_st */
    	em[1812] = 1774; em[1813] = 0; 
    em[1814] = 1; em[1815] = 8; em[1816] = 1; /* 1814: pointer.struct.asn1_string_st */
    	em[1817] = 1774; em[1818] = 0; 
    em[1819] = 1; em[1820] = 8; em[1821] = 1; /* 1819: pointer.struct.asn1_string_st */
    	em[1822] = 1774; em[1823] = 0; 
    em[1824] = 1; em[1825] = 8; em[1826] = 1; /* 1824: pointer.struct.asn1_string_st */
    	em[1827] = 1774; em[1828] = 0; 
    em[1829] = 1; em[1830] = 8; em[1831] = 1; /* 1829: pointer.struct.asn1_string_st */
    	em[1832] = 1774; em[1833] = 0; 
    em[1834] = 1; em[1835] = 8; em[1836] = 1; /* 1834: pointer.struct.asn1_string_st */
    	em[1837] = 1774; em[1838] = 0; 
    em[1839] = 1; em[1840] = 8; em[1841] = 1; /* 1839: pointer.struct.asn1_string_st */
    	em[1842] = 1774; em[1843] = 0; 
    em[1844] = 1; em[1845] = 8; em[1846] = 1; /* 1844: pointer.struct.asn1_string_st */
    	em[1847] = 1774; em[1848] = 0; 
    em[1849] = 1; em[1850] = 8; em[1851] = 1; /* 1849: pointer.struct.ASN1_VALUE_st */
    	em[1852] = 1854; em[1853] = 0; 
    em[1854] = 0; em[1855] = 0; em[1856] = 0; /* 1854: struct.ASN1_VALUE_st */
    em[1857] = 8884097; em[1858] = 8; em[1859] = 0; /* 1857: pointer.func */
    em[1860] = 1; em[1861] = 8; em[1862] = 1; /* 1860: pointer.struct.bio_st */
    	em[1863] = 1865; em[1864] = 0; 
    em[1865] = 0; em[1866] = 112; em[1867] = 7; /* 1865: struct.bio_st */
    	em[1868] = 1882; em[1869] = 0; 
    	em[1870] = 1926; em[1871] = 8; 
    	em[1872] = 77; em[1873] = 16; 
    	em[1874] = 467; em[1875] = 48; 
    	em[1876] = 1860; em[1877] = 56; 
    	em[1878] = 1860; em[1879] = 64; 
    	em[1880] = 1929; em[1881] = 96; 
    em[1882] = 1; em[1883] = 8; em[1884] = 1; /* 1882: pointer.struct.bio_method_st */
    	em[1885] = 1887; em[1886] = 0; 
    em[1887] = 0; em[1888] = 80; em[1889] = 9; /* 1887: struct.bio_method_st */
    	em[1890] = 183; em[1891] = 8; 
    	em[1892] = 1908; em[1893] = 16; 
    	em[1894] = 1911; em[1895] = 24; 
    	em[1896] = 1914; em[1897] = 32; 
    	em[1898] = 1911; em[1899] = 40; 
    	em[1900] = 1917; em[1901] = 48; 
    	em[1902] = 1920; em[1903] = 56; 
    	em[1904] = 1920; em[1905] = 64; 
    	em[1906] = 1923; em[1907] = 72; 
    em[1908] = 8884097; em[1909] = 8; em[1910] = 0; /* 1908: pointer.func */
    em[1911] = 8884097; em[1912] = 8; em[1913] = 0; /* 1911: pointer.func */
    em[1914] = 8884097; em[1915] = 8; em[1916] = 0; /* 1914: pointer.func */
    em[1917] = 8884097; em[1918] = 8; em[1919] = 0; /* 1917: pointer.func */
    em[1920] = 8884097; em[1921] = 8; em[1922] = 0; /* 1920: pointer.func */
    em[1923] = 8884097; em[1924] = 8; em[1925] = 0; /* 1923: pointer.func */
    em[1926] = 8884097; em[1927] = 8; em[1928] = 0; /* 1926: pointer.func */
    em[1929] = 0; em[1930] = 32; em[1931] = 2; /* 1929: struct.crypto_ex_data_st_fake */
    	em[1932] = 1936; em[1933] = 8; 
    	em[1934] = 473; em[1935] = 24; 
    em[1936] = 8884099; em[1937] = 8; em[1938] = 2; /* 1936: pointer_to_array_of_pointers_to_stack */
    	em[1939] = 467; em[1940] = 0; 
    	em[1941] = 470; em[1942] = 20; 
    em[1943] = 1; em[1944] = 8; em[1945] = 1; /* 1943: pointer.struct.bio_st */
    	em[1946] = 1865; em[1947] = 0; 
    em[1948] = 0; em[1949] = 1; em[1950] = 0; /* 1948: char */
    args_addr->arg_entity_index[0] = 1943;
    args_addr->arg_entity_index[1] = 0;
    args_addr->arg_entity_index[2] = 1857;
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

