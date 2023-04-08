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
    	em[19] = 1253; em[20] = 48; 
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
    	em[492] = 928; em[493] = 408; 
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
    	em[846] = 598; em[847] = 8; 
    	em[848] = 598; em[849] = 16; 
    	em[850] = 598; em[851] = 32; 
    	em[852] = 598; em[853] = 40; 
    	em[854] = 632; em[855] = 56; 
    	em[856] = 598; em[857] = 64; 
    	em[858] = 598; em[859] = 72; 
    	em[860] = 870; em[861] = 80; 
    	em[862] = 598; em[863] = 96; 
    	em[864] = 878; em[865] = 112; 
    	em[866] = 892; em[867] = 128; 
    	em[868] = 593; em[869] = 136; 
    em[870] = 1; em[871] = 8; em[872] = 1; /* 870: pointer.unsigned char */
    	em[873] = 875; em[874] = 0; 
    em[875] = 0; em[876] = 1; em[877] = 0; /* 875: unsigned char */
    em[878] = 0; em[879] = 32; em[880] = 2; /* 878: struct.crypto_ex_data_st_fake */
    	em[881] = 885; em[882] = 8; 
    	em[883] = 473; em[884] = 24; 
    em[885] = 8884099; em[886] = 8; em[887] = 2; /* 885: pointer_to_array_of_pointers_to_stack */
    	em[888] = 467; em[889] = 0; 
    	em[890] = 470; em[891] = 20; 
    em[892] = 1; em[893] = 8; em[894] = 1; /* 892: pointer.struct.dh_method */
    	em[895] = 897; em[896] = 0; 
    em[897] = 0; em[898] = 72; em[899] = 8; /* 897: struct.dh_method */
    	em[900] = 183; em[901] = 0; 
    	em[902] = 916; em[903] = 8; 
    	em[904] = 919; em[905] = 16; 
    	em[906] = 922; em[907] = 24; 
    	em[908] = 916; em[909] = 32; 
    	em[910] = 916; em[911] = 40; 
    	em[912] = 77; em[913] = 56; 
    	em[914] = 925; em[915] = 64; 
    em[916] = 8884097; em[917] = 8; em[918] = 0; /* 916: pointer.func */
    em[919] = 8884097; em[920] = 8; em[921] = 0; /* 919: pointer.func */
    em[922] = 8884097; em[923] = 8; em[924] = 0; /* 922: pointer.func */
    em[925] = 8884097; em[926] = 8; em[927] = 0; /* 925: pointer.func */
    em[928] = 1; em[929] = 8; em[930] = 1; /* 928: pointer.struct.ec_key_st */
    	em[931] = 933; em[932] = 0; 
    em[933] = 0; em[934] = 56; em[935] = 4; /* 933: struct.ec_key_st */
    	em[936] = 944; em[937] = 8; 
    	em[938] = 1208; em[939] = 16; 
    	em[940] = 1213; em[941] = 24; 
    	em[942] = 1230; em[943] = 48; 
    em[944] = 1; em[945] = 8; em[946] = 1; /* 944: pointer.struct.ec_group_st */
    	em[947] = 949; em[948] = 0; 
    em[949] = 0; em[950] = 232; em[951] = 12; /* 949: struct.ec_group_st */
    	em[952] = 976; em[953] = 0; 
    	em[954] = 1148; em[955] = 8; 
    	em[956] = 1164; em[957] = 16; 
    	em[958] = 1164; em[959] = 40; 
    	em[960] = 870; em[961] = 80; 
    	em[962] = 1176; em[963] = 96; 
    	em[964] = 1164; em[965] = 104; 
    	em[966] = 1164; em[967] = 152; 
    	em[968] = 1164; em[969] = 176; 
    	em[970] = 467; em[971] = 208; 
    	em[972] = 467; em[973] = 216; 
    	em[974] = 1205; em[975] = 224; 
    em[976] = 1; em[977] = 8; em[978] = 1; /* 976: pointer.struct.ec_method_st */
    	em[979] = 981; em[980] = 0; 
    em[981] = 0; em[982] = 304; em[983] = 37; /* 981: struct.ec_method_st */
    	em[984] = 1058; em[985] = 8; 
    	em[986] = 1061; em[987] = 16; 
    	em[988] = 1061; em[989] = 24; 
    	em[990] = 1064; em[991] = 32; 
    	em[992] = 1067; em[993] = 40; 
    	em[994] = 1070; em[995] = 48; 
    	em[996] = 1073; em[997] = 56; 
    	em[998] = 1076; em[999] = 64; 
    	em[1000] = 1079; em[1001] = 72; 
    	em[1002] = 1082; em[1003] = 80; 
    	em[1004] = 1082; em[1005] = 88; 
    	em[1006] = 1085; em[1007] = 96; 
    	em[1008] = 1088; em[1009] = 104; 
    	em[1010] = 1091; em[1011] = 112; 
    	em[1012] = 1094; em[1013] = 120; 
    	em[1014] = 1097; em[1015] = 128; 
    	em[1016] = 1100; em[1017] = 136; 
    	em[1018] = 1103; em[1019] = 144; 
    	em[1020] = 1106; em[1021] = 152; 
    	em[1022] = 1109; em[1023] = 160; 
    	em[1024] = 1112; em[1025] = 168; 
    	em[1026] = 1115; em[1027] = 176; 
    	em[1028] = 1118; em[1029] = 184; 
    	em[1030] = 1121; em[1031] = 192; 
    	em[1032] = 1124; em[1033] = 200; 
    	em[1034] = 1127; em[1035] = 208; 
    	em[1036] = 1118; em[1037] = 216; 
    	em[1038] = 1130; em[1039] = 224; 
    	em[1040] = 1133; em[1041] = 232; 
    	em[1042] = 1136; em[1043] = 240; 
    	em[1044] = 1073; em[1045] = 248; 
    	em[1046] = 1139; em[1047] = 256; 
    	em[1048] = 1142; em[1049] = 264; 
    	em[1050] = 1139; em[1051] = 272; 
    	em[1052] = 1142; em[1053] = 280; 
    	em[1054] = 1142; em[1055] = 288; 
    	em[1056] = 1145; em[1057] = 296; 
    em[1058] = 8884097; em[1059] = 8; em[1060] = 0; /* 1058: pointer.func */
    em[1061] = 8884097; em[1062] = 8; em[1063] = 0; /* 1061: pointer.func */
    em[1064] = 8884097; em[1065] = 8; em[1066] = 0; /* 1064: pointer.func */
    em[1067] = 8884097; em[1068] = 8; em[1069] = 0; /* 1067: pointer.func */
    em[1070] = 8884097; em[1071] = 8; em[1072] = 0; /* 1070: pointer.func */
    em[1073] = 8884097; em[1074] = 8; em[1075] = 0; /* 1073: pointer.func */
    em[1076] = 8884097; em[1077] = 8; em[1078] = 0; /* 1076: pointer.func */
    em[1079] = 8884097; em[1080] = 8; em[1081] = 0; /* 1079: pointer.func */
    em[1082] = 8884097; em[1083] = 8; em[1084] = 0; /* 1082: pointer.func */
    em[1085] = 8884097; em[1086] = 8; em[1087] = 0; /* 1085: pointer.func */
    em[1088] = 8884097; em[1089] = 8; em[1090] = 0; /* 1088: pointer.func */
    em[1091] = 8884097; em[1092] = 8; em[1093] = 0; /* 1091: pointer.func */
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
    em[1148] = 1; em[1149] = 8; em[1150] = 1; /* 1148: pointer.struct.ec_point_st */
    	em[1151] = 1153; em[1152] = 0; 
    em[1153] = 0; em[1154] = 88; em[1155] = 4; /* 1153: struct.ec_point_st */
    	em[1156] = 976; em[1157] = 0; 
    	em[1158] = 1164; em[1159] = 8; 
    	em[1160] = 1164; em[1161] = 32; 
    	em[1162] = 1164; em[1163] = 56; 
    em[1164] = 0; em[1165] = 24; em[1166] = 1; /* 1164: struct.bignum_st */
    	em[1167] = 1169; em[1168] = 0; 
    em[1169] = 8884099; em[1170] = 8; em[1171] = 2; /* 1169: pointer_to_array_of_pointers_to_stack */
    	em[1172] = 615; em[1173] = 0; 
    	em[1174] = 470; em[1175] = 12; 
    em[1176] = 1; em[1177] = 8; em[1178] = 1; /* 1176: pointer.struct.ec_extra_data_st */
    	em[1179] = 1181; em[1180] = 0; 
    em[1181] = 0; em[1182] = 40; em[1183] = 5; /* 1181: struct.ec_extra_data_st */
    	em[1184] = 1194; em[1185] = 0; 
    	em[1186] = 467; em[1187] = 8; 
    	em[1188] = 1199; em[1189] = 16; 
    	em[1190] = 1202; em[1191] = 24; 
    	em[1192] = 1202; em[1193] = 32; 
    em[1194] = 1; em[1195] = 8; em[1196] = 1; /* 1194: pointer.struct.ec_extra_data_st */
    	em[1197] = 1181; em[1198] = 0; 
    em[1199] = 8884097; em[1200] = 8; em[1201] = 0; /* 1199: pointer.func */
    em[1202] = 8884097; em[1203] = 8; em[1204] = 0; /* 1202: pointer.func */
    em[1205] = 8884097; em[1206] = 8; em[1207] = 0; /* 1205: pointer.func */
    em[1208] = 1; em[1209] = 8; em[1210] = 1; /* 1208: pointer.struct.ec_point_st */
    	em[1211] = 1153; em[1212] = 0; 
    em[1213] = 1; em[1214] = 8; em[1215] = 1; /* 1213: pointer.struct.bignum_st */
    	em[1216] = 1218; em[1217] = 0; 
    em[1218] = 0; em[1219] = 24; em[1220] = 1; /* 1218: struct.bignum_st */
    	em[1221] = 1223; em[1222] = 0; 
    em[1223] = 8884099; em[1224] = 8; em[1225] = 2; /* 1223: pointer_to_array_of_pointers_to_stack */
    	em[1226] = 615; em[1227] = 0; 
    	em[1228] = 470; em[1229] = 12; 
    em[1230] = 1; em[1231] = 8; em[1232] = 1; /* 1230: pointer.struct.ec_extra_data_st */
    	em[1233] = 1235; em[1234] = 0; 
    em[1235] = 0; em[1236] = 40; em[1237] = 5; /* 1235: struct.ec_extra_data_st */
    	em[1238] = 1248; em[1239] = 0; 
    	em[1240] = 467; em[1241] = 8; 
    	em[1242] = 1199; em[1243] = 16; 
    	em[1244] = 1202; em[1245] = 24; 
    	em[1246] = 1202; em[1247] = 32; 
    em[1248] = 1; em[1249] = 8; em[1250] = 1; /* 1248: pointer.struct.ec_extra_data_st */
    	em[1251] = 1235; em[1252] = 0; 
    em[1253] = 1; em[1254] = 8; em[1255] = 1; /* 1253: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[1256] = 1258; em[1257] = 0; 
    em[1258] = 0; em[1259] = 32; em[1260] = 2; /* 1258: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[1261] = 1265; em[1262] = 8; 
    	em[1263] = 473; em[1264] = 24; 
    em[1265] = 8884099; em[1266] = 8; em[1267] = 2; /* 1265: pointer_to_array_of_pointers_to_stack */
    	em[1268] = 1272; em[1269] = 0; 
    	em[1270] = 470; em[1271] = 20; 
    em[1272] = 0; em[1273] = 8; em[1274] = 1; /* 1272: pointer.X509_ATTRIBUTE */
    	em[1275] = 1277; em[1276] = 0; 
    em[1277] = 0; em[1278] = 0; em[1279] = 1; /* 1277: X509_ATTRIBUTE */
    	em[1280] = 1282; em[1281] = 0; 
    em[1282] = 0; em[1283] = 24; em[1284] = 2; /* 1282: struct.x509_attributes_st */
    	em[1285] = 1289; em[1286] = 0; 
    	em[1287] = 1308; em[1288] = 16; 
    em[1289] = 1; em[1290] = 8; em[1291] = 1; /* 1289: pointer.struct.asn1_object_st */
    	em[1292] = 1294; em[1293] = 0; 
    em[1294] = 0; em[1295] = 40; em[1296] = 3; /* 1294: struct.asn1_object_st */
    	em[1297] = 183; em[1298] = 0; 
    	em[1299] = 183; em[1300] = 8; 
    	em[1301] = 1303; em[1302] = 24; 
    em[1303] = 1; em[1304] = 8; em[1305] = 1; /* 1303: pointer.unsigned char */
    	em[1306] = 875; em[1307] = 0; 
    em[1308] = 0; em[1309] = 8; em[1310] = 3; /* 1308: union.unknown */
    	em[1311] = 77; em[1312] = 0; 
    	em[1313] = 1317; em[1314] = 0; 
    	em[1315] = 1496; em[1316] = 0; 
    em[1317] = 1; em[1318] = 8; em[1319] = 1; /* 1317: pointer.struct.stack_st_ASN1_TYPE */
    	em[1320] = 1322; em[1321] = 0; 
    em[1322] = 0; em[1323] = 32; em[1324] = 2; /* 1322: struct.stack_st_fake_ASN1_TYPE */
    	em[1325] = 1329; em[1326] = 8; 
    	em[1327] = 473; em[1328] = 24; 
    em[1329] = 8884099; em[1330] = 8; em[1331] = 2; /* 1329: pointer_to_array_of_pointers_to_stack */
    	em[1332] = 1336; em[1333] = 0; 
    	em[1334] = 470; em[1335] = 20; 
    em[1336] = 0; em[1337] = 8; em[1338] = 1; /* 1336: pointer.ASN1_TYPE */
    	em[1339] = 1341; em[1340] = 0; 
    em[1341] = 0; em[1342] = 0; em[1343] = 1; /* 1341: ASN1_TYPE */
    	em[1344] = 1346; em[1345] = 0; 
    em[1346] = 0; em[1347] = 16; em[1348] = 1; /* 1346: struct.asn1_type_st */
    	em[1349] = 1351; em[1350] = 8; 
    em[1351] = 0; em[1352] = 8; em[1353] = 20; /* 1351: union.unknown */
    	em[1354] = 77; em[1355] = 0; 
    	em[1356] = 1394; em[1357] = 0; 
    	em[1358] = 1404; em[1359] = 0; 
    	em[1360] = 1418; em[1361] = 0; 
    	em[1362] = 1423; em[1363] = 0; 
    	em[1364] = 1428; em[1365] = 0; 
    	em[1366] = 1433; em[1367] = 0; 
    	em[1368] = 1438; em[1369] = 0; 
    	em[1370] = 1443; em[1371] = 0; 
    	em[1372] = 1448; em[1373] = 0; 
    	em[1374] = 1453; em[1375] = 0; 
    	em[1376] = 1458; em[1377] = 0; 
    	em[1378] = 1463; em[1379] = 0; 
    	em[1380] = 1468; em[1381] = 0; 
    	em[1382] = 1473; em[1383] = 0; 
    	em[1384] = 1478; em[1385] = 0; 
    	em[1386] = 1483; em[1387] = 0; 
    	em[1388] = 1394; em[1389] = 0; 
    	em[1390] = 1394; em[1391] = 0; 
    	em[1392] = 1488; em[1393] = 0; 
    em[1394] = 1; em[1395] = 8; em[1396] = 1; /* 1394: pointer.struct.asn1_string_st */
    	em[1397] = 1399; em[1398] = 0; 
    em[1399] = 0; em[1400] = 24; em[1401] = 1; /* 1399: struct.asn1_string_st */
    	em[1402] = 870; em[1403] = 8; 
    em[1404] = 1; em[1405] = 8; em[1406] = 1; /* 1404: pointer.struct.asn1_object_st */
    	em[1407] = 1409; em[1408] = 0; 
    em[1409] = 0; em[1410] = 40; em[1411] = 3; /* 1409: struct.asn1_object_st */
    	em[1412] = 183; em[1413] = 0; 
    	em[1414] = 183; em[1415] = 8; 
    	em[1416] = 1303; em[1417] = 24; 
    em[1418] = 1; em[1419] = 8; em[1420] = 1; /* 1418: pointer.struct.asn1_string_st */
    	em[1421] = 1399; em[1422] = 0; 
    em[1423] = 1; em[1424] = 8; em[1425] = 1; /* 1423: pointer.struct.asn1_string_st */
    	em[1426] = 1399; em[1427] = 0; 
    em[1428] = 1; em[1429] = 8; em[1430] = 1; /* 1428: pointer.struct.asn1_string_st */
    	em[1431] = 1399; em[1432] = 0; 
    em[1433] = 1; em[1434] = 8; em[1435] = 1; /* 1433: pointer.struct.asn1_string_st */
    	em[1436] = 1399; em[1437] = 0; 
    em[1438] = 1; em[1439] = 8; em[1440] = 1; /* 1438: pointer.struct.asn1_string_st */
    	em[1441] = 1399; em[1442] = 0; 
    em[1443] = 1; em[1444] = 8; em[1445] = 1; /* 1443: pointer.struct.asn1_string_st */
    	em[1446] = 1399; em[1447] = 0; 
    em[1448] = 1; em[1449] = 8; em[1450] = 1; /* 1448: pointer.struct.asn1_string_st */
    	em[1451] = 1399; em[1452] = 0; 
    em[1453] = 1; em[1454] = 8; em[1455] = 1; /* 1453: pointer.struct.asn1_string_st */
    	em[1456] = 1399; em[1457] = 0; 
    em[1458] = 1; em[1459] = 8; em[1460] = 1; /* 1458: pointer.struct.asn1_string_st */
    	em[1461] = 1399; em[1462] = 0; 
    em[1463] = 1; em[1464] = 8; em[1465] = 1; /* 1463: pointer.struct.asn1_string_st */
    	em[1466] = 1399; em[1467] = 0; 
    em[1468] = 1; em[1469] = 8; em[1470] = 1; /* 1468: pointer.struct.asn1_string_st */
    	em[1471] = 1399; em[1472] = 0; 
    em[1473] = 1; em[1474] = 8; em[1475] = 1; /* 1473: pointer.struct.asn1_string_st */
    	em[1476] = 1399; em[1477] = 0; 
    em[1478] = 1; em[1479] = 8; em[1480] = 1; /* 1478: pointer.struct.asn1_string_st */
    	em[1481] = 1399; em[1482] = 0; 
    em[1483] = 1; em[1484] = 8; em[1485] = 1; /* 1483: pointer.struct.asn1_string_st */
    	em[1486] = 1399; em[1487] = 0; 
    em[1488] = 1; em[1489] = 8; em[1490] = 1; /* 1488: pointer.struct.ASN1_VALUE_st */
    	em[1491] = 1493; em[1492] = 0; 
    em[1493] = 0; em[1494] = 0; em[1495] = 0; /* 1493: struct.ASN1_VALUE_st */
    em[1496] = 1; em[1497] = 8; em[1498] = 1; /* 1496: pointer.struct.asn1_type_st */
    	em[1499] = 1501; em[1500] = 0; 
    em[1501] = 0; em[1502] = 16; em[1503] = 1; /* 1501: struct.asn1_type_st */
    	em[1504] = 1506; em[1505] = 8; 
    em[1506] = 0; em[1507] = 8; em[1508] = 20; /* 1506: union.unknown */
    	em[1509] = 77; em[1510] = 0; 
    	em[1511] = 1549; em[1512] = 0; 
    	em[1513] = 1289; em[1514] = 0; 
    	em[1515] = 1559; em[1516] = 0; 
    	em[1517] = 1564; em[1518] = 0; 
    	em[1519] = 1569; em[1520] = 0; 
    	em[1521] = 1574; em[1522] = 0; 
    	em[1523] = 1579; em[1524] = 0; 
    	em[1525] = 1584; em[1526] = 0; 
    	em[1527] = 1589; em[1528] = 0; 
    	em[1529] = 1594; em[1530] = 0; 
    	em[1531] = 1599; em[1532] = 0; 
    	em[1533] = 1604; em[1534] = 0; 
    	em[1535] = 1609; em[1536] = 0; 
    	em[1537] = 1614; em[1538] = 0; 
    	em[1539] = 1619; em[1540] = 0; 
    	em[1541] = 1624; em[1542] = 0; 
    	em[1543] = 1549; em[1544] = 0; 
    	em[1545] = 1549; em[1546] = 0; 
    	em[1547] = 1629; em[1548] = 0; 
    em[1549] = 1; em[1550] = 8; em[1551] = 1; /* 1549: pointer.struct.asn1_string_st */
    	em[1552] = 1554; em[1553] = 0; 
    em[1554] = 0; em[1555] = 24; em[1556] = 1; /* 1554: struct.asn1_string_st */
    	em[1557] = 870; em[1558] = 8; 
    em[1559] = 1; em[1560] = 8; em[1561] = 1; /* 1559: pointer.struct.asn1_string_st */
    	em[1562] = 1554; em[1563] = 0; 
    em[1564] = 1; em[1565] = 8; em[1566] = 1; /* 1564: pointer.struct.asn1_string_st */
    	em[1567] = 1554; em[1568] = 0; 
    em[1569] = 1; em[1570] = 8; em[1571] = 1; /* 1569: pointer.struct.asn1_string_st */
    	em[1572] = 1554; em[1573] = 0; 
    em[1574] = 1; em[1575] = 8; em[1576] = 1; /* 1574: pointer.struct.asn1_string_st */
    	em[1577] = 1554; em[1578] = 0; 
    em[1579] = 1; em[1580] = 8; em[1581] = 1; /* 1579: pointer.struct.asn1_string_st */
    	em[1582] = 1554; em[1583] = 0; 
    em[1584] = 1; em[1585] = 8; em[1586] = 1; /* 1584: pointer.struct.asn1_string_st */
    	em[1587] = 1554; em[1588] = 0; 
    em[1589] = 1; em[1590] = 8; em[1591] = 1; /* 1589: pointer.struct.asn1_string_st */
    	em[1592] = 1554; em[1593] = 0; 
    em[1594] = 1; em[1595] = 8; em[1596] = 1; /* 1594: pointer.struct.asn1_string_st */
    	em[1597] = 1554; em[1598] = 0; 
    em[1599] = 1; em[1600] = 8; em[1601] = 1; /* 1599: pointer.struct.asn1_string_st */
    	em[1602] = 1554; em[1603] = 0; 
    em[1604] = 1; em[1605] = 8; em[1606] = 1; /* 1604: pointer.struct.asn1_string_st */
    	em[1607] = 1554; em[1608] = 0; 
    em[1609] = 1; em[1610] = 8; em[1611] = 1; /* 1609: pointer.struct.asn1_string_st */
    	em[1612] = 1554; em[1613] = 0; 
    em[1614] = 1; em[1615] = 8; em[1616] = 1; /* 1614: pointer.struct.asn1_string_st */
    	em[1617] = 1554; em[1618] = 0; 
    em[1619] = 1; em[1620] = 8; em[1621] = 1; /* 1619: pointer.struct.asn1_string_st */
    	em[1622] = 1554; em[1623] = 0; 
    em[1624] = 1; em[1625] = 8; em[1626] = 1; /* 1624: pointer.struct.asn1_string_st */
    	em[1627] = 1554; em[1628] = 0; 
    em[1629] = 1; em[1630] = 8; em[1631] = 1; /* 1629: pointer.struct.ASN1_VALUE_st */
    	em[1632] = 1634; em[1633] = 0; 
    em[1634] = 0; em[1635] = 0; em[1636] = 0; /* 1634: struct.ASN1_VALUE_st */
    em[1637] = 1; em[1638] = 8; em[1639] = 1; /* 1637: pointer.struct.bio_st */
    	em[1640] = 1642; em[1641] = 0; 
    em[1642] = 0; em[1643] = 112; em[1644] = 7; /* 1642: struct.bio_st */
    	em[1645] = 1659; em[1646] = 0; 
    	em[1647] = 1703; em[1648] = 8; 
    	em[1649] = 77; em[1650] = 16; 
    	em[1651] = 467; em[1652] = 48; 
    	em[1653] = 1637; em[1654] = 56; 
    	em[1655] = 1637; em[1656] = 64; 
    	em[1657] = 1706; em[1658] = 96; 
    em[1659] = 1; em[1660] = 8; em[1661] = 1; /* 1659: pointer.struct.bio_method_st */
    	em[1662] = 1664; em[1663] = 0; 
    em[1664] = 0; em[1665] = 80; em[1666] = 9; /* 1664: struct.bio_method_st */
    	em[1667] = 183; em[1668] = 8; 
    	em[1669] = 1685; em[1670] = 16; 
    	em[1671] = 1688; em[1672] = 24; 
    	em[1673] = 1691; em[1674] = 32; 
    	em[1675] = 1688; em[1676] = 40; 
    	em[1677] = 1694; em[1678] = 48; 
    	em[1679] = 1697; em[1680] = 56; 
    	em[1681] = 1697; em[1682] = 64; 
    	em[1683] = 1700; em[1684] = 72; 
    em[1685] = 8884097; em[1686] = 8; em[1687] = 0; /* 1685: pointer.func */
    em[1688] = 8884097; em[1689] = 8; em[1690] = 0; /* 1688: pointer.func */
    em[1691] = 8884097; em[1692] = 8; em[1693] = 0; /* 1691: pointer.func */
    em[1694] = 8884097; em[1695] = 8; em[1696] = 0; /* 1694: pointer.func */
    em[1697] = 8884097; em[1698] = 8; em[1699] = 0; /* 1697: pointer.func */
    em[1700] = 8884097; em[1701] = 8; em[1702] = 0; /* 1700: pointer.func */
    em[1703] = 8884097; em[1704] = 8; em[1705] = 0; /* 1703: pointer.func */
    em[1706] = 0; em[1707] = 32; em[1708] = 2; /* 1706: struct.crypto_ex_data_st_fake */
    	em[1709] = 1713; em[1710] = 8; 
    	em[1711] = 473; em[1712] = 24; 
    em[1713] = 8884099; em[1714] = 8; em[1715] = 2; /* 1713: pointer_to_array_of_pointers_to_stack */
    	em[1716] = 467; em[1717] = 0; 
    	em[1718] = 470; em[1719] = 20; 
    em[1720] = 1; em[1721] = 8; em[1722] = 1; /* 1720: pointer.struct.bio_st */
    	em[1723] = 1642; em[1724] = 0; 
    em[1725] = 0; em[1726] = 1; em[1727] = 0; /* 1725: char */
    em[1728] = 8884097; em[1729] = 8; em[1730] = 0; /* 1728: pointer.func */
    args_addr->arg_entity_index[0] = 1720;
    args_addr->arg_entity_index[1] = 0;
    args_addr->arg_entity_index[2] = 1728;
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

