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
    em[0] = 8884097; em[1] = 8; em[2] = 0; /* 0: pointer.func */
    em[3] = 1; em[4] = 8; em[5] = 1; /* 3: pointer.struct.bio_st */
    	em[6] = 8; em[7] = 0; 
    em[8] = 0; em[9] = 112; em[10] = 7; /* 8: struct.bio_st */
    	em[11] = 25; em[12] = 0; 
    	em[13] = 74; em[14] = 8; 
    	em[15] = 77; em[16] = 16; 
    	em[17] = 82; em[18] = 48; 
    	em[19] = 3; em[20] = 56; 
    	em[21] = 3; em[22] = 64; 
    	em[23] = 85; em[24] = 96; 
    em[25] = 1; em[26] = 8; em[27] = 1; /* 25: pointer.struct.bio_method_st */
    	em[28] = 30; em[29] = 0; 
    em[30] = 0; em[31] = 80; em[32] = 9; /* 30: struct.bio_method_st */
    	em[33] = 51; em[34] = 8; 
    	em[35] = 56; em[36] = 16; 
    	em[37] = 59; em[38] = 24; 
    	em[39] = 62; em[40] = 32; 
    	em[41] = 59; em[42] = 40; 
    	em[43] = 65; em[44] = 48; 
    	em[45] = 68; em[46] = 56; 
    	em[47] = 68; em[48] = 64; 
    	em[49] = 71; em[50] = 72; 
    em[51] = 1; em[52] = 8; em[53] = 1; /* 51: pointer.char */
    	em[54] = 8884096; em[55] = 0; 
    em[56] = 8884097; em[57] = 8; em[58] = 0; /* 56: pointer.func */
    em[59] = 8884097; em[60] = 8; em[61] = 0; /* 59: pointer.func */
    em[62] = 8884097; em[63] = 8; em[64] = 0; /* 62: pointer.func */
    em[65] = 8884097; em[66] = 8; em[67] = 0; /* 65: pointer.func */
    em[68] = 8884097; em[69] = 8; em[70] = 0; /* 68: pointer.func */
    em[71] = 8884097; em[72] = 8; em[73] = 0; /* 71: pointer.func */
    em[74] = 8884097; em[75] = 8; em[76] = 0; /* 74: pointer.func */
    em[77] = 1; em[78] = 8; em[79] = 1; /* 77: pointer.char */
    	em[80] = 8884096; em[81] = 0; 
    em[82] = 0; em[83] = 8; em[84] = 0; /* 82: pointer.void */
    em[85] = 0; em[86] = 32; em[87] = 2; /* 85: struct.crypto_ex_data_st_fake */
    	em[88] = 92; em[89] = 8; 
    	em[90] = 102; em[91] = 24; 
    em[92] = 8884099; em[93] = 8; em[94] = 2; /* 92: pointer_to_array_of_pointers_to_stack */
    	em[95] = 82; em[96] = 0; 
    	em[97] = 99; em[98] = 20; 
    em[99] = 0; em[100] = 4; em[101] = 0; /* 99: int */
    em[102] = 8884097; em[103] = 8; em[104] = 0; /* 102: pointer.func */
    em[105] = 1; em[106] = 8; em[107] = 1; /* 105: pointer.struct.bio_st */
    	em[108] = 8; em[109] = 0; 
    em[110] = 1; em[111] = 8; em[112] = 1; /* 110: pointer.struct.ASN1_VALUE_st */
    	em[113] = 115; em[114] = 0; 
    em[115] = 0; em[116] = 0; em[117] = 0; /* 115: struct.ASN1_VALUE_st */
    em[118] = 1; em[119] = 8; em[120] = 1; /* 118: pointer.struct.asn1_string_st */
    	em[121] = 123; em[122] = 0; 
    em[123] = 0; em[124] = 24; em[125] = 1; /* 123: struct.asn1_string_st */
    	em[126] = 128; em[127] = 8; 
    em[128] = 1; em[129] = 8; em[130] = 1; /* 128: pointer.unsigned char */
    	em[131] = 133; em[132] = 0; 
    em[133] = 0; em[134] = 1; em[135] = 0; /* 133: unsigned char */
    em[136] = 1; em[137] = 8; em[138] = 1; /* 136: pointer.struct.asn1_string_st */
    	em[139] = 123; em[140] = 0; 
    em[141] = 1; em[142] = 8; em[143] = 1; /* 141: pointer.struct.asn1_string_st */
    	em[144] = 123; em[145] = 0; 
    em[146] = 1; em[147] = 8; em[148] = 1; /* 146: pointer.struct.asn1_string_st */
    	em[149] = 123; em[150] = 0; 
    em[151] = 1; em[152] = 8; em[153] = 1; /* 151: pointer.struct.asn1_string_st */
    	em[154] = 123; em[155] = 0; 
    em[156] = 1; em[157] = 8; em[158] = 1; /* 156: pointer.struct.asn1_string_st */
    	em[159] = 123; em[160] = 0; 
    em[161] = 1; em[162] = 8; em[163] = 1; /* 161: pointer.struct.asn1_string_st */
    	em[164] = 123; em[165] = 0; 
    em[166] = 1; em[167] = 8; em[168] = 1; /* 166: pointer.struct.asn1_string_st */
    	em[169] = 123; em[170] = 0; 
    em[171] = 1; em[172] = 8; em[173] = 1; /* 171: pointer.struct.asn1_string_st */
    	em[174] = 123; em[175] = 0; 
    em[176] = 1; em[177] = 8; em[178] = 1; /* 176: pointer.struct.asn1_string_st */
    	em[179] = 123; em[180] = 0; 
    em[181] = 1; em[182] = 8; em[183] = 1; /* 181: pointer.struct.asn1_string_st */
    	em[184] = 123; em[185] = 0; 
    em[186] = 0; em[187] = 144; em[188] = 12; /* 186: struct.dh_st */
    	em[189] = 213; em[190] = 8; 
    	em[191] = 213; em[192] = 16; 
    	em[193] = 213; em[194] = 32; 
    	em[195] = 213; em[196] = 40; 
    	em[197] = 233; em[198] = 56; 
    	em[199] = 213; em[200] = 64; 
    	em[201] = 213; em[202] = 72; 
    	em[203] = 128; em[204] = 80; 
    	em[205] = 213; em[206] = 96; 
    	em[207] = 247; em[208] = 112; 
    	em[209] = 261; em[210] = 128; 
    	em[211] = 297; em[212] = 136; 
    em[213] = 1; em[214] = 8; em[215] = 1; /* 213: pointer.struct.bignum_st */
    	em[216] = 218; em[217] = 0; 
    em[218] = 0; em[219] = 24; em[220] = 1; /* 218: struct.bignum_st */
    	em[221] = 223; em[222] = 0; 
    em[223] = 8884099; em[224] = 8; em[225] = 2; /* 223: pointer_to_array_of_pointers_to_stack */
    	em[226] = 230; em[227] = 0; 
    	em[228] = 99; em[229] = 12; 
    em[230] = 0; em[231] = 8; em[232] = 0; /* 230: long unsigned int */
    em[233] = 1; em[234] = 8; em[235] = 1; /* 233: pointer.struct.bn_mont_ctx_st */
    	em[236] = 238; em[237] = 0; 
    em[238] = 0; em[239] = 96; em[240] = 3; /* 238: struct.bn_mont_ctx_st */
    	em[241] = 218; em[242] = 8; 
    	em[243] = 218; em[244] = 32; 
    	em[245] = 218; em[246] = 56; 
    em[247] = 0; em[248] = 32; em[249] = 2; /* 247: struct.crypto_ex_data_st_fake */
    	em[250] = 254; em[251] = 8; 
    	em[252] = 102; em[253] = 24; 
    em[254] = 8884099; em[255] = 8; em[256] = 2; /* 254: pointer_to_array_of_pointers_to_stack */
    	em[257] = 82; em[258] = 0; 
    	em[259] = 99; em[260] = 20; 
    em[261] = 1; em[262] = 8; em[263] = 1; /* 261: pointer.struct.dh_method */
    	em[264] = 266; em[265] = 0; 
    em[266] = 0; em[267] = 72; em[268] = 8; /* 266: struct.dh_method */
    	em[269] = 51; em[270] = 0; 
    	em[271] = 285; em[272] = 8; 
    	em[273] = 288; em[274] = 16; 
    	em[275] = 291; em[276] = 24; 
    	em[277] = 285; em[278] = 32; 
    	em[279] = 285; em[280] = 40; 
    	em[281] = 77; em[282] = 56; 
    	em[283] = 294; em[284] = 64; 
    em[285] = 8884097; em[286] = 8; em[287] = 0; /* 285: pointer.func */
    em[288] = 8884097; em[289] = 8; em[290] = 0; /* 288: pointer.func */
    em[291] = 8884097; em[292] = 8; em[293] = 0; /* 291: pointer.func */
    em[294] = 8884097; em[295] = 8; em[296] = 0; /* 294: pointer.func */
    em[297] = 1; em[298] = 8; em[299] = 1; /* 297: pointer.struct.engine_st */
    	em[300] = 302; em[301] = 0; 
    em[302] = 0; em[303] = 216; em[304] = 24; /* 302: struct.engine_st */
    	em[305] = 51; em[306] = 0; 
    	em[307] = 51; em[308] = 8; 
    	em[309] = 353; em[310] = 16; 
    	em[311] = 408; em[312] = 24; 
    	em[313] = 459; em[314] = 32; 
    	em[315] = 495; em[316] = 40; 
    	em[317] = 512; em[318] = 48; 
    	em[319] = 539; em[320] = 56; 
    	em[321] = 574; em[322] = 64; 
    	em[323] = 582; em[324] = 72; 
    	em[325] = 585; em[326] = 80; 
    	em[327] = 588; em[328] = 88; 
    	em[329] = 591; em[330] = 96; 
    	em[331] = 594; em[332] = 104; 
    	em[333] = 594; em[334] = 112; 
    	em[335] = 594; em[336] = 120; 
    	em[337] = 597; em[338] = 128; 
    	em[339] = 600; em[340] = 136; 
    	em[341] = 600; em[342] = 144; 
    	em[343] = 603; em[344] = 152; 
    	em[345] = 606; em[346] = 160; 
    	em[347] = 618; em[348] = 184; 
    	em[349] = 632; em[350] = 200; 
    	em[351] = 632; em[352] = 208; 
    em[353] = 1; em[354] = 8; em[355] = 1; /* 353: pointer.struct.rsa_meth_st */
    	em[356] = 358; em[357] = 0; 
    em[358] = 0; em[359] = 112; em[360] = 13; /* 358: struct.rsa_meth_st */
    	em[361] = 51; em[362] = 0; 
    	em[363] = 387; em[364] = 8; 
    	em[365] = 387; em[366] = 16; 
    	em[367] = 387; em[368] = 24; 
    	em[369] = 387; em[370] = 32; 
    	em[371] = 390; em[372] = 40; 
    	em[373] = 393; em[374] = 48; 
    	em[375] = 396; em[376] = 56; 
    	em[377] = 396; em[378] = 64; 
    	em[379] = 77; em[380] = 80; 
    	em[381] = 399; em[382] = 88; 
    	em[383] = 402; em[384] = 96; 
    	em[385] = 405; em[386] = 104; 
    em[387] = 8884097; em[388] = 8; em[389] = 0; /* 387: pointer.func */
    em[390] = 8884097; em[391] = 8; em[392] = 0; /* 390: pointer.func */
    em[393] = 8884097; em[394] = 8; em[395] = 0; /* 393: pointer.func */
    em[396] = 8884097; em[397] = 8; em[398] = 0; /* 396: pointer.func */
    em[399] = 8884097; em[400] = 8; em[401] = 0; /* 399: pointer.func */
    em[402] = 8884097; em[403] = 8; em[404] = 0; /* 402: pointer.func */
    em[405] = 8884097; em[406] = 8; em[407] = 0; /* 405: pointer.func */
    em[408] = 1; em[409] = 8; em[410] = 1; /* 408: pointer.struct.dsa_method */
    	em[411] = 413; em[412] = 0; 
    em[413] = 0; em[414] = 96; em[415] = 11; /* 413: struct.dsa_method */
    	em[416] = 51; em[417] = 0; 
    	em[418] = 438; em[419] = 8; 
    	em[420] = 441; em[421] = 16; 
    	em[422] = 444; em[423] = 24; 
    	em[424] = 447; em[425] = 32; 
    	em[426] = 450; em[427] = 40; 
    	em[428] = 453; em[429] = 48; 
    	em[430] = 453; em[431] = 56; 
    	em[432] = 77; em[433] = 72; 
    	em[434] = 456; em[435] = 80; 
    	em[436] = 453; em[437] = 88; 
    em[438] = 8884097; em[439] = 8; em[440] = 0; /* 438: pointer.func */
    em[441] = 8884097; em[442] = 8; em[443] = 0; /* 441: pointer.func */
    em[444] = 8884097; em[445] = 8; em[446] = 0; /* 444: pointer.func */
    em[447] = 8884097; em[448] = 8; em[449] = 0; /* 447: pointer.func */
    em[450] = 8884097; em[451] = 8; em[452] = 0; /* 450: pointer.func */
    em[453] = 8884097; em[454] = 8; em[455] = 0; /* 453: pointer.func */
    em[456] = 8884097; em[457] = 8; em[458] = 0; /* 456: pointer.func */
    em[459] = 1; em[460] = 8; em[461] = 1; /* 459: pointer.struct.dh_method */
    	em[462] = 464; em[463] = 0; 
    em[464] = 0; em[465] = 72; em[466] = 8; /* 464: struct.dh_method */
    	em[467] = 51; em[468] = 0; 
    	em[469] = 483; em[470] = 8; 
    	em[471] = 486; em[472] = 16; 
    	em[473] = 489; em[474] = 24; 
    	em[475] = 483; em[476] = 32; 
    	em[477] = 483; em[478] = 40; 
    	em[479] = 77; em[480] = 56; 
    	em[481] = 492; em[482] = 64; 
    em[483] = 8884097; em[484] = 8; em[485] = 0; /* 483: pointer.func */
    em[486] = 8884097; em[487] = 8; em[488] = 0; /* 486: pointer.func */
    em[489] = 8884097; em[490] = 8; em[491] = 0; /* 489: pointer.func */
    em[492] = 8884097; em[493] = 8; em[494] = 0; /* 492: pointer.func */
    em[495] = 1; em[496] = 8; em[497] = 1; /* 495: pointer.struct.ecdh_method */
    	em[498] = 500; em[499] = 0; 
    em[500] = 0; em[501] = 32; em[502] = 3; /* 500: struct.ecdh_method */
    	em[503] = 51; em[504] = 0; 
    	em[505] = 509; em[506] = 8; 
    	em[507] = 77; em[508] = 24; 
    em[509] = 8884097; em[510] = 8; em[511] = 0; /* 509: pointer.func */
    em[512] = 1; em[513] = 8; em[514] = 1; /* 512: pointer.struct.ecdsa_method */
    	em[515] = 517; em[516] = 0; 
    em[517] = 0; em[518] = 48; em[519] = 5; /* 517: struct.ecdsa_method */
    	em[520] = 51; em[521] = 0; 
    	em[522] = 530; em[523] = 8; 
    	em[524] = 533; em[525] = 16; 
    	em[526] = 536; em[527] = 24; 
    	em[528] = 77; em[529] = 40; 
    em[530] = 8884097; em[531] = 8; em[532] = 0; /* 530: pointer.func */
    em[533] = 8884097; em[534] = 8; em[535] = 0; /* 533: pointer.func */
    em[536] = 8884097; em[537] = 8; em[538] = 0; /* 536: pointer.func */
    em[539] = 1; em[540] = 8; em[541] = 1; /* 539: pointer.struct.rand_meth_st */
    	em[542] = 544; em[543] = 0; 
    em[544] = 0; em[545] = 48; em[546] = 6; /* 544: struct.rand_meth_st */
    	em[547] = 559; em[548] = 0; 
    	em[549] = 562; em[550] = 8; 
    	em[551] = 565; em[552] = 16; 
    	em[553] = 568; em[554] = 24; 
    	em[555] = 562; em[556] = 32; 
    	em[557] = 571; em[558] = 40; 
    em[559] = 8884097; em[560] = 8; em[561] = 0; /* 559: pointer.func */
    em[562] = 8884097; em[563] = 8; em[564] = 0; /* 562: pointer.func */
    em[565] = 8884097; em[566] = 8; em[567] = 0; /* 565: pointer.func */
    em[568] = 8884097; em[569] = 8; em[570] = 0; /* 568: pointer.func */
    em[571] = 8884097; em[572] = 8; em[573] = 0; /* 571: pointer.func */
    em[574] = 1; em[575] = 8; em[576] = 1; /* 574: pointer.struct.store_method_st */
    	em[577] = 579; em[578] = 0; 
    em[579] = 0; em[580] = 0; em[581] = 0; /* 579: struct.store_method_st */
    em[582] = 8884097; em[583] = 8; em[584] = 0; /* 582: pointer.func */
    em[585] = 8884097; em[586] = 8; em[587] = 0; /* 585: pointer.func */
    em[588] = 8884097; em[589] = 8; em[590] = 0; /* 588: pointer.func */
    em[591] = 8884097; em[592] = 8; em[593] = 0; /* 591: pointer.func */
    em[594] = 8884097; em[595] = 8; em[596] = 0; /* 594: pointer.func */
    em[597] = 8884097; em[598] = 8; em[599] = 0; /* 597: pointer.func */
    em[600] = 8884097; em[601] = 8; em[602] = 0; /* 600: pointer.func */
    em[603] = 8884097; em[604] = 8; em[605] = 0; /* 603: pointer.func */
    em[606] = 1; em[607] = 8; em[608] = 1; /* 606: pointer.struct.ENGINE_CMD_DEFN_st */
    	em[609] = 611; em[610] = 0; 
    em[611] = 0; em[612] = 32; em[613] = 2; /* 611: struct.ENGINE_CMD_DEFN_st */
    	em[614] = 51; em[615] = 8; 
    	em[616] = 51; em[617] = 16; 
    em[618] = 0; em[619] = 32; em[620] = 2; /* 618: struct.crypto_ex_data_st_fake */
    	em[621] = 625; em[622] = 8; 
    	em[623] = 102; em[624] = 24; 
    em[625] = 8884099; em[626] = 8; em[627] = 2; /* 625: pointer_to_array_of_pointers_to_stack */
    	em[628] = 82; em[629] = 0; 
    	em[630] = 99; em[631] = 20; 
    em[632] = 1; em[633] = 8; em[634] = 1; /* 632: pointer.struct.engine_st */
    	em[635] = 302; em[636] = 0; 
    em[637] = 1; em[638] = 8; em[639] = 1; /* 637: pointer.struct.dh_st */
    	em[640] = 186; em[641] = 0; 
    em[642] = 1; em[643] = 8; em[644] = 1; /* 642: pointer.struct.asn1_string_st */
    	em[645] = 123; em[646] = 0; 
    em[647] = 8884097; em[648] = 8; em[649] = 0; /* 647: pointer.func */
    em[650] = 1; em[651] = 8; em[652] = 1; /* 650: pointer.struct.evp_pkey_asn1_method_st */
    	em[653] = 655; em[654] = 0; 
    em[655] = 0; em[656] = 208; em[657] = 24; /* 655: struct.evp_pkey_asn1_method_st */
    	em[658] = 77; em[659] = 16; 
    	em[660] = 77; em[661] = 24; 
    	em[662] = 706; em[663] = 32; 
    	em[664] = 709; em[665] = 40; 
    	em[666] = 712; em[667] = 48; 
    	em[668] = 715; em[669] = 56; 
    	em[670] = 718; em[671] = 64; 
    	em[672] = 721; em[673] = 72; 
    	em[674] = 715; em[675] = 80; 
    	em[676] = 724; em[677] = 88; 
    	em[678] = 724; em[679] = 96; 
    	em[680] = 727; em[681] = 104; 
    	em[682] = 730; em[683] = 112; 
    	em[684] = 724; em[685] = 120; 
    	em[686] = 733; em[687] = 128; 
    	em[688] = 712; em[689] = 136; 
    	em[690] = 715; em[691] = 144; 
    	em[692] = 736; em[693] = 152; 
    	em[694] = 739; em[695] = 160; 
    	em[696] = 742; em[697] = 168; 
    	em[698] = 727; em[699] = 176; 
    	em[700] = 730; em[701] = 184; 
    	em[702] = 745; em[703] = 192; 
    	em[704] = 748; em[705] = 200; 
    em[706] = 8884097; em[707] = 8; em[708] = 0; /* 706: pointer.func */
    em[709] = 8884097; em[710] = 8; em[711] = 0; /* 709: pointer.func */
    em[712] = 8884097; em[713] = 8; em[714] = 0; /* 712: pointer.func */
    em[715] = 8884097; em[716] = 8; em[717] = 0; /* 715: pointer.func */
    em[718] = 8884097; em[719] = 8; em[720] = 0; /* 718: pointer.func */
    em[721] = 8884097; em[722] = 8; em[723] = 0; /* 721: pointer.func */
    em[724] = 8884097; em[725] = 8; em[726] = 0; /* 724: pointer.func */
    em[727] = 8884097; em[728] = 8; em[729] = 0; /* 727: pointer.func */
    em[730] = 8884097; em[731] = 8; em[732] = 0; /* 730: pointer.func */
    em[733] = 8884097; em[734] = 8; em[735] = 0; /* 733: pointer.func */
    em[736] = 8884097; em[737] = 8; em[738] = 0; /* 736: pointer.func */
    em[739] = 8884097; em[740] = 8; em[741] = 0; /* 739: pointer.func */
    em[742] = 8884097; em[743] = 8; em[744] = 0; /* 742: pointer.func */
    em[745] = 8884097; em[746] = 8; em[747] = 0; /* 745: pointer.func */
    em[748] = 8884097; em[749] = 8; em[750] = 0; /* 748: pointer.func */
    em[751] = 8884097; em[752] = 8; em[753] = 0; /* 751: pointer.func */
    em[754] = 1; em[755] = 8; em[756] = 1; /* 754: pointer.struct.asn1_string_st */
    	em[757] = 759; em[758] = 0; 
    em[759] = 0; em[760] = 24; em[761] = 1; /* 759: struct.asn1_string_st */
    	em[762] = 128; em[763] = 8; 
    em[764] = 1; em[765] = 8; em[766] = 1; /* 764: pointer.struct.dsa_method */
    	em[767] = 769; em[768] = 0; 
    em[769] = 0; em[770] = 96; em[771] = 11; /* 769: struct.dsa_method */
    	em[772] = 51; em[773] = 0; 
    	em[774] = 794; em[775] = 8; 
    	em[776] = 751; em[777] = 16; 
    	em[778] = 797; em[779] = 24; 
    	em[780] = 800; em[781] = 32; 
    	em[782] = 803; em[783] = 40; 
    	em[784] = 647; em[785] = 48; 
    	em[786] = 647; em[787] = 56; 
    	em[788] = 77; em[789] = 72; 
    	em[790] = 806; em[791] = 80; 
    	em[792] = 647; em[793] = 88; 
    em[794] = 8884097; em[795] = 8; em[796] = 0; /* 794: pointer.func */
    em[797] = 8884097; em[798] = 8; em[799] = 0; /* 797: pointer.func */
    em[800] = 8884097; em[801] = 8; em[802] = 0; /* 800: pointer.func */
    em[803] = 8884097; em[804] = 8; em[805] = 0; /* 803: pointer.func */
    em[806] = 8884097; em[807] = 8; em[808] = 0; /* 806: pointer.func */
    em[809] = 8884097; em[810] = 8; em[811] = 0; /* 809: pointer.func */
    em[812] = 8884097; em[813] = 8; em[814] = 0; /* 812: pointer.func */
    em[815] = 1; em[816] = 8; em[817] = 1; /* 815: pointer.struct.engine_st */
    	em[818] = 302; em[819] = 0; 
    em[820] = 1; em[821] = 8; em[822] = 1; /* 820: pointer.struct.bignum_st */
    	em[823] = 825; em[824] = 0; 
    em[825] = 0; em[826] = 24; em[827] = 1; /* 825: struct.bignum_st */
    	em[828] = 830; em[829] = 0; 
    em[830] = 8884099; em[831] = 8; em[832] = 2; /* 830: pointer_to_array_of_pointers_to_stack */
    	em[833] = 230; em[834] = 0; 
    	em[835] = 99; em[836] = 12; 
    em[837] = 1; em[838] = 8; em[839] = 1; /* 837: pointer.unsigned char */
    	em[840] = 133; em[841] = 0; 
    em[842] = 8884097; em[843] = 8; em[844] = 0; /* 842: pointer.func */
    em[845] = 0; em[846] = 1; em[847] = 0; /* 845: char */
    em[848] = 1; em[849] = 8; em[850] = 1; /* 848: pointer.struct.asn1_object_st */
    	em[851] = 853; em[852] = 0; 
    em[853] = 0; em[854] = 40; em[855] = 3; /* 853: struct.asn1_object_st */
    	em[856] = 51; em[857] = 0; 
    	em[858] = 51; em[859] = 8; 
    	em[860] = 837; em[861] = 24; 
    em[862] = 1; em[863] = 8; em[864] = 1; /* 862: pointer.pointer.struct.evp_pkey_st */
    	em[865] = 867; em[866] = 0; 
    em[867] = 1; em[868] = 8; em[869] = 1; /* 867: pointer.struct.evp_pkey_st */
    	em[870] = 872; em[871] = 0; 
    em[872] = 0; em[873] = 56; em[874] = 4; /* 872: struct.evp_pkey_st */
    	em[875] = 650; em[876] = 16; 
    	em[877] = 883; em[878] = 24; 
    	em[879] = 888; em[880] = 32; 
    	em[881] = 1669; em[882] = 48; 
    em[883] = 1; em[884] = 8; em[885] = 1; /* 883: pointer.struct.engine_st */
    	em[886] = 302; em[887] = 0; 
    em[888] = 8884101; em[889] = 8; em[890] = 6; /* 888: union.union_of_evp_pkey_st */
    	em[891] = 82; em[892] = 0; 
    	em[893] = 903; em[894] = 6; 
    	em[895] = 1086; em[896] = 116; 
    	em[897] = 637; em[898] = 28; 
    	em[899] = 1166; em[900] = 408; 
    	em[901] = 99; em[902] = 0; 
    em[903] = 1; em[904] = 8; em[905] = 1; /* 903: pointer.struct.rsa_st */
    	em[906] = 908; em[907] = 0; 
    em[908] = 0; em[909] = 168; em[910] = 17; /* 908: struct.rsa_st */
    	em[911] = 945; em[912] = 16; 
    	em[913] = 815; em[914] = 24; 
    	em[915] = 820; em[916] = 32; 
    	em[917] = 820; em[918] = 40; 
    	em[919] = 820; em[920] = 48; 
    	em[921] = 820; em[922] = 56; 
    	em[923] = 820; em[924] = 64; 
    	em[925] = 820; em[926] = 72; 
    	em[927] = 820; em[928] = 80; 
    	em[929] = 820; em[930] = 88; 
    	em[931] = 997; em[932] = 96; 
    	em[933] = 1011; em[934] = 120; 
    	em[935] = 1011; em[936] = 128; 
    	em[937] = 1011; em[938] = 136; 
    	em[939] = 77; em[940] = 144; 
    	em[941] = 1025; em[942] = 152; 
    	em[943] = 1025; em[944] = 160; 
    em[945] = 1; em[946] = 8; em[947] = 1; /* 945: pointer.struct.rsa_meth_st */
    	em[948] = 950; em[949] = 0; 
    em[950] = 0; em[951] = 112; em[952] = 13; /* 950: struct.rsa_meth_st */
    	em[953] = 51; em[954] = 0; 
    	em[955] = 979; em[956] = 8; 
    	em[957] = 979; em[958] = 16; 
    	em[959] = 979; em[960] = 24; 
    	em[961] = 979; em[962] = 32; 
    	em[963] = 982; em[964] = 40; 
    	em[965] = 985; em[966] = 48; 
    	em[967] = 988; em[968] = 56; 
    	em[969] = 988; em[970] = 64; 
    	em[971] = 77; em[972] = 80; 
    	em[973] = 842; em[974] = 88; 
    	em[975] = 991; em[976] = 96; 
    	em[977] = 994; em[978] = 104; 
    em[979] = 8884097; em[980] = 8; em[981] = 0; /* 979: pointer.func */
    em[982] = 8884097; em[983] = 8; em[984] = 0; /* 982: pointer.func */
    em[985] = 8884097; em[986] = 8; em[987] = 0; /* 985: pointer.func */
    em[988] = 8884097; em[989] = 8; em[990] = 0; /* 988: pointer.func */
    em[991] = 8884097; em[992] = 8; em[993] = 0; /* 991: pointer.func */
    em[994] = 8884097; em[995] = 8; em[996] = 0; /* 994: pointer.func */
    em[997] = 0; em[998] = 32; em[999] = 2; /* 997: struct.crypto_ex_data_st_fake */
    	em[1000] = 1004; em[1001] = 8; 
    	em[1002] = 102; em[1003] = 24; 
    em[1004] = 8884099; em[1005] = 8; em[1006] = 2; /* 1004: pointer_to_array_of_pointers_to_stack */
    	em[1007] = 82; em[1008] = 0; 
    	em[1009] = 99; em[1010] = 20; 
    em[1011] = 1; em[1012] = 8; em[1013] = 1; /* 1011: pointer.struct.bn_mont_ctx_st */
    	em[1014] = 1016; em[1015] = 0; 
    em[1016] = 0; em[1017] = 96; em[1018] = 3; /* 1016: struct.bn_mont_ctx_st */
    	em[1019] = 825; em[1020] = 8; 
    	em[1021] = 825; em[1022] = 32; 
    	em[1023] = 825; em[1024] = 56; 
    em[1025] = 1; em[1026] = 8; em[1027] = 1; /* 1025: pointer.struct.bn_blinding_st */
    	em[1028] = 1030; em[1029] = 0; 
    em[1030] = 0; em[1031] = 88; em[1032] = 7; /* 1030: struct.bn_blinding_st */
    	em[1033] = 1047; em[1034] = 0; 
    	em[1035] = 1047; em[1036] = 8; 
    	em[1037] = 1047; em[1038] = 16; 
    	em[1039] = 1047; em[1040] = 24; 
    	em[1041] = 1064; em[1042] = 40; 
    	em[1043] = 1069; em[1044] = 72; 
    	em[1045] = 1083; em[1046] = 80; 
    em[1047] = 1; em[1048] = 8; em[1049] = 1; /* 1047: pointer.struct.bignum_st */
    	em[1050] = 1052; em[1051] = 0; 
    em[1052] = 0; em[1053] = 24; em[1054] = 1; /* 1052: struct.bignum_st */
    	em[1055] = 1057; em[1056] = 0; 
    em[1057] = 8884099; em[1058] = 8; em[1059] = 2; /* 1057: pointer_to_array_of_pointers_to_stack */
    	em[1060] = 230; em[1061] = 0; 
    	em[1062] = 99; em[1063] = 12; 
    em[1064] = 0; em[1065] = 16; em[1066] = 1; /* 1064: struct.crypto_threadid_st */
    	em[1067] = 82; em[1068] = 0; 
    em[1069] = 1; em[1070] = 8; em[1071] = 1; /* 1069: pointer.struct.bn_mont_ctx_st */
    	em[1072] = 1074; em[1073] = 0; 
    em[1074] = 0; em[1075] = 96; em[1076] = 3; /* 1074: struct.bn_mont_ctx_st */
    	em[1077] = 1052; em[1078] = 8; 
    	em[1079] = 1052; em[1080] = 32; 
    	em[1081] = 1052; em[1082] = 56; 
    em[1083] = 8884097; em[1084] = 8; em[1085] = 0; /* 1083: pointer.func */
    em[1086] = 1; em[1087] = 8; em[1088] = 1; /* 1086: pointer.struct.dsa_st */
    	em[1089] = 1091; em[1090] = 0; 
    em[1091] = 0; em[1092] = 136; em[1093] = 11; /* 1091: struct.dsa_st */
    	em[1094] = 1116; em[1095] = 24; 
    	em[1096] = 1116; em[1097] = 32; 
    	em[1098] = 1116; em[1099] = 40; 
    	em[1100] = 1116; em[1101] = 48; 
    	em[1102] = 1116; em[1103] = 56; 
    	em[1104] = 1116; em[1105] = 64; 
    	em[1106] = 1116; em[1107] = 72; 
    	em[1108] = 1133; em[1109] = 88; 
    	em[1110] = 1147; em[1111] = 104; 
    	em[1112] = 764; em[1113] = 120; 
    	em[1114] = 1161; em[1115] = 128; 
    em[1116] = 1; em[1117] = 8; em[1118] = 1; /* 1116: pointer.struct.bignum_st */
    	em[1119] = 1121; em[1120] = 0; 
    em[1121] = 0; em[1122] = 24; em[1123] = 1; /* 1121: struct.bignum_st */
    	em[1124] = 1126; em[1125] = 0; 
    em[1126] = 8884099; em[1127] = 8; em[1128] = 2; /* 1126: pointer_to_array_of_pointers_to_stack */
    	em[1129] = 230; em[1130] = 0; 
    	em[1131] = 99; em[1132] = 12; 
    em[1133] = 1; em[1134] = 8; em[1135] = 1; /* 1133: pointer.struct.bn_mont_ctx_st */
    	em[1136] = 1138; em[1137] = 0; 
    em[1138] = 0; em[1139] = 96; em[1140] = 3; /* 1138: struct.bn_mont_ctx_st */
    	em[1141] = 1121; em[1142] = 8; 
    	em[1143] = 1121; em[1144] = 32; 
    	em[1145] = 1121; em[1146] = 56; 
    em[1147] = 0; em[1148] = 32; em[1149] = 2; /* 1147: struct.crypto_ex_data_st_fake */
    	em[1150] = 1154; em[1151] = 8; 
    	em[1152] = 102; em[1153] = 24; 
    em[1154] = 8884099; em[1155] = 8; em[1156] = 2; /* 1154: pointer_to_array_of_pointers_to_stack */
    	em[1157] = 82; em[1158] = 0; 
    	em[1159] = 99; em[1160] = 20; 
    em[1161] = 1; em[1162] = 8; em[1163] = 1; /* 1161: pointer.struct.engine_st */
    	em[1164] = 302; em[1165] = 0; 
    em[1166] = 1; em[1167] = 8; em[1168] = 1; /* 1166: pointer.struct.ec_key_st */
    	em[1169] = 1171; em[1170] = 0; 
    em[1171] = 0; em[1172] = 56; em[1173] = 4; /* 1171: struct.ec_key_st */
    	em[1174] = 1182; em[1175] = 8; 
    	em[1176] = 1624; em[1177] = 16; 
    	em[1178] = 1629; em[1179] = 24; 
    	em[1180] = 1646; em[1181] = 48; 
    em[1182] = 1; em[1183] = 8; em[1184] = 1; /* 1182: pointer.struct.ec_group_st */
    	em[1185] = 1187; em[1186] = 0; 
    em[1187] = 0; em[1188] = 232; em[1189] = 12; /* 1187: struct.ec_group_st */
    	em[1190] = 1214; em[1191] = 0; 
    	em[1192] = 1380; em[1193] = 8; 
    	em[1194] = 1580; em[1195] = 16; 
    	em[1196] = 1580; em[1197] = 40; 
    	em[1198] = 128; em[1199] = 80; 
    	em[1200] = 1592; em[1201] = 96; 
    	em[1202] = 1580; em[1203] = 104; 
    	em[1204] = 1580; em[1205] = 152; 
    	em[1206] = 1580; em[1207] = 176; 
    	em[1208] = 82; em[1209] = 208; 
    	em[1210] = 82; em[1211] = 216; 
    	em[1212] = 1621; em[1213] = 224; 
    em[1214] = 1; em[1215] = 8; em[1216] = 1; /* 1214: pointer.struct.ec_method_st */
    	em[1217] = 1219; em[1218] = 0; 
    em[1219] = 0; em[1220] = 304; em[1221] = 37; /* 1219: struct.ec_method_st */
    	em[1222] = 1296; em[1223] = 8; 
    	em[1224] = 1299; em[1225] = 16; 
    	em[1226] = 1299; em[1227] = 24; 
    	em[1228] = 1302; em[1229] = 32; 
    	em[1230] = 1305; em[1231] = 40; 
    	em[1232] = 1308; em[1233] = 48; 
    	em[1234] = 1311; em[1235] = 56; 
    	em[1236] = 1314; em[1237] = 64; 
    	em[1238] = 1317; em[1239] = 72; 
    	em[1240] = 1320; em[1241] = 80; 
    	em[1242] = 1320; em[1243] = 88; 
    	em[1244] = 1323; em[1245] = 96; 
    	em[1246] = 1326; em[1247] = 104; 
    	em[1248] = 1329; em[1249] = 112; 
    	em[1250] = 809; em[1251] = 120; 
    	em[1252] = 1332; em[1253] = 128; 
    	em[1254] = 1335; em[1255] = 136; 
    	em[1256] = 1338; em[1257] = 144; 
    	em[1258] = 1341; em[1259] = 152; 
    	em[1260] = 1344; em[1261] = 160; 
    	em[1262] = 1347; em[1263] = 168; 
    	em[1264] = 1350; em[1265] = 176; 
    	em[1266] = 1353; em[1267] = 184; 
    	em[1268] = 1356; em[1269] = 192; 
    	em[1270] = 1359; em[1271] = 200; 
    	em[1272] = 1362; em[1273] = 208; 
    	em[1274] = 1353; em[1275] = 216; 
    	em[1276] = 1365; em[1277] = 224; 
    	em[1278] = 1368; em[1279] = 232; 
    	em[1280] = 1371; em[1281] = 240; 
    	em[1282] = 1311; em[1283] = 248; 
    	em[1284] = 1374; em[1285] = 256; 
    	em[1286] = 812; em[1287] = 264; 
    	em[1288] = 1374; em[1289] = 272; 
    	em[1290] = 812; em[1291] = 280; 
    	em[1292] = 812; em[1293] = 288; 
    	em[1294] = 1377; em[1295] = 296; 
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
    em[1362] = 8884097; em[1363] = 8; em[1364] = 0; /* 1362: pointer.func */
    em[1365] = 8884097; em[1366] = 8; em[1367] = 0; /* 1365: pointer.func */
    em[1368] = 8884097; em[1369] = 8; em[1370] = 0; /* 1368: pointer.func */
    em[1371] = 8884097; em[1372] = 8; em[1373] = 0; /* 1371: pointer.func */
    em[1374] = 8884097; em[1375] = 8; em[1376] = 0; /* 1374: pointer.func */
    em[1377] = 8884097; em[1378] = 8; em[1379] = 0; /* 1377: pointer.func */
    em[1380] = 1; em[1381] = 8; em[1382] = 1; /* 1380: pointer.struct.ec_point_st */
    	em[1383] = 1385; em[1384] = 0; 
    em[1385] = 0; em[1386] = 88; em[1387] = 4; /* 1385: struct.ec_point_st */
    	em[1388] = 1396; em[1389] = 0; 
    	em[1390] = 1568; em[1391] = 8; 
    	em[1392] = 1568; em[1393] = 32; 
    	em[1394] = 1568; em[1395] = 56; 
    em[1396] = 1; em[1397] = 8; em[1398] = 1; /* 1396: pointer.struct.ec_method_st */
    	em[1399] = 1401; em[1400] = 0; 
    em[1401] = 0; em[1402] = 304; em[1403] = 37; /* 1401: struct.ec_method_st */
    	em[1404] = 1478; em[1405] = 8; 
    	em[1406] = 1481; em[1407] = 16; 
    	em[1408] = 1481; em[1409] = 24; 
    	em[1410] = 1484; em[1411] = 32; 
    	em[1412] = 1487; em[1413] = 40; 
    	em[1414] = 1490; em[1415] = 48; 
    	em[1416] = 1493; em[1417] = 56; 
    	em[1418] = 1496; em[1419] = 64; 
    	em[1420] = 1499; em[1421] = 72; 
    	em[1422] = 1502; em[1423] = 80; 
    	em[1424] = 1502; em[1425] = 88; 
    	em[1426] = 1505; em[1427] = 96; 
    	em[1428] = 1508; em[1429] = 104; 
    	em[1430] = 1511; em[1431] = 112; 
    	em[1432] = 1514; em[1433] = 120; 
    	em[1434] = 1517; em[1435] = 128; 
    	em[1436] = 1520; em[1437] = 136; 
    	em[1438] = 1523; em[1439] = 144; 
    	em[1440] = 1526; em[1441] = 152; 
    	em[1442] = 1529; em[1443] = 160; 
    	em[1444] = 1532; em[1445] = 168; 
    	em[1446] = 1535; em[1447] = 176; 
    	em[1448] = 1538; em[1449] = 184; 
    	em[1450] = 1541; em[1451] = 192; 
    	em[1452] = 1544; em[1453] = 200; 
    	em[1454] = 1547; em[1455] = 208; 
    	em[1456] = 1538; em[1457] = 216; 
    	em[1458] = 1550; em[1459] = 224; 
    	em[1460] = 1553; em[1461] = 232; 
    	em[1462] = 1556; em[1463] = 240; 
    	em[1464] = 1493; em[1465] = 248; 
    	em[1466] = 1559; em[1467] = 256; 
    	em[1468] = 1562; em[1469] = 264; 
    	em[1470] = 1559; em[1471] = 272; 
    	em[1472] = 1562; em[1473] = 280; 
    	em[1474] = 1562; em[1475] = 288; 
    	em[1476] = 1565; em[1477] = 296; 
    em[1478] = 8884097; em[1479] = 8; em[1480] = 0; /* 1478: pointer.func */
    em[1481] = 8884097; em[1482] = 8; em[1483] = 0; /* 1481: pointer.func */
    em[1484] = 8884097; em[1485] = 8; em[1486] = 0; /* 1484: pointer.func */
    em[1487] = 8884097; em[1488] = 8; em[1489] = 0; /* 1487: pointer.func */
    em[1490] = 8884097; em[1491] = 8; em[1492] = 0; /* 1490: pointer.func */
    em[1493] = 8884097; em[1494] = 8; em[1495] = 0; /* 1493: pointer.func */
    em[1496] = 8884097; em[1497] = 8; em[1498] = 0; /* 1496: pointer.func */
    em[1499] = 8884097; em[1500] = 8; em[1501] = 0; /* 1499: pointer.func */
    em[1502] = 8884097; em[1503] = 8; em[1504] = 0; /* 1502: pointer.func */
    em[1505] = 8884097; em[1506] = 8; em[1507] = 0; /* 1505: pointer.func */
    em[1508] = 8884097; em[1509] = 8; em[1510] = 0; /* 1508: pointer.func */
    em[1511] = 8884097; em[1512] = 8; em[1513] = 0; /* 1511: pointer.func */
    em[1514] = 8884097; em[1515] = 8; em[1516] = 0; /* 1514: pointer.func */
    em[1517] = 8884097; em[1518] = 8; em[1519] = 0; /* 1517: pointer.func */
    em[1520] = 8884097; em[1521] = 8; em[1522] = 0; /* 1520: pointer.func */
    em[1523] = 8884097; em[1524] = 8; em[1525] = 0; /* 1523: pointer.func */
    em[1526] = 8884097; em[1527] = 8; em[1528] = 0; /* 1526: pointer.func */
    em[1529] = 8884097; em[1530] = 8; em[1531] = 0; /* 1529: pointer.func */
    em[1532] = 8884097; em[1533] = 8; em[1534] = 0; /* 1532: pointer.func */
    em[1535] = 8884097; em[1536] = 8; em[1537] = 0; /* 1535: pointer.func */
    em[1538] = 8884097; em[1539] = 8; em[1540] = 0; /* 1538: pointer.func */
    em[1541] = 8884097; em[1542] = 8; em[1543] = 0; /* 1541: pointer.func */
    em[1544] = 8884097; em[1545] = 8; em[1546] = 0; /* 1544: pointer.func */
    em[1547] = 8884097; em[1548] = 8; em[1549] = 0; /* 1547: pointer.func */
    em[1550] = 8884097; em[1551] = 8; em[1552] = 0; /* 1550: pointer.func */
    em[1553] = 8884097; em[1554] = 8; em[1555] = 0; /* 1553: pointer.func */
    em[1556] = 8884097; em[1557] = 8; em[1558] = 0; /* 1556: pointer.func */
    em[1559] = 8884097; em[1560] = 8; em[1561] = 0; /* 1559: pointer.func */
    em[1562] = 8884097; em[1563] = 8; em[1564] = 0; /* 1562: pointer.func */
    em[1565] = 8884097; em[1566] = 8; em[1567] = 0; /* 1565: pointer.func */
    em[1568] = 0; em[1569] = 24; em[1570] = 1; /* 1568: struct.bignum_st */
    	em[1571] = 1573; em[1572] = 0; 
    em[1573] = 8884099; em[1574] = 8; em[1575] = 2; /* 1573: pointer_to_array_of_pointers_to_stack */
    	em[1576] = 230; em[1577] = 0; 
    	em[1578] = 99; em[1579] = 12; 
    em[1580] = 0; em[1581] = 24; em[1582] = 1; /* 1580: struct.bignum_st */
    	em[1583] = 1585; em[1584] = 0; 
    em[1585] = 8884099; em[1586] = 8; em[1587] = 2; /* 1585: pointer_to_array_of_pointers_to_stack */
    	em[1588] = 230; em[1589] = 0; 
    	em[1590] = 99; em[1591] = 12; 
    em[1592] = 1; em[1593] = 8; em[1594] = 1; /* 1592: pointer.struct.ec_extra_data_st */
    	em[1595] = 1597; em[1596] = 0; 
    em[1597] = 0; em[1598] = 40; em[1599] = 5; /* 1597: struct.ec_extra_data_st */
    	em[1600] = 1610; em[1601] = 0; 
    	em[1602] = 82; em[1603] = 8; 
    	em[1604] = 1615; em[1605] = 16; 
    	em[1606] = 1618; em[1607] = 24; 
    	em[1608] = 1618; em[1609] = 32; 
    em[1610] = 1; em[1611] = 8; em[1612] = 1; /* 1610: pointer.struct.ec_extra_data_st */
    	em[1613] = 1597; em[1614] = 0; 
    em[1615] = 8884097; em[1616] = 8; em[1617] = 0; /* 1615: pointer.func */
    em[1618] = 8884097; em[1619] = 8; em[1620] = 0; /* 1618: pointer.func */
    em[1621] = 8884097; em[1622] = 8; em[1623] = 0; /* 1621: pointer.func */
    em[1624] = 1; em[1625] = 8; em[1626] = 1; /* 1624: pointer.struct.ec_point_st */
    	em[1627] = 1385; em[1628] = 0; 
    em[1629] = 1; em[1630] = 8; em[1631] = 1; /* 1629: pointer.struct.bignum_st */
    	em[1632] = 1634; em[1633] = 0; 
    em[1634] = 0; em[1635] = 24; em[1636] = 1; /* 1634: struct.bignum_st */
    	em[1637] = 1639; em[1638] = 0; 
    em[1639] = 8884099; em[1640] = 8; em[1641] = 2; /* 1639: pointer_to_array_of_pointers_to_stack */
    	em[1642] = 230; em[1643] = 0; 
    	em[1644] = 99; em[1645] = 12; 
    em[1646] = 1; em[1647] = 8; em[1648] = 1; /* 1646: pointer.struct.ec_extra_data_st */
    	em[1649] = 1651; em[1650] = 0; 
    em[1651] = 0; em[1652] = 40; em[1653] = 5; /* 1651: struct.ec_extra_data_st */
    	em[1654] = 1664; em[1655] = 0; 
    	em[1656] = 82; em[1657] = 8; 
    	em[1658] = 1615; em[1659] = 16; 
    	em[1660] = 1618; em[1661] = 24; 
    	em[1662] = 1618; em[1663] = 32; 
    em[1664] = 1; em[1665] = 8; em[1666] = 1; /* 1664: pointer.struct.ec_extra_data_st */
    	em[1667] = 1651; em[1668] = 0; 
    em[1669] = 1; em[1670] = 8; em[1671] = 1; /* 1669: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[1672] = 1674; em[1673] = 0; 
    em[1674] = 0; em[1675] = 32; em[1676] = 2; /* 1674: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[1677] = 1681; em[1678] = 8; 
    	em[1679] = 102; em[1680] = 24; 
    em[1681] = 8884099; em[1682] = 8; em[1683] = 2; /* 1681: pointer_to_array_of_pointers_to_stack */
    	em[1684] = 1688; em[1685] = 0; 
    	em[1686] = 99; em[1687] = 20; 
    em[1688] = 0; em[1689] = 8; em[1690] = 1; /* 1688: pointer.X509_ATTRIBUTE */
    	em[1691] = 1693; em[1692] = 0; 
    em[1693] = 0; em[1694] = 0; em[1695] = 1; /* 1693: X509_ATTRIBUTE */
    	em[1696] = 1698; em[1697] = 0; 
    em[1698] = 0; em[1699] = 24; em[1700] = 2; /* 1698: struct.x509_attributes_st */
    	em[1701] = 1705; em[1702] = 0; 
    	em[1703] = 1719; em[1704] = 16; 
    em[1705] = 1; em[1706] = 8; em[1707] = 1; /* 1705: pointer.struct.asn1_object_st */
    	em[1708] = 1710; em[1709] = 0; 
    em[1710] = 0; em[1711] = 40; em[1712] = 3; /* 1710: struct.asn1_object_st */
    	em[1713] = 51; em[1714] = 0; 
    	em[1715] = 51; em[1716] = 8; 
    	em[1717] = 837; em[1718] = 24; 
    em[1719] = 0; em[1720] = 8; em[1721] = 3; /* 1719: union.unknown */
    	em[1722] = 77; em[1723] = 0; 
    	em[1724] = 1728; em[1725] = 0; 
    	em[1726] = 1883; em[1727] = 0; 
    em[1728] = 1; em[1729] = 8; em[1730] = 1; /* 1728: pointer.struct.stack_st_ASN1_TYPE */
    	em[1731] = 1733; em[1732] = 0; 
    em[1733] = 0; em[1734] = 32; em[1735] = 2; /* 1733: struct.stack_st_fake_ASN1_TYPE */
    	em[1736] = 1740; em[1737] = 8; 
    	em[1738] = 102; em[1739] = 24; 
    em[1740] = 8884099; em[1741] = 8; em[1742] = 2; /* 1740: pointer_to_array_of_pointers_to_stack */
    	em[1743] = 1747; em[1744] = 0; 
    	em[1745] = 99; em[1746] = 20; 
    em[1747] = 0; em[1748] = 8; em[1749] = 1; /* 1747: pointer.ASN1_TYPE */
    	em[1750] = 1752; em[1751] = 0; 
    em[1752] = 0; em[1753] = 0; em[1754] = 1; /* 1752: ASN1_TYPE */
    	em[1755] = 1757; em[1756] = 0; 
    em[1757] = 0; em[1758] = 16; em[1759] = 1; /* 1757: struct.asn1_type_st */
    	em[1760] = 1762; em[1761] = 8; 
    em[1762] = 0; em[1763] = 8; em[1764] = 20; /* 1762: union.unknown */
    	em[1765] = 77; em[1766] = 0; 
    	em[1767] = 1805; em[1768] = 0; 
    	em[1769] = 848; em[1770] = 0; 
    	em[1771] = 1810; em[1772] = 0; 
    	em[1773] = 1815; em[1774] = 0; 
    	em[1775] = 1820; em[1776] = 0; 
    	em[1777] = 1825; em[1778] = 0; 
    	em[1779] = 1830; em[1780] = 0; 
    	em[1781] = 1835; em[1782] = 0; 
    	em[1783] = 754; em[1784] = 0; 
    	em[1785] = 1840; em[1786] = 0; 
    	em[1787] = 1845; em[1788] = 0; 
    	em[1789] = 1850; em[1790] = 0; 
    	em[1791] = 1855; em[1792] = 0; 
    	em[1793] = 1860; em[1794] = 0; 
    	em[1795] = 1865; em[1796] = 0; 
    	em[1797] = 1870; em[1798] = 0; 
    	em[1799] = 1805; em[1800] = 0; 
    	em[1801] = 1805; em[1802] = 0; 
    	em[1803] = 1875; em[1804] = 0; 
    em[1805] = 1; em[1806] = 8; em[1807] = 1; /* 1805: pointer.struct.asn1_string_st */
    	em[1808] = 759; em[1809] = 0; 
    em[1810] = 1; em[1811] = 8; em[1812] = 1; /* 1810: pointer.struct.asn1_string_st */
    	em[1813] = 759; em[1814] = 0; 
    em[1815] = 1; em[1816] = 8; em[1817] = 1; /* 1815: pointer.struct.asn1_string_st */
    	em[1818] = 759; em[1819] = 0; 
    em[1820] = 1; em[1821] = 8; em[1822] = 1; /* 1820: pointer.struct.asn1_string_st */
    	em[1823] = 759; em[1824] = 0; 
    em[1825] = 1; em[1826] = 8; em[1827] = 1; /* 1825: pointer.struct.asn1_string_st */
    	em[1828] = 759; em[1829] = 0; 
    em[1830] = 1; em[1831] = 8; em[1832] = 1; /* 1830: pointer.struct.asn1_string_st */
    	em[1833] = 759; em[1834] = 0; 
    em[1835] = 1; em[1836] = 8; em[1837] = 1; /* 1835: pointer.struct.asn1_string_st */
    	em[1838] = 759; em[1839] = 0; 
    em[1840] = 1; em[1841] = 8; em[1842] = 1; /* 1840: pointer.struct.asn1_string_st */
    	em[1843] = 759; em[1844] = 0; 
    em[1845] = 1; em[1846] = 8; em[1847] = 1; /* 1845: pointer.struct.asn1_string_st */
    	em[1848] = 759; em[1849] = 0; 
    em[1850] = 1; em[1851] = 8; em[1852] = 1; /* 1850: pointer.struct.asn1_string_st */
    	em[1853] = 759; em[1854] = 0; 
    em[1855] = 1; em[1856] = 8; em[1857] = 1; /* 1855: pointer.struct.asn1_string_st */
    	em[1858] = 759; em[1859] = 0; 
    em[1860] = 1; em[1861] = 8; em[1862] = 1; /* 1860: pointer.struct.asn1_string_st */
    	em[1863] = 759; em[1864] = 0; 
    em[1865] = 1; em[1866] = 8; em[1867] = 1; /* 1865: pointer.struct.asn1_string_st */
    	em[1868] = 759; em[1869] = 0; 
    em[1870] = 1; em[1871] = 8; em[1872] = 1; /* 1870: pointer.struct.asn1_string_st */
    	em[1873] = 759; em[1874] = 0; 
    em[1875] = 1; em[1876] = 8; em[1877] = 1; /* 1875: pointer.struct.ASN1_VALUE_st */
    	em[1878] = 1880; em[1879] = 0; 
    em[1880] = 0; em[1881] = 0; em[1882] = 0; /* 1880: struct.ASN1_VALUE_st */
    em[1883] = 1; em[1884] = 8; em[1885] = 1; /* 1883: pointer.struct.asn1_type_st */
    	em[1886] = 1888; em[1887] = 0; 
    em[1888] = 0; em[1889] = 16; em[1890] = 1; /* 1888: struct.asn1_type_st */
    	em[1891] = 1893; em[1892] = 8; 
    em[1893] = 0; em[1894] = 8; em[1895] = 20; /* 1893: union.unknown */
    	em[1896] = 77; em[1897] = 0; 
    	em[1898] = 181; em[1899] = 0; 
    	em[1900] = 1705; em[1901] = 0; 
    	em[1902] = 1936; em[1903] = 0; 
    	em[1904] = 176; em[1905] = 0; 
    	em[1906] = 171; em[1907] = 0; 
    	em[1908] = 166; em[1909] = 0; 
    	em[1910] = 642; em[1911] = 0; 
    	em[1912] = 161; em[1913] = 0; 
    	em[1914] = 156; em[1915] = 0; 
    	em[1916] = 151; em[1917] = 0; 
    	em[1918] = 146; em[1919] = 0; 
    	em[1920] = 1941; em[1921] = 0; 
    	em[1922] = 141; em[1923] = 0; 
    	em[1924] = 136; em[1925] = 0; 
    	em[1926] = 1946; em[1927] = 0; 
    	em[1928] = 118; em[1929] = 0; 
    	em[1930] = 181; em[1931] = 0; 
    	em[1932] = 181; em[1933] = 0; 
    	em[1934] = 110; em[1935] = 0; 
    em[1936] = 1; em[1937] = 8; em[1938] = 1; /* 1936: pointer.struct.asn1_string_st */
    	em[1939] = 123; em[1940] = 0; 
    em[1941] = 1; em[1942] = 8; em[1943] = 1; /* 1941: pointer.struct.asn1_string_st */
    	em[1944] = 123; em[1945] = 0; 
    em[1946] = 1; em[1947] = 8; em[1948] = 1; /* 1946: pointer.struct.asn1_string_st */
    	em[1949] = 123; em[1950] = 0; 
    args_addr->arg_entity_index[0] = 105;
    args_addr->arg_entity_index[1] = 862;
    args_addr->arg_entity_index[2] = 0;
    args_addr->arg_entity_index[3] = 82;
    args_addr->ret_entity_index = 867;
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

