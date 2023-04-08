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
    em[186] = 1; em[187] = 8; em[188] = 1; /* 186: pointer.struct.asn1_string_st */
    	em[189] = 123; em[190] = 0; 
    em[191] = 1; em[192] = 8; em[193] = 1; /* 191: pointer.struct.dh_st */
    	em[194] = 196; em[195] = 0; 
    em[196] = 0; em[197] = 144; em[198] = 12; /* 196: struct.dh_st */
    	em[199] = 223; em[200] = 8; 
    	em[201] = 223; em[202] = 16; 
    	em[203] = 223; em[204] = 32; 
    	em[205] = 223; em[206] = 40; 
    	em[207] = 243; em[208] = 56; 
    	em[209] = 223; em[210] = 64; 
    	em[211] = 223; em[212] = 72; 
    	em[213] = 128; em[214] = 80; 
    	em[215] = 223; em[216] = 96; 
    	em[217] = 257; em[218] = 112; 
    	em[219] = 271; em[220] = 128; 
    	em[221] = 307; em[222] = 136; 
    em[223] = 1; em[224] = 8; em[225] = 1; /* 223: pointer.struct.bignum_st */
    	em[226] = 228; em[227] = 0; 
    em[228] = 0; em[229] = 24; em[230] = 1; /* 228: struct.bignum_st */
    	em[231] = 233; em[232] = 0; 
    em[233] = 8884099; em[234] = 8; em[235] = 2; /* 233: pointer_to_array_of_pointers_to_stack */
    	em[236] = 240; em[237] = 0; 
    	em[238] = 99; em[239] = 12; 
    em[240] = 0; em[241] = 8; em[242] = 0; /* 240: long unsigned int */
    em[243] = 1; em[244] = 8; em[245] = 1; /* 243: pointer.struct.bn_mont_ctx_st */
    	em[246] = 248; em[247] = 0; 
    em[248] = 0; em[249] = 96; em[250] = 3; /* 248: struct.bn_mont_ctx_st */
    	em[251] = 228; em[252] = 8; 
    	em[253] = 228; em[254] = 32; 
    	em[255] = 228; em[256] = 56; 
    em[257] = 0; em[258] = 32; em[259] = 2; /* 257: struct.crypto_ex_data_st_fake */
    	em[260] = 264; em[261] = 8; 
    	em[262] = 102; em[263] = 24; 
    em[264] = 8884099; em[265] = 8; em[266] = 2; /* 264: pointer_to_array_of_pointers_to_stack */
    	em[267] = 82; em[268] = 0; 
    	em[269] = 99; em[270] = 20; 
    em[271] = 1; em[272] = 8; em[273] = 1; /* 271: pointer.struct.dh_method */
    	em[274] = 276; em[275] = 0; 
    em[276] = 0; em[277] = 72; em[278] = 8; /* 276: struct.dh_method */
    	em[279] = 51; em[280] = 0; 
    	em[281] = 295; em[282] = 8; 
    	em[283] = 298; em[284] = 16; 
    	em[285] = 301; em[286] = 24; 
    	em[287] = 295; em[288] = 32; 
    	em[289] = 295; em[290] = 40; 
    	em[291] = 77; em[292] = 56; 
    	em[293] = 304; em[294] = 64; 
    em[295] = 8884097; em[296] = 8; em[297] = 0; /* 295: pointer.func */
    em[298] = 8884097; em[299] = 8; em[300] = 0; /* 298: pointer.func */
    em[301] = 8884097; em[302] = 8; em[303] = 0; /* 301: pointer.func */
    em[304] = 8884097; em[305] = 8; em[306] = 0; /* 304: pointer.func */
    em[307] = 1; em[308] = 8; em[309] = 1; /* 307: pointer.struct.engine_st */
    	em[310] = 312; em[311] = 0; 
    em[312] = 0; em[313] = 216; em[314] = 24; /* 312: struct.engine_st */
    	em[315] = 51; em[316] = 0; 
    	em[317] = 51; em[318] = 8; 
    	em[319] = 363; em[320] = 16; 
    	em[321] = 418; em[322] = 24; 
    	em[323] = 469; em[324] = 32; 
    	em[325] = 505; em[326] = 40; 
    	em[327] = 522; em[328] = 48; 
    	em[329] = 549; em[330] = 56; 
    	em[331] = 584; em[332] = 64; 
    	em[333] = 592; em[334] = 72; 
    	em[335] = 595; em[336] = 80; 
    	em[337] = 598; em[338] = 88; 
    	em[339] = 601; em[340] = 96; 
    	em[341] = 604; em[342] = 104; 
    	em[343] = 604; em[344] = 112; 
    	em[345] = 604; em[346] = 120; 
    	em[347] = 607; em[348] = 128; 
    	em[349] = 610; em[350] = 136; 
    	em[351] = 610; em[352] = 144; 
    	em[353] = 613; em[354] = 152; 
    	em[355] = 616; em[356] = 160; 
    	em[357] = 628; em[358] = 184; 
    	em[359] = 642; em[360] = 200; 
    	em[361] = 642; em[362] = 208; 
    em[363] = 1; em[364] = 8; em[365] = 1; /* 363: pointer.struct.rsa_meth_st */
    	em[366] = 368; em[367] = 0; 
    em[368] = 0; em[369] = 112; em[370] = 13; /* 368: struct.rsa_meth_st */
    	em[371] = 51; em[372] = 0; 
    	em[373] = 397; em[374] = 8; 
    	em[375] = 397; em[376] = 16; 
    	em[377] = 397; em[378] = 24; 
    	em[379] = 397; em[380] = 32; 
    	em[381] = 400; em[382] = 40; 
    	em[383] = 403; em[384] = 48; 
    	em[385] = 406; em[386] = 56; 
    	em[387] = 406; em[388] = 64; 
    	em[389] = 77; em[390] = 80; 
    	em[391] = 409; em[392] = 88; 
    	em[393] = 412; em[394] = 96; 
    	em[395] = 415; em[396] = 104; 
    em[397] = 8884097; em[398] = 8; em[399] = 0; /* 397: pointer.func */
    em[400] = 8884097; em[401] = 8; em[402] = 0; /* 400: pointer.func */
    em[403] = 8884097; em[404] = 8; em[405] = 0; /* 403: pointer.func */
    em[406] = 8884097; em[407] = 8; em[408] = 0; /* 406: pointer.func */
    em[409] = 8884097; em[410] = 8; em[411] = 0; /* 409: pointer.func */
    em[412] = 8884097; em[413] = 8; em[414] = 0; /* 412: pointer.func */
    em[415] = 8884097; em[416] = 8; em[417] = 0; /* 415: pointer.func */
    em[418] = 1; em[419] = 8; em[420] = 1; /* 418: pointer.struct.dsa_method */
    	em[421] = 423; em[422] = 0; 
    em[423] = 0; em[424] = 96; em[425] = 11; /* 423: struct.dsa_method */
    	em[426] = 51; em[427] = 0; 
    	em[428] = 448; em[429] = 8; 
    	em[430] = 451; em[431] = 16; 
    	em[432] = 454; em[433] = 24; 
    	em[434] = 457; em[435] = 32; 
    	em[436] = 460; em[437] = 40; 
    	em[438] = 463; em[439] = 48; 
    	em[440] = 463; em[441] = 56; 
    	em[442] = 77; em[443] = 72; 
    	em[444] = 466; em[445] = 80; 
    	em[446] = 463; em[447] = 88; 
    em[448] = 8884097; em[449] = 8; em[450] = 0; /* 448: pointer.func */
    em[451] = 8884097; em[452] = 8; em[453] = 0; /* 451: pointer.func */
    em[454] = 8884097; em[455] = 8; em[456] = 0; /* 454: pointer.func */
    em[457] = 8884097; em[458] = 8; em[459] = 0; /* 457: pointer.func */
    em[460] = 8884097; em[461] = 8; em[462] = 0; /* 460: pointer.func */
    em[463] = 8884097; em[464] = 8; em[465] = 0; /* 463: pointer.func */
    em[466] = 8884097; em[467] = 8; em[468] = 0; /* 466: pointer.func */
    em[469] = 1; em[470] = 8; em[471] = 1; /* 469: pointer.struct.dh_method */
    	em[472] = 474; em[473] = 0; 
    em[474] = 0; em[475] = 72; em[476] = 8; /* 474: struct.dh_method */
    	em[477] = 51; em[478] = 0; 
    	em[479] = 493; em[480] = 8; 
    	em[481] = 496; em[482] = 16; 
    	em[483] = 499; em[484] = 24; 
    	em[485] = 493; em[486] = 32; 
    	em[487] = 493; em[488] = 40; 
    	em[489] = 77; em[490] = 56; 
    	em[491] = 502; em[492] = 64; 
    em[493] = 8884097; em[494] = 8; em[495] = 0; /* 493: pointer.func */
    em[496] = 8884097; em[497] = 8; em[498] = 0; /* 496: pointer.func */
    em[499] = 8884097; em[500] = 8; em[501] = 0; /* 499: pointer.func */
    em[502] = 8884097; em[503] = 8; em[504] = 0; /* 502: pointer.func */
    em[505] = 1; em[506] = 8; em[507] = 1; /* 505: pointer.struct.ecdh_method */
    	em[508] = 510; em[509] = 0; 
    em[510] = 0; em[511] = 32; em[512] = 3; /* 510: struct.ecdh_method */
    	em[513] = 51; em[514] = 0; 
    	em[515] = 519; em[516] = 8; 
    	em[517] = 77; em[518] = 24; 
    em[519] = 8884097; em[520] = 8; em[521] = 0; /* 519: pointer.func */
    em[522] = 1; em[523] = 8; em[524] = 1; /* 522: pointer.struct.ecdsa_method */
    	em[525] = 527; em[526] = 0; 
    em[527] = 0; em[528] = 48; em[529] = 5; /* 527: struct.ecdsa_method */
    	em[530] = 51; em[531] = 0; 
    	em[532] = 540; em[533] = 8; 
    	em[534] = 543; em[535] = 16; 
    	em[536] = 546; em[537] = 24; 
    	em[538] = 77; em[539] = 40; 
    em[540] = 8884097; em[541] = 8; em[542] = 0; /* 540: pointer.func */
    em[543] = 8884097; em[544] = 8; em[545] = 0; /* 543: pointer.func */
    em[546] = 8884097; em[547] = 8; em[548] = 0; /* 546: pointer.func */
    em[549] = 1; em[550] = 8; em[551] = 1; /* 549: pointer.struct.rand_meth_st */
    	em[552] = 554; em[553] = 0; 
    em[554] = 0; em[555] = 48; em[556] = 6; /* 554: struct.rand_meth_st */
    	em[557] = 569; em[558] = 0; 
    	em[559] = 572; em[560] = 8; 
    	em[561] = 575; em[562] = 16; 
    	em[563] = 578; em[564] = 24; 
    	em[565] = 572; em[566] = 32; 
    	em[567] = 581; em[568] = 40; 
    em[569] = 8884097; em[570] = 8; em[571] = 0; /* 569: pointer.func */
    em[572] = 8884097; em[573] = 8; em[574] = 0; /* 572: pointer.func */
    em[575] = 8884097; em[576] = 8; em[577] = 0; /* 575: pointer.func */
    em[578] = 8884097; em[579] = 8; em[580] = 0; /* 578: pointer.func */
    em[581] = 8884097; em[582] = 8; em[583] = 0; /* 581: pointer.func */
    em[584] = 1; em[585] = 8; em[586] = 1; /* 584: pointer.struct.store_method_st */
    	em[587] = 589; em[588] = 0; 
    em[589] = 0; em[590] = 0; em[591] = 0; /* 589: struct.store_method_st */
    em[592] = 8884097; em[593] = 8; em[594] = 0; /* 592: pointer.func */
    em[595] = 8884097; em[596] = 8; em[597] = 0; /* 595: pointer.func */
    em[598] = 8884097; em[599] = 8; em[600] = 0; /* 598: pointer.func */
    em[601] = 8884097; em[602] = 8; em[603] = 0; /* 601: pointer.func */
    em[604] = 8884097; em[605] = 8; em[606] = 0; /* 604: pointer.func */
    em[607] = 8884097; em[608] = 8; em[609] = 0; /* 607: pointer.func */
    em[610] = 8884097; em[611] = 8; em[612] = 0; /* 610: pointer.func */
    em[613] = 8884097; em[614] = 8; em[615] = 0; /* 613: pointer.func */
    em[616] = 1; em[617] = 8; em[618] = 1; /* 616: pointer.struct.ENGINE_CMD_DEFN_st */
    	em[619] = 621; em[620] = 0; 
    em[621] = 0; em[622] = 32; em[623] = 2; /* 621: struct.ENGINE_CMD_DEFN_st */
    	em[624] = 51; em[625] = 8; 
    	em[626] = 51; em[627] = 16; 
    em[628] = 0; em[629] = 32; em[630] = 2; /* 628: struct.crypto_ex_data_st_fake */
    	em[631] = 635; em[632] = 8; 
    	em[633] = 102; em[634] = 24; 
    em[635] = 8884099; em[636] = 8; em[637] = 2; /* 635: pointer_to_array_of_pointers_to_stack */
    	em[638] = 82; em[639] = 0; 
    	em[640] = 99; em[641] = 20; 
    em[642] = 1; em[643] = 8; em[644] = 1; /* 642: pointer.struct.engine_st */
    	em[645] = 312; em[646] = 0; 
    em[647] = 1; em[648] = 8; em[649] = 1; /* 647: pointer.struct.asn1_string_st */
    	em[650] = 123; em[651] = 0; 
    em[652] = 8884097; em[653] = 8; em[654] = 0; /* 652: pointer.func */
    em[655] = 8884097; em[656] = 8; em[657] = 0; /* 655: pointer.func */
    em[658] = 8884097; em[659] = 8; em[660] = 0; /* 658: pointer.func */
    em[661] = 1; em[662] = 8; em[663] = 1; /* 661: pointer.struct.dsa_method */
    	em[664] = 666; em[665] = 0; 
    em[666] = 0; em[667] = 96; em[668] = 11; /* 666: struct.dsa_method */
    	em[669] = 51; em[670] = 0; 
    	em[671] = 691; em[672] = 8; 
    	em[673] = 658; em[674] = 16; 
    	em[675] = 694; em[676] = 24; 
    	em[677] = 652; em[678] = 32; 
    	em[679] = 697; em[680] = 40; 
    	em[681] = 700; em[682] = 48; 
    	em[683] = 700; em[684] = 56; 
    	em[685] = 77; em[686] = 72; 
    	em[687] = 703; em[688] = 80; 
    	em[689] = 700; em[690] = 88; 
    em[691] = 8884097; em[692] = 8; em[693] = 0; /* 691: pointer.func */
    em[694] = 8884097; em[695] = 8; em[696] = 0; /* 694: pointer.func */
    em[697] = 8884097; em[698] = 8; em[699] = 0; /* 697: pointer.func */
    em[700] = 8884097; em[701] = 8; em[702] = 0; /* 700: pointer.func */
    em[703] = 8884097; em[704] = 8; em[705] = 0; /* 703: pointer.func */
    em[706] = 1; em[707] = 8; em[708] = 1; /* 706: pointer.struct.bn_mont_ctx_st */
    	em[709] = 711; em[710] = 0; 
    em[711] = 0; em[712] = 96; em[713] = 3; /* 711: struct.bn_mont_ctx_st */
    	em[714] = 720; em[715] = 8; 
    	em[716] = 720; em[717] = 32; 
    	em[718] = 720; em[719] = 56; 
    em[720] = 0; em[721] = 24; em[722] = 1; /* 720: struct.bignum_st */
    	em[723] = 725; em[724] = 0; 
    em[725] = 8884099; em[726] = 8; em[727] = 2; /* 725: pointer_to_array_of_pointers_to_stack */
    	em[728] = 240; em[729] = 0; 
    	em[730] = 99; em[731] = 12; 
    em[732] = 1; em[733] = 8; em[734] = 1; /* 732: pointer.struct.engine_st */
    	em[735] = 312; em[736] = 0; 
    em[737] = 0; em[738] = 0; em[739] = 1; /* 737: X509_ATTRIBUTE */
    	em[740] = 742; em[741] = 0; 
    em[742] = 0; em[743] = 24; em[744] = 2; /* 742: struct.x509_attributes_st */
    	em[745] = 749; em[746] = 0; 
    	em[747] = 768; em[748] = 16; 
    em[749] = 1; em[750] = 8; em[751] = 1; /* 749: pointer.struct.asn1_object_st */
    	em[752] = 754; em[753] = 0; 
    em[754] = 0; em[755] = 40; em[756] = 3; /* 754: struct.asn1_object_st */
    	em[757] = 51; em[758] = 0; 
    	em[759] = 51; em[760] = 8; 
    	em[761] = 763; em[762] = 24; 
    em[763] = 1; em[764] = 8; em[765] = 1; /* 763: pointer.unsigned char */
    	em[766] = 133; em[767] = 0; 
    em[768] = 0; em[769] = 8; em[770] = 3; /* 768: union.unknown */
    	em[771] = 77; em[772] = 0; 
    	em[773] = 777; em[774] = 0; 
    	em[775] = 956; em[776] = 0; 
    em[777] = 1; em[778] = 8; em[779] = 1; /* 777: pointer.struct.stack_st_ASN1_TYPE */
    	em[780] = 782; em[781] = 0; 
    em[782] = 0; em[783] = 32; em[784] = 2; /* 782: struct.stack_st_fake_ASN1_TYPE */
    	em[785] = 789; em[786] = 8; 
    	em[787] = 102; em[788] = 24; 
    em[789] = 8884099; em[790] = 8; em[791] = 2; /* 789: pointer_to_array_of_pointers_to_stack */
    	em[792] = 796; em[793] = 0; 
    	em[794] = 99; em[795] = 20; 
    em[796] = 0; em[797] = 8; em[798] = 1; /* 796: pointer.ASN1_TYPE */
    	em[799] = 801; em[800] = 0; 
    em[801] = 0; em[802] = 0; em[803] = 1; /* 801: ASN1_TYPE */
    	em[804] = 806; em[805] = 0; 
    em[806] = 0; em[807] = 16; em[808] = 1; /* 806: struct.asn1_type_st */
    	em[809] = 811; em[810] = 8; 
    em[811] = 0; em[812] = 8; em[813] = 20; /* 811: union.unknown */
    	em[814] = 77; em[815] = 0; 
    	em[816] = 854; em[817] = 0; 
    	em[818] = 864; em[819] = 0; 
    	em[820] = 878; em[821] = 0; 
    	em[822] = 883; em[823] = 0; 
    	em[824] = 888; em[825] = 0; 
    	em[826] = 893; em[827] = 0; 
    	em[828] = 898; em[829] = 0; 
    	em[830] = 903; em[831] = 0; 
    	em[832] = 908; em[833] = 0; 
    	em[834] = 913; em[835] = 0; 
    	em[836] = 918; em[837] = 0; 
    	em[838] = 923; em[839] = 0; 
    	em[840] = 928; em[841] = 0; 
    	em[842] = 933; em[843] = 0; 
    	em[844] = 938; em[845] = 0; 
    	em[846] = 943; em[847] = 0; 
    	em[848] = 854; em[849] = 0; 
    	em[850] = 854; em[851] = 0; 
    	em[852] = 948; em[853] = 0; 
    em[854] = 1; em[855] = 8; em[856] = 1; /* 854: pointer.struct.asn1_string_st */
    	em[857] = 859; em[858] = 0; 
    em[859] = 0; em[860] = 24; em[861] = 1; /* 859: struct.asn1_string_st */
    	em[862] = 128; em[863] = 8; 
    em[864] = 1; em[865] = 8; em[866] = 1; /* 864: pointer.struct.asn1_object_st */
    	em[867] = 869; em[868] = 0; 
    em[869] = 0; em[870] = 40; em[871] = 3; /* 869: struct.asn1_object_st */
    	em[872] = 51; em[873] = 0; 
    	em[874] = 51; em[875] = 8; 
    	em[876] = 763; em[877] = 24; 
    em[878] = 1; em[879] = 8; em[880] = 1; /* 878: pointer.struct.asn1_string_st */
    	em[881] = 859; em[882] = 0; 
    em[883] = 1; em[884] = 8; em[885] = 1; /* 883: pointer.struct.asn1_string_st */
    	em[886] = 859; em[887] = 0; 
    em[888] = 1; em[889] = 8; em[890] = 1; /* 888: pointer.struct.asn1_string_st */
    	em[891] = 859; em[892] = 0; 
    em[893] = 1; em[894] = 8; em[895] = 1; /* 893: pointer.struct.asn1_string_st */
    	em[896] = 859; em[897] = 0; 
    em[898] = 1; em[899] = 8; em[900] = 1; /* 898: pointer.struct.asn1_string_st */
    	em[901] = 859; em[902] = 0; 
    em[903] = 1; em[904] = 8; em[905] = 1; /* 903: pointer.struct.asn1_string_st */
    	em[906] = 859; em[907] = 0; 
    em[908] = 1; em[909] = 8; em[910] = 1; /* 908: pointer.struct.asn1_string_st */
    	em[911] = 859; em[912] = 0; 
    em[913] = 1; em[914] = 8; em[915] = 1; /* 913: pointer.struct.asn1_string_st */
    	em[916] = 859; em[917] = 0; 
    em[918] = 1; em[919] = 8; em[920] = 1; /* 918: pointer.struct.asn1_string_st */
    	em[921] = 859; em[922] = 0; 
    em[923] = 1; em[924] = 8; em[925] = 1; /* 923: pointer.struct.asn1_string_st */
    	em[926] = 859; em[927] = 0; 
    em[928] = 1; em[929] = 8; em[930] = 1; /* 928: pointer.struct.asn1_string_st */
    	em[931] = 859; em[932] = 0; 
    em[933] = 1; em[934] = 8; em[935] = 1; /* 933: pointer.struct.asn1_string_st */
    	em[936] = 859; em[937] = 0; 
    em[938] = 1; em[939] = 8; em[940] = 1; /* 938: pointer.struct.asn1_string_st */
    	em[941] = 859; em[942] = 0; 
    em[943] = 1; em[944] = 8; em[945] = 1; /* 943: pointer.struct.asn1_string_st */
    	em[946] = 859; em[947] = 0; 
    em[948] = 1; em[949] = 8; em[950] = 1; /* 948: pointer.struct.ASN1_VALUE_st */
    	em[951] = 953; em[952] = 0; 
    em[953] = 0; em[954] = 0; em[955] = 0; /* 953: struct.ASN1_VALUE_st */
    em[956] = 1; em[957] = 8; em[958] = 1; /* 956: pointer.struct.asn1_type_st */
    	em[959] = 961; em[960] = 0; 
    em[961] = 0; em[962] = 16; em[963] = 1; /* 961: struct.asn1_type_st */
    	em[964] = 966; em[965] = 8; 
    em[966] = 0; em[967] = 8; em[968] = 20; /* 966: union.unknown */
    	em[969] = 77; em[970] = 0; 
    	em[971] = 186; em[972] = 0; 
    	em[973] = 749; em[974] = 0; 
    	em[975] = 181; em[976] = 0; 
    	em[977] = 176; em[978] = 0; 
    	em[979] = 171; em[980] = 0; 
    	em[981] = 166; em[982] = 0; 
    	em[983] = 1009; em[984] = 0; 
    	em[985] = 161; em[986] = 0; 
    	em[987] = 156; em[988] = 0; 
    	em[989] = 151; em[990] = 0; 
    	em[991] = 146; em[992] = 0; 
    	em[993] = 1014; em[994] = 0; 
    	em[995] = 141; em[996] = 0; 
    	em[997] = 136; em[998] = 0; 
    	em[999] = 647; em[1000] = 0; 
    	em[1001] = 118; em[1002] = 0; 
    	em[1003] = 186; em[1004] = 0; 
    	em[1005] = 186; em[1006] = 0; 
    	em[1007] = 110; em[1008] = 0; 
    em[1009] = 1; em[1010] = 8; em[1011] = 1; /* 1009: pointer.struct.asn1_string_st */
    	em[1012] = 123; em[1013] = 0; 
    em[1014] = 1; em[1015] = 8; em[1016] = 1; /* 1014: pointer.struct.asn1_string_st */
    	em[1017] = 123; em[1018] = 0; 
    em[1019] = 1; em[1020] = 8; em[1021] = 1; /* 1019: pointer.struct.bignum_st */
    	em[1022] = 720; em[1023] = 0; 
    em[1024] = 0; em[1025] = 136; em[1026] = 11; /* 1024: struct.dsa_st */
    	em[1027] = 1019; em[1028] = 24; 
    	em[1029] = 1019; em[1030] = 32; 
    	em[1031] = 1019; em[1032] = 40; 
    	em[1033] = 1019; em[1034] = 48; 
    	em[1035] = 1019; em[1036] = 56; 
    	em[1037] = 1019; em[1038] = 64; 
    	em[1039] = 1019; em[1040] = 72; 
    	em[1041] = 706; em[1042] = 88; 
    	em[1043] = 1049; em[1044] = 104; 
    	em[1045] = 661; em[1046] = 120; 
    	em[1047] = 1063; em[1048] = 128; 
    em[1049] = 0; em[1050] = 32; em[1051] = 2; /* 1049: struct.crypto_ex_data_st_fake */
    	em[1052] = 1056; em[1053] = 8; 
    	em[1054] = 102; em[1055] = 24; 
    em[1056] = 8884099; em[1057] = 8; em[1058] = 2; /* 1056: pointer_to_array_of_pointers_to_stack */
    	em[1059] = 82; em[1060] = 0; 
    	em[1061] = 99; em[1062] = 20; 
    em[1063] = 1; em[1064] = 8; em[1065] = 1; /* 1063: pointer.struct.engine_st */
    	em[1066] = 312; em[1067] = 0; 
    em[1068] = 8884097; em[1069] = 8; em[1070] = 0; /* 1068: pointer.func */
    em[1071] = 0; em[1072] = 88; em[1073] = 7; /* 1071: struct.bn_blinding_st */
    	em[1074] = 1088; em[1075] = 0; 
    	em[1076] = 1088; em[1077] = 8; 
    	em[1078] = 1088; em[1079] = 16; 
    	em[1080] = 1088; em[1081] = 24; 
    	em[1082] = 1105; em[1083] = 40; 
    	em[1084] = 1110; em[1085] = 72; 
    	em[1086] = 1124; em[1087] = 80; 
    em[1088] = 1; em[1089] = 8; em[1090] = 1; /* 1088: pointer.struct.bignum_st */
    	em[1091] = 1093; em[1092] = 0; 
    em[1093] = 0; em[1094] = 24; em[1095] = 1; /* 1093: struct.bignum_st */
    	em[1096] = 1098; em[1097] = 0; 
    em[1098] = 8884099; em[1099] = 8; em[1100] = 2; /* 1098: pointer_to_array_of_pointers_to_stack */
    	em[1101] = 240; em[1102] = 0; 
    	em[1103] = 99; em[1104] = 12; 
    em[1105] = 0; em[1106] = 16; em[1107] = 1; /* 1105: struct.crypto_threadid_st */
    	em[1108] = 82; em[1109] = 0; 
    em[1110] = 1; em[1111] = 8; em[1112] = 1; /* 1110: pointer.struct.bn_mont_ctx_st */
    	em[1113] = 1115; em[1114] = 0; 
    em[1115] = 0; em[1116] = 96; em[1117] = 3; /* 1115: struct.bn_mont_ctx_st */
    	em[1118] = 1093; em[1119] = 8; 
    	em[1120] = 1093; em[1121] = 32; 
    	em[1122] = 1093; em[1123] = 56; 
    em[1124] = 8884097; em[1125] = 8; em[1126] = 0; /* 1124: pointer.func */
    em[1127] = 0; em[1128] = 96; em[1129] = 3; /* 1127: struct.bn_mont_ctx_st */
    	em[1130] = 1136; em[1131] = 8; 
    	em[1132] = 1136; em[1133] = 32; 
    	em[1134] = 1136; em[1135] = 56; 
    em[1136] = 0; em[1137] = 24; em[1138] = 1; /* 1136: struct.bignum_st */
    	em[1139] = 1141; em[1140] = 0; 
    em[1141] = 8884099; em[1142] = 8; em[1143] = 2; /* 1141: pointer_to_array_of_pointers_to_stack */
    	em[1144] = 240; em[1145] = 0; 
    	em[1146] = 99; em[1147] = 12; 
    em[1148] = 1; em[1149] = 8; em[1150] = 1; /* 1148: pointer.struct.ec_method_st */
    	em[1151] = 1153; em[1152] = 0; 
    em[1153] = 0; em[1154] = 304; em[1155] = 37; /* 1153: struct.ec_method_st */
    	em[1156] = 1230; em[1157] = 8; 
    	em[1158] = 1233; em[1159] = 16; 
    	em[1160] = 1233; em[1161] = 24; 
    	em[1162] = 1236; em[1163] = 32; 
    	em[1164] = 1239; em[1165] = 40; 
    	em[1166] = 1242; em[1167] = 48; 
    	em[1168] = 1245; em[1169] = 56; 
    	em[1170] = 1248; em[1171] = 64; 
    	em[1172] = 1251; em[1173] = 72; 
    	em[1174] = 1254; em[1175] = 80; 
    	em[1176] = 1254; em[1177] = 88; 
    	em[1178] = 1257; em[1179] = 96; 
    	em[1180] = 1260; em[1181] = 104; 
    	em[1182] = 1263; em[1183] = 112; 
    	em[1184] = 1266; em[1185] = 120; 
    	em[1186] = 1269; em[1187] = 128; 
    	em[1188] = 1272; em[1189] = 136; 
    	em[1190] = 1275; em[1191] = 144; 
    	em[1192] = 1278; em[1193] = 152; 
    	em[1194] = 1281; em[1195] = 160; 
    	em[1196] = 1284; em[1197] = 168; 
    	em[1198] = 1287; em[1199] = 176; 
    	em[1200] = 1290; em[1201] = 184; 
    	em[1202] = 1293; em[1203] = 192; 
    	em[1204] = 655; em[1205] = 200; 
    	em[1206] = 1296; em[1207] = 208; 
    	em[1208] = 1290; em[1209] = 216; 
    	em[1210] = 1299; em[1211] = 224; 
    	em[1212] = 1302; em[1213] = 232; 
    	em[1214] = 1305; em[1215] = 240; 
    	em[1216] = 1245; em[1217] = 248; 
    	em[1218] = 1308; em[1219] = 256; 
    	em[1220] = 1311; em[1221] = 264; 
    	em[1222] = 1308; em[1223] = 272; 
    	em[1224] = 1311; em[1225] = 280; 
    	em[1226] = 1311; em[1227] = 288; 
    	em[1228] = 1314; em[1229] = 296; 
    em[1230] = 8884097; em[1231] = 8; em[1232] = 0; /* 1230: pointer.func */
    em[1233] = 8884097; em[1234] = 8; em[1235] = 0; /* 1233: pointer.func */
    em[1236] = 8884097; em[1237] = 8; em[1238] = 0; /* 1236: pointer.func */
    em[1239] = 8884097; em[1240] = 8; em[1241] = 0; /* 1239: pointer.func */
    em[1242] = 8884097; em[1243] = 8; em[1244] = 0; /* 1242: pointer.func */
    em[1245] = 8884097; em[1246] = 8; em[1247] = 0; /* 1245: pointer.func */
    em[1248] = 8884097; em[1249] = 8; em[1250] = 0; /* 1248: pointer.func */
    em[1251] = 8884097; em[1252] = 8; em[1253] = 0; /* 1251: pointer.func */
    em[1254] = 8884097; em[1255] = 8; em[1256] = 0; /* 1254: pointer.func */
    em[1257] = 8884097; em[1258] = 8; em[1259] = 0; /* 1257: pointer.func */
    em[1260] = 8884097; em[1261] = 8; em[1262] = 0; /* 1260: pointer.func */
    em[1263] = 8884097; em[1264] = 8; em[1265] = 0; /* 1263: pointer.func */
    em[1266] = 8884097; em[1267] = 8; em[1268] = 0; /* 1266: pointer.func */
    em[1269] = 8884097; em[1270] = 8; em[1271] = 0; /* 1269: pointer.func */
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
    em[1317] = 1; em[1318] = 8; em[1319] = 1; /* 1317: pointer.struct.bignum_st */
    	em[1320] = 1136; em[1321] = 0; 
    em[1322] = 8884097; em[1323] = 8; em[1324] = 0; /* 1322: pointer.func */
    em[1325] = 8884097; em[1326] = 8; em[1327] = 0; /* 1325: pointer.func */
    em[1328] = 8884097; em[1329] = 8; em[1330] = 0; /* 1328: pointer.func */
    em[1331] = 1; em[1332] = 8; em[1333] = 1; /* 1331: pointer.struct.dsa_st */
    	em[1334] = 1024; em[1335] = 0; 
    em[1336] = 8884097; em[1337] = 8; em[1338] = 0; /* 1336: pointer.func */
    em[1339] = 8884097; em[1340] = 8; em[1341] = 0; /* 1339: pointer.func */
    em[1342] = 8884097; em[1343] = 8; em[1344] = 0; /* 1342: pointer.func */
    em[1345] = 8884097; em[1346] = 8; em[1347] = 0; /* 1345: pointer.func */
    em[1348] = 1; em[1349] = 8; em[1350] = 1; /* 1348: pointer.struct.bn_mont_ctx_st */
    	em[1351] = 1127; em[1352] = 0; 
    em[1353] = 8884097; em[1354] = 8; em[1355] = 0; /* 1353: pointer.func */
    em[1356] = 8884097; em[1357] = 8; em[1358] = 0; /* 1356: pointer.func */
    em[1359] = 0; em[1360] = 168; em[1361] = 17; /* 1359: struct.rsa_st */
    	em[1362] = 1396; em[1363] = 16; 
    	em[1364] = 1433; em[1365] = 24; 
    	em[1366] = 1317; em[1367] = 32; 
    	em[1368] = 1317; em[1369] = 40; 
    	em[1370] = 1317; em[1371] = 48; 
    	em[1372] = 1317; em[1373] = 56; 
    	em[1374] = 1317; em[1375] = 64; 
    	em[1376] = 1317; em[1377] = 72; 
    	em[1378] = 1317; em[1379] = 80; 
    	em[1380] = 1317; em[1381] = 88; 
    	em[1382] = 1438; em[1383] = 96; 
    	em[1384] = 1348; em[1385] = 120; 
    	em[1386] = 1348; em[1387] = 128; 
    	em[1388] = 1348; em[1389] = 136; 
    	em[1390] = 77; em[1391] = 144; 
    	em[1392] = 1452; em[1393] = 152; 
    	em[1394] = 1452; em[1395] = 160; 
    em[1396] = 1; em[1397] = 8; em[1398] = 1; /* 1396: pointer.struct.rsa_meth_st */
    	em[1399] = 1401; em[1400] = 0; 
    em[1401] = 0; em[1402] = 112; em[1403] = 13; /* 1401: struct.rsa_meth_st */
    	em[1404] = 51; em[1405] = 0; 
    	em[1406] = 1430; em[1407] = 8; 
    	em[1408] = 1430; em[1409] = 16; 
    	em[1410] = 1430; em[1411] = 24; 
    	em[1412] = 1430; em[1413] = 32; 
    	em[1414] = 1345; em[1415] = 40; 
    	em[1416] = 1339; em[1417] = 48; 
    	em[1418] = 1325; em[1419] = 56; 
    	em[1420] = 1325; em[1421] = 64; 
    	em[1422] = 77; em[1423] = 80; 
    	em[1424] = 1328; em[1425] = 88; 
    	em[1426] = 1336; em[1427] = 96; 
    	em[1428] = 1322; em[1429] = 104; 
    em[1430] = 8884097; em[1431] = 8; em[1432] = 0; /* 1430: pointer.func */
    em[1433] = 1; em[1434] = 8; em[1435] = 1; /* 1433: pointer.struct.engine_st */
    	em[1436] = 312; em[1437] = 0; 
    em[1438] = 0; em[1439] = 32; em[1440] = 2; /* 1438: struct.crypto_ex_data_st_fake */
    	em[1441] = 1445; em[1442] = 8; 
    	em[1443] = 102; em[1444] = 24; 
    em[1445] = 8884099; em[1446] = 8; em[1447] = 2; /* 1445: pointer_to_array_of_pointers_to_stack */
    	em[1448] = 82; em[1449] = 0; 
    	em[1450] = 99; em[1451] = 20; 
    em[1452] = 1; em[1453] = 8; em[1454] = 1; /* 1452: pointer.struct.bn_blinding_st */
    	em[1455] = 1071; em[1456] = 0; 
    em[1457] = 8884097; em[1458] = 8; em[1459] = 0; /* 1457: pointer.func */
    em[1460] = 1; em[1461] = 8; em[1462] = 1; /* 1460: pointer.struct.ec_method_st */
    	em[1463] = 1465; em[1464] = 0; 
    em[1465] = 0; em[1466] = 304; em[1467] = 37; /* 1465: struct.ec_method_st */
    	em[1468] = 1542; em[1469] = 8; 
    	em[1470] = 1545; em[1471] = 16; 
    	em[1472] = 1545; em[1473] = 24; 
    	em[1474] = 1548; em[1475] = 32; 
    	em[1476] = 1551; em[1477] = 40; 
    	em[1478] = 1554; em[1479] = 48; 
    	em[1480] = 1557; em[1481] = 56; 
    	em[1482] = 1560; em[1483] = 64; 
    	em[1484] = 1563; em[1485] = 72; 
    	em[1486] = 1566; em[1487] = 80; 
    	em[1488] = 1566; em[1489] = 88; 
    	em[1490] = 1457; em[1491] = 96; 
    	em[1492] = 1569; em[1493] = 104; 
    	em[1494] = 1572; em[1495] = 112; 
    	em[1496] = 1068; em[1497] = 120; 
    	em[1498] = 1575; em[1499] = 128; 
    	em[1500] = 1578; em[1501] = 136; 
    	em[1502] = 1581; em[1503] = 144; 
    	em[1504] = 1584; em[1505] = 152; 
    	em[1506] = 1587; em[1507] = 160; 
    	em[1508] = 1590; em[1509] = 168; 
    	em[1510] = 1593; em[1511] = 176; 
    	em[1512] = 1596; em[1513] = 184; 
    	em[1514] = 1599; em[1515] = 192; 
    	em[1516] = 1353; em[1517] = 200; 
    	em[1518] = 1602; em[1519] = 208; 
    	em[1520] = 1596; em[1521] = 216; 
    	em[1522] = 1605; em[1523] = 224; 
    	em[1524] = 1608; em[1525] = 232; 
    	em[1526] = 1611; em[1527] = 240; 
    	em[1528] = 1557; em[1529] = 248; 
    	em[1530] = 1614; em[1531] = 256; 
    	em[1532] = 1617; em[1533] = 264; 
    	em[1534] = 1614; em[1535] = 272; 
    	em[1536] = 1617; em[1537] = 280; 
    	em[1538] = 1617; em[1539] = 288; 
    	em[1540] = 1620; em[1541] = 296; 
    em[1542] = 8884097; em[1543] = 8; em[1544] = 0; /* 1542: pointer.func */
    em[1545] = 8884097; em[1546] = 8; em[1547] = 0; /* 1545: pointer.func */
    em[1548] = 8884097; em[1549] = 8; em[1550] = 0; /* 1548: pointer.func */
    em[1551] = 8884097; em[1552] = 8; em[1553] = 0; /* 1551: pointer.func */
    em[1554] = 8884097; em[1555] = 8; em[1556] = 0; /* 1554: pointer.func */
    em[1557] = 8884097; em[1558] = 8; em[1559] = 0; /* 1557: pointer.func */
    em[1560] = 8884097; em[1561] = 8; em[1562] = 0; /* 1560: pointer.func */
    em[1563] = 8884097; em[1564] = 8; em[1565] = 0; /* 1563: pointer.func */
    em[1566] = 8884097; em[1567] = 8; em[1568] = 0; /* 1566: pointer.func */
    em[1569] = 8884097; em[1570] = 8; em[1571] = 0; /* 1569: pointer.func */
    em[1572] = 8884097; em[1573] = 8; em[1574] = 0; /* 1572: pointer.func */
    em[1575] = 8884097; em[1576] = 8; em[1577] = 0; /* 1575: pointer.func */
    em[1578] = 8884097; em[1579] = 8; em[1580] = 0; /* 1578: pointer.func */
    em[1581] = 8884097; em[1582] = 8; em[1583] = 0; /* 1581: pointer.func */
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
    em[1632] = 0; em[1633] = 1; em[1634] = 0; /* 1632: char */
    em[1635] = 0; em[1636] = 24; em[1637] = 1; /* 1635: struct.bignum_st */
    	em[1638] = 1640; em[1639] = 0; 
    em[1640] = 8884099; em[1641] = 8; em[1642] = 2; /* 1640: pointer_to_array_of_pointers_to_stack */
    	em[1643] = 240; em[1644] = 0; 
    	em[1645] = 99; em[1646] = 12; 
    em[1647] = 8884097; em[1648] = 8; em[1649] = 0; /* 1647: pointer.func */
    em[1650] = 0; em[1651] = 56; em[1652] = 4; /* 1650: struct.evp_pkey_st */
    	em[1653] = 1661; em[1654] = 16; 
    	em[1655] = 732; em[1656] = 24; 
    	em[1657] = 1747; em[1658] = 32; 
    	em[1659] = 1917; em[1660] = 48; 
    em[1661] = 1; em[1662] = 8; em[1663] = 1; /* 1661: pointer.struct.evp_pkey_asn1_method_st */
    	em[1664] = 1666; em[1665] = 0; 
    em[1666] = 0; em[1667] = 208; em[1668] = 24; /* 1666: struct.evp_pkey_asn1_method_st */
    	em[1669] = 77; em[1670] = 16; 
    	em[1671] = 77; em[1672] = 24; 
    	em[1673] = 1717; em[1674] = 32; 
    	em[1675] = 1720; em[1676] = 40; 
    	em[1677] = 1342; em[1678] = 48; 
    	em[1679] = 1723; em[1680] = 56; 
    	em[1681] = 1726; em[1682] = 64; 
    	em[1683] = 1729; em[1684] = 72; 
    	em[1685] = 1723; em[1686] = 80; 
    	em[1687] = 1356; em[1688] = 88; 
    	em[1689] = 1356; em[1690] = 96; 
    	em[1691] = 1629; em[1692] = 104; 
    	em[1693] = 1732; em[1694] = 112; 
    	em[1695] = 1356; em[1696] = 120; 
    	em[1697] = 1735; em[1698] = 128; 
    	em[1699] = 1342; em[1700] = 136; 
    	em[1701] = 1723; em[1702] = 144; 
    	em[1703] = 1738; em[1704] = 152; 
    	em[1705] = 1741; em[1706] = 160; 
    	em[1707] = 1623; em[1708] = 168; 
    	em[1709] = 1629; em[1710] = 176; 
    	em[1711] = 1732; em[1712] = 184; 
    	em[1713] = 1647; em[1714] = 192; 
    	em[1715] = 1744; em[1716] = 200; 
    em[1717] = 8884097; em[1718] = 8; em[1719] = 0; /* 1717: pointer.func */
    em[1720] = 8884097; em[1721] = 8; em[1722] = 0; /* 1720: pointer.func */
    em[1723] = 8884097; em[1724] = 8; em[1725] = 0; /* 1723: pointer.func */
    em[1726] = 8884097; em[1727] = 8; em[1728] = 0; /* 1726: pointer.func */
    em[1729] = 8884097; em[1730] = 8; em[1731] = 0; /* 1729: pointer.func */
    em[1732] = 8884097; em[1733] = 8; em[1734] = 0; /* 1732: pointer.func */
    em[1735] = 8884097; em[1736] = 8; em[1737] = 0; /* 1735: pointer.func */
    em[1738] = 8884097; em[1739] = 8; em[1740] = 0; /* 1738: pointer.func */
    em[1741] = 8884097; em[1742] = 8; em[1743] = 0; /* 1741: pointer.func */
    em[1744] = 8884097; em[1745] = 8; em[1746] = 0; /* 1744: pointer.func */
    em[1747] = 0; em[1748] = 8; em[1749] = 6; /* 1747: union.union_of_evp_pkey_st */
    	em[1750] = 82; em[1751] = 0; 
    	em[1752] = 1762; em[1753] = 6; 
    	em[1754] = 1331; em[1755] = 116; 
    	em[1756] = 191; em[1757] = 28; 
    	em[1758] = 1767; em[1759] = 408; 
    	em[1760] = 99; em[1761] = 0; 
    em[1762] = 1; em[1763] = 8; em[1764] = 1; /* 1762: pointer.struct.rsa_st */
    	em[1765] = 1359; em[1766] = 0; 
    em[1767] = 1; em[1768] = 8; em[1769] = 1; /* 1767: pointer.struct.ec_key_st */
    	em[1770] = 1772; em[1771] = 0; 
    em[1772] = 0; em[1773] = 56; em[1774] = 4; /* 1772: struct.ec_key_st */
    	em[1775] = 1783; em[1776] = 8; 
    	em[1777] = 1872; em[1778] = 16; 
    	em[1779] = 1877; em[1780] = 24; 
    	em[1781] = 1894; em[1782] = 48; 
    em[1783] = 1; em[1784] = 8; em[1785] = 1; /* 1783: pointer.struct.ec_group_st */
    	em[1786] = 1788; em[1787] = 0; 
    em[1788] = 0; em[1789] = 232; em[1790] = 12; /* 1788: struct.ec_group_st */
    	em[1791] = 1460; em[1792] = 0; 
    	em[1793] = 1815; em[1794] = 8; 
    	em[1795] = 1831; em[1796] = 16; 
    	em[1797] = 1831; em[1798] = 40; 
    	em[1799] = 128; em[1800] = 80; 
    	em[1801] = 1843; em[1802] = 96; 
    	em[1803] = 1831; em[1804] = 104; 
    	em[1805] = 1831; em[1806] = 152; 
    	em[1807] = 1831; em[1808] = 176; 
    	em[1809] = 82; em[1810] = 208; 
    	em[1811] = 82; em[1812] = 216; 
    	em[1813] = 1626; em[1814] = 224; 
    em[1815] = 1; em[1816] = 8; em[1817] = 1; /* 1815: pointer.struct.ec_point_st */
    	em[1818] = 1820; em[1819] = 0; 
    em[1820] = 0; em[1821] = 88; em[1822] = 4; /* 1820: struct.ec_point_st */
    	em[1823] = 1148; em[1824] = 0; 
    	em[1825] = 1635; em[1826] = 8; 
    	em[1827] = 1635; em[1828] = 32; 
    	em[1829] = 1635; em[1830] = 56; 
    em[1831] = 0; em[1832] = 24; em[1833] = 1; /* 1831: struct.bignum_st */
    	em[1834] = 1836; em[1835] = 0; 
    em[1836] = 8884099; em[1837] = 8; em[1838] = 2; /* 1836: pointer_to_array_of_pointers_to_stack */
    	em[1839] = 240; em[1840] = 0; 
    	em[1841] = 99; em[1842] = 12; 
    em[1843] = 1; em[1844] = 8; em[1845] = 1; /* 1843: pointer.struct.ec_extra_data_st */
    	em[1846] = 1848; em[1847] = 0; 
    em[1848] = 0; em[1849] = 40; em[1850] = 5; /* 1848: struct.ec_extra_data_st */
    	em[1851] = 1861; em[1852] = 0; 
    	em[1853] = 82; em[1854] = 8; 
    	em[1855] = 1866; em[1856] = 16; 
    	em[1857] = 1869; em[1858] = 24; 
    	em[1859] = 1869; em[1860] = 32; 
    em[1861] = 1; em[1862] = 8; em[1863] = 1; /* 1861: pointer.struct.ec_extra_data_st */
    	em[1864] = 1848; em[1865] = 0; 
    em[1866] = 8884097; em[1867] = 8; em[1868] = 0; /* 1866: pointer.func */
    em[1869] = 8884097; em[1870] = 8; em[1871] = 0; /* 1869: pointer.func */
    em[1872] = 1; em[1873] = 8; em[1874] = 1; /* 1872: pointer.struct.ec_point_st */
    	em[1875] = 1820; em[1876] = 0; 
    em[1877] = 1; em[1878] = 8; em[1879] = 1; /* 1877: pointer.struct.bignum_st */
    	em[1880] = 1882; em[1881] = 0; 
    em[1882] = 0; em[1883] = 24; em[1884] = 1; /* 1882: struct.bignum_st */
    	em[1885] = 1887; em[1886] = 0; 
    em[1887] = 8884099; em[1888] = 8; em[1889] = 2; /* 1887: pointer_to_array_of_pointers_to_stack */
    	em[1890] = 240; em[1891] = 0; 
    	em[1892] = 99; em[1893] = 12; 
    em[1894] = 1; em[1895] = 8; em[1896] = 1; /* 1894: pointer.struct.ec_extra_data_st */
    	em[1897] = 1899; em[1898] = 0; 
    em[1899] = 0; em[1900] = 40; em[1901] = 5; /* 1899: struct.ec_extra_data_st */
    	em[1902] = 1912; em[1903] = 0; 
    	em[1904] = 82; em[1905] = 8; 
    	em[1906] = 1866; em[1907] = 16; 
    	em[1908] = 1869; em[1909] = 24; 
    	em[1910] = 1869; em[1911] = 32; 
    em[1912] = 1; em[1913] = 8; em[1914] = 1; /* 1912: pointer.struct.ec_extra_data_st */
    	em[1915] = 1899; em[1916] = 0; 
    em[1917] = 1; em[1918] = 8; em[1919] = 1; /* 1917: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[1920] = 1922; em[1921] = 0; 
    em[1922] = 0; em[1923] = 32; em[1924] = 2; /* 1922: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[1925] = 1929; em[1926] = 8; 
    	em[1927] = 102; em[1928] = 24; 
    em[1929] = 8884099; em[1930] = 8; em[1931] = 2; /* 1929: pointer_to_array_of_pointers_to_stack */
    	em[1932] = 1936; em[1933] = 0; 
    	em[1934] = 99; em[1935] = 20; 
    em[1936] = 0; em[1937] = 8; em[1938] = 1; /* 1936: pointer.X509_ATTRIBUTE */
    	em[1939] = 737; em[1940] = 0; 
    em[1941] = 1; em[1942] = 8; em[1943] = 1; /* 1941: pointer.struct.evp_pkey_st */
    	em[1944] = 1650; em[1945] = 0; 
    em[1946] = 1; em[1947] = 8; em[1948] = 1; /* 1946: pointer.pointer.struct.evp_pkey_st */
    	em[1949] = 1941; em[1950] = 0; 
    args_addr->arg_entity_index[0] = 105;
    args_addr->arg_entity_index[1] = 1946;
    args_addr->arg_entity_index[2] = 0;
    args_addr->arg_entity_index[3] = 82;
    args_addr->ret_entity_index = 1941;
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

