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

int bb_HMAC_Init_ex(HMAC_CTX * arg_a,const void * arg_b,int arg_c,const EVP_MD * arg_d,ENGINE * arg_e);

int HMAC_Init_ex(HMAC_CTX * arg_a,const void * arg_b,int arg_c,const EVP_MD * arg_d,ENGINE * arg_e) 
{
    unsigned long in_lib = syscall(890);
    printf("HMAC_Init_ex called %lu\n", in_lib);
    if (!in_lib)
        return bb_HMAC_Init_ex(arg_a,arg_b,arg_c,arg_d,arg_e);
    else {
        int (*orig_HMAC_Init_ex)(HMAC_CTX *,const void *,int,const EVP_MD *,ENGINE *);
        orig_HMAC_Init_ex = dlsym(RTLD_NEXT, "HMAC_Init_ex");
        return orig_HMAC_Init_ex(arg_a,arg_b,arg_c,arg_d,arg_e);
    }
}

int bb_HMAC_Init_ex(HMAC_CTX * arg_a,const void * arg_b,int arg_c,const EVP_MD * arg_d,ENGINE * arg_e) 
{
    int ret;

    struct lib_enter_args *args_addr = malloc(sizeof(struct lib_enter_args));
    memset(args_addr, 0, sizeof(struct lib_enter_args));
    args_addr->num_args = 0;
    uint32_t *em = args_addr->entity_metadata;
    em[0] = 1; em[1] = 8; em[2] = 1; /* 0: pointer.int */
    	em[3] = 5; em[4] = 0; 
    em[5] = 0; em[6] = 4; em[7] = 0; /* 5: int */
    em[8] = 8884097; em[9] = 8; em[10] = 0; /* 8: pointer.func */
    em[11] = 0; em[12] = 0; em[13] = 0; /* 11: struct.ASN1_VALUE_st */
    em[14] = 1; em[15] = 8; em[16] = 1; /* 14: pointer.struct.ASN1_VALUE_st */
    	em[17] = 11; em[18] = 0; 
    em[19] = 1; em[20] = 8; em[21] = 1; /* 19: pointer.struct.asn1_string_st */
    	em[22] = 24; em[23] = 0; 
    em[24] = 0; em[25] = 24; em[26] = 1; /* 24: struct.asn1_string_st */
    	em[27] = 29; em[28] = 8; 
    em[29] = 1; em[30] = 8; em[31] = 1; /* 29: pointer.unsigned char */
    	em[32] = 34; em[33] = 0; 
    em[34] = 0; em[35] = 1; em[36] = 0; /* 34: unsigned char */
    em[37] = 1; em[38] = 8; em[39] = 1; /* 37: pointer.struct.asn1_string_st */
    	em[40] = 24; em[41] = 0; 
    em[42] = 1; em[43] = 8; em[44] = 1; /* 42: pointer.struct.asn1_string_st */
    	em[45] = 24; em[46] = 0; 
    em[47] = 1; em[48] = 8; em[49] = 1; /* 47: pointer.struct.asn1_string_st */
    	em[50] = 24; em[51] = 0; 
    em[52] = 1; em[53] = 8; em[54] = 1; /* 52: pointer.struct.asn1_string_st */
    	em[55] = 24; em[56] = 0; 
    em[57] = 8884097; em[58] = 8; em[59] = 0; /* 57: pointer.func */
    em[60] = 0; em[61] = 24; em[62] = 1; /* 60: struct.asn1_string_st */
    	em[63] = 29; em[64] = 8; 
    em[65] = 8884097; em[66] = 8; em[67] = 0; /* 65: pointer.func */
    em[68] = 8884101; em[69] = 8; em[70] = 6; /* 68: union.union_of_evp_pkey_st */
    	em[71] = 83; em[72] = 0; 
    	em[73] = 86; em[74] = 6; 
    	em[75] = 639; em[76] = 116; 
    	em[77] = 770; em[78] = 28; 
    	em[79] = 852; em[80] = 408; 
    	em[81] = 5; em[82] = 0; 
    em[83] = 0; em[84] = 8; em[85] = 0; /* 83: pointer.void */
    em[86] = 1; em[87] = 8; em[88] = 1; /* 86: pointer.struct.rsa_st */
    	em[89] = 91; em[90] = 0; 
    em[91] = 0; em[92] = 168; em[93] = 17; /* 91: struct.rsa_st */
    	em[94] = 128; em[95] = 16; 
    	em[96] = 187; em[97] = 24; 
    	em[98] = 530; em[99] = 32; 
    	em[100] = 530; em[101] = 40; 
    	em[102] = 530; em[103] = 48; 
    	em[104] = 530; em[105] = 56; 
    	em[106] = 530; em[107] = 64; 
    	em[108] = 530; em[109] = 72; 
    	em[110] = 530; em[111] = 80; 
    	em[112] = 530; em[113] = 88; 
    	em[114] = 550; em[115] = 96; 
    	em[116] = 564; em[117] = 120; 
    	em[118] = 564; em[119] = 128; 
    	em[120] = 564; em[121] = 136; 
    	em[122] = 173; em[123] = 144; 
    	em[124] = 578; em[125] = 152; 
    	em[126] = 578; em[127] = 160; 
    em[128] = 1; em[129] = 8; em[130] = 1; /* 128: pointer.struct.rsa_meth_st */
    	em[131] = 133; em[132] = 0; 
    em[133] = 0; em[134] = 112; em[135] = 13; /* 133: struct.rsa_meth_st */
    	em[136] = 162; em[137] = 0; 
    	em[138] = 167; em[139] = 8; 
    	em[140] = 167; em[141] = 16; 
    	em[142] = 167; em[143] = 24; 
    	em[144] = 167; em[145] = 32; 
    	em[146] = 170; em[147] = 40; 
    	em[148] = 65; em[149] = 48; 
    	em[150] = 57; em[151] = 56; 
    	em[152] = 57; em[153] = 64; 
    	em[154] = 173; em[155] = 80; 
    	em[156] = 178; em[157] = 88; 
    	em[158] = 181; em[159] = 96; 
    	em[160] = 184; em[161] = 104; 
    em[162] = 1; em[163] = 8; em[164] = 1; /* 162: pointer.char */
    	em[165] = 8884096; em[166] = 0; 
    em[167] = 8884097; em[168] = 8; em[169] = 0; /* 167: pointer.func */
    em[170] = 8884097; em[171] = 8; em[172] = 0; /* 170: pointer.func */
    em[173] = 1; em[174] = 8; em[175] = 1; /* 173: pointer.char */
    	em[176] = 8884096; em[177] = 0; 
    em[178] = 8884097; em[179] = 8; em[180] = 0; /* 178: pointer.func */
    em[181] = 8884097; em[182] = 8; em[183] = 0; /* 181: pointer.func */
    em[184] = 8884097; em[185] = 8; em[186] = 0; /* 184: pointer.func */
    em[187] = 1; em[188] = 8; em[189] = 1; /* 187: pointer.struct.engine_st */
    	em[190] = 192; em[191] = 0; 
    em[192] = 0; em[193] = 216; em[194] = 24; /* 192: struct.engine_st */
    	em[195] = 162; em[196] = 0; 
    	em[197] = 162; em[198] = 8; 
    	em[199] = 243; em[200] = 16; 
    	em[201] = 298; em[202] = 24; 
    	em[203] = 349; em[204] = 32; 
    	em[205] = 385; em[206] = 40; 
    	em[207] = 402; em[208] = 48; 
    	em[209] = 429; em[210] = 56; 
    	em[211] = 464; em[212] = 64; 
    	em[213] = 472; em[214] = 72; 
    	em[215] = 475; em[216] = 80; 
    	em[217] = 478; em[218] = 88; 
    	em[219] = 481; em[220] = 96; 
    	em[221] = 484; em[222] = 104; 
    	em[223] = 484; em[224] = 112; 
    	em[225] = 484; em[226] = 120; 
    	em[227] = 487; em[228] = 128; 
    	em[229] = 490; em[230] = 136; 
    	em[231] = 490; em[232] = 144; 
    	em[233] = 493; em[234] = 152; 
    	em[235] = 496; em[236] = 160; 
    	em[237] = 508; em[238] = 184; 
    	em[239] = 525; em[240] = 200; 
    	em[241] = 525; em[242] = 208; 
    em[243] = 1; em[244] = 8; em[245] = 1; /* 243: pointer.struct.rsa_meth_st */
    	em[246] = 248; em[247] = 0; 
    em[248] = 0; em[249] = 112; em[250] = 13; /* 248: struct.rsa_meth_st */
    	em[251] = 162; em[252] = 0; 
    	em[253] = 277; em[254] = 8; 
    	em[255] = 277; em[256] = 16; 
    	em[257] = 277; em[258] = 24; 
    	em[259] = 277; em[260] = 32; 
    	em[261] = 280; em[262] = 40; 
    	em[263] = 283; em[264] = 48; 
    	em[265] = 286; em[266] = 56; 
    	em[267] = 286; em[268] = 64; 
    	em[269] = 173; em[270] = 80; 
    	em[271] = 289; em[272] = 88; 
    	em[273] = 292; em[274] = 96; 
    	em[275] = 295; em[276] = 104; 
    em[277] = 8884097; em[278] = 8; em[279] = 0; /* 277: pointer.func */
    em[280] = 8884097; em[281] = 8; em[282] = 0; /* 280: pointer.func */
    em[283] = 8884097; em[284] = 8; em[285] = 0; /* 283: pointer.func */
    em[286] = 8884097; em[287] = 8; em[288] = 0; /* 286: pointer.func */
    em[289] = 8884097; em[290] = 8; em[291] = 0; /* 289: pointer.func */
    em[292] = 8884097; em[293] = 8; em[294] = 0; /* 292: pointer.func */
    em[295] = 8884097; em[296] = 8; em[297] = 0; /* 295: pointer.func */
    em[298] = 1; em[299] = 8; em[300] = 1; /* 298: pointer.struct.dsa_method */
    	em[301] = 303; em[302] = 0; 
    em[303] = 0; em[304] = 96; em[305] = 11; /* 303: struct.dsa_method */
    	em[306] = 162; em[307] = 0; 
    	em[308] = 328; em[309] = 8; 
    	em[310] = 331; em[311] = 16; 
    	em[312] = 334; em[313] = 24; 
    	em[314] = 337; em[315] = 32; 
    	em[316] = 340; em[317] = 40; 
    	em[318] = 343; em[319] = 48; 
    	em[320] = 343; em[321] = 56; 
    	em[322] = 173; em[323] = 72; 
    	em[324] = 346; em[325] = 80; 
    	em[326] = 343; em[327] = 88; 
    em[328] = 8884097; em[329] = 8; em[330] = 0; /* 328: pointer.func */
    em[331] = 8884097; em[332] = 8; em[333] = 0; /* 331: pointer.func */
    em[334] = 8884097; em[335] = 8; em[336] = 0; /* 334: pointer.func */
    em[337] = 8884097; em[338] = 8; em[339] = 0; /* 337: pointer.func */
    em[340] = 8884097; em[341] = 8; em[342] = 0; /* 340: pointer.func */
    em[343] = 8884097; em[344] = 8; em[345] = 0; /* 343: pointer.func */
    em[346] = 8884097; em[347] = 8; em[348] = 0; /* 346: pointer.func */
    em[349] = 1; em[350] = 8; em[351] = 1; /* 349: pointer.struct.dh_method */
    	em[352] = 354; em[353] = 0; 
    em[354] = 0; em[355] = 72; em[356] = 8; /* 354: struct.dh_method */
    	em[357] = 162; em[358] = 0; 
    	em[359] = 373; em[360] = 8; 
    	em[361] = 376; em[362] = 16; 
    	em[363] = 379; em[364] = 24; 
    	em[365] = 373; em[366] = 32; 
    	em[367] = 373; em[368] = 40; 
    	em[369] = 173; em[370] = 56; 
    	em[371] = 382; em[372] = 64; 
    em[373] = 8884097; em[374] = 8; em[375] = 0; /* 373: pointer.func */
    em[376] = 8884097; em[377] = 8; em[378] = 0; /* 376: pointer.func */
    em[379] = 8884097; em[380] = 8; em[381] = 0; /* 379: pointer.func */
    em[382] = 8884097; em[383] = 8; em[384] = 0; /* 382: pointer.func */
    em[385] = 1; em[386] = 8; em[387] = 1; /* 385: pointer.struct.ecdh_method */
    	em[388] = 390; em[389] = 0; 
    em[390] = 0; em[391] = 32; em[392] = 3; /* 390: struct.ecdh_method */
    	em[393] = 162; em[394] = 0; 
    	em[395] = 399; em[396] = 8; 
    	em[397] = 173; em[398] = 24; 
    em[399] = 8884097; em[400] = 8; em[401] = 0; /* 399: pointer.func */
    em[402] = 1; em[403] = 8; em[404] = 1; /* 402: pointer.struct.ecdsa_method */
    	em[405] = 407; em[406] = 0; 
    em[407] = 0; em[408] = 48; em[409] = 5; /* 407: struct.ecdsa_method */
    	em[410] = 162; em[411] = 0; 
    	em[412] = 420; em[413] = 8; 
    	em[414] = 423; em[415] = 16; 
    	em[416] = 426; em[417] = 24; 
    	em[418] = 173; em[419] = 40; 
    em[420] = 8884097; em[421] = 8; em[422] = 0; /* 420: pointer.func */
    em[423] = 8884097; em[424] = 8; em[425] = 0; /* 423: pointer.func */
    em[426] = 8884097; em[427] = 8; em[428] = 0; /* 426: pointer.func */
    em[429] = 1; em[430] = 8; em[431] = 1; /* 429: pointer.struct.rand_meth_st */
    	em[432] = 434; em[433] = 0; 
    em[434] = 0; em[435] = 48; em[436] = 6; /* 434: struct.rand_meth_st */
    	em[437] = 449; em[438] = 0; 
    	em[439] = 452; em[440] = 8; 
    	em[441] = 455; em[442] = 16; 
    	em[443] = 458; em[444] = 24; 
    	em[445] = 452; em[446] = 32; 
    	em[447] = 461; em[448] = 40; 
    em[449] = 8884097; em[450] = 8; em[451] = 0; /* 449: pointer.func */
    em[452] = 8884097; em[453] = 8; em[454] = 0; /* 452: pointer.func */
    em[455] = 8884097; em[456] = 8; em[457] = 0; /* 455: pointer.func */
    em[458] = 8884097; em[459] = 8; em[460] = 0; /* 458: pointer.func */
    em[461] = 8884097; em[462] = 8; em[463] = 0; /* 461: pointer.func */
    em[464] = 1; em[465] = 8; em[466] = 1; /* 464: pointer.struct.store_method_st */
    	em[467] = 469; em[468] = 0; 
    em[469] = 0; em[470] = 0; em[471] = 0; /* 469: struct.store_method_st */
    em[472] = 8884097; em[473] = 8; em[474] = 0; /* 472: pointer.func */
    em[475] = 8884097; em[476] = 8; em[477] = 0; /* 475: pointer.func */
    em[478] = 8884097; em[479] = 8; em[480] = 0; /* 478: pointer.func */
    em[481] = 8884097; em[482] = 8; em[483] = 0; /* 481: pointer.func */
    em[484] = 8884097; em[485] = 8; em[486] = 0; /* 484: pointer.func */
    em[487] = 8884097; em[488] = 8; em[489] = 0; /* 487: pointer.func */
    em[490] = 8884097; em[491] = 8; em[492] = 0; /* 490: pointer.func */
    em[493] = 8884097; em[494] = 8; em[495] = 0; /* 493: pointer.func */
    em[496] = 1; em[497] = 8; em[498] = 1; /* 496: pointer.struct.ENGINE_CMD_DEFN_st */
    	em[499] = 501; em[500] = 0; 
    em[501] = 0; em[502] = 32; em[503] = 2; /* 501: struct.ENGINE_CMD_DEFN_st */
    	em[504] = 162; em[505] = 8; 
    	em[506] = 162; em[507] = 16; 
    em[508] = 0; em[509] = 32; em[510] = 2; /* 508: struct.crypto_ex_data_st_fake */
    	em[511] = 515; em[512] = 8; 
    	em[513] = 522; em[514] = 24; 
    em[515] = 8884099; em[516] = 8; em[517] = 2; /* 515: pointer_to_array_of_pointers_to_stack */
    	em[518] = 83; em[519] = 0; 
    	em[520] = 5; em[521] = 20; 
    em[522] = 8884097; em[523] = 8; em[524] = 0; /* 522: pointer.func */
    em[525] = 1; em[526] = 8; em[527] = 1; /* 525: pointer.struct.engine_st */
    	em[528] = 192; em[529] = 0; 
    em[530] = 1; em[531] = 8; em[532] = 1; /* 530: pointer.struct.bignum_st */
    	em[533] = 535; em[534] = 0; 
    em[535] = 0; em[536] = 24; em[537] = 1; /* 535: struct.bignum_st */
    	em[538] = 540; em[539] = 0; 
    em[540] = 8884099; em[541] = 8; em[542] = 2; /* 540: pointer_to_array_of_pointers_to_stack */
    	em[543] = 547; em[544] = 0; 
    	em[545] = 5; em[546] = 12; 
    em[547] = 0; em[548] = 8; em[549] = 0; /* 547: long unsigned int */
    em[550] = 0; em[551] = 32; em[552] = 2; /* 550: struct.crypto_ex_data_st_fake */
    	em[553] = 557; em[554] = 8; 
    	em[555] = 522; em[556] = 24; 
    em[557] = 8884099; em[558] = 8; em[559] = 2; /* 557: pointer_to_array_of_pointers_to_stack */
    	em[560] = 83; em[561] = 0; 
    	em[562] = 5; em[563] = 20; 
    em[564] = 1; em[565] = 8; em[566] = 1; /* 564: pointer.struct.bn_mont_ctx_st */
    	em[567] = 569; em[568] = 0; 
    em[569] = 0; em[570] = 96; em[571] = 3; /* 569: struct.bn_mont_ctx_st */
    	em[572] = 535; em[573] = 8; 
    	em[574] = 535; em[575] = 32; 
    	em[576] = 535; em[577] = 56; 
    em[578] = 1; em[579] = 8; em[580] = 1; /* 578: pointer.struct.bn_blinding_st */
    	em[581] = 583; em[582] = 0; 
    em[583] = 0; em[584] = 88; em[585] = 7; /* 583: struct.bn_blinding_st */
    	em[586] = 600; em[587] = 0; 
    	em[588] = 600; em[589] = 8; 
    	em[590] = 600; em[591] = 16; 
    	em[592] = 600; em[593] = 24; 
    	em[594] = 617; em[595] = 40; 
    	em[596] = 622; em[597] = 72; 
    	em[598] = 636; em[599] = 80; 
    em[600] = 1; em[601] = 8; em[602] = 1; /* 600: pointer.struct.bignum_st */
    	em[603] = 605; em[604] = 0; 
    em[605] = 0; em[606] = 24; em[607] = 1; /* 605: struct.bignum_st */
    	em[608] = 610; em[609] = 0; 
    em[610] = 8884099; em[611] = 8; em[612] = 2; /* 610: pointer_to_array_of_pointers_to_stack */
    	em[613] = 547; em[614] = 0; 
    	em[615] = 5; em[616] = 12; 
    em[617] = 0; em[618] = 16; em[619] = 1; /* 617: struct.crypto_threadid_st */
    	em[620] = 83; em[621] = 0; 
    em[622] = 1; em[623] = 8; em[624] = 1; /* 622: pointer.struct.bn_mont_ctx_st */
    	em[625] = 627; em[626] = 0; 
    em[627] = 0; em[628] = 96; em[629] = 3; /* 627: struct.bn_mont_ctx_st */
    	em[630] = 605; em[631] = 8; 
    	em[632] = 605; em[633] = 32; 
    	em[634] = 605; em[635] = 56; 
    em[636] = 8884097; em[637] = 8; em[638] = 0; /* 636: pointer.func */
    em[639] = 1; em[640] = 8; em[641] = 1; /* 639: pointer.struct.dsa_st */
    	em[642] = 644; em[643] = 0; 
    em[644] = 0; em[645] = 136; em[646] = 11; /* 644: struct.dsa_st */
    	em[647] = 669; em[648] = 24; 
    	em[649] = 669; em[650] = 32; 
    	em[651] = 669; em[652] = 40; 
    	em[653] = 669; em[654] = 48; 
    	em[655] = 669; em[656] = 56; 
    	em[657] = 669; em[658] = 64; 
    	em[659] = 669; em[660] = 72; 
    	em[661] = 686; em[662] = 88; 
    	em[663] = 700; em[664] = 104; 
    	em[665] = 714; em[666] = 120; 
    	em[667] = 765; em[668] = 128; 
    em[669] = 1; em[670] = 8; em[671] = 1; /* 669: pointer.struct.bignum_st */
    	em[672] = 674; em[673] = 0; 
    em[674] = 0; em[675] = 24; em[676] = 1; /* 674: struct.bignum_st */
    	em[677] = 679; em[678] = 0; 
    em[679] = 8884099; em[680] = 8; em[681] = 2; /* 679: pointer_to_array_of_pointers_to_stack */
    	em[682] = 547; em[683] = 0; 
    	em[684] = 5; em[685] = 12; 
    em[686] = 1; em[687] = 8; em[688] = 1; /* 686: pointer.struct.bn_mont_ctx_st */
    	em[689] = 691; em[690] = 0; 
    em[691] = 0; em[692] = 96; em[693] = 3; /* 691: struct.bn_mont_ctx_st */
    	em[694] = 674; em[695] = 8; 
    	em[696] = 674; em[697] = 32; 
    	em[698] = 674; em[699] = 56; 
    em[700] = 0; em[701] = 32; em[702] = 2; /* 700: struct.crypto_ex_data_st_fake */
    	em[703] = 707; em[704] = 8; 
    	em[705] = 522; em[706] = 24; 
    em[707] = 8884099; em[708] = 8; em[709] = 2; /* 707: pointer_to_array_of_pointers_to_stack */
    	em[710] = 83; em[711] = 0; 
    	em[712] = 5; em[713] = 20; 
    em[714] = 1; em[715] = 8; em[716] = 1; /* 714: pointer.struct.dsa_method */
    	em[717] = 719; em[718] = 0; 
    em[719] = 0; em[720] = 96; em[721] = 11; /* 719: struct.dsa_method */
    	em[722] = 162; em[723] = 0; 
    	em[724] = 744; em[725] = 8; 
    	em[726] = 747; em[727] = 16; 
    	em[728] = 750; em[729] = 24; 
    	em[730] = 753; em[731] = 32; 
    	em[732] = 756; em[733] = 40; 
    	em[734] = 759; em[735] = 48; 
    	em[736] = 759; em[737] = 56; 
    	em[738] = 173; em[739] = 72; 
    	em[740] = 762; em[741] = 80; 
    	em[742] = 759; em[743] = 88; 
    em[744] = 8884097; em[745] = 8; em[746] = 0; /* 744: pointer.func */
    em[747] = 8884097; em[748] = 8; em[749] = 0; /* 747: pointer.func */
    em[750] = 8884097; em[751] = 8; em[752] = 0; /* 750: pointer.func */
    em[753] = 8884097; em[754] = 8; em[755] = 0; /* 753: pointer.func */
    em[756] = 8884097; em[757] = 8; em[758] = 0; /* 756: pointer.func */
    em[759] = 8884097; em[760] = 8; em[761] = 0; /* 759: pointer.func */
    em[762] = 8884097; em[763] = 8; em[764] = 0; /* 762: pointer.func */
    em[765] = 1; em[766] = 8; em[767] = 1; /* 765: pointer.struct.engine_st */
    	em[768] = 192; em[769] = 0; 
    em[770] = 1; em[771] = 8; em[772] = 1; /* 770: pointer.struct.dh_st */
    	em[773] = 775; em[774] = 0; 
    em[775] = 0; em[776] = 144; em[777] = 12; /* 775: struct.dh_st */
    	em[778] = 530; em[779] = 8; 
    	em[780] = 530; em[781] = 16; 
    	em[782] = 530; em[783] = 32; 
    	em[784] = 530; em[785] = 40; 
    	em[786] = 564; em[787] = 56; 
    	em[788] = 530; em[789] = 64; 
    	em[790] = 530; em[791] = 72; 
    	em[792] = 29; em[793] = 80; 
    	em[794] = 530; em[795] = 96; 
    	em[796] = 802; em[797] = 112; 
    	em[798] = 816; em[799] = 128; 
    	em[800] = 187; em[801] = 136; 
    em[802] = 0; em[803] = 32; em[804] = 2; /* 802: struct.crypto_ex_data_st_fake */
    	em[805] = 809; em[806] = 8; 
    	em[807] = 522; em[808] = 24; 
    em[809] = 8884099; em[810] = 8; em[811] = 2; /* 809: pointer_to_array_of_pointers_to_stack */
    	em[812] = 83; em[813] = 0; 
    	em[814] = 5; em[815] = 20; 
    em[816] = 1; em[817] = 8; em[818] = 1; /* 816: pointer.struct.dh_method */
    	em[819] = 821; em[820] = 0; 
    em[821] = 0; em[822] = 72; em[823] = 8; /* 821: struct.dh_method */
    	em[824] = 162; em[825] = 0; 
    	em[826] = 840; em[827] = 8; 
    	em[828] = 843; em[829] = 16; 
    	em[830] = 846; em[831] = 24; 
    	em[832] = 840; em[833] = 32; 
    	em[834] = 840; em[835] = 40; 
    	em[836] = 173; em[837] = 56; 
    	em[838] = 849; em[839] = 64; 
    em[840] = 8884097; em[841] = 8; em[842] = 0; /* 840: pointer.func */
    em[843] = 8884097; em[844] = 8; em[845] = 0; /* 843: pointer.func */
    em[846] = 8884097; em[847] = 8; em[848] = 0; /* 846: pointer.func */
    em[849] = 8884097; em[850] = 8; em[851] = 0; /* 849: pointer.func */
    em[852] = 1; em[853] = 8; em[854] = 1; /* 852: pointer.struct.ec_key_st */
    	em[855] = 857; em[856] = 0; 
    em[857] = 0; em[858] = 56; em[859] = 4; /* 857: struct.ec_key_st */
    	em[860] = 868; em[861] = 8; 
    	em[862] = 1132; em[863] = 16; 
    	em[864] = 1137; em[865] = 24; 
    	em[866] = 1154; em[867] = 48; 
    em[868] = 1; em[869] = 8; em[870] = 1; /* 868: pointer.struct.ec_group_st */
    	em[871] = 873; em[872] = 0; 
    em[873] = 0; em[874] = 232; em[875] = 12; /* 873: struct.ec_group_st */
    	em[876] = 900; em[877] = 0; 
    	em[878] = 1072; em[879] = 8; 
    	em[880] = 1088; em[881] = 16; 
    	em[882] = 1088; em[883] = 40; 
    	em[884] = 29; em[885] = 80; 
    	em[886] = 1100; em[887] = 96; 
    	em[888] = 1088; em[889] = 104; 
    	em[890] = 1088; em[891] = 152; 
    	em[892] = 1088; em[893] = 176; 
    	em[894] = 83; em[895] = 208; 
    	em[896] = 83; em[897] = 216; 
    	em[898] = 1129; em[899] = 224; 
    em[900] = 1; em[901] = 8; em[902] = 1; /* 900: pointer.struct.ec_method_st */
    	em[903] = 905; em[904] = 0; 
    em[905] = 0; em[906] = 304; em[907] = 37; /* 905: struct.ec_method_st */
    	em[908] = 982; em[909] = 8; 
    	em[910] = 985; em[911] = 16; 
    	em[912] = 985; em[913] = 24; 
    	em[914] = 988; em[915] = 32; 
    	em[916] = 991; em[917] = 40; 
    	em[918] = 994; em[919] = 48; 
    	em[920] = 997; em[921] = 56; 
    	em[922] = 1000; em[923] = 64; 
    	em[924] = 1003; em[925] = 72; 
    	em[926] = 1006; em[927] = 80; 
    	em[928] = 1006; em[929] = 88; 
    	em[930] = 1009; em[931] = 96; 
    	em[932] = 1012; em[933] = 104; 
    	em[934] = 1015; em[935] = 112; 
    	em[936] = 1018; em[937] = 120; 
    	em[938] = 1021; em[939] = 128; 
    	em[940] = 1024; em[941] = 136; 
    	em[942] = 1027; em[943] = 144; 
    	em[944] = 1030; em[945] = 152; 
    	em[946] = 1033; em[947] = 160; 
    	em[948] = 1036; em[949] = 168; 
    	em[950] = 1039; em[951] = 176; 
    	em[952] = 1042; em[953] = 184; 
    	em[954] = 1045; em[955] = 192; 
    	em[956] = 1048; em[957] = 200; 
    	em[958] = 1051; em[959] = 208; 
    	em[960] = 1042; em[961] = 216; 
    	em[962] = 1054; em[963] = 224; 
    	em[964] = 1057; em[965] = 232; 
    	em[966] = 1060; em[967] = 240; 
    	em[968] = 997; em[969] = 248; 
    	em[970] = 1063; em[971] = 256; 
    	em[972] = 1066; em[973] = 264; 
    	em[974] = 1063; em[975] = 272; 
    	em[976] = 1066; em[977] = 280; 
    	em[978] = 1066; em[979] = 288; 
    	em[980] = 1069; em[981] = 296; 
    em[982] = 8884097; em[983] = 8; em[984] = 0; /* 982: pointer.func */
    em[985] = 8884097; em[986] = 8; em[987] = 0; /* 985: pointer.func */
    em[988] = 8884097; em[989] = 8; em[990] = 0; /* 988: pointer.func */
    em[991] = 8884097; em[992] = 8; em[993] = 0; /* 991: pointer.func */
    em[994] = 8884097; em[995] = 8; em[996] = 0; /* 994: pointer.func */
    em[997] = 8884097; em[998] = 8; em[999] = 0; /* 997: pointer.func */
    em[1000] = 8884097; em[1001] = 8; em[1002] = 0; /* 1000: pointer.func */
    em[1003] = 8884097; em[1004] = 8; em[1005] = 0; /* 1003: pointer.func */
    em[1006] = 8884097; em[1007] = 8; em[1008] = 0; /* 1006: pointer.func */
    em[1009] = 8884097; em[1010] = 8; em[1011] = 0; /* 1009: pointer.func */
    em[1012] = 8884097; em[1013] = 8; em[1014] = 0; /* 1012: pointer.func */
    em[1015] = 8884097; em[1016] = 8; em[1017] = 0; /* 1015: pointer.func */
    em[1018] = 8884097; em[1019] = 8; em[1020] = 0; /* 1018: pointer.func */
    em[1021] = 8884097; em[1022] = 8; em[1023] = 0; /* 1021: pointer.func */
    em[1024] = 8884097; em[1025] = 8; em[1026] = 0; /* 1024: pointer.func */
    em[1027] = 8884097; em[1028] = 8; em[1029] = 0; /* 1027: pointer.func */
    em[1030] = 8884097; em[1031] = 8; em[1032] = 0; /* 1030: pointer.func */
    em[1033] = 8884097; em[1034] = 8; em[1035] = 0; /* 1033: pointer.func */
    em[1036] = 8884097; em[1037] = 8; em[1038] = 0; /* 1036: pointer.func */
    em[1039] = 8884097; em[1040] = 8; em[1041] = 0; /* 1039: pointer.func */
    em[1042] = 8884097; em[1043] = 8; em[1044] = 0; /* 1042: pointer.func */
    em[1045] = 8884097; em[1046] = 8; em[1047] = 0; /* 1045: pointer.func */
    em[1048] = 8884097; em[1049] = 8; em[1050] = 0; /* 1048: pointer.func */
    em[1051] = 8884097; em[1052] = 8; em[1053] = 0; /* 1051: pointer.func */
    em[1054] = 8884097; em[1055] = 8; em[1056] = 0; /* 1054: pointer.func */
    em[1057] = 8884097; em[1058] = 8; em[1059] = 0; /* 1057: pointer.func */
    em[1060] = 8884097; em[1061] = 8; em[1062] = 0; /* 1060: pointer.func */
    em[1063] = 8884097; em[1064] = 8; em[1065] = 0; /* 1063: pointer.func */
    em[1066] = 8884097; em[1067] = 8; em[1068] = 0; /* 1066: pointer.func */
    em[1069] = 8884097; em[1070] = 8; em[1071] = 0; /* 1069: pointer.func */
    em[1072] = 1; em[1073] = 8; em[1074] = 1; /* 1072: pointer.struct.ec_point_st */
    	em[1075] = 1077; em[1076] = 0; 
    em[1077] = 0; em[1078] = 88; em[1079] = 4; /* 1077: struct.ec_point_st */
    	em[1080] = 900; em[1081] = 0; 
    	em[1082] = 1088; em[1083] = 8; 
    	em[1084] = 1088; em[1085] = 32; 
    	em[1086] = 1088; em[1087] = 56; 
    em[1088] = 0; em[1089] = 24; em[1090] = 1; /* 1088: struct.bignum_st */
    	em[1091] = 1093; em[1092] = 0; 
    em[1093] = 8884099; em[1094] = 8; em[1095] = 2; /* 1093: pointer_to_array_of_pointers_to_stack */
    	em[1096] = 547; em[1097] = 0; 
    	em[1098] = 5; em[1099] = 12; 
    em[1100] = 1; em[1101] = 8; em[1102] = 1; /* 1100: pointer.struct.ec_extra_data_st */
    	em[1103] = 1105; em[1104] = 0; 
    em[1105] = 0; em[1106] = 40; em[1107] = 5; /* 1105: struct.ec_extra_data_st */
    	em[1108] = 1118; em[1109] = 0; 
    	em[1110] = 83; em[1111] = 8; 
    	em[1112] = 1123; em[1113] = 16; 
    	em[1114] = 1126; em[1115] = 24; 
    	em[1116] = 1126; em[1117] = 32; 
    em[1118] = 1; em[1119] = 8; em[1120] = 1; /* 1118: pointer.struct.ec_extra_data_st */
    	em[1121] = 1105; em[1122] = 0; 
    em[1123] = 8884097; em[1124] = 8; em[1125] = 0; /* 1123: pointer.func */
    em[1126] = 8884097; em[1127] = 8; em[1128] = 0; /* 1126: pointer.func */
    em[1129] = 8884097; em[1130] = 8; em[1131] = 0; /* 1129: pointer.func */
    em[1132] = 1; em[1133] = 8; em[1134] = 1; /* 1132: pointer.struct.ec_point_st */
    	em[1135] = 1077; em[1136] = 0; 
    em[1137] = 1; em[1138] = 8; em[1139] = 1; /* 1137: pointer.struct.bignum_st */
    	em[1140] = 1142; em[1141] = 0; 
    em[1142] = 0; em[1143] = 24; em[1144] = 1; /* 1142: struct.bignum_st */
    	em[1145] = 1147; em[1146] = 0; 
    em[1147] = 8884099; em[1148] = 8; em[1149] = 2; /* 1147: pointer_to_array_of_pointers_to_stack */
    	em[1150] = 547; em[1151] = 0; 
    	em[1152] = 5; em[1153] = 12; 
    em[1154] = 1; em[1155] = 8; em[1156] = 1; /* 1154: pointer.struct.ec_extra_data_st */
    	em[1157] = 1159; em[1158] = 0; 
    em[1159] = 0; em[1160] = 40; em[1161] = 5; /* 1159: struct.ec_extra_data_st */
    	em[1162] = 1172; em[1163] = 0; 
    	em[1164] = 83; em[1165] = 8; 
    	em[1166] = 1123; em[1167] = 16; 
    	em[1168] = 1126; em[1169] = 24; 
    	em[1170] = 1126; em[1171] = 32; 
    em[1172] = 1; em[1173] = 8; em[1174] = 1; /* 1172: pointer.struct.ec_extra_data_st */
    	em[1175] = 1159; em[1176] = 0; 
    em[1177] = 8884097; em[1178] = 8; em[1179] = 0; /* 1177: pointer.func */
    em[1180] = 8884097; em[1181] = 8; em[1182] = 0; /* 1180: pointer.func */
    em[1183] = 8884097; em[1184] = 8; em[1185] = 0; /* 1183: pointer.func */
    em[1186] = 8884097; em[1187] = 8; em[1188] = 0; /* 1186: pointer.func */
    em[1189] = 0; em[1190] = 208; em[1191] = 24; /* 1189: struct.evp_pkey_asn1_method_st */
    	em[1192] = 173; em[1193] = 16; 
    	em[1194] = 173; em[1195] = 24; 
    	em[1196] = 1240; em[1197] = 32; 
    	em[1198] = 1243; em[1199] = 40; 
    	em[1200] = 1246; em[1201] = 48; 
    	em[1202] = 1249; em[1203] = 56; 
    	em[1204] = 1252; em[1205] = 64; 
    	em[1206] = 1255; em[1207] = 72; 
    	em[1208] = 1249; em[1209] = 80; 
    	em[1210] = 1186; em[1211] = 88; 
    	em[1212] = 1186; em[1213] = 96; 
    	em[1214] = 1258; em[1215] = 104; 
    	em[1216] = 1261; em[1217] = 112; 
    	em[1218] = 1186; em[1219] = 120; 
    	em[1220] = 1264; em[1221] = 128; 
    	em[1222] = 1246; em[1223] = 136; 
    	em[1224] = 1249; em[1225] = 144; 
    	em[1226] = 1267; em[1227] = 152; 
    	em[1228] = 1270; em[1229] = 160; 
    	em[1230] = 1183; em[1231] = 168; 
    	em[1232] = 1258; em[1233] = 176; 
    	em[1234] = 1261; em[1235] = 184; 
    	em[1236] = 1273; em[1237] = 192; 
    	em[1238] = 1177; em[1239] = 200; 
    em[1240] = 8884097; em[1241] = 8; em[1242] = 0; /* 1240: pointer.func */
    em[1243] = 8884097; em[1244] = 8; em[1245] = 0; /* 1243: pointer.func */
    em[1246] = 8884097; em[1247] = 8; em[1248] = 0; /* 1246: pointer.func */
    em[1249] = 8884097; em[1250] = 8; em[1251] = 0; /* 1249: pointer.func */
    em[1252] = 8884097; em[1253] = 8; em[1254] = 0; /* 1252: pointer.func */
    em[1255] = 8884097; em[1256] = 8; em[1257] = 0; /* 1255: pointer.func */
    em[1258] = 8884097; em[1259] = 8; em[1260] = 0; /* 1258: pointer.func */
    em[1261] = 8884097; em[1262] = 8; em[1263] = 0; /* 1261: pointer.func */
    em[1264] = 8884097; em[1265] = 8; em[1266] = 0; /* 1264: pointer.func */
    em[1267] = 8884097; em[1268] = 8; em[1269] = 0; /* 1267: pointer.func */
    em[1270] = 8884097; em[1271] = 8; em[1272] = 0; /* 1270: pointer.func */
    em[1273] = 8884097; em[1274] = 8; em[1275] = 0; /* 1273: pointer.func */
    em[1276] = 8884097; em[1277] = 8; em[1278] = 0; /* 1276: pointer.func */
    em[1279] = 0; em[1280] = 40; em[1281] = 3; /* 1279: struct.asn1_object_st */
    	em[1282] = 162; em[1283] = 0; 
    	em[1284] = 162; em[1285] = 8; 
    	em[1286] = 1288; em[1287] = 24; 
    em[1288] = 1; em[1289] = 8; em[1290] = 1; /* 1288: pointer.unsigned char */
    	em[1291] = 34; em[1292] = 0; 
    em[1293] = 1; em[1294] = 8; em[1295] = 1; /* 1293: pointer.struct.asn1_string_st */
    	em[1296] = 60; em[1297] = 0; 
    em[1298] = 8884097; em[1299] = 8; em[1300] = 0; /* 1298: pointer.func */
    em[1301] = 1; em[1302] = 8; em[1303] = 1; /* 1301: pointer.struct.engine_st */
    	em[1304] = 192; em[1305] = 0; 
    em[1306] = 1; em[1307] = 8; em[1308] = 1; /* 1306: pointer.struct.asn1_string_st */
    	em[1309] = 60; em[1310] = 0; 
    em[1311] = 1; em[1312] = 8; em[1313] = 1; /* 1311: pointer.struct.asn1_string_st */
    	em[1314] = 24; em[1315] = 0; 
    em[1316] = 1; em[1317] = 8; em[1318] = 1; /* 1316: pointer.struct.engine_st */
    	em[1319] = 192; em[1320] = 0; 
    em[1321] = 8884097; em[1322] = 8; em[1323] = 0; /* 1321: pointer.func */
    em[1324] = 8884097; em[1325] = 8; em[1326] = 0; /* 1324: pointer.func */
    em[1327] = 1; em[1328] = 8; em[1329] = 1; /* 1327: pointer.struct.asn1_string_st */
    	em[1330] = 24; em[1331] = 0; 
    em[1332] = 8884097; em[1333] = 8; em[1334] = 0; /* 1332: pointer.func */
    em[1335] = 8884097; em[1336] = 8; em[1337] = 0; /* 1335: pointer.func */
    em[1338] = 8884097; em[1339] = 8; em[1340] = 0; /* 1338: pointer.func */
    em[1341] = 0; em[1342] = 208; em[1343] = 25; /* 1341: struct.evp_pkey_method_st */
    	em[1344] = 1394; em[1345] = 8; 
    	em[1346] = 1397; em[1347] = 16; 
    	em[1348] = 1338; em[1349] = 24; 
    	em[1350] = 1394; em[1351] = 32; 
    	em[1352] = 1400; em[1353] = 40; 
    	em[1354] = 1394; em[1355] = 48; 
    	em[1356] = 1400; em[1357] = 56; 
    	em[1358] = 1394; em[1359] = 64; 
    	em[1360] = 1335; em[1361] = 72; 
    	em[1362] = 1394; em[1363] = 80; 
    	em[1364] = 1403; em[1365] = 88; 
    	em[1366] = 1394; em[1367] = 96; 
    	em[1368] = 1335; em[1369] = 104; 
    	em[1370] = 1332; em[1371] = 112; 
    	em[1372] = 1406; em[1373] = 120; 
    	em[1374] = 1332; em[1375] = 128; 
    	em[1376] = 1324; em[1377] = 136; 
    	em[1378] = 1394; em[1379] = 144; 
    	em[1380] = 1335; em[1381] = 152; 
    	em[1382] = 1394; em[1383] = 160; 
    	em[1384] = 1335; em[1385] = 168; 
    	em[1386] = 1394; em[1387] = 176; 
    	em[1388] = 1409; em[1389] = 184; 
    	em[1390] = 1412; em[1391] = 192; 
    	em[1392] = 1298; em[1393] = 200; 
    em[1394] = 8884097; em[1395] = 8; em[1396] = 0; /* 1394: pointer.func */
    em[1397] = 8884097; em[1398] = 8; em[1399] = 0; /* 1397: pointer.func */
    em[1400] = 8884097; em[1401] = 8; em[1402] = 0; /* 1400: pointer.func */
    em[1403] = 8884097; em[1404] = 8; em[1405] = 0; /* 1403: pointer.func */
    em[1406] = 8884097; em[1407] = 8; em[1408] = 0; /* 1406: pointer.func */
    em[1409] = 8884097; em[1410] = 8; em[1411] = 0; /* 1409: pointer.func */
    em[1412] = 8884097; em[1413] = 8; em[1414] = 0; /* 1412: pointer.func */
    em[1415] = 0; em[1416] = 288; em[1417] = 4; /* 1415: struct.hmac_ctx_st */
    	em[1418] = 1426; em[1419] = 0; 
    	em[1420] = 1462; em[1421] = 8; 
    	em[1422] = 1462; em[1423] = 56; 
    	em[1424] = 1462; em[1425] = 104; 
    em[1426] = 1; em[1427] = 8; em[1428] = 1; /* 1426: pointer.struct.env_md_st */
    	em[1429] = 1431; em[1430] = 0; 
    em[1431] = 0; em[1432] = 120; em[1433] = 8; /* 1431: struct.env_md_st */
    	em[1434] = 1321; em[1435] = 24; 
    	em[1436] = 1450; em[1437] = 32; 
    	em[1438] = 1453; em[1439] = 40; 
    	em[1440] = 1456; em[1441] = 48; 
    	em[1442] = 1321; em[1443] = 56; 
    	em[1444] = 1459; em[1445] = 64; 
    	em[1446] = 1276; em[1447] = 72; 
    	em[1448] = 1180; em[1449] = 112; 
    em[1450] = 8884097; em[1451] = 8; em[1452] = 0; /* 1450: pointer.func */
    em[1453] = 8884097; em[1454] = 8; em[1455] = 0; /* 1453: pointer.func */
    em[1456] = 8884097; em[1457] = 8; em[1458] = 0; /* 1456: pointer.func */
    em[1459] = 8884097; em[1460] = 8; em[1461] = 0; /* 1459: pointer.func */
    em[1462] = 0; em[1463] = 48; em[1464] = 5; /* 1462: struct.env_md_ctx_st */
    	em[1465] = 1426; em[1466] = 0; 
    	em[1467] = 1301; em[1468] = 8; 
    	em[1469] = 83; em[1470] = 24; 
    	em[1471] = 1475; em[1472] = 32; 
    	em[1473] = 1450; em[1474] = 40; 
    em[1475] = 1; em[1476] = 8; em[1477] = 1; /* 1475: pointer.struct.evp_pkey_ctx_st */
    	em[1478] = 1480; em[1479] = 0; 
    em[1480] = 0; em[1481] = 80; em[1482] = 8; /* 1480: struct.evp_pkey_ctx_st */
    	em[1483] = 1499; em[1484] = 0; 
    	em[1485] = 1316; em[1486] = 8; 
    	em[1487] = 1504; em[1488] = 16; 
    	em[1489] = 1504; em[1490] = 24; 
    	em[1491] = 83; em[1492] = 40; 
    	em[1493] = 83; em[1494] = 48; 
    	em[1495] = 8; em[1496] = 56; 
    	em[1497] = 0; em[1498] = 64; 
    em[1499] = 1; em[1500] = 8; em[1501] = 1; /* 1499: pointer.struct.evp_pkey_method_st */
    	em[1502] = 1341; em[1503] = 0; 
    em[1504] = 1; em[1505] = 8; em[1506] = 1; /* 1504: pointer.struct.evp_pkey_st */
    	em[1507] = 1509; em[1508] = 0; 
    em[1509] = 0; em[1510] = 56; em[1511] = 4; /* 1509: struct.evp_pkey_st */
    	em[1512] = 1520; em[1513] = 16; 
    	em[1514] = 1316; em[1515] = 24; 
    	em[1516] = 68; em[1517] = 32; 
    	em[1518] = 1525; em[1519] = 48; 
    em[1520] = 1; em[1521] = 8; em[1522] = 1; /* 1520: pointer.struct.evp_pkey_asn1_method_st */
    	em[1523] = 1189; em[1524] = 0; 
    em[1525] = 1; em[1526] = 8; em[1527] = 1; /* 1525: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[1528] = 1530; em[1529] = 0; 
    em[1530] = 0; em[1531] = 32; em[1532] = 2; /* 1530: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[1533] = 1537; em[1534] = 8; 
    	em[1535] = 522; em[1536] = 24; 
    em[1537] = 8884099; em[1538] = 8; em[1539] = 2; /* 1537: pointer_to_array_of_pointers_to_stack */
    	em[1540] = 1544; em[1541] = 0; 
    	em[1542] = 5; em[1543] = 20; 
    em[1544] = 0; em[1545] = 8; em[1546] = 1; /* 1544: pointer.X509_ATTRIBUTE */
    	em[1547] = 1549; em[1548] = 0; 
    em[1549] = 0; em[1550] = 0; em[1551] = 1; /* 1549: X509_ATTRIBUTE */
    	em[1552] = 1554; em[1553] = 0; 
    em[1554] = 0; em[1555] = 24; em[1556] = 2; /* 1554: struct.x509_attributes_st */
    	em[1557] = 1561; em[1558] = 0; 
    	em[1559] = 1575; em[1560] = 16; 
    em[1561] = 1; em[1562] = 8; em[1563] = 1; /* 1561: pointer.struct.asn1_object_st */
    	em[1564] = 1566; em[1565] = 0; 
    em[1566] = 0; em[1567] = 40; em[1568] = 3; /* 1566: struct.asn1_object_st */
    	em[1569] = 162; em[1570] = 0; 
    	em[1571] = 162; em[1572] = 8; 
    	em[1573] = 1288; em[1574] = 24; 
    em[1575] = 0; em[1576] = 8; em[1577] = 3; /* 1575: union.unknown */
    	em[1578] = 173; em[1579] = 0; 
    	em[1580] = 1584; em[1581] = 0; 
    	em[1582] = 1739; em[1583] = 0; 
    em[1584] = 1; em[1585] = 8; em[1586] = 1; /* 1584: pointer.struct.stack_st_ASN1_TYPE */
    	em[1587] = 1589; em[1588] = 0; 
    em[1589] = 0; em[1590] = 32; em[1591] = 2; /* 1589: struct.stack_st_fake_ASN1_TYPE */
    	em[1592] = 1596; em[1593] = 8; 
    	em[1594] = 522; em[1595] = 24; 
    em[1596] = 8884099; em[1597] = 8; em[1598] = 2; /* 1596: pointer_to_array_of_pointers_to_stack */
    	em[1599] = 1603; em[1600] = 0; 
    	em[1601] = 5; em[1602] = 20; 
    em[1603] = 0; em[1604] = 8; em[1605] = 1; /* 1603: pointer.ASN1_TYPE */
    	em[1606] = 1608; em[1607] = 0; 
    em[1608] = 0; em[1609] = 0; em[1610] = 1; /* 1608: ASN1_TYPE */
    	em[1611] = 1613; em[1612] = 0; 
    em[1613] = 0; em[1614] = 16; em[1615] = 1; /* 1613: struct.asn1_type_st */
    	em[1616] = 1618; em[1617] = 8; 
    em[1618] = 0; em[1619] = 8; em[1620] = 20; /* 1618: union.unknown */
    	em[1621] = 173; em[1622] = 0; 
    	em[1623] = 1661; em[1624] = 0; 
    	em[1625] = 1666; em[1626] = 0; 
    	em[1627] = 1671; em[1628] = 0; 
    	em[1629] = 1676; em[1630] = 0; 
    	em[1631] = 1681; em[1632] = 0; 
    	em[1633] = 1686; em[1634] = 0; 
    	em[1635] = 1691; em[1636] = 0; 
    	em[1637] = 1696; em[1638] = 0; 
    	em[1639] = 1701; em[1640] = 0; 
    	em[1641] = 1306; em[1642] = 0; 
    	em[1643] = 1706; em[1644] = 0; 
    	em[1645] = 1711; em[1646] = 0; 
    	em[1647] = 1716; em[1648] = 0; 
    	em[1649] = 1721; em[1650] = 0; 
    	em[1651] = 1293; em[1652] = 0; 
    	em[1653] = 1726; em[1654] = 0; 
    	em[1655] = 1661; em[1656] = 0; 
    	em[1657] = 1661; em[1658] = 0; 
    	em[1659] = 1731; em[1660] = 0; 
    em[1661] = 1; em[1662] = 8; em[1663] = 1; /* 1661: pointer.struct.asn1_string_st */
    	em[1664] = 60; em[1665] = 0; 
    em[1666] = 1; em[1667] = 8; em[1668] = 1; /* 1666: pointer.struct.asn1_object_st */
    	em[1669] = 1279; em[1670] = 0; 
    em[1671] = 1; em[1672] = 8; em[1673] = 1; /* 1671: pointer.struct.asn1_string_st */
    	em[1674] = 60; em[1675] = 0; 
    em[1676] = 1; em[1677] = 8; em[1678] = 1; /* 1676: pointer.struct.asn1_string_st */
    	em[1679] = 60; em[1680] = 0; 
    em[1681] = 1; em[1682] = 8; em[1683] = 1; /* 1681: pointer.struct.asn1_string_st */
    	em[1684] = 60; em[1685] = 0; 
    em[1686] = 1; em[1687] = 8; em[1688] = 1; /* 1686: pointer.struct.asn1_string_st */
    	em[1689] = 60; em[1690] = 0; 
    em[1691] = 1; em[1692] = 8; em[1693] = 1; /* 1691: pointer.struct.asn1_string_st */
    	em[1694] = 60; em[1695] = 0; 
    em[1696] = 1; em[1697] = 8; em[1698] = 1; /* 1696: pointer.struct.asn1_string_st */
    	em[1699] = 60; em[1700] = 0; 
    em[1701] = 1; em[1702] = 8; em[1703] = 1; /* 1701: pointer.struct.asn1_string_st */
    	em[1704] = 60; em[1705] = 0; 
    em[1706] = 1; em[1707] = 8; em[1708] = 1; /* 1706: pointer.struct.asn1_string_st */
    	em[1709] = 60; em[1710] = 0; 
    em[1711] = 1; em[1712] = 8; em[1713] = 1; /* 1711: pointer.struct.asn1_string_st */
    	em[1714] = 60; em[1715] = 0; 
    em[1716] = 1; em[1717] = 8; em[1718] = 1; /* 1716: pointer.struct.asn1_string_st */
    	em[1719] = 60; em[1720] = 0; 
    em[1721] = 1; em[1722] = 8; em[1723] = 1; /* 1721: pointer.struct.asn1_string_st */
    	em[1724] = 60; em[1725] = 0; 
    em[1726] = 1; em[1727] = 8; em[1728] = 1; /* 1726: pointer.struct.asn1_string_st */
    	em[1729] = 60; em[1730] = 0; 
    em[1731] = 1; em[1732] = 8; em[1733] = 1; /* 1731: pointer.struct.ASN1_VALUE_st */
    	em[1734] = 1736; em[1735] = 0; 
    em[1736] = 0; em[1737] = 0; em[1738] = 0; /* 1736: struct.ASN1_VALUE_st */
    em[1739] = 1; em[1740] = 8; em[1741] = 1; /* 1739: pointer.struct.asn1_type_st */
    	em[1742] = 1744; em[1743] = 0; 
    em[1744] = 0; em[1745] = 16; em[1746] = 1; /* 1744: struct.asn1_type_st */
    	em[1747] = 1749; em[1748] = 8; 
    em[1749] = 0; em[1750] = 8; em[1751] = 20; /* 1749: union.unknown */
    	em[1752] = 173; em[1753] = 0; 
    	em[1754] = 1792; em[1755] = 0; 
    	em[1756] = 1561; em[1757] = 0; 
    	em[1758] = 1327; em[1759] = 0; 
    	em[1760] = 1797; em[1761] = 0; 
    	em[1762] = 1802; em[1763] = 0; 
    	em[1764] = 1807; em[1765] = 0; 
    	em[1766] = 1812; em[1767] = 0; 
    	em[1768] = 1311; em[1769] = 0; 
    	em[1770] = 1817; em[1771] = 0; 
    	em[1772] = 52; em[1773] = 0; 
    	em[1774] = 47; em[1775] = 0; 
    	em[1776] = 42; em[1777] = 0; 
    	em[1778] = 1822; em[1779] = 0; 
    	em[1780] = 1827; em[1781] = 0; 
    	em[1782] = 37; em[1783] = 0; 
    	em[1784] = 19; em[1785] = 0; 
    	em[1786] = 1792; em[1787] = 0; 
    	em[1788] = 1792; em[1789] = 0; 
    	em[1790] = 14; em[1791] = 0; 
    em[1792] = 1; em[1793] = 8; em[1794] = 1; /* 1792: pointer.struct.asn1_string_st */
    	em[1795] = 24; em[1796] = 0; 
    em[1797] = 1; em[1798] = 8; em[1799] = 1; /* 1797: pointer.struct.asn1_string_st */
    	em[1800] = 24; em[1801] = 0; 
    em[1802] = 1; em[1803] = 8; em[1804] = 1; /* 1802: pointer.struct.asn1_string_st */
    	em[1805] = 24; em[1806] = 0; 
    em[1807] = 1; em[1808] = 8; em[1809] = 1; /* 1807: pointer.struct.asn1_string_st */
    	em[1810] = 24; em[1811] = 0; 
    em[1812] = 1; em[1813] = 8; em[1814] = 1; /* 1812: pointer.struct.asn1_string_st */
    	em[1815] = 24; em[1816] = 0; 
    em[1817] = 1; em[1818] = 8; em[1819] = 1; /* 1817: pointer.struct.asn1_string_st */
    	em[1820] = 24; em[1821] = 0; 
    em[1822] = 1; em[1823] = 8; em[1824] = 1; /* 1822: pointer.struct.asn1_string_st */
    	em[1825] = 24; em[1826] = 0; 
    em[1827] = 1; em[1828] = 8; em[1829] = 1; /* 1827: pointer.struct.asn1_string_st */
    	em[1830] = 24; em[1831] = 0; 
    em[1832] = 0; em[1833] = 1; em[1834] = 0; /* 1832: char */
    em[1835] = 1; em[1836] = 8; em[1837] = 1; /* 1835: pointer.struct.hmac_ctx_st */
    	em[1838] = 1415; em[1839] = 0; 
    args_addr->arg_entity_index[0] = 1835;
    args_addr->arg_entity_index[1] = 83;
    args_addr->arg_entity_index[2] = 5;
    args_addr->arg_entity_index[3] = 1426;
    args_addr->arg_entity_index[4] = 1301;
    args_addr->ret_entity_index = 5;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_arg(args_addr, arg_d);
    populate_arg(args_addr, arg_e);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    HMAC_CTX * new_arg_a = *((HMAC_CTX * *)new_args->args[0]);

    const void * new_arg_b = *((const void * *)new_args->args[1]);

    int new_arg_c = *((int *)new_args->args[2]);

    const EVP_MD * new_arg_d = *((const EVP_MD * *)new_args->args[3]);

    ENGINE * new_arg_e = *((ENGINE * *)new_args->args[4]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_HMAC_Init_ex)(HMAC_CTX *,const void *,int,const EVP_MD *,ENGINE *);
    orig_HMAC_Init_ex = dlsym(RTLD_NEXT, "HMAC_Init_ex");
    *new_ret_ptr = (*orig_HMAC_Init_ex)(new_arg_a,new_arg_b,new_arg_c,new_arg_d,new_arg_e);

    syscall(889);

    free(args_addr);

    return ret;
}

