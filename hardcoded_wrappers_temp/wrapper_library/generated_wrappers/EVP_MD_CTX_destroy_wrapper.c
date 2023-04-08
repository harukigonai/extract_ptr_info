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

void bb_EVP_MD_CTX_destroy(EVP_MD_CTX * arg_a);

void EVP_MD_CTX_destroy(EVP_MD_CTX * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("EVP_MD_CTX_destroy called %lu\n", in_lib);
    if (!in_lib)
        bb_EVP_MD_CTX_destroy(arg_a);
    else {
        void (*orig_EVP_MD_CTX_destroy)(EVP_MD_CTX *);
        orig_EVP_MD_CTX_destroy = dlsym(RTLD_NEXT, "EVP_MD_CTX_destroy");
        orig_EVP_MD_CTX_destroy(arg_a);
    }
}

void bb_EVP_MD_CTX_destroy(EVP_MD_CTX * arg_a) 
{
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
    em[47] = 8884097; em[48] = 8; em[49] = 0; /* 47: pointer.func */
    em[50] = 8884097; em[51] = 8; em[52] = 0; /* 50: pointer.func */
    em[53] = 0; em[54] = 24; em[55] = 1; /* 53: struct.asn1_string_st */
    	em[56] = 29; em[57] = 8; 
    em[58] = 8884097; em[59] = 8; em[60] = 0; /* 58: pointer.func */
    em[61] = 8884101; em[62] = 8; em[63] = 6; /* 61: union.union_of_evp_pkey_st */
    	em[64] = 76; em[65] = 0; 
    	em[66] = 79; em[67] = 6; 
    	em[68] = 632; em[69] = 116; 
    	em[70] = 763; em[71] = 28; 
    	em[72] = 842; em[73] = 408; 
    	em[74] = 5; em[75] = 0; 
    em[76] = 0; em[77] = 8; em[78] = 0; /* 76: pointer.void */
    em[79] = 1; em[80] = 8; em[81] = 1; /* 79: pointer.struct.rsa_st */
    	em[82] = 84; em[83] = 0; 
    em[84] = 0; em[85] = 168; em[86] = 17; /* 84: struct.rsa_st */
    	em[87] = 121; em[88] = 16; 
    	em[89] = 180; em[90] = 24; 
    	em[91] = 523; em[92] = 32; 
    	em[93] = 523; em[94] = 40; 
    	em[95] = 523; em[96] = 48; 
    	em[97] = 523; em[98] = 56; 
    	em[99] = 523; em[100] = 64; 
    	em[101] = 523; em[102] = 72; 
    	em[103] = 523; em[104] = 80; 
    	em[105] = 523; em[106] = 88; 
    	em[107] = 543; em[108] = 96; 
    	em[109] = 557; em[110] = 120; 
    	em[111] = 557; em[112] = 128; 
    	em[113] = 557; em[114] = 136; 
    	em[115] = 166; em[116] = 144; 
    	em[117] = 571; em[118] = 152; 
    	em[119] = 571; em[120] = 160; 
    em[121] = 1; em[122] = 8; em[123] = 1; /* 121: pointer.struct.rsa_meth_st */
    	em[124] = 126; em[125] = 0; 
    em[126] = 0; em[127] = 112; em[128] = 13; /* 126: struct.rsa_meth_st */
    	em[129] = 155; em[130] = 0; 
    	em[131] = 160; em[132] = 8; 
    	em[133] = 160; em[134] = 16; 
    	em[135] = 160; em[136] = 24; 
    	em[137] = 160; em[138] = 32; 
    	em[139] = 163; em[140] = 40; 
    	em[141] = 58; em[142] = 48; 
    	em[143] = 50; em[144] = 56; 
    	em[145] = 50; em[146] = 64; 
    	em[147] = 166; em[148] = 80; 
    	em[149] = 171; em[150] = 88; 
    	em[151] = 174; em[152] = 96; 
    	em[153] = 177; em[154] = 104; 
    em[155] = 1; em[156] = 8; em[157] = 1; /* 155: pointer.char */
    	em[158] = 8884096; em[159] = 0; 
    em[160] = 8884097; em[161] = 8; em[162] = 0; /* 160: pointer.func */
    em[163] = 8884097; em[164] = 8; em[165] = 0; /* 163: pointer.func */
    em[166] = 1; em[167] = 8; em[168] = 1; /* 166: pointer.char */
    	em[169] = 8884096; em[170] = 0; 
    em[171] = 8884097; em[172] = 8; em[173] = 0; /* 171: pointer.func */
    em[174] = 8884097; em[175] = 8; em[176] = 0; /* 174: pointer.func */
    em[177] = 8884097; em[178] = 8; em[179] = 0; /* 177: pointer.func */
    em[180] = 1; em[181] = 8; em[182] = 1; /* 180: pointer.struct.engine_st */
    	em[183] = 185; em[184] = 0; 
    em[185] = 0; em[186] = 216; em[187] = 24; /* 185: struct.engine_st */
    	em[188] = 155; em[189] = 0; 
    	em[190] = 155; em[191] = 8; 
    	em[192] = 236; em[193] = 16; 
    	em[194] = 291; em[195] = 24; 
    	em[196] = 342; em[197] = 32; 
    	em[198] = 378; em[199] = 40; 
    	em[200] = 395; em[201] = 48; 
    	em[202] = 422; em[203] = 56; 
    	em[204] = 457; em[205] = 64; 
    	em[206] = 465; em[207] = 72; 
    	em[208] = 468; em[209] = 80; 
    	em[210] = 471; em[211] = 88; 
    	em[212] = 474; em[213] = 96; 
    	em[214] = 477; em[215] = 104; 
    	em[216] = 477; em[217] = 112; 
    	em[218] = 477; em[219] = 120; 
    	em[220] = 480; em[221] = 128; 
    	em[222] = 483; em[223] = 136; 
    	em[224] = 483; em[225] = 144; 
    	em[226] = 486; em[227] = 152; 
    	em[228] = 489; em[229] = 160; 
    	em[230] = 501; em[231] = 184; 
    	em[232] = 518; em[233] = 200; 
    	em[234] = 518; em[235] = 208; 
    em[236] = 1; em[237] = 8; em[238] = 1; /* 236: pointer.struct.rsa_meth_st */
    	em[239] = 241; em[240] = 0; 
    em[241] = 0; em[242] = 112; em[243] = 13; /* 241: struct.rsa_meth_st */
    	em[244] = 155; em[245] = 0; 
    	em[246] = 270; em[247] = 8; 
    	em[248] = 270; em[249] = 16; 
    	em[250] = 270; em[251] = 24; 
    	em[252] = 270; em[253] = 32; 
    	em[254] = 273; em[255] = 40; 
    	em[256] = 276; em[257] = 48; 
    	em[258] = 279; em[259] = 56; 
    	em[260] = 279; em[261] = 64; 
    	em[262] = 166; em[263] = 80; 
    	em[264] = 282; em[265] = 88; 
    	em[266] = 285; em[267] = 96; 
    	em[268] = 288; em[269] = 104; 
    em[270] = 8884097; em[271] = 8; em[272] = 0; /* 270: pointer.func */
    em[273] = 8884097; em[274] = 8; em[275] = 0; /* 273: pointer.func */
    em[276] = 8884097; em[277] = 8; em[278] = 0; /* 276: pointer.func */
    em[279] = 8884097; em[280] = 8; em[281] = 0; /* 279: pointer.func */
    em[282] = 8884097; em[283] = 8; em[284] = 0; /* 282: pointer.func */
    em[285] = 8884097; em[286] = 8; em[287] = 0; /* 285: pointer.func */
    em[288] = 8884097; em[289] = 8; em[290] = 0; /* 288: pointer.func */
    em[291] = 1; em[292] = 8; em[293] = 1; /* 291: pointer.struct.dsa_method */
    	em[294] = 296; em[295] = 0; 
    em[296] = 0; em[297] = 96; em[298] = 11; /* 296: struct.dsa_method */
    	em[299] = 155; em[300] = 0; 
    	em[301] = 321; em[302] = 8; 
    	em[303] = 324; em[304] = 16; 
    	em[305] = 327; em[306] = 24; 
    	em[307] = 330; em[308] = 32; 
    	em[309] = 333; em[310] = 40; 
    	em[311] = 336; em[312] = 48; 
    	em[313] = 336; em[314] = 56; 
    	em[315] = 166; em[316] = 72; 
    	em[317] = 339; em[318] = 80; 
    	em[319] = 336; em[320] = 88; 
    em[321] = 8884097; em[322] = 8; em[323] = 0; /* 321: pointer.func */
    em[324] = 8884097; em[325] = 8; em[326] = 0; /* 324: pointer.func */
    em[327] = 8884097; em[328] = 8; em[329] = 0; /* 327: pointer.func */
    em[330] = 8884097; em[331] = 8; em[332] = 0; /* 330: pointer.func */
    em[333] = 8884097; em[334] = 8; em[335] = 0; /* 333: pointer.func */
    em[336] = 8884097; em[337] = 8; em[338] = 0; /* 336: pointer.func */
    em[339] = 8884097; em[340] = 8; em[341] = 0; /* 339: pointer.func */
    em[342] = 1; em[343] = 8; em[344] = 1; /* 342: pointer.struct.dh_method */
    	em[345] = 347; em[346] = 0; 
    em[347] = 0; em[348] = 72; em[349] = 8; /* 347: struct.dh_method */
    	em[350] = 155; em[351] = 0; 
    	em[352] = 366; em[353] = 8; 
    	em[354] = 369; em[355] = 16; 
    	em[356] = 372; em[357] = 24; 
    	em[358] = 366; em[359] = 32; 
    	em[360] = 366; em[361] = 40; 
    	em[362] = 166; em[363] = 56; 
    	em[364] = 375; em[365] = 64; 
    em[366] = 8884097; em[367] = 8; em[368] = 0; /* 366: pointer.func */
    em[369] = 8884097; em[370] = 8; em[371] = 0; /* 369: pointer.func */
    em[372] = 8884097; em[373] = 8; em[374] = 0; /* 372: pointer.func */
    em[375] = 8884097; em[376] = 8; em[377] = 0; /* 375: pointer.func */
    em[378] = 1; em[379] = 8; em[380] = 1; /* 378: pointer.struct.ecdh_method */
    	em[381] = 383; em[382] = 0; 
    em[383] = 0; em[384] = 32; em[385] = 3; /* 383: struct.ecdh_method */
    	em[386] = 155; em[387] = 0; 
    	em[388] = 392; em[389] = 8; 
    	em[390] = 166; em[391] = 24; 
    em[392] = 8884097; em[393] = 8; em[394] = 0; /* 392: pointer.func */
    em[395] = 1; em[396] = 8; em[397] = 1; /* 395: pointer.struct.ecdsa_method */
    	em[398] = 400; em[399] = 0; 
    em[400] = 0; em[401] = 48; em[402] = 5; /* 400: struct.ecdsa_method */
    	em[403] = 155; em[404] = 0; 
    	em[405] = 413; em[406] = 8; 
    	em[407] = 416; em[408] = 16; 
    	em[409] = 419; em[410] = 24; 
    	em[411] = 166; em[412] = 40; 
    em[413] = 8884097; em[414] = 8; em[415] = 0; /* 413: pointer.func */
    em[416] = 8884097; em[417] = 8; em[418] = 0; /* 416: pointer.func */
    em[419] = 8884097; em[420] = 8; em[421] = 0; /* 419: pointer.func */
    em[422] = 1; em[423] = 8; em[424] = 1; /* 422: pointer.struct.rand_meth_st */
    	em[425] = 427; em[426] = 0; 
    em[427] = 0; em[428] = 48; em[429] = 6; /* 427: struct.rand_meth_st */
    	em[430] = 442; em[431] = 0; 
    	em[432] = 445; em[433] = 8; 
    	em[434] = 448; em[435] = 16; 
    	em[436] = 451; em[437] = 24; 
    	em[438] = 445; em[439] = 32; 
    	em[440] = 454; em[441] = 40; 
    em[442] = 8884097; em[443] = 8; em[444] = 0; /* 442: pointer.func */
    em[445] = 8884097; em[446] = 8; em[447] = 0; /* 445: pointer.func */
    em[448] = 8884097; em[449] = 8; em[450] = 0; /* 448: pointer.func */
    em[451] = 8884097; em[452] = 8; em[453] = 0; /* 451: pointer.func */
    em[454] = 8884097; em[455] = 8; em[456] = 0; /* 454: pointer.func */
    em[457] = 1; em[458] = 8; em[459] = 1; /* 457: pointer.struct.store_method_st */
    	em[460] = 462; em[461] = 0; 
    em[462] = 0; em[463] = 0; em[464] = 0; /* 462: struct.store_method_st */
    em[465] = 8884097; em[466] = 8; em[467] = 0; /* 465: pointer.func */
    em[468] = 8884097; em[469] = 8; em[470] = 0; /* 468: pointer.func */
    em[471] = 8884097; em[472] = 8; em[473] = 0; /* 471: pointer.func */
    em[474] = 8884097; em[475] = 8; em[476] = 0; /* 474: pointer.func */
    em[477] = 8884097; em[478] = 8; em[479] = 0; /* 477: pointer.func */
    em[480] = 8884097; em[481] = 8; em[482] = 0; /* 480: pointer.func */
    em[483] = 8884097; em[484] = 8; em[485] = 0; /* 483: pointer.func */
    em[486] = 8884097; em[487] = 8; em[488] = 0; /* 486: pointer.func */
    em[489] = 1; em[490] = 8; em[491] = 1; /* 489: pointer.struct.ENGINE_CMD_DEFN_st */
    	em[492] = 494; em[493] = 0; 
    em[494] = 0; em[495] = 32; em[496] = 2; /* 494: struct.ENGINE_CMD_DEFN_st */
    	em[497] = 155; em[498] = 8; 
    	em[499] = 155; em[500] = 16; 
    em[501] = 0; em[502] = 32; em[503] = 2; /* 501: struct.crypto_ex_data_st_fake */
    	em[504] = 508; em[505] = 8; 
    	em[506] = 515; em[507] = 24; 
    em[508] = 8884099; em[509] = 8; em[510] = 2; /* 508: pointer_to_array_of_pointers_to_stack */
    	em[511] = 76; em[512] = 0; 
    	em[513] = 5; em[514] = 20; 
    em[515] = 8884097; em[516] = 8; em[517] = 0; /* 515: pointer.func */
    em[518] = 1; em[519] = 8; em[520] = 1; /* 518: pointer.struct.engine_st */
    	em[521] = 185; em[522] = 0; 
    em[523] = 1; em[524] = 8; em[525] = 1; /* 523: pointer.struct.bignum_st */
    	em[526] = 528; em[527] = 0; 
    em[528] = 0; em[529] = 24; em[530] = 1; /* 528: struct.bignum_st */
    	em[531] = 533; em[532] = 0; 
    em[533] = 8884099; em[534] = 8; em[535] = 2; /* 533: pointer_to_array_of_pointers_to_stack */
    	em[536] = 540; em[537] = 0; 
    	em[538] = 5; em[539] = 12; 
    em[540] = 0; em[541] = 8; em[542] = 0; /* 540: long unsigned int */
    em[543] = 0; em[544] = 32; em[545] = 2; /* 543: struct.crypto_ex_data_st_fake */
    	em[546] = 550; em[547] = 8; 
    	em[548] = 515; em[549] = 24; 
    em[550] = 8884099; em[551] = 8; em[552] = 2; /* 550: pointer_to_array_of_pointers_to_stack */
    	em[553] = 76; em[554] = 0; 
    	em[555] = 5; em[556] = 20; 
    em[557] = 1; em[558] = 8; em[559] = 1; /* 557: pointer.struct.bn_mont_ctx_st */
    	em[560] = 562; em[561] = 0; 
    em[562] = 0; em[563] = 96; em[564] = 3; /* 562: struct.bn_mont_ctx_st */
    	em[565] = 528; em[566] = 8; 
    	em[567] = 528; em[568] = 32; 
    	em[569] = 528; em[570] = 56; 
    em[571] = 1; em[572] = 8; em[573] = 1; /* 571: pointer.struct.bn_blinding_st */
    	em[574] = 576; em[575] = 0; 
    em[576] = 0; em[577] = 88; em[578] = 7; /* 576: struct.bn_blinding_st */
    	em[579] = 593; em[580] = 0; 
    	em[581] = 593; em[582] = 8; 
    	em[583] = 593; em[584] = 16; 
    	em[585] = 593; em[586] = 24; 
    	em[587] = 610; em[588] = 40; 
    	em[589] = 615; em[590] = 72; 
    	em[591] = 629; em[592] = 80; 
    em[593] = 1; em[594] = 8; em[595] = 1; /* 593: pointer.struct.bignum_st */
    	em[596] = 598; em[597] = 0; 
    em[598] = 0; em[599] = 24; em[600] = 1; /* 598: struct.bignum_st */
    	em[601] = 603; em[602] = 0; 
    em[603] = 8884099; em[604] = 8; em[605] = 2; /* 603: pointer_to_array_of_pointers_to_stack */
    	em[606] = 540; em[607] = 0; 
    	em[608] = 5; em[609] = 12; 
    em[610] = 0; em[611] = 16; em[612] = 1; /* 610: struct.crypto_threadid_st */
    	em[613] = 76; em[614] = 0; 
    em[615] = 1; em[616] = 8; em[617] = 1; /* 615: pointer.struct.bn_mont_ctx_st */
    	em[618] = 620; em[619] = 0; 
    em[620] = 0; em[621] = 96; em[622] = 3; /* 620: struct.bn_mont_ctx_st */
    	em[623] = 598; em[624] = 8; 
    	em[625] = 598; em[626] = 32; 
    	em[627] = 598; em[628] = 56; 
    em[629] = 8884097; em[630] = 8; em[631] = 0; /* 629: pointer.func */
    em[632] = 1; em[633] = 8; em[634] = 1; /* 632: pointer.struct.dsa_st */
    	em[635] = 637; em[636] = 0; 
    em[637] = 0; em[638] = 136; em[639] = 11; /* 637: struct.dsa_st */
    	em[640] = 662; em[641] = 24; 
    	em[642] = 662; em[643] = 32; 
    	em[644] = 662; em[645] = 40; 
    	em[646] = 662; em[647] = 48; 
    	em[648] = 662; em[649] = 56; 
    	em[650] = 662; em[651] = 64; 
    	em[652] = 662; em[653] = 72; 
    	em[654] = 679; em[655] = 88; 
    	em[656] = 693; em[657] = 104; 
    	em[658] = 707; em[659] = 120; 
    	em[660] = 758; em[661] = 128; 
    em[662] = 1; em[663] = 8; em[664] = 1; /* 662: pointer.struct.bignum_st */
    	em[665] = 667; em[666] = 0; 
    em[667] = 0; em[668] = 24; em[669] = 1; /* 667: struct.bignum_st */
    	em[670] = 672; em[671] = 0; 
    em[672] = 8884099; em[673] = 8; em[674] = 2; /* 672: pointer_to_array_of_pointers_to_stack */
    	em[675] = 540; em[676] = 0; 
    	em[677] = 5; em[678] = 12; 
    em[679] = 1; em[680] = 8; em[681] = 1; /* 679: pointer.struct.bn_mont_ctx_st */
    	em[682] = 684; em[683] = 0; 
    em[684] = 0; em[685] = 96; em[686] = 3; /* 684: struct.bn_mont_ctx_st */
    	em[687] = 667; em[688] = 8; 
    	em[689] = 667; em[690] = 32; 
    	em[691] = 667; em[692] = 56; 
    em[693] = 0; em[694] = 32; em[695] = 2; /* 693: struct.crypto_ex_data_st_fake */
    	em[696] = 700; em[697] = 8; 
    	em[698] = 515; em[699] = 24; 
    em[700] = 8884099; em[701] = 8; em[702] = 2; /* 700: pointer_to_array_of_pointers_to_stack */
    	em[703] = 76; em[704] = 0; 
    	em[705] = 5; em[706] = 20; 
    em[707] = 1; em[708] = 8; em[709] = 1; /* 707: pointer.struct.dsa_method */
    	em[710] = 712; em[711] = 0; 
    em[712] = 0; em[713] = 96; em[714] = 11; /* 712: struct.dsa_method */
    	em[715] = 155; em[716] = 0; 
    	em[717] = 737; em[718] = 8; 
    	em[719] = 740; em[720] = 16; 
    	em[721] = 743; em[722] = 24; 
    	em[723] = 746; em[724] = 32; 
    	em[725] = 749; em[726] = 40; 
    	em[727] = 752; em[728] = 48; 
    	em[729] = 752; em[730] = 56; 
    	em[731] = 166; em[732] = 72; 
    	em[733] = 755; em[734] = 80; 
    	em[735] = 752; em[736] = 88; 
    em[737] = 8884097; em[738] = 8; em[739] = 0; /* 737: pointer.func */
    em[740] = 8884097; em[741] = 8; em[742] = 0; /* 740: pointer.func */
    em[743] = 8884097; em[744] = 8; em[745] = 0; /* 743: pointer.func */
    em[746] = 8884097; em[747] = 8; em[748] = 0; /* 746: pointer.func */
    em[749] = 8884097; em[750] = 8; em[751] = 0; /* 749: pointer.func */
    em[752] = 8884097; em[753] = 8; em[754] = 0; /* 752: pointer.func */
    em[755] = 8884097; em[756] = 8; em[757] = 0; /* 755: pointer.func */
    em[758] = 1; em[759] = 8; em[760] = 1; /* 758: pointer.struct.engine_st */
    	em[761] = 185; em[762] = 0; 
    em[763] = 1; em[764] = 8; em[765] = 1; /* 763: pointer.struct.dh_st */
    	em[766] = 768; em[767] = 0; 
    em[768] = 0; em[769] = 144; em[770] = 12; /* 768: struct.dh_st */
    	em[771] = 523; em[772] = 8; 
    	em[773] = 523; em[774] = 16; 
    	em[775] = 523; em[776] = 32; 
    	em[777] = 523; em[778] = 40; 
    	em[779] = 557; em[780] = 56; 
    	em[781] = 523; em[782] = 64; 
    	em[783] = 523; em[784] = 72; 
    	em[785] = 29; em[786] = 80; 
    	em[787] = 523; em[788] = 96; 
    	em[789] = 795; em[790] = 112; 
    	em[791] = 809; em[792] = 128; 
    	em[793] = 180; em[794] = 136; 
    em[795] = 0; em[796] = 32; em[797] = 2; /* 795: struct.crypto_ex_data_st_fake */
    	em[798] = 802; em[799] = 8; 
    	em[800] = 515; em[801] = 24; 
    em[802] = 8884099; em[803] = 8; em[804] = 2; /* 802: pointer_to_array_of_pointers_to_stack */
    	em[805] = 76; em[806] = 0; 
    	em[807] = 5; em[808] = 20; 
    em[809] = 1; em[810] = 8; em[811] = 1; /* 809: pointer.struct.dh_method */
    	em[812] = 814; em[813] = 0; 
    em[814] = 0; em[815] = 72; em[816] = 8; /* 814: struct.dh_method */
    	em[817] = 155; em[818] = 0; 
    	em[819] = 833; em[820] = 8; 
    	em[821] = 836; em[822] = 16; 
    	em[823] = 47; em[824] = 24; 
    	em[825] = 833; em[826] = 32; 
    	em[827] = 833; em[828] = 40; 
    	em[829] = 166; em[830] = 56; 
    	em[831] = 839; em[832] = 64; 
    em[833] = 8884097; em[834] = 8; em[835] = 0; /* 833: pointer.func */
    em[836] = 8884097; em[837] = 8; em[838] = 0; /* 836: pointer.func */
    em[839] = 8884097; em[840] = 8; em[841] = 0; /* 839: pointer.func */
    em[842] = 1; em[843] = 8; em[844] = 1; /* 842: pointer.struct.ec_key_st */
    	em[845] = 847; em[846] = 0; 
    em[847] = 0; em[848] = 56; em[849] = 4; /* 847: struct.ec_key_st */
    	em[850] = 858; em[851] = 8; 
    	em[852] = 1122; em[853] = 16; 
    	em[854] = 1127; em[855] = 24; 
    	em[856] = 1144; em[857] = 48; 
    em[858] = 1; em[859] = 8; em[860] = 1; /* 858: pointer.struct.ec_group_st */
    	em[861] = 863; em[862] = 0; 
    em[863] = 0; em[864] = 232; em[865] = 12; /* 863: struct.ec_group_st */
    	em[866] = 890; em[867] = 0; 
    	em[868] = 1062; em[869] = 8; 
    	em[870] = 1078; em[871] = 16; 
    	em[872] = 1078; em[873] = 40; 
    	em[874] = 29; em[875] = 80; 
    	em[876] = 1090; em[877] = 96; 
    	em[878] = 1078; em[879] = 104; 
    	em[880] = 1078; em[881] = 152; 
    	em[882] = 1078; em[883] = 176; 
    	em[884] = 76; em[885] = 208; 
    	em[886] = 76; em[887] = 216; 
    	em[888] = 1119; em[889] = 224; 
    em[890] = 1; em[891] = 8; em[892] = 1; /* 890: pointer.struct.ec_method_st */
    	em[893] = 895; em[894] = 0; 
    em[895] = 0; em[896] = 304; em[897] = 37; /* 895: struct.ec_method_st */
    	em[898] = 972; em[899] = 8; 
    	em[900] = 975; em[901] = 16; 
    	em[902] = 975; em[903] = 24; 
    	em[904] = 978; em[905] = 32; 
    	em[906] = 981; em[907] = 40; 
    	em[908] = 984; em[909] = 48; 
    	em[910] = 987; em[911] = 56; 
    	em[912] = 990; em[913] = 64; 
    	em[914] = 993; em[915] = 72; 
    	em[916] = 996; em[917] = 80; 
    	em[918] = 996; em[919] = 88; 
    	em[920] = 999; em[921] = 96; 
    	em[922] = 1002; em[923] = 104; 
    	em[924] = 1005; em[925] = 112; 
    	em[926] = 1008; em[927] = 120; 
    	em[928] = 1011; em[929] = 128; 
    	em[930] = 1014; em[931] = 136; 
    	em[932] = 1017; em[933] = 144; 
    	em[934] = 1020; em[935] = 152; 
    	em[936] = 1023; em[937] = 160; 
    	em[938] = 1026; em[939] = 168; 
    	em[940] = 1029; em[941] = 176; 
    	em[942] = 1032; em[943] = 184; 
    	em[944] = 1035; em[945] = 192; 
    	em[946] = 1038; em[947] = 200; 
    	em[948] = 1041; em[949] = 208; 
    	em[950] = 1032; em[951] = 216; 
    	em[952] = 1044; em[953] = 224; 
    	em[954] = 1047; em[955] = 232; 
    	em[956] = 1050; em[957] = 240; 
    	em[958] = 987; em[959] = 248; 
    	em[960] = 1053; em[961] = 256; 
    	em[962] = 1056; em[963] = 264; 
    	em[964] = 1053; em[965] = 272; 
    	em[966] = 1056; em[967] = 280; 
    	em[968] = 1056; em[969] = 288; 
    	em[970] = 1059; em[971] = 296; 
    em[972] = 8884097; em[973] = 8; em[974] = 0; /* 972: pointer.func */
    em[975] = 8884097; em[976] = 8; em[977] = 0; /* 975: pointer.func */
    em[978] = 8884097; em[979] = 8; em[980] = 0; /* 978: pointer.func */
    em[981] = 8884097; em[982] = 8; em[983] = 0; /* 981: pointer.func */
    em[984] = 8884097; em[985] = 8; em[986] = 0; /* 984: pointer.func */
    em[987] = 8884097; em[988] = 8; em[989] = 0; /* 987: pointer.func */
    em[990] = 8884097; em[991] = 8; em[992] = 0; /* 990: pointer.func */
    em[993] = 8884097; em[994] = 8; em[995] = 0; /* 993: pointer.func */
    em[996] = 8884097; em[997] = 8; em[998] = 0; /* 996: pointer.func */
    em[999] = 8884097; em[1000] = 8; em[1001] = 0; /* 999: pointer.func */
    em[1002] = 8884097; em[1003] = 8; em[1004] = 0; /* 1002: pointer.func */
    em[1005] = 8884097; em[1006] = 8; em[1007] = 0; /* 1005: pointer.func */
    em[1008] = 8884097; em[1009] = 8; em[1010] = 0; /* 1008: pointer.func */
    em[1011] = 8884097; em[1012] = 8; em[1013] = 0; /* 1011: pointer.func */
    em[1014] = 8884097; em[1015] = 8; em[1016] = 0; /* 1014: pointer.func */
    em[1017] = 8884097; em[1018] = 8; em[1019] = 0; /* 1017: pointer.func */
    em[1020] = 8884097; em[1021] = 8; em[1022] = 0; /* 1020: pointer.func */
    em[1023] = 8884097; em[1024] = 8; em[1025] = 0; /* 1023: pointer.func */
    em[1026] = 8884097; em[1027] = 8; em[1028] = 0; /* 1026: pointer.func */
    em[1029] = 8884097; em[1030] = 8; em[1031] = 0; /* 1029: pointer.func */
    em[1032] = 8884097; em[1033] = 8; em[1034] = 0; /* 1032: pointer.func */
    em[1035] = 8884097; em[1036] = 8; em[1037] = 0; /* 1035: pointer.func */
    em[1038] = 8884097; em[1039] = 8; em[1040] = 0; /* 1038: pointer.func */
    em[1041] = 8884097; em[1042] = 8; em[1043] = 0; /* 1041: pointer.func */
    em[1044] = 8884097; em[1045] = 8; em[1046] = 0; /* 1044: pointer.func */
    em[1047] = 8884097; em[1048] = 8; em[1049] = 0; /* 1047: pointer.func */
    em[1050] = 8884097; em[1051] = 8; em[1052] = 0; /* 1050: pointer.func */
    em[1053] = 8884097; em[1054] = 8; em[1055] = 0; /* 1053: pointer.func */
    em[1056] = 8884097; em[1057] = 8; em[1058] = 0; /* 1056: pointer.func */
    em[1059] = 8884097; em[1060] = 8; em[1061] = 0; /* 1059: pointer.func */
    em[1062] = 1; em[1063] = 8; em[1064] = 1; /* 1062: pointer.struct.ec_point_st */
    	em[1065] = 1067; em[1066] = 0; 
    em[1067] = 0; em[1068] = 88; em[1069] = 4; /* 1067: struct.ec_point_st */
    	em[1070] = 890; em[1071] = 0; 
    	em[1072] = 1078; em[1073] = 8; 
    	em[1074] = 1078; em[1075] = 32; 
    	em[1076] = 1078; em[1077] = 56; 
    em[1078] = 0; em[1079] = 24; em[1080] = 1; /* 1078: struct.bignum_st */
    	em[1081] = 1083; em[1082] = 0; 
    em[1083] = 8884099; em[1084] = 8; em[1085] = 2; /* 1083: pointer_to_array_of_pointers_to_stack */
    	em[1086] = 540; em[1087] = 0; 
    	em[1088] = 5; em[1089] = 12; 
    em[1090] = 1; em[1091] = 8; em[1092] = 1; /* 1090: pointer.struct.ec_extra_data_st */
    	em[1093] = 1095; em[1094] = 0; 
    em[1095] = 0; em[1096] = 40; em[1097] = 5; /* 1095: struct.ec_extra_data_st */
    	em[1098] = 1108; em[1099] = 0; 
    	em[1100] = 76; em[1101] = 8; 
    	em[1102] = 1113; em[1103] = 16; 
    	em[1104] = 1116; em[1105] = 24; 
    	em[1106] = 1116; em[1107] = 32; 
    em[1108] = 1; em[1109] = 8; em[1110] = 1; /* 1108: pointer.struct.ec_extra_data_st */
    	em[1111] = 1095; em[1112] = 0; 
    em[1113] = 8884097; em[1114] = 8; em[1115] = 0; /* 1113: pointer.func */
    em[1116] = 8884097; em[1117] = 8; em[1118] = 0; /* 1116: pointer.func */
    em[1119] = 8884097; em[1120] = 8; em[1121] = 0; /* 1119: pointer.func */
    em[1122] = 1; em[1123] = 8; em[1124] = 1; /* 1122: pointer.struct.ec_point_st */
    	em[1125] = 1067; em[1126] = 0; 
    em[1127] = 1; em[1128] = 8; em[1129] = 1; /* 1127: pointer.struct.bignum_st */
    	em[1130] = 1132; em[1131] = 0; 
    em[1132] = 0; em[1133] = 24; em[1134] = 1; /* 1132: struct.bignum_st */
    	em[1135] = 1137; em[1136] = 0; 
    em[1137] = 8884099; em[1138] = 8; em[1139] = 2; /* 1137: pointer_to_array_of_pointers_to_stack */
    	em[1140] = 540; em[1141] = 0; 
    	em[1142] = 5; em[1143] = 12; 
    em[1144] = 1; em[1145] = 8; em[1146] = 1; /* 1144: pointer.struct.ec_extra_data_st */
    	em[1147] = 1149; em[1148] = 0; 
    em[1149] = 0; em[1150] = 40; em[1151] = 5; /* 1149: struct.ec_extra_data_st */
    	em[1152] = 1162; em[1153] = 0; 
    	em[1154] = 76; em[1155] = 8; 
    	em[1156] = 1113; em[1157] = 16; 
    	em[1158] = 1116; em[1159] = 24; 
    	em[1160] = 1116; em[1161] = 32; 
    em[1162] = 1; em[1163] = 8; em[1164] = 1; /* 1162: pointer.struct.ec_extra_data_st */
    	em[1165] = 1149; em[1166] = 0; 
    em[1167] = 8884097; em[1168] = 8; em[1169] = 0; /* 1167: pointer.func */
    em[1170] = 8884097; em[1171] = 8; em[1172] = 0; /* 1170: pointer.func */
    em[1173] = 8884097; em[1174] = 8; em[1175] = 0; /* 1173: pointer.func */
    em[1176] = 0; em[1177] = 208; em[1178] = 24; /* 1176: struct.evp_pkey_asn1_method_st */
    	em[1179] = 166; em[1180] = 16; 
    	em[1181] = 166; em[1182] = 24; 
    	em[1183] = 1227; em[1184] = 32; 
    	em[1185] = 1230; em[1186] = 40; 
    	em[1187] = 1233; em[1188] = 48; 
    	em[1189] = 1236; em[1190] = 56; 
    	em[1191] = 1239; em[1192] = 64; 
    	em[1193] = 1242; em[1194] = 72; 
    	em[1195] = 1236; em[1196] = 80; 
    	em[1197] = 1173; em[1198] = 88; 
    	em[1199] = 1173; em[1200] = 96; 
    	em[1201] = 1245; em[1202] = 104; 
    	em[1203] = 1248; em[1204] = 112; 
    	em[1205] = 1173; em[1206] = 120; 
    	em[1207] = 1251; em[1208] = 128; 
    	em[1209] = 1233; em[1210] = 136; 
    	em[1211] = 1236; em[1212] = 144; 
    	em[1213] = 1254; em[1214] = 152; 
    	em[1215] = 1257; em[1216] = 160; 
    	em[1217] = 1170; em[1218] = 168; 
    	em[1219] = 1245; em[1220] = 176; 
    	em[1221] = 1248; em[1222] = 184; 
    	em[1223] = 1260; em[1224] = 192; 
    	em[1225] = 1167; em[1226] = 200; 
    em[1227] = 8884097; em[1228] = 8; em[1229] = 0; /* 1227: pointer.func */
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
    em[1266] = 0; em[1267] = 40; em[1268] = 3; /* 1266: struct.asn1_object_st */
    	em[1269] = 155; em[1270] = 0; 
    	em[1271] = 155; em[1272] = 8; 
    	em[1273] = 1275; em[1274] = 24; 
    em[1275] = 1; em[1276] = 8; em[1277] = 1; /* 1275: pointer.unsigned char */
    	em[1278] = 34; em[1279] = 0; 
    em[1280] = 1; em[1281] = 8; em[1282] = 1; /* 1280: pointer.struct.asn1_string_st */
    	em[1283] = 53; em[1284] = 0; 
    em[1285] = 8884097; em[1286] = 8; em[1287] = 0; /* 1285: pointer.func */
    em[1288] = 1; em[1289] = 8; em[1290] = 1; /* 1288: pointer.struct.asn1_string_st */
    	em[1291] = 53; em[1292] = 0; 
    em[1293] = 1; em[1294] = 8; em[1295] = 1; /* 1293: pointer.struct.asn1_string_st */
    	em[1296] = 24; em[1297] = 0; 
    em[1298] = 8884097; em[1299] = 8; em[1300] = 0; /* 1298: pointer.func */
    em[1301] = 0; em[1302] = 120; em[1303] = 8; /* 1301: struct.env_md_st */
    	em[1304] = 1320; em[1305] = 24; 
    	em[1306] = 1323; em[1307] = 32; 
    	em[1308] = 1326; em[1309] = 40; 
    	em[1310] = 1329; em[1311] = 48; 
    	em[1312] = 1320; em[1313] = 56; 
    	em[1314] = 1332; em[1315] = 64; 
    	em[1316] = 1263; em[1317] = 72; 
    	em[1318] = 1335; em[1319] = 112; 
    em[1320] = 8884097; em[1321] = 8; em[1322] = 0; /* 1320: pointer.func */
    em[1323] = 8884097; em[1324] = 8; em[1325] = 0; /* 1323: pointer.func */
    em[1326] = 8884097; em[1327] = 8; em[1328] = 0; /* 1326: pointer.func */
    em[1329] = 8884097; em[1330] = 8; em[1331] = 0; /* 1329: pointer.func */
    em[1332] = 8884097; em[1333] = 8; em[1334] = 0; /* 1332: pointer.func */
    em[1335] = 8884097; em[1336] = 8; em[1337] = 0; /* 1335: pointer.func */
    em[1338] = 1; em[1339] = 8; em[1340] = 1; /* 1338: pointer.struct.asn1_string_st */
    	em[1341] = 24; em[1342] = 0; 
    em[1343] = 8884097; em[1344] = 8; em[1345] = 0; /* 1343: pointer.func */
    em[1346] = 8884097; em[1347] = 8; em[1348] = 0; /* 1346: pointer.func */
    em[1349] = 1; em[1350] = 8; em[1351] = 1; /* 1349: pointer.struct.evp_pkey_ctx_st */
    	em[1352] = 1354; em[1353] = 0; 
    em[1354] = 0; em[1355] = 80; em[1356] = 8; /* 1354: struct.evp_pkey_ctx_st */
    	em[1357] = 1373; em[1358] = 0; 
    	em[1359] = 1455; em[1360] = 8; 
    	em[1361] = 1460; em[1362] = 16; 
    	em[1363] = 1460; em[1364] = 24; 
    	em[1365] = 76; em[1366] = 40; 
    	em[1367] = 76; em[1368] = 48; 
    	em[1369] = 8; em[1370] = 56; 
    	em[1371] = 0; em[1372] = 64; 
    em[1373] = 1; em[1374] = 8; em[1375] = 1; /* 1373: pointer.struct.evp_pkey_method_st */
    	em[1376] = 1378; em[1377] = 0; 
    em[1378] = 0; em[1379] = 208; em[1380] = 25; /* 1378: struct.evp_pkey_method_st */
    	em[1381] = 1431; em[1382] = 8; 
    	em[1383] = 1434; em[1384] = 16; 
    	em[1385] = 1346; em[1386] = 24; 
    	em[1387] = 1431; em[1388] = 32; 
    	em[1389] = 1437; em[1390] = 40; 
    	em[1391] = 1431; em[1392] = 48; 
    	em[1393] = 1437; em[1394] = 56; 
    	em[1395] = 1431; em[1396] = 64; 
    	em[1397] = 1343; em[1398] = 72; 
    	em[1399] = 1431; em[1400] = 80; 
    	em[1401] = 1440; em[1402] = 88; 
    	em[1403] = 1431; em[1404] = 96; 
    	em[1405] = 1343; em[1406] = 104; 
    	em[1407] = 1443; em[1408] = 112; 
    	em[1409] = 1446; em[1410] = 120; 
    	em[1411] = 1443; em[1412] = 128; 
    	em[1413] = 1298; em[1414] = 136; 
    	em[1415] = 1431; em[1416] = 144; 
    	em[1417] = 1343; em[1418] = 152; 
    	em[1419] = 1431; em[1420] = 160; 
    	em[1421] = 1343; em[1422] = 168; 
    	em[1423] = 1431; em[1424] = 176; 
    	em[1425] = 1449; em[1426] = 184; 
    	em[1427] = 1452; em[1428] = 192; 
    	em[1429] = 1285; em[1430] = 200; 
    em[1431] = 8884097; em[1432] = 8; em[1433] = 0; /* 1431: pointer.func */
    em[1434] = 8884097; em[1435] = 8; em[1436] = 0; /* 1434: pointer.func */
    em[1437] = 8884097; em[1438] = 8; em[1439] = 0; /* 1437: pointer.func */
    em[1440] = 8884097; em[1441] = 8; em[1442] = 0; /* 1440: pointer.func */
    em[1443] = 8884097; em[1444] = 8; em[1445] = 0; /* 1443: pointer.func */
    em[1446] = 8884097; em[1447] = 8; em[1448] = 0; /* 1446: pointer.func */
    em[1449] = 8884097; em[1450] = 8; em[1451] = 0; /* 1449: pointer.func */
    em[1452] = 8884097; em[1453] = 8; em[1454] = 0; /* 1452: pointer.func */
    em[1455] = 1; em[1456] = 8; em[1457] = 1; /* 1455: pointer.struct.engine_st */
    	em[1458] = 185; em[1459] = 0; 
    em[1460] = 1; em[1461] = 8; em[1462] = 1; /* 1460: pointer.struct.evp_pkey_st */
    	em[1463] = 1465; em[1464] = 0; 
    em[1465] = 0; em[1466] = 56; em[1467] = 4; /* 1465: struct.evp_pkey_st */
    	em[1468] = 1476; em[1469] = 16; 
    	em[1470] = 1455; em[1471] = 24; 
    	em[1472] = 61; em[1473] = 32; 
    	em[1474] = 1481; em[1475] = 48; 
    em[1476] = 1; em[1477] = 8; em[1478] = 1; /* 1476: pointer.struct.evp_pkey_asn1_method_st */
    	em[1479] = 1176; em[1480] = 0; 
    em[1481] = 1; em[1482] = 8; em[1483] = 1; /* 1481: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[1484] = 1486; em[1485] = 0; 
    em[1486] = 0; em[1487] = 32; em[1488] = 2; /* 1486: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[1489] = 1493; em[1490] = 8; 
    	em[1491] = 515; em[1492] = 24; 
    em[1493] = 8884099; em[1494] = 8; em[1495] = 2; /* 1493: pointer_to_array_of_pointers_to_stack */
    	em[1496] = 1500; em[1497] = 0; 
    	em[1498] = 5; em[1499] = 20; 
    em[1500] = 0; em[1501] = 8; em[1502] = 1; /* 1500: pointer.X509_ATTRIBUTE */
    	em[1503] = 1505; em[1504] = 0; 
    em[1505] = 0; em[1506] = 0; em[1507] = 1; /* 1505: X509_ATTRIBUTE */
    	em[1508] = 1510; em[1509] = 0; 
    em[1510] = 0; em[1511] = 24; em[1512] = 2; /* 1510: struct.x509_attributes_st */
    	em[1513] = 1517; em[1514] = 0; 
    	em[1515] = 1531; em[1516] = 16; 
    em[1517] = 1; em[1518] = 8; em[1519] = 1; /* 1517: pointer.struct.asn1_object_st */
    	em[1520] = 1522; em[1521] = 0; 
    em[1522] = 0; em[1523] = 40; em[1524] = 3; /* 1522: struct.asn1_object_st */
    	em[1525] = 155; em[1526] = 0; 
    	em[1527] = 155; em[1528] = 8; 
    	em[1529] = 1275; em[1530] = 24; 
    em[1531] = 0; em[1532] = 8; em[1533] = 3; /* 1531: union.unknown */
    	em[1534] = 166; em[1535] = 0; 
    	em[1536] = 1540; em[1537] = 0; 
    	em[1538] = 1695; em[1539] = 0; 
    em[1540] = 1; em[1541] = 8; em[1542] = 1; /* 1540: pointer.struct.stack_st_ASN1_TYPE */
    	em[1543] = 1545; em[1544] = 0; 
    em[1545] = 0; em[1546] = 32; em[1547] = 2; /* 1545: struct.stack_st_fake_ASN1_TYPE */
    	em[1548] = 1552; em[1549] = 8; 
    	em[1550] = 515; em[1551] = 24; 
    em[1552] = 8884099; em[1553] = 8; em[1554] = 2; /* 1552: pointer_to_array_of_pointers_to_stack */
    	em[1555] = 1559; em[1556] = 0; 
    	em[1557] = 5; em[1558] = 20; 
    em[1559] = 0; em[1560] = 8; em[1561] = 1; /* 1559: pointer.ASN1_TYPE */
    	em[1562] = 1564; em[1563] = 0; 
    em[1564] = 0; em[1565] = 0; em[1566] = 1; /* 1564: ASN1_TYPE */
    	em[1567] = 1569; em[1568] = 0; 
    em[1569] = 0; em[1570] = 16; em[1571] = 1; /* 1569: struct.asn1_type_st */
    	em[1572] = 1574; em[1573] = 8; 
    em[1574] = 0; em[1575] = 8; em[1576] = 20; /* 1574: union.unknown */
    	em[1577] = 166; em[1578] = 0; 
    	em[1579] = 1617; em[1580] = 0; 
    	em[1581] = 1622; em[1582] = 0; 
    	em[1583] = 1627; em[1584] = 0; 
    	em[1585] = 1632; em[1586] = 0; 
    	em[1587] = 1637; em[1588] = 0; 
    	em[1589] = 1642; em[1590] = 0; 
    	em[1591] = 1647; em[1592] = 0; 
    	em[1593] = 1652; em[1594] = 0; 
    	em[1595] = 1657; em[1596] = 0; 
    	em[1597] = 1288; em[1598] = 0; 
    	em[1599] = 1662; em[1600] = 0; 
    	em[1601] = 1667; em[1602] = 0; 
    	em[1603] = 1672; em[1604] = 0; 
    	em[1605] = 1677; em[1606] = 0; 
    	em[1607] = 1280; em[1608] = 0; 
    	em[1609] = 1682; em[1610] = 0; 
    	em[1611] = 1617; em[1612] = 0; 
    	em[1613] = 1617; em[1614] = 0; 
    	em[1615] = 1687; em[1616] = 0; 
    em[1617] = 1; em[1618] = 8; em[1619] = 1; /* 1617: pointer.struct.asn1_string_st */
    	em[1620] = 53; em[1621] = 0; 
    em[1622] = 1; em[1623] = 8; em[1624] = 1; /* 1622: pointer.struct.asn1_object_st */
    	em[1625] = 1266; em[1626] = 0; 
    em[1627] = 1; em[1628] = 8; em[1629] = 1; /* 1627: pointer.struct.asn1_string_st */
    	em[1630] = 53; em[1631] = 0; 
    em[1632] = 1; em[1633] = 8; em[1634] = 1; /* 1632: pointer.struct.asn1_string_st */
    	em[1635] = 53; em[1636] = 0; 
    em[1637] = 1; em[1638] = 8; em[1639] = 1; /* 1637: pointer.struct.asn1_string_st */
    	em[1640] = 53; em[1641] = 0; 
    em[1642] = 1; em[1643] = 8; em[1644] = 1; /* 1642: pointer.struct.asn1_string_st */
    	em[1645] = 53; em[1646] = 0; 
    em[1647] = 1; em[1648] = 8; em[1649] = 1; /* 1647: pointer.struct.asn1_string_st */
    	em[1650] = 53; em[1651] = 0; 
    em[1652] = 1; em[1653] = 8; em[1654] = 1; /* 1652: pointer.struct.asn1_string_st */
    	em[1655] = 53; em[1656] = 0; 
    em[1657] = 1; em[1658] = 8; em[1659] = 1; /* 1657: pointer.struct.asn1_string_st */
    	em[1660] = 53; em[1661] = 0; 
    em[1662] = 1; em[1663] = 8; em[1664] = 1; /* 1662: pointer.struct.asn1_string_st */
    	em[1665] = 53; em[1666] = 0; 
    em[1667] = 1; em[1668] = 8; em[1669] = 1; /* 1667: pointer.struct.asn1_string_st */
    	em[1670] = 53; em[1671] = 0; 
    em[1672] = 1; em[1673] = 8; em[1674] = 1; /* 1672: pointer.struct.asn1_string_st */
    	em[1675] = 53; em[1676] = 0; 
    em[1677] = 1; em[1678] = 8; em[1679] = 1; /* 1677: pointer.struct.asn1_string_st */
    	em[1680] = 53; em[1681] = 0; 
    em[1682] = 1; em[1683] = 8; em[1684] = 1; /* 1682: pointer.struct.asn1_string_st */
    	em[1685] = 53; em[1686] = 0; 
    em[1687] = 1; em[1688] = 8; em[1689] = 1; /* 1687: pointer.struct.ASN1_VALUE_st */
    	em[1690] = 1692; em[1691] = 0; 
    em[1692] = 0; em[1693] = 0; em[1694] = 0; /* 1692: struct.ASN1_VALUE_st */
    em[1695] = 1; em[1696] = 8; em[1697] = 1; /* 1695: pointer.struct.asn1_type_st */
    	em[1698] = 1700; em[1699] = 0; 
    em[1700] = 0; em[1701] = 16; em[1702] = 1; /* 1700: struct.asn1_type_st */
    	em[1703] = 1705; em[1704] = 8; 
    em[1705] = 0; em[1706] = 8; em[1707] = 20; /* 1705: union.unknown */
    	em[1708] = 166; em[1709] = 0; 
    	em[1710] = 1748; em[1711] = 0; 
    	em[1712] = 1517; em[1713] = 0; 
    	em[1714] = 1338; em[1715] = 0; 
    	em[1716] = 1753; em[1717] = 0; 
    	em[1718] = 1758; em[1719] = 0; 
    	em[1720] = 1763; em[1721] = 0; 
    	em[1722] = 1768; em[1723] = 0; 
    	em[1724] = 1293; em[1725] = 0; 
    	em[1726] = 1773; em[1727] = 0; 
    	em[1728] = 1778; em[1729] = 0; 
    	em[1730] = 1783; em[1731] = 0; 
    	em[1732] = 42; em[1733] = 0; 
    	em[1734] = 1788; em[1735] = 0; 
    	em[1736] = 1793; em[1737] = 0; 
    	em[1738] = 37; em[1739] = 0; 
    	em[1740] = 19; em[1741] = 0; 
    	em[1742] = 1748; em[1743] = 0; 
    	em[1744] = 1748; em[1745] = 0; 
    	em[1746] = 14; em[1747] = 0; 
    em[1748] = 1; em[1749] = 8; em[1750] = 1; /* 1748: pointer.struct.asn1_string_st */
    	em[1751] = 24; em[1752] = 0; 
    em[1753] = 1; em[1754] = 8; em[1755] = 1; /* 1753: pointer.struct.asn1_string_st */
    	em[1756] = 24; em[1757] = 0; 
    em[1758] = 1; em[1759] = 8; em[1760] = 1; /* 1758: pointer.struct.asn1_string_st */
    	em[1761] = 24; em[1762] = 0; 
    em[1763] = 1; em[1764] = 8; em[1765] = 1; /* 1763: pointer.struct.asn1_string_st */
    	em[1766] = 24; em[1767] = 0; 
    em[1768] = 1; em[1769] = 8; em[1770] = 1; /* 1768: pointer.struct.asn1_string_st */
    	em[1771] = 24; em[1772] = 0; 
    em[1773] = 1; em[1774] = 8; em[1775] = 1; /* 1773: pointer.struct.asn1_string_st */
    	em[1776] = 24; em[1777] = 0; 
    em[1778] = 1; em[1779] = 8; em[1780] = 1; /* 1778: pointer.struct.asn1_string_st */
    	em[1781] = 24; em[1782] = 0; 
    em[1783] = 1; em[1784] = 8; em[1785] = 1; /* 1783: pointer.struct.asn1_string_st */
    	em[1786] = 24; em[1787] = 0; 
    em[1788] = 1; em[1789] = 8; em[1790] = 1; /* 1788: pointer.struct.asn1_string_st */
    	em[1791] = 24; em[1792] = 0; 
    em[1793] = 1; em[1794] = 8; em[1795] = 1; /* 1793: pointer.struct.asn1_string_st */
    	em[1796] = 24; em[1797] = 0; 
    em[1798] = 0; em[1799] = 1; em[1800] = 0; /* 1798: char */
    em[1801] = 0; em[1802] = 48; em[1803] = 5; /* 1801: struct.env_md_ctx_st */
    	em[1804] = 1814; em[1805] = 0; 
    	em[1806] = 1455; em[1807] = 8; 
    	em[1808] = 76; em[1809] = 24; 
    	em[1810] = 1349; em[1811] = 32; 
    	em[1812] = 1323; em[1813] = 40; 
    em[1814] = 1; em[1815] = 8; em[1816] = 1; /* 1814: pointer.struct.env_md_st */
    	em[1817] = 1301; em[1818] = 0; 
    em[1819] = 1; em[1820] = 8; em[1821] = 1; /* 1819: pointer.struct.env_md_ctx_st */
    	em[1822] = 1801; em[1823] = 0; 
    args_addr->arg_entity_index[0] = 1819;
    args_addr->ret_entity_index = -1;
    populate_arg(args_addr, arg_a);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    EVP_MD_CTX * new_arg_a = *((EVP_MD_CTX * *)new_args->args[0]);

    void (*orig_EVP_MD_CTX_destroy)(EVP_MD_CTX *);
    orig_EVP_MD_CTX_destroy = dlsym(RTLD_NEXT, "EVP_MD_CTX_destroy");
    (*orig_EVP_MD_CTX_destroy)(new_arg_a);

    syscall(889);

    free(args_addr);

}

