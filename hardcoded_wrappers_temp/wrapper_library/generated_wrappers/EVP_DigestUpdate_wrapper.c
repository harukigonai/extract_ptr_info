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

int bb_EVP_DigestUpdate(EVP_MD_CTX * arg_a, const void * arg_b,size_t arg_c);

int EVP_DigestUpdate(EVP_MD_CTX * arg_a, const void * arg_b,size_t arg_c) 
{
    unsigned long in_lib = syscall(890);
    printf("EVP_DigestUpdate called %lu\n", in_lib);
    if (!in_lib)
        return bb_EVP_DigestUpdate(arg_a,arg_b,arg_c);
    else {
        int (*orig_EVP_DigestUpdate)(EVP_MD_CTX *, const void *,size_t);
        orig_EVP_DigestUpdate = dlsym(RTLD_NEXT, "EVP_DigestUpdate");
        return orig_EVP_DigestUpdate(arg_a,arg_b,arg_c);
    }
}

int bb_EVP_DigestUpdate(EVP_MD_CTX * arg_a, const void * arg_b,size_t arg_c) 
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
    em[52] = 8884097; em[53] = 8; em[54] = 0; /* 52: pointer.func */
    em[55] = 0; em[56] = 24; em[57] = 1; /* 55: struct.asn1_string_st */
    	em[58] = 29; em[59] = 8; 
    em[60] = 8884097; em[61] = 8; em[62] = 0; /* 60: pointer.func */
    em[63] = 8884101; em[64] = 8; em[65] = 6; /* 63: union.union_of_evp_pkey_st */
    	em[66] = 78; em[67] = 0; 
    	em[68] = 81; em[69] = 6; 
    	em[70] = 634; em[71] = 116; 
    	em[72] = 765; em[73] = 28; 
    	em[74] = 847; em[75] = 408; 
    	em[76] = 5; em[77] = 0; 
    em[78] = 0; em[79] = 8; em[80] = 0; /* 78: pointer.void */
    em[81] = 1; em[82] = 8; em[83] = 1; /* 81: pointer.struct.rsa_st */
    	em[84] = 86; em[85] = 0; 
    em[86] = 0; em[87] = 168; em[88] = 17; /* 86: struct.rsa_st */
    	em[89] = 123; em[90] = 16; 
    	em[91] = 182; em[92] = 24; 
    	em[93] = 525; em[94] = 32; 
    	em[95] = 525; em[96] = 40; 
    	em[97] = 525; em[98] = 48; 
    	em[99] = 525; em[100] = 56; 
    	em[101] = 525; em[102] = 64; 
    	em[103] = 525; em[104] = 72; 
    	em[105] = 525; em[106] = 80; 
    	em[107] = 525; em[108] = 88; 
    	em[109] = 545; em[110] = 96; 
    	em[111] = 559; em[112] = 120; 
    	em[113] = 559; em[114] = 128; 
    	em[115] = 559; em[116] = 136; 
    	em[117] = 168; em[118] = 144; 
    	em[119] = 573; em[120] = 152; 
    	em[121] = 573; em[122] = 160; 
    em[123] = 1; em[124] = 8; em[125] = 1; /* 123: pointer.struct.rsa_meth_st */
    	em[126] = 128; em[127] = 0; 
    em[128] = 0; em[129] = 112; em[130] = 13; /* 128: struct.rsa_meth_st */
    	em[131] = 157; em[132] = 0; 
    	em[133] = 162; em[134] = 8; 
    	em[135] = 162; em[136] = 16; 
    	em[137] = 162; em[138] = 24; 
    	em[139] = 162; em[140] = 32; 
    	em[141] = 165; em[142] = 40; 
    	em[143] = 60; em[144] = 48; 
    	em[145] = 52; em[146] = 56; 
    	em[147] = 52; em[148] = 64; 
    	em[149] = 168; em[150] = 80; 
    	em[151] = 173; em[152] = 88; 
    	em[153] = 176; em[154] = 96; 
    	em[155] = 179; em[156] = 104; 
    em[157] = 1; em[158] = 8; em[159] = 1; /* 157: pointer.char */
    	em[160] = 8884096; em[161] = 0; 
    em[162] = 8884097; em[163] = 8; em[164] = 0; /* 162: pointer.func */
    em[165] = 8884097; em[166] = 8; em[167] = 0; /* 165: pointer.func */
    em[168] = 1; em[169] = 8; em[170] = 1; /* 168: pointer.char */
    	em[171] = 8884096; em[172] = 0; 
    em[173] = 8884097; em[174] = 8; em[175] = 0; /* 173: pointer.func */
    em[176] = 8884097; em[177] = 8; em[178] = 0; /* 176: pointer.func */
    em[179] = 8884097; em[180] = 8; em[181] = 0; /* 179: pointer.func */
    em[182] = 1; em[183] = 8; em[184] = 1; /* 182: pointer.struct.engine_st */
    	em[185] = 187; em[186] = 0; 
    em[187] = 0; em[188] = 216; em[189] = 24; /* 187: struct.engine_st */
    	em[190] = 157; em[191] = 0; 
    	em[192] = 157; em[193] = 8; 
    	em[194] = 238; em[195] = 16; 
    	em[196] = 293; em[197] = 24; 
    	em[198] = 344; em[199] = 32; 
    	em[200] = 380; em[201] = 40; 
    	em[202] = 397; em[203] = 48; 
    	em[204] = 424; em[205] = 56; 
    	em[206] = 459; em[207] = 64; 
    	em[208] = 467; em[209] = 72; 
    	em[210] = 470; em[211] = 80; 
    	em[212] = 473; em[213] = 88; 
    	em[214] = 476; em[215] = 96; 
    	em[216] = 479; em[217] = 104; 
    	em[218] = 479; em[219] = 112; 
    	em[220] = 479; em[221] = 120; 
    	em[222] = 482; em[223] = 128; 
    	em[224] = 485; em[225] = 136; 
    	em[226] = 485; em[227] = 144; 
    	em[228] = 488; em[229] = 152; 
    	em[230] = 491; em[231] = 160; 
    	em[232] = 503; em[233] = 184; 
    	em[234] = 520; em[235] = 200; 
    	em[236] = 520; em[237] = 208; 
    em[238] = 1; em[239] = 8; em[240] = 1; /* 238: pointer.struct.rsa_meth_st */
    	em[241] = 243; em[242] = 0; 
    em[243] = 0; em[244] = 112; em[245] = 13; /* 243: struct.rsa_meth_st */
    	em[246] = 157; em[247] = 0; 
    	em[248] = 272; em[249] = 8; 
    	em[250] = 272; em[251] = 16; 
    	em[252] = 272; em[253] = 24; 
    	em[254] = 272; em[255] = 32; 
    	em[256] = 275; em[257] = 40; 
    	em[258] = 278; em[259] = 48; 
    	em[260] = 281; em[261] = 56; 
    	em[262] = 281; em[263] = 64; 
    	em[264] = 168; em[265] = 80; 
    	em[266] = 284; em[267] = 88; 
    	em[268] = 287; em[269] = 96; 
    	em[270] = 290; em[271] = 104; 
    em[272] = 8884097; em[273] = 8; em[274] = 0; /* 272: pointer.func */
    em[275] = 8884097; em[276] = 8; em[277] = 0; /* 275: pointer.func */
    em[278] = 8884097; em[279] = 8; em[280] = 0; /* 278: pointer.func */
    em[281] = 8884097; em[282] = 8; em[283] = 0; /* 281: pointer.func */
    em[284] = 8884097; em[285] = 8; em[286] = 0; /* 284: pointer.func */
    em[287] = 8884097; em[288] = 8; em[289] = 0; /* 287: pointer.func */
    em[290] = 8884097; em[291] = 8; em[292] = 0; /* 290: pointer.func */
    em[293] = 1; em[294] = 8; em[295] = 1; /* 293: pointer.struct.dsa_method */
    	em[296] = 298; em[297] = 0; 
    em[298] = 0; em[299] = 96; em[300] = 11; /* 298: struct.dsa_method */
    	em[301] = 157; em[302] = 0; 
    	em[303] = 323; em[304] = 8; 
    	em[305] = 326; em[306] = 16; 
    	em[307] = 329; em[308] = 24; 
    	em[309] = 332; em[310] = 32; 
    	em[311] = 335; em[312] = 40; 
    	em[313] = 338; em[314] = 48; 
    	em[315] = 338; em[316] = 56; 
    	em[317] = 168; em[318] = 72; 
    	em[319] = 341; em[320] = 80; 
    	em[321] = 338; em[322] = 88; 
    em[323] = 8884097; em[324] = 8; em[325] = 0; /* 323: pointer.func */
    em[326] = 8884097; em[327] = 8; em[328] = 0; /* 326: pointer.func */
    em[329] = 8884097; em[330] = 8; em[331] = 0; /* 329: pointer.func */
    em[332] = 8884097; em[333] = 8; em[334] = 0; /* 332: pointer.func */
    em[335] = 8884097; em[336] = 8; em[337] = 0; /* 335: pointer.func */
    em[338] = 8884097; em[339] = 8; em[340] = 0; /* 338: pointer.func */
    em[341] = 8884097; em[342] = 8; em[343] = 0; /* 341: pointer.func */
    em[344] = 1; em[345] = 8; em[346] = 1; /* 344: pointer.struct.dh_method */
    	em[347] = 349; em[348] = 0; 
    em[349] = 0; em[350] = 72; em[351] = 8; /* 349: struct.dh_method */
    	em[352] = 157; em[353] = 0; 
    	em[354] = 368; em[355] = 8; 
    	em[356] = 371; em[357] = 16; 
    	em[358] = 374; em[359] = 24; 
    	em[360] = 368; em[361] = 32; 
    	em[362] = 368; em[363] = 40; 
    	em[364] = 168; em[365] = 56; 
    	em[366] = 377; em[367] = 64; 
    em[368] = 8884097; em[369] = 8; em[370] = 0; /* 368: pointer.func */
    em[371] = 8884097; em[372] = 8; em[373] = 0; /* 371: pointer.func */
    em[374] = 8884097; em[375] = 8; em[376] = 0; /* 374: pointer.func */
    em[377] = 8884097; em[378] = 8; em[379] = 0; /* 377: pointer.func */
    em[380] = 1; em[381] = 8; em[382] = 1; /* 380: pointer.struct.ecdh_method */
    	em[383] = 385; em[384] = 0; 
    em[385] = 0; em[386] = 32; em[387] = 3; /* 385: struct.ecdh_method */
    	em[388] = 157; em[389] = 0; 
    	em[390] = 394; em[391] = 8; 
    	em[392] = 168; em[393] = 24; 
    em[394] = 8884097; em[395] = 8; em[396] = 0; /* 394: pointer.func */
    em[397] = 1; em[398] = 8; em[399] = 1; /* 397: pointer.struct.ecdsa_method */
    	em[400] = 402; em[401] = 0; 
    em[402] = 0; em[403] = 48; em[404] = 5; /* 402: struct.ecdsa_method */
    	em[405] = 157; em[406] = 0; 
    	em[407] = 415; em[408] = 8; 
    	em[409] = 418; em[410] = 16; 
    	em[411] = 421; em[412] = 24; 
    	em[413] = 168; em[414] = 40; 
    em[415] = 8884097; em[416] = 8; em[417] = 0; /* 415: pointer.func */
    em[418] = 8884097; em[419] = 8; em[420] = 0; /* 418: pointer.func */
    em[421] = 8884097; em[422] = 8; em[423] = 0; /* 421: pointer.func */
    em[424] = 1; em[425] = 8; em[426] = 1; /* 424: pointer.struct.rand_meth_st */
    	em[427] = 429; em[428] = 0; 
    em[429] = 0; em[430] = 48; em[431] = 6; /* 429: struct.rand_meth_st */
    	em[432] = 444; em[433] = 0; 
    	em[434] = 447; em[435] = 8; 
    	em[436] = 450; em[437] = 16; 
    	em[438] = 453; em[439] = 24; 
    	em[440] = 447; em[441] = 32; 
    	em[442] = 456; em[443] = 40; 
    em[444] = 8884097; em[445] = 8; em[446] = 0; /* 444: pointer.func */
    em[447] = 8884097; em[448] = 8; em[449] = 0; /* 447: pointer.func */
    em[450] = 8884097; em[451] = 8; em[452] = 0; /* 450: pointer.func */
    em[453] = 8884097; em[454] = 8; em[455] = 0; /* 453: pointer.func */
    em[456] = 8884097; em[457] = 8; em[458] = 0; /* 456: pointer.func */
    em[459] = 1; em[460] = 8; em[461] = 1; /* 459: pointer.struct.store_method_st */
    	em[462] = 464; em[463] = 0; 
    em[464] = 0; em[465] = 0; em[466] = 0; /* 464: struct.store_method_st */
    em[467] = 8884097; em[468] = 8; em[469] = 0; /* 467: pointer.func */
    em[470] = 8884097; em[471] = 8; em[472] = 0; /* 470: pointer.func */
    em[473] = 8884097; em[474] = 8; em[475] = 0; /* 473: pointer.func */
    em[476] = 8884097; em[477] = 8; em[478] = 0; /* 476: pointer.func */
    em[479] = 8884097; em[480] = 8; em[481] = 0; /* 479: pointer.func */
    em[482] = 8884097; em[483] = 8; em[484] = 0; /* 482: pointer.func */
    em[485] = 8884097; em[486] = 8; em[487] = 0; /* 485: pointer.func */
    em[488] = 8884097; em[489] = 8; em[490] = 0; /* 488: pointer.func */
    em[491] = 1; em[492] = 8; em[493] = 1; /* 491: pointer.struct.ENGINE_CMD_DEFN_st */
    	em[494] = 496; em[495] = 0; 
    em[496] = 0; em[497] = 32; em[498] = 2; /* 496: struct.ENGINE_CMD_DEFN_st */
    	em[499] = 157; em[500] = 8; 
    	em[501] = 157; em[502] = 16; 
    em[503] = 0; em[504] = 32; em[505] = 2; /* 503: struct.crypto_ex_data_st_fake */
    	em[506] = 510; em[507] = 8; 
    	em[508] = 517; em[509] = 24; 
    em[510] = 8884099; em[511] = 8; em[512] = 2; /* 510: pointer_to_array_of_pointers_to_stack */
    	em[513] = 78; em[514] = 0; 
    	em[515] = 5; em[516] = 20; 
    em[517] = 8884097; em[518] = 8; em[519] = 0; /* 517: pointer.func */
    em[520] = 1; em[521] = 8; em[522] = 1; /* 520: pointer.struct.engine_st */
    	em[523] = 187; em[524] = 0; 
    em[525] = 1; em[526] = 8; em[527] = 1; /* 525: pointer.struct.bignum_st */
    	em[528] = 530; em[529] = 0; 
    em[530] = 0; em[531] = 24; em[532] = 1; /* 530: struct.bignum_st */
    	em[533] = 535; em[534] = 0; 
    em[535] = 8884099; em[536] = 8; em[537] = 2; /* 535: pointer_to_array_of_pointers_to_stack */
    	em[538] = 542; em[539] = 0; 
    	em[540] = 5; em[541] = 12; 
    em[542] = 0; em[543] = 8; em[544] = 0; /* 542: long unsigned int */
    em[545] = 0; em[546] = 32; em[547] = 2; /* 545: struct.crypto_ex_data_st_fake */
    	em[548] = 552; em[549] = 8; 
    	em[550] = 517; em[551] = 24; 
    em[552] = 8884099; em[553] = 8; em[554] = 2; /* 552: pointer_to_array_of_pointers_to_stack */
    	em[555] = 78; em[556] = 0; 
    	em[557] = 5; em[558] = 20; 
    em[559] = 1; em[560] = 8; em[561] = 1; /* 559: pointer.struct.bn_mont_ctx_st */
    	em[562] = 564; em[563] = 0; 
    em[564] = 0; em[565] = 96; em[566] = 3; /* 564: struct.bn_mont_ctx_st */
    	em[567] = 530; em[568] = 8; 
    	em[569] = 530; em[570] = 32; 
    	em[571] = 530; em[572] = 56; 
    em[573] = 1; em[574] = 8; em[575] = 1; /* 573: pointer.struct.bn_blinding_st */
    	em[576] = 578; em[577] = 0; 
    em[578] = 0; em[579] = 88; em[580] = 7; /* 578: struct.bn_blinding_st */
    	em[581] = 595; em[582] = 0; 
    	em[583] = 595; em[584] = 8; 
    	em[585] = 595; em[586] = 16; 
    	em[587] = 595; em[588] = 24; 
    	em[589] = 612; em[590] = 40; 
    	em[591] = 617; em[592] = 72; 
    	em[593] = 631; em[594] = 80; 
    em[595] = 1; em[596] = 8; em[597] = 1; /* 595: pointer.struct.bignum_st */
    	em[598] = 600; em[599] = 0; 
    em[600] = 0; em[601] = 24; em[602] = 1; /* 600: struct.bignum_st */
    	em[603] = 605; em[604] = 0; 
    em[605] = 8884099; em[606] = 8; em[607] = 2; /* 605: pointer_to_array_of_pointers_to_stack */
    	em[608] = 542; em[609] = 0; 
    	em[610] = 5; em[611] = 12; 
    em[612] = 0; em[613] = 16; em[614] = 1; /* 612: struct.crypto_threadid_st */
    	em[615] = 78; em[616] = 0; 
    em[617] = 1; em[618] = 8; em[619] = 1; /* 617: pointer.struct.bn_mont_ctx_st */
    	em[620] = 622; em[621] = 0; 
    em[622] = 0; em[623] = 96; em[624] = 3; /* 622: struct.bn_mont_ctx_st */
    	em[625] = 600; em[626] = 8; 
    	em[627] = 600; em[628] = 32; 
    	em[629] = 600; em[630] = 56; 
    em[631] = 8884097; em[632] = 8; em[633] = 0; /* 631: pointer.func */
    em[634] = 1; em[635] = 8; em[636] = 1; /* 634: pointer.struct.dsa_st */
    	em[637] = 639; em[638] = 0; 
    em[639] = 0; em[640] = 136; em[641] = 11; /* 639: struct.dsa_st */
    	em[642] = 664; em[643] = 24; 
    	em[644] = 664; em[645] = 32; 
    	em[646] = 664; em[647] = 40; 
    	em[648] = 664; em[649] = 48; 
    	em[650] = 664; em[651] = 56; 
    	em[652] = 664; em[653] = 64; 
    	em[654] = 664; em[655] = 72; 
    	em[656] = 681; em[657] = 88; 
    	em[658] = 695; em[659] = 104; 
    	em[660] = 709; em[661] = 120; 
    	em[662] = 760; em[663] = 128; 
    em[664] = 1; em[665] = 8; em[666] = 1; /* 664: pointer.struct.bignum_st */
    	em[667] = 669; em[668] = 0; 
    em[669] = 0; em[670] = 24; em[671] = 1; /* 669: struct.bignum_st */
    	em[672] = 674; em[673] = 0; 
    em[674] = 8884099; em[675] = 8; em[676] = 2; /* 674: pointer_to_array_of_pointers_to_stack */
    	em[677] = 542; em[678] = 0; 
    	em[679] = 5; em[680] = 12; 
    em[681] = 1; em[682] = 8; em[683] = 1; /* 681: pointer.struct.bn_mont_ctx_st */
    	em[684] = 686; em[685] = 0; 
    em[686] = 0; em[687] = 96; em[688] = 3; /* 686: struct.bn_mont_ctx_st */
    	em[689] = 669; em[690] = 8; 
    	em[691] = 669; em[692] = 32; 
    	em[693] = 669; em[694] = 56; 
    em[695] = 0; em[696] = 32; em[697] = 2; /* 695: struct.crypto_ex_data_st_fake */
    	em[698] = 702; em[699] = 8; 
    	em[700] = 517; em[701] = 24; 
    em[702] = 8884099; em[703] = 8; em[704] = 2; /* 702: pointer_to_array_of_pointers_to_stack */
    	em[705] = 78; em[706] = 0; 
    	em[707] = 5; em[708] = 20; 
    em[709] = 1; em[710] = 8; em[711] = 1; /* 709: pointer.struct.dsa_method */
    	em[712] = 714; em[713] = 0; 
    em[714] = 0; em[715] = 96; em[716] = 11; /* 714: struct.dsa_method */
    	em[717] = 157; em[718] = 0; 
    	em[719] = 739; em[720] = 8; 
    	em[721] = 742; em[722] = 16; 
    	em[723] = 745; em[724] = 24; 
    	em[725] = 748; em[726] = 32; 
    	em[727] = 751; em[728] = 40; 
    	em[729] = 754; em[730] = 48; 
    	em[731] = 754; em[732] = 56; 
    	em[733] = 168; em[734] = 72; 
    	em[735] = 757; em[736] = 80; 
    	em[737] = 754; em[738] = 88; 
    em[739] = 8884097; em[740] = 8; em[741] = 0; /* 739: pointer.func */
    em[742] = 8884097; em[743] = 8; em[744] = 0; /* 742: pointer.func */
    em[745] = 8884097; em[746] = 8; em[747] = 0; /* 745: pointer.func */
    em[748] = 8884097; em[749] = 8; em[750] = 0; /* 748: pointer.func */
    em[751] = 8884097; em[752] = 8; em[753] = 0; /* 751: pointer.func */
    em[754] = 8884097; em[755] = 8; em[756] = 0; /* 754: pointer.func */
    em[757] = 8884097; em[758] = 8; em[759] = 0; /* 757: pointer.func */
    em[760] = 1; em[761] = 8; em[762] = 1; /* 760: pointer.struct.engine_st */
    	em[763] = 187; em[764] = 0; 
    em[765] = 1; em[766] = 8; em[767] = 1; /* 765: pointer.struct.dh_st */
    	em[768] = 770; em[769] = 0; 
    em[770] = 0; em[771] = 144; em[772] = 12; /* 770: struct.dh_st */
    	em[773] = 525; em[774] = 8; 
    	em[775] = 525; em[776] = 16; 
    	em[777] = 525; em[778] = 32; 
    	em[779] = 525; em[780] = 40; 
    	em[781] = 559; em[782] = 56; 
    	em[783] = 525; em[784] = 64; 
    	em[785] = 525; em[786] = 72; 
    	em[787] = 29; em[788] = 80; 
    	em[789] = 525; em[790] = 96; 
    	em[791] = 797; em[792] = 112; 
    	em[793] = 811; em[794] = 128; 
    	em[795] = 182; em[796] = 136; 
    em[797] = 0; em[798] = 32; em[799] = 2; /* 797: struct.crypto_ex_data_st_fake */
    	em[800] = 804; em[801] = 8; 
    	em[802] = 517; em[803] = 24; 
    em[804] = 8884099; em[805] = 8; em[806] = 2; /* 804: pointer_to_array_of_pointers_to_stack */
    	em[807] = 78; em[808] = 0; 
    	em[809] = 5; em[810] = 20; 
    em[811] = 1; em[812] = 8; em[813] = 1; /* 811: pointer.struct.dh_method */
    	em[814] = 816; em[815] = 0; 
    em[816] = 0; em[817] = 72; em[818] = 8; /* 816: struct.dh_method */
    	em[819] = 157; em[820] = 0; 
    	em[821] = 835; em[822] = 8; 
    	em[823] = 838; em[824] = 16; 
    	em[825] = 841; em[826] = 24; 
    	em[827] = 835; em[828] = 32; 
    	em[829] = 835; em[830] = 40; 
    	em[831] = 168; em[832] = 56; 
    	em[833] = 844; em[834] = 64; 
    em[835] = 8884097; em[836] = 8; em[837] = 0; /* 835: pointer.func */
    em[838] = 8884097; em[839] = 8; em[840] = 0; /* 838: pointer.func */
    em[841] = 8884097; em[842] = 8; em[843] = 0; /* 841: pointer.func */
    em[844] = 8884097; em[845] = 8; em[846] = 0; /* 844: pointer.func */
    em[847] = 1; em[848] = 8; em[849] = 1; /* 847: pointer.struct.ec_key_st */
    	em[850] = 852; em[851] = 0; 
    em[852] = 0; em[853] = 56; em[854] = 4; /* 852: struct.ec_key_st */
    	em[855] = 863; em[856] = 8; 
    	em[857] = 1127; em[858] = 16; 
    	em[859] = 1132; em[860] = 24; 
    	em[861] = 1149; em[862] = 48; 
    em[863] = 1; em[864] = 8; em[865] = 1; /* 863: pointer.struct.ec_group_st */
    	em[866] = 868; em[867] = 0; 
    em[868] = 0; em[869] = 232; em[870] = 12; /* 868: struct.ec_group_st */
    	em[871] = 895; em[872] = 0; 
    	em[873] = 1067; em[874] = 8; 
    	em[875] = 1083; em[876] = 16; 
    	em[877] = 1083; em[878] = 40; 
    	em[879] = 29; em[880] = 80; 
    	em[881] = 1095; em[882] = 96; 
    	em[883] = 1083; em[884] = 104; 
    	em[885] = 1083; em[886] = 152; 
    	em[887] = 1083; em[888] = 176; 
    	em[889] = 78; em[890] = 208; 
    	em[891] = 78; em[892] = 216; 
    	em[893] = 1124; em[894] = 224; 
    em[895] = 1; em[896] = 8; em[897] = 1; /* 895: pointer.struct.ec_method_st */
    	em[898] = 900; em[899] = 0; 
    em[900] = 0; em[901] = 304; em[902] = 37; /* 900: struct.ec_method_st */
    	em[903] = 977; em[904] = 8; 
    	em[905] = 980; em[906] = 16; 
    	em[907] = 980; em[908] = 24; 
    	em[909] = 983; em[910] = 32; 
    	em[911] = 986; em[912] = 40; 
    	em[913] = 989; em[914] = 48; 
    	em[915] = 992; em[916] = 56; 
    	em[917] = 995; em[918] = 64; 
    	em[919] = 998; em[920] = 72; 
    	em[921] = 1001; em[922] = 80; 
    	em[923] = 1001; em[924] = 88; 
    	em[925] = 1004; em[926] = 96; 
    	em[927] = 1007; em[928] = 104; 
    	em[929] = 1010; em[930] = 112; 
    	em[931] = 1013; em[932] = 120; 
    	em[933] = 1016; em[934] = 128; 
    	em[935] = 1019; em[936] = 136; 
    	em[937] = 1022; em[938] = 144; 
    	em[939] = 1025; em[940] = 152; 
    	em[941] = 1028; em[942] = 160; 
    	em[943] = 1031; em[944] = 168; 
    	em[945] = 1034; em[946] = 176; 
    	em[947] = 1037; em[948] = 184; 
    	em[949] = 1040; em[950] = 192; 
    	em[951] = 1043; em[952] = 200; 
    	em[953] = 1046; em[954] = 208; 
    	em[955] = 1037; em[956] = 216; 
    	em[957] = 1049; em[958] = 224; 
    	em[959] = 1052; em[960] = 232; 
    	em[961] = 1055; em[962] = 240; 
    	em[963] = 992; em[964] = 248; 
    	em[965] = 1058; em[966] = 256; 
    	em[967] = 1061; em[968] = 264; 
    	em[969] = 1058; em[970] = 272; 
    	em[971] = 1061; em[972] = 280; 
    	em[973] = 1061; em[974] = 288; 
    	em[975] = 1064; em[976] = 296; 
    em[977] = 8884097; em[978] = 8; em[979] = 0; /* 977: pointer.func */
    em[980] = 8884097; em[981] = 8; em[982] = 0; /* 980: pointer.func */
    em[983] = 8884097; em[984] = 8; em[985] = 0; /* 983: pointer.func */
    em[986] = 8884097; em[987] = 8; em[988] = 0; /* 986: pointer.func */
    em[989] = 8884097; em[990] = 8; em[991] = 0; /* 989: pointer.func */
    em[992] = 8884097; em[993] = 8; em[994] = 0; /* 992: pointer.func */
    em[995] = 8884097; em[996] = 8; em[997] = 0; /* 995: pointer.func */
    em[998] = 8884097; em[999] = 8; em[1000] = 0; /* 998: pointer.func */
    em[1001] = 8884097; em[1002] = 8; em[1003] = 0; /* 1001: pointer.func */
    em[1004] = 8884097; em[1005] = 8; em[1006] = 0; /* 1004: pointer.func */
    em[1007] = 8884097; em[1008] = 8; em[1009] = 0; /* 1007: pointer.func */
    em[1010] = 8884097; em[1011] = 8; em[1012] = 0; /* 1010: pointer.func */
    em[1013] = 8884097; em[1014] = 8; em[1015] = 0; /* 1013: pointer.func */
    em[1016] = 8884097; em[1017] = 8; em[1018] = 0; /* 1016: pointer.func */
    em[1019] = 8884097; em[1020] = 8; em[1021] = 0; /* 1019: pointer.func */
    em[1022] = 8884097; em[1023] = 8; em[1024] = 0; /* 1022: pointer.func */
    em[1025] = 8884097; em[1026] = 8; em[1027] = 0; /* 1025: pointer.func */
    em[1028] = 8884097; em[1029] = 8; em[1030] = 0; /* 1028: pointer.func */
    em[1031] = 8884097; em[1032] = 8; em[1033] = 0; /* 1031: pointer.func */
    em[1034] = 8884097; em[1035] = 8; em[1036] = 0; /* 1034: pointer.func */
    em[1037] = 8884097; em[1038] = 8; em[1039] = 0; /* 1037: pointer.func */
    em[1040] = 8884097; em[1041] = 8; em[1042] = 0; /* 1040: pointer.func */
    em[1043] = 8884097; em[1044] = 8; em[1045] = 0; /* 1043: pointer.func */
    em[1046] = 8884097; em[1047] = 8; em[1048] = 0; /* 1046: pointer.func */
    em[1049] = 8884097; em[1050] = 8; em[1051] = 0; /* 1049: pointer.func */
    em[1052] = 8884097; em[1053] = 8; em[1054] = 0; /* 1052: pointer.func */
    em[1055] = 8884097; em[1056] = 8; em[1057] = 0; /* 1055: pointer.func */
    em[1058] = 8884097; em[1059] = 8; em[1060] = 0; /* 1058: pointer.func */
    em[1061] = 8884097; em[1062] = 8; em[1063] = 0; /* 1061: pointer.func */
    em[1064] = 8884097; em[1065] = 8; em[1066] = 0; /* 1064: pointer.func */
    em[1067] = 1; em[1068] = 8; em[1069] = 1; /* 1067: pointer.struct.ec_point_st */
    	em[1070] = 1072; em[1071] = 0; 
    em[1072] = 0; em[1073] = 88; em[1074] = 4; /* 1072: struct.ec_point_st */
    	em[1075] = 895; em[1076] = 0; 
    	em[1077] = 1083; em[1078] = 8; 
    	em[1079] = 1083; em[1080] = 32; 
    	em[1081] = 1083; em[1082] = 56; 
    em[1083] = 0; em[1084] = 24; em[1085] = 1; /* 1083: struct.bignum_st */
    	em[1086] = 1088; em[1087] = 0; 
    em[1088] = 8884099; em[1089] = 8; em[1090] = 2; /* 1088: pointer_to_array_of_pointers_to_stack */
    	em[1091] = 542; em[1092] = 0; 
    	em[1093] = 5; em[1094] = 12; 
    em[1095] = 1; em[1096] = 8; em[1097] = 1; /* 1095: pointer.struct.ec_extra_data_st */
    	em[1098] = 1100; em[1099] = 0; 
    em[1100] = 0; em[1101] = 40; em[1102] = 5; /* 1100: struct.ec_extra_data_st */
    	em[1103] = 1113; em[1104] = 0; 
    	em[1105] = 78; em[1106] = 8; 
    	em[1107] = 1118; em[1108] = 16; 
    	em[1109] = 1121; em[1110] = 24; 
    	em[1111] = 1121; em[1112] = 32; 
    em[1113] = 1; em[1114] = 8; em[1115] = 1; /* 1113: pointer.struct.ec_extra_data_st */
    	em[1116] = 1100; em[1117] = 0; 
    em[1118] = 8884097; em[1119] = 8; em[1120] = 0; /* 1118: pointer.func */
    em[1121] = 8884097; em[1122] = 8; em[1123] = 0; /* 1121: pointer.func */
    em[1124] = 8884097; em[1125] = 8; em[1126] = 0; /* 1124: pointer.func */
    em[1127] = 1; em[1128] = 8; em[1129] = 1; /* 1127: pointer.struct.ec_point_st */
    	em[1130] = 1072; em[1131] = 0; 
    em[1132] = 1; em[1133] = 8; em[1134] = 1; /* 1132: pointer.struct.bignum_st */
    	em[1135] = 1137; em[1136] = 0; 
    em[1137] = 0; em[1138] = 24; em[1139] = 1; /* 1137: struct.bignum_st */
    	em[1140] = 1142; em[1141] = 0; 
    em[1142] = 8884099; em[1143] = 8; em[1144] = 2; /* 1142: pointer_to_array_of_pointers_to_stack */
    	em[1145] = 542; em[1146] = 0; 
    	em[1147] = 5; em[1148] = 12; 
    em[1149] = 1; em[1150] = 8; em[1151] = 1; /* 1149: pointer.struct.ec_extra_data_st */
    	em[1152] = 1154; em[1153] = 0; 
    em[1154] = 0; em[1155] = 40; em[1156] = 5; /* 1154: struct.ec_extra_data_st */
    	em[1157] = 1167; em[1158] = 0; 
    	em[1159] = 78; em[1160] = 8; 
    	em[1161] = 1118; em[1162] = 16; 
    	em[1163] = 1121; em[1164] = 24; 
    	em[1165] = 1121; em[1166] = 32; 
    em[1167] = 1; em[1168] = 8; em[1169] = 1; /* 1167: pointer.struct.ec_extra_data_st */
    	em[1170] = 1154; em[1171] = 0; 
    em[1172] = 8884097; em[1173] = 8; em[1174] = 0; /* 1172: pointer.func */
    em[1175] = 8884097; em[1176] = 8; em[1177] = 0; /* 1175: pointer.func */
    em[1178] = 8884097; em[1179] = 8; em[1180] = 0; /* 1178: pointer.func */
    em[1181] = 0; em[1182] = 208; em[1183] = 24; /* 1181: struct.evp_pkey_asn1_method_st */
    	em[1184] = 168; em[1185] = 16; 
    	em[1186] = 168; em[1187] = 24; 
    	em[1188] = 1232; em[1189] = 32; 
    	em[1190] = 1235; em[1191] = 40; 
    	em[1192] = 1238; em[1193] = 48; 
    	em[1194] = 1241; em[1195] = 56; 
    	em[1196] = 1244; em[1197] = 64; 
    	em[1198] = 1247; em[1199] = 72; 
    	em[1200] = 1241; em[1201] = 80; 
    	em[1202] = 1178; em[1203] = 88; 
    	em[1204] = 1178; em[1205] = 96; 
    	em[1206] = 1250; em[1207] = 104; 
    	em[1208] = 1253; em[1209] = 112; 
    	em[1210] = 1178; em[1211] = 120; 
    	em[1212] = 1256; em[1213] = 128; 
    	em[1214] = 1238; em[1215] = 136; 
    	em[1216] = 1241; em[1217] = 144; 
    	em[1218] = 1259; em[1219] = 152; 
    	em[1220] = 1262; em[1221] = 160; 
    	em[1222] = 1175; em[1223] = 168; 
    	em[1224] = 1250; em[1225] = 176; 
    	em[1226] = 1253; em[1227] = 184; 
    	em[1228] = 1265; em[1229] = 192; 
    	em[1230] = 1172; em[1231] = 200; 
    em[1232] = 8884097; em[1233] = 8; em[1234] = 0; /* 1232: pointer.func */
    em[1235] = 8884097; em[1236] = 8; em[1237] = 0; /* 1235: pointer.func */
    em[1238] = 8884097; em[1239] = 8; em[1240] = 0; /* 1238: pointer.func */
    em[1241] = 8884097; em[1242] = 8; em[1243] = 0; /* 1241: pointer.func */
    em[1244] = 8884097; em[1245] = 8; em[1246] = 0; /* 1244: pointer.func */
    em[1247] = 8884097; em[1248] = 8; em[1249] = 0; /* 1247: pointer.func */
    em[1250] = 8884097; em[1251] = 8; em[1252] = 0; /* 1250: pointer.func */
    em[1253] = 8884097; em[1254] = 8; em[1255] = 0; /* 1253: pointer.func */
    em[1256] = 8884097; em[1257] = 8; em[1258] = 0; /* 1256: pointer.func */
    em[1259] = 8884097; em[1260] = 8; em[1261] = 0; /* 1259: pointer.func */
    em[1262] = 8884097; em[1263] = 8; em[1264] = 0; /* 1262: pointer.func */
    em[1265] = 8884097; em[1266] = 8; em[1267] = 0; /* 1265: pointer.func */
    em[1268] = 8884097; em[1269] = 8; em[1270] = 0; /* 1268: pointer.func */
    em[1271] = 0; em[1272] = 40; em[1273] = 3; /* 1271: struct.asn1_object_st */
    	em[1274] = 157; em[1275] = 0; 
    	em[1276] = 157; em[1277] = 8; 
    	em[1278] = 1280; em[1279] = 24; 
    em[1280] = 1; em[1281] = 8; em[1282] = 1; /* 1280: pointer.unsigned char */
    	em[1283] = 34; em[1284] = 0; 
    em[1285] = 1; em[1286] = 8; em[1287] = 1; /* 1285: pointer.struct.asn1_string_st */
    	em[1288] = 55; em[1289] = 0; 
    em[1290] = 8884097; em[1291] = 8; em[1292] = 0; /* 1290: pointer.func */
    em[1293] = 1; em[1294] = 8; em[1295] = 1; /* 1293: pointer.struct.asn1_string_st */
    	em[1296] = 55; em[1297] = 0; 
    em[1298] = 1; em[1299] = 8; em[1300] = 1; /* 1298: pointer.struct.asn1_string_st */
    	em[1301] = 24; em[1302] = 0; 
    em[1303] = 8884097; em[1304] = 8; em[1305] = 0; /* 1303: pointer.func */
    em[1306] = 0; em[1307] = 120; em[1308] = 8; /* 1306: struct.env_md_st */
    	em[1309] = 1325; em[1310] = 24; 
    	em[1311] = 1328; em[1312] = 32; 
    	em[1313] = 1331; em[1314] = 40; 
    	em[1315] = 1334; em[1316] = 48; 
    	em[1317] = 1325; em[1318] = 56; 
    	em[1319] = 1337; em[1320] = 64; 
    	em[1321] = 1268; em[1322] = 72; 
    	em[1323] = 1340; em[1324] = 112; 
    em[1325] = 8884097; em[1326] = 8; em[1327] = 0; /* 1325: pointer.func */
    em[1328] = 8884097; em[1329] = 8; em[1330] = 0; /* 1328: pointer.func */
    em[1331] = 8884097; em[1332] = 8; em[1333] = 0; /* 1331: pointer.func */
    em[1334] = 8884097; em[1335] = 8; em[1336] = 0; /* 1334: pointer.func */
    em[1337] = 8884097; em[1338] = 8; em[1339] = 0; /* 1337: pointer.func */
    em[1340] = 8884097; em[1341] = 8; em[1342] = 0; /* 1340: pointer.func */
    em[1343] = 1; em[1344] = 8; em[1345] = 1; /* 1343: pointer.struct.asn1_string_st */
    	em[1346] = 24; em[1347] = 0; 
    em[1348] = 8884097; em[1349] = 8; em[1350] = 0; /* 1348: pointer.func */
    em[1351] = 8884097; em[1352] = 8; em[1353] = 0; /* 1351: pointer.func */
    em[1354] = 1; em[1355] = 8; em[1356] = 1; /* 1354: pointer.struct.evp_pkey_ctx_st */
    	em[1357] = 1359; em[1358] = 0; 
    em[1359] = 0; em[1360] = 80; em[1361] = 8; /* 1359: struct.evp_pkey_ctx_st */
    	em[1362] = 1378; em[1363] = 0; 
    	em[1364] = 1460; em[1365] = 8; 
    	em[1366] = 1465; em[1367] = 16; 
    	em[1368] = 1465; em[1369] = 24; 
    	em[1370] = 78; em[1371] = 40; 
    	em[1372] = 78; em[1373] = 48; 
    	em[1374] = 8; em[1375] = 56; 
    	em[1376] = 0; em[1377] = 64; 
    em[1378] = 1; em[1379] = 8; em[1380] = 1; /* 1378: pointer.struct.evp_pkey_method_st */
    	em[1381] = 1383; em[1382] = 0; 
    em[1383] = 0; em[1384] = 208; em[1385] = 25; /* 1383: struct.evp_pkey_method_st */
    	em[1386] = 1436; em[1387] = 8; 
    	em[1388] = 1439; em[1389] = 16; 
    	em[1390] = 1351; em[1391] = 24; 
    	em[1392] = 1436; em[1393] = 32; 
    	em[1394] = 1442; em[1395] = 40; 
    	em[1396] = 1436; em[1397] = 48; 
    	em[1398] = 1442; em[1399] = 56; 
    	em[1400] = 1436; em[1401] = 64; 
    	em[1402] = 1348; em[1403] = 72; 
    	em[1404] = 1436; em[1405] = 80; 
    	em[1406] = 1445; em[1407] = 88; 
    	em[1408] = 1436; em[1409] = 96; 
    	em[1410] = 1348; em[1411] = 104; 
    	em[1412] = 1448; em[1413] = 112; 
    	em[1414] = 1451; em[1415] = 120; 
    	em[1416] = 1448; em[1417] = 128; 
    	em[1418] = 1303; em[1419] = 136; 
    	em[1420] = 1436; em[1421] = 144; 
    	em[1422] = 1348; em[1423] = 152; 
    	em[1424] = 1436; em[1425] = 160; 
    	em[1426] = 1348; em[1427] = 168; 
    	em[1428] = 1436; em[1429] = 176; 
    	em[1430] = 1454; em[1431] = 184; 
    	em[1432] = 1457; em[1433] = 192; 
    	em[1434] = 1290; em[1435] = 200; 
    em[1436] = 8884097; em[1437] = 8; em[1438] = 0; /* 1436: pointer.func */
    em[1439] = 8884097; em[1440] = 8; em[1441] = 0; /* 1439: pointer.func */
    em[1442] = 8884097; em[1443] = 8; em[1444] = 0; /* 1442: pointer.func */
    em[1445] = 8884097; em[1446] = 8; em[1447] = 0; /* 1445: pointer.func */
    em[1448] = 8884097; em[1449] = 8; em[1450] = 0; /* 1448: pointer.func */
    em[1451] = 8884097; em[1452] = 8; em[1453] = 0; /* 1451: pointer.func */
    em[1454] = 8884097; em[1455] = 8; em[1456] = 0; /* 1454: pointer.func */
    em[1457] = 8884097; em[1458] = 8; em[1459] = 0; /* 1457: pointer.func */
    em[1460] = 1; em[1461] = 8; em[1462] = 1; /* 1460: pointer.struct.engine_st */
    	em[1463] = 187; em[1464] = 0; 
    em[1465] = 1; em[1466] = 8; em[1467] = 1; /* 1465: pointer.struct.evp_pkey_st */
    	em[1468] = 1470; em[1469] = 0; 
    em[1470] = 0; em[1471] = 56; em[1472] = 4; /* 1470: struct.evp_pkey_st */
    	em[1473] = 1481; em[1474] = 16; 
    	em[1475] = 1460; em[1476] = 24; 
    	em[1477] = 63; em[1478] = 32; 
    	em[1479] = 1486; em[1480] = 48; 
    em[1481] = 1; em[1482] = 8; em[1483] = 1; /* 1481: pointer.struct.evp_pkey_asn1_method_st */
    	em[1484] = 1181; em[1485] = 0; 
    em[1486] = 1; em[1487] = 8; em[1488] = 1; /* 1486: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[1489] = 1491; em[1490] = 0; 
    em[1491] = 0; em[1492] = 32; em[1493] = 2; /* 1491: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[1494] = 1498; em[1495] = 8; 
    	em[1496] = 517; em[1497] = 24; 
    em[1498] = 8884099; em[1499] = 8; em[1500] = 2; /* 1498: pointer_to_array_of_pointers_to_stack */
    	em[1501] = 1505; em[1502] = 0; 
    	em[1503] = 5; em[1504] = 20; 
    em[1505] = 0; em[1506] = 8; em[1507] = 1; /* 1505: pointer.X509_ATTRIBUTE */
    	em[1508] = 1510; em[1509] = 0; 
    em[1510] = 0; em[1511] = 0; em[1512] = 1; /* 1510: X509_ATTRIBUTE */
    	em[1513] = 1515; em[1514] = 0; 
    em[1515] = 0; em[1516] = 24; em[1517] = 2; /* 1515: struct.x509_attributes_st */
    	em[1518] = 1522; em[1519] = 0; 
    	em[1520] = 1536; em[1521] = 16; 
    em[1522] = 1; em[1523] = 8; em[1524] = 1; /* 1522: pointer.struct.asn1_object_st */
    	em[1525] = 1527; em[1526] = 0; 
    em[1527] = 0; em[1528] = 40; em[1529] = 3; /* 1527: struct.asn1_object_st */
    	em[1530] = 157; em[1531] = 0; 
    	em[1532] = 157; em[1533] = 8; 
    	em[1534] = 1280; em[1535] = 24; 
    em[1536] = 0; em[1537] = 8; em[1538] = 3; /* 1536: union.unknown */
    	em[1539] = 168; em[1540] = 0; 
    	em[1541] = 1545; em[1542] = 0; 
    	em[1543] = 1700; em[1544] = 0; 
    em[1545] = 1; em[1546] = 8; em[1547] = 1; /* 1545: pointer.struct.stack_st_ASN1_TYPE */
    	em[1548] = 1550; em[1549] = 0; 
    em[1550] = 0; em[1551] = 32; em[1552] = 2; /* 1550: struct.stack_st_fake_ASN1_TYPE */
    	em[1553] = 1557; em[1554] = 8; 
    	em[1555] = 517; em[1556] = 24; 
    em[1557] = 8884099; em[1558] = 8; em[1559] = 2; /* 1557: pointer_to_array_of_pointers_to_stack */
    	em[1560] = 1564; em[1561] = 0; 
    	em[1562] = 5; em[1563] = 20; 
    em[1564] = 0; em[1565] = 8; em[1566] = 1; /* 1564: pointer.ASN1_TYPE */
    	em[1567] = 1569; em[1568] = 0; 
    em[1569] = 0; em[1570] = 0; em[1571] = 1; /* 1569: ASN1_TYPE */
    	em[1572] = 1574; em[1573] = 0; 
    em[1574] = 0; em[1575] = 16; em[1576] = 1; /* 1574: struct.asn1_type_st */
    	em[1577] = 1579; em[1578] = 8; 
    em[1579] = 0; em[1580] = 8; em[1581] = 20; /* 1579: union.unknown */
    	em[1582] = 168; em[1583] = 0; 
    	em[1584] = 1622; em[1585] = 0; 
    	em[1586] = 1627; em[1587] = 0; 
    	em[1588] = 1632; em[1589] = 0; 
    	em[1590] = 1637; em[1591] = 0; 
    	em[1592] = 1642; em[1593] = 0; 
    	em[1594] = 1647; em[1595] = 0; 
    	em[1596] = 1652; em[1597] = 0; 
    	em[1598] = 1657; em[1599] = 0; 
    	em[1600] = 1662; em[1601] = 0; 
    	em[1602] = 1293; em[1603] = 0; 
    	em[1604] = 1667; em[1605] = 0; 
    	em[1606] = 1672; em[1607] = 0; 
    	em[1608] = 1677; em[1609] = 0; 
    	em[1610] = 1682; em[1611] = 0; 
    	em[1612] = 1285; em[1613] = 0; 
    	em[1614] = 1687; em[1615] = 0; 
    	em[1616] = 1622; em[1617] = 0; 
    	em[1618] = 1622; em[1619] = 0; 
    	em[1620] = 1692; em[1621] = 0; 
    em[1622] = 1; em[1623] = 8; em[1624] = 1; /* 1622: pointer.struct.asn1_string_st */
    	em[1625] = 55; em[1626] = 0; 
    em[1627] = 1; em[1628] = 8; em[1629] = 1; /* 1627: pointer.struct.asn1_object_st */
    	em[1630] = 1271; em[1631] = 0; 
    em[1632] = 1; em[1633] = 8; em[1634] = 1; /* 1632: pointer.struct.asn1_string_st */
    	em[1635] = 55; em[1636] = 0; 
    em[1637] = 1; em[1638] = 8; em[1639] = 1; /* 1637: pointer.struct.asn1_string_st */
    	em[1640] = 55; em[1641] = 0; 
    em[1642] = 1; em[1643] = 8; em[1644] = 1; /* 1642: pointer.struct.asn1_string_st */
    	em[1645] = 55; em[1646] = 0; 
    em[1647] = 1; em[1648] = 8; em[1649] = 1; /* 1647: pointer.struct.asn1_string_st */
    	em[1650] = 55; em[1651] = 0; 
    em[1652] = 1; em[1653] = 8; em[1654] = 1; /* 1652: pointer.struct.asn1_string_st */
    	em[1655] = 55; em[1656] = 0; 
    em[1657] = 1; em[1658] = 8; em[1659] = 1; /* 1657: pointer.struct.asn1_string_st */
    	em[1660] = 55; em[1661] = 0; 
    em[1662] = 1; em[1663] = 8; em[1664] = 1; /* 1662: pointer.struct.asn1_string_st */
    	em[1665] = 55; em[1666] = 0; 
    em[1667] = 1; em[1668] = 8; em[1669] = 1; /* 1667: pointer.struct.asn1_string_st */
    	em[1670] = 55; em[1671] = 0; 
    em[1672] = 1; em[1673] = 8; em[1674] = 1; /* 1672: pointer.struct.asn1_string_st */
    	em[1675] = 55; em[1676] = 0; 
    em[1677] = 1; em[1678] = 8; em[1679] = 1; /* 1677: pointer.struct.asn1_string_st */
    	em[1680] = 55; em[1681] = 0; 
    em[1682] = 1; em[1683] = 8; em[1684] = 1; /* 1682: pointer.struct.asn1_string_st */
    	em[1685] = 55; em[1686] = 0; 
    em[1687] = 1; em[1688] = 8; em[1689] = 1; /* 1687: pointer.struct.asn1_string_st */
    	em[1690] = 55; em[1691] = 0; 
    em[1692] = 1; em[1693] = 8; em[1694] = 1; /* 1692: pointer.struct.ASN1_VALUE_st */
    	em[1695] = 1697; em[1696] = 0; 
    em[1697] = 0; em[1698] = 0; em[1699] = 0; /* 1697: struct.ASN1_VALUE_st */
    em[1700] = 1; em[1701] = 8; em[1702] = 1; /* 1700: pointer.struct.asn1_type_st */
    	em[1703] = 1705; em[1704] = 0; 
    em[1705] = 0; em[1706] = 16; em[1707] = 1; /* 1705: struct.asn1_type_st */
    	em[1708] = 1710; em[1709] = 8; 
    em[1710] = 0; em[1711] = 8; em[1712] = 20; /* 1710: union.unknown */
    	em[1713] = 168; em[1714] = 0; 
    	em[1715] = 1753; em[1716] = 0; 
    	em[1717] = 1522; em[1718] = 0; 
    	em[1719] = 1343; em[1720] = 0; 
    	em[1721] = 1758; em[1722] = 0; 
    	em[1723] = 1763; em[1724] = 0; 
    	em[1725] = 1768; em[1726] = 0; 
    	em[1727] = 1773; em[1728] = 0; 
    	em[1729] = 1298; em[1730] = 0; 
    	em[1731] = 1778; em[1732] = 0; 
    	em[1733] = 1783; em[1734] = 0; 
    	em[1735] = 47; em[1736] = 0; 
    	em[1737] = 42; em[1738] = 0; 
    	em[1739] = 1788; em[1740] = 0; 
    	em[1741] = 1793; em[1742] = 0; 
    	em[1743] = 37; em[1744] = 0; 
    	em[1745] = 19; em[1746] = 0; 
    	em[1747] = 1753; em[1748] = 0; 
    	em[1749] = 1753; em[1750] = 0; 
    	em[1751] = 14; em[1752] = 0; 
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
    	em[1806] = 1460; em[1807] = 8; 
    	em[1808] = 78; em[1809] = 24; 
    	em[1810] = 1354; em[1811] = 32; 
    	em[1812] = 1328; em[1813] = 40; 
    em[1814] = 1; em[1815] = 8; em[1816] = 1; /* 1814: pointer.struct.env_md_st */
    	em[1817] = 1306; em[1818] = 0; 
    em[1819] = 0; em[1820] = 0; em[1821] = 0; /* 1819: size_t */
    em[1822] = 1; em[1823] = 8; em[1824] = 1; /* 1822: pointer.struct.env_md_ctx_st */
    	em[1825] = 1801; em[1826] = 0; 
    args_addr->arg_entity_index[0] = 1822;
    args_addr->arg_entity_index[1] = 78;
    args_addr->arg_entity_index[2] = 1819;
    args_addr->ret_entity_index = 5;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    EVP_MD_CTX * new_arg_a = *((EVP_MD_CTX * *)new_args->args[0]);

     const void * new_arg_b = *(( const void * *)new_args->args[1]);

    size_t new_arg_c = *((size_t *)new_args->args[2]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_EVP_DigestUpdate)(EVP_MD_CTX *, const void *,size_t);
    orig_EVP_DigestUpdate = dlsym(RTLD_NEXT, "EVP_DigestUpdate");
    *new_ret_ptr = (*orig_EVP_DigestUpdate)(new_arg_a,new_arg_b,new_arg_c);

    syscall(889);

    free(args_addr);

    return ret;
}

