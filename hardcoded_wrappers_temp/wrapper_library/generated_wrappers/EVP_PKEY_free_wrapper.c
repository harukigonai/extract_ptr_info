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

void bb_EVP_PKEY_free(EVP_PKEY * arg_a);

void EVP_PKEY_free(EVP_PKEY * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("EVP_PKEY_free called %lu\n", in_lib);
    if (!in_lib)
        bb_EVP_PKEY_free(arg_a);
    else {
        void (*orig_EVP_PKEY_free)(EVP_PKEY *);
        orig_EVP_PKEY_free = dlsym(RTLD_NEXT, "EVP_PKEY_free");
        orig_EVP_PKEY_free(arg_a);
    }
}

void bb_EVP_PKEY_free(EVP_PKEY * arg_a) 
{
    struct lib_enter_args *args_addr = malloc(sizeof(struct lib_enter_args));
    memset(args_addr, 0, sizeof(struct lib_enter_args));
    args_addr->num_args = 0;
    uint32_t *em = args_addr->entity_metadata;
    em[0] = 1; em[1] = 8; em[2] = 1; /* 0: pointer.struct.ASN1_VALUE_st */
    	em[3] = 5; em[4] = 0; 
    em[5] = 0; em[6] = 0; em[7] = 0; /* 5: struct.ASN1_VALUE_st */
    em[8] = 1; em[9] = 8; em[10] = 1; /* 8: pointer.struct.asn1_string_st */
    	em[11] = 13; em[12] = 0; 
    em[13] = 0; em[14] = 24; em[15] = 1; /* 13: struct.asn1_string_st */
    	em[16] = 18; em[17] = 8; 
    em[18] = 1; em[19] = 8; em[20] = 1; /* 18: pointer.unsigned char */
    	em[21] = 23; em[22] = 0; 
    em[23] = 0; em[24] = 1; em[25] = 0; /* 23: unsigned char */
    em[26] = 1; em[27] = 8; em[28] = 1; /* 26: pointer.struct.asn1_string_st */
    	em[29] = 13; em[30] = 0; 
    em[31] = 1; em[32] = 8; em[33] = 1; /* 31: pointer.struct.asn1_string_st */
    	em[34] = 13; em[35] = 0; 
    em[36] = 1; em[37] = 8; em[38] = 1; /* 36: pointer.struct.asn1_string_st */
    	em[39] = 13; em[40] = 0; 
    em[41] = 1; em[42] = 8; em[43] = 1; /* 41: pointer.struct.asn1_string_st */
    	em[44] = 13; em[45] = 0; 
    em[46] = 1; em[47] = 8; em[48] = 1; /* 46: pointer.struct.asn1_string_st */
    	em[49] = 13; em[50] = 0; 
    em[51] = 1; em[52] = 8; em[53] = 1; /* 51: pointer.struct.asn1_string_st */
    	em[54] = 13; em[55] = 0; 
    em[56] = 1; em[57] = 8; em[58] = 1; /* 56: pointer.struct.asn1_string_st */
    	em[59] = 13; em[60] = 0; 
    em[61] = 1; em[62] = 8; em[63] = 1; /* 61: pointer.struct.asn1_string_st */
    	em[64] = 13; em[65] = 0; 
    em[66] = 1; em[67] = 8; em[68] = 1; /* 66: pointer.struct.asn1_string_st */
    	em[69] = 13; em[70] = 0; 
    em[71] = 1; em[72] = 8; em[73] = 1; /* 71: pointer.struct.asn1_string_st */
    	em[74] = 13; em[75] = 0; 
    em[76] = 0; em[77] = 24; em[78] = 1; /* 76: struct.bignum_st */
    	em[79] = 81; em[80] = 0; 
    em[81] = 8884099; em[82] = 8; em[83] = 2; /* 81: pointer_to_array_of_pointers_to_stack */
    	em[84] = 88; em[85] = 0; 
    	em[86] = 91; em[87] = 12; 
    em[88] = 0; em[89] = 8; em[90] = 0; /* 88: long unsigned int */
    em[91] = 0; em[92] = 4; em[93] = 0; /* 91: int */
    em[94] = 0; em[95] = 144; em[96] = 12; /* 94: struct.dh_st */
    	em[97] = 121; em[98] = 8; 
    	em[99] = 121; em[100] = 16; 
    	em[101] = 121; em[102] = 32; 
    	em[103] = 121; em[104] = 40; 
    	em[105] = 126; em[106] = 56; 
    	em[107] = 121; em[108] = 64; 
    	em[109] = 121; em[110] = 72; 
    	em[111] = 18; em[112] = 80; 
    	em[113] = 121; em[114] = 96; 
    	em[115] = 140; em[116] = 112; 
    	em[117] = 160; em[118] = 128; 
    	em[119] = 206; em[120] = 136; 
    em[121] = 1; em[122] = 8; em[123] = 1; /* 121: pointer.struct.bignum_st */
    	em[124] = 76; em[125] = 0; 
    em[126] = 1; em[127] = 8; em[128] = 1; /* 126: pointer.struct.bn_mont_ctx_st */
    	em[129] = 131; em[130] = 0; 
    em[131] = 0; em[132] = 96; em[133] = 3; /* 131: struct.bn_mont_ctx_st */
    	em[134] = 76; em[135] = 8; 
    	em[136] = 76; em[137] = 32; 
    	em[138] = 76; em[139] = 56; 
    em[140] = 0; em[141] = 32; em[142] = 2; /* 140: struct.crypto_ex_data_st_fake */
    	em[143] = 147; em[144] = 8; 
    	em[145] = 157; em[146] = 24; 
    em[147] = 8884099; em[148] = 8; em[149] = 2; /* 147: pointer_to_array_of_pointers_to_stack */
    	em[150] = 154; em[151] = 0; 
    	em[152] = 91; em[153] = 20; 
    em[154] = 0; em[155] = 8; em[156] = 0; /* 154: pointer.void */
    em[157] = 8884097; em[158] = 8; em[159] = 0; /* 157: pointer.func */
    em[160] = 1; em[161] = 8; em[162] = 1; /* 160: pointer.struct.dh_method */
    	em[163] = 165; em[164] = 0; 
    em[165] = 0; em[166] = 72; em[167] = 8; /* 165: struct.dh_method */
    	em[168] = 184; em[169] = 0; 
    	em[170] = 189; em[171] = 8; 
    	em[172] = 192; em[173] = 16; 
    	em[174] = 195; em[175] = 24; 
    	em[176] = 189; em[177] = 32; 
    	em[178] = 189; em[179] = 40; 
    	em[180] = 198; em[181] = 56; 
    	em[182] = 203; em[183] = 64; 
    em[184] = 1; em[185] = 8; em[186] = 1; /* 184: pointer.char */
    	em[187] = 8884096; em[188] = 0; 
    em[189] = 8884097; em[190] = 8; em[191] = 0; /* 189: pointer.func */
    em[192] = 8884097; em[193] = 8; em[194] = 0; /* 192: pointer.func */
    em[195] = 8884097; em[196] = 8; em[197] = 0; /* 195: pointer.func */
    em[198] = 1; em[199] = 8; em[200] = 1; /* 198: pointer.char */
    	em[201] = 8884096; em[202] = 0; 
    em[203] = 8884097; em[204] = 8; em[205] = 0; /* 203: pointer.func */
    em[206] = 1; em[207] = 8; em[208] = 1; /* 206: pointer.struct.engine_st */
    	em[209] = 211; em[210] = 0; 
    em[211] = 0; em[212] = 216; em[213] = 24; /* 211: struct.engine_st */
    	em[214] = 184; em[215] = 0; 
    	em[216] = 184; em[217] = 8; 
    	em[218] = 262; em[219] = 16; 
    	em[220] = 317; em[221] = 24; 
    	em[222] = 368; em[223] = 32; 
    	em[224] = 404; em[225] = 40; 
    	em[226] = 421; em[227] = 48; 
    	em[228] = 448; em[229] = 56; 
    	em[230] = 483; em[231] = 64; 
    	em[232] = 491; em[233] = 72; 
    	em[234] = 494; em[235] = 80; 
    	em[236] = 497; em[237] = 88; 
    	em[238] = 500; em[239] = 96; 
    	em[240] = 503; em[241] = 104; 
    	em[242] = 503; em[243] = 112; 
    	em[244] = 503; em[245] = 120; 
    	em[246] = 506; em[247] = 128; 
    	em[248] = 509; em[249] = 136; 
    	em[250] = 509; em[251] = 144; 
    	em[252] = 512; em[253] = 152; 
    	em[254] = 515; em[255] = 160; 
    	em[256] = 527; em[257] = 184; 
    	em[258] = 541; em[259] = 200; 
    	em[260] = 541; em[261] = 208; 
    em[262] = 1; em[263] = 8; em[264] = 1; /* 262: pointer.struct.rsa_meth_st */
    	em[265] = 267; em[266] = 0; 
    em[267] = 0; em[268] = 112; em[269] = 13; /* 267: struct.rsa_meth_st */
    	em[270] = 184; em[271] = 0; 
    	em[272] = 296; em[273] = 8; 
    	em[274] = 296; em[275] = 16; 
    	em[276] = 296; em[277] = 24; 
    	em[278] = 296; em[279] = 32; 
    	em[280] = 299; em[281] = 40; 
    	em[282] = 302; em[283] = 48; 
    	em[284] = 305; em[285] = 56; 
    	em[286] = 305; em[287] = 64; 
    	em[288] = 198; em[289] = 80; 
    	em[290] = 308; em[291] = 88; 
    	em[292] = 311; em[293] = 96; 
    	em[294] = 314; em[295] = 104; 
    em[296] = 8884097; em[297] = 8; em[298] = 0; /* 296: pointer.func */
    em[299] = 8884097; em[300] = 8; em[301] = 0; /* 299: pointer.func */
    em[302] = 8884097; em[303] = 8; em[304] = 0; /* 302: pointer.func */
    em[305] = 8884097; em[306] = 8; em[307] = 0; /* 305: pointer.func */
    em[308] = 8884097; em[309] = 8; em[310] = 0; /* 308: pointer.func */
    em[311] = 8884097; em[312] = 8; em[313] = 0; /* 311: pointer.func */
    em[314] = 8884097; em[315] = 8; em[316] = 0; /* 314: pointer.func */
    em[317] = 1; em[318] = 8; em[319] = 1; /* 317: pointer.struct.dsa_method */
    	em[320] = 322; em[321] = 0; 
    em[322] = 0; em[323] = 96; em[324] = 11; /* 322: struct.dsa_method */
    	em[325] = 184; em[326] = 0; 
    	em[327] = 347; em[328] = 8; 
    	em[329] = 350; em[330] = 16; 
    	em[331] = 353; em[332] = 24; 
    	em[333] = 356; em[334] = 32; 
    	em[335] = 359; em[336] = 40; 
    	em[337] = 362; em[338] = 48; 
    	em[339] = 362; em[340] = 56; 
    	em[341] = 198; em[342] = 72; 
    	em[343] = 365; em[344] = 80; 
    	em[345] = 362; em[346] = 88; 
    em[347] = 8884097; em[348] = 8; em[349] = 0; /* 347: pointer.func */
    em[350] = 8884097; em[351] = 8; em[352] = 0; /* 350: pointer.func */
    em[353] = 8884097; em[354] = 8; em[355] = 0; /* 353: pointer.func */
    em[356] = 8884097; em[357] = 8; em[358] = 0; /* 356: pointer.func */
    em[359] = 8884097; em[360] = 8; em[361] = 0; /* 359: pointer.func */
    em[362] = 8884097; em[363] = 8; em[364] = 0; /* 362: pointer.func */
    em[365] = 8884097; em[366] = 8; em[367] = 0; /* 365: pointer.func */
    em[368] = 1; em[369] = 8; em[370] = 1; /* 368: pointer.struct.dh_method */
    	em[371] = 373; em[372] = 0; 
    em[373] = 0; em[374] = 72; em[375] = 8; /* 373: struct.dh_method */
    	em[376] = 184; em[377] = 0; 
    	em[378] = 392; em[379] = 8; 
    	em[380] = 395; em[381] = 16; 
    	em[382] = 398; em[383] = 24; 
    	em[384] = 392; em[385] = 32; 
    	em[386] = 392; em[387] = 40; 
    	em[388] = 198; em[389] = 56; 
    	em[390] = 401; em[391] = 64; 
    em[392] = 8884097; em[393] = 8; em[394] = 0; /* 392: pointer.func */
    em[395] = 8884097; em[396] = 8; em[397] = 0; /* 395: pointer.func */
    em[398] = 8884097; em[399] = 8; em[400] = 0; /* 398: pointer.func */
    em[401] = 8884097; em[402] = 8; em[403] = 0; /* 401: pointer.func */
    em[404] = 1; em[405] = 8; em[406] = 1; /* 404: pointer.struct.ecdh_method */
    	em[407] = 409; em[408] = 0; 
    em[409] = 0; em[410] = 32; em[411] = 3; /* 409: struct.ecdh_method */
    	em[412] = 184; em[413] = 0; 
    	em[414] = 418; em[415] = 8; 
    	em[416] = 198; em[417] = 24; 
    em[418] = 8884097; em[419] = 8; em[420] = 0; /* 418: pointer.func */
    em[421] = 1; em[422] = 8; em[423] = 1; /* 421: pointer.struct.ecdsa_method */
    	em[424] = 426; em[425] = 0; 
    em[426] = 0; em[427] = 48; em[428] = 5; /* 426: struct.ecdsa_method */
    	em[429] = 184; em[430] = 0; 
    	em[431] = 439; em[432] = 8; 
    	em[433] = 442; em[434] = 16; 
    	em[435] = 445; em[436] = 24; 
    	em[437] = 198; em[438] = 40; 
    em[439] = 8884097; em[440] = 8; em[441] = 0; /* 439: pointer.func */
    em[442] = 8884097; em[443] = 8; em[444] = 0; /* 442: pointer.func */
    em[445] = 8884097; em[446] = 8; em[447] = 0; /* 445: pointer.func */
    em[448] = 1; em[449] = 8; em[450] = 1; /* 448: pointer.struct.rand_meth_st */
    	em[451] = 453; em[452] = 0; 
    em[453] = 0; em[454] = 48; em[455] = 6; /* 453: struct.rand_meth_st */
    	em[456] = 468; em[457] = 0; 
    	em[458] = 471; em[459] = 8; 
    	em[460] = 474; em[461] = 16; 
    	em[462] = 477; em[463] = 24; 
    	em[464] = 471; em[465] = 32; 
    	em[466] = 480; em[467] = 40; 
    em[468] = 8884097; em[469] = 8; em[470] = 0; /* 468: pointer.func */
    em[471] = 8884097; em[472] = 8; em[473] = 0; /* 471: pointer.func */
    em[474] = 8884097; em[475] = 8; em[476] = 0; /* 474: pointer.func */
    em[477] = 8884097; em[478] = 8; em[479] = 0; /* 477: pointer.func */
    em[480] = 8884097; em[481] = 8; em[482] = 0; /* 480: pointer.func */
    em[483] = 1; em[484] = 8; em[485] = 1; /* 483: pointer.struct.store_method_st */
    	em[486] = 488; em[487] = 0; 
    em[488] = 0; em[489] = 0; em[490] = 0; /* 488: struct.store_method_st */
    em[491] = 8884097; em[492] = 8; em[493] = 0; /* 491: pointer.func */
    em[494] = 8884097; em[495] = 8; em[496] = 0; /* 494: pointer.func */
    em[497] = 8884097; em[498] = 8; em[499] = 0; /* 497: pointer.func */
    em[500] = 8884097; em[501] = 8; em[502] = 0; /* 500: pointer.func */
    em[503] = 8884097; em[504] = 8; em[505] = 0; /* 503: pointer.func */
    em[506] = 8884097; em[507] = 8; em[508] = 0; /* 506: pointer.func */
    em[509] = 8884097; em[510] = 8; em[511] = 0; /* 509: pointer.func */
    em[512] = 8884097; em[513] = 8; em[514] = 0; /* 512: pointer.func */
    em[515] = 1; em[516] = 8; em[517] = 1; /* 515: pointer.struct.ENGINE_CMD_DEFN_st */
    	em[518] = 520; em[519] = 0; 
    em[520] = 0; em[521] = 32; em[522] = 2; /* 520: struct.ENGINE_CMD_DEFN_st */
    	em[523] = 184; em[524] = 8; 
    	em[525] = 184; em[526] = 16; 
    em[527] = 0; em[528] = 32; em[529] = 2; /* 527: struct.crypto_ex_data_st_fake */
    	em[530] = 534; em[531] = 8; 
    	em[532] = 157; em[533] = 24; 
    em[534] = 8884099; em[535] = 8; em[536] = 2; /* 534: pointer_to_array_of_pointers_to_stack */
    	em[537] = 154; em[538] = 0; 
    	em[539] = 91; em[540] = 20; 
    em[541] = 1; em[542] = 8; em[543] = 1; /* 541: pointer.struct.engine_st */
    	em[544] = 211; em[545] = 0; 
    em[546] = 8884097; em[547] = 8; em[548] = 0; /* 546: pointer.func */
    em[549] = 8884097; em[550] = 8; em[551] = 0; /* 549: pointer.func */
    em[552] = 1; em[553] = 8; em[554] = 1; /* 552: pointer.struct.dsa_method */
    	em[555] = 557; em[556] = 0; 
    em[557] = 0; em[558] = 96; em[559] = 11; /* 557: struct.dsa_method */
    	em[560] = 184; em[561] = 0; 
    	em[562] = 582; em[563] = 8; 
    	em[564] = 549; em[565] = 16; 
    	em[566] = 585; em[567] = 24; 
    	em[568] = 588; em[569] = 32; 
    	em[570] = 591; em[571] = 40; 
    	em[572] = 546; em[573] = 48; 
    	em[574] = 546; em[575] = 56; 
    	em[576] = 198; em[577] = 72; 
    	em[578] = 594; em[579] = 80; 
    	em[580] = 546; em[581] = 88; 
    em[582] = 8884097; em[583] = 8; em[584] = 0; /* 582: pointer.func */
    em[585] = 8884097; em[586] = 8; em[587] = 0; /* 585: pointer.func */
    em[588] = 8884097; em[589] = 8; em[590] = 0; /* 588: pointer.func */
    em[591] = 8884097; em[592] = 8; em[593] = 0; /* 591: pointer.func */
    em[594] = 8884097; em[595] = 8; em[596] = 0; /* 594: pointer.func */
    em[597] = 1; em[598] = 8; em[599] = 1; /* 597: pointer.struct.dsa_st */
    	em[600] = 602; em[601] = 0; 
    em[602] = 0; em[603] = 136; em[604] = 11; /* 602: struct.dsa_st */
    	em[605] = 627; em[606] = 24; 
    	em[607] = 627; em[608] = 32; 
    	em[609] = 627; em[610] = 40; 
    	em[611] = 627; em[612] = 48; 
    	em[613] = 627; em[614] = 56; 
    	em[615] = 627; em[616] = 64; 
    	em[617] = 627; em[618] = 72; 
    	em[619] = 644; em[620] = 88; 
    	em[621] = 658; em[622] = 104; 
    	em[623] = 552; em[624] = 120; 
    	em[625] = 672; em[626] = 128; 
    em[627] = 1; em[628] = 8; em[629] = 1; /* 627: pointer.struct.bignum_st */
    	em[630] = 632; em[631] = 0; 
    em[632] = 0; em[633] = 24; em[634] = 1; /* 632: struct.bignum_st */
    	em[635] = 637; em[636] = 0; 
    em[637] = 8884099; em[638] = 8; em[639] = 2; /* 637: pointer_to_array_of_pointers_to_stack */
    	em[640] = 88; em[641] = 0; 
    	em[642] = 91; em[643] = 12; 
    em[644] = 1; em[645] = 8; em[646] = 1; /* 644: pointer.struct.bn_mont_ctx_st */
    	em[647] = 649; em[648] = 0; 
    em[649] = 0; em[650] = 96; em[651] = 3; /* 649: struct.bn_mont_ctx_st */
    	em[652] = 632; em[653] = 8; 
    	em[654] = 632; em[655] = 32; 
    	em[656] = 632; em[657] = 56; 
    em[658] = 0; em[659] = 32; em[660] = 2; /* 658: struct.crypto_ex_data_st_fake */
    	em[661] = 665; em[662] = 8; 
    	em[663] = 157; em[664] = 24; 
    em[665] = 8884099; em[666] = 8; em[667] = 2; /* 665: pointer_to_array_of_pointers_to_stack */
    	em[668] = 154; em[669] = 0; 
    	em[670] = 91; em[671] = 20; 
    em[672] = 1; em[673] = 8; em[674] = 1; /* 672: pointer.struct.engine_st */
    	em[675] = 211; em[676] = 0; 
    em[677] = 0; em[678] = 88; em[679] = 7; /* 677: struct.bn_blinding_st */
    	em[680] = 694; em[681] = 0; 
    	em[682] = 694; em[683] = 8; 
    	em[684] = 694; em[685] = 16; 
    	em[686] = 694; em[687] = 24; 
    	em[688] = 711; em[689] = 40; 
    	em[690] = 716; em[691] = 72; 
    	em[692] = 730; em[693] = 80; 
    em[694] = 1; em[695] = 8; em[696] = 1; /* 694: pointer.struct.bignum_st */
    	em[697] = 699; em[698] = 0; 
    em[699] = 0; em[700] = 24; em[701] = 1; /* 699: struct.bignum_st */
    	em[702] = 704; em[703] = 0; 
    em[704] = 8884099; em[705] = 8; em[706] = 2; /* 704: pointer_to_array_of_pointers_to_stack */
    	em[707] = 88; em[708] = 0; 
    	em[709] = 91; em[710] = 12; 
    em[711] = 0; em[712] = 16; em[713] = 1; /* 711: struct.crypto_threadid_st */
    	em[714] = 154; em[715] = 0; 
    em[716] = 1; em[717] = 8; em[718] = 1; /* 716: pointer.struct.bn_mont_ctx_st */
    	em[719] = 721; em[720] = 0; 
    em[721] = 0; em[722] = 96; em[723] = 3; /* 721: struct.bn_mont_ctx_st */
    	em[724] = 699; em[725] = 8; 
    	em[726] = 699; em[727] = 32; 
    	em[728] = 699; em[729] = 56; 
    em[730] = 8884097; em[731] = 8; em[732] = 0; /* 730: pointer.func */
    em[733] = 0; em[734] = 96; em[735] = 3; /* 733: struct.bn_mont_ctx_st */
    	em[736] = 742; em[737] = 8; 
    	em[738] = 742; em[739] = 32; 
    	em[740] = 742; em[741] = 56; 
    em[742] = 0; em[743] = 24; em[744] = 1; /* 742: struct.bignum_st */
    	em[745] = 747; em[746] = 0; 
    em[747] = 8884099; em[748] = 8; em[749] = 2; /* 747: pointer_to_array_of_pointers_to_stack */
    	em[750] = 88; em[751] = 0; 
    	em[752] = 91; em[753] = 12; 
    em[754] = 8884097; em[755] = 8; em[756] = 0; /* 754: pointer.func */
    em[757] = 8884097; em[758] = 8; em[759] = 0; /* 757: pointer.func */
    em[760] = 1; em[761] = 8; em[762] = 1; /* 760: pointer.struct.ec_key_st */
    	em[763] = 765; em[764] = 0; 
    em[765] = 0; em[766] = 56; em[767] = 4; /* 765: struct.ec_key_st */
    	em[768] = 776; em[769] = 8; 
    	em[770] = 1221; em[771] = 16; 
    	em[772] = 1226; em[773] = 24; 
    	em[774] = 1243; em[775] = 48; 
    em[776] = 1; em[777] = 8; em[778] = 1; /* 776: pointer.struct.ec_group_st */
    	em[779] = 781; em[780] = 0; 
    em[781] = 0; em[782] = 232; em[783] = 12; /* 781: struct.ec_group_st */
    	em[784] = 808; em[785] = 0; 
    	em[786] = 977; em[787] = 8; 
    	em[788] = 1177; em[789] = 16; 
    	em[790] = 1177; em[791] = 40; 
    	em[792] = 18; em[793] = 80; 
    	em[794] = 1189; em[795] = 96; 
    	em[796] = 1177; em[797] = 104; 
    	em[798] = 1177; em[799] = 152; 
    	em[800] = 1177; em[801] = 176; 
    	em[802] = 154; em[803] = 208; 
    	em[804] = 154; em[805] = 216; 
    	em[806] = 1218; em[807] = 224; 
    em[808] = 1; em[809] = 8; em[810] = 1; /* 808: pointer.struct.ec_method_st */
    	em[811] = 813; em[812] = 0; 
    em[813] = 0; em[814] = 304; em[815] = 37; /* 813: struct.ec_method_st */
    	em[816] = 890; em[817] = 8; 
    	em[818] = 893; em[819] = 16; 
    	em[820] = 893; em[821] = 24; 
    	em[822] = 896; em[823] = 32; 
    	em[824] = 754; em[825] = 40; 
    	em[826] = 899; em[827] = 48; 
    	em[828] = 902; em[829] = 56; 
    	em[830] = 905; em[831] = 64; 
    	em[832] = 908; em[833] = 72; 
    	em[834] = 911; em[835] = 80; 
    	em[836] = 911; em[837] = 88; 
    	em[838] = 914; em[839] = 96; 
    	em[840] = 917; em[841] = 104; 
    	em[842] = 920; em[843] = 112; 
    	em[844] = 923; em[845] = 120; 
    	em[846] = 926; em[847] = 128; 
    	em[848] = 929; em[849] = 136; 
    	em[850] = 932; em[851] = 144; 
    	em[852] = 935; em[853] = 152; 
    	em[854] = 938; em[855] = 160; 
    	em[856] = 941; em[857] = 168; 
    	em[858] = 944; em[859] = 176; 
    	em[860] = 947; em[861] = 184; 
    	em[862] = 950; em[863] = 192; 
    	em[864] = 953; em[865] = 200; 
    	em[866] = 956; em[867] = 208; 
    	em[868] = 947; em[869] = 216; 
    	em[870] = 959; em[871] = 224; 
    	em[872] = 962; em[873] = 232; 
    	em[874] = 965; em[875] = 240; 
    	em[876] = 902; em[877] = 248; 
    	em[878] = 968; em[879] = 256; 
    	em[880] = 971; em[881] = 264; 
    	em[882] = 968; em[883] = 272; 
    	em[884] = 971; em[885] = 280; 
    	em[886] = 971; em[887] = 288; 
    	em[888] = 974; em[889] = 296; 
    em[890] = 8884097; em[891] = 8; em[892] = 0; /* 890: pointer.func */
    em[893] = 8884097; em[894] = 8; em[895] = 0; /* 893: pointer.func */
    em[896] = 8884097; em[897] = 8; em[898] = 0; /* 896: pointer.func */
    em[899] = 8884097; em[900] = 8; em[901] = 0; /* 899: pointer.func */
    em[902] = 8884097; em[903] = 8; em[904] = 0; /* 902: pointer.func */
    em[905] = 8884097; em[906] = 8; em[907] = 0; /* 905: pointer.func */
    em[908] = 8884097; em[909] = 8; em[910] = 0; /* 908: pointer.func */
    em[911] = 8884097; em[912] = 8; em[913] = 0; /* 911: pointer.func */
    em[914] = 8884097; em[915] = 8; em[916] = 0; /* 914: pointer.func */
    em[917] = 8884097; em[918] = 8; em[919] = 0; /* 917: pointer.func */
    em[920] = 8884097; em[921] = 8; em[922] = 0; /* 920: pointer.func */
    em[923] = 8884097; em[924] = 8; em[925] = 0; /* 923: pointer.func */
    em[926] = 8884097; em[927] = 8; em[928] = 0; /* 926: pointer.func */
    em[929] = 8884097; em[930] = 8; em[931] = 0; /* 929: pointer.func */
    em[932] = 8884097; em[933] = 8; em[934] = 0; /* 932: pointer.func */
    em[935] = 8884097; em[936] = 8; em[937] = 0; /* 935: pointer.func */
    em[938] = 8884097; em[939] = 8; em[940] = 0; /* 938: pointer.func */
    em[941] = 8884097; em[942] = 8; em[943] = 0; /* 941: pointer.func */
    em[944] = 8884097; em[945] = 8; em[946] = 0; /* 944: pointer.func */
    em[947] = 8884097; em[948] = 8; em[949] = 0; /* 947: pointer.func */
    em[950] = 8884097; em[951] = 8; em[952] = 0; /* 950: pointer.func */
    em[953] = 8884097; em[954] = 8; em[955] = 0; /* 953: pointer.func */
    em[956] = 8884097; em[957] = 8; em[958] = 0; /* 956: pointer.func */
    em[959] = 8884097; em[960] = 8; em[961] = 0; /* 959: pointer.func */
    em[962] = 8884097; em[963] = 8; em[964] = 0; /* 962: pointer.func */
    em[965] = 8884097; em[966] = 8; em[967] = 0; /* 965: pointer.func */
    em[968] = 8884097; em[969] = 8; em[970] = 0; /* 968: pointer.func */
    em[971] = 8884097; em[972] = 8; em[973] = 0; /* 971: pointer.func */
    em[974] = 8884097; em[975] = 8; em[976] = 0; /* 974: pointer.func */
    em[977] = 1; em[978] = 8; em[979] = 1; /* 977: pointer.struct.ec_point_st */
    	em[980] = 982; em[981] = 0; 
    em[982] = 0; em[983] = 88; em[984] = 4; /* 982: struct.ec_point_st */
    	em[985] = 993; em[986] = 0; 
    	em[987] = 1165; em[988] = 8; 
    	em[989] = 1165; em[990] = 32; 
    	em[991] = 1165; em[992] = 56; 
    em[993] = 1; em[994] = 8; em[995] = 1; /* 993: pointer.struct.ec_method_st */
    	em[996] = 998; em[997] = 0; 
    em[998] = 0; em[999] = 304; em[1000] = 37; /* 998: struct.ec_method_st */
    	em[1001] = 1075; em[1002] = 8; 
    	em[1003] = 1078; em[1004] = 16; 
    	em[1005] = 1078; em[1006] = 24; 
    	em[1007] = 1081; em[1008] = 32; 
    	em[1009] = 1084; em[1010] = 40; 
    	em[1011] = 1087; em[1012] = 48; 
    	em[1013] = 1090; em[1014] = 56; 
    	em[1015] = 1093; em[1016] = 64; 
    	em[1017] = 1096; em[1018] = 72; 
    	em[1019] = 1099; em[1020] = 80; 
    	em[1021] = 1099; em[1022] = 88; 
    	em[1023] = 1102; em[1024] = 96; 
    	em[1025] = 1105; em[1026] = 104; 
    	em[1027] = 1108; em[1028] = 112; 
    	em[1029] = 1111; em[1030] = 120; 
    	em[1031] = 1114; em[1032] = 128; 
    	em[1033] = 1117; em[1034] = 136; 
    	em[1035] = 1120; em[1036] = 144; 
    	em[1037] = 1123; em[1038] = 152; 
    	em[1039] = 1126; em[1040] = 160; 
    	em[1041] = 1129; em[1042] = 168; 
    	em[1043] = 1132; em[1044] = 176; 
    	em[1045] = 1135; em[1046] = 184; 
    	em[1047] = 1138; em[1048] = 192; 
    	em[1049] = 1141; em[1050] = 200; 
    	em[1051] = 1144; em[1052] = 208; 
    	em[1053] = 1135; em[1054] = 216; 
    	em[1055] = 1147; em[1056] = 224; 
    	em[1057] = 1150; em[1058] = 232; 
    	em[1059] = 1153; em[1060] = 240; 
    	em[1061] = 1090; em[1062] = 248; 
    	em[1063] = 1156; em[1064] = 256; 
    	em[1065] = 1159; em[1066] = 264; 
    	em[1067] = 1156; em[1068] = 272; 
    	em[1069] = 1159; em[1070] = 280; 
    	em[1071] = 1159; em[1072] = 288; 
    	em[1073] = 1162; em[1074] = 296; 
    em[1075] = 8884097; em[1076] = 8; em[1077] = 0; /* 1075: pointer.func */
    em[1078] = 8884097; em[1079] = 8; em[1080] = 0; /* 1078: pointer.func */
    em[1081] = 8884097; em[1082] = 8; em[1083] = 0; /* 1081: pointer.func */
    em[1084] = 8884097; em[1085] = 8; em[1086] = 0; /* 1084: pointer.func */
    em[1087] = 8884097; em[1088] = 8; em[1089] = 0; /* 1087: pointer.func */
    em[1090] = 8884097; em[1091] = 8; em[1092] = 0; /* 1090: pointer.func */
    em[1093] = 8884097; em[1094] = 8; em[1095] = 0; /* 1093: pointer.func */
    em[1096] = 8884097; em[1097] = 8; em[1098] = 0; /* 1096: pointer.func */
    em[1099] = 8884097; em[1100] = 8; em[1101] = 0; /* 1099: pointer.func */
    em[1102] = 8884097; em[1103] = 8; em[1104] = 0; /* 1102: pointer.func */
    em[1105] = 8884097; em[1106] = 8; em[1107] = 0; /* 1105: pointer.func */
    em[1108] = 8884097; em[1109] = 8; em[1110] = 0; /* 1108: pointer.func */
    em[1111] = 8884097; em[1112] = 8; em[1113] = 0; /* 1111: pointer.func */
    em[1114] = 8884097; em[1115] = 8; em[1116] = 0; /* 1114: pointer.func */
    em[1117] = 8884097; em[1118] = 8; em[1119] = 0; /* 1117: pointer.func */
    em[1120] = 8884097; em[1121] = 8; em[1122] = 0; /* 1120: pointer.func */
    em[1123] = 8884097; em[1124] = 8; em[1125] = 0; /* 1123: pointer.func */
    em[1126] = 8884097; em[1127] = 8; em[1128] = 0; /* 1126: pointer.func */
    em[1129] = 8884097; em[1130] = 8; em[1131] = 0; /* 1129: pointer.func */
    em[1132] = 8884097; em[1133] = 8; em[1134] = 0; /* 1132: pointer.func */
    em[1135] = 8884097; em[1136] = 8; em[1137] = 0; /* 1135: pointer.func */
    em[1138] = 8884097; em[1139] = 8; em[1140] = 0; /* 1138: pointer.func */
    em[1141] = 8884097; em[1142] = 8; em[1143] = 0; /* 1141: pointer.func */
    em[1144] = 8884097; em[1145] = 8; em[1146] = 0; /* 1144: pointer.func */
    em[1147] = 8884097; em[1148] = 8; em[1149] = 0; /* 1147: pointer.func */
    em[1150] = 8884097; em[1151] = 8; em[1152] = 0; /* 1150: pointer.func */
    em[1153] = 8884097; em[1154] = 8; em[1155] = 0; /* 1153: pointer.func */
    em[1156] = 8884097; em[1157] = 8; em[1158] = 0; /* 1156: pointer.func */
    em[1159] = 8884097; em[1160] = 8; em[1161] = 0; /* 1159: pointer.func */
    em[1162] = 8884097; em[1163] = 8; em[1164] = 0; /* 1162: pointer.func */
    em[1165] = 0; em[1166] = 24; em[1167] = 1; /* 1165: struct.bignum_st */
    	em[1168] = 1170; em[1169] = 0; 
    em[1170] = 8884099; em[1171] = 8; em[1172] = 2; /* 1170: pointer_to_array_of_pointers_to_stack */
    	em[1173] = 88; em[1174] = 0; 
    	em[1175] = 91; em[1176] = 12; 
    em[1177] = 0; em[1178] = 24; em[1179] = 1; /* 1177: struct.bignum_st */
    	em[1180] = 1182; em[1181] = 0; 
    em[1182] = 8884099; em[1183] = 8; em[1184] = 2; /* 1182: pointer_to_array_of_pointers_to_stack */
    	em[1185] = 88; em[1186] = 0; 
    	em[1187] = 91; em[1188] = 12; 
    em[1189] = 1; em[1190] = 8; em[1191] = 1; /* 1189: pointer.struct.ec_extra_data_st */
    	em[1192] = 1194; em[1193] = 0; 
    em[1194] = 0; em[1195] = 40; em[1196] = 5; /* 1194: struct.ec_extra_data_st */
    	em[1197] = 1207; em[1198] = 0; 
    	em[1199] = 154; em[1200] = 8; 
    	em[1201] = 1212; em[1202] = 16; 
    	em[1203] = 1215; em[1204] = 24; 
    	em[1205] = 1215; em[1206] = 32; 
    em[1207] = 1; em[1208] = 8; em[1209] = 1; /* 1207: pointer.struct.ec_extra_data_st */
    	em[1210] = 1194; em[1211] = 0; 
    em[1212] = 8884097; em[1213] = 8; em[1214] = 0; /* 1212: pointer.func */
    em[1215] = 8884097; em[1216] = 8; em[1217] = 0; /* 1215: pointer.func */
    em[1218] = 8884097; em[1219] = 8; em[1220] = 0; /* 1218: pointer.func */
    em[1221] = 1; em[1222] = 8; em[1223] = 1; /* 1221: pointer.struct.ec_point_st */
    	em[1224] = 982; em[1225] = 0; 
    em[1226] = 1; em[1227] = 8; em[1228] = 1; /* 1226: pointer.struct.bignum_st */
    	em[1229] = 1231; em[1230] = 0; 
    em[1231] = 0; em[1232] = 24; em[1233] = 1; /* 1231: struct.bignum_st */
    	em[1234] = 1236; em[1235] = 0; 
    em[1236] = 8884099; em[1237] = 8; em[1238] = 2; /* 1236: pointer_to_array_of_pointers_to_stack */
    	em[1239] = 88; em[1240] = 0; 
    	em[1241] = 91; em[1242] = 12; 
    em[1243] = 1; em[1244] = 8; em[1245] = 1; /* 1243: pointer.struct.ec_extra_data_st */
    	em[1246] = 1248; em[1247] = 0; 
    em[1248] = 0; em[1249] = 40; em[1250] = 5; /* 1248: struct.ec_extra_data_st */
    	em[1251] = 1261; em[1252] = 0; 
    	em[1253] = 154; em[1254] = 8; 
    	em[1255] = 1212; em[1256] = 16; 
    	em[1257] = 1215; em[1258] = 24; 
    	em[1259] = 1215; em[1260] = 32; 
    em[1261] = 1; em[1262] = 8; em[1263] = 1; /* 1261: pointer.struct.ec_extra_data_st */
    	em[1264] = 1248; em[1265] = 0; 
    em[1266] = 1; em[1267] = 8; em[1268] = 1; /* 1266: pointer.struct.bignum_st */
    	em[1269] = 742; em[1270] = 0; 
    em[1271] = 1; em[1272] = 8; em[1273] = 1; /* 1271: pointer.unsigned char */
    	em[1274] = 23; em[1275] = 0; 
    em[1276] = 8884097; em[1277] = 8; em[1278] = 0; /* 1276: pointer.func */
    em[1279] = 0; em[1280] = 1; em[1281] = 0; /* 1279: char */
    em[1282] = 1; em[1283] = 8; em[1284] = 1; /* 1282: pointer.struct.asn1_object_st */
    	em[1285] = 1287; em[1286] = 0; 
    em[1287] = 0; em[1288] = 40; em[1289] = 3; /* 1287: struct.asn1_object_st */
    	em[1290] = 184; em[1291] = 0; 
    	em[1292] = 184; em[1293] = 8; 
    	em[1294] = 1271; em[1295] = 24; 
    em[1296] = 8884097; em[1297] = 8; em[1298] = 0; /* 1296: pointer.func */
    em[1299] = 8884097; em[1300] = 8; em[1301] = 0; /* 1299: pointer.func */
    em[1302] = 8884097; em[1303] = 8; em[1304] = 0; /* 1302: pointer.func */
    em[1305] = 0; em[1306] = 112; em[1307] = 13; /* 1305: struct.rsa_meth_st */
    	em[1308] = 184; em[1309] = 0; 
    	em[1310] = 1302; em[1311] = 8; 
    	em[1312] = 1302; em[1313] = 16; 
    	em[1314] = 1302; em[1315] = 24; 
    	em[1316] = 1302; em[1317] = 32; 
    	em[1318] = 1334; em[1319] = 40; 
    	em[1320] = 1299; em[1321] = 48; 
    	em[1322] = 1296; em[1323] = 56; 
    	em[1324] = 1296; em[1325] = 64; 
    	em[1326] = 198; em[1327] = 80; 
    	em[1328] = 1276; em[1329] = 88; 
    	em[1330] = 1337; em[1331] = 96; 
    	em[1332] = 757; em[1333] = 104; 
    em[1334] = 8884097; em[1335] = 8; em[1336] = 0; /* 1334: pointer.func */
    em[1337] = 8884097; em[1338] = 8; em[1339] = 0; /* 1337: pointer.func */
    em[1340] = 1; em[1341] = 8; em[1342] = 1; /* 1340: pointer.struct.rsa_meth_st */
    	em[1343] = 1305; em[1344] = 0; 
    em[1345] = 0; em[1346] = 168; em[1347] = 17; /* 1345: struct.rsa_st */
    	em[1348] = 1340; em[1349] = 16; 
    	em[1350] = 1382; em[1351] = 24; 
    	em[1352] = 1266; em[1353] = 32; 
    	em[1354] = 1266; em[1355] = 40; 
    	em[1356] = 1266; em[1357] = 48; 
    	em[1358] = 1266; em[1359] = 56; 
    	em[1360] = 1266; em[1361] = 64; 
    	em[1362] = 1266; em[1363] = 72; 
    	em[1364] = 1266; em[1365] = 80; 
    	em[1366] = 1266; em[1367] = 88; 
    	em[1368] = 1387; em[1369] = 96; 
    	em[1370] = 1401; em[1371] = 120; 
    	em[1372] = 1401; em[1373] = 128; 
    	em[1374] = 1401; em[1375] = 136; 
    	em[1376] = 198; em[1377] = 144; 
    	em[1378] = 1406; em[1379] = 152; 
    	em[1380] = 1406; em[1381] = 160; 
    em[1382] = 1; em[1383] = 8; em[1384] = 1; /* 1382: pointer.struct.engine_st */
    	em[1385] = 211; em[1386] = 0; 
    em[1387] = 0; em[1388] = 32; em[1389] = 2; /* 1387: struct.crypto_ex_data_st_fake */
    	em[1390] = 1394; em[1391] = 8; 
    	em[1392] = 157; em[1393] = 24; 
    em[1394] = 8884099; em[1395] = 8; em[1396] = 2; /* 1394: pointer_to_array_of_pointers_to_stack */
    	em[1397] = 154; em[1398] = 0; 
    	em[1399] = 91; em[1400] = 20; 
    em[1401] = 1; em[1402] = 8; em[1403] = 1; /* 1401: pointer.struct.bn_mont_ctx_st */
    	em[1404] = 733; em[1405] = 0; 
    em[1406] = 1; em[1407] = 8; em[1408] = 1; /* 1406: pointer.struct.bn_blinding_st */
    	em[1409] = 677; em[1410] = 0; 
    em[1411] = 0; em[1412] = 8; em[1413] = 5; /* 1411: union.unknown */
    	em[1414] = 198; em[1415] = 0; 
    	em[1416] = 1424; em[1417] = 0; 
    	em[1418] = 597; em[1419] = 0; 
    	em[1420] = 1429; em[1421] = 0; 
    	em[1422] = 760; em[1423] = 0; 
    em[1424] = 1; em[1425] = 8; em[1426] = 1; /* 1424: pointer.struct.rsa_st */
    	em[1427] = 1345; em[1428] = 0; 
    em[1429] = 1; em[1430] = 8; em[1431] = 1; /* 1429: pointer.struct.dh_st */
    	em[1432] = 94; em[1433] = 0; 
    em[1434] = 1; em[1435] = 8; em[1436] = 1; /* 1434: pointer.struct.asn1_string_st */
    	em[1437] = 1439; em[1438] = 0; 
    em[1439] = 0; em[1440] = 24; em[1441] = 1; /* 1439: struct.asn1_string_st */
    	em[1442] = 18; em[1443] = 8; 
    em[1444] = 1; em[1445] = 8; em[1446] = 1; /* 1444: pointer.struct.evp_pkey_asn1_method_st */
    	em[1447] = 1449; em[1448] = 0; 
    em[1449] = 0; em[1450] = 208; em[1451] = 24; /* 1449: struct.evp_pkey_asn1_method_st */
    	em[1452] = 198; em[1453] = 16; 
    	em[1454] = 198; em[1455] = 24; 
    	em[1456] = 1500; em[1457] = 32; 
    	em[1458] = 1503; em[1459] = 40; 
    	em[1460] = 1506; em[1461] = 48; 
    	em[1462] = 1509; em[1463] = 56; 
    	em[1464] = 1512; em[1465] = 64; 
    	em[1466] = 1515; em[1467] = 72; 
    	em[1468] = 1509; em[1469] = 80; 
    	em[1470] = 1518; em[1471] = 88; 
    	em[1472] = 1518; em[1473] = 96; 
    	em[1474] = 1521; em[1475] = 104; 
    	em[1476] = 1524; em[1477] = 112; 
    	em[1478] = 1518; em[1479] = 120; 
    	em[1480] = 1527; em[1481] = 128; 
    	em[1482] = 1506; em[1483] = 136; 
    	em[1484] = 1509; em[1485] = 144; 
    	em[1486] = 1530; em[1487] = 152; 
    	em[1488] = 1533; em[1489] = 160; 
    	em[1490] = 1536; em[1491] = 168; 
    	em[1492] = 1521; em[1493] = 176; 
    	em[1494] = 1524; em[1495] = 184; 
    	em[1496] = 1539; em[1497] = 192; 
    	em[1498] = 1542; em[1499] = 200; 
    em[1500] = 8884097; em[1501] = 8; em[1502] = 0; /* 1500: pointer.func */
    em[1503] = 8884097; em[1504] = 8; em[1505] = 0; /* 1503: pointer.func */
    em[1506] = 8884097; em[1507] = 8; em[1508] = 0; /* 1506: pointer.func */
    em[1509] = 8884097; em[1510] = 8; em[1511] = 0; /* 1509: pointer.func */
    em[1512] = 8884097; em[1513] = 8; em[1514] = 0; /* 1512: pointer.func */
    em[1515] = 8884097; em[1516] = 8; em[1517] = 0; /* 1515: pointer.func */
    em[1518] = 8884097; em[1519] = 8; em[1520] = 0; /* 1518: pointer.func */
    em[1521] = 8884097; em[1522] = 8; em[1523] = 0; /* 1521: pointer.func */
    em[1524] = 8884097; em[1525] = 8; em[1526] = 0; /* 1524: pointer.func */
    em[1527] = 8884097; em[1528] = 8; em[1529] = 0; /* 1527: pointer.func */
    em[1530] = 8884097; em[1531] = 8; em[1532] = 0; /* 1530: pointer.func */
    em[1533] = 8884097; em[1534] = 8; em[1535] = 0; /* 1533: pointer.func */
    em[1536] = 8884097; em[1537] = 8; em[1538] = 0; /* 1536: pointer.func */
    em[1539] = 8884097; em[1540] = 8; em[1541] = 0; /* 1539: pointer.func */
    em[1542] = 8884097; em[1543] = 8; em[1544] = 0; /* 1542: pointer.func */
    em[1545] = 1; em[1546] = 8; em[1547] = 1; /* 1545: pointer.struct.asn1_string_st */
    	em[1548] = 1439; em[1549] = 0; 
    em[1550] = 1; em[1551] = 8; em[1552] = 1; /* 1550: pointer.struct.ASN1_VALUE_st */
    	em[1553] = 1555; em[1554] = 0; 
    em[1555] = 0; em[1556] = 0; em[1557] = 0; /* 1555: struct.ASN1_VALUE_st */
    em[1558] = 0; em[1559] = 24; em[1560] = 2; /* 1558: struct.x509_attributes_st */
    	em[1561] = 1565; em[1562] = 0; 
    	em[1563] = 1579; em[1564] = 16; 
    em[1565] = 1; em[1566] = 8; em[1567] = 1; /* 1565: pointer.struct.asn1_object_st */
    	em[1568] = 1570; em[1569] = 0; 
    em[1570] = 0; em[1571] = 40; em[1572] = 3; /* 1570: struct.asn1_object_st */
    	em[1573] = 184; em[1574] = 0; 
    	em[1575] = 184; em[1576] = 8; 
    	em[1577] = 1271; em[1578] = 24; 
    em[1579] = 0; em[1580] = 8; em[1581] = 3; /* 1579: union.unknown */
    	em[1582] = 198; em[1583] = 0; 
    	em[1584] = 1588; em[1585] = 0; 
    	em[1586] = 1730; em[1587] = 0; 
    em[1588] = 1; em[1589] = 8; em[1590] = 1; /* 1588: pointer.struct.stack_st_ASN1_TYPE */
    	em[1591] = 1593; em[1592] = 0; 
    em[1593] = 0; em[1594] = 32; em[1595] = 2; /* 1593: struct.stack_st_fake_ASN1_TYPE */
    	em[1596] = 1600; em[1597] = 8; 
    	em[1598] = 157; em[1599] = 24; 
    em[1600] = 8884099; em[1601] = 8; em[1602] = 2; /* 1600: pointer_to_array_of_pointers_to_stack */
    	em[1603] = 1607; em[1604] = 0; 
    	em[1605] = 91; em[1606] = 20; 
    em[1607] = 0; em[1608] = 8; em[1609] = 1; /* 1607: pointer.ASN1_TYPE */
    	em[1610] = 1612; em[1611] = 0; 
    em[1612] = 0; em[1613] = 0; em[1614] = 1; /* 1612: ASN1_TYPE */
    	em[1615] = 1617; em[1616] = 0; 
    em[1617] = 0; em[1618] = 16; em[1619] = 1; /* 1617: struct.asn1_type_st */
    	em[1620] = 1622; em[1621] = 8; 
    em[1622] = 0; em[1623] = 8; em[1624] = 20; /* 1622: union.unknown */
    	em[1625] = 198; em[1626] = 0; 
    	em[1627] = 1665; em[1628] = 0; 
    	em[1629] = 1282; em[1630] = 0; 
    	em[1631] = 1670; em[1632] = 0; 
    	em[1633] = 1675; em[1634] = 0; 
    	em[1635] = 1680; em[1636] = 0; 
    	em[1637] = 1434; em[1638] = 0; 
    	em[1639] = 1685; em[1640] = 0; 
    	em[1641] = 1690; em[1642] = 0; 
    	em[1643] = 1545; em[1644] = 0; 
    	em[1645] = 1695; em[1646] = 0; 
    	em[1647] = 1700; em[1648] = 0; 
    	em[1649] = 1705; em[1650] = 0; 
    	em[1651] = 1710; em[1652] = 0; 
    	em[1653] = 1715; em[1654] = 0; 
    	em[1655] = 1720; em[1656] = 0; 
    	em[1657] = 1725; em[1658] = 0; 
    	em[1659] = 1665; em[1660] = 0; 
    	em[1661] = 1665; em[1662] = 0; 
    	em[1663] = 1550; em[1664] = 0; 
    em[1665] = 1; em[1666] = 8; em[1667] = 1; /* 1665: pointer.struct.asn1_string_st */
    	em[1668] = 1439; em[1669] = 0; 
    em[1670] = 1; em[1671] = 8; em[1672] = 1; /* 1670: pointer.struct.asn1_string_st */
    	em[1673] = 1439; em[1674] = 0; 
    em[1675] = 1; em[1676] = 8; em[1677] = 1; /* 1675: pointer.struct.asn1_string_st */
    	em[1678] = 1439; em[1679] = 0; 
    em[1680] = 1; em[1681] = 8; em[1682] = 1; /* 1680: pointer.struct.asn1_string_st */
    	em[1683] = 1439; em[1684] = 0; 
    em[1685] = 1; em[1686] = 8; em[1687] = 1; /* 1685: pointer.struct.asn1_string_st */
    	em[1688] = 1439; em[1689] = 0; 
    em[1690] = 1; em[1691] = 8; em[1692] = 1; /* 1690: pointer.struct.asn1_string_st */
    	em[1693] = 1439; em[1694] = 0; 
    em[1695] = 1; em[1696] = 8; em[1697] = 1; /* 1695: pointer.struct.asn1_string_st */
    	em[1698] = 1439; em[1699] = 0; 
    em[1700] = 1; em[1701] = 8; em[1702] = 1; /* 1700: pointer.struct.asn1_string_st */
    	em[1703] = 1439; em[1704] = 0; 
    em[1705] = 1; em[1706] = 8; em[1707] = 1; /* 1705: pointer.struct.asn1_string_st */
    	em[1708] = 1439; em[1709] = 0; 
    em[1710] = 1; em[1711] = 8; em[1712] = 1; /* 1710: pointer.struct.asn1_string_st */
    	em[1713] = 1439; em[1714] = 0; 
    em[1715] = 1; em[1716] = 8; em[1717] = 1; /* 1715: pointer.struct.asn1_string_st */
    	em[1718] = 1439; em[1719] = 0; 
    em[1720] = 1; em[1721] = 8; em[1722] = 1; /* 1720: pointer.struct.asn1_string_st */
    	em[1723] = 1439; em[1724] = 0; 
    em[1725] = 1; em[1726] = 8; em[1727] = 1; /* 1725: pointer.struct.asn1_string_st */
    	em[1728] = 1439; em[1729] = 0; 
    em[1730] = 1; em[1731] = 8; em[1732] = 1; /* 1730: pointer.struct.asn1_type_st */
    	em[1733] = 1735; em[1734] = 0; 
    em[1735] = 0; em[1736] = 16; em[1737] = 1; /* 1735: struct.asn1_type_st */
    	em[1738] = 1740; em[1739] = 8; 
    em[1740] = 0; em[1741] = 8; em[1742] = 20; /* 1740: union.unknown */
    	em[1743] = 198; em[1744] = 0; 
    	em[1745] = 1783; em[1746] = 0; 
    	em[1747] = 1565; em[1748] = 0; 
    	em[1749] = 1788; em[1750] = 0; 
    	em[1751] = 71; em[1752] = 0; 
    	em[1753] = 66; em[1754] = 0; 
    	em[1755] = 61; em[1756] = 0; 
    	em[1757] = 1793; em[1758] = 0; 
    	em[1759] = 56; em[1760] = 0; 
    	em[1761] = 51; em[1762] = 0; 
    	em[1763] = 46; em[1764] = 0; 
    	em[1765] = 41; em[1766] = 0; 
    	em[1767] = 36; em[1768] = 0; 
    	em[1769] = 31; em[1770] = 0; 
    	em[1771] = 26; em[1772] = 0; 
    	em[1773] = 1798; em[1774] = 0; 
    	em[1775] = 8; em[1776] = 0; 
    	em[1777] = 1783; em[1778] = 0; 
    	em[1779] = 1783; em[1780] = 0; 
    	em[1781] = 0; em[1782] = 0; 
    em[1783] = 1; em[1784] = 8; em[1785] = 1; /* 1783: pointer.struct.asn1_string_st */
    	em[1786] = 13; em[1787] = 0; 
    em[1788] = 1; em[1789] = 8; em[1790] = 1; /* 1788: pointer.struct.asn1_string_st */
    	em[1791] = 13; em[1792] = 0; 
    em[1793] = 1; em[1794] = 8; em[1795] = 1; /* 1793: pointer.struct.asn1_string_st */
    	em[1796] = 13; em[1797] = 0; 
    em[1798] = 1; em[1799] = 8; em[1800] = 1; /* 1798: pointer.struct.asn1_string_st */
    	em[1801] = 13; em[1802] = 0; 
    em[1803] = 1; em[1804] = 8; em[1805] = 1; /* 1803: pointer.struct.evp_pkey_st */
    	em[1806] = 1808; em[1807] = 0; 
    em[1808] = 0; em[1809] = 56; em[1810] = 4; /* 1808: struct.evp_pkey_st */
    	em[1811] = 1444; em[1812] = 16; 
    	em[1813] = 206; em[1814] = 24; 
    	em[1815] = 1411; em[1816] = 32; 
    	em[1817] = 1819; em[1818] = 48; 
    em[1819] = 1; em[1820] = 8; em[1821] = 1; /* 1819: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[1822] = 1824; em[1823] = 0; 
    em[1824] = 0; em[1825] = 32; em[1826] = 2; /* 1824: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[1827] = 1831; em[1828] = 8; 
    	em[1829] = 157; em[1830] = 24; 
    em[1831] = 8884099; em[1832] = 8; em[1833] = 2; /* 1831: pointer_to_array_of_pointers_to_stack */
    	em[1834] = 1838; em[1835] = 0; 
    	em[1836] = 91; em[1837] = 20; 
    em[1838] = 0; em[1839] = 8; em[1840] = 1; /* 1838: pointer.X509_ATTRIBUTE */
    	em[1841] = 1843; em[1842] = 0; 
    em[1843] = 0; em[1844] = 0; em[1845] = 1; /* 1843: X509_ATTRIBUTE */
    	em[1846] = 1558; em[1847] = 0; 
    args_addr->arg_entity_index[0] = 1803;
    args_addr->ret_entity_index = -1;
    populate_arg(args_addr, arg_a);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    EVP_PKEY * new_arg_a = *((EVP_PKEY * *)new_args->args[0]);

    void (*orig_EVP_PKEY_free)(EVP_PKEY *);
    orig_EVP_PKEY_free = dlsym(RTLD_NEXT, "EVP_PKEY_free");
    (*orig_EVP_PKEY_free)(new_arg_a);

    syscall(889);

    free(args_addr);

}

