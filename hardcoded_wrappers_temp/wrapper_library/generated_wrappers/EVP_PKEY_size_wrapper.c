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

int bb_EVP_PKEY_size(EVP_PKEY * arg_a);

int EVP_PKEY_size(EVP_PKEY * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("EVP_PKEY_size called %lu\n", in_lib);
    if (!in_lib)
        return bb_EVP_PKEY_size(arg_a);
    else {
        int (*orig_EVP_PKEY_size)(EVP_PKEY *);
        orig_EVP_PKEY_size = dlsym(RTLD_NEXT, "EVP_PKEY_size");
        return orig_EVP_PKEY_size(arg_a);
    }
}

int bb_EVP_PKEY_size(EVP_PKEY * arg_a) 
{
    int ret;

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
    em[552] = 1; em[553] = 8; em[554] = 1; /* 552: pointer.struct.asn1_string_st */
    	em[555] = 557; em[556] = 0; 
    em[557] = 0; em[558] = 24; em[559] = 1; /* 557: struct.asn1_string_st */
    	em[560] = 18; em[561] = 8; 
    em[562] = 1; em[563] = 8; em[564] = 1; /* 562: pointer.struct.dsa_method */
    	em[565] = 567; em[566] = 0; 
    em[567] = 0; em[568] = 96; em[569] = 11; /* 567: struct.dsa_method */
    	em[570] = 184; em[571] = 0; 
    	em[572] = 592; em[573] = 8; 
    	em[574] = 549; em[575] = 16; 
    	em[576] = 595; em[577] = 24; 
    	em[578] = 598; em[579] = 32; 
    	em[580] = 601; em[581] = 40; 
    	em[582] = 546; em[583] = 48; 
    	em[584] = 546; em[585] = 56; 
    	em[586] = 198; em[587] = 72; 
    	em[588] = 604; em[589] = 80; 
    	em[590] = 546; em[591] = 88; 
    em[592] = 8884097; em[593] = 8; em[594] = 0; /* 592: pointer.func */
    em[595] = 8884097; em[596] = 8; em[597] = 0; /* 595: pointer.func */
    em[598] = 8884097; em[599] = 8; em[600] = 0; /* 598: pointer.func */
    em[601] = 8884097; em[602] = 8; em[603] = 0; /* 601: pointer.func */
    em[604] = 8884097; em[605] = 8; em[606] = 0; /* 604: pointer.func */
    em[607] = 1; em[608] = 8; em[609] = 1; /* 607: pointer.struct.dsa_st */
    	em[610] = 612; em[611] = 0; 
    em[612] = 0; em[613] = 136; em[614] = 11; /* 612: struct.dsa_st */
    	em[615] = 637; em[616] = 24; 
    	em[617] = 637; em[618] = 32; 
    	em[619] = 637; em[620] = 40; 
    	em[621] = 637; em[622] = 48; 
    	em[623] = 637; em[624] = 56; 
    	em[625] = 637; em[626] = 64; 
    	em[627] = 637; em[628] = 72; 
    	em[629] = 654; em[630] = 88; 
    	em[631] = 668; em[632] = 104; 
    	em[633] = 562; em[634] = 120; 
    	em[635] = 682; em[636] = 128; 
    em[637] = 1; em[638] = 8; em[639] = 1; /* 637: pointer.struct.bignum_st */
    	em[640] = 642; em[641] = 0; 
    em[642] = 0; em[643] = 24; em[644] = 1; /* 642: struct.bignum_st */
    	em[645] = 647; em[646] = 0; 
    em[647] = 8884099; em[648] = 8; em[649] = 2; /* 647: pointer_to_array_of_pointers_to_stack */
    	em[650] = 88; em[651] = 0; 
    	em[652] = 91; em[653] = 12; 
    em[654] = 1; em[655] = 8; em[656] = 1; /* 654: pointer.struct.bn_mont_ctx_st */
    	em[657] = 659; em[658] = 0; 
    em[659] = 0; em[660] = 96; em[661] = 3; /* 659: struct.bn_mont_ctx_st */
    	em[662] = 642; em[663] = 8; 
    	em[664] = 642; em[665] = 32; 
    	em[666] = 642; em[667] = 56; 
    em[668] = 0; em[669] = 32; em[670] = 2; /* 668: struct.crypto_ex_data_st_fake */
    	em[671] = 675; em[672] = 8; 
    	em[673] = 157; em[674] = 24; 
    em[675] = 8884099; em[676] = 8; em[677] = 2; /* 675: pointer_to_array_of_pointers_to_stack */
    	em[678] = 154; em[679] = 0; 
    	em[680] = 91; em[681] = 20; 
    em[682] = 1; em[683] = 8; em[684] = 1; /* 682: pointer.struct.engine_st */
    	em[685] = 211; em[686] = 0; 
    em[687] = 0; em[688] = 88; em[689] = 7; /* 687: struct.bn_blinding_st */
    	em[690] = 704; em[691] = 0; 
    	em[692] = 704; em[693] = 8; 
    	em[694] = 704; em[695] = 16; 
    	em[696] = 704; em[697] = 24; 
    	em[698] = 721; em[699] = 40; 
    	em[700] = 726; em[701] = 72; 
    	em[702] = 740; em[703] = 80; 
    em[704] = 1; em[705] = 8; em[706] = 1; /* 704: pointer.struct.bignum_st */
    	em[707] = 709; em[708] = 0; 
    em[709] = 0; em[710] = 24; em[711] = 1; /* 709: struct.bignum_st */
    	em[712] = 714; em[713] = 0; 
    em[714] = 8884099; em[715] = 8; em[716] = 2; /* 714: pointer_to_array_of_pointers_to_stack */
    	em[717] = 88; em[718] = 0; 
    	em[719] = 91; em[720] = 12; 
    em[721] = 0; em[722] = 16; em[723] = 1; /* 721: struct.crypto_threadid_st */
    	em[724] = 154; em[725] = 0; 
    em[726] = 1; em[727] = 8; em[728] = 1; /* 726: pointer.struct.bn_mont_ctx_st */
    	em[729] = 731; em[730] = 0; 
    em[731] = 0; em[732] = 96; em[733] = 3; /* 731: struct.bn_mont_ctx_st */
    	em[734] = 709; em[735] = 8; 
    	em[736] = 709; em[737] = 32; 
    	em[738] = 709; em[739] = 56; 
    em[740] = 8884097; em[741] = 8; em[742] = 0; /* 740: pointer.func */
    em[743] = 0; em[744] = 96; em[745] = 3; /* 743: struct.bn_mont_ctx_st */
    	em[746] = 752; em[747] = 8; 
    	em[748] = 752; em[749] = 32; 
    	em[750] = 752; em[751] = 56; 
    em[752] = 0; em[753] = 24; em[754] = 1; /* 752: struct.bignum_st */
    	em[755] = 757; em[756] = 0; 
    em[757] = 8884099; em[758] = 8; em[759] = 2; /* 757: pointer_to_array_of_pointers_to_stack */
    	em[760] = 88; em[761] = 0; 
    	em[762] = 91; em[763] = 12; 
    em[764] = 8884097; em[765] = 8; em[766] = 0; /* 764: pointer.func */
    em[767] = 8884097; em[768] = 8; em[769] = 0; /* 767: pointer.func */
    em[770] = 1; em[771] = 8; em[772] = 1; /* 770: pointer.struct.ec_key_st */
    	em[773] = 775; em[774] = 0; 
    em[775] = 0; em[776] = 56; em[777] = 4; /* 775: struct.ec_key_st */
    	em[778] = 786; em[779] = 8; 
    	em[780] = 1231; em[781] = 16; 
    	em[782] = 1236; em[783] = 24; 
    	em[784] = 1253; em[785] = 48; 
    em[786] = 1; em[787] = 8; em[788] = 1; /* 786: pointer.struct.ec_group_st */
    	em[789] = 791; em[790] = 0; 
    em[791] = 0; em[792] = 232; em[793] = 12; /* 791: struct.ec_group_st */
    	em[794] = 818; em[795] = 0; 
    	em[796] = 987; em[797] = 8; 
    	em[798] = 1187; em[799] = 16; 
    	em[800] = 1187; em[801] = 40; 
    	em[802] = 18; em[803] = 80; 
    	em[804] = 1199; em[805] = 96; 
    	em[806] = 1187; em[807] = 104; 
    	em[808] = 1187; em[809] = 152; 
    	em[810] = 1187; em[811] = 176; 
    	em[812] = 154; em[813] = 208; 
    	em[814] = 154; em[815] = 216; 
    	em[816] = 1228; em[817] = 224; 
    em[818] = 1; em[819] = 8; em[820] = 1; /* 818: pointer.struct.ec_method_st */
    	em[821] = 823; em[822] = 0; 
    em[823] = 0; em[824] = 304; em[825] = 37; /* 823: struct.ec_method_st */
    	em[826] = 900; em[827] = 8; 
    	em[828] = 903; em[829] = 16; 
    	em[830] = 903; em[831] = 24; 
    	em[832] = 906; em[833] = 32; 
    	em[834] = 764; em[835] = 40; 
    	em[836] = 909; em[837] = 48; 
    	em[838] = 912; em[839] = 56; 
    	em[840] = 915; em[841] = 64; 
    	em[842] = 918; em[843] = 72; 
    	em[844] = 921; em[845] = 80; 
    	em[846] = 921; em[847] = 88; 
    	em[848] = 924; em[849] = 96; 
    	em[850] = 927; em[851] = 104; 
    	em[852] = 930; em[853] = 112; 
    	em[854] = 933; em[855] = 120; 
    	em[856] = 936; em[857] = 128; 
    	em[858] = 939; em[859] = 136; 
    	em[860] = 942; em[861] = 144; 
    	em[862] = 945; em[863] = 152; 
    	em[864] = 948; em[865] = 160; 
    	em[866] = 951; em[867] = 168; 
    	em[868] = 954; em[869] = 176; 
    	em[870] = 957; em[871] = 184; 
    	em[872] = 960; em[873] = 192; 
    	em[874] = 963; em[875] = 200; 
    	em[876] = 966; em[877] = 208; 
    	em[878] = 957; em[879] = 216; 
    	em[880] = 969; em[881] = 224; 
    	em[882] = 972; em[883] = 232; 
    	em[884] = 975; em[885] = 240; 
    	em[886] = 912; em[887] = 248; 
    	em[888] = 978; em[889] = 256; 
    	em[890] = 981; em[891] = 264; 
    	em[892] = 978; em[893] = 272; 
    	em[894] = 981; em[895] = 280; 
    	em[896] = 981; em[897] = 288; 
    	em[898] = 984; em[899] = 296; 
    em[900] = 8884097; em[901] = 8; em[902] = 0; /* 900: pointer.func */
    em[903] = 8884097; em[904] = 8; em[905] = 0; /* 903: pointer.func */
    em[906] = 8884097; em[907] = 8; em[908] = 0; /* 906: pointer.func */
    em[909] = 8884097; em[910] = 8; em[911] = 0; /* 909: pointer.func */
    em[912] = 8884097; em[913] = 8; em[914] = 0; /* 912: pointer.func */
    em[915] = 8884097; em[916] = 8; em[917] = 0; /* 915: pointer.func */
    em[918] = 8884097; em[919] = 8; em[920] = 0; /* 918: pointer.func */
    em[921] = 8884097; em[922] = 8; em[923] = 0; /* 921: pointer.func */
    em[924] = 8884097; em[925] = 8; em[926] = 0; /* 924: pointer.func */
    em[927] = 8884097; em[928] = 8; em[929] = 0; /* 927: pointer.func */
    em[930] = 8884097; em[931] = 8; em[932] = 0; /* 930: pointer.func */
    em[933] = 8884097; em[934] = 8; em[935] = 0; /* 933: pointer.func */
    em[936] = 8884097; em[937] = 8; em[938] = 0; /* 936: pointer.func */
    em[939] = 8884097; em[940] = 8; em[941] = 0; /* 939: pointer.func */
    em[942] = 8884097; em[943] = 8; em[944] = 0; /* 942: pointer.func */
    em[945] = 8884097; em[946] = 8; em[947] = 0; /* 945: pointer.func */
    em[948] = 8884097; em[949] = 8; em[950] = 0; /* 948: pointer.func */
    em[951] = 8884097; em[952] = 8; em[953] = 0; /* 951: pointer.func */
    em[954] = 8884097; em[955] = 8; em[956] = 0; /* 954: pointer.func */
    em[957] = 8884097; em[958] = 8; em[959] = 0; /* 957: pointer.func */
    em[960] = 8884097; em[961] = 8; em[962] = 0; /* 960: pointer.func */
    em[963] = 8884097; em[964] = 8; em[965] = 0; /* 963: pointer.func */
    em[966] = 8884097; em[967] = 8; em[968] = 0; /* 966: pointer.func */
    em[969] = 8884097; em[970] = 8; em[971] = 0; /* 969: pointer.func */
    em[972] = 8884097; em[973] = 8; em[974] = 0; /* 972: pointer.func */
    em[975] = 8884097; em[976] = 8; em[977] = 0; /* 975: pointer.func */
    em[978] = 8884097; em[979] = 8; em[980] = 0; /* 978: pointer.func */
    em[981] = 8884097; em[982] = 8; em[983] = 0; /* 981: pointer.func */
    em[984] = 8884097; em[985] = 8; em[986] = 0; /* 984: pointer.func */
    em[987] = 1; em[988] = 8; em[989] = 1; /* 987: pointer.struct.ec_point_st */
    	em[990] = 992; em[991] = 0; 
    em[992] = 0; em[993] = 88; em[994] = 4; /* 992: struct.ec_point_st */
    	em[995] = 1003; em[996] = 0; 
    	em[997] = 1175; em[998] = 8; 
    	em[999] = 1175; em[1000] = 32; 
    	em[1001] = 1175; em[1002] = 56; 
    em[1003] = 1; em[1004] = 8; em[1005] = 1; /* 1003: pointer.struct.ec_method_st */
    	em[1006] = 1008; em[1007] = 0; 
    em[1008] = 0; em[1009] = 304; em[1010] = 37; /* 1008: struct.ec_method_st */
    	em[1011] = 1085; em[1012] = 8; 
    	em[1013] = 1088; em[1014] = 16; 
    	em[1015] = 1088; em[1016] = 24; 
    	em[1017] = 1091; em[1018] = 32; 
    	em[1019] = 1094; em[1020] = 40; 
    	em[1021] = 1097; em[1022] = 48; 
    	em[1023] = 1100; em[1024] = 56; 
    	em[1025] = 1103; em[1026] = 64; 
    	em[1027] = 1106; em[1028] = 72; 
    	em[1029] = 1109; em[1030] = 80; 
    	em[1031] = 1109; em[1032] = 88; 
    	em[1033] = 1112; em[1034] = 96; 
    	em[1035] = 1115; em[1036] = 104; 
    	em[1037] = 1118; em[1038] = 112; 
    	em[1039] = 1121; em[1040] = 120; 
    	em[1041] = 1124; em[1042] = 128; 
    	em[1043] = 1127; em[1044] = 136; 
    	em[1045] = 1130; em[1046] = 144; 
    	em[1047] = 1133; em[1048] = 152; 
    	em[1049] = 1136; em[1050] = 160; 
    	em[1051] = 1139; em[1052] = 168; 
    	em[1053] = 1142; em[1054] = 176; 
    	em[1055] = 1145; em[1056] = 184; 
    	em[1057] = 1148; em[1058] = 192; 
    	em[1059] = 1151; em[1060] = 200; 
    	em[1061] = 1154; em[1062] = 208; 
    	em[1063] = 1145; em[1064] = 216; 
    	em[1065] = 1157; em[1066] = 224; 
    	em[1067] = 1160; em[1068] = 232; 
    	em[1069] = 1163; em[1070] = 240; 
    	em[1071] = 1100; em[1072] = 248; 
    	em[1073] = 1166; em[1074] = 256; 
    	em[1075] = 1169; em[1076] = 264; 
    	em[1077] = 1166; em[1078] = 272; 
    	em[1079] = 1169; em[1080] = 280; 
    	em[1081] = 1169; em[1082] = 288; 
    	em[1083] = 1172; em[1084] = 296; 
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
    em[1148] = 8884097; em[1149] = 8; em[1150] = 0; /* 1148: pointer.func */
    em[1151] = 8884097; em[1152] = 8; em[1153] = 0; /* 1151: pointer.func */
    em[1154] = 8884097; em[1155] = 8; em[1156] = 0; /* 1154: pointer.func */
    em[1157] = 8884097; em[1158] = 8; em[1159] = 0; /* 1157: pointer.func */
    em[1160] = 8884097; em[1161] = 8; em[1162] = 0; /* 1160: pointer.func */
    em[1163] = 8884097; em[1164] = 8; em[1165] = 0; /* 1163: pointer.func */
    em[1166] = 8884097; em[1167] = 8; em[1168] = 0; /* 1166: pointer.func */
    em[1169] = 8884097; em[1170] = 8; em[1171] = 0; /* 1169: pointer.func */
    em[1172] = 8884097; em[1173] = 8; em[1174] = 0; /* 1172: pointer.func */
    em[1175] = 0; em[1176] = 24; em[1177] = 1; /* 1175: struct.bignum_st */
    	em[1178] = 1180; em[1179] = 0; 
    em[1180] = 8884099; em[1181] = 8; em[1182] = 2; /* 1180: pointer_to_array_of_pointers_to_stack */
    	em[1183] = 88; em[1184] = 0; 
    	em[1185] = 91; em[1186] = 12; 
    em[1187] = 0; em[1188] = 24; em[1189] = 1; /* 1187: struct.bignum_st */
    	em[1190] = 1192; em[1191] = 0; 
    em[1192] = 8884099; em[1193] = 8; em[1194] = 2; /* 1192: pointer_to_array_of_pointers_to_stack */
    	em[1195] = 88; em[1196] = 0; 
    	em[1197] = 91; em[1198] = 12; 
    em[1199] = 1; em[1200] = 8; em[1201] = 1; /* 1199: pointer.struct.ec_extra_data_st */
    	em[1202] = 1204; em[1203] = 0; 
    em[1204] = 0; em[1205] = 40; em[1206] = 5; /* 1204: struct.ec_extra_data_st */
    	em[1207] = 1217; em[1208] = 0; 
    	em[1209] = 154; em[1210] = 8; 
    	em[1211] = 1222; em[1212] = 16; 
    	em[1213] = 1225; em[1214] = 24; 
    	em[1215] = 1225; em[1216] = 32; 
    em[1217] = 1; em[1218] = 8; em[1219] = 1; /* 1217: pointer.struct.ec_extra_data_st */
    	em[1220] = 1204; em[1221] = 0; 
    em[1222] = 8884097; em[1223] = 8; em[1224] = 0; /* 1222: pointer.func */
    em[1225] = 8884097; em[1226] = 8; em[1227] = 0; /* 1225: pointer.func */
    em[1228] = 8884097; em[1229] = 8; em[1230] = 0; /* 1228: pointer.func */
    em[1231] = 1; em[1232] = 8; em[1233] = 1; /* 1231: pointer.struct.ec_point_st */
    	em[1234] = 992; em[1235] = 0; 
    em[1236] = 1; em[1237] = 8; em[1238] = 1; /* 1236: pointer.struct.bignum_st */
    	em[1239] = 1241; em[1240] = 0; 
    em[1241] = 0; em[1242] = 24; em[1243] = 1; /* 1241: struct.bignum_st */
    	em[1244] = 1246; em[1245] = 0; 
    em[1246] = 8884099; em[1247] = 8; em[1248] = 2; /* 1246: pointer_to_array_of_pointers_to_stack */
    	em[1249] = 88; em[1250] = 0; 
    	em[1251] = 91; em[1252] = 12; 
    em[1253] = 1; em[1254] = 8; em[1255] = 1; /* 1253: pointer.struct.ec_extra_data_st */
    	em[1256] = 1258; em[1257] = 0; 
    em[1258] = 0; em[1259] = 40; em[1260] = 5; /* 1258: struct.ec_extra_data_st */
    	em[1261] = 1271; em[1262] = 0; 
    	em[1263] = 154; em[1264] = 8; 
    	em[1265] = 1222; em[1266] = 16; 
    	em[1267] = 1225; em[1268] = 24; 
    	em[1269] = 1225; em[1270] = 32; 
    em[1271] = 1; em[1272] = 8; em[1273] = 1; /* 1271: pointer.struct.ec_extra_data_st */
    	em[1274] = 1258; em[1275] = 0; 
    em[1276] = 1; em[1277] = 8; em[1278] = 1; /* 1276: pointer.struct.bignum_st */
    	em[1279] = 752; em[1280] = 0; 
    em[1281] = 1; em[1282] = 8; em[1283] = 1; /* 1281: pointer.unsigned char */
    	em[1284] = 23; em[1285] = 0; 
    em[1286] = 8884097; em[1287] = 8; em[1288] = 0; /* 1286: pointer.func */
    em[1289] = 8884099; em[1290] = 8; em[1291] = 2; /* 1289: pointer_to_array_of_pointers_to_stack */
    	em[1292] = 1296; em[1293] = 0; 
    	em[1294] = 91; em[1295] = 20; 
    em[1296] = 0; em[1297] = 8; em[1298] = 1; /* 1296: pointer.ASN1_TYPE */
    	em[1299] = 1301; em[1300] = 0; 
    em[1301] = 0; em[1302] = 0; em[1303] = 1; /* 1301: ASN1_TYPE */
    	em[1304] = 1306; em[1305] = 0; 
    em[1306] = 0; em[1307] = 16; em[1308] = 1; /* 1306: struct.asn1_type_st */
    	em[1309] = 1311; em[1310] = 8; 
    em[1311] = 0; em[1312] = 8; em[1313] = 20; /* 1311: union.unknown */
    	em[1314] = 198; em[1315] = 0; 
    	em[1316] = 1354; em[1317] = 0; 
    	em[1318] = 1359; em[1319] = 0; 
    	em[1320] = 1373; em[1321] = 0; 
    	em[1322] = 1378; em[1323] = 0; 
    	em[1324] = 1383; em[1325] = 0; 
    	em[1326] = 1388; em[1327] = 0; 
    	em[1328] = 1393; em[1329] = 0; 
    	em[1330] = 1398; em[1331] = 0; 
    	em[1332] = 552; em[1333] = 0; 
    	em[1334] = 1403; em[1335] = 0; 
    	em[1336] = 1408; em[1337] = 0; 
    	em[1338] = 1413; em[1339] = 0; 
    	em[1340] = 1418; em[1341] = 0; 
    	em[1342] = 1423; em[1343] = 0; 
    	em[1344] = 1428; em[1345] = 0; 
    	em[1346] = 1433; em[1347] = 0; 
    	em[1348] = 1354; em[1349] = 0; 
    	em[1350] = 1354; em[1351] = 0; 
    	em[1352] = 1438; em[1353] = 0; 
    em[1354] = 1; em[1355] = 8; em[1356] = 1; /* 1354: pointer.struct.asn1_string_st */
    	em[1357] = 557; em[1358] = 0; 
    em[1359] = 1; em[1360] = 8; em[1361] = 1; /* 1359: pointer.struct.asn1_object_st */
    	em[1362] = 1364; em[1363] = 0; 
    em[1364] = 0; em[1365] = 40; em[1366] = 3; /* 1364: struct.asn1_object_st */
    	em[1367] = 184; em[1368] = 0; 
    	em[1369] = 184; em[1370] = 8; 
    	em[1371] = 1281; em[1372] = 24; 
    em[1373] = 1; em[1374] = 8; em[1375] = 1; /* 1373: pointer.struct.asn1_string_st */
    	em[1376] = 557; em[1377] = 0; 
    em[1378] = 1; em[1379] = 8; em[1380] = 1; /* 1378: pointer.struct.asn1_string_st */
    	em[1381] = 557; em[1382] = 0; 
    em[1383] = 1; em[1384] = 8; em[1385] = 1; /* 1383: pointer.struct.asn1_string_st */
    	em[1386] = 557; em[1387] = 0; 
    em[1388] = 1; em[1389] = 8; em[1390] = 1; /* 1388: pointer.struct.asn1_string_st */
    	em[1391] = 557; em[1392] = 0; 
    em[1393] = 1; em[1394] = 8; em[1395] = 1; /* 1393: pointer.struct.asn1_string_st */
    	em[1396] = 557; em[1397] = 0; 
    em[1398] = 1; em[1399] = 8; em[1400] = 1; /* 1398: pointer.struct.asn1_string_st */
    	em[1401] = 557; em[1402] = 0; 
    em[1403] = 1; em[1404] = 8; em[1405] = 1; /* 1403: pointer.struct.asn1_string_st */
    	em[1406] = 557; em[1407] = 0; 
    em[1408] = 1; em[1409] = 8; em[1410] = 1; /* 1408: pointer.struct.asn1_string_st */
    	em[1411] = 557; em[1412] = 0; 
    em[1413] = 1; em[1414] = 8; em[1415] = 1; /* 1413: pointer.struct.asn1_string_st */
    	em[1416] = 557; em[1417] = 0; 
    em[1418] = 1; em[1419] = 8; em[1420] = 1; /* 1418: pointer.struct.asn1_string_st */
    	em[1421] = 557; em[1422] = 0; 
    em[1423] = 1; em[1424] = 8; em[1425] = 1; /* 1423: pointer.struct.asn1_string_st */
    	em[1426] = 557; em[1427] = 0; 
    em[1428] = 1; em[1429] = 8; em[1430] = 1; /* 1428: pointer.struct.asn1_string_st */
    	em[1431] = 557; em[1432] = 0; 
    em[1433] = 1; em[1434] = 8; em[1435] = 1; /* 1433: pointer.struct.asn1_string_st */
    	em[1436] = 557; em[1437] = 0; 
    em[1438] = 1; em[1439] = 8; em[1440] = 1; /* 1438: pointer.struct.ASN1_VALUE_st */
    	em[1441] = 1443; em[1442] = 0; 
    em[1443] = 0; em[1444] = 0; em[1445] = 0; /* 1443: struct.ASN1_VALUE_st */
    em[1446] = 0; em[1447] = 1; em[1448] = 0; /* 1446: char */
    em[1449] = 8884097; em[1450] = 8; em[1451] = 0; /* 1449: pointer.func */
    em[1452] = 8884097; em[1453] = 8; em[1454] = 0; /* 1452: pointer.func */
    em[1455] = 0; em[1456] = 112; em[1457] = 13; /* 1455: struct.rsa_meth_st */
    	em[1458] = 184; em[1459] = 0; 
    	em[1460] = 1452; em[1461] = 8; 
    	em[1462] = 1452; em[1463] = 16; 
    	em[1464] = 1452; em[1465] = 24; 
    	em[1466] = 1452; em[1467] = 32; 
    	em[1468] = 1484; em[1469] = 40; 
    	em[1470] = 1487; em[1471] = 48; 
    	em[1472] = 1449; em[1473] = 56; 
    	em[1474] = 1449; em[1475] = 64; 
    	em[1476] = 198; em[1477] = 80; 
    	em[1478] = 1286; em[1479] = 88; 
    	em[1480] = 1490; em[1481] = 96; 
    	em[1482] = 767; em[1483] = 104; 
    em[1484] = 8884097; em[1485] = 8; em[1486] = 0; /* 1484: pointer.func */
    em[1487] = 8884097; em[1488] = 8; em[1489] = 0; /* 1487: pointer.func */
    em[1490] = 8884097; em[1491] = 8; em[1492] = 0; /* 1490: pointer.func */
    em[1493] = 1; em[1494] = 8; em[1495] = 1; /* 1493: pointer.struct.rsa_meth_st */
    	em[1496] = 1455; em[1497] = 0; 
    em[1498] = 0; em[1499] = 168; em[1500] = 17; /* 1498: struct.rsa_st */
    	em[1501] = 1493; em[1502] = 16; 
    	em[1503] = 1535; em[1504] = 24; 
    	em[1505] = 1276; em[1506] = 32; 
    	em[1507] = 1276; em[1508] = 40; 
    	em[1509] = 1276; em[1510] = 48; 
    	em[1511] = 1276; em[1512] = 56; 
    	em[1513] = 1276; em[1514] = 64; 
    	em[1515] = 1276; em[1516] = 72; 
    	em[1517] = 1276; em[1518] = 80; 
    	em[1519] = 1276; em[1520] = 88; 
    	em[1521] = 1540; em[1522] = 96; 
    	em[1523] = 1554; em[1524] = 120; 
    	em[1525] = 1554; em[1526] = 128; 
    	em[1527] = 1554; em[1528] = 136; 
    	em[1529] = 198; em[1530] = 144; 
    	em[1531] = 1559; em[1532] = 152; 
    	em[1533] = 1559; em[1534] = 160; 
    em[1535] = 1; em[1536] = 8; em[1537] = 1; /* 1535: pointer.struct.engine_st */
    	em[1538] = 211; em[1539] = 0; 
    em[1540] = 0; em[1541] = 32; em[1542] = 2; /* 1540: struct.crypto_ex_data_st_fake */
    	em[1543] = 1547; em[1544] = 8; 
    	em[1545] = 157; em[1546] = 24; 
    em[1547] = 8884099; em[1548] = 8; em[1549] = 2; /* 1547: pointer_to_array_of_pointers_to_stack */
    	em[1550] = 154; em[1551] = 0; 
    	em[1552] = 91; em[1553] = 20; 
    em[1554] = 1; em[1555] = 8; em[1556] = 1; /* 1554: pointer.struct.bn_mont_ctx_st */
    	em[1557] = 743; em[1558] = 0; 
    em[1559] = 1; em[1560] = 8; em[1561] = 1; /* 1559: pointer.struct.bn_blinding_st */
    	em[1562] = 687; em[1563] = 0; 
    em[1564] = 8884101; em[1565] = 8; em[1566] = 6; /* 1564: union.union_of_evp_pkey_st */
    	em[1567] = 154; em[1568] = 0; 
    	em[1569] = 1579; em[1570] = 6; 
    	em[1571] = 607; em[1572] = 116; 
    	em[1573] = 1584; em[1574] = 28; 
    	em[1575] = 770; em[1576] = 408; 
    	em[1577] = 91; em[1578] = 0; 
    em[1579] = 1; em[1580] = 8; em[1581] = 1; /* 1579: pointer.struct.rsa_st */
    	em[1582] = 1498; em[1583] = 0; 
    em[1584] = 1; em[1585] = 8; em[1586] = 1; /* 1584: pointer.struct.dh_st */
    	em[1587] = 94; em[1588] = 0; 
    em[1589] = 1; em[1590] = 8; em[1591] = 1; /* 1589: pointer.struct.evp_pkey_asn1_method_st */
    	em[1592] = 1594; em[1593] = 0; 
    em[1594] = 0; em[1595] = 208; em[1596] = 24; /* 1594: struct.evp_pkey_asn1_method_st */
    	em[1597] = 198; em[1598] = 16; 
    	em[1599] = 198; em[1600] = 24; 
    	em[1601] = 1645; em[1602] = 32; 
    	em[1603] = 1648; em[1604] = 40; 
    	em[1605] = 1651; em[1606] = 48; 
    	em[1607] = 1654; em[1608] = 56; 
    	em[1609] = 1657; em[1610] = 64; 
    	em[1611] = 1660; em[1612] = 72; 
    	em[1613] = 1654; em[1614] = 80; 
    	em[1615] = 1663; em[1616] = 88; 
    	em[1617] = 1663; em[1618] = 96; 
    	em[1619] = 1666; em[1620] = 104; 
    	em[1621] = 1669; em[1622] = 112; 
    	em[1623] = 1663; em[1624] = 120; 
    	em[1625] = 1672; em[1626] = 128; 
    	em[1627] = 1651; em[1628] = 136; 
    	em[1629] = 1654; em[1630] = 144; 
    	em[1631] = 1675; em[1632] = 152; 
    	em[1633] = 1678; em[1634] = 160; 
    	em[1635] = 1681; em[1636] = 168; 
    	em[1637] = 1666; em[1638] = 176; 
    	em[1639] = 1669; em[1640] = 184; 
    	em[1641] = 1684; em[1642] = 192; 
    	em[1643] = 1687; em[1644] = 200; 
    em[1645] = 8884097; em[1646] = 8; em[1647] = 0; /* 1645: pointer.func */
    em[1648] = 8884097; em[1649] = 8; em[1650] = 0; /* 1648: pointer.func */
    em[1651] = 8884097; em[1652] = 8; em[1653] = 0; /* 1651: pointer.func */
    em[1654] = 8884097; em[1655] = 8; em[1656] = 0; /* 1654: pointer.func */
    em[1657] = 8884097; em[1658] = 8; em[1659] = 0; /* 1657: pointer.func */
    em[1660] = 8884097; em[1661] = 8; em[1662] = 0; /* 1660: pointer.func */
    em[1663] = 8884097; em[1664] = 8; em[1665] = 0; /* 1663: pointer.func */
    em[1666] = 8884097; em[1667] = 8; em[1668] = 0; /* 1666: pointer.func */
    em[1669] = 8884097; em[1670] = 8; em[1671] = 0; /* 1669: pointer.func */
    em[1672] = 8884097; em[1673] = 8; em[1674] = 0; /* 1672: pointer.func */
    em[1675] = 8884097; em[1676] = 8; em[1677] = 0; /* 1675: pointer.func */
    em[1678] = 8884097; em[1679] = 8; em[1680] = 0; /* 1678: pointer.func */
    em[1681] = 8884097; em[1682] = 8; em[1683] = 0; /* 1681: pointer.func */
    em[1684] = 8884097; em[1685] = 8; em[1686] = 0; /* 1684: pointer.func */
    em[1687] = 8884097; em[1688] = 8; em[1689] = 0; /* 1687: pointer.func */
    em[1690] = 0; em[1691] = 24; em[1692] = 2; /* 1690: struct.x509_attributes_st */
    	em[1693] = 1697; em[1694] = 0; 
    	em[1695] = 1711; em[1696] = 16; 
    em[1697] = 1; em[1698] = 8; em[1699] = 1; /* 1697: pointer.struct.asn1_object_st */
    	em[1700] = 1702; em[1701] = 0; 
    em[1702] = 0; em[1703] = 40; em[1704] = 3; /* 1702: struct.asn1_object_st */
    	em[1705] = 184; em[1706] = 0; 
    	em[1707] = 184; em[1708] = 8; 
    	em[1709] = 1281; em[1710] = 24; 
    em[1711] = 0; em[1712] = 8; em[1713] = 3; /* 1711: union.unknown */
    	em[1714] = 198; em[1715] = 0; 
    	em[1716] = 1720; em[1717] = 0; 
    	em[1718] = 1732; em[1719] = 0; 
    em[1720] = 1; em[1721] = 8; em[1722] = 1; /* 1720: pointer.struct.stack_st_ASN1_TYPE */
    	em[1723] = 1725; em[1724] = 0; 
    em[1725] = 0; em[1726] = 32; em[1727] = 2; /* 1725: struct.stack_st_fake_ASN1_TYPE */
    	em[1728] = 1289; em[1729] = 8; 
    	em[1730] = 157; em[1731] = 24; 
    em[1732] = 1; em[1733] = 8; em[1734] = 1; /* 1732: pointer.struct.asn1_type_st */
    	em[1735] = 1737; em[1736] = 0; 
    em[1737] = 0; em[1738] = 16; em[1739] = 1; /* 1737: struct.asn1_type_st */
    	em[1740] = 1742; em[1741] = 8; 
    em[1742] = 0; em[1743] = 8; em[1744] = 20; /* 1742: union.unknown */
    	em[1745] = 198; em[1746] = 0; 
    	em[1747] = 1785; em[1748] = 0; 
    	em[1749] = 1697; em[1750] = 0; 
    	em[1751] = 1790; em[1752] = 0; 
    	em[1753] = 71; em[1754] = 0; 
    	em[1755] = 66; em[1756] = 0; 
    	em[1757] = 61; em[1758] = 0; 
    	em[1759] = 1795; em[1760] = 0; 
    	em[1761] = 56; em[1762] = 0; 
    	em[1763] = 51; em[1764] = 0; 
    	em[1765] = 46; em[1766] = 0; 
    	em[1767] = 41; em[1768] = 0; 
    	em[1769] = 36; em[1770] = 0; 
    	em[1771] = 31; em[1772] = 0; 
    	em[1773] = 26; em[1774] = 0; 
    	em[1775] = 1800; em[1776] = 0; 
    	em[1777] = 8; em[1778] = 0; 
    	em[1779] = 1785; em[1780] = 0; 
    	em[1781] = 1785; em[1782] = 0; 
    	em[1783] = 0; em[1784] = 0; 
    em[1785] = 1; em[1786] = 8; em[1787] = 1; /* 1785: pointer.struct.asn1_string_st */
    	em[1788] = 13; em[1789] = 0; 
    em[1790] = 1; em[1791] = 8; em[1792] = 1; /* 1790: pointer.struct.asn1_string_st */
    	em[1793] = 13; em[1794] = 0; 
    em[1795] = 1; em[1796] = 8; em[1797] = 1; /* 1795: pointer.struct.asn1_string_st */
    	em[1798] = 13; em[1799] = 0; 
    em[1800] = 1; em[1801] = 8; em[1802] = 1; /* 1800: pointer.struct.asn1_string_st */
    	em[1803] = 13; em[1804] = 0; 
    em[1805] = 0; em[1806] = 56; em[1807] = 4; /* 1805: struct.evp_pkey_st */
    	em[1808] = 1589; em[1809] = 16; 
    	em[1810] = 206; em[1811] = 24; 
    	em[1812] = 1564; em[1813] = 32; 
    	em[1814] = 1816; em[1815] = 48; 
    em[1816] = 1; em[1817] = 8; em[1818] = 1; /* 1816: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[1819] = 1821; em[1820] = 0; 
    em[1821] = 0; em[1822] = 32; em[1823] = 2; /* 1821: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[1824] = 1828; em[1825] = 8; 
    	em[1826] = 157; em[1827] = 24; 
    em[1828] = 8884099; em[1829] = 8; em[1830] = 2; /* 1828: pointer_to_array_of_pointers_to_stack */
    	em[1831] = 1835; em[1832] = 0; 
    	em[1833] = 91; em[1834] = 20; 
    em[1835] = 0; em[1836] = 8; em[1837] = 1; /* 1835: pointer.X509_ATTRIBUTE */
    	em[1838] = 1840; em[1839] = 0; 
    em[1840] = 0; em[1841] = 0; em[1842] = 1; /* 1840: X509_ATTRIBUTE */
    	em[1843] = 1690; em[1844] = 0; 
    em[1845] = 1; em[1846] = 8; em[1847] = 1; /* 1845: pointer.struct.evp_pkey_st */
    	em[1848] = 1805; em[1849] = 0; 
    args_addr->arg_entity_index[0] = 1845;
    args_addr->ret_entity_index = 91;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    EVP_PKEY * new_arg_a = *((EVP_PKEY * *)new_args->args[0]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_EVP_PKEY_size)(EVP_PKEY *);
    orig_EVP_PKEY_size = dlsym(RTLD_NEXT, "EVP_PKEY_size");
    *new_ret_ptr = (*orig_EVP_PKEY_size)(new_arg_a);

    syscall(889);

    free(args_addr);

    return ret;
}

