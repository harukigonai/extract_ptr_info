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
    em[76] = 1; em[77] = 8; em[78] = 1; /* 76: pointer.struct.asn1_string_st */
    	em[79] = 13; em[80] = 0; 
    em[81] = 8884097; em[82] = 8; em[83] = 0; /* 81: pointer.func */
    em[84] = 8884097; em[85] = 8; em[86] = 0; /* 84: pointer.func */
    em[87] = 1; em[88] = 8; em[89] = 1; /* 87: pointer.struct.asn1_string_st */
    	em[90] = 92; em[91] = 0; 
    em[92] = 0; em[93] = 24; em[94] = 1; /* 92: struct.asn1_string_st */
    	em[95] = 18; em[96] = 8; 
    em[97] = 8884097; em[98] = 8; em[99] = 0; /* 97: pointer.func */
    em[100] = 0; em[101] = 72; em[102] = 8; /* 100: struct.dh_method */
    	em[103] = 119; em[104] = 0; 
    	em[105] = 124; em[106] = 8; 
    	em[107] = 127; em[108] = 16; 
    	em[109] = 130; em[110] = 24; 
    	em[111] = 124; em[112] = 32; 
    	em[113] = 124; em[114] = 40; 
    	em[115] = 133; em[116] = 56; 
    	em[117] = 138; em[118] = 64; 
    em[119] = 1; em[120] = 8; em[121] = 1; /* 119: pointer.char */
    	em[122] = 8884096; em[123] = 0; 
    em[124] = 8884097; em[125] = 8; em[126] = 0; /* 124: pointer.func */
    em[127] = 8884097; em[128] = 8; em[129] = 0; /* 127: pointer.func */
    em[130] = 8884097; em[131] = 8; em[132] = 0; /* 130: pointer.func */
    em[133] = 1; em[134] = 8; em[135] = 1; /* 133: pointer.char */
    	em[136] = 8884096; em[137] = 0; 
    em[138] = 8884097; em[139] = 8; em[140] = 0; /* 138: pointer.func */
    em[141] = 8884097; em[142] = 8; em[143] = 0; /* 141: pointer.func */
    em[144] = 8884097; em[145] = 8; em[146] = 0; /* 144: pointer.func */
    em[147] = 0; em[148] = 16; em[149] = 1; /* 147: struct.crypto_threadid_st */
    	em[150] = 152; em[151] = 0; 
    em[152] = 0; em[153] = 8; em[154] = 0; /* 152: pointer.void */
    em[155] = 0; em[156] = 32; em[157] = 3; /* 155: struct.ecdh_method */
    	em[158] = 119; em[159] = 0; 
    	em[160] = 164; em[161] = 8; 
    	em[162] = 133; em[163] = 24; 
    em[164] = 8884097; em[165] = 8; em[166] = 0; /* 164: pointer.func */
    em[167] = 1; em[168] = 8; em[169] = 1; /* 167: pointer.struct.asn1_string_st */
    	em[170] = 13; em[171] = 0; 
    em[172] = 8884097; em[173] = 8; em[174] = 0; /* 172: pointer.func */
    em[175] = 1; em[176] = 8; em[177] = 1; /* 175: pointer.struct.bignum_st */
    	em[178] = 180; em[179] = 0; 
    em[180] = 0; em[181] = 24; em[182] = 1; /* 180: struct.bignum_st */
    	em[183] = 185; em[184] = 0; 
    em[185] = 8884099; em[186] = 8; em[187] = 2; /* 185: pointer_to_array_of_pointers_to_stack */
    	em[188] = 192; em[189] = 0; 
    	em[190] = 195; em[191] = 12; 
    em[192] = 0; em[193] = 8; em[194] = 0; /* 192: long unsigned int */
    em[195] = 0; em[196] = 4; em[197] = 0; /* 195: int */
    em[198] = 0; em[199] = 96; em[200] = 11; /* 198: struct.dsa_method */
    	em[201] = 119; em[202] = 0; 
    	em[203] = 223; em[204] = 8; 
    	em[205] = 226; em[206] = 16; 
    	em[207] = 172; em[208] = 24; 
    	em[209] = 144; em[210] = 32; 
    	em[211] = 229; em[212] = 40; 
    	em[213] = 232; em[214] = 48; 
    	em[215] = 232; em[216] = 56; 
    	em[217] = 133; em[218] = 72; 
    	em[219] = 97; em[220] = 80; 
    	em[221] = 232; em[222] = 88; 
    em[223] = 8884097; em[224] = 8; em[225] = 0; /* 223: pointer.func */
    em[226] = 8884097; em[227] = 8; em[228] = 0; /* 226: pointer.func */
    em[229] = 8884097; em[230] = 8; em[231] = 0; /* 229: pointer.func */
    em[232] = 8884097; em[233] = 8; em[234] = 0; /* 232: pointer.func */
    em[235] = 8884097; em[236] = 8; em[237] = 0; /* 235: pointer.func */
    em[238] = 8884097; em[239] = 8; em[240] = 0; /* 238: pointer.func */
    em[241] = 1; em[242] = 8; em[243] = 1; /* 241: pointer.struct.dsa_method */
    	em[244] = 198; em[245] = 0; 
    em[246] = 1; em[247] = 8; em[248] = 1; /* 246: pointer.struct.engine_st */
    	em[249] = 251; em[250] = 0; 
    em[251] = 0; em[252] = 216; em[253] = 24; /* 251: struct.engine_st */
    	em[254] = 119; em[255] = 0; 
    	em[256] = 119; em[257] = 8; 
    	em[258] = 302; em[259] = 16; 
    	em[260] = 357; em[261] = 24; 
    	em[262] = 408; em[263] = 32; 
    	em[264] = 413; em[265] = 40; 
    	em[266] = 418; em[267] = 48; 
    	em[268] = 445; em[269] = 56; 
    	em[270] = 480; em[271] = 64; 
    	em[272] = 488; em[273] = 72; 
    	em[274] = 491; em[275] = 80; 
    	em[276] = 494; em[277] = 88; 
    	em[278] = 497; em[279] = 96; 
    	em[280] = 500; em[281] = 104; 
    	em[282] = 500; em[283] = 112; 
    	em[284] = 500; em[285] = 120; 
    	em[286] = 503; em[287] = 128; 
    	em[288] = 506; em[289] = 136; 
    	em[290] = 506; em[291] = 144; 
    	em[292] = 509; em[293] = 152; 
    	em[294] = 512; em[295] = 160; 
    	em[296] = 524; em[297] = 184; 
    	em[298] = 541; em[299] = 200; 
    	em[300] = 541; em[301] = 208; 
    em[302] = 1; em[303] = 8; em[304] = 1; /* 302: pointer.struct.rsa_meth_st */
    	em[305] = 307; em[306] = 0; 
    em[307] = 0; em[308] = 112; em[309] = 13; /* 307: struct.rsa_meth_st */
    	em[310] = 119; em[311] = 0; 
    	em[312] = 336; em[313] = 8; 
    	em[314] = 336; em[315] = 16; 
    	em[316] = 336; em[317] = 24; 
    	em[318] = 336; em[319] = 32; 
    	em[320] = 339; em[321] = 40; 
    	em[322] = 342; em[323] = 48; 
    	em[324] = 345; em[325] = 56; 
    	em[326] = 345; em[327] = 64; 
    	em[328] = 133; em[329] = 80; 
    	em[330] = 348; em[331] = 88; 
    	em[332] = 351; em[333] = 96; 
    	em[334] = 354; em[335] = 104; 
    em[336] = 8884097; em[337] = 8; em[338] = 0; /* 336: pointer.func */
    em[339] = 8884097; em[340] = 8; em[341] = 0; /* 339: pointer.func */
    em[342] = 8884097; em[343] = 8; em[344] = 0; /* 342: pointer.func */
    em[345] = 8884097; em[346] = 8; em[347] = 0; /* 345: pointer.func */
    em[348] = 8884097; em[349] = 8; em[350] = 0; /* 348: pointer.func */
    em[351] = 8884097; em[352] = 8; em[353] = 0; /* 351: pointer.func */
    em[354] = 8884097; em[355] = 8; em[356] = 0; /* 354: pointer.func */
    em[357] = 1; em[358] = 8; em[359] = 1; /* 357: pointer.struct.dsa_method */
    	em[360] = 362; em[361] = 0; 
    em[362] = 0; em[363] = 96; em[364] = 11; /* 362: struct.dsa_method */
    	em[365] = 119; em[366] = 0; 
    	em[367] = 387; em[368] = 8; 
    	em[369] = 390; em[370] = 16; 
    	em[371] = 393; em[372] = 24; 
    	em[373] = 396; em[374] = 32; 
    	em[375] = 399; em[376] = 40; 
    	em[377] = 402; em[378] = 48; 
    	em[379] = 402; em[380] = 56; 
    	em[381] = 133; em[382] = 72; 
    	em[383] = 405; em[384] = 80; 
    	em[385] = 402; em[386] = 88; 
    em[387] = 8884097; em[388] = 8; em[389] = 0; /* 387: pointer.func */
    em[390] = 8884097; em[391] = 8; em[392] = 0; /* 390: pointer.func */
    em[393] = 8884097; em[394] = 8; em[395] = 0; /* 393: pointer.func */
    em[396] = 8884097; em[397] = 8; em[398] = 0; /* 396: pointer.func */
    em[399] = 8884097; em[400] = 8; em[401] = 0; /* 399: pointer.func */
    em[402] = 8884097; em[403] = 8; em[404] = 0; /* 402: pointer.func */
    em[405] = 8884097; em[406] = 8; em[407] = 0; /* 405: pointer.func */
    em[408] = 1; em[409] = 8; em[410] = 1; /* 408: pointer.struct.dh_method */
    	em[411] = 100; em[412] = 0; 
    em[413] = 1; em[414] = 8; em[415] = 1; /* 413: pointer.struct.ecdh_method */
    	em[416] = 155; em[417] = 0; 
    em[418] = 1; em[419] = 8; em[420] = 1; /* 418: pointer.struct.ecdsa_method */
    	em[421] = 423; em[422] = 0; 
    em[423] = 0; em[424] = 48; em[425] = 5; /* 423: struct.ecdsa_method */
    	em[426] = 119; em[427] = 0; 
    	em[428] = 436; em[429] = 8; 
    	em[430] = 439; em[431] = 16; 
    	em[432] = 442; em[433] = 24; 
    	em[434] = 133; em[435] = 40; 
    em[436] = 8884097; em[437] = 8; em[438] = 0; /* 436: pointer.func */
    em[439] = 8884097; em[440] = 8; em[441] = 0; /* 439: pointer.func */
    em[442] = 8884097; em[443] = 8; em[444] = 0; /* 442: pointer.func */
    em[445] = 1; em[446] = 8; em[447] = 1; /* 445: pointer.struct.rand_meth_st */
    	em[448] = 450; em[449] = 0; 
    em[450] = 0; em[451] = 48; em[452] = 6; /* 450: struct.rand_meth_st */
    	em[453] = 465; em[454] = 0; 
    	em[455] = 468; em[456] = 8; 
    	em[457] = 471; em[458] = 16; 
    	em[459] = 474; em[460] = 24; 
    	em[461] = 468; em[462] = 32; 
    	em[463] = 477; em[464] = 40; 
    em[465] = 8884097; em[466] = 8; em[467] = 0; /* 465: pointer.func */
    em[468] = 8884097; em[469] = 8; em[470] = 0; /* 468: pointer.func */
    em[471] = 8884097; em[472] = 8; em[473] = 0; /* 471: pointer.func */
    em[474] = 8884097; em[475] = 8; em[476] = 0; /* 474: pointer.func */
    em[477] = 8884097; em[478] = 8; em[479] = 0; /* 477: pointer.func */
    em[480] = 1; em[481] = 8; em[482] = 1; /* 480: pointer.struct.store_method_st */
    	em[483] = 485; em[484] = 0; 
    em[485] = 0; em[486] = 0; em[487] = 0; /* 485: struct.store_method_st */
    em[488] = 8884097; em[489] = 8; em[490] = 0; /* 488: pointer.func */
    em[491] = 8884097; em[492] = 8; em[493] = 0; /* 491: pointer.func */
    em[494] = 8884097; em[495] = 8; em[496] = 0; /* 494: pointer.func */
    em[497] = 8884097; em[498] = 8; em[499] = 0; /* 497: pointer.func */
    em[500] = 8884097; em[501] = 8; em[502] = 0; /* 500: pointer.func */
    em[503] = 8884097; em[504] = 8; em[505] = 0; /* 503: pointer.func */
    em[506] = 8884097; em[507] = 8; em[508] = 0; /* 506: pointer.func */
    em[509] = 8884097; em[510] = 8; em[511] = 0; /* 509: pointer.func */
    em[512] = 1; em[513] = 8; em[514] = 1; /* 512: pointer.struct.ENGINE_CMD_DEFN_st */
    	em[515] = 517; em[516] = 0; 
    em[517] = 0; em[518] = 32; em[519] = 2; /* 517: struct.ENGINE_CMD_DEFN_st */
    	em[520] = 119; em[521] = 8; 
    	em[522] = 119; em[523] = 16; 
    em[524] = 0; em[525] = 32; em[526] = 2; /* 524: struct.crypto_ex_data_st_fake */
    	em[527] = 531; em[528] = 8; 
    	em[529] = 538; em[530] = 24; 
    em[531] = 8884099; em[532] = 8; em[533] = 2; /* 531: pointer_to_array_of_pointers_to_stack */
    	em[534] = 152; em[535] = 0; 
    	em[536] = 195; em[537] = 20; 
    em[538] = 8884097; em[539] = 8; em[540] = 0; /* 538: pointer.func */
    em[541] = 1; em[542] = 8; em[543] = 1; /* 541: pointer.struct.engine_st */
    	em[544] = 251; em[545] = 0; 
    em[546] = 8884097; em[547] = 8; em[548] = 0; /* 546: pointer.func */
    em[549] = 8884097; em[550] = 8; em[551] = 0; /* 549: pointer.func */
    em[552] = 8884097; em[553] = 8; em[554] = 0; /* 552: pointer.func */
    em[555] = 8884097; em[556] = 8; em[557] = 0; /* 555: pointer.func */
    em[558] = 8884097; em[559] = 8; em[560] = 0; /* 558: pointer.func */
    em[561] = 0; em[562] = 112; em[563] = 13; /* 561: struct.rsa_meth_st */
    	em[564] = 119; em[565] = 0; 
    	em[566] = 555; em[567] = 8; 
    	em[568] = 555; em[569] = 16; 
    	em[570] = 555; em[571] = 24; 
    	em[572] = 555; em[573] = 32; 
    	em[574] = 552; em[575] = 40; 
    	em[576] = 549; em[577] = 48; 
    	em[578] = 590; em[579] = 56; 
    	em[580] = 590; em[581] = 64; 
    	em[582] = 133; em[583] = 80; 
    	em[584] = 593; em[585] = 88; 
    	em[586] = 596; em[587] = 96; 
    	em[588] = 546; em[589] = 104; 
    em[590] = 8884097; em[591] = 8; em[592] = 0; /* 590: pointer.func */
    em[593] = 8884097; em[594] = 8; em[595] = 0; /* 593: pointer.func */
    em[596] = 8884097; em[597] = 8; em[598] = 0; /* 596: pointer.func */
    em[599] = 1; em[600] = 8; em[601] = 1; /* 599: pointer.struct.rsa_st */
    	em[602] = 604; em[603] = 0; 
    em[604] = 0; em[605] = 168; em[606] = 17; /* 604: struct.rsa_st */
    	em[607] = 641; em[608] = 16; 
    	em[609] = 246; em[610] = 24; 
    	em[611] = 646; em[612] = 32; 
    	em[613] = 646; em[614] = 40; 
    	em[615] = 646; em[616] = 48; 
    	em[617] = 646; em[618] = 56; 
    	em[619] = 646; em[620] = 64; 
    	em[621] = 646; em[622] = 72; 
    	em[623] = 646; em[624] = 80; 
    	em[625] = 646; em[626] = 88; 
    	em[627] = 663; em[628] = 96; 
    	em[629] = 677; em[630] = 120; 
    	em[631] = 677; em[632] = 128; 
    	em[633] = 677; em[634] = 136; 
    	em[635] = 133; em[636] = 144; 
    	em[637] = 691; em[638] = 152; 
    	em[639] = 691; em[640] = 160; 
    em[641] = 1; em[642] = 8; em[643] = 1; /* 641: pointer.struct.rsa_meth_st */
    	em[644] = 561; em[645] = 0; 
    em[646] = 1; em[647] = 8; em[648] = 1; /* 646: pointer.struct.bignum_st */
    	em[649] = 651; em[650] = 0; 
    em[651] = 0; em[652] = 24; em[653] = 1; /* 651: struct.bignum_st */
    	em[654] = 656; em[655] = 0; 
    em[656] = 8884099; em[657] = 8; em[658] = 2; /* 656: pointer_to_array_of_pointers_to_stack */
    	em[659] = 192; em[660] = 0; 
    	em[661] = 195; em[662] = 12; 
    em[663] = 0; em[664] = 32; em[665] = 2; /* 663: struct.crypto_ex_data_st_fake */
    	em[666] = 670; em[667] = 8; 
    	em[668] = 538; em[669] = 24; 
    em[670] = 8884099; em[671] = 8; em[672] = 2; /* 670: pointer_to_array_of_pointers_to_stack */
    	em[673] = 152; em[674] = 0; 
    	em[675] = 195; em[676] = 20; 
    em[677] = 1; em[678] = 8; em[679] = 1; /* 677: pointer.struct.bn_mont_ctx_st */
    	em[680] = 682; em[681] = 0; 
    em[682] = 0; em[683] = 96; em[684] = 3; /* 682: struct.bn_mont_ctx_st */
    	em[685] = 651; em[686] = 8; 
    	em[687] = 651; em[688] = 32; 
    	em[689] = 651; em[690] = 56; 
    em[691] = 1; em[692] = 8; em[693] = 1; /* 691: pointer.struct.bn_blinding_st */
    	em[694] = 696; em[695] = 0; 
    em[696] = 0; em[697] = 88; em[698] = 7; /* 696: struct.bn_blinding_st */
    	em[699] = 713; em[700] = 0; 
    	em[701] = 713; em[702] = 8; 
    	em[703] = 713; em[704] = 16; 
    	em[705] = 713; em[706] = 24; 
    	em[707] = 147; em[708] = 40; 
    	em[709] = 730; em[710] = 72; 
    	em[711] = 235; em[712] = 80; 
    em[713] = 1; em[714] = 8; em[715] = 1; /* 713: pointer.struct.bignum_st */
    	em[716] = 718; em[717] = 0; 
    em[718] = 0; em[719] = 24; em[720] = 1; /* 718: struct.bignum_st */
    	em[721] = 723; em[722] = 0; 
    em[723] = 8884099; em[724] = 8; em[725] = 2; /* 723: pointer_to_array_of_pointers_to_stack */
    	em[726] = 192; em[727] = 0; 
    	em[728] = 195; em[729] = 12; 
    em[730] = 1; em[731] = 8; em[732] = 1; /* 730: pointer.struct.bn_mont_ctx_st */
    	em[733] = 735; em[734] = 0; 
    em[735] = 0; em[736] = 96; em[737] = 3; /* 735: struct.bn_mont_ctx_st */
    	em[738] = 718; em[739] = 8; 
    	em[740] = 718; em[741] = 32; 
    	em[742] = 718; em[743] = 56; 
    em[744] = 0; em[745] = 8; em[746] = 5; /* 744: union.unknown */
    	em[747] = 133; em[748] = 0; 
    	em[749] = 599; em[750] = 0; 
    	em[751] = 757; em[752] = 0; 
    	em[753] = 837; em[754] = 0; 
    	em[755] = 935; em[756] = 0; 
    em[757] = 1; em[758] = 8; em[759] = 1; /* 757: pointer.struct.dsa_st */
    	em[760] = 762; em[761] = 0; 
    em[762] = 0; em[763] = 136; em[764] = 11; /* 762: struct.dsa_st */
    	em[765] = 787; em[766] = 24; 
    	em[767] = 787; em[768] = 32; 
    	em[769] = 787; em[770] = 40; 
    	em[771] = 787; em[772] = 48; 
    	em[773] = 787; em[774] = 56; 
    	em[775] = 787; em[776] = 64; 
    	em[777] = 787; em[778] = 72; 
    	em[779] = 804; em[780] = 88; 
    	em[781] = 818; em[782] = 104; 
    	em[783] = 241; em[784] = 120; 
    	em[785] = 832; em[786] = 128; 
    em[787] = 1; em[788] = 8; em[789] = 1; /* 787: pointer.struct.bignum_st */
    	em[790] = 792; em[791] = 0; 
    em[792] = 0; em[793] = 24; em[794] = 1; /* 792: struct.bignum_st */
    	em[795] = 797; em[796] = 0; 
    em[797] = 8884099; em[798] = 8; em[799] = 2; /* 797: pointer_to_array_of_pointers_to_stack */
    	em[800] = 192; em[801] = 0; 
    	em[802] = 195; em[803] = 12; 
    em[804] = 1; em[805] = 8; em[806] = 1; /* 804: pointer.struct.bn_mont_ctx_st */
    	em[807] = 809; em[808] = 0; 
    em[809] = 0; em[810] = 96; em[811] = 3; /* 809: struct.bn_mont_ctx_st */
    	em[812] = 792; em[813] = 8; 
    	em[814] = 792; em[815] = 32; 
    	em[816] = 792; em[817] = 56; 
    em[818] = 0; em[819] = 32; em[820] = 2; /* 818: struct.crypto_ex_data_st_fake */
    	em[821] = 825; em[822] = 8; 
    	em[823] = 538; em[824] = 24; 
    em[825] = 8884099; em[826] = 8; em[827] = 2; /* 825: pointer_to_array_of_pointers_to_stack */
    	em[828] = 152; em[829] = 0; 
    	em[830] = 195; em[831] = 20; 
    em[832] = 1; em[833] = 8; em[834] = 1; /* 832: pointer.struct.engine_st */
    	em[835] = 251; em[836] = 0; 
    em[837] = 1; em[838] = 8; em[839] = 1; /* 837: pointer.struct.dh_st */
    	em[840] = 842; em[841] = 0; 
    em[842] = 0; em[843] = 144; em[844] = 12; /* 842: struct.dh_st */
    	em[845] = 175; em[846] = 8; 
    	em[847] = 175; em[848] = 16; 
    	em[849] = 175; em[850] = 32; 
    	em[851] = 175; em[852] = 40; 
    	em[853] = 869; em[854] = 56; 
    	em[855] = 175; em[856] = 64; 
    	em[857] = 175; em[858] = 72; 
    	em[859] = 18; em[860] = 80; 
    	em[861] = 175; em[862] = 96; 
    	em[863] = 883; em[864] = 112; 
    	em[865] = 897; em[866] = 128; 
    	em[867] = 930; em[868] = 136; 
    em[869] = 1; em[870] = 8; em[871] = 1; /* 869: pointer.struct.bn_mont_ctx_st */
    	em[872] = 874; em[873] = 0; 
    em[874] = 0; em[875] = 96; em[876] = 3; /* 874: struct.bn_mont_ctx_st */
    	em[877] = 180; em[878] = 8; 
    	em[879] = 180; em[880] = 32; 
    	em[881] = 180; em[882] = 56; 
    em[883] = 0; em[884] = 32; em[885] = 2; /* 883: struct.crypto_ex_data_st_fake */
    	em[886] = 890; em[887] = 8; 
    	em[888] = 538; em[889] = 24; 
    em[890] = 8884099; em[891] = 8; em[892] = 2; /* 890: pointer_to_array_of_pointers_to_stack */
    	em[893] = 152; em[894] = 0; 
    	em[895] = 195; em[896] = 20; 
    em[897] = 1; em[898] = 8; em[899] = 1; /* 897: pointer.struct.dh_method */
    	em[900] = 902; em[901] = 0; 
    em[902] = 0; em[903] = 72; em[904] = 8; /* 902: struct.dh_method */
    	em[905] = 119; em[906] = 0; 
    	em[907] = 921; em[908] = 8; 
    	em[909] = 924; em[910] = 16; 
    	em[911] = 141; em[912] = 24; 
    	em[913] = 921; em[914] = 32; 
    	em[915] = 921; em[916] = 40; 
    	em[917] = 133; em[918] = 56; 
    	em[919] = 927; em[920] = 64; 
    em[921] = 8884097; em[922] = 8; em[923] = 0; /* 921: pointer.func */
    em[924] = 8884097; em[925] = 8; em[926] = 0; /* 924: pointer.func */
    em[927] = 8884097; em[928] = 8; em[929] = 0; /* 927: pointer.func */
    em[930] = 1; em[931] = 8; em[932] = 1; /* 930: pointer.struct.engine_st */
    	em[933] = 251; em[934] = 0; 
    em[935] = 1; em[936] = 8; em[937] = 1; /* 935: pointer.struct.ec_key_st */
    	em[938] = 940; em[939] = 0; 
    em[940] = 0; em[941] = 56; em[942] = 4; /* 940: struct.ec_key_st */
    	em[943] = 951; em[944] = 8; 
    	em[945] = 1390; em[946] = 16; 
    	em[947] = 1395; em[948] = 24; 
    	em[949] = 1412; em[950] = 48; 
    em[951] = 1; em[952] = 8; em[953] = 1; /* 951: pointer.struct.ec_group_st */
    	em[954] = 956; em[955] = 0; 
    em[956] = 0; em[957] = 232; em[958] = 12; /* 956: struct.ec_group_st */
    	em[959] = 983; em[960] = 0; 
    	em[961] = 1146; em[962] = 8; 
    	em[963] = 1346; em[964] = 16; 
    	em[965] = 1346; em[966] = 40; 
    	em[967] = 18; em[968] = 80; 
    	em[969] = 1358; em[970] = 96; 
    	em[971] = 1346; em[972] = 104; 
    	em[973] = 1346; em[974] = 152; 
    	em[975] = 1346; em[976] = 176; 
    	em[977] = 152; em[978] = 208; 
    	em[979] = 152; em[980] = 216; 
    	em[981] = 1387; em[982] = 224; 
    em[983] = 1; em[984] = 8; em[985] = 1; /* 983: pointer.struct.ec_method_st */
    	em[986] = 988; em[987] = 0; 
    em[988] = 0; em[989] = 304; em[990] = 37; /* 988: struct.ec_method_st */
    	em[991] = 1065; em[992] = 8; 
    	em[993] = 238; em[994] = 16; 
    	em[995] = 238; em[996] = 24; 
    	em[997] = 1068; em[998] = 32; 
    	em[999] = 1071; em[1000] = 40; 
    	em[1001] = 1074; em[1002] = 48; 
    	em[1003] = 1077; em[1004] = 56; 
    	em[1005] = 1080; em[1006] = 64; 
    	em[1007] = 1083; em[1008] = 72; 
    	em[1009] = 1086; em[1010] = 80; 
    	em[1011] = 1086; em[1012] = 88; 
    	em[1013] = 1089; em[1014] = 96; 
    	em[1015] = 1092; em[1016] = 104; 
    	em[1017] = 1095; em[1018] = 112; 
    	em[1019] = 1098; em[1020] = 120; 
    	em[1021] = 1101; em[1022] = 128; 
    	em[1023] = 1104; em[1024] = 136; 
    	em[1025] = 1107; em[1026] = 144; 
    	em[1027] = 1110; em[1028] = 152; 
    	em[1029] = 1113; em[1030] = 160; 
    	em[1031] = 1116; em[1032] = 168; 
    	em[1033] = 81; em[1034] = 176; 
    	em[1035] = 1119; em[1036] = 184; 
    	em[1037] = 1122; em[1038] = 192; 
    	em[1039] = 1125; em[1040] = 200; 
    	em[1041] = 1128; em[1042] = 208; 
    	em[1043] = 1119; em[1044] = 216; 
    	em[1045] = 1131; em[1046] = 224; 
    	em[1047] = 1134; em[1048] = 232; 
    	em[1049] = 558; em[1050] = 240; 
    	em[1051] = 1077; em[1052] = 248; 
    	em[1053] = 1137; em[1054] = 256; 
    	em[1055] = 1140; em[1056] = 264; 
    	em[1057] = 1137; em[1058] = 272; 
    	em[1059] = 1140; em[1060] = 280; 
    	em[1061] = 1140; em[1062] = 288; 
    	em[1063] = 1143; em[1064] = 296; 
    em[1065] = 8884097; em[1066] = 8; em[1067] = 0; /* 1065: pointer.func */
    em[1068] = 8884097; em[1069] = 8; em[1070] = 0; /* 1068: pointer.func */
    em[1071] = 8884097; em[1072] = 8; em[1073] = 0; /* 1071: pointer.func */
    em[1074] = 8884097; em[1075] = 8; em[1076] = 0; /* 1074: pointer.func */
    em[1077] = 8884097; em[1078] = 8; em[1079] = 0; /* 1077: pointer.func */
    em[1080] = 8884097; em[1081] = 8; em[1082] = 0; /* 1080: pointer.func */
    em[1083] = 8884097; em[1084] = 8; em[1085] = 0; /* 1083: pointer.func */
    em[1086] = 8884097; em[1087] = 8; em[1088] = 0; /* 1086: pointer.func */
    em[1089] = 8884097; em[1090] = 8; em[1091] = 0; /* 1089: pointer.func */
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
    em[1146] = 1; em[1147] = 8; em[1148] = 1; /* 1146: pointer.struct.ec_point_st */
    	em[1149] = 1151; em[1150] = 0; 
    em[1151] = 0; em[1152] = 88; em[1153] = 4; /* 1151: struct.ec_point_st */
    	em[1154] = 1162; em[1155] = 0; 
    	em[1156] = 1334; em[1157] = 8; 
    	em[1158] = 1334; em[1159] = 32; 
    	em[1160] = 1334; em[1161] = 56; 
    em[1162] = 1; em[1163] = 8; em[1164] = 1; /* 1162: pointer.struct.ec_method_st */
    	em[1165] = 1167; em[1166] = 0; 
    em[1167] = 0; em[1168] = 304; em[1169] = 37; /* 1167: struct.ec_method_st */
    	em[1170] = 1244; em[1171] = 8; 
    	em[1172] = 1247; em[1173] = 16; 
    	em[1174] = 1247; em[1175] = 24; 
    	em[1176] = 1250; em[1177] = 32; 
    	em[1178] = 1253; em[1179] = 40; 
    	em[1180] = 1256; em[1181] = 48; 
    	em[1182] = 1259; em[1183] = 56; 
    	em[1184] = 1262; em[1185] = 64; 
    	em[1186] = 1265; em[1187] = 72; 
    	em[1188] = 1268; em[1189] = 80; 
    	em[1190] = 1268; em[1191] = 88; 
    	em[1192] = 1271; em[1193] = 96; 
    	em[1194] = 1274; em[1195] = 104; 
    	em[1196] = 1277; em[1197] = 112; 
    	em[1198] = 1280; em[1199] = 120; 
    	em[1200] = 1283; em[1201] = 128; 
    	em[1202] = 1286; em[1203] = 136; 
    	em[1204] = 1289; em[1205] = 144; 
    	em[1206] = 1292; em[1207] = 152; 
    	em[1208] = 1295; em[1209] = 160; 
    	em[1210] = 1298; em[1211] = 168; 
    	em[1212] = 1301; em[1213] = 176; 
    	em[1214] = 1304; em[1215] = 184; 
    	em[1216] = 1307; em[1217] = 192; 
    	em[1218] = 1310; em[1219] = 200; 
    	em[1220] = 1313; em[1221] = 208; 
    	em[1222] = 1304; em[1223] = 216; 
    	em[1224] = 1316; em[1225] = 224; 
    	em[1226] = 1319; em[1227] = 232; 
    	em[1228] = 1322; em[1229] = 240; 
    	em[1230] = 1259; em[1231] = 248; 
    	em[1232] = 1325; em[1233] = 256; 
    	em[1234] = 1328; em[1235] = 264; 
    	em[1236] = 1325; em[1237] = 272; 
    	em[1238] = 1328; em[1239] = 280; 
    	em[1240] = 1328; em[1241] = 288; 
    	em[1242] = 1331; em[1243] = 296; 
    em[1244] = 8884097; em[1245] = 8; em[1246] = 0; /* 1244: pointer.func */
    em[1247] = 8884097; em[1248] = 8; em[1249] = 0; /* 1247: pointer.func */
    em[1250] = 8884097; em[1251] = 8; em[1252] = 0; /* 1250: pointer.func */
    em[1253] = 8884097; em[1254] = 8; em[1255] = 0; /* 1253: pointer.func */
    em[1256] = 8884097; em[1257] = 8; em[1258] = 0; /* 1256: pointer.func */
    em[1259] = 8884097; em[1260] = 8; em[1261] = 0; /* 1259: pointer.func */
    em[1262] = 8884097; em[1263] = 8; em[1264] = 0; /* 1262: pointer.func */
    em[1265] = 8884097; em[1266] = 8; em[1267] = 0; /* 1265: pointer.func */
    em[1268] = 8884097; em[1269] = 8; em[1270] = 0; /* 1268: pointer.func */
    em[1271] = 8884097; em[1272] = 8; em[1273] = 0; /* 1271: pointer.func */
    em[1274] = 8884097; em[1275] = 8; em[1276] = 0; /* 1274: pointer.func */
    em[1277] = 8884097; em[1278] = 8; em[1279] = 0; /* 1277: pointer.func */
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
    em[1334] = 0; em[1335] = 24; em[1336] = 1; /* 1334: struct.bignum_st */
    	em[1337] = 1339; em[1338] = 0; 
    em[1339] = 8884099; em[1340] = 8; em[1341] = 2; /* 1339: pointer_to_array_of_pointers_to_stack */
    	em[1342] = 192; em[1343] = 0; 
    	em[1344] = 195; em[1345] = 12; 
    em[1346] = 0; em[1347] = 24; em[1348] = 1; /* 1346: struct.bignum_st */
    	em[1349] = 1351; em[1350] = 0; 
    em[1351] = 8884099; em[1352] = 8; em[1353] = 2; /* 1351: pointer_to_array_of_pointers_to_stack */
    	em[1354] = 192; em[1355] = 0; 
    	em[1356] = 195; em[1357] = 12; 
    em[1358] = 1; em[1359] = 8; em[1360] = 1; /* 1358: pointer.struct.ec_extra_data_st */
    	em[1361] = 1363; em[1362] = 0; 
    em[1363] = 0; em[1364] = 40; em[1365] = 5; /* 1363: struct.ec_extra_data_st */
    	em[1366] = 1376; em[1367] = 0; 
    	em[1368] = 152; em[1369] = 8; 
    	em[1370] = 1381; em[1371] = 16; 
    	em[1372] = 1384; em[1373] = 24; 
    	em[1374] = 1384; em[1375] = 32; 
    em[1376] = 1; em[1377] = 8; em[1378] = 1; /* 1376: pointer.struct.ec_extra_data_st */
    	em[1379] = 1363; em[1380] = 0; 
    em[1381] = 8884097; em[1382] = 8; em[1383] = 0; /* 1381: pointer.func */
    em[1384] = 8884097; em[1385] = 8; em[1386] = 0; /* 1384: pointer.func */
    em[1387] = 8884097; em[1388] = 8; em[1389] = 0; /* 1387: pointer.func */
    em[1390] = 1; em[1391] = 8; em[1392] = 1; /* 1390: pointer.struct.ec_point_st */
    	em[1393] = 1151; em[1394] = 0; 
    em[1395] = 1; em[1396] = 8; em[1397] = 1; /* 1395: pointer.struct.bignum_st */
    	em[1398] = 1400; em[1399] = 0; 
    em[1400] = 0; em[1401] = 24; em[1402] = 1; /* 1400: struct.bignum_st */
    	em[1403] = 1405; em[1404] = 0; 
    em[1405] = 8884099; em[1406] = 8; em[1407] = 2; /* 1405: pointer_to_array_of_pointers_to_stack */
    	em[1408] = 192; em[1409] = 0; 
    	em[1410] = 195; em[1411] = 12; 
    em[1412] = 1; em[1413] = 8; em[1414] = 1; /* 1412: pointer.struct.ec_extra_data_st */
    	em[1415] = 1417; em[1416] = 0; 
    em[1417] = 0; em[1418] = 40; em[1419] = 5; /* 1417: struct.ec_extra_data_st */
    	em[1420] = 1430; em[1421] = 0; 
    	em[1422] = 152; em[1423] = 8; 
    	em[1424] = 1381; em[1425] = 16; 
    	em[1426] = 1384; em[1427] = 24; 
    	em[1428] = 1384; em[1429] = 32; 
    em[1430] = 1; em[1431] = 8; em[1432] = 1; /* 1430: pointer.struct.ec_extra_data_st */
    	em[1433] = 1417; em[1434] = 0; 
    em[1435] = 0; em[1436] = 16; em[1437] = 1; /* 1435: struct.asn1_type_st */
    	em[1438] = 1440; em[1439] = 8; 
    em[1440] = 0; em[1441] = 8; em[1442] = 20; /* 1440: union.unknown */
    	em[1443] = 133; em[1444] = 0; 
    	em[1445] = 76; em[1446] = 0; 
    	em[1447] = 1483; em[1448] = 0; 
    	em[1449] = 1502; em[1450] = 0; 
    	em[1451] = 71; em[1452] = 0; 
    	em[1453] = 66; em[1454] = 0; 
    	em[1455] = 61; em[1456] = 0; 
    	em[1457] = 56; em[1458] = 0; 
    	em[1459] = 51; em[1460] = 0; 
    	em[1461] = 46; em[1462] = 0; 
    	em[1463] = 41; em[1464] = 0; 
    	em[1465] = 36; em[1466] = 0; 
    	em[1467] = 31; em[1468] = 0; 
    	em[1469] = 26; em[1470] = 0; 
    	em[1471] = 167; em[1472] = 0; 
    	em[1473] = 1507; em[1474] = 0; 
    	em[1475] = 8; em[1476] = 0; 
    	em[1477] = 76; em[1478] = 0; 
    	em[1479] = 76; em[1480] = 0; 
    	em[1481] = 0; em[1482] = 0; 
    em[1483] = 1; em[1484] = 8; em[1485] = 1; /* 1483: pointer.struct.asn1_object_st */
    	em[1486] = 1488; em[1487] = 0; 
    em[1488] = 0; em[1489] = 40; em[1490] = 3; /* 1488: struct.asn1_object_st */
    	em[1491] = 119; em[1492] = 0; 
    	em[1493] = 119; em[1494] = 8; 
    	em[1495] = 1497; em[1496] = 24; 
    em[1497] = 1; em[1498] = 8; em[1499] = 1; /* 1497: pointer.unsigned char */
    	em[1500] = 23; em[1501] = 0; 
    em[1502] = 1; em[1503] = 8; em[1504] = 1; /* 1502: pointer.struct.asn1_string_st */
    	em[1505] = 13; em[1506] = 0; 
    em[1507] = 1; em[1508] = 8; em[1509] = 1; /* 1507: pointer.struct.asn1_string_st */
    	em[1510] = 13; em[1511] = 0; 
    em[1512] = 1; em[1513] = 8; em[1514] = 1; /* 1512: pointer.struct.evp_pkey_asn1_method_st */
    	em[1515] = 1517; em[1516] = 0; 
    em[1517] = 0; em[1518] = 208; em[1519] = 24; /* 1517: struct.evp_pkey_asn1_method_st */
    	em[1520] = 133; em[1521] = 16; 
    	em[1522] = 133; em[1523] = 24; 
    	em[1524] = 84; em[1525] = 32; 
    	em[1526] = 1568; em[1527] = 40; 
    	em[1528] = 1571; em[1529] = 48; 
    	em[1530] = 1574; em[1531] = 56; 
    	em[1532] = 1577; em[1533] = 64; 
    	em[1534] = 1580; em[1535] = 72; 
    	em[1536] = 1574; em[1537] = 80; 
    	em[1538] = 1583; em[1539] = 88; 
    	em[1540] = 1583; em[1541] = 96; 
    	em[1542] = 1586; em[1543] = 104; 
    	em[1544] = 1589; em[1545] = 112; 
    	em[1546] = 1583; em[1547] = 120; 
    	em[1548] = 1592; em[1549] = 128; 
    	em[1550] = 1571; em[1551] = 136; 
    	em[1552] = 1574; em[1553] = 144; 
    	em[1554] = 1595; em[1555] = 152; 
    	em[1556] = 1598; em[1557] = 160; 
    	em[1558] = 1601; em[1559] = 168; 
    	em[1560] = 1586; em[1561] = 176; 
    	em[1562] = 1589; em[1563] = 184; 
    	em[1564] = 1604; em[1565] = 192; 
    	em[1566] = 1607; em[1567] = 200; 
    em[1568] = 8884097; em[1569] = 8; em[1570] = 0; /* 1568: pointer.func */
    em[1571] = 8884097; em[1572] = 8; em[1573] = 0; /* 1571: pointer.func */
    em[1574] = 8884097; em[1575] = 8; em[1576] = 0; /* 1574: pointer.func */
    em[1577] = 8884097; em[1578] = 8; em[1579] = 0; /* 1577: pointer.func */
    em[1580] = 8884097; em[1581] = 8; em[1582] = 0; /* 1580: pointer.func */
    em[1583] = 8884097; em[1584] = 8; em[1585] = 0; /* 1583: pointer.func */
    em[1586] = 8884097; em[1587] = 8; em[1588] = 0; /* 1586: pointer.func */
    em[1589] = 8884097; em[1590] = 8; em[1591] = 0; /* 1589: pointer.func */
    em[1592] = 8884097; em[1593] = 8; em[1594] = 0; /* 1592: pointer.func */
    em[1595] = 8884097; em[1596] = 8; em[1597] = 0; /* 1595: pointer.func */
    em[1598] = 8884097; em[1599] = 8; em[1600] = 0; /* 1598: pointer.func */
    em[1601] = 8884097; em[1602] = 8; em[1603] = 0; /* 1601: pointer.func */
    em[1604] = 8884097; em[1605] = 8; em[1606] = 0; /* 1604: pointer.func */
    em[1607] = 8884097; em[1608] = 8; em[1609] = 0; /* 1607: pointer.func */
    em[1610] = 1; em[1611] = 8; em[1612] = 1; /* 1610: pointer.struct.asn1_string_st */
    	em[1613] = 92; em[1614] = 0; 
    em[1615] = 1; em[1616] = 8; em[1617] = 1; /* 1615: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[1618] = 1620; em[1619] = 0; 
    em[1620] = 0; em[1621] = 32; em[1622] = 2; /* 1620: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[1623] = 1627; em[1624] = 8; 
    	em[1625] = 538; em[1626] = 24; 
    em[1627] = 8884099; em[1628] = 8; em[1629] = 2; /* 1627: pointer_to_array_of_pointers_to_stack */
    	em[1630] = 1634; em[1631] = 0; 
    	em[1632] = 195; em[1633] = 20; 
    em[1634] = 0; em[1635] = 8; em[1636] = 1; /* 1634: pointer.X509_ATTRIBUTE */
    	em[1637] = 1639; em[1638] = 0; 
    em[1639] = 0; em[1640] = 0; em[1641] = 1; /* 1639: X509_ATTRIBUTE */
    	em[1642] = 1644; em[1643] = 0; 
    em[1644] = 0; em[1645] = 24; em[1646] = 2; /* 1644: struct.x509_attributes_st */
    	em[1647] = 1483; em[1648] = 0; 
    	em[1649] = 1651; em[1650] = 16; 
    em[1651] = 0; em[1652] = 8; em[1653] = 3; /* 1651: union.unknown */
    	em[1654] = 133; em[1655] = 0; 
    	em[1656] = 1660; em[1657] = 0; 
    	em[1658] = 1824; em[1659] = 0; 
    em[1660] = 1; em[1661] = 8; em[1662] = 1; /* 1660: pointer.struct.stack_st_ASN1_TYPE */
    	em[1663] = 1665; em[1664] = 0; 
    em[1665] = 0; em[1666] = 32; em[1667] = 2; /* 1665: struct.stack_st_fake_ASN1_TYPE */
    	em[1668] = 1672; em[1669] = 8; 
    	em[1670] = 538; em[1671] = 24; 
    em[1672] = 8884099; em[1673] = 8; em[1674] = 2; /* 1672: pointer_to_array_of_pointers_to_stack */
    	em[1675] = 1679; em[1676] = 0; 
    	em[1677] = 195; em[1678] = 20; 
    em[1679] = 0; em[1680] = 8; em[1681] = 1; /* 1679: pointer.ASN1_TYPE */
    	em[1682] = 1684; em[1683] = 0; 
    em[1684] = 0; em[1685] = 0; em[1686] = 1; /* 1684: ASN1_TYPE */
    	em[1687] = 1689; em[1688] = 0; 
    em[1689] = 0; em[1690] = 16; em[1691] = 1; /* 1689: struct.asn1_type_st */
    	em[1692] = 1694; em[1693] = 8; 
    em[1694] = 0; em[1695] = 8; em[1696] = 20; /* 1694: union.unknown */
    	em[1697] = 133; em[1698] = 0; 
    	em[1699] = 1737; em[1700] = 0; 
    	em[1701] = 1742; em[1702] = 0; 
    	em[1703] = 1756; em[1704] = 0; 
    	em[1705] = 1761; em[1706] = 0; 
    	em[1707] = 1766; em[1708] = 0; 
    	em[1709] = 1771; em[1710] = 0; 
    	em[1711] = 1776; em[1712] = 0; 
    	em[1713] = 1781; em[1714] = 0; 
    	em[1715] = 1786; em[1716] = 0; 
    	em[1717] = 1791; em[1718] = 0; 
    	em[1719] = 87; em[1720] = 0; 
    	em[1721] = 1796; em[1722] = 0; 
    	em[1723] = 1801; em[1724] = 0; 
    	em[1725] = 1806; em[1726] = 0; 
    	em[1727] = 1811; em[1728] = 0; 
    	em[1729] = 1610; em[1730] = 0; 
    	em[1731] = 1737; em[1732] = 0; 
    	em[1733] = 1737; em[1734] = 0; 
    	em[1735] = 1816; em[1736] = 0; 
    em[1737] = 1; em[1738] = 8; em[1739] = 1; /* 1737: pointer.struct.asn1_string_st */
    	em[1740] = 92; em[1741] = 0; 
    em[1742] = 1; em[1743] = 8; em[1744] = 1; /* 1742: pointer.struct.asn1_object_st */
    	em[1745] = 1747; em[1746] = 0; 
    em[1747] = 0; em[1748] = 40; em[1749] = 3; /* 1747: struct.asn1_object_st */
    	em[1750] = 119; em[1751] = 0; 
    	em[1752] = 119; em[1753] = 8; 
    	em[1754] = 1497; em[1755] = 24; 
    em[1756] = 1; em[1757] = 8; em[1758] = 1; /* 1756: pointer.struct.asn1_string_st */
    	em[1759] = 92; em[1760] = 0; 
    em[1761] = 1; em[1762] = 8; em[1763] = 1; /* 1761: pointer.struct.asn1_string_st */
    	em[1764] = 92; em[1765] = 0; 
    em[1766] = 1; em[1767] = 8; em[1768] = 1; /* 1766: pointer.struct.asn1_string_st */
    	em[1769] = 92; em[1770] = 0; 
    em[1771] = 1; em[1772] = 8; em[1773] = 1; /* 1771: pointer.struct.asn1_string_st */
    	em[1774] = 92; em[1775] = 0; 
    em[1776] = 1; em[1777] = 8; em[1778] = 1; /* 1776: pointer.struct.asn1_string_st */
    	em[1779] = 92; em[1780] = 0; 
    em[1781] = 1; em[1782] = 8; em[1783] = 1; /* 1781: pointer.struct.asn1_string_st */
    	em[1784] = 92; em[1785] = 0; 
    em[1786] = 1; em[1787] = 8; em[1788] = 1; /* 1786: pointer.struct.asn1_string_st */
    	em[1789] = 92; em[1790] = 0; 
    em[1791] = 1; em[1792] = 8; em[1793] = 1; /* 1791: pointer.struct.asn1_string_st */
    	em[1794] = 92; em[1795] = 0; 
    em[1796] = 1; em[1797] = 8; em[1798] = 1; /* 1796: pointer.struct.asn1_string_st */
    	em[1799] = 92; em[1800] = 0; 
    em[1801] = 1; em[1802] = 8; em[1803] = 1; /* 1801: pointer.struct.asn1_string_st */
    	em[1804] = 92; em[1805] = 0; 
    em[1806] = 1; em[1807] = 8; em[1808] = 1; /* 1806: pointer.struct.asn1_string_st */
    	em[1809] = 92; em[1810] = 0; 
    em[1811] = 1; em[1812] = 8; em[1813] = 1; /* 1811: pointer.struct.asn1_string_st */
    	em[1814] = 92; em[1815] = 0; 
    em[1816] = 1; em[1817] = 8; em[1818] = 1; /* 1816: pointer.struct.ASN1_VALUE_st */
    	em[1819] = 1821; em[1820] = 0; 
    em[1821] = 0; em[1822] = 0; em[1823] = 0; /* 1821: struct.ASN1_VALUE_st */
    em[1824] = 1; em[1825] = 8; em[1826] = 1; /* 1824: pointer.struct.asn1_type_st */
    	em[1827] = 1435; em[1828] = 0; 
    em[1829] = 1; em[1830] = 8; em[1831] = 1; /* 1829: pointer.struct.engine_st */
    	em[1832] = 251; em[1833] = 0; 
    em[1834] = 0; em[1835] = 56; em[1836] = 4; /* 1834: struct.evp_pkey_st */
    	em[1837] = 1512; em[1838] = 16; 
    	em[1839] = 1829; em[1840] = 24; 
    	em[1841] = 744; em[1842] = 32; 
    	em[1843] = 1615; em[1844] = 48; 
    em[1845] = 0; em[1846] = 1; em[1847] = 0; /* 1845: char */
    em[1848] = 1; em[1849] = 8; em[1850] = 1; /* 1848: pointer.struct.evp_pkey_st */
    	em[1851] = 1834; em[1852] = 0; 
    args_addr->arg_entity_index[0] = 1848;
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

