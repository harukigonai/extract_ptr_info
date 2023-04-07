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
    em[0] = 0; em[1] = 0; em[2] = 0; /* 0: struct.ASN1_VALUE_st */
    em[3] = 1; em[4] = 8; em[5] = 1; /* 3: pointer.struct.ASN1_VALUE_st */
    	em[6] = 0; em[7] = 0; 
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
    em[66] = 0; em[67] = 16; em[68] = 1; /* 66: struct.asn1_type_st */
    	em[69] = 71; em[70] = 8; 
    em[71] = 0; em[72] = 8; em[73] = 20; /* 71: union.unknown */
    	em[74] = 114; em[75] = 0; 
    	em[76] = 61; em[77] = 0; 
    	em[78] = 119; em[79] = 0; 
    	em[80] = 143; em[81] = 0; 
    	em[82] = 56; em[83] = 0; 
    	em[84] = 51; em[85] = 0; 
    	em[86] = 46; em[87] = 0; 
    	em[88] = 148; em[89] = 0; 
    	em[90] = 41; em[91] = 0; 
    	em[92] = 36; em[93] = 0; 
    	em[94] = 31; em[95] = 0; 
    	em[96] = 26; em[97] = 0; 
    	em[98] = 153; em[99] = 0; 
    	em[100] = 158; em[101] = 0; 
    	em[102] = 163; em[103] = 0; 
    	em[104] = 168; em[105] = 0; 
    	em[106] = 8; em[107] = 0; 
    	em[108] = 61; em[109] = 0; 
    	em[110] = 61; em[111] = 0; 
    	em[112] = 3; em[113] = 0; 
    em[114] = 1; em[115] = 8; em[116] = 1; /* 114: pointer.char */
    	em[117] = 8884096; em[118] = 0; 
    em[119] = 1; em[120] = 8; em[121] = 1; /* 119: pointer.struct.asn1_object_st */
    	em[122] = 124; em[123] = 0; 
    em[124] = 0; em[125] = 40; em[126] = 3; /* 124: struct.asn1_object_st */
    	em[127] = 133; em[128] = 0; 
    	em[129] = 133; em[130] = 8; 
    	em[131] = 138; em[132] = 24; 
    em[133] = 1; em[134] = 8; em[135] = 1; /* 133: pointer.char */
    	em[136] = 8884096; em[137] = 0; 
    em[138] = 1; em[139] = 8; em[140] = 1; /* 138: pointer.unsigned char */
    	em[141] = 23; em[142] = 0; 
    em[143] = 1; em[144] = 8; em[145] = 1; /* 143: pointer.struct.asn1_string_st */
    	em[146] = 13; em[147] = 0; 
    em[148] = 1; em[149] = 8; em[150] = 1; /* 148: pointer.struct.asn1_string_st */
    	em[151] = 13; em[152] = 0; 
    em[153] = 1; em[154] = 8; em[155] = 1; /* 153: pointer.struct.asn1_string_st */
    	em[156] = 13; em[157] = 0; 
    em[158] = 1; em[159] = 8; em[160] = 1; /* 158: pointer.struct.asn1_string_st */
    	em[161] = 13; em[162] = 0; 
    em[163] = 1; em[164] = 8; em[165] = 1; /* 163: pointer.struct.asn1_string_st */
    	em[166] = 13; em[167] = 0; 
    em[168] = 1; em[169] = 8; em[170] = 1; /* 168: pointer.struct.asn1_string_st */
    	em[171] = 13; em[172] = 0; 
    em[173] = 0; em[174] = 0; em[175] = 0; /* 173: struct.ASN1_VALUE_st */
    em[176] = 1; em[177] = 8; em[178] = 1; /* 176: pointer.struct.asn1_string_st */
    	em[179] = 181; em[180] = 0; 
    em[181] = 0; em[182] = 24; em[183] = 1; /* 181: struct.asn1_string_st */
    	em[184] = 18; em[185] = 8; 
    em[186] = 1; em[187] = 8; em[188] = 1; /* 186: pointer.struct.asn1_string_st */
    	em[189] = 181; em[190] = 0; 
    em[191] = 1; em[192] = 8; em[193] = 1; /* 191: pointer.struct.asn1_string_st */
    	em[194] = 181; em[195] = 0; 
    em[196] = 1; em[197] = 8; em[198] = 1; /* 196: pointer.struct.asn1_string_st */
    	em[199] = 181; em[200] = 0; 
    em[201] = 1; em[202] = 8; em[203] = 1; /* 201: pointer.struct.asn1_string_st */
    	em[204] = 181; em[205] = 0; 
    em[206] = 1; em[207] = 8; em[208] = 1; /* 206: pointer.struct.dsa_method */
    	em[209] = 211; em[210] = 0; 
    em[211] = 0; em[212] = 96; em[213] = 11; /* 211: struct.dsa_method */
    	em[214] = 133; em[215] = 0; 
    	em[216] = 236; em[217] = 8; 
    	em[218] = 239; em[219] = 16; 
    	em[220] = 242; em[221] = 24; 
    	em[222] = 245; em[223] = 32; 
    	em[224] = 248; em[225] = 40; 
    	em[226] = 251; em[227] = 48; 
    	em[228] = 251; em[229] = 56; 
    	em[230] = 114; em[231] = 72; 
    	em[232] = 254; em[233] = 80; 
    	em[234] = 251; em[235] = 88; 
    em[236] = 8884097; em[237] = 8; em[238] = 0; /* 236: pointer.func */
    em[239] = 8884097; em[240] = 8; em[241] = 0; /* 239: pointer.func */
    em[242] = 8884097; em[243] = 8; em[244] = 0; /* 242: pointer.func */
    em[245] = 8884097; em[246] = 8; em[247] = 0; /* 245: pointer.func */
    em[248] = 8884097; em[249] = 8; em[250] = 0; /* 248: pointer.func */
    em[251] = 8884097; em[252] = 8; em[253] = 0; /* 251: pointer.func */
    em[254] = 8884097; em[255] = 8; em[256] = 0; /* 254: pointer.func */
    em[257] = 1; em[258] = 8; em[259] = 1; /* 257: pointer.struct.dsa_st */
    	em[260] = 262; em[261] = 0; 
    em[262] = 0; em[263] = 136; em[264] = 11; /* 262: struct.dsa_st */
    	em[265] = 287; em[266] = 24; 
    	em[267] = 287; em[268] = 32; 
    	em[269] = 287; em[270] = 40; 
    	em[271] = 287; em[272] = 48; 
    	em[273] = 287; em[274] = 56; 
    	em[275] = 287; em[276] = 64; 
    	em[277] = 287; em[278] = 72; 
    	em[279] = 310; em[280] = 88; 
    	em[281] = 324; em[282] = 104; 
    	em[283] = 206; em[284] = 120; 
    	em[285] = 354; em[286] = 128; 
    em[287] = 1; em[288] = 8; em[289] = 1; /* 287: pointer.struct.bignum_st */
    	em[290] = 292; em[291] = 0; 
    em[292] = 0; em[293] = 24; em[294] = 1; /* 292: struct.bignum_st */
    	em[295] = 297; em[296] = 0; 
    em[297] = 8884099; em[298] = 8; em[299] = 2; /* 297: pointer_to_array_of_pointers_to_stack */
    	em[300] = 304; em[301] = 0; 
    	em[302] = 307; em[303] = 12; 
    em[304] = 0; em[305] = 4; em[306] = 0; /* 304: unsigned int */
    em[307] = 0; em[308] = 4; em[309] = 0; /* 307: int */
    em[310] = 1; em[311] = 8; em[312] = 1; /* 310: pointer.struct.bn_mont_ctx_st */
    	em[313] = 315; em[314] = 0; 
    em[315] = 0; em[316] = 96; em[317] = 3; /* 315: struct.bn_mont_ctx_st */
    	em[318] = 292; em[319] = 8; 
    	em[320] = 292; em[321] = 32; 
    	em[322] = 292; em[323] = 56; 
    em[324] = 0; em[325] = 16; em[326] = 1; /* 324: struct.crypto_ex_data_st */
    	em[327] = 329; em[328] = 0; 
    em[329] = 1; em[330] = 8; em[331] = 1; /* 329: pointer.struct.stack_st_void */
    	em[332] = 334; em[333] = 0; 
    em[334] = 0; em[335] = 32; em[336] = 1; /* 334: struct.stack_st_void */
    	em[337] = 339; em[338] = 0; 
    em[339] = 0; em[340] = 32; em[341] = 2; /* 339: struct.stack_st */
    	em[342] = 346; em[343] = 8; 
    	em[344] = 351; em[345] = 24; 
    em[346] = 1; em[347] = 8; em[348] = 1; /* 346: pointer.pointer.char */
    	em[349] = 114; em[350] = 0; 
    em[351] = 8884097; em[352] = 8; em[353] = 0; /* 351: pointer.func */
    em[354] = 1; em[355] = 8; em[356] = 1; /* 354: pointer.struct.engine_st */
    	em[357] = 359; em[358] = 0; 
    em[359] = 0; em[360] = 216; em[361] = 24; /* 359: struct.engine_st */
    	em[362] = 133; em[363] = 0; 
    	em[364] = 133; em[365] = 8; 
    	em[366] = 410; em[367] = 16; 
    	em[368] = 465; em[369] = 24; 
    	em[370] = 516; em[371] = 32; 
    	em[372] = 552; em[373] = 40; 
    	em[374] = 569; em[375] = 48; 
    	em[376] = 596; em[377] = 56; 
    	em[378] = 631; em[379] = 64; 
    	em[380] = 639; em[381] = 72; 
    	em[382] = 642; em[383] = 80; 
    	em[384] = 645; em[385] = 88; 
    	em[386] = 648; em[387] = 96; 
    	em[388] = 651; em[389] = 104; 
    	em[390] = 651; em[391] = 112; 
    	em[392] = 651; em[393] = 120; 
    	em[394] = 654; em[395] = 128; 
    	em[396] = 657; em[397] = 136; 
    	em[398] = 657; em[399] = 144; 
    	em[400] = 660; em[401] = 152; 
    	em[402] = 663; em[403] = 160; 
    	em[404] = 675; em[405] = 184; 
    	em[406] = 697; em[407] = 200; 
    	em[408] = 697; em[409] = 208; 
    em[410] = 1; em[411] = 8; em[412] = 1; /* 410: pointer.struct.rsa_meth_st */
    	em[413] = 415; em[414] = 0; 
    em[415] = 0; em[416] = 112; em[417] = 13; /* 415: struct.rsa_meth_st */
    	em[418] = 133; em[419] = 0; 
    	em[420] = 444; em[421] = 8; 
    	em[422] = 444; em[423] = 16; 
    	em[424] = 444; em[425] = 24; 
    	em[426] = 444; em[427] = 32; 
    	em[428] = 447; em[429] = 40; 
    	em[430] = 450; em[431] = 48; 
    	em[432] = 453; em[433] = 56; 
    	em[434] = 453; em[435] = 64; 
    	em[436] = 114; em[437] = 80; 
    	em[438] = 456; em[439] = 88; 
    	em[440] = 459; em[441] = 96; 
    	em[442] = 462; em[443] = 104; 
    em[444] = 8884097; em[445] = 8; em[446] = 0; /* 444: pointer.func */
    em[447] = 8884097; em[448] = 8; em[449] = 0; /* 447: pointer.func */
    em[450] = 8884097; em[451] = 8; em[452] = 0; /* 450: pointer.func */
    em[453] = 8884097; em[454] = 8; em[455] = 0; /* 453: pointer.func */
    em[456] = 8884097; em[457] = 8; em[458] = 0; /* 456: pointer.func */
    em[459] = 8884097; em[460] = 8; em[461] = 0; /* 459: pointer.func */
    em[462] = 8884097; em[463] = 8; em[464] = 0; /* 462: pointer.func */
    em[465] = 1; em[466] = 8; em[467] = 1; /* 465: pointer.struct.dsa_method */
    	em[468] = 470; em[469] = 0; 
    em[470] = 0; em[471] = 96; em[472] = 11; /* 470: struct.dsa_method */
    	em[473] = 133; em[474] = 0; 
    	em[475] = 495; em[476] = 8; 
    	em[477] = 498; em[478] = 16; 
    	em[479] = 501; em[480] = 24; 
    	em[481] = 504; em[482] = 32; 
    	em[483] = 507; em[484] = 40; 
    	em[485] = 510; em[486] = 48; 
    	em[487] = 510; em[488] = 56; 
    	em[489] = 114; em[490] = 72; 
    	em[491] = 513; em[492] = 80; 
    	em[493] = 510; em[494] = 88; 
    em[495] = 8884097; em[496] = 8; em[497] = 0; /* 495: pointer.func */
    em[498] = 8884097; em[499] = 8; em[500] = 0; /* 498: pointer.func */
    em[501] = 8884097; em[502] = 8; em[503] = 0; /* 501: pointer.func */
    em[504] = 8884097; em[505] = 8; em[506] = 0; /* 504: pointer.func */
    em[507] = 8884097; em[508] = 8; em[509] = 0; /* 507: pointer.func */
    em[510] = 8884097; em[511] = 8; em[512] = 0; /* 510: pointer.func */
    em[513] = 8884097; em[514] = 8; em[515] = 0; /* 513: pointer.func */
    em[516] = 1; em[517] = 8; em[518] = 1; /* 516: pointer.struct.dh_method */
    	em[519] = 521; em[520] = 0; 
    em[521] = 0; em[522] = 72; em[523] = 8; /* 521: struct.dh_method */
    	em[524] = 133; em[525] = 0; 
    	em[526] = 540; em[527] = 8; 
    	em[528] = 543; em[529] = 16; 
    	em[530] = 546; em[531] = 24; 
    	em[532] = 540; em[533] = 32; 
    	em[534] = 540; em[535] = 40; 
    	em[536] = 114; em[537] = 56; 
    	em[538] = 549; em[539] = 64; 
    em[540] = 8884097; em[541] = 8; em[542] = 0; /* 540: pointer.func */
    em[543] = 8884097; em[544] = 8; em[545] = 0; /* 543: pointer.func */
    em[546] = 8884097; em[547] = 8; em[548] = 0; /* 546: pointer.func */
    em[549] = 8884097; em[550] = 8; em[551] = 0; /* 549: pointer.func */
    em[552] = 1; em[553] = 8; em[554] = 1; /* 552: pointer.struct.ecdh_method */
    	em[555] = 557; em[556] = 0; 
    em[557] = 0; em[558] = 32; em[559] = 3; /* 557: struct.ecdh_method */
    	em[560] = 133; em[561] = 0; 
    	em[562] = 566; em[563] = 8; 
    	em[564] = 114; em[565] = 24; 
    em[566] = 8884097; em[567] = 8; em[568] = 0; /* 566: pointer.func */
    em[569] = 1; em[570] = 8; em[571] = 1; /* 569: pointer.struct.ecdsa_method */
    	em[572] = 574; em[573] = 0; 
    em[574] = 0; em[575] = 48; em[576] = 5; /* 574: struct.ecdsa_method */
    	em[577] = 133; em[578] = 0; 
    	em[579] = 587; em[580] = 8; 
    	em[581] = 590; em[582] = 16; 
    	em[583] = 593; em[584] = 24; 
    	em[585] = 114; em[586] = 40; 
    em[587] = 8884097; em[588] = 8; em[589] = 0; /* 587: pointer.func */
    em[590] = 8884097; em[591] = 8; em[592] = 0; /* 590: pointer.func */
    em[593] = 8884097; em[594] = 8; em[595] = 0; /* 593: pointer.func */
    em[596] = 1; em[597] = 8; em[598] = 1; /* 596: pointer.struct.rand_meth_st */
    	em[599] = 601; em[600] = 0; 
    em[601] = 0; em[602] = 48; em[603] = 6; /* 601: struct.rand_meth_st */
    	em[604] = 616; em[605] = 0; 
    	em[606] = 619; em[607] = 8; 
    	em[608] = 622; em[609] = 16; 
    	em[610] = 625; em[611] = 24; 
    	em[612] = 619; em[613] = 32; 
    	em[614] = 628; em[615] = 40; 
    em[616] = 8884097; em[617] = 8; em[618] = 0; /* 616: pointer.func */
    em[619] = 8884097; em[620] = 8; em[621] = 0; /* 619: pointer.func */
    em[622] = 8884097; em[623] = 8; em[624] = 0; /* 622: pointer.func */
    em[625] = 8884097; em[626] = 8; em[627] = 0; /* 625: pointer.func */
    em[628] = 8884097; em[629] = 8; em[630] = 0; /* 628: pointer.func */
    em[631] = 1; em[632] = 8; em[633] = 1; /* 631: pointer.struct.store_method_st */
    	em[634] = 636; em[635] = 0; 
    em[636] = 0; em[637] = 0; em[638] = 0; /* 636: struct.store_method_st */
    em[639] = 8884097; em[640] = 8; em[641] = 0; /* 639: pointer.func */
    em[642] = 8884097; em[643] = 8; em[644] = 0; /* 642: pointer.func */
    em[645] = 8884097; em[646] = 8; em[647] = 0; /* 645: pointer.func */
    em[648] = 8884097; em[649] = 8; em[650] = 0; /* 648: pointer.func */
    em[651] = 8884097; em[652] = 8; em[653] = 0; /* 651: pointer.func */
    em[654] = 8884097; em[655] = 8; em[656] = 0; /* 654: pointer.func */
    em[657] = 8884097; em[658] = 8; em[659] = 0; /* 657: pointer.func */
    em[660] = 8884097; em[661] = 8; em[662] = 0; /* 660: pointer.func */
    em[663] = 1; em[664] = 8; em[665] = 1; /* 663: pointer.struct.ENGINE_CMD_DEFN_st */
    	em[666] = 668; em[667] = 0; 
    em[668] = 0; em[669] = 32; em[670] = 2; /* 668: struct.ENGINE_CMD_DEFN_st */
    	em[671] = 133; em[672] = 8; 
    	em[673] = 133; em[674] = 16; 
    em[675] = 0; em[676] = 16; em[677] = 1; /* 675: struct.crypto_ex_data_st */
    	em[678] = 680; em[679] = 0; 
    em[680] = 1; em[681] = 8; em[682] = 1; /* 680: pointer.struct.stack_st_void */
    	em[683] = 685; em[684] = 0; 
    em[685] = 0; em[686] = 32; em[687] = 1; /* 685: struct.stack_st_void */
    	em[688] = 690; em[689] = 0; 
    em[690] = 0; em[691] = 32; em[692] = 2; /* 690: struct.stack_st */
    	em[693] = 346; em[694] = 8; 
    	em[695] = 351; em[696] = 24; 
    em[697] = 1; em[698] = 8; em[699] = 1; /* 697: pointer.struct.engine_st */
    	em[700] = 359; em[701] = 0; 
    em[702] = 0; em[703] = 8; em[704] = 0; /* 702: pointer.void */
    em[705] = 0; em[706] = 88; em[707] = 7; /* 705: struct.bn_blinding_st */
    	em[708] = 722; em[709] = 0; 
    	em[710] = 722; em[711] = 8; 
    	em[712] = 722; em[713] = 16; 
    	em[714] = 722; em[715] = 24; 
    	em[716] = 739; em[717] = 40; 
    	em[718] = 744; em[719] = 72; 
    	em[720] = 758; em[721] = 80; 
    em[722] = 1; em[723] = 8; em[724] = 1; /* 722: pointer.struct.bignum_st */
    	em[725] = 727; em[726] = 0; 
    em[727] = 0; em[728] = 24; em[729] = 1; /* 727: struct.bignum_st */
    	em[730] = 732; em[731] = 0; 
    em[732] = 8884099; em[733] = 8; em[734] = 2; /* 732: pointer_to_array_of_pointers_to_stack */
    	em[735] = 304; em[736] = 0; 
    	em[737] = 307; em[738] = 12; 
    em[739] = 0; em[740] = 16; em[741] = 1; /* 739: struct.crypto_threadid_st */
    	em[742] = 702; em[743] = 0; 
    em[744] = 1; em[745] = 8; em[746] = 1; /* 744: pointer.struct.bn_mont_ctx_st */
    	em[747] = 749; em[748] = 0; 
    em[749] = 0; em[750] = 96; em[751] = 3; /* 749: struct.bn_mont_ctx_st */
    	em[752] = 727; em[753] = 8; 
    	em[754] = 727; em[755] = 32; 
    	em[756] = 727; em[757] = 56; 
    em[758] = 8884097; em[759] = 8; em[760] = 0; /* 758: pointer.func */
    em[761] = 0; em[762] = 96; em[763] = 3; /* 761: struct.bn_mont_ctx_st */
    	em[764] = 770; em[765] = 8; 
    	em[766] = 770; em[767] = 32; 
    	em[768] = 770; em[769] = 56; 
    em[770] = 0; em[771] = 24; em[772] = 1; /* 770: struct.bignum_st */
    	em[773] = 775; em[774] = 0; 
    em[775] = 8884099; em[776] = 8; em[777] = 2; /* 775: pointer_to_array_of_pointers_to_stack */
    	em[778] = 304; em[779] = 0; 
    	em[780] = 307; em[781] = 12; 
    em[782] = 1; em[783] = 8; em[784] = 1; /* 782: pointer.struct.stack_st_void */
    	em[785] = 787; em[786] = 0; 
    em[787] = 0; em[788] = 32; em[789] = 1; /* 787: struct.stack_st_void */
    	em[790] = 792; em[791] = 0; 
    em[792] = 0; em[793] = 32; em[794] = 2; /* 792: struct.stack_st */
    	em[795] = 346; em[796] = 8; 
    	em[797] = 351; em[798] = 24; 
    em[799] = 8884097; em[800] = 8; em[801] = 0; /* 799: pointer.func */
    em[802] = 8884097; em[803] = 8; em[804] = 0; /* 802: pointer.func */
    em[805] = 1; em[806] = 8; em[807] = 1; /* 805: pointer.struct.asn1_string_st */
    	em[808] = 181; em[809] = 0; 
    em[810] = 8884097; em[811] = 8; em[812] = 0; /* 810: pointer.func */
    em[813] = 0; em[814] = 88; em[815] = 4; /* 813: struct.ec_point_st */
    	em[816] = 824; em[817] = 0; 
    	em[818] = 993; em[819] = 8; 
    	em[820] = 993; em[821] = 32; 
    	em[822] = 993; em[823] = 56; 
    em[824] = 1; em[825] = 8; em[826] = 1; /* 824: pointer.struct.ec_method_st */
    	em[827] = 829; em[828] = 0; 
    em[829] = 0; em[830] = 304; em[831] = 37; /* 829: struct.ec_method_st */
    	em[832] = 906; em[833] = 8; 
    	em[834] = 909; em[835] = 16; 
    	em[836] = 909; em[837] = 24; 
    	em[838] = 912; em[839] = 32; 
    	em[840] = 915; em[841] = 40; 
    	em[842] = 918; em[843] = 48; 
    	em[844] = 921; em[845] = 56; 
    	em[846] = 924; em[847] = 64; 
    	em[848] = 927; em[849] = 72; 
    	em[850] = 930; em[851] = 80; 
    	em[852] = 930; em[853] = 88; 
    	em[854] = 933; em[855] = 96; 
    	em[856] = 936; em[857] = 104; 
    	em[858] = 939; em[859] = 112; 
    	em[860] = 942; em[861] = 120; 
    	em[862] = 945; em[863] = 128; 
    	em[864] = 948; em[865] = 136; 
    	em[866] = 951; em[867] = 144; 
    	em[868] = 954; em[869] = 152; 
    	em[870] = 957; em[871] = 160; 
    	em[872] = 960; em[873] = 168; 
    	em[874] = 799; em[875] = 176; 
    	em[876] = 963; em[877] = 184; 
    	em[878] = 966; em[879] = 192; 
    	em[880] = 969; em[881] = 200; 
    	em[882] = 972; em[883] = 208; 
    	em[884] = 963; em[885] = 216; 
    	em[886] = 975; em[887] = 224; 
    	em[888] = 978; em[889] = 232; 
    	em[890] = 981; em[891] = 240; 
    	em[892] = 921; em[893] = 248; 
    	em[894] = 984; em[895] = 256; 
    	em[896] = 987; em[897] = 264; 
    	em[898] = 984; em[899] = 272; 
    	em[900] = 987; em[901] = 280; 
    	em[902] = 987; em[903] = 288; 
    	em[904] = 990; em[905] = 296; 
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
    em[987] = 8884097; em[988] = 8; em[989] = 0; /* 987: pointer.func */
    em[990] = 8884097; em[991] = 8; em[992] = 0; /* 990: pointer.func */
    em[993] = 0; em[994] = 24; em[995] = 1; /* 993: struct.bignum_st */
    	em[996] = 998; em[997] = 0; 
    em[998] = 8884099; em[999] = 8; em[1000] = 2; /* 998: pointer_to_array_of_pointers_to_stack */
    	em[1001] = 304; em[1002] = 0; 
    	em[1003] = 307; em[1004] = 12; 
    em[1005] = 1; em[1006] = 8; em[1007] = 1; /* 1005: pointer.struct.ASN1_VALUE_st */
    	em[1008] = 173; em[1009] = 0; 
    em[1010] = 0; em[1011] = 16; em[1012] = 1; /* 1010: struct.crypto_ex_data_st */
    	em[1013] = 782; em[1014] = 0; 
    em[1015] = 8884097; em[1016] = 8; em[1017] = 0; /* 1015: pointer.func */
    em[1018] = 8884097; em[1019] = 8; em[1020] = 0; /* 1018: pointer.func */
    em[1021] = 8884097; em[1022] = 8; em[1023] = 0; /* 1021: pointer.func */
    em[1024] = 1; em[1025] = 8; em[1026] = 1; /* 1024: pointer.struct.bignum_st */
    	em[1027] = 770; em[1028] = 0; 
    em[1029] = 8884097; em[1030] = 8; em[1031] = 0; /* 1029: pointer.func */
    em[1032] = 0; em[1033] = 1; em[1034] = 0; /* 1032: char */
    em[1035] = 1; em[1036] = 8; em[1037] = 1; /* 1035: pointer.struct.asn1_object_st */
    	em[1038] = 1040; em[1039] = 0; 
    em[1040] = 0; em[1041] = 40; em[1042] = 3; /* 1040: struct.asn1_object_st */
    	em[1043] = 133; em[1044] = 0; 
    	em[1045] = 133; em[1046] = 8; 
    	em[1047] = 138; em[1048] = 24; 
    em[1049] = 0; em[1050] = 8; em[1051] = 1; /* 1049: pointer.ASN1_TYPE */
    	em[1052] = 1054; em[1053] = 0; 
    em[1054] = 0; em[1055] = 0; em[1056] = 1; /* 1054: ASN1_TYPE */
    	em[1057] = 1059; em[1058] = 0; 
    em[1059] = 0; em[1060] = 16; em[1061] = 1; /* 1059: struct.asn1_type_st */
    	em[1062] = 1064; em[1063] = 8; 
    em[1064] = 0; em[1065] = 8; em[1066] = 20; /* 1064: union.unknown */
    	em[1067] = 114; em[1068] = 0; 
    	em[1069] = 1107; em[1070] = 0; 
    	em[1071] = 1035; em[1072] = 0; 
    	em[1073] = 1112; em[1074] = 0; 
    	em[1075] = 1117; em[1076] = 0; 
    	em[1077] = 1122; em[1078] = 0; 
    	em[1079] = 805; em[1080] = 0; 
    	em[1081] = 201; em[1082] = 0; 
    	em[1083] = 1127; em[1084] = 0; 
    	em[1085] = 196; em[1086] = 0; 
    	em[1087] = 1132; em[1088] = 0; 
    	em[1089] = 1137; em[1090] = 0; 
    	em[1091] = 1142; em[1092] = 0; 
    	em[1093] = 1147; em[1094] = 0; 
    	em[1095] = 191; em[1096] = 0; 
    	em[1097] = 186; em[1098] = 0; 
    	em[1099] = 176; em[1100] = 0; 
    	em[1101] = 1107; em[1102] = 0; 
    	em[1103] = 1107; em[1104] = 0; 
    	em[1105] = 1005; em[1106] = 0; 
    em[1107] = 1; em[1108] = 8; em[1109] = 1; /* 1107: pointer.struct.asn1_string_st */
    	em[1110] = 181; em[1111] = 0; 
    em[1112] = 1; em[1113] = 8; em[1114] = 1; /* 1112: pointer.struct.asn1_string_st */
    	em[1115] = 181; em[1116] = 0; 
    em[1117] = 1; em[1118] = 8; em[1119] = 1; /* 1117: pointer.struct.asn1_string_st */
    	em[1120] = 181; em[1121] = 0; 
    em[1122] = 1; em[1123] = 8; em[1124] = 1; /* 1122: pointer.struct.asn1_string_st */
    	em[1125] = 181; em[1126] = 0; 
    em[1127] = 1; em[1128] = 8; em[1129] = 1; /* 1127: pointer.struct.asn1_string_st */
    	em[1130] = 181; em[1131] = 0; 
    em[1132] = 1; em[1133] = 8; em[1134] = 1; /* 1132: pointer.struct.asn1_string_st */
    	em[1135] = 181; em[1136] = 0; 
    em[1137] = 1; em[1138] = 8; em[1139] = 1; /* 1137: pointer.struct.asn1_string_st */
    	em[1140] = 181; em[1141] = 0; 
    em[1142] = 1; em[1143] = 8; em[1144] = 1; /* 1142: pointer.struct.asn1_string_st */
    	em[1145] = 181; em[1146] = 0; 
    em[1147] = 1; em[1148] = 8; em[1149] = 1; /* 1147: pointer.struct.asn1_string_st */
    	em[1150] = 181; em[1151] = 0; 
    em[1152] = 0; em[1153] = 208; em[1154] = 24; /* 1152: struct.evp_pkey_asn1_method_st */
    	em[1155] = 114; em[1156] = 16; 
    	em[1157] = 114; em[1158] = 24; 
    	em[1159] = 1203; em[1160] = 32; 
    	em[1161] = 1206; em[1162] = 40; 
    	em[1163] = 1209; em[1164] = 48; 
    	em[1165] = 1212; em[1166] = 56; 
    	em[1167] = 1215; em[1168] = 64; 
    	em[1169] = 1218; em[1170] = 72; 
    	em[1171] = 1212; em[1172] = 80; 
    	em[1173] = 1221; em[1174] = 88; 
    	em[1175] = 1221; em[1176] = 96; 
    	em[1177] = 1224; em[1178] = 104; 
    	em[1179] = 1227; em[1180] = 112; 
    	em[1181] = 1221; em[1182] = 120; 
    	em[1183] = 1230; em[1184] = 128; 
    	em[1185] = 1209; em[1186] = 136; 
    	em[1187] = 1212; em[1188] = 144; 
    	em[1189] = 1015; em[1190] = 152; 
    	em[1191] = 1233; em[1192] = 160; 
    	em[1193] = 1236; em[1194] = 168; 
    	em[1195] = 1224; em[1196] = 176; 
    	em[1197] = 1227; em[1198] = 184; 
    	em[1199] = 1239; em[1200] = 192; 
    	em[1201] = 1242; em[1202] = 200; 
    em[1203] = 8884097; em[1204] = 8; em[1205] = 0; /* 1203: pointer.func */
    em[1206] = 8884097; em[1207] = 8; em[1208] = 0; /* 1206: pointer.func */
    em[1209] = 8884097; em[1210] = 8; em[1211] = 0; /* 1209: pointer.func */
    em[1212] = 8884097; em[1213] = 8; em[1214] = 0; /* 1212: pointer.func */
    em[1215] = 8884097; em[1216] = 8; em[1217] = 0; /* 1215: pointer.func */
    em[1218] = 8884097; em[1219] = 8; em[1220] = 0; /* 1218: pointer.func */
    em[1221] = 8884097; em[1222] = 8; em[1223] = 0; /* 1221: pointer.func */
    em[1224] = 8884097; em[1225] = 8; em[1226] = 0; /* 1224: pointer.func */
    em[1227] = 8884097; em[1228] = 8; em[1229] = 0; /* 1227: pointer.func */
    em[1230] = 8884097; em[1231] = 8; em[1232] = 0; /* 1230: pointer.func */
    em[1233] = 8884097; em[1234] = 8; em[1235] = 0; /* 1233: pointer.func */
    em[1236] = 8884097; em[1237] = 8; em[1238] = 0; /* 1236: pointer.func */
    em[1239] = 8884097; em[1240] = 8; em[1241] = 0; /* 1239: pointer.func */
    em[1242] = 8884097; em[1243] = 8; em[1244] = 0; /* 1242: pointer.func */
    em[1245] = 8884097; em[1246] = 8; em[1247] = 0; /* 1245: pointer.func */
    em[1248] = 0; em[1249] = 112; em[1250] = 13; /* 1248: struct.rsa_meth_st */
    	em[1251] = 133; em[1252] = 0; 
    	em[1253] = 1277; em[1254] = 8; 
    	em[1255] = 1277; em[1256] = 16; 
    	em[1257] = 1277; em[1258] = 24; 
    	em[1259] = 1277; em[1260] = 32; 
    	em[1261] = 1280; em[1262] = 40; 
    	em[1263] = 1283; em[1264] = 48; 
    	em[1265] = 1245; em[1266] = 56; 
    	em[1267] = 1245; em[1268] = 64; 
    	em[1269] = 114; em[1270] = 80; 
    	em[1271] = 1029; em[1272] = 88; 
    	em[1273] = 1286; em[1274] = 96; 
    	em[1275] = 1021; em[1276] = 104; 
    em[1277] = 8884097; em[1278] = 8; em[1279] = 0; /* 1277: pointer.func */
    em[1280] = 8884097; em[1281] = 8; em[1282] = 0; /* 1280: pointer.func */
    em[1283] = 8884097; em[1284] = 8; em[1285] = 0; /* 1283: pointer.func */
    em[1286] = 8884097; em[1287] = 8; em[1288] = 0; /* 1286: pointer.func */
    em[1289] = 1; em[1290] = 8; em[1291] = 1; /* 1289: pointer.struct.rsa_meth_st */
    	em[1292] = 1248; em[1293] = 0; 
    em[1294] = 0; em[1295] = 168; em[1296] = 17; /* 1294: struct.rsa_st */
    	em[1297] = 1289; em[1298] = 16; 
    	em[1299] = 1331; em[1300] = 24; 
    	em[1301] = 1024; em[1302] = 32; 
    	em[1303] = 1024; em[1304] = 40; 
    	em[1305] = 1024; em[1306] = 48; 
    	em[1307] = 1024; em[1308] = 56; 
    	em[1309] = 1024; em[1310] = 64; 
    	em[1311] = 1024; em[1312] = 72; 
    	em[1313] = 1024; em[1314] = 80; 
    	em[1315] = 1024; em[1316] = 88; 
    	em[1317] = 1010; em[1318] = 96; 
    	em[1319] = 1336; em[1320] = 120; 
    	em[1321] = 1336; em[1322] = 128; 
    	em[1323] = 1336; em[1324] = 136; 
    	em[1325] = 114; em[1326] = 144; 
    	em[1327] = 1341; em[1328] = 152; 
    	em[1329] = 1341; em[1330] = 160; 
    em[1331] = 1; em[1332] = 8; em[1333] = 1; /* 1331: pointer.struct.engine_st */
    	em[1334] = 359; em[1335] = 0; 
    em[1336] = 1; em[1337] = 8; em[1338] = 1; /* 1336: pointer.struct.bn_mont_ctx_st */
    	em[1339] = 761; em[1340] = 0; 
    em[1341] = 1; em[1342] = 8; em[1343] = 1; /* 1341: pointer.struct.bn_blinding_st */
    	em[1344] = 705; em[1345] = 0; 
    em[1346] = 0; em[1347] = 8; em[1348] = 5; /* 1346: union.unknown */
    	em[1349] = 114; em[1350] = 0; 
    	em[1351] = 1359; em[1352] = 0; 
    	em[1353] = 257; em[1354] = 0; 
    	em[1355] = 1364; em[1356] = 0; 
    	em[1357] = 1490; em[1358] = 0; 
    em[1359] = 1; em[1360] = 8; em[1361] = 1; /* 1359: pointer.struct.rsa_st */
    	em[1362] = 1294; em[1363] = 0; 
    em[1364] = 1; em[1365] = 8; em[1366] = 1; /* 1364: pointer.struct.dh_st */
    	em[1367] = 1369; em[1368] = 0; 
    em[1369] = 0; em[1370] = 144; em[1371] = 12; /* 1369: struct.dh_st */
    	em[1372] = 1396; em[1373] = 8; 
    	em[1374] = 1396; em[1375] = 16; 
    	em[1376] = 1396; em[1377] = 32; 
    	em[1378] = 1396; em[1379] = 40; 
    	em[1380] = 1413; em[1381] = 56; 
    	em[1382] = 1396; em[1383] = 64; 
    	em[1384] = 1396; em[1385] = 72; 
    	em[1386] = 18; em[1387] = 80; 
    	em[1388] = 1396; em[1389] = 96; 
    	em[1390] = 1427; em[1391] = 112; 
    	em[1392] = 1449; em[1393] = 128; 
    	em[1394] = 1485; em[1395] = 136; 
    em[1396] = 1; em[1397] = 8; em[1398] = 1; /* 1396: pointer.struct.bignum_st */
    	em[1399] = 1401; em[1400] = 0; 
    em[1401] = 0; em[1402] = 24; em[1403] = 1; /* 1401: struct.bignum_st */
    	em[1404] = 1406; em[1405] = 0; 
    em[1406] = 8884099; em[1407] = 8; em[1408] = 2; /* 1406: pointer_to_array_of_pointers_to_stack */
    	em[1409] = 304; em[1410] = 0; 
    	em[1411] = 307; em[1412] = 12; 
    em[1413] = 1; em[1414] = 8; em[1415] = 1; /* 1413: pointer.struct.bn_mont_ctx_st */
    	em[1416] = 1418; em[1417] = 0; 
    em[1418] = 0; em[1419] = 96; em[1420] = 3; /* 1418: struct.bn_mont_ctx_st */
    	em[1421] = 1401; em[1422] = 8; 
    	em[1423] = 1401; em[1424] = 32; 
    	em[1425] = 1401; em[1426] = 56; 
    em[1427] = 0; em[1428] = 16; em[1429] = 1; /* 1427: struct.crypto_ex_data_st */
    	em[1430] = 1432; em[1431] = 0; 
    em[1432] = 1; em[1433] = 8; em[1434] = 1; /* 1432: pointer.struct.stack_st_void */
    	em[1435] = 1437; em[1436] = 0; 
    em[1437] = 0; em[1438] = 32; em[1439] = 1; /* 1437: struct.stack_st_void */
    	em[1440] = 1442; em[1441] = 0; 
    em[1442] = 0; em[1443] = 32; em[1444] = 2; /* 1442: struct.stack_st */
    	em[1445] = 346; em[1446] = 8; 
    	em[1447] = 351; em[1448] = 24; 
    em[1449] = 1; em[1450] = 8; em[1451] = 1; /* 1449: pointer.struct.dh_method */
    	em[1452] = 1454; em[1453] = 0; 
    em[1454] = 0; em[1455] = 72; em[1456] = 8; /* 1454: struct.dh_method */
    	em[1457] = 133; em[1458] = 0; 
    	em[1459] = 1473; em[1460] = 8; 
    	em[1461] = 1476; em[1462] = 16; 
    	em[1463] = 1479; em[1464] = 24; 
    	em[1465] = 1473; em[1466] = 32; 
    	em[1467] = 1473; em[1468] = 40; 
    	em[1469] = 114; em[1470] = 56; 
    	em[1471] = 1482; em[1472] = 64; 
    em[1473] = 8884097; em[1474] = 8; em[1475] = 0; /* 1473: pointer.func */
    em[1476] = 8884097; em[1477] = 8; em[1478] = 0; /* 1476: pointer.func */
    em[1479] = 8884097; em[1480] = 8; em[1481] = 0; /* 1479: pointer.func */
    em[1482] = 8884097; em[1483] = 8; em[1484] = 0; /* 1482: pointer.func */
    em[1485] = 1; em[1486] = 8; em[1487] = 1; /* 1485: pointer.struct.engine_st */
    	em[1488] = 359; em[1489] = 0; 
    em[1490] = 1; em[1491] = 8; em[1492] = 1; /* 1490: pointer.struct.ec_key_st */
    	em[1493] = 1495; em[1494] = 0; 
    em[1495] = 0; em[1496] = 56; em[1497] = 4; /* 1495: struct.ec_key_st */
    	em[1498] = 1506; em[1499] = 8; 
    	em[1500] = 1750; em[1501] = 16; 
    	em[1502] = 1755; em[1503] = 24; 
    	em[1504] = 1772; em[1505] = 48; 
    em[1506] = 1; em[1507] = 8; em[1508] = 1; /* 1506: pointer.struct.ec_group_st */
    	em[1509] = 1511; em[1510] = 0; 
    em[1511] = 0; em[1512] = 232; em[1513] = 12; /* 1511: struct.ec_group_st */
    	em[1514] = 1538; em[1515] = 0; 
    	em[1516] = 1701; em[1517] = 8; 
    	em[1518] = 1706; em[1519] = 16; 
    	em[1520] = 1706; em[1521] = 40; 
    	em[1522] = 18; em[1523] = 80; 
    	em[1524] = 1718; em[1525] = 96; 
    	em[1526] = 1706; em[1527] = 104; 
    	em[1528] = 1706; em[1529] = 152; 
    	em[1530] = 1706; em[1531] = 176; 
    	em[1532] = 702; em[1533] = 208; 
    	em[1534] = 702; em[1535] = 216; 
    	em[1536] = 1747; em[1537] = 224; 
    em[1538] = 1; em[1539] = 8; em[1540] = 1; /* 1538: pointer.struct.ec_method_st */
    	em[1541] = 1543; em[1542] = 0; 
    em[1543] = 0; em[1544] = 304; em[1545] = 37; /* 1543: struct.ec_method_st */
    	em[1546] = 1620; em[1547] = 8; 
    	em[1548] = 1623; em[1549] = 16; 
    	em[1550] = 1623; em[1551] = 24; 
    	em[1552] = 1626; em[1553] = 32; 
    	em[1554] = 1018; em[1555] = 40; 
    	em[1556] = 1629; em[1557] = 48; 
    	em[1558] = 1632; em[1559] = 56; 
    	em[1560] = 1635; em[1561] = 64; 
    	em[1562] = 1638; em[1563] = 72; 
    	em[1564] = 1641; em[1565] = 80; 
    	em[1566] = 1641; em[1567] = 88; 
    	em[1568] = 1644; em[1569] = 96; 
    	em[1570] = 1647; em[1571] = 104; 
    	em[1572] = 1650; em[1573] = 112; 
    	em[1574] = 1653; em[1575] = 120; 
    	em[1576] = 1656; em[1577] = 128; 
    	em[1578] = 1659; em[1579] = 136; 
    	em[1580] = 802; em[1581] = 144; 
    	em[1582] = 1662; em[1583] = 152; 
    	em[1584] = 1665; em[1585] = 160; 
    	em[1586] = 1668; em[1587] = 168; 
    	em[1588] = 1671; em[1589] = 176; 
    	em[1590] = 1674; em[1591] = 184; 
    	em[1592] = 1677; em[1593] = 192; 
    	em[1594] = 1680; em[1595] = 200; 
    	em[1596] = 1683; em[1597] = 208; 
    	em[1598] = 1674; em[1599] = 216; 
    	em[1600] = 810; em[1601] = 224; 
    	em[1602] = 1686; em[1603] = 232; 
    	em[1604] = 1689; em[1605] = 240; 
    	em[1606] = 1632; em[1607] = 248; 
    	em[1608] = 1692; em[1609] = 256; 
    	em[1610] = 1695; em[1611] = 264; 
    	em[1612] = 1692; em[1613] = 272; 
    	em[1614] = 1695; em[1615] = 280; 
    	em[1616] = 1695; em[1617] = 288; 
    	em[1618] = 1698; em[1619] = 296; 
    em[1620] = 8884097; em[1621] = 8; em[1622] = 0; /* 1620: pointer.func */
    em[1623] = 8884097; em[1624] = 8; em[1625] = 0; /* 1623: pointer.func */
    em[1626] = 8884097; em[1627] = 8; em[1628] = 0; /* 1626: pointer.func */
    em[1629] = 8884097; em[1630] = 8; em[1631] = 0; /* 1629: pointer.func */
    em[1632] = 8884097; em[1633] = 8; em[1634] = 0; /* 1632: pointer.func */
    em[1635] = 8884097; em[1636] = 8; em[1637] = 0; /* 1635: pointer.func */
    em[1638] = 8884097; em[1639] = 8; em[1640] = 0; /* 1638: pointer.func */
    em[1641] = 8884097; em[1642] = 8; em[1643] = 0; /* 1641: pointer.func */
    em[1644] = 8884097; em[1645] = 8; em[1646] = 0; /* 1644: pointer.func */
    em[1647] = 8884097; em[1648] = 8; em[1649] = 0; /* 1647: pointer.func */
    em[1650] = 8884097; em[1651] = 8; em[1652] = 0; /* 1650: pointer.func */
    em[1653] = 8884097; em[1654] = 8; em[1655] = 0; /* 1653: pointer.func */
    em[1656] = 8884097; em[1657] = 8; em[1658] = 0; /* 1656: pointer.func */
    em[1659] = 8884097; em[1660] = 8; em[1661] = 0; /* 1659: pointer.func */
    em[1662] = 8884097; em[1663] = 8; em[1664] = 0; /* 1662: pointer.func */
    em[1665] = 8884097; em[1666] = 8; em[1667] = 0; /* 1665: pointer.func */
    em[1668] = 8884097; em[1669] = 8; em[1670] = 0; /* 1668: pointer.func */
    em[1671] = 8884097; em[1672] = 8; em[1673] = 0; /* 1671: pointer.func */
    em[1674] = 8884097; em[1675] = 8; em[1676] = 0; /* 1674: pointer.func */
    em[1677] = 8884097; em[1678] = 8; em[1679] = 0; /* 1677: pointer.func */
    em[1680] = 8884097; em[1681] = 8; em[1682] = 0; /* 1680: pointer.func */
    em[1683] = 8884097; em[1684] = 8; em[1685] = 0; /* 1683: pointer.func */
    em[1686] = 8884097; em[1687] = 8; em[1688] = 0; /* 1686: pointer.func */
    em[1689] = 8884097; em[1690] = 8; em[1691] = 0; /* 1689: pointer.func */
    em[1692] = 8884097; em[1693] = 8; em[1694] = 0; /* 1692: pointer.func */
    em[1695] = 8884097; em[1696] = 8; em[1697] = 0; /* 1695: pointer.func */
    em[1698] = 8884097; em[1699] = 8; em[1700] = 0; /* 1698: pointer.func */
    em[1701] = 1; em[1702] = 8; em[1703] = 1; /* 1701: pointer.struct.ec_point_st */
    	em[1704] = 813; em[1705] = 0; 
    em[1706] = 0; em[1707] = 24; em[1708] = 1; /* 1706: struct.bignum_st */
    	em[1709] = 1711; em[1710] = 0; 
    em[1711] = 8884099; em[1712] = 8; em[1713] = 2; /* 1711: pointer_to_array_of_pointers_to_stack */
    	em[1714] = 304; em[1715] = 0; 
    	em[1716] = 307; em[1717] = 12; 
    em[1718] = 1; em[1719] = 8; em[1720] = 1; /* 1718: pointer.struct.ec_extra_data_st */
    	em[1721] = 1723; em[1722] = 0; 
    em[1723] = 0; em[1724] = 40; em[1725] = 5; /* 1723: struct.ec_extra_data_st */
    	em[1726] = 1736; em[1727] = 0; 
    	em[1728] = 702; em[1729] = 8; 
    	em[1730] = 1741; em[1731] = 16; 
    	em[1732] = 1744; em[1733] = 24; 
    	em[1734] = 1744; em[1735] = 32; 
    em[1736] = 1; em[1737] = 8; em[1738] = 1; /* 1736: pointer.struct.ec_extra_data_st */
    	em[1739] = 1723; em[1740] = 0; 
    em[1741] = 8884097; em[1742] = 8; em[1743] = 0; /* 1741: pointer.func */
    em[1744] = 8884097; em[1745] = 8; em[1746] = 0; /* 1744: pointer.func */
    em[1747] = 8884097; em[1748] = 8; em[1749] = 0; /* 1747: pointer.func */
    em[1750] = 1; em[1751] = 8; em[1752] = 1; /* 1750: pointer.struct.ec_point_st */
    	em[1753] = 813; em[1754] = 0; 
    em[1755] = 1; em[1756] = 8; em[1757] = 1; /* 1755: pointer.struct.bignum_st */
    	em[1758] = 1760; em[1759] = 0; 
    em[1760] = 0; em[1761] = 24; em[1762] = 1; /* 1760: struct.bignum_st */
    	em[1763] = 1765; em[1764] = 0; 
    em[1765] = 8884099; em[1766] = 8; em[1767] = 2; /* 1765: pointer_to_array_of_pointers_to_stack */
    	em[1768] = 304; em[1769] = 0; 
    	em[1770] = 307; em[1771] = 12; 
    em[1772] = 1; em[1773] = 8; em[1774] = 1; /* 1772: pointer.struct.ec_extra_data_st */
    	em[1775] = 1777; em[1776] = 0; 
    em[1777] = 0; em[1778] = 40; em[1779] = 5; /* 1777: struct.ec_extra_data_st */
    	em[1780] = 1790; em[1781] = 0; 
    	em[1782] = 702; em[1783] = 8; 
    	em[1784] = 1741; em[1785] = 16; 
    	em[1786] = 1744; em[1787] = 24; 
    	em[1788] = 1744; em[1789] = 32; 
    em[1790] = 1; em[1791] = 8; em[1792] = 1; /* 1790: pointer.struct.ec_extra_data_st */
    	em[1793] = 1777; em[1794] = 0; 
    em[1795] = 1; em[1796] = 8; em[1797] = 1; /* 1795: pointer.struct.evp_pkey_asn1_method_st */
    	em[1798] = 1152; em[1799] = 0; 
    em[1800] = 8884099; em[1801] = 8; em[1802] = 2; /* 1800: pointer_to_array_of_pointers_to_stack */
    	em[1803] = 1049; em[1804] = 0; 
    	em[1805] = 307; em[1806] = 20; 
    em[1807] = 0; em[1808] = 24; em[1809] = 2; /* 1807: struct.x509_attributes_st */
    	em[1810] = 119; em[1811] = 0; 
    	em[1812] = 1814; em[1813] = 16; 
    em[1814] = 0; em[1815] = 8; em[1816] = 3; /* 1814: union.unknown */
    	em[1817] = 114; em[1818] = 0; 
    	em[1819] = 1823; em[1820] = 0; 
    	em[1821] = 1835; em[1822] = 0; 
    em[1823] = 1; em[1824] = 8; em[1825] = 1; /* 1823: pointer.struct.stack_st_ASN1_TYPE */
    	em[1826] = 1828; em[1827] = 0; 
    em[1828] = 0; em[1829] = 32; em[1830] = 2; /* 1828: struct.stack_st_fake_ASN1_TYPE */
    	em[1831] = 1800; em[1832] = 8; 
    	em[1833] = 351; em[1834] = 24; 
    em[1835] = 1; em[1836] = 8; em[1837] = 1; /* 1835: pointer.struct.asn1_type_st */
    	em[1838] = 66; em[1839] = 0; 
    em[1840] = 0; em[1841] = 56; em[1842] = 4; /* 1840: struct.evp_pkey_st */
    	em[1843] = 1795; em[1844] = 16; 
    	em[1845] = 1485; em[1846] = 24; 
    	em[1847] = 1346; em[1848] = 32; 
    	em[1849] = 1851; em[1850] = 48; 
    em[1851] = 1; em[1852] = 8; em[1853] = 1; /* 1851: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[1854] = 1856; em[1855] = 0; 
    em[1856] = 0; em[1857] = 32; em[1858] = 2; /* 1856: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[1859] = 1863; em[1860] = 8; 
    	em[1861] = 351; em[1862] = 24; 
    em[1863] = 8884099; em[1864] = 8; em[1865] = 2; /* 1863: pointer_to_array_of_pointers_to_stack */
    	em[1866] = 1870; em[1867] = 0; 
    	em[1868] = 307; em[1869] = 20; 
    em[1870] = 0; em[1871] = 8; em[1872] = 1; /* 1870: pointer.X509_ATTRIBUTE */
    	em[1873] = 1875; em[1874] = 0; 
    em[1875] = 0; em[1876] = 0; em[1877] = 1; /* 1875: X509_ATTRIBUTE */
    	em[1878] = 1807; em[1879] = 0; 
    em[1880] = 1; em[1881] = 8; em[1882] = 1; /* 1880: pointer.struct.evp_pkey_st */
    	em[1883] = 1840; em[1884] = 0; 
    args_addr->arg_entity_index[0] = 1880;
    args_addr->ret_entity_index = 307;
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

