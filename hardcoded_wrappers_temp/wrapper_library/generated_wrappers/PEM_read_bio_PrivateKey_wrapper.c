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
    em[3] = 0; em[4] = 32; em[5] = 2; /* 3: struct.stack_st */
    	em[6] = 10; em[7] = 8; 
    	em[8] = 20; em[9] = 24; 
    em[10] = 1; em[11] = 8; em[12] = 1; /* 10: pointer.pointer.char */
    	em[13] = 15; em[14] = 0; 
    em[15] = 1; em[16] = 8; em[17] = 1; /* 15: pointer.char */
    	em[18] = 8884096; em[19] = 0; 
    em[20] = 8884097; em[21] = 8; em[22] = 0; /* 20: pointer.func */
    em[23] = 0; em[24] = 32; em[25] = 1; /* 23: struct.stack_st_void */
    	em[26] = 3; em[27] = 0; 
    em[28] = 1; em[29] = 8; em[30] = 1; /* 28: pointer.struct.stack_st_void */
    	em[31] = 23; em[32] = 0; 
    em[33] = 0; em[34] = 16; em[35] = 1; /* 33: struct.crypto_ex_data_st */
    	em[36] = 28; em[37] = 0; 
    em[38] = 1; em[39] = 8; em[40] = 1; /* 38: pointer.struct.bio_st */
    	em[41] = 43; em[42] = 0; 
    em[43] = 0; em[44] = 112; em[45] = 7; /* 43: struct.bio_st */
    	em[46] = 60; em[47] = 0; 
    	em[48] = 109; em[49] = 8; 
    	em[50] = 15; em[51] = 16; 
    	em[52] = 112; em[53] = 48; 
    	em[54] = 38; em[55] = 56; 
    	em[56] = 38; em[57] = 64; 
    	em[58] = 33; em[59] = 96; 
    em[60] = 1; em[61] = 8; em[62] = 1; /* 60: pointer.struct.bio_method_st */
    	em[63] = 65; em[64] = 0; 
    em[65] = 0; em[66] = 80; em[67] = 9; /* 65: struct.bio_method_st */
    	em[68] = 86; em[69] = 8; 
    	em[70] = 91; em[71] = 16; 
    	em[72] = 94; em[73] = 24; 
    	em[74] = 97; em[75] = 32; 
    	em[76] = 94; em[77] = 40; 
    	em[78] = 100; em[79] = 48; 
    	em[80] = 103; em[81] = 56; 
    	em[82] = 103; em[83] = 64; 
    	em[84] = 106; em[85] = 72; 
    em[86] = 1; em[87] = 8; em[88] = 1; /* 86: pointer.char */
    	em[89] = 8884096; em[90] = 0; 
    em[91] = 8884097; em[92] = 8; em[93] = 0; /* 91: pointer.func */
    em[94] = 8884097; em[95] = 8; em[96] = 0; /* 94: pointer.func */
    em[97] = 8884097; em[98] = 8; em[99] = 0; /* 97: pointer.func */
    em[100] = 8884097; em[101] = 8; em[102] = 0; /* 100: pointer.func */
    em[103] = 8884097; em[104] = 8; em[105] = 0; /* 103: pointer.func */
    em[106] = 8884097; em[107] = 8; em[108] = 0; /* 106: pointer.func */
    em[109] = 8884097; em[110] = 8; em[111] = 0; /* 109: pointer.func */
    em[112] = 0; em[113] = 8; em[114] = 0; /* 112: pointer.void */
    em[115] = 1; em[116] = 8; em[117] = 1; /* 115: pointer.struct.bio_st */
    	em[118] = 43; em[119] = 0; 
    em[120] = 1; em[121] = 8; em[122] = 1; /* 120: pointer.struct.ASN1_VALUE_st */
    	em[123] = 125; em[124] = 0; 
    em[125] = 0; em[126] = 0; em[127] = 0; /* 125: struct.ASN1_VALUE_st */
    em[128] = 1; em[129] = 8; em[130] = 1; /* 128: pointer.struct.asn1_string_st */
    	em[131] = 133; em[132] = 0; 
    em[133] = 0; em[134] = 24; em[135] = 1; /* 133: struct.asn1_string_st */
    	em[136] = 138; em[137] = 8; 
    em[138] = 1; em[139] = 8; em[140] = 1; /* 138: pointer.unsigned char */
    	em[141] = 143; em[142] = 0; 
    em[143] = 0; em[144] = 1; em[145] = 0; /* 143: unsigned char */
    em[146] = 1; em[147] = 8; em[148] = 1; /* 146: pointer.struct.asn1_string_st */
    	em[149] = 133; em[150] = 0; 
    em[151] = 1; em[152] = 8; em[153] = 1; /* 151: pointer.struct.asn1_string_st */
    	em[154] = 133; em[155] = 0; 
    em[156] = 1; em[157] = 8; em[158] = 1; /* 156: pointer.struct.asn1_string_st */
    	em[159] = 133; em[160] = 0; 
    em[161] = 1; em[162] = 8; em[163] = 1; /* 161: pointer.struct.asn1_string_st */
    	em[164] = 133; em[165] = 0; 
    em[166] = 1; em[167] = 8; em[168] = 1; /* 166: pointer.struct.asn1_string_st */
    	em[169] = 133; em[170] = 0; 
    em[171] = 1; em[172] = 8; em[173] = 1; /* 171: pointer.struct.asn1_string_st */
    	em[174] = 133; em[175] = 0; 
    em[176] = 1; em[177] = 8; em[178] = 1; /* 176: pointer.struct.asn1_string_st */
    	em[179] = 133; em[180] = 0; 
    em[181] = 1; em[182] = 8; em[183] = 1; /* 181: pointer.struct.asn1_string_st */
    	em[184] = 133; em[185] = 0; 
    em[186] = 1; em[187] = 8; em[188] = 1; /* 186: pointer.struct.asn1_string_st */
    	em[189] = 133; em[190] = 0; 
    em[191] = 1; em[192] = 8; em[193] = 1; /* 191: pointer.struct.asn1_string_st */
    	em[194] = 133; em[195] = 0; 
    em[196] = 1; em[197] = 8; em[198] = 1; /* 196: pointer.struct.asn1_string_st */
    	em[199] = 133; em[200] = 0; 
    em[201] = 1; em[202] = 8; em[203] = 1; /* 201: pointer.struct.asn1_string_st */
    	em[204] = 133; em[205] = 0; 
    em[206] = 0; em[207] = 16; em[208] = 1; /* 206: struct.asn1_type_st */
    	em[209] = 211; em[210] = 8; 
    em[211] = 0; em[212] = 8; em[213] = 20; /* 211: union.unknown */
    	em[214] = 15; em[215] = 0; 
    	em[216] = 201; em[217] = 0; 
    	em[218] = 254; em[219] = 0; 
    	em[220] = 273; em[221] = 0; 
    	em[222] = 196; em[223] = 0; 
    	em[224] = 191; em[225] = 0; 
    	em[226] = 186; em[227] = 0; 
    	em[228] = 181; em[229] = 0; 
    	em[230] = 278; em[231] = 0; 
    	em[232] = 176; em[233] = 0; 
    	em[234] = 171; em[235] = 0; 
    	em[236] = 166; em[237] = 0; 
    	em[238] = 161; em[239] = 0; 
    	em[240] = 156; em[241] = 0; 
    	em[242] = 151; em[243] = 0; 
    	em[244] = 146; em[245] = 0; 
    	em[246] = 128; em[247] = 0; 
    	em[248] = 201; em[249] = 0; 
    	em[250] = 201; em[251] = 0; 
    	em[252] = 120; em[253] = 0; 
    em[254] = 1; em[255] = 8; em[256] = 1; /* 254: pointer.struct.asn1_object_st */
    	em[257] = 259; em[258] = 0; 
    em[259] = 0; em[260] = 40; em[261] = 3; /* 259: struct.asn1_object_st */
    	em[262] = 86; em[263] = 0; 
    	em[264] = 86; em[265] = 8; 
    	em[266] = 268; em[267] = 24; 
    em[268] = 1; em[269] = 8; em[270] = 1; /* 268: pointer.unsigned char */
    	em[271] = 143; em[272] = 0; 
    em[273] = 1; em[274] = 8; em[275] = 1; /* 273: pointer.struct.asn1_string_st */
    	em[276] = 133; em[277] = 0; 
    em[278] = 1; em[279] = 8; em[280] = 1; /* 278: pointer.struct.asn1_string_st */
    	em[281] = 133; em[282] = 0; 
    em[283] = 1; em[284] = 8; em[285] = 1; /* 283: pointer.struct.asn1_string_st */
    	em[286] = 288; em[287] = 0; 
    em[288] = 0; em[289] = 24; em[290] = 1; /* 288: struct.asn1_string_st */
    	em[291] = 138; em[292] = 8; 
    em[293] = 8884099; em[294] = 8; em[295] = 2; /* 293: pointer_to_array_of_pointers_to_stack */
    	em[296] = 300; em[297] = 0; 
    	em[298] = 450; em[299] = 20; 
    em[300] = 0; em[301] = 8; em[302] = 1; /* 300: pointer.ASN1_TYPE */
    	em[303] = 305; em[304] = 0; 
    em[305] = 0; em[306] = 0; em[307] = 1; /* 305: ASN1_TYPE */
    	em[308] = 310; em[309] = 0; 
    em[310] = 0; em[311] = 16; em[312] = 1; /* 310: struct.asn1_type_st */
    	em[313] = 315; em[314] = 8; 
    em[315] = 0; em[316] = 8; em[317] = 20; /* 315: union.unknown */
    	em[318] = 15; em[319] = 0; 
    	em[320] = 358; em[321] = 0; 
    	em[322] = 363; em[323] = 0; 
    	em[324] = 377; em[325] = 0; 
    	em[326] = 382; em[327] = 0; 
    	em[328] = 387; em[329] = 0; 
    	em[330] = 392; em[331] = 0; 
    	em[332] = 397; em[333] = 0; 
    	em[334] = 402; em[335] = 0; 
    	em[336] = 407; em[337] = 0; 
    	em[338] = 412; em[339] = 0; 
    	em[340] = 417; em[341] = 0; 
    	em[342] = 422; em[343] = 0; 
    	em[344] = 427; em[345] = 0; 
    	em[346] = 432; em[347] = 0; 
    	em[348] = 437; em[349] = 0; 
    	em[350] = 283; em[351] = 0; 
    	em[352] = 358; em[353] = 0; 
    	em[354] = 358; em[355] = 0; 
    	em[356] = 442; em[357] = 0; 
    em[358] = 1; em[359] = 8; em[360] = 1; /* 358: pointer.struct.asn1_string_st */
    	em[361] = 288; em[362] = 0; 
    em[363] = 1; em[364] = 8; em[365] = 1; /* 363: pointer.struct.asn1_object_st */
    	em[366] = 368; em[367] = 0; 
    em[368] = 0; em[369] = 40; em[370] = 3; /* 368: struct.asn1_object_st */
    	em[371] = 86; em[372] = 0; 
    	em[373] = 86; em[374] = 8; 
    	em[375] = 268; em[376] = 24; 
    em[377] = 1; em[378] = 8; em[379] = 1; /* 377: pointer.struct.asn1_string_st */
    	em[380] = 288; em[381] = 0; 
    em[382] = 1; em[383] = 8; em[384] = 1; /* 382: pointer.struct.asn1_string_st */
    	em[385] = 288; em[386] = 0; 
    em[387] = 1; em[388] = 8; em[389] = 1; /* 387: pointer.struct.asn1_string_st */
    	em[390] = 288; em[391] = 0; 
    em[392] = 1; em[393] = 8; em[394] = 1; /* 392: pointer.struct.asn1_string_st */
    	em[395] = 288; em[396] = 0; 
    em[397] = 1; em[398] = 8; em[399] = 1; /* 397: pointer.struct.asn1_string_st */
    	em[400] = 288; em[401] = 0; 
    em[402] = 1; em[403] = 8; em[404] = 1; /* 402: pointer.struct.asn1_string_st */
    	em[405] = 288; em[406] = 0; 
    em[407] = 1; em[408] = 8; em[409] = 1; /* 407: pointer.struct.asn1_string_st */
    	em[410] = 288; em[411] = 0; 
    em[412] = 1; em[413] = 8; em[414] = 1; /* 412: pointer.struct.asn1_string_st */
    	em[415] = 288; em[416] = 0; 
    em[417] = 1; em[418] = 8; em[419] = 1; /* 417: pointer.struct.asn1_string_st */
    	em[420] = 288; em[421] = 0; 
    em[422] = 1; em[423] = 8; em[424] = 1; /* 422: pointer.struct.asn1_string_st */
    	em[425] = 288; em[426] = 0; 
    em[427] = 1; em[428] = 8; em[429] = 1; /* 427: pointer.struct.asn1_string_st */
    	em[430] = 288; em[431] = 0; 
    em[432] = 1; em[433] = 8; em[434] = 1; /* 432: pointer.struct.asn1_string_st */
    	em[435] = 288; em[436] = 0; 
    em[437] = 1; em[438] = 8; em[439] = 1; /* 437: pointer.struct.asn1_string_st */
    	em[440] = 288; em[441] = 0; 
    em[442] = 1; em[443] = 8; em[444] = 1; /* 442: pointer.struct.ASN1_VALUE_st */
    	em[445] = 447; em[446] = 0; 
    em[447] = 0; em[448] = 0; em[449] = 0; /* 447: struct.ASN1_VALUE_st */
    em[450] = 0; em[451] = 4; em[452] = 0; /* 450: int */
    em[453] = 8884097; em[454] = 8; em[455] = 0; /* 453: pointer.func */
    em[456] = 1; em[457] = 8; em[458] = 1; /* 456: pointer.struct.dh_st */
    	em[459] = 461; em[460] = 0; 
    em[461] = 0; em[462] = 144; em[463] = 12; /* 461: struct.dh_st */
    	em[464] = 488; em[465] = 8; 
    	em[466] = 488; em[467] = 16; 
    	em[468] = 488; em[469] = 32; 
    	em[470] = 488; em[471] = 40; 
    	em[472] = 508; em[473] = 56; 
    	em[474] = 488; em[475] = 64; 
    	em[476] = 488; em[477] = 72; 
    	em[478] = 138; em[479] = 80; 
    	em[480] = 488; em[481] = 96; 
    	em[482] = 522; em[483] = 112; 
    	em[484] = 544; em[485] = 128; 
    	em[486] = 580; em[487] = 136; 
    em[488] = 1; em[489] = 8; em[490] = 1; /* 488: pointer.struct.bignum_st */
    	em[491] = 493; em[492] = 0; 
    em[493] = 0; em[494] = 24; em[495] = 1; /* 493: struct.bignum_st */
    	em[496] = 498; em[497] = 0; 
    em[498] = 8884099; em[499] = 8; em[500] = 2; /* 498: pointer_to_array_of_pointers_to_stack */
    	em[501] = 505; em[502] = 0; 
    	em[503] = 450; em[504] = 12; 
    em[505] = 0; em[506] = 8; em[507] = 0; /* 505: long unsigned int */
    em[508] = 1; em[509] = 8; em[510] = 1; /* 508: pointer.struct.bn_mont_ctx_st */
    	em[511] = 513; em[512] = 0; 
    em[513] = 0; em[514] = 96; em[515] = 3; /* 513: struct.bn_mont_ctx_st */
    	em[516] = 493; em[517] = 8; 
    	em[518] = 493; em[519] = 32; 
    	em[520] = 493; em[521] = 56; 
    em[522] = 0; em[523] = 16; em[524] = 1; /* 522: struct.crypto_ex_data_st */
    	em[525] = 527; em[526] = 0; 
    em[527] = 1; em[528] = 8; em[529] = 1; /* 527: pointer.struct.stack_st_void */
    	em[530] = 532; em[531] = 0; 
    em[532] = 0; em[533] = 32; em[534] = 1; /* 532: struct.stack_st_void */
    	em[535] = 537; em[536] = 0; 
    em[537] = 0; em[538] = 32; em[539] = 2; /* 537: struct.stack_st */
    	em[540] = 10; em[541] = 8; 
    	em[542] = 20; em[543] = 24; 
    em[544] = 1; em[545] = 8; em[546] = 1; /* 544: pointer.struct.dh_method */
    	em[547] = 549; em[548] = 0; 
    em[549] = 0; em[550] = 72; em[551] = 8; /* 549: struct.dh_method */
    	em[552] = 86; em[553] = 0; 
    	em[554] = 568; em[555] = 8; 
    	em[556] = 571; em[557] = 16; 
    	em[558] = 574; em[559] = 24; 
    	em[560] = 568; em[561] = 32; 
    	em[562] = 568; em[563] = 40; 
    	em[564] = 15; em[565] = 56; 
    	em[566] = 577; em[567] = 64; 
    em[568] = 8884097; em[569] = 8; em[570] = 0; /* 568: pointer.func */
    em[571] = 8884097; em[572] = 8; em[573] = 0; /* 571: pointer.func */
    em[574] = 8884097; em[575] = 8; em[576] = 0; /* 574: pointer.func */
    em[577] = 8884097; em[578] = 8; em[579] = 0; /* 577: pointer.func */
    em[580] = 1; em[581] = 8; em[582] = 1; /* 580: pointer.struct.engine_st */
    	em[583] = 585; em[584] = 0; 
    em[585] = 0; em[586] = 216; em[587] = 24; /* 585: struct.engine_st */
    	em[588] = 86; em[589] = 0; 
    	em[590] = 86; em[591] = 8; 
    	em[592] = 636; em[593] = 16; 
    	em[594] = 691; em[595] = 24; 
    	em[596] = 742; em[597] = 32; 
    	em[598] = 778; em[599] = 40; 
    	em[600] = 795; em[601] = 48; 
    	em[602] = 822; em[603] = 56; 
    	em[604] = 857; em[605] = 64; 
    	em[606] = 865; em[607] = 72; 
    	em[608] = 868; em[609] = 80; 
    	em[610] = 871; em[611] = 88; 
    	em[612] = 874; em[613] = 96; 
    	em[614] = 877; em[615] = 104; 
    	em[616] = 877; em[617] = 112; 
    	em[618] = 877; em[619] = 120; 
    	em[620] = 880; em[621] = 128; 
    	em[622] = 883; em[623] = 136; 
    	em[624] = 883; em[625] = 144; 
    	em[626] = 886; em[627] = 152; 
    	em[628] = 889; em[629] = 160; 
    	em[630] = 901; em[631] = 184; 
    	em[632] = 923; em[633] = 200; 
    	em[634] = 923; em[635] = 208; 
    em[636] = 1; em[637] = 8; em[638] = 1; /* 636: pointer.struct.rsa_meth_st */
    	em[639] = 641; em[640] = 0; 
    em[641] = 0; em[642] = 112; em[643] = 13; /* 641: struct.rsa_meth_st */
    	em[644] = 86; em[645] = 0; 
    	em[646] = 670; em[647] = 8; 
    	em[648] = 670; em[649] = 16; 
    	em[650] = 670; em[651] = 24; 
    	em[652] = 670; em[653] = 32; 
    	em[654] = 673; em[655] = 40; 
    	em[656] = 676; em[657] = 48; 
    	em[658] = 679; em[659] = 56; 
    	em[660] = 679; em[661] = 64; 
    	em[662] = 15; em[663] = 80; 
    	em[664] = 682; em[665] = 88; 
    	em[666] = 685; em[667] = 96; 
    	em[668] = 688; em[669] = 104; 
    em[670] = 8884097; em[671] = 8; em[672] = 0; /* 670: pointer.func */
    em[673] = 8884097; em[674] = 8; em[675] = 0; /* 673: pointer.func */
    em[676] = 8884097; em[677] = 8; em[678] = 0; /* 676: pointer.func */
    em[679] = 8884097; em[680] = 8; em[681] = 0; /* 679: pointer.func */
    em[682] = 8884097; em[683] = 8; em[684] = 0; /* 682: pointer.func */
    em[685] = 8884097; em[686] = 8; em[687] = 0; /* 685: pointer.func */
    em[688] = 8884097; em[689] = 8; em[690] = 0; /* 688: pointer.func */
    em[691] = 1; em[692] = 8; em[693] = 1; /* 691: pointer.struct.dsa_method */
    	em[694] = 696; em[695] = 0; 
    em[696] = 0; em[697] = 96; em[698] = 11; /* 696: struct.dsa_method */
    	em[699] = 86; em[700] = 0; 
    	em[701] = 721; em[702] = 8; 
    	em[703] = 724; em[704] = 16; 
    	em[705] = 727; em[706] = 24; 
    	em[707] = 730; em[708] = 32; 
    	em[709] = 733; em[710] = 40; 
    	em[711] = 736; em[712] = 48; 
    	em[713] = 736; em[714] = 56; 
    	em[715] = 15; em[716] = 72; 
    	em[717] = 739; em[718] = 80; 
    	em[719] = 736; em[720] = 88; 
    em[721] = 8884097; em[722] = 8; em[723] = 0; /* 721: pointer.func */
    em[724] = 8884097; em[725] = 8; em[726] = 0; /* 724: pointer.func */
    em[727] = 8884097; em[728] = 8; em[729] = 0; /* 727: pointer.func */
    em[730] = 8884097; em[731] = 8; em[732] = 0; /* 730: pointer.func */
    em[733] = 8884097; em[734] = 8; em[735] = 0; /* 733: pointer.func */
    em[736] = 8884097; em[737] = 8; em[738] = 0; /* 736: pointer.func */
    em[739] = 8884097; em[740] = 8; em[741] = 0; /* 739: pointer.func */
    em[742] = 1; em[743] = 8; em[744] = 1; /* 742: pointer.struct.dh_method */
    	em[745] = 747; em[746] = 0; 
    em[747] = 0; em[748] = 72; em[749] = 8; /* 747: struct.dh_method */
    	em[750] = 86; em[751] = 0; 
    	em[752] = 766; em[753] = 8; 
    	em[754] = 769; em[755] = 16; 
    	em[756] = 772; em[757] = 24; 
    	em[758] = 766; em[759] = 32; 
    	em[760] = 766; em[761] = 40; 
    	em[762] = 15; em[763] = 56; 
    	em[764] = 775; em[765] = 64; 
    em[766] = 8884097; em[767] = 8; em[768] = 0; /* 766: pointer.func */
    em[769] = 8884097; em[770] = 8; em[771] = 0; /* 769: pointer.func */
    em[772] = 8884097; em[773] = 8; em[774] = 0; /* 772: pointer.func */
    em[775] = 8884097; em[776] = 8; em[777] = 0; /* 775: pointer.func */
    em[778] = 1; em[779] = 8; em[780] = 1; /* 778: pointer.struct.ecdh_method */
    	em[781] = 783; em[782] = 0; 
    em[783] = 0; em[784] = 32; em[785] = 3; /* 783: struct.ecdh_method */
    	em[786] = 86; em[787] = 0; 
    	em[788] = 792; em[789] = 8; 
    	em[790] = 15; em[791] = 24; 
    em[792] = 8884097; em[793] = 8; em[794] = 0; /* 792: pointer.func */
    em[795] = 1; em[796] = 8; em[797] = 1; /* 795: pointer.struct.ecdsa_method */
    	em[798] = 800; em[799] = 0; 
    em[800] = 0; em[801] = 48; em[802] = 5; /* 800: struct.ecdsa_method */
    	em[803] = 86; em[804] = 0; 
    	em[805] = 813; em[806] = 8; 
    	em[807] = 816; em[808] = 16; 
    	em[809] = 819; em[810] = 24; 
    	em[811] = 15; em[812] = 40; 
    em[813] = 8884097; em[814] = 8; em[815] = 0; /* 813: pointer.func */
    em[816] = 8884097; em[817] = 8; em[818] = 0; /* 816: pointer.func */
    em[819] = 8884097; em[820] = 8; em[821] = 0; /* 819: pointer.func */
    em[822] = 1; em[823] = 8; em[824] = 1; /* 822: pointer.struct.rand_meth_st */
    	em[825] = 827; em[826] = 0; 
    em[827] = 0; em[828] = 48; em[829] = 6; /* 827: struct.rand_meth_st */
    	em[830] = 842; em[831] = 0; 
    	em[832] = 845; em[833] = 8; 
    	em[834] = 848; em[835] = 16; 
    	em[836] = 851; em[837] = 24; 
    	em[838] = 845; em[839] = 32; 
    	em[840] = 854; em[841] = 40; 
    em[842] = 8884097; em[843] = 8; em[844] = 0; /* 842: pointer.func */
    em[845] = 8884097; em[846] = 8; em[847] = 0; /* 845: pointer.func */
    em[848] = 8884097; em[849] = 8; em[850] = 0; /* 848: pointer.func */
    em[851] = 8884097; em[852] = 8; em[853] = 0; /* 851: pointer.func */
    em[854] = 8884097; em[855] = 8; em[856] = 0; /* 854: pointer.func */
    em[857] = 1; em[858] = 8; em[859] = 1; /* 857: pointer.struct.store_method_st */
    	em[860] = 862; em[861] = 0; 
    em[862] = 0; em[863] = 0; em[864] = 0; /* 862: struct.store_method_st */
    em[865] = 8884097; em[866] = 8; em[867] = 0; /* 865: pointer.func */
    em[868] = 8884097; em[869] = 8; em[870] = 0; /* 868: pointer.func */
    em[871] = 8884097; em[872] = 8; em[873] = 0; /* 871: pointer.func */
    em[874] = 8884097; em[875] = 8; em[876] = 0; /* 874: pointer.func */
    em[877] = 8884097; em[878] = 8; em[879] = 0; /* 877: pointer.func */
    em[880] = 8884097; em[881] = 8; em[882] = 0; /* 880: pointer.func */
    em[883] = 8884097; em[884] = 8; em[885] = 0; /* 883: pointer.func */
    em[886] = 8884097; em[887] = 8; em[888] = 0; /* 886: pointer.func */
    em[889] = 1; em[890] = 8; em[891] = 1; /* 889: pointer.struct.ENGINE_CMD_DEFN_st */
    	em[892] = 894; em[893] = 0; 
    em[894] = 0; em[895] = 32; em[896] = 2; /* 894: struct.ENGINE_CMD_DEFN_st */
    	em[897] = 86; em[898] = 8; 
    	em[899] = 86; em[900] = 16; 
    em[901] = 0; em[902] = 16; em[903] = 1; /* 901: struct.crypto_ex_data_st */
    	em[904] = 906; em[905] = 0; 
    em[906] = 1; em[907] = 8; em[908] = 1; /* 906: pointer.struct.stack_st_void */
    	em[909] = 911; em[910] = 0; 
    em[911] = 0; em[912] = 32; em[913] = 1; /* 911: struct.stack_st_void */
    	em[914] = 916; em[915] = 0; 
    em[916] = 0; em[917] = 32; em[918] = 2; /* 916: struct.stack_st */
    	em[919] = 10; em[920] = 8; 
    	em[921] = 20; em[922] = 24; 
    em[923] = 1; em[924] = 8; em[925] = 1; /* 923: pointer.struct.engine_st */
    	em[926] = 585; em[927] = 0; 
    em[928] = 8884097; em[929] = 8; em[930] = 0; /* 928: pointer.func */
    em[931] = 0; em[932] = 136; em[933] = 11; /* 931: struct.dsa_st */
    	em[934] = 956; em[935] = 24; 
    	em[936] = 956; em[937] = 32; 
    	em[938] = 956; em[939] = 40; 
    	em[940] = 956; em[941] = 48; 
    	em[942] = 956; em[943] = 56; 
    	em[944] = 956; em[945] = 64; 
    	em[946] = 956; em[947] = 72; 
    	em[948] = 973; em[949] = 88; 
    	em[950] = 987; em[951] = 104; 
    	em[952] = 1009; em[953] = 120; 
    	em[954] = 580; em[955] = 128; 
    em[956] = 1; em[957] = 8; em[958] = 1; /* 956: pointer.struct.bignum_st */
    	em[959] = 961; em[960] = 0; 
    em[961] = 0; em[962] = 24; em[963] = 1; /* 961: struct.bignum_st */
    	em[964] = 966; em[965] = 0; 
    em[966] = 8884099; em[967] = 8; em[968] = 2; /* 966: pointer_to_array_of_pointers_to_stack */
    	em[969] = 505; em[970] = 0; 
    	em[971] = 450; em[972] = 12; 
    em[973] = 1; em[974] = 8; em[975] = 1; /* 973: pointer.struct.bn_mont_ctx_st */
    	em[976] = 978; em[977] = 0; 
    em[978] = 0; em[979] = 96; em[980] = 3; /* 978: struct.bn_mont_ctx_st */
    	em[981] = 961; em[982] = 8; 
    	em[983] = 961; em[984] = 32; 
    	em[985] = 961; em[986] = 56; 
    em[987] = 0; em[988] = 16; em[989] = 1; /* 987: struct.crypto_ex_data_st */
    	em[990] = 992; em[991] = 0; 
    em[992] = 1; em[993] = 8; em[994] = 1; /* 992: pointer.struct.stack_st_void */
    	em[995] = 997; em[996] = 0; 
    em[997] = 0; em[998] = 32; em[999] = 1; /* 997: struct.stack_st_void */
    	em[1000] = 1002; em[1001] = 0; 
    em[1002] = 0; em[1003] = 32; em[1004] = 2; /* 1002: struct.stack_st */
    	em[1005] = 10; em[1006] = 8; 
    	em[1007] = 20; em[1008] = 24; 
    em[1009] = 1; em[1010] = 8; em[1011] = 1; /* 1009: pointer.struct.dsa_method */
    	em[1012] = 1014; em[1013] = 0; 
    em[1014] = 0; em[1015] = 96; em[1016] = 11; /* 1014: struct.dsa_method */
    	em[1017] = 86; em[1018] = 0; 
    	em[1019] = 1039; em[1020] = 8; 
    	em[1021] = 1042; em[1022] = 16; 
    	em[1023] = 1045; em[1024] = 24; 
    	em[1025] = 453; em[1026] = 32; 
    	em[1027] = 1048; em[1028] = 40; 
    	em[1029] = 1051; em[1030] = 48; 
    	em[1031] = 1051; em[1032] = 56; 
    	em[1033] = 15; em[1034] = 72; 
    	em[1035] = 1054; em[1036] = 80; 
    	em[1037] = 1051; em[1038] = 88; 
    em[1039] = 8884097; em[1040] = 8; em[1041] = 0; /* 1039: pointer.func */
    em[1042] = 8884097; em[1043] = 8; em[1044] = 0; /* 1042: pointer.func */
    em[1045] = 8884097; em[1046] = 8; em[1047] = 0; /* 1045: pointer.func */
    em[1048] = 8884097; em[1049] = 8; em[1050] = 0; /* 1048: pointer.func */
    em[1051] = 8884097; em[1052] = 8; em[1053] = 0; /* 1051: pointer.func */
    em[1054] = 8884097; em[1055] = 8; em[1056] = 0; /* 1054: pointer.func */
    em[1057] = 1; em[1058] = 8; em[1059] = 1; /* 1057: pointer.struct.bignum_st */
    	em[1060] = 1062; em[1061] = 0; 
    em[1062] = 0; em[1063] = 24; em[1064] = 1; /* 1062: struct.bignum_st */
    	em[1065] = 1067; em[1066] = 0; 
    em[1067] = 8884099; em[1068] = 8; em[1069] = 2; /* 1067: pointer_to_array_of_pointers_to_stack */
    	em[1070] = 505; em[1071] = 0; 
    	em[1072] = 450; em[1073] = 12; 
    em[1074] = 1; em[1075] = 8; em[1076] = 1; /* 1074: pointer.struct.dsa_st */
    	em[1077] = 931; em[1078] = 0; 
    em[1079] = 0; em[1080] = 32; em[1081] = 2; /* 1079: struct.stack_st_fake_ASN1_TYPE */
    	em[1082] = 293; em[1083] = 8; 
    	em[1084] = 20; em[1085] = 24; 
    em[1086] = 0; em[1087] = 88; em[1088] = 7; /* 1086: struct.bn_blinding_st */
    	em[1089] = 1057; em[1090] = 0; 
    	em[1091] = 1057; em[1092] = 8; 
    	em[1093] = 1057; em[1094] = 16; 
    	em[1095] = 1057; em[1096] = 24; 
    	em[1097] = 1103; em[1098] = 40; 
    	em[1099] = 1108; em[1100] = 72; 
    	em[1101] = 1122; em[1102] = 80; 
    em[1103] = 0; em[1104] = 16; em[1105] = 1; /* 1103: struct.crypto_threadid_st */
    	em[1106] = 112; em[1107] = 0; 
    em[1108] = 1; em[1109] = 8; em[1110] = 1; /* 1108: pointer.struct.bn_mont_ctx_st */
    	em[1111] = 1113; em[1112] = 0; 
    em[1113] = 0; em[1114] = 96; em[1115] = 3; /* 1113: struct.bn_mont_ctx_st */
    	em[1116] = 1062; em[1117] = 8; 
    	em[1118] = 1062; em[1119] = 32; 
    	em[1120] = 1062; em[1121] = 56; 
    em[1122] = 8884097; em[1123] = 8; em[1124] = 0; /* 1122: pointer.func */
    em[1125] = 8884097; em[1126] = 8; em[1127] = 0; /* 1125: pointer.func */
    em[1128] = 1; em[1129] = 8; em[1130] = 1; /* 1128: pointer.struct.bn_blinding_st */
    	em[1131] = 1086; em[1132] = 0; 
    em[1133] = 1; em[1134] = 8; em[1135] = 1; /* 1133: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[1136] = 1138; em[1137] = 0; 
    em[1138] = 0; em[1139] = 32; em[1140] = 2; /* 1138: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[1141] = 1145; em[1142] = 8; 
    	em[1143] = 20; em[1144] = 24; 
    em[1145] = 8884099; em[1146] = 8; em[1147] = 2; /* 1145: pointer_to_array_of_pointers_to_stack */
    	em[1148] = 1152; em[1149] = 0; 
    	em[1150] = 450; em[1151] = 20; 
    em[1152] = 0; em[1153] = 8; em[1154] = 1; /* 1152: pointer.X509_ATTRIBUTE */
    	em[1155] = 1157; em[1156] = 0; 
    em[1157] = 0; em[1158] = 0; em[1159] = 1; /* 1157: X509_ATTRIBUTE */
    	em[1160] = 1162; em[1161] = 0; 
    em[1162] = 0; em[1163] = 24; em[1164] = 2; /* 1162: struct.x509_attributes_st */
    	em[1165] = 254; em[1166] = 0; 
    	em[1167] = 1169; em[1168] = 16; 
    em[1169] = 0; em[1170] = 8; em[1171] = 3; /* 1169: union.unknown */
    	em[1172] = 15; em[1173] = 0; 
    	em[1174] = 1178; em[1175] = 0; 
    	em[1176] = 1183; em[1177] = 0; 
    em[1178] = 1; em[1179] = 8; em[1180] = 1; /* 1178: pointer.struct.stack_st_ASN1_TYPE */
    	em[1181] = 1079; em[1182] = 0; 
    em[1183] = 1; em[1184] = 8; em[1185] = 1; /* 1183: pointer.struct.asn1_type_st */
    	em[1186] = 206; em[1187] = 0; 
    em[1188] = 8884097; em[1189] = 8; em[1190] = 0; /* 1188: pointer.func */
    em[1191] = 0; em[1192] = 112; em[1193] = 13; /* 1191: struct.rsa_meth_st */
    	em[1194] = 86; em[1195] = 0; 
    	em[1196] = 1220; em[1197] = 8; 
    	em[1198] = 1220; em[1199] = 16; 
    	em[1200] = 1220; em[1201] = 24; 
    	em[1202] = 1220; em[1203] = 32; 
    	em[1204] = 1223; em[1205] = 40; 
    	em[1206] = 1226; em[1207] = 48; 
    	em[1208] = 1188; em[1209] = 56; 
    	em[1210] = 1188; em[1211] = 64; 
    	em[1212] = 15; em[1213] = 80; 
    	em[1214] = 1229; em[1215] = 88; 
    	em[1216] = 1232; em[1217] = 96; 
    	em[1218] = 1235; em[1219] = 104; 
    em[1220] = 8884097; em[1221] = 8; em[1222] = 0; /* 1220: pointer.func */
    em[1223] = 8884097; em[1224] = 8; em[1225] = 0; /* 1223: pointer.func */
    em[1226] = 8884097; em[1227] = 8; em[1228] = 0; /* 1226: pointer.func */
    em[1229] = 8884097; em[1230] = 8; em[1231] = 0; /* 1229: pointer.func */
    em[1232] = 8884097; em[1233] = 8; em[1234] = 0; /* 1232: pointer.func */
    em[1235] = 8884097; em[1236] = 8; em[1237] = 0; /* 1235: pointer.func */
    em[1238] = 1; em[1239] = 8; em[1240] = 1; /* 1238: pointer.struct.ec_key_st */
    	em[1241] = 1243; em[1242] = 0; 
    em[1243] = 0; em[1244] = 56; em[1245] = 4; /* 1243: struct.ec_key_st */
    	em[1246] = 1254; em[1247] = 8; 
    	em[1248] = 1696; em[1249] = 16; 
    	em[1250] = 1701; em[1251] = 24; 
    	em[1252] = 1718; em[1253] = 48; 
    em[1254] = 1; em[1255] = 8; em[1256] = 1; /* 1254: pointer.struct.ec_group_st */
    	em[1257] = 1259; em[1258] = 0; 
    em[1259] = 0; em[1260] = 232; em[1261] = 12; /* 1259: struct.ec_group_st */
    	em[1262] = 1286; em[1263] = 0; 
    	em[1264] = 1452; em[1265] = 8; 
    	em[1266] = 1652; em[1267] = 16; 
    	em[1268] = 1652; em[1269] = 40; 
    	em[1270] = 138; em[1271] = 80; 
    	em[1272] = 1664; em[1273] = 96; 
    	em[1274] = 1652; em[1275] = 104; 
    	em[1276] = 1652; em[1277] = 152; 
    	em[1278] = 1652; em[1279] = 176; 
    	em[1280] = 112; em[1281] = 208; 
    	em[1282] = 112; em[1283] = 216; 
    	em[1284] = 1693; em[1285] = 224; 
    em[1286] = 1; em[1287] = 8; em[1288] = 1; /* 1286: pointer.struct.ec_method_st */
    	em[1289] = 1291; em[1290] = 0; 
    em[1291] = 0; em[1292] = 304; em[1293] = 37; /* 1291: struct.ec_method_st */
    	em[1294] = 1368; em[1295] = 8; 
    	em[1296] = 928; em[1297] = 16; 
    	em[1298] = 928; em[1299] = 24; 
    	em[1300] = 1371; em[1301] = 32; 
    	em[1302] = 1374; em[1303] = 40; 
    	em[1304] = 1377; em[1305] = 48; 
    	em[1306] = 1380; em[1307] = 56; 
    	em[1308] = 1383; em[1309] = 64; 
    	em[1310] = 1386; em[1311] = 72; 
    	em[1312] = 1389; em[1313] = 80; 
    	em[1314] = 1389; em[1315] = 88; 
    	em[1316] = 1392; em[1317] = 96; 
    	em[1318] = 1395; em[1319] = 104; 
    	em[1320] = 1398; em[1321] = 112; 
    	em[1322] = 1401; em[1323] = 120; 
    	em[1324] = 1404; em[1325] = 128; 
    	em[1326] = 1407; em[1327] = 136; 
    	em[1328] = 1410; em[1329] = 144; 
    	em[1330] = 1413; em[1331] = 152; 
    	em[1332] = 1416; em[1333] = 160; 
    	em[1334] = 1419; em[1335] = 168; 
    	em[1336] = 1422; em[1337] = 176; 
    	em[1338] = 1425; em[1339] = 184; 
    	em[1340] = 1428; em[1341] = 192; 
    	em[1342] = 1431; em[1343] = 200; 
    	em[1344] = 1434; em[1345] = 208; 
    	em[1346] = 1425; em[1347] = 216; 
    	em[1348] = 1125; em[1349] = 224; 
    	em[1350] = 1437; em[1351] = 232; 
    	em[1352] = 1440; em[1353] = 240; 
    	em[1354] = 1380; em[1355] = 248; 
    	em[1356] = 1443; em[1357] = 256; 
    	em[1358] = 1446; em[1359] = 264; 
    	em[1360] = 1443; em[1361] = 272; 
    	em[1362] = 1446; em[1363] = 280; 
    	em[1364] = 1446; em[1365] = 288; 
    	em[1366] = 1449; em[1367] = 296; 
    em[1368] = 8884097; em[1369] = 8; em[1370] = 0; /* 1368: pointer.func */
    em[1371] = 8884097; em[1372] = 8; em[1373] = 0; /* 1371: pointer.func */
    em[1374] = 8884097; em[1375] = 8; em[1376] = 0; /* 1374: pointer.func */
    em[1377] = 8884097; em[1378] = 8; em[1379] = 0; /* 1377: pointer.func */
    em[1380] = 8884097; em[1381] = 8; em[1382] = 0; /* 1380: pointer.func */
    em[1383] = 8884097; em[1384] = 8; em[1385] = 0; /* 1383: pointer.func */
    em[1386] = 8884097; em[1387] = 8; em[1388] = 0; /* 1386: pointer.func */
    em[1389] = 8884097; em[1390] = 8; em[1391] = 0; /* 1389: pointer.func */
    em[1392] = 8884097; em[1393] = 8; em[1394] = 0; /* 1392: pointer.func */
    em[1395] = 8884097; em[1396] = 8; em[1397] = 0; /* 1395: pointer.func */
    em[1398] = 8884097; em[1399] = 8; em[1400] = 0; /* 1398: pointer.func */
    em[1401] = 8884097; em[1402] = 8; em[1403] = 0; /* 1401: pointer.func */
    em[1404] = 8884097; em[1405] = 8; em[1406] = 0; /* 1404: pointer.func */
    em[1407] = 8884097; em[1408] = 8; em[1409] = 0; /* 1407: pointer.func */
    em[1410] = 8884097; em[1411] = 8; em[1412] = 0; /* 1410: pointer.func */
    em[1413] = 8884097; em[1414] = 8; em[1415] = 0; /* 1413: pointer.func */
    em[1416] = 8884097; em[1417] = 8; em[1418] = 0; /* 1416: pointer.func */
    em[1419] = 8884097; em[1420] = 8; em[1421] = 0; /* 1419: pointer.func */
    em[1422] = 8884097; em[1423] = 8; em[1424] = 0; /* 1422: pointer.func */
    em[1425] = 8884097; em[1426] = 8; em[1427] = 0; /* 1425: pointer.func */
    em[1428] = 8884097; em[1429] = 8; em[1430] = 0; /* 1428: pointer.func */
    em[1431] = 8884097; em[1432] = 8; em[1433] = 0; /* 1431: pointer.func */
    em[1434] = 8884097; em[1435] = 8; em[1436] = 0; /* 1434: pointer.func */
    em[1437] = 8884097; em[1438] = 8; em[1439] = 0; /* 1437: pointer.func */
    em[1440] = 8884097; em[1441] = 8; em[1442] = 0; /* 1440: pointer.func */
    em[1443] = 8884097; em[1444] = 8; em[1445] = 0; /* 1443: pointer.func */
    em[1446] = 8884097; em[1447] = 8; em[1448] = 0; /* 1446: pointer.func */
    em[1449] = 8884097; em[1450] = 8; em[1451] = 0; /* 1449: pointer.func */
    em[1452] = 1; em[1453] = 8; em[1454] = 1; /* 1452: pointer.struct.ec_point_st */
    	em[1455] = 1457; em[1456] = 0; 
    em[1457] = 0; em[1458] = 88; em[1459] = 4; /* 1457: struct.ec_point_st */
    	em[1460] = 1468; em[1461] = 0; 
    	em[1462] = 1640; em[1463] = 8; 
    	em[1464] = 1640; em[1465] = 32; 
    	em[1466] = 1640; em[1467] = 56; 
    em[1468] = 1; em[1469] = 8; em[1470] = 1; /* 1468: pointer.struct.ec_method_st */
    	em[1471] = 1473; em[1472] = 0; 
    em[1473] = 0; em[1474] = 304; em[1475] = 37; /* 1473: struct.ec_method_st */
    	em[1476] = 1550; em[1477] = 8; 
    	em[1478] = 1553; em[1479] = 16; 
    	em[1480] = 1553; em[1481] = 24; 
    	em[1482] = 1556; em[1483] = 32; 
    	em[1484] = 1559; em[1485] = 40; 
    	em[1486] = 1562; em[1487] = 48; 
    	em[1488] = 1565; em[1489] = 56; 
    	em[1490] = 1568; em[1491] = 64; 
    	em[1492] = 1571; em[1493] = 72; 
    	em[1494] = 1574; em[1495] = 80; 
    	em[1496] = 1574; em[1497] = 88; 
    	em[1498] = 1577; em[1499] = 96; 
    	em[1500] = 1580; em[1501] = 104; 
    	em[1502] = 1583; em[1503] = 112; 
    	em[1504] = 1586; em[1505] = 120; 
    	em[1506] = 1589; em[1507] = 128; 
    	em[1508] = 1592; em[1509] = 136; 
    	em[1510] = 1595; em[1511] = 144; 
    	em[1512] = 1598; em[1513] = 152; 
    	em[1514] = 1601; em[1515] = 160; 
    	em[1516] = 1604; em[1517] = 168; 
    	em[1518] = 1607; em[1519] = 176; 
    	em[1520] = 1610; em[1521] = 184; 
    	em[1522] = 1613; em[1523] = 192; 
    	em[1524] = 1616; em[1525] = 200; 
    	em[1526] = 1619; em[1527] = 208; 
    	em[1528] = 1610; em[1529] = 216; 
    	em[1530] = 1622; em[1531] = 224; 
    	em[1532] = 1625; em[1533] = 232; 
    	em[1534] = 1628; em[1535] = 240; 
    	em[1536] = 1565; em[1537] = 248; 
    	em[1538] = 1631; em[1539] = 256; 
    	em[1540] = 1634; em[1541] = 264; 
    	em[1542] = 1631; em[1543] = 272; 
    	em[1544] = 1634; em[1545] = 280; 
    	em[1546] = 1634; em[1547] = 288; 
    	em[1548] = 1637; em[1549] = 296; 
    em[1550] = 8884097; em[1551] = 8; em[1552] = 0; /* 1550: pointer.func */
    em[1553] = 8884097; em[1554] = 8; em[1555] = 0; /* 1553: pointer.func */
    em[1556] = 8884097; em[1557] = 8; em[1558] = 0; /* 1556: pointer.func */
    em[1559] = 8884097; em[1560] = 8; em[1561] = 0; /* 1559: pointer.func */
    em[1562] = 8884097; em[1563] = 8; em[1564] = 0; /* 1562: pointer.func */
    em[1565] = 8884097; em[1566] = 8; em[1567] = 0; /* 1565: pointer.func */
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
    em[1610] = 8884097; em[1611] = 8; em[1612] = 0; /* 1610: pointer.func */
    em[1613] = 8884097; em[1614] = 8; em[1615] = 0; /* 1613: pointer.func */
    em[1616] = 8884097; em[1617] = 8; em[1618] = 0; /* 1616: pointer.func */
    em[1619] = 8884097; em[1620] = 8; em[1621] = 0; /* 1619: pointer.func */
    em[1622] = 8884097; em[1623] = 8; em[1624] = 0; /* 1622: pointer.func */
    em[1625] = 8884097; em[1626] = 8; em[1627] = 0; /* 1625: pointer.func */
    em[1628] = 8884097; em[1629] = 8; em[1630] = 0; /* 1628: pointer.func */
    em[1631] = 8884097; em[1632] = 8; em[1633] = 0; /* 1631: pointer.func */
    em[1634] = 8884097; em[1635] = 8; em[1636] = 0; /* 1634: pointer.func */
    em[1637] = 8884097; em[1638] = 8; em[1639] = 0; /* 1637: pointer.func */
    em[1640] = 0; em[1641] = 24; em[1642] = 1; /* 1640: struct.bignum_st */
    	em[1643] = 1645; em[1644] = 0; 
    em[1645] = 8884099; em[1646] = 8; em[1647] = 2; /* 1645: pointer_to_array_of_pointers_to_stack */
    	em[1648] = 505; em[1649] = 0; 
    	em[1650] = 450; em[1651] = 12; 
    em[1652] = 0; em[1653] = 24; em[1654] = 1; /* 1652: struct.bignum_st */
    	em[1655] = 1657; em[1656] = 0; 
    em[1657] = 8884099; em[1658] = 8; em[1659] = 2; /* 1657: pointer_to_array_of_pointers_to_stack */
    	em[1660] = 505; em[1661] = 0; 
    	em[1662] = 450; em[1663] = 12; 
    em[1664] = 1; em[1665] = 8; em[1666] = 1; /* 1664: pointer.struct.ec_extra_data_st */
    	em[1667] = 1669; em[1668] = 0; 
    em[1669] = 0; em[1670] = 40; em[1671] = 5; /* 1669: struct.ec_extra_data_st */
    	em[1672] = 1682; em[1673] = 0; 
    	em[1674] = 112; em[1675] = 8; 
    	em[1676] = 1687; em[1677] = 16; 
    	em[1678] = 1690; em[1679] = 24; 
    	em[1680] = 1690; em[1681] = 32; 
    em[1682] = 1; em[1683] = 8; em[1684] = 1; /* 1682: pointer.struct.ec_extra_data_st */
    	em[1685] = 1669; em[1686] = 0; 
    em[1687] = 8884097; em[1688] = 8; em[1689] = 0; /* 1687: pointer.func */
    em[1690] = 8884097; em[1691] = 8; em[1692] = 0; /* 1690: pointer.func */
    em[1693] = 8884097; em[1694] = 8; em[1695] = 0; /* 1693: pointer.func */
    em[1696] = 1; em[1697] = 8; em[1698] = 1; /* 1696: pointer.struct.ec_point_st */
    	em[1699] = 1457; em[1700] = 0; 
    em[1701] = 1; em[1702] = 8; em[1703] = 1; /* 1701: pointer.struct.bignum_st */
    	em[1704] = 1706; em[1705] = 0; 
    em[1706] = 0; em[1707] = 24; em[1708] = 1; /* 1706: struct.bignum_st */
    	em[1709] = 1711; em[1710] = 0; 
    em[1711] = 8884099; em[1712] = 8; em[1713] = 2; /* 1711: pointer_to_array_of_pointers_to_stack */
    	em[1714] = 505; em[1715] = 0; 
    	em[1716] = 450; em[1717] = 12; 
    em[1718] = 1; em[1719] = 8; em[1720] = 1; /* 1718: pointer.struct.ec_extra_data_st */
    	em[1721] = 1723; em[1722] = 0; 
    em[1723] = 0; em[1724] = 40; em[1725] = 5; /* 1723: struct.ec_extra_data_st */
    	em[1726] = 1736; em[1727] = 0; 
    	em[1728] = 112; em[1729] = 8; 
    	em[1730] = 1687; em[1731] = 16; 
    	em[1732] = 1690; em[1733] = 24; 
    	em[1734] = 1690; em[1735] = 32; 
    em[1736] = 1; em[1737] = 8; em[1738] = 1; /* 1736: pointer.struct.ec_extra_data_st */
    	em[1739] = 1723; em[1740] = 0; 
    em[1741] = 0; em[1742] = 168; em[1743] = 17; /* 1741: struct.rsa_st */
    	em[1744] = 1778; em[1745] = 16; 
    	em[1746] = 580; em[1747] = 24; 
    	em[1748] = 956; em[1749] = 32; 
    	em[1750] = 956; em[1751] = 40; 
    	em[1752] = 956; em[1753] = 48; 
    	em[1754] = 956; em[1755] = 56; 
    	em[1756] = 956; em[1757] = 64; 
    	em[1758] = 956; em[1759] = 72; 
    	em[1760] = 956; em[1761] = 80; 
    	em[1762] = 956; em[1763] = 88; 
    	em[1764] = 987; em[1765] = 96; 
    	em[1766] = 973; em[1767] = 120; 
    	em[1768] = 973; em[1769] = 128; 
    	em[1770] = 973; em[1771] = 136; 
    	em[1772] = 15; em[1773] = 144; 
    	em[1774] = 1128; em[1775] = 152; 
    	em[1776] = 1128; em[1777] = 160; 
    em[1778] = 1; em[1779] = 8; em[1780] = 1; /* 1778: pointer.struct.rsa_meth_st */
    	em[1781] = 1191; em[1782] = 0; 
    em[1783] = 0; em[1784] = 8; em[1785] = 5; /* 1783: union.unknown */
    	em[1786] = 15; em[1787] = 0; 
    	em[1788] = 1796; em[1789] = 0; 
    	em[1790] = 1074; em[1791] = 0; 
    	em[1792] = 456; em[1793] = 0; 
    	em[1794] = 1238; em[1795] = 0; 
    em[1796] = 1; em[1797] = 8; em[1798] = 1; /* 1796: pointer.struct.rsa_st */
    	em[1799] = 1741; em[1800] = 0; 
    em[1801] = 1; em[1802] = 8; em[1803] = 1; /* 1801: pointer.pointer.struct.evp_pkey_st */
    	em[1804] = 1806; em[1805] = 0; 
    em[1806] = 1; em[1807] = 8; em[1808] = 1; /* 1806: pointer.struct.evp_pkey_st */
    	em[1809] = 1811; em[1810] = 0; 
    em[1811] = 0; em[1812] = 56; em[1813] = 4; /* 1811: struct.evp_pkey_st */
    	em[1814] = 1822; em[1815] = 16; 
    	em[1816] = 1923; em[1817] = 24; 
    	em[1818] = 1783; em[1819] = 32; 
    	em[1820] = 1133; em[1821] = 48; 
    em[1822] = 1; em[1823] = 8; em[1824] = 1; /* 1822: pointer.struct.evp_pkey_asn1_method_st */
    	em[1825] = 1827; em[1826] = 0; 
    em[1827] = 0; em[1828] = 208; em[1829] = 24; /* 1827: struct.evp_pkey_asn1_method_st */
    	em[1830] = 15; em[1831] = 16; 
    	em[1832] = 15; em[1833] = 24; 
    	em[1834] = 1878; em[1835] = 32; 
    	em[1836] = 1881; em[1837] = 40; 
    	em[1838] = 1884; em[1839] = 48; 
    	em[1840] = 1887; em[1841] = 56; 
    	em[1842] = 1890; em[1843] = 64; 
    	em[1844] = 1893; em[1845] = 72; 
    	em[1846] = 1887; em[1847] = 80; 
    	em[1848] = 1896; em[1849] = 88; 
    	em[1850] = 1896; em[1851] = 96; 
    	em[1852] = 1899; em[1853] = 104; 
    	em[1854] = 1902; em[1855] = 112; 
    	em[1856] = 1896; em[1857] = 120; 
    	em[1858] = 1905; em[1859] = 128; 
    	em[1860] = 1884; em[1861] = 136; 
    	em[1862] = 1887; em[1863] = 144; 
    	em[1864] = 1908; em[1865] = 152; 
    	em[1866] = 1911; em[1867] = 160; 
    	em[1868] = 1914; em[1869] = 168; 
    	em[1870] = 1899; em[1871] = 176; 
    	em[1872] = 1902; em[1873] = 184; 
    	em[1874] = 1917; em[1875] = 192; 
    	em[1876] = 1920; em[1877] = 200; 
    em[1878] = 8884097; em[1879] = 8; em[1880] = 0; /* 1878: pointer.func */
    em[1881] = 8884097; em[1882] = 8; em[1883] = 0; /* 1881: pointer.func */
    em[1884] = 8884097; em[1885] = 8; em[1886] = 0; /* 1884: pointer.func */
    em[1887] = 8884097; em[1888] = 8; em[1889] = 0; /* 1887: pointer.func */
    em[1890] = 8884097; em[1891] = 8; em[1892] = 0; /* 1890: pointer.func */
    em[1893] = 8884097; em[1894] = 8; em[1895] = 0; /* 1893: pointer.func */
    em[1896] = 8884097; em[1897] = 8; em[1898] = 0; /* 1896: pointer.func */
    em[1899] = 8884097; em[1900] = 8; em[1901] = 0; /* 1899: pointer.func */
    em[1902] = 8884097; em[1903] = 8; em[1904] = 0; /* 1902: pointer.func */
    em[1905] = 8884097; em[1906] = 8; em[1907] = 0; /* 1905: pointer.func */
    em[1908] = 8884097; em[1909] = 8; em[1910] = 0; /* 1908: pointer.func */
    em[1911] = 8884097; em[1912] = 8; em[1913] = 0; /* 1911: pointer.func */
    em[1914] = 8884097; em[1915] = 8; em[1916] = 0; /* 1914: pointer.func */
    em[1917] = 8884097; em[1918] = 8; em[1919] = 0; /* 1917: pointer.func */
    em[1920] = 8884097; em[1921] = 8; em[1922] = 0; /* 1920: pointer.func */
    em[1923] = 1; em[1924] = 8; em[1925] = 1; /* 1923: pointer.struct.engine_st */
    	em[1926] = 585; em[1927] = 0; 
    em[1928] = 0; em[1929] = 1; em[1930] = 0; /* 1928: char */
    args_addr->arg_entity_index[0] = 115;
    args_addr->arg_entity_index[1] = 1801;
    args_addr->arg_entity_index[2] = 0;
    args_addr->arg_entity_index[3] = 112;
    args_addr->ret_entity_index = 1806;
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

