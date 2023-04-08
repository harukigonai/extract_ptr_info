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

X509_NAME * bb_X509_get_subject_name(X509 * arg_a);

X509_NAME * X509_get_subject_name(X509 * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("X509_get_subject_name called %lu\n", in_lib);
    if (!in_lib)
        return bb_X509_get_subject_name(arg_a);
    else {
        X509_NAME * (*orig_X509_get_subject_name)(X509 *);
        orig_X509_get_subject_name = dlsym(RTLD_NEXT, "X509_get_subject_name");
        return orig_X509_get_subject_name(arg_a);
    }
}

X509_NAME * bb_X509_get_subject_name(X509 * arg_a) 
{
    X509_NAME * ret;

    struct lib_enter_args *args_addr = malloc(sizeof(struct lib_enter_args));
    memset(args_addr, 0, sizeof(struct lib_enter_args));
    args_addr->num_args = 0;
    uint32_t *em = args_addr->entity_metadata;
    em[0] = 1; em[1] = 8; em[2] = 1; /* 0: pointer.struct.stack_st_X509_ALGOR */
    	em[3] = 5; em[4] = 0; 
    em[5] = 0; em[6] = 32; em[7] = 2; /* 5: struct.stack_st_fake_X509_ALGOR */
    	em[8] = 12; em[9] = 8; 
    	em[10] = 217; em[11] = 24; 
    em[12] = 8884099; em[13] = 8; em[14] = 2; /* 12: pointer_to_array_of_pointers_to_stack */
    	em[15] = 19; em[16] = 0; 
    	em[17] = 214; em[18] = 20; 
    em[19] = 0; em[20] = 8; em[21] = 1; /* 19: pointer.X509_ALGOR */
    	em[22] = 24; em[23] = 0; 
    em[24] = 0; em[25] = 0; em[26] = 1; /* 24: X509_ALGOR */
    	em[27] = 29; em[28] = 0; 
    em[29] = 0; em[30] = 16; em[31] = 2; /* 29: struct.X509_algor_st */
    	em[32] = 36; em[33] = 0; 
    	em[34] = 63; em[35] = 8; 
    em[36] = 1; em[37] = 8; em[38] = 1; /* 36: pointer.struct.asn1_object_st */
    	em[39] = 41; em[40] = 0; 
    em[41] = 0; em[42] = 40; em[43] = 3; /* 41: struct.asn1_object_st */
    	em[44] = 50; em[45] = 0; 
    	em[46] = 50; em[47] = 8; 
    	em[48] = 55; em[49] = 24; 
    em[50] = 1; em[51] = 8; em[52] = 1; /* 50: pointer.char */
    	em[53] = 8884096; em[54] = 0; 
    em[55] = 1; em[56] = 8; em[57] = 1; /* 55: pointer.unsigned char */
    	em[58] = 60; em[59] = 0; 
    em[60] = 0; em[61] = 1; em[62] = 0; /* 60: unsigned char */
    em[63] = 1; em[64] = 8; em[65] = 1; /* 63: pointer.struct.asn1_type_st */
    	em[66] = 68; em[67] = 0; 
    em[68] = 0; em[69] = 16; em[70] = 1; /* 68: struct.asn1_type_st */
    	em[71] = 73; em[72] = 8; 
    em[73] = 0; em[74] = 8; em[75] = 20; /* 73: union.unknown */
    	em[76] = 116; em[77] = 0; 
    	em[78] = 121; em[79] = 0; 
    	em[80] = 36; em[81] = 0; 
    	em[82] = 136; em[83] = 0; 
    	em[84] = 141; em[85] = 0; 
    	em[86] = 146; em[87] = 0; 
    	em[88] = 151; em[89] = 0; 
    	em[90] = 156; em[91] = 0; 
    	em[92] = 161; em[93] = 0; 
    	em[94] = 166; em[95] = 0; 
    	em[96] = 171; em[97] = 0; 
    	em[98] = 176; em[99] = 0; 
    	em[100] = 181; em[101] = 0; 
    	em[102] = 186; em[103] = 0; 
    	em[104] = 191; em[105] = 0; 
    	em[106] = 196; em[107] = 0; 
    	em[108] = 201; em[109] = 0; 
    	em[110] = 121; em[111] = 0; 
    	em[112] = 121; em[113] = 0; 
    	em[114] = 206; em[115] = 0; 
    em[116] = 1; em[117] = 8; em[118] = 1; /* 116: pointer.char */
    	em[119] = 8884096; em[120] = 0; 
    em[121] = 1; em[122] = 8; em[123] = 1; /* 121: pointer.struct.asn1_string_st */
    	em[124] = 126; em[125] = 0; 
    em[126] = 0; em[127] = 24; em[128] = 1; /* 126: struct.asn1_string_st */
    	em[129] = 131; em[130] = 8; 
    em[131] = 1; em[132] = 8; em[133] = 1; /* 131: pointer.unsigned char */
    	em[134] = 60; em[135] = 0; 
    em[136] = 1; em[137] = 8; em[138] = 1; /* 136: pointer.struct.asn1_string_st */
    	em[139] = 126; em[140] = 0; 
    em[141] = 1; em[142] = 8; em[143] = 1; /* 141: pointer.struct.asn1_string_st */
    	em[144] = 126; em[145] = 0; 
    em[146] = 1; em[147] = 8; em[148] = 1; /* 146: pointer.struct.asn1_string_st */
    	em[149] = 126; em[150] = 0; 
    em[151] = 1; em[152] = 8; em[153] = 1; /* 151: pointer.struct.asn1_string_st */
    	em[154] = 126; em[155] = 0; 
    em[156] = 1; em[157] = 8; em[158] = 1; /* 156: pointer.struct.asn1_string_st */
    	em[159] = 126; em[160] = 0; 
    em[161] = 1; em[162] = 8; em[163] = 1; /* 161: pointer.struct.asn1_string_st */
    	em[164] = 126; em[165] = 0; 
    em[166] = 1; em[167] = 8; em[168] = 1; /* 166: pointer.struct.asn1_string_st */
    	em[169] = 126; em[170] = 0; 
    em[171] = 1; em[172] = 8; em[173] = 1; /* 171: pointer.struct.asn1_string_st */
    	em[174] = 126; em[175] = 0; 
    em[176] = 1; em[177] = 8; em[178] = 1; /* 176: pointer.struct.asn1_string_st */
    	em[179] = 126; em[180] = 0; 
    em[181] = 1; em[182] = 8; em[183] = 1; /* 181: pointer.struct.asn1_string_st */
    	em[184] = 126; em[185] = 0; 
    em[186] = 1; em[187] = 8; em[188] = 1; /* 186: pointer.struct.asn1_string_st */
    	em[189] = 126; em[190] = 0; 
    em[191] = 1; em[192] = 8; em[193] = 1; /* 191: pointer.struct.asn1_string_st */
    	em[194] = 126; em[195] = 0; 
    em[196] = 1; em[197] = 8; em[198] = 1; /* 196: pointer.struct.asn1_string_st */
    	em[199] = 126; em[200] = 0; 
    em[201] = 1; em[202] = 8; em[203] = 1; /* 201: pointer.struct.asn1_string_st */
    	em[204] = 126; em[205] = 0; 
    em[206] = 1; em[207] = 8; em[208] = 1; /* 206: pointer.struct.ASN1_VALUE_st */
    	em[209] = 211; em[210] = 0; 
    em[211] = 0; em[212] = 0; em[213] = 0; /* 211: struct.ASN1_VALUE_st */
    em[214] = 0; em[215] = 4; em[216] = 0; /* 214: int */
    em[217] = 8884097; em[218] = 8; em[219] = 0; /* 217: pointer.func */
    em[220] = 1; em[221] = 8; em[222] = 1; /* 220: pointer.struct.stack_st_ASN1_OBJECT */
    	em[223] = 225; em[224] = 0; 
    em[225] = 0; em[226] = 32; em[227] = 2; /* 225: struct.stack_st_fake_ASN1_OBJECT */
    	em[228] = 232; em[229] = 8; 
    	em[230] = 217; em[231] = 24; 
    em[232] = 8884099; em[233] = 8; em[234] = 2; /* 232: pointer_to_array_of_pointers_to_stack */
    	em[235] = 239; em[236] = 0; 
    	em[237] = 214; em[238] = 20; 
    em[239] = 0; em[240] = 8; em[241] = 1; /* 239: pointer.ASN1_OBJECT */
    	em[242] = 244; em[243] = 0; 
    em[244] = 0; em[245] = 0; em[246] = 1; /* 244: ASN1_OBJECT */
    	em[247] = 249; em[248] = 0; 
    em[249] = 0; em[250] = 40; em[251] = 3; /* 249: struct.asn1_object_st */
    	em[252] = 50; em[253] = 0; 
    	em[254] = 50; em[255] = 8; 
    	em[256] = 55; em[257] = 24; 
    em[258] = 0; em[259] = 40; em[260] = 5; /* 258: struct.x509_cert_aux_st */
    	em[261] = 220; em[262] = 0; 
    	em[263] = 220; em[264] = 8; 
    	em[265] = 271; em[266] = 16; 
    	em[267] = 281; em[268] = 24; 
    	em[269] = 0; em[270] = 32; 
    em[271] = 1; em[272] = 8; em[273] = 1; /* 271: pointer.struct.asn1_string_st */
    	em[274] = 276; em[275] = 0; 
    em[276] = 0; em[277] = 24; em[278] = 1; /* 276: struct.asn1_string_st */
    	em[279] = 131; em[280] = 8; 
    em[281] = 1; em[282] = 8; em[283] = 1; /* 281: pointer.struct.asn1_string_st */
    	em[284] = 276; em[285] = 0; 
    em[286] = 1; em[287] = 8; em[288] = 1; /* 286: pointer.struct.x509_cert_aux_st */
    	em[289] = 258; em[290] = 0; 
    em[291] = 1; em[292] = 8; em[293] = 1; /* 291: pointer.struct.EDIPartyName_st */
    	em[294] = 296; em[295] = 0; 
    em[296] = 0; em[297] = 16; em[298] = 2; /* 296: struct.EDIPartyName_st */
    	em[299] = 303; em[300] = 0; 
    	em[301] = 303; em[302] = 8; 
    em[303] = 1; em[304] = 8; em[305] = 1; /* 303: pointer.struct.asn1_string_st */
    	em[306] = 308; em[307] = 0; 
    em[308] = 0; em[309] = 24; em[310] = 1; /* 308: struct.asn1_string_st */
    	em[311] = 131; em[312] = 8; 
    em[313] = 0; em[314] = 24; em[315] = 1; /* 313: struct.buf_mem_st */
    	em[316] = 116; em[317] = 8; 
    em[318] = 1; em[319] = 8; em[320] = 1; /* 318: pointer.struct.X509_name_st */
    	em[321] = 323; em[322] = 0; 
    em[323] = 0; em[324] = 40; em[325] = 3; /* 323: struct.X509_name_st */
    	em[326] = 332; em[327] = 0; 
    	em[328] = 392; em[329] = 16; 
    	em[330] = 131; em[331] = 24; 
    em[332] = 1; em[333] = 8; em[334] = 1; /* 332: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[335] = 337; em[336] = 0; 
    em[337] = 0; em[338] = 32; em[339] = 2; /* 337: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[340] = 344; em[341] = 8; 
    	em[342] = 217; em[343] = 24; 
    em[344] = 8884099; em[345] = 8; em[346] = 2; /* 344: pointer_to_array_of_pointers_to_stack */
    	em[347] = 351; em[348] = 0; 
    	em[349] = 214; em[350] = 20; 
    em[351] = 0; em[352] = 8; em[353] = 1; /* 351: pointer.X509_NAME_ENTRY */
    	em[354] = 356; em[355] = 0; 
    em[356] = 0; em[357] = 0; em[358] = 1; /* 356: X509_NAME_ENTRY */
    	em[359] = 361; em[360] = 0; 
    em[361] = 0; em[362] = 24; em[363] = 2; /* 361: struct.X509_name_entry_st */
    	em[364] = 368; em[365] = 0; 
    	em[366] = 382; em[367] = 8; 
    em[368] = 1; em[369] = 8; em[370] = 1; /* 368: pointer.struct.asn1_object_st */
    	em[371] = 373; em[372] = 0; 
    em[373] = 0; em[374] = 40; em[375] = 3; /* 373: struct.asn1_object_st */
    	em[376] = 50; em[377] = 0; 
    	em[378] = 50; em[379] = 8; 
    	em[380] = 55; em[381] = 24; 
    em[382] = 1; em[383] = 8; em[384] = 1; /* 382: pointer.struct.asn1_string_st */
    	em[385] = 387; em[386] = 0; 
    em[387] = 0; em[388] = 24; em[389] = 1; /* 387: struct.asn1_string_st */
    	em[390] = 131; em[391] = 8; 
    em[392] = 1; em[393] = 8; em[394] = 1; /* 392: pointer.struct.buf_mem_st */
    	em[395] = 313; em[396] = 0; 
    em[397] = 1; em[398] = 8; em[399] = 1; /* 397: pointer.struct.asn1_string_st */
    	em[400] = 308; em[401] = 0; 
    em[402] = 1; em[403] = 8; em[404] = 1; /* 402: pointer.struct.asn1_string_st */
    	em[405] = 308; em[406] = 0; 
    em[407] = 1; em[408] = 8; em[409] = 1; /* 407: pointer.struct.asn1_string_st */
    	em[410] = 308; em[411] = 0; 
    em[412] = 1; em[413] = 8; em[414] = 1; /* 412: pointer.struct.asn1_string_st */
    	em[415] = 308; em[416] = 0; 
    em[417] = 1; em[418] = 8; em[419] = 1; /* 417: pointer.struct.asn1_string_st */
    	em[420] = 308; em[421] = 0; 
    em[422] = 1; em[423] = 8; em[424] = 1; /* 422: pointer.struct.asn1_string_st */
    	em[425] = 308; em[426] = 0; 
    em[427] = 0; em[428] = 40; em[429] = 3; /* 427: struct.asn1_object_st */
    	em[430] = 50; em[431] = 0; 
    	em[432] = 50; em[433] = 8; 
    	em[434] = 55; em[435] = 24; 
    em[436] = 1; em[437] = 8; em[438] = 1; /* 436: pointer.struct.asn1_object_st */
    	em[439] = 427; em[440] = 0; 
    em[441] = 0; em[442] = 16; em[443] = 2; /* 441: struct.otherName_st */
    	em[444] = 436; em[445] = 0; 
    	em[446] = 448; em[447] = 8; 
    em[448] = 1; em[449] = 8; em[450] = 1; /* 448: pointer.struct.asn1_type_st */
    	em[451] = 453; em[452] = 0; 
    em[453] = 0; em[454] = 16; em[455] = 1; /* 453: struct.asn1_type_st */
    	em[456] = 458; em[457] = 8; 
    em[458] = 0; em[459] = 8; em[460] = 20; /* 458: union.unknown */
    	em[461] = 116; em[462] = 0; 
    	em[463] = 303; em[464] = 0; 
    	em[465] = 436; em[466] = 0; 
    	em[467] = 501; em[468] = 0; 
    	em[469] = 506; em[470] = 0; 
    	em[471] = 511; em[472] = 0; 
    	em[473] = 422; em[474] = 0; 
    	em[475] = 417; em[476] = 0; 
    	em[477] = 412; em[478] = 0; 
    	em[479] = 516; em[480] = 0; 
    	em[481] = 521; em[482] = 0; 
    	em[483] = 526; em[484] = 0; 
    	em[485] = 407; em[486] = 0; 
    	em[487] = 402; em[488] = 0; 
    	em[489] = 397; em[490] = 0; 
    	em[491] = 531; em[492] = 0; 
    	em[493] = 536; em[494] = 0; 
    	em[495] = 303; em[496] = 0; 
    	em[497] = 303; em[498] = 0; 
    	em[499] = 541; em[500] = 0; 
    em[501] = 1; em[502] = 8; em[503] = 1; /* 501: pointer.struct.asn1_string_st */
    	em[504] = 308; em[505] = 0; 
    em[506] = 1; em[507] = 8; em[508] = 1; /* 506: pointer.struct.asn1_string_st */
    	em[509] = 308; em[510] = 0; 
    em[511] = 1; em[512] = 8; em[513] = 1; /* 511: pointer.struct.asn1_string_st */
    	em[514] = 308; em[515] = 0; 
    em[516] = 1; em[517] = 8; em[518] = 1; /* 516: pointer.struct.asn1_string_st */
    	em[519] = 308; em[520] = 0; 
    em[521] = 1; em[522] = 8; em[523] = 1; /* 521: pointer.struct.asn1_string_st */
    	em[524] = 308; em[525] = 0; 
    em[526] = 1; em[527] = 8; em[528] = 1; /* 526: pointer.struct.asn1_string_st */
    	em[529] = 308; em[530] = 0; 
    em[531] = 1; em[532] = 8; em[533] = 1; /* 531: pointer.struct.asn1_string_st */
    	em[534] = 308; em[535] = 0; 
    em[536] = 1; em[537] = 8; em[538] = 1; /* 536: pointer.struct.asn1_string_st */
    	em[539] = 308; em[540] = 0; 
    em[541] = 1; em[542] = 8; em[543] = 1; /* 541: pointer.struct.ASN1_VALUE_st */
    	em[544] = 546; em[545] = 0; 
    em[546] = 0; em[547] = 0; em[548] = 0; /* 546: struct.ASN1_VALUE_st */
    em[549] = 0; em[550] = 16; em[551] = 1; /* 549: struct.GENERAL_NAME_st */
    	em[552] = 554; em[553] = 8; 
    em[554] = 0; em[555] = 8; em[556] = 15; /* 554: union.unknown */
    	em[557] = 116; em[558] = 0; 
    	em[559] = 587; em[560] = 0; 
    	em[561] = 516; em[562] = 0; 
    	em[563] = 516; em[564] = 0; 
    	em[565] = 448; em[566] = 0; 
    	em[567] = 318; em[568] = 0; 
    	em[569] = 291; em[570] = 0; 
    	em[571] = 516; em[572] = 0; 
    	em[573] = 422; em[574] = 0; 
    	em[575] = 436; em[576] = 0; 
    	em[577] = 422; em[578] = 0; 
    	em[579] = 318; em[580] = 0; 
    	em[581] = 516; em[582] = 0; 
    	em[583] = 436; em[584] = 0; 
    	em[585] = 448; em[586] = 0; 
    em[587] = 1; em[588] = 8; em[589] = 1; /* 587: pointer.struct.otherName_st */
    	em[590] = 441; em[591] = 0; 
    em[592] = 1; em[593] = 8; em[594] = 1; /* 592: pointer.struct.GENERAL_NAME_st */
    	em[595] = 549; em[596] = 0; 
    em[597] = 0; em[598] = 24; em[599] = 3; /* 597: struct.GENERAL_SUBTREE_st */
    	em[600] = 592; em[601] = 0; 
    	em[602] = 501; em[603] = 8; 
    	em[604] = 501; em[605] = 16; 
    em[606] = 0; em[607] = 0; em[608] = 1; /* 606: GENERAL_SUBTREE */
    	em[609] = 597; em[610] = 0; 
    em[611] = 0; em[612] = 16; em[613] = 2; /* 611: struct.NAME_CONSTRAINTS_st */
    	em[614] = 618; em[615] = 0; 
    	em[616] = 618; em[617] = 8; 
    em[618] = 1; em[619] = 8; em[620] = 1; /* 618: pointer.struct.stack_st_GENERAL_SUBTREE */
    	em[621] = 623; em[622] = 0; 
    em[623] = 0; em[624] = 32; em[625] = 2; /* 623: struct.stack_st_fake_GENERAL_SUBTREE */
    	em[626] = 630; em[627] = 8; 
    	em[628] = 217; em[629] = 24; 
    em[630] = 8884099; em[631] = 8; em[632] = 2; /* 630: pointer_to_array_of_pointers_to_stack */
    	em[633] = 637; em[634] = 0; 
    	em[635] = 214; em[636] = 20; 
    em[637] = 0; em[638] = 8; em[639] = 1; /* 637: pointer.GENERAL_SUBTREE */
    	em[640] = 606; em[641] = 0; 
    em[642] = 1; em[643] = 8; em[644] = 1; /* 642: pointer.struct.asn1_string_st */
    	em[645] = 647; em[646] = 0; 
    em[647] = 0; em[648] = 24; em[649] = 1; /* 647: struct.asn1_string_st */
    	em[650] = 131; em[651] = 8; 
    em[652] = 1; em[653] = 8; em[654] = 1; /* 652: pointer.struct.buf_mem_st */
    	em[655] = 657; em[656] = 0; 
    em[657] = 0; em[658] = 24; em[659] = 1; /* 657: struct.buf_mem_st */
    	em[660] = 116; em[661] = 8; 
    em[662] = 0; em[663] = 40; em[664] = 3; /* 662: struct.X509_name_st */
    	em[665] = 671; em[666] = 0; 
    	em[667] = 652; em[668] = 16; 
    	em[669] = 131; em[670] = 24; 
    em[671] = 1; em[672] = 8; em[673] = 1; /* 671: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[674] = 676; em[675] = 0; 
    em[676] = 0; em[677] = 32; em[678] = 2; /* 676: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[679] = 683; em[680] = 8; 
    	em[681] = 217; em[682] = 24; 
    em[683] = 8884099; em[684] = 8; em[685] = 2; /* 683: pointer_to_array_of_pointers_to_stack */
    	em[686] = 690; em[687] = 0; 
    	em[688] = 214; em[689] = 20; 
    em[690] = 0; em[691] = 8; em[692] = 1; /* 690: pointer.X509_NAME_ENTRY */
    	em[693] = 356; em[694] = 0; 
    em[695] = 1; em[696] = 8; em[697] = 1; /* 695: pointer.struct.DIST_POINT_NAME_st */
    	em[698] = 700; em[699] = 0; 
    em[700] = 0; em[701] = 24; em[702] = 2; /* 700: struct.DIST_POINT_NAME_st */
    	em[703] = 707; em[704] = 8; 
    	em[705] = 1008; em[706] = 16; 
    em[707] = 0; em[708] = 8; em[709] = 2; /* 707: union.unknown */
    	em[710] = 714; em[711] = 0; 
    	em[712] = 671; em[713] = 0; 
    em[714] = 1; em[715] = 8; em[716] = 1; /* 714: pointer.struct.stack_st_GENERAL_NAME */
    	em[717] = 719; em[718] = 0; 
    em[719] = 0; em[720] = 32; em[721] = 2; /* 719: struct.stack_st_fake_GENERAL_NAME */
    	em[722] = 726; em[723] = 8; 
    	em[724] = 217; em[725] = 24; 
    em[726] = 8884099; em[727] = 8; em[728] = 2; /* 726: pointer_to_array_of_pointers_to_stack */
    	em[729] = 733; em[730] = 0; 
    	em[731] = 214; em[732] = 20; 
    em[733] = 0; em[734] = 8; em[735] = 1; /* 733: pointer.GENERAL_NAME */
    	em[736] = 738; em[737] = 0; 
    em[738] = 0; em[739] = 0; em[740] = 1; /* 738: GENERAL_NAME */
    	em[741] = 743; em[742] = 0; 
    em[743] = 0; em[744] = 16; em[745] = 1; /* 743: struct.GENERAL_NAME_st */
    	em[746] = 748; em[747] = 8; 
    em[748] = 0; em[749] = 8; em[750] = 15; /* 748: union.unknown */
    	em[751] = 116; em[752] = 0; 
    	em[753] = 781; em[754] = 0; 
    	em[755] = 900; em[756] = 0; 
    	em[757] = 900; em[758] = 0; 
    	em[759] = 807; em[760] = 0; 
    	em[761] = 948; em[762] = 0; 
    	em[763] = 996; em[764] = 0; 
    	em[765] = 900; em[766] = 0; 
    	em[767] = 885; em[768] = 0; 
    	em[769] = 793; em[770] = 0; 
    	em[771] = 885; em[772] = 0; 
    	em[773] = 948; em[774] = 0; 
    	em[775] = 900; em[776] = 0; 
    	em[777] = 793; em[778] = 0; 
    	em[779] = 807; em[780] = 0; 
    em[781] = 1; em[782] = 8; em[783] = 1; /* 781: pointer.struct.otherName_st */
    	em[784] = 786; em[785] = 0; 
    em[786] = 0; em[787] = 16; em[788] = 2; /* 786: struct.otherName_st */
    	em[789] = 793; em[790] = 0; 
    	em[791] = 807; em[792] = 8; 
    em[793] = 1; em[794] = 8; em[795] = 1; /* 793: pointer.struct.asn1_object_st */
    	em[796] = 798; em[797] = 0; 
    em[798] = 0; em[799] = 40; em[800] = 3; /* 798: struct.asn1_object_st */
    	em[801] = 50; em[802] = 0; 
    	em[803] = 50; em[804] = 8; 
    	em[805] = 55; em[806] = 24; 
    em[807] = 1; em[808] = 8; em[809] = 1; /* 807: pointer.struct.asn1_type_st */
    	em[810] = 812; em[811] = 0; 
    em[812] = 0; em[813] = 16; em[814] = 1; /* 812: struct.asn1_type_st */
    	em[815] = 817; em[816] = 8; 
    em[817] = 0; em[818] = 8; em[819] = 20; /* 817: union.unknown */
    	em[820] = 116; em[821] = 0; 
    	em[822] = 860; em[823] = 0; 
    	em[824] = 793; em[825] = 0; 
    	em[826] = 870; em[827] = 0; 
    	em[828] = 875; em[829] = 0; 
    	em[830] = 880; em[831] = 0; 
    	em[832] = 885; em[833] = 0; 
    	em[834] = 890; em[835] = 0; 
    	em[836] = 895; em[837] = 0; 
    	em[838] = 900; em[839] = 0; 
    	em[840] = 905; em[841] = 0; 
    	em[842] = 910; em[843] = 0; 
    	em[844] = 915; em[845] = 0; 
    	em[846] = 920; em[847] = 0; 
    	em[848] = 925; em[849] = 0; 
    	em[850] = 930; em[851] = 0; 
    	em[852] = 935; em[853] = 0; 
    	em[854] = 860; em[855] = 0; 
    	em[856] = 860; em[857] = 0; 
    	em[858] = 940; em[859] = 0; 
    em[860] = 1; em[861] = 8; em[862] = 1; /* 860: pointer.struct.asn1_string_st */
    	em[863] = 865; em[864] = 0; 
    em[865] = 0; em[866] = 24; em[867] = 1; /* 865: struct.asn1_string_st */
    	em[868] = 131; em[869] = 8; 
    em[870] = 1; em[871] = 8; em[872] = 1; /* 870: pointer.struct.asn1_string_st */
    	em[873] = 865; em[874] = 0; 
    em[875] = 1; em[876] = 8; em[877] = 1; /* 875: pointer.struct.asn1_string_st */
    	em[878] = 865; em[879] = 0; 
    em[880] = 1; em[881] = 8; em[882] = 1; /* 880: pointer.struct.asn1_string_st */
    	em[883] = 865; em[884] = 0; 
    em[885] = 1; em[886] = 8; em[887] = 1; /* 885: pointer.struct.asn1_string_st */
    	em[888] = 865; em[889] = 0; 
    em[890] = 1; em[891] = 8; em[892] = 1; /* 890: pointer.struct.asn1_string_st */
    	em[893] = 865; em[894] = 0; 
    em[895] = 1; em[896] = 8; em[897] = 1; /* 895: pointer.struct.asn1_string_st */
    	em[898] = 865; em[899] = 0; 
    em[900] = 1; em[901] = 8; em[902] = 1; /* 900: pointer.struct.asn1_string_st */
    	em[903] = 865; em[904] = 0; 
    em[905] = 1; em[906] = 8; em[907] = 1; /* 905: pointer.struct.asn1_string_st */
    	em[908] = 865; em[909] = 0; 
    em[910] = 1; em[911] = 8; em[912] = 1; /* 910: pointer.struct.asn1_string_st */
    	em[913] = 865; em[914] = 0; 
    em[915] = 1; em[916] = 8; em[917] = 1; /* 915: pointer.struct.asn1_string_st */
    	em[918] = 865; em[919] = 0; 
    em[920] = 1; em[921] = 8; em[922] = 1; /* 920: pointer.struct.asn1_string_st */
    	em[923] = 865; em[924] = 0; 
    em[925] = 1; em[926] = 8; em[927] = 1; /* 925: pointer.struct.asn1_string_st */
    	em[928] = 865; em[929] = 0; 
    em[930] = 1; em[931] = 8; em[932] = 1; /* 930: pointer.struct.asn1_string_st */
    	em[933] = 865; em[934] = 0; 
    em[935] = 1; em[936] = 8; em[937] = 1; /* 935: pointer.struct.asn1_string_st */
    	em[938] = 865; em[939] = 0; 
    em[940] = 1; em[941] = 8; em[942] = 1; /* 940: pointer.struct.ASN1_VALUE_st */
    	em[943] = 945; em[944] = 0; 
    em[945] = 0; em[946] = 0; em[947] = 0; /* 945: struct.ASN1_VALUE_st */
    em[948] = 1; em[949] = 8; em[950] = 1; /* 948: pointer.struct.X509_name_st */
    	em[951] = 953; em[952] = 0; 
    em[953] = 0; em[954] = 40; em[955] = 3; /* 953: struct.X509_name_st */
    	em[956] = 962; em[957] = 0; 
    	em[958] = 986; em[959] = 16; 
    	em[960] = 131; em[961] = 24; 
    em[962] = 1; em[963] = 8; em[964] = 1; /* 962: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[965] = 967; em[966] = 0; 
    em[967] = 0; em[968] = 32; em[969] = 2; /* 967: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[970] = 974; em[971] = 8; 
    	em[972] = 217; em[973] = 24; 
    em[974] = 8884099; em[975] = 8; em[976] = 2; /* 974: pointer_to_array_of_pointers_to_stack */
    	em[977] = 981; em[978] = 0; 
    	em[979] = 214; em[980] = 20; 
    em[981] = 0; em[982] = 8; em[983] = 1; /* 981: pointer.X509_NAME_ENTRY */
    	em[984] = 356; em[985] = 0; 
    em[986] = 1; em[987] = 8; em[988] = 1; /* 986: pointer.struct.buf_mem_st */
    	em[989] = 991; em[990] = 0; 
    em[991] = 0; em[992] = 24; em[993] = 1; /* 991: struct.buf_mem_st */
    	em[994] = 116; em[995] = 8; 
    em[996] = 1; em[997] = 8; em[998] = 1; /* 996: pointer.struct.EDIPartyName_st */
    	em[999] = 1001; em[1000] = 0; 
    em[1001] = 0; em[1002] = 16; em[1003] = 2; /* 1001: struct.EDIPartyName_st */
    	em[1004] = 860; em[1005] = 0; 
    	em[1006] = 860; em[1007] = 8; 
    em[1008] = 1; em[1009] = 8; em[1010] = 1; /* 1008: pointer.struct.X509_name_st */
    	em[1011] = 662; em[1012] = 0; 
    em[1013] = 0; em[1014] = 0; em[1015] = 1; /* 1013: DIST_POINT */
    	em[1016] = 1018; em[1017] = 0; 
    em[1018] = 0; em[1019] = 32; em[1020] = 3; /* 1018: struct.DIST_POINT_st */
    	em[1021] = 695; em[1022] = 0; 
    	em[1023] = 642; em[1024] = 8; 
    	em[1025] = 714; em[1026] = 16; 
    em[1027] = 1; em[1028] = 8; em[1029] = 1; /* 1027: pointer.struct.stack_st_X509_POLICY_DATA */
    	em[1030] = 1032; em[1031] = 0; 
    em[1032] = 0; em[1033] = 32; em[1034] = 2; /* 1032: struct.stack_st_fake_X509_POLICY_DATA */
    	em[1035] = 1039; em[1036] = 8; 
    	em[1037] = 217; em[1038] = 24; 
    em[1039] = 8884099; em[1040] = 8; em[1041] = 2; /* 1039: pointer_to_array_of_pointers_to_stack */
    	em[1042] = 1046; em[1043] = 0; 
    	em[1044] = 214; em[1045] = 20; 
    em[1046] = 0; em[1047] = 8; em[1048] = 1; /* 1046: pointer.X509_POLICY_DATA */
    	em[1049] = 1051; em[1050] = 0; 
    em[1051] = 0; em[1052] = 0; em[1053] = 1; /* 1051: X509_POLICY_DATA */
    	em[1054] = 1056; em[1055] = 0; 
    em[1056] = 0; em[1057] = 32; em[1058] = 3; /* 1056: struct.X509_POLICY_DATA_st */
    	em[1059] = 1065; em[1060] = 8; 
    	em[1061] = 1079; em[1062] = 16; 
    	em[1063] = 1329; em[1064] = 24; 
    em[1065] = 1; em[1066] = 8; em[1067] = 1; /* 1065: pointer.struct.asn1_object_st */
    	em[1068] = 1070; em[1069] = 0; 
    em[1070] = 0; em[1071] = 40; em[1072] = 3; /* 1070: struct.asn1_object_st */
    	em[1073] = 50; em[1074] = 0; 
    	em[1075] = 50; em[1076] = 8; 
    	em[1077] = 55; em[1078] = 24; 
    em[1079] = 1; em[1080] = 8; em[1081] = 1; /* 1079: pointer.struct.stack_st_POLICYQUALINFO */
    	em[1082] = 1084; em[1083] = 0; 
    em[1084] = 0; em[1085] = 32; em[1086] = 2; /* 1084: struct.stack_st_fake_POLICYQUALINFO */
    	em[1087] = 1091; em[1088] = 8; 
    	em[1089] = 217; em[1090] = 24; 
    em[1091] = 8884099; em[1092] = 8; em[1093] = 2; /* 1091: pointer_to_array_of_pointers_to_stack */
    	em[1094] = 1098; em[1095] = 0; 
    	em[1096] = 214; em[1097] = 20; 
    em[1098] = 0; em[1099] = 8; em[1100] = 1; /* 1098: pointer.POLICYQUALINFO */
    	em[1101] = 1103; em[1102] = 0; 
    em[1103] = 0; em[1104] = 0; em[1105] = 1; /* 1103: POLICYQUALINFO */
    	em[1106] = 1108; em[1107] = 0; 
    em[1108] = 0; em[1109] = 16; em[1110] = 2; /* 1108: struct.POLICYQUALINFO_st */
    	em[1111] = 1115; em[1112] = 0; 
    	em[1113] = 1129; em[1114] = 8; 
    em[1115] = 1; em[1116] = 8; em[1117] = 1; /* 1115: pointer.struct.asn1_object_st */
    	em[1118] = 1120; em[1119] = 0; 
    em[1120] = 0; em[1121] = 40; em[1122] = 3; /* 1120: struct.asn1_object_st */
    	em[1123] = 50; em[1124] = 0; 
    	em[1125] = 50; em[1126] = 8; 
    	em[1127] = 55; em[1128] = 24; 
    em[1129] = 0; em[1130] = 8; em[1131] = 3; /* 1129: union.unknown */
    	em[1132] = 1138; em[1133] = 0; 
    	em[1134] = 1148; em[1135] = 0; 
    	em[1136] = 1211; em[1137] = 0; 
    em[1138] = 1; em[1139] = 8; em[1140] = 1; /* 1138: pointer.struct.asn1_string_st */
    	em[1141] = 1143; em[1142] = 0; 
    em[1143] = 0; em[1144] = 24; em[1145] = 1; /* 1143: struct.asn1_string_st */
    	em[1146] = 131; em[1147] = 8; 
    em[1148] = 1; em[1149] = 8; em[1150] = 1; /* 1148: pointer.struct.USERNOTICE_st */
    	em[1151] = 1153; em[1152] = 0; 
    em[1153] = 0; em[1154] = 16; em[1155] = 2; /* 1153: struct.USERNOTICE_st */
    	em[1156] = 1160; em[1157] = 0; 
    	em[1158] = 1172; em[1159] = 8; 
    em[1160] = 1; em[1161] = 8; em[1162] = 1; /* 1160: pointer.struct.NOTICEREF_st */
    	em[1163] = 1165; em[1164] = 0; 
    em[1165] = 0; em[1166] = 16; em[1167] = 2; /* 1165: struct.NOTICEREF_st */
    	em[1168] = 1172; em[1169] = 0; 
    	em[1170] = 1177; em[1171] = 8; 
    em[1172] = 1; em[1173] = 8; em[1174] = 1; /* 1172: pointer.struct.asn1_string_st */
    	em[1175] = 1143; em[1176] = 0; 
    em[1177] = 1; em[1178] = 8; em[1179] = 1; /* 1177: pointer.struct.stack_st_ASN1_INTEGER */
    	em[1180] = 1182; em[1181] = 0; 
    em[1182] = 0; em[1183] = 32; em[1184] = 2; /* 1182: struct.stack_st_fake_ASN1_INTEGER */
    	em[1185] = 1189; em[1186] = 8; 
    	em[1187] = 217; em[1188] = 24; 
    em[1189] = 8884099; em[1190] = 8; em[1191] = 2; /* 1189: pointer_to_array_of_pointers_to_stack */
    	em[1192] = 1196; em[1193] = 0; 
    	em[1194] = 214; em[1195] = 20; 
    em[1196] = 0; em[1197] = 8; em[1198] = 1; /* 1196: pointer.ASN1_INTEGER */
    	em[1199] = 1201; em[1200] = 0; 
    em[1201] = 0; em[1202] = 0; em[1203] = 1; /* 1201: ASN1_INTEGER */
    	em[1204] = 1206; em[1205] = 0; 
    em[1206] = 0; em[1207] = 24; em[1208] = 1; /* 1206: struct.asn1_string_st */
    	em[1209] = 131; em[1210] = 8; 
    em[1211] = 1; em[1212] = 8; em[1213] = 1; /* 1211: pointer.struct.asn1_type_st */
    	em[1214] = 1216; em[1215] = 0; 
    em[1216] = 0; em[1217] = 16; em[1218] = 1; /* 1216: struct.asn1_type_st */
    	em[1219] = 1221; em[1220] = 8; 
    em[1221] = 0; em[1222] = 8; em[1223] = 20; /* 1221: union.unknown */
    	em[1224] = 116; em[1225] = 0; 
    	em[1226] = 1172; em[1227] = 0; 
    	em[1228] = 1115; em[1229] = 0; 
    	em[1230] = 1264; em[1231] = 0; 
    	em[1232] = 1269; em[1233] = 0; 
    	em[1234] = 1274; em[1235] = 0; 
    	em[1236] = 1279; em[1237] = 0; 
    	em[1238] = 1284; em[1239] = 0; 
    	em[1240] = 1289; em[1241] = 0; 
    	em[1242] = 1138; em[1243] = 0; 
    	em[1244] = 1294; em[1245] = 0; 
    	em[1246] = 1299; em[1247] = 0; 
    	em[1248] = 1304; em[1249] = 0; 
    	em[1250] = 1309; em[1251] = 0; 
    	em[1252] = 1314; em[1253] = 0; 
    	em[1254] = 1319; em[1255] = 0; 
    	em[1256] = 1324; em[1257] = 0; 
    	em[1258] = 1172; em[1259] = 0; 
    	em[1260] = 1172; em[1261] = 0; 
    	em[1262] = 541; em[1263] = 0; 
    em[1264] = 1; em[1265] = 8; em[1266] = 1; /* 1264: pointer.struct.asn1_string_st */
    	em[1267] = 1143; em[1268] = 0; 
    em[1269] = 1; em[1270] = 8; em[1271] = 1; /* 1269: pointer.struct.asn1_string_st */
    	em[1272] = 1143; em[1273] = 0; 
    em[1274] = 1; em[1275] = 8; em[1276] = 1; /* 1274: pointer.struct.asn1_string_st */
    	em[1277] = 1143; em[1278] = 0; 
    em[1279] = 1; em[1280] = 8; em[1281] = 1; /* 1279: pointer.struct.asn1_string_st */
    	em[1282] = 1143; em[1283] = 0; 
    em[1284] = 1; em[1285] = 8; em[1286] = 1; /* 1284: pointer.struct.asn1_string_st */
    	em[1287] = 1143; em[1288] = 0; 
    em[1289] = 1; em[1290] = 8; em[1291] = 1; /* 1289: pointer.struct.asn1_string_st */
    	em[1292] = 1143; em[1293] = 0; 
    em[1294] = 1; em[1295] = 8; em[1296] = 1; /* 1294: pointer.struct.asn1_string_st */
    	em[1297] = 1143; em[1298] = 0; 
    em[1299] = 1; em[1300] = 8; em[1301] = 1; /* 1299: pointer.struct.asn1_string_st */
    	em[1302] = 1143; em[1303] = 0; 
    em[1304] = 1; em[1305] = 8; em[1306] = 1; /* 1304: pointer.struct.asn1_string_st */
    	em[1307] = 1143; em[1308] = 0; 
    em[1309] = 1; em[1310] = 8; em[1311] = 1; /* 1309: pointer.struct.asn1_string_st */
    	em[1312] = 1143; em[1313] = 0; 
    em[1314] = 1; em[1315] = 8; em[1316] = 1; /* 1314: pointer.struct.asn1_string_st */
    	em[1317] = 1143; em[1318] = 0; 
    em[1319] = 1; em[1320] = 8; em[1321] = 1; /* 1319: pointer.struct.asn1_string_st */
    	em[1322] = 1143; em[1323] = 0; 
    em[1324] = 1; em[1325] = 8; em[1326] = 1; /* 1324: pointer.struct.asn1_string_st */
    	em[1327] = 1143; em[1328] = 0; 
    em[1329] = 1; em[1330] = 8; em[1331] = 1; /* 1329: pointer.struct.stack_st_ASN1_OBJECT */
    	em[1332] = 1334; em[1333] = 0; 
    em[1334] = 0; em[1335] = 32; em[1336] = 2; /* 1334: struct.stack_st_fake_ASN1_OBJECT */
    	em[1337] = 1341; em[1338] = 8; 
    	em[1339] = 217; em[1340] = 24; 
    em[1341] = 8884099; em[1342] = 8; em[1343] = 2; /* 1341: pointer_to_array_of_pointers_to_stack */
    	em[1344] = 1348; em[1345] = 0; 
    	em[1346] = 214; em[1347] = 20; 
    em[1348] = 0; em[1349] = 8; em[1350] = 1; /* 1348: pointer.ASN1_OBJECT */
    	em[1351] = 244; em[1352] = 0; 
    em[1353] = 1; em[1354] = 8; em[1355] = 1; /* 1353: pointer.struct.asn1_string_st */
    	em[1356] = 1358; em[1357] = 0; 
    em[1358] = 0; em[1359] = 24; em[1360] = 1; /* 1358: struct.asn1_string_st */
    	em[1361] = 131; em[1362] = 8; 
    em[1363] = 1; em[1364] = 8; em[1365] = 1; /* 1363: pointer.struct.asn1_string_st */
    	em[1366] = 1358; em[1367] = 0; 
    em[1368] = 1; em[1369] = 8; em[1370] = 1; /* 1368: pointer.struct.AUTHORITY_KEYID_st */
    	em[1371] = 1373; em[1372] = 0; 
    em[1373] = 0; em[1374] = 24; em[1375] = 3; /* 1373: struct.AUTHORITY_KEYID_st */
    	em[1376] = 1363; em[1377] = 0; 
    	em[1378] = 1382; em[1379] = 8; 
    	em[1380] = 1353; em[1381] = 16; 
    em[1382] = 1; em[1383] = 8; em[1384] = 1; /* 1382: pointer.struct.stack_st_GENERAL_NAME */
    	em[1385] = 1387; em[1386] = 0; 
    em[1387] = 0; em[1388] = 32; em[1389] = 2; /* 1387: struct.stack_st_fake_GENERAL_NAME */
    	em[1390] = 1394; em[1391] = 8; 
    	em[1392] = 217; em[1393] = 24; 
    em[1394] = 8884099; em[1395] = 8; em[1396] = 2; /* 1394: pointer_to_array_of_pointers_to_stack */
    	em[1397] = 1401; em[1398] = 0; 
    	em[1399] = 214; em[1400] = 20; 
    em[1401] = 0; em[1402] = 8; em[1403] = 1; /* 1401: pointer.GENERAL_NAME */
    	em[1404] = 738; em[1405] = 0; 
    em[1406] = 0; em[1407] = 24; em[1408] = 1; /* 1406: struct.ASN1_ENCODING_st */
    	em[1409] = 131; em[1410] = 0; 
    em[1411] = 0; em[1412] = 40; em[1413] = 3; /* 1411: struct.asn1_object_st */
    	em[1414] = 50; em[1415] = 0; 
    	em[1416] = 50; em[1417] = 8; 
    	em[1418] = 55; em[1419] = 24; 
    em[1420] = 1; em[1421] = 8; em[1422] = 1; /* 1420: pointer.struct.asn1_object_st */
    	em[1423] = 1411; em[1424] = 0; 
    em[1425] = 1; em[1426] = 8; em[1427] = 1; /* 1425: pointer.struct.asn1_string_st */
    	em[1428] = 276; em[1429] = 0; 
    em[1430] = 0; em[1431] = 0; em[1432] = 0; /* 1430: struct.ASN1_VALUE_st */
    em[1433] = 1; em[1434] = 8; em[1435] = 1; /* 1433: pointer.struct.ASN1_VALUE_st */
    	em[1436] = 1430; em[1437] = 0; 
    em[1438] = 1; em[1439] = 8; em[1440] = 1; /* 1438: pointer.struct.asn1_string_st */
    	em[1441] = 1443; em[1442] = 0; 
    em[1443] = 0; em[1444] = 24; em[1445] = 1; /* 1443: struct.asn1_string_st */
    	em[1446] = 131; em[1447] = 8; 
    em[1448] = 1; em[1449] = 8; em[1450] = 1; /* 1448: pointer.struct.asn1_string_st */
    	em[1451] = 1443; em[1452] = 0; 
    em[1453] = 1; em[1454] = 8; em[1455] = 1; /* 1453: pointer.struct.asn1_string_st */
    	em[1456] = 1443; em[1457] = 0; 
    em[1458] = 1; em[1459] = 8; em[1460] = 1; /* 1458: pointer.struct.asn1_string_st */
    	em[1461] = 1443; em[1462] = 0; 
    em[1463] = 1; em[1464] = 8; em[1465] = 1; /* 1463: pointer.struct.asn1_string_st */
    	em[1466] = 1443; em[1467] = 0; 
    em[1468] = 1; em[1469] = 8; em[1470] = 1; /* 1468: pointer.struct.asn1_string_st */
    	em[1471] = 1443; em[1472] = 0; 
    em[1473] = 1; em[1474] = 8; em[1475] = 1; /* 1473: pointer.struct.asn1_string_st */
    	em[1476] = 1443; em[1477] = 0; 
    em[1478] = 1; em[1479] = 8; em[1480] = 1; /* 1478: pointer.struct.asn1_string_st */
    	em[1481] = 1443; em[1482] = 0; 
    em[1483] = 1; em[1484] = 8; em[1485] = 1; /* 1483: pointer.struct.asn1_string_st */
    	em[1486] = 1443; em[1487] = 0; 
    em[1488] = 0; em[1489] = 8; em[1490] = 20; /* 1488: union.unknown */
    	em[1491] = 116; em[1492] = 0; 
    	em[1493] = 1531; em[1494] = 0; 
    	em[1495] = 1536; em[1496] = 0; 
    	em[1497] = 1483; em[1498] = 0; 
    	em[1499] = 1550; em[1500] = 0; 
    	em[1501] = 1478; em[1502] = 0; 
    	em[1503] = 1555; em[1504] = 0; 
    	em[1505] = 1473; em[1506] = 0; 
    	em[1507] = 1468; em[1508] = 0; 
    	em[1509] = 1463; em[1510] = 0; 
    	em[1511] = 1458; em[1512] = 0; 
    	em[1513] = 1453; em[1514] = 0; 
    	em[1515] = 1448; em[1516] = 0; 
    	em[1517] = 1560; em[1518] = 0; 
    	em[1519] = 1565; em[1520] = 0; 
    	em[1521] = 1570; em[1522] = 0; 
    	em[1523] = 1438; em[1524] = 0; 
    	em[1525] = 1531; em[1526] = 0; 
    	em[1527] = 1531; em[1528] = 0; 
    	em[1529] = 1433; em[1530] = 0; 
    em[1531] = 1; em[1532] = 8; em[1533] = 1; /* 1531: pointer.struct.asn1_string_st */
    	em[1534] = 1443; em[1535] = 0; 
    em[1536] = 1; em[1537] = 8; em[1538] = 1; /* 1536: pointer.struct.asn1_object_st */
    	em[1539] = 1541; em[1540] = 0; 
    em[1541] = 0; em[1542] = 40; em[1543] = 3; /* 1541: struct.asn1_object_st */
    	em[1544] = 50; em[1545] = 0; 
    	em[1546] = 50; em[1547] = 8; 
    	em[1548] = 55; em[1549] = 24; 
    em[1550] = 1; em[1551] = 8; em[1552] = 1; /* 1550: pointer.struct.asn1_string_st */
    	em[1553] = 1443; em[1554] = 0; 
    em[1555] = 1; em[1556] = 8; em[1557] = 1; /* 1555: pointer.struct.asn1_string_st */
    	em[1558] = 1443; em[1559] = 0; 
    em[1560] = 1; em[1561] = 8; em[1562] = 1; /* 1560: pointer.struct.asn1_string_st */
    	em[1563] = 1443; em[1564] = 0; 
    em[1565] = 1; em[1566] = 8; em[1567] = 1; /* 1565: pointer.struct.asn1_string_st */
    	em[1568] = 1443; em[1569] = 0; 
    em[1570] = 1; em[1571] = 8; em[1572] = 1; /* 1570: pointer.struct.asn1_string_st */
    	em[1573] = 1443; em[1574] = 0; 
    em[1575] = 0; em[1576] = 16; em[1577] = 1; /* 1575: struct.asn1_type_st */
    	em[1578] = 1488; em[1579] = 8; 
    em[1580] = 0; em[1581] = 0; em[1582] = 1; /* 1580: X509_EXTENSION */
    	em[1583] = 1585; em[1584] = 0; 
    em[1585] = 0; em[1586] = 24; em[1587] = 2; /* 1585: struct.X509_extension_st */
    	em[1588] = 1420; em[1589] = 0; 
    	em[1590] = 1592; em[1591] = 16; 
    em[1592] = 1; em[1593] = 8; em[1594] = 1; /* 1592: pointer.struct.asn1_string_st */
    	em[1595] = 1597; em[1596] = 0; 
    em[1597] = 0; em[1598] = 24; em[1599] = 1; /* 1597: struct.asn1_string_st */
    	em[1600] = 131; em[1601] = 8; 
    em[1602] = 1; em[1603] = 8; em[1604] = 1; /* 1602: pointer.struct.asn1_type_st */
    	em[1605] = 1575; em[1606] = 0; 
    em[1607] = 1; em[1608] = 8; em[1609] = 1; /* 1607: pointer.struct.asn1_string_st */
    	em[1610] = 1612; em[1611] = 0; 
    em[1612] = 0; em[1613] = 24; em[1614] = 1; /* 1612: struct.asn1_string_st */
    	em[1615] = 131; em[1616] = 8; 
    em[1617] = 1; em[1618] = 8; em[1619] = 1; /* 1617: pointer.struct.asn1_string_st */
    	em[1620] = 1612; em[1621] = 0; 
    em[1622] = 1; em[1623] = 8; em[1624] = 1; /* 1622: pointer.struct.asn1_string_st */
    	em[1625] = 1612; em[1626] = 0; 
    em[1627] = 1; em[1628] = 8; em[1629] = 1; /* 1627: pointer.struct.asn1_string_st */
    	em[1630] = 1612; em[1631] = 0; 
    em[1632] = 1; em[1633] = 8; em[1634] = 1; /* 1632: pointer.struct.asn1_string_st */
    	em[1635] = 1612; em[1636] = 0; 
    em[1637] = 1; em[1638] = 8; em[1639] = 1; /* 1637: pointer.struct.asn1_string_st */
    	em[1640] = 1612; em[1641] = 0; 
    em[1642] = 8884097; em[1643] = 8; em[1644] = 0; /* 1642: pointer.func */
    em[1645] = 8884097; em[1646] = 8; em[1647] = 0; /* 1645: pointer.func */
    em[1648] = 8884097; em[1649] = 8; em[1650] = 0; /* 1648: pointer.func */
    em[1651] = 8884097; em[1652] = 8; em[1653] = 0; /* 1651: pointer.func */
    em[1654] = 8884097; em[1655] = 8; em[1656] = 0; /* 1654: pointer.func */
    em[1657] = 0; em[1658] = 48; em[1659] = 6; /* 1657: struct.rand_meth_st */
    	em[1660] = 1672; em[1661] = 0; 
    	em[1662] = 1675; em[1663] = 8; 
    	em[1664] = 1678; em[1665] = 16; 
    	em[1666] = 1681; em[1667] = 24; 
    	em[1668] = 1675; em[1669] = 32; 
    	em[1670] = 1645; em[1671] = 40; 
    em[1672] = 8884097; em[1673] = 8; em[1674] = 0; /* 1672: pointer.func */
    em[1675] = 8884097; em[1676] = 8; em[1677] = 0; /* 1675: pointer.func */
    em[1678] = 8884097; em[1679] = 8; em[1680] = 0; /* 1678: pointer.func */
    em[1681] = 8884097; em[1682] = 8; em[1683] = 0; /* 1681: pointer.func */
    em[1684] = 8884097; em[1685] = 8; em[1686] = 0; /* 1684: pointer.func */
    em[1687] = 1; em[1688] = 8; em[1689] = 1; /* 1687: pointer.struct.bignum_st */
    	em[1690] = 1692; em[1691] = 0; 
    em[1692] = 0; em[1693] = 24; em[1694] = 1; /* 1692: struct.bignum_st */
    	em[1695] = 1697; em[1696] = 0; 
    em[1697] = 8884099; em[1698] = 8; em[1699] = 2; /* 1697: pointer_to_array_of_pointers_to_stack */
    	em[1700] = 1704; em[1701] = 0; 
    	em[1702] = 214; em[1703] = 12; 
    em[1704] = 0; em[1705] = 8; em[1706] = 0; /* 1704: long unsigned int */
    em[1707] = 0; em[1708] = 32; em[1709] = 3; /* 1707: struct.ecdh_method */
    	em[1710] = 50; em[1711] = 0; 
    	em[1712] = 1716; em[1713] = 8; 
    	em[1714] = 116; em[1715] = 24; 
    em[1716] = 8884097; em[1717] = 8; em[1718] = 0; /* 1716: pointer.func */
    em[1719] = 8884097; em[1720] = 8; em[1721] = 0; /* 1719: pointer.func */
    em[1722] = 8884097; em[1723] = 8; em[1724] = 0; /* 1722: pointer.func */
    em[1725] = 0; em[1726] = 40; em[1727] = 5; /* 1725: struct.ec_extra_data_st */
    	em[1728] = 1738; em[1729] = 0; 
    	em[1730] = 1743; em[1731] = 8; 
    	em[1732] = 1746; em[1733] = 16; 
    	em[1734] = 1749; em[1735] = 24; 
    	em[1736] = 1749; em[1737] = 32; 
    em[1738] = 1; em[1739] = 8; em[1740] = 1; /* 1738: pointer.struct.ec_extra_data_st */
    	em[1741] = 1725; em[1742] = 0; 
    em[1743] = 0; em[1744] = 8; em[1745] = 0; /* 1743: pointer.void */
    em[1746] = 8884097; em[1747] = 8; em[1748] = 0; /* 1746: pointer.func */
    em[1749] = 8884097; em[1750] = 8; em[1751] = 0; /* 1749: pointer.func */
    em[1752] = 1; em[1753] = 8; em[1754] = 1; /* 1752: pointer.struct.X509_POLICY_DATA_st */
    	em[1755] = 1056; em[1756] = 0; 
    em[1757] = 8884097; em[1758] = 8; em[1759] = 0; /* 1757: pointer.func */
    em[1760] = 0; em[1761] = 40; em[1762] = 2; /* 1760: struct.X509_POLICY_CACHE_st */
    	em[1763] = 1752; em[1764] = 0; 
    	em[1765] = 1027; em[1766] = 8; 
    em[1767] = 8884097; em[1768] = 8; em[1769] = 0; /* 1767: pointer.func */
    em[1770] = 1; em[1771] = 8; em[1772] = 1; /* 1770: pointer.struct.rsa_meth_st */
    	em[1773] = 1775; em[1774] = 0; 
    em[1775] = 0; em[1776] = 112; em[1777] = 13; /* 1775: struct.rsa_meth_st */
    	em[1778] = 50; em[1779] = 0; 
    	em[1780] = 1757; em[1781] = 8; 
    	em[1782] = 1757; em[1783] = 16; 
    	em[1784] = 1757; em[1785] = 24; 
    	em[1786] = 1757; em[1787] = 32; 
    	em[1788] = 1804; em[1789] = 40; 
    	em[1790] = 1807; em[1791] = 48; 
    	em[1792] = 1810; em[1793] = 56; 
    	em[1794] = 1810; em[1795] = 64; 
    	em[1796] = 116; em[1797] = 80; 
    	em[1798] = 1813; em[1799] = 88; 
    	em[1800] = 1816; em[1801] = 96; 
    	em[1802] = 1819; em[1803] = 104; 
    em[1804] = 8884097; em[1805] = 8; em[1806] = 0; /* 1804: pointer.func */
    em[1807] = 8884097; em[1808] = 8; em[1809] = 0; /* 1807: pointer.func */
    em[1810] = 8884097; em[1811] = 8; em[1812] = 0; /* 1810: pointer.func */
    em[1813] = 8884097; em[1814] = 8; em[1815] = 0; /* 1813: pointer.func */
    em[1816] = 8884097; em[1817] = 8; em[1818] = 0; /* 1816: pointer.func */
    em[1819] = 8884097; em[1820] = 8; em[1821] = 0; /* 1819: pointer.func */
    em[1822] = 8884097; em[1823] = 8; em[1824] = 0; /* 1822: pointer.func */
    em[1825] = 8884097; em[1826] = 8; em[1827] = 0; /* 1825: pointer.func */
    em[1828] = 0; em[1829] = 208; em[1830] = 24; /* 1828: struct.evp_pkey_asn1_method_st */
    	em[1831] = 116; em[1832] = 16; 
    	em[1833] = 116; em[1834] = 24; 
    	em[1835] = 1879; em[1836] = 32; 
    	em[1837] = 1882; em[1838] = 40; 
    	em[1839] = 1885; em[1840] = 48; 
    	em[1841] = 1888; em[1842] = 56; 
    	em[1843] = 1891; em[1844] = 64; 
    	em[1845] = 1894; em[1846] = 72; 
    	em[1847] = 1888; em[1848] = 80; 
    	em[1849] = 1825; em[1850] = 88; 
    	em[1851] = 1825; em[1852] = 96; 
    	em[1853] = 1897; em[1854] = 104; 
    	em[1855] = 1900; em[1856] = 112; 
    	em[1857] = 1825; em[1858] = 120; 
    	em[1859] = 1903; em[1860] = 128; 
    	em[1861] = 1885; em[1862] = 136; 
    	em[1863] = 1888; em[1864] = 144; 
    	em[1865] = 1684; em[1866] = 152; 
    	em[1867] = 1906; em[1868] = 160; 
    	em[1869] = 1822; em[1870] = 168; 
    	em[1871] = 1897; em[1872] = 176; 
    	em[1873] = 1900; em[1874] = 184; 
    	em[1875] = 1909; em[1876] = 192; 
    	em[1877] = 1912; em[1878] = 200; 
    em[1879] = 8884097; em[1880] = 8; em[1881] = 0; /* 1879: pointer.func */
    em[1882] = 8884097; em[1883] = 8; em[1884] = 0; /* 1882: pointer.func */
    em[1885] = 8884097; em[1886] = 8; em[1887] = 0; /* 1885: pointer.func */
    em[1888] = 8884097; em[1889] = 8; em[1890] = 0; /* 1888: pointer.func */
    em[1891] = 8884097; em[1892] = 8; em[1893] = 0; /* 1891: pointer.func */
    em[1894] = 8884097; em[1895] = 8; em[1896] = 0; /* 1894: pointer.func */
    em[1897] = 8884097; em[1898] = 8; em[1899] = 0; /* 1897: pointer.func */
    em[1900] = 8884097; em[1901] = 8; em[1902] = 0; /* 1900: pointer.func */
    em[1903] = 8884097; em[1904] = 8; em[1905] = 0; /* 1903: pointer.func */
    em[1906] = 8884097; em[1907] = 8; em[1908] = 0; /* 1906: pointer.func */
    em[1909] = 8884097; em[1910] = 8; em[1911] = 0; /* 1909: pointer.func */
    em[1912] = 8884097; em[1913] = 8; em[1914] = 0; /* 1912: pointer.func */
    em[1915] = 1; em[1916] = 8; em[1917] = 1; /* 1915: pointer.struct.ec_group_st */
    	em[1918] = 1920; em[1919] = 0; 
    em[1920] = 0; em[1921] = 232; em[1922] = 12; /* 1920: struct.ec_group_st */
    	em[1923] = 1947; em[1924] = 0; 
    	em[1925] = 2116; em[1926] = 8; 
    	em[1927] = 2132; em[1928] = 16; 
    	em[1929] = 2132; em[1930] = 40; 
    	em[1931] = 131; em[1932] = 80; 
    	em[1933] = 2144; em[1934] = 96; 
    	em[1935] = 2132; em[1936] = 104; 
    	em[1937] = 2132; em[1938] = 152; 
    	em[1939] = 2132; em[1940] = 176; 
    	em[1941] = 1743; em[1942] = 208; 
    	em[1943] = 1743; em[1944] = 216; 
    	em[1945] = 2167; em[1946] = 224; 
    em[1947] = 1; em[1948] = 8; em[1949] = 1; /* 1947: pointer.struct.ec_method_st */
    	em[1950] = 1952; em[1951] = 0; 
    em[1952] = 0; em[1953] = 304; em[1954] = 37; /* 1952: struct.ec_method_st */
    	em[1955] = 2029; em[1956] = 8; 
    	em[1957] = 2032; em[1958] = 16; 
    	em[1959] = 2032; em[1960] = 24; 
    	em[1961] = 2035; em[1962] = 32; 
    	em[1963] = 2038; em[1964] = 40; 
    	em[1965] = 2041; em[1966] = 48; 
    	em[1967] = 2044; em[1968] = 56; 
    	em[1969] = 2047; em[1970] = 64; 
    	em[1971] = 1654; em[1972] = 72; 
    	em[1973] = 2050; em[1974] = 80; 
    	em[1975] = 2050; em[1976] = 88; 
    	em[1977] = 2053; em[1978] = 96; 
    	em[1979] = 2056; em[1980] = 104; 
    	em[1981] = 2059; em[1982] = 112; 
    	em[1983] = 2062; em[1984] = 120; 
    	em[1985] = 2065; em[1986] = 128; 
    	em[1987] = 2068; em[1988] = 136; 
    	em[1989] = 2071; em[1990] = 144; 
    	em[1991] = 2074; em[1992] = 152; 
    	em[1993] = 2077; em[1994] = 160; 
    	em[1995] = 2080; em[1996] = 168; 
    	em[1997] = 2083; em[1998] = 176; 
    	em[1999] = 2086; em[2000] = 184; 
    	em[2001] = 2089; em[2002] = 192; 
    	em[2003] = 2092; em[2004] = 200; 
    	em[2005] = 2095; em[2006] = 208; 
    	em[2007] = 2086; em[2008] = 216; 
    	em[2009] = 2098; em[2010] = 224; 
    	em[2011] = 2101; em[2012] = 232; 
    	em[2013] = 2104; em[2014] = 240; 
    	em[2015] = 2044; em[2016] = 248; 
    	em[2017] = 2107; em[2018] = 256; 
    	em[2019] = 2110; em[2020] = 264; 
    	em[2021] = 2107; em[2022] = 272; 
    	em[2023] = 2110; em[2024] = 280; 
    	em[2025] = 2110; em[2026] = 288; 
    	em[2027] = 2113; em[2028] = 296; 
    em[2029] = 8884097; em[2030] = 8; em[2031] = 0; /* 2029: pointer.func */
    em[2032] = 8884097; em[2033] = 8; em[2034] = 0; /* 2032: pointer.func */
    em[2035] = 8884097; em[2036] = 8; em[2037] = 0; /* 2035: pointer.func */
    em[2038] = 8884097; em[2039] = 8; em[2040] = 0; /* 2038: pointer.func */
    em[2041] = 8884097; em[2042] = 8; em[2043] = 0; /* 2041: pointer.func */
    em[2044] = 8884097; em[2045] = 8; em[2046] = 0; /* 2044: pointer.func */
    em[2047] = 8884097; em[2048] = 8; em[2049] = 0; /* 2047: pointer.func */
    em[2050] = 8884097; em[2051] = 8; em[2052] = 0; /* 2050: pointer.func */
    em[2053] = 8884097; em[2054] = 8; em[2055] = 0; /* 2053: pointer.func */
    em[2056] = 8884097; em[2057] = 8; em[2058] = 0; /* 2056: pointer.func */
    em[2059] = 8884097; em[2060] = 8; em[2061] = 0; /* 2059: pointer.func */
    em[2062] = 8884097; em[2063] = 8; em[2064] = 0; /* 2062: pointer.func */
    em[2065] = 8884097; em[2066] = 8; em[2067] = 0; /* 2065: pointer.func */
    em[2068] = 8884097; em[2069] = 8; em[2070] = 0; /* 2068: pointer.func */
    em[2071] = 8884097; em[2072] = 8; em[2073] = 0; /* 2071: pointer.func */
    em[2074] = 8884097; em[2075] = 8; em[2076] = 0; /* 2074: pointer.func */
    em[2077] = 8884097; em[2078] = 8; em[2079] = 0; /* 2077: pointer.func */
    em[2080] = 8884097; em[2081] = 8; em[2082] = 0; /* 2080: pointer.func */
    em[2083] = 8884097; em[2084] = 8; em[2085] = 0; /* 2083: pointer.func */
    em[2086] = 8884097; em[2087] = 8; em[2088] = 0; /* 2086: pointer.func */
    em[2089] = 8884097; em[2090] = 8; em[2091] = 0; /* 2089: pointer.func */
    em[2092] = 8884097; em[2093] = 8; em[2094] = 0; /* 2092: pointer.func */
    em[2095] = 8884097; em[2096] = 8; em[2097] = 0; /* 2095: pointer.func */
    em[2098] = 8884097; em[2099] = 8; em[2100] = 0; /* 2098: pointer.func */
    em[2101] = 8884097; em[2102] = 8; em[2103] = 0; /* 2101: pointer.func */
    em[2104] = 8884097; em[2105] = 8; em[2106] = 0; /* 2104: pointer.func */
    em[2107] = 8884097; em[2108] = 8; em[2109] = 0; /* 2107: pointer.func */
    em[2110] = 8884097; em[2111] = 8; em[2112] = 0; /* 2110: pointer.func */
    em[2113] = 8884097; em[2114] = 8; em[2115] = 0; /* 2113: pointer.func */
    em[2116] = 1; em[2117] = 8; em[2118] = 1; /* 2116: pointer.struct.ec_point_st */
    	em[2119] = 2121; em[2120] = 0; 
    em[2121] = 0; em[2122] = 88; em[2123] = 4; /* 2121: struct.ec_point_st */
    	em[2124] = 1947; em[2125] = 0; 
    	em[2126] = 2132; em[2127] = 8; 
    	em[2128] = 2132; em[2129] = 32; 
    	em[2130] = 2132; em[2131] = 56; 
    em[2132] = 0; em[2133] = 24; em[2134] = 1; /* 2132: struct.bignum_st */
    	em[2135] = 2137; em[2136] = 0; 
    em[2137] = 8884099; em[2138] = 8; em[2139] = 2; /* 2137: pointer_to_array_of_pointers_to_stack */
    	em[2140] = 1704; em[2141] = 0; 
    	em[2142] = 214; em[2143] = 12; 
    em[2144] = 1; em[2145] = 8; em[2146] = 1; /* 2144: pointer.struct.ec_extra_data_st */
    	em[2147] = 2149; em[2148] = 0; 
    em[2149] = 0; em[2150] = 40; em[2151] = 5; /* 2149: struct.ec_extra_data_st */
    	em[2152] = 2162; em[2153] = 0; 
    	em[2154] = 1743; em[2155] = 8; 
    	em[2156] = 1746; em[2157] = 16; 
    	em[2158] = 1749; em[2159] = 24; 
    	em[2160] = 1749; em[2161] = 32; 
    em[2162] = 1; em[2163] = 8; em[2164] = 1; /* 2162: pointer.struct.ec_extra_data_st */
    	em[2165] = 2149; em[2166] = 0; 
    em[2167] = 8884097; em[2168] = 8; em[2169] = 0; /* 2167: pointer.func */
    em[2170] = 0; em[2171] = 40; em[2172] = 3; /* 2170: struct.asn1_object_st */
    	em[2173] = 50; em[2174] = 0; 
    	em[2175] = 50; em[2176] = 8; 
    	em[2177] = 55; em[2178] = 24; 
    em[2179] = 1; em[2180] = 8; em[2181] = 1; /* 2179: pointer.struct.x509_st */
    	em[2182] = 2184; em[2183] = 0; 
    em[2184] = 0; em[2185] = 184; em[2186] = 12; /* 2184: struct.x509_st */
    	em[2187] = 2211; em[2188] = 0; 
    	em[2189] = 2246; em[2190] = 8; 
    	em[2191] = 1425; em[2192] = 16; 
    	em[2193] = 116; em[2194] = 32; 
    	em[2195] = 3244; em[2196] = 40; 
    	em[2197] = 281; em[2198] = 104; 
    	em[2199] = 1368; em[2200] = 112; 
    	em[2201] = 3258; em[2202] = 120; 
    	em[2203] = 3263; em[2204] = 128; 
    	em[2205] = 3287; em[2206] = 136; 
    	em[2207] = 3311; em[2208] = 144; 
    	em[2209] = 286; em[2210] = 176; 
    em[2211] = 1; em[2212] = 8; em[2213] = 1; /* 2211: pointer.struct.x509_cinf_st */
    	em[2214] = 2216; em[2215] = 0; 
    em[2216] = 0; em[2217] = 104; em[2218] = 11; /* 2216: struct.x509_cinf_st */
    	em[2219] = 2241; em[2220] = 0; 
    	em[2221] = 2241; em[2222] = 8; 
    	em[2223] = 2246; em[2224] = 16; 
    	em[2225] = 2251; em[2226] = 24; 
    	em[2227] = 2299; em[2228] = 32; 
    	em[2229] = 2251; em[2230] = 40; 
    	em[2231] = 2316; em[2232] = 48; 
    	em[2233] = 1425; em[2234] = 56; 
    	em[2235] = 1425; em[2236] = 64; 
    	em[2237] = 3220; em[2238] = 72; 
    	em[2239] = 1406; em[2240] = 80; 
    em[2241] = 1; em[2242] = 8; em[2243] = 1; /* 2241: pointer.struct.asn1_string_st */
    	em[2244] = 276; em[2245] = 0; 
    em[2246] = 1; em[2247] = 8; em[2248] = 1; /* 2246: pointer.struct.X509_algor_st */
    	em[2249] = 29; em[2250] = 0; 
    em[2251] = 1; em[2252] = 8; em[2253] = 1; /* 2251: pointer.struct.X509_name_st */
    	em[2254] = 2256; em[2255] = 0; 
    em[2256] = 0; em[2257] = 40; em[2258] = 3; /* 2256: struct.X509_name_st */
    	em[2259] = 2265; em[2260] = 0; 
    	em[2261] = 2289; em[2262] = 16; 
    	em[2263] = 131; em[2264] = 24; 
    em[2265] = 1; em[2266] = 8; em[2267] = 1; /* 2265: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[2268] = 2270; em[2269] = 0; 
    em[2270] = 0; em[2271] = 32; em[2272] = 2; /* 2270: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[2273] = 2277; em[2274] = 8; 
    	em[2275] = 217; em[2276] = 24; 
    em[2277] = 8884099; em[2278] = 8; em[2279] = 2; /* 2277: pointer_to_array_of_pointers_to_stack */
    	em[2280] = 2284; em[2281] = 0; 
    	em[2282] = 214; em[2283] = 20; 
    em[2284] = 0; em[2285] = 8; em[2286] = 1; /* 2284: pointer.X509_NAME_ENTRY */
    	em[2287] = 356; em[2288] = 0; 
    em[2289] = 1; em[2290] = 8; em[2291] = 1; /* 2289: pointer.struct.buf_mem_st */
    	em[2292] = 2294; em[2293] = 0; 
    em[2294] = 0; em[2295] = 24; em[2296] = 1; /* 2294: struct.buf_mem_st */
    	em[2297] = 116; em[2298] = 8; 
    em[2299] = 1; em[2300] = 8; em[2301] = 1; /* 2299: pointer.struct.X509_val_st */
    	em[2302] = 2304; em[2303] = 0; 
    em[2304] = 0; em[2305] = 16; em[2306] = 2; /* 2304: struct.X509_val_st */
    	em[2307] = 2311; em[2308] = 0; 
    	em[2309] = 2311; em[2310] = 8; 
    em[2311] = 1; em[2312] = 8; em[2313] = 1; /* 2311: pointer.struct.asn1_string_st */
    	em[2314] = 276; em[2315] = 0; 
    em[2316] = 1; em[2317] = 8; em[2318] = 1; /* 2316: pointer.struct.X509_pubkey_st */
    	em[2319] = 2321; em[2320] = 0; 
    em[2321] = 0; em[2322] = 24; em[2323] = 3; /* 2321: struct.X509_pubkey_st */
    	em[2324] = 2330; em[2325] = 0; 
    	em[2326] = 2335; em[2327] = 8; 
    	em[2328] = 2340; em[2329] = 16; 
    em[2330] = 1; em[2331] = 8; em[2332] = 1; /* 2330: pointer.struct.X509_algor_st */
    	em[2333] = 29; em[2334] = 0; 
    em[2335] = 1; em[2336] = 8; em[2337] = 1; /* 2335: pointer.struct.asn1_string_st */
    	em[2338] = 1206; em[2339] = 0; 
    em[2340] = 1; em[2341] = 8; em[2342] = 1; /* 2340: pointer.struct.evp_pkey_st */
    	em[2343] = 2345; em[2344] = 0; 
    em[2345] = 0; em[2346] = 56; em[2347] = 4; /* 2345: struct.evp_pkey_st */
    	em[2348] = 2356; em[2349] = 16; 
    	em[2350] = 2361; em[2351] = 24; 
    	em[2352] = 2589; em[2353] = 32; 
    	em[2354] = 3048; em[2355] = 48; 
    em[2356] = 1; em[2357] = 8; em[2358] = 1; /* 2356: pointer.struct.evp_pkey_asn1_method_st */
    	em[2359] = 1828; em[2360] = 0; 
    em[2361] = 1; em[2362] = 8; em[2363] = 1; /* 2361: pointer.struct.engine_st */
    	em[2364] = 2366; em[2365] = 0; 
    em[2366] = 0; em[2367] = 216; em[2368] = 24; /* 2366: struct.engine_st */
    	em[2369] = 50; em[2370] = 0; 
    	em[2371] = 50; em[2372] = 8; 
    	em[2373] = 1770; em[2374] = 16; 
    	em[2375] = 2417; em[2376] = 24; 
    	em[2377] = 2462; em[2378] = 32; 
    	em[2379] = 2495; em[2380] = 40; 
    	em[2381] = 2500; em[2382] = 48; 
    	em[2383] = 2527; em[2384] = 56; 
    	em[2385] = 2532; em[2386] = 64; 
    	em[2387] = 2540; em[2388] = 72; 
    	em[2389] = 2543; em[2390] = 80; 
    	em[2391] = 1642; em[2392] = 88; 
    	em[2393] = 1651; em[2394] = 96; 
    	em[2395] = 2546; em[2396] = 104; 
    	em[2397] = 2546; em[2398] = 112; 
    	em[2399] = 2546; em[2400] = 120; 
    	em[2401] = 2549; em[2402] = 128; 
    	em[2403] = 2552; em[2404] = 136; 
    	em[2405] = 2552; em[2406] = 144; 
    	em[2407] = 2555; em[2408] = 152; 
    	em[2409] = 2558; em[2410] = 160; 
    	em[2411] = 2570; em[2412] = 184; 
    	em[2413] = 2584; em[2414] = 200; 
    	em[2415] = 2584; em[2416] = 208; 
    em[2417] = 1; em[2418] = 8; em[2419] = 1; /* 2417: pointer.struct.dsa_method */
    	em[2420] = 2422; em[2421] = 0; 
    em[2422] = 0; em[2423] = 96; em[2424] = 11; /* 2422: struct.dsa_method */
    	em[2425] = 50; em[2426] = 0; 
    	em[2427] = 2447; em[2428] = 8; 
    	em[2429] = 1722; em[2430] = 16; 
    	em[2431] = 2450; em[2432] = 24; 
    	em[2433] = 2453; em[2434] = 32; 
    	em[2435] = 2456; em[2436] = 40; 
    	em[2437] = 1648; em[2438] = 48; 
    	em[2439] = 1648; em[2440] = 56; 
    	em[2441] = 116; em[2442] = 72; 
    	em[2443] = 2459; em[2444] = 80; 
    	em[2445] = 1648; em[2446] = 88; 
    em[2447] = 8884097; em[2448] = 8; em[2449] = 0; /* 2447: pointer.func */
    em[2450] = 8884097; em[2451] = 8; em[2452] = 0; /* 2450: pointer.func */
    em[2453] = 8884097; em[2454] = 8; em[2455] = 0; /* 2453: pointer.func */
    em[2456] = 8884097; em[2457] = 8; em[2458] = 0; /* 2456: pointer.func */
    em[2459] = 8884097; em[2460] = 8; em[2461] = 0; /* 2459: pointer.func */
    em[2462] = 1; em[2463] = 8; em[2464] = 1; /* 2462: pointer.struct.dh_method */
    	em[2465] = 2467; em[2466] = 0; 
    em[2467] = 0; em[2468] = 72; em[2469] = 8; /* 2467: struct.dh_method */
    	em[2470] = 50; em[2471] = 0; 
    	em[2472] = 1719; em[2473] = 8; 
    	em[2474] = 2486; em[2475] = 16; 
    	em[2476] = 2489; em[2477] = 24; 
    	em[2478] = 1719; em[2479] = 32; 
    	em[2480] = 1719; em[2481] = 40; 
    	em[2482] = 116; em[2483] = 56; 
    	em[2484] = 2492; em[2485] = 64; 
    em[2486] = 8884097; em[2487] = 8; em[2488] = 0; /* 2486: pointer.func */
    em[2489] = 8884097; em[2490] = 8; em[2491] = 0; /* 2489: pointer.func */
    em[2492] = 8884097; em[2493] = 8; em[2494] = 0; /* 2492: pointer.func */
    em[2495] = 1; em[2496] = 8; em[2497] = 1; /* 2495: pointer.struct.ecdh_method */
    	em[2498] = 1707; em[2499] = 0; 
    em[2500] = 1; em[2501] = 8; em[2502] = 1; /* 2500: pointer.struct.ecdsa_method */
    	em[2503] = 2505; em[2504] = 0; 
    em[2505] = 0; em[2506] = 48; em[2507] = 5; /* 2505: struct.ecdsa_method */
    	em[2508] = 50; em[2509] = 0; 
    	em[2510] = 2518; em[2511] = 8; 
    	em[2512] = 2521; em[2513] = 16; 
    	em[2514] = 2524; em[2515] = 24; 
    	em[2516] = 116; em[2517] = 40; 
    em[2518] = 8884097; em[2519] = 8; em[2520] = 0; /* 2518: pointer.func */
    em[2521] = 8884097; em[2522] = 8; em[2523] = 0; /* 2521: pointer.func */
    em[2524] = 8884097; em[2525] = 8; em[2526] = 0; /* 2524: pointer.func */
    em[2527] = 1; em[2528] = 8; em[2529] = 1; /* 2527: pointer.struct.rand_meth_st */
    	em[2530] = 1657; em[2531] = 0; 
    em[2532] = 1; em[2533] = 8; em[2534] = 1; /* 2532: pointer.struct.store_method_st */
    	em[2535] = 2537; em[2536] = 0; 
    em[2537] = 0; em[2538] = 0; em[2539] = 0; /* 2537: struct.store_method_st */
    em[2540] = 8884097; em[2541] = 8; em[2542] = 0; /* 2540: pointer.func */
    em[2543] = 8884097; em[2544] = 8; em[2545] = 0; /* 2543: pointer.func */
    em[2546] = 8884097; em[2547] = 8; em[2548] = 0; /* 2546: pointer.func */
    em[2549] = 8884097; em[2550] = 8; em[2551] = 0; /* 2549: pointer.func */
    em[2552] = 8884097; em[2553] = 8; em[2554] = 0; /* 2552: pointer.func */
    em[2555] = 8884097; em[2556] = 8; em[2557] = 0; /* 2555: pointer.func */
    em[2558] = 1; em[2559] = 8; em[2560] = 1; /* 2558: pointer.struct.ENGINE_CMD_DEFN_st */
    	em[2561] = 2563; em[2562] = 0; 
    em[2563] = 0; em[2564] = 32; em[2565] = 2; /* 2563: struct.ENGINE_CMD_DEFN_st */
    	em[2566] = 50; em[2567] = 8; 
    	em[2568] = 50; em[2569] = 16; 
    em[2570] = 0; em[2571] = 32; em[2572] = 2; /* 2570: struct.crypto_ex_data_st_fake */
    	em[2573] = 2577; em[2574] = 8; 
    	em[2575] = 217; em[2576] = 24; 
    em[2577] = 8884099; em[2578] = 8; em[2579] = 2; /* 2577: pointer_to_array_of_pointers_to_stack */
    	em[2580] = 1743; em[2581] = 0; 
    	em[2582] = 214; em[2583] = 20; 
    em[2584] = 1; em[2585] = 8; em[2586] = 1; /* 2584: pointer.struct.engine_st */
    	em[2587] = 2366; em[2588] = 0; 
    em[2589] = 8884101; em[2590] = 8; em[2591] = 6; /* 2589: union.union_of_evp_pkey_st */
    	em[2592] = 1743; em[2593] = 0; 
    	em[2594] = 2604; em[2595] = 6; 
    	em[2596] = 2812; em[2597] = 116; 
    	em[2598] = 2923; em[2599] = 28; 
    	em[2600] = 3005; em[2601] = 408; 
    	em[2602] = 214; em[2603] = 0; 
    em[2604] = 1; em[2605] = 8; em[2606] = 1; /* 2604: pointer.struct.rsa_st */
    	em[2607] = 2609; em[2608] = 0; 
    em[2609] = 0; em[2610] = 168; em[2611] = 17; /* 2609: struct.rsa_st */
    	em[2612] = 2646; em[2613] = 16; 
    	em[2614] = 2701; em[2615] = 24; 
    	em[2616] = 2706; em[2617] = 32; 
    	em[2618] = 2706; em[2619] = 40; 
    	em[2620] = 2706; em[2621] = 48; 
    	em[2622] = 2706; em[2623] = 56; 
    	em[2624] = 2706; em[2625] = 64; 
    	em[2626] = 2706; em[2627] = 72; 
    	em[2628] = 2706; em[2629] = 80; 
    	em[2630] = 2706; em[2631] = 88; 
    	em[2632] = 2723; em[2633] = 96; 
    	em[2634] = 2737; em[2635] = 120; 
    	em[2636] = 2737; em[2637] = 128; 
    	em[2638] = 2737; em[2639] = 136; 
    	em[2640] = 116; em[2641] = 144; 
    	em[2642] = 2751; em[2643] = 152; 
    	em[2644] = 2751; em[2645] = 160; 
    em[2646] = 1; em[2647] = 8; em[2648] = 1; /* 2646: pointer.struct.rsa_meth_st */
    	em[2649] = 2651; em[2650] = 0; 
    em[2651] = 0; em[2652] = 112; em[2653] = 13; /* 2651: struct.rsa_meth_st */
    	em[2654] = 50; em[2655] = 0; 
    	em[2656] = 2680; em[2657] = 8; 
    	em[2658] = 2680; em[2659] = 16; 
    	em[2660] = 2680; em[2661] = 24; 
    	em[2662] = 2680; em[2663] = 32; 
    	em[2664] = 2683; em[2665] = 40; 
    	em[2666] = 2686; em[2667] = 48; 
    	em[2668] = 2689; em[2669] = 56; 
    	em[2670] = 2689; em[2671] = 64; 
    	em[2672] = 116; em[2673] = 80; 
    	em[2674] = 2692; em[2675] = 88; 
    	em[2676] = 2695; em[2677] = 96; 
    	em[2678] = 2698; em[2679] = 104; 
    em[2680] = 8884097; em[2681] = 8; em[2682] = 0; /* 2680: pointer.func */
    em[2683] = 8884097; em[2684] = 8; em[2685] = 0; /* 2683: pointer.func */
    em[2686] = 8884097; em[2687] = 8; em[2688] = 0; /* 2686: pointer.func */
    em[2689] = 8884097; em[2690] = 8; em[2691] = 0; /* 2689: pointer.func */
    em[2692] = 8884097; em[2693] = 8; em[2694] = 0; /* 2692: pointer.func */
    em[2695] = 8884097; em[2696] = 8; em[2697] = 0; /* 2695: pointer.func */
    em[2698] = 8884097; em[2699] = 8; em[2700] = 0; /* 2698: pointer.func */
    em[2701] = 1; em[2702] = 8; em[2703] = 1; /* 2701: pointer.struct.engine_st */
    	em[2704] = 2366; em[2705] = 0; 
    em[2706] = 1; em[2707] = 8; em[2708] = 1; /* 2706: pointer.struct.bignum_st */
    	em[2709] = 2711; em[2710] = 0; 
    em[2711] = 0; em[2712] = 24; em[2713] = 1; /* 2711: struct.bignum_st */
    	em[2714] = 2716; em[2715] = 0; 
    em[2716] = 8884099; em[2717] = 8; em[2718] = 2; /* 2716: pointer_to_array_of_pointers_to_stack */
    	em[2719] = 1704; em[2720] = 0; 
    	em[2721] = 214; em[2722] = 12; 
    em[2723] = 0; em[2724] = 32; em[2725] = 2; /* 2723: struct.crypto_ex_data_st_fake */
    	em[2726] = 2730; em[2727] = 8; 
    	em[2728] = 217; em[2729] = 24; 
    em[2730] = 8884099; em[2731] = 8; em[2732] = 2; /* 2730: pointer_to_array_of_pointers_to_stack */
    	em[2733] = 1743; em[2734] = 0; 
    	em[2735] = 214; em[2736] = 20; 
    em[2737] = 1; em[2738] = 8; em[2739] = 1; /* 2737: pointer.struct.bn_mont_ctx_st */
    	em[2740] = 2742; em[2741] = 0; 
    em[2742] = 0; em[2743] = 96; em[2744] = 3; /* 2742: struct.bn_mont_ctx_st */
    	em[2745] = 2711; em[2746] = 8; 
    	em[2747] = 2711; em[2748] = 32; 
    	em[2749] = 2711; em[2750] = 56; 
    em[2751] = 1; em[2752] = 8; em[2753] = 1; /* 2751: pointer.struct.bn_blinding_st */
    	em[2754] = 2756; em[2755] = 0; 
    em[2756] = 0; em[2757] = 88; em[2758] = 7; /* 2756: struct.bn_blinding_st */
    	em[2759] = 2773; em[2760] = 0; 
    	em[2761] = 2773; em[2762] = 8; 
    	em[2763] = 2773; em[2764] = 16; 
    	em[2765] = 2773; em[2766] = 24; 
    	em[2767] = 2790; em[2768] = 40; 
    	em[2769] = 2795; em[2770] = 72; 
    	em[2771] = 2809; em[2772] = 80; 
    em[2773] = 1; em[2774] = 8; em[2775] = 1; /* 2773: pointer.struct.bignum_st */
    	em[2776] = 2778; em[2777] = 0; 
    em[2778] = 0; em[2779] = 24; em[2780] = 1; /* 2778: struct.bignum_st */
    	em[2781] = 2783; em[2782] = 0; 
    em[2783] = 8884099; em[2784] = 8; em[2785] = 2; /* 2783: pointer_to_array_of_pointers_to_stack */
    	em[2786] = 1704; em[2787] = 0; 
    	em[2788] = 214; em[2789] = 12; 
    em[2790] = 0; em[2791] = 16; em[2792] = 1; /* 2790: struct.crypto_threadid_st */
    	em[2793] = 1743; em[2794] = 0; 
    em[2795] = 1; em[2796] = 8; em[2797] = 1; /* 2795: pointer.struct.bn_mont_ctx_st */
    	em[2798] = 2800; em[2799] = 0; 
    em[2800] = 0; em[2801] = 96; em[2802] = 3; /* 2800: struct.bn_mont_ctx_st */
    	em[2803] = 2778; em[2804] = 8; 
    	em[2805] = 2778; em[2806] = 32; 
    	em[2807] = 2778; em[2808] = 56; 
    em[2809] = 8884097; em[2810] = 8; em[2811] = 0; /* 2809: pointer.func */
    em[2812] = 1; em[2813] = 8; em[2814] = 1; /* 2812: pointer.struct.dsa_st */
    	em[2815] = 2817; em[2816] = 0; 
    em[2817] = 0; em[2818] = 136; em[2819] = 11; /* 2817: struct.dsa_st */
    	em[2820] = 1687; em[2821] = 24; 
    	em[2822] = 1687; em[2823] = 32; 
    	em[2824] = 1687; em[2825] = 40; 
    	em[2826] = 1687; em[2827] = 48; 
    	em[2828] = 1687; em[2829] = 56; 
    	em[2830] = 1687; em[2831] = 64; 
    	em[2832] = 1687; em[2833] = 72; 
    	em[2834] = 2842; em[2835] = 88; 
    	em[2836] = 2856; em[2837] = 104; 
    	em[2838] = 2870; em[2839] = 120; 
    	em[2840] = 2918; em[2841] = 128; 
    em[2842] = 1; em[2843] = 8; em[2844] = 1; /* 2842: pointer.struct.bn_mont_ctx_st */
    	em[2845] = 2847; em[2846] = 0; 
    em[2847] = 0; em[2848] = 96; em[2849] = 3; /* 2847: struct.bn_mont_ctx_st */
    	em[2850] = 1692; em[2851] = 8; 
    	em[2852] = 1692; em[2853] = 32; 
    	em[2854] = 1692; em[2855] = 56; 
    em[2856] = 0; em[2857] = 32; em[2858] = 2; /* 2856: struct.crypto_ex_data_st_fake */
    	em[2859] = 2863; em[2860] = 8; 
    	em[2861] = 217; em[2862] = 24; 
    em[2863] = 8884099; em[2864] = 8; em[2865] = 2; /* 2863: pointer_to_array_of_pointers_to_stack */
    	em[2866] = 1743; em[2867] = 0; 
    	em[2868] = 214; em[2869] = 20; 
    em[2870] = 1; em[2871] = 8; em[2872] = 1; /* 2870: pointer.struct.dsa_method */
    	em[2873] = 2875; em[2874] = 0; 
    em[2875] = 0; em[2876] = 96; em[2877] = 11; /* 2875: struct.dsa_method */
    	em[2878] = 50; em[2879] = 0; 
    	em[2880] = 2900; em[2881] = 8; 
    	em[2882] = 2903; em[2883] = 16; 
    	em[2884] = 2906; em[2885] = 24; 
    	em[2886] = 2909; em[2887] = 32; 
    	em[2888] = 2912; em[2889] = 40; 
    	em[2890] = 2915; em[2891] = 48; 
    	em[2892] = 2915; em[2893] = 56; 
    	em[2894] = 116; em[2895] = 72; 
    	em[2896] = 1767; em[2897] = 80; 
    	em[2898] = 2915; em[2899] = 88; 
    em[2900] = 8884097; em[2901] = 8; em[2902] = 0; /* 2900: pointer.func */
    em[2903] = 8884097; em[2904] = 8; em[2905] = 0; /* 2903: pointer.func */
    em[2906] = 8884097; em[2907] = 8; em[2908] = 0; /* 2906: pointer.func */
    em[2909] = 8884097; em[2910] = 8; em[2911] = 0; /* 2909: pointer.func */
    em[2912] = 8884097; em[2913] = 8; em[2914] = 0; /* 2912: pointer.func */
    em[2915] = 8884097; em[2916] = 8; em[2917] = 0; /* 2915: pointer.func */
    em[2918] = 1; em[2919] = 8; em[2920] = 1; /* 2918: pointer.struct.engine_st */
    	em[2921] = 2366; em[2922] = 0; 
    em[2923] = 1; em[2924] = 8; em[2925] = 1; /* 2923: pointer.struct.dh_st */
    	em[2926] = 2928; em[2927] = 0; 
    em[2928] = 0; em[2929] = 144; em[2930] = 12; /* 2928: struct.dh_st */
    	em[2931] = 2706; em[2932] = 8; 
    	em[2933] = 2706; em[2934] = 16; 
    	em[2935] = 2706; em[2936] = 32; 
    	em[2937] = 2706; em[2938] = 40; 
    	em[2939] = 2737; em[2940] = 56; 
    	em[2941] = 2706; em[2942] = 64; 
    	em[2943] = 2706; em[2944] = 72; 
    	em[2945] = 131; em[2946] = 80; 
    	em[2947] = 2706; em[2948] = 96; 
    	em[2949] = 2955; em[2950] = 112; 
    	em[2951] = 2969; em[2952] = 128; 
    	em[2953] = 2701; em[2954] = 136; 
    em[2955] = 0; em[2956] = 32; em[2957] = 2; /* 2955: struct.crypto_ex_data_st_fake */
    	em[2958] = 2962; em[2959] = 8; 
    	em[2960] = 217; em[2961] = 24; 
    em[2962] = 8884099; em[2963] = 8; em[2964] = 2; /* 2962: pointer_to_array_of_pointers_to_stack */
    	em[2965] = 1743; em[2966] = 0; 
    	em[2967] = 214; em[2968] = 20; 
    em[2969] = 1; em[2970] = 8; em[2971] = 1; /* 2969: pointer.struct.dh_method */
    	em[2972] = 2974; em[2973] = 0; 
    em[2974] = 0; em[2975] = 72; em[2976] = 8; /* 2974: struct.dh_method */
    	em[2977] = 50; em[2978] = 0; 
    	em[2979] = 2993; em[2980] = 8; 
    	em[2981] = 2996; em[2982] = 16; 
    	em[2983] = 2999; em[2984] = 24; 
    	em[2985] = 2993; em[2986] = 32; 
    	em[2987] = 2993; em[2988] = 40; 
    	em[2989] = 116; em[2990] = 56; 
    	em[2991] = 3002; em[2992] = 64; 
    em[2993] = 8884097; em[2994] = 8; em[2995] = 0; /* 2993: pointer.func */
    em[2996] = 8884097; em[2997] = 8; em[2998] = 0; /* 2996: pointer.func */
    em[2999] = 8884097; em[3000] = 8; em[3001] = 0; /* 2999: pointer.func */
    em[3002] = 8884097; em[3003] = 8; em[3004] = 0; /* 3002: pointer.func */
    em[3005] = 1; em[3006] = 8; em[3007] = 1; /* 3005: pointer.struct.ec_key_st */
    	em[3008] = 3010; em[3009] = 0; 
    em[3010] = 0; em[3011] = 56; em[3012] = 4; /* 3010: struct.ec_key_st */
    	em[3013] = 1915; em[3014] = 8; 
    	em[3015] = 3021; em[3016] = 16; 
    	em[3017] = 3026; em[3018] = 24; 
    	em[3019] = 3043; em[3020] = 48; 
    em[3021] = 1; em[3022] = 8; em[3023] = 1; /* 3021: pointer.struct.ec_point_st */
    	em[3024] = 2121; em[3025] = 0; 
    em[3026] = 1; em[3027] = 8; em[3028] = 1; /* 3026: pointer.struct.bignum_st */
    	em[3029] = 3031; em[3030] = 0; 
    em[3031] = 0; em[3032] = 24; em[3033] = 1; /* 3031: struct.bignum_st */
    	em[3034] = 3036; em[3035] = 0; 
    em[3036] = 8884099; em[3037] = 8; em[3038] = 2; /* 3036: pointer_to_array_of_pointers_to_stack */
    	em[3039] = 1704; em[3040] = 0; 
    	em[3041] = 214; em[3042] = 12; 
    em[3043] = 1; em[3044] = 8; em[3045] = 1; /* 3043: pointer.struct.ec_extra_data_st */
    	em[3046] = 1725; em[3047] = 0; 
    em[3048] = 1; em[3049] = 8; em[3050] = 1; /* 3048: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[3051] = 3053; em[3052] = 0; 
    em[3053] = 0; em[3054] = 32; em[3055] = 2; /* 3053: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[3056] = 3060; em[3057] = 8; 
    	em[3058] = 217; em[3059] = 24; 
    em[3060] = 8884099; em[3061] = 8; em[3062] = 2; /* 3060: pointer_to_array_of_pointers_to_stack */
    	em[3063] = 3067; em[3064] = 0; 
    	em[3065] = 214; em[3066] = 20; 
    em[3067] = 0; em[3068] = 8; em[3069] = 1; /* 3067: pointer.X509_ATTRIBUTE */
    	em[3070] = 3072; em[3071] = 0; 
    em[3072] = 0; em[3073] = 0; em[3074] = 1; /* 3072: X509_ATTRIBUTE */
    	em[3075] = 3077; em[3076] = 0; 
    em[3077] = 0; em[3078] = 24; em[3079] = 2; /* 3077: struct.x509_attributes_st */
    	em[3080] = 1536; em[3081] = 0; 
    	em[3082] = 3084; em[3083] = 16; 
    em[3084] = 0; em[3085] = 8; em[3086] = 3; /* 3084: union.unknown */
    	em[3087] = 116; em[3088] = 0; 
    	em[3089] = 3093; em[3090] = 0; 
    	em[3091] = 1602; em[3092] = 0; 
    em[3093] = 1; em[3094] = 8; em[3095] = 1; /* 3093: pointer.struct.stack_st_ASN1_TYPE */
    	em[3096] = 3098; em[3097] = 0; 
    em[3098] = 0; em[3099] = 32; em[3100] = 2; /* 3098: struct.stack_st_fake_ASN1_TYPE */
    	em[3101] = 3105; em[3102] = 8; 
    	em[3103] = 217; em[3104] = 24; 
    em[3105] = 8884099; em[3106] = 8; em[3107] = 2; /* 3105: pointer_to_array_of_pointers_to_stack */
    	em[3108] = 3112; em[3109] = 0; 
    	em[3110] = 214; em[3111] = 20; 
    em[3112] = 0; em[3113] = 8; em[3114] = 1; /* 3112: pointer.ASN1_TYPE */
    	em[3115] = 3117; em[3116] = 0; 
    em[3117] = 0; em[3118] = 0; em[3119] = 1; /* 3117: ASN1_TYPE */
    	em[3120] = 3122; em[3121] = 0; 
    em[3122] = 0; em[3123] = 16; em[3124] = 1; /* 3122: struct.asn1_type_st */
    	em[3125] = 3127; em[3126] = 8; 
    em[3127] = 0; em[3128] = 8; em[3129] = 20; /* 3127: union.unknown */
    	em[3130] = 116; em[3131] = 0; 
    	em[3132] = 3170; em[3133] = 0; 
    	em[3134] = 3175; em[3135] = 0; 
    	em[3136] = 3180; em[3137] = 0; 
    	em[3138] = 3185; em[3139] = 0; 
    	em[3140] = 3190; em[3141] = 0; 
    	em[3142] = 3195; em[3143] = 0; 
    	em[3144] = 3200; em[3145] = 0; 
    	em[3146] = 3205; em[3147] = 0; 
    	em[3148] = 3210; em[3149] = 0; 
    	em[3150] = 1637; em[3151] = 0; 
    	em[3152] = 1632; em[3153] = 0; 
    	em[3154] = 1627; em[3155] = 0; 
    	em[3156] = 1622; em[3157] = 0; 
    	em[3158] = 1617; em[3159] = 0; 
    	em[3160] = 1607; em[3161] = 0; 
    	em[3162] = 3215; em[3163] = 0; 
    	em[3164] = 3170; em[3165] = 0; 
    	em[3166] = 3170; em[3167] = 0; 
    	em[3168] = 541; em[3169] = 0; 
    em[3170] = 1; em[3171] = 8; em[3172] = 1; /* 3170: pointer.struct.asn1_string_st */
    	em[3173] = 1612; em[3174] = 0; 
    em[3175] = 1; em[3176] = 8; em[3177] = 1; /* 3175: pointer.struct.asn1_object_st */
    	em[3178] = 2170; em[3179] = 0; 
    em[3180] = 1; em[3181] = 8; em[3182] = 1; /* 3180: pointer.struct.asn1_string_st */
    	em[3183] = 1612; em[3184] = 0; 
    em[3185] = 1; em[3186] = 8; em[3187] = 1; /* 3185: pointer.struct.asn1_string_st */
    	em[3188] = 1612; em[3189] = 0; 
    em[3190] = 1; em[3191] = 8; em[3192] = 1; /* 3190: pointer.struct.asn1_string_st */
    	em[3193] = 1612; em[3194] = 0; 
    em[3195] = 1; em[3196] = 8; em[3197] = 1; /* 3195: pointer.struct.asn1_string_st */
    	em[3198] = 1612; em[3199] = 0; 
    em[3200] = 1; em[3201] = 8; em[3202] = 1; /* 3200: pointer.struct.asn1_string_st */
    	em[3203] = 1612; em[3204] = 0; 
    em[3205] = 1; em[3206] = 8; em[3207] = 1; /* 3205: pointer.struct.asn1_string_st */
    	em[3208] = 1612; em[3209] = 0; 
    em[3210] = 1; em[3211] = 8; em[3212] = 1; /* 3210: pointer.struct.asn1_string_st */
    	em[3213] = 1612; em[3214] = 0; 
    em[3215] = 1; em[3216] = 8; em[3217] = 1; /* 3215: pointer.struct.asn1_string_st */
    	em[3218] = 1612; em[3219] = 0; 
    em[3220] = 1; em[3221] = 8; em[3222] = 1; /* 3220: pointer.struct.stack_st_X509_EXTENSION */
    	em[3223] = 3225; em[3224] = 0; 
    em[3225] = 0; em[3226] = 32; em[3227] = 2; /* 3225: struct.stack_st_fake_X509_EXTENSION */
    	em[3228] = 3232; em[3229] = 8; 
    	em[3230] = 217; em[3231] = 24; 
    em[3232] = 8884099; em[3233] = 8; em[3234] = 2; /* 3232: pointer_to_array_of_pointers_to_stack */
    	em[3235] = 3239; em[3236] = 0; 
    	em[3237] = 214; em[3238] = 20; 
    em[3239] = 0; em[3240] = 8; em[3241] = 1; /* 3239: pointer.X509_EXTENSION */
    	em[3242] = 1580; em[3243] = 0; 
    em[3244] = 0; em[3245] = 32; em[3246] = 2; /* 3244: struct.crypto_ex_data_st_fake */
    	em[3247] = 3251; em[3248] = 8; 
    	em[3249] = 217; em[3250] = 24; 
    em[3251] = 8884099; em[3252] = 8; em[3253] = 2; /* 3251: pointer_to_array_of_pointers_to_stack */
    	em[3254] = 1743; em[3255] = 0; 
    	em[3256] = 214; em[3257] = 20; 
    em[3258] = 1; em[3259] = 8; em[3260] = 1; /* 3258: pointer.struct.X509_POLICY_CACHE_st */
    	em[3261] = 1760; em[3262] = 0; 
    em[3263] = 1; em[3264] = 8; em[3265] = 1; /* 3263: pointer.struct.stack_st_DIST_POINT */
    	em[3266] = 3268; em[3267] = 0; 
    em[3268] = 0; em[3269] = 32; em[3270] = 2; /* 3268: struct.stack_st_fake_DIST_POINT */
    	em[3271] = 3275; em[3272] = 8; 
    	em[3273] = 217; em[3274] = 24; 
    em[3275] = 8884099; em[3276] = 8; em[3277] = 2; /* 3275: pointer_to_array_of_pointers_to_stack */
    	em[3278] = 3282; em[3279] = 0; 
    	em[3280] = 214; em[3281] = 20; 
    em[3282] = 0; em[3283] = 8; em[3284] = 1; /* 3282: pointer.DIST_POINT */
    	em[3285] = 1013; em[3286] = 0; 
    em[3287] = 1; em[3288] = 8; em[3289] = 1; /* 3287: pointer.struct.stack_st_GENERAL_NAME */
    	em[3290] = 3292; em[3291] = 0; 
    em[3292] = 0; em[3293] = 32; em[3294] = 2; /* 3292: struct.stack_st_fake_GENERAL_NAME */
    	em[3295] = 3299; em[3296] = 8; 
    	em[3297] = 217; em[3298] = 24; 
    em[3299] = 8884099; em[3300] = 8; em[3301] = 2; /* 3299: pointer_to_array_of_pointers_to_stack */
    	em[3302] = 3306; em[3303] = 0; 
    	em[3304] = 214; em[3305] = 20; 
    em[3306] = 0; em[3307] = 8; em[3308] = 1; /* 3306: pointer.GENERAL_NAME */
    	em[3309] = 738; em[3310] = 0; 
    em[3311] = 1; em[3312] = 8; em[3313] = 1; /* 3311: pointer.struct.NAME_CONSTRAINTS_st */
    	em[3314] = 611; em[3315] = 0; 
    em[3316] = 0; em[3317] = 1; em[3318] = 0; /* 3316: char */
    args_addr->arg_entity_index[0] = 2179;
    args_addr->ret_entity_index = 2251;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    X509 * new_arg_a = *((X509 * *)new_args->args[0]);

    X509_NAME * *new_ret_ptr = (X509_NAME * *)new_args->ret;

    X509_NAME * (*orig_X509_get_subject_name)(X509 *);
    orig_X509_get_subject_name = dlsym(RTLD_NEXT, "X509_get_subject_name");
    *new_ret_ptr = (*orig_X509_get_subject_name)(new_arg_a);

    syscall(889);

    free(args_addr);

    return ret;
}

