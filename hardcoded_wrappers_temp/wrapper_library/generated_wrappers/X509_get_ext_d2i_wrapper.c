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

void * bb_X509_get_ext_d2i(X509 * arg_a,int arg_b,int * arg_c,int * arg_d);

void * X509_get_ext_d2i(X509 * arg_a,int arg_b,int * arg_c,int * arg_d) 
{
    unsigned long in_lib = syscall(890);
    printf("X509_get_ext_d2i called %lu\n", in_lib);
    if (!in_lib)
        return bb_X509_get_ext_d2i(arg_a,arg_b,arg_c,arg_d);
    else {
        void * (*orig_X509_get_ext_d2i)(X509 *,int,int *,int *);
        orig_X509_get_ext_d2i = dlsym(RTLD_NEXT, "X509_get_ext_d2i");
        return orig_X509_get_ext_d2i(arg_a,arg_b,arg_c,arg_d);
    }
}

void * bb_X509_get_ext_d2i(X509 * arg_a,int arg_b,int * arg_c,int * arg_d) 
{
    void * ret;

    struct lib_enter_args *args_addr = malloc(sizeof(struct lib_enter_args));
    memset(args_addr, 0, sizeof(struct lib_enter_args));
    args_addr->num_args = 0;
    uint32_t *em = args_addr->entity_metadata;
    em[0] = 0; em[1] = 0; em[2] = 1; /* 0: X509_ALGOR */
    	em[3] = 5; em[4] = 0; 
    em[5] = 0; em[6] = 16; em[7] = 2; /* 5: struct.X509_algor_st */
    	em[8] = 12; em[9] = 0; 
    	em[10] = 39; em[11] = 8; 
    em[12] = 1; em[13] = 8; em[14] = 1; /* 12: pointer.struct.asn1_object_st */
    	em[15] = 17; em[16] = 0; 
    em[17] = 0; em[18] = 40; em[19] = 3; /* 17: struct.asn1_object_st */
    	em[20] = 26; em[21] = 0; 
    	em[22] = 26; em[23] = 8; 
    	em[24] = 31; em[25] = 24; 
    em[26] = 1; em[27] = 8; em[28] = 1; /* 26: pointer.char */
    	em[29] = 8884096; em[30] = 0; 
    em[31] = 1; em[32] = 8; em[33] = 1; /* 31: pointer.unsigned char */
    	em[34] = 36; em[35] = 0; 
    em[36] = 0; em[37] = 1; em[38] = 0; /* 36: unsigned char */
    em[39] = 1; em[40] = 8; em[41] = 1; /* 39: pointer.struct.asn1_type_st */
    	em[42] = 44; em[43] = 0; 
    em[44] = 0; em[45] = 16; em[46] = 1; /* 44: struct.asn1_type_st */
    	em[47] = 49; em[48] = 8; 
    em[49] = 0; em[50] = 8; em[51] = 20; /* 49: union.unknown */
    	em[52] = 92; em[53] = 0; 
    	em[54] = 97; em[55] = 0; 
    	em[56] = 12; em[57] = 0; 
    	em[58] = 112; em[59] = 0; 
    	em[60] = 117; em[61] = 0; 
    	em[62] = 122; em[63] = 0; 
    	em[64] = 127; em[65] = 0; 
    	em[66] = 132; em[67] = 0; 
    	em[68] = 137; em[69] = 0; 
    	em[70] = 142; em[71] = 0; 
    	em[72] = 147; em[73] = 0; 
    	em[74] = 152; em[75] = 0; 
    	em[76] = 157; em[77] = 0; 
    	em[78] = 162; em[79] = 0; 
    	em[80] = 167; em[81] = 0; 
    	em[82] = 172; em[83] = 0; 
    	em[84] = 177; em[85] = 0; 
    	em[86] = 97; em[87] = 0; 
    	em[88] = 97; em[89] = 0; 
    	em[90] = 182; em[91] = 0; 
    em[92] = 1; em[93] = 8; em[94] = 1; /* 92: pointer.char */
    	em[95] = 8884096; em[96] = 0; 
    em[97] = 1; em[98] = 8; em[99] = 1; /* 97: pointer.struct.asn1_string_st */
    	em[100] = 102; em[101] = 0; 
    em[102] = 0; em[103] = 24; em[104] = 1; /* 102: struct.asn1_string_st */
    	em[105] = 107; em[106] = 8; 
    em[107] = 1; em[108] = 8; em[109] = 1; /* 107: pointer.unsigned char */
    	em[110] = 36; em[111] = 0; 
    em[112] = 1; em[113] = 8; em[114] = 1; /* 112: pointer.struct.asn1_string_st */
    	em[115] = 102; em[116] = 0; 
    em[117] = 1; em[118] = 8; em[119] = 1; /* 117: pointer.struct.asn1_string_st */
    	em[120] = 102; em[121] = 0; 
    em[122] = 1; em[123] = 8; em[124] = 1; /* 122: pointer.struct.asn1_string_st */
    	em[125] = 102; em[126] = 0; 
    em[127] = 1; em[128] = 8; em[129] = 1; /* 127: pointer.struct.asn1_string_st */
    	em[130] = 102; em[131] = 0; 
    em[132] = 1; em[133] = 8; em[134] = 1; /* 132: pointer.struct.asn1_string_st */
    	em[135] = 102; em[136] = 0; 
    em[137] = 1; em[138] = 8; em[139] = 1; /* 137: pointer.struct.asn1_string_st */
    	em[140] = 102; em[141] = 0; 
    em[142] = 1; em[143] = 8; em[144] = 1; /* 142: pointer.struct.asn1_string_st */
    	em[145] = 102; em[146] = 0; 
    em[147] = 1; em[148] = 8; em[149] = 1; /* 147: pointer.struct.asn1_string_st */
    	em[150] = 102; em[151] = 0; 
    em[152] = 1; em[153] = 8; em[154] = 1; /* 152: pointer.struct.asn1_string_st */
    	em[155] = 102; em[156] = 0; 
    em[157] = 1; em[158] = 8; em[159] = 1; /* 157: pointer.struct.asn1_string_st */
    	em[160] = 102; em[161] = 0; 
    em[162] = 1; em[163] = 8; em[164] = 1; /* 162: pointer.struct.asn1_string_st */
    	em[165] = 102; em[166] = 0; 
    em[167] = 1; em[168] = 8; em[169] = 1; /* 167: pointer.struct.asn1_string_st */
    	em[170] = 102; em[171] = 0; 
    em[172] = 1; em[173] = 8; em[174] = 1; /* 172: pointer.struct.asn1_string_st */
    	em[175] = 102; em[176] = 0; 
    em[177] = 1; em[178] = 8; em[179] = 1; /* 177: pointer.struct.asn1_string_st */
    	em[180] = 102; em[181] = 0; 
    em[182] = 1; em[183] = 8; em[184] = 1; /* 182: pointer.struct.ASN1_VALUE_st */
    	em[185] = 187; em[186] = 0; 
    em[187] = 0; em[188] = 0; em[189] = 0; /* 187: struct.ASN1_VALUE_st */
    em[190] = 1; em[191] = 8; em[192] = 1; /* 190: pointer.struct.stack_st_X509_ALGOR */
    	em[193] = 195; em[194] = 0; 
    em[195] = 0; em[196] = 32; em[197] = 2; /* 195: struct.stack_st_fake_X509_ALGOR */
    	em[198] = 202; em[199] = 8; 
    	em[200] = 217; em[201] = 24; 
    em[202] = 8884099; em[203] = 8; em[204] = 2; /* 202: pointer_to_array_of_pointers_to_stack */
    	em[205] = 209; em[206] = 0; 
    	em[207] = 214; em[208] = 20; 
    em[209] = 0; em[210] = 8; em[211] = 1; /* 209: pointer.X509_ALGOR */
    	em[212] = 0; em[213] = 0; 
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
    	em[252] = 26; em[253] = 0; 
    	em[254] = 26; em[255] = 8; 
    	em[256] = 31; em[257] = 24; 
    em[258] = 1; em[259] = 8; em[260] = 1; /* 258: pointer.struct.x509_cert_aux_st */
    	em[261] = 263; em[262] = 0; 
    em[263] = 0; em[264] = 40; em[265] = 5; /* 263: struct.x509_cert_aux_st */
    	em[266] = 220; em[267] = 0; 
    	em[268] = 220; em[269] = 8; 
    	em[270] = 276; em[271] = 16; 
    	em[272] = 286; em[273] = 24; 
    	em[274] = 190; em[275] = 32; 
    em[276] = 1; em[277] = 8; em[278] = 1; /* 276: pointer.struct.asn1_string_st */
    	em[279] = 281; em[280] = 0; 
    em[281] = 0; em[282] = 24; em[283] = 1; /* 281: struct.asn1_string_st */
    	em[284] = 107; em[285] = 8; 
    em[286] = 1; em[287] = 8; em[288] = 1; /* 286: pointer.struct.asn1_string_st */
    	em[289] = 281; em[290] = 0; 
    em[291] = 0; em[292] = 16; em[293] = 2; /* 291: struct.EDIPartyName_st */
    	em[294] = 298; em[295] = 0; 
    	em[296] = 298; em[297] = 8; 
    em[298] = 1; em[299] = 8; em[300] = 1; /* 298: pointer.struct.asn1_string_st */
    	em[301] = 303; em[302] = 0; 
    em[303] = 0; em[304] = 24; em[305] = 1; /* 303: struct.asn1_string_st */
    	em[306] = 107; em[307] = 8; 
    em[308] = 1; em[309] = 8; em[310] = 1; /* 308: pointer.struct.EDIPartyName_st */
    	em[311] = 291; em[312] = 0; 
    em[313] = 1; em[314] = 8; em[315] = 1; /* 313: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[316] = 318; em[317] = 0; 
    em[318] = 0; em[319] = 32; em[320] = 2; /* 318: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[321] = 325; em[322] = 8; 
    	em[323] = 217; em[324] = 24; 
    em[325] = 8884099; em[326] = 8; em[327] = 2; /* 325: pointer_to_array_of_pointers_to_stack */
    	em[328] = 332; em[329] = 0; 
    	em[330] = 214; em[331] = 20; 
    em[332] = 0; em[333] = 8; em[334] = 1; /* 332: pointer.X509_NAME_ENTRY */
    	em[335] = 337; em[336] = 0; 
    em[337] = 0; em[338] = 0; em[339] = 1; /* 337: X509_NAME_ENTRY */
    	em[340] = 342; em[341] = 0; 
    em[342] = 0; em[343] = 24; em[344] = 2; /* 342: struct.X509_name_entry_st */
    	em[345] = 349; em[346] = 0; 
    	em[347] = 363; em[348] = 8; 
    em[349] = 1; em[350] = 8; em[351] = 1; /* 349: pointer.struct.asn1_object_st */
    	em[352] = 354; em[353] = 0; 
    em[354] = 0; em[355] = 40; em[356] = 3; /* 354: struct.asn1_object_st */
    	em[357] = 26; em[358] = 0; 
    	em[359] = 26; em[360] = 8; 
    	em[361] = 31; em[362] = 24; 
    em[363] = 1; em[364] = 8; em[365] = 1; /* 363: pointer.struct.asn1_string_st */
    	em[366] = 368; em[367] = 0; 
    em[368] = 0; em[369] = 24; em[370] = 1; /* 368: struct.asn1_string_st */
    	em[371] = 107; em[372] = 8; 
    em[373] = 0; em[374] = 40; em[375] = 3; /* 373: struct.X509_name_st */
    	em[376] = 313; em[377] = 0; 
    	em[378] = 382; em[379] = 16; 
    	em[380] = 107; em[381] = 24; 
    em[382] = 1; em[383] = 8; em[384] = 1; /* 382: pointer.struct.buf_mem_st */
    	em[385] = 387; em[386] = 0; 
    em[387] = 0; em[388] = 24; em[389] = 1; /* 387: struct.buf_mem_st */
    	em[390] = 92; em[391] = 8; 
    em[392] = 1; em[393] = 8; em[394] = 1; /* 392: pointer.struct.asn1_string_st */
    	em[395] = 303; em[396] = 0; 
    em[397] = 1; em[398] = 8; em[399] = 1; /* 397: pointer.struct.asn1_string_st */
    	em[400] = 303; em[401] = 0; 
    em[402] = 1; em[403] = 8; em[404] = 1; /* 402: pointer.struct.asn1_string_st */
    	em[405] = 303; em[406] = 0; 
    em[407] = 1; em[408] = 8; em[409] = 1; /* 407: pointer.struct.asn1_string_st */
    	em[410] = 303; em[411] = 0; 
    em[412] = 1; em[413] = 8; em[414] = 1; /* 412: pointer.struct.asn1_string_st */
    	em[415] = 303; em[416] = 0; 
    em[417] = 0; em[418] = 8; em[419] = 20; /* 417: union.unknown */
    	em[420] = 92; em[421] = 0; 
    	em[422] = 298; em[423] = 0; 
    	em[424] = 460; em[425] = 0; 
    	em[426] = 474; em[427] = 0; 
    	em[428] = 479; em[429] = 0; 
    	em[430] = 484; em[431] = 0; 
    	em[432] = 412; em[433] = 0; 
    	em[434] = 489; em[435] = 0; 
    	em[436] = 407; em[437] = 0; 
    	em[438] = 494; em[439] = 0; 
    	em[440] = 402; em[441] = 0; 
    	em[442] = 397; em[443] = 0; 
    	em[444] = 499; em[445] = 0; 
    	em[446] = 504; em[447] = 0; 
    	em[448] = 392; em[449] = 0; 
    	em[450] = 509; em[451] = 0; 
    	em[452] = 514; em[453] = 0; 
    	em[454] = 298; em[455] = 0; 
    	em[456] = 298; em[457] = 0; 
    	em[458] = 519; em[459] = 0; 
    em[460] = 1; em[461] = 8; em[462] = 1; /* 460: pointer.struct.asn1_object_st */
    	em[463] = 465; em[464] = 0; 
    em[465] = 0; em[466] = 40; em[467] = 3; /* 465: struct.asn1_object_st */
    	em[468] = 26; em[469] = 0; 
    	em[470] = 26; em[471] = 8; 
    	em[472] = 31; em[473] = 24; 
    em[474] = 1; em[475] = 8; em[476] = 1; /* 474: pointer.struct.asn1_string_st */
    	em[477] = 303; em[478] = 0; 
    em[479] = 1; em[480] = 8; em[481] = 1; /* 479: pointer.struct.asn1_string_st */
    	em[482] = 303; em[483] = 0; 
    em[484] = 1; em[485] = 8; em[486] = 1; /* 484: pointer.struct.asn1_string_st */
    	em[487] = 303; em[488] = 0; 
    em[489] = 1; em[490] = 8; em[491] = 1; /* 489: pointer.struct.asn1_string_st */
    	em[492] = 303; em[493] = 0; 
    em[494] = 1; em[495] = 8; em[496] = 1; /* 494: pointer.struct.asn1_string_st */
    	em[497] = 303; em[498] = 0; 
    em[499] = 1; em[500] = 8; em[501] = 1; /* 499: pointer.struct.asn1_string_st */
    	em[502] = 303; em[503] = 0; 
    em[504] = 1; em[505] = 8; em[506] = 1; /* 504: pointer.struct.asn1_string_st */
    	em[507] = 303; em[508] = 0; 
    em[509] = 1; em[510] = 8; em[511] = 1; /* 509: pointer.struct.asn1_string_st */
    	em[512] = 303; em[513] = 0; 
    em[514] = 1; em[515] = 8; em[516] = 1; /* 514: pointer.struct.asn1_string_st */
    	em[517] = 303; em[518] = 0; 
    em[519] = 1; em[520] = 8; em[521] = 1; /* 519: pointer.struct.ASN1_VALUE_st */
    	em[522] = 524; em[523] = 0; 
    em[524] = 0; em[525] = 0; em[526] = 0; /* 524: struct.ASN1_VALUE_st */
    em[527] = 1; em[528] = 8; em[529] = 1; /* 527: pointer.struct.otherName_st */
    	em[530] = 532; em[531] = 0; 
    em[532] = 0; em[533] = 16; em[534] = 2; /* 532: struct.otherName_st */
    	em[535] = 460; em[536] = 0; 
    	em[537] = 539; em[538] = 8; 
    em[539] = 1; em[540] = 8; em[541] = 1; /* 539: pointer.struct.asn1_type_st */
    	em[542] = 544; em[543] = 0; 
    em[544] = 0; em[545] = 16; em[546] = 1; /* 544: struct.asn1_type_st */
    	em[547] = 417; em[548] = 8; 
    em[549] = 0; em[550] = 16; em[551] = 1; /* 549: struct.GENERAL_NAME_st */
    	em[552] = 554; em[553] = 8; 
    em[554] = 0; em[555] = 8; em[556] = 15; /* 554: union.unknown */
    	em[557] = 92; em[558] = 0; 
    	em[559] = 527; em[560] = 0; 
    	em[561] = 494; em[562] = 0; 
    	em[563] = 494; em[564] = 0; 
    	em[565] = 539; em[566] = 0; 
    	em[567] = 587; em[568] = 0; 
    	em[569] = 308; em[570] = 0; 
    	em[571] = 494; em[572] = 0; 
    	em[573] = 412; em[574] = 0; 
    	em[575] = 460; em[576] = 0; 
    	em[577] = 412; em[578] = 0; 
    	em[579] = 587; em[580] = 0; 
    	em[581] = 494; em[582] = 0; 
    	em[583] = 460; em[584] = 0; 
    	em[585] = 539; em[586] = 0; 
    em[587] = 1; em[588] = 8; em[589] = 1; /* 587: pointer.struct.X509_name_st */
    	em[590] = 373; em[591] = 0; 
    em[592] = 1; em[593] = 8; em[594] = 1; /* 592: pointer.struct.GENERAL_NAME_st */
    	em[595] = 549; em[596] = 0; 
    em[597] = 1; em[598] = 8; em[599] = 1; /* 597: pointer.struct.NAME_CONSTRAINTS_st */
    	em[600] = 602; em[601] = 0; 
    em[602] = 0; em[603] = 16; em[604] = 2; /* 602: struct.NAME_CONSTRAINTS_st */
    	em[605] = 609; em[606] = 0; 
    	em[607] = 609; em[608] = 8; 
    em[609] = 1; em[610] = 8; em[611] = 1; /* 609: pointer.struct.stack_st_GENERAL_SUBTREE */
    	em[612] = 614; em[613] = 0; 
    em[614] = 0; em[615] = 32; em[616] = 2; /* 614: struct.stack_st_fake_GENERAL_SUBTREE */
    	em[617] = 621; em[618] = 8; 
    	em[619] = 217; em[620] = 24; 
    em[621] = 8884099; em[622] = 8; em[623] = 2; /* 621: pointer_to_array_of_pointers_to_stack */
    	em[624] = 628; em[625] = 0; 
    	em[626] = 214; em[627] = 20; 
    em[628] = 0; em[629] = 8; em[630] = 1; /* 628: pointer.GENERAL_SUBTREE */
    	em[631] = 633; em[632] = 0; 
    em[633] = 0; em[634] = 0; em[635] = 1; /* 633: GENERAL_SUBTREE */
    	em[636] = 638; em[637] = 0; 
    em[638] = 0; em[639] = 24; em[640] = 3; /* 638: struct.GENERAL_SUBTREE_st */
    	em[641] = 592; em[642] = 0; 
    	em[643] = 474; em[644] = 8; 
    	em[645] = 474; em[646] = 16; 
    em[647] = 1; em[648] = 8; em[649] = 1; /* 647: pointer.struct.stack_st_GENERAL_NAME */
    	em[650] = 652; em[651] = 0; 
    em[652] = 0; em[653] = 32; em[654] = 2; /* 652: struct.stack_st_fake_GENERAL_NAME */
    	em[655] = 659; em[656] = 8; 
    	em[657] = 217; em[658] = 24; 
    em[659] = 8884099; em[660] = 8; em[661] = 2; /* 659: pointer_to_array_of_pointers_to_stack */
    	em[662] = 666; em[663] = 0; 
    	em[664] = 214; em[665] = 20; 
    em[666] = 0; em[667] = 8; em[668] = 1; /* 666: pointer.GENERAL_NAME */
    	em[669] = 671; em[670] = 0; 
    em[671] = 0; em[672] = 0; em[673] = 1; /* 671: GENERAL_NAME */
    	em[674] = 676; em[675] = 0; 
    em[676] = 0; em[677] = 16; em[678] = 1; /* 676: struct.GENERAL_NAME_st */
    	em[679] = 681; em[680] = 8; 
    em[681] = 0; em[682] = 8; em[683] = 15; /* 681: union.unknown */
    	em[684] = 92; em[685] = 0; 
    	em[686] = 714; em[687] = 0; 
    	em[688] = 833; em[689] = 0; 
    	em[690] = 833; em[691] = 0; 
    	em[692] = 740; em[693] = 0; 
    	em[694] = 873; em[695] = 0; 
    	em[696] = 921; em[697] = 0; 
    	em[698] = 833; em[699] = 0; 
    	em[700] = 818; em[701] = 0; 
    	em[702] = 726; em[703] = 0; 
    	em[704] = 818; em[705] = 0; 
    	em[706] = 873; em[707] = 0; 
    	em[708] = 833; em[709] = 0; 
    	em[710] = 726; em[711] = 0; 
    	em[712] = 740; em[713] = 0; 
    em[714] = 1; em[715] = 8; em[716] = 1; /* 714: pointer.struct.otherName_st */
    	em[717] = 719; em[718] = 0; 
    em[719] = 0; em[720] = 16; em[721] = 2; /* 719: struct.otherName_st */
    	em[722] = 726; em[723] = 0; 
    	em[724] = 740; em[725] = 8; 
    em[726] = 1; em[727] = 8; em[728] = 1; /* 726: pointer.struct.asn1_object_st */
    	em[729] = 731; em[730] = 0; 
    em[731] = 0; em[732] = 40; em[733] = 3; /* 731: struct.asn1_object_st */
    	em[734] = 26; em[735] = 0; 
    	em[736] = 26; em[737] = 8; 
    	em[738] = 31; em[739] = 24; 
    em[740] = 1; em[741] = 8; em[742] = 1; /* 740: pointer.struct.asn1_type_st */
    	em[743] = 745; em[744] = 0; 
    em[745] = 0; em[746] = 16; em[747] = 1; /* 745: struct.asn1_type_st */
    	em[748] = 750; em[749] = 8; 
    em[750] = 0; em[751] = 8; em[752] = 20; /* 750: union.unknown */
    	em[753] = 92; em[754] = 0; 
    	em[755] = 793; em[756] = 0; 
    	em[757] = 726; em[758] = 0; 
    	em[759] = 803; em[760] = 0; 
    	em[761] = 808; em[762] = 0; 
    	em[763] = 813; em[764] = 0; 
    	em[765] = 818; em[766] = 0; 
    	em[767] = 823; em[768] = 0; 
    	em[769] = 828; em[770] = 0; 
    	em[771] = 833; em[772] = 0; 
    	em[773] = 838; em[774] = 0; 
    	em[775] = 843; em[776] = 0; 
    	em[777] = 848; em[778] = 0; 
    	em[779] = 853; em[780] = 0; 
    	em[781] = 858; em[782] = 0; 
    	em[783] = 863; em[784] = 0; 
    	em[785] = 868; em[786] = 0; 
    	em[787] = 793; em[788] = 0; 
    	em[789] = 793; em[790] = 0; 
    	em[791] = 519; em[792] = 0; 
    em[793] = 1; em[794] = 8; em[795] = 1; /* 793: pointer.struct.asn1_string_st */
    	em[796] = 798; em[797] = 0; 
    em[798] = 0; em[799] = 24; em[800] = 1; /* 798: struct.asn1_string_st */
    	em[801] = 107; em[802] = 8; 
    em[803] = 1; em[804] = 8; em[805] = 1; /* 803: pointer.struct.asn1_string_st */
    	em[806] = 798; em[807] = 0; 
    em[808] = 1; em[809] = 8; em[810] = 1; /* 808: pointer.struct.asn1_string_st */
    	em[811] = 798; em[812] = 0; 
    em[813] = 1; em[814] = 8; em[815] = 1; /* 813: pointer.struct.asn1_string_st */
    	em[816] = 798; em[817] = 0; 
    em[818] = 1; em[819] = 8; em[820] = 1; /* 818: pointer.struct.asn1_string_st */
    	em[821] = 798; em[822] = 0; 
    em[823] = 1; em[824] = 8; em[825] = 1; /* 823: pointer.struct.asn1_string_st */
    	em[826] = 798; em[827] = 0; 
    em[828] = 1; em[829] = 8; em[830] = 1; /* 828: pointer.struct.asn1_string_st */
    	em[831] = 798; em[832] = 0; 
    em[833] = 1; em[834] = 8; em[835] = 1; /* 833: pointer.struct.asn1_string_st */
    	em[836] = 798; em[837] = 0; 
    em[838] = 1; em[839] = 8; em[840] = 1; /* 838: pointer.struct.asn1_string_st */
    	em[841] = 798; em[842] = 0; 
    em[843] = 1; em[844] = 8; em[845] = 1; /* 843: pointer.struct.asn1_string_st */
    	em[846] = 798; em[847] = 0; 
    em[848] = 1; em[849] = 8; em[850] = 1; /* 848: pointer.struct.asn1_string_st */
    	em[851] = 798; em[852] = 0; 
    em[853] = 1; em[854] = 8; em[855] = 1; /* 853: pointer.struct.asn1_string_st */
    	em[856] = 798; em[857] = 0; 
    em[858] = 1; em[859] = 8; em[860] = 1; /* 858: pointer.struct.asn1_string_st */
    	em[861] = 798; em[862] = 0; 
    em[863] = 1; em[864] = 8; em[865] = 1; /* 863: pointer.struct.asn1_string_st */
    	em[866] = 798; em[867] = 0; 
    em[868] = 1; em[869] = 8; em[870] = 1; /* 868: pointer.struct.asn1_string_st */
    	em[871] = 798; em[872] = 0; 
    em[873] = 1; em[874] = 8; em[875] = 1; /* 873: pointer.struct.X509_name_st */
    	em[876] = 878; em[877] = 0; 
    em[878] = 0; em[879] = 40; em[880] = 3; /* 878: struct.X509_name_st */
    	em[881] = 887; em[882] = 0; 
    	em[883] = 911; em[884] = 16; 
    	em[885] = 107; em[886] = 24; 
    em[887] = 1; em[888] = 8; em[889] = 1; /* 887: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[890] = 892; em[891] = 0; 
    em[892] = 0; em[893] = 32; em[894] = 2; /* 892: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[895] = 899; em[896] = 8; 
    	em[897] = 217; em[898] = 24; 
    em[899] = 8884099; em[900] = 8; em[901] = 2; /* 899: pointer_to_array_of_pointers_to_stack */
    	em[902] = 906; em[903] = 0; 
    	em[904] = 214; em[905] = 20; 
    em[906] = 0; em[907] = 8; em[908] = 1; /* 906: pointer.X509_NAME_ENTRY */
    	em[909] = 337; em[910] = 0; 
    em[911] = 1; em[912] = 8; em[913] = 1; /* 911: pointer.struct.buf_mem_st */
    	em[914] = 916; em[915] = 0; 
    em[916] = 0; em[917] = 24; em[918] = 1; /* 916: struct.buf_mem_st */
    	em[919] = 92; em[920] = 8; 
    em[921] = 1; em[922] = 8; em[923] = 1; /* 921: pointer.struct.EDIPartyName_st */
    	em[924] = 926; em[925] = 0; 
    em[926] = 0; em[927] = 16; em[928] = 2; /* 926: struct.EDIPartyName_st */
    	em[929] = 793; em[930] = 0; 
    	em[931] = 793; em[932] = 8; 
    em[933] = 0; em[934] = 24; em[935] = 1; /* 933: struct.asn1_string_st */
    	em[936] = 107; em[937] = 8; 
    em[938] = 1; em[939] = 8; em[940] = 1; /* 938: pointer.struct.buf_mem_st */
    	em[941] = 943; em[942] = 0; 
    em[943] = 0; em[944] = 24; em[945] = 1; /* 943: struct.buf_mem_st */
    	em[946] = 92; em[947] = 8; 
    em[948] = 1; em[949] = 8; em[950] = 1; /* 948: pointer.struct.stack_st_GENERAL_NAME */
    	em[951] = 953; em[952] = 0; 
    em[953] = 0; em[954] = 32; em[955] = 2; /* 953: struct.stack_st_fake_GENERAL_NAME */
    	em[956] = 960; em[957] = 8; 
    	em[958] = 217; em[959] = 24; 
    em[960] = 8884099; em[961] = 8; em[962] = 2; /* 960: pointer_to_array_of_pointers_to_stack */
    	em[963] = 967; em[964] = 0; 
    	em[965] = 214; em[966] = 20; 
    em[967] = 0; em[968] = 8; em[969] = 1; /* 967: pointer.GENERAL_NAME */
    	em[970] = 671; em[971] = 0; 
    em[972] = 0; em[973] = 8; em[974] = 2; /* 972: union.unknown */
    	em[975] = 948; em[976] = 0; 
    	em[977] = 979; em[978] = 0; 
    em[979] = 1; em[980] = 8; em[981] = 1; /* 979: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[982] = 984; em[983] = 0; 
    em[984] = 0; em[985] = 32; em[986] = 2; /* 984: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[987] = 991; em[988] = 8; 
    	em[989] = 217; em[990] = 24; 
    em[991] = 8884099; em[992] = 8; em[993] = 2; /* 991: pointer_to_array_of_pointers_to_stack */
    	em[994] = 998; em[995] = 0; 
    	em[996] = 214; em[997] = 20; 
    em[998] = 0; em[999] = 8; em[1000] = 1; /* 998: pointer.X509_NAME_ENTRY */
    	em[1001] = 337; em[1002] = 0; 
    em[1003] = 0; em[1004] = 24; em[1005] = 2; /* 1003: struct.DIST_POINT_NAME_st */
    	em[1006] = 972; em[1007] = 8; 
    	em[1008] = 1010; em[1009] = 16; 
    em[1010] = 1; em[1011] = 8; em[1012] = 1; /* 1010: pointer.struct.X509_name_st */
    	em[1013] = 1015; em[1014] = 0; 
    em[1015] = 0; em[1016] = 40; em[1017] = 3; /* 1015: struct.X509_name_st */
    	em[1018] = 979; em[1019] = 0; 
    	em[1020] = 938; em[1021] = 16; 
    	em[1022] = 107; em[1023] = 24; 
    em[1024] = 1; em[1025] = 8; em[1026] = 1; /* 1024: pointer.struct.DIST_POINT_NAME_st */
    	em[1027] = 1003; em[1028] = 0; 
    em[1029] = 0; em[1030] = 0; em[1031] = 1; /* 1029: DIST_POINT */
    	em[1032] = 1034; em[1033] = 0; 
    em[1034] = 0; em[1035] = 32; em[1036] = 3; /* 1034: struct.DIST_POINT_st */
    	em[1037] = 1024; em[1038] = 0; 
    	em[1039] = 1043; em[1040] = 8; 
    	em[1041] = 948; em[1042] = 16; 
    em[1043] = 1; em[1044] = 8; em[1045] = 1; /* 1043: pointer.struct.asn1_string_st */
    	em[1046] = 933; em[1047] = 0; 
    em[1048] = 1; em[1049] = 8; em[1050] = 1; /* 1048: pointer.struct.stack_st_DIST_POINT */
    	em[1051] = 1053; em[1052] = 0; 
    em[1053] = 0; em[1054] = 32; em[1055] = 2; /* 1053: struct.stack_st_fake_DIST_POINT */
    	em[1056] = 1060; em[1057] = 8; 
    	em[1058] = 217; em[1059] = 24; 
    em[1060] = 8884099; em[1061] = 8; em[1062] = 2; /* 1060: pointer_to_array_of_pointers_to_stack */
    	em[1063] = 1067; em[1064] = 0; 
    	em[1065] = 214; em[1066] = 20; 
    em[1067] = 0; em[1068] = 8; em[1069] = 1; /* 1067: pointer.DIST_POINT */
    	em[1070] = 1029; em[1071] = 0; 
    em[1072] = 1; em[1073] = 8; em[1074] = 1; /* 1072: pointer.struct.stack_st_ASN1_OBJECT */
    	em[1075] = 1077; em[1076] = 0; 
    em[1077] = 0; em[1078] = 32; em[1079] = 2; /* 1077: struct.stack_st_fake_ASN1_OBJECT */
    	em[1080] = 1084; em[1081] = 8; 
    	em[1082] = 217; em[1083] = 24; 
    em[1084] = 8884099; em[1085] = 8; em[1086] = 2; /* 1084: pointer_to_array_of_pointers_to_stack */
    	em[1087] = 1091; em[1088] = 0; 
    	em[1089] = 214; em[1090] = 20; 
    em[1091] = 0; em[1092] = 8; em[1093] = 1; /* 1091: pointer.ASN1_OBJECT */
    	em[1094] = 244; em[1095] = 0; 
    em[1096] = 1; em[1097] = 8; em[1098] = 1; /* 1096: pointer.struct.stack_st_POLICYQUALINFO */
    	em[1099] = 1101; em[1100] = 0; 
    em[1101] = 0; em[1102] = 32; em[1103] = 2; /* 1101: struct.stack_st_fake_POLICYQUALINFO */
    	em[1104] = 1108; em[1105] = 8; 
    	em[1106] = 217; em[1107] = 24; 
    em[1108] = 8884099; em[1109] = 8; em[1110] = 2; /* 1108: pointer_to_array_of_pointers_to_stack */
    	em[1111] = 1115; em[1112] = 0; 
    	em[1113] = 214; em[1114] = 20; 
    em[1115] = 0; em[1116] = 8; em[1117] = 1; /* 1115: pointer.POLICYQUALINFO */
    	em[1118] = 1120; em[1119] = 0; 
    em[1120] = 0; em[1121] = 0; em[1122] = 1; /* 1120: POLICYQUALINFO */
    	em[1123] = 1125; em[1124] = 0; 
    em[1125] = 0; em[1126] = 16; em[1127] = 2; /* 1125: struct.POLICYQUALINFO_st */
    	em[1128] = 1132; em[1129] = 0; 
    	em[1130] = 1146; em[1131] = 8; 
    em[1132] = 1; em[1133] = 8; em[1134] = 1; /* 1132: pointer.struct.asn1_object_st */
    	em[1135] = 1137; em[1136] = 0; 
    em[1137] = 0; em[1138] = 40; em[1139] = 3; /* 1137: struct.asn1_object_st */
    	em[1140] = 26; em[1141] = 0; 
    	em[1142] = 26; em[1143] = 8; 
    	em[1144] = 31; em[1145] = 24; 
    em[1146] = 0; em[1147] = 8; em[1148] = 3; /* 1146: union.unknown */
    	em[1149] = 1155; em[1150] = 0; 
    	em[1151] = 1165; em[1152] = 0; 
    	em[1153] = 1223; em[1154] = 0; 
    em[1155] = 1; em[1156] = 8; em[1157] = 1; /* 1155: pointer.struct.asn1_string_st */
    	em[1158] = 1160; em[1159] = 0; 
    em[1160] = 0; em[1161] = 24; em[1162] = 1; /* 1160: struct.asn1_string_st */
    	em[1163] = 107; em[1164] = 8; 
    em[1165] = 1; em[1166] = 8; em[1167] = 1; /* 1165: pointer.struct.USERNOTICE_st */
    	em[1168] = 1170; em[1169] = 0; 
    em[1170] = 0; em[1171] = 16; em[1172] = 2; /* 1170: struct.USERNOTICE_st */
    	em[1173] = 1177; em[1174] = 0; 
    	em[1175] = 1189; em[1176] = 8; 
    em[1177] = 1; em[1178] = 8; em[1179] = 1; /* 1177: pointer.struct.NOTICEREF_st */
    	em[1180] = 1182; em[1181] = 0; 
    em[1182] = 0; em[1183] = 16; em[1184] = 2; /* 1182: struct.NOTICEREF_st */
    	em[1185] = 1189; em[1186] = 0; 
    	em[1187] = 1194; em[1188] = 8; 
    em[1189] = 1; em[1190] = 8; em[1191] = 1; /* 1189: pointer.struct.asn1_string_st */
    	em[1192] = 1160; em[1193] = 0; 
    em[1194] = 1; em[1195] = 8; em[1196] = 1; /* 1194: pointer.struct.stack_st_ASN1_INTEGER */
    	em[1197] = 1199; em[1198] = 0; 
    em[1199] = 0; em[1200] = 32; em[1201] = 2; /* 1199: struct.stack_st_fake_ASN1_INTEGER */
    	em[1202] = 1206; em[1203] = 8; 
    	em[1204] = 217; em[1205] = 24; 
    em[1206] = 8884099; em[1207] = 8; em[1208] = 2; /* 1206: pointer_to_array_of_pointers_to_stack */
    	em[1209] = 1213; em[1210] = 0; 
    	em[1211] = 214; em[1212] = 20; 
    em[1213] = 0; em[1214] = 8; em[1215] = 1; /* 1213: pointer.ASN1_INTEGER */
    	em[1216] = 1218; em[1217] = 0; 
    em[1218] = 0; em[1219] = 0; em[1220] = 1; /* 1218: ASN1_INTEGER */
    	em[1221] = 102; em[1222] = 0; 
    em[1223] = 1; em[1224] = 8; em[1225] = 1; /* 1223: pointer.struct.asn1_type_st */
    	em[1226] = 1228; em[1227] = 0; 
    em[1228] = 0; em[1229] = 16; em[1230] = 1; /* 1228: struct.asn1_type_st */
    	em[1231] = 1233; em[1232] = 8; 
    em[1233] = 0; em[1234] = 8; em[1235] = 20; /* 1233: union.unknown */
    	em[1236] = 92; em[1237] = 0; 
    	em[1238] = 1189; em[1239] = 0; 
    	em[1240] = 1132; em[1241] = 0; 
    	em[1242] = 1276; em[1243] = 0; 
    	em[1244] = 1281; em[1245] = 0; 
    	em[1246] = 1286; em[1247] = 0; 
    	em[1248] = 1291; em[1249] = 0; 
    	em[1250] = 1296; em[1251] = 0; 
    	em[1252] = 1301; em[1253] = 0; 
    	em[1254] = 1155; em[1255] = 0; 
    	em[1256] = 1306; em[1257] = 0; 
    	em[1258] = 1311; em[1259] = 0; 
    	em[1260] = 1316; em[1261] = 0; 
    	em[1262] = 1321; em[1263] = 0; 
    	em[1264] = 1326; em[1265] = 0; 
    	em[1266] = 1331; em[1267] = 0; 
    	em[1268] = 1336; em[1269] = 0; 
    	em[1270] = 1189; em[1271] = 0; 
    	em[1272] = 1189; em[1273] = 0; 
    	em[1274] = 519; em[1275] = 0; 
    em[1276] = 1; em[1277] = 8; em[1278] = 1; /* 1276: pointer.struct.asn1_string_st */
    	em[1279] = 1160; em[1280] = 0; 
    em[1281] = 1; em[1282] = 8; em[1283] = 1; /* 1281: pointer.struct.asn1_string_st */
    	em[1284] = 1160; em[1285] = 0; 
    em[1286] = 1; em[1287] = 8; em[1288] = 1; /* 1286: pointer.struct.asn1_string_st */
    	em[1289] = 1160; em[1290] = 0; 
    em[1291] = 1; em[1292] = 8; em[1293] = 1; /* 1291: pointer.struct.asn1_string_st */
    	em[1294] = 1160; em[1295] = 0; 
    em[1296] = 1; em[1297] = 8; em[1298] = 1; /* 1296: pointer.struct.asn1_string_st */
    	em[1299] = 1160; em[1300] = 0; 
    em[1301] = 1; em[1302] = 8; em[1303] = 1; /* 1301: pointer.struct.asn1_string_st */
    	em[1304] = 1160; em[1305] = 0; 
    em[1306] = 1; em[1307] = 8; em[1308] = 1; /* 1306: pointer.struct.asn1_string_st */
    	em[1309] = 1160; em[1310] = 0; 
    em[1311] = 1; em[1312] = 8; em[1313] = 1; /* 1311: pointer.struct.asn1_string_st */
    	em[1314] = 1160; em[1315] = 0; 
    em[1316] = 1; em[1317] = 8; em[1318] = 1; /* 1316: pointer.struct.asn1_string_st */
    	em[1319] = 1160; em[1320] = 0; 
    em[1321] = 1; em[1322] = 8; em[1323] = 1; /* 1321: pointer.struct.asn1_string_st */
    	em[1324] = 1160; em[1325] = 0; 
    em[1326] = 1; em[1327] = 8; em[1328] = 1; /* 1326: pointer.struct.asn1_string_st */
    	em[1329] = 1160; em[1330] = 0; 
    em[1331] = 1; em[1332] = 8; em[1333] = 1; /* 1331: pointer.struct.asn1_string_st */
    	em[1334] = 1160; em[1335] = 0; 
    em[1336] = 1; em[1337] = 8; em[1338] = 1; /* 1336: pointer.struct.asn1_string_st */
    	em[1339] = 1160; em[1340] = 0; 
    em[1341] = 1; em[1342] = 8; em[1343] = 1; /* 1341: pointer.struct.asn1_object_st */
    	em[1344] = 1346; em[1345] = 0; 
    em[1346] = 0; em[1347] = 40; em[1348] = 3; /* 1346: struct.asn1_object_st */
    	em[1349] = 26; em[1350] = 0; 
    	em[1351] = 26; em[1352] = 8; 
    	em[1353] = 31; em[1354] = 24; 
    em[1355] = 0; em[1356] = 32; em[1357] = 3; /* 1355: struct.X509_POLICY_DATA_st */
    	em[1358] = 1341; em[1359] = 8; 
    	em[1360] = 1096; em[1361] = 16; 
    	em[1362] = 1072; em[1363] = 24; 
    em[1364] = 1; em[1365] = 8; em[1366] = 1; /* 1364: pointer.struct.stack_st_X509_POLICY_DATA */
    	em[1367] = 1369; em[1368] = 0; 
    em[1369] = 0; em[1370] = 32; em[1371] = 2; /* 1369: struct.stack_st_fake_X509_POLICY_DATA */
    	em[1372] = 1376; em[1373] = 8; 
    	em[1374] = 217; em[1375] = 24; 
    em[1376] = 8884099; em[1377] = 8; em[1378] = 2; /* 1376: pointer_to_array_of_pointers_to_stack */
    	em[1379] = 1383; em[1380] = 0; 
    	em[1381] = 214; em[1382] = 20; 
    em[1383] = 0; em[1384] = 8; em[1385] = 1; /* 1383: pointer.X509_POLICY_DATA */
    	em[1386] = 1388; em[1387] = 0; 
    em[1388] = 0; em[1389] = 0; em[1390] = 1; /* 1388: X509_POLICY_DATA */
    	em[1391] = 1355; em[1392] = 0; 
    em[1393] = 1; em[1394] = 8; em[1395] = 1; /* 1393: pointer.struct.stack_st_ASN1_OBJECT */
    	em[1396] = 1398; em[1397] = 0; 
    em[1398] = 0; em[1399] = 32; em[1400] = 2; /* 1398: struct.stack_st_fake_ASN1_OBJECT */
    	em[1401] = 1405; em[1402] = 8; 
    	em[1403] = 217; em[1404] = 24; 
    em[1405] = 8884099; em[1406] = 8; em[1407] = 2; /* 1405: pointer_to_array_of_pointers_to_stack */
    	em[1408] = 1412; em[1409] = 0; 
    	em[1410] = 214; em[1411] = 20; 
    em[1412] = 0; em[1413] = 8; em[1414] = 1; /* 1412: pointer.ASN1_OBJECT */
    	em[1415] = 244; em[1416] = 0; 
    em[1417] = 1; em[1418] = 8; em[1419] = 1; /* 1417: pointer.struct.stack_st_POLICYQUALINFO */
    	em[1420] = 1422; em[1421] = 0; 
    em[1422] = 0; em[1423] = 32; em[1424] = 2; /* 1422: struct.stack_st_fake_POLICYQUALINFO */
    	em[1425] = 1429; em[1426] = 8; 
    	em[1427] = 217; em[1428] = 24; 
    em[1429] = 8884099; em[1430] = 8; em[1431] = 2; /* 1429: pointer_to_array_of_pointers_to_stack */
    	em[1432] = 1436; em[1433] = 0; 
    	em[1434] = 214; em[1435] = 20; 
    em[1436] = 0; em[1437] = 8; em[1438] = 1; /* 1436: pointer.POLICYQUALINFO */
    	em[1439] = 1120; em[1440] = 0; 
    em[1441] = 0; em[1442] = 40; em[1443] = 3; /* 1441: struct.asn1_object_st */
    	em[1444] = 26; em[1445] = 0; 
    	em[1446] = 26; em[1447] = 8; 
    	em[1448] = 31; em[1449] = 24; 
    em[1450] = 0; em[1451] = 32; em[1452] = 3; /* 1450: struct.X509_POLICY_DATA_st */
    	em[1453] = 1459; em[1454] = 8; 
    	em[1455] = 1417; em[1456] = 16; 
    	em[1457] = 1393; em[1458] = 24; 
    em[1459] = 1; em[1460] = 8; em[1461] = 1; /* 1459: pointer.struct.asn1_object_st */
    	em[1462] = 1441; em[1463] = 0; 
    em[1464] = 1; em[1465] = 8; em[1466] = 1; /* 1464: pointer.struct.X509_POLICY_DATA_st */
    	em[1467] = 1450; em[1468] = 0; 
    em[1469] = 0; em[1470] = 40; em[1471] = 2; /* 1469: struct.X509_POLICY_CACHE_st */
    	em[1472] = 1464; em[1473] = 0; 
    	em[1474] = 1364; em[1475] = 8; 
    em[1476] = 1; em[1477] = 8; em[1478] = 1; /* 1476: pointer.struct.asn1_string_st */
    	em[1479] = 1481; em[1480] = 0; 
    em[1481] = 0; em[1482] = 24; em[1483] = 1; /* 1481: struct.asn1_string_st */
    	em[1484] = 107; em[1485] = 8; 
    em[1486] = 1; em[1487] = 8; em[1488] = 1; /* 1486: pointer.struct.stack_st_GENERAL_NAME */
    	em[1489] = 1491; em[1490] = 0; 
    em[1491] = 0; em[1492] = 32; em[1493] = 2; /* 1491: struct.stack_st_fake_GENERAL_NAME */
    	em[1494] = 1498; em[1495] = 8; 
    	em[1496] = 217; em[1497] = 24; 
    em[1498] = 8884099; em[1499] = 8; em[1500] = 2; /* 1498: pointer_to_array_of_pointers_to_stack */
    	em[1501] = 1505; em[1502] = 0; 
    	em[1503] = 214; em[1504] = 20; 
    em[1505] = 0; em[1506] = 8; em[1507] = 1; /* 1505: pointer.GENERAL_NAME */
    	em[1508] = 671; em[1509] = 0; 
    em[1510] = 0; em[1511] = 24; em[1512] = 1; /* 1510: struct.asn1_string_st */
    	em[1513] = 107; em[1514] = 8; 
    em[1515] = 1; em[1516] = 8; em[1517] = 1; /* 1515: pointer.struct.asn1_string_st */
    	em[1518] = 1510; em[1519] = 0; 
    em[1520] = 1; em[1521] = 8; em[1522] = 1; /* 1520: pointer.struct.stack_st_X509_EXTENSION */
    	em[1523] = 1525; em[1524] = 0; 
    em[1525] = 0; em[1526] = 32; em[1527] = 2; /* 1525: struct.stack_st_fake_X509_EXTENSION */
    	em[1528] = 1532; em[1529] = 8; 
    	em[1530] = 217; em[1531] = 24; 
    em[1532] = 8884099; em[1533] = 8; em[1534] = 2; /* 1532: pointer_to_array_of_pointers_to_stack */
    	em[1535] = 1539; em[1536] = 0; 
    	em[1537] = 214; em[1538] = 20; 
    em[1539] = 0; em[1540] = 8; em[1541] = 1; /* 1539: pointer.X509_EXTENSION */
    	em[1542] = 1544; em[1543] = 0; 
    em[1544] = 0; em[1545] = 0; em[1546] = 1; /* 1544: X509_EXTENSION */
    	em[1547] = 1549; em[1548] = 0; 
    em[1549] = 0; em[1550] = 24; em[1551] = 2; /* 1549: struct.X509_extension_st */
    	em[1552] = 1556; em[1553] = 0; 
    	em[1554] = 1515; em[1555] = 16; 
    em[1556] = 1; em[1557] = 8; em[1558] = 1; /* 1556: pointer.struct.asn1_object_st */
    	em[1559] = 1561; em[1560] = 0; 
    em[1561] = 0; em[1562] = 40; em[1563] = 3; /* 1561: struct.asn1_object_st */
    	em[1564] = 26; em[1565] = 0; 
    	em[1566] = 26; em[1567] = 8; 
    	em[1568] = 31; em[1569] = 24; 
    em[1570] = 1; em[1571] = 8; em[1572] = 1; /* 1570: pointer.struct.asn1_string_st */
    	em[1573] = 281; em[1574] = 0; 
    em[1575] = 1; em[1576] = 8; em[1577] = 1; /* 1575: pointer.struct.asn1_string_st */
    	em[1578] = 1580; em[1579] = 0; 
    em[1580] = 0; em[1581] = 24; em[1582] = 1; /* 1580: struct.asn1_string_st */
    	em[1583] = 107; em[1584] = 8; 
    em[1585] = 1; em[1586] = 8; em[1587] = 1; /* 1585: pointer.struct.asn1_string_st */
    	em[1588] = 1580; em[1589] = 0; 
    em[1590] = 1; em[1591] = 8; em[1592] = 1; /* 1590: pointer.struct.asn1_string_st */
    	em[1593] = 1580; em[1594] = 0; 
    em[1595] = 1; em[1596] = 8; em[1597] = 1; /* 1595: pointer.struct.asn1_string_st */
    	em[1598] = 1580; em[1599] = 0; 
    em[1600] = 1; em[1601] = 8; em[1602] = 1; /* 1600: pointer.struct.asn1_string_st */
    	em[1603] = 1580; em[1604] = 0; 
    em[1605] = 1; em[1606] = 8; em[1607] = 1; /* 1605: pointer.struct.asn1_string_st */
    	em[1608] = 1580; em[1609] = 0; 
    em[1610] = 1; em[1611] = 8; em[1612] = 1; /* 1610: pointer.struct.asn1_string_st */
    	em[1613] = 1580; em[1614] = 0; 
    em[1615] = 1; em[1616] = 8; em[1617] = 1; /* 1615: pointer.struct.asn1_string_st */
    	em[1618] = 1580; em[1619] = 0; 
    em[1620] = 1; em[1621] = 8; em[1622] = 1; /* 1620: pointer.struct.asn1_string_st */
    	em[1623] = 1580; em[1624] = 0; 
    em[1625] = 0; em[1626] = 8; em[1627] = 20; /* 1625: union.unknown */
    	em[1628] = 92; em[1629] = 0; 
    	em[1630] = 1668; em[1631] = 0; 
    	em[1632] = 1673; em[1633] = 0; 
    	em[1634] = 1687; em[1635] = 0; 
    	em[1636] = 1620; em[1637] = 0; 
    	em[1638] = 1692; em[1639] = 0; 
    	em[1640] = 1615; em[1641] = 0; 
    	em[1642] = 1697; em[1643] = 0; 
    	em[1644] = 1610; em[1645] = 0; 
    	em[1646] = 1605; em[1647] = 0; 
    	em[1648] = 1600; em[1649] = 0; 
    	em[1650] = 1595; em[1651] = 0; 
    	em[1652] = 1702; em[1653] = 0; 
    	em[1654] = 1590; em[1655] = 0; 
    	em[1656] = 1585; em[1657] = 0; 
    	em[1658] = 1707; em[1659] = 0; 
    	em[1660] = 1575; em[1661] = 0; 
    	em[1662] = 1668; em[1663] = 0; 
    	em[1664] = 1668; em[1665] = 0; 
    	em[1666] = 182; em[1667] = 0; 
    em[1668] = 1; em[1669] = 8; em[1670] = 1; /* 1668: pointer.struct.asn1_string_st */
    	em[1671] = 1580; em[1672] = 0; 
    em[1673] = 1; em[1674] = 8; em[1675] = 1; /* 1673: pointer.struct.asn1_object_st */
    	em[1676] = 1678; em[1677] = 0; 
    em[1678] = 0; em[1679] = 40; em[1680] = 3; /* 1678: struct.asn1_object_st */
    	em[1681] = 26; em[1682] = 0; 
    	em[1683] = 26; em[1684] = 8; 
    	em[1685] = 31; em[1686] = 24; 
    em[1687] = 1; em[1688] = 8; em[1689] = 1; /* 1687: pointer.struct.asn1_string_st */
    	em[1690] = 1580; em[1691] = 0; 
    em[1692] = 1; em[1693] = 8; em[1694] = 1; /* 1692: pointer.struct.asn1_string_st */
    	em[1695] = 1580; em[1696] = 0; 
    em[1697] = 1; em[1698] = 8; em[1699] = 1; /* 1697: pointer.struct.asn1_string_st */
    	em[1700] = 1580; em[1701] = 0; 
    em[1702] = 1; em[1703] = 8; em[1704] = 1; /* 1702: pointer.struct.asn1_string_st */
    	em[1705] = 1580; em[1706] = 0; 
    em[1707] = 1; em[1708] = 8; em[1709] = 1; /* 1707: pointer.struct.asn1_string_st */
    	em[1710] = 1580; em[1711] = 0; 
    em[1712] = 0; em[1713] = 16; em[1714] = 1; /* 1712: struct.asn1_type_st */
    	em[1715] = 1625; em[1716] = 8; 
    em[1717] = 1; em[1718] = 8; em[1719] = 1; /* 1717: pointer.struct.ASN1_VALUE_st */
    	em[1720] = 1722; em[1721] = 0; 
    em[1722] = 0; em[1723] = 0; em[1724] = 0; /* 1722: struct.ASN1_VALUE_st */
    em[1725] = 1; em[1726] = 8; em[1727] = 1; /* 1725: pointer.struct.asn1_string_st */
    	em[1728] = 1730; em[1729] = 0; 
    em[1730] = 0; em[1731] = 24; em[1732] = 1; /* 1730: struct.asn1_string_st */
    	em[1733] = 107; em[1734] = 8; 
    em[1735] = 1; em[1736] = 8; em[1737] = 1; /* 1735: pointer.struct.asn1_string_st */
    	em[1738] = 1730; em[1739] = 0; 
    em[1740] = 1; em[1741] = 8; em[1742] = 1; /* 1740: pointer.struct.asn1_string_st */
    	em[1743] = 1730; em[1744] = 0; 
    em[1745] = 1; em[1746] = 8; em[1747] = 1; /* 1745: pointer.struct.asn1_string_st */
    	em[1748] = 1730; em[1749] = 0; 
    em[1750] = 1; em[1751] = 8; em[1752] = 1; /* 1750: pointer.struct.asn1_string_st */
    	em[1753] = 1730; em[1754] = 0; 
    em[1755] = 0; em[1756] = 40; em[1757] = 3; /* 1755: struct.asn1_object_st */
    	em[1758] = 26; em[1759] = 0; 
    	em[1760] = 26; em[1761] = 8; 
    	em[1762] = 31; em[1763] = 24; 
    em[1764] = 1; em[1765] = 8; em[1766] = 1; /* 1764: pointer.struct.asn1_object_st */
    	em[1767] = 1755; em[1768] = 0; 
    em[1769] = 1; em[1770] = 8; em[1771] = 1; /* 1769: pointer.struct.asn1_string_st */
    	em[1772] = 1730; em[1773] = 0; 
    em[1774] = 1; em[1775] = 8; em[1776] = 1; /* 1774: pointer.struct.stack_st_ASN1_TYPE */
    	em[1777] = 1779; em[1778] = 0; 
    em[1779] = 0; em[1780] = 32; em[1781] = 2; /* 1779: struct.stack_st_fake_ASN1_TYPE */
    	em[1782] = 1786; em[1783] = 8; 
    	em[1784] = 217; em[1785] = 24; 
    em[1786] = 8884099; em[1787] = 8; em[1788] = 2; /* 1786: pointer_to_array_of_pointers_to_stack */
    	em[1789] = 1793; em[1790] = 0; 
    	em[1791] = 214; em[1792] = 20; 
    em[1793] = 0; em[1794] = 8; em[1795] = 1; /* 1793: pointer.ASN1_TYPE */
    	em[1796] = 1798; em[1797] = 0; 
    em[1798] = 0; em[1799] = 0; em[1800] = 1; /* 1798: ASN1_TYPE */
    	em[1801] = 1803; em[1802] = 0; 
    em[1803] = 0; em[1804] = 16; em[1805] = 1; /* 1803: struct.asn1_type_st */
    	em[1806] = 1808; em[1807] = 8; 
    em[1808] = 0; em[1809] = 8; em[1810] = 20; /* 1808: union.unknown */
    	em[1811] = 92; em[1812] = 0; 
    	em[1813] = 1769; em[1814] = 0; 
    	em[1815] = 1764; em[1816] = 0; 
    	em[1817] = 1750; em[1818] = 0; 
    	em[1819] = 1745; em[1820] = 0; 
    	em[1821] = 1851; em[1822] = 0; 
    	em[1823] = 1856; em[1824] = 0; 
    	em[1825] = 1861; em[1826] = 0; 
    	em[1827] = 1740; em[1828] = 0; 
    	em[1829] = 1735; em[1830] = 0; 
    	em[1831] = 1866; em[1832] = 0; 
    	em[1833] = 1871; em[1834] = 0; 
    	em[1835] = 1876; em[1836] = 0; 
    	em[1837] = 1881; em[1838] = 0; 
    	em[1839] = 1886; em[1840] = 0; 
    	em[1841] = 1891; em[1842] = 0; 
    	em[1843] = 1725; em[1844] = 0; 
    	em[1845] = 1769; em[1846] = 0; 
    	em[1847] = 1769; em[1848] = 0; 
    	em[1849] = 1717; em[1850] = 0; 
    em[1851] = 1; em[1852] = 8; em[1853] = 1; /* 1851: pointer.struct.asn1_string_st */
    	em[1854] = 1730; em[1855] = 0; 
    em[1856] = 1; em[1857] = 8; em[1858] = 1; /* 1856: pointer.struct.asn1_string_st */
    	em[1859] = 1730; em[1860] = 0; 
    em[1861] = 1; em[1862] = 8; em[1863] = 1; /* 1861: pointer.struct.asn1_string_st */
    	em[1864] = 1730; em[1865] = 0; 
    em[1866] = 1; em[1867] = 8; em[1868] = 1; /* 1866: pointer.struct.asn1_string_st */
    	em[1869] = 1730; em[1870] = 0; 
    em[1871] = 1; em[1872] = 8; em[1873] = 1; /* 1871: pointer.struct.asn1_string_st */
    	em[1874] = 1730; em[1875] = 0; 
    em[1876] = 1; em[1877] = 8; em[1878] = 1; /* 1876: pointer.struct.asn1_string_st */
    	em[1879] = 1730; em[1880] = 0; 
    em[1881] = 1; em[1882] = 8; em[1883] = 1; /* 1881: pointer.struct.asn1_string_st */
    	em[1884] = 1730; em[1885] = 0; 
    em[1886] = 1; em[1887] = 8; em[1888] = 1; /* 1886: pointer.struct.asn1_string_st */
    	em[1889] = 1730; em[1890] = 0; 
    em[1891] = 1; em[1892] = 8; em[1893] = 1; /* 1891: pointer.struct.asn1_string_st */
    	em[1894] = 1730; em[1895] = 0; 
    em[1896] = 0; em[1897] = 8; em[1898] = 3; /* 1896: union.unknown */
    	em[1899] = 92; em[1900] = 0; 
    	em[1901] = 1774; em[1902] = 0; 
    	em[1903] = 1905; em[1904] = 0; 
    em[1905] = 1; em[1906] = 8; em[1907] = 1; /* 1905: pointer.struct.asn1_type_st */
    	em[1908] = 1712; em[1909] = 0; 
    em[1910] = 0; em[1911] = 24; em[1912] = 2; /* 1910: struct.x509_attributes_st */
    	em[1913] = 1673; em[1914] = 0; 
    	em[1915] = 1896; em[1916] = 16; 
    em[1917] = 1; em[1918] = 8; em[1919] = 1; /* 1917: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[1920] = 1922; em[1921] = 0; 
    em[1922] = 0; em[1923] = 32; em[1924] = 2; /* 1922: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[1925] = 1929; em[1926] = 8; 
    	em[1927] = 217; em[1928] = 24; 
    em[1929] = 8884099; em[1930] = 8; em[1931] = 2; /* 1929: pointer_to_array_of_pointers_to_stack */
    	em[1932] = 1936; em[1933] = 0; 
    	em[1934] = 214; em[1935] = 20; 
    em[1936] = 0; em[1937] = 8; em[1938] = 1; /* 1936: pointer.X509_ATTRIBUTE */
    	em[1939] = 1941; em[1940] = 0; 
    em[1941] = 0; em[1942] = 0; em[1943] = 1; /* 1941: X509_ATTRIBUTE */
    	em[1944] = 1910; em[1945] = 0; 
    em[1946] = 0; em[1947] = 40; em[1948] = 5; /* 1946: struct.ec_extra_data_st */
    	em[1949] = 1959; em[1950] = 0; 
    	em[1951] = 1964; em[1952] = 8; 
    	em[1953] = 1967; em[1954] = 16; 
    	em[1955] = 1970; em[1956] = 24; 
    	em[1957] = 1970; em[1958] = 32; 
    em[1959] = 1; em[1960] = 8; em[1961] = 1; /* 1959: pointer.struct.ec_extra_data_st */
    	em[1962] = 1946; em[1963] = 0; 
    em[1964] = 0; em[1965] = 8; em[1966] = 0; /* 1964: pointer.void */
    em[1967] = 8884097; em[1968] = 8; em[1969] = 0; /* 1967: pointer.func */
    em[1970] = 8884097; em[1971] = 8; em[1972] = 0; /* 1970: pointer.func */
    em[1973] = 1; em[1974] = 8; em[1975] = 1; /* 1973: pointer.struct.ec_extra_data_st */
    	em[1976] = 1946; em[1977] = 0; 
    em[1978] = 0; em[1979] = 24; em[1980] = 1; /* 1978: struct.bignum_st */
    	em[1981] = 1983; em[1982] = 0; 
    em[1983] = 8884099; em[1984] = 8; em[1985] = 2; /* 1983: pointer_to_array_of_pointers_to_stack */
    	em[1986] = 1990; em[1987] = 0; 
    	em[1988] = 214; em[1989] = 12; 
    em[1990] = 0; em[1991] = 8; em[1992] = 0; /* 1990: long unsigned int */
    em[1993] = 1; em[1994] = 8; em[1995] = 1; /* 1993: pointer.struct.bignum_st */
    	em[1996] = 1978; em[1997] = 0; 
    em[1998] = 1; em[1999] = 8; em[2000] = 1; /* 1998: pointer.struct.ec_point_st */
    	em[2001] = 2003; em[2002] = 0; 
    em[2003] = 0; em[2004] = 88; em[2005] = 4; /* 2003: struct.ec_point_st */
    	em[2006] = 2014; em[2007] = 0; 
    	em[2008] = 2186; em[2009] = 8; 
    	em[2010] = 2186; em[2011] = 32; 
    	em[2012] = 2186; em[2013] = 56; 
    em[2014] = 1; em[2015] = 8; em[2016] = 1; /* 2014: pointer.struct.ec_method_st */
    	em[2017] = 2019; em[2018] = 0; 
    em[2019] = 0; em[2020] = 304; em[2021] = 37; /* 2019: struct.ec_method_st */
    	em[2022] = 2096; em[2023] = 8; 
    	em[2024] = 2099; em[2025] = 16; 
    	em[2026] = 2099; em[2027] = 24; 
    	em[2028] = 2102; em[2029] = 32; 
    	em[2030] = 2105; em[2031] = 40; 
    	em[2032] = 2108; em[2033] = 48; 
    	em[2034] = 2111; em[2035] = 56; 
    	em[2036] = 2114; em[2037] = 64; 
    	em[2038] = 2117; em[2039] = 72; 
    	em[2040] = 2120; em[2041] = 80; 
    	em[2042] = 2120; em[2043] = 88; 
    	em[2044] = 2123; em[2045] = 96; 
    	em[2046] = 2126; em[2047] = 104; 
    	em[2048] = 2129; em[2049] = 112; 
    	em[2050] = 2132; em[2051] = 120; 
    	em[2052] = 2135; em[2053] = 128; 
    	em[2054] = 2138; em[2055] = 136; 
    	em[2056] = 2141; em[2057] = 144; 
    	em[2058] = 2144; em[2059] = 152; 
    	em[2060] = 2147; em[2061] = 160; 
    	em[2062] = 2150; em[2063] = 168; 
    	em[2064] = 2153; em[2065] = 176; 
    	em[2066] = 2156; em[2067] = 184; 
    	em[2068] = 2159; em[2069] = 192; 
    	em[2070] = 2162; em[2071] = 200; 
    	em[2072] = 2165; em[2073] = 208; 
    	em[2074] = 2156; em[2075] = 216; 
    	em[2076] = 2168; em[2077] = 224; 
    	em[2078] = 2171; em[2079] = 232; 
    	em[2080] = 2174; em[2081] = 240; 
    	em[2082] = 2111; em[2083] = 248; 
    	em[2084] = 2177; em[2085] = 256; 
    	em[2086] = 2180; em[2087] = 264; 
    	em[2088] = 2177; em[2089] = 272; 
    	em[2090] = 2180; em[2091] = 280; 
    	em[2092] = 2180; em[2093] = 288; 
    	em[2094] = 2183; em[2095] = 296; 
    em[2096] = 8884097; em[2097] = 8; em[2098] = 0; /* 2096: pointer.func */
    em[2099] = 8884097; em[2100] = 8; em[2101] = 0; /* 2099: pointer.func */
    em[2102] = 8884097; em[2103] = 8; em[2104] = 0; /* 2102: pointer.func */
    em[2105] = 8884097; em[2106] = 8; em[2107] = 0; /* 2105: pointer.func */
    em[2108] = 8884097; em[2109] = 8; em[2110] = 0; /* 2108: pointer.func */
    em[2111] = 8884097; em[2112] = 8; em[2113] = 0; /* 2111: pointer.func */
    em[2114] = 8884097; em[2115] = 8; em[2116] = 0; /* 2114: pointer.func */
    em[2117] = 8884097; em[2118] = 8; em[2119] = 0; /* 2117: pointer.func */
    em[2120] = 8884097; em[2121] = 8; em[2122] = 0; /* 2120: pointer.func */
    em[2123] = 8884097; em[2124] = 8; em[2125] = 0; /* 2123: pointer.func */
    em[2126] = 8884097; em[2127] = 8; em[2128] = 0; /* 2126: pointer.func */
    em[2129] = 8884097; em[2130] = 8; em[2131] = 0; /* 2129: pointer.func */
    em[2132] = 8884097; em[2133] = 8; em[2134] = 0; /* 2132: pointer.func */
    em[2135] = 8884097; em[2136] = 8; em[2137] = 0; /* 2135: pointer.func */
    em[2138] = 8884097; em[2139] = 8; em[2140] = 0; /* 2138: pointer.func */
    em[2141] = 8884097; em[2142] = 8; em[2143] = 0; /* 2141: pointer.func */
    em[2144] = 8884097; em[2145] = 8; em[2146] = 0; /* 2144: pointer.func */
    em[2147] = 8884097; em[2148] = 8; em[2149] = 0; /* 2147: pointer.func */
    em[2150] = 8884097; em[2151] = 8; em[2152] = 0; /* 2150: pointer.func */
    em[2153] = 8884097; em[2154] = 8; em[2155] = 0; /* 2153: pointer.func */
    em[2156] = 8884097; em[2157] = 8; em[2158] = 0; /* 2156: pointer.func */
    em[2159] = 8884097; em[2160] = 8; em[2161] = 0; /* 2159: pointer.func */
    em[2162] = 8884097; em[2163] = 8; em[2164] = 0; /* 2162: pointer.func */
    em[2165] = 8884097; em[2166] = 8; em[2167] = 0; /* 2165: pointer.func */
    em[2168] = 8884097; em[2169] = 8; em[2170] = 0; /* 2168: pointer.func */
    em[2171] = 8884097; em[2172] = 8; em[2173] = 0; /* 2171: pointer.func */
    em[2174] = 8884097; em[2175] = 8; em[2176] = 0; /* 2174: pointer.func */
    em[2177] = 8884097; em[2178] = 8; em[2179] = 0; /* 2177: pointer.func */
    em[2180] = 8884097; em[2181] = 8; em[2182] = 0; /* 2180: pointer.func */
    em[2183] = 8884097; em[2184] = 8; em[2185] = 0; /* 2183: pointer.func */
    em[2186] = 0; em[2187] = 24; em[2188] = 1; /* 2186: struct.bignum_st */
    	em[2189] = 2191; em[2190] = 0; 
    em[2191] = 8884099; em[2192] = 8; em[2193] = 2; /* 2191: pointer_to_array_of_pointers_to_stack */
    	em[2194] = 1990; em[2195] = 0; 
    	em[2196] = 214; em[2197] = 12; 
    em[2198] = 8884097; em[2199] = 8; em[2200] = 0; /* 2198: pointer.func */
    em[2201] = 1; em[2202] = 8; em[2203] = 1; /* 2201: pointer.struct.ec_extra_data_st */
    	em[2204] = 2206; em[2205] = 0; 
    em[2206] = 0; em[2207] = 40; em[2208] = 5; /* 2206: struct.ec_extra_data_st */
    	em[2209] = 2201; em[2210] = 0; 
    	em[2211] = 1964; em[2212] = 8; 
    	em[2213] = 1967; em[2214] = 16; 
    	em[2215] = 1970; em[2216] = 24; 
    	em[2217] = 1970; em[2218] = 32; 
    em[2219] = 1; em[2220] = 8; em[2221] = 1; /* 2219: pointer.struct.ec_extra_data_st */
    	em[2222] = 2206; em[2223] = 0; 
    em[2224] = 8884097; em[2225] = 8; em[2226] = 0; /* 2224: pointer.func */
    em[2227] = 8884097; em[2228] = 8; em[2229] = 0; /* 2227: pointer.func */
    em[2230] = 8884097; em[2231] = 8; em[2232] = 0; /* 2230: pointer.func */
    em[2233] = 8884097; em[2234] = 8; em[2235] = 0; /* 2233: pointer.func */
    em[2236] = 8884097; em[2237] = 8; em[2238] = 0; /* 2236: pointer.func */
    em[2239] = 8884097; em[2240] = 8; em[2241] = 0; /* 2239: pointer.func */
    em[2242] = 0; em[2243] = 16; em[2244] = 1; /* 2242: struct.crypto_threadid_st */
    	em[2245] = 1964; em[2246] = 0; 
    em[2247] = 8884097; em[2248] = 8; em[2249] = 0; /* 2247: pointer.func */
    em[2250] = 1; em[2251] = 8; em[2252] = 1; /* 2250: pointer.struct.dh_method */
    	em[2253] = 2255; em[2254] = 0; 
    em[2255] = 0; em[2256] = 72; em[2257] = 8; /* 2255: struct.dh_method */
    	em[2258] = 26; em[2259] = 0; 
    	em[2260] = 2274; em[2261] = 8; 
    	em[2262] = 2277; em[2263] = 16; 
    	em[2264] = 2280; em[2265] = 24; 
    	em[2266] = 2274; em[2267] = 32; 
    	em[2268] = 2274; em[2269] = 40; 
    	em[2270] = 92; em[2271] = 56; 
    	em[2272] = 2283; em[2273] = 64; 
    em[2274] = 8884097; em[2275] = 8; em[2276] = 0; /* 2274: pointer.func */
    em[2277] = 8884097; em[2278] = 8; em[2279] = 0; /* 2277: pointer.func */
    em[2280] = 8884097; em[2281] = 8; em[2282] = 0; /* 2280: pointer.func */
    em[2283] = 8884097; em[2284] = 8; em[2285] = 0; /* 2283: pointer.func */
    em[2286] = 8884097; em[2287] = 8; em[2288] = 0; /* 2286: pointer.func */
    em[2289] = 8884097; em[2290] = 8; em[2291] = 0; /* 2289: pointer.func */
    em[2292] = 0; em[2293] = 48; em[2294] = 6; /* 2292: struct.rand_meth_st */
    	em[2295] = 2307; em[2296] = 0; 
    	em[2297] = 2310; em[2298] = 8; 
    	em[2299] = 2313; em[2300] = 16; 
    	em[2301] = 2233; em[2302] = 24; 
    	em[2303] = 2310; em[2304] = 32; 
    	em[2305] = 2227; em[2306] = 40; 
    em[2307] = 8884097; em[2308] = 8; em[2309] = 0; /* 2307: pointer.func */
    em[2310] = 8884097; em[2311] = 8; em[2312] = 0; /* 2310: pointer.func */
    em[2313] = 8884097; em[2314] = 8; em[2315] = 0; /* 2313: pointer.func */
    em[2316] = 1; em[2317] = 8; em[2318] = 1; /* 2316: pointer.struct.engine_st */
    	em[2319] = 2321; em[2320] = 0; 
    em[2321] = 0; em[2322] = 216; em[2323] = 24; /* 2321: struct.engine_st */
    	em[2324] = 26; em[2325] = 0; 
    	em[2326] = 26; em[2327] = 8; 
    	em[2328] = 2372; em[2329] = 16; 
    	em[2330] = 2424; em[2331] = 24; 
    	em[2332] = 2250; em[2333] = 32; 
    	em[2334] = 2472; em[2335] = 40; 
    	em[2336] = 2489; em[2337] = 48; 
    	em[2338] = 2510; em[2339] = 56; 
    	em[2340] = 2515; em[2341] = 64; 
    	em[2342] = 2224; em[2343] = 72; 
    	em[2344] = 2523; em[2345] = 80; 
    	em[2346] = 2526; em[2347] = 88; 
    	em[2348] = 2529; em[2349] = 96; 
    	em[2350] = 2532; em[2351] = 104; 
    	em[2352] = 2532; em[2353] = 112; 
    	em[2354] = 2532; em[2355] = 120; 
    	em[2356] = 2535; em[2357] = 128; 
    	em[2358] = 2538; em[2359] = 136; 
    	em[2360] = 2538; em[2361] = 144; 
    	em[2362] = 2541; em[2363] = 152; 
    	em[2364] = 2544; em[2365] = 160; 
    	em[2366] = 2556; em[2367] = 184; 
    	em[2368] = 2570; em[2369] = 200; 
    	em[2370] = 2570; em[2371] = 208; 
    em[2372] = 1; em[2373] = 8; em[2374] = 1; /* 2372: pointer.struct.rsa_meth_st */
    	em[2375] = 2377; em[2376] = 0; 
    em[2377] = 0; em[2378] = 112; em[2379] = 13; /* 2377: struct.rsa_meth_st */
    	em[2380] = 26; em[2381] = 0; 
    	em[2382] = 2406; em[2383] = 8; 
    	em[2384] = 2406; em[2385] = 16; 
    	em[2386] = 2406; em[2387] = 24; 
    	em[2388] = 2406; em[2389] = 32; 
    	em[2390] = 2409; em[2391] = 40; 
    	em[2392] = 2412; em[2393] = 48; 
    	em[2394] = 2286; em[2395] = 56; 
    	em[2396] = 2286; em[2397] = 64; 
    	em[2398] = 92; em[2399] = 80; 
    	em[2400] = 2415; em[2401] = 88; 
    	em[2402] = 2418; em[2403] = 96; 
    	em[2404] = 2421; em[2405] = 104; 
    em[2406] = 8884097; em[2407] = 8; em[2408] = 0; /* 2406: pointer.func */
    em[2409] = 8884097; em[2410] = 8; em[2411] = 0; /* 2409: pointer.func */
    em[2412] = 8884097; em[2413] = 8; em[2414] = 0; /* 2412: pointer.func */
    em[2415] = 8884097; em[2416] = 8; em[2417] = 0; /* 2415: pointer.func */
    em[2418] = 8884097; em[2419] = 8; em[2420] = 0; /* 2418: pointer.func */
    em[2421] = 8884097; em[2422] = 8; em[2423] = 0; /* 2421: pointer.func */
    em[2424] = 1; em[2425] = 8; em[2426] = 1; /* 2424: pointer.struct.dsa_method */
    	em[2427] = 2429; em[2428] = 0; 
    em[2429] = 0; em[2430] = 96; em[2431] = 11; /* 2429: struct.dsa_method */
    	em[2432] = 26; em[2433] = 0; 
    	em[2434] = 2454; em[2435] = 8; 
    	em[2436] = 2457; em[2437] = 16; 
    	em[2438] = 2460; em[2439] = 24; 
    	em[2440] = 2463; em[2441] = 32; 
    	em[2442] = 2247; em[2443] = 40; 
    	em[2444] = 2466; em[2445] = 48; 
    	em[2446] = 2466; em[2447] = 56; 
    	em[2448] = 92; em[2449] = 72; 
    	em[2450] = 2469; em[2451] = 80; 
    	em[2452] = 2466; em[2453] = 88; 
    em[2454] = 8884097; em[2455] = 8; em[2456] = 0; /* 2454: pointer.func */
    em[2457] = 8884097; em[2458] = 8; em[2459] = 0; /* 2457: pointer.func */
    em[2460] = 8884097; em[2461] = 8; em[2462] = 0; /* 2460: pointer.func */
    em[2463] = 8884097; em[2464] = 8; em[2465] = 0; /* 2463: pointer.func */
    em[2466] = 8884097; em[2467] = 8; em[2468] = 0; /* 2466: pointer.func */
    em[2469] = 8884097; em[2470] = 8; em[2471] = 0; /* 2469: pointer.func */
    em[2472] = 1; em[2473] = 8; em[2474] = 1; /* 2472: pointer.struct.ecdh_method */
    	em[2475] = 2477; em[2476] = 0; 
    em[2477] = 0; em[2478] = 32; em[2479] = 3; /* 2477: struct.ecdh_method */
    	em[2480] = 26; em[2481] = 0; 
    	em[2482] = 2486; em[2483] = 8; 
    	em[2484] = 92; em[2485] = 24; 
    em[2486] = 8884097; em[2487] = 8; em[2488] = 0; /* 2486: pointer.func */
    em[2489] = 1; em[2490] = 8; em[2491] = 1; /* 2489: pointer.struct.ecdsa_method */
    	em[2492] = 2494; em[2493] = 0; 
    em[2494] = 0; em[2495] = 48; em[2496] = 5; /* 2494: struct.ecdsa_method */
    	em[2497] = 26; em[2498] = 0; 
    	em[2499] = 2239; em[2500] = 8; 
    	em[2501] = 2236; em[2502] = 16; 
    	em[2503] = 2507; em[2504] = 24; 
    	em[2505] = 92; em[2506] = 40; 
    em[2507] = 8884097; em[2508] = 8; em[2509] = 0; /* 2507: pointer.func */
    em[2510] = 1; em[2511] = 8; em[2512] = 1; /* 2510: pointer.struct.rand_meth_st */
    	em[2513] = 2292; em[2514] = 0; 
    em[2515] = 1; em[2516] = 8; em[2517] = 1; /* 2515: pointer.struct.store_method_st */
    	em[2518] = 2520; em[2519] = 0; 
    em[2520] = 0; em[2521] = 0; em[2522] = 0; /* 2520: struct.store_method_st */
    em[2523] = 8884097; em[2524] = 8; em[2525] = 0; /* 2523: pointer.func */
    em[2526] = 8884097; em[2527] = 8; em[2528] = 0; /* 2526: pointer.func */
    em[2529] = 8884097; em[2530] = 8; em[2531] = 0; /* 2529: pointer.func */
    em[2532] = 8884097; em[2533] = 8; em[2534] = 0; /* 2532: pointer.func */
    em[2535] = 8884097; em[2536] = 8; em[2537] = 0; /* 2535: pointer.func */
    em[2538] = 8884097; em[2539] = 8; em[2540] = 0; /* 2538: pointer.func */
    em[2541] = 8884097; em[2542] = 8; em[2543] = 0; /* 2541: pointer.func */
    em[2544] = 1; em[2545] = 8; em[2546] = 1; /* 2544: pointer.struct.ENGINE_CMD_DEFN_st */
    	em[2547] = 2549; em[2548] = 0; 
    em[2549] = 0; em[2550] = 32; em[2551] = 2; /* 2549: struct.ENGINE_CMD_DEFN_st */
    	em[2552] = 26; em[2553] = 8; 
    	em[2554] = 26; em[2555] = 16; 
    em[2556] = 0; em[2557] = 32; em[2558] = 2; /* 2556: struct.crypto_ex_data_st_fake */
    	em[2559] = 2563; em[2560] = 8; 
    	em[2561] = 217; em[2562] = 24; 
    em[2563] = 8884099; em[2564] = 8; em[2565] = 2; /* 2563: pointer_to_array_of_pointers_to_stack */
    	em[2566] = 1964; em[2567] = 0; 
    	em[2568] = 214; em[2569] = 20; 
    em[2570] = 1; em[2571] = 8; em[2572] = 1; /* 2570: pointer.struct.engine_st */
    	em[2573] = 2321; em[2574] = 0; 
    em[2575] = 8884097; em[2576] = 8; em[2577] = 0; /* 2575: pointer.func */
    em[2578] = 8884097; em[2579] = 8; em[2580] = 0; /* 2578: pointer.func */
    em[2581] = 8884097; em[2582] = 8; em[2583] = 0; /* 2581: pointer.func */
    em[2584] = 1; em[2585] = 8; em[2586] = 1; /* 2584: pointer.struct.asn1_string_st */
    	em[2587] = 1481; em[2588] = 0; 
    em[2589] = 8884097; em[2590] = 8; em[2591] = 0; /* 2589: pointer.func */
    em[2592] = 8884097; em[2593] = 8; em[2594] = 0; /* 2592: pointer.func */
    em[2595] = 8884097; em[2596] = 8; em[2597] = 0; /* 2595: pointer.func */
    em[2598] = 8884097; em[2599] = 8; em[2600] = 0; /* 2598: pointer.func */
    em[2601] = 8884097; em[2602] = 8; em[2603] = 0; /* 2601: pointer.func */
    em[2604] = 1; em[2605] = 8; em[2606] = 1; /* 2604: pointer.struct.dh_method */
    	em[2607] = 2609; em[2608] = 0; 
    em[2609] = 0; em[2610] = 72; em[2611] = 8; /* 2609: struct.dh_method */
    	em[2612] = 26; em[2613] = 0; 
    	em[2614] = 2628; em[2615] = 8; 
    	em[2616] = 2631; em[2617] = 16; 
    	em[2618] = 2592; em[2619] = 24; 
    	em[2620] = 2628; em[2621] = 32; 
    	em[2622] = 2628; em[2623] = 40; 
    	em[2624] = 92; em[2625] = 56; 
    	em[2626] = 2634; em[2627] = 64; 
    em[2628] = 8884097; em[2629] = 8; em[2630] = 0; /* 2628: pointer.func */
    em[2631] = 8884097; em[2632] = 8; em[2633] = 0; /* 2631: pointer.func */
    em[2634] = 8884097; em[2635] = 8; em[2636] = 0; /* 2634: pointer.func */
    em[2637] = 8884097; em[2638] = 8; em[2639] = 0; /* 2637: pointer.func */
    em[2640] = 8884097; em[2641] = 8; em[2642] = 0; /* 2640: pointer.func */
    em[2643] = 8884097; em[2644] = 8; em[2645] = 0; /* 2643: pointer.func */
    em[2646] = 0; em[2647] = 208; em[2648] = 24; /* 2646: struct.evp_pkey_asn1_method_st */
    	em[2649] = 92; em[2650] = 16; 
    	em[2651] = 92; em[2652] = 24; 
    	em[2653] = 2578; em[2654] = 32; 
    	em[2655] = 2643; em[2656] = 40; 
    	em[2657] = 2697; em[2658] = 48; 
    	em[2659] = 2700; em[2660] = 56; 
    	em[2661] = 2703; em[2662] = 64; 
    	em[2663] = 2289; em[2664] = 72; 
    	em[2665] = 2700; em[2666] = 80; 
    	em[2667] = 2706; em[2668] = 88; 
    	em[2669] = 2706; em[2670] = 96; 
    	em[2671] = 2637; em[2672] = 104; 
    	em[2673] = 2640; em[2674] = 112; 
    	em[2675] = 2706; em[2676] = 120; 
    	em[2677] = 2709; em[2678] = 128; 
    	em[2679] = 2697; em[2680] = 136; 
    	em[2681] = 2700; em[2682] = 144; 
    	em[2683] = 2601; em[2684] = 152; 
    	em[2685] = 2712; em[2686] = 160; 
    	em[2687] = 2715; em[2688] = 168; 
    	em[2689] = 2637; em[2690] = 176; 
    	em[2691] = 2640; em[2692] = 184; 
    	em[2693] = 2595; em[2694] = 192; 
    	em[2695] = 2589; em[2696] = 200; 
    em[2697] = 8884097; em[2698] = 8; em[2699] = 0; /* 2697: pointer.func */
    em[2700] = 8884097; em[2701] = 8; em[2702] = 0; /* 2700: pointer.func */
    em[2703] = 8884097; em[2704] = 8; em[2705] = 0; /* 2703: pointer.func */
    em[2706] = 8884097; em[2707] = 8; em[2708] = 0; /* 2706: pointer.func */
    em[2709] = 8884097; em[2710] = 8; em[2711] = 0; /* 2709: pointer.func */
    em[2712] = 8884097; em[2713] = 8; em[2714] = 0; /* 2712: pointer.func */
    em[2715] = 8884097; em[2716] = 8; em[2717] = 0; /* 2715: pointer.func */
    em[2718] = 8884097; em[2719] = 8; em[2720] = 0; /* 2718: pointer.func */
    em[2721] = 1; em[2722] = 8; em[2723] = 1; /* 2721: pointer.struct.evp_pkey_asn1_method_st */
    	em[2724] = 2646; em[2725] = 0; 
    em[2726] = 0; em[2727] = 56; em[2728] = 4; /* 2726: struct.evp_pkey_st */
    	em[2729] = 2721; em[2730] = 16; 
    	em[2731] = 2737; em[2732] = 24; 
    	em[2733] = 2742; em[2734] = 32; 
    	em[2735] = 1917; em[2736] = 48; 
    em[2737] = 1; em[2738] = 8; em[2739] = 1; /* 2737: pointer.struct.engine_st */
    	em[2740] = 2321; em[2741] = 0; 
    em[2742] = 8884101; em[2743] = 8; em[2744] = 6; /* 2742: union.union_of_evp_pkey_st */
    	em[2745] = 1964; em[2746] = 0; 
    	em[2747] = 2757; em[2748] = 6; 
    	em[2749] = 2954; em[2750] = 116; 
    	em[2751] = 3085; em[2752] = 28; 
    	em[2753] = 3162; em[2754] = 408; 
    	em[2755] = 214; em[2756] = 0; 
    em[2757] = 1; em[2758] = 8; em[2759] = 1; /* 2757: pointer.struct.rsa_st */
    	em[2760] = 2762; em[2761] = 0; 
    em[2762] = 0; em[2763] = 168; em[2764] = 17; /* 2762: struct.rsa_st */
    	em[2765] = 2799; em[2766] = 16; 
    	em[2767] = 2848; em[2768] = 24; 
    	em[2769] = 2853; em[2770] = 32; 
    	em[2771] = 2853; em[2772] = 40; 
    	em[2773] = 2853; em[2774] = 48; 
    	em[2775] = 2853; em[2776] = 56; 
    	em[2777] = 2853; em[2778] = 64; 
    	em[2779] = 2853; em[2780] = 72; 
    	em[2781] = 2853; em[2782] = 80; 
    	em[2783] = 2853; em[2784] = 88; 
    	em[2785] = 2870; em[2786] = 96; 
    	em[2787] = 2884; em[2788] = 120; 
    	em[2789] = 2884; em[2790] = 128; 
    	em[2791] = 2884; em[2792] = 136; 
    	em[2793] = 92; em[2794] = 144; 
    	em[2795] = 2898; em[2796] = 152; 
    	em[2797] = 2898; em[2798] = 160; 
    em[2799] = 1; em[2800] = 8; em[2801] = 1; /* 2799: pointer.struct.rsa_meth_st */
    	em[2802] = 2804; em[2803] = 0; 
    em[2804] = 0; em[2805] = 112; em[2806] = 13; /* 2804: struct.rsa_meth_st */
    	em[2807] = 26; em[2808] = 0; 
    	em[2809] = 2833; em[2810] = 8; 
    	em[2811] = 2833; em[2812] = 16; 
    	em[2813] = 2833; em[2814] = 24; 
    	em[2815] = 2833; em[2816] = 32; 
    	em[2817] = 2836; em[2818] = 40; 
    	em[2819] = 2575; em[2820] = 48; 
    	em[2821] = 2839; em[2822] = 56; 
    	em[2823] = 2839; em[2824] = 64; 
    	em[2825] = 92; em[2826] = 80; 
    	em[2827] = 2842; em[2828] = 88; 
    	em[2829] = 2581; em[2830] = 96; 
    	em[2831] = 2845; em[2832] = 104; 
    em[2833] = 8884097; em[2834] = 8; em[2835] = 0; /* 2833: pointer.func */
    em[2836] = 8884097; em[2837] = 8; em[2838] = 0; /* 2836: pointer.func */
    em[2839] = 8884097; em[2840] = 8; em[2841] = 0; /* 2839: pointer.func */
    em[2842] = 8884097; em[2843] = 8; em[2844] = 0; /* 2842: pointer.func */
    em[2845] = 8884097; em[2846] = 8; em[2847] = 0; /* 2845: pointer.func */
    em[2848] = 1; em[2849] = 8; em[2850] = 1; /* 2848: pointer.struct.engine_st */
    	em[2851] = 2321; em[2852] = 0; 
    em[2853] = 1; em[2854] = 8; em[2855] = 1; /* 2853: pointer.struct.bignum_st */
    	em[2856] = 2858; em[2857] = 0; 
    em[2858] = 0; em[2859] = 24; em[2860] = 1; /* 2858: struct.bignum_st */
    	em[2861] = 2863; em[2862] = 0; 
    em[2863] = 8884099; em[2864] = 8; em[2865] = 2; /* 2863: pointer_to_array_of_pointers_to_stack */
    	em[2866] = 1990; em[2867] = 0; 
    	em[2868] = 214; em[2869] = 12; 
    em[2870] = 0; em[2871] = 32; em[2872] = 2; /* 2870: struct.crypto_ex_data_st_fake */
    	em[2873] = 2877; em[2874] = 8; 
    	em[2875] = 217; em[2876] = 24; 
    em[2877] = 8884099; em[2878] = 8; em[2879] = 2; /* 2877: pointer_to_array_of_pointers_to_stack */
    	em[2880] = 1964; em[2881] = 0; 
    	em[2882] = 214; em[2883] = 20; 
    em[2884] = 1; em[2885] = 8; em[2886] = 1; /* 2884: pointer.struct.bn_mont_ctx_st */
    	em[2887] = 2889; em[2888] = 0; 
    em[2889] = 0; em[2890] = 96; em[2891] = 3; /* 2889: struct.bn_mont_ctx_st */
    	em[2892] = 2858; em[2893] = 8; 
    	em[2894] = 2858; em[2895] = 32; 
    	em[2896] = 2858; em[2897] = 56; 
    em[2898] = 1; em[2899] = 8; em[2900] = 1; /* 2898: pointer.struct.bn_blinding_st */
    	em[2901] = 2903; em[2902] = 0; 
    em[2903] = 0; em[2904] = 88; em[2905] = 7; /* 2903: struct.bn_blinding_st */
    	em[2906] = 2920; em[2907] = 0; 
    	em[2908] = 2920; em[2909] = 8; 
    	em[2910] = 2920; em[2911] = 16; 
    	em[2912] = 2920; em[2913] = 24; 
    	em[2914] = 2242; em[2915] = 40; 
    	em[2916] = 2937; em[2917] = 72; 
    	em[2918] = 2951; em[2919] = 80; 
    em[2920] = 1; em[2921] = 8; em[2922] = 1; /* 2920: pointer.struct.bignum_st */
    	em[2923] = 2925; em[2924] = 0; 
    em[2925] = 0; em[2926] = 24; em[2927] = 1; /* 2925: struct.bignum_st */
    	em[2928] = 2930; em[2929] = 0; 
    em[2930] = 8884099; em[2931] = 8; em[2932] = 2; /* 2930: pointer_to_array_of_pointers_to_stack */
    	em[2933] = 1990; em[2934] = 0; 
    	em[2935] = 214; em[2936] = 12; 
    em[2937] = 1; em[2938] = 8; em[2939] = 1; /* 2937: pointer.struct.bn_mont_ctx_st */
    	em[2940] = 2942; em[2941] = 0; 
    em[2942] = 0; em[2943] = 96; em[2944] = 3; /* 2942: struct.bn_mont_ctx_st */
    	em[2945] = 2925; em[2946] = 8; 
    	em[2947] = 2925; em[2948] = 32; 
    	em[2949] = 2925; em[2950] = 56; 
    em[2951] = 8884097; em[2952] = 8; em[2953] = 0; /* 2951: pointer.func */
    em[2954] = 1; em[2955] = 8; em[2956] = 1; /* 2954: pointer.struct.dsa_st */
    	em[2957] = 2959; em[2958] = 0; 
    em[2959] = 0; em[2960] = 136; em[2961] = 11; /* 2959: struct.dsa_st */
    	em[2962] = 2984; em[2963] = 24; 
    	em[2964] = 2984; em[2965] = 32; 
    	em[2966] = 2984; em[2967] = 40; 
    	em[2968] = 2984; em[2969] = 48; 
    	em[2970] = 2984; em[2971] = 56; 
    	em[2972] = 2984; em[2973] = 64; 
    	em[2974] = 2984; em[2975] = 72; 
    	em[2976] = 3001; em[2977] = 88; 
    	em[2978] = 3015; em[2979] = 104; 
    	em[2980] = 3029; em[2981] = 120; 
    	em[2982] = 3080; em[2983] = 128; 
    em[2984] = 1; em[2985] = 8; em[2986] = 1; /* 2984: pointer.struct.bignum_st */
    	em[2987] = 2989; em[2988] = 0; 
    em[2989] = 0; em[2990] = 24; em[2991] = 1; /* 2989: struct.bignum_st */
    	em[2992] = 2994; em[2993] = 0; 
    em[2994] = 8884099; em[2995] = 8; em[2996] = 2; /* 2994: pointer_to_array_of_pointers_to_stack */
    	em[2997] = 1990; em[2998] = 0; 
    	em[2999] = 214; em[3000] = 12; 
    em[3001] = 1; em[3002] = 8; em[3003] = 1; /* 3001: pointer.struct.bn_mont_ctx_st */
    	em[3004] = 3006; em[3005] = 0; 
    em[3006] = 0; em[3007] = 96; em[3008] = 3; /* 3006: struct.bn_mont_ctx_st */
    	em[3009] = 2989; em[3010] = 8; 
    	em[3011] = 2989; em[3012] = 32; 
    	em[3013] = 2989; em[3014] = 56; 
    em[3015] = 0; em[3016] = 32; em[3017] = 2; /* 3015: struct.crypto_ex_data_st_fake */
    	em[3018] = 3022; em[3019] = 8; 
    	em[3020] = 217; em[3021] = 24; 
    em[3022] = 8884099; em[3023] = 8; em[3024] = 2; /* 3022: pointer_to_array_of_pointers_to_stack */
    	em[3025] = 1964; em[3026] = 0; 
    	em[3027] = 214; em[3028] = 20; 
    em[3029] = 1; em[3030] = 8; em[3031] = 1; /* 3029: pointer.struct.dsa_method */
    	em[3032] = 3034; em[3033] = 0; 
    em[3034] = 0; em[3035] = 96; em[3036] = 11; /* 3034: struct.dsa_method */
    	em[3037] = 26; em[3038] = 0; 
    	em[3039] = 3059; em[3040] = 8; 
    	em[3041] = 3062; em[3042] = 16; 
    	em[3043] = 3065; em[3044] = 24; 
    	em[3045] = 3068; em[3046] = 32; 
    	em[3047] = 3071; em[3048] = 40; 
    	em[3049] = 3074; em[3050] = 48; 
    	em[3051] = 3074; em[3052] = 56; 
    	em[3053] = 92; em[3054] = 72; 
    	em[3055] = 3077; em[3056] = 80; 
    	em[3057] = 3074; em[3058] = 88; 
    em[3059] = 8884097; em[3060] = 8; em[3061] = 0; /* 3059: pointer.func */
    em[3062] = 8884097; em[3063] = 8; em[3064] = 0; /* 3062: pointer.func */
    em[3065] = 8884097; em[3066] = 8; em[3067] = 0; /* 3065: pointer.func */
    em[3068] = 8884097; em[3069] = 8; em[3070] = 0; /* 3068: pointer.func */
    em[3071] = 8884097; em[3072] = 8; em[3073] = 0; /* 3071: pointer.func */
    em[3074] = 8884097; em[3075] = 8; em[3076] = 0; /* 3074: pointer.func */
    em[3077] = 8884097; em[3078] = 8; em[3079] = 0; /* 3077: pointer.func */
    em[3080] = 1; em[3081] = 8; em[3082] = 1; /* 3080: pointer.struct.engine_st */
    	em[3083] = 2321; em[3084] = 0; 
    em[3085] = 1; em[3086] = 8; em[3087] = 1; /* 3085: pointer.struct.dh_st */
    	em[3088] = 3090; em[3089] = 0; 
    em[3090] = 0; em[3091] = 144; em[3092] = 12; /* 3090: struct.dh_st */
    	em[3093] = 3117; em[3094] = 8; 
    	em[3095] = 3117; em[3096] = 16; 
    	em[3097] = 3117; em[3098] = 32; 
    	em[3099] = 3117; em[3100] = 40; 
    	em[3101] = 3134; em[3102] = 56; 
    	em[3103] = 3117; em[3104] = 64; 
    	em[3105] = 3117; em[3106] = 72; 
    	em[3107] = 107; em[3108] = 80; 
    	em[3109] = 3117; em[3110] = 96; 
    	em[3111] = 3148; em[3112] = 112; 
    	em[3113] = 2604; em[3114] = 128; 
    	em[3115] = 2316; em[3116] = 136; 
    em[3117] = 1; em[3118] = 8; em[3119] = 1; /* 3117: pointer.struct.bignum_st */
    	em[3120] = 3122; em[3121] = 0; 
    em[3122] = 0; em[3123] = 24; em[3124] = 1; /* 3122: struct.bignum_st */
    	em[3125] = 3127; em[3126] = 0; 
    em[3127] = 8884099; em[3128] = 8; em[3129] = 2; /* 3127: pointer_to_array_of_pointers_to_stack */
    	em[3130] = 1990; em[3131] = 0; 
    	em[3132] = 214; em[3133] = 12; 
    em[3134] = 1; em[3135] = 8; em[3136] = 1; /* 3134: pointer.struct.bn_mont_ctx_st */
    	em[3137] = 3139; em[3138] = 0; 
    em[3139] = 0; em[3140] = 96; em[3141] = 3; /* 3139: struct.bn_mont_ctx_st */
    	em[3142] = 3122; em[3143] = 8; 
    	em[3144] = 3122; em[3145] = 32; 
    	em[3146] = 3122; em[3147] = 56; 
    em[3148] = 0; em[3149] = 32; em[3150] = 2; /* 3148: struct.crypto_ex_data_st_fake */
    	em[3151] = 3155; em[3152] = 8; 
    	em[3153] = 217; em[3154] = 24; 
    em[3155] = 8884099; em[3156] = 8; em[3157] = 2; /* 3155: pointer_to_array_of_pointers_to_stack */
    	em[3158] = 1964; em[3159] = 0; 
    	em[3160] = 214; em[3161] = 20; 
    em[3162] = 1; em[3163] = 8; em[3164] = 1; /* 3162: pointer.struct.ec_key_st */
    	em[3165] = 3167; em[3166] = 0; 
    em[3167] = 0; em[3168] = 56; em[3169] = 4; /* 3167: struct.ec_key_st */
    	em[3170] = 3178; em[3171] = 8; 
    	em[3172] = 1998; em[3173] = 16; 
    	em[3174] = 1993; em[3175] = 24; 
    	em[3176] = 1973; em[3177] = 48; 
    em[3178] = 1; em[3179] = 8; em[3180] = 1; /* 3178: pointer.struct.ec_group_st */
    	em[3181] = 3183; em[3182] = 0; 
    em[3183] = 0; em[3184] = 232; em[3185] = 12; /* 3183: struct.ec_group_st */
    	em[3186] = 3210; em[3187] = 0; 
    	em[3188] = 3373; em[3189] = 8; 
    	em[3190] = 3378; em[3191] = 16; 
    	em[3192] = 3378; em[3193] = 40; 
    	em[3194] = 107; em[3195] = 80; 
    	em[3196] = 2219; em[3197] = 96; 
    	em[3198] = 3378; em[3199] = 104; 
    	em[3200] = 3378; em[3201] = 152; 
    	em[3202] = 3378; em[3203] = 176; 
    	em[3204] = 1964; em[3205] = 208; 
    	em[3206] = 1964; em[3207] = 216; 
    	em[3208] = 2198; em[3209] = 224; 
    em[3210] = 1; em[3211] = 8; em[3212] = 1; /* 3210: pointer.struct.ec_method_st */
    	em[3213] = 3215; em[3214] = 0; 
    em[3215] = 0; em[3216] = 304; em[3217] = 37; /* 3215: struct.ec_method_st */
    	em[3218] = 3292; em[3219] = 8; 
    	em[3220] = 3295; em[3221] = 16; 
    	em[3222] = 3295; em[3223] = 24; 
    	em[3224] = 3298; em[3225] = 32; 
    	em[3226] = 3301; em[3227] = 40; 
    	em[3228] = 3304; em[3229] = 48; 
    	em[3230] = 3307; em[3231] = 56; 
    	em[3232] = 2598; em[3233] = 64; 
    	em[3234] = 2718; em[3235] = 72; 
    	em[3236] = 3310; em[3237] = 80; 
    	em[3238] = 3310; em[3239] = 88; 
    	em[3240] = 3313; em[3241] = 96; 
    	em[3242] = 3316; em[3243] = 104; 
    	em[3244] = 3319; em[3245] = 112; 
    	em[3246] = 3322; em[3247] = 120; 
    	em[3248] = 2230; em[3249] = 128; 
    	em[3250] = 3325; em[3251] = 136; 
    	em[3252] = 3328; em[3253] = 144; 
    	em[3254] = 3331; em[3255] = 152; 
    	em[3256] = 3334; em[3257] = 160; 
    	em[3258] = 3337; em[3259] = 168; 
    	em[3260] = 3340; em[3261] = 176; 
    	em[3262] = 3343; em[3263] = 184; 
    	em[3264] = 3346; em[3265] = 192; 
    	em[3266] = 3349; em[3267] = 200; 
    	em[3268] = 3352; em[3269] = 208; 
    	em[3270] = 3343; em[3271] = 216; 
    	em[3272] = 3355; em[3273] = 224; 
    	em[3274] = 3358; em[3275] = 232; 
    	em[3276] = 3361; em[3277] = 240; 
    	em[3278] = 3307; em[3279] = 248; 
    	em[3280] = 3364; em[3281] = 256; 
    	em[3282] = 3367; em[3283] = 264; 
    	em[3284] = 3364; em[3285] = 272; 
    	em[3286] = 3367; em[3287] = 280; 
    	em[3288] = 3367; em[3289] = 288; 
    	em[3290] = 3370; em[3291] = 296; 
    em[3292] = 8884097; em[3293] = 8; em[3294] = 0; /* 3292: pointer.func */
    em[3295] = 8884097; em[3296] = 8; em[3297] = 0; /* 3295: pointer.func */
    em[3298] = 8884097; em[3299] = 8; em[3300] = 0; /* 3298: pointer.func */
    em[3301] = 8884097; em[3302] = 8; em[3303] = 0; /* 3301: pointer.func */
    em[3304] = 8884097; em[3305] = 8; em[3306] = 0; /* 3304: pointer.func */
    em[3307] = 8884097; em[3308] = 8; em[3309] = 0; /* 3307: pointer.func */
    em[3310] = 8884097; em[3311] = 8; em[3312] = 0; /* 3310: pointer.func */
    em[3313] = 8884097; em[3314] = 8; em[3315] = 0; /* 3313: pointer.func */
    em[3316] = 8884097; em[3317] = 8; em[3318] = 0; /* 3316: pointer.func */
    em[3319] = 8884097; em[3320] = 8; em[3321] = 0; /* 3319: pointer.func */
    em[3322] = 8884097; em[3323] = 8; em[3324] = 0; /* 3322: pointer.func */
    em[3325] = 8884097; em[3326] = 8; em[3327] = 0; /* 3325: pointer.func */
    em[3328] = 8884097; em[3329] = 8; em[3330] = 0; /* 3328: pointer.func */
    em[3331] = 8884097; em[3332] = 8; em[3333] = 0; /* 3331: pointer.func */
    em[3334] = 8884097; em[3335] = 8; em[3336] = 0; /* 3334: pointer.func */
    em[3337] = 8884097; em[3338] = 8; em[3339] = 0; /* 3337: pointer.func */
    em[3340] = 8884097; em[3341] = 8; em[3342] = 0; /* 3340: pointer.func */
    em[3343] = 8884097; em[3344] = 8; em[3345] = 0; /* 3343: pointer.func */
    em[3346] = 8884097; em[3347] = 8; em[3348] = 0; /* 3346: pointer.func */
    em[3349] = 8884097; em[3350] = 8; em[3351] = 0; /* 3349: pointer.func */
    em[3352] = 8884097; em[3353] = 8; em[3354] = 0; /* 3352: pointer.func */
    em[3355] = 8884097; em[3356] = 8; em[3357] = 0; /* 3355: pointer.func */
    em[3358] = 8884097; em[3359] = 8; em[3360] = 0; /* 3358: pointer.func */
    em[3361] = 8884097; em[3362] = 8; em[3363] = 0; /* 3361: pointer.func */
    em[3364] = 8884097; em[3365] = 8; em[3366] = 0; /* 3364: pointer.func */
    em[3367] = 8884097; em[3368] = 8; em[3369] = 0; /* 3367: pointer.func */
    em[3370] = 8884097; em[3371] = 8; em[3372] = 0; /* 3370: pointer.func */
    em[3373] = 1; em[3374] = 8; em[3375] = 1; /* 3373: pointer.struct.ec_point_st */
    	em[3376] = 2003; em[3377] = 0; 
    em[3378] = 0; em[3379] = 24; em[3380] = 1; /* 3378: struct.bignum_st */
    	em[3381] = 3383; em[3382] = 0; 
    em[3383] = 8884099; em[3384] = 8; em[3385] = 2; /* 3383: pointer_to_array_of_pointers_to_stack */
    	em[3386] = 1990; em[3387] = 0; 
    	em[3388] = 214; em[3389] = 12; 
    em[3390] = 1; em[3391] = 8; em[3392] = 1; /* 3390: pointer.struct.evp_pkey_st */
    	em[3393] = 2726; em[3394] = 0; 
    em[3395] = 0; em[3396] = 24; em[3397] = 1; /* 3395: struct.asn1_string_st */
    	em[3398] = 107; em[3399] = 8; 
    em[3400] = 1; em[3401] = 8; em[3402] = 1; /* 3400: pointer.struct.X509_algor_st */
    	em[3403] = 5; em[3404] = 0; 
    em[3405] = 1; em[3406] = 8; em[3407] = 1; /* 3405: pointer.struct.AUTHORITY_KEYID_st */
    	em[3408] = 3410; em[3409] = 0; 
    em[3410] = 0; em[3411] = 24; em[3412] = 3; /* 3410: struct.AUTHORITY_KEYID_st */
    	em[3413] = 2584; em[3414] = 0; 
    	em[3415] = 1486; em[3416] = 8; 
    	em[3417] = 1476; em[3418] = 16; 
    em[3419] = 1; em[3420] = 8; em[3421] = 1; /* 3419: pointer.struct.asn1_string_st */
    	em[3422] = 3395; em[3423] = 0; 
    em[3424] = 0; em[3425] = 24; em[3426] = 3; /* 3424: struct.X509_pubkey_st */
    	em[3427] = 3400; em[3428] = 0; 
    	em[3429] = 3419; em[3430] = 8; 
    	em[3431] = 3390; em[3432] = 16; 
    em[3433] = 1; em[3434] = 8; em[3435] = 1; /* 3433: pointer.int */
    	em[3436] = 214; em[3437] = 0; 
    em[3438] = 0; em[3439] = 184; em[3440] = 12; /* 3438: struct.x509_st */
    	em[3441] = 3465; em[3442] = 0; 
    	em[3443] = 3500; em[3444] = 8; 
    	em[3445] = 1570; em[3446] = 16; 
    	em[3447] = 92; em[3448] = 32; 
    	em[3449] = 3580; em[3450] = 40; 
    	em[3451] = 286; em[3452] = 104; 
    	em[3453] = 3405; em[3454] = 112; 
    	em[3455] = 3594; em[3456] = 120; 
    	em[3457] = 1048; em[3458] = 128; 
    	em[3459] = 647; em[3460] = 136; 
    	em[3461] = 597; em[3462] = 144; 
    	em[3463] = 258; em[3464] = 176; 
    em[3465] = 1; em[3466] = 8; em[3467] = 1; /* 3465: pointer.struct.x509_cinf_st */
    	em[3468] = 3470; em[3469] = 0; 
    em[3470] = 0; em[3471] = 104; em[3472] = 11; /* 3470: struct.x509_cinf_st */
    	em[3473] = 3495; em[3474] = 0; 
    	em[3475] = 3495; em[3476] = 8; 
    	em[3477] = 3500; em[3478] = 16; 
    	em[3479] = 3505; em[3480] = 24; 
    	em[3481] = 3553; em[3482] = 32; 
    	em[3483] = 3505; em[3484] = 40; 
    	em[3485] = 3570; em[3486] = 48; 
    	em[3487] = 1570; em[3488] = 56; 
    	em[3489] = 1570; em[3490] = 64; 
    	em[3491] = 1520; em[3492] = 72; 
    	em[3493] = 3575; em[3494] = 80; 
    em[3495] = 1; em[3496] = 8; em[3497] = 1; /* 3495: pointer.struct.asn1_string_st */
    	em[3498] = 281; em[3499] = 0; 
    em[3500] = 1; em[3501] = 8; em[3502] = 1; /* 3500: pointer.struct.X509_algor_st */
    	em[3503] = 5; em[3504] = 0; 
    em[3505] = 1; em[3506] = 8; em[3507] = 1; /* 3505: pointer.struct.X509_name_st */
    	em[3508] = 3510; em[3509] = 0; 
    em[3510] = 0; em[3511] = 40; em[3512] = 3; /* 3510: struct.X509_name_st */
    	em[3513] = 3519; em[3514] = 0; 
    	em[3515] = 3543; em[3516] = 16; 
    	em[3517] = 107; em[3518] = 24; 
    em[3519] = 1; em[3520] = 8; em[3521] = 1; /* 3519: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[3522] = 3524; em[3523] = 0; 
    em[3524] = 0; em[3525] = 32; em[3526] = 2; /* 3524: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[3527] = 3531; em[3528] = 8; 
    	em[3529] = 217; em[3530] = 24; 
    em[3531] = 8884099; em[3532] = 8; em[3533] = 2; /* 3531: pointer_to_array_of_pointers_to_stack */
    	em[3534] = 3538; em[3535] = 0; 
    	em[3536] = 214; em[3537] = 20; 
    em[3538] = 0; em[3539] = 8; em[3540] = 1; /* 3538: pointer.X509_NAME_ENTRY */
    	em[3541] = 337; em[3542] = 0; 
    em[3543] = 1; em[3544] = 8; em[3545] = 1; /* 3543: pointer.struct.buf_mem_st */
    	em[3546] = 3548; em[3547] = 0; 
    em[3548] = 0; em[3549] = 24; em[3550] = 1; /* 3548: struct.buf_mem_st */
    	em[3551] = 92; em[3552] = 8; 
    em[3553] = 1; em[3554] = 8; em[3555] = 1; /* 3553: pointer.struct.X509_val_st */
    	em[3556] = 3558; em[3557] = 0; 
    em[3558] = 0; em[3559] = 16; em[3560] = 2; /* 3558: struct.X509_val_st */
    	em[3561] = 3565; em[3562] = 0; 
    	em[3563] = 3565; em[3564] = 8; 
    em[3565] = 1; em[3566] = 8; em[3567] = 1; /* 3565: pointer.struct.asn1_string_st */
    	em[3568] = 281; em[3569] = 0; 
    em[3570] = 1; em[3571] = 8; em[3572] = 1; /* 3570: pointer.struct.X509_pubkey_st */
    	em[3573] = 3424; em[3574] = 0; 
    em[3575] = 0; em[3576] = 24; em[3577] = 1; /* 3575: struct.ASN1_ENCODING_st */
    	em[3578] = 107; em[3579] = 0; 
    em[3580] = 0; em[3581] = 32; em[3582] = 2; /* 3580: struct.crypto_ex_data_st_fake */
    	em[3583] = 3587; em[3584] = 8; 
    	em[3585] = 217; em[3586] = 24; 
    em[3587] = 8884099; em[3588] = 8; em[3589] = 2; /* 3587: pointer_to_array_of_pointers_to_stack */
    	em[3590] = 1964; em[3591] = 0; 
    	em[3592] = 214; em[3593] = 20; 
    em[3594] = 1; em[3595] = 8; em[3596] = 1; /* 3594: pointer.struct.X509_POLICY_CACHE_st */
    	em[3597] = 1469; em[3598] = 0; 
    em[3599] = 0; em[3600] = 1; em[3601] = 0; /* 3599: char */
    em[3602] = 1; em[3603] = 8; em[3604] = 1; /* 3602: pointer.struct.x509_st */
    	em[3605] = 3438; em[3606] = 0; 
    args_addr->arg_entity_index[0] = 3602;
    args_addr->arg_entity_index[1] = 214;
    args_addr->arg_entity_index[2] = 3433;
    args_addr->arg_entity_index[3] = 3433;
    args_addr->ret_entity_index = 1964;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_arg(args_addr, arg_d);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    X509 * new_arg_a = *((X509 * *)new_args->args[0]);

    int new_arg_b = *((int *)new_args->args[1]);

    int * new_arg_c = *((int * *)new_args->args[2]);

    int * new_arg_d = *((int * *)new_args->args[3]);

    void * *new_ret_ptr = (void * *)new_args->ret;

    void * (*orig_X509_get_ext_d2i)(X509 *,int,int *,int *);
    orig_X509_get_ext_d2i = dlsym(RTLD_NEXT, "X509_get_ext_d2i");
    *new_ret_ptr = (*orig_X509_get_ext_d2i)(new_arg_a,new_arg_b,new_arg_c,new_arg_d);

    syscall(889);

    free(args_addr);

    return ret;
}

