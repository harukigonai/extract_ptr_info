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
    em[190] = 1; em[191] = 8; em[192] = 1; /* 190: pointer.struct.x509_cert_aux_st */
    	em[193] = 195; em[194] = 0; 
    em[195] = 0; em[196] = 40; em[197] = 5; /* 195: struct.x509_cert_aux_st */
    	em[198] = 208; em[199] = 0; 
    	em[200] = 208; em[201] = 8; 
    	em[202] = 252; em[203] = 16; 
    	em[204] = 262; em[205] = 24; 
    	em[206] = 267; em[207] = 32; 
    em[208] = 1; em[209] = 8; em[210] = 1; /* 208: pointer.struct.stack_st_ASN1_OBJECT */
    	em[211] = 213; em[212] = 0; 
    em[213] = 0; em[214] = 32; em[215] = 2; /* 213: struct.stack_st_fake_ASN1_OBJECT */
    	em[216] = 220; em[217] = 8; 
    	em[218] = 249; em[219] = 24; 
    em[220] = 8884099; em[221] = 8; em[222] = 2; /* 220: pointer_to_array_of_pointers_to_stack */
    	em[223] = 227; em[224] = 0; 
    	em[225] = 246; em[226] = 20; 
    em[227] = 0; em[228] = 8; em[229] = 1; /* 227: pointer.ASN1_OBJECT */
    	em[230] = 232; em[231] = 0; 
    em[232] = 0; em[233] = 0; em[234] = 1; /* 232: ASN1_OBJECT */
    	em[235] = 237; em[236] = 0; 
    em[237] = 0; em[238] = 40; em[239] = 3; /* 237: struct.asn1_object_st */
    	em[240] = 26; em[241] = 0; 
    	em[242] = 26; em[243] = 8; 
    	em[244] = 31; em[245] = 24; 
    em[246] = 0; em[247] = 4; em[248] = 0; /* 246: int */
    em[249] = 8884097; em[250] = 8; em[251] = 0; /* 249: pointer.func */
    em[252] = 1; em[253] = 8; em[254] = 1; /* 252: pointer.struct.asn1_string_st */
    	em[255] = 257; em[256] = 0; 
    em[257] = 0; em[258] = 24; em[259] = 1; /* 257: struct.asn1_string_st */
    	em[260] = 107; em[261] = 8; 
    em[262] = 1; em[263] = 8; em[264] = 1; /* 262: pointer.struct.asn1_string_st */
    	em[265] = 257; em[266] = 0; 
    em[267] = 1; em[268] = 8; em[269] = 1; /* 267: pointer.struct.stack_st_X509_ALGOR */
    	em[270] = 272; em[271] = 0; 
    em[272] = 0; em[273] = 32; em[274] = 2; /* 272: struct.stack_st_fake_X509_ALGOR */
    	em[275] = 279; em[276] = 8; 
    	em[277] = 249; em[278] = 24; 
    em[279] = 8884099; em[280] = 8; em[281] = 2; /* 279: pointer_to_array_of_pointers_to_stack */
    	em[282] = 286; em[283] = 0; 
    	em[284] = 246; em[285] = 20; 
    em[286] = 0; em[287] = 8; em[288] = 1; /* 286: pointer.X509_ALGOR */
    	em[289] = 0; em[290] = 0; 
    em[291] = 0; em[292] = 16; em[293] = 2; /* 291: struct.EDIPartyName_st */
    	em[294] = 298; em[295] = 0; 
    	em[296] = 298; em[297] = 8; 
    em[298] = 1; em[299] = 8; em[300] = 1; /* 298: pointer.struct.asn1_string_st */
    	em[301] = 303; em[302] = 0; 
    em[303] = 0; em[304] = 24; em[305] = 1; /* 303: struct.asn1_string_st */
    	em[306] = 107; em[307] = 8; 
    em[308] = 0; em[309] = 24; em[310] = 1; /* 308: struct.buf_mem_st */
    	em[311] = 92; em[312] = 8; 
    em[313] = 1; em[314] = 8; em[315] = 1; /* 313: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[316] = 318; em[317] = 0; 
    em[318] = 0; em[319] = 32; em[320] = 2; /* 318: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[321] = 325; em[322] = 8; 
    	em[323] = 249; em[324] = 24; 
    em[325] = 8884099; em[326] = 8; em[327] = 2; /* 325: pointer_to_array_of_pointers_to_stack */
    	em[328] = 332; em[329] = 0; 
    	em[330] = 246; em[331] = 20; 
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
    em[373] = 1; em[374] = 8; em[375] = 1; /* 373: pointer.struct.asn1_string_st */
    	em[376] = 303; em[377] = 0; 
    em[378] = 1; em[379] = 8; em[380] = 1; /* 378: pointer.struct.asn1_string_st */
    	em[381] = 303; em[382] = 0; 
    em[383] = 1; em[384] = 8; em[385] = 1; /* 383: pointer.struct.asn1_string_st */
    	em[386] = 303; em[387] = 0; 
    em[388] = 1; em[389] = 8; em[390] = 1; /* 388: pointer.struct.asn1_string_st */
    	em[391] = 303; em[392] = 0; 
    em[393] = 1; em[394] = 8; em[395] = 1; /* 393: pointer.struct.asn1_string_st */
    	em[396] = 303; em[397] = 0; 
    em[398] = 0; em[399] = 8; em[400] = 20; /* 398: union.unknown */
    	em[401] = 92; em[402] = 0; 
    	em[403] = 298; em[404] = 0; 
    	em[405] = 441; em[406] = 0; 
    	em[407] = 455; em[408] = 0; 
    	em[409] = 460; em[410] = 0; 
    	em[411] = 465; em[412] = 0; 
    	em[413] = 393; em[414] = 0; 
    	em[415] = 470; em[416] = 0; 
    	em[417] = 475; em[418] = 0; 
    	em[419] = 480; em[420] = 0; 
    	em[421] = 388; em[422] = 0; 
    	em[423] = 383; em[424] = 0; 
    	em[425] = 378; em[426] = 0; 
    	em[427] = 485; em[428] = 0; 
    	em[429] = 373; em[430] = 0; 
    	em[431] = 490; em[432] = 0; 
    	em[433] = 495; em[434] = 0; 
    	em[435] = 298; em[436] = 0; 
    	em[437] = 298; em[438] = 0; 
    	em[439] = 500; em[440] = 0; 
    em[441] = 1; em[442] = 8; em[443] = 1; /* 441: pointer.struct.asn1_object_st */
    	em[444] = 446; em[445] = 0; 
    em[446] = 0; em[447] = 40; em[448] = 3; /* 446: struct.asn1_object_st */
    	em[449] = 26; em[450] = 0; 
    	em[451] = 26; em[452] = 8; 
    	em[453] = 31; em[454] = 24; 
    em[455] = 1; em[456] = 8; em[457] = 1; /* 455: pointer.struct.asn1_string_st */
    	em[458] = 303; em[459] = 0; 
    em[460] = 1; em[461] = 8; em[462] = 1; /* 460: pointer.struct.asn1_string_st */
    	em[463] = 303; em[464] = 0; 
    em[465] = 1; em[466] = 8; em[467] = 1; /* 465: pointer.struct.asn1_string_st */
    	em[468] = 303; em[469] = 0; 
    em[470] = 1; em[471] = 8; em[472] = 1; /* 470: pointer.struct.asn1_string_st */
    	em[473] = 303; em[474] = 0; 
    em[475] = 1; em[476] = 8; em[477] = 1; /* 475: pointer.struct.asn1_string_st */
    	em[478] = 303; em[479] = 0; 
    em[480] = 1; em[481] = 8; em[482] = 1; /* 480: pointer.struct.asn1_string_st */
    	em[483] = 303; em[484] = 0; 
    em[485] = 1; em[486] = 8; em[487] = 1; /* 485: pointer.struct.asn1_string_st */
    	em[488] = 303; em[489] = 0; 
    em[490] = 1; em[491] = 8; em[492] = 1; /* 490: pointer.struct.asn1_string_st */
    	em[493] = 303; em[494] = 0; 
    em[495] = 1; em[496] = 8; em[497] = 1; /* 495: pointer.struct.asn1_string_st */
    	em[498] = 303; em[499] = 0; 
    em[500] = 1; em[501] = 8; em[502] = 1; /* 500: pointer.struct.ASN1_VALUE_st */
    	em[503] = 505; em[504] = 0; 
    em[505] = 0; em[506] = 0; em[507] = 0; /* 505: struct.ASN1_VALUE_st */
    em[508] = 1; em[509] = 8; em[510] = 1; /* 508: pointer.struct.GENERAL_NAME_st */
    	em[511] = 513; em[512] = 0; 
    em[513] = 0; em[514] = 16; em[515] = 1; /* 513: struct.GENERAL_NAME_st */
    	em[516] = 518; em[517] = 8; 
    em[518] = 0; em[519] = 8; em[520] = 15; /* 518: union.unknown */
    	em[521] = 92; em[522] = 0; 
    	em[523] = 551; em[524] = 0; 
    	em[525] = 480; em[526] = 0; 
    	em[527] = 480; em[528] = 0; 
    	em[529] = 563; em[530] = 0; 
    	em[531] = 573; em[532] = 0; 
    	em[533] = 592; em[534] = 0; 
    	em[535] = 480; em[536] = 0; 
    	em[537] = 393; em[538] = 0; 
    	em[539] = 441; em[540] = 0; 
    	em[541] = 393; em[542] = 0; 
    	em[543] = 573; em[544] = 0; 
    	em[545] = 480; em[546] = 0; 
    	em[547] = 441; em[548] = 0; 
    	em[549] = 563; em[550] = 0; 
    em[551] = 1; em[552] = 8; em[553] = 1; /* 551: pointer.struct.otherName_st */
    	em[554] = 556; em[555] = 0; 
    em[556] = 0; em[557] = 16; em[558] = 2; /* 556: struct.otherName_st */
    	em[559] = 441; em[560] = 0; 
    	em[561] = 563; em[562] = 8; 
    em[563] = 1; em[564] = 8; em[565] = 1; /* 563: pointer.struct.asn1_type_st */
    	em[566] = 568; em[567] = 0; 
    em[568] = 0; em[569] = 16; em[570] = 1; /* 568: struct.asn1_type_st */
    	em[571] = 398; em[572] = 8; 
    em[573] = 1; em[574] = 8; em[575] = 1; /* 573: pointer.struct.X509_name_st */
    	em[576] = 578; em[577] = 0; 
    em[578] = 0; em[579] = 40; em[580] = 3; /* 578: struct.X509_name_st */
    	em[581] = 313; em[582] = 0; 
    	em[583] = 587; em[584] = 16; 
    	em[585] = 107; em[586] = 24; 
    em[587] = 1; em[588] = 8; em[589] = 1; /* 587: pointer.struct.buf_mem_st */
    	em[590] = 308; em[591] = 0; 
    em[592] = 1; em[593] = 8; em[594] = 1; /* 592: pointer.struct.EDIPartyName_st */
    	em[595] = 291; em[596] = 0; 
    em[597] = 0; em[598] = 0; em[599] = 1; /* 597: GENERAL_SUBTREE */
    	em[600] = 602; em[601] = 0; 
    em[602] = 0; em[603] = 24; em[604] = 3; /* 602: struct.GENERAL_SUBTREE_st */
    	em[605] = 508; em[606] = 0; 
    	em[607] = 455; em[608] = 8; 
    	em[609] = 455; em[610] = 16; 
    em[611] = 1; em[612] = 8; em[613] = 1; /* 611: pointer.struct.stack_st_GENERAL_SUBTREE */
    	em[614] = 616; em[615] = 0; 
    em[616] = 0; em[617] = 32; em[618] = 2; /* 616: struct.stack_st_fake_GENERAL_SUBTREE */
    	em[619] = 623; em[620] = 8; 
    	em[621] = 249; em[622] = 24; 
    em[623] = 8884099; em[624] = 8; em[625] = 2; /* 623: pointer_to_array_of_pointers_to_stack */
    	em[626] = 630; em[627] = 0; 
    	em[628] = 246; em[629] = 20; 
    em[630] = 0; em[631] = 8; em[632] = 1; /* 630: pointer.GENERAL_SUBTREE */
    	em[633] = 597; em[634] = 0; 
    em[635] = 0; em[636] = 16; em[637] = 2; /* 635: struct.NAME_CONSTRAINTS_st */
    	em[638] = 611; em[639] = 0; 
    	em[640] = 611; em[641] = 8; 
    em[642] = 1; em[643] = 8; em[644] = 1; /* 642: pointer.struct.NAME_CONSTRAINTS_st */
    	em[645] = 635; em[646] = 0; 
    em[647] = 0; em[648] = 8; em[649] = 2; /* 647: union.unknown */
    	em[650] = 654; em[651] = 0; 
    	em[652] = 940; em[653] = 0; 
    em[654] = 1; em[655] = 8; em[656] = 1; /* 654: pointer.struct.stack_st_GENERAL_NAME */
    	em[657] = 659; em[658] = 0; 
    em[659] = 0; em[660] = 32; em[661] = 2; /* 659: struct.stack_st_fake_GENERAL_NAME */
    	em[662] = 666; em[663] = 8; 
    	em[664] = 249; em[665] = 24; 
    em[666] = 8884099; em[667] = 8; em[668] = 2; /* 666: pointer_to_array_of_pointers_to_stack */
    	em[669] = 673; em[670] = 0; 
    	em[671] = 246; em[672] = 20; 
    em[673] = 0; em[674] = 8; em[675] = 1; /* 673: pointer.GENERAL_NAME */
    	em[676] = 678; em[677] = 0; 
    em[678] = 0; em[679] = 0; em[680] = 1; /* 678: GENERAL_NAME */
    	em[681] = 683; em[682] = 0; 
    em[683] = 0; em[684] = 16; em[685] = 1; /* 683: struct.GENERAL_NAME_st */
    	em[686] = 688; em[687] = 8; 
    em[688] = 0; em[689] = 8; em[690] = 15; /* 688: union.unknown */
    	em[691] = 92; em[692] = 0; 
    	em[693] = 721; em[694] = 0; 
    	em[695] = 840; em[696] = 0; 
    	em[697] = 840; em[698] = 0; 
    	em[699] = 747; em[700] = 0; 
    	em[701] = 880; em[702] = 0; 
    	em[703] = 928; em[704] = 0; 
    	em[705] = 840; em[706] = 0; 
    	em[707] = 825; em[708] = 0; 
    	em[709] = 733; em[710] = 0; 
    	em[711] = 825; em[712] = 0; 
    	em[713] = 880; em[714] = 0; 
    	em[715] = 840; em[716] = 0; 
    	em[717] = 733; em[718] = 0; 
    	em[719] = 747; em[720] = 0; 
    em[721] = 1; em[722] = 8; em[723] = 1; /* 721: pointer.struct.otherName_st */
    	em[724] = 726; em[725] = 0; 
    em[726] = 0; em[727] = 16; em[728] = 2; /* 726: struct.otherName_st */
    	em[729] = 733; em[730] = 0; 
    	em[731] = 747; em[732] = 8; 
    em[733] = 1; em[734] = 8; em[735] = 1; /* 733: pointer.struct.asn1_object_st */
    	em[736] = 738; em[737] = 0; 
    em[738] = 0; em[739] = 40; em[740] = 3; /* 738: struct.asn1_object_st */
    	em[741] = 26; em[742] = 0; 
    	em[743] = 26; em[744] = 8; 
    	em[745] = 31; em[746] = 24; 
    em[747] = 1; em[748] = 8; em[749] = 1; /* 747: pointer.struct.asn1_type_st */
    	em[750] = 752; em[751] = 0; 
    em[752] = 0; em[753] = 16; em[754] = 1; /* 752: struct.asn1_type_st */
    	em[755] = 757; em[756] = 8; 
    em[757] = 0; em[758] = 8; em[759] = 20; /* 757: union.unknown */
    	em[760] = 92; em[761] = 0; 
    	em[762] = 800; em[763] = 0; 
    	em[764] = 733; em[765] = 0; 
    	em[766] = 810; em[767] = 0; 
    	em[768] = 815; em[769] = 0; 
    	em[770] = 820; em[771] = 0; 
    	em[772] = 825; em[773] = 0; 
    	em[774] = 830; em[775] = 0; 
    	em[776] = 835; em[777] = 0; 
    	em[778] = 840; em[779] = 0; 
    	em[780] = 845; em[781] = 0; 
    	em[782] = 850; em[783] = 0; 
    	em[784] = 855; em[785] = 0; 
    	em[786] = 860; em[787] = 0; 
    	em[788] = 865; em[789] = 0; 
    	em[790] = 870; em[791] = 0; 
    	em[792] = 875; em[793] = 0; 
    	em[794] = 800; em[795] = 0; 
    	em[796] = 800; em[797] = 0; 
    	em[798] = 500; em[799] = 0; 
    em[800] = 1; em[801] = 8; em[802] = 1; /* 800: pointer.struct.asn1_string_st */
    	em[803] = 805; em[804] = 0; 
    em[805] = 0; em[806] = 24; em[807] = 1; /* 805: struct.asn1_string_st */
    	em[808] = 107; em[809] = 8; 
    em[810] = 1; em[811] = 8; em[812] = 1; /* 810: pointer.struct.asn1_string_st */
    	em[813] = 805; em[814] = 0; 
    em[815] = 1; em[816] = 8; em[817] = 1; /* 815: pointer.struct.asn1_string_st */
    	em[818] = 805; em[819] = 0; 
    em[820] = 1; em[821] = 8; em[822] = 1; /* 820: pointer.struct.asn1_string_st */
    	em[823] = 805; em[824] = 0; 
    em[825] = 1; em[826] = 8; em[827] = 1; /* 825: pointer.struct.asn1_string_st */
    	em[828] = 805; em[829] = 0; 
    em[830] = 1; em[831] = 8; em[832] = 1; /* 830: pointer.struct.asn1_string_st */
    	em[833] = 805; em[834] = 0; 
    em[835] = 1; em[836] = 8; em[837] = 1; /* 835: pointer.struct.asn1_string_st */
    	em[838] = 805; em[839] = 0; 
    em[840] = 1; em[841] = 8; em[842] = 1; /* 840: pointer.struct.asn1_string_st */
    	em[843] = 805; em[844] = 0; 
    em[845] = 1; em[846] = 8; em[847] = 1; /* 845: pointer.struct.asn1_string_st */
    	em[848] = 805; em[849] = 0; 
    em[850] = 1; em[851] = 8; em[852] = 1; /* 850: pointer.struct.asn1_string_st */
    	em[853] = 805; em[854] = 0; 
    em[855] = 1; em[856] = 8; em[857] = 1; /* 855: pointer.struct.asn1_string_st */
    	em[858] = 805; em[859] = 0; 
    em[860] = 1; em[861] = 8; em[862] = 1; /* 860: pointer.struct.asn1_string_st */
    	em[863] = 805; em[864] = 0; 
    em[865] = 1; em[866] = 8; em[867] = 1; /* 865: pointer.struct.asn1_string_st */
    	em[868] = 805; em[869] = 0; 
    em[870] = 1; em[871] = 8; em[872] = 1; /* 870: pointer.struct.asn1_string_st */
    	em[873] = 805; em[874] = 0; 
    em[875] = 1; em[876] = 8; em[877] = 1; /* 875: pointer.struct.asn1_string_st */
    	em[878] = 805; em[879] = 0; 
    em[880] = 1; em[881] = 8; em[882] = 1; /* 880: pointer.struct.X509_name_st */
    	em[883] = 885; em[884] = 0; 
    em[885] = 0; em[886] = 40; em[887] = 3; /* 885: struct.X509_name_st */
    	em[888] = 894; em[889] = 0; 
    	em[890] = 918; em[891] = 16; 
    	em[892] = 107; em[893] = 24; 
    em[894] = 1; em[895] = 8; em[896] = 1; /* 894: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[897] = 899; em[898] = 0; 
    em[899] = 0; em[900] = 32; em[901] = 2; /* 899: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[902] = 906; em[903] = 8; 
    	em[904] = 249; em[905] = 24; 
    em[906] = 8884099; em[907] = 8; em[908] = 2; /* 906: pointer_to_array_of_pointers_to_stack */
    	em[909] = 913; em[910] = 0; 
    	em[911] = 246; em[912] = 20; 
    em[913] = 0; em[914] = 8; em[915] = 1; /* 913: pointer.X509_NAME_ENTRY */
    	em[916] = 337; em[917] = 0; 
    em[918] = 1; em[919] = 8; em[920] = 1; /* 918: pointer.struct.buf_mem_st */
    	em[921] = 923; em[922] = 0; 
    em[923] = 0; em[924] = 24; em[925] = 1; /* 923: struct.buf_mem_st */
    	em[926] = 92; em[927] = 8; 
    em[928] = 1; em[929] = 8; em[930] = 1; /* 928: pointer.struct.EDIPartyName_st */
    	em[931] = 933; em[932] = 0; 
    em[933] = 0; em[934] = 16; em[935] = 2; /* 933: struct.EDIPartyName_st */
    	em[936] = 800; em[937] = 0; 
    	em[938] = 800; em[939] = 8; 
    em[940] = 1; em[941] = 8; em[942] = 1; /* 940: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[943] = 945; em[944] = 0; 
    em[945] = 0; em[946] = 32; em[947] = 2; /* 945: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[948] = 952; em[949] = 8; 
    	em[950] = 249; em[951] = 24; 
    em[952] = 8884099; em[953] = 8; em[954] = 2; /* 952: pointer_to_array_of_pointers_to_stack */
    	em[955] = 959; em[956] = 0; 
    	em[957] = 246; em[958] = 20; 
    em[959] = 0; em[960] = 8; em[961] = 1; /* 959: pointer.X509_NAME_ENTRY */
    	em[962] = 337; em[963] = 0; 
    em[964] = 1; em[965] = 8; em[966] = 1; /* 964: pointer.struct.DIST_POINT_NAME_st */
    	em[967] = 969; em[968] = 0; 
    em[969] = 0; em[970] = 24; em[971] = 2; /* 969: struct.DIST_POINT_NAME_st */
    	em[972] = 647; em[973] = 8; 
    	em[974] = 976; em[975] = 16; 
    em[976] = 1; em[977] = 8; em[978] = 1; /* 976: pointer.struct.X509_name_st */
    	em[979] = 981; em[980] = 0; 
    em[981] = 0; em[982] = 40; em[983] = 3; /* 981: struct.X509_name_st */
    	em[984] = 940; em[985] = 0; 
    	em[986] = 990; em[987] = 16; 
    	em[988] = 107; em[989] = 24; 
    em[990] = 1; em[991] = 8; em[992] = 1; /* 990: pointer.struct.buf_mem_st */
    	em[993] = 995; em[994] = 0; 
    em[995] = 0; em[996] = 24; em[997] = 1; /* 995: struct.buf_mem_st */
    	em[998] = 92; em[999] = 8; 
    em[1000] = 1; em[1001] = 8; em[1002] = 1; /* 1000: pointer.struct.stack_st_ASN1_OBJECT */
    	em[1003] = 1005; em[1004] = 0; 
    em[1005] = 0; em[1006] = 32; em[1007] = 2; /* 1005: struct.stack_st_fake_ASN1_OBJECT */
    	em[1008] = 1012; em[1009] = 8; 
    	em[1010] = 249; em[1011] = 24; 
    em[1012] = 8884099; em[1013] = 8; em[1014] = 2; /* 1012: pointer_to_array_of_pointers_to_stack */
    	em[1015] = 1019; em[1016] = 0; 
    	em[1017] = 246; em[1018] = 20; 
    em[1019] = 0; em[1020] = 8; em[1021] = 1; /* 1019: pointer.ASN1_OBJECT */
    	em[1022] = 232; em[1023] = 0; 
    em[1024] = 1; em[1025] = 8; em[1026] = 1; /* 1024: pointer.struct.stack_st_POLICYQUALINFO */
    	em[1027] = 1029; em[1028] = 0; 
    em[1029] = 0; em[1030] = 32; em[1031] = 2; /* 1029: struct.stack_st_fake_POLICYQUALINFO */
    	em[1032] = 1036; em[1033] = 8; 
    	em[1034] = 249; em[1035] = 24; 
    em[1036] = 8884099; em[1037] = 8; em[1038] = 2; /* 1036: pointer_to_array_of_pointers_to_stack */
    	em[1039] = 1043; em[1040] = 0; 
    	em[1041] = 246; em[1042] = 20; 
    em[1043] = 0; em[1044] = 8; em[1045] = 1; /* 1043: pointer.POLICYQUALINFO */
    	em[1046] = 1048; em[1047] = 0; 
    em[1048] = 0; em[1049] = 0; em[1050] = 1; /* 1048: POLICYQUALINFO */
    	em[1051] = 1053; em[1052] = 0; 
    em[1053] = 0; em[1054] = 16; em[1055] = 2; /* 1053: struct.POLICYQUALINFO_st */
    	em[1056] = 1060; em[1057] = 0; 
    	em[1058] = 1074; em[1059] = 8; 
    em[1060] = 1; em[1061] = 8; em[1062] = 1; /* 1060: pointer.struct.asn1_object_st */
    	em[1063] = 1065; em[1064] = 0; 
    em[1065] = 0; em[1066] = 40; em[1067] = 3; /* 1065: struct.asn1_object_st */
    	em[1068] = 26; em[1069] = 0; 
    	em[1070] = 26; em[1071] = 8; 
    	em[1072] = 31; em[1073] = 24; 
    em[1074] = 0; em[1075] = 8; em[1076] = 3; /* 1074: union.unknown */
    	em[1077] = 1083; em[1078] = 0; 
    	em[1079] = 1093; em[1080] = 0; 
    	em[1081] = 1156; em[1082] = 0; 
    em[1083] = 1; em[1084] = 8; em[1085] = 1; /* 1083: pointer.struct.asn1_string_st */
    	em[1086] = 1088; em[1087] = 0; 
    em[1088] = 0; em[1089] = 24; em[1090] = 1; /* 1088: struct.asn1_string_st */
    	em[1091] = 107; em[1092] = 8; 
    em[1093] = 1; em[1094] = 8; em[1095] = 1; /* 1093: pointer.struct.USERNOTICE_st */
    	em[1096] = 1098; em[1097] = 0; 
    em[1098] = 0; em[1099] = 16; em[1100] = 2; /* 1098: struct.USERNOTICE_st */
    	em[1101] = 1105; em[1102] = 0; 
    	em[1103] = 1117; em[1104] = 8; 
    em[1105] = 1; em[1106] = 8; em[1107] = 1; /* 1105: pointer.struct.NOTICEREF_st */
    	em[1108] = 1110; em[1109] = 0; 
    em[1110] = 0; em[1111] = 16; em[1112] = 2; /* 1110: struct.NOTICEREF_st */
    	em[1113] = 1117; em[1114] = 0; 
    	em[1115] = 1122; em[1116] = 8; 
    em[1117] = 1; em[1118] = 8; em[1119] = 1; /* 1117: pointer.struct.asn1_string_st */
    	em[1120] = 1088; em[1121] = 0; 
    em[1122] = 1; em[1123] = 8; em[1124] = 1; /* 1122: pointer.struct.stack_st_ASN1_INTEGER */
    	em[1125] = 1127; em[1126] = 0; 
    em[1127] = 0; em[1128] = 32; em[1129] = 2; /* 1127: struct.stack_st_fake_ASN1_INTEGER */
    	em[1130] = 1134; em[1131] = 8; 
    	em[1132] = 249; em[1133] = 24; 
    em[1134] = 8884099; em[1135] = 8; em[1136] = 2; /* 1134: pointer_to_array_of_pointers_to_stack */
    	em[1137] = 1141; em[1138] = 0; 
    	em[1139] = 246; em[1140] = 20; 
    em[1141] = 0; em[1142] = 8; em[1143] = 1; /* 1141: pointer.ASN1_INTEGER */
    	em[1144] = 1146; em[1145] = 0; 
    em[1146] = 0; em[1147] = 0; em[1148] = 1; /* 1146: ASN1_INTEGER */
    	em[1149] = 1151; em[1150] = 0; 
    em[1151] = 0; em[1152] = 24; em[1153] = 1; /* 1151: struct.asn1_string_st */
    	em[1154] = 107; em[1155] = 8; 
    em[1156] = 1; em[1157] = 8; em[1158] = 1; /* 1156: pointer.struct.asn1_type_st */
    	em[1159] = 1161; em[1160] = 0; 
    em[1161] = 0; em[1162] = 16; em[1163] = 1; /* 1161: struct.asn1_type_st */
    	em[1164] = 1166; em[1165] = 8; 
    em[1166] = 0; em[1167] = 8; em[1168] = 20; /* 1166: union.unknown */
    	em[1169] = 92; em[1170] = 0; 
    	em[1171] = 1117; em[1172] = 0; 
    	em[1173] = 1060; em[1174] = 0; 
    	em[1175] = 1209; em[1176] = 0; 
    	em[1177] = 1214; em[1178] = 0; 
    	em[1179] = 1219; em[1180] = 0; 
    	em[1181] = 1224; em[1182] = 0; 
    	em[1183] = 1229; em[1184] = 0; 
    	em[1185] = 1234; em[1186] = 0; 
    	em[1187] = 1083; em[1188] = 0; 
    	em[1189] = 1239; em[1190] = 0; 
    	em[1191] = 1244; em[1192] = 0; 
    	em[1193] = 1249; em[1194] = 0; 
    	em[1195] = 1254; em[1196] = 0; 
    	em[1197] = 1259; em[1198] = 0; 
    	em[1199] = 1264; em[1200] = 0; 
    	em[1201] = 1269; em[1202] = 0; 
    	em[1203] = 1117; em[1204] = 0; 
    	em[1205] = 1117; em[1206] = 0; 
    	em[1207] = 500; em[1208] = 0; 
    em[1209] = 1; em[1210] = 8; em[1211] = 1; /* 1209: pointer.struct.asn1_string_st */
    	em[1212] = 1088; em[1213] = 0; 
    em[1214] = 1; em[1215] = 8; em[1216] = 1; /* 1214: pointer.struct.asn1_string_st */
    	em[1217] = 1088; em[1218] = 0; 
    em[1219] = 1; em[1220] = 8; em[1221] = 1; /* 1219: pointer.struct.asn1_string_st */
    	em[1222] = 1088; em[1223] = 0; 
    em[1224] = 1; em[1225] = 8; em[1226] = 1; /* 1224: pointer.struct.asn1_string_st */
    	em[1227] = 1088; em[1228] = 0; 
    em[1229] = 1; em[1230] = 8; em[1231] = 1; /* 1229: pointer.struct.asn1_string_st */
    	em[1232] = 1088; em[1233] = 0; 
    em[1234] = 1; em[1235] = 8; em[1236] = 1; /* 1234: pointer.struct.asn1_string_st */
    	em[1237] = 1088; em[1238] = 0; 
    em[1239] = 1; em[1240] = 8; em[1241] = 1; /* 1239: pointer.struct.asn1_string_st */
    	em[1242] = 1088; em[1243] = 0; 
    em[1244] = 1; em[1245] = 8; em[1246] = 1; /* 1244: pointer.struct.asn1_string_st */
    	em[1247] = 1088; em[1248] = 0; 
    em[1249] = 1; em[1250] = 8; em[1251] = 1; /* 1249: pointer.struct.asn1_string_st */
    	em[1252] = 1088; em[1253] = 0; 
    em[1254] = 1; em[1255] = 8; em[1256] = 1; /* 1254: pointer.struct.asn1_string_st */
    	em[1257] = 1088; em[1258] = 0; 
    em[1259] = 1; em[1260] = 8; em[1261] = 1; /* 1259: pointer.struct.asn1_string_st */
    	em[1262] = 1088; em[1263] = 0; 
    em[1264] = 1; em[1265] = 8; em[1266] = 1; /* 1264: pointer.struct.asn1_string_st */
    	em[1267] = 1088; em[1268] = 0; 
    em[1269] = 1; em[1270] = 8; em[1271] = 1; /* 1269: pointer.struct.asn1_string_st */
    	em[1272] = 1088; em[1273] = 0; 
    em[1274] = 1; em[1275] = 8; em[1276] = 1; /* 1274: pointer.struct.asn1_object_st */
    	em[1277] = 1279; em[1278] = 0; 
    em[1279] = 0; em[1280] = 40; em[1281] = 3; /* 1279: struct.asn1_object_st */
    	em[1282] = 26; em[1283] = 0; 
    	em[1284] = 26; em[1285] = 8; 
    	em[1286] = 31; em[1287] = 24; 
    em[1288] = 0; em[1289] = 32; em[1290] = 3; /* 1288: struct.X509_POLICY_DATA_st */
    	em[1291] = 1274; em[1292] = 8; 
    	em[1293] = 1024; em[1294] = 16; 
    	em[1295] = 1000; em[1296] = 24; 
    em[1297] = 1; em[1298] = 8; em[1299] = 1; /* 1297: pointer.struct.stack_st_ASN1_OBJECT */
    	em[1300] = 1302; em[1301] = 0; 
    em[1302] = 0; em[1303] = 32; em[1304] = 2; /* 1302: struct.stack_st_fake_ASN1_OBJECT */
    	em[1305] = 1309; em[1306] = 8; 
    	em[1307] = 249; em[1308] = 24; 
    em[1309] = 8884099; em[1310] = 8; em[1311] = 2; /* 1309: pointer_to_array_of_pointers_to_stack */
    	em[1312] = 1316; em[1313] = 0; 
    	em[1314] = 246; em[1315] = 20; 
    em[1316] = 0; em[1317] = 8; em[1318] = 1; /* 1316: pointer.ASN1_OBJECT */
    	em[1319] = 232; em[1320] = 0; 
    em[1321] = 1; em[1322] = 8; em[1323] = 1; /* 1321: pointer.struct.stack_st_POLICYQUALINFO */
    	em[1324] = 1326; em[1325] = 0; 
    em[1326] = 0; em[1327] = 32; em[1328] = 2; /* 1326: struct.stack_st_fake_POLICYQUALINFO */
    	em[1329] = 1333; em[1330] = 8; 
    	em[1331] = 249; em[1332] = 24; 
    em[1333] = 8884099; em[1334] = 8; em[1335] = 2; /* 1333: pointer_to_array_of_pointers_to_stack */
    	em[1336] = 1340; em[1337] = 0; 
    	em[1338] = 246; em[1339] = 20; 
    em[1340] = 0; em[1341] = 8; em[1342] = 1; /* 1340: pointer.POLICYQUALINFO */
    	em[1343] = 1048; em[1344] = 0; 
    em[1345] = 0; em[1346] = 40; em[1347] = 3; /* 1345: struct.asn1_object_st */
    	em[1348] = 26; em[1349] = 0; 
    	em[1350] = 26; em[1351] = 8; 
    	em[1352] = 31; em[1353] = 24; 
    em[1354] = 0; em[1355] = 32; em[1356] = 3; /* 1354: struct.X509_POLICY_DATA_st */
    	em[1357] = 1363; em[1358] = 8; 
    	em[1359] = 1321; em[1360] = 16; 
    	em[1361] = 1297; em[1362] = 24; 
    em[1363] = 1; em[1364] = 8; em[1365] = 1; /* 1363: pointer.struct.asn1_object_st */
    	em[1366] = 1345; em[1367] = 0; 
    em[1368] = 0; em[1369] = 40; em[1370] = 2; /* 1368: struct.X509_POLICY_CACHE_st */
    	em[1371] = 1375; em[1372] = 0; 
    	em[1373] = 1380; em[1374] = 8; 
    em[1375] = 1; em[1376] = 8; em[1377] = 1; /* 1375: pointer.struct.X509_POLICY_DATA_st */
    	em[1378] = 1354; em[1379] = 0; 
    em[1380] = 1; em[1381] = 8; em[1382] = 1; /* 1380: pointer.struct.stack_st_X509_POLICY_DATA */
    	em[1383] = 1385; em[1384] = 0; 
    em[1385] = 0; em[1386] = 32; em[1387] = 2; /* 1385: struct.stack_st_fake_X509_POLICY_DATA */
    	em[1388] = 1392; em[1389] = 8; 
    	em[1390] = 249; em[1391] = 24; 
    em[1392] = 8884099; em[1393] = 8; em[1394] = 2; /* 1392: pointer_to_array_of_pointers_to_stack */
    	em[1395] = 1399; em[1396] = 0; 
    	em[1397] = 246; em[1398] = 20; 
    em[1399] = 0; em[1400] = 8; em[1401] = 1; /* 1399: pointer.X509_POLICY_DATA */
    	em[1402] = 1404; em[1403] = 0; 
    em[1404] = 0; em[1405] = 0; em[1406] = 1; /* 1404: X509_POLICY_DATA */
    	em[1407] = 1288; em[1408] = 0; 
    em[1409] = 1; em[1410] = 8; em[1411] = 1; /* 1409: pointer.struct.asn1_string_st */
    	em[1412] = 1414; em[1413] = 0; 
    em[1414] = 0; em[1415] = 24; em[1416] = 1; /* 1414: struct.asn1_string_st */
    	em[1417] = 107; em[1418] = 8; 
    em[1419] = 0; em[1420] = 0; em[1421] = 1; /* 1419: DIST_POINT */
    	em[1422] = 1424; em[1423] = 0; 
    em[1424] = 0; em[1425] = 32; em[1426] = 3; /* 1424: struct.DIST_POINT_st */
    	em[1427] = 964; em[1428] = 0; 
    	em[1429] = 1433; em[1430] = 8; 
    	em[1431] = 654; em[1432] = 16; 
    em[1433] = 1; em[1434] = 8; em[1435] = 1; /* 1433: pointer.struct.asn1_string_st */
    	em[1436] = 1438; em[1437] = 0; 
    em[1438] = 0; em[1439] = 24; em[1440] = 1; /* 1438: struct.asn1_string_st */
    	em[1441] = 107; em[1442] = 8; 
    em[1443] = 1; em[1444] = 8; em[1445] = 1; /* 1443: pointer.struct.stack_st_GENERAL_NAME */
    	em[1446] = 1448; em[1447] = 0; 
    em[1448] = 0; em[1449] = 32; em[1450] = 2; /* 1448: struct.stack_st_fake_GENERAL_NAME */
    	em[1451] = 1455; em[1452] = 8; 
    	em[1453] = 249; em[1454] = 24; 
    em[1455] = 8884099; em[1456] = 8; em[1457] = 2; /* 1455: pointer_to_array_of_pointers_to_stack */
    	em[1458] = 1462; em[1459] = 0; 
    	em[1460] = 246; em[1461] = 20; 
    em[1462] = 0; em[1463] = 8; em[1464] = 1; /* 1462: pointer.GENERAL_NAME */
    	em[1465] = 678; em[1466] = 0; 
    em[1467] = 1; em[1468] = 8; em[1469] = 1; /* 1467: pointer.struct.stack_st_DIST_POINT */
    	em[1470] = 1472; em[1471] = 0; 
    em[1472] = 0; em[1473] = 32; em[1474] = 2; /* 1472: struct.stack_st_fake_DIST_POINT */
    	em[1475] = 1479; em[1476] = 8; 
    	em[1477] = 249; em[1478] = 24; 
    em[1479] = 8884099; em[1480] = 8; em[1481] = 2; /* 1479: pointer_to_array_of_pointers_to_stack */
    	em[1482] = 1486; em[1483] = 0; 
    	em[1484] = 246; em[1485] = 20; 
    em[1486] = 0; em[1487] = 8; em[1488] = 1; /* 1486: pointer.DIST_POINT */
    	em[1489] = 1419; em[1490] = 0; 
    em[1491] = 0; em[1492] = 24; em[1493] = 1; /* 1491: struct.asn1_string_st */
    	em[1494] = 107; em[1495] = 8; 
    em[1496] = 1; em[1497] = 8; em[1498] = 1; /* 1496: pointer.struct.asn1_string_st */
    	em[1499] = 1491; em[1500] = 0; 
    em[1501] = 1; em[1502] = 8; em[1503] = 1; /* 1501: pointer.struct.stack_st_X509_EXTENSION */
    	em[1504] = 1506; em[1505] = 0; 
    em[1506] = 0; em[1507] = 32; em[1508] = 2; /* 1506: struct.stack_st_fake_X509_EXTENSION */
    	em[1509] = 1513; em[1510] = 8; 
    	em[1511] = 249; em[1512] = 24; 
    em[1513] = 8884099; em[1514] = 8; em[1515] = 2; /* 1513: pointer_to_array_of_pointers_to_stack */
    	em[1516] = 1520; em[1517] = 0; 
    	em[1518] = 246; em[1519] = 20; 
    em[1520] = 0; em[1521] = 8; em[1522] = 1; /* 1520: pointer.X509_EXTENSION */
    	em[1523] = 1525; em[1524] = 0; 
    em[1525] = 0; em[1526] = 0; em[1527] = 1; /* 1525: X509_EXTENSION */
    	em[1528] = 1530; em[1529] = 0; 
    em[1530] = 0; em[1531] = 24; em[1532] = 2; /* 1530: struct.X509_extension_st */
    	em[1533] = 1537; em[1534] = 0; 
    	em[1535] = 1496; em[1536] = 16; 
    em[1537] = 1; em[1538] = 8; em[1539] = 1; /* 1537: pointer.struct.asn1_object_st */
    	em[1540] = 1542; em[1541] = 0; 
    em[1542] = 0; em[1543] = 40; em[1544] = 3; /* 1542: struct.asn1_object_st */
    	em[1545] = 26; em[1546] = 0; 
    	em[1547] = 26; em[1548] = 8; 
    	em[1549] = 31; em[1550] = 24; 
    em[1551] = 1; em[1552] = 8; em[1553] = 1; /* 1551: pointer.struct.ASN1_VALUE_st */
    	em[1554] = 1556; em[1555] = 0; 
    em[1556] = 0; em[1557] = 0; em[1558] = 0; /* 1556: struct.ASN1_VALUE_st */
    em[1559] = 1; em[1560] = 8; em[1561] = 1; /* 1559: pointer.struct.asn1_string_st */
    	em[1562] = 1564; em[1563] = 0; 
    em[1564] = 0; em[1565] = 24; em[1566] = 1; /* 1564: struct.asn1_string_st */
    	em[1567] = 107; em[1568] = 8; 
    em[1569] = 1; em[1570] = 8; em[1571] = 1; /* 1569: pointer.struct.asn1_string_st */
    	em[1572] = 1564; em[1573] = 0; 
    em[1574] = 1; em[1575] = 8; em[1576] = 1; /* 1574: pointer.struct.asn1_string_st */
    	em[1577] = 1564; em[1578] = 0; 
    em[1579] = 1; em[1580] = 8; em[1581] = 1; /* 1579: pointer.struct.asn1_string_st */
    	em[1582] = 1564; em[1583] = 0; 
    em[1584] = 1; em[1585] = 8; em[1586] = 1; /* 1584: pointer.struct.asn1_string_st */
    	em[1587] = 1564; em[1588] = 0; 
    em[1589] = 1; em[1590] = 8; em[1591] = 1; /* 1589: pointer.struct.asn1_string_st */
    	em[1592] = 1564; em[1593] = 0; 
    em[1594] = 1; em[1595] = 8; em[1596] = 1; /* 1594: pointer.struct.asn1_string_st */
    	em[1597] = 1564; em[1598] = 0; 
    em[1599] = 1; em[1600] = 8; em[1601] = 1; /* 1599: pointer.struct.asn1_string_st */
    	em[1602] = 1564; em[1603] = 0; 
    em[1604] = 1; em[1605] = 8; em[1606] = 1; /* 1604: pointer.struct.asn1_string_st */
    	em[1607] = 1564; em[1608] = 0; 
    em[1609] = 1; em[1610] = 8; em[1611] = 1; /* 1609: pointer.struct.asn1_string_st */
    	em[1612] = 1564; em[1613] = 0; 
    em[1614] = 1; em[1615] = 8; em[1616] = 1; /* 1614: pointer.struct.asn1_string_st */
    	em[1617] = 1564; em[1618] = 0; 
    em[1619] = 0; em[1620] = 8; em[1621] = 20; /* 1619: union.unknown */
    	em[1622] = 92; em[1623] = 0; 
    	em[1624] = 1614; em[1625] = 0; 
    	em[1626] = 1662; em[1627] = 0; 
    	em[1628] = 1676; em[1629] = 0; 
    	em[1630] = 1609; em[1631] = 0; 
    	em[1632] = 1604; em[1633] = 0; 
    	em[1634] = 1599; em[1635] = 0; 
    	em[1636] = 1594; em[1637] = 0; 
    	em[1638] = 1589; em[1639] = 0; 
    	em[1640] = 1584; em[1641] = 0; 
    	em[1642] = 1579; em[1643] = 0; 
    	em[1644] = 1574; em[1645] = 0; 
    	em[1646] = 1681; em[1647] = 0; 
    	em[1648] = 1569; em[1649] = 0; 
    	em[1650] = 1686; em[1651] = 0; 
    	em[1652] = 1691; em[1653] = 0; 
    	em[1654] = 1559; em[1655] = 0; 
    	em[1656] = 1614; em[1657] = 0; 
    	em[1658] = 1614; em[1659] = 0; 
    	em[1660] = 1551; em[1661] = 0; 
    em[1662] = 1; em[1663] = 8; em[1664] = 1; /* 1662: pointer.struct.asn1_object_st */
    	em[1665] = 1667; em[1666] = 0; 
    em[1667] = 0; em[1668] = 40; em[1669] = 3; /* 1667: struct.asn1_object_st */
    	em[1670] = 26; em[1671] = 0; 
    	em[1672] = 26; em[1673] = 8; 
    	em[1674] = 31; em[1675] = 24; 
    em[1676] = 1; em[1677] = 8; em[1678] = 1; /* 1676: pointer.struct.asn1_string_st */
    	em[1679] = 1564; em[1680] = 0; 
    em[1681] = 1; em[1682] = 8; em[1683] = 1; /* 1681: pointer.struct.asn1_string_st */
    	em[1684] = 1564; em[1685] = 0; 
    em[1686] = 1; em[1687] = 8; em[1688] = 1; /* 1686: pointer.struct.asn1_string_st */
    	em[1689] = 1564; em[1690] = 0; 
    em[1691] = 1; em[1692] = 8; em[1693] = 1; /* 1691: pointer.struct.asn1_string_st */
    	em[1694] = 1564; em[1695] = 0; 
    em[1696] = 0; em[1697] = 16; em[1698] = 1; /* 1696: struct.asn1_type_st */
    	em[1699] = 1619; em[1700] = 8; 
    em[1701] = 1; em[1702] = 8; em[1703] = 1; /* 1701: pointer.struct.ASN1_VALUE_st */
    	em[1704] = 1706; em[1705] = 0; 
    em[1706] = 0; em[1707] = 0; em[1708] = 0; /* 1706: struct.ASN1_VALUE_st */
    em[1709] = 1; em[1710] = 8; em[1711] = 1; /* 1709: pointer.struct.asn1_string_st */
    	em[1712] = 1714; em[1713] = 0; 
    em[1714] = 0; em[1715] = 24; em[1716] = 1; /* 1714: struct.asn1_string_st */
    	em[1717] = 107; em[1718] = 8; 
    em[1719] = 1; em[1720] = 8; em[1721] = 1; /* 1719: pointer.struct.asn1_string_st */
    	em[1722] = 1714; em[1723] = 0; 
    em[1724] = 1; em[1725] = 8; em[1726] = 1; /* 1724: pointer.struct.asn1_string_st */
    	em[1727] = 1714; em[1728] = 0; 
    em[1729] = 1; em[1730] = 8; em[1731] = 1; /* 1729: pointer.struct.asn1_string_st */
    	em[1732] = 1714; em[1733] = 0; 
    em[1734] = 1; em[1735] = 8; em[1736] = 1; /* 1734: pointer.struct.asn1_string_st */
    	em[1737] = 1714; em[1738] = 0; 
    em[1739] = 1; em[1740] = 8; em[1741] = 1; /* 1739: pointer.struct.asn1_string_st */
    	em[1742] = 1714; em[1743] = 0; 
    em[1744] = 1; em[1745] = 8; em[1746] = 1; /* 1744: pointer.struct.asn1_string_st */
    	em[1747] = 1714; em[1748] = 0; 
    em[1749] = 1; em[1750] = 8; em[1751] = 1; /* 1749: pointer.struct.asn1_string_st */
    	em[1752] = 1714; em[1753] = 0; 
    em[1754] = 1; em[1755] = 8; em[1756] = 1; /* 1754: pointer.struct.asn1_string_st */
    	em[1757] = 1714; em[1758] = 0; 
    em[1759] = 1; em[1760] = 8; em[1761] = 1; /* 1759: pointer.struct.asn1_string_st */
    	em[1762] = 1714; em[1763] = 0; 
    em[1764] = 1; em[1765] = 8; em[1766] = 1; /* 1764: pointer.struct.asn1_string_st */
    	em[1767] = 1714; em[1768] = 0; 
    em[1769] = 0; em[1770] = 16; em[1771] = 1; /* 1769: struct.asn1_type_st */
    	em[1772] = 1774; em[1773] = 8; 
    em[1774] = 0; em[1775] = 8; em[1776] = 20; /* 1774: union.unknown */
    	em[1777] = 92; em[1778] = 0; 
    	em[1779] = 1764; em[1780] = 0; 
    	em[1781] = 1817; em[1782] = 0; 
    	em[1783] = 1754; em[1784] = 0; 
    	em[1785] = 1749; em[1786] = 0; 
    	em[1787] = 1744; em[1788] = 0; 
    	em[1789] = 1822; em[1790] = 0; 
    	em[1791] = 1739; em[1792] = 0; 
    	em[1793] = 1827; em[1794] = 0; 
    	em[1795] = 1734; em[1796] = 0; 
    	em[1797] = 1832; em[1798] = 0; 
    	em[1799] = 1729; em[1800] = 0; 
    	em[1801] = 1759; em[1802] = 0; 
    	em[1803] = 1724; em[1804] = 0; 
    	em[1805] = 1719; em[1806] = 0; 
    	em[1807] = 1709; em[1808] = 0; 
    	em[1809] = 1837; em[1810] = 0; 
    	em[1811] = 1764; em[1812] = 0; 
    	em[1813] = 1764; em[1814] = 0; 
    	em[1815] = 1701; em[1816] = 0; 
    em[1817] = 1; em[1818] = 8; em[1819] = 1; /* 1817: pointer.struct.asn1_object_st */
    	em[1820] = 237; em[1821] = 0; 
    em[1822] = 1; em[1823] = 8; em[1824] = 1; /* 1822: pointer.struct.asn1_string_st */
    	em[1825] = 1714; em[1826] = 0; 
    em[1827] = 1; em[1828] = 8; em[1829] = 1; /* 1827: pointer.struct.asn1_string_st */
    	em[1830] = 1714; em[1831] = 0; 
    em[1832] = 1; em[1833] = 8; em[1834] = 1; /* 1832: pointer.struct.asn1_string_st */
    	em[1835] = 1714; em[1836] = 0; 
    em[1837] = 1; em[1838] = 8; em[1839] = 1; /* 1837: pointer.struct.asn1_string_st */
    	em[1840] = 1714; em[1841] = 0; 
    em[1842] = 0; em[1843] = 0; em[1844] = 1; /* 1842: ASN1_TYPE */
    	em[1845] = 1769; em[1846] = 0; 
    em[1847] = 1; em[1848] = 8; em[1849] = 1; /* 1847: pointer.struct.stack_st_ASN1_TYPE */
    	em[1850] = 1852; em[1851] = 0; 
    em[1852] = 0; em[1853] = 32; em[1854] = 2; /* 1852: struct.stack_st_fake_ASN1_TYPE */
    	em[1855] = 1859; em[1856] = 8; 
    	em[1857] = 249; em[1858] = 24; 
    em[1859] = 8884099; em[1860] = 8; em[1861] = 2; /* 1859: pointer_to_array_of_pointers_to_stack */
    	em[1862] = 1866; em[1863] = 0; 
    	em[1864] = 246; em[1865] = 20; 
    em[1866] = 0; em[1867] = 8; em[1868] = 1; /* 1866: pointer.ASN1_TYPE */
    	em[1869] = 1842; em[1870] = 0; 
    em[1871] = 0; em[1872] = 8; em[1873] = 3; /* 1871: union.unknown */
    	em[1874] = 92; em[1875] = 0; 
    	em[1876] = 1847; em[1877] = 0; 
    	em[1878] = 1880; em[1879] = 0; 
    em[1880] = 1; em[1881] = 8; em[1882] = 1; /* 1880: pointer.struct.asn1_type_st */
    	em[1883] = 1696; em[1884] = 0; 
    em[1885] = 0; em[1886] = 24; em[1887] = 2; /* 1885: struct.x509_attributes_st */
    	em[1888] = 1662; em[1889] = 0; 
    	em[1890] = 1871; em[1891] = 16; 
    em[1892] = 0; em[1893] = 40; em[1894] = 5; /* 1892: struct.ec_extra_data_st */
    	em[1895] = 1905; em[1896] = 0; 
    	em[1897] = 1910; em[1898] = 8; 
    	em[1899] = 1913; em[1900] = 16; 
    	em[1901] = 1916; em[1902] = 24; 
    	em[1903] = 1916; em[1904] = 32; 
    em[1905] = 1; em[1906] = 8; em[1907] = 1; /* 1905: pointer.struct.ec_extra_data_st */
    	em[1908] = 1892; em[1909] = 0; 
    em[1910] = 0; em[1911] = 8; em[1912] = 0; /* 1910: pointer.void */
    em[1913] = 8884097; em[1914] = 8; em[1915] = 0; /* 1913: pointer.func */
    em[1916] = 8884097; em[1917] = 8; em[1918] = 0; /* 1916: pointer.func */
    em[1919] = 1; em[1920] = 8; em[1921] = 1; /* 1919: pointer.struct.ec_extra_data_st */
    	em[1922] = 1892; em[1923] = 0; 
    em[1924] = 0; em[1925] = 24; em[1926] = 1; /* 1924: struct.bignum_st */
    	em[1927] = 1929; em[1928] = 0; 
    em[1929] = 8884099; em[1930] = 8; em[1931] = 2; /* 1929: pointer_to_array_of_pointers_to_stack */
    	em[1932] = 1936; em[1933] = 0; 
    	em[1934] = 246; em[1935] = 12; 
    em[1936] = 0; em[1937] = 8; em[1938] = 0; /* 1936: long unsigned int */
    em[1939] = 1; em[1940] = 8; em[1941] = 1; /* 1939: pointer.struct.ec_point_st */
    	em[1942] = 1944; em[1943] = 0; 
    em[1944] = 0; em[1945] = 88; em[1946] = 4; /* 1944: struct.ec_point_st */
    	em[1947] = 1955; em[1948] = 0; 
    	em[1949] = 2127; em[1950] = 8; 
    	em[1951] = 2127; em[1952] = 32; 
    	em[1953] = 2127; em[1954] = 56; 
    em[1955] = 1; em[1956] = 8; em[1957] = 1; /* 1955: pointer.struct.ec_method_st */
    	em[1958] = 1960; em[1959] = 0; 
    em[1960] = 0; em[1961] = 304; em[1962] = 37; /* 1960: struct.ec_method_st */
    	em[1963] = 2037; em[1964] = 8; 
    	em[1965] = 2040; em[1966] = 16; 
    	em[1967] = 2040; em[1968] = 24; 
    	em[1969] = 2043; em[1970] = 32; 
    	em[1971] = 2046; em[1972] = 40; 
    	em[1973] = 2049; em[1974] = 48; 
    	em[1975] = 2052; em[1976] = 56; 
    	em[1977] = 2055; em[1978] = 64; 
    	em[1979] = 2058; em[1980] = 72; 
    	em[1981] = 2061; em[1982] = 80; 
    	em[1983] = 2061; em[1984] = 88; 
    	em[1985] = 2064; em[1986] = 96; 
    	em[1987] = 2067; em[1988] = 104; 
    	em[1989] = 2070; em[1990] = 112; 
    	em[1991] = 2073; em[1992] = 120; 
    	em[1993] = 2076; em[1994] = 128; 
    	em[1995] = 2079; em[1996] = 136; 
    	em[1997] = 2082; em[1998] = 144; 
    	em[1999] = 2085; em[2000] = 152; 
    	em[2001] = 2088; em[2002] = 160; 
    	em[2003] = 2091; em[2004] = 168; 
    	em[2005] = 2094; em[2006] = 176; 
    	em[2007] = 2097; em[2008] = 184; 
    	em[2009] = 2100; em[2010] = 192; 
    	em[2011] = 2103; em[2012] = 200; 
    	em[2013] = 2106; em[2014] = 208; 
    	em[2015] = 2097; em[2016] = 216; 
    	em[2017] = 2109; em[2018] = 224; 
    	em[2019] = 2112; em[2020] = 232; 
    	em[2021] = 2115; em[2022] = 240; 
    	em[2023] = 2052; em[2024] = 248; 
    	em[2025] = 2118; em[2026] = 256; 
    	em[2027] = 2121; em[2028] = 264; 
    	em[2029] = 2118; em[2030] = 272; 
    	em[2031] = 2121; em[2032] = 280; 
    	em[2033] = 2121; em[2034] = 288; 
    	em[2035] = 2124; em[2036] = 296; 
    em[2037] = 8884097; em[2038] = 8; em[2039] = 0; /* 2037: pointer.func */
    em[2040] = 8884097; em[2041] = 8; em[2042] = 0; /* 2040: pointer.func */
    em[2043] = 8884097; em[2044] = 8; em[2045] = 0; /* 2043: pointer.func */
    em[2046] = 8884097; em[2047] = 8; em[2048] = 0; /* 2046: pointer.func */
    em[2049] = 8884097; em[2050] = 8; em[2051] = 0; /* 2049: pointer.func */
    em[2052] = 8884097; em[2053] = 8; em[2054] = 0; /* 2052: pointer.func */
    em[2055] = 8884097; em[2056] = 8; em[2057] = 0; /* 2055: pointer.func */
    em[2058] = 8884097; em[2059] = 8; em[2060] = 0; /* 2058: pointer.func */
    em[2061] = 8884097; em[2062] = 8; em[2063] = 0; /* 2061: pointer.func */
    em[2064] = 8884097; em[2065] = 8; em[2066] = 0; /* 2064: pointer.func */
    em[2067] = 8884097; em[2068] = 8; em[2069] = 0; /* 2067: pointer.func */
    em[2070] = 8884097; em[2071] = 8; em[2072] = 0; /* 2070: pointer.func */
    em[2073] = 8884097; em[2074] = 8; em[2075] = 0; /* 2073: pointer.func */
    em[2076] = 8884097; em[2077] = 8; em[2078] = 0; /* 2076: pointer.func */
    em[2079] = 8884097; em[2080] = 8; em[2081] = 0; /* 2079: pointer.func */
    em[2082] = 8884097; em[2083] = 8; em[2084] = 0; /* 2082: pointer.func */
    em[2085] = 8884097; em[2086] = 8; em[2087] = 0; /* 2085: pointer.func */
    em[2088] = 8884097; em[2089] = 8; em[2090] = 0; /* 2088: pointer.func */
    em[2091] = 8884097; em[2092] = 8; em[2093] = 0; /* 2091: pointer.func */
    em[2094] = 8884097; em[2095] = 8; em[2096] = 0; /* 2094: pointer.func */
    em[2097] = 8884097; em[2098] = 8; em[2099] = 0; /* 2097: pointer.func */
    em[2100] = 8884097; em[2101] = 8; em[2102] = 0; /* 2100: pointer.func */
    em[2103] = 8884097; em[2104] = 8; em[2105] = 0; /* 2103: pointer.func */
    em[2106] = 8884097; em[2107] = 8; em[2108] = 0; /* 2106: pointer.func */
    em[2109] = 8884097; em[2110] = 8; em[2111] = 0; /* 2109: pointer.func */
    em[2112] = 8884097; em[2113] = 8; em[2114] = 0; /* 2112: pointer.func */
    em[2115] = 8884097; em[2116] = 8; em[2117] = 0; /* 2115: pointer.func */
    em[2118] = 8884097; em[2119] = 8; em[2120] = 0; /* 2118: pointer.func */
    em[2121] = 8884097; em[2122] = 8; em[2123] = 0; /* 2121: pointer.func */
    em[2124] = 8884097; em[2125] = 8; em[2126] = 0; /* 2124: pointer.func */
    em[2127] = 0; em[2128] = 24; em[2129] = 1; /* 2127: struct.bignum_st */
    	em[2130] = 2132; em[2131] = 0; 
    em[2132] = 8884099; em[2133] = 8; em[2134] = 2; /* 2132: pointer_to_array_of_pointers_to_stack */
    	em[2135] = 1936; em[2136] = 0; 
    	em[2137] = 246; em[2138] = 12; 
    em[2139] = 0; em[2140] = 40; em[2141] = 5; /* 2139: struct.ec_extra_data_st */
    	em[2142] = 2152; em[2143] = 0; 
    	em[2144] = 1910; em[2145] = 8; 
    	em[2146] = 1913; em[2147] = 16; 
    	em[2148] = 1916; em[2149] = 24; 
    	em[2150] = 1916; em[2151] = 32; 
    em[2152] = 1; em[2153] = 8; em[2154] = 1; /* 2152: pointer.struct.ec_extra_data_st */
    	em[2155] = 2139; em[2156] = 0; 
    em[2157] = 0; em[2158] = 24; em[2159] = 1; /* 2157: struct.bignum_st */
    	em[2160] = 2162; em[2161] = 0; 
    em[2162] = 8884099; em[2163] = 8; em[2164] = 2; /* 2162: pointer_to_array_of_pointers_to_stack */
    	em[2165] = 1936; em[2166] = 0; 
    	em[2167] = 246; em[2168] = 12; 
    em[2169] = 8884097; em[2170] = 8; em[2171] = 0; /* 2169: pointer.func */
    em[2172] = 8884097; em[2173] = 8; em[2174] = 0; /* 2172: pointer.func */
    em[2175] = 8884097; em[2176] = 8; em[2177] = 0; /* 2175: pointer.func */
    em[2178] = 8884097; em[2179] = 8; em[2180] = 0; /* 2178: pointer.func */
    em[2181] = 8884097; em[2182] = 8; em[2183] = 0; /* 2181: pointer.func */
    em[2184] = 8884097; em[2185] = 8; em[2186] = 0; /* 2184: pointer.func */
    em[2187] = 8884097; em[2188] = 8; em[2189] = 0; /* 2187: pointer.func */
    em[2190] = 8884097; em[2191] = 8; em[2192] = 0; /* 2190: pointer.func */
    em[2193] = 0; em[2194] = 32; em[2195] = 3; /* 2193: struct.ecdh_method */
    	em[2196] = 26; em[2197] = 0; 
    	em[2198] = 2202; em[2199] = 8; 
    	em[2200] = 92; em[2201] = 24; 
    em[2202] = 8884097; em[2203] = 8; em[2204] = 0; /* 2202: pointer.func */
    em[2205] = 0; em[2206] = 16; em[2207] = 1; /* 2205: struct.crypto_threadid_st */
    	em[2208] = 1910; em[2209] = 0; 
    em[2210] = 8884097; em[2211] = 8; em[2212] = 0; /* 2210: pointer.func */
    em[2213] = 8884097; em[2214] = 8; em[2215] = 0; /* 2213: pointer.func */
    em[2216] = 8884097; em[2217] = 8; em[2218] = 0; /* 2216: pointer.func */
    em[2219] = 0; em[2220] = 24; em[2221] = 1; /* 2219: struct.ASN1_ENCODING_st */
    	em[2222] = 107; em[2223] = 0; 
    em[2224] = 8884097; em[2225] = 8; em[2226] = 0; /* 2224: pointer.func */
    em[2227] = 8884097; em[2228] = 8; em[2229] = 0; /* 2227: pointer.func */
    em[2230] = 1; em[2231] = 8; em[2232] = 1; /* 2230: pointer.struct.asn1_string_st */
    	em[2233] = 257; em[2234] = 0; 
    em[2235] = 8884097; em[2236] = 8; em[2237] = 0; /* 2235: pointer.func */
    em[2238] = 8884097; em[2239] = 8; em[2240] = 0; /* 2238: pointer.func */
    em[2241] = 8884097; em[2242] = 8; em[2243] = 0; /* 2241: pointer.func */
    em[2244] = 8884097; em[2245] = 8; em[2246] = 0; /* 2244: pointer.func */
    em[2247] = 8884097; em[2248] = 8; em[2249] = 0; /* 2247: pointer.func */
    em[2250] = 0; em[2251] = 232; em[2252] = 12; /* 2250: struct.ec_group_st */
    	em[2253] = 2277; em[2254] = 0; 
    	em[2255] = 2446; em[2256] = 8; 
    	em[2257] = 2157; em[2258] = 16; 
    	em[2259] = 2157; em[2260] = 40; 
    	em[2261] = 107; em[2262] = 80; 
    	em[2263] = 2451; em[2264] = 96; 
    	em[2265] = 2157; em[2266] = 104; 
    	em[2267] = 2157; em[2268] = 152; 
    	em[2269] = 2157; em[2270] = 176; 
    	em[2271] = 1910; em[2272] = 208; 
    	em[2273] = 1910; em[2274] = 216; 
    	em[2275] = 2456; em[2276] = 224; 
    em[2277] = 1; em[2278] = 8; em[2279] = 1; /* 2277: pointer.struct.ec_method_st */
    	em[2280] = 2282; em[2281] = 0; 
    em[2282] = 0; em[2283] = 304; em[2284] = 37; /* 2282: struct.ec_method_st */
    	em[2285] = 2359; em[2286] = 8; 
    	em[2287] = 2362; em[2288] = 16; 
    	em[2289] = 2362; em[2290] = 24; 
    	em[2291] = 2365; em[2292] = 32; 
    	em[2293] = 2368; em[2294] = 40; 
    	em[2295] = 2371; em[2296] = 48; 
    	em[2297] = 2374; em[2298] = 56; 
    	em[2299] = 2377; em[2300] = 64; 
    	em[2301] = 2380; em[2302] = 72; 
    	em[2303] = 2383; em[2304] = 80; 
    	em[2305] = 2383; em[2306] = 88; 
    	em[2307] = 2386; em[2308] = 96; 
    	em[2309] = 2389; em[2310] = 104; 
    	em[2311] = 2392; em[2312] = 112; 
    	em[2313] = 2395; em[2314] = 120; 
    	em[2315] = 2398; em[2316] = 128; 
    	em[2317] = 2401; em[2318] = 136; 
    	em[2319] = 2404; em[2320] = 144; 
    	em[2321] = 2407; em[2322] = 152; 
    	em[2323] = 2410; em[2324] = 160; 
    	em[2325] = 2413; em[2326] = 168; 
    	em[2327] = 2416; em[2328] = 176; 
    	em[2329] = 2419; em[2330] = 184; 
    	em[2331] = 2422; em[2332] = 192; 
    	em[2333] = 2425; em[2334] = 200; 
    	em[2335] = 2428; em[2336] = 208; 
    	em[2337] = 2419; em[2338] = 216; 
    	em[2339] = 2431; em[2340] = 224; 
    	em[2341] = 2434; em[2342] = 232; 
    	em[2343] = 2178; em[2344] = 240; 
    	em[2345] = 2374; em[2346] = 248; 
    	em[2347] = 2437; em[2348] = 256; 
    	em[2349] = 2440; em[2350] = 264; 
    	em[2351] = 2437; em[2352] = 272; 
    	em[2353] = 2440; em[2354] = 280; 
    	em[2355] = 2440; em[2356] = 288; 
    	em[2357] = 2443; em[2358] = 296; 
    em[2359] = 8884097; em[2360] = 8; em[2361] = 0; /* 2359: pointer.func */
    em[2362] = 8884097; em[2363] = 8; em[2364] = 0; /* 2362: pointer.func */
    em[2365] = 8884097; em[2366] = 8; em[2367] = 0; /* 2365: pointer.func */
    em[2368] = 8884097; em[2369] = 8; em[2370] = 0; /* 2368: pointer.func */
    em[2371] = 8884097; em[2372] = 8; em[2373] = 0; /* 2371: pointer.func */
    em[2374] = 8884097; em[2375] = 8; em[2376] = 0; /* 2374: pointer.func */
    em[2377] = 8884097; em[2378] = 8; em[2379] = 0; /* 2377: pointer.func */
    em[2380] = 8884097; em[2381] = 8; em[2382] = 0; /* 2380: pointer.func */
    em[2383] = 8884097; em[2384] = 8; em[2385] = 0; /* 2383: pointer.func */
    em[2386] = 8884097; em[2387] = 8; em[2388] = 0; /* 2386: pointer.func */
    em[2389] = 8884097; em[2390] = 8; em[2391] = 0; /* 2389: pointer.func */
    em[2392] = 8884097; em[2393] = 8; em[2394] = 0; /* 2392: pointer.func */
    em[2395] = 8884097; em[2396] = 8; em[2397] = 0; /* 2395: pointer.func */
    em[2398] = 8884097; em[2399] = 8; em[2400] = 0; /* 2398: pointer.func */
    em[2401] = 8884097; em[2402] = 8; em[2403] = 0; /* 2401: pointer.func */
    em[2404] = 8884097; em[2405] = 8; em[2406] = 0; /* 2404: pointer.func */
    em[2407] = 8884097; em[2408] = 8; em[2409] = 0; /* 2407: pointer.func */
    em[2410] = 8884097; em[2411] = 8; em[2412] = 0; /* 2410: pointer.func */
    em[2413] = 8884097; em[2414] = 8; em[2415] = 0; /* 2413: pointer.func */
    em[2416] = 8884097; em[2417] = 8; em[2418] = 0; /* 2416: pointer.func */
    em[2419] = 8884097; em[2420] = 8; em[2421] = 0; /* 2419: pointer.func */
    em[2422] = 8884097; em[2423] = 8; em[2424] = 0; /* 2422: pointer.func */
    em[2425] = 8884097; em[2426] = 8; em[2427] = 0; /* 2425: pointer.func */
    em[2428] = 8884097; em[2429] = 8; em[2430] = 0; /* 2428: pointer.func */
    em[2431] = 8884097; em[2432] = 8; em[2433] = 0; /* 2431: pointer.func */
    em[2434] = 8884097; em[2435] = 8; em[2436] = 0; /* 2434: pointer.func */
    em[2437] = 8884097; em[2438] = 8; em[2439] = 0; /* 2437: pointer.func */
    em[2440] = 8884097; em[2441] = 8; em[2442] = 0; /* 2440: pointer.func */
    em[2443] = 8884097; em[2444] = 8; em[2445] = 0; /* 2443: pointer.func */
    em[2446] = 1; em[2447] = 8; em[2448] = 1; /* 2446: pointer.struct.ec_point_st */
    	em[2449] = 1944; em[2450] = 0; 
    em[2451] = 1; em[2452] = 8; em[2453] = 1; /* 2451: pointer.struct.ec_extra_data_st */
    	em[2454] = 2139; em[2455] = 0; 
    em[2456] = 8884097; em[2457] = 8; em[2458] = 0; /* 2456: pointer.func */
    em[2459] = 8884097; em[2460] = 8; em[2461] = 0; /* 2459: pointer.func */
    em[2462] = 8884097; em[2463] = 8; em[2464] = 0; /* 2462: pointer.func */
    em[2465] = 0; em[2466] = 96; em[2467] = 3; /* 2465: struct.bn_mont_ctx_st */
    	em[2468] = 2474; em[2469] = 8; 
    	em[2470] = 2474; em[2471] = 32; 
    	em[2472] = 2474; em[2473] = 56; 
    em[2474] = 0; em[2475] = 24; em[2476] = 1; /* 2474: struct.bignum_st */
    	em[2477] = 2479; em[2478] = 0; 
    em[2479] = 8884099; em[2480] = 8; em[2481] = 2; /* 2479: pointer_to_array_of_pointers_to_stack */
    	em[2482] = 1936; em[2483] = 0; 
    	em[2484] = 246; em[2485] = 12; 
    em[2486] = 1; em[2487] = 8; em[2488] = 1; /* 2486: pointer.struct.rsa_meth_st */
    	em[2489] = 2491; em[2490] = 0; 
    em[2491] = 0; em[2492] = 112; em[2493] = 13; /* 2491: struct.rsa_meth_st */
    	em[2494] = 26; em[2495] = 0; 
    	em[2496] = 2520; em[2497] = 8; 
    	em[2498] = 2520; em[2499] = 16; 
    	em[2500] = 2520; em[2501] = 24; 
    	em[2502] = 2520; em[2503] = 32; 
    	em[2504] = 2523; em[2505] = 40; 
    	em[2506] = 2462; em[2507] = 48; 
    	em[2508] = 2459; em[2509] = 56; 
    	em[2510] = 2459; em[2511] = 64; 
    	em[2512] = 92; em[2513] = 80; 
    	em[2514] = 2526; em[2515] = 88; 
    	em[2516] = 2247; em[2517] = 96; 
    	em[2518] = 2529; em[2519] = 104; 
    em[2520] = 8884097; em[2521] = 8; em[2522] = 0; /* 2520: pointer.func */
    em[2523] = 8884097; em[2524] = 8; em[2525] = 0; /* 2523: pointer.func */
    em[2526] = 8884097; em[2527] = 8; em[2528] = 0; /* 2526: pointer.func */
    em[2529] = 8884097; em[2530] = 8; em[2531] = 0; /* 2529: pointer.func */
    em[2532] = 8884097; em[2533] = 8; em[2534] = 0; /* 2532: pointer.func */
    em[2535] = 1; em[2536] = 8; em[2537] = 1; /* 2535: pointer.struct.AUTHORITY_KEYID_st */
    	em[2538] = 2540; em[2539] = 0; 
    em[2540] = 0; em[2541] = 24; em[2542] = 3; /* 2540: struct.AUTHORITY_KEYID_st */
    	em[2543] = 2549; em[2544] = 0; 
    	em[2545] = 1443; em[2546] = 8; 
    	em[2547] = 1409; em[2548] = 16; 
    em[2549] = 1; em[2550] = 8; em[2551] = 1; /* 2549: pointer.struct.asn1_string_st */
    	em[2552] = 1414; em[2553] = 0; 
    em[2554] = 0; em[2555] = 216; em[2556] = 24; /* 2554: struct.engine_st */
    	em[2557] = 26; em[2558] = 0; 
    	em[2559] = 26; em[2560] = 8; 
    	em[2561] = 2486; em[2562] = 16; 
    	em[2563] = 2605; em[2564] = 24; 
    	em[2565] = 2641; em[2566] = 32; 
    	em[2567] = 2668; em[2568] = 40; 
    	em[2569] = 2673; em[2570] = 48; 
    	em[2571] = 2697; em[2572] = 56; 
    	em[2573] = 2726; em[2574] = 64; 
    	em[2575] = 2181; em[2576] = 72; 
    	em[2577] = 2734; em[2578] = 80; 
    	em[2579] = 2737; em[2580] = 88; 
    	em[2581] = 2740; em[2582] = 96; 
    	em[2583] = 2743; em[2584] = 104; 
    	em[2585] = 2743; em[2586] = 112; 
    	em[2587] = 2743; em[2588] = 120; 
    	em[2589] = 2746; em[2590] = 128; 
    	em[2591] = 2749; em[2592] = 136; 
    	em[2593] = 2749; em[2594] = 144; 
    	em[2595] = 2752; em[2596] = 152; 
    	em[2597] = 2755; em[2598] = 160; 
    	em[2599] = 2767; em[2600] = 184; 
    	em[2601] = 2781; em[2602] = 200; 
    	em[2603] = 2781; em[2604] = 208; 
    em[2605] = 1; em[2606] = 8; em[2607] = 1; /* 2605: pointer.struct.dsa_method */
    	em[2608] = 2610; em[2609] = 0; 
    em[2610] = 0; em[2611] = 96; em[2612] = 11; /* 2610: struct.dsa_method */
    	em[2613] = 26; em[2614] = 0; 
    	em[2615] = 2241; em[2616] = 8; 
    	em[2617] = 2635; em[2618] = 16; 
    	em[2619] = 2638; em[2620] = 24; 
    	em[2621] = 2238; em[2622] = 32; 
    	em[2623] = 2216; em[2624] = 40; 
    	em[2625] = 2172; em[2626] = 48; 
    	em[2627] = 2172; em[2628] = 56; 
    	em[2629] = 92; em[2630] = 72; 
    	em[2631] = 2532; em[2632] = 80; 
    	em[2633] = 2172; em[2634] = 88; 
    em[2635] = 8884097; em[2636] = 8; em[2637] = 0; /* 2635: pointer.func */
    em[2638] = 8884097; em[2639] = 8; em[2640] = 0; /* 2638: pointer.func */
    em[2641] = 1; em[2642] = 8; em[2643] = 1; /* 2641: pointer.struct.dh_method */
    	em[2644] = 2646; em[2645] = 0; 
    em[2646] = 0; em[2647] = 72; em[2648] = 8; /* 2646: struct.dh_method */
    	em[2649] = 26; em[2650] = 0; 
    	em[2651] = 2665; em[2652] = 8; 
    	em[2653] = 2244; em[2654] = 16; 
    	em[2655] = 2224; em[2656] = 24; 
    	em[2657] = 2665; em[2658] = 32; 
    	em[2659] = 2665; em[2660] = 40; 
    	em[2661] = 92; em[2662] = 56; 
    	em[2663] = 2213; em[2664] = 64; 
    em[2665] = 8884097; em[2666] = 8; em[2667] = 0; /* 2665: pointer.func */
    em[2668] = 1; em[2669] = 8; em[2670] = 1; /* 2668: pointer.struct.ecdh_method */
    	em[2671] = 2193; em[2672] = 0; 
    em[2673] = 1; em[2674] = 8; em[2675] = 1; /* 2673: pointer.struct.ecdsa_method */
    	em[2676] = 2678; em[2677] = 0; 
    em[2678] = 0; em[2679] = 48; em[2680] = 5; /* 2678: struct.ecdsa_method */
    	em[2681] = 26; em[2682] = 0; 
    	em[2683] = 2187; em[2684] = 8; 
    	em[2685] = 2691; em[2686] = 16; 
    	em[2687] = 2694; em[2688] = 24; 
    	em[2689] = 92; em[2690] = 40; 
    em[2691] = 8884097; em[2692] = 8; em[2693] = 0; /* 2691: pointer.func */
    em[2694] = 8884097; em[2695] = 8; em[2696] = 0; /* 2694: pointer.func */
    em[2697] = 1; em[2698] = 8; em[2699] = 1; /* 2697: pointer.struct.rand_meth_st */
    	em[2700] = 2702; em[2701] = 0; 
    em[2702] = 0; em[2703] = 48; em[2704] = 6; /* 2702: struct.rand_meth_st */
    	em[2705] = 2717; em[2706] = 0; 
    	em[2707] = 2720; em[2708] = 8; 
    	em[2709] = 2184; em[2710] = 16; 
    	em[2711] = 2723; em[2712] = 24; 
    	em[2713] = 2720; em[2714] = 32; 
    	em[2715] = 2169; em[2716] = 40; 
    em[2717] = 8884097; em[2718] = 8; em[2719] = 0; /* 2717: pointer.func */
    em[2720] = 8884097; em[2721] = 8; em[2722] = 0; /* 2720: pointer.func */
    em[2723] = 8884097; em[2724] = 8; em[2725] = 0; /* 2723: pointer.func */
    em[2726] = 1; em[2727] = 8; em[2728] = 1; /* 2726: pointer.struct.store_method_st */
    	em[2729] = 2731; em[2730] = 0; 
    em[2731] = 0; em[2732] = 0; em[2733] = 0; /* 2731: struct.store_method_st */
    em[2734] = 8884097; em[2735] = 8; em[2736] = 0; /* 2734: pointer.func */
    em[2737] = 8884097; em[2738] = 8; em[2739] = 0; /* 2737: pointer.func */
    em[2740] = 8884097; em[2741] = 8; em[2742] = 0; /* 2740: pointer.func */
    em[2743] = 8884097; em[2744] = 8; em[2745] = 0; /* 2743: pointer.func */
    em[2746] = 8884097; em[2747] = 8; em[2748] = 0; /* 2746: pointer.func */
    em[2749] = 8884097; em[2750] = 8; em[2751] = 0; /* 2749: pointer.func */
    em[2752] = 8884097; em[2753] = 8; em[2754] = 0; /* 2752: pointer.func */
    em[2755] = 1; em[2756] = 8; em[2757] = 1; /* 2755: pointer.struct.ENGINE_CMD_DEFN_st */
    	em[2758] = 2760; em[2759] = 0; 
    em[2760] = 0; em[2761] = 32; em[2762] = 2; /* 2760: struct.ENGINE_CMD_DEFN_st */
    	em[2763] = 26; em[2764] = 8; 
    	em[2765] = 26; em[2766] = 16; 
    em[2767] = 0; em[2768] = 32; em[2769] = 2; /* 2767: struct.crypto_ex_data_st_fake */
    	em[2770] = 2774; em[2771] = 8; 
    	em[2772] = 249; em[2773] = 24; 
    em[2774] = 8884099; em[2775] = 8; em[2776] = 2; /* 2774: pointer_to_array_of_pointers_to_stack */
    	em[2777] = 1910; em[2778] = 0; 
    	em[2779] = 246; em[2780] = 20; 
    em[2781] = 1; em[2782] = 8; em[2783] = 1; /* 2781: pointer.struct.engine_st */
    	em[2784] = 2554; em[2785] = 0; 
    em[2786] = 8884097; em[2787] = 8; em[2788] = 0; /* 2786: pointer.func */
    em[2789] = 8884097; em[2790] = 8; em[2791] = 0; /* 2789: pointer.func */
    em[2792] = 8884097; em[2793] = 8; em[2794] = 0; /* 2792: pointer.func */
    em[2795] = 8884097; em[2796] = 8; em[2797] = 0; /* 2795: pointer.func */
    em[2798] = 8884097; em[2799] = 8; em[2800] = 0; /* 2798: pointer.func */
    em[2801] = 1; em[2802] = 8; em[2803] = 1; /* 2801: pointer.struct.buf_mem_st */
    	em[2804] = 2806; em[2805] = 0; 
    em[2806] = 0; em[2807] = 24; em[2808] = 1; /* 2806: struct.buf_mem_st */
    	em[2809] = 92; em[2810] = 8; 
    em[2811] = 0; em[2812] = 1; em[2813] = 0; /* 2811: char */
    em[2814] = 8884097; em[2815] = 8; em[2816] = 0; /* 2814: pointer.func */
    em[2817] = 8884097; em[2818] = 8; em[2819] = 0; /* 2817: pointer.func */
    em[2820] = 8884097; em[2821] = 8; em[2822] = 0; /* 2820: pointer.func */
    em[2823] = 0; em[2824] = 208; em[2825] = 24; /* 2823: struct.evp_pkey_asn1_method_st */
    	em[2826] = 92; em[2827] = 16; 
    	em[2828] = 92; em[2829] = 24; 
    	em[2830] = 2792; em[2831] = 32; 
    	em[2832] = 2820; em[2833] = 40; 
    	em[2834] = 2874; em[2835] = 48; 
    	em[2836] = 2817; em[2837] = 56; 
    	em[2838] = 2814; em[2839] = 64; 
    	em[2840] = 2877; em[2841] = 72; 
    	em[2842] = 2817; em[2843] = 80; 
    	em[2844] = 2880; em[2845] = 88; 
    	em[2846] = 2880; em[2847] = 96; 
    	em[2848] = 2883; em[2849] = 104; 
    	em[2850] = 2798; em[2851] = 112; 
    	em[2852] = 2880; em[2853] = 120; 
    	em[2854] = 2886; em[2855] = 128; 
    	em[2856] = 2874; em[2857] = 136; 
    	em[2858] = 2817; em[2859] = 144; 
    	em[2860] = 2795; em[2861] = 152; 
    	em[2862] = 2789; em[2863] = 160; 
    	em[2864] = 2889; em[2865] = 168; 
    	em[2866] = 2883; em[2867] = 176; 
    	em[2868] = 2798; em[2869] = 184; 
    	em[2870] = 2786; em[2871] = 192; 
    	em[2872] = 2892; em[2873] = 200; 
    em[2874] = 8884097; em[2875] = 8; em[2876] = 0; /* 2874: pointer.func */
    em[2877] = 8884097; em[2878] = 8; em[2879] = 0; /* 2877: pointer.func */
    em[2880] = 8884097; em[2881] = 8; em[2882] = 0; /* 2880: pointer.func */
    em[2883] = 8884097; em[2884] = 8; em[2885] = 0; /* 2883: pointer.func */
    em[2886] = 8884097; em[2887] = 8; em[2888] = 0; /* 2886: pointer.func */
    em[2889] = 8884097; em[2890] = 8; em[2891] = 0; /* 2889: pointer.func */
    em[2892] = 8884097; em[2893] = 8; em[2894] = 0; /* 2892: pointer.func */
    em[2895] = 1; em[2896] = 8; em[2897] = 1; /* 2895: pointer.struct.evp_pkey_asn1_method_st */
    	em[2898] = 2823; em[2899] = 0; 
    em[2900] = 0; em[2901] = 56; em[2902] = 4; /* 2900: struct.evp_pkey_st */
    	em[2903] = 2895; em[2904] = 16; 
    	em[2905] = 2911; em[2906] = 24; 
    	em[2907] = 2916; em[2908] = 32; 
    	em[2909] = 3371; em[2910] = 48; 
    em[2911] = 1; em[2912] = 8; em[2913] = 1; /* 2911: pointer.struct.engine_st */
    	em[2914] = 2554; em[2915] = 0; 
    em[2916] = 0; em[2917] = 8; em[2918] = 5; /* 2916: union.unknown */
    	em[2919] = 92; em[2920] = 0; 
    	em[2921] = 2929; em[2922] = 0; 
    	em[2923] = 3105; em[2924] = 0; 
    	em[2925] = 3230; em[2926] = 0; 
    	em[2927] = 3345; em[2928] = 0; 
    em[2929] = 1; em[2930] = 8; em[2931] = 1; /* 2929: pointer.struct.rsa_st */
    	em[2932] = 2934; em[2933] = 0; 
    em[2934] = 0; em[2935] = 168; em[2936] = 17; /* 2934: struct.rsa_st */
    	em[2937] = 2971; em[2938] = 16; 
    	em[2939] = 3020; em[2940] = 24; 
    	em[2941] = 3025; em[2942] = 32; 
    	em[2943] = 3025; em[2944] = 40; 
    	em[2945] = 3025; em[2946] = 48; 
    	em[2947] = 3025; em[2948] = 56; 
    	em[2949] = 3025; em[2950] = 64; 
    	em[2951] = 3025; em[2952] = 72; 
    	em[2953] = 3025; em[2954] = 80; 
    	em[2955] = 3025; em[2956] = 88; 
    	em[2957] = 3030; em[2958] = 96; 
    	em[2959] = 3044; em[2960] = 120; 
    	em[2961] = 3044; em[2962] = 128; 
    	em[2963] = 3044; em[2964] = 136; 
    	em[2965] = 92; em[2966] = 144; 
    	em[2967] = 3049; em[2968] = 152; 
    	em[2969] = 3049; em[2970] = 160; 
    em[2971] = 1; em[2972] = 8; em[2973] = 1; /* 2971: pointer.struct.rsa_meth_st */
    	em[2974] = 2976; em[2975] = 0; 
    em[2976] = 0; em[2977] = 112; em[2978] = 13; /* 2976: struct.rsa_meth_st */
    	em[2979] = 26; em[2980] = 0; 
    	em[2981] = 2175; em[2982] = 8; 
    	em[2983] = 2175; em[2984] = 16; 
    	em[2985] = 2175; em[2986] = 24; 
    	em[2987] = 2175; em[2988] = 32; 
    	em[2989] = 3005; em[2990] = 40; 
    	em[2991] = 2190; em[2992] = 48; 
    	em[2993] = 3008; em[2994] = 56; 
    	em[2995] = 3008; em[2996] = 64; 
    	em[2997] = 92; em[2998] = 80; 
    	em[2999] = 3011; em[3000] = 88; 
    	em[3001] = 3014; em[3002] = 96; 
    	em[3003] = 3017; em[3004] = 104; 
    em[3005] = 8884097; em[3006] = 8; em[3007] = 0; /* 3005: pointer.func */
    em[3008] = 8884097; em[3009] = 8; em[3010] = 0; /* 3008: pointer.func */
    em[3011] = 8884097; em[3012] = 8; em[3013] = 0; /* 3011: pointer.func */
    em[3014] = 8884097; em[3015] = 8; em[3016] = 0; /* 3014: pointer.func */
    em[3017] = 8884097; em[3018] = 8; em[3019] = 0; /* 3017: pointer.func */
    em[3020] = 1; em[3021] = 8; em[3022] = 1; /* 3020: pointer.struct.engine_st */
    	em[3023] = 2554; em[3024] = 0; 
    em[3025] = 1; em[3026] = 8; em[3027] = 1; /* 3025: pointer.struct.bignum_st */
    	em[3028] = 2474; em[3029] = 0; 
    em[3030] = 0; em[3031] = 32; em[3032] = 2; /* 3030: struct.crypto_ex_data_st_fake */
    	em[3033] = 3037; em[3034] = 8; 
    	em[3035] = 249; em[3036] = 24; 
    em[3037] = 8884099; em[3038] = 8; em[3039] = 2; /* 3037: pointer_to_array_of_pointers_to_stack */
    	em[3040] = 1910; em[3041] = 0; 
    	em[3042] = 246; em[3043] = 20; 
    em[3044] = 1; em[3045] = 8; em[3046] = 1; /* 3044: pointer.struct.bn_mont_ctx_st */
    	em[3047] = 2465; em[3048] = 0; 
    em[3049] = 1; em[3050] = 8; em[3051] = 1; /* 3049: pointer.struct.bn_blinding_st */
    	em[3052] = 3054; em[3053] = 0; 
    em[3054] = 0; em[3055] = 88; em[3056] = 7; /* 3054: struct.bn_blinding_st */
    	em[3057] = 3071; em[3058] = 0; 
    	em[3059] = 3071; em[3060] = 8; 
    	em[3061] = 3071; em[3062] = 16; 
    	em[3063] = 3071; em[3064] = 24; 
    	em[3065] = 2205; em[3066] = 40; 
    	em[3067] = 3088; em[3068] = 72; 
    	em[3069] = 3102; em[3070] = 80; 
    em[3071] = 1; em[3072] = 8; em[3073] = 1; /* 3071: pointer.struct.bignum_st */
    	em[3074] = 3076; em[3075] = 0; 
    em[3076] = 0; em[3077] = 24; em[3078] = 1; /* 3076: struct.bignum_st */
    	em[3079] = 3081; em[3080] = 0; 
    em[3081] = 8884099; em[3082] = 8; em[3083] = 2; /* 3081: pointer_to_array_of_pointers_to_stack */
    	em[3084] = 1936; em[3085] = 0; 
    	em[3086] = 246; em[3087] = 12; 
    em[3088] = 1; em[3089] = 8; em[3090] = 1; /* 3088: pointer.struct.bn_mont_ctx_st */
    	em[3091] = 3093; em[3092] = 0; 
    em[3093] = 0; em[3094] = 96; em[3095] = 3; /* 3093: struct.bn_mont_ctx_st */
    	em[3096] = 3076; em[3097] = 8; 
    	em[3098] = 3076; em[3099] = 32; 
    	em[3100] = 3076; em[3101] = 56; 
    em[3102] = 8884097; em[3103] = 8; em[3104] = 0; /* 3102: pointer.func */
    em[3105] = 1; em[3106] = 8; em[3107] = 1; /* 3105: pointer.struct.dsa_st */
    	em[3108] = 3110; em[3109] = 0; 
    em[3110] = 0; em[3111] = 136; em[3112] = 11; /* 3110: struct.dsa_st */
    	em[3113] = 3135; em[3114] = 24; 
    	em[3115] = 3135; em[3116] = 32; 
    	em[3117] = 3135; em[3118] = 40; 
    	em[3119] = 3135; em[3120] = 48; 
    	em[3121] = 3135; em[3122] = 56; 
    	em[3123] = 3135; em[3124] = 64; 
    	em[3125] = 3135; em[3126] = 72; 
    	em[3127] = 3152; em[3128] = 88; 
    	em[3129] = 3166; em[3130] = 104; 
    	em[3131] = 3180; em[3132] = 120; 
    	em[3133] = 3225; em[3134] = 128; 
    em[3135] = 1; em[3136] = 8; em[3137] = 1; /* 3135: pointer.struct.bignum_st */
    	em[3138] = 3140; em[3139] = 0; 
    em[3140] = 0; em[3141] = 24; em[3142] = 1; /* 3140: struct.bignum_st */
    	em[3143] = 3145; em[3144] = 0; 
    em[3145] = 8884099; em[3146] = 8; em[3147] = 2; /* 3145: pointer_to_array_of_pointers_to_stack */
    	em[3148] = 1936; em[3149] = 0; 
    	em[3150] = 246; em[3151] = 12; 
    em[3152] = 1; em[3153] = 8; em[3154] = 1; /* 3152: pointer.struct.bn_mont_ctx_st */
    	em[3155] = 3157; em[3156] = 0; 
    em[3157] = 0; em[3158] = 96; em[3159] = 3; /* 3157: struct.bn_mont_ctx_st */
    	em[3160] = 3140; em[3161] = 8; 
    	em[3162] = 3140; em[3163] = 32; 
    	em[3164] = 3140; em[3165] = 56; 
    em[3166] = 0; em[3167] = 32; em[3168] = 2; /* 3166: struct.crypto_ex_data_st_fake */
    	em[3169] = 3173; em[3170] = 8; 
    	em[3171] = 249; em[3172] = 24; 
    em[3173] = 8884099; em[3174] = 8; em[3175] = 2; /* 3173: pointer_to_array_of_pointers_to_stack */
    	em[3176] = 1910; em[3177] = 0; 
    	em[3178] = 246; em[3179] = 20; 
    em[3180] = 1; em[3181] = 8; em[3182] = 1; /* 3180: pointer.struct.dsa_method */
    	em[3183] = 3185; em[3184] = 0; 
    em[3185] = 0; em[3186] = 96; em[3187] = 11; /* 3185: struct.dsa_method */
    	em[3188] = 26; em[3189] = 0; 
    	em[3190] = 3210; em[3191] = 8; 
    	em[3192] = 3213; em[3193] = 16; 
    	em[3194] = 3216; em[3195] = 24; 
    	em[3196] = 2210; em[3197] = 32; 
    	em[3198] = 3219; em[3199] = 40; 
    	em[3200] = 3222; em[3201] = 48; 
    	em[3202] = 3222; em[3203] = 56; 
    	em[3204] = 92; em[3205] = 72; 
    	em[3206] = 2227; em[3207] = 80; 
    	em[3208] = 3222; em[3209] = 88; 
    em[3210] = 8884097; em[3211] = 8; em[3212] = 0; /* 3210: pointer.func */
    em[3213] = 8884097; em[3214] = 8; em[3215] = 0; /* 3213: pointer.func */
    em[3216] = 8884097; em[3217] = 8; em[3218] = 0; /* 3216: pointer.func */
    em[3219] = 8884097; em[3220] = 8; em[3221] = 0; /* 3219: pointer.func */
    em[3222] = 8884097; em[3223] = 8; em[3224] = 0; /* 3222: pointer.func */
    em[3225] = 1; em[3226] = 8; em[3227] = 1; /* 3225: pointer.struct.engine_st */
    	em[3228] = 2554; em[3229] = 0; 
    em[3230] = 1; em[3231] = 8; em[3232] = 1; /* 3230: pointer.struct.dh_st */
    	em[3233] = 3235; em[3234] = 0; 
    em[3235] = 0; em[3236] = 144; em[3237] = 12; /* 3235: struct.dh_st */
    	em[3238] = 3262; em[3239] = 8; 
    	em[3240] = 3262; em[3241] = 16; 
    	em[3242] = 3262; em[3243] = 32; 
    	em[3244] = 3262; em[3245] = 40; 
    	em[3246] = 3279; em[3247] = 56; 
    	em[3248] = 3262; em[3249] = 64; 
    	em[3250] = 3262; em[3251] = 72; 
    	em[3252] = 107; em[3253] = 80; 
    	em[3254] = 3262; em[3255] = 96; 
    	em[3256] = 3293; em[3257] = 112; 
    	em[3258] = 3307; em[3259] = 128; 
    	em[3260] = 3340; em[3261] = 136; 
    em[3262] = 1; em[3263] = 8; em[3264] = 1; /* 3262: pointer.struct.bignum_st */
    	em[3265] = 3267; em[3266] = 0; 
    em[3267] = 0; em[3268] = 24; em[3269] = 1; /* 3267: struct.bignum_st */
    	em[3270] = 3272; em[3271] = 0; 
    em[3272] = 8884099; em[3273] = 8; em[3274] = 2; /* 3272: pointer_to_array_of_pointers_to_stack */
    	em[3275] = 1936; em[3276] = 0; 
    	em[3277] = 246; em[3278] = 12; 
    em[3279] = 1; em[3280] = 8; em[3281] = 1; /* 3279: pointer.struct.bn_mont_ctx_st */
    	em[3282] = 3284; em[3283] = 0; 
    em[3284] = 0; em[3285] = 96; em[3286] = 3; /* 3284: struct.bn_mont_ctx_st */
    	em[3287] = 3267; em[3288] = 8; 
    	em[3289] = 3267; em[3290] = 32; 
    	em[3291] = 3267; em[3292] = 56; 
    em[3293] = 0; em[3294] = 32; em[3295] = 2; /* 3293: struct.crypto_ex_data_st_fake */
    	em[3296] = 3300; em[3297] = 8; 
    	em[3298] = 249; em[3299] = 24; 
    em[3300] = 8884099; em[3301] = 8; em[3302] = 2; /* 3300: pointer_to_array_of_pointers_to_stack */
    	em[3303] = 1910; em[3304] = 0; 
    	em[3305] = 246; em[3306] = 20; 
    em[3307] = 1; em[3308] = 8; em[3309] = 1; /* 3307: pointer.struct.dh_method */
    	em[3310] = 3312; em[3311] = 0; 
    em[3312] = 0; em[3313] = 72; em[3314] = 8; /* 3312: struct.dh_method */
    	em[3315] = 26; em[3316] = 0; 
    	em[3317] = 3331; em[3318] = 8; 
    	em[3319] = 3334; em[3320] = 16; 
    	em[3321] = 2235; em[3322] = 24; 
    	em[3323] = 3331; em[3324] = 32; 
    	em[3325] = 3331; em[3326] = 40; 
    	em[3327] = 92; em[3328] = 56; 
    	em[3329] = 3337; em[3330] = 64; 
    em[3331] = 8884097; em[3332] = 8; em[3333] = 0; /* 3331: pointer.func */
    em[3334] = 8884097; em[3335] = 8; em[3336] = 0; /* 3334: pointer.func */
    em[3337] = 8884097; em[3338] = 8; em[3339] = 0; /* 3337: pointer.func */
    em[3340] = 1; em[3341] = 8; em[3342] = 1; /* 3340: pointer.struct.engine_st */
    	em[3343] = 2554; em[3344] = 0; 
    em[3345] = 1; em[3346] = 8; em[3347] = 1; /* 3345: pointer.struct.ec_key_st */
    	em[3348] = 3350; em[3349] = 0; 
    em[3350] = 0; em[3351] = 56; em[3352] = 4; /* 3350: struct.ec_key_st */
    	em[3353] = 3361; em[3354] = 8; 
    	em[3355] = 1939; em[3356] = 16; 
    	em[3357] = 3366; em[3358] = 24; 
    	em[3359] = 1919; em[3360] = 48; 
    em[3361] = 1; em[3362] = 8; em[3363] = 1; /* 3361: pointer.struct.ec_group_st */
    	em[3364] = 2250; em[3365] = 0; 
    em[3366] = 1; em[3367] = 8; em[3368] = 1; /* 3366: pointer.struct.bignum_st */
    	em[3369] = 1924; em[3370] = 0; 
    em[3371] = 1; em[3372] = 8; em[3373] = 1; /* 3371: pointer.struct.stack_st_X509_ATTRIBUTE */
    	em[3374] = 3376; em[3375] = 0; 
    em[3376] = 0; em[3377] = 32; em[3378] = 2; /* 3376: struct.stack_st_fake_X509_ATTRIBUTE */
    	em[3379] = 3383; em[3380] = 8; 
    	em[3381] = 249; em[3382] = 24; 
    em[3383] = 8884099; em[3384] = 8; em[3385] = 2; /* 3383: pointer_to_array_of_pointers_to_stack */
    	em[3386] = 3390; em[3387] = 0; 
    	em[3388] = 246; em[3389] = 20; 
    em[3390] = 0; em[3391] = 8; em[3392] = 1; /* 3390: pointer.X509_ATTRIBUTE */
    	em[3393] = 3395; em[3394] = 0; 
    em[3395] = 0; em[3396] = 0; em[3397] = 1; /* 3395: X509_ATTRIBUTE */
    	em[3398] = 1885; em[3399] = 0; 
    em[3400] = 0; em[3401] = 184; em[3402] = 12; /* 3400: struct.x509_st */
    	em[3403] = 3427; em[3404] = 0; 
    	em[3405] = 3462; em[3406] = 8; 
    	em[3407] = 2230; em[3408] = 16; 
    	em[3409] = 92; em[3410] = 32; 
    	em[3411] = 3556; em[3412] = 40; 
    	em[3413] = 262; em[3414] = 104; 
    	em[3415] = 2535; em[3416] = 112; 
    	em[3417] = 3570; em[3418] = 120; 
    	em[3419] = 1467; em[3420] = 128; 
    	em[3421] = 3575; em[3422] = 136; 
    	em[3423] = 642; em[3424] = 144; 
    	em[3425] = 190; em[3426] = 176; 
    em[3427] = 1; em[3428] = 8; em[3429] = 1; /* 3427: pointer.struct.x509_cinf_st */
    	em[3430] = 3432; em[3431] = 0; 
    em[3432] = 0; em[3433] = 104; em[3434] = 11; /* 3432: struct.x509_cinf_st */
    	em[3435] = 3457; em[3436] = 0; 
    	em[3437] = 3457; em[3438] = 8; 
    	em[3439] = 3462; em[3440] = 16; 
    	em[3441] = 3467; em[3442] = 24; 
    	em[3443] = 3505; em[3444] = 32; 
    	em[3445] = 3467; em[3446] = 40; 
    	em[3447] = 3522; em[3448] = 48; 
    	em[3449] = 2230; em[3450] = 56; 
    	em[3451] = 2230; em[3452] = 64; 
    	em[3453] = 1501; em[3454] = 72; 
    	em[3455] = 2219; em[3456] = 80; 
    em[3457] = 1; em[3458] = 8; em[3459] = 1; /* 3457: pointer.struct.asn1_string_st */
    	em[3460] = 257; em[3461] = 0; 
    em[3462] = 1; em[3463] = 8; em[3464] = 1; /* 3462: pointer.struct.X509_algor_st */
    	em[3465] = 5; em[3466] = 0; 
    em[3467] = 1; em[3468] = 8; em[3469] = 1; /* 3467: pointer.struct.X509_name_st */
    	em[3470] = 3472; em[3471] = 0; 
    em[3472] = 0; em[3473] = 40; em[3474] = 3; /* 3472: struct.X509_name_st */
    	em[3475] = 3481; em[3476] = 0; 
    	em[3477] = 2801; em[3478] = 16; 
    	em[3479] = 107; em[3480] = 24; 
    em[3481] = 1; em[3482] = 8; em[3483] = 1; /* 3481: pointer.struct.stack_st_X509_NAME_ENTRY */
    	em[3484] = 3486; em[3485] = 0; 
    em[3486] = 0; em[3487] = 32; em[3488] = 2; /* 3486: struct.stack_st_fake_X509_NAME_ENTRY */
    	em[3489] = 3493; em[3490] = 8; 
    	em[3491] = 249; em[3492] = 24; 
    em[3493] = 8884099; em[3494] = 8; em[3495] = 2; /* 3493: pointer_to_array_of_pointers_to_stack */
    	em[3496] = 3500; em[3497] = 0; 
    	em[3498] = 246; em[3499] = 20; 
    em[3500] = 0; em[3501] = 8; em[3502] = 1; /* 3500: pointer.X509_NAME_ENTRY */
    	em[3503] = 337; em[3504] = 0; 
    em[3505] = 1; em[3506] = 8; em[3507] = 1; /* 3505: pointer.struct.X509_val_st */
    	em[3508] = 3510; em[3509] = 0; 
    em[3510] = 0; em[3511] = 16; em[3512] = 2; /* 3510: struct.X509_val_st */
    	em[3513] = 3517; em[3514] = 0; 
    	em[3515] = 3517; em[3516] = 8; 
    em[3517] = 1; em[3518] = 8; em[3519] = 1; /* 3517: pointer.struct.asn1_string_st */
    	em[3520] = 257; em[3521] = 0; 
    em[3522] = 1; em[3523] = 8; em[3524] = 1; /* 3522: pointer.struct.X509_pubkey_st */
    	em[3525] = 3527; em[3526] = 0; 
    em[3527] = 0; em[3528] = 24; em[3529] = 3; /* 3527: struct.X509_pubkey_st */
    	em[3530] = 3536; em[3531] = 0; 
    	em[3532] = 3541; em[3533] = 8; 
    	em[3534] = 3551; em[3535] = 16; 
    em[3536] = 1; em[3537] = 8; em[3538] = 1; /* 3536: pointer.struct.X509_algor_st */
    	em[3539] = 5; em[3540] = 0; 
    em[3541] = 1; em[3542] = 8; em[3543] = 1; /* 3541: pointer.struct.asn1_string_st */
    	em[3544] = 3546; em[3545] = 0; 
    em[3546] = 0; em[3547] = 24; em[3548] = 1; /* 3546: struct.asn1_string_st */
    	em[3549] = 107; em[3550] = 8; 
    em[3551] = 1; em[3552] = 8; em[3553] = 1; /* 3551: pointer.struct.evp_pkey_st */
    	em[3554] = 2900; em[3555] = 0; 
    em[3556] = 0; em[3557] = 32; em[3558] = 2; /* 3556: struct.crypto_ex_data_st_fake */
    	em[3559] = 3563; em[3560] = 8; 
    	em[3561] = 249; em[3562] = 24; 
    em[3563] = 8884099; em[3564] = 8; em[3565] = 2; /* 3563: pointer_to_array_of_pointers_to_stack */
    	em[3566] = 1910; em[3567] = 0; 
    	em[3568] = 246; em[3569] = 20; 
    em[3570] = 1; em[3571] = 8; em[3572] = 1; /* 3570: pointer.struct.X509_POLICY_CACHE_st */
    	em[3573] = 1368; em[3574] = 0; 
    em[3575] = 1; em[3576] = 8; em[3577] = 1; /* 3575: pointer.struct.stack_st_GENERAL_NAME */
    	em[3578] = 3580; em[3579] = 0; 
    em[3580] = 0; em[3581] = 32; em[3582] = 2; /* 3580: struct.stack_st_fake_GENERAL_NAME */
    	em[3583] = 3587; em[3584] = 8; 
    	em[3585] = 249; em[3586] = 24; 
    em[3587] = 8884099; em[3588] = 8; em[3589] = 2; /* 3587: pointer_to_array_of_pointers_to_stack */
    	em[3590] = 3594; em[3591] = 0; 
    	em[3592] = 246; em[3593] = 20; 
    em[3594] = 0; em[3595] = 8; em[3596] = 1; /* 3594: pointer.GENERAL_NAME */
    	em[3597] = 678; em[3598] = 0; 
    em[3599] = 1; em[3600] = 8; em[3601] = 1; /* 3599: pointer.int */
    	em[3602] = 246; em[3603] = 0; 
    em[3604] = 1; em[3605] = 8; em[3606] = 1; /* 3604: pointer.struct.x509_st */
    	em[3607] = 3400; em[3608] = 0; 
    args_addr->arg_entity_index[0] = 3604;
    args_addr->arg_entity_index[1] = 246;
    args_addr->arg_entity_index[2] = 3599;
    args_addr->arg_entity_index[3] = 3599;
    args_addr->ret_entity_index = 1910;
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

