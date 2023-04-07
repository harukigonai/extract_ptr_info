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

void bb_EC_GROUP_free(EC_GROUP * arg_a);

void EC_GROUP_free(EC_GROUP * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("EC_GROUP_free called %lu\n", in_lib);
    if (!in_lib)
        bb_EC_GROUP_free(arg_a);
    else {
        void (*orig_EC_GROUP_free)(EC_GROUP *);
        orig_EC_GROUP_free = dlsym(RTLD_NEXT, "EC_GROUP_free");
        orig_EC_GROUP_free(arg_a);
    }
}

void bb_EC_GROUP_free(EC_GROUP * arg_a) 
{
    struct lib_enter_args *args_addr = malloc(sizeof(struct lib_enter_args));
    memset(args_addr, 0, sizeof(struct lib_enter_args));
    args_addr->num_args = 0;
    uint32_t *em = args_addr->entity_metadata;
    em[0] = 8884097; em[1] = 8; em[2] = 0; /* 0: pointer.func */
    em[3] = 8884097; em[4] = 8; em[5] = 0; /* 3: pointer.func */
    em[6] = 0; em[7] = 40; em[8] = 5; /* 6: struct.ec_extra_data_st */
    	em[9] = 19; em[10] = 0; 
    	em[11] = 24; em[12] = 8; 
    	em[13] = 3; em[14] = 16; 
    	em[15] = 27; em[16] = 24; 
    	em[17] = 27; em[18] = 32; 
    em[19] = 1; em[20] = 8; em[21] = 1; /* 19: pointer.struct.ec_extra_data_st */
    	em[22] = 6; em[23] = 0; 
    em[24] = 0; em[25] = 8; em[26] = 0; /* 24: pointer.void */
    em[27] = 8884097; em[28] = 8; em[29] = 0; /* 27: pointer.func */
    em[30] = 1; em[31] = 8; em[32] = 1; /* 30: pointer.struct.ec_extra_data_st */
    	em[33] = 6; em[34] = 0; 
    em[35] = 0; em[36] = 4; em[37] = 0; /* 35: int */
    em[38] = 0; em[39] = 4; em[40] = 0; /* 38: unsigned int */
    em[41] = 8884099; em[42] = 8; em[43] = 2; /* 41: pointer_to_array_of_pointers_to_stack */
    	em[44] = 38; em[45] = 0; 
    	em[46] = 35; em[47] = 12; 
    em[48] = 0; em[49] = 24; em[50] = 1; /* 48: struct.bignum_st */
    	em[51] = 53; em[52] = 0; 
    em[53] = 8884099; em[54] = 8; em[55] = 2; /* 53: pointer_to_array_of_pointers_to_stack */
    	em[56] = 38; em[57] = 0; 
    	em[58] = 35; em[59] = 12; 
    em[60] = 8884097; em[61] = 8; em[62] = 0; /* 60: pointer.func */
    em[63] = 8884097; em[64] = 8; em[65] = 0; /* 63: pointer.func */
    em[66] = 8884097; em[67] = 8; em[68] = 0; /* 66: pointer.func */
    em[69] = 8884097; em[70] = 8; em[71] = 0; /* 69: pointer.func */
    em[72] = 8884097; em[73] = 8; em[74] = 0; /* 72: pointer.func */
    em[75] = 8884097; em[76] = 8; em[77] = 0; /* 75: pointer.func */
    em[78] = 8884097; em[79] = 8; em[80] = 0; /* 78: pointer.func */
    em[81] = 8884097; em[82] = 8; em[83] = 0; /* 81: pointer.func */
    em[84] = 8884097; em[85] = 8; em[86] = 0; /* 84: pointer.func */
    em[87] = 8884097; em[88] = 8; em[89] = 0; /* 87: pointer.func */
    em[90] = 0; em[91] = 232; em[92] = 12; /* 90: struct.ec_group_st */
    	em[93] = 117; em[94] = 0; 
    	em[95] = 277; em[96] = 8; 
    	em[97] = 447; em[98] = 16; 
    	em[99] = 447; em[100] = 40; 
    	em[101] = 452; em[102] = 80; 
    	em[103] = 30; em[104] = 96; 
    	em[105] = 447; em[106] = 104; 
    	em[107] = 447; em[108] = 152; 
    	em[109] = 447; em[110] = 176; 
    	em[111] = 24; em[112] = 208; 
    	em[113] = 24; em[114] = 216; 
    	em[115] = 0; em[116] = 224; 
    em[117] = 1; em[118] = 8; em[119] = 1; /* 117: pointer.struct.ec_method_st */
    	em[120] = 122; em[121] = 0; 
    em[122] = 0; em[123] = 304; em[124] = 37; /* 122: struct.ec_method_st */
    	em[125] = 199; em[126] = 8; 
    	em[127] = 202; em[128] = 16; 
    	em[129] = 202; em[130] = 24; 
    	em[131] = 205; em[132] = 32; 
    	em[133] = 208; em[134] = 40; 
    	em[135] = 211; em[136] = 48; 
    	em[137] = 214; em[138] = 56; 
    	em[139] = 217; em[140] = 64; 
    	em[141] = 220; em[142] = 72; 
    	em[143] = 223; em[144] = 80; 
    	em[145] = 223; em[146] = 88; 
    	em[147] = 226; em[148] = 96; 
    	em[149] = 229; em[150] = 104; 
    	em[151] = 232; em[152] = 112; 
    	em[153] = 235; em[154] = 120; 
    	em[155] = 238; em[156] = 128; 
    	em[157] = 241; em[158] = 136; 
    	em[159] = 244; em[160] = 144; 
    	em[161] = 247; em[162] = 152; 
    	em[163] = 250; em[164] = 160; 
    	em[165] = 87; em[166] = 168; 
    	em[167] = 81; em[168] = 176; 
    	em[169] = 253; em[170] = 184; 
    	em[171] = 78; em[172] = 192; 
    	em[173] = 256; em[174] = 200; 
    	em[175] = 259; em[176] = 208; 
    	em[177] = 253; em[178] = 216; 
    	em[179] = 75; em[180] = 224; 
    	em[181] = 262; em[182] = 232; 
    	em[183] = 265; em[184] = 240; 
    	em[185] = 214; em[186] = 248; 
    	em[187] = 268; em[188] = 256; 
    	em[189] = 271; em[190] = 264; 
    	em[191] = 268; em[192] = 272; 
    	em[193] = 271; em[194] = 280; 
    	em[195] = 271; em[196] = 288; 
    	em[197] = 274; em[198] = 296; 
    em[199] = 8884097; em[200] = 8; em[201] = 0; /* 199: pointer.func */
    em[202] = 8884097; em[203] = 8; em[204] = 0; /* 202: pointer.func */
    em[205] = 8884097; em[206] = 8; em[207] = 0; /* 205: pointer.func */
    em[208] = 8884097; em[209] = 8; em[210] = 0; /* 208: pointer.func */
    em[211] = 8884097; em[212] = 8; em[213] = 0; /* 211: pointer.func */
    em[214] = 8884097; em[215] = 8; em[216] = 0; /* 214: pointer.func */
    em[217] = 8884097; em[218] = 8; em[219] = 0; /* 217: pointer.func */
    em[220] = 8884097; em[221] = 8; em[222] = 0; /* 220: pointer.func */
    em[223] = 8884097; em[224] = 8; em[225] = 0; /* 223: pointer.func */
    em[226] = 8884097; em[227] = 8; em[228] = 0; /* 226: pointer.func */
    em[229] = 8884097; em[230] = 8; em[231] = 0; /* 229: pointer.func */
    em[232] = 8884097; em[233] = 8; em[234] = 0; /* 232: pointer.func */
    em[235] = 8884097; em[236] = 8; em[237] = 0; /* 235: pointer.func */
    em[238] = 8884097; em[239] = 8; em[240] = 0; /* 238: pointer.func */
    em[241] = 8884097; em[242] = 8; em[243] = 0; /* 241: pointer.func */
    em[244] = 8884097; em[245] = 8; em[246] = 0; /* 244: pointer.func */
    em[247] = 8884097; em[248] = 8; em[249] = 0; /* 247: pointer.func */
    em[250] = 8884097; em[251] = 8; em[252] = 0; /* 250: pointer.func */
    em[253] = 8884097; em[254] = 8; em[255] = 0; /* 253: pointer.func */
    em[256] = 8884097; em[257] = 8; em[258] = 0; /* 256: pointer.func */
    em[259] = 8884097; em[260] = 8; em[261] = 0; /* 259: pointer.func */
    em[262] = 8884097; em[263] = 8; em[264] = 0; /* 262: pointer.func */
    em[265] = 8884097; em[266] = 8; em[267] = 0; /* 265: pointer.func */
    em[268] = 8884097; em[269] = 8; em[270] = 0; /* 268: pointer.func */
    em[271] = 8884097; em[272] = 8; em[273] = 0; /* 271: pointer.func */
    em[274] = 8884097; em[275] = 8; em[276] = 0; /* 274: pointer.func */
    em[277] = 1; em[278] = 8; em[279] = 1; /* 277: pointer.struct.ec_point_st */
    	em[280] = 282; em[281] = 0; 
    em[282] = 0; em[283] = 88; em[284] = 4; /* 282: struct.ec_point_st */
    	em[285] = 293; em[286] = 0; 
    	em[287] = 48; em[288] = 8; 
    	em[289] = 48; em[290] = 32; 
    	em[291] = 48; em[292] = 56; 
    em[293] = 1; em[294] = 8; em[295] = 1; /* 293: pointer.struct.ec_method_st */
    	em[296] = 298; em[297] = 0; 
    em[298] = 0; em[299] = 304; em[300] = 37; /* 298: struct.ec_method_st */
    	em[301] = 375; em[302] = 8; 
    	em[303] = 378; em[304] = 16; 
    	em[305] = 378; em[306] = 24; 
    	em[307] = 381; em[308] = 32; 
    	em[309] = 384; em[310] = 40; 
    	em[311] = 387; em[312] = 48; 
    	em[313] = 390; em[314] = 56; 
    	em[315] = 393; em[316] = 64; 
    	em[317] = 396; em[318] = 72; 
    	em[319] = 399; em[320] = 80; 
    	em[321] = 399; em[322] = 88; 
    	em[323] = 402; em[324] = 96; 
    	em[325] = 405; em[326] = 104; 
    	em[327] = 408; em[328] = 112; 
    	em[329] = 411; em[330] = 120; 
    	em[331] = 414; em[332] = 128; 
    	em[333] = 417; em[334] = 136; 
    	em[335] = 84; em[336] = 144; 
    	em[337] = 420; em[338] = 152; 
    	em[339] = 423; em[340] = 160; 
    	em[341] = 426; em[342] = 168; 
    	em[343] = 429; em[344] = 176; 
    	em[345] = 432; em[346] = 184; 
    	em[347] = 72; em[348] = 192; 
    	em[349] = 69; em[350] = 200; 
    	em[351] = 435; em[352] = 208; 
    	em[353] = 432; em[354] = 216; 
    	em[355] = 438; em[356] = 224; 
    	em[357] = 66; em[358] = 232; 
    	em[359] = 441; em[360] = 240; 
    	em[361] = 390; em[362] = 248; 
    	em[363] = 63; em[364] = 256; 
    	em[365] = 444; em[366] = 264; 
    	em[367] = 63; em[368] = 272; 
    	em[369] = 444; em[370] = 280; 
    	em[371] = 444; em[372] = 288; 
    	em[373] = 60; em[374] = 296; 
    em[375] = 8884097; em[376] = 8; em[377] = 0; /* 375: pointer.func */
    em[378] = 8884097; em[379] = 8; em[380] = 0; /* 378: pointer.func */
    em[381] = 8884097; em[382] = 8; em[383] = 0; /* 381: pointer.func */
    em[384] = 8884097; em[385] = 8; em[386] = 0; /* 384: pointer.func */
    em[387] = 8884097; em[388] = 8; em[389] = 0; /* 387: pointer.func */
    em[390] = 8884097; em[391] = 8; em[392] = 0; /* 390: pointer.func */
    em[393] = 8884097; em[394] = 8; em[395] = 0; /* 393: pointer.func */
    em[396] = 8884097; em[397] = 8; em[398] = 0; /* 396: pointer.func */
    em[399] = 8884097; em[400] = 8; em[401] = 0; /* 399: pointer.func */
    em[402] = 8884097; em[403] = 8; em[404] = 0; /* 402: pointer.func */
    em[405] = 8884097; em[406] = 8; em[407] = 0; /* 405: pointer.func */
    em[408] = 8884097; em[409] = 8; em[410] = 0; /* 408: pointer.func */
    em[411] = 8884097; em[412] = 8; em[413] = 0; /* 411: pointer.func */
    em[414] = 8884097; em[415] = 8; em[416] = 0; /* 414: pointer.func */
    em[417] = 8884097; em[418] = 8; em[419] = 0; /* 417: pointer.func */
    em[420] = 8884097; em[421] = 8; em[422] = 0; /* 420: pointer.func */
    em[423] = 8884097; em[424] = 8; em[425] = 0; /* 423: pointer.func */
    em[426] = 8884097; em[427] = 8; em[428] = 0; /* 426: pointer.func */
    em[429] = 8884097; em[430] = 8; em[431] = 0; /* 429: pointer.func */
    em[432] = 8884097; em[433] = 8; em[434] = 0; /* 432: pointer.func */
    em[435] = 8884097; em[436] = 8; em[437] = 0; /* 435: pointer.func */
    em[438] = 8884097; em[439] = 8; em[440] = 0; /* 438: pointer.func */
    em[441] = 8884097; em[442] = 8; em[443] = 0; /* 441: pointer.func */
    em[444] = 8884097; em[445] = 8; em[446] = 0; /* 444: pointer.func */
    em[447] = 0; em[448] = 24; em[449] = 1; /* 447: struct.bignum_st */
    	em[450] = 41; em[451] = 0; 
    em[452] = 1; em[453] = 8; em[454] = 1; /* 452: pointer.unsigned char */
    	em[455] = 457; em[456] = 0; 
    em[457] = 0; em[458] = 1; em[459] = 0; /* 457: unsigned char */
    em[460] = 1; em[461] = 8; em[462] = 1; /* 460: pointer.struct.ec_group_st */
    	em[463] = 90; em[464] = 0; 
    args_addr->arg_entity_index[0] = 460;
    args_addr->ret_entity_index = -1;
    populate_arg(args_addr, arg_a);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    EC_GROUP * new_arg_a = *((EC_GROUP * *)new_args->args[0]);

    void (*orig_EC_GROUP_free)(EC_GROUP *);
    orig_EC_GROUP_free = dlsym(RTLD_NEXT, "EC_GROUP_free");
    (*orig_EC_GROUP_free)(new_arg_a);

    syscall(889);

    free(args_addr);

}

