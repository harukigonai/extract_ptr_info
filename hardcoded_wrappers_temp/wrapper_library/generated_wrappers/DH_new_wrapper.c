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

DH * bb_DH_new(void);

DH * DH_new(void) 
{
    unsigned long in_lib = syscall(890);
    printf("DH_new called %lu\n", in_lib);
    if (!in_lib)
        return bb_DH_new();
    else {
        DH * (*orig_DH_new)(void);
        orig_DH_new = dlsym(RTLD_NEXT, "DH_new");
        return orig_DH_new();
    }
}

DH * bb_DH_new(void) 
{
    DH * ret;

    struct lib_enter_args *args_addr = malloc(sizeof(struct lib_enter_args));
    memset(args_addr, 0, sizeof(struct lib_enter_args));
    args_addr->num_args = 0;
    uint32_t *em = args_addr->entity_metadata;
    em[0] = 1; em[1] = 8; em[2] = 1; /* 0: pointer.struct.ENGINE_CMD_DEFN_st */
    	em[3] = 5; em[4] = 0; 
    em[5] = 0; em[6] = 32; em[7] = 2; /* 5: struct.ENGINE_CMD_DEFN_st */
    	em[8] = 12; em[9] = 8; 
    	em[10] = 12; em[11] = 16; 
    em[12] = 1; em[13] = 8; em[14] = 1; /* 12: pointer.char */
    	em[15] = 8884096; em[16] = 0; 
    em[17] = 8884097; em[18] = 8; em[19] = 0; /* 17: pointer.func */
    em[20] = 8884097; em[21] = 8; em[22] = 0; /* 20: pointer.func */
    em[23] = 8884097; em[24] = 8; em[25] = 0; /* 23: pointer.func */
    em[26] = 8884097; em[27] = 8; em[28] = 0; /* 26: pointer.func */
    em[29] = 8884097; em[30] = 8; em[31] = 0; /* 29: pointer.func */
    em[32] = 8884097; em[33] = 8; em[34] = 0; /* 32: pointer.func */
    em[35] = 8884097; em[36] = 8; em[37] = 0; /* 35: pointer.func */
    em[38] = 1; em[39] = 8; em[40] = 1; /* 38: pointer.struct.store_method_st */
    	em[41] = 43; em[42] = 0; 
    em[43] = 0; em[44] = 0; em[45] = 0; /* 43: struct.store_method_st */
    em[46] = 8884097; em[47] = 8; em[48] = 0; /* 46: pointer.func */
    em[49] = 8884097; em[50] = 8; em[51] = 0; /* 49: pointer.func */
    em[52] = 8884097; em[53] = 8; em[54] = 0; /* 52: pointer.func */
    em[55] = 8884097; em[56] = 8; em[57] = 0; /* 55: pointer.func */
    em[58] = 0; em[59] = 216; em[60] = 24; /* 58: struct.engine_st */
    	em[61] = 12; em[62] = 0; 
    	em[63] = 12; em[64] = 8; 
    	em[65] = 109; em[66] = 16; 
    	em[67] = 169; em[68] = 24; 
    	em[69] = 220; em[70] = 32; 
    	em[71] = 256; em[72] = 40; 
    	em[73] = 273; em[74] = 48; 
    	em[75] = 300; em[76] = 56; 
    	em[77] = 38; em[78] = 64; 
    	em[79] = 35; em[80] = 72; 
    	em[81] = 323; em[82] = 80; 
    	em[83] = 32; em[84] = 88; 
    	em[85] = 29; em[86] = 96; 
    	em[87] = 26; em[88] = 104; 
    	em[89] = 26; em[90] = 112; 
    	em[91] = 26; em[92] = 120; 
    	em[93] = 23; em[94] = 128; 
    	em[95] = 20; em[96] = 136; 
    	em[97] = 20; em[98] = 144; 
    	em[99] = 17; em[100] = 152; 
    	em[101] = 0; em[102] = 160; 
    	em[103] = 326; em[104] = 184; 
    	em[105] = 349; em[106] = 200; 
    	em[107] = 349; em[108] = 208; 
    em[109] = 1; em[110] = 8; em[111] = 1; /* 109: pointer.struct.rsa_meth_st */
    	em[112] = 114; em[113] = 0; 
    em[114] = 0; em[115] = 112; em[116] = 13; /* 114: struct.rsa_meth_st */
    	em[117] = 12; em[118] = 0; 
    	em[119] = 143; em[120] = 8; 
    	em[121] = 143; em[122] = 16; 
    	em[123] = 143; em[124] = 24; 
    	em[125] = 143; em[126] = 32; 
    	em[127] = 146; em[128] = 40; 
    	em[129] = 149; em[130] = 48; 
    	em[131] = 152; em[132] = 56; 
    	em[133] = 152; em[134] = 64; 
    	em[135] = 155; em[136] = 80; 
    	em[137] = 160; em[138] = 88; 
    	em[139] = 163; em[140] = 96; 
    	em[141] = 166; em[142] = 104; 
    em[143] = 8884097; em[144] = 8; em[145] = 0; /* 143: pointer.func */
    em[146] = 8884097; em[147] = 8; em[148] = 0; /* 146: pointer.func */
    em[149] = 8884097; em[150] = 8; em[151] = 0; /* 149: pointer.func */
    em[152] = 8884097; em[153] = 8; em[154] = 0; /* 152: pointer.func */
    em[155] = 1; em[156] = 8; em[157] = 1; /* 155: pointer.char */
    	em[158] = 8884096; em[159] = 0; 
    em[160] = 8884097; em[161] = 8; em[162] = 0; /* 160: pointer.func */
    em[163] = 8884097; em[164] = 8; em[165] = 0; /* 163: pointer.func */
    em[166] = 8884097; em[167] = 8; em[168] = 0; /* 166: pointer.func */
    em[169] = 1; em[170] = 8; em[171] = 1; /* 169: pointer.struct.dsa_method */
    	em[172] = 174; em[173] = 0; 
    em[174] = 0; em[175] = 96; em[176] = 11; /* 174: struct.dsa_method */
    	em[177] = 12; em[178] = 0; 
    	em[179] = 199; em[180] = 8; 
    	em[181] = 202; em[182] = 16; 
    	em[183] = 205; em[184] = 24; 
    	em[185] = 208; em[186] = 32; 
    	em[187] = 211; em[188] = 40; 
    	em[189] = 214; em[190] = 48; 
    	em[191] = 214; em[192] = 56; 
    	em[193] = 155; em[194] = 72; 
    	em[195] = 217; em[196] = 80; 
    	em[197] = 214; em[198] = 88; 
    em[199] = 8884097; em[200] = 8; em[201] = 0; /* 199: pointer.func */
    em[202] = 8884097; em[203] = 8; em[204] = 0; /* 202: pointer.func */
    em[205] = 8884097; em[206] = 8; em[207] = 0; /* 205: pointer.func */
    em[208] = 8884097; em[209] = 8; em[210] = 0; /* 208: pointer.func */
    em[211] = 8884097; em[212] = 8; em[213] = 0; /* 211: pointer.func */
    em[214] = 8884097; em[215] = 8; em[216] = 0; /* 214: pointer.func */
    em[217] = 8884097; em[218] = 8; em[219] = 0; /* 217: pointer.func */
    em[220] = 1; em[221] = 8; em[222] = 1; /* 220: pointer.struct.dh_method */
    	em[223] = 225; em[224] = 0; 
    em[225] = 0; em[226] = 72; em[227] = 8; /* 225: struct.dh_method */
    	em[228] = 12; em[229] = 0; 
    	em[230] = 244; em[231] = 8; 
    	em[232] = 247; em[233] = 16; 
    	em[234] = 250; em[235] = 24; 
    	em[236] = 244; em[237] = 32; 
    	em[238] = 244; em[239] = 40; 
    	em[240] = 155; em[241] = 56; 
    	em[242] = 253; em[243] = 64; 
    em[244] = 8884097; em[245] = 8; em[246] = 0; /* 244: pointer.func */
    em[247] = 8884097; em[248] = 8; em[249] = 0; /* 247: pointer.func */
    em[250] = 8884097; em[251] = 8; em[252] = 0; /* 250: pointer.func */
    em[253] = 8884097; em[254] = 8; em[255] = 0; /* 253: pointer.func */
    em[256] = 1; em[257] = 8; em[258] = 1; /* 256: pointer.struct.ecdh_method */
    	em[259] = 261; em[260] = 0; 
    em[261] = 0; em[262] = 32; em[263] = 3; /* 261: struct.ecdh_method */
    	em[264] = 12; em[265] = 0; 
    	em[266] = 270; em[267] = 8; 
    	em[268] = 155; em[269] = 24; 
    em[270] = 8884097; em[271] = 8; em[272] = 0; /* 270: pointer.func */
    em[273] = 1; em[274] = 8; em[275] = 1; /* 273: pointer.struct.ecdsa_method */
    	em[276] = 278; em[277] = 0; 
    em[278] = 0; em[279] = 48; em[280] = 5; /* 278: struct.ecdsa_method */
    	em[281] = 12; em[282] = 0; 
    	em[283] = 291; em[284] = 8; 
    	em[285] = 294; em[286] = 16; 
    	em[287] = 297; em[288] = 24; 
    	em[289] = 155; em[290] = 40; 
    em[291] = 8884097; em[292] = 8; em[293] = 0; /* 291: pointer.func */
    em[294] = 8884097; em[295] = 8; em[296] = 0; /* 294: pointer.func */
    em[297] = 8884097; em[298] = 8; em[299] = 0; /* 297: pointer.func */
    em[300] = 1; em[301] = 8; em[302] = 1; /* 300: pointer.struct.rand_meth_st */
    	em[303] = 305; em[304] = 0; 
    em[305] = 0; em[306] = 48; em[307] = 6; /* 305: struct.rand_meth_st */
    	em[308] = 320; em[309] = 0; 
    	em[310] = 55; em[311] = 8; 
    	em[312] = 52; em[313] = 16; 
    	em[314] = 49; em[315] = 24; 
    	em[316] = 55; em[317] = 32; 
    	em[318] = 46; em[319] = 40; 
    em[320] = 8884097; em[321] = 8; em[322] = 0; /* 320: pointer.func */
    em[323] = 8884097; em[324] = 8; em[325] = 0; /* 323: pointer.func */
    em[326] = 0; em[327] = 32; em[328] = 2; /* 326: struct.crypto_ex_data_st_fake */
    	em[329] = 333; em[330] = 8; 
    	em[331] = 346; em[332] = 24; 
    em[333] = 8884099; em[334] = 8; em[335] = 2; /* 333: pointer_to_array_of_pointers_to_stack */
    	em[336] = 340; em[337] = 0; 
    	em[338] = 343; em[339] = 20; 
    em[340] = 0; em[341] = 8; em[342] = 0; /* 340: pointer.void */
    em[343] = 0; em[344] = 4; em[345] = 0; /* 343: int */
    em[346] = 8884097; em[347] = 8; em[348] = 0; /* 346: pointer.func */
    em[349] = 1; em[350] = 8; em[351] = 1; /* 349: pointer.struct.engine_st */
    	em[352] = 58; em[353] = 0; 
    em[354] = 0; em[355] = 1; em[356] = 0; /* 354: char */
    em[357] = 8884097; em[358] = 8; em[359] = 0; /* 357: pointer.func */
    em[360] = 0; em[361] = 72; em[362] = 8; /* 360: struct.dh_method */
    	em[363] = 12; em[364] = 0; 
    	em[365] = 379; em[366] = 8; 
    	em[367] = 382; em[368] = 16; 
    	em[369] = 385; em[370] = 24; 
    	em[371] = 379; em[372] = 32; 
    	em[373] = 379; em[374] = 40; 
    	em[375] = 155; em[376] = 56; 
    	em[377] = 357; em[378] = 64; 
    em[379] = 8884097; em[380] = 8; em[381] = 0; /* 379: pointer.func */
    em[382] = 8884097; em[383] = 8; em[384] = 0; /* 382: pointer.func */
    em[385] = 8884097; em[386] = 8; em[387] = 0; /* 385: pointer.func */
    em[388] = 1; em[389] = 8; em[390] = 1; /* 388: pointer.struct.dh_method */
    	em[391] = 360; em[392] = 0; 
    em[393] = 0; em[394] = 144; em[395] = 12; /* 393: struct.dh_st */
    	em[396] = 420; em[397] = 8; 
    	em[398] = 420; em[399] = 16; 
    	em[400] = 420; em[401] = 32; 
    	em[402] = 420; em[403] = 40; 
    	em[404] = 440; em[405] = 56; 
    	em[406] = 420; em[407] = 64; 
    	em[408] = 420; em[409] = 72; 
    	em[410] = 454; em[411] = 80; 
    	em[412] = 420; em[413] = 96; 
    	em[414] = 462; em[415] = 112; 
    	em[416] = 388; em[417] = 128; 
    	em[418] = 476; em[419] = 136; 
    em[420] = 1; em[421] = 8; em[422] = 1; /* 420: pointer.struct.bignum_st */
    	em[423] = 425; em[424] = 0; 
    em[425] = 0; em[426] = 24; em[427] = 1; /* 425: struct.bignum_st */
    	em[428] = 430; em[429] = 0; 
    em[430] = 8884099; em[431] = 8; em[432] = 2; /* 430: pointer_to_array_of_pointers_to_stack */
    	em[433] = 437; em[434] = 0; 
    	em[435] = 343; em[436] = 12; 
    em[437] = 0; em[438] = 8; em[439] = 0; /* 437: long unsigned int */
    em[440] = 1; em[441] = 8; em[442] = 1; /* 440: pointer.struct.bn_mont_ctx_st */
    	em[443] = 445; em[444] = 0; 
    em[445] = 0; em[446] = 96; em[447] = 3; /* 445: struct.bn_mont_ctx_st */
    	em[448] = 425; em[449] = 8; 
    	em[450] = 425; em[451] = 32; 
    	em[452] = 425; em[453] = 56; 
    em[454] = 1; em[455] = 8; em[456] = 1; /* 454: pointer.unsigned char */
    	em[457] = 459; em[458] = 0; 
    em[459] = 0; em[460] = 1; em[461] = 0; /* 459: unsigned char */
    em[462] = 0; em[463] = 32; em[464] = 2; /* 462: struct.crypto_ex_data_st_fake */
    	em[465] = 469; em[466] = 8; 
    	em[467] = 346; em[468] = 24; 
    em[469] = 8884099; em[470] = 8; em[471] = 2; /* 469: pointer_to_array_of_pointers_to_stack */
    	em[472] = 340; em[473] = 0; 
    	em[474] = 343; em[475] = 20; 
    em[476] = 1; em[477] = 8; em[478] = 1; /* 476: pointer.struct.engine_st */
    	em[479] = 58; em[480] = 0; 
    em[481] = 1; em[482] = 8; em[483] = 1; /* 481: pointer.struct.dh_st */
    	em[484] = 393; em[485] = 0; 
    args_addr->ret_entity_index = 481;
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    DH * *new_ret_ptr = (DH * *)new_args->ret;

    DH * (*orig_DH_new)(void);
    orig_DH_new = dlsym(RTLD_NEXT, "DH_new");
    *new_ret_ptr = (*orig_DH_new)();

    syscall(889);

    free(args_addr);

    return ret;
}

