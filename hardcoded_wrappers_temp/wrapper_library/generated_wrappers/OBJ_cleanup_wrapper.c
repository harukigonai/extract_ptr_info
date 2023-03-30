#define _GNU_SOURCE

#include <stdio.h>
#include <dlfcn.h>
#include <sys/syscall.h>
#include <unistd.h>
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

void OBJ_cleanup(void) 
{
    if (syscall(890))
        _OBJ_cleanup()
    else {
        void (*orig_OBJ_cleanup)(void);
        orig_OBJ_cleanup = dlsym(RTLD_NEXT, "OBJ_cleanup");
        orig_OBJ_cleanup();
    }
}

void _OBJ_cleanup(void) 
{
    printf("OBJ_cleanup called\n");
    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
        },
        .arg_entity_index = { -1 },
        .ret_entity_index = -1,
    };
    struct lib_enter_args *args_addr = &args;

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    void (*orig_OBJ_cleanup)(void);
    orig_OBJ_cleanup = dlsym(RTLD_NEXT, "OBJ_cleanup");
    (*orig_OBJ_cleanup)();

    syscall(889);

}

