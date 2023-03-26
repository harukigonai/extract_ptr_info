#define _GNU_SOURCE

#include <stdio.h>
#include <dlfcn.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <pthread.h>
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

int SSL_CIPHER_get_bits(const SSL_CIPHER * a,int * b) {
    printo("SSL_CIPHER_get_bits called\n");
    int (*f_ptr)(const SSL_CIPHER *,int *);
    f_ptr = dlsym(RTLD_NEXT, "SSL_CIPHER_get_bits");
    return (*f_ptr)(a,b);
}

const char * SSL_CIPHER_get_name(const SSL_CIPHER * a) {
    printo("SSL_CIPHER_get_name called\n");
    char * (*f_ptr)(const SSL_CIPHER *);
    f_ptr = dlsym(RTLD_NEXT, "SSL_CIPHER_get_name");
    return (*f_ptr)(a);
}

int SSL_CTX_check_private_key(const SSL_CTX * a) {
    printo("SSL_CTX_check_private_key called\n");
    int (*f_ptr)(const SSL_CTX *);
    f_ptr = dlsym(RTLD_NEXT, "SSL_CTX_check_private_key");
    return (*f_ptr)(a);
}

long SSL_CTX_ctrl(SSL_CTX * a,int b,long c,void * d) {
    printo("SSL_CTX_ctrl called\n");
    long (*f_ptr)(SSL_CTX *,int,long,void *);
    f_ptr = dlsym(RTLD_NEXT, "SSL_CTX_ctrl");
    return (*f_ptr)(a,b,c,d);
}

void SSL_CTX_free(SSL_CTX * a) {
    printo("SSL_CTX_free called\n");
    void (*f_ptr)(SSL_CTX *);
    f_ptr = dlsym(RTLD_NEXT, "SSL_CTX_free");
    return (*f_ptr)(a);
}

X509_STORE * SSL_CTX_get_cert_store(const SSL_CTX * a) {
    printo("SSL_CTX_get_cert_store called\n");
    X509_STORE * (*f_ptr)(const SSL_CTX *);
    f_ptr = dlsym(RTLD_NEXT, "SSL_CTX_get_cert_store");
    return (*f_ptr)(a);
}

BIO * SSL_get_wbio(const SSL * a) {
    printo("SSL_get_wbio called\n");
    BIO * (*f_ptr)(const SSL *);
    f_ptr = dlsym(RTLD_NEXT, "SSL_get_wbio");
    return (*f_ptr)(a);
}
EVP_PKEY * SSL_get_privatekey(SSL * a) {
    printo("SSL_get_privatekey called\n");
    EVP_PKEY * (*f_ptr)(SSL *);
    f_ptr = dlsym(RTLD_NEXT, "SSL_get_privatekey");
    return (*f_ptr)(a);
}
SSL * SSL_new(SSL_CTX * a) {
    printo("SSL_new called\n");
    SSL * (*f_ptr)(SSL_CTX *);
    f_ptr = dlsym(RTLD_NEXT, "SSL_new");
    return (*f_ptr)(a);
}
SSL_CTX * SSL_get_SSL_CTX(const SSL * a) {
    printo("SSL_get_SSL_CTX called\n");
    SSL_CTX * (*f_ptr)(const SSL *);
    f_ptr = dlsym(RTLD_NEXT, "SSL_get_SSL_CTX");
    return (*f_ptr)(a);
}
SSL_CTX * SSL_set_SSL_CTX(SSL * a,SSL_CTX* b) {
    printo("SSL_set_SSL_CTX called\n");
    SSL_CTX * (*f_ptr)(SSL *,SSL_CTX*);
    f_ptr = dlsym(RTLD_NEXT, "SSL_set_SSL_CTX");
    return (*f_ptr)(a,b);
}
SSL_SESSION * SSL_get_session(const SSL * a) {
    printo("SSL_get_session called\n");
    SSL_SESSION * (*f_ptr)(const SSL *);
    f_ptr = dlsym(RTLD_NEXT, "SSL_get_session");
    return (*f_ptr)(a);
}
SSL_SESSION * d2i_SSL_SESSION(SSL_SESSION ** a,const unsigned char ** b,long c) {
    printo("d2i_SSL_SESSION called\n");
    SSL_SESSION * (*f_ptr)(SSL_SESSION **,const unsigned char **,long);
    f_ptr = dlsym(RTLD_NEXT, "d2i_SSL_SESSION");
    return (*f_ptr)(a,b,c);
}
UI_METHOD * UI_create_method(char * a) {
    printo("UI_create_method called\n");
    UI_METHOD * (*f_ptr)(char *);
    f_ptr = dlsym(RTLD_NEXT, "UI_create_method");
    return (*f_ptr)(a);
}
X509 * SSL_get_certificate(const SSL * a) {
    printo("SSL_get_certificate called\n");
    X509 * (*f_ptr)(const SSL *);
    f_ptr = dlsym(RTLD_NEXT, "SSL_get_certificate");
    return (*f_ptr)(a);
}
X509 * SSL_get_peer_certificate(const SSL * a) {
    printo("SSL_get_peer_certificate called\n");
    X509 * (*f_ptr)(const SSL *);
    f_ptr = dlsym(RTLD_NEXT, "SSL_get_peer_certificate");
    return (*f_ptr)(a);
}

char * SSL_CIPHER_get_version(const SSL_CIPHER * a) {
    printo("SSL_CIPHER_get_version called\n");
    char * (*f_ptr)(const SSL_CIPHER *);
    f_ptr = dlsym(RTLD_NEXT, "SSL_CIPHER_get_version");
    return (*f_ptr)(a);
}
char * SSL_get_srp_userinfo(SSL * a) {
    printo("SSL_get_srp_userinfo called\n");
    char * (*f_ptr)(SSL *);
    f_ptr = dlsym(RTLD_NEXT, "SSL_get_srp_userinfo");
    return (*f_ptr)(a);
}
char * SSL_get_srp_username(SSL * a) {
    printo("SSL_get_srp_username called\n");
    char * (*f_ptr)(SSL *);
    f_ptr = dlsym(RTLD_NEXT, "SSL_get_srp_username");
    return (*f_ptr)(a);
}
const EVP_MD * EVP_sha256(void) {
    printo("EVP_sha256 called\n");
    EVP_MD * (*f_ptr)(void);
    f_ptr = dlsym(RTLD_NEXT, "EVP_sha256");
    return (*f_ptr)();
}
const SSL_CIPHER * SSL_get_current_cipher(const SSL * a) {
    printo("SSL_get_current_cipher called\n");
    SSL_CIPHER * (*f_ptr)(const SSL *);
    f_ptr = dlsym(RTLD_NEXT, "SSL_get_current_cipher");
    return (*f_ptr)(a);
}
const char * OCSP_response_status_str(long a) {
    printo("OCSP_response_status_str called\n");
    const char * (*f_ptr)(long);
    f_ptr = dlsym(RTLD_NEXT, "OCSP_response_status_str");
    return (*f_ptr)(a);
}

const char * SSL_alert_desc_string_long(int a) {
    printo("SSL_alert_desc_string_long called\n");
    const char * (*f_ptr)(int);
    f_ptr = dlsym(RTLD_NEXT, "SSL_alert_desc_string_long");
    return (*f_ptr)(a);
}
const char * SSL_alert_type_string_long(int a) {
    printo("SSL_alert_type_string_long called\n");
    const char * (*f_ptr)(int);
    f_ptr = dlsym(RTLD_NEXT, "SSL_alert_type_string_long");
    return (*f_ptr)(a);
}
const char * SSL_get_servername(const SSL * a,const int b) {
    printo("SSL_get_servername called\n");
    char * (*f_ptr)(const SSL *,const int);
    f_ptr = dlsym(RTLD_NEXT, "SSL_get_servername");
    return (*f_ptr)(a,b);
}
const char * SSL_get_version(const SSL * a) {
    printo("SSL_get_version called\n");
    char * (*f_ptr)(const SSL *);
    f_ptr = dlsym(RTLD_NEXT, "SSL_get_version");
    return (*f_ptr)(a);
}
const char * SSL_state_string_long(const SSL * a) {
    printo("SSL_state_string_long called\n");
    char * (*f_ptr)(const SSL *);
    f_ptr = dlsym(RTLD_NEXT, "SSL_state_string_long");
    return (*f_ptr)(a);
}
const unsigned char * SSL_SESSION_get_id(const SSL_SESSION * a,unsigned int * b) {
    printo("SSL_SESSION_get_id called\n");
    const unsigned char * (*f_ptr)(const SSL_SESSION *,unsigned int *);
    f_ptr = dlsym(RTLD_NEXT, "SSL_SESSION_get_id");
    return (*f_ptr)(a,b);
}

int (*SSL_CTX_get_verify_callback(const SSL_CTX * a))(int, X509_STORE_CTX *) {
    printo("SSL_CTX_get_verify_callback called\n");
    int (*(*f_ptr)(const SSL_CTX *))(int, X509_STORE_CTX *);
    f_ptr = dlsym(RTLD_NEXT, "SSL_CTX_get_verify_callback");
    return (*f_ptr)(a);
}



int SSL_CTX_get_verify_mode(const SSL_CTX * a) {
    printo("SSL_CTX_get_verify_mode called\n");
    int (*f_ptr)(const SSL_CTX *);
    f_ptr = dlsym(RTLD_NEXT, "SSL_CTX_get_verify_mode");
    return (*f_ptr)(a);
}
int SSL_CTX_load_verify_locations(SSL_CTX * a,const char * b,const char * c) {
    printo("SSL_CTX_load_verify_locations called\n");
    int (*f_ptr)(SSL_CTX *,const char *,const char *);
    f_ptr = dlsym(RTLD_NEXT, "SSL_CTX_load_verify_locations");
    return (*f_ptr)(a,b,c);
}
int SSL_CTX_set_cipher_list(SSL_CTX * a,const char * b) {
    printo("SSL_CTX_set_cipher_list called\n");
    int (*f_ptr)(SSL_CTX *,const char *);
    f_ptr = dlsym(RTLD_NEXT, "SSL_CTX_set_cipher_list");
    return (*f_ptr)(a,b);
}
int SSL_CTX_set_srp_cb_arg(SSL_CTX * a,void * b) {
    printo("SSL_CTX_set_srp_cb_arg called\n");
    int (*f_ptr)(SSL_CTX *,void *);
    f_ptr = dlsym(RTLD_NEXT, "SSL_CTX_set_srp_cb_arg");
    return (*f_ptr)(a,b);
}
int SSL_CTX_set_srp_username_callback(SSL_CTX * a,int (*b)(SSL *, int *, void *)) {
    printo("SSL_CTX_set_srp_username_callback called\n");
    int (*f_ptr)(SSL_CTX *,int (*)(SSL *, int *, void *));
    f_ptr = dlsym(RTLD_NEXT, "SSL_CTX_set_srp_username_callback");
    return (*f_ptr)(a,b);
}
int SSL_CTX_use_PrivateKey(SSL_CTX * a,EVP_PKEY * b) {
    printo("SSL_CTX_use_PrivateKey called\n");
    int (*f_ptr)(SSL_CTX *,EVP_PKEY *);
    f_ptr = dlsym(RTLD_NEXT, "SSL_CTX_use_PrivateKey");
    return (*f_ptr)(a,b);
}
int SSL_CTX_use_PrivateKey_file(SSL_CTX * a,const char * b,int c) {
    printo("SSL_CTX_use_PrivateKey_file called\n");
    int (*f_ptr)(SSL_CTX *,const char *,int);
    f_ptr = dlsym(RTLD_NEXT, "SSL_CTX_use_PrivateKey_file");
    return (*f_ptr)(a,b,c);
}
int SSL_CTX_use_certificate(SSL_CTX * a,X509 * b) {
    printo("SSL_CTX_use_certificate called\n");
    int (*f_ptr)(SSL_CTX *,X509 *);
    f_ptr = dlsym(RTLD_NEXT, "SSL_CTX_use_certificate");
    return (*f_ptr)(a,b);
}
int SSL_CTX_use_certificate_chain_file(SSL_CTX * a,const char * b) {
    printo("SSL_CTX_use_certificate_chain_file called\n");
    int (*f_ptr)(SSL_CTX *,const char *);
    f_ptr = dlsym(RTLD_NEXT, "SSL_CTX_use_certificate_chain_file");
    return (*f_ptr)(a,b);
}
int SSL_CTX_use_certificate_file(SSL_CTX * a,const char * b,int c) {
    printo("SSL_CTX_use_certificate_file called\n");
    int (*f_ptr)(SSL_CTX *,const char *,int);
    f_ptr = dlsym(RTLD_NEXT, "SSL_CTX_use_certificate_file");
    return (*f_ptr)(a,b,c);
}
int SSL_SESSION_print(BIO * a,const SSL_SESSION * b) {
    printo("SSL_SESSION_print called\n");
    int (*f_ptr)(BIO *,const SSL_SESSION *);
    f_ptr = dlsym(RTLD_NEXT, "SSL_SESSION_print");
    return (*f_ptr)(a,b);
}
int SSL_accept(SSL * a) {
    printo("SSL_accept called\n");
    int (*f_ptr)(SSL *);
    f_ptr = dlsym(RTLD_NEXT, "SSL_accept");
    return (*f_ptr)(a);
}
int SSL_check_private_key(const SSL * a) {
    printo("SSL_check_private_key called\n");
    int (*f_ptr)(const SSL *);
    f_ptr = dlsym(RTLD_NEXT, "SSL_check_private_key");
    return (*f_ptr)(a);
}
int SSL_connect(SSL * a) {
    printo("SSL_connect called\n");
    int (*f_ptr)(SSL *);
    f_ptr = dlsym(RTLD_NEXT, "SSL_connect");
    return (*f_ptr)(a);
}
int SSL_do_handshake(SSL * a) {
    printo("SSL_do_handshake called\n");
    int (*f_ptr)(SSL *);
    f_ptr = dlsym(RTLD_NEXT, "SSL_do_handshake");
    return (*f_ptr)(a);
}
int SSL_get_error(const SSL * a,int b) {
    printo("SSL_get_error called\n");
    int (*f_ptr)(const SSL *,int);
    f_ptr = dlsym(RTLD_NEXT, "SSL_get_error");
    return (*f_ptr)(a,b);
}
int SSL_get_ex_data_X509_STORE_CTX_idx(void) {
    printo("SSL_get_ex_data_X509_STORE_CTX_idx called\n");
    int (*f_ptr)(void);
    f_ptr = dlsym(RTLD_NEXT, "SSL_get_ex_data_X509_STORE_CTX_idx");
    return (*f_ptr)();
}
int SSL_get_ex_new_index(long a,void * b,CRYPTO_EX_new * c,CRYPTO_EX_dup * d,CRYPTO_EX_free * e) {
    printo("SSL_get_ex_new_index called\n");
    int (*f_ptr)(long,void *,CRYPTO_EX_new *,CRYPTO_EX_dup *,CRYPTO_EX_free *);
    f_ptr = dlsym(RTLD_NEXT, "SSL_get_ex_new_index");
    return (*f_ptr)(a,b,c,d,e);
}
int SSL_get_shutdown(const SSL * a) {
    printo("SSL_get_shutdown called\n");
    int (*f_ptr)(const SSL *);
    f_ptr = dlsym(RTLD_NEXT, "SSL_get_shutdown");
    return (*f_ptr)(a);
}
int SSL_get_verify_depth(const SSL * a) {
    printo("SSL_get_verify_depth called\n");
    int (*f_ptr)(const SSL *);
    f_ptr = dlsym(RTLD_NEXT, "SSL_get_verify_depth");
    return (*f_ptr)(a);
}
int SSL_get_verify_mode(const SSL * a) {
    printo("SSL_get_verify_mode called\n");
    int (*f_ptr)(const SSL *);
    f_ptr = dlsym(RTLD_NEXT, "SSL_get_verify_mode");
    return (*f_ptr)(a);
}
int SSL_library_init(void) {
    printo("SSL_library_init called\n");
    int (*f_ptr)(void);
    f_ptr = dlsym(RTLD_NEXT, "SSL_library_init");
    return (*f_ptr)();
}
int SSL_peek(SSL * a,void * b,int c) {
    printo("SSL_peek called\n");
    int (*f_ptr)(SSL *,void *,int);
    f_ptr = dlsym(RTLD_NEXT, "SSL_peek");
    return (*f_ptr)(a,b,c);
}
int SSL_read(SSL * a,void * b,int c) {
    printo("SSL_read called\n");
    int (*f_ptr)(SSL *,void *,int);
    f_ptr = dlsym(RTLD_NEXT, "SSL_read");
    return (*f_ptr)(a,b,c);
}
int SSL_renegotiate(SSL * a) {
    printo("SSL_renegotiate called\n");
    int (*f_ptr)(SSL *);
    f_ptr = dlsym(RTLD_NEXT, "SSL_renegotiate");
    return (*f_ptr)(a);
}
int SSL_set_cipher_list(SSL * a,const char * b) {
    printo("SSL_set_cipher_list called\n");
    int (*f_ptr)(SSL *,const char *);
    f_ptr = dlsym(RTLD_NEXT, "SSL_set_cipher_list");
    return (*f_ptr)(a,b);
}
int SSL_set_ex_data(SSL * a,int b,void * c) {
    printo("SSL_set_ex_data called\n");
    int (*f_ptr)(SSL *,int,void *);
    f_ptr = dlsym(RTLD_NEXT, "SSL_set_ex_data");
    return (*f_ptr)(a,b,c);
}
int SSL_set_session_id_context(SSL * a,const unsigned char * b,unsigned int c) {
    printo("SSL_set_session_id_context called\n");
    int (*f_ptr)(SSL *,const unsigned char *,unsigned int);
    f_ptr = dlsym(RTLD_NEXT, "SSL_set_session_id_context");
    return (*f_ptr)(a,b,c);
}
int SSL_set_srp_server_param(SSL * a,const BIGNUM * b,const BIGNUM * c,BIGNUM * d,BIGNUM * e,char * f) {
    printo("SSL_set_srp_server_param called\n");
    int (*f_ptr)(SSL *,const BIGNUM *,const BIGNUM *,BIGNUM *,BIGNUM *,char *);
    f_ptr = dlsym(RTLD_NEXT, "SSL_set_srp_server_param");
    return (*f_ptr)(a,b,c,d,e,f);
}
int SSL_shutdown(SSL * a) {
    printo("SSL_shutdown called\n");
    int (*f_ptr)(SSL *);
    f_ptr = dlsym(RTLD_NEXT, "SSL_shutdown");
    return (*f_ptr)(a);
}
int SSL_use_PrivateKey(SSL * a,EVP_PKEY * b) {
    printo("SSL_use_PrivateKey called\n");
    int (*f_ptr)(SSL *,EVP_PKEY *);
    f_ptr = dlsym(RTLD_NEXT, "SSL_use_PrivateKey");
    return (*f_ptr)(a,b);
}
int SSL_use_certificate(SSL * a,X509 * b) {
    printo("SSL_use_certificate called\n");
    int (*f_ptr)(SSL *,X509 *);
    f_ptr = dlsym(RTLD_NEXT, "SSL_use_certificate");
    return (*f_ptr)(a,b);
}
int SSL_version(const SSL * a) {
    printo("SSL_version called\n");
    int (*f_ptr)(const SSL *);
    f_ptr = dlsym(RTLD_NEXT, "SSL_version");
    return (*f_ptr)(a);
}
int SSL_write(SSL * a,const void * b,int c) {
    printo("SSL_write called\n");
    int (*f_ptr)(SSL *,const void *,int);
    f_ptr = dlsym(RTLD_NEXT, "SSL_write");
    return (*f_ptr)(a,b,c);
}
int ssl_verify_alarm_type(long a) {
    printo("ssl_verify_alarm_type called\n");
    int (*f_ptr)(long);
    f_ptr = dlsym(RTLD_NEXT, "ssl_verify_alarm_type");
    return (*f_ptr)(a);
}

long SSL_CTX_set_timeout(SSL_CTX * a,long b) {
    printo("SSL_CTX_set_timeout called\n");
    long (*f_ptr)(SSL_CTX *,long);
    f_ptr = dlsym(RTLD_NEXT, "SSL_CTX_set_timeout");
    return (*f_ptr)(a,b);
}
long SSL_SESSION_get_time(const SSL_SESSION * a) {
    printo("SSL_SESSION_get_time called\n");
    long (*f_ptr)(const SSL_SESSION *);
    f_ptr = dlsym(RTLD_NEXT, "SSL_SESSION_get_time");
    return (*f_ptr)(a);
}
long SSL_get_verify_result(const SSL * a) {
    printo("SSL_get_verify_result called\n");
    long (*f_ptr)(const SSL *);
    f_ptr = dlsym(RTLD_NEXT, "SSL_get_verify_result");
    return (*f_ptr)(a);
}
unsigned int SSL_SESSION_get_compress_id(const SSL_SESSION * a) {
    printo("SSL_SESSION_get_compress_id called\n");
    unsigned int (*f_ptr)(const SSL_SESSION *);
    f_ptr = dlsym(RTLD_NEXT, "SSL_SESSION_get_compress_id");
    return (*f_ptr)(a);
}
STACK_OF(SSL_COMP) * SSL_COMP_get_compression_methods(void) {
    printo("SSL_COMP_get_compression_methods called\n");
    STACK_OF(SSL_COMP) * (*f_ptr)(void);
    f_ptr = dlsym(RTLD_NEXT, "SSL_COMP_get_compression_methods");
    return (*f_ptr)();
}
void * SSL_get_ex_data(const SSL * a,int b) {
    printo("SSL_get_ex_data called\n");
    void * (*f_ptr)(const SSL *,int);
    f_ptr = dlsym(RTLD_NEXT, "SSL_get_ex_data");
    return (*f_ptr)(a,b);
}

void SSL_CTX_sess_set_get_cb(SSL_CTX * a,SSL_SESSION *(*b)(struct ssl_st *, unsigned char *, int, int *)) {
    printo("SSL_CTX_sess_set_get_cb called\n");
    void (*f_ptr)(SSL_CTX *,SSL_SESSION *(*)(struct ssl_st *, unsigned char *, int, int *));
    f_ptr = dlsym(RTLD_NEXT, "SSL_CTX_sess_set_get_cb");
    return (*f_ptr)(a,b);
}
void SSL_CTX_sess_set_new_cb(SSL_CTX * a,int (*b)(struct ssl_st *, SSL_SESSION *)) {
    printo("SSL_CTX_sess_set_new_cb called\n");
    void (*f_ptr)(SSL_CTX *,int (*)(struct ssl_st *, SSL_SESSION *));
    f_ptr = dlsym(RTLD_NEXT, "SSL_CTX_sess_set_new_cb");
    return (*f_ptr)(a,b);
}
void SSL_CTX_sess_set_remove_cb(SSL_CTX * a,void (*b)(struct ssl_ctx_st *,SSL_SESSION *)) {
    printo("SSL_CTX_sess_set_remove_cb called\n");
    void (*f_ptr)(SSL_CTX *,void (*)(struct ssl_ctx_st *,SSL_SESSION *));
    f_ptr = dlsym(RTLD_NEXT, "SSL_CTX_sess_set_remove_cb");
    return (*f_ptr)(a,b);
}
void SSL_CTX_set_client_CA_list(SSL_CTX * a,STACK_OF(X509_NAME) * b) {
    printo("SSL_CTX_set_client_CA_list called\n");
    void (*f_ptr)(SSL_CTX *,STACK_OF(X509_NAME) *);
    f_ptr = dlsym(RTLD_NEXT, "SSL_CTX_set_client_CA_list");
    return (*f_ptr)(a,b);
}
void SSL_CTX_set_client_cert_cb(SSL_CTX * a,int (*b)(SSL *, X509 **, EVP_PKEY **)) {
    printo("SSL_CTX_set_client_cert_cb called\n");
    void (*f_ptr)(SSL_CTX *,int (*)(SSL *, X509 **, EVP_PKEY **));
    f_ptr = dlsym(RTLD_NEXT, "SSL_CTX_set_client_cert_cb");
    return (*f_ptr)(a,b);
}
void SSL_CTX_set_default_passwd_cb(SSL_CTX * a,pem_password_cb * b) {
    printo("SSL_CTX_set_default_passwd_cb called\n");
    void (*f_ptr)(SSL_CTX *,pem_password_cb *);
    f_ptr = dlsym(RTLD_NEXT, "SSL_CTX_set_default_passwd_cb");
    return (*f_ptr)(a,b);
}
void SSL_CTX_set_info_callback(SSL_CTX *a, void (*b)(const SSL *,int,int)) {
    printo("SSL_CTX_set_info_callback called\n");
    void (*f_ptr)(SSL_CTX *,void (*)(const SSL *, int, int));
    f_ptr = dlsym(RTLD_NEXT, "SSL_CTX_set_info_callback");
    return (*f_ptr)(a,b);
}
void SSL_CTX_set_tmp_dh_callback(SSL_CTX * a,DH *(*b)(SSL *, int, int)) {
    printo("SSL_CTX_set_tmp_dh_callback called\n");
    void (*f_ptr)(SSL_CTX *,DH *(*)(SSL *, int, int));
    f_ptr = dlsym(RTLD_NEXT, "SSL_CTX_set_tmp_dh_callback");
    return (*f_ptr)(a,b);
}
void SSL_CTX_set_verify(SSL_CTX * a,int b,int (*c)(int, X509_STORE_CTX *)) {
    printo("SSL_CTX_set_verify called\n");
    void (*f_ptr)(SSL_CTX *,int,int (*)(int, X509_STORE_CTX *));
    f_ptr = dlsym(RTLD_NEXT, "SSL_CTX_set_verify");
    return (*f_ptr)(a,b,c);
}
void SSL_SESSION_free(SSL_SESSION * a) {
    printo("SSL_SESSION_free called\n");
    void (*f_ptr)(SSL_SESSION *);
    f_ptr = dlsym(RTLD_NEXT, "SSL_SESSION_free");
    return (*f_ptr)(a);
}
void SSL_free(SSL * a) {
    printo("SSL_free called\n");
    void (*f_ptr)(SSL *);
    f_ptr = dlsym(RTLD_NEXT, "SSL_free");
    return (*f_ptr)(a);
}
void SSL_load_error_strings(void) {
    printo("SSL_load_error_strings called\n");
    void (*f_ptr)(void);
    f_ptr = dlsym(RTLD_NEXT, "SSL_load_error_strings");
    return (*f_ptr)();
}
void SSL_set_accept_state(SSL * a) {
    printo("SSL_set_accept_state called\n");
    void (*f_ptr)(SSL *);
    f_ptr = dlsym(RTLD_NEXT, "SSL_set_accept_state");
    return (*f_ptr)(a);
}
void SSL_set_bio(SSL * a,BIO * b,BIO * c) {
    printo("SSL_set_bio called\n");
    void (*f_ptr)(SSL *,BIO *,BIO *);
    f_ptr = dlsym(RTLD_NEXT, "SSL_set_bio");
    return (*f_ptr)(a,b,c);
}
void SSL_set_connect_state(SSL * a) {
    printo("SSL_set_connect_state called\n");
    void (*f_ptr)(SSL *);
    f_ptr = dlsym(RTLD_NEXT, "SSL_set_connect_state");
    return (*f_ptr)(a);
}
void SSL_set_shutdown(SSL * a,int b) {
    printo("SSL_set_shutdown called\n");
    void (*f_ptr)(SSL *,int);
    f_ptr = dlsym(RTLD_NEXT, "SSL_set_shutdown");
    return (*f_ptr)(a,b);
}
void SSL_set_verify(SSL * a,int b,int (*c)(int, X509_STORE_CTX *)) {
    printo("SSL_set_verify called\n");
    void (*f_ptr)(SSL *,int,int (*)(int, X509_STORE_CTX *));
    f_ptr = dlsym(RTLD_NEXT, "SSL_set_verify");
    return (*f_ptr)(a,b,c);
}
void SSL_set_verify_result(SSL * a,long b) {
    printo("SSL_set_verify_result called\n");
    void (*f_ptr)(SSL *,long);
    f_ptr = dlsym(RTLD_NEXT, "SSL_set_verify_result");
    return (*f_ptr)(a,b);
}
