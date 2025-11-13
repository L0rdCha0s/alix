#ifndef NET_TLS_H
#define NET_TLS_H

#include "types.h"
#include "tcp.h"
#include "crypto/sha256.h"
#include "crypto/aes.h"
#include "crypto/rsa.h"
#include "crypto/p256.h"

typedef enum
{
    TLS_KEY_EXCHANGE_NONE = 0,
    TLS_KEY_EXCHANGE_RSA,
    TLS_KEY_EXCHANGE_ECDHE_RSA
} tls_key_exchange_t;

typedef struct
{
    net_tcp_socket_t *socket;
    bool handshake_complete;
    bool keys_ready;
    uint16_t cipher_suite;
    tls_key_exchange_t key_exchange;
    sha256_ctx_t handshake_hash;
    uint8_t client_random[32];
    uint8_t server_random[32];
    uint8_t master_secret[48];
    uint8_t client_write_mac[32];
    uint8_t server_write_mac[32];
    uint8_t client_write_key[16];
    uint8_t server_write_key[16];
    uint8_t client_write_iv[16];
    uint8_t server_write_iv[16];
    aes128_enc_ctx_t client_enc;
    aes128_enc_ctx_t server_enc;
    aes128_dec_ctx_t server_dec;
    uint64_t client_seq;
    uint64_t server_seq;
    rsa_public_key_t server_key;
    uint8_t ecdhe_private[P256_SCALAR_SIZE];
    uint8_t ecdhe_public[P256_POINT_SIZE];
    size_t ecdhe_public_len;
    uint8_t ecdhe_server_public[P256_POINT_SIZE];
    size_t ecdhe_server_public_len;
    uint16_t ecdhe_named_curve;
    bool ecdhe_client_keys_ready;
    bool ecdhe_server_params_ready;
    uint8_t client_gcm_H[16];
    uint8_t server_gcm_H[16];
    uint8_t recv_plain[16384];
    size_t recv_plain_len;
    size_t recv_plain_offset;
    uint8_t record_buffer[18432];
    size_t record_buffer_len;
    int socket_fd;
} tls_session_t;

bool tls_session_init(tls_session_t *session, net_tcp_socket_t *socket);
bool tls_session_handshake(tls_session_t *session, const char *hostname);
bool tls_session_send(tls_session_t *session, const uint8_t *data, size_t length);
size_t tls_session_recv(tls_session_t *session, uint8_t *buffer, size_t capacity);
void tls_session_close(tls_session_t *session);

#endif
