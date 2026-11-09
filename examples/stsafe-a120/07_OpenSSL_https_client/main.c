/**
 * *****************************************************************************
 * @file    main.c
 * @brief   STSAFE-A HTTPS Client Example using OpenSSL 3.x Provider
 * *****************************************************************************
 *           COPYRIGHT 2026 STMicroelectronics
 * *****************************************************************************
 * Usage:
 *   ./07_OpenSSL_https_client [host] [port] [path] [ca_file] [busID] [slotID] [client_cert] [client_key]
 *
 * Defaults:
 *   host        = "localhost"
 *   port        = 8443
 *   path        = "/"
 *   ca_file     = NULL (disables peer verification if NULL, or verifies CA if set)
 *   busID       = 1
 *   slotID      = 1
 *   client_cert = NULL (optional client certificate for mutual TLS / mTLS)
 *   client_key  = NULL (optional client hardware private key for mTLS)
 *
 * Description:
 *   Demonstrates an HTTPS / TLS client powered by the STSAFE-A secure element
 *   via the OpenSSL 3.x Provider architecture:
 *   - Establishes a secure TLS session with an HTTPS server.
 *   - Supports mutual TLS (mTLS) authentication: the client authenticates itself
 *     to the server using a hardware-protected private key in the STSAFE-A.
 *   - If client_cert / client_key are omitted, an STSAFE-A client identity
 *     key pair and certificate are automatically provisioned on the fly to
 *     demonstrate full hardware-backed client authentication.
 *   - Sends an HTTP/1.1 GET request and prints the server's response.
 * *****************************************************************************
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>

#include "stse_provider.h"

#define DEFAULT_HOST       "localhost"
#define DEFAULT_PORT       8443
#define DEFAULT_PATH       "/"
#define DEFAULT_BUS        1
#define DEFAULT_SLOT       1
#define BUFFER_SIZE        4096

static void ssl_die(const char *msg)
{
    fprintf(stderr, "[-] ERROR: %s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

/**
 * @brief Generate a self-signed client X.509 certificate for the given hardware-backed key.
 */
static X509 *create_self_signed_client_cert(EVP_PKEY *hw_key, const char *client_id, const char *prov_name)
{
    X509 *cert = X509_new();
    if (!cert) ssl_die("X509_new failed");

    ASN1_INTEGER_set(X509_get_serialNumber(cert), 100);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 31536000L);

    if (X509_set_pubkey(cert, hw_key) <= 0)
        ssl_die("X509_set_pubkey failed");

    X509_NAME *name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char *)"FR", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const unsigned char *)"STMicroelectronics", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)client_id, -1, -1, 0);
    X509_set_issuer_name(cert, name);

    printf("[*] Signing client identity certificate on STSAFE-A hardware (SHA2-256) ...\n");
    char prop_query[64];
    snprintf(prop_query, sizeof(prop_query), "provider=%s", prov_name);

    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    if (!mctx) ssl_die("EVP_MD_CTX_new failed");

    if (EVP_DigestSignInit_ex(mctx, NULL, "SHA2-256", NULL, prop_query, hw_key, NULL) <= 0)
        ssl_die("EVP_DigestSignInit_ex failed for client certificate signing");

    if (X509_sign_ctx(cert, mctx) <= 0)
        ssl_die("X509_sign_ctx with STSAFE hardware key failed");

    EVP_MD_CTX_free(mctx);
    printf("[+] Client certificate signed successfully by STSAFE-A!\n");
    return cert;
}

/**
 * @brief Establish a TCP connection to the specified host and port.
 */
static int tcp_connect(const char *hostname, int port)
{
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    struct addrinfo hints, *res, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int status = getaddrinfo(hostname, port_str, &hints, &res);
    if (status != 0) {
        fprintf(stderr, "[-] getaddrinfo error: %s\n", gai_strerror(status));
        return -1;
    }

    int sock_fd = -1;
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        sock_fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock_fd < 0) continue;

        if (connect(sock_fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            /* Set send and receive timeouts so client doesn't hang indefinitely */
            struct timeval tv = { .tv_sec = 10, .tv_usec = 0 };
            setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            setsockopt(sock_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
            break; /* Success */
        }
        close(sock_fd);
        sock_fd = -1;
    }

    freeaddrinfo(res);
    return sock_fd;
}

int main(int argc, char *argv[])
{
    const char *host        = DEFAULT_HOST;
    int         port        = DEFAULT_PORT;
    const char *path        = DEFAULT_PATH;
    const char *ca_file     = NULL;
    uint32_t    bus_id      = DEFAULT_BUS;
    uint32_t    slot        = DEFAULT_SLOT;
    const char *client_cert = NULL;
    const char *client_key  = NULL;

    if (argc > 1 && strlen(argv[1]) > 0) host        = argv[1];
    if (argc > 2 && strlen(argv[2]) > 0) port        = atoi(argv[2]);
    if (argc > 3 && strlen(argv[3]) > 0) path        = argv[3];
    if (argc > 4 && strlen(argv[4]) > 0) ca_file     = argv[4];
    if (argc > 5 && strlen(argv[5]) > 0) bus_id      = (uint32_t)atoi(argv[5]);
    if (argc > 6 && strlen(argv[6]) > 0) slot        = (uint32_t)atoi(argv[6]);
    if (argc > 7 && strlen(argv[7]) > 0) client_cert = argv[7];
    if (argc > 8 && strlen(argv[8]) > 0) client_key  = argv[8];

    printf("====================================================================\n");
    printf("       STSAFE-A OpenSSL 3.x Hardware-Backed HTTPS Client            \n");
    printf("====================================================================\n");
    printf("Target: https://%s:%d%s\n", host, port, path);
    printf("Config: I2C Bus=%u, Client Key Slot=%u\n\n", bus_id, slot);

    /* ----------------------------------------------------------------
     * 1. Load OpenSSL providers
     *    stsafe-a120 (or stsafe-a110) for hardware crypto
     *    default for standard software algorithms and TLS state machine
     * --------------------------------------------------------------- */
    /* Load 'default' software provider first for TLS engine, ciphers, and ephemeral key exchange */
    OSSL_PROVIDER *prov_default = OSSL_PROVIDER_load(NULL, "default");
    if (!prov_default) {
        ssl_die("Failed to load OpenSSL 'default' provider.");
    }
    printf("    -> Loaded software provider: default\n");

    /* Load hardware provider for STSAFE-A key storage and signatures */
    const char *prov_name = "stsafe-a120";
    OSSL_PROVIDER *prov_stse = OSSL_PROVIDER_load(NULL, prov_name);
    if (!prov_stse) {
        prov_name = "stsafe-a110";
        prov_stse = OSSL_PROVIDER_load(NULL, prov_name);
    }
    if (!prov_stse) {
        ssl_die("Failed to load stsafe-a120 / stsafe-a110 provider. Check OPENSSL_MODULES.");
    }
    printf("    -> Loaded hardware provider: %s\n", prov_name);

    /* ----------------------------------------------------------------
     * 2. Initialize TLS Client Context
     * --------------------------------------------------------------- */
    printf("\n[2] Initializing TLS Client Context ...\n");
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ssl_ctx = SSL_CTX_new_ex(NULL, "?provider=default", method);
    if (!ssl_ctx) ssl_die("SSL_CTX_new_ex failed");

    SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION);
    SSL_CTX_set_security_level(ssl_ctx, 1);

    /* Explicitly enable standard key agreement groups for TLS 1.3 & TLS 1.2 (ECDHE) */
    SSL_CTX_set1_groups_list(ssl_ctx, "X25519:P-256:P-384:P-521");

    /* Configure standard ciphers for both TLS 1.3 and TLS 1.2 */
    SSL_CTX_set_ciphersuites(ssl_ctx,
        "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256");
    SSL_CTX_set_cipher_list(ssl_ctx,
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305");

    /* Server certificate verification setup */
    if (ca_file) {
        printf("    -> Loading CA certificate for server verification: %s\n", ca_file);
        if (SSL_CTX_load_verify_locations(ssl_ctx, ca_file, NULL) <= 0)
            ssl_die("SSL_CTX_load_verify_locations failed");
        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
    } else {
        printf("    -> Notice: No CA certificate specified, peer verification disabled (test mode)\n");
        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);
    }

    /* ----------------------------------------------------------------
     * 3. Configure Hardware-Backed Client Authentication (mTLS)
     * --------------------------------------------------------------- */
    printf("\n[3] Setting up STSAFE-A Client Identity for mutual TLS (mTLS) ...\n");
    EVP_PKEY *hw_key = NULL;
    X509     *cert   = NULL;

    if (client_key) {
        printf("    -> Loading client hardware key from file: %s\n", client_key);
        BIO *kbio = BIO_new_file(client_key, "r");
        if (!kbio) ssl_die("Failed to open client_key file");
        hw_key = PEM_read_bio_PrivateKey(kbio, NULL, NULL, NULL);
        BIO_free(kbio);
        if (!hw_key) ssl_die("Failed to parse client hardware key PEM");
    } else {
        printf("    -> Initializing hardware client key pair in Slot %u (Bus %u) ...\n", slot, bus_id);
        char prop_query[64];
        snprintf(prop_query, sizeof(prop_query), "provider=%s", prov_name);

        EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", prop_query);
        if (!kctx) ssl_die("EVP_PKEY_CTX_new_from_name failed");

        if (EVP_PKEY_keygen_init(kctx) <= 0)
            ssl_die("EVP_PKEY_keygen_init failed");

        OSSL_PARAM gen_params[] = {
            OSSL_PARAM_uint32(STSE_PROV_PARAM_SLOT, &slot),
            OSSL_PARAM_uint32(STSE_PROV_PARAM_BUS,  &bus_id),
            OSSL_PARAM_END
        };
        if (EVP_PKEY_CTX_set_params(kctx, gen_params) <= 0)
            ssl_die("EVP_PKEY_CTX_set_params failed");

        if (EVP_PKEY_generate(kctx, &hw_key) <= 0)
            ssl_die("EVP_PKEY_generate failed (is se-daemon running?)");

        EVP_PKEY_CTX_free(kctx);
        printf("    -> Client hardware key active in Slot %u!\n", slot);
    }

    if (client_cert) {
        printf("    -> Loading client certificate from file: %s\n", client_cert);
        BIO *cbio = BIO_new_file(client_cert, "r");
        if (!cbio) ssl_die("Failed to open client_cert file");
        cert = PEM_read_bio_X509(cbio, NULL, NULL, NULL);
        BIO_free(cbio);
        if (!cert) ssl_die("Failed to parse client certificate");
    } else {
        printf("    -> Generating self-signed client certificate with STSAFE hardware ...\n");
        cert = create_self_signed_client_cert(hw_key, "stsafe-client-node", prov_name);
    }

    if (SSL_CTX_use_certificate(ssl_ctx, cert) <= 0)
        ssl_die("SSL_CTX_use_certificate failed");

    if (SSL_CTX_use_PrivateKey(ssl_ctx, hw_key) <= 0)
        ssl_die("SSL_CTX_use_PrivateKey failed with client hardware key");

    if (SSL_CTX_check_private_key(ssl_ctx) <= 0)
        ssl_die("Client private key does not match certificate");

    printf("[+] Client credentials bound to STSAFE-A secure element successfully!\n");

    /* ----------------------------------------------------------------
     * 4. Connect to Server
     * --------------------------------------------------------------- */
    printf("\n[4] Connecting to %s:%d ...\n", host, port);
    int sock_fd = tcp_connect(host, port);
    if (sock_fd < 0) {
        fprintf(stderr, "[-] Failed to connect to %s:%d\n", host, port);
        return EXIT_FAILURE;
    }
    printf("[+] TCP connection established!\n");

    SSL *ssl = SSL_new(ssl_ctx);
    if (!ssl) ssl_die("SSL_new failed");

    SSL_set_fd(ssl, sock_fd);

    /* Set Server Name Indication (SNI) */
    SSL_set_tlsext_host_name(ssl, host);

    printf("[*] Performing TLS handshake with server ...\n");
    if (SSL_connect(ssl) <= 0) {
        fprintf(stderr, "[-] TLS Handshake failed\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(sock_fd);
        return EXIT_FAILURE;
    }

    printf("[+] TLS connection established!\n");
    printf("    -> Protocol : %s\n", SSL_get_version(ssl));
    printf("    -> Cipher   : %s\n", SSL_get_cipher(ssl));

    /* Print Server Certificate Info */
    X509 *server_cert = SSL_get_peer_certificate(ssl);
    if (server_cert) {
        char subj[256];
        X509_NAME_oneline(X509_get_subject_name(server_cert), subj, sizeof(subj));
        printf("    -> Server Subject: %s\n", subj);
        X509_free(server_cert);
    }

    /* ----------------------------------------------------------------
     * 5. Send HTTPS GET Request & Read Response
     * --------------------------------------------------------------- */
    printf("\n[5] Sending HTTPS GET Request ...\n");
    char request[BUFFER_SIZE];
    int req_len = snprintf(request, sizeof(request),
                          "GET %s HTTP/1.1\r\n"
                          "Host: %s:%d\r\n"
                          "User-Agent: STSAFE-A-OpenSSL-Client/1.0\r\n"
                          "Accept: */*\r\n"
                          "Connection: close\r\n"
                          "\r\n",
                          path, host, port);

    if (SSL_write(ssl, request, req_len) <= 0) {
        fprintf(stderr, "[-] SSL_write request failed\n");
        ERR_print_errors_fp(stderr);
    } else {
        printf("[+] Request sent (%d bytes)\n", req_len);
    }

    printf("\n[6] Server Response:\n");
    printf("--------------------------------------------------------------------\n");
    char buf[BUFFER_SIZE];
    int bytes = 0;
    int total_bytes = 0;
    while ((bytes = SSL_read(ssl, buf, sizeof(buf) - 1)) > 0) {
        buf[bytes] = '\0';
        printf("%s", buf);
        total_bytes += bytes;
    }
    if (bytes <= 0 && total_bytes == 0) {
        int err = SSL_get_error(ssl, bytes);
        if (err == SSL_ERROR_ZERO_RETURN) {
            printf("[!] Server closed connection cleanly without response data.\n");
        } else if (err == SSL_ERROR_SYSCALL) {
            printf("[!] Connection timed out or reset while waiting for HTTP response from server.\n");
        } else {
            printf("[!] SSL_read error: %d\n", err);
            ERR_print_errors_fp(stdout);
        }
    }
    printf("\n--------------------------------------------------------------------\n");

    /* ----------------------------------------------------------------
     * 6. Cleanup & Teardown
     * --------------------------------------------------------------- */
    printf("[+] HTTPS transaction completed successfully.\n");
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock_fd);
    SSL_CTX_free(ssl_ctx);
    X509_free(cert);
    EVP_PKEY_free(hw_key);
    OSSL_PROVIDER_unload(prov_stse);
    OSSL_PROVIDER_unload(prov_default);

    return EXIT_SUCCESS;
}
