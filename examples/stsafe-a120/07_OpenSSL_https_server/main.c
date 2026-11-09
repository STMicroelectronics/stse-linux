/**
 * *****************************************************************************
 * @file    main.c
 * @brief   STSAFE-A HTTPS Server Example using OpenSSL 3.x Provider
 * *****************************************************************************
 *           COPYRIGHT 2026 STMicroelectronics
 * *****************************************************************************
 * Usage:
 *   ./07_OpenSSL_https_server [port] [busID] [slotID] [cert_file] [key_file]
 *
 * Defaults:
 *   port      = 8443
 *   busID     = 1
 *   slotID    = 1
 *   cert_file = (optional path to certificate; auto-generated if omitted)
 *   key_file  = (optional path to STSAFE PEM private key)
 *
 * Description:
 *   Demonstrates an HTTPS / TLS 1.3 server powered by the STSAFE-A secure element
 *   via the OpenSSL 3.x Provider architecture.
 *   - The server private key is protected in the STSAFE-A hardware key slot.
 *   - During the TLS handshake, CertificateVerify ECDSA signatures are computed
 *     directly inside the STSAFE-A hardware via EVP_DigestSign.
 *   - Ephemeral TLS key exchanges (ECDHE / X25519) and symmetric session ciphers
 *     are handled smoothly by OpenSSL's default software provider.
 * *****************************************************************************
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
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

#define DEFAULT_PORT       8443
#define DEFAULT_BUS        1
#define DEFAULT_SLOT       1
#define BUFFER_SIZE        4096

static volatile int g_keep_running = 1;

static void sigint_handler(int sig)
{
    (void)sig;
    g_keep_running = 0;
}

static void ssl_die(const char *msg)
{
    fprintf(stderr, "[-] ERROR: %s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

/**
 * @brief Generate a self-signed X.509 certificate for the given hardware-backed key.
 */
/**
 * @brief Generate a self-signed X.509 certificate for the given hardware-backed key.
 */
static X509 *create_self_signed_cert(EVP_PKEY *hw_key, const char *common_name, const char *prov_name)
{
    X509 *cert = X509_new();
    if (!cert) ssl_die("X509_new failed");

    /* Serial number */
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);

    /* Valid for 365 days */
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 31536000L);

    /* Bind public key */
    if (X509_set_pubkey(cert, hw_key) <= 0)
        ssl_die("X509_set_pubkey failed");

    /* Subject and Issuer name */
    X509_NAME *name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char *)"FR", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const unsigned char *)"STMicroelectronics", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, (const unsigned char *)"STSAFE Security", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)common_name, -1, -1, 0);
    X509_set_issuer_name(cert, name);

    /* Sign certificate using the STSAFE hardware key via X509_sign_ctx */
    printf("[*] Signing X.509 server certificate on STSAFE-A hardware (SHA2-256) ...\n");
    char prop_query[64];
    snprintf(prop_query, sizeof(prop_query), "provider=%s", prov_name);

    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    if (!mctx) ssl_die("EVP_MD_CTX_new failed");

    if (EVP_DigestSignInit_ex(mctx, NULL, "SHA2-256", NULL, prop_query, hw_key, NULL) <= 0)
        ssl_die("EVP_DigestSignInit_ex failed for certificate signing");

    if (X509_sign_ctx(cert, mctx) <= 0)
        ssl_die("X509_sign_ctx with STSAFE hardware key failed");

    EVP_MD_CTX_free(mctx);
    printf("[+] Certificate self-signed successfully by STSAFE-A!\n");
    return cert;
}

/**
 * @brief Handle a single HTTPS client connection.
 */
static void handle_client(SSL *ssl)
{
    char buf[BUFFER_SIZE];
    int bytes = SSL_read(ssl, buf, sizeof(buf) - 1);
    if (bytes <= 0) {
        int err = SSL_get_error(ssl, bytes);
        if (err != SSL_ERROR_ZERO_RETURN) {
            fprintf(stderr, "[-] SSL_read error (code %d)\n", err);
            ERR_print_errors_fp(stderr);
        }
        return;
    }

    buf[bytes] = '\0';
    printf("[+] Received HTTPS Request (%d bytes):\n", bytes);
    /* Print first line of request */
    char *eol = strstr(buf, "\r\n");
    if (eol) *eol = '\0';
    printf("    --> %s\n", buf);

    /* Send standard HTTP 200 response */
    const char html_body[] =
        "<!DOCTYPE html>\n"
        "<html>\n"
        "<head><title>STSAFE-A HTTPS Server</title></head>\n"
        "<body style='font-family: sans-serif; margin: 40px; background: #f0f4f8;'>\n"
        "  <h1 style='color: #03234b;'>STSAFE-A Secure HTTPS Server</h1>\n"
        "  <p>This TLS connection was authenticated by an <strong>STMicroelectronics STSAFE-A</strong> hardware secure element.</p>\n"
        "  <ul>\n"
        "    <li>Hardware Slot: Protected NIST P-256 ECDSA Private Key</li>\n"
        "    <li>Handshake Signature: Hardware-accelerated via OpenSSL 3.x Provider</li>\n"
        "    <li>Middleware: stse-linux</li>\n"
        "  </ul>\n"
        "</body>\n"
        "</html>\n";

    char response[BUFFER_SIZE];
    int resp_len = snprintf(response, sizeof(response),
                            "HTTP/1.1 200 OK\r\n"
                            "Content-Type: text/html; charset=utf-8\r\n"
                            "Content-Length: %zu\r\n"
                            "Connection: close\r\n"
                            "\r\n"
                            "%s",
                            strlen(html_body), html_body);

    if (SSL_write(ssl, response, resp_len) <= 0) {
        fprintf(stderr, "[-] SSL_write response failed\n");
        ERR_print_errors_fp(stderr);
    } else {
        printf("[+] Sent HTTP 200 response (%d bytes)\n", resp_len);
    }

    SSL_shutdown(ssl);
}

int main(int argc, char *argv[])
{
    int port        = DEFAULT_PORT;
    uint32_t bus_id = DEFAULT_BUS;
    uint32_t slot   = DEFAULT_SLOT;
    const char *cert_file = NULL;
    const char *key_file  = NULL;

    if (argc > 1 && strlen(argv[1]) > 0) port     = atoi(argv[1]);
    if (argc > 2 && strlen(argv[2]) > 0) bus_id   = (uint32_t)atoi(argv[2]);
    if (argc > 3 && strlen(argv[3]) > 0) slot     = (uint32_t)atoi(argv[3]);
    if (argc > 4 && strlen(argv[4]) > 0) cert_file = argv[4];
    if (argc > 5 && strlen(argv[5]) > 0) key_file  = argv[5];

    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);
    signal(SIGPIPE, SIG_IGN);

    printf("====================================================================\n");
    printf("       STSAFE-A OpenSSL 3.x Hardware-Backed HTTPS Server            \n");
    printf("====================================================================\n");
    printf("Config: Port=%d, I2C Bus=%u, Key Slot=%u\n\n", port, bus_id, slot);

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
        /* Fallback attempt to STSAFE-A110 provider if A120 not present */
        prov_name = "stsafe-a110";
        prov_stse = OSSL_PROVIDER_load(NULL, prov_name);
    }
    if (!prov_stse) {
        ssl_die("Failed to load stsafe-a120 / stsafe-a110 provider. Check OPENSSL_MODULES.");
    }
    printf("    -> Loaded hardware provider: %s\n", prov_name);


    /* ----------------------------------------------------------------
     * 2. Obtain Hardware-Backed Private Key and Certificate
     * --------------------------------------------------------------- */
    printf("\n[2] Setting up Server Private Key and Certificate ...\n");
    EVP_PKEY *hw_key = NULL;
    X509     *cert   = NULL;

    if (key_file) {
        /* Load hardware key reference from PEM file (RFC 5915 format) */
        printf("    -> Loading hardware key from file: %s\n", key_file);
        BIO *kbio = BIO_new_file(key_file, "r");
        if (!kbio) ssl_die("Failed to open key_file");
        hw_key = PEM_read_bio_PrivateKey(kbio, NULL, NULL, NULL);
        BIO_free(kbio);
        if (!hw_key) ssl_die("Failed to parse hardware key PEM");
    } else {
        /* Generate key pair in target slot of STSAFE-A */
        printf("    -> Initializing hardware key pair in Slot %u (Bus %u) ...\n", slot, bus_id);
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
        printf("    -> Hardware key pair active in Slot %u!\n", slot);
    }

    if (cert_file) {
        printf("    -> Loading certificate from file: %s\n", cert_file);
        BIO *cbio = BIO_new_file(cert_file, "r");
        if (!cbio) ssl_die("Failed to open cert_file");
        cert = PEM_read_bio_X509(cbio, NULL, NULL, NULL);
        BIO_free(cbio);
        if (!cert) ssl_die("Failed to parse certificate file");
    } else {
        printf("    -> Generating self-signed certificate with STSAFE hardware signature ...\n");
        cert = create_self_signed_cert(hw_key, "stsafe.local", prov_name);
    }

    /* ----------------------------------------------------------------
     * 3. Configure TLS Server Context
     * --------------------------------------------------------------- */
    printf("\n[3] Initializing TLS Server Context ...\n");

    /* Initialize SSL_CTX with default software provider preference for internal
     * operations (ephemeral ECDHE keygen, session encryption, record layer).
     * Hardware keys loaded into the context carry their own provider reference. */
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ssl_ctx = SSL_CTX_new_ex(NULL, "?provider=default", method);
    if (!ssl_ctx) ssl_die("SSL_CTX_new_ex failed");

    /* Require modern TLS 1.2+ (TLS 1.3 preferred) */
    SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION);
    SSL_CTX_set_security_level(ssl_ctx, 1);

    /* Explicitly enable standard key agreement groups for TLS 1.3 & TLS 1.2 (ECDHE) */
    if (!SSL_CTX_set1_groups_list(ssl_ctx, "X25519:P-256:P-384:P-521")) {
        fprintf(stderr, "[!] Warning: failed to configure supported groups list\n");
    }

    /* Configure standard ciphers for both TLS 1.3 and TLS 1.2 */
    SSL_CTX_set_ciphersuites(ssl_ctx,
        "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256");
    SSL_CTX_set_cipher_list(ssl_ctx,
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305");

    /* Bind certificate */
    if (SSL_CTX_use_certificate(ssl_ctx, cert) <= 0)
        ssl_die("SSL_CTX_use_certificate failed");

    /* Bind STSAFE-A hardware private key */
    if (SSL_CTX_use_PrivateKey(ssl_ctx, hw_key) <= 0)
        ssl_die("SSL_CTX_use_PrivateKey failed with STSAFE hardware key");

    /* Verify that private key matches certificate */
    if (SSL_CTX_check_private_key(ssl_ctx) <= 0)
        ssl_die("Private key does not match certificate public key");

    printf("[+] SSL Context configured with STSAFE-A hardware private key!\n");

    /* ----------------------------------------------------------------
     * 4. Create TCP Listening Socket
     * --------------------------------------------------------------- */
    printf("\n[4] Binding TCP server socket on port %d ...\n", port);
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("[-] socket");
        return EXIT_FAILURE;
    }

    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in saddr;
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family      = AF_INET;
    saddr.sin_port        = htons((uint16_t)port);
    saddr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(listen_fd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
        perror("[-] bind");
        close(listen_fd);
        return EXIT_FAILURE;
    }

    if (listen(listen_fd, 5) < 0) {
        perror("[-] listen");
        close(listen_fd);
        return EXIT_FAILURE;
    }

    printf("[+] HTTPS Server listening on https://0.0.0.0:%d/\n", port);
    printf("    (Press Ctrl+C to stop server)\n\n");

    /* ----------------------------------------------------------------
     * 5. Main Connection Loop
     * --------------------------------------------------------------- */
    while (g_keep_running) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(listen_fd, &rfds);
        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };

        int sel = select(listen_fd + 1, &rfds, NULL, NULL, &tv);
        if (sel <= 0) continue;

        struct sockaddr_in caddr;
        socklen_t clen = sizeof(caddr);
        int client_fd = accept(listen_fd, (struct sockaddr *)&caddr, &clen);
        if (client_fd < 0) {
            if (g_keep_running) perror("[-] accept");
            continue;
        }

        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &caddr.sin_addr, ip_str, sizeof(ip_str));
        printf("\n[*] Connection accepted from %s:%d\n", ip_str, ntohs(caddr.sin_port));

        SSL *ssl = SSL_new(ssl_ctx);
        if (!ssl) {
            ERR_print_errors_fp(stderr);
            close(client_fd);
            continue;
        }

        SSL_set_fd(ssl, client_fd);

        printf("[*] Performing TLS handshake (STSAFE-A CertificateVerify signature) ...\n");
        int ret = SSL_accept(ssl);
        if (ret <= 0) {
            fprintf(stderr, "[-] TLS Handshake failed\n");
            ERR_print_errors_fp(stderr);
        } else {
            printf("[+] TLS Handshake established!\n");
            printf("    -> Protocol : %s\n", SSL_get_version(ssl));
            printf("    -> Cipher   : %s\n", SSL_get_cipher(ssl));
            handle_client(ssl);
        }

        SSL_free(ssl);
        close(client_fd);
    }

    /* ----------------------------------------------------------------
     * 6. Cleanup & Shutdown
     * --------------------------------------------------------------- */
    printf("\n[*] Shutting down HTTPS server ...\n");
    close(listen_fd);
    SSL_CTX_free(ssl_ctx);
    X509_free(cert);
    EVP_PKEY_free(hw_key);
    OSSL_PROVIDER_unload(prov_stse);
    OSSL_PROVIDER_unload(prov_default);

    printf("[+] HTTPS Server terminated gracefully.\n");
    return EXIT_SUCCESS;
}
