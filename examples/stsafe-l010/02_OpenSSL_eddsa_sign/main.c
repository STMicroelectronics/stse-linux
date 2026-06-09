/**
 * *****************************************************************************
 * @file    main.c
 * @brief   STSAFE-L010 OpenSSL 3.x Provider demo — Linux/MPU port
 * *****************************************************************************
 *           COPYRIGHT 2026 STMicroelectronics
 * *****************************************************************************
 * Usage:  ./l010_02_OpenSSL_eddsa_sign [busID [slotID]]
 *         (defaults: busID=1, slotID=0)
 *
 * Prerequisites:
 *   OPENSSL_MODULES=<path/to/build>  — directory containing stse.so
 *   se-daemon running, libstse.so installed
 *
 * How it works (all via standard OpenSSL 3.x EVP APIs):
 *   1. Initialize STSAFE-L010 native handler and read the device certificate.
 *   2. Parse the device certificate using libstse to extract the public key.
 *   3. Load the "stse" provider (stse.so) and the "default" provider.
 *   4. Import the public key and configure slot/bus using EVP_PKEY_fromdata()
 *      to construct an EVP_PKEY context linked to the hardware slot.
 *   5. Sign test data on hardware via one-shot EVP_DigestSign() with
 *      "provider=stse" context property.
 *   6. Verify the signature in software via one-shot EVP_DigestVerify()
 *      using the default provider context.
 *
 * *****************************************************************************
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>

#include "stselib.h"
#include "stse_provider.h"   /* STSE_PROV_PARAM_SLOT, STSE_PROV_PARAM_BUS */

#define TEST_DATA_LEN   16
#define STSAFE_CERTIFICATE_ZONE_0 0U

static void ssl_die(const char *msg)
{
    fprintf(stderr, "ERROR: %s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
    stse_ReturnCode_t stse_ret;
    stse_Handler_t stse_handler;
    uint32_t bus_id = 1;
    uint32_t slot   = 0;

    if (argc > 1) bus_id = (uint32_t)atoi(argv[1]);
    if (argc > 2) slot   = (uint32_t)atoi(argv[2]);

    printf("--------------------------------------------------\n");
    printf("-     STSAFE-L010 OpenSSL 3.x Provider demo      -\n");
    printf("--------------------------------------------------\n\n");

    /* ----------------------------------------------------------------
     * 1. Initialize native STSAFE-L010 to read the device certificate
     * --------------------------------------------------------------- */
    printf("[1] Initializing target STSAFE-L010 on bus %u ...\n", bus_id);
    stse_ret = stse_set_default_handler_value(&stse_handler);
    if (stse_ret != STSE_OK) {
        fprintf(stderr, "    stse_set_default_handler_value ERROR : 0x%04X\n", stse_ret);
        return EXIT_FAILURE;
    }

    stse_handler.device_type = STSAFE_L010;
    stse_handler.io.busID    = (uint8_t)bus_id;
    stse_handler.io.BusSpeed = 100;
    stse_handler.io.Devaddr  = 0x0C;

    stse_ret = stse_init(&stse_handler);
    if (stse_ret != STSE_OK) {
        fprintf(stderr, "    stse_init ERROR : 0x%04X\n", stse_ret);
        return EXIT_FAILURE;
    }
    printf("    STSAFE-L010 initialized successfully.\n\n");

    /* ----------------------------------------------------------------
     * 2. Read and Parse the Device Certificate
     * --------------------------------------------------------------- */
    printf("[2] Reading and parsing device certificate ...\n");
    uint16_t cert_size = 0;
    stse_ret = stse_get_device_certificate_size(&stse_handler, STSAFE_CERTIFICATE_ZONE_0, &cert_size);
    if (stse_ret != STSE_OK) {
        fprintf(stderr, "    stse_get_device_certificate_size ERROR : 0x%04X\n", stse_ret);
        return EXIT_FAILURE;
    }

    uint8_t *cert_buf = malloc(cert_size);
    if (!cert_buf) {
        fprintf(stderr, "    Allocation failed for certificate buffer (%u bytes).\n", cert_size);
        return EXIT_FAILURE;
    }

    stse_ret = stse_get_device_certificate(&stse_handler, STSAFE_CERTIFICATE_ZONE_0, cert_size, cert_buf);
    if (stse_ret != STSE_OK) {
        fprintf(stderr, "    stse_get_device_certificate ERROR : 0x%04X\n", stse_ret);
        free(cert_buf);
        return EXIT_FAILURE;
    }

    stse_certificate_t parsed_cert;
    stse_ret = stse_certificate_parse(cert_buf, &parsed_cert, NULL);
    if (stse_ret != STSE_OK) {
        fprintf(stderr, "    stse_certificate_parse ERROR : 0x%04X\n", stse_ret);
        free(cert_buf);
        return EXIT_FAILURE;
    }

    if (parsed_cert.EllipticCurve != EC_Ed25519) {
        fprintf(stderr, "    ERROR: Certificate public key curve is not Ed25519.\n");
        free(cert_buf);
        return EXIT_FAILURE;
    }
    printf("    Ed25519 Certificate read successfully (%u bytes).\n\n", cert_size);
    free(cert_buf);

    /* ----------------------------------------------------------------
     * 3. Load OpenSSL providers
     *    stsafel.so — hardware keygen + sign (STSAFE-L010)
     *    default  — software verify, RNG
     * --------------------------------------------------------------- */
    OSSL_PROVIDER *prov_stse    = OSSL_PROVIDER_load(NULL, "stsafel");
    OSSL_PROVIDER *prov_default = OSSL_PROVIDER_load(NULL, "default");

    if (!prov_stse)
        ssl_die("OSSL_PROVIDER_load(\"stsafel\") failed — "
                "set OPENSSL_MODULES to the directory containing stsafel.so");
    if (!prov_default)
        ssl_die("OSSL_PROVIDER_load(\"default\") failed");

    printf("[3] Providers loaded (stsafel + default)  OK\n");

    /* ----------------------------------------------------------------
     * 4. Build EVP_PKEY from parsed public key and configuration
     * --------------------------------------------------------------- */
    printf("[4] Building EVP_PKEY from public key (fromdata) ...");
    fflush(stdout);

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, "ED25519", "provider=stsafel");
    if (!pctx)                               ssl_die("EVP_PKEY_CTX_new_from_name");
    if (EVP_PKEY_fromdata_init(pctx) <= 0)   ssl_die("EVP_PKEY_fromdata_init");

    OSSL_PARAM params[4];
    uint32_t slot_val = slot;
    uint32_t bus_val  = bus_id;
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                                  (void *)parsed_cert.PubKey.pX,
                                                  parsed_cert.PubKey.fsize);
    params[1] = OSSL_PARAM_construct_uint32(STSE_PROV_PARAM_SLOT, &slot_val);
    params[2] = OSSL_PARAM_construct_uint32(STSE_PROV_PARAM_BUS,  &bus_val);
    params[3] = OSSL_PARAM_construct_end();

    EVP_PKEY *hw_pkey = NULL;
    if (EVP_PKEY_fromdata(pctx, &hw_pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0)
        ssl_die("EVP_PKEY_fromdata");
    EVP_PKEY_CTX_free(pctx);
    printf("  OK\n");

    /* ----------------------------------------------------------------
     * 5. Random test data
     * --------------------------------------------------------------- */
    unsigned char test_data[TEST_DATA_LEN];
    if (RAND_bytes(test_data, sizeof(test_data)) != 1)
        ssl_die("RAND_bytes");
    printf("[5] Generated %d bytes of random test data  OK\n", TEST_DATA_LEN);

    /* ----------------------------------------------------------------
     * 6. Sign with STSAFE-L010 hardware via standard EVP_DigestSign API
     * --------------------------------------------------------------- */
    printf("[6] Ed25519 sign (hardware) ...");
    fflush(stdout);

    EVP_MD_CTX *sign_ctx = EVP_MD_CTX_new();
    if (!sign_ctx) ssl_die("EVP_MD_CTX_new (sign)");

    if (EVP_DigestSignInit_ex(sign_ctx, NULL, NULL, NULL,
                              "provider=stsafel", hw_pkey, NULL) <= 0)
        ssl_die("EVP_DigestSignInit_ex");

    size_t sig_len = 0;
    if (EVP_DigestSign(sign_ctx, NULL, &sig_len, test_data, sizeof(test_data)) <= 0)
        ssl_die("EVP_DigestSign (size query)");

    unsigned char *sig = OPENSSL_malloc(sig_len);
    if (!sig) ssl_die("OPENSSL_malloc");

    if (EVP_DigestSign(sign_ctx, sig, &sig_len, test_data, sizeof(test_data)) <= 0)
        ssl_die("EVP_DigestSign");
    EVP_MD_CTX_free(sign_ctx);
    printf("  OK  (%zu bytes raw)\n", sig_len);

    /* ----------------------------------------------------------------
     * 7. Verify with default provider (software)
     * --------------------------------------------------------------- */
    printf("[7] Ed25519 verify (OpenSSL software, default provider) ...");
    fflush(stdout);

    EVP_MD_CTX *vfy_ctx = EVP_MD_CTX_new();
    if (!vfy_ctx) ssl_die("EVP_MD_CTX_new (verify)");

    if (EVP_DigestVerifyInit_ex(vfy_ctx, NULL, NULL, NULL,
                                NULL, hw_pkey, NULL) <= 0)
        ssl_die("EVP_DigestVerifyInit_ex");

    int vfy = EVP_DigestVerify(vfy_ctx, sig, sig_len, test_data, sizeof(test_data));
    EVP_MD_CTX_free(vfy_ctx);
    OPENSSL_free(sig);
    EVP_PKEY_free(hw_pkey);
    OSSL_PROVIDER_unload(prov_stse);
    OSSL_PROVIDER_unload(prov_default);

    printf("  %s\n\n", (vfy == 1) ? "OK" : "FAIL");

    if (vfy == 1) {
        printf("Ed25519 provider demo: SUCCESS\n");
        return EXIT_SUCCESS;
    }
    ERR_print_errors_fp(stderr);
    printf("Ed25519 provider demo: FAILED\n");
    return EXIT_FAILURE;
}
