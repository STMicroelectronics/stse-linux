/**
 * *****************************************************************************
 * @file    main.c
 * @brief   STSAFE-A120 OpenSSL 3.x Provider ECDSA demo — Linux/MPU port
 * *****************************************************************************
 *           COPYRIGHT 2026 STMicroelectronics
 * *****************************************************************************
 * Usage:  ./a120_02_OpenSSL_ecdsa_sign_verify [busID [slotID]]
 *         (defaults: busID=1, slotID=0)
 *
 * Prerequisites:
 *   OPENSSL_MODULES=<path/to/build>  — directory containing stsafea.so
 *   se-daemon running, libstse.so installed
 *
 * How it works (all via standard OpenSSL 3.x EVP APIs):
 *   1. Load the "stsafea" provider (stsafea.so) and the "default" provider.
 *   2. Generate a NIST-P256 key pair on STSAFE-A hardware using
 *      EVP_PKEY_generate() with "provider=stsafea" property and custom
 *      stse-slot / stse-bus parameters. Private key never leaves HW.
 *   3. Sign test data on hardware via EVP_DigestSign* ("provider=stsafea").
 *   4. Verify the signature in hardware via EVP_DigestVerify* ("provider=stsafea").
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

#include "stse_provider.h"   /* STSE_PROV_PARAM_SLOT, STSE_PROV_PARAM_BUS */

#define TEST_DATA_LEN   64

static void ssl_die(const char *msg)
{
    fprintf(stderr, "ERROR: %s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
    uint32_t bus_id = 1;
    uint32_t slot   = 0;
    if (argc > 1) bus_id = (uint32_t)atoi(argv[1]);
    if (argc > 2) slot   = (uint32_t)atoi(argv[2]);

    printf("--------------------------------------------------\n");
    printf("-     STSAFE-A120 OpenSSL 3.x Provider ECDSA     -\n");
    printf("-           Sign & Verify Demo                   -\n");
    printf("--------------------------------------------------\n\n");

    /* ----------------------------------------------------------------
     * 1. Load providers
     *    stsafea.so — hardware keygen + sign + verify (STSAFE-A120)
     *    default    — software fallback/digest/RNG helper
     * --------------------------------------------------------------- */
    OSSL_PROVIDER *prov_stse    = OSSL_PROVIDER_load(NULL, "stsafea");
    OSSL_PROVIDER *prov_default = OSSL_PROVIDER_load(NULL, "default");

    if (!prov_stse)
        ssl_die("OSSL_PROVIDER_load(\"stsafea\") failed — "
                "set OPENSSL_MODULES to the directory containing stsafea.so");
    if (!prov_default)
        ssl_die("OSSL_PROVIDER_load(\"default\") failed");

    printf("[1] Providers loaded (stsafea + default)  OK\n");

    /* ----------------------------------------------------------------
     * 2. Generate NIST-P256 key pair on STSAFE-A hardware
     * --------------------------------------------------------------- */
    printf("[2] Generating NIST-P256 key pair on slot %u bus %u ...",
           slot, bus_id);
    fflush(stdout);

    OSSL_PARAM gen_params[] = {
        OSSL_PARAM_uint32(STSE_PROV_PARAM_SLOT, &slot),
        OSSL_PARAM_uint32(STSE_PROV_PARAM_BUS,  &bus_id),
        OSSL_PARAM_END
    };

    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_from_name(NULL, "EC",
                                                      "provider=stsafea");
    if (!kctx)                               ssl_die("EVP_PKEY_CTX_new_from_name");
    if (EVP_PKEY_keygen_init(kctx) <= 0)    ssl_die("EVP_PKEY_keygen_init");
    if (EVP_PKEY_CTX_set_params(kctx, gen_params) <= 0)
                                             ssl_die("EVP_PKEY_CTX_set_params");

    EVP_PKEY *hw_pkey = NULL;
    if (EVP_PKEY_generate(kctx, &hw_pkey) <= 0)
        ssl_die("EVP_PKEY_generate — check stse-daemon and key slot AC");
    EVP_PKEY_CTX_free(kctx);
    printf("  OK\n");

    /* ----------------------------------------------------------------
     * 3. Random test data
     * --------------------------------------------------------------- */
    unsigned char test_data[TEST_DATA_LEN];
    if (RAND_bytes(test_data, sizeof(test_data)) != 1)
        ssl_die("RAND_bytes");
    printf("[3] Generated %d bytes of random test data  OK\n", TEST_DATA_LEN);

    /* ----------------------------------------------------------------
     * 4. Sign with STSAFE-A hardware via standard EVP_DigestSign* API
     * --------------------------------------------------------------- */
    printf("[4] ECDSA sign (hardware, SHA-256) ...");
    fflush(stdout);

    EVP_MD_CTX *sign_ctx = EVP_MD_CTX_new();
    if (!sign_ctx) ssl_die("EVP_MD_CTX_new (sign)");

    if (EVP_DigestSignInit_ex(sign_ctx, NULL, "SHA2-256", NULL,
                              "provider=stsafea", hw_pkey, NULL) <= 0)
        ssl_die("EVP_DigestSignInit_ex");
    if (EVP_DigestSignUpdate(sign_ctx, test_data, sizeof(test_data)) <= 0)
        ssl_die("EVP_DigestSignUpdate");

    size_t sig_len = 0;
    if (EVP_DigestSignFinal(sign_ctx, NULL, &sig_len) <= 0)
        ssl_die("EVP_DigestSignFinal (size query)");

    unsigned char *sig = OPENSSL_malloc(sig_len);
    if (!sig) ssl_die("OPENSSL_malloc");

    if (EVP_DigestSignFinal(sign_ctx, sig, &sig_len) <= 0)
        ssl_die("EVP_DigestSignFinal");
    EVP_MD_CTX_free(sign_ctx);
    printf("  OK  (%zu bytes DER)\n", sig_len);

    /* ----------------------------------------------------------------
     * 5. Verify with STSAFE-A hardware
     * --------------------------------------------------------------- */
    printf("[5] ECDSA verify (STSAFE-A120 hardware, stsafea provider) ...");
    fflush(stdout);

    EVP_MD_CTX *vfy_ctx = EVP_MD_CTX_new();
    if (!vfy_ctx) ssl_die("EVP_MD_CTX_new (verify)");

    if (EVP_DigestVerifyInit_ex(vfy_ctx, NULL, "SHA2-256", NULL,
                                "provider=stsafea", hw_pkey, NULL) <= 0)
        ssl_die("EVP_DigestVerifyInit_ex");
    if (EVP_DigestVerifyUpdate(vfy_ctx, test_data, sizeof(test_data)) <= 0)
        ssl_die("EVP_DigestVerifyUpdate");

    int vfy = EVP_DigestVerifyFinal(vfy_ctx, sig, sig_len);
    EVP_MD_CTX_free(vfy_ctx);
    OPENSSL_free(sig);
    EVP_PKEY_free(hw_pkey);
    OSSL_PROVIDER_unload(prov_stse);
    OSSL_PROVIDER_unload(prov_default);

    printf("  %s\n\n", (vfy == 1) ? "OK" : "FAIL");

    if (vfy == 1) {
        printf("ECDSA provider sign/verify demo: SUCCESS\n");
        return EXIT_SUCCESS;
    }
    ERR_print_errors_fp(stderr);
    printf("ECDSA provider sign/verify demo: FAILED\n");
    return EXIT_FAILURE;
}
