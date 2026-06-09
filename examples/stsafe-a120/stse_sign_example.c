/**
 ******************************************************************************
 * @file    stse_sign_example.c
 * @author  CS application team
 * @brief   STSAFE ECDSA signature example via PKCS#11 (STSELib sal/pkcs11)
 ******************************************************************************
 *           COPYRIGHT 2024 STMicroelectronics
 *
 * This software is licensed under terms that can be found in the LICENSE file in
 * the root directory of this software component.
 * If no LICENSE file comes with this software, it is provided AS-IS.
 *
 ******************************************************************************
 *
 * Demonstrates ECDSA-SHA256 signature generation using the PKCS#11 Cryptoki
 * interface provided directly by STSELib (STSELib/sal/pkcs11/stse_cryptoki.c).
 * This is the same STSELib that is compiled into libstse.so unchanged.
 *
 * Call flow:
 *   Application → C_Sign() [STSELib sal/pkcs11]
 *               → stse_ecc_generate_signature() [STSELib api/]
 *               → stse_platform_i2c_* [modified platform layer]
 *               → se-daemon (IPC, /var/run/se-daemon.sock)
 *               → /dev/i2c-N
 *
 * The application calls standard PKCS#11 C_* functions — no custom wrappers,
 * no daemon awareness.  The bus proxy is transparent.
 *
 * Steps:
 *   1. C_Initialize()   — init STSELib PKCS#11 provider
 *   2. C_OpenSession()  — open session on slot 0
 *   3. C_FindObjects()  — find the private key in slot 0
 *   4. C_SignInit()     — select CKM_ECDSA_SHA256
 *   5. C_Sign()         — hash + sign on STSAFE-A chip
 *   6. C_CloseSession() / C_Finalize()
 *   8. C_Finalize()     — clean up
 *
 * Usage:
 *   ./stse_sign_example [busID]
 *
 * Prerequisites:
 *   - se-daemon must be running: systemctl start se-daemon
 *   - The calling user must be in the 'se-daemon' group
 *   - The STSAFE-A must have a NIST P-256 key in slot 0
 *
 ******************************************************************************
 */

#include "stselib.h"
#include "sal/pkcs11/pkcs11.h"
#include "sal/pkcs11/stse_pkcs11.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define NIST_P256_SIG_SIZE  64U

static const char test_message[] = "STSAFE PKCS11 signature test message";

static void print_hex(const char *label, const uint8_t *buf, size_t len)
{
    printf("  %s", label);
    for (size_t i = 0; i < len; i++) {
        if (i > 0 && (i % 16) == 0) { printf("\n        "); }
        printf("%02X ", buf[i]);
    }
    printf("\n");
}

static const char *ckr_str(CK_RV rv)
{
    switch (rv) {
        case CKR_OK:                      return "CKR_OK";
        case CKR_CRYPTOKI_NOT_INITIALIZED: return "CKR_CRYPTOKI_NOT_INITIALIZED";
        case CKR_DEVICE_ERROR:            return "CKR_DEVICE_ERROR";
        case CKR_SESSION_HANDLE_INVALID:  return "CKR_SESSION_HANDLE_INVALID";
        case CKR_KEY_HANDLE_INVALID:      return "CKR_KEY_HANDLE_INVALID";
        case CKR_ARGUMENTS_BAD:           return "CKR_ARGUMENTS_BAD";
        case CKR_BUFFER_TOO_SMALL:        return "CKR_BUFFER_TOO_SMALL";
        default: {
            static char buf[32];
            snprintf(buf, sizeof(buf), "0x%08lX", (unsigned long)rv);
            return buf;
        }
    }
}

int main(int argc, char *argv[])
{
    uint8_t           busID     = 1;
    CK_RV             rv;
    CK_SESSION_HANDLE hSession  = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE  hKey      = CK_INVALID_HANDLE;
    uint8_t           signature[NIST_P256_SIG_SIZE + 4];
    CK_ULONG          sig_len   = sizeof(signature);

    if (argc > 1) busID = (uint8_t)atoi(argv[1]);

    printf("------------------------------------------------------------\n");
    printf("-       STSAFE-A ECDSA Signature Example (PKCS#11)         -\n");
    printf("------------------------------------------------------------\n");
    printf("I2C bus: /dev/i2c-%u  (via se-daemon)\n\n", (unsigned)busID);

    /* Configure the STSELib PKCS#11 provider before C_Initialize */
    stse_pkcs11_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.i2c_addr    = 0x20U;
    cfg.bus_id      = busID;
    cfg.bus_speed   = 400U;
    cfg.device_type = STSAFE_A120;
    stse_pkcs11_set_config(&cfg);

    /* ---- 1. Initialize ---- */
    printf("[1] C_Initialize...\n");
    rv = C_Initialize(NULL);
    if (rv != CKR_OK) {
        fprintf(stderr, "    FAILED: %s\n    Is se-daemon running?\n", ckr_str(rv));
        return EXIT_FAILURE;
    }
    printf("    OK\n\n");

    /* ---- 2. Open session on slot 0 ---- */
    printf("[2] C_OpenSession...\n");
    rv = C_OpenSession(0, CKF_SERIAL_SESSION, NULL, NULL, &hSession);
    if (rv != CKR_OK) {
        fprintf(stderr, "    FAILED: %s\n", ckr_str(rv));
        C_Finalize(NULL);
        return EXIT_FAILURE;
    }
    printf("    Session handle: %lu\n\n", (unsigned long)hSession);

    /* ---- 3. Find private key in slot 0 ---- */
    printf("[3] C_FindObjects (CKO_PRIVATE_KEY)...\n");
    CK_OBJECT_CLASS klass = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE    tmpl  = { CKA_CLASS, &klass, sizeof(klass) };
    CK_ULONG        found = 0;

    rv = C_FindObjectsInit(hSession, &tmpl, 1);
    if (rv == CKR_OK) {
        rv = C_FindObjects(hSession, &hKey, 1, &found);
        C_FindObjectsFinal(hSession);
    }
    if (rv != CKR_OK || found == 0) {
        fprintf(stderr, "    FAILED: %s (found=%lu)\n", ckr_str(rv), (unsigned long)found);
        fprintf(stderr, "    No key provisioned in slot 0?\n");
        C_CloseSession(hSession);
        C_Finalize(NULL);
        return EXIT_FAILURE;
    }
    printf("    Private key handle: 0x%08lX\n\n", (unsigned long)hKey);

    /* ---- 5. SignInit with CKM_ECDSA_SHA256 ---- */
    printf("[4] C_SignInit (CKM_ECDSA_SHA256)...\n");
    CK_MECHANISM mech = { CKM_ECDSA_SHA256, NULL, 0 };
    rv = C_SignInit(hSession, &mech, hKey);
    if (rv != CKR_OK) {
        fprintf(stderr, "    FAILED: %s\n", ckr_str(rv));
        C_CloseSession(hSession);
        C_Finalize(NULL);
        return EXIT_FAILURE;
    }
    printf("    OK\n\n");

    /* ---- 5. Sign ---- */
    printf("[5] C_Sign...\n");
    printf("    Message: \"%s\"\n", test_message);
    rv = C_Sign(hSession,
                (CK_BYTE_PTR)(uintptr_t)test_message,
                (CK_ULONG)strlen(test_message),
                signature, &sig_len);
    if (rv != CKR_OK) {
        fprintf(stderr, "    FAILED: %s\n", ckr_str(rv));
        C_CloseSession(hSession);
        C_Finalize(NULL);
        return EXIT_FAILURE;
    }
    print_hex("Signature (r||s): ", signature, (size_t)sig_len);
    printf("    OK (%lu bytes)\n\n", (unsigned long)sig_len);

    /* ---- 6. Cleanup ---- */
    printf("[6] C_CloseSession...\n");
    C_CloseSession(hSession);
    printf("    OK\n\n");

    /* ---- 7. Finalize ---- */
    printf("[7] C_Finalize...\n");
    C_Finalize(NULL);
    printf("    OK\n\n");

    printf("------------------------------------------------------------\n");
    printf("  ECDSA-SHA256 signature generated successfully via PKCS#11.\n");
    printf("------------------------------------------------------------\n");
    return EXIT_SUCCESS;
}
