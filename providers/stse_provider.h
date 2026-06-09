/**
 ******************************************************************************
 * @file    stse_provider.h
 * @brief   STSAFE-A120 OpenSSL 3.x Provider — public header
 ******************************************************************************
 *           COPYRIGHT 2024 STMicroelectronics
 ******************************************************************************
 *
 * This header is the only public interface needed by applications that load
 * the stse provider.  It exposes the custom OSSL_PARAM key names used to
 * pass the hardware slot number and I²C bus ID at key generation time.
 *
 * Usage in application code:
 *
 *   #include "stse_provider.h"          // for STSE_PROV_PARAM_*
 *   #include <openssl/provider.h>
 *   #include <openssl/evp.h>
 *   #include <openssl/params.h>
 *
 *   // Load the provider (stse.so must be in OPENSSL_MODULES directory)
 *   OSSL_PROVIDER *prov = OSSL_PROVIDER_load(NULL, "stse");
 *
 *   // Generate a hardware-backed NIST P-256 key pair on slot 1, bus 1
 *   uint32_t slot = 1, bus = 1;
 *   OSSL_PARAM params[] = {
 *       OSSL_PARAM_uint32(STSE_PROV_PARAM_SLOT, &slot),
 *       OSSL_PARAM_uint32(STSE_PROV_PARAM_BUS,  &bus),
 *       OSSL_PARAM_END
 *   };
 *   EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", "provider=stse");
 *   EVP_PKEY_keygen_init(kctx);
 *   EVP_PKEY_CTX_set_params(kctx, params);
 *   EVP_PKEY *pkey = NULL;
 *   EVP_PKEY_generate(kctx, &pkey);
 *
 *   // Sign with hardware via standard EVP_DigestSign* API
 *   EVP_MD_CTX *mctx = EVP_MD_CTX_new();
 *   EVP_DigestSignInit_ex(mctx, NULL, "SHA2-256", NULL, "provider=stse", pkey, NULL);
 *   EVP_DigestSignUpdate(mctx, data, len);
 *   EVP_DigestSignFinal(mctx, sig, &sig_len);
 *
 *   // Verify in software — OpenSSL automatically exports the public key
 *   // from the stse provider and imports it into the default EC keymgmt
 *   EVP_MD_CTX *vctx = EVP_MD_CTX_new();
 *   EVP_DigestVerifyInit_ex(vctx, NULL, "SHA2-256", NULL, NULL, pkey, NULL);
 *   EVP_DigestVerifyUpdate(vctx, data, len);
 *   int ok = EVP_DigestVerifyFinal(vctx, sig, sig_len);
 *
 ******************************************************************************
 */

#ifndef STSE_PROVIDER_H
#define STSE_PROVIDER_H

/**
 * @brief Custom OSSL_PARAM key: STSAFE-A hardware key slot number (uint32_t).
 *        Valid range: 0 .. (number of ECC slots on device - 1).
 *        Default if not supplied: 0.
 */
#define STSE_PROV_PARAM_SLOT  "stse-slot"

/**
 * @brief Custom OSSL_PARAM key: Linux I²C bus number (uint32_t).
 *        Selects /dev/i2c-N via the se-daemon IPC.
 *        Default if not supplied: 1  (/dev/i2c-1).
 */
#define STSE_PROV_PARAM_BUS   "stse-bus"

/**
 * @brief Custom OSSL_PARAM key: I²C device address (uint32_t).
 *        7-bit I²C address of the secure element on the selected bus.
 *        Default if not supplied: 0x20 for STSAFE-A120, 0x0C for STSAFE-L010.
 */
#define STSE_PROV_PARAM_DEVADDR "stse-devaddr"

#endif /* STSE_PROVIDER_H */
