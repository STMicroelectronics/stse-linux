/**
 * *****************************************************************************
 * @file    stsafel_provider.c
 * @brief   STSAFE-L010 OpenSSL 3.x Provider
 * *****************************************************************************
 *           COPYRIGHT 2026 STMicroelectronics
 * *****************************************************************************
 */

#define _GNU_SOURCE
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

#include "stselib.h"
#include "stse_provider.h"

/* =========================================================================
 * NOTE: stsafel.so links directly against libstse.so — no dlopen/dlsym.
 * =========================================================================

/* =========================================================================
 * Provider context — one per OSSL_PROVIDER_load() call
 * ========================================================================= */
typedef struct stse_provctx_st {
    const OSSL_CORE_HANDLE *handle;
    stse_Handler_t          handler;
    uint8_t                 active_bus_id;   /* bus used for current handler  */
    uint8_t                 active_dev_addr; /* I²C device address in use    */
    int                     initialized;
} stse_provctx_t;

/* =========================================================================
 * Key data — per EVP_PKEY
 * ========================================================================= */
typedef struct stse_key_st {
    stse_provctx_t *provctx;
    uint8_t         slot;
    uint8_t         bus_id;
    uint8_t         dev_addr;
    uint8_t         pub_point[32]; /* raw 32 bytes for Ed25519 */
    size_t          pub_len;
    int             has_pub;
} stse_key_t;

/* =========================================================================
 * Key generation context — per EVP_PKEY_CTX (keygen)
 * ========================================================================= */
typedef struct stse_genctx_st {
    stse_provctx_t *provctx;
    uint8_t         slot;
    uint8_t         bus_id;
    uint8_t         dev_addr;
} stse_genctx_t;

/* =========================================================================
 * Signature context — per EVP_MD_CTX sign/verify operation
 * ========================================================================= */
typedef struct stse_sigctx_st {
    stse_provctx_t *provctx;
    stse_key_t     *key;    /* borrowed from EVP_PKEY */
    EVP_MD_CTX     *md_ctx;
    EVP_PKEY_CTX   *sw_pkey_ctx;
} stse_sigctx_t;

/* =========================================================================
 * Forward declarations
 * ========================================================================= */
static int stse_keymgmt_gen_set_params(void *vgenctx, const OSSL_PARAM params[]);
static void *stse_keymgmt_new(void *vprovctx);
static void  stse_keymgmt_free(void *vkey);

/* =========================================================================
 * libstse.so loading + STSAFE-L initialisation
 * ========================================================================= */

static int provctx_ensure_init(stse_provctx_t *pctx, uint8_t bus_id,
                                uint8_t dev_addr, stse_device_t dev_type)
{
    if (pctx->initialized && pctx->active_bus_id == bus_id &&
        pctx->active_dev_addr == dev_addr && pctx->handler.device_type == dev_type)
        return 1;

    stse_ReturnCode_t rc = stse_set_default_handler_value(&pctx->handler);
    if (rc != STSE_OK) {
        fprintf(stderr, "[stsafel_provider] set_default_handler_value: %d\n", rc);
        return 0;
    }

    pctx->handler.device_type = dev_type;
    pctx->handler.io.busID    = bus_id;
    pctx->handler.io.BusSpeed = 100;
    pctx->handler.io.Devaddr  = dev_addr;

    rc = stse_init(&pctx->handler);
    if (rc != STSE_OK) {
        fprintf(stderr, "[stsafel_provider] stse_init (device %d, bus %u, devaddr 0x%02X): %d\n",
                dev_type, bus_id, dev_addr, rc);
        pctx->initialized = 0;
        return 0;
    }

    pctx->active_bus_id   = bus_id;
    pctx->active_dev_addr = dev_addr;
    pctx->initialized     = 1;
    return 1;
}

/* =========================================================================
 * KEYMGMT — key lifecycle
 * ========================================================================= */

static void *stse_keymgmt_new(void *vprovctx)
{
    stse_key_t *key = OPENSSL_zalloc(sizeof(*key));
    if (!key) return NULL;
    key->provctx    = (stse_provctx_t *)vprovctx;
    key->slot       = 0;
    key->bus_id     = 1;
    key->has_pub    = 0;
    return key;
}

static void *stsafel_ed_keymgmt_new(void *vprovctx)
{
    stse_key_t *key = stse_keymgmt_new(vprovctx);
    if (key) {
        key->pub_len  = 32;
        key->dev_addr = 0x0C; /* default STSAFE-L010 I²C address */
    }
    return key;
}

static void stse_keymgmt_free(void *vkey)
{
    OPENSSL_free(vkey);
}

static int stsafel_ed_keymgmt_has(const void *vkey, int selection)
{
    const stse_key_t *key = (const stse_key_t *)vkey;
    if (!key) return 0;

    int ok = 1;
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
        ok = ok && 1;  /* present on-chip */
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
        ok = ok && key->has_pub;

    return ok;
}

static int stsafel_ed_keymgmt_export(void *vkey, int selection,
                                     OSSL_CALLBACK *cb, void *cbarg)
{
    stse_key_t *key = (stse_key_t *)vkey;
    if (!key) return 0;

    if (!(selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY))
        return 1;
    if (!key->has_pub)
        return 0;

    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_octet_string(
        OSSL_PKEY_PARAM_PUB_KEY, key->pub_point, key->pub_len);
    params[1] = OSSL_PARAM_construct_end();
    return cb(params, cbarg);
}

static const OSSL_PARAM stsafel_ed_keymgmt_export_types_tab[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY,   NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *stsafel_ed_keymgmt_export_types(int selection)
{
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
        return stsafel_ed_keymgmt_export_types_tab;
    return NULL;
}

static int stsafel_ed_keymgmt_import(void *vkey, int selection,
                                     const OSSL_PARAM params[])
{
    stse_key_t *key = (stse_key_t *)vkey;
    if (!key) return 0;

    if (!(selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY))
        return 1;

    const OSSL_PARAM *p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (!p) return 0;

    const void *pub_data = NULL;
    size_t      pub_len  = 0;
    if (!OSSL_PARAM_get_octet_string_ptr(p, &pub_data, &pub_len))
        return 0;

    if (pub_len != 32) return 0;

    memcpy(key->pub_point, pub_data, 32);
    key->pub_len = 32;
    key->has_pub = 1;

    const OSSL_PARAM *p_slot = OSSL_PARAM_locate_const(params, STSE_PROV_PARAM_SLOT);
    if (p_slot) {
        uint32_t val;
        if (OSSL_PARAM_get_uint32(p_slot, &val))
            key->slot = (uint8_t)val;
    }

    const OSSL_PARAM *p_bus = OSSL_PARAM_locate_const(params, STSE_PROV_PARAM_BUS);
    if (p_bus) {
        uint32_t val;
        if (OSSL_PARAM_get_uint32(p_bus, &val))
            key->bus_id = (uint8_t)val;
    }

    const OSSL_PARAM *p_da = OSSL_PARAM_locate_const(params, STSE_PROV_PARAM_DEVADDR);
    if (p_da) {
        uint32_t val;
        if (OSSL_PARAM_get_uint32(p_da, &val))
            key->dev_addr = (uint8_t)val;
    }

    return 1;
}

static const OSSL_PARAM *stsafel_ed_keymgmt_import_types(int selection)
{
    return stsafel_ed_keymgmt_export_types(selection);
}

static const OSSL_PARAM stse_keymgmt_gettable_params_tab[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY,   NULL, 0),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS,               NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *stse_keymgmt_gettable_params(void *vprovctx)
{
    (void)vprovctx;
    return stse_keymgmt_gettable_params_tab;
}

static int stsafel_ed_keymgmt_get_params(void *vkey, OSSL_PARAM params[])
{
    stse_key_t *key = (stse_key_t *)vkey;
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (p) {
        if (!key->has_pub) return 0;
        if (!OSSL_PARAM_set_octet_string(p, key->pub_point, key->pub_len))
            return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if (p) {
        int bits = 256;
        if (!OSSL_PARAM_set_int(p, bits)) return 0;
    }
    return 1;
}

/* =========================================================================
 * KEYMGMT — key generation
 * ========================================================================= */

static void *stsafel_ed_keymgmt_gen_init(void *vprovctx, int selection,
                                         const OSSL_PARAM params[])
{
    if (!(selection & OSSL_KEYMGMT_SELECT_KEYPAIR)) return NULL;

    stse_genctx_t *gctx = OPENSSL_zalloc(sizeof(*gctx));
    if (!gctx) return NULL;

    gctx->provctx  = (stse_provctx_t *)vprovctx;
    gctx->slot     = 0;
    gctx->bus_id   = 1;
    gctx->dev_addr = 0x0C; /* default STSAFE-L010 I²C address */

    if (params)
        stse_keymgmt_gen_set_params(gctx, params);

    return gctx;
}

static int stse_keymgmt_gen_set_params(void *vgenctx,
                                        const OSSL_PARAM params[])
{
    stse_genctx_t *gctx = (stse_genctx_t *)vgenctx;
    const OSSL_PARAM *p;
    uint32_t val;

    p = OSSL_PARAM_locate_const(params, STSE_PROV_PARAM_SLOT);
    if (p) {
        if (!OSSL_PARAM_get_uint32(p, &val)) return 0;
        gctx->slot = (uint8_t)val;
    }

    p = OSSL_PARAM_locate_const(params, STSE_PROV_PARAM_BUS);
    if (p) {
        if (!OSSL_PARAM_get_uint32(p, &val)) return 0;
        gctx->bus_id = (uint8_t)val;
    }

    p = OSSL_PARAM_locate_const(params, STSE_PROV_PARAM_DEVADDR);
    if (p) {
        if (!OSSL_PARAM_get_uint32(p, &val)) return 0;
        gctx->dev_addr = (uint8_t)val;
    }

    return 1;
}

static const OSSL_PARAM stse_keymgmt_gen_settable_params_tab[] = {
    OSSL_PARAM_uint32(STSE_PROV_PARAM_SLOT,    NULL),
    OSSL_PARAM_uint32(STSE_PROV_PARAM_BUS,     NULL),
    OSSL_PARAM_uint32(STSE_PROV_PARAM_DEVADDR, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *stse_keymgmt_gen_settable_params(void *vgenctx,
                                                           void *vprovctx)
{
    (void)vgenctx; (void)vprovctx;
    return stse_keymgmt_gen_settable_params_tab;
}

static void *stse_keymgmt_gen(void *vgenctx, OSSL_CALLBACK *cb, void *cbarg)
{
    (void)cb; (void)cbarg;
    stse_genctx_t  *gctx = (stse_genctx_t *)vgenctx;
    stse_provctx_t *pctx = gctx->provctx;

    if (!provctx_ensure_init(pctx, gctx->bus_id, gctx->dev_addr, STSAFE_L010)) return NULL;

    stse_key_t *key = (stse_key_t *)stsafel_ed_keymgmt_new(pctx);
    if (!key) return NULL;
    key->slot     = gctx->slot;
    key->bus_id   = gctx->bus_id;
    key->dev_addr = gctx->dev_addr;

    uint8_t raw_pub[32];
    stse_ReturnCode_t rc = stse_generate_ecc_key_pair(&pctx->handler,
                                                       gctx->slot,
                                                       STSE_ECC_KT_ED25519,
                                                       255, raw_pub);
    if (rc != STSE_OK) {
        fprintf(stderr, "[stsafel_provider] Ed25519 keygen slot=%u bus=%u: err %d\n",
                gctx->slot, gctx->bus_id, rc);
        stse_keymgmt_free(key);
        return NULL;
    }

    memcpy(key->pub_point, raw_pub, 32);
    key->pub_len = 32;
    key->has_pub = 1;
    return key;
}

static void stse_keymgmt_gen_cleanup(void *vgenctx)
{
    OPENSSL_free(vgenctx);
}

static const char *stsafel_ed_keymgmt_query_operation_name(int operation_id)
{
    if (operation_id == OSSL_OP_SIGNATURE)
        return "ED25519";
    return NULL;
}

/* =========================================================================
 * SIGNATURE — signing helper (raw digest → DER)
 * ========================================================================= */

static int do_hw_sign(stse_provctx_t *pctx, stse_key_t *key,
                      const unsigned char *digest, size_t digest_len,
                      unsigned char *sig, size_t *siglen, size_t sigsize)
{
    if (!sig) {
        *siglen = 64;
        return 1;
    }
    if (sigsize < 64) return 0;

    // Enforce 16-byte challenge size for STSAFE-L010
    if (digest_len != 16) {
        fprintf(stderr, "[stsafel_provider] error: L010 requires strictly 16-byte challenge, got %zu\n", digest_len);
        return 0;
    }

    if (!provctx_ensure_init(pctx, key->bus_id, key->dev_addr, STSAFE_L010)) return 0;

    stse_ReturnCode_t rc = stse_ecc_generate_signature(&pctx->handler,
                                                        key->slot,
                                                        STSE_ECC_KT_ED25519,
                                                        digest, (PLAT_UI16)digest_len,
                                                        sig);
    if (rc != STSE_OK) {
        fprintf(stderr, "[stsafel_provider] Ed25519 sign slot=%u: err 0x%04X\n",
                key->slot, rc);
        return 0;
    }
    *siglen = 64;
    return 1;
}

static EVP_PKEY *stse_key_to_sw_pkey(const stse_key_t *key)
{
    if (!key || !key->has_pub) return NULL;

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, "ED25519", "provider=default");
    if (pctx == NULL) return NULL;

    if (EVP_PKEY_fromdata_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }

    OSSL_PARAM params[2];
    int np = 0;
    params[np++] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, (void *)key->pub_point, key->pub_len);
    params[np] = OSSL_PARAM_construct_end();

    EVP_PKEY *sw_pkey = NULL;
    if (EVP_PKEY_fromdata(pctx, &sw_pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(pctx);
    return sw_pkey;
}

/* =========================================================================
 * SIGNATURE — dispatch functions
 * ========================================================================= */

static void *stse_sig_newctx(void *vprovctx, const char *propq)
{
    (void)propq;
    stse_sigctx_t *sctx = OPENSSL_zalloc(sizeof(*sctx));
    if (!sctx) return NULL;
    sctx->provctx = (stse_provctx_t *)vprovctx;
    return sctx;
}

static void stse_sig_freectx(void *vsigctx)
{
    stse_sigctx_t *sctx = (stse_sigctx_t *)vsigctx;
    if (!sctx) return;
    EVP_MD_CTX_free(sctx->md_ctx);
    EVP_PKEY_CTX_free(sctx->sw_pkey_ctx);
    OPENSSL_free(sctx);
}

static void *stse_sig_dupctx(void *vsigctx)
{
    stse_sigctx_t *src = (stse_sigctx_t *)vsigctx;
    stse_sigctx_t *dst = OPENSSL_zalloc(sizeof(*dst));
    if (!dst) return NULL;
    dst->provctx = src->provctx;
    dst->key     = src->key;
    if (src->md_ctx) {
        dst->md_ctx = EVP_MD_CTX_new();
        if (!dst->md_ctx ||
            !EVP_MD_CTX_copy_ex(dst->md_ctx, src->md_ctx)) {
            EVP_MD_CTX_free(dst->md_ctx);
            OPENSSL_free(dst);
            return NULL;
        }
    }
    if (src->sw_pkey_ctx) {
        dst->sw_pkey_ctx = EVP_PKEY_CTX_dup(src->sw_pkey_ctx);
        if (!dst->sw_pkey_ctx) {
            EVP_MD_CTX_free(dst->md_ctx);
            EVP_PKEY_CTX_free(dst->sw_pkey_ctx);
            OPENSSL_free(dst);
            return NULL;
        }
    }
    return dst;
}

static int stse_sig_sign_init(void *vsigctx, void *vkey,
                               const OSSL_PARAM params[])
{
    (void)params;
    stse_sigctx_t *sctx = (stse_sigctx_t *)vsigctx;
    sctx->key = (stse_key_t *)vkey;
    if (!sctx->key) return 0;
    return 1;
}

static int stse_sig_sign(void *vsigctx,
                          unsigned char *sig, size_t *siglen, size_t sigsize,
                          const unsigned char *tbs, size_t tbslen)
{
    stse_sigctx_t *sctx = (stse_sigctx_t *)vsigctx;
    if (!sctx->key) return 0;
    return do_hw_sign(sctx->provctx, sctx->key,
                      tbs, tbslen, sig, siglen, sigsize);
}

static int stse_sig_verify_init(void *vsigctx, void *vkey,
                                 const OSSL_PARAM params[])
{
    (void)params;
    stse_sigctx_t *sctx = (stse_sigctx_t *)vsigctx;
    sctx->key = (stse_key_t *)vkey;
    if (!sctx->key) return 0;

    EVP_MD_CTX_free(sctx->md_ctx);
    sctx->md_ctx = NULL;

    EVP_PKEY *sw_pkey = stse_key_to_sw_pkey(sctx->key);
    if (!sw_pkey) return 0;

    EVP_PKEY_CTX_free(sctx->sw_pkey_ctx);
    sctx->sw_pkey_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, sw_pkey, "provider=default");
    EVP_PKEY_free(sw_pkey);

    if (!sctx->sw_pkey_ctx) return 0;

    if (EVP_PKEY_verify_init(sctx->sw_pkey_ctx) <= 0) {
        EVP_PKEY_CTX_free(sctx->sw_pkey_ctx);
        sctx->sw_pkey_ctx = NULL;
        return 0;
    }

    return 1;
}

static int stse_sig_verify(void *vsigctx,
                            const unsigned char *sig, size_t siglen,
                            const unsigned char *tbs, size_t tbslen)
{
    stse_sigctx_t *sctx = (stse_sigctx_t *)vsigctx;
    if (!sctx->sw_pkey_ctx) return 0;
    return EVP_PKEY_verify(sctx->sw_pkey_ctx, sig, siglen, tbs, tbslen);
}

static int stse_sig_digest_sign_init(void *vsigctx, const char *mdname,
                                      void *vkey, const OSSL_PARAM params[])
{
    (void)mdname; (void)params;
    stse_sigctx_t *sctx = (stse_sigctx_t *)vsigctx;
    sctx->key = (stse_key_t *)vkey;
    if (!sctx->key) return 0;
    return 1;
}

static int stse_sig_digest_sign(void *vsigctx,
                                 unsigned char *sig, size_t *siglen, size_t sigsize,
                                 const unsigned char *tbs, size_t tbslen)
{
    stse_sigctx_t *sctx = (stse_sigctx_t *)vsigctx;
    if (!sctx->key) return 0;
    return do_hw_sign(sctx->provctx, sctx->key,
                      tbs, tbslen, sig, siglen, sigsize);
}

static int stse_sig_digest_verify_init(void *vsigctx, const char *mdname,
                                        void *vkey, const OSSL_PARAM params[])
{
    stse_sigctx_t *sctx = (stse_sigctx_t *)vsigctx;
    sctx->key = (stse_key_t *)vkey;
    if (!sctx->key) return 0;

    EVP_PKEY_CTX_free(sctx->sw_pkey_ctx);
    sctx->sw_pkey_ctx = NULL;

    EVP_PKEY *sw_pkey = stse_key_to_sw_pkey(sctx->key);
    if (!sw_pkey) return 0;

    EVP_MD_CTX_free(sctx->md_ctx);
    sctx->md_ctx = EVP_MD_CTX_new();
    if (!sctx->md_ctx) {
        EVP_PKEY_free(sw_pkey);
        return 0;
    }

    if (EVP_DigestVerifyInit_ex(sctx->md_ctx, NULL, mdname, NULL, "provider=default", sw_pkey, params) <= 0) {
        EVP_MD_CTX_free(sctx->md_ctx);
        sctx->md_ctx = NULL;
        EVP_PKEY_free(sw_pkey);
        return 0;
    }

    EVP_PKEY_free(sw_pkey);
    return 1;
}

static int stse_sig_digest_verify(void *vsigctx,
                                  const unsigned char *sig, size_t siglen,
                                  const unsigned char *tbs, size_t tbslen)
{
    stse_sigctx_t *sctx = (stse_sigctx_t *)vsigctx;
    if (!sctx->key) return 0;

    EVP_PKEY *sw_pkey = stse_key_to_sw_pkey(sctx->key);
    if (!sw_pkey) return 0;

    EVP_MD_CTX *sw_ctx = EVP_MD_CTX_new();
    if (!sw_ctx) {
        EVP_PKEY_free(sw_pkey);
        return 0;
    }

    int ret = 0;
    if (EVP_DigestVerifyInit_ex(sw_ctx, NULL, NULL, NULL, "provider=default", sw_pkey, NULL) > 0) {
        ret = EVP_DigestVerify(sw_ctx, sig, siglen, tbs, tbslen);
    }

    EVP_MD_CTX_free(sw_ctx);
    EVP_PKEY_free(sw_pkey);
    return ret;
}

/* =========================================================================
 * Dispatch tables
 * ========================================================================= */

static const OSSL_DISPATCH stsafel_ed_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW,                  (void (*)(void))stsafel_ed_keymgmt_new },
    { OSSL_FUNC_KEYMGMT_FREE,                 (void (*)(void))stse_keymgmt_free },
    { OSSL_FUNC_KEYMGMT_HAS,                  (void (*)(void))stsafel_ed_keymgmt_has },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS,           (void (*)(void))stsafel_ed_keymgmt_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,      (void (*)(void))stse_keymgmt_gettable_params },
    { OSSL_FUNC_KEYMGMT_EXPORT,               (void (*)(void))stsafel_ed_keymgmt_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,         (void (*)(void))stsafel_ed_keymgmt_export_types },
    { OSSL_FUNC_KEYMGMT_IMPORT,               (void (*)(void))stsafel_ed_keymgmt_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,         (void (*)(void))stsafel_ed_keymgmt_import_types },
    { OSSL_FUNC_KEYMGMT_GEN_INIT,             (void (*)(void))stsafel_ed_keymgmt_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,       (void (*)(void))stse_keymgmt_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,   (void (*)(void))stse_keymgmt_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN,                  (void (*)(void))stse_keymgmt_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP,          (void (*)(void))stse_keymgmt_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (void (*)(void))stsafel_ed_keymgmt_query_operation_name },
    OSSL_DISPATCH_END
};

static const OSSL_DISPATCH stsafel_eddsa_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX,             (void (*)(void))stse_sig_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX,            (void (*)(void))stse_sig_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX,             (void (*)(void))stse_sig_dupctx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT,          (void (*)(void))stse_sig_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN,               (void (*)(void))stse_sig_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT,        (void (*)(void))stse_sig_verify_init },
    { OSSL_FUNC_SIGNATURE_VERIFY,             (void (*)(void))stse_sig_verify },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,   (void (*)(void))stse_sig_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN,        (void (*)(void))stse_sig_digest_sign },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void))stse_sig_digest_verify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY,      (void (*)(void))stse_sig_digest_verify },
    OSSL_DISPATCH_END
};

/* =========================================================================
 * Algorithm tables
 * ========================================================================= */

static const OSSL_ALGORITHM stsafel_keymgmt_algs[] = {
    {
        "ED25519:1.3.101.112",
        "provider=stsafel",
        stsafel_ed_keymgmt_functions,
        "STSAFE-L010 hardware-backed Ed25519 key management"
    },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM stsafel_signature_algs[] = {
    {
        "ED25519:1.3.101.112",
        "provider=stsafel",
        stsafel_eddsa_functions,
        "STSAFE-L010 hardware Ed25519 signature"
    },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *stsafel_query_operation(void *vprovctx,
                                                     int operation_id,
                                                     int *no_cache)
{
    (void)vprovctx;
    *no_cache = 0;
    switch (operation_id) {
    case OSSL_OP_KEYMGMT:   return stsafel_keymgmt_algs;
    case OSSL_OP_SIGNATURE: return stsafel_signature_algs;
    default:                return NULL;
    }
}

/* =========================================================================
 * Provider info and teardown
 * ========================================================================= */

static const OSSL_PARAM stse_prov_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME,    OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS,  OSSL_PARAM_INTEGER,  NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *stse_prov_gettable_params(void *vprovctx)
{
    (void)vprovctx;
    return stse_prov_param_types;
}

static int stse_prov_get_params(void *vprovctx, OSSL_PARAM params[])
{
    (void)vprovctx;
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p && !OSSL_PARAM_set_utf8_ptr(p, "stsafel")) return 0;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p && !OSSL_PARAM_set_utf8_ptr(p, "1.0.0")) return 0;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p) {
        int status = 1;
        if (!OSSL_PARAM_set_int(p, status)) return 0;
    }
    return 1;
}

static void stse_prov_teardown(void *vprovctx)
{
    OPENSSL_free(vprovctx);
}

static const OSSL_DISPATCH stse_prov_functions[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN,             (void (*)(void))stse_prov_teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,      (void (*)(void))stse_prov_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS,           (void (*)(void))stse_prov_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION,      (void (*)(void))stsafel_query_operation },
    OSSL_DISPATCH_END
};

/* =========================================================================
 * Entry point — single exported symbol
 * ========================================================================= */
int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                        const OSSL_DISPATCH    *in,
                        const OSSL_DISPATCH   **out,
                        void                  **provctx)
{
    (void)in;
    stse_provctx_t *pctx = OPENSSL_zalloc(sizeof(*pctx));
    if (!pctx) return 0;

    pctx->handle        = handle;
    pctx->initialized   = 0;
    pctx->active_bus_id = 255;

    *provctx = pctx;
    *out     = stse_prov_functions;
    return 1;
}
