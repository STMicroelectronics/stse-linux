/**
 * *****************************************************************************
 * @file    stsafea_provider.c
 * @brief   STSAFE-A120 OpenSSL 3.x Provider
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
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

#include "stselib.h"
#include "stse_provider.h"

/* =========================================================================
 * NOTE: stsafea.so links directly against libstse.so — no dlopen/dlsym.
 * =========================================================================

/* =========================================================================
 * Curve mapping and parameters
 * ========================================================================= */
typedef struct {
    const char *name;
    stse_ecc_key_type_t type;
    int bits;
    size_t coord_len;
} curve_map_t;

static const curve_map_t ec_curves[] = {
    { "prime256v1", STSE_ECC_KT_NIST_P_256, 256, 32 },
    { "P-256", STSE_ECC_KT_NIST_P_256, 256, 32 },
    { "secp384r1", STSE_ECC_KT_NIST_P_384, 384, 48 },
    { "P-384", STSE_ECC_KT_NIST_P_384, 384, 48 },
    { "nistp521", STSE_ECC_KT_NIST_P_521, 521, 66 },
    { "P-521", STSE_ECC_KT_NIST_P_521, 521, 66 },
    { "brainpoolP256r1", STSE_ECC_KT_BP_P_256, 256, 32 },
    { "brainpoolP384r1", STSE_ECC_KT_BP_P_384, 384, 48 },
    { "brainpoolP512r1", STSE_ECC_KT_BP_P_512, 512, 64 },
    { NULL, STSE_ECC_KT_INVALID, 0, 0 }
};

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
typedef enum {
    STSE_KEY_TYPE_EC,
    STSE_KEY_TYPE_X25519
} stse_key_type_t;

typedef struct stse_key_st {
    stse_provctx_t *provctx;
    stse_key_type_t key_type;
    stse_ecc_key_type_t curve_type;
    uint8_t         slot;
    uint8_t         bus_id;
    uint8_t         dev_addr;
    uint8_t         pub_point[133]; /* 0x04 || X || Y for EC, or raw 32 bytes for X25519 */
    size_t          pub_len;
    int             has_pub;
} stse_key_t;

/* =========================================================================
 * Key generation context — per EVP_PKEY_CTX (keygen)
 * ========================================================================= */
typedef struct stse_genctx_st {
    stse_provctx_t     *provctx;
    stse_key_type_t     key_type;
    stse_ecc_key_type_t curve_type;
    uint8_t             slot;
    uint8_t             bus_id;
    uint8_t             dev_addr;
} stse_genctx_t;

/* =========================================================================
 * Signature context — per EVP_MD_CTX sign/verify operation
 * ========================================================================= */
typedef struct stse_sigctx_st {
    stse_provctx_t *provctx;
    stse_key_t     *key;    /* borrowed from EVP_PKEY */
    EVP_MD_CTX     *md_ctx; /* for digest streaming API */
} stse_sigctx_t;

/* =========================================================================
 * Forward declarations
 * ========================================================================= */
static int stse_keymgmt_gen_set_params(void *vgenctx, const OSSL_PARAM params[]);
static void *stse_keymgmt_new(void *vprovctx);
static void  stse_keymgmt_free(void *vkey);

/* =========================================================================
 * libstse.so loading + STSAFE-A initialisation
 * ========================================================================= */

static int provctx_ensure_init(stse_provctx_t *pctx, uint8_t bus_id,
                                uint8_t dev_addr, stse_device_t dev_type)
{
    if (pctx->initialized && pctx->active_bus_id == bus_id &&
        pctx->active_dev_addr == dev_addr && pctx->handler.device_type == dev_type)
        return 1;

    stse_ReturnCode_t rc = stse_set_default_handler_value(&pctx->handler);
    if (rc != STSE_OK) {
        fprintf(stderr, "[stsafea_provider] set_default_handler_value: %d\n", rc);
        return 0;
    }

    pctx->handler.device_type = dev_type;
    pctx->handler.io.busID    = bus_id;
    pctx->handler.io.BusSpeed = 400;
    pctx->handler.io.Devaddr  = dev_addr;

    rc = stse_init(&pctx->handler);
    if (rc != STSE_OK) {
        fprintf(stderr, "[stsafea_provider] stse_init (device %d, bus %u, devaddr 0x%02X): %d\n",
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

static void *stsafea_ec_keymgmt_new(void *vprovctx)
{
    stse_key_t *key = stse_keymgmt_new(vprovctx);
    if (key) {
        key->key_type   = STSE_KEY_TYPE_EC;
        key->curve_type = STSE_ECC_KT_NIST_P_256; /* default */
        key->pub_len    = 65; /* 0x04 || X || Y (NIST P-256 default) */
        key->dev_addr   = 0x20; /* default STSAFE-A120 I²C address */
    }
    return key;
}

static void *stsafea_x25519_keymgmt_new(void *vprovctx)
{
    stse_key_t *key = stse_keymgmt_new(vprovctx);
    if (key) {
        key->key_type   = STSE_KEY_TYPE_X25519;
        key->curve_type = STSE_ECC_KT_CURVE25519;
        key->pub_len    = 32;
        key->dev_addr   = 0x20; /* default STSAFE-A120 I²C address */
    }
    return key;
}

static void stse_keymgmt_free(void *vkey)
{
    OPENSSL_free(vkey);
}

static int stsafea_ec_keymgmt_has(const void *vkey, int selection)
{
    const stse_key_t *key = (const stse_key_t *)vkey;
    if (!key) return 0;

    int ok = 1;
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
        ok = ok && 1;  /* present on-chip */
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
        ok = ok && key->has_pub;
    if (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS)
        ok = ok && 1;

    return ok;
}

static int stsafea_x25519_keymgmt_has(const void *vkey, int selection)
{
    const stse_key_t *key = (const stse_key_t *)vkey;
    if (!key) return 0;

    int ok = 1;
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
        ok = ok && 1;
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
        ok = ok && key->has_pub;

    return ok;
}

static int stsafea_ec_keymgmt_export(void *vkey, int selection,
                                     OSSL_CALLBACK *cb, void *cbarg)
{
    stse_key_t *key = (stse_key_t *)vkey;
    if (!key) return 0;

    if (!(selection & (OSSL_KEYMGMT_SELECT_PUBLIC_KEY |
                       OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS)))
        return 1;
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) && !key->has_pub)
        return 0;

    const char *grp_name = "prime256v1";
    for (int i = 0; ec_curves[i].name != NULL; i++) {
        if (ec_curves[i].type == key->curve_type) {
            grp_name = ec_curves[i].name;
            break;
        }
    }

    OSSL_PARAM params[3];
    int np = 0;

    if (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) {
        params[np++] = OSSL_PARAM_construct_utf8_string(
            OSSL_PKEY_PARAM_GROUP_NAME, (char *)grp_name, 0);
    }
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        params[np++] = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PUB_KEY, key->pub_point, key->pub_len);
    }
    params[np] = OSSL_PARAM_construct_end();
    return cb(params, cbarg);
}

static int stsafea_x25519_keymgmt_export(void *vkey, int selection,
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

static const OSSL_PARAM stsafea_ec_keymgmt_export_types_tab[] = {
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY,   NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *stsafea_ec_keymgmt_export_types(int selection)
{
    if (selection & (OSSL_KEYMGMT_SELECT_PUBLIC_KEY |
                     OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS))
        return stsafea_ec_keymgmt_export_types_tab;
    return NULL;
}

static const OSSL_PARAM stsafea_x25519_keymgmt_export_types_tab[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY,   NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *stsafea_x25519_keymgmt_export_types(int selection)
{
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
        return stsafea_x25519_keymgmt_export_types_tab;
    return NULL;
}

static int stsafea_ec_keymgmt_import(void *vkey, int selection,
                                     const OSSL_PARAM params[])
{
    stse_key_t *key = (stse_key_t *)vkey;
    if (!key) return 0;

    if (!(selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY))
        return 1;

    const OSSL_PARAM *p_grp = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME);
    if (p_grp) {
        char name[64];
        char *pname = name;
        if (!OSSL_PARAM_get_utf8_string(p_grp, &pname, sizeof(name)))
            return 0;
        int found = 0;
        for (int i = 0; ec_curves[i].name != NULL; i++) {
            if (strcasecmp(name, ec_curves[i].name) == 0) {
                key->curve_type = ec_curves[i].type;
                found = 1;
                break;
            }
        }
        if (!found) return 0;
    } else {
        key->curve_type = STSE_ECC_KT_NIST_P_256;
    }

    const OSSL_PARAM *p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (!p) return 0;

    const void *pub_data = NULL;
    size_t      pub_len  = 0;
    if (!OSSL_PARAM_get_octet_string_ptr(p, &pub_data, &pub_len))
        return 0;

    size_t field_len = 32;
    for (int i = 0; ec_curves[i].name != NULL; i++) {
        if (ec_curves[i].type == key->curve_type) {
            field_len = ec_curves[i].coord_len;
            break;
        }
    }

    if (pub_len != 1 + 2 * field_len) return 0;

    memcpy(key->pub_point, pub_data, pub_len);
    key->pub_len = pub_len;
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

    const OSSL_PARAM *p_da_ec = OSSL_PARAM_locate_const(params, STSE_PROV_PARAM_DEVADDR);
    if (p_da_ec) {
        uint32_t val;
        if (OSSL_PARAM_get_uint32(p_da_ec, &val))
            key->dev_addr = (uint8_t)val;
    }

    return 1;
}

static int stsafea_x25519_keymgmt_import(void *vkey, int selection,
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

    const OSSL_PARAM *p_da_x25 = OSSL_PARAM_locate_const(params, STSE_PROV_PARAM_DEVADDR);
    if (p_da_x25) {
        uint32_t val;
        if (OSSL_PARAM_get_uint32(p_da_x25, &val))
            key->dev_addr = (uint8_t)val;
    }

    return 1;
}

static const OSSL_PARAM *stsafea_ec_keymgmt_import_types(int selection)
{
    return stsafea_ec_keymgmt_export_types(selection);
}

static const OSSL_PARAM *stsafea_x25519_keymgmt_import_types(int selection)
{
    return stsafea_x25519_keymgmt_export_types(selection);
}

static const OSSL_PARAM stse_keymgmt_gettable_params_tab[] = {
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY,   NULL, 0),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS,               NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *stse_keymgmt_gettable_params(void *vprovctx)
{
    (void)vprovctx;
    return stse_keymgmt_gettable_params_tab;
}

static int stsafea_ec_keymgmt_get_params(void *vkey, OSSL_PARAM params[])
{
    stse_key_t *key = (stse_key_t *)vkey;
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_GROUP_NAME);
    if (p) {
        const char *grp_name = "prime256v1";
        for (int i = 0; ec_curves[i].name != NULL; i++) {
            if (ec_curves[i].type == key->curve_type) {
                grp_name = ec_curves[i].name;
                break;
            }
        }
        if (!OSSL_PARAM_set_utf8_string(p, grp_name))
            return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (p) {
        if (!key->has_pub) return 0;
        if (!OSSL_PARAM_set_octet_string(p, key->pub_point, key->pub_len))
            return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if (p) {
        int bits = 256;
        for (int i = 0; ec_curves[i].name != NULL; i++) {
            if (ec_curves[i].type == key->curve_type) {
                bits = ec_curves[i].bits;
                break;
            }
        }
        if (!OSSL_PARAM_set_int(p, bits)) return 0;
    }
    return 1;
}

static int stsafea_x25519_keymgmt_get_params(void *vkey, OSSL_PARAM params[])
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

static void *stse_keymgmt_gen_init(void *vprovctx, int selection,
                                    const OSSL_PARAM params[])
{
    if (!(selection & OSSL_KEYMGMT_SELECT_KEYPAIR)) return NULL;

    stse_genctx_t *gctx = OPENSSL_zalloc(sizeof(*gctx));
    if (!gctx) return NULL;

    gctx->provctx = (stse_provctx_t *)vprovctx;
    gctx->slot    = 0;
    gctx->bus_id  = 1;

    if (params)
        stse_keymgmt_gen_set_params(gctx, params);

    return gctx;
}

static void *stsafea_ec_keymgmt_gen_init(void *vprovctx, int selection,
                                         const OSSL_PARAM params[])
{
    stse_genctx_t *gctx = stse_keymgmt_gen_init(vprovctx, selection, params);
    if (gctx) {
        gctx->key_type   = STSE_KEY_TYPE_EC;
        gctx->curve_type = STSE_ECC_KT_NIST_P_256; /* default */
        gctx->dev_addr   = 0x20; /* default STSAFE-A120 I²C address */
    }
    return gctx;
}

static void *stsafea_x25519_keymgmt_gen_init(void *vprovctx, int selection,
                                             const OSSL_PARAM params[])
{
    stse_genctx_t *gctx = stse_keymgmt_gen_init(vprovctx, selection, params);
    if (gctx) {
        gctx->key_type   = STSE_KEY_TYPE_X25519;
        gctx->curve_type = STSE_ECC_KT_CURVE25519;
        gctx->dev_addr   = 0x20; /* default STSAFE-A120 I²C address */
    }
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

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME);
    if (p && gctx->key_type == STSE_KEY_TYPE_EC) {
        char name[64];
        char *pname = name;
        if (!OSSL_PARAM_get_utf8_string(p, &pname, sizeof(name)))
            return 0;
        int found = 0;
        for (int i = 0; ec_curves[i].name != NULL; i++) {
            if (strcasecmp(name, ec_curves[i].name) == 0) {
                gctx->curve_type = ec_curves[i].type;
                found = 1;
                break;
            }
        }
        if (!found) return 0;
    }

    return 1;
}

static const OSSL_PARAM stse_keymgmt_gen_settable_params_tab[] = {
    OSSL_PARAM_uint32(STSE_PROV_PARAM_SLOT,    NULL),
    OSSL_PARAM_uint32(STSE_PROV_PARAM_BUS,     NULL),
    OSSL_PARAM_uint32(STSE_PROV_PARAM_DEVADDR, NULL),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
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

    if (!provctx_ensure_init(pctx, gctx->bus_id, gctx->dev_addr, STSAFE_A120)) return NULL;

    if (gctx->key_type == STSE_KEY_TYPE_X25519) {
        stse_key_t *key = (stse_key_t *)stsafea_x25519_keymgmt_new(pctx);
        if (!key) return NULL;
        key->slot     = gctx->slot;
        key->bus_id   = gctx->bus_id;
        key->dev_addr = gctx->dev_addr;

        uint8_t raw_pub[32];
        stse_ReturnCode_t rc = stse_generate_ecc_key_pair(&pctx->handler,
                                                           gctx->slot,
                                                           STSE_ECC_KT_CURVE25519,
                                                           255, raw_pub);
        if (rc != STSE_OK) {
            fprintf(stderr, "[stsafea_provider] X25519 keygen slot=%u bus=%u: err %d\n",
                    gctx->slot, gctx->bus_id, rc);
            stse_keymgmt_free(key);
            return NULL;
        }

        memcpy(key->pub_point, raw_pub, 32);
        key->pub_len = 32;
        key->has_pub = 1;
        return key;
    } else {
        stse_key_t *key = (stse_key_t *)stsafea_ec_keymgmt_new(pctx);
        if (!key) return NULL;
        key->slot       = gctx->slot;
        key->bus_id     = gctx->bus_id;
        key->dev_addr   = gctx->dev_addr;
        key->curve_type = gctx->curve_type;

        size_t field_len = 32;
        for (int i = 0; ec_curves[i].name != NULL; i++) {
            if (ec_curves[i].type == gctx->curve_type) {
                field_len = ec_curves[i].coord_len;
                break;
            }
        }

        uint8_t *raw_pub = OPENSSL_malloc(field_len * 2);
        if (!raw_pub) {
            stse_keymgmt_free(key);
            return NULL;
        }

        stse_ReturnCode_t rc = stse_generate_ecc_key_pair(&pctx->handler,
                                                           gctx->slot,
                                                           gctx->curve_type,
                                                           255, raw_pub);
        if (rc != STSE_OK) {
            fprintf(stderr, "[stsafea_provider] EC keygen curve=%u slot=%u bus=%u: err %d\n",
                    gctx->curve_type, gctx->slot, gctx->bus_id, rc);
            OPENSSL_free(raw_pub);
            stse_keymgmt_free(key);
            return NULL;
        }

        key->pub_point[0] = 0x04; /* uncompressed prefix */
        memcpy(key->pub_point + 1, raw_pub, field_len * 2);
        key->pub_len = 1 + field_len * 2;
        key->has_pub = 1;
        OPENSSL_free(raw_pub);
        return key;
    }
}

static void stse_keymgmt_gen_cleanup(void *vgenctx)
{
    OPENSSL_free(vgenctx);
}

static const char *stsafea_ec_keymgmt_query_operation_name(int operation_id)
{
    if (operation_id == OSSL_OP_SIGNATURE)
        return "ECDSA";
    return NULL;
}

static const char *stsafea_x25519_keymgmt_query_operation_name(int operation_id)
{
    (void)operation_id;
    return NULL;
}

/* =========================================================================
 * SIGNATURE — signing helper (raw digest → DER)
 * ========================================================================= */

static int do_hw_sign(stse_provctx_t *pctx, stse_key_t *key,
                      const unsigned char *digest, size_t digest_len,
                      unsigned char *sig, size_t *siglen, size_t sigsize)
{
    if (key->key_type != STSE_KEY_TYPE_EC) return 0;

    size_t field_len = 32;
    for (int i = 0; ec_curves[i].name != NULL; i++) {
        if (ec_curves[i].type == key->curve_type) {
            field_len = ec_curves[i].coord_len;
            break;
        }
    }

    size_t max_der_len = field_len * 2 + 16; /* safe bound for ECDSA DER */

    if (!sig) {
        *siglen = max_der_len;
        return 1;
    }

    if (!provctx_ensure_init(pctx, key->bus_id, key->dev_addr, STSAFE_A120)) return 0;

    uint8_t *raw_sig = OPENSSL_malloc(field_len * 2);
    if (!raw_sig) return 0;

    stse_ReturnCode_t rc = stse_ecc_generate_signature(&pctx->handler,
                                                        key->slot,
                                                        key->curve_type,
                                                        digest, (PLAT_UI16)digest_len,
                                                        raw_sig);
    if (rc != STSE_OK) {
        fprintf(stderr, "[stsafea_provider] sign curve=%u slot=%u: err %d\n",
                key->curve_type, key->slot, rc);
        OPENSSL_free(raw_sig);
        return 0;
    }

    BIGNUM *r = BN_bin2bn(raw_sig,             field_len, NULL);
    BIGNUM *s = BN_bin2bn(raw_sig + field_len, field_len, NULL);
    OPENSSL_free(raw_sig);

    if (!r || !s) { BN_free(r); BN_free(s); return 0; }

    ECDSA_SIG *ecdsa = ECDSA_SIG_new();
    if (!ecdsa) { BN_free(r); BN_free(s); return 0; }
    ECDSA_SIG_set0(ecdsa, r, s); /* ownership transferred */

    unsigned char *der     = NULL;
    int            der_len = i2d_ECDSA_SIG(ecdsa, &der);
    ECDSA_SIG_free(ecdsa);

    if (der_len <= 0) return 0;
    if ((size_t)der_len > sigsize) { OPENSSL_free(der); return 0; }

    memcpy(sig, der, (size_t)der_len);
    *siglen = (size_t)der_len;
    OPENSSL_free(der);
    return 1;
}

/* =========================================================================
 * SIGNATURE — verification helper (DER → raw R||S → HW verify)
 * ========================================================================= */

static int do_hw_verify(stse_provctx_t *pctx, stse_key_t *key,
                        const unsigned char *sig, size_t siglen,
                        const unsigned char *digest, size_t digest_len)
{
    if (key->key_type != STSE_KEY_TYPE_EC) return 0;

    if (!provctx_ensure_init(pctx, key->bus_id, key->dev_addr, STSAFE_A120)) return 0;

    size_t field_len = 32;
    for (int i = 0; ec_curves[i].name != NULL; i++) {
        if (ec_curves[i].type == key->curve_type) {
            field_len = ec_curves[i].coord_len;
            break;
        }
    }

    const unsigned char *p = sig;
    ECDSA_SIG *ecdsa = d2i_ECDSA_SIG(NULL, &p, (long)siglen);
    if (!ecdsa) return 0;

    const BIGNUM *r = NULL;
    const BIGNUM *s = NULL;
    ECDSA_SIG_get0(ecdsa, &r, &s);
    if (!r || !s) {
        ECDSA_SIG_free(ecdsa);
        return 0;
    }

    size_t raw_sig_len = field_len * 2;
    uint8_t *raw_sig = OPENSSL_malloc(raw_sig_len);
    if (!raw_sig) {
        ECDSA_SIG_free(ecdsa);
        return 0;
    }
    memset(raw_sig, 0, raw_sig_len);

    if (BN_bn2binpad(r, raw_sig, field_len) <= 0 ||
        BN_bn2binpad(s, raw_sig + field_len, field_len) <= 0) {
        OPENSSL_free(raw_sig);
        ECDSA_SIG_free(ecdsa);
        return 0;
    }
    ECDSA_SIG_free(ecdsa);

    /* Pass public key coordinates (excluding the 0x04 uncompressed prefix) */
    const uint8_t *pub_key_to_verify = key->pub_point + 1;

    uint8_t signature_validity = 0;
    stse_ReturnCode_t rc = stse_ecc_verify_signature(&pctx->handler,
                                                      key->curve_type,
                                                      pub_key_to_verify,
                                                      raw_sig,
                                                      digest, (PLAT_UI16)digest_len,
                                                      0, /* eddsa_variant 0 */
                                                      &signature_validity);
    OPENSSL_free(raw_sig);

    if (rc != STSE_OK) {
        fprintf(stderr, "[stsafea_provider] verify curve=%u slot=%u: err %d\n",
                key->curve_type, key->slot, rc);
        return 0;
    }

    return (signature_validity == 1) ? 1 : 0;
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
    return dst;
}

static int stse_sig_sign_init(void *vsigctx, void *vkey,
                               const OSSL_PARAM params[])
{
    (void)params;
    stse_sigctx_t *sctx = (stse_sigctx_t *)vsigctx;
    sctx->key = (stse_key_t *)vkey;
    if (!sctx->key) return 0;
    EVP_MD_CTX_free(sctx->md_ctx);
    sctx->md_ctx = NULL;
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
    return 1;
}

static int stse_sig_verify(void *vsigctx,
                            const unsigned char *sig, size_t siglen,
                            const unsigned char *tbs, size_t tbslen)
{
    stse_sigctx_t *sctx = (stse_sigctx_t *)vsigctx;
    if (!sctx->key) return 0;
    return do_hw_verify(sctx->provctx, sctx->key,
                        sig, siglen, tbs, tbslen);
}

static int stse_sig_digest_sign_init(void *vsigctx, const char *mdname,
                                      void *vkey, const OSSL_PARAM params[])
{
    (void)params;
    stse_sigctx_t *sctx = (stse_sigctx_t *)vsigctx;
    sctx->key = (stse_key_t *)vkey;
    if (!sctx->key) return 0;

    const char *digest_name = (mdname && *mdname) ? mdname : "SHA2-256";
    const EVP_MD *md = EVP_get_digestbyname(digest_name);
    if (!md) {
        fprintf(stderr, "[stsafea_provider] unknown digest: %s\n", digest_name);
        return 0;
    }

    EVP_MD_CTX_free(sctx->md_ctx);
    sctx->md_ctx = EVP_MD_CTX_new();
    if (!sctx->md_ctx) return 0;
    if (!EVP_DigestInit_ex(sctx->md_ctx, md, NULL)) {
        EVP_MD_CTX_free(sctx->md_ctx);
        sctx->md_ctx = NULL;
        return 0;
    }
    return 1;
}

static int stse_sig_digest_sign_update(void *vsigctx,
                                        const unsigned char *data,
                                        size_t datalen)
{
    stse_sigctx_t *sctx = (stse_sigctx_t *)vsigctx;
    if (!sctx->md_ctx) return 0;
    return EVP_DigestUpdate(sctx->md_ctx, data, datalen) ? 1 : 0;
}

static int stse_sig_digest_sign_final(void *vsigctx,
                                       unsigned char *sig, size_t *siglen,
                                       size_t sigsize)
{
    stse_sigctx_t *sctx = (stse_sigctx_t *)vsigctx;
    if (!sctx->md_ctx || !sctx->key) return 0;

    size_t field_len = 32;
    for (int i = 0; ec_curves[i].name != NULL; i++) {
        if (ec_curves[i].type == sctx->key->curve_type) {
            field_len = ec_curves[i].coord_len;
            break;
        }
    }
    size_t max_der_len = field_len * 2 + 16;

    if (!sig) {
        *siglen = max_der_len;
        return 1;
    }

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int  dlen = 0;
    if (!EVP_DigestFinal_ex(sctx->md_ctx, digest, &dlen)) return 0;

    return do_hw_sign(sctx->provctx, sctx->key,
                      digest, dlen, sig, siglen, sigsize);
}

static int stse_sig_digest_verify_init(void *vsigctx, const char *mdname,
                                        void *vkey, const OSSL_PARAM params[])
{
    (void)params;
    stse_sigctx_t *sctx = (stse_sigctx_t *)vsigctx;
    sctx->key = (stse_key_t *)vkey;
    if (!sctx->key) return 0;

    const char *digest_name = (mdname && *mdname) ? mdname : "SHA2-256";
    const EVP_MD *md = EVP_get_digestbyname(digest_name);
    if (!md) {
        fprintf(stderr, "[stsafea_provider] unknown digest: %s\n", digest_name);
        return 0;
    }

    EVP_MD_CTX_free(sctx->md_ctx);
    sctx->md_ctx = EVP_MD_CTX_new();
    if (!sctx->md_ctx) return 0;
    if (!EVP_DigestInit_ex(sctx->md_ctx, md, NULL)) {
        EVP_MD_CTX_free(sctx->md_ctx);
        sctx->md_ctx = NULL;
        return 0;
    }
    return 1;
}

static int stse_sig_digest_verify_update(void *vsigctx,
                                          const unsigned char *data,
                                          size_t datalen)
{
    stse_sigctx_t *sctx = (stse_sigctx_t *)vsigctx;
    if (!sctx->md_ctx) return 0;
    return EVP_DigestUpdate(sctx->md_ctx, data, datalen) ? 1 : 0;
}

static int stse_sig_digest_verify_final(void *vsigctx,
                                         const unsigned char *sig,
                                         size_t siglen)
{
    stse_sigctx_t *sctx = (stse_sigctx_t *)vsigctx;
    if (!sctx->md_ctx || !sctx->key) return 0;

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int  dlen = 0;
    if (!EVP_DigestFinal_ex(sctx->md_ctx, digest, &dlen)) return 0;

    return do_hw_verify(sctx->provctx, sctx->key,
                        sig, siglen, digest, dlen);
}

static const OSSL_PARAM stse_sig_gettable_ctx_params_tab[] = {
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *stse_sig_gettable_ctx_params(void *vsigctx,
                                                        void *vprovctx)
{
    (void)vsigctx; (void)vprovctx;
    return stse_sig_gettable_ctx_params_tab;
}

static int stse_sig_get_ctx_params(void *vsigctx, OSSL_PARAM params[])
{
    (void)vsigctx;
    OSSL_PARAM *p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p && !OSSL_PARAM_set_utf8_string(p, "SHA2-256"))
        return 0;
    return 1;
}

static const OSSL_PARAM stse_sig_settable_ctx_params_tab[] = {
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *stse_sig_settable_ctx_params(void *vsigctx,
                                                        void *vprovctx)
{
    (void)vsigctx; (void)vprovctx;
    return stse_sig_settable_ctx_params_tab;
}

static int stse_sig_set_ctx_params(void *vsigctx, const OSSL_PARAM params[])
{
    (void)vsigctx; (void)params;
    return 1;
}

/* =========================================================================
 * Dispatch tables
 * ========================================================================= */

static const OSSL_DISPATCH stsafea_ec_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW,                  (void (*)(void))stsafea_ec_keymgmt_new },
    { OSSL_FUNC_KEYMGMT_FREE,                 (void (*)(void))stse_keymgmt_free },
    { OSSL_FUNC_KEYMGMT_HAS,                  (void (*)(void))stsafea_ec_keymgmt_has },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS,           (void (*)(void))stsafea_ec_keymgmt_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,      (void (*)(void))stse_keymgmt_gettable_params },
    { OSSL_FUNC_KEYMGMT_EXPORT,               (void (*)(void))stsafea_ec_keymgmt_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,         (void (*)(void))stsafea_ec_keymgmt_export_types },
    { OSSL_FUNC_KEYMGMT_IMPORT,               (void (*)(void))stsafea_ec_keymgmt_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,         (void (*)(void))stsafea_ec_keymgmt_import_types },
    { OSSL_FUNC_KEYMGMT_GEN_INIT,             (void (*)(void))stsafea_ec_keymgmt_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,       (void (*)(void))stse_keymgmt_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,   (void (*)(void))stse_keymgmt_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN,                  (void (*)(void))stse_keymgmt_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP,          (void (*)(void))stse_keymgmt_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (void (*)(void))stsafea_ec_keymgmt_query_operation_name },
    OSSL_DISPATCH_END
};

static const OSSL_DISPATCH stsafea_x25519_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW,                  (void (*)(void))stsafea_x25519_keymgmt_new },
    { OSSL_FUNC_KEYMGMT_FREE,                 (void (*)(void))stse_keymgmt_free },
    { OSSL_FUNC_KEYMGMT_HAS,                  (void (*)(void))stsafea_x25519_keymgmt_has },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS,           (void (*)(void))stsafea_x25519_keymgmt_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,      (void (*)(void))stse_keymgmt_gettable_params },
    { OSSL_FUNC_KEYMGMT_EXPORT,               (void (*)(void))stsafea_x25519_keymgmt_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,         (void (*)(void))stsafea_x25519_keymgmt_export_types },
    { OSSL_FUNC_KEYMGMT_IMPORT,               (void (*)(void))stsafea_x25519_keymgmt_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,         (void (*)(void))stsafea_x25519_keymgmt_import_types },
    { OSSL_FUNC_KEYMGMT_GEN_INIT,             (void (*)(void))stsafea_x25519_keymgmt_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,       (void (*)(void))stse_keymgmt_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,   (void (*)(void))stse_keymgmt_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN,                  (void (*)(void))stse_keymgmt_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP,          (void (*)(void))stse_keymgmt_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (void (*)(void))stsafea_x25519_keymgmt_query_operation_name },
    OSSL_DISPATCH_END
};

static const OSSL_DISPATCH stsafea_ecdsa_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX,             (void (*)(void))stse_sig_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX,            (void (*)(void))stse_sig_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX,             (void (*)(void))stse_sig_dupctx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT,          (void (*)(void))stse_sig_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN,               (void (*)(void))stse_sig_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT,        (void (*)(void))stse_sig_verify_init },
    { OSSL_FUNC_SIGNATURE_VERIFY,             (void (*)(void))stse_sig_verify },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,   (void (*)(void))stse_sig_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (void (*)(void))stse_sig_digest_sign_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,  (void (*)(void))stse_sig_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,   (void (*)(void))stse_sig_digest_verify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE, (void (*)(void))stse_sig_digest_verify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,  (void (*)(void))stse_sig_digest_verify_final },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,     (void (*)(void))stse_sig_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))stse_sig_gettable_ctx_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,     (void (*)(void))stse_sig_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void (*)(void))stse_sig_settable_ctx_params },
    OSSL_DISPATCH_END
};

/* =========================================================================
 * Algorithm tables
 * ========================================================================= */

static const OSSL_ALGORITHM stsafea_keymgmt_algs[] = {
    {
        "EC:id-ecPublicKey:1.2.840.10045.2.1",
        "provider=stsafea",
        stsafea_ec_keymgmt_functions,
        "STSAFE-A120 NIST & Brainpool hardware-backed EC key management"
    },
    {
        "X25519:1.3.101.110",
        "provider=stsafea",
        stsafea_x25519_keymgmt_functions,
        "STSAFE-A120 hardware-backed X25519 key management"
    },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM stsafea_signature_algs[] = {
    {
        "ECDSA:1.2.840.10045.4.3.2",
        "provider=stsafea",
        stsafea_ecdsa_functions,
        "STSAFE-A120 hardware ECDSA signature"
    },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *stsafea_query_operation(void *vprovctx,
                                                     int operation_id,
                                                     int *no_cache)
{
    (void)vprovctx;
    *no_cache = 0;
    switch (operation_id) {
    case OSSL_OP_KEYMGMT:   return stsafea_keymgmt_algs;
    case OSSL_OP_SIGNATURE: return stsafea_signature_algs;
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
    if (p && !OSSL_PARAM_set_utf8_ptr(p, "stsafea")) return 0;

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
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION,      (void (*)(void))stsafea_query_operation },
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
