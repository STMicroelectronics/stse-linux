/*!
 ******************************************************************************
 * \file    stse_ipc.h
 * \brief   Platform-level IPC protocol between libstse.so and se-daemon.
 *
 * Purpose
 * ────────
 * The STSELib API (stse_init, stse_ecc_generate_signature, C_Sign, …) is
 * compiled directly into libstse.so and called by applications without any
 * modification.
 *
 * The only layer that changes is STSELib_Platform: instead of calling Linux
 * I2C ioctls directly (which requires /dev/i2c-* access), the platform I2C
 * functions send IPC requests to the privileged se-daemon, which owns the
 * bus and serialises concurrent access.
 *
 * Wire format
 * ────────────
 *   Request:  [ se_plat_hdr_t ]  [ payload bytes ]
 *   Response: [ se_plat_hdr_t ]  [ se_plat_status_t ] [ optional data bytes ]
 *
 * All integers are host byte-order (little-endian on ARM/x86).
 * Packed structs guarantee zero-padding on the wire.
 *
 * Mutex protocol
 * ───────────────
 *   SE_PLAT_I2C_WRITE  — daemon acquires the global I2C bus mutex then writes.
 *   SE_PLAT_I2C_READ   — daemon reads (bus mutex is still held by this client).
 *   SE_PLAT_I2C_UNLOCK — daemon releases the bus mutex.
 *
 * The client sends WRITE, then one or more READs, then UNLOCK — matching
 * exactly the STSELib call sequence:
 *   i2c_send_stop → i2c_receive_start → i2c_receive_continue → i2c_receive_stop
 *
 * If the client disconnects while holding the mutex the daemon releases it
 * automatically in the thread cleanup handler.
 *
 * ******************************************************************************
 * \attention
 * COPYRIGHT 2024 STMicroelectronics
 * Licensed under the terms found in the LICENSE file in the root directory.
 * ******************************************************************************
 */

#ifndef STSE_IPC_H
#define STSE_IPC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/* ---------------------------------------------------------------------------
 * Socket path and protocol constants
 * --------------------------------------------------------------------------*/

/** Unix Domain Socket where se-daemon listens */
#define SE_DAEMON_SOCKET_PATH   "/var/run/se-daemon.sock"

/** Magic bytes in every message header */
#define SE_PLAT_MAGIC           0x504C4154U  /* "PLAT" */

/** Protocol version */
#define SE_PLAT_VERSION         0x01U

/** Maximum I2C frame size (STSAFE-A120 max) */
#define SE_PLAT_MAX_FRAME       755U

/* ---------------------------------------------------------------------------
 * Message header — 12 bytes, always present
 * --------------------------------------------------------------------------*/
typedef struct __attribute__((packed)) se_plat_hdr {
    uint32_t magic;        /*!< Must equal SE_PLAT_MAGIC     */
    uint8_t  version;      /*!< Must equal SE_PLAT_VERSION   */
    uint8_t  cmd;          /*!< se_plat_cmd_t                */
    uint16_t _pad;
    uint32_t payload_len;  /*!< Bytes immediately following  */
} se_plat_hdr_t;

/* ---------------------------------------------------------------------------
 * Command identifiers
 * --------------------------------------------------------------------------*/
typedef enum {
    SE_PLAT_I2C_INIT    = 0x01U, /*!< Open /dev/i2c-N (no mutex)       */
    SE_PLAT_I2C_WAKE    = 0x02U, /*!< Zero-length write (no mutex)      */
    SE_PLAT_I2C_WRITE   = 0x03U, /*!< Write frame   → acquires mutex    */
    SE_PLAT_I2C_READ    = 0x04U, /*!< Read N bytes  → mutex held        */
    SE_PLAT_I2C_UNLOCK  = 0x05U, /*!< Release mutex                     */
} se_plat_cmd_t;

/* ---------------------------------------------------------------------------
 * Common response prefix (always first 4 bytes of every response payload)
 * --------------------------------------------------------------------------*/
typedef struct __attribute__((packed)) {
    int32_t status;    /*!< 0 = OK, negative = error code (stse_ReturnCode_t) */
} se_plat_status_t;

/* ---------------------------------------------------------------------------
 * SE_PLAT_I2C_INIT request payload
 * --------------------------------------------------------------------------*/
typedef struct __attribute__((packed)) {
    uint8_t bus_id;
} se_plat_i2c_init_req_t;

/* SE_PLAT_I2C_INIT response: se_plat_status_t only */

/* ---------------------------------------------------------------------------
 * SE_PLAT_I2C_WAKE request payload
 * --------------------------------------------------------------------------*/
typedef struct __attribute__((packed)) {
    uint8_t  bus_id;
    uint8_t  dev_addr;
    uint16_t speed_khz;
} se_plat_i2c_wake_req_t;

/* SE_PLAT_I2C_WAKE response: se_plat_status_t only */

/* ---------------------------------------------------------------------------
 * SE_PLAT_I2C_WRITE request payload
 *   Fixed header followed by data_len raw bytes
 * --------------------------------------------------------------------------*/
typedef struct __attribute__((packed)) {
    uint8_t  bus_id;
    uint8_t  dev_addr;
    uint16_t speed_khz;
    uint16_t data_len;   /*!< Number of frame bytes that immediately follow */
} se_plat_i2c_write_req_t;

/* SE_PLAT_I2C_WRITE response: se_plat_status_t only */

/* ---------------------------------------------------------------------------
 * SE_PLAT_I2C_READ request payload
 * --------------------------------------------------------------------------*/
typedef struct __attribute__((packed)) {
    uint8_t  bus_id;
    uint8_t  dev_addr;
    uint16_t speed_khz;
    uint16_t read_len;   /*!< Number of bytes to read from device */
} se_plat_i2c_read_req_t;

/* SE_PLAT_I2C_READ response payload:
 *   [ se_plat_status_t ][ uint16_t data_len ][ data_len bytes ]
 */
typedef struct __attribute__((packed)) {
    int32_t  status;
    uint16_t data_len;   /*!< Number of received bytes that follow */
} se_plat_i2c_read_rsp_t;

/* ---------------------------------------------------------------------------
 * SE_PLAT_I2C_UNLOCK: no request payload, se_plat_status_t response only
 * --------------------------------------------------------------------------*/

#ifdef __cplusplus
}
#endif

#endif /* STSE_IPC_H */

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
