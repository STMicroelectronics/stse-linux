/******************************************************************************
 * \file    stse_platform_i2c.c
 * \brief   STSecureElement I2C platform — IPC proxy for Linux daemon model
 * \author  STMicroelectronics - CS application team
 *
 ******************************************************************************
 * \attention
 *
 * <h2><center>&copy; COPYRIGHT 2024 STMicroelectronics</center></h2>
 *
 * This software is licensed under terms that can be found in the LICENSE file
 * in the root directory of this software component.
 * If no LICENSE file comes with this software, it is provided AS-IS.
 *
 ******************************************************************************
 *
 * Architecture
 * ─────────────
 * libstse.so contains the full STSELib (api/, services/, sal/pkcs11/ etc.)
 * compiled unchanged.  This file is the ONLY platform source that changes:
 * instead of calling Linux I2C ioctls directly, each I2C platform function
 * is a thin proxy that communicates with the privileged se-daemon via a Unix
 * Domain Socket.
 *
 * The daemon owns /dev/i2c-*, holds the global bus mutex, and serialises
 * concurrent callers.  Applications need only be in the 'se-daemon' group.
 *
 * Mutex lifecycle
 * ────────────────
 *  send_stop     → SE_PLAT_I2C_WRITE  : daemon acquires global I2C mutex
 *  receive_start → SE_PLAT_I2C_READ   : reads (mutex still held)
 *  receive_continue → (local copy from cached response, no IPC)
 *  receive_stop  → local copy + SE_PLAT_I2C_UNLOCK : daemon releases mutex
 *
 * All other platform files (delay, aes, ecc, hash, random, crc) are
 * unchanged — they are local and need no elevated privilege.
 *
 ******************************************************************************
 */

#include "stse_conf.h"
#include "stselib.h"
#include "stse_ipc.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

/* ===========================================================================
 * IPC connection management (process-global, thread-safe)
 * =========================================================================*/

static __thread int  g_sock_fd    = -1;
static __thread int  g_expect_second_phase = 0;
static __thread stse_device_t g_stse_device_type = STSAFE_A120;

void stse_platform_i2c_set_device_type(stse_device_t device_type)
{
    g_stse_device_type = device_type;
}

static int ipc_write_all(int fd, const void *buf, size_t n)
{
    const uint8_t *p = (const uint8_t *)buf;
    while (n > 0) {
        ssize_t w = write(fd, p, n);
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        if (w == 0) return -1;
        p += (size_t)w; n -= (size_t)w;
    }
    return 0;
}

static int ipc_read_all(int fd, void *buf, size_t n)
{
    uint8_t *p = (uint8_t *)buf;
    while (n > 0) {
        ssize_t r = read(fd, p, n);
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        if (r == 0) return -1;
        p += (size_t)r; n -= (size_t)r;
    }
    return 0;
}

/* Caller must hold g_conn_mutex */
static int ipc_ensure_connected(void)
{
    if (g_sock_fd >= 0) return 0;

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { perror("[stse_plat] socket"); return -1; }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SE_DAEMON_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "[stse_plat] connect to %s failed: %s\n",
                SE_DAEMON_SOCKET_PATH, strerror(errno));
        close(fd);
        return -1;
    }
    g_sock_fd = fd;
    return 0;
}

/* Send a platform command; receive its response.  Caller holds g_conn_mutex. */
static int ipc_transact(uint8_t      cmd,
                        const void  *req_payload, uint32_t req_len,
                        void        *rsp_payload, uint32_t rsp_cap,
                        uint32_t    *rsp_len_out)
{
    if (ipc_ensure_connected() != 0) return -1;

    se_plat_hdr_t hdr;
    hdr.magic       = SE_PLAT_MAGIC;
    hdr.version     = SE_PLAT_VERSION;
    hdr.cmd         = cmd;
    hdr._pad        = 0;
    hdr.payload_len = req_len;

    if (ipc_write_all(g_sock_fd, &hdr, sizeof(hdr)) != 0) goto drop;
    if (req_len > 0 && req_payload) {
        if (ipc_write_all(g_sock_fd, req_payload, req_len) != 0) goto drop;
    }

    se_plat_hdr_t rsp_hdr;
    if (ipc_read_all(g_sock_fd, &rsp_hdr, sizeof(rsp_hdr)) != 0) goto drop;

    if (rsp_hdr.magic != SE_PLAT_MAGIC || rsp_hdr.version != SE_PLAT_VERSION ||
        rsp_hdr.cmd   != cmd) {
        fprintf(stderr, "[stse_plat] bad response (cmd=0x%02X)\n", rsp_hdr.cmd);
        goto drop;
    }

    uint32_t plen = rsp_hdr.payload_len;
    if (rsp_len_out) *rsp_len_out = plen;

    if (plen > 0) {
        if (plen > rsp_cap) {
            /* Drain socket to stay in sync */
            uint8_t drain[64]; uint32_t rem = plen;
            while (rem > 0) {
                uint32_t chunk = (rem < sizeof(drain)) ? rem : (uint32_t)sizeof(drain);
                if (ipc_read_all(g_sock_fd, drain, chunk) != 0) goto drop;
                rem -= chunk;
            }
            return -1;
        }
        if (ipc_read_all(g_sock_fd, rsp_payload, plen) != 0) goto drop;
    }
    return 0;

drop:
    close(g_sock_fd); g_sock_fd = -1;
    return -1;
}

/* ===========================================================================
 * Local Tx/Rx frame buffers
 * =========================================================================*/

static __thread PLAT_UI8  tx_buf[SE_PLAT_MAX_FRAME];
static __thread PLAT_UI16 tx_size;
static __thread PLAT_UI16 tx_off;

static __thread PLAT_UI8  rx_buf[SE_PLAT_MAX_FRAME];
static __thread PLAT_UI16 rx_size;
static __thread PLAT_UI16 rx_off;

/* ===========================================================================
 * STSELib platform I2C interface
 * =========================================================================*/

stse_ReturnCode_t stse_platform_i2c_init(PLAT_UI8 busID)
{
    se_plat_i2c_init_req_t req = { .bus_id = busID };
    se_plat_status_t       rsp;
    uint32_t               rsp_len = 0;

    int rc = ipc_transact(SE_PLAT_I2C_INIT, &req, sizeof(req),
                          &rsp, sizeof(rsp), &rsp_len);

    if (rc != 0 || rsp_len < sizeof(rsp) || rsp.status != 0)
        return STSE_PLATFORM_BUS_ACK_ERROR;

    /* Send a zero-length I2C write (START + addr + STOP) to wake the STSAFE-A120/L010.
     * On Linux, BusSendStart is a local buffer op — no I2C activity occurs until
     * BusSendStop. This means the STSAFE-A/L never receives the SDA transition it
     * needs to exit low-power mode before the first command frame arrives.
     * Sending a wake pulse here (NACK from device is normal and ignored) followed
     * by a 2 ms t_rec delay ensures the device is ready before stse_init proceeds.
     * STSAFE-A120 default I2C address = 0x20, STSAFE-L010 default I2C address = 0x0C. */
    if (g_stse_device_type != STSAFE_L010) {
        stse_platform_i2c_wake(busID, 0x20U, 100U);
        struct timespec t_rec = { .tv_sec = 0, .tv_nsec = 2000000L }; /* 2 ms */
        nanosleep(&t_rec, NULL);
    }

    return STSE_OK;
}

stse_ReturnCode_t stse_platform_i2c_wake(PLAT_UI8 busID, PLAT_UI8 devAddr, PLAT_UI16 speed)
{
    se_plat_i2c_wake_req_t req = {
        .bus_id = busID, .dev_addr = devAddr, .speed_khz = speed
    };
    se_plat_status_t rsp;
    uint32_t         rsp_len = 0;

    int rc = ipc_transact(SE_PLAT_I2C_WAKE, &req, sizeof(req),
                          &rsp, sizeof(rsp), &rsp_len);

    return (rc == 0 && rsp_len >= sizeof(rsp) && rsp.status == 0)
           ? STSE_OK : STSE_PLATFORM_BUS_ACK_ERROR;
}

/* send_start / send_continue: buffer the frame locally — no IPC */

stse_ReturnCode_t stse_platform_i2c_send_start(PLAT_UI8 busID, PLAT_UI8 devAddr,
                                                PLAT_UI16 speed, PLAT_UI16 frameLength)
{
    (void)busID; (void)devAddr; (void)speed;
    if (frameLength > sizeof(tx_buf)) return STSE_PLATFORM_BUFFER_ERR;
    tx_size = frameLength;
    tx_off  = 0;
    return STSE_OK;
}

stse_ReturnCode_t stse_platform_i2c_send_continue(PLAT_UI8 busID, PLAT_UI8 devAddr,
                                                   PLAT_UI16 speed,
                                                   PLAT_UI8 *pData, PLAT_UI16 data_size)
{
    (void)busID; (void)devAddr; (void)speed;
    if (data_size == 0) return STSE_OK;
    if ((PLAT_UI16)(tx_off + data_size) > tx_size) return STSE_PLATFORM_BUFFER_ERR;
    if (pData) memcpy(tx_buf + tx_off, pData, data_size);
    else       memset(tx_buf + tx_off, 0x00,  data_size);
    tx_off += data_size;
    return STSE_OK;
}

/*
 * send_stop: IPC SE_PLAT_I2C_WRITE — daemon acquires the global I2C bus mutex
 * and writes the frame.  The mutex stays locked until receive_stop sends UNLOCK.
 */
stse_ReturnCode_t stse_platform_i2c_send_stop(PLAT_UI8 busID, PLAT_UI8 devAddr,
                                               PLAT_UI16 speed,
                                               PLAT_UI8 *pData, PLAT_UI16 data_size)
{
    stse_ReturnCode_t ret = stse_platform_i2c_send_continue(busID, devAddr, speed,
                                                             pData, data_size);
    if (ret != STSE_OK) return ret;

    uint32_t req_total = (uint32_t)(sizeof(se_plat_i2c_write_req_t) + tx_size);
    uint8_t *req_buf   = malloc(req_total);
    if (!req_buf) return STSE_PLATFORM_BUFFER_ERR;

    se_plat_i2c_write_req_t *wreq = (se_plat_i2c_write_req_t *)req_buf;
    wreq->bus_id    = busID;
    wreq->dev_addr  = devAddr;
    wreq->speed_khz = speed;
    wreq->data_len  = tx_size;
    memcpy(req_buf + sizeof(*wreq), tx_buf, tx_size);

    se_plat_status_t rsp;
    uint32_t         rsp_len = 0;

    int rc = ipc_transact(SE_PLAT_I2C_WRITE, req_buf, req_total,
                          &rsp, sizeof(rsp), &rsp_len);

    free(req_buf);

    if (rc != 0 || rsp_len < sizeof(rsp) || rsp.status != 0)
        return STSE_PLATFORM_BUS_ACK_ERROR;

    rx_size = 0;
    rx_off  = 0;
    return STSE_OK;
}

/*
 * receive_start: IPC SE_PLAT_I2C_READ — daemon reads frameLength bytes from
 * the I2C bus (bus mutex still held) and returns them.  The bytes are cached
 * in rx_buf for receive_continue / receive_stop (which are local only).
 */
stse_ReturnCode_t stse_platform_i2c_receive_start(PLAT_UI8 busID, PLAT_UI8 devAddr,
                                                   PLAT_UI16 speed, PLAT_UI16 frameLength)
{
    se_plat_i2c_read_req_t req = {
        .bus_id    = busID,
        .dev_addr  = devAddr,
        .speed_khz = speed,
        .read_len  = frameLength
    };

    uint32_t rsp_cap = (uint32_t)(sizeof(se_plat_i2c_read_rsp_t) + frameLength);
    uint8_t *rsp_buf = malloc(rsp_cap);
    if (!rsp_buf) return STSE_PLATFORM_BUFFER_ERR;

    uint32_t rsp_len = 0;

    int rc = ipc_transact(SE_PLAT_I2C_READ, &req, sizeof(req),
                          rsp_buf, rsp_cap, &rsp_len);

    if (rc != 0 || rsp_len < sizeof(se_plat_i2c_read_rsp_t)) {
        free(rsp_buf); return STSE_PLATFORM_BUS_ACK_ERROR;
    }
    se_plat_i2c_read_rsp_t *rrsp = (se_plat_i2c_read_rsp_t *)rsp_buf;
    if (rrsp->status != 0 || rrsp->data_len == 0) {
        free(rsp_buf);
        return (rrsp->status == (int32_t)STSE_PLATFORM_BUS_ACK_ERROR)
               ? STSE_PLATFORM_BUS_ACK_ERROR : STSE_PLATFORM_BUS_ACK_ERROR;
    }

    PLAT_UI16 dlen = rrsp->data_len;
    if (dlen > (PLAT_UI16)sizeof(rx_buf)) dlen = (PLAT_UI16)sizeof(rx_buf);
    memcpy(rx_buf, rsp_buf + sizeof(*rrsp), dlen);
    rx_size = dlen;
    rx_off  = 0;

    free(rsp_buf);

    /* Detect if this is Phase 1 of a two-phase read */
    if (g_stse_device_type != STSAFE_L010 && frameLength == 5 && rx_size >= 3) {
        PLAT_UI16 total_response_length = (PLAT_UI16)((rx_buf[1] << 8) | rx_buf[2]);
        /* Total frame size on bus is: 1 byte header + 2 bytes length + total_response_length */
        /* If it's larger than Phase 1 request size (5), a Phase 2 read will follow. */
        if (3 + total_response_length > 5) {
            g_expect_second_phase = 1;
        } else {
            g_expect_second_phase = 0;
        }
    } else if (frameLength == 2 && rx_size >= 2) {
        PLAT_UI16 total_response_length = (PLAT_UI16)((rx_buf[0] << 8) | rx_buf[1]);
        if (total_response_length > 0) {
            g_expect_second_phase = 1;
        } else {
            g_expect_second_phase = 0;
        }
    } else {
        g_expect_second_phase = 0;
    }

    return STSE_OK;
}

/* receive_continue: copy from local rx cache — no IPC */
stse_ReturnCode_t stse_platform_i2c_receive_continue(PLAT_UI8 busID, PLAT_UI8 devAddr,
                                                     PLAT_UI16 speed,
                                                     PLAT_UI8 *pData, PLAT_UI16 data_size)
{
    (void)busID; (void)devAddr; (void)speed;
    if (data_size == 0) return STSE_OK;
    if ((PLAT_UI16)(rx_off + data_size) > rx_size) return STSE_PLATFORM_BUFFER_ERR;
    /* pData == NULL means "discard" (STSELib discards the length field this way).
     * We must still advance rx_off so subsequent reads land on the correct bytes. */
    if (pData)
        memcpy(pData, rx_buf + rx_off, data_size);
    rx_off += data_size;
    return STSE_OK;
}

/*
 * receive_stop: copy final bytes from rx cache, then send SE_PLAT_I2C_UNLOCK
 * so the daemon releases the global I2C bus mutex.
 */
stse_ReturnCode_t stse_platform_i2c_receive_stop(PLAT_UI8 busID, PLAT_UI8 devAddr,
                                                  PLAT_UI16 speed,
                                                  PLAT_UI8 *pData, PLAT_UI16 data_size)
{
    stse_ReturnCode_t ret = stse_platform_i2c_receive_continue(busID, devAddr, speed,
                                                               pData, data_size);

    /* Always send UNLOCK to avoid leaving the daemon-side mutex locked,
     * unless we expect a Phase 2 read to follow immediately. */
    if (!g_expect_second_phase) {
        se_plat_status_t rsp;
        uint32_t         rsp_len = 0;
        ipc_transact(SE_PLAT_I2C_UNLOCK, NULL, 0, &rsp, sizeof(rsp), &rsp_len);
    } else {
        /* Reset flag so Phase 2's stop will unlock */
        g_expect_second_phase = 0;
    }

    rx_size = 0;
    rx_off  = 0;
    return ret;
}

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
