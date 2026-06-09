/*!
 ******************************************************************************
 * \file    se_daemon.c
 * \brief   STSAFE SE daemon — privileged I2C bus manager
 *
 * This daemon is intentionally small.  It does NOT include STSELib.
 * Its sole responsibility is:
 *   1. Open /dev/i2c-* with the required privilege.
 *   2. Accept connections from libstse.so (via the modified platform layer).
 *   3. Serialise I2C transactions with a global mutex.
 *   4. Execute the I2C ioctls on behalf of the caller.
 *
 * The full STSELib (api/, services/, sal/pkcs11/) is compiled into libstse.so
 * and runs entirely in the application process.  The daemon is not involved in
 * APDU construction, key management, or PKCS#11 — it is a pure I2C bus proxy.
 *
 * Usage:
 *   se-daemon [--bus N] [--socket PATH] [--debug]
 *     --bus N      Pre-open I2C bus N on start (default: 1)
 *     --socket P   Listen on socket path P (default: /var/run/se-daemon.sock)
 *     --debug      Print every I2C TX/RX frame to stderr in hex
 *
 ******************************************************************************
 * \attention
 * COPYRIGHT 2024 STMicroelectronics
 * Licensed under the terms found in the LICENSE file in the root directory.
 ******************************************************************************
 */

#define _GNU_SOURCE  /* struct ucred, SO_PEERCRED */

#include "stse_ipc.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/i2c-dev.h>
#include <linux/i2c.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include <grp.h>
#include <semaphore.h>
#include <sys/time.h>

/* ---------------------------------------------------------------------------
 * I2C bus state
 * --------------------------------------------------------------------------*/
#define I2C_BUS_MAX  16
#define MAX_CLIENTS  16   /* max concurrent client connections */
static int              g_i2c_fds[I2C_BUS_MAX];
static pthread_mutex_t  g_i2c_mutexes[I2C_BUS_MAX];
static pthread_mutex_t  g_init_mutex = PTHREAD_MUTEX_INITIALIZER;
static sem_t            g_conn_sem;   /* counts available client slots */

/* ---------------------------------------------------------------------------
 * Server state
 * --------------------------------------------------------------------------*/
static volatile int g_running   = 1;
static int          g_server_fd = -1;
static char         g_socket_path[128] = SE_DAEMON_SOCKET_PATH;
static int          g_debug     = 0;  /*!< Enable I2C frame tracing (--debug) */

/* ---------------------------------------------------------------------------
 * Debug helpers
 * --------------------------------------------------------------------------*/
static void hex_dump(const char *label, uint8_t addr,
                     const uint8_t *buf, uint16_t len)
{
    fprintf(stderr, "[i2c] %s addr=0x%02X len=%u:\n       ", label, addr, len);
    for (uint16_t i = 0; i < len; i++) {
        fprintf(stderr, "%02X ", buf[i]);
        if ((i & 0x0F) == 0x0F && i + 1 < len)
            fprintf(stderr, "\n       ");
    }
    fprintf(stderr, "\n");
}

/* ---------------------------------------------------------------------------
 * C2 fix: snapshot the bus fd under the init mutex to avoid TOCTOU.
 *         Returns -1 if bus is out of range or not yet opened.
 * --------------------------------------------------------------------------*/
static int get_bus_fd(uint8_t bus)
{
    if (bus >= I2C_BUS_MAX) return -1;
    pthread_mutex_lock(&g_init_mutex);
    int fd = g_i2c_fds[bus];
    pthread_mutex_unlock(&g_init_mutex);
    return fd;
}

/* ---------------------------------------------------------------------------
 * Per-connection state
 * --------------------------------------------------------------------------*/
typedef struct {
    int  fd;
    int  holds_mutex_bus;   /*!< Bus index if holding a mutex, or -1 if none */
} conn_t;

/* ---------------------------------------------------------------------------
 * Helpers
 * --------------------------------------------------------------------------*/
static int write_all(int fd, const void *buf, size_t n)
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

static int read_all(int fd, void *buf, size_t n)
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

static int send_response(int fd, uint8_t cmd, const void *payload, uint32_t payload_len)
{
    se_plat_hdr_t hdr;
    hdr.magic       = SE_PLAT_MAGIC;
    hdr.version     = SE_PLAT_VERSION;
    hdr.cmd         = cmd;
    hdr._pad        = 0;
    hdr.payload_len = payload_len;
    if (write_all(fd, &hdr, sizeof(hdr)) != 0) return -1;
    if (payload_len > 0 && payload) {
        if (write_all(fd, payload, payload_len) != 0) return -1;
    }
    return 0;
}

static int send_status(int fd, uint8_t cmd, int32_t status)
{
    se_plat_status_t s = { .status = status };
    return send_response(fd, cmd, &s, sizeof(s));
}

/* ---------------------------------------------------------------------------
 * Command handlers
 * --------------------------------------------------------------------------*/

static int handle_i2c_init(conn_t *c, const uint8_t *payload, uint32_t plen)
{
    if (plen < sizeof(se_plat_i2c_init_req_t))
        return send_status(c->fd, SE_PLAT_I2C_INIT, -1);

    const se_plat_i2c_init_req_t *req = (const se_plat_i2c_init_req_t *)payload;
    uint8_t bus = req->bus_id;

    if (bus >= I2C_BUS_MAX) return send_status(c->fd, SE_PLAT_I2C_INIT, -1);

    /* Open if not already open (serialized via g_init_mutex) */
    pthread_mutex_lock(&g_init_mutex);
    if (g_i2c_fds[bus] < 0) {
        char path[32];
        snprintf(path, sizeof(path), "/dev/i2c-%u", (unsigned)bus);
        g_i2c_fds[bus] = open(path, O_RDWR);
        if (g_i2c_fds[bus] < 0) {
            fprintf(stderr, "[daemon] open %s: %s\n", path, strerror(errno));
            pthread_mutex_unlock(&g_init_mutex);
            return send_status(c->fd, SE_PLAT_I2C_INIT, -1);
        }
        printf("[daemon] opened %s\n", path);
    }
    pthread_mutex_unlock(&g_init_mutex);
    return send_status(c->fd, SE_PLAT_I2C_INIT, 0);
}

static int handle_i2c_wake(conn_t *c, const uint8_t *payload, uint32_t plen)
{
    if (plen < sizeof(se_plat_i2c_wake_req_t))
        return send_status(c->fd, SE_PLAT_I2C_WAKE, -1);

    const se_plat_i2c_wake_req_t *req = (const se_plat_i2c_wake_req_t *)payload;
    uint8_t bus = req->bus_id;

    int busfd = get_bus_fd(bus);
    if (busfd < 0)
        return send_status(c->fd, SE_PLAT_I2C_WAKE, -1);

    /* Serialize wake to prevent colliding with active I2C operations on the bus */
    pthread_mutex_lock(&g_i2c_mutexes[bus]);

    /* Generate I2C START+addr+STOP to wake the STSAFE-A from low-power mode.
     * A 1-byte dummy write is used instead of zero-length because some i2c-dev
     * drivers reject len=0.  NACK from the device is expected and ignored. */
    uint8_t dummy = 0x00;
    struct i2c_msg             msg  = { .addr  = req->dev_addr,
                                        .flags = 0,
                                        .len   = 1,
                                        .buf   = &dummy };
    struct i2c_rdwr_ioctl_data xfer = { .msgs = &msg, .nmsgs = 1 };
    ioctl(busfd, I2C_RDWR, &xfer); /* NACK expected; ignore error */

    pthread_mutex_unlock(&g_i2c_mutexes[bus]);

    return send_status(c->fd, SE_PLAT_I2C_WAKE, 0);
}

static int handle_i2c_write(conn_t *c, const uint8_t *payload, uint32_t plen)
{
    if (plen < sizeof(se_plat_i2c_write_req_t))
        return send_status(c->fd, SE_PLAT_I2C_WRITE, -1);

    const se_plat_i2c_write_req_t *req = (const se_plat_i2c_write_req_t *)payload;
    uint8_t  bus      = req->bus_id;
    uint16_t data_len = req->data_len;

    int busfd = get_bus_fd(bus);
    if (busfd < 0 ||
        (uint32_t)(sizeof(*req) + data_len) > plen)
        return send_status(c->fd, SE_PLAT_I2C_WRITE, -1);

    const uint8_t *frame = payload + sizeof(*req);

    /* Acquire per-bus I2C mutex if not already held by this connection */
    if (c->holds_mutex_bus != (int)bus) {
        pthread_mutex_lock(&g_i2c_mutexes[bus]);
        c->holds_mutex_bus = bus;
    }

    if (g_debug)
        hex_dump("TX >", req->dev_addr, frame, data_len);

    struct i2c_msg             msg  = { .addr  = req->dev_addr,
                                        .flags = 0,
                                        .len   = data_len,
                                        .buf   = (uint8_t *)(uintptr_t)frame };
    struct i2c_rdwr_ioctl_data xfer = { .msgs = &msg, .nmsgs = 1 };

    int32_t status = 0;
    if (ioctl(busfd, I2C_RDWR, &xfer) < 0) {
        fprintf(stderr, "[daemon] I2C write failed: %s\n", strerror(errno));
        status = -1;
        pthread_mutex_unlock(&g_i2c_mutexes[bus]);
        c->holds_mutex_bus = -1;
    }
    /* On success: mutex is held until UNLOCK */
    return send_status(c->fd, SE_PLAT_I2C_WRITE, status);
}

static int handle_i2c_read(conn_t *c, const uint8_t *payload, uint32_t plen)
{
    if (plen < sizeof(se_plat_i2c_read_req_t))
        return send_status(c->fd, SE_PLAT_I2C_READ, -1);

    const se_plat_i2c_read_req_t *req = (const se_plat_i2c_read_req_t *)payload;
    uint8_t  bus      = req->bus_id;
    uint16_t read_len = req->read_len;

    int busfd = get_bus_fd(bus);
    if (busfd < 0 ||
        read_len == 0 || read_len > SE_PLAT_MAX_FRAME)
        return send_status(c->fd, SE_PLAT_I2C_READ, -1);

    /* Enforce mutex check: read is only allowed if this connection holds the lock for this bus */
    if (c->holds_mutex_bus != bus) {
        fprintf(stderr, "[daemon] read attempt on bus %u without holding lock (holds lock for bus %d)\n",
                bus, c->holds_mutex_bus);
        return send_status(c->fd, SE_PLAT_I2C_READ, -1);
    }

    uint8_t rx_data[SE_PLAT_MAX_FRAME];

    struct i2c_msg             msg  = { .addr  = req->dev_addr,
                                        .flags = I2C_M_RD,
                                        .len   = read_len,
                                        .buf   = rx_data };
    struct i2c_rdwr_ioctl_data xfer = { .msgs = &msg, .nmsgs = 1 };

    int32_t status = 0;
    uint16_t actual = 0;
    if (ioctl(busfd, I2C_RDWR, &xfer) < 0) {
        fprintf(stderr, "[daemon] I2C read failed: %s\n", strerror(errno));
        status = -1;
    } else {
        actual = read_len;
        if (g_debug)
            hex_dump("RX <", req->dev_addr, rx_data, actual);
    }

    /* Build response: se_plat_i2c_read_rsp_t + actual data bytes */
    uint32_t rsp_total = (uint32_t)(sizeof(se_plat_i2c_read_rsp_t) + actual);
    uint8_t *rsp_buf   = malloc(rsp_total);
    if (!rsp_buf) { return send_status(c->fd, SE_PLAT_I2C_READ, -1); }

    se_plat_i2c_read_rsp_t *rsp = (se_plat_i2c_read_rsp_t *)rsp_buf;
    rsp->status   = status;
    rsp->data_len = actual;
    if (actual > 0) { memcpy(rsp_buf + sizeof(*rsp), rx_data, actual); }

    int rc = send_response(c->fd, SE_PLAT_I2C_READ, rsp_buf, rsp_total);
    free(rsp_buf);
    return rc;
}

static int handle_i2c_unlock(conn_t *c)
{
    if (c->holds_mutex_bus >= 0) {
        pthread_mutex_unlock(&g_i2c_mutexes[c->holds_mutex_bus]);
        c->holds_mutex_bus = -1;
    }
    return send_status(c->fd, SE_PLAT_I2C_UNLOCK, 0);
}

/* ---------------------------------------------------------------------------
 * Per-client worker thread
 * --------------------------------------------------------------------------*/
static void *worker_thread(void *arg)
{
    conn_t *c = (conn_t *)arg;

    /* Log peer identity */
    struct ucred cred; socklen_t clen = sizeof(cred);
    if (getsockopt(c->fd, SOL_SOCKET, SO_PEERCRED, &cred, &clen) == 0) {
        printf("[daemon] client connected: pid=%d uid=%d\n",
               (int)cred.pid, (int)cred.uid);
    }

    uint8_t *payload_buf = NULL;
    uint32_t payload_cap = 0;

    while (1) {
        /* Read header */
        se_plat_hdr_t hdr;
        if (read_all(c->fd, &hdr, sizeof(hdr)) != 0) break;

        if (hdr.magic != SE_PLAT_MAGIC || hdr.version != SE_PLAT_VERSION) {
            fprintf(stderr, "[daemon] invalid header magic 0x%08X\n", hdr.magic);
            break;
        }
        if (hdr.payload_len > SE_PLAT_MAX_FRAME + 64U) {
            fprintf(stderr, "[daemon] payload too large (%u)\n", hdr.payload_len);
            break;
        }

        /* Read payload */
        if (hdr.payload_len > payload_cap) {
            uint8_t *nb = realloc(payload_buf, hdr.payload_len);
            if (!nb) break;
            payload_buf = nb;
            payload_cap = hdr.payload_len;
        }
        if (hdr.payload_len > 0) {
            if (read_all(c->fd, payload_buf, hdr.payload_len) != 0) break;
        }

        /* Dispatch */
        int rc;
        switch ((se_plat_cmd_t)hdr.cmd) {
            case SE_PLAT_I2C_INIT:   rc = handle_i2c_init(c, payload_buf, hdr.payload_len); break;
            case SE_PLAT_I2C_WAKE:   rc = handle_i2c_wake(c, payload_buf, hdr.payload_len); break;
            case SE_PLAT_I2C_WRITE:  rc = handle_i2c_write(c, payload_buf, hdr.payload_len); break;
            case SE_PLAT_I2C_READ:   rc = handle_i2c_read(c, payload_buf, hdr.payload_len); break;
            case SE_PLAT_I2C_UNLOCK: rc = handle_i2c_unlock(c); break;
            default:
                fprintf(stderr, "[daemon] unknown cmd 0x%02X\n", hdr.cmd);
                rc = -1;
                break;
        }
        if (rc != 0) break;
    }

    /* Cleanup: release mutex if client disconnected while holding it */
    if (c->holds_mutex_bus >= 0) {
        fprintf(stderr, "[daemon] client fd=%d dropped while holding lock on bus %d — releasing\n",
                c->fd, c->holds_mutex_bus);
        pthread_mutex_unlock(&g_i2c_mutexes[c->holds_mutex_bus]);
    }

    if (payload_buf) free(payload_buf);
    close(c->fd);
    printf("[daemon] client disconnected: fd=%d\n", c->fd);
    free(c);
    sem_post(&g_conn_sem);   /* C1: release one connection slot */
    return NULL;
}

/* ---------------------------------------------------------------------------
 * Signal handling
 * --------------------------------------------------------------------------*/
static void sig_handler(int sig)
{
    (void)sig;
    g_running = 0;
    if (g_server_fd >= 0) { close(g_server_fd); g_server_fd = -1; }
}

/* ---------------------------------------------------------------------------
 * main
 * --------------------------------------------------------------------------*/
int main(int argc, char *argv[])
{
    /* Initialise I2C fd table and per-bus mutexes */
    for (int i = 0; i < I2C_BUS_MAX; i++) {
        g_i2c_fds[i] = -1;
        pthread_mutex_init(&g_i2c_mutexes[i], NULL);
    }

    /* C1: initialise connection-count semaphore */
    if (sem_init(&g_conn_sem, 0, MAX_CLIENTS) != 0) {
        perror("[daemon] sem_init"); return EXIT_FAILURE;
    }

    /* Parse arguments */
    int pre_open_bus = 1;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--bus") == 0 && i + 1 < argc) {
            char *ep; errno = 0;
            long v = strtol(argv[++i], &ep, 10);
            if (errno != 0 || *ep != '\0' || v < 0 || v >= I2C_BUS_MAX) {
                fprintf(stderr, "[daemon] invalid bus number: %s\n", argv[i]);
                return EXIT_FAILURE;
            }
            pre_open_bus = (int)v;
        } else if (strcmp(argv[i], "--socket") == 0 && i + 1 < argc) {
            strncpy(g_socket_path, argv[++i], sizeof(g_socket_path) - 1);
        } else if (strcmp(argv[i], "--debug") == 0) {
            g_debug = 1;
        } else {
            fprintf(stderr, "Usage: %s [--bus N] [--socket PATH] [--debug]\n", argv[0]);
            return EXIT_FAILURE;
        }
    }

    printf("[daemon] STSAFE SE Daemon starting (I2C bus proxy)\n");

    /* Pre-open the default I2C bus */
    if (pre_open_bus >= 0 && pre_open_bus < I2C_BUS_MAX) {
        char path[32];
        snprintf(path, sizeof(path), "/dev/i2c-%d", pre_open_bus);
        g_i2c_fds[pre_open_bus] = open(path, O_RDWR);
        if (g_i2c_fds[pre_open_bus] < 0) {
            fprintf(stderr, "[daemon] warning: cannot pre-open %s: %s\n",
                    path, strerror(errno));
        } else {
            printf("[daemon] pre-opened %s\n", path);
        }
    }

    /* Signals */
    struct sigaction sa; memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler; sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    /* Unix Domain Socket */
    g_server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (g_server_fd < 0) { perror("[daemon] socket"); return EXIT_FAILURE; }

    unlink(g_socket_path);
    struct sockaddr_un addr; memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, g_socket_path, sizeof(addr.sun_path) - 1);

    if (bind(g_server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("[daemon] bind"); close(g_server_fd); return EXIT_FAILURE;
    }
    chmod(g_socket_path, 0660); /* rw-rw---- : root + se-daemon group */

    /* Change socket group to 'se-daemon' if it exists */
    struct group *grp = getgrnam("se-daemon");
    if (grp) {
        if (chown(g_socket_path, -1, grp->gr_gid) < 0) {
            perror("[daemon] chown socket group failed");
        } else {
            printf("[daemon] socket group ownership set to 'se-daemon'\n");
        }
    } else {
        fprintf(stderr, "[daemon] warning: group 'se-daemon' not found; socket group remains root\n");
    }

    if (listen(g_server_fd, 16) < 0) {
        perror("[daemon] listen"); unlink(g_socket_path);
        close(g_server_fd); return EXIT_FAILURE;
    }
    printf("[daemon] listening on %s\n", g_socket_path);

    /* Accept loop */
    while (g_running) {
        int cfd = accept(g_server_fd, NULL, NULL);
        if (cfd < 0) {
            if (!g_running) break;
            if (errno == EINTR) continue;
            perror("[daemon] accept"); continue;
        }

        conn_t *c = calloc(1, sizeof(*c));
        if (!c) { close(cfd); continue; }
        c->fd              = cfd;
        c->holds_mutex_bus = -1;

        /* C1: enforce connection limit — reject rather than block */
        if (sem_trywait(&g_conn_sem) != 0) {
            fprintf(stderr, "[daemon] connection limit (%d) reached, rejecting fd=%d\n",
                    MAX_CLIENTS, cfd);
            free(c); close(cfd); continue;
        }

        /* Set inactivity read timeout (5 seconds) */
        struct timeval tv;
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        if (setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
            perror("[daemon] setsockopt SO_RCVTIMEO");
        }

        pthread_t tid;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        if (pthread_create(&tid, &attr, worker_thread, c) != 0) {
            perror("[daemon] pthread_create"); free(c); close(cfd);
        }
        pthread_attr_destroy(&attr);
    }

    printf("[daemon] shutting down\n");
    if (g_server_fd >= 0) close(g_server_fd);
    unlink(g_socket_path);
    for (int i = 0; i < I2C_BUS_MAX; i++) {
        if (g_i2c_fds[i] >= 0) close(g_i2c_fds[i]);
    }
    return EXIT_SUCCESS;
}

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
