/**
 ******************************************************************************
 * @file    stse_echo_example.c
 * @author  CS application team
 * @brief   STSAFE echo command example
 ******************************************************************************
 *           COPYRIGHT 2024 STMicroelectronics
 *
 * This software is licensed under terms that can be found in the LICENSE file in
 * the root directory of this software component.
 * If no LICENSE file comes with this software, it is provided AS-IS.
 *
 ******************************************************************************
 *
 * Demonstrates basic STSAFE-A communication via the echo command using the
 * standard STSELib API.  The application calls STSELib functions directly
 * (no daemon awareness) — the I2C bus access is transparently proxied to the
 * privileged se-daemon through the modified STSELib_Platform layer.
 *
 * Call flow:
 *   Application → stsafea_echo() [STSELib]
 *               → stse_platform_i2c_* [modified platform layer]
 *               → se-daemon (IPC, /var/run/se-daemon.sock)
 *               → /dev/i2c-N  (daemon has the privilege)
 *
 * Usage:
 *   ./stse_echo_example [busID]
 *   busID defaults to 1 (/dev/i2c-1) if not provided
 *
 * Prerequisites:
 *   - se-daemon must be running: systemctl start se-daemon
 *   - The calling user must be in the 'se-daemon' group
 *
 ******************************************************************************
 */

#include "stselib.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ECHO_MESSAGE_LENGTH 16U

static void print_hex(const char *label, const uint8_t *buf, size_t len) {
    printf("%s", label);
    for (size_t i = 0; i < len; i++) printf("%02X ", buf[i]);
    printf("\n");
}

int main(int argc, char *argv[]) {
    stse_ReturnCode_t ret;
    stse_Handler_t    handler;
    uint8_t           message[ECHO_MESSAGE_LENGTH];
    uint8_t           echo[ECHO_MESSAGE_LENGTH];
    uint8_t           busID = 1;

    if (argc > 1) busID = (uint8_t)atoi(argv[1]);

    printf("------------------------------------------------------------\n");
    printf("-               STSAFE-A Echo Example                      -\n");
    printf("------------------------------------------------------------\n");
    printf("I2C bus: /dev/i2c-%u  (via se-daemon)\n\n", (unsigned)busID);

    ret = stse_set_default_handler_value(&handler);
    if (ret != STSE_OK) {
        fprintf(stderr, "stse_set_default_handler_value ERROR: 0x%04X\n", ret);
        return EXIT_FAILURE;
    }
    handler.device_type = STSAFE_A120;
    handler.io.busID    = busID;
    handler.io.BusSpeed = 400;

    ret = stse_init(&handler);
    if (ret != STSE_OK) {
        fprintf(stderr, "stse_init ERROR: 0x%04X\n  Is se-daemon running?\n", ret);
        return EXIT_FAILURE;
    }
    printf("Device initialised successfully.\n\n");

    for (int i = 0; i < 10; i++) {
        for (size_t j = 0; j < ECHO_MESSAGE_LENGTH; j++)
            message[j] = (uint8_t)((i * ECHO_MESSAGE_LENGTH + j) & 0xFF);

        printf("[%d] Sending: ", i + 1);
        print_hex("", message, ECHO_MESSAGE_LENGTH);

        memset(echo, 0, sizeof(echo));
        ret = stsafea_echo(&handler, message, echo, ECHO_MESSAGE_LENGTH);
        if (ret != STSE_OK) {
            fprintf(stderr, "    stsafea_echo ERROR: 0x%04X\n", ret);
            return EXIT_FAILURE;
        }

        printf("    Echoed: ");
        print_hex("", echo, ECHO_MESSAGE_LENGTH);

        if (memcmp(message, echo, ECHO_MESSAGE_LENGTH) != 0) {
            fprintf(stderr, "    MISMATCH!\n");
            return EXIT_FAILURE;
        }
        printf("    OK\n\n");
        sleep(1);
    }

    printf("Echo test completed successfully.\n");
    return EXIT_SUCCESS;
}
