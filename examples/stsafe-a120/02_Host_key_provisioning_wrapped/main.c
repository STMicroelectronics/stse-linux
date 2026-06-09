/**
 ******************************************************************************
 * @file    main.c
 * @brief   STSAFE-A120 Host key provisioning (wrapped) — Linux/MPU port
 ******************************************************************************
 *           COPYRIGHT 2022 STMicroelectronics
 ******************************************************************************
 * Usage:  ./02_Host_key_provisioning_wrapped [busID]   (default busID = 1)
 *
 * Provisions AES-128 host keys using ECDH-based key wrapping.
 * Requires group-01 examples to have been run first (no pre-existing host key).
 ******************************************************************************
 */

#include "Apps_utils.h"

int main(int argc, char *argv[]) {
    stse_ReturnCode_t stse_ret = STSE_API_INVALID_PARAMETER;
    stse_Handler_t    stse_handler;
    uint8_t           busID = 1;

    if (argc > 1) busID = (uint8_t)atoi(argv[1]);

    /* New host keys to provision via wrapped method */
    stsafea_aes_128_host_keys_t host_keys = {
        .host_mac_key    = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                            0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
        .host_cipher_key = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}
    };

    apps_terminal_init(115200);

    printf("----------------------------------------------------------------------------------------------------------------");
    printf("\n\r-                              STSAFE-A120 Host key provisioning (wrapped) example                           -");
    printf("\n\r----------------------------------------------------------------------------------------------------------------");
    printf("\n\r- Provisions host keys via ECDH wrapped method.                                                               -");
    printf("\n\r- Prerequisites: run 02_Host_key_provisioning first to open the slot.                                         -");
    printf("\n\r----------------------------------------------------------------------------------------------------------------");

    stse_ret = stse_set_default_handler_value(&stse_handler);
    if (stse_ret != STSE_OK) { apps_process_error(stse_ret); }

    stse_handler.device_type  = STSAFE_A120;
    stse_handler.io.busID     = busID;
    stse_handler.io.BusSpeed  = 400;

    printf("\n\r - Initialize target STSAFE-A120 on /dev/i2c-%u", (unsigned)busID);
    stse_ret = stse_init(&stse_handler);
    if (stse_ret != STSE_OK) {
        printf(PRINT_RED "\n\r ## stse_init ERROR : 0x%04X\n\r", stse_ret);
        apps_process_error(stse_ret);
    }

    printf("\n\n\r - Display current host key provisioning control fields:");
    apps_print_host_key_provisioning_control_fields(&stse_handler);

    printf("\n\n\r - Host MAC key to provision:\n\r");
    apps_print_hex_buffer(host_keys.host_mac_key, STSAFEA_HOST_AES_128_MAC_KEY_SIZE);
    printf("\n\n\r - Host cipher key to provision:\n\r");
    apps_print_hex_buffer(host_keys.host_cipher_key, STSAFEA_HOST_AES_128_CIPHER_KEY_SIZE);

    /* Provision via wrapped ECDH method */
    stse_ret = stse_host_key_provisioning_wrapped(&stse_handler,
                                                   STSAFEA_AES_128_HOST_KEY,
                                                   (stsafea_host_keys_t *)&host_keys,
                                                   STSE_ECC_KT_NIST_P_256);
    if (stse_ret != STSE_OK) {
        printf(PRINT_RED "\n\n\r - stse_host_key_provisioning_wrapped ERROR : 0x%04X\n\r" PRINT_RESET, stse_ret);
        return 1;
    }
    printf(PRINT_GREEN "\n\n\r - stse_host_key_provisioning_wrapped : PASS\n\r" PRINT_RESET);
    return 0;
}
