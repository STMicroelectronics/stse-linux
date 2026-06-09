/**
 ******************************************************************************
 * @file    main.c
 * @brief   STSAFE-A120 Host key provisioning (plaintext) — Linux/MPU port
 ******************************************************************************
 *           COPYRIGHT 2022 STMicroelectronics
 ******************************************************************************
 * Usage:  ./02_Host_key_provisioning [busID]   (default busID = 1)
 *
 * WARNING: Writes test keys and enables permanent re-provisioning.
 *          NOT suitable for production use.
 ******************************************************************************
 */

#include "Apps_utils.h"

int main(int argc, char *argv[]) {
    stse_ReturnCode_t stse_ret = STSE_API_INVALID_PARAMETER;
    stse_Handler_t    stse_handler;
    uint8_t           busID = 1;

    if (argc > 1) busID = (uint8_t)atoi(argv[1]);

    stsafea_aes_128_host_keys_t host_keys = {
        .host_mac_key    = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                            0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
        .host_cipher_key = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}
    };
    stsafea_host_key_provisioning_ctrl_fields_t provisioning_ctrl_fields;

    apps_terminal_init(115200);

    printf("----------------------------------------------------------------------------------------------------------------");
    printf("\n\r-                              STSAFE-A120 Host key provisioning example                                     -");
    printf("\n\r----------------------------------------------------------------------------------------------------------------");
    printf(PRINT_RED
           "\n\r| /!\\  WARNING: This will write test keys and enable re-provisioning permanently. |\n\r" PRINT_RESET);
    printf("Press Enter to continue, Ctrl-C to abort.\n\r");
    apps_terminal_read_string(NULL, NULL);

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

    printf("\n\n\r - Host MAC key to write:\n\r");
    apps_print_hex_buffer(host_keys.host_mac_key, STSAFEA_HOST_AES_128_MAC_KEY_SIZE);
    printf("\n\n\r - Host cipher key to write:\n\r");
    apps_print_hex_buffer(host_keys.host_cipher_key, STSAFEA_HOST_AES_128_CIPHER_KEY_SIZE);

    printf("\n\n\r - Query host key slot provisioning control fields:");
    stse_ret = stsafea_query_host_key_provisioning_ctrl_fields(&stse_handler,
                                                                &provisioning_ctrl_fields);
    if (stse_ret != STSE_OK) {
        printf(PRINT_RED "\n\n\r - stsafea_query_host_key_provisioning_ctrl_fields ERROR : 0x%04X", stse_ret);
        apps_process_error(stse_ret);
    }
    apps_print_host_key_provisioning_control_fields(&stse_handler);

    if (provisioning_ctrl_fields.change_right == 0) {
        if (provisioning_ctrl_fields.reprovision == 0) {
            printf(PRINT_RED "\n\r - ERROR : Host keys are already locked and re-provisioning disabled\n\r" PRINT_RESET);
            return 1;
        } else {
            printf(PRINT_CYAN "\n\r - Host key provisioning control fields value already set" PRINT_RESET);
        }
    } else {
        printf("\n\n\r - Opening host key slot to re-provisioning");
        provisioning_ctrl_fields.filler                               = 0;
        provisioning_ctrl_fields.change_right                         = 0;
        provisioning_ctrl_fields.reprovision                          = 1;
        provisioning_ctrl_fields.plaintext                            = 1;
        provisioning_ctrl_fields.wrapped_anonymous                    = 1;
        provisioning_ctrl_fields.wrapped_or_DH_derived_authentication_key = 0xFF;
        stse_ret = stsafea_put_host_key_provisioning_ctrl_fields(&stse_handler,
                                                                   &provisioning_ctrl_fields);
        if (stse_ret != STSE_OK) {
            printf(PRINT_RED "\n\n\r - stsafea_put_host_key_provisioning_ctrl_fields ERROR : 0x%04X", stse_ret);
        }
    }

    stse_ret = stse_host_key_provisioning(&stse_handler,
                                           STSAFEA_AES_128_HOST_KEY,
                                           (stsafea_host_keys_t *)&host_keys);
    if (stse_ret != STSE_OK) {
        printf(PRINT_RED "\n\n\r - stse_host_key_provisioning ERROR : 0x%04X\n\r" PRINT_RESET, stse_ret);
        return 1;
    }
    printf(PRINT_GREEN "\n\n\r - stse_host_key_provisioning : PASS\n\r" PRINT_RESET);
    return 0;
}
