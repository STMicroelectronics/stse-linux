/**
 ******************************************************************************
 * @file    main.c
 * @brief   STSAFE-A120 Key wrapping/unwrapping — Linux/MPU port
 ******************************************************************************
 *           COPYRIGHT 2022 STMicroelectronics
 ******************************************************************************
 * Usage:  ./03_Key_wrapping [busID]   (default busID = 1)
 *
 * Prerequisites: Run 02_Host_key_provisioning first (host session needed).
 ******************************************************************************
 */

#include "Apps_utils.h"

#define BUFFER_SIZE 16

#define ENCRYPT_NO 0x00

const stsafea_aes_128_host_keys_t host_keys = {
    .host_mac_key    = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
    .host_cipher_key = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}
};

int main(int argc, char *argv[]) {
    stse_ReturnCode_t stse_ret = STSE_API_INVALID_PARAMETER;
    stse_Handler_t    stse_handler;
    stse_session_t    host_session_handler;
    uint8_t           busID = 1;

    if (argc > 1) busID = (uint8_t)atoi(argv[1]);

    uint8_t plain_text_secret[BUFFER_SIZE];
    uint8_t wrapped_secret[BUFFER_SIZE + 8]   = {0};
    uint8_t unwrapped_secret[BUFFER_SIZE]      = {0};
    stse_cmd_access_conditions_t wrap_protection   = STSE_CMD_AC_NEVER;
    stse_cmd_access_conditions_t unwrap_protection = STSE_CMD_AC_NEVER;
    PLAT_UI8 wrap_cmd_encryption_flag   = 0;
    PLAT_UI8 unwrap_rsp_encryption_flag = 0;

    apps_terminal_init(115200);

    printf("----------------------------------------------------------------------------------------------------------------");
    printf("\n\r-                                STSAFE-A120 key wrapping Example                                             -");
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

    /* Check access conditions */
    stsafea_perso_info_get_cmd_AC(&stse_handler.perso_info, STSAFEA_CMD_WRAP_LOCAL_ENVELOPE, &wrap_protection);
    stsafea_perso_info_get_cmd_AC(&stse_handler.perso_info, STSAFEA_CMD_UNWRAP_LOCAL_ENVELOPE, &unwrap_protection);
    stsafea_perso_info_get_cmd_encrypt_flag(&stse_handler.perso_info, STSAFEA_CMD_WRAP_LOCAL_ENVELOPE, &wrap_cmd_encryption_flag);
    stsafea_perso_info_get_rsp_encrypt_flag(&stse_handler.perso_info, STSAFEA_CMD_UNWRAP_LOCAL_ENVELOPE, &unwrap_rsp_encryption_flag);

    if (wrap_protection == 0 || unwrap_protection == 0 ||
        wrap_cmd_encryption_flag == 0 || unwrap_rsp_encryption_flag == 0) {
        printf(PRINT_CYAN "\n\n\r"
               "- WARNING: Command access conditions not configured.\n\r"
               "- To avoid secret leakage, run 02_Command_AC_provisioning first.\n\r"
               PRINT_RESET);
    }

    /* Provision a wrap/unwrap key in slot 0 (SPL05 only) */
    stse_ret = stsafea_generate_wrap_unwrap_key(&stse_handler, 0, STSE_AES_128_KT);
    if (stse_ret != STSE_OK && stse_ret != STSE_ACCESS_CONDITION_NOT_SATISFIED) {
        printf(PRINT_RED "\n\r - stsafea_generate_wrap_unwrap_key ERROR : 0x%04X", stse_ret);
        apps_process_error(stse_ret);
    } else if (stse_ret != STSE_ACCESS_CONDITION_NOT_SATISFIED) {
        printf("\n\r - New AES-128 wrap/unwrap key generated in slot 0");
    }

    /* Provision plain text buffer */
    for (uint16_t k = 0; k < BUFFER_SIZE; k++)
        plain_text_secret[k] = (uint8_t)k;

    printf("\n\r - Plain-text buffer to be wrapped:\n\r");
    apps_print_hex_buffer(plain_text_secret, BUFFER_SIZE);

    /* Open host session for protected exchanges */
    stsafea_session_clear_context(&host_session_handler);
    stse_ret = stsafea_open_host_session(&stse_handler, &host_session_handler,
                                          (uint8_t *)host_keys.host_mac_key,
                                          (uint8_t *)host_keys.host_cipher_key);
    if (stse_ret != STSE_OK) {
        printf(PRINT_RED "\n\r - stsafea_open_host_session ERROR : 0x%04X", stse_ret);
        if (stse_ret == STSE_SERVICE_SESSION_ERROR)
            printf("\n\r - Host keys not populated");
        apps_process_error(stse_ret);
    }

    /* Wrap payload */
    stse_ret = stsafea_wrap_payload(&stse_handler, 0,
                                     plain_text_secret, BUFFER_SIZE,
                                     wrapped_secret,    BUFFER_SIZE + 8);
    if (stse_ret != STSE_OK) {
        printf(PRINT_RED "\n\n\r - stsafea_wrap_payload ERROR : 0x%04X", stse_ret);
        apps_process_error(stse_ret);
    } else {
        printf("\n\n\r - Wrapped buffer:\n\r");
        apps_print_hex_buffer(wrapped_secret, BUFFER_SIZE + 8);
    }

    /* Un-wrap payload */
    stse_ret = stsafea_unwrap_payload(&stse_handler, 0,
                                       wrapped_secret,   BUFFER_SIZE + 8,
                                       unwrapped_secret, BUFFER_SIZE);
    if (stse_ret != STSE_OK) {
        printf(PRINT_RED "\n\n\r - stsafea_unwrap_payload ERROR : 0x%04X", stse_ret);
    } else {
        printf("\n\n\r - Un-wrapped buffer:\n\r");
        apps_print_hex_buffer(unwrapped_secret, BUFFER_SIZE);
    }

    stsafea_close_host_session(&host_session_handler);

    if (apps_compare_buffers(plain_text_secret, unwrapped_secret, BUFFER_SIZE)) {
        printf(PRINT_RED "\n\n\r ## WRAP/UNWRAP COMPARE ERROR!\n\r" PRINT_RESET);
        return 1;
    }
    printf(PRINT_RESET "\n\r\n\r*#*# STMICROELECTRONICS #*#*\n\r");
    printf(PRINT_GREEN "\n\n\r - Key wrapping : SUCCESS\n\r" PRINT_RESET);
    return 0;
}
