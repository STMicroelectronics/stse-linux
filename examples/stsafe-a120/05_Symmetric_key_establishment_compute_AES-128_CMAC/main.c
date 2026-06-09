/**
 ******************************************************************************
 * @file    main.c
 * @brief   STSAFE-A120 Symmetric key establishment — AES-128 CMAC — Linux port
 ******************************************************************************
 *           COPYRIGHT 2022 STMicroelectronics
 ******************************************************************************
 * Usage:  ./05_Symmetric_key_establishment_compute_AES-128_CMAC [busID]
 *
 * Prerequisites: Run 04_Symmetric_key_provisioning_control_fields first.
 ******************************************************************************
 */

#include "Apps_utils.h"

#define AES_128_CMAC_KEY_SIZE 16
#define CMAC_DATA_SIZE        64
#define CMAC_TAG_SIZE          8   /* min MAC length */

int main(int argc, char *argv[]) {
    stse_ReturnCode_t stse_ret = STSE_API_INVALID_PARAMETER;
    stse_Handler_t    stse_handler;
    stse_session_t    host_session_handler;
    uint8_t           busID = 1;

    if (argc > 1) busID = (uint8_t)atoi(argv[1]);

    PLAT_UI16 symmetric_key_slot = 0;
    uint8_t pAES_CMAC_Key[AES_128_CMAC_KEY_SIZE];
    uint8_t data_to_cmac[CMAC_DATA_SIZE];
    uint8_t cmac_tag[CMAC_TAG_SIZE];
    uint8_t cmac_verify_result = 0;

    const stsafea_aes_128_host_keys_t host_keys = {
        .host_mac_key    = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                            0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
        .host_cipher_key = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}
    };

    stsafea_generic_key_information_t aes_cmac_128_key_info = {
        .info_length       = STSAFEA_KEY_INFO_LENGTH_CMAC,
        .lock_indicator    = STSAFEA_SYMMETRIC_KEY_LOCK_INDICATOR_UNLOCKED,
        .slot_number       = 0,   /* overwritten below */
        .type              = STSAFEA_SYMMETRIC_KEY_TYPE_AES_128,
        .mode_of_operation = STSAFEA_KEY_OPERATION_MODE_CMAC,
        .usage             = { .mac_generation = 1, .mac_verification = 1 },
        .CMAC = { .min_MAC_length = CMAC_TAG_SIZE }
    };

    apps_terminal_init(115200);

    printf("----------------------------------------------------------------------------------------------------------------");
    printf("\n\r-               STSAFE-A120 Symmetric key establishment + AES-128-CMAC example                               -");
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

    printf("\n\n\r");
    apps_print_symmetric_key_table_info(&stse_handler);

    printf(PRINT_BOLD PRINT_ITALIC "\n\n\r==> Enter symmetric key slot: ");
    apps_terminal_read_unsigned_integer(&symmetric_key_slot);

    /* Generate and establish AES-128-CMAC key */
    aes_cmac_128_key_info.slot_number = (PLAT_UI8)symmetric_key_slot;
    stse_ret = stse_establish_symmetric_key(&stse_handler, STSE_ECC_KT_NIST_P_256,
                                             1,
                                             &aes_cmac_128_key_info, pAES_CMAC_Key);
    printf(PRINT_RESET "\n\n\r - stse_establish_symmetric_key: ");
    if (stse_ret != STSE_OK) {
        printf(PRINT_RED "ERROR 0x%04X" PRINT_RESET, stse_ret);
        apps_process_error(stse_ret);
    } else {
        printf(PRINT_GREEN "OK" PRINT_RESET);
        printf("\n\r - Established key (local copy):\n\r");
        apps_print_hex_buffer(pAES_CMAC_Key, AES_128_CMAC_KEY_SIZE);
    }

    /* Open host session */
    stsafea_session_clear_context(&host_session_handler);
    stse_ret = stsafea_open_host_session(&stse_handler, &host_session_handler,
                                          (uint8_t *)host_keys.host_mac_key,
                                          (uint8_t *)host_keys.host_cipher_key);
    if (stse_ret != STSE_OK) {
        printf(PRINT_RED "\n\r - stsafea_open_host_session ERROR : 0x%04X\n\r", stse_ret);
        apps_process_error(stse_ret);
    }

    /* Generate CMAC */
    apps_randomize_buffer(data_to_cmac, sizeof(data_to_cmac));
    printf("\n\n\r - Data:\n\r");
    apps_print_hex_buffer(data_to_cmac, sizeof(data_to_cmac));

    stse_ret = stse_cmac_hmac_compute(&stse_handler, (PLAT_UI8)symmetric_key_slot,
                                       data_to_cmac, (PLAT_UI8)sizeof(data_to_cmac),
                                       cmac_tag, CMAC_TAG_SIZE);
    printf("\n\n\r - stse_cmac_hmac_compute: ");
    if (stse_ret != STSE_OK) {
        printf(PRINT_RED "ERROR 0x%04X" PRINT_RESET, stse_ret);
        apps_process_error(stse_ret);
    } else {
        printf(PRINT_GREEN "OK" PRINT_RESET);
        printf("\n\r - CMAC Tag:\n\r");
        apps_print_hex_buffer(cmac_tag, sizeof(cmac_tag));
    }

    /* Verify CMAC */
    stse_ret = stse_cmac_hmac_verify(&stse_handler, (PLAT_UI8)symmetric_key_slot,
                                      cmac_tag, CMAC_TAG_SIZE,
                                      data_to_cmac, (PLAT_UI8)sizeof(data_to_cmac),
                                      &cmac_verify_result);
    printf("\n\n\r - stse_cmac_hmac_verify: ");
    if (stse_ret != STSE_OK || cmac_verify_result != 1) {
        printf(PRINT_RED "FAILED (0x%04X, result=%u)\n\r" PRINT_RESET, stse_ret, cmac_verify_result);
        stsafea_close_host_session(&host_session_handler);
        return 1;
    }
    printf(PRINT_GREEN "OK\n\r" PRINT_RESET);

    stsafea_close_host_session(&host_session_handler);

    printf(PRINT_GREEN "\n\n\r - AES-128-CMAC establish+compute+verify : SUCCESS\n\r" PRINT_RESET);
    return 0;
}
