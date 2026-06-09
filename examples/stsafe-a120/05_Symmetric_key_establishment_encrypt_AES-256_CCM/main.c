/**
 ******************************************************************************
 * @file    main.c
 * @brief   STSAFE-A120 Symmetric key establishment — AES-256 CCM — Linux port
 ******************************************************************************
 *           COPYRIGHT 2022 STMicroelectronics
 ******************************************************************************
 * Usage:  ./05_Symmetric_key_establishment_encrypt_AES-256_CCM [busID]
 *
 * Prerequisites: Run 04_Symmetric_key_provisioning_control_fields first.
 ******************************************************************************
 */

#include "Apps_utils.h"

#define AES_256_KEY_SIZE    32
#define PLAIN_DATA_SIZE     32
#define CCM_NONCE_SIZE      13
#define CCM_TAG_SIZE        16
#define CCM_AAD_SIZE         8

int main(int argc, char *argv[]) {
    stse_ReturnCode_t stse_ret = STSE_API_INVALID_PARAMETER;
    stse_Handler_t    stse_handler;
    stse_session_t    host_session_handler;
    uint8_t           busID = 1;

    if (argc > 1) busID = (uint8_t)atoi(argv[1]);

    PLAT_UI16 symmetric_key_slot = 0;
    uint8_t pAES_CCM_Key[AES_256_KEY_SIZE];
    uint8_t plain_data[PLAIN_DATA_SIZE];
    uint8_t encrypted_data[PLAIN_DATA_SIZE];
    uint8_t decrypted_data[PLAIN_DATA_SIZE];
    uint8_t nonce[CCM_NONCE_SIZE];
    uint8_t aad[CCM_AAD_SIZE];
    uint8_t tag[CCM_TAG_SIZE];
    uint8_t decrypt_verify_result = 0;

    const stsafea_aes_128_host_keys_t host_keys = {
        .host_mac_key    = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                            0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
        .host_cipher_key = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}
    };

    stsafea_generic_key_information_t aes_ccm_256_key_info = {
        .info_length       = STSAFEA_KEY_INFO_LENGTH_CCM,
        .lock_indicator    = STSAFEA_SYMMETRIC_KEY_LOCK_INDICATOR_UNLOCKED,
        .slot_number       = 0,   /* overwritten below */
        .type              = STSAFEA_SYMMETRIC_KEY_TYPE_AES_256,
        .mode_of_operation = STSAFEA_KEY_OPERATION_MODE_CCM,
        .usage             = { .encryption = 1, .decryption = 1 },
        .CCM = { .auth_tag_length = CCM_TAG_SIZE, .counter_presence = 0, .counter_offset_in_nonce = 0 }
    };

    apps_terminal_init(115200);

    printf("----------------------------------------------------------------------------------------------------------------");
    printf("\n\r-               STSAFE-A120 Symmetric key establishment + AES-256-CCM example                                -");
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

    /* Establish AES-256-CCM key */
    aes_ccm_256_key_info.slot_number = (PLAT_UI8)symmetric_key_slot;
    stse_ret = stse_establish_symmetric_key(&stse_handler, STSE_ECC_KT_NIST_P_256,
                                             1,
                                             &aes_ccm_256_key_info, pAES_CCM_Key);
    printf(PRINT_RESET "\n\n\r - stse_establish_symmetric_key: ");
    if (stse_ret != STSE_OK) {
        printf(PRINT_RED "ERROR 0x%04X" PRINT_RESET, stse_ret);
        apps_process_error(stse_ret);
    } else {
        printf(PRINT_GREEN "OK" PRINT_RESET);
        printf("\n\r - Established key (local copy):\n\r");
        apps_print_hex_buffer(pAES_CCM_Key, AES_256_KEY_SIZE);
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

    /* Prepare data */
    apps_randomize_buffer(plain_data, sizeof(plain_data));
    apps_randomize_buffer(nonce,      sizeof(nonce));
    apps_randomize_buffer(aad,        sizeof(aad));

    printf("\n\n\r - Plain data:\n\r");
    apps_print_hex_buffer(plain_data, sizeof(plain_data));
    printf("\n\r - Nonce:\n\r");
    apps_print_hex_buffer(nonce, sizeof(nonce));
    printf("\n\r - AAD:\n\r");
    apps_print_hex_buffer(aad, sizeof(aad));

    /* Encrypt */
    stse_ret = stse_aes_ccm_encrypt(&stse_handler, (PLAT_UI8)symmetric_key_slot,
                                     CCM_TAG_SIZE,
                                     nonce,
                                     CCM_AAD_SIZE,  aad,
                                     PLAIN_DATA_SIZE, plain_data,
                                     encrypted_data, tag,
                                     0, NULL);
    printf("\n\n\r - stse_aes_ccm_encrypt: ");
    if (stse_ret != STSE_OK) {
        printf(PRINT_RED "ERROR 0x%04X" PRINT_RESET, stse_ret);
        apps_process_error(stse_ret);
    } else {
        printf(PRINT_GREEN "OK" PRINT_RESET);
        printf("\n\r - Encrypted data:\n\r");
        apps_print_hex_buffer(encrypted_data, sizeof(encrypted_data));
        printf("\n\r - Tag:\n\r");
        apps_print_hex_buffer(tag, sizeof(tag));
    }

    /* Decrypt */
    stse_ret = stse_aes_ccm_decrypt(&stse_handler, (PLAT_UI8)symmetric_key_slot,
                                     CCM_TAG_SIZE,
                                     nonce,
                                     CCM_AAD_SIZE,  aad,
                                     PLAIN_DATA_SIZE, encrypted_data,
                                     tag, &decrypt_verify_result,
                                     decrypted_data);
    printf("\n\n\r - stse_aes_ccm_decrypt: ");
    if (stse_ret != STSE_OK || decrypt_verify_result != 1) {
        printf(PRINT_RED "FAILED (0x%04X, result=%u)\n\r" PRINT_RESET, stse_ret, decrypt_verify_result);
        stsafea_close_host_session(&host_session_handler);
        return 1;
    }
    printf(PRINT_GREEN "OK\n\r" PRINT_RESET);
    printf("\n\r - Decrypted data:\n\r");
    apps_print_hex_buffer(decrypted_data, sizeof(decrypted_data));

    stsafea_close_host_session(&host_session_handler);

    if (apps_compare_buffers(plain_data, decrypted_data, PLAIN_DATA_SIZE)) {
        printf(PRINT_RED "\n\n\r - DECRYPT DATA COMPARE FAILED!\n\r" PRINT_RESET);
        return 1;
    }
    printf(PRINT_GREEN "\n\n\r - AES-256-CCM establish+encrypt+decrypt : SUCCESS\n\r" PRINT_RESET);
    return 0;
}
