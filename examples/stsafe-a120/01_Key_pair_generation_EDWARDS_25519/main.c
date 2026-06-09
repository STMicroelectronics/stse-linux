/**
 ******************************************************************************
 * @file    main.c
 * @brief   STSAFE-A120 Edwards 25519 key pair generation — Linux/MPU port
 ******************************************************************************
 *           COPYRIGHT 2022 STMicroelectronics
 ******************************************************************************
 * Usage:  ./01_Key_pair_generation_EDWARDS_25519 [busID]   (default busID=1)
 *
 * Note: Edwards 25519 (EdDSA) signs the message directly, not a hash.
 *       The hash is embedded in the EdDSA algorithm on the STSAFE-A120.
 ******************************************************************************
 */

#include "Apps_utils.h"

int main(int argc, char *argv[]) {
    stse_ReturnCode_t stse_ret = STSE_API_INVALID_PARAMETER;
    stse_Handler_t    stse_handler;
    uint8_t           busID = 1;

    if (argc > 1) busID = (uint8_t)atoi(argv[1]);

    apps_terminal_init(115200);

    printf("----------------------------------------------------------------------------------------------------------------");
    printf("\n\r-                          STSAFE-A120 Edwards 25519 key pair generation                                      -");
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

    uint8_t public_key[stse_ecc_info_table[STSE_ECC_KT_ED25519].public_key_size];
    stse_ret = stse_generate_ecc_key_pair(&stse_handler, 1,
                                           STSE_ECC_KT_ED25519, 255,
                                           public_key);
    if (stse_ret != STSE_OK) {
        printf(PRINT_RED "\n\n\r ## stse_generate_ecc_key_pair : 0x%04X", stse_ret);
        apps_process_error(stse_ret);
    }
    printf("\n\n\r - Ed25519 key pair generated in slot 1");
    printf("\n\r\t o public key:\n\r");
    apps_print_hex_buffer(public_key, sizeof(public_key));

    /* For EdDSA the message is signed directly (min_signature_message_size bytes) */
    uint8_t message[stse_ecc_info_table[STSE_ECC_KT_ED25519].min_signature_message_size];
    apps_randomize_buffer(message, sizeof(message));
    printf("\n\n\r - Message to sign:\n\r");
    apps_print_hex_buffer(message, sizeof(message));

    uint8_t signature[stse_ecc_info_table[STSE_ECC_KT_ED25519].signature_size];
    stse_ret = stse_ecc_generate_signature(&stse_handler, 1,
                                            STSE_ECC_KT_ED25519,
                                            message, sizeof(message), signature);
    if (stse_ret != STSE_OK) {
        printf(PRINT_RED "\n\n\r ## stse_ecc_generate_signature : 0x%04X", stse_ret);
        apps_process_error(stse_ret);
    }
    printf("\n\n\r - Ed25519 Signature:\n\r");
    apps_print_hex_buffer(signature, sizeof(signature));

    uint8_t verification_status = 0;
    stse_ret = stse_ecc_verify_signature(&stse_handler, STSE_ECC_KT_ED25519,
                                          public_key, signature,
                                          message, sizeof(message), 0,
                                          &verification_status);
    if (stse_ret != STSE_OK || verification_status != 1) {
        printf(PRINT_RED "\n\n\r - Ed25519 verify : FAILED\n\r" PRINT_RESET);
        return 1;
    }
    printf(PRINT_GREEN "\n\n\r - Ed25519 sign+verify : SUCCESS\n\r" PRINT_RESET);
    return 0;
}
