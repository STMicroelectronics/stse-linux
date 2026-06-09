/**
 ******************************************************************************
 * @file    main.c
 * @brief   STSAFE-A120 NIST P-256 key pair generation — Linux/MPU port
 ******************************************************************************
 *           COPYRIGHT 2022 STMicroelectronics
 * Licensed under the terms in the LICENSE file at the root of this component.
 ******************************************************************************
 * Usage:  ./01_Key_pair_generation_NIST_P256 [busID]   (default busID = 1)
 ******************************************************************************
 */

#include "Apps_utils.h"

#define HASH_SIZE(x) (x - x % 16)

int main(int argc, char *argv[]) {
    stse_ReturnCode_t stse_ret = STSE_API_INVALID_PARAMETER;
    stse_Handler_t    stse_handler;
    uint8_t           busID = 1;

    if (argc > 1) busID = (uint8_t)atoi(argv[1]);

    apps_terminal_init(115200);

    printf("----------------------------------------------------------------------------------------------------------------");
    printf("\n\r-                             STSAFE-A120 NIST-P256 key pair generation                                       -");
    printf("\n\r----------------------------------------------------------------------------------------------------------------");
    printf("\n\r- Generates a NIST-P256 key pair in slot 1, signs a hash, then verifies.                                      -");
    printf("\n\r----------------------------------------------------------------------------------------------------------------");

    stse_ret = stse_set_default_handler_value(&stse_handler);
    if (stse_ret != STSE_OK) {
        printf(PRINT_RED "\n\r ## stse_set_default_handler_value ERROR : 0x%04X\n\r", stse_ret);
        apps_process_error(stse_ret);
    }

    stse_handler.device_type  = STSAFE_A120;
    stse_handler.io.busID     = busID;
    stse_handler.io.BusSpeed  = 400;

    printf("\n\r - Initialize target STSAFE-A120 on /dev/i2c-%u", (unsigned)busID);
    stse_ret = stse_init(&stse_handler);
    if (stse_ret != STSE_OK) {
        printf(PRINT_RED "\n\r ## stse_init ERROR : 0x%04X\n\r", stse_ret);
        apps_process_error(stse_ret);
    }

    /* Generate NIST-P256 key pair in slot 1 */
    uint8_t slot_1_public_key[stse_ecc_info_table[STSE_ECC_KT_NIST_P_256].public_key_size];
    stse_ret = stse_generate_ecc_key_pair(&stse_handler, 1,
                                           STSE_ECC_KT_NIST_P_256, 255,
                                           slot_1_public_key);
    if (stse_ret != STSE_OK) {
        printf(PRINT_RED "\n\n\r ## stse_generate_ecc_key_pair : 0x%04X", stse_ret);
        apps_process_error(stse_ret);
    }
    printf("\n\n\r - STSAFE-A120 generate ECC key pair : success");
    printf("\n\r\t o public key:\n\r");
    apps_print_hex_buffer(slot_1_public_key, sizeof(slot_1_public_key));

    /* Generate hash to sign */
    uint8_t hash[HASH_SIZE(stse_ecc_info_table[STSE_ECC_KT_NIST_P_256].min_signature_message_size)];
    printf("\n\n\r - Plain-text hash:\n\r");
    apps_randomize_buffer(hash, sizeof(hash));
    apps_print_hex_buffer(hash, sizeof(hash));

    /* Generate ECDSA signature */
    uint8_t signature[stse_ecc_info_table[STSE_ECC_KT_NIST_P_256].signature_size];
    stse_ret = stse_ecc_generate_signature(&stse_handler, 1,
                                            STSE_ECC_KT_NIST_P_256,
                                            hash, sizeof(hash), signature);
    if (stse_ret != STSE_OK) {
        printf(PRINT_RED "\n\n\r ## stse_ecc_generate_signature : 0x%04X", stse_ret);
        apps_process_error(stse_ret);
    }
    printf("\n\n\r - STSAFE-A120 generate signature : success");
    printf("\n\r\t o signature:\n\r");
    apps_print_hex_buffer(signature, sizeof(signature));

    /* Verify signature */
    uint8_t verification_status = 0;
    stse_ret = stse_ecc_verify_signature(&stse_handler, STSE_ECC_KT_NIST_P_256,
                                          slot_1_public_key, signature,
                                          hash, sizeof(hash), 0,
                                          &verification_status);
    if (stse_ret != STSE_OK) {
        printf(PRINT_RED "\n\n\r ## stse_ecc_verify_signature : 0x%04X", stse_ret);
        apps_process_error(stse_ret);
    }
    if (verification_status != 1) {
        printf(PRINT_RED "\n\n\r - STSAFE-A120 verify signature : FAILED\n\r" PRINT_RESET);
        return 1;
    }

    printf(PRINT_GREEN "\n\n\r - STSAFE-A120 verify signature : SUCCESS\n\r" PRINT_RESET);
    return 0;
}
