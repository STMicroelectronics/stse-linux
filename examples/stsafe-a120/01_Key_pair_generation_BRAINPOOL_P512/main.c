/**
 ******************************************************************************
 * @file    main.c
 * @brief   STSAFE-A120 Brainpool P-512 key pair generation — Linux/MPU port
 ******************************************************************************
 *           COPYRIGHT 2022 STMicroelectronics
 ******************************************************************************
 * Usage:  ./01_Key_pair_generation_BRAINPOOL_P512 [busID]  (default busID=1)
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
    printf("\n\r-                          STSAFE-A120 Brainpool P-512 key pair generation                                    -");
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

    uint8_t public_key[stse_ecc_info_table[STSE_ECC_KT_BP_P_512].public_key_size];
    stse_ret = stse_generate_ecc_key_pair(&stse_handler, 1,
                                           STSE_ECC_KT_BP_P_512, 255,
                                           public_key);
    if (stse_ret != STSE_OK) {
        printf(PRINT_RED "\n\n\r ## stse_generate_ecc_key_pair : 0x%04X", stse_ret);
        apps_process_error(stse_ret);
    }
    printf("\n\n\r - ECC key pair (Brainpool P-512) generated in slot 1");
    printf("\n\r\t o public key:\n\r");
    apps_print_hex_buffer(public_key, sizeof(public_key));

    uint8_t hash[stse_ecc_info_table[STSE_ECC_KT_BP_P_512].min_signature_message_size];
    apps_randomize_buffer(hash, sizeof(hash));
    printf("\n\n\r - Hash:\n\r");
    apps_print_hex_buffer(hash, sizeof(hash));

    uint8_t signature[stse_ecc_info_table[STSE_ECC_KT_BP_P_512].signature_size];
    stse_ret = stse_ecc_generate_signature(&stse_handler, 1,
                                            STSE_ECC_KT_BP_P_512,
                                            hash, sizeof(hash), signature);
    if (stse_ret != STSE_OK) {
        printf(PRINT_RED "\n\n\r ## stse_ecc_generate_signature : 0x%04X", stse_ret);
        apps_process_error(stse_ret);
    }
    printf("\n\n\r - Signature:\n\r");
    apps_print_hex_buffer(signature, sizeof(signature));

    uint8_t verification_status = 0;
    stse_ret = stse_ecc_verify_signature(&stse_handler, STSE_ECC_KT_BP_P_512,
                                          public_key, signature,
                                          hash, sizeof(hash), 0,
                                          &verification_status);
    if (stse_ret != STSE_OK || verification_status != 1) {
        printf(PRINT_RED "\n\n\r - Brainpool P-512 verify : FAILED\n\r" PRINT_RESET);
        return 1;
    }
    printf(PRINT_GREEN "\n\n\r - Brainpool P-512 sign+verify : SUCCESS\n\r" PRINT_RESET);
    return 0;
}
