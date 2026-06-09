/**
 ******************************************************************************
 * @file    main.c
 * @brief   STSAFE-A120 Hash example — Linux/MPU port
 ******************************************************************************
 *           COPYRIGHT 2022 STMicroelectronics
 * Licensed under the terms in the LICENSE file at the root of this component.
 ******************************************************************************
 * Usage:  ./01_Hash [busID]   (default busID = 1 → /dev/i2c-1)
 ******************************************************************************
 */

#include "Apps_utils.h"

int main(int argc, char *argv[]) {
    stse_ReturnCode_t stse_ret = STSE_API_INVALID_PARAMETER;
    stse_Handler_t    stse_handler;
    uint8_t           busID = 1;

    if (argc > 1) busID = (uint8_t)atoi(argv[1]);

    PLAT_UI16 message_length = 128;
    PLAT_UI8  message_to_hash[128];

    stse_hash_algorithm_t hash_algo  = STSE_SHA_256;
    PLAT_UI16             hash_length = stsafea_hash_info_table[hash_algo].length;
    PLAT_UI8              hash_platform[hash_length];
    PLAT_UI8              hash_stsafea[hash_length];

    apps_terminal_init(115200);

    printf("----------------------------------------------------------------------------------------------------------------");
    printf("\n\r-                                      STSAFE-A120 hash commands example                                      -");
    printf("\n\r----------------------------------------------------------------------------------------------------------------");
    printf("\n\r- This example computes SHA-256 both on the host (via platform crypto) and on STSAFE-A120,                    -");
    printf("\n\r- then compares the two results to verify correctness.                                                         -");
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

    printf("\n\n\r - Message buffer to hash:\n\r");
    apps_randomize_buffer(message_to_hash, message_length);
    apps_print_hex_buffer(message_to_hash, message_length);

    /* Hash using platform OpenSSL */
    stse_ret = stse_platform_hash_compute(hash_algo, message_to_hash, message_length,
                                          hash_platform, &hash_length);
    if (stse_ret != STSE_OK) {
        printf(PRINT_RED "\n\n\r - stse_platform_hash_compute ERROR : 0x%04X", stse_ret);
    } else {
        printf("\n\n\r - stse_platform_hash_compute (SHA-256):\n\r");
        apps_print_hex_buffer(hash_platform, hash_length);
    }

    /* Hash using STSAFE-A120 on-chip */
    stse_ret = stse_compute_hash(&stse_handler, hash_algo, message_to_hash,
                                  message_length, hash_stsafea, &hash_length);
    if (stse_ret != STSE_OK) {
        printf(PRINT_RED "\n\n\r - stse_compute_hash ERROR : 0x%04X", stse_ret);
    } else {
        printf("\n\n\r - stse_compute_hash (STSAFE-A120):\n\r");
        apps_print_hex_buffer(hash_stsafea, hash_length);
    }

    if (memcmp(hash_platform, hash_stsafea, hash_length)) {
        printf(PRINT_RED "\n\n\r - memcmp ERROR: hashes differ!\n\r" PRINT_RESET);
        return 1;
    }

    printf(PRINT_GREEN "\n\n\r - HASH SUCCESS: platform and STSAFE-A120 hashes match.\n\r" PRINT_RESET);
    return 0;
}
