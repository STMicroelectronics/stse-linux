/**
 ******************************************************************************
 * @file    main.c
 * @brief   STSAFE-A120 Random number generation example — Linux/MPU port
 ******************************************************************************
 *           COPYRIGHT 2022 STMicroelectronics
 * Licensed under the terms in the LICENSE file at the root of this component.
 ******************************************************************************
 * Usage:  ./01_Random_number [busID]   (default busID = 1 → /dev/i2c-1)
 ******************************************************************************
 */

#include "Apps_utils.h"

int main(int argc, char *argv[]) {
    stse_ReturnCode_t stse_ret = STSE_API_INVALID_PARAMETER;
    stse_Handler_t    stse_handler;
    uint8_t           busID = 1;

    if (argc > 1) busID = (uint8_t)atoi(argv[1]);

    PLAT_UI16 random_size = 64;
    PLAT_UI8  pRandom[64];

    apps_terminal_init(115200);

    printf("----------------------------------------------------------------------------------------------------------------");
    printf("\n\r-                                  STSAFE-A120 Random number generation example                               -");
    printf("\n\r----------------------------------------------------------------------------------------------------------------");
    printf("\n\r- Generates 64 bytes of true random data using the STSAFE-A120 on-chip TRNG                                   -");
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

    stse_ret = stse_generate_random(&stse_handler, pRandom, random_size);
    if (stse_ret != STSE_OK) {
        printf(PRINT_RED "\n\n\r - stse_generate_random ERROR : 0x%04X\n\r" PRINT_RESET, stse_ret);
        apps_process_error(stse_ret);
    }

    printf("\n\n\r - stse_generate_random (%d bytes):\n\r", random_size);
    apps_print_hex_buffer(pRandom, random_size);
    printf("\n\r\n\r" PRINT_GREEN "Random number generation: SUCCESS\n\r" PRINT_RESET);

    return 0;
}
