/**
 ******************************************************************************
 * @file    main.c
 * @brief   STSAFE-A120 Secure data storage zone access — Linux/MPU port
 ******************************************************************************
 *           COPYRIGHT 2022 STMicroelectronics
 ******************************************************************************
 * Usage:  ./01_Secure_data_storage_zone_access [busID]   (default busID = 1)
 *
 * Note: Zone IDs are aligned with STSAFE-A120 SPL05 personalization.
 ******************************************************************************
 */

#include "Apps_utils.h"

#define READ_BUFFER_SIZE 100
#define RANDOM_SIZE      100

int main(int argc, char *argv[]) {
    stse_ReturnCode_t stse_ret = STSE_API_INVALID_PARAMETER;
    stse_Handler_t    stse_handler;
    uint8_t           busID = 1;

    if (argc > 1) busID = (uint8_t)atoi(argv[1]);

    uint8_t readBuffer[READ_BUFFER_SIZE];
    uint8_t random[RANDOM_SIZE];

    apps_terminal_init(115200);

    printf("----------------------------------------------------------------------------------------------------------------");
    printf("\n\r-                            STSAFE-A120 secure data storage zone access example                              -");
    printf("\n\r----------------------------------------------------------------------------------------------------------------");
    printf("\n\r- Queries partition table, reads zone 1, writes random data, then verifies.                                   -");
    printf("\n\r- Zone IDs aligned with STSAFE-A120 SPL05 personalization.                                                   -");
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

    /* Print partition table */
    apps_print_data_partition_record_table(&stse_handler);

    /* Read Zone 1 */
    stse_ret = stse_data_storage_read_data_zone(&stse_handler, 1, 0x0000,
                                                 readBuffer, sizeof(readBuffer),
                                                 4, STSE_NO_PROT);
    if (stse_ret != STSE_OK) {
        printf(PRINT_RED "\n\n\r ### stse_data_storage_read_data_zone : ERROR 0x%04X", stse_ret);
        apps_process_error(stse_ret);
    } else {
        printf("\n\n\r - stse_data_storage_read_data_zone (zone:01, len:%zu):\n\r", sizeof(readBuffer));
        apps_print_hex_buffer(readBuffer, sizeof(readBuffer));
    }

    /* Update Zone 1 with random data */
    stse_ret = stsafea_generate_random(&stse_handler, random, RANDOM_SIZE);
    if (stse_ret != STSE_OK) {
        printf(PRINT_RED "\n\n\r ### stsafea_generate_random : ERROR 0x%04X", stse_ret);
        apps_process_error(stse_ret);
    }
    stse_ret = stse_data_storage_update_data_zone(&stse_handler, 1, 0x0000,
                                                   random, sizeof(random),
                                                   STSE_NON_ATOMIC_ACCESS, STSE_NO_PROT);
    if (stse_ret != STSE_OK) {
        printf(PRINT_RED "\n\n\r ### stse_data_storage_update_data_zone : ERROR 0x%04X", stse_ret);
        apps_process_error(stse_ret);
    } else {
        printf("\n\n\r - stse_data_storage_update_data_zone (zone:01, len:%zu):\n\r", sizeof(random));
        apps_print_hex_buffer(random, sizeof(random));
    }

    /* Read back Zone 1 to verify */
    stse_ret = stse_data_storage_read_data_zone(&stse_handler, 1, 0x0000,
                                                 readBuffer, sizeof(readBuffer),
                                                 4, STSE_NO_PROT);
    if (stse_ret != STSE_OK) {
        printf(PRINT_RED "\n\n\r ### stse_data_storage_read_data_zone (verify) : ERROR 0x%04X", stse_ret);
        apps_process_error(stse_ret);
    } else {
        printf("\n\n\r - Read-back zone 1 (verify):\n\r");
        apps_print_hex_buffer(readBuffer, sizeof(readBuffer));
    }

    if (apps_compare_buffers(random, readBuffer, RANDOM_SIZE)) {
        printf(PRINT_RED "\n\n\r - DATA COMPARE ERROR!\n\r" PRINT_RESET);
        return 1;
    }
    printf(PRINT_GREEN "\n\n\r - Zone access test : SUCCESS\n\r" PRINT_RESET);
    return 0;
}
