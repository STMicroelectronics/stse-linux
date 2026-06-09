/**
 ******************************************************************************
 * @file    main.c
 * @brief   STSAFE-A120 Secure data storage with counter — Linux/MPU port
 ******************************************************************************
 *           COPYRIGHT 2022 STMicroelectronics
 ******************************************************************************
 * Usage:  ./01_Secure_data_storage_counter_access [busID]   (default busID=1)
 *
 * Note: Zone IDs are aligned with STSAFE-A120 SPL05 personalization.
 ******************************************************************************
 */

#include "Apps_utils.h"

#define READ_BUFFER_SIZE 16
#define RANDOM_SIZE      16

int main(int argc, char *argv[]) {
    stse_ReturnCode_t stse_ret = STSE_API_INVALID_PARAMETER;
    stse_Handler_t    stse_handler;
    uint8_t           busID = 1;

    if (argc > 1) busID = (uint8_t)atoi(argv[1]);

    uint8_t  readBuffer[READ_BUFFER_SIZE];
    uint8_t  random[RANDOM_SIZE];
    uint32_t counter_value;
    uint32_t new_counter_value;

    apps_terminal_init(115200);

    printf("----------------------------------------------------------------------------------------------------------------");
    printf("\n\r-                            STSAFE-A120 secure data storage counter access example                          -");
    printf("\n\r----------------------------------------------------------------------------------------------------------------");
    printf("\n\r- Queries partition table, reads zone 5 (counter), decrements counter, verifies.                              -");
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

    apps_print_data_partition_record_table(&stse_handler);

    /* Read zone 5 (counter zone) */
    stse_ret = stse_data_storage_read_counter_zone(&stse_handler, 5, 0x0000,
                                                    readBuffer, sizeof(readBuffer),
                                                    4, &counter_value, STSE_NO_PROT);
    if (stse_ret != STSE_OK) {
        printf(PRINT_RED "\n\n\r ### stse_data_storage_read_counter_zone : ERROR 0x%04X", stse_ret);
        apps_process_error(stse_ret);
    } else {
        printf("\n\n\r - stse_data_storage_read_counter_zone (zone:05, len:%zu)\n\r", sizeof(readBuffer));
        printf("\n\r\t o Associated Data:\n\r");
        apps_print_hex_buffer(readBuffer, sizeof(readBuffer));
        printf("\n\r\t o Counter Value : %u", counter_value);
    }

    /* Decrement zone 5 counter */
    apps_randomize_buffer(random, sizeof(random));
    stse_ret = stse_data_storage_decrement_counter_zone(&stse_handler, 5,
                                                         1, 0x0000,
                                                         random, sizeof(random),
                                                         &new_counter_value,
                                                         STSE_NO_PROT);
    if (stse_ret != STSE_OK) {
        printf(PRINT_RED "\n\n\r ### stse_data_storage_decrement_counter_zone : ERROR 0x%04X", stse_ret);
        apps_process_error(stse_ret);
    } else {
        printf("\n\n\r - stse_data_storage_decrement_counter_zone (zone:05, len:%zu)\n\r", sizeof(random));
        printf("\n\r\t o New Associated Data:\n\r");
        apps_print_hex_buffer(random, sizeof(random));
        printf("\n\r\t o New Counter Value : %u", new_counter_value);
    }

    /* Read again to verify */
    stse_ret = stse_data_storage_read_counter_zone(&stse_handler, 5, 0x0000,
                                                    readBuffer, sizeof(readBuffer),
                                                    4, &counter_value, STSE_NO_PROT);
    if (stse_ret != STSE_OK) {
        printf(PRINT_RED "\n\n\r ### stse_data_storage_read_counter_zone : ERROR 0x%04X", stse_ret);
        apps_process_error(stse_ret);
    } else {
        printf("\n\n\r - stse_data_storage_read_counter_zone (verify) (zone:05, len:%zu)\n\r", sizeof(readBuffer));
        printf("\n\r\t o Associated Data:\n\r");
        apps_print_hex_buffer(readBuffer, sizeof(readBuffer));
        printf("\n\r\t o Counter Value : %u\n\r", counter_value);
    }

    printf(PRINT_GREEN "\n\n\r - Counter zone access test : SUCCESS\n\r" PRINT_RESET);
    return 0;
}
