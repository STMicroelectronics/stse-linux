/**
 ******************************************************************************
 * @file    main.c
 * @brief   STSAFE-A120 Echo loop example — Linux/MPU port
 ******************************************************************************
 *           COPYRIGHT 2022 STMicroelectronics
 * Licensed under the terms in the LICENSE file at the root of this component.
 ******************************************************************************
 * Usage:  ./01_Echo_loop [busID]   (default busID = 1 → /dev/i2c-1)
 ******************************************************************************
 */

#include "Apps_utils.h"

int main(int argc, char *argv[]) {
    stse_ReturnCode_t stse_ret = STSE_API_INVALID_PARAMETER;
    stse_Handler_t    stse_handler;
    uint16_t          message_length = 0;
    uint8_t           busID = 1;

    if (argc > 1) busID = (uint8_t)atoi(argv[1]);

    apps_terminal_init(115200);

    printf("----------------------------------------------------------------------------------------------------------------");
    printf("\n\r-                                   STSAFE-A Echo loop example                                                -");
    printf("\n\r----------------------------------------------------------------------------------------------------------------");

    stse_ret = stse_set_default_handler_value(&stse_handler);
    if (stse_ret != STSE_OK) {
        printf("\n\r ## stse_set_default_handler_value ERROR : 0x%04X\n\r", stse_ret);
        apps_process_error(stse_ret);
    }

    stse_handler.device_type  = STSAFE_A120;
    stse_handler.io.busID     = busID;
    stse_handler.io.BusSpeed  = 400;

    printf("\n\r - Initialize target STSAFE-A120 on /dev/i2c-%u", (unsigned)busID);
    stse_ret = stse_init(&stse_handler);
    if (stse_ret != STSE_OK) {
        printf("\n\r ## stse_init ERROR : 0x%04X\n\r", stse_ret);
        apps_process_error(stse_ret);
    }

    for (int iteration = 0; iteration < 1000; iteration++) {
        /* Generate random message length (1..500) */
        message_length = (uint16_t)(apps_generate_random_number() & 0x1FF);
        if ((message_length > 500) || (message_length == 0))
            message_length = 1;

        uint8_t message[500]        = {0};
        uint8_t echoed_message[500] = {0};

        apps_randomize_buffer(message, message_length);

        printf("\n\r ## Message (%d bytes):\n\r", message_length);
        apps_print_hex_buffer(message, message_length);

        stse_ret = stse_device_echo(&stse_handler, message, echoed_message, message_length);
        if (stse_ret != STSE_OK) {
            printf("\n\r## stse_device_echo ERROR : 0x%04X\n\r", stse_ret);
            apps_process_error(stse_ret);
        }

        if (apps_compare_buffers(message, echoed_message, message_length)) {
            printf("\n\n \r ## ECHO MESSAGES COMPARE ERROR (%d)", message_length);
            printf("\n\r\t Echoed Message:\n\r");
            apps_print_hex_buffer(echoed_message, message_length);
            apps_process_error(1);
        }

        printf("\n\n \r ## Echoed Message:\n\r");
        apps_print_hex_buffer(echoed_message, message_length);
        printf("\n\r\n\r*#*# STMICROELECTRONICS #*#*\n\r");

        apps_delay_ms(1000);
    }

    printf("\n\r Echo loop completed successfully.\n\r");
    return 0;
}
