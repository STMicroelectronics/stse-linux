/**
 ******************************************************************************
 * @file    main.c
 * @brief   STSAFE-A120 Symmetric key slot control fields — Linux/MPU port
 ******************************************************************************
 *           COPYRIGHT 2022 STMicroelectronics
 ******************************************************************************
 * Usage:  ./04_Symmetric_key_provisioning_control_fields [busID]  (default=1)
 *
 * WARNING: Permanent configuration — controls how symmetric keys can be
 *          provisioned to the slot.
 ******************************************************************************
 */

#include "Apps_utils.h"

int main(int argc, char *argv[]) {
    stse_ReturnCode_t stse_ret = STSE_API_INVALID_PARAMETER;
    stse_Handler_t    stse_handler;
    uint8_t           busID = 1;

    if (argc > 1) busID = (uint8_t)atoi(argv[1]);

    PLAT_UI16 symmetric_key_slot = 0;
    stsafea_symmetric_key_slot_provisioning_ctrl_fields_t ctrl_fields = {0};

    /* Configure symmetric key slot to enable wrapped & ECDHE provisioning */
    ctrl_fields.wrapped_anonymous                = 1;
    ctrl_fields.ECDHE_anonymous                  = 1;
    ctrl_fields.wrapped_authentication_key        = 0xFF;
    ctrl_fields.ECDHE_authentication_key          = 0xFF;

    apps_terminal_init(115200);

    printf("----------------------------------------------------------------------------------------------------------------");
    printf("\n\r-              STSAFE-A120 Configure Symmetric key slot provisioning control fields example                  -");
    printf("\n\r----------------------------------------------------------------------------------------------------------------");
    printf("\n\r- WARNING: Permanent operation — once change_right is disabled, settings cannot be changed again.             -");
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
    apps_print_symmetric_key_table_provisioning_control_fields(&stse_handler);

    printf(PRINT_BOLD PRINT_ITALIC "\n\n\r==> Enter the slot number to write: ");
    apps_terminal_read_unsigned_integer(&symmetric_key_slot);

    stse_ret = stsafea_put_symmetric_key_slot_provisioning_ctrl_fields(
            &stse_handler, (PLAT_UI8)symmetric_key_slot, &ctrl_fields);
    printf(PRINT_RESET "\n\n\r - Put slot %u provisioning control fields: ",
           (unsigned)symmetric_key_slot);
    if (stse_ret == STSE_OK) {
        printf(PRINT_GREEN "OK" PRINT_RESET);
    } else if (stse_ret == STSE_ACCESS_CONDITION_NOT_SATISFIED) {
        printf(PRINT_CYAN "Already done" PRINT_RESET);
    } else {
        printf(PRINT_RED "Error 0x%04X" PRINT_RESET, stse_ret);
        apps_process_error(stse_ret);
    }

    return 0;
}
