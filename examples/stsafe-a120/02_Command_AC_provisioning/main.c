/**
 ******************************************************************************
 * @file    main.c
 * @brief   STSAFE-A120 Command AC provisioning — Linux/MPU port
 ******************************************************************************
 *           COPYRIGHT 2022 STMicroelectronics
 ******************************************************************************
 * Usage:  ./02_Command_AC_provisioning [busID]   (default busID = 1)
 *
 * WARNING: Permanent operation — provisions command access conditions.
 *          Use with caution; incorrect settings may lock device functions.
 ******************************************************************************
 */

#include "Apps_utils.h"
#include "services/stsafea/stsafea_frame_transfer.h"

#define AC_FREE     0x01
#define AC_HOST_CMAC 0x03
#define ENCRYPT_NO  0x00
#define ENCRYPT_RSP 0x01
#define ENCRYPT_CMD 0x02

PLAT_UI8 command_AC_table[] = {
    0x00, AC_FREE,       /* Echo                          */
    0x02, AC_FREE,       /* Reset                         */
    0x04, AC_FREE,       /* Decrement                     */
    0x05, AC_FREE,       /* Read                          */
    0x06, AC_FREE,       /* Update                        */
    0x08, AC_HOST_CMAC,  /* Reserved                      */
    0x09, AC_FREE,       /* Generate MAC                  */
    0x0A, AC_FREE,       /* Verify MAC                    */
    0x0E, AC_HOST_CMAC,  /* Wrap local envelope           */
    0x0F, AC_HOST_CMAC,  /* Unwrap local envelope         */
    0x11, AC_FREE,       /* Generate Key                  */
    0x15, AC_FREE,       /* Get signature                 */
    0x16, AC_FREE,       /* Generate signature            */
    0x17, AC_FREE,       /* Verify signature              */
    0x18, AC_HOST_CMAC,  /* Establish key                 */
    0x1A, AC_FREE,       /* Verify password               */
    0x1B, AC_HOST_CMAC,  /* Encrypt                       */
    0x1C, AC_HOST_CMAC,  /* Decrypt                       */
    0x1F, 0x00, AC_FREE, /* Start Hash                    */
    0x1F, 0x01, AC_FREE, /* Process Hash                  */
    0x1F, 0x02, AC_FREE, /* Finish Hash                   */
    0x1F, 0x03, AC_FREE, /* Start volatile KEK session    */
    0x1F, 0x04, AC_FREE, /* Establish symmetric keys      */
    0x1F, 0x05, AC_FREE, /* Confirm symmetric keys        */
    0x1F, 0x06, AC_FREE, /* Stop volatile KEK session     */
    0x1F, 0x07, AC_FREE, /* Write host key V2 plaintext   */
    0x1F, 0x08, AC_FREE, /* Write host key V2 wrapped     */
    0x1F, 0x09, AC_FREE, /* Write symmetric key wrapped   */
    0x1F, 0x0A, AC_FREE, /* Write public key              */
    0x1F, 0x0B, AC_FREE, /* Generate ECDHE key            */
    0x1F, 0x0C, AC_FREE, /* Reserved                      */
    0x1F, 0x0D, AC_FREE, /* Reserved                      */
    0x1F, 0x0E, AC_FREE, /* Generate challenge            */
    0x1F, 0x0F, AC_FREE, /* Verify entity signature       */
    0x1F, 0x10, AC_FREE, /* Derive keys                   */
    0x1F, 0x11, AC_FREE, /* Start encrypt                 */
    0x1F, 0x12, AC_FREE, /* Process encrypt               */
    0x1F, 0x13, AC_FREE, /* Finish encrypt                */
    0x1F, 0x14, AC_FREE, /* Start decrypt                 */
    0x1F, 0x15, AC_FREE, /* Process decrypt               */
    0x1F, 0x16, AC_FREE, /* Finish decrypt                */
    0x1F, 0x17, AC_FREE, /* Write symmetric key plaintext */
    0x1F, 0x18, AC_FREE, /* Establish host key V2         */
    0x1F, 0x19, AC_FREE, /* Erase symmetric key slot      */
    0x1F, 0x1A, AC_FREE  /* Decompress public key         */
};

PLAT_UI8 command_encryption_table[] = {
    0x00, ENCRYPT_NO,  /* Echo                          */
    0x02, ENCRYPT_NO,  /* Reset                         */
    0x04, ENCRYPT_NO,  /* Decrement                     */
    0x05, ENCRYPT_NO,  /* Read                          */
    0x06, ENCRYPT_NO,  /* Update                        */
    0x08, ENCRYPT_NO,  /* Reserved                      */
    0x09, ENCRYPT_NO,  /* Generate MAC                  */
    0x0A, ENCRYPT_NO,  /* Verify MAC                    */
    0x0E, ENCRYPT_CMD, /* Wrap local envelope           */
    0x0F, ENCRYPT_RSP, /* Unwrap local envelope         */
    0x11, ENCRYPT_NO,  /* Generate Key                  */
    0x15, ENCRYPT_NO,  /* Get signature                 */
    0x16, ENCRYPT_NO,  /* Generate signature            */
    0x17, ENCRYPT_NO,  /* Verify signature              */
    0x18, ENCRYPT_RSP, /* Establish key                 */
    0x1A, ENCRYPT_NO,  /* Verify password               */
    0x1B, ENCRYPT_CMD, /* Encrypt                       */
    0x1C, ENCRYPT_RSP, /* Decrypt                       */
    0x1F, 0x00, ENCRYPT_NO, 0x1F, 0x01, ENCRYPT_NO,
    0x1F, 0x02, ENCRYPT_NO, 0x1F, 0x03, ENCRYPT_NO,
    0x1F, 0x04, ENCRYPT_NO, 0x1F, 0x05, ENCRYPT_NO,
    0x1F, 0x06, ENCRYPT_NO, 0x1F, 0x07, ENCRYPT_NO,
    0x1F, 0x08, ENCRYPT_NO, 0x1F, 0x09, ENCRYPT_NO,
    0x1F, 0x0A, ENCRYPT_NO, 0x1F, 0x0B, ENCRYPT_NO,
    0x1F, 0x0C, ENCRYPT_NO, 0x1F, 0x0D, ENCRYPT_NO,
    0x1F, 0x0E, ENCRYPT_NO, 0x1F, 0x0F, ENCRYPT_NO,
    0x1F, 0x10, ENCRYPT_NO, 0x1F, 0x11, ENCRYPT_NO,
    0x1F, 0x12, ENCRYPT_NO, 0x1F, 0x13, ENCRYPT_NO,
    0x1F, 0x14, ENCRYPT_NO, 0x1F, 0x15, ENCRYPT_NO,
    0x1F, 0x16, ENCRYPT_NO, 0x1F, 0x17, ENCRYPT_NO,
    0x1F, 0x18, ENCRYPT_NO, 0x1F, 0x19, ENCRYPT_NO,
    0x1F, 0x1A, ENCRYPT_NO
};

int main(int argc, char *argv[]) {
    stse_ReturnCode_t stse_ret = STSE_API_INVALID_PARAMETER;
    stse_Handler_t    stse_handler;
    uint8_t           busID = 1;

    if (argc > 1) busID = (uint8_t)atoi(argv[1]);

    PLAT_UI8               total_command_count = 0;
    stse_cmd_authorization_CR_t change_rights;
    PLAT_UI8               put_cmd_AC_header[]  = {0x10, 0x29, 0x2D};
    PLAT_UI8               put_cmd_enc_header[] = {0x10, 0x2A, 0x2D};
    PLAT_UI8               rsp_header;

    stse_frame_allocate(CmdFrame);
    stse_frame_allocate(RspFrame);
    stse_frame_element_allocate_push(&CmdFrame, eCmd_header,  3,                        NULL);
    stse_frame_element_allocate_push(&CmdFrame, eCmd_payload, sizeof(command_AC_table), NULL);
    stse_frame_element_allocate_push(&RspFrame, eRsp_header,  1,                        &rsp_header);

    apps_terminal_init(115200);

    printf("----------------------------------------------------------------------------------------------------------------");
    printf("\n\r-                   STSAFE-A120 Configure commands access conditions & encryption example                    -");
    printf("\n\r----------------------------------------------------------------------------------------------------------------");
    printf(PRINT_RED "\n\r- WARNING: Permanent configuration change!\n\r" PRINT_RESET);
    printf("- Press Enter to continue, Ctrl-C to abort.\n\r");
    apps_terminal_read_string(NULL, NULL);

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

    stse_ret = stsafea_get_command_count(&stse_handler, &total_command_count);
    if (stse_ret != STSE_OK) {
        printf(PRINT_RED "\n\n\r - stsafea_get_command_count error: 0x%04X", stse_ret);
        apps_process_error(stse_ret);
    }

    stse_cmd_authorization_record_t record_table[total_command_count];
    stse_ret = stsafea_get_command_AC_table(&stse_handler, total_command_count,
                                             &change_rights, record_table);
    if (stse_ret != STSE_OK) {
        printf(PRINT_RED "\n\n\r - stsafea_get_command_AC_table error: 0x%04X", stse_ret);
        apps_process_error(stse_ret);
    }
    printf(PRINT_RESET "\n\n\r - Current STSAFE-A120 Command AC table (AC CR=%d / Enc CR=%d)\n",
           change_rights.cmd_AC_CR, change_rights.host_encryption_flag_CR);
    apps_print_command_ac_record_table(record_table, total_command_count);

    /* Put command AC conditions */
    eCmd_header.pData  = put_cmd_AC_header;
    eCmd_payload.pData = command_AC_table;
    stse_ret = stsafea_frame_raw_transfer(&stse_handler, &CmdFrame, &RspFrame, 100);
    if (stse_ret != STSE_OK) {
        printf(PRINT_RED "\n\n\r - put command AC error: 0x%04X", stse_ret);
        if (stse_ret == STSE_ACCESS_CONDITION_NOT_SATISFIED)
            printf(PRINT_CYAN "\n\n\r - command AC already defined" PRINT_RESET);
        apps_process_error(stse_ret);
    } else if (rsp_header != STSE_OK) {
        printf(PRINT_RED "\n\n\r - put command AC error in response: 0x%04X", rsp_header);
        apps_process_error(stse_ret);
    } else {
        printf(PRINT_GREEN "\n\n\r - STSAFE-A120 Commands AC updated" PRINT_RESET);
    }

    /* Put command encryption */
    eCmd_header.pData  = put_cmd_enc_header;
    eCmd_payload.pData = command_encryption_table;
    stse_ret = stsafea_frame_raw_transfer(&stse_handler, &CmdFrame, &RspFrame, 100);
    if (stse_ret != STSE_OK) {
        printf(PRINT_RED "\n\n\r - put command encryption error: 0x%04X", stse_ret);
        if (stse_ret == STSE_ACCESS_CONDITION_NOT_SATISFIED)
            printf(PRINT_CYAN "\n\n\r - command encryption already defined" PRINT_RESET);
        apps_process_error(stse_ret);
    } else if (rsp_header != STSE_OK) {
        printf(PRINT_RED "\n\n\r - put command encryption error: 0x%04X", rsp_header);
        apps_process_error(stse_ret);
    } else {
        printf(PRINT_GREEN "\n\n\r - STSAFE-A120 Commands encryption updated" PRINT_RESET);
    }

    /* Query updated table */
    stse_ret = stsafea_get_command_AC_table(&stse_handler, total_command_count,
                                             &change_rights, record_table);
    if (stse_ret != STSE_OK) {
        printf(PRINT_RED "\n\n\r - query command AC error: 0x%04X", stse_ret);
        apps_process_error(stse_ret);
    }
    printf(PRINT_RESET "\n\n\r - Updated STSAFE-A120 Command AC table (AC CR=%d / Enc CR=%d)\n",
           change_rights.cmd_AC_CR, change_rights.host_encryption_flag_CR);
    apps_print_command_ac_record_table(record_table, total_command_count);

    return 0;
}
