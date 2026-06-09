/**
 ******************************************************************************
 * @file    main.c
 * @brief   STSAFE-A120 ECDH key establishment — Linux/MPU port
 ******************************************************************************
 *           COPYRIGHT 2022 STMicroelectronics
 ******************************************************************************
 * Usage:  ./03_ECDH [busID]   (default busID = 1)
 *
 * Prerequisites: Run 02_Host_key_provisioning first.
 ******************************************************************************
 */

#include "Apps_utils.h"

#define ENCRYPT_NO  0x00
#define ENCRYPT_RSP 0x01

const stsafea_aes_128_host_keys_t host_keys = {
    .host_mac_key    = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
    .host_cipher_key = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}
};

int main(int argc, char *argv[]) {
    stse_ReturnCode_t stse_ret = STSE_API_INVALID_PARAMETER;
    stse_Handler_t    stse_handler;
    stse_session_t    host_session_handler;
    uint8_t           busID = 1;

    if (argc > 1) busID = (uint8_t)atoi(argv[1]);

    stse_cmd_access_conditions_t establish_key_protection       = STSE_CMD_AC_NEVER;
    PLAT_UI8                     establish_key_rsp_encryption_flag = ENCRYPT_NO;

    stse_ecc_key_type_t key_type = STSE_ECC_KT_NIST_P_256;

    /* Host NIST P-256 public key (example key — replace with your own) */
    static uint8_t host_public_key[] = {
        0xe2, 0xaa, 0x79, 0x20, 0x16, 0x90, 0xd8, 0x50, 0x3f, 0x79, 0x2b, 0xb8, 0xf5, 0x14, 0x67, 0x3d,
        0x8c, 0x88, 0x85, 0x8a, 0x82, 0xc2, 0xb8, 0xd1, 0xb7, 0xe8, 0x14, 0x53, 0x23, 0x0e, 0xac, 0xbb,
        0x7d, 0x25, 0xeb, 0x2c, 0x09, 0xf4, 0xb0, 0x67, 0x20, 0x35, 0xac, 0x0d, 0x14, 0x1e, 0xe6, 0xd1,
        0x42, 0x20, 0x1c, 0x21, 0xef, 0xee, 0xb7, 0x87, 0x98, 0xdf, 0xe8, 0x76, 0xae, 0x7d, 0x1a, 0x07
    };

    /* 0xFF = ephemeral ECDHE key slot; 0x01..0x04 = static ECDH key slot */
    uint8_t slot_number = 0xFF;

    PLAT_UI16 pub_key_size       = stse_ecc_info_table[key_type].public_key_size;
    PLAT_UI8  stse_public_key[pub_key_size];
    PLAT_UI16 shared_secret_size = stse_ecc_info_table[key_type].shared_secret_size;
    PLAT_UI8  shared_secret[shared_secret_size];

    apps_terminal_init(115200);

    printf("----------------------------------------------------------------------------------------------------------------");
    printf("\n\r-                                      STSAFE-A ECDH example                                                  -");
    printf("\n\r----------------------------------------------------------------------------------------------------------------");
    printf("\n\r- Prerequisites: run 02_Host_key_provisioning first.                                                           -");
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

    /* Check establish-key access condition */
    stsafea_perso_info_get_cmd_AC(&stse_handler.perso_info, STSAFEA_CMD_ESTABLISH_KEY,
                                   &establish_key_protection);
    stsafea_perso_info_get_rsp_encrypt_flag(&stse_handler.perso_info, STSAFEA_CMD_ESTABLISH_KEY,
                                             &establish_key_rsp_encryption_flag);

    if (establish_key_protection < STSE_CMD_AC_HOST || establish_key_rsp_encryption_flag == ENCRYPT_NO) {
        printf(PRINT_CYAN "\n\n\r"
               "----------------------------------------------------------------------------------------------------------------\n\r"
               "-                                          !!!!! WARNING !!!!!                                                  -\n\r"
               "- To avoid key leakage, it is recommended to provision command access conditions first.                         -\n\r"
               "----------------------------------------------------------------------------------------------------------------\n\r"
               PRINT_RESET);
    }

    /* Generate ECC key pair on STSAFE */
    stse_ret = stsafea_generate_ecc_key_pair(&stse_handler, slot_number, key_type, 1, stse_public_key);
    if (stse_ret != STSE_OK) {
        memset(host_public_key, 0, sizeof(host_public_key));
        printf(PRINT_RED "\n\r ## stsafea_generate_ecc_key_pair ERROR : 0x%04X\n\r", stse_ret);
        apps_process_error(stse_ret);
    }

    /* Open host session */
    stsafea_session_clear_context(&host_session_handler);
    stse_ret = stsafea_open_host_session(&stse_handler, &host_session_handler,
                                          (uint8_t *)host_keys.host_mac_key,
                                          (uint8_t *)host_keys.host_cipher_key);
    if (stse_ret != STSE_OK) {
        printf(PRINT_RED "\n\r - stsafea_open_host_session ERROR : 0x%04X", stse_ret);
        if (stse_ret == STSE_SERVICE_SESSION_ERROR)
            printf("\n\r - Host keys not populated through STSE");
        apps_process_error(stse_ret);
    }

    /* ECDH key establishment */
    stse_ret = stse_ecc_establish_shared_secret(&stse_handler, slot_number, key_type,
                                                 host_public_key, shared_secret);
    if (stse_ret != STSE_OK) {
        memset(host_public_key, 0, sizeof(host_public_key));
        printf(PRINT_RED "\n\r ## stse_ecc_establish_shared_secret ERROR : 0x%04X\n\r", stse_ret);
        apps_process_error(stse_ret);
    }
    printf(PRINT_GREEN "\n\n\r\t - Shared secret:\n\r" PRINT_RESET);
    apps_print_hex_buffer(shared_secret, sizeof(shared_secret));

    stsafea_close_host_session(&host_session_handler);

    printf(PRINT_GREEN "\n\n\r - ECDH : SUCCESS\n\r" PRINT_RESET);
    return 0;
}
