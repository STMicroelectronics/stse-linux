/**
 ******************************************************************************
 * @file    Apps_utils.h
 * @author  CS application team
 * @brief   Application utilities header — Linux/MPU port
 *          Provides the same API as the MCU SDK Apps_utils, adapted for Linux.
 ******************************************************************************
 *           COPYRIGHT 2022 STMicroelectronics
 *
 * This software is licensed under terms that can be found in the LICENSE file
 * in the root directory of this software component.
 * If no LICENSE file comes with this software, it is provided AS-IS.
 *
 ******************************************************************************
 */

#ifndef APPS_UTILS_H
#define APPS_UTILS_H

#include "stselib.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---------------------------------------------------------------------------
 * Terminal control sequences (ANSI)
 * -------------------------------------------------------------------------*/
#define PRINT_CLEAR_SCREEN  "\x1B[1;1H\x1B[2J"
#define PRINT_BLINK         "\x1B[5m"
#define PRINT_UNDERLINE     "\x1B[4m"
#define PRINT_BELL          "\a"
#define PRINT_BOLD          "\x1B[1m"
#define PRINT_ITALIC        "\x1B[3m"
#define PRINT_RESET         "\x1B[0m"

#ifdef DISABLE_PRINT_COLOR
#define PRINT_BLACK   ""
#define PRINT_RED     ""
#define PRINT_GREEN   ""
#define PRINT_YELLOW  ""
#define PRINT_BLUE    ""
#define PRINT_MAGENTA ""
#define PRINT_CYAN    ""
#define PRINT_WHITE   ""
#else
#define PRINT_BLACK   "\x1B[30m"
#define PRINT_RED     "\x1B[31m"
#define PRINT_GREEN   "\x1B[32m"
#define PRINT_YELLOW  "\x1B[33m"
#define PRINT_BLUE    "\x1B[34m"
#define PRINT_MAGENTA "\x1B[35m"
#define PRINT_CYAN    "\x1B[36m"
#define PRINT_WHITE   "\x1B[37m"
#endif

/* ---------------------------------------------------------------------------
 * Terminal I/O
 * -------------------------------------------------------------------------*/
void    apps_terminal_init(uint32_t baudrate);
uint8_t apps_terminal_read_string(char *string, uint8_t *length);
uint8_t apps_terminal_read_unsigned_integer(uint16_t *integer);

/* ---------------------------------------------------------------------------
 * Print helpers
 * -------------------------------------------------------------------------*/
void apps_print_data_partition_record_table(stse_Handler_t *pSTSE);
void apps_print_symmetric_key_table_info(stse_Handler_t *pSTSE);
void apps_print_symmetric_key_table_provisioning_control_fields(stse_Handler_t *pSTSE);
void apps_print_asymmetric_key_table_info(stse_Handler_t *pSTSE);
void apps_print_host_key_provisioning_control_fields(stse_Handler_t *pSTSE);
void apps_print_generic_public_key_slot_configuration_flags(stse_Handler_t *pSTSE,
                                                            PLAT_UI8 slot_number);
void apps_print_hex_buffer(uint8_t *buffer, uint16_t buffer_size);
void apps_print_command_ac_record_table(
        stse_cmd_authorization_record_t *command_ac_record_table,
        uint8_t total_command_count);
void apps_print_life_cycle_state(stsafea_life_cycle_state_t life_cycle_state);

/* ---------------------------------------------------------------------------
 * Utility functions
 * -------------------------------------------------------------------------*/
uint32_t apps_generate_random_number(void);
void     apps_randomize_buffer(uint8_t *pBuffer, uint16_t buffer_length);
uint8_t  apps_compare_buffers(uint8_t *pBuffer1, uint8_t *pBuffer2,
                               uint16_t buffers_length);
void     apps_delay_ms(uint16_t ms);
void     apps_process_error(uint32_t err);  /* calls exit(1) on Linux */

/* ---------------------------------------------------------------------------
 * Curve-ID helpers (used by multi-step auth and ECDH examples)
 * -------------------------------------------------------------------------*/
char             *get_key_type_str(stse_ecc_key_type_t key_type);
stse_ReturnCode_t get_curve_id_key_type(stsafea_ecc_curve_id_t curve_id,
                                        stse_ecc_key_type_t   *pKey_type);

#endif /* APPS_UTILS_H */
