/**
 ******************************************************************************
 * @file    Apps_utils.c
 * @author  CS application team
 * @brief   Application utilities implementation — Linux/MPU port
 *          Replaces MCU-specific drivers (uart, rng, delay_ms) with POSIX
 *          equivalents while keeping the same STSELib helper functions.
 ******************************************************************************
 *           COPYRIGHT 2022 STMicroelectronics
 *
 * This software is licensed under terms that can be found in the LICENSE file
 * in the root directory of this software component.
 * If no LICENSE file comes with this software, it is provided AS-IS.
 *
 ******************************************************************************
 */

#include "Apps_utils.h"

#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/random.h>  /* getrandom() — Linux 3.17+ */

/* ---------------------------------------------------------------------------
 * Terminal I/O
 * -------------------------------------------------------------------------*/

/**
 * @brief  Initialise terminal (no-op on Linux — stdout/stdin already ready).
 * @param  baudrate  Ignored on Linux.
 */
void apps_terminal_init(uint32_t baudrate) {
    (void)baudrate;
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin,  NULL, _IONBF, 0);
    printf(PRINT_RESET PRINT_CLEAR_SCREEN);
}

/**
 * @brief  Read a string from stdin until CR/LF or EOF.
 * @param  string  Buffer to fill (may be NULL).
 * @param  length  In: max length; out: bytes read.  May be NULL (unlimited).
 * @return 0 on success, 1 if max length exceeded.
 */
uint8_t apps_terminal_read_string(char *string, uint8_t *length) {
    char   buf[256];
    size_t maxlen = (length != NULL) ? *length : sizeof(buf) - 1U;

    if (maxlen >= sizeof(buf))
        maxlen = sizeof(buf) - 1U;

    if (fgets(buf, (int)(maxlen + 1U), stdin) == NULL)
        return 1;

    /* Strip trailing newline */
    size_t n = strlen(buf);
    if (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
        buf[--n] = '\0';

    if (string != NULL)
        memcpy(string, buf, n + 1U);

    if (length != NULL)
        *length = (uint8_t)n;

    return 0;
}

/**
 * @brief  Read an unsigned integer from stdin.
 * @param  integer  Output pointer.
 * @return 0 on success, 1 on error.
 */
uint8_t apps_terminal_read_unsigned_integer(uint16_t *integer) {
    unsigned int val = 0;
    if (scanf("%u", &val) != 1)
        return 1;
    *integer = (uint16_t)val;
    return 0;
}

/* ---------------------------------------------------------------------------
 * Random number generation
 * -------------------------------------------------------------------------*/

/**
 * @brief  Generate a random 32-bit number using the OS CSPRNG.
 */
uint32_t apps_generate_random_number(void) {
    uint32_t rnd = 0;
    ssize_t  ret = getrandom(&rnd, sizeof(rnd), 0);
    if (ret != (ssize_t)sizeof(rnd)) {
        /* Fallback: read from /dev/urandom */
        int fd = open("/dev/urandom", O_RDONLY);
        if (fd >= 0) {
            (void)read(fd, &rnd, sizeof(rnd));
            close(fd);
        }
    }
    return rnd;
}

/**
 * @brief  Fill a buffer with cryptographically random bytes.
 */
void apps_randomize_buffer(uint8_t *pBuffer, uint16_t buffer_length) {
    ssize_t ret = getrandom(pBuffer, buffer_length, 0);
    if (ret != (ssize_t)buffer_length) {
        /* Fallback: read from /dev/urandom byte by byte */
        int fd = open("/dev/urandom", O_RDONLY);
        if (fd >= 0) {
            (void)read(fd, pBuffer, buffer_length);
            close(fd);
        } else {
            for (uint16_t i = 0; i < buffer_length; i++)
                pBuffer[i] = (uint8_t)(apps_generate_random_number() & 0xFF);
        }
    }
}

/* ---------------------------------------------------------------------------
 * Timing
 * -------------------------------------------------------------------------*/

/**
 * @brief  Delay execution for the specified number of milliseconds.
 */
void apps_delay_ms(uint16_t ms) {
    usleep((useconds_t)ms * 1000U);
}

/* ---------------------------------------------------------------------------
 * Error handling
 * -------------------------------------------------------------------------*/

/**
 * @brief  Handle a fatal error by printing to stderr and exiting.
 * @note   Unlike the MCU version this DOES return (via exit()).
 */
void apps_process_error(uint32_t err) {
    fprintf(stderr, PRINT_RED "\n\r ## apps_process_error: 0x%08X — aborting\n\r" PRINT_RESET,
            (unsigned int)err);
    fflush(stderr);
    exit(1);
}

/* ---------------------------------------------------------------------------
 * Hex buffer printing
 * -------------------------------------------------------------------------*/

/**
 * @brief  Print a byte buffer in hexadecimal format (16 bytes per line).
 */
void apps_print_hex_buffer(uint8_t *buffer, uint16_t buffer_size) {
    uint16_t i;
    for (i = 0; i < buffer_size; i++) {
        if (i % 16 == 0)
            printf(" \n\r ");
        printf(" 0x%02X", buffer[i]);
    }
}

/* ---------------------------------------------------------------------------
 * Life-cycle state
 * -------------------------------------------------------------------------*/
void apps_print_life_cycle_state(stsafea_life_cycle_state_t life_cycle_state) {
    switch (life_cycle_state) {
    case STSAFEA_LCS_BORN:               printf("BORN");                 break;
    case STSAFEA_LCS_PATCHING:           printf("PATCHING");             break;
    case STSAFEA_LCS_OPERATIONAL:        printf("OPERATIONAL");          break;
    case STSAFEA_LCS_TERMINATED:         printf("TERMINATED");           break;
    case STSAFEA_LCS_BORN_AND_LOCKED:    printf("BORN_AND_LOCKED");      break;
    case STSAFEA_LCS_OPERATIONAL_AND_LOCKED: printf("OPERATIONAL_AND_LOCKED"); break;
    default:                             printf("UNKNOWN");              break;
    }
}

/* ---------------------------------------------------------------------------
 * Curve-ID helpers
 * -------------------------------------------------------------------------*/

char *get_key_type_str(stse_ecc_key_type_t key_type) {
    switch (key_type) {
#ifdef STSE_CONF_ECC_NIST_P_256
    case STSE_ECC_KT_NIST_P_256: return ("NIST_P_256");
#endif
#ifdef STSE_CONF_ECC_NIST_P_384
    case STSE_ECC_KT_NIST_P_384: return ("NIST_P_384");
#endif
#ifdef STSE_CONF_ECC_NIST_P_521
    case STSE_ECC_KT_NIST_P_521: return ("NIST_P_521");
#endif
#ifdef STSE_CONF_ECC_BRAINPOOL_P_256
    case STSE_ECC_KT_BP_P_256:   return (" BP_P_256 ");
#endif
#ifdef STSE_CONF_ECC_BRAINPOOL_P_384
    case STSE_ECC_KT_BP_P_384:   return (" BP_P_384 ");
#endif
#ifdef STSE_CONF_ECC_BRAINPOOL_P_512
    case STSE_ECC_KT_BP_P_512:   return (" BP_P_512 ");
#endif
#ifdef STSE_CONF_ECC_CURVE_25519
    case STSE_ECC_KT_CURVE25519: return ("CURVE25519");
#endif
#ifdef STSE_CONF_ECC_EDWARD_25519
    case STSE_ECC_KT_ED25519:    return (" ED25519  ");
#endif
    default: return (PRINT_YELLOW "bad curve ID" PRINT_RESET);
    }
}

stse_ReturnCode_t get_curve_id_key_type(stsafea_ecc_curve_id_t  curve_id,
                                         stse_ecc_key_type_t    *pKey_type) {
    stse_ecc_key_type_t curve_id_index;
    int diff;
    *pKey_type = STSE_ECC_KT_INVALID;

    for (curve_id_index = (stse_ecc_key_type_t)0;
         curve_id_index < STSE_ECC_KT_INVALID;
         curve_id_index++) {
        diff = memcmp((PLAT_UI8 *)&stse_ecc_info_table[curve_id_index].curve_id,
                      (PLAT_UI8 *)&curve_id,
                      stse_ecc_info_table[curve_id_index].curve_id_total_length);
        if (diff == 0) {
            *pKey_type = curve_id_index;
            break;
        }
    }
    if (curve_id_index >= STSE_ECC_KT_INVALID || *pKey_type == STSE_ECC_KT_INVALID)
        return STSE_UNEXPECTED_ERROR;
    return STSE_OK;
}

/* ---------------------------------------------------------------------------
 * Buffer comparison
 * -------------------------------------------------------------------------*/
uint8_t apps_compare_buffers(uint8_t *pBuffer1, uint8_t *pBuffer2,
                              uint16_t buffers_length) {
    for (uint16_t i = 0; i < buffers_length; i++) {
        if (pBuffer1[i] != pBuffer2[i])
            return 1;
    }
    return 0;
}

/* ---------------------------------------------------------------------------
 * Data partition table
 * -------------------------------------------------------------------------*/
void apps_print_data_partition_record_table(stse_Handler_t *pSTSE) {
    uint8_t           i;
    stse_ReturnCode_t ret;
    uint16_t          data_partition_record_table_length;
    uint8_t           total_zone_count;

    ret = stse_data_storage_get_total_partition_count(pSTSE, &total_zone_count);
    if (ret != STSE_OK) {
        printf("\n\n\r ### stse_data_storage_get_total_partition_count : ERROR 0x%04X", ret);
        while (1) ;
    }

    stsafea_data_partition_record_t data_partition_record_table[total_zone_count];
    data_partition_record_table_length = sizeof(data_partition_record_table);

    ret = stse_data_storage_get_partitioning_table(pSTSE, total_zone_count,
                                                    data_partition_record_table,
                                                    data_partition_record_table_length);
    if (ret != STSE_OK) {
        printf("\n\r ### stse_data_storage_get_partitioning_table : ERROR 0x%04X", ret);
        while (1) ;
    } else {
        printf("\n\n\r - stse_data_storage_get_partitioning_table");
    }

    printf("\n\r  ID | COUNTER | DATA SEGMENT SIZE | READ AC CR |  READ AC | UPDATE AC CR | UPDATE AC | COUNTER VAL \r\n");
    for (i = 0; i < total_zone_count; i++) {
        printf(" %03d | ", data_partition_record_table[i].index);
        printf("   %c    |", (data_partition_record_table[i].zone_type) == 0 ? '.' : 'x');
        printf("       %04u        | ", data_partition_record_table[i].data_segment_length);
        printf(" %s | ", (data_partition_record_table[i].read_ac_cr) == 1 ? " ALLOWED " : " DENIED  ");
        switch (data_partition_record_table[i].read_ac) {
        case STSE_AC_ALWAYS:        printf(" ALWAYS  |"); break;
        case STSE_AC_HOST:          printf("   HOST  |"); break;
        case STSE_AC_AUTH_AND_HOST: printf("AUT+HOST |"); break;
        default:                    printf("  NEVER  |"); break;
        }
        printf(" %s | ", (data_partition_record_table[i].update_ac_cr) == 1 ? "   ALLOWED  " : "   DENIED   ");
        switch (data_partition_record_table[i].update_ac) {
        case STSE_AC_ALWAYS:        printf("  ALWAYS  |"); break;
        case STSE_AC_HOST:          printf("   HOST   |"); break;
        case STSE_AC_AUTH_AND_HOST: printf("AUT+HOST |");  break;
        default:                    printf("  NEVER   |"); break;
        }
        printf(" %06" PRIu32 "\r\n", data_partition_record_table[i].counter_value);
    }
}

/* ---------------------------------------------------------------------------
 * Command AC record table
 * -------------------------------------------------------------------------*/
void apps_print_command_ac_record_table(
        stse_cmd_authorization_record_t *command_ac_record_table,
        uint8_t total_command_count) {
    uint8_t i;
    printf("\n\r  HEADER | EXT-HEADER |    AC  | CMDEnc | RSPEnc  ");
    for (i = 0; i < total_command_count; i++) {
        printf("\n\r");
        printf("   0x%02X  | ", command_ac_record_table[i].header);
        if (command_ac_record_table[i].extended_header != 0)
            printf("    0x%02X   | ", command_ac_record_table[i].extended_header);
        else
            printf("     -     | ");
        switch (command_ac_record_table[i].command_AC) {
        case STSE_CMD_AC_NEVER:         printf(" NEVER  |"); break;
        case STSE_CMD_AC_FREE:          printf("  FREE  |"); break;
        case STSE_CMD_AC_ADMIN:         printf(" ADMIN  |"); break;
        case STSE_CMD_AC_HOST:          printf("  HOST  |"); break;
        case STSE_CMD_AC_ADMIN_OR_PWD:  printf("ADM/PWD |"); break;
        case STSE_CMD_AC_ADMIN_OR_HOST: printf(" ADM/HST|"); break;
        default:                        printf("  --?-- |"); break;
        }
        printf(" %s | ", (command_ac_record_table[i].host_encryption_flags.cmd) == 1 ? "  YES " : "  NO  ");
        printf(" %s | ", (command_ac_record_table[i].host_encryption_flags.rsp) == 1 ? "  YES " : "  NO  ");
    }
}

/* ---------------------------------------------------------------------------
 * Symmetric key table information
 * -------------------------------------------------------------------------*/
void apps_print_symmetric_key_table_info(stse_Handler_t *pSTSE) {
    stse_ReturnCode_t ret;
    PLAT_UI8 i;
    PLAT_UI8 slot_count;

    ret = stse_get_symmetric_key_slots_count(pSTSE, &slot_count);
    if (ret != STSE_OK) {
        printf("\n\n\r - stse_get_symmetric_key_slots_count : ERROR 0x%04x", ret);
        while (1) ;
    }

    stsafea_symmetric_key_slot_information_t symmetric_key_table[slot_count];
    ret = stse_get_symmetric_key_table_info(pSTSE, slot_count, symmetric_key_table);
    if (ret != STSE_OK) {
        printf("\n\n\r - stse_get_symmetric_key_table_info : ERROR 0x%04x", ret);
        while (1) ;
    }

    printf("\n\n\r");
    printf("\n\r  SLOT | LOCK | KEY TYPE | MODE | DERIVE | MAC_GEN | MAC_VER | ENC | DEC\n\r");
    for (i = 0; i < slot_count; i++) {
        printf("\r\n   %02d  |", i);
        printf("   %s  |", (symmetric_key_table[i].lock_indicator == 0) ? "." : "x");
        if (symmetric_key_table[i].key_presence == 1) {
            printf(" %s  |", (symmetric_key_table[i].key_type == 0) ? "AES128" : "AES256");
            char *mode_str = "RFU";
            switch (symmetric_key_table[i].mode_of_operation) {
                case STSAFEA_KEY_OPERATION_MODE_CCM:  mode_str = "CCM"; break;
                case STSAFEA_KEY_OPERATION_MODE_CMAC: mode_str = "CMAC"; break;
                case STSAFEA_KEY_OPERATION_MODE_ECB:  mode_str = "ECB"; break;
                case STSAFEA_KEY_OPERATION_MODE_GCM:  mode_str = "GCM"; break;
                case STSAFEA_KEY_OPERATION_MODE_HKDF: mode_str = "HKDF"; break;
                case STSAFEA_KEY_OPERATION_MODE_HMAC: mode_str = "HMAC"; break;
            }
            printf("  %-4s|",  mode_str);
            printf("    %s   |", (symmetric_key_table[i].key_usage.derive == 0)            ? "." : "x");
            printf("    %s    |", (symmetric_key_table[i].key_usage.mac_generation == 0)  ? "." : "x");
            printf("    %s    |", (symmetric_key_table[i].key_usage.mac_verification == 0)? "." : "x");
            printf("  %s  |", (symmetric_key_table[i].key_usage.encryption == 0)          ? "." : "x");
            printf("  %s  |", (symmetric_key_table[i].key_usage.decryption == 0)          ? "." : "x");
        } else {
            printf("    .     |     .   |    .   |    .    |    .    |  .  |  .  |");
        }
    }
}

/* ---------------------------------------------------------------------------
 * Symmetric key provisioning control fields
 * -------------------------------------------------------------------------*/
void apps_print_symmetric_key_table_provisioning_control_fields(stse_Handler_t *pSTSE) {
    stse_ReturnCode_t ret;
    PLAT_UI8 i;
    PLAT_UI8 slot_count;
    stsafea_symmetric_key_slot_provisioning_ctrl_fields_t ctrl_fields;

    ret = stse_get_symmetric_key_slots_count(pSTSE, &slot_count);
    if (ret != STSE_OK) {
        printf("\n\n\r - stse_get_symmetric_key_slots_count : ERROR 0x%04x", ret);
        while (1) ;
    }

    printf("\n\n\r");
    printf("\n\r  SLOT | CHANGE RIGHT | DERIVED | PLAINTEXT | PUT KEY | WRAPPED | ECDHE\n\r");
    for (i = 0; i < slot_count; i++) {
        printf("\r\n   %02d  |", i);
        ret = stse_get_symmetric_key_slot_provisioning_ctrl_fields(pSTSE, i, &ctrl_fields);
        if (ret != STSE_OK) {
            printf(" ERROR 0x%04x", ret);
            while (1) ;
        }
        printf("       %s      |", (ctrl_fields.change_right == 0)  ? "." : "x");
        printf("    %s    |",       (ctrl_fields.derived == 0)       ? "." : "x");
        printf("     %s     |",     (ctrl_fields.plaintext == 0)     ? "." : "x");
        printf("    %s    |",       (ctrl_fields.put_key == 0)       ? "." : "x");
        if (ctrl_fields.wrapped_authentication_key != 0xFF)
            printf("  0x%02X   |", ctrl_fields.wrapped_authentication_key);
        else
            printf("    %s    |", (ctrl_fields.wrapped_anonymous == 0) ? "." : "x");
        if (ctrl_fields.ECDHE_authentication_key != 0xFF)
            printf(" 0x%02X ", ctrl_fields.ECDHE_authentication_key);
        else
            printf("   %s   ", (ctrl_fields.ECDHE_anonymous == 0) ? "." : "x");
    }
}

/* ---------------------------------------------------------------------------
 * Asymmetric key table information
 * -------------------------------------------------------------------------*/
void apps_print_asymmetric_key_table_info(stse_Handler_t *pSTSE) {
    stse_ReturnCode_t ret;
    PLAT_UI8  i;
    PLAT_UI8  slot_count;
    PLAT_UI16 global_usage_limit;
    stse_ecc_key_type_t key_type;

    ret = stse_get_ecc_key_slots_count(pSTSE, &slot_count);
    if (ret != STSE_OK) {
        printf("\n\n\r - stse_get_ecc_key_slots_count : ERROR 0x%04x", ret);
        while (1) ;
    }

    stsafea_private_key_slot_information_t pPrivate_key_table_info[slot_count];
    ret = stse_get_ecc_key_table_info(pSTSE, slot_count, &global_usage_limit,
                                       pPrivate_key_table_info);
    if (ret != STSE_OK) {
        printf("\n\n\r - stse_get_ecc_key_table_info : ERROR 0x%04x", ret);
        while (1) ;
    }

    printf("\n\n\r  SLOT | PRESENCE |    TYPE    | Gen Key AC | Sig Gen | Key establishment\n\r");
    for (i = 0; i < slot_count; i++) {
        get_curve_id_key_type(pPrivate_key_table_info[i].curve_id, &key_type);
        printf("\r\n  0x%02X |", pPrivate_key_table_info[i].slot_number);
        printf("    %s     |", (pPrivate_key_table_info[i].presence_flag == 0) ? "." : "x");
        printf(" %s |", (pPrivate_key_table_info[i].presence_flag == 0) ? "    .    " : get_key_type_str(key_type));
        printf("  %s |",
               (pPrivate_key_table_info[i].mode_of_operation.generate_key_AC == 0) ? "  Free   " :
               (pPrivate_key_table_info[i].mode_of_operation.generate_key_AC == 1) ? "  Host   " : "Forbidden");
        printf("    %s    |",
               (pPrivate_key_table_info[i].mode_of_operation.sig_gen_over_external_data == 0 &&
                pPrivate_key_table_info[i].mode_of_operation.sig_gen_over_internal_external_data == 0)
               ? "." : "x");
        printf("         %s", (pPrivate_key_table_info[i].mode_of_operation.key_establishment == 0) ? "." : "x");
    }
}

/* ---------------------------------------------------------------------------
 * Host key provisioning control fields
 * -------------------------------------------------------------------------*/
void apps_print_host_key_provisioning_control_fields(stse_Handler_t *pSTSE) {
    stsafea_host_key_provisioning_ctrl_fields_t provisioning_ctrl_fields;
    stse_ReturnCode_t ret;

    ret = stsafea_query_host_key_provisioning_ctrl_fields(pSTSE, &provisioning_ctrl_fields);
    if (ret != STSE_OK) {
        printf("\n\n\r - " PRINT_RED
               "stsafea_query_host_key_provisioning_ctrl_fields ERROR : 0x%04X" PRINT_RESET, ret);
        while (1) ;
    }

    printf("\n\r  Change right | Re-provision | Plaintext | Wrapped anonymous | Wrapped auth key\n\r");
    printf("      %s     |", (provisioning_ctrl_fields.change_right == 0) ? "NO " : "YES");
    printf("     %s      |", (provisioning_ctrl_fields.reprovision   == 0) ? "NO " : "YES");
    printf("    %s    |",    (provisioning_ctrl_fields.plaintext      == 0) ? "NO " : "YES");
    printf("        %s        |", (provisioning_ctrl_fields.wrapped_anonymous == 0) ? "NO " : "YES");
    printf("            0x%02X            ", provisioning_ctrl_fields.wrapped_or_DH_derived_authentication_key);
}

/* ---------------------------------------------------------------------------
 * Generic public key slot configuration
 * -------------------------------------------------------------------------*/
void apps_print_generic_public_key_slot_configuration_flags(stse_Handler_t *pSTSE,
                                                             PLAT_UI8 slot_number) {
    stse_ReturnCode_t ret;
    PLAT_UI8          generic_public_key_presence;
    stse_ecc_key_type_t generic_public_key_type;
    stsafea_generic_public_key_configuration_flags_t generic_public_key_config;

    ret = stsafea_query_generic_public_key_slot_info(pSTSE, slot_number,
                                                      &generic_public_key_presence,
                                                      &generic_public_key_config,
                                                      &generic_public_key_type);
    if (ret != STSE_OK) {
        printf("\n\n\r - " PRINT_RED
               "stsafea_query_generic_public_key_slot_info ERROR : 0x%04X" PRINT_RESET, ret);
        while (1) ;
    }

    printf("\n\r  Slot | Change right | Establish sym key | Volatile KEK | Key presence\n\r");
    printf("  0x%02X |", slot_number);
    printf("     %s     |", (generic_public_key_config.change_right             == 0) ? "NO " : "YES");
    printf("         %s         |", (generic_public_key_config.establish_symmetric_key == 0) ? "FORBIDDEN" : "ALLOWED  ");
    printf("          %s         |", (generic_public_key_config.start_volatile_kek_session == 0) ? "FORBIDDEN" : "ALLOWED  ");
    printf("      %s     ", (generic_public_key_presence == 0) ? "NO " : "YES");
}
