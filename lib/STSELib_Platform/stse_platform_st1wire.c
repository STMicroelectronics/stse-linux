/******************************************************************************
 * \file    stse_platform_st1wire.c
 * \brief   STSecureElement ST1Wire platform stub for Linux
 * \author  STMicroelectronics - CS application team
 *
 ******************************************************************************
 * \attention
 *
 * <h2><center>&copy; COPYRIGHT 2022 STMicroelectronics</center></h2>
 *
 * This software is licensed under terms that can be found in the LICENSE file in
 * the root directory of this software component.
 * If no LICENSE file comes with this software, it is provided AS-IS.
 *
 ******************************************************************************
 *
 * ST1Wire is a single-wire half-duplex UART variant used by the STSAFE-L device.
 * Unlike I2C (which uses the standard Linux i2c-dev interface), ST1Wire requires
 * platform-specific GPIO bit-banging or a dedicated UART configuration.
 *
 * This file provides stub implementations that return STSE_PLATFORM_BUS_ACK_ERROR
 * so that the library links and loads correctly.  To use STSAFE-L over ST1Wire on
 * a specific platform, replace these stubs with a real implementation using the
 * board's UART or GPIO resources.
 *
 ******************************************************************************
 */

#include "stse_conf.h"
#include "stselib.h"

#ifdef STSE_CONF_USE_ST1WIRE

stse_ReturnCode_t stse_platform_st1wire_init(PLAT_UI8 busID) {
    (void)busID;
    /*
     * Stub: ST1Wire is not implemented on this platform.
     * Implement this function for STSAFE-L support via single-wire UART.
     */
    return STSE_PLATFORM_BUS_ACK_ERROR;
}

stse_ReturnCode_t stse_platform_st1wire_send_start(PLAT_UI8  busID,
                                                   PLAT_UI8  devAddr,
                                                   PLAT_UI16 speed,
                                                   PLAT_UI16 FrameLength) {
    (void)busID;
    (void)devAddr;
    (void)speed;
    (void)FrameLength;
    return STSE_PLATFORM_BUS_ACK_ERROR;
}

stse_ReturnCode_t stse_platform_st1wire_send_continue(PLAT_UI8  busID,
                                                      PLAT_UI8  devAddr,
                                                      PLAT_UI16 speed,
                                                      PLAT_UI8 *pData,
                                                      PLAT_UI16 data_size) {
    (void)busID;
    (void)devAddr;
    (void)speed;
    (void)pData;
    (void)data_size;
    return STSE_PLATFORM_BUS_ACK_ERROR;
}

stse_ReturnCode_t stse_platform_st1wire_send_stop(PLAT_UI8  busID,
                                                  PLAT_UI8  devAddr,
                                                  PLAT_UI16 speed,
                                                  PLAT_UI8 *pData,
                                                  PLAT_UI16 data_size) {
    (void)busID;
    (void)devAddr;
    (void)speed;
    (void)pData;
    (void)data_size;
    return STSE_PLATFORM_BUS_ACK_ERROR;
}

stse_ReturnCode_t stse_platform_st1wire_receive_start(PLAT_UI8  busID,
                                                      PLAT_UI8  devAddr,
                                                      PLAT_UI16 speed,
                                                      PLAT_UI16 frameLength) {
    (void)busID;
    (void)devAddr;
    (void)speed;
    (void)frameLength;
    return STSE_PLATFORM_BUS_ACK_ERROR;
}

stse_ReturnCode_t stse_platform_st1wire_receive_continue(PLAT_UI8  busID,
                                                         PLAT_UI8  devAddr,
                                                         PLAT_UI16 speed,
                                                         PLAT_UI8 *pData,
                                                         PLAT_UI16 data_size) {
    (void)busID;
    (void)devAddr;
    (void)speed;
    (void)pData;
    (void)data_size;
    return STSE_PLATFORM_BUS_ACK_ERROR;
}

stse_ReturnCode_t stse_platform_st1wire_receive_stop(PLAT_UI8  busID,
                                                     PLAT_UI8  devAddr,
                                                     PLAT_UI16 speed,
                                                     PLAT_UI8 *pData,
                                                     PLAT_UI16 data_size) {
    (void)busID;
    (void)devAddr;
    (void)speed;
    (void)pData;
    (void)data_size;
    return STSE_PLATFORM_BUS_ACK_ERROR;
}

#endif /* STSE_CONF_USE_ST1WIRE */
