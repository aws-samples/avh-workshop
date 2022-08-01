/* -----------------------------------------------------------------------------
 * Copyright (c) 2021 Arm Limited (or its affiliates). All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * -------------------------------------------------------------------------- */

#include "FreeRTOS.h"
#include "iot_wifi.h"
#include "Driver_WiFi.h"

/* Defines number of the underlying driver (Driver_WiFi#) */
/* Default: 0                                             */
#ifndef WIFI_DRIVER_NUMBER_CONNECT
#define WIFI_DRIVER_NUMBER_CONNECT    0
#endif


/* Reference to the underlying WiFi driver */
extern ARM_DRIVER_WIFI                  ARM_Driver_WiFi_(WIFI_DRIVER_NUMBER_CONNECT);
#define Driver_WIFI                   (&ARM_Driver_WiFi_(WIFI_DRIVER_NUMBER_CONNECT))

static WIFIDeviceMode_t WiFiMode;

/**
  Signal WiFi Events.

  \param[in]     event    \ref wifi_event notification mask
  \param[in]     arg      Pointer to argument of signaled event
  \return        none
*/
void WIFI_SignalEvent (uint32_t event, void *arg) {

}

/**
 * @brief Turns on Wi-Fi.
 *
 * This function turns on Wi-Fi module,initializes the drivers and must be called
 * before calling any other Wi-Fi API
 *
 * @return @ref eWiFiSuccess if Wi-Fi module was successfully turned on, failure code otherwise.
 */
WIFIReturnCode_t WIFI_On (void) {
  WIFIReturnCode_t rc;
  int32_t stat;

  rc = eWiFiFailure;

  stat = Driver_WIFI->Initialize(WIFI_SignalEvent);

  if (stat == ARM_DRIVER_OK) {
    stat = Driver_WIFI->PowerControl (ARM_POWER_FULL);
    
    if (stat == ARM_DRIVER_OK) {
      rc = eWiFiSuccess;
    }
  }

  return rc;
}

/**
 * @brief Turns off Wi-Fi.
 *
 * This function turns off the Wi-Fi module. The Wi-Fi peripheral should be put in a
 * low power or off state in this routine.
 *
 * @return @ref eWiFiSuccess if Wi-Fi module was successfully turned off, failure code otherwise.
 */
WIFIReturnCode_t WIFI_Off (void) {
  WIFIReturnCode_t rc;
  int32_t stat;

  rc = eWiFiFailure;

  stat = Driver_WIFI->PowerControl (ARM_POWER_OFF);

  if (stat == ARM_DRIVER_OK) {
      stat = Driver_WIFI->Uninitialize();

    if (stat == ARM_DRIVER_OK) {
      rc = eWiFiSuccess;
    }
  }

  return rc;
}

/**
 * @brief Connects to the Wi-Fi Access Point (AP) specified in the input.
 *
 * The Wi-Fi should stay connected when the same Access Point it is currently connected to
 * is specified. Otherwise, the Wi-Fi should disconnect and connect to the new Access Point
 * specified. If the new Access Point specifed has invalid parameters, then the Wi-Fi should be
 * disconnected.
 *
 * @param[in] pxNetworkParams Configuration to join AP.
 *
 * @return @ref eWiFiSuccess if connection is successful, failure code otherwise.
 *
 * **Example**
 * @code
 * WIFINetworkParams_t xNetworkParams;
 * WIFIReturnCode_t xWifiStatus;
 * xNetworkParams.pcSSID = "SSID String";
 * xNetworkParams.ucSSIDLength = SSIDLen;
 * xNetworkParams.pcPassword = "Password String";
 * xNetworkParams.ucPasswordLength = PassLength;
 * xNetworkParams.xSecurity = eWiFiSecurityWPA2;
 * xWifiStatus = WIFI_ConnectAP( &( xNetworkParams ) );
 * if(xWifiStatus == eWiFiSuccess)
 * {
 *     //Connected to AP.
 * }
 * @endcode
 *
 * @see WIFINetworkParams_t
 */
WIFIReturnCode_t WIFI_ConnectAP (const WIFINetworkParams_t * const pxNetworkParams) {
  WIFIReturnCode_t rc;
  ARM_WIFI_CONFIG_t config;
  char ssid[32+1];
  char pass[64+1];
  uint32_t i;
  int32_t stat;

  rc = eWiFiFailure;

  /* Create SSID string */
  for (i = 0; i < pxNetworkParams->ucSSIDLength; i++) {
    ssid[i] = pxNetworkParams->ucSSID[i];
  }
  ssid[i] = '\0';

  config.ssid = ssid;
  config.pass = pass;

  /* Set security type */
  switch (pxNetworkParams->xSecurity) {
    case eWiFiSecurityOpen:
      config.security = ARM_WIFI_SECURITY_OPEN;

      pass[0] = '\0';
      break;

    case eWiFiSecurityWEP:
      config.security = ARM_WIFI_SECURITY_WEP;
      break;

    case eWiFiSecurityWPA:
      config.security = ARM_WIFI_SECURITY_WPA;
      break;

    case eWiFiSecurityWPA2:
      config.security = ARM_WIFI_SECURITY_WPA2;

      /* Create password string */
      for (i = 0; i < pxNetworkParams->xPassword.xWPA.ucLength; i++) {
        pass[i] = pxNetworkParams->xPassword.xWPA.cPassphrase[i];
      }
      pass[i] = '\0';
      break;

    default:
      config.security = ARM_WIFI_SECURITY_UNKNOWN; break;
  }

  config.ch = 0U;
  config.wps_method = ARM_WIFI_WPS_METHOD_NONE;

  stat = Driver_WIFI->Activate(0U, &config);
  if (stat == ARM_DRIVER_OK) {
    /* Check connection */
    if (Driver_WIFI->IsConnected() == 1U) {
      rc = eWiFiSuccess;
    }
  }

  return rc;
}

/**
 * @brief Disconnects from the currently connected Access Point.
 *
 * @return @ref eWiFiSuccess if disconnection was successful or if the device is already
 * disconnected, failure code otherwise.
 */
WIFIReturnCode_t WIFI_Disconnect (void) {
  WIFIReturnCode_t rc;
  int32_t stat;

  stat = Driver_WIFI->Deactivate(0U);
  if (stat == ARM_DRIVER_OK) {
    rc = eWiFiSuccess;
  } else {
    rc = eWiFiFailure;
  }

  return rc;
}

/**
 * @brief Resets the Wi-Fi Module.
 *
 * @return @ref eWiFiSuccess if Wi-Fi module was successfully reset, failure code otherwise.
 */
WIFIReturnCode_t WIFI_Reset (void) {
  WIFIReturnCode_t rc;
  int32_t stat;

  Driver_WIFI->PowerControl (ARM_POWER_OFF);

  stat = Driver_WIFI->PowerControl (ARM_POWER_FULL);

  if (stat == ARM_DRIVER_OK) {
    rc = eWiFiSuccess;
  } else {
    rc = eWiFiFailure;
  }
  return rc;
}

/**
 * @brief Sets the Wi-Fi mode.
 *
 * @param[in] xDeviceMode - Mode of the device Station / Access Point /P2P.
 *
 * **Example**
 * @code
 * WIFIReturnCode_t xWifiStatus;
 * xWifiStatus = WIFI_SetMode(eWiFiModeStation);
 * if(xWifiStatus == eWiFiSuccess)
 * {
 *     //device Set to station mode
 * }
 * @endcode
 *
 * @return @ref eWiFiSuccess if Wi-Fi mode was set successfully, failure code otherwise.
 */
WIFIReturnCode_t WIFI_SetMode (WIFIDeviceMode_t xDeviceMode) {
  WIFIReturnCode_t rc;

  WiFiMode = xDeviceMode;

  if (xDeviceMode == eWiFiModeP2P) {
    rc = eWiFiFailure;
  } else {
    rc = eWiFiSuccess;
  }

  return rc;
}

/**
 * @brief Gets the Wi-Fi mode.
 *
 * @param[out] pxDeviceMode - return mode Station / Access Point /P2P
 *
 * **Example**
 * @code
 * WIFIReturnCode_t xWifiStatus;
 * WIFIDeviceMode_t xDeviceMode;
 * xWifiStatus = WIFI_GetMode(&xDeviceMode);
 * if(xWifiStatus == eWiFiSuccess)
 * {
 *    //device mode is xDeviceMode
 * }
 * @endcode
 *
 * @return @ref eWiFiSuccess if Wi-Fi mode was successfully retrieved, failure code otherwise.
 */
WIFIReturnCode_t WIFI_GetMode (WIFIDeviceMode_t *pxDeviceMode) {
  *pxDeviceMode = WiFiMode;

  return eWiFiSuccess;
}

/**
 * @brief Add a Wi-Fi Network profile.
 *
 * Adds a Wi-fi network to the network list in Non Volatile memory.
 *
 * @param[in] pxNetworkProfile - Network profile parameters
 * @param[out] pusIndex - Network profile index in storage
 *
 * @return Index of the profile storage on success, or failure return code on failure.
 *
 * **Example**
 * @code
 * WIFINetworkProfile_t xNetworkProfile = {0};
 * WIFIReturnCode_t xWiFiStatus;
 * uint16_t usIndex;
 * strncpy( xNetworkProfile.cSSID, "SSID_Name", SSIDLen));
 * xNetworkProfile.ucSSIDLength = SSIDLen;
 * strncpy( xNetworkProfile.cPassword, "PASSWORD",PASSLen );
 * xNetworkProfile.ucPasswordLength = PASSLen;
 * xNetworkProfile.xSecurity = eWiFiSecurityWPA2;
 * WIFI_NetworkAdd( &xNetworkProfile, &usIndex );
 * @endcode
 */
WIFIReturnCode_t WIFI_NetworkAdd (const WIFINetworkProfile_t *const pxNetworkProfile, uint16_t *pusIndex) {
  return eWiFiNotSupported;
}

/**
 * @brief Get a Wi-Fi network profile.
 *
 * Gets the Wi-Fi network parameters at the given index from network list in non-volatile
 * memory.
 *
 * @note The WIFINetworkProfile_t data returned must have the the SSID and Password lengths
 * specified as the length without a null terminator.
 *
 * @param[out] pxNetworkProfile - pointer to return network profile parameters
 * @param[in] usIndex - Index of the network profile,
 *                      must be between 0 to wificonfigMAX_NETWORK_PROFILES
 *
 * @return @ref eWiFiSuccess if the network profile was successfully retrieved, failure code
 * otherwise.
 *
 * @see WIFINetworkProfile_t
 *
 * **Example**
 * @code
 * WIFINetworkProfile_t xNetworkProfile = {0};
 * uint16_t usIndex = 3;  //Get profile stored at index 3.
 * WIFI_NetworkGet( &xNetworkProfile, usIndex );
 * @endcode
 */
WIFIReturnCode_t WIFI_NetworkGet (WIFINetworkProfile_t *pxNetworkProfile, uint16_t usIndex) {
  return eWiFiNotSupported;
}

/**
 * @brief Delete a Wi-Fi Network profile.
 *
 * Deletes the Wi-Fi network profile from the network profile list at given index in
 * non-volatile memory
 *
 * @param[in] usIndex - Index of the network profile, must be between 0 to
 *                      wificonfigMAX_NETWORK_PROFILES.
 *
 *                      If wificonfigMAX_NETWORK_PROFILES is the index, then all
 *                      network profiles will be deleted.
 *
 * @return @ref eWiFiSuccess if successful, failure code otherwise. If successful, the
 * interface IP address is copied into the IP address buffer.
 *
 * **Example**
 * @code
 * uint16_t usIndex = 2; //Delete profile at index 2
 * WIFI_NetworkDelete( usIndex );
 * @endcode
 *
 */
WIFIReturnCode_t WIFI_NetworkDelete (uint16_t usIndex) {
  return eWiFiNotSupported;
}

/**
 * @brief Ping an IP address in the network.
 *
 * @param[in] pucIPAddr IP Address array to ping.
 * @param[in] usCount Number of times to ping
 * @param[in] ulIntervalMS Interval in mili-seconds for ping operation
 *
 * @return @ref eWiFiSuccess if ping was successful, other failure code otherwise.
 */
WIFIReturnCode_t WIFI_Ping (uint8_t *pucIPAddr, uint16_t usCount, uint32_t ulIntervalMS ) {
  WIFIReturnCode_t rc;
  int32_t stat;
  const uint8_t *ip;
  uint32_t ip_len;

  /* Current implementation ignores number of times to ping and ping interval */
  (void)usCount;
  (void)ulIntervalMS;

  ip     = pucIPAddr;
  ip_len = 4U;

  stat = Driver_WIFI->Ping (ip, ip_len);

  if (stat == ARM_DRIVER_OK) {
    rc = eWiFiSuccess;
  } else {
    rc = eWiFiFailure;
  }

  return rc;
}

/**
 * @brief Retrieves the Wi-Fi interface's MAC address.
 *
 * @param[out] pucMac MAC Address buffer sized 6 bytes.
 *
 * **Example**
 * @code
 * uint8_t ucMacAddressVal[ wificonfigMAX_BSSID_LEN ];
 * WIFI_GetMAC( &ucMacAddressVal[0] );
 * @endcode
 *
 * @return @ref eWiFiSuccess if the MAC address was successfully retrieved, failure code
 * otherwise. The returned MAC address must be 6 consecutive bytes with no delimitters.
 */
WIFIReturnCode_t WIFI_GetMAC (uint8_t *pucMac) {
  WIFIReturnCode_t rc;
  int32_t stat;
  uint32_t mac_len;

  mac_len = 6U;

  if (WiFiMode == eWiFiModeStation) {
    /* Retrieve station MAC address */
    stat = Driver_WIFI->GetOption (0U, ARM_WIFI_MAC, pucMac, &mac_len);

    if (stat == ARM_DRIVER_OK) {
      rc = eWiFiSuccess;
    } else {
      rc = eWiFiFailure;
    }
  }
  else if (WiFiMode == eWiFiModeAP) {
    /* Retrieve access point MAC address */
    stat = Driver_WIFI->GetOption (1U, ARM_WIFI_MAC, pucMac, &mac_len);

    if (stat == ARM_DRIVER_OK) {
      rc = eWiFiSuccess;
    } else {
      rc = eWiFiFailure;
    }
  }
  else {
    if (WiFiMode == eWiFiModeAPStation) {
      /* Which MAC to provide??? */
      rc = eWiFiNotSupported;
    } else {
      rc = eWiFiFailure;
    }
  }
  return rc;
}

/**
 * @brief Retrieves the host IP address from a host name using DNS.
 *
 * @param[in] pcHost - Host (node) name.
 * @param[in] pucIPAddr - IP Address buffer.
 *
 * @return @ref eWiFiSuccess if the host IP address was successfully retrieved, failure code
 * otherwise.
 *
 * **Example**
 * @code
 * uint8_t ucIPAddr[ 4 ];
 * WIFI_GetHostIP( "amazon.com", &ucIPAddr[0] );
 * @endcode
 */
WIFIReturnCode_t WIFI_GetHostIP (char *pcHost, uint8_t *pucIPAddr) {
  WIFIReturnCode_t rc;
  int32_t stat;
  uint32_t ip;
  uint32_t ip_len;

  ip_len = sizeof(ip);

  stat = Driver_WIFI->SocketGetHostByName (pcHost, ARM_SOCKET_AF_INET, (uint8_t *)&ip, &ip_len);

  if (stat == 0) {
    /* Copy resolved IP address */
    memcpy (pucIPAddr, &ip, ip_len);

    rc = eWiFiSuccess;
  } else {
    rc = eWiFiFailure;
  }

  return rc;
}

/**
 * @brief Perform a Wi-Fi network Scan.
 *
 * @param[in] pxBuffer - Buffer for scan results.
 * @param[in] ucNumNetworks - Number of networks to retrieve in scan result.
 *
 * @return @ref eWiFiSuccess if the Wi-Fi network scan was successful, failure code otherwise.
 *
 * @note The input buffer will have the results of the scan.
 *
 * **Example**
 * @code
 * const uint8_t ucNumNetworks = 10; //Get 10 scan results
 * WIFIScanResult_t xScanResults[ ucNumNetworks ];
 * WIFI_Scan( xScanResults, ucNumNetworks );
 * @endcode
 */
WIFIReturnCode_t WIFI_Scan (WIFIScanResult_t *pxBuffer, uint8_t ucNumNetworks) {
  WIFIReturnCode_t rc;
  int32_t stat;
  ARM_WIFI_SCAN_INFO_t *p;
  uint32_t i;
  uint32_t ssid_len;
  WIFISecurity_t security;
  uint8_t ch;
  uint8_t rssi;

  /* Size of WIFIScanResult_t is the same or larger as ARM_WIFI_SCAN_INFO_t */
  p = (ARM_WIFI_SCAN_INFO_t *)pxBuffer;

  stat = Driver_WIFI->Scan (p, ucNumNetworks);
  
  if (stat >= 0) {
    /* Process received data */
    for (i = 0U; i < stat; i++) {
      ssid_len = strlen (p[i].ssid);

      /* Store security type */
      if (p[i].security == ARM_WIFI_SECURITY_OPEN) {
        security = eWiFiSecurityOpen;
      }
      else if (p[i].security == ARM_WIFI_SECURITY_WEP) {
        security = eWiFiSecurityWEP;
      }
      else if (p[i].security == ARM_WIFI_SECURITY_WPA) {
        security = eWiFiSecurityWPA;
      }
      else if (p[i].security == ARM_WIFI_SECURITY_WPA2) {
        security = eWiFiSecurityWPA2;
      }
      else if (p[i].security == ARM_WIFI_SECURITY_UNKNOWN) {
        /* Unknown security type */
        security = eWiFiSecurityNotSupported;
      }
      else {
        /* Error in the WiFi driver */
        security = eWiFiSecurityNotSupported;
      }

      /* Store channel and signal strength */
      ch   = p[i].ch;
      rssi = p[i].rssi;

      /* Set stored values to fit into WIFIScanResult_t structure */
      pxBuffer[i].ucSSIDLength = (uint8_t)ssid_len;
      pxBuffer[i].xSecurity    = security;
      pxBuffer[i].cRSSI        = rssi;
      pxBuffer[i].ucChannel    = ch;
    }

    rc = eWiFiSuccess;
  }
  else {
    rc = eWiFiFailure;
  }

  return rc;
}

/**
 * @brief Start SoftAP mode.
 *
 * @return @ref eWiFiSuccess if SoftAP was successfully started, failure code otherwise.
 */
WIFIReturnCode_t WIFI_StartAP (void) {
  return eWiFiFailure;
}

/**
 * @brief Stop SoftAP mode.
 *
 * @return @ref eWiFiSuccess if the SoftAP was successfully stopped, failure code otherwise.
 */
WIFIReturnCode_t WIFI_StopAP (void) {
  return eWiFiFailure;
}

/**
 * @brief Configure SoftAP.
 *
 * @param[in] pxNetworkParams - Network parameters to configure AP.
 *
 * @return @ref eWiFiSuccess if SoftAP was successfully configured, failure code otherwise.
 *
 * **Example**
 * @code
 * WIFINetworkParams_t xNetworkParams;
 * xNetworkParams.pcSSID = "SSID_Name";
 * xNetworkParams.pcPassword = "PASSWORD";
 * xNetworkParams.xSecurity = eWiFiSecurityWPA2;
 * xNetworkParams.cChannel = ChannelNum;
 * WIFI_ConfigureAP( &xNetworkParams );
 * @endcode
 */
WIFIReturnCode_t WIFI_ConfigureAP (const WIFINetworkParams_t *const pxNetworkParams) {
  return eWiFiFailure;
}

/**
 * @brief Set the Wi-Fi power management mode.
 *
 * @param[in] xPMModeType - Power mode type.
 *
 * @param[in] pvOptionValue - A buffer containing the value of the option to set
 *                            depends on the mode type
 *                            example - beacon interval in sec
 *
 * @return @ref eWiFiSuccess if the power mode was successfully configured, failure code otherwise.
 */
/* @[declare_wifi_wifi_setpmmode] */
WIFIReturnCode_t WIFI_SetPMMode (WIFIPMMode_t xPMModeType, const void *pvOptionValue ) {
  return eWiFiFailure;
}

/**
 * @brief Get the Wi-Fi power management mode
 *
 * @param[out] pxPMModeType - pointer to get current power mode set.
 *
 * @param[out] pvOptionValue - optional value
 *
 * @return @ref eWiFiSuccess if the power mode was successfully retrieved, failure code otherwise.
 */
/* @[declare_wifi_wifi_getpmmode] */
WIFIReturnCode_t WIFI_GetPMMode (WIFIPMMode_t *pxPMModeType, void *pvOptionValue ) {
  return eWiFiFailure;
}

/**
 * @brief Register a Wi-Fi event Handler.
 *
 * @param[in] xEventType - Wi-Fi event type.
 * @param[in] xHandler - Wi-Fi event handler.
 *
 * @return eWiFiSuccess if registration is successful, failure code otherwise.
 */
WIFIReturnCode_t WIFI_RegisterEvent (WIFIEventType_t xEventType, WIFIEventHandler_t xHandler) {
  return eWiFiNotSupported;
}

/**
 *
 * @brief Check if the Wi-Fi is connected and the AP configuration matches the query.
 *
 * param[in] pxNetworkParams - Network parameters to query, if NULL then just check the
 * Wi-Fi link status.
 */
BaseType_t WIFI_IsConnected (const WIFINetworkParams_t *pxNetworkParams) {
  return eWiFiFailure;
}

/**
 * @brief Start a Wi-Fi scan.
 *
 * This is an asynchronous call, the result will be notified by an event.
 * @see WiFiEventInfoScanDone_t.
 *
 * @param[in] pxScanConfig - Parameters for scan, NULL if default scan
 * (i.e. broadcast scan on all channels).
 *
 * @return eWiFiSuccess if scan was started successfully, failure code otherwise.
 */
WIFIReturnCode_t WIFI_StartScan (WIFIScanConfig_t *pxScanConfig) {
  return eWiFiFailure;
}

/**
 * @brief Get Wi-Fi scan results. It should be called only after scan is completed.  Scan results are sorted in decreasing rssi order.
 *
 * @param[out] pxBuffer - Handle to the READ ONLY scan results buffer.
 * @param[out] ucNumNetworks - Actual number of networks in the scan results.
 *
 * @return eWiFiSuccess if the scan results were got successfully, failure code otherwise.
 */
WIFIReturnCode_t WIFI_GetScanResults (const WIFIScanResult_t **pxBuffer, uint16_t *ucNumNetworks) {
  return eWiFiFailure;
}

/**
 * @brief Connect to the Wi-Fi Access Point (AP) specified in the input.
 *
 * This is an asynchronous call, the result will be notified by an event.
 * @see WiFiEventInfoConnected_t.
 *
 * The Wi-Fi should stay connected when the specified AP is the same as the
 * currently connected AP. Otherwise, the Wi-Fi should disconnect and connect
 * to the specified AP. If the specified AP has invalid parameters, the Wi-Fi
 * should be disconnected.
 *
 * @param[in] pxNetworkParams - Configuration of the targeted AP.
 *
 * @return eWiFiSuccess if connection was started successfully, failure code otherwise.
 */
WIFIReturnCode_t WIFI_StartConnectAP (const WIFINetworkParams_t * pxNetworkParams) {
  return eWiFiFailure;
}

/**
 * @brief Wi-Fi station disconnects from AP.
 *
 * This is an asynchronous call. The result will be notified by an event.
 * @see WiFiEventInfoDisconnected_t.
 *
 * @return eWiFiSuccess if disconnection was started successfully, failure code otherwise.
 */
WIFIReturnCode_t WIFI_StartDisconnect (void) {
  return eWiFiFailure;
}

/**
 * @brief Get Wi-Fi info of the connected AP.
 *
 * This is a synchronous call.
 *
 * @param[out] pxConnectionInfo - Wi-Fi info of the connected AP.
 *
 * @return eWiFiSuccess if connection info was got successfully, failure code otherwise.
 */
WIFIReturnCode_t WIFI_GetConnectionInfo (WIFIConnectionInfo_t * pxConnectionInfo) {
  return eWiFiFailure;
}

/**
 * @brief Get IP configuration (IP address, NetworkMask, Gateway and
 *        DNS server addresses).
 *
 * This is a synchronous call.
 *
 * @param[out] pxIPInfo - Current IP configuration.
 *
 * @return eWiFiSuccess if connection info was got successfully, failure code otherwise.
 */
WIFIReturnCode_t WIFI_GetIPInfo (WIFIIPConfiguration_t * pxIPInfo) {
  return eWiFiFailure;
}

/**
 * @brief Get the RSSI of the connected AP.
 *
 * This only works when the station is connected.
 *
 * @param[out] pcRSSI - RSSI of the connected AP.
 *
 * @return eWiFiSuccess if RSSI was got successfully, failure code otherwise.
 */
WIFIReturnCode_t WIFI_GetRSSI (int8_t *pcRSSI) {
  return eWiFiFailure;
}

/**
 * @brief SoftAP mode get connected station list.
 *
 * @param[out] pxStationList - Buffer for station list, supplied by the caller.
 * @param[in, out] pcStationListSize - Input size of the list, output number of connected stations.
 *
 * @return eWiFiSuccess if stations were got successfully (manybe none),
 * failure code otherwise.
 */
WIFIReturnCode_t WIFI_GetStationList (WIFIStationInfo_t *pxStationList, uint8_t *pcStationListSize) {
  return eWiFiFailure;
}

/**
 * @brief AP mode disconnecting a station.
 *
 * This is an asynchronous call, the result will be notified by an event.
 * @see WiFiEventInfoAPStationDisconnected_t.
 *
 * @param[in] pucMac - MAC Address of the station to be disconnected.
 *
 * @return eWiFiSuccess if disconnection was started successfully, failure code otherwise.
 */
WIFIReturnCode_t WIFI_StartDisconnectStation (uint8_t *pucMac) {
  return eWiFiFailure;
}

/**
 * @brief Set Wi-Fi MAC addresses.
 *
 * The given MAC address will become the station MAC address. The AP MAC address
 * (i.e. BSSID) will be the same MAC address but with the local bit set.
 *
 * @param[in] pucMac - Station MAC address.
 *
 * @return eWiFiSuccess if MAC address was set successfully, failure code otherwise.
 *
 * @note On some platforms the change of MAC address can only take effect after reboot.
 */
WIFIReturnCode_t WIFI_SetMAC (uint8_t * pucMac) {
  return eWiFiFailure;
}

/**
 * @brief Set country based configuration (including channel list, power table)
 *
 * @param[in] pcCountryCode - Country code (null-terminated string, e.g. "US", "CN". See ISO-3166).
 *
 * @return eWiFiSuccess if Country Code is set successfully, failure code otherwise.
 */
WIFIReturnCode_t WIFI_SetCountryCode (const char * pcCountryCode) {
  return eWiFiFailure;
}

/**
 * @brief Get the currently configured country code.
 *
 * @param[out] pcCountryCode - Null-terminated string to hold the country code (see ISO-3166).
 * Must be at least 4 bytes.
 *
 * @return eWiFiSuccess if Country Code is retrieved successfully, failure code otherwise.
 */
WIFIReturnCode_t WIFI_GetCountryCode (char *pcCountryCode) {
  return eWiFiFailure;
}

/**
 * @brief Get the Wi-Fi statistics.
 *
 * @param[out] pxStats - Structure to hold the WiFi statistics.
 *
 * @return eWiFiSuccess if statistics are retrieved successfully, failure code otherwise.
 */
WIFIReturnCode_t WIFI_GetStatistic (WIFIStatisticInfo_t *pxStats) {
  return eWiFiFailure;
}

/**
 * @brief Get the Wi-Fi capability.
 *
 * @param[out] pxCaps - Structure to hold the Wi-Fi capabilities.
 *
 * @return eWiFiSuccess if capabilities are retrieved successfully, failure code otherwise.
 */
WIFIReturnCode_t WIFI_GetCapability (WIFICapabilityInfo_t *pxCaps) {
  return eWiFiFailure;
}
