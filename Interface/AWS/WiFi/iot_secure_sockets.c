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

#include "iot_secure_sockets.h"
#include "iot_wifi.h"
#include "iot_tls.h"
#include "Driver_WiFi.h"


/* Defines number of the underlying driver (Driver_WiFi#) */
/* Default: 0                                             */
#ifndef WIFI_DRIVER_NUMBER_CONNECT
#define WIFI_DRIVER_NUMBER_CONNECT    0
#endif


/* Defines memory allocation and free functions */
#ifndef SSOCK_MALLOC
#define SSOCK_MALLOC                  pvPortMalloc
#endif
#ifndef SSOCK_FREE
#define SSOCK_FREE                    vPortFree
#endif


/* Reference to the underlying WiFi driver */
extern ARM_DRIVER_WIFI                  ARM_Driver_WiFi_(WIFI_DRIVER_NUMBER_CONNECT);
#define Driver_WIFI                   (&ARM_Driver_WiFi_(WIFI_DRIVER_NUMBER_CONNECT))

#define SSOCK_FLAGS_CONNECTED         (1U << 0)
#define SSOCK_FLAGS_USE_TLS           (1U << 1)
#define SSOCK_FLAGS_SHUTDOWN_RD       (1U << 2)
#define SSOCK_FLAGS_SHUTDOWN_WR       (1U << 3)

/* Socket */
struct xSOCKET {
  int32_t id;
  uint32_t flags;
  void *TLS_context;        // TLS context 
  char *destination;        // Destination URL. See SOCKETS_SO_SERVER_NAME_INDICATION.
  char *server_cert;        // Server certificate. See SOCKETS_SO_TRUSTED_SERVER_CERTIFICATE.
  uint32_t server_cert_len; // Server certificate length.
};

static BaseType_t Recv_Cb (void *pvCallerContext, unsigned char * pucReceiveBuffer, size_t xReceiveLength);
static BaseType_t Send_Cb (void *pvCallerContext, const unsigned char *pucData,     size_t xDataLength);

/**
 * @brief Secure Sockets library initialization function.
 *
 * This function does general initialization and setup. It must be called once
 * and only once before calling any other function.
 *
 * @return
 * * `pdPASS` if everything succeeds
 * * `pdFAIL` otherwise.
 */
BaseType_t SOCKETS_Init (void) {
  return pdPASS;
}

/**
 * @brief Creates a TCP socket.
 *
 * See the [FreeRTOS+TCP networking tutorial]
 * (https://freertos.org/FreeRTOS-Plus/FreeRTOS_Plus_TCP/TCP_Networking_Tutorial.html)
 * for more information on TCP sockets.
 *
 * See the [Berkeley Sockets API]
 * (https://en.wikipedia.org/wiki/Berkeley_sockets#Socket_API_functions)
 * in wikipedia
 *
 * @sa SOCKETS_Close()
 *
 * @param[in] lDomain Must be set to SOCKETS_AF_INET. See @ref SocketDomains.
 * @param[in] lType Set to SOCKETS_SOCK_STREAM to create a TCP socket.
 * No other value is valid.  See @ref SocketTypes.
 * @param[in] lProtocol Set to SOCKETS_IPPROTO_TCP to create a TCP socket.
 * No other value is valid. See @ref Protocols.
 *
 * @return
 * * If a socket is created successfully, then the socket handle is
 * returned
 * * @ref SOCKETS_INVALID_SOCKET is returned if an error occurred.
 */

/*
 * This call allocates memory and claims a socket resource.
 */
Socket_t SOCKETS_Socket (int32_t lDomain, int32_t lType, int32_t lProtocol) {
  Socket_t socket;
  int32_t af, type, protocol;

  if ((lDomain != SOCKETS_AF_INET) || (lType != SOCKETS_SOCK_STREAM) || (lProtocol != SOCKETS_IPPROTO_TCP)) {
    socket = SOCKETS_INVALID_SOCKET;
  }
  else {
    socket = (Socket_t)SSOCK_MALLOC(sizeof(struct xSOCKET));
    
    if (socket != NULL) {
      /* Initialize structure member values */
      socket->flags = 0U;
      socket->TLS_context = NULL;
      socket->destination = NULL;
      socket->server_cert = NULL;
      socket->server_cert_len = 0U;
      
      if (socket != NULL) {
        af       = ARM_SOCKET_AF_INET;
        type     = ARM_SOCKET_SOCK_STREAM;
        protocol = ARM_SOCKET_IPPROTO_TCP;

        socket->id = Driver_WIFI->SocketCreate (af, type, protocol);

        if (socket->id < 0) {
          /* Socket create failed, release resources */
          SSOCK_FREE (socket);

          /* Invalidate handle */
          socket = NULL;
        }
      }
    }

    if (socket == NULL) {
      /* Socket create failed, set appropriate error code */
      socket = SOCKETS_INVALID_SOCKET;
    }
  }

  return (socket);
}

/**
 * @brief Bind a TCP socket.
 *
 * See the [FreeRTOS+TCP networking tutorial]
 * (https://freertos.org/FreeRTOS-Plus/FreeRTOS_Plus_TCP/TCP_Networking_Tutorial.html)
 * for more information on TCP sockets.
 *
 * See the [Berkeley Sockets API]
 * (https://en.wikipedia.org/wiki/Berkeley_sockets#Socket_API_functions)
 * in wikipedia
 *
 * @sa SOCKETS_Bind()
 * A pre-configured source port allows customers to bind to the specified local port instead of ephemeral port
 * for security and packet filter reasons.
 *
 * Limitations:
 *
 *   i.  The caller of SOCKETS_Bind() API should make sure the socket address has the correct local IP address for the interface.
 *   ii. Some source ports may be unavailable depending on the TCP/IP stack implementation.
 *
 *       NOTE: If the SOCKETS_Bind() API binds to a source port in ephemeral port range, and the caller calls SOCKETS_Bind() API
 *             before SOCKETS_Connect() API, then a conflict of source port arises as another TCP connection
 *             may pick the the same chosen port via tcp_new_port() API ( by scanning its internal TCP connection list )
 *
 *
 * @param[in] xSocket The handle of the socket to which specified address to be bound.
 * @param[in] pxAddress A pointer to a SocketsSockaddr_t structure that contains
 * the address and port to be bound to the socket.
 * @param[in] xAddressLength Should be set to sizeof( @ref SocketsSockaddr_t ).
 *
 * @return
 * * If the bind was successful then SOCKETS_ERROR_NONE is returned.
 * * If an error occurred, a negative value is returned. @ref SocketsErrors
 */
int32_t SOCKETS_Bind (Socket_t xSocket, SocketsSockaddr_t *pxAddress, Socklen_t xAddressLength) {
  const uint8_t *ip;
  uint32_t ip_len;
  uint16_t port;
  int32_t rc;
  
  if (pxAddress == NULL) {
    rc = SOCKETS_SOCKET_ERROR;
  }
  else {
    ip     = (const uint8_t *)&pxAddress->ulAddress;
    ip_len = 4U;
    port   = SOCKETS_ntohs (pxAddress->usPort);

    rc = Driver_WIFI->SocketBind (xSocket->id, ip, ip_len, port);

    if (rc == 0) {
      rc = SOCKETS_ERROR_NONE;
    } else if (rc == ARM_SOCKET_ESOCK) {
      rc = SOCKETS_SOCKET_ERROR;
    } else if (rc == ARM_SOCKET_EINVAL) {
      rc = SOCKETS_EINVAL;
    } else if (rc == ARM_SOCKET_EADDRINUSE) {
      rc = SOCKETS_EINVAL;
    } else {
      if (rc == ARM_SOCKET_ERROR) {
        rc = SOCKETS_SOCKET_ERROR;
      }
    }
  }
  
  return SOCKETS_SOCKET_ERROR;
}

/**
 * @brief Connects the socket to the specified IP address and port.
 *
 * The socket must first have been successfully created by a call to SOCKETS_Socket().
 *
 * \note To create a secure socket, SOCKETS_SetSockOpt() should be called with the
 * SOCKETS_SO_REQUIRE_TLS option \a before SOCKETS_Connect() is called.
 *
 * If this function returns an error the socket is considered invalid.
 *
 * \warning SOCKETS_Connect() is not safe to be called on the same socket
 * from multiple threads simultaneously with SOCKETS_Connect(),
 * SOCKETS_SetSockOpt(), SOCKETS_Shutdown(), SOCKETS_Close().
 *
 * See the [Berkeley Sockets API]
 * (https://en.wikipedia.org/wiki/Berkeley_sockets#Socket_API_functions)
 * in wikipedia
 *
 * @param[in] xSocket The handle of the socket to be connected.
 * @param[in] pxAddress A pointer to a SocketsSockaddr_t structure that contains the
 * the address to connect the socket to.
 * @param[in] xAddressLength Should be set to sizeof( @ref SocketsSockaddr_t ).
 *
 * @return
 * * @ref SOCKETS_ERROR_NONE if a connection is established.
 * * If an error occurred, a negative value is returned. @ref SocketsErrors
 */
int32_t SOCKETS_Connect (Socket_t xSocket, SocketsSockaddr_t *pxAddress, Socklen_t xAddressLength) {
  const uint8_t *ip;
  uint32_t ip_len;
  uint16_t port;
  int32_t rc;
  TLSParams_t tls_par = { 0 };

  if (xSocket == NULL) {
    rc = SOCKETS_SOCKET_ERROR;
  }
  else {
    if ((xSocket->flags & SSOCK_FLAGS_CONNECTED) == 0U) {
      ip     = (const uint8_t *)&pxAddress->ulAddress;
      ip_len = 4U;
      port   = SOCKETS_ntohs (pxAddress->usPort);

      rc = Driver_WIFI->SocketConnect (xSocket->id, ip, ip_len, port);

      if (rc == 0) {
        /* Socket is connected */
        xSocket->flags |= SSOCK_FLAGS_CONNECTED;

        rc = SOCKETS_ERROR_NONE;
      } else if (rc == ARM_SOCKET_ESOCK) {
        rc = SOCKETS_SOCKET_ERROR;
      } else if (rc == ARM_SOCKET_EINVAL) {
        rc = SOCKETS_EINVAL;
      } else if (rc == ARM_SOCKET_EALREADY) {
        rc = SOCKETS_EINVAL;
      } else if (rc == ARM_SOCKET_EINPROGRESS ) {
        rc = SOCKETS_SOCKET_ERROR;
      } else if (rc == ARM_SOCKET_EISCONN) {
        rc = SOCKETS_EISCONN;
      } else {
        if (rc == ARM_SOCKET_ERROR) {
          rc = SOCKETS_SOCKET_ERROR;
        }
      }

    }
    else {
      /* Socket is already connected */
      rc = SOCKETS_SOCKET_ERROR;
    }
  }

  if (rc == SOCKETS_ERROR_NONE) {
    if ((xSocket->flags & SSOCK_FLAGS_USE_TLS) != 0U) {
      /* Initialize TLS */
      tls_par.ulSize                    = sizeof(tls_par);
      tls_par.pcDestination             = xSocket->destination;
      tls_par.pcServerCertificate       = xSocket->server_cert;
      tls_par.ulServerCertificateLength = xSocket->server_cert_len;
      tls_par.pvCallerContext           = (void *)xSocket;
      tls_par.pxNetworkRecv             = &Recv_Cb;
      tls_par.pxNetworkSend             = &Send_Cb;

      if (TLS_Init (&xSocket->TLS_context, &tls_par) == pdFREERTOS_ERRNO_NONE) {
        /* Initiate TLS handshake */
        if (TLS_Connect (xSocket->TLS_context) != pdFREERTOS_ERRNO_NONE) {
          /* Handshake failed */
          rc = SOCKETS_TLS_HANDSHAKE_ERROR;
        }
      }
      else {
        /* TLS initialization failed */
        rc = SOCKETS_TLS_INIT_ERROR;
      }
    }
  }
  
  return (rc);
}

/**
 * @brief Receive data from a TCP socket.
 *
 * The socket must have already been created using a call to SOCKETS_Socket()
 * and connected to a remote socket using SOCKETS_Connect().
 *
 * See the [Berkeley Sockets API]
 * (https://en.wikipedia.org/wiki/Berkeley_sockets#Socket_API_functions)
 * in wikipedia
 *
 * @param[in] xSocket The handle of the socket from which data is being received.
 * @param[out] pvBuffer The buffer into which the received data will be placed.
 * @param[in] xBufferLength The maximum number of bytes which can be received.
 * pvBuffer must be at least xBufferLength bytes long.
 * @param[in] ulFlags Not currently used. Should be set to 0.
 *
 * @return
 * * If the receive was successful then the number of bytes received (placed in the
 *   buffer pointed to by pvBuffer) is returned.
 * * If a timeout occurred before data could be received then 0 is returned (timeout
 *   is set using @ref SOCKETS_SO_RCVTIMEO).
 * * If an error occurred, a negative value is returned. @ref SocketsErrors
 */
int32_t SOCKETS_Recv (Socket_t xSocket, void *pvBuffer, size_t xBufferLength, uint32_t ulFlags) {
  int32_t rc;

  if (xSocket == NULL) {
    rc = SOCKETS_SOCKET_ERROR;
  }
  else {
    if ((xSocket->flags & SSOCK_FLAGS_SHUTDOWN_RD) == 0U) {
      /* Receive is allowed */
      if ((xSocket->flags & SSOCK_FLAGS_USE_TLS) == 0U) {
        /* Non-secure receive */
        rc = Driver_WIFI->SocketRecv (xSocket->id, pvBuffer, xBufferLength);

        if (rc < 0) {
          if (rc == ARM_SOCKET_ESOCK) {
            /* Invalid socket */
            rc = SOCKETS_SOCKET_ERROR;
          } else if (rc == ARM_SOCKET_EINVAL) {
            /* Invalid argument */
            rc = SOCKETS_EINVAL;
          } else if (rc == ARM_SOCKET_ENOTCONN) {
            /* Socket is not connected */
            rc = SOCKETS_ENOTCONN;
          } else if (rc == ARM_SOCKET_ECONNRESET) {
            /* Connection reset by the peer */
            rc = SOCKETS_ECLOSED;
          } else if (rc == ARM_SOCKET_ECONNABORTED) {
            /* Connection aborted locally */
            rc = SOCKETS_ECLOSED;
          } else if (rc == ARM_SOCKET_EAGAIN) {
            /* Operation would block or timed out */
            rc = SOCKETS_EWOULDBLOCK;
          } else {
            /* Unspecified error */
            rc = SOCKETS_SOCKET_ERROR;
          }
        }
      }
      else {
        /* Secure receive */
        rc = TLS_Recv (xSocket->TLS_context, pvBuffer, xBufferLength);

        if (rc < 0) {
          rc = SOCKETS_TLS_RECV_ERROR;
        }
      }
    }
    else {
      /* Socket is closed for read */
      rc = SOCKETS_ECLOSED;
    }
  }

  return (rc);
}

/**
 * @brief Transmit data to the remote socket.
 *
 * The socket must have already been created using a call to SOCKETS_Socket() and
 * connected to a remote socket using SOCKETS_Connect().
 *
 * See the [Berkeley Sockets API]
 * (https://en.wikipedia.org/wiki/Berkeley_sockets#Socket_API_functions)
 * in wikipedia
 *
 * @param[in] xSocket The handle of the sending socket.
 * @param[in] pvBuffer The buffer containing the data to be sent.
 * @param[in] xDataLength The length of the data to be sent.
 * @param[in] ulFlags Not currently used. Should be set to 0.
 *
 * @return
 * * On success, the number of bytes actually sent is returned.
 * * If an error occurred, a negative value is returned. @ref SocketsErrors
 */
int32_t SOCKETS_Send (Socket_t xSocket, const void *pvBuffer, size_t xDataLength, uint32_t ulFlags) {
  int32_t rc;

  if (xSocket == NULL) {
    rc = SOCKETS_SOCKET_ERROR;
  }
  else {
    if ((xSocket->flags & SSOCK_FLAGS_SHUTDOWN_WR) == 0U) {
      /* Write is allowed */
      if ((xSocket->flags & SSOCK_FLAGS_USE_TLS) == 0U) {
        /* Non-secure write */
        rc = Driver_WIFI->SocketSend (xSocket->id, pvBuffer, xDataLength);

        if (rc < 0) {
          if (rc == ARM_SOCKET_ESOCK) {
            /* Invalid socket */
            rc = SOCKETS_SOCKET_ERROR;
          } else if (rc == ARM_SOCKET_EINVAL) {
            /* Invalid argument */
            rc = SOCKETS_EINVAL;
          } else if (rc == ARM_SOCKET_ENOTCONN) {
            /* Socket is not connected */
            rc = SOCKETS_ENOTCONN;
          } else if (rc == ARM_SOCKET_ECONNRESET) {
            /* Connection reset by the peer */
            rc = SOCKETS_ECLOSED;
          } else if (rc == ARM_SOCKET_ECONNABORTED) {
            /* Connection aborted locally */
            rc = SOCKETS_ECLOSED;
          } else if (rc == ARM_SOCKET_EAGAIN) {
            /* Operation would block or timed out */
            rc = SOCKETS_EWOULDBLOCK;
          } else {
            /* Unspecified error */
            rc = SOCKETS_SOCKET_ERROR;
          }
        }
      }
      else {
        /* Secure receive */
        rc = TLS_Send (xSocket->TLS_context, pvBuffer, xDataLength);

        if (rc < 0) {
          rc = SOCKETS_TLS_SEND_ERROR;
        }
      }
    }
    else {
      /* Socket is closed for write */
      rc = SOCKETS_ECLOSED;
    }
  }

  return (rc);
}

/**
 * @brief Closes all or part of a full-duplex connection on the socket.
 *
 * Disable reads and writes on a connected TCP socket. A connected TCP socket must be gracefully
 * shut down before it can be closed.
 *
 * See the [Berkeley Sockets API]
 * (https://en.wikipedia.org/wiki/Berkeley_sockets#Socket_API_functions)
 * in wikipedia
 *
 * \warning SOCKETS_Shutdown() is not safe to be called on the same socket
 * from multiple threads simultaneously with SOCKETS_Connect(),
 * SOCKETS_SetSockOpt(), SOCKETS_Shutdown(), SOCKETS_Close().
 *
 * @param[in] xSocket The handle of the socket to shutdown.
 * @param[in] ulHow SOCKETS_SHUT_RD, SOCKETS_SHUT_WR or SOCKETS_SHUT_RDWR.
 * @ref ShutdownFlags
 *
 * @return
 * * If the operation was successful, 0 is returned.
 * * If an error occurred, a negative value is returned. @ref SocketsErrors
 */
int32_t SOCKETS_Shutdown (Socket_t xSocket, uint32_t ulHow) {
  int32_t rc;
  
  if (xSocket == NULL) {
    rc = SOCKETS_SOCKET_ERROR;
  }
  else {
    rc = SOCKETS_ERROR_NONE;

    switch (ulHow) {
      case SOCKETS_SHUT_RD:
        /* Further receive calls on this socket should return error */
        xSocket->flags |= SSOCK_FLAGS_SHUTDOWN_RD;
        break;

      case SOCKETS_SHUT_WR:
        /* Further send calls on this socket should return error */
        xSocket->flags |= SSOCK_FLAGS_SHUTDOWN_WR;
        break;

      case SOCKETS_SHUT_RDWR:
        /* Further send or receive calls on this socket should return error */
        xSocket->flags |= SSOCK_FLAGS_SHUTDOWN_RD | SSOCK_FLAGS_SHUTDOWN_WR;
        break;

      default:
        rc = SOCKETS_EINVAL;
    }
  }

  return (rc);
}

/**
 * @brief Closes the socket and frees the related resources.
 *
 * A socket should be shutdown gracefully before it is closed, and cannot be used after it has been closed.
 *
 * See the [Berkeley Sockets API]
 * (https://en.wikipedia.org/wiki/Berkeley_sockets#Socket_API_functions)
 * in wikipedia
 *
 * \warning SOCKETS_Close() is not safe to be called on the same socket
 * from multiple threads simultaneously with SOCKETS_Connect(),
 * SOCKETS_SetSockOpt(), SOCKETS_Shutdown(), SOCKETS_Close().
 *
 * @param[in] xSocket The handle of the socket to close.
 *
 * @return
 * * On success, 0 is returned.
 * * If an error occurred, a negative value is returned. @ref SocketsErrors
 */
int32_t SOCKETS_Close(Socket_t xSocket) {
  int32_t rc;

  if (xSocket == NULL ) {
    rc = SOCKETS_ERROR_NONE;
  }
  else {
    rc = Driver_WIFI->SocketClose (xSocket->id);

    if (rc == 0) {
      /* Socket is closed */
    } else if (rc == ARM_SOCKET_ESOCK) {
      rc = SOCKETS_SOCKET_ERROR;
    } else if (rc == ARM_SOCKET_EAGAIN) {
      rc = SOCKETS_SOCKET_ERROR;
    } else {
      rc = SOCKETS_SOCKET_ERROR;
    }

    /* Cleanup resources */
    if (xSocket->server_cert != NULL) {
      SSOCK_FREE (xSocket->server_cert);
    }

    if (xSocket->destination != NULL) {
      SSOCK_FREE (xSocket->destination);
    }

    if ((xSocket->flags & SSOCK_FLAGS_USE_TLS) != 0U) {
      TLS_Cleanup (xSocket->TLS_context);
    }

    /* Destroy socket */
    SSOCK_FREE (xSocket);
  }

  return (rc);
}

/**
 * @brief Manipulates the options for the socket.
 *
 * See the [Berkeley Sockets API]
 * (https://en.wikipedia.org/wiki/Berkeley_sockets#Socket_API_functions)
 * in wikipedia
 *
 * @param[in] xSocket The handle of the socket to set the option for.
 * @param[in] lLevel Not currently used. Should be set to 0.
 * @param[in] lOptionName See @ref SetSockOptOptions.
 * @param[in] pvOptionValue A buffer containing the value of the option to set.
 * @param[in] xOptionLength The length of the buffer pointed to by pvOptionValue.
 *
 * \warning SOCKETS_Close() is not safe to be called on the same socket
 * from multiple threads simultaneously with SOCKETS_Connect(),
 * SOCKETS_SetSockOpt(), SOCKETS_Shutdown(), SOCKETS_Close().
 *
 * @note Socket option support and possible values vary by port. Please see
 * PORT_SPECIFIC_LINK to check the valid options and limitations of your device.
 *
 *  - Berkeley Socket Options
 *    - @ref SOCKETS_SO_RCVTIMEO
 *      - Sets the receive timeout
 *      - pvOptionValue (TickType_t) is the number of milliseconds that the
 *      receive function should wait before timing out.
 *      - Setting pvOptionValue = 0 causes receive to wait forever.
 *      - See PORT_SPECIFIC_LINK for device limitations.
 *    - @ref SOCKETS_SO_SNDTIMEO
 *      - Sets the send timeout
 *      - pvOptionValue (TickType_t) is the number of milliseconds that the
 *      send function should wait before timing out.
 *      - Setting pvOptionValue = 0 causes send to wait forever.
 *      - See PORT_SPECIFIC_LINK for device limitations.
 *  - Non-Standard Options
 *    - @ref SOCKETS_SO_NONBLOCK
 *      - Makes a socket non-blocking.
 *      - Non-blocking connect is not supported - socket option should be
 *        called after connect.
 *      - pvOptionValue is ignored for this option.
 *    - @ref SOCKETS_SO_WAKEUP_CALLBACK
 *      - Set the callback to be called whenever there is data available on
 *      the socket for reading
 *      - This option provides an asynchronous way to handle received data
 *      - pvOptionValue is a pointer to the callback function
 *      - See PORT_SPECIFIC_LINK for device limitations.
 *  - Security Sockets Options
 *    - @ref SOCKETS_SO_REQUIRE_TLS
 *      - Use TLS for all connect, send, and receive on this socket.
 *      - This socket options MUST be set for TLS to be used, even
 *        if other secure socket options are set.
 *      - This socket option should be set before SOCKETS_Connect() is
 *        called.
 *      - pvOptionValue is ignored for this option.
 *    - @ref SOCKETS_SO_TRUSTED_SERVER_CERTIFICATE
 *      - Set the root of trust server certificate for the socket.
 *      - This socket option only takes effect if @ref SOCKETS_SO_REQUIRE_TLS
 *        is also set.  If @ref SOCKETS_SO_REQUIRE_TLS is not set,
 *        this option will be ignored.
 *      - pvOptionValue is a pointer to the formatted server certificate.
 *        TODO: Link to description of how to format certificates with \n
 *      - xOptionLength (BaseType_t) is the length of the certificate
 *        in bytes.
 *    - @ref SOCKETS_SO_SERVER_NAME_INDICATION
 *      - Use Server Name Indication (SNI)
 *      - This socket option only takes effect if @ref SOCKETS_SO_REQUIRE_TLS
 *        is also set.  If @ref SOCKETS_SO_REQUIRE_TLS is not set,
 *        this option will be ignored.
 *      - pvOptionValue is a pointer to a string containing the hostname
 *      - xOptionLength is the length of the hostname string in bytes.
 *    - @ref SOCKETS_SO_ALPN_PROTOCOLS
 *      - Negotiate an application protocol along with TLS.
 *      - The ALPN list is expressed as an array of NULL-terminated ANSI
 *        strings.
 *      - xOptionLength is the number of items in the array.
 *    - @ref SOCKETS_SO_TCPKEEPALIVE
 *      - Enable or disable the TCP keep-alive functionality.
 *      - pvOptionValue is the value to enable or disable Keepalive.
 *    - @ref SOCKETS_SO_TCPKEEPALIVE_INTERVAL
 *      - Set the time in seconds between individual TCP keep-alive probes.
 *      - pvOptionValue is the time in seconds.
 *    - @ref SOCKETS_SO_TCPKEEPALIVE_COUNT
 *      - Set the maximum number of keep-alive probes TCP should send before
 *        dropping the connection.
 *      - pvOptionValue is the maximum number of keep-alive probes.
 *    - @ref SOCKETS_SO_TCPKEEPALIVE_IDLE_TIME
 *      - Set the time in seconds for which the connection needs to remain idle
 *        before TCP starts sending keep-alive probes.
 *      - pvOptionValue is the time in seconds.
 *
 * @return
 * * On success, 0 is returned.
 * * If an error occurred, a negative value is returned. @ref SocketsErrors
 */
int32_t SOCKETS_SetSockOpt (Socket_t xSocket, int32_t lLevel, int32_t lOptionName, const void *pvOptionValue, size_t xOptionLength) {
  int32_t rc;
  
  if (xSocket == NULL) {
    rc = SOCKETS_SOCKET_ERROR;
  }
  else {
    switch (lOptionName) {
      case SOCKETS_SO_RCVTIMEO:
        rc = Driver_WIFI->SocketSetOpt (xSocket->id, ARM_SOCKET_SO_RCVTIMEO, pvOptionValue, xOptionLength);

        if (rc == 0) {
          rc = SOCKETS_ERROR_NONE;
        } else if (rc == ARM_SOCKET_ESOCK) {
          rc = SOCKETS_SOCKET_ERROR;
        } else if (rc == ARM_SOCKET_EINVAL) {
          rc = SOCKETS_EINVAL;
        } else if (rc == ARM_SOCKET_ENOTSUP) {
          rc = SOCKETS_SOCKET_ERROR;
        } else {
          if (rc == ARM_SOCKET_ERROR) {
            rc = SOCKETS_SOCKET_ERROR;
          }
        }
        break;

      case SOCKETS_SO_SNDTIMEO:
        rc = Driver_WIFI->SocketSetOpt (xSocket->id, ARM_SOCKET_SO_SNDTIMEO, pvOptionValue, xOptionLength);

        if (rc == 0) {
          rc = SOCKETS_ERROR_NONE;
        } else if (rc == ARM_SOCKET_ESOCK) {
          rc = SOCKETS_SOCKET_ERROR;
        } else if (rc == ARM_SOCKET_EINVAL) {
          rc = SOCKETS_EINVAL;
        } else if (rc == ARM_SOCKET_ENOTSUP) {
          rc = SOCKETS_SOCKET_ERROR;
        } else {
          if (rc == ARM_SOCKET_ERROR) {
            rc = SOCKETS_SOCKET_ERROR;
          }
        }
        break;

      case SOCKETS_SO_NONBLOCK:
        rc = Driver_WIFI->SocketSetOpt (xSocket->id, ARM_SOCKET_IO_FIONBIO, pvOptionValue, xOptionLength);

        if (rc == 0) {
          rc = SOCKETS_ERROR_NONE;
        } else if (rc == ARM_SOCKET_ESOCK) {
          rc = SOCKETS_SOCKET_ERROR;
        } else if (rc == ARM_SOCKET_EINVAL) {
          rc = SOCKETS_EINVAL;
        } else if (rc == ARM_SOCKET_ENOTSUP) {
          rc = SOCKETS_SOCKET_ERROR;
        } else {
          if (rc == ARM_SOCKET_ERROR) {
            rc = SOCKETS_SOCKET_ERROR;
          }
        }
        break;

      case SOCKETS_SO_WAKEUP_CALLBACK:
        break;

      case SOCKETS_SO_REQUIRE_TLS:
        if ((xSocket->flags & SSOCK_FLAGS_CONNECTED) == 0) {
          xSocket->flags |= SSOCK_FLAGS_USE_TLS;

          rc = SOCKETS_ERROR_NONE;
        }
        else {
          /* TLS must be set before the connection is established */
          rc = SOCKETS_SOCKET_ERROR;
        }
        break;

      case SOCKETS_SO_TRUSTED_SERVER_CERTIFICATE:
        if ((xSocket->flags & SSOCK_FLAGS_CONNECTED) == 0) {
          xSocket->server_cert = (char *)SSOCK_MALLOC(xOptionLength);

          if (xSocket->server_cert != NULL) {
            /* Copy certificate */
            memcpy (xSocket->server_cert, pvOptionValue, xOptionLength);

            /* Set certificate length */
            xSocket->server_cert_len = xOptionLength;

            rc = SOCKETS_ERROR_NONE;
          }
          else {
            /* Out of memory */
            rc = SOCKETS_ENOMEM;
          }
        }
        else {
          /* Trusted server certificate must be set before the connection is established */
          rc = SOCKETS_SOCKET_ERROR;
        }
        break;

      case SOCKETS_SO_SERVER_NAME_INDICATION:
        if ((xSocket->flags & SSOCK_FLAGS_CONNECTED) == 0) {
          xSocket->destination = (char *)SSOCK_MALLOC(xOptionLength + 1U);

          if (xSocket->destination != NULL) {
            /* Copy destination string  */
            memcpy (xSocket->destination, pvOptionValue, xOptionLength);
            
            /* Add NUL terminator */
            xSocket->destination[xOptionLength] = '\0';

            rc = SOCKETS_ERROR_NONE;
          }
          else {
            /* Out of memory */
            rc = SOCKETS_ENOMEM;
          }
        }
        else {
          /* Server name indication must be set before the connection is established */
          rc = SOCKETS_SOCKET_ERROR;
        }
        break;

      case SOCKETS_SO_ALPN_PROTOCOLS:
      case SOCKETS_SO_TCPKEEPALIVE:
      case SOCKETS_SO_TCPKEEPALIVE_INTERVAL:
      case SOCKETS_SO_TCPKEEPALIVE_COUNT:
      case SOCKETS_SO_TCPKEEPALIVE_IDLE_TIME:
      default:
        rc = SOCKETS_SOCKET_ERROR;
    }
  }

  return (rc);
}

/**
 * @brief Resolve a host name using Domain Name Service.
 *
 * See the [Berkeley Sockets API]
 * (https://en.wikipedia.org/wiki/Berkeley_sockets#Socket_API_functions)
 * in wikipedia
 *
 * @param[in] pcHostName The host name to resolve.
 * @return
 * * The IPv4 address of the specified host.
 * * If an error has occurred, 0 is returned.
 */
uint32_t SOCKETS_GetHostByName (const char *pcHostName) {
  uint32_t ip;
  uint32_t ip_len;
  int32_t rval;

  ip_len = sizeof(ip);

  rval = Driver_WIFI->SocketGetHostByName (pcHostName, ARM_SOCKET_AF_INET, (uint8_t *)&ip, &ip_len);

  if (rval != 0) {
    ip = 0U;
  }

  return (ip);
}


/**
 * @brief Defines callback type for receiving bytes from the network.
 *
 * @param[in] pvCallerContext Opaque context handle provided by caller.
 * @param[out] pucReceiveBuffer Buffer to fill with received data.
 * @param[in] xReceiveLength Length of previous parameter in bytes.
 *
 * @return The number of bytes actually read.
 */
static BaseType_t Recv_Cb (void *pvCallerContext, unsigned char * pucReceiveBuffer, size_t xReceiveLength) {
  Socket_t xSocket;
  int32_t rc;

  xSocket = (Socket_t)pvCallerContext;

  rc = Driver_WIFI->SocketRecv (xSocket->id, pucReceiveBuffer, xReceiveLength);

  if (rc < 0) {
    if (rc == ARM_SOCKET_ESOCK) {
      /* Invalid socket */
      rc = SOCKETS_SOCKET_ERROR;
    } else if (rc == ARM_SOCKET_EINVAL) {
      /* Invalid argument */
      rc = SOCKETS_EINVAL;
    } else if (rc == ARM_SOCKET_ENOTCONN) {
      /* Socket is not connected */
      rc = SOCKETS_ENOTCONN;
    } else if (rc == ARM_SOCKET_ECONNRESET) {
      /* Connection reset by the peer */
      rc = SOCKETS_ECLOSED;
    } else if (rc == ARM_SOCKET_ECONNABORTED) {
      /* Connection aborted locally */
      rc = SOCKETS_ECLOSED;
    } else if (rc == ARM_SOCKET_EAGAIN) {
      /* Operation would block or timed out */
      rc = SOCKETS_EWOULDBLOCK;
    } else {
      /* Unspecified error */
      rc = SOCKETS_SOCKET_ERROR;
    }

    if (rc == SOCKETS_EWOULDBLOCK) {
      rc = 0;
    }
  }

  return (rc);
}

/**
 * @brief Defines callback type for sending bytes to the network.
 *
 * @param[in] pvCallerContext Opaque context handle provided by caller.
 * @param[out] pucReceiveBuffer Buffer of data to send.
 * @param[in] xReceiveLength Length of previous parameter in bytes.
 *
 * @return The number of bytes actually sent.
 */
static BaseType_t Send_Cb (void *pvCallerContext, const unsigned char *pucData, size_t xDataLength) {
  Socket_t xSocket;
  int32_t rc;

  xSocket = (Socket_t)pvCallerContext;

  rc = Driver_WIFI->SocketSend (xSocket->id, pucData, xDataLength);

  if (rc < 0) {
    if (rc == ARM_SOCKET_ESOCK) {
      /* Invalid socket */
      rc = SOCKETS_SOCKET_ERROR;
    } else if (rc == ARM_SOCKET_EINVAL) {
      /* Invalid argument */
      rc = SOCKETS_EINVAL;
    } else if (rc == ARM_SOCKET_ENOTCONN) {
      /* Socket is not connected */
      rc = SOCKETS_ENOTCONN;
    } else if (rc == ARM_SOCKET_ECONNRESET) {
      /* Connection reset by the peer */
      rc = SOCKETS_ECLOSED;
    } else if (rc == ARM_SOCKET_ECONNABORTED) {
      /* Connection aborted locally */
      rc = SOCKETS_ECLOSED;
    } else if (rc == ARM_SOCKET_EAGAIN) {
      /* Operation would block or timed out */
      rc = SOCKETS_EWOULDBLOCK;
    } else {
      /* Unspecified error */
      rc = SOCKETS_SOCKET_ERROR;
    }
  }

  return (rc);
}
