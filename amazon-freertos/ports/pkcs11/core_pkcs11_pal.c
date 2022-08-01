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

/*
  Note: This is demo implementation using RAM to load and store certificates.
        Such implementation should only be used during development phase.
        Production ready application should store certificates into flash or
        other non volatile memory.
*/

#include "iot_crypto.h"
#include "core_pkcs11.h"
#include "core_pkcs11_pal.h"
#include "core_pkcs11_config.h"

/* Certificates */
#include "aws_clientcredential_keys.h"

enum eObjectHandles {
  eInvalidHandle = 0,       /* Invalid handle                */
  eDevicePrivateKey,        /* Device private key            */
  eDevicePublicKey,         /* Device public key             */
  eDeviceCertificate,       /* Device certificate            */
  eCodeSigningKey,          /* Code verification key         */
  eJitpCertificate,         /* Just-In-Time-Provisioning key */
  eRootCertificate          /* Trusted root certificate      */
};

#define CERTIFICATE_PEM_MAX_SIZE  2048

#define CERTIFICATE_STATUS_PRESENT   1
#define CERTIFICATE_STATUS_PRIVATE   2

typedef struct {
  CK_CHAR  Pem[CERTIFICATE_PEM_MAX_SIZE];
  uint16_t Size;
  uint16_t Status;
} Certificate_t;

typedef struct {
  Certificate_t *ClientCertificate;
  Certificate_t *ClientPrivateKey;
  Certificate_t *CodeVerifyKey;
} PKCS11_Keys_t;

Certificate_t ClientCertificate;
Certificate_t ClientPrivateKey;
Certificate_t CodeVerifyKey;

PKCS11_Keys_t PKCS11_Key[] = {
  &ClientCertificate,
  &ClientPrivateKey,
  &CodeVerifyKey
};

static CK_OBJECT_HANDLE handle_from_label (uint8_t *label);
static Certificate_t   *cert_from_handle  (CK_OBJECT_HANDLE h);


/**
 * @brief Initializes the PKCS #11 PAL.
 *
 * This is always called first in C_Initialize if the module is not already
 * initialized.
 *
 * @return CKR_OK on success.
 * CKR_FUNCTION_FAILED on failure.
 */
CK_RV PKCS11_PAL_Initialize (void) {
  Certificate_t *cert;

  /* Copy device certificate */
  cert = PKCS11_Key->ClientCertificate;

  memcpy (cert->Pem, keyCLIENT_CERTIFICATE_PEM, sizeof(keyCLIENT_CERTIFICATE_PEM));
  cert->Size   = sizeof(keyCLIENT_CERTIFICATE_PEM);
  cert->Status = CERTIFICATE_STATUS_PRESENT;

  /* Copy private key */
  cert = PKCS11_Key->ClientPrivateKey;

  memcpy (cert->Pem, keyCLIENT_PRIVATE_KEY_PEM, sizeof(keyCLIENT_PRIVATE_KEY_PEM));
  cert->Size   = sizeof(keyCLIENT_PRIVATE_KEY_PEM);
  cert->Status = CERTIFICATE_STATUS_PRESENT | CERTIFICATE_STATUS_PRIVATE;

  CRYPTO_Init();
  return CKR_OK;
}


/**
 * @brief Saves an object in non-volatile storage.
 *
 * Port-specific file write for cryptographic information.
 *
 * @param[in] pxLabel       Attribute containing label of the object to be stored.
 * @param[in] pucData       The object data to be saved.
 * @param[in] ulDataSize    Size (in bytes) of object data.
 *
 * @return The object handle if successful.
 * eInvalidHandle = 0 if unsuccessful.
 */
CK_OBJECT_HANDLE PKCS11_PAL_SaveObject (CK_ATTRIBUTE_PTR pxLabel, CK_BYTE_PTR pucData, CK_ULONG ulDataSize) {
  CK_OBJECT_HANDLE h;
  Certificate_t *cert;

  if (ulDataSize > CERTIFICATE_PEM_MAX_SIZE) {
    h = eInvalidHandle;
  }
  else {
    if (strcmp (pxLabel->pValue, pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS) == 0) {
      /* Device private key label is specified */
      cert = PKCS11_Key->ClientPrivateKey;

      /* Copy certificate */
      memcpy (cert->Pem, pucData, ulDataSize);

      /* Set its size and status */
      cert->Size   = ulDataSize;
      cert->Status = CERTIFICATE_STATUS_PRESENT;
      
      /* Return certificate handle */
      h = eDevicePrivateKey;
    }
    else if (strcmp (pxLabel->pValue, pkcs11configLABEL_DEVICE_PUBLIC_KEY_FOR_TLS) == 0) {
      /* Device public key label is specified */

      /* Currently not supported */
      h = eInvalidHandle;
    }
    else if (strcmp (pxLabel->pValue, pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS) == 0) {
      /* Client certificate label is specified */
      cert = PKCS11_Key->ClientCertificate;

      /* Copy certificate */
      memcpy (cert->Pem, pucData, ulDataSize);

      /* Set its size and status */
      cert->Size   = ulDataSize;
      cert->Status = CERTIFICATE_STATUS_PRESENT;
      
      /* Return certificate handle */
      h = eDeviceCertificate;
    }
    else if (strcmp (pxLabel->pValue, pkcs11configLABEL_CODE_VERIFICATION_KEY) == 0) {
      /* Code verification key label is specified */
      cert = PKCS11_Key->CodeVerifyKey;

      /* Copy certificate */
      memcpy (cert->Pem, pucData, ulDataSize);

      /* Set its size and status */
      cert->Size   = ulDataSize;
      cert->Status = CERTIFICATE_STATUS_PRESENT;
      
      /* Return certificate handle */
      h = eCodeSigningKey;
    }
    else if (strcmp (pxLabel->pValue, pkcs11configLABEL_JITP_CERTIFICATE) == 0) {
      /* Just-In-Time-Provisioning key label is specified */

      /* Currently not supported */
      h = eInvalidHandle;
    }
    else if (strcmp (pxLabel->pValue, pkcs11configLABEL_ROOT_CERTIFICATE) == 0) {
      /* AWS Trusted Root Certificate key label is specified */

      /* Currently not supported */
      h = eInvalidHandle;
    }
    else {
      /* Unknown label */
      h = eInvalidHandle;
    }
  }

  return h;
}


/**
 * @brief Delete an object from NVM.
 *
 * @param[in] xHandle       Handle to a PKCS #11 object.
 */
CK_RV PKCS11_PAL_DestroyObject (CK_OBJECT_HANDLE xHandle) {
  CK_RV rval;
  Certificate_t *cert;

  cert = cert_from_handle (xHandle);

  if (cert == NULL) {
    rval = CKR_OBJECT_HANDLE_INVALID;
  }
  else {
    /* Clear certificate data */
    memset (cert->Pem, 0x00, cert->Size);
    /* Clear certificat status */
    cert->Status = 0U;

    rval = CKR_OK;
  }

  return (rval);
}


/**
 * @brief Translates a PKCS #11 label into an object handle.
 *
 * Port-specific object handle retrieval.
 *
 *
 * @param[in] pxLabel         Pointer to the label of the object
 *                           who's handle should be found.
 * @param[in] usLength       The length of the label, in bytes.
 *
 * @return The object handle if operation was successful.
 * Returns eInvalidHandle if unsuccessful.
 */
CK_OBJECT_HANDLE PKCS11_PAL_FindObject (CK_BYTE_PTR pxLabel, CK_ULONG usLength) {
  CK_OBJECT_HANDLE h;
  Certificate_t *cert;

  h = handle_from_label (pxLabel);
  
  if (h != eInvalidHandle) {
    /* Check certificate status */
    cert = cert_from_handle(h);

    if (cert == NULL) {
      /* Unsupported handle */
      h = eInvalidHandle;
    }
    else {
      if ((cert->Status & CERTIFICATE_STATUS_PRESENT) == 0U) {
        /* Invalid certificate */
        h = eInvalidHandle;
      }
    }
  }

  return (h);
}


/**
 * @brief Gets the value of an object in storage, by handle.
 *
 * Port-specific file access for cryptographic information.
 *
 * This call dynamically allocates the buffer which object value
 * data is copied into.  PKCS11_PAL_GetObjectValueCleanup()
 * should be called after each use to free the dynamically allocated
 * buffer.
 *
 * @sa PKCS11_PAL_GetObjectValueCleanup
 *
 * @param[in]  xHandle      The PKCS #11 object handle of the object to get the value of.
 * @param[out] ppucData     Pointer to buffer for file data.
 * @param[out] pulDataSize  Size (in bytes) of data located in file.
 * @param[out] pIsPrivate   Boolean indicating if value is private (CK_TRUE)
 *                          or exportable (CK_FALSE)
 *
 * @return CKR_OK if operation was successful.  CKR_KEY_HANDLE_INVALID if
 * no such object handle was found, CKR_DEVICE_MEMORY if memory for
 * buffer could not be allocated, CKR_FUNCTION_FAILED for device driver
 * error.
 */
CK_RV PKCS11_PAL_GetObjectValue (CK_OBJECT_HANDLE xHandle, CK_BYTE_PTR *ppucData, CK_ULONG_PTR pulDataSize, CK_BBOOL *pIsPrivate) {
  CK_RV rval = CKR_OBJECT_HANDLE_INVALID;
  Certificate_t *cert;

  cert = cert_from_handle(xHandle);

  if (cert == NULL) {
    /* Unsupported handle */
    rval = CKR_OBJECT_HANDLE_INVALID;
  }
  else {
    if ((cert->Status & CERTIFICATE_STATUS_PRESENT) == 0U) {
      /* Invalid certificate */
      rval = CKR_OBJECT_HANDLE_INVALID;
    }
    else {
      /* Return certificate content and size */
      *ppucData    = cert->Pem;
      *pulDataSize = cert->Size;

      if ((cert->Status & CERTIFICATE_STATUS_PRIVATE) == 0U) {
        *pIsPrivate = CK_FALSE;
      } else {
        *pIsPrivate = CK_TRUE;
      }
      rval = CKR_OK;
    }
  }

  return (rval);
}


/**
 * @brief Cleanup after PKCS11_GetObjectValue().
 *
 * @param[in] pucData       The buffer to free.
 *                          (*ppucData from PKCS11_PAL_GetObjectValue())
 * @param[in] ulDataSize    The length of the buffer to free.
 *                          (*pulDataSize from PKCS11_PAL_GetObjectValue())
 */
void PKCS11_PAL_GetObjectValueCleanup (CK_BYTE_PTR pucData, CK_ULONG ulDataSize) {
  ( void ) pucData;
  ( void ) ulDataSize;

  /* Nothing to do, dynamic allocation is not used */
}


/**
  Translate PKCS#11 label to the corresponding handle.
*/
static CK_OBJECT_HANDLE handle_from_label (uint8_t *label) {
  CK_OBJECT_HANDLE h;

  if (label == NULL) {
    h = eInvalidHandle;
  }
  else {
    if(memcmp(label, &pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS, sizeof(pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS)) == 0) {
      /* This is the PKCS #11 label for device private key */
      h = eDevicePrivateKey;
    }
    else if(memcmp(label, &pkcs11configLABEL_DEVICE_PUBLIC_KEY_FOR_TLS, sizeof(pkcs11configLABEL_DEVICE_PUBLIC_KEY_FOR_TLS)) == 0) {
      /* This is the PKCS #11 label for device public key */
      h = eDevicePublicKey;
    }
    else if(memcmp(label, &pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS, sizeof(pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS)) == 0) {
      /* This is the PKCS #11 label for the device certificate */
      h = eDeviceCertificate;
    }
    else if(memcmp(label, &pkcs11configLABEL_CODE_VERIFICATION_KEY, sizeof(pkcs11configLABEL_CODE_VERIFICATION_KEY)) == 0) {
      /* This is the PKCS #11 label for the object to be used for code verification */
      h = eCodeSigningKey;
    }
    else if(memcmp(label, &pkcs11configLABEL_JITP_CERTIFICATE, sizeof(pkcs11configLABEL_JITP_CERTIFICATE)) == 0) {
      /* This is the PKCS #11 label for Just-In-Time-Provisioning */
      h = eJitpCertificate;
    }
    else if(memcmp(label, &pkcs11configLABEL_ROOT_CERTIFICATE, sizeof(pkcs11configLABEL_ROOT_CERTIFICATE)) == 0) {
      /* This is the PKCS #11 label for the AWS Trusted Root Certificate */
      h = eRootCertificate;
    }
    else {
      /*  Unknown label */
      h = eInvalidHandle;
    }
  }
  return (h);
}


/*
  Translate PKCS#11 handle to the corresponding certificate.
*/
static Certificate_t *cert_from_handle (CK_OBJECT_HANDLE h) {
  Certificate_t *cert;

  switch (h) {
    case eDevicePrivateKey:  cert = PKCS11_Key->ClientPrivateKey;  break;
    case eDevicePublicKey:   cert = NULL;                          break;
    case eDeviceCertificate: cert = PKCS11_Key->ClientCertificate; break;
    case eCodeSigningKey:    cert = NULL;                          break;
    case eJitpCertificate:   cert = NULL;                          break;
    case eRootCertificate:   cert = NULL;                          break;
    default:
      /* Unknown handle */
      cert = NULL;
      break;
  }

  return (cert);
}
