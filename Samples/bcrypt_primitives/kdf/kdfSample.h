// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.

/*++

Abstract:
    Header file for sample KDF program.

--*/

#include <windows.h>
#include <stdio.h>
#include <bcrypt.h>
#include <ncrypt.h>


/*
 * Useful macros
 */
#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

/*
 * Macros for KSP (Static party)
 */
#define SAMPLE_KSP                          MS_KEY_STORAGE_PROVIDER
#define SAMPLE_KSP_KEY_EXCHANGE_ALGORITHM   NCRYPT_ECDH_P256_ALGORITHM
#define SAMPLE_KSP_KEYNAME                  L"Sample ECDH"

/*
 * Macros for Primitive (Ephemeral party)
 */
#define SAMPLE_PRIMITIVE_PROVIDER           MS_PRIMITIVE_PROVIDER
#define SAMPLE_EPH_KEY_EXCHANGE_ALGORITHM   BCRYPT_ECDH_P256_ALGORITHM
#define SAMPLE_KEY_LENGTH                   256


/*
 * Function prototypes
 */
void kdfHMACSample (void);
void kdfHashSample (void);

/*
 * Functions called for each party in the key exchange
 */
SECURITY_STATUS GenerateStaticKeyExchangeKeyPair (
    __in NCRYPT_PROV_HANDLE     hProv,
    __out NCRYPT_KEY_HANDLE     *phPrivKey,
    __out PBYTE                 *ppbPublicKeyBlob,
    __inout DWORD               *pcbPublicKeyBlob);
SECURITY_STATUS Party1Phase1 ();
SECURITY_STATUS Party1Phase2 ();

NTSTATUS GenerateEphemeralKeyExchangeKeyPair (
    __in BCRYPT_ALG_HANDLE      hExchAlg,
    __out BCRYPT_KEY_HANDLE     *phPrivKey,
    __out PBYTE                 *ppbPubBlob,
    __inout DWORD               *pcbPubBlob);
