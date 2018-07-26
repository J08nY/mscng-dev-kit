// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.

/*++

Abstract:
    Sample program for HASH-based Key Derivation Function (KDF).

--*/

#include "kdfSample.h"


static const BYTE rgbSecretPrepend[] = 
{
    0x12, 0x34, 0x56
};

static const BYTE rgbSecretAppend[] = 
{
    0xab, 0xcd, 0xef
};

//
// 1. Generate two key exchange key-pairs for two communicating parties
// 2. Exchange a shared secret using these key pairs
// 3. Derive a secret key from the exchanged shared secret using the KDF_HASH algorithm
// 4. Comapre the derived key values to see they are the same
//
void kdfHashSample (void)
{
    NCRYPT_PROV_HANDLE      hProvA          = NULL;
    NCRYPT_KEY_HANDLE       hPrivKeyA       = NULL,
                            hPubKeyA        = NULL;
    SECURITY_STATUS         secStatus       = ERROR_SUCCESS;
    NTSTATUS                status          = STATUS_UNSUCCESSFUL;
    BCRYPT_ALG_HANDLE       hExchAlgB       = NULL;
    BCRYPT_KEY_HANDLE       hPrivKeyB       = NULL;
    BCRYPT_KEY_HANDLE       hPubKeyB        = NULL;
    PBYTE                   pbPubBlobA      = NULL,
                            pbPubBlobB      = NULL,
                            pbAgreedSecretA = NULL,
                            pbAgreedSecretB = NULL;
    DWORD                   cbPubBlobA      = 0,
                            cbPubBlobB      = 0,
                            cbAgreedSecretA = 0,
                            cbAgreedSecretB = 0;
    NCRYPT_SECRET_HANDLE    hAgreedSecretA  = NULL;
    BCRYPT_SECRET_HANDLE    hAgreedSecretB  = NULL;
    BCryptBufferDesc        ParameterList   = {0};
    
    const DWORD             cbBuffer        = 3;
    BCryptBuffer            rgBuffer[cbBuffer] = {0};

    //get a handle to MS KSP
    if(FAILED(secStatus = NCryptOpenStorageProvider(
                                                &hProvA, 
                                                MS_KEY_STORAGE_PROVIDER, 
                                                0)))
    {
        wprintf(L"**** Error 0x%x returned by NCryptOpenStorageProvider\n", secStatus);
        goto Cleanup;
    }

    // Generate Party A's static key exchange key pair
    secStatus = GenerateStaticKeyExchangeKeyPair (hProvA, &hPrivKeyA, &pbPubBlobA, &cbPubBlobA);
    if (FAILED(secStatus))
    {
        wprintf (L"**** Error 0x%x returned by GenerateKeyExchangeKeyPair\n", secStatus);
        goto Cleanup;
    }

    // open alg provider handle
    if(!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(
                                        &hExchAlgB, 
                                        SAMPLE_EPH_KEY_EXCHANGE_ALGORITHM, 
                                        SAMPLE_PRIMITIVE_PROVIDER, 
                                        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
        goto Cleanup;
    }

    // B generates an ephemeral key exchange key pair, same algorithm
    status = GenerateEphemeralKeyExchangeKeyPair (
        hExchAlgB,
        &hPrivKeyB,
        &pbPubBlobB,
        &cbPubBlobB);
    if (!NT_SUCCESS (status))
    {
        wprintf(L"**** Error 0x%x returned by GenerateEphemeralKeyExchangeKeyPair\n", status);
        goto Cleanup;
    }

    // A imports B's public key
    if(FAILED(secStatus = NCryptImportKey(
                                    hProvA,
                                    NULL,
                                    BCRYPT_ECCPUBLIC_BLOB,
                                    NULL,
                                    &hPubKeyA,
                                    pbPubBlobB,
                                    cbPubBlobB,
                                    0)))
    {
        wprintf(L"**** Error 0x%x returned by NCryptImportKey\n", secStatus);
        goto Cleanup;
    }


    // A generates the agreed secret
   if(FAILED(secStatus = NCryptSecretAgreement(
                                        hPrivKeyA,
                                        hPubKeyA,
                                        &hAgreedSecretA,
                                        0)))
    {
        wprintf(L"**** Error 0x%x returned by NCryptSecretAgreement\n", secStatus);
        goto Cleanup;
    }


    //
    // build KDF parameter list
    //

    //specify hash algorithm, SHA1 if null
    rgBuffer[0].BufferType = KDF_HASH_ALGORITHM;
    rgBuffer[0].cbBuffer   = (DWORD)((wcslen(BCRYPT_SHA256_ALGORITHM) + 1) * sizeof(WCHAR));
    rgBuffer[0].pvBuffer   = (PVOID)BCRYPT_SHA256_ALGORITHM;
        
    //specify secret to append
    rgBuffer[1].BufferType = KDF_SECRET_APPEND;
    rgBuffer[1].cbBuffer   = sizeof(rgbSecretAppend);
    rgBuffer[1].pvBuffer   = (PVOID)rgbSecretAppend;

    //specify secret to prepend
    rgBuffer[2].BufferType = KDF_SECRET_PREPEND;
    rgBuffer[2].cbBuffer   = sizeof(rgbSecretPrepend);
    rgBuffer[2].pvBuffer   = (PVOID)rgbSecretPrepend;

    ParameterList.cBuffers  = 3;
    ParameterList.pBuffers  = rgBuffer;
    ParameterList.ulVersion = BCRYPTBUFFER_VERSION;

    //derive keys from secret using specified KDF (HASH)
    if(FAILED(secStatus = NCryptDeriveKey(
                                   hAgreedSecretA,
                                   BCRYPT_KDF_HASH,
                                   &ParameterList,
                                   NULL,
                                   0,
                                   &cbAgreedSecretA,
                                   0)))
    {
        wprintf(L"**** Error 0x%x returned by NCryptDeriveKey\n", secStatus);
        goto Cleanup;
    }

    pbAgreedSecretA = (PBYTE)HeapAlloc (GetProcessHeap (), 0, cbAgreedSecretA);
    if(NULL == pbAgreedSecretA)
    {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }
    
    if(FAILED(secStatus = NCryptDeriveKey(
                                   hAgreedSecretA,
                                   BCRYPT_KDF_HASH,
                                   &ParameterList,
                                   pbAgreedSecretA,
                                   cbAgreedSecretA,
                                   &cbAgreedSecretA,
                                   0)))
    {
        wprintf(L"**** Error 0x%x returned by NCryptDeriveKey\n", secStatus);
        goto Cleanup;
    }
        
        
    // B imports A's public key
    if(!NT_SUCCESS(status = BCryptImportKeyPair(
                                            hExchAlgB,
                                            NULL,
                                            BCRYPT_ECCPUBLIC_BLOB,
                                            &hPubKeyB,
                                            pbPubBlobA,
                                            cbPubBlobA,
                                            0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptImportKeyPair\n", status);
        goto Cleanup;
    }


    // B generates the agreed secret
    if(!NT_SUCCESS(status = BCryptSecretAgreement(
                                                hPrivKeyB,
                                                hPubKeyB,
                                                &hAgreedSecretB,
                                                0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptSecretAgreement\n", status);
        goto Cleanup;
    }

    if(!NT_SUCCESS(status = BCryptDeriveKey(
                                       hAgreedSecretB,
                                       BCRYPT_KDF_HASH,
                                       &ParameterList,
                                       NULL,
                                       0,
                                       &cbAgreedSecretB,
                                       0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptDeriveKey\n", status);
        goto Cleanup;
    }

    pbAgreedSecretB = (PBYTE)HeapAlloc (GetProcessHeap (), 0, cbAgreedSecretB);
    if(NULL == pbAgreedSecretB)
    {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }
    
    if(!NT_SUCCESS(status = BCryptDeriveKey(
                                       hAgreedSecretB,
                                       BCRYPT_KDF_HASH,
                                       &ParameterList,
                                       pbAgreedSecretB,
                                       cbAgreedSecretB,
                                       &cbAgreedSecretB,
                                       0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptDeriveKey\n", status);
        goto Cleanup;
    }

    // at this point the rgbAgreedSecretA should be the same as
    // rgbAgreedSecretB.
    // In a real scenario, the agreed secrets on both sides will probably 
    // be input to a BCryptGenerateSymmetricKey function. Here we will
    // simply compare them.
    if ((cbAgreedSecretA != cbAgreedSecretB) ||
        (memcmp(pbAgreedSecretA, pbAgreedSecretB, cbAgreedSecretA)))
    {
        wprintf(L"**** Error agreed keys are different\n");
        goto Cleanup;
    }

	wprintf(L"Success!\n");

Cleanup:

    if (hPubKeyA)    
    {
        NCryptFreeObject(hPubKeyA);
    }  

    if (hPubKeyB)    
    {
        BCryptDestroyKey(hPubKeyB);
    }

    if (hPrivKeyA)    
    {
        NCryptDeleteKey(hPrivKeyA, 0);
    }
 
    if (hPrivKeyB)    
    {
        BCryptDestroyKey(hPrivKeyB);
    }
 
    if (hProvA)    
    {
        NCryptFreeObject(hProvA);
    }  

    if(hExchAlgB)
    {
        BCryptCloseAlgorithmProvider(hExchAlgB,0);
    }

    if(hAgreedSecretB)
    {
        BCryptDestroySecret(hAgreedSecretB);
    }

    if(hAgreedSecretA)
    {
        NCryptFreeObject(hAgreedSecretA);
    }

    if(pbPubBlobA)
    {
        HeapFree(GetProcessHeap(), 0, pbPubBlobA);
    }

    if(pbPubBlobB)
    {
        HeapFree(GetProcessHeap(), 0, pbPubBlobB);
    }

    if(pbAgreedSecretA)
    {
        HeapFree(GetProcessHeap(), 0, pbAgreedSecretA);
    }

    if(pbAgreedSecretB)
    {
        HeapFree(GetProcessHeap(), 0, pbAgreedSecretB);
    }

}

//
// Generate a static key exchange key pair using NCrypt APIs.
// The key exchange algorithm is defined in the SAMPLE_KSP_KEY_EXCHANGE_ALGORITHM macro
// The private key handle and public key blob are returned in the out parameters.
//
SECURITY_STATUS GenerateStaticKeyExchangeKeyPair (
    __in NCRYPT_PROV_HANDLE     hProv,
    __out NCRYPT_KEY_HANDLE     *phPrivKey,
    __out PBYTE                 *ppbPublicKeyBlob,
    __inout DWORD               *pcbPublicKeyBlob)
{
    SECURITY_STATUS         secStatus        = ERROR_SUCCESS;
    DWORD                   dwPolicy         = 0;

    *phPrivKey = NULL;
    *ppbPublicKeyBlob = 0;

    // delete existing keys
    if(SUCCEEDED(secStatus = NCryptOpenKey(
                                        hProv,
                                        phPrivKey,
                                        SAMPLE_KSP_KEYNAME,
                                        0,
                                        0)))
    {
            if(FAILED(secStatus = NCryptDeleteKey (*phPrivKey, 0)))
            {
                wprintf(L"**** Error 0x%x returned by NCryptDeleteKey\n", secStatus);
                goto Cleanup;
            }

            *phPrivKey = 0;
    }

    // A generates a private key
    if(FAILED(secStatus = NCryptCreatePersistedKey(
                                            hProv,
                                            phPrivKey,
                                            SAMPLE_KSP_KEY_EXCHANGE_ALGORITHM,
                                            SAMPLE_KSP_KEYNAME,
                                            0,
                                            0)))
    {
        wprintf(L"**** Error 0x%x returned by NCryptCreatePersistedKey\n", secStatus);
        goto Cleanup;
    }

    // make the key exportable
    dwPolicy = NCRYPT_ALLOW_EXPORT_FLAG;

    if(FAILED(secStatus = NCryptSetProperty(
                                    *phPrivKey, 
                                    NCRYPT_EXPORT_POLICY_PROPERTY,
                                    (PBYTE)&dwPolicy,
                                    sizeof(DWORD),
                                    NCRYPT_PERSIST_FLAG)))
    {
        wprintf(L"**** Error 0x%x returned by NCryptSetProperty\n", secStatus);
        goto Cleanup;
    }

    // finalize the key
    if(FAILED(secStatus = NCryptFinalizeKey(
                                        *phPrivKey, 
                                        0)))
    {
        wprintf(L"**** Error 0x%x returned by NCryptFinalizeKey\n", secStatus);
        goto Cleanup;
    }

    // A exports ECDH public key
    if(FAILED(secStatus = NCryptExportKey(
                                    *phPrivKey,
                                    NULL,
                                    BCRYPT_ECCPUBLIC_BLOB,
                                    NULL,
                                    NULL,
                                    0,
                                    pcbPublicKeyBlob,
                                    0)))
    {
        wprintf(L"**** Error 0x%x returned by NCryptExportKey\n", secStatus);
        goto Cleanup;
    }

    *ppbPublicKeyBlob = (PBYTE)HeapAlloc (GetProcessHeap (), 0, *pcbPublicKeyBlob);
    if(NULL == *ppbPublicKeyBlob)
    {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    // Export the public key blob to output buffer
    if(FAILED(secStatus = NCryptExportKey(
                        *phPrivKey,
                        NULL,
                        BCRYPT_ECCPUBLIC_BLOB,
                        NULL,
                        *ppbPublicKeyBlob,
                        *pcbPublicKeyBlob,
                        pcbPublicKeyBlob,
                        0)))
    {
        wprintf(L"**** Error 0x%x returned by NCryptExportKey\n", secStatus);
        goto Cleanup;
    }

    //
    // Clean up, if any
    //
Cleanup:
    if (FAILED(secStatus))
    {
        NCryptDeleteKey (*phPrivKey, 0);
        *pcbPublicKeyBlob = 0;
        HeapFree(GetProcessHeap(), 0, *ppbPublicKeyBlob);
        *ppbPublicKeyBlob = NULL;
    }

    return secStatus;
}

//
// Generate an ephemeral key exchange key pair using BCrypt APIs.
// The key exchange algorithm is defined in the SAMPLE_KEY_EXCHANGE_ALGORITHM macro
// The public and private key handles are returned in the out parameters.
//
NTSTATUS GenerateEphemeralKeyExchangeKeyPair (
    __in BCRYPT_ALG_HANDLE      hExchAlg,
    __out BCRYPT_KEY_HANDLE     *phPrivKey,
    __out PBYTE                 *ppbPubBlob,
    __inout DWORD               *pcbPubBlob)
{
    NTSTATUS                status          = STATUS_UNSUCCESSFUL;

    if(!NT_SUCCESS(status = BCryptGenerateKeyPair(
                                            hExchAlg,
                                            phPrivKey,
                                            SAMPLE_KEY_LENGTH,
                                            0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptGenerateKeyPair\n", status);
        goto Cleanup;
    }

    if(!NT_SUCCESS(status = BCryptFinalizeKeyPair(*phPrivKey, 0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptFinalizeKeyPair\n", status);
        goto Cleanup;
    }

    // B exports ECDH public key
    if(!NT_SUCCESS(status = BCryptExportKey(
                                    *phPrivKey,
                                    NULL,
                                    BCRYPT_ECCPUBLIC_BLOB,
                                    NULL,
                                    0,
                                    pcbPubBlob,
                                    0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptExportKey\n", status);
        goto Cleanup;
    }

    *ppbPubBlob = (PBYTE)HeapAlloc (GetProcessHeap (), 0, *pcbPubBlob);
    if(NULL == *ppbPubBlob)
    {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    if(!NT_SUCCESS(status = BCryptExportKey(
                                    *phPrivKey,
                                    NULL,
                                    BCRYPT_ECCPUBLIC_BLOB,
                                    *ppbPubBlob,
                                    *pcbPubBlob,
                                    pcbPubBlob,
                                    0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptExportKey\n", status);
        goto Cleanup;
    }

    //
    // Clean up, if any
    //
Cleanup:
    if (!NT_SUCCESS(status))
    {
        BCryptDestroyKey (*phPrivKey);
        *pcbPubBlob = 0;
        HeapFree(GetProcessHeap(), 0, *ppbPubBlob);
        *ppbPubBlob = NULL;
    }

    return status;
}
