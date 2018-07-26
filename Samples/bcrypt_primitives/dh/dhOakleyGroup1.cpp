// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.
/*++

Abstract:

    Sample program for DH Oakley group1 Secret Agreement using CNG
    
    See http://www.ietf.org/rfc/rfc2409.txt?number=2409
    
    Uses ephemeral keys (group1 = 768 bits key)

--*/

#include <windows.h>
#include <stdio.h>
#include <bcrypt.h>

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)

#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)


static const BYTE OakleyGroup1P[] = 
{
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc9, 0x0f,
    0xda, 0xa2, 0x21, 0x68, 0xc2, 0x34, 0xc4, 0xc6, 0x62, 0x8b,
    0x80, 0xdc, 0x1c, 0xd1, 0x29, 0x02, 0x4e, 0x08, 0x8a, 0x67,
    0xcc, 0x74, 0x02, 0x0b, 0xbe, 0xa6, 0x3b, 0x13, 0x9b, 0x22,
    0x51, 0x4a, 0x08, 0x79, 0x8e, 0x34, 0x04, 0xdd, 0xef, 0x95,
    0x19, 0xb3, 0xcd, 0x3a, 0x43, 0x1b, 0x30, 0x2b, 0x0a, 0x6d,
    0xf2, 0x5f, 0x14, 0x37, 0x4f, 0xe1, 0x35, 0x6d, 0x6d, 0x51,
    0xc2, 0x45, 0xe4, 0x85, 0xb5, 0x76, 0x62, 0x5e, 0x7e, 0xc6,
    0xf4, 0x4c, 0x42, 0xe9, 0xa6, 0x3a, 0x36, 0x20, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

static const BYTE OakleyGroup1G[] = 
{
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x02
};

static const BYTE rgbTlsSeed[] = 
{
    0x61, 0x62, 0x63, 0x64, 0x62, 0x63, 0x64, 0x65, 0x63, 0x64, 
    0x65, 0x66, 0x64, 0x65, 0x66, 0x67, 0x65, 0x66, 0x67, 0x68, 
    0x66, 0x67, 0x68, 0x69, 0x67, 0x68, 0x69, 0x6a, 0x68, 0x69, 
    0x6a, 0x6b, 0x69, 0x6a, 0x6b, 0x6c, 0x6a, 0x6b, 0x6c, 0x6d, 
    0x6b, 0x6c, 0x6d, 0x6e, 0x6c, 0x6d, 0x6e, 0x6f, 0x6d, 0x6e, 
    0x66, 0x67, 0x68, 0x69, 0x67, 0x68, 0x69, 0x6a, 0x68, 0x69, 
    0x6f, 0x70, 0x6e, 0x6f
};

LPCWSTR  pszLabel      = L"MyTlsLabel";

void __cdecl wmain(
                   int                      argc, 
                   __in_ecount(argc) LPWSTR *wargv)
{
    BCRYPT_ALG_HANDLE       hExchAlgA       = NULL;
    BCRYPT_ALG_HANDLE       hExchAlgB       = NULL;
    BCRYPT_KEY_HANDLE       hPrivKeyA       = NULL;
    BCRYPT_KEY_HANDLE       hPubKeyA        = NULL;
    BCRYPT_KEY_HANDLE       hPrivKeyB       = NULL;
    BCRYPT_KEY_HANDLE       hPubKeyB        = NULL;
    NTSTATUS                status          = STATUS_UNSUCCESSFUL;
    PBYTE                   pbPubBlobA      = NULL,
                            pbPubBlobB      = NULL,
                            pbAgreedSecretA = NULL,
                            pbAgreedSecretB = NULL,
                            pbDhParamBlob   = NULL;
    DWORD                   cbPubBlobA      = 0,
                            cbPubBlobB      = 0,
                            cbAgreedSecretA = 0,
                            cbAgreedSecretB = 0,
                            cbDhParamBlob   = 0,
                            dwKeyLen        = 0;
    BCRYPT_SECRET_HANDLE    hAgreedSecretA  = NULL,
                            hAgreedSecretB  = NULL;
    BCryptBufferDesc        ParameterList   = {0};
    
    const DWORD             cbBuffer        = 2;
    BCryptBuffer            rgBuffer[cbBuffer] = {0};

    BCRYPT_DH_PARAMETER_HEADER  *pbDhParamHdr  = NULL;



    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(wargv);


    dwKeyLen = 768;//bits

    //
    //construct the DH parameter blob. this is the only supported
    //method for DH in CNG.
    //
    //calculate size of param blob and allocate memory
    cbDhParamBlob = sizeof(BCRYPT_DH_PARAMETER_HEADER) + 
                    sizeof(OakleyGroup1G) + 
                    sizeof(OakleyGroup1P);

    pbDhParamBlob = (PBYTE)HeapAlloc (GetProcessHeap (), 0, cbDhParamBlob);
    if(NULL == pbDhParamBlob)
    {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    pbDhParamHdr  = (BCRYPT_DH_PARAMETER_HEADER *)pbDhParamBlob;

    //set header properties on param blob
    pbDhParamHdr->cbLength      = cbDhParamBlob;
    pbDhParamHdr->cbKeyLength   = dwKeyLen/8;//bytes
    pbDhParamHdr->dwMagic       = BCRYPT_DH_PARAMETERS_MAGIC;

    //set prime
    memcpy(pbDhParamBlob + sizeof(BCRYPT_DH_PARAMETER_HEADER),
           OakleyGroup1P,
           sizeof(OakleyGroup1P));

    //set generator
    memcpy(pbDhParamBlob + sizeof(BCRYPT_DH_PARAMETER_HEADER) + sizeof(OakleyGroup1P),
           OakleyGroup1G,
           sizeof(OakleyGroup1G));


    //open alg provider handle
    if(!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(
                                                &hExchAlgA, 
                                                BCRYPT_DH_ALGORITHM, 
                                                NULL, 
                                                0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
        goto Cleanup;
    }

    if(!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(
                                                    &hExchAlgB, 
                                                    BCRYPT_DH_ALGORITHM, 
                                                    NULL, 
                                                    0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
        goto Cleanup;
    }

    //A generates a private key
    if(!NT_SUCCESS(status = BCryptGenerateKeyPair(
                                            hExchAlgA,
                                            &hPrivKeyA,
                                            dwKeyLen,
                                            0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptGenerateKeyPair\n", status);
        goto Cleanup;
    }

    if(!NT_SUCCESS(status = BCryptSetProperty(
                                        hPrivKeyA,
                                        BCRYPT_DH_PARAMETERS,
                                        pbDhParamBlob,
                                        cbDhParamBlob,
                                        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptSetProperty\n", status);
        goto Cleanup;
    }

    if(!NT_SUCCESS(status = BCryptFinalizeKeyPair(hPrivKeyA, 0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptFinalizeKeyPair\n", status);
        goto Cleanup;
    }


    // A exports DH public key
    if(!NT_SUCCESS(status = BCryptExportKey(
                                    hPrivKeyA,
                                    NULL,
                                    BCRYPT_DH_PUBLIC_BLOB,
                                    NULL,
                                    0,
                                    &cbPubBlobA,
                                    0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptExportKey\n", status);
        goto Cleanup;
    }

    pbPubBlobA = (PBYTE)HeapAlloc (GetProcessHeap (), 0, cbPubBlobA);
    if(NULL == pbPubBlobA)
    {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    if(!NT_SUCCESS(status = BCryptExportKey(
                                        hPrivKeyA,
                                        NULL,
                                        BCRYPT_DH_PUBLIC_BLOB,
                                        pbPubBlobA,
                                        cbPubBlobA,
                                        &cbPubBlobA,
                                        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptExportKey\n", status);
        goto Cleanup;
    }


    //B generates a private key
    if(!NT_SUCCESS(status = BCryptGenerateKeyPair(
                                            hExchAlgB,
                                            &hPrivKeyB,
                                            dwKeyLen,
                                            0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptGenerateKeyPair\n", status);
        goto Cleanup;
    }

    if(!NT_SUCCESS(status = BCryptSetProperty(
                                        hPrivKeyB,
                                        BCRYPT_DH_PARAMETERS,
                                        pbDhParamBlob,
                                        cbDhParamBlob,
                                        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptSetProperty\n", status);
        goto Cleanup;
    }

    if(!NT_SUCCESS(status = BCryptFinalizeKeyPair(hPrivKeyB, 0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptFinalizeKeyPair\n", status);
        goto Cleanup;
    }


    // B exports DH public key
    if(!NT_SUCCESS(status = BCryptExportKey(
                                    hPrivKeyB,
                                    NULL,
                                    BCRYPT_DH_PUBLIC_BLOB,
                                    NULL,
                                    0,
                                    &cbPubBlobB,
                                    0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptExportKey\n", status);
        goto Cleanup;
    }

    pbPubBlobB = (PBYTE)HeapAlloc (GetProcessHeap (), 0, cbPubBlobB);
    if(NULL == pbPubBlobB)
    {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    if(!NT_SUCCESS(status = BCryptExportKey(
                                        hPrivKeyB,
                                        NULL,
                                        BCRYPT_DH_PUBLIC_BLOB,
                                        pbPubBlobB,
                                        cbPubBlobB,
                                        &cbPubBlobB,
                                        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptExportKey\n", status);
        goto Cleanup;
    }


    //A imports B's public key
    if(!NT_SUCCESS(status = BCryptImportKeyPair(
                                        hExchAlgA,
                                        NULL,
                                        BCRYPT_DH_PUBLIC_BLOB,
                                        &hPubKeyA,
                                        pbPubBlobB,
                                        cbPubBlobB,
                                        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptImportKeyPair\n", status);
        goto Cleanup;
    }

    if(!NT_SUCCESS(status = BCryptCloseAlgorithmProvider(hExchAlgA,0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptCloseAlgorithmProvider\n", status);
        goto Cleanup;
    }

    hExchAlgA =0;
    

    //
    //build KDF parameter list
    //

    //specify hash algorithm, SHA1 if null

    //specify secret to append
    rgBuffer[0].BufferType = KDF_TLS_PRF_SEED;
    rgBuffer[0].cbBuffer   = sizeof(rgbTlsSeed);
    rgBuffer[0].pvBuffer   = (PVOID)rgbTlsSeed;

    //specify secret to prepend
    rgBuffer[1].BufferType = KDF_TLS_PRF_LABEL;
    rgBuffer[1].cbBuffer   = (DWORD)((wcslen(pszLabel) + 1) * sizeof(WCHAR));
    rgBuffer[1].pvBuffer   = (PVOID)pszLabel;

    ParameterList.cBuffers  = 2;
    ParameterList.pBuffers  = rgBuffer;
    ParameterList.ulVersion = BCRYPTBUFFER_VERSION;

    // A generates the agreed secret
   if(!NT_SUCCESS(status = BCryptSecretAgreement(
                                                hPrivKeyA,
                                                hPubKeyA,
                                                &hAgreedSecretA,
                                                0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptSecretAgreement\n", status);
        goto Cleanup;
    }

    if(!NT_SUCCESS(status = BCryptDeriveKey(
                                       hAgreedSecretA,
                                       BCRYPT_KDF_TLS_PRF,
                                       &ParameterList,
                                       NULL,
                                       0,
                                       &cbAgreedSecretA,
                                       0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptDeriveKey\n", status);
        goto Cleanup;
    }

    pbAgreedSecretA = (PBYTE)HeapAlloc (GetProcessHeap (), 0, cbAgreedSecretA);
    if(NULL == pbAgreedSecretA)
    {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }
    
    if(!NT_SUCCESS(status = BCryptDeriveKey(
                                       hAgreedSecretA,
                                       BCRYPT_KDF_TLS_PRF,
                                       &ParameterList,
                                       pbAgreedSecretA,
                                       cbAgreedSecretA,
                                       &cbAgreedSecretA,
                                       0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptDeriveKey\n", status);
        goto Cleanup;
    }

    // B imports A's public key
    if(!NT_SUCCESS(status = BCryptImportKeyPair(
                                        hExchAlgB,
                                        NULL,
                                        BCRYPT_DH_PUBLIC_BLOB,
                                        &hPubKeyB,
                                        pbPubBlobA,
                                        cbPubBlobA,
                                        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptImportKeyPair\n", status);
        goto Cleanup;
    }

    if(!NT_SUCCESS(status = BCryptCloseAlgorithmProvider(hExchAlgB,0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptCloseAlgorithmProvider\n", status);
        goto Cleanup;
    }

    hExchAlgB =0;
    

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
                                       BCRYPT_KDF_TLS_PRF,
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
                                       BCRYPT_KDF_TLS_PRF,
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
    //In a real scenario, the agreed secrets on both sides will probably 
    //be input to a BCryptGenerateSymmetricKey function. Here we will
    //simply compare them

    if ((cbAgreedSecretA != cbAgreedSecretB) ||
        (memcmp(pbAgreedSecretA, pbAgreedSecretB, cbAgreedSecretA)))
    {
        wprintf(L"**** Error agreed keys differ\n");
        goto Cleanup;

    }

	wprintf(L"Success!\n");

Cleanup:

    if (hPubKeyA)    
    {
        BCryptDestroyKey(hPubKeyA);
    }

    if (hPubKeyB)    
    {
        BCryptDestroyKey(hPubKeyB);
    }

    if (hPrivKeyA)    
    {
        BCryptDestroyKey(hPrivKeyA);
    }

    if (hPrivKeyB)    
    {
        BCryptDestroyKey(hPrivKeyB);
    }

    if(hExchAlgA)
    {
        BCryptCloseAlgorithmProvider(hExchAlgA,0);
    }

    if(hExchAlgB)
    {
        BCryptCloseAlgorithmProvider(hExchAlgB,0);
    }

    if(hAgreedSecretA)
    {
        BCryptDestroySecret(hAgreedSecretA);
    }

    if(hAgreedSecretB)
    {
        BCryptDestroySecret(hAgreedSecretB);
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

    if(pbDhParamBlob)
    {
        HeapFree(GetProcessHeap(), 0, pbDhParamBlob);
    }

}

