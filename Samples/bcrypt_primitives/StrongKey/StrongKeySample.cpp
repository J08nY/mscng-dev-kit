// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.
/*++

Abstract:

    Sample program strong key UX using CNG

--*/
#include <windows.h>
#include <stdio.h>
#include <bcrypt.h>

#define STATUS_SUCCESS  ((NTSTATUS)0L)

int __cdecl main()
{
    NTSTATUS    Status  = STATUS_SUCCESS;
    NCRYPT_PROV_HANDLE      hProvider       = 0;
    NCRYPT_KEY_HANDLE       hKey            = 0;
    LPCWSTR                 pszKeyName      = L"MyKey";
    NCRYPT_UI_POLICY        UIPolicy        = {0};
    HWND                    hwndConsole     = NULL;

    BYTE                    rgbHash[20];
    PBYTE                   pbSignature     = NULL;
    DWORD                   cbSignature;
    DWORD                   i;
    BCRYPT_PKCS1_PADDING_INFO PKCS1PaddingInfo;
    VOID                    *pPaddingInfo;

    printf("Strong Key UX Sample\n");

    ZeroMemory(&UIPolicy, sizeof(UIPolicy));

    // Open Microsoft KSP (Key Storage Provider) to get a handle to it.
    Status = NCryptOpenStorageProvider(&hProvider,
                                       MS_KEY_STORAGE_PROVIDER,
                                       0);
    if (FAILED(Status))
    {
        printf("ERROR: NCryptOpenStorageProvider : 0x%x\n", Status);
        goto Cleanup;
    }

    // Create an RSA key exchange key-pair in the MS KSP
    // overwriting an existing key with the provided name.
    Status = NCryptCreatePersistedKey(hProvider,
                                      &hKey,
                                      NCRYPT_RSA_ALGORITHM,
                                      pszKeyName,
                                      AT_KEYEXCHANGE,
                                      NCRYPT_OVERWRITE_KEY_FLAG);
    if (FAILED(Status))
    {
        printf("ERROR: NCryptCreatePersistedKey : 0x%x\n", Status);
        goto Cleanup;
    }
	else{
		printf("Create New RSA key\n");
	}

    // Set the policy on this key-pair, before finalizing the key-pair
    // generation. Once the key pair generation is finalized, these
    // properties can't be changed.
    UIPolicy.dwVersion = 1;
    UIPolicy.dwFlags = NCRYPT_UI_PROTECT_KEY_FLAG;
	
    UIPolicy.pszCreationTitle   = L"Strong Key UX Sample";
    UIPolicy.pszFriendlyName    = L"Test Friendly Name";
    UIPolicy.pszDescription = L"This is a Sample";

    Status = NCryptSetProperty(hKey,
                               NCRYPT_UI_POLICY_PROPERTY,
                               (PBYTE)&UIPolicy,
                               sizeof(UIPolicy),
                               0);
    if (FAILED(Status))
    {
        printf("ERROR: NCryptSetProperty(set UI params) : 0x%x\n", Status);
        goto Cleanup;
    }

    // Get a handle to the console window to use in key's property.
    hwndConsole = GetConsoleWindow();
    if (hwndConsole == NULL)
    {
        Status = NTE_INVALID_HANDLE;
        printf("ERROR: GetConsoleWindow : 0x%x\n", Status);
        goto Cleanup;
    }

    // OK, now attach that handle to the key
    Status = NCryptSetProperty(hKey,
                               NCRYPT_WINDOW_HANDLE_PROPERTY,
                               (PBYTE)&hwndConsole,
                               sizeof(hwndConsole),
                               0);
    if (FAILED(Status))
    {
        printf("ERROR: NCryptSetProperty(HWND) : 0x%x\n", Status);
        goto Cleanup;
    }

    // Finalize the key-pair generation process.
    // From here on, the key handle is usable.
    Status = NCryptFinalizeKey(hKey, 0);
    if (FAILED(Status))
    {
        printf("ERROR: NCryptFinalizeKey : 0x%x\n", Status);
        goto Cleanup;
    }

    // and delete this object
    NCryptFreeObject(hKey);

    //
    // Here we start using the key for some purpose.
    // The intent from here on is to show the strong key UX per its policy set above.
    //
    // Get a handle to the private key in the provider (KSP).
    Status = NCryptOpenKey(
                    hProvider,
                    &hKey,
                    pszKeyName,
                    AT_KEYEXCHANGE,
                    0);

    if(FAILED(Status))
    {
        printf("ERROR: NCryptOpenKey : 0x%x\n", Status);
        goto Cleanup;
    }
	else{
		printf("Open a RSA key to sign\n");
	}

    // Set the Window handle property on the key handle
    Status = NCryptSetProperty(hKey,
                               NCRYPT_WINDOW_HANDLE_PROPERTY,
                               (PBYTE)&hwndConsole,
                               sizeof(hwndConsole),
                               0);
    if (FAILED(Status))
    {
        printf("ERROR: NCryptSetProperty(HWND) : 0x%x\n", Status);
        goto Cleanup;
    }

   // initialize hash
    for(i = 0; i < sizeof(rgbHash); i++)
    {
        rgbHash[i] = (BYTE)(i + 1);
    }

    PKCS1PaddingInfo.pszAlgId = NCRYPT_SHA1_ALGORITHM;
    pPaddingInfo = &PKCS1PaddingInfo;

    // Call into signature function to determine the required output length
    Status = NCryptSignHash(hKey,
                            pPaddingInfo,
                            rgbHash,
                            sizeof(rgbHash),
                            NULL,
                            0,
                            &cbSignature,
                            NCRYPT_PAD_PKCS1_FLAG);
    if (FAILED(Status))
    {
        printf("ERROR: NCryptSignHash(size) : 0x%x\n", Status);
        goto Cleanup;
    }

    // Allocate memory fort he signature
    pbSignature = (PBYTE) LocalAlloc(LMEM_ZEROINIT, cbSignature);
    if (pbSignature == NULL)
    {
        printf("ERROR: Not enough memory for signature\n");
        Status = STATUS_NO_MEMORY;
        goto Cleanup;
    }

    // And call the signature function again to sign the data
    // and to get the signature blob
    Status = NCryptSignHash(hKey,
                            pPaddingInfo,
                            rgbHash,
                            sizeof(rgbHash),
                            pbSignature,
                            cbSignature,
                            &cbSignature,
                            NCRYPT_PAD_PKCS1_FLAG);
    if (FAILED(Status))
    {
        printf("ERROR: NCryptSignHash() : 0x%x\n", Status);
        goto Cleanup;
    }
	else{
		printf("SUCCESS: Sign the Hash \n");
	}

    // All done.

	wprintf(L"Success!\n");

Cleanup:

    // Clean up resources
   if (pbSignature)
    {
        LocalFree(pbSignature);
        pbSignature = NULL;
    }

    if (hKey)
    {
        NCryptDeleteKey(hKey, 0);
        hKey = 0;
    }
	
    return 0;
}
