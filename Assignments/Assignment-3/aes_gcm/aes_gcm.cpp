#include "aes_gcm.h"


AESGCM:: ~AESGCM(){
    Cleanup();
}

// Freebie: initialize AES class
AESGCM::AESGCM( BYTE key[AES_256_KEY_SIZE]){
    hAlg = 0;
    hKey = NULL;

    // create a handle to an AES-GCM provider
    nStatus = ::BCryptOpenAlgorithmProvider(
        &hAlg, 
        BCRYPT_AES_ALGORITHM, 
        NULL, 
        0);
    if (! NT_SUCCESS(nStatus))
    {
        wprintf(L"**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", nStatus);
        Cleanup();
        return;
    }
    if (!hAlg){
        wprintf(L"Invalid handle!\n");
    }
    nStatus = ::BCryptSetProperty(
        hAlg, 
        BCRYPT_CHAINING_MODE, 
        (BYTE*)BCRYPT_CHAIN_MODE_GCM, 
        sizeof(BCRYPT_CHAIN_MODE_GCM), 
        0);
    if (!NT_SUCCESS(nStatus)){
         wprintf(L"**** Error 0x%x returned by BCryptGetProperty ><\n", nStatus);
         Cleanup();
         return;
    }
    //        bcryptResult = BCryptGenerateSymmetricKey(algHandle, &keyHandle, 0, 0, (PUCHAR)&key[0], key.size(), 0);

    nStatus = ::BCryptGenerateSymmetricKey(
        hAlg, 
        &hKey, 
        NULL, 
        0, 
        key, 
        AES_256_KEY_SIZE, 
        0);
    if (!NT_SUCCESS(nStatus)){
        wprintf(L"**** Error 0x%x returned by BCryptGenerateSymmetricKey\n", nStatus);
        Cleanup();
        return;
    }
    DWORD cbResult = 0;
     nStatus = ::BCryptGetProperty(
         hAlg, 
         BCRYPT_AUTH_TAG_LENGTH, 
         (BYTE*)&authTagLengths, 
         sizeof(authTagLengths), 
         &cbResult, 
         0);
   if (!NT_SUCCESS(nStatus)){
       wprintf(L"**** Error 0x%x returned by BCryptGetProperty when calculating auth tag len\n", nStatus);
   }

   
}


void AESGCM::Decrypt(BYTE* nonce, size_t nonceLen, BYTE* data, size_t dataLen, BYTE* macTag, size_t macTagLen){
    /*Struct Documentation
    typedef struct _BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
    ULONG     cbSize;
    ULONG     dwInfoVersion;
    PUCHAR    pbNonce;
    ULONG     cbNonce;
    PUCHAR    pbAuthData;
    ULONG     cbAuthData;
    PUCHAR    pbTag;
    ULONG     cbTag;
    PUCHAR    pbMacContext;
    ULONG     cbMacContext;
    ULONG     cbAAD;
    ULONGLONG cbData;
    ULONG     dwFlags;
    } BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO, *PBCRYPT_AUTHENTICATED_CIPHER_MODE_INFO; */

    //Create Struct
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO padInfoStruct;
    BCRYPT_INIT_AUTH_MODE_INFO(padInfoStruct);
    //Set Vals
    padInfoStruct.pbNonce = nonce;
    padInfoStruct.cbNonce = nonceLen;
    padInfoStruct.pbAuthData = NULL; //buffer of Authenticated data
    padInfoStruct.cbAuthData = 0; //size of pbauthdata
    padInfoStruct.pbTag = macTag; //for decrypt
    padInfoStruct.cbTag = macTagLen; //for decrypt
    padInfoStruct.pbMacContext = NULL; //assume not chaining for now
    padInfoStruct.cbMacContext = 0; //assume not chaining for now

    ULONG *bufferSize = 0;

    //Output Buffer Size 
    status = BCryptDecrypt(
                                    hKey, 
                                    data, 
                                    dataLen, 
                                    (PVOID) &padInfoStruct, //padInfo: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO
                                    nonce,
                                    nonceLen,
                                    NULL, 
                                    0, 
                                    bufferSize, 
                                    BCRYPT_BLOCK_PADDING); 
    if(!NT_SUCCESS(status))
    {
        wprintf(L"**** Error1 0x%x returned by BCryptDecrypt\n", status);
        Cleanup();
        return;
    }

    //Number of Bytes copied
    DWORD cbResult = 0;
    //Create Plaintext variable
    PBYTE decryptedOutput = (PBYTE)HeapAlloc (GetProcessHeap (), 0, *bufferSize);
    //Actually Decrypt
    status =  BCryptDecrypt(
                                    hKey, 
                                    data, 
                                    dataLen, 
                                    (PVOID) &padInfoStruct, //padInfo: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO
                                    nonce,
                                    nonceLen,
                                    decryptedOutput, //(pbPlainText)
                                    *bufferSize, //(&cbPlainText)
                                    &cbResult, //number of bytes copied
                                    BCRYPT_BLOCK_PADDING); 
     if(!NT_SUCCESS(status))
    {
        wprintf(L"**** Error2 0x%x returned by BCryptDecrypt\n", status);
        Cleanup();
        return;
    }

}

void AESGCM::Encrypt(BYTE* nonce, size_t nonceLen, BYTE* data, size_t dataLen){
    /*Struct Documentation
    typedef struct _BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
    ULONG     cbSize;
    ULONG     dwInfoVersion;
    PUCHAR    pbNonce;
    ULONG     cbNonce;
    PUCHAR    pbAuthData;
    ULONG     cbAuthData;
    PUCHAR    pbTag;
    ULONG     cbTag;
    PUCHAR    pbMacContext;
    ULONG     cbMacContext;
    ULONG     cbAAD;
    ULONGLONG cbData;
    ULONG     dwFlags;
    } BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO, *PBCRYPT_AUTHENTICATED_CIPHER_MODE_INFO; */

    //Create Struct
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO padInfoStruct;
    BCRYPT_INIT_AUTH_MODE_INFO(padInfoStruct);
    //Set Vals
    padInfoStruct.pbNonce = nonce;
    padInfoStruct.cbNonce = nonceLen;
    padInfoStruct.pbAuthData = NULL; //buffer of Authenticated data
    padInfoStruct.cbAuthData = 0; //size of pbauthdata
    //padInfoStruct.pbTag = macTag; //for decrypt
    //padInfoStruct.cbTag = macTagLen; //for decrypt
    padInfoStruct.pbMacContext = NULL; //assume not chaining for now
    padInfoStruct.cbMacContext = 0; //assume not chaining for now

    ULONG *bufferSize = 0;

    //Get Size of buffer
    if(!NT_SUCCESS(status = BCryptEncrypt(
                                        hKey, 
                                        data, 
                                        dataLen,
                                        (PVOID) &padInfoStruct,
                                        nonce,
                                        nonceLen, 
                                        NULL, 
                                        0, 
                                        bufferSize, //&cbCipherText
                                        BCRYPT_BLOCK_PADDING)))
    {
        wprintf(L"**** Error1 0x%x returned by BCryptEncrypt\n", status);
        wprintf(L"**** Buffer Size is %x \n", status);
        Cleanup();
        return;
    }

    //Create pbCipherText param
    PBYTE encryptedOutput = (PBYTE)HeapAlloc (GetProcessHeap (), 0, *bufferSize);

    //Create cbData
    DWORD cbResult = 0; 
    //Actually Encrypt now
    if(!NT_SUCCESS(status = BCryptEncrypt(
                                        hKey, 
                                        data, 
                                        dataLen,
                                        (PVOID) &padInfoStruct, //padding info stuct
                                        nonce,
                                        nonceLen, 
                                        encryptedOutput, 
                                        *bufferSize, //size of output (cbCipherText from previous call)
                                        &cbResult, //&cbData
                                        BCRYPT_BLOCK_PADDING)))
    {
        wprintf(L"**** Error2 0x%x returned by BCryptEncrypt\n", status);
        //wprintf(L"**** Buffer Size is %x \n", status);
        Cleanup();
        return;
    }








}

void AESGCM::Cleanup(){
    if(hAlg){
        ::BCryptCloseAlgorithmProvider(hAlg,0);
        hAlg = NULL;
    }
    if(hKey){
        ::BCryptDestroyKey(hKey);
        hKey = NULL;
    }
    if(tag){
          ::HeapFree(GetProcessHeap(), 0, tag);
          tag = NULL;
    }
    if(ciphertext){
        ::HeapFree(GetProcessHeap(), 0, tag);
        ciphertext = NULL;
    }
    if(plaintext){
        ::HeapFree(GetProcessHeap(), 0, plaintext);
        plaintext = NULL;
    }
}
