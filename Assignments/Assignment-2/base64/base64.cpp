#include <windows.h>
#include <wincrypt.h>
#include <tchar.h>
#include <iostream>
#include <vector>
#include <cstdint>


//hint: use CRYPT_STRING_BASE64


std::wstring  b64Encode(std::vector<uint8_t> binaryData){
    // note that this will convert your std::string into a c string. 
    auto rawData = binaryData.data();
    // std::vector<uint8_t> is a perfectly fine container for raw binary  data 
    // as it is allocated in contiguous chunks of memory 
    // you can also easily convert it to raw data via returnBuff.data()


    // Hint: you should make two calls to ::CryptBinaryToStringW 
    // One to get the right size for the buffer
    DWORD BufferSize = 0;
    //FIRST CALL
    CryptBinaryToStringW(rawData, binaryData.size(), CRYPT_STRING_BASE64, NULL, &BufferSize);

    // Then one to copy the data over
    std::wstring returnBuff;
    LPWSTR DestBuffer = returnBuff.data(); 

    //SECOND CALL
    CryptBinaryToStringW(rawData, binaryData.size(), CRYPT_STRING_BASE64, DestBuffer, &BufferSize);

    //change me
    return returnBuff.data();
}


std::vector<uint8_t> b64Decode(std::wstring inputString){
    // as before you should make two calls to ::CryptStringToBinaryW 
    
    DWORD BufferSize = 0; 
    
    //FIRST CALL
    CryptStringToBinaryW(inputString.data(), inputString.length(), CRYPT_STRING_BASE64, NULL, &BufferSize, NULL, NULL);
   

    unsigned char charBuffer[BufferSize];
    
    //SECOND CALL
    CryptStringToBinaryW(inputString.data(), inputString.length(), CRYPT_STRING_BASE64, charBuffer, &BufferSize, NULL, NULL);
   
    std::vector<uint8_t> returnVector;
    returnVector.assign(charBuffer, charBuffer + BufferSize) ;

    return returnVector;
}

int wmain(int argc,  wchar_t* argv[]){
    if(argc !=3){
        std::wcout << L"Incorrect number of arguments" << std::endl;
        return 0;
    }
    std::wstring action = std::wstring(argv[1]);
    
    std::wstring dataString = std::wstring(argv[2]);

   

    if( action == L"decode"){
        // in this case, we assume the raw data happens to also be a string
        auto resultVector = b64Decode(dataString);
        std::wstring resultStr(resultVector.begin(), resultVector.end());
        // note needs to be none null 
        std::wcout << resultStr << std::endl;

    } else if( action == L"encode"){
         // note this removes the null terminator 
        std::vector<uint8_t> stringData(dataString.begin(), dataString.end());

        b64Encode(stringData );
        std::wcout << b64Encode(stringData) << std::endl;
    } else{
        std::wcout << L"Wrong action: use either decode of encode" << std::endl;
    }
    return 0;
}