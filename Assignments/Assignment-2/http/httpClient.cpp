#include <windows.h>
#include <string>
#include <iostream>
#include <winhttp.h>


std::wstring makeHttpRequest(std::wstring fqdn, int port, std::wstring uri, bool useTLS){
    
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    LPCWSTR pszOutBuffer;
    BOOL  bResults = FALSE;
    HINTERNET  hSession = NULL, 
               hConnect = NULL,
               hRequest = NULL;
    // Use WinHttpOpen to obtain a session handle.
    hSession = WinHttpOpen( L"httpClient",  
                            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                            WINHTTP_NO_PROXY_NAME, 
                            WINHTTP_NO_PROXY_BYPASS, 0);

    // Specify an HTTP server.
    if (hSession)
        hConnect = WinHttpConnect( hSession, fqdn.data(), port, 0);


    // Create an HTTP request handle.
    if (hConnect)
        hRequest = WinHttpOpenRequest( hConnect, L"GET", NULL,
                                       NULL, WINHTTP_NO_REFERER, 
                                       WINHTTP_DEFAULT_ACCEPT_TYPES, 
                                       WINHTTP_FLAG_SECURE);

    // Send a request.
    if (hRequest)
        bResults = WinHttpSendRequest( hRequest,
                                       WINHTTP_NO_ADDITIONAL_HEADERS,
                                       0, WINHTTP_NO_REQUEST_DATA, 0, 
                                       0, 0);

 
    // End the request.
    if (bResults)
        bResults = WinHttpReceiveResponse( hRequest, NULL);

    // Continue to verify data until there is nothing left.
    wchar_t *charbuffer[4096];
    
    std::wstring result;
    if (bResults)
        do 
        {

            // Verify available data.
            dwSize = 0;
            if (!WinHttpQueryDataAvailable( hRequest, &dwSize))
                wprintf( L"Error %u in WinHttpQueryDataAvailable.\n",
                        GetLastError());

            // Allocate space for the buffer.
            pszOutBuffer = new wchar_t[dwSize+1];
            if (!pszOutBuffer)
            {
                wprintf(L"Out of memory\n");
                dwSize=0;
            }
            else
            {
                // Read the Data.
                //ZeroMemory(pszOutBuffer, dwSize+1);

                if (!WinHttpReadData( hRequest, (LPVOID)pszOutBuffer, 
                                      dwSize, &dwDownloaded))
                    wprintf( L"Error %u in WinHttpReadData.\n", GetLastError());
                else
                    wprintf( L"%s\n", pszOutBuffer);
                    result.append(pszOutBuffer);
            
                // Free the memory allocated to the buffer.
                delete [] pszOutBuffer;
            }

        } while (dwSize > 0);


    // Report any errors.
    if (!bResults)
        wprintf( L"Error %d has occurred.\n", GetLastError());

    // Close open handles.
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);
    
    
    return result;
}

int wmain(int argc,  wchar_t* argv[]){
    if(argc !=5){
        std::wcout << L"Incorrect number of arguments: you need 4 positional arguemts" << std::endl;
        return 0;
    }

    std::wstring fqdn = std::wstring(argv[1]);
    int port = std::stoi( argv[2] );
    std::wstring uri = std::wstring(argv[3]);
    int  useTLS =std::stoi(argv[4]);
    bool tls;
    if (useTLS == 1){
        tls = true;
    } else if (useTLS == 0){
        tls = false;

    } else{
        std::wcout << L"bad value for useTls" << std::endl;
        return 0;
    }
     std::wcout << makeHttpRequest(fqdn,  port, uri, tls) << std::endl;
    return 0;
    
}