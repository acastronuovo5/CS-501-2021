#include <windows.h>
#include <stdio.h>


DWORD Rva2Offset( DWORD dwRva, UINT_PTR uiBaseAddress );

DWORD WalkExportTable(BYTE* peBytes, char* name);

