#include <windows.h>
#include "../include/pe.h"
#include <vector>

void* PE64::GetAdressData(int adress, int size)
{
    free(allocatedAdress);

    void* data = malloc(size);

    fseek(PeFile, adress, SEEK_SET);
    fread(data, size, 1, PeFile);

    return data;
}

void PE64::ParseFile()
{
    ParseDOS();
    ParseFileHeader();
    ParseOptionalHeader();
    ParseSectionHeader();
}

void PE64::ParseDOS()
{
    fseek(PeFile, 0, SEEK_SET);
    fread(&PEFILE_DOS_HEADER, sizeof(_IMAGE_DOS_HEADER), 1, PeFile);

    PEFILE_DOS_HEADER_EMAGIC = PEFILE_DOS_HEADER.e_magic;
    PEFILE_DOS_HEADER_ELFANEW = PEFILE_DOS_HEADER.e_lfanew; 
}

void PE64::ParseFileHeader()
{
    FILE_HEADER_ENTRY = PEFILE_DOS_HEADER_ELFANEW + sizeof(DWORD);

    fseek(PeFile, FILE_HEADER_ENTRY, SEEK_SET);
    fread(&PEFILE_FILE_HEADER, sizeof(_IMAGE_FILE_HEADER), 1, PeFile);

    OPTIONAL_HEADER_SIZE = PEFILE_FILE_HEADER.SizeOfOptionalHeader;
    NUMBER_OF_SECTIONS = PEFILE_FILE_HEADER.NumberOfSections;
}

void PE64::ParseOptionalHeader()
{
    OPTIONAL_HEADER_ENTRY = FILE_HEADER_ENTRY + sizeof(_IMAGE_FILE_HEADER);

    if (OPTIONAL_HEADER_SIZE == 224)
    {
        fseek(PeFile, OPTIONAL_HEADER_ENTRY, SEEK_SET);
        fread(&PEFILE_OPTIONAL_HEADER, OPTIONAL_HEADER_SIZE, 1, PeFile);
    }
    if (OPTIONAL_HEADER_SIZE == 240)
    {
        fseek(PeFile, OPTIONAL_HEADER_ENTRY, SEEK_SET);
        fread(&PEFILE_OPTIONAL_HEADER64, OPTIONAL_HEADER_SIZE, 1, PeFile);
    }
}

void PE64::ParseSectionHeader()
{
    SECTION_HEADER_ENTRY = OPTIONAL_HEADER_ENTRY + OPTIONAL_HEADER_SIZE;
    PEFILE_SECTION_HEADERS = new _IMAGE_SECTION_HEADER[NUMBER_OF_SECTIONS];

    for (int i = 0; i < NUMBER_OF_SECTIONS; i++) 
    {
        // If not working for x32/x86 then its this  ->  |------------------|
        int offset = PEFILE_DOS_HEADER.e_lfanew + sizeof(_IMAGE_NT_HEADERS64) + (i * IMAGE_SIZEOF_SECTION_HEADER);  
        fseek(PeFile, offset, SEEK_SET);
        fread(&PEFILE_SECTION_HEADERS[i], sizeof(IMAGE_SECTION_HEADER), 1, PeFile);
    }


    for (int i = 0; i < NUMBER_OF_SECTIONS; i++)
    {
       std::cout << PEFILE_SECTION_HEADERS[i].Name;
    }
}

void PE64::ParseImports()
{

}