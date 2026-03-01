#include "../include/pe.h"
#include <vector>

void PE64::ParseFile()
{
    ParseDOS();
    ParseFileHeader();
    ParseOptionalHeader();
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

