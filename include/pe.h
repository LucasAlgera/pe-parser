#ifndef PE_H
#define PE_H

#include <string>
#include <iostream>
#include <fstream>
#include <windows.h>

class PE64
{
public: 
	PE64(char* _fileName, FILE* _PeFile)
		: fileName(_fileName), PeFile(_PeFile)
	{
		ParseFile();
	}
	PE64( FILE* _PeFile)
		: PeFile(_PeFile)
	{
		ParseFile();
	}

	void* GetAdressData(int adress, int size);

	char* fileName;
	FILE* PeFile;

	_IMAGE_DOS_HEADER PEFILE_DOS_HEADER;

	WORD PEFILE_DOS_HEADER_EMAGIC;
	WORD PEFILE_DOS_HEADER_ELFANEW;

	LONG FILE_HEADER_ENTRY;
	_IMAGE_FILE_HEADER PEFILE_FILE_HEADER;
	LONG OPTIONAL_HEADER_SIZE;

	LONG OPTIONAL_HEADER_ENTRY;
	_IMAGE_OPTIONAL_HEADER PEFILE_OPTIONAL_HEADER;
	_IMAGE_OPTIONAL_HEADER64 PEFILE_OPTIONAL_HEADER64;

	LONG SECTION_HEADER_ENTRY;
	LONG NUMBER_OF_SECTIONS;
	PIMAGE_SECTION_HEADER PEFILE_SECTION_HEADERS;
private:

	// Parsers
	void ParseFile();

	void ParseDOS();
	void ParseFileHeader();
	void ParseOptionalHeader();
	void ParseSectionHeader();
	void ParseImports();

	void* allocatedAdress = nullptr;
};

#endif // PE_H

