#include "../include/pe.h"

int main()
{
    FILE* fptr;

    fptr = fopen("D:/Projects/Year3/pe-parser/executables/udbest.exe", "r");

    if (fptr == NULL) {
        printf("The file is not opened.");
        return 0;
    }

    PE64 PE( fptr );
}