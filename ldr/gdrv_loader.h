#include "global.h"
#include "dropper.h"


const wchar_t* Gdrv_Path = L"C:\\Windows\\System32\\Drivers\\gdrv.sys";

const wchar_t* Drv_Path = L"C:\\Windows\\System32\\Drivers\\vmulti.sys";

int start_driver()
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    char input[10];
    printf("Load or unload driver?\n");
    scanf("%s", input);

    if (strcmp(input, "LOAD") == 0 || strcmp(input, "load") == 0)
    {
        if (DropDriverFromBytes(Gdrv_Path) && DropDriverFromBytes2(Drv_Path))
        {
            // Load driver
            Status = WindLoadDriver((PWCHAR)Gdrv_Path, (PWCHAR)Drv_Path, FALSE);

            if (NT_SUCCESS(Status))
                printf("Driver loaded successfully\n");

            DeleteFile((LPCSTR)Gdrv_Path);
        }
    }
    else if (strcmp(input, "Unload") == 0 || strcmp(input, "unload") == 0)
    {
        // Unload driver
        Status = WindUnloadDriver((PWCHAR)Drv_Path[1], 0);
        if (NT_SUCCESS(Status))
            printf("Driver unloaded successfully\n");
    }

    if (!NT_SUCCESS(Status))
        printf("Error: %08X\n", Status);

    return true;
}
