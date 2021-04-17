#include <windows.h>
#include <iostream>
#include <fstream>

#define SecToMs(Sec) Sec * 1000

enum FileType {
    EXE,
    DLL,
    SYS,
    EFI,
    UNK
};

enum SubsystemType {
    UnknownFile,
    Native,
    WindowsGui,
    WindowsCui,
    Os2Cui = 5,
    PoisxCui = 7,
    NativeWindows = 8,
    WindowsCeGui = 9,
    EfiApplication = 10,
    EfiBootServiceDriver = 11,
    EfiRuntimeDriver = 12,
    EfiRom = 13
};

void ErrorAndExit(const char* Error, const char* Fix) {

    printf("[!] %s!\n[-] %s!\n[->] Usage: NoEmbeds.exe ToRip.exe\n\n[~] Exitting in 5 seconds!", Error, Fix);
    Sleep(SecToMs(5));

    TerminateProcess((HANDLE)-1, 1);
}

const char* GetFileTypeStr(FileType Type) {

    //I'm too lazy to deal with things here, maybe add more or fix it /shrug
    switch (Type) {
    case EXE:
        return "exe";
    case DLL:
        return "dll";
    case SYS:
        return "sys";
    case EFI:
        return "efi";
    case UNK:
        return ".bin";
    }

    return ".bin";
}

FileType GetFileType(SubsystemType SubSystem) {

    switch (SubSystem) {
    case Native:
        return FileType::SYS;
    case WindowsGui:
        return FileType::EXE;
    case WindowsCui:
        return FileType::EXE;
    case NativeWindows:
        return FileType::SYS;
    case WindowsCeGui:
        return FileType::EXE;
    case EfiApplication:
        return FileType::EFI;
    case EfiBootServiceDriver:
        return FileType::EFI;
    case EfiRom:
        return FileType::EFI;
    default:
        return FileType::UNK;
    }

    return FileType::UNK;
}

const char* GetSubsystemTypeStr(SubsystemType SubSystem) {

    //I'm too lazy to deal with things here, maybe add more /shrug
    switch (SubSystem) {
    case Native:
        return "Native";
    case WindowsGui:
        return "Gui Executable";
    case WindowsCui:
        return "Console Executable";
    case NativeWindows:
        return "Native";
    case WindowsCeGui:
        return "Windows CeGui Executable";
    case EfiApplication:
        return "Efi Application";
    case EfiBootServiceDriver:
        return "Efi Boot Service Driver";
    case EfiRom:
        return "Efi Rom";
    default:
        return "Unknown Type";
    }

    return "Unknown Type";
}

void WriteBinaryFileToDisk(void* MemoryLocation, DWORD Size, const char* FileName, FileType Type) {

    static int TimesCalled = 0;

    char FileNameBuffer[MAX_PATH];
    sprintf_s(FileNameBuffer, "%s~Rip%d.%s", FileName, TimesCalled, GetFileTypeStr(Type));

    std::ofstream Binary(FileNameBuffer, std::ios::binary);
    if (!Binary) {
        return;
    }

    Binary.write((char*)MemoryLocation, Size);
    Binary.close();

    ++TimesCalled;
}

void LogDump(const char* ExecutableNameDumped, DWORD Size, void* MemoryLocation, SubsystemType Subsystem) {

    static int TimesCalled = 0;

    printf("[+] Dumped %s file at 0x%llx to %s~Rip%d.%s\n", GetSubsystemTypeStr(Subsystem), MemoryLocation, ExecutableNameDumped, TimesCalled, GetFileTypeStr(GetFileType(Subsystem)));
    ++TimesCalled;
}

int main(int argc, char** argv) {

    if (argc != 2) {
        ErrorAndExit("Insufficient parameters", "Please supply a file");
    }

    std::ifstream Binary(argv[1], std::ios::binary | std::ios::ate);
    if (!Binary) {
        ErrorAndExit("Unable to open binary file", "Please supply a valid file path");
    }

    DWORD FileSize = Binary.tellg();
    if (!FileSize) {
        ErrorAndExit("Invalid file size", "Please supply a valid file");
    }

    void* BinaryLocationInMemory = VirtualAlloc(0, FileSize, MEM_COMMIT, PAGE_READWRITE);
    if (!BinaryLocationInMemory) {
        ErrorAndExit("Unable to allocate memory to store binary file", "Input binary file in lesser sized chunks");
    }

    Binary.seekg(0, std::ios::beg);
    Binary.read((char*)BinaryLocationInMemory, FileSize);
    Binary.close();

    printf("[+] Initialized Dumping!\n\n");

    for (DWORD CurrentByte = 0; CurrentByte < FileSize; ++CurrentByte) {

        PIMAGE_DOS_HEADER DosHeader = PIMAGE_DOS_HEADER((char*)BinaryLocationInMemory + CurrentByte);
        // Bad checks, implement your own.
        if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE || DosHeader->e_lfanew >= FileSize || DosHeader->e_ovno >= 6 || DosHeader->e_minalloc != 0) {
            continue;
        }

        PIMAGE_NT_HEADERS64 NtHeader = PIMAGE_NT_HEADERS64((char*)BinaryLocationInMemory + CurrentByte + DosHeader->e_lfanew);
        if (NtHeader->Signature != IMAGE_NT_SIGNATURE) {
            continue;
        }

        DWORD RipFileSize = FileSize - CurrentByte;

        if(NtHeader->OptionalHeader.SizeOfImage <= FileSize) {
            RipFileSize = NtHeader->OptionalHeader.SizeOfImage;
        }

        //Fix sections in case you are trying to rip all embeds in a memory dumped file.
        PIMAGE_SECTION_HEADER SectionHeader = IMAGE_FIRST_SECTION(NtHeader);
        for (int CurrentSectionCount = 0; CurrentSectionCount < NtHeader->FileHeader.NumberOfSections; ++CurrentSectionCount, ++SectionHeader) {
            SectionHeader->SizeOfRawData = SectionHeader->Misc.VirtualSize;
            SectionHeader->PointerToRawData = SectionHeader->VirtualAddress;
        }

        SubsystemType SubSystem = SubsystemType(NtHeader->OptionalHeader.Subsystem);
        FileType FileType = GetFileType(SubSystem);

        LogDump(argv[1], RipFileSize, (char*)BinaryLocationInMemory + CurrentByte, SubSystem);

        WriteBinaryFileToDisk((char*)BinaryLocationInMemory + CurrentByte, RipFileSize, argv[1], FileType);
    }


    VirtualFree(BinaryLocationInMemory, 0, MEM_RELEASE);



    printf("[!!!] Dumped all images!\n\n[~] Exitting in 5 seconds!");
    Sleep(SecToMs(5));

    TerminateProcess((HANDLE)-1, 1);
}