# you-vGotInFected
* Because the code contain asm inside, I recommended to download and use the file in release section instead of compiling yourself or open .sln file with visual studio then compile.
* Tested on 2 samples: Easy_Crackme.exe and targetProgram.exe, already included in the repo.

Usage: run file

*you-vGotInFected.exe* 

Process injecting code include 2 phases:
1. Add a new section to the target PE file
2. Injecting asm code into the new section & modify the entry point to the new section

Process de-injecting code include 2 phases:
1. Remove the last section in the section table
2. Restore the entry point of the file which is already saved when injecting



If you wish to try the 3rd function, you may want to copy 2 samples into a folder and do the same above.
Implement the code from vxug, modified and improving!!!
