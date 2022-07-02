# ClearDriverTraces
clearing traces of a loaded driver

## DESCRIPTION  
This project gets rid of some entries left behind by loading a signed kernel driver which can lead to the certificate getting blacklisted.

## NOTES
I have only provided the right offsets for my windows version (21h1). You can get the correct offsets from ida. Open the module they are loaded in, search for them in the name search window, rebase the program to 0, and then copy their location.

## USAGE 
Compile in x64 release and sign it. Load it like any other signed driver.
