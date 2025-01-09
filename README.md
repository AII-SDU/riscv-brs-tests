riscv-brs-tests
=======================

RISC-V Boot and Runtime Services Test Suite

## Overview

Used for getting source and run brs test in a Qemu
environment rapidly. There are two menu in build.sh .

## How To Run

Download and enter riscv-brs-tests repository.

        cd riscv-brs-tests

Run build.sh, firstly you will see start menu.
There are 6 options in this menu:   

        1. Initialize Target Directory  
        2. Compile Components  
        3. Build Disk Image  
        4. Install Components  
        5. Clean Up  
        6. Exit  

If you don't make any choice within 10 seconds,
the script will execute all choices.

Specially, if you choose "Compile Components",   
you will see a menu which contains 11 options: 

        1. linux  
        2. grub  
        3. edk2  
        4. edk2-test  
        5. edk2-test-parser  
        6. buildroot  
        7. opensbi  
        8. sbi-test  
        9. qemu  
        C. Compile All Components  
        0. Back to main menu  

Similar with last menu, if you don't make any 
choice within 10 seconds, all components will
be compiled.

After executing the build.sh, you will see a 
directory named 'target'. Enter this directory
and run start_uefi_sct.sh.

        cd target  
        . start_uefi_sct.sh

Brs test will be executed.