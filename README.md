Windows Pwn Step-by-Step
===
- [Intro](#Goal)
- [Environment](#Environment)
- [Tools](#Tools)
- [ExploitMe_1](#ExploitMe_1)
- [Reference](#Reference)

# Intro
In Linux pwn, I often need to debug dynamically between chal and exploit script

The steps are：
1. Add a `raw_input('>')` to exploit python script
2. Run exploit script
3. Find out chal process `pid`
    - Linux
        - `pidof chal`
    - Windows
        - Use tools (e.g. 火絨劍, Process Explorer)
4. Attach debugger to this process with the `pid`
    - Linux
        - `gdb at $(pidof chal)`
    - Windows
        - Use tools (e.g. WinDbg)
5. The debugger stops at internal of something like `read()` of standard lib
    - Windows
        - There are many threads in process, and debugger may not stop at the thread executing `read()`
        - Switch to this thread with command like `~0s`
6. Input `finish` (command of gdb), until the process return to some function like `main()`
    - Windows WinDbg
        - `Shift` + `F11`
7. Check whether my exploit script writes bytes to memeory correctly
    - gdb
        - `x/10xg $ebp-0x20`
    - WinDbg
        - `d @esp-0x20`

Check out ExploitMe Demo ;)

# Environment
Version 1909 (OS Build 18363.657)

# Tools
## [pwintools](https://github.com/masthoon/pwintools)
Basic pwntools for Windows written in python 2.7 
### Deps
- [PythonForWindows](https://github.com/hakril/PythonForWindows)
    ```
    git clone https://github.com/hakril/PythonForWindows.git
    python setup.py install
    ```
- [capstone](https://www.capstone-engine.org/download.html)
    ```
    pip install capstone
    ```
    
### Install
```
git clone https://github.com/masthoon/pwintools.git
```
- Revise [setup.py](#) from
    ```
    install_requires=[
        'PythonForWindows==0.4',
    ],
    ```
    to
    ```
    install_requires=[
        'PythonForWindows==0.5',
    ],
    ```
```
python setup.py
```


## WinDbg
Install `WinDbg Preview` in Microsoft $tore

## ncat
`ncat` is part of `nmap`

Install [nmap](https://nmap.org/download.html)

## ROPgadget
Install [ROPgadget](https://github.com/JonathanSalwan/ROPgadget)
```
pip install ropgadget
```

The path is `C:\Python27\Scripts\ROPgadget`

![image](https://raw.githubusercontent.com/LJP-TW/Windows-Pwn-Step-by-Step/master/screenshot/0_ropgadget.png)



## 火絨劍
You can use other process explorer tools as a alter
- 火絨劍: http://bbs.huorong.cn/thread-7800-1-1.html

## PE-bear
Install [PE-bear](https://hshrzd.wordpress.com/pe-bear/)

# ExploitMe_1
`ExploitMe_1.exe` is a simple program with buffer overflow vuln

This is a similar example of [this book](https://docs.alexomar.com/biblioteca/Modern%20Windows%20Exploit%20Development.pdf), at page 89

The book also teaches you to build shellcode ;)

## Disable mitigation
- Disable `DEP`
    Set VS2019 project property
    - Linker
        - Advanced
            - Data Execution Prevention (DEP): No (/NXCOMPAT:NO)
- Disable `GS`
    Set VS2019 project property
    - Configuration Properties
        - C/C++
            - Code Generation
                - Security Check: Disable Security Check (/GS-)
- Disable `ASLR`
    Run [setting.bat](#)

## Demo
First, let's disable `ASLR`
```
.\setting.bat
```
![image](https://github.com/LJP-TW/Windows-Pwn-Step-by-Step/blob/master/screenshot/1_DisableASLR.png?raw=true)

### Debug
1. Edit `exploit.py`
    Add `raw_input('>')` at line7
    ![image](https://github.com/LJP-TW/Windows-Pwn-Step-by-Step/blob/master/screenshot/2_editExploit.png?raw=true)
    
2. Run `exploit.py`
    ![image](https://github.com/LJP-TW/Windows-Pwn-Step-by-Step/blob/master/screenshot/3_runExploit.png?raw=true)
    
3. Find `pid`
    In this demo, it's `3168`
    ![image](https://github.com/LJP-TW/Windows-Pwn-Step-by-Step/blob/master/screenshot/4_findPid.png?raw=true)
    
4. Attach to this process with WinDbg
    - Check `Show processes from all users`

    ![image](https://github.com/LJP-TW/Windows-Pwn-Step-by-Step/blob/master/screenshot/5_attach.png?raw=true)

    ![image](https://github.com/LJP-TW/Windows-Pwn-Step-by-Step/blob/master/screenshot/5_attach2.png?raw=true)
    
    - command `k`: Display the stack frame
        - There is no something like `main`
            ![image](https://github.com/LJP-TW/Windows-Pwn-Step-by-Step/blob/master/screenshot/6_WinDbg_k.png?raw=true)

    - command `~`: See a list of all threads
        ![image](https://github.com/LJP-TW/Windows-Pwn-Step-by-Step/blob/master/screenshot/6_WinDbg_~.png?raw=true)
        - Switch to thread 0: `~0s`
            ![image](https://github.com/LJP-TW/Windows-Pwn-Step-by-Step/blob/master/screenshot/6_WinDbg_~0s.png?raw=true)
        - Display the stack frame again
        - `ExploitMe_1!main+0x4d` that's what I want to see!
            ![image](https://github.com/LJP-TW/Windows-Pwn-Step-by-Step/blob/master/screenshot/6_WinDbg_k2.png?raw=true)
5. Return to main
    - `Shift` + `F11`
        WinDbg is stuck, waiting for input
        ![image](https://github.com/LJP-TW/Windows-Pwn-Step-by-Step/blob/master/screenshot/7_WinDbg_gu.png?raw=true)
    - Press Enter at exploit
        ![gif](https://github.com/LJP-TW/Windows-Pwn-Step-by-Step/blob/master/screenshot/8_enterExploit.gif?raw=true)
    - `Shift` + `F11` until return to main
        ![gif](https://github.com/LJP-TW/Windows-Pwn-Step-by-Step/blob/master/screenshot/9_ret2Main.gif?raw=true)

6. Check memory
    ![gif](https://github.com/LJP-TW/Windows-Pwn-Step-by-Step/blob/master/screenshot/10_checkMem.gif?raw=true)

7. Continue process
    - `F10`
        ![gif](https://github.com/LJP-TW/Windows-Pwn-Step-by-Step/blob/master/screenshot/11_continue.gif?raw=true)
        ![gif](https://github.com/LJP-TW/Windows-Pwn-Step-by-Step/blob/master/screenshot/12_ret.gif)

#### Find gadget
1. Use ROPgadget to find gadgets in kernel32.dll
    - In this demo we disable ASLR, so we can use gadget in dll
    ```
    python \Python27\Scripts\ROPgadget --binary \Windows\SysWoW64\kernel32.dll > gadget
    ```

2. Find `push esp ; ret`
    ```
    0x6b86ade5 : push esp ; ret
    ```
    
3. Find Image base of `\Windows\SysWoW64\kernel32.dll`
    - Use PE-bear
    - Find out the Image base is `0x6b800000`
        ![image](https://github.com/LJP-TW/Windows-Pwn-Step-by-Step/blob/master/screenshot/13_pebear.png?raw=true)
    - So the offset of `push esp ; ret` gadget is `0x6b86ade5 - 0x6b800000 = 0x6ade5`

4. Do the steps of debug to step 5 again
    - Then find out the where Kernel32 starts
    - command `lm`: List modules
    - Find out the base is `0x76f70000`
        ![image](https://github.com/LJP-TW/Windows-Pwn-Step-by-Step/blob/master/screenshot/14_kernel32base.png?raw=true)
    - So the gadget address is `0x76f70000 + 0x6ade5 = 0x76fdade5`

5. Check gadget
    ![image](https://github.com/LJP-TW/Windows-Pwn-Step-by-Step/blob/master/screenshot/15_checkgadget.png?raw=true)
    - Remember to revise exploit script

### Pwn
![gif](https://github.com/LJP-TW/Windows-Pwn-Step-by-Step/blob/master/screenshot/16_pwned.gif?raw=true)

# Reference
- [Modern Windows Exploit Development](https://docs.alexomar.com/biblioteca/Modern%20Windows%20Exploit%20Development.pdf)
- https://stackoverflow.com/questions/4946685/good-tutorial-for-windbg

###### tags: `security`