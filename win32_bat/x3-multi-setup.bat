@echo on
echo FuckADarkSoft
@echo off
set /p x3ip= "Please enter X3 IP Address: " 
set /p x3user= "Please enter X3 username: "
set /p x3pass= "Please enter X3 password: "
set /p tdegextension= "Please enter tdegboot new extension: "

timeout 2
psexec \\%x3ip% -u %x3user% -p %x3pass% taskkill /IM tdegboot.exe /F
timeout 5
psexec \\%x3ip% -u %x3user% -p %x3pass% cmd.exe /c ren "c:\tdegboot.exe" "tdegboot.exe.%tdegextension%"
timeout 5
copy /y tdegboot.exe \\%x3ip%\c$\
timeout 5
psexec \\%x3ip% -u %x3user% -p %x3pass% ewfmgr.exe -commit c:
timeout 5
psexec \\%x3ip% -u %x3user% -p %x3pass% shutdown /s /t 2

