@echo off
setlocal
set CLSID={5f3e9c28-3e4a-4a8a-9b0c-9c423e3aa711}
set NAME=My AMSI Provider
set DLL64=%~dp0MyProvider64.dll
set DLL32=%~dp0MyProvider32.dll

set IS64=0
if defined PROCESSOR_ARCHITEW6432 set IS64=1
if /i "%PROCESSOR_ARCHITECTURE%"=="AMD64" set IS64=1

if "%IS64%"=="1" (
  %SystemRoot%\System32\reg.exe add "HKLM\SOFTWARE\Classes\CLSID\%CLSID%" /ve /t REG_SZ /d "%NAME%" /f /reg:64
  %SystemRoot%\System32\reg.exe add "HKLM\SOFTWARE\Classes\CLSID\%CLSID%\InprocServer32" /ve /t REG_SZ /d "%DLL64%" /f /reg:64
  %SystemRoot%\System32\reg.exe add "HKLM\SOFTWARE\Classes\CLSID\%CLSID%\InprocServer32" /v ThreadingModel /t REG_SZ /d Both /f /reg:64
  %SystemRoot%\System32\reg.exe add "HKLM\SOFTWARE\Microsoft\AMSI\Providers\%CLSID%" /ve /t REG_SZ /d "%NAME%" /f /reg:64
  
  %SystemRoot%\System32\reg.exe add "HKLM\SOFTWARE\Classes\CLSID\%CLSID%" /ve /t REG_SZ /d "%NAME%" /f /reg:32
  %SystemRoot%\System32\reg.exe add "HKLM\SOFTWARE\Classes\CLSID\%CLSID%\InprocServer32" /ve /t REG_SZ /d "%DLL32%" /f /reg:32
  %SystemRoot%\System32\reg.exe add "HKLM\SOFTWARE\Classes\CLSID\%CLSID%\InprocServer32" /v ThreadingModel /t REG_SZ /d Both /f /reg:32
  %SystemRoot%\System32\reg.exe add "HKLM\SOFTWARE\Microsoft\AMSI\Providers\%CLSID%" /ve /t REG_SZ /d "%NAME%" /f /reg:32
) else (
  %SystemRoot%\System32\reg.exe add "HKLM\SOFTWARE\Classes\CLSID\%CLSID%" /ve /t REG_SZ /d "%NAME%" /f
  %SystemRoot%\System32\reg.exe add "HKLM\SOFTWARE\Classes\CLSID\%CLSID%\InprocServer32" /ve /t REG_SZ /d "%DLL32%" /f
  %SystemRoot%\System32\reg.exe add "HKLM\SOFTWARE\Classes\CLSID\%CLSID%\InprocServer32" /v ThreadingModel /t REG_SZ /d Both /f
  %SystemRoot%\System32\reg.exe add "HKLM\SOFTWARE\Microsoft\AMSI\Providers\%CLSID%" /ve /t REG_SZ /d "%NAME%" /f
)
endlocal
