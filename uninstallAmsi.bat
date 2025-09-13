@echo off
setlocal
set CLSID={5f3e9c28-3e4a-4a8a-9b0c-9c423e3aa711}

set IS64=0
if defined PROCESSOR_ARCHITEW6432 set IS64=1
if /i "%PROCESSOR_ARCHITECTURE%"=="AMD64" set IS64=1

if "%IS64%"=="1" (
  %SystemRoot%\System32\reg.exe delete "HKLM\SOFTWARE\Microsoft\AMSI\Providers\%CLSID%" /f /reg:64
  %SystemRoot%\System32\reg.exe delete "HKLM\SOFTWARE\Classes\CLSID\%CLSID%\InprocServer32" /f /reg:64
  %SystemRoot%\System32\reg.exe delete "HKLM\SOFTWARE\Classes\CLSID\%CLSID%" /f /reg:64

  %SystemRoot%\System32\reg.exe delete "HKLM\SOFTWARE\Microsoft\AMSI\Providers\%CLSID%" /f /reg:32
  %SystemRoot%\System32\reg.exe delete "HKLM\SOFTWARE\Classes\CLSID\%CLSID%\InprocServer32" /f /reg:32
  %SystemRoot%\System32\reg.exe delete "HKLM\SOFTWARE\Classes\CLSID\%CLSID%" /f /reg:32
) else (
  %SystemRoot%\System32\reg.exe delete "HKLM\SOFTWARE\Microsoft\AMSI\Providers\%CLSID%" /f
  %SystemRoot%\System32\reg.exe delete "HKLM\SOFTWARE\Classes\CLSID\%CLSID%\InprocServer32" /f
  %SystemRoot%\System32\reg.exe delete "HKLM\SOFTWARE\Classes\CLSID\%CLSID%" /f
)
endlocal
