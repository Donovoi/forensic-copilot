@echo off
setlocal EnableExtensions EnableDelayedExpansion

set "RESULT_DRIVE="
for %%D in (C D E F G H I J K L M N O P Q R S T U V W Y Z) do (
    vol %%D: >X:\forensic-volume.tmp 2>nul
    find /I "FC_RESULTS" X:\forensic-volume.tmp >nul && set "RESULT_DRIVE=%%D:"
)
del /q X:\forensic-volume.tmp >nul 2>&1

if not defined RESULT_DRIVE (
    echo The FC_RESULTS volume was not found.
    goto shutdown
)

for /f "usebackq tokens=1,* delims==" %%A in ("!RESULT_DRIVE!\forensic-config.ini") do (
    set "%%A=%%B"
)

>"!RESULT_DRIVE!\run-status.partial.txt" echo STATUS=started
>>"!RESULT_DRIVE!\run-status.partial.txt" echo MODE=!MODE!
>>"!RESULT_DRIVE!\run-status.partial.txt" echo EXPECTED_VOLUME_SERIAL=!EXPECTED_VOLUME_SERIAL!

if not "!DERIVATIVE_PARTITION!"=="0" (
    >X:\forensic-assign.txt echo select disk !DERIVATIVE_DISK!
    >>X:\forensic-assign.txt echo select partition !DERIVATIVE_PARTITION!
    >>X:\forensic-assign.txt echo assign letter=W noerr
    >>X:\forensic-assign.txt echo detail partition
    diskpart /s X:\forensic-assign.txt >"!RESULT_DRIVE!\diskpart.txt" 2>&1
    >>"!RESULT_DRIVE!\run-status.partial.txt" echo DISKPART_EXIT=!ERRORLEVEL!
    del /q X:\forensic-assign.txt >nul 2>&1
)

set "TARGET_DRIVE="
set /a MATCH_COUNT=0
for %%D in (C D E F G H I J K L M N O P Q R S T U V W Y Z) do (
    vol %%D: >X:\forensic-volume.tmp 2>nul
    find /I "!EXPECTED_VOLUME_SERIAL!" X:\forensic-volume.tmp >nul && (
        set /a MATCH_COUNT+=1
        set "TARGET_DRIVE=%%D:"
    )
)
del /q X:\forensic-volume.tmp >nul 2>&1

if not "!MATCH_COUNT!"=="1" (
    >>"!RESULT_DRIVE!\run-status.partial.txt" echo STATUS=failed
    >>"!RESULT_DRIVE!\run-status.partial.txt" echo REASON=expected-volume-serial-match-count-!MATCH_COUNT!
    move /y "!RESULT_DRIVE!\run-status.partial.txt" "!RESULT_DRIVE!\run-status.txt" >nul
    goto shutdown
)

vol !TARGET_DRIVE! >"!RESULT_DRIVE!\target-volume.txt" 2>&1
>>"!RESULT_DRIVE!\run-status.partial.txt" echo TARGET_DRIVE=!TARGET_DRIVE!

rem A parameter-free chkdsk reports status and does not repair the volume.
chkdsk !TARGET_DRIVE! >"!RESULT_DRIVE!\chkdsk-scan.txt" 2>&1
set "SCAN_EXIT=!ERRORLEVEL!"
>>"!RESULT_DRIVE!\run-status.partial.txt" echo SCAN_EXIT=!SCAN_EXIT!

if /I "!MODE!"=="repair" (
    chkdsk !TARGET_DRIVE! /offlinescanandfix >"!RESULT_DRIVE!\chkdsk-repair.txt" 2>&1
    set "REPAIR_EXIT=!ERRORLEVEL!"
    >>"!RESULT_DRIVE!\run-status.partial.txt" echo REPAIR_EXIT=!REPAIR_EXIT!
)

>>"!RESULT_DRIVE!\run-status.partial.txt" echo STATUS=complete
move /y "!RESULT_DRIVE!\run-status.partial.txt" "!RESULT_DRIVE!\run-status.txt" >nul

:shutdown
wpeutil shutdown
exit /b 0
