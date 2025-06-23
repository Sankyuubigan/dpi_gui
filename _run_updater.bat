@echo off
REM This batch file is now 100% ASCII to avoid any encoding issues.
REM All user-facing messages are handled by the python script.

REM Set UTF-8 codepage just in case for python's output
chcp 65001 > nul

REM --- Run the main python update script ---
python update.py

REM --- Check the result ---
if %errorlevel% neq 0 (
    echo.
    echo !!! The python script reported an error. Update canceled.
    goto end
)

echo.
echo --- Installing Update ---
echo.

REM --- Find the path to the new build ---
set "SOURCE_PATH=_update_temp\dist\dpi_gui"

REM --- Check if the folder exists ---
if not exist "%SOURCE_PATH%" (
    echo !!! Could not find the new build folder: %SOURCE_PATH%
    goto end
)

REM --- Copy files, replacing old ones ---
echo -> Copying new files...
xcopy "%SOURCE_PATH%" "." /E /H /C /I /Y > nul

if %errorlevel% neq 0 (
    echo !!! ERROR COPYING FILES.
    goto end
)

echo -> Copying complete.
echo.
echo -> Cleaning up temporary files...
rmdir /s /q _update_temp

echo.
echo ==================================================
echo      UPDATE COMPLETED SUCCESSFULLY!
echo ==================================================
echo.

:end
pause