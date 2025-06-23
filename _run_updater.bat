@echo off
REM This batch file is now 100% ASCII to avoid any encoding issues.

REM Give the main app a moment to close completely
timeout /t 2 /nobreak > nul

echo --- Installing Update ---

REM --- Find the path to the new build ---
set "SOURCE_PATH=%~dp0_update_temp"

REM --- Check if the folder exists ---
if not exist "%SOURCE_PATH%" (
    echo !!! Could not find the new build folder: %SOURCE_PATH%
    goto end
)

REM --- Copy files, replacing old ones ---
echo -> Copying new files...
xcopy "%SOURCE_PATH%" "%~dp0" /E /H /C /I /Y > nul

if %errorlevel% neq 0 (
    echo !!! ERROR COPYING FILES.
    goto end
)

echo -> Copying complete.
echo.
echo -> Cleaning up temporary files...
rmdir /s /q "%SOURCE_PATH%"

echo.
echo ==================================================
echo      UPDATE COMPLETED SUCCESSFULLY!
echo ==================================================
echo.
echo You can now run the application again.
echo This window will close in 5 seconds...
timeout /t 5 > nul

:end
exit