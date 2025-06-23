@echo off
REM Устанавливаем кодировку UTF-8 для корректного вывода из Python
chcp 65001 > nul

echo.
echo --- The main application is now closed. Starting the update process... ---
echo.

REM --- Запускаем основной скрипт обновления ---
python update.py

REM --- Проверяем результат ---
if %errorlevel% neq 0 (
    echo.
    echo !!! An error occurred during download/build. Update canceled.
    goto end
)

echo.
echo --- Installing Update ---
echo.

REM --- Находим путь к новой сборке ---
set "SOURCE_PATH=_update_temp\dist\dpi_gui"

REM --- Проверяем, существует ли папка ---
if not exist "%SOURCE_PATH%" (
    echo !!! Could not find the new build folder: %SOURCE_PATH%
    goto end
)

REM --- Копируем файлы с заменой ---
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
echo      You can now run dpi_gui.exe
echo ==================================================
echo.

:end
pause