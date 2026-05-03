@echo off
setlocal

echo ===================================================
echo   Malyzer - Publicacion (ejecutable autocontenido)
echo ===================================================
echo.

dotnet publish -c Release -r win-x64 --self-contained true ^
    -p:PublishSingleFile=true ^
    -p:IncludeNativeLibrariesForSelfExtract=true ^
    -p:DebugType=none ^
    -p:DebugSymbols=false ^
    -o publicacion

if %errorlevel% neq 0 (
    echo ERROR: Fallo la publicacion.
    pause
    exit /b 1
)

echo.
echo Publicacion completa en: publicacion\Malyzer.exe
echo Tamano del ejecutable:
dir publicacion\Malyzer.exe | findstr Malyzer.exe
echo.
pause
endlocal
