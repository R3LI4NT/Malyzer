@echo off
setlocal

echo ===================================================
echo   Malyzer - Compilacion y ejecucion
echo ===================================================
echo.

where dotnet >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: dotnet no encontrado en PATH.
    echo Instala el SDK de .NET 8 desde: https://dotnet.microsoft.com/download/dotnet/8.0
    pause
    exit /b 1
)

for /f "tokens=*" %%v in ('dotnet --version') do set DOTNETVER=%%v
echo SDK detectado: %DOTNETVER%
echo.

echo [1/3] Restaurando paquetes...
dotnet restore
if %errorlevel% neq 0 goto :error

echo.
echo [2/3] Compilando en Release...
dotnet build -c Release --no-restore
if %errorlevel% neq 0 goto :error

echo.
echo [3/3] Ejecutando...
dotnet run -c Release --no-build
goto :fin

:error
echo.
echo ERROR: Fallo el proceso de compilacion.
pause
exit /b 1

:fin
endlocal
