@echo off
REM Script to generate RSA key pair for CSRF token signing (Windows)
REM Usage: generate-keys.bat [output-directory]

setlocal

if "%~1"=="" (
    set OUTPUT_DIR=.
) else (
    set OUTPUT_DIR=%~1
)

set PRIVATE_KEY=%OUTPUT_DIR%\csrf-private-key.pem
set PUBLIC_KEY=%OUTPUT_DIR%\csrf-public-key.pem

echo.
echo 🔐 Generating RSA key pair for CSRF protection...
echo.

REM Check if openssl is installed
where openssl >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo ❌ Error: openssl is not installed
    echo Please install openssl first:
    echo   Download from: https://slproweb.com/products/Win32OpenSSL.html
    echo   Or use Git Bash which includes openssl
    exit /b 1
)

REM Generate private key
echo 📝 Generating private key...
openssl genrsa -out "%PRIVATE_KEY%" 2048

if %ERRORLEVEL% NEQ 0 (
    echo ❌ Failed to generate private key
    exit /b 1
)

echo ✅ Private key generated: %PRIVATE_KEY%

REM Extract public key
echo 📝 Extracting public key...
openssl rsa -in "%PRIVATE_KEY%" -pubout -out "%PUBLIC_KEY%"

if %ERRORLEVEL% NEQ 0 (
    echo ❌ Failed to extract public key
    exit /b 1
)

echo ✅ Public key generated: %PUBLIC_KEY%
echo.
echo 🎉 Key pair generated successfully!
echo.
echo ⚠️  IMPORTANT SECURITY NOTES:
echo   1. NEVER commit the private key to version control
echo   2. Store the private key securely (vault, secrets manager)
echo   3. The private key should ONLY be on the token-issuing service
echo   4. The public key goes on the gateway (this project)
echo   5. Rotate keys periodically (recommended: every 90 days)
echo.
echo 📋 Next steps:
echo   1. Copy %PUBLIC_KEY% to src\main\resources\keys\
echo   2. Securely transfer %PRIVATE_KEY% to token-issuing service
echo   3. Delete %PRIVATE_KEY% from this machine
echo   4. Update Confluence: Secure Store Inventory
echo.

endlocal
