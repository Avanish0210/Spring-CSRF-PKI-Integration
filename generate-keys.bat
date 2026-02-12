@echo off
set "OUT_DIR=keys"
if not exist %OUT_DIR% mkdir %OUT_DIR%
echo Generating keys in %OUT_DIR%...
openssl genrsa -out %OUT_DIR%/csrf-private-key.pem 2048
openssl rsa -in %OUT_DIR%/csrf-private-key.pem -pubout -out %OUT_DIR%/csrf-public-key.pem
echo Done.
