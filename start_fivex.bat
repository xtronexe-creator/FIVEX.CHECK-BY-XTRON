<<<<<<< HEAD
@echo off
echo ========================================
echo   FiveX.check System Starter
echo ========================================
echo.

echo Step 1: Starting PostgreSQL...
net start postgresql-x64-17
echo.

echo Step 2: Starting Backend Server...
start cmd /k "cd /d C:\Users\xtron\Desktop\FiveX.check-main\FiveX.check-main && pnpm run dev"
timeout /t 5

echo Step 3: Opening Website...
start http://localhost:3000/codes
echo.

echo ========================================
echo System Started!
echo.
echo Next Steps:
echo 1. Generate Code from website
echo 2. Run scanner manually: python FiveXCheck_Scanner_Enhanced.py
echo 3. Enter code in scanner
echo 4. View results at http://localhost:3000/results
echo ========================================
=======
@echo off
echo ========================================
echo   FiveX.check System Starter
echo ========================================
echo.

echo Step 1: Starting PostgreSQL...
net start postgresql-x64-17
echo.

echo Step 2: Starting Backend Server...
start cmd /k "cd /d C:\Users\xtron\Desktop\FiveX.check-main\FiveX.check-main && pnpm run dev"
timeout /t 5

echo Step 3: Opening Website...
start http://localhost:3000/codes
echo.

echo ========================================
echo System Started!
echo.
echo Next Steps:
echo 1. Generate Code from website
echo 2. Run scanner manually: python FiveXCheck_Scanner_Enhanced.py
echo 3. Enter code in scanner
echo 4. View results at http://localhost:3000/results
echo ========================================
>>>>>>> 053d8fe (Initial commit with all files (node_modules excluded))
pause