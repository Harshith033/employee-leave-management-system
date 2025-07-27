@echo off
REM Windows deployment script for Employee Leave Management System

echo.
echo 🚀 Employee Leave Management System - Windows Deployment
echo =======================================================
echo.

REM Check Python version
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python is not installed or not in PATH
    echo Please install Python 3.8 or higher and try again
    pause
    exit /b 1
)

for /f "tokens=*" %%i in ('python --version') do set python_version=%%i
echo ✓ %python_version%

REM Create virtual environment if it doesn't exist
if not exist ".venv" (
    echo 📦 Creating virtual environment...
    python -m venv .venv
    echo ✓ Virtual environment created
) else (
    echo ✓ Virtual environment already exists
)

REM Activate virtual environment
echo 🔧 Activating virtual environment...
call .venv\Scripts\activate.bat

REM Upgrade pip
echo ⬆️ Upgrading pip...
python -m pip install --upgrade pip

REM Install dependencies
echo 📥 Installing dependencies...
pip install -r requirements.txt

REM Create .env file if it doesn't exist
if not exist ".env" (
    echo 📝 Creating .env file from template...
    copy .env.template .env >nul
    echo ⚠️ Please update .env file with your actual configuration values
) else (
    echo ✓ .env file already exists
)

REM Initialize database
echo 🗄️ Initializing database...
python -c "from app import app, db; app.app_context().push(); db.create_all(); print('✓ Database initialized successfully')"

REM Display completion message
echo.
echo 🎉 Setup complete! Starting the application...
echo.
echo 📋 Default login credentials:
echo    Admin: admin@elms.com / admin123
echo    Manager: manager@elms.com / manager123
echo    Employee: employee@elms.com / employee123
echo.
echo 🌐 Access the application at: http://127.0.0.1:5000
echo.
echo Press Ctrl+C to stop the server
echo.

REM Run the application
python app.py

pause
