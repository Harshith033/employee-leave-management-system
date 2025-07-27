#!/bin/bash
# Deployment script for Employee Leave Management System

echo "🚀 Employee Leave Management System - Deployment Script"
echo "======================================================="

# Check Python version
python_version=$(python --version 2>&1)
echo "✓ Python version: $python_version"

# Create virtual environment if it doesn't exist
if [ ! -d ".venv" ]; then
    echo "📦 Creating virtual environment..."
    python -m venv .venv
    echo "✓ Virtual environment created"
else
    echo "✓ Virtual environment already exists"
fi

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source .venv/Scripts/activate || source .venv/bin/activate

# Upgrade pip
echo "⬆️ Upgrading pip..."
python -m pip install --upgrade pip

# Install dependencies
echo "📥 Installing dependencies..."
pip install -r requirements.txt

# Create .env file if it doesn't exist
if [ ! -f ".env" ]; then
    echo "📝 Creating .env file from template..."
    cp .env.template .env
    echo "⚠️ Please update .env file with your actual configuration values"
else
    echo "✓ .env file already exists"
fi

# Initialize database
echo "🗄️ Initializing database..."
python -c "
from app import app, db
with app.app_context():
    db.create_all()
    print('✓ Database initialized successfully')
"

# Run the application
echo ""
echo "🎉 Setup complete! Starting the application..."
echo ""
echo "📋 Default login credentials:"
echo "   Admin: admin@elms.com / admin123"
echo "   Manager: manager@elms.com / manager123" 
echo "   Employee: employee@elms.com / employee123"
echo ""
echo "🌐 Access the application at: http://127.0.0.1:5000"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

python app.py
