"""
Employee Leave Management System (ELMS)
Configuration settings and environment variables
"""

import os
from datetime import timedelta

class Config:
    """Base configuration class"""
    
    # Basic Flask configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    
    # Database configuration
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///elms.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Session configuration
    PERMANENT_SESSION_LIFETIME = timedelta(hours=2)
    SESSION_COOKIE_SECURE = False  # Set to True in production with HTTPS
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # Application settings
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = None
    
    # File upload settings (if needed for future features)
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    
    # Pagination settings
    POSTS_PER_PAGE = 25
    
    # Email settings (for future email notifications)
    MAIL_SERVER = os.environ.get('MAIL_SERVER')
    MAIL_PORT = int(os.environ.get('MAIL_PORT') or 587)
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', 'on', '1']
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    
    # Admin settings
    ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL') or 'admin@elms.com'
    
    # Logging configuration
    LOG_LEVEL = os.environ.get('LOG_LEVEL') or 'INFO'
    
    @staticmethod
    def init_app(app):
        """Initialize application with this config"""
        pass

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or 'sqlite:///elms-dev.db'

class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('TEST_DATABASE_URL') or 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///elms.db'
    SESSION_COOKIE_SECURE = True  # Require HTTPS
    
    @classmethod
    def init_app(cls, app):
        Config.init_app(app)
        
        # Log to stderr in production
        import logging
        from logging import StreamHandler
        file_handler = StreamHandler()
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)

class HerokuConfig(ProductionConfig):
    """Heroku-specific configuration"""
    SSL_REDIRECT = True
    
    @classmethod
    def init_app(cls, app):
        ProductionConfig.init_app(app)
        
        # Handle reverse proxy headers
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app)

# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'heroku': HerokuConfig,
    'default': DevelopmentConfig
}

# Default roles and permissions
DEFAULT_ROLES = {
    'admin': {
        'permissions': ['manage_users', 'view_all_requests', 'export_data', 'view_audit_logs'],
        'description': 'Full system access'
    },
    'manager': {
        'permissions': ['manage_team_requests', 'view_team_data', 'apply_leave'],
        'description': 'Team management and own leave requests'
    },
    'employee': {
        'permissions': ['apply_leave', 'view_own_requests'],
        'description': 'Basic employee leave management'
    }
}

# Application constants
APP_NAME = "Employee Leave Management System"
APP_VERSION = "1.0.0"
APP_DESCRIPTION = "A comprehensive role-based leave management system"

# Leave request statuses
LEAVE_STATUS = {
    'PENDING': 'pending',
    'APPROVED': 'approved', 
    'REJECTED': 'rejected'
}

# Audit log action types
AUDIT_ACTIONS = {
    'LOGIN': 'User logged in',
    'LOGOUT': 'User logged out',
    'LEAVE_APPLY': 'Applied for leave',
    'LEAVE_EDIT': 'Edited leave request',
    'LEAVE_CANCEL': 'Cancelled leave request',
    'LEAVE_APPROVE': 'Approved leave request',
    'LEAVE_REJECT': 'Rejected leave request',
    'USER_CREATE': 'Created new user',
    'USER_DELETE': 'Deleted user',
    'EXPORT_CSV': 'Exported data to CSV',
    'EXPORT_PDF': 'Exported data to PDF'
}
