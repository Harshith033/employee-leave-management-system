from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, DateField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Email, Length, ValidationError, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date, timedelta
import pandas as pd
import os
from functools import wraps
from io import BytesIO
import secrets

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///leaves.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# Initialize Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Rest of your application code will go here...
# I'll add it in the next step
