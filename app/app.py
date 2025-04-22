from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail
import os
import secrets
from datetime import timedelta
from dotenv import load_dotenv

# Load environment 
load_dotenv()

app = Flask(__name__)

# Initialize extensions
db = SQLAlchemy(app)
mail = Mail(app)

# Import routes after app is created 
from routes import *

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True) 