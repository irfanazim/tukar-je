from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail

# Initialize extensions
db = SQLAlchemy()
mail = Mail()

def create_app():
    app = Flask(__name__)
    
    # Load configuration
    app.config.from_object('app.config.Config')
    
    # Initialize extensions with app
    db.init_app(app)
    mail.init_app(app)
    
    # Register blueprints
    from .routes import main
    app.register_blueprint(main)
    
    return app 