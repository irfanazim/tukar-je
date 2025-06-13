from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail
from sqlalchemy import event
from sqlalchemy.engine import Engine
import sqlite3
from flask_migrate import Migrate
from flask_login import LoginManager, current_user

# Enable foreign key support in SQLite
@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    if isinstance(dbapi_connection, sqlite3.Connection):  
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON;")
        cursor.close()

# Initialize extensions
db = SQLAlchemy()
mail = Mail()
migrate = Migrate()

def create_app():
    app = Flask(__name__)
    
    # Load configuration
    app.config.from_object('app.config.Config')
    
    # Initialize extensions with app
    db.init_app(app)
    mail.init_app(app)
    migrate.init_app(app, db)

    # Setup Login Manager
    login_manager = LoginManager()
    login_manager.init_app(app)

    from .models import User  

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    login_manager.login_view = 'main.login'
    login_manager.login_message_category = 'info'
    
    # Register blueprints
    from .routes import main
    app.register_blueprint(main)
    
    return app