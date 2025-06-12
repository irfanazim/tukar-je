import os
from app import create_app, db

app = create_app()

# Create database tables
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True) 