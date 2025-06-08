import os
from app import create_app, db

app = create_app()

if __name__ == '__main__':
    # For production deployment
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port) 