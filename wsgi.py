import sys
from dotenv import load_dotenv
import os

path = '/home/tukarje/tukar-je'
if path not in sys.path:
    sys.path.append(path)

# Load environment variables from .env file
load_dotenv(os.path.join(path, '.env'))

from run import app as application 