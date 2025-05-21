# config.py
import os

# Flask DEBUG mode. Set to False in production.
DEBUG = True  # Change to False for production

# Secret key for session management, CSRF protection, etc.
# IMPORTANT: Change this to a long, random, and secret string in production!
# You can generate one using: import os; os.urandom(24)
SECRET_KEY = os.environ.get('SECRET_KEY') or 'your_very_secret_and_random_key_should_go_here'

# --- Application Specific Configurations ---

# Folder to store uploaded files
UPLOAD_FOLDER = 'uploads'

# Time in seconds before uploaded files expire and are deleted
EXPIRATION_TIME = 24 * 60 * 60  # 24 hours

# Custom domain (or IP:Port) to be used in the returned file URLs
# IMPORTANT: For production, set this via an environment variable or a production-specific config.
# Example for local development: 'http://localhost:8080'
# Example for production: 'https://your-actual-domain.com'
CUSTOM_DOMAIN = os.environ.get('CUSTOM_DOMAIN') or 'http://localhost:8080'

# --- URL Download Feature Configurations ---

# Chunk size for streaming downloads from URLs
DOWNLOAD_CHUNK_SIZE = 8192  # 8KB

# Timeout in seconds for requests when downloading from a URL
DOWNLOAD_TIMEOUT = 30  # 30 seconds

# Number of retries if a URL download fails
DOWNLOAD_RETRIES = 3

# Backoff factor for retries (e.g., 0.5 -> retries after 0.5s, 1s, 2s, ...)
DOWNLOAD_BACKOFF_FACTOR = 0.5

# --- Optional: Database Configuration (if you add a database later) ---
# SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///site.db'
# SQLALCHEMY_TRACK_MODIFICATIONS = False
