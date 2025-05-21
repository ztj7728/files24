import os
import time
import uuid
import shutil # shutil is not explicitly used in the final version, but good to have for file ops
from flask import Flask, request, jsonify, send_from_directory, current_app
from threading import Thread
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry # Corrected import path for Retry
from urllib.parse import urlparse, unquote
import logging
import re # For cleaning filenames

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# --- Load Configuration ---
# This will load variables from config.py into app.config
try:
    app.config.from_pyfile('config.py')
    logger.info("Configuration loaded from config.py")
except FileNotFoundError:
    logger.error("config.py not found. Please ensure it exists.")
    # Fallback to default settings or exit (depending on your needs)
    # For this example, we'll let it potentially fail later if config keys are missing
    # or define minimal defaults here:
    app.config.setdefault('UPLOAD_FOLDER', 'uploads_default')
    app.config.setdefault('EXPIRATION_TIME', 24 * 60 * 60)
    app.config.setdefault('CUSTOM_DOMAIN', 'http://localhost:5000') # Default if config.py fails
    app.config.setdefault('DOWNLOAD_CHUNK_SIZE', 8192)
    app.config.setdefault('DOWNLOAD_TIMEOUT', 30)
    app.config.setdefault('DOWNLOAD_RETRIES', 3)
    app.config.setdefault('DOWNLOAD_BACKOFF_FACTOR', 0.5)


# Ensure UPLOAD_FOLDER exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    try:
        os.makedirs(app.config['UPLOAD_FOLDER'])
        logger.info(f"Created upload folder: {app.config['UPLOAD_FOLDER']}")
    except OSError as e:
        logger.error(f"Could not create upload folder {app.config['UPLOAD_FOLDER']}: {e}")
        # Potentially exit or handle more gracefully


# --- Helper Functions ---
def sanitize_filename(filename):
    """
    Sanitizes a filename by removing potentially dangerous characters and
    limiting its length.
    Decodes URL-encoded characters first.
    """
    if not filename:
        return ""
    
    # Decode URL-encoded characters like %20
    filename = unquote(filename)

    # Remove directory traversal attempts
    filename = filename.replace("..", "")
    
    # Keep only alphanumeric, dots, underscores, hyphens.
    # Remove or replace other characters.
    filename = re.sub(r'[^\w.\-_]', '_', filename)
    
    # Limit length to prevent excessively long filenames
    max_len = 200 # Max filename length (conservative)
    if len(filename) > max_len:
        name, ext = os.path.splitext(filename)
        name = name[:max_len - len(ext) -1] # -1 for the dot
        filename = name + ext
        
    # Ensure filename is not empty after sanitization
    if not filename.strip("._-"):
        return f"file_{uuid.uuid4().hex[:8]}" # Generic filename if all chars removed
    
    return filename.strip("._-")


def get_filename_from_url(url, response_headers):
    """
    Attempts to extract a filename from the Content-Disposition header or URL.
    """
    filename = None
    # 1. Try Content-Disposition
    content_disposition = response_headers.get('content-disposition')
    if content_disposition:
        # Regex to find filename*=UTF-8''name or filename="name"
        # Prioritize filename* for encoding support
        fn_star_match = re.search(r"filename\*=UTF-8''([\w%.-]+)", content_disposition, re.IGNORECASE)
        if fn_star_match:
            filename = unquote(fn_star_match.group(1))
            logger.info(f"Filename from Content-Disposition (filename*): {filename}")
        else:
            fn_match = re.search(r'filename="?([^"]+)"?', content_disposition, re.IGNORECASE)
            if fn_match:
                filename = fn_match.group(1)
                logger.info(f"Filename from Content-Disposition (filename): {filename}")
    
    # 2. If not found, try from URL path
    if not filename:
        parsed_url = urlparse(url)
        filename_from_path = os.path.basename(parsed_url.path)
        if filename_from_path: # Ensure it's not empty (e.g. URL ends with /)
            filename = filename_from_path
            logger.info(f"Filename from URL path: {filename}")

    # 3. If still no filename, or filename is just an extension or problematic
    if not filename or filename.startswith('.'): # if filename is like ".zip"
        content_type = response_headers.get('content-type', '').split(';')[0].lower()
        ext_map = {
            'image/jpeg': '.jpg', 'image/jpg': '.jpg',
            'image/png': '.png',
            'image/gif': '.gif',
            'application/pdf': '.pdf',
            'text/plain': '.txt',
            'application/zip': '.zip',
            'application/octet-stream': '.bin' # Generic binary
        }
        extension = ext_map.get(content_type, '.dat') # Default extension
        filename = f"downloaded_file{extension}"
        logger.info(f"Generated filename '{filename}' based on content-type or default.")
        
    return sanitize_filename(filename) if filename else f"unknown_file_{uuid.uuid4().hex[:6]}.dat"

def download_file_from_url_with_retry(url_to_download, destination_folder):
    session = requests.Session()
    retry_strategy = Retry(
        total=current_app.config.get('DOWNLOAD_RETRIES', 3),
        backoff_factor=current_app.config.get('DOWNLOAD_BACKOFF_FACTOR', 0.5),
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS"]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    try:
        logger.info(f"Attempting to download from URL: {url_to_download}")
        with session.get(
            url_to_download,
            stream=True,
            timeout=current_app.config.get('DOWNLOAD_TIMEOUT', 30),
            allow_redirects=True # Follow redirects
        ) as r:
            r.raise_for_status()

            original_filename = get_filename_from_url(url_to_download, r.headers)
            
            # Ensure there's a base name and an extension, even if generic
            base, ext = os.path.splitext(original_filename)
            if not base: # If original_filename was just ".txt"
                base = f"file_{uuid.uuid4().hex[:6]}"
            if not ext and base == original_filename: # No extension found at all
                # Try to guess from content-type again for extension if not already done by get_filename_from_url
                content_type = r.headers.get('content-type', '').split(';')[0].lower()
                ext_map = {'image/jpeg': '.jpg', 'image/png': '.png', 'application/pdf': '.pdf'}
                ext = ext_map.get(content_type, '.dat') # Default if no better guess

            unique_filename = f"{uuid.uuid4()}{ext if ext.startswith('.') else '.' + ext if ext else '.dat'}"
            
            file_path = os.path.join(destination_folder, unique_filename)

            with open(file_path, 'wb') as f:
                for chunk in r.iter_content(chunk_size=current_app.config.get('DOWNLOAD_CHUNK_SIZE', 8192)):
                    f.write(chunk)
            
            logger.info(f"Successfully downloaded '{original_filename}' as '{unique_filename}' to '{file_path}'")
            return file_path, unique_filename, None
            
    except requests.exceptions.SSLError as e:
        logger.error(f"SSL Error downloading {url_to_download}: {e}. Consider `verify=False` if trusted, but be cautious.")
        return None, None, f"SSL error: {str(e)}"
    except requests.exceptions.ConnectionError as e:
        logger.error(f"Connection error downloading {url_to_download}: {e}")
        return None, None, f"Connection error: {str(e)}"
    except requests.exceptions.Timeout as e:
        logger.error(f"Timeout downloading {url_to_download}: {e}")
        return None, None, f"Timeout: {str(e)}"
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to download from {url_to_download} after retries: {e}")
        return None, None, f"Download request failed: {str(e)}"
    except Exception as e:
        logger.error(f"An unexpected error occurred during download from {url_to_download}: {e}", exc_info=True)
        return None, None, f"Unexpected error: {str(e)}"

# --- File Cleanup Thread ---
def cleanup_files_task():
    # This function needs to be run within an app context to access current_app.config
    # So, when starting the thread, we pass the app instance.
    # However, for a daemon thread, it's often better if it can re-create context or access config directly.
    # For simplicity here, we assume config is loaded when thread starts.
    
    # Local copy of config values to avoid issues if app context changes (though less likely for daemon)
    # This is more robust if the thread runs independently or if config could change.
    # However, current_app.config should be stable once app is initialized.
    
    _app = current_app._get_current_object() # Get the actual app instance for the thread
    
    logger.info("Cleanup thread started.")
    while True:
        # Access config through the app instance passed or captured
        upload_folder = _app.config.get('UPLOAD_FOLDER')
        expiration_time = _app.config.get('EXPIRATION_TIME')

        if not upload_folder or expiration_time is None:
            logger.error("Cleanup task: UPLOAD_FOLDER or EXPIRATION_TIME not configured. Skipping cleanup cycle.")
            time.sleep(3600) # Sleep for an hour and try again
            continue
            
        try:
            current_time = time.time()
            if not os.path.exists(upload_folder):
                logger.warning(f"Upload folder '{upload_folder}' not found during cleanup. Will check again later.")
                time.sleep(60 * 10) # Check more frequently if folder is missing
                continue

            for filename in os.listdir(upload_folder):
                file_path = os.path.join(upload_folder, filename)
                try:
                    if os.path.isfile(file_path):
                        file_mod_time = os.path.getmtime(file_path)
                        if file_mod_time + expiration_time < current_time:
                            os.remove(file_path)
                            logger.info(f"File {filename} has been removed due to expiration.")
                except FileNotFoundError:
                    # This can happen if file is deleted by another process or request
                    logger.warning(f"File {filename} not found during cleanup scan (possibly already deleted).")
                except Exception as e:
                    logger.error(f"Error removing file {filename} during cleanup: {e}")
        except Exception as e:
            logger.error(f"Error in cleanup_files_task main loop: {e}", exc_info=True)
        
        time.sleep(60 * 60)  # Check every hour


# --- Flask Routes ---
@app.route('/upload', methods=['POST'])
def upload_file_route():
    if 'file' not in request.files:
        logger.warning("Upload attempt with no 'file' part in request.files.")
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']
    if file.filename == '':
        logger.warning("Upload attempt with an empty filename.")
        return jsonify({"error": "No selected file"}), 400

    try:
        # Sanitize the original filename before extracting extension
        original_sanitized_filename = sanitize_filename(file.filename)
        _, file_extension = os.path.splitext(original_sanitized_filename)
        
        unique_filename = f"{uuid.uuid4()}{file_extension if file_extension else '.dat'}"
        
        upload_folder_path = current_app.config['UPLOAD_FOLDER']
        file_path = os.path.join(upload_folder_path, unique_filename)
        
        file.save(file_path)
        
        file_url = f"{current_app.config['CUSTOM_DOMAIN']}/{unique_filename}"
        logger.info(f"File '{original_sanitized_filename}' uploaded as '{unique_filename}'. URL: {file_url}")
        return jsonify({"file_url": file_url, "filename": unique_filename}), 200
    except Exception as e:
        logger.error(f"Error during file upload: {e}", exc_info=True)
        return jsonify({"error": "Server failed to upload file"}), 500

@app.route('/download_from_url', methods=['POST'])
def download_from_url_route():
    data = request.get_json()
    if not data or 'url' not in data:
        logger.warning("Download from URL: Missing 'url' in JSON payload.")
        return jsonify({"error": "Missing 'url' in JSON payload"}), 400

    url_to_download = data['url']
    
    if not (url_to_download.startswith('http://') or url_to_download.startswith('https://')):
        logger.warning(f"Download from URL: Invalid URL scheme for '{url_to_download}'.")
        return jsonify({"error": "Invalid URL scheme. Must be http or https."}), 400

    upload_folder_path = current_app.config['UPLOAD_FOLDER']
    
    saved_file_path, unique_filename, error_message = download_file_from_url_with_retry(url_to_download, upload_folder_path)

    if error_message:
        # Error already logged in download_file_from_url_with_retry
        return jsonify({"error": f"Failed to download file from URL: {error_message}"}), 500
    
    if saved_file_path and unique_filename:
        file_url = f"{current_app.config['CUSTOM_DOMAIN']}/{unique_filename}"
        logger.info(f"File from URL '{url_to_download}' downloaded as '{unique_filename}'. URL: {file_url}")
        return jsonify({"file_url": file_url, "original_url": url_to_download, "filename": unique_filename}), 200
    else:
        # This case should ideally be covered by error_message
        logger.error("Download from URL: Download processing finished but file path or unique filename is missing.")
        return jsonify({"error": "An unknown error occurred during download processing."}), 500


@app.route('/<path:filename>')
def get_file_route(filename):
    # Sanitize filename again for serving, although UUIDs should be safe
    # This is more for defense in depth if the source of filename could be tampered with
    # However, since our filenames are UUIDs, this is less critical here.
    # filename = sanitize_filename(filename) # Already sanitized by UUID usually

    upload_folder_path = current_app.config['UPLOAD_FOLDER']
    
    # Security: Basic check to prevent path traversal, send_from_directory handles most of this.
    # Ensure the requested filename does not try to escape the UPLOAD_FOLDER.
    # os.path.abspath and os.path.normpath are good tools here.
    safe_base_path = os.path.abspath(upload_folder_path)
    requested_file_path = os.path.abspath(os.path.join(upload_folder_path, filename))

    if not requested_file_path.startswith(safe_base_path):
        logger.warning(f"Access Denied: Attempt to access file outside upload folder: '{filename}' resolved to '{requested_file_path}'")
        return jsonify({"error": "Access denied. Invalid path."}), 403 # Forbidden

    # send_from_directory is generally safe and handles Content-Type, etc.
    # It will raise a 404 if file not found within the directory.
    try:
        logger.info(f"Serving file: {filename} from {upload_folder_path}")
        return send_from_directory(upload_folder_path, filename, as_attachment=False) # as_attachment=True to force download
    except FileNotFoundError:
        logger.warning(f"File not found for serving: {filename} in {upload_folder_path}")
        return jsonify({"error": "File not found"}), 404
    except Exception as e:
        logger.error(f"Error serving file {filename}: {e}", exc_info=True)
        return jsonify({"error": "Server error while trying to serve file"}), 500

if __name__ == '__main__':
    # Start cleanup thread
    # The check for WERKZEUG_RUN_MAIN is to prevent the thread from starting twice
    # when Flask's reloader is active (debug=True).
    if not app.debug or os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        # Pass the app instance to the thread target if it needs app context
        # Or, ensure the thread function can get app context correctly.
        # For daemon threads, it's usually cleaner if they operate with minimal direct dependency on the app object
        # if they are truly standalone. But for config access, app context is needed.
        with app.app_context(): # Ensure app context is available for the thread to read config
            cleanup_thread = Thread(target=cleanup_files_task, daemon=True)
            cleanup_thread.start()
            logger.info("Cleanup thread initiated.")
    else:
        logger.info("Cleanup thread will start with Werkzeug reloader's main process.")

    # Get host and port from config or use defaults
    host = os.environ.get('FLASK_RUN_HOST', '0.0.0.0')
    port = int(os.environ.get('FLASK_RUN_PORT', 8080))
    
    logger.info(f"Starting Flask server on {host}:{port} with debug={app.debug}")
    app.run(host=host, port=port, debug=app.debug)
