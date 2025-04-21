from flask import Flask, render_template
from routes.traffic import traffic
from routes.data import data  # Add this import
import os
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Secure random secret key

# Create necessary folders
UPLOAD_FOLDER = os.path.join(app.root_path, 'uploads')
MODEL_FOLDER = os.path.join(app.root_path, 'models')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(MODEL_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MODEL_FOLDER'] = MODEL_FOLDER

# Register blueprints
app.register_blueprint(traffic, url_prefix='/traffic')
app.register_blueprint(data, url_prefix='/data')  # Add this line

# Routes
@app.route('/')
def home():
    logger.info("Serving home page")
    return render_template('home.html')

if __name__ == '__main__':
    logger.info("Starting Flask application")
    app.run(debug=True, host='0.0.0.0', port=5000)