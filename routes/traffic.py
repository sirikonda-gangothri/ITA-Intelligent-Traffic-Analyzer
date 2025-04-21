from flask import Blueprint, jsonify, request, render_template, send_file, abort
from scapy.all import sniff, IP, TCP, conf
import csv
import os
import threading
from datetime import datetime
from collections import deque
import pickle
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import io
import base64
import joblib
import tempfile
import shutil
import sklearn
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

traffic = Blueprint('traffic', __name__, template_folder='templates')

# Global variables
is_monitoring = False
csv_file = os.path.join('data', 'network_traffic_features.csv')
packet_queue = deque(maxlen=1000)
prediction_queue = deque(maxlen=100)
capture_thread = None
loaded_model = None
model_loaded = False
graph_data = deque(maxlen=50)

# Ensure data directory exists
os.makedirs('data', exist_ok=True)

def select_network_interface():
    """Select the most appropriate network interface"""
    for iface in conf.ifaces:
        iface_name = conf.ifaces[iface].name
        if 'Ethernet' in iface_name or 'Wi-Fi' in iface_name or 'eth' in iface_name.lower():
            return iface_name
    return conf.ifaces.dev_from_index(0).name if conf.ifaces else None

def predict_traffic(packet_features):
    """Predict traffic type using loaded model"""
    if not model_loaded or loaded_model is None:
        return "No model loaded"
    
    try:
        # Get all available features from the packet
        available_features = {k: v for k, v in packet_features.items() 
                            if k not in ['timestamp', 'source_ip', 'destination_ip', 'prediction']}
        
        # Get the number of features the model expects
        expected_features = getattr(loaded_model, 'n_features_in_', len(available_features))
        
        # Prepare feature array with zeros
        features = np.zeros(expected_features)
        
        # Fill in available features up to the expected number
        for i, (key, value) in enumerate(available_features.items()):
            if i < expected_features:
                features[i] = value
        
        features_array = features.reshape(1, -1)
        prediction = loaded_model.predict(features_array)[0]
        
        prediction_labels = {0: "Normal", 1: "Malicious"}
        return prediction_labels.get(prediction, str(prediction))
    except Exception as e:
        logger.error(f"Prediction error: {str(e)}")
        return "Prediction error"

@traffic.route('/load_model', methods=['POST'])
def load_model():
    global loaded_model, model_loaded
    
    if 'model' not in request.files:
        logger.error("No file part in request")
        return jsonify({'error': 'No file uploaded'}), 400
    
    model_file = request.files['model']
    
    if not model_file or model_file.filename == '':
        logger.error("No selected file")
        return jsonify({'error': 'No selected file'}), 400
        
    # Accept .pkl, .joblib, and .sav files
    if not model_file.filename.lower().endswith(('.pkl', '.joblib', '.sav')):
        logger.error(f"Invalid file type: {model_file.filename}")
        return jsonify({'error': 'Invalid file type. Please upload a .pkl, .joblib, or .sav file'}), 400
    
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = os.path.join(temp_dir, model_file.filename)
            model_file.save(temp_path)
            logger.info(f"Saved uploaded file to {temp_path}")
            
            # Try loading with joblib first
            try:
                loaded_model = joblib.load(temp_path)
                logger.info("Model loaded successfully with joblib")
            except Exception as joblib_error:
                logger.warning(f"Joblib load failed: {str(joblib_error)}. Trying pickle...")
                try:
                    with open(temp_path, 'rb') as f:
                        loaded_model = pickle.load(f)
                    logger.info("Model loaded successfully with pickle")
                except Exception as pickle_error:
                    error_msg = f"Failed to load model: {str(pickle_error)}"
                    logger.error(error_msg)
                    return jsonify({'error': error_msg}), 400
            
            if not hasattr(loaded_model, 'predict'):
                error_msg = "Uploaded file is not a valid scikit-learn model (missing predict method)"
                logger.error(error_msg)
                return jsonify({'error': error_msg}), 400
            
            model_loaded = True
            expected_features = getattr(loaded_model, 'n_features_in_', 'Unknown')
            logger.info(f"Model loaded successfully. Expected features: {expected_features}, scikit-learn version: {sklearn.__version__}")
            
            return jsonify({
                'status': 'Model loaded successfully',
                'model_type': str(type(loaded_model).__name__),
                'features_expected': expected_features,
                'sklearn_version': sklearn.__version__
            })
            
    except Exception as e:
        logger.error(f"Error loading model: {str(e)}")
        return jsonify({
            'error': f'Error loading model: {str(e)}',
            'advice': 'Ensure the file is a valid scikit-learn model saved with joblib or pickle.'
        }), 500

@traffic.route('/start_capture', methods=['POST'])
def start_capture():
    global is_monitoring, capture_thread
    
    if is_monitoring:
        return jsonify({'error': 'Capture already running'}), 400
    
    if not model_loaded:
        return jsonify({'error': 'No model loaded'}), 400
    
    is_monitoring = True
    packet_queue.clear()
    prediction_queue.clear()
    graph_data.clear()
    
    capture_thread = threading.Thread(target=start_sniffing)
    capture_thread.daemon = True
    capture_thread.start()
    
    return jsonify({
        'status': 'Capture started',
        'output_file': os.path.abspath(csv_file),
        'message': f"Capturing network traffic to {csv_file}"
    })

def start_sniffing():
    """Start packet capture on selected interface"""
    global is_monitoring
    
    try:
        if not os.path.exists(csv_file):
            with open(csv_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=[
                    'timestamp', 'source_ip', 'destination_ip',
                    'avg_bwd_segment_size', 'bwd_packet_length_mean',
                    'init_win_bytes_forward', 'fwd_iat_max', 'fwd_iat_total',
                    'max_packet_length', 'bwd_packet_length_max',
                    'bwd_packet_length_std', 'bwd_iat_max',
                    'init_win_bytes_backward', 'bwd_iat_total', 'prediction'
                ])
                writer.writeheader()

        iface = select_network_interface()
        if iface:
            logger.info(f"Starting capture on interface {iface}")
            sniff(prn=process_packet, store=False, stop_filter=lambda x: not is_monitoring, iface=iface)
        else:
            logger.error("No suitable network interface found")
    except Exception as e:
        logger.error(f"Capture error: {str(e)}")
    finally:
        is_monitoring = False

@traffic.route('/stop_capture', methods=['POST'])
def stop_capture():
    global is_monitoring
    
    if not is_monitoring:
        return jsonify({'error': 'No capture running'}), 400
    
    is_monitoring = False
    
    if capture_thread and capture_thread.is_alive():
        capture_thread.join(timeout=5)
    
    return jsonify({
        'status': 'Capture stopped',
        'output_file': os.path.abspath(csv_file),
        'count': len(prediction_queue),
        'message': f"Capture stopped. {len(prediction_queue)} packets analyzed"
    })

@traffic.route('/get_predictions')
def get_predictions():
    """Endpoint to get recent predictions for display"""
    try:
        graph_img = generate_graph()
        return jsonify({
            'predictions': list(prediction_queue)[-100:],
            'count': len(prediction_queue),
            'graph': graph_img
        })
    except Exception as e:
        logger.error(f"Error getting predictions: {str(e)}")
        return jsonify({'error': str(e)}), 500

def generate_graph():
    """Generate visualization graph"""
    if not graph_data:
        return None
    
    try:
        plt.figure(figsize=(10, 4))
        timestamps = [d['timestamp'] for d in graph_data]
        lengths = [d['length'] for d in graph_data]
        predictions = [d['prediction'] for d in graph_data]
        
        try:
            times = [datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%f") for ts in timestamps]
        except ValueError:
            times = [datetime.strptime(ts.split('.')[0], "%Y-%m-%dT%H:%M:%S") for ts in timestamps]
        
        fig, ax1 = plt.subplots(figsize=(10, 4))
        ax1.plot(times, lengths, 'b-', label='Packet Size')
        ax1.set_xlabel('Time')
        ax1.set_ylabel('Packet Size (bytes)', color='b')
        ax1.tick_params('y', colors='b')
        
        ax2 = ax1.twinx()
        pred_numeric = [1 if p == "Malicious" else 0 for p in predictions]
        ax2.plot(times, pred_numeric, 'r--', label='Prediction (Malicious)')
        ax2.set_ylabel('Prediction', color='r')
        ax2.tick_params('y', colors='r')
        ax2.set_yticks([0, 1])
        ax2.set_yticklabels(['Normal', 'Malicious'])
        
        plt.title('Network Traffic Analysis')
        fig.tight_layout()
        
        buf = io.BytesIO()
        plt.savefig(buf, format='png', dpi=100)
        buf.seek(0)
        plt.close()
        
        return base64.b64encode(buf.read()).decode('utf-8')
    except Exception as e:
        logger.error(f"Error generating graph: {str(e)}")
        return None

@traffic.route('/')
def traffic_home():
    try:
        return render_template('traffic.html')
    except Exception as e:
        logger.error(f"Error rendering traffic page: {str(e)}")
        abort(404)

@traffic.route('/download_csv')
def download_csv():
    if not os.path.exists(csv_file):
        logger.error("CSV file not found")
        return jsonify({'error': 'No data file available'}), 404
    
    try:
        return send_file(
            csv_file,
            as_attachment=True,
            download_name='network_traffic_analysis.csv',
            mimetype='text/csv'
        )
    except Exception as e:
        logger.error(f"Error sending CSV file: {str(e)}")
        return jsonify({'error': str(e)}), 500

def process_packet(packet):
    """Process each captured packet and extract features"""
    if IP in packet:
        row = {
            'timestamp': datetime.now().isoformat(),
            'source_ip': packet[IP].src,
            'destination_ip': packet[IP].dst,
            'avg_bwd_segment_size': 0,
            'bwd_packet_length_mean': 0,
            'init_win_bytes_forward': 0,
            'fwd_iat_max': 0,
            'fwd_iat_total': 0,
            'max_packet_length': len(packet),
            'bwd_packet_length_max': 0,
            'bwd_packet_length_std': 0,
            'bwd_iat_max': 0,
            'init_win_bytes_backward': 0,
            'bwd_iat_total': 0,
            'prediction': 'Unknown'
        }

        if TCP in packet:
            row['init_win_bytes_forward'] = packet[TCP].window if 'window' in packet[TCP].fields else 0
        
        if model_loaded:
            row['prediction'] = predict_traffic(row)
        else:
            row['prediction'] = "No model"
        
        packet_queue.append(row)
        prediction_queue.append(row)
        
        graph_data.append({
            'timestamp': row['timestamp'],
            'length': row['max_packet_length'],
            'prediction': row['prediction']
        })
        
        try:
            file_exists = os.path.isfile(csv_file)
            with open(csv_file, 'a', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=row.keys())
                if not file_exists:
                    writer.writeheader()
                writer.writerow(row)
        except Exception as e:
            logger.error(f"Error writing to CSV: {str(e)}")
        
        return row
    return None