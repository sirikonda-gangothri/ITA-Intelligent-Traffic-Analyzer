document.addEventListener('DOMContentLoaded', function() {
    // DOM Elements
    const startBtn = document.getElementById('startBtn');
    const stopBtn = document.getElementById('stopBtn');
    const modelUpload = document.getElementById('modelUpload');
    const modelStatus = document.getElementById('modelStatus');
    const statusElement = document.getElementById('status');
    const fileInfoElement = document.getElementById('fileInfo');
    const packetCountElement = document.getElementById('packetCount');
    const threatLevelElement = document.getElementById('threatLevel');
    const activityLog = document.getElementById('activityLog');
    const predictionTableBody = document.getElementById('predictionTableBody');
    const trafficGraph = document.getElementById('trafficGraph');
    const resetModelBtn = document.createElement('button');
    let emptyRow = predictionTableBody.querySelector('.empty-row');

    // State variables
    let isCapturing = false;
    let updateInterval;
    let threatCount = 0;
    let totalPackets = 0;

    // Initialize reset button
    resetModelBtn.textContent = 'Reset Model';
    resetModelBtn.className = 'btn btn-secondary';
    resetModelBtn.style.marginLeft = '10px';
    resetModelBtn.disabled = true;
    modelUpload.parentNode.appendChild(resetModelBtn);

    // Add log entry
    function addLogEntry(message) {
        const timestamp = new Date().toLocaleTimeString();
        const entry = document.createElement('div');
        entry.className = 'log-entry';
        entry.innerHTML = `[<span class="log-time">${timestamp}</span>] ${message}`;
        activityLog.appendChild(entry);
        activityLog.scrollTop = activityLog.scrollHeight;
    }

    // Update status
    function updateStatus(status, message) {
        statusElement.className = `status-card status-${status}`;
        statusElement.innerHTML = `
            <i class="fas fa-${getStatusIcon(status)}"></i>
            <span class="status-text">${message}</span>
        `;
        
        if (status === 'active') {
            startBtn.disabled = true;
            stopBtn.disabled = false;
            isCapturing = true;
        } else {
            startBtn.disabled = !modelUpload.files.length || modelStatus.textContent.includes('failed');
            stopBtn.disabled = true;
            isCapturing = false;
        }
    }

    function getStatusIcon(status) {
        const icons = {
            ready: 'info-circle',
            active: 'play-circle',
            stopped: 'stop-circle',
            error: 'exclamation-circle'
        };
        return icons[status] || 'info-circle';
    }

    // Format time
    function formatTime(timestamp) {
        return new Date(timestamp).toLocaleTimeString();
    }

    // Update threat level display
    function updateThreatLevel(threatCount, totalPackets) {
        if (totalPackets === 0) {
            threatLevelElement.textContent = 'Unknown';
            threatLevelElement.className = 'stat-value';
            return;
        }
        
        const threatPercentage = (threatCount / totalPackets) * 100;
        
        if (threatPercentage > 20) {
            threatLevelElement.textContent = `High (${threatPercentage.toFixed(1)}%)`;
            threatLevelElement.className = 'stat-value threat-high';
        } else if (threatPercentage > 5) {
            threatLevelElement.textContent = `Medium (${threatPercentage.toFixed(1)}%)`;
            threatLevelElement.className = 'stat-value threat-medium';
        } else {
            threatLevelElement.textContent = `Low (${threatPercentage.toFixed(1)}%)`;
            threatLevelElement.className = 'stat-value threat-low';
        }
    }

    // Update prediction display
    function updatePredictionDisplay() {
        fetch('/traffic/get_predictions')
            .then(response => {
                if (!response.ok) throw new Error(`HTTP error! Status: ${response.status}`);
                return response.json();
            })
            .then(data => {
                if (emptyRow) {
                    emptyRow.remove();
                    emptyRow = null;
                }

                predictionTableBody.innerHTML = '';
                
                data.predictions.slice().reverse().forEach(pred => {
                    const row = document.createElement('tr');
                    row.className = pred.prediction === 'Malicious' ? 'threat-row' : '';
                    row.innerHTML = `
                        <td>${formatTime(pred.timestamp)}</td>
                        <td>${pred.source_ip}</td>
                        <td>${pred.destination_ip}</td>
                        <td>${pred.max_packet_length}</td>
                        <td class="prediction-cell ${pred.prediction === 'Malicious' ? 'threat' : 'normal'}">
                            ${pred.prediction}
                        </td>
                    `;
                    predictionTableBody.appendChild(row);
                });

                packetCountElement.textContent = data.count || 0;
                totalPackets = data.count || 0;
                
                threatCount = data.predictions.filter(p => p.prediction === 'Malicious').length;
                updateThreatLevel(threatCount, totalPackets);
                
                if (data.graph) {
                    trafficGraph.src = `data:image/png;base64,${data.graph}`;
                }
            })
            .catch(error => {
                console.error('Error fetching predictions:', error);
                addLogEntry(`Error fetching predictions: ${error.message}`);
            });
    }

    // Model upload handler
    modelUpload.addEventListener('change', function() {
        if (!this.files.length) return;
        
        modelStatus.textContent = 'Uploading...';
        modelStatus.style.color = 'var(--warning-color)';
        
        const formData = new FormData();
        formData.append('model', this.files[0]);
        
        fetch('/traffic/load_model', {
            method: 'POST',
            body: formData,
            headers: {
                'Accept': 'application/json'
            }
        })
        .then(response => {
            const contentType = response.headers.get('content-type');
            if (!contentType || !contentType.includes('application/json')) {
                return response.text().then(text => {
                    throw new Error(`Server error: ${text.substring(0, 100)}`);
                });
            }
            return response.json();
        })
        .then(data => {
            if (data.error) {
                throw new Error(data.error);
            }
            modelStatus.textContent = `Model loaded (${data.model_type})`;
            modelStatus.style.color = 'var(--success-color)';
            addLogEntry(`Model loaded successfully. Expected features: ${data.features_expected}, scikit-learn version: ${data.sklearn_version}`);
            startBtn.disabled = false;
            resetModelBtn.disabled = false;
        })
        .catch(error => {
            modelStatus.textContent = 'Model load failed';
            modelStatus.style.color = 'var(--danger-color)';
            addLogEntry(`Error loading model: ${error.message}`);
            console.error('Model load error:', error);
            startBtn.disabled = true;
            resetModelBtn.disabled = false;
        });
    });

    // Reset model handler
    resetModelBtn.addEventListener('click', function() {
        modelUpload.value = '';
        modelStatus.textContent = 'No model loaded';
        modelStatus.style.color = 'var(--text-color)';
        startBtn.disabled = true;
        resetModelBtn.disabled = true;
        addLogEntry('Model reset');
    });

    // Start capture
    startBtn.addEventListener('click', function() {
        fetch('/traffic/start_capture', { method: 'POST' })
            .then(response => {
                if (!response.ok) throw new Error(`HTTP error! Status: ${response.status}`);
                return response.json();
            })
            .then(data => {
                updateStatus('active', 'Analyzing network traffic...');
                fileInfoElement.textContent = data.output_file;
                addLogEntry('Analysis started with model');
                
                updateInterval = setInterval(updatePredictionDisplay, 500);
                updatePredictionDisplay();
            })
            .catch(error => {
                updateStatus('error', 'Error starting analysis');
                addLogEntry(`Error: ${error.message}`);
                console.error('Capture error:', error);
            });
    });

    // Stop capture
    stopBtn.addEventListener('click', function() {
        fetch('/traffic/stop_capture', { method: 'POST' })
            .then(response => {
                if (!response.ok) throw new Error(`HTTP error! Status: ${response.status}`);
                return response.json();
            })
            .then(data => {
                clearInterval(updateInterval);
                updateStatus('stopped', 'Analysis completed');
                addLogEntry(`Analysis stopped. ${data.count} packets analyzed`);
                updatePredictionDisplay();
            })
            .catch(error => {
                updateStatus('error', 'Error stopping analysis');
                addLogEntry(`Error: ${error.message}`);
            });
    });

    // Initial setup
    updateStatus('ready', 'Load model to begin analysis');
    addLogEntry('System initialized');
});