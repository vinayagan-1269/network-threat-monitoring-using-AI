# AI Network Threat Monitor

An AI-assisted network threat monitoring system that captures live network traffic, extracts network flow features, and uses a machine learning model to identify suspicious network activity.

## 🚀 Overview

The system monitors live network traffic and processes it through an automated pipeline:

**Live Traffic → WinDump → PCAP → CICFlowMeter → Feature Adapter → Machine Learning Model → Prediction → SQLite Database → Flask Dashboard**

The machine learning model classifies network flows into:

- **BENIGN**
- **PortScan**
- **DDoS**

Detected network activity and flow information are stored in an SQLite database for monitoring and historical analysis.

## ✨ Features

- Live network traffic capture
- Automated PCAP generation
- Network flow feature extraction using CICFlowMeter
- Machine learning-based traffic classification
- Detection of PortScan and DDoS activity
- Flask-based web dashboard
- Live network flow monitoring
- Threat statistics and alerts
- Monitoring history
- SQLite-based data storage
- Network interface selection and monitoring control

## 🏗️ System Architecture

```text
Live Network Traffic
        │
        ▼
     WinDump
        │
        ▼
   PCAP Capture
        │
        ▼
   CICFlowMeter
        │
        ▼
  Feature Adapter
        │
        ▼
Machine Learning Model
        │
        ▼
    Prediction
        │
        ▼
   SQLite Database
        │
        ▼
  Flask Dashboard
🛠️ Technologies Used
Programming
Python
JavaScript
HTML
CSS
Backend & Database
Flask
SQLite
Pandas
Joblib
Network & Security
WinDump
CICFlowMeter
Network Traffic Analysis
Machine Learning
📂 Project Structure
network-threat-monitoring-using-AI/
│
├── app.py
├── automated_pipeline.py
├── database.py
├── test_database.py
├── requirements.txt
├── .gitignore
│
├── models/
│   └── attack_model.pkl
│
├── static/
│   ├── script.js
│   └── style.css
│
└── templates/
    └── dashboard.html
⚙️ How It Works
1. Network Capture

WinDump captures live network traffic from the selected network interface and generates a PCAP file.

2. Flow Extraction

CICFlowMeter processes the captured packets and extracts network flow features.

3. Feature Processing

The extracted features are adapted to match the feature structure expected by the trained machine learning model.

4. Threat Classification

The machine learning model analyzes each network flow and classifies it as:

BENIGN
PortScan
DDoS
5. Data Storage

Network flows and detected security events are stored in an SQLite database for monitoring and historical analysis.

6. Dashboard

The Flask application provides a web-based dashboard for viewing:

Live network flows
Threat statistics
Security alerts
Monitoring history
Flow details
📦 Installation
1. Clone the repository
git clone https://github.com/vinayagan-1269/network-threat-monitoring-using-AI.git
2. Navigate into the project
cd network-threat-monitoring-using-AI
3. Install Python dependencies
pip install -r requirements.txt
🔧 External Dependencies

This project also requires:

WinDump
CICFlowMeter

These tools must be installed separately and configured on the system.

▶️ Running the Application

Start the Flask application:

python app.py

Then open the local dashboard in your browser.

📊 Detection Classes
Class	Description
BENIGN	Normal network traffic
PortScan	Network activity associated with port scanning
DDoS	Network activity associated with distributed denial-of-service behavior
⚠️ Limitations
Prediction accuracy depends on the quality and coverage of the training dataset.
Different network interfaces may require different capture configurations or feature adaptations.
Detection performance depends on whether observed traffic resembles patterns represented in the training data.
The current implementation is intended for monitoring and educational/research purposes.
🔮 Future Improvements
Support for additional attack classes
Improved feature adaptation for different network environments
Real-time notification mechanisms
Improved model accuracy using larger and more diverse datasets
Deployment on dedicated monitoring infrastructure
Additional visualization and reporting features
👨‍💻 Author

Vinayagan S

B.Tech CSE, Cyber Security
VIT-AP University

LinkedIn1
