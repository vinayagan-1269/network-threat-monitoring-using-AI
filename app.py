from flask import Flask, render_template, jsonify
import pandas as pd
import os
import subprocess
import sys
from pandas.errors import EmptyDataError
from flask import Flask, render_template, jsonify, request
import database

app = Flask(__name__)


# --------------------------------------------------
# PATHS
# --------------------------------------------------

CSV_FILE = r"D:\studies PDF\sih 2026\imp\ml training\dataset\live_test.csv"

PIPELINE_FILE = r"D:\studies PDF\sih 2026\working model\automated_pipeline.py"

WINDUMP_PATH = r"C:\WinDump\WinDump.exe"

# --------------------------------------------------
# MONITORING PROCESS
# --------------------------------------------------

pipeline_process = None


# --------------------------------------------------
# DASHBOARD
# --------------------------------------------------

@app.route("/")
def dashboard():

    return render_template("dashboard.html")


# --------------------------------------------------
# AVAILABLE NETWORK INTERFACES
# --------------------------------------------------

@app.route("/api/interfaces")
def get_interfaces():

    result = subprocess.run(
        [WINDUMP_PATH, "-D"],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:

        return jsonify({
            "status": "error",
            "message": "Could not retrieve network interfaces.",
            "details": result.stderr
        }), 500

    interfaces = []

    for line in result.stdout.splitlines():

        line = line.strip()

        if not line:
            continue

        # WinDump format:
        # 1.\Device\NPF_{...} (description)

        parts = line.split(".", 1)

        if len(parts) != 2:
            continue

        try:
            number = int(parts[0])
        except ValueError:
            continue

        description = parts[1].strip()

        interfaces.append({
            "number": number,
            "description": description
        })

    return jsonify({
        "status": "success",
        "interfaces": interfaces
    })

# --------------------------------------------------
# START MONITORING
# --------------------------------------------------

@app.route("/api/start", methods=["POST"])
def start_monitoring():

    global pipeline_process

    if pipeline_process is not None:

        if pipeline_process.poll() is None:

            return jsonify({
                "status": "already_running"
            })


    data = request.get_json(silent=True) or {}

    interface = data.get("interface")

    if interface is None:

        return jsonify({
            "status": "error",
            "message": "No interface selected."
        }), 400


    try:

        interface = int(interface)

    except ValueError:

        return jsonify({
            "status": "error",
            "message": "Invalid interface number."
        }), 400
    
    database.clear_threat_history()

    print(
        f"Starting monitoring pipeline on interface {interface}..."
    )


    pipeline_process = subprocess.Popen(
        [
            sys.executable,
            PIPELINE_FILE,
            str(interface)
        ]
    )


    return jsonify({
        "status": "started",
        "interface": interface
    })

# --------------------------------------------------
# STOP MONITORING
# --------------------------------------------------

@app.route("/api/stop", methods=["POST"])
def stop_monitoring():

    global pipeline_process

    if pipeline_process is None:

        return jsonify({
            "status": "not_running"
        })


    if pipeline_process.poll() is not None:

        pipeline_process = None

        return jsonify({
            "status": "not_running"
        })


    print("Stopping monitoring pipeline...")

    pipeline_process.terminate()

    pipeline_process.wait()

    pipeline_process = None

    return jsonify({
        "status": "stopped"
    })


# --------------------------------------------------
# MONITORING STATUS
# --------------------------------------------------

@app.route("/api/status")
def monitoring_status():

    global pipeline_process

    if pipeline_process is not None:

        if pipeline_process.poll() is None:

            return jsonify({
                "running": True
            })

    return jsonify({
        "running": False
    })


# --------------------------------------------------
# TRAFFIC STATISTICS
# --------------------------------------------------

@app.route("/api/stats")
def get_stats():

    if not os.path.exists(CSV_FILE):

        return jsonify({
            "total_flows": 0,
            "benign": 0,
            "ddos": 0,
            "portscan": 0
        })


    try:

        df = pd.read_csv(CSV_FILE)

    except EmptyDataError:

        return jsonify({
            "total_flows": 0,
            "benign": 0,
            "ddos": 0,
            "portscan": 0
        })


    prediction_counts = (
        df["Prediction"].value_counts().to_dict()
        if "Prediction" in df.columns
        else {}
    )


    return jsonify({

        "total_flows": len(df),

        "benign":
            prediction_counts.get("BENIGN", 0),

        "ddos":
            prediction_counts.get("DDoS", 0),

        "portscan":
            prediction_counts.get("PortScan", 0)

    })


# --------------------------------------------------
# FLOW DATA
# --------------------------------------------------

@app.route("/api/flows")
def get_flows():

    if not os.path.exists(CSV_FILE):

        return jsonify([])


    try:

        df = pd.read_csv(CSV_FILE)

    except EmptyDataError:

        return jsonify([])


    columns = [

        "timestamp",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "protocol",
        "tot_fwd_pkts",
        "tot_bwd_pkts",
        "flow_duration",
        "Prediction"

    ]


    available_columns = [

        column
        for column in columns
        if column in df.columns

    ]


    flows = (
        df[available_columns]
        .fillna("")
        .to_dict(orient="records")
    )


    return jsonify(flows)

# --------------------------------------------------
# FLOW HISTORY
# --------------------------------------------------

@app.route("/api/history")
def get_history():

    flows = database.get_recent_flows(100)

    return jsonify({
        "status": "success",
        "flows": flows
    })

# --------------------------------------------------
# THREAT ALERTS
# --------------------------------------------------

@app.route("/api/alerts")
def get_alerts():

    threats = database.get_threat_history(100)

    return jsonify({
        "status": "success",
        "alerts": threats
    })

# --------------------------------------------------
# START FLASK
# --------------------------------------------------

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
        use_reloader=False
    )
