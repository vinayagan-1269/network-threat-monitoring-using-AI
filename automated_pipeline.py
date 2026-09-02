import subprocess
import os
import time
import pandas as pd
import joblib
import sys
import database

# --------------------------------------------------
# Paths
# --------------------------------------------------

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

CAPTURE_FILE = BASE_DIR / "captures" / "live_capture.pcap"

CAPTURE_DURATION = 20
NUMBER_OF_CYCLES = 3

WINDUMP_PATH = r"C:\WinDump\WinDump.exe"

PCAP_FILE = CAPTURE_FILE

MODEL_PATH = BASE_DIR / "models" / "attack_model.pkl"

OUTPUT_CSV = BASE_DIR / "captures" / "live_test.csv"

CICFLOWMETER_COMMAND = "cicflowmeter"

# --------------------------------------------------
# NETWORK INTERFACE SELECTION
# --------------------------------------------------

def select_interface():

    print("\n" + "=" * 60)
    print("AVAILABLE NETWORK INTERFACES")
    print("=" * 60)

    result = subprocess.run(
        [WINDUMP_PATH, "-D"],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:

        print("ERROR: Could not retrieve network interfaces.")
        print(result.stderr)

        raise SystemExit(1)

    interfaces = [
        line.strip()
        for line in result.stdout.splitlines()
        if line.strip()
    ]

    if not interfaces:

        print("ERROR: No network interfaces found.")
        raise SystemExit(1)

    for interface in interfaces:
        print(interface)

    print("\n" + "-" * 60)

    while True:

        choice = input(
            "Enter the interface number to capture from: "
        )

        try:
            interface_number = int(choice)

            if 1 <= interface_number <= len(interfaces):

                print(
                    f"\nSelected interface: {interface_number}"
                )

                return interface_number

            else:

                print(
                    f"Please enter a number between 1 and "
                    f"{len(interfaces)}."
                )

        except ValueError:

            print("Please enter a valid number.")
            
# Select interface before monitoring starts
# --------------------------------------------------
# NETWORK INTERFACE
# --------------------------------------------------

# Interface can be supplied by Flask.
# Default to interface 5 when running manually.

if len(sys.argv) > 1:
    INTERFACE = int(sys.argv[1])
else:
    INTERFACE = 5
# --------------------------------------------------
# FEATURE MAPPING
# --------------------------------------------------

feature_mapping = {
    "dst_port": "Destination Port",
    "flow_duration": "Flow Duration",
    "tot_fwd_pkts": "Total Fwd Packets",
    "tot_bwd_pkts": "Total Backward Packets",
    "totlen_fwd_pkts": "Total Length of Fwd Packets",
    "totlen_bwd_pkts": "Total Length of Bwd Packets",

    "fwd_pkt_len_max": "Fwd Packet Length Max",
    "fwd_pkt_len_min": "Fwd Packet Length Min",
    "fwd_pkt_len_mean": "Fwd Packet Length Mean",
    "fwd_pkt_len_std": "Fwd Packet Length Std",

    "bwd_pkt_len_max": "Bwd Packet Length Max",
    "bwd_pkt_len_min": "Bwd Packet Length Min",
    "bwd_pkt_len_mean": "Bwd Packet Length Mean",
    "bwd_pkt_len_std": "Bwd Packet Length Std",

    "flow_byts_s": "Flow Bytes/s",
    "flow_pkts_s": "Flow Packets/s",

    "flow_iat_mean": "Flow IAT Mean",
    "flow_iat_std": "Flow IAT Std",
    "flow_iat_max": "Flow IAT Max",
    "flow_iat_min": "Flow IAT Min",

    "fwd_iat_tot": "Fwd IAT Total",
    "fwd_iat_mean": "Fwd IAT Mean",
    "fwd_iat_std": "Fwd IAT Std",
    "fwd_iat_max": "Fwd IAT Max",
    "fwd_iat_min": "Fwd IAT Min",

    "bwd_iat_tot": "Bwd IAT Total",
    "bwd_iat_mean": "Bwd IAT Mean",
    "bwd_iat_std": "Bwd IAT Std",
    "bwd_iat_max": "Bwd IAT Max",
    "bwd_iat_min": "Bwd IAT Min",

    "fwd_psh_flags": "Fwd PSH Flags",
    "bwd_psh_flags": "Bwd PSH Flags",
    "fwd_urg_flags": "Fwd URG Flags",
    "bwd_urg_flags": "Bwd URG Flags",
    "bwd_header_len": "Bwd Header Length",

    "fwd_pkts_s": "Fwd Packets/s",
    "bwd_pkts_s": "Bwd Packets/s",

    "pkt_len_min": "Min Packet Length",
    "pkt_len_max": "Max Packet Length",
    "pkt_len_mean": "Packet Length Mean",
    "pkt_len_std": "Packet Length Std",
    "pkt_len_var": "Packet Length Variance",

    "fin_flag_cnt": "FIN Flag Count",
    "syn_flag_cnt": "SYN Flag Count",
    "rst_flag_cnt": "RST Flag Count",
    "psh_flag_cnt": "PSH Flag Count",
    "ack_flag_cnt": "ACK Flag Count",
    "urg_flag_cnt": "URG Flag Count",
    "ece_flag_cnt": "ECE Flag Count",
    "cwr_flag_count": "CWE Flag Count",

    "down_up_ratio": "Down/Up Ratio",
    "pkt_size_avg": "Average Packet Size",

    "fwd_seg_size_avg": "Avg Fwd Segment Size",
    "bwd_seg_size_avg": "Avg Bwd Segment Size",

    "fwd_byts_b_avg": "Fwd Avg Bytes/Bulk",
    "fwd_pkts_b_avg": "Fwd Avg Packets/Bulk",
    "fwd_blk_rate_avg": "Fwd Avg Bulk Rate",

    "bwd_byts_b_avg": "Bwd Avg Bytes/Bulk",
    "bwd_pkts_b_avg": "Bwd Avg Packets/Bulk",
    "bwd_blk_rate_avg": "Bwd Avg Bulk Rate",

    "subflow_fwd_pkts": "Subflow Fwd Packets",
    "subflow_fwd_byts": "Subflow Fwd Bytes",
    "subflow_bwd_pkts": "Subflow Bwd Packets",
    "subflow_bwd_byts": "Subflow Bwd Bytes",

    "init_fwd_win_byts": "Init_Win_bytes_forward",
    "init_bwd_win_byts": "Init_Win_bytes_backward",

    "fwd_act_data_pkts": "act_data_pkt_fwd",
    "fwd_seg_size_min": "min_seg_size_forward",

    "active_mean": "Active Mean",
    "active_std": "Active Std",
    "active_max": "Active Max",
    "active_min": "Active Min",

    "idle_mean": "Idle Mean",
    "idle_std": "Idle Std",
    "idle_max": "Idle Max",
    "idle_min": "Idle Min"
}


# --------------------------------------------------
# LOAD MODEL ONCE
# --------------------------------------------------

print("Loading AI model...")

model = joblib.load(MODEL_PATH)

expected_features = model.feature_names_in_

print("Model loaded successfully.")
print("Expected features:", len(expected_features))

# --------------------------------------------------
# INITIALIZE DATABASE
# --------------------------------------------------

print("Initializing database...")

database.initialize_database()

print("Database ready.")

# ==================================================
# MONITORING LOOP
# ==================================================

for cycle in range(1, NUMBER_OF_CYCLES + 1):

    print("\n")
    print("#" * 60)
    print(f"MONITORING CYCLE {cycle}/{NUMBER_OF_CYCLES}")
    print("#" * 60)


    # --------------------------------------------------
    # STEP 1: LIVE PACKET CAPTURE
    # --------------------------------------------------

    print("\n" + "=" * 60)
    print("STEP 1: LIVE PACKET CAPTURE")
    print("=" * 60)

    print(f"Capturing from interface {INTERFACE}")
    print(f"Capture duration: {CAPTURE_DURATION} seconds")

    # Remove previous capture
    if os.path.exists(CAPTURE_FILE):
        os.remove(CAPTURE_FILE)

    capture_command = [
        WINDUMP_PATH,
        "-i",
        str(INTERFACE),
        "-w",
        CAPTURE_FILE
    ]

    print("Starting WinDump...")

    process = subprocess.Popen(
        capture_command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )

    time.sleep(CAPTURE_DURATION)

    print("\nStopping capture...")

    process.terminate()
    process.wait()

    print("Packet capture complete.")
    print("PCAP:", CAPTURE_FILE)


    # --------------------------------------------------
    # STEP 2: FLOW EXTRACTION
    # --------------------------------------------------

    print("\n" + "=" * 60)
    print("STEP 2: FLOW EXTRACTION")
    print("=" * 60)

    # Remove previous CSV
    if os.path.exists(OUTPUT_CSV):
        os.remove(OUTPUT_CSV)

    command = [
        CICFLOWMETER_COMMAND,
        "-f",
        PCAP_FILE,
        "-c",
        OUTPUT_CSV
    ]

    print("Running CICFlowMeter...")

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    if result.returncode != 0:

        print("\nCICFlowMeter failed:")
        print(result.stderr)

        raise SystemExit(1)

    print("Flow extraction complete.")
    print("CSV:", OUTPUT_CSV)


    # --------------------------------------------------
    # STEP 3: CHECK CSV
    # --------------------------------------------------

    print("\n" + "=" * 60)
    print("STEP 3: CSV CHECK")
    print("=" * 60)

    if not os.path.exists(OUTPUT_CSV):

        print("ERROR: CSV was not created.")
        raise SystemExit(1)

    print("CSV successfully created.")


    # --------------------------------------------------
    # STEP 4: LOAD CSV
    # --------------------------------------------------

    print("\n" + "=" * 60)
    print("STEP 4: LOAD TRAFFIC DATA")
    print("=" * 60)

    df = pd.read_csv(OUTPUT_CSV)

    print("Flows loaded:", len(df))


    # --------------------------------------------------
    # STEP 5: FEATURE ADAPTER
    # --------------------------------------------------

    print("\n" + "=" * 60)
    print("STEP 5: FEATURE ADAPTER")
    print("=" * 60)

    metadata = [
        "src_ip",
        "dst_ip",
        "src_port",
        "timestamp"
    ]

    X = df.drop(
        columns=metadata,
        errors="ignore"
    )

    X = X.rename(
        columns=feature_mapping
    )

    # CICFlowMeter has one Fwd Header Length,
    # while the training dataset contains it twice.

    X["Fwd Header Length"] = X["fwd_header_len"]

    X["Fwd Header Length.1"] = X["fwd_header_len"]

    X = X.drop(
        columns=["fwd_header_len"]
    )


    # --------------------------------------------------
    # STEP 6: MATCH MODEL FEATURES
    # --------------------------------------------------

    print("\n" + "=" * 60)
    print("STEP 6: MATCH MODEL FEATURES")
    print("=" * 60)

    missing = set(expected_features) - set(X.columns)

    if missing:

        print("\nMissing features:")

        for feature in missing:
            print(feature)

        raise ValueError(
            "Input does not contain all required features."
        )

    X = X[expected_features]

    print("Model input shape:", X.shape)

    # Detect groups of TCP flows from one source
    # to one destination across many ports.
    
    scan_groups = (
        df[df["protocol"] == 6]
        .groupby(["src_ip", "dst_ip"])
    )

    scan_pairs = set()

    for (src, dst), group in scan_groups:
    
        unique_ports = group["dst_port"].nunique()

        syn_flows = (
            group["syn_flag_cnt"] >= 1
        ).sum()

        if unique_ports >= 10 and syn_flows >= 5:
            scan_pairs.add((src, dst))
    print("\nDetected scan pairs:")

    for pair in scan_pairs:
        print(pair)

    # --------------------------------------------------
    # STEP 7: AI PREDICTION
    # --------------------------------------------------
    
    print("\n" + "=" * 60)
    print("STEP 7: AI PREDICTION")
    print("=" * 60)
    
    predictions = model.predict(X)

    for i, row in df.iterrows():

        if (row["src_ip"], row["dst_ip"]) in scan_pairs:
            predictions[i] = "PortScan"
        
    # Attach AI prediction to the original flow data
    df["Prediction"] = predictions
    
    # Save predictions back to the CSV
    df.to_csv(OUTPUT_CSV, index=False)
    

    # --------------------------------------------------
    # SAVE RESULTS TO DATABASE
    # --------------------------------------------------
    
    print("\nSaving results to database...")
    
    for _, row in df.iterrows():
    
        flow = row.to_dict()
    
        database.save_flow(flow)
    
        if flow.get("Prediction") in ["DDoS", "PortScan"]:
    
            database.save_threat(flow)
    
    print("Results saved to database.")
 
 
    # --------------------------------------------------
    # OVERALL PREDICTION SUMMARY
    # --------------------------------------------------
    
    prediction_counts = df["Prediction"].value_counts()
    
    print("\nPrediction summary:")
    
    for label in ["BENIGN", "PortScan", "DDoS"]:
    
        count = prediction_counts.get(label, 0)
    
        print(f"{label:<12}: {count}")


    # --------------------------------------------------
    # FLOW DETAILS
    # --------------------------------------------------
    
    print("\n" + "=" * 60)
    print("FLOW DETAILS")
    print("=" * 60)
    
    display_columns = [
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

    # Only display columns that actually exist
    available_columns = [
        column
        for column in display_columns
        if column in df.columns
    ]
    
    flow_table = df[available_columns].copy()
    
    print(flow_table.to_string(index=False))


    # --------------------------------------------------
    # CYCLE SUMMARY
    # --------------------------------------------------

    print("\n" + "=" * 60)
    print(f"CYCLE {cycle} COMPLETE")
    print("=" * 60)

    print(
        "LIVE TRAFFIC → WinDump → PCAP → "
        "CICFlowMeter → Adapter → AI → Prediction"
    )


# ==================================================
# ALL CYCLES COMPLETE
# ==================================================

print("\n")
print("#" * 60)
print("MONITORING SESSION COMPLETE")
print("#" * 60)

print(f"Completed {NUMBER_OF_CYCLES} cycles.")
