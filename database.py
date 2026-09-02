import sqlite3

DATABASE_PATH = r"D:\studies PDF\sih 2026\working model\network_monitor.db"


# --------------------------------------------------
# DATABASE CONNECTION
# --------------------------------------------------

def get_connection():

    connection = sqlite3.connect(DATABASE_PATH)

    connection.row_factory = sqlite3.Row

    return connection


# --------------------------------------------------
# INITIALIZE DATABASE
# --------------------------------------------------

def initialize_database():

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS flows (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            timestamp TEXT,

            src_ip TEXT,

            dst_ip TEXT,

            src_port INTEGER,

            dst_port INTEGER,

            protocol INTEGER,

            tot_fwd_pkts INTEGER,

            tot_bwd_pkts INTEGER,

            flow_duration REAL,

            prediction TEXT

        )
    """)


    cursor.execute("""
        CREATE TABLE IF NOT EXISTS threat_events (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            timestamp TEXT,

            src_ip TEXT,

            dst_ip TEXT,

            src_port INTEGER,

            dst_port INTEGER,

            protocol INTEGER,

            prediction TEXT

        )
    """)


    connection.commit()

    connection.close()


# --------------------------------------------------
# SAVE FLOW
# --------------------------------------------------

def save_flow(flow):

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO flows (

            timestamp,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            tot_fwd_pkts,
            tot_bwd_pkts,
            flow_duration,
            prediction

        )

        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (

        flow.get("timestamp"),
        flow.get("src_ip"),
        flow.get("dst_ip"),
        flow.get("src_port"),
        flow.get("dst_port"),
        flow.get("protocol"),
        flow.get("tot_fwd_pkts"),
        flow.get("tot_bwd_pkts"),
        flow.get("flow_duration"),
        flow.get("Prediction")

    ))

    connection.commit()

    connection.close()


# --------------------------------------------------
# SAVE THREAT
# --------------------------------------------------

def save_threat(flow):

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO threat_events (

            timestamp,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            prediction

        )

        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (

        flow.get("timestamp"),
        flow.get("src_ip"),
        flow.get("dst_ip"),
        flow.get("src_port"),
        flow.get("dst_port"),
        flow.get("protocol"),
        flow.get("Prediction")

    ))

    connection.commit()

    connection.close()

    # --------------------------------------------------
      # CLEAR THREAT HISTORY
    # --------------------------------------------------
def clear_threat_history():
    
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        DELETE FROM threat_events
    """)

    connection.commit()
    connection.close()


# --------------------------------------------------
# GET RECENT FLOWS
# --------------------------------------------------

def get_recent_flows(limit=100):

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        SELECT *

        FROM flows

        ORDER BY id DESC

        LIMIT ?
    """, (limit,))

    rows = cursor.fetchall()

    connection.close()

    return [dict(row) for row in rows]


# --------------------------------------------------
# GET THREAT HISTORY
# --------------------------------------------------

def get_threat_history(limit=100):

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        SELECT *

        FROM threat_events

        ORDER BY id DESC

        LIMIT ?
    """, (limit,))

    rows = cursor.fetchall()

    connection.close()

    return [dict(row) for row in rows]
