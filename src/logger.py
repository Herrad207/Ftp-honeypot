import json
import os
from datetime import datetime

def write_log(data, filename="logs/honeypot_log.json"):
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    data["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(filename, "a") as logfile:
            json.dump(data, logfile)
            logfile.write("\n")
        print("Log entry added successfully.")
    except Exception as e:
        print(f"Error writing to log file: {e}")
