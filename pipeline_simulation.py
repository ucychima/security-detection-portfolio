from log_parser import LogParser
from detections import Detections
import json
import os

def load_logs():
    logs = []
    parser = LogParser()

    for file in os.listdir("sample_logs"):
        with open(f"sample_logs/{file}", "r") as f:
            for line in f:
                parsed = parser.parse_line(line)
                logs.append(parsed)

    return logs

def run_pipeline():
    logs = load_logs()
    det = Detections()

    alerts = []
    alerts.extend(det.impossible_travel(logs))
    alerts.extend(det.privilege_escalation(logs))
    alerts.extend(det.brute_force(logs))
    alerts.extend(det.suspicious_powershell(logs))
    alerts.extend(det.data_exfiltration(logs))

    print(json.dumps(alerts, indent=4))

if __name__ == "__main__":
    run_pipeline()