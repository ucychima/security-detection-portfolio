from datetime import datetime, timedelta
import base64
import math

class Detections:

    def impossible_travel(self, logs):
        alerts = []
        user_last_seen = {}

        for log in logs:
            user = log.get("user")
            ip = log.get("src_ip")
            ts = log.get("timestamp")

            if not user or not ip or not ts:
                continue

            ts = datetime.fromisoformat(ts)

            if user in user_last_seen:
                last_ip, last_ts = user_last_seen[user]

                time_diff = (ts - last_ts).total_seconds() / 3600

                if time_diff < 1 and ip != last_ip:
                    alerts.append({
                        "alert": "Impossible Travel Detected",
                        "user": user,
                        "previous_ip": last_ip,
                        "current_ip": ip,
                        "timestamp": ts.isoformat()
                    })

            user_last_seen[user] = (ip, ts)

        return alerts

    def privilege_escalation(self, logs):
        alerts = []
        sensitive_actions = ["CreateUser", "AttachRolePolicy", "AssumeRole"]

        for log in logs:
            action = log.get("action")
            if action in sensitive_actions:
                alerts.append({
                    "alert": "Privilege Escalation Attempt",
                    "action": action,
                    "user": log.get("user"),
                    "timestamp": log.get("timestamp")
                })

        return alerts

    def brute_force(self, logs):
        alerts = []
        failed_attempts = {}

        for log in logs:
            if "failed" in str(log.get("action", "")).lower():
                ip = log.get("src_ip")
                ts = datetime.fromisoformat(log.get("timestamp"))

                if ip not in failed_attempts:
                    failed_attempts[ip] = []

                failed_attempts[ip].append(ts)

        for ip, attempts in failed_attempts.items():
            attempts.sort()
            for i in range(len(attempts) - 5):
                if (attempts[i+5] - attempts[i]) < timedelta(minutes=10):
                    alerts.append({
                        "alert": "Brute Force Login Attempt",
                        "src_ip": ip,
                        "attempts": 6
                    })
                    break

        return alerts

    def suspicious_powershell(self, logs):
        alerts = []
        indicators = ["-enc", "FromBase64String", "IEX"]

        for log in logs:
            action = str(log.get("action", "")).lower()
            if any(ind in action for ind in indicators):
                alerts.append({
                    "alert": "Suspicious PowerShell Execution",
                    "command": action,
                    "timestamp": log.get("timestamp")
                })

        return alerts

    def data_exfiltration(self, logs):
        alerts = []

        for log in logs:
            if "bytes_out" in log and int(log["bytes_out"]) > 500000000:
                alerts.append({
                    "alert": "Possible Data Exfiltration",
                    "src_ip": log.get("src_ip"),
                    "bytes_out": log.get("bytes_out")
                })

        return alerts