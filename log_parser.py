import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime

class LogParser:
    def __init__(self):
        pass

    def detect_format(self, line):
        line = line.strip()

        if line.startswith("{") and line.endswith("}"):
            return "json"
        if "<Event" in line or line.startswith("<"):
            return "xml"
        if re.match(r"^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}", line):
            return "syslog"
        if "," in line:
            return "csv"
        return "unknown"

    def parse_json(self, line):
        try:
            return json.loads(line)
        except:
            return {}

    def parse_syslog(self, line):
        pattern = r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) (?P<process>\S+): (?P<message>.*)"
        match = re.match(pattern, line)
        return match.groupdict() if match else {}

    def parse_xml(self, line):
        try:
            root = ET.fromstring(line)
            event_data = {}
            for child in root.iter():
                event_data[child.tag] = child.text
            return event_data
        except:
            return {}

    def normalize(self, parsed):
        return {
            "timestamp": parsed.get("timestamp") or parsed.get("EventTime") or parsed.get("eventTime"),
            "user": parsed.get("user") or parsed.get("User") or parsed.get("UserName"),
            "src_ip": parsed.get("src_ip") or parsed.get("SourceIpAddress") or parsed.get("ipAddress"),
            "dest_ip": parsed.get("dest_ip") or parsed.get("DestinationIp") or None,
            "action": parsed.get("action") or parsed.get("eventName") or parsed.get("Message"),
            "event_type": parsed.get("event_type") or parsed.get("EventID") or parsed.get("eventType")
        }

    def parse_line(self, line):
        fmt = self.detect_format(line)

        if fmt == "json":
            parsed = self.parse_json(line)
        elif fmt == "syslog":
            parsed = self.parse_syslog(line)
        elif fmt == "xml":
            parsed = self.parse_xml(line)
        else:
            parsed = {}

        return self.normalize(parsed)