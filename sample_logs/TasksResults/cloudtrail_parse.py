import json
import pprint

cloudtrail_file = r'C:\Users\chima\Documents\Projects\security-detection-portfolio\sample_logs\cloudtrail.json'
with open(cloudtrail_file, 'r') as f:
    cloudtrail_data = [json.loads(line.strip()) for line in f]
alice_events = [event for event in cloudtrail_data if event['user'] == 'alice']

pprint.pprint(alice_events)