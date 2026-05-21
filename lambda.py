import json
import boto3
import urllib.parse
import urllib.request
import gzip
import io
import base64

s3_client = boto3.client('s3')
ec2_client = boto3.client('ec2')
ec2_resource = boto3.resource('ec2')

def lambda_handler(event, context):
    print("Received Live WAF Event: " + json.dumps(event))
    
    # ==================== CONFIGURATION BLOCK ====================
    # Paste your exact IDs and Twilio values here
    INSTANCE_ID = "" 
    QUARANTINE_SG = "" 
    
    TWILIO_ACCOUNT_SID = ""
    TWILIO_AUTH_TOKEN = ""
    FROM_NUMBER = ""
    TO_NUMBER = ""
    # =============================================================
    
    try:
        bucket_name = event['Records'][0]['s3']['bucket']['name']
        file_key = urllib.parse.unquote_plus(event['Records'][0]['s3']['object']['key'], encoding='utf-8')
        
        response = s3_client.get_object(Bucket=bucket_name, Key=file_key)
        compressed_body = response['Body'].read()
        
        if file_key.endswith('.gz'):
            print("Detected Gzip compression. Extracting archive contents...")
            with gzip.GzipFile(fileobj=io.BytesIO(compressed_body)) as gzip_file:
                raw_log = gzip_file.read().decode('utf-8')
        else:
            raw_log = compressed_body.decode('utf-8')
            
        # Split the file contents into individual log lines
        log_lines = raw_log.splitlines()
        print(f"Processing a batch of {len(log_lines)} logs from WAF storage...")
        
    except Exception as parse_error:
        print(f"Failed to fetch or parse log object from S3: {str(parse_error)}")
        return

    # Loop through EVERY entry inside the log file to search for a block
    threat_detected = False
    attacker_ip = "Unknown IP Address"
    
    for line in log_lines:
        if not line.strip():
            continue
        try:
            log_data = json.loads(line)
            if log_data.get('action') == 'BLOCK':
                threat_detected = True
                http_request = log_data.get('httpRequest', {})
                attacker_ip = http_request.get('clientIp', "Unknown IP Address")
                break # Threat found! Stop searching the file and isolate immediately
        except Exception as e:
            print(f"Error reading line: {str(e)}")
            continue

    if not threat_detected:
        print("Log batch verified clean. No blocked malicious entries found in this payload.")
        return

    # Proceed with isolation if a BLOCK was found
    instance_name = "Production Infrastructure"
    try:
        instance = ec2_resource.Instance(INSTANCE_ID)
        for tag in instance.tags or []:
            if tag['Key'] == 'Name':
                instance_name = tag['Value']
                break
    except Exception as tag_err:
        print(f"Name Tag lookup failed: {str(tag_err)}")

    print(f"🚨 WAF Block Extracted from batch! Target: {instance_name} | Attacker: {attacker_ip}")

    try:
        ec2_client.modify_instance_attribute(
            InstanceId=INSTANCE_ID,
            Groups=[QUARANTINE_SG]
        )
        print(f"Network isolated cleanly for {instance_name}.")
        
        trigger_voice_alert(instance_name, attacker_ip, TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, FROM_NUMBER, TO_NUMBER)
        
    except Exception as e:
        print(f"Containment execution wrapper failed: {str(e)}")

def trigger_voice_alert(instance_name, attacker_ip, sid, token, from_num, to_num):
    clean_name = str(instance_name).replace("<", "").replace(">", "").replace("&", "and").replace("-", " dash ").replace("_", " underscore ")
    clean_ip = str(attacker_ip).replace(".", " dot ")

    speech_text = (
        f"Security Alert. The inline web application firewall has blocked an attack "
        f"against your {clean_name} infrastructure. The threat originated from I P address {clean_ip}. "
        f"The containment engine has successfully isolated the target server."
    )
    
    twiml_payload = f"<Response><Say voice=\"alice\">{speech_text}</Say></Response>"
    payload_dict = {"To": to_num, "From": from_num, "Twiml": twiml_payload}
    post_data = urllib.parse.urlencode(payload_dict).encode('utf-8')
    
    twilio_url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Calls.json"
    auth_str = f"{sid}:{token}"
    b64_auth = base64.b64encode(auth_str.encode()).decode()
    
    req = urllib.request.Request(
        twilio_url, 
        data=post_data,
        headers={
            'Authorization': 'Basic ' + b64_auth,
            'Content-Type': 'application/x-www-form-urlencoded'
        }
    )
    
    with urllib.request.urlopen(req) as response:
        print("Twilio call gateway accepted structured request payload: ", response.read().decode())
