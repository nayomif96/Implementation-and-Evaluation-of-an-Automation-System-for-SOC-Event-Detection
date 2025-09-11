from datetime import datetime, timezone, timedelta
from elasticsearch import Elasticsearch
import mysql.connector
import pytz
import re
import json
import ipaddress

# --- CONFIGURATION ---
ELASTIC_HOST = 'https://192.168.200.11:9200'
ELASTIC_USERNAME = 'elastic'
ELASTIC_PASSWORD = 'vO*YWo0MrsAys8n3c7IH'
LOG_INDEX_PATTERN = "filebeat-*"
LAST_FETCH_FILE = "/home/nayomi/my_python_scripts/last_fetch.txt"

# --- MYSQL CONFIGURATION ---
MYSQL_CONFIG = {
    'host': '192.168.200.20',
    'user': 'siemuser',
    'password': 'admin1234',
    'database': 'IDS_Feedback'
}


IPV4_REGEX = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')

def extract_ipv4(ip_list):
    """Extract first IPv4 from list or string; return None if none found."""
    if isinstance(ip_list, list):
        for ip in ip_list:
            try:
                ip_obj = ipaddress.ip_address(ip)
                if ip_obj.version == 4:
                    return str(ip_obj)
            except ValueError:
                continue
        return ip_list[0] if ip_list else None
    elif isinstance(ip_list, str):
        try:
            ip_obj = ipaddress.ip_address(ip_list)
            if ip_obj.version == 4:
                return ip_list
            else:
                return None
        except ValueError:
            return None
    return None

def list_to_str(val):
    if isinstance(val, list):
        return ','.join(str(x) for x in val)
    return val

def json_to_str(val):
    if isinstance(val, dict):
        return json.dumps(val)
    return val

def normalize_message_field(val):
    if isinstance(val, list):
        return ' '.join(str(x) for x in val)
    return str(val) if val else None

def convert_iso_to_mysql_datetime(ts,target_tz='Europe/London'):
    if not ts:
        return None

    if ts.endswith('Z'):
        ts = ts[:-1] + '+00:00'
    try:
        dt = datetime.fromisoformat(ts)

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        target_timezone = pytz.timezone(target_tz)
        dt = dt.astimezone(target_timezone)

        return dt.replace(tzinfo=None)
    except Exception as e:
        print(f">>> Error converting timestamp {ts}: {e}")
        return None


# --- ELASTICSEARCH CLIENT SETUP ---
def create_es_client(host, user, password):
    try:
        print(">>> Connecting to Elasticsearch...")
        es = Elasticsearch(
            host,
            basic_auth=(user, password),
            verify_certs=False,
            ssl_show_warn=False
        )
        if es.ping():
            print(">>> Connected successfully.")
            return es
        else:
            print(">>> Connection failed. Check host and credentials.")
            return None
    except Exception as e:
        print(f">>> An unexpected error occurred: {e}")
        return None


def load_last_fetch_time(last_fetch_file):
    try:
        with open(last_fetch_file, "r") as f:
            ts_string = f.read().strip()
            return datetime.fromisoformat(ts_string)
    except FileNotFoundError:
        print(">>> No previous fetch time file found. Will fetch all available logs.")
        return None
    except Exception as e:
        print(f">>> Error loading last fetch time: {e}. Fetching last 1 hour logs.")
        return datetime.now(timezone.utc) - timedelta(hours=1)

def save_last_fetch_time(ts: datetime, last_fetch_file):
    if last_fetch_file:
        try:
            with open(last_fetch_file, "w") as f:
                f.write(ts.isoformat())
        except Exception as e:
            print(f">>> Error saving last fetch time: {e}")


def insert_suricata(cursor, log):
    insert_sql = """
        INSERT INTO suricata_logs (timestamp, log_file_path, destination_port, destination_ip, source_port, source_ip,
                                   network_protocol, network_direction, event_original, event_created, event_kind,
                                   event_module, event_category, event_dataset, message, destination_bytes, rule_name,
                                   rule_id, rule_category, source_bytes, event_severity)
        VALUES (%(timestamp)s, %(log_file_path)s, %(destination_port)s, %(destination_ip)s, %(source_port)s, %(source_ip)s,
                %(network_protocol)s, %(network_direction)s, %(event_original)s, %(event_created)s, %(event_kind)s,
                %(event_module)s, %(event_category)s, %(event_dataset)s, %(message)s, %(destination_bytes)s, %(rule_name)s,
                %(rule_id)s, %(rule_category)s, %(source_bytes)s, %(event_severity)s)
    """

    data = {
        'timestamp': convert_iso_to_mysql_datetime(log.get('@timestamp'), target_tz='Europe/London'),
        'log_file_path': log.get('log', {}).get('file', {}).get('path'),
        'destination_port': log.get('destination', {}).get('port'),
        'destination_ip': log.get('destination', {}).get('ip'),
        'source_port': log.get('source', {}).get('port'),
        'source_ip': log.get('source', {}).get('ip'),
        'network_protocol': log.get('network', {}).get('protocol'),
        'network_direction': log.get('network', {}).get('direction'),
        'event_original': json_to_str(log.get('event', {}).get('original')),
        'event_created': convert_iso_to_mysql_datetime(log.get('event', {}).get('created')),
        'event_kind': log.get('event', {}).get('kind'),
        'event_module': log.get('event', {}).get('module'),
        'event_category': list_to_str(log.get('event', {}).get('category')),
        'event_dataset': log.get('event', {}).get('dataset'),
        'message': normalize_message_field(log.get('message')),
        'destination_bytes': log.get('destination', {}).get('bytes'),
        'rule_name': list_to_str(log.get('rule', {}).get('name')),
        'rule_id': log.get('rule', {}).get('id'),
        'rule_category': list_to_str(log.get('rule', {}).get('category')),
        'source_bytes': log.get('source', {}).get('bytes'),
        'event_severity': log.get('event', {}).get('severity'),
    }

    cursor.execute(insert_sql, data)

def insert_syslog(cursor, log):
    # Extract host IP 
    host_ip = extract_ipv4(log.get('host', {}).get('ip'))

    # Normalize message
    message_text = normalize_message_field(log.get('message'))

    source_ip = log.get('source', {}).get('ip')
    if not source_ip:
        message_text = normalize_message_field(log.get('message'))
        if message_text:
            ip_match = IPV4_REGEX.search(message_text)
            if ip_match:
                found_ip = ip_match.group(0)
                
                if found_ip != host_ip and found_ip !='0.0.0.0':
                    source_ip = found_ip

   
    if not source_ip:
        return  

    insert_sql = """
            INSERT INTO syslog (message, timestamp, log_file_path, host_ip, event_kind, event_module, event_dataset, source_ip)
            VALUES (%(message)s, %(timestamp)s, %(log_file_path)s, %(host_ip)s, %(event_kind)s, %(event_module)s, %(event_dataset)s, %(source_ip)s)
        """

    data = {
        'message': message_text,
        'timestamp': convert_iso_to_mysql_datetime(log.get('@timestamp'), target_tz='Europe/London'),
        'log_file_path': log.get('log', {}).get('file', {}).get('path'),
        'host_ip': host_ip,
        'event_kind': log.get('event', {}).get('kind'),
        'event_module': log.get('event', {}).get('module'),
        'event_dataset': log.get('event', {}).get('dataset'),
        'source_ip': source_ip
    }
    cursor.execute(insert_sql, data)

def insert_authlog(cursor, log):
    
    host_ip = extract_ipv4(log.get('host', {}).get('ip'))

    # Extract source IP/address from log
    source_ip = log.get('source', {}).get('ip')
    source_address = log.get('source', {}).get('address')

    if not source_ip and not source_address:
        message_text = normalize_message_field(log.get('message'))
        if message_text:
            ip_match = IPV4_REGEX.search(message_text)
            if ip_match:
                found_ip = ip_match.group(0)                
                if found_ip != host_ip:
                    source_ip = found_ip
                    source_address = found_ip

    if not source_ip:
        return  

    insert_sql = """
        INSERT INTO authlog (message, timestamp, process_name, log_file_path, host_ip, event_kind, event_module, event_dataset,
                             event_category, event_type, event_outcome, user_name, source_address, source_ip, event_action, source_port)
        VALUES (%(message)s, %(timestamp)s, %(process_name)s, %(log_file_path)s, %(host_ip)s, %(event_kind)s, %(event_module)s, %(event_dataset)s,
                %(event_category)s, %(event_type)s, %(event_outcome)s, %(user_name)s, %(source_address)s, %(source_ip)s, %(event_action)s, %(source_port)s)
    """

    data = {
        'message': normalize_message_field(log.get('message')),
        'timestamp': convert_iso_to_mysql_datetime(log.get('@timestamp'), target_tz='Europe/London'),
        'process_name': log.get('process', {}).get('name'),
        'log_file_path': log.get('log', {}).get('file', {}).get('path'),
        'host_ip': host_ip,
        'event_kind': log.get('event', {}).get('kind'),
        'event_module': log.get('event', {}).get('module'),
        'event_dataset': log.get('event', {}).get('dataset'),
        'event_category': list_to_str(log.get('event', {}).get('category')),
        'event_type': list_to_str(log.get('event', {}).get('type')),
        'event_outcome': log.get('event', {}).get('outcome'),
        'user_name': log.get('user', {}).get('name'),
        'source_address': source_address,
        'source_ip': source_ip,
        'event_action': log.get('event', {}).get('action'),
        'source_port': log.get('source', {}).get('port'),
    }

    cursor.execute(insert_sql, data)

def insert_vsftpd(cursor, log):
    insert_sql = """
        INSERT INTO vsftpd_logs (timestamp, message, host_ip, log_file_path, event_dataset, event_module, source_ip)
        VALUES (%(timestamp)s, %(message)s, %(host_ip)s, %(log_file_path)s, %(event_dataset)s, %(event_module)s, %(source_ip)s)
    """

    data = {
        'timestamp': convert_iso_to_mysql_datetime(log.get('@timestamp'), target_tz='Europe/London'),
        'message': normalize_message_field(log.get('message')),
        'host_ip': extract_ipv4(log.get('host', {}).get('ip')),
        'log_file_path': log.get('log', {}).get('file', {}).get('path'),
        'event_dataset': log.get('event', {}).get('dataset'),
        'event_module': log.get('event', {}).get('module'),
        'source_ip': log.get('source', {}).get('ip'),
    }

    cursor.execute(insert_sql, data)

def fetch_and_process_logs(es, mysql_conn, index_pattern, last_fetch_file):

    if not index_pattern:
        print(">>> Log index pattern cannot be empty.")
        return

    start_time = load_last_fetch_time(last_fetch_file)
    end_time = datetime.now(timezone.utc)

    query_range = {"lte": end_time.isoformat()}
    if start_time:
        print(f">>> Fetching logs from {start_time.isoformat()} to {end_time.isoformat()}...")
        query_range["gte"] = start_time.isoformat()
    else:
        print(f">>> Performing initial fetch of all logs up to {end_time.isoformat()}...")

    query = {
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": query_range}},
                    {"bool": {
                        "should": [
                            {"term": {"event.module": "suricata"}},
                            {"term": {"event.module": "system"}},
                            {"term": {"event.module": "vsftpd"}},
                        ],
                        "minimum_should_match": 1
                    }}
                ]
            }
        },
        "sort": [{"@timestamp": {"order": "asc"}}],
        "size": 1000
    }

    total_logs_fetched = 0
    latest_timestamp = start_time

    cursor = mysql_conn.cursor()

    try:
        response = es.search(index=index_pattern, body=query, scroll="2m")
        scroll_id = response['_scroll_id']
        scroll_size = len(response['hits']['hits'])
        total_hits = response['hits']['total']['value']

        print(f">>> Found a total of {total_hits} logs matching the query.")

        while scroll_size > 0:
            hits = response['hits']['hits']
            if not hits:
                break

            for hit in hits:
                log_entry = hit['_source']
                event_module = log_entry.get('event', {}).get('module')
                event_dataset = log_entry.get('event', {}).get('dataset')

                # Suricata logs
                if event_module == 'suricata':
                    insert_suricata(cursor, log_entry)

                # System logs (authlog and syslog)
                elif event_module == 'system':
                    if event_dataset == 'system.auth':
                        insert_authlog(cursor, log_entry)
                    elif event_dataset == 'system.syslog':
                        insert_syslog(cursor, log_entry)

                # Vsftpd logs
                elif event_module == 'vsftpd':
                    # Extract IPv4 from message and add to source.ip
                    message = log_entry.get('message', '')
                    ip_match = IPV4_REGEX.search(message)
                    if ip_match:
                        if 'source' not in log_entry:
                            log_entry['source'] = {}
                        log_entry['source']['ip'] = ip_match.group(0)
                    insert_vsftpd(cursor, log_entry)

            mysql_conn.commit()

            total_logs_fetched += len(hits)
            print(f">>> Processed {len(hits)} logs. Total logs fetched: {total_logs_fetched}")

            last_hit_ts = datetime.fromisoformat(hits[-1]['_source']['@timestamp'].replace('Z', '+00:00'))
            if latest_timestamp is None or last_hit_ts > latest_timestamp:
                latest_timestamp = last_hit_ts

            response = es.scroll(scroll_id=scroll_id, scroll="2m")
            scroll_id = response['_scroll_id']
            scroll_size = len(response['hits']['hits'])

    except Exception as e:
        print(f">>> An error occurred during fetching or processing: {e}")
    finally:
        if 'scroll_id' in locals():
            try:
                es.clear_scroll(scroll_id=scroll_id)
                print(">>> Scroll context cleared.")
            except Exception as e:
                print(f">>> Error clearing scroll context: {e}")

        cursor.close()

    if total_logs_fetched > 0:
        save_last_fetch_time(latest_timestamp, last_fetch_file)
        print(f">>> All logs processed and saved.")
    else:
        print(">>> No new logs found. Last fetch timestamp remains unchanged.")


if __name__ == "__main__":
    es_client = create_es_client(ELASTIC_HOST, ELASTIC_USERNAME, ELASTIC_PASSWORD)
    if es_client:
        try:
            mysql_conn = mysql.connector.connect(**MYSQL_CONFIG)
            cursor = mysql_conn.cursor()
            tables_to_truncate = ['authlog', 'syslog', 'vsftpd_logs', 'suricata_logs']
            for table in tables_to_truncate:
                try:
                    cursor.execute(f"TRUNCATE TABLE {table};")
                    print(f">>> Table {table} truncated successfully.")
                except mysql.connector.Error as e:
                    print(f">>> Error truncating table {table}: {e}")
            mysql_conn.commit()  
            fetch_and_process_logs(es_client, mysql_conn, LOG_INDEX_PATTERN, LAST_FETCH_FILE)
        except mysql.connector.Error as err:
            print(f">>> MySQL connection error: {err}")
        finally:
            if mysql_conn.is_connected():
                mysql_conn.close()
