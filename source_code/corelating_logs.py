import pandas as pd
import pymysql
import warnings
import urllib3
from pymisp import ExpandedPyMISP
import re

warnings.simplefilter(action='ignore', category=FutureWarning)
warnings.simplefilter(action='ignore', category=UserWarning)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
pd.set_option('display.max_columns', None)

MISP_URL = "https://misp.local/"
API_KEY = "Y8gKoub27x31uA3Bcqm16tMPipw3rkhnAa1JyY83"
VERIFY_SSL = False
misp = ExpandedPyMISP(MISP_URL, API_KEY, VERIFY_SSL)
# DB connection 
conn = pymysql.connect(
    host='192.168.200.20',
    user='siemuser',
    password='admin1234',
    db='IDS_Feedback',
)
cursor = conn.cursor()
misp_check= pd.read_sql("SELECT DISTINCT source_ip FROM (SELECT source_ip,incident_id FROM suricata_logs UNION SELECT source_ip,incident_id FROM authlog UNION SELECT source_ip,incident_id "
                        "FROM vsftpd_logs) AS combined_ips WHERE incident_id IS NULL and source_ip IS NOT NULL AND INET_ATON(source_ip) IS NOT NULL;", conn)
suricata_df = pd.read_sql("SELECT * FROM suricata_logs WHERE incident_id IS NULL and source_ip IS NOT NULL", conn)
syslog_df = pd.read_sql("SELECT * FROM syslog WHERE incident_id IS NULL and source_ip IS NOT NULL", conn)
authlog_df = pd.read_sql("SELECT * FROM authlog WHERE incident_id IS NULL and source_ip IS NOT NULL", conn)
vsftpd_df = pd.read_sql("SELECT * FROM vsftpd_logs WHERE incident_id IS NULL and source_ip IS NOT NULL", conn)
max_incident_id = pd.read_sql("SELECT incident_id FROM prediction_data ORDER BY CAST(SUBSTRING(incident_id, 4) AS UNSIGNED) DESC LIMIT 1;", conn)

if not max_incident_id.empty:
    max_inc_num = int(max_incident_id.iloc[0]['incident_id'][3:])
    max_inc_num= max_inc_num+1
else:
    max_inc_num = 1


def check_ips_in_misp(ip_list):

    results = []
    
    expected_columns = ["ip", "has_ioc", "event_id", "attribute_id", "category", "type", "value", "comment",
                        "event_info", "event_link"]

    for ip in ip_list:
        attributes = misp.search(controller='attributes', value=ip)
        if attributes and 'Attribute' in attributes and attributes['Attribute']:

            for a in attributes['Attribute']:
                results.append({
                    "ip": ip,
                    "has_ioc": True,
                    "event_id": a.get("event_id"),
                    "attribute_id": a.get("id"),
                    "category": a.get("category"),
                    "type": a.get("type"),
                    "value": a.get("value"),
                    "comment": a.get("comment", "N/A"),
                    "event_info": a.get("Event", {}).get("info", "N/A"),
                    "event_link": f"{MISP_URL}events/view/{a.get('event_id')}"
                })
   
    if not results:
        return pd.DataFrame(columns=expected_columns)
    return pd.DataFrame(results)


def add_misp_ioc_columns(log_df, misp_results_df, log_type='generic'):
    misp_columns = ["has_ioc", "event_id", "attribute_id", "category", "type", "value", "comment", "event_info", "event_link"]

    
    if log_type.lower() == 'suricata':
        ip_cols = ['source_ip', 'destination_ip']
    else:
        ip_cols = ['source_ip', 'host_ip']

    for idx, row in log_df.iterrows():
        found_ioc = False
        for ip_col in ip_cols:
            ip_val = row.get(ip_col)
            if ip_val and ip_val in misp_results_df['ip'].values:
                matching = misp_results_df[misp_results_df['ip'] == ip_val]
                if not matching.empty:
                    found_ioc = True
                    for col in misp_columns:
                        if col in matching.columns:
                            log_df.at[idx, col] = matching.iloc[0][col]
                    break  
        
        if not found_ioc:
            for col in misp_columns:
                if col in log_df.columns:
                    if log_df[col].dtype == bool:
                        log_df.at[idx, col] = False
                    else:
                        log_df.at[idx, col] = ""
    return log_df


def group_suricata_alerts(suricata_df):

    suricata_df['timestamp'] = pd.to_datetime(suricata_df['timestamp'], errors='coerce')

    # Filter only alert events
    suricata_alert_df = suricata_df[suricata_df['event_kind'] == 'alert']
    suricata_alert_df = suricata_alert_df.sort_values('timestamp').reset_index(drop=True)

    # Create 30-minute time window start and end
    suricata_alert_df['time_group_start'] = suricata_alert_df['timestamp'].dt.floor('30T')
    suricata_alert_df['time_group_end'] = suricata_alert_df['time_group_start'] + pd.Timedelta(minutes=30)
    suricata_alert_df['time_range'] = suricata_alert_df['time_group_start'].dt.strftime('%Y-%m-%d %H:%M:%S') + " - " + suricata_alert_df['time_group_end'].dt.strftime('%Y-%m-%d %H:%M:%S')

    # Normalize IP pairs 
    suricata_alert_df['ip1'] = suricata_alert_df.apply(
        lambda row: min(row['source_ip'], row['destination_ip']), axis=1)
    suricata_alert_df['ip2'] = suricata_alert_df.apply(
        lambda row: max(row['source_ip'], row['destination_ip']), axis=1)
    suricata_alert_df['ip1'] = suricata_alert_df['ip1'].fillna('').astype(str)
    suricata_alert_df['ip2'] = suricata_alert_df['ip2'].fillna('').astype(str)
    # Create a combined source_dest_ip column with normalized IPs
    suricata_alert_df['source_dest_ip'] = suricata_alert_df['ip1'] + '|' + suricata_alert_df['ip2']

    suricata_alert_df['group_id'] = -1
    group_counter = 0

    for idx, row in suricata_alert_df.iterrows():
        if suricata_alert_df.at[idx, 'group_id'] != -1:
            continue
        suricata_alert_df.at[idx, 'group_id'] = group_counter
        mask = (
            (suricata_alert_df['group_id'] == -1) &
            (suricata_alert_df['time_group_start'] == row['time_group_start']) &
            (suricata_alert_df['source_dest_ip'] == row['source_dest_ip']) &
            (suricata_alert_df['network_protocol'] == row['network_protocol']) &
            (suricata_alert_df['rule_id'] == row['rule_id']) &
            (suricata_alert_df['event_kind'] == row['event_kind'])  # event_kind check added here
        )
        suricata_alert_df.loc[mask, 'group_id'] = group_counter
        group_counter += 1

    def find_reverse_groups(df):
        merged = True
        while merged:
            merged = False
            group_ids = df['group_id'].unique()
            for i in group_ids:
                for j in group_ids:
                    if i >= j:
                        continue
                    gi_df = df[df['group_id'] == i]
                    gj_df = df[df['group_id'] == j]
                    if gi_df.empty or gj_df.empty:
                        continue
                    gi = gi_df.iloc[0]
                    gj = gj_df.iloc[0]
                    if (
                        gi['time_group_start'] == gj['time_group_start'] and
                        gi['source_dest_ip'] == gj['source_dest_ip'] and
                        gi['network_protocol'] == gj['network_protocol'] and
                        gi['event_kind'] == gj['event_kind']  # event_kind check here too
                    ):
                        df.loc[df['group_id'] == j, 'group_id'] = i
                        merged = True
            if merged:
                unique_groups = sorted(df['group_id'].unique())
                mapping = {old: new for new, old in enumerate(unique_groups)}
                df['group_id'] = df['group_id'].map(mapping)
        return df

    suricata_alert_df = find_reverse_groups(suricata_alert_df)

    suricata_alert_df = suricata_alert_df.sort_values(['incident_id', 'timestamp']).reset_index(drop=True)
    suricata_alert_df.drop(columns=['time_group_start','time_group_end','ip1','ip2'], inplace=True)

    return suricata_alert_df


def group_logs(group_df):

    group_df['timestamp'] = pd.to_datetime(group_df['timestamp'], errors='coerce')

    group_df = group_df.sort_values('timestamp').reset_index(drop=True)

    # Create 30-minute time window start and end
    group_df['time_group_start'] = group_df['timestamp'].dt.floor('30T')
    group_df['time_group_end'] = group_df['time_group_start'] + pd.Timedelta(minutes=30)
    group_df['time_range'] = group_df['time_group_start'].dt.strftime('%Y-%m-%d %H:%M:%S') + " - " + group_df['time_group_end'].dt.strftime('%Y-%m-%d %H:%M:%S')

    # Normalize IP pairs (source_ip, host_ip)
    group_df['ip1'] = group_df.apply(lambda row: min(row['source_ip'], row['host_ip']), axis=1)
    group_df['ip2'] = group_df.apply(lambda row: max(row['source_ip'], row['host_ip']), axis=1)
    group_df['ip1'] = group_df['ip1'].fillna('').astype(str)
    group_df['ip2'] = group_df['ip2'].fillna('').astype(str)

    # Combined normalized IP pair column
    group_df['source_dest_ip'] = group_df['ip1'] + '|' + group_df['ip2'].astype(str).fillna('')
   
    group_df['group_id'] = -1
    group_counter = 0

    for idx, row in group_df.iterrows():
        if group_df.at[idx, 'group_id'] != -1:
            continue
        group_df.at[idx, 'group_id'] = group_counter
        mask = (
            (group_df['group_id'] == -1) &
            (group_df['time_group_start'] == row['time_group_start']) &
            (group_df['source_dest_ip'] == row['source_dest_ip'])
        )
        group_df.loc[mask, 'group_id'] = group_counter
        group_counter += 1

    def find_reverse_groups(df):
        merged = True
        while merged:
            merged = False
            group_ids = df['group_id'].unique()
            for i in group_ids:
                for j in group_ids:
                    if i >= j:
                        continue
                    gi_df = df[df['group_id'] == i]
                    gj_df = df[df['group_id'] == j]
                    if gi_df.empty or gj_df.empty:
                        continue
                    gi = gi_df.iloc[0]
                    gj = gj_df.iloc[0]
                    if (
                        gi['time_group_start'] == gj['time_group_start'] and
                        gi['source_dest_ip'] == gj['source_dest_ip']
                    ):
                        df.loc[df['group_id'] == j, 'group_id'] = i
                        merged = True
            if merged:
                unique_groups = sorted(df['group_id'].unique())
                mapping = {old: new for new, old in enumerate(unique_groups)}
                df['group_id'] = df['group_id'].map(mapping)
        return df

    group_df = find_reverse_groups(group_df)

    # Sort by group_id and timestamp
    group_df = group_df.sort_values(['group_id', 'timestamp']).reset_index(drop=True)

    group_df.drop(columns=['time_group_start', 'time_group_end', 'ip1', 'ip2'], inplace=True)

    return group_df

def update_vsftpd_auth(row):
    if row['process_name'] == 'vsftpd' and ('authentication' in row['message'].lower() or 'auth' in row['message'].lower()):
        row['event_category'] = 'authentication'
        # Extract outcome: success/failure
        outcome_match = re.search(r'authentication\s+(\w+)', row['message'], re.IGNORECASE)
        row['event_outcome'] = outcome_match.group(1).lower() if outcome_match else None
        # Extract ruser
        ruser_match = re.search(r'ruser=(\w+)', row['message'])
        row['user_name'] = ruser_match.group(1) if ruser_match else None
    return row

def get_event_category(g):
    cats = g['event_category'].dropna().str.lower().unique()
    if any("authentication" in c for c in cats):
        return "authentication"
    return cats[0] if len(cats) > 0 else "unknown"

def row_filled_count(row):

    return sum(1 for v in row if pd.notna(v) and str(v).strip() != "")

def grouping_datasets(df, count, conn, cursor):
    
    null_mask = df['incident_id'].isna()
    null_rows = df[null_mask]

    for idx, row in null_rows.iterrows():
        new_incident_id = f"INC{str(count).zfill(2)}"
        df.at[idx, 'incident_id'] = new_incident_id

        tr = row['time_range']
        sd_ip = row['source_dest_ip']

        # --- SURICATA ---
        in_suricata_mask = (filtered_suricata_df['time_range'] == tr) & (filtered_suricata_df['source_dest_ip'] == sd_ip)
        in_suricata = bool(in_suricata_mask.any())
        suri_data = {}
        if in_suricata:
            filtered_suricata_df.loc[in_suricata_mask, 'incident_id'] = new_incident_id
            suri_rows = filtered_suricata_df.loc[in_suricata_mask]
            if not suri_rows.empty:
                suri_match = suri_rows.iloc[0].to_dict()
                suri_data = {
                    'message_suri': suri_match.get('message'),
                    'network_protocol_suri': suri_match.get('network_protocol'),
                    'event_dataset_suri': suri_match.get('event_dataset'),
                    'event_original_suri': suri_match.get('event_original'),
                    'rule_name_suri': suri_match.get('rule_name'),
                    'rule_id_suri': suri_match.get('rule_id'),
                    'rule_category_suri': suri_match.get('rule_category'),
                    'event_severity_suri': suri_match.get('event_severity')
                }

        # --- AUTHLOG ---
        in_authlog_mask = (filtered_authlog_df['time_range'] == tr) & (filtered_authlog_df['source_dest_ip'] == sd_ip)
        in_authlog = bool(in_authlog_mask.any())
        auth_data = {}
        if in_authlog:
            filtered_authlog_df.loc[in_authlog_mask, 'incident_id'] = new_incident_id
            auth_rows = filtered_authlog_df.loc[in_authlog_mask]
            if not auth_rows.empty:
                auth_match = auth_rows.iloc[0].to_dict()
                auth_data = {
                    'event_dataset_auth': auth_match.get('event_dataset'),
                    'message_auth': auth_match.get('message'),
                    'process_name_auth': auth_match.get('process_name'),
                    'event_outcome_auth': auth_match.get('event_outcome'),
                    'event_category_auth': auth_match.get('event_category'),
                    'event_action_auth': auth_match.get('event_action')
                }

        # --- VSFTPD ---
        in_vsftpd_mask = (filtered_vsftpd_df['time_range'] == tr) & (filtered_vsftpd_df['source_dest_ip'] == sd_ip)
        in_vsftpd = bool(in_vsftpd_mask.any())
        vsftpd_data = {}
        if in_vsftpd:
            filtered_vsftpd_df.loc[in_vsftpd_mask, 'incident_id'] = new_incident_id
            vsftpd_rows = filtered_vsftpd_df.loc[in_vsftpd_mask]
            if not vsftpd_rows.empty:
                vsftpd_match = vsftpd_rows.iloc[0].to_dict()
                vsftpd_data = {
                    'event_dataset_vsftpd': vsftpd_match.get('event_dataset'),
                    'message_vsftpd': vsftpd_match.get('message')
                }

        # --- SYSLOG ---
        in_syslog_mask = (filtered_syslog_df['time_range'] == tr) & (filtered_syslog_df['source_dest_ip'] == sd_ip)
        in_syslog = bool(in_syslog_mask.any())
        syslog_data = {}
        if in_syslog:
            filtered_syslog_df.loc[in_syslog_mask, 'incident_id'] = new_incident_id
            syslog_rows = filtered_syslog_df.loc[in_syslog_mask]
            if not syslog_rows.empty:
                syslog_match = syslog_rows.iloc[0].to_dict()
                syslog_data = {
                    'event_dataset_sys': syslog_match.get('event_dataset'),
                    'message_sys': syslog_match.get('message')
                }

        has_ioc_flag = bool(row.get("has_ioc"))

      
        new_row = {
            'incident_id': new_incident_id,
            'timestamp': row.get('timestamp'),
            'source_ip': row.get('source_ip'),
            'destination_ip': row.get('destination_ip') or row.get('host_ip'),
            'message_suri': suri_data.get('message_suri'),
            'network_protocol_suri': suri_data.get('network_protocol_suri'),
            'event_dataset_suri': suri_data.get('event_dataset_suri'),
            'event_original_suri': suri_data.get('event_original_suri'),
            'rule_name_suri': suri_data.get('rule_name_suri'),
            'rule_id_suri': suri_data.get('rule_id_suri'),
            'rule_category_suri': suri_data.get('rule_category_suri'),
            'event_severity_suri': suri_data.get('event_severity_suri'),
            'MISP_Event_ID': row.get('event_id'),
            'MISP_Category': row.get('category'),
            'MISP_Type': row.get('type'),
            'MISP_Value': row.get('value'),
            'MISP_Comment': row.get('comment'),
            'MISP_Event_Info': row.get('event_info'),
            'MISP_url': row.get('event_link'),
            'event_dataset_auth': auth_data.get('event_dataset_auth'),
            'message_auth': auth_data.get('message_auth'),
            'process_name_auth': auth_data.get('process_name_auth'),
            'event_outcome_auth': auth_data.get('event_outcome_auth'),
            'event_category_auth': auth_data.get('event_category_auth'),
            'event_action_auth': auth_data.get('event_action_auth'),
            'event_dataset_sys': syslog_data.get('event_dataset_sys'),
            'message_sys': syslog_data.get('message_sys'),
            'event_dataset_vsftpd': vsftpd_data.get('event_dataset_vsftpd'),
            'message_vsftpd': vsftpd_data.get('message_vsftpd'),
            'in_suricata': str(in_suricata),
            'in_syslog': str(in_syslog),
            'in_vsftpd': str(in_vsftpd),
            'in_authlog': str(in_authlog),
            'has_ioc': str(has_ioc_flag),
            'initial_prediction': None,
            'prediction_reason': None,
            'analyst_feedback': None,
            'analyst_comments': None,
            'feedback_modified_prediction': None,
            'Status': 'New'
        }

        new_row.update(suri_data)
        new_row.update(auth_data)
        new_row.update(vsftpd_data)
        new_row.update(syslog_data)
        

        columns = ', '.join(new_row.keys())
        placeholders = ', '.join(['%s'] * len(new_row))
        sql = f"INSERT INTO prediction_data ({columns}) VALUES ({placeholders})"
        cursor.execute(sql, tuple(new_row.values()))
        conn.commit()

        count += 1  

    return df, count


ip_list = misp_check['source_ip'].tolist()

print("Fetching MISP  Data")
misp_results_df = check_ips_in_misp(ip_list)

print("Updating MISP Data to logs")
# Add MISP IOC info to other logs by matching IPs
authlog_df = add_misp_ioc_columns(authlog_df, misp_results_df,  log_type='generic')
suricata_df = add_misp_ioc_columns(suricata_df, misp_results_df,  log_type='generic')
syslog_df = add_misp_ioc_columns(syslog_df, misp_results_df,  log_type='generic')
vsftpd_df = add_misp_ioc_columns(vsftpd_df, misp_results_df,  log_type='generic')
print("MISP data successfully update")

# grouping logs absed on timestamp-30min , source,destination ip, network_protocol and event type
print("Grouping Events into Incidents")
grouped_suricata_df = group_suricata_alerts(suricata_df)
grouped_authlog_df = group_logs(authlog_df)
grouped_vsftpd_df = group_logs(vsftpd_df)
grouped_syslog_df = group_logs(syslog_df)


grouped_authlog_df = grouped_authlog_df.apply(update_vsftpd_auth, axis=1)

filtered_suricata_df = grouped_suricata_df.groupby('group_id', group_keys=False).apply(
    lambda g: g[g['has_ioc'].notna() & (g['has_ioc'] != '')].head(1) if (g['has_ioc'].notna() & (g['has_ioc'] != '')).any() else g.head(1)
).reset_index(drop=True)



# Group by group_id
filtered_authlog_df = grouped_authlog_df.groupby('group_id', group_keys=False).apply(
    lambda g: (
        g.loc[g.apply(row_filled_count, axis=1).idxmax()]  # pick row with most filled values
        .to_frame().T  
        .assign(
            message=lambda df: [
                f"For {g['process_name'].iloc[0]} "
                f"{g['event_outcome'].notna().sum()} {get_event_category(g)} attempts, "
                f"where {(g['event_outcome'].str.lower() == 'failure').sum()} Failure "
                f"and {(g['event_outcome'].str.lower() == 'success').sum()} Success were identified"
            ] * len(df)
            if g['event_category'].str.contains('authentication', case=False, na=False).any()
            else df.get('message', [None] * len(df))
        )
    )
).reset_index(drop=True)


# Group by group_id and create human-readable summary for FTP
filtered_vsftpd_df = grouped_vsftpd_df.groupby('group_id', group_keys=False).apply(
    lambda g: (
        g.loc[g.apply(row_filled_count, axis=1).idxmax()]
        .to_frame().T
        .assign(
            message=lambda df: [
                f"{g['message'].str.contains('CONNECT', case=False).sum()} connection(s), "
                f"{g['message'].str.contains('LOGIN', case=False).sum()} login attempt(s) "
                f"({g['message'].str.contains('OK LOGIN', case=False).sum()} success, "
                f"{g['message'].str.contains('FAIL LOGIN', case=False).sum()} failure); "
                + ("Transfers: " + "; ".join(
                    g[g['message'].str.contains('UPLOAD|DOWNLOAD|DELETE', case=False)]['message']
                     .apply(lambda x: next((act for act in ["UPLOAD:", "DOWNLOAD:", "DELETE:"] if act in x), "") + x.split(next((act for act in ["UPLOAD:", "DOWNLOAD:", "DELETE:"] if act in x), ""))[1].strip())
                     .tolist()
                ) if g['message'].str.contains('UPLOAD|DOWNLOAD|DELETE', case=False).any() else "Transfers: No file transfers detected.")
            ] * len(df)
        )
    )
).reset_index(drop=True)


filtered_syslog_df = grouped_syslog_df.groupby('group_id', group_keys=False).apply(
    lambda g: (
        (g[g['has_ioc'].notna() & (g['has_ioc'] != '')].head(1)
         if (g['has_ioc'].notna() & (g['has_ioc'] != '')).any()
         else g.head(1))
        .assign(
            message=lambda df: [
                ", ".join([
                    f"{g['message'].str.contains('SYN', case=False).sum()} SYN packet(s)" if g['message'].str.contains('SYN', case=False).sum() > 0 else "",
                    f"{g['message'].str.contains('BLOCK', case=False).sum()} blocked packet(s)" if g['message'].str.contains('BLOCK', case=False).sum() > 0 else "",
                    f"{g['message'].str.contains('DROP', case=False).sum()} dropped packet(s)" if g['message'].str.contains('DROP', case=False).sum() > 0 else "",
                    f"{g['message'].str.contains('ACCEPT', case=False).sum()} accepted packet(s)" if g['message'].str.contains('ACCEPT', case=False).sum() > 0 else "",
                    f"{g['message'].str.contains('AUTHENTICATION', case=False).sum()} authentication-related message(s)" if g['message'].str.contains('AUTHENTICATION', case=False).sum() > 0 else "",
                    f"{g['message'].str.contains('LOGIN', case=False).sum()} login-related message(s)" if g['message'].str.contains('LOGIN', case=False).sum() > 0 else ""
                ]).replace(", ,", ", ").strip(", ")
            ] * len(df)
        )
    )
).reset_index(drop=True)
filtered_syslog_df = filtered_syslog_df[filtered_syslog_df['message'].str.strip() != ""]



print("Finding Co-relation between logs")
suricata_data,max_inc_num = grouping_datasets(filtered_suricata_df,max_inc_num, conn, cursor)
auth_data,max_inc_num = grouping_datasets(filtered_authlog_df,max_inc_num,conn, cursor)
ftp_data,max_inc_num  = grouping_datasets(filtered_vsftpd_df,max_inc_num, conn, cursor)
sys_data,max_inc_num  = grouping_datasets(filtered_syslog_df,max_inc_num, conn, cursor)

pd.set_option('display.max_rows', None)
cursor.close()
conn.close()





