import streamlit as st
import pandas as pd
import pymysql
import yaml
import ipaddress
import re
import matplotlib.pyplot as plt
import paramiko
import os
import subprocess

st.set_page_config(layout="wide")

# DB Connection
conn = pymysql.connect(
    host='192.168.200.20',
    user='siemuser',
    password='admin1234',
    db='IDS_Feedback',
)
cursor = conn.cursor()
if "db_conn_closed" not in st.session_state:
    st.session_state.db_conn_closed = False

# Load Data
prediction_data = pd.read_sql("SELECT * FROM prediction_data WHERE Status='New';", conn)
history_data = pd.read_sql("SELECT * FROM prediction_data WHERE Status='Completed';", conn)

# ---- Outcome calculation ----
def get_home_net_ips(yaml_path):
    with open(yaml_path, 'r') as file:
        config = yaml.safe_load(file)

    home_net_raw = config.get('vars', {}).get('address-groups', {}).get('HOME_NET')
    if not home_net_raw:
        return []

    home_net_str = home_net_raw.strip('"').strip("'")
    entries = [x.strip() for x in home_net_str.strip("[]").split(",")]

    ips = []
    for entry in entries:
        if not entry:
            continue
        try:
            network = ipaddress.ip_network(entry, strict=False)
            ips.extend([str(ip) for ip in network.hosts()])
        except ValueError:
            print(f"Skipping invalid entry: {entry}")

    return ips

def to_bool(series):
    return series.apply(lambda x: True if str(x).lower() in ['true', '1'] else False)



def calculate_feedback_outcome(df,history_df):
    # Normalize boolean columns
    bool_columns = ['has_ioc', 'in_suricata', 'in_syslog', 'in_vsftpd', 'in_authlog']
    for col in bool_columns:
        df[col] = to_bool(df[col])

    yaml_file = "/etc/suricata/suricata.yaml"
    home_net_ips = get_home_net_ips(yaml_file)
    home_net_set = set(home_net_ips)

    def is_in_home_net(ip):
        return ip in home_net_set

    def extract_auth_attempts(message_auth):
        #Extract the number before 'authentication'
        if not message_auth or not isinstance(message_auth, str):
            return None
        match = re.search(r"(\d+)\s+authentication", message_auth.lower())
        return int(match.group(1)) if match else None

    def extract_ftp_activity(message_vsftpd):
        
        if not message_vsftpd or not isinstance(message_vsftpd, str):
            return {"login_attempts": None, "bytes_transferred": None}

        msg = message_vsftpd.lower()
        result = {"login_attempts": None, "bytes_transferred": None}

        # --- Extract login attempts ---
        login_match = re.search(r"(\d+)\s+login attempt", msg)
        if login_match:
            result["login_attempts"] = int(login_match.group(1))

        # --- Extract bytes transferred ---
        bytes_match = re.search(r"(\d+)\s+bytes", msg)
        if bytes_match:
            result["bytes_transferred"] = int(bytes_match.group(1))

        return result


    def extract_syslog_attempts(message_syslog: str):

        if not message_syslog or not isinstance(message_syslog, str):
            return None

        patterns = {
            "syn": r"\b(\d+)?\s*syn\b",
            "block": r"\b(\d+)?\s*block\b",
            "drop": r"\b(\d+)?\s*drop\b",
            "accept": r"\b(\d+)?\s*accept\b",
            "authentication": r"\b(\d+)?\s*authentication\b",
            "login": r"\b(\d+)?\s*login\b",
        }
        counts = {}
        for key, pat in patterns.items():

            match = re.search(pat, message_syslog, re.IGNORECASE)
            if match:

                if match.group(1):
                    counts[key] = int(match.group(1))
                else:
                    counts[key] = len(re.findall(pat, message_syslog, re.IGNORECASE))

        return counts if counts else None

    df["auth_feedback"] = ""
    df["ftp_feedback"] = ""
    df["sys_feedback"] = ""


    # --- Historical feedback group ---
    feedback_group = history_df.groupby(['rule_id_suri','source_ip' ,'destination_ip']).agg(
        feedback_counts=pd.NamedAgg(
            column='analyst_feedback',
            aggfunc=lambda x: x.value_counts().to_dict()
        ),
        incident_ids=pd.NamedAgg(column='incident_id', aggfunc=lambda x: list(x))
    )

    def get_prediction_confidence(feedback_counts, incident_ids):

        total_feedback = sum(feedback_counts.values())
        if total_feedback == 0:
            return None, 0, "N/A", []

        # calculate proportions
        proportions = {fb: c / total_feedback for fb, c in feedback_counts.items()}

        # pick dominant feedback (highest proportion)
        dominant_feedback, max_prop = max(proportions.items(), key=lambda x: x[1])
        dominant_percent = round(max_prop * 100)

        # confidence range
        if dominant_percent >= 80:
            confidence_label = "High"
        elif dominant_percent >= 60:
            confidence_label = "Medium"
        else:
            confidence_label = "Low"

        dominant_count = feedback_counts[dominant_feedback]
        dominant_incidents = incident_ids[:dominant_count]

        return dominant_feedback, dominant_percent, confidence_label, dominant_incidents

    def get_fn_confidence(has_ioc, suricata_flag, log_flags):

        if not has_ioc or suricata_flag:
            return None, 0, "N/A"

        log_sources = [k for k, v in log_flags.items() if v]
        log_count = len(log_sources)

        if log_count >= 3:
            confidence = 80
            level = "High"
        elif log_count == 2:
            confidence = 60
            level = "Medium"
        else:
            confidence = 50
            level = "Low"

        return confidence, level, log_sources


    # ------ Check 1 Present in suricata and MISP ---------- TP

    tp_mask = (df['has_ioc'] == True) & (df['in_suricata'] == True)

    df.loc[tp_mask, 'initial_prediction'] = 'True Positive'
    for idx in df[tp_mask].index:
        comments = []
        rule_id = df.at[idx, 'rule_id_suri']
        src_ip = df.at[idx, 'source_ip']
        dst_ip = df.at[idx, 'destination_ip']

        # ---Historical feedback check ---
        try:
            hist_row = feedback_group.loc[(rule_id,src_ip, dst_ip)]
            feedback_counts = hist_row['feedback_counts']
            incident_ids = hist_row['incident_ids']

            dominant_feedback, dominant_percent, confidence_label, dominant_incidents = get_prediction_confidence(feedback_counts, incident_ids)

            if dominant_feedback:
                
                dominant_count = feedback_counts[dominant_feedback]
                dominant_incidents = incident_ids[:dominant_count]

                df.at[idx, 'initial_prediction'] = dominant_feedback
                df.at[idx, 'prediction_confidence'] = confidence_label
                df.at[idx, 'prediction_reason'] = (
                    f"This incident has been classified as {dominant_feedback} "
                    f"with {dominant_percent}% confidence ({confidence_label}). "
                    f"Decision is based on prior analyst feedback from incidents: "
                    f"{', '.join(map(str, dominant_incidents))}."
                )
                continue

        except KeyError:
            pass

        log_flags = {
            "authlog": df.at[idx, 'in_authlog'],
            "ftplog": df.at[idx, 'in_vsftpd'],
            "syslog": df.at[idx, 'in_syslog'],
            "Suricata alert": df.at[idx, 'in_suricata'],
            "IOC": df.at[idx, 'has_ioc']
        }

        confidence, level, logs = get_fn_confidence(
            has_ioc=True,
            suricata_flag=False,
            log_flags=log_flags
        )

        logs_str = ", ".join(logs) if logs else ""

        df.at[idx, 'prediction_confidence'] = level
        df.at[idx, 'prediction_reason'] = (
            f"This incident has been classified as a True Positive based on correlation with threat intel "
            f"and was also supported by {logs_str}."
        )

    # ------ Check 2 present in Suricata and not in MISP---------- FP, TP

    check2 = (df['has_ioc'] == False) & (df['in_suricata'] == True)

    for idx in df[check2].index:
        comments = []
        prediction = "False Positive"

        rule_id = df.at[idx, 'rule_id_suri']
        src_ip = df.at[idx, 'source_ip']
        dst_ip = df.at[idx, 'destination_ip']


        # --- Historical feedback check ---
        try:
            hist_row = feedback_group.loc[(rule_id, src_ip,dst_ip)]
            feedback_counts = hist_row['feedback_counts']
            incident_ids = hist_row['incident_ids']

            dominant_feedback, dominant_percent, confidence_label, dominant_incidents = get_prediction_confidence(feedback_counts, incident_ids)

            if dominant_feedback:
                
                dominant_count = feedback_counts[dominant_feedback]
                dominant_incidents = incident_ids[:dominant_count]
                df.at[idx, 'initial_prediction'] = dominant_feedback
                df.at[idx, 'prediction_confidence'] = confidence_label
                df.at[idx, 'prediction_reason'] = (
                    f"This incident has been classified as {dominant_feedback} "
                    f"with {dominant_percent}% confidence ({confidence_label}). "
                    f"Decision is based on prior analyst feedback from incidents: "
                    f"{', '.join(map(str, dominant_incidents))}."
                )
                continue

        except KeyError:
            pass

        src_in_home = is_in_home_net(src_ip)
        dst_in_home = is_in_home_net(dst_ip)

        if src_in_home and dst_in_home:
            context = "internal network"
        else:
            parts = []
            if not src_in_home:
                parts.append(f"source IP {src_ip} is external network")
            if not dst_in_home:
                parts.append(f"destination IP {dst_ip} is external network")
            context = "; ".join(parts)

        # --- authlog ---
        if df.at[idx, 'in_authlog']:
            attempts = extract_auth_attempts(df.at[idx, 'message_auth'])
            if attempts and attempts > 5:
                reason = f"{attempts} authentication attempts detected in authlog"
                prediction = "True Positive"
            else:
                reason = "low number of authentication attempts detected in Authlog"
            comments.append(reason)

        # --- vsftpd ---
        if df.at[idx, 'in_vsftpd']:
            ftp_activity = extract_ftp_activity(df.at[idx, 'message_vsftpd'])
            ftp_attempts = ftp_activity.get("login_attempts")
            ftp_bytes = ftp_activity.get("bytes_transferred")

            # Thresholds
            LOGIN_THRESHOLD = 5
            BYTES_THRESHOLD = 20_000_000  #  (~20 MB)

            reason_parts = []
            # --- Check login attempts ---
            if ftp_attempts is not None and ftp_attempts > LOGIN_THRESHOLD:
                reason_parts.append(f"{ftp_attempts} authentication attempts detected in FTP")
                prediction = "True Positive"

            # --- Check bytes transferred ---
            if ftp_bytes is not None and ftp_bytes > BYTES_THRESHOLD:
                reason_parts.append(f"{ftp_bytes} bytes transferred in FTP session")
                prediction = "True Positive"

            if not reason_parts:
                reason_parts.append("Low number of FTP attempts and small/no file transfer detected")

            reason = " and ".join(reason_parts)
            df.at[idx, 'initial_prediction'] = prediction
            df.at[idx, 'prediction_reason'] = reason

            comments.append(reason)

        # --- syslog ---
        if df.at[idx, 'in_syslog']:
            syslog_counts = extract_syslog_attempts(df.at[idx, 'message_sys'])
            total_suspicious = sum(syslog_counts.values()) if syslog_counts else 0
            if total_suspicious > 10 or (syslog_counts and any(v > 5 for v in syslog_counts.values())):
                reason = "high/repeated syslog events: " + ", ".join(
                    f"{k.upper()}={v}" for k, v in syslog_counts.items() if v > 0
                )
                prediction = "True Positive"
            else:
                reason = "low number of syslog events"
            comments.append(reason)

        log_flags = {
            "authlog": df.at[idx, 'in_authlog'],
            "ftplog": df.at[idx, 'in_vsftpd'],
            "syslog": df.at[idx, 'in_syslog'],
            "suricata": df.at[idx, 'in_suricata'],
            "IOC": df.at[idx, 'has_ioc']
        }

        confidence, level, logs = get_fn_confidence(
            has_ioc=True,
            suricata_flag=False,
            log_flags=log_flags
        )

        logs_str = ", ".join(comments) if comments else "no extra logs found"
        df.at[idx, 'initial_prediction'] = prediction
        df.at[idx, 'prediction_confidence'] = level
        df.at[idx, 'prediction_reason'] = (
            f"This incident has been classified as {prediction} because its {context}, and {logs_str}."
        )

    # ------ Check 3 present in IOC and not in Suricata---------- FN

    check3 = (df['has_ioc'] == True) & (df['in_suricata'] == False)

    df.loc[check3, 'initial_prediction'] = 'False Negative'
    for idx in df[check3].index:
        log_flags = {
            "authlog": df.at[idx, 'in_authlog'],
            "ftplog": df.at[idx, 'in_vsftpd'],
            "syslog": df.at[idx, 'in_syslog'],
            "suricata": df.at[idx, 'in_suricata'],
            "IOC": df.at[idx, 'has_ioc']
        }

        confidence, level, logs = get_fn_confidence(
            has_ioc=True,
            suricata_flag=False,
            log_flags=log_flags
        )

        logs_str = ", ".join(logs) if logs else "no extra logs"


        df.at[idx, 'prediction_confidence'] = level
        df.at[idx, 'prediction_reason'] = (
            f"This incident has been classified as a False Negative "
            f"with {confidence}% confidence ({level}). "
            f"IOC was detected but no alert was generated in IDS. "
            f"Supporting evidence: {logs_str}."
        )

    # ------ Check 4 not present in IOC and not in Suricata---------- FN, TN

    check4 = (df['has_ioc'] == False) & (df['in_suricata'] == False)

    for idx in df[check4].index:

        comments = []
        prediction = "True Negative"

        src_ip = df.at[idx, 'source_ip']
        dst_ip = df.at[idx, 'destination_ip']

        src_in_home = is_in_home_net(src_ip)
        dst_in_home = is_in_home_net(dst_ip)

        if src_in_home and dst_in_home:
            context = "internal network"
        else:
            parts = []
            if not src_in_home:
                parts.append(f"source IP {src_ip} is external network")
            if not dst_in_home:
                parts.append(f"destination IP {dst_ip} is external network")
            context = "; ".join(parts)

        # --- authlog ---
        if df.at[idx, 'in_authlog']:
            attempts = extract_auth_attempts(df.at[idx, 'message_auth'])
            if attempts and attempts > 5:
                reason = f"{attempts} authentication attempts detected in authlog"
                prediction = "False Negative"  # promote
            else:
                reason = "low number of authentication attempts detected in Authlog"
            comments.append(reason)

        # --- vsftpd ---
        if df.at[idx, 'in_vsftpd']:
            ftp_activity = extract_ftp_activity(df.at[idx, 'message_vsftpd'])
            ftp_attempts = ftp_activity.get("login_attempts")
            ftp_bytes = ftp_activity.get("bytes_transferred")

            # Thresholds
            LOGIN_THRESHOLD = 5
            BYTES_THRESHOLD = 20_000_000  #  (~20 MB)

            reason_parts = []
            # --- Check login attempts ---
            if ftp_attempts is not None and ftp_attempts > LOGIN_THRESHOLD:
                reason_parts.append(f"{ftp_attempts} authentication attempts detected in FTP")
                prediction = "True Positive"

            # --- Check bytes transferred ---
            if ftp_bytes is not None and ftp_bytes > BYTES_THRESHOLD:
                reason_parts.append(f"{ftp_bytes} bytes transferred in FTP session")
                prediction = "True Positive"

            if not reason_parts:
                reason_parts.append("Low number of FTP attempts and small/no file transfer detected")

            
            reason = " and ".join(reason_parts)
            df.at[idx, 'initial_prediction'] = prediction
            df.at[idx, 'prediction_reason'] = reason
            comments.append(reason)

        # --- syslog ---
        if df.at[idx, 'in_syslog']:
            syslog_counts = extract_syslog_attempts(df.at[idx, 'message_sys'])
            total_suspicious = sum(syslog_counts.values()) if syslog_counts else 0
            if total_suspicious > 10 or (syslog_counts and any(v > 5 for v in syslog_counts.values())):
                reason = "high/repeated syslog events: " + ", ".join(
                    f"{k.upper()}={v}" for k, v in syslog_counts.items() if v > 0
                )
                prediction = "False Negative"
            else:
                reason = "low number of syslog events"
            comments.append(reason)

        
        log_flags = {
            "authlog": df.at[idx, 'in_authlog'],
            "ftplog": df.at[idx, 'in_vsftpd'],
            "syslog": df.at[idx, 'in_syslog'],
            "suricata": df.at[idx, 'in_suricata'],
            "IOC": df.at[idx, 'has_ioc']
        }

        confidence, level, logs = get_fn_confidence(
            has_ioc=True,
            suricata_flag=False,
            log_flags=log_flags
        )

        logs_str = ", ".join(comments) if comments else "no extra logs found"
        df.at[idx, 'initial_prediction'] = prediction
        df.at[idx, 'prediction_confidence'] = level
        df.at[idx, 'prediction_reason'] = (
            f"This incident has been classified as {prediction} because its {context}, and {logs_str}."
        )

    return df

def save_feedback_to_db(incident_id,initial_prediction,prediction_reason,feedback, comment,firewall_rule,firewall_rule_data,
                        suricata_rule, suricata_rule_data,prediction_confidence,conn):

    try:
        cursor = conn.cursor()
        sql = """
            UPDATE prediction_data
            SET prediction_reason = %s,
                initial_prediction = %s,
                analyst_feedback = %s,
                analyst_comments = %s,
                firewall_rule = %s,
                firewall_rule_data = %s,
                suricata_rule = %s,
                suricata_rule_data = %s,
                prediction_confidence = %s,
                Status = 'Completed'
            WHERE incident_id = %s
        """
        cursor.execute(
            sql,
            (
                prediction_reason,
                initial_prediction,
                feedback,
                comment,
                firewall_rule,
                str(firewall_rule_data),
                suricata_rule,
                str(suricata_rule_data),
                prediction_confidence,
                incident_id
            )
        )
        conn.commit()
        cursor.close()
    except Exception as e:
        print(f"Error saving to database: {e}")


def display_full_log_details(row):
    st.write("**Incident Details:**")
    st.markdown(f"**Timestamp:** {row.get('timestamp', 'N/A')}", unsafe_allow_html=True)
    st.markdown(
        f"**Source IP:** {row.get('source_ip', 'N/A')}&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"
        f"**Destination IP:** {row.get('destination_ip', 'N/A')}", unsafe_allow_html=True)

    st.write("---")
    st.markdown("**Suricata Logs:**", unsafe_allow_html=True)
    if pd.notna(row.get('event_dataset_suri')):
        st.markdown(f"**Message:** {row.get('message_suri', 'N/A')}", unsafe_allow_html=True)
        st.markdown(f"**Network Protocol:** {row.get('network_protocol_suri', 'N/A')}",unsafe_allow_html=True)
        st.markdown(f"**Event Origin:** {row.get('event_original_suri', 'N/A')}", unsafe_allow_html=True)
        st.markdown(f"**Rule ID:** {row.get('rule_id_suri', 'N/A')} &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"
                    f"**Rule Name:** {row.get('rule_name_suri', 'N/A')}", unsafe_allow_html=True)
        st.markdown(
            f"**Rule Category:** {row.get('rule_category_suri', 'N/A')}&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"
            f"**Event Severity:** {row.get('event_severity_suri', 'N/A')}", unsafe_allow_html=True)

    else:
        st.markdown("No Suricata logs present for this Incident.", unsafe_allow_html=True)
    st.write("---")

    st.markdown("**Auth Logs:**", unsafe_allow_html=True)
    if pd.notna(row.get('event_dataset_auth')):
        st.markdown(f"**Message:** {row.get('message_auth', 'N/A')}", unsafe_allow_html=True)
        st.markdown(
            f"**Process Name:** {row.get('process_name_auth', 'N/A')}&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"
            f"**Event Action:** {row.get('event_action_auth', 'N/A')}", unsafe_allow_html=True)
        st.markdown(
            f"**Event Category:** {row.get('event_category_auth', 'N/A')}&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"
            f"**Event Outcome:** {row.get('event_outcome_auth', 'N/A')}", unsafe_allow_html=True)
    else:
        st.markdown("No auth logs present for this Incident.", unsafe_allow_html=True)

    st.write("---")
    st.markdown("**Sys Logs:**", unsafe_allow_html=True)
    if pd.notna(row.get('event_dataset_sys')):
        st.markdown(f"**Message:** {row.get('message_sys', 'N/A')}", unsafe_allow_html=True)
    else:
        st.markdown("No Sys logs present for this Incident.", unsafe_allow_html=True)

    st.write("---")
    st.markdown("**FTP Logs:**", unsafe_allow_html=True)
    if pd.notna(row.get('event_dataset_vsftpd')):
        st.markdown(f"**Message:** {row.get('message_vsftpd', 'N/A')}", unsafe_allow_html=True)
    else:
        st.markdown("No FTP logs present for this Incident.", unsafe_allow_html=True)
    st.write("---")

    st.markdown("**MISP Threat Intel:**", unsafe_allow_html=True)
    if row.get('MISP_Event_ID') and str(row.get('MISP_Event_ID')).strip():
        st.markdown(f"**Event ID:** {row.get('MISP_Event_ID', 'N/A')}", unsafe_allow_html=True)
        st.markdown(f"**Category** {row.get('MISP_Category', 'N/A')}&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"
                    f"**Type:** {row.get('MISP_Type', 'N/A')} ", unsafe_allow_html=True)
        st.markdown(f"**Malicious IP:** {row.get('MISP_Value', 'N/A')}", unsafe_allow_html=True)
        st.markdown(f"**Comments:** {row.get('MISP_Comment', 'N/A')}", unsafe_allow_html=True)
        st.markdown(f"**Event Info:** {row.get('Event_Info', 'N/A')}", unsafe_allow_html=True)
        misp_link = row.get('MISP_url', 'N/A')
        st.markdown(f"**Link:** [{misp_link}]({misp_link})", unsafe_allow_html=True)

    else:
        st.markdown("No MISP Threat Intel present for this Incident.", unsafe_allow_html=True)
    st.write("---")

    st.markdown("**Automation Prediction:**", unsafe_allow_html=True)
    st.markdown(f"**Prediction:** {row.get('initial_prediction', 'N/A')} &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"
                    f"**Confidence Level:** {row.get('prediction_confidence', 'N/A')} ", unsafe_allow_html=True)
    st.markdown(f"**Prediction Reason:** {row.get('prediction_reason', 'N/A')}", unsafe_allow_html=True)


def load_active_suricata_rules(yaml_file="/etc/suricata/suricata.yaml"):

    rules_by_sid = {}
    # Load YAML
    try:
        with open(yaml_file, "r") as f:
            suricata_config = yaml.safe_load(f)
    except Exception as e:
        print(f"Error loading YAML: {e}")
        return rules_by_sid

    # Default rule path
    rule_path = suricata_config.get("default-rule-path")
    # Active rule files
    active_rule_files = []
    for rulefile in suricata_config.get("rule-files", []):
        rulefile = rulefile.strip()
        if rulefile and not rulefile.startswith("#"):
            active_rule_files.append(os.path.join(rule_path, rulefile))

    # Read active rules
    for filepath in active_rule_files:
        if not os.path.exists(filepath):
            continue
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Extract SID
                if "sid:" in line:
                    try:
                        sid_part = [x for x in line.split(";") if "sid:" in x][0]
                        sid_value = int(sid_part.split(":")[1].strip())
                        rules_by_sid[sid_value] = line
                    except:
                        continue

    return rules_by_sid


def add_suricata_rule(rule_text, rules_file="/var/lib/suricata/rules/suricata.rules"):

    rule_text_escaped = rule_text.replace('"', r'\"')

    cmd = f'echo "{rule_text_escaped}" >> {rules_file}'

    result = subprocess.run(['sudo', 'bash', '-c', cmd], capture_output=True, text=True)

    if result.returncode == 0:
        print("Rule added successfully!")
    else:
        print(f"Error adding rule: {result.stderr}")

    return result

def add_suppression_rule(rule_text, rules_file="/etc/suricata/threshold.config"):
    try:
        with open(rules_file, "r") as f:
            existing_rules = f.read().splitlines()
    except FileNotFoundError:
        existing_rules = []

    # Check if the rule already exists
    if rule_text in existing_rules:
        result="Rule already exists"
        return result

    rule_text_escaped = rule_text

    cmd = f'echo "{rule_text_escaped}" >> {rules_file}'

    result = subprocess.run(['sudo', 'bash', '-c', cmd], capture_output=True, text=True)

    if result.returncode == 0:
        print("Rule added successfully!")
    else:
        print(f"Error adding rule: {result.stderr}")

    return result

def execute_sudo(ssh, cmd, password):

    full_cmd = f"sudo -S {cmd}"
    stdin, stdout, stderr = ssh.exec_command(full_cmd, get_pty=True)
    stdin.write(password + "\n")
    stdin.flush()
    out = stdout.read().decode()
    err = stderr.read().decode()
    return out, err

def check_rule(source_ip, destination_ip,router_ip="192.168.200.1", username="nayomi", password="admin"):
    #Check if an iptables rule already exist
    list_cmd = "sudo iptables -L FORWARD -v -n --line-numbers"
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(router_ip, username=username, password=password)
        out, err = execute_sudo(ssh, list_cmd, password)
        if err:
            return None, f"Error listing rules: {err}"

        for line in out.splitlines():
            if source_ip in line and destination_ip in line :
                return line, None
        return None, None
    finally:
        ssh.close()

def add_rule(rule_cmd,router_ip="192.168.200.1", username="nayomi", password="admin"):
    #Add a new iptables rule.
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(router_ip, username=username, password=password)
        out_add, err_add = execute_sudo(ssh, rule_cmd, password)
        if err_add:
            return f"Error adding rule:\n{err_add}"

        save_cmd = "sudo sh -c 'iptables-save > /etc/iptables/rules.v4'"
        err_save = execute_sudo(ssh, save_cmd, password)
        if err_save:
            return f"Rule added but failed to save permanently:\n{err_add}"

        return f"Rule added successfully:\n{rule_cmd}"
    finally:
        ssh.close()

def feedback_section(idx):
    feedback = st.selectbox(
        "Analyst Feedback:",
        options=["Select an Option", "True Positive", "True Negative", "False Positive", "False Negative"],
        key=f'feedback_tp_{idx}'
    )

    comment = st.text_area(
        "Analyst Comments:",
        key=f'comment_tp_{idx}'
    )
    return feedback, comment

def firewall_section(row, idx):
    fw_rule = ""
    firewall_rule_values = {}

    existing_rule, error = check_rule(row['source_ip'], row['destination_ip'])
    if error:
        st.error(error)

    existing_actions = set()
    if existing_rule:
        st.text("A firewall rule already exists:")
        header = "num pkts bytes target prot opt in out source destination"
        cols = header.split()
        values = existing_rule.split()
        df_rule = pd.DataFrame([values], columns=cols)
        st.dataframe(df_rule, use_container_width=True)

        if "ACCEPT" in existing_rule:
            existing_actions.add("Allow")
        if "DROP" in existing_rule:
            existing_actions.add("Drop")
        if "REJECT" in existing_rule:
            existing_actions.add("Reject")

    add_another_key = f'add_another_rule_{idx}'
    if add_another_key not in st.session_state:
        st.session_state[add_another_key] = False

    st.session_state[add_another_key] = st.checkbox(
        "Add firewall rule",
        value=st.session_state[add_another_key],
        key=f'add_chk_{idx}'
    )

    if st.session_state[add_another_key]:
        available_actions = [a for a in ["Allow", "Drop", "Reject"] if a not in existing_actions]
        if available_actions:
            firewall_action = st.radio(
                "Select firewall action to add:",
                options=available_actions,
                key=f'firewall_action_{idx}',
                horizontal=True
            )
            action_map = {"Allow": "ACCEPT", "Drop": "DROP", "Reject": "REJECT"}
            action = action_map[firewall_action]

            fw_rule = st.text_area(
                f"Firewall Rule for Incident {row['incident_id']}",
                value=f"iptables -I FORWARD 1 -s {row['source_ip']} -d {row['destination_ip']} -j {action}",
                key=f'fw_rule_{idx}'
            )

    firewall_rule_values[row['incident_id']] = fw_rule
    st.session_state[f'firewall_rules_{idx}'] = firewall_rule_values
    return fw_rule

def suricata_section(row, idx):
    rules_by_sid = load_active_suricata_rules()
    incident_sids_raw = row.get("rule_id_suri", [])
    initial_incident = row.get("initial_prediction").strip()

    source_ip = row.get("source_ip", "")
    destination_ip = row.get("destination_ip", "")
    suricata_rule = ""

    suricata_rule_values = {}

    if isinstance(incident_sids_raw, str):
        incident_sids = [int(sid.strip()) for sid in incident_sids_raw.split(",") if sid.strip()]
    elif isinstance(incident_sids_raw, (list, tuple, pd.Series)):
        incident_sids = [int(sid) for sid in incident_sids_raw]
    else:
        incident_sids = []


    if initial_incident == "False Negative":

        if rules_by_sid:
            new_sid = max(rules_by_sid.keys()) + 1
        else:
            new_sid = 10001

        st.markdown(f"**False Negative detected. Suggested SID for new rule: {new_sid}**")
        st.markdown("**Rule syntax template:**")
        st.code(f"alert tcp any any -> any any (msg:\"<your message>\"; sid:{new_sid}; rev:1;)",
                language="none")

        new_rule = st.text_area(
            f"Write Suricata Rule for False Negative :",
            value="",
            height=100,
            key=f'fn_rule_suricata_{idx}_{new_sid}'
        )

    else:
        for sid in incident_sids:
            if sid in rules_by_sid:
                rule_text = rules_by_sid[sid]

                if initial_incident == "True Positive":
                    st.markdown(f"**Suricata Rule for SID {sid}:**")
                    new_rule = rule_text
                    st.code(rule_text, language="none")


                elif initial_incident == "False Positive":
                    st.markdown(f"**Suricata Rule for SID {sid}:**")
                    st.code(rule_text, language="none")
                    st.markdown("**Suggested Suppression Rule:**")
                    suppress_rule = (
                        f"suppress gen_id 1, sig_id {sid}, track by_src, ip {source_ip}")
                    st.code(suppress_rule, language="none")
                    new_rule = suppress_rule



    suricata_rule_values[row['incident_id']] = new_rule
    st.session_state[f'suricata_rules_{idx}'] = suricata_rule_values
    return new_rule

def handle_submit(row, idx, conn, prediction_data, feedback, comment, fw_rule,new_rule, none,rule_action):
    if feedback != "Select an Option":
        prediction_data.loc[idx, 'analyst_feedback'] = feedback
        prediction_data.loc[idx, 'analyst_comments'] = comment
        prediction_data.loc[idx, 'Status'] = 'Completed'
        if "None" in rule_action:
         none=none

        firewall_rule = "N"
        firewall_rule_data = ""
        if "Add Firewall Rule" in rule_action and fw_rule:
            result = add_rule(fw_rule)
            st.text_area(f"Applied Firewall Rule for {row['incident_id']}", result)
            firewall_rule = "Y"
            firewall_rule_data = fw_rule

        suricata_rule_data = ""

        if "Add Suricata Rule" in rule_action and new_rule:

            initial_incident = str(row.get("initial_prediction", "")).strip().upper()

            if initial_incident == "FALSE NEGATIVE":
               
                result = add_suricata_rule(new_rule)
                st.text_area(f"Applied Suricata Alert Rule for {row['incident_id']}", result)
                suricata_rule_data = new_rule

            elif initial_incident == "FALSE POSITIVE":
                
                result = add_suppression_rule(new_rule)
                st.text_area(f"Applied Suricata Suppression Rule for {row['incident_id']}", result)
                suricata_rule_data = new_rule

            else: 
                suricata_rule_data = new_rule

        suricata_rule_Y_N = "Y" if suricata_rule_data else "N"

        save_feedback_to_db(
            incident_id=row['incident_id'],
            initial_prediction=str(row.get('initial_prediction')),
            prediction_reason=row.get('prediction_reason'),
            feedback=feedback,
            comment=comment,
            firewall_rule=firewall_rule,
            firewall_rule_data=firewall_rule_data,
            suricata_rule=suricata_rule_Y_N,
            suricata_rule_data=suricata_rule_data,
            prediction_confidence=row.get('prediction_confidence'),
            conn=conn
        )

        st.success(f"Feedback submitted for log {row['incident_id']}!")
    else:
        st.warning("Please select a feedback option before submitting.")


# ---- UI ----
def main():
    st.title("SOC Feedback Dashboard")

    tab1, tab2, tab3 = st.tabs(["Dashboard", "Feedback Outcome", "History"])
    history_data_display=history_data

    with tab1:

        
        history_data['timestamp'] = pd.to_datetime(
            history_data['timestamp'].astype(str),
            errors='coerce',
            infer_datetime_format=True
        )

        all_metrics = (
            history_data.groupby(history_data['timestamp'].dt.floor("D"))['analyst_feedback']
            .value_counts()
            .unstack(fill_value=0)  
            .reset_index()
            .rename(columns={"timestamp": "Date"})
        )

      
        for col in ["True Positive", "False Positive", "False Negative", "True Negative"]:
            if col not in all_metrics.columns:
                all_metrics[col] = 0

        all_metrics = all_metrics.sort_values("Date")

        start_date = all_metrics['Date'].min()
        end_date = pd.Timestamp.today().normalize()  # today
        full_dates = pd.date_range(start=start_date, end=end_date, freq='D')

        all_metrics = all_metrics.set_index('Date').reindex(full_dates, fill_value=0).rename_axis(
            'Date').reset_index()

        # ------------------- Plotting -------------------
        fig, ax = plt.subplots(figsize=(12, 5))

        
        fig.patch.set_facecolor('None')
        ax.patch.set_facecolor('None')

        # Plot each metric        
        ax.plot(all_metrics['Date'], all_metrics['True Positive'], color='#66ff66',label='True Positive')
        ax.plot(all_metrics['Date'], all_metrics['False Positive'], color='orange',label='False Positive')
        ax.plot(all_metrics['Date'], all_metrics['False Negative'], color='red',label='False Negative')

        # Title and labels
        ax.set_title('Predictions Over Time', fontsize=15, fontweight='bold', pad=20, color='white')
        ax.set_xlabel('Date', fontsize=10, labelpad=15, color='white')
        ax.set_ylabel('Count', fontsize=10, labelpad=15, color='white')

        y_max = max(
            all_metrics['True Positive'].max(),
            all_metrics['False Positive'].max(),
            all_metrics['False Negative'].max()
        )
        ax.set_ylim(0, y_max + 10)

        ax.legend(fontsize=12, facecolor='None', edgecolor='None', labelcolor='white',loc='upper right',bbox_to_anchor=(1, 1))
        ax.grid(True, which='both', linestyle='--', linewidth=0.5, color='gray')

       
        ax.tick_params(axis='x', colors='white')
        ax.tick_params(axis='y', colors='white')
        for spine in ax.spines.values():
            spine.set_color('white')

        ax.set_xlim(start_date, end_date)

        plt.tight_layout()

        st.pyplot(fig)



    with tab2:

        sub_tab_tp, sub_tab_fp, sub_tab_fn, sub_tab_tn = st.tabs(["True Positive", "False Positive", "False Negative", "True Negative"])
        prediction_data_outcome = calculate_feedback_outcome(prediction_data,history_data)
        tp_df = prediction_data_outcome[prediction_data_outcome['initial_prediction'] == 'True Positive']
        fp_df = prediction_data_outcome[prediction_data_outcome['initial_prediction'] == 'False Positive']
        fn_df = prediction_data_outcome[prediction_data_outcome['initial_prediction'] == 'False Negative']
        tn_df = prediction_data_outcome[prediction_data_outcome['initial_prediction'] == 'True Negative']

        confidence_order = ["High", "Medium", "Low"]

      
        tp_df['prediction_confidence'] = pd.Categorical(
            tp_df['prediction_confidence'], categories=confidence_order, ordered=True
        )
        fp_df['prediction_confidence'] = pd.Categorical(
            fp_df['prediction_confidence'], categories=confidence_order, ordered=True
        )
        fn_df['prediction_confidence'] = pd.Categorical(
            fn_df['prediction_confidence'], categories=confidence_order, ordered=True
        )
        tn_df['prediction_confidence'] = pd.Categorical(
            tn_df['prediction_confidence'], categories=confidence_order, ordered=True
        )

        # Sort by confidence first, then by timestamp
        tp_df = tp_df.sort_values(['prediction_confidence', 'timestamp'], ascending=[True, False])
        fp_df = fp_df.sort_values(['prediction_confidence', 'timestamp'], ascending=[True, False])
        fn_df = fn_df.sort_values(['prediction_confidence', 'timestamp'], ascending=[True, False])
        tn_df = tn_df.sort_values(['prediction_confidence', 'timestamp'], ascending=[True, False])


        # ---- True Positives ----
        with sub_tab_tp:
            st.subheader("True Positive Feedback")

            if not tp_df.empty:
                for idx, row in tp_df.iterrows():
                    summary = f"{row.get('incident_id')} - {row['rule_name_suri']} | **Prediction Confidence:** {row['prediction_confidence']}"
                    with st.expander(summary):
                        display_full_log_details(row)

                        
                        feedback, comment = feedback_section(idx)

                        rule_action = st.multiselect(
                            "Select actions to take for this incident:",
                            options=["None", "Add Firewall Rule", "Add Suricata Rule"],
                            default=[],
                            key=f'rule_action_tp_{idx}'
                        )
                        none = ""
                        if "None" in rule_action:
                            none= ""

                        fw_rule = ""
                        if "Add Firewall Rule" in rule_action:
                            fw_rule =firewall_section(row, idx)

                        suricata_rule= ""
                        if "Add Suricata Rule" in rule_action:
                            suricata_rule=suricata_section(row, idx)

                        
                        if st.button("Submit", key=f'submit_feedback_tp_{idx}'):
                            handle_submit(row, idx, conn, prediction_data, feedback, comment, fw_rule,suricata_rule,none, rule_action)
        # ---- False Positives ----
        with sub_tab_fp:
            st.subheader("False Positive Feedback")
            if not fp_df.empty:
                for idx, row in fp_df.iterrows():
                    summary = f"{row.get('incident_id')} - {row['rule_name_suri']} | **Prediction Confidence:** {row['prediction_confidence']}"
                    with st.expander(summary):
                        display_full_log_details(row)
                        
                        feedback, comment = feedback_section(idx)

                        rule_action = st.multiselect(
                            "Select actions to take for this incident:",
                            options=["None", "Add Firewall Rule", "Add Suricata Rule"],
                            default=[],
                            key=f'rule_action_tp_{idx}'
                        )
                        if "None" in rule_action:
                            none= ""

                        fw_rule = ""
                        if "Add Firewall Rule" in rule_action:
                            fw_rule = firewall_section(row, idx)

                        suricata_rule = ""
                        if "Add Suricata Rule" in rule_action:
                            suricata_rule=suricata_section(row, idx)

                        
                        if st.button("Submit", key=f'submit_feedback_tp_{idx}'):
                            handle_submit(row, idx, conn, prediction_data, feedback, comment, fw_rule,suricata_rule, none,rule_action)

        # ---- False Negatives ----
        with sub_tab_fn:
            st.subheader("False Negative Feedback")
            if not fn_df.empty:
                for idx, row in fn_df.iterrows():
                    summary = f"{row.get('incident_id')} - {row['rule_name_suri']} | **Prediction Confidence:** {row['prediction_confidence']}"
                    with st.expander(summary):
                        display_full_log_details(row)
                        
                        feedback, comment = feedback_section(idx)

                        rule_action = st.multiselect(
                            "Select actions to take for this incident:",
                            options=["None", "Add Firewall Rule", "Add Suricata Rule"],
                            default=[],
                            key=f'rule_action_tp_{idx}'
                        )

                        if "None" in rule_action:
                            none = ""

                        fw_rule = ""
                        if "Add Firewall Rule" in rule_action:
                            fw_rule = firewall_section(row, idx)

                        suricata_rule = ""
                        if "Add Suricata Rule" in rule_action:
                            suricata_rule=suricata_section(row, idx)

                        if st.button("Submit", key=f'submit_feedback_tp_{idx}'):
                            handle_submit(row, idx, conn, prediction_data, feedback, comment, fw_rule,suricata_rule,none, rule_action)

        # ---- True Negatives ----
        with sub_tab_tn:
            st.subheader("True Negative Feedback")
            if not tn_df.empty:
                for idx, row in tn_df.iterrows():
                    summary = f"{row.get('incident_id')} - {row['rule_name_suri']} | **Prediction Confidence:** {row['prediction_confidence']}"
                    with st.expander(summary):
                        display_full_log_details(row)
                        with st.form(key=f'feedback_form_tp_{idx}'):
                            
                            feedback, comment = feedback_section(idx)
                            fw_rule=""
                            suricata_rule=""
                            none=""

                            submitted = st.form_submit_button("Submit")
                            if submitted:
                                handle_submit(row, idx, conn, prediction_data, feedback, comment, fw_rule,suricata_rule,none, rule_action)


    with tab3:
        st.header("History")
        completed_logs = history_data_display[history_data_display['Status'] == 'Completed']

        search_query = st.text_input("Search completed logs:", help="Search across all columns.")

        if search_query:

            search_mask = completed_logs.astype(str).apply(
                lambda row: row.str.contains(search_query, case=False, na=False).any(), axis=1
            )
            filtered_logs = completed_logs[search_mask]
        else:
            filtered_logs = completed_logs

        if not filtered_logs.empty:
            st.subheader("Completed Logs:")
            for index, row in filtered_logs.iterrows():
                summary_line = (
                    f"**Status:** {row['Status']} | "
                    f"**Message:** {row.get('message_suri', 'N/A')} | "
                    f"**Analyst Feedback:** {row.get('analyst_feedback', 'N/A')}"
                )
                with st.expander(summary_line):
                    display_full_log_details(row)
                    st.markdown(f"**Analyst Feedback:** {row.get('analyst_feedback', 'N/A')}", unsafe_allow_html=True)
                    st.markdown(f"**Analyst Comments:** {row.get('analyst_comments', 'N/A')}", unsafe_allow_html=True)

        else:
            st.info("No completed logs found matching your search criteria.")


if __name__ == "__main__":

    main()
    if not st.session_state.db_conn_closed:
        conn.close()
        st.session_state.db_conn_closed = True
