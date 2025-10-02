# 🛡️ Implementation and Evaluation of an Automation System for SOC Event Detection  

An **adaptive Intrusion Detection System (IDS)** project that integrates **Suricata, ELK Stack (Elasticsearch, Logstash, Kibana), Filebeat/Winlogbeat, MISP, MySQL, and Python** to reduce false positives in Security Operations Centers (SOCs) through **log correlation and analyst feedback**.  

This project simulates **real-world SOC workflows**, where analysts classify alerts, enrich them with threat intelligence, and tune detection rules to improve accuracy and reduce noise.  

---

## 🔍 Overview  

Security Operations Centers are overwhelmed by thousands of alerts daily. Traditional IDS and SIEM systems generate **high false positive rates**, leading to alert fatigue, slower response, and missed threats.  

This project solves that challenge by:  
- Collecting and correlating logs from multiple sources (Suricata, system logs, authentication logs, FTP logs, Windows logs).  
- Enriching alerts with **MISP threat intelligence**.  
- Classifying events using **True Positive (TP), True Negative (TN), False Positive (FP), False Negative (FN)**.  
- Providing an **analyst dashboard (Streamlit)** for reviewing and validating alerts.  
- Incorporating **feedback loops** to adapt Suricata rules and firewall policies.  

📊 *Result: Achieved 92% prediction accuracy in classification, with reduced false positives.*  

---

## 💻 Hardware & Software Requirements  

### Hardware (Lab Setup)  
- **Virtualization:** Oracle VirtualBox  
- **VMs:**  
  - Router VM  
  - Ubuntu Server 24 (SIEM, Filebeat)  
  - Ubuntu Server 22 (MISP)  
  - Windows 10 VM (endpoint)  
  - Kali Linux VM (attacker)  
- **Resources:**  
  - CPU: 4–6 cores  
  - RAM: 16 GB  
  - Storage: 80–100 GB   

### Software  
- **OS:** Windows 10, Ubuntu 22/24, Kali Linux  
- **IDS:** Suricata  
- **SIEM:** Elasticsearch 9.0.3, Kibana 9.0.3  
- **Log Shippers:** Filebeat 9.0.4, Winlogbeat  
- **Threat Intelligence:** MISP  
- **Database:** MySQL  
- **Programming:** Python 3.10+, Streamlit, Pandas, Matplotlib  

---

## 🏗️ Design Phase  

### Network Topology  

![Network Topology](https://github.com/nayomif96/Implementation-and-Evaluation-of-an-Automation-System-for-SOC-Event-Detection/blob/main/images/net_dig.png)  

- **Internal VLAN:** Windows VM, Ubuntu Server, SIEM VM, MISP VM.  
- **External VLAN:** Kali Linux attacker VM.  
- **Router VM:** Routes and isolates traffic, enforces NAT and firewall rules.  

---

## ⚙️ Implementation  

### Component Integration  

![Integration](https://github.com/nayomif96/Implementation-and-Evaluation-of-an-Automation-System-for-SOC-Event-Detection/blob/main/images/flow%20dig.jpeg)  

1. **Suricata IDS** → inspects traffic, generates alerts.  
2. **Filebeat/Winlogbeat** → forwards logs to Elasticsearch.  
3. **Elasticsearch** → indexes logs, supports queries.  
4. **Kibana** → visual dashboards for analysts.  
5. **MISP** → enriches alerts with threat intel (IPs/domains/hashes).  
6. **Python Scripts** →  
   - Correlate Suricata, syslog, FTP, auth, and Windows logs.
   - Classify alerts (TP/TN/FP/FN)
     
   ![Classify alerts (TP/TN/FP/FN).](https://github.com/nayomif96/Implementation-and-Evaluation-of-an-Automation-System-for-SOC-Event-Detection/blob/main/images/prediction.png)

    Events from multiple sources are collected, and each alert is classified as a True Positive, True Negative, False Positive, or False      Negative. The process considers whether Suricata detected the event, checks for known Indicators of Compromise (IOCs), and incorporates historical analyst feedback from similar events.
   
   ![Classifiy](https://github.com/nayomif96/Implementation-and-Evaluation-of-an-Automation-System-for-SOC-Event-Detection/blob/main/images/log_check_criteria.png)
   ![Classif](https://github.com/nayomif96/Implementation-and-Evaluation-of-an-Automation-System-for-SOC-Event-Detection/blob/main/images/log_check_prdiction.png)
   Each event is further verified using FTP, authentication, and syslog data to refine its classification. FTP logs are checked for repeated failed logins, logins from unusual locations, or abnormal file transfers. Authentication records are reviewed for excessive failed attempts or unexpected successful logins. Syslog entries are analysed for network events like BLOCK, DROP, and ACCEPT, with attention to sudden spikes from the same IP. These checks help confirm whether an alert is a true incident (True Positive), a false alert (False Positive), a missed detection (False Negative), or normal activity (True Negative).
   
   - Store results in MySQL.  
   - Provide feedback loop for analyst corrections.  
8. **Streamlit Dashboard** →  
   - Displays alert details & context.  
   - Allows analyst validation (TP/FP/FN/TN).  
   - Enables mitigation actions (update firewall rules, Suricata rules).  

---

## 🧪 Testing Phase  

The system was evaluated against multiple scenarios to simulate real SOC workloads. Tests included **True Positive (malicious traffic detected)**, **False Negative (missed attacks)**, and **False Positive (benign activity flagged as malicious)** cases.  

---

### ✅ True Positive Scenarios  

| Activity | Source → Target | Description | Source IP Address |
|----------|-----------------|-------------|-------------------|
| SSH brute force | Kali → Ubuntu | Repeated login attempts on SSH to test brute force detection | 192.168.100.228, 192.168.100.150 |
| FTP brute force | Kali → Ubuntu | Repeated login attempts on FTP to trigger brute force alerts | 192.168.100.248, 192.168.100.138 |
| Nmap scan | Kali → Ubuntu | TCP SYN scan on ports 21 and 22 to simulate reconnaissance | 192.168.100.128 |
| Malicious download | Windows → Ubuntu | Access to a known malicious URL to trigger a download-related alert | 192.168.200.12 |

---

### ❌ False Negative Scenarios  

| Activity | Source → Target | Description | Source IP Address |
|----------|-----------------|-------------|-------------------|
| Slow SSH brute force | Kali → Ubuntu | Brute force at very low rate (1 attempt/minute) to test evasion | 192.168.100.223, 192.168.100.233 |
| Encrypted SSH payload | Kali → Ubuntu | Malicious SSH packets with encryption to test detection evasion | 192.168.100.100 |

---

### ⚠️ False Positive Scenarios  

| Activity | Source → Target | Description | Source IP Address |
|----------|-----------------|-------------|-------------------|
| Large FTP transfer | Windows → Ubuntu | Upload of a large file (>1KB) to FTP server | 192.168.200.12 |
| Multiple SSH sessions | Windows → Ubuntu | Multiple concurrent SSH sessions (benign heavy activity) | 192.168.200.12 |
| Continuous SSH data transfer | Windows → Ubuntu | Large file transfer via SCP | 192.168.200.12 |
| ICMP flood | Windows → Ubuntu | Continuous ping to simulate stress (non-malicious) | 192.168.200.12 |
| Multiple SSH login failures | Windows → Ubuntu | Repeated failed login attempts from legitimate testing | 192.168.200.12 |
| File transfer via SCP | Windows → Ubuntu | Large file transfer from Windows to Ubuntu | 192.168.200.12 |
| DNS lookup | Windows → Ubuntu | Query for non-existent domain to test alert response | 192.168.200.12 |


---

## 📊 Results  

### Prediction Accuracy  
![Accuracy]([images/results_accuracy.png](https://github.com/nayomif96/Implementation-and-Evaluation-of-an-Automation-System-for-SOC-Event-Detection/blob/main/images/result.png)  

- **Overall Accuracy:** 92%  
- **Precision:** 90%  
- **Recall:** 89%  
- **Improvement:** Noticeable reduction in **false positives** compared to baseline Suricata rules.  


