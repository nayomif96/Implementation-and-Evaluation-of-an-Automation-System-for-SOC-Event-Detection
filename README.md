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

### System Design  
![System Design](https://github.com/nayomif96/Implementation-and-Evaluation-of-an-Automation-System-for-SOC-Event-Detection/tree/ae81fabe3f1850d0b61495d907a292497e63ed90/images) 

- Suricata monitors traffic & generates alerts.  
- Filebeat & Winlogbeat forward logs to Elasticsearch.  
- MISP enriches events with Indicators of Compromise (IOCs).  
- MySQL stores correlation and feedback data.  
- Python correlation engine classifies events.  
- Streamlit dashboard provides analyst feedback & mitigation actions.  

### Network Topology  
![Network Topology](images/network_topology.png)  

- **Internal VLAN:** Windows VM, Ubuntu Server, SIEM VM, MISP VM.  
- **External VLAN:** Kali Linux attacker VM.  
- **Router VM:** Routes and isolates traffic, enforces NAT and firewall rules.  

---

## ⚙️ Implementation  

### Component Integration  
![Integration](images/integration.png)  

1. **Suricata IDS** → inspects traffic, generates alerts.  
2. **Filebeat/Winlogbeat** → forwards logs to Elasticsearch.  
3. **Elasticsearch** → indexes logs, supports queries.  
4. **Kibana** → visual dashboards for analysts.  
5. **MISP** → enriches alerts with threat intel (IPs/domains/hashes).  
6. **Python Scripts** →  
   - Correlate Suricata, syslog, FTP, auth, and Windows logs.  
   - Classify alerts (TP/TN/FP/FN).  
   - Store results in MySQL.  
   - Provide feedback loop for analyst corrections.  
7. **Streamlit Dashboard** →  
   - Displays alert details & context.  
   - Allows analyst validation (TP/FP/FN/TN).  
   - Enables mitigation actions (update firewall rules, Suricata rules).  

---

## 🧪 Testing Phase  

Testing included simulated **normal traffic** and **attack scenarios**:  

| Test Case | Input | Expected Result | Actual Result | Status |
|-----------|-------|-----------------|---------------|--------|
| TC1 | Nmap Port Scan | Alert → TP | Detected correctly | ✅ |
| TC2 | Normal HTTP browsing | No alert → TN | Correctly ignored | ✅ |
| TC3 | Benign misclassified | Alert → FP | Flagged as FP | ✅ |
| TC4 | Custom payload attack | Alert → TP | Detected correctly | ✅ |
| TC5 | Low-signature stealth attack | Missed → FN | Recorded FN | ✅ |

---

## 📊 Results  

### Prediction Accuracy  
![Accuracy](images/results_accuracy.png)  

- **Overall Accuracy:** 92%  
- **Precision:** 90%  
- **Recall:** 89%  
- **Improvement:** Noticeable reduction in **false positives** compared to baseline Suricata rules.  

### Analyst Dashboard  
![Dashboard](images/dashboard.png)
