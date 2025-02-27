# 🔍 Security Incident Report: Brute Force Attack Detected

## 📌 Summary  
On **All Time**, Splunk detected a **brute-force attack** targeting multiple user accounts. The attack originated from a suspicious IP address attempting  **failed login attempts** within a given time frame.  

## 🔹 Incident Details
- **Event IDs & Counts:**  
  - **4625** (Failed Logon Attempts) → 10 events  
  - **4624** (Successful Logins) → 208 events  
  - **4672** (Privilege Escalation) → 192 events  
  - **Top 5 Users with Most Failed Logins:** 10 events  
  - **Top 5 IP Addresses with Most Failed Logins:** 10 events  
  - **Brute-Force Attempts (More than 50 Failed Logins from Same IP):** 10 events  
  
- **Date & Time:** All Time  
- **Source IP:** `127.0.0.1`  
- **Targeted User(s):** VINAY_R$  
- **Event IDs:**  
  - **4625** (Failed Logon Attempts)  
  - **4624** (Successful Logins)  
  - **4672** (Privilege Escalation)  

## 🔍 Investigation Steps  
The following **Splunk queries** were used to identify suspicious activity:  

### 1️⃣ **Find Failed Logins (Event ID 4625 - Failed Login Attempt)**  
```spl
index=* source="windows security logs.csv" host="securitylogs" sourcetype="csv" "Event ID"=4625
```

### 2️⃣ **Find Successful Logins (Event ID 4624 - Successful Login Attempt)**  
```spl
index=* source="windows security logs.csv" host="securitylogs" sourcetype="csv" "Event ID"=4624
```

### 3️⃣ **Find Suspicious Admin Privilege Escalations (Event ID 4672 - Privilege Escalation)**  
```spl
index=* source="windows security logs.csv" host="securitylogs" sourcetype="csv" "Event ID"=4672
```

### 4️⃣ **Find the Top 5 Users with Most Failed Logins**  
```spl
index=* source="windows security logs.csv" host="securitylogs" sourcetype="csv" "Event ID"=4625 | stats count by "Account Name" | sort -count | head 5
```

### 5️⃣ **Find the Top 5 IP Addresses with Most Failed Logins**  
```spl
index=* source="windows security logs.csv" host="securitylogs" sourcetype="csv" "Event ID"=4625 | stats count by "Source IP Address" | sort -count | head 5
```

### 6️⃣ **Find Brute-Force Attempts (More than 50 Failed Logins from Same IP)**  
```spl
index=* source="windows security logs.csv" host="securitylogs" sourcetype="csv" "Event ID"=4625 | stats count by "Source IP Address" | where count > 50
```

