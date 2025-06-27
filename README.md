# Final_Project_Elevate_labs
# 🔍 Vulnerability Scanner

A simple and intuitive web-based vulnerability scanner built using Flask. This tool allows users to analyze websites for common security vulnerabilities by simply entering a URL and selecting specific checks.

## 🌐 Live Preview (Localhost)
Runs on: `http://127.0.0.1:5000`

---

## 🚀 Features

### ✅ Website Scanning Interface
- Clean UI with gradient header: **"Scan Your Website for Vulnerabilities"**
- Input field to enter a URL (e.g., `https://example.com`)
- Multiple **individual checks** for:
  - Open Ports
  - CSRF (Cross-Site Request Forgery)
  - Clickjacking
  - SQL Injection
  - Directory Traversal
  - SSL/TLS Security
  - CORS Misconfigurations
  - Host Header Injection
  - XSS (Cross-Site Scripting)

### 🔐 Brute Force Module
- A red button labeled **"Run Brute Force Attack"**
- Test for weak login credentials (used only on test environments for ethical hacking purposes)

---

## 📊 Scan Results

Example result shown for: `http://www.testfire.net`

| Vulnerability             | Status                                                                 |
|--------------------------|------------------------------------------------------------------------|
| **Open Ports**           | Port 80, 443, and 8080 are open                                        |
| **CSRF**                 | Potential CSRF in `/search.jsp` form                                   |
| **SSL/TLS**              | Certificate Error: Hostname mismatch                                   |
| **Clickjacking**         | X-Frame-Options header missing (Clickjacking possible)                 |

---

## 🛠️ Technologies Used
- Python (Flask)
- HTML/CSS + Bootstrap for styling
- Socket/requests for scanning logic
- Security modules (like `ssl`, `socket`, `requests`, `nmap`, etc.)

---

## ⚠️ Disclaimer
This tool is intended for **educational and ethical hacking purposes only**. Use it **only on websites you own or have explicit permission to test**. Unauthorized scanning may be illegal.

---

## 📸 Screenshots

### 🔎 Home Scanner UI
![Scanner UI](./screenshots/1png)

### 📋 Results Section
![Results Page](./screenshots/2.png)

---

## 📂 Project Structure
