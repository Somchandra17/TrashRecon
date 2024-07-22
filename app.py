from flask import Flask, render_template, request, redirect, url_for, send_from_directory
import os
import subprocess
import shutil
import threading

app = Flask(__name__)

# Constants
RESOLVERS_PATH = os.path.expanduser("~/.config/puredns/resolvers.txt")
WORDLIST_PATH = "/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt"
TOOLS = ["puredns", "httpx", "dnsx", "smap", "aquatone", "waybackurls", "gf"]

def check_prerequisites():
    missing_tools = [tool for tool in TOOLS if not shutil.which(tool)]
    if missing_tools:
        return f"Missing tools: {', '.join(missing_tools)}. Please install them and add to PATH."
    
    if not os.path.exists(RESOLVERS_PATH):
        shutil.copy("resolvers.txt", RESOLVERS_PATH)
    
    if not os.path.exists(WORDLIST_PATH):
        shutil.copy("subdomains-top1million-110000.txt", WORDLIST_PATH)
    
    return None

def create_domain_folder(domain):
    domain_path = os.path.expanduser(f"~/TrashRecon/{domain}")
    os.makedirs(domain_path, exist_ok=True)
    return domain_path

def run_command(command, cwd=None):
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd)
    stdout, stderr = process.communicate()
    if process.returncode != 0:
        return f"Error executing command: {command}\n{stderr.decode()}"
    return stdout.decode()

def phase_one(domain_path, domain):
    puredns_output = os.path.join(domain_path, "puredns.txt")
    run_command(f"puredns bruteforce {WORDLIST_PATH} {domain} > {puredns_output}", cwd=domain_path)
    
    working_domains = os.path.join(domain_path, "workingdomains.txt")
    run_command(f"cat {puredns_output} | httpx -mc 200,301,302,307,308 | sed 's/https:\/\///' | sort -u > {working_domains}", cwd=domain_path)

def phase_two(domain_path):
    run_command(f"cat workingdomains.txt | dnsx -a -resp -nc | sort -u > a_records.txt", cwd=domain_path)
    run_command(f"cat workingdomains.txt | dnsx -silent -cname -resp -nc > cname.txt", cwd=domain_path)
    run_command(f"cat workingdomains.txt | dnsx -a -ro -nc | sort -u > IPs.txt", cwd=domain_path)

def phase_three(domain_path, domain):
    smap_output = os.path.join(domain_path, "smap.json")
    run_command(f"smap -Pn -p0-65535 -iL IPs.txt -oJ {smap_output}", cwd=domain_path)

def phase_four(domain_path, domain):
    aquatone_folder = os.path.join(domain_path, "aquatone")
    run_command(f"cat workingdomains.txt | aquatone -chrome-path /snap/bin/chromium -out {aquatone_folder}", cwd=domain_path)

def additional_phases(domain_path, domain):
    waybackurls_folder = os.path.join(domain_path, "waybackurls")
    os.makedirs(waybackurls_folder, exist_ok=True)
    waybackurls_output = os.path.join(waybackurls_folder, "waybackurls.txt")
    run_command(f"waybackurls {domain} > {waybackurls_output}", cwd=waybackurls_folder)
    
    gf_patterns = ["xss", "idor", "lfi", "debug_logic", "img-traversal", "interestingEXT", "interestingparams", "interestingsubs", "jsvar", "rce", "redirect", "sqli", "ssrf", "ssti"]
    for pattern in gf_patterns:
        output_file = os.path.join(waybackurls_folder, f"{pattern}.txt")
        run_command(f"cat {waybackurls_output} | gf {pattern} | sort -u > {output_file}", cwd=waybackurls_folder)

def run_recon(domain):
    domain_path = create_domain_folder(domain)
    phase_one(domain_path, domain)
    phase_two(domain_path)
    phase_three(domain_path, domain)
    phase_four(domain_path, domain)
    additional_phases(domain_path, domain)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start', methods=['POST'])
def start():
    domain = request.form['domain']
    error = check_prerequisites()
    if error:
        return error
    
    threading.Thread(target=run_recon, args=(domain,)).start()
    return redirect(url_for('status'))

@app.route('/status')
def status():
    return render_template('status.html')

@app.route('/download/<domain>')
def download(domain):
    domain_path = os.path.expanduser(f"~/TrashRecon/{domain}")
    return send_from_directory(directory=domain_path, filename='', as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)