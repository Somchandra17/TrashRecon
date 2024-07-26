from flask import Flask, render_template, request, redirect, url_for, send_from_directory, Response
import os
import subprocess
import shutil
import threading
import json
import zipfile

app = Flask(__name__)

# Constants
RESOLVERS_PATH = os.path.expanduser("~/.config/puredns/resolvers.txt")
WORDLIST_PATH = os.path.expanduser("~/app/subdomains-top1million-110000.txt")
TOOLS = ["puredns", "httpx", "dnsx", "smap", "aquatone", "waybackurls", "gf", "massdns", "subzy", "waymore", "assetfinder", "subfinder", "amass", "katana"]

status_updates = []

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

def clear_past_folders():
    trashrecon_path = os.path.expanduser("~/TrashRecon")
    if os.path.exists(trashrecon_path):
        shutil.rmtree(trashrecon_path)
    os.makedirs(trashrecon_path, exist_ok=True)

def run_command(command, cwd=None):
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd)
    stdout, stderr = process.communicate()
    if process.returncode != 0:
        return f"Error executing command: {command}\n{stderr.decode()}"
    return stdout.decode()

def update_status(phase, status, output=None, tree=None):
    status_updates.append({
        "id": f"{phase}-status",
        "status": status,
        "output": output,
        "tree": tree
    })

def generate_tree(path, prefix=""):
    tree = []
    for root, dirs, files in os.walk(path):
        level = root.replace(path, '').count(os.sep)
        indent = ' ' * 4 * (level)
        tree.append(f"{prefix}{indent}{os.path.basename(root)}/")
        sub_indent = ' ' * 4 * (level + 1)
        for f in files:
            tree.append(f"{prefix}{sub_indent}{f}")
    return "\n".join(tree)

def phase_one(domain_path, domain):
    update_status("phase1", "Running")
    message = "Starting Phase 1: Subdomain Enumeration."

    domain_parts = domain.split('.')
    base_domain = domain_parts[0]
    tld = '.'.join(domain_parts[1:])  

    run_command(f"puredns bruteforce {WORDLIST_PATH} {domain} > {os.path.join(domain_path, 'puredns.txt')}", cwd=domain_path)
    run_command(f"subfinder -nc -silent -d {domain} > {os.path.join(domain_path, 'subfinder.txt')}", cwd=domain_path)
    run_command(f"amass enum -nocolor -d {domain} > {os.path.join(domain_path, 'amass.txt')}", cwd=domain_path)
    run_command(f"assetfinder -subs-only {domain} > {os.path.join(domain_path, 'assetfinder.txt')}", cwd=domain_path)
    run_command(f"waybackurls {domain} > {os.path.join(domain_path, 'wayback.txt')}", cwd=domain_path)
    run_command(f"waymore -i {domain} -mode U -oU {os.path.join(domain_path, 'waymore.txt')}", cwd=domain_path)

    run_command(f"cat {os.path.join(domain_path, 'wayback.txt')} {os.path.join(domain_path, 'waymore.txt')} > {os.path.join(domain_path, 'merged_way.txt')}", cwd=domain_path)
    run_command(f"cat {os.path.join(domain_path, 'merged_way.txt')} | sed 's/{base_domain}.*$/{tld}/' | sed 's/https:\/\///' | sed 's/http:\/\///' | sort -u | uniq > {os.path.join(domain_path, 'way_domains.txt')}", cwd=domain_path)
    run_command(f"cat {os.path.join(domain_path, 'puredns.txt')} {os.path.join(domain_path, 'subfinder.txt')} {os.path.join(domain_path, 'amass.txt')} {os.path.join(domain_path, 'assetfinder.txt')} {os.path.join(domain_path, 'way_domains.txt')} | sort -u | uniq > {os.path.join(domain_path, 'raw.txt')}", cwd=domain_path)
    run_command(f"cat {os.path.join(domain_path, 'raw.txt')} | grep {domain} > {os.path.join(domain_path, 'final_subdomains.txt')}", cwd=domain_path)
    run_command(f"cat {os.path.join(domain_path, 'final_subdomains.txt')} | httpx -mc 200,301,302,307,308 | sed 's/https:\/\///' | sort -u | tee {os.path.join(domain_path, 'workingdomains.txt')}", cwd=domain_path)

    update_status("phase1", "Completed", generate_tree(domain_path))

def phase_two(domain_path):
    update_status("phase2", "Running")
    run_command(f"cat {os.path.join(domain_path, 'workingdomains.txt')} | dnsx -a -resp -nc | sort -u | tee {os.path.join(domain_path, 'a_records.txt')}", cwd=domain_path)
    run_command(f"cat {os.path.join(domain_path, 'workingdomains.txt')} | dnsx -silent -cname -resp -nc | tee {os.path.join(domain_path, 'cname.txt')}", cwd=domain_path)
    run_command(f"cat {os.path.join(domain_path, 'workingdomains.txt')} | dnsx -a -ro -nc | sort -u | tee {os.path.join(domain_path, 'IPs.txt')}", cwd=domain_path)
    update_status("phase2", "Completed", generate_tree(domain_path))

def phase_three(domain_path, domain):
    update_status("phase3", "Running")
    smap_output = os.path.join(domain_path, "port_scan.json")
    run_command(f"smap -Pn -p0-65535 -iL {os.path.join(domain_path, 'IPs.txt')} -oJ {smap_output}", cwd=domain_path)
    update_status("phase3", "Completed", generate_tree(domain_path))

def phase_four(domain_path, domain):
    update_status("phase4", "Running")
    aquatone_folder = os.path.join(domain_path, "aquatone")
    run_command(f"cat {os.path.join(domain_path, 'workingdomains.txt')} | aquatone -chrome-path /usr/bin/chromium -out {aquatone_folder}", cwd=domain_path)
    update_status("phase4", "Completed", generate_tree(domain_path))

def phase_five(domain_path, domain):
    update_status("phase5", "Running")
    message = "Starting Phase 7: GF Enumeration."

    gf_folder = os.path.join(domain_path, "GF")
    os.makedirs(gf_folder, exist_ok=True)
    gf_patterns = ["xss", "idor", "lfi", "debug_logic", "img-traversal", "interestingEXT", "interestingparams", "interestingsubs", "jsvar", "rce", "redirect", "sqli", "ssrf", "ssti"]
    
    run_command(f"cat {os.path.join(domain_path, 'merged_way.txt')} {os.path.join(domain_path, 'endpoints.txt')} | sort -u | uniq | tee {os.path.join(domain_path, 'merged_endpoints.txt')}", cwd=domain_path)
    
    for pattern in gf_patterns:
        output_file = os.path.join(gf_folder, f"{pattern}.txt")
        run_command(f"cat {os.path.join(domain_path, 'merged_endpoints.txt')} | gf {pattern} | sort -u | tee {output_file}", cwd=domain_path)
    
    update_status("phase5", "Completed", generate_tree(domain_path))

def phase_six(domain_path, domain):
    update_status("phase6", "Running")
    message = "Starting Phase 5: Checking for Subdomains Takeover(subzy)."
    subzy_output = os.path.join(domain_path, "subdomains_takeover.txt")
    run_command(f"subzy run --targets {os.path.join(domain_path, 'workingdomains.txt')} > {subzy_output}", cwd=domain_path)
    update_status("phase6", "Completed", generate_tree(domain_path))

def phase_seven(domain_path, domain):
    update_status("phase7", "Running")
    message = "Starting Phase 7: Crawling Endpoints."
    katana_output = os.path.join(domain_path, "endpoints.txt")
    run_command(f"katana -u {os.path.join(domain_path, 'workingdomains.txt')} -d 5 -jsl -jc -o {katana_output}", cwd=domain_path)
    update_status("phase7", "Completed", generate_tree(domain_path))

def phase_eight(domain_path, domain):
    update_status("phase8", "Running")
    message = "Starting Phase 8: Looking for exposed API keys."
    secretx_output = os.path.join(domain_path, "api.txt")
    run_command(f"python3 secretx.py --list {os.path.join(domain_path, 'endpoints.txt')} --threads 60 --output {secretx_output}", cwd="/app/secretx/")
    update_status("phase8", "Completed", generate_tree(domain_path))

def summarize_results(domain_path):
    puredns_output = os.path.join(domain_path, "final_subdomains.txt")
    working_domains = os.path.join(domain_path, "workingdomains.txt")
    try:
        with open(puredns_output, 'r') as file:
            subdomains_count = len(file.readlines())
        with open(working_domains, 'r') as file:
            working_domains_count = len(file.readlines())
    except FileNotFoundError:
        subdomains_count = 0
        working_domains_count = 0
    update_status("summary", "Completed", f"Total number of subdomains found: {subdomains_count}\nTotal number of working domains: {working_domains_count}")

def run_recon(domain):
    domain_path = create_domain_folder(domain)
    phase_one(domain_path, domain)
    phase_two(domain_path)
    phase_three(domain_path, domain)
    phase_four(domain_path, domain)
    phase_six(domain_path, domain)
    phase_seven(domain_path, domain)
    phase_five(domain_path, domain)
    phase_eight(domain_path, domain)
    summarize_results(domain_path)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start', methods=['POST'])
def start():
    domain = request.form['domain']
    if not domain:
        return redirect(url_for('index'))
    
    clear_past_folders()
    error = check_prerequisites()
    if error:
         return error
    
    threading.Thread(target=run_recon, args=(domain,)).start()
    return redirect(url_for('status', domain=domain))

@app.route('/status')
def status():
    return render_template('status.html')

@app.route('/stream')
def stream():
    def event_stream():
        while True:
            if status_updates:
                data = status_updates.pop(0)
                yield f"data: {json.dumps(data)}\n\n"
    return Response(event_stream(), mimetype="text/event-stream")

@app.route('/download/<domain>')
def download(domain):
    domain_path = os.path.expanduser(f"~/TrashRecon/{domain}")
    zip_path = os.path.expanduser(f"~/TrashRecon/{domain}.zip")
    
    with zipfile.ZipFile(zip_path, 'w') as zipf:
        for root, dirs, files in os.walk(domain_path):
            for file in files:
                zipf.write(os.path.join(root, file), os.path.relpath(os.path.join(root, file), domain_path))
    
    return send_from_directory(directory=os.path.dirname(zip_path), path=os.path.basename(zip_path), as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')