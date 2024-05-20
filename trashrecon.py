import sys
import os
import subprocess
import shutil
import threading
import time

# Constants
RESOLVERS_PATH = os.path.expanduser("~/.config/puredns/resolvers.txt")
WORDLIST_PATH = os.path.expanduser("~/app/subdomains-top1million-110000.txt")
TOOLS = ["puredns", "httpx", "dnsx", "smap", "aquatone", "waybackurls", "gf", "massdns", "subzy", "waymore", "assetfinder", "subfinder", "amass"]

def create_domain_folder(domain):
    domain_path = os.path.expanduser(f"~/TrashRecon/{domain}")
    os.makedirs(domain_path, exist_ok=True)
    return domain_path

def run_command(command, cwd=None):
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd)
    stdout, stderr = process.communicate()
    if process.returncode != 0:
        print(f"Error executing command: {command}\n{stderr.decode()}")
        exit(1)
    print(stdout.decode())  # directly to the console

def phase_one(domain_path, domain):
    message = "Starting Phase 1: Subdomain Enumeration."
    run_command(f'cowsay "{message}"')

    domain_parts = domain.split('.')
    base_domain = domain_parts[0]
    tld = '.'.join(domain_parts[1:])  

    # Running various subdomain discovery tools
    run_command(f"puredns bruteforce {WORDLIST_PATH} {domain} > {os.path.join(domain_path, 'puredns.txt')}", cwd=domain_path)
    print("Done with puredns.")
    run_command(f"subfinder -nc -silent -d {domain} > {os.path.join(domain_path, 'subfinder.txt')}", cwd=domain_path)
    print("Done with subfinder.")
    run_command(f"amass enum -nocolor -d {domain} > {os.path.join(domain_path, 'amass.txt')}", cwd=domain_path)
    print("Done with amass.")
    run_command(f"assetfinder -subs-only {domain} > {os.path.join(domain_path, 'assetfinder.txt')}", cwd=domain_path)
    print("Done with assetfinder.")
    run_command(f"waybackurls {domain} > {os.path.join(domain_path, 'wayback.txt')}", cwd=domain_path)
    print("Done with waybackurls.")
    run_command(f"waymore -i {domain} -mode U -oU {os.path.join(domain_path, 'waymore.txt')}", cwd=domain_path)
    print("Done with waymore.")

    # Merging wayback and waymore outputs
    run_command(f"cat {os.path.join(domain_path, 'wayback.txt')} {os.path.join(domain_path, 'waymore.txt')} > {os.path.join(domain_path, 'merged_way.txt')}", cwd=domain_path)
    print("Done merging wayback and waymore outputs.")
    # Extracting unique domains from merged file
    run_command(f"cat {os.path.join(domain_path, 'merged_way.txt')} | sed 's/{base_domain}.*$/{tld}/' | sed 's/https:\/\///' | sed 's/http:\/\///' | sort -u | uniq > {os.path.join(domain_path, 'way_domains.txt')}", cwd=domain_path)
    print("Done extracting unique domains from merged file.")
    # Combining all subdomains into one file and filtering unique entries
    run_command(f"cat {os.path.join(domain_path, 'puredns.txt')} {os.path.join(domain_path, 'subfinder.txt')} {os.path.join(domain_path, 'amass.txt')} {os.path.join(domain_path, 'assetfinder.txt')} {os.path.join(domain_path, 'way_domains.txt')} | sort -u | uniq > {os.path.join(domain_path, 'final_subdomains.txt')}", cwd=domain_path)
    print("Done combining all subdomains into one file and filtering unique entries.")
    # Running httpx on the final list of subdomains
    run_command(f"cat {os.path.join(domain_path, 'final_subdomains.txt')} | httpx -mc 200,301,302,307,308 | sed 's/https:\/\///' | sort -u > {os.path.join(domain_path, 'workingdomains.txt')}", cwd=domain_path)
    print("Done running httpx on the final list of subdomains.")

def phase_five(domain_path, domain):
    message = "Starting Phase 5: GF Enumeration."
    run_command(f'cowsay "{message}"')

    gf_folder = os.path.join(domain_path, "GF")
    os.makedirs(gf_folder, exist_ok=True)
    gf_patterns = ["xss", "idor", "lfi", "debug_logic", "img-traversal", "interestingEXT", "interestingparams", "interestingsubs", "jsvar", "rce", "redirect", "sqli", "ssrf", "ssti"]
    for pattern in gf_patterns:
        output_file = os.path.join(gf_folder, f"{pattern}.txt")
        run_command(f"cat {os.path.join(domain_path, 'merged_way.txt')} | gf {pattern} | sort -u > {output_file}", cwd=domain_path)

def phase_two(domain_path):
    message = "Starting Phase 2: Extracting A and CNAME Records."
    run_command(f'cowsay "{message}"')
    run_command(f"cat {os.path.join(domain_path, 'workingdomains.txt')} | dnsx -a -resp -nc | sort -u > {os.path.join(domain_path, 'a_records.txt')}", cwd=domain_path)
    run_command(f"cat {os.path.join(domain_path, 'workingdomains.txt')} | dnsx -silent -cname -resp -nc > {os.path.join(domain_path, 'cname.txt')}", cwd=domain_path)
    run_command(f"cat {os.path.join(domain_path, 'workingdomains.txt')} | dnsx -a -ro -nc | sort -u > {os.path.join(domain_path, 'IPs.txt')}", cwd=domain_path)

def phase_three(domain_path, domain):
    message = "Starting Phase 3: Port Scanning."
    run_command(f'cowsay "{message}"')
    smap_output = os.path.join(domain_path, "smap.json")
    run_command(f"smap -Pn -p0-65535 -iL {os.path.join(domain_path, 'IPs.txt')} -oJ {smap_output}", cwd=domain_path)

def phase_four(domain_path, domain):
    message = "Starting Phase 4: Taking Screenshots."
    run_command(f'cowsay "{message}"')
    aquatone_folder = os.path.join(domain_path, "aquatone")
    run_command(f"cat {os.path.join(domain_path, 'workingdomains.txt')} | aquatone -chrome-path /usr/bin/chromium -out {aquatone_folder}", cwd=domain_path)

def phase_six(domain_path, domain):
    message = "Starting Phase 6: Checking for Subdomains Takeover(subzy)."
    run_command(f'cowsay "{message}"')
    subzy_output = os.path.join(domain_path, "subdomains_takeover.txt")
    run_command(f"subzy run --targets {os.path.join(domain_path, 'workingdomains.txt')} > {subzy_output}", cwd=domain_path)

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
    print(f"Total number of subdomains found: {subdomains_count}")
    print(f"Total number of working domains: {working_domains_count}")

def animate():
    sys.stdout.write('\rStarting recon process... please wait.')
    chars = "|/-\\"
    i = 0
    while done == 'false':
        sys.stdout.write('\rNot Stuck ' + chars[i])
        sys.stdout.flush()
        time.sleep(0.1)
        i = (i + 1) % len(chars)
    sys.stdout.write('\rDone!  :)     \n')

def main():
    global done
    print("""

  ______                              ____                              
    /                       /         /    )                            
---/------)__----__---__---/__-------/___ /----__----__----__----__-----
  /      /   ) /   ) (_ ` /   )     /    |   /___) /   ' /   ) /   )    
_/______/_____(___(_(__)_/___/_____/_____|__(___ _(___ _(___/_/___/_____
            Tools: puredns, httpx, dnsx, smap, aquatone, waybackurls, gf,
                   massdns, subzy, waymore, assetfinder, subfinder, amass
          

    """)
    domain = input("Enter the domain name: ")
    domain_path = create_domain_folder(domain)

    done = 'false'
    animation_thread = threading.Thread(target=animate)
    animation_thread.start()

    phase_one(domain_path, domain)
    phase_two(domain_path)
    phase_three(domain_path, domain)
    phase_four(domain_path, domain)
    phase_five(domain_path, domain)
    phase_six(domain_path, domain)
    
    summarize_results(domain_path)
    print(f"TrashRecon is terminated. Results stored in {domain_path}")

    done = 'true'
    animation_thread.join()

if __name__ == "__main__":
    main()