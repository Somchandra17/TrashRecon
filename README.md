# TrashRecon

TrashRecon is a comprehensive Python-based reconnaissance framework designed for security researchers and penetration testers. It automates various phases of the information gathering process, enhancing the efficiency and depth of security assessments.

## Features

- Subdomain Enumeration: Utilizes tools like puredns, subfinder, amass, assetfinder, waybackurls, and waymore to discover subdomains.
- HTTP Status Check and Sorting: Uses httpx to check the availability and status of discovered domains.
- DNS Record Extraction: Extracts A and CNAME records using dnsx.
- Port Scanning: Conducts thorough port scans on identified IPs using smap.
- Screenshot Capture: Takes screenshots of live domains using aquatone.
- Vulnerability Pattern Search: Searches for common vulnerability patterns in URLs using gf.
- Subdomain Takeover Checking: Checks for vulnerable subdomains using subzy.
- Endpoint Crawling: Crawls endpoints to gather more data using katana.
- API Key Scanning: Optionally scans for exposed API keys using secretx, providing an option to skip this resource-intensive task.

## Prerequisites

Before installing and running TrashRecon, ensure you have Python 3.x installed on your system. Additionally, TrashRecon depends on several external tools:

- [puredns](https://github.com/d3mondev/puredns)
- [httpx](https://github.com/projectdiscovery/httpx)
- [dnsx](https://github.com/projectdiscovery/dnsx)
- [smap](https://github.com/s0md3v/Smap)
- [aquatone](https://github.com/Abhinandan-Khurana/aquatone)
- [waybackurls](https://github.com/tomnomnom/waybackurls)
- [gf](https://github.com/tomnomnom/gf)
- [gf-patterns](https://github.com/1ndianl33t/Gf-Patterns)
- [massdns](https://github.com/blechschmidt/massdns)
- [subfinder](https://github.com/projectdiscovery/subfinder)
- [amass](https://github.com/OWASP/Amass)
- [assetfinder](https://github.com/tomnomnom/assetfinder)
- [waymore](https://github.com/xnl-h4ck3r/waymore)
- [subzy](https://github.com/LukaSikic/subzy)
- [secretx](https://github.com/Somchandra17/secretx)
- [katana](https://github.com/projectdiscovery/katana)

These tools must be installed and accessible in your system's PATH for TrashRecon to function correctly.

## Installation

### Using Docker (Easy to use and No setup!)

1. Pull the Docker image:
   ```bash
   docker pull 0xsom/trashrecon:latest
   ```
2. Run the Docker container:
   ```bash
   docker run -it -v /path/on/host:/root/TrashRecon/ 0xsom/trashrecon:latest
   ```
- 🚧 Make sure to change ```/path/on/host``` on the above command 🚧

---
### Manual Installation Or If you want to run it locally (Not recommended)

1. Clone the TrashRecon repository:
   ```bash
   git clone https://github.com/Somchandra17/TrashRecon.git
   ```
2. Go to the directory:
   ```bash
   cd TrashRecon
   ```
3. Install the required tools and dependencies:

| Tool            | Installation Command                                                                 | Path to Copy Wordlist |
|-----------------|--------------------------------------------------------------------------------------|-----------------------|
| Python 3.x      | Already installed or `sudo apt-get install python3`                                  |                       |
| pip             | `sudo apt-get install python3-pip`                                                   |                       |
| puredns         | `go install -v github.com/d3mondev/puredns/v2@latest`                                | `/root/.config/puredns/resolvers.txt` |
| httpx           | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest`                   |                       |
| dnsx            | `go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest`                     |                       |
| smap            | `go install -v github.com/s0md3v/smap/cmd/smap@latest`                               |                       |
| aquatone        | `go install -v github.com/Abhinandan-Khurana/aquatone@v1.7.2`                        |                       |
| waybackurls     | `go install -v github.com/tomnomnom/waybackurls@latest`                              |                       |
| gf              | `go install -v github.com/tomnomnom/gf@latest`                                       |                       |
| subzy           | `go install -v github.com/LukaSikic/subzy@latest`                                    |                       |
| subfinder       | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`        |                       |
| amass           | `go install -v github.com/owasp-amass/amass/v3.19.2/...@master`                      |                       |
| assetfinder     | `go install -v github.com/tomnomnom/assetfinder@latest`                              |                       |
| waymore         | `pip install waymore --break-system-packages`                                        |                       |
| massdns         | `git clone https://github.com/blechschmidt/massdns.git && cd massdns && make && make install` | `/app/subdomains-top1million-110000.txt` |
| gf-patterns     | `git clone https://github.com/1ndianl33t/Gf-Patterns /root/.gf`                      |                       |
| katana          | 'go install -v github.com/projectdiscovery/katana/cmd/katana@latest'                 |                       |
| secretx         | 'git clone https://github.com/Somchandra17/secretx.git'                              |                       |

4. Ensure the external tools listed in the Prerequisites section are installed and in your system's PATH.

## Usage
1. To run from the docker container:

   ```bash
      docker run -it -v /path/on/host:/root/TrashRecon/ 0xsom/trashrecon:latest
   ```

3. To start using TrashRecon on host, run the following command from the TrashRecon directory:

```bash
   python3 trashrecon.py
```
