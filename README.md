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
- API Key Scanning: Scans for exposed API keys using secretx.

## Installation

### Using Docker (Easy to use and No setup!)
1. Go to the cloned directory:
   ```bash
   cd TrashRecon
   ```

3. Build the Docker image:
   ```bash
   docker build -t trashrecon-gui .
   ```
4. Run the Docker container:
   ```bash
   docker run -it -p 5000:5000 0xsom/trashrecon-gui
   ```

---

### Manual Installation (Not recommended)

1. Clone the TrashRecon repository:
   ```bash
   git clone https://github.com/Somchandra17/TrashRecon.git
   ```
2. Go to the directory:
   ```bash
   cd TrashRecon
   ```

## ScreenShots

1. ![image](https://github.com/user-attachments/assets/4c1efc66-1d3c-4419-a0cf-6f618d9ed796)
2. ![image](https://github.com/user-attachments/assets/855c88e0-c7cd-4c2c-97da-bc2171dfb39d)



## Usage

### Using Docker

1. Run the Docker container:
   ```bash
   docker run -it -p 5000:5000 trashrecon-gui
   ```

2. Open a web browser and navigate to `http://localhost:5000` to access the TrashRecon web interface.

3. Enter the domain you want to perform reconnaissance on and start the process. The application will run the various phases and update the status in real-time.

4. Once the reconnaissance is complete, you can download the results from the provided link in the application.

### Running Locally

1. Start the Flask application:
   ```bash
   python3 app.py
   ```

2. Open a web browser and navigate to `http://localhost:5000` to access the TrashRecon web interface.

3. Enter the domain you want to perform reconnaissance on and start the process. The application will run the various phases and update the status in real-time.

4. Once the reconnaissance is complete, you can download the results from the provided link in the application.
