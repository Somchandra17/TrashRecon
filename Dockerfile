FROM golang:latest

WORKDIR /app

RUN apt update && apt -y install python3 python3-pip cowsay chromium wget

# Install Python dependencies
RUN pip install pytest-shutil waymore --break-system-packages flask

# Install secretx
RUN git clone https://github.com/Somchandra17/secretx.git
# Clone and install massdns
RUN git clone https://github.com/blechschmidt/massdns.git && cd massdns && make && make install
RUN cd .. && rm -rf massdns

# Install Go packages
RUN go install -v github.com/projectdiscovery/katana/cmd/katana@latest
RUN go install -v github.com/OWASP/Amass/v3/cmd/amass@v3.19.2
RUN go install -v github.com/d3mondev/puredns/v2@latest
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
RUN go install -v github.com/s0md3v/smap/cmd/smap@latest
RUN go install -v github.com/Abhinandan-Khurana/aquatone@v1.7.2
RUN go install -v github.com/tomnomnom/waybackurls@latest
RUN go install -v github.com/tomnomnom/gf@latest
RUN go install -v github.com/LukaSikic/subzy@latest
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN go install -v github.com/tomnomnom/assetfinder@latest

# Set up subzy
RUN mkdir -p /root/subzy
RUN wget https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/master/fingerprints.json -O /root/subzy/fingerprints.json
RUN mkdir -p /root/.gf
RUN mkdir -p /root/.config/puredns
RUN subzy update

# Clone Gf-Patterns repository
RUN git clone https://github.com/1ndianl33t/Gf-Patterns /root/.gf

# Copy necessary files
RUN mkdir -p /root/app
COPY resolvers.txt /root/.config/puredns/resolvers.txt
COPY subdomains-top1million-110000.txt /root/app/subdomains-top1million-110000.txt
COPY trashrecon.py /app/trashrecon.py
COPY app.py /app/app.py
COPY templates /app/templates
COPY static /app/static
RUN apt-get -qy autoremove

# Ensure results directory exists
RUN mkdir -p /root/TrashRecon

# Set entrypoint
ENTRYPOINT ["python3", "/app/app.py"]