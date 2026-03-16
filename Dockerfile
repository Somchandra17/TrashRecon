# =============================================================================
# Stage 1: Build all Go tools + massdns
# =============================================================================
FROM golang:1.25-bookworm AS builder

RUN go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -v github.com/owasp-amass/amass/v3/cmd/amass@latest && \
    go install -v github.com/d3mondev/puredns/v2@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install -v github.com/s0md3v/smap/cmd/smap@latest && \
    go install -v github.com/Abhinandan-Khurana/aquatone@v1.7.2 && \
    go install -v github.com/tomnomnom/waybackurls@latest && \
    go install -v github.com/tomnomnom/gf@latest && \
    go install -v github.com/PentestPad/subzy@latest && \
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/tomnomnom/assetfinder@latest && \
    go install -v github.com/projectdiscovery/asnmap/cmd/asnmap@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

RUN git clone --depth 1 https://github.com/blechschmidt/massdns.git /tmp/massdns && \
    cd /tmp/massdns && make

# =============================================================================
# Stage 2: Slim runtime image (no Go SDK, no build toolchain)
# =============================================================================
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 python3-pip chromium wget git ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /go/bin/ /usr/local/bin/
COPY --from=builder /tmp/massdns/bin/massdns /usr/local/bin/massdns

RUN pip install --no-cache-dir waymore --break-system-packages

WORKDIR /app

RUN mkdir -p /root/.gf /root/.config/puredns /root/app /root/TrashRecon /root/subzy && \
    git clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns /root/.gf && \
    git clone --depth 1 https://github.com/Somchandra17/secretx.git /app/secretx && \
    wget -q https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/master/fingerprints.json \
        -O /root/subzy/fingerprints.json && \
    (subzy update || true) && \
    (nuclei -update-templates -silent 2>/dev/null || true)

# Download fresh wordlist + resolvers at build time; bundled copies as fallback
COPY resolvers.txt /tmp/resolvers_fallback.txt
COPY subdomains-top1million-110000.txt /tmp/wordlist_fallback.txt

RUN (wget -q -O /root/.config/puredns/resolvers.txt \
         https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt \
     && [ -s /root/.config/puredns/resolvers.txt ]) \
    || cp /tmp/resolvers_fallback.txt /root/.config/puredns/resolvers.txt \
    ; \
    (wget -q -O /root/app/subdomains-top1million-110000.txt \
         https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt \
     && [ -s /root/app/subdomains-top1million-110000.txt ]) \
    || cp /tmp/wordlist_fallback.txt /root/app/subdomains-top1million-110000.txt \
    ; \
    rm -f /tmp/resolvers_fallback.txt /tmp/wordlist_fallback.txt

COPY trashrecon.py banner.txt /app/

ENTRYPOINT ["python3", "/app/trashrecon.py"]
