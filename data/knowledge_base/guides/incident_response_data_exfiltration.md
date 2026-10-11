# Incident Response Playbook: Data Exfiltration and Egress Anomalies

## 1. Overview
Data exfiltration (MITRE ATT&CK `TA0010`) refers to unauthorized theft or transmission of sensitive enterprise data to adversary-controlled external infrastructure.

## 2. Common Exfiltration Channels and Indicators

### Alternative Protocol Egress (`T1048`)
- Exfiltration over non-standard protocols or alternative ports (e.g., DNS tunneling, ICMP echo payloads, direct SFTP/FTP egress).
- Indicator: High bytes transmitted outbound (`bytes_out_mb > 50 MB`) from endpoints to unexpected destinations.

### Application Layer Protocol C2 / Exfiltration (`T1071`)
- Exfiltration over HTTPS/HTTP via legitimate cloud storage services (Mega, Dropbox, Google Drive, AWS S3 buckets) or custom web servers.
- Indicator: Unusually large upload volume relative to download volume, sustained external socket connections (`external_connections > 20`).

### Archive Collected Data (`T1560`)
- Adversaries compress, encrypt, or package sensitive files prior to exfiltration using utilities like `7z.exe`, `rar.exe`, or built-in PowerShell archiving (`Compress-Archive`).
- Indicator: Rare process execution bursts involving archiving utilities before network egress spikes.

## 3. Playbook Workflow
1. Identify the source host and user context initiating the outbound data spike.
2. Determine destination IP address, domain, ASN, and geographic location.
3. Review firewall and web proxy logs for the exact protocol and URL paths utilized.
4. Check endpoint file access logs for mass file reads or compression events immediately preceding the egress connection.
5. If exfiltration is confirmed, isolate the affected host from the network, preserve forensic memory images, and notify legal and incident response leads.
