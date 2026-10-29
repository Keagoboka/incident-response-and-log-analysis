# Incident Case Write-Up: Investigating a Suspicious Web Upload via PCAP & CyberChef

**Analyst:** Junior SOC / Incident Response Analyst  
**Category:** Network Traffic Analysis & Static Artifact Triage  
**Target File:** `suspicious_file.bin` (SHA256: `E415BD0655572B3BB248AB79925E163FD721B0F08A529497B2854ED6FA2BBF8B`)  
**Status:** Inconclusive Plaintext / Identified as Custom Obfuscated Binary Payload  

---

## Executive Summary

While monitoring web server activity, I flagged an unexpected HTTP file upload originating from an internal network address (`192.168.124.7`). Using **Wireshark**, I reconstructed the TCP session and confirmed a successful `POST` request carrying a 307,200-byte payload (`suspicious_file.bin`) submitted with a `curl/7.81.0` user-agent.

To triage the threat, I extracted the raw binary payload, calculated its SHA256 checksum via **PowerShell**, and queried **VirusTotal** for threat intelligence signatures (which yielded zero public detections). Moving to static analysis in **CyberChef**, I de-obfuscated an outer Base64 layer but encountered an unsupported compression format during `Zlib`/`Deflate` unpacking. Advanced string extraction and regex pattern matching confirmed the presence of high-entropy binary structures rather than standard plaintext scripts.

---

## Phase 1: Network Traffic Analysis (Wireshark)

### Initial Finding & Reconnaissance
I started my investigation by opening the capture file (`SOC3.pcapng`) in Wireshark and filtering for HTTP traffic connected to the local web server (`192.168.124.7:8080`).

1. **Recon Phase:** The client initially issued two `GET` requests:
   - Request 1 targeted the standard web page endpoint.
   - Request 2 targeted an image asset (`.jpg`), which received an HTTP `404 Not Found` response from the server.
2. **Session Establishment:** The TCP 3-way handshake established cleanly without packet loss or TCP reset flags.
3. **Data Transfer Volume:** Following TCP Stream 3, I observed 40+ continuous `ACK` packets carrying full 1448-byte segment payloads, signaling a large outbound stream.

### Key Indicator: The HTTP POST Request
Inspect of the raw HTTP request header revealed a suspicious staging vector:

```http
POST /tcp-lab/upload-post HTTP/1.1
Host: 192.168.124.7:8080
User-Agent: curl/7.81.0
Accept: */*
Content-Length: 307200
Content-Type: application/x-www-form-urlencoded
```

#### Analyst Takeaway
- **User-Agent Anomaly:** Standard users upload files through browser user-agents (e.g., Chrome, Firefox). The presence of `curl/7.81.0` points toward command-line script automation.
- **Payload Size:** The request transferred exactly 307,200 bytes of raw data.

> **Visual Proof:**  
> ![Wireshark TCP Stream Showing HTTP POST and curl User-Agent](IOCs%201,1.png)

---

## Phase 2: Hash Generation & Threat Intelligence Check

Once I verified the upload payload had landed, I carved out the raw HTTP body bytes and saved them as `suspicious_file.bin`.

### Cryptographic Fingerprinting
In PowerShell, I ran `Get-FileHash` to establish a unique SHA256 fingerprint:

```powershell
Get-FileHash -Path "C:\Users\user\investigation on\suspicious_file.bin" -Algorithm SHA256
```

#### Output
- **Algorithm:** SHA256  
- **Hash:** `E415BD0655572B3BB248AB79925E163FD721B0F08A529497B2854ED6FA2BBF8B`  

> **Visual Proof:**  
> ![PowerShell SHA256 Hash Execution](IOc%201.2.png)

### VirusTotal Query Results
I searched the SHA256 string across VirusTotal to check for known malware family signatures or threat vendor tags:
- **Result:** *No matches found.* 
- **Analyst Note:** An unknown hash does not mean the file is safe; it often indicates zero-day staging, custom-compiled binaries, or unique per-target obfuscation.

---

## Phase 3: Static Analysis & Obfuscation Decoding (CyberChef)

To inspect the raw payload safely, I loaded `suspicious_file.bin` into **CyberChef**.

### 1. File Signature Check
Scanning the initial bytes (`36 7e 5a`) revealed no standard magic numbers (such as `4D 5A` for Windows executables or `50 4B` for ZIP archives). However, examining raw string fragments showed a repeating `Y4zD` sequence, a known signature marker for Base64-wrapped data.

### 2. Recipe De-Obfuscation Attempt
I constructed a multi-stage recipe to strip obfuscation layers:
1. **`From Base64`** *(Alphabet: A-Za-z0-9+/=, Non-alphabet chars removed)*: Successfully decoded the raw ASCII payload into binary byte streams.
2. **`Raw Deflate` / `Zlib Inflate` / `Gunzip`**: Tested standard decompression routines. CyberChef returned an `unsupported compression method` error, confirming the payload does not rely on standard Zlib/Gzip packaging.
3. **`XOR Brute Force`**: Executed single-byte XOR key brute-forcing across all 256 keys to check for simple XOR ciphers.
4. **`Regular Expression`** (`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}` and `https?://[^\s]+`): Filtered for plain-text IPv4 addresses and web URLs.
5. **`Strings`**: Extracted minimum 4-character printable ASCII sequences.

> **Visual Proof:**  
> ![CyberChef Recipe Workflow and High-Entropy Output](IOCs%201.3.png)

### 3. Recipe Findings
After applying `Strings` and Regex filters, the output collapsed into high-entropy character blocks (`PJ'q1jHo`, `PY7@9`, `ETfF`). No plain-text URLs, IP callbacks, or script commands were exposed, indicating the underlying stream is a compiled binary payload or custom-encrypted blob rather than an uncompiled shell script.

---

## Conclusion & Recommended Actions

### Summary of Findings
1. **Upload Vector:** Confirmed an automated HTTP `POST` upload executed via a `curl/7.81.0` CLI agent from private IP `192.168.124.7`.
2. **File Identification:** Carved payload `suspicious_file.bin` (307,200 bytes, SHA256: `E415BD0...`).
3. **Intel Baseline:** Zero VirusTotal hits, confirming a novel or custom-packaged sample.
4. **Obfuscation Assessment:** Outer Base64 wrapper resolved to a non-standard binary structure resistant to static string extractions and single-byte XOR ciphers.

### Recommended Next Steps
- **Dynamic Analysis:** Submit `suspicious_file.bin` to an isolated detonation sandbox (e.g., ANY.RUN or Hybrid Analysis) to capture runtime behaviors, process spawning (`cmd.exe`/`powershell.exe`), and potential network C2 callbacks.
- **Host Endpoint Audit:** Audit `192.168.124.7` for unauthorized scheduled tasks, unexpected command-line `curl` processes, or compromised user sessions.
