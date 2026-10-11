# SMTP NSE Enhancements

This repository contains two custom Nmap Scripting Engine (NSE) scripts developed as part of a cybersecurity assignment.

## Scripts

### 1. SMTP Response Code Analyzer
Displays SMTP response codes and response text obtained from EHLO and HELP commands.

### 2. SMTP Capability Counter
Lists the distinct SMTP extensions advertised by the server, counts them, and checks whether STARTTLS is advertised.

## Execution

Run the scripts against a local SMTP service on port 25:

```bash
sudo nmap -p 25 --script smtp-response-analyzer localhost
sudo nmap -p 25 --script smtp-capability-counter localhost
```

These scripts were tested against a local SMTP service. The STARTTLS check identifies whether the server advertises the extension; it does not verify a successful TLS handshake.
