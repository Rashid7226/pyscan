# Pyscan

Safe, signature-based malware scanner for Linux hosting servers.

## Files

```text
pyscan/
├── pyscan.py
├── install.sh
├── README.md
└── VERSION
```

## Install

Run as root:

```bash
curl -fsSL https://raw.githubusercontent.com/Rashid7226/pyscan/main/install.sh | bash
```

For a private repository, this unauthenticated raw URL will not work; use an authenticated deployment method instead.

## Scan one cPanel account

```bash
pyscan -u USERNAME -t 2
```

## Scan a specific path

```bash
pyscan -p /home/USERNAME/public_html -t 2
```

## Scan all /home

```bash
pyscan -p /home -t 2
```

## Logs

```text
/var/log/pyscan.log
```

Signature cache:

```text
/var/cache/pyscan/
```

## Quarantine

Detection does not modify files by default. After reviewing results:

```bash
pyscan -p /home -t 2 --quarantine /root/pyscan-quarantine
```

## Update

```bash
pyscan update
```

Start production deployment with one account and 2 workers. Review the log before scanning all accounts or enabling quarantine.
