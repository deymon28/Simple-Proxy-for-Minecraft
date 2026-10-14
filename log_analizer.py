"""Summarize proxy logs: top clients by connection attempts, with rejected counts.

Usage: python log_analizer.py [LOG_FILE] [--top N]
Without LOG_FILE the newest log in the logs directory is used.
"""
import argparse
import glob
import os
import re
import sys
from collections import Counter

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ATTEMPT = re.compile(r'Connection attempt from ([0-9.]+|[0-9a-fA-F:]*:[0-9a-fA-F:]+?)(?::\d+)?\s*$', re.M)
REJECTED = re.compile(r'Rejected: (\S+) is not in the allowed list(?: \| Attempts: (\d+))?')


def newest_log(log_dir):
    logs = glob.glob(os.path.join(log_dir, 'proxy*.log'))
    return max(logs, key=os.path.getmtime) if logs else None


def analyze(text):
    attempts, rejected = Counter(), Counter()
    for ip in ATTEMPT.findall(text):
        attempts[ip] += 1
    for ip, n in REJECTED.findall(text):
        rejected[ip] += 1
        # New-format logs report suppressed repeats in "Attempts"; old logs
        # already have one "Connection attempt" line per rejected connection.
        if n:
            attempts[ip] += int(n)
    return attempts, rejected


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('log_file', nargs='?')
    p.add_argument('--top', type=int, default=10)
    p.add_argument('--log-dir', default=os.path.join(BASE_DIR, 'logs'))
    args = p.parse_args()

    path = args.log_file or newest_log(args.log_dir)
    if not path or not os.path.isfile(path):
        sys.exit("No log file found")

    with open(path, encoding='utf-8', errors='replace') as f:
        attempts, rejected = analyze(f.read())

    print(f"Log: {os.path.basename(path)}")
    print(f"Top {args.top} IPs by connection attempts:")
    for ip, count in attempts.most_common(args.top):
        status = "rejected" if rejected[ip] else "allowed"
        print(f"{ip}: {count} attempts ({status})")


if __name__ == '__main__':
    main()
