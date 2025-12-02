# Kisakye Kirabo

from geoip import geolite2
from datetime import datetime
import re
import os

LOGFILE = "/home/student/Downloads/syslog.log"
THRESHOLD = 10

# clear terminal for cleaner report display
def clear_terminal():
    os.system('clear')


def extract_failed_logins(logfile):
    failed_ips = {}

    # match multiple common failure messages
    patterns = [
        r"Failed password.*from\s+(\d+\.\d+\.\d+\.\d+)",
        r"Invalid user.*from\s+(\d+\.\d+\.\d+\.\d+)",
        r"authentication failure;.*rhost=(\d+\.\d+\.\d+\.\d+)",
        r"Failed login.*from\s+(\d+\.\d+\.\d+\.\d+)"
    ]

    try:
        with open(logfile, "r", errors="ignore") as f:
            for line in f:
                for pattern in patterns:
                    results = re.findall(pattern, line)
                    for ip in results:
                        failed_ips[ip] = failed_ips.get(ip, 0) + 1
    except FileNotFoundError:
        print("Error: log file not found at {}".format(logfile))
    except PermissionError:
        print("Error: insufficient permissions to read {}".format(logfile))

    return failed_ips


def ip_to_country(ip):
    try:
        match = geolite2.lookup(ip)
        if match is None:
            return "Unknown"

        # try different possible attributes
        country = getattr(match, "country", None)
        if country:
            return country
        country_code = getattr(match, "country_code", None)
        if country_code:
            return country_code
        return "Unknown"
    except Exception:
        return "Unknown"


def main():
    clear_terminal()

    failed_ips = extract_failed_logins(LOGFILE)

    # keep only IPs with >= threshold
    filtered = {ip: count for ip, count in failed_ips.items() if count >= THRESHOLD}

    # sort ascending by count
    sorted_ips = sorted(filtered.items(), key=lambda x: x[1])

    print("Attacker Report - {}\n".format(datetime.now().strftime('%B %d, %Y')))
    print("{:<6} {:<18} {}".format('COUNT', 'IP ADDRESS', 'COUNTRY'))
    print("-" * 50)

    if not sorted_ips:
        print("No IPs found with {} or more failed attempts.".format(THRESHOLD))
        return

    for ip, count in sorted_ips:
        country = ip_to_country(ip)
        print("{:<6} {:<18} {}".format(count, ip, country))


if __name__ == "__main__":
    main()
