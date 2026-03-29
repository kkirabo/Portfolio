# Written by ki 
# !/usr/bin/python
# OR
# !/usr/bin/python3


import subprocess
import sys
from urllib.parse import urlparse

def normalize_target(raw_target: str) -> str:
    raw_target = raw_target.strip()
    if raw_target.startswith("http://") or raw_target.startswith("https://"):
        parsed = urlparse(raw_target)
        if parsed.hostname:
            return parsed.hostname
        raise ValueError("Unable to parse hostname from URL")
    return raw_target


def main():
    target = input("Enter the target: ").strip()
    if not target:
        print("Please enter a valid target.")
        sys.exit(1)

    try:
        target = normalize_target(target)
    except ValueError as e:
        print("Invalid target:", e)
        sys.exit(1)
        
    scan_type = input("Enter '1' for service scan or '2' for port scan: ").strip()
    
    # validate the user choice and run the appropriate scan
    try:
        if scan_type == "1": 
            # version scan
            result = subprocess.run(["nmap", "-sC", "-sV", target], 
                                    capture_output=True, 
                                    text = True,
                                    check = True)
            print(result.stdout)
        elif scan_type == "2":
            # port scan
            result = subprocess.run(["nmap", "-p-", "--min-rate 1000", "-T4", target],
                        capture_output=True, 
                        text = True, 
                        check = True)  
            print(result.stdout)
        else: 
            raise ValueError(f"Unknown option '{scan_type}'. Please enter 1 or 2.")
    

    except subprocess.CalledProcessError as e: 
        print(f"nmap exit with status {e.returncode}")
        print(e.stdout or e.stderr)
        sys.exit(e.returncode)
    except FileNotFoundError:
        print("'nmap' is not installed. Please install nmap and ensure it's on your PATH.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nInterrupted by user")
        sys.exit(1)
    except Exception as e:
        print("Error:", e)
        sys.exit(1)


if __name__ == "__main__":
    main()

    

