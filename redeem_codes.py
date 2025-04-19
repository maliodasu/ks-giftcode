#!/usr/bin/env python3
# Kingshot Gift Code Redeemer Script Version 1.0.0
# See https://github.com/justncodes/ks-giftcode

import os
import requests
import time
import hashlib
import json
import csv
import argparse
import sys
from datetime import datetime
from glob import glob

# Configuration
LOGIN_URL = "https://kingshot-giftcode.centurygame.com/api/player"
REDEEM_URL = "https://kingshot-giftcode.centurygame.com/api/gift_code"
WOS_ENCRYPT_KEY = "mN4!pQs6JrYwV9"  # The secret key

DELAY = 1 # Seconds between each redemption, less than 1s may result in being blocked
RETRY_DELAY = 2  # Seconds between retries
MAX_RETRIES = 3  # Max retry attempts per request

script_dir = os.path.dirname(os.path.abspath(__file__)) # store log in same directory as script
LOG_FILE = os.path.join(script_dir, "redeemed_codes.txt")

RESULT_MESSAGES = {
    "SUCCESS": "Successfully redeemed",
    "RECEIVED": "Already redeemed",
    "SAME TYPE EXCHANGE": "Successfully redeemed (same type)",
    "TIME ERROR": "Code has expired",
    "TIMEOUT RETRY": "Server requested retry",
    "USED": "Claim limit reached, unable to claim",
}

counters = {
    "success": 0,
    "already_redeemed": 0,
    "errors": 0,
}

# Log messages to file and console
def log(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp} - {message}"

    try:
        print(log_entry)
    except UnicodeEncodeError:
        cleaned = log_entry.encode('utf-8', errors='replace').decode('ascii', errors='replace')
        print(cleaned)

    try:
        with open(LOG_FILE, "a", encoding="utf-8-sig") as f:
            f.write(log_entry + "\n")
    except Exception as e:
        print(f"{timestamp} - LOGGING ERROR: Could not write to {LOG_FILE}. Error: {e}")
        print(f"{timestamp} - ORIGINAL MESSAGE: {log_entry}")

# Generate the sign, an MD5 hash sent with the POST payload
def encode_data(data):
    secret = WOS_ENCRYPT_KEY
    sorted_keys = sorted(data.keys())

    encoded_data = "&".join(
        [
            f"{key}={json.dumps(data[key]) if isinstance(data[key], dict) else data[key]}"
            for key in sorted_keys
        ]
    )

    return {"sign": hashlib.md5(f"{encoded_data}{secret}".encode()).hexdigest(), **data}

# Send POST and handle retries if failed
def make_request(url, payload):
    for attempt in range(MAX_RETRIES):
        try:
            response = requests.post(url, json=payload)

            if response.status_code == 200:
                response_data = response.json()
                msg_content = response_data.get("msg", "")
                if isinstance(msg_content, str) and msg_content.strip('.') == "TIMEOUT RETRY":
                    if attempt < MAX_RETRIES - 1:
                        log(f"Attempt {attempt+1}: Server requested retry for payload: {payload.get('fid', 'N/A')}")
                        time.sleep(RETRY_DELAY)
                        continue
                    else:
                        log(f"Attempt {attempt+1}: Max retries reached after server requested retry for payload: {payload.get('fid', 'N/A')}")
                        return response

                return response

            log(f"Attempt {attempt+1} failed for FID {payload.get('fid', 'N/A')}: HTTP {response.status_code}, Response: {response.text[:200]}")

        except requests.exceptions.RequestException as e:
            log(f"Attempt {attempt+1} failed for FID {payload.get('fid', 'N/A')}: RequestException: {str(e)}")
        except json.JSONDecodeError as e:
             log(f"Attempt {attempt+1} failed for FID {payload.get('fid', 'N/A')}: JSONDecodeError: {str(e)}. Response text: {response.text[:200]}")

        if attempt < MAX_RETRIES - 1:
            time.sleep(RETRY_DELAY)

    log(f"All {MAX_RETRIES} attempts failed for request to {url} with FID {payload.get('fid', 'N/A')}.")
    return None

# Redeem a gift code for a player and return the response
def redeem_gift_code(fid, cdk):
    if not str(fid).strip().isdigit():
        log(f"Skipping invalid FID: '{fid}'")
        return {"msg": "Invalid FID format"}
    fid = str(fid).strip()

    try:
        # === Login Request ===
        login_payload = encode_data({"fid": fid, "time": int(time.time() * 1000)})
        login_resp = make_request(LOGIN_URL, login_payload)

        if not login_resp:
             return {"msg": "Login request failed after retries"}

        try:
            login_data = login_resp.json()
            if login_data.get("code") != 0:
                login_msg = login_data.get('msg', 'Unknown login error')
                log(f"Login failed for {fid}: Code {login_data.get('code')}, Message: {login_msg}")
                return {"msg": f"Login failed: {login_msg}"}

            nickname = login_data.get("data", {}).get("nickname")
            log(f"Processing {nickname or 'Unknown Player'} ({fid})")

        except json.JSONDecodeError:
             log(f"Login response for {fid} was not valid JSON: {login_resp.text[:200]}")
             return {"msg": "Login response invalid JSON"}

        # === Redeem Request ===
        redeem_payload = encode_data({
            "fid": fid,
            "cdk": cdk,
            "time": int(time.time() * 1000)
        })

        redeem_resp = make_request(REDEEM_URL, redeem_payload)

        if not redeem_resp:
            return {"msg": "Redemption request failed after retries"}

        try:
            return redeem_resp.json()
        except json.JSONDecodeError:
            log(f"Redemption response for {fid} was not valid JSON: {redeem_resp.text[:200]}")
            return {"msg": "Redemption response invalid JSON"}

    except Exception as e:
        log(f"Unexpected error during redemption for {fid}: {str(e)}")
        return {"msg": f"Unexpected Error: {str(e)}"}

# Read player IDs from a CSV file
def read_player_ids_from_csv(file_path):
    """
    Reads player IDs from a CSV file.
    Handles files where IDs are one per line, OR comma-separated on one or more lines.
    Strips whitespace from each ID and ignores empty entries.
    """
    player_ids = []
    format_detected = "newline" # Assume newline format initially
    try:
        # Using utf-8-sig to handle potential BOM (Byte Order Mark)
        with open(file_path, mode="r", newline="", encoding="utf-8-sig") as file:
            # Read a small sample to detect format more reliably
            sample = "".join(file.readline() for _ in range(5))
            if ',' in sample:
                format_detected = "comma-separated"
            file.seek(0)

            log(f"Reading {file_path} (detected format: {format_detected})")
            reader = csv.reader(file)
            for row_num, row in enumerate(reader, 1):
                for item in row:
                    fid = item.strip()
                    if fid:
                        player_ids.append(fid)
                    elif item and not fid:
                        log(f"Warning: Ignoring whitespace-only entry in {file_path} on row {row_num}")
                if not row and format_detected == "newline":
                     log(f"Warning: Ignoring empty line in {file_path} on row {row_num}")

    except FileNotFoundError:
        raise
    except Exception as e:
        log(f"Error reading or processing CSV file {file_path}: {str(e)}")
        return [] # Return empty list on other read errors, allowing script to continue

    return player_ids

# Print summary of actions
def print_summary():
    log("\n=== Redemption Complete ===")
    log(f"Successfully redeemed: {counters['success']}")
    log(f"Already redeemed: {counters['already_redeemed']}")
    log(f"Errors/Failures: {counters['errors']}")

# Main script
if __name__ == "__main__":
    # Set up command-line argument parsing
    parser = argparse.ArgumentParser(description="Redeem gift codes for player IDs from a CSV file.")
    parser.add_argument("--csv", required=True, help="Path to the CSV file containing player IDs (or *.csv for all files in a folder).")
    parser.add_argument("--code", required=True, help="The gift code to redeem.")
    args = parser.parse_args()

    # Log initialization message
    start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log(f"\n=== Starting redemption for gift code: {args.code} at {start_time} ===")

    # Handle *.csv input
    if args.csv == "*.csv":
        # Use the script's directory if no folder is specified
        csv_files = glob(os.path.join(script_dir, "*.csv"))
    else:
        # Use the specified folder or file
        if os.path.isdir(args.csv):
            csv_files = glob(os.path.join(args.csv, "*.csv"))
        else:
            csv_files = [args.csv]

    if not csv_files:
        log("Error: No CSV files found.")
        sys.exit(1)

    # Process all CSV files
    for csv_file in csv_files:
        try:
            player_ids = read_player_ids_from_csv(csv_file)
            log(f"Loaded {len(player_ids)} player IDs from {csv_file}")

            # Redeem gift code for each player
            for fid in player_ids:
                result = redeem_gift_code(fid, args.code)

                raw_msg = result.get('msg', 'Unknown error').strip('.')
                friendly_msg = RESULT_MESSAGES.get(raw_msg, raw_msg)

                # Exit immediately if code is expired or claim limit reached
                if raw_msg == "TIME ERROR":
                    log("Code has expired! Script will now exit.")
                    print_summary()
                    sys.exit(1)
                elif raw_msg == "USED":
                    log("Claim limit reached! Script will now exit.")
                    print_summary()
                    sys.exit(1)

                # Update counters based on result
                if raw_msg in ["SUCCESS", "SAME TYPE EXCHANGE"]:
                    counters["success"] += 1
                elif raw_msg == "RECEIVED":
                    counters["already_redeemed"] += 1
                elif raw_msg == "TIMEOUT RETRY":
                    pass
                else:
                    counters["errors"] += 1

                log(f"Result: {friendly_msg}")
                time.sleep(DELAY)

        except FileNotFoundError:
            log(f"Error: CSV file '{csv_file}' not found")
        except Exception as e:
            log(f"Error processing {csv_file}: {str(e)}")

    # Print final summary
    print_summary()