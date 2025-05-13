#!/usr/bin/env python3
# Kingshot Gift Code Redeemer Script Version 1.0.0 with Threading
# See https://github.com/maliodasu/ks-giftcode

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
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
import threading

# Configuration
LOGIN_URL = "https://kingshot-giftcode.centurygame.com/api/player"
REDEEM_URL = "https://kingshot-giftcode.centurygame.com/api/gift_code"
WOS_ENCRYPT_KEY = "mN4!pQs6JrYwV9"  # The secret key

DELAY = 1  # Base delay between requests
RETRY_DELAY = 2  # Seconds between retries
MAX_RETRIES = 3  # Max retry attempts per request
DEFAULT_THREADS = 3  # Start with 3 threads, adjust based on server response

script_dir = os.path.dirname(os.path.abspath(__file__))  # store log in same directory as script
LOG_FILE = os.path.join(script_dir, "redeemed_codes.txt")

RESULT_MESSAGES = {
    "SUCCESS": "Successfully redeemed",
    "RECEIVED": "Already redeemed",
    "SAME TYPE EXCHANGE": "Successfully redeemed (same type)",
    "TIME ERROR": "Code has expired",
    "TIMEOUT RETRY": "Server requested retry",
    "USED": "Claim limit reached, unable to claim",
    "THREAD_ERROR": "Thread execution error",
    "RATE_LIMITED": "Server rate limit exceeded",
}

counters = {
    "success": 0,
    "already_redeemed": 0,
    "errors": 0,
    "rate_limited": 0,
}

# Thread-safe logging and counters
log_lock = threading.Lock()
counters_lock = threading.Lock()

# Enhanced log messages to file and console with thread info
def log(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    thread_id = threading.get_ident()
    log_entry = f"{timestamp} [Thread-{thread_id}] - {message}"

    with log_lock:
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

# Update counters in a thread-safe way
def update_counter(counter_name, increment=1):
    with counters_lock:
        counters[counter_name] += increment

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

# Send POST and handle retries if failed with rate limiting detection
def make_request(url, payload):
    for attempt in range(MAX_RETRIES):
        try:
            response = requests.post(url, json=payload)
            
            # Check for rate limiting (429 status code)
            if response.status_code == 429:
                update_counter("rate_limited")
                log(f"Rate limited detected for FID {payload.get('fid', 'N/A')}")
                time.sleep(RETRY_DELAY * (attempt + 1))  # Exponential backoff
                continue

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
            time.sleep(RETRY_DELAY * (attempt + 1))  # Exponential backoff

    log(f"All {MAX_RETRIES} attempts failed for request to {url} with FID {payload.get('fid', 'N/A')}.")
    return None

# Modifikasi redeem_gift_code
def redeem_gift_code(fid, cdk):
    if not str(fid).strip().isdigit():
        log(f"Skipping invalid FID: '{fid}'")
        return {"msg": "Invalid FID format"}, None  # Kembalikan None untuk nickname
    fid = str(fid).strip()

    try:
        # === Login Request ===
        login_payload = encode_data({"fid": fid, "time": int(time.time() * 1000)})
        login_resp = make_request(LOGIN_URL, login_payload)

        if not login_resp:
            return {"msg": "Login request failed after retries"}, None

        try:
            login_data = login_resp.json()
            if login_data.get("code") != 0:
                login_msg = login_data.get('msg', 'Unknown login error')
                return {"msg": f"Login failed: {login_msg}"}, None

            nickname = login_data.get("data", {}).get("nickname", "Unknown")

        except json.JSONDecodeError:
            return {"msg": "Login response invalid JSON"}, None

        # === Redeem Request ===
        redeem_payload = encode_data({
            "fid": fid,
            "cdk": cdk,
            "time": int(time.time() * 1000)
        })

        redeem_resp = make_request(REDEEM_URL, redeem_payload)

        if not redeem_resp:
            return {"msg": "Redemption request failed after retries"}, nickname

        try:
            return redeem_resp.json(), nickname
        except json.JSONDecodeError:
            return {"msg": "Redemption response invalid JSON"}, nickname

    except Exception as e:
        return {"msg": f"Unexpected Error: {str(e)}"}, None

# Thread worker function
def process_player(fid, code):
    try:
        result, nickname = redeem_gift_code(fid, code)
        raw_msg = result.get('msg', 'Unknown error').strip('.')
        friendly_msg = RESULT_MESSAGES.get(raw_msg, raw_msg)

        # Handle critical errors that should stop the script
        if raw_msg == "TIME ERROR":
            log("Code has expired! Script will now exit.")
            return "EXIT"
        elif raw_msg == "USED":
            log("Claim limit reached! Script will now exit.")
            return "EXIT"
        elif raw_msg == "RATE_LIMITED":
            log("Rate limit detected! Consider reducing thread count.")
            return "RATE_LIMITED"

        # Update counters based on result
        if raw_msg in ["RECEIVED", "SAME TYPE EXCHANGE"]:
            update_counter("already_redeemed")
        elif raw_msg == "SUCCESS":
            update_counter("success")
        elif raw_msg != "TIMEOUT RETRY":
            update_counter("errors")

        log(f"Player {nickname} ({fid}): {friendly_msg}")
        time.sleep(DELAY)  # Maintain some delay even with threading
        
        return raw_msg
    except Exception as e:
        log(f"Thread error for FID {fid}: {str(e)}")
        update_counter("errors")
        return "THREAD_ERROR"

# Read player IDs from a CSV file
def read_player_ids_from_csv(file_path):
    player_ids = []
    format_detected = "newline"
    try:
        with open(file_path, mode="r", newline="", encoding="utf-8-sig") as file:
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
        return []
    return player_ids

# Print summary of actions
def print_summary():
    log("\n=== Redemption Complete ===")
    log(f"Successfully redeemed: {counters['success']}")
    log(f"Already redeemed: {counters['already_redeemed']}")
    log(f"Errors/Failures: {counters['errors']}")
    log(f"Rate limited occurrences: {counters['rate_limited']}")
    log(f"Threads used: {args.threads}")

# Adaptive thread management
def adjust_thread_count(current_count, rate_limit_hits):
    if rate_limit_hits > 2:
        return max(1, current_count - 1)  # Reduce threads if rate limited
    elif rate_limit_hits == 0 and current_count < 5:
        return current_count + 1  # Carefully increase threads
    return current_count

# Main script
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Redeem gift codes for player IDs from a CSV file.")
    parser.add_argument("--csv", required=True, help="Path to the CSV file containing player IDs (or *.csv for all files in a folder).")
    parser.add_argument("--code", required=True, help="The gift code to redeem.")
    parser.add_argument("--threads", type=int, required=False, default=3, help="Max Threads (default: 3)")
    args = parser.parse_args()

    start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log(f"\n=== Starting redemption for gift code: {args.code} at {start_time} ===")
    log(f"Initial thread count: {args.threads}")

    if args.csv == "*.csv":
        csv_files = glob(os.path.join(script_dir, "*.csv"))
    else:
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

            current_thread_count = args.threads
            with ThreadPoolExecutor(max_workers=current_thread_count) as executor:
                futures = {executor.submit(process_player, fid, args.code): fid for fid in player_ids}
                should_exit = False
                
                for future in as_completed(futures):
                    if should_exit:
                        break
                        
                    fid = futures[future]
                    try:
                        result = future.result()
                        if result == "EXIT":
                            should_exit = True
                            # Cancel all pending tasks
                            for f in futures:
                                if not f.done():
                                    f.cancel()
                    except Exception as e:
                        log(f"Error processing FID {fid}: {str(e)}")
                        update_counter("errors")

                if should_exit:
                    print_summary()
                    sys.exit(1)

            # If we broke out to adjust thread count, restart with new count
            if current_thread_count != args.threads:
                log(f"Restarting with adjusted thread count: {current_thread_count}")
                with ThreadPoolExecutor(max_workers=current_thread_count) as executor:
                    remaining_ids = [fid for fid in player_ids if fid not in [futures[f] for f in futures if f.done()]]
                    futures = {executor.submit(process_player, fid, args.code): fid for fid in remaining_ids}
                    
                    for future in as_completed(futures):
                        fid = futures[future]
                        try:
                            result = future.result()
                            if result == "EXIT":
                                for future in futures:
                                    future.cancel()
                                executor.shutdown(wait=False)
                                print_summary()
                                sys.exit(1)
                        except Exception as e:
                            log(f"Error processing FID {fid}: {str(e)}")
                            update_counter("errors")

        except FileNotFoundError:
            log(f"Error: CSV file '{csv_file}' not found")
        except Exception as e:
            log(f"Error processing {csv_file}: {str(e)}")

    print_summary()