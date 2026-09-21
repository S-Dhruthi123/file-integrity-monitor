import os
import hashlib
import json
import time
from pathlib import Path

BASELINE_FILE = "baseline.json"
TARGET_DIR = "./test_folder"

def calculate_hash(file_path):
    # This function calculates the fingerprint (SHA-256)
    sha256 = hashlib.sha256()
    try:
        # 'rb' means read as binary (not text)
        # We read in 4096 byte chunks so big files don't crash RAM
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest() # returns 64 char code
    except:
        return None

def scan_folder(folder_path):
    # os.walk goes into main folder and ALL subfolders (Bonus feature)
    file_hashes = {}
    for root, _, files in os.walk(folder_path):
        for file in files:
            full_path = os.path.join(root, file)
            # Don't hash the baseline file itself
            if os.path.abspath(full_path) == os.path.abspath(BASELINE_FILE):
                continue
            # rel_path = file name relative to test_folder
            rel_path = os.path.relpath(full_path, folder_path)
            file_hash = calculate_hash(full_path)
            if file_hash:
                file_hashes[rel_path] = file_hash
    return file_hashes

def create_baseline():
    print(f"[+] Scanning {TARGET_DIR} for baseline...")
    hashes = scan_folder(TARGET_DIR)
    # Save hashes to a JSON file (our notebook)
    with open(BASELINE_FILE, 'w') as f:
        json.dump(hashes, f, indent=4)
    
    # BONUS: Protect baseline file itself from tampering
    baseline_hash = calculate_hash(BASELINE_FILE)
    with open(BASELINE_FILE + ".sha256", 'w') as f:
        f.write(baseline_hash)
    print(f"[+] Baseline saved with {len(hashes)} files.")

def check_integrity():
    # BONUS: First check if attacker changed our notebook
    if os.path.exists(BASELINE_FILE + ".sha256"):
        with open(BASELINE_FILE + ".sha256", 'r') as f:
            stored_hash = f.read().strip()
        current_hash = calculate_hash(BASELINE_FILE)
        if stored_hash != current_hash:
            print("[!] CRITICAL: Baseline file has been TAMPERED!")
            return

    if not os.path.exists(BASELINE_FILE):
        print("[-] No baseline found. Run with --baseline first.")
        return

    with open(BASELINE_FILE, 'r') as f:
        baseline = json.load(f) # Load old fingerprints

    current = scan_folder(TARGET_DIR) # Take new fingerprints

    modified, added, deleted = [], [], []

    # Logic for DELETED and MODIFIED
    for file_path, old_hash in baseline.items():
        if file_path not in current:
            deleted.append(file_path)
        elif current[file_path] != old_hash:
            modified.append(file_path)

    # Logic for ADDED
    for file_path in current:
        if file_path not in baseline:
            added.append(file_path)

    print("\n--- INTEGRITY REPORT ---")
    if not modified and not added and not deleted:
        print("[OK] No changes detected.")
    else:
        if modified: print(f"[!] MODIFIED ({len(modified)}): {modified}")
        if added: print(f"[+] ADDED ({len(added)}): {added}")
        if deleted: print(f"[-] DELETED ({len(deleted)}): {deleted}")
    print("------------------------\n")

# This part handles command line arguments like --baseline
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="File Integrity Monitor")
    parser.add_argument('--baseline', action='store_true', help='Create baseline')
    parser.add_argument('--check', action='store_true', help='Check integrity')
    parser.add_argument('--monitor', type=int, help='Monitor every N seconds')
    args = parser.parse_args()

    Path(TARGET_DIR).mkdir(exist_ok=True)

    if args.baseline:
        create_baseline()
    elif args.monitor:
        print(f"[*] Monitoring every {args.monitor}s. Press Ctrl+C to stop.")
        try:
            while True:
                check_integrity()
                time.sleep(args.monitor)
        except KeyboardInterrupt:
            print("\n[*] Stopped.")
    else:
        check_integrity()
