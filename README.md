# Whiteout Survival Gift Code Redemption Script

Python script that automates the process of redeeming gift codes in the game **Whiteout Survival**. It reads a list of Player IDs from one or more `.csv` files, sends requests to the game's giftcode redemption API, and redeems the specified gift code for each player.

---

## Features

- **Flexible CSV Import**: Reads player IDs from `.csv` files. Supports **both** formats:
    - One player ID per line.
    - Multiple player IDs on a single line, separated by commas (whitespace is ignored).
- **Command-Line Interface**: Accepts the `.csv` file path (or a directory, or `*.csv`) and gift code as arguments.
- **Error Handling**: Provides clear error messages for missing/invalid inputs and API responses.
- **Retry Logic**: Automatically retries failed requests when the server indicates temporary issues (e.g., `TIMEOUT RETRY`).
- **Verbose Logging**: Shows timestamp, player nickname (if available), and ID during processing. Logs all output to a file (`redeemed_codes.txt`).
- **Summary Report**: Provides a summary of successful redemptions, already redeemed codes, and errors at the end.
- **Rate Limiting**: Includes a configurable delay between requests to avoid triggering API rate limits.

---

## Prerequisites

1.  **Python 3.x**: Download and install Python from [python.org](https://www.python.org/). Ensure Python is added to your system's PATH during installation.
2.  **Required Libraries**: Install the necessary Python library using `pip` from your command line or terminal:
    ~~~bash
    pip install requests
    ~~~

---

## Setup

1.  **Get the Script**:
    *   Clone the repository:
        ~~~bash
        git clone https://github.com/justncodes/wos-giftcode.git
        cd wos-giftcode
        ~~~
    *   Or, download the `redeem_codes.py` script directly from the repository.

2.  **Prepare the CSV File(s)**:
    *   Create one or more `.csv` files (e.g., `player_ids.csv`).
    *   **Format**: You can list IDs in two ways (or even mix formats within a file, though keeping it consistent is recommended):
        *   **One ID per line:** Each player ID is on its own row.
        *   **Comma-separated IDs:** Multiple player IDs on the same line, separated by commas. Whitespace around the commas or IDs will be automatically removed.
    *   Place the `.csv` file(s) in the same directory as the script, or note the full path to provide as an argument.

    *   **Example `ids_newline.csv` (One ID per line):**
        ~~~csv
        57845354
        98765432
        12345678
        ~~~

    *   **Example `ids_comma.csv` (Comma-separated):**
        ~~~csv
        57845354, 98765432, 12345678
        44445555, 66667777
        ~~~

    *   **Example `ids_mixed.csv` (Mixed - also works):**
        ~~~csv
        57845354
        98765432, 12345678
        44445555,66667777,88889999
        11112222
        ~~~

---

## Usage

Run the script from your command line or terminal using `python`:

~~~bash
python redeem_codes.py --csv <path_or_pattern> --code <gift_code>
~~~

### Arguments

-   `--csv`: Specifies the player ID source. Can be:
    *   A path to a single `.csv` file (e.g., `player_ids.csv` or `C:\Users\You\Documents\ids.csv`).
    *   A path to a folder/directory containing `.csv` files (e.g., `/home/user/wos_ids/` or `.` for the current directory). The script will process all files ending in `.csv` within that folder.
    *   The pattern `*.csv` to process all `.csv` files located in the *same directory as the script itself*.
-   `--code`: The gift code you want to redeem (e.g., `WOS2025`).

### Examples

*   **Process a specific file in the current directory:**
    ~~~bash
    python redeem_codes.py --csv player_ids.csv --code ILoveWOS
    ~~~

*   **Process a specific file using its full path:**
    ~~~bash
    python redeem_codes.py --csv "/path/to/your/data/player_ids.csv" --code ILoveWOS
    ~~~

*   **Process all `.csv` files in a specific folder:**
    ~~~bash
    python redeem_codes.py --csv /path/to/your/folder --code ILoveWOS
    ~~~

*   **Process all `.csv` files located in the script's directory:**
    ~~~bash
    python redeem_codes.py --csv *.csv --code ILoveWOS
    ~~~

---

## Output

### Sample Run

~~~plaintext
2025-02-21 10:30:00 - === Starting redemption process at 2025-02-21 10:30:00 ===
2025-02-21 10:30:00 - Gift Code: ILoveWOS
2025-02-21 10:30:00 - Input Path/Pattern: ids_comma.csv
2025-02-21 10:30:00 - Log File: /path/to/script/redeemed_codes.txt
2025-02-21 10:30:00 - ------------------------------
2025-02-21 10:30:00 - Processing single CSV file: ids_comma.csv
2025-02-21 10:30:00 - Found 1 CSV file(s) to process: ids_comma.csv
2025-02-21 10:30:00 -
--- Processing file: ids_comma.csv ---
2025-02-21 10:30:00 - Reading ids_comma.csv (detected format: comma-separated)
2025-02-21 10:30:00 - Loaded 5 player IDs.
2025-02-21 10:30:00 - --- [File 1/1, ID 1/5] ---
2025-02-21 10:30:00 - Processing PlayerOne (57845354)
2025-02-21 10:30:01 - Result for 57845354: Successfully redeemed
2025-02-21 10:30:02 - --- [File 1/1, ID 2/5] ---
2025-02-21 10:30:02 - Processing PlayerTwo (98765432)
2025-02-21 10:30:03 - Result for 98765432: Already redeemed
2025-02-21 10:30:04 - --- [File 1/1, ID 3/5] ---
2025-02-21 10:30:04 - Processing PlayerThree (12345678)
2025-02-21 10:30:04 - Result for 12345678: Successfully redeemed
2025-02-21 10:30:05 - --- [File 1/1, ID 4/5] ---
2025-02-21 10:30:05 - Processing PlayerFour (44445555)
2025-02-21 10:30:06 - Result for 44445555: Unknown/Other (INVALID PLAYER)
2025-02-21 10:30:07 - --- [File 1/1, ID 5/5] ---
2025-02-21 10:30:07 - Processing PlayerFive (66667777)
2025-02-21 10:30:07 - Login failed for 66667777: Code 1001, Message: Login failed
2025-02-21 10:30:07 - Result for 66667777: Login failed: Login failed
2025-02-21 10:30:08 - --- Finished processing file: ids_comma.csv ---
2025-02-21 10:30:08 - ------------------------------
2025-02-21 10:30:08 - Processed 1 file(s) containing a total of 5 potential IDs.
2025-02-21 10:30:08 -
=== Redemption Complete ===
2025-02-21 10:30:08 - Successfully redeemed: 2
2025-02-21 10:30:08 - Already redeemed/Same Type: 1
2025-02-21 10:30:08 - Errors/Failures: 2
2025-02-21 10:30:08 - === Redemption process finished at 2025-02-21 10:30:08 ===
~~~

### Logging

All console output is automatically appended to a log file named `redeemed_codes.txt`, created in the same directory where the script is run.

---

## Troubleshooting

1.  **`pip` command not found**: Ensure Python is installed correctly and its `Scripts` directory (Windows) or equivalent (macOS/Linux) is in your system's PATH environment variable.
2.  **ModuleNotFoundError**: Make sure you've installed the required libraries (`pip install requests`).
3.  **CSV File Not Found**: Verify the path provided with `--csv` is correct. Check for typos. If using `*.csv` or a folder path, ensure `.csv` files actually exist there.
4.  **Permission Denied (Log File)**: Ensure the script has permission to write files in the directory it's running from. Try running the terminal/command prompt as an administrator (use with caution).
5.  **Code Expired / Claim Limit Reached**: The script will detect these specific API responses (`TIME ERROR`, `USED`) and stop execution, logging the reason. Verify the gift code's validity.
6.  **API Rate Limiting / `TIMEOUT RETRY` failures**: If you see many `Server requested retry` messages followed by failures, the API might be temporarily overloaded or you might be sending requests too quickly. Try increasing the `DELAY` value (in seconds) near the top of the script file (e.g., `DELAY = 2`).

---

## Changelog


### v2.2.0 (Current Version)
- Added support for reading comma-separated player IDs within CSV files.
- Improved CSV file path handling in `--csv` argument (folder path, `*.csv` pattern).
- Enhanced logging detail and error categorization.

### v2.1.0
- Added support for processing all .csv files in a folder or the script's directory using `*.csv`.
- Improved error handling for missing or invalid .csv files.

### v2.0.0
- Added retry logic for failed requests (e.g., `TIMEOUT RETRY`).
- Display player nicknames during processing.
- Added Unicode support for special characters and foreign alphabets.
- Added a summary report of redemptions at the end.
- Improved error handling and logging.

### v1.0.0 (Initial Release)
- Basic functionality: CSV import (newline separated), command-line args, API requests.
- Initial error handling and rate limiting.

---

## Credits

- **Author**: justncodes (\[SIR\] Yolo on #340)
- **Repository**: [wos-giftcode](https://github.com/justncodes/wos-giftcode)

---

## Support

If you encounter any issues or have questions, feel free to open an issue on the [GitHub repository](https://github.com/justncodes/wos-giftcode/issues).

---

## License

This project is licensed under the GPLv3 License. See the `LICENSE` file for details.