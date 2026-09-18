# Domain Validator

A Python utility that reads a list of domains from an Excel spreadsheet, resolves their DNS A and NS records, and checks whether they match expected values. The script then writes the results back into a new Excel file with validation status for each domain.

## Features

- Reads domains from an Excel file
- Resolves DNS A records
- Resolves DNS NS records
- Validates results against expected values
- Writes updated results to a new Excel file
- Logs progress and warnings for unresolved or invalid records

## Use Case

This tool is useful for verifying whether domains are correctly configured to point to a known IP address and/or nameserver substring. It is especially handy for bulk domain checks in spreadsheet-based workflows.

## Requirements

- Python 3.9+
- pandas
- dnspython

Install dependencies:

```bash
pip install pandas dnspython openpyxl
```

## Project Structure

```text
domains-validator/
├── domains-validator.py
├── README.md
└── (input/output Excel files in your configured paths)
```

## Configuration

Open `domains-validator.py` and update these values before running the script:

```python
EXCEL_INPUT_PATH = '/mnt/c/Users/a/rootz.xlsx'
EXCEL_OUTPUT_PATH = '/mnt/c/Users/a/root_updated.xlsx'

EXPECTED_IP = '37.27.108.238'
EXPECTED_NS_SUBSTRING = 'hosterz.net'
```

### Meaning of the configuration

- `EXCEL_INPUT_PATH`: The Excel file containing the domains to validate
- `EXCEL_OUTPUT_PATH`: The file where the updated results will be saved
- `EXPECTED_IP`: Required A record value to match
- `EXPECTED_NS_SUBSTRING`: Required NS record substring to match

## Expected Excel Input Format

The script expects an Excel file with a column named `Domain`.

Example:

| Domain |
|--------|
| example.com |
| sample.net |
| mydomain.org |

If a row has an empty or missing domain, the script marks it as:

```text
Empty domain
```

## How It Works

The script does the following for each row:

1. Reads the domain from the `Domain` column
2. Resolves the domain’s A record using DNS
3. Resolves the domain’s NS record using DNS
4. Checks whether the returned values match the configured expectations
5. Stores the results in new columns:
   - `A RECORD`
   - `NS RECORD`
   - `STATUS`
6. Saves the updated workbook to the output path

## Status Logic

The validation uses this logic:

- If both A and NS records are missing, it returns:
  - `Domain does not exist or no records found`
- If the A record contains the expected IP, or the NS record contains the expected NS substring, it returns:
  - `Valid`
- Otherwise it returns:
  - `Invalid`

## Example Output

After processing, the spreadsheet will include output similar to:

| Domain | A RECORD | NS RECORD | STATUS |
|--------|----------|-----------|--------|
| example.com | 93.184.216.34 | ns1.example.com, ns2.example.com | Valid |
| fake-domain.xyz |  |  | Domain does not exist or no records found |
|  |  |  | Empty domain |

## Running the Script

From the project directory:

```bash
python domains-validator.py
```

The script will:

- open the Excel input file
- validate each domain
- save the output to the configured Excel output path
- log activity to the console

## Logging

The script uses Python’s `logging` module with standard INFO-level output. It logs:

- file loaded successfully
- each domain being processed
- completion status
- warnings for domains that could not be processed successfully

## Error Handling

The script gracefully handles common DNS errors such as:

- NXDOMAIN
- NoAnswer
- general DNS exceptions

If DNS cannot resolve a record, it returns an empty value instead of crashing.

## Notes

- This script assumes a specific environment path (`/mnt/c/...`) and may need updates for your operating system or filesystem layout.
- It is designed for a fixed validation pattern and may need modification if your expected DNS values or columns differ.
- The script uses `pandas` to read and write Excel files. If you use `.xlsx` files, ensure that the required Excel engine is installed.

## Troubleshooting

### 1. Module not found: pandas or dns

Install dependencies:

```bash
pip install pandas dnspython openpyxl
```

### 2. File not found error

Check that the input path exists and that the file name is correct.

### 3. No domains validated

Confirm that the Excel file includes a column named `Domain` exactly as spelled.

### 4. Incorrect validation results

Verify that:

- the DNS values are correct
- the expected IP and NS substring match your target setup
- the domain names are properly formatted without hidden spaces

## License

This project does not currently include a license file. If you plan to share or distribute it publicly, consider adding an appropriate license such as MIT.

## Author

Ahmed Sabri

## Repository URL

https://github.com/Ahmed-Sabri/domains-validator

## Summary

This tool helps you quickly validate a batch of domains in Excel format by checking their DNS A and NS records against expected values. It is ideal for bulk DNS verification and spreadsheet-based domain audits.
