import pandas as pd
import dns.resolver
import logging
from typing import Tuple, Optional

# --- Configuration ---
EXCEL_INPUT_PATH = '/mnt/c/Users/a/rootz.xlsx'
EXCEL_OUTPUT_PATH = '/mnt/c/Users/a/root_updated.xlsx'

EXPECTED_IP = '37.27.108.238'
EXPECTED_NS_SUBSTRING = 'hosterz.net'

# --- Logging setup ---
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

def resolve_a_record(domain: str) -> Optional[str]:
    """Resolve A record for a domain."""
    try:
        answers = dns.resolver.resolve(domain, 'A')
        return ', '.join(str(rdata) for rdata in answers)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        return None

def resolve_ns_record(domain: str) -> Optional[str]:
    """Resolve NS record for a domain."""
    try:
        answers = dns.resolver.resolve(domain, 'NS')
        return ', '.join(str(rdata).rstrip('.') for rdata in answers)  # Remove trailing dot
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        return None

def determine_status(a_record: Optional[str], ns_record: Optional[str]) -> str:
    """Determine domain status based on A and NS records."""
    if a_record is None and ns_record is None:
        return "Domain does not exist or no records found"
    if (a_record and EXPECTED_IP in a_record) or (ns_record and EXPECTED_NS_SUBSTRING in ns_record):
        return "Valid"
    return "Invalid"

def process_domain(domain: str) -> Tuple[str, str, str]:
    """Process a single domain and return A, NS, and status."""
    logging.info(f"Processing domain: {domain}")
    
    a_record = resolve_a_record(domain)
    ns_record = resolve_ns_record(domain)
    status = determine_status(a_record, ns_record)
    
    return (
        a_record or '',
        ns_record or '',
        status
    )

def main():
    # Load data
    df = pd.read_excel(EXCEL_INPUT_PATH)
    logging.info(f"Loaded Excel file with {len(df)} rows")

    # Initialize result columns
    df['A RECORD'] = ''
    df['NS RECORD'] = ''
    df['STATUS'] = ''

    # Process each domain
    for idx, row in df.iterrows():
        domain = str(row['Domain']).strip()
        if not domain:
            df.at[idx, 'STATUS'] = 'Empty domain'
            continue

        a_rec, ns_rec, status = process_domain(domain)
        df.at[idx, 'A RECORD'] = a_rec
        df.at[idx, 'NS RECORD'] = ns_rec
        df.at[idx, 'STATUS'] = status

    # Save result
    df.to_excel(EXCEL_OUTPUT_PATH, index=False)
    logging.info(f"Updated Excel file saved to {EXCEL_OUTPUT_PATH}")

    # Final check
    unprocessed = df['STATUS'].isin(['Empty domain', 'Domain does not exist or no records found'])
    if unprocessed.any():
        logging.warning("Some domains were not processed successfully. Check the output file.")
    else:
        logging.info("All domains processed successfully!")

if __name__ == "__main__":
    main()
