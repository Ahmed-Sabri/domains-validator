import pandas as pd
import dns.resolver

# Load the Excel file
df = pd.read_excel('/home/ahmedz/Downloads/root.xlsx')

print("Loaded Excel file with", len(df), "rows")

# Create a new column to store the results
df['A RECORD'] = ''
df['NS RECORD'] = ''
df['STATUS'] = ''

# Process each domain
for index, row in df.iterrows():
  domain = row['Domain']
  print("Processing domain:", domain)
  try:
	  answers = dns.resolver.resolve(domain, 'A')
	  a_record = ', '.join([str(rdata) for rdata in answers])
	  answers = dns.resolver.resolve(domain, 'NS')
	  ns_record = ', '.join([str(rdata) for rdata in answers])
	  df.at[index, 'A RECORD'] = a_record
	  df.at[index, 'NS RECORD'] = ns_record
	  if '5.9.90.154' in a_record or 'hosterz.net' in ns_record:
		  df.at[index, 'STATUS'] = 'Valid'
	  else:
		  df.at[index, 'STATUS'] = 'Invalid'
  except dns.resolver.NXDOMAIN:
	  print(f"Domain {domain} does not exist. Skipping...")
	  df.at[index, 'STATUS'] = 'Domain does not exist'
  except dns.resolver.NoAnswer:
	  print(f"Domain {domain} did not return an answer. Skipping...")
	  df.at[index, 'STATUS'] = 'No answer'

# Save the updated Excel file
df.to_excel('/home/ahmedz/Downloads/root_updated.xlsx', index=False)

print("Updated Excel file saved to root_updated.xlsx")

# Check if all domains were processed
if len(df) == len(df.dropna()):
  print("All domains were processed successfully!")
else:
  print("Not all domains were processed. Check the output file for errors."
