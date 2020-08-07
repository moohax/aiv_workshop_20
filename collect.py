import os
import re
import csv
import base64
from hashlib import md5
from subprocess import Popen, PIPE
from collections import namedtuple

# Define the path the PowerShellCorpus
scripts = 'C:\\Users\\will\\Desktop\\projects\\AIVillage_Adversarial\\PowerShellCorpus\\Github'

# Create the data structure for entries
ScoredEntry = namedtuple('ScoredEntry', 'name path hash content label')

# Create the regex to gather the score
re_score = re.compile(r'Scan result is \d+. IsMalware: \d+')

# Storage for all the entries
labeled_data = []

# Create our dataset 
# Traverse each subdirectory
for path in os.walk(scripts):

    if path[2]:
        for script in path[2]:

            # Get script path
            temp_path = (f'{path[0]}\\{script}')
            
            # Scan the content of the file
            process = Popen(['AmsiStream.exe', f'{temp_path}'], stdout=PIPE)
            (output, err) = process.communicate()
            exit_code = process.wait()
            
            if not output:
                continue
                
            # Collect the result
            try:
                result = re.findall(re_score, output.decode())[0]

            except Exception as e:
                #print(f'[!] Error: {e} ({temp_path})')
                continue
            
            # Get content of file
            with open(temp_path, 'r', errors='ignore') as f:
                content = f.read()
                content = base64.b64encode(content.encode())

            # Hash the content the look for duplicates later
            hashed = md5(content.encode()).hexdigest()
            
            # Create the entry
            labeled_entry = ScoredEntry(name=script, path=temp_path, hash=hashed, content=content.decode(), label=result)

            # Add it to the list
            labeled_data.append(labeled_entry)

            # Debug
            # if '32768' in result:
            #     print(f'[+] Malware {temp_path}')

        # Write the csv
        with open('amsi_data.csv', 'w', encoding='utf-8', newline='') as df:
            writer = csv.writer(df)
            writer.writerow(('name', 'hash', 'label', 'content'))
            writer.writerows([(entry.name, entry.hash, entry.label, entry.content) for entry in labeled_data])