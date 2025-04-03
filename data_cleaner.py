import csv
import validators

def is_valid_url(url):
    return validators.url(url)

def preprocess_csv(input_file, output_file):
    with open(input_file, mode='r', encoding='utf-8') as infile, \
         open(output_file, mode='w', encoding='utf-8', newline='') as outfile:
        
        reader = csv.DictReader(infile)
        fieldnames = reader.fieldnames
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()
        
        for row in reader:
            url = row['url']
            label = row['type'].strip().lower()  # Make label lowercase

            if not url.startswith('http://') and not url.startswith('https://'):
                row['url'] = 'http://' + url  # Add default protocol
                url = row['url']
            
            # Check if URL is valid and add "http://" if missing
            if not is_valid_url(url):
                continue  # Skip invalid URLs
            
            
            
            # Write cleaned row to output file
            row['type'] = label
            # row['url'] = f'"{row["url"]}"'  
            writer.writerow(row)

preprocess_csv('testData.csv', 'clean_urls.csv')