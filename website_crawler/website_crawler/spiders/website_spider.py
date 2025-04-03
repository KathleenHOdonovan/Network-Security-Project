import scrapy
import csv
import re
import json
from urllib.parse import urlparse, urljoin

#can be run with the following command: scrapy crawl website_spider -o output.json

class WebsiteSpiderSpider(scrapy.Spider):
    name = "website_spider"
    allowed_domains = []  # Dynamically set based on input URLs
    max_depth = 2  # Adjust crawling depth

    # Read URLs from the CSV file
    def start_requests(self):
        with open('/u/zsx4ey/NetworkSec/Project/clean_urls.csv', newline='', encoding='utf-8') as csvfile:
            csvreader = csv.DictReader(csvfile)
            for row in csvreader:
                # Each row contains a URL and label
                url = row['url']
                label = row['label']

                # Skip crawling malware sites
                if label.lower() == "malware":
                    self.logger.warning(f"Skipping malware site: {url}")
                    continue  # Don't request this URL


                # Dynamically allow domains from input URLs
                parsed_url = urlparse(url)
                self.allowed_domains.append(parsed_url.netloc)

                
                
                # Pass the URL and label to the parse method
                yield scrapy.Request(url=url, callback=self.parse, meta={'label': label, 'depth': 0})

    def parse(self, response):
        #extract relevant data from the webpage to determine if the webpage is malicious
        #example: url, title, meta_data, text, javascript, forms

     #"""Extract features from the webpage and follow links."""
        url = response.url
        label = response.meta['label']
        depth = response.meta['depth']  # Track crawl depth

        # Extract website features
        features = {
            "url": url,
            "label": label,
            "domain_length": len(urlparse(url).netloc),
            "num_subdomains": urlparse(url).netloc.count("."),
            "has_https": urlparse(url).scheme == "https",
            "num_special_chars": len(re.findall(r"[@\-_%~]", url)),
            "title": response.css("title::text").get(),
            "meta_description": response.css("meta[name='description']::attr(content)").get(),
            "text": self.extract_text(response),
            "num_scripts": len(response.css("script")),
            "num_iframes": len(response.css("iframe")),
            "num_external_links": len([link for link in response.css("a::attr(href)").getall() if link.startswith("http")]),
            "has_obfuscated_js": self.detect_obfuscated_js(response),
            #"domain_age": self.get_domain_age(url),
        }

        yield features  # Output the extracted features

        # Follow links if within max depth
        if depth < self.max_depth:
            for link in response.css("a::attr(href)").getall():
                absolute_link = urljoin(response.url, link)
                if self.is_valid_url(absolute_link):
                    yield scrapy.Request(
                        url=absolute_link,
                        callback=self.parse,
                        meta={'label': label, 'depth': depth + 1}  # Increase depth
                    )

    def extract_text(self, response):
        #"""Extract visible text from the webpage."""
        raw_text = response.css("body *::text").getall()
        return " ".join(raw_text).strip()[:500]

    def detect_obfuscated_js(self, response):
        #"""Detect if the page contains obfuscated JavaScript (Base64 encoding)."""
        scripts = response.css("script::text").getall()
        return any("eval(" in script and "base64" in script for script in scripts)

    # def get_domain_age(self, url):
    #     #"""(Optional) Get domain age using WHOIS lookup. Requires API or WHOIS query."""
    #     return "unknown"

    def is_valid_url(self, url):
        #"""Check if a URL should be followed (same domain, not a file, etc.)."""
        parsed = urlparse(url)
        if parsed.netloc in self.allowed_domains and not parsed.path.endswith(('.jpg', '.png', '.pdf', '.zip')):
            return True
        return False