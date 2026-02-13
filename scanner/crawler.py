from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import requests
from typing import List, Set
from utils.helpers import network_helper
import time

class WebCrawler:
    def __init__(self, max_depth: int = 3, max_pages: int = 20):
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.visited_urls: Set[str] = set()
        self.to_visit: List[tuple] = []  # (url, depth)
        self.found_urls: Set[str] = set()
        
    def extract_links(self, url: str, html_content: str) -> List[str]:
        """Extract all links from HTML content"""
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            links = []
            
            for link in soup.find_all('a', href=True):
                href = link['href']
                full_url = urljoin(url, href)
                
                # Only include HTTP/HTTPS URLs from same domain
                if self._is_valid_crawl_url(full_url, url):
                    links.append(full_url)
            
            return list(set(links))  # Remove duplicates
        except Exception as e:
            print(f"Error extracting links from {url}: {str(e)}")
            return []
    
    def _is_valid_crawl_url(self, url: str, base_url: str) -> bool:
        """Check if URL is valid for crawling"""
        try:
            url_parsed = urlparse(url)
            base_parsed = urlparse(base_url)
            
            # Same domain only
            if url_parsed.netloc != base_parsed.netloc:
                return False
            
            # Only HTTP/HTTPS
            if url_parsed.scheme not in ['http', 'https']:
                return False
            
            # Skip fragments and query parameters for basic crawling
            if url_parsed.fragment or url_parsed.query:
                return False
            
            return True
        except:
            return False
    
    def crawl(self, start_url: str) -> List[str]:
        """Crawl website up to max depth"""
        if not network_helper.is_valid_url(start_url):
            return []
        
        # Add starting URL
        self.to_visit.append((start_url, 0))
        self.found_urls.add(start_url)
        
        while self.to_visit and len(self.found_urls) < self.max_pages:
            current_url, depth = self.to_visit.pop(0)
            
            if current_url in self.visited_urls or depth >= self.max_depth:
                continue
            
            self.visited_urls.add(current_url)
            
            # Get page content
            content = network_helper.get_page_content(current_url)
            if not content:
                continue
            
            # Extract links
            links = self.extract_links(current_url, content)
            
            # Add new links to crawl queue
            for link in links:
                if link not in self.found_urls and link not in self.visited_urls:
                    self.found_urls.add(link)
                    if depth + 1 < self.max_depth:
                        self.to_visit.append((link, depth + 1))
            
            # Be respectful - add small delay
            time.sleep(0.1)
        
        return list(self.found_urls)

# Convenience function
def get_crawl_urls(url: str, max_depth: int = 3, max_pages: int = 20) -> List[str]:
    """Simple function to get URLs to scan"""
    crawler = WebCrawler(max_depth=max_depth, max_pages=max_pages)
    return crawler.crawl(url)