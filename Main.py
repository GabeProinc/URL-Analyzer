import tkinter as tk
from tkinter import messagebox
import customtkinter as ctk
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import re
import socket
import ssl
import whois
from datetime import datetime

class UrlAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("URL Analyzer")
        self.root.geometry("900x700")
        ctk.set_appearance_mode("System")
        ctk.set_default_color_theme("blue")

        self.main_frame = ctk.CTkFrame(self.root, corner_radius=10)
        self.main_frame.pack(pady=20, padx=20, fill="both", expand=True)

        self.credits_label = ctk.CTkLabel(self.main_frame, text="Created by GabeProInc, September 08, 2025", font=("Helvetica", 12, "italic"), text_color="gray")
        self.credits_label.pack(pady=(0, 10))

        self.url_label = ctk.CTkLabel(self.main_frame, text="Enter Website URL (e.g., example.com):", font=("Helvetica", 16))
        self.url_label.pack(pady=(10, 5))
        self.url_entry = ctk.CTkEntry(self.main_frame, width=500, height=40, font=("Helvetica", 14), placeholder_text="https://example.com")
        self.url_entry.pack(pady=5)

        self.analyze_button = ctk.CTkButton(self.main_frame, text="Analyze Website", command=self.analyze_url, height=40, font=("Helvetica", 14), corner_radius=8)
        self.analyze_button.pack(pady=10)

        self.status_label = ctk.CTkLabel(self.main_frame, text="", font=("Helvetica", 12), text_color="gray")
        self.status_label.pack(pady=5)

        self.tab_view = ctk.CTkTabview(self.main_frame, height=450, corner_radius=10)
        self.tab_view.pack(pady=10, fill="both", expand=True)
        self.tab_view.add("Overview")
        self.tab_view.add("Links")
        self.tab_view.add("WHOIS & SSL")

        self.overview_text = ctk.CTkTextbox(self.tab_view.tab("Overview"), height=400, font=("Helvetica", 12), wrap="word")
        self.overview_text.pack(pady=10, padx=10, fill="both", expand=True)
        self.overview_text.configure(state="disabled")

        self.links_text = ctk.CTkTextbox(self.tab_view.tab("Links"), height=400, font=("Helvetica", 12), wrap="word")
        self.links_text.pack(pady=10, padx=10, fill="both", expand=True)
        self.links_text.configure(state="disabled")

        self.whois_ssl_text = ctk.CTkTextbox(self.tab_view.tab("WHOIS & SSL"), height=400, font=("Helvetica", 12), wrap="word")
        self.whois_ssl_text.pack(pady=10, padx=10, fill="both", expand=True)
        self.whois_ssl_text.configure(state="disabled")

    def analyze_url(self):
        url = self.url_entry.get().strip()
        if not url:
            self.show_error("E001", "No URL entered. Please type a website address, like example.com.")
            return

        self.status_label.configure(text="Analyzing website...", text_color="blue")
        self.clear_results()

        try:
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url

            result = {
                'url': url,
                'timestamp': datetime.now().isoformat(),
                'details': {}
            }

            parsed_url = urlparse(url)
            result['details']['scheme'] = parsed_url.scheme
            result['details']['hostname'] = parsed_url.hostname

            try:
                ip_address = socket.gethostbyname(parsed_url.hostname)
                geo_response = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=5)
                geo_response.raise_for_status()
                geo_data = geo_response.json()
                result['details']['location'] = {
                    'city': geo_data.get('city', 'N/A'),
                    'country': geo_data.get('country', 'N/A'),
                    'isp': geo_data.get('isp', 'N/A')
                }
            except Exception as e:
                result['details']['location'] = f"Unable to determine location: {str(e)}"

            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()

            result['details']['http_status'] = response.status_code
            result['details']['response_time'] = response.elapsed.total_seconds()

            soup = BeautifulSoup(response.text, 'html.parser')

            result['details']['title'] = soup.title.string.strip() if soup.title else 'No title found'

            meta_author = soup.find('meta', attrs={'name': re.compile(r'author', re.I)})
            meta_og_site = soup.find('meta', attrs={'property': re.compile(r'og:site_name', re.I)})
            result['details']['creator'] = meta_author['content'] if meta_author and meta_author.get('content') else (
                meta_og_site['content'] if meta_og_site and meta_og_site.get('content') else 'Unknown')

            meta_desc = soup.find('meta', attrs={'name': re.compile(r'description', re.I)})
            result['details']['meta_description'] = meta_desc['content'] if meta_desc and meta_desc.get('content') else 'No description found'

            favicon = soup.find('link', rel=re.compile(r'icon', re.I))
            result['details']['favicon'] = favicon['href'] if favicon and favicon.get('href') else 'No favicon found'

            try:
                robots_response = requests.get(f"{parsed_url.scheme}://{parsed_url.hostname}/robots.txt", headers=headers, timeout=5)
                result['details']['robots_txt'] = 'Available' if robots_response.status_code == 200 else 'Not found'
            except:
                result['details']['robots_txt'] = 'Not found'
            try:
                sitemap_response = requests.get(f"{parsed_url.scheme}://{parsed_url.hostname}/sitemap.xml", headers=headers, timeout=5)
                result['details']['sitemap'] = 'Available' if sitemap_response.status_code == 200 else 'Not found'
            except:
                result['details']['sitemap'] = 'Not found'

            links = {'internal': [], 'external': []}
            for link in soup.find_all('a', href=True):
                href = link['href']
                try:
                    if href.startswith(('http://', 'https://')):
                        link_host = urlparse(href).hostname
                        if link_host == parsed_url.hostname:
                            links['internal'].append(href)
                        else:
                            links['external'].append(href)
                    elif href.startswith('/'):
                        links['internal'].append(url + href)
                    else:
                        links['internal'].append(url + '/' + href)
                except:
                    continue
            result['details']['links'] = links

            result['details']['image_count'] = len([img for img in soup.find_all('img') if img.get('src')])

            text = soup.get_text()
            words = re.findall(r'\w+', text)
            result['details']['word_count'] = len(words)

            if parsed_url.scheme == 'https':
                try:
                    context = ssl.create_default_context()
                    with socket.create_connection((parsed_url.hostname, 443)) as sock:
                        with context.wrap_socket(sock, server_hostname=parsed_url.hostname) as ssock:
                            cert = ssock.getpeercert()
                            result['details']['ssl_info'] = {
                                'issuer': cert.get('issuer', 'N/A'),
                                'notAfter': cert.get('notAfter', 'N/A')
                            }
                except Exception as e:
                    result['details']['ssl_info'] = f"Unable to check security certificate: {str(e)}"

            try:
                whois_info = whois.whois(parsed_url.hostname)
                result['details']['whois'] = {
                    'domain_name': whois_info.domain_name or 'N/A',
                    'registrar': whois_info.registrar or 'N/A',
                    'organization': whois_info.org or 'N/A',
                    'creation_date': str(whois_info.creation_date) or 'N/A',
                    'expiration_date': str(whois_info.expiration_date) or 'N/A'
                }
                if result['details']['creator'] == 'Unknown' and whois_info.org:
                    result['details']['creator'] = whois_info.org
            except Exception as e:
                result['details']['whois'] = f"Unable to get domain info: {str(e)}"

            self.display_results(result)
            self.status_label.configure(text="Analysis complete!", text_color="green")

        except requests.exceptions.RequestException as e:
            self.show_error("E002", f"Couldn’t connect to the website: {str(e)}. Check the URL or your internet connection.")
            self.status_label.configure(text="Analysis failed", text_color="red")
        except Exception as e:
            self.show_error("E003", f"Something went wrong: {str(e)}. Try again or check the URL.")
            self.status_label.configure(text="Analysis failed", text_color="red")

    def show_error(self, code, message):
        messagebox.showerror("Error", f"Error {code}: {message}")

    def clear_results(self):
        for text_widget in [self.overview_text, self.links_text, self.whois_ssl_text]:
            text_widget.configure(state="normal")
            text_widget.delete(1.0, tk.END)
            text_widget.configure(state="disabled")

    def display_results(self, result):
        self.overview_text.configure(state="normal")
        self.overview_text.insert(tk.END, f"Website: {result['url']}\n")
        self.overview_text.insert(tk.END, f"Analyzed on: {result['timestamp']}\n\n")
        self.overview_text.insert(tk.END, f"Title: {result['details']['title']}\n")
        self.overview_text.insert(tk.END, f"Description: {result['details']['meta_description']}\n")
        self.overview_text.insert(tk.END, f"Creator/Organization: {result['details']['creator']}\n")
        if isinstance(result['details']['location'], dict):
            self.overview_text.insert(tk.END, f"Server Location: {result['details']['location']['city']}, {result['details']['location']['country']} (ISP: {result['details']['location']['isp']})\n")
        else:
            self.overview_text.insert(tk.END, f"Server Location: {result['details']['location']}\n")
        self.overview_text.insert(tk.END, f"Status Code: {result['details']['http_status']} (OK if 200)\n")
        self.overview_text.insert(tk.END, f"Response Time: {result['details']['response_time']:.3f} seconds\n")
        self.overview_text.insert(tk.END, f"Word Count: {result['details']['word_count']} words\n")
        self.overview_text.insert(tk.END, f"Images: {result['details']['image_count']} images\n")
        self.overview_text.insert(tk.END, f"Favicon: {result['details']['favicon']}\n")
        self.overview_text.insert(tk.END, f"Robots.txt: {result['details']['robots_txt']}\n")
        self.overview_text.insert(tk.END, f"Sitemap: {result['details']['sitemap']}\n")
        self.overview_text.configure(state="disabled")

        self.links_text.configure(state="normal")
        self.links_text.insert(tk.END, f"Internal Links ({len(result['details']['links']['internal'])}):\n")
        for link in result['details']['links']['internal'][:10]:
            self.links_text.insert(tk.END, f" - {link}\n")
        if len(result['details']['links']['internal']) > 10:
            self.links_text.insert(tk.END, f"... and {len(result['details']['links']['internal']) - 10} more\n")
        self.links_text.insert(tk.END, f"\nExternal Links ({len(result['details']['links']['external'])}):\n")
        for link in result['details']['links']['external'][:10]:
            self.links_text.insert(tk.END, f" - {link}\n")
        if len(result['details']['links']['external']) > 10:
            self.links_text.insert(tk.END, f"... and {len(result['details']['links']['external']) - 10} more\n")
        self.links_text.configure(state="disabled")

        self.whois_ssl_text.configure(state="normal")
        if isinstance(result['details']['whois'], dict):
            self.whois_ssl_text.insert(tk.END, "Domain Information:\n")
            self.whois_ssl_text.insert(tk.END, f"Domain Name: {result['details']['whois']['domain_name']}\n")
            self.whois_ssl_text.insert(tk.END, f"Registrar: {result['details']['whois']['registrar']}\n")
            self.whois_ssl_text.insert(tk.END, f"Organization: {result['details']['whois']['organization']}\n")
            self.whois_ssl_text.insert(tk.END, f"Created On: {result['details']['whois']['creation_date']}\n")
            self.whois_ssl_text.insert(tk.END, f"Expires On: {result['details']['whois']['expiration_date']}\n")
        else:
            self.whois_ssl_text.insert(tk.END, f"Domain Information: {result['details']['whois']}\n")
        self.whois_ssl_text.insert(tk.END, "\nSecurity Certificate (SSL):\n")
        if isinstance(result['details']['ssl_info'], dict):
            self.whois_ssl_text.insert(tk.END, f"Issuer: {result['details']['ssl_info']['issuer']}\n")
            self.whois_ssl_text.insert(tk.END, f"Valid Until: {result['details']['ssl_info']['notAfter']}\n")
        else:
            self.whois_ssl_text.insert(tk.END, f"{result['details']['ssl_info']}\n")
        self.whois_ssl_text.configure(state="disabled")

if __name__ == "__main__":
    ctk.set_appearance_mode("System")
    root = ctk.CTk()
    app = UrlAnalyzerApp(root)
    root.mainloop()
