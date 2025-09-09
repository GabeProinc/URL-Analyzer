import sys
from PyQt5.QtCore import QUrl, Qt
from PyQt5.QtWidgets import QMainWindow, QApplication, QToolBar, QAction, QLineEdit, QStatusBar, QTabWidget, QTextEdit, QMessageBox, QProgressBar
from PyQt5.QtWebEngineWidgets import QWebEngineView
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import re
import socket
import ssl
import whois
from datetime import datetime

class MainWindow(QMainWindow):
    def __init__(self):
        super(MainWindow, self).__init__()
        self.setWindowTitle("Epic Browser & Analyzer")
        self.setGeometry(100, 100, 1000, 800)

        self.central_widget = QTabWidget()
        self.setCentralWidget(self.central_widget)

        self.browser_tab = QWebEngineView()
        self.browser_tab.setUrl(QUrl("http://google.com"))
        self.browser_tab.urlChanged.connect(self.update_urlbar)
        self.browser_tab.loadFinished.connect(self.update_title)
        self.central_widget.addTab(self.browser_tab, "Browser")

        self.overview_text = QTextEdit()
        self.overview_text.setReadOnly(True)
        self.overview_text.setFontFamily("Helvetica")
        self.overview_text.setFontPointSize(12)
        self.central_widget.addTab(self.overview_text, "Overview")

        self.links_text = QTextEdit()
        self.links_text.setReadOnly(True)
        self.links_text.setFontFamily("Helvetica")
        self.links_text.setFontPointSize(12)
        self.central_widget.addTab(self.links_text, "Links")

        self.whois_ssl_text = QTextEdit()
        self.whois_ssl_text.setReadOnly(True)
        self.whois_ssl_text.setFontFamily("Helvetica")
        self.whois_ssl_text.setFontPointSize(12)
        self.central_widget.addTab(self.whois_ssl_text, "WHOIS & SSL")

        self.status = QStatusBar()
        self.setStatusBar(self.status)
        self.status.showMessage("Created by GabeProInc, September 08, 2025")

        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximumWidth(200)
        self.progress_bar.setVisible(False)
        self.status.addPermanentWidget(self.progress_bar)

        navtb = QToolBar("Navigation")
        self.addToolBar(navtb)

        back_btn = QAction("Back", self)
        back_btn.setStatusTip("Back to previous page")
        back_btn.triggered.connect(self.browser_tab.back)
        navtb.addAction(back_btn)

        next_btn = QAction("Forward", self)
        next_btn.setStatusTip("Forward to next page")
        next_btn.triggered.connect(self.browser_tab.forward)
        navtb.addAction(next_btn)

        reload_btn = QAction("Reload", self)
        reload_btn.setStatusTip("Reload page")
        reload_btn.triggered.connect(self.browser_tab.reload)
        navtb.addAction(reload_btn)

        home_btn = QAction("Home", self)
        home_btn.setStatusTip("Go home")
        home_btn.triggered.connect(self.navigate_home)
        navtb.addAction(home_btn)

        analyze_btn = QAction("Analyze", self)
        analyze_btn.setStatusTip("Analyze current website")
        analyze_btn.triggered.connect(self.analyze_url)
        navtb.addAction(analyze_btn)

        navtb.addSeparator()

        self.urlbar = QLineEdit()
        self.urlbar.setStyleSheet("padding: 5px; font-size: 14px; border-radius: 5px;")
        self.urlbar.returnPressed.connect(self.navigate_to_url)
        navtb.addWidget(self.urlbar)

        stop_btn = QAction("Stop", self)
        stop_btn.setStatusTip("Stop loading current page")
        stop_btn.triggered.connect(self.browser_tab.stop)
        navtb.addAction(stop_btn)

        self.setStyleSheet("""
            QMainWindow { background-color: #f0f0f0; }
            QTabWidget::pane { border: 1px solid #ccc; border-radius: 5px; }
            QTabBar::tab { background: #3b82f6; color: white; padding: 10px; border-radius: 5px; }
            QTabBar::tab:selected { background: #2563eb; }
            QTextEdit { background: #ffffff; border: 1px solid #ccc; border-radius: 5px; padding: 10px; }
            QToolBar { background: #e5e7eb; border: none; }
            QAction { font-size: 14px; }
        """)

    def update_title(self):
        title = self.browser_tab.page().title()
        self.setWindowTitle(f"{title} - Epic Browser & Analyzer")

    def navigate_home(self):
        self.browser_tab.setUrl(QUrl("http://www.google.com"))

    def navigate_to_url(self):
        q = QUrl(self.urlbar.text())
        if q.scheme() == "":
            q.setScheme("http")
        self.browser_tab.setUrl(q)

    def update_urlbar(self, q):
        self.urlbar.setText(q.toString())
        self.urlbar.setCursorPosition(0)

    def analyze_url(self):
        url = self.urlbar.text()
        if not url:
            self.show_error("E001", "No URL entered. Please type a website address, like example.com.")
            return

        self.status.showMessage("Analyzing website... 🌐", 5000)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
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
            self.progress_bar.setValue(20)

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
            self.progress_bar.setValue(40)

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
            self.progress_bar.setValue(60)

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
            self.progress_bar.setValue(80)

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
            self.progress_bar.setValue(100)

            self.display_results(result)
            self.status.showMessage("Analysis complete! Check the tabs for details! 🎉", 5000)
            self.progress_bar.setVisible(False)

        except requests.exceptions.RequestException as e:
            self.show_error("E002", f"Couldn’t connect to the website: {str(e)}. Check the URL or your internet connection.")
            self.status.showMessage("Analysis failed 😞", 5000)
            self.progress_bar.setVisible(False)
        except Exception as e:
            self.show_error("E003", f"Something went wrong: {str(e)}. Try again or check the URL.")
            self.status.showMessage("Analysis failed 😞", 5000)
            self.progress_bar.setVisible(False)

    def show_error(self, code, message):
        QMessageBox.critical(self, "Error", f"Error {code}: {message}")

    def clear_results(self):
        self.overview_text.clear()
        self.links_text.clear()
        self.whois_ssl_text.clear()

    def display_results(self, result):
        self.overview_text.setText(
            f"Website: {result['url']}\n"
            f"Analyzed on: {result['timestamp']}\n\n"
            f"Title: {result['details']['title']}\n"
            f"Description: {result['details']['meta_description']}\n"
            f"Creator/Organization: {result['details']['creator']}\n"
            f"Server Location: {result['details']['location']['city']}, {result['details']['location']['country']} (ISP: {result['details']['location']['isp']})"
            if isinstance(result['details']['location'], dict) else f"Server Location: {result['details']['location']}\n"
            f"Status Code: {result['details']['http_status']} (OK if 200)\n"
            f"Response Time: {result['details']['response_time']:.3f} seconds\n"
            f"Word Count: {result['details']['word_count']} words\n"
            f"Images: {result['details']['image_count']} images\n"
            f"Favicon: {result['details']['favicon']}\n"
            f"Robots.txt: {result['details']['robots_txt']}\n"
            f"Sitemap: {result['details']['sitemap']}\n"
        )

        links_text = f"Internal Links ({len(result['details']['links']['internal'])}):\n"
        for link in result['details']['links']['internal'][:10]:
            links_text += f" - {link}\n"
        if len(result['details']['links']['internal']) > 10:
            links_text += f"... and {len(result['details']['links']['internal']) - 10} more\n"
        links_text += f"\nExternal Links ({len(result['details']['links']['external'])}):\n"
        for link in result['details']['links']['external'][:10]:
            links_text += f" - {link}\n"
        if len(result['details']['links']['external']) > 10:
            links_text += f"... and {len(result['details']['links']['external']) - 10} more\n"
        self.links_text.setText(links_text)

        whois_ssl_text = "Domain Information:\n"
        if isinstance(result['details']['whois'], dict):
            whois_ssl_text += (
                f"Domain Name: {result['details']['whois']['domain_name']}\n"
                f"Registrar: {result['details']['whois']['registrar']}\n"
                f"Organization: {result['details']['whois']['organization']}\n"
                f"Created On: {result['details']['whois']['creation_date']}\n"
                f"Expires On: {result['details']['whois']['expiration_date']}\n"
            )
        else:
            whois_ssl_text += f"{result['details']['whois']}\n"
        whois_ssl_text += "\nSecurity Certificate (SSL):\n"
        if isinstance(result['details']['ssl_info'], dict):
            whois_ssl_text += (
                f"Issuer: {result['details']['ssl_info']['issuer']}\n"
                f"Valid Until: {result['details']['ssl_info']['notAfter']}\n"
            )
        else:
            whois_ssl_text += f"{result['details']['ssl_info']}\n"
        self.whois_ssl_text.setText(whois_ssl_text)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setApplicationName("Epic Browser & Analyzer")
    window = MainWindow()
    window.show()
    app.exec_()
