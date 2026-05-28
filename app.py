import json
from http.server import SimpleHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import time

import whois

def check_domain(domain):
    try:
        q = whois.query(domain)
        return {
            "domain": domain,
            "free": q is None,
            "error": None
        }
    except Exception as e:
        # If the whois query throws an exception, it could be an unsupported TLD or connection error
        error_msg = str(e)
        if "Unknown TLD" in error_msg:
            return {"domain": domain, "free": False, "error": "Неподдерживаемая зона"}
        return {"domain": domain, "free": False, "error": error_msg}

class DomainCheckerHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        parsed_path = urlparse(self.path)
        
        if parsed_path.path == '/api/check':
            query = parse_qs(parsed_path.query)
            domains = query.get('domains', [])
            
            if not domains:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"No domains provided")
                return
            
            domains_list = domains[0].split(',')
            results = []
            
            # Simple sequential check to avoid spamming whois servers
            for domain in domains_list:
                domain = domain.strip().lower()
                if domain:
                    res = check_domain(domain)
                    results.append(res)
                    time.sleep(0.5) # Slight delay to respect rate limits
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(results).encode('utf-8'))
        else:
            # Serve static files
            if self.path == '/':
                self.path = '/static/index.html'
            elif not self.path.startswith('/static/'):
                self.path = '/static' + self.path
                
            return super().do_GET()

if __name__ == '__main__':
    port = 8080
    server_address = ('0.0.0.0', port)
    httpd = HTTPServer(server_address, DomainCheckerHandler)
    print(f"Domain Checker Server running at http://0.0.0.0:{port}/")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()