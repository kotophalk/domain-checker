import requests

def test_frontend_xss_fix():
    print("Testing if escapeHtml is in the frontend index.html...")
    try:
        response = requests.get("http://localhost:8080/")
        html_content = response.text
        if "escapeHtml" in html_content and "escapeHtml(item.domain)" in html_content:
            print("Frontend index.html has the escapeHtml fix!")
            return True
        else:
            print("Fix is missing in frontend index.html")
            return False
    except Exception as e:
        print("Failed to reach server:", e)
        return False

def test_api_returns_payload():
    print("Testing if API returns the XSS payload (so it can be escaped by frontend)...")
    try:
        response = requests.get("http://localhost:8080/api/check?domains=%3Cscript%3Ealert(1)%3C/script%3E")
        data = response.json()
        domain_val = data[0]['domain']
        if domain_val == "<script>alert(1)</script>":
            print("API reflects the domain correctly, frontend fix will mitigate it!")
            return True
        else:
            print("Unexpected API behavior")
            return False
    except Exception as e:
        print("API test failed:", e)
        return False

if __name__ == "__main__":
    t1 = test_frontend_xss_fix()
    t2 = test_api_returns_payload()
    if t1 and t2:
        print("All tests passed!")
        exit(0)
    else:
        print("Tests failed!")
        exit(1)
