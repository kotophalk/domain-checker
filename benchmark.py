import time
import requests
import threading

def make_request(url):
    start = time.time()
    r = requests.get(url)
    end = time.time()
    print(f"Request took {end - start:.2f}s, status {r.status_code}")

def run_benchmark():
    url = "http://127.0.0.1:8080/api/check?domains=google.com,example.com,test.com"
    threads = []
    start_total = time.time()

    for _ in range(3):
        t = threading.Thread(target=make_request, args=(url,))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    end_total = time.time()
    print(f"Total time: {end_total - start_total:.2f}s")

if __name__ == "__main__":
    run_benchmark()
