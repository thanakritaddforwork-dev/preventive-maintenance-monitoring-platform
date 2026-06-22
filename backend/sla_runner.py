import requests

API = "http://127.0.0.1:8000/api/sla/rooms/check"

try:
    r = requests.post(API, timeout=10)
    print("SLA CHECK:", r.json())
except Exception as e:
    print("SLA CHECK FAILED:", e)
