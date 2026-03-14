<<<<<<< HEAD
import requests
import json

# Try different formats
formats = [
    # Format 1: Array
    [{"code": "U617U09AR9YQ", "deviceName": "TestPC"}],
    
    # Format 2: Object with keys
    {"0": {"code": "U617U09AR9YQ", "deviceName": "TestPC"}},
    
    # Format 3: Direct object
    {"code": "U617U09AR9YQ", "deviceName": "TestPC"},
    
    # Format 4: With batch key
    {"batch": [{"code": "U617U09AR9YQ", "deviceName": "TestPC"}]}
]

url = "http://localhost:3000/api/trpc/scanCode.validate"

for i, payload in enumerate(formats):
    print(f"\nTrying format {i+1}:")
    print(f"Payload: {json.dumps(payload)}")
    
    try:
        response = requests.post(url, json=payload, timeout=5)
        print(f"Status: {response.status_code}")
        if response.status_code == 200:
            print(f"✅ SUCCESS! Format {i+1} works")
            print(f"Response: {response.json()}")
            break
        else:
            print(f"❌ Failed with status {response.status_code}")
            print(f"Response: {response.text[:200]}")
    except Exception as e:
=======
import requests
import json

# Try different formats
formats = [
    # Format 1: Array
    [{"code": "U617U09AR9YQ", "deviceName": "TestPC"}],
    
    # Format 2: Object with keys
    {"0": {"code": "U617U09AR9YQ", "deviceName": "TestPC"}},
    
    # Format 3: Direct object
    {"code": "U617U09AR9YQ", "deviceName": "TestPC"},
    
    # Format 4: With batch key
    {"batch": [{"code": "U617U09AR9YQ", "deviceName": "TestPC"}]}
]

url = "http://localhost:3000/api/trpc/scanCode.validate"

for i, payload in enumerate(formats):
    print(f"\nTrying format {i+1}:")
    print(f"Payload: {json.dumps(payload)}")
    
    try:
        response = requests.post(url, json=payload, timeout=5)
        print(f"Status: {response.status_code}")
        if response.status_code == 200:
            print(f"✅ SUCCESS! Format {i+1} works")
            print(f"Response: {response.json()}")
            break
        else:
            print(f"❌ Failed with status {response.status_code}")
            print(f"Response: {response.text[:200]}")
    except Exception as e:
>>>>>>> 053d8fe (Initial commit with all files (node_modules excluded))
        print(f"Error: {e}")