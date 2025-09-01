
import requests
import time

# API endpoint
url = "https://prompt-manager-extension.onrender.com/userlist"



# Headers
headers = {
    "Content-Type": "application/json"
}

# Query parameters
# params = {
#     "scope": "personal",
#     "q": "search_term"
# }

# # Headers
# headers = {
#     "X-User-ID": "1",
#     "Content-Type": "application/json"
# }

while True:
    try:
        # response = requests.get(url, headers=headers, params=params, timeout=10)
        response = requests.get(url, headers=headers, timeout=10)

        print("\n--- API Call ---")
        print("Status Code:", response.status_code)

        # If response is JSON
        try:
            print("Response Body:", response.json())
        except ValueError:
            print("Response Body (raw):", response.text)

    except requests.exceptions.RequestException as e:
        print("Error:", e)

    # Wait 5 minutes before next call
    time.sleep(5 * 60)
