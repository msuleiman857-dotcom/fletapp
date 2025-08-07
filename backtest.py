import requests

# suleimanios540@gmail.com

data = {
    "username": 'suleiman'
}

SECRET_API_KEY = "my_super_secret_key_12345"

headers = {
    "X-API-KEY": SECRET_API_KEY,
    "Content-Type": "application/json"
}

response = requests.post(
    "https://suleiman005.pythonanywhere.com/api/search_user",
    json=data,
    headers=headers
)

print(f"Status: {response.status_code} → {response.text}")
