from playwright.sync_api import sync_playwright
import os
import json
import urllib.parse
import requests

USERNAME = os.getenv("USERNAME")
PASSWORD = os.getenv("PASSWORD")
APP_URL = os.getenv("APP_URL")
CLIENT_ID = os.getenv("CLIENT_ID", "default")
REALM = os.getenv("REALM", "default")
BASE = "https://localhost"

REDIRECT_URI = "https://localhost"
TOKEN_ENDPOINT = f"{BASE}/auth/realms/{REALM}/protocol/openid-connect/token"
AUTH_URL = (
    f"{BASE}/auth/realms/{REALM}/protocol/openid-connect/auth"
    f"?client_id={CLIENT_ID}"
    f"&redirect_uri={urllib.parse.quote(REDIRECT_URI)}"
    f"&response_mode=query"
    f"&response_type=code"
    f"&scope=openid"
)

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    context = browser.new_context()
    page = context.new_page()

## May need to be CUSTOMIZED per login page
    # Start login flow
    page.goto(AUTH_URL)
    page.fill('input[name="username"]', USERNAME)
    page.fill('input[name="password"]', PASSWORD)
    page.click('input[type="submit"]')

    # Wait until redirect to app with ?code=... in URL
    page.wait_for_url(lambda url: url.startswith(REDIRECT_URI) and "code=" in url, timeout=10000)
    redirected_url = page.url
    parsed = urllib.parse.urlparse(redirected_url)
    query_params = urllib.parse.parse_qs(parsed.query)
    auth_code = query_params.get("code", [None])[0]

    cookies = context.cookies()
    context.close()
    browser.close()
    jwt_token = None
    if auth_code:
        data = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": REDIRECT_URI,
            "client_id": CLIENT_ID,
        }

        response = requests.post(TOKEN_ENDPOINT, data=data)
        if response.status_code == 200:
            token_json = response.json()
            jwt_token = token_json.get("access_token")
        else:
            print("Token exchange failed:", response.status_code, response.text)


    # Build output
    output = {}
    if jwt_token:
        output["headers"] = [{"Authorization": f"Bearer {jwt_token}"}]
    output["cookies"] = [{c["name"]: c["value"]} for c in cookies]

    print(json.dumps(output))
