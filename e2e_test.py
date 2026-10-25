# e2e_test.py - End-to-end verification for TrustVault
print("DIAG: script start", flush=True)
import os, sys, json, uuid
import requests
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables (do not print secrets)
load_dotenv(dotenv_path=Path(__file__).parents[2] / '.env')

BASE_URL = f"http://localhost:{os.getenv('PORT', '8000')}"

def signup(email, password):
    return requests.post(f"{BASE_URL}/api/v1/auth/signup", json={"email": email, "password": password})

def login(email, password):
    return requests.post(f"{BASE_URL}/api/v1/auth/login", json={"email": email, "password": password})

def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}

def upload_doc(token, title, content_bytes, mime="application/pdf"):
    files = {"file": (f"{title}.pdf", content_bytes, mime)}
    data = {"title": title}
    return requests.post(f"{BASE_URL}/api/v1/documents", headers=auth_headers(token), data=data, files=files)

def list_docs(token):
    return requests.get(f"{BASE_URL}/api/v1/documents", headers=auth_headers(token))

def get_download(token, doc_id):
    return requests.get(f"{BASE_URL}/api/v1/documents/{doc_id}", headers=auth_headers(token))

def delete_doc(token, doc_id):
    return requests.delete(f"{BASE_URL}/api/v1/documents/{doc_id}", headers=auth_headers(token))

def main():
    print("DIAG: entering main", flush=True)
    suffix = uuid.uuid4().hex[:6]
    email_a = f"e2e_a_{suffix}@example.com"
    email_b = f"e2e_b_{suffix}@example.com"
    pwd = "TestPass123!"
    results = []
    # A signup/login
    r = signup(email_a, pwd)
    results.append(("signup A", r.status_code))
    token_a = r.json().get("access_token") if r.status_code == 200 else None
    if not token_a:
        r = login(email_a, pwd)
        results.append(("login A after signup fail", r.status_code))
        token_a = r.json().get("access_token") if r.status_code == 200 else None
    # B signup/login
    r = signup(email_b, pwd)
    results.append(("signup B", r.status_code))
    token_b = r.json().get("access_token") if r.status_code == 200 else None
    if not token_b:
        r = login(email_b, pwd)
        results.append(("login B after signup fail", r.status_code))
        token_b = r.json().get("access_token") if r.status_code == 200 else None
    if not token_a or not token_b:
        print(json.dumps({"stage": "auth_failed", "details": results}, indent=2))
        sys.exit(1)
    # Upload doc as A
    content = b"Hello TrustVault!"
    r = upload_doc(token_a, "testdoc", content)
    results.append(("upload A", r.status_code))
    doc_id = r.json().get("id") if r.status_code == 201 else None
    # List A
    r = list_docs(token_a)
    results.append(("list A", r.status_code))
    list_a_ids = [d.get("id") for d in r.json()] if r.status_code == 200 else []
    results.append(("doc appears in A list", doc_id in list_a_ids if doc_id else False))
    # Get download URL A
    if doc_id:
        r = get_download(token_a, doc_id)
        results.append(("download URL A", r.status_code))
    # B list (should not see doc)
    r = list_docs(token_b)
    results.append(("list B", r.status_code))
    list_b_ids = [d.get("id") for d in r.json()] if r.status_code == 200 else []
    results.append(("doc not in B list", doc_id not in list_b_ids if doc_id else True))
    # B try download (should be 403/404)
    if doc_id:
        r = get_download(token_b, doc_id)
        results.append(("download B forbidden", r.status_code))
    # A delete
    if doc_id:
        r = delete_doc(token_a, doc_id)
        results.append(("delete A", r.status_code))
        r = list_docs(token_a)
        after_ids = [d.get("id") for d in r.json()] if r.status_code == 200 else []
        results.append(("doc removed after delete", doc_id not in after_ids))
    print(json.dumps({"results": results}, indent=2))

if __name__ == "__main__":
    main()
