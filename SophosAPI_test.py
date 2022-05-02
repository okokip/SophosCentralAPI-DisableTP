import sys
import json
import requests

url = 'https://api5.central.sophos.com/gateway'
client_id = ''
client_secret = ''
def whoami(token):
    uri = 'https://api.central.sophos.com/whoami/v1'
    h = {'Authorization': f'Bearer {token}'}
    r = requests.get(uri, headers=h)
    if r.status_code == 200:
        j = json.loads(r.text)
        tenant_id = j['id']
        tenant_type = j['idType']
        data_region = j['apiHosts']['dataRegion']
        return tenant_id, tenant_type, data_region
    else:
        print("Unable to obtain whoami details")

def auth(client_id, client_secret):
    uri = "https://id.sophos.com/api/v2/oauth2/token"
    d = {'grant_type': 'client_credentials', 'client_id': client_id, 'client_secret': client_secret, 'scope': 'token'}
    r = requests.post(uri, data=d)
    if r.status_code == 200:
        j = json.loads(r.text)
        jwt = j['access_token']
        tenant_id, tenant_type, data_region = whoami(jwt)
        return jwt, tenant_id, tenant_type, data_region    
    else:
        print("Authentication failed")
        return False
		
jwt, tenant_id, tenant_type, data_region = auth(client_id, client_secret)
u = f"{data_region}/endpoint/v1/endpoints"
h = {'Authorization': f'Bearer {jwt}', 'X-Tenant-ID': f'{tenant_id}'}
r = requests.get(u, headers=h)
