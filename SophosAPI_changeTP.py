import sys
import json
import requests
import pandas as pd


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


def disable_tp(jwt, tenant_id, data_region, df):
	req_result = []
	for ep_id in df.ID:
		sc_url = f"{data_region}/endpoint/v1/endpoints/{ep_id}/tamper-protection"
		sc_rh = {'Authorization': f'Bearer {jwt}', 'X-Tenant-ID': f'{tenant_id}', "Accept": "application/json", "Content-Type": "application/json"}
		sc_rb = {"enabled": True}
		request_post = requests.post(sc_url, headers=sc_rh, json=sc_rb)
		print(request_post.content)
		req_result.append(request_post.content)
	return req_result


if __name__ == '__main__':
	print("Please Enter Your Client ID :")
	client_id = input()
	print("Please Enter Your Client Secret :")
	client_secret = input()
	df = pd.read_csv('report.csv')
	jwt, tenant_id, tenant_type, data_region = auth(client_id, client_secret)
	result = disable_tp(jwt, tenant_id, data_region, df)
	print(result)
