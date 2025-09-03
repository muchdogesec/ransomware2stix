from functools import lru_cache
import json
import logging
import os
from urllib.parse import urljoin
import requests


DEFAULT_OBJECT_URLS = [
    "https://raw.githubusercontent.com/muchdogesec/stix4doge/refs/heads/main/objects/marking-definition/ransomware2stix.json",
    "https://raw.githubusercontent.com/muchdogesec/stix4doge/refs/heads/main/objects/identity/ransomware2stix.json",
]


def get_victims():
    resp = requests.get('https://data.ransomware.live/victims.json')
    return resp.json()

# def get_victims():
#     return json.loads(open('victims.json').read())

@lru_cache
def get_default_objects():
    return [requests.get(url).json() for url in DEFAULT_OBJECT_URLS]


def _get_objects(endpoint, headers):
    data = []
    page = 1
    while True:
        resp = requests.get(endpoint, params=dict(page=page, page_size=1000), headers=headers)
        if resp.status_code != 200:
            break
        d = resp.json()
        if len(d['objects']) == 0:
            break
        data.extend(d['objects'])
        page+=1
        if d['page_results_count'] < d['page_size']:
            break
    return data

def get_attack_objects(attack_ids):
    if not attack_ids:
        return []
    logging.debug(f"retrieving attack objects: {attack_ids}")
    endpoint = urljoin(os.environ['CTIBUTLER_BASE_URL'] + '/', f"v1/attack-enterprise/objects/?attack_id="+','.join(attack_ids))

    headers = {}
    if api_key := os.environ.get('CTIBUTLER_API_KEY'):
        headers['API-KEY'] = api_key

    return _get_objects(endpoint, headers)

@lru_cache
def get_location_objects():
    logging.info(f"retrieving location objects")
    endpoint = urljoin(os.environ['CTIBUTLER_BASE_URL'] + '/', f"v1/location/objects/?location_type=country")
    headers = {}
    if api_key := os.environ.get('CTIBUTLER_API_KEY'):
        headers['API-KEY'] = api_key

    return _get_objects(endpoint, headers)
