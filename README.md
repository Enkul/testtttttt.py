# testtttttt.py
from __future__ import print_function
from future import standard_library
standard_library.install_aliases()
import urllib.request, urllib.parse, urllib.error
import httplib2
from xml.dom import minidom
from bs4 import BeautifulSoup
import time
import xml.etree.ElementTree as ET
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

RL
baseurl = 'test'
userName = 'test'
password = 'test'
searchQuery = 'splunk query'


VIRUSTOTAL_API_KEY = 'b46d3f9de3016a8ce7e5cd2712e6558fe4fda60df261a41abe8f9ff4ee99c54d'

headers = {
    'x-apikey': VIRUSTOTAL_API_KEY,
    'Accept': 'application/json'
}


serverContent = httplib2.Http(disable_ssl_certificate_validation=True).request(
    baseurl + '/services/auth/login', 'POST', headers={}, body=urllib.parse.urlencode({'username': userName, 'password': password}))[1]
sessionKey = minidom.parseString(serverContent).getElementsByTagName('sessionKey')[0].childNodes[0].nodeValue


searchQuery = searchQuery.strip()
if not (searchQuery.startswith('search') or searchQuery.startswith("|")):
    searchQuery = 'search ' + searchQuery


response = httplib2.Http(disable_ssl_certificate_validation=True).request(
    baseurl + '/services/search/jobs', 'POST', headers={'Authorization': 'Splunk %s' % sessionKey},
    body=urllib.parse.urlencode({'search': searchQuery}))[1]

soup = BeautifulSoup(response.decode(), 'xml')
searchSID = soup.response.sid.string


while True:
    testFinish = httplib2.Http(disable_ssl_certificate_validation=True).request(
        baseurl + '/services/search/jobs/' + searchSID, 'GET', headers={'Authorization': 'Splunk %s' % sessionKey})[1]
    finishCheck = BeautifulSoup(testFinish.decode(), 'xml')
    isDone = int(finishCheck.find('s:key', {"name": "isDone"}).text)
    if isDone:
        break
    time.sleep(3)


response2 = httplib2.Http(disable_ssl_certificate_validation=True).request(
    baseurl + '/services/search/jobs/' + searchSID + '/results/', 'GET', headers={'Authorization': 'Splunk %s' % sessionKey})

tree = ET.ElementTree(ET.fromstring(response2[1].decode()))
results = tree.getroot()
src_ips = [field.find("value/text").text for result in results.findall(".//result") for field in result if field.get('k') == 'src']


for ip in src_ips:
    vt_url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
    response = requests.get(url=vt_url, headers=headers, verify=False)
    vt_response = response.json()
    
    
    if 'data' in vt_response:
        data = vt_response['data']
        attributes = data.get('attributes', {})
        last_analysis_stats = attributes.get('last_analysis_stats', {})
        
        print(f"IP Address: {ip}")
        print(f"  Harmless: {last_analysis_stats.get('harmless', 'N/A')}")
        print(f"  Malicious: {last_analysis_stats.get('malicious', 'N/A')}")
        print(f"  Suspicious: {last_analysis_stats.get('suspicious', 'N/A')}")
        print(f"  Undetected: {last_analysis_stats.get('undetected', 'N/A')}")
        print(f"  Reputation: {attributes.get('reputation', 'N/A')}")
        print(f"  Last Analysis Date: {attributes.get('last_analysis_date', 'N/A')}")
        print(f"  Total Votes: {attributes.get('total_votes', 'N/A')}")
        print()
    else:
        print(f"No data available for IP Address: {ip}")
        print()

