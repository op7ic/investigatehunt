import sys
import requests
import configparser
import time
import json
import datetime


# Ignore insecure cert warnings (enable only if working with onsite-amp deployments)
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def checkAPITimeout(headers, request):
    """Ensure we don't cross API limits, sleep if we are approaching close to limits"""
    if str(request.status_code) == '200':
        pass
    elif str(request.status_code) == '404':
        time.sleep(45)
        pass
    elif str(request.status_code) == '503':
        # server sarted to block us
        time.sleep(90)
        pass
    else:
        # in any other case, sleep
        time.sleep(90)
        pass

def convertTime(value):
	# value need to be divided by 1000 due to formatting
	return datetime.datetime.fromtimestamp(int(value)/1000).isoformat()
	
# Validate a command line parameter was provided
if len(sys.argv) < 3:
    sys.exit('Usage: <config file.txt> <domainlistfile.txt>\n %s' % sys.argv[0])

# Parse config to extract API keys
config = configparser.ConfigParser()
config.read(sys.argv[1])
api_key = config['settings']['investigate_api_key']

domain_list = sys.argv[2]

# Session object
session = requests.Session()
session.headers.update({'Authorization': 'Bearer {}'.format(api_key)})

# Print CSV header
print("{},{},{},{},{},{},{},{},{},{}".format("Date","Domain/IP","SHA256","MD5","SHA1","Threat Score","First Seen","Last Seen","File Type","File Size"))
try:
    fp = open(domain_list,'r')
    for single_domain in fp.readlines():
        domain=single_domain.strip()
        URL_API='https://investigate.api.umbrella.com/samples/{}?limit=500&sortby=score'.format(domain)
        samples_request = session.get(URL_API, verify=False)
        checkAPITimeout(samples_request.headers,samples_request)
        samples_request_json = samples_request.json()
        time.sleep(1)
        for event in samples_request_json['samples']:
            print("{},{},{},{},{},{},{},{},{},{}".format(datetime.datetime.utcnow().isoformat(),str(domain).replace(".","[.]"),event['sha256'],event['md5'],event['sha1'],event['threatScore'],convertTime(event['firstSeen']),convertTime(event['lastSeen']),str(event['magicType']).replace(",","|"),event['size']))

        if 'error' in samples_request_json:
            print("{},{},{},{},{},{},{},{},{},{}".format(datetime.datetime.utcnow().isoformat(),str(domain).replace(".","[.]"),"No Data","No Data","No Data","No Data","No Data","No Data","No Data","No Data"))
        else:
            try:
                if (samples_request_json['moreDataAvailable'] == True):
                    offsets = [100,200,300,400,500]
                    for x in offsets:
                        URL_API='https://investigate.api.umbrella.com/samples/{}?offset={}&limit=500&sortby=score'.format(domain,x)
                        samples_request_iter = session.get(URL_API, verify=False)
                        checkAPITimeout(samples_request_iter.headers,samples_request_iter)
                        time.sleep(1)
                        samples_request_json_iter = samples_request_iter.json()
                        if (samples_request_json_iter['moreDataAvailable'] == True):
                            for event in samples_request_json_iter['samples']:
                                print("{},{},{},{},{},{},{},{},{},{}".format(
                                datetime.datetime.utcnow().isoformat(),
                                str(domain).replace(".","[.]"),
                                event['sha256'],
                                event['md5'],
                                event['sha1'],
                                event['threatScore'],
                                convertTime(event['firstSeen']),
                                convertTime(event['lastSeen']),
                                str(event['magicType']).replace(",","|"),
                                event['size']))
                        else:
                            break
            except KeyError:
                pass
finally:
    fp.close()