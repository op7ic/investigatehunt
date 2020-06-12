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

def isMalicious(value):
	if value == 0:
		return "Unclassified"
	if value == -1:
		return "Malicious"
	if value == 1:
		return "Benign"

def match_category(number):
	categories=dict({'0': 'Adware', '1': 'Alcohol', '2': 'Auctions', '3': 'Blogs', '4': 'Chat', '5': 'Classifieds', 
	'6': 'Dating', '7': 'Drugs', '8': 'Ecommerce/Shopping', '9': 'File Storage', '10': 'Gambling', '11': 'Games', 
	'12': 'Hate/Discrimination', '13': 'Health and Fitness', '14': 'Humor', '15': 'Instant Messaging', '16': 
	'Jobs/Employment', '17': 'Movies', '18': 'News/Media', '19': 'P2P/File sharing', '20': 'Photo Sharing', 
	'21': 'Portals', '22': 'Radio', '23': 'Search Engines', '24': 'Social Networking', '25': 'Software/Technology', 
	'26': 'Television', '28': 'Video Sharing', '29': 'Visual Search Engines', '30': 'Weapons', '31': 'Webmail', '32': 
	'Business Services', '33': 'Educational Institutions', '34': 'Financial Institutions', '35': 'Government', '36': 
	'Music', '37': 'Parked Domains', '38': 'Tobacco', '39': 'Sports', '40': 'Adult Themes', '41': 'Lingerie/Bikini', 
	'42': 'Nudity', '43': 'Proxy/Anonymizer', '44': 'Pornography', '45': 'Sexuality', '46': 'Tasteless', '47': 'Academic Fraud', 
	'48': 'Automotive', '49': 'Forums/Message boards', '50': 'Non-Profits', '51': 'Podcasts', '52': 'Politics', '53': 'Religious', 
	'54': 'Research/Reference', '55': 'Travel', '57': 'Anime/Manga/Webcomic', '58': 'Web Spam', '59': 'Typo Squatting', '60': 
	'Drive-by Downloads/Exploits', '61': 'Dynamic DNS', '62': 'Mobile Threats', '63': 'High Risk Sites and Locations', '64': 
	'Command and Control', '65': 'Command and Control', '66': 'Malware', '67': 'Malware', '68': 'Phishing', '108': 'Newly Seen Domains', 
	'109': 'Potentially Harmful', '110': 'DNS Tunneling VPN', '111': 'Arts', '112': 'Astrology', '113': 'Computer Security', 
	'114': 'Digital Postcards', '115': 'Dining and Drinking', '116': 'Dynamic and Residential', '117': 'Fashion', '118': 
	'File Transfer Services', '119': 'Freeware and Shareware', '120': 'Hacking', '121': 'Illegal Activities', 
	'122': 'Illegal Downloads', '123': 'Infrastructure', '124': 'Internet Telephony', '125': 'Lotteries', 
	'126': 'Mobile Phones', '127': 'Nature', '128': 'Online Trading', '129': 'Personal Sites', '130': 'Professional Networking', 
	'131': 'Real Estate', '132': 'SaaS and B2B', '133': 'Safe for Kids', '134': 'Science and Technology', '135': 'Sex Education', 
	'136': 'Social Science', '137': 'Society and Culture', '138': 'Software Updates', '139': 'Web Hosting', '140': 'Web Page Translation', 
	'141': 'Organization Email', '142': 'Online Meetings', '143': 'Paranormal', '144': 'Personal VPN', '145': 'DIY Projects', 
	'146': 'Hunting', '147': 'Military', '150': 'Cryptomining'})
	return categories.get(str(number))

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
print("{},{},{},{},{},{},{},{},{},{},{},{},{}".format("Date",
				"Domain",
    			"Category",
    			"Security Category",
    			"Verdict",
    			"Risk Score",
    			"DGA Score",
    			"Perplexity",
    			"Domain Entropy",
    			"ASN Score",
    			"Popularity",
    			"Securerank2 Score",
    			"Attack",
    			"Threat Type"))
try:
    fp = open(domain_list,'r')
    for single_domain in fp.readlines():
    	try:
    		domain=single_domain.strip()
    		# URL to API mapping
    		URL_API='https://investigate.api.umbrella.com/domains/categorization/{}'.format(domain)
    		responsecategorization = session.get(URL_API, verify=False)
    		checkAPITimeout(responsecategorization.headers,responsecategorization)
    		responsecategorization_json = responsecategorization.json()
    		category_score = responsecategorization_json['{}'.format(domain)]['status']
    		category_content_category = responsecategorization_json['{}'.format(domain)]['content_categories']
    		category_content_security_category = responsecategorization_json['{}'.format(domain)]['security_categories']
    		catList = list()
    		secList = list()
    		for cat in category_content_category:
    			catList.append(match_category(cat))
    		for sec_cat in category_content_security_category:
    			secList.append(match_category(sec_cat))

    		URL_API='https://investigate.api.umbrella.com/domains/risk-score/{}'.format(domain)
    		risk_score = session.get(URL_API, verify=False)
    		checkAPITimeout(risk_score.headers,risk_score)
    		risk_score_json = risk_score.json()
    		
    		URL_API_SEC='https://investigate.api.umbrella.com/security/name/{}'.format(domain)
    		responsesecurity = session.get(URL_API_SEC, verify=False)
    		checkAPITimeout(responsesecurity.headers,responsesecurity)
    		responsesecurity_json = responsesecurity.json()
    		

    		#print(responsesecurity_json)
    		dga_score = responsesecurity_json['dga_score']
    		perplexity = responsesecurity_json['perplexity']
    		asn_score = responsesecurity_json['asn_score']
    		popularity = responsesecurity_json['popularity']
    		domain_entropy = responsesecurity_json['entropy']
    		securerank2 = responsesecurity_json['securerank2']
    		attack = responsesecurity_json['attack']
    		threat_type = responsesecurity_json['threat_type']

    		print("{},{},{},{},{},{},{},{},{},{},{},{},{},{}".format(
    			datetime.datetime.utcnow().isoformat(),
    			str(domain).replace(".","[.]"),
    			"|".join(catList),
    			"|".join(secList),
    			isMalicious(category_score),
    			risk_score_json['risk_score'],
    			dga_score,
    			perplexity,
    			domain_entropy,
    			asn_score,
    			popularity,
    			securerank2,
    			attack,
    			threat_type
    			))

    		# We need to sleep so API won't kick up. 3 API queries are allowed per second in Tier 1
    		time.sleep(1)

    	except:
    		# In theory this should never really happen
    		print("{},{},{},{},{},{},{},{},{},{},{},{},{}".format(
    			datetime.datetime.utcnow().isoformat(),
    			str(domain).replace(".","[.]"),
    			"Lookup Failed",
    			"Lookup Failed",
    			"Lookup Failed",
    			"Lookup Failed",
    			"Lookup Failed",
    			"Lookup Failed",
    			"Lookup Failed",
    			"Lookup Failed",
    			"Lookup Failed",
    			"Lookup Failed",
    			"Lookup Failed",
    			"Lookup Failed"
    			))
    		pass
finally:
    fp.close()


