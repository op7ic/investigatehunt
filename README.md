# investigatehunt

This repository contains basic threat hunting scripts for [Umbrella Investigate](https://umbrella.cisco.com/products/umbrella-investigate) API. Scripts are heavily based on already existing code published by [OpenDNS](https://github.com/opendns/investigate-examples/) with some optimization towards handling file inputs, csv output and pagination. Please add API key to [config.txt](config.txt) file and pass it as argument to appropriate scripts.


## get_domain_SHA256.py

This script will print out up to 500 first SHA256 hashes associated with given domain or IP address. The result of this lookup can be used for threat hunting activity in conjunction with other EDR tools such as [Cisco AMP](https://www.cisco.com/c/en/us/products/security/advanced-malware-protection/index.html) or API searches for these tools. Please note that there are some limitations associated with SHA256 lookups against benign, well known, domains such as ```google.com```. Thread Grid Investigate documentation provides more details around these limitations [here](https://docs.umbrella.com/investigate-api/docs/threat-grid-integration-cisco-amp-threat-grid).

How to invoke:
```
python3 get_domain_SHA256.py <config file.txt> <input file>
```

Input file can take both domain names as well as IPs. CIDR is not supported however. Sample file:
```
amazon.com
8.8.8.8
bbc.com
cisco.com
1.1.1.1
2.2.2.2
```

## search_domain_list2csv.py

This script takes a file with list of domain names and returns information about them in csv format.

How to invoke:
```
python3 search_domain_list2csv.py <config file.txt> <domain list file.txt>
```
Output file will contain the following fields in the CSV rows. 

- Lookup time (current UTC in ISO8601 format)
- Domain name
- Domain category (i.e. shopping)
- Security category 
- Verdict (malicious/unclassified/benign)
- Risk score (lower is better)
- DGA score (ranges from -100 (suspicious) to 0 (benign))
- Perplexity (A second score on the likeliness of the name to be algorithmically generated, on a scale from 0 to 100)
- Domain entropy (The number of bits required to encode the domain name, as a score)
- ASN Score (ASN reputation score, ranges from -100 to 0 with -100 being very suspicious)
- Popularity (The number of unique client IPs visiting this site, relative to the all requests to all sites)
- Securerank2 Rating (Scores returned range from -100 (suspicious) to 100 (benign))
- Attack (The name of any known attacks associated with this domain)
- Threat Type (The type of the known attack, such as botnet or APT)

More information on specific field description can be found [here](https://docs.umbrella.com/investigate-api/docs/security-information-for-a-domain-1):

## single_domain_classification.py

This script takes a single domain name as command line parameter and prints out classification, along with appropriate categories in CSV format.

How to invoke:
```
python3 single_domain_classification.py <config file.txt> <domain name>
```

Output file will contain the following fields in the CSV rows:

- Lookup time (current UTC in ISO8601 format)
- Domain name
- Domain category (i.e. shopping)
- Security category 
- Verdict (malicious/unclassified/benign)

## Threat hunting using Investigate samples and AMP4E

Once results of ```get_domain_SHA256.py``` script are returned, one can simply feed SHA256/MD5/SHA1 into scripts in [amphunt](https://github.com/op7ic/amphunt) repository to search for specific results. In particular, [multikeyword_search.py](https://github.com/op7ic/amphunt/blob/master/multikeyword_search.py), [hash2processarg.py](https://github.com/op7ic/amphunt/blob/master/hash2processarg.py) or [hash2connection.py](https://github.com/op7ic/amphunt/blob/master/hash2connection.py) could be of use for such activity.

## Prerequisites 

- Python3.6+

## TODO

- [x] Output to CSV
- [ ] Optimize output
- [ ] Better exception / error handling / code quality. These tools are mostly PoC for now