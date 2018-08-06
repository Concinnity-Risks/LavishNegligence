#!/usr/bin/env python
#
# CA-Cert-Graph.py
# Stream the SSL/TLS certificates that Shodan is collecting at the moment
#
# WARNING: This script only works with people that have a subscription API plan!
# And by default the Streaming API only returns 1% of the data that Shodan gathers.
# If you wish to have more access please contact us at support@shodan.io for pricing
# information.
#
# Author: achillean (altered by blackswanburst)

import shodan
import json
from pybloom_live import BloomFilter

def pretty(d, indent=0):
   for key, value in d.items():
      print('\t' * indent + str(key))
      if isinstance(value, dict):
        pretty(value, indent+1)
      elif isinstance(value, unicode):
        print('\t' * (indent+1) + str(value.encode("ascii","ignore")))
      else:
        print('\t' * (indent+1) + str(value))

print("Constructing bloomfilter...")
bf = BloomFilter(4000000000, 0.001)

# Configuration
API_KEY = ""
# Open a file
print("Preparing graphs...")
graph = open("Cert-Graph.csv", "w")
graph.write("Source,Target,Expired,IssuedDate,ExpiryDate,Version,SignatureAlgorithm,KeyType,Bits\n")
print("Initialising variables...")
# Setup the api
api = shodan.Shodan(API_KEY)
#iteration counter
n = 0
unique = 0
print('Listening for certs...')
for banner in api.stream.ports([443, 8443]):
    #pretty(banner)
    if 'ssl' in banner:
        n += 1
        #pretty(banner['ssl']['cert'])
        if n >= 100:
            # Close opened file
            graph.close()
            break
        #elif banner['ssl']['cert']['fingerprint']['sha256'] in bf:
        else:
            graph.write(json.dumps(banner['ssl']['cert']['subject'])+","+json.dumps(banner['ssl']['cert']['issuer'])+","+str(banner['ssl']['cert']['expired'])+","+banner['ssl']['cert']['issued']+","+banner['ssl']['cert']['expires']+","+str(banner['ssl']['cert']['version'])+","+banner['ssl']['cert']['sig_alg']+","+banner['ssl']['cert']['pubkey']['type']+","+str(banner['ssl']['cert']['pubkey']['bits'])+"\n")
graph.close()
