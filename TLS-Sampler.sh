#!/bin/bash
sleep $(($RANDOM % 21600 )); cd /home/praxis/LavishNegligence && python CertificateFetcher.py >> TLS-Error.log
