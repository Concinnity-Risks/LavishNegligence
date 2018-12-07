#!/bin/bash
sleep $(($RANDOM % 21600 )); cd /home/praxis/LavishNegligence && python CA-Cert-Graph.py >> TLS-Error.log
