#!/bin/bash

echo '🔥 Starting all 20 vulnerable servers...'

python3 server_bufovr.py &
python3 server_cmdi.py &
python3 server_crlf_injection.py &
python3 server_credsexpose.py &
python3 server_dirtrav.py &
python3 server_graphqli.py &
python3 server_infodisc.py &
python3 server_insecdeser.py &
python3 server_insecperm.py &
python3 server_jwt.py &
python3 server_nosqli.py &
python3 server_prototype_pollution.py &
python3 server_ratelimit.py &
python3 server_sqli.py &
python3 server_ssrf.py &
python3 server_ssti.py &
python3 server_sessfix.py &
python3 server_xss.py &
python3 server_xxe.py &
python3 server_safe.py &

echo '✅ All 20 servers started!'
echo 'Ports: 5001-5020'
wait
