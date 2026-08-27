#!/bin/bash

echo '🛑 Stopping all servers...'
pkill -f 'python3 server_.*\.py'
echo '✅ All servers stopped!'
