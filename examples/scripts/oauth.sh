#!/bin/bash
OAUTH_UTILITY=../../bin/turnutils_oauth
echo "--------------create an access_token---------------"
$OAUTH_UTILITY -e --server-name example.com --long-term-key-id 1234 --long-term-key SEdrajMyS0pHaXV5MDk4c2RmYXFiTmpPaWF6NzE5MjM= --long-term-key-timestamp 249213600 --long-term-key-lifetime 86400 --token-mac-key WmtzanB3ZW9peFhtdm42NzUzNG0=  --token-timestamp 16332934350000

echo "---------------create and validate and print out the decoded access_token---------------"
$OAUTH_UTILITY -v -d -e --server-name example.com --long-term-key-id 1234 --long-term-key SEdrajMyS0pHaXV5MDk4c2RmYXFiTmpPaWF6NzE5MjM= --long-term-key-timestamp 249213600 --long-term-key-lifetime 86400 --token-mac-key WmtzanB3ZW9peFhtdm42NzUzNG0=  --token-timestamp 16332934350000

echo -e "\n---------------just validate only the access_token---------------"
$OAUTH_UTILITY -d --server-name example.com --long-term-key-id 1234 --long-term-key SEdrajMyS0pHaXV5MDk4c2RmYXFiTmpPaWF6NzE5MjM= --long-term-key-timestamp 249213600 --long-term-key-lifetime 86400 --token AAyi1nAiKbhykYXGUzGF9uM/nUu67J4z1ySG3weLavUN6JLQm+HCPvCNkVWWVrOppCSTmYapLx+jDhgZcx0vMA==

echo -e "\n---------------validate and print out the decoded access_token---------------"
$OAUTH_UTILITY -v -d --server-name example.com --long-term-key-id 1234 --long-term-key SEdrajMyS0pHaXV5MDk4c2RmYXFiTmpPaWF6NzE5MjM= --long-term-key-timestamp 249213600 --long-term-key-lifetime 86400 --token AAyi1nAiKbhykYXGUzGF9uM/nUu67J4z1ySG3weLavUN6JLQm+HCPvCNkVWWVrOppCSTmYapLx+jDhgZcx0vMA==


