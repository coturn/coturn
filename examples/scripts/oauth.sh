#!/bin/bash

OAUTH_UTILITY=bin/turnutils_oauth

echo "--------------create an access_token---------------"
$OAUTH_UTILITY -e --server-name example.com --auth-key-id 1234 --auth-key SEdrajMyS0pHaXV5MDk4c2RmYXFiTmpPaWF6NzE5MjM= --auth-key-timestamp 249213600 --auth-key-lifetime 21600 --token-mac-key WmtzanB3ZW9peFhtdm42NzUzNG0=  --token-timestamp 16333642137600 --token-lifetime=3600

echo "---------------create and validate and print out the decoded access_token---------------"
$OAUTH_UTILITY -v -d -e --server-name example.com --auth-key-id 1234 --auth-key SEdrajMyS0pHaXV5MDk4c2RmYXFiTmpPaWF6NzE5MjM= --auth-key-timestamp 249213600 --auth-key-lifetime 21600 --token-mac-key WmtzanB3ZW9peFhtdm42NzUzNG0=  --token-timestamp 16333642137600 --token-lifetime=3600

echo -e "\n---------------just validate only the access_token---------------"
$OAUTH_UTILITY -d --server-name example.com --auth-key-id 1234 --auth-key SEdrajMyS0pHaXV5MDk4c2RmYXFiTmpPaWF6NzE5MjM= --auth-key-timestamp 249213600 --auth-key-lifetime 21600 --token AAy1JBYVLo16iq9gFdHyyknmx5T/Lq9YlbxgUdLcStOFS0H8xhHceHOL2f49qxp4uBpGuuLeLqk+RcAa5uP2EQ== --token-lifetime=3600

echo -e "\n---------------validate and print out the decoded access_token---------------"
$OAUTH_UTILITY -v -d --server-name example.com --auth-key-id 1234 --auth-key SEdrajMyS0pHaXV5MDk4c2RmYXFiTmpPaWF6NzE5MjM= --auth-key-timestamp 249213600 --auth-key-lifetime 21600 --token AAy1JBYVLo16iq9gFdHyyknmx5T/Lq9YlbxgUdLcStOFS0H8xhHceHOL2f49qxp4uBpGuuLeLqk+RcAa5uP2EQ== --token-lifetime=3600


