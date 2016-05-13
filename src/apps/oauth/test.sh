#!/bin/bash

echo "--------------create token---------------"
./bin/turnutils_oauth -e --server-name vvc.niif.hu --long-term-key-id 1234 --long-term-key SEdrajMyS0pHaXV5MDk4c2RmYXFiTmpPaWF6NzE5MjM= --long-term-key-timestamp 1464077257 --long-term-key-lifetime 3600 --token-mac-key WmtzanB3ZW9peFhtdm42NzUzNG0=  --token-timestamp 92470300704768

echo "---------------create and validate and print out decoded token---------------"
./bin/turnutils_oauth -v -d -e --server-name vvc.niif.hu --long-term-key-id 1234 --long-term-key SEdrajMyS0pHaXV5MDk4c2RmYXFiTmpPaWF6NzE5MjM= --long-term-key-timestamp 1464077257 --long-term-key-lifetime 3600 --token-mac-key WmtzanB3ZW9peFhtdm42NzUzNG0=  --token-timestamp 92470300704768

echo "---------------validate token---------------"
./bin/turnutils_oauth -d --server-name vvc.niif.hu --long-term-key-id 1234 --long-term-key SEdrajMyS0pHaXV5MDk4c2RmYXFiTmpPaWF6NzE5MjM= --long-term-key-timestamp 1464077257 --long-term-key-lifetime 3600 --token AAwAAAAAAAAAAAAAAABbhGtRHVrDPexC4TQJppr6QNyUwpfB6fS9R3QmwjYvW6YyShKY2fbeUs5lSebE4nYQfA==

echo "---------------validate and print out decoded token---------------"
./bin/turnutils_oauth -v -d --server-name vvc.niif.hu --long-term-key-id 1234 --long-term-key SEdrajMyS0pHaXV5MDk4c2RmYXFiTmpPaWF6NzE5MjM= --long-term-key-timestamp 1464077257 --long-term-key-lifetime 3600 --token AAwAAAAAAAAAAAAAAABbhGtRHVrDPexC4TQJppr6QNyUwpfB6fS9R3QmwjYvW6YyShKY2fbeUs5lSebE4nYQfA==


