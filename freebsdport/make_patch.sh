#!/bin/sh

diff -ru turnserver.orig/ turnserver/ > turnserver.patch
tar cvfLz turnserver.tgz turnserver


