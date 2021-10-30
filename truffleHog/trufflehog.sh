#!/bin/sh
trufflehog "$@"  | python /usr/bin/trufflehog-parser.py
