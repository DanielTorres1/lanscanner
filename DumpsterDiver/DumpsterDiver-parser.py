#!/usr/bin/python3
# De una lista de URL de github las descarga en formato raw y busca ciertos patrones (passwords, correos, etc)
import pprint
import re
import time
import sys
import json
import argparse


parser = argparse.ArgumentParser()
parser.add_argument("--format", "-f", help="set file")
parser.parse_args()
args = parser.parse_args()




secretosEncontrados = []
Lines = sys.stdin.readlines()
for line in Lines:
    if "been found" in line:
		print (f'line {line}')
        nameRegex = re.compile(r'The following string: (.*) has been found in (.*)')
        mo = nameRegex.search(line)        
        stringsFound = mo.group(1)
        path = mo.group(2)
        if (len(stringsFound)<100) and (stringsFound not in secretosEncontrados):                        
            secretosEncontrados.append({"File": path, "Strings found": stringsFound})
            if "grep"  in args.format:
                print (f'File: {path} Strings found {stringsFound}')

if "json" in args.format:
    print(json.dumps(secretosEncontrados, indent=1))
