#!/usr/bin/python
# De una lista de URL de github las descarga en formato raw y busca ciertos patrones (passwords, correos, etc)
import sys
import json
import pprint

secretosEncontrados = []
Lines = sys.stdin.readlines()
for line in Lines:
    result = json.loads(line)
    path = result['path']
    stringsFound = result['stringsFound']
    for cadena in stringsFound:
        if (len(cadena)<100) and (cadena not in secretosEncontrados):            
            #print(f' File {path} : Strings found: {cadena}')
            secretosEncontrados.append({"File": path, "Strings found": cadena})
    #print(json.dumps(result, indent=4))    
    #sys.exit("OK")

pprint.pprint(secretosEncontrados)