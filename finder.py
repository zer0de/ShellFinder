#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# based on fuckshell from @jofpin
# 

import os
import sys
try:
    import urllib2
except:
    import urllib.request as urllib2
import re

#
# Fuckshell
#
# Webshell scan!

if "linux" in sys.platform:
    os.system("clear")
elif "win" in sys.platform:
    os.system("cls")
else:
    pass

_author_ = "José Pino (Fraph)"
_version_ = "1.0"

#Colors
color = {"blue": "\033[34m", "red": "\033[31m", "green": "\033[32m", "white": "\033[97m", "yellow": "\033[33m"}

def gscan(): #Global scan
        print("")
        print("\t\t-------------" + color['blue'] + "Shell Finder" + color['white'] + "------------")
        print("\t\tx      Developed by: zer0.de        x")
        print("\t\tx             OWC RulZ              x")
        print("\t\t  ----------------------------------\n\n")
        print("")
        
        #check files available
        try:
            lines = open('dic.txt').read().splitlines()
        except:
            sys.exit(color['white']  + "Error: " + color['red'] + "dic.txt not found\n" + color['white'])
                       
        try:
            hosts = open('host.txt').read().splitlines()
        except:
            sys.exit(color['white']  + "Error: " + color['red'] + "host.txt not found\n" + color['white'])
        
        
        rela =[] #relationship
        avai =[] #available
        redi =[] #redirect
        
        
        for url in hosts:
            print(color['green'] + "[+]" + color['blue'] + "Scanning..." + url + "\n" + color['white'])
            for line in lines:
                try:
                    coneccion_url = 'http://' + url + '/' + line
                    r = urllib2.Request(coneccion_url)
                    r.add_unredirected_header('User-Agent', 'Mozilla/5.0 (Windows; U; Windows NT 6.0;en-US; rv:1.9.2) Gecko/20100115 Firefox/3.6')#UserAgent
                    r.add_unredirected_header('Referer', 'http://www.google.com/')
                    req = urllib2.urlopen(r)
                    resp = req.read()
                    if req.getcode()==200:
                            print(color['yellow'] + 'Found '+ line + color['white'] + "\n" ) #Found
                            rela.append(coneccion_url)
                    else:
                            print(color['green'] + '/' + coneccion_url + "\n") #Redirection
                            redi.append(coneccion_url) 
                except urllib2.HTTPError as e:
                        if e.code == 401:
                                print(color['red'] + '|' + coneccion_url() + "\n") #Possible suspicion
                                avai.append(coneccion_url)
                        elif e.code == 404:
                                #print(color['red'] + '-' + color['white']) #Not Found
                                pass
                        elif e.code == 503:
                                print(color['red'] + 'x' + coneccion_url + "\n") #Not Found
                        else:
                                print(color['blue'] + '/' + coneccion_url + "\n") #Redirection
                                redi.append(coneccion_url)                                   
        print('\n')
        print( color['blue'] + "[!]" + " " + color['green'] + "Result:" + color['white'])
    
           
        if len(rela) == 0:
            print(color['green'] + "\t Nothing Found" + color['white']) # founds
            print(color['green'] + '================================================================' + color['white'])
        else:
             print(color['blue'] + "[>]" + " " + color['yellow'] + "Possible malicious files\n" + color['white'])
             for relas in rela:
                 print(color['red'] + "\t Shell: " + relas + color['white']) # founds
                 print(color['red'] + '================================================================' + color['white'])
        if not avai:
            pass
        else:
            print(color['blue'] + "[+]" + " " + color['yellow'] + "Possible detected WebShell\n" + color['white'])
            for avais in avai:
                print(color['red'] + "\t WebShell: " + color['white'] + avais)
                print(color['yellow'] + '==================================================================' + color['white'])
        if not redi:
            pass
        else:
            print("Statements of other income")
            for redis in redi:
                print(color['red'] + "\t" + color['white'] + redis)
                print(color['blue'] + '===================================================================' + color['white'])
                
if __name__ == "__main__":
        try:
            gscan()
        except KeyboardInterrupt:
            pass
        except Exception as e:
            print(color['red'] + "Error: " + color['white'] + "%s" % e )
