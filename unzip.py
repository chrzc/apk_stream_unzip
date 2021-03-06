# -*- coding: utf-8 -*-
"""
Created on Tue Sep 18 10:46:17 2018

@author: 87985
"""



from __future__ import print_function
import sys
import hexdump
import sys,os
import pandas as pd
import requests 
import re
import tarfile, io
from argparse import ArgumentParser
import lxml.etree as etree

from androguard.core import androconf
from androguard.core.bytecodes import apk
from androguard.util import read

def run(url): # url is a apk download url
    try:
        r1 = requests.head(url,timeout=5)
        if (r1.status_code == 302):
            r1 = requests.get(url,stream=True)
        if ('Content-Length' in r1.headers):
            #print (r1.headers)
            range_end = r1.headers['Content-Length']
            range_start = str(int(r1.headers['Content-Length']) - 1024*1024)
            
            headers = {'Range': 'bytes='+range_start+'-'+range_end}
            r1.close()
            r = requests.get(url=url,headers=headers,timeout=5) #cut the last 1M content and deal 302 status code
            if (b'resources.arsc' in r.content):
                print("YES")
                start_46 = r.content.find(b'resources.arsc')
                start_0 = start_46 - 46
                if (r.content[start_0:start_0+4]==b'\x50\x4b\x01\x02'):
                    disk_number_start = r.content[start_0+42:start_0+46]
                    compressed_size = r.content[start_0+20:start_0+24]
                    number_start = int.from_bytes(disk_number_start, byteorder='little')
                    number_end = number_start + int.from_bytes(compressed_size, byteorder='little')
                    if (number_end + 1000 < int(range_end)):
                        headers = {'Range': 'bytes=' + str(number_start) + '-' + str(number_end+1000)}
                    else:
                        headers = {'Range': 'bytes=' + str(number_start) + '-'}
                    r.close()
                    r3 = requests.get(url=url,headers=headers,timeout=5)
                    a = r3.content
                    r3.close()
                    com_size = a[18:22]
                    name_length = a[26:28]
                    extra_length = a[28:30]
                    size2  = int.from_bytes(com_size, byteorder='little')#file_uncompressed_size
                    n = int.from_bytes(name_length, byteorder='little') #file_name_length
                    m = int.from_bytes(extra_length, byteorder='little')
                    resc = a[30+n+m:30+n+m+size2]
                    kkk = apk.ARSCParser(resc)
                    #list1.append(kkk.get_packages_names()[0])          
                    x = kkk.get_string(kkk.get_packages_names()[0],"app_name")[1]
                    print(x)
                    return x
                else:
                    return ('')
            else:
                return ('')
        else:
            return ('')
    except:
        return ('')
    return ('')
	
# if it has information, it return a list of package_name and app_name
