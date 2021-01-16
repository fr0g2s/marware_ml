# system module
import os,sys
import time, glob, csv
import pefile
import math
import glob
import os
import random
import subprocess
import shutil
# user module
cwd = os.getcwd()
sys.path.append(cwd)
from common import common
from common import strings

'''
    # Extract Features. Ver.BoB. 2021.
                            by hyunmini
'''

class FeatureExtractor():

    def __init__(self, source, output):
        
        self.listAPI = [ 
            'CreateMutex', 
            'CreateFile', 
            'WinExec', 
            'CreateProcess', 
            'ShellExecute',
            'SetWindowsHookEx', 
            'IsDebuggerPresent',
            'Sleep',
            'VirtualProtect',
            'UrlDownloadToFile',
            'DeleteFile',
            'ReadProcessMemory',
            'GetModuleHandleA',
            'WinHttpOpen'
            # add api here
        ]
        
        self.listStrings = [
            '.exe', '.vbs', '.bat', 'powershell', 'del.exe /', 
            'del /','cmd /', 'taskmgr','taskkill', 'mshta', 'ollydbg', 'w32dasm',
            'admin', 'ttp=', 'cks=', 'o/o/', 'advpack','1+KY','Rich'
            # add string here
        ]

        self.header = ['lable'] + self.listAPI + self.listStrings

        self.source = source
        self.output = output
        self.target = ''
        self.pe = None
        self.allFeature = []

    def extract_maliciousAPI(self):

        importString = ''
        for mod in self.pe['pe_imports']:
            for func in mod['imports']:
                importString += func['name'].decode('utf-8')

        results = []
        
        for api in self.listAPI:
            results.append(importString.lower().count(api.lower()))

        return results

    def extract_string(self):
        results = []

        all_strings = strings.Strings(self.target)
        all_strings = ' '.join(all_strings.run())
        #print(all_strings)

        for strCate in self.listStrings:
            results.append(all_strings.lower().count(strCate.lower()))

        return results

    def getFeature(self, target):
        data =[]
        # label
        if '1.vir' in target:
            data.append(1)
        else:
            data.append(0)

        # load given file
        pe = common.PortableExecutable(self.target)
        self.pe = pe.analysis()

        # extract features
        data += self.extract_maliciousAPI() 
        data += self.extract_string()   

        return data

    def getFeaturesAll(self):
        '''
            Extract feature from target folder
        '''
        results = []
        targets = glob.glob(self.source + '/*.vir')
        
        maxlen = len(targets) 

        index = 0
        
        for target in targets:
            index += 1
            print("[{}/{}] target: ".format(index,maxlen), target)
            self.target = target
            target = target.replace('\\','/')
            result = self.getFeature(self.target)
            results.append(result)
            # if index == 100:
            #     break
            
        self.allFeature = results        
        return results

    def saveToFile(self):
        # save Header
        csv_file= open(self.output,"w",  newline='')
        writer = csv.writer(csv_file, delimiter=',')
        writer.writerow(self.header)

        # save Feature Data
        for feature in self.allFeature:
            writer.writerow(feature)
        csv_file.close()
        



if __name__ == '__main__':
    # main #
    start_time = time.time()
    srcPath = ""
    if len(sys.argv) != 2:
        print("Usage: python {} [targetPath]".format(sys.argv[0]))
        sys.exit()

    srcPath = sys.argv[1]
    destPath = "features.csv" 

    features = FeatureExtractor(source=srcPath,output=destPath)    
    features.getFeaturesAll()
    features.saveToFile()

    end_time = time.time()
    
    print("WorkingTime: {} sec".format(end_time-start_time))

    print("[+] Finish !!")
