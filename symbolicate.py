#! /usr/local/bin/python
# -*- coding: utf-8 -*-

' iOS symbolicate crash '

__author__ = 'liuqing'

import sys
import os
import re
import commands

# BinaryImage
class BinaryImage (object):

    def __init__(self, *args):
        self.startAddr = args[0]
        self.endAddr = args[1]
        self.libName = args[2]
        self.arch = args[3]
        self.uuid = args[4]
        self.symPath = args[5]

# Target
class Target (object):

    def __init__(self, libName, addr, lineNum):
        self.libName = libName
        self.addr = addr
        self.lineNum = lineNum


# helpers
def parseAppName(line):

    # example: "Process:   AppName  [800]"

    components = line.split()
    return components[1]


def parseAppVersion(line):

    # example: "Version:    7.9 (912)"

    components = line.split(":")
    return components[1].strip()


def parseArch(line):

    # example: "Code Type: ARM-64"

    components = line.split(":")
    return components[1].split()


def parseOSVersion(line):

    # example: "OS Version:    iOS 9.3.5 (13G36)"

    components = line.split(":")
    ver = components[1]
    subComponents = ver.split()
    length = len(subComponents)
    return subComponents[length - 2] + " " + subComponents[length - 1]


def parseBinaryImage(line):

    # example: "0x181d8f000 - 0x182112fff  CoreFoundation arm64  <d72e357f5b3337aa9693522564a6032e> /System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"

    components = line.split()
    uuid = components[5]
    if uuid.startswith("<") and uuid.endswith(">"):
        uuid = uuid[1:len(uuid) - 1].lower()
    components[5] = uuid
    return BinaryImage(*([components[0]] + components[2:len(components)]))


def isUUIDMatch(uuidInLog, uuidsInSym, arch):
    uuidDescs = []
    if isinstance(uuidsInSym, basestring):
        uuidDescs = uuidsInSym.split("\n")
    elif isinstance(uuidsInSym, list):
        uuidDescs = uuidsInSym

    res = False
    for uuidDesc in uuidDescs:
        if arch in uuidDesc:
            uuid = (uuidDesc.split())[1]
            uuid = "".join(uuid.split("-")).lower()
            if uuid == uuidInLog:
                res = True

    return res


# check the validity
if len(sys.argv) != 3:
    print("Usage: python " + os.path.basename(sys.argv[0]) + " <CRASH_LOG_PATH> <dSYM_PATH>")
    os._exit(1)

crashPath = sys.argv[1]
symPath = sys.argv[2]

if not os.path.exists(crashPath):
    print("crash log doesn't exist.")
    os._exit(1)

if not os.path.exists(symPath):
    print("symbol file doesn't exist.")
    os._exit(1)


# gather info
appName = ""
appVersion = ""
arch = ""
OSVersion = ""
libName2BinaryImage = {}
libName2Targets = {}
output = []
downloadUrl = "https://github.com/Zuikyo/iOS-System-Symbols/blob/master/collected-symbol-files.md"
crashLog = open(crashPath)
lineNum = 0
line = crashLog.readline()
while line:
    output.append(line)

    line = line.strip()

    if line.startswith("Process:"):
        appName = parseAppName(line)

    if line.startswith("Version:"):
        appVersion = parseAppVersion(line)

    if line.startswith("Code Type:"):
        arch = parseArch(line)

    if line.startswith("OS Version:"):
        OSVersion = parseOSVersion(line)

    m = re.match(r"^\d+\s+([\w\.]+)\s+(0x\w+)\s+0x\w+\s+\+\s+\d+$", line)
    if m:
        libName = m.group(1)
        addr = m.group(2)
        target = Target(libName, addr, lineNum)
        if libName2Targets.has_key(libName):
            targets = libName2Targets[libName]
            targets.append(target)
        else:
            libName2Targets[libName] = [target]

    if re.match(r"^0x\w+\s+\-\s+0x\w+", line):
        binaryImage = parseBinaryImage(line)
        if appName in binaryImage.libName:
            binaryImage.libName = appName
        libName = binaryImage.libName
        libName2BinaryImage[libName] = binaryImage

    line = crashLog.readline()
    lineNum += 1

crashLog.close()

print("#################### INFO ####################")
print("\tApp: " + appName + " " + appVersion)
print("\tOS: iOS " + OSVersion)
print("################## END INFO ##################")
print("")

# begin symbolicating
sysSymPath = os.path.join(os.environ["HOME"], "Library/Developer/Xcode/iOS DeviceSupport", OSVersion, "Symbols")
if not os.path.exists(sysSymPath):
    cf = "\"" + OSVersion + "-Caches\""
    f = "\"" + OSVersion + "\""
    cf7z = "\"" + OSVersion + "-Caches.7z\""
    f7z = "\"" + OSVersion + ".7z\""
    print("Warning! System symbol file is absent.")
    print("You can:")
    print("1. Download " + cf7z + " or " + f7z + " from this repository: " + downloadUrl)
    print("2. Extract files from the .7z file")
    print("3. If the folder's name is " + cf + ", change directory to \"" + OSVersion + "-Caches/Symbols/System/Library/Caches/com.apple.dyld\", \n"
                                               "   and execute command: "
                                               "dsc_extractor " + "dyld_shared_cache_" + libName2BinaryImage[appName].arch + " \"" + sysSymPath + "\"")
    print("4. If the folder's name is " + f + ", just copy the folder to \"" + os.environ["HOME"] + "/Library/Developer/Xcode/iOS DeviceSupport/\"")
    print("5. Rerun this script")
    print("")

print("Begin symbolicating...")
for (libName, targets) in libName2Targets.iteritems():
    absSymPath = ""
    binaryImage = libName2BinaryImage[libName]
    if libName == appName:
        absSymPath = os.path.join(symPath, appName + ".app.dSYM", "Contents", "Resources", "DWARF", appName)
    elif re.match(r"^(/System|/usr)", binaryImage.symPath):
        absSymPath = sysSymPath + binaryImage.symPath

    absSymPath = "\"" + absSymPath + "\""

    cmd = "dwarfdump --uuid " + absSymPath
    code, res = commands.getstatusoutput(cmd)
    if code == 0:
        if isUUIDMatch(binaryImage.uuid, res, binaryImage.arch):
            addrs = map(lambda t: t.addr, targets)
            loadAddr = binaryImage.startAddr
            cmd = "xcrun atos -o " + absSymPath + " -arch " + binaryImage.arch + " -l " + loadAddr + " " + " ".join(addrs)
            print("")
            print(binaryImage.libName)
            print(cmd)
            print("")
            code, res = commands.getstatusoutput(cmd)
            substitues = res.split("\n")

            count = len(targets)
            for i in range(0, count):
                lineNum = targets[i].lineNum
                oldLine = output[lineNum]
                output[lineNum] = oldLine[0:oldLine.rindex("0x")] + substitues[i] + "\n"
        else:
            print("Warning! UUIDs of \"" + libName + "\" in crash log and .dSYM don't match.\n")

try:
    outFile = open("symbol.crash", "w")
    outFile.writelines(output)
    print("Done! The output file is \"" + os.path.join(os.getcwd(), "symbol.crash\"."))
except IOError:
    print("".join(output))
