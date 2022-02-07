import requests, time, sys, pyfiglet, json, socket

tagsl = ["-i", "-v", "-b", "-m"]
tags = {"-i":"", "-v":False, "-b":False, "ip":[], "hosts":[], "files":[]}
data = {}
# https://internetdb.shodan.io/[ip]
 

# Gets supplied arguments by checking if arg is in
# tagsl. If it is, assign the following value to arg in tags (dict)
def getargs():
  for i in sys.argv[1:]:
    if i in tagsl:
      if i == "-m":
        tags["hosts"].append(sys.argv[sys.argv.index(i)+1])
      elif type(tags[i]) == type(str(tags["-i"])):
        tags[i] = sys.argv[sys.argv.index(i)+1]
      elif not tags[i]:
        tags[i] = True
    if i.count(".") == 3:
      tags["ip"].append(i)
    elif i.count(".") == 1 and i not in tags["hosts"] and i[-3:] != "txt":
      tags["hosts"].append(i)
    elif i.count(".") == 1 and i not in tags["hosts"] and i[-3:] == "txt":
      tags["files"].append(i)
    if "-" in i and i not in tagsl and len(i) <= 3:
      print(f"[!] Flag '{i}' not recognized, skipping it")
  return tags

# Essentially print(), but checks to see if verbose
# mode is on before printing
def verbose(string):
  if tags["-v"] == True:
    print(string)

# Probably the most important part: Prints the Banner
def banner():
  if tags["-b"] == True:
    print(pyfiglet.figlet_format(">> SuperSploit <<"))
    print(">>   Kind of daft vuln searcher, but has its uses I guess  <<\n")

def internetdbsearch():
  verbose("---------------[    SCANNING IP    ]---------------")
  try:
    for i in tags["ip"]:
      verbose(f"|   Scanning IP '{i}'...")
      data[str(i)] =  requests.get(f"https://internetdb.shodan.io/{i}").json()
      verbose(f"|   [✔]   Scanning of '{i}' done")
  except TypeError:
    pass
  verbose("---------------[   DONE WITH SCAN   ]---------------\n")
  return data

def readtxtforurls():
  try:
    for i in tags["files"]:
      try:
        with open(i, "r") as file:
          lines = [p for line in file for p in line.split()]
          for i in lines:
            if i.count(".") == 3:
              tags["ip"].append(i)
            else:
              tags["hosts"].append(i)
      except FileNotFoundError:
        verbose(f"[!]   File '{i}' not found, skipping it...")
  except TypeError:
    pass
  return tags

def handledns():
  verbose("---------------[    HANDLING DNS    ]---------------")
  try:
    for i in tags["hosts"]:
      verbose(f"|   Resolving DNS for URL '{i}'...")
      try: 
        ip = str(socket.gethostbyname(i))
        tags["ip"].append(ip)
        verbose(f"|   [✔]   IP for '{i}' found: '{ip}'")
      except UnicodeError:
        verbose(f"[!]   DNS resolution for '{i}' failed, URL too long. Skipping it")
      except socket.gaierror:
        verbose(f"[!]   DNS resolution for '{i} failed, URL not found. Skipping it")
  except TypeError:
    pass
  verbose("---------------[   DONE WITH DNS   ]---------------\n")
  verbose("\n")
  return tags

def parsedata():
  for i in data:
    i = data[i]
    headerstr = f"---------------[ Results for {i['ip']} ]---------------"
    endstr = ""
    for p in range(len(headerstr)):
      endstr += "-"
    print(headerstr)
    if i["hostnames"]:
      print("|\n|   >>   Hostnames:")
      for b in i["hostnames"]:
        print(f"|   [h]   {b}")
    if i["cpes"]:
      print(f"|\n|   >>   CPEs found:")
      for b in i["cpes"]:
        print(f"|   [{b[5]}]   {b[7:]}")
    print("|\n|   >>   Ports:")
    for b in i["ports"]:
      print(f"|   [p]   {b}")
    if i["vulns"]:
      print("|\n|   >>   Vulns:")
      for b in i["vulns"]:
        print(f"|   [v]   {b}")
    else:
      print("|\n|   >>   No vulns found!")
    print(f"{endstr}\n\n")
  
  
# Starts everything up
if __name__ == "__main__":
  tags = getargs()
  banner()
  tags = readtxtforurls()
  tags = handledns()
  data = internetdbsearch()
  parsedata()
  
