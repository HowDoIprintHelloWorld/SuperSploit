import requests, time, sys, pyfiglet, json, socket
from bs4 import BeautifulSoup

tagsl = ["-i", "-v", "-b", "-m", "-u", "-a"]
tags = {"-i":"", "-v":False, "-b":False, "ip":[], "hosts":[], "files":[], "-u":False}
data = {}
# https://internetdb.shodan.io/[ip]
 

def help():
  helpstr = """
  Usage:
  
      python3 scan4vulns.py [arguments] [IPs/URLs/.txt]


  Arguments:
  
    -h       ===>>     Displays this help message

    -v       ===>>     Displays verbose messages (DNS & Scan points)

    -b       ===>>     Most important: Display the banner :)

    -m       ===>>     URLs are only registred with one '.', use -m to manually\n                       assign the following parameter the "url" tag

    -u       ===>>     Displays the URLs for the found CVEs. Also displays the \n                       severity of found CVEs (!Warning! This will take a lot longer than usual)
                       
    -a       ===>>     Because I'm lazy, this tag applies -b, -v & -u in one argument
  """
  print(helpstr)




# Gets supplied arguments by checking if arg is in
# tagsl. If it is, assign the following value to arg in tags (dict)
def getargs():
  paraml = sys.argv[1:]
  for i in paraml:
    if i in tagsl:
      if i == "-m":
        tags["hosts"].append(sys.argv[sys.argv.index(i)+1])
      elif i == "-a":
        for j in ["-v", "-b", "-u"]:
          paraml.append(j)
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
    if "-" in i and i not in tagsl and len(i) <= 2:
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
    print(pyfiglet.figlet_format(">> Scan4Vulns <<"))
    print(">>   Kind of daft vuln searcher, but has its uses I guess  <<\n")

# Searches the InternetDB for raw info on the target
def internetdbsearch():
  verbose("---------------[    SCANNING IP    ]---------------")
  try:
    for i in tags["ip"]:
      verbose(f"|   Scanning IP '{i}'...")
      data[str(i)] =  requests.get(f"https://internetdb.shodan.io/{i}").json()
      verbose(f"|   [✔]   Scanning of '{i}' done")
  except TypeError:
    pass
  verbose("---------------[   DONE WITH SCAN   ]---------------\n\n\n")
  return data

def makeseparator():
  seperator = "========================================================="
  verbose(seperator)
  verbose("-----------------------> RESULTS <-----------------------")          
  verbose(f"{seperator}\n\n")


# Reads a given .txt file and appends all found URLs to hosts
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

# Handles DNS to get scannable IPs for previously found URLs
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

# Takes found data and presents it nicely :)
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
      print("|\n|   >>   Vulns:", end="")
      for b in i["vulns"]:
        if i["vulns"].index(b)+1 < 10:
          print(f"\n|   [v{i['vulns'].index(b)+1}]   {b}", end="")
        else:
          print(f"\n|   [v{i['vulns'].index(b)+1}]  {b}", end="")
        if tags["-u"]:
          print(f"     -      {getseverity(b)}\n|   https://nvd.nist.gov/vuln/detail/{b}\n|", end="")
    else:
      print("|\n|   >>   No vulns found!")
    print(f"\n{endstr}\n\n")

# If the -u parameter is supplied (or -a), prints out the severity
def getseverity(cve):
  try:
    content = requests.get(f"https://nvd.nist.gov/vuln/detail/{cve}").text
    soup = BeautifulSoup(content, features="html5lib")
    severity = soup.find(id="Cvss3NistCalculatorAnchor").get_text()
  except AttributeError:
    return "No severity found..."
  return severity
  
  
# Starts everything up
if __name__ == "__main__":
  if "-h" in sys.argv:
    help()
    sys.exit()
  tags = getargs()
  banner()
  tags = readtxtforurls()
  tags = handledns()
  data = internetdbsearch()
  makeseparator()
  parsedata()
  
