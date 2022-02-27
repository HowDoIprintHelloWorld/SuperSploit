# SuperSploit

<h1>Scan4Vulns - A nice visualization and interface for the InternetDB</h1>

(More details coming soon :) )

Usage:
  
      python3 scan4vulns.py [arguments] [IPs/URLs/.txt]
  Arguments:
  
    -h       ===>>     Displays this help message
    -v       ===>>     Displays verbose messages (DNS & Scan points)
    -b       ===>>     Most important: Display the banner :)
    -m       ===>>     URLs are only registred with one '.', use -m to manually assign the following parameter the "url" tag
    -u       ===>>     Displays the URLs for the found CVEs. Also displays the severity of found CVEs (!Warning! This will take a lot longer than usual)
    -a       ===>>     Because I'm lazy, this tag applies -b, -v & -u in one argument
