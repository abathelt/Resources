# OSINT
##### Notes from the The Cyber Mentor OSINT course. <br />
https://academy.tcm-sec.com/p/osint-fundamentals <br />

Content: <br />
- [Search Engine Operators](#SEO)
- [Reverse Image Searching](#RIS)
- [Identifying Geographical Locations](#IGL)
- [Discovering Email Addresses](#DEA)
- [Hunting Breached Credentials](#HBC)
- [Hunting Usernames and Accounts](#HUA)
- [Searching for People](#SfP)
- [Voter Records](#VR)
- [Hunting Phone Numbers](#HPN)
- [Discovering Birthdates](#DB)
- [Searching for Resumes](#SfR)
- [Twitter](#T)
- [Facebook](#FB)
- [Instagram](#IG)
- [Snapchat](#SN)
- [Reddit](#R)
- [LinkedIn](#LI)
- [TIKTOK](#TK)
- [Website](#Web)
- [Hunting Business Information](#HBI)
- [Wireless](#Wireless)
- [Building an OSINT Lab](#Lab)
- [Tools](#Tools)
- [Frameworks](#frame)
- [Additional Resources](#AR)

### <a name="SEO"></a>Search Engine Operators
- "name" site:reddit.com
- [Google](https://www.google.com/)
- [Google Advanced Search](https://www.google.com/advanced_search)
- [Google Search Guide](http://www.googleguide.com/print/adv_op_ref.pdf)
- [Bing](https://www.bing.com/)
- [Bing Search Guide](https://www.bruceclay.com/blog/bing-google-advanced-search-operators/)
- [Yandex](https://yandex.com/)
- [DuckDuckGo](https://duckduckgo.com/)
- [DuckDuckGo Search Guide](https://help.duckduckgo.com/duckduckgo-help-pages/results/syntax/)
- [Baidu](http://www.baidu.com/)

### <a name="RIS"></a> Reverse Image Searching
- [Google Image Search](https://images.google.com)
- [Yandex](https://yandex.com)
- [TinEye](https://tineye.com)
- [Jeffrey's Image Metadata Viewer](http://exif.regex.info/exif.cgi)

### <a name="IGL"></a> Identifying Geographical Locations
- [GeoGuessr](https://www.geoguessr.com)
- [GeoGuessr - The Top Tips, Tricks and Techniques](https://somerandomstuff1.wordpress.com/2019/02/08/geoguessr-the-top-tips-tricks-and-techniques/)

### <a name="DEA"></a>Discovering Email Addresses
- [Hunter.io](https://hunter.io/)
- [Phonebook.cz](https://phonebook.cz/)
- [VoilaNorbert](https://www.voilanorbert.com/)
- [Email Hippo](https://tools.verifyemailaddress.io/)
- [Email Checker](https://email-checker.net/validate)
- [Clearbit Connect](https://chrome.google.com/webstore/detail/clearbit-connect-supercha/pmnhcgfcafcnkbengdcanjablaabjplo?hl=en)

### <a name="HBC"></a> Hunting Breached Credentials 
- [Dehashed](https://dehashed.com/)
- [WeLeakInfo](https://weleakinfo.to/v2/)
- [LeakCheck](https://leakcheck.io/)
- [SnusBase](https://snusbase.com/)
- [Scylla.sh](https://scylla.sh/)
- [HaveIBeenPwned](https://haveibeenpwned.com/)

### <a name="HUA"></a>Hunting Usernames and Accounts
- [NameChk](https://namechk.com/)
- [WhatsMyName](https://whatsmyname.app/)
- [NameCheckup](https://namecheckup.com/)

### <a name="SfP"></a> Searching for People
- [WhitePages](https://www.whitepages.com/)
- [TruePeopleSearch](https://www.truepeoplesearch.com/)
- [FastPeopleSearch](https://www.fastpeoplesearch.com/)
- [FastBackgroundCheck](https://www.fastbackgroundcheck.com/)
- [WebMii](https://webmii.com/)
- [PeekYou](https://peekyou.com/)
- [411](https://www.411.com/)
- [Spokeo](https://www.spokeo.com/)
- [That'sThem](https://thatsthem.com/)

### <a name="VR"></a> Voter Records
- [Voter Records](https://www.voterrecords.com)

### <a name="HPN"></a> Hunting Phone Numbers
- you can search with emojis (phone emoji) in google. 
- [TrueCaller](https://www.truecaller.com/)
- [CallerID Test](https://calleridtest.com/)
- [Infobel](https://infobel.com/)

### <a name="DB"></a>Discovering Birthdates
- Search in google: <br />
- "Name" intext:"birthday"<br />
- "Name" intext:"happy birthday" site:facebook.com<br />

### <a name="SfR"></a> Searching for Resumes
Search in google: <br />
- "Name" site:linkedin.com 
- "Name" resume filetype:pdf 
- "Name" resume filetype:doc 
- "Name" resume site:dropbox.com 
- "Name" resume site:google.com 
- "Name" resume site:drive.google.com 
- "Name" resume site:scribd.com 

### <a name="T"></a>Twitter
- [Twitter Advanced Search](https://twitter.com/search-advanced)
- Use hashtags
- to:username - who replay to user
- @username - checks who tag that user
- from:username since:2019-02-01 until:2019-03-01
- from:username word
- geocode:34.0206842,-118.551814,11<b>km</b> - geolocation, it requires km at the end, eg. 11km. 
- geocode:34.0206842,-118.551814,11km to:username
- [Social Bearing](https://socialbearing.com/)
- [Twitonomy](https://www.twitonomy.com/)
- [Sleeping Time](http://sleepingtime.org/)
- [Mentionmapp](https://mentionmapp.com/)
- [Tweetbeaver](https://tweetbeaver.com/)
- [Spoonbill.io](http://spoonbill.io/)
- [Tinfoleak](https://tinfoleak.com/)
- [TweetDeck](https://tweetdeck.com/) ⭐

### <a name="FB"></a> Facebook
- [Sowdust Github](https://sowdust.github.io/fb-search/)
- [IntelligenceX Facebook Search](https://intelx.io/tools?tab=facebook)
- In Facebook search: photos of Mark Zuckerberg - it shows photo he post and the one people tagged him 
- search for user ID in FB - View page source and search (ctrl+f) "userID" - this is needed for IntelligenceX Facebook Search

### <a name="IG"></a> Instagram
- [Wopita](https://wopita.com/) 
- [Code of a Ninja](https://codeofaninja.com/tools/find-instagram-user-id/) - find user ID
- [InstaDP](https://www.instadp.com/) - full size of the images
- [ImgInn](https://imginn.com/) - you can download save images
- Search in Google: username site:instagram.com

### <a name="SN"></a> Snapchat
- [Snapchat Maps](https://map.snapchat.com)

### <a name="R"></a> Reddit
- reddit.com/u/username
- In Reddit search: username
- In Reddit search: "username"
- Use sort by
- Analyze user's profile - check comment section there might be some sensitive information
- In Google: "username" site:reddit.com
- In Google: "username" site:reddit.com intext:searchedphrase

### <a name="LI"></a> LinkedIn
- Contact information
- Location
- LION - open networkers - to create a connection for fake account - A LION is a LinkedIn Open Networker – instead of connecting only with people you know, as LinkedIn recommends, LIONs connect with everybody. They'll always accept an invitation. Some even put "LION" after their name.

### <a name="TK"></a> TIKTOK
- Check image for reverse image
- Search for historical data

### <a name="Web"></a> Website
- In Google: site:example.com name
- [BuiltWith](https://builtwith.com/) - what the website is built in (frameworks, widgets etc)
- [Domain Dossier](https://centralops.net/co/) - checkbox service scan (passive recon)
- [DNSlytics](https://dnslytics.com/reverse-ip) - search for all domains which use the IP address
- [SpyOnWeb](https://spyonweb.com/) - search for IP, domain, analytics (UA)
- [Virus Total](https://www.virustotal.com/) - you can find UA in the datils - Google Tag Manager
- [Visual Ping](https://visualping.io/) - how the website change over a time
- [Back Link Watch](http://backlinkwatch.com/index.php) - looking for backlinks if the link to the website was posted somewhere else
- [View DNS](https://viewdns.info/)
- reddit.com/domain/example.com 
- In Google: site:example.com -www inrul:admin
- [SubdomainRadar](https://subdomainradar.io) - Discover and track the largest number of subdomains using multiple exclusive data sources.
- [Pentest-Tools Subdomain Finder](https://pentest-tools.com/information-gathering/find-subdomains-of-domain#)
- [Spyse](https://spyse.com/)
- [crt.sh](https://crt.sh/) - search: %.example.com
- [Shodan](https://shodan.io)
- In Shodan: ciy:atlanta port:3389 org:choopa
- [Wayback Machine](https://web.archive.org/)
- In Google: search for website, click on 3 dots next to address and pick cached if the website is not available right now. 

### <a name="HBI"></a> Hunting Business Information
- Search for badge, desk, dresscode, apps on LinkedIn 
- When in LinkedIn the user's name is not visible, you can copy the user's title and do google search to find the person.
- In Google: site:linkedin.com/in/ "* at Company Name" - search for people form a particular company
- [Open Corporates](https://opencorporates.com/)
- [AI HIT](https://www.aihitdata.com/)
- [Indeed](https://indeed.com/) - job posting

### <a name="Wireless"></a> Wireless
- [WiGLE](https://wigle.net/) - advance search

### <a name="Lab"></a> Building an OSINT Lab
- [VMWare Workstation Player](https://www.vmware.com/ca/products/workstation-player/workstation-player-evaluation.html)
- [VirtualBox](https://www.virtualbox.org/wiki/Downloads)
- [TraceLabs OSINT VM](https://www.tracelabs.org/initiatives/osint-vm)
- [TraceLabs OSINT VM Installation Guide](https://download.tracelabs.org/Trace-Labs-OSINT-VM-Installation-Guide-v2.pdf)

### <a name="Tools"></a> Tools
- ExifTool
 ```
sudo apt install libimage-exiftool-perl
exiftool <img>
```

- [breach-parse](https://github.com/hmaverickadams/breach-parse)
- theHarvester
```
theHarvester -d tesla.com -b google -l 500
./breach-parse.sh @tesla.com tesla.txt
```
- [H8mail](https://github.com/khast3x/h8mail)
An email OSINT and breach hunting tool using different breach and reconnaissance services, or local breaches such as Troy Hunt's "Collection1" and the infamous "Breach Compilation" torrent.
```
h8mail -t shark@tesla.com -bc "/opt/breach-parse/BreachCompilation/" -sk
 ```
- Whatsmyname
```
whatsmyname -u thecybermentor
```

- Sherlock
 ```
sherlock thecybermentor
 ```

- [Phoneinfoga](https://github.com/sundowndev/phoneinfoga)
```
phoneinfoga scan -n 14082492815
phoneinfoga serve -p 8080
```

- [Twint](https://github.com/twintproject/twint)
```
pip3 install --upgrade -e git+https://github.com/twintproject/twint.git@origin/master#egg=twint
pip3 install --upgrade aiohttp_socks
twint -u username
twint -u username -s WordOfInterest
```

- Before you install below tools
```
nano ~/.bashrc

export GOPATH=$HOME/go 
export GOROOT=/usr/lib/go
export PATH=$PATH:$GOROOT/bin:$GOPATH/bin
```

- [Subfinder](https://github.com/projectdiscovery/subfinder)
```
GO111MODULE=on go get -u -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder
assetfinder tcm-sec.com
```
- [Assetfinder](https://github.com/tomnomnom/assetfinder)
```
go get -u github.com/tomnomnom/assetfinder
assetfinder tcm-sec.com
```
- [httprobe](https://github.com/tomnomnom/httprobe)
```
go get -u github.com/tomnomnom/httprobe
cat tesla.txt | sort -u | httprobe -s -p https:443
```
- [Amass](https://github.com/OWASP/Amass)
```
amass enum -d tcm-sec.com
```
- [GoWitness](https://github.com/sensepost/gowitness/wiki/Installation)
```
go get -u github.com/sensepost/gowitness
export GO111MODULE=on
gowitness file -f ./alive.txt -P ./pics --no-http
```

### <a name="frame"></a> Frameworks
- Recon-ng
```
marketplace search

marketplace install hackertarget
modules load hackertarget
options set SOURCE example.com
run
show hosts

marketplace install profiler
modules load profiler
info
options set SOURCE username
run
show profiles
```
- Spiderfoot
- sn0int
- Maltego
- [Hunchly](https://hunch.ly) - 30 day trial, paid $129.99, runs only in Google Chrome 

### <a name="AR"></a> Additional Resources
- [TraceLabs](https://www.tracelabs.org/)
- [Innocent Lives Foundation](https://www.innocentlivesfoundation.org/)
- [Alethe Denis](https://twitter.com/AletheDenis)
- [Joe Gray](https://twitter.com/C_3PJoe)
- [IntelTechniques](https://inteltechniques.com/)
- [OSINT Flowcharts](https://github.com/willc/OSINT-flowcharts)
