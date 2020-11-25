#!/bin/bash

directory=$1

######################################################
#Usage 
#

if [ -z "$1" ]
  then
    echo "Usage: ./cliShellScanner.sh <root website directory>"
    echo "Example Usage: ./cliShellScanner.sh /var/www/html/"
  exit
fi

######################################################
#Create Directory 
#

if [ ! -d "recon" ];then
      mkdir recon
fi

######################################################
#Finding Shell Files extension
#

echo "[+] Harvesting shell files using common shell file extension..."
find $directory -type f \( -name '*.php3' -o -name '*.php4' -o -name '*.php5' -o -name '*.phtml' -o -name '*.php' -o -name '*.pl' -o -name '*.py' -o -name '*.cgi' -o -name '*.asp' -o -name '*.html' -o -name '*.htm.*'-o -name '*.php3.*' -o -name '*.php4.*' -o -name '*.php5.*' -o -name '*.phtml.*' -o -name '*.phar.*' -o -name '*.php.*' -o -name '*.pl.*' -o -name '*.py.*' -o -name '*.cgi.*' -o -name '*.asp.*' -o -name '*.js.*' -o -name '*.html' -o -name '*.htm'  \) >> ./recon/qualifier.txt
sleep 1

######################################################
#Common content for shell
#

echo "[+] Finding unique string inside file extensions..."
for shellfile in $(cat ./recon/qualifier.txt);do grep -rnl -E 'IndoXploit'\|'b374k'\|'c99'\|'R57'\|'shell'\|'Shell'\|'Sh3ll'\|'bindport'\|'exploit'\|'sha1'\|'chunk_split'\|'back_connect'\|'backdoor'\|'file_uploads'\|'netcat'\|'/etc/passwd'\|'dbname'\|'login_shell'\|'hacked'\|'Hacked'\|'0x1999'\|'multipart/form-data'\|'base64_encode'\|'base64_decode'\|'eval'\|'function'\|'Obfuscation'\|'proxy'\|'getenv'\|'exec'\|'public_html'\|'getcwd'\|'md5_pass'\|'download'\|'Brute'\|'Backdoor'\|'Encoder'\|'urldecode'\|'defaced'\|'deface'\|'Defaced'\|'Legion'\|'Touched By'\|'WORM'\|'INTRUDER'\|'setcookie' $shellfile >> ./recon/semifinal1.txt; done
sleep 1

######################################################
#PHP Shell Files extension
#

echo "[+] Harvesting PHP file created & modified 30 days ago..."
find $directory -type f -name '*.php' -mtime -30 >> ./recon/quaterfinal.txt
sleep 1

echo "[+] Finding unique string inside PHP file extensions..."
for phpfile in $(cat ./recon/quaterfinal.txt);do grep -rnl -E 'IndoXploit'\|'b374k'\|'c99'\|'R57'\|'shell'\|'Shell'\|'Sh3ll'\|'bindport'\|'exploit'\|'sha1'\|'chunk_split'\|'back_connect'\|'backdoor'\|'file_uploads'\|'netcat'\|'/etc/passwd'\|'dbname'\|'login_shell'\|'hacked'\|'Hacked'\|'0x1999'\|'multipart/form-data'\|'base64_encode'\|'base64_decode'\|'eval'\|'function'\|'Obfuscation'\|'proxy'\|'getenv'\|'exec'\|'public_html'\|'getcwd'\|'md5_pass'\|'download'\|'Brute'\|'Backdoor'\|'Encoder'\|'urldecode'\|'defaced'\|'deface'\|'Defaced'\|'Legion'\|'Touched By'\|'WORM'\|'INTRUDER'\|'setcookie'  $phpfile >> ./recon/semifinal.txt; done
sleep 1

echo "[+] Harvesting done..."
sleep 1

######################################################
#Finalizing file list
#

echo "[+] Sorting files..."
sort ./recon/semifinal1.txt | uniq > ./recon/prefinal.txt
sort ./recon/semifinal.txt | uniq >> ./recon/prefinal.txt
sleep 1

echo "[+] Checking files for false positive..."

STRING="view.html.php"
for checkfile in $(cat ./recon/prefinal.txt);do 
	if [[ "$checkfile" != *"$STRING"* ]];then
		echo $checkfile >> ./recon/prefinal1.txt
	fi
done

STRING="module.audio"
for checkfile in $(cat ./recon/prefinal1.txt);do 
	if [[ "$checkfile" == *"$STRING"* ]];then
		echo $checkfile >> ./recon/prefinal2.txt
	fi
done

STRING="module.tag"
for checkfile in $(cat ./recon/prefinal1.txt);do 
	if [[ "$checkfile" == *"$STRING"* ]];then
		echo $checkfile >> ./recon/prefinal2.txt
	fi
done

for stringfile in $(cat ./recon/prefinal1.txt);do grep -rnl -E 'GNU'\|'BSD'\|'opensource'\|'Opensource'\|'license'\|'LICENSE'\|'Redistributions'\|'framework'\|'WARRANTY'\|'Annex'\|'Cyrillic'\|'nodecounter'\|'Sodium'\|'sodium'\|'PHPMailer'\|'log-level'\|'Unicode'\|'unicode'\|'composer'\|'ReCaptcha'\|'www.php.net'\|'PCRE'\|'ASCII'\|'utf-8'\|'WordPress'\|'wp_scripts'\|'Etag'\|'akismet'\|'hello_dolly'\|'IDNA'\|'Polyfill'\|'logger'\|'IXR_'\|'Requests_Hooks'\|'AtomLib'\|'WP_Date_Query'\|'Translation_Entry'\|'POMO_Reader'\|'Requests_Cookie'\|'Requests_Exception'\|'Requests_Hooker'\|'Requests_Response'\|'Requests_Utility'\|'Plural_Forms' $stringfile  >> ./recon/prefinal2.txt;done

echo "[+] Sorting and removing duplicates line..."
sort ./recon/prefinal1.txt | uniq > ./recon/prefinal3.txt
sort ./recon/prefinal2.txt | uniq >> ./recon/prefinal3.txt
sort ./recon/prefinal3.txt | uniq -u >> ./recon/final.txt
sleep 1

echo "[+] Deleting temp files..."
rm -rf ./recon/qualifier.txt
rm -rf ./recon/quaterfinal.txt
rm -rf ./recon/semifinal.txt
rm -rf ./recon/semifinal1.txt
rm -rf ./recon/prefinal.txt
rm -rf ./recon/prefinal1.txt
rm -rf ./recon/prefinal2.txt
rm -rf ./recon/prefinal3.txt
sleep 1

echo "[+] Suspected shell are in "$directory"recon/final.txt"
sleep 1

echo "[+] Listing the files for you..."
cat ./recon/final.txt
sleep 1

echo "[+] Done!"

exit
