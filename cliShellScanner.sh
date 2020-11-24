#!/bin/bash

directory=$1

if [ -z "$1" ]
  then
    echo "Usage: ./cliShellScanner.sh <root website directory>"
    echo "Example Usage: ./cliShellScanner.sh /var/www/html/"
  exit
fi

######################################################
#Directory 
#

if [ ! -d "recon" ];then
      mkdir recon
fi

######################################################
#Common Shell Files extension
#

echo "[+] Harvesting shell files using common shell file extension..."
find $directory -type f -name '*.php3' >> ./recon/qualifier.txt
find $directory -type f -name '*.php4' >> ./recon/qualifier.txt
find $directory -type f -name '*.php5' >> ./recon/qualifier.txt
find $directory -type f -name '*.phtml' >> ./recon/qualifier.txt
#find $directory -type f -name '*.php' >> ./recon/qualifier.txt
find $directory -type f -name '*.php3.*' >> ./recon/qualifier.txt
find $directory -type f -name '*.php4.*' >> ./recon/qualifier.txt
find $directory -type f -name '*.php5.*' >> ./recon/qualifier.txt
find $directory -type f -name '*.phtml.*' >> ./recon/qualifier.txt
find $directory -type f -name '*.phar.*' >> ./recon/qualifier.txt
find $directory -type f -name '*.php.*' >> ./recon/qualifier.txt
find $directory -type f -name '*.pl.*' >> ./recon/qualifier.txt
find $directory -type f -name '*.py.*' >> ./recon/qualifier.txt
find $directory -type f -name '*.cgi.*' >> ./recon/qualifier.txt
find $directory -type f -name '*.asp.*' >> ./recon/qualifier.txt
find $directory -type f -name '*.js.*' >> ./recon/qualifier.txt
find $directory -type f -name '*.html.*' >> ./recon/qualifier.txt
find $directory -type f -name '*.htm.*' >> ./recon/qualifier.txt
sleep 1

######################################################
#Common Shell Files extension
#

echo "[+] Finding common unique shell string inside file extensions..."
for shellfile in $(cat ./recon/qualifier.txt);do grep -rnwl $shellfile -e 'IndoXploit' >> ./recon/semifinal1.txt; done
for shellfile in $(cat ./recon/qualifier.txt);do grep -rnwl $shellfile -e 'b374k' >> ./recon/semifinal1.txt; done
for shellfile in $(cat ./recon/qualifier.txt);do grep -rnwl $shellfile -e 'c99' >> ./recon/semifinal1.txt;done
for shellfile in $(cat ./recon/qualifier.txt);do grep -rnwl $shellfile -e 'R57' >> ./recon/semifinal1.txt;done
for shellfile in $(cat ./recon/qualifier.txt);do grep -rnwl $shellfile -e 'shell' >> ./recon/semifinal1.txt;done
for shellfile in $(cat ./recon/qualifier.txt);do grep -rnwl $shellfile -e 'Shell' >> ./recon/semifinal1.txt;done
for shellfile in $(cat ./recon/qualifier.txt);do grep -rnwl $shellfile -e 'Sh3ll' >> ./recon/semifinal1.txt;done
for shellfile in $(cat ./recon/qualifier.txt);do grep -rnwl $shellfile -e 'bindport' >> ./recon/semifinal1.txt;done
for shellfile in $(cat ./recon/qualifier.txt);do grep -rnwl $shellfile -e 'exploit' >> ./recon/semifinal1.txt;done
for shellfile in $(cat ./recon/qualifier.txt);do grep -rnwl $shellfile -e 'sha1' >> ./recon/semifinal1.txt;done
for shellfile in $(cat ./recon/qualifier.txt);do grep -rnwl $shellfile -e 'chunk_split' >> ./recon/semifinal1.txt;done
for shellfile in $(cat ./recon/qualifier.txt);do grep -rnwl $shellfile -e 'back_connect' >> ./recon/semifinal1.txt;done
for shellfile in $(cat ./recon/qualifier.txt);do grep -rnwl $shellfile -e 'backdoor' >> ./recon/semifinal1.txt;done
for shellfile in $(cat ./recon/qualifier.txt);do grep -rnwl $shellfile -e 'file_uploads' >> ./recon/semifinal1.txt;done
for shellfile in $(cat ./recon/qualifier.txt);do grep -rnwl $shellfile -e 'netcat' >> ./recon/semifinal1.txt;done
for shellfile in $(cat ./recon/qualifier.txt);do grep -rnwl $shellfile -e '/etc/passwd' >> ./recon/semifinal1.txt;done
for shellfile in $(cat ./recon/qualifier.txt);do grep -rnwl $shellfile -e 'dbname' >> ./recon/semifinal1.txt;done
for shellfile in $(cat ./recon/qualifier.txt);do grep -rnwl $shellfile -e 'login_shell' >> ./recon/semifinal1.txt;done
for shellfile in $(cat ./recon/qualifier.txt);do grep -rnwl $shellfile -e '0x1999' >> ./recon/semifinal1.txt;done
for shellfile in $(cat ./recon/qualifier.txt);do grep -rnwl $shellfile -e 'multipart/form-data' >> ./recon/semifinal1.txt;done
for shellfile in $(cat ./recon/qualifier.txt);do grep -rnwl $shellfile -e 'base64_encode' >> ./recon/semifinal1.txt;done
for shellfile in $(cat ./recon/qualifier.txt);do grep -rnwl $shellfile -e 'base64_decode' >> ./recon/semifinal1.txt;done
for shellfile in $(cat ./recon/qualifier.txt);do grep -rnwl $shellfile -e 'eval' >> ./recon/semifinal1.txt;done
for shellfile in $(cat ./recon/qualifier.txt);do grep -rnwl $shellfile -e 'function' >> ./recon/semifinal1.txt;done
for shellfile in $(cat ./recon/qualifier.txt);do grep -rnwl $shellfile -e 'Obfuscation' >> ./recon/semifinal1.txt;done
for shellfile in $(cat ./recon/qualifier.txt);do grep -rnwl $shellfile -e 'proxy' >> ./recon/semifinal1.txt;done
for shellfile in $(cat ./recon/qualifier.txt);do grep -rnwl $shellfile -e 'getenv' >> ./recon/semifinal1.txt;done
for shellfile in $(cat ./recon/qualifier.txt);do grep -rnwl $shellfile -e 'exec' >> ./recon/semifinal1.txt;done
for shellfile in $(cat ./recon/qualifier.txt);do grep -rnwl $shellfile -e 'public_html' >> ./recon/semifinal1.txt;done
for shellfile in $(cat ./recon/qualifier.txt);do grep -rnwl $shellfile -e 'getcwd' >> ./recon/semifinal1.txt;done
for shellfile in $(cat ./recon/qualifier.txt);do grep -rnwl $shellfile -e 'md5_pass' >> ./recon/semifinal1.txt;done
for shellfile in $(cat ./recon/qualifier.txt);do grep -rnwl $shellfile -e 'download' >> ./recon/semifinal1.txt;done
for shellfile in $(cat ./recon/qualifier.txt);do grep -rnwl $shellfile -e 'Brute' >> ./recon/semifinal1.txt;done
for shellfile in $(cat ./recon/qualifier.txt);do grep -rnwl $shellfile -e 'Backdoor' >> ./recon/semifinal1.txt;done
for shellfile in $(cat ./recon/qualifier.txt);do grep -rnwl $shellfile -e 'Encoder' >> ./recon/semifinal1.txt;done
sleep 1

######################################################
#PHP Shell Files extension
#

echo "[+] Harvesting PHP file created & modified 30 days ago..."
find $directory -type f -name '*.php' -mtime -30 >> ./recon/quaterfinal.txt
sleep 1

echo "[+] Finding common unique shell string inside PHP files..."
for phpfile in $(cat ./recon/quaterfinal.txt);do grep -rnwl $phpfile -e 'IndoXploit' >> ./recon/semifinal.txt; done
for phpfile in $(cat ./recon/quaterfinal.txt);do grep -rnwl $phpfile -e 'b374k' >> ./recon/semifinal.txt; done
for phpfile in $(cat ./recon/quaterfinal.txt);do grep -rnwl $phpfile -e 'c99' >> ./recon/semifinal.txt;done
for phpfile in $(cat ./recon/quaterfinal.txt);do grep -rnwl $phpfile -e 'R57' >> ./recon/semifinal.txt;done
for phpfile in $(cat ./recon/quaterfinal.txt);do grep -rnwl $phpfile -e 'shell' >> ./recon/semifinal.txt;done
for phpfile in $(cat ./recon/quaterfinal.txt);do grep -rnwl $phpfile -e 'Shell' >> ./recon/semifinal.txt;done
for phpfile in $(cat ./recon/quaterfinal.txt);do grep -rnwl $phpfile -e 'Sh3ll' >> ./recon/semifinal.txt;done
for phpfile in $(cat ./recon/quaterfinal.txt);do grep -rnwl $phpfile -e 'bindport' >> ./recon/semifinal.txt;done
for phpfile in $(cat ./recon/quaterfinal.txt);do grep -rnwl $phpfile -e 'exploit' >> ./recon/semifinal.txt;done
for phpfile in $(cat ./recon/quaterfinal.txt);do grep -rnwl $phpfile -e 'sha1' >> ./recon/semifinal.txt;done
for phpfile in $(cat ./recon/quaterfinal.txt);do grep -rnwl $phpfile -e 'chunk_split' >> ./recon/semifinal.txt;done
for phpfile in $(cat ./recon/quaterfinal.txt);do grep -rnwl $phpfile -e 'back_connect' >> ./recon/semifinal.txt;done
for phpfile in $(cat ./recon/quaterfinal.txt);do grep -rnwl $phpfile -e 'backdoor' >> ./recon/semifinal.txt;done
for phpfile in $(cat ./recon/quaterfinal.txt);do grep -rnwl $phpfile -e 'file_uploads' >> ./recon/semifinal.txt;done
for phpfile in $(cat ./recon/quaterfinal.txt);do grep -rnwl $phpfile -e 'netcat' >> ./recon/semifinal.txt;done
for phpfile in $(cat ./recon/quaterfinal.txt);do grep -rnwl $phpfile -e '/etc/passwd' >> ./recon/semifinal.txt;done
for phpfile in $(cat ./recon/quaterfinal.txt);do grep -rnwl $phpfile -e 'dbname' >> ./recon/semifinal.txt;done
for phpfile in $(cat ./recon/quaterfinal.txt);do grep -rnwl $phpfile -e 'login_shell' >> ./recon/semifinal.txt;done
for phpfile in $(cat ./recon/quaterfinal.txt);do grep -rnwl $phpfile -e '0x1999' >> ./recon/semifinal.txt;done
for phpfile in $(cat ./recon/quaterfinal.txt);do grep -rnwl $phpfile -e 'multipart/form-data' >> ./recon/semifinal.txt;done
for phpfile in $(cat ./recon/quaterfinal.txt);do grep -rnwl $phpfile -e 'base64_encode' >> ./recon/semifinal.txt;done
for phpfile in $(cat ./recon/quaterfinal.txt);do grep -rnwl $phpfile -e 'base64_decode' >> ./recon/semifinal.txt;done
for phpfile in $(cat ./recon/quaterfinal.txt);do grep -rnwl $phpfile -e 'eval' >> ./recon/semifinal.txt;done
for phpfile in $(cat ./recon/quaterfinal.txt);do grep -rnwl $phpfile -e 'function' >> ./recon/semifinal.txt;done
for phpfile in $(cat ./recon/quaterfinal.txt);do grep -rnwl $phpfile -e 'Obfuscation' >> ./recon/semifinal.txt;done
for phpfile in $(cat ./recon/quaterfinal.txt);do grep -rnwl $phpfile -e 'proxy' >> ./recon/semifinal.txt;done
for phpfile in $(cat ./recon/quaterfinal.txt);do grep -rnwl $phpfile -e 'getenv' >> ./recon/semifinal.txt;done
for phpfile in $(cat ./recon/quaterfinal.txt);do grep -rnwl $phpfile -e 'exec' >> ./recon/semifinal.txt;done
for phpfile in $(cat ./recon/quaterfinal.txt);do grep -rnwl $phpfile -e 'public_html' >> ./recon/semifinal.txt;done
for phpfile in $(cat ./recon/quaterfinal.txt);do grep -rnwl $phpfile -e 'getcwd' >> ./recon/semifinal.txt;done
for phpfile in $(cat ./recon/quaterfinal.txt);do grep -rnwl $phpfile -e 'md5_pass' >> ./recon/semifinal.txt;done
for phpfile in $(cat ./recon/quaterfinal.txt);do grep -rnwl $phpfile -e 'download' >> ./recon/semifinal.txt;done
for phpfile in $(cat ./recon/quaterfinal.txt);do grep -rnwl $phpfile -e 'Brute' >> ./recon/semifinal.txt;done
for phpfile in $(cat ./recon/quaterfinal.txt);do grep -rnwl $phpfile -e 'Backdoor' >> ./recon/semifinal.txt;done
for phpfile in $(cat ./recon/quaterfinal.txt);do grep -rnwl $phpfile -e 'Encoder' >> ./recon/semifinal.txt;done
sleep 1

echo "[+] Harvesting done..."
sleep 1

######################################################
#Finalizing file list
#

echo "[+] Sorting and removing duplicates line..."
sort ./recon/semifinal1.txt | uniq > ./recon/prefinal.txt
sort ./recon/semifinal.txt | uniq >> ./recon/prefinal.txt
sleep 1


STRING="view.html.php"
for checkfile in $(cat ./recon/prefinal.txt);do 
	if [[ "$checkfile" != *"$STRING"* ]];then
		echo $checkfile >> ./recon/final.txt
	fi
done

echo "[+] Deleting temp files..."
rm -rf ./recon/qualifier.txt
rm -rf ./recon/quaterfinal.txt
rm -rf ./recon/semifinal.txt
rm -rf ./recon/semifinal1.txt
rm -rf ./recon/prefinal.txt
sleep 1

echo "[+] Suspected shell are in "$directory"recon/final.txt"
sleep 1

echo "[+] Listing the files for you..."
cat ./recon/final.txt
sleep 1

echo "[+] Done!"

exit
