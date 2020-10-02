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
sleep 1

######################################################
#PHP Shell Files extension
#

echo "[+] Harvesting PHP file created & modified 30days ago..."
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
sort ./recon/qualifier.txt | uniq > ./recon/final.txt
sort ./recon/semifinal.txt | uniq >> ./recon/final.txt
sleep 1

echo "[+] Deleting temp files..."
rm -rf ./recon/qualifier.txt
rm -rf ./recon/quaterfinal.txt
rm -rf ./recon/semifinal.txt
sleep 1

echo "[+] Suspected shell are in "$directory"recon/final.txt"
sleep 1

echo "[+] Listing the files for you..."
cat ./recon/final.txt
sleep 1

echo "[+] Done!"

exit
