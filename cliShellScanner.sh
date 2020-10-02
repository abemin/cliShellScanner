#!/bin/bash

directory=$1

if [ -z "$1" ]
  then
    echo "Usage: ./cliShellScanner.ah <root website directory>"
	echo "Example Usage: ./cliShellScanner.ah /var/www/html/"
	exit
fi

######################################################
#Directory 
#

if [ ! -d "recon" ];then
	  rm -rf recon
      mkdir recon
fi

######################################################
#Shell Files 
#

echo "[+] Harvesting shell files using common shell file extension..."
find $directory -type f -name '*.php3' >> ./recon/qualifier.txt
find $directory -type f -name '*.php4' >> ./recon/qualifier.txt
find $directory -type f -name '*.php5' >> ./recon/qualifier.txt
find $directory -type f -name '*.phtml' >> ./recon/qualifier.txt
sleep 1

echo "[+] Harvesting shell files using PHP file extension..."
find $directory -type f -name '*.php' >> ./recon/quaterfinal.txt

echo "[+] Finding common unique shell string inside PHP files..."
for phpfile in $(cat ./recon/quaterfinal.txt);do grep -rnwl $phpfile -e 'b374k' >> ./recon/semifinal.txt; done
for phpfile in $(cat ./recon/quaterfinal.txt);do grep -rnwl $phpfile -e 'c99' >> ./recon/semifinal.txt;done
for phpfile in $(cat ./recon/quaterfinal.txt);do grep -rnwl $phpfile -e 'R57' >> ./recon/semifinal.txt;done
for phpfile in $(cat ./recon/quaterfinal.txt);do grep -rnwl $phpfile -e 'shell' >> ./recon/semifinal.txt;done
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

echo "[+] Harvesting done..."
sleep 1

echo "[+] Sorting and removing duplicates line..."
sort ./recon/qualifier.txt | uniq > ./recon/final.txt
sort ./recon/semifinal.txt | uniq >> ./recon/final.txt

echo "[+] Suspected shell are in "$directory"recon/final.txt"
exit
