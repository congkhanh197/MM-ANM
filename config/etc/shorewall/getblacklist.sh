#!/bin/bash


#
# Shorewall blacklist file
# blacklist file
#
BLACKLIST="/etc/shorewall/blrules"

#
# get URL
# 

URL[0]="http://feeds.dshield.org/block.txt"
URL[1]="http://www.spamhaus.org/drop/drop.lasso"

# 
# Don't Edit After this line
#

# Temporary dump staging folder
  TMP=$(mktemp -d -t tmp.XXXXXXXXXX)
#
# @method to delete Temporary folder
#
function finish {
  rm -rf "$TMP"
}
trap finish EXIT

#cat $BLACKLIST > "$TMP/blacklist"
cat /dev/null > $BLACKLIST

echo "#AUTO LIST" >> "$TMP/blacklist"
echo "#ACTION		SOURCE				DEST		PROTO		DPORT" >> "$TMP/blacklist"
## top 20 attacking class C (/24)
wget -q -O - ${URL[0]} | sed '1,/Start/d' | sed '/#/d' | awk '{printf "DROP\t\tnet:%s/%s\t\tall\n",$1,$3}' | sed 's/ /\//' >> "$TMP/blacklist"

##  Spamhaus DROP List
wget -q -O - ${URL[1]} | sed '1,/Expires/d' | awk '{{printf "DROP\t\tnet:%s\t\tall\n",$1}}'  >> "$TMP/blacklist"

#sed -e 's/^/DROP\t\tall\t\tnet:/' "$TMP/blacklist" >> $BLACKLIST

echo "#LAST LINE -- ADD YOUR ENTRIES BEFORE THIS ONE -- DO NOT REMOVE" >> "$TMP/blacklist"
cat "$TMP/blacklist" > $BLACKLIST
shorewall refresh &>/dev/null
