#!/bin/bash
# depend coreutils-cksum

# init
DCL='https://github.com/felixonmars/dnsmasq-china-list/archive/master.zip'
IPIP='https://github.com/17mon/china_ip_list/archive/master.zip'
COIP='https://github.com/gaoyifan/china-operator-ip/archive/ip-lists.zip'
IPLIS='https://github.com/metowolf/iplist/archive/master.zip'
AUVPN='https://github.com/zealic/autorosvpn/archive/master.zip'
CNRU2='https://github.com/misakaio/chnroutes2/archive/master.zip'
CNDNS=223.5.5.5
LINEPERPART=200

MAINDOMAIN=accelerated-domains.china.conf
BROKENDOMAIN=broken-domains.txt
CDNLIST=cdn-testlist.txt
NSBLACK=ns-blacklist.txt
NSWHITE=ns-whitelist.txt
CNROUTE=chnroutes.txt
PARTINDEX=.index
MAINLIST="$MAINDOMAIN $CDNLIST $NSBLACK $NSWHITE"

CURRENTDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRCDIR="$CURRENTDIR/Source"
CUSTOMDIR="$CURRENTDIR/Custom"
WORKDIR="$CURRENTDIR/Workshop"


# sub function

download_sources() {
mkdir "$SRCDIR" 2>/dev/null
local cnroute="$SRCDIR/$CNROUTE"

# donwload dnsmasq-china-list/accelerated-domains.china.conf
curl -sSL -o data.zip "$DCL" && unzip -joq data.zip $(echo $MAINLIST|sed -n 's|^|*/|; s| | */|g; p') -d "$SRCDIR"

# donaload CN/HK CIDR
#curl -sSL -o data.zip "$IPIP" && unzip -joq data.zip */china_ip_list.txt && mv china_ip_list.txt "$cnroute"
#curl -sSL -o data.zip "$COIP" 
#curl -sSL -o data.zip "$IPLIS" 
#curl -sSL -o data.zip "$AUVPN" 
curl -sSL -o data.zip "$CNRU2" && unzip -joq data.zip */chnroutes.txt -d "$SRCDIR"

rm -f data.zip

}

