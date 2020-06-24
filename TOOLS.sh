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

# rev <string>
rev() {
local string
local line
local timeout=20
if   [ "$1" == "" ]; then
	while read -r -t$timeout line; do
		echo "$line" | sed -E '/\n/!G; s|(.)(.*\n)|&\2\1|; //D; s|.||'
	done
else
	string="$1"
	echo "$string" | sed -E '/\n/!G; s|(.)(.*\n)|&\2\1|; //D; s|.||'
fi

}

# check_cn_cidr <ipaddress>
# check_cn_cidr 223.5.5.5 || echo false
check_cn_cidr() {
local ip
local line
local timeout=20
if   [ "$1" == "" ]; then
	local count=0
	while read -r -t$timeout line; do
		line="$(echo "$line" | sed -En "s|^([0-9\.]+)|\1| p" | grep -E "^((2(5[0-5]|[0-4][0-9])|[0-1]?[0-9]{1,2})\.){3}(2(5[0-5]|[0-4][0-9])|[0-1]?[0-9]{1,2})$")"
		if [ ! "$line" == "" ]; then
			ip[$count]="$line"
			((count++))
		fi
	done
else
	ip=("$1")
	if [ "$(echo "${ip[0]}" | grep -E "^((2(5[0-5]|[0-4][0-9])|[0-1]?[0-9]{1,2})\.){3}(2(5[0-5]|[0-4][0-9])|[0-1]?[0-9]{1,2})$")" == "" ]; then echo 'check_cn_cidr: The <ipaddress> parameter is invalid'; return 1; fi
fi

local cnroute="$SRCDIR/$CNROUTE"
eval "MASKGROUP=($(cat "$cnroute" | sed -En "s|^([0-9]+\.){3}[0-9]+/([0-9]+)$|\2| p" | sort | uniq))"
local fumask
local remask
local bitand

local ippart1
local ippart2
local ippart3
local ippart4

#echo "${#ip[@]}"
for _ip in "${ip[@]}"; do

ippart1=$(echo "$_ip" | sed -En "s|^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)$|\1| p")
ippart2=$(echo "$_ip" | sed -En "s|^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)$|\2| p")
ippart3=$(echo "$_ip" | sed -En "s|^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)$|\3| p")
ippart4=$(echo "$_ip" | sed -En "s|^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)$|\4| p")

	for _mask in "${MASKGROUP[@]}"; do
		fumask=$[ $_mask / 8 ]
		remask=$[ $_mask % 8 ]
		bitand="$[ (2**${remask}-1) << (8-${remask}) ]"

		case "$fumask" in
			0) grep -E "^$[ ${ippart1} & $bitand ]\..+/${_mask}$" "$cnroute";;
			1) grep -E "^${ippart1}\.$[ ${ippart2} & $bitand ]\..+/${_mask}$" "$cnroute";;
			2) grep -E "^${ippart1}\.${ippart2}\.$[ ${ippart3} & $bitand ]\..+/${_mask}$" "$cnroute";;
			3) grep -E "^${ippart1}\.${ippart2}\.${ippart3}\.$[ ${ippart4} & $bitand ]/${_mask}$" "$cnroute";;
			#*) return 1;;
		esac
	done
done
}

# tldextract <url or rawdomain>
tldextract() {
local dns=$CNDNS

local domain
local line
local timeout=20
if   [ "$1" == "" ]; then
	while read -r -t$timeout line; do
		line="$(echo "$line" | sed -En "s|^(https?://)?([^/]+).*$|\2| p")"
		if [ ! "$line" == "" ]; then
			dig $line @$dns +trace | grep -E "^.+\s[0-9]+\sIN\sNS\s.+$" | cut -f1 |
			grep -Ev "^\.$|^[a-zA-Z]+\.$" | sort -u | sed -n "s|\.$|| p" | rev | sort -t'.' -rk1,2 | sort -t'.' -uk1,2 | rev # >> Multiple values
		fi
	done
else
	domain="$(echo "$1" | sed -En "s|^(https?://)?([^/]+).*$|\2| p")"
	if [ "$(echo "$domain" | sed -n "s|[ \t0-9\.]||g p")" == "" ]; then echo 'check_white: The <domain> requires a valid argument'; return 1; fi
	dig $domain @$dns +trace | grep -E "^.+\s[0-9]+\sIN\sNS\s.+$" | cut -f1 |
	grep -Ev "^\.$|^[a-zA-Z]+\.$" | sort -u | sed -n "s|\.$|| p" | rev | sort -t'.' -rk1,2 | sort -t'.' -uk1,2 | rev # >> Multiple values
	# sort reference: https://segmentfault.com/q/1010000000665713/a-1020000013574021
fi

# test_domain=(www.nc.jx.cn t.sina.com.cn yahoo.co.jp dsany.sgnic.sg tse1-mm.cn.bing.net www.henan.gov.cn.cdn30.com www.youngfunding.co.uk www.right.com.cn store.nintendo.co.jp store.steampowered.com www.taobao.com www.baidu.com www.bilibili.com blog.longwin.com.tw pvt.k12.ma.us)

}

# check_cdn <domain>
check_cdn(){
local cdnlist="$SRCDIR/$CDNLIST"

local domain
local line
local timeout=20
if   [ "$1" == "" ]; then
	while read -r -t$timeout line; do
		if [ ! "$(echo "$line" | sed -n "s|[ \t0-9\.]||g p")" == "" ]; then
			grep -E "\b${line}$" "$cdnlist"
		fi
	done
else
	domain="$1"
	if [ "$(echo "$domain" | sed -n "s|[ \t0-9\.]||g p")" == "" ]; then echo 'check_cdn: The <domain> requires a valid argument'; return 1; fi
	grep -E "\b${domain}$" "$cdnlist"
fi

}

