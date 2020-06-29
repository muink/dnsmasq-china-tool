#!/bin/bash
# depend coreutils-cksum

# init
DCL='https://github.com/felixonmars/dnsmasq-china-list/archive/master.zip'
IPIP='https://github.com/17mon/china_ip_list/archive/master.zip'
CZIP='https://github.com/metowolf/iplist/archive/master.zip'
COIP='https://github.com/gaoyifan/china-operator-ip/archive/ip-lists.zip'
CNRU2='https://github.com/misakaio/chnroutes2/archive/master.zip'
AUVPN='https://github.com/zealic/autorosvpn/archive/master.zip'
CNDNS=223.5.5.5
LINEPERPART=200

MAINDOMAIN=accelerated-domains.china.conf
BROKENDOMAIN=broken-domains.txt
CDNLIST=cdn-testlist.txt
NSBLACK=ns-blacklist.txt
NSWHITE=ns-whitelist.txt
CNROUTE=cnrouteing.txt
PARTINDEX=.index
MAINLIST="$MAINDOMAIN $CDNLIST $NSBLACK $NSWHITE"

CURRENTDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRCDIR="$CURRENTDIR/Source"
CUSTOMDIR="$CURRENTDIR/Custom"
WORKDIR="$CURRENTDIR/Workshop"


# sub function

download_sources() {
mkdir "$SRCDIR" 2>/dev/null
mkdir "$CUSTOMDIR" 2>/dev/null
pushd "$SRCDIR" >/dev/null

# donwload dnsmasq-china-list/accelerated-domains.china.conf
curl -sSL -o data.zip "$DCL" && unzip -joq data.zip $(echo $MAINLIST|sed -n 's|^|*/|; s| | */|g; p')

#[ -f "$CUSTOMDIR/$CDNLIST" ] && (sort -m "$CDNLIST" "$CUSTOMDIR/$CDNLIST" | grep '[^[:space:]]' | sort -u -o "$CDNLIST")
[ -f "$CUSTOMDIR/$NSWHITE" ] && (sort -m "$NSWHITE" "$CUSTOMDIR/$NSWHITE" | grep '[^[:space:]]' | sort -u -o "$NSWHITE")
[ -f "$CUSTOMDIR/$NSBLACK" ] && (sort -m "$NSBLACK" "$CUSTOMDIR/$NSBLACK" | grep '[^[:space:]]' | sort -u -o "$NSBLACK")

# donaload CN CIDR
rm -f "$CNROUTE" 2>/dev/null
curl -sSL -o data.zip "$IPIP" && unzip -joq data.zip */china_ip_list.txt && mv "china_ip_list.txt" "$CNROUTE"
#curl -sSL -o data.zip "$CZIP" && unzip -joq data.zip */special/china.txt && mv "china.txt" "$CNROUTE"
#curl -sSL -o data.zip "$COIP" && unzip -joq data.zip */china.txt && mv "china.txt" "$CNROUTE"
#sort -t'.' -nk1,1 -rnk2,2 -rnk3,3 -rk4,4 "$CNROUTE" -o "$CNROUTE"

rm -f data.zip

popd >/dev/null
}

# update sources
update_sources() {
local srcdomain="$SRCDIR/$MAINDOMAIN"
local outdomain="$CURRENTDIR/$MAINDOMAIN"
local basedomain="$CURRENTDIR/$MAINDOMAIN.base"

mkdir "$CUSTOMDIR" 2>/dev/null
local patch="$CUSTOMDIR/$MAINDOMAIN"

if [ -e "$basedomain" ]; then
	diff -aZBN "$basedomain" "$srcdomain" | sed -n "/^< / {s|^< || p}" >> "$patch.del"
	diff -aZBN "$basedomain" "$srcdomain" | sed -n "/^> / {s|^> || p}" > "/tmp/$MAINDOMAIN.add"
	cut_srcdomain "/tmp/$MAINDOMAIN.add" # generate new conf part file
	cat "/tmp/$MAINDOMAIN.add" >> "$outdomain"
else
	cut_srcdomain "$srcdomain"
	cp -f "$srcdomain" "$outdomain"
fi

cp -f "$srcdomain" "$basedomain"
sort -u "$outdomain" -o "$outdomain"

}

# cut_srcdomain <becut>
cut_srcdomain() {
if   [ -z "$1" ]; then echo 'cut_srcdomain: The <becut> requires an argument'; return 1;
elif [ -f "$1" ]; then local srcdomain="$1";
else echo 'cut_srcdomain: The <becut> parameter is invalid'; return 1; fi

mkdir "$WORKDIR" 2>/dev/null
local domainlinepart="$WORKDIR/${MAINDOMAIN%.*}"

# Existing index count
local index="$WORKDIR/$PARTINDEX"
if [ -f "$index" ]; then local indexcount=$[ $(cat "$index") + 0 ];
else local indexcount=0; fi


local totalline=$[ $(sed -n "$=" "$srcdomain") + 0 ]
local lineperfile=$LINEPERPART
local filescount=$[ $totalline / $lineperfile ]
local remainder=$[ $totalline % $lineperfile ]

	for _count in $(seq $[ 1 + $indexcount ] $[ $filescount + $indexcount ]); do
		local basepoint=$[ $[ $_count - 1 ] * $lineperfile + 1 ]
		local endpoint=$[ $[ $_count - 1 ] * $lineperfile + $lineperfile ]
		sed -En "$basepoint,$endpoint s|^server=/(.+)/[0-9\.]+$|\1| p" "$srcdomain" > "${domainlinepart}.${_count}.conf"
	done
	if [ "$remainder" -gt "0" ]; then
		sed -En "$[ $[ $filescount + $indexcount ] * $lineperfile + 1 ],$ s|^server=/(.+)/[0-9\.]+$|\1| p" "$srcdomain" > "${domainlinepart}.$[ $filescount + $indexcount + 1 ].conf"
		let filescount+=1
	fi
	echo "$[ $filescount + $indexcount ]" > "$index"

}

# rand_num <min> <max> [<rounds>]
rand_num() {
if   [ -z "$3" -o "$[ $3 + 1 ]" -eq "1" ]; then local rounds=1;
elif [ "$3" -gt "$2" ]; then local rounds=$2;
else local rounds=$3; fi
local min=
local max=
local num=

(for _ in $(seq 1 $[ $rounds + $rounds / 2 ]); do
	min=$1
	max=$[ $2 - $min + 1 ]
	num=$(cat /dev/urandom | head -n 10 | cksum | cut -f1 -d' ')
	echo $[ $num % $max + $min ]
done) | sort -u | sed -n "1,$rounds p"

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

# find_in_cidr
# find_in_cidr <cidrrules> <ipaddress> <maskgroup>
find_in_cidr() {
#	local initvar=(rules ip)
#	for _var in "${initvar[@]}"; do
#		if [ -z "$1" ]; then echo "find_in_cidr: The <$_var> requires an argument"; return 1;
#		else eval "local \$_var=\"\$1\"" && shift; fi
#	done
#
#[ ! -f "$rules" ] && echo "find_in_cidr: The <cidrrules> parameter is invalid"; return 1
#[ ! "$(echo "$ip" | grep -E "^((2(5[0-5]|[0-4][0-9])|[0-1]?[0-9]{1,2})\.){3}(2(5[0-5]|[0-4][0-9])|[0-1]?[0-9]{1,2})$")" == "" ] && echo "find_in_cidr: The <ipaddress> parameter is invalid"; return 1
#local maskgp=("$@"); #[ "${#arr[@]}" -eq "0" ] && echo "find_in_cidr: The <maskgroup> requires an array argument"; return 1


ippart1=$(echo "$ip" | sed -En "s|^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)$|\1| p")
ippart2=$(echo "$ip" | sed -En "s|^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)$|\2| p")
ippart3=$(echo "$ip" | sed -En "s|^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)$|\3| p")
ippart4=$(echo "$ip" | sed -En "s|^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)$|\4| p")

	for _mask in "${maskgroup[@]}"; do
		fumask=$[ $_mask / 8 ]
		remask=$[ $_mask % 8 ]
		bitand="$[ (2**${remask}-1) << (8-${remask}) ]"

		case "$fumask" in
			0) grep -E "^$[ ${ippart1} & $bitand ]\..+/${_mask}\b" "$cnroute";;
			1) grep -E "^${ippart1}\.$[ ${ippart2} & $bitand ]\..+/${_mask}\b" "$cnroute";;
			2) grep -E "^${ippart1}\.${ippart2}\.$[ ${ippart3} & $bitand ]\..+/${_mask}\b" "$cnroute";;
			3) grep -E "^${ippart1}\.${ippart2}\.${ippart3}\.$[ ${ippart4} & $bitand ]/${_mask}\b" "$cnroute";;
			4) grep -E "^${ippart1}\.${ippart2}\.${ippart3}\.${ippart4}/${_mask}\b" "$cnroute";;
			#*) return 1;;
		esac
	done

}

# tldextract <url or rawdomain>
# echo "www.baidu.com" | tldextract | xargs
tldextract() {
local dns=$CNDNS
local retry=5

local domain
local line
local timeout=20
if   [ "$1" == "" ]; then
	while read -r -t$timeout line; do
		line="$(echo "$line" | sed -En "s|^(https?://)?([^/]+).*$|\2| p")"
		if [ ! "$line" == "" ]; then
			dig $line @$dns +trace +tries=$retry | grep -E "^.+\s[0-9]+\sIN\sNS\s.+$" | cut -f1 |
			grep -Ev "^\.$|^[a-zA-Z]+\.$" | sort -u | sed -n "s|\.$|| p" | rev | sort -t'.' -rk1,2 | sort -t'.' -uk1,2 | rev | tr 'A-Z' 'a-z' # >> Multiple values
		fi
	done
else
	domain="$(echo "$1" | sed -En "s|^(https?://)?([^/]+).*$|\2| p")"
	if [ "$(echo "$domain" | sed -n "s|[ \t0-9\.]||g p")" == "" ]; then echo 'check_white: The <domain> requires a valid argument'; return 1; fi
	dig $domain @$dns +trace +tries=$retry | grep -E "^.+\s[0-9]+\sIN\sNS\s.+$" | cut -f1 |
	grep -Ev "^\.$|^[a-zA-Z]+\.$" | sort -u | sed -n "s|\.$|| p" | rev | sort -t'.' -rk1,2 | sort -t'.' -uk1,2 | rev | tr 'A-Z' 'a-z' # >> Multiple values
	# sort reference: https://segmentfault.com/q/1010000000665713/a-1020000013574021
fi

# test_domain=(www.nc.jx.cn t.sina.com.cn yahoo.co.jp dsany.sgnic.sg tse1-mm.cn.bing.net www.henan.gov.cn.cdn30.com www.youngfunding.co.uk www.right.com.cn store.nintendo.co.jp store.steampowered.com www.taobao.com www.baidu.com www.bilibili.com blog.longwin.com.tw pvt.k12.ma.us)

}

# get_nsdomain <tld>
# echo "baidu.com" | get_nsdomain | xargs
get_nsdomain() {
local dns=$CNDNS
local retry=5

local tld
local line
local timeout=20
if   [ "$1" == "" ]; then
	while read -r -t$timeout line; do
		if [ ! "$(echo "$line" | sed -n "s|[ \t0-9\.]||g p")" == "" ]; then
			#echo "$line" | xargs dig @$dns -t ns +short #|
			#cut -f1 --complement -d'.' | sort -u | tr 'A-Z' 'a-z' # >> Multiple values
			dig $line @$dns +trace +tries=$retry | grep -E "^.+\s[0-9]+\sIN\sNS\s.+$" | grep -Ev "^\.\s|^[a-zA-Z]+\.\s" | awk '{print $5}' | sort -u | tr 'A-Z' 'a-z' # >> Multiple values
		fi
	done
else
	tld="$1"
	if [ "$(echo "$tld" | sed -n "s|[ \t0-9\.]||g p")" == "" ]; then echo 'check_white: The <tld> requires a valid argument'; return 1; fi
	#echo "$tld" | xargs dig @$dns -t ns +short #|
	#cut -f1 --complement -d'.' | sort -u | tr 'A-Z' 'a-z' # >> Multiple values
	dig $tld @$dns +trace +tries=$retry | grep -E "^.+\s[0-9]+\sIN\sNS\s.+$" | grep -Ev "^\.\s|^[a-zA-Z]+\.\s" | awk '{print $5}' | sort -u | tr 'A-Z' 'a-z' # >> Multiple values
fi

# test_tld=(nc.jx.cn weibo.com sina.com.cn yahoo.co.jp sgnic.sg bing.net cdn30.com youngfunding.co.uk right.com.cn nintendo.co.jp steampowered.com taobao.com a.shifen.com baidu.com bilibili.com longwin.com.tw k12.ma.us)

}

# check_cn_ip <ipaddress>
# check_cn_ip 223.5.5.5 || echo false
check_cn_ip() {
local cnroute="$SRCDIR/$CNROUTE"
local line
local ip
local timeout=20

eval "maskgroup=($(cat "$cnroute" | sed -En "s|^([0-9]+\.){3}[0-9]+/([0-9]+)$|\2| p" | sort -u))"
local fumask
local remask
local bitand

local ippart1
local ippart2
local ippart3
local ippart4

if   [ "$1" == "" ]; then
	while read -r -t$timeout line; do
		ip="$(echo "$line" | sed -En "s|^([0-9\.]+)|\1| p" | grep -E "^((2(5[0-5]|[0-4][0-9])|[0-1]?[0-9]{1,2})\.){3}(2(5[0-5]|[0-4][0-9])|[0-1]?[0-9]{1,2})$")"
		if [ ! "$ip" == "" ]; then
			find_in_cidr
		fi
	done
else
	ip="$1"
	if [ "$(echo "${ip[0]}" | grep -E "^((2(5[0-5]|[0-4][0-9])|[0-1]?[0-9]{1,2})\.){3}(2(5[0-5]|[0-4][0-9])|[0-1]?[0-9]{1,2})$")" == "" ]; then echo 'check_cn_ip: The <ipaddress> parameter is invalid'; return 1; fi
	find_in_cidr
fi

}

# check_nocn_domain <domain>
check_nocn_domain() {
local dns=$CNDNS

local domain
local line
local timeout=20
if   [ "$1" == "" ]; then
	while read -r -t$timeout line; do
		if [ ! "$(echo "$line" | sed -n "s|[ \t0-9\.]||g p")" == "" ]; then
			[ "$(dig $line @$dns +short | grep -E "^[0-9\.]+" | check_cn_ip)" == "" ] && echo $line # > $(date +%Y-%m-%d_%T)
		fi
	done
else
	domain="$1"
	if [ "$(echo "$domain" | sed -n "s|[ \t0-9\.]||g p")" == "" ]; then echo 'check_nocn_domain: The <domain> requires a valid argument'; return 1; fi
	[ "$(dig $domain @$dns +short | grep -E "^[0-9\.]+" | check_cn_ip)" == "" ] && echo $domain # > $(date +%Y-%m-%d_%T)
fi

}

# check_cdn <tld>
check_cdn(){
local cdnlist="$SRCDIR/$CDNLIST"

local domain
local line
local timeout=20
if   [ "$1" == "" ]; then
	while read -r -t$timeout line; do
		if [ ! "$(echo "$line" | sed -n "s|[ \t0-9\.]||g p")" == "" ]; then
			[ ! "$(grep -E "\b${line}$" "$cdnlist")" == "" ] && echo "$line"
		fi
	done
else
	domain="$1"
	if [ "$(echo "$domain" | sed -n "s|[ \t0-9\.]||g p")" == "" ]; then echo 'check_cdn: The <domain> requires a valid argument'; return 1; fi
	[ ! "$(grep -E "\b${domain}$" "$cdnlist")" == "" ] && echo "$domain"
fi

}

# check_white <nsdomain>
check_white() {
local whitelist="$SRCDIR/$NSWHITE"

local nsdomain
local line
local timeout=20
if   [ "$1" == "" ]; then
	while read -r -t$timeout line; do
		if [ ! "$(echo "$line" | sed -n "s|[ \t0-9\.]||g p")" == "" ]; then
			echo "$line" | grep -f "$whitelist"
		fi
	done
else
	nsdomain="$1"
	if [ "$(echo "$nsdomain" | sed -n "s|[ \t0-9\.]||g p")" == "" ]; then echo 'check_white: The <nsdomain> requires a valid argument'; return 1; fi
	echo "$nsdomain" | grep -f "$whitelist"
fi

}

# check_black <nsdomain>
check_black() {
local blacklist="$SRCDIR/$NSBLACK"

local nsdomain
local line
local timeout=20
if   [ "$1" == "" ]; then
	while read -r -t$timeout line; do
		if [ ! "$(echo "$line" | sed -n "s|[ \t0-9\.]||g p")" == "" ]; then
			echo "$line" | grep -f "$blacklist"
		fi
	done
else
	nsdomain="$1"
	if [ "$(echo "$nsdomain" | sed -n "s|[ \t0-9\.]||g p")" == "" ]; then echo 'check_black: The <nsdomain> requires a valid argument'; return 1; fi
	echo "$nsdomain" | grep -f "$blacklist"
fi

}

