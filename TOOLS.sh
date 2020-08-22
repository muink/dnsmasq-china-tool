#!/bin/bash
# dependent: bash curl unzip coreutils-cksum bind-dig diffutils coreutils-stat

# init
DCL='https://github.com/felixonmars/dnsmasq-china-list/archive/master.zip'
IPIP='https://github.com/17mon/china_ip_list/archive/master.zip'
CZIP='https://github.com/metowolf/iplist/raw/master/data/special/china.txt'
CZIPHK='https://github.com/metowolf/iplist/raw/master/data/country/HK.txt'
COIP='https://github.com/gaoyifan/china-operator-ip/archive/ip-lists.zip'
CNRU2='https://github.com/misakaio/chnroutes2/archive/master.zip'
AUVPN='https://github.com/zealic/autorosvpn/archive/master.zip'
CNDNS=223.5.5.5
LINEPERPART=200
#DIGTCP=+tcp

MAINDOMAIN=accelerated-domains.china.conf
INVALIDREVERIFY=invalid-reverify.txt
POISONORINVALID=poison-or-invalid.txt
UNVERIFIEDDOMAIN=unverified-domain.txt
UNVERIFIEDNS=unverified-ns.txt
CDNLIST=cdn-testlist.txt
NSBLACK=ns-blacklist.txt
NSWHITE=ns-whitelist.txt
DOMAINBLACK=domain-blacklist.txt
DOMAINWHITE=domain-whitelist.txt
CNROUTE=cnrouting.txt
PARTINDEX=.index
MAINLIST="$MAINDOMAIN $CDNLIST $NSBLACK $NSWHITE"

TMPDIR="/tmp/DNSCNIAT"
CURRENTDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
#CURRENTDIR="/etc/dnsmasq-china-tool"
SRCDIR="$CURRENTDIR/Source"
CUSTOMDIR="$CURRENTDIR/Custom"
WORKDIR="$CURRENTDIR/Workshop"

_FUNCTION="$1"; shift
# _PARAMETERS: "$@"


# sub function

download_sources() {
mkdir "$SRCDIR" 2>/dev/null
mkdir "$CUSTOMDIR" 2>/dev/null
mkdir "$TMPDIR" 2>/dev/null
pushd "$SRCDIR" >/dev/null

# donwload dnsmasq-china-list/accelerated-domains.china.conf
curl -sSL -o data.zip "$DCL" && unzip -joq data.zip -d "$TMPDIR/"
mv -f $(echo $MAINLIST|sed -n "s|^|$TMPDIR/|; s| | $TMPDIR/|g; p") $SRCDIR/
update_rules

# donaload CN CIDR
rm -f "$CNROUTE" 2>/dev/null
curl -sSL -o data.zip "$IPIP" && unzip -joq data.zip -d "$TMPDIR/" && mv -f "$TMPDIR/china_ip_list.txt" "$CNROUTE" && echo >> "$CNROUTE"
curl -sSL -o "china.txt" "$CZIP" && cat "china.txt" >> "$CNROUTE" && echo >> "$CNROUTE"
#curl -sSL -o data.zip "$COIP" && unzip -joq data.zip -d "$TMPDIR/" && mv -f "$TMPDIR/china.txt" "$CNROUTE"
#sort -t'.' -nk1,1 -rnk2,2 -rnk3,3 -rk4,4 "$CNROUTE" -o "$CNROUTE"
curl -sSL -o "HK.txt" "$CZIPHK" && cat "HK.txt" >> "$CNROUTE" && echo >> "$CNROUTE"

rm -rf "$TMPDIR"
rm -f data.zip
rm -f china.txt
rm -f HK.txt
grep '[^[:space:]]' "$CNROUTE" | grep -v '#' | sort -uo "$CNROUTE"
sort -n -t'.' -k1,1 -k2,2 -k3,3 -k4,4 "$CNROUTE" -o "$CNROUTE"

popd >/dev/null
}

# update rules
update_rules() {
echo >> "$SRCDIR/$NSWHITE"
echo >> "$SRCDIR/$NSBLACK"
[ -f "$CUSTOMDIR/$NSWHITE" ] && sort -m "$SRCDIR/$NSWHITE" "$CUSTOMDIR/$NSWHITE" | grep -v '#' | sort -u -o "$SRCDIR/$NSWHITE"
[ -f "$CUSTOMDIR/$NSBLACK" ] && sort -m "$SRCDIR/$NSBLACK" "$CUSTOMDIR/$NSBLACK" | grep -Ev '#|status: NXDOMAIN' | sort -u -o "$SRCDIR/$NSBLACK"
cat "$SRCDIR/$NSWHITE" | grep '[^[:space:]]' | grep -v '#' | sed -E "s|^\.|\\\.|; s|([^\\])\.|\1\\\.|g" | sort -u -o "$SRCDIR/$NSWHITE"
cat "$SRCDIR/$NSBLACK" | grep '[^[:space:]]' | grep -v '#' | sed -E "s|^\.|\\\.|; s|([^\\])\.|\1\\\.|g" | sort -u -o "$SRCDIR/$NSBLACK"

}

# update sources
update_sources() {
local srcdomain="$SRCDIR/$MAINDOMAIN"
local outdomain="$CURRENTDIR/$MAINDOMAIN"
local basedomain="$CURRENTDIR/$MAINDOMAIN.base"
local basedate="$CURRENTDIR/.basedate"

local srcdate="$(stat -c '%y' "$srcdomain" | cut -f1 -d' ')"

mkdir "$CUSTOMDIR" 2>/dev/null
local patch="$CUSTOMDIR/$MAINDOMAIN"

if [ -e "$basedomain" ]; then
	diff -aBN "$basedomain" "$srcdomain" | sed -n "/^> / {s|^> || p}" > "/tmp/$MAINDOMAIN.add"
	diff -aBN "$basedomain" "$srcdomain" | sed -n "/^< / {s|^< || p}" | grep -vf "/tmp/$MAINDOMAIN.add" | sed "s|^server=/||; s|/[0-9\.]\+.*$||" >> "$patch.del"
	cut_srcdomain "/tmp/$MAINDOMAIN.add" # generate new conf part file
	cat "/tmp/$MAINDOMAIN.add" >> "$outdomain"
else
	cut_srcdomain "$srcdomain"
	cp -f "$srcdomain" "$outdomain"
fi

cat "$outdomain" | grep '[^[:space:]]' | grep -v '#' | sort -u -o "$outdomain"
cp -f "$srcdomain" "$basedomain"
echo "$srcdate" > "$basedate"

}

# cut_srcdomain <becut>
cut_srcdomain() {
if   [ -z "$1" ]; then >&2 echo 'cut_srcdomain: The <becut> requires an argument'; return 1;
elif [ -f "$1" ]; then local srcdomain="$1";
else >&2 echo 'cut_srcdomain: The <becut> parameter is invalid'; return 1; fi

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
		sed -En "$basepoint,$endpoint s|^server=/(.+)/[0-9\.]+.*$|\1| p" "$srcdomain" > "${domainlinepart}.${_count}.conf"
	done
	if [ "$remainder" -gt "0" ]; then
		sed -En "$[ $filescount * $lineperfile + 1 ],$ s|^server=/(.+)/[0-9\.]+.*$|\1| p" "$srcdomain" > "${domainlinepart}.$[ $filescount + $indexcount + 1 ].conf"
		let filescount+=1
	fi
	echo "$[ $filescount + $indexcount ]" > "$index"

}

# rand_num <min> <max> [<rounds>]
rand_num() {
if   [ -z "$3" -o "$[ $3 + 1 ]" -eq "1" ]; then local rounds=1;
elif [ "$3" -gt "$[ $2 - $1 ]" ]; then seq "$1" "$2"; return 0;
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
#		if [ -z "$1" ]; then >&2 echo "find_in_cidr: The <$_var> requires an argument"; return 1;
#		else eval "local \$_var=\"\$1\"" && shift; fi
#	done
#
#[ ! -f "$rules" ] && >&2 echo "find_in_cidr: The <cidrrules> parameter is invalid"; return 1
#[ ! "$(echo "$ip" | grep -E "^((2(5[0-5]|[0-4][0-9])|[0-1]?[0-9]{1,2})\.){3}(2(5[0-5]|[0-4][0-9])|[0-1]?[0-9]{1,2})$")" == "" ] && >&2 echo "find_in_cidr: The <ipaddress> parameter is invalid"; return 1
#local maskgp=("$@"); #[ "${#arr[@]}" -eq "0" ] && >&2 echo "find_in_cidr: The <maskgroup> requires an array argument"; return 1


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
local timout=1
local tries=1
local retry=2

local domain
local line
local timeout=20
if   [ "$1" == "" ]; then
	while read -r -t$timeout line; do
		line="$(echo "$line" | sed -En "s|^(https?://)?([^/]+).*$|\2| p")"
		if [ ! "$line" == "" ]; then
			dig $line @$dns +trace +timeout=$timout +tries=$tries +retry=$retry $DIGTCP 2>/dev/null | grep -E "^.+\s[0-9]+\sIN\sNS\s.+$" | cut -f1 |
			grep -Ev "^\.$|^[a-zA-Z]+\.$" | sort -u | sed -n "s|\.$|| p" | rev | sort -t'.' -rk1,2 | sort -t'.' -uk1,2 | rev | tr 'A-Z' 'a-z' # >> Multiple values
		fi
	done
else
	domain="$(echo "$1" | sed -En "s|^(https?://)?([^/]+).*$|\2| p")"
	if [ "$(echo "$domain" | sed -n "s|[ \t0-9\.]||g p")" == "" ]; then >&2 echo 'check_white: The <domain> requires a valid argument'; return 1; fi
	dig $domain @$dns +trace +timeout=$timout +tries=$tries +retry=$retry $DIGTCP 2>/dev/null | grep -E "^.+\s[0-9]+\sIN\sNS\s.+$" | cut -f1 |
	grep -Ev "^\.$|^[a-zA-Z]+\.$" | sort -u | sed -n "s|\.$|| p" | rev | sort -t'.' -rk1,2 | sort -t'.' -uk1,2 | rev | tr 'A-Z' 'a-z' # >> Multiple values
	# sort reference: https://segmentfault.com/q/1010000000665713/a-1020000013574021
fi

# test_domain=(www.nc.jx.cn t.sina.com.cn yahoo.co.jp dsany.sgnic.sg tse1-mm.cn.bing.net www.henan.gov.cn.cdn30.com www.youngfunding.co.uk www.right.com.cn store.nintendo.co.jp store.steampowered.com www.taobao.com www.baidu.com www.bilibili.com blog.longwin.com.tw pvt.k12.ma.us)

}

# get_nsdomain <tld>
# echo "baidu.com" | get_nsdomain | xargs
get_nsdomain() {
local dns=$CNDNS
local timout=1
local tries=1
local retry=2

local tld
local line
local timeout=20
if   [ "$1" == "" ]; then
	while read -r -t$timeout line; do
		if [ ! "$(echo "$line" | sed -n "s|[ \t0-9\.]||g p")" == "" ]; then
			#echo "$line" | xargs dig @$dns -t ns +short $DIGTCP #|
			#cut -f1 --complement -d'.' | sort -u | tr 'A-Z' 'a-z' # >> Multiple values
			dig $line @$dns +trace +timeout=$timout +tries=$tries +retry=$retry $DIGTCP 2>/dev/null | grep -E "^.+\s[0-9]+\sIN\sNS\s.+$" | grep -E "^$line" | awk '{print $5}' | sort -u | tr 'A-Z' 'a-z' # >> Multiple values
		fi
	done
else
	tld="$1"
	if [ "$(echo "$tld" | sed -n "s|[ \t0-9\.]||g p")" == "" ]; then >&2 echo 'check_white: The <tld> requires a valid argument'; return 1; fi
	#echo "$tld" | xargs dig @$dns -t ns +short $DIGTCP #|
	#cut -f1 --complement -d'.' | sort -u | tr 'A-Z' 'a-z' # >> Multiple values
	dig $tld @$dns +trace +timeout=$timout +tries=$tries +retry=$retry $DIGTCP 2>/dev/null | grep -E "^.+\s[0-9]+\sIN\sNS\s.+$" | grep -E "^$tld" | awk '{print $5}' | sort -u | tr 'A-Z' 'a-z' # >> Multiple values
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
	if [ "$(echo "${ip[0]}" | grep -E "^((2(5[0-5]|[0-4][0-9])|[0-1]?[0-9]{1,2})\.){3}(2(5[0-5]|[0-4][0-9])|[0-1]?[0-9]{1,2})$")" == "" ]; then >&2 echo 'check_cn_ip: The <ipaddress> parameter is invalid'; return 1; fi
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
			[ "$(dig $line @$dns +short $DIGTCP | grep -E "^[0-9\.]+" | check_cn_ip)" == "" ] && echo $line # > $(date +%Y-%m-%d_%T)
		fi
	done
else
	domain="$1"
	if [ "$(echo "$domain" | sed -n "s|[ \t0-9\.]||g p")" == "" ]; then >&2 echo 'check_nocn_domain: The <domain> requires a valid argument'; return 1; fi
	[ "$(dig $domain @$dns +short $DIGTCP | grep -E "^[0-9\.]+" | check_cn_ip)" == "" ] && echo $domain # > $(date +%Y-%m-%d_%T)
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
	if [ "$(echo "$domain" | sed -n "s|[ \t0-9\.]||g p")" == "" ]; then >&2 echo 'check_cdn: The <domain> requires a valid argument'; return 1; fi
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
	if [ "$(echo "$nsdomain" | sed -n "s|[ \t0-9\.]||g p")" == "" ]; then >&2 echo 'check_white: The <nsdomain> requires a valid argument'; return 1; fi
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
	if [ "$(echo "$nsdomain" | sed -n "s|[ \t0-9\.]||g p")" == "" ]; then >&2 echo 'check_black: The <nsdomain> requires a valid argument'; return 1; fi
	echo "$nsdomain" | grep -f "$blacklist"
fi

}

# verify_domain [<rounds>]
verify_domain() {
[ -z "$1" -o "$[ $1 + 1 ]" -eq "1" ] && local rounds=1 || local rounds=$1

# Workshop
local workidir="$WORKDIR"
local index="$WORKDIR/$PARTINDEX"
local domainlinepart="$WORKDIR/${MAINDOMAIN%.*}"
local partcount=$[ $(ls -1 "$workidir/" | grep -E "\.conf$" | sed -n '$=') + 0 ]

# Custom
local patch="$CUSTOMDIR/$MAINDOMAIN"
local poisonorinvalid="$CUSTOMDIR/$POISONORINVALID"
local invalidreverify="$CUSTOMDIR/$INVALIDREVERIFY"
local unverifiedns="$CUSTOMDIR/$UNVERIFIEDNS"
local unverifieddomain="$CUSTOMDIR/$UNVERIFIEDDOMAIN"

local domainblk="$CUSTOMDIR/$DOMAINBLACK"
local domainwit="$CUSTOMDIR/$DOMAINWHITE"


update_rules
echo "$[ $(ls -1 "$workidir/" | sed -En "s|^.+\.([0-9]+)\.conf$|\1| p" | sort -rn | sed -n '1p') + 0 ]" > "$index" # update .index count

if [ "$partcount" -gt "0" ]; then
	local whichone=$(rand_num 1 $partcount $rounds | xargs | sed 's|^|^|; s/ /:|^/g; s|$|:|')
	local pickdindex=$(ls -1 "$workidir/" | grep -E "\.conf$" | grep -n "" | grep -E "$whichone" | sed -En "s|^.+\.([0-9]+)\.conf$|\1| p" | xargs)
	local count=1

	local tld
	local nslist

	for _i in $pickdindex; do
		echo "rounds: $count/$rounds  index: $_i"  lines: $[ $(sed -n '$=' "${domainlinepart}.${_i}.conf") + 0 ]

		for _l in $(seq 1 $[ $(sed -n '$=' "${domainlinepart}.${_i}.conf") + 0 ]); do
			tld="$(sed -n "$_l p" "${domainlinepart}.${_i}.conf")"
			#echo $_l: $tld
			[ "$[ $_l % 10 ]" -eq "0" ] && echo -n "${_l}.. "
			echo "$tld" | grep -E "\.?cn\.?$|\.top\.?$" >/dev/null && continue
			check_cdn "$tld" >/dev/null && continue
			echo "$tld" | grep -Ef "$poisonorinvalid" >/dev/null && echo "$tld" >> "$patch.del" && continue

			if [ "$(echo "$tld" | grep -E "^[^\.]+(\.[^\.]+){2,}$")" ]; then
			#DOMAIN
				echo "$tld" | grep -Ef "$domainwit" >/dev/null && continue
				echo "$tld" | grep -Ef "$domainblk" >/dev/null && echo "$tld" >> "$patch.del" && continue
				[ "$(tldextract "$tld" | grep "$tld")" == "" ] && echo "$tld" >> "$unverifieddomain" && continue #verify domain or sld
			fi
			#NS
			nslist="$(get_nsdomain "$tld" | xargs)"
				[ "$nslist" == "" ] && echo "$tld" >> "$invalidreverify" && continue
				check_white "$nslist" >/dev/null && continue
				check_black "$nslist" >/dev/null && echo "$tld" >> "$patch.del" && continue
			echo "${tld}:${nslist}" >> "$unverifiedns"
		done

		rm -f "${domainlinepart}.${_i}.conf"
		((count++))
	done
fi

}

# commit_changes
commit_changes() {
local patch="$CUSTOMDIR/$MAINDOMAIN"
local outdomain="$CURRENTDIR/$MAINDOMAIN"

local delline="$[ $(sed -n '$=' "$patch.del" 2>/dev/null) + 0 ]"

if [ "$delline" -gt "0" ]; then
	sed -E "s|^([^#])|/\1|; s|([^0-9])$|\1/|; s|([^\\])\.|\1\\\.|g" "$patch.del" > "/tmp/$MAINDOMAIN.del"
	grep -vf "/tmp/$MAINDOMAIN.del" "$outdomain" | grep '[^[:space:]]' | grep -v '#' | sort -u -o "$outdomain"
	rm -f "$patch.del"
fi

cat "$patch" >> "$outdomain"

}

# show_status
show_status() {
local srcdomain="$SRCDIR/$MAINDOMAIN"
local basedate="$CURRENTDIR/.basedate"
local patch="$CUSTOMDIR/$MAINDOMAIN"
[ -d "$WORKDIR" ] || mkdir "$WORKDIR"

local srcdate="$(stat -c '%y' "$srcdomain" | cut -f1 -d' ')"
local basedate="$(cat "$basedate")"
local confcount="$[ $(ls -1 "$WORKDIR/" | grep -E "\.conf$" | sed -n '$=') + 0 ]"
local delline="$[ $(sed -n '$=' "$patch.del" 2>/dev/null) + 0 ]"

echo 
echo "Download Date: $srcdate    Local Date: $basedate    Unverified Count: $confcount    Unapplied changes: $delline"
echo 
echo Available commands:
echo 
echo "  download_sources"
echo "  update_rules"
echo "  update_sources"
echo "  verify_domain [<rounds>]"
echo "  commit_changes"
echo 
echo "  tldextract <url or rawdomain> e.g. https://www.taobao.com/"
echo "  get_nsdomain <tld> e.g. taobao.com"
echo 
echo "  check_cn_ip <ip>"
echo "  check_nocn_domain <domain>  e.g. www.taobao.com"
echo 
echo "  check_cdn <tld> e.g. taobao.com"
echo "  check_white <nsdomain> e.g. ns4.taobao.com."
echo "  check_black <nsdomain> e.g. ns4.taobao.com."
echo 

}



# MAIN
[ ! -e "$SRCDIR/$MAINDOMAIN" -o ! -e "$SRCDIR/$CNROUTE" ] && download_sources
[ ! -e "$CURRENTDIR/$MAINDOMAIN.base" ] && update_sources

[ -z "$_FUNCTION" ] && show_status

$_FUNCTION "$@"
