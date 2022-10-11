#!/bin/sh
# dependent: bash curl unzip coreutils-cksum bind-dig diffutils coreutils-stat

# init
DCL='https://github.com/felixonmars/dnsmasq-china-list/raw/master/accelerated-domains.china.conf'
DOMAINBLACK=domain-blacklist.txt

CURRENTDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CUSTOMDIR="$CURRENTDIR/Custom"

Repo='muink/dnsmasq-china-tool'
Origin='accelerated-domains2.china.conf'
Clash='accelerated-domains2.china.yml'
SwitchyOmega='accelerated-domains2.china.sorl'



# Origin
git checkout master -- $CUSTOMDIR/$DOMAINBLACK
git reset -- $CUSTOMDIR/$DOMAINBLACK
curl -sSL "$DCL" | grep -Evf $CUSTOMDIR/$DOMAINBLACK > $Origin


# Clash
cat << EOF > $Clash
# domain
# Source: https://github.com/$Repo/blob/list/$Clash
# Last Modified: `date -u '+%F %T %Z'`
payload:
EOF
sed -E "s|/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$|'|; s|server=/|  - '+.|" "$Origin" >> "$Clash"
echo >> "$Clash"


# SwitchyOmega
cat << EOF > $SwitchyOmega
[AutoProxy 0.2.9]
! Expires: 24h
! Title: china-dnsmasq-tool
! Last Modified: `date -Ru`
!
! HomePage: https://github.com/$Repo
! License: MIT

EOF
sed -E "s|/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$||; s|server=/|\|\||" $Origin >> $SwitchyOmega