#!/bin/sh

CURRENTDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd $CURRENTDIR

Repo='muink/dnsmasq-china-tool'
Origin='accelerated-domains.china.conf'
Clash='accelerated-domains.china.yml'
SwitchyOmega='accelerated-domains.china.sorl'



# Clash
cat << EOF > $Clash
# domain
# Source: https://github.com/$Repo/blob/list/$Clash
# Last Modified: `date -u '+%F %T %Z'`
payload:
EOF
sed -E "s|/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$|'|; s|server=/|  - '+.|" "$Origin" >> "$Clash"
echo -e "\n" >> "$Clash"


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

