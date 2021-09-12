#!/bin/sh

. /lib/functions/system.sh

[ -z "$(uci -q get usteer-influxdb.settings.host)" ] || exit 0

RANDOM_STR="$(tr -dc A-Za-z0-9 </dev/urandom | head -c 13 ; echo '')"
LABEL_MAC="$(get_mac_label)"

if [ -z "$LABEL_MAC" ]; then
	uci -q set usteer-influxdb.settings.host="$RANDOM_STR"
else
	uci -q set usteer-influxdb.settings.host="$LABEL_MAC"
fi

uci commit usteer-influxdb
