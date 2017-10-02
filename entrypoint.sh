#!/bin/bash
set -e

if [ -r /.firstboot ]; then
	# Create the config file
	cat <<__CONFIG__ >/opt/paste2splunk/settings.conf
[pastebin]
api_scrape = https://pastebin.com/api_scraping.php
api_raw = https://pastebin.com/api_scrape_item.php?i=
paste_limit = 200
store_all = false

[yara]
rule_path = YaraRules

[splunk]
server = SPLUNK_SERVER
xport = SPLUNK_PORT
username = SPLUNK_USER
password = SPLUNK_PASS
index = SPLUNK_INDEX
__CONFIG__

	if [ -z $SPLUNK_SERVER ]; then
		echo "ERROR: \$SPLUNK_SERVER is not defined"
		exit 1
	else
		sed -i "s/SPLUNK_SERVER/$SPLUNK_SERVER/" /opt/paste2splunk/settings.conf
	fi

	if [ -z $SPLUNK_PORT ]; then
		echo "ERROR: \$SPLUNK_PORT is not defined"
		exit 1
	else
		sed -i "s/SPLUNK_PORT/$SPLUNK_PORT/" /opt/paste2splunk/settings.conf
	fi
	if [ -z $SPLUNK_USER ]; then
		echo "ERROR: \$SPLUNK_USER is not defined"
		exit 1
	else
		sed -i "s/SPLUNK_USER/$SPLUNK_USER/" /opt/paste2splunk/settings.conf
	fi
	if [ -z $SPLUNK_PASS ]; then
		echo "ERROR: \$SPLUNK_PASS is not defined"
		exit 1
	else
		sed -i "s/SPLUNK_PASS/$SPLUNK_PASS/" /opt/paste2splunk/settings.conf
	fi
	if [ -z $SPLUNK_INDEX ]; then
		echo "ERROR: \$SPLUNK_INDEX is not defined"
		exit 1
	else
		sed -i "s/SPLUNK_INDEX/$SPLUNK_INDEX/" /opt/paste2splunk/settings.conf
	fi

	# Enable logrotage
	cat <<__LOGROTATE__ >/etc/cron.daily/logrotate
#!/bin/sh
test -x /usr/sbin/logrotate || exit 0
/usr/sbin/logrotate /opt/paste2splunk/logrotate.conf
__LOGROTATE__
	chmod 0755 /etc/cron.daily/logrotate

	# Unpack YARA rules 
	cd /opt/paste2splunk
	tar xzf /tmp/yararules.tgz && rm /tmp/yararules.tgz
	rm /.firstboot
fi
/usr/sbin/cron && tail -f /var/log/cron.log
