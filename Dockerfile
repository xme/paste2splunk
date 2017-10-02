FROM ubuntu:latest
MAINTAINER Xavier Mertens <xavier@rootshell.be>

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y yara git python-pip python-yara python-requests python-coverage python-configparser cron

RUN pip install splunk-sdk
WORKDIR /opt
RUN git clone https://github.com/xme/paste2splunk.git
WORKDIR /opt/paste2splunk
RUN tar czpf /tmp/yararules.tgz YaraRules

# Create the cron job
RUN echo '*/2 * * * * root (cd /opt/paste2splunk; /usr/bin/python paste2splunk.py >>/var/log/cron.log 2>&1)' >/etc/cron.d/paste2splunk
RUN chmod 0644 /etc/cron.d/paste2splunk
RUN touch /var/log/cron.log
RUN touch /.firstboot

COPY entrypoint.sh /
RUN chmod 0755 /entrypoint.sh

VOLUME /opt/paste2splunk/YaraRules
 
# Run the command on container startup
ENTRYPOINT ["/entrypoint.sh"]
