# Introduction
paste2splunk is a Pastebin crawler which index pasties into Splunk. The main script has been forked from the PasteHunter project(https://github.com/kevthehermit/PasteHunter). I just forked it and added support for the Splunk API.

# Usage
You can use it in a standalone way or in a Docker.

## Standalone
Close the project in a local directory:

# git clone https://github.com/xme/paste2splunk.git

Then edit the file settings.conf

## Docker container

Edit the docker-compose.yml and change the environment variables to match your environment.
