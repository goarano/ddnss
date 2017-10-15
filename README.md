# ddnss
Dynamic Domain Name Service Switch

# Introduction
Simple Python HTTP server that reads a callers IP and saves it to a folder.
An NSS module on the host will then use these saved IPs to connect them with a specified hostname, ending with ```.ddnss``` as TLD.
The endpoint is secured using Basic HTTP Auth.

# Setup

## SSL
Use a proxy (e.g. nginx) for SSL connections.

## Docker
Example for docker-compose, see ```docker-compose.yml```

# Examples
## Save IP
```curl -u myuser:mypassword https://ddnss.example.com/myhost -X PUT```
or
```curl -u myuser:mypassword https://ddnss.example.com/myhost -X PUT -d "ip=127.0.0.1"```
or
```curl -u myuser:mypassword https://ddnss.example.com/myhost/set -X POST -F "ip=127.0.0.1"```

## Get saved IP
```curl -u myuser:mypassword https://ddnss.example.com/myhost```
