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
