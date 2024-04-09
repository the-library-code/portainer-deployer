#!/bin/bash

# Env vars are set via Gitlab CICD variables. All variables set this way can be access inside the container. 
sed -i "s@\"url\"@$PORTAINER_URL@g" /etc/portainer-deployer/app.conf
sed -i "s@\"user\"@$PORTAINER_USER@g" /etc/portainer-deployer/app.conf
sed -i "s@\"token\"@$PORTAINER_TOKEN@g" /etc/portainer-deployer/app.conf

/bin/bash