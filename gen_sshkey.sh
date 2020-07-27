#!/bin/sh

ssh-keygen -t rsa -b 4096 -C "$(git config user.email)" -f actions-deploy-key -N ""
