#!/bin/bash
aws ecr get-login-password --region us-east-2 | kubectl create secret docker-registry ecr-reg-cred \
--docker-server=577638372446.dkr.ecr.us-east-2.amazonaws.com \
--docker-username=AWS \
--docker-password=$(aws ecr get-login-password --region us-east-2)