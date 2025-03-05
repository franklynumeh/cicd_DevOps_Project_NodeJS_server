#!/bin/bash
docker run -d \
-p 8080:8080 \
-p 50000:50000 \
-p 4000:4000 \
-p 3000:3000 \
-v jenkins_home:/var/jenkins_home \
-v /home/ec2-user/main/projects/:/app \
-v /var/run/docker.sock:/var/run/docker.sock \
jenkins/jenkins:lts
