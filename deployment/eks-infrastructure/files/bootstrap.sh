#!/bin/bash
/etc/eks/bootstrap.sh --apiserver-endpoint '${endpoint}' --b64-cluster-ca '${cluster_ca}' '${cluster_name}'
