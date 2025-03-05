# manual steps required
1. Desired subnets for alb endpoints must be tagged with kubernetes.io/role/internal-elb with value of 1
2. create desired s3 bucket to store state in and update tfvars for environment
3. request and store ldap bind user password in aws secret
# deployment
## Troubleshooting go to the above server and use kubectl to connect
ssh -i kmp-devon-dev-test.pem ec2-user@10.147.232.32

## credentials
get credentials from cloudtamer for cli access. Copy and paste in terminal

## configure kubeconfig
aws eks update-kubeconfig --region us-east-1 --name devon-test

## delete resources on namespace
kubectl delete all --all -n jupyter

## get all pods
kubectl get pods -A

## get all deployments
kubectl get deployments -A

## force restart of deployment
kubectl rollout restart deployment/hub -n jupyter

## finding alb ingress address
kubectl describe service/proxy-public -n jupyter


# deleting state that gets stuck during destory:

terraform state rm helm_release.aws_load_balancer_controller
terraform state rm helm_release.nvidia_device_plugin
terraform state rm kubernetes_cluster_role.alb_ingress_controller
terraform state rm kubernetes_cluster_role_binding.alb_ingress_controller
terraform state rm kubernetes_config_map.nvidia_device_plugin
terraform state rm kubernetes_namespace_v1.jupyter-namespace
terraform state rm kubernetes_secret.alb_ingress_controller
terraform state rm kubernetes_service_account.alb_ingress_controller
terraform state rm kubernetes_storage_class_v1.ebs_sc
terraform state rm kubernetes_storage_class_v1.ebs_sc_wait