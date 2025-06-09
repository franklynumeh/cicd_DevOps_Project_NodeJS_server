eksctl create cluster \
  --name frank-cluster \
  --region us-east-1 \
  --without-nodegroup
eksctl create nodegroup \
  --cluster frank-cluster \
  --region us-east-1 \
  --name ec2-workers \
  --node-type t3.medium \
  --nodes 1 \
  --nodes-min 1 \
  --nodes-max 2 \
  --ssh-access \
  --ssh-public-key eks-test-ec2 \
  --managed


  aws eks update-kubeconfig --name frank-cluster --region us-east-1
# then build and push to ecr
# then run deply yaml file - these deploy a deploymen,namespace, service and ingress resourec, not an ingress controller yet

# the ingress controller will read the ingress resourece and this will create an alb for us and configure it

eksctl utils associate-iam-oidc-provider --cluster frank-cluster --approve


aws iam create-policy \
    --policy-name AWSLoadBalancerControllerIAMPolicy \
    --policy-document file://aws-load-balancer-controller-policy.json


eksctl create iamserviceaccount \
  --cluster=frank-cluster \
  --namespace=kube-system \
  --name=aws-load-balancer-controller \
  --role-name AmazonEKSLoadBalancerControllerRole \
  --attach-policy-arn=arn:aws:iam::577638372446:policy/AWSLoadBalancerControllerIAMPolicy \
  --approve

  now we will use helm chart tp create a controller, that will use the service account for running the controller pod


  helm repo add eks https://aws.github.io/eks-charts
  helm repo update eks

helm install aws-load-balancer-controller eks/aws-load-balancer-controller -n kube-system \
  --set clusterName=frank-cluster \
  --set serviceAccount.create=false \
  --set serviceAccount.name=aws-load-balancer-controller \
  --set region=us-east-1 \
  --set vpcId=vpc-09ccd9ca39d55a84c

  kubectl get deployment -n kube-system aws-load-balancer-controller

eksctl delete cluster --name frank-cluster --region us-east-1

aws iam detach-role-policy \
  --role-name AmazonEKSLoadBalancerControllerRole \
  --policy-arn arn:aws:iam::577638372446:policy/AWSLoadBalancerControllerIAMPolicy

aws iam delete-policy --policy-arn arn:aws:iam::577638372446:policy/AWSLoadBalancerControllerIAMPolicy

aws iam delete-role --role-name AmazonEKSLoadBalancerControllerRole

aws ecr delete-repository --repository-name shopping-app-rep --force

delete dns record - alb

delete cloudformation stack manually on aws console


installgit
node
awscli
eksctl
kubectl
helm
docker
