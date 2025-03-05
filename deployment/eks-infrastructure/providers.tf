############
# provider #
############
provider "aws" {
  region = "us-east-1"
}
provider "kubernetes" {
  host                   = aws_eks_cluster.cluster.endpoint
  cluster_ca_certificate = base64decode(aws_eks_cluster.cluster.certificate_authority[0].data)
  token = data.aws_eks_cluster_auth.k8s_auth.token
}
provider "helm" {
  kubernetes {
    host                   = aws_eks_cluster.cluster.endpoint
    cluster_ca_certificate = base64decode(aws_eks_cluster.cluster.certificate_authority[0].data)
    token = data.aws_eks_cluster_auth.k8s_auth.token  
  }
}
