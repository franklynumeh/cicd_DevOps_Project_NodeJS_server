################
# data sources #
################
data "aws_eks_cluster" "cluster" {
  name = var.cluster_name_prefix
}

data "aws_eks_cluster_auth" "k8s_auth" {
  name = data.aws_eks_cluster.cluster.name
}

data "aws_subnet" "private_subnets" {
  for_each = toset(var.private_subnets)
  id = each.value
}