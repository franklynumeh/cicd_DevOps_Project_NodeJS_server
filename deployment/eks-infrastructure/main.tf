##################
# code - stage  #
##################

## cluster iam role
resource "aws_iam_role" "iam-cluster-role" {
  name = "${var.cluster_name_prefix}-iam-role"
  path                 = var.iam_path
  permissions_boundary = "arn:aws:iam::${data.aws_caller_identity._.account_id}:policy/cms-cloud-admin/ct-ado-poweruser-permissions-boundary-policy"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "sts:AssumeRole",
          "sts:TagSession"
        ]
        Effect = "Allow"
        Principal = {
          Service = "eks.amazonaws.com"
        }
      },
    ]
  })
}

## node iam role
resource "aws_iam_role" "eks_nodes" {
  name                 = "${var.cluster_name_prefix}-worker"
  path                 = var.iam_path
  permissions_boundary = "arn:aws:iam::${data.aws_caller_identity._.account_id}:policy/cms-cloud-admin/ct-ado-poweruser-permissions-boundary-policy"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "sts:AssumeRole",
          "sts:TagSession"
        ]
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })
}

## cluster security group
resource "aws_security_group" "eks_cluster" {
  name        = "eks-cluster-sg"
  description = "Cluster communication with worker nodes"
  vpc_id      = var.vpc_id

  tags = {
    Name = "eks-cluster-sg"
  }
}

## node security group
resource "aws_security_group" "eks_nodes" {
  name        = "eks-cluster-nodes-sg"
  description = "Security group for all nodes in the cluster"
  vpc_id      = var.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name                                        = "eks-cluster-nodes-sg"
    "kubernetes.io/cluster/${var.cluster_name_prefix}" = "owned"
  }
}

## cloud watch policy
resource "aws_iam_policy" "cloudwatch_logs" {
  name        = "eks-cluster-cloudWatch-logs-policy"
  description = "A policy to allow sending logs to CloudWatch"
  path        = var.iam_path

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}
##################
# code - stage  #
##################

## cluster role policies
resource "aws_iam_role_policy_attachment" "cluster_AmazonEKSClusterPolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.iam-cluster-role.name
}

resource "aws_iam_role_policy_attachment" "cluster_AmazonEKSComputePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSComputePolicy"
  role       = aws_iam_role.iam-cluster-role.name
}

resource "aws_iam_role_policy_attachment" "cluster_AmazonEKSBlockStoragePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSBlockStoragePolicy"
  role       = aws_iam_role.iam-cluster-role.name
}

resource "aws_iam_role_policy_attachment" "cluster_AmazonEKSLoadBalancingPolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSLoadBalancingPolicy"
  role       = aws_iam_role.iam-cluster-role.name
}

resource "aws_iam_role_policy_attachment" "cluster_AmazonEKSNetworkingPolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSNetworkingPolicy"
  role       = aws_iam_role.iam-cluster-role.name
}

resource "aws_iam_role_policy_attachment" "cluster_cloudwatch_logs_attach" {
  policy_arn = aws_iam_policy.cloudwatch_logs.arn
  role       = aws_iam_role.iam-cluster-role.name
}

resource "aws_iam_role_policy_attachment" "cluster_AmazonEBSCSIDriverPolicy" {
  role       = aws_iam_role.eks_nodes.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
}

resource "aws_iam_role_policy_attachment" "cluster_AmazonEFSCSIDriverPolicy" {
  role       = aws_iam_role.eks_nodes.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEFSCSIDriverPolicy"
}

## node policies
resource "aws_iam_role_policy_attachment" "aws_eks_worker_node_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.eks_nodes.name
}

resource "aws_iam_role_policy_attachment" "aws_eks_cni_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.eks_nodes.name
}

resource "aws_iam_role_policy_attachment" "ec2_read_only" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.eks_nodes.name
}

resource "aws_iam_role_policy_attachment" "node_AmazonEBSCSIDriverPolicy" {
  role       = aws_iam_role.eks_nodes.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
}

resource "aws_iam_role_policy_attachment" "node_AmazonEFSCSIDriverPolicy" {
  role       = aws_iam_role.eks_nodes.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEFSCSIDriverPolicy"
}

## cluster sg rules
resource "aws_security_group_rule" "cluster_inbound" {
  description              = "Allow worker nodes to communicate with the cluster API Server"
  from_port                = 443
  protocol                 = "tcp"
  security_group_id        = aws_security_group.eks_cluster.id
  source_security_group_id = aws_security_group.eks_nodes.id
  to_port                  = 443
  type                     = "ingress"
}

resource "aws_security_group_rule" "cluster_inbound_all" {
  description              = "Allow worker nodes to communicate with the cluster API Server"
  from_port                = 443
  protocol                 = "tcp"
  security_group_id        = aws_security_group.eks_cluster.id
  # revert this to 0.0.0.0/0 if needed. Not having this blocked jenkins from being able to talk to kubernetes.
  cidr_blocks              = ["10.0.0.0/8"]
  to_port                  = 443
  type                     = "ingress"
}

resource "aws_security_group_rule" "cluster_outbound" {
  description              = "Allow cluster API Server to communicate with the worker nodes"
  from_port                = 1024
  protocol                 = "tcp"
  security_group_id        = aws_security_group.eks_cluster.id
  source_security_group_id = aws_security_group.eks_nodes.id
  to_port                  = 65535
  type                     = "egress"
}

## node sg rules
resource "aws_security_group_rule" "nodes" {
  description              = "Allow nodes to communicate with each other"
  from_port                = 0
  protocol                 = "-1"
  security_group_id        = aws_security_group.eks_nodes.id
  source_security_group_id = aws_security_group.eks_nodes.id
  to_port                  = 65535
  type                     = "ingress"
}

resource "aws_security_group_rule" "nodes_inbound" {
  description              = "Allow worker Kubelets and pods to receive communication from the cluster control plane"
  from_port                = 1025
  protocol                 = "tcp"
  security_group_id        = aws_security_group.eks_nodes.id
  source_security_group_id = aws_security_group.eks_cluster.id
  to_port                  = 65535
  type                     = "ingress"
}


##################
# code - stage  #
##################

resource "aws_eks_cluster" "cluster" {
  name = "${var.cluster_name_prefix}"

  access_config {
    authentication_mode = "API"
    bootstrap_cluster_creator_admin_permissions = false
  }

  role_arn = aws_iam_role.iam-cluster-role.arn
  version  = "1.31"
  enabled_cluster_log_types = [ "api","audit","authenticator","controllerManager","scheduler" ]
  vpc_config {
    endpoint_private_access = true
    endpoint_public_access  = false
    subnet_ids = var.private_subnets
    security_group_ids = [aws_security_group.eks_cluster.id, aws_security_group.eks_nodes.id]
  }

  # Ensure that IAM Role permissions are created before and deleted
  # after EKS Cluster handling. Otherwise, EKS will not be able to
  # properly delete EKS managed EC2 infrastructure such as Security Groups.
  depends_on = [
    aws_iam_role_policy_attachment.cluster_AmazonEKSClusterPolicy,
    aws_iam_role_policy_attachment.cluster_AmazonEKSComputePolicy,
    aws_iam_role_policy_attachment.cluster_AmazonEKSBlockStoragePolicy,
    aws_iam_role_policy_attachment.cluster_AmazonEKSLoadBalancingPolicy,
    aws_iam_role_policy_attachment.cluster_AmazonEKSNetworkingPolicy,
    aws_iam_role_policy_attachment.cluster_AmazonEBSCSIDriverPolicy,
    aws_iam_role_policy_attachment.cluster_AmazonEFSCSIDriverPolicy,
  ]
}

##################
# code - stage  #
##################
## ec2 user
resource "aws_eks_access_entry" "eks_jenkins_access" {
  cluster_name      = aws_eks_cluster.cluster.name
  principal_arn     = "arn:aws:iam::${data.aws_caller_identity._.account_id}:role/delegatedadmin/developer/jenkins-role"
  type              = "STANDARD"
}

resource "aws_eks_access_policy_association" "eks_jenkins_policy" {
  cluster_name  = aws_eks_cluster.cluster.name
  policy_arn    = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
  principal_arn = "arn:aws:iam::${data.aws_caller_identity._.account_id}:role/delegatedadmin/developer/jenkins-role"

  access_scope {
    type       = "cluster"
  }
  depends_on = [ 
    aws_eks_access_entry.eks_jenkins_access
   ]
}

resource "aws_eks_access_entry" "eks_ec2_access" {
  cluster_name      = aws_eks_cluster.cluster.name
  principal_arn = aws_iam_role.eks_nodes.arn
  type              = "EC2_LINUX"
  depends_on = [ 
    aws_eks_access_entry.eks_jenkins_access
   ]
}

resource "aws_eks_access_entry" "eks_admins_access" {
  cluster_name      = aws_eks_cluster.cluster.name
  principal_arn     = "arn:aws:iam::${data.aws_caller_identity._.account_id}:role/ct-ado-${var.project_name}-application-admin"
  type              = "STANDARD"
  depends_on = [ 
    aws_eks_access_entry.eks_jenkins_access
  ]
}

resource "aws_eks_access_policy_association" "eks_admin_policy" {
  cluster_name  = aws_eks_cluster.cluster.name
  policy_arn    = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
  principal_arn = "arn:aws:iam::${data.aws_caller_identity._.account_id}:role/ct-ado-${var.project_name}-application-admin"

  access_scope {
    type       = "cluster"
  }
  depends_on = [ 
    aws_eks_access_entry.eks_jenkins_access
  ]
}

resource "aws_eks_access_entry" "cluster_iam_role_access" {
  cluster_name      = aws_eks_cluster.cluster.name
  principal_arn     = "arn:aws:iam::${data.aws_caller_identity._.account_id}:role/delegatedadmin/developer/${var.cluster_name_prefix}-iam-role"
  type              = "STANDARD"
  depends_on = [ 
    aws_eks_access_entry.eks_jenkins_access
  ]
}

resource "aws_eks_access_policy_association" "cluster_iam_role_admin_policy" {
  cluster_name  = aws_eks_cluster.cluster.name
  policy_arn    = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
  principal_arn = "arn:aws:iam::${data.aws_caller_identity._.account_id}:role/delegatedadmin/developer/${var.cluster_name_prefix}-iam-role"

  access_scope {
    type       = "cluster"
  }
  depends_on = [ 
    aws_eks_access_entry.eks_jenkins_access
  ]
}
##################
# code - stage  #
##################
resource "aws_iam_openid_connect_provider" "cluster_oidc" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.cluster_cert.certificates[0].sha1_fingerprint]
  url             = aws_eks_cluster.cluster.identity[0].oidc[0].issuer
}

##################
# code - stage  #
##################
resource "aws_iam_role" "iam_role_cni" {
  path                 = var.iam_path
  permissions_boundary = "arn:aws:iam::${data.aws_caller_identity._.account_id}:policy/cms-cloud-admin/ct-ado-poweruser-permissions-boundary-policy"
  assume_role_policy = data.aws_iam_policy_document.cni_assume_role_policy.json
  name               = "${var.cluster_name_prefix}-cni"
}
resource "aws_iam_role" "iam_role_ebs" {
  path                 = var.iam_path
  permissions_boundary = "arn:aws:iam::${data.aws_caller_identity._.account_id}:policy/cms-cloud-admin/ct-ado-poweruser-permissions-boundary-policy"
  assume_role_policy = data.aws_iam_policy_document.ebs_assume_role_policy.json
  name               = "${var.cluster_name_prefix}-ebs"
}
resource "aws_iam_role" "iam_role_efs" {
  path                 = var.iam_path
  permissions_boundary = "arn:aws:iam::${data.aws_caller_identity._.account_id}:policy/cms-cloud-admin/ct-ado-poweruser-permissions-boundary-policy"
  assume_role_policy = data.aws_iam_policy_document.efs_assume_role_policy.json
  name               = "${var.cluster_name_prefix}-efs"
}
##################
# code - stage  #
##################
resource "aws_iam_role_policy_attachment" "cni_iam_role_policy_attach" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.iam_role_cni.name
}

resource "aws_iam_role_policy_attachment" "ebs_iam_role_policy_attach" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
  role       = aws_iam_role.iam_role_ebs.name
}

resource "aws_iam_role_policy_attachment" "efs_iam_role_policy_attach" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEFSCSIDriverPolicy"
  role       = aws_iam_role.iam_role_efs.name
}
##################
# code - stage  #
##################
resource "aws_launch_template" "non_gpu" {
  name_prefix   = "${var.cluster_name_prefix}"
  image_id      = data.aws_ami.gi_ami.id
  instance_type = var.eks_instance_type_non_gpu
  update_default_version = true
  block_device_mappings {
    device_name = var.ebs_device_name_non_gpu
    ebs {
      volume_size = var.ebs_volume_size_non_gpu
    }
  }

  user_data = base64encode(
    templatefile("files/bootstrap.sh", {
      cluster_name = "${aws_eks_cluster.cluster.name}"
      endpoint     = "${aws_eks_cluster.cluster.endpoint}"
      cluster_ca   = "${aws_eks_cluster.cluster.certificate_authority[0].data}"
      region       = "us-east-1"
      }
    )
  )
  depends_on = [
    aws_iam_role_policy_attachment.aws_eks_worker_node_policy,
    aws_iam_role_policy_attachment.aws_eks_cni_policy,
    aws_iam_role_policy_attachment.ec2_read_only,
    aws_iam_role_policy_attachment.node_AmazonEBSCSIDriverPolicy,
    aws_iam_role_policy_attachment.node_AmazonEFSCSIDriverPolicy,
    aws_eks_access_entry.eks_ec2_access,
    aws_eks_access_entry.eks_jenkins_access,
    aws_eks_access_entry.eks_admins_access,
    aws_eks_access_entry.cluster_iam_role_access,
    aws_eks_access_policy_association.eks_jenkins_policy,
    aws_eks_access_policy_association.eks_admin_policy,
    aws_eks_access_policy_association.cluster_iam_role_admin_policy,
  ]
}
##################
# code - stage  #
##################

# Nodes groups
resource "aws_eks_node_group" "non_gpu" {
  cluster_name    = aws_eks_cluster.cluster.name
  node_group_name = "${aws_eks_cluster.cluster.name}-non-gpu"
  node_role_arn   = aws_iam_role.eks_nodes.arn
  subnet_ids      = var.private_subnets

  ami_type       = "CUSTOM"
  //cms_golden_ami_name      = "amzn2-eks-1.31-gi-2024-11-13T12-28-18Z"
  //instance_types = [var.eks_instance_type_non_gpu]

  scaling_config {
    desired_size = 1
    max_size     = 1
    min_size     = 1
  }

  update_config {
    max_unavailable = 1
  }

  launch_template {
    id      = aws_launch_template.non_gpu.id
    version = aws_launch_template.non_gpu.latest_version
  }

  tags = {
    Name = "${aws_eks_cluster.cluster.name}-non-gpu"
  }

  # Ensure that IAM Role permissions are created before and deleted after EKS Node Group handling.
  # Otherwise, EKS will not be able to properly delete EC2 Instances and Elastic Network Interfaces.
  depends_on = [
    aws_iam_role_policy_attachment.aws_eks_worker_node_policy,
    aws_iam_role_policy_attachment.aws_eks_cni_policy,
    aws_iam_role_policy_attachment.ec2_read_only,
    aws_eks_access_entry.eks_ec2_access,
    aws_eks_access_entry.eks_jenkins_access,
    aws_eks_access_entry.eks_admins_access,
    aws_eks_access_policy_association.eks_jenkins_policy,
    aws_eks_access_policy_association.eks_admin_policy,
    aws_launch_template.non_gpu,
  ]
}

###################
# code - stage #
###################
resource "aws_eks_addon" "eks_addon_vpn_coredns" {
    cluster_name = aws_eks_cluster.cluster.name
    addon_name = "coredns"
    resolve_conflicts_on_update = "OVERWRITE"
    //service_account_role_arn = aws_iam_role.iam_role_cni.arn
    //configuration_values = jsondecode()
    depends_on = [ 
        aws_eks_node_group.non_gpu,
     ]
}

resource "aws_eks_addon" "eks_addon_vpn_kube_proxy" {
    cluster_name = aws_eks_cluster.cluster.name
    addon_name = "kube-proxy"
    resolve_conflicts_on_update = "OVERWRITE"
    //service_account_role_arn = aws_iam_role.iam_role_cni.arn
    //configuration_values = jsondecode()
    depends_on = [ 
        aws_eks_node_group.non_gpu,
     ]
}

resource "aws_eks_addon" "ebs_addon_vpn_cni" {
    cluster_name = aws_eks_cluster.cluster.name
    addon_name = "vpc-cni"
    resolve_conflicts_on_update = "OVERWRITE"
    service_account_role_arn = aws_iam_role.iam_role_cni.arn
    configuration_values = jsonencode({
      enableNetworkPolicy = "true"
    })
    depends_on = [ 
        aws_eks_node_group.non_gpu,
     ]
}

resource "aws_eks_addon" "ebs_addon_ebs_csi" {
    cluster_name = aws_eks_cluster.cluster.name
    addon_name = "aws-ebs-csi-driver"
    resolve_conflicts_on_update = "OVERWRITE"
    service_account_role_arn = aws_iam_role.iam_role_ebs.arn
    //configuration_values = jsondecode()
    depends_on = [ 
         aws_eks_addon.ebs_addon_vpn_cni,
     ]
}

resource "aws_eks_addon" "eks_addon_efs_csi" {
    cluster_name = aws_eks_cluster.cluster.name
    addon_name = "aws-efs-csi-driver"
    resolve_conflicts_on_update = "OVERWRITE"
    service_account_role_arn = aws_iam_role.iam_role_efs.arn
    //configuration_values = jsondecode()
    depends_on = [ 
         aws_eks_addon.ebs_addon_vpn_cni,
     ]
}

###################
# code - stage #
###################

resource "kubernetes_storage_class_v1" "ebs_sc" {
  metadata {
    name = "ebs-sc"
  }

  storage_provisioner = "ebs.csi.aws.com"

  parameters = {
    type = "gp2"
  }
  reclaim_policy         = "Retain"
  allow_volume_expansion = true
  volume_binding_mode    = "Immediate"
  depends_on = [ 
    aws_eks_addon.ebs_addon_ebs_csi,
  ]
}

resource "kubernetes_storage_class_v1" "ebs_sc_wait" {
  metadata {
    name = "ebs-sc-wait"
  }

  storage_provisioner = "ebs.csi.aws.com"

  parameters = {
    type = "gp2"
  }
  reclaim_policy         = "Retain"
  allow_volume_expansion = true
  volume_binding_mode    = "WaitForFirstConsumer"
  depends_on = [ 
    aws_eks_addon.ebs_addon_ebs_csi,
  ]
}

##################
# code - stage  #
##################
resource "kubernetes_config_map" "nvidia_device_plugin" {
  depends_on = [ 
    aws_eks_cluster.cluster 
    ]
  metadata {
    name      = "nvidia-device-plugin"
    namespace = "kube-system"
  }
  data = {
    any = <<-EOF
      version: v1
      flags:
        migStrategy: none
      sharing:
        timeSlicing:
          resources:
          - name: nvidia.com/gpu
            replicas: 8
    EOF
  }
}

resource "aws_iam_role" "eks_alb_ingress_controller_iam_role" {
  name                 = "${join("", [for word in split("-", aws_eks_cluster.cluster.name) : title(word)])}EksAlbInCtl"
  assume_role_policy   = data.aws_iam_policy_document.alb_assume_role_policy.json
  path                 = var.iam_path
  permissions_boundary = var.iam_permissions_boundary
}

resource "aws_iam_policy" "eks_alb_ingress_controller_policy" {
  name        = "${join("", [for word in split("-", aws_eks_cluster.cluster.name) : title(word)])}EksAlbInCtlIamPolicy"
  description = "Policy for the ALB Ingress Controller"
  policy      = data.aws_iam_policy_document.alb_ingress_controller_iam_policy.json
  path        = var.iam_path
}

resource "kubernetes_cluster_role_binding" "alb_ingress_controller" {
  depends_on = [ 
    aws_eks_cluster.cluster,
    aws_eks_access_entry.eks_jenkins_access,
    aws_eks_access_policy_association.eks_jenkins_policy,
    ]
  metadata {
    name = "alb-ingress-controller"

    labels = {
      "app.kubernetes.io/name" = "alb-ingress-controller"
    }
  }

  subject {
    kind      = "ServiceAccount"
    name      = "alb-ingress-controller"
    namespace = "kube-system"
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = "alb-ingress-controller"
  }
}

resource "kubernetes_cluster_role" "alb_ingress_controller" {
  depends_on = [ 
    aws_eks_cluster.cluster,
    aws_eks_access_entry.eks_jenkins_access,
    aws_eks_access_policy_association.eks_jenkins_policy,
    ]
  metadata {
    name = "alb-ingress-controller"

    labels = {
      "app.kubernetes.io/name" = "alb-ingress-controller"
    }
  }

  rule {
    verbs      = ["create", "get", "list", "update", "watch", "patch"]
    api_groups = ["", "extensions"]
    resources  = ["configmaps", "endpoints", "events", "ingresses", "ingresses/status", "services", "pods/status"]
  }

  rule {
    verbs      = ["get", "list", "watch"]
    api_groups = ["", "extensions"]
    resources  = ["nodes", "pods", "secrets", "services", "namespaces"]
  }
}

resource "kubernetes_secret" "alb_ingress_controller" {
  depends_on = [ 
    aws_eks_cluster.cluster,
    aws_eks_access_entry.eks_jenkins_access,
    aws_eks_access_policy_association.eks_jenkins_policy,
    ]
  metadata {
    name = "alb-ingress-controller"
  }
}
##################
# code - stage  #
##################
resource "helm_release" "nvidia_device_plugin" {
  depends_on = [
    kubernetes_service_account.alb_ingress_controller,
    aws_eks_cluster.cluster,
    kubernetes_config_map.nvidia_device_plugin,
    aws_eks_node_group.non_gpu,
    aws_eks_access_entry.eks_jenkins_access,
    aws_eks_access_policy_association.eks_jenkins_policy,
  ]
  name       = "nvdp"
  repository = "https://nvidia.github.io/k8s-device-plugin"
  chart      = "nvidia-device-plugin"
  namespace  = "kube-system"
  version    = "0.14.0"

  values = [
    "${file("files/nvdp-values.yaml")}"
  ]

  set {
    name  = "config.name"
    value = "nvidia-device-plugin"
  }
}

resource "aws_iam_role_policy_attachment" "alb_ingress_controller_policy_attachment" {
  role       = aws_iam_role.eks_alb_ingress_controller_iam_role.name
  policy_arn = aws_iam_policy.eks_alb_ingress_controller_policy.arn
}

resource "kubernetes_service_account" "alb_ingress_controller" {
  depends_on = [
    kubernetes_secret.alb_ingress_controller,
    aws_eks_access_entry.eks_jenkins_access,
    aws_eks_access_policy_association.eks_jenkins_policy,
  ]

  metadata {
    name      = "alb-ingress-controller"
    namespace = "kube-system"

    labels = {
      "app.kubernetes.io/name" = "alb-ingress-controller"
    }

    annotations = {
      "eks.amazonaws.com/role-arn" = aws_iam_role.eks_alb_ingress_controller_iam_role.arn
    }
  }
  secret {
    name = "alb-ingress-controller"
  }
}

##################
# code - stage  #
##################

resource "kubernetes_namespace_v1" "jupyter-namespace" {
  depends_on = [
    kubernetes_service_account.alb_ingress_controller,
    aws_eks_access_entry.eks_jenkins_access,
    aws_eks_access_policy_association.eks_jenkins_policy,
  ]
  metadata {
    name = "jupyter"
  }
}

resource "helm_release" "aws_load_balancer_controller" {
  depends_on = [
    kubernetes_service_account.alb_ingress_controller,
    aws_eks_access_entry.eks_jenkins_access,
    aws_eks_access_policy_association.eks_jenkins_policy,
  ]

  name             = "aws-load-balancer-controller"
  repository       = "https://aws.github.io/eks-charts"
  chart            = "aws-load-balancer-controller"
  namespace        = "kube-system"
  create_namespace = false

  set {
    name  = "clusterName"
    value = aws_eks_cluster.cluster.name
  }

  set {
    name  = "serviceAccount.create"
    value = "false"
  }

  set {
    name  = "serviceAccount.name"
    value = kubernetes_service_account.alb_ingress_controller.metadata[0].name
  }

  set {
    name  = "region"
    value = "us-east-1"
  }

  set {
    name  = "vpcId"
    value = var.vpc_id
  }
}

##################
# code - stage  #
##################
resource "aws_launch_template" "gpu" {
  name_prefix   = "${var.cluster_name_prefix}-gpu"
  image_id      = data.aws_ssm_parameter.gpu_ami.value
  instance_type = var.eks_instance_type_gpu
  update_default_version = true
  block_device_mappings {
    device_name = var.ebs_device_name_gpu
    ebs {
      volume_size = var.ebs_volume_size_gpu
    }
  }

  user_data = base64encode(
    templatefile("files/bootstrap.sh", {
      cluster_name = "${aws_eks_cluster.cluster.name}"
      endpoint     = "${aws_eks_cluster.cluster.endpoint}"
      cluster_ca   = "${aws_eks_cluster.cluster.certificate_authority[0].data}"
      region       = "us-east-1"
      }
    )
  )
  depends_on = [
    helm_release.aws_load_balancer_controller,
    aws_eks_access_entry.eks_jenkins_access,
    aws_eks_access_policy_association.eks_jenkins_policy,
  ]
}
##################
# code - stage  #
##################

# Nodes groups
resource "aws_eks_node_group" "gpu" {
  cluster_name    = aws_eks_cluster.cluster.name
  node_group_name = "${aws_eks_cluster.cluster.name}-gpu"
  node_role_arn   = aws_iam_role.eks_nodes.arn
  subnet_ids      = var.private_subnets

  ami_type       = "CUSTOM"
  //cms_golden_ami_name      = "amzn2-eks-1.31-gi-2024-11-13T12-28-18Z"
  //instance_types = [var.eks_instance_type_non_gpu]

  scaling_config {
    desired_size = var.eks_jupyter_scaling_desired_size
    max_size     = var.eks_jupyter_scaling_max_size
    min_size     = var.eks_jupyter_scaling_min_size
  }
  
  labels = {
    "hub.jupyter.org/jupyter-user-nodes" = "jupyter-users"
  }

  update_config {
    max_unavailable = 1
  }

  launch_template {
    id      = aws_launch_template.gpu.id
    version = aws_launch_template.gpu.latest_version
  }

  tags = {
    Name = "${aws_eks_cluster.cluster.name}-gpu"
  }

  # Ensure that IAM Role permissions are created before and deleted after EKS Node Group handling.
  # Otherwise, EKS will not be able to properly delete EC2 Instances and Elastic Network Interfaces.
  depends_on = [
    helm_release.aws_load_balancer_controller,
    aws_eks_access_entry.eks_jenkins_access,
    aws_eks_access_policy_association.eks_jenkins_policy,
  ]
}

##################
# code - stage  #
##################

resource "aws_ecr_repository" "repositories" {
  for_each = toset(var.repository_names)
  name                 = "${var.cluster_name_prefix}-${each.value}"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = true
  }
}



##################
# code - stage  #
##################

resource "aws_ecr_lifecycle_policy" "repository_lifecycle_policies" {
  for_each = aws_ecr_repository.repositories
  repository = each.value.name

  policy = <<EOF
{
    "rules": [
        {
            "rulePriority": 1,
            "description": "Expire images older than 14 days",
            "selection": {
                "tagStatus": "untagged",
                "countType": "sinceImagePushed",
                "countUnit": "days",
                "countNumber": 14
            },
            "action": {
                "type": "expire"
            }
        }
    ]
}
EOF
}
