######################
# stage - code - nfs #
######################
resource "aws_security_group" "efs-sg" {
  name_prefix = "${var.cluster_name_prefix}-efs-sg"
  description = "Security group for ${var.cluster_name_prefix}-efs-sg"
  vpc_id      = var.vpc_id
  lifecycle {
    create_before_destroy = true
  }
}
resource "aws_vpc_security_group_ingress_rule" "allow_efs_access_ingress" {
  for_each = data.aws_subnet.private_subnets
  security_group_id = aws_security_group.efs-sg.id
  cidr_ipv4         = each.value.cidr_block
  from_port         = 2049
  ip_protocol       = "tcp"
  to_port           = 2049
}

resource "aws_vpc_security_group_egress_rule" "allow_efs_access_egress" {
  security_group_id = aws_security_group.efs-sg.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

resource "aws_efs_file_system" "jupyterhub-efs-fs" {
  creation_token = "${var.cluster_name_prefix}-jupyterhub-users-efs"
  encrypted      = false
}

resource "aws_efs_mount_target" "mount" {
    for_each        = toset(var.private_subnets)
    file_system_id  = aws_efs_file_system.jupyterhub-efs-fs.id
    subnet_id       = each.key
    security_groups = [aws_security_group.efs-sg.id]
}

resource "kubernetes_storage_class_v1" "efs_sc" {
  metadata {
    name = "efs-sc"
  }
  storage_provisioner = "efs.csi.aws.com"
  parameters = {
   provisioningMode = "efs-ap"
   fileSystemId = "${aws_efs_file_system.jupyterhub-efs-fs.id}"
   directoryPerms = "777"
  }
  reclaim_policy      = "Retain"
}

resource "kubernetes_persistent_volume_claim_v1" "efs-user-pvc" {
  metadata {
    name = "${var.cluster_name_prefix}-jupyterhub-users-efs-pvc"
    namespace = "jupyter"
  }
  spec {
    access_modes = ["ReadWriteMany"]
    storage_class_name = ""
    resources {
      requests = {
        storage = "5Gi"
      }
    }
    volume_name = "${kubernetes_persistent_volume_v1.efs-user-pv.metadata.0.name}"
  }
}
resource "kubernetes_persistent_volume_v1" "efs-user-pv" {
    metadata {
      name = "${var.cluster_name_prefix}-jupyterhub-users-efs-pv"
    }
    spec {
        access_modes = ["ReadWriteMany"]
        capacity = {
            storage = "50Gi"
        }
        persistent_volume_source {
            nfs {
                path = "/"
                server = "${aws_efs_file_system.jupyterhub-efs-fs.id}.efs.us-east-1.amazonaws.com"
            }

        }
    }
}
