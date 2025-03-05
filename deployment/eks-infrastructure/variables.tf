########
# vars #
########
variable "cluster_name_prefix" {
  description = "short cluster name to be used in defining resources as prefix"
  type = string
}

variable "environment" {
  description = "The environment we are deploying"
  type        = string
  nullable    = false
}

variable "vpc_id" {
  description = "The CMS-provided VPC ID"
  type        = string
  nullable    = false
}

variable "private_subnets" {
  description = "The private subnets"
  type        = list(any)
  nullable    = false
}

variable "iam_path" {
  description = "The AWS policy path for provisioned IAM roles"
  type        = string
  default     = "/delegatedadmin/developer/"
}

variable "iam_permissions_boundary" {
  description = "The permissions limit for this infra"
  type        = string
  nullable    = false
}

variable "eks_instance_type_non_gpu" {
  description = "The instance size and type for non-GPU operations"
  type        = string
  default     = "t3.small"
}

variable "eks_instance_type_gpu" {
  description = "The instance size and type for GPU operations"
  type        = string
  default     = "t3.small"
}

variable "ebs_device_name_non_gpu" {
  description = "The mount path"
  type        = string
  default     = "/dev/xvda"
}

variable "ebs_volume_size_non_gpu" {
  description = "How big should our volumes be"
  type        = number
  default     = 100
}

variable "ebs_device_name_gpu" {
  description = "The mount path"
  type        = string
  default     = "/dev/xvda"
}

variable "ebs_volume_size_gpu" {
  description = "How big should our volumes be"
  type        = number
  default     = 100
}

variable "ami_name" {
  description = "AMI name to lookup for deployments"
  type        = string
  default     = "amzn2-eks-1.31-gi-2024-11-13T12-28-18Z"
}

variable "eks_jupyter_group_instance_type" {
  description = "The instance size and type for Jupyter GPU operations"
  type        = string
  default     = "g4dn.2xlarge"
}

variable "eks_jupyter_scaling_desired_size" {
  description = "How many nodes do you want to be active for Jupyter"
  type        = number
  default     = 3
}

variable "eks_jupyter_scaling_min_size" {
  description = "The minimum nodes do you want to be active for Jupyter"
  type        = number
  default     = 1
}

variable "eks_jupyter_scaling_max_size" {
  description = "The maximum nodes do you want to be active for Jupyter"
  type        = number
  default     = 12
}
variable "repository_names" {
  description = "Name of ecr repositories to create for ai workspace"
  type = list(string)
  default = ["ai-workspace","ai-workspace-codeserver"]
}
variable "project_name" {
  description = "short name of project used in rendering project application admin role"
  type = string
  default = "kmp"
}

variable "zone_name" {
  type = string
}