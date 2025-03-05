#############
# variables #
#############

variable "cluster_name_prefix" {
  description = "short cluster name to be used in defining resources as prefix"
  type = string
  default = "devon-test"
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