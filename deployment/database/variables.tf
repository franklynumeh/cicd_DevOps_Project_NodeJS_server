########
# vars #
########
variable "cluster_name_prefix" {
  description = "short cluster name to be used in defining resources as prefix"
  type = string
  default = "devon-test"
}

variable "vpc_id" {
  description = "The CMS-provided VPC ID"
  type        = string
  nullable    = false
  default = "vpc-0eb7997e98dcf2a2a"
}

variable "private_subnets" {
  description = "The private subnets"
  type        = list(any)
  nullable    = false
}

variable "db_subnets" {
  description = "The db subnets"
  type        = list(any)
  nullable    = false
}