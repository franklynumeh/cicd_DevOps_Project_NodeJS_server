#############
# variables #
#############

variable "cluster_name_prefix" {
  description = "short cluster name to be used in defining resources as prefix"
  type = string
}

#variable "ldap_bind_user" {
#  description = "bind user dn value"
#  type = string
#}

variable "ldap_server_port" {
  type = number
}

variable "ldap_server_address" {
  type = string
}
variable "zone_name" {
  type = string
}

variable "jupyter-cert-secret-path" {
  type = string
}

variable "jupyter-cert-key-secret-path" {
  type = string
}

variable "jupyter-artifactory-secret-path-password" {
  type = string
}

variable "jupyter-artifactory-secret-path-user" {
  type = string
}