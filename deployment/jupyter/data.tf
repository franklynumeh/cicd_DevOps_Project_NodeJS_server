################
# data sources #
################
data "aws_eks_cluster" "cluster" {
  name = var.cluster_name_prefix
}

data "aws_eks_cluster_auth" "k8s_auth" {
  name = data.aws_eks_cluster.cluster.name
}

data "aws_rds_cluster" "database" {
    cluster_identifier = "${var.cluster_name_prefix}-jupyterhub-db"
}

data "aws_secretsmanager_secret" "master_password_secret" {
  name = "${var.cluster_name_prefix}-db-master-password"
}

data "aws_secretsmanager_secret_version" "master_password_secret_value" {
  secret_id = data.aws_secretsmanager_secret.master_password_secret.id
}

# tls certificate
data "aws_secretsmanager_secret" "tls_cert_secret" {
  name = "${var.jupyter-cert-secret-path}"
}

data "aws_secretsmanager_secret_version" "tls_cert_secret_value" {
  secret_id = data.aws_secretsmanager_secret.tls_cert_secret.id
}

# tls private key
data "aws_secretsmanager_secret" "tls_private_key_secret" {
  name = "${var.jupyter-cert-key-secret-path}"
}

data "aws_secretsmanager_secret_version" "tls_private_key_secret_value" {
  secret_id = data.aws_secretsmanager_secret.tls_private_key_secret.id
}

# artifactory credentials
data "aws_secretsmanager_secret" "artifactory_user_secret" {
  name = "${var.jupyter-artifactory-secret-path-user}"
}

data "aws_secretsmanager_secret_version" "artifactory_user_secret_value" {
  secret_id = data.aws_secretsmanager_secret.artifactory_user_secret.id
}

data "aws_secretsmanager_secret" "artifactory_password_secret" {
  name = "${var.jupyter-artifactory-secret-path-password}"
}

data "aws_secretsmanager_secret_version" "artifactory_password_secret_value" {
  secret_id = data.aws_secretsmanager_secret.artifactory_password_secret.id
}


/*
data "aws_secretsmanager_secret" "ldap_bind_user_secret" {
  name = "${var.cluster_name_prefix}-ldap-bind-user-secret"
}

data "aws_secretsmanager_secret_version" "ldap_bind_user_secret_value" {
  secret_id = data.aws_secretsmanager_secret.ldap_bind_user_secret.id
}
*/

data "aws_route53_zone" "ai_workspace_zone" {
  name         = "${var.zone_name}."
  private_zone = true
}

data "aws_lb" "jupyterhub-alb" {
  depends_on = [ 
    helm_release.jupyterhub_helm_deployment 
  ]
  name = "${var.cluster_name_prefix}-jupyterhub-alb"
}

