##########
# locals #
##########
locals {
  database_string = "postgresql://${data.aws_rds_cluster.database.master_username}:${data.aws_secretsmanager_secret_version.master_password_secret_value.secret_string}@${data.aws_rds_cluster.database.endpoint}:5432/jupyterhub"
}

################################
# stage - k8s secrets for helm #
################################
resource "kubernetes_secret_v1" "tls-secret" {
  metadata {
    name = "jupyterhub-tls"
    namespace = "jupyter"
  }

  data = {
    "tls.crt" = data.aws_secretsmanager_secret_version.tls_cert_secret_value.secret_string
    "tls.key" = sensitive(data.aws_secretsmanager_secret_version.tls_private_key_secret_value.secret_string)
  }

  type = "kubernetes.io/tls"
}

########################
# stage - helm release #
########################
resource "helm_release" "jupyterhub_helm_deployment" {
  depends_on = [ 
    kubernetes_secret_v1.tls-secret 
  ]
  name             = "jupyterhub"
  repository       = "https://hub.jupyter.org/helm-chart"
  chart            = "jupyterhub"
  namespace        = "jupyter"
  create_namespace = false
  timeout          = 300
  #cleanup_on_fail = true
  values = [
    "${templatefile(
        "files/values.yaml",
        {
            "database_string" = local.database_string
            "pvc_name_string" = "${var.cluster_name_prefix}-jupyterhub-users-efs-pvc"
            //"ldap_password" = data.aws_secretsmanager_secret_version.ldap_bind_user_secret_value.secret_string
            //"ldap_bind_user" = var.ldap_bind_user
            "server_address" = var.ldap_server_address
            "server_port" = var.ldap_server_port
            "load_balancer_name" = "${var.cluster_name_prefix}-jupyterhub-alb"
            "hosts" = "${var.zone_name}"
            "artifactory_user" = "${data.aws_secretsmanager_secret_version.artifactory_user_secret_value.secret_string}"
            "artifactory_password" = "${data.aws_secretsmanager_secret_version.artifactory_password_secret_value.secret_string}"
            "ui_image" = "artifactory.cloud.cms.gov/docker/jupyterhub-ui:latest"  

        }
    )}"
  ]
  recreate_pods = true
}
##########
# 
##########

resource "aws_route53_record" "ai_workspace_lb_dns_record" {
  depends_on = [ 
    helm_release.jupyterhub_helm_deployment 
  ]
  zone_id = data.aws_route53_zone.ai_workspace_zone.zone_id
  name    = ""
  type    = "A"

  alias {
    name                   = data.aws_lb.jupyterhub-alb.dns_name
    zone_id                = data.aws_lb.jupyterhub-alb.zone_id
    evaluate_target_health = true
  }
}
