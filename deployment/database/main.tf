###############
# rds - stage #
###############
resource "aws_secretsmanager_secret" "master_password_secret" {
  name = "${var.cluster_name_prefix}-db-master-password"
  recovery_window_in_days = "0"
}

resource "aws_secretsmanager_secret_version" "master_password_secret_value" {
  secret_id     = aws_secretsmanager_secret.master_password_secret.id
  secret_string = data.aws_secretsmanager_random_password.master_password.random_password
  lifecycle {
    ignore_changes = [
      secret_string, 
    ]
  }
}

resource "aws_db_subnet_group" "db_subnets" {
  name       = "jupyterhub-db"
  subnet_ids = var.db_subnets
}

resource "aws_rds_cluster" "jupyterhub-postgresql" {
  cluster_identifier      = "${var.cluster_name_prefix}-jupyterhub-db"
  engine                  = "aurora-postgresql"
  availability_zones      = ["us-east-1a","us-east-1b","us-east-1c"]
  database_name           = "jupyterhub"
  master_username         = "jupyterhubdb"
  master_password         = aws_secretsmanager_secret_version.master_password_secret_value.secret_string
  db_subnet_group_name = aws_db_subnet_group.db_subnets.name
  skip_final_snapshot = true
  backup_retention_period = 1
  vpc_security_group_ids = [aws_security_group.postgres_database_security_group.id]
}
resource "aws_rds_cluster_instance" "jupyterhubdb_cluster_instances" {
  count              = 1
  identifier         = "jupyterhubdb-cl-${count.index}"
  cluster_identifier = aws_rds_cluster.jupyterhub-postgresql.id
  instance_class     = "db.t3.large"
  engine             = aws_rds_cluster.jupyterhub-postgresql.engine
  engine_version     = aws_rds_cluster.jupyterhub-postgresql.engine_version_actual
}

resource "aws_security_group" "postgres_database_security_group" {
  name_prefix = "${var.cluster_name_prefix}-jupyterhub-db-sg"
  description = "Security group for ${var.cluster_name_prefix}-jupyterhub-db"
  vpc_id      = var.vpc_id
  lifecycle {
    create_before_destroy = true
  }
}
resource "aws_vpc_security_group_ingress_rule" "allow_db_access" {
  for_each = data.aws_subnet.private_subnets
  security_group_id = aws_security_group.postgres_database_security_group.id
  cidr_ipv4         = each.value.cidr_block
  from_port         = 5432
  ip_protocol       = "tcp"
  to_port           = 5432
}

resource "aws_vpc_security_group_egress_rule" "allow_all_traffic_ipv4" {
  security_group_id = aws_security_group.postgres_database_security_group.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}
