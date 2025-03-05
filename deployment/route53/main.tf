###########
# route53 #
###########

resource "aws_route53_zone" "ai_workspace_zone" {
  name = var.zone_name
  force_destroy = true
  vpc {
    vpc_id = var.vpc_id
  }
  lifecycle {
    ignore_changes = [ 
        vpc
     ]
    prevent_destroy = true
  }
}