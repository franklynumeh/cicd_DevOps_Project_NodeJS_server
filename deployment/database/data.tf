########
# data #
########
data "aws_subnet" "private_subnets" {
  for_each = toset(var.private_subnets)
  id = each.value
}

data "aws_secretsmanager_random_password" "master_password" {
  password_length = 8
  exclude_numbers = false
  exclude_punctuation = true
  include_space = false
}