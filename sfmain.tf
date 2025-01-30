resource "aws_launch_template" "spot_instance_template" {
  name          = "spot-instance-template"
  image_id      = var.ami_id
  instance_type = var.instance_type
  key_name      = var.key_name
}

resource "aws_autoscaling_group" "spot_asg" {
  desired_capacity = var.asg_desired_capacity
  min_size         = var.asg_min_size
  max_size         = var.asg_max_size
  vpc_zone_identifier = [var.subnet_id]

  launch_template {
    id      = aws_launch_template.spot_instance_template.id
    version = "$Latest"
  }
}

