variable "ami_id" {
  description = "The AMI ID for the EC2 Spot Instances"
  type        = string
}

variable "instance_type" {
  description = "Instance type for Spot Instances"
  type        = string
  default     = "t3.micro"
}

variable "key_name" {
  description = "The SSH key pair name"
  type        = string
}

variable "subnet_id" {
  description = "The subnet ID where Spot Instances will be launched"
  type        = string
}

variable "asg_min_size" {
  description = "Minimum number of Spot Instances in the Auto Scaling Group"
  type        = number
  default     = 1
}

variable "asg_max_size" {
  description = "Maximum number of Spot Instances in the Auto Scaling Group"
  type        = number
  default     = 5
}

variable "asg_desired_capacity" {
  description = "Desired number of Spot Instances"
  type        = number
  default     = 2
}