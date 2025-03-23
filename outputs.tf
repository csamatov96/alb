output "lb" {
  description = "Attributes of the ALB"
  value = {
    arn      = aws_lb.main.arn
    id       = aws_lb.main.id
    dns_name = aws_lb.main.dns_name
    tags     = aws_lb.main.tags_all
  }
}

output "lb_target_group" {
  description = "Attributes of the ALB target group"
  value = {
    for name, group in local.target_groups : name => {
      arn  = aws_lb_target_group.main[name].arn
      id   = aws_lb_target_group.main[name].id
      name = aws_lb_target_group.main[name].name
      tags = aws_lb_target_group.main[name].tags_all
    }
  }
}

output "security_group" {
  description = "Attributes of the ALB Security Group (if created)"
  value = {
    arn  = length(var.security_groups) == 0 ? aws_security_group.main["enabled"].arn : ""
    id   = length(var.security_groups) == 0 ? aws_security_group.main["enabled"].id : ""
    tags = length(var.security_groups) == 0 ? aws_security_group.main["enabled"].tags_all : {}
  }
}
