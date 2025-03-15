resource "time_static" "main" {}

# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb
resource "aws_lb" "main" {
  name                       = local.names.alb
  internal                   = var.internal
  load_balancer_type         = "application"
  security_groups            = length(var.security_groups) == 0 ? [aws_security_group.main["enabled"].id] : var.security_groups
  drop_invalid_header_fields = var.drop_invalid_header_fields
  subnets                    = var.subnets
  idle_timeout               = var.idle_timeout
  enable_deletion_protection = var.enable_deletion_protection
  enable_http2               = var.enable_http2
  customer_owned_ipv4_pool   = var.customer_owned_ipv4_pool
  ip_address_type            = var.ip_address_type
  tags                       = merge(local.tags, { Name = local.names.alb })
  desync_mitigation_mode     = var.desync_mitigation_mode

  dynamic "access_logs" {
    for_each = local.logging.enabled ? { enabled = local.logging } : {}

    content {
      bucket  = access_logs.value.bucket
      prefix  = access_logs.value.prefix
      enabled = access_logs.value.enabled
    }
  }

}

# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_target_group
resource "aws_lb_target_group" "main" {
  for_each = local.target_groups

  name                          = lookup(each.value, "custom_name", null) == null ? null : each.value.custom_name
  deregistration_delay          = each.value.deregistration_delay
  load_balancing_algorithm_type = each.value.load_balancing_algorithm_type
  port                          = each.value.port
  protocol_version              = each.value.protocol_version
  protocol                      = each.value.protocol
  proxy_protocol_v2             = each.value.proxy_protocol_v2
  slow_start                    = each.value.slow_start
  target_type                   = each.value.target_type
  vpc_id                        = each.value.vpc_id
  tags                          = merge(local.tags, { Name = join("-", [local.name_base, each.key, "tg"]) })

  lifecycle {
    create_before_destroy = true
  }

  dynamic "health_check" {
    for_each = { enabled = lookup(each.value, "health_check", {}) }

    content {
      enabled             = lookup(health_check.value, "enabled", true)
      healthy_threshold   = lookup(health_check.value, "healthy_threshold", 3)
      interval            = lookup(health_check.value, "interval", 30)
      matcher             = lookup(health_check.value, "matcher", "200-399")
      path                = lookup(health_check.value, "path", "/")
      port                = lookup(health_check.value, "port", 80)
      protocol            = lookup(health_check.value, "protocol", "HTTP")
      timeout             = lookup(health_check.value, "timeout", 6)
      unhealthy_threshold = lookup(health_check.value, "unhealthy_threshold", 3)
    }
  }

  dynamic "stickiness" {
    for_each = { enabled = lookup(each.value, "stickiness", {}) }

    content {
      enabled         = lookup(stickiness.value, "enabled", false)
      cookie_duration = lookup(stickiness.value, "cookie_duration", 86400)
      type            = lookup(stickiness.value, "type", "lb_cookie")
    }
  }

}

# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_target_group_attachment
resource "aws_lb_target_group_attachment" "main" {
  for_each = var.target_group_members

  target_group_arn = aws_lb_target_group.main[each.value.target_group_key].arn
  target_id        = each.value.target_id
  port             = lookup(each.value, "port", aws_lb_target_group.main[each.value.target_group_key].port)
}

# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_listener
resource "aws_lb_listener" "standard_listeners" {
  for_each = local.standard_listeners

  load_balancer_arn = aws_lb.main.arn
  port              = each.value.port
  protocol          = each.value.protocol
  certificate_arn   = each.value.certificate_arn
  ssl_policy        = each.value.ssl_policy
  tags              = merge(local.tags, { Name = "${local.name_base}-${each.key}-lsr" })

  default_action {
    type = each.value.default_action.type

    # "forward" default action
    target_group_arn = each.value.default_action.type == "forward" ? aws_lb_target_group.main[each.value.default_action.target_group].arn : null

    # "fixed-response" default action
    dynamic "fixed_response" {
      for_each = each.value.default_action.type == "fixed-response" ? { enabled = each.value.default_action.configuration } : {}

      content {
        content_type = lookup(fixed_response.value, "content_type", "text/plain")
        message_body = lookup(fixed_response.value, "message_body", "Access Denied")
        status_code  = lookup(fixed_response.value, "status_code", "403")
      }
    }

    # "redirect" default action
    dynamic "redirect" {
      for_each = each.value.default_action.type == "redirect" ? { enabled = each.value.default_action.configuration } : {}

      content {
        port        = lookup(redirect.value, "port", null)
        protocol    = lookup(redirect.value, "protocol", null)
        status_code = lookup(redirect.value, "status_code", null)
      }

    }
  }
}

# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_listener_rule
resource "aws_lb_listener_rule" "standard_listeners" {
  count = var.standard_listeners.https.enabled ? length(var.https_listener_rules) : 0

  listener_arn = aws_lb_listener.standard_listeners["https"].arn
  priority     = lookup(var.https_listener_rules[count.index], "priority", null)
  tags         = merge(local.tags, { Name = "${local.name_base}-${lookup(var.https_listener_rules[count.index], "https_listener_index", count.index)}-https-lsr-rule" })

  /*

  for_each = local.standard_listener_rules

  listener_arn = aws_lb_listener.standard_listeners[each.key].arn
  priority     = each.value.priority
  tags         = merge(local.tags, { Name = "${local.name_base}-${each.key}-lsr-rule" })


  action {
    type             = each.value.action.type
    target_group_arn = each.value.action.type == "forward" ? aws_lb_target_group.main[each.value.action.target_group].arn : null
  }

  condition {
    http_header {
      http_header_name = each.value.conditions.http_headers.http_header_name
      values           = each.value.conditions.http_headers.values
    }
  }
*/

  # copied from https://github.com/terraform-aws-modules/terraform-aws-alb/blob/v6.8.0/main.tf#L15353

  # redirect actions
  dynamic "action" {
    for_each = [
      for action_rule in var.https_listener_rules[count.index].actions :
      action_rule
      if action_rule.type == "redirect"
    ]

    content {
      type = action.value["type"]
      redirect {
        host        = lookup(action.value, "host", null)
        path        = lookup(action.value, "path", null)
        port        = lookup(action.value, "port", null)
        protocol    = lookup(action.value, "protocol", null)
        query       = lookup(action.value, "query", null)
        status_code = action.value["status_code"]
      }
    }
  }

  # fixed-response actions
  dynamic "action" {
    for_each = [
      for action_rule in var.https_listener_rules[count.index].actions :
      action_rule
      if action_rule.type == "fixed-response"
    ]

    content {
      type = action.value["type"]
      fixed_response {
        message_body = lookup(action.value, "message_body", null)
        status_code  = lookup(action.value, "status_code", null)
        content_type = action.value["content_type"]
      }
    }
  }

  # forward actions
  dynamic "action" {
    for_each = [
      for action_rule in var.https_listener_rules[count.index].actions :
      action_rule
      if action_rule.type == "forward"
    ]

    content {
      type             = action.value["type"]
      target_group_arn = aws_lb_target_group.main[lookup(action.value, "target_group", "default")].arn
    }
  }

  # weighted forward actions
  dynamic "action" {
    for_each = [
      for action_rule in var.https_listener_rules[count.index].actions :
      action_rule
      if action_rule.type == "weighted-forward"
    ]

    content {
      type = "forward"
      forward {
        dynamic "target_group" {
          for_each = action.value["target_groups"]

          content {
            arn    = aws_lb_target_group.main[target_group.value["target_group_index"]].id
            weight = target_group.value["weight"]
          }
        }
        dynamic "stickiness" {
          for_each = [lookup(action.value, "stickiness", {})]

          content {
            enabled  = try(stickiness.value["enabled"], false)
            duration = try(stickiness.value["duration"], 1)
          }
        }
      }
    }
  }

  # Path Pattern condition
  dynamic "condition" {
    for_each = [
      for condition_rule in var.https_listener_rules[count.index].conditions :
      condition_rule
      if length(lookup(condition_rule, "path_patterns", [])) > 0
    ]

    content {
      path_pattern {
        values = condition.value["path_patterns"]
      }
    }
  }

  # Host header condition
  dynamic "condition" {
    for_each = [
      for condition_rule in var.https_listener_rules[count.index].conditions :
      condition_rule
      if length(lookup(condition_rule, "host_headers", [])) > 0
    ]

    content {
      host_header {
        values = condition.value["host_headers"]
      }
    }
  }

  # Http header condition
  dynamic "condition" {
    for_each = [
      for condition_rule in var.https_listener_rules[count.index].conditions :
      condition_rule
      if length(lookup(condition_rule, "http_headers", [])) > 0
    ]

    content {
      dynamic "http_header" {
        for_each = condition.value["http_headers"]

        content {
          http_header_name = http_header.value["http_header_name"]
          values           = http_header.value["values"]
        }
      }
    }
  }

  # Http request method condition
  dynamic "condition" {
    for_each = [
      for condition_rule in var.https_listener_rules[count.index].conditions :
      condition_rule
      if length(lookup(condition_rule, "http_request_methods", [])) > 0
    ]

    content {
      http_request_method {
        values = condition.value["http_request_methods"]
      }
    }
  }

  # Query string condition
  dynamic "condition" {
    for_each = [
      for condition_rule in var.https_listener_rules[count.index].conditions :
      condition_rule
      if length(lookup(condition_rule, "query_strings", [])) > 0
    ]

    content {
      dynamic "query_string" {
        for_each = condition.value["query_strings"]

        content {
          key   = lookup(query_string.value, "key", null)
          value = query_string.value["value"]
        }
      }
    }
  }

  # Source IP address condition
  dynamic "condition" {
    for_each = [
      for condition_rule in var.https_listener_rules[count.index].conditions :
      condition_rule
      if length(lookup(condition_rule, "source_ips", [])) > 0
    ]

    content {
      source_ip {
        values = condition.value["source_ips"]
      }
    }
  }

}

# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_listener
resource "aws_lb_listener" "main" {
  for_each = local.custom_listeners

  load_balancer_arn = aws_lb.main.arn
  port              = each.value.port
  protocol          = each.value.protocol
  certificate_arn   = each.value.certificate_arn
  ssl_policy        = each.value.ssl_policy
  tags              = merge(local.tags, { Name = "${local.name_base}-${each.key}-lsr" })

  default_action {
    type = each.value.default_action.type

    dynamic "fixed_response" {
      for_each = each.value.default_action.type == "fixed-response" ? { enabled = each.value.default_action.configuration } : {}

      content {
        content_type = fixed_response.value.content_type
        status_code  = fixed_response.value.status_code
        message_body = fixed_response.value.message_body
      }
    }

    dynamic "redirect" {
      for_each = each.value.default_action.type == "redirect" ? { enabled = each.value.default_action.configuration } : {}

      content {
        host        = redirect.value.host
        path        = redirect.value.path
        port        = redirect.value.port
        protocol    = redirect.value.protocol
        status_code = redirect.value.status_code
        query       = redirect.value.query
      }
    }

    dynamic "forward" {
      for_each = each.value.default_action.type == "forward" ? { enabled = each.value.default_action.configuration } : {}

      content {
        target_group {
          arn = aws_lb_target_group.main[forward.value.target_group].arn
        }
      }
    }
  }
}

# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_listener_certificate
resource "aws_lb_listener_certificate" "standard_listeners" {
  for_each = var.standard_listeners.https.enabled ? local.standard_listeners.https.additional_certificate_arns : {}

  listener_arn    = aws_lb_listener.standard_listeners["https"].arn
  certificate_arn = each.value

  # Explicitely define the dependency to make sure all listeners are created
  # before attempting to attach more certificates.
  depends_on = [
    aws_lb_listener.standard_listeners
  ]
}

# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_listener_certificate
resource "aws_lb_listener_certificate" "main" {
  for_each = local.additional_certificates_map

  listener_arn    = aws_lb_listener.main[each.value.listener_name].arn
  certificate_arn = each.value.certificate_arn

  # Explicitely define the dependency to make sure all listeners are created
  # before attempting to attach more certificates.
  depends_on = [
    aws_lb_listener.main
  ]
}

# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_listener_rule
resource "aws_lb_listener_rule" "main" {
  for_each = local.custom_listener_rules

  listener_arn = aws_lb_listener.main[each.key].arn
  priority     = each.value.priority
  tags         = merge(local.tags, { Name = "${local.name_base}-${each.key}-lsr-rule" })

  action {
    type             = each.value.action.type
    target_group_arn = each.value.action.type == "forward" ? aws_lb_target_group.main[each.value.action.configuration.target_group].arn : null
  }

  dynamic "condition" {
    for_each = each.value.conditions

    content {
      dynamic "http_header" {
        for_each = condition.key == "http_header" ? { enabled = condition.value } : {}

        content {
          http_header_name = http_header.value.http_header_name
          values           = http_header.value.values
        }
      }
    }
  }
}

# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group
resource "aws_security_group" "main" {
  for_each = length(var.security_groups) == 0 ? { enabled = true } : {}

  name                   = local.names.security_group
  description            = "Security Group for ${local.name_base}"
  vpc_id                 = var.vpc_id
  revoke_rules_on_delete = true
  tags                   = merge(local.tags, { Name = local.names.security_group })
}

# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule
resource "aws_security_group_rule" "main" {
  for_each = length(var.security_groups) == 0 ? local.security_group_rules : {}

  type              = each.key
  security_group_id = aws_security_group.main["enabled"].id
  from_port         = each.value.from_port
  to_port           = each.value.to_port
  protocol          = each.value.protocol
  cidr_blocks       = each.value.cidr_blocks
  description       = each.value.description
}

# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl_association
resource "aws_wafv2_web_acl_association" "main" {
  for_each = var.enable_waf_integration ? { enabled = true } : {}

  resource_arn = aws_lb.main.arn
  web_acl_arn  = var.web_acl_id
}
