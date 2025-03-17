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


variable "create" {
  description = "Controls if resources should be created."
  type        = bool
  default     = false
}

variable "ca_certificates_bundle_s3_key" {
  description = "The S3 key where the CA certificates bundle is stored."
  type        = string
}

variable "ca_certificates_bundle_s3_bucket" {
  description = "The S3 bucket where the CA certificates bundle is stored."
  type        = string
}

resource "aws_lb_trust_store" "this" {
  count = var.create ? 1 : 0

  ca_certificates_bundle_s3_bucket = var.ca_certificates_bundle_s3_bucket
  ca_certificates_bundle_s3_key    = var.ca_certificates_bundle_s3_key
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

  mutual_authentication {
    mode = var.mode
    #    trust_store_arn = aws_lb_trust_store.this[0].arn
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




#############################################################################################
locals {
  custom_listeners = {
    for listener in var.custom_listeners : "${listener.protocol}-${listener.port}" => {
      port                        = lookup(listener, "port", null)
      protocol                    = lookup(listener, "protocol", null)
      certificate_arn             = lookup(listener, "certificate_arn", null)
      ssl_policy                  = lookup(listener, "protocol", null) == "HTTPS" ? lookup(listener, "ssl_policy", "ELBSecurityPolicy-2016-08") : null
      additional_certificate_arns = lookup(listener, "additional_certificate_arns", null)

      actions = {}

      default_action = {
        type = listener.default_action.type

        configuration = {
          target_group = listener.default_action.type == "forward" ? listener.default_action.target_group_key : null
          status_code  = listener.default_action.type == "redirect" ? listener.default_action.configuration.status_code : null
          host         = listener.default_action.type == "redirect" ? lookup(listener.default_action.configuration, "host", "#{host}") : null
          path         = listener.default_action.type == "redirect" ? lookup(listener.default_action.configuration, "path", "/#{path}") : null
          port         = listener.default_action.type == "redirect" ? lookup(listener.default_action.configuration, "port", "#{port}") : null
          protocol     = listener.default_action.type == "redirect" ? lookup(listener.default_action.configuration, "protocol", "#{protocol}") : null
          query        = listener.default_action.type == "redirect" ? lookup(listener.default_action.configuration, "query", "#{query}") : null

        }
      }

      conditions = listener.conditions
    }
  }

  # Get all of the additional certificates defined within the listeners and
  # create a list with the information needed for the certificate resource.
  additional_certificates = flatten([
    for listener_name, listener_rule in local.custom_listeners : [
      for cert_name, cert_arn in listener_rule.additional_certificate_arns : {
        listener_name = listener_name
        cert_name     = cert_name
        cert_arn      = cert_arn
      }
    ] if contains(keys(listener_rule), "additional_certificate_arns") && listener_rule.additional_certificate_arns != null
  ])

  # Convert the list of additional certificates into a named map for the
  # for_each statement to work with named instances.
  additional_certificates_map = {
    for values in local.additional_certificates : "${values.listener_name}_${values.cert_name}" => {
      certificate_arn = values.cert_arn
      listener_name   = values.listener_name
    }
  }

  custom_listener_rules = {
    for listener_name, listener_rule in local.custom_listeners : listener_name => {
      priority = lookup(listener_rule, "priority", 1)

      action = {
        type = listener_rule.default_action.type

        configuration = {
          target_group = listener_rule.default_action.type == "forward" ? listener_rule.default_action.configuration.target_group : null
        }
      }

      conditions = listener_rule.conditions
    } if listener_rule.actions != {}
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



