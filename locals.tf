locals {
  name_suffix = regex("^[a-z0-9\\-]{0,10}", lower(var.name_suffix))

  tags = merge(
    var.additional_tags,
    var.required_tags,
    {
      provisioner        = "terraform"
      provisioner-module = "terraform-aws-alb"
      creation-time      = time_static.main.rfc3339
    }
  )

  name_base = join(
    "-",
    compact(
      [
        local.tags.application,
        local.tags.environment,
        replace(local.tags.region, "-", ""),
        local.name_suffix,
        "alb"
      ]
    )
  )

  logging_target_prefix = join(
    "/",
    compact(
      [
        data.aws_caller_identity.current.account_id,
        local.tags.application,
        local.tags.environment,
        local.tags.region,
        local.name_suffix,
      ]
    )
  )

  logging = {
    enabled = lookup(var.logging, "enabled", false)
    bucket  = lookup(var.logging, "bucket", "palig-2148-prod-logging-elb-access-logs")
    prefix  = lookup(var.logging, "prefix", local.logging_target_prefix)
  }

  names = {
    alb            = local.name_base
    security_group = "${local.name_base}-sg"
  }

  # ----------------------------------------------------------------------------
  # Build Standard Listener objects
  # ----------------------------------------------------------------------------
  standard_listeners = merge(
    var.standard_listeners.http_redirect.enabled ? {
      http_redirect = {
        certificate_arn = null
        port            = "80"
        protocol        = "HTTP"
        ssl_policy      = null

        default_action = {
          type         = can(var.standard_listeners.http_redirect.default_action != "") ? var.standard_listeners.http_redirect.default_action.type : "redirect"
          target_group = can(var.standard_listeners.http_redirect.default_action.target_group != "") ? var.standard_listeners.http_redirect.default_action.target_group : "default"

          configuration = {
            content_type = can(var.standard_listeners.http_redirect.default_action.configuration.content_type != "") ? var.standard_listeners.http_redirect.default_action.configuration.content_type : "text/plain"
            message_body = can(var.standard_listeners.http_redirect.default_action.configuration.message_body != "") ? var.standard_listeners.http_redirect.default_action.configuration.message_body : "Access Denied"
            status_code  = can(var.standard_listeners.http_redirect.default_action.configuration.status_code != "") ? var.standard_listeners.http_redirect.default_action.configuration.status_code : "HTTP_301"
            port         = can(var.standard_listeners.http_redirect.default_action.configuration.port != "") ? var.standard_listeners.http_redirect.default_action.configuration.port : 443
            protocol     = can(var.standard_listeners.http_redirect.default_action.configuration.protocol != "") ? var.standard_listeners.http_redirect.default_action.configuration.protocol : "HTTPS"
          }
        }

      }
    } : {},
    var.standard_listeners.https.enabled ? {
      https = {
        certificate_arn             = var.standard_listeners.https.enabled ? var.standard_listeners.https.certificate_arn : null
        additional_certificate_arns = lookup(var.standard_listeners.https, "additional_certificate_arns", {})
        port                        = "443"
        protocol                    = "HTTPS"
        ssl_policy                  = lookup(var.standard_listeners.https, "ssl_policy", "ELBSecurityPolicy-2016-08")

        default_action = {
          type         = can(var.standard_listeners.https.default_action != "") ? var.standard_listeners.https.default_action.type : "fixed-response"
          target_group = can(var.standard_listeners.https.default_action.target_group != "") ? var.standard_listeners.https.default_action.target_group : "default"

          configuration = {
            content_type = can(var.standard_listeners.https.default_action.configuration.content_type != "") ? var.standard_listeners.https.default_action.configuration.content_type : "text/plain"
            message_body = can(var.standard_listeners.https.default_action.configuration.message_body != "") ? var.standard_listeners.https.default_action.configuration.message_body : "Access Denied"
            status_code  = can(var.standard_listeners.https.default_action.configuration.status_code != "") ? var.standard_listeners.https.default_action.configuration.status_code : "403"
            port         = can(var.standard_listeners.https.default_action.configuration.port != "") ? var.standard_listeners.https.default_action.configuration.port : 443
            protocol     = can(var.standard_listeners.https.default_action.configuration.protocol != "") ? var.standard_listeners.https.default_action.configuration.protocol : "HTTPS"
          }
        }
      }
    } : {}
  )

  custom_listeners = {
    for listener in var.custom_listeners : "${listener.protocol}-${listener.port}" => {
      port                        = lookup(listener, "port", null)
      priority = lookup(listener_rule, "priority", 1)
      protocol                    = lookup(listener, "protocol", null)
      certificate_arn             = lookup(listener, "certificate_arn", null)
      ssl_policy                  = lookup(listener, "protocol", null) == "HTTPS" ? lookup(listener, "ssl_policy", "ELBSecurityPolicy-2016-08") : null
      additional_certificate_arns = lookup(listener, "additional_certificate_arns", null)

#      actions = {}

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
    } if listener_rule.default_action != {}
  }

  target_groups = length(var.target_groups) == 0 ? {
    default = {
      custom_name                   = null
      deregistration_delay          = 300
      load_balancing_algorithm_type = "round_robin"
      port                          = 80
      protocol_version              = null
      protocol                      = "HTTP"
      proxy_protocol_v2             = false
      slow_start                    = 0
      target_type                   = "instance"
      vpc_id                        = var.vpc_id
      health_check                  = {}
      stickiness                    = {}
    }
    } : {
    for group_name, target_group in var.target_groups : group_name => {
      custom_name                   = lookup(target_group, "custom_name", null)
      deregistration_delay          = lookup(target_group, "deregistration_delay", 300)
      load_balancing_algorithm_type = lookup(target_group, "load_balancing_algorithm_type", "round_robin")
      port                          = lookup(target_group, "port", 80)
      protocol_version              = lookup(target_group, "protocol_version", null)
      protocol                      = lookup(target_group, "protocol", "HTTP")
      proxy_protocol_v2             = lookup(target_group, "proxy_protocol_v2", false)
      slow_start                    = lookup(target_group, "slow_start", 0)
      target_type                   = lookup(target_group, "target_type", "instance")
      vpc_id                        = var.vpc_id
      health_check                  = lookup(target_group, "health_check", {})
      stickiness                    = lookup(target_group, "stickiness", {})
    }
  }

  # ----------------------------------------------------------------------------
  # Security Group Rules
  # ----------------------------------------------------------------------------
  security_group_rules = {
    ingress = {
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      description = ""
      cidr_blocks = ["0.0.0.0/0"]
    }

    egress = {
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      description = ""
      cidr_blocks = ["0.0.0.0/0"]
    }
  }
}
