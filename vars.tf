variable "name_suffix" {
  description = "A name to append to the end of all resources."
  type        = string
  default     = ""
}

variable "additional_tags" {
  description = "A map of tags to be assigned to the resources. These will be overwritten if they conflict with required tags."
  type        = map(string)
  default     = {}
}

variable "required_tags" {
  description = "A map of tags that are required for all resources."
  type = object({
    application      = string
    environment      = string
    organization     = string
    provisioner-file = string
    region           = string
  })
}

variable "vpc_id" {
  description = "The VPC to create a Security Group in. Also used as default VPC for target group if not specified in target_group object."
  type        = string
  default     = null
}

variable "logging" {
  description = "Configure logging for the S3 bucket."
  type        = map(string)
  default     = {}
}

variable "internal" {
  description = "If true, the LB will be internal."
  type        = bool
  default     = false
}

variable "security_groups" {
  description = "A list of existing security groups to assign to the load balancer. When not defined, a security group will be created."
  type        = list(string)
  default     = []
}

variable "target_groups" {
  description = "A list of named target_group objects."
  type        = any
  default     = {}
}

variable "drop_invalid_header_fields" {
  description = ""
  type        = bool
  default     = false
}

variable "subnets" {
  description = ""
  type        = list(string)
  default     = []
}

variable "idle_timeout" {
  description = ""
  type        = number
  default     = 60
}

variable "enable_deletion_protection" {
  description = ""
  type        = bool
  default     = false
}

variable "enable_http2" {
  description = ""
  type        = bool
  default     = true
}

variable "customer_owned_ipv4_pool" {
  description = ""
  type        = string
  default     = null
}

variable "ip_address_type" {
  description = ""
  type        = string
  default     = "ipv4"
}

variable "target_group_members" {
  description = "A map of named target_group_member objects."
  type        = any
  default     = {}
}

variable "standard_listeners" {
  description = "Enable standard listener configurations."
  type        = any
  default     = {}
}

variable "custom_listeners" {
  description = "A list of `listener` objects."
  type        = any
  default     = []
}

variable "enable_waf_integration" {
  description = "Enable WAF integration. This will create an association between the WAF and the ALB. When true, var.web_acl_id is required."
  type        = bool
  default     = false
}

variable "web_acl_id" {
  description = "If you're using AWS WAF to ALB, the Id of the AWS WAF web ACL that is associated with the ALB. The WAF Web ACL must exist in the WAF Global (ALB) region and the credentials configuring this argument must have waf:GetWebACL permissions assigned. If using WAFv2, provide the ARN of the web ACL."
  type        = string
  default     = null
}

variable "https_listener_rules" {
  description = "A list of maps describing the Listener Rules for this ALB. Required key/values: actions, conditions. Optional key/values: priority, https_listener_index (default to https_listeners[count.index])"
  type        = any
  default     = []
}

variable "desync_mitigation_mode" {
  description = "HTTP desync mode"
  type        = string
  default     = "defensive"
}
