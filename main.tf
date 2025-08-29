terraform {
  required_version = ">= 1.5.0"
  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = ">= 3.113.0" }
    random  = { source = "hashicorp/random",  version = ">= 3.5.1" }
    local   = { source = "hashicorp/local",   version = ">= 2.4.0" }
  }
}

provider "azurerm" { 
  features {} 
  subscription_id = var.my_subscription_id
}

############################
# Variables (edit these)
############################
variable "my_subscription_id"  { default = "c30115c5-79c4-4755-a139-f5642c22d69f" } # your subscription for Grafana
variable "location"            { default = "israelcentral" }
variable "rg_name"             { default = "rg-l1-observability" }
variable "vnet_name"           { default = "vnet-l1-hub" }
variable "vnet_cidr"           { default = "10.50.0.0/16" }
variable "subnet_appint_cidr"  { default = "10.50.10.0/24" } # App Service VNet integration
variable "subnet_pe_cidr"      { default = "10.50.20.0/24" } # Private Endpoints
variable "subnet_pg_cidr"      { default = "10.50.30.0/24" } # PostgreSQL delegated subnet

variable "plan_name"           { default = "asp-grafana-p3v3" }
variable "app_name"            { default = "app-grafana-l1" }
variable "grafana_image"       { default = "grafana/grafana" }
variable "grafana_tag"         { default = "latest" }

# Postgres
variable "pg_server_name"      { default = "pg-grafana-l1" }  # must be globally unique
variable "pg_admin_user"       { default = "grafadmin" }
variable "pg_version"          { default = "16" }
variable "pg_sku_name"         { default = "GP_Standard_D2ds_v4" }

# RBAC for Grafana MI
#monitor_subscription_id → subscription ID where Grafana needs read access to metrics.
#The Terraform script assigns the Grafana MI the Monitoring Reader role at the subscription scope.
#That allows Grafana to pull metrics & resource metadata for all resources in that subscription.
variable "monitor_subscription_id" { default = "" }  # e.g. "00000000-0000-0000-0000-000000000000"

#law_resource_id → resource ID of one Log Analytics Workspace (LAW).
#The script assigns the Grafana MI the Log Analytics Reader role on that LAW.
#That allows Grafana to run KQL queries against logs in that workspace.
# e.g. /subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-monitor/providers/Microsoft.OperationalInsights/workspaces/law-prod
variable "law_resource_id"         { default = "" }  # one workspace (you can add more later)

# Azure Monitor Private Link Scope (AMPLS): link these resources (add as many as needed)
# Grafana (VNet) → AMPLS Private Endpoint → Azure Monitor (private) -> Log Analytics 
# If you have two workspaces:
# law-prod in subscription 1111...
# law-dev in subscription 2222...
# Your Terraform vars could look like:
#
# law_resource_ids = [
#  "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg-observability/providers/Microsoft.OperationalInsights/workspaces/law-prod",
#  "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-dev/providers/Microsoft.OperationalInsights/workspaces/law-dev"
# ]
variable "law_resource_ids" {
  type    = list(string)
  default = []  # e.g. ["/subscriptions/.../resourceGroups/.../providers/Microsoft.OperationalInsights/workspaces/LAW1", ...]
}
## Grafana (VNet) → AMPLS Private Endpoint → Azure Monitor (private) -> App Insights
variable "appinsights_resource_ids" {
  type    = list(string)
  default = []  # e.g. ["/subscriptions/.../resourceGroups/.../providers/microsoft.insights/components/my-ai"]
}

# Grafana provisioning: list your subscriptions/tenants to pre-create datasources
variable "datasources" {
  type = list(object({
    name            = string
    tenant_id       = string
    subscription_id = string
  }))
  default = [
    # { name = "AzureMonitor-Prod", tenant_id = "CHANGEME_TENANT", subscription_id = "CHANGEME_SUB" }
  ]
}

############################
# Resource Group & Network
############################
resource "azurerm_resource_group" "rg" {
  name     = var.rg_name
  location = var.location
}

resource "azurerm_virtual_network" "vnet" {
  name                = var.vnet_name
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  address_space       = [var.vnet_cidr]
}


# With VNet Integration, the App Service can send its outbound traffic into your hub VNet.
# App Service injects its outbound tunnel there
resource "azurerm_subnet" "s_appint" {
  name                 = "snet-appsvc-integration"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = [var.subnet_appint_cidr]

  # REQUIRED for App Service Regional VNet Integration
  delegation {
    name = "delegation-appservice"
    service_delegation {
      name = "Microsoft.Web/serverFarms"
      actions = [
        "Microsoft.Network/virtualNetworks/subnets/action",
      ]
    }
  }
}

# The Private Endpoint for Grafana Web App sits there, and its IP is what your DNS entry
# (app-grafana-l1.privatelink.azurewebsites.net) resolves to.
# Your NOC users (via VPN or peering) connect to that PE IP to open the Grafana UI.
resource "azurerm_subnet" "s_pe" {
  name                                          = "snet-private-endpoints"
  resource_group_name                           = azurerm_resource_group.rg.name
  virtual_network_name                          = azurerm_virtual_network.vnet.name
  address_prefixes                              = [var.subnet_pe_cidr]
  private_endpoint_network_policies     = "Disabled" # Private Endpoint is essentially a NIC owned by Azure’s platform so your 
                                                # policies should be disabled to allow Azure manage it
}


resource "azurerm_subnet" "s_pg" {
  name                 = "snet-postgres-delegated"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = [var.subnet_pg_cidr]
  delegation {
    name = "pg-flex-delegation"
    service_delegation {
      name    = "Microsoft.DBforPostgreSQL/flexibleServers"
      actions = [
        "Microsoft.Network/virtualNetworks/subnets/join/action",
        "Microsoft.Network/virtualNetworks/subnets/prepareNetworkPolicies/action"
      ]
    }
  }
}

############################
# Private DNS for App Service & Postgres
############################
resource "azurerm_private_dns_zone" "pdz_webapp" {
  name                = "privatelink.azurewebsites.net"
  resource_group_name = azurerm_resource_group.rg.name
}
resource "azurerm_private_dns_zone" "pdz_postgres" {
  name                = "privatelink.postgres.database.azure.com"
  resource_group_name = azurerm_resource_group.rg.name
}
resource "azurerm_private_dns_zone_virtual_network_link" "pdz_webapp_link" {
  name                  = "link-webapp"
  resource_group_name   = azurerm_resource_group.rg.name
  private_dns_zone_name = azurerm_private_dns_zone.pdz_webapp.name
  virtual_network_id    = azurerm_virtual_network.vnet.id
}
resource "azurerm_private_dns_zone_virtual_network_link" "pdz_postgres_link" {
  name                  = "link-postgres"
  resource_group_name   = azurerm_resource_group.rg.name
  private_dns_zone_name = azurerm_private_dns_zone.pdz_postgres.name
  virtual_network_id    = azurerm_virtual_network.vnet.id
}

# --- DNS Resolver Subnet (must be dedicated; /28 or larger) ---
variable "subnet_dns_in_cidr" {
  description = "CIDR for DNS Private Resolver inbound endpoint subnet"
  type        = string
  default     = "10.50.3.0/28"
}

# --- P2S VPN client pool (used for NSG rule) ---
variable "p2s_pool_cidr" {
  description = "P2S client address pool CIDR"
  type        = string
  default     = "172.16.201.0/24"
}

# Dedicated subnet for the inbound endpoint (no other resources)
resource "azurerm_subnet" "s_dns_inbound" {
  name                 = "snet-dns-inbound"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = [var.subnet_dns_in_cidr] # /28 or larger; dedicated

  # REQUIRED for Private DNS Resolver endpoints
  delegation {
    name = "dnsresolver-delegation"
    service_delegation {
      name = "Microsoft.Network/dnsResolvers"
      actions = [
        "Microsoft.Network/virtualNetworks/subnets/join/action" #,
        #Microsoft.Network/virtualNetworks/subnets/read",
      ]
    }
  }
}

# resource "azurerm_network_security_group" "nsg_dns_inbound" {
#   name                = "nsg-dns-inbound"
#   location            = azurerm_resource_group.rg.location
#   resource_group_name = azurerm_resource_group.rg.name

#   security_rule {
#     name                       = "Allow-DNS-UDP-from-P2S"
#     priority                   = 100
#     direction                  = "Inbound"
#     access                     = "Allow"
#     protocol                   = "Udp"
#     source_port_range          = "*"
#     destination_port_range     = "53"
#     source_address_prefix      = var.p2s_pool_cidr
#     destination_address_prefix = "*"
#   }

#   security_rule {
#     name                       = "Allow-DNS-TCP-from-P2S"
#     priority                   = 110
#     direction                  = "Inbound"
#     access                     = "Allow"
#     protocol                   = "Tcp"
#     source_port_range          = "*"
#     destination_port_range     = "53"
#     source_address_prefix      = var.p2s_pool_cidr
#     destination_address_prefix = "*"
#   }
# }

# resource "azurerm_subnet_network_security_group_association" "assoc_dns_inbound" {
#   subnet_id                 = azurerm_subnet.s_dns_inbound.id
#   network_security_group_id = azurerm_network_security_group.nsg_dns_inbound.id
# }
# The resolver resource bound to your hub VNet
resource "azurerm_private_dns_resolver" "pdr" {
  name                = "pdr-l1-hub"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  virtual_network_id  = azurerm_virtual_network.vnet.id
}

# Inbound endpoint (gives you one or more IPs to query from clients)
resource "azurerm_private_dns_resolver_inbound_endpoint" "pdr_in" {
  name                     = "pdr-inbound"
  location                 = azurerm_resource_group.rg.location
  private_dns_resolver_id  = azurerm_private_dns_resolver.pdr.id

  ip_configurations {
    private_ip_allocation_method = "Dynamic"
    subnet_id                    = azurerm_subnet.s_dns_inbound.id
  }
}

# Outputs (handy for NRPT / client config)
output "dns_resolver_inbound_ips" {
  description = "IP(s) of the DNS Private Resolver inbound endpoint"
  value       = azurerm_private_dns_resolver_inbound_endpoint.pdr_in.ip_configurations[*].private_ip_address
}





############################
# Postgres Flexible Server (private)
############################
resource "random_password" "pg_admin_pw" {
  length = 24
  special = true
}
resource "azurerm_postgresql_flexible_server" "pg" {
  name                   = var.pg_server_name
  resource_group_name    = azurerm_resource_group.rg.name
  location               = azurerm_resource_group.rg.location
  version                = var.pg_version
  administrator_login    = var.pg_admin_user
  administrator_password = random_password.pg_admin_pw.result
  sku_name               = var.pg_sku_name

  storage_mb                    = 65536
  backup_retention_days         = 7
  delegated_subnet_id           = azurerm_subnet.s_pg.id
  private_dns_zone_id           = azurerm_private_dns_zone.pdz_postgres.id
  public_network_access_enabled = false

  lifecycle {
    ignore_changes = [
      zone,
      high_availability[0].standby_availability_zone
    ]
  }

  high_availability { mode = "ZoneRedundant" }
}
resource "azurerm_postgresql_flexible_server_database" "pgdb" {
  name      = "grafana"
  server_id = azurerm_postgresql_flexible_server.pg.id
  collation = "en_US.utf8"
  charset   = "UTF8"
}

############################
# App Service Plan + Web App (Grafana)
############################
resource "azurerm_service_plan" "plan" {
  name                = var.plan_name
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  os_type             = "Linux"
  sku_name            = "P1v3"
  zone_balancing_enabled = true
}

resource "random_password" "grafana_admin_pw" {
  length  = 20
  special = true
}

# Storage account (Azure Files) for persistence
resource "azurerm_storage_account" "sa" {
  name                     = "st${replace(var.app_name, "-", "")}"
  resource_group_name      = azurerm_resource_group.rg.name
  location                 = azurerm_resource_group.rg.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_2"
}

resource "azurerm_storage_share" "share" {
  name                 = "grafana"
  storage_account_id = azurerm_storage_account.sa.id
  quota                = 100
}

# Directories for provisioning
# DISABLED
# known azurerm v3.x bug in azurerm_storage_share_directory where it mis-parses the File Share ARM ID and complains about the core.windows.net suffix
# resource "azurerm_storage_share_directory" "dir_provisioning" {
#   name            = "provisioning"
#   storage_share_id = azurerm_storage_share.share.id
# }

# resource "azurerm_storage_share_directory" "dir_datasources" {
#   name            = "provisioning/datasources"
#   storage_share_id = azurerm_storage_share.share.id
# }


resource "azurerm_linux_web_app" "grafana" {
  name                = var.app_name
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  service_plan_id     = azurerm_service_plan.plan.id
  https_only          = true
  public_network_access_enabled = true

  identity { type = "SystemAssigned" }

  site_config {
    always_on              = true
    vnet_route_all_enabled = true
    ftps_state             = "Disabled"
    application_stack {
      docker_image_name     = var.grafana_image #including tag like : appsvc/staticsite:latest

    }
  }

  # Persist data/provisioning/plugins under /home/grafana (Azure Files mount)
  # App Service mounts Azure File Share so Grafana can see provisioning/config files.
  storage_account {
    name         = "grafanafs"
    type         = "AzureFiles"
    account_name = azurerm_storage_account.sa.name
    access_key   = azurerm_storage_account.sa.primary_access_key
    share_name   = azurerm_storage_share.share.name
    mount_path   = "/home/grafana"
  }

  app_settings = {
    "GF_SECURITY_ADMIN_PASSWORD" = random_password.grafana_admin_pw.result

    # DB (Postgres)
    "GF_DATABASE_TYPE"       = "postgres"
    "GF_DATABASE_HOST"       = "${azurerm_postgresql_flexible_server.pg.fqdn}:5432"
    "GF_DATABASE_NAME"       = azurerm_postgresql_flexible_server_database.pgdb.name
    "GF_DATABASE_USER"       = var.pg_admin_user  # Remove the @server part
    "GF_DATABASE_PASSWORD"   = random_password.pg_admin_pw.result
    "GF_DATABASE_SSL_MODE"   = "require"

    # Persist paths to Azure Files mount
    "GF_PATHS_DATA"          = "/home/grafana/data"
    "GF_PATHS_PLUGINS"       = "/home/grafana/plugins"
    "GF_PATHS_PROVISIONING"  = "/home/grafana/provisioning"
  }
}

# VNet integration for outbound through hub/NVA
resource "azurerm_app_service_virtual_network_swift_connection" "app_vnet_integration" {
  app_service_id = azurerm_linux_web_app.grafana.id
  subnet_id      = azurerm_subnet.s_appint.id
}

# Private Endpoint for the Web App (sites)
resource "azurerm_private_endpoint" "pe_grafana" {
  name                = "pe-grafana-sites"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  subnet_id           = azurerm_subnet.s_pe.id

  private_service_connection {
    name                           = "psc-grafana-sites"
    private_connection_resource_id = azurerm_linux_web_app.grafana.id
    is_manual_connection           = false
    subresource_names              = ["sites"]
  }

  private_dns_zone_group {
    name                 = "pdzg-webapp"
    private_dns_zone_ids = [azurerm_private_dns_zone.pdz_webapp.id]
  }
}

############################
# AMPLS (Azure Monitor Private Link Scope)
############################
resource "azurerm_monitor_private_link_scope" "ampls" {
  name                = "ampls-grafana"
  resource_group_name = azurerm_resource_group.rg.name

  # (optional) default access modes can be set here via features as provider adds support
}

# Link Log Analytics & App Insights resources to AMPLS
resource "azurerm_monitor_private_link_scoped_service" "ampls_law" {
  for_each             = toset(var.law_resource_ids)
  name                 = "law-${replace(element(split("/", each.value), length(split("/", each.value))-1), ".", "-")}"
  resource_group_name  = azurerm_resource_group.rg.name
  scope_name           = azurerm_monitor_private_link_scope.ampls.name
  linked_resource_id   = each.value
}

resource "azurerm_monitor_private_link_scoped_service" "ampls_ai" {
  for_each             = toset(var.appinsights_resource_ids)
  name                 = "ai-${replace(element(split("/", each.value), length(split("/", each.value))-1), ".", "-")}"
  resource_group_name  = azurerm_resource_group.rg.name
  scope_name           = azurerm_monitor_private_link_scope.ampls.name
  linked_resource_id   = each.value
}

# Private DNS for Azure Monitor (AMPLS)
# NOTE: Azure Monitor uses several shared/global endpoints. Keep ONE AMPLS per DNS boundary.
# When you use Azure Monitor Private Link Scope (AMPLS) and create a Private Endpoint for azuremonitor,
# Azure needs to return private A records for a bunch of Azure Monitor/Logs/Application Insights hostnames. 
# These zones host those private records. Without them, queries would still resolve to public endpoints and the traffic wouldn’t stay private.
locals {
  monitor_private_zones = [
    "privatelink.monitor.azure.com",
    "privatelink.oms.opinsights.azure.com",
    "privatelink.ods.opinsights.azure.com",
    # a Private DNS zone group on a single Private Endpoint can reference at most 5 zones
    # so to use those it should be splitted to 2 PEs
    # "privatelink.agentsvc.azure-automation.net",
    # "privatelink.applicationinsights.azure.com",
    # "privatelink.profiler.applicationinsights.azure.com",
    # "privatelink.live.applicationinsights.azure.com",
  ]
}

# block creates the Private DNS zones for Azure Monitor’s Private Link and links them to your VNet so names like *.privatelink.monitor.azure.com resolve to private IPs inside your hub.
# creates one Private DNS zone per name (loop via for_each).
resource "azurerm_private_dns_zone" "pdz_monitor" {
  for_each            = toset(local.monitor_private_zones)
  name                = each.value
  resource_group_name = azurerm_resource_group.rg.name
}

# for each created zone, creates a VNet link to your hub VNet so VMs/App Service (via VNet integration) resolve those names to Private Endpoint IPs.
resource "azurerm_private_dns_zone_virtual_network_link" "pdz_monitor_link" {
  for_each                = azurerm_private_dns_zone.pdz_monitor
  name                    = "link-${replace(each.value.name, ".", "-")}"
  resource_group_name     = azurerm_resource_group.rg.name
  private_dns_zone_name   = each.value.name
  virtual_network_id      = azurerm_virtual_network.vnet.id
}

# Private Endpoint to the AMPLS
resource "azurerm_private_endpoint" "pe_ampls" {
  name                = "pe-ampls"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  subnet_id           = azurerm_subnet.s_pe.id

  private_service_connection {
    name                           = "psc-ampls"
    private_connection_resource_id = azurerm_monitor_private_link_scope.ampls.id
    is_manual_connection           = false
    subresource_names              = ["azuremonitor"]
  }

  # Attach all AMPLS-related DNS zones in one group
  private_dns_zone_group {
    name = "pdzg-ampls"
    private_dns_zone_ids = [
      for z in azurerm_private_dns_zone.pdz_monitor : z.id
    ]
  }
}

############################
# Optional RBAC for Grafana MI
############################
resource "azurerm_role_assignment" "mi_monitor_reader" {
  count                = length(var.monitor_subscription_id) > 0 ? 1 : 0
  scope                = "/subscriptions/${var.monitor_subscription_id}"
  role_definition_name = "Monitoring Reader"
  principal_id         = azurerm_linux_web_app.grafana.identity[0].principal_id
}

resource "azurerm_role_assignment" "mi_law_reader" {
  count                = length(var.law_resource_id) > 0 ? 1 : 0
  scope                = var.law_resource_id
  role_definition_name = "Log Analytics Reader"
  principal_id         = azurerm_linux_web_app.grafana.identity[0].principal_id
}

############################
# Outputs
############################
output "grafana_private_fqdn" {
  value       = "${var.app_name}.privatelink.azurewebsites.net"
  description = "Reach this FQDN from your VPN/VNet for Grafana UI"
}
output "postgres_fqdn" {
  value = azurerm_postgresql_flexible_server.pg.fqdn
}
output "grafana_mi_principal_id" {
  value = azurerm_linux_web_app.grafana.identity[0].principal_id
}
