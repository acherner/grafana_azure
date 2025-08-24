terraform {
  required_version = ">= 1.5.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.110.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.5.1"
    }
  }
}

provider "azurerm" {
  features {}
}

# -----------------------------
# Variables (edit to your env)
# -----------------------------
variable "location"            { default = "westeurope" }
variable "rg_name"             { default = "rg-l1-observability" }
variable "vnet_name"           { default = "vnet-l1-hub" }
variable "vnet_cidr"           { default = "10.50.0.0/16" }
variable "subnet_appint_cidr"  { default = "10.50.10.0/24" }   # App Service VNet integration
variable "subnet_pe_cidr"      { default = "10.50.20.0/24" }   # Private Endpoints
variable "subnet_pg_cidr"      { default = "10.50.30.0/24" }   # Delegated to PostgreSQL
variable "plan_name"           { default = "asp-grafana-p3v3" }
variable "app_name"            { default = "app-grafana-l1" }
variable "pg_server_name"      { default = "pg-grafana-l1" }   # must be globally unique
variable "pg_admin_user"       { default = "grafadmin" }
variable "pg_sku_name"         { default = "GP_Standard_D2ds_v5" } # pick your size
variable "pg_version"          { default = "16" }
variable "grafana_image"       { default = "grafana/grafana" }
variable "grafana_tag"         { default = "latest" }

# Optionally scope RBAC for MI:
variable "monitor_subscription_id" { default = "" } # subscription to grant Monitoring Reader (leave blank to skip)
variable "law_resource_id"         { default = "" } # Log Analytics workspace resource ID (to grant Log Analytics Reader)

# -----------------------------
# Resource Group
# -----------------------------
resource "azurerm_resource_group" "rg" {
  name     = var.rg_name
  location = var.location
}

# -----------------------------
# Networking: VNet + Subnets
# -----------------------------
resource "azurerm_virtual_network" "vnet" {
  name                = var.vnet_name
  address_space       = [var.vnet_cidr]
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
}

resource "azurerm_subnet" "s_appint" {
  name                 = "snet-appsvc-integration"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = [var.subnet_appint_cidr]
  # No delegation required for App Service regional VNet integration
  # Ensure no Gateway/PE in this subnet
}

resource "azurerm_subnet" "s_pe" {
  name                 = "snet-private-endpoints"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = [var.subnet_pe_cidr]
  private_endpoint_network_policies_enabled = false
}

resource "azurerm_subnet" "s_pg" {
  name                 = "snet-postgres-delegated"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = [var.subnet_pg_cidr]
  delegation {
    name = "pg-flex-delegation"
    service_delegation {
      name = "Microsoft.DBforPostgreSQL/flexibleServers"
      actions = [
        "Microsoft.Network/virtualNetworks/subnets/join/action",
        "Microsoft.Network/virtualNetworks/subnets/prepareNetworkPolicies/action"
      ]
    }
  }
}

# -----------------------------
# Private DNS Zones
# -----------------------------
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

# -----------------------------
# PostgreSQL Flexible Server (private)
# -----------------------------
resource "random_password" "pg_admin_pw" {
  length  = 24
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

  storage_mb                   = 65536
  backup_retention_days        = 7
  zone                         = "1"

  delegated_subnet_id          = azurerm_subnet.s_pg.id
  private_dns_zone_id          = azurerm_private_dns_zone.pdz_postgres.id

  high_availability {
    mode = "ZoneRedundant"
  }

  maintenance_window {
    day_of_week  = 0
    start_hour   = 0
    start_minute = 0
  }

  # Disable public internet
  public_network_access_enabled = false
}

resource "azurerm_postgresql_flexible_server_database" "pgdb" {
  name      = "grafana"
  server_id = azurerm_postgresql_flexible_server.pg.id
  collation = "en_US.utf8"
  charset   = "UTF8"
}

# -----------------------------
# App Service Plan (Linux)
# -----------------------------
resource "azurerm_service_plan" "plan" {
  name                = var.plan_name
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  os_type             = "Linux"
  sku_name            = "P1v3" # adjust as needed
  zone_balancing_enabled = true
}

# -----------------------------
# Grafana App (Linux Web App, container)
# -----------------------------
resource "random_password" "grafana_admin_pw" {
  length  = 20
  special = true
}

resource "azurerm_linux_web_app" "grafana" {
  name                = var.app_name
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  service_plan_id     = azurerm_service_plan.plan.id

  https_only = true

  identity {
    type = "SystemAssigned"
  }

  site_config {
    always_on                 = true
    vnet_route_all_enabled    = true   # route ALL egress via VNet (so NVA/UDR policies apply)
    ftps_state                = "Disabled"

    application_stack {
      docker_image     = var.grafana_image
      docker_image_tag = var.grafana_tag
    }

    # (Optional) lock down public endpoint with access restrictions.
    # Private Endpoint connections bypass these, so we can deny public.
    ip_restriction {
      name     = "deny-all-public"
      priority = 100
      action   = "Deny"
      ip_address = "0.0.0.0/0"
    }
    scm_use_main_ip_restriction = true
  }

  app_settings = {
    # Grafana admin (change on first login, or use Key Vault)
    "GF_SECURITY_ADMIN_PASSWORD" = random_password.grafana_admin_pw.result

    # Database (Postgres) configuration
    "GF_DATABASE_TYPE"       = "postgres"
    "GF_DATABASE_HOST"       = "${azurerm_postgresql_flexible_server.pg.fqdn}:5432"
    "GF_DATABASE_NAME"       = azurerm_postgresql_flexible_server_database.pgdb.name
    "GF_DATABASE_USER"       = "${var.pg_admin_user}@${azurerm_postgresql_flexible_server.pg.name}"
    "GF_DATABASE_PASSWORD"   = random_password.pg_admin_pw.result
    "GF_DATABASE_SSL_MODE"   = "require"
  }
}

# Web App VNet Integration (regional integration into s_appint)
resource "azurerm_app_service_virtual_network_swift_connection" "app_vnet_integration" {
  app_service_id = azurerm_linux_web_app.grafana.id
  subnet_id      = azurerm_subnet.s_appint.id
}

# -----------------------------
# Private Endpoint for Web App
# -----------------------------
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

# -----------------------------
# Optional RBAC: let Grafana MI read Azure Monitor & Logs
# -----------------------------
# Monitoring Reader at subscription scope
resource "azurerm_role_assignment" "mi_monitor_reader" {
  count                = length(var.monitor_subscription_id) > 0 ? 1 : 0
  scope                = "/subscriptions/${var.monitor_subscription_id}"
  role_definition_name = "Monitoring Reader"
  principal_id         = azurerm_linux_web_app.grafana.identity[0].principal_id
}

# Log Analytics Reader at workspace scope
resource "azurerm_role_assignment" "mi_law_reader" {
  count                = length(var.law_resource_id) > 0 ? 1 : 0
  scope                = var.law_resource_id
  role_definition_name = "Log Analytics Reader"
  principal_id         = azurerm_linux_web_app.grafana.identity[0].principal_id
}

# -----------------------------
# Outputs
# -----------------------------
output "grafana_private_fqdn" {
  description = "Resolve inside VNet/VPN: the privatelink FQDN for the Web App"
  value       = "${var.app_name}.privatelink.azurewebsites.net"
}

output "postgres_fqdn" {
  value = azurerm_postgresql_flexible_server.pg.fqdn
}

output "grafana_mi_principal_id" {
  value = azurerm_linux_web_app.grafana.identity[0].principal_id
}
