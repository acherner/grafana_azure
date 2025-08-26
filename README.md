# grafana_azure

What this does

Creates RG, VNet (L1) with subnets for App Service VNet Integration, Private Endpoints, and Postgres (delegated).

Creates Private DNS zones for App Service & Postgres privatelink, links them to the VNet.

Deploys Azure Database for PostgreSQL Flexible Server private (delegated subnet + private DNS).

Deploys App Service Plan (Linux) + Linux Web App running grafana/grafana:latest.

Enables Managed Identity on the web app; sets Grafana DB env vars; routes all egress via VNet (so your NVA/UDRs can inspect).

Adds a Private Endpoint for the Web App.

Example RBAC to grant the MI “Monitoring Reader” on one subscription and “Log Analytics Reader” on one workspace.

Notes

Replace CHANGEME_* values.

This is a starter; add your NVA/UDR/peering outside this module.

For production, consider Key Vault for secrets and pin Grafana image tags.


test right now with an Azure VPN Client from your local PC:

In the L1 hub where Grafana lives, deploy an Azure VPN Gateway (Point-to-Site enabled).

Configure the VPN Gateway to use either:

Certificate auth (default, quick for lab), or

Azure AD auth (better, so NOC users log in with Entra).

Download the Azure VPN Client (Windows/macOS) and import the profile (from the Azure Portal).

Once connected, your PC gets an IP from the P2S pool; you can now resolve and reach:

app-grafana-l1.privatelink.azurewebsites.net → Private IP inside your hub → Grafana UI.

pg-grafana-l1.postgres.database.azure.com (if you want to test DB reach).

So yes: install Azure VPN Client locally, connect, and you’ll be able to hit the Grafana UI over the Private Endpoint in L1.





How to use this

Populate var.datasources with the tenant+subscription pairs you want pre-provisioned in Grafana.

If you want Grafana’s MI to read Monitor/Logs immediately, set monitor_subscription_id and law_resource_id (or use your own loops).

For AMPLS, add your law_resource_ids / appinsights_resource_ids to scope them privately.

Connect with Azure VPN Client to your L1 VNet, then browse grafana_private_fqdn from the output.

Verify (what this implements & why)

AMPLS makes Azure Monitor/Log Analytics private behind one Private Endpoint; you link workspaces/AI components to the scope, and DNS for shared endpoints is handled via Private DNS zones. Keep one AMPLS per DNS boundary to avoid conflicts. 
Microsoft Learn

The Terraform resources used are azurerm_monitor_private_link_scope and azurerm_monitor_private_link_scoped_service (to attach LAW/AppInsights), and a Private Endpoint with subresource azuremonitor. 
search.opentofu.org
Shisho Cloud byGMO - 開発組織のための 脆弱性診断ツール
GitHub

The DNS zones you see created (e.g., privatelink.monitor.azure.com, privatelink.oms/opinsights, privatelink.applicationinsights...) are the set Azure Monitor uses with AMPLS. 
Cloudtrooper
Microsoft Learn

Azure Files + the App Service mount persists Grafana data and provisioning. Uploading datasources.yaml is done with azurerm_storage_share_file and directories via azurerm_storage_share_directory. 
Terraform Registry
+1

Quick test checklist

From your VPN-connected PC: nslookup ${var.app_name}.privatelink.azurewebsites.net → private IP from snet-private-endpoints.

In Grafana (admin / auto-generated password), verify the Azure Monitor datasources exist (from YAML) and Save & Test succeeds.

If you enforce egress via NVA: allow service tags / FQDNs for Azure Resource Manager and Azure Monitor/Log Analytics (AMPLS will shift these to private IPs once in place). 
Microsoft Learn



COST:

| Component                         | Estimated Monthly Cost |
| --------------------------------- | ---------------------- |
| App Service (P1v3)                | \$124                  |
| PostgreSQL Flexible Server (D2ds) | \$130                  |
| Private Endpoints (2×)            | \~\$14.40              |
| Azure Files Storage               | \~\$5                  |
| Azure Monitor Private Link Scope  | Minimal (PE included)  |
| **Total (approx)**                | **\~\$273/month**      |



========================================================================================================

az login --use-device-code
az account show --output table
az account set --subscription "c30115c5-79c4-4755-a139-f5642c22d69f"

=== test routing and DNS from your VPN-connected machine with

az network private-endpoint-connection list \
  --name app-grafana-l1 \
  --resource-group rg-l1-observability
