data "azurerm_client_config" "current" {}

resource "azurerm_resource_group" "crc_rg" {
  name     = "TF-cloudresumechallenge"
  location = "centralus"
}

resource "azurerm_storage_account" "crc_sa" {
  name                     = "tfcrcresumestorage"
  resource_group_name      = azurerm_resource_group.crc_rg.name
  location                 = azurerm_resource_group.crc_rg.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  static_website {
    index_document     = "index.html"
    error_404_document = "404.html"
  }

}

resource "azurerm_cdn_profile" "crc_cdn" {
  name                = "TF-crcresumecdnprofile"
  resource_group_name = azurerm_resource_group.crc_rg.name
  location            = azurerm_resource_group.crc_rg.location
  sku                 = "Standard_Microsoft"
}

resource "azurerm_cdn_endpoint" "crc_endpoint" {
  name                = "TF-crcresume-endpoint"
  resource_group_name = azurerm_resource_group.crc_rg.name
  location            = azurerm_resource_group.crc_rg.location
  profile_name        = azurerm_cdn_profile.crc_cdn.name
  origin_host_header  = "tfcrcresumestorage.z19.web.core.windows.net"
  origin {
    name      = "TF-crcresume-endpoint"
    host_name = "tfcrcresumestorage.z19.web.core.windows.net"
  }

  delivery_rule {
    name  = "wwwtoapex"
    order = 1
    request_uri_condition {
      operator     = "BeginsWith"
      match_values = ["www", "http://www", "https://www"]
    }
    url_redirect_action {
      redirect_type = "Moved"
      protocol      = "Https"
      hostname      = "cjmedina.dev"
    }
  }
}

resource "azurerm_dns_zone" "crc_dnszone" {
  name                = "cjmedina.dev"
  resource_group_name = azurerm_resource_group.crc_rg.name
}

resource "azurerm_dns_a_record" "crc_dns_a1" {
  name                = "@"
  resource_group_name = azurerm_resource_group.crc_rg.name
  zone_name           = azurerm_dns_zone.crc_dnszone.name
  ttl                 = 300
  target_resource_id  = azurerm_cdn_endpoint.crc_endpoint.id
}

resource "azurerm_dns_cname_record" "crc_dns_cname1" {
  name                = "cdnverify"
  resource_group_name = azurerm_resource_group.crc_rg.name
  zone_name           = azurerm_dns_zone.crc_dnszone.name
  ttl                 = 3600
  record              = "cdnverify.TF-crcresume-endpoint.azureedge.net"
}

resource "azurerm_dns_cname_record" "crc_dns_cname2" {
  name                = "www"
  resource_group_name = azurerm_resource_group.crc_rg.name
  zone_name           = azurerm_dns_zone.crc_dnszone.name
  ttl                 = 3600
  record              = "TF-crcresume-endpoint.azureedge.net"
}

resource "azurerm_key_vault" "crc_keyvault" {
  name                = "tfcrc-keyvault"
  location            = azurerm_resource_group.crc_rg.location
  resource_group_name = azurerm_resource_group.crc_rg.name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "standard"
}

resource "azurerm_key_vault_access_policy" "crc_keyvault_ap_user" {
  key_vault_id = azurerm_key_vault.crc_keyvault.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = "3c6aeed1-fc22-465c-b0f1-c6c3df859be1"

  certificate_permissions = [
    "Create",
    "Delete",
    "DeleteIssuers",
    "Get",
    "GetIssuers",
    "Import",
    "List",
    "ListIssuers",
    "ManageContacts",
    "ManageIssuers",
    "SetIssuers",
    "Update",
  ]

  key_permissions = [
    "Backup",
    "Create",
    "Decrypt",
    "Delete",
    "Encrypt",
    "Get",
    "Import",
    "List",
    "Purge",
    "Recover",
    "Restore",
    "Sign",
    "UnwrapKey",
    "Update",
    "Verify",
    "WrapKey",
  ]

  secret_permissions = [
    "Backup",
    "Delete",
    "Get",
    "List",
    "Purge",
    "Recover",
    "Restore",
    "Set",
  ]
}

resource "azurerm_key_vault_access_policy" "crc_keyvault_ap_cdn" {
  key_vault_id = azurerm_key_vault.crc_keyvault.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = "25feca8b-d0f0-4466-aebd-e14f74fa85f9"

  certificate_permissions = [
    "Create",
    "Delete",
    "DeleteIssuers",
    "Get",
    "GetIssuers",
    "Import",
    "List",
    "ListIssuers",
    "ManageContacts",
    "ManageIssuers",
    "SetIssuers",
    "Update",
  ]

  key_permissions = [
    "Backup",
    "Create",
    "Decrypt",
    "Delete",
    "Encrypt",
    "Get",
    "Import",
    "List",
    "Purge",
    "Recover",
    "Restore",
    "Sign",
    "UnwrapKey",
    "Update",
    "Verify",
    "WrapKey",
  ]

  secret_permissions = [
    "Backup",
    "Delete",
    "Get",
    "List",
    "Purge",
    "Recover",
    "Restore",
    "Set",
  ]
}

resource "azurerm_key_vault_certificate" "crc_cert" {
  name         = "crc-tf-cert2"
  key_vault_id = azurerm_key_vault.crc_keyvault.id

  certificate {
    contents = filebase64("crcresume-keyvault-cjmedina-dev-20221115.pfx")
  }

  depends_on = [azurerm_key_vault_access_policy.crc_keyvault_ap_cdn, azurerm_key_vault_access_policy.crc_keyvault_ap_user]
}

resource "azurerm_cdn_endpoint_custom_domain" "crc_cdn_domain" {
  name            = "crc-domain"
  cdn_endpoint_id = azurerm_cdn_endpoint.crc_endpoint.id
  host_name       = "www.cjmedina.dev"

  user_managed_https {
    key_vault_certificate_id = azurerm_key_vault_certificate.crc_cert.id
  }
}

resource "azurerm_cdn_endpoint_custom_domain" "crc_cdn_domain2" {
  name            = "crc-domain-apex"
  cdn_endpoint_id = azurerm_cdn_endpoint.crc_endpoint.id
  host_name       = "cjmedina.dev"

  user_managed_https {
    key_vault_certificate_id = azurerm_key_vault_certificate.crc_cert.id
  }
}

resource "azurerm_cosmosdb_account" "crc_cosmos" {
  name                = "crc-cosmos"
  location            = azurerm_resource_group.crc_rg.location
  resource_group_name = azurerm_resource_group.crc_rg.name
  offer_type          = "Standard"
  enable_free_tier = true
  
  capabilities {
	name = "EnableServerless"
  }
  
  geo_location {
    location          = "westus"
    failover_priority = 0
  }

  consistency_policy {
    consistency_level       = "BoundedStaleness"
    max_interval_in_seconds = 300
    max_staleness_prefix    = 100000
  }
  
  cors_rule {
	allowed_headers = ["Access-Control-Allow-Origin"]
	allowed_methods = ["GET", "POST"]
	allowed_origins = ["*"]
	exposed_headers = ["Access-Control-Allow-Origin"]
	max_age_in_seconds = "3600"
  }
}

resource "azurerm_cosmosdb_sql_database" "crc_db" {
  name                = "crc-db"
  resource_group_name = azurerm_resource_group.crc_rg.name
  account_name        = azurerm_cosmosdb_account.crc_cosmos.name
}

resource "azurerm_app_service_plan" "crc_service_plan" {
  name                = "crc-service"
  location            = azurerm_resource_group.crc_rg.location
  resource_group_name = azurerm_resource_group.crc_rg.name

  kind                = "FunctionApp"
  reserved            = true

  sku {
    tier = "Dynamic"
    size = "Y1"
  }
}

resource "azurerm_cosmosdb_sql_container" "example" {
  name                  = "crc-visitorcount"
  resource_group_name   = azurerm_resource_group.crc_rg.name
  account_name          = azurerm_cosmosdb_account.crc_cosmos.name
  database_name         = azurerm_cosmosdb_sql_database.crc_db.name
  partition_key_path    = "/id"
  partition_key_version = 1

  indexing_policy {
    indexing_mode = "consistent"

    included_path {
      path = "/*"
    }

    included_path {
      path = "/included/?"
    }

    excluded_path {
      path = "/excluded/?"
    }
  }

  unique_key {
    paths = ["/definition/idlong", "/definition/idshort"]
  }
}

resource "azurerm_log_analytics_workspace" "crc_workspace" {
  name                = "crc-workspace"
  location            = azurerm_resource_group.crc_rg.location
  resource_group_name = azurerm_resource_group.crc_rg.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
}

resource "azurerm_application_insights" "crc_appinsights" {
  name                = "crc-appinsights"
  location            = azurerm_resource_group.crc_rg.location
  resource_group_name = azurerm_resource_group.crc_rg.name
  workspace_id        = azurerm_log_analytics_workspace.crc_workspace.id
  application_type    = "web"
}

resource "azurerm_function_app" "crc_function_app" {
  name                = "crc-counterapp"
  location            = azurerm_resource_group.crc_rg.location
  resource_group_name = azurerm_resource_group.crc_rg.name
  app_service_plan_id     = azurerm_app_service_plan.crc_service_plan.id
  storage_account_name       = azurerm_storage_account.crc_sa.name
  storage_account_access_key = azurerm_storage_account.crc_sa.primary_access_key
  version = "~4"
  https_only                 = true
  os_type                    = "linux"
  
  app_settings = {
	  "AzureCosmosDBConnectionString" = var.AZConnectionString
      "FUNCTIONS_WORKER_RUNTIME" = "python"
      "APPINSIGHTS_INSTRUMENTATIONKEY" = "${azurerm_application_insights.crc_appinsights.instrumentation_key}"
      "APPLICATIONINSIGHTS_CONNECTION_STRING" = "InstrumentationKey=${azurerm_application_insights.crc_appinsights.instrumentation_key};IngestionEndpoint=https://centralus-2.in.applicationinsights.azure.com/;LiveEndpoint=https://centralus.livediagnostics.monitor.azure.com/"
  }

  site_config {
        linux_fx_version= "Python|3.8"        
        ftps_state = "Disabled"
		
	    cors {
		  allowed_origins = ["https://cjmedina.dev", "https://tf-crcresume-endpoint.azureedge.net/"]
	    }
    }
}