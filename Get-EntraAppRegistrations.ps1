<#################################################################################

Script that exports all app registrations with secrets and certificates expiring in the next X days

#################################################################################>

[CmdletBinding()]
param(
    # Number of days until the secrets expire as an integer.
    [Parameter(Mandatory=$True)]
    [string]$DaysUntilExpiration, 
    
    # 'Yes'|'No' Include expired secrets.
    [Parameter(Mandatory=$True)]
    [string]$IncludeAlreadyExpired,

    # Client ID
    [Parameter(Mandatory=$True)]
    [string]$ClientId,

    # Client Secret
    [Parameter(Mandatory=$True)]
    [string]$ClientSecret,

    # Tenant ID
    [Parameter(Mandatory=$True)]
    [string]$TenantId,

    # Team Webhook URL
    [Parameter(Mandatory=$True)]
    [string]$hookUrl
)

# Error handler
$ErrorActionPreference = "Stop"
trap {
    throw $_
}

# Function to check if a module is installed and install it if not
function Set-EnsureModule {
    param (
        [string]$ModuleName
    )
    if (-not (Get-Module -ListAvailable -Name $ModuleName)) {
        Write-Host "Module $ModuleName is not installed. Installing..."
        Install-Module -Name $ModuleName -Scope CurrentUser -Force -AllowClobber
    } else {
        Write-Host "Module $ModuleName is already installed."
    }
}

# Ensure required modules are installed
Set-EnsureModule -ModuleName 'Az'

# Authenticate with Azure CLI using service principal
az login --service-principal -u $ClientId -p $ClientSecret --tenant $TenantId  --allow-no-subscriptions

$Messages = @{
    ExpirationDays = @{
        Info   = 'Filter the applications to log by the number of days until their secrets expire.'
    }
    AlreadyExpired = @{
        Info   = 'Would you like to see Applications with already expired secrets as well?'
    }
    DurationNotice = @{
        Info = @(
            'The operation is running and will take longer the more applications the tenant has...'
            'Please wait...'
        ) -join ' '
    }
}

Write-Host $Messages.ExpirationDays.Info $DaysUntilExpiration -ForegroundColor Green
Write-Host $Messages.AlreadyExpired.Info $IncludeAlreadyExpired -ForegroundColor Green

$Now = Get-Date

Write-Host $Messages.DurationNotice.Info -ForegroundColor yellow

$Applications = az ad app list --all --query "[].{DisplayName:displayName, AppId:appId, ObjectID:id}" --output json | ConvertFrom-Json

# $Applications = Get-MgApplication -all

$Logs = @()

foreach ($App in $Applications) {
    $AppName = $App.DisplayName
    $AppID   = $App.ObjectID
    $ApplID  = $App.AppId

    # Get application details using Azure CLI
    $AppDetails = az ad app show --id $AppID --output json | ConvertFrom-Json

    $Secrets = $AppDetails.passwordCredentials
    $Certs   = $AppDetails.keyCredentials


    foreach ($Secret in $Secrets) {
            $StartDate  = $Secret.StartDateTime
            $EndDate    = $Secret.EndDateTime
            $SecretName = $Secret.DisplayName

        # List application owners using Azure CLI
        $Owner = az ad app owner list --id $AppID --output json | ConvertFrom-Json
        $Username = $Owner.userPrincipalName -join ';'
        $OwnerID  = $Owner.id -join ';'

        if ($null -eq $SecretName){
            $SecretName = '<<No SecretName>>'
        }
        if ($null -eq $Owner.displayName) {
            $Username = '<<No Owner>>'
            $OwnerID = '<<No Owner ObjectID>>'
        }

        $RemainingDaysCount = ($EndDate - $Now).Days

        if ($IncludeAlreadyExpired -eq 'No') {
                    if ($RemainingDaysCount -le $DaysUntilExpiration -and $RemainingDaysCount -gt 0) {
                        $Logs += [PSCustomObject]@{
                            'ApplicationName'        = $AppName
                            'ApplicationID'          = $ApplID
                            'Secret Name'            = $SecretName
                            'Secret Start Date'      = $StartDate
                            'Secret End Date'        = $EndDate
                            'Certificate Name'       = '<<Null>>'
                            'Certificate Start Date' = '<<Null>>'
                            'Certificate End Date'   = '<<Null>>'
                            'Owner'                  = $Username
                            'Owner_ObjectID'         = $OwnerID
                        }
                    }
                } elseif ($IncludeAlreadyExpired -eq 'Yes') {
                    if ($RemainingDaysCount -le $DaysUntilExpiration) {
                        $Logs += [PSCustomObject]@{
                            'ApplicationName'        = $AppName
                            'ApplicationID'          = $ApplID
                            'Secret Name'            = $SecretName
                            'Secret Start Date'      = $StartDate
                            'Secret End Date'        = $EndDate
                            'Certificate Name'       = '<<Null>>'
                            'Certificate Start Date' = '<<Null>>'
                            'Certificate End Date'   = '<<Null>>'
                            'Owner'                  = $Username
                            'Owner_ObjectID'         = $OwnerID
                        }
                    }
                }
            }

    foreach ($Cert in $Certs) {
            $StartDate = $Cert.startDateTime
            $EndDate   = $Cert.endDateTime
            $CertName  = $Cert.displayName

        # List application owners using Azure CLI
        $Owner = az ad app owner list --id $AppID --output json | ConvertFrom-Json
        $Username = $Owner.userPrincipalName -join ';'
        $OwnerID  = $Owner.id -join ';'

        if ($null -eq $Owner.displayName) {
            $Username = '<<No Owner>>'
            $OwnerID = '<<No Owner ObjectID>>'
        }

        $RemainingDaysCount = ($EndDate - $Now).Days

        if ($IncludeAlreadyExpired -eq 'No') {
                    if ($RemainingDaysCount -le $DaysUntilExpiration -and $RemainingDaysCount -gt 0) {
                        $Logs += [PSCustomObject]@{
                            'ApplicationName'        = $AppName
                            'ApplicationID'          = $ApplID
                            'Secret Name'            = '<<Null>>'
                            'Certificate Name'       = $CertName
                            'Certificate Start Date' = $StartDate
                            'Certificate End Date'   = $EndDate
                            'Owner'                  = $Username
                            'Owner_ObjectID'         = $OwnerID
                        }
                    }
                } elseif ($IncludeAlreadyExpired -eq 'Yes') {
                    if ($RemainingDaysCount -le $DaysUntilExpiration) {
                        $Logs += [PSCustomObject]@{
                            'ApplicationName'        = $AppName
                            'ApplicationID'          = $ApplID
                            'Secret Name'            = '<<Null>>'
                            'Certificate Name'       = $CertName
                            'Certificate Start Date' = $StartDate
                            'Certificate End Date'   = $EndDate
                            'Owner'                  = $Username
                            'Owner_ObjectID'         = $OwnerID
                        }
                    }
                }
            }
}

if ($Logs) {

    # Define the variables
    $title = "Publish App registrations with secrets and certificates expiring in the next $DaysUntilExpiration days"
    $creatorName = "Azure Pipeline"
    $createdUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")  # ISO 8601 UTC format
    $viewUrl = "https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/RegisteredApps"
    $hookUrl = $hookUrl
    # Convert the Logs object to a string
    $description = $Logs | Out-String
    # Object (template)
    $message = @{
        type        = "message"
        attachments = @(
            @{
                contentType = "application/vnd.microsoft.card.adaptive"
                contentUrl  = $null
                content     = @{
                    type     = "AdaptiveCard"
                    body     = @(
                        @{
                            type  = "TextBlock"
                            size  = "Medium"
                            weight = "Bolder"
                            text  = $title
                            style = "heading"
                            wrap  = $true
                        },
                        @{
                            type   = "ColumnSet"
                            columns = @(
                                @{
                                    type  = "Column"
                                    items = @(
                                        @{
                                            type   = "Image"
                                            style  = "Person"
                                            url    = "https://icons.veryicon.com/png/o/business/vscode-program-item-icon/azure-pipelines.png"
                                            altText = $creatorName
                                            size   = "Small"
                                        }
                                    )
                                    width = "auto"
                                },
                                @{
                                    type  = "Column"
                                    items = @(
                                        @{
                                            type   = "TextBlock"
                                            weight = "Bolder"
                                            text   = $creatorName
                                            wrap   = $true
                                        },
                                        @{
                                            type    = "TextBlock"
                                            spacing = "None"
                                            text    = "Created {{DATE($createdUtc, SHORT)}}"
                                            isSubtle = $true
                                            wrap    = $true
                                        }
                                    )
                                    width = "stretch"
                                }
                            )
                        },
                        @{
                            type  = "TextBlock"
                            text  = $description
                            wrap  = $true
                        }
                    )
                    actions  = @(
                        @{
                            type  = "Action.OpenUrl"
                            title = "View App registrations"
                            url   = $viewUrl
                            role  = "Button"
                        }
                    )
                    schema  = "http://adaptivecards.io/schemas/adaptive-card.json"
                    version = "1.6"
                }
            }
        )
    }

    # Convert the object to JSON
    $jsonMessage = $message | ConvertTo-Json -Depth 30
    Invoke-WebRequest -uri $hookUrl -Method POST -Body $jsonMessage -Headers @{'Content-Type' = 'application/json'}
} else {
    Write-Output "No app registration that will expire in the next $DaysUntilExpiration days"
}








