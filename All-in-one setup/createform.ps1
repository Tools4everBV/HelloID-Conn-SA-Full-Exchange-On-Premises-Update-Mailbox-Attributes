# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

#HelloID variables
#Note: when running this script inside HelloID; portalUrl and API credentials are provided automatically (generate and save API credentials first in your admin panel!)
$portalUrl = "https://CUSTOMER.helloid.com"
$apiKey = "API_KEY"
$apiSecret = "API_SECRET"
$delegatedFormAccessGroupNames = @("HID_administrators") #Only unique names are supported. Groups must exist!
$delegatedFormCategories = @("Active Directory","User Management") #Only unique names are supported. Categories will be created if not exists
$script:debugLogging = $false #Default value: $false. If $true, the HelloID resource GUIDs will be shown in the logging
$script:duplicateForm = $false #Default value: $false. If $true, the HelloID resource names will be changed to import a duplicate Form
$script:duplicateFormSuffix = "_tmp" #the suffix will be added to all HelloID resource names to generate a duplicate form with different resource names

#The following HelloID Global variables are used by this form. No existing HelloID global variables will be overriden only new ones are created.
#NOTE: You can also update the HelloID Global variable values afterwards in the HelloID Admin Portal: https://<CUSTOMER>.helloid.com/admin/variablelibrary
$globalHelloIDVariables = [System.Collections.Generic.List[object]]@();

#Global variable #1 >> ExchangeAdminUsername
$tmpName = @'
ExchangeAdminUsername
'@ 
$tmpValue = "" 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "True"});

#Global variable #2 >> ExchangeAuthentication
$tmpName = @'
ExchangeAuthentication
'@ 
$tmpValue = @'
kerberos
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});

#Global variable #3 >> ExchangeAdminPassword
$tmpName = @'
ExchangeAdminPassword
'@ 
$tmpValue = "" 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "True"});

#Global variable #4 >> ExchangeConnectionUri
$tmpName = @'
ExchangeConnectionUri
'@ 
$tmpValue = @'
http://myserver.mydomain.com/PowerShell
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});

#Global variable #5 >> ExchangeUpdateMailboxAttributesSearchOU
$tmpName = @'
ExchangeUpdateMailboxAttributesSearchOU
'@ 
$tmpValue = @'
mydomain.com/users
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});


#make sure write-information logging is visual
$InformationPreference = "continue"

# Check for prefilled API Authorization header
if (-not [string]::IsNullOrEmpty($portalApiBasic)) {
    $script:headers = @{"authorization" = $portalApiBasic}
    Write-Information "Using prefilled API credentials"
} else {
    # Create authorization headers with HelloID API key
    $pair = "$apiKey" + ":" + "$apiSecret"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
    $base64 = [System.Convert]::ToBase64String($bytes)
    $key = "Basic $base64"
    $script:headers = @{"authorization" = $Key}
    Write-Information "Using manual API credentials"
}

# Check for prefilled PortalBaseURL
if (-not [string]::IsNullOrEmpty($portalBaseUrl)) {
    $script:PortalBaseUrl = $portalBaseUrl
    Write-Information "Using prefilled PortalURL: $script:PortalBaseUrl"
} else {
    $script:PortalBaseUrl = $portalUrl
    Write-Information "Using manual PortalURL: $script:PortalBaseUrl"
}

# Define specific endpoint URI
$script:PortalBaseUrl = $script:PortalBaseUrl.trim("/") + "/"  
 

function Invoke-HelloIDGlobalVariable {
    param(
        [parameter(Mandatory)][String]$Name,
        [parameter(Mandatory)][String][AllowEmptyString()]$Value,
        [parameter(Mandatory)][String]$Secret
    )

    $Name = $Name + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    try {
        $uri = ($script:PortalBaseUrl + "api/v1/automation/variables/named/$Name")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
    
        if ([string]::IsNullOrEmpty($response.automationVariableGuid)) {
            #Create Variable
            $body = @{
                name     = $Name;
                value    = $Value;
                secret   = $Secret;
                ItemType = 0;
            }    
            $body = ConvertTo-Json -InputObject $body
    
            $uri = ($script:PortalBaseUrl + "api/v1/automation/variable")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
            $variableGuid = $response.automationVariableGuid

            Write-Information "Variable '$Name' created$(if ($script:debugLogging -eq $true) { ": " + $variableGuid })"
        } else {
            $variableGuid = $response.automationVariableGuid
            Write-Warning "Variable '$Name' already exists$(if ($script:debugLogging -eq $true) { ": " + $variableGuid })"
        }
    } catch {
        Write-Error "Variable '$Name', message: $_"
    }
}

function Invoke-HelloIDAutomationTask {
    param(
        [parameter(Mandatory)][String]$TaskName,
        [parameter(Mandatory)][String]$UseTemplate,
        [parameter(Mandatory)][String]$AutomationContainer,
        [parameter(Mandatory)][String][AllowEmptyString()]$Variables,
        [parameter(Mandatory)][String]$PowershellScript,
        [parameter()][String][AllowEmptyString()]$ObjectGuid,
        [parameter()][String][AllowEmptyString()]$ForceCreateTask,
        [parameter(Mandatory)][Ref]$returnObject
    )
    
    $TaskName = $TaskName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    try {
        $uri = ($script:PortalBaseUrl +"api/v1/automationtasks?search=$TaskName&container=$AutomationContainer")
        $responseRaw = (Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false) 
        $response = $responseRaw | Where-Object -filter {$_.name -eq $TaskName}
    
        if([string]::IsNullOrEmpty($response.automationTaskGuid) -or $ForceCreateTask -eq $true) {
            #Create Task

            $body = @{
                name                = $TaskName;
                useTemplate         = $UseTemplate;
                powerShellScript    = $PowershellScript;
                automationContainer = $AutomationContainer;
                objectGuid          = $ObjectGuid;
                variables           = [Object[]]($Variables | ConvertFrom-Json);
            }
            $body = ConvertTo-Json -InputObject $body
    
            $uri = ($script:PortalBaseUrl +"api/v1/automationtasks/powershell")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
            $taskGuid = $response.automationTaskGuid

            Write-Information "Powershell task '$TaskName' created$(if ($script:debugLogging -eq $true) { ": " + $taskGuid })"
        } else {
            #Get TaskGUID
            $taskGuid = $response.automationTaskGuid
            Write-Warning "Powershell task '$TaskName' already exists$(if ($script:debugLogging -eq $true) { ": " + $taskGuid })"
        }
    } catch {
        Write-Error "Powershell task '$TaskName', message: $_"
    }

    $returnObject.Value = $taskGuid
}

function Invoke-HelloIDDatasource {
    param(
        [parameter(Mandatory)][String]$DatasourceName,
        [parameter(Mandatory)][String]$DatasourceType,
        [parameter(Mandatory)][String][AllowEmptyString()]$DatasourceModel,
        [parameter()][String][AllowEmptyString()]$DatasourceStaticValue,
        [parameter()][String][AllowEmptyString()]$DatasourcePsScript,        
        [parameter()][String][AllowEmptyString()]$DatasourceInput,
        [parameter()][String][AllowEmptyString()]$AutomationTaskGuid,
        [parameter(Mandatory)][Ref]$returnObject
    )

    $DatasourceName = $DatasourceName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    $datasourceTypeName = switch($DatasourceType) { 
        "1" { "Native data source"; break} 
        "2" { "Static data source"; break} 
        "3" { "Task data source"; break} 
        "4" { "Powershell data source"; break}
    }
    
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/datasource/named/$DatasourceName")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
      
        if([string]::IsNullOrEmpty($response.dataSourceGUID)) {
            #Create DataSource
            $body = @{
                name               = $DatasourceName;
                type               = $DatasourceType;
                model              = [Object[]]($DatasourceModel | ConvertFrom-Json);
                automationTaskGUID = $AutomationTaskGuid;
                value              = [Object[]]($DatasourceStaticValue | ConvertFrom-Json);
                script             = $DatasourcePsScript;
                input              = [Object[]]($DatasourceInput | ConvertFrom-Json);
            }
            $body = ConvertTo-Json -InputObject $body
      
            $uri = ($script:PortalBaseUrl +"api/v1/datasource")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
              
            $datasourceGuid = $response.dataSourceGUID
            Write-Information "$datasourceTypeName '$DatasourceName' created$(if ($script:debugLogging -eq $true) { ": " + $datasourceGuid })"
        } else {
            #Get DatasourceGUID
            $datasourceGuid = $response.dataSourceGUID
            Write-Warning "$datasourceTypeName '$DatasourceName' already exists$(if ($script:debugLogging -eq $true) { ": " + $datasourceGuid })"
        }
    } catch {
      Write-Error "$datasourceTypeName '$DatasourceName', message: $_"
    }

    $returnObject.Value = $datasourceGuid
}

function Invoke-HelloIDDynamicForm {
    param(
        [parameter(Mandatory)][String]$FormName,
        [parameter(Mandatory)][String]$FormSchema,
        [parameter(Mandatory)][Ref]$returnObject
    )
    
    $FormName = $FormName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    try {
        try {
            $uri = ($script:PortalBaseUrl +"api/v1/forms/$FormName")
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        } catch {
            $response = $null
        }
    
        if(([string]::IsNullOrEmpty($response.dynamicFormGUID)) -or ($response.isUpdated -eq $true)) {
            #Create Dynamic form
            $body = @{
                Name       = $FormName;
                FormSchema = [Object[]]($FormSchema | ConvertFrom-Json)
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl +"api/v1/forms")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
    
            $formGuid = $response.dynamicFormGUID
            Write-Information "Dynamic form '$formName' created$(if ($script:debugLogging -eq $true) { ": " + $formGuid })"
        } else {
            $formGuid = $response.dynamicFormGUID
            Write-Warning "Dynamic form '$FormName' already exists$(if ($script:debugLogging -eq $true) { ": " + $formGuid })"
        }
    } catch {
        Write-Error "Dynamic form '$FormName', message: $_"
    }

    $returnObject.Value = $formGuid
}


function Invoke-HelloIDDelegatedForm {
    param(
        [parameter(Mandatory)][String]$DelegatedFormName,
        [parameter(Mandatory)][String]$DynamicFormGuid,
        [parameter()][String][AllowEmptyString()]$AccessGroups,
        [parameter()][String][AllowEmptyString()]$Categories,
        [parameter(Mandatory)][String]$UseFaIcon,
        [parameter()][String][AllowEmptyString()]$FaIcon,
        [parameter(Mandatory)][Ref]$returnObject
    )
    $delegatedFormCreated = $false
    $DelegatedFormName = $DelegatedFormName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    try {
        try {
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms/$DelegatedFormName")
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        } catch {
            $response = $null
        }
    
        if([string]::IsNullOrEmpty($response.delegatedFormGUID)) {
            #Create DelegatedForm
            $body = @{
                name            = $DelegatedFormName;
                dynamicFormGUID = $DynamicFormGuid;
                isEnabled       = "True";
                accessGroups    = [Object[]]($AccessGroups | ConvertFrom-Json);
                useFaIcon       = $UseFaIcon;
                faIcon          = $FaIcon;
            }    
            $body = ConvertTo-Json -InputObject $body
    
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
    
            $delegatedFormGuid = $response.delegatedFormGUID
            Write-Information "Delegated form '$DelegatedFormName' created$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormGuid })"
            $delegatedFormCreated = $true

            $bodyCategories = $Categories
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms/$delegatedFormGuid/categories")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $bodyCategories
            Write-Information "Delegated form '$DelegatedFormName' updated with categories"
        } else {
            #Get delegatedFormGUID
            $delegatedFormGuid = $response.delegatedFormGUID
            Write-Warning "Delegated form '$DelegatedFormName' already exists$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormGuid })"
        }
    } catch {
        Write-Error "Delegated form '$DelegatedFormName', message: $_"
    }

    $returnObject.value.guid = $delegatedFormGuid
    $returnObject.value.created = $delegatedFormCreated
}
<# Begin: HelloID Global Variables #>
foreach ($item in $globalHelloIDVariables) {
	Invoke-HelloIDGlobalVariable -Name $item.name -Value $item.value -Secret $item.secret 
}
<# End: HelloID Global Variables #>


<# Begin: HelloID Data sources #>
<# Begin: DataSource "Exchange-On-Premises-Update-Mailbox-Attributes-Selected-Mailbox" #>
$tmpPsScript = @'
# used global defined variables in helloid
# $ExchangeConnectionUri
# $ExchangeAdminUsername
# $ExchangeAdminPassword
# $ExchangeAuthentication

## connect to exchange and get selected mailbox
$MailboxIdentity = $datasource.selectedMailbox.Identity

try {
    $adminSecurePassword = ConvertTo-SecureString -String $ExchangeAdminPassword -AsPlainText -Force
    $adminCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ExchangeAdminUsername, $adminSecurePassword

    $sessionOptionParams = @{
        SkipCACheck         = $false
        SkipCNCheck         = $false
        SkipRevocationCheck = $false
    }

    $sessionOption = New-PSSessionOption  @SessionOptionParams 

    $sessionParams = @{
        AllowRedirection  = $true
        Authentication    = $ExchangeAuthentication 
        ConfigurationName = 'Microsoft.Exchange' 
        ConnectionUri     = $ExchangeConnectionUri 
        Credential        = $adminCredential        
        SessionOption     = $sessionOption       
    }

    $exchangeSession = New-PSSession @SessionParams
    Write-Information "Successfully connected to Exchange '$ExchangeConnectionUri'"  


    $getMailboxParams = @{
        Identity = $MailboxIdentity
               
    }
    
    $invokecommandParams = @{
        Session      = $exchangeSession
        Scriptblock  = [scriptblock] { Param ($Params)Get-Mailbox @Params }
        ArgumentList = $getMailboxParams
    }  
    
    $box = Invoke-Command @invokeCommandParams
    $resultMailboxList = [System.Collections.Generic.List[PSCustomObject]]::New()
    $resultMailbox = @{
        ExchangeGuid      = $box.ExchangeGuid
        SamAccountName    = $box.samAccountName     
        UserPrincipalName = $box.UserPrincipalName
        DistinguishedName = $box.DistinguishedName
        DisplayName       = $box.DisplayName
        Identity          = $box.Identity
        CustomAttribute1  = $box.CustomAttribute1
        CustomAttribute2  = $box.CustomAttribute2
        CustomAttribute3  = $box.CustomAttribute3
        CustomAttribute4  = $box.CustomAttribute4
        CustomAttribute5  = $box.CustomAttribute5
        CustomAttribute6  = $box.CustomAttribute6
        CustomAttribute7  = $box.CustomAttribute7
        CustomAttribute8  = $box.CustomAttribute8
        CustomAttribute9  = $box.CustomAttribute9
        CustomAttribute10 = $box.CustomAttribute10
        CustomAttribute11 = $box.CustomAttribute11
        CustomAttribute12 = $box.CustomAttribute12
        CustomAttribute13 = $box.CustomAttribute13
        CustomAttribute14 = $box.CustomAttribute14
        CustomAttribute15 = $box.CustomAttribute15
        IsdefaultSelected = $true
    }
    $resultMailboxList.add($resultMailbox)

    Write-Output $resultMailboxList
}
catch {
    Write-Error "Error getting mailbox $MailboxIdentity  using the URI '$exchangeConnectionUri', Message '$($_.Exception.Message)'"
}



'@ 
$tmpModel = @'
[{"key":"SamAccountName","type":0},{"key":"CustomAttribute12","type":0},{"key":"ExchangeGuid","type":0},{"key":"CustomAttribute8","type":0},{"key":"UserPrincipalName","type":0},{"key":"CustomAttribute11","type":0},{"key":"CustomAttribute15","type":0},{"key":"CustomAttribute1","type":0},{"key":"CustomAttribute3","type":0},{"key":"CustomAttribute9","type":0},{"key":"CustomAttribute2","type":0},{"key":"CustomAttribute13","type":0},{"key":"CustomAttribute4","type":0},{"key":"DistinguishedName","type":0},{"key":"CustomAttribute14","type":0},{"key":"CustomAttribute10","type":0},{"key":"CustomAttribute5","type":0},{"key":"DisplayName","type":0},{"key":"CustomAttribute6","type":0},{"key":"CustomAttribute7","type":0},{"key":"Identity","type":0},{"key":"IsdefaultSelected","type":0}]
'@ 
$tmpInput = @'
[{"description":"selected mailbox","translateDescription":false,"inputFieldType":1,"key":"SelectedMailbox","type":0,"options":1}]
'@ 
$dataSourceGuid_1 = [PSCustomObject]@{} 
$dataSourceGuid_1_Name = @'
Exchange-On-Premises-Update-Mailbox-Attributes-Selected-Mailbox
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_1_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_1) 
<# End: DataSource "Exchange-On-Premises-Update-Mailbox-Attributes-Selected-Mailbox" #>

<# Begin: DataSource "Exchange-On-Premises-Update-Mailbox-Attributes-GetMailbox" #>
$tmpPsScript = @'
# used global defined variables in helloid
# $ExchangeConnectionUri
# $ExchangeAdminUsername
# $ExchangeAdminPassword
# $ExchangeAuthentication
# $ExchangeUpdateMailboxAttributesSearchOU 
## connect to exchange and get list of mailboxes

try {
    $adminSecurePassword = ConvertTo-SecureString -String $ExchangeAdminPassword -AsPlainText -Force
    $adminCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ExchangeAdminUsername, $adminSecurePassword
    $searchOUs = $ExchangeUpdateMailboxAttributesSearchOU  
    $searchValue = ($dataSource.SearchMailbox).trim()
    $searchQuery = "*$searchValue*"   


    $sessionOptionParams = @{
        SkipCACheck         = $false
        SkipCNCheck         = $false
        SkipRevocationCheck = $false
    }

    $sessionOption = New-PSSessionOption  @SessionOptionParams 

    $sessionParams = @{
        AllowRedirection  = $true
        Authentication    = $ExchangeAuthentication 
        ConfigurationName = 'Microsoft.Exchange' 
        ConnectionUri     = $ExchangeConnectionUri 
        Credential        = $adminCredential        
        SessionOption     = $sessionOption       
    }

    $exchangeSession = New-PSSession @SessionParams  
    Write-Information "Successfully connected to Exchange '$ExchangeConnectionUri'"   

    Write-Information "Search query is '$searchQuery'" 
    Write-Information "Search OU is '$searchOUs'" 
    $getMailboxParams = @{
        RecipientTypeDetails = @('UserMailbox') 
        OrganizationalUnit   = $searchOUs 
        Filter               = "Name -like '$searchQuery' -or DisplayName -like '$searchQuery' -or userPrincipalName -like '$searchQuery' -or Alias -like '$searchQuery'"   
    }
    
    $invokecommandParams = @{
        Session      = $exchangeSession
        Scriptblock  = [scriptblock] { Param ($Params)Get-Mailbox @Params }
        ArgumentList = $getMailboxParams
    }  
    
    $mailBoxes = Invoke-Command @invokeCommandParams   

    $resultMailboxList = [System.Collections.Generic.List[PSCustomObject]]::New()
    foreach ($box in $mailBoxes) {
        $resultMailbox = @{
            ExchangeGuid      = $box.ExchangeGuid
            SamAccountName    = $box.samAccountName     
            UserPrincipalName = $box.UserPrincipalName
            DistinguishedName = $box.DistinguishedName
            DisplayName       = $box.DisplayName
            Identity          = $box.Identity       
        }
        $resultMailboxList.add($resultMailbox)

    }
    $resultMailboxList
    
    Remove-PSSession($exchangeSession)
  
}
catch {
    Write-Error "Error searching for mailboxes using the URI '$exchangeConnectionUri', Message '$($_.Exception.Message)'"
}

'@ 
$tmpModel = @'
[{"key":"Identity","type":0},{"key":"DisplayName","type":0},{"key":"DistinguishedName","type":0},{"key":"UserPrincipalName","type":0},{"key":"ExchangeGuid","type":0},{"key":"SamAccountName","type":0}]
'@ 
$tmpInput = @'
[{"description":"Search  filter","translateDescription":false,"inputFieldType":1,"key":"SearchMailbox","type":0,"options":1}]
'@ 
$dataSourceGuid_0 = [PSCustomObject]@{} 
$dataSourceGuid_0_Name = @'
Exchange-On-Premises-Update-Mailbox-Attributes-GetMailbox
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_0_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_0) 
<# End: DataSource "Exchange-On-Premises-Update-Mailbox-Attributes-GetMailbox" #>
<# End: HelloID Data sources #>

<# Begin: Dynamic Form "Exchange-On-Premises-Update-Mailbox-Attributes" #>
$tmpSchema = @"
[{"label":"Select mailbox","fields":[{"key":"textInput","templateOptions":{"label":"Search","required":true},"type":"input","summaryVisibility":"Hide element","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"gridMailboxList","templateOptions":{"label":"Mailbox List","required":true,"grid":{"columns":[{"headerName":"Identity","field":"Identity"},{"headerName":"Display Name","field":"DisplayName"},{"headerName":"Distinguished Name","field":"DistinguishedName"},{"headerName":"User Principal Name","field":"UserPrincipalName"},{"headerName":"Exchange Guid","field":"ExchangeGuid"},{"headerName":"Sam Account Name","field":"SamAccountName"}],"height":300,"rowSelection":"single"},"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_0","input":{"propertyInputs":[{"propertyName":"SearchMailbox","otherFieldValue":{"otherFieldKey":"textInput"}}]}},"useFilter":true,"useDefault":false},"type":"grid","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":true}]},{"label":"Edit attributes","fields":[{"key":"gridSelectedMailbox","templateOptions":{"label":"Selected Mailbox ","required":false,"grid":{"columns":[{"headerName":"Sam Account Name","field":"SamAccountName"},{"headerName":"Custom Attribute12","field":"CustomAttribute12"},{"headerName":"Exchange Guid","field":"ExchangeGuid"},{"headerName":"Custom Attribute8","field":"CustomAttribute8"},{"headerName":"User Principal Name","field":"UserPrincipalName"},{"headerName":"Custom Attribute11","field":"CustomAttribute11"},{"headerName":"Custom Attribute15","field":"CustomAttribute15"},{"headerName":"Custom Attribute1","field":"CustomAttribute1"},{"headerName":"Custom Attribute3","field":"CustomAttribute3"},{"headerName":"Custom Attribute9","field":"CustomAttribute9"},{"headerName":"Custom Attribute2","field":"CustomAttribute2"},{"headerName":"Custom Attribute13","field":"CustomAttribute13"},{"headerName":"Custom Attribute4","field":"CustomAttribute4"},{"headerName":"Distinguished Name","field":"DistinguishedName"},{"headerName":"Custom Attribute14","field":"CustomAttribute14"},{"headerName":"Custom Attribute10","field":"CustomAttribute10"},{"headerName":"Custom Attribute5","field":"CustomAttribute5"},{"headerName":"Display Name","field":"DisplayName"},{"headerName":"Custom Attribute6","field":"CustomAttribute6"},{"headerName":"Custom Attribute7","field":"CustomAttribute7"},{"headerName":"Identity","field":"Identity"},{"headerName":"Isdefault Selected","field":"IsdefaultSelected"}],"height":150,"rowSelection":"single"},"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_1","input":{"propertyInputs":[{"propertyName":"SelectedMailbox","otherFieldValue":{"otherFieldKey":"gridMailboxList"}}]}},"useDefault":true,"defaultSelectorProperty":"IsdefaultSelected"},"type":"grid","summaryVisibility":"Hide element","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":true},{"key":"textDisplayName","templateOptions":{"label":"Display name","useDependOn":true,"dependOn":"gridSelectedMailbox","dependOnProperty":"DisplayName","placeholder":"\u003cretrieving current value\u003e"},"type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"textCA1","templateOptions":{"label":"CustomAttribute1","useDependOn":true,"dependOn":"gridSelectedMailbox","dependOnProperty":"CustomAttribute1","placeholder":"\u003cretrieving current value\u003e"},"type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"textCA2","templateOptions":{"label":"CustomAttribute2","useDependOn":true,"dependOn":"gridSelectedMailbox","dependOnProperty":"CustomAttribute2","placeholder":"\u003cretrieving current value\u003e"},"type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"textCA3","templateOptions":{"label":"CustomAttribute3","useDependOn":true,"dependOn":"gridSelectedMailbox","dependOnProperty":"CustomAttribute3","placeholder":"\u003cretrieving current value\u003e"},"type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"textCA4","templateOptions":{"label":"CustomAttribute4","useDependOn":true,"dependOn":"gridSelectedMailbox","dependOnProperty":"CustomAttribute4","placeholder":"\u003cretrieving current value\u003e"},"type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"textCA5","templateOptions":{"label":"CustomAttribute5","useDependOn":true,"dependOn":"gridSelectedMailbox","dependOnProperty":"CustomAttribute5","placeholder":"\u003cretrieving current value\u003e"},"type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"textCA6","templateOptions":{"label":"CustomAttribute6","useDependOn":true,"dependOn":"gridSelectedMailbox","dependOnProperty":"CustomAttribute6","placeholder":"\u003cretrieving current value\u003e"},"type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"textCA7","templateOptions":{"label":"CustomAttribute7","useDependOn":true,"dependOn":"gridSelectedMailbox","dependOnProperty":"CustomAttribute7","placeholder":"\u003cretrieving current value\u003e"},"type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false}]}]
"@ 

$dynamicFormGuid = [PSCustomObject]@{} 
$dynamicFormName = @'
Exchange-On-Premises-Update-Mailbox-Attributes
'@ 
Invoke-HelloIDDynamicForm -FormName $dynamicFormName -FormSchema $tmpSchema  -returnObject ([Ref]$dynamicFormGuid) 
<# END: Dynamic Form #>

<# Begin: Delegated Form Access Groups and Categories #>
$delegatedFormAccessGroupGuids = @()
foreach($group in $delegatedFormAccessGroupNames) {
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/groups/$group")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        $delegatedFormAccessGroupGuid = $response.groupGuid
        $delegatedFormAccessGroupGuids += $delegatedFormAccessGroupGuid
        
        Write-Information "HelloID (access)group '$group' successfully found$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormAccessGroupGuid })"
    } catch {
        Write-Error "HelloID (access)group '$group', message: $_"
    }
}
$delegatedFormAccessGroupGuids = ($delegatedFormAccessGroupGuids | Select-Object -Unique | ConvertTo-Json -Compress)

$delegatedFormCategoryGuids = @()
foreach($category in $delegatedFormCategories) {
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/delegatedformcategories/$category")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        $tmpGuid = $response.delegatedFormCategoryGuid
        $delegatedFormCategoryGuids += $tmpGuid
        
        Write-Information "HelloID Delegated Form category '$category' successfully found$(if ($script:debugLogging -eq $true) { ": " + $tmpGuid })"
    } catch {
        Write-Warning "HelloID Delegated Form category '$category' not found"
        $body = @{
            name = @{"en" = $category};
        }
        $body = ConvertTo-Json -InputObject $body

        $uri = ($script:PortalBaseUrl +"api/v1/delegatedformcategories")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
        $tmpGuid = $response.delegatedFormCategoryGuid
        $delegatedFormCategoryGuids += $tmpGuid

        Write-Information "HelloID Delegated Form category '$category' successfully created$(if ($script:debugLogging -eq $true) { ": " + $tmpGuid })"
    }
}
$delegatedFormCategoryGuids = (ConvertTo-Json -InputObject $delegatedFormCategoryGuids -Compress)
<# End: Delegated Form Access Groups and Categories #>

<# Begin: Delegated Form #>
$delegatedFormRef = [PSCustomObject]@{guid = $null; created = $null} 
$delegatedFormName = @'
Exchange-On-Premises-Update-Mailbox-Attributes
'@
Invoke-HelloIDDelegatedForm -DelegatedFormName $delegatedFormName -DynamicFormGuid $dynamicFormGuid -AccessGroups $delegatedFormAccessGroupGuids -Categories $delegatedFormCategoryGuids -UseFaIcon "True" -FaIcon "fa fa-file-text-o" -returnObject ([Ref]$delegatedFormRef) 
<# End: Delegated Form #>

<# Begin: Delegated Form Task #>
if($delegatedFormRef.created -eq $true) { 
	$tmpScript = @'
# used global defined variables in helloid
# $ExchangeConnectionUri
# $ExchangeAdminUsername
# $ExchangeAdminPassword
# $ExchangeAuthentication

## connect to exchange and get list of mailboxes

try {
    $adminSecurePassword = ConvertTo-SecureString -String $ExchangeAdminPassword -AsPlainText -Force
    $adminCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ExchangeAdminUsername, $adminSecurePassword

    $sessionOptionParams = @{
        SkipCACheck         = $false
        SkipCNCheck         = $false
        SkipRevocationCheck = $false
    }

    $sessionOption = New-PSSessionOption  @SessionOptionParams 

    $sessionParams = @{
        AllowRedirection  = $true
        Authentication    = $ExchangeAuthentication 
        ConfigurationName = 'Microsoft.Exchange' 
        ConnectionUri     = $ExchangeConnectionUri 
        Credential        = $adminCredential        
        SessionOption     = $sessionOption       
    }

    $exchangeSession = New-PSSession @SessionParams
    HID-Write-Status -Message "Successfully connected to Exchange '$ExchangeConnectionUri'" -Event Information

    $SetMailboxParams = @{
        identity = $MailboxIdentity  
    } 
    if ( -not ($null -eq $MailboxDisplayName)) {
      
        $SetMailboxParams.add("DisplayName", $MailboxDisplayName)     
    }
    if ( -not ($null -eq $CustomAttribute1)) {
        $SetMailboxParams.add("CustomAttribute1", $CustomAttribute1)     
    }
    if ( -not ($null -eq $CustomAttribute2)) {
        $SetMailboxParams.add("CustomAttribute2", $CustomAttribute2)     
    }
    if ( -not ($null -eq $CustomAttribute3)) {
        $SetMailboxParams.add("CustomAttribute3", $CustomAttribute3)     
    }
    if ( -not ($null -eq $CustomAttribute4)) {
        $SetMailboxParams.add("CustomAttribute4", $CustomAttribute4)     
    }
    if ( -not ($null -eq $CustomAttribute5)) {
        $SetMailboxParams.add("CustomAttribute5", $CustomAttribute5)     
    }
    if ( -not ($null -eq $CustomAttribute6)) {
        $SetMailboxParams.add("CustomAttribute6", $CustomAttribute6)     
    }
    if ( -not ($null -eq $CustomAttribute7)) {
        $SetMailboxParams.add("CustomAttribute7", $CustomAttribute7)     
    }    

    $invokecommandParams = @{
        Session      = $exchangeSession
        Scriptblock  = [scriptblock] { Param ($Params)Set-Mailbox @Params }
        ArgumentList = $SetMailboxParams
    }  
  
    $null = Invoke-Command @invokeCommandParams
     
    HID-Write-Status -Message "Succesfully updated mailbox $MailboxIdentity" -Event Success
    HID-Write-Summary -Message "Succesfully updated mailbox attributes for $MailboxIdentity" -Event Success   
    
    Remove-PSSession($exchangeSession)
  
}
catch {
    HID-Write-Status "Error updating mailbox $MailboxIdentity using the URI '$exchangeConnectionUri', Message: '$($_.Exception.Message)'" -Event Error
    HID-Write-Summary -Message "Failed to updated mailbox attributes for  $MailboxIdentity"  -Event Failed
}


'@; 

	$tmpVariables = @'
[{"name":"CustomAttribute3","value":"{{form.textCA3}}","secret":false,"typeConstraint":"string"},{"name":"CustomAttribute4","value":"{{form.textCA4}}","secret":false,"typeConstraint":"string"},{"name":"CustomAttribute1","value":"{{form.textCA1}}","secret":false,"typeConstraint":"string"},{"name":"CustomAttribute5","value":"{{form.textCA5}}","secret":false,"typeConstraint":"string"},{"name":"CustomAttribute6","value":"{{form.textCA6}}","secret":false,"typeConstraint":"string"},{"name":"CustomAttribute7","value":"{{form.textCA7}}","secret":false,"typeConstraint":"string"},{"name":"CustomAttribute2","value":"{{form.textCA2}}","secret":false,"typeConstraint":"string"},{"name":"MailboxIdentity","value":"{{form.gridSelectedMailbox.Identity}}","secret":false,"typeConstraint":"string"}]
'@ 

	$delegatedFormTaskGuid = [PSCustomObject]@{} 
$delegatedFormTaskName = @'
Exchange-On-Premises-Update-Mailbox-Attributes
'@
	Invoke-HelloIDAutomationTask -TaskName $delegatedFormTaskName -UseTemplate "False" -AutomationContainer "8" -Variables $tmpVariables -PowershellScript $tmpScript -ObjectGuid $delegatedFormRef.guid -ForceCreateTask $true -returnObject ([Ref]$delegatedFormTaskGuid) 
} else {
	Write-Warning "Delegated form '$delegatedFormName' already exists. Nothing to do with the Delegated Form task..." 
}
<# End: Delegated Form Task #>
