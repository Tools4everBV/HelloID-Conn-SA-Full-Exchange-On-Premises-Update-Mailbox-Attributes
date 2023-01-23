# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

#HelloID variables
#Note: when running this script inside HelloID; portalUrl and API credentials are provided automatically (generate and save API credentials first in your admin panel!)
$portalUrl = "https://CUSTOMER.helloid.com"
$apiKey = "API_KEY"
$apiSecret = "API_SECRET"
$delegatedFormAccessGroupNames = @("Users") #Only unique names are supported. Groups must exist!
$delegatedFormCategories = @("Exchange Administration","Exchange On-Premise") #Only unique names are supported. Categories will be created if not exists
$script:debugLogging = $false #Default value: $false. If $true, the HelloID resource GUIDs will be shown in the logging
$script:duplicateForm = $false #Default value: $false. If $true, the HelloID resource names will be changed to import a duplicate Form
$script:duplicateFormSuffix = "_tmp" #the suffix will be added to all HelloID resource names to generate a duplicate form with different resource names

#The following HelloID Global variables are used by this form. No existing HelloID global variables will be overriden only new ones are created.
#NOTE: You can also update the HelloID Global variable values afterwards in the HelloID Admin Portal: https://<CUSTOMER>.helloid.com/admin/variablelibrary
$globalHelloIDVariables = [System.Collections.Generic.List[object]]@();

#Global variable #1 >> ExchangeConnectionUri
$tmpName = @'
ExchangeConnectionUri
'@ 
$tmpValue = "" 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});

#Global variable #2 >> ExchangeAdminPassword
$tmpName = @'
ExchangeAdminPassword
'@ 
$tmpValue = ""  
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});

#Global variable #3 >> ExchangeAdminUsername
$tmpName = @'
ExchangeAdminUsername
'@ 
$tmpValue = ""  
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});

#Global variable #4 >> ExchangeAuthentication
$tmpName = @'
ExchangeAuthentication
'@ 
$tmpValue = @'
kerberos
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});

#Global variable #5 >> ExchangeSearchOU
$tmpName = @'
ExchangeSearchOU
'@ 
$tmpValue = @'
Enyoi.local/HelloID
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

# Make sure to reveive an empty array using PowerShell Core
function ConvertFrom-Json-WithEmptyArray([string]$jsonString) {
    # Running in PowerShell Core?
    if($IsCoreCLR -eq $true){
        $r = [Object[]]($jsonString | ConvertFrom-Json -NoEnumerate)
        return ,$r  # Force return value to be an array using a comma
    } else {
        $r = [Object[]]($jsonString | ConvertFrom-Json)
        return ,$r  # Force return value to be an array using a comma
    }
}

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
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
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
                variables           = (ConvertFrom-Json-WithEmptyArray($Variables));
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
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
                model              = (ConvertFrom-Json-WithEmptyArray($DatasourceModel));
                automationTaskGUID = $AutomationTaskGuid;
                value              = (ConvertFrom-Json-WithEmptyArray($DatasourceStaticValue));
                script             = $DatasourcePsScript;
                input              = (ConvertFrom-Json-WithEmptyArray($DatasourceInput));
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
      
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
                FormSchema = (ConvertFrom-Json-WithEmptyArray($FormSchema));
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
        [parameter()][Array][AllowEmptyString()]$AccessGroups,
        [parameter()][String][AllowEmptyString()]$Categories,
        [parameter(Mandatory)][String]$UseFaIcon,
        [parameter()][String][AllowEmptyString()]$FaIcon,
        [parameter()][String][AllowEmptyString()]$task,
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
                useFaIcon       = $UseFaIcon;
                faIcon          = $FaIcon;
                task            = ConvertFrom-Json -inputObject $task;
            }
            if(-not[String]::IsNullOrEmpty($AccessGroups)) { 
                $body += @{
                    accessGroups    = (ConvertFrom-Json-WithEmptyArray($AccessGroups));
                }
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
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
    $adminCredential = [System.Management.Automation.PSCredential]::new($ExchangeAdminUsername,$adminSecurePassword)

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
[{"key":"CustomAttribute4","type":0},{"key":"ExchangeGuid","type":0},{"key":"CustomAttribute7","type":0},{"key":"CustomAttribute10","type":0},{"key":"DistinguishedName","type":0},{"key":"CustomAttribute1","type":0},{"key":"UserPrincipalName","type":0},{"key":"CustomAttribute5","type":0},{"key":"CustomAttribute2","type":0},{"key":"CustomAttribute15","type":0},{"key":"CustomAttribute9","type":0},{"key":"CustomAttribute14","type":0},{"key":"CustomAttribute11","type":0},{"key":"CustomAttribute12","type":0},{"key":"DisplayName","type":0},{"key":"CustomAttribute8","type":0},{"key":"SamAccountName","type":0},{"key":"IsdefaultSelected","type":0},{"key":"CustomAttribute13","type":0},{"key":"CustomAttribute3","type":0},{"key":"Identity","type":0},{"key":"CustomAttribute6","type":0}]
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
# Connect to Exchange
try {
    $adminSecurePassword = ConvertTo-SecureString -String "$ExchangeAdminPassword" -AsPlainText -Force
    $adminCredential = [System.Management.Automation.PSCredential]::new($ExchangeAdminUsername,$adminSecurePassword)
    $sessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
    $exchangeSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $exchangeConnectionUri -Credential $adminCredential -SessionOption $sessionOption -ErrorAction Stop 
    #-AllowRedirection
    $null = Import-PSSession $exchangeSession -DisableNameChecking -AllowClobber
    Write-Information "Successfully connected to Exchange using the URI [$exchangeConnectionUri]"         
}
catch {
    Write-Error "Error connecting to Exchange using the URI [$exchangeConnectionUri]. Error: $($_.Exception.Message)"    
}

try {
    $searchValue = $dataSource.searchMailbox
    $searchQuery = "*$searchValue*"
    $searchOUs = $ExchangeSearchOU

    Write-Information "Search query is '$searchQuery'" 
    Write-Information "Search OU is '$searchOUs'" 

    $getMailboxParams = @{
        RecipientTypeDetails = @('UserMailbox') 
        OrganizationalUnit   = $searchOUs 
        Filter               = "{Name -like '$searchQuery' -or DisplayName -like '$searchQuery' -or userPrincipalName -like '$searchQuery' -or Alias -like '$searchQuery'}"   
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
  
}
catch {
    Write-Error "Error searching for mailboxes using the URI '$exchangeConnectionUri', Message '$($_.Exception.Message)'"
}

# Disconnect from Exchange
try {
    Remove-PsSession -Session $exchangeSession -Confirm:$false -ErrorAction Stop
    Write-Information "Successfully disconnected from Exchange using the URI [$exchangeConnectionUri]"         
}
catch {
    Write-Error "Error disconnecting from Exchange.  Error: $($_.Exception.Message)"    
}
<#----- Exchange On-Premises: End -----#>
'@ 
$tmpModel = @'
[{"key":"Identity","type":0},{"key":"SamAccountName","type":0},{"key":"DistinguishedName","type":0},{"key":"DisplayName","type":0},{"key":"ExchangeGuid","type":0},{"key":"UserPrincipalName","type":0}]
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

<# Begin: Dynamic Form "Exchange on-premise - Update mailbox attributes" #>
$tmpSchema = @"
[{"label":"Select mailbox","fields":[{"key":"textInput","templateOptions":{"label":"Search","required":true},"type":"input","summaryVisibility":"Hide element","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"gridMailboxList","templateOptions":{"label":"Mailbox List","required":true,"grid":{"columns":[{"headerName":"Identity","field":"Identity"},{"headerName":"Display Name","field":"DisplayName"},{"headerName":"Distinguished Name","field":"DistinguishedName"},{"headerName":"User Principal Name","field":"UserPrincipalName"},{"headerName":"Exchange Guid","field":"ExchangeGuid"},{"headerName":"Sam Account Name","field":"SamAccountName"}],"height":300,"rowSelection":"single"},"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_0","input":{"propertyInputs":[{"propertyName":"SearchMailbox","otherFieldValue":{"otherFieldKey":"textInput"}}]}},"useFilter":true,"useDefault":false},"type":"grid","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":true}]},{"label":"Edit attributes","fields":[{"key":"gridSelectedMailbox","templateOptions":{"label":"Selected Mailbox ","required":false,"grid":{"columns":[{"headerName":"Display Name","field":"DisplayName"},{"headerName":"Sam Account Name","field":"SamAccountName"},{"headerName":"User Principal Name","field":"UserPrincipalName"},{"headerName":"Distinguished Name","field":"DistinguishedName"},{"headerName":"Custom Attribute1","field":"CustomAttribute1"},{"headerName":"Custom Attribute2","field":"CustomAttribute2"},{"headerName":"Custom Attribute3","field":"CustomAttribute3"},{"headerName":"Custom Attribute4","field":"CustomAttribute4"},{"headerName":"Custom Attribute5","field":"CustomAttribute5"},{"headerName":"Custom Attribute6","field":"CustomAttribute6"},{"headerName":"Custom Attribute7","field":"CustomAttribute7"},{"headerName":"Custom Attribute8","field":"CustomAttribute8"},{"headerName":"Custom Attribute9","field":"CustomAttribute9"},{"headerName":"Custom Attribute10","field":"CustomAttribute10"},{"headerName":"Custom Attribute11","field":"CustomAttribute11"},{"headerName":"Custom Attribute12","field":"CustomAttribute12"},{"headerName":"Custom Attribute13","field":"CustomAttribute13"},{"headerName":"Custom Attribute14","field":"CustomAttribute14"},{"headerName":"Custom Attribute15","field":"CustomAttribute15"},{"headerName":"Identity","field":"Identity"},{"headerName":"Exchange Guid","field":"ExchangeGuid"},{"headerName":"Isdefault Selected","field":"IsdefaultSelected"}],"height":150,"rowSelection":"single"},"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_1","input":{"propertyInputs":[{"propertyName":"SelectedMailbox","otherFieldValue":{"otherFieldKey":"gridMailboxList"}}]}},"useDefault":true,"defaultSelectorProperty":"IsdefaultSelected"},"type":"grid","summaryVisibility":"Hide element","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":true},{"key":"textDisplayName","templateOptions":{"label":"Display name","useDependOn":true,"dependOn":"gridSelectedMailbox","dependOnProperty":"DisplayName","placeholder":"\u003cretrieving current value\u003e"},"type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"textCA1","templateOptions":{"label":"CustomAttribute1","useDependOn":true,"dependOn":"gridSelectedMailbox","dependOnProperty":"CustomAttribute1","placeholder":"\u003cretrieving current value\u003e"},"type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"textCA2","templateOptions":{"label":"CustomAttribute2","useDependOn":true,"dependOn":"gridSelectedMailbox","dependOnProperty":"CustomAttribute2","placeholder":"\u003cretrieving current value\u003e"},"type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"textCA3","templateOptions":{"label":"CustomAttribute3","useDependOn":true,"dependOn":"gridSelectedMailbox","dependOnProperty":"CustomAttribute3","placeholder":"\u003cretrieving current value\u003e"},"type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"textCA4","templateOptions":{"label":"CustomAttribute4","useDependOn":true,"dependOn":"gridSelectedMailbox","dependOnProperty":"CustomAttribute4","placeholder":"\u003cretrieving current value\u003e"},"type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"textCA5","templateOptions":{"label":"CustomAttribute5","useDependOn":true,"dependOn":"gridSelectedMailbox","dependOnProperty":"CustomAttribute5","placeholder":"\u003cretrieving current value\u003e"},"type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"textCA6","templateOptions":{"label":"CustomAttribute6","useDependOn":true,"dependOn":"gridSelectedMailbox","dependOnProperty":"CustomAttribute6","placeholder":"\u003cretrieving current value\u003e"},"type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"textCA7","templateOptions":{"label":"CustomAttribute7","useDependOn":true,"dependOn":"gridSelectedMailbox","dependOnProperty":"CustomAttribute7","placeholder":"\u003cretrieving current value\u003e"},"type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false}]}]
"@ 

$dynamicFormGuid = [PSCustomObject]@{} 
$dynamicFormName = @'
Exchange on-premise - Update mailbox attributes
'@ 
Invoke-HelloIDDynamicForm -FormName $dynamicFormName -FormSchema $tmpSchema  -returnObject ([Ref]$dynamicFormGuid) 
<# END: Dynamic Form #>

<# Begin: Delegated Form Access Groups and Categories #>
$delegatedFormAccessGroupGuids = @()
if(-not[String]::IsNullOrEmpty($delegatedFormAccessGroupNames)){
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
    if($null -ne $delegatedFormAccessGroupGuids){
        $delegatedFormAccessGroupGuids = ($delegatedFormAccessGroupGuids | Select-Object -Unique | ConvertTo-Json -Depth 100 -Compress)
    }
}

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
        $body = ConvertTo-Json -InputObject $body -Depth 100

        $uri = ($script:PortalBaseUrl +"api/v1/delegatedformcategories")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
        $tmpGuid = $response.delegatedFormCategoryGuid
        $delegatedFormCategoryGuids += $tmpGuid

        Write-Information "HelloID Delegated Form category '$category' successfully created$(if ($script:debugLogging -eq $true) { ": " + $tmpGuid })"
    }
}
$delegatedFormCategoryGuids = (ConvertTo-Json -InputObject $delegatedFormCategoryGuids -Depth 100 -Compress)
<# End: Delegated Form Access Groups and Categories #>

<# Begin: Delegated Form #>
$delegatedFormRef = [PSCustomObject]@{guid = $null; created = $null} 
$delegatedFormName = @'
Exchange on-premise - Update mailbox attributes
'@
$tmpTask = @'
{"name":"Exchange on-premise - Update mailbox attributes","script":"$VerbosePreference = \"SilentlyContinue\"\r\n$InformationPreference = \"Continue\"\r\n$WarningPreference = \"Continue\"\r\n\r\n# variables configured in form\r\n$MailboxIdentity = $form.gridSelectedMailbox.Identity\r\n$MailboxDisplayName = $form.gridSelectedMailbox.DisplayName\r\n$ExchangeGuid = $form.gridSelectedMailbox.ExchangeGuid\r\n$CustomAttribute1 = $form.textCA1\r\n$CustomAttribute2 = $form.textCA2\r\n$CustomAttribute3 = $form.textCA3\r\n$CustomAttribute4 = $form.textCA4\r\n$CustomAttribute5 = $form.textCA5\r\n$CustomAttribute6 = $form.textCA6\r\n$CustomAttribute7 = $form.textCA7\r\n\r\n# Connect to Exchange\r\ntry {\r\n    $adminSecurePassword = ConvertTo-SecureString -String \"$ExchangeAdminPassword\" -AsPlainText -Force\r\n    $adminCredential = [System.Management.Automation.PSCredential]::new($ExchangeAdminUsername,$adminSecurePassword)\r\n    $sessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck\r\n    $exchangeSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $exchangeConnectionUri -Credential $adminCredential -SessionOption $sessionOption -ErrorAction Stop \r\n    #-AllowRedirection\r\n    $session = Import-PSSession $exchangeSession -DisableNameChecking -AllowClobber\r\n    Write-Information \"Successfully connected to Exchange using the URI [$exchangeConnectionUri]\" \r\n    \r\n    $Log = @{\r\n        Action            = \"UpdateAccount\" # optional. ENUM (undefined = default) \r\n        System            = \"Exchange On-Premise\" # optional (free format text) \r\n        Message           = \"Successfully connected to Exchange using the URI [$exchangeConnectionUri]\" # required (free format text) \r\n        IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n        TargetDisplayName = $exchangeConnectionUri # optional (free format text) \r\n        TargetIdentifier  = $([string]$session.GUID) # optional (free format text) \r\n    }\r\n    #send result back  \r\n    Write-Information -Tags \"Audit\" -MessageData $log\r\n}\r\ncatch {\r\n    Write-Error \"Error connecting to Exchange using the URI [$exchangeConnectionUri]. Error: $($_.Exception.Message)\"\r\n    $Log = @{\r\n        Action            = \"UpdateAccount\" # optional. ENUM (undefined = default) \r\n        System            = \"Exchange On-Premise\" # optional (free format text) \r\n        Message           = \"Failed to connect to Exchange using the URI [$exchangeConnectionUri].\" # required (free format text) \r\n        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n        TargetDisplayName = $exchangeConnectionUri # optional (free format text) \r\n        TargetIdentifier  = $([string]$session.GUID) # optional (free format text) \r\n    }\r\n    #send result back  \r\n    Write-Information -Tags \"Audit\" -MessageData $log\r\n}\r\n\r\ntry {\r\n    $SetMailboxParams = @{\r\n        identity = $MailboxIdentity  \r\n    } \r\n    if ( -not ($null -eq $MailboxDisplayName)) {      \r\n        $SetMailboxParams.add(\"DisplayName\", $MailboxDisplayName)     \r\n    }\r\n    if ( -not ($null -eq $CustomAttribute1)) {\r\n        $SetMailboxParams.add(\"CustomAttribute1\", $CustomAttribute1)     \r\n    }\r\n    if ( -not ($null -eq $CustomAttribute2)) {\r\n        $SetMailboxParams.add(\"CustomAttribute2\", $CustomAttribute2)     \r\n    }\r\n    if ( -not ($null -eq $CustomAttribute3)) {\r\n        $SetMailboxParams.add(\"CustomAttribute3\", $CustomAttribute3)     \r\n    }\r\n    if ( -not ($null -eq $CustomAttribute4)) {\r\n        $SetMailboxParams.add(\"CustomAttribute4\", $CustomAttribute4)     \r\n    }\r\n    if ( -not ($null -eq $CustomAttribute5)) {\r\n        $SetMailboxParams.add(\"CustomAttribute5\", $CustomAttribute5)     \r\n    }\r\n    if ( -not ($null -eq $CustomAttribute6)) {\r\n        $SetMailboxParams.add(\"CustomAttribute6\", $CustomAttribute6)     \r\n    }\r\n    if ( -not ($null -eq $CustomAttribute7)) {\r\n        $SetMailboxParams.add(\"CustomAttribute7\", $CustomAttribute7)     \r\n    }    \r\n\r\n    $invokecommandParams = @{\r\n        Session      = $exchangeSession\r\n        Scriptblock  = [scriptblock] { Param ($Params)Set-Mailbox @Params }\r\n        ArgumentList = $SetMailboxParams\r\n    }  \r\n  \r\n    $null = Invoke-Command @invokeCommandParams -ErrorAction Stop\r\n     \r\n    Write-Information \"Succesfully updated mailbox [$MailboxIdentity]\"\r\n    $Log = @{\r\n        Action            = \"UpdateAccount\" # optional. ENUM (undefined = default) \r\n        System            = \"Exchange On-Premise\" # optional (free format text) \r\n        Message           = \"Succesfully updated mailbox [$MailboxIdentity].\" # required (free format text) \r\n        IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n        TargetDisplayName = $MailboxDisplayName # optional (free format text) \r\n        TargetIdentifier  = [string]$ExchangeGuid # optional (free format text) \r\n    }\r\n    #send result back  \r\n    Write-Information -Tags \"Audit\" -MessageData $log\r\n}\r\ncatch {\r\n    Write-Error \"Error updating mailbox [$MailboxIdentity] using the URI [$exchangeConnectionUri]. Error: \u0027$($_.Exception.Message)\u0027\"\r\n    $Log = @{\r\n        Action            = \"UpdateAccount\" # optional. ENUM (undefined = default) \r\n        System            = \"Exchange On-Premise\" # optional (free format text) \r\n        Message           = \"Failed to updated mailbox attributes for [$MailboxIdentity].\" # required (free format text) \r\n        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n        TargetDisplayName = $MailboxDisplayName # optional (free format text) \r\n        TargetIdentifier  = [string]$ExchangeGuid # optional (free format text) \r\n    }\r\n    #send result back  \r\n    Write-Information -Tags \"Audit\" -MessageData $log    \r\n}\r\n\r\n# Disconnect from Exchange\r\ntry {\r\n    Remove-PsSession -Session $exchangeSession -Confirm:$false -ErrorAction Stop\r\n    Write-Information \"Successfully disconnected from Exchange using the URI [$exchangeConnectionUri]\"     \r\n    $Log = @{\r\n        Action            = \"UpdateAccount\" # optional. ENUM (undefined = default) \r\n        System            = \"Exchange On-Premise\" # optional (free format text) \r\n        Message           = \"Successfully disconnected from Exchange using the URI [$exchangeConnectionUri]\" # required (free format text) \r\n        IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n        TargetDisplayName = $exchangeConnectionUri # optional (free format text) \r\n        TargetIdentifier  = $([string]$session.GUID) # optional (free format text) \r\n    }\r\n    #send result back  \r\n    Write-Information -Tags \"Audit\" -MessageData $log\r\n}\r\ncatch {\r\n    Write-Error \"Error disconnecting from Exchange.  Error: $($_.Exception.Message)\"\r\n    $Log = @{\r\n        Action            = \"UpdateAccount\" # optional. ENUM (undefined = default) \r\n        System            = \"Exchange On-Premise\" # optional (free format text) \r\n        Message           = \"Failed to disconnect from Exchange using the URI [$exchangeConnectionUri].\" # required (free format text) \r\n        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n        TargetDisplayName = $exchangeConnectionUri # optional (free format text) \r\n        TargetIdentifier  = $([string]$session.GUID) # optional (free format text) \r\n    }\r\n    #send result back  \r\n    Write-Information -Tags \"Audit\" -MessageData $log\r\n}\r\n\u003c#----- Exchange On-Premises: End -----#\u003e\r\n","runInCloud":false}
'@ 

Invoke-HelloIDDelegatedForm -DelegatedFormName $delegatedFormName -DynamicFormGuid $dynamicFormGuid -AccessGroups $delegatedFormAccessGroupGuids -Categories $delegatedFormCategoryGuids -UseFaIcon "True" -FaIcon "fa fa-file-text-o" -task $tmpTask -returnObject ([Ref]$delegatedFormRef) 
<# End: Delegated Form #>

