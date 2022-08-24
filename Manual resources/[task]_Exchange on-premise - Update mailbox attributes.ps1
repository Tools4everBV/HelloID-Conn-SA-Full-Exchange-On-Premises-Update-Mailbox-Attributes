$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# variables configured in form
$MailboxIdentity = $form.gridSelectedMailbox.Identity
$MailboxDisplayName = $form.gridSelectedMailbox.DisplayName
$ExchangeGuid = $form.gridSelectedMailbox.ExchangeGuid
$CustomAttribute1 = $form.textCA1
$CustomAttribute2 = $form.textCA2
$CustomAttribute3 = $form.textCA3
$CustomAttribute4 = $form.textCA4
$CustomAttribute5 = $form.textCA5
$CustomAttribute6 = $form.textCA6
$CustomAttribute7 = $form.textCA7

# Connect to Exchange
try {
    $adminSecurePassword = ConvertTo-SecureString -String "$ExchangeAdminPassword" -AsPlainText -Force
    $adminCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ExchangeAdminUsername, $adminSecurePassword
    $sessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
    $exchangeSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $exchangeConnectionUri -Credential $adminCredential -SessionOption $sessionOption -ErrorAction Stop 
    #-AllowRedirection
    $session = Import-PSSession $exchangeSession -DisableNameChecking -AllowClobber
    Write-Information "Successfully connected to Exchange using the URI [$exchangeConnectionUri]" 
    
    $Log = @{
        Action            = "UpdateAccount" # optional. ENUM (undefined = default) 
        System            = "Exchange On-Premise" # optional (free format text) 
        Message           = "Successfully connected to Exchange using the URI [$exchangeConnectionUri]" # required (free format text) 
        IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
        TargetDisplayName = $exchangeConnectionUri # optional (free format text) 
        TargetIdentifier  = $([string]$session.GUID) # optional (free format text) 
    }
    #send result back  
    Write-Information -Tags "Audit" -MessageData $log
}
catch {
    Write-Error "Error connecting to Exchange using the URI [$exchangeConnectionUri]. Error: $($_.Exception.Message)"
    $Log = @{
        Action            = "UpdateAccount" # optional. ENUM (undefined = default) 
        System            = "Exchange On-Premise" # optional (free format text) 
        Message           = "Failed to connect to Exchange using the URI [$exchangeConnectionUri]." # required (free format text) 
        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
        TargetDisplayName = $exchangeConnectionUri # optional (free format text) 
        TargetIdentifier  = $([string]$session.GUID) # optional (free format text) 
    }
    #send result back  
    Write-Information -Tags "Audit" -MessageData $log
}

try {
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
  
    $null = Invoke-Command @invokeCommandParams -ErrorAction Stop
     
    Write-Information "Succesfully updated mailbox [$MailboxIdentity]"
    $Log = @{
        Action            = "UpdateAccount" # optional. ENUM (undefined = default) 
        System            = "Exchange On-Premise" # optional (free format text) 
        Message           = "Succesfully updated mailbox [$MailboxIdentity]." # required (free format text) 
        IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
        TargetDisplayName = $MailboxDisplayName # optional (free format text) 
        TargetIdentifier  = [string]$ExchangeGuid # optional (free format text) 
    }
    #send result back  
    Write-Information -Tags "Audit" -MessageData $log
}
catch {
    Write-Error "Error updating mailbox [$MailboxIdentity] using the URI [$exchangeConnectionUri]. Error: '$($_.Exception.Message)'"
    $Log = @{
        Action            = "UpdateAccount" # optional. ENUM (undefined = default) 
        System            = "Exchange On-Premise" # optional (free format text) 
        Message           = "Failed to updated mailbox attributes for [$MailboxIdentity]." # required (free format text) 
        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
        TargetDisplayName = $MailboxDisplayName # optional (free format text) 
        TargetIdentifier  = [string]$ExchangeGuid # optional (free format text) 
    }
    #send result back  
    Write-Information -Tags "Audit" -MessageData $log    
}

# Disconnect from Exchange
try {
    Remove-PsSession -Session $exchangeSession -Confirm:$false -ErrorAction Stop
    Write-Information "Successfully disconnected from Exchange using the URI [$exchangeConnectionUri]"     
    $Log = @{
        Action            = "UpdateAccount" # optional. ENUM (undefined = default) 
        System            = "Exchange On-Premise" # optional (free format text) 
        Message           = "Successfully disconnected from Exchange using the URI [$exchangeConnectionUri]" # required (free format text) 
        IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
        TargetDisplayName = $exchangeConnectionUri # optional (free format text) 
        TargetIdentifier  = $([string]$session.GUID) # optional (free format text) 
    }
    #send result back  
    Write-Information -Tags "Audit" -MessageData $log
}
catch {
    Write-Error "Error disconnecting from Exchange.  Error: $($_.Exception.Message)"
    $Log = @{
        Action            = "UpdateAccount" # optional. ENUM (undefined = default) 
        System            = "Exchange On-Premise" # optional (free format text) 
        Message           = "Failed to disconnect from Exchange using the URI [$exchangeConnectionUri]." # required (free format text) 
        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
        TargetDisplayName = $exchangeConnectionUri # optional (free format text) 
        TargetIdentifier  = $([string]$session.GUID) # optional (free format text) 
    }
    #send result back  
    Write-Information -Tags "Audit" -MessageData $log
}
<#----- Exchange On-Premises: End -----#>

