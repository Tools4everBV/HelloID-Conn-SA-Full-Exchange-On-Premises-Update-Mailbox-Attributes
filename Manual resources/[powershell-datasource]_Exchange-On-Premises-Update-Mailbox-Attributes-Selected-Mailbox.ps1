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



