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

