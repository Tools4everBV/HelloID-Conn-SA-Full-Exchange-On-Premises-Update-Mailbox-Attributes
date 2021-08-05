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


