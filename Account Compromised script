
<#
-Run AV scan on client machine.  - Wont be included as part of the script
 
-Locate where the compromise originated from
 
-Remove any rules that have been put in including mail forwards, automatic replies and sweep rules.
 
-Check account has not been blacklisted by the mail filter and Office 365. 
 
-Block any IP’s or email addresses to prevent further spreading.
 
-Review security and provide recommendations to the customer and account manager such as MFA if not enabled 
 



#>
#Publisher: James.elliott
#Vertion: 5.1 live
#Date: 27/07/2023
#Change log: 
# Unified Audit Log now working takes a while to run on all users so moved this step to the end
<#

Known issues 


New-ComplianceSearchAction : A parameter cannot be found that matches parameter name 'Preview'. Fixed needs the azuread preview module 

Get-AzureADAuditSignInLogs : Error occurred while executing GetAuditSignInLogs Code: Authentication_RequestFromNonPremiumTenantOrB2CTenant Message: Neither tenant is B2C or tenant doesn't have premium license - Looking for fix dosent happen on all tennenets 



The term 'Add-IPBlockListEntry' is not recognised - Potentially issues with installing the module 



#>
 




write-host "*******************************************************************************"
Write-Host "------  Account Compromised Script By Mr Powershell JElliott             ------" -ForegroundColor Green
Write-Host "------  This script does the following:                                  ------"
Write-Host "------   -Connect to MSOnline, AzureADPreview & ExchangeOnlineManagement ------"
Write-Host "------   -Blocking Sign-ins                                              ------"
Write-Host "------   -Revokes Azure ADUser All Refresh Token                         ------"
Write-Host "------   -365 and Azure ADAudit logs to csv                              ------"
Write-Host "------   -Check IP blacklists                                            ------"
Write-Host "------   -Blocked malicious IPs from 365                                 ------"
Write-Host "------   -Checks inbox rules and exports log to csv                      ------"
Write-Host "------   -Removes inbox rules                                            ------"
Write-Host "------   -Runs Compliance Search and exports log to csv                  ------"
Write-Host "------   -Purge deletes malicious email from Compliance Search           ------"
Write-Host "------   -Reset 365 Password                                             ------"
write-host "*******************************************************************************"


#write-warning "Admin account and tennant prerequisites - You will require eDiscovery Manager permissions and need UnifiedAuditLogIngestionEnabled to get the best results"



Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -force


Write-Host "This can be ran as a none admin :)" -ForegroundColor Green


Write-Host "Checking Modules are installed......" 

if (Get-Module -ListAvailable -Name MSOnline) {
Write-Host "MSOnline Module is already installed"
}
else {
Write-Host "Installing Graph Module"
Install-Module Microsoft.Graph -Scope CurrentUser -force
}

#Import-Module  Microsoft.Graph

if (Get-Module -ListAvailable -Name AzureADPreview) {
Write-Host "AzureADPreview Module is already installed"
}
else {
Write-Host "Installing AzureADPreview Module"
Install-Module -Name AzureADPreview -Scope CurrentUser -force
}

Import-Module AzureADPreview


if (Get-Module -ListAvailable -Name ExchangeOnlineManagement) {
Write-Host "ExchangeOnlineManagement Module is already installed"
}
else {
Write-Host "Installing ExchangeOnlineManagement Module"
Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -force
}

Import-Module ExchangeOnlineManagement


if (Get-Module -ListAvailable -Name PSBlackListChecker) {
Write-Host "PSBlackListChecker Module is already installed"
}
else {
Write-Host "Installing PSBlackListChecker Module"
Install-Module -Name PSBlackListChecker -Scope CurrentUser -force
}

Import-Module PSBlackListChecker









$reply = Read-Host -Prompt "Connect to Microsoft services[y/n]"
if ( $reply -match "[nN]" ) {




} 
if ( $reply -match "[yY]" ) { 

$adminName = Read-Host -Prompt "Enter 365 tennant admin email" 

Write-Host "Connecting to Microsoft services" -ForegroundColor Green

#Import-Module MSOnline Retired
#Connect-MsolService 



Connect-MgGraph -Scopes "User.Read.All", "Group.ReadWrite.All"



Start-Sleep -Seconds 5

#Import-Module AzureADpreview
Connect-AzureAD 
Start-Sleep -Seconds 5

#Import-Module ExchangeOnlineManagement
Connect-ExchangeOnline -UserPrincipalName $adminName -ShowProgress $true
Start-Sleep -Seconds 5







#$Pass = Get-Content "C:\365s.txt" | ConvertTo-SecureString

#$Pass = (Read-Host -Prompt "Enter 365 tennant admin Password" -AsSecureString);

#$credential = new-object -typename System.Management.Automation.PSCredential -argumentlist $AdminName, $Pass



}

#Logs path 



$email =  Read-Host -Prompt "Enter email address of the compromised Account"  
New-Item  -Path "C:\Compromised account $email Logs" -ItemType Directory -ErrorAction SilentlyContinue
$Path = "C:\Compromised account $email Logs"
Start-Transcript -Path "$Path\Account-Compromised-Script.log" -Append




$reply1 = Read-Host -Prompt "Block Sign-ins [y/n]"
if ( $reply1 -match "[nN]" ) {


Write-Warning "Sign-ins not blocked"

} 
if ( $reply1 -match "[yY]" ) { 



$params = @{ accountEnabled = $false }


Write-Host "Blocking Sign-ins for $email" -ForegroundColor Green

Update-MgUser -UserId $email -BodyParameter $params

#Set-MsolUser -UserPrincipalName $email -BlockCredential $true


}



$reply2 = Read-Host -Prompt "Revoke Azure ADUser All Refresh Tokens [y/n]"
if ( $reply2 -match "[nN]" ) {


Write-Warning "Revoke Azure ADUser All Refresh Token has not been ran"

} 
if ( $reply2 -match "[yY]" ) { 

Write-Host "Revoke Azure ADUser All Refresh Token for $email" -ForegroundColor Green


#Revoke-AzureADUserAllRefreshToken -ObjectId $email

Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/users/$email/revokeSignInSessions"



}








$reply3 = Read-Host -Prompt "Audit AAD Sign-In Logs [y/n]"

if ($reply3 -match "[nN]") {
    Write-Warning "AuditAADSignInLogs has not been run."
}

if ($reply3 -match "[yY]") {
    Clear-Host

    $StartDate = (Get-Date).AddDays(-6).ToString("yyyy-MM-dd")
    Write-Host "Getting Azure AD Audit Sign-In Log for $email. Please check $Path" -ForegroundColor Green

    # Fetch sign-in logs
    $Records = Get-AzureADAuditSignInLogs -Filter "startsWith(userPrincipalName,'$email')" -All:$true

    $Report = [System.Collections.Generic.List[Object]]::new()

    foreach ($Rec in $Records) {
        $Status = if ($Rec.Status.ErrorCode -eq 0) { "Success" } else { $Rec.Status.FailureReason }

        $ReportLine = [PSCustomObject]@{
            TimeStamp   = (Get-Date $Rec.CreatedDateTime).ToString("g")
            User        = $Rec.UserPrincipalName
            Name        = $Rec.UserDisplayName
            IPAddress   = $Rec.IpAddress
            ClientApp   = $Rec.ClientAppUsed
            Device      = $Rec.DeviceDetail.OperatingSystem
            Location    = "$($Rec.Location.City), $($Rec.Location.State), $($Rec.Location.CountryOrRegion)"
            Appname     = $Rec.AppDisplayName
            Resource    = $Rec.ResourceDisplayName
            Status      = $Status
            Correlation = $Rec.CorrelationId
            Interactive = $Rec.IsInteractive
        }

        $Report.Add($ReportLine)
    }

    Write-Host "$($Report.Count) sign-in audit records processed." -ForegroundColor Cyan

    # Export to CSV
    $csvPath = Join-Path $Path "UserAuditAADSignInLogs.csv"
    $Report | Export-Csv -Path $csvPath -NoTypeInformation

    # Display the report
    Write-Information -MessageData "AuditAADSignInLogs result:" -InformationAction Continue
    Import-Csv -Path $csvPath | Format-Table -AutoSize
}




######

$reply4 = Read-Host -Prompt "Check User Unified Audit Logs [y/n]"
if ( $reply4 -match "[nN]" ) {
}

if ( $reply4 -match "[yY]" ) { 

$UnifiedAuditLogIngestionEnabled = Get-AdminAuditLogConfig | Format-List UnifiedAuditLogIngestionEnabled


if ($UnifiedAuditLogIngestionEnabled -eq $true) {

Write-Host "Enabling UnifiedAuditLogIngestion" -ForegroundColor Green
Enable-OrganizationCustomization
Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true

}
else {

#Get-AdminAuditLogConfig | Format-List UnifiedAuditLogIngestionEnabled
Write-Host "UnifiedAuditLogIngestion enabled" -ForegroundColor Green
}






$StartDate=(((Get-Date).AddDays(-7))).Date
$EndDate=Get-Date

$OutputCSV="C:\Compromised account $email Logs\UserUnifiedAuditLog.csv" 
$IntervalTimeInMinutes=1440    #$IntervalTimeInMinutes=Read-Host Enter interval time period '(in minutes)'
$CurrentStart=$StartDate
$CurrentEnd=$CurrentStart.AddMinutes($IntervalTimeInMinutes)

#Filter for successful login attempts
if($success.IsPresent)
{
 $Operation="UserLoggedIn,TeamsSessionStarted,MailboxLogin"
}
#Filter for successful login attempts
elseif($Failed.IsPresent)
{
 $Operation="UserLoginFailed"
}
else
{
 $Operation="UserLoggedIn,UserLoginFailed,TeamsSessionStarted,MailboxLogin"
}

#Check whether CurrentEnd exceeds EndDate(checks for 1st iteration)
if($CurrentEnd -gt $EndDate)
{
 $CurrentEnd=$EndDate
}

$AggregateResults = 0
$CurrentResult= @()
$CurrentResultCount=0
Write-Host `nRetrieving audit log from $StartDate to $EndDate... -ForegroundColor Yellow

while($true)
{ 
 #Write-Host Retrieving audit log between StartDate $CurrentStart to EndDate $CurrentEnd ******* IntervalTime $IntervalTimeInMinutes minutes
 if($CurrentStart -eq $CurrentEnd)
 {
  Write-Host Start and end time are same.Please enter different time range -ForegroundColor Red
  Exit
 }

 #Getting audit log for specific user(s) for a given time range
  $Results=Search-UnifiedAuditLog -UserIds $email -StartDate $CurrentStart -EndDate $CurrentEnd -operations $Operation -SessionId s -SessionCommand ReturnLargeSet -ResultSize 5000

 #$Results.count
 $AllAuditData=@()
 $AllAudits=
 foreach($Result in $Results)
 {
  $AuditData=$Result.auditdata | ConvertFrom-Json
  $AuditData.CreationTime=(Get-Date($AuditData.CreationTime)).ToLocalTime()
  $AllAudits=@{'Login Time'=$AuditData.CreationTime;'User Name'=$AuditData.UserId;'IP Address'=$AuditData.ClientIP;'Operation'=$AuditData.Operation;'Result Status'=$AuditData.ResultStatus;'Workload'=$AuditData.Workload}
  $AllAuditData= New-Object PSObject -Property $AllAudits
  $AllAuditData | Sort 'Login Time','User Name' | select 'Login Time','User Name','IP Address',Operation,'Result Status',Workload | Export-Csv $OutputCSV -NoTypeInformation -Append
 }
 Write-Progress -Activity "`n     Retrieving audit log from $StartDate to $EndDate.."`n" Processed audit record count: $AggregateResults"
 #$CurrentResult += $Results
 $currentResultCount=$CurrentResultCount+($Results.count)
 $AggregateResults +=$Results.count
 if(($CurrentResultCount -eq 50000) -or ($Results.count -lt 5000))
 {
  if($CurrentResultCount -eq 50000)
  {
   Write-Host Retrieved max record for the current range.Proceeding further may cause data loss or rerun the script with reduced time interval. -ForegroundColor Red
   $Confirm=Read-Host `nAre you sure you want to continue? [Y] Yes [N] No
   if($Confirm -notmatch "[Y]")
   {
    Write-Host Please rerun the script with reduced time interval -ForegroundColor Red
    Exit
   }
   else
   {
    Write-Host Proceeding audit log collection with data loss
   }
  } 
  #Check for last iteration
  if(($CurrentEnd -eq $EndDate))
  {
   break
  }
  [DateTime]$CurrentStart=$CurrentEnd
  #Break loop if start date exceeds current date(There will be no data)
  if($CurrentStart -gt (Get-Date))
  {
   break
  }
  [DateTime]$CurrentEnd=$CurrentStart.AddMinutes($IntervalTimeInMinutes)
  if($CurrentEnd -gt $EndDate)
  {
   $CurrentEnd=$EndDate
  }
  
  $CurrentResultCount=0
  $CurrentResult = @()
 }
}

If($AggregateResults -eq 0)
{
 Write-Host No records found
}
else
{
 if((Test-Path -Path $OutputCSV) -eq "True") 
 {
  Write-Host ""
  Write-Host " The Output file availble in:" -NoNewline -ForegroundColor Yellow
  Write-Host $OutputCSV 
    Write-Host `nThe output file contains $AggregateResults audit records
  
 }
 
}

}


####









$reply5 = Read-Host -Prompt "Would you like to Check if a IP or domain is blacklisted [y/n]"
if ( $reply5 -match "[nN]" ) {


Write-Warning "No IP address need to be checked"

} 
if ( $reply5 -match "[yY]" ) { 



$ip = Read-Host -Prompt "Enter ip or domain to check if they are on a black list"  



Search-BlackList -IP $ip | Format-Table

Write-Host "If no results show IP or domain is not on a blacklist" -ForegroundColor Green
}





$reply6 = Read-Host -Prompt "Would you like to block a IP in 365 [y/n]"
if ( $reply6 -match "[nN]" ) {


Write-Warning "No IP address need to be blocked"

} 
if ( $reply6 -match "[yY]" ) { 
$blockip = Read-Host -Prompt "Enter IP address to block "  

Add-IPBlockListEntry -IPAddress $blockip
}




$reply7 = Read-Host -Prompt "Check email forwards, inbox rules, auto reply  [y/n]"

if ($reply7 -match "[nN]") {
    Write-Warning "Email forwards, inbox rules & auto reply have not been checked"
}

if ($reply7 -match "[yY]") {




 
Write-Host "Fetching inbox rules for $email..." -ForegroundColor Cyan


# Ensure the output directory exists
if (-not (Test-Path -Path $Path)) {
    New-Item -Path $Path -ItemType Directory | Out-Null
}

# Get inbox rules
$rules = Get-InboxRule -Mailbox $email

# Check if any rules exist
if ($rules.Count -gt 0) {
    Write-Host "Found $($rules.Count) inbox rule(s) for $email. Exporting to CSV..." -ForegroundColor Cyan

    $rules | Select-Object MailboxOwnerID, Name, Enabled, Priority, From, SubjectContainsWords, SentTo, RedirectTo, ForwardTo, DeleteMessage, MoveToFolder |
        Export-Csv -Path "$Path\InboxRules_$($email -replace '@','_').csv" -NoTypeInformation -Encoding UTF8

    Write-Host "Inbox rules exported to $Path\InboxRules_$($email -replace '@','_').csv" -ForegroundColor Green
} else {
    Write-Host "No inbox rules found for $email." -ForegroundColor Yellow
}


    Write-Host "Getting email forwards for all accounts . Please check $Path" -ForegroundColor Green

    # Email Forwarding
    Get-Mailbox | Where-Object { $_.ForwardingSmtpAddress -ne $null } |
        Select-Object UserPrincipalName, ForwardingAddress, ForwardingSmtpAddress, DeliverToMailboxAndForward |
        Export-Csv -Path "$Path\AccountsWithForwardingRules.csv" -NoTypeInformation -Encoding UTF8

    Write-Information "Email forwards result saved to $Path\AccountsWithForwardingRules.csv" -InformationAction Continue
    Import-Csv -Path "$Path\AccountsWithForwardingRules.csv" | Format-Table -AutoSize

    # Inbox Rules
    Write-Host "Checking inbox rules for $email..." -ForegroundColor Green
    Get-InboxRule -Mailbox $email |
        Select-Object MailboxOwnerID, Name, Enabled, From, Description, RedirectTo, ForwardTo, SentTo |
        Export-Csv -Path "$Path\UserOutlookRulesCheck.csv" -NoTypeInformation -Encoding UTF8

    Write-Information "Inbox rules result saved to $Path\UserOutlookRulesCheck.csv" -InformationAction Continue
    Import-Csv -Path "$Path\UserOutlookRulesCheck.csv" | Format-Table -AutoSize

    # Auto Reply (Out of Office)
    Write-Host "Checking auto-reply (out of office) for $email..." -ForegroundColor Green
    Get-MailboxAutoReplyConfiguration -Identity $email |
        Select-Object Identity, AutoReplyState |
        Export-Csv -Path "$Path\CheckEmailOutOfOffice.csv" -NoTypeInformation -Encoding UTF8

    Write-Information "Auto reply result saved to $Path\CheckEmailOutOfOffice.csv" -InformationAction Continue
    Import-Csv -Path "$Path\CheckEmailOutOfOffice.csv" | Format-Table -AutoSize
}


Write-warning "Please be aware this will remove selected inbox rules"
Write-Host 
$reply8 = Read-Host -Prompt "Would you remove inbox rule by identity [y/n]"
if ( $reply8 -match "[nN]" ) {Write-warning "inbox rules not removed"} 
if ( $reply8 -match "[yY]" ) { 


$ruleIdentity = Import-Csv -Path "$Path\OutlookRulescheck.csv" |  Select-Object -ExpandProperty Name | Out-GridView -Title "Outlook Rule to remove" -OutputMode Single



Remove-InboxRule -Mailbox $email -Identity $ruleIdentity




}




Write-warning "Please be aware this will remove all inbox rules and cannot be undone!"
Write-Host 
$reply9 = Read-Host -Prompt "Would you remove all inbox rules [y/n]"
if ( $reply9 -match "[nN]" ) {Write-warning "inbox rules not removed"} 
if ( $reply9 -match "[yY]" ) { 



Get-InboxRule -Mailbox $email | Remove-InboxRule

}








Write-Host
$reply10 = Read-Host -Prompt "Would you like to set a new password and Re-enabling account [y/n]"

if ($reply10 -match "[nN]") {
    Write-Warning "New Password not set"
}

if ($reply10 -match "[yY]") {
    Write-Host "Set a new password and Re-enabling account" -ForegroundColor Green

    $newPassword = Read-Host -Prompt "Provide New Password" -AsSecureString

    # Uncomment the line below to actually set the password
    # Set-MsolUserPassword -UserPrincipalName $email -NewPassword $newPassword

    Write-Host "Un-blocking 365 logins" -ForegroundColor Green

    # Uncomment the line below to unblock the user in MSOnline
    # Set-MsolUser -UserPrincipalName $email -BlockCredential $false

    # Microsoft Graph equivalent
    $params = @{ accountEnabled = $true }

    # Make sure you're connected to Microsoft Graph before running this
    Update-MgUser -UserId $email -BodyParameter $params
}








#New-ComplianceSearch -Name "Search All-Financial Report" -ExchangeLocation all -ContentMatchQuery 'sent>=01/01/2015 AND sent<=06/30/2015 AND subject:"financial report"'


$reply11 = Read-Host -Prompt "Connect to Security & Compliance [y/n]"
if ( $reply11 -match "[nN]" ) {Write-warning "No connected to Security & Compliance"


} 
if ( $reply11 -match "[yY]" ) { 


Write-Host "Starting IPPSSession to connect to Security & Compliance" -ForegroundColor Green
Connect-IPPSSession –UserPrincipalName $adminName



Write-Host "adding $adminName as eDiscoveryCaseAdmin" -ForegroundColor Green
Add-eDiscoveryCaseAdmin -User $adminName -Confirm:$false -ErrorAction SilentlyContinue
Write-Host "adding $adminName as Discovery Management" -ForegroundColor Green
Add-RoleGroupMember "Discovery Management" -member $adminName -Confirm:$false -ErrorAction SilentlyContinue

$reply12 = Read-Host -Prompt "Run Complience search for suspicious email [y/n]"
if ( $reply12 -match "[nN]" ) {Write-warning "No Complience search has been ran"


} 
if ( $reply12 -match "[yY]" ) { 





$Searchname = Read-Host -Prompt "Complient content search name"
$ContentMatchQuery = Read-Host -Prompt "Enter Email Body Content"
$ExchangeLocation = Read-Host -Prompt "Enter Exchange Location for example All / or spesific email adresses with commas"
#$Subject = Read-Host -Prompt "Enter Subject of email"



$ResultsCSV = "$Path\ComplianceCaseResults.csv"

#$Terms = @("Body:'$ContentMatchQuery'AND subject:'$Subject'")

#$Terms = @("Body:'$ContentMatchQuery'")


$Count = 1

Foreach ($Term in $Terms)
{
	Write-Host "Creating case to search for $Term.." -ForegroundColor Yellow
	$CaseName = "$Searchname Case" + $count++
	Write-Host "Case Name: $CaseName"
	New-ComplianceSearch -Name $CaseName -ExchangeLocation $ExchangeLocation -AllowNotFoundExchangeLocationsEnabled $true -ContentMatchQuery $ContentMatchQuery
	Write-Host "Starting case.. $CaseName"
	Start-ComplianceSearch $CaseName
	Start-Sleep -Seconds 5
	Do
	{
		Write-Host "Waiting until $CaseName is finished running..."
		$Status = Get-ComplianceSearch $CaseName | Select-Object -ExpandProperty Status
	}
	Until ($Status -eq "Completed")
	Write-Host "Gathering item count for $CaseName..."
	Get-ComplianceSearch $CaseName | Select-Object Name, ContentMatchQuery, Items, SuccessResults | Export-Csv -NoTypeInformation $ResultsCSV -Append
  
}




Start-Sleep -Seconds 20
#Import-CSV -Path "$Path\ComplianceCaseResults.csv" | ft


Get-ComplianceSearch $CaseName | Select-Object Name, ContentMatchQuery, Items, SuccessResults

#New-ComplianceSearchAction -SearchName "$CaseName" -Preview




Write-Host 
$reply13 = Read-Host -Prompt "Would you like purge all email that meet the Compliance Search results please check $Path ComplianceSearchResults.csv and ComplianceCaseExtendedResults.csv [y/n]"
if ( $reply13 -match "[nN]" ) {Write-warning "removal of emails not complete"} 
if ( $reply13 -match "[yY]" ) { 


New-ComplianceSearchAction –SearchName "$CaseName" –Purge –PurgeType SoftDelete -force



Get-ComplianceSearchAction | Export-Csv -Path "$Path\CasePurgeResults.csv"



#$date = (Get-Date).ToString("dd/MM/yyyy")
#Get-ComplianceSearchAction | Where-Object { JobEndTime -like $date}

}
}
}


















$reply14 = Read-Host -Prompt "Search Unified AuditLog of all users this takes some time to run[y/n]"
if ( $reply14 -match "[nN]" ) {


Write-Warning "Search Unified Audit Log not checked"

} 
if ( $reply14 -match "[yY]" ) { 

$UnifiedAuditLogIngestionEnabled = Get-AdminAuditLogConfig | Format-List UnifiedAuditLogIngestionEnabled


if ($UnifiedAuditLogIngestionEnabled -eq $true) {

Write-Host "Enabling UnifiedAuditLogIngestion" -ForegroundColor Green
Enable-OrganizationCustomization
Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true

}
else {

#Get-AdminAuditLogConfig | Format-List UnifiedAuditLogIngestionEnabled
Write-Host "UnifiedAuditLogIngestion enabled" -ForegroundColor Green
}








$days = Read-Host -Prompt "Enter the number of days you would like to collect logs from 1 - 90"  
Write-Warning = "Audit log can only be retrieved  past 90 days. "



 $StartDate=(((Get-Date).AddDays(-$days))).Date
 $EndDate=Get-Date


#Param
(
    [Parameter(Mandatory = $false)]
    [switch]$Success,
    [switch]$Failed,
    [Nullable[DateTime]]$StartDate,
    [Nullable[DateTime]]$EndDate,
    [string]$UserName,
    [string]$AdminName,
    [string]$Password
)

#Getting StartDate and EndDate for Audit log
if ((($StartDate -eq $null) -and ($EndDate -ne $null)) -or (($StartDate -ne $null) -and ($EndDate -eq $null)))
{
 Write-Host `nPlease enter both StartDate and EndDate for Audit log collection -ForegroundColor Red
 exit
}   
elseif(($StartDate -eq $null) -and ($EndDate -eq $null))
{
 $StartDate=(((Get-Date).AddDays(-90))).Date
 $EndDate=Get-Date
}
else
{
 $StartDate=[DateTime]$StartDate
 $EndDate=[DateTime]$EndDate
 if($StartDate -lt ((Get-Date).AddDays(-90)))
 { 
  Write-Host `nAudit log can be retrieved only for past 90 days. Please select a date after (Get-Date).AddDays(-90) -ForegroundColor Red
  Exit
 }
 if($EndDate -lt ($StartDate))
 {
  Write-Host `nEnd time should be later than start time -ForegroundColor Red
  Exit
 }
}


 

$OutputCSV="C:\Compromised account $email Logs\UnifiedAuditLogs.csv" 
$IntervalTimeInMinutes=1440    #$IntervalTimeInMinutes=Read-Host Enter interval time period '(in minutes)'
$CurrentStart=$StartDate
$CurrentEnd=$CurrentStart.AddMinutes($IntervalTimeInMinutes)

#Filter for successful login attempts
if($success.IsPresent)
{
 $Operation="UserLoggedIn,TeamsSessionStarted,MailboxLogin"
}
#Filter for successful login attempts
elseif($Failed.IsPresent)
{
 $Operation="UserLoginFailed"
}
else
{
 $Operation="UserLoggedIn,UserLoginFailed,TeamsSessionStarted,MailboxLogin"
}

#Check whether CurrentEnd exceeds EndDate(checks for 1st iteration)
if($CurrentEnd -gt $EndDate)
{
 $CurrentEnd=$EndDate
}

$AggregateResults = 0
$CurrentResult= @()
$CurrentResultCount=0
Write-Host `nRetrieving audit log from $StartDate to $EndDate... -ForegroundColor Yellow

while($true)
{ 
 #Write-Host Retrieving audit log between StartDate $CurrentStart to EndDate $CurrentEnd ******* IntervalTime $IntervalTimeInMinutes minutes
 if($CurrentStart -eq $CurrentEnd)
 {
  Write-Host Start and end time are same.Please enter different time range -ForegroundColor Red
  Exit
 }


 #Getting audit log for all users for a given time range
 $Results=Search-UnifiedAuditLog -StartDate $CurrentStart -EndDate $CurrentEnd -Operations $Operation -SessionId s -SessionCommand ReturnLargeSet -ResultSize 5000
 
 #$Results.count
 $AllAuditData=@()
 $AllAudits=
 foreach($Result in $Results)
 {
  $AuditData=$Result.auditdata | ConvertFrom-Json
  $AuditData.CreationTime=(Get-Date($AuditData.CreationTime)).ToLocalTime()
  $AllAudits=@{'Login Time'=$AuditData.CreationTime;'User Name'=$AuditData.UserId;'IP Address'=$AuditData.ClientIP;'Operation'=$AuditData.Operation;'Result Status'=$AuditData.ResultStatus;'Workload'=$AuditData.Workload}
  $AllAuditData= New-Object PSObject -Property $AllAudits
  $AllAuditData | Sort 'Login Time','User Name' | select 'Login Time','User Name','IP Address',Operation,'Result Status',Workload | Export-Csv $OutputCSV -NoTypeInformation -Append
 }
 #Write-Progress -Activity "`n     Retrieving audit log from $StartDate to $EndDate.."`n" Processed audit record count: $AggregateResults"
 #$CurrentResult += $Results
 #$currentResultCount=$CurrentResultCount+($Results.count)
 #$AggregateResults +=$Results.count
 if(($CurrentResultCount -eq 50000) -or ($Results.count -lt 5000))
 {
  if($CurrentResultCount -eq 50000)
  {
   Write-Host Retrieved max record for the current range.Proceeding further may cause data loss or rerun the script with reduced time interval. -ForegroundColor Red
   $Confirm=Read-Host `nAre you sure you want to continue? [Y] Yes [N] No
   if($Confirm -notmatch "[Y]")
   {
    Write-Host Please rerun the script with reduced time interval -ForegroundColor Red
    
   }
   else
   {
    Write-Host Proceeding audit log collection with data loss
   }
  } 
  #Check for last iteration
  if(($CurrentEnd -eq $EndDate))
  {
   break
  }
  [DateTime]$CurrentStart=$CurrentEnd
  #Break loop if start date exceeds current date(There will be no data)
  if($CurrentStart -gt (Get-Date))
  {
   break
  }
  [DateTime]$CurrentEnd=$CurrentStart.AddMinutes($IntervalTimeInMinutes)
  if($CurrentEnd -gt $EndDate)
  {
   $CurrentEnd=$EndDate
  }
  
  $CurrentResultCount=0
  $CurrentResult = @()
 }
}

If($AggregateResults -eq 0)
{
 Write-Host No records found
}
else
{
 if((Test-Path -Path $OutputCSV) -eq "True") 
 {
  Write-Host ""
  Write-Host " The Output file availble in:" -NoNewline -ForegroundColor Yellow
  Write-Host $OutputCSV 
    Write-Host `nThe output file contains $AggregateResults audit records
  
 }
 
 Write-Information -MessageData "UnifiedAuditLog result for more info check $Path" -InformationAction Continue
#Import-CSV -Path "$OutputCSV" | ft


}
}
Stop-Transcript
