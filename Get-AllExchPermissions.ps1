<#
.Synopsis
	Extracts all Exchange permissions (FullAccess, Send-As and folder permissions)
.DESCRIPTION
	This Powershell cmdlet loops through all Exchange 2007 or newer mailboxes and returns Exchange folder permissions (Inbox,Calendar,etc.), Exchange mailbox permissions (FullAccess) and AD permissions (Send-As). Group membership is expanded for direct user to delegate relationships.
	
    Version 2 Improvements - 05/08/2017
        - Reduced the amount of LDAP queries during the process to increase performance and decrease overall load generated
        - Added skip switches for folder, mailbox and AD permissions processing
        - Combines multiple permissions between user and delegate into single line item in CSV
    
    NOTE: This script introduces resource load to the environment and should be executed off-hours. On average, processing time is around 30 - 45 minutes per 1000 mailboxes. This script must be executed from the Exchange Management Shell (EMS) on an administrative workstation or Exchange server.
    
	Developed by Brian Cheatham

.EXAMPLE
	Get-AllExchPermissions
.EXAMPLE
	Get-AllExchPermissions -SkipFolderPermissions
.EXAMPLE
	Get-AllExchPermissions -ExcludeAccount DOMAIN\Username
.EXAMPLE
	Get-AllExchPermissions -CSVFile C:\Reports\AllExchPermisssions.csv
#>

function Get-AllExchPermissions
{
    [CmdletBinding()]
    Param
    (
		# Specify the full path to the desired $CSVFile
		[Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [string]
        $CSVFile =  "C:\Reports\AllExchPermissions.csv",
		# Specify which Exchange mailbox folders to export permissions for, default is Calendar, Contacts, Inbox
		[Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [array]
        $MailboxFolders =  @("Calendar","Contacts","Inbox"),
		# Specify this parameter to skip Exchange folder permission processing such as Reviewer on another user's calendar
		[Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [switch]
        $SkipFolderPermissions,
		# Specify this parameter to skip Exchange mailbox permission processing such as FullAccess permission
		[Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [switch]
        $SkipMailboxPermissions,
		# Specify this parameter to skip AD permission processing such as Send-As permissions
		[Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [switch]
        $SkipADPermissions,
        # Specify this parameter to exclude an account such as a migration admin account in format DOMAIN\Username
        [Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [string]
        $ExcludeAccount
    )

    Begin {
    
        New-Variable -Name Coll -Option AllScope -Value @()
     
	    function Add-DelegateInfotoHash ([string]$PermName, [string]$PermEmail, [string]$PermDelegate, [string]$PermDelegateEmail, [string]$PermAccessRights) {
		
            $ExistingAccessRights = $Coll | where {$_.Email.Equals($PermEmail) -and $_.DelegateEmail.Equals($PermDelegateEmail)} | Select-Object Name,Delegate,AccessRights

            If ($ExistingAccessRights.AccessRights) {

                $AllAccessRights = $ExistingAccessRights.AccessRights.toString() + ' ' + $PermAccessRights

                $Coll | where {$_.Email.Equals($PermEmail) -and $_.DelegateEmail.Equals($PermDelegateEmail)} | %{$_.AccessRights = $AllAccessRights} 
                

            } Else {

                $AllAccessRights = $PermAccessRights
            
                $Perms = @{}
                $Perms.Name = $PermName
		        $Perms.Email = $PermEmail
		        $Perms.Delegate = $PermDelegate
                $Perms.DelegateEmail = $PermDelegateEmail
		        $Perms.AccessRights = $AllAccessRights
		        $Coll += new-object psobject -property $Perms
            }

	    }

    	Write-Host "Preparing script for execution..." -NoNewLine
    
    }
    Process
    {
	
    Import-Module ActiveDirectory

    # Create object with all mailboxes
    $AllMailboxes = Get-Mailbox -ResultSize Unlimited | where { ($_.Name -notlike "*DiscoverySearchMailbox*") } | Sort-Object DisplayName | Select-Object Name,DisplayName,Alias,PrimarySmtpAddress,DistinguishedName
	# Create object with all AD user and group objects
	$AllADObjects = Get-ADObject -LDAPFilter "(|(&(objectCategory=person)(objectClass=user))(objectCategory=group))" -Properties * | Select-Object Name,DisplayName,sAMAccountName,mail,objectClass

	Write-Host "Done!"
    Write-Host "This script is looping through all mailboxes to export permissions and might take some time."
    Write-Host "Estimating 30 - 45 minutes per 1000 mailboxes depending upon groups as delegates and nesting, etc."

    ForEach ($Mailbox in $AllMailboxes) {

	    Write-Host "Processing" $Mailbox.DisplayName "..." -NoNewLine

		If ($SkipFolderPermissions -eq $false) {
		
			ForEach ($Folder in $MailboxFolders) {

		        #Query to see if there is a folder with this name, if not, skip the folder
		        $FolderPath = Get-MailboxFolderStatistics -Identity $Mailbox.PrimarySmtpAddress.toString() | where {($_.Name -eq $Folder)} | Select-Object Name
		
		        If ($FolderPath.Name) {
				
			        $FolderID = $Mailbox.PrimarySmtpAddress.toString() + ":\" + $Folder
					
			        $FolderPermissions = Get-MailboxFolderPermission -identity $FolderID  | where { ($_.User -notlike "Default") -and ($_.User -notlike "Anonymous") -and ($_.User -notlike "NT User:*") }

			        ForEach ($Permission in $FolderPermissions) {
					
						If ($Permission.User) {

                            $AccessRights = $Folder + "-" + $Permission.AccessRights -join ' '
					
							$Delegate = $Permission.User

							If ($Delegate -like "ExchangePublishedUser.*") {

								$Delegate = $Delegate -replace 'ExchangePublishedUser.',''
							
								$ADObject = $AllADObjects | where {$_.mail -eq $Delegate} | Select-Object DisplayName,mail,sAMAccountName,objectClass

							} Else {

								$ADObject = $AllADObjects | where {$_.DisplayName -eq $Delegate} | Select-Object DisplayName,mail,sAMAccountName,objectClass
								
							}


							If ($ADObject) {

								#Check to see if the object is a user
								Switch ($ADObject.objectClass) {
						
									"user" {

										If ($ADObject.DisplayName) {
										
											Add-DelegateInfotoHash $Mailbox.DisplayName $Mailbox.PrimarySmtpAddress $ADObject.DisplayName $ADObject.mail $AccessRights

										}
														
									}

									"group" {

										#If it's not a user it's a group, so query the group for a list of members.
										$SAN = $ADObject.sAMAccountName
										$GroupMembers = Get-ADGroupMember $SAN -Recursive | Get-ADUser -Properties DisplayName,EmailAddress | Select-Object DisplayName,EmailAddress

										If ($GroupMembers) {

											Foreach ($Member in $GroupMembers) {
									
												If ($Member.DisplayName) {

													Add-DelegateInfotoHash $Mailbox.DisplayName $Mailbox.PrimarySmtpAddress $Member.DisplayName $Member.EmailAddress $AccessRights

												}					
											}		
										}
									}	
					
									default {
					
										break
									}
								}	
							}
				        }
			        }
		        }                                            
            }

        Write-Host "Folder perms done! ..." -NoNewLine

	    }                                       

        If ($SkipMailboxPermissions -eq $false) {
        
            $MailboxPermissions = Get-MailboxPermission -identity $Mailbox.DistinguishedName.toString() | where { ($_.AccessRights -like "*FullAccess*") -and ($_.IsInherited -eq $false) -and -not ($_.User -like "NT AUTHORITY\SELF") -and -not ($_.User -like "S-1-5-*") -and -not ($_.User -like $ExcludeAccount) } | Select-Object User,AccessRights

	        ForEach ($MailboxPermission in $MailboxPermissions) {
        
		        If ($MailboxPermission.User) {
		
			        $AccessRights = "Mailbox-" + $MailboxPermission.AccessRights -join ' '
			
			        #Turn security principal into a string so we can split it
			        $DomainSAN = $MailboxPermission.User.ToString()
			        #Take the Domain\Username, split it, and capture only the SamAccountName
			        $SAN = $DomainSAN.Split("\")[1]

			        #Query $AllADObjects for an object where the username given is a sAMAccountname.  sAMAccountnames are unique so we get back one return.
                    $ADObject = $AllADObjects | where {$_.sAMAccountName -eq $SAN} | Select-Object DisplayName,mail,sAMAccountName,objectClass

				    If ($ADObject) {

					    #Check to see if the object is a user
					    Switch ($ADObject.objectClass) {
						
						    "user" {

							    If ($ADObject.DisplayName) {
										
								    Add-DelegateInfotoHash $Mailbox.DisplayName $Mailbox.PrimarySmtpAddress $ADObject.DisplayName $ADObject.mail $AccessRights

							    }
														
						    }

						    "group" {

							    #If it's not a user it's a group, so query the group for a list of members.
							    $GroupMembers = Get-ADGroupMember $SAN -Recursive | Get-ADUser -Properties DisplayName,EmailAddress | Select-Object DisplayName,EmailAddress

							    If ($GroupMembers) {

								    Foreach ($Member in $GroupMembers) {
									
									    If ($Member.DisplayName) {

										    Add-DelegateInfotoHash $Mailbox.DisplayName $Mailbox.PrimarySmtpAddress $Member.DisplayName $Member.EmailAddress $AccessRights

									    }					
								    }		
							    }
						    }	
					
						    default {
					
							    break
						    }
					    }	
				    }
                }

            }

        Write-Host "Mailbox perms done! ..." -NoNewLine

        }

        If ($SkipADPermissions -eq $false) {

            $ADPermissions = Get-ADPermission -identity $Mailbox.DistinguishedName.toString() | where { ($_.ExtendedRights -like "*Send-As*") -and ($_.IsInherited -eq $false) -and -not ($_.User -like "NT AUTHORITY\SELF") -and -not ($_.User -like "S-1-5-*") -and -not ($_.User -like $ExcludeAccount) } | Select-Object User,ExtendedRights

	        ForEach ($ADPermission in $ADPermissions) {
        
		        If ($ADPermission.User) {
		
			        $AccessRights = "AD-" + $ADPermission.ExtendedRights -join ' '
			
			        #Turn security principal into a string so we can split it
			        $DomainSAN = $ADPermission.User.ToString()
			        #Take the Domain\Username, split it, and capture only the SamAccountName
			        $SAN = $DomainSAN.Split("\")[1]

			        #Query $AllADObjects for an object where the username given is a sAMAccountname.  sAMAccountnames are unique so we get back one return.
                    $ADObject = $AllADObjects | where {$_.sAMAccountName -eq $SAN} | Select-Object DisplayName,mail,sAMAccountName,objectClass

				    If ($ADObject) {

					    #Check to see if the object is a user
					    Switch ($ADObject.objectClass) {
						
						    "user" {

							    If ($ADObject.DisplayName) {
										
								    Add-DelegateInfotoHash $Mailbox.DisplayName $Mailbox.PrimarySmtpAddress $ADObject.DisplayName $ADObject.mail $AccessRights

							    }
														
						    }

						    "group" {

							    #If it's not a user it's a group, so query the group for a list of members.
							    $GroupMembers = Get-ADGroupMember $SAN -Recursive | Get-ADUser -Properties DisplayName,EmailAddress | Select-Object DisplayName,EmailAddress

							    If ($GroupMembers) {

								    Foreach ($Member in $GroupMembers) {
									
									    If ($Member.DisplayName) {

										    Add-DelegateInfotoHash $Mailbox.DisplayName $Mailbox.PrimarySmtpAddress $Member.DisplayName $Member.EmailAddress $AccessRights

									    }					
								    }		
							    }
						    }	
					
						    default {
					
							    break
						    }
					    }	
				    }
                }

            }

        Write-Host "AD perms done! ..." -NoNewLine

        }

	    Write-Host "Done!"
	
    }

    Write-Host "Writing output to $CSVFile..." -NoNewLine

    $Coll | Select-Object Name,Email,Delegate,DelegateEmail,AccessRights | Export-Csv $CSVFile -NoTypeInformation

    }
    End
    {

    Write-Host "Done!"

    }
}