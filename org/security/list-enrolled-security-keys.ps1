<#
.SYNOPSIS
    List enrolled Security Keys in the tenant.

.DESCRIPTION
    This runbook lists all FIDO2 Security Keys enrolled in the tenant in two modes:
    1. Per Security Key: Lists all security keys with the users enrolled to each key
    2. Per User: Lists all users with their enrolled security keys (with option to show shared usage)
    
    You can optionally filter to specific users by providing a list of user emails.

.PARAMETER Mode
    The display mode for the output:
    - "PerKey": Group by security key and show enrolled users
    - "PerUser": Group by user and show their security keys

.PARAMETER UserList
    Optional array of user email addresses to filter the results.
    If provided, only these users will be included in the output.
    If empty, all users with security keys will be shown.

.PARAMETER ShowSharedKeyUsers
    When in "PerUser" mode, show other users who also have the same security key enrolled.
    Only applies to "PerUser" mode.

.INPUTS
RunbookCustomization: {
    "Parameters": {
        "Mode": {
            "DisplayName": "Display Mode",
            "Description": "Choose how to display the security keys information",
            "Required": true,
            "SelectSimple": {
                "Per Security Key": "PerKey",
                "Per User": "PerUser"
            }
        },
        "UserList": {
            "DisplayName": "Filter Users (Optional)",
            "Description": "Comma-separated list of user emails to filter results. Leave empty to show all users.",
            "Required": false
        },
        "ShowSharedKeyUsers": {
            "DisplayName": "Show Shared Key Users",
            "Description": "In 'Per User' mode, show other users who have the same security key enrolled",
            "Required": false,
            "SelectSimple": {
                "Yes": true,
                "No": false
            },
            "Customization": {
                "Conditions": [
                    {
                        "DependsOn": "Mode",
                        "Value": "PerUser"
                    }
                ]
            }
        },
        "CallerName": {
            "Hide": true
        }
    }
}
#>

#Requires -Modules @{ModuleName = "RealmJoin.RunbookHelper"; ModuleVersion = "0.8.4" }
#Requires -Modules @{ModuleName = "Microsoft.Graph.Authentication"; ModuleVersion = "2.28.0" }

param (
    [Parameter(Mandatory = $true)]
    [ValidateSet("PerKey", "PerUser")]
    [string]$Mode,
    
    [Parameter(Mandatory = $false)]
    [string]$UserList = "",
    
    [Parameter(Mandatory = $false)]
    [bool]$ShowSharedKeyUsers = $false,
    
    # CallerName is tracked purely for auditing purposes
    [Parameter(Mandatory = $true)]
    [string]$CallerName
)

########################################################
#region     RJ Log Part
##
########################################################

# Add Caller and Version in Verbose output
if ($CallerName) {
    Write-RjRbLog -Message "Caller: '$CallerName'" -Verbose
}

$Version = "1.0.0"
Write-RjRbLog -Message "Version: $Version" -Verbose

# Add Parameters in Verbose output
Write-RjRbLog -Message "Submitted parameters:" -Verbose
Write-RjRbLog -Message "Mode: $Mode" -Verbose
Write-RjRbLog -Message "UserList: '$UserList'" -Verbose
Write-RjRbLog -Message "ShowSharedKeyUsers: $ShowSharedKeyUsers" -Verbose

#endregion

####################################################################
#region Connect to Microsoft Graph
####################################################################

try {
    Write-Verbose "Connecting to Microsoft Graph..."
    Connect-MgGraph -Identity -NoWelcome -ErrorAction Stop
    Write-Verbose "Successfully connected to Microsoft Graph."
}
catch {
    Write-Error "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
    throw
}

#endregion

####################################################################
#region Process User List Filter
####################################################################

$FilteredUsers = @()
if ($UserList -and $UserList.Trim() -ne "") {
    # Parse comma-separated user list
    $UserEmails = $UserList -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
    Write-Verbose "Filtering to specific users: $($UserEmails -join ', ')"
    
    foreach ($email in $UserEmails) {
        try {
            $user = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/users/$email" -Method Get -ErrorAction Stop
            $FilteredUsers += $user
            Write-Verbose "Found user: $($user.userPrincipalName)"
        }
        catch {
            Write-Warning "Could not find user: $email - $($_.Exception.Message)"
        }
    }
    
    if ($FilteredUsers.Count -eq 0) {
        Write-Output "No valid users found from the provided list."
        return
    }
}
else {
    # Get all enabled users
    Write-Verbose "Retrieving all enabled users..."
    $usersBaseURI = 'https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,accountEnabled&$filter=accountEnabled eq true'
    
    try {
        $currentURI = $usersBaseURI
        do {
            Write-Verbose "Fetching users from URI: $currentURI"
            $response = Invoke-MgGraphRequest -Uri $currentURI -Method Get -ErrorAction Stop
            if ($response -and $response.value) {
                $FilteredUsers += $response.value
                Write-Verbose "Retrieved $($response.value.Count) users in this batch. Total users so far: $($FilteredUsers.Count)."
            }
            $currentURI = $response.'@odata.nextLink'
        } while ($null -ne $currentURI)
        
        Write-Verbose "Retrieved total users: $($FilteredUsers.Count)"
    }
    catch {
        Write-Error "Failed to retrieve users: $($_.Exception.Message)"
        throw
    }
}

#endregion

####################################################################
#region Retrieve Security Keys Data
####################################################################

$UsersWithSecurityKeys = @()
$AllSecurityKeys = @()

Write-Verbose "Checking security keys for $($FilteredUsers.Count) users..."

foreach ($user in $FilteredUsers) {
    try {
        # Get FIDO2 authentication methods for the user
        $fido2URI = "https://graph.microsoft.com/v1.0/users/$($user.id)/authentication/fido2Methods"
        Write-Verbose "Checking FIDO2 methods for user: $($user.userPrincipalName)"
        
        $fido2Response = Invoke-MgGraphRequest -Uri $fido2URI -Method Get -ErrorAction Stop
        
        if ($fido2Response.value -and $fido2Response.value.Count -gt 0) {
            Write-Verbose "Found $($fido2Response.value.Count) FIDO2 key(s) for user: $($user.userPrincipalName)"
            
            $userSecurityKeys = @()
            foreach ($fido2Key in $fido2Response.value) {
                $keyInfo = [PSCustomObject]@{
                    KeyId = $fido2Key.id
                    DisplayName = $fido2Key.displayName
                    CreatedDateTime = $fido2Key.createdDateTime
                    Model = $fido2Key.model
                    AttestationCertificates = $fido2Key.attestationCertificates
                    AttestationLevel = $fido2Key.attestationLevel
                    AaGuid = $fido2Key.aaGuid
                }
                
                $userSecurityKeys += $keyInfo
                
                # Add to global list for "Per Key" mode
                $AllSecurityKeys += [PSCustomObject]@{
                    KeyId = $fido2Key.id
                    DisplayName = $fido2Key.displayName
                    Model = $fido2Key.model
                    CreatedDateTime = $fido2Key.createdDateTime
                    AttestationLevel = $fido2Key.attestationLevel
                    AaGuid = $fido2Key.aaGuid
                    UserDisplayName = $user.displayName
                    UserPrincipalName = $user.userPrincipalName
                    UserId = $user.id
                }
            }
            
            $UsersWithSecurityKeys += [PSCustomObject]@{
                UserId = $user.id
                UserDisplayName = $user.displayName
                UserPrincipalName = $user.userPrincipalName
                SecurityKeys = $userSecurityKeys
            }
        }
    }
    catch {
        Write-Warning "Failed to retrieve FIDO2 methods for user $($user.userPrincipalName): $($_.Exception.Message)"
    }
}

#endregion

####################################################################
#region Display Results
####################################################################

if ($UsersWithSecurityKeys.Count -eq 0) {
    Write-Output "No users found with enrolled security keys."
    return
}

Write-Output "Found $($UsersWithSecurityKeys.Count) users with enrolled security keys."
Write-Output ""

if ($Mode -eq "PerKey") {
    #region Per Security Key Mode
    Write-Output "=== Security Keys by Key ==="
    Write-Output ""
    
    # Group by security key
    $KeyGroups = $AllSecurityKeys | Group-Object -Property KeyId
    $SortedKeyGroups = $KeyGroups | Sort-Object Name
    
    foreach ($keyGroup in $SortedKeyGroups) {
        $firstKey = $keyGroup.Group[0]
        $keyDisplayName = if ($firstKey.DisplayName) { $firstKey.DisplayName } else { "Unnamed Key" }
        $keyModel = if ($firstKey.Model) { " ($($firstKey.Model))" } else { "" }
        
        Write-Output "Key: $($firstKey.KeyId) - $keyDisplayName$keyModel"
        
        # Sort users alphabetically
        $sortedUsers = $keyGroup.Group | Sort-Object UserPrincipalName
        foreach ($keyUser in $sortedUsers) {
            Write-Output "  - $($keyUser.UserPrincipalName) ($($keyUser.UserDisplayName))"
        }
        Write-Output ""
    }
    #endregion
}
else {
    #region Per User Mode
    Write-Output "=== Security Keys by User ==="
    Write-Output ""
    
    # Sort users alphabetically
    $SortedUsers = $UsersWithSecurityKeys | Sort-Object UserPrincipalName
    
    foreach ($userWithKeys in $SortedUsers) {
        Write-Output "$($userWithKeys.UserPrincipalName) ($($userWithKeys.UserDisplayName)):"
        
        # Sort keys by display name or ID
        $sortedKeys = $userWithKeys.SecurityKeys | Sort-Object DisplayName, KeyId
        
        foreach ($key in $sortedKeys) {
            $keyDisplayName = if ($key.DisplayName) { $key.DisplayName } else { "Unnamed Key" }
            $keyModel = if ($key.Model) { " ($($key.Model))" } else { "" }
            
            Write-Output "  - $($key.KeyId) - $keyDisplayName$keyModel"
            
            # Show other users with the same key if requested
            if ($ShowSharedKeyUsers) {
                $otherUsers = $AllSecurityKeys | Where-Object { $_.KeyId -eq $key.KeyId -and $_.UserId -ne $userWithKeys.UserId }
                if ($otherUsers) {
                    foreach ($otherUser in $otherUsers) {
                        Write-Output "    Also enrolled to: $($otherUser.UserPrincipalName) ($($otherUser.UserDisplayName))"
                    }
                }
            }
        }
        Write-Output ""
    }
    #endregion
}

# Summary statistics
Write-Output "=== Summary ==="
Write-Output "Total users with security keys: $($UsersWithSecurityKeys.Count)"
Write-Output "Total security keys found: $($AllSecurityKeys.Count)"
Write-Output "Unique security keys: $(($AllSecurityKeys | Group-Object KeyId).Count)"

#endregion