<#
.SYNOPSIS
Compares users in AD to a List provided and either creates a user or disables them based off if they are in the list or not in it.
.DESCRIPTION
Recreating the Engineers script to create users based on a provided list, **(Not yet complete)the list can either be hardcoded into the script, a CSV file or Json file**
The script will first check and compare the users in AD to make sure they are equal
If a user is in the list provided and not in AD it will go and create that user
If a user is in AD but not in the list it will set that user to Disabled and remove their admin rights
#>

## Create a nested hashtable of users to compare to the returned value of Get-AdminADUsers
$Global:USERS_DICT = @{
    'a.Admin1' = @{
        'firstname' = 'Admin'
        'lastname' = '1'
        'samaccountname' = 'a.Admin1'
        'group' = 'engineers'
    }
    'a.Admin2' = @{
        'firstname' = 'Admin'
        'lastname' = '2'
        'samaccountname' = 'a.Admin2'
        'group' = 'helpdesk'
    }
}

$Global:GROUPS_ARRAY = @('ServerAdmins','HelpDesk', 'Elevated')

$Global:OU_ARRAY = @('Computers','Distribution Groups','Employees','IT Admins', 'Security Groups','Service Accounts','Shared Accounts')

function Get-AdminADUsers {
    [cmdletbinding()]
    param (
        [parameter(Mandatory = $false)]
        [string]$OU,

        [parameter(Mandatory = $false)]
        [string]$Prefix = 'a.'
    )

    Begin { 
        ## Create an empty list to store the object data in
        $user_list = [System.Collections.Generic.List[Object]]::new()
        
        ## If OU is specified in the parameters it will set the $users variable to search the specified OU
        switch ($PSBoundParameters.ContainsKey('OU')) {
            $true { $users = Get-AdUser -SearchBase $OU -Filter "samaccountname -like '$($Prefix)*'" }
            Default { $users = Get-AdUser -Filter "samaccountname -like '$($Prefix)*'" }
        } # End Switch
    } #end begin

    Process {
        Write-Verbose "Grabbing a list of users with the prefix $Prefix"
        foreach ($user in $users) {
            $user_list.Add($user)
        } # End foreach
    } # end process

    End {
        
        return $user_list
    }

} # end function

function Compare-ADUsersToAdd {
    [cmdletbinding()]
    param (
        [parameter(Mandatory=$false,ValueFromPipeline,Position=0)]
        $current_users = $null,

        [parameter(Mandatory,ValueFromPipeline,Position=1)]
        [ValidateNotNullOrEmpty()]
        $user_to_compare
    )
    
    Begin {
            ## Create empty list that will be passed to the New-AdminADUsers function
            $users_to_add = [System.Collections.Generic.List[Object]]::new()
            $userkeys = $user_to_compare.keys
    }
    Process {
        ## Loop through the each user in the hashtable and get their samaccountname that is provided
        Write-Verbose "Comparing users to add to AD..."
        foreach ($user in $userkeys) {
            ## Check if the samaccountname is listed in the current_users list that was passed from the previous Get-AdminADUsers function
            if ($user -in $current_users.samaccountname) {
                Continue
            } # end if
            else {
                Write-Verbose "Found user to add, adding user: $user to list..."
                $users_to_add.Add($user_to_compare[$user])
            } # end else
        } # end foreach
    }
    End {
        return $users_to_add
    }
}

function Compare-ADUsersToDisable {
    [cmdletbinding()]
    param (
        [parameter(Mandatory=$false,ValueFromPipeline,Position=0)]
        $current_users = $null,

        [parameter(Mandatory,ValueFromPipeline,Position=1)]
        [ValidateNotNullOrEmpty()]
        $user_to_compare
    )

    Begin {
            ## Create empty list that will be passed to the Set-AdminADUsers function
            $users_to_disable = [System.Collections.Generic.List[Object]]::new()
    }
    Process {
        ## Loop through each user from Get-AdminADUsers and get the samaccountname that is provided
        Write-Verbose "Comparing users to disable..."
        foreach ($user in $current_users) {
            ## Check if the samaccountname is listed in the current_users list that was passed from the previous Get-AdminADUsers function
            if ($user.samaccountname -in $user_to_compare.keys) {
                Continue
            } # end if
            else {
            Write-Verbose "Found user to disable, adding user: $($user.DisplayName) to list..."
            $users_to_disable.Add($user)
            } # end else
        } # end foreach
    }
    End {
        return $users_to_disable
    }
}

function New-Password {
    param()

    Begin {
        Add-Type -AssemblyName 'System.Web'
    }

    Process {
        $password = [System.Web.Security.Membership]::GeneratePassword(16, 6)
        $sec_pass = ConvertTo-SecureString -String $password -AsPlainText -Force
    }

    End {
        return $sec_pass
    }
}

function Get-OU {
    [cmdletbinding()]
    param(
        [parameter(Mandatory=$false,Position=0)]
        [string]$ou = 'Business'
    )

    Begin{}

    Process {
        Write-Verbose "Checking for $ou and if it doesn't exist returning null"
        try {
            $returned_ou = Get-ADOrganizationalUnit -Filter "Name -eq '$ou'"
            Write-Verbose "OU found, returning value..."
        }
        catch {
            Write-Verbose "No OU found, returning null..."
            $returned_ou = $null
        }
    }

    End {
        return $returned_ou
    }
}

function Get-OUs {
    [cmdletbinding()]
    param(
        [parameter(Mandatory=$false,Position=0)]
        $ou_path
    )
    Begin {
        $add_ou_list = [System.Collections.Generic.List[Object]]::new()
    }
    Process {
        ## Checks if ou_path is null and if not loops through OUs global variable and check if they exist and if not add them to a list to be created
        if ($ou_path) {
            Write-Verbose "Checking if new ous need to be created..."
            foreach ($ou in $Global:OU_ARRAY) {
                switch ([Adsi]::Exists("LDAP://OU=$ou,$($ou_path.DistinguishedName)")) {
                    $true { Continue }
                    Default { $add_ou_list.Add($ou) }
                }
            }
        }
    }
    End {
        ## If list is not empty return it and if it is return null
        if ($add_ou_list) {
            return $add_ou_list
        }
        return $null
    }
}

function New-OUs {
    [cmdletbinding()]
    param (
        [parameter(Mandatory=$false,ValueFromPipeline,Position=0)]
        $ous_to_add = $null,

        [parameter(Mandatory=$false,Position=1)]
        $ou_path = $null
    )
    Begin {
        ## Check if OU Path is null and creates the Businss OU,
        ## NOTE: you can add a paramater that takes in the name you want to use and replace 'Business' with it.
        if ($null -eq $ou_path) {
            Write-Verbose "Creating Business OU..."
            New-ADOrganizationalUnit -Name 'Business'
            $ou_path = Get-ADOrganizationalUnit -Filter "Name -eq 'Business'"
        }
    }
    Process {
        ## Checks if ous_to_add is null and if not adds the ou's passed from the parameter
        if ($ous_to_add) {
            Write-Verbose "Creating new ous..."
            foreach ($OU in $ous_to_add) {
                Write-Verbose "Creating new OU: $ou"
                New-ADOrganizationalUnit -Name $OU -Path $ou_path.DistinguishedName
            }
        }
        $itadminsOU = Get-ADOrganizationalUnit -Identity "OU=IT Admins,$($ou_path.DistinguishedName)"
    }
    End {
        ## Returns IT Admins OU to be used to create the groups and users in
        return $itadminsOU.DistinguishedName
    }
}

function Get-Groups {
    [cmdletbinding()]
    param()
    Begin {
        $groups_to_add = [System.Collections.Generic.List[Object]]::new()
    }

    Process {
        Write-Verbose "Checking if groups exist..."
        foreach ($group in $GROUPS_ARRAY) {
            if (Get-AdGroup -filter "Name -eq '$($group)'") {
                Continue
            }
            else {
                Write-Verbose "Group doesn't exist, adding $group to list..."
                $groups_to_add.Add($group)
            }            
        }
    }
    End {
        return $groups_to_add
    }
}

function New-Groups {
    [cmdletbinding()]
    param (
        [parameter(Mandatory,ValueFromPipeline,Position=0)]
        $group_list,
        [parameter(Mandatory,ValueFromPipeline,Position=1)]
        $OUPath
    )

    Begin {
        if ($null -eq $group_list) {
            Write-Debug "group_list is null, exiting the function New-Groups"
            Exit
        }
        $roles = @(
            'Domain Admins',
            'Group Policy Creator Owners',
            'Schema Admins',
            'Enterprise Admins',
            'Organization Management'
        )
    }

    Process {
        Write-Verbose 'Creating groups privded from the $group_list variable...'
        foreach ($group in $group_list) {
            Write-Verbose "Creaing new group: $group"
            New-ADGroup -Name $group -DisplayName $group -Path $OUPath -GroupScope Global -GroupCategory Security
            foreach ($role in $roles){
                try {
                    Write-Versbose "Adding role: $role to group $group..."
                    Add-ADGroupMember -Identity $role -Members $group
                }
                catch {
                    Write-Verbose "$role does not exist moving on to next one..."
                }
            }
        }
    }
}

function New-AdminADUsers {
    [cmdletbinding()]
    param (
        [parameter(Mandatory,ValueFromPipeline,Position=0)]
        [ValidateNotNullOrEmpty()]
        $user_list,

        [parameter(Mandatory,ValueFromPipeline,Position=1)]
        [ValidateNotNullOrEmpty()]
        $OUPath
    )

    Begin {}

    Process {

        foreach ($user in $user_list) {
            $user_params = @{
                'Name' = $user.samaccountname
                'DisplayName' = $user.samaccountname
                'AccountPassword' = New-Password
                'Path' = $OUPath
                'GivenName' = $user.firstname
                'Surname' = $user.lastname
                'Description' = 'Support Engineer'
                'Enabled' = $false
            }

            New-ADUser @user_params

            switch ($user.group) {
                'engineers' { 
                Write-Verbose "Adding $($user.samaccountname) to engineers and helpdesk group..."
                Add-ADGroupMember -Identity 'ServerAdmins' -Members $user.samaccountname
                Add-ADGroupMember -Identity 'HelpDesk' -Members $user.samaccountname
                }
                'helpdesk' { 
                Write-Verbose "Adding $($user.samaccountname) to helpdesk group..."
                Add-ADGroupMember -Identity 'HelpDesk' -Members $user.samaccountname 
                }
                Default {Continue}
            }
        }
    }
}

function Set-AdminADUsers {
    [cmdletbinding()]
    param (
        [parameter(Mandatory,ValueFromPipeline,Position=0)]
        [ValidateNotNullOrEmpty()]
        $users_to_disable
    )

    Begin {}

    Process {
        foreach ($user in $users_to_disable) {
            Write-Verbose "User not found in Hash Table, disabling user: $($user.samaccountname)..."
            Set-ADUser -Identity $user.samaccountname -Enabled $false
            switch ($user.group) {
                'engineers' { Remove-ADGroupMember -Identity 'ServerAdmins' -Members $user.samaccountname -Confirm:$false}
                'helpdesk' { Remove-ADGroupMember -Identity 'HelpDesk' -Members $user.samaccountname -Confirm:$false}
                Default { Continue }
            }
        }
    }
}

function Set-AdminUserStandards {
    [cmdletbinding()]
    param ()

    Begin {
        ######## Configure Variables for use in pipeline ########
        ## Get the current Admin users in AD
        $current_users = Get-AdminADUsers
        ## Get list of users to add and disable
        $users_to_add = Compare-ADUsersToAdd -current_users $current_users -user_to_compare $USERS_DICT
        $users_to_disable = Compare-ADUsersToDisable -current_users $current_users -user_to_compare $USERS_DICT
        ## Get OU's
        $base_ou_path = Get-OU
        $ous_to_add = Get-OUs -ou_path $base_ou_path
        ## Get groups
        $groups_to_add = Get-Groups 
    }

    Process {
        ## Starting script process
        Write-Verbose "Checking if OU_path is null and creating OU's if it is..."
        if ($ous_to_add -and $base_ou_path) {
            $IT_admins_ou = New-OUs -ous_to_add $ous_to_add -ou_path $base_ou_path
            Write-Verbose "OU's have been added to AD..."
        }
        elseif ($base_ou_path -and $null -eq $ous_to_add) {
            $IT_admins_ou = "OU=IT Admins,$($base_ou_path.DistinguishedName)"
        }
        else {
            try {
                $IT_admins_ou = New-OUs -ous_to_add $OU_ARRAY -ou_path $base_ou_path
                Write-Verbose "OU's have been added to AD..."
            }
            catch {
                Write-Error "OUs are already created..."
                $IT_admins_ou = "OU=IT Admins,$($base_ou_path.DistinguishedName)"
            }
        }

        Write-Verbose "Checking if groups need to be added..."
        if ($groups_to_add) {
            New-Groups -group_list $groups_to_add -OUPath $IT_admins_ou
            Write-Verbose "Groups have been added to AD..."
        }

        Write-Verbose "Checking for users to add..."
        if ($users_to_add) {
            Write-Verbose "Users to add found, adding users..."
            New-AdminADUsers -user_list $users_to_add -OUPath $IT_admins_ou
        }

        Write-Verbose "Checking for users to disable..."
        if ($users_to_disable) {
            Write-Verbose "Users to disable found, disabling users..."
            Set-AdminADUsers -users_to_disable $users_to_disable
        }
    }
}

Set-AdminUserStandards -Verbose
