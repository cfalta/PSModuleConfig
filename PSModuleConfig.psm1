Set-StrictMode -Version 1.0

function Get-PSModuleConfigDefaults
{
    #Default for Windows OS
    $BasePath = $env:USERPROFILE 

    #Set BasePath to $Home since $env is not available on macOS
    if($PSVersionTable.OS -like "*Darwin*")
    {
        $BasePath = $Home 
    }

    #Not necessary at this stage but we keep it here in case we want to further distinguish betweend language modes in the future
    if($ExecutionContext.SessionState.LanguageMode -eq "ConstrainedLanguage")
    {
        $Defaults = New-Object -TypeName psobject
        $Defaults | Add-Member -MemberType NoteProperty -Name version -Value "1.0.0"
        $Defaults | Add-Member -MemberType NoteProperty -Name defaultconfigfolder -Value (Join-Path -Path $BasePath -ChildPath "PSModuleConfig")    
    }
    else {
        $Defaults = [PSCustomObject]@{
            version = "1.0.0"
            defaultconfigfolder = (Join-Path -Path $BasePath -ChildPath "PSModuleConfig")
        }
    }
    return $Defaults
}

function New-PSModuleConfig
{
    ##Params
    [CmdletBinding()]
    Param (
        #Name of the config file
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Name,

        #Data as hashtable
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [hashtable]
        $Data,

        #Encrypt switch
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Switch]
        $Encrypt,

        #Force switch to overwrite existing config files
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Switch]
        $Force
    )

    $DefaultConfigFolder = (Get-PSModuleConfigDefaults).defaultconfigfolder
    $PSModuleConfigVersion = (Get-PSModuleConfigDefaults).version

    if($PSBoundParameters['Encrypt'])
    {
        $UseEncryption=$true
    }
    else
    {
        $UseEncryption=$false
    }

    #Run Test-PSModuleConfig to check if the config file already exists in $DefaultConfigFolder
    if (Test-PSModuleConfig -ConfigName $Name -ConfigFolder $DefaultConfigFolder)
    {
        if($Force)
        {
            Write-Warning "Config file $Name already exists. Overwriting it as -Force switch was used"
        }
        else
        {
            Write-Output "Config file $Name already exists. Use -Force switch to overwrite it"
            return
        }
    }
    
    #Create PSCustomObject called $NewConfig        
    #Add the default psmoduleconfig params like encrypt under a node called psmoduleconfig
    if($ExecutionContext.SessionState.LanguageMode -eq "ConstrainedLanguage")
    {
        $NewConfig = New-Object -TypeName psobject
        $PSModuleConfigObject = New-Object -TypeName psobject
        $PSModuleConfigObject | Add-Member -MemberType NoteProperty -Name version -Value $PSModuleConfigVersion
        $PSModuleConfigObject | Add-Member -MemberType NoteProperty -Name encrypt -Value $UseEncryption
        $NewConfig | Add-Member -MemberType NoteProperty -Name psmoduleconfig -Value $PSModuleConfigObject
    }
    else {
        $NewConfig = [PSCustomObject]@{
            psmoduleconfig = @{
                version = $PSModuleConfigVersion
                encrypt = $UseEncryption
            }
        }
    }


    #Convert PSCustomobject to json
    $NewConfigJson = $NewConfig | ConvertTo-Json

    #Write it to a json file called $Name.json
    $NewConfigJson | Out-File -FilePath (Join-Path -Path $DefaultConfigFolder -ChildPath "$Name.json")

    #If $Data is not null, run Set-PSModuleConfig to add the data to the config file
    if($Data)
    {
        Set-PSModuleConfig -Name $Name -Data $Data
    }

}

function Get-PSModuleConfig
{
    ##Params
    [CmdletBinding()]
    Param (
        #Name of the config file
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Name
    )

    $DefaultConfigFolder = (Get-PSModuleConfigDefaults).defaultconfigfolder

    #Run Test-PSModuleConfig
    #If the config file does not exist, stop
    if (-not (Test-PSModuleConfig -ConfigName $Name))
    {
        Write-Error "Config file $Name does not exist. Please create it first"
        return
    }

    #Read config and convertfrom-json, on error stop
    try{
        $Config = Get-Content -Path (Join-Path -Path $DefaultConfigFolder -ChildPath "$Name.json") | ConvertFrom-Json -ErrorAction Stop
    }
    catch
    {
        Write-Error "Error reading config file $Name.json. Please check the file and try again"
        return
    }

    #Return the config
    return $Config

}

function Set-PSModuleConfig
{
    ##Params
    [CmdletBinding()]
    Param (
        #Name of the config file
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Name,
        #Parameterset Single, Param Key, Mandatory
        [Parameter(Mandatory = $true, ParameterSetName = "Single")]
        [ValidateNotNullOrEmpty()]
        [String]
        $Key,
        #Parameterset Single, Param Value, Mandatory
        [Parameter(Mandatory = $true, ParameterSetName = "Single")]
        [ValidateNotNullOrEmpty()]
        [String]
        $Value,
        #Parameterset Hashtable, Param Data, Mandatory
        [Parameter(Mandatory = $true, ParameterSetName = "Hashtable")]
        [ValidateNotNullOrEmpty()]
        [hashtable]
        $Data
    )

    $DefaultConfigFolder = (Get-PSModuleConfigDefaults).defaultconfigfolder
    
    #Get the existing config
    $OldConfig = Get-PSModuleConfig -Name $Name
    
    #Create a hashtable called $NewConfig based on the params
    if($PSCmdlet.ParameterSetName -eq "Single")
    {
        $NewConfig = @{
            $Key = $Value
        }
    }
    else
    {
        $NewConfig = $Data
    }

    #Check if encryption is set to true, if yes iterate through the keys and encrypt the values
    if($OldConfig.psmoduleconfig.encrypt -eq $true)
    {
        $NewConfigCrypt = $NewConfig.Clone()
        foreach ($SingleKey in $NewConfig.Keys)
        {
            $NewConfigCrypt[$SingleKey] = (ConvertTo-SecureString -String $NewConfig[$SingleKey] -AsPlainText -Force | ConvertFrom-SecureString)
        }
        $NewConfig = $NewConfigCrypt
    }

    #For each key in $OldConfig, check if it exists in $NewConfig. Add it if it does not
    foreach ($SingleKey in ($OldConfig.$Name).psobject.Properties.Name)
    {
        if(-not $NewConfig.ContainsKey($SingleKey))
        {
            $NewConfig.Add($SingleKey,$OldConfig.$Name.$SingleKey)
        }
    }

    #Create a new PSCustomObject containing an alphabetically sorted version of $NewConfig since you cannot sort a hashtable
    $NewConfigSorted = New-Object psobject
    $NewConfig.GetEnumerator() | Sort-Object Name | ForEach-Object {
        $NewConfigSorted | Add-Member -MemberType NoteProperty -Name $_.Key -Value $_.Value
    }

    #Create a new PSCustomObject with metadata and the new config
    if($ExecutionContext.SessionState.LanguageMode -eq "ConstrainedLanguage")
    {
        $FinalConfig  = New-Object -TypeName psobject
        $FinalConfig  | Add-Member -MemberType NoteProperty -Name psmoduleconfig -Value $OldConfig.psmoduleconfig
        $FinalConfig  | Add-Member -MemberType NoteProperty -Name $Name -Value $NewConfigSorted
    }
    else {
        $FinalConfig = [PSCustomObject]@{
            psmoduleconfig = $OldConfig.psmoduleconfig
            $Name = $NewConfigSorted
            }
    }

    

    #convert $newconfig back to json and write to config file
    $NewConfigJson = $FinalConfig | ConvertTo-Json
    $NewConfigJson | Out-File -FilePath (Join-Path -Path $DefaultConfigFolder -ChildPath "$Name.json") -Force
}

function Remove-PSModuleConfig
{
    ##Params
    [CmdletBinding()]
    Param (
        #Name of the config file
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Name
    )

    $DefaultConfigFolder = (Get-PSModuleConfigDefaults).defaultconfigfolder

    #Run Test-PSModuleConfig
    #If the config file does not exist, stop
    if (-not (Test-PSModuleConfig -ConfigName $Name))
    {
        Write-Error "Config file $Name does not exist. Nothing to remove"
        return
    }

    #Remove the config file
    Remove-Item -Path (Join-Path -Path $DefaultConfigFolder -ChildPath "$Name.json")
}

function Enable-PSModuleConfigEncryption
{
    ##Params
    [CmdletBinding()]
    Param (
        #Name of the config file
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Name
    )

    #Get the existing config
    $OldConfig = Get-PSModuleConfig -Name $Name -ErrorAction Stop

    if($OldConfig.psmoduleconfig.encrypt -eq $true)
    {
        Write-Error "Encryption flag is already set."
    }
    else {
        #Set the encrypt flag to true
        $OldConfig.psmoduleconfig.encrypt = $true
        
        #encrypt the data. using convertto-json workaround if constrained language mode is enabled since .copy() is not available in that case
        if($ExecutionContext.SessionState.LanguageMode -eq "ConstrainedLanguage")
        {
            $NewConfigCrypt = ($OldConfig | convertto-json -Depth 100) | convertfrom-json
        }
        else {
            $NewConfigCrypt = $OldConfig.psobject.copy()
        }
    

        foreach ($SingleKey in $OldConfig.$Name.psobject.properties.name)
        {
            $NewConfigCrypt.$Name.$SingleKey = (ConvertTo-SecureString -String $NewConfigCrypt.$Name.$SingleKey -AsPlainText -Force | ConvertFrom-SecureString)
        }

        #convert $newconfig back to json and write to config file
        $DefaultConfigFolder = (Get-PSModuleConfigDefaults).defaultconfigfolder
        $NewConfigJson = $NewConfigCrypt | ConvertTo-Json
        $NewConfigJson | Out-File -FilePath (Join-Path -Path $DefaultConfigFolder -ChildPath "$Name.json") -Force
    }
}

function Disable-PSModuleConfigEncryption
{
    ##Params
    [CmdletBinding()]
    Param (
        #Name of the config file
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Name
    )

    #Get the existing config
    $OldConfigRaw = Get-PSModuleConfig -Name $Name -ErrorAction Stop

    #Check encrypt flag first
    if($OldConfigRaw.psmoduleconfig.encrypt -eq $true)
    {
        $OldConfigRaw.psmoduleconfig.encrypt = $False
        $DecryptedData = Read-PSModuleConfig -Name $Name
        $OldConfigRaw.$Name = $DecryptedData
    }
    else {
        Write-Error "Encryption flag is not set. Are you sure this config is encrypted? If you want to proceed, set the flag manually to true and try again."
    }

    #convert $newconfig back to json and write to config file
    $DefaultConfigFolder = (Get-PSModuleConfigDefaults).defaultconfigfolder
    $NewConfigJson = $OldConfigRaw | ConvertTo-Json
    $NewConfigJson | Out-File -FilePath (Join-Path -Path $DefaultConfigFolder -ChildPath "$Name.json") -Force

}

function Test-PSModuleConfig
{
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ConfigName,
        
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ConfigFolder = ((Get-PSModuleConfigDefaults).defaultconfigfolder)
        )

    $ConfigFilePath = Join-Path -Path $ConfigFolder -ChildPath "$ConfigName.json"

    Write-Verbose $ConfigFilePath
    #Check if folder PSModuleConfig in the user profile directory exists. If not, create it
    if (-not (Test-Path -Path $ConfigFolder))
    {
        $null = New-Item -Path $ConfigFolder -ItemType Directory
    }
    #Check if the config file exists. If yes, return true. If no, return false.
    if (Test-Path -Path $ConfigFilePath)
    {
        return $true
    }
    else
    {
        return $false
    }
}

function Read-PSModuleConfig
{
    #Reads the config file based on the name and returns only the data, not the metadata
    ##Params
    [CmdletBinding()]
    Param (
        #Name of the config file
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Name
    )

    $Config = Get-PSModuleConfig -Name $Name
    
    if($Config)
    {
        #using convertto-json workaround if constrained language mode is enabled since .copy() is not available in that case
        if($ExecutionContext.SessionState.LanguageMode -eq "ConstrainedLanguage")
        {
            $ConfigData = ($Config.$Name | convertto-json -Depth 100) | convertfrom-json
        }
        else {
            $ConfigData = $Config.$Name.psobject.Copy()
        }

        #Check if encryption is set to true, if yes iterate through the keys and decrypt the values
        if($Config.psmoduleconfig.encrypt -eq $true)
        {
            foreach($item in $Config.$Name.psobject.Properties.Name)
            {
                try
                {
                    #If convert to securestring fails, we assume that the value is not encrypted and just copy it. Should make that better in the future :/
                    $TempVar = ($Config.$Name.$item | ConvertTo-SecureString)

                    if($PSVersionTable.PSVersion.Major -ge 7)
                    {
                        $ConfigData.$item = ($TempVar | ConvertFrom-SecureString -AsPlainText)
                    }
                    else {
                        [pscredential]$TempCredObject = New-Object System.Management.Automation.PSCredential ("none", $TempVar)
                        $ConfigData.$item = $TempCredObject.GetNetworkCredential().Password
                    }
                    
                }
                catch
                {
                    $ConfigData.$item = $Config.$Name.$item
                }
    
            }
        }
    
        $ConfigData
    }

}