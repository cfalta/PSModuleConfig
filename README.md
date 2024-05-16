# PSModuleConfig
A generic configuration management module for Powershell modules. PSModuleConfig offers a standardized way to store configuration parameters for other Powershell modules like URIs, User preferences, etc.

# Usage

## Create a new configuration with two config entries

```
New-PSModuleConfig -Name MyModule -Data @{"URI"="https://myapi.com"; "OtherParam"="SomedataHere"}
```

This will create the following file under `$env:userprofile\PSModuleConfig\MyModule.json`

```
{
    "psmoduleconfig":  {
                           "version":  "1.0.0",
                           "encrypt":  false
                       },
    "MyModule":  {
                     "OtherParam":  "SomedataHere",
                     "URI":  "https://myapi.com"
                 }
}
```

## Create a new empty configuration and add the data later

```
New-PSModuleConfig -Name MyModule
Set-PSModuleConfig -Name MyModule -Key "URI" -Value "https://myapi.com"
Set-PSModuleConfig -Name MyModule -Key "OtherParam" -Value "SomedataHere"
```

Add multiple entries at once using a dictionary.

```
New-PSModuleConfig -Name MyModule
Set-PSModuleConfig -Name MyModule -Data @{"URI"="https://myapi.com"; "OtherParam"="SomedataHere"}
```

## Protect an existing configuration

```
Enable-PSModuleConfigEncryption -Name MyModule
```

This will use ConvertFrom-SecureString with default to protect the configuration items using DPAPI. The known limitations of SecureString in Memory apply. See Microsofts [documentation](https://learn.microsoft.com/en-us/dotnet/fundamentals/runtime-libraries/system-security-securestring) for more details.

Disable like this.

```
Disable-PSModuleConfigEncryption -Name MyModule
```

You can also protect an new configuration right from the start using the `New-PSModuleConfig` command with the `-Encrypt` flag.

```
New-PSModuleConfig -Name MyModule -Data @{"URI"="https://myapi.com"; "OtherParam"="SomedataHere"} -Encrypt
```