<#
Copyright 2014 Cloudbase Solutions Srl

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
#>

$Source = @"
using System;
using System.Text;
using System.Runtime.InteropServices;

namespace PSCloudbase
{
    public sealed class Win32IniApi
    {
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        public static extern uint GetPrivateProfileString(
           string lpAppName,
           string lpKeyName,
           string lpDefault,
           StringBuilder lpReturnedString,
           uint nSize,
           string lpFileName);

        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool WritePrivateProfileString(
           string lpAppName,
           string lpKeyName,
           StringBuilder lpString, // Don't use string, as Powershell replaces $null with an empty string
           string lpFileName);

        [DllImport("Kernel32.dll")]
        public static extern uint GetLastError();
    }
}
"@

Add-Type -TypeDefinition $Source -Language CSharp

function Get-IniFileValue
{
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$Key,

        [parameter()]
        [string]$Section = "DEFAULT",

        [parameter()]
        [string]$Default = $null,

        [parameter(Mandatory=$true)]
        [string]$Path,

        [parameter()]
        [switch]$AsBoolean
    )
    process
    {
        $sb = New-Object -TypeName "System.Text.StringBuilder" -ArgumentList 1000
        $retVal = [PSCloudbase.Win32IniApi]::GetPrivateProfileString($Section, $Key, $Default, $sb, $sb.Capacity, $Path)
        if (!$retVal)
        {
            $lastErr = [PSCloudbase.Win32IniApi]::GetLastError()
            if ($lastErr -ne 2)
            {
                throw "Cannot get value from ini file: " + [PSCloudbase.Win32IniApi]::GetLastError()
            }
            elseif (!(Test-Path $Path))
            {
                throw "Ini file '$Path' does not exist"
            }
        }

        $value = $sb.ToString()
        if($AsBoolean)
        {
            return [System.Convert]::ToBoolean($value)
        }
        else
        {
            return $value
        }
    }
}

function Set-IniFileValue
{
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$Key,

        [parameter()]
        [string]$Section = "DEFAULT",

        [parameter(Mandatory=$true)]
        [string]$Value,

        [parameter(Mandatory=$true)]
        [string]$Path
    )
    process
    {
        $retVal = [PSCloudbase.Win32IniApi]::WritePrivateProfileString($Section, $Key, $Value, $Path)
        if (!$retVal -and [PSCloudbase.Win32IniApi]::GetLastError())
        {
            throw "Cannot set value in ini file: " + [PSCloudbase.Win32IniApi]::GetLastError()
        }
    }
}

function Remove-IniFileValue
{
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$Key,

        [parameter()]
        [string]$Section = "DEFAULT",

        [parameter(Mandatory=$true)]
        [string]$Path
    )
    process
    {
        $retVal = [PSCloudbase.Win32IniApi]::WritePrivateProfileString($Section, $Key, $null, $Path)
        if (!$retVal -and [PSCloudbase.Win32IniApi]::GetLastError())
        {
            throw "Cannot remove value from ini file: " + [PSCloudbase.Win32IniApi]::GetLastError()
        }
    }
}

Export-ModuleMember Get-IniFileValue, Set-IniFileValue, Remove-IniFileValue
