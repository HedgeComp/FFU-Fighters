<# 
    .PARAMETER Make
    Make of the device to download drivers. Accepted values are: 'Microsoft', 'Dell', 'HP', 'Lenovo'.
    
    .PARAMETER Model
    Model of the device to download drivers. This is required if Make is set.
    
    .PARAMETER ModelList
    Path to a CSV file containing rows of "Make" and "Model" to process.

    .PARAMETER DriverFolder
    Path to your desired Drivers Folder

Useage example:

.\DriverDownloads.ps1 -Make HP -Model 'ProDesk 600' -DriversFolder 'c:\ffudrivers\' -verbose
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false, Position = 0)]
    [ValidateScript({ Test-Path $_ })]
  #  [string]$ISOPath,
    [string]$WindowsVersion = '24H2',
   # [ValidateSet(
    #    'Home', 'Home N', 'Home Single Language', 'Education', 'Education N', 
    #    'Pro', 'Pro N', 'Pro Education', 'Pro Education N', 'Pro for Workstations', 
    #    'Pro N for Workstations', 'Enterprise', 'Enterprise N', 'Standard', 
    #    'Standard (Desktop Experience)', 'Datacenter', 'Datacenter (Desktop Experience)'
    #)]
    #[string]$WindowsSKU = 'Pro',

    [ValidateScript({ Test-Path $_ })]
    [string]$FFUDevelopmentPath = $PSScriptRoot,

    #[hashtable]$AppsScriptVariables,

    [ValidateSet('Microsoft', 'Dell', 'HP', 'Lenovo')]
    [string]$Make,

    [string]$WindowsArch = 'x64',
    [int]$WindowsRelease = 11,
    [string]$DriversFolder,
    [string]$Model,
    [string]$ModelList
)

# -------------------------------------------------------------------------
#  RUNTIME CHECK FOR $Make
# -------------------------------------------------------------------------
$validMakes = @('Microsoft', 'Dell', 'HP', 'Lenovo')
if ($PSBoundParameters.ContainsKey('Make') -and $Make -and $Make -notin $validMakes) {
    Write-Error "Invalid '-Make' parameter: '$Make'. Valid values are: $($validMakes -join ', ')"
    exit
}
# -------------------------------------------------------------------------
#Write-host "diver path is $FFUDevelopmentPath"
if (-not $DriversFolder) {
    $DriversFolder = Join-Path $PSScriptRoot '\DRIVERS'
}
Write-Host "Driverfoldesr set to $driversFolder"
##############################################################################
#  LOGGING / HELPER FUNCTIONS
##############################################################################

# Replace this dummy logging function with your own logger if you want
function WriteLog($message) {
    Write-Host $message
}

function Invoke-Process {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$ArgumentList,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [bool]$Wait = $true
    )

    $ErrorActionPreference = 'Stop'

    try {
        $stdOutTempFile = "$env:TEMP\$((New-Guid).Guid)"
        $stdErrTempFile = "$env:TEMP\$((New-Guid).Guid)"

        $startProcessParams = @{
            FilePath               = $FilePath
            ArgumentList           = $ArgumentList
            RedirectStandardError  = $stdErrTempFile
            RedirectStandardOutput = $stdOutTempFile
            Wait                   = $($Wait);
            PassThru               = $true;
            NoNewWindow            = $true;
        }
        if ($PSCmdlet.ShouldProcess("Process [$($FilePath)]", "Run with args: [$($ArgumentList)]")) {
            $cmd = Start-Process @startProcessParams
            $cmdOutput = Get-Content -Path $stdOutTempFile -Raw
            $cmdError = Get-Content -Path $stdErrTempFile -Raw
            if ($cmd.ExitCode -ne 0 -and $wait -eq $true) {
                if ($cmdError) {
                    throw $cmdError.Trim()
                }
                if ($cmdOutput) {
                    throw $cmdOutput.Trim()
                }
            }
            else {
                if ([string]::IsNullOrEmpty($cmdOutput) -eq $false) {
                    WriteLog $cmdOutput
                }
            }
        }
    }
    catch {
        #$PSCmdlet.ThrowTerminatingError($_)
        WriteLog $_
        # Write-Host "Script failed - $Logfile for more info"
        throw $_
    
    }
    finally {
        Remove-Item -Path $stdOutTempFile, $stdErrTempFile -Force -ErrorAction Ignore
    }
    return $cmd
}

function Start-BitsTransferWithRetry {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Source,
        [Parameter(Mandatory = $true)]
        [string]$Destination,
        [int]$Retries = 3
    )

    $attempt = 0
    while ($attempt -lt $Retries) {
        try {
            $OriginalVerbosePreference = $VerbosePreference
            $VerbosePreference = 'SilentlyContinue'
            $ProgressPreference = 'SilentlyContinue'
            Start-BitsTransfer -Source $Source -Destination $Destination -ErrorAction Stop
            $ProgressPreference = 'Continue'
            $VerbosePreference = $OriginalVerbosePreference
            return
        }
        catch {
            $attempt++
            WriteLog "Attempt $attempt of $Retries failed to download $Source. Retrying..."
            Start-Sleep -Seconds 5
        }
    }
    WriteLog "Failed to download $Source after $Retries attempts."
    return $false
}

function Test-Url {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Url
    )
    try {
        $request = [System.Net.WebRequest]::Create($Url)
        $request.Method = 'HEAD'
        $response = $request.GetResponse()
        return $true
    }
    catch {
        return $false
    }
}

##############################################################################
#  MICROSOFT DRIVERS
##############################################################################
function Get-MicrosoftDrivers {
    param (
        [string]$Make,
        [string]$Model,
        [int]$WindowsRelease
    )

    $url = "https://support.microsoft.com/en-us/surface/download-drivers-and-firmware-for-surface-09bb2e09-2a4b-cb69-0951-078a7739e120"

    # Download the webpage content
    WriteLog "Getting Surface driver information from $url"
    $OriginalVerbosePreference = $VerbosePreference
    $VerbosePreference = 'SilentlyContinue'
    $webContent = Invoke-WebRequest -Uri $url -UseBasicParsing
    $VerbosePreference = $OriginalVerbosePreference
    WriteLog "Complete"

    # Parse the HTML content using Regex
    WriteLog "Parsing web content for models and download links"
    $html = $webContent.Content

    $divPattern = '<div[^>]*class="selectable-content-options__option-content(?: ocHidden)?"[^>]*>(.*?)</div>'
    $divMatches = [regex]::Matches($html, $divPattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)

    $models = @()

    foreach ($divMatch in $divMatches) {
        $divContent = $divMatch.Groups[1].Value

        $tablePattern = '<table[^>]*>(.*?)</table>'
        $tableMatches = [regex]::Matches($divContent, $tablePattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)

        foreach ($tableMatch in $tableMatches) {
            $tableContent = $tableMatch.Groups[1].Value

            $rowPattern = '<tr[^>]*>(.*?)</tr>'
            $rowMatches = [regex]::Matches($tableContent, $rowPattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)

            foreach ($rowMatch in $rowMatches) {
                $rowContent = $rowMatch.Groups[1].Value
                $cellPattern = '<td[^>]*>\s*(?:<p[^>]*>)?(.*?)(?:</p>)?\s*</td>'
                $cellMatches = [regex]::Matches($rowContent, $cellPattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)

                if ($cellMatches.Count -ge 2) {
                    $modelName = ($cellMatches[0].Groups[1].Value).Trim()
                    $secondTdContent = $cellMatches[1].Groups[1].Value.Trim()
                    $linkPattern = '<a[^>]+href="([^"]+)"[^>]*>'
                    $linkMatch = [regex]::Match($secondTdContent, $linkPattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

                    if ($linkMatch.Success) {
                        $modelLink = $linkMatch.Groups[1].Value
                    }
                    else {
                        $modelLink = $secondTdContent
                    }
                    $models += [PSCustomObject]@{ Model = $modelName; Link = $modelLink }
                }
            }
        }
    }

    WriteLog "Parsing complete"

    $selectedModel = $models | Where-Object { $_.Model -eq $Model }

    if ($null -eq $selectedModel) {
        WriteLog "The model '$Model' was not found in the list of available models."
        for ($i = 0; $i -lt $models.Count; $i++) {
            Write-Host "$($i + 1). $($models[$i].Model)"
        }
        do {
            $selection = Read-Host "Enter the number of the model you want to select"
            if ($selection -match '^\d+$' -and [int]$selection -ge 1 -and [int]$selection -le $models.Count) {
                $selectedModel = $models[$selection - 1]
            }
            else {
                Write-Host "Invalid selection. Please try again."
            }
        } while ($null -eq $selectedModel)
    }

    $Model = $selectedModel.Model
    WriteLog "Model: $Model"
    WriteLog "Download Page: $($selectedModel.Link)"

    WriteLog "Getting download page content"
    $OriginalVerbosePreference = $VerbosePreference
    $VerbosePreference = 'SilentlyContinue'
    $downloadPageContent = Invoke-WebRequest -Uri $selectedModel.Link -UseBasicParsing
    $VerbosePreference = $OriginalVerbosePreference
    WriteLog "Complete"
    WriteLog "Parsing download page for file"

    $scriptPattern = '<script>window.__DLCDetails__={(.*?)}<\/script>'
    $scriptMatch = [regex]::Match($downloadPageContent.Content, $scriptPattern)
    if ($scriptMatch.Success) {
        $scriptContent = $scriptMatch.Groups[1].Value
        $downloadFilePattern = '"name":"(.*?)",.*?"url":"(.*?)"'
        $downloadFileMatches = [regex]::Matches($scriptContent, $downloadFilePattern)

        $downloadLink = $null
        foreach ($downloadFile in $downloadFileMatches) {
            $fileName = $downloadFile.Groups[1].Value
            $fileUrl  = $downloadFile.Groups[2].Value
            if ($fileName -match "Win$WindowsRelease") {
                $downloadLink = $fileUrl
                break
            }
        }

        if ($downloadLink) {
            WriteLog "Download Link for Windows ${WindowsRelease}: $downloadLink"

            if (-not (Test-Path -Path $DriversFolder)) {
                WriteLog "Creating Drivers folder: $DriversFolder"
                New-Item -Path $DriversFolder -ItemType Directory -Force | Out-Null
            }
            $surfaceDriversPath = Join-Path -Path $DriversFolder -ChildPath $Make
            $modelPath = Join-Path -Path $surfaceDriversPath -ChildPath $Model
            if (-Not (Test-Path -Path $modelPath)) {
                WriteLog "Creating model folder: $modelPath"
                New-Item -Path $modelPath -ItemType Directory | Out-Null
            }

            $filePath = Join-Path -Path $surfaceDriversPath -ChildPath ($fileName)
            WriteLog "Downloading $Model driver file to $filePath"
            Start-BitsTransferWithRetry -Source $downloadLink -Destination $filePath
            WriteLog "Download complete"

            $fileExtension = [System.IO.Path]::GetExtension($filePath).ToLower()
            if ($fileExtension -eq ".msi") {
                WriteLog "Extracting MSI file to $modelPath"
                $arguments = "/a `"$($filePath)`" /qn TARGETDIR=`"$($modelPath)`""
                Invoke-Process -FilePath "msiexec.exe" -ArgumentList $arguments | Out-Null
                WriteLog "Extraction complete"
            }
            elseif ($fileExtension -eq ".zip") {
                WriteLog "Extracting ZIP file to $modelPath"
                $ProgressPreference = 'SilentlyContinue'
                Expand-Archive -Path $filePath -DestinationPath $modelPath -Force
                $ProgressPreference = 'Continue'
                WriteLog "Extraction complete"
            }
            else {
                WriteLog "Unsupported file type: $fileExtension"
            }
            WriteLog "Removing $filePath"
            Remove-Item -Path $filePath -Force
            WriteLog "Complete"
        }
        else {
            WriteLog "No download link found for Windows $WindowsRelease."
        }
    }
    else {
        WriteLog "Failed to parse the download page for the MSI file."
    }
}

function Get-HPDrivers {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$Make,
        [Parameter()]
        [string]$Model,
        [Parameter()]
        [ValidateSet("x64", "x86", "ARM64")]
        [string]$WindowsArch,
        [Parameter()]
        [ValidateSet(10, 11)]
        [int]$WindowsRelease,
        [Parameter()]
        [string]$WindowsVersion
    )

    ###############################################################################
    # (OPTIONAL) Convert-ComplexVersion
    # Used to handle slash- or multi-part version strings. If your HP "version"
    # strings are always simple, you can omit or simplify this.
    ###############################################################################
    function Convert-ComplexVersion {
        param (
            [Parameter(Mandatory)]
            [string]$VersionString
        )

        # Split by slash in case the version string has multiple sub-versions
        $parts = $VersionString -split '/'

        $validVersions = @()
        foreach ($part in $parts) {
            try {
                # Attempt conversion to [System.Version]
                $converted = [Version]$part
                $validVersions += $converted
            }
            catch {
                # Ignore parts that are not valid versions
            }
        }

        # If none of the parts were valid, return 0.0.0.0 as a fallback
        if ($validVersions.Count -eq 0) {
            return [Version]"0.0.0.0"
        }

        # Return the highest version (descending sort, pick the first)
        return $validVersions | Sort-Object -Descending | Select-Object -First 1
    }

    WriteLog "Gathering HP drivers for model: $Model"

    # -------------------------------------------------------------------------
    # Download and extract platformList.cab
    # -------------------------------------------------------------------------
    $PlatformListUrl = 'https://hpia.hpcloud.hp.com/ref/platformList.cab'
    $DriversFolder   = Join-Path $DriversFolder $Make
    $PlatformListCab = Join-Path $DriversFolder 'platformList.cab'
    $PlatformListXml = Join-Path $DriversFolder 'PlatformList.xml'

    if (-not (Test-Path -Path $DriversFolder)) {
        WriteLog "Creating Drivers folder: $DriversFolder"
        New-Item -Path $DriversFolder -ItemType Directory -Force | Out-Null
        WriteLog "Drivers folder created."
    }

    WriteLog "Downloading $PlatformListUrl to $PlatformListCab"
    Start-BitsTransferWithRetry -Source $PlatformListUrl -Destination $PlatformListCab
    WriteLog "Download complete."

    WriteLog "Expanding $PlatformListCab to $PlatformListXml"
    Invoke-Process -FilePath 'expand.exe' -ArgumentList "$PlatformListCab $PlatformListXml" | Out-Null
    WriteLog "Expansion complete."

    # Parse the platform list to find SystemID
    [xml]$PlatformListContent = Get-Content -Path $PlatformListXml
    $ProductNodes = $PlatformListContent.ImagePal.Platform | Where-Object { $_.ProductName.'#text' -match $Model }

    $ProductNames = @()
    foreach ($node in $ProductNodes) {
        foreach ($productName in $node.ProductName) {
            if ($productName.'#text' -match $Model) {
                $ProductNames += [PSCustomObject]@{
                    ProductName = $productName.'#text'
                    SystemID    = $node.SystemID
                    OSReleaseID = $node.OS.OSReleaseIdFileName -replace 'H','h'
                    IsWindows11 = $node.OS.IsWindows11 -contains 'true'
                }
            }
        }
    }

    if ($ProductNames.Count -gt 1) {
        Write-Host "More than one model found matching '$Model':"
        for ($i = 0; $i -lt $ProductNames.Count; $i++) {
            Write-Host "$($i + 1). $($ProductNames[$i].ProductName)"
        }
        $selection = Read-Host "Select the number of the correct model"
        if ($selection -match '^\d+$' -and [int]$selection -le $ProductNames.Count) {
            $SelectedProduct = $ProductNames[[int]$selection - 1]
            $ProductName     = $SelectedProduct.ProductName
            $SystemID        = $SelectedProduct.SystemID
            $ValidOSReleaseIDs = $SelectedProduct.OSReleaseID
            $IsWindows11     = $SelectedProduct.IsWindows11
        }
        else {
            Write-Host "Invalid selection. Exiting."
            exit
        }
    }
    elseif ($ProductNames.Count -eq 1) {
        $SelectedProduct = $ProductNames[0]
        $ProductName     = $SelectedProduct.ProductName
        $SystemID        = $SelectedProduct.SystemID
        $ValidOSReleaseIDs = $SelectedProduct.OSReleaseID
        $IsWindows11     = $SelectedProduct.IsWindows11
    }
    else {
        Write-Host "No models found matching '$Model'. Exiting."
        exit
    }

    if (-not $SystemID) {
        Write-Host "SystemID not found for model: $Model. Exiting."
        exit
    }

    # Validate WindowsRelease vs. IsWindows11
    if ($WindowsRelease -eq 11 -and -not $IsWindows11) {
        Write-Host "No drivers are available for Windows 11 for this model. Exiting."
        exit
    }

    # Validate WindowsVersion
    $OSReleaseIDs = $ValidOSReleaseIDs -split ' '
    $MatchingReleaseID = $OSReleaseIDs | Where-Object { $_ -eq "$WindowsVersion" }
    if (-not $MatchingReleaseID) {
        Write-Host "The specified WindowsVersion '$WindowsVersion' is not valid for $ProductName. Valid IDs:"
        for ($i = 0; $i -lt $OSReleaseIDs.Count; $i++) {
            Write-Host "$($i + 1). $($OSReleaseIDs[$i])"
        }
        $selection = Read-Host "Select the number for the correct OSReleaseID"
        if ($selection -match '^\d+$' -and [int]$selection -le $OSReleaseIDs.Count) {
            $WindowsVersion = $OSReleaseIDs[[int]$selection - 1]
        }
        else {
            Write-Host "Invalid selection. Exiting."
            exit
        }
    }

    # Construct the driver cab URL
    $Arch = $WindowsArch -replace "^x", ""
    $HPWindowsVersion = $WindowsVersion -replace 'H','h'
    #$ModelRelease  = $SystemID + "_$Arch" + "_$WindowsRelease" + ".0.$WindowsVersion"
    $ModelRelease  = $SystemID + "_$Arch" + "_$WindowsRelease" + ".0.$HPWindowsVersion"
    $DriverCabUrl  = "https://hpia.hpcloud.hp.com/ref/$SystemID/$ModelRelease.cab"
    $DriverCabFile = Join-Path $DriversFolder "$ModelRelease.cab"
    $DriverXmlFile = Join-Path $DriversFolder "$ModelRelease.xml"

    if (-not (Test-Url -Url $DriverCabUrl)) {
        Write-Host "HP Driver cab URL not accessible: $DriverCabUrl. Exiting."
        exit
    }

    WriteLog "Downloading HP Driver cab from $DriverCabUrl to $DriverCabFile"
    Start-BitsTransferWithRetry -Source $DriverCabUrl -Destination $DriverCabFile
    WriteLog "Expanding HP Driver cab to $DriverXmlFile"
    Invoke-Process -FilePath 'expand.exe' -ArgumentList "$DriverCabFile $DriverXmlFile" | Out-Null

    [xml]$DriverXmlContent = Get-Content -Path $DriverXmlFile
    $baseUrl = "https://ftp.hp.com/pub/softpaq/sp"

    WriteLog "Downloading drivers for $ProductName"

    foreach ($update in $DriverXmlContent.ImagePal.Solutions.UpdateInfo) {

        # Only handle "Driver" items
        if ($update.Category -notmatch '^Driver') {
            continue
        }

        # Extract info
        $Name      = $update.Name -replace '[\\\/\:\*\?\"\<\>\|]', '_'
        $Category  = $update.Category -replace '[\\\/\:\*\?\"\<\>\|]', '_'
        $Version   = $update.Version  # Keep the raw version string here

        $DriverUrl     = "https://$($update.URL)"
        $DriverFileName= [System.IO.Path]::GetFileName($DriverUrl)
        $downloadFolder= Join-Path $DriversFolder "$ProductName\$Category"
        $DriverFilePath= Join-Path $downloadFolder $DriverFileName

        # ------------------------------------------------------------------------------
        # VERSION CHECK (new logic)
        # ------------------------------------------------------------------------------
        # Convert the remote version to a System.Version
        [Version]$remoteVersion = Convert-ComplexVersion($Version)

        # We'll store the local version in a file named driver.ver under $downloadFolder
        $localVersionFile = Join-Path $downloadFolder "driver.ver"
        [Version]$localVersion = [Version]"0.0.0.0"

        # If that file exists, read it
        if (Test-Path $localVersionFile) {
            try {
                $localVersionString = Get-Content -Path $localVersionFile -ErrorAction Stop
                $localVersion       = [Version]$localVersionString
            }
            catch {
                # Could not parse local version; fall back to 0.0.0.0
            }
        }

        # If local version >= remote, skip download
        if ($localVersion -ge $remoteVersion) {
            WriteLog "Driver $Name (version $localVersion) is already up to date. Skipping..."
            continue
        }
        # ------------------------------------------------------------------------------
        # END VERSION CHECK
        # ------------------------------------------------------------------------------

        # If we haven't downloaded/extracted this version yet, proceed
        if (-not (Test-Path -Path $downloadFolder)) {
            WriteLog "Creating download folder: $downloadFolder"
            New-Item -Path $downloadFolder -ItemType Directory -Force | Out-Null
        }

        # Download if needed
        if (Test-Path -Path $DriverFilePath) {
            WriteLog "Driver file already exists: $DriverFilePath; re-downloading not forced in this example."
        }
        else {
            WriteLog "Downloading driver to: $DriverFilePath"
          $downloadsuccess =  Start-BitsTransferWithRetry -Source $DriverUrl -Destination $DriverFilePath
            
        }

        if ($downloadsuccess) {WriteLog "Driver downloaded."
        # Extract
        $extractFolder = "$downloadFolder\$Name\$Version\" + $DriverFileName.TrimEnd('.exe')
        #$extractFolder = Join-Path $downloadFolder "$Name\$($Version -replace '[\\\/\:\*\?\"\<\>\|]', '_')\" + $DriverFileName.TrimEnd('.exe')
        if (-not (Test-Path $extractFolder)) {
            WriteLog "Creating extraction folder: $extractFolder"
            New-Item -Path $extractFolder -ItemType Directory -Force | Out-Null
        }

        $arguments = "/s /e /f `"$extractFolder`""
        WriteLog "Extracting driver: $DriverFilePath"
        Invoke-Process -FilePath $DriverFilePath -ArgumentList $arguments | Out-Null
        WriteLog "Driver extracted to: $extractFolder"

        # Remove the driver .exe after extraction
        Remove-Item -Path $DriverFilePath -Force
        WriteLog "Driver installation file deleted: $DriverFilePath"

        # Store the new version in driver.ver
        try {
            $remoteVersion.ToString() | Out-File -FilePath $localVersionFile -Force -Encoding UTF8
            WriteLog "Updated driver.ver with version $remoteVersion"
        }
        catch {
            WriteLog "Failed to store driver version: $_"
        }
    }
    }

    # Cleanup cabs
    Remove-Item -Path $DriverCabFile, $DriverXmlFile, $PlatformListCab, $PlatformListXml -Force
    WriteLog "Driver cab and xml files deleted."
}


##############################################################################
#  LENOVO DRIVERS
##############################################################################
function Get-LenovoDrivers {
    param (
        [Parameter()]
        [string]$Model,
        [Parameter()]
        [ValidateSet("x64", "x86", "ARM64")]
        [string]$WindowsArch,
        [Parameter()]
        [ValidateSet(10, 11)]
        [int]$WindowsRelease
    )

    ###############################################################################
    # FUNCTION: Convert-ComplexVersion
    # PURPOSE:  Safely convert multi-part/slash-separated version strings into a
    #           single [System.Version] by choosing the highest valid version found.
    ###############################################################################
    function Convert-ComplexVersion {
        param (
            [Parameter(Mandatory)]
            [string]$VersionString
        )

        $parts = $VersionString -split '/'
        $validVersions = @()
        foreach ($part in $parts) {
            try {
                $converted = [Version]$part
                $validVersions += $converted
            }
            catch {
                # ignore
            }
        }
        if ($validVersions.Count -eq 0) {
            return [Version]"0.0.0.0"
        }
        return $validVersions | Sort-Object -Descending | Select-Object -First 1
    }

    ###############################################################################
    # FUNCTION: Get-LenovoPSREF
    ###############################################################################
    function Get-LenovoPSREF {
        param (
            [string]$ModelName
        )

        $url = "https://psref.lenovo.com/api/search/DefinitionFilterAndSearch/Suggest?kw=$ModelName"
        WriteLog "Querying Lenovo PSREF API for model: $ModelName"
        $OriginalVerbosePreference = $VerbosePreference
        $VerbosePreference = 'SilentlyContinue'
        $response = Invoke-WebRequest -Uri $url -UseBasicParsing
        $VerbosePreference = $OriginalVerbosePreference
        WriteLog "Complete"

        $jsonResponse = $response.Content | ConvertFrom-Json

        $products = @()
        foreach ($item in $jsonResponse.data) {
            $productName = $item.ProductName
            $machineTypes = $item.MachineType -split " / "

            foreach ($machineType in $machineTypes) {
                if ($machineType -eq $ModelName) {
                    WriteLog "Model name entered is a matching machine type"
                    $products = @()
                    $products += [pscustomobject]@{
                        ProductName = $productName
                        MachineType = $machineType
                    }
                    return $products
                }
                $products += [pscustomobject]@{
                    ProductName = $productName
                    MachineType = $machineType
                }
            }
        }
        return ,$products
    }

    ###############################################################################
    # MAIN SCRIPT LOGIC
    ###############################################################################
    $machineTypes = Get-LenovoPSREF -ModelName $Model
    if ($machineTypes.ProductName.Count -eq 0) {
        WriteLog "No machine types found for model: $Model"
        WriteLog "Enter a valid model or machine type in the -model parameter"
        exit
    }
    elseif ($machineTypes.ProductName.Count -eq 1) {
        $machineType = $machineTypes[0].MachineType
        $model = $machineTypes[0].ProductName
    }
    else {
        WriteLog "Multiple machine types found for model: $Model"
        for ($i = 0; $i -lt $machineTypes.ProductName.Count; $i++) {
            Write-Host "$($i + 1). $($machineTypes[$i].ProductName) ($($machineTypes[$i].MachineType))"
        }
        $selection = Read-Host "Enter the number of the model you want to select"
        $machineType = $machineTypes[$selection - 1].MachineType
        $model = $machineTypes[$selection - 1].ProductName
    }

    $ModelRelease = $machineType + "_Win" + $WindowsRelease
    $CatalogUrl = "https://download.lenovo.com/catalog/$ModelRelease.xml"
    WriteLog "Lenovo Driver catalog URL: $CatalogUrl"

    if (-not (Test-Url -Url $CatalogUrl)) {
        Write-Error "Lenovo Driver catalog URL is not accessible: $CatalogUrl"
        exit
    }

    $driversFolder = "$DriversFolder\Lenovo"
    if (-not (Test-Path -Path $DriversFolder)) {
        WriteLog "Creating Drivers folder: $DriversFolder"
        New-Item -Path $DriversFolder -ItemType Directory -Force | Out-Null
    }

    $LenovoCatalogXML = "$DriversFolder\$ModelRelease.xml"
    WriteLog "Downloading $CatalogUrl to $LenovoCatalogXML"
    Start-BitsTransferWithRetry -Source $CatalogUrl -Destination $LenovoCatalogXML
    WriteLog "Download Complete"

    $xmlContent = [xml](Get-Content -Path $LenovoCatalogXML)
    WriteLog "Parsing Lenovo catalog XML"

    foreach ($package in $xmlContent.packages.package) {
        $packageUrl = $package.location
        $category   = $package.category

        if ($category -like 'BIOS*') {
            continue
        }
        if ($category -eq 'Motherboard Devices Backplanes core chipset onboard video PCIe switches') {
            $category = 'Motherboard Devices'
        }

        $packageName = [System.IO.Path]::GetFileName($packageUrl)
        $baseURL     = $packageUrl -replace $packageName, ""
        $packageXMLPath = "$DriversFolder\$packageName"
        WriteLog "Retreaving $category package XML $packageUrl" # to $packageXMLPath"
        If ((Start-BitsTransferWithRetry -Source $packageUrl -Destination $packageXMLPath) -eq $false) {
            Write-Output "Failed to download $category package XML: $packageXMLPath"
            continue
        }

        $packageXmlContent = [xml](Get-Content -Path $packageXMLPath)
        $packageType       = $packageXmlContent.Package.PackageType.type
        $packageTitle      = $packageXmlContent.Package.title.InnerText
        $packageTitle      = $packageTitle -replace '[\\\/\:\*\?\"\<\>\|]', '_'
        $packageTitle      = $packageTitle -replace ' - .*', ''

        if ($packageType -ne 2) {
            Remove-Item -Path $packageXMLPath -Force
            continue
        }

        $driverFileName  = $packageXmlContent.Package.Files.Installer.File.Name
        $extractCommand  = $packageXmlContent.Package.ExtractCommand
        if (!($extractCommand)) {
            Remove-Item -Path $packageXMLPath -Force
            continue
        }

        $rawVersionString = $packageXmlContent.Package.version
        if (-not $rawVersionString) {
            $rawVersionString = '0.0.0.0'
        }
        [Version]$remoteVersion = Convert-ComplexVersion $rawVersionString

        $downloadFolder   = "$DriversFolder\$model\$category\$packageTitle"
        $localVersionFile = Join-Path $downloadFolder "driver.ver"
        [Version]$localVersion = [Version]"0.0.0.0"
        if (Test-Path $localVersionFile) {
            try {
                $localVersionString = Get-Content -Path $localVersionFile -ErrorAction Stop
                $localVersion       = [Version]$localVersionString
            }
            catch {
            }
        }
        if ($localVersion -ge $remoteVersion) {
            WriteLog "Driver $packageTitle (version $localVersion) is already up to date. Skipping..."
            Remove-Item -Path $packageXMLPath -Force
            continue
        }

        $driverUrl       = $baseURL + $driverFileName
        $driverFilePath  = Join-Path -Path $downloadFolder -ChildPath $driverFileName
        if (Test-Path -Path $driverFilePath) {
            WriteLog "Driver already downloaded: $driverFilePath skipping"
            continue
        }

        if (-not (Test-Path -Path $downloadFolder)) {
            WriteLog "Creating download folder: $downloadFolder"
            New-Item -Path $downloadFolder -ItemType Directory -Force | Out-Null
        }

        WriteLog "Downloading driver: $driverUrl to $driverFilePath"
        Start-BitsTransferWithRetry -Source $driverUrl -Destination $driverFilePath
        WriteLog "Driver downloaded"

        $extractFolder = $downloadFolder + "\" + $driverFileName.TrimEnd($driverFileName[-4..-1])
        WriteLog "Creating extract folder: $extractFolder"
        New-Item -Path $extractFolder -ItemType Directory -Force | Out-Null
        WriteLog "Extract folder created"

        $modifiedExtractCommand = $extractCommand -replace '%PACKAGEPATH%', "`"$extractFolder`""

        WriteLog "Extracting driver: $driverFilePath"
        try {
            Invoke-Process -FilePath $driverFilePath -ArgumentList $modifiedExtractCommand | Out-Null
        }
        catch {
            $arguments = "/s /e=`"$extractFolder`""
            WriteLog "Extraction with default command failed; retrying with $arguments"
            Invoke-Process -FilePath $driverFilePath -ArgumentList $arguments | Out-Null
        }
        WriteLog "Driver extracted"

        try {
            $remoteVersion.ToString() | Out-File -FilePath $localVersionFile -Force -Encoding UTF8
        }
        catch {
        }

        WriteLog "Deleting driver installation file: $driverFilePath"
        Remove-Item -Path $driverFilePath -Force

        WriteLog "Deleting package XML file: $packageXMLPath"
        Remove-Item -Path $packageXMLPath -Force
    }

    WriteLog "Deleting catalog XML file: $LenovoCatalogXML"
    Remove-Item -Path $LenovoCatalogXML -Force
    WriteLog "Catalog XML file deleted"
    WriteLog "Lenovo Driver Download Completed"
    WriteLog "************************************************"
}

##############################################################################
#  DELL DRIVERS
##############################################################################
function Get-DellDrivers {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Model,
        [Parameter(Mandatory = $true)]
        [ValidateSet("x64", "x86", "ARM64")]
        [string]$WindowsArch,
        [Parameter(Mandatory = $true)]
        [int]$WindowsRelease
    )

    WriteLog "Gathering Dell drivers for $Model..."

    if (-not (Test-Path -Path $DriversFolder)) {
        WriteLog "Creating Drivers folder: $DriversFolder"
        New-Item -Path $DriversFolder -ItemType Directory -Force | Out-Null
        WriteLog "Drivers folder created"
    }

    $DriversFolder = Join-Path $DriversFolder 'Dell'
    WriteLog "Creating Dell Drivers folder: $DriversFolder"
    New-Item -Path $DriversFolder -ItemType Directory -Force | Out-Null
    WriteLog "Dell Drivers folder created"

    # CatalogPC.cab is for Windows client PCs, Catalog.cab is for Windows Server
    if ($WindowsRelease -le 11) {
        $catalogUrl = "http://downloads.dell.com/catalog/CatalogPC.cab"
        $DellCabFile = Join-Path $DriversFolder 'CatalogPC.cab'
        $DellCatalogXML = Join-Path $DriversFolder 'CatalogPC.xml'
    }
    else {
        $catalogUrl = "https://downloads.dell.com/catalog/Catalog.cab"
        $DellCabFile = Join-Path $DriversFolder 'Catalog.cab'
        $DellCatalogXML = Join-Path $DriversFolder 'Catalog.xml'
    }
    
    if (-not (Test-Url -Url $catalogUrl)) {
        WriteLog "Dell Catalog cab URL is not accessible: $catalogUrl. Exiting."
        exit
    }

    WriteLog "Downloading Dell Catalog cab file: $catalogUrl to $DellCabFile"
    Start-BitsTransferWithRetry -Source $catalogUrl -Destination $DellCabFile
    WriteLog "Dell Catalog cab file downloaded"

    WriteLog "Extracting Dell Catalog cab file to $DellCatalogXML"
    Invoke-Process -FilePath 'Expand.exe' -ArgumentList "$DellCabFile $DellCatalogXML" | Out-Null
    WriteLog "Dell Catalog cab file extracted"

    $xmlContent   = [xml](Get-Content -Path $DellCatalogXML)
    $baseLocation = "https://" + $xmlContent.manifest.baseLocation + "/"
    $latestDrivers = @{}

    $softwareComponents = $xmlContent.Manifest.SoftwareComponent | Where-Object { $_.ComponentType.value -eq "DRVR" }
    foreach ($component in $softwareComponents) {
        $models = $component.SupportedSystems.Brand.Model
        foreach ($item in $models) {
            if ($item.Display.'#cdata-section' -match $Model) {
                if ($WindowsRelease -le 11) {
                    $validOS = $component.SupportedOperatingSystems.OperatingSystem | Where-Object { $_.osArch -eq $WindowsArch }
                }
                elseif ($WindowsRelease -eq 2016) {
                    $validOS = $component.SupportedOperatingSystems.OperatingSystem | Where-Object {
                        ($_.osArch -eq $WindowsArch) -and ($_.osCode -match "W14")
                    }
                }
                elseif ($WindowsRelease -eq 2019) {
                    $validOS = $component.SupportedOperatingSystems.OperatingSystem | Where-Object {
                        ($_.osArch -eq $WindowsArch) -and ($_.osCode -match "W19")
                    }
                }
                elseif ($WindowsRelease -eq 2022) {
                    $validOS = $component.SupportedOperatingSystems.OperatingSystem | Where-Object {
                        ($_.osArch -eq $WindowsArch) -and ($_.osCode -match "W22")
                    }
                }
                elseif ($WindowsRelease -eq 2025) {
                    $validOS = $component.SupportedOperatingSystems.OperatingSystem | Where-Object {
                        ($_.osArch -eq $WindowsArch) -and ($_.osCode -match "W25")
                    }
                }
                else {
                    $validOS = $component.SupportedOperatingSystems.OperatingSystem | Where-Object {
                        ($_.osArch -eq $WindowsArch) -and ($_.osCode -match "W22")
                    }
                }
                if ($validOS) {
                    $driverPath   = $component.path
                    $downloadUrl  = $baseLocation + $driverPath
                    $driverFileName = [System.IO.Path]::GetFileName($driverPath)
                    $name         = $component.Name.Display.'#cdata-section'
                    $name         = $name -replace '[\\\/\:\*\?\"\<\>\| ]', '_'
                    $name         = $name -replace '[\,]', '-'
                    $category     = $component.Category.Display.'#cdata-section'
                    $category     = $category -replace '[\\\/\:\*\?\"\<\>\| ]', '_'
                    $version      = [version]$component.vendorVersion
                    $namePrefix   = ($name -split '-')[0]

                    if ($latestDrivers[$category]) {
                        if ($latestDrivers[$category][$namePrefix]) {
                            if ($latestDrivers[$category][$namePrefix].Version -lt $version) {
                                $latestDrivers[$category][$namePrefix] = [PSCustomObject]@{
                                    Name          = $name
                                    DownloadUrl   = $downloadUrl
                                    DriverFileName= $driverFileName
                                    Version       = $version
                                    Category      = $category
                                }
                            }
                        }
                        else {
                            $latestDrivers[$category][$namePrefix] = [PSCustomObject]@{
                                Name          = $name
                                DownloadUrl   = $downloadUrl
                                DriverFileName= $driverFileName
                                Version       = $version
                                Category      = $category
                            }
                        }
                    }
                    else {
                        $latestDrivers[$category] = @{}
                        $latestDrivers[$category][$namePrefix] = [PSCustomObject]@{
                            Name          = $name
                            DownloadUrl   = $downloadUrl
                            DriverFileName= $driverFileName
                            Version       = $version
                            Category      = $category
                        }
                    }
                }
            }
        }
    }

    foreach ($category in $latestDrivers.Keys) {
        foreach ($driver in $latestDrivers[$category].Values) {
            $downloadFolder = "$DriversFolder\$Model\$($driver.Category)"
            $driverFilePath = Join-Path -Path $downloadFolder -ChildPath $driver.DriverFileName
            
            if (Test-Path -Path $driverFilePath) {
                WriteLog "Driver already downloaded: $driverFilePath skipping"
                continue
            }

            if (-not (Test-Path -Path $downloadFolder)) {
                WriteLog "Creating download folder: $downloadFolder"
                New-Item -Path $downloadFolder -ItemType Directory -Force | Out-Null
            }

            WriteLog "Downloading driver: $($driver.DownloadUrl) to $driverFilePath"
            try {
                Start-BitsTransferWithRetry -Source $driver.DownloadUrl -Destination $driverFilePath
                WriteLog "Driver downloaded"
            }
            catch {
                WriteLog "Failed to download driver: $($driver.DownloadUrl) to $driverFilePath"
                continue
            }
            
            $extractFolder = $downloadFolder + "\" + $driver.DriverFileName.TrimEnd($driver.DriverFileName[-4..-1])
            $arguments     = "/s /drivers=`"$extractFolder`""
            WriteLog "Extracting driver: $driverFilePath with $arguments"
            try {
                # Example handling for certain categories:
                if ($driver.Category -eq "Chipset") {
                    $process = Invoke-Process -FilePath $driverFilePath -ArgumentList $arguments -Wait $false
                    Start-Sleep -Seconds 5
                    if ($process.HasExited -eq $false) {
                        WriteLog "Forcing chipset extraction process to exit."
                        Stop-Process -Id $process.Id -Force
                    }
                }
                else {
                    Invoke-Process -FilePath $driverFilePath -ArgumentList $arguments | Out-Null
                }

                # Check if the folder is empty; if so, try alternative extraction
                if (!(Get-ChildItem -Path $extractFolder -Recurse | Where-Object { -not $_.PSIsContainer })) {
                    WriteLog "Extraction with /drivers= failed. Retrying with /s /e= method"
                    Remove-Item -Path $extractFolder -Force -Recurse -ErrorAction SilentlyContinue
                    $arguments = "/s /e=`"$extractFolder`""
                    Invoke-Process -FilePath $driverFilePath -ArgumentList $arguments | Out-Null
                }
            }
            catch {
                WriteLog "Extraction with /drivers= switch failed. Retrying with /s /e=."
                $arguments = "/s /e=`"$extractFolder`""
                Invoke-Process -FilePath $driverFilePath -ArgumentList $arguments | Out-Null
            }

            WriteLog "Deleting driver file: $driverFilePath"
            Remove-Item -Path $driverFilePath -Force
        }
    }
}

##############################################################################
#  WRAPPER FUNCTION TO CALL DRIVER GETTERS
##############################################################################
function Get-Drivers {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Make,
        [Parameter(Mandatory = $true)]
        [string]$Model,
        [Parameter(Mandatory = $true)]
        [string]$WindowsArch,
        [Parameter(Mandatory = $true)]
        [int]$WindowsRelease,
        [Parameter(Mandatory = $false)]
        [string]$WindowsVersion,
        [Parameter(Mandatory = $false)]
        [bool]$InstallDrivers,
        [Parameter(Mandatory = $false)]
        [bool]$CopyDrivers
    )

    # Only proceed if we have Make, Model, and a reason to get drivers
    if (($Make -and $Model)) {   #-and ($InstallDrivers -or $CopyDrivers)) {
        try {
            if ($Make -eq 'HP') {
                Get-HPDrivers -Make $Make -Model $Model -WindowsArch $WindowsArch -WindowsRelease $WindowsRelease -WindowsVersion $WindowsVersion
            }
            if ($Make -eq 'Microsoft') {
                Get-MicrosoftDrivers -Make $Make -Model $Model -WindowsArch $WindowsArch -WindowsRelease $WindowsRelease
            }
            if ($Make -eq 'Lenovo') {
                Get-LenovoDrivers -Model $Model -WindowsArch $WindowsArch -WindowsRelease $WindowsRelease
            }
            if ($Make -eq 'Dell') {
                Get-DellDrivers -Model $Model -WindowsArch $WindowsArch -WindowsRelease $WindowsRelease
            }
        }
        catch {
            throw $_
        }
    }
    else {
        WriteLog "Skipping driver download: either Make/Model missing or neither InstallDrivers/CopyDrivers is true."
    }
}
write-host "hers is the $ModelList "
#$ModelList ='V:\FFUDevelopment\DrivDownloads\ModelList.csv'

##############################################################################
#  MAIN SCRIPT LOGIC
##############################################################################
if ($ModelList) {
    if (Test-Path $ModelList) {
        $csvData = Import-Csv -Path $ModelList
        writeLog "CSV File found"
        foreach ($row in $csvData) {
            $currentMake  = $row.Make
            $currentModel = $row.Model

            # Decide how these booleans are set or read them from CSV
            $installDrivers = $true  
            $copyDrivers    = $true  

            Get-Drivers -Make $currentMake `
                        -Model $currentModel `
                        -WindowsArch $WindowsArch `
                        -WindowsRelease $WindowsRelease `
                        -WindowsVersion $WindowsVersion
            
                       
                    
        }
        # Uncomment if you want to stop the script after CSV processing:
        # exit
    WriteLog "Finished Parsing CSV File"
    }
    else {
        Write-Host "CSV not found at $ModelList"
        # exit or handle error
    }
}
else {
    # Example usage if ModelList is not provided
    Write-Host "Processing a single Make/Model"

    # Sample or default values:
    #$make = "Lenovo"
    #$model = "T14 Gen 5"
    #$copydrivers = $true
    Write-Host "Make: $Make"
    Write-Host "Model: $Model"

    $installDrivers = $true
    if (($make -and $model) -and ($installDrivers -or $copydrivers)) {
        try {
            if ($Make -eq 'HP'){
                Get-HPDrivers -Make $Make -Model $Model -WindowsArch $WindowsArch -WindowsRelease $WindowsRelease -WindowsVersion $WindowsVersion
            }
            if ($make -eq 'Microsoft'){
                Get-MicrosoftDrivers -Make $Make -Model $Model -WindowsArch $WindowsArch -WindowsRelease $WindowsRelease
            }
            if ($make -eq 'Lenovo'){
                Get-LenovoDrivers -Model $Model -WindowsArch $WindowsArch -WindowsRelease $WindowsRelease
            }
            if ($make -eq 'Dell'){
                Get-DellDrivers -Model $Model -WindowsArch $WindowsArch -WindowsRelease $WindowsRelease
            }
        }
        catch {
            throw $_
        }
    }
    else {
        WriteLog "Skipping driver download because neither InstallDrivers nor CopyDrivers is set to true, or Make/Model missing."
    }
}
WriteLog "All Driver Downloads Completed"
Write-Host "Driver Downloads Complete"
