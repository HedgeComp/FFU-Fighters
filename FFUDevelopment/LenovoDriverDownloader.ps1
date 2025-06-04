$WindowsRelease = "11"
$DriversFolder = "c:\FFUBOOT\drivers"
$windowsArch ="x64"
$Model = "T14 Gen 5"
$ModelName ="P16s Gen 3"


function Invoke-Process {
    [CmdletBinding(SupportsShouldProcess)]
    param
    (
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

function Test-Url {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Url
    )
    try {
        # Create a web request and check the response
        $request = [System.Net.WebRequest]::Create($Url)
        $request.Method = 'HEAD'
        $response = $request.GetResponse()
        return $true
    }
    catch {
        return $false
    }
}



# Function to download a file using BITS with retry and error handling
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
            Write-Host "Attempt $attempt of $Retries failed to download $Source. Retrying..."
            Start-Sleep -Seconds 5
        }
    }
    Write-Host "Failed to download $Source after $Retries attempts."
    return $false
}






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

    function Get-LenovoPSREF {
        param (
            [string]$ModelName
        )

        $url = "https://psref.lenovo.com/api/search/DefinitionFilterAndSearch/Suggest?kw=$ModelName"
        Write-Host "Querying Lenovo PSREF API for model: $ModelName"
        $OriginalVerbosePreference = $VerbosePreference
        $VerbosePreference = 'SilentlyContinue'
        $response = Invoke-WebRequest -Uri $url -UseBasicParsing -Headers $Headers -UserAgent $UserAgent
        $VerbosePreference = $OriginalVerbosePreference
        Write-Host "Complete"

        $jsonResponse = $response.Content | ConvertFrom-Json

        $products = @()
        foreach ($item in $jsonResponse.data) {
            $productName = $item.ProductName
            $machineTypes = $item.MachineType -split " / "

            foreach ($machineType in $machineTypes) {
                if ($machineType -eq $ModelName) {
                    Write-Host "Model name entered is a matching machine type"
                    $products = @()
                    $products += [pscustomobject]@{
                        ProductName = $productName
                        MachineType = $machineType
                    }
                    Write-Host "Product Name: $productName Machine Type: $machineType"
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
    
    # Parse the Lenovo PSREF page for the model
    $machineTypes = Get-LenovoPSREF -ModelName $Model
    if ($machineTypes.ProductName.Count -eq 0) {
        Write-Host "No machine types found for model: $Model"
        Write-Host "Enter a valid model or machine type in the -model parameter"
        exit
    } elseif ($machineTypes.ProductName.Count -eq 1) {
        $machineType = $machineTypes[0].MachineType
        $model = $machineTypes[0].ProductName
    } else {
        if ($VerbosePreference -ne 'Continue'){
            Write-Output "Multiple machine types found for model: $Model"
        }
        Write-Host "Multiple machine types found for model: $Model"
        for ($i = 0; $i -lt $machineTypes.ProductName.Count; $i++) {
            if ($VerbosePreference -ne 'Continue'){
                Write-Output "$($i + 1). $($machineTypes[$i].ProductName) ($($machineTypes[$i].MachineType))"
            }
            Write-Host "$($i + 1). $($machineTypes[$i].ProductName) ($($machineTypes[$i].MachineType))"
        }
        $selection = Read-Host "Enter the number of the model you want to select"
        $machineType = $machineTypes[$selection - 1].MachineType
        Write-Host "Selected machine type: $machineType"
        $model = $machineTypes[$selection - 1].ProductName
        Write-Host "Selected model: $model"
    }
    

    # Construct the catalog URL based on Windows release and machine type
    $ModelRelease = $machineType + "_Win" + $WindowsRelease
    $CatalogUrl = "https://download.lenovo.com/catalog/$ModelRelease.xml"
    Write-Host "Lenovo Driver catalog URL: $CatalogUrl"

    if (-not (Test-Url -Url $catalogUrl)) {
        Write-Error "Lenovo Driver catalog URL is not accessible: $catalogUrl"
        Write-Host "Lenovo Driver catalog URL is not accessible: $catalogUrl"
        exit
    }

    # Create the folder structure for the Lenovo drivers
    $driversFolder = "$DriversFolder\$model ($machineType)"
    Write-Host "Selected model: $model"
    if (-not (Test-Path -Path $DriversFolder)) {
        Write-Host "Creating Drivers folder: $DriversFolder"
        New-Item -Path $DriversFolder -ItemType Directory -Force | Out-Null
        Write-Host "Drivers folder created"
    }

    # Download and parse the Lenovo catalog XML
    $LenovoCatalogXML = "$DriversFolder\$ModelRelease.xml"
    Write-Host "Downloading $catalogUrl to $LenovoCatalogXML"
    Start-BitsTransferWithRetry -Source $catalogUrl -Destination $LenovoCatalogXML
    Write-Host "Download Complete"
    $xmlContent = [xml](Get-Content -Path $LenovoCatalogXML)

    Write-Host "Parsing Lenovo catalog XML"
    # Process each package in the catalog
    foreach ($package in $xmlContent.packages.package) {
        $packageUrl = $package.location
        $category = $package.category

        #If category starts with BIOS, skip the package
        if ($category -like 'BIOS*') {
            continue
        }

        #If category name is 'Motherboard Devices Backplanes core chipset onboard video PCIe switches', truncate to 'Motherboard Devices' to shorten path
        if ($category -eq 'Motherboard Devices Backplanes core chipset onboard video PCIe switches') {
            $category = 'Motherboard Devices'
        }

        $packageName = [System.IO.Path]::GetFileName($packageUrl)
        #Remove the filename from the $packageURL
        $baseURL = $packageUrl -replace $packageName, "" 

        # Download the package XML
        $packageXMLPath = "$DriversFolder\$packageName"
        Write-Host "Downloading $category package XML $packageUrl to $packageXMLPath"
        If ((Start-BitsTransferWithRetry -Source $packageUrl -Destination $packageXMLPath) -eq $false) {
            Write-Output "Failed to download $category package XML: $packageXMLPath"
            Write-Host "Failed to download $category package XML: $packageXMLPath"
            continue
        }

        # Load the package XML content
        $packageXmlContent = [xml](Get-Content -Path $packageXMLPath)
        $packageType = $packageXmlContent.Package.PackageType.type
        $packageTitle = $packageXmlContent.Package.title.InnerText

        # Fix the name for drivers that contain illegal characters for folder name purposes
        $packageTitle = $packageTitle -replace '[\\\/\:\*\?\"\<\>\|]', '_'

        # If ' - ' is in the package title, truncate the title to the first part of the string.
        $packageTitle = $packageTitle -replace ' - .*', ''

        #Check if packagetype = 2. If packagetype is not 2, skip the package. $packageType is a System.Xml.XmlElement.
        #This filters out Firmware, BIOS, and other non-INF drivers
        if ($packageType -ne 2) {
            Remove-Item -Path $packageXMLPath -Force
            continue
        }

        # Extract the driver file name and the extract command
        $driverFileName = $packageXmlContent.Package.Files.Installer.File.Name
        $extractCommand = $packageXmlContent.Package.ExtractCommand

        #if extract command is empty/missing, skip the package
        if (!($extractCommand)) {
            Remove-Item -Path $packageXMLPath -Force
            continue
        }

        # Create the download URL and folder structure
        $driverUrl = $baseUrl + $driverFileName
        $downloadFolder = "$DriversFolder\$Model\$Category\$packageTitle"
        $driverFilePath = Join-Path -Path $downloadFolder -ChildPath $driverFileName

        # Check if file has already been downloaded
        if (Test-Path -Path $driverFilePath) {
            Write-Output "Driver already downloaded: $driverFilePath skipping"
            Write-Host "Driver already downloaded: $driverFilePath skipping"
            continue
        }

        if (-not (Test-Path -Path $downloadFolder)) {
            Write-Host "Creating download folder: $downloadFolder"
            New-Item -Path $downloadFolder -ItemType Directory -Force | Out-Null
            Write-Host "Download folder created"
        }

        # Download the driver with retry
        Write-Host "Downloading driver: $driverUrl to $driverFilePath"
        Start-BitsTransferWithRetry -Source $driverUrl -Destination $driverFilePath
        Write-Host "Driver downloaded"

        # Make folder for extraction
        $extractFolder = $downloadFolder + "\" + $driverFileName.TrimEnd($driverFileName[-4..-1])
        Write-Host "Creating extract folder: $extractFolder"
        New-Item -Path $extractFolder -ItemType Directory -Force | Out-Null
        Write-Host "Extract folder created"

        # Modify the extract command
        $modifiedExtractCommand = $extractCommand -replace '%PACKAGEPATH%', "`"$extractFolder`""

        # Extract the driver
        # Start-Process -FilePath $driverFilePath -ArgumentList $modifiedExtractCommand -Wait -NoNewWindow
        Write-Host "Extracting driver: $driverFilePath to $extractFolder"
        Invoke-Process -FilePath $driverFilePath -ArgumentList $modifiedExtractCommand | Out-Null
        Write-Host "Driver extracted"

        # Delete the .exe driver file after extraction
        Write-Host "Deleting driver installation file: $driverFilePath"
        Remove-Item -Path $driverFilePath -Force
        Write-Host "Driver installation file deleted: $driverFilePath"

        # Delete the package XML file after extraction
        Write-Host "Deleting package XML file: $packageXMLPath"
        Remove-Item -Path $packageXMLPath -Force
        Write-Host "Package XML file deleted"
    }

    #Delete the catalog XML file after processing
    Write-Host "Deleting catalog XML file: $LenovoCatalogXML"
    Remove-Item -Path $LenovoCatalogXML -Force
    Write-Host "Catalog XML file deleted"
}

Get-LenovoDrivers $Model $windowsArch $WindowsRelease
