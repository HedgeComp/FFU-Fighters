function Get-PCInfo {
    [CmdletBinding()]
    param()

    Write-Host "--- Retrieving Computer Manufacturer, Model, and Processor ---" -ForegroundColor Cyan

    # Attempt to retrieve Win32_ComputerSystem
    try {
        $computerSystemCIM = Get-CimInstance -ClassName Win32_ComputerSystemProduct -ErrorAction Stop
       
    } catch {
        Write-Host "Failed to retrieve Win32_ComputerSystem" -ForegroundColor Red
        $computerSystemCIM = $null
    }

    # Attempt to retrieve Win32_Processor
    try {
        $processorCIM = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop
        }
  catch {
        Write-Host "Failed to retrieve Win32_Processor" -ForegroundColor Red
        $processorCIM = $null
    }

    # Attempt to retrieve Memory
    try {
        $physicalMemory = Get-CimInstance -ClassName Win32_PhysicalMemory -ErrorAction Stop
        $totalMemoryGB = ($physicalMemory.Capacity | Measure-Object -Sum).Sum / 1GB
        } catch {
        Write-Host "Failed to retrieve Win32_PhysicalMemory" -ForegroundColor Red
        $totalMemoryGB = 0
    }

    # If the objects are null, output 'Undetermined'
    $name         = if ($computerSystemCIM) { $computerSystemCIM.Name    } else { "Undetermined" }
    $manufacturer = if ($computerSystemCIM) { $computerSystemCIM.Vendor  } else { "Undetermined" }
    $model        = if ($computerSystemCIM) { $computerSystemCIM.Version } else { "Undetermined" }
    $processor    = if ($processorCIM)      { $processorCIM.Name        } else { "Undetermined" }

    cls
    Write-Host "-------- DEVICE INFORMATION --------" -ForegroundColor White -BackgroundColor DarkGray

    Write-Host " Make:" -BackgroundColor DarkGray -ForegroundColor White -NoNewLine
    Write-Host "  $manufacturer " -ForegroundColor White -BackgroundColor Blue

       
   
    # If Vendor is not Lenovo use $name is the Vendors Model
    if ($manufacturer -ne 'Lenovo') {
        # If Version is blank, show 'Name:' line with $model, 'Model:' line with $name
        Write-Host " Model:" -BackgroundColor darkGray -ForegroundColor White -NoNewLine
        Write-Host " $name " -ForegroundColor White -BackgroundColor Blue
    } else {
        # Lenovo Devices Use Machine Type for Name and Version for Model
        Write-Host " Model:" -BackgroundColor darkGray -ForegroundColor White -NoNewLine
        Write-Host " $model " -ForegroundColor White -BackgroundColor Blue

        Write-Host " Machine Type:" -BackgroundColor darkGray -ForegroundColor White -NoNewLine
        Write-Host " $name " -ForegroundColor White -BackgroundColor Blue
    }

    Write-Host " Processor:" -BackgroundColor DarkGray -ForegroundColor White -NoNewLine
    Write-Host " $processor " -ForegroundColor White -BackgroundColor Blue

    Write-Host " Memory:" -BackgroundColor DarkGray -ForegroundColor White -NoNewLine
    Write-Host " $totalMemoryGB GB " -ForegroundColor White -BackgroundColor blue
}



get-pcinfo
