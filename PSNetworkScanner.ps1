Add-Type -AssemblyName PresentationFramework

# ---------------- LOAD OUI DATABASE ----------------
$VendorDB = @{}
$ouiPath = "$PSScriptRoot\oui.txt"

if (Test-Path $ouiPath) {
    Write-Host "Loading OUI database..."

    Get-Content $ouiPath | ForEach-Object {
        $line = $_.Trim()

        if ($line -match '^([0-9A-Fa-f]{6})\s+\(base 16\)\s+(.+)$') {
            $raw = $matches[1].ToUpper()
            $prefix = ($raw -replace '(.{2})(.{2})(.{2})','$1:$2:$3')
            $VendorDB[$prefix] = $matches[2].Trim()
        }
    }

    Write-Host "Loaded $($VendorDB.Count) vendors"
}

# fallback
$VendorDB["F4:5C:89"]="Apple"
$VendorDB["00:15:5D"]="Microsoft (Hyper-V)"
$VendorDB["00:50:56"]="VMware"

$VMWarePrefixes = "00:05:69","00:0C:29","00:50:56"
$HyperVPrefixes = "00:15:5D"
$PhoneVendors = "Apple","Samsung","Huawei","Xiaomi"
$CommonPorts = 21,22,80,443,445,3389

# ---------------- UI ----------------
[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="IP Scanner PRO" Height="650" Width="1150"
        Background="#1e1e1e" Foreground="White">

<Grid Margin="10">
<Grid.RowDefinitions>
<RowDefinition Height="Auto"/>
<RowDefinition Height="Auto"/>
<RowDefinition/>
</Grid.RowDefinitions>

<StackPanel Orientation="Horizontal">
<TextBox Name="StartIPBox" Width="140" Margin="5"/>
<TextBox Name="EndIPBox" Width="140" Margin="5"/>
<Button Name="AutoButton" Content="Auto" Width="80" Margin="5"/>
<Button Name="ScanButton" Content="Scan" Width="100" Margin="5"/>
<Button Name="ExportButton" Content="Export CSV" Width="120" Margin="5"/>
<CheckBox Name="FilterUpOnly" Content="Only Up" Foreground="White" Margin="10"/>
</StackPanel>

<ProgressBar Name="ProgressBar" Grid.Row="1" Height="20"/>

<DataGrid Name="ResultsGrid" Grid.Row="2" AutoGenerateColumns="False"
          Background="#2d2d30"
          Foreground="White"
          RowBackground="#2d2d30"
          AlternatingRowBackground="#252526"
          GridLinesVisibility="None"
          BorderThickness="0">

<DataGrid.Resources>
<SolidColorBrush x:Key="{x:Static SystemColors.HighlightBrushKey}" Color="#007acc"/>
<SolidColorBrush x:Key="{x:Static SystemColors.HighlightTextBrushKey}" Color="White"/>
</DataGrid.Resources>

<DataGrid.ColumnHeaderStyle>
<Style TargetType="DataGridColumnHeader">
<Setter Property="Background" Value="#3c3c3c"/>
<Setter Property="Foreground" Value="White"/>
<Setter Property="FontWeight" Value="Bold"/>
</Style>
</DataGrid.ColumnHeaderStyle>

<DataGrid.CellStyle>
<Style TargetType="DataGridCell">
<Setter Property="Foreground" Value="White"/>
<Setter Property="Background" Value="Transparent"/>
</Style>
</DataGrid.CellStyle>

<DataGrid.RowStyle>
<Style TargetType="DataGridRow">
<Setter Property="Foreground" Value="White"/>

<Style.Triggers>
<DataTrigger Binding="{Binding Status}" Value="Up">
<Setter Property="Foreground" Value="#4CAF50"/>
</DataTrigger>
<DataTrigger Binding="{Binding Status}" Value="Down">
<Setter Property="Foreground" Value="#F44336"/>
</DataTrigger>
</Style.Triggers>

</Style>
</DataGrid.RowStyle>

<DataGrid.Columns>
<DataGridTextColumn Header="" Binding="{Binding Icon}"/>
<DataGridTextColumn Header="IP" Binding="{Binding IP}"/>
<DataGridTextColumn Header="Host" Binding="{Binding Host}"/>
<DataGridTextColumn Header="MAC" Binding="{Binding MAC}"/>
<DataGridTextColumn Header="Vendor" Binding="{Binding Vendor}"/>
<DataGridTextColumn Header="Ports" Binding="{Binding Ports}"/>
<DataGridTextColumn Header="Type" Binding="{Binding Type}"/>
<DataGridTextColumn Header="Status" Binding="{Binding Status}"/>
</DataGrid.Columns>

</DataGrid>
</Grid>
</Window>
"@

# ✅ SAFE LOAD (NO MORE SILENT FAIL)
try {
    $reader = New-Object System.Xml.XmlNodeReader $xaml
    $window = [Windows.Markup.XamlReader]::Load($reader)
}
catch {
    Write-Host "XAML failed to load:" -ForegroundColor Red
    Write-Host $_
    return
}

# Controls
$StartIPBox = $window.FindName("StartIPBox")
$EndIPBox   = $window.FindName("EndIPBox")
$ScanButton = $window.FindName("ScanButton")
$AutoButton = $window.FindName("AutoButton")
$ExportButton = $window.FindName("ExportButton")
$FilterUpOnly = $window.FindName("FilterUpOnly")
$ResultsGrid = $window.FindName("ResultsGrid")
$ProgressBar = $window.FindName("ProgressBar")

$script:AllResults = @()

# ---------------- RANGE ----------------
function Get-Range($start,$end){

    function IP2Int($ip){
        $p = $ip -split "\."
        ([int]$p[0] -shl 24) -bor ([int]$p[1] -shl 16) -bor ([int]$p[2] -shl 8) -bor ([int]$p[3])
    }

    function Int2IP($i){
        "{0}.{1}.{2}.{3}" -f (($i -shr 24)-band255),(($i -shr 16)-band255),(($i -shr 8)-band255),($i-band255)
    }

    $s = IP2Int $start
    $e = IP2Int $end

    for($x=$s;$x -le $e;$x++){ Int2IP $x }
}

# ---------------- FILTER ----------------
function Apply-Filter{
    if($FilterUpOnly.IsChecked){
        $ResultsGrid.ItemsSource = $script:AllResults | Where-Object Status -eq "Up"
    } else {
        $ResultsGrid.ItemsSource = $script:AllResults
    }
}

# ---------------- SCAN ----------------
function Start-Scan($ips){

    $script:AllResults=@()

    $scanScript = {
        param($scanIPs,$vendors,$portsList,$vmw,$hyp)

        foreach($ip in $scanIPs){

            $alive = Test-Connection -Quiet -Count 1 $ip -ErrorAction SilentlyContinue

            $mac="";$vendor="";$hostname="";$ports="";$icon="[?]";$type="Unknown";$prefix=""

            if($alive){

                try{$hostname=[System.Net.Dns]::GetHostEntry($ip).HostName}catch{}

                Test-Connection $ip | Out-Null
                $n=Get-NetNeighbor -IPAddress $ip -ErrorAction SilentlyContinue
                if($n){$mac=$n.LinkLayerAddress}

                if($mac){
                    $normalized = ($mac -replace "-",":").ToUpper()
                    $prefix = ($normalized -split ":")[0..2] -join ":"

                    if($vendors.ContainsKey($prefix)){
                        $vendor = $vendors[$prefix]
                    }
                }

                foreach($p in $portsList){
                    try{
                        $tcp=New-Object Net.Sockets.TcpClient
                        if($tcp.ConnectAsync($ip,$p).Wait(80)){
                            if($tcp.Connected){$ports+="$p,"}
                        }
                        $tcp.Close()
                    }catch{}
                }

                if($ports){$ports=$ports.TrimEnd(",")}

                if($vmw -contains $prefix){$type="VM";$icon="[VM]"}
                elseif($hyp -contains $prefix){$type="VM";$icon="[VM]"}
                elseif($vendor -match "Apple|Samsung"){$type="Phone";$icon="[PH]"}
                elseif($ports -match "3389"){$type="Windows";$icon="[PC]"}
                elseif($ports -match "22"){$type="Linux";$icon="[LX]"}
            }

            [pscustomobject]@{
                Icon=$icon;IP=$ip;Host=$hostname;MAC=$mac
                Vendor=$vendor;Ports=$ports;Type=$type
                Status=if($alive){"Up"}else{"Down"}
            }
        }
    }

    $script:ScanPool = [RunspaceFactory]::CreateRunspacePool(1,50)
    $script:ScanPool.Open()
    $script:ScanWorkItems = New-Object System.Collections.Generic.List[object]
    $script:ScanErrors = New-Object System.Collections.Generic.List[string]
    $script:ScanCompleted = 0
    $script:ScanTotal = @($ips).Count

    foreach($ip in $ips){
        $worker = [PowerShell]::Create()
        $worker.RunspacePool = $script:ScanPool
        [void]$worker.AddScript($scanScript)
        [void]$worker.AddArgument(@($ip))
        [void]$worker.AddArgument($VendorDB)
        [void]$worker.AddArgument($CommonPorts)
        [void]$worker.AddArgument($VMWarePrefixes)
        [void]$worker.AddArgument($HyperVPrefixes)

        $workItem = [pscustomobject]@{
            PowerShell = $worker
            AsyncResult = $worker.BeginInvoke()
        }
        [void]$script:ScanWorkItems.Add($workItem)
    }

    $ScanButton.IsEnabled = $false
    $ProgressBar.IsIndeterminate = $false
    $ProgressBar.Minimum = 0
    $ProgressBar.Maximum = $script:ScanTotal
    $ProgressBar.Value = 0
    $script:ScanTimer.Start()
}

$script:ScanTimer = New-Object System.Windows.Threading.DispatcherTimer
$script:ScanTimer.Interval = [TimeSpan]::FromMilliseconds(100)
$script:ScanTimer.Add_Tick({
    if(-not $script:ScanWorkItems){
        return
    }

    $completedItems = @($script:ScanWorkItems | Where-Object { $_.AsyncResult.IsCompleted })
    foreach($item in $completedItems){
        try{
            $scanOutput = $item.PowerShell.EndInvoke($item.AsyncResult)
            foreach($result in $scanOutput){
                $script:AllResults += $result
            }

            if($item.PowerShell.Streams.Error.Count -gt 0){
                foreach($errorRecord in $item.PowerShell.Streams.Error){
                    [void]$script:ScanErrors.Add($errorRecord.ToString())
                }
            }
        }catch{
            [void]$script:ScanErrors.Add($_.Exception.Message)
        }finally{
            $item.PowerShell.Dispose()
            [void]$script:ScanWorkItems.Remove($item)
            $script:ScanCompleted++
            $ProgressBar.Value = $script:ScanCompleted
            Apply-Filter
        }
    }

    if($script:ScanWorkItems.Count -eq 0){
        $script:ScanTimer.Stop()
        $script:ScanPool.Close()
        $script:ScanPool.Dispose()
        $script:ScanPool = $null
        if($script:ScanErrors.Count -gt 0){
            $message = ($script:ScanErrors | Select-Object -First 3) -join "`n"
            [System.Windows.MessageBox]::Show("Some scan tasks reported errors:`n$message","Scan Warning")
        }
        $ScanButton.IsEnabled = $true
    }
})

# ---------------- EVENTS ----------------
function Set-AutoRange{
    $base = (Get-NetIPAddress -AddressFamily IPv4 | Where {$_.IPAddress -notlike "169.*"} | Select -First 1).IPAddress -split '\.'
    if($base.Count -ne 4){
        throw "No usable IPv4 address was found."
    }

    $StartIPBox.Text="$($base[0]).$($base[1]).$($base[2]).1"
    $EndIPBox.Text="$($base[0]).$($base[1]).$($base[2]).254"
}

$AutoButton.Add_Click({
    try{ Set-AutoRange }
    catch{ [System.Windows.MessageBox]::Show($_.Exception.Message,"Network Error") }
})

$ScanButton.Add_Click({
    try{
        if([string]::IsNullOrWhiteSpace($StartIPBox.Text) -or [string]::IsNullOrWhiteSpace($EndIPBox.Text)){
            Set-AutoRange
        }

        $startAddress = $null
        $endAddress = $null
        if(-not [System.Net.IPAddress]::TryParse($StartIPBox.Text,[ref]$startAddress) -or
           -not [System.Net.IPAddress]::TryParse($EndIPBox.Text,[ref]$endAddress)){
            throw "Enter valid start and end IPv4 addresses."
        }

        $scanIPs = @(Get-Range $StartIPBox.Text $EndIPBox.Text)
        if($scanIPs.Count -eq 0){
            throw "The scan range is empty or the end address precedes the start address."
        }

        Start-Scan $scanIPs
    }catch{
        [System.Windows.MessageBox]::Show($_.Exception.Message,"Scan Error")
    }
})

$FilterUpOnly.Add_Click({Apply-Filter})

$ExportButton.Add_Click({
    $file="$env:USERPROFILE\Desktop\scan.csv"
    $script:AllResults | Export-Csv -NoTypeInformation $file
    Invoke-Item $file
})

$window.ShowDialog()
5.5.2 

