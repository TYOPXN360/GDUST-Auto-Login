# 校园网 curl 认证脚本
param(
    [string]$NetAdapterName = "WLAN",  # 默认网卡名称，可自定义
    [switch]$y,  # 自动保持不断线
    [switch]$n   # 不启用自动保持（与 -y 冲突）
)

# 脚本内部存储的账号密码（首次为空，用户输入后会写入）
$savedUsername = ""
$savedPassword = ""

function WaitForKeyAndExit {
    param([int]$ExitCode = 0)
    Write-Host "`n按任意键退出..." -ForegroundColor Cyan
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    Exit $ExitCode
}

function Check-ParamConflict {
    if ($y -and $n) {
        Write-Host "参数 -y 与 -n 不能同时使用" -ForegroundColor Red
        WaitForKeyAndExit -ExitCode 1
    }
}

function Get-AccountInfo {
    # 如果脚本内部已有账号密码，直接使用
    if (-not [string]::IsNullOrWhiteSpace($savedUsername) -and -not [string]::IsNullOrWhiteSpace($savedPassword)) {
        Write-Host "检测到已保存的账号密码，直接使用" -ForegroundColor Green
        return $savedUsername, $savedPassword
    }

    # 否则询问用户输入
    $username = Read-Host "请输入账号（通常为学号/手机号）"
    while ([string]::IsNullOrWhiteSpace($username)) {
        Write-Host "账号不能为空" -ForegroundColor Red
        $username = Read-Host "请输入账号"
    }

    $password = Read-Host "请输入密码"
    while ([string]::IsNullOrWhiteSpace($password)) {
        Write-Host "密码不能为空" -ForegroundColor Red
        $password = Read-Host "请输入密码"
    }

    # 写入脚本内部
    try {
        $scriptPath = if (-not [string]::IsNullOrWhiteSpace($PSCommandPath)) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
        if (-not (Test-Path -Path $scriptPath -PathType Leaf)) {
            throw "脚本路径无效，无法写入账号密码"
        }

        $scriptContent = (Get-Content -Path $scriptPath) -join "`n"
        $updatedContent = $scriptContent -replace '(?m)^\s*\$savedUsername\s*=.*', "`$savedUsername = `"$username`"" `
                                            -replace '(?m)^\s*\$savedPassword\s*=.*', "`$savedPassword = `"$password`""
        Set-Content -Path $scriptPath -Value $updatedContent -Force
        Write-Host "账号密码已写入脚本，下次运行无需再次输入" -ForegroundColor Green
    } catch {
        Write-Host "写入失败，请手动修改脚本中的 `$savedUsername 和 `$savedPassword" -ForegroundColor Yellow
    }

    return $username, $password
}

function Start-AuthFlow {
    param(
        [string]$Username,
        [string]$Password,
        [string]$Basip = "172.18.100.100",
        [bool]$IsReconnect = $false,
        [string]$AdapterName = $NetAdapterName
    )

    try {
        # 只匹配指定网卡名称
        $adapter = Get-NetAdapter | Where-Object {
            $_.Name -eq $AdapterName -and $_.Status -eq "Up"
        } | ForEach-Object {
            $ipv4Addr = $_ | Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue
            if ($ipv4Addr) {
                $_ | Add-Member -NotePropertyName "IPv4Address" -NotePropertyValue $ipv4Addr.IPAddress -PassThru
            }
        } | Select-Object -First 1

        if (-not $adapter) {
            Write-Host "[错误] 未找到名称为 $AdapterName 的网卡或未启用" -ForegroundColor Red
            return $false, $null, $null
        }

        $wlanUserIp = $adapter.IPv4Address
        $clientMac = $adapter.MacAddress
        Write-Host "[认证信息] 网卡=$($adapter.Name) | IP=$wlanUserIp | MAC=$clientMac" -ForegroundColor Cyan
    } catch {
        Write-Host "[错误] 获取网卡信息失败 $_" -ForegroundColor Red
        return $false, $null, $null
    }

    # 第一次认证请求
    $postParams = "usrname=$Username&passwd=$Password&treaty=on&nasid=1&usrmac=$clientMac&usrip=$wlanUserIp&basip=$Basip&success=http://8.135.34.165/.../success&fail=http://8.135.34.165/.../fail"
    $url1 = "http://8.135.34.165/lfradius/libs/portal/unify/portal.php/login/Panabit_login"

    $response1 = & curl.exe -s -X POST $url1 -H "Content-Type: application/x-www-form-urlencoded" -d $postParams

    if ($response1 -match "fail" -or $response1 -match "密码错误") {
        Write-Host "[提示] 认证失败：$response1" -ForegroundColor Red
        return $false, $null, $null
    }

    # 第二次 AJAX 登录请求
    $ajaxParams = "action=login&user=$Username&pwd=$Password&usrmac=$clientMac&ip=$wlanUserIp&success=http://8.135.34.165/.../success&fail=http://8.135.34.165/.../fail"
    $url2 = "http://172.18.100.100:8010/cgi-bin/webauth/ajax_webauth"

    $response2 = & curl.exe -s -X POST $url2 -H "Content-Type: application/x-www-form-urlencoded" -d $ajaxParams

    if ($response2 -match "success" -or $response2 -match "SUCCESS") {
        Write-Host "[结果] 认证成功" -ForegroundColor Green
        return $true, $wlanUserIp, $clientMac
    } elseif ($response2 -match "fail" -or $response2 -match "FAIL" -or $response2 -match "密码错误") {
        Write-Host "[结果] 认证失败：$response2" -ForegroundColor Red
        return $false, $null, $null
    } else {
        Write-Host "[结果] 未能识别返回内容，原始响应：$response2" -ForegroundColor Yellow
        return $false, $null, $null
    }
}

# 主流程
Check-ParamConflict
$usrname, $passwordPlain = Get-AccountInfo

$firstAuthSuccess, $userIp, $userMac = Start-AuthFlow -Username $usrname -Password $passwordPlain -IsReconnect $false
if (-not $firstAuthSuccess) {
    Write-Host "[最终结果] 首次认证失败" -ForegroundColor Red
    WaitForKeyAndExit -ExitCode 1
}

# 测试外网连通性
$curlOutput = & curl.exe -s -o NUL -w "%{http_code}" https://bing.com
if ($curlOutput -match '^(200|3\d{2})$') {
    Write-Host "网络已通，HTTP状态码=$curlOutput" -ForegroundColor Green
} else {
    Write-Host "网络未通，状态码=$curlOutput" -ForegroundColor Red
    WaitForKeyAndExit -ExitCode 1
}

# 防断联逻辑参数处理
if ($y) {
    $startAntiDisconnect = $true
} elseif ($n) {
    $startAntiDisconnect = $false
} else {
    $userInput = Read-Host "是否开启防断联进程？输入 Y 开启 / N 不开启"
    $userInput = $userInput.Trim().ToUpper()
    $startAntiDisconnect = ($userInput -eq "Y")
}

# 防断联主循环
if ($startAntiDisconnect) {
    Write-Host "已开启防断联进程，每 5 秒检测一次网络" -ForegroundColor Green
    while ($true) {
        Start-Sleep -Seconds 5
        $curlOutputLoop = & curl.exe -s -o NUL -w "%{http_code}" https://bing.com
        if ($curlOutputLoop -notmatch '^(200|3\d{2})$') {
            Write-Host "网络异常，尝试重新认证..." -ForegroundColor Yellow
            $reconnectSuccess, $reconnectIp, $reconnectMac = Start-AuthFlow -Username $usrname -Password $passwordPlain -IsReconnect $true
            if ($reconnectSuccess) {
                Write-Host "已重新认证成功" -ForegroundColor Green
            }
        }
    }
} else {
    Write-Host "脚本结束" -ForegroundColor Cyan
    WaitForKeyAndExit -ExitCode 0
}
