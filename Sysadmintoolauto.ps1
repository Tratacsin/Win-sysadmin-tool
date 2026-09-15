<#
.SYNOPSIS
    Windows Automation & Maintenance Suite
.DESCRIPTION
    Скрипт для автоматизации администрирования Windows (управление пользователями,очистка диска,анализ логов)
.AUTHOR
    Your Name
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)][switch]$CreateUser,
    [Parameter(Mandatory=$false)][string]$Username,
    [Parameter(Mandatory=$false)][string]$Group = "Users",
    [Parameter(Mandatory=$false)][switch]$CleanDisk,
    [Parameter(Mandatory=$false)][switch]$ParseLogs,
    [Parameter(Mandatory=$false)][switch]$All
)

#Проверка прав Администратора
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[!] Ошибка: Для выполнения скрипта требуются права Администратора!" -ForegroundColor Red
    exit
}

$LogFile = "C:\ProgramData\WinAdminTool.log"

function Write-Log {
    param ([string]$Message, [string]$Level = "INFO")
    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $FormattedMessage = "[$TimeStamp] [$Level] $Message"
    Add-Content -Path $LogFile -Value $FormattedMessage
    
    switch ($Level) {
        "INFO"    { Write-Host $FormattedMessage -ForegroundColor Green }
        "WARNING" { Write-Host $FormattedMessage -ForegroundColor Yellow }
        "ERROR"   { Write-Host $FormattedMessage -ForegroundColor Red }
    }
}

# 1. СОЗДАНИЕ ПОЛЬЗОВАТЕЛЯ
function New-CustomUser {
    param ([string]$AccountName, [string]$GroupName)

    if (-not $AccountName) {
        $AccountName = Read-Host "Введите имя нового пользователя"
    }

    $existingUser = Get-LocalUser -Name $AccountName -ErrorAction SilentlyContinue
    if ($existingUser) {
        Write-Log "Пользователь $AccountName уже существует." "WARNING"
        return
    }

    #Генерация случайного 16-значного пароля
    Add-Type -AssemblyName System.Web
    $PasswordString = [System.Web.Security.Membership]::GeneratePassword(16, 3)
    $SecurePassword = ConvertTo-SecureString $PasswordString -AsPlainText -Force

    #Создание локальной учетной записи
    New-LocalUser -Name $AccountName -Password $SecurePassword -FullName "Auto Generated User" -Description "Created via WinAdminTool" | Out-Null
    
    #Смена пароля при первом входе
    Set-LocalUser -Name $AccountName -ChangePasswordAtNextLogon $true

    #Добавление в группу
    Add-LocalGroupMember -Group $GroupName -Member $AccountName -ErrorAction SilentlyContinue

    Write-Log "Пользователь $AccountName успешно создан и добавлен в группу '$GroupName'!" "INFO"
    Write-Host "Временный пароль: $PasswordString" -ForegroundColor Yellow
}

#2.ОЧИСТКА ДИСКА
function Invoke-DiskCleanup {
    Write-Log "Запуск процедуры очистки диска..." "INFO"

    $InitialFreeSpace = (Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'").FreeSpace

    #1.Очистка пользовательских и системных Temp папок
    $TempFolders = @(
        "C:\Windows\Temp\*",
        "C:\Users\*\AppData\Local\Temp\*",
        "C:\Windows\Prefetch\*"
    )
    foreach ($folder in $TempFolders) {
        Remove-Item -Path $folder -Recurse -Force -ErrorAction SilentlyContinue
    }

    #2.Очистка Корзины
    Clear-RecycleBin -DriveLetter C -Confirm:$false -ErrorAction SilentlyContinue

    #3.Очистка кэша Windows Update
    Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "C:\Windows\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue
    Start-Service -Name wuauserv -ErrorAction SilentlyContinue

    $FinalFreeSpace = (Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'").FreeSpace
    $FreedMB = [math]::Round(($FinalFreeSpace - $InitialFreeSpace) / 1MB, 2)

    Write-Log "Очистка завершена. Освобождено: $FreedMB МБ." "INFO"
}

#3.ПАРСИНГ СОБЫТИЙ (EVENT LOG)
function Get-SecurityLogAnalysis {
    Write-Log "Анализ журнала событий Security на ошибки входа (Event ID 4625)..." "INFO"

    #Извлекаем последние 500 записей о неудачном входе
    $FailedLogons = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 500 -ErrorAction SilentlyContinue

    if (-not $FailedLogons) {
        Write-Log "Неудачных попыток входа не обнаружено." "INFO"
        return
    }

    $Report = foreach ($Event in $FailedLogons) {
        $xml = [xml]$Event.ToXml()
        [PSCustomObject]@{
            TimeCreated = $Event.TimeCreated
            TargetUser  = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'}).'#text'
            IpAddress   = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'IpAddress'}).'#text'
        }
    }

    Write-Host "`n=== Топ-5 IP-адресов по попыткам брутфорса ===" -ForegroundColor Yellow
    $Report | Group-Object IpAddress | Sort-Object Count -Descending | Select-Object -First 5 Count, Name | Format-Table -AutoSize

    Write-Host "=== Топ-5 атакуемых учетных записей ===" -ForegroundColor Yellow
    $Report | Group-Object TargetUser | Sort-Object Count -Descending | Select-Object -First 5 Count, Name | Format-Table -AutoSize
}

# ОБРАБОТКА ВХОДНЫХ ПАРАМЕТРОВ
if ($CreateUser) { New-CustomUser -AccountName $Username -GroupName $Group }
if ($CleanDisk)  { Invoke-DiskCleanup }
if ($ParseLogs)  { Get-SecurityLogAnalysis }
if ($All) {
    Invoke-DiskCleanup
    Get-SecurityLogAnalysis
}

if (-not ($CreateUser -or $CleanDisk -or $ParseLogs -or $All)) {
    Write-Host @"
Использование:
  .\WinAdminTool.ps1 -CreateUser -Username "john_doe" -Group "Administrators"
  .\WinAdminTool.ps1 -CleanDisk
  .\WinAdminTool.ps1 -ParseLogs
  .\WinAdminTool.ps1 -All
"@
}