param(
    [Parameter(Mandatory)][string]$ConfigDir,
    [Parameter(Mandatory)][string]$AccountsDir
)

$ErrorActionPreference = 'Stop'

function Find-TokenFile([string]$Profile) {
    if ($Profile -cnotmatch '\A[a-z0-9]{8,32}\z') { return }
    $path = $AccountsDir
    foreach ($name in @($Profile, '.gemini', 'antigravity-cli', 'antigravity-oauth-token')) {
        $path = Join-Path $path $name
        $item = Get-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        if (-not $item -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { return }
    }
    if (-not $item.PSIsContainer -and $item.Length -gt 0 -and $item.Length -le 65536) { $item.FullName }
}

function Get-MagpieProfiles {
    $indexPath = Join-Path $ConfigDir 'plugin-auth.json'
    if (-not (Test-Path -LiteralPath $indexPath -PathType Leaf)) { return }
    $index = Get-Content -LiteralPath $indexPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $seen = @{}
    foreach ($entry in $index.PSObject.Properties) {
        if ($entry.Name -cnotmatch '^agy-cli(?:-plugin)?(?:#.+)?$') { continue }
        $metadata = $entry.Value.metadata
        $profile = $metadata.agyHome
        if ($profile -isnot [string] -or $seen.ContainsKey($profile) -or -not (Find-TokenFile $profile)) { continue }
        $seen[$profile] = $true
        $email = $metadata.email
        $label = if ($email -is [string] -and $email -match '\A[^\s@]+@[^\s@]+\z') { "$email  ($profile)" } else { $profile }
        [pscustomobject]@{ Profile = $profile; Label = $label }
    }
}

function Read-RefreshToken([string]$Profile) {
    $file = Find-TokenFile $Profile
    if (-not $file) { return }
    $saved = Get-Content -LiteralPath $file -Raw -Encoding UTF8 | ConvertFrom-Json
    $refresh = $saved.token.refresh_token
    if ($refresh -is [string] -and $refresh.Trim() -match '\A[^\s\p{Cc}]+\z') { $refresh.Trim() }
}

try {
    $profiles = @(Get-MagpieProfiles | Sort-Object Label)
    if ($profiles.Count -eq 0) { exit 3 }
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -Namespace MagpieAgy -Name PickerWindow -MemberDefinition @'
[DllImport("user32.dll")]
public static extern bool ShowWindow(IntPtr handle, int command);
'@

    $dialog = New-Object Windows.Forms.Form
    try {
        $dialog.Text = 'AGY 令牌管理'
        $dialog.ClientSize = New-Object Drawing.Size(560, 132)
        $dialog.StartPosition = 'CenterScreen'
        $dialog.FormBorderStyle = 'FixedDialog'
        $dialog.MaximizeBox = $false
        $dialog.MinimizeBox = $false
        $dialog.TopMost = $true

        $label = New-Object Windows.Forms.Label
        $label.Text = '选择要导出 Refresh Token 的 Magpie 账号。'
        $label.SetBounds(16, 17, 528, 23)
        $choices = New-Object Windows.Forms.ComboBox
        $choices.DropDownStyle = 'DropDownList'
        $choices.DisplayMember = 'Label'
        $choices.SetBounds(16, 45, 528, 24)
        foreach ($profile in $profiles) { [void]$choices.Items.Add($profile) }
        $choices.SelectedIndex = 0

        $copy = New-Object Windows.Forms.Button
        $copy.Text = '复制 RT'
        $copy.SetBounds(332, 86, 102, 31)
        $copy.DialogResult = 'OK'
        $cancel = New-Object Windows.Forms.Button
        $cancel.Text = '取消'
        $cancel.SetBounds(442, 86, 102, 31)
        $cancel.DialogResult = 'Cancel'
        $dialog.AcceptButton = $copy
        $dialog.CancelButton = $cancel
        $dialog.Controls.AddRange(@($label, $choices, $copy, $cancel))
        # The host hides PowerShell's console. Explicitly show the dialog itself.
        $dialog.Add_Shown({ [void][MagpieAgy.PickerWindow]::ShowWindow($this.Handle, 5) })
        if ($dialog.ShowDialog() -ne 'OK') { exit 2 }
        $refresh = Read-RefreshToken $choices.SelectedItem.Profile
        if (-not $refresh) { exit 1 }
        [Windows.Forms.Clipboard]::SetText($refresh)
    } finally {
        $dialog.Dispose()
    }
    exit 0
} catch {
    # The plugin host receives only the status code, including for malformed JSON.
    exit 1
}
