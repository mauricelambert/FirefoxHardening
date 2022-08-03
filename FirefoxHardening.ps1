###################
#    This file implements a CIS based Hardening for Mozilla Firefox browser.
#    Copyright (C) 2022  Maurice Lambert

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
###################

$copyright=@'
FirefoxHardening  Copyright (C) 2022  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
'@

echo $copyright

$configurations = @{
	# Custom
	"dom.event.clipboardevents.enabled"="false"
	"geo.enabled"="false"
	"browser.cache.disk.enable"="false"
	"browser.cache.disk.capacity"="0"
	"browser.cache.memory.max_entry_size"="5120"
	"browser.cache.memory.capacity"="20000"
	"browser.cache.offline.enable"="false"
	"browser.cache.offline.capacity"="0"
	"network.http.sendRefererHeader"="2"
	"network.prefetch-next"="false"
	"browser.sessionhistory.max_entries"="5"
	"browser.display.use_document_fonts"="0"
	"privacy.trackingprotection.enabled"="true"
	"extensions.getAddons.cache.enabled"="false"
	"network.dns.disableIPv6"="true"
	"browser.tabs.closeWindowWithLastTab"="false"
	"network.manage-offline-status"="false"
	"browser.urlbar.maxRichResults"="0"
	"browser.urlbar.matchOnlyTyped"="true"
	"xpinstall.signatures.required"="true"
	"extensions.pocket.enabled"="false"
	"media.peerconnection.enabled"="false"
	"privacy.resistFingerprinting"="true"
	"privacy.firstparty.isolate"="true"
	"media.navigator.enabled"="false"
	"webgl.disabled"="true"
	"browser.urlbar.placeholderName"='"DuckDuckGo"'
	"browser.urlbar.placeholderName.private"='"DuckDuckGo"'
        "devtools.theme"='"dark"'
	"widget.content.allow-gtk-dark-theme"="true"
	"widget.gtk.alt-theme.dark"="true"
	"browser.theme.toolbar-theme"="2"
	"browser.in-content.dark-mode"="true"
	
	# CIS
	"app.update.enabled"="true"
	"app.update.auto"="true"
	"app.update.staging.enabled"="true"
	"plugins.update.notifyUser"="true"
	"plugins.hide_infobar_for_outdated_plugin"="false"
	"app.update.interval"="43200"
	"app.update.promptWaitTime"="172800"
	"app.update.silent"="false"
	"browser.search.update"="true"
	"network.http.sendSecureXSiteReferrer"="false"                  # Level 2
	"network.auth.force-generic-ntlm-v1"="false"
	"network.http.phishy-userpass-length"="1"
	"network.IDN_show_punycode"="true"                              # Level 2
	"security.fileuri.strict_origin_policy"="true"
	"services.sync.enabled"="false"
	"media.peerconnection.use_document_iceservers"="false"
	"browser.ssl_override_behavior"="0"                             # Level 2
	"security.tls.version.max"="3"
	"security.tls.version.min"="1"
	"security.OCSP.enabled"="1"                                     # Level 2
	"security.mixed_content.block_active_content"="true"
	"security.ocsp.require"="true"                                  # Level 2
	"dom.disable_window_status_change"="true"
	"security.xpconnect.plugin.unrestricted"="false"
	"dom.disable_window_open_feature.location"="true"
	"dom.disable_window_open_feature.status"="true"
	"dom.allow_scripts_to_close_windows"="false"
	"privacy.popups.policy"="1"
	"browser.urlbar.filter.javascript"="true"
	"signon.rememberSignons"="false"
	"network.cookie.cookieBehavior"="1"
	"privacy.donottrackheader.enabled"="true"
	"privacy.donottrackheader.value"="1"
	"privacy.trackingprotection.pbmode"="true"
	"security.dialog_enable_delay"="2000"
	"browser.helperApps.alwaysAsk.force"="true"
	"xpinstall.whitelist.required"="true"
	"extensions.blocklist.enabled"="true"
	"extensions.blocklist.interval"="86400"
	"network.protocol-handler.warn-external-default"="true"
	"privacy.popups.disable_from_plugins"="2"
	"extensions.update.autoUpdateDefault"="true"
	"extensions.update.enabled"="true"
	"extensions.update.interval"="86400"
	"browser.download.manager.scanWhenDone"="true"
	"network.jar.open-unsafe-types"="false"
	"browser.safebrowsing.enabled"="true"
	"browser.safebrowsing.malware.enabled"="true"
	
}

$appdata_files=$(Resolve-Path "$((Get-Item Env:APPDATA).value)\Mozilla\Firefox\Profiles\*\prefs.js" | Select -ExpandProperty Path)
$appdata_files+=$(Resolve-Path "C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\prefs.js" | Select -ExpandProperty Path)
$directories=$(Resolve-Path "C:\*Program*\*Mozilla*Firefox*\defaults\pref" | Select -ExpandProperty Path)

function HardenFile () {
	param (
		[Parameter(Mandatory)][string]$file,
		[Parameter(Mandatory)][string]$pref_type
	)
	
	$content=$(Get-Content $file)
	
	if (-not $content) {
		$content="//`n"
	}
	
	[String]$content=$($content -Join "`n")
	foreach($key in $configurations.keys) {
		$content=ChangeFirefoxPref -pref_type $pref_type -content $content -config $key -data $configurations[$key]
	}
	Set-Content -Path $file -Value $content
}

function ChangeFirefoxPref () {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory)][string]$pref_type,
		[Parameter(Mandatory)][string]$content,
		[Parameter(Mandatory)][string]$config,
		[Parameter(Mandatory)][string]$data
	)

	$regex=$pref_type + '\("' + $($config -replace "\.", "\.") + '",[^\n]*'
	if ($content -match $regex) {
		return $content -replace $regex, $($pref_type + '("' + $config + '", ' + $data + ');')
	} else {
		
		return $content + "`n" + $pref_type + '("' + $config + '", ' + $data + ');'
	}
}

if ($appdata_files.GetType().Name -match "String") {
	$appdata_files=@($appdata_files)
}

foreach ($directory in $directories) {
	$file=$directory + '\local-settings.js'
	Set-Content -Path $file -Value $('pref("general.config.obscure_value", 0);' + "`n" + 'pref("general.config.filename", "mozilla.cfg");')
	$file=$directory + '\..\..\mozilla.cfg'
	HardenFile -file $file -pref_type "lockPref"
}

foreach ($file in $appdata_files) {
	HardenFile -file $file -pref_type "user_pref"
}
