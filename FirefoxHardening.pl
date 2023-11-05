#!/usr/bin/env perl

# 
# 2022-08-02
# Maurice LAMBERT <mauricelambert434@gmail.com>
# https://github.com/mauricelambert/FirefoxHardening

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

package FirefoxHardening;

use v5.26;
use strict;
use open qw( :encoding(UTF-8) :std );

our $NAME            = "FirefoxHardening";
our $VERSION         = "0.0.1";
our $AUTHOR          = "Maurice Lambert";
our $MAINTAINER      = "Maurice Lambert";
our $AUTHOR_MAIL     = 'mauricelambert434@gmail.com';
our $MAINTAINER_MAIL = 'mauricelambert434@gmail.com';

our $DESCRIPTION = "This file implements a CIS based Hardening for Mozilla Firefox browser.";
our $URL         = "https://github.com/mauricelambert/$NAME";
our $LICENSE     = "GPL-3.0 License";
our $COPYRIGHT   = <<'EOF';
FirefoxHardening  Copyright (C) 2022  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
EOF

print $COPYRIGHT;

my %configurations = (
   # Custom
	"dom.event.clipboardevents.enabled" => "false",
	"geo.enabled" => "false",
	"browser.cache.disk.enable" => "false",
	"browser.cache.disk.capacity" => "0",
	"browser.cache.memory.max_entry_size" => "5120",
	"browser.cache.memory.capacity" => "20000",
	"browser.cache.offline.enable" => "false",
	"browser.cache.offline.capacity" => "0",
	"network.http.sendRefererHeader" => "2",
	"network.prefetch-next" => "false",
	"browser.sessionhistory.max_entries" => "5",
	"browser.display.use_document_fonts" => "0",
	"privacy.trackingprotection.enabled" => "true",
	"extensions.getAddons.cache.enabled" => "false",
	"network.dns.disableIPv6" => "true",
	"browser.tabs.closeWindowWithLastTab" => "false",
	"network.manage-offline-status" => "false",
	"browser.urlbar.maxRichResults" => "0",
	"browser.urlbar.matchOnlyTyped" => "true",
	"xpinstall.signatures.required" => "true",
	"extensions.pocket.enabled" => "false",
	"media.peerconnection.enabled" => "false",
	"privacy.resistFingerprinting" => "true",
	"privacy.firstparty.isolate" => "true",
	"media.navigator.enabled" => "false",
	"webgl.disabled" => "true",
	"browser.urlbar.placeholderName" => '"DuckDuckGo"',
	"browser.urlbar.placeholderName.private" => '"DuckDuckGo"',
	"devtools.theme" => '"dark"',
	"widget.content.allow-gtk-dark-theme" => "true",
	"widget.gtk.alt-theme.dark" => "true",
	"browser.theme.toolbar-theme" => "2",
	"browser.in-content.dark-mode" => "true",
	
	# CIS
	"app.update.enabled" => "true",
	"app.update.auto" => "true",
	"app.update.staging.enabled" => "true",
	"plugins.update.notifyUser" => "true",
	"plugins.hide_infobar_for_outdated_plugin" => "false",
	"app.update.interval" => "43200",
	"app.update.promptWaitTime" => "172800",
	"app.update.silent" => "false",
	"browser.search.update" => "true",
	"network.http.sendSecureXSiteReferrer" => "false",                  # Level 2
	"network.auth.force-generic-ntlm-v1" => "false",
	"network.http.phishy-userpass-length" => "1",
	"network.IDN_show_punycode" => "true",                              # Level 2
	"security.fileuri.strict_origin_policy" => "true",
	"services.sync.enabled" => "false",
	"media.peerconnection.use_document_iceservers" => "false",
	"browser.ssl_override_behavior" => "0",                             # Level 2
	"security.tls.version.max" => "3",
	"security.tls.version.min" => "1",
	"security.OCSP.enabled" => "1",                                     # Level 2
	"security.mixed_content.block_active_content" => "true",
	"security.ocsp.require" => "true",                                  # Level 2
	"dom.disable_window_status_change" => "true",
	"security.xpconnect.plugin.unrestricted" => "false",
	"dom.disable_window_open_feature.location" => "true",
	"dom.disable_window_open_feature.status" => "true",
	"dom.allow_scripts_to_close_windows" => "false",
	"privacy.popups.policy" => "1",
	"browser.urlbar.filter.javascript" => "true",
	"signon.rememberSignons" => "false",
	"network.cookie.cookieBehavior" => "1",
	"privacy.donottrackheader.enabled" => "true",
	"privacy.donottrackheader.value" => "1",
	"privacy.trackingprotection.pbmode" => "true",
	"security.dialog_enable_delay" => "2000",
	"browser.helperApps.alwaysAsk.force" => "true",
	"xpinstall.whitelist.required" => "true",
	"extensions.blocklist.enabled" => "true",
	"extensions.blocklist.interval" => "86400",
	"network.protocol-handler.warn-external-default" => "true",
	"privacy.popups.disable_from_plugins" => "2",
	"extensions.update.autoUpdateDefault" => "true",
	"extensions.update.enabled" => "true",
	"extensions.update.interval" => "86400",
	"browser.download.manager.scanWhenDone" => "true",
	"network.jar.open-unsafe-types" => "false",
	"browser.safebrowsing.enabled" => "true",
	"browser.safebrowsing.malware.enabled" => "true",
);

my @directories = </usr/lib/*firefox*/defaults/pref>;
my @appdata_files = </home/*/.mozilla/firefox/*/prefs.js>;

sub set_content {
	my ($filename, $data) = @_;
	open my $file, '>', $filename or die "Can't open $filename: $!";
	print $file "${data}\n" or die "Can't write $filename: $!";
	close $file;
}

sub get_content {
	my ($filename) = @_;
	open my $file, '<', $filename or die "Can't open $filename: $!";
	my $contents = do { local $/; <$file> };
	return $contents;
}

sub change_firefox_pref {
	my ($pref_type, $content, $config, $value) = @_;

	$_ = $config;
	s/\./\\./g;
	my $regex = qr/${pref_type}\(\"${_}\",[^\n]*/;
	my $data = "${pref_type}(\"${config}\", ${value});";

	if ($content =~ /${regex}/) {
		$content =~ s/${regex}/${data}/;
	} else {
		$content = $content . "\n${data}";
	}

	return $content;
}

sub harden_file {
	my ($file, $pref_type) = @_;
	my ($content, $config, $value);

	if (-e $file) {
		$content = get_content $file;
	} else {
		$content = "//\n";
	}

	while (($config, $value) = each (%configurations)) {
		$content = change_firefox_pref($pref_type, $content, $config, $value);
	}

	set_content $file, $content;
}

foreach my $directory (@directories) {
	my $filename = $directory . '/local-settings.js';
	set_content $filename, "pref(\"general.config.obscure_value\", 0);\npref(\"general.config.filename\", \"mozilla.cfg\");";

	harden_file $directory . '/../../mozilla.cfg', "lockPref";
}

foreach my $file (@appdata_files) {
	harden_file $file, "user_pref";
}
