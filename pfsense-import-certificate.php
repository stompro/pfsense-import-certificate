<?php

/**
 * Import SSL certificates from a pre-determined place on the filesystem.
 * Once imported, set them for use in the GUI
 */

if (empty($argc)) {
	echo "Only accessible from the CLI.\r\n";
	die(1);
}

if ($argc != 3) {
	echo "Usage: php " . $argv[0] . " /path/to/certificate.crt /path/to/private/key.pem /path/to/chain.pem \r\n";
	die(1);
}

require_once "certs.inc";
require_once "pfsense-utils.inc";
require_once "functions.inc";
require_once "filter.inc";
require_once "shaper.inc";

$certificate = trim(file_get_contents($argv[1]));
$key = trim(file_get_contents($argv[2]));
if ($argv[3]) { #If CA specified load it.
  $ca = trim(file_get_contents($argv[3]));
}

// Do some quick verification of the certificate, similar to what the GUI does
if (empty($certificate)) {
	echo "The certificate is empty.\r\n";
	die(1);
}
if (!strstr($certificate, "BEGIN CERTIFICATE") || !strstr($certificate, "END CERTIFICATE")) {
	echo "This certificate does not appear to be valid.\r\n";
	die(1);
}

// Verification that the certificate matches the key
if (empty($key)) {
	echo "The key is empty.\r\n";
	die(1);
}
if (cert_get_publickey($certificate, false) != cert_get_publickey($key, false, 'prv')) {
	echo "The private key does not match the certificate.\r\n";
	die(1);
}

$cert = array();
$cert['refid'] = uniqid();
$cert['descr'] = "Certificate added to pfsense through " . $argv[0] . " on " . date("Y/m/d");

cert_import($cert, $certificate, $key);

// Set up the existing certificate store
// Copied from system_certmanager.php
if (!is_array($config['ca'])) {
	$config['ca'] = array();
}

$a_ca =& $config['ca'];

if (!is_array($config['cert'])) {
	$config['cert'] = array();
}

$a_cert =& $config['cert'];

$internal_ca_count = 0;
foreach ($a_ca as $ca) {
	if ($ca['prv']) {
		$internal_ca_count++;
	}
}

// Check if the certificate we just parsed is already imported (we'll check the certificate portion)
foreach ($a_cert as $existing_cert) {
	if ($existing_cert['crt'] === $cert['crt']) {
		echo "The certificate is already imported.\r\n";
		die(); // exit with a valid error code, as this is intended behaviour
	}
}

// Append the final certificate
$a_cert[] = $cert;

// Write out the updated configuration
write_config("Save new certificate config, from pfsense-import-certificate.php");
sleep(3); //sleep to space out the write_config calls so they show distinctly

// Assuming that all worked, we now need to set the new certificate for use in the GUI
$config['system']['webgui']['ssl-certref'] = $cert['refid'];

// If Unbound is set to use TLS, then set the new certificate to be used by Unbound also.
if (isset($config['unbound']['enable']) and isset($config['unbound']['enablessl'])) {
  echo "Install Unbound Certificate\r\n";
  $config['unbound']['sslcertref'] = $cert['refid'];
  $restartunbound = true;
}

// If captive portal is set to use TLS, then set the new certificate
//   to be used by captive portals
foreach ($config['captiveportal'] as $cpid => $cportal) {
  if(isset($cportal['enable']) and isset($cportal['httpslogin'])){
    echo "Update Captive Portal Certificate: $cpid\r\n";
    $config['captiveportal'][$cpid]['certref'] = $cert['refid'];
  }
}

// If haproxy is set to offload ssl, then set the new certificate
foreach ($config['installedpackages']['haproxy']['ha_backends']['item'] as $itemid => $haitem) {
  if(isset($haitem['ssloffloadacl_an'])) {
    $name = $haitem['name'];
    echo "Updating HAProxy certificate for backend: $name\r\n";
    $config['installedpackages']['haproxy']['ha_backends']['item'][$itemid]['ssloffloadcert'] = $cert['refid'];
  }
}

write_config("Set new certificate as active for webgui, from pfsense-import-certificate.php");
sleep(3); //sleep to space out the write_config calls

//Use cert_get_all_services to grab all services now using the new cert.

$services = cert_get_all_services($cert['refid']);

//Restart all services that are using the new cert.
echo "Restart services that are using the new cert\r\n";
print_r($services);
log_error(gettext("Restart services that are using the new cert"));

cert_restart_services($services);
//All except unbound, there is a bug in cert_restart_services... it doesn't restart unbound
//https://redmine.pfsense.org/issues/15062

echo "Completed! New certificate installed.\r\n";

// If unbound cert was updated, then restart unbound.
// Remove once bug fixed
if ($restartunbound) {
  echo "Restart Unbound\n";
  log_error(gettext("Unbound configuration has changed. Restarting Unbound."));
  service_control_restart('unbound','');
}


// Delete unused certificates added by this script

$a_cert =& $config['cert'];
$name = '';
foreach ($a_cert as $cid => $acrt) {
  echo "Eval Cert for delete: $cid\r\n";
  if (!cert_in_use($acrt['refid']) and preg_match("/pfsense-import-certificate\.php/",$acrt['descr'])) {
    echo "-->Delete this certificate\r\n";
    // cert not in use and matches description pattern
    $name.=htmlspecialchars($acrt['descr'])." ";
    unset($a_cert[$cid]);
  }
}

if($name){
        echo "Deleted old certificates: save the config.\r\n";
        $savemsg = sprintf(gettext("Deleted certificate: %s , from pfsense-import-certificate.php"), $name);
        write_config($savemsg);
}
