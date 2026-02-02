<?php

/**
 * Import SSL certificates from a pre-determined place on the filesystem.
 * Once imported, set them for use in the GUI
 */

if (empty($argc)) {
	echo "Only accessible from the CLI.\r\n";
	die(1);
}

if ($argc < 3) {
	echo "Usage: php " . $argv[0] . " /path/to/certificate.crt /path/to/private/key.pem /path/to/chain.pem \r\n";
	die(1);
}

require_once "certs.inc";
require_once "pfsense-utils.inc";
require_once "functions.inc";
require_once "filter.inc";
require_once "shaper.inc";

$debug = 0; //set to non zero to enable extra debug messages

// Set up the existing certificate store
// Copied from system_camanager.php
if (!is_array($config['ca'])) {
	$config['ca'] = array();
}
$a_ca =& $config['ca'];



$certificate = trim(file_get_contents($argv[1]));
$key = trim(file_get_contents($argv[2]));
if ($argv[3]) { #If CA specified load it.
  $ca_certificate = trim(file_get_contents($argv[3]));
}


### CA Import ###
if($ca_certificate){
  echo "Start CA Import - \n";
  ##Import the Intermediate CA - Chain.pem
  $ca=array();
  $ca['refid'] = uniqid();
  $ca['descr'] = "CA added to pfsense through " . $argv[0] . " on " . date("Y/m/d");
  $ca['trust'] = "disabled";
  $ca['randomserial'] = "disabled";

  ca_import($ca, $ca_certificate, "", "");
  !$debug or print "Debug: ca var after ca_import\n";
  !$debug or print_r($ca);

  // Check if the ca certificate we just parsed is already imported (we'll check the certificate portion)
  $skip_ca = 0;
  foreach ($a_ca as $existing_ca) {
    if ($existing_ca['crt'] === $ca['crt']) {
      echo " The CA is already imported.\r\n";
      //skip importing CA, not needed.
      $skip_ca = 1;
    }
  }

  if(!$skip_ca){
    echo " Write CA Config\r\n";
    // config_set_path('ca/', $ca); //doesn't work in 2_7_1 and before
    $a_ca[] = $ca;
    write_config("Save new certificate authority config, from pfsense-import-certificate.php");
    !$debug or print "Debug: a_ca after write config\n";
    !$debug or print_r($a_ca);
    !$debug or print "Debug: config[ca] after write config\n";
    !$debug or print_r($config['ca']);
    sleep(3); //sleep to space out the write_config calls so they show distinctly
  }
}
### CA Import ###

### Cert Import ###
echo "Start Cert Import --\n";

if (!is_array($config['cert'])) {
	$config['cert'] = array();
}
$a_cert =& $config['cert'];

// Do some quick verification of the certificate, similar to what the GUI does
if (empty($certificate)) {
	echo " The certificate is empty.\r\n";
	die(1);
}
if (!strstr($certificate, "BEGIN CERTIFICATE") || !strstr($certificate, "END CERTIFICATE")) {
	echo " This certificate does not appear to be valid.\r\n";
	die(1);
}

// Verification that the certificate matches the key
if (empty($key)) {
	echo " The key is empty.\r\n";
	die(1);
}
if (cert_get_publickey($certificate, false) != cert_get_publickey($key, false, 'prv')) {
	echo " The private key does not match the certificate.\r\n";
	die(1);
}

$cert = array();
$cert['refid'] = uniqid();
$cert['descr'] = "Certificate added to pfsense through " . $argv[0] . " on " . date("Y/m/d");

cert_import($cert, $certificate, $key);

!$debug or print "Debug: cert after cert_import function\n";
!$debug or print_r($cert);

$skip_cert = 0;
// Check if the certificate we just parsed is already imported (we'll check the certificate portion)
foreach ($a_cert as $existing_cert) {
	if ($existing_cert['crt'] === $cert['crt']) {
		echo " The certificate is already imported.\r\n";
    $skip_cert = 1;
		//die(); // exit with a valid error code, as this is intended behaviour
	}
}

if(!$skip_cert){
  echo " Write Cert Config\r\n";
  // Append the final certificate
  $a_cert[] = $cert;

  // Write out the updated configuration
  write_config("Save new certificate config, from pfsense-import-certificate.php");
  !$debug or print "Debug: a_cert value\n";
  !$debug or print_r($a_cert);
  !$debug or print "Debug: config cert value\n";
  !$debug or print_r($config['cert']);
  sleep(3); //sleep to space out the write_config calls so they show distinctly
}
### Cert Import ###

### Enable new cert for services ###
if(!$skip_cert){ //No need to do any of this if cert import was skipped
  echo "Setup new cert to be used by services ---\n";
  // Assuming that all worked, we now need to set the new certificate for use in the GUI
  $config['system']['webgui']['ssl-certref'] = $cert['refid'];

  // If Unbound is set to use TLS, then set the new certificate to be used by Unbound also.
  if (isset($config['unbound']['enable']) and isset($config['unbound']['enablessl'])) {
    echo " Install Unbound Certificate\r\n";
    $config['unbound']['sslcertref'] = $cert['refid'];
    $restartunbound = true;
  }

  // If captive portal is set to use TLS, then set the new certificate
  //   to be used by captive portals
  foreach ($config['captiveportal'] as $cpid => $cportal) {
    if(isset($cportal['enable']) and isset($cportal['httpslogin'])){
      echo " Update Captive Portal Certificate: $cpid\r\n";
      $config['captiveportal'][$cpid]['certref'] = $cert['refid'];
    }
  }
  !$debug or print "Debug: CertRef set for services\n";
  !$debug or print "Debug: Webui:".$config['system']['webgui']['ssl-certref']."\n\r";
  !$debug or print "Debug: Unbound:".$config['unbound']['sslcertref']."\n\r";

  write_config("Set new certificate as active for webgui, from pfsense-import-certificate.php");
  sleep(3); //sleep to space out the write_config calls
  ### Enable new cert for services ###

  ### Restart Services ###
  //Use cert_get_all_services to grab all services now using the new cert.

  $services = cert_get_all_services($cert['refid']);

  //Restart all services that are using the new cert.
  echo "Restart services that are using the new cert ----\r\n";
  !$debug or print_r($services);
  log_error(gettext("Restart services that are using the new cert"));

  cert_restart_services($services);
  //All except unbound, there is a bug in cert_restart_services... it doesn't restart unbound
  //https://redmine.pfsense.org/issues/15062

  

  // If unbound cert was updated, then restart unbound.
  // Remove once bug fixed
  if ($restartunbound) {
    echo " Restart Unbound\n";
    log_error(gettext("Unbound configuration has changed. Restarting Unbound."));
    service_control_restart('unbound','');
  }
  ### Restart Services ###

  echo "Completed! New certificate installed.\r\n";

}

// Delete unused certificates added by this script
echo "Delete old unused certificates and CAs -----\n";
!$debug or print "Debug: What does the config look like right before we start with the deletes?\n";

$a_cert =& $config['cert'];
!$debug or print_r($a_cert);
$name = '';
foreach ($a_cert as $cid => $acrt) {
  echo " ->Eval Cert for delete: $cid\r\n";
  if (!cert_in_use($acrt['refid']) and preg_match("/pfsense-import-certificate\.php/",$acrt['descr'])) {
    echo " -->Delete this certificate (",$acrt['refid']," - ",$acrt['descr'],"\r\n";
    // cert not in use and matches description pattern
    $name.=htmlspecialchars($acrt['descr'])." ";
    unset($a_cert[$cid]);
  }
}

if($name){
        echo " Deleted old certificates: save the config.\r\n";
        $savemsg = sprintf(gettext("Deleted certificate: %s , from pfsense-import-certificate.php"), $name);
        write_config($savemsg);
        sleep(3); //sleep to space out the write_config calls
}

// Delete unused CA Certificates added by this script

$a_ca =& $config['ca'];
$a_cert =& $config['cert'];
!$debug or print_r($a_ca);
$name = '';
foreach ($a_ca as $caid => $aca) {
  echo " ->Eval CA for delete: $caid\r\n";
  if (!ca_in_use($aca['refid']) and (  preg_match("/pfsense-import-certificate\.php/",$aca['descr']) 
                                  //or   preg_match("/LetsEncrypt Intermediate E\d/i",$aca['descr']) //Remove extra Intermediate Letsencrypt CAs at the same time
                                    )) {
    //check if any certs reference this ca
    $certcount = 0;
    //Check if CA is used by any certs
    foreach ($a_cert as $certck) {
      if ($certck['caref'] == $aca['refid']) {
        $certcount++;
      }
	  }
    //Check if CA is used by any other CAs
    foreach ($a_ca as $certck) {
      if ($certck['caref'] == $aca['refid']) {
        $certcount++;
      }
    }
    if(!$certcount){
      echo " -->Delete this CA (",$aca['refid']," - ",$aca['descr'],")\r\n";
      // cert not in use and matches description pattern
      $name.=htmlspecialchars($aca['descr'])." ";
      unset($a_ca[$caid]);
    }
  }
}

if($name){
        echo " Deleted old ca certs: save the config.\r\n";
        $savemsg = sprintf(gettext("Deleted CA: %s , from pfsense-import-certificate.php"), $name);
        write_config($savemsg);
        sleep(3); //sleep to space out the write_config calls
}

!$debug or print "Debug: What does the config look like right before we quit?\n";
!$debug or print_r($a_cert);
!$debug or print_r($a_ca);