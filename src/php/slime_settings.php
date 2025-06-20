<?php

/**
 * SLIME S/MIME Plugin
 *
 * Copyright (c) 2025 Zdenek Dobes
 * See README file for more details.
 * 
 */

require_once('slime_smimeFile.php');

/**
 * This class holds information about plugin configuration and user customization
 * Represents functions in S/MIME setting section
*/

class slime_settings {

    public $plugin_enabled;
    public $certificateDirectoryPath;
    public $trustedCertificateDirectoryPath;
    public $numberOfSubdirectories;
    public $maxNumberOfCertificates;
    public $supportedAlgs;
    public $weakAlgs;
    public $disableWeakAlg;
    public $disableAuthEnveloped;
    public $strictPolicy;
    public $newerPKCS7CType;

    public $slime;
    public $identities;
    public $currentPageNumber;
    public $currentCertificatesNumber;

    /**
     * Gets user customization setting
     * 
     * @param slime_smime $slime Plugin class
     */

    function __construct($slime){

        $this->slime = $slime;
        $this->plugin_enabled = $slime->rc->config->get('slime_plugin_enabled', true);
        $this->certificateDirectoryPath = $slime->rc->config->get('slime_path_to_certs', "");
        $this->trustedCertificateDirectoryPath = $slime->rc->config->get('slime_path_to_trusted_certs', "");
        $this->numberOfSubdirectories = $slime->rc->config->get('slime_numberOfSubdirectories', 1);
        $this->supportedAlgs = $slime->rc->config->get('slime_supported_sym_alg', array('aes_128_cbc'));
        $this->weakAlgs = $slime->rc->config->get('slime_weak_sym_algorithms', array());
        $this->newerPKCS7CType = $slime->rc->config->get('slime_useNewerPKCS7CType', false);

        $this->maxNumberOfCertificates = $slime->rc->config->get('slime_numberOfCertificates', 100);
        if($this->maxNumberOfCertificates < 0){
            $this->maxNumberOfCertificates = 100;
        }
        else if($this->maxNumberOfCertificates > 1000){
            $this->maxNumberOfCertificates = 1000;
        }

        // If strict mode is on, also disable weak algorithms
        $this->strictPolicy = $slime->rc->config->get('slime_strictPolicy', false);
        $this->disableWeakAlg = $this->strictPolicy ? true : $slime->rc->config->get('slime_disableUnsafeSymAlg', false);
        $this->disableAuthEnveloped = $this->strictPolicy ? false : $slime->rc->config->get('slime_disableAuthEnveloped', false);

        $this->currentPageNumber = 1;
        $this->identities = $slime->rc->user->list_identities();
    }

    /**
     * Initialize settings, creates subdirectories for storing certificates
     * 
     * @param slime_smime $slime Plugin class
     */
    function initSettings(){

    // If invalid certificate directory, use default
    if(!is_readable($this->certificateDirectoryPath)){
        $newCertPath = getcwd() . "/plugins/slime_smime/certificates";
        if(!file_exists($newCertPath)){
            mkdir($newCertPath, 0777, true);
        }
        $this->certificateDirectoryPath = $newCertPath;
    }

    // If invalid trusted CA directory, use system store
    if($this->trustedCertificateDirectoryPath != "" && !is_readable($this->trustedCertificateDirectoryPath)){
        $this->trustedCertificateDirectoryPath = "";
    }

     // Normalizes path
     $this->certificateDirectoryPath = substr($this->certificateDirectoryPath, -1) == "/" || substr($this->certificateDirectoryPath, -1) == '\\' ? $this->certificateDirectoryPath : $this->certificateDirectoryPath . "/";

    // If plugin was not initialized
    if(count(scandir($this->certificateDirectoryPath)) === 2){

        // Create hash subdirectories
        if($this->numberOfSubdirectories > 1){

            if($this->numberOfSubdirectories > 1024){
                $this->numberOfSubdirectories = 1024;
            }
            
            // Checks if number of subdirectories is power of 2
            if($this->numberOfSubdirectories > 0 && ($this->numberOfSubdirectories & ($this->numberOfSubdirectories - 1)) == 0){
                
                for ($i = 0; $i < $this->numberOfSubdirectories; $i++) {

                    $subdir = $this->certificateDirectoryPath . sprintf("%d", $i);
                    if (!file_exists($subdir)) {
                        mkdir($subdir, 0777, true);
                    }
                }
            }

            // Creates one subdirectory
            else{

                $subdir = $this->certificateDirectoryPath . "0";
                if (!file_exists($subdir)) {
                    mkdir($subdir, 0777, true);
                }
            }
            
        }

        // Creates one subdirectory
        else{

            $subdir = $this->certificateDirectoryPath . "0";
            if (!file_exists($subdir)) {
                mkdir($subdir, 0777, true);
            }
        }
    }
   }

   /**
     * Checks if user did not disable the plugin
     * 
     * @return bool True if plugin is enabled
     */

   function isPluginEnabled(){
    return $this->plugin_enabled;
   }

   /**
     * Imports a certificate 
     * 
     * @param string $uploaded_file Path of the imported temporary file
     * @param string $password Password of the PKCS#12 file
     * @param string $type Content Type of the file
     * 
     * @return int Enumeration value of the outcome
     */

   function importCertificate($uploaded_file, $password, $type){
    $new_file = new slime_smimeFile($uploaded_file, $this->slime, $type);
    return $new_file->createFile($password);
  }

     /**
     * Exports a certificate
     * 
     * @param string $email E-mail of the file owner
     * @param string $exportType File format of desired exported file 
     * @param string $password Password for the new PKCS#12 file
     * @param bool $isOld True if this certificate expires later than current one
     * @param string $extension File extension
     * 
     * @return int Enumeration value of the outcome
     */

  function exportCertificate($email, $exportType, $password, $isOld, $extension){
    if($isOld){
        $suffix = "." . $extension;
    }
    else{
        $suffix = substr($exportType, 0, 4) == "pkcs" ? ".p12" : ".crt";
    }
    $filename = $this->emailToFolderName($email) . $suffix;
    $isOldString = $isOld ? "old_pkcs/" : "";
    $file_path = $this->getPathForUser() ."/" . $isOldString . $filename;

    // Other certs
    if($exportType == "crt"){

        // Ensures no data are stored in cache that could be send 
        ob_clean();
        
        // Sending data to user
        header('Content-Type: application/x-x509-ca-cert');
        header('Content-Disposition: attachment; filename="export.crt"');
        if(file_exists($file_path)){
            readfile($file_path);
        }

    }

    // My certs or PKCS#12 files
    else{

        $new_file = new slime_smimeFile($file_path, $this->slime, $suffix);

        // PKCS#12 to .crt
        if($exportType == "pkcs_crt"){
            $content = trim($new_file->PKCSToCertPath());
            $downloadFile = "export.crt";
            $contentType = "application/x-x509-ca-cert";
        }

        // PKCS#12 no new password entered
        else if($password == null){
            return slime_smime::FILE_IS_MISSING_A_PASSWORD;
        }

        // PKCS#12 to PKCS#12
        else{
            $content = $new_file->PKCSSectureCert($password, $email);
            $downloadFile = "export.p12";
            $contentType = "application/x-pkcs12";
        }

        // Ensures no data are stored in cache that could be send 
        ob_clean();

        // Sending data to user
        header('Content-Type: ' . $contentType);
        header('Content-Disposition: attachment; filename="' . $downloadFile .'"');
        echo $content;
    }

    return slime_smime::FILE_SUCCESS;
  }

    /**
     * Deletes a certificate 
     * 
     * @param string $certName Name of the owner of the certificate
     * @param string $type Content Type of the file
     * @param bool $isOld True if this certificate expires later than current one
     * @param string $extension File extension
     * 
     * @return bool Success of the unlink() function
     */

  function deleteCertificate($certName, $type, $isOld, $extension){
    $new_file = new slime_smimeFile($certName, $this->slime, $type, null, $isOld, $extension);
    return $new_file->deleteFile();
  }

    /**
     * Gets all certificates that are stored in p12 and crt format
     * 
     * @return array .p12 and .crt files from user directory
     */

   function getCertificates(){
    $certificates = array();
    $certDir = $this->getPathForUser();
    $allPKCS = glob($certDir . "/*.p12", GLOB_BRACE);
    $allPKCSOld = glob($certDir . "/old_pkcs/*", GLOB_BRACE);
    $allCRTS = glob($certDir . "/*.crt", GLOB_BRACE);
    $allCerts = array_merge($allPKCS, $allPKCSOld, $allCRTS);
    $this->currentCertificatesNumber = count($allCerts);

    // Removes certificates based on the current number of page  
    $offset = ($this->currentPageNumber - 1) * $this->maxNumberOfCertificates;
    $limit = $this->maxNumberOfCertificates;
    $allCerts = array_slice($allCerts, $offset);

    // Finding wheter there is PKCS#12 that matches current identity
    $indexOfUsedPKCS = -1;
    $allPKCS = array_slice($allPKCS, $offset);
    foreach($allPKCS as $index => $file){
        if($index == 0){
            $indexOfUsedPKCS = 0;
        }
        else if($this->folderNameToEmail(pathinfo($file, PATHINFO_FILENAME)) == $this->slime->rc->user->get_identity()['email']){
            $indexOfUsedPKCS = $index;
        }
    }

    // Appends metadata so it is easily showed by UI
    foreach($allCerts as $index => $file){
        $type = pathinfo($file, PATHINFO_EXTENSION);
        $email = $this->folderNameToEmail(pathinfo($file, PATHINFO_FILENAME));
        $id = uniqid($email);
        $isUsed = $indexOfUsedPKCS == $index;

        $isOld = $type != "p12" && $type != "crt" ? "True" : "False";
        array_push($certificates, array("name" => $email, "id" => $id, "type" => $type, "isOld" => $isOld, "isUsed" => $isUsed));

        // Checks if max number of certs is not exceeded
        if(--$limit == 0){
            break;
        }
    }

    return $certificates;
   }

   /**
     * Checks if strict mode was set in config.inc
     * 
     * @return bool True if strict mode is on
     */

    function isInStrictMode(){
        return $this->strictPolicy;
    }

    /**
     * Encodes E-mail so it is can be saved as a file
     * 
     * @param string $email E-mail to convert
     * 
     * @return string Encoded E-mail
     */

    function emailToFolderName($email){
        $encoded = base64_encode($email);
        $safeEncoded = str_replace(["/", "+", "="], ["_", "-", ""], $encoded);
        return $safeEncoded;
    }

    /**
     * Decoded file name so owners E-mail is restored
     * 
     * @param string $email File to convert
     * 
     * @return string E-mail before encoding
     */

    function folderNameToEmail($fileName){
        $decodedBase64 = str_replace(["_", "-"], ["/", "+"], $fileName);
        $mod = strlen($decodedBase64) % 4;
        if($mod){
            $decodedBase64 .= str_repeat("=", 4 - $mod);
        }
        return base64_decode($decodedBase64);
    }

    /**
     * Gets users login username 
     * 
     * @return string Login username
     */

    function getUsername(){
        return $this->slime->rc->config->get('slime_username', '');
    }

    /**
     * Gets users hash password 
     * 
     * @return string Login hash password
     */

     function getHashPass(){
        return $this->slime->rc->config->get('slime_hashPassword', '');
    }

    /**
     * Returns path to user directory
     * 
     * @return string Path to user directory
     */

    function getPathForUser(){
        $login = $this->getUsername();
        $targetSubdirectory = hash('sha256', $login) & ($this->numberOfSubdirectories - 1);
        $certDir = $this->certificateDirectoryPath . $targetSubdirectory . '/' . $login;
        return $certDir;
    }

   /**
     * Returns path to trusted certificates
     * 
     * @return string Path to trusted certificates
     */

    function getTrustedCertificatesPath(){
        if($this->trustedCertificateDirectoryPath == ""){
            $path = "";
        }
        else{
            // Normalize path
            $path = substr($this->trustedCertificateDirectoryPath, -1) == "/" ? $this->trustedCertificateDirectoryPath : $this->trustedCertificateDirectoryPath . "/";
        }

        return $path;
    }

    /**
     * Returns file name of the user PKCS#12 file
     * 
     * @return string PKCS#12 file name
     */

    function getExistingPKCS12(){
        $certDir = $this->getPathForUser();
        $allPKCS = glob($certDir . "/*.p12", GLOB_BRACE);

        // Finds first PKCS#12 file that matches user identity
        foreach($this->identities as $identity){
            foreach($allPKCS as $file){
                $file_name = $this->folderNameToEmail(pathinfo($file, PATHINFO_FILENAME));

                if($file_name == $identity['email']){
                    return $file_name;
                }
            }
        }
        return "";
    }

    /**
     * Returns file name of the user PKCS#12 file, only if it matches current user identity
     * 
     * @param string $From 
     * 
     * @return string PKCS#12 file name
     */

    function getExistingPKCS12CurrentIdentity($From){
        $certDir = $this->getPathForUser();
        $allPKCS = glob($certDir . "/*.p12", GLOB_BRACE);

        $currentIdentity = $From;

        // Finds first PKCS#12 file that matches user identity
        foreach($allPKCS as $file){
            $fileName = $this->folderNameToEmail(pathinfo($file, PATHINFO_FILENAME));

            if($fileName == $currentIdentity){
                return $fileName;
            }
        }

        // If any subject name matches, parse files to get Alternate Identities
        foreach($allPKCS as $file){
            $fileName = $this->folderNameToEmail(pathinfo($file, PATHINFO_FILENAME));

            $smimeFile = new slime_smimeFile($fileName, $this->slime, "application/x-pkcs12");
            $cert = $smimeFile->getCertificate();
            $certData = openssl_x509_parse($cert);
            $altEmails = $smimeFile->getSubjectAltEmails($certData);

            foreach($altEmails as $email){
                if($email == $currentIdentity){
                    return $fileName;
                }
            }
        }

        return "";
    }

    /**
     * Gets old PKCS#12 that can decrypt old messages
     * 
     * @return array Array of user certificates with their coresponding private keys
     */

    function getOldPKCS(){
        $certDir = $this->getPathForUser() . "/old_pkcs";
        if(!is_readable($certDir)){
            return array();
        }
        $old_certs = array();
        $old_pks = array();
        $oldPKCS = glob($certDir . "/*.p12", GLOB_BRACE);

        // Gets all previous certificates and their coresponding private keys
        foreach($oldPKCS as $file){
            $fileName = $this->folderNameToEmail(preg_replace('/_\d+$/', '', pathinfo($file, PATHINFO_FILENAME)));
            $pkcsFile = new slime_smimeFile($fileName, $this->slime, "application/x-pkcs12", null, true);
            array_push($old_certs, $pkcsFile->getCertificate());
            array_push($old_pks, $pkcsFile->getPK());
        }

        return array_map(function($cert, $pk){
            return ['cert' => $cert, 'pk' => $pk];
        }, $old_certs, $old_pks);
    }

    /**
     * Gets PKCS#12 file that matches a specific user identity
     * 
     * @param string $encodedIdentity User identity encoded by emailToFolderName() method
     * 
     * @return string PKCS#12 file name
     */

    function getPKCSPathForIdentity($encodedIdentity){
        $certDir = $this->getPathForUser();
        $allPKCS = glob($certDir . "/*.p12", GLOB_BRACE);

        foreach ($allPKCS as $file) {
            $fileName = pathinfo($file, PATHINFO_FILENAME);
            if($fileName == $encodedIdentity){
                return $fileName;
            }
        }
        
        return "";
    }

    /**
     * Set user S/MIME options
     * 
     * @param array $preferences Desired user options 
     */

    function updateSettings($preferences){

        // If strict mode is on, disable weak algorithms by default
        if($this->isInStrictMode()){
          $preferences['slime_disable_weak'] = "false";
        }
        $this->slime->rc->user->save_prefs([
          'slime_enable' => $preferences['slime_enable'] == "true" ? 1 : 0,
          'slime_sign_every' => $preferences['slime_sign_every'] == "true" ? 1 : 0,
          'slime_encrypt_every' => $preferences['slime_encrypt_every'] == "true" ? 1 : 0,
          'slime_import_signature' => $preferences['slime_import_signature'] == "true" ? 1 : 0,
          'slime_import_all' => $preferences['slime_import_all'] == "true" ? 1 : 0,
          'slime_disable_weak' => $preferences['slime_disable_weak'] == "true" ? 1 : 0,
          'slime_trust_levels' => $preferences['slime_trust_levels'] == "true" ? 1 : 0,
          'slime_encryption_algorithm' => $preferences['slime_encryption_algorithm'],
        ]); 
    }
  
    /**
     * Get user S/MIME options
     * 
     * @return array Current user options 
     */
  
    function getSettings(){
        $preferences['slime_enable'] = $this->slime->rc->config->get('slime_enable', 1);
        $preferences['slime_sign_every'] = $this->slime->rc->config->get('slime_sign_every', 0);
        $preferences['slime_encrypt_every'] = $this->slime->rc->config->get('slime_encrypt_every', 0);
        $preferences['slime_import_signature'] = $this->slime->rc->config->get('slime_import_signature', 0);
        $preferences['slime_import_all'] = $this->slime->rc->config->get('slime_import_all', 0);
        $preferences['slime_disable_weak'] = $this->slime->rc->config->get('slime_disable_weak', 0);
        $preferences['slime_trust_levels'] = $this->slime->rc->config->get('slime_trust_levels', 0);
        $preferences['slime_encryption_algorithm'] = $this->slime->rc->config->get('slime_encryption_algorithm', "aes_128_cbc");
  
        return $preferences;
    }

    /**
     * Calling directly OpenSSL CLI commands
     * 
     * @param string $command OpenSSL CLI command
     * 
     * @return array Returns stdout. If error occured also stderr
     */

    function cliCommand($command){

        // Read both stderr and stdout in case of an error
        $descriptorspec = [
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];

        $process = proc_open($command, $descriptorspec, $pipes);

        // If command executed correctly
        if(is_resource($process)){
            $out['stdout'] = stream_get_contents($pipes[1]);
            fclose($pipes[1]);

            // Catching errors
            if(!$out['stdout']){
                $out['stderr'] = stream_get_contents($pipes[2]);
                fclose($pipes[2]);
            }
        }
        proc_close($process);
        return $out;
    }

     /**
     * Reorders PCKS#12 files in old_pkcs folder after an old file was removed
     * 
     * @param string $deletedFile File that was deleted
     */

    function reorderOldPKCSFile($deletedFile){
        $certDir = $this->getPathForUser() . "/old_pkcs";
        if(!is_readable($certDir)){
            return;
        }

        // Get file info of deleted file
        $fileName = pathinfo($deletedFile, PATHINFO_FILENAME);
        $extension = pathinfo($deletedFile, PATHINFO_EXTENSION);

        $oldPKCS = glob($certDir . "/*", GLOB_BRACE);
        foreach($oldPKCS as $file){

            // Get file info of current file
            $curFileName = pathinfo($file, PATHINFO_FILENAME);
            $curExtension = pathinfo($file, PATHINFO_EXTENSION);

            // Same identity and higher order number
            if($curFileName == $fileName && (int) $curExtension > (int) $extension){
                rename($certDir . "/" . $file, $certDir . '/' . $curFileName . "." . ((int) $curExtension - 1));
            }
        }
    }

    /**
     * Searches all certificate files and checks if any contains an email in Subject Alternative Name
     * 
     * @param string $recipient E-mail of the recipient 
     * 
     * @return slime_smimeFile On success file with the certificate, on failure null 
     */

    function searchAlternativeNames($recipient){
    $certDir = $this->getPathForUser();
    $allCRTS = glob($certDir . "/*.crt", GLOB_BRACE);

    foreach($allCRTS as $file){
        $fileSlime = new slime_smimeFile($file, $this->slime, "application/x-x509-ca-cert");
        $x509_cert = $fileSlime->getCertificate();
        $cert = openssl_x509_parse($x509_cert);
        $emails = $fileSlime->getSubjectAltEmails($cert);

        foreach($emails as $email){
            if($email == $recipient){
                return $fileSlime;
            }
        }
    }

    return null;
    }

    /**
     * Returns list of the supported AuthEnvelopedData algorithms by plugin 
     * 
     * @return array Supported symmetric AuthEnvelopedData algorithms
     */

     function getAuthEnvelopedAlgList(){
        return array('aes_128_gcm', 'aes_192_gcm', 'aes_256_gcm');
    }

   /**
    * Gets all certificates included in a digital signature  
    *
    * @param string $signature SignedData CMS type in DER
    *
    * @return string Certificates in PEM format
    */

    function getCertificatesFromSignature($signature){

        $signatureFile = new slime_temporaryFile();
        $signatureFile->writeContent($signature);

        // Parses SignedData and prints them in PEM format 
        $command = "openssl pkcs7 -in " . $signatureFile->getFile() . " -inform DER -print_certs";
        $result = $this->cliCommand($command);
        $signatureFile->removeFile();

        // Failed to parse signature
        if($result['stderr']){
            return "";
        }
        $stdout = $result['stdout'];

        // Signature doesn't contain any certificate
        if(preg_match_all('/-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----/s', $stdout, $all_certs) === false){
            return "";
        }
        $allCerts = implode("\r\n", $all_certs[0]);

        return $allCerts;
    }

    /**
    * Maps trust level value to a printable one 
    *
    * @param int $trustLevel Enumerate trust level
    *
    * @return string Printable trust level
    */

    function mapTrustLevel($trustLevel){
        switch($trustLevel){
            case slime_smime::MESSAGE_SIGNATURE_CLASS_1:
                return 1;
            case slime_smime::MESSAGE_SIGNATURE_CLASS_2:
                return 2;
            case slime_smime::MESSAGE_SIGNATURE_CLASS_3:
                return 3;
            default:
                return 0;
        }
    }

    /**
    * Maps symmetric algorithms to standardized form
    *
    * @param array $algorithms Symmetric algoritms from config.inc.php
    *
    * @return array Their standardized forms
    */

    function mapSymAlgs($algorithms){
        $map = ['3des' => 'des-ede3-cbc', 'aes_128_cbc' => 'aes-128-cbc', 'aes_192_cbc' => 'aes-192-cbc',
                'aes_256_cbc' => 'aes-256-cbc', 'rc2_128' => 'rc2-128-cbc', 'aes_128_gcm' => 'aes-128-gcm',
                'aes_192_gcm' => 'aes-192-gcm', 'aes_256_gcm' => 'aes-256-gcm'];

        $mapped = array_map(function($item) use ($map) {
            return $map[$item] ?? $item;
        }, $algorithms);

        return $mapped;
    }
}