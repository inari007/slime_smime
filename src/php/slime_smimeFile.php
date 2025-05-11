<?php

/**
 * SLIME S/MIME Plugin
 *
 * Copyright (c) 2025 Zdenek Dobes
 * See README file for more details.
 * 
 */

/**
 * This class represents files used by the plugin (mostly .crt and .p12) 
*/

class slime_smimeFile{

    private $filePath;
    private $content;
    private $slime;
    private $type;
    private $isAttachment;
    private $isOld;

    /**
     * Object constructor
     * 
     * @param string $file Either path to file or recipients E-mail
     * @param slime_smime $slime plugin class
     * @param string $type Content Type of the file
     * @param string $newContent When was not created yet and doesn't have a temporary file
     * @param bool $isOld True if this certificate expires later than current one
     * @param int $suffix If other then -1 then it is located in old_pkcs folder
     */

    function __construct($file, $slime, $mimeType, $newContent = null, $isOld = false, $suffix = -1){
        
        // If absolute path to file is not provided (only owners E-mail), get one
        if(basename($file) == $file){

            // If its not old PKCS#12 => set file extension type
            if(!$isOld){
                $suffix = $mimeType == "application/x-pkcs12" ? ".p12" : ".crt";
            }
            else{
                $suffix = "." . $suffix;
            }
            $isOldString = $isOld ? "old_pkcs/" : "";
            $file = $slime->settings->getPathForUser() . "/" . $isOldString . $slime->settings->emailToFolderName($file) . $suffix;
        }
        $this->filePath = $file;

        // When temporary file doesn't exist (only attachments)
        if($newContent != null){
            $this->content = $newContent;
            $this->isAttachment = true;
        }
        else{
            $this->content = file_get_contents($file);
            $this->isAttachment = false;
        }
        $this->slime = $slime;
        $this->type = $mimeType;
        $this->isOld = $isOld;
    }

    /**
     * Creates a new file or overwrites an existing file 
     * 
     * @param string $password Password used to unlock PKCS#12 file 
     * 
     * @return array Information about the outcome  
     */
    
    function createFile($password = ""){

        $out = array();
        // .crt, .cer, .pem, text streams and PKCS#7 files (all in PEM format)
        if($this->type == "application/x-x509-ca-cert" || $this->type == "application/x-x509-user-cert" || $this->type == "application/x-pem-file" ||
           $this->type == "application/octet-stream" || $this->type == "application/x-pkcs7-certificates"){
          
            // PKCS#7 can include multiple certificates in 1 PEM
            if(preg_match_all('/-----BEGIN PKCS7-----(.*?)-----END PKCS7-----/s', $this->content, $matches)){
                
                $pkcs7File = $matches[0][0];
                if(!openssl_pkcs7_read($pkcs7File, $allCerts)){
                    $result['status'] = slime_smime::FILE_INVALID_PKCS7;
                    return $result;
                }
            }

            // Find all certificates in the file
            else if(!preg_match_all('/-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----/s', $this->content, $allCerts)){
                $result['status'] = slime_smime::FILE_WRONG_PEM_FORMAT;
                return $result;
            }

            $extracerts = array();
            foreach ($allCerts[0] as $index => $singleCert) {

                // First certificate is users
                if($index == 0){
                    $x509Cert = $singleCert;
                    $cert = openssl_x509_parse($x509Cert);

                    // Certificate format is not ok
                    if($cert == false){
                        $result['status'] = slime_smime::FILE_INVALID_CERTIFICATE;
                        return $result;
                    }
                }

                // Intermediate certificates (certificate path)
                else{

                    $extracert = openssl_x509_parse($singleCert);

                    // Certificate format is not ok
                    if($extracert != false){

                        // Do not include root certificates
                        if(trim($extracert['subject']['CN']) != trim($extracert['issuer']['CN'])){
                            array_push($extracerts, $singleCert);
                        }
                        
                    }
                }

                // Doesn't have PK in it 
                $isUserOwnerOfPK = false;
                $purpose = X509_PURPOSE_SMIME_ENCRYPT;
            }
        }

        // .pkcs, .pfx (PKCS#12 files)
        else if($this->type == "application/x-pkcs12"){

            // If not successfully unlocked with the password 
            if(!openssl_pkcs12_read($this->content, $out, $password)){
                $result['status'] = slime_smime::FILE_IS_PROTECTED_BY_PASSWORD;
                return $result;
            }

            $x509Cert = $out['cert'];
            $cert = openssl_x509_parse($x509Cert);

            // Certificate format is not ok
            if($cert == false){
                $result['status'] = slime_smime::FILE_INVALID_CERTIFICATE;
                return $result;
            }

            $extracerts = array();
            foreach($out['extracerts'] as $extracert){
                $parsedExtra = openssl_x509_parse($extracert);

                // Certificate format is not ok
                if($parsedExtra != false){

                    // Do not include root certificates
                    if(trim($parsedExtra['subject']['CN']) != trim($parsedExtra['issuer']['CN'])){
                        array_push($extracerts, $extracert);
                    }

                }
            }
            
            // If cert subject name matches one of the identities and PK is present
            $isUserOwnerOfPK = $this->isUserOwner($cert) && isset($out['pkey']);
            $purpose = X509_PURPOSE_ANY;
        }

        // Other files
        else{
            $result['status'] = slime_smime::FILE_TYPE_NOT_SUPPORTED;
            return $result;
        }
        
        // Gets path to the user directory
        $certPath = $this->slime->settings->getPathForUser();
        
        // If directory wasn't created yet, create one
        if(!is_readable($certPath)){
            mkdir($certPath, 0777, true);
        }

        // Format properly certificate path
        $extracertsString = $this->type == "application/x-pkcs12" ? implode("\r\n", array_reverse($extracerts)) : implode("\r\n", $extracerts);
        $extracertsString = preg_replace("/\r\n|\r|\n/", "\r\n", $extracertsString);

        // If certificate can't be used for either signing or encrypting, or is just invalid
        $certErrors = $this->isCertificateValid($x509Cert, $extracertsString, $purpose);
        if(!empty($certErrors)){
            $result['error'] = $certErrors[0];

            // If public certificates (they need to be valid)
            if($this->type != "application/x-pkcs12"){
                $result['status'] = slime_smime::FILE_INVALID_CERTIFICATE;
                return $result;
            }
        }

        // Get e-mail of the owner
        $rawUsername = $this->getEmailFromCert($cert);

        // Certificates without e-mail are pointless to keep
        if(!$rawUsername){
            $result['status'] = slime_smime::FILE_EMAIL_NOT_IN_CERT;
            return $result;
        }

        // Code e-mail into format that is file system safe
        $codedUsername = $this->slime->settings->emailToFolderName($rawUsername);

        // Saves as pkcs#12
        if($isUserOwnerOfPK){
            
            // Path to old certificates
            $oldPKCSPath = $certPath . '/old_pkcs';
            if (!file_exists($oldPKCSPath)) {
                mkdir($oldPKCSPath, 0777, true);
            }

            // If user does not have PKCS#12 to this identity yet
            $currentPKCS12 = $this->slime->settings->getPKCSPathForIdentity($codedUsername);
            if($currentPKCS12 == ""){
                $file = $certPath . '/' . $codedUsername . '.p12';
            }

            // If user already has active PKCS#12
            else{

                // Gets its content and parse it
                $curPKCSPath = $certPath . '/' . $currentPKCS12 . '.p12';
                $content = file_get_contents($curPKCSPath);
                openssl_pkcs12_read($content, $outPKCS, $this->slime->settings->getHashPass());
                $curCert = openssl_x509_parse($outPKCS['cert']);

                // Checks if current one is not the same as the one importing
                if($cert['serialNumber'] == $curCert['serialNumber'] && $cert['issuer']['CN'] == $curCert['issuer']['CN']){
                    $file = $certPath . '/' . $codedUsername . '.p12';
                }
    
                // If importing newer certificate, move current to old
                else if($cert['validTo_time_t'] >= $curCert['validTo_time_t']){
                    $newFileName = $this->generateOldPKCSName($cert, $codedUsername);
                    $file = $certPath . '/' . $codedUsername . '.p12';
                    rename($file, $oldPKCSPath . '/' . $newFileName);
                }
    
                // If importing older, create it directly as an old
                else{
                    $newFileName = $this->generateOldPKCSName($cert, $codedUsername);
                    $file = $oldPKCSPath . '/' . $newFileName;
                }
            }
            
            // Creates a new file
            openssl_pkcs12_export_to_file($x509Cert, $file, $out['pkey'], $this->slime->settings->getHashPass(), array('extracerts' => $extracerts));
        }

        // Import an attachment as .crt file
        else if($this->isAttachment){
            array_unshift($extracerts, $x509Cert);
            $allCerts = implode("\r\n\r\n", $extracerts);
            file_put_contents($this->filePath, $allCerts);
        }
        
        // Saves as .crt
        else{
            $file = $certPath . '/' . $codedUsername . '.crt';
            array_unshift($extracerts, $x509Cert);
            $allCerts = implode("\r\n\r\n", $extracerts);
            file_put_contents($file, $allCerts);
        }

        $result['status'] = slime_smime::FILE_SUCCESS;
        return $result;
    }

    /**
     * Generate a new name for the PKCS#12 file in the old_pkcs folder
     * 
     * @param array $newCertParsed Imported crtificate parsed by openssl_x509_parse() function
     * @param string $codedUsername E-mail coded by emailToFolderName() method
     * 
     * @return string Name of the new file
     */

    function generateOldPKCSName($newCertParsed, $codedUsername){
        $oldPKCS = $this->slime->settings->getOldPKCS();

        $index = 0;
        foreach($oldPKCS as $pkcs){

            // If old certificate was manually modified and becomes invalid, ignore it
            if(openssl_pkcs12_read($pkcs['cert'], $out, $this->slime->settings->getHashPass())){
                $oldCert = openssl_x509_parse($out['cert']);
                
                // If its the same certificate => replace it
                if($oldCert['serialNumber'] == $newCertParsed['serialNumber'] && $oldCert['issuer']['CN'] == $newCertParsed['issuer']['CN']){
                    break;
                }
            }
            $index++;
        }
        return $codedUsername . "." . $index;
    }

    /**
     * Returns all emails contained in Subject Alternative Name attribute of X.509 extension
     * 
     * @param array $cert Imported certificate by openssl_x509_parse() function
     * 
     * @return array E-mails present in Subject Alternative Name
     */

    function getSubjectAltEmails($cert){
        if($cert['extensions']['subjectAltName']){
            preg_match_all('/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/', $cert['extensions']['subjectAltName'], $matches);
            return $matches[0];
        }
        return [];
    }

    /**
     * Returns first value from certificate subject that matches e-mail format 
     * 
     * @param array $cert Imported certificate by openssl_x509_parse() function
     * 
     * @return string|bool E-mail or false if any e-mail address is present
     */

    function getEmailFromCert($cert){
        $possibleEmails = array_merge($cert['subject'], $this->getSubjectAltEmails($cert));
        foreach($possibleEmails as $email){
            if(filter_var($email, FILTER_VALIDATE_EMAIL)){
                return $email;
            }
        }
        return false;
    }

    /**
     * Checks if logged user is an owner of the certificate 
     * 
     * @param array $cert Imported certificate by openssl_x509_parse() function
     * 
     * @return bool True if user is an owner
     */

    function isUserOwner($cert){
        $user_identities = $this->slime->settings->identities;
        $possibleEmails = array_merge($cert['subject'], $this->getSubjectAltEmails($cert));

        foreach($possibleEmails as $email){
            foreach($user_identities as $identity){
                if($identity['email'] == $email){
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Checks expiration date and purpose of the certificate
     * 
     * @param string $cert Imported certificate in PEM format
     * @param string $extracerts Certificate path in PEM format
     * @param int $purpose Enumerate value used by openssl_x509_checkpurpose() function
     * 
     * @return array It holds error strings in case of a failure
     */

    function isCertificateValid($cert, $extracerts, $purpose){

        $certFile = new slime_temporaryFile();
        $certFile->writeContent($cert);

        $extraCertFiles = array();
        $extraCertString = "";

        // Certificate path provided
        if($extracerts != ""){
            $extracertsArray = explode("\r\n\r\n", $extracerts);

            // Gets certificates of all Intermediate and Root CA
            foreach($extracertsArray as $extracert){
                $extracertFile = new slime_temporaryFile();
                $extracertFile->writeContent(trim($extracert));
                $extraCertString .= (string) $extracertFile->getFile() . " ";

                // Ensuring temporary files last
                $extraCertFiles[] = $extracertFile;
            }
        }

        $trustedCAPath = $this->slime->settings->getTrustedCertificatesPath();
        $trustedCAPath = $trustedCAPath != "" ? ' -CApath ' . $trustedCAPath : "";

        switch($purpose){
            case X509_PURPOSE_SMIME_SIGN:
                $purposeString = "-purpose smimesign";
                break;

            case X509_PURPOSE_SMIME_ENCRYPT:
                $purposeString = "-purpose smimeencrypt";
                break;

            case X509_PURPOSE_SMIME_SIGN | X509_PURPOSE_SMIME_ENCRYPT:
                $purposeString = "-purpose smimesign -purpose smimeencrypt";
                break;

            default:
                $purposeString = "-purpose any";
                break;
        }

        // Verifies certificate path
        $command = 'openssl verify' . $trustedCAPath . ' ' . $purposeString . 
        ' -untrusted ' . $extraCertString . $certFile->getFile();
        $outputErrors = array();

        // Calls the verify command, puts output into $stdout and $stderr
        $out = $this->slime->settings->cliCommand($command);
        $stdout = $out['stdout'];
        $stderr = $out['stderr'];  

        // Catching errors
        if(!$stdout){

            // Normalizes EOL and separate lines
            $lines = preg_split('/\r\n|\r|\n/', $stderr);

            $errors = array();
            $certLevels = 0;

            // Get errors
            foreach($lines as $line){

                // If its error line
                if(strpos(strtolower($line), 'error') === 0){
                    array_push($errors, ["certLvl" => $certLevels, "isError" => True, "content" => $line]);
                }

                // If certificate path not provided or is untrusted
                else if(strpos(strtolower($line), 'could not find untrusted certificates') === 0){
                    array_push($outputErrors, $this->slime->gettext('verify_incomplete_certificate_path'));
                }

                // If its CA or imported certificate line
                else{
                    array_push($errors, ["certLvl" => $certLevels, "isError" => False, "content" => $line]);
                    $certLevels++;
                }
            }

            // Format errors for printings
            foreach($errors as $error){
                if($error['isError']){

                    // If single certificate is present
                    if($error['certLvl'] == 1 && $certLevels == 1){
                        $issuer = $this->slime->gettext('verify_certificate');
                    }

                    // If error caused Intermediate CA
                    else if($error['certLvl'] < $certLevels){
                        $issuer = $this->slime->gettext('verify_intermediate');
                    }

                    else{
                        $issuer = $this->slime->gettext('verify_certificate');
                    }

                    // Get error text 
                    $errorContent = trim(substr($error['content'], strrpos($error['content'], ':') + 1));
                    $errorString = $issuer . ": '" . $errorContent . "'";

                    array_push($outputErrors, $errorString);
                }
            }
            if(empty($outputErrors)){
                array_push($outputErrors, $this->slime->gettext('verify_undefined_error'));
            }
        }

        $certFile->removeFile();
        if($extracerts != ""){
            foreach($extraCertFiles as $tmpFile){
                $tmpFile->removeFile();
            }
        }
        return $outputErrors;
    }

    /**
     * Gets and formats certificate information to show to user
     * 
     * @return array Certificate data
     */

    function getCertificateData(){

        // My certificates (PKCS#12)
        if($this->type == "application/x-pkcs12"){
            $out = array();
            openssl_pkcs12_read($this->content, $out, $this->slime->settings->getHashPass());
            $x509_cert = $out['cert'];
        }

        // Public certificates (.crt)
        else{
            preg_match_all('/-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----/s', $this->content, $all_certs);
            $x509_cert = $all_certs[0][0];
        }

        // Gets certificate data
        $cert = openssl_x509_parse($x509_cert);
        $public_key = openssl_pkey_get_public($x509_cert);
        $key_details = openssl_pkey_get_details($public_key);

        // Gets used language so date can be formated properly
        $currentLanguage = $this->slime->rc->config->get('language');

        $certificate = array("name" => $cert['subject']['CN'], 
        "serialNumber" => $cert['serialNumber'], 
        "validFrom" => $this->getCertificateTime($cert['validFrom_time_t'], $currentLanguage), 
        "validTo" => $this->getCertificateTime($cert['validTo_time_t'], $currentLanguage), 
        "issuer" => $cert['issuer']['CN'], 
        "usage" => isset($cert['extensions']['keyUsage']) ? $this->getKeyUsage($cert['extensions']['keyUsage']) : $this->slime->gettext('no_information'),
        "algorithmsUsed" => $cert['signatureTypeLN'],
        "keyLength" => $key_details['bits'],
        "keyType" => $this->type == "application/x-pkcs12" ? $this->slime->gettext('key_pair') : $this->slime->gettext('public_key')
    );

        return $certificate;
    }

    /**
     * Formats time based on user language
     * 
     * @param int $timestamp Timestamp value in time_t
     * @param string $currentLanguage Language set by user
     * 
     * @return string Formated time
     */

    function getCertificateTime($timestamp, $currentLanguage){

        $previousLocale = setlocale(LC_TIME, 0);
        $locale = $currentLanguage . '.UTF-8';

        if(setlocale(LC_TIME, $locale) === false){
            if($currentLanguage == "cs_CZ"){
                $czech_months = [
                    1 => 'Leden', 2 => 'Únor', 3 => 'Březen', 4 => 'Duben',
                    5 => 'Květen', 6 => 'Červen', 7 => 'Červenec', 8 => 'Srpen',
                    9 => 'Září', 10 => 'Říjen', 11 => 'Listopad', 12 => 'Prosinec'
                ];
    
                $day = date('d', $timestamp);
                $month = $czech_months[date('n', $timestamp)];
                $year = date('Y', $timestamp);
    
                $time = $day .'. ' . $month . " " . $year;
            }
            else{
                $time = strftime('%B %d, %Y', $timestamp);
            }
        }
        else{
            $time = strftime('%B %d, %Y', $timestamp);
            setlocale(LC_TIME, $previousLocale);
        }

        return $time;
    }

    /**
     * Formats key usage 
     * 
     * @param string $keyUsage Key usage in X509 certs
     * 
     * @return string Formated key usage
     */

    function getKeyUsage($keyUsage){
        $out = $keyUsage;

        $out = str_replace("Digital Signature", $this->slime->gettext('usage_sign'), $out);
        $out = str_replace("Key Encipherment", $this->slime->gettext('usage_encrypt'), $out);

        return $out;
    }

     /**
     * Removes the file
     * 
     * @return bool True if deletion was succesful 
     */

    function deleteFile(){
        $out = unlink($this->filePath);

        // Reorders file names in old_pkcs directory 
        if($this->isOld){
            $this->slime->settings->reorderOldPKCSFile(basename($this->filePath));
        }

        return $out;
    }

    /**
     * Gets certificate path from PKCS#12 file
     * 
     * @return string Certificate in PEM format
     */

    function PKCSToCertPath(){
        $out = array();
        openssl_pkcs12_read($this->content, $out, $this->slime->settings->getHashPass());

        return $out['cert'] . "\r\n" . implode("\r\n\r\n", $out['extracerts']);
    }

     /**
     * Creates PKCS#12 file
     * 
     * @param string $password Password that unlocks PKCS#12 file
     * @param string $email Email of the owner of the PKCS#12 file
     * 
     * @return string PKCS#12 file
     */

    function PKCSSectureCert($password, $email){
        $pkcs_file = array();
        openssl_pkcs12_read($this->content, $pkcs_file, $this->slime->settings->getHashPass());

        $x509_cert = $pkcs_file['cert'];
        $pkey = $pkcs_file['pkey'];
        $extracerts = $pkcs_file['extracerts'];

        openssl_pkcs12_export($x509_cert, $out, $pkey, $password, array('extracerts' => $extracerts, 'friendly_name' => $email));

        return $out;
    }

    /**
     * Get certificate from the file
     * 
     * @return string Certificate in PEM format
     */

    function getCertificate(){
        if($this->type == "application/x-pkcs12"){
            $out = array();
            if(openssl_pkcs12_read($this->content, $out, $this->slime->settings->getHashPass()) === false){
                return "";
            }
            $x509_cert = $out['cert'];
        }
        else{
            if(preg_match_all('/-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----/s', $this->content, $all_certs) === false){
                return "";
            }
            $x509_cert = $all_certs[0][0];
        }

        return $x509_cert;
    }



    /**
     * Get private key from the file
     * 
     * @return string Private key in PEM format
     */

    function getPK(){
        if($this->type == "application/x-pkcs12"){
            $out = array();
            openssl_pkcs12_read($this->content, $out, $this->slime->settings->getHashPass());
            $pkey = $out['pkey'];
            return $pkey;
        }
        else{
            return "";
        }
    }

    /**
     * Get extracerts from the file
     * 
     * @return string Extracerts in PEM format
     */

    function getExtraCerts(){
        if($this->type == "application/x-pkcs12"){
            $out = array();
            openssl_pkcs12_read($this->content, $out, $this->slime->settings->getHashPass());
            $extracerts = $out['extracerts'];
            return implode("\r\n", $extracerts);
        }
        else{
            if(preg_match_all('/-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----/s', $this->content, $all_certs) === false){
                return "";
            }
            $extracerts = implode("\r\n", $all_certs[0]);
            return $extracerts;
        }
    }
}

