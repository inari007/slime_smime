<?php

/**
 * SLIME S/MIME Plugin
 *
 * Copyright (c) 2025 Zdenek Dobes
 * See README file for more details.
 * 
 */

require_once('slime_temporaryFile.php');

/**
 * Cryptography engine for securing/verifying messages via S/MIME
 * Uses OpenSSL
*/

class slime_cryptoEngine {

    private $slime;
    private $currentCert;
    private $currentPK;
    private $extracerts;
    private $oldPKCS;

    /**
     * Saves reference to plugin class
     * 
     * @param slime_smime $slime Plugin class
     * @param string $currentCert User certificate in PEM format
     * @param string $currentPK User private key in PEM format
     * @param string $extracerts User extracerts in PEM format
     */

    function __construct($slime, $currentCert, $currentPK, $extracerts) {
        $this->slime = $slime;
        $this->currentCert = $currentCert;
        $this->currentPK = $currentPK;
        $this->extracerts = $extracerts;
        $this->oldPKCS = array();
    }

    /**
     * Sets older/expired PKCS#12 files for decrypting older messages
     * 
     * @param array $oldPKCS Array of certificates and private keys by getOldPKCS() method
     */

    function setOldPKCS($oldPKCS){
        $this->oldPKCS = $oldPKCS;
    }

    /**
     * Signs content of the message
     * 
     * @param slime_message $message Message object to be signed 
     * @param string $subject Sender of the message
     * 
     * @return string Signed message 
     */

    function signMessage($message, $subject){

        // Moves content info from msg header to body so it could be signed
        $message->saveContentInfo();
        $message->prependContentInfoToContent();
        $message->removeContentInfoFromHeader();

        // Set name of the sender same as certificate subject
        $message->setFrom($subject);

        $inputFile = new slime_temporaryFile();
        $inputFile->writeContent($message->getMessageContent());
        $certsFile = new slime_temporaryFile();
        $certsFile->writeContent($this->extracerts);
        $outputFile = new slime_temporaryFile();

        if(openssl_pkcs7_sign(
          $inputFile->getFile(),
          $outputFile->getFile(),
          $this->currentCert,
          array($this->currentPK, $this->slime->settings->getHashPass()),
          $message->getMessageHeader(),
          PKCS7_DETACHED,
          $certsFile->getFile(),
          ) == false){
            $inputFile->removeFile();
            $certsFile->removeFile();
            $outputFile->removeFile();
            return "";
          }
  
        // Formats rest of the message (only content and its metadata are signed)
        $signed_msg = $outputFile->getContent();

        // Sets either newer Content-Type and protocol value to application/pkcs7-signature or legacy application/x-pkcs7-signature (change in config)
        // Type application/pkcs7-signature is prefered but still not widely supported
        $signed_msg = $message->setPKCS7ContentType($signed_msg, $this->slime->settings->newerPKCS7CType, "sign");

        $signed_msg = $message->removeSecondMimeVersion($signed_msg); 

        $inputFile->removeFile();
        $certsFile->removeFile();
        $outputFile->removeFile();

        return $signed_msg;
    }

    /**
     * Encrypts content of the message
     * 
     * @param slime_message $message Message object to be encrypted
     * @param array $certificates Certificates of all the recipients and the sender
     * 
     * @return string Encrypted message 
     */

    function encryptMessage($message, $certificates){

        // Moves content info from msg header to body so it could be encrypted
        $message->saveContentInfo();
        $message->prependContentInfoToContent();
        $message->removeContentInfoFromHeader();

        $inputFile = new slime_temporaryFile();
        $inputFile->writeContent($message->getMessageContent());
        $outputFile = new slime_temporaryFile();

        // Get prefered symmetric algorithm of the user
        $usedAlgorithm = $this->getSymAlg();
        $isAuthEnveloped = in_array($usedAlgorithm, $this->slime->settings->getAuthEnvelopedAlgList());

        // AuthEnvelopedData Encryption
        if($isAuthEnveloped){

            // Converts into OpenSSL CLI format 
            $usedAlgorithm = str_replace("_", "-", $usedAlgorithm);
            
            $recipientCertsFiles = array();
            $recipientsString = ""; 

            // Create tmp files for all certificates of the recipients
            foreach($certificates as $cert){
                $certificateFile = new slime_temporaryFile();
                $certificateFile->writeContent(trim($cert));
                $recipientsString .= ' -recip ' . (string) $certificateFile->getFile();

                // Ensuring temporary files last
                $recipientCertsFiles[] = $certificateFile;
            }
            $command = 'openssl cms -encrypt -binary -stream -in ' . $inputFile->getFile()
            . ' -out ' . $outputFile->getFile() . ' -' . $usedAlgorithm . $recipientsString;

            // Calls the encrypt command, puts output into $stdout and $stderr
            $out = $this->slime->settings->cliCommand($command);
            $stderr = $out['stderr'];

            foreach($recipientCertsFiles as $tmpFile){
                $tmpFile->removeFile();
            }
            
            if($stderr){
                $inputFile->removeFile();
                $outputFile->removeFile();
                return "";
            }
        }

        // EnvelopedData Encryption
        else{

            if(openssl_pkcs7_encrypt(
                $inputFile->getFile(),
                $outputFile->getFile(),
                $certificates,
                $message->getMessageHeader(),
                0,
                $usedAlgorithm
            ) == false){
                $inputFile->removeFile();
                $outputFile->removeFile();
                return "";
            }
        }

        // Formats message
        $encrypted_msg = $outputFile->getContent();

        // Sets either newer Content-Type application/pkcs7-mime or legacy application/x-pkcs7-mime (change in config)
        // Type application/pkcs7-mime is prefered but still not widely supported
        $encrypted_msg = $message->setPKCS7ContentType($encrypted_msg, $this->slime->settings->newerPKCS7CType, "encrypt");

        $encrypted_msg = $message->removeSecondMimeVersion($encrypted_msg);

        $inputFile->removeFile();
        $outputFile->removeFile();

        return $encrypted_msg;
    }

    /**
     * Mapping symmetric algorithms from options to OpenSSL enumeration
     * 
     * @return int Symmetric algorithm enum
     */

    function getSymAlg(){
        $preferences = $this->slime->settings->getSettings();
        $alg = $preferences['slime_encryption_algorithm'];

        // If algorithm is considered weak, then it was disabled, but was left active
        if(in_array($alg, $this->slime->settings->weakAlgs) && $this->slime->settings->disableWeakAlg){
            
            // Use default
            $alg = 'aes_128_cbc';
        }

        // AuthEnvelopedData keeps string vals for CLI 'openssl cms -encrypt'
        if(in_array($alg, $this->slime->settings->getAuthEnvelopedAlgList())){

            // If algorithm is still active after disabling
            if($this->slime->settings->disableAuthEnveloped){

                // Use default
                $alg = 'aes_128_cbc';
            }
            else{
                return $alg;
            }
        }

        // EnvelopedData requires enum constants for openssl_pkcs7_encrypt()
        switch($alg){

            case 'aes_128_cbc':
                return OPENSSL_CIPHER_AES_128_CBC;

            case 'aes_192_cbc':
                return OPENSSL_CIPHER_AES_192_CBC;

            case 'aes_256_cbc':
                return OPENSSL_CIPHER_AES_256_CBC;

            case 'rc2_128':
                return OPENSSL_CIPHER_RC2_128;

            case '3des':
                return OPENSSL_CIPHER_3DES;

            default:
                return OPENSSL_CIPHER_AES_128_CBC;
            
        }
    }

    /**
     * Attach a certificate (certificate path) as an attachment to a message
     * 
     * @param slime_message $message Message object
     * @param string $certificates Certificate im PEM format
     * 
     * @return Mail_mime Message object to send
     */

    function attachCertificate($message, $certificates){
        $ContentType = $this->slime->settings->newerPKCS7CType ? "application/pkcs7-mime;" : "application/x-pkcs7-mime;";
        $message->message->addAttachment($certificates,
            $ContentType,
            "smime.p7c",
            false,
            "base64",
            'attachment', 
            '', '', '', '', '', '', '', 
            ["Content-Type" => $ContentType . ' smime-type=certs-only; name="smime.p7c"',
            "Content-Disposition" => 'attachment; filename="smime.p7c"',
            "Content-Description" => 'S/MIME distributed certificate']
        );

        return $message->message;
    }

    /**
     * Verifies a signature from received message
     * 
     * @param slime_receive_msg $message Received message object
     * 
     * @return int Operation status
     */

    function verifySignature($message){

        // Gets signed content of the message
        $signedContent = $message->getContent();

        $inputFile = new slime_temporaryFile();
        $inputFile->writeContent($signedContent);

        $certFile = new slime_temporaryFile();
        $certFile->writeContent($this->currentCert);

        $outputFile = new slime_temporaryFile();

        // Gets system certificates
        $trustedCAPath = $this->slime->settings->getTrustedCertificatesPath();
        $trustedCAPath = $trustedCAPath != "" ? ' -CApath ' . $trustedCAPath : "";
        $out = 0;

        // Verify signature
        $command = 'openssl smime -verify -in ' . $inputFile->getFile() . $trustedCAPath
        . ' -certfile ' . $certFile->getFile() . ' -out ' . $outputFile->getFile();
        $result = $this->slime->settings->cliCommand($command);
        $stderr = $result['stderr'];

        if(strpos($stderr, "Verification successful") !== false){
            $out |= slime_smime::MESSAGE_SIGNATURE_VERIFIED;

            $result = $this->checkCertificate($message);

            if(!$result['success']){
                $out |= slime_smime::MESSAGE_SIGNATURE_WRONG_SUBJECT;
            }
            if(isset($result['class'])){
                $out |= $result['class'];
            }
        }
        else{
            $out |= slime_smime::MESSAGE_SIGNATURE_NOT_VERIFIED;
        }

        $inputFile->removeFile();
        $certFile->removeFile();
        $outputFile->removeFile();

        return $out;
    }

    /**
     * Parses user certificate in digital signature and checks its values
     * 
     * @param slime_receive_msg $message Received message object
     * 
     * @return array Results with key 'success' and 'class'
     */

    function checkCertificate($message){

        // If certificate cannot be parsed
        $result['success'] = false;

        // Parse signature in message and get certificates included
        $signature = $message->getSignature();
        $certificates = $this->slime->settings->getCertificatesFromSignature($signature);

        // Get first certificate 
        if(preg_match('/-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----/s', $certificates, $matches)){
            $parsedCert = openssl_x509_parse($matches[0]);

            // Checks
            $result['success'] = $this->verifySender($message, $parsedCert);

            // Check only if required by user
            $preferences = $this->slime->settings->getSettings();
            if($preferences['slime_trust_levels']){
                $result['class'] = $this->getTrustLevel($parsedCert);
            }
            
        }
        return $result;
    }

    /**
     * Gets trust level of the certificate used for a signature
     * 
     * @param array $parsedCert parsed certificate from openssl_x509_parse()
     * 
     * @return int Enumerate class of the certificate
     */

    function getTrustLevel($parsedCert){
        $subject = $parsedCert['subject'];

        // If certificate doesnt contain neither organization name or organizational unit
        if(!isset($subject['OU']) && !isset($subject['O'])){
            return slime_smime::MESSAGE_SIGNATURE_CLASS_1;
        }

        // If certificate doesnt contain neither legal organization name or jurisdiction
        if(!isset($subject['L']) && !isset($subject['ST']) && !isset($subject['C'])){
            return slime_smime::MESSAGE_SIGNATURE_CLASS_2;
        }

        return slime_smime::MESSAGE_SIGNATURE_CLASS_3;;
    }

    /**
     * Checks if sender (From attribute) matches any identity contained in digital certificate
     * 
     * @param slime_receive_msg $message Received message object
     * @param array $parsedCert parsed certificate from openssl_x509_parse()
     * 
     * @return bool True if sender is included in cert
     */

    function verifySender($message, $parsedCert){

        $sender = $message->getSender();
        $xsender = $message->getXSender();

        $possibleEmails = $parsedCert['subject'];

        // If Alternative Names included, search among them as well
        if($parsedCert['extensions']['subjectAltName']){
            preg_match_all('/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/', $parsedCert['extensions']['subjectAltName'], $matches);
            $possibleEmails = array_merge($possibleEmails, $matches[0]);
        }

        // Match identities in certificate with the sender
        foreach($possibleEmails as $email){
            if($email == $sender || $email == $xsender){
                return true;
            }
        }
        return false;
    }

    /**
     * Checks if there is an attached certificate in the message
     * 
     * @param rcube_message_part $attachment Current MIME message part
     * @param string $fileType File extension of the attachment or certificate   
     * 
     * @return bool True if a certificate is present
     */

    function isAttachmentCertificate($attachment, $fileType){
        $mimeType = $fileType == ".p7c" ? "pkcs7-mime" : "pkcs7-signature";
        
        // Narrowing to S/MIME (and few others)
        if($attachment->mimetype != ("application/" . $mimeType) && $attachment->mimetype != ("application/x-" . $mimeType)){
            return false;
        }

        // Standard uses .p7c files for distributing certificates
        if(strpos(substr($attachment->filename, -4), $fileType) === false){
            return false;
        }

        return true;
    }

    /**
     * Decrypts message content
     * 
     * @param slime_receive_msg $message Received message object
     * @param bool $isAuth True if message contains authEnvelopedData, false if EnvelopedData
     * 
     * @return array Data about operation status and decrypted content 
     */

    function decryptMessage($message, $isAuth){

        $inputFile = new slime_temporaryFile();
        $inputFile->writeContent($message->getContent());

        $pkFile = new slime_temporaryFile();
        $certFile = new slime_temporaryFile();
        $outputFile = new slime_temporaryFile();

        // Puts current private key first
        array_unshift($this->oldPKCS, ['cert' => $this->currentCert, 'pk' => $this->currentPK]);

        // Tries to decrypt the message with every owned private key (older messages)
        foreach($this->oldPKCS as $pkcs){
            $certFile->writeContent($pkcs['cert']);
            $pkFile->writeContent($pkcs['pk']);

            // AuthEnvelopedData Decryption
            if($isAuth){
                $command = 'openssl cms -decrypt -binary -in ' . $inputFile->getFile() . ' -out ' . 
                $outputFile->getFile() . ' -inkey ' . $pkFile->getFile();
                $out = $this->slime->settings->cliCommand($command);
                $stderr = $out['stderr'];

                $success = $stderr == "";
            }

            // EnvelopedData Decryption
            else{
                $success = openssl_pkcs7_decrypt(
                    $inputFile->getFile(), 
                    $outputFile->getFile(), 
                    $certFile->getContent(), 
                    $pkFile->getContent()
                );
            }

            if($success){

                $decryptedContent = $outputFile->getContent();

                // Rendering decrypted HTML content is forbidded due to EFAIL
                if($message->isHTMLMessage($decryptedContent)){
                    $messageInfo['status'] = slime_smime::MESSAGE_DECRYPTION_HTML;
                    break;
                }

                $messageInfo['status'] = slime_smime::MESSAGE_DECRYPTION_SUCCESSFULLY;
                $preferences = $this->slime->settings->getSettings();

                // If user doesn't want to show info about alg strength
                if(!$preferences['slime_disable_weak']){

                    switch($this->isAlgSafe($message)){

                        // If used algorithm is considered weak
                        case slime_smime::MESSAGE_DECRYPTION_WEAK:
                            $messageInfo['status'] |= slime_smime::MESSAGE_DECRYPTION_WEAK;
                            break;

                        case slime_smime::FUNCTION_FAILED:
                            break;

                        case slime_smime::FUNCTION_SUCCESS:
                            break;

                        default:
                            break;

                    }
                }
                $messageInfo['content'] = $decryptedContent;
                break;
            }
        }

        // If message was not decrypted
        if(!isset($messageInfo['status'])){
            $messageInfo['status'] = slime_smime::MESSAGE_DECRYPTION_FAILED;
        }

        // If decryption failed
        if($messageInfo['status'] == slime_smime::MESSAGE_DECRYPTION_FAILED || $messageInfo['status'] == slime_smime::MESSAGE_DECRYPTION_HTML){
            
            // Returns enrypted content in PEM format
            $messageInfo['content'] = $message->getEncryptedContent();
        }

        $inputFile->removeFile();
        $outputFile->removeFile();
        $certFile->removeFile();
        $pkFile->removeFile();

        return $messageInfo;
    }

    /**
     * Checks if used symmetric algorithm is considered safe
     * 
     * @param slime_receive_msg $message Received message object
     * 
     * @return int Operation status
     */

    function isAlgSafe($message){
        $content = $message->getEncryptedContent();
        $inputFile = new slime_temporaryFile();
        $inputFile->writeContent($content);

        // Decode and parse encrypted content
        $output = shell_exec('openssl asn1parse -in ' . $inputFile->getFile() .' -inform PEM');
        if($output == ""){
            $out = slime_smime::FUNCTION_FAILED;
        }

        else{

            // Checks if message was encrypted by any algorithm that is considered weak
            foreach($this->slime->settings->weakAlgs as $weakAlg){
                if(strpos($output, $weakAlg)){
                    $out = slime_smime::FUNCTION_FAILED;
                }
                else{
                    $out = slime_smime::FUNCTION_SUCCESS;
                }
            }
        }
        $inputFile->removeFile();
        return $out;
    }
}