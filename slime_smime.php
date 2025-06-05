<?php

/**
 * SLIME S/MIME Plugin
 *
 * Plugin to provide security via S/MIME standard.
 *
 * @version 1.0
 * @author Zdenek Dobes
 * @license MIT
 * Copyright (c) 2025 Zdenek Dobes
 * See README file for more details.
 * 
 */
    
  require_once('src/php/slime_message.php');
  require_once('src/php/slime_cryptoEngine.php');
  require_once('src/php/slime_ui.php');
  require_once('src/php/slime_settings.php');
  require_once('src/php/slime_smimeFile.php');
  require_once('src/php/slime_receive_msg.php');

/**
 * This class initializes the plugin and handles hooks and actions.
 * Hook details - https://github.com/roundcube/roundcubemail/wiki/Plugin-Hooks
 */

  class slime_smime extends rcube_plugin{

    public $task = 'login|mail|settings';
    public $rc;
    public $ui;
    public $settings;
    public $db;

    public $tmpUsername;
    public $tmpPassword;
    public $certs = array();
    public $statusMsg = array();

    const FILE_EMAIL_NOT_IN_CERT = 7;
    const FILE_INVALID_PKCS7 = 6;
    const FILE_WRONG_PEM_FORMAT = 5;
    const FILE_TYPE_NOT_SUPPORTED = 4;
    const FILE_INVALID_CERTIFICATE = 3;
    const FILE_IS_MISSING_A_PASSWORD = 2;
    const FILE_IS_PROTECTED_BY_PASSWORD = 1;
    const FILE_SUCCESS = 0;

    const MESSAGE_ATTACHED_CERTIFICATE = 8;
    const MESSAGE_ENCRYPTED_AUTH = 4;
    const MESSAGE_ENCRYPTED = 2;
    const MESSAGE_SIGNED = 1;

    const MESSAGE_SIGNATURE_CLASS_3 = 1024;
    const MESSAGE_SIGNATURE_CLASS_2 = 512;
    const MESSAGE_SIGNATURE_CLASS_1 = 256;
    const MESSAGE_DECRYPTION_HTML = 128;
    const MESSAGE_DECRYPTION_WEAK = 64;
    const MESSAGE_NO_PK_ENCRYPTED = 32;
    const MESSAGE_DECRYPTION_FAILED = 16;
    const MESSAGE_DECRYPTION_SUCCESSFULLY = 8;
    const MESSAGE_SIGNATURE_WRONG_SUBJECT = 4;
    const MESSAGE_SIGNATURE_NOT_VERIFIED = 2;
    const MESSAGE_SIGNATURE_VERIFIED = 1;

    const FUNCTION_SUCCESS = 0;
    const FUNCTION_FAILED = -1;

    function init(){
      $this->rc = rcube::get_instance();

      /*
      $file = fopen("C:/wamp/www/roundcubemail-1.6.9/plugins/slime_smime/tmp/ee.txt", 'w');
      fwrite($file, print_r($this->message->headers->structure, true));
      fclose($file);
      */

      $this->load_config('config.inc.php');
      $this->settings = new slime_settings($this);
      
      // Stops loading plugin if set in config
      if(!$this->settings->isPluginEnabled()){
        return;
      }

      // Creates subdirectories for storing certificates
      $this->settings->initSettings();

      // Adds localization (used by gettext() methods)
      $this->add_texts('localization/', true);

      // Adds UI elements to client
      $this->ui = new slime_ui($this);
      $this->ui->createUIelements();

      if($this->rc->task == 'mail'){
        $this->add_hook('message_before_send', array($this, 'processMessageToSend'));
        $this->add_hook('message_load', array($this, 'processReceivedMessage'));
        $this->add_hook('message_body_prefix', array($this, 'showMessageStatusText'));
        $this->add_hook('template_object_messagebody', array($this, 'handleCertificateAttachment'));
        $this->register_action('plugin.slime.import_certificate', array($this, 'importCert'));
      }
      else if($this->rc->task == 'login'){
        $this->add_hook('authenticate', array($this, 'getPasswordHash'));
        $this->add_hook('login_after', array($this, 'saveAuthValues'));
      } 
    }

    /**
     * Handler for message_before_send hook
     * Distributes certificate/encrypts/signs outcoming message
     * 
     * @param array $args Original parameters
     * 
     * @return array Modified parameters
     */
  
    function processMessageToSend($args){

      $purpose = $this->ui->getMessagePurposeUI();

      // If any operations were not selected or plugin is turned off
      if(!$purpose['enable']){
        return $args;
      }

      // When sending attached certificates, disable encryption and signing
      // (Signature already contains certificates, encryption not supported)
      if($purpose['attach']){
        $purpose['sign'] = false;
        $purpose['encrypt'] = false;
      }

      $message = new slime_message($args['message']);

      // Don't encrypt HTML messages (EFAIL vulnerability)
      if($message->isMsgHTML && $purpose['encrypt']){
        return $this->generateErrorWhenSending($args, 'encrypt_error_efail');
      }

      // Get senders PKCS#12 file
      $pkcsPath = $this->settings->getExistingPKCS12CurrentIdentity($args['from']);

      // If user do not have a PKCS#12 file
      if($pkcsPath == ""){
        if($purpose['sign']){
          return $this->generateErrorWhenSending($args, 'sign_error_pkcs');
        }

        // User technically can distribute his certificate without a private key
        // but won't be able to decrypt content anyway
        else if($purpose['attach']){
          return $this->generateErrorWhenSending($args, 'distribute_error_pkcs');
        }
      }

      $mimeType = $pkcsPath == "" ? "application/x-x509-ca-cert" : "application/x-pkcs12";
      $smimeFile = new slime_smimeFile($pkcsPath, $this, $mimeType);
      
      // Get a private Key and certificate from PKCS#12 file
      $cert = $smimeFile->getCertificate();
      if($cert == ""){
        return $this->generateErrorWhenSending($args, 'send_error_cert_missing');
      }
      $pk = $smimeFile->getPK();
      $extracerts = $smimeFile->getExtraCerts();

      $engine = new slime_cryptoEngine($this, $cert, $pk, $extracerts);

      // Verifies used certificate
      $verificationPurpose = 0;
      $verificationPurpose |= $purpose['sign'] ? X509_PURPOSE_SMIME_SIGN : 0;
      $verificationPurpose |= $purpose['encrypt'] | $purpose['attach'] ? X509_PURPOSE_SMIME_ENCRYPT : 0;
      $errors = $smimeFile->isCertificateValid($cert, $extracerts, $verificationPurpose);
      if(!empty($errors)){
        return $this->generateErrorWhenSending($args, 'send_error_cert_invalid');
      }

      // Ensuring message is normalized
      $message->setMessageContent($message->normalizeMessage($message->getMessageContent()));

      // Signing message
      if($purpose['sign']){

        if($pk == ""){
          return $this->generateErrorWhenSending($args, 'sign_error_pk');
        }

        // Adds a signature
        $newMessage = $engine->signMessage($message, $args['from']);
        if($newMessage == ""){
          return $this->generateErrorWhenSending($args, 'sign_error');
        }

        // Removes OpenSSL generated comment from the message and sets its content
        $content = $message->removeAdditionalText($newMessage);
        $message->setMessage($content);
      }

      // Encrypting message
      if($purpose['encrypt']){

        // Include sender as a recipient (so he can read the sent message)
        $certs = array($cert);
        $recipients = $message->getAllRecipients();

        // Gets certificates of all the recipients
        foreach($recipients as $recipient){
          $notInclude = false;

          // Checks if recipient is not a sender (otherwise redundant certificates)
          foreach($this->settings->identities as $identity){
            if($identity == $recipient){
              $notInclude = true;
            }
          }
          if($notInclude){
            continue;
          }

          $smimeFileRec = new slime_smimeFile($recipient, $this, "application/x-x509-ca-cert");
          $certRec = $smimeFileRec->getCertificate();

          // If any certificate of the recipient doesn't exist
          if($certRec == ""){
            
            // Tries to search for the certificate as an Subject Alternative Name in X.509 extension
            $smimeFileRec = $this->settings->searchAlternativeNames($recipient);
            if($smimeFileRec == null){
              return $this->generateErrorWhenSending($args, 'encrypt_error_cert_rec', ['recipient' => $recipient]);
            }
            $certRec = $smimeFileRec->getCertificate();
          }

          // Checks if recipient has a valid certificate
          $extracertsRec = $smimeFileRec->getExtraCerts();
          $errors = $smimeFileRec->isCertificateValid($certRec, $extracertsRec, X509_PURPOSE_SMIME_ENCRYPT);
          if(!empty($errors)){
            return $this->generateErrorWhenSending($args, 'encrypt_error_recipient_cert_invalid', ['recipient' => $recipient]);
          }

          // Include certificate into encryption
          array_push($certs, $certRec);
        }

        // Generate an encrypted message
        $newMessage = $engine->encryptMessage($message, $certs);
        if($newMessage == ""){
          return $this->generateErrorWhenSending($args, 'encrypt_error');
        }

        // Sets content of the message
        $message->setMessage($newMessage);
      }

      // Distributing certificates (Sends certificate path)
      if($purpose['attach']){

        // Order and format certificates 
        $allCerts = array($extracerts);
        array_unshift($allCerts, $cert);
        $allCertsContent = implode("\r\n\r\n", $allCerts);

        // Appends certificate to the message
        $args['message'] = $engine->attachCertificate($message, $allCertsContent);
      }

      // Adjust formats of encrypted/signed message before sending
      else{
        $args['message'] = $message->convertToMailMime($purpose);
      }

      return $args;
    }

    /**
     * Function for throwing errors in processMessageToSend() method
     * 
     * @param array $args Original parameters
     * @param string $type Reference to error text in localization folder
     * @param array $vars Dynamic error text values
     * 
     * @return array Modified parameters
     */

    function generateErrorWhenSending(&$args, $type, $vars = []){
      $args['error'] = $this->gettext([
        'name' => $type,
        'vars' => $vars
      ]);
      $args['abort'] = true;
      return $args;
    }

    /**
     * Handler for message_load hook
     * Shows attached certificate/verifies signature/decrypts incoming message
     * 
     * @param array $args Original parameters
     * 
     * @return array Modified parameters
     */

    function processReceivedMessage($args){

      // Get user settings
      $preferences = $this->settings->getSettings();

      // If plugin is turned off
      if(!$preferences['slime_enable']){
        return $args;
      }

      $message = $args['object'];
      $messageObj = new slime_receive_msg($this, $message);

      // Checks if message is encrypted/signed/contains certificate
      $rootPart = $messageObj->getMessageStructure();
      $rootPartCType = $messageObj->getMimeType($rootPart);
      $purposeBits = $this->getMessagePurpose($rootPart, $rootPartCType);

      if($purposeBits == 0){
        return $args;
      }
      $purpose['sign'] = $this->isBitSet($purposeBits, self::MESSAGE_SIGNED);
      $purpose['attach'] = $this->isBitSet($purposeBits, self::MESSAGE_ATTACHED_CERTIFICATE);
      $purpose['encrypt'] = $this->isBitSet($purposeBits, self::MESSAGE_ENCRYPTED);
      $purpose['encryptAuth'] = $this->isBitSet($purposeBits, self::MESSAGE_ENCRYPTED_AUTH);

      // Get senders PKCS#12 file path
      $filePath = $this->settings->getExistingPKCS12();

      // If PKCS#12 does not exist, can't decrypt the message
      if($filePath == "" && $purpose['encrypt']){
        array_push($this->statusMsg, self::MESSAGE_NO_PK_ENCRYPTED);
        $args['object']->body = $messageObj->getEncryptedContent();
        return $args;
      }

      $mimeType = $filePath == "" ? "application/x-x509-ca-cert" : "application/x-pkcs12";
      $pkcsFile = new slime_smimeFile($filePath, $this, $mimeType);

      // If only attached certificate is present
      if($purpose['attach'] && !$purpose['sign'] && !$purpose['encrypt']){
        $engine = new slime_cryptoEngine($this, "", "", "");
      }
      else{
        $cert = $pkcsFile->getCertificate();
        $pk = $pkcsFile->getPK();
        $extracerts = $pkcsFile->getExtraCerts();
  
        $engine = new slime_cryptoEngine($this, $cert, $pk, $extracerts);
      }

      // Encrypted message
      if($purpose['encrypt']){

        // Caches old PKCS#12 files (To read older messages) 
        $engine->setOldPKCS($this->settings->getOldPKCS());

        // Decrypts message
        $messageInfo = $engine->decryptMessage($messageObj, $purpose['encryptAuth']);
        if($this->isBitSet($messageInfo['status'], self::MESSAGE_DECRYPTION_HTML)){
          array_push($this->statusMsg, self::MESSAGE_DECRYPTION_HTML);
        }

        if($this->isBitSet($messageInfo['status'], self::MESSAGE_DECRYPTION_SUCCESSFULLY)){
          array_push($this->statusMsg, self::MESSAGE_DECRYPTION_SUCCESSFULLY);
        }
        else if($this->isBitSet($messageInfo['status'], self::MESSAGE_DECRYPTION_FAILED)){
          array_push($this->statusMsg, self::MESSAGE_DECRYPTION_FAILED);
          $args['object']->body = $messageInfo['content'];
          return $args;
        }
        
        if($this->isBitSet($messageInfo['status'], self::MESSAGE_DECRYPTION_WEAK)){
          array_push($this->statusMsg, self::MESSAGE_DECRYPTION_WEAK);
        }
        
        // Sets content of the message
        $messageObj->setContent($messageInfo['content']);
        if($messageObj->isMessageSigned($messageInfo['content'])){
          $purpose['sign'] = true;
        }
      }

      // Signed message
      if($purpose['sign']){

        // Verify a signature
        $status = $engine->verifySignature($messageObj);
        if($this->isBitSet($status, self::MESSAGE_SIGNATURE_VERIFIED)){

          // If certificate identities doesn't match sender (From) 
          if($this->isBitSet($status, self::MESSAGE_SIGNATURE_WRONG_SUBJECT)){
            array_push($this->statusMsg, self::MESSAGE_SIGNATURE_WRONG_SUBJECT);
          }

          array_push($this->statusMsg, self::MESSAGE_SIGNATURE_VERIFIED);

          // If user wants to show a trust level 
          if($this->isBitSet($status, self::MESSAGE_SIGNATURE_CLASS_1)){
            array_push($this->statusMsg, self::MESSAGE_SIGNATURE_CLASS_1);
          }
          else if($this->isBitSet($status, self::MESSAGE_SIGNATURE_CLASS_2)){
            array_push($this->statusMsg, self::MESSAGE_SIGNATURE_CLASS_2);
          }
          else if($this->isBitSet($status, self::MESSAGE_SIGNATURE_CLASS_3)){
            array_push($this->statusMsg, self::MESSAGE_SIGNATURE_CLASS_3);
          }

        }
        else if($this->isBitSet($status, self::MESSAGE_SIGNATURE_NOT_VERIFIED)){
          array_push($this->statusMsg, self::MESSAGE_SIGNATURE_NOT_VERIFIED);
        }
      }

      // Additional formating for decrypted messages
      if($purpose['encrypt']){
        $newStructure = rcube_mime::parse_message($messageObj->getContent());

        $args['object']->body = $this->decryptedToPrintable($newStructure);
        $args['object']->structure = $newStructure;
        
        // Adds decrypted attachments
        $attachments = $this->findAllAttachments($newStructure);

        $index = count($args['object']->attachments);
        foreach ($attachments as $attachment){
          $attachment->mime_id = (string) ++$index;
          $args['object']->attachments[] = $attachment;
          $args['object']->mime_parts[] = $attachment;
        }
      }

      // Initialize importable attachments/certificates
      $this->certs = array();

      // Attached certificates
      if($purpose['attach'] || ($purpose['sign'] && $preferences['slime_import_signature'])){

        // Checks all the attachments
        foreach((array) $args['object']->attachments as $attachment){

          // Checks if attachment is a attached certificate or a signature
          $isAttachedCertificate = $engine->isAttachmentCertificate($attachment, ".p7c");
          $isAttachedSignature = $engine->isAttachmentCertificate($attachment, ".p7s");
          if($isAttachedCertificate || $isAttachedSignature){
            $this->rc->output->set_env('uid', $message->uid);

            // Automatically import a certificate if set in settings
            if($preferences['slime_import_all']){
              $this->ui->import_attachment($message->uid, $attachment->mime_id, $message, $isAttachedSignature);
            }

            // Caches the certificate(its ID) in case user clicks the import button
            // (Handled by template_object_messagebody hook)
            $attachmentItem['mimeID'] = $attachment->mime_id;
            $attachmentItem['isSignature'] = $isAttachedSignature;
            array_push($this->certs, $attachmentItem);
          }
        }
      }

      return $args;
      }

    /**
     * Recursively find out which S/MIME operations were used on the message
     * 
     * @param rcube_message_part $currentPart Message node with one distinguish content type 
     * @param string $cType Content Type of the part
     * 
     * @return string Printable content
     */

      function getMessagePurpose($currentPart, $cType){
    
        $purpose = 0;
  
        // Leaf nodes
        if(strpos($cType, "multipart") === false){
          if($cType == "application/x-pkcs7-mime" || $cType == "application/pkcs7-mime"){
            if(isset($currentPart->ctype_parameters['smime-type'])){
              if($currentPart->ctype_parameters['smime-type'] == "signed-data"){
                $purpose = self::MESSAGE_SIGNED;
              }
              else if($currentPart->ctype_parameters['smime-type'] == "certs-only"){
                $purpose = self::MESSAGE_ATTACHED_CERTIFICATE;
              }
              else if($currentPart->ctype_parameters['smime-type'] == "enveloped-data"){
                $purpose = self::MESSAGE_ENCRYPTED;
              }
              else if($currentPart->ctype_parameters['smime-type'] == "authEnveloped-data"){
                $purpose = self::MESSAGE_ENCRYPTED | self::MESSAGE_ENCRYPTED_AUTH;
              }
            }
            else if(strpos($currentPart->filename, ".p7c", -4) !== false){
              $purpose = self::MESSAGE_ATTACHED_CERTIFICATE;
            }
          }
        }
  
        // Parent nodes
        else{
          if($cType == "multipart/signed"){
            $purpose = self::MESSAGE_SIGNED;
          }
  
          foreach($currentPart->parts as $child){
            $purpose |= $this->getMessagePurpose($child, $child->mimetype);
          }
        }
        return $purpose;
      }

    /**
     * Checks if the bit is set (used to represent multiple states)
     * 
     * @param int $value representation of multiple attributes
     * @param int $bit attribute to check
     * 
     * @return bool 
     */

     function isBitSet($value, $bit){
      return (($value & $bit) === $bit);
    }

    /**
     * Recursively (due to multipart) format printable parts of a decrypted messages
     * 
     * @param rcube_message_part $currentPart Message node with one distinguish content type 
     * 
     * @return string Printable content
     */

    function decryptedToPrintable($currentPart){

      $currentContentType = $currentPart->mimetype;
      switch($currentContentType){

        case "text/plain":
          if($currentPart->filename == ""){
            return $currentPart->body;
          }
          break;

        case "multipart/related":
        case "multipart/alternative":
        case "multipart/signed":
        case "multipart/mixed":
          $out = "";
          foreach($currentPart->parts as $child){
            $out .= $this->decryptedToPrintable($child);
          }
          return $out; 

        default:
          return "";

      }
      return "";
    }

    /**
     * Recursively find all attachments
     * 
     * @param rcube_message_part $currentPart Message node with one distinguish content type 
     * 
     * @return array of rcube_message_part representing files
     */

    function findAllAttachments($currentPart){

      // If its a file
      if(isset($currentPart->filename) && $currentPart->filename != ""){
        return array($currentPart);
      }

      $currentAttachments = array();

      // Add files of children
      foreach($currentPart->parts as $child){
        $childAttachments = $this->findAllAttachments($child);
        $currentAttachments = array_merge($childAttachments, $currentAttachments);
      }

      return $currentAttachments;
    }
    
    /**
     * Handler for template_object_messagebody hook
     * Adds import UI element when attached certificates is present in received message  
     * 
     * @param array $args Original parameters
     * 
     * @return array Modified parameters
     */ 

    function handleCertificateAttachment($args){
      return $this->ui->messageAttachment($args);
    }

    /**
     * Handler for plugin.slime.import_certificate action
     * Imports certificate from received message
     */

    function importCert(){
      $this->ui->import_attachment();
    }

    /**
     * Handler for message_body_prefix hook
     * Shows status text of a received message (E.g. "Verified signature!")
     * 
     * @param array $args Original parameters
     * 
     * @return array Modified parameters
     */

    function showMessageStatusText($args){
      return $this->ui->receivedMessageStatus($args);
    }

     /**
     * Handler for authenticate hook
     * Calculates hash of the user password and saves the username temporarily
     * 
     * @param array $args Original parameters
     * 
     * @return array Modified parameters
     */

    function getPasswordHash($args){
      $valid = $args['valid'];
      if(!$valid){
        return $args;
      }

      $username = $args['user'];
      $password = $args['pass'];

      $this->tmpUsername = $username;
      $this->tmpPassword = hash('sha256', $password);

      return $args;
    }

    /**
     * Handler for login_after hook
     * Saves hash and username persistently
     * 
     * @param array $args Original parameters
     * 
     * @return array Modified parameters
     */

    function saveAuthValues($args){

      $this->rc->user->save_prefs([
        'slime_username' => $this->tmpUsername,
        'slime_hashPassword' => $this->tmpPassword,
      ]);

      return $args;
    }
  }