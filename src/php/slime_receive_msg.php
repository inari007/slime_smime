<?php

/**
 * SLIME S/MIME Plugin
 *
 * Copyright (c) 2025 Zdenek Dobes
 * See README file for more details.
 * 
 */

/**
 * This class represents received message
 * Used by processReceivedMessage() method
*/

class slime_receive_msg {

    private $slime;
    private $message;
    private $header;
    private $raw_message;

    /**
     * Creates received message object
     * 
     * @param slime_smime $slime Plugin class
     * @param object $message Received message object
     */

    function __construct($slime, $message){
        $this->slime = $slime;
        $this->message = $message;
        $this->header = $message->headers;

        // Get raw message from storage based on its ID
        $this->raw_message = $this->normalizeMessage($this->slime->rc->get_storage()->get_raw_body($this->header->uid));
    }

    /**
     * Returns structure of the message
     * 
     * @return rcube_message_part Message MIME structure
     */

    function getMessageStructure(){
      return $this->message->headers->structure;
    }

    /**
     * Returns content type of the current rcube_message_part
     * 
     * @param rcube_message_part $part Current MIME message part 
     * 
     * @return string Content type
     */

    function getMimeType($part){
      return $part->mimetype;
    }

    /**
     * Returns message object
     * 
     * @return rcube_message Message object
     */

    function getMessage(){
        return $this->message;
    }

    /**
     * Returns header of the message
     * 
     * @return array Message header
     */

    function getHeader(){
        return $this->header;
    }

    /**
     * Normalizes message (Ensures lines end with CRLF)
     * 
     * @param string $content Message content 
     * 
     * @return string Normalized message
     */

    function normalizeMessage($content){
        return preg_replace("/\r\n|\r|\n/", "\r\n", $content);
    }

    /**
     * Gets sender of the message
     * 
     * @return string E-mail of the sender
     */

    function getSender(){
        $line = $this->header->from;

        // Regex for E-mail address
        preg_match('/<?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})>?/', $line, $matches);
        $folderName = $matches[1];
        return $folderName;
    }

    /**
     * Gets X-sender of the message
     * 
     * @return string E-mail of the x-sender
     */

    function getXSender(){
      preg_match('/^X-Sender:\s*(.+)$/mi', $this->raw_message, $matches);
      return trim($matches[1]);
    }

    /**
     * Get message part header and its content in multipart/signed message
     * 
     * @return string Content of the signed message
     */

    function getSignedContent(){
        $structure = $this->message->headers->structure;
        $boundary = "--" . $this->getBoundary($structure) . "\r\n";
  
          // Finds boundaries in the message
          if(preg_match_all("/" . preg_quote($boundary, "/") . "/", $this->raw_message, $matches, PREG_OFFSET_CAPTURE) > 1){
            
            // Get positions of the first 2 boundaries (message content)
            $positions = array_map(fn($match) => $match[1], $matches[0]);
            $secondPos = $positions[0] + strlen($boundary);
            $thirdPos = $positions[1];
            $length = $thirdPos - $secondPos;
            
            // Separates content from the message 
            $signedContent = substr($this->raw_message, $secondPos, $length);
            return $signedContent;
          }
          return "";
      }

    /**
     * Get encrypted encoded content of the message
     * 
     * @return string Message string in PEM format
     */

      function getEncryptedContent(){
        list($header, $body) = explode("\r\n\r\n", $this->raw_message, 2);
        return "-----BEGIN S/MIME MESSAGE-----\r\n" . $body . "-----END S/MIME MESSAGE-----";
      }

    /**
     * Gets raw message content
     * 
     * @return string Raw message content
     */

      function getContent(){
        return $this->raw_message;
      }

    /**
     * Recursively find boundary of the multipart/signed part
     * 
     * @param rcube_message_part $currentPart Current MIME message part 
     * 
     * @return string Boundary string
     */
  
      function getBoundary($currentPart){
        if($currentPart->mimetype == "multipart/signed"){
          return $currentPart->ctype_parameters['boundary'];
        }
        else{
          $out = "";
          foreach ($currentPart->parts as $child){
            $out .= $this->getBoundary($child);
          }
          return $out;
        }
      }

    /**
     * Replace content of the raw message
     * 
     * @param string $newContent Raw message with new content
     */

      function setContent($newContent){
        list($rawHeader, $rawBody) = explode("\r\n\r\n", $this->raw_message, 2);
        list($newHeader, $newBody) = explode("\r\n\r\n", $newContent, 2);

        // Keeps old header but attributes defining content are replaced
        $newHeader = trim($this->removeContentInfo($rawHeader)) . "\r\n" . $newHeader;
        $this->raw_message = $newHeader . "\r\n\r\n" . $newBody;
      }

    /**
     * Removes attributes defining content from header
     * 
     * @param string $header Content header
     * 
     * @return string Header without content attributes
     */

      function removeContentInfo($header){
        $pattern = '/^(Content-Type|Content-Transfer-Encoding|Content-ID|Content-Description|Content-Disposition):[^\r\n]*(?:\r?\n[ \t][^\r\n]*)*/im';
        return preg_replace($pattern, '', $header);
      }

    /**
     * Checks if message includes HTML content
     * 
     * @return bool True if message includes HTML content
     */

      function isHTMLMessage($content){
        return strpos($content, "\r\nContent-Type: text/html"); 
      }

      /**
       * Gets signature content from a signed message
       * 
       * @return string SignedData CMS type
       */

      function getSignature(){

        $structure = $this->message->structure;
        $boundary = "--" . $this->getBoundary($structure);

        // Finds child with Signature content-type
        if(preg_match('/Content-Type: application\/(?:x-)?pkcs7-signature(.*)/s', $this->raw_message, $content)){

          // Finds signature content
          if(!preg_match("/(?:\r\n|\n){2}(.*?)(?=" . preg_quote($boundary, '/') . ")/s", $content[1], $signature)){
            return "";
          }
          $signature = trim($signature[1]);
          
          // Gets encoding of the content
          if(preg_match('/Content-Transfer-Encoding:\s*(\S+)/i', $content[1], $encoding)){
            if($encoding[1] == "base64"){
              return base64_decode($signature);
            }
          }
          return $signature;
        }
        return "";
      }
}