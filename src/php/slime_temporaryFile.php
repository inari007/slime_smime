<?php

/**
 * SLIME S/MIME Plugin
 *
 * Copyright (c) 2025 Zdenek Dobes
 * See README file for more details.
 * 
 */

 /**
  * Support class for calling OpenSSL functions that use files as input and output
  */

class slime_temporaryFile {

    private $file;

    /**
     * Instantly creates file 
     */

    function __construct() {
        $this->createFile();
    }

    /**
     * Creates a temporary file
     */

    function createFile() {
        $this->file = tempnam("./plugins/slime_smime/tmp/", "slime_tmp");
    }

    /**
     * Gets path of the file
     * 
     * @return string File path
     */

    function getFile(){
        return $this->file;
    }

    /**
     * Gets content of the file
     * 
     * @return string File content
     */

    function getContent() {
        return(file_get_contents($this->file));
    }

    /**
     * Appends content of the file
     * 
     * @param string File content
     */

    function writeContent($content) {
        file_put_contents($this->file, $content);
    }

    /**
     * Removes the file
     */

    function removeFile() {
        unlink(realpath($this->file));
    }
}