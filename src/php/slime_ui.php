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
  * This class handles UI actions and dynamically generates UI elements   
  */

class slime_ui{

    private $slime;
    private $curretData;
    private $isElastic;

    /**
     * Saves reference to plugin class
     * 
     * @param slime_smime $slime Plugin class
     */

    function __construct($slime){
        $this->slime = $slime;
    }

    /**
     * Initialize UI elements, loads CSS and JS files 
     */

    function createUIelements(){

        $this->isElastic = array_key_exists('elastic', (array) $this->slime->rc->output->skins);

        // Elastic CSS
        if($this->isElastic){
            $this->slime->include_stylesheet("src/css/slime_elastic.css");
        }

        // Larry CSS
        else{
            $this->slime->include_stylesheet("src/css/slime_larry.css");
        }
        $this->slime->include_script('src/js/min_slime_smime.js');

        // Handler for all setting actions 
        $this->slime->add_hook('settings_actions', array($this, 'settings_actions'));

        // Types of actions in settings section (import, export, delete,..)
        $action = rcube_utils::get_input_value('_a', rcube_utils::INPUT_GPC);

        // Add sidebar UI functions when composing a new message
        if ($this->slime->rc->action == 'compose') {

            // Elastic compose
            if($this->isElastic){
                $this->slime->api->add_content($this->composeSideBarUI(), 'composeoptions');
            }

            // Larry compose
            else{
                $this->composeUpperBarUILarry();
                $this->slime->rc->output->add_footer($this->composeSideBarUI());
            }
        }

        // Specify handling S/MIME settings section actions 
        else if($this->slime->rc->action == 'plugin.slime_settings_section'){
            $this->slime->register_action("plugin.slime_settings_section", array($this, 'showSectionSettingsUI'));

            switch ($action) {
                case 'import':
                    $this->cert_import();
                    break;

                case 'export':
                    $this->cert_export();
                    break;

                case 'export_password':
                    $this->cert_export_password();
                    break;

                case 'delete':
                    $this->cert_delete();
                    break;

                case 'update_settings':
                    $this->update_settings();
                    break;

                case 'options':
                    $this->slime_options();
                    break;

                case 'info':
                    $this->slime_cert_info();
                    break;

                case 'certs':
                    $this->cert_lists();
                    break;
            }

            $this->slime->rc->output->add_handlers([
                'mycertslist'     => [$this, 'slime_my_certificates'],
                'othercertslist'     => [$this, 'slime_other_certificates'],
                'countdisplay' => [$this, 'slime_page_number'],
            ]);
        
    
        }
    }

    /**
     * Template for page numbers
     *
     * @param array $args Object attributes
     *
     * @return string HTML content
     */
    
    function slime_page_number($args){

        // Adds ID if not included
        if(empty($args['id'])) {
            $args['id'] = 'slimePageNum';
        }

        $this->slime->rc->output->add_gui_object('countdisplay', $args['id']);

        return html::span($args, $this->getPageNumString());
    }

    /**
     * Provides info about current page in settings
     *
     * @return string Page content text
     */

    function getPageNumString(){
        $currentPage = $this->slime->settings->currentPageNumber;
        $currentCertNum = isset($this->slime->settings->currentCertificatesNumber) ? $this->slime->settings->currentCertificatesNumber : 1;
        $maxPage = $currentCertNum == 0 ? 1 : ceil($currentCertNum / $this->slime->settings->maxNumberOfCertificates);
        
        // makes values accessible in JS
        $this->slime->rc->output->set_env('pagecount', $maxPage);
        $this->slime->rc->output->set_env('current_page', $currentPage);
        
        return $this->slime->gettext([
            'name' => 'page_num',
            'vars' => ['current_page' => $currentPage, 'max_page' => $maxPage]
        ]);
    }

    /**
     * Handler for message_body_prefix hook
     * Generates status text of a received message (E.g. "Verified signature!")
     * 
     * @param array $args Original parameters
     * 
     * @return array Modified parameters
     */

    function receivedMessageStatus($args){

        $messages = array();

        // Iterates through status codes that were saved during processing received message
        foreach($this->slime->statusMsg as $status){

            // Creates unique ID 
            $attributes = ['id' => 'slime-statusMessage_' . $status];

            if($status == slime_smime::MESSAGE_SIGNATURE_VERIFIED){
                $attributes['class'] = 'boxconfirmation slime_status slime_confirm signed';
                $msg = rcube::Q($this->slime->gettext('sig_valid'));
            }
            else if($status == slime_smime::MESSAGE_SIGNATURE_NOT_VERIFIED){
                $attributes['class'] = 'boxerror slime_status slime_error signed';
                $msg = rcube::Q($this->slime->gettext('sig_invalid'));
            }
            else if($status == slime_smime::MESSAGE_SIGNATURE_WRONG_SUBJECT){
                $attributes['class'] = $this->slime->settings->isInStrictMode() ? 'boxerror slime_status slime_error signed' : 'boxwarning slime_status slime_warning signed';
                $msg = rcube::Q($this->slime->gettext('sig_wrong_subject'));
            }
            else if($status == slime_smime::MESSAGE_DECRYPTION_SUCCESSFULLY){
                $attributes['class'] = 'boxconfirmation slime_status slime_confirm encrypted';
                $msg = rcube::Q($this->slime->gettext('dec_success'));
            }
            else if($status == slime_smime::MESSAGE_DECRYPTION_FAILED){
                $attributes['class'] = 'boxerror slime_status slime_error encrypted';
                $msg = rcube::Q($this->slime->gettext('dec_failed'));
            }
            else if($status == slime_smime::MESSAGE_NO_PK_ENCRYPTED){
                $attributes['class'] = 'boxerror slime_status slime_error encrypted';
                $msg = rcube::Q($this->slime->gettext('dec_no_pkcs'));
            }
            else if($status == slime_smime::MESSAGE_DECRYPTION_HTML){
                $attributes['class'] = 'boxerror slime_status slime_error encrypted';
                $msg = rcube::Q($this->slime->gettext('dec_html_content'));
            }
            else if($status == slime_smime::MESSAGE_DECRYPTION_WEAK){
                $attributes['class'] = $this->slime->settings->isInStrictMode() ? 'boxerror slime_status slime_error encrypted' : 'boxwarning slime_status slime_warning encrypted';
                $msg = rcube::Q($this->slime->gettext('dec_weak_alg'));
            }
            else if($status == slime_smime::MESSAGE_SIGNATURE_CLASS_1 || $status == slime_smime::MESSAGE_SIGNATURE_CLASS_2 || $status == slime_smime::MESSAGE_SIGNATURE_CLASS_3){
                $attributes['class'] = 'boxconfirmation slime_status slime_confirm alert-success';
                $msg = rcube::Q($this->slime->gettext([
                            'name' => 'sig_trust_level',
                            'vars' => ['trust_level' => $this->slime->settings->mapTrustLevel($status)]
                        ]));
            }

            // Saves message classes and its content
            $attributes['msg'] = $msg;
            array_push($messages, $attributes);
        }

        // Generates status messages
        foreach($messages as $msg){
            $args['prefix'] .= html::div($msg, $msg['msg']);
        }

        return $args;
    }

     /**
     * Handler for template_object_messagebody hook
     * Adds import UI element when attached certificates is present in received message  
     * 
     * @param array $args Original parameters
     * 
     * @return array Modified parameters
     */ 

    function messageAttachment($args){

        foreach($this->slime->certs as $part){
            $args['content'] = html::p(['class' => 'slime_attachment boxinformation aligned-buttons'],
                html::span(null, rcube::Q($this->slime->gettext($part['isSignature'] ? 'sig_found' : 'cert_found'))) .
                html::tag('button', [
                        'onclick' => "return ".rcmail_output::JS_OBJECT_NAME.".slime_import_attachment('" . rcube::JQ($part['mimeID']) . "', '" . rcube::JQ($part['isSignature']) . "')",
                        'title'   => $this->slime->gettext('cert_title'),
                        'class'   => 'import btn-sm',
                    ], rcube::Q($this->slime->rc->gettext('import'))
                )
            ) . $args['content'];
        }

        return $args;
    }

    /**
     * Get slider info from UI to find out which S/MIME operations apply
     */

    function getMessagePurposeUI(){
        $preferences = $this->slime->settings->getSettings();

        if($preferences['slime_enable'] == 1){
            $purpose['sign'] = (bool) rcube_utils::get_input_value('_slime_sign', rcube_utils::INPUT_POST);
            $purpose['encrypt'] = (bool) rcube_utils::get_input_value('_slime_encrypt', rcube_utils::INPUT_POST);
            $purpose['attach'] = (bool) rcube_utils::get_input_value('_slime_distribute', rcube_utils::INPUT_POST);
        
            // If none of S/MIME UI sliders is on, disable plugin 
            $purpose['enable'] = $purpose['sign'] || $purpose['encrypt'] || $purpose['attach'];
        }
        else{
            $purpose['enable'] = false;
        }
        
        return $purpose;
    }

    /**
     * Action handler for Save button in S/MIME Option
     * Get values from option page and persistently save them
     */

    function update_settings(){
        $preferences['slime_enable'] = rcube_utils::get_input_value('_slime_enable', rcube_utils::INPUT_POST);
        $preferences['slime_sign_every'] = rcube_utils::get_input_value('_slime_sign_every', rcube_utils::INPUT_POST);
        $preferences['slime_encrypt_every'] = rcube_utils::get_input_value('_slime_encrypt_every', rcube_utils::INPUT_POST);
        $preferences['slime_import_signature'] = rcube_utils::get_input_value('_slime_import_signature', rcube_utils::INPUT_POST);
        $preferences['slime_import_all'] = rcube_utils::get_input_value('_slime_import_all', rcube_utils::INPUT_POST);
        $preferences['slime_disable_weak'] = rcube_utils::get_input_value('_slime_disable_weak', rcube_utils::INPUT_POST);
        $preferences['slime_trust_levels'] = rcube_utils::get_input_value('_slime_trust_levels', rcube_utils::INPUT_POST);
        $preferences['slime_encryption_algorithm'] = rcube_utils::get_input_value('_slime_encryption_algorithm', rcube_utils::INPUT_POST);

        // Persistently saves options
        $this->slime->settings->updateSettings($preferences);

        $this->slime->rc->output->show_message('slime_smime.update_success', 'confirmation');
    }

    /**
     * Action handler for a Import button
     */

    function cert_import(){

        // Checks if any temporary file was added (if a file was imported by user)
        if(!empty($_FILES['_file']['tmp_name']) && is_uploaded_file($_FILES['_file']['tmp_name'])){
            
            $password = isset($_POST['_passwd']) ? $_POST['_passwd'] : null;

            // The import of the file
            $result = $this->slime->settings->importCertificate($_FILES['_file']['tmp_name'], $password, $_FILES['_file']['type']);
            $status = $result['status'];

            // Generating responds for user
            switch($status){

                case slime_smime::FILE_IS_PROTECTED_BY_PASSWORD:
                    if($password !== null){
                        $this->slime->rc->output->show_message('slime_smime.import_password_error', 'error');
                    }

                    // Opens a window with a password request
                    $this->slime->rc->output->command('parent.slime_certificate_password', [
                        "type" => "import",
                    ]);
                    break;

                case slime_smime::FILE_EMAIL_NOT_IN_CERT:
                    $this->slime->rc->output->show_message('slime_smime.import_email_not_present', 'error');
                    break;

                case slime_smime::FILE_INVALID_PKCS7:
                    $this->slime->rc->output->show_message('slime_smime.import_invalid_pkcs7', 'error');
                    break;

                case slime_smime::FILE_WRONG_PEM_FORMAT:
                    $this->slime->rc->output->show_message('slime_smime.import_file_no_pem', 'error');
                    break;

                case slime_smime::FILE_TYPE_NOT_SUPPORTED:
                    $this->slime->rc->output->show_message('slime_smime.import_file_not_supported', 'error');
                    break;

                case slime_smime::FILE_INVALID_CERTIFICATE:

                    // Get first error message and show it 
                    if(isset($result['error'])){
                        $text = $this->slime->gettext([
                            'name' => 'import_warning',
                            'vars' => ['error' => $result['error']]
                        ]);
                        $this->slime->rc->output->show_message($text, 'error');
                    }
                    else{
                        $this->slime->rc->output->show_message('slime_smime.import_invalid_cert', 'error');
                    }
                    break;

                case slime_smime::FILE_SUCCESS:

                    if(isset($result['error'])){
                        $text = $this->slime->gettext([
                            'name' => 'import_warning',
                            'vars' => ['error' => $result['error']]
                        ]);
                        $this->slime->rc->output->show_message($text, 'notice');
                    }

                    $this->slime->rc->output->show_message('slime_smime.import_success', 'confirmation');

                    // Reframes page so new certificate is loaded and closes the import window
                    $this->slime->rc->output->command('parent.slime_certs');
                    $this->slime->rc->output->command('parent.slime_import_success');
                    break;
              }
        }

        // Catching errors
        else if(!empty($_FILES['_file']['error'])){
            if(RCMAIL_VERSION > '1.6'){
                rcmail_action::upload_error($_FILES['_file']['error']);
            }
            else{
                $err = $_FILES['_file']['error'];
                if($err == UPLOAD_ERR_INI_SIZE || $err == UPLOAD_ERR_FORM_SIZE){
                    $this->slime->rc->output->show_message('filesizeerror', 'error',
                        array('size' => $this->slime->rc->show_bytes(rcube_utils::max_upload_size())));
                }
                else{
                    $this->slime->rc->output->show_message('fileuploaderror', 'error');
                }
            }
            $this->slime->rc->output->send('iframe');
        }

        // Adds UI elemets into the certificate import window
        $this->slime->rc->output->add_handlers([
            'importform' => [$this, 'cert_import_form'],
        ]);
        
        // Opens import window
        $this->slime->rc->output->set_pagetitle($this->slime->gettext('smime'));
        $this->slime->rc->output->send('slime_smime.slime_import');
    }

    /**
     * Action handler for exporting "My certificates"
     */

    function cert_export_password(){
        $id = rcube_utils::get_input_value('_id', rcube_utils::INPUT_POST);

        // Each certificate has unique ID as a last 13 characters   
        $id = substr($id, 0, -13);  
        $exportType = rcube_utils::get_input_value('_exportType', rcube_utils::INPUT_POST);
        $password = rcube_utils::get_input_value('_passwd', rcube_utils::INPUT_POST);
        $isOld = rcube_utils::get_input_value('_isOld', rcube_utils::INPUT_POST);
        $extension = rcube_utils::get_input_value('_extension', rcube_utils::INPUT_POST);

        // The export of the file
        $success = $this->slime->settings->exportCertificate($id, $exportType, $password, $isOld == "True", $extension);

        if($success == slime_smime::FILE_IS_MISSING_A_PASSWORD){
            $this->slime->rc->output->command('parent.slime_certificate_password', [
                "type" => "export",
                "isOld" => $isOld,
                "extension" => $extension
            ]);
        }
        else{
            $this->slime->rc->output->command('plugin.slime_certificate_password_not_req');
        }
    }

    /**
     * Action handler for exporting "Public certificates"
     * Used for both my and public certificates 
     */

    function cert_export(){      
        $id = rcube_utils::get_input_value('_id', rcube_utils::INPUT_POST);

        // Each certificate has unique ID as a last 13 characters   
        $id = substr($id, 0, -13);
        $exportType = rcube_utils::get_input_value('_exportType', rcube_utils::INPUT_POST);
        $password = rcube_utils::get_input_value('_passwd', rcube_utils::INPUT_POST);
        $isOld = rcube_utils::get_input_value('_isOld', rcube_utils::INPUT_POST);
        $extension = rcube_utils::get_input_value('_extension', rcube_utils::INPUT_POST);

        // The export of the file
        $success = $this->slime->settings->exportCertificate($id, $exportType, $password, $isOld == "True", $extension);

        switch ($success){
            case slime_smime::FILE_SUCCESS:
                break;

            case slime_smime::FILE_IS_MISSING_A_PASSWORD:
                $this->slime->rc->output->command('plugin.slime_certificate_password_req', [
                    "type" => "export",
                    "isOld" => $isOld,
                    "extension" => $extension
                ]);
                break;

        }
        exit();
    }

    /**
     * Action handler when deleting certificates
     */

    function cert_delete(){
        $id = rcube_utils::get_input_value('_id', rcube_utils::INPUT_POST);

        // Each certificate has unique ID as a last 13 characters   
        $id = substr($id, 0, -13);
        $exportType = rcube_utils::get_input_value('_type', rcube_utils::INPUT_POST);
        $mimeType = $exportType == "pkcs12" ? "application/x-pkcs12" : "application/x-x509-ca-cert";
        $isOld = rcube_utils::get_input_value('_isOld', rcube_utils::INPUT_POST) == "True";
        $extension = rcube_utils::get_input_value('_extension', rcube_utils::INPUT_POST);

        // The deletion of the file
        $success = $this->slime->settings->deleteCertificate($id, $mimeType, $isOld, $extension);

        if(!$success){
            $this->slime->rc->output->show_message('slime_smime.delete_fail', 'error');
        }
        else{
            $this->slime->rc->output->show_message('slime_smime.delete_success', 'confirmation');

            // Reframes page so deleted certificate is not shown
            $this->slime->rc->output->command('remove_cert');
        }
        $this->slime->rc->output->send();
    }

    /**
     * Handler for both my certificate list and public certificate list
     */

    function cert_lists(){
        $this->slime->settings->currentPageNumber = intval(rcube_utils::get_input_value('_page', rcube_utils::INPUT_GPC));
        
        // Gets both my and public certificates
        $allCerts = $this->slime->settings->getCertificates();

        foreach ($allCerts as $item) {
            $this->slime->rc->output->command('slime_add_certs_to_list', [
                    'name'  => rcube::Q($item['name']),
                    'id'    => $item['id'],
                    'type'  => $item['type'],
                    'isOld' => $item['isOld'],
                    'isUsed' => $item['isUsed']
            ]);
        }

        // Roundcube build-in command for moving between pages correctly
        $this->slime->rc->output->command('set_rowcount', $this->getPageNumString());
        $this->slime->rc->output->send();
    }

    /**
     * Action handler when specific certificate is clicked 
     * Shows page with detail certificate information
     */

    function slime_cert_info(){
        $id = rcube_utils::get_input_value('_id', rcube_utils::INPUT_GET);
        
        // Each certificate has unique ID as a last 13 characters   
        $id = substr($id, 0, -13);
        $type = rcube_utils::get_input_value('_type', rcube_utils::INPUT_GET);
        $mimeType = $type == "crt" ? "application/x-x509-ca-cert" : "application/x-pkcs12";
        $isOld = rcube_utils::get_input_value('_isOld', rcube_utils::INPUT_GET) == "True";
        $certFile = new slime_smimeFile($id, $this->slime, $mimeType, null, $isOld, $type);

        // Gets formated certificate data 
        $this->curretData = $certFile->getCertificateData();
        
        $this->slime->rc->output->add_handlers([
            'certdata' => [$this, 'slime_cert_data'],
        ]);

        // Opens page with certificate data
        $this->slime->rc->output->set_pagetitle($this->slime->gettext('smime'));
        $this->slime->rc->output->send('slime_smime.slime_certInfo');
    }

    /**
     * Template for certificate information
     *
     * @param array $args Object attributes
     *
     * @return string HTML content
     */

    function slime_cert_data($args){
        $out   = '';
        $table = new html_table(['cols' => 2]);

        $table->add('title', html::label(null, $this->slime->gettext('subject_name')));
        $table->add(null, $this->curretData['name']);

        if($this->curretData['altIdentities']){
            $table->add('title', html::label(null, $this->slime->gettext('alternative_identities')));
            $table->add(null, $this->curretData['altIdentities']);
        }

        $table->add('title', html::label(null, $this->slime->gettext('serial_number')));
        $table->add(null, $this->curretData['serialNumber']);

        $table->add('title', html::label(null, $this->slime->gettext('valid_from')));
        $table->add(null, $this->curretData['validFrom']);

        $table->add('title', html::label(null, $this->slime->gettext('expires_on')));
        $table->add(null, $this->curretData['validTo']);

        $table->add('title', html::label(null, $this->slime->gettext('certificate_authority')));
        $table->add(null, $this->curretData['issuer']);

        $table->add('title', html::label(null, $this->slime->gettext('usage')));
        $table->add(null, $this->curretData['usage']);

        $out .= html::tag('fieldset', null,
            html::tag('legend', null, $this->slime->gettext('certificate_title_first')) . $table->show($args)
        );

        $table = new html_table(['cols' => 2]);

        $table->add('title', html::label(null, $this->slime->gettext('algorithm_used')));
        $table->add(null, $this->curretData['algorithmsUsed']);

        $table->add('title', html::label(null, $this->slime->gettext('key_size')));
        $table->add(null, $this->curretData['keyLength']);

        $table->add('title', html::label(null, $this->slime->gettext('key_type')));
        $table->add(null, $this->curretData['keyType']);

        $out .= html::tag('fieldset', null,
            html::tag('legend', null, $this->slime->gettext('certificate_title_second')) . $table->show($args)
        );

        return $out;
    }

    /**
     * Handler for my certificates
     * Adds build-in UI table element   
     * 
     * @param array $args Original parameters
     * 
     * @return array Modified parameters
     */ 

    function slime_my_certificates($args){
        if(RCMAIL_VERSION > '1.6'){
            $out = rcmail_action::table_output($args, [], array('name'), 'id');
        }
        else{
            $out = $this->slime->rc->table_output($args, [],  array('name'), 'id');
        }

        $this->slime->rc->output->add_gui_object('mycertslist', $args['id']);
        $this->slime->rc->output->include_script('list.js');

        return $out;
    }

    /**
     * Handler for public certificates
     * Adds build-in UI table element   
     * 
     * @param array $args Original parameters
     * 
     * @return array Modified parameters
     */ 

    function slime_other_certificates($args){
        if(RCMAIL_VERSION > '1.6'){
            $out = rcmail_action::table_output($args, [], array('name'), 'id');
        }
        else{
            $out = $this->slime->rc->table_output($args, [],  array('name'), 'id');
        }

        $this->slime->rc->output->add_gui_object('othercertslist', $args['id']);
        $this->slime->rc->output->include_script('list.js');

        return $out;
    }

    /**
     * Handler for S/MIME options
     */ 

    function slime_options(){
        if($this->isElastic){
            $this->slime->rc->output->add_handlers([
                'slime_options' => [$this, 'slime_options_form_elastic'],
            ]);
        }
        else{
            $this->slime->rc->output->add_handlers([
                'slime_options' => [$this, 'slime_options_form_larry'],
            ]);
        }
    
        // Opens S/MIME options window
        $this->slime->rc->output->set_pagetitle($this->slime->gettext('smime'));
        $this->slime->rc->output->send('slime_smime.slime_options');
    }

    /**
     * Template for composing message using Larry skin
     * Adds S/MIME button to the upper bar
     */ 

    function composeUpperBarUILarry(){
        $this->slime->add_button([
            'type'     => 'link',
            'id'       => 'slime_larry_send',
            'command'  => 'plugin.slime',
            'onclick'  => "rcmail.command('menu-open', 'slime_menu', event.target, event)",
            'class'    => 'button slime_button',
            'title'    => 'smime_hover',
            'label'    => 'smime',
            'domain'   => $this->slime->ID,
            'width'    => 32,
            'height'   => 32,
            'aria-owns'     => 'slime_menu',
            'aria-haspopup' => 'true',
            'aria-expanded' => 'false',
        ], 'toolbar'
    );
    }

    /**
     * Template for composing message
     * Adds side bar to Elastic and pop-up content to Larry
     * 
     * @return string HTML content
     */ 

    function composeSideBarUI(){

        $preferences = $this->slime->settings->getSettings();

        if($preferences['slime_enable'] == 1){

            $isLarry = !$this->isElastic;

            $sideBarContent = $isLarry ? "" : html::div('smime_sidebar_first_row', html::tag('fieldset', null,
                    html::tag('legend', null, $this->slime->gettext('smime'))
                ));

            $disabled = $preferences['slime_import_all'] == 1;
            $chbox = new html_checkbox(['value' => 1, 'class' => "form-check-input slime_slider_send"]);
            
            $sideBarContent .= html::div('form-group form-check row',
            html::label(['for' => 'slimesign', 'class' => 'col-form-label col-6'],
                rcube::Q($this->slime->gettext('sign'))
            )
            . html::div('form-check col-6',
                $chbox->show($preferences['slime_sign_every'], [
                        'name'     => '_slime_sign',
                        'id'       => 'slimesign',
                        'disabled' => $disabled,
                ])
            )
            );
    
            $sideBarContent .= html::div('form-group form-check row',
                html::label(['for' => 'slimeencrypt', 'class' => 'col-form-label col-6'],
                    rcube::Q($this->slime->gettext('encrypt'))
                )
                . html::div('form-check col-6',
                    $chbox->show($preferences['slime_encrypt_every'], [
                            'name'     => '_slime_encrypt',
                            'id'       => 'slimeencrypt',
                            'disabled' => $disabled,
                    ])
                )
            );
    
            $sideBarContent .= html::div('form-group form-check row smime_sidebar_last_row',
                html::label(['for' => 'slimedistribute', 'class' => 'col-form-label col-6'],
                    rcube::Q($this->slime->gettext('distribute'))
                )
                . html::div('form-check col-6',
                    $chbox->show($preferences['slime_import_all'], [
                            'name'     => '_slime_distribute',
                            'id'       => 'slimedistribute',
                            'disabled' => false,
                    ])
                )
            );

            if($isLarry){
                return html::div(['id' => 'slime_menu', 'class' => 'popupmenu'], $sideBarContent);
            }
            return $sideBarContent;
        }
    }

    /**
     * Action handler for S/MIME item in menu
     * Open S/MIME section
     */

    function showSectionSettingsUI(){
        $this->slime->rc->output->set_pagetitle($this->slime->gettext('smime'));
        $this->slime->rc->output->send('slime_smime.slime_settings');
    }

    /**
     * Template for S/MIME item in menu
     */

    function settings_actions($args){
        $args['actions'][] = [
            'type'   => 'link',
            'command' => 'plugin.slime_settings_section',
            'class'  => 'smime_section',
            'label'  => 'smime',
            'title'  => 'smime',
            'domain' => 'slime_smime',
            'id'     => 'smime_section'
        ];
        return $args;
    }

    /**
     * Handler for plugin.slime.import_certificate action or called automatically when option is set
     * Imports attached certificate to user directory 
     * 
     * @param string $messageID ID of the current message
     * @param string $attachmentMimeID ID of the part of the message that contains attachment
     * @param rcube_message $message Object of the current message
     * @param bool $isSignature True if certificate is imported from SignedData CMS type
     */

    function import_attachment($messageID = "", $attachmentMimeID = "", $message = null, $isSignature = false){

        // If message object needs to be created (manual import)
        if($messageID == "" && $attachmentMimeID == ""){
            $messageID = rcube_utils::get_input_value('_uid', rcube_utils::INPUT_POST);
            $attachmentMimeID = rcube_utils::get_input_value('_attachment', rcube_utils::INPUT_POST);
            $isSignature = rcube_utils::get_input_value('_isSignature', rcube_utils::INPUT_POST);
            $message = new rcube_message($messageID);
        }
            
        // If message object is already used by processReceivedMessage() method (automatical import)
        if($attachmentMimeID && $messageID){
            $messageObj = new slime_receive_msg($this->slime, $message);
            
            // Get owner E-mail, XSender prefered
            $xSender = $messageObj->getXSender();
            $Sender = $messageObj->getSender();
            $newFileName = $xSender == "" ? $Sender : $xSender;
            $newFileContent = $message->get_part_body($attachmentMimeID);

            // If content is part of the SignedData CMS type, parse the certificates first
            if($isSignature){
                $newFileContent = $this->slime->settings->getCertificatesFromSignature($newFileContent);
                
                // Unable to get certificates from signature
                if($newFileContent == ""){
                    $this->slime->rc->output->show_message('slime_smime.import_signature_failed', 'error');
                    return;
                }
            }

            $newFile = new slime_smimeFile($newFileName, $this->slime, "application/x-x509-ca-cert", $newFileContent);
            $result = $newFile->createFile();
            if($result['status'] == slime_smime::FILE_SUCCESS){
                $this->slime->rc->output->show_message('slime_smime.import_success', 'confirmation');
            }
            else{
                if(isset($result['error'])){
                    $text = $this->slime->gettext([
                        'name' => 'import_warning',
                        'vars' => ['error' => $result['error']]
                    ]);
                    $this->slime->rc->output->show_message($text, 'error');
                }
                else{
                    $this->slime->rc->output->show_message('slime_smime.import_invalid_cert', 'error');
                }
            }
        }
    }

    /**
     * Template for import certificates window
     * Creates form and adds UI elements to the import window
     * 
     * @param array $args Original parameters
     * 
     * @return string HTML content
     */

    function cert_import_form($args){
        $args += ['id' => 'CertImportForm'];

        if(empty($args['part']) || $args['part'] == 'import'){
            $title  = $this->slime->gettext('smime');
            $upload = new html_inputfield([
                    'type'  => 'file',
                    'name'  => '_file',
                    'id'    => 'slimemimportfile',
                    'size'  => 30,
                    'class' => 'form-control'
            ]);

            $upload_button = new html_button([
                    'class'   => 'button import',
                    'onclick' => "return rcmail.command('plugin.slime-import','',this,event)",
            ]);

            if(RCMAIL_VERSION > '1.6'){
                $max_filesize  = rcmail_action::upload_init();
            } 
           else{
                $max_filesize  = $this->slime->rc->upload_init();
            }

            $form = html::div(null, html::p(null, rcube::Q($this->slime->gettext('import_description'), 'show'))
                . $upload->show()
                . html::div('hint', $this->slime->rc->gettext(['id' => 'importfile', 'name' => 'maxuploadsize', 'vars' => ['size' => $max_filesize]]))
                . (empty($args['part']) ? html::br() . html::br() . $upload_button->show($this->slime->rc->gettext('import')) : '')
            );

            if(empty($args['part'])){
                $form = html::tag('fieldset', '', html::tag('legend', null, $title) . $form);
            }
            else{
                $this->slime->rc->output->set_pagetitle($title);
            }

            $warning = $this->slime->gettext('import_info');
            $warning = html::div(['class' => 'boxinformation mb-3', 'id' => 'cert-notice'], $warning);

            $form = $warning . $form;
        }

        $this->slime->rc->output->add_gui_object('importform', $args['id']);
        $this->slime->rc->output->add_label('selectimportfile', 'importwait', 'close', 'import');

        $out = $this->slime->rc->output->form_tag([
                'action'  => $this->slime->rc->url(['action' => $this->slime->rc->action, 'a' => 'import']),
                'method'  => 'post',
                'enctype' => 'multipart/form-data'
            ] + $args,
            $form ?? ''
        );

        return $out;
    }

    /**
     * Template for S/MIME options using Larry skin 
     * 
     * @param array $args Original parameters
     * 
     * @return string HTML content
     */

    function slime_options_form_larry($args){
        $args += ['id' => 'OptionsForm'];
        $out   = '';

        if (empty($args['part']) || $args['part'] == 'slime_options') {
            $preferences = $this->slime->settings->getSettings(); 
            $disabled = $preferences['slime_enable'] == 0;

            $chbox = new html_checkbox(['value' => 1, 'class' => 'form-check-input slime_slider_option']);
        
            $table = new html_table(['cols' => 2]);

            $table->add('title', html::label(['for' => 'slimeenable', 'class' => 'col-form-label col-6'],
            rcube::Q($this->slime->gettext('enable'))));
            $table->add(null, html::div('form-check col-6', $chbox->show($preferences['slime_enable'], [
                    'name'     => '_slime_enable',
                    'id'       => 'slimeenable',
                    'disabled' => false,
                ])));

            $table->add('title', html::label(['for' => 'slimesignevery', 'class' => 'col-form-label col-6'],
            rcube::Q($this->slime->gettext('sign_every'))));
            $table->add(null, html::div('form-check col-6', $chbox->show($preferences['slime_sign_every'], [
                    'name'     => '_slime_sign_every',
                    'id'       => 'slimesignevery',
                    'disabled' => $disabled,
                ])));

            $table->add('title', html::label(['for' => 'slimeencryptevery', 'class' => 'col-form-label col-6'],
            rcube::Q($this->slime->gettext('encrypt_every'))));
            $table->add(null, html::div('form-check col-6', $chbox->show($preferences['slime_encrypt_every'], [
                    'name'     => '_slime_encrypt_every',
                    'id'       => 'slimeencryptevery',
                    'disabled' => $disabled,
                ])));

            $table->add('title', html::label(['for' => 'slimeimportsignature', 'class' => 'col-form-label col-6'],
            rcube::Q($this->slime->gettext('import_signature'))));
            $table->add(null, html::div('form-check col-6', $chbox->show($preferences['slime_import_signature'], [
                    'name'     => '_slime_import_signature',
                    'id'       => 'slimeimportsignature',
                    'disabled' => $disabled,
                ])));

            $table->add('title', html::label(['for' => 'slimeimportevery', 'class' => 'col-form-label col-6'],
            rcube::Q($this->slime->gettext('import_every'))));
            $table->add(null, html::div('form-check col-6', $chbox->show($preferences['slime_import_all'], [
                    'name'     => '_slime_import_every',
                    'id'       => 'slimeimportevery',
                    'disabled' => $disabled,
                ])));

            $out .= html::tag('fieldset', null,
                html::tag('legend', null, $this->slime->gettext('options_title_first')) . $table->show($args)
            );

            $table = new html_table(['cols' => 2]);

            if(!$this->slime->settings->isInStrictMode()){
                $table->add('title', html::label(['for' => 'slimedisableweak', 'class' => 'col-form-label col-6'],
                rcube::Q($this->slime->gettext('disable_weak'))));
                $table->add(null, html::div('form-check col-6', $chbox->show($preferences['slime_disable_weak'], [
                        'name'     => '_slime_disable_weak',
                        'id'       => 'slimedisableweak',
                        'disabled' => $disabled,
                    ])));
            }

            $table->add('title', html::label(['for' => 'slimetrustlevels', 'class' => 'col-form-label col-6'],
                rcube::Q($this->slime->gettext('trust_levels'))));
                $table->add(null, html::div('form-check col-6', $chbox->show($preferences['slime_trust_levels'], [
                        'name'     => '_slime_trust_levels',
                        'id'       => 'slimetrustlevels',
                        'disabled' => $disabled,
                    ])));

            $select = new html_select(['name' => 'type', 'id' => 'slime_encryption_algorithm', 'class' => 'custom-select col-sm-6 slime_options_select', 'disabled' => $disabled]);
            $select = $this->addSymmetricAlgorithms($select);

            $table->add('title', html::label('encryption_algorithm', rcube::Q($this->slime->gettext('encryption_algorithm'))));
            $table->add(null, $select->show($preferences['slime_encryption_algorithm']));

            $out .= html::tag('fieldset', null,
                html::tag('legend', null, $this->slime->gettext('options_title_second')) 
                . $table->show($args)
            );
        }

        return $out;
    }

    /**
     * Template for S/MIME options using Elastic skin 
     * 
     * @param array $args Original parameters
     * 
     * @return string HTML content
     */

    function slime_options_form_elastic($attrib){
        $attrib += ['id' => 'OptionsForm'];

        if (empty($attrib['part']) || $attrib['part'] == 'slime_options') {

            $preferences = $this->slime->settings->getSettings();   
            $disabled = $preferences['slime_enable'] == 0;

            $chbox = new html_checkbox(['value' => 1, 'class' => 'form-check-input slime_slider_option']);

            $options = html::div('smime_options_title main', html::tag('fieldset', null,
                html::tag('legend', null, $this->slime->gettext('options_title_first'))
            ));
            
            $options .= html::div('form-group form-check row',
            html::label(['for' => 'slimeenable', 'class' => 'col-form-label col-6'],
                rcube::Q($this->slime->gettext('enable'))
            )
            . html::div('form-check col-6',
                $chbox->show($preferences['slime_enable'], [
                        'name'     => '_slime_enable',
                        'id'       => 'slimeenable',
                        'disabled' => false,
                ])
            )
            );
    
            $options .= html::div('form-group form-check row',
                html::label(['for' => 'slimesignevery', 'class' => 'col-form-label col-6'],
                    rcube::Q($this->slime->gettext('sign_every'))
                )
                . html::div('form-check col-6',
                    $chbox->show($preferences['slime_sign_every'], [
                            'name'     => '_slime_sign_every',
                            'id'       => 'slimesignevery',
                            'disabled' => $disabled,
                    ])
                )
            );

            $options .= html::div('form-group form-check row',
                html::label(['for' => 'slimeencryptevery', 'class' => 'col-form-label col-6'],
                    rcube::Q($this->slime->gettext('encrypt_every'))
                )
                . html::div('form-check col-6',
                    $chbox->show($preferences['slime_encrypt_every'], [
                            'name'     => '_slime_encrypt_every',
                            'id'       => 'slimeencryptevery',
                            'disabled' => $disabled,
                    ])
                )
            );

            $options .= html::div('form-group form-check row',
                html::label(['for' => 'slimeimportsignature', 'class' => 'col-form-label col-6'],
                    rcube::Q($this->slime->gettext('import_signature'))
                )
                . html::div('form-check col-6',
                    $chbox->show($preferences['slime_import_signature'], [
                            'name'     => '_slime_import_signature',
                            'id'       => 'slimeimportsignature',
                            'disabled' => $disabled,
                    ])
                )
            );

            $options .= html::div('form-group form-check row',
                html::label(['for' => 'slimeimportevery', 'class' => 'col-form-label col-6'],
                    rcube::Q($this->slime->gettext('import_every'))
                )
                . html::div('form-check col-6',
                    $chbox->show($preferences['slime_import_all'], [
                            'name'     => '_slime_import_every',
                            'id'       => 'slimeimportevery',
                            'disabled' => $disabled,
                    ])
                )
            );

            $table  = new html_table(['cols' => 2]);

            $select = new html_select(['name' => 'type', 'id' => 'slime_encryption_algorithm', 'class' => 'custom-select col-sm-6 slime_options_select', 'disabled' => $disabled]);
            $select = $this->addSymmetricAlgorithms($select);

            $table->add('title slime_options_title', html::label('encryption_algorithm', rcube::Q($this->slime->gettext('encryption_algorithm'))));
            $table->add(null, $select->show($preferences['slime_encryption_algorithm']));

            $options .= html::div(['class' => 'smime_options_title advanced', 'id' => 'slime_advanced'], html::tag('fieldset', ['class' => "advanced"],
                html::tag('legend', null, $this->slime->gettext('options_title_second')) 
                . html::div('collapse slime_collapse', 
                    $this->getDisableWeakOption($chbox, $preferences, $disabled)
                    . $this->getTrustLevelOption($chbox, $preferences, $disabled)
                    . $table->show($attrib)
                )
            ));

        }

        return $options;
    }

    /**
     * Adds symmetric algorithms as an selectable options to a select 
     * 
     * @param html_select $select Select element
     * 
     * @return html_select Select element with added options
     */ 

    function addSymmetricAlgorithms($select){
        foreach($this->slime->settings->supportedAlgs as $supportedAlg){

            // If algorithm is considered weak (set in config.inc)
            if(in_array($supportedAlg, $this->slime->settings->weakAlgs)){

                // Don't show weak algorithms when set
                if(!$this->slime->settings->disableWeakAlg){
                    $select->add($this->slime->gettext($supportedAlg) . " " . $this->slime->gettext('not_recommended'), $supportedAlg);
                }
            }

            //If algorithm is used for generating AuthEnvelopedData type
            else if(in_array($supportedAlg, $this->slime->settings->getAuthEnvelopedAlgList())){

                // Don't show AuthEnvelopedData algs when set
                if(!$this->slime->settings->disableAuthEnveloped){
                    $select->add($this->slime->gettext($supportedAlg), $supportedAlg);
                }
            }

            //If algorithm is used for generating EnvelopedData type
            else{

                // Don't show EnvelopedData algs in strict mode
                if(!$this->slime->settings->strictPolicy){
                    $select->add($this->slime->gettext($supportedAlg), $supportedAlg);
                }
            }
        }
        return $select;
    }

    /**
     * Support function for slime_options_form_elastic() handler
     * Disables option: 'Disable weak algorithms' if strict mode is set in config.inc
     * 
     * @param html_checkbox $chbox Checkbox element to be showed
     * @param array $preferences Current user settings
     * @param bool $disabled True if user set enable_plugin slider to off
     * 
     * @return string HTML content
     */ 

    function getDisableWeakOption($chbox, $preferences, $disabled){
        if(!$this->slime->settings->isInStrictMode()){
            return  html::div('form-group form-check row',
            html::label(['for' => 'slimedisableweak', 'class' => 'col-form-label col-6'],
                rcube::Q($this->slime->gettext('disable_weak'))
            )
            . html::div('form-check col-6',
                $chbox->show($preferences['slime_disable_weak'], [
                        'name'     => '_slime_disable_weak',
                        'id'       => 'slimedisableweak',
                        'disabled' => $disabled,
                    ])
                )
            );
        }
        else{
            return "";
        }
    }

    /**
     * Support function for slime_options_form_elastic() handler
     * 
     * @param html_checkbox $chbox Checkbox element to be showed
     * @param array $preferences Current user settings
     * @param bool $disabled True if user set enable_plugin slider to off
     * 
     * @return string HTML content
     */ 

    function getTrustLevelOption($chbox, $preferences, $disabled){
        return  html::div('form-group form-check row',
            html::label(['for' => 'slimetrustlevels', 'class' => 'col-form-label col-6'],
                rcube::Q($this->slime->gettext('trust_levels'))
            )
            . html::div('form-check col-6',
                $chbox->show($preferences['slime_trust_levels'], [
                        'name'     => '_slime_trust_levels',
                        'id'       => 'slimetrustlevels',
                        'disabled' => $disabled,
                    ])
                )
            );
    }

}