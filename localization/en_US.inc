<?php
// If date formating for other languages is not working properly
// it is neccesary to 

// Send a message 
$labels = [];
$labels['smime'] = 'S/MIME';
$labels['smime_hover'] = 'Composing S/MIME messages';
$labels['sign'] = 'Digitally sign this message';
$labels['encrypt'] = 'Encrypt this message';
$labels['distribute'] = 'Attach my certificate';

$labels['send_error_cert_invalid'] = 'Sending failed! Used certificate is invalid!';

$labels['sign_error_pkcs'] = 'Signing failed! Unable to find a PKCS#12 file!';
$labels['sign_error_pk'] = 'Signing failed! Unable to find a private key!';
$labels['sign_error_cert'] = 'Signing failed! Unable to find a certificate!';
$labels['sign_error'] = 'Signing failed! Undefined error!';

$labels['encrypt_error_efail'] = 'Encrypting HTML content is not safe!';
$labels['encrypt_error_cert'] = 'Encryption failed! Unable to find certificate your certificate!';
$labels['encrypt_error_cert_rec'] = 'Encryption failed! Unable to find a certificate of the recipient $recipient!';
$labels['encrypt_error_recipient_cert_invalid'] = 'Encryption failed! Recipient $recipient has an invalid certificate!';
$labels['encrypt_error'] = 'Encryption failed! Undefined error!';

$labels['distribute_error_pkcs'] = 'Attaching certificate failed! Unable to find a PKCS#12 file!';
$labels['distribute_error_cert'] = 'Attaching certificate failed! Unable to find a certificate!';

// Receive a message

$labels['cert_found'] = 'This message contains attached digital certificate.';
$labels['cert_title'] = 'Import a certificate';

$messages['sig_valid'] = 'Verified signature!';
$messages['sig_invalid'] = 'Invalid signature!';

$messages['dec_success'] = 'Message decrypted successfully!';
$messages['dec_failed'] = 'Message decryption failed!';
$messages['dec_no_pkcs'] = 'Message decryption failed! PKCS#12 file was not found!';
$messages['dec_weak_alg'] = 'Weak symmetric algorithm was used! Proceed with caution!';

// S/MIME settings
$labels['settings'] = 'S/MIME settings';
$labels['myCerts'] = 'My certificates';
$labels['pubCerts'] = 'Public certificates';
$labels['import'] = 'Import';
$labels['export'] = 'Export';
$labels['delete'] = 'Delete';
$labels['page_num'] = 'Page $current_page of $max_page';
$labels['used'] = 'used';

// S/MIME settings
$labels['options_title'] = 'S/MIME settings';
$labels['options_title_first'] = 'Main Options';
$labels['enable'] = 'Enable S/MIME';
$labels['encrypt_every'] = 'Encrypt every message (if possible)';
$labels['sign_every'] = 'Sign every message (if possible)';
$labels['import_every'] = 'Import all received certificates';

$labels['options_title_second'] = 'Advanced Options';
$labels['disable_weak'] = 'Disable weak cipher warnings';

$labels['encryption_algorithm'] = 'Encryption algorithm';
$labels['aes_128_cbc'] = 'AES-128-CBC';
$labels['aes_192_cbc'] = 'AES-192-CBC';
$labels['aes_256_cbc'] = 'AES-256-CBC';
$labels['aes_128_gcm'] = 'AES-128-GCM';
$labels['aes_192_gcm'] = 'AES-192-GCM';
$labels['aes_256_gcm'] = 'AES-256-GCM';
$labels['rc2_128'] = 'RC2-128';
$labels['3des'] = '3DES';
$labels['not_recommended'] = '(not recommended!)';

$labels['save'] = 'Save';

// Certificate information
$labels['cert_title'] = 'Certificate information';
$labels['certificate_title_first'] = 'Basic information';
$labels['subject_name'] = 'Subject name';
$labels['serial_number'] = 'Serial Number';
$labels['valid_from'] = 'Valid from';
$labels['expires_on'] = 'Expires on';
$labels['certificate_authority'] = 'Certificate Authority';
$labels['usage'] = 'Usage';
$labels['usage_sign'] = 'Digital Signature';
$labels['usage_encrypt'] = 'Key Encipherment';

$labels['certificate_title_second'] = 'Keys used';
$labels['algorithm_used'] = 'Algorithms used';
$labels['key_size'] = 'Key size';
$labels['key_type'] = 'Key type';
$labels['no_information'] = 'No information';
$labels['key_pair'] = 'Key pair';
$labels['public_key'] = 'Public key';
$labels['update_success'] = 'S/MIME options were saved!';

// Import certificate
$labels['importcerts'] = 'Import a certificate';
$labels['import_success'] = 'The certificate was imported successfully!';
$labels['import_warning'] = '$error';
$labels['import_password_error'] = 'Incorrect password!';
$labels['import_invalid_cert'] = 'Invalid certificate format!';
$labels['import_invalid_pkcs7'] = 'Invalid PKCS#7 format!';
$labels['certificate_protected_title'] = 'Enter a password';
$labels['certificate_protected'] = 'The certificate is protected by a password. Please enter the password to import it.';
$labels['import_file_not_supported'] = 'This file type is not supported!';
$labels['import_file_no_pem'] = 'Certificate is not in PEM format!';

$labels['import_info'] = 'All certificates are stored safely on the server.';
$labels['import_description'] = 'You can import PKCS#12 files or public certificates in PEM format.';

// Delete certificate
$labels['deletecerts'] = 'Delete a certificate';

$messages['cert_delete_msg'] = 'Are you sure, you want to delete selected certificate?';
$messages['cert_delete_title'] = 'Removing a certificate';
$messages['delete_success'] = 'Certificate was deleted successfully';
$messages['delete_fail'] = 'Certificate could not be deleted';

// Export certificate
$labels['exportcerts'] = 'Export a certificate';
$labels['export_msg'] = 'Do you want to export only certificate or both certificate and its private key as PKCS#12 file?';
$labels['export_crt'] = 'Export certificate only';
$labels['export_pkcs12'] = 'Export PKCS#12 file';
$labels['export_password_title'] = 'Create a password';
$labels['export_password'] = 'Create a password for your PCKS#12 file.';

// Verify certificate
$labels['verify_certificate'] = 'Certificate issued';
$labels['verify_intermediate'] = 'Intermediate CA';
$labels['verify_undefined_error'] = 'Undefined verification error occured!';
$labels['verify_incomplete_certificate_path'] = 'Unable to form a certificate path!';
