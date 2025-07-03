<?php

// Odeslat zprávu
$labels = [];
$labels['smime'] = 'S/MIME';
$labels['smime_hover'] = 'Odesílání zpráv S/MIME';
$labels['sign'] = 'Digitálně podepsat tuto zprávu';
$labels['encrypt'] = 'Zašifrovat tuto zprávu';
$labels['distribute'] = 'Připojit můj certifikát';

$labels['send_error_cert_missing'] = 'Odesílání selhalo! Nepodařilo se najít certifikát, který se shoduje s aktuální identitou!';
$labels['send_error_cert_invalid'] = 'Odesílání selhalo! Použitý certifikát je neplatný!';

$labels['sign_error_pkcs'] = 'Podepisování selhalo! Nepodařilo se najít PKCS#12 soubor, který se shoduje s aktuální identitou!';
$labels['sign_error_pk'] = 'Podepisování selhalo! Nepodařilo se najít soukromý klíč!';
$labels['sign_error'] = 'Podepisování selhalo! Nedefinovaná chyba!';

$labels['encrypt_error_efail'] = 'Šifrování HTML obsahu není bezpečné!';
$labels['encrypt_error_cert_rec'] = 'Šifrování selhalo! Nepodařilo se najít certifikát příjemce $recipient!';
$labels['encrypt_error_recipient_cert_invalid'] = 'Šifrování selhalo! Příjemce $recipient má neplatný certifikát!';
$labels['encrypt_error'] = 'Šifrování selhalo! Nedefinovaná chyba!';

$labels['distribute_error_pkcs'] = 'Připojení certifikátu selhalo! Nepodařilo se najít PKCS#12 soubor, který se shoduje s aktuální identitou!';

// Obdržet zprávu
$labels['cert_found'] = 'Tato zpráva obsahuje přiložený digitální certifikát';
$labels['cert_title'] = 'Importovat certifikát';

$labels['sig_found'] = 'Elektronický podpis obsahuje digitální certifikát.';

$messages['sig_valid'] = 'Ověřený elektronický podpis!';
$messages['sig_invalid'] = 'Neplatný elektronický podpis!';
$messages['sig_wrong_subject'] = 'Odesílatel zprávy není vlastníkem certifikátu uvnitř elektronického podpisu!';
$messages['sig_trust_level'] = 'Úroveň věrohodnosti $trust_level!';

$messages['dec_success'] = 'Zpráva byla úspěšně dešifrována!';
$messages['dec_failed'] = 'Dešifrování zprávy selhalo!';
$messages['dec_no_pkcs'] = 'Dešifrování zprávy selhalo! Soubor PKCS#12 nebyl nalezen!';
$messages['dec_html_content'] = 'Dešifrování zprávy selhalo! Dešifrování obsahu HTML je zakázáno!';
$messages['dec_weak_alg'] = 'Zpráva byla zašifrována slabým symetrickým algoritmem! Postupujte s obezřetností!';

// S/MIME sekce
$labels['settings'] = 'S/MIME nastavení';
$labels['myCerts'] = 'Moje certifikáty';
$labels['pubCerts'] = 'Veřejné certifikáty';
$labels['import'] = 'Importovat';
$labels['export'] = 'Exportovat';
$labels['delete'] = 'Smazání';
$labels['page_num'] = 'Strana $current_page z $max_page';
$labels['used'] = 'používaný';

// Nastavení S/MIME
$labels['options_title'] = 'Nastavení S/MIME';
$labels['options_title_first'] = 'Hlavní nastavení';
$labels['enable'] = 'Povolit S/MIME';
$labels['encrypt_every'] = 'Šifrovat všechny zprávy (pokud možno)';
$labels['sign_every'] = 'Podepsat všechny zprávy (pokud možno)';
$labels['import_signature'] = 'Import certifikátů skrze elektronický podpis';
$labels['import_every'] = 'Importovat doručené certifikáty automaticky';

$labels['options_title_second'] = 'Pokročilá nastavení';
$labels['html_encryption'] = 'Povolit šifrování obsahu HTML';
$labels['trust_levels'] = 'Zobrazovat úrovně důvěryhodnosti digitálních certifikátů';
$labels['disable_weak'] = 'Vypnout varování o slabých šifrách';

$labels['encryption_algorithm'] = 'Šifrovací algoritmus';
$labels['aes_128_cbc'] = 'AES-128-CBC';
$labels['aes_192_cbc'] = 'AES-192-CBC';
$labels['aes_256_cbc'] = 'AES-256-CBC';
$labels['aes_128_gcm'] = 'AES-128-GCM';
$labels['aes_192_gcm'] = 'AES-192-GCM';
$labels['aes_256_gcm'] = 'AES-256-GCM';
$labels['rc2_128'] = 'RC2-128';
$labels['3des'] = '3DES';
$labels['not_recommended'] = '(není doporučeno!)';

$labels['save'] = 'Uložit';

// Informace o certifikátu
$labels['cert_title'] = 'Informace o certifikátu';
$labels['certificate_title_first'] = 'Základní informace';
$labels['subject_name'] = 'Název subjektu';
$labels['alternative_identities'] = 'Alternativní identity';
$labels['serial_number'] = 'Sériové číslo';
$labels['valid_from'] = 'Platný od';
$labels['expires_on'] = 'Platný do';
$labels['certificate_authority'] = 'Certifikační autorita';
$labels['usage'] = 'Použití';
$labels['usage_sign'] = 'Elektronický podpis';
$labels['usage_encrypt'] = 'Šifrování';

$labels['certificate_title_second'] = 'Využité klíče';
$labels['algorithm_used'] = 'Využívané algoritmy';
$labels['key_size'] = 'Velikost klíče';
$labels['key_type'] = 'Typ klíče';
$labels['no_information'] = 'Žádné informace';
$labels['key_pair'] = 'Oba asymetrické klíče';
$labels['public_key'] = 'Veřejný klíč';
$labels['update_success'] = 'Nastavení S/MIME bylo uloženo!';

// Importovat certifikát
$labels['importcerts'] = 'Importovat certifikát';
$labels['import_success'] = 'Certifikát byl úspěšně importován!';
$labels['import_warning'] = '$error';
$labels['import_password_error'] = 'Nesprávné heslo!';
$labels['import_invalid_cert'] = 'Neplatný formát certifikátu!';
$labels['import_invalid_pkcs7'] = 'Neplatný formát PKCS#7!';
$labels['import_signature_failed'] = 'Nepovedlo se extrahovat certifikáty z elektronického podpisu!';
$labels['certificate_protected_title'] = 'Zadejte heslo';
$labels['certificate_protected'] = 'Tento certifikát je chráněn heslem. Zadejte ho pro úspěšné importování.';
$labels['import_file_not_supported'] = 'Tento typ soubor není podporován!';
$labels['import_file_no_pem'] = 'Certifikát není v PEM formátu!';
$labels['import_email_not_present'] = 'Certifikát neobsahuje žádný e-mail!';

$labels['import_info'] = 'Všechny certifikáty jsou bezpečně ukládány na serveru.';
$labels['import_description'] = 'Můžete vkládat soubory PKCS#12 či veřejné certifikáty ve formátu PEM.';

// Smazat certifikát
$messages['cert_delete_msg'] = 'Jste si jist, že chcete smazat zvolený certifikát?';
$messages['cert_delete_title'] = 'Odstranění certifikátu';
$messages['delete_success'] = 'Certifikát byl úspěrně odstraněn';
$messages['delete_fail'] = 'Certifikát se nepodařilo odstranit';

// Exportovat certifikát
$labels['exportcerts'] = 'Exportovat certifikát';
$labels['export_msg'] = 'Chcete exportovat pouze certifikát nebo certifikát se soukromým klíčem v podobě souboru PKCS#12?';
$labels['export_crt'] = 'Exportovat pouze certifikát';
$labels['export_pkcs12'] = 'Exportovat soubor PKCS#12';
$labels['export_password_title'] = 'Vytvořte heslo';
$labels['export_password'] = 'Vytvořte heslo pro soubor PKCS#12.';

// Verifikovat certifikát
$labels['verify_certificate'] = 'Vydaný certifikát';
$labels['verify_intermediate'] = 'Zprostředkovávající CA';
$labels['verify_undefined_error'] = 'Nedefinovaná chyba verifikace certifikátu!';
$labels['verify_incomplete_certificate_path'] = 'Nepodařilo se sestavit certifikační cestu!';
