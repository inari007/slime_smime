rcmail.addEventListener('init', function(evt) {
    
  const gui = rcmail.gui_objects;
  const env = rcmail.env;

  if(env.task == 'settings'){
    if(gui.mycertslist && gui.othercertslist){
        rcmail.mycertslist = new rcube_list_widget(gui.mycertslist,
            {multiselect:false, draggable:false, keyboard:true});
        rcmail.mycertslist.init().focus();
    
        rcmail.othercertslist = new rcube_list_widget(gui.othercertslist,
            {multiselect:false, draggable:false, keyboard:true});
        rcmail.othercertslist.init().focus();

        $(document).ready(function () {
            rcmail.slime_certs();
        });

        rcmail.register_command('firstpage', function() { rcmail.slime_change_page((x) => 1); });
        rcmail.register_command('lastpage', function() { rcmail.slime_change_page((x) => -1); });
        rcmail.register_command('previouspage', function() { rcmail.slime_change_page((x) => x - 1); });
        rcmail.register_command('nextpage', function() { rcmail.slime_change_page((x) => x + 1); });
    }

    if(rcmail.env.action == 'plugin.slime_settings_section'){
        rcmail.register_command('plugin.slime-cert-import', function() { rcmail.slime_open_import_window(); }, true);
        rcmail.register_command('plugin.slime-import', function() { rcmail.slime_import(); }, true);
        rcmail.register_command('plugin.slime-cert-delete', function() { rcmail.slime_delete(); });
        rcmail.register_command('plugin.slime-cert-export', function() { rcmail.slime_open_export(); });
        rcmail.register_command('plugin.slime-option-save', function() { rcmail.slime_save_options(); }, true);

        rcmail.addEventListener('plugin.slime_certificate_password_not_req', function() {rcmail.slime_open_export(); });

        $(".slime_section_item").on("click", function() {SelectItem(this);});
        $(".certificates_title").on("click", function() {ExpandItem(this);});
       
        $("#slime_options_button").on("click", function() {rcmail.slime_open_options();});
        $("#slime_advanced").find("legend:first").on("click", function() {rcmail.slime_open_advanced();});
        $("#slime_options_save").prop("disabled", false);

        $('.slime_slider_option').on('change', function() {ClickSliderOptions(this)});

    }
}
    else if(env.task == 'mail'){
        $('.slime_slider_send').on('change', function() {ClickSliderSend(this)});
        $('#slime_menu').find('input,label').mouseup(function(e) {e.stopPropagation();});
    }

    const observer = new MutationObserver((mutationsList) => {
        for (const mutation of mutationsList) {
            if (mutation.type === 'attributes' && mutation.attributeName === 'class') {
                changeBetweenLightDarkMode(mutation.target.classList.contains('dark-mode'));
            }
        }
    });

    observer.observe(document.documentElement, {
        attributes: true,
        attributeFilter: ['class'] 
    });

    changeBetweenLightDarkMode(document.documentElement.classList.contains('dark-mode'));

    function changeBetweenLightDarkMode(isDark) {
        if(isDark){
            $("#my_certificates_item").removeClass('slime_smime_my_certificates_item_light').addClass('slime_smime_my_certificates_item_dark');
            $("#public_certificates_item").removeClass('slime_smime_public_certificates_item_light').addClass('slime_smime_public_certificates_item_dark');
            $("#smime_section").removeClass('smime_section_light').addClass('smime_section_dark');
            $('.certificates_title').removeClass('certificates_title_light').addClass('certificates_title_dark');
        }
        else{
            $("#my_certificates_item").removeClass('slime_smime_my_certificates_item_dark').addClass('slime_smime_my_certificates_item_light');
            $("#public_certificates_item").removeClass('slime_smime_public_certificates_item_dark').addClass('slime_smime_public_certificates_item_light');
            $("#smime_section").removeClass('smime_section_dark').addClass('smime_section_light');
            $('.certificates_title').removeClass('certificates_title_dark').addClass('certificates_title_light');
        }
    }

rcube_webmail.prototype.slime_import_attachment = function(mimeID, isSignature){
    var lock = this.set_busy(true, 'loading');
    var post = {_uid: this.env.uid, _attachment: mimeID, _isSignature: isSignature};

    this.http_post('plugin.slime.import_certificate', post, lock);
};

rcube_webmail.prototype.slime_save_options = function(){
    settings = {
        "_a": "update_settings", 
        "_slime_enable" : $("#slimeenable").prop('checked'),
        "_slime_sign_every" : $("#slimesignevery").prop('checked'),
        "_slime_encrypt_every" : $("#slimeencryptevery").prop('checked'),
        "_slime_import_signature" : $("#slimeimportsignature").prop('checked'),
        "_slime_import_all" : $("#slimeimportevery").prop('checked'),
        "_slime_html_encryption" : $("#slimehtmlencryption").prop('checked'),
        "_slime_trust_levels" : $("#slimetrustlevels").prop('checked'),
        "_slime_disable_weak" : $("#slimedisableweak").prop('checked'),
        "_slime_encryption_algorithm" : $("#slime_encryption_algorithm").val(),
    };
    var lock = this.set_busy(true, 'loading');
    this.http_post('plugin.slime_settings_section', settings, lock);
}


rcube_webmail.prototype.slime_open_export = function(){
    var item = $('.slime_section_item.selected:first');
    var isOld = $(item).hasClass('isOld_True') ? "True" : "False";
    var extension = item.data("extension");

    // if target includes a private key
    if($("#my_certs-table").has(item).length > 0){
        return this.show_popup_dialog(
            this.get_label('slime_smime.export_msg'),
            this.get_label('slime_smime.exportcerts'),
            [{
                'class': 'export mainaction',
                text: this.get_label('slime_smime.export_crt'),
                click: function(e) {
                    rcmail.slime_export(item, "pkcs_crt", null, isOld, extension);
                    $(this).remove();
                }
            },
            {
                'class': 'export',
                text: this.get_label('slime_smime.export_pkcs12'),
                click: function(e) {
                    rcmail.slime_export_password(item, "pkcs_secured", isOld, extension);
                    $(this).remove();
                }
            },
            {
                'class': 'cancel',
                text: this.get_label('close'),
                click: function(e) {
                    $(this).remove();
                }
            }],
            {width: 500}
        );
    };
    rcmail.slime_export(item, "crt", null, isOld, extension);
}

rcube_webmail.prototype.slime_export = function(item, typeOfExport, password = null, isOld, extension){
    var id = 'certexport-' + new Date().getTime();

    var form = $('<form>').attr({target: id, method: 'post', style: 'display:none',
            action: '?_action=plugin.slime_settings_section&_a=export'});
    var iframe = $('<iframe>').attr({name: id, style: 'display:none'});
        form.addClass('slimeExportForm');

    form.append($('<input>').attr({name: "_id", value: $(item).attr("id")}));
    form.append($('<input>').attr({name: "_exportType", value: typeOfExport}));
    form.append($('<input>').attr({name: "_isOld", value: isOld}));
    form.append($('<input>').attr({name: "_extension", value: extension}));
    if(password != null){
        form.append($('<input>').attr({name: "_passwd", value: password}));
    }
    iframe.appendTo(document.body);
    form.appendTo(document.body).submit();
};

rcube_webmail.prototype.slime_export_password = function(item, typeOfExport, isOld, extension){
    var params = {'_a': "export_password", "_id": $(item).attr("id"), "_exportType": typeOfExport, "_isOld": isOld, "_extension": extension};
    var lock = this.set_busy(true, 'loading');
    this.http_post('plugin.slime_settings_section', params, lock);
};

rcube_webmail.prototype.remove_cert = function(){
    rcmail.slime_certs();
    this.enable_command('plugin.slime-cert-delete', 'plugin.slime-cert-export', false);
};

rcube_webmail.prototype.slime_delete = function(){
    var item = $('.slime_section_item.selected:first');

    var itemDelType = $("#my_certs-table").has(item).length > 0 ? "pkcs12" : "crt";
    var isOld = $(item).hasClass('isOld_True') ? "True" : "False";
    var extension = item.data("extension");

    this.confirm_dialog(this.get_label('slime_smime.cert_delete_msg'), 'delete', function(e, ref) {
        var lock = ref.display_message(ref.get_label('slime_smime.cert_delete_title'), 'loading');
        var post = {_a: 'delete', _id: $(item).attr("id"), _type: itemDelType, _isOld: isOld, _extension: extension};

        ref.http_post('plugin.slime_settings_section', post, lock);
    });
};

rcube_webmail.prototype.slime_add_certs_to_list = function(r){
    if(!gui.othercertslist || !gui.mycertslist || !this.mycertslist || !this.othercertslist){
        return false;
    }

    var list;
    if(r.type == "crt"){
        list = this.othercertslist;
    }
    else{
        list = this.mycertslist;
    }
    var row = document.createElement('tr');
    var col = document.createElement('td');

    row.id = r.id;
    row.className = 'message slime_section_item isOld_' + r.isOld;
    row.dataset.extension = r.type;

    col.className = 'name certItem';
    col.innerText = r.isUsed ? r.name + " [" + this.get_label("slime_smime.used") + "]" : r.name;
    row.appendChild(col);
    row.addEventListener('click', function() {rcmail.slime_cert_select(this, r.type, r.isOld);});
    list.insert_row(row);
};

rcube_webmail.prototype.slime_certs = function(){

    if(this.is_framed()){
        return parent.rcmail.slime_certs();
    }

    var params = {'_a': "certs", '_page' : this.env.current_page};
    var lock = this.set_busy(true, 'loading');

    if(this.mycertslist){
        this.mycertslist.clear(true);
    }
    if(this.othercertslist){
        this.othercertslist.clear(true);
    }

    if(!this.env.current_page){
        this.env.current_page = 1;
    }

    this.triggerEvent('listupdate', {list: this.mycertslist});
    this.triggerEvent('listupdate', {list: this.othercertslist});
    this.http_post('plugin.slime_settings_section', params, lock);
};

rcube_webmail.prototype.slime_change_page = function(operation){
    var curPage = this.env.current_page;
    var maxPage = this.env.pagecount;

    let pageNum = operation(curPage);
    if(pageNum == -1){
        pageNum = maxPage;
    }
    else if(pageNum == 0){
        pageNum = 1;
    }
    else if(maxPage < pageNum){
        pageNum = maxPage;
    }

    this.env.current_page = pageNum;
    this.slime_certs();
};

rcube_webmail.prototype.slime_cert_select = function(item, type, isOld){     
    var win;
    var url = '&_action=plugin.slime_settings_section&_a=info&_id=' + $(item).attr("id") + '&_type=' + type + '&_isOld=' + isOld;

    if (win = this.get_frame_window(this.env.contentframe)) {
        if (!url) {
            if (win.location && win.location.href.indexOf(this.env.blankpage) < 0)
                win.location.href = this.env.blankpage;
            if (this.env.frame_lock)
                this.set_busy(false, null, this.env.frame_lock);
            return;
        }

        this.env.frame_lock = this.set_busy(true, 'loading');
        win.location.href = this.env.comm_path + '&_framed=1' + url;
    }
    this.enable_command('plugin.slime-cert-delete', 'plugin.slime-cert-export', true);
    SelectItem(item);
};

function SelectItem(item) {
    $(".slime_section_item").not(item).removeClass("selected focused");
    $(item).addClass("selected focused");
}

function ExpandItem(item){
    $(item).toggleClass("certificates_title_expanded");
    if($(item).attr("id") == "slime_my_certificates_button"){
        $("#my_certs-table").toggleClass("hidden");
    }
    else{
        $("#other_certs-table").toggleClass("hidden");
    }
}

function ClickSliderOptions(item){
    if(item.id == 'slimeenable'){
        disabled_buttons = !$('#slimesignevery').prop('disabled');
        $('.slime_slider_option').not('#slimeenable').prop('disabled', disabled_buttons);
        $('.slime_options_select').prop('disabled', disabled_buttons);
    }
}

function ClickSliderSend(item){
    if(item.id == 'slimedistribute'){
        disabled_buttons = !$('#slimesign').prop('disabled');
        $('.slime_slider_send').not('#slimedistribute').prop('disabled', disabled_buttons);
    }
}

rcube_webmail.prototype.slime_open_advanced = function(){
    $("#slime_advanced").find(".collapse:first").toggleClass("show");
}

rcube_webmail.prototype.slime_open_options = function(){
    var win;
    let url = "&_action=plugin.slime_settings_section&_a=options";

    if (win = this.get_frame_window(this.env.contentframe)) {
        if (!url) {
            if (win.location && win.location.href.indexOf(this.env.blankpage) < 0)
                win.location.href = this.env.blankpage;
            if (this.env.frame_lock)
                this.set_busy(false, null, this.env.frame_lock);
            return;
        }

        this.env.frame_lock = this.set_busy(true, 'loading');
        win.location.href = this.env.comm_path + '&_framed=1' + url;
    }
    this.enable_command('plugin.slime-cert-delete', 'plugin.slime-cert-export', false);
}

rcube_webmail.prototype.slime_open_import_window = function(){
    var dialog = $('<iframe>').attr('src', this.url('plugin.slime_settings_section', {_a: 'import', _framed: 1})),
        import_func = function(e) {
            var win = dialog[0].contentWindow;
            win.rcmail.slime_import();
        };

    this.slime_import_dialog = this.simple_dialog(dialog, 'slime_smime.importcerts', import_func, {
        button: 'import',
        width: 500,
        height: 180
    });
};

rcube_webmail.prototype.slime_import = function(){
    var form = gui.importform;
    var id = 'certimport-' + new Date().getTime();
    var file = document.getElementById('slimemimportfile');
    if (file && !file.value) {
        this.alert_dialog(this.get_label('selectimportfile'));
        return;
    }
    var lock = this.set_busy(true, 'importwait');
    $('<iframe>').attr({name: id, style: 'display:none'}).appendTo(document.body);
    $(form).attr({target: id, action: this.add_url(form.action, '_unlock', lock)}).submit();
    return true;
};

rcube_webmail.prototype.slime_import_success = function(){
    var dialog = this.slime_import_dialog || parent.rcmail.slime_import_dialog;
    dialog.dialog('destroy');
};

rcube_webmail.prototype.slime_certificate_password = function(r){
    var ref = this;
    var msg = r.type == "import" ? this.get_label('slime_smime.certificate_protected') : this.get_label('slime_smime.export_password');
    var myprompt = $('<div class="prompt">'),
    myprompt_content = $('<p class="message">')
        .appendTo(myprompt),
    myprompt_input = $('<input>').attr({type: 'password', size: 30, 'data-submit': 'true'})
        .appendTo(myprompt);

    myprompt_content.text(msg);

    this.show_popup_dialog(myprompt, this.get_label(r.type == "import" ? 'slime_smime.certificate_protected_title' : 'slime_smime.export_password_title'),
        [{
            text: this.get_label('ok'),
            'class': 'mainaction save unlock',
            click: function(e) {
                e.stopPropagation();

                var jq = ref.is_framed() ? window.parent.$ : $;

                var password = myprompt_input.val();

                if (!password) {
                    myprompt_input.focus();
                    return;
                }

                ref.slime_password_submit(password, r.type, r.isOld, r.extension);
                jq(this).remove();
            }
        },
        {
            text: this.get_label('cancel'),
            'class': 'cancel',
            click: function(e) {
                var jq = ref.is_framed() ? window.parent.$ : $;
                e.stopPropagation();
                jq(this).remove();
            }
        }], {width: 400});
};

rcube_webmail.prototype.slime_password_submit = function(password, type, isOld, extension){
    if(type == "import"){
        var form = this.gui_objects.importform;

        $(form).append($('<input>').attr({type: 'hidden', name: '_passwd', value: password}));
        return this.slime_import();
    }
    else{
        var item = $('.slime_section_item.selected:first');
        rcmail.slime_export(item, "pkcs_secured", password, isOld, extension);
    }

};

  });