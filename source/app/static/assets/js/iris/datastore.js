var ds_filter;

function load_datastore() {

    ds_filter = ace.edit("ds_file_search",
    {
        autoScrollEditorIntoView: true,
        minLines: 1,
        maxLines: 5
    });
    ds_filter.setTheme("ace/theme/tomorrow");
    ds_filter.session.setMode("ace/mode/json");
    ds_filter.renderer.setShowGutter(false);
    ds_filter.setShowPrintMargin(false);
    ds_filter.renderer.setScrollMargin(10, 10);
    ds_filter.setOption("displayIndentGuides", true);
    ds_filter.setOption("indentedSoftWrap", true);
    ds_filter.setOption("showLineNumbers", false);
    ds_filter.setOption("placeholder", "Search files");
    ds_filter.setOption("highlightActiveLine", false);
    ds_filter.commands.addCommand({
            name: "Do filter",
            bindKey: { win: "Enter", mac: "Enter" },
            exec: function (editor) {
                      filter_ds_files();
            }
    });

    get_request_api('/datastore/list/tree')
    .done(function (data){
        if(notify_auto_api(data, true)){
            $('#ds-tree-root').empty();
            build_ds_tree(data.data, 'ds-tree-root');
            reparse_activate_tree();
            show_datastore();
        }
    });
}

function build_ds_tree(data, tree_node) {

    var standard_files_filters = [
                {value: 'name: ', score: 10, meta: '匹配文件名'},
                {value: 'storage_name: ', score: 10, meta: '匹配本地存储文件名'},
                {value: 'tag: ', score: 10, meta: '匹配文件标签'},
                {value: 'description: ', score: 10, meta: '匹配文件描述'},
                {value: 'is_ioc: ', score: 10, meta: "匹配文件是IOC"},
                {value: 'is_evidence: ', score: 10, meta: "匹配文件是证据"},
                {value: 'has_password: ', score: 10, meta: "匹配文件是密码保护"},
                {value: 'id: ', score: 10, meta: "匹配文件ID"},
                {value: 'uuid: ', score: 10, meta: "匹配文件UUID"},
                {value: 'sha256: ', score: 10, meta: "匹配文件sha256"},
                {value: 'AND ', score: 10, meta: 'AND操作符'}
              ]

    for (node in data) {

        if (data[node] === null) {
            break;
        }

        if (data[node].type == 'directory') {
            data[node].name = sanitizeHTML(data[node].name);
            can_delete = '';
            if (!data[node].is_root) {
                can_delete = `<div class="dropdown-divider"></div><a href="#" class="dropdown-item text-danger" onclick="delete_ds_folder('${node}');"><small class="fa fa-trash mr-2"></small>删除</a>`;
            }
            jnode = `<li>
                    <span id='${node}' title='Folder ID ${node}' data-node-id="${node}"><i class="fa-regular fa-folder"></i> ${sanitizeHTML(data[node].name)}</span> <i class="fas fa-plus ds-folder-menu" role="menu" style="cursor:pointer;" data-toggle="dropdown" aria-expanded="false"></i>
                        <div class="dropdown-menu" role="menu">
                                <a href="#" class="dropdown-item" onclick="add_ds_folder('${node}');return false;"><small class="fa-solid fa-folder mr-2"></small>添加子文件夹</a>
                                <a href="#" class="dropdown-item" onclick="add_ds_file('${node}');return false;"><small class="fa-solid fa-file mr-2"></small>添加文件</a>
                                <a href="#" class="dropdown-item" onclick="add_ds_multi_files('${node}');return false;"><small class="fa-solid fa-file-circle-plus fa-box mr-2"></small>添加多个文件</a>
                                <div class="dropdown-divider"></div>
                                <a href="#" class="dropdown-item" onclick="move_ds_folder('${node}');return false;"><small class="fa fa-arrow-right-arrow-left mr-2"></small>移动</a>
                                <a href="#" class="dropdown-item" onclick="rename_ds_folder('${node}', '${sanitizeHTML(data[node].name)}');return false;"><small class="fa-solid fa-pencil mr-2"></small>重命名</a>
                                ${can_delete}
                        </div>
                    <ul id='tree-${node}'></ul>
                </li>`;
            $('#'+ tree_node).append(jnode);
            build_ds_tree(data[node].children, 'tree-' + node);
        } else {
            data[node].file_original_name = sanitizeHTML(data[node].file_original_name);
            data[node].file_password = sanitizeHTML(data[node].file_password);
            data[node].file_description = sanitizeHTML(data[node].file_description);
            standard_files_filters.push({
                value: data[node].file_original_name,
                score: 1,
                meta: data[node].file_description
            });
            icon = '';
            if (data[node].file_is_ioc) {
                icon += '<i class="fa-solid fa-virus-covid text-danger mr-1" title="文件是IOC"></i>';
            }
            if (data[node].file_is_evidence) {
                icon += '<i class="fa-solid fa-file-shield text-success mr-1" title="文件是证据"></i>';
            }
            if (icon.length === 0) {
                icon = '<i class="fa-regular fa-file mr-1" title="常规文件"></i>';
            }
            icon_lock = '';
            has_password = data[node].file_password !== null && data[node].file_password.length > 0;
            if (has_password) {
                icon_lock = '<i title="密码保护" class="fa-solid fa-lock text-success mr-1"></i>'
            }
            icn_content = btoa(icon + icon_lock);
            jnode = `<li>
                <span id='${node}' data-file-id="${node}" title="ID : ${data[node].file_id}\nUUID : ${data[node].file_uuid}" class='tree-leaf'>
                      <span role="menu" style="cursor:pointer;" data-toggle="dropdown" aria-expanded="false">${icon}${icon_lock} ${sanitizeHTML(data[node].file_original_name)}</span>
                      <i class="fa-regular fa-circle ds-file-selector" style="cursor:pointer;display:none;" onclick="ds_file_select('${node}');"></i>
                        <div class="dropdown-menu" role="menu">
                                <a href="#" class="dropdown-item" onclick="get_link_ds_file('${node}');return false;"><small class="fa fa-link mr-2"></small>链接</a>
                                <a href="#" class="dropdown-item" onclick="get_mk_link_ds_file('${node}', '${toBinary64(data[node].file_original_name)}', '${icn_content}', '${has_password}');return false;"><small class="fa-brands fa-markdown mr-2"></small>Markdown链接</a>
                                <a href="#" class="dropdown-item" onclick="download_ds_file('${node}');return false;"><small class="fa-solid fa-download mr-2"></small>下载</a>
                                <div class="dropdown-divider"></div>
                                <a href="#" class="dropdown-item" onclick="info_ds_file('${node}');return false;"><small class="fa fa-eye mr-2"></small>信息</a>
                                <a href="#" class="dropdown-item" onclick="edit_ds_file('${node}');return false;"><small class="fa fa-pencil mr-2"></small>编辑</a>
                                <a href="#" class="dropdown-item" onclick="move_ds_file('${node}');return false;"><small class="fa fa-arrow-right-arrow-left mr-2"></small>移动</a>
                                <div class="dropdown-divider"></div>
                                <a href="#" class="dropdown-item text-danger" onclick="delete_ds_file('${node}');"><small class="fa fa-trash mr-2"></small>删除</a>
                        </div>
                    </span>
                </li>`;
            $('#'+ tree_node).append(jnode);
        }
    }
    ds_filter.setOptions({
          enableBasicAutocompletion: [{
            getCompletions: (editor, session, pos, prefix, callback) => {
              callback(null, standard_files_filters);
            },
          }],
          enableLiveAutocompletion: true,
    });
}

function show_datastore() {
    $('html').addClass('ds_sidebar_open');
    $('.ds-sidebar-toggler').addClass('toggled');
}

function hide_datastore() {
    $('html').removeClass('ds_sidebar_open');
    $('.ds-sidebar-toggler').removeClass('toggled');
}

function reparse_activate_tree() {
    $('.tree li:has(ul)').addClass('parent_li').find(' > span').attr('title', '折叠此分支');
    $('.tree li.parent_li > span').on('click', function (e) {
        var children = $(this).parent('li.parent_li').find(' > ul > li');
        if (children.is(":visible")) {
            children.hide('fast');
            $(this).attr('title', '展开此分支').find(' > i').addClass('icon-plus-sign').removeClass('icon-minus-sign');
        } else {
            children.show('fast');
            $(this).attr('title', '折叠此分支').find(' > i').addClass('icon-minus-sign').removeClass('icon-plus-sign');
        }
        e.stopPropagation();
    });
}

function add_ds_folder(parent_node) {
    $('#ds_mod_folder_name').data('parent-node', parent_node);
    $('#ds_mod_folder_name').data('node-update', false);
    $('#ds_mod_folder_name').val('');
    $('#modal_ds_folder').modal("show");
}

function rename_ds_folder(parent_node, name) {
    $('#ds_mod_folder_name').data('parent-node', parent_node);
    $('#ds_mod_folder_name').data('node-update', true);
    $('#ds_mod_folder_name').val(name);
    $('#modal_ds_folder').modal("show");
}

function delete_ds_folder(node) {
    node = node.replace('d-', '');
    swal({
        title: "你确定吗?",
        text: "这将删除包括在内的所有文件和子文件夹",
        icon: "warning",
        buttons: true,
        dangerMode: true,
        confirmButtonColor: '#3085d6',
        cancelButtonColor: '#d33',
        confirmButtonText: '是,删除它!'
    })
    .then((willDelete) => {
        if (willDelete) {
           var data_sent = {
                "csrf_token": $('#csrf_token').val()
            }
            post_request_api('/datastore/folder/delete/' + node, JSON.stringify(data_sent))
            .done((data) => {
                if (notify_auto_api(data)) {
                    reset_ds_file_view();
                    load_datastore();
                }
            });
        } else {
            swal("Pfew，好险");
        }
    });
}

function save_ds_mod_folder() {
    var data = Object();

    data['parent_node'] = $('#ds_mod_folder_name').data('parent-node').replace('d-', '');
    data['folder_name'] =  $('#ds_mod_folder_name').val();
    data['csrf_token'] = $('#csrf_token').val();

    if ($('#ds_mod_folder_name').data('node-update')) {
        uri = '/datastore/folder/rename/' + data['parent_node'];
    } else {
        uri = '/datastore/folder/add';
    }

    post_request_api(uri, JSON.stringify(data))
    .done(function (data){
        if(notify_auto_api(data)){
            $('#modal_ds_folder').modal("hide");
            load_datastore();
        }
    });
}

function add_ds_file(node) {
    node = node.replace('d-', '');
    let url = '/datastore/file/add/'+ node +'/modal' + case_param();
    $('#modal_ds_file_content').load(url, function (response, status, xhr) {
        if (status !== "success") {
             ajax_notify_error(xhr, url);
             return false;
        }

        $('#modal_ds_file').modal("show");
    });
}

function add_ds_multi_files(node) {
    node = node.replace('d-', '');
    let url = '/datastore/file/add/'+ node +'/multi-modal' + case_param();
    $('#modal_ds_file_content').load(url, function (response, status, xhr) {
        if (status !== "success") {
             ajax_notify_error(xhr, url);
             return false;
        }

        $('#modal_ds_file').modal("show");
    });
}

function edit_ds_file(node) {
    node = node.replace('f-', '');
    url = '/datastore/file/update/'+ node +'/modal' + case_param();
    $('#modal_ds_file_content').load(url, function (response, status, xhr) {
        if (status !== "success") {
             ajax_notify_error(xhr, url);
             return false;
        }

        $('#modal_ds_file').modal("show");
    });
}

function info_ds_file(node) {
    node = node.replace('f-', '');
    url = '/datastore/file/info/'+ node +'/modal' + case_param();
    $('#modal_ds_file_content').load(url, function (response, status, xhr) {
        if (status !== "success") {
             ajax_notify_error(xhr, url);
             return false;
        }

        $('#modal_ds_file').modal("show");
    });
}

async function save_ds_multi_files(node, index_i) {
    let formData = new FormData($('#form_new_ds_files')[0]);
    let totalFiles = $('#input_upload_ds_files').prop('files').length;
    let index = index_i === undefined ? 0 : index_i;
    if (index >= totalFiles) {
        window.swal.close();
        $('#modal_ds_file').modal("hide");
        return;
    }
    let file = $('#input_upload_ds_files').prop('files')[index];
    formData.append('file_content', file);
    formData.append('file_original_name', file.name);
    let uri = '/datastore/file/add/' + node;
    await post_request_data_api(uri, formData, true, function () {
        window.swal({
            title: `文件 ${file.name} 正在上传. (${index}/${totalFiles} 文件)`,
            text: "请稍候.文件上传后,此窗口将自动关闭",
            icon: "/static/assets/img/loader.gif",
            button: false,
            allowOutsideClick: false
        });
    }).then((data) => {
        notify_auto_api(data);
        index += 1;
        save_ds_multi_files(node, index);
        load_datastore();
    }).always((data) => {
        window.swal.close();
    });
}

function save_ds_file(node, file_id) {
    var formData = new FormData($('#form_new_ds_file')[0]);
    formData.append('file_content', $('#input_upload_ds_file').prop('files')[0]);
    let uri = '';

    if (file_id === undefined) {
        uri = '/datastore/file/add/' + node;
    } else {
        uri = '/datastore/file/update/' + file_id;
    }

    post_request_data_api(uri, formData, true, function() {
        window.swal({
              title: "文件正在上传",
              text: "请稍候.文件上传后,此窗口将自动关闭.",
              icon: "/static/assets/img/loader.gif",
              button: false,
              allowOutsideClick: false
        });
    })
    .done(function (data){
        if(notify_auto_api(data)){
            $('#modal_ds_file').modal("hide");
            reset_ds_file_view();
            load_datastore();
        }
    })
    .always((data) => {
        window.swal.close();
    });
}

function refresh_ds(){
    reset_ds_file_view();
    load_datastore();
    notify_success('数据存储已刷新');
}

function upload_interactive_data(data_blob, filename, completion_callback) {

    var data_sent = Object()
    data_sent["csrf_token"] = $('#csrf_token').val();
    data_sent["file_content"] = data_blob.split(';base64,')[1];
    data_sent["file_original_name"] = filename;

    post_request_api('/datastore/file/add-interactive', JSON.stringify(data_sent), true)
    .done(function (data){
        if(notify_auto_api(data)) {
            if (completion_callback !== undefined) {
                completion_callback(data);
            }
        }
    });
}

function toggle_select_file() {
    if ($('.btn-ds-bulk-selector').hasClass('active')) {
        reset_ds_file_view();
        load_datastore();
    } else {
        $('.ds-file-selector').show(250);
        $('.btn-ds-bulk').show(250);
        $('.btn-ds-bulk-selector').addClass('active');
    }
}

function move_ds_file(file_id) {

    reparse_activate_tree_selection();
    $('.ds-file-selector').show();
    $('#msg_mv_dst_folder').text('未选择目标');
    $('#msg_select_destination_folder').show();

    ds_file_select(file_id);
}

function reset_ds_file_view() {
    $(".node-selected").removeClass("node-selected");
    $(".file-selected").removeClass("file-selected");
    $('.ds-file-selector').hide();
    $('#msg_select_destination_folder').attr("data-file-id", '');
    $('#msg_select_destination_folder').hide();
    $('#msg_select_destination_folder_folder').hide();
    $('.ds-file-selector').hide();
    $('.btn-ds-bulk').hide();
    $('.btn-ds-bulk-selector').removeClass('active');
}

function ds_file_select(file_id) {
    file_id = '#'+ file_id;
    if ($(file_id).hasClass('file-selected')) {
        $(file_id + '> i').removeClass('fa-circle-check');
        $(file_id + '> i').addClass('fa-circle');
        $(file_id).removeClass('file-selected');
    } else {
        $(file_id+ '> i').removeClass('fa-circle');
        $(file_id+ '> i').addClass('fa-circle-check');
        $(file_id).addClass('file-selected');
    }
    $('#msg_mv_files').text($('.file-selected').length);
}

function validate_ds_file_move() {
    var data_sent = Object();
    if ($(".node-selected").length === 0) {
        notify_error('未选择目标文件夹');
        return false;
    }
    if ($(".file-selected").length === 0) {
        notify_error('未选择要移动的文件');
        return false;
    }

    data_sent['destination-node'] = $(".node-selected").data('node-id').replace('d-', '');
    data_sent['csrf_token'] = $('#csrf_token').val();
    index = 0;
    selected_files = $(".file-selected");
    selected_files.each((index) => {
        file_id = $(selected_files[index]).data('file-id').replace('f-', '');
        post_request_api('/datastore/file/move/' + file_id, JSON.stringify(data_sent))
        .done((data) => {
            if (notify_auto_api(data)) {
                if (index == $(".file-selected").length - 1) {
                    reset_ds_file_view();
                    load_datastore();
                }
                index +=1;
            }
        });
    });
}

function move_ds_folder(node_id) {
     reset_ds_file_view();

    $('#msg_mv_folder').text($('#' + node_id).text());
    $('#msg_mv_dst_folder_folder').text('未选择目标');
    $('#msg_select_destination_folder_folder').show();

    reparse_activate_tree_selection();
    $('#' + node_id).addClass('node-source-selected');
}

function validate_ds_folder_move() {
    var data_sent = Object();
    if ($(".node-selected").length === 0) {
        notify_error('未选择目标文件夹');
        return false;
    }
    if ($(".node-source-selected").length === 0) {
        notify_error('没有要移动的初始文件夹');
        return false;
    }

    data_sent['destination-node'] = $(".node-selected").data('node-id').replace('d-', '');
    data_sent['csrf_token'] = $('#csrf_token').val();

    node_id = $(".node-source-selected").data('node-id').replace('d-', '');
    post_request_api('/datastore/folder/move/' + node_id, JSON.stringify(data_sent))
    .done((data) => {
        if (notify_auto_api(data)) {
            reset_ds_file_view();
            load_datastore();
        }
    });
}

function delete_ds_file(file_id) {
    file_id = file_id.replace('f-', '');
    swal({
        title: "你确定吗?",
        text: "这将删除服务器上的文件，任何手动引用都将失效",
        icon: "warning",
        buttons: true,
        dangerMode: true,
        confirmButtonColor: '#3085d6',
        cancelButtonColor: '#d33',
        confirmButtonText: '是,删除它!'
    })
    .then((willDelete) => {
        if (willDelete) {
            var data_sent = {
                "csrf_token": $('#csrf_token').val()
            }
            post_request_api('/datastore/file/delete/' + file_id, JSON.stringify(data_sent))
            .done((data) => {
                if (notify_auto_api(data)) {
                    reset_ds_file_view();
                    load_datastore();
                }
            });
        } else {
            swal("Pfew, 好险");
        }
    });
}

function delete_bulk_ds_file() {

    selected_files = $(".file-selected");
    swal({
        title: "你确定吗?",
        text: `你要删除 ${selected_files.length} 个文件\n这将删除服务器上的文件，任何手动引用都将失效`,
        icon: "warning",
        buttons: true,
        dangerMode: true,
        confirmButtonColor: '#3085d6',
        cancelButtonColor: '#d33',
        confirmButtonText: '是,删除它!'
    })
    .then((willDelete) => {
        if (willDelete) {
            selected_files.each((index) => {
                file_id = $(selected_files[index]).data('file-id').replace('f-', '');
                var data_sent = {
                    "csrf_token": $('#csrf_token').val()
                }
                post_request_api('/datastore/file/delete/' + file_id, JSON.stringify(data_sent))
                .done((data) => {
                    if (notify_auto_api(data)) {
                        if (index == $(".file-selected").length - 1) {
                            reset_ds_file_view();
                            load_datastore();
                        }
                        index +=1;
                    }
                });
            });
        } else {
            swal("Pfew, 好险");
        }
    });
}

function get_link_ds_file(file_id) {

   file_id = file_id.replace('f-', '');

   link = location.protocol + '//' + location.host + '/datastore/file/view/' + file_id;
   link = link + case_param();

   navigator.clipboard.writeText(link).then(function() {
          notify_success('文件链接已复制')
    }, function(err) {
        notify_error('无法复制链接. 错误 ' + err);
        console.error('File link link', err);
    });

}

function build_dsfile_view_link(file_id) {
   file_id = file_id.replace('f-', '');

   link = '/datastore/file/view/' + file_id;
   link = link + case_param();

   return link;
}

function get_mk_link_ds_file(file_id, filename, file_icon, has_password) {

   let link = build_dsfile_view_link(file_id);

   filename = sanitizeHTML(fromBinary64(filename));


   if (has_password == 'false' && ['png', 'svg', 'jpeg', 'jpg', 'webp', 'bmp', 'gif'].includes(filename.split('.').pop())) {
        mk_link = `![\`${filename}\`](${link} =60%x40%)`;
    } else {
        file_icon = atob(file_icon);
        mk_link = `[${file_icon} [DS] \`${filename}\`](${link})`;
    }

   navigator.clipboard.writeText(mk_link).then(function() {
          notify_success('Markdown文件链接已复制')
    }, function(err) {
        notify_error('无法复制链接. 错误 ' + err);
        console.error(`Markdown file link ${md_link}`, err);
    });

}

function download_ds_file(file_id) {
    let link = build_dsfile_view_link(file_id);
    downloadURI(link, name);
}

function reparse_activate_tree_selection() {
    $('.tree li.parent_li > span').on('click', function (e) {
        if ($(this).hasClass('node-selected')) {
            $(this).removeClass('node-selected');
            $('#msg_mv_dst_folder').text('未选择目标');
            $('#msg_mv_dst_folder_folder').text('未选择目标');
        } else {
            $(".node-selected").removeClass("node-selected");
            $(this).addClass('node-selected');
            $('#msg_mv_dst_folder').text($(".node-selected").text());
            $('#msg_mv_dst_folder_folder').text($(".node-selected").text());
        }
    });
}

var parsed_filter_ds = {};
var ds_keywords = ['storage_name', 'name', 'tag', 'description', 'is_ioc', 'is_evidence', 'has_password', 'uuid', 'id', 'sha256'];

function parse_filter(str_filter, keywords) {
  for (var k = 0; k < keywords.length; k++) {
  	keyword = keywords[k];
    items = str_filter.split(keyword + ':');

    ita = items[1];

    if (ita === undefined) {
    	continue;
    }

    item = split_bool(ita);

    if (item != null) {
      if (!(keyword in parsed_filter_ds)) {
        parsed_filter_ds[keyword] = [];
      }
      if (!parsed_filter_ds[keyword].includes(item)) {
        parsed_filter_ds[keyword].push(item.trim());
      }

      if (items[1] != undefined) {
        str_filter = str_filter.replace(keyword + ':' + item, '');
        if (parse_filter(str_filter, keywords)) {
        	keywords.shift();
        }
      }
    }
  }
  return true;
}

function filter_ds_files() {

    ds_keywords = ['storage_name', 'name', 'tag', 'description', 'is_ioc', 'is_evidence', 'has_password', 'uuid', 'id', 'sha256'];
    parsed_filter_ds = {};
    parse_filter(ds_filter.getValue(), ds_keywords);
    filter_query = encodeURIComponent(JSON.stringify(parsed_filter_ds));

    $('#btn_filter_ds_files').text('搜索中..');
    get_request_data_api("/datastore/list/filter",{ 'q': filter_query })
    .done(function (data){
        if(notify_auto_api(data, true)){
            $('#ds-tree-root').empty();
            build_ds_tree(data.data, 'ds-tree-root');
            reparse_activate_tree();
            show_datastore();
        }
    })
    .always(() => {
        $('#btn_filter_ds_files').text('Search');
    });
}

function reset_ds_files_filter() {
    ds_filter.setValue("");
    load_datastore();
}

function show_ds_filter_help() {
    $('#modal_help').load('/datastore/filter-help/modal' + case_param(), function (response, status, xhr) {
        if (status !== "success") {
             ajax_notify_error(xhr, '/datastore/filter-help/modal');
             return false;
        }
        $('#modal_help').modal('show');
    });
}

