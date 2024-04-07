function add_case_template() {
    let url = '/manage/case-templates/add/modal' + case_param();
    $('#modal_case_template_json').load(url, function (response, status, xhr) {
        if (status !== "success") {
             ajax_notify_error(xhr, url);
             return false;
        }

        let editor = ace.edit("editor_detail",
            {
                autoScrollEditorIntoView: true,
                minLines: 30,
            });
        editor.setTheme("ace/theme/tomorrow");
        editor.session.setMode("ace/mode/json");
        editor.renderer.setShowGutter(true);
        editor.setOption("showLineNumbers", true);
        editor.setOption("showPrintMargin", false);
        editor.setOption("displayIndentGuides", true);
        editor.setOption("maxLines", "Infinity");
        editor.session.setUseWrapMode(true);
        editor.setOption("indentedSoftWrap", true);
        editor.renderer.setScrollMargin(8, 5)

        editor.setOptions({
          enableBasicAutocompletion: [{
            getCompletions: (editor, session, pos, prefix, callback) => {
              callback(null, [
                {value: 'name', score: 1, meta: '模板名称'},
                {value: 'display', score: 1, meta: '模板显示名'},
                {value: 'description', score: 1, meta: '模板描述'},
                {value: 'author', score: 1, meta: '模板作者'},
                {value: 'title_prefix', score: 1, meta: '案例前缀'},
                {value: 'summary', score: 1, meta: '案例摘要'},
                {value: 'tags', score: 1, meta: '案例或任务的标签'},
                {value: 'tasks', score: 1, meta: '案例的任务'},
                {value: 'note_groups', score: 1, meta: '笔记组'},
                {value: 'title', score: 1, meta: '任务或注释组或注释的标题'},
                {value: 'content', score: 1, meta: '笔记的内容'},
              ]);
            },
          }],
          enableLiveAutocompletion: true,
          enableSnippets: true
        });

        $('#submit_new_case_template').on("click", function () {
            let data_sent = Object();
            data_sent['case_template_json'] = editor.getSession().getValue();
            data_sent['csrf_token'] = $("#csrf_token").val();

            post_request_api('/manage/case-templates/add', JSON.stringify(data_sent), false, function() {
                window.swal({
                      title: "添加中...",
                      text: "请等待",
                      icon: "/static/assets/img/loader.gif",
                      button: false,
                      allowOutsideClick: false
                });
            })
            .done((data) => {
                if (notify_auto_api(data)) {
                    refresh_case_template_table();
                    $('#modal_case_template').modal('hide');
                }
            })
            .fail((error) => {
                let data = error.responseJSON;
                $('#submit_new_case_template').text('保存');
                $('#alert_case_template_edit').text(data.message);
                if (data.data && data.data.length > 0) {

                    let output='<li>'+ sanitizeHTML(data.data) +'</li>';
                    $('#case_template_err_details_list').append(output);

                    $('#alert_case_template_details').show();
                }
                $('#alert_case_template_edit').show();
            })
            .always((data) => {
                window.swal.close();
            });

            return false;
        })
    });
    $('#modal_case_template').modal({ show: true });
}

$('#case_templates_table').dataTable( {
    "ajax": {
      "url": "/manage/case-templates/list" + case_param(),
      "contentType": "application/json",
      "type": "GET",
      "data": function ( d ) {
        if (d.status == 'success') {
          return JSON.stringify( d.data );
        } else {
          return JSON.stringify([]);
        }
      }
    },
    "order": [[ 0, "desc" ]],
    "autoWidth": false,
    "columns": [
            {
                "data": "id",
                "render": function ( data, type, row ) {
                    return '<a href="#" onclick="case_template_detail(\'' + row['id'] + '\');">' + sanitizeHTML(data) +'</a>';
                }
            },
            {
                "data": "display_name",
                "render": function ( data, type, row ) {
                    return '<a href="#" onclick="case_template_detail(\'' + row['id'] + '\');">' + sanitizeHTML(data) +'</a>';
                }
            },
            {
                "data": "description"
            },
            {
                "data": "added_by"
            },
            {
                "data": "created_at"
            },
            {
                "data": "updated_at"
            }

        ]
    }
);

function refresh_case_template_table() {
  $('#case_templates_table').DataTable().ajax.reload();
  notify_success("已刷新");
}

function delete_case_template(id) {
    swal({
        title: "你确定吗 ?",
        text: "操作不能恢复!",
        icon: "warning",
        buttons: true,
        dangerMode: true,
        confirmButtonColor: '#3085d6',
        cancelButtonColor: '#d33',
        confirmButtonText: '是,删除它!'
    })
    .then((willDelete) => {
        if (willDelete) {
            post_request_api('/manage/case-templates/delete/' + id)
            .done((data) => {
                if(notify_auto_api(data)) {
                    window.location.href = '/manage/case-templates' + case_param();
                }
            });
        } else {
            swal("Pfew,好险");
        }
    });
}

function case_template_detail(ctempl_id) {
    let url = '/manage/case-templates/' + ctempl_id + '/modal' + case_param();
    $('#modal_case_template_json').load(url, function (response, status, xhr) {
        if (status !== "success") {
             ajax_notify_error(xhr, url);
             return false;
        }

        let editor = ace.edit("editor_detail",
            {
                autoScrollEditorIntoView: true,
                minLines: 30,
            });
        editor.setTheme("ace/theme/tomorrow");
        editor.session.setMode("ace/mode/json");
        editor.renderer.setShowGutter(true);
        editor.setOption("showLineNumbers", true);
        editor.setOption("showPrintMargin", false);
        editor.setOption("displayIndentGuides", true);
        editor.setOption("maxLines", "Infinity");
        editor.session.setUseWrapMode(true);
        editor.setOption("indentedSoftWrap", true);
        editor.renderer.setScrollMargin(8, 5)

        editor.setOptions({
          enableBasicAutocompletion: [{
            getCompletions: (editor, session, pos, prefix, callback) => {
              callback(null, [
                {value: 'name', score: 1, meta: '模板名称'},
                {value: 'display_name', score: 1, meta: '模板显示名'},
                {value: 'description', score: 1, meta: '模板描述'},
                {value: 'author', score: 1, meta: '模板作者'},
                {value: 'title_prefix', score: 1, meta: '案例前缀'},
                {value: 'summary', score: 1, meta: '案例摘要'},
                {value: 'tags', score: 1, meta: '案例或任务的标签'},
                {value: 'tasks', score: 1, meta: '案例的任务'},
                {value: 'note_groups', score: 1, meta: '笔记组'},
                {value: 'title', score: 1, meta: '任务或笔记组或笔记的标题'},
                {value: 'content', score: 1, meta: '笔记的内容'},
              ]);
            },
          }],
          enableLiveAutocompletion: true,
          enableSnippets: true
        });

        $('#submit_new_case_template').on("click", function () {
            update_case_template(ctempl_id, editor, false, false);
        });

        $('#submit_delete_case_template').on("click", function () {
            delete_case_template(ctempl_id);
        });
    });
    $('#modal_case_template').modal({ show: true });
}

function update_case_template(ctempl_id, editor, partial, complete){
    event.preventDefault();

    let data_sent = Object();
    data_sent['case_template_json'] = editor.getSession().getValue();
    data_sent['csrf_token'] = $("#csrf_token").val();

    $('#alert_case_template_edit').empty();
    $('#alert_case_template_details').hide();
    $('#case_template_err_details_list').empty();

    post_request_api('/manage/case-templates/update/' + ctempl_id, JSON.stringify(data_sent), false, function() {
        window.swal({
              title: "更新中...",
              text: "请等待",
              icon: "/static/assets/img/loader.gif",
              button: false,
              allowOutsideClick: false
        });
    })
    .done((data) => {
        notify_auto_api(data);
    })
    .fail((error) => {
        let data = error.responseJSON;
        $('#submit_new_case_template').text('更新');
        $('#alert_case_template_edit').text(data.message);
        if (data.data && data.data.length > 0) {
            let output='<li>'+ sanitizeHTML(data.data) +'</li>';
            $('#case_template_err_details_list').append(output);

            $('#alert_case_template_details').show();
        }
        $('#alert_case_template_edit').show();
    })
    .always((data) => {
        window.swal.close();
    });

    return false;
}

function fire_upload_case_template() {
    let url = '/manage/case-templates/upload/modal' + case_param();
    $('#modal_upload_case_template_json').load(url, function (response, status, xhr) {
        if (status !== "success") {
             ajax_notify_error(xhr, url);
             return false;
        }
    });
    $('#modal_upload_case_template').modal({ show: true });
}

function upload_case_template() {

    if ($("#input_upload_case_template").val() !== "")
    {
        var file = $("#input_upload_case_template").get(0).files[0];
        var reader = new FileReader();
        reader.onload = function (e) {
            fileData = e.target.result
            var data = new Object();
            data['csrf_token'] = $('#csrf_token').val();
            data['case_template_json'] = fileData;

            post_request_api('/manage/case-templates/add', JSON.stringify(data), false, function() {
                window.swal({
                      title: "添加中...",
                      text: "请等待",
                      icon: "/static/assets/img/loader.gif",
                      button: false,
                      allowOutsideClick: false
                });
            })
           .done((data) => {
                notify_auto_api(data);
                jsdata = data;
                if (jsdata.status == "success") {
                    refresh_case_template_table();
                    $('#modal_upload_case_template').modal('hide');
                }
           })
           .fail((error) => {
                let data = error.responseJSON;
                $('#alert_upload_case_template').text(data.message);
                if (data.data && data.data.length > 0) {

                    let output='<li>'+ sanitizeHTML(data.data) +'</li>';
                    $('#upload_case_template_err_details_list').append(output);

                    $('#alert_upload_case_template_details').show();
                }
                $('#alert_upload_case_template').show();
            })
            .always((data) => {
                $("#input_upload_case_template").val("");
                window.swal.close();
            });

        };
        reader.readAsText(file);
    }


    return false;
}

function downloadCaseTemplateDefinition() {
    event.preventDefault();
    let editor = ace.edit("editor_detail");
    let data = editor.getSession().getValue();

    let filename = "case_template.json";
    download_file(filename, 'text/json' , data);
}
