/* reload the ioc table */
var g_ioc_id = null;
var g_ioc_desc_editor = null;


function reload_iocs() {
    get_case_ioc();
}

function edit_in_ioc_desc() {
    if($('#container_ioc_desc_content').is(':visible')) {
        $('#container_ioc_description').show(100);
        $('#container_ioc_desc_content').hide(100);
        $('#ioc_edition_btn').hide(100);
        $('#ioc_preview_button').hide(100);
    } else {
        $('#ioc_preview_button').show(100);
        $('#ioc_edition_btn').show(100);
        $('#container_ioc_desc_content').show(100);
        $('#container_ioc_description').hide(100);
    }
}

function _parse_ioc_values() {
    const ioc_value = $('#ioc_value').val();
    if (!$('#ioc_one_per_line').is(':checked')) {
        return [ioc_value];
    } else {
        return ioc_value.split(/\r?\n/).filter((value) => value !== '' && value !== '\n');
    }
}

/* Fetch a modal that is compatible with the requested ioc type */ 
function add_ioc() {
    url = 'ioc/add/modal' + case_param();

    $('#modal_add_ioc_content').load(url, function (response, status, xhr) {
        hide_minimized_modal_box();
        if (status !== "success") {
             ajax_notify_error(xhr, url);
             return false;
        }

        g_ioc_desc_editor = get_new_ace_editor('ioc_description', 'ioc_desc_content', 'target_ioc_desc',
                            function() {
                                $('#last_saved').addClass('btn-danger').removeClass('btn-success');
                                $('#last_saved > i').attr('class', "fa-solid fa-file-circle-exclamation");
                            }, null);

        g_ioc_desc_editor.setOption("minLines", "10");
        edit_in_ioc_desc();

        headers = get_editor_headers('g_ioc_desc_editor', null, 'ioc_edition_btn');
        $('#ioc_edition_btn').append(headers);


        $('#submit_new_ioc').on("click", function () {
            if(!$('form#form_new_ioc').valid()) {
                return false;
            }

            var data = $('#form_new_ioc').serializeObject();
            data['ioc_tags'] = $('#ioc_tags').val();
            data['ioc_description'] = g_ioc_desc_editor.getValue();

            ret = get_custom_attributes_fields();
            has_error = ret[0].length > 0;
            attributes = ret[1];

            if (has_error) {
                return false;
            }

            data['custom_attributes'] = attributes;

            id = $('#ioc_id').val();

            const iocs_values = _parse_ioc_values();
            iocs_values.forEach((ioc_value, index) => {
                data['ioc_value'] = ioc_value;
                case_id = get_caseid()
                post_request_api(`/api/v2/cases/${case_id}/iocs`, JSON.stringify(data), true, function () {
                    $('#submit_new_ioc').text('Saving data..')
                        .attr("disabled", true)
                        .removeClass('bt-outline-success')
                        .addClass('btn-success', 'text-dark');
                })
                .done((data, textStatus) => {
                    if (textStatus === 'success') {
                        reload_iocs();
                        notify_success('IOC added');
                        // TODO would better to close the modal if all requests succeed (should combine the results? promises...)
                        if (index == (iocs_values.length - 1)) {
                            $('#modal_add_ioc').modal('hide');
                        }
                    } else {
                        $('#submit_new_ioc').text('Save again');
                        swal("Oh no !", data, "error")
                    }
                })
                .fail((error) => {
                    notify_error(error.responseJSON.message);
                })
                .always(function () {
                    $('#submit_new_ioc').text('Save')
                        .attr("disabled", false)
                        .addClass('bt-outline-success')
                        .removeClass('btn-success', 'text-dark');
                })
            })
            return false;
        });

        $('#modal_add_ioc').modal({ show: true });
        $('#ioc_value').focus();

    });

    return false;
}

function save_ioc() {
    $('#submit_new_ioc').click();
}

/* Retrieve the list of iocs and build a datatable for each type of ioc */
function get_case_ioc() {
    show_loader();

    get_request_data_api('/case/ioc/state').done((response, textStatus) => {
        if (textStatus !== 'success') {
            return;
        }
        set_last_state(response.data);
    });

    get_request_data_api(`/api/v2/cases/${get_caseid()}/iocs`, { 'per_page': Number.MAX_SAFE_INTEGER })
    .done((data, textStatus) => {
        if (textStatus !== 'success') {
            Table.clear().draw()
            return;
        }

        if (data == null) {
            Table.clear().draw();
            swal("Oh no !", data.message, "error")
            return;
        }

        Table.clear();
        Table.rows.add(data.data);

        $('#ioc_table_wrapper').on('click', function(e){
            if($('.popover').length>1)
                $('.popover').popover('hide');
                $(e.target).popover('toggle');
            });

        $('#ioc_table_wrapper').show();
        Table.columns.adjust().draw();
        load_menu_mod_options('ioc', Table, delete_ioc);
        hide_loader();
        Table.responsive.recalc();

        $(document)
            .off('click', '.ioc_details_link')
            .on('click', '.ioc_details_link', function(event) {
            event.preventDefault();
            let ioc_id = $(this).data('ioc_id');

            edit_ioc(ioc_id);
        });
    });
}


/* Edit an ioc */
function edit_ioc(ioc_id) {
    url = 'ioc/' + ioc_id + '/modal' + case_param();
    $('#modal_add_ioc_content').load(url, function (response, status, xhr) {
        hide_minimized_modal_box();
        if (status !== "success") {
             ajax_notify_error(xhr, url);
             return false;
        }

        g_ioc_id = ioc_id;
        g_ioc_desc_editor = get_new_ace_editor('ioc_description', 'ioc_desc_content', 'target_ioc_desc',
                            function() {
                                $('#last_saved').addClass('btn-danger').removeClass('btn-success');
                                $('#last_saved > i').attr('class', "fa-solid fa-file-circle-exclamation");
                            }, null, false, false);

        g_ioc_desc_editor.setOption("minLines", "10");
        preview_ioc_description(true);
        headers = get_editor_headers('g_ioc_desc_editor', null, 'ioc_edition_btn');
        $('#ioc_edition_btn').append(headers);

        load_menu_mod_options_modal(ioc_id, 'ioc', $("#ioc_modal_quick_actions"));
        $('.dtr-modal').hide();
        $('#modal_add_ioc').modal({ show: true });
        edit_in_ioc_desc();
    });

}

function preview_ioc_description(no_btn_update) {
    if(!$('#container_ioc_description').is(':visible')) {
        ioc_desc = g_ioc_desc_editor.getValue();
        converter = get_showdown_convert();
        html = converter.makeHtml(do_md_filter_xss(ioc_desc));
        ioc_desc_html = do_md_filter_xss(html);
        $('#target_ioc_desc').html(ioc_desc_html);
        $('#container_ioc_description').show();
        if (!no_btn_update) {
            $('#ioc_preview_button').html('<i class="fa-solid fa-eye-slash"></i>');
        }
        $('#container_ioc_desc_content').hide();
    }
    else {
        $('#container_ioc_description').hide();
         if (!no_btn_update) {
            $('#ioc_preview_button').html('<i class="fa-solid fa-eye"></i>');
        }

        $('#ioc_preview_button').html('<i class="fa-solid fa-eye"></i>');
        $('#container_ioc_desc_content').show();
    }
}

function update_ioc(ioc_id) {
    if(!$('form#form_new_ioc').valid()) {
        return false;
    }

    if (ioc_id === undefined || ioc_id === null) {
        ioc_id = g_ioc_id;
    }

    var data = $('#form_new_ioc').serializeObject();
    data['ioc_tags'] = $('#ioc_tags').val();
    ret = get_custom_attributes_fields();
    has_error = ret[0].length > 0;
    attributes = ret[1];

    if (has_error){
        return false;
    }
    data['ioc_description'] = g_ioc_desc_editor.getValue();
    data['custom_attributes'] = attributes;
    let cid = get_caseid();
    put_request_api(`/api/v2/cases/${cid}/iocs/${ioc_id}`, JSON.stringify(data))
    .done((data, textStatus) => {
        if (textStatus == 'success') {
            reload_iocs();

            $('#modal_add_ioc').modal('hide');

            notify_success('IOC updated');

        } else {
            $('#submit_new_ioc').text('Save again');
            notify_error(data.message);
        }
    })

}

/* Delete an ioc */
function delete_ioc(ioc_id) {
    do_deletion_prompt("You are about to delete IOC #" + ioc_id)
    .then((doDelete) => {
        if (doDelete) {
            let cid = get_caseid();
            delete_request_api(`/api/v2/cases/${cid}/iocs/${ioc_id}`)
            .done((data, textStatus) => {
                if (textStatus === 'nocontent') {
                    reload_iocs();
                    notify_success(`IOC ${ioc_id} deleted`);
                    $('#modal_add_ioc').modal('hide');

                } else {
                    swal("Oh no !", data.message, "error")
                }
            })
        }
    });
}

function fire_upload_iocs() {
    $('#modal_upload_ioc').modal('show');
}

function upload_ioc() {

    var file = $("#input_upload_ioc").get(0).files[0];
    var reader = new FileReader();
    reader.onload = function (e) {
        fileData = e.target.result
        var data = new Object();
        data['csrf_token'] = $('#csrf_token').val();
        data['CSVData'] = fileData;

        post_request_api('/case/ioc/upload', JSON.stringify(data), true)
        .done((data) => {
            jsdata = data;
            if (jsdata.status == "success") {
                reload_iocs();
                $('#modal_upload_ioc').modal('hide');
                swal("Got news for you", data.message, "success");

            } else {
                swal("Got bad news for you", data.message, "error");
            }
        })
    };
    reader.readAsText(file)

    return false;
}

function generate_sample_csv(){
    csv_data = "ioc_value,ioc_type,ioc_description,ioc_tags,ioc_tlp\n"
    csv_data += "1.1.1.1,ip-dst,Cloudflare DNS IP address,Cloudflare|DNS,green\n"
    csv_data += "wannacry.exe,filename,Wannacry sample found,Wannacry|Malware|PE,amber"
    download_file("sample_iocs.csv", "text/csv", csv_data);
}

/* Page is ready, fetch the iocs of the case */
$(document).ready(function(){

    /* add filtering fields for each table of the page (must be done before datatable initialization) */
    $.each($.find("table"), function(index, element){
        addFilterFields($(element).attr("id"));
    });

    Table = $("#ioc_table").DataTable({
        dom: '<"container-fluid"<"row"<"col"l><"col"f>>>rt<"container-fluid"<"row"<"col"i><"col"p>>>',
        fixedHeader: true,
        aaData: [],
        aoColumns: [
          {
            "data": "ioc_value",
            "render": function (data, type, row, meta) {
                if (type === 'display') {

                    let datak = '';
                    let anchor = $('<a>')
                        .attr('href', 'javascript:void(0);')
                        .attr('data-ioc_id', row['ioc_id'])
                        .attr('title', `IOC ID #${row['ioc_id']} - ${data}`)
                        .addClass('ioc_details_link')

                    if (isWhiteSpace(data) || data === null) {
                        datak = '#' + row['ioc_id'];
                        anchor.text(datak);
                    } else {
                        datak= ellipsis_field(data, 64);
                        anchor.html(datak);
                    }

                    return anchor.prop('outerHTML');
                }

              return data;
            }
          },
          { "data": "ioc_type",
           "render": function (data, type, row, meta) {
              if (type === 'display') {
                data = sanitizeHTML(data.type_name);
              }
              return data;
              }
          },
          { "data": "ioc_description",
           "render": function (data, type, row, meta) {
              if (type === 'display') {
                  return ret_obj_dt_description(data);
              }
              return data;
            }
          },
          { "data": "ioc_tags",
            "render": function (data, type, row, meta) {
              if (type === 'display' && data != null) {
                  let tags = "";
                  let de = data.split(',');
                  for (let tag in de) {
                      tags += get_tag_from_data(de[tag], 'badge badge-light ml-2');
                  }
                  return tags;
              }
              return data;
            }
          },
          { "data": "link",
            "render": function (data, type, row, meta) {
              if (type === 'display' && data != null) {
                  links = "";
                  for (link in data) {
                    links += '<span data-toggle="popover" style="cursor: pointer;" data-trigger="hover" class="text-primary mr-3" href="#" title="Case info" data-content="' + sanitizeHTML(data[link]['case_name']) +
                     ' (' + sanitizeHTML(data[link]['client_name']) + ')' + '">#' + data[link]['case_id'] + '</span>'
                  }
                  return links;
              } else if (type === 'export' && data != null) {
                  return data.map(ds => sanitizeHTML(ds['case_name'])).join(',');
                }
              return data;
            }
          },
          {
            "data": "tlp",
            "render": function(data, type, row, meta) {
               if (type === 'display') {
                  if (data) {
                      bscolor = data.tlp_bscolor;
                      data = sanitizeHTML(data.tlp_name);
                      data = '<span class="badge badge-' + bscolor + ' ml-2">tlp:' + data + '</span>';
                  } else {
                      data = '<span class="badge badge-light ml-2">Unspecified</span>';
                  }
              }
              return data;
            }
          }
        ],
        filter: true,
        info: true,
        ordering: true,
        processing: true,
        retrieve: true,
        responsive: {
            details: {
                display: $.fn.dataTable.Responsive.display.childRow,
                renderer: $.fn.dataTable.Responsive.renderer.tableAll()
            }
        },
        buttons: [],
        orderCellsTop: true,
        initComplete: function () {
            tableFiltering(this.api(), 'ioc_table');
        },
        select: true
    });
    $("#ioc_table").css("font-size", 12);

    Table.on( 'responsive-resize', function ( e, datatable, columns ) {
            hide_table_search_input( columns );
    });

    var buttons = new $.fn.dataTable.Buttons(Table, {
     buttons: [
        { "extend": 'csvHtml5', "text":'<i class="fas fa-cloud-download-alt"></i>',"className": 'btn btn-link text-white'
        , "titleAttr": 'Download as CSV', "exportOptions": { "columns": ':visible', 'orthogonal':  'export' } } ,
        { "extend": 'copyHtml5', "text":'<i class="fas fa-copy"></i>',"className": 'btn btn-link text-white'
        , "titleAttr": 'Copy', "exportOptions": { "columns": ':visible', 'orthogonal':  'export' } },
        { "extend": 'colvis', "text":'<i class="fas fa-eye-slash"></i>',"className": 'btn btn-link text-white'
        , "titleAttr": 'Toggle columns' }
    ]
}).container().appendTo($('#tables_button'));

    get_case_ioc();
    // TODO instead of polling, could work with socket IO events (would maybe be more reactive timewise)
    setInterval(function() { check_update('/case/ioc/state'); }, 3000);

    shared_id = getSharedLink();
    if (shared_id) {
        edit_ioc(shared_id);
    }
});