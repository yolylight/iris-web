channel = 'iris_update_status';

function log_error(message) {
    add_update_log(message, true);
}

function log_msg(message) {
    add_update_log(message, false)
}

function add_update_log(message, is_error) {
    html_wrap = `<h4><i class="mt-2 fas fa-check text-success"></i>  `
    if (is_error) {
        html_wrap = `<h4><i class="mt-2 fas fa-times text-danger"></i> `
    }
    $("#updates_log").append(html_wrap + message + '</h4><br/>')
    $('html, body').animate({
        scrollTop: $("#updates_log_end").offset().top
    }, 50);
}

function get_caseid() {
    queryString = window.location.search;
    urlParams = new URLSearchParams(queryString);

    return urlParams.get('cid')
}

function case_param() {
    var params = {
        cid: get_caseid
    }
    return '?'+ $.param(params);
}

function initiate_update() {
    $.ajax({
        url: '/manage/server/start-update' + case_param(),
        type: "GET",
        dataType: "json",
        beforeSend : function () {
            log_msg('更新请求已发送.期待尽快得到反馈');
        },
        success: function (data) {},
        error: function (data) {
            log_error('启动更新时出现意外错误');
        }
    });
}

var intervalId = null;
var ios = io('/server-updates');
var update_socket = null;
var current_version = null;
var updated_version = null;
var steps = 0;
var no_resp_time = 0;

function check_server_version() {
    $.ajax({
        url: '/api/versions' + case_param(),
        type: "GET",
        dataType: "json",
        timeout: 1000,
        success: function (data) {
            server_version = data.data.iris_current;
            if (server_version == current_version) {
                add_update_log('出了点问题 - 服务器仍是相同版本', true);
                add_update_log('请检查服务器日志', true);
                clearInterval(intervalId);
                $('#tag_bottom').hide();
                $('#update_return_button').show();
            } else {
                add_update_log('成功从' + current_version + ' 更新到 ' + server_version, false);
                add_update_log('你可以离开此页', false);
                clearInterval(intervalId);
                $('#tag_bottom').hide();
                $('#update_return_button').show();
            }
        },
        error: function (error) {
            log_error('出问题了,服务器未响应');
            log_error('请检查服务器日志')
            clearInterval(intervalId);
            $('#tag_bottom').hide();
            $('#update_return_button').show();
        }
    });
}

function ping_check_server_online() {

    $.ajax({
        url: '/api/ping' + case_param(),
        type: "GET",
        dataType: "json",
        timeout: 1000,
        success: function (data) {
            $("#offline_time").hide();
            log_msg('服务已重新上线');
            clearInterval(intervalId);
            check_server_version();
        },
        error: function (error) {
            no_resp_time += 1;
            if (no_resp_time > 29) {
                log_error('出问题了,服务器未响应');
                log_error('请检查服务器日志')
                clearInterval(intervalId);
                $('#tag_bottom').hide();
                $('#update_return_button').show();
            }
            $("#offline_time").html('<h4 id="offline_time"><i class="fas fa-clock"></i> 尝试 '+ no_resp_time +' / 30</h4><br/>');
            $("#offline_time").show();
        }
    });
}

function start_updates(){
    $('#update_start_btn').hide();
    $('.update_start_txt').hide();
    $('#container-updates').show();
    update_socket.emit('update_get_current_version', { 'channel': channel });
    update_socket.emit('update_ping', { 'channel': channel });
//    index = 0;
//    while(index < 20) {
//        add_update_log('ping');
//        index += 1;
//    }
}


$(document).ready(function(){

    update_socket = ios.connect();

    update_socket.on( "update_status", function(data) {
        add_update_log(data.message, data.is_error)
    }.bind() );

    update_socket.on( "update_ping", function(data) {
        log_msg('服务器连接已验证');
        log_msg('开始更新');
        initiate_update();
    }.bind() );

    update_socket.on( "server_has_updated", function(data) {
        log_msg('服务器报告更新已应用. 检查中 . . .');
        check_server_version();
    }.bind() );

    update_socket.on('disconnect', function () {
        add_update_log('服务器脱机，等待连接', false);
        intervalId = window.setInterval(function(){
            ping_check_server_online();
        }, 1000);
    });

    update_socket.on('update_current_version', function (data) {
        add_update_log('服务器报告版本 ' + data.version , false);
        if (current_version == null) {
            current_version = data.version;
        }
    });

    update_socket.on('update_has_fail', function () {
        $('#tag_bottom').hide();
        $('#update_return_button').show();
    });

    update_socket.emit('join-update', { 'channel': channel });


});
