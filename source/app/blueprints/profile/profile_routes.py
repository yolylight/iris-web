#  IRIS Source Code
#  Copyright (C) 2021 - Airbus CyberSecurity (SAS)
#  ir@cyberactionlab.net
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public
#  License as published by the Free Software Foundation; either
#  version 3 of the License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with this program; if not, write to the Free Software Foundation,
#  Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

import marshmallow
# IMPORTS ------------------------------------------------
import secrets
from flask import Blueprint
from flask import redirect
from flask import render_template
from flask import request
from flask import session
from flask import url_for
from flask_login import current_user
from flask_wtf import FlaskForm

from app import db
from app.datamgmt.manage.manage_srv_settings_db import get_srv_settings
from app.datamgmt.manage.manage_users_db import get_user
from app.datamgmt.manage.manage_users_db import get_user_primary_org
from app.datamgmt.manage.manage_users_db import update_user
from app.iris_engine.access_control.utils import ac_current_user_has_permission
from app.iris_engine.access_control.utils import ac_get_effective_permissions_of_user
from app.iris_engine.access_control.utils import ac_recompute_effective_ac
from app.iris_engine.utils.tracker import track_activity
from app.models.authorization import Permissions
from app.schema.marshables import UserSchema, BasicUserSchema
from app.util import ac_api_requires
from app.util import ac_requires
from app.util import endpoint_deprecated
from app.util import response_error
from app.util import response_success

profile_blueprint = Blueprint('profile',
                              __name__,
                              template_folder='templates')


# CONTENT ------------------------------------------------
@profile_blueprint.route('/user/settings', methods=['GET'])
@ac_requires(no_cid_required=True)
def user_settings(caseid, url_redir):
    if url_redir:
        return redirect(url_for('profile.user_settings', cid=caseid))

    return render_template('profile.html')


@profile_blueprint.route('/user/token/renew', methods=['GET'])
@ac_api_requires(no_cid_required=True)
def user_renew_api(caseid):

    user = get_user(current_user.id)
    user.api_key = secrets.token_urlsafe(nbytes=64)

    db.session.commit()

    return response_success("Token已续期")


@profile_blueprint.route('/user/is-admin', methods=['GET'])
@endpoint_deprecated('Use /user/has-permission to check permission', 'v1.5.0')
def user_is_admin(caseid):
    pass


@profile_blueprint.route('/user/has-permission', methods=['POST'])
@ac_api_requires(no_cid_required=True)
def user_has_permission(caseid):

    req_js = request.json
    if not req_js:
        return response_error('无效请求')

    if not req_js.get('permission_name') or not \
            req_js.get('permission_value'):
        return response_error('无效请求')

    if req_js.get('permission_value') not in Permissions._value2member_map_:
        return response_error('权限无效')

    if Permissions(req_js.get('permission_value')).name.lower() != req_js.get('permission_name').lower():
        return response_error('权限value-name不符')

    if ac_current_user_has_permission(Permissions(req_js.get('permission_value'))):
        return response_success('用户获得权限')
    else:
        return response_error('用户没有权限', status=403)


@profile_blueprint.route('/user/update/modal', methods=['GET'])
@ac_requires(no_cid_required=True)
def update_pwd_modal(caseid, url_redir):
    if url_redir:
        return redirect(url_for('profile.user_settings', cid=caseid))

    form = FlaskForm()

    server_settings = get_srv_settings()

    return render_template("modal_pwd_user.html", form=form, server_settings=server_settings)


@profile_blueprint.route('/user/update', methods=['POST'])
@ac_api_requires(no_cid_required=True)
def update_user_view(caseid):
    try:
        user = get_user(current_user.id)
        if not user:
            return response_error("对于此案例用户ID无效")

        # validate before saving
        user_schema = UserSchema()
        jsdata = request.get_json()
        jsdata['user_id'] = current_user.id
        puo = get_user_primary_org(current_user.id)

        jsdata['user_primary_organisation_id'] = puo.org_id

        cuser = user_schema.load(jsdata, instance=user, partial=True)
        update_user(password=jsdata.get('user_password'),
                    user=user)
        db.session.commit()

        if cuser:
            track_activity("user {} updated itself".format(user.user), caseid=caseid)
            return response_success("用户已更新", data=user_schema.dump(user))

        return response_error("由于内部原因无法更新用户")

    except marshmallow.exceptions.ValidationError as e:
        return response_error(msg="数据错误", data=e.messages, status=400)


@profile_blueprint.route('/user/theme/set/<string:theme>', methods=['GET'])
@ac_api_requires(no_cid_required=True)
def profile_set_theme(theme, caseid):
    if theme not in ['dark', 'light']:
        return response_error('无效数据')

    user = get_user(current_user.id)
    if not user:
        return response_error("无效用户ID")

    user.in_dark_mode = (theme == 'dark')
    db.session.commit()

    return response_success('Theme changed')


@profile_blueprint.route('/user/deletion-prompt/set/<string:val>', methods=['GET'])
@ac_api_requires(no_cid_required=True)
def profile_set_deletion_prompt(val, caseid):
    if val not in ['true', 'false']:
        return response_error('无效数据')

    user = get_user(current_user.id)
    if not user:
        return response_error("无效用户ID")

    user.has_deletion_confirmation = (val == 'true')
    db.session.commit()

    return response_success('删除提示 {}'.format('启用' if val == 'true' else '禁用'))


@profile_blueprint.route('/user/mini-sidebar/set/<string:val>', methods=['GET'])
@ac_api_requires(no_cid_required=True)
def profile_set_minisidebar(val, caseid):
    if val not in ['true', 'false']:
        return response_error('无效数据')

    user = get_user(current_user.id)
    if not user:
        return response_error("无效用户ID")

    user.has_mini_sidebar = (val == 'true')
    db.session.commit()

    return response_success('侧边栏 {}'.format('启用' if val == 'true' else '禁用'))


@profile_blueprint.route('/user/refresh-permissions', methods=['GET'])
@ac_api_requires(no_cid_required=True)
def profile_refresh_permissions_and_ac(caseid):

    user = get_user(current_user.id)
    if not user:
        return response_error("无效用户ID")

    ac_recompute_effective_ac(current_user.id)
    session['permissions'] = ac_get_effective_permissions_of_user(user)

    return response_success('已刷新访问控制和权限')


@profile_blueprint.route('/user/whoami', methods=['GET'])
@ac_api_requires(no_cid_required=True)
def profile_whoami(caseid):
    """
    Returns the current user's profile
    """
    user = get_user(current_user.id)
    if not user:
        return response_error("无效用户ID")

    user_schema = BasicUserSchema()
    return response_success(data=user_schema.dump(user))
