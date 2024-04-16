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

from flask_wtf import FlaskForm
from wtforms import BooleanField
from wtforms import PasswordField
from wtforms import SelectField
from wtforms import SelectMultipleField
from wtforms import StringField
from wtforms import TextAreaField
from wtforms import widgets
from wtforms.validators import DataRequired
from wtforms.validators import Email
from wtforms.validators import InputRequired


class LoginForm(FlaskForm):
    username = StringField(u'用户名', validators=[DataRequired()])
    password = PasswordField(u'密码', validators=[DataRequired()])


class RegisterForm(FlaskForm):
    name = StringField(u'名称', validators=[DataRequired()])
    username = StringField(u'用户名', validators=[DataRequired()])
    password = PasswordField(u'密码', validators=[DataRequired()])
    email = StringField(u'邮箱', validators=[DataRequired(), Email()])


class SearchForm(FlaskForm):
    search_type = StringField(u'搜索类型', validators=[DataRequired()])
    search_value = StringField(u'搜索值', validators=[DataRequired()])


class AddCustomerForm(FlaskForm):
    customer_name = StringField(u'客户名称', validators=[DataRequired()])
    customer_description = TextAreaField(u'客户描述', validators=[DataRequired()])
    customer_sla = TextAreaField(u'客户SLA', validators=[DataRequired()])


class MultiCheckboxField(SelectMultipleField):
    widget = widgets.ListWidget(prefix_label=False)
    option_widget = widgets.CheckboxInput()


class AddAssetForm(FlaskForm):
    asset_name = StringField(u'资产名称', validators=[DataRequired()])
    asset_description = StringField(u'资产描述', validators=[DataRequired()])
    asset_icon_compromised = StringField(u'资产已入侵图标描述', default="ioc_question-mark.png")
    asset_icon_not_compromised = StringField(u'资产未入侵图标描述', default="question-mark.png")


class AttributeForm(FlaskForm):
    attribute_content = TextAreaField(u'属性内容', validators=[DataRequired()])


class AddIocTypeForm(FlaskForm):
    type_name = StringField(u'类型名称', validators=[DataRequired()])
    type_description = StringField(u'类型描述', validators=[DataRequired()])
    type_taxonomy = TextAreaField(u'类型分类')
    type_validation_regex = StringField(u'类型验证正则')
    type_validation_expect = StringField(u'类型验证需求')


class CaseClassificationForm(FlaskForm):
    name = StringField(u'案例分类名称', validators=[DataRequired()])
    name_expanded = StringField(u'案例分类名称扩展', validators=[DataRequired()])
    description = StringField(u'案例分类描述', validators=[DataRequired()])


class EvidenceTypeForm(FlaskForm):
    name = StringField(u'证据类型名称', validators=[DataRequired()])
    description = StringField(u'证据类型描述', validators=[DataRequired()])


class CaseStateForm(FlaskForm):
    state_name = StringField(u'案例状态名称', validators=[DataRequired()])
    state_description = StringField(u'案例状态描述', validators=[DataRequired()])


class AddReportTemplateForm(FlaskForm):
    report_name = StringField(u'报告名称', validators=[DataRequired()])
    report_description = StringField(u'报告描述', validators=[DataRequired()])
    report_name_format = StringField(u'报告名称格式', validators=[DataRequired()])
    report_language = SelectField(u'语言', validators=[DataRequired()])
    report_type = SelectField(u'报告类型', validators=[DataRequired()])


class CaseTemplateForm(FlaskForm):
    case_template_json = TextAreaField(u'案例模板 JSON', validators=[DataRequired()])


class AddUserForm(FlaskForm):
    user_login = StringField(u'名称', validators=[DataRequired()])
    user_name = StringField(u'用户名', validators=[DataRequired()])
    user_password = PasswordField(u'密码', validators=[DataRequired()])
    user_email = StringField(u'邮箱', validators=[DataRequired(), Email()])
    user_is_service_account = BooleanField(u'作为服务账户')


class AddGroupForm(FlaskForm):
    group_name = StringField(u'组名称', validators=[DataRequired()])
    group_description = StringField(u'组描述', validators=[DataRequired()])


class AddOrganisationForm(FlaskForm):
    org_name = StringField(u'组织名称', validators=[DataRequired()])
    org_description = StringField(u'组织描述', validators=[DataRequired()])
    org_url = StringField(u'组织url', validators=[DataRequired()])
    org_logo = StringField(u'组织logo', validators=[DataRequired()])
    org_email = StringField(u'组织邮箱', validators=[DataRequired()])
    org_nationality = StringField(u'组织国家', validators=[DataRequired()])
    org_sector = StringField(u'组织地区', validators=[DataRequired()])
    org_type = StringField(u'组织类型', validators=[DataRequired()])


class ModalAddCaseAssetForm(FlaskForm):
    asset_id = SelectField(u'资产类型', validators=[DataRequired()])


class AddCaseForm(FlaskForm):
    case_name = StringField(u'案例名称', validators=[InputRequired()])
    case_description = StringField(u'案例描述', validators=[InputRequired()])
    case_soc_id = StringField(u'SOC案例')
    case_customer = SelectField(u'客户', validators=[InputRequired()])
    case_organisations = SelectMultipleField(u'组织')
    classification_id = SelectField(u'分类')
    case_template_id = SelectField(u'案例模板')


class ContactForm(FlaskForm):
    contact_name = StringField(u'联系人名称', validators=[DataRequired()])
    contact_role = StringField(u'联系人角色', validators=[DataRequired()])
    contact_email = StringField(u'联系人邮箱', validators=[DataRequired(), Email()])
    contact_work_phone = StringField(u'工作电话', validators=[DataRequired()])
    contact_mobile_phone = StringField(u'移动电话', validators=[DataRequired()])
    contact_note = TextAreaField(u'联系人描述', validators=[DataRequired()])


class PipelinesCaseForm(FlaskForm):
    pipeline = SelectField(u'处理管道')


class AssetBasicForm(FlaskForm):
    asset_name = StringField(u'名称', validators=[DataRequired()])
    asset_description = TextAreaField(u'描述')
    asset_domain = StringField(u'域名')
    asset_ip = StringField(u'IP')
    asset_info = TextAreaField(u'资产信息')
    asset_compromise_status_id = SelectField(u'入侵状态')
    asset_type_id = SelectField(u'资产类型', validators=[DataRequired()])
    analysis_status_id = SelectField(u'资产状态', validators=[DataRequired()])
    asset_tags = StringField(u'资产标签')


class CaseEventForm(FlaskForm):
    event_title = StringField(u'事件名称', validators=[DataRequired()])
    event_source = StringField(u'事件来源')
    event_content = TextAreaField(u'事件描述')
    event_raw = TextAreaField(u'事件原始数据')
    event_assets = SelectField(u'事件资产')
    event_category_id = SelectField(u'事件分类')
    event_tz = StringField(u'事件时区', validators=[DataRequired()])
    event_in_summary = BooleanField(u'添加到摘要')
    event_tags = StringField(u'事件标签')
    event_in_graph = BooleanField(u'显示在图表')


class CaseTaskForm(FlaskForm):
    task_title = StringField(u'任务标题', validators=[DataRequired()])
    task_description = TextAreaField(u'任务描述')
    task_status_id = SelectField(u'任务状态', validators=[DataRequired()])
    task_assignees_id = SelectMultipleField(u'分配人')
    task_tags = StringField(u'任务标签')


class CaseGlobalTaskForm(FlaskForm):
    task_title = StringField(u'任务标题')
    task_description = TextAreaField(u'任务描述')
    task_assignee_id = SelectField(u'任务分配')
    task_status_id = SelectField(u'任务状态')
    task_tags = StringField(u'任务标签')


class ModalAddCaseIOCForm(FlaskForm):
    ioc_tags = StringField(u'IOC标签')
    ioc_value = TextAreaField(u'IOC值', validators=[DataRequired()])
    ioc_description = TextAreaField(u'IOC描述')
    ioc_type_id = SelectField(u'IOC类型', validators=[DataRequired()])
    ioc_tlp_id = SelectField(u'IOC TLP', validators=[DataRequired()])


class ModalDSFileForm(FlaskForm):
    file_original_name = StringField(u'文件名', validators=[DataRequired()])
    file_description = TextAreaField(u'文件描述')
    file_password = StringField(u'文件密码')
    file_is_ioc = BooleanField(u'文件是IOC')
    file_is_evidence = BooleanField(u'文件是证据')


class CaseNoteForm(FlaskForm):
    note_title = StringField(u'笔记标题', validators=[DataRequired()])
    note_content = StringField(u'笔记内容')


class AddModuleForm(FlaskForm):
    module_name = StringField(u'模块名称', validators=[DataRequired()])


class UpdateModuleParameterForm(FlaskForm):
    module_name = StringField(u'模块名称', validators=[DataRequired()])
