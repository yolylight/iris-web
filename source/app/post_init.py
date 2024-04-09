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
import json

from pathlib import Path

import glob
import os
import random
import secrets
import string
import socket
import time
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, exc, or_, text
from sqlalchemy_utils import create_database
from sqlalchemy_utils import database_exists

from app import app
from app import bc
from app import celery
from app import db
from app.datamgmt.iris_engine.modules_db import iris_module_disable_by_id
from app.datamgmt.manage.manage_groups_db import add_case_access_to_group
from app.datamgmt.manage.manage_users_db import add_user_to_group
from app.datamgmt.manage.manage_users_db import add_user_to_organisation
from app.iris_engine.access_control.utils import ac_add_user_effective_access
from app.iris_engine.demo_builder import create_demo_cases
from app.iris_engine.access_control.utils import ac_get_mask_analyst
from app.datamgmt.manage.manage_groups_db import get_group_by_name
from app.iris_engine.access_control.utils import ac_get_mask_full_permissions
from app.iris_engine.module_handler.module_handler import check_module_health
from app.iris_engine.module_handler.module_handler import instantiate_module_from_name
from app.iris_engine.module_handler.module_handler import register_module
from app.models import create_safe_limited
from app.models.alerts import Severity, AlertStatus, AlertResolutionStatus
from app.models.authorization import CaseAccessLevel
from app.models.authorization import Group
from app.models.authorization import Organisation
from app.models.authorization import User
from app.models.cases import Cases, CaseState
from app.models.cases import Client
from app.models.models import AnalysisStatus, CaseClassification, ReviewStatus, ReviewStatusList, EvidenceTypes
from app.models.models import AssetsType
from app.models.models import EventCategory
from app.models.models import IocType
from app.models.models import IrisHook
from app.models.models import IrisModule
from app.models.models import Languages
from app.models.models import OsType
from app.models.models import ReportType
from app.models.models import ServerSettings
from app.models.models import TaskStatus
from app.models.models import Tlp
from app.models.models import create_safe
from app.models.models import create_safe_attr
from app.models.models import get_by_value_or_create
from app.models.models import get_or_create
from app.iris_engine.demo_builder import create_demo_users

log = app.logger

# Get the database host and port from environment variables
db_host = app.config.get('PG_SERVER')
db_port = int(app.config.get('PG_PORT'))

# Get the retry parameters from environment variables
retry_count = int(app.config.get('DB_RETRY_COUNT'))
retry_delay = int(app.config.get('DB_RETRY_DELAY'))


def connect_to_database(host: str, port: int) -> bool:
    """Attempts to connect to a database at the specified host and port.

    Args:
        host: A string representing the hostname or IP address of the database server.
        port: An integer representing the port number to connect to.

    Returns:
        A boolean value indicating whether the connection was successful.
    """
    # Create a new socket object
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        # Try to connect to the database
        s.connect((host, port))
        # If the connection was successful, close the socket and return True
        s.close()
        return True
    except socket.error:
        # If the connection failed, close the socket and return False
        s.close()
        return False


def run_post_init(development=False):
    """Runs post-initiation steps for the IRIS application.

    Args:
        development: A boolean value indicating whether the application is running in development mode.
    """
    # Log the IRIS version and post-initiation steps
    log.info(f'IRIS {app.config.get("IRIS_VERSION")}')
    log.info("Running post initiation steps")

    if os.getenv("IRIS_WORKER") is None:
        # Attempt to connect to the database with retries
        log.info("Attempting to connect to the database...")
        for i in range(retry_count):
            log.info("Connecting to database, attempt " + str(i+1) + "/" + str(retry_count))
            conn = connect_to_database(db_host,db_port)
            if conn:
                break
            log.info("Retrying in " + str(retry_delay) + "seconds...")
            time.sleep(retry_delay)
        # If the connection is still not established, exit the script
        if not conn:
            log.info("Failed to connect to database after " + str(retry_count) + " attempts.")
            exit(1)

        # Setup database before everything
        #log.info("Adding pgcrypto extension")
        #pg_add_pgcrypto_ext()

        # Setup database before everything
        with app.app_context():
            log.info("Creating all Iris tables")
            db.create_all(bind_key=None)
            db.session.commit()

            log.info("Creating Celery metatasks tables")
            create_safe_db(db_name="iris_tasks")
            db.create_all(bind_key="iris_tasks")
            db.session.commit()

            log.info("Running DB migration")

            alembic_cfg = Config(file_='app/alembic.ini')
            alembic_cfg.set_main_option('sqlalchemy.url', app.config['SQLALCHEMY_DATABASE_URI'])
            command.upgrade(alembic_cfg, 'head')

            # Create base server settings if they don't exist
            srv_settings = ServerSettings.query.first()
            if srv_settings is None:
                log.info("Creating base server settings")
                create_safe_server_settings()
                srv_settings = ServerSettings.query.first()

            prevent_objects = srv_settings.prevent_post_objects_repush

            # Create base languages, OS types, IOC types, attributes, report types, TLP, event categories, assets,
            # analysis status, case classification, task status, severities, alert status, case states, and hooks
            log.info("Creating base languages")
            create_safe_languages()

            log.info("Creating base os types")
            create_safe_os_types()

            if not prevent_objects:
                log.info("Creating base IOC types")
                create_safe_ioctypes()

            log.info("Creating base attributes")
            create_safe_attributes()

            log.info("Creating base report types")
            create_safe_report_types()

            log.info("Creating base TLP")
            create_safe_tlp()

            log.info("Creating base events categories")
            create_safe_events_cats()

            if not prevent_objects:
                log.info("Creating base assets")
                create_safe_assets()

            log.info("Creating base analysis status")
            create_safe_analysis_status()

            if not prevent_objects:
                log.info("Creating base case classification")
                create_safe_classifications()

            log.info("Creating base tasks status")
            create_safe_task_status()

            log.info("Creating base severities")
            create_safe_severities()

            log.info("Creating base alert status")
            create_safe_alert_status()

            log.info("Creating base evidence types")
            create_safe_evidence_types()

            log.info("Creating base alert resolution status")
            create_safe_alert_resolution_status()

            if not prevent_objects:
                log.info("Creating base case states")
                create_safe_case_states()

            log.info("Creating base review status")
            create_safe_review_status()

            log.info("Creating base hooks")
            create_safe_hooks()

            # Create initial authorization model, administrative user, and customer
            log.info("Creating initial authorisation model")
            def_org, gadm, ganalysts = create_safe_auth_model()

            log.info("Creating first administrative user")
            admin, pwd = create_safe_admin(def_org=def_org, gadm=gadm)

            if not srv_settings.prevent_post_mod_repush:
                log.info("Registering default modules")
                register_default_modules()

            log.info("Creating initial customer")
            client = create_safe_client()

            log.info("Creating initial case")
            create_safe_case(
                user=admin,
                client=client,
                groups=[gadm, ganalysts]
            )

            # Setup symlinks for custom_assets
            log.info("Creating symlinks for custom asset icons")
            custom_assets_symlinks()

            # If demo mode is enabled, create demo users and cases
            if app.config.get('DEMO_MODE_ENABLED') == 'True':
                log.warning("============================")
                log.warning("|  THIS IS DEMO INSTANCE   |")
                log.warning("| DO NOT USE IN PRODUCTION |")
                log.warning("============================")
                users_data = create_demo_users(def_org, gadm, ganalysts,
                                               int(app.config.get('DEMO_USERS_COUNT', 10)),
                                               app.config.get('DEMO_USERS_SEED'),
                                               int(app.config.get('DEMO_ADM_COUNT', 4)),
                                               app.config.get('DEMO_ADM_SEED'))

                create_demo_cases(users_data=users_data,
                                  cases_count=int(app.config.get('DEMO_CASES_COUNT', 20)),
                                  clients_count=int(app.config.get('DEMO_CLIENTS_COUNT', 4)))

            # Log completion message
            log.info("Post-init steps completed")
            log.warning("===============================")
            log.warning(f"| IRIS IS READY on port  {os.getenv('INTERFACE_HTTPS_PORT')} |")
            log.warning("===============================")

            # If an administrative user was created, log their credentials
            if pwd is not None:
                log.info(f'You can now login with user {admin.user} and password >>> {pwd} <<< '
                         f'on {os.getenv("INTERFACE_HTTPS_PORT")}')


def create_safe_db(db_name):
    """Creates a new database with the specified name if it does not already exist.

    Args:
        db_name: A string representing the name of the database to create.
    """
    # Create a new engine object for the specified database
    engine = create_engine(app.config["SQALCHEMY_PIGGER_URI"] + db_name)

    # Check if the database already exists
    if not database_exists(engine.url):
        # If the database does not exist, create it
        create_database(engine.url)

    # Dispose of the engine object
    engine.dispose()


def create_safe_hooks():
    # --- Alert
    create_safe(db.session, IrisHook, hook_name='on_postload_alert_create',
                hook_description='Triggered on alert creation, after commit in DB')

    create_safe(db.session, IrisHook, hook_name='on_postload_alert_delete',
                hook_description='Triggered on alert deletion, after commit in DB')

    create_safe(db.session, IrisHook, hook_name='on_postload_alert_update',
                hook_description='Triggered on alert update, after commit in DB')

    create_safe(db.session, IrisHook, hook_name='on_postload_alert_resolution_update',
                hook_description='Triggered on alert resolution update, after commit in DB')

    create_safe(db.session, IrisHook, hook_name='on_postload_alert_status_update',
                hook_description='Triggered on alert status update, after commit in DB')

    create_safe(db.session, IrisHook, hook_name='on_postload_alert_escalate',
                hook_description='Triggered on alert escalation, after commit in DB')

    create_safe(db.session, IrisHook, hook_name='on_postload_alert_merge',
                hook_description='Triggered on alert merge, after commit in DB')

    create_safe(db.session, IrisHook, hook_name='on_postload_alert_unmerge',
                hook_description='Triggered on alert unmerge, after commit in DB')

    create_safe(db.session, IrisHook, hook_name='on_manual_trigger_alert',
                hook_description='Triggered upon user action')

    # --- Case
    create_safe(db.session, IrisHook, hook_name='on_preload_case_create',
                hook_description='Triggered on case creation, before commit in DB')
    create_safe(db.session, IrisHook, hook_name='on_postload_case_create',
                hook_description='Triggered on case creation, after commit in DB')

    create_safe(db.session, IrisHook, hook_name='on_preload_case_delete',
                hook_description='Triggered on case deletion, before commit in DB')
    create_safe(db.session, IrisHook, hook_name='on_postload_case_delete',
                hook_description='Triggered on case deletion, after commit in DB')

    create_safe(db.session, IrisHook, hook_name='on_postload_case_update',
                hook_description='Triggered on case update, after commit in DB')

    create_safe(db.session, IrisHook, hook_name='on_manual_trigger_case',
                hook_description='Triggered upon user action')

    # --- Assets
    create_safe(db.session, IrisHook, hook_name='on_preload_asset_create',
                hook_description='Triggered on asset creation, before commit in DB')
    create_safe(db.session, IrisHook, hook_name='on_postload_asset_create',
                hook_description='Triggered on asset creation, after commit in DB')

    create_safe(db.session, IrisHook, hook_name='on_preload_asset_update',
                hook_description='Triggered on asset update, before commit in DB')
    create_safe(db.session, IrisHook, hook_name='on_postload_asset_update',
                hook_description='Triggered on asset update, after commit in DB')

    create_safe(db.session, IrisHook, hook_name='on_preload_asset_delete',
                hook_description='Triggered on asset deletion, before commit in DB')
    create_safe(db.session, IrisHook, hook_name='on_postload_asset_delete',
                hook_description='Triggered on asset deletion, after commit in DB')

    create_safe(db.session, IrisHook, hook_name='on_manual_trigger_asset',
                hook_description='Triggered upon user action')

    # --- Notes
    create_safe(db.session, IrisHook, hook_name='on_preload_note_create',
                hook_description='Triggered on note creation, before commit in DB')
    create_safe(db.session, IrisHook, hook_name='on_postload_note_create',
                hook_description='Triggered on note creation, after commit in DB')

    create_safe(db.session, IrisHook, hook_name='on_preload_note_update',
                hook_description='Triggered on note update, before commit in DB')
    create_safe(db.session, IrisHook, hook_name='on_postload_note_update',
                hook_description='Triggered on note update, after commit in DB')

    create_safe(db.session, IrisHook, hook_name='on_preload_note_delete',
                hook_description='Triggered on note deletion, before commit in DB')
    create_safe(db.session, IrisHook, hook_name='on_postload_note_delete',
                hook_description='Triggered on note deletion, after commit in DB')

    create_safe(db.session, IrisHook, hook_name='on_manual_trigger_note',
                hook_description='Triggered upon user action')

    # --- iocs
    create_safe(db.session, IrisHook, hook_name='on_preload_ioc_create',
                hook_description='Triggered on ioc creation, before commit in DB')
    create_safe(db.session, IrisHook, hook_name='on_postload_ioc_create',
                hook_description='Triggered on ioc creation, after commit in DB')

    create_safe(db.session, IrisHook, hook_name='on_preload_ioc_update',
                hook_description='Triggered on ioc update, before commit in DB')
    create_safe(db.session, IrisHook, hook_name='on_postload_ioc_update',
                hook_description='Triggered on ioc update, after commit in DB')

    create_safe(db.session, IrisHook, hook_name='on_preload_ioc_delete',
                hook_description='Triggered on ioc deletion, before commit in DB')
    create_safe(db.session, IrisHook, hook_name='on_postload_ioc_delete',
                hook_description='Triggered on ioc deletion, after commit in DB')

    create_safe(db.session, IrisHook, hook_name='on_manual_trigger_ioc',
                hook_description='Triggered upon user action')

    # --- events
    create_safe(db.session, IrisHook, hook_name='on_preload_event_create',
                hook_description='Triggered on event creation, before commit in DB')
    create_safe(db.session, IrisHook, hook_name='on_postload_event_create',
                hook_description='Triggered on event creation, after commit in DB')
    create_safe(db.session, IrisHook, hook_name='on_preload_event_duplicate',
                hook_description='Triggered on event duplication, before commit in DB')

    create_safe(db.session, IrisHook, hook_name='on_preload_event_update',
                hook_description='Triggered on event update, before commit in DB')
    create_safe(db.session, IrisHook, hook_name='on_postload_event_update',
                hook_description='Triggered on event update, after commit in DB')

    create_safe(db.session, IrisHook, hook_name='on_preload_event_delete',
                hook_description='Triggered on event deletion, before commit in DB')
    create_safe(db.session, IrisHook, hook_name='on_postload_event_delete',
                hook_description='Triggered on event deletion, after commit in DB')

    create_safe(db.session, IrisHook, hook_name='on_manual_trigger_event',
                hook_description='Triggered upon user action')

    # --- evidence
    create_safe(db.session, IrisHook, hook_name='on_preload_evidence_create',
                hook_description='Triggered on evidence creation, before commit in DB')
    create_safe(db.session, IrisHook, hook_name='on_postload_evidence_create',
                hook_description='Triggered on evidence creation, after commit in DB')

    create_safe(db.session, IrisHook, hook_name='on_preload_evidence_update',
                hook_description='Triggered on evidence update, before commit in DB')
    create_safe(db.session, IrisHook, hook_name='on_postload_evidence_update',
                hook_description='Triggered on evidence update, after commit in DB')

    create_safe(db.session, IrisHook, hook_name='on_preload_evidence_delete',
                hook_description='Triggered on evidence deletion, before commit in DB')
    create_safe(db.session, IrisHook, hook_name='on_postload_evidence_delete',
                hook_description='Triggered on evidence deletion, after commit in DB')

    create_safe(db.session, IrisHook, hook_name='on_manual_trigger_evidence',
                hook_description='Triggered upon user action')

    # --- tasks
    create_safe(db.session, IrisHook, hook_name='on_preload_task_create',
                hook_description='Triggered on task creation, before commit in DB')
    create_safe(db.session, IrisHook, hook_name='on_postload_task_create',
                hook_description='Triggered on task creation, after commit in DB')

    create_safe(db.session, IrisHook, hook_name='on_preload_task_update',
                hook_description='Triggered on task update, before commit in DB')
    create_safe(db.session, IrisHook, hook_name='on_postload_task_update',
                hook_description='Triggered on task update, after commit in DB')

    create_safe(db.session, IrisHook, hook_name='on_preload_task_delete',
                hook_description='Triggered on task deletion, before commit in DB')
    create_safe(db.session, IrisHook, hook_name='on_postload_task_delete',
                hook_description='Triggered on task deletion, after commit in DB')

    create_safe(db.session, IrisHook, hook_name='on_manual_trigger_task',
                hook_description='Triggered upon user action')

    # --- global tasks
    create_safe(db.session, IrisHook, hook_name='on_preload_global_task_create',
                hook_description='Triggered on global task creation, before commit in DB')
    create_safe(db.session, IrisHook, hook_name='on_postload_global_task_create',
                hook_description='Triggered on global task creation, after commit in DB')

    create_safe(db.session, IrisHook, hook_name='on_preload_global_task_update',
                hook_description='Triggered on task update, before commit in DB')
    create_safe(db.session, IrisHook, hook_name='on_postload_global_task_update',
                hook_description='Triggered on global task update, after commit in DB')

    create_safe(db.session, IrisHook, hook_name='on_preload_global_task_delete',
                hook_description='Triggered on task deletion, before commit in DB')
    create_safe(db.session, IrisHook, hook_name='on_postload_global_task_delete',
                hook_description='Triggered on global task deletion, after commit in DB')

    create_safe(db.session, IrisHook, hook_name='on_manual_trigger_global_task',
                hook_description='Triggered upon user action')

    # --- reports
    create_safe(db.session, IrisHook, hook_name='on_preload_report_create',
                hook_description='Triggered on report creation, before generation in DB')
    create_safe(db.session, IrisHook, hook_name='on_postload_report_create',
                hook_description='Triggered on report creation, before download of the document')

    create_safe(db.session, IrisHook, hook_name='on_preload_activities_report_create',
                hook_description='Triggered on activities report creation, before generation in DB')
    create_safe(db.session, IrisHook, hook_name='on_postload_activities_report_create',
                hook_description='Triggered on activities report creation, before download of the document')

    # --- comments
    create_safe(db.session, IrisHook, hook_name='on_postload_asset_commented',
                hook_description='Triggered on event commented, after commit in DB')
    create_safe(db.session, IrisHook, hook_name='on_postload_asset_comment_update',
                hook_description='Triggered on event comment update, after commit in DB')
    create_safe(db.session, IrisHook, hook_name='on_postload_asset_comment_delete',
                hook_description='Triggered on event comment deletion, after commit in DB')

    create_safe(db.session, IrisHook, hook_name='on_postload_evidence_commented',
                hook_description='Triggered on evidence commented, after commit in DB')
    create_safe(db.session, IrisHook, hook_name='on_postload_evidence_comment_update',
                hook_description='Triggered on evidence comment update, after commit in DB')
    create_safe(db.session, IrisHook, hook_name='on_postload_evidence_comment_delete',
                hook_description='Triggered on evidence comment deletion, after commit in DB')

    create_safe(db.session, IrisHook, hook_name='on_postload_task_commented',
                hook_description='Triggered on task commented, after commit in DB')
    create_safe(db.session, IrisHook, hook_name='on_postload_task_comment_update',
                hook_description='Triggered on task comment update, after commit in DB')
    create_safe(db.session, IrisHook, hook_name='on_postload_task_comment_delete',
                hook_description='Triggered on task comment deletion, after commit in DB')

    create_safe(db.session, IrisHook, hook_name='on_postload_ioc_commented',
                hook_description='Triggered on IOC commented, after commit in DB')
    create_safe(db.session, IrisHook, hook_name='on_postload_ioc_comment_update',
                hook_description='Triggered on IOC comment update, after commit in DB')
    create_safe(db.session, IrisHook, hook_name='on_postload_ioc_comment_delete',
                hook_description='Triggered on IOC comment deletion, after commit in DB')

    create_safe(db.session, IrisHook, hook_name='on_postload_event_commented',
                hook_description='Triggered on event commented, after commit in DB')
    create_safe(db.session, IrisHook, hook_name='on_postload_event_comment_update',
                hook_description='Triggered on event comment update, after commit in DB')
    create_safe(db.session, IrisHook, hook_name='on_postload_event_comment_delete',
                hook_description='Triggered on event comment deletion, after commit in DB')

    create_safe(db.session, IrisHook, hook_name='on_postload_note_commented',
                hook_description='Triggered on note commented, after commit in DB')
    create_safe(db.session, IrisHook, hook_name='on_postload_note_comment_update',
                hook_description='Triggered on note comment update, after commit in DB')
    create_safe(db.session, IrisHook, hook_name='on_postload_note_comment_delete',
                hook_description='Triggered on note comment deletion, after commit in DB')

    create_safe(db.session, IrisHook, hook_name='on_postload_alert_commented',
                hook_description='Triggered on alert commented, after commit in DB')
    create_safe(db.session, IrisHook, hook_name='on_postload_alert_comment_update',
                hook_description='Triggered on alert comment update, after commit in DB')
    create_safe(db.session, IrisHook, hook_name='on_postload_alert_comment_delete',
                hook_description='Triggered on alert comment deletion, after commit in DB')


def pg_add_pgcrypto_ext():
    """Adds the pgcrypto extension to the PostgreSQL database.

    This extension provides cryptographic functions for PostgreSQL.

    """

    # Set the application context
    with app.app_context():

        # Open a connection to the iris_db database
        with db.engine.connect() as con:
            # Execute a SQL command to create the pgcrypto extension if it does not already exist
            con.execute(text('CREATE EXTENSION IF NOT EXISTS pgcrypto CASCADE;'))
            db.session.commit()
            log.info("pgcrypto extension added")


def create_safe_languages():
    """Creates new Language objects if they do not already exist.

    This function creates new Language objects with the specified name and code
    if they do not already exist in the database.

    """
    # Create new Language objects for each language
    create_safe(db.session, Languages, name="french", code="FR")
    create_safe(db.session, Languages, name="english", code="EN")
    create_safe(db.session, Languages, name="german", code="DE")
    create_safe(db.session, Languages, name="bulgarian", code="BG")
    create_safe(db.session, Languages, name="croatian", code="HR")
    create_safe(db.session, Languages, name="danish", code="DK")
    create_safe(db.session, Languages, name="dutch", code="NL")
    create_safe(db.session, Languages, name="estonian", code="EE")
    create_safe(db.session, Languages, name="finnish", code="FI")
    create_safe(db.session, Languages, name="greek", code="GR")
    create_safe(db.session, Languages, name="hungarian", code="HU")
    create_safe(db.session, Languages, name="irish", code="IE")
    create_safe(db.session, Languages, name="italian", code="IT")
    create_safe(db.session, Languages, name="latvian", code="LV")
    create_safe(db.session, Languages, name="lithuanian", code="LT")
    create_safe(db.session, Languages, name="maltese", code="MT")
    create_safe(db.session, Languages, name="polish", code="PL")
    create_safe(db.session, Languages, name="portuguese", code="PT")
    create_safe(db.session, Languages, name="romanian", code="RO")
    create_safe(db.session, Languages, name="slovak", code="SK")
    create_safe(db.session, Languages, name="slovenian", code="SI")
    create_safe(db.session, Languages, name="spanish", code="ES")
    create_safe(db.session, Languages, name="swedish", code="SE")
    create_safe(db.session, Languages, name="indian", code="IN")
    create_safe(db.session, Languages, name="chinese", code="CN")
    create_safe(db.session, Languages, name="korean", code="KR")
    create_safe(db.session, Languages, name="arabic", code="AR")
    create_safe(db.session, Languages, name="japanese", code="JP")
    create_safe(db.session, Languages, name="turkish", code="TR")
    create_safe(db.session, Languages, name="vietnamese", code="VN")
    create_safe(db.session, Languages, name="thai", code="TH")
    create_safe(db.session, Languages, name="hebrew", code="IL")
    create_safe(db.session, Languages, name="czech", code="CZ")
    create_safe(db.session, Languages, name="norwegian", code="NO")
    create_safe(db.session, Languages, name="brazilian", code="BR")
    create_safe(db.session, Languages, name="ukrainian", code="UA")
    create_safe(db.session, Languages, name="catalan", code="CA")
    create_safe(db.session, Languages, name="serbian", code="RS")
    create_safe(db.session, Languages, name="persian", code="IR")
    create_safe(db.session, Languages, name="afrikaans", code="ZA")
    create_safe(db.session, Languages, name="albanian", code="AL")
    create_safe(db.session, Languages, name="armenian", code="AM")


def create_safe_events_cats():
    """Creates new EventCategory objects if they do not already exist.

    This function creates new EventCategory objects with the specified name
    if they do not already exist in the database.

    """
    # Create new EventCategory objects for each category
    create_safe(db.session, EventCategory, name="未指定")
    create_safe(db.session, EventCategory, name="合规")
    create_safe(db.session, EventCategory, name="补救")
    create_safe(db.session, EventCategory, name="初始访问")
    create_safe(db.session, EventCategory, name="执行")
    create_safe(db.session, EventCategory, name="持久化")
    create_safe(db.session, EventCategory, name="权限提升")
    create_safe(db.session, EventCategory, name="防御绕过")
    create_safe(db.session, EventCategory, name="凭据访问")
    create_safe(db.session, EventCategory, name="发现")
    create_safe(db.session, EventCategory, name="横向移动")
    create_safe(db.session, EventCategory, name="手机")
    create_safe(db.session, EventCategory, name="命令与控制")
    create_safe(db.session, EventCategory, name="泄露")
    create_safe(db.session, EventCategory, name="影响")


def create_safe_classifications():
    """Creates new CaseClassification objects if they do not already exist.

    This function reads the MISP classification taxonomy from a JSON file and creates
    new CaseClassification objects with the specified name, name_expanded, and description
    if they do not already exist in the database.

    """
    # Read the MISP classification taxonomy from a JSON file
    log.info("Reading MISP classification taxonomy from resources/misp.classification.taxonomy.json")
    with open(Path(__file__).parent / 'resources' / 'misp.classification.taxonomy.json') as data_file:
        data = json.load(data_file)
        # Iterate over each classification in the taxonomy
        for c in data.get('values'):
            predicate = c.get('predicate')
            entries = c.get('entry')
            # Iterate over each entry in the classification
            for entry in entries:
                # Create a new CaseClassification object with the specified name, name_expanded, and description
                create_safe(db.session, CaseClassification,
                            name=f"{predicate}:{entry.get('value')}",
                            name_expanded=f"{predicate.title()}: {entry.get('expanded')}",
                            description=entry['description'])


def create_safe_analysis_status():
    """Creates new AnalysisStatus objects if they do not already exist.

    This function creates new AnalysisStatus objects with the specified name
    if they do not already exist in the database.

    """
    # Create new AnalysisStatus objects for each status
    create_safe(db.session, AnalysisStatus, name='未指定')
    create_safe(db.session, AnalysisStatus, name='待完成')
    create_safe(db.session, AnalysisStatus, name='已开始')
    create_safe(db.session, AnalysisStatus, name='待定')
    create_safe(db.session, AnalysisStatus, name='已取消')
    create_safe(db.session, AnalysisStatus, name='已完成')


def create_safe_task_status():
    """Creates new TaskStatus objects if they do not already exist.

    This function creates new TaskStatus objects with the specified status name,
    status description, and Bootstrap color if they do not already exist in the database.

    """
    # Create new TaskStatus objects for each status
    create_safe(db.session, TaskStatus, status_name='待完成', status_description="", status_bscolor="danger")
    create_safe(db.session, TaskStatus, status_name='处理中', status_description="", status_bscolor="warning")
    create_safe(db.session, TaskStatus, status_name='暂停', status_description="", status_bscolor="muted")
    create_safe(db.session, TaskStatus, status_name='已完成', status_description="", status_bscolor="success")
    create_safe(db.session, TaskStatus, status_name='已取消', status_description="", status_bscolor="muted")


def create_safe_severities():
    """Creates new Severity objects if they do not already exist.

    This function creates new Severity objects with the specified severity name
    and severity description if they do not already exist in the database.

    """
    # Create new Severity objects for each severity level
    create_safe(db.session, Severity, severity_name='未指定', severity_description="Unspecified")
    create_safe(db.session, Severity, severity_name='信息', severity_description="Informational")
    create_safe(db.session, Severity, severity_name='低', severity_description="Low")
    create_safe(db.session, Severity, severity_name='中', severity_description="Medium")
    create_safe(db.session, Severity, severity_name='高', severity_description="High")
    create_safe(db.session, Severity, severity_name='严重', severity_description="Critical")


def create_safe_alert_status():
    """Creates new AlertStatus objects if they do not already exist.

    This function creates new AlertStatus objects with the specified status name
    and status description if they do not already exist in the database.

    """
    # Create new AlertStatus objects for each status
    create_safe(db.session, AlertStatus, status_name='未指定', status_description="未指定")
    create_safe(db.session, AlertStatus, status_name='新建', status_description="告警新建并且未分配")
    create_safe(db.session, AlertStatus, status_name='已分配', status_description="告警已分配用户并"
                                                                                    "待调查")
    create_safe(db.session, AlertStatus, status_name='处理中', status_description="告警调查中")
    create_safe(db.session, AlertStatus, status_name='待定', status_description="告警待定状态")
    create_safe(db.session, AlertStatus, status_name='已关闭', status_description="告警关闭,未采取动作")
    create_safe(db.session, AlertStatus, status_name='已合并', status_description="告警合并到已有案例")
    create_safe(db.session, AlertStatus, status_name='已升级', status_description="告警转换为新案例")


def create_safe_evidence_types():
    """Creates new Evidence Types objects if they do not already exist.

    This function creates new Evidence Types objects with the specified type name
    and type description if they do not already exist in the database.

    """
    # Create new EvidenceType objects for each status
    create_safe(db.session, EvidenceTypes, name='未指定', description="未指定")

    create_safe(db.session, EvidenceTypes, name='HDD 映像- 通用', description="硬盘的通用副本")
    create_safe(db.session, EvidenceTypes, name='HDD 映像- DD - 其他', description="DD生成的硬盘拷贝")
    create_safe(db.session, EvidenceTypes, name='HDD 映像- DD - Windows', description="DD生成的硬盘拷贝")
    create_safe(db.session, EvidenceTypes, name='HDD 映像- DD - Unix', description="DD生成的硬盘拷贝")
    create_safe(db.session, EvidenceTypes, name='HDD 映像- DD - MacOS', description="DD生成的硬盘拷贝")

    create_safe(db.session, EvidenceTypes, name='HDD 映像- E01 - 其他', description="E01生成的硬盘映像")
    create_safe(db.session, EvidenceTypes, name='HDD 映像- E01 - Windows', description="E01生成的硬盘映像")
    create_safe(db.session, EvidenceTypes, name='HDD 映像- E01 - Unix', description="E01生成的硬盘映像")
    create_safe(db.session, EvidenceTypes, name='HDD 映像- E01 - MacOS', description="E01生成的硬盘映像")

    create_safe(db.session, EvidenceTypes, name='HDD 映像- AFF4 - 其他', description="AFF4生成的硬盘映像")
    create_safe(db.session, EvidenceTypes, name='HDD 映像- AFF4 - Windows', description="AFF4生成的硬盘映像")
    create_safe(db.session, EvidenceTypes, name='HDD 映像- AFF4 - Unix', description="AFF4生成的硬盘映像")
    create_safe(db.session, EvidenceTypes, name='HDD 映像 - AFF4 - MacOS', description="AFF4生成的硬盘映像")

    create_safe(db.session, EvidenceTypes, name='SSD 镜像- 通用', description="固态硬盘的通用副本")
    create_safe(db.session, EvidenceTypes, name='SSD 镜像- DD - 其他', description="固态硬盘的 DD 副本")
    create_safe(db.session, EvidenceTypes, name='SSD 镜像- DD - Windows', description="固态硬盘的 DD 副本")
    create_safe(db.session, EvidenceTypes, name='SSD 镜像- DD - Unix', description="固态硬盘的 DD 副本")
    create_safe(db.session, EvidenceTypes, name='SSD 镜像- DD - MacOS', description="固态硬盘的 DD 副本")

    create_safe(db.session, EvidenceTypes, name='SSD 镜像 - E01 - 其他', description="固态硬盘的 EO1 副本")
    create_safe(db.session, EvidenceTypes, name='SSD 镜像 - E01 - Windows', description="固态硬盘的 EO1 副本")
    create_safe(db.session, EvidenceTypes, name='SSD 镜像 - E01 - Unix', description="固态硬盘的 EO1 副本")
    create_safe(db.session, EvidenceTypes, name='SSD 镜像 - E01 - MacOS', description="固态硬盘上的 MacOS EO1 副本")

    create_safe(db.session, EvidenceTypes, name='SSD 镜像 - AFF4 - Other', description="AFF4 生成固态硬盘副本")
    create_safe(db.session, EvidenceTypes, name='SSD 镜像 - AFF4 - Windows', description="AFF4 生成固态硬盘副本")
    create_safe(db.session, EvidenceTypes, name='SSD 镜像 - AFF4 - Unix', description="AFF4 生成固态硬盘副本")
    create_safe(db.session, EvidenceTypes, name='SSD 镜像 - AFF4 - MacOS', description="AFF4 生成固态硬盘副本")

    create_safe(db.session, EvidenceTypes, name='VM 镜像 - 通用', description="通用的虚拟机副本")
    create_safe(db.session, EvidenceTypes, name='VM 镜像 - Linux 服务器', description="Linux 服务器虚拟机副本")
    create_safe(db.session, EvidenceTypes, name='VM 镜像 - Windows 服务器', description="Windows 服务器虚拟机副本")

    create_safe(db.session, EvidenceTypes, name='电话映像 - Android', description="Android手机的副本")
    create_safe(db.session, EvidenceTypes, name='电话映像 - iPhone', description="iPhone 的副本")
    create_safe(db.session, EvidenceTypes, name='电话备份 - Android (adb)', description="Android 系统的 adb 备份")
    create_safe(db.session, EvidenceTypes, name='电话备份 - iPhone (iTunes)', description="iPhone 的 iTunes 备份")

    create_safe(db.session, EvidenceTypes, name='平板映像 - Android', description="Android平板电脑副本")
    create_safe(db.session, EvidenceTypes, name='平板映像 - iPad', description="iPad 平板电脑副本")
    create_safe(db.session, EvidenceTypes, name='平板备份 - Android (adb)', description="Android 平板电脑的 adb 备份")
    create_safe(db.session, EvidenceTypes, name='平板备份 - iPad (iTunes)', description="iTunes 备份 iPad")

    create_safe(db.session, EvidenceTypes, name='集合 - Velociraptor', description="Velociraptor 集合")
    create_safe(db.session, EvidenceTypes, name='集合 - ORC', description="ORC 集合")
    create_safe(db.session, EvidenceTypes, name='集合 - KAPE', description="KAPE 集合")

    create_safe(db.session, EvidenceTypes, name="内存取证 - 物理RAM", description="物理 RAM 取证")
    create_safe(db.session, EvidenceTypes, name="内存取证 - VMEM", description="vmem 文件")

    create_safe(db.session, EvidenceTypes, name="Logs - Linux", description="标准Linux日志")
    create_safe(db.session, EvidenceTypes, name="Logs - Windows EVTX", description="标准Windows EVTX日志")
    create_safe(db.session, EvidenceTypes, name="Logs - Windows EVT", description="标准Windows EVT日志")
    create_safe(db.session, EvidenceTypes, name="Logs - MacOS", description="标准MacOS日志")
    create_safe(db.session, EvidenceTypes, name="Logs - 通用", description="通用日志")
    create_safe(db.session, EvidenceTypes, name="Logs - 防火墙", description="防火墙日志")
    create_safe(db.session, EvidenceTypes, name="Logs - Proxy", description="代理日志")
    create_safe(db.session, EvidenceTypes, name="Logs - DNS", description="DNS日志")
    create_safe(db.session, EvidenceTypes, name="Logs - Email", description="Email日志")

    create_safe(db.session, EvidenceTypes, name="可执行文件 - Windows (PE)", description="通用 Windows 可执行文件")
    create_safe(db.session, EvidenceTypes, name="可执行文件 - Linux (ELF)", description="通用 Linux 可执行文件")
    create_safe(db.session, EvidenceTypes, name="可执行文件 - MacOS (Mach-O)", description="通用 MacOS 可执行文件")
    create_safe(db.session, EvidenceTypes, name="可执行文件 - 通用", description="通用可执行文件")

    create_safe(db.session, EvidenceTypes, name="脚本 - 通用", description="通用脚本")

    create_safe(db.session, EvidenceTypes, name="通用 - 数据块", description="通用数据块")


def create_safe_alert_resolution_status():
    """Creates new AlertResolutionStatus objects if they do not already exist.

    This function creates new AlertResolutionStatus objects with the specified resolution_status_name
    and resolution_status_description if they do not already exist in the database.

    """
    create_safe(db.session, AlertResolutionStatus, resolution_status_name='误报',
                resolution_status_description="告警是误报")
    create_safe(db.session, AlertResolutionStatus, resolution_status_name='有问题有影响',
                resolution_status_description="告警是真实的并造成了影响")
    create_safe(db.session, AlertResolutionStatus, resolution_status_name='有问题无影响',
                resolution_status_description="告警是真实的但没有影响")
    create_safe(db.session, AlertResolutionStatus, resolution_status_name='不适用',
                resolution_status_description="告警不适用")
    create_safe(db.session, AlertResolutionStatus, resolution_status_name='未知',
                resolution_status_description="未知解决状态")


def create_safe_case_states():
    """Creates new CaseState objects if they do not already exist.

    This function creates new CaseState objects with the specified state name,
    state description, and protected status if they do not already exist in the database.

    """
    # Create new CaseState objects for each state
    create_safe(db.session, CaseState, state_name='未指定', state_description="未指定", protected=True)
    create_safe(db.session, CaseState, state_name='处理中', state_description="案例正在调查")
    create_safe(db.session, CaseState, state_name='开放', state_description="案例开放中", protected=True)
    create_safe(db.session, CaseState, state_name='遏制', state_description="遏制进行中")
    create_safe(db.session, CaseState, state_name='根除', state_description="根除进行中")
    create_safe(db.session, CaseState, state_name='恢复', state_description="恢复进行中")
    create_safe(db.session, CaseState, state_name='事件后', state_description="事件后阶段")
    create_safe(db.session, CaseState, state_name='报告中', state_description="报告正在进行")
    create_safe(db.session, CaseState, state_name='已关闭', state_description="案例已关闭", protected=True)


def create_safe_review_status():
    """Creates new ReviewStatus objects if they do not already exist.

    This function creates new ReviewStatus objects with the specified status name
    if they do not already exist in the database.
    """
    create_safe(db.session, ReviewStatus, status_name=ReviewStatusList.no_review_required)
    create_safe(db.session, ReviewStatus, status_name=ReviewStatusList.not_reviewed)
    create_safe(db.session, ReviewStatus, status_name=ReviewStatusList.pending_review)
    create_safe(db.session, ReviewStatus, status_name=ReviewStatusList.review_in_progress)
    create_safe(db.session, ReviewStatus, status_name=ReviewStatusList.reviewed)


def create_safe_assets():
    """Creates new AssetsType objects if they do not already exist.

    This function creates new AssetsType objects with the specified asset name,
    asset description, and asset icons if they do not already exist in the database.

    """
    # Create new AssetsType objects for each asset type
    get_by_value_or_create(db.session, AssetsType, "asset_name", asset_name="账户",
                           asset_description="通用账户", asset_icon_not_compromised="user.png",
                           asset_icon_compromised="ioc_user.png")
    get_by_value_or_create(db.session, AssetsType, "asset_name", asset_name="防火墙", asset_description="防火墙",
                           asset_icon_not_compromised="firewall.png", asset_icon_compromised="ioc_firewall.png")
    get_by_value_or_create(db.session, AssetsType, "asset_name", asset_name="Linux - 服务器",
                           asset_description="Linux服务器", asset_icon_not_compromised="server.png",
                           asset_icon_compromised="ioc_server.png")
    get_by_value_or_create(db.session, AssetsType, "asset_name", asset_name="Linux - 计算机",
                           asset_description="Linux 计算机", asset_icon_not_compromised="desktop.png",
                           asset_icon_compromised="ioc_desktop.png")
    get_by_value_or_create(db.session, AssetsType, "asset_name", asset_name="Linux 账户",
                           asset_description="Linux 账户", asset_icon_not_compromised="user.png",
                           asset_icon_compromised="ioc_user.png")
    get_by_value_or_create(db.session, AssetsType, "asset_name", asset_name="Mac - 计算机",
                           asset_description="Mac 计算机", asset_icon_not_compromised="desktop.png",
                           asset_icon_compromised="ioc_desktop.png")
    get_by_value_or_create(db.session, AssetsType, "asset_name", asset_name="电话 - Android",
                           asset_description="Android 电话", asset_icon_not_compromised="phone.png",
                           asset_icon_compromised="ioc_phone.png")
    get_by_value_or_create(db.session, AssetsType, "asset_name", asset_name="电话 - IOS",
                           asset_description="Apple 电话", asset_icon_not_compromised="phone.png",
                           asset_icon_compromised="ioc_phone.png")
    get_by_value_or_create(db.session, AssetsType, "asset_name", asset_name="Windows - 计算机",
                           asset_description="标准 Windows 计算机",
                           asset_icon_not_compromised="windows_desktop.png",
                           asset_icon_compromised="ioc_windows_desktop.png")
    get_by_value_or_create(db.session, AssetsType, "asset_name", asset_name="Windows - 服务器",
                           asset_description="标准 Windows 服务器", asset_icon_not_compromised="windows_server.png",
                           asset_icon_compromised="ioc_windows_server.png")
    get_by_value_or_create(db.session, AssetsType, "asset_name", asset_name="Windows - DC",
                           asset_description="域控", asset_icon_not_compromised="windows_server.png",
                           asset_icon_compromised="ioc_windows_server.png")
    get_by_value_or_create(db.session, AssetsType, "asset_name", asset_name="路由器", asset_description="路由器",
                           asset_icon_not_compromised="router.png", asset_icon_compromised="ioc_router.png")
    get_by_value_or_create(db.session, AssetsType, "asset_name", asset_name="交换机", asset_description="交换机",
                           asset_icon_not_compromised="switch.png", asset_icon_compromised="ioc_switch.png")
    get_by_value_or_create(db.session, AssetsType, "asset_name", asset_name="VPN", asset_description="VPN",
                           asset_icon_not_compromised="vpn.png", asset_icon_compromised="ioc_vpn.png")
    get_by_value_or_create(db.session, AssetsType, "asset_name", asset_name="WAF", asset_description="WAF",
                           asset_icon_not_compromised="firewall.png", asset_icon_compromised="ioc_firewall.png")
    get_by_value_or_create(db.session, AssetsType, "asset_name", asset_name="Windows 账户 - 本地",
                           asset_description="Windows 账户 - 本地", asset_icon_not_compromised="user.png",
                           asset_icon_compromised="ioc_user.png")
    get_by_value_or_create(db.session, AssetsType, "asset_name", asset_name="Windows 账户 - 本地 - 管理员",
                           asset_description="Windows 账户 - 本地 - 管理员", asset_icon_not_compromised="user.png",
                           asset_icon_compromised="ioc_user.png")
    get_by_value_or_create(db.session, AssetsType, "asset_name", asset_name="Windows 账户 - AD",
                           asset_description="Windows 账户 - AD", asset_icon_not_compromised="user.png",
                           asset_icon_compromised="ioc_user.png")
    get_by_value_or_create(db.session, AssetsType, "asset_name", asset_name="Windows 账户 - AD - 管理员",
                           asset_description="Windows 账户 - AD - 管理员", asset_icon_not_compromised="user.png",
                           asset_icon_compromised="ioc_user.png")
    get_by_value_or_create(db.session, AssetsType, "asset_name", asset_name="Windows 账户 - AD - krbtgt",
                           asset_description="Windows 账户 - AD - krbtgt", asset_icon_not_compromised="user.png",
                           asset_icon_compromised="ioc_user.png")
    get_by_value_or_create(db.session, AssetsType, "asset_name", asset_name="Windows Account - AD - Service",
                           asset_description="Windows 账户 - AD - krbtgt", asset_icon_not_compromised="user.png",
                           asset_icon_compromised="ioc_user.png")


def create_safe_client():
    """Creates a new Client object if it does not already exist.

    This function creates a new Client object with the specified client name
    and client description if it does not already exist in the database.

    """
    # Create a new Client object if it does not already exist
    client = get_or_create(db.session, Client,
                           name="示例客户")

    return client


def create_safe_auth_model():
    """Creates new Organisation, Group, and User objects if they do not already exist.

    This function creates a new Organisation object with the specified name and description,
    and creates new Group objects with the specified name, description, auto-follow status,
    auto-follow access level, and permissions if they do not already exist in the database.
    It also updates the attributes of the existing Group objects if they have changed.

    """
    # Create new Organisation object
    def_org = get_or_create(db.session, Organisation, org_name="默认组织",
                            org_description="默认组织")

    # Create new Administrator Group object
    try:
        gadm = get_or_create(db.session, Group, group_name="Administrators", group_description="管理员",
                             group_auto_follow=True, group_auto_follow_access_level=CaseAccessLevel.full_access.value,
                             group_permissions=ac_get_mask_full_permissions())

    except exc.IntegrityError:
        db.session.rollback()
        log.warning('Administrator group integrity error. Group permissions were probably changed. Updating.')
        gadm = Group.query.filter(
            Group.group_name == "Administrators"
        ).first()

    # Update Administrator Group object attributes
    if gadm.group_permissions != ac_get_mask_full_permissions():
        gadm.group_permissions = ac_get_mask_full_permissions()

    if gadm.group_auto_follow_access_level != CaseAccessLevel.full_access.value:
        gadm.group_auto_follow_access_level = CaseAccessLevel.full_access.value

    if gadm.group_auto_follow is not True:
        gadm.group_auto_follow = True

    db.session.commit()

    # Create new Analysts Group object
    try:
        ganalysts = get_or_create(db.session, Group, group_name="Analysts", group_description="分析师",
                                  group_auto_follow=False,
                                  group_auto_follow_access_level=CaseAccessLevel.full_access.value,
                                  group_permissions=ac_get_mask_analyst())

    except exc.IntegrityError:
        db.session.rollback()
        log.warning('Analysts group integrity error. Group permissions were probably changed. Updating.')
        ganalysts = get_group_by_name("Analysts")

    # Update Analysts Group object attributes
    if ganalysts.group_permissions != ac_get_mask_analyst():
        ganalysts.group_permissions = ac_get_mask_analyst()

    if ganalysts.group_auto_follow is not False:
        ganalysts.group_auto_follow = False

    if ganalysts.group_auto_follow_access_level != CaseAccessLevel.full_access.value:
        ganalysts.group_auto_follow_access_level = CaseAccessLevel.full_access.value

    db.session.commit()

    return def_org, gadm, ganalysts


def create_safe_admin(def_org, gadm):
    """Creates a new admin user if one does not already exist.

    This function creates a new admin user with the specified username, email, and password
    if one does not already exist in the database. If an admin user already exists, it updates
    the email address of the existing user if it has changed.

    """
    # Get admin username and email from app config
    admin_username = app.config.get('IRIS_ADM_USERNAME')
    if admin_username is None:
        admin_username = 'administrator'

    admin_email = app.config.get('IRIS_ADM_EMAIL')
    if admin_email is None:
        admin_email = 'administrator@localhost'

    # Check if admin user already exists
    user = User.query.filter(or_(
        User.user == admin_username,
        User.email == admin_email
    )).first()
    password = None

    if not user:
        # Generate a new password if one was not provided in the app config
        password = app.config.get('IRIS_ADM_PASSWORD')
        if password is None:
            password = ''.join(random.choices(string.printable[:-6], k=16))

        log.info(f'Creating first admin user with username "{admin_username}"')

        # Create new User object for admin user
        user = User(
            user=admin_username,
            name=admin_username,
            email=admin_email,
            password=bc.generate_password_hash(password.encode('utf8')).decode('utf8'),
            active=True
        )

        # Generate a new API key if one was not provided in the app config
        api_key = app.config.get('IRIS_ADM_API_KEY')
        if api_key is None:
            api_key = secrets.token_urlsafe(nbytes=64)

        user.api_key = api_key
        db.session.add(user)

        db.session.commit()

        # Add admin user to admin group and default organisation
        add_user_to_group(user_id=user.id, group_id=gadm.group_id)
        add_user_to_organisation(user_id=user.id, org_id=def_org.org_id)

        log.warning(f">>> Administrator password: {password}")

        db.session.commit()

    else:
        if not os.environ.get('IRIS_ADM_PASSWORD'):
            # Prevent leak of user set password in logs
            log.warning(">>> Administrator already exists")

        if user.email != admin_email:
            # Update email address of existing admin user if it has changed
            log.warning(f'Email of administrator will be updated via config to {admin_email}')
            user.email = admin_email
            db.session.commit()

    return user, password


def create_safe_case(user, client, groups):
    """Creates a new case if one does not already exist for the specified client.

    This function creates a new case with the specified name, description, SOC ID, user, and client
    if one does not already exist in the database for the specified client. It also adds the specified
    user and groups to the case with full access level.

    """
    # Check if a case already exists for the client
    case = Cases.query.filter(
        Cases.client_id == client.client_id
    ).first()

    if not case:
        # Create a new case for the client
        case = Cases(
            name="示例案例",
            description="这是一个示例.",
            soc_id="soc_id_demo",
            user=user,
            client_id=client.client_id
        )

        # Validate the case and save it to the database
        case.validate_on_build()
        case.save()

        db.session.commit()

    # Add the specified user and groups to the case with full access level
    for group in groups:
        add_case_access_to_group(group=group,
                                 cases_list=[case.case_id],
                                 access_level=CaseAccessLevel.full_access.value)
        ac_add_user_effective_access(users_list=[user.id],
                                     case_id=1,
                                     access_level=CaseAccessLevel.full_access.value)

    return case


def create_safe_report_types():
    """Creates new ReportType objects if they do not already exist.

    This function creates new ReportType objects with the specified names if they do not already
    exist in the database.

    """
    create_safe(db.session, ReportType, name="调查")
    create_safe(db.session, ReportType, name="活动")


def create_safe_attributes():
    """Creates new Attribute objects if they do not already exist.

    This function creates new Attribute objects with the specified display name, description,
    object type, and content if they do not already exist in the database.

    """
    create_safe_attr(db.session, attribute_display_name='IOC',
                     attribute_description='定义IOC默认属性', attribute_for='ioc',
                     attribute_content={})
    create_safe_attr(db.session, attribute_display_name='Events',
                     attribute_description='定义Event默认属性', attribute_for='event',
                     attribute_content={})
    create_safe_attr(db.session, attribute_display_name='Assets',
                     attribute_description='定义Asset默认属性', attribute_for='asset',
                     attribute_content={})
    create_safe_attr(db.session, attribute_display_name='Tasks',
                     attribute_description='定义Task默认属性', attribute_for='task',
                     attribute_content={})
    create_safe_attr(db.session, attribute_display_name='Notes',
                     attribute_description='定义Note默认属性', attribute_for='note',
                     attribute_content={})
    create_safe_attr(db.session, attribute_display_name='Evidences',
                     attribute_description='定义Evidences默认属性', attribute_for='evidence',
                     attribute_content={})
    create_safe_attr(db.session, attribute_display_name='Cases',
                     attribute_description='定义Case默认属性', attribute_for='case',
                     attribute_content={})
    create_safe_attr(db.session, attribute_display_name='Customers',
                     attribute_description='定义Customer默认属性', attribute_for='client',
                     attribute_content={})


def create_safe_ioctypes():
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="AS",
                        type_description="自治系统", type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="aba-rtn",
                        type_description="ABA 路由转接号码",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="账户",
                        type_description="任何类型的账户",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="匿名",
                        type_description="匿名值 - 通过关系描述匿名对象",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="附件",
                        type_description="外部信息附件",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="authentihash",
                        type_description="可执行文件认证代码签名哈希", type_taxonomy="",
                        type_validation_regex="[a-f0-9]{64}", type_validation_expect="64 hexadecimal characters"
                        )
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="布尔值",
                        type_description="	布尔值 -在对象内使用",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="btc",
                        type_description="比特币钱包地址", type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="活动-id",
                        type_description="关联活动ID",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="活动-名称",
                        type_description="关联活动名称",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="cdhash",
                        type_description="苹果代码目录散列，用于识别代码签名的 Mach-O 可执行文件",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="chrome-扩展-id",
                        type_description="Chrome 扩展 id",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="社区-id",
                        type_description="社区 ID 流量散列算法，将多个流量监控器映射为共同的流量 ID",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="cookie",
                        type_description="通常存储在用户网络客户端上的 HTTP cookie.这可能包括认证 cookie 或会话 cookie.",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="dash",
                        type_description="Dash地址", type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="日期时间",
                        type_description="ISO 8601 格式的日期时间",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="dkim",
                        type_description="DKIM公钥", type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="dkim-签名",
                        type_description="DKIM签名", type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="dns-soa-email",
                        type_description="RFC1035 规定，DNS 区域应有一个 SOA（权威声明）记录，其中包含一个电子邮件地址，可与该域的 PoC 取得联系。这有时可用于不同域名之间的归属/链接，即使受到 whois 隐私保护也是如此。",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="域名",
                        type_description="恶意软件中使用的域名",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="域名|ip",
                        type_description="域名及其 IP 地址（在 DNS 解析中找到），用 | 分隔",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="email",
                        type_description="电子邮件地址", type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="email-附件",
                        type_description="电子邮件附件的文件名。", type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="email-正文",
                        type_description="Email正文", type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="email-dst",
                        type_description="目的电子邮件地址。在描述电子邮件时用于描述收件人。",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="email-dst-显示名称",
                        type_description="Email收件人显示名称", type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="email-头部",
                        type_description="Email头部", type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="email-消息-id",
                        type_description="电子邮件消息ID",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="email-mime-边界",
                        type_description="在多部分电子邮件中分隔各部分的电子邮件 MIME 边界",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="email-reply-to",
                        type_description="电子邮件回复头",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="email-src",
                        type_description="源电子邮件地址。在描述电子邮件时用于描述发件人。",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="email-src-显示名称",
                        type_description="电子邮件来源显示名称",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="email-主题",
                        type_description="电子邮件的主题",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="email-索引标题",
                        type_description="电子邮件主题索引标题",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="email-x-mailer",
                        type_description="电子邮件 x-mailer 标头",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="favicon-mmh3",
                        type_description="favicon-mmh3 是 Shodan 中使用的 favicon 的 murmur3 哈希值。",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="文件名",
                        type_description="文件名", type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="文件名-模式",
                        type_description="文件名中的模式",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="文件名|authentihash",
                        type_description="以 md5 格式表示的校验和",
                        type_taxonomy="",
                        type_validation_regex='.+\|[a-f0-9]{64}',
                        type_validation_expect="filename|64 hexadecimal characters")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="文件名|impfuzzy",
                        type_description="导入fuzzy哈希 - 基于导入样本生成的fuzzy哈希",
                        type_taxonomy="", )
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="文件名|imphash",
                        type_description="导入哈希 - 根据样本中的导入数据创建的哈希值。",
                        type_taxonomy="",
                        type_validation_regex='.+\|[a-f0-9]{32}',
                        type_validation_expect="filename|32 hexadecimal characters")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="文件名|md5",
                        type_description="用 | 分隔的文件名和 md5 哈希值", type_taxonomy="",
                        type_validation_regex='.+\|[a-f0-9]{32}',
                        type_validation_expect="filename|32 hexadecimal characters")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="文件名|pehash",
                        type_description="用 | 分隔的文件名和 PEhash", type_taxonomy="",
                        type_validation_regex='.+\|[a-f0-9]{40}',
                        type_validation_expect="filename|40 hexadecimal characters")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="文件名|sha1",
                        type_description="用 | 分隔的文件名和 sha1 哈希值", type_taxonomy="",
                        type_validation_regex='.+\|[a-f0-9]{40}',
                        type_validation_expect="filename|40 hexadecimal characters")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="文件名|sha224",
                        type_description="用 | 分隔的文件名和 sha-224 哈希值", type_taxonomy="",
                        type_validation_regex='.+\|[a-f0-9]{56}',
                        type_validation_expect="filename|56 hexadecimal characters")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="文件名|sha256",
                        type_description="用 | 分隔的文件名和 sha256 哈希值", type_taxonomy="",
                        type_validation_regex='.+\|[a-f0-9]{64}',
                        type_validation_expect="filename|64 hexadecimal characters")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="文件名|sha3-224",
                        type_description="用 | 分隔的文件名和 sha3-224 哈希值", type_taxonomy="",
                        type_validation_regex='.+\|[a-f0-9]{56}',
                        type_validation_expect="filename|56 hexadecimal characters")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="文件名|sha3-256",
                        type_description="用 | 分隔的文件名和 sha3-256 哈希值", type_taxonomy="",
                        type_validation_regex='.+\|[a-f0-9]{64}',
                        type_validation_expect="filename|64 hexadecimal characters")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="文件名|sha3-384",
                        type_description="用 | 分隔的文件名和 sha3-384 哈希值", type_taxonomy="",
                        type_validation_regex='.+\|[a-f0-9]{96}',
                        type_validation_expect="filename|96 hexadecimal characters")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="文件名|sha3-512",
                        type_description="用 | 分隔的文件名和 sha3-512 哈希值", type_taxonomy="",
                        type_validation_regex='.+\|[a-f0-9]{128}',
                        type_validation_expect="filename|128 hexadecimal characters")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="文件名|sha384",
                        type_description="用 | 分隔的文件名和 sha-384哈希值", type_taxonomy="",
                        type_validation_regex='.+\|[a-f0-9]{96}',
                        type_validation_expect="filename|96 hexadecimal characters")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="文件名|sha512",
                        type_description="文件名和用 | 分隔的 sha-512 哈希值", type_taxonomy="",
                        type_validation_regex='.+\|[a-f0-9]{128}',
                        type_validation_expect="filename|128 hexadecimal characters")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="文件名|sha512/224",
                        type_description="文件名和用 | 分隔的 sha-512/224 哈希值", type_taxonomy="",
                        type_validation_regex='.+\|[a-f0-9]{56}',
                        type_validation_expect="filename|56 hexadecimal characters")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="文件名|sha512/256",
                        type_description="文件名和用 | 分隔的 sha-512/256 哈希值", type_taxonomy="",
                        type_validation_regex='.+\|[a-f0-9]{64}',
                        type_validation_expect="filename|64 hexadecimal characters")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="文件名|ssdeep",
                        type_description="ssdeep格式的校验和",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="文件名|tlsh",
                        type_description="用 | 分隔的文件名和趋势科技敏感位置哈希值",
                        type_taxonomy="",
                        type_validation_regex='.+\|t?[a-f0-9]{35,}',
                        type_validation_expect="filename|at least 35 hexadecimal characters, optionally starting with t1 instead of hexadecimal characters"
                        )
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="文件名|vhash",
                        type_description="用 | 分隔的文件名和 VirusTotal 哈希值", type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="名字",
                        type_description="自然人的名字",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="float",
                        type_description="浮点数值.", type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="全名",
                        type_description="自然人的全名",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="gene",
                        type_description="GENE - Go Evtx sigNature Engine",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="git-commit-id",
                        type_description="git 提交 ID.", type_taxonomy="",
                        type_validation_regex="[a-f0-9]{40}", type_validation_expect="40 hexadecimal characters")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="github-组织",
                        type_description="一个 github 组织",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="github-repository",
                        type_description="一个 github 仓库",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="github-用户名",
                        type_description="github 用户名",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="hassh-md5",
                        type_description="hassh 是一种网络指纹标准，可用于识别特定的客户端 SSH 实现。指纹可以以 MD5 指纹的形式轻松存储、搜索和共享.",
                        type_taxonomy="",
                        type_validation_regex="[a-f0-9]{32}", type_validation_expect="32 hexadecimal characters")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="hasshserver-md5",
                        type_description="hasshServer 是一种网络指纹标准，可用于识别特定的服务器 SSH 实现。指纹可以以 MD5 指纹的形式轻松存储、搜索和共享.",
                        type_taxonomy="",
                        type_validation_regex="[a-f0-9]{32}", type_validation_expect="32 hexadecimal characters")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="hex",
                        type_description="十六进制格式的数值",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="主机名",
                        type_description="攻击者的完整主机/域名",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="主机名|端口",
                        type_description="用 | 分隔的主机名和端口号", type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="http-方法",
                        type_description="恶意软件使用的 HTTP 方法（如 POST、GET...）.", type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="iban",
                        type_description="International Bank Account Number",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="身份证号码",
                        type_description="身份证号码",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="impfuzzy",
                        type_description="便携式可执行文件格式导入表的模糊哈希值", type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="imphash",
                        type_description="导入哈希值 - 根据样本中的导入创建的哈希值。",
                        type_taxonomy="",
                        type_validation_regex="[a-f0-9]{32}", type_validation_expect="32 hexadecimal characters")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="ip-any",
                        type_description="攻击者或 C&C 服务器的源 IP 地址或目标 IP 地址",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="ip-dst",
                        type_description="攻击者或 C&C 服务器的目标 IP 地址", type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="ip-dst|port",
                        type_description="用 | 分隔的 IP 目的地和端口号", type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="ip-src",
                        type_description="攻击者的源 IP 地址",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="ip-src|port",
                        type_description="用 | 分隔的 IP 源和端口号", type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="ja3-fingerprint-md5",
                        type_description="JA3 是一种创建 SSL/TLS 客户端指纹的方法，可以在任何平台上轻松生成，并可轻松共享，以获取威胁情报。",
                        type_taxonomy="",
                        type_validation_regex="[a-f0-9]{32}", type_validation_expect="32 hexadecimal characters")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="jabber-id",
                        type_description="Jabber ID", type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="jarm-指纹",
                        type_description="JARM 是一种创建 SSL/TLS 服务器指纹的方法。", type_taxonomy="",
                        type_validation_regex="[a-f0-9]{62}", type_validation_expect="62 hexadecimal characters")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="kusto-query",
                        type_description="Kusto 查询 - Microsoft Azure 的 Kusto 是一项用于存储和运行大数据交互式分析的服务。",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="链接",
                        type_description="链接到外部信息",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="mac-address",
                        type_description="Mac 地址", type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="mac-eui-64",
                        type_description="Mac EUI-64 地址", type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="恶意软件-样本",
                        type_description="包含恶意软件样本的加密附件", type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="恶意软件-类型",
                        type_description="恶意软件类型", type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="md5",
                        type_description="md5 格式的校验和", type_taxonomy="",
                        type_validation_regex="[a-f0-9]{32}", type_validation_expect="32 hexadecimal characters")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="中间名",
                        type_description="自然人的中间名",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="mime-type",
                        type_description="媒体类型（也称 MIME 类型和内容类型）是互联网上传输的文件格式和格式内容的两部分标识符",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="mobile-application-id",
                        type_description="移动应用程序的应用程序 ID", type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="mutex",
                        type_description="Mutex，使用格式 \BaseNamedObjects<Mutex>", type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="命名管道",
                        type_description="命名管道，使用 .\pipe<PipeName> 格式", type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="other",
                        type_description="其他属性", type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="file-path",
                        type_description="文件路径", type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="pattern-in-file",
                        type_description="文件中可识别恶意软件的模式", type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="pattern-in-memory",
                        type_description="可识别恶意软件的内存转储模式", type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="pattern-in-traffic",
                        type_description="可识别恶意软件的网络流量模式", type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="pdb",
                        type_description="微软程序数据库 (PDB) 路径信息", type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="pehash",
                        type_description="PEhash - 根据 PE 可执行文件的某些片段计算出的哈希值",
                        type_taxonomy="",
                        type_validation_regex="[a-f0-9]{40}", type_validation_expect="40 hexadecimal characters")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="pgp-private-key",
                        type_description="PGP 私钥",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="pgp-public-key",
                        type_description="PGP 公钥", type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="phone-number",
                        type_description="电话号码", type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="port",
                        type_description="端口号", type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="process-state",
                        type_description="进程的状态", type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="prtn",
                        type_description="特费电话号码",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="regkey",
                        type_description="注册表键或值", type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="regkey|value",
                        type_description="注册表键 + 值用 | 分隔的数据",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="sha1",
                        type_description="sha1 格式的校验和", type_taxonomy="",
                        type_validation_regex="[a-f0-9]{40}", type_validation_expect="40 hexadecimal characters")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="sha224",
                        type_description="sha-224 格式的校验和",
                        type_taxonomy="",
                        type_validation_regex="[a-f0-9]{56}", type_validation_expect="56 hexadecimal characters")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="sha256",
                        type_description="sha256格式的校验和",
                        type_taxonomy="",
                        type_validation_regex="[a-f0-9]{64}", type_validation_expect="64 hexadecimal characters")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="sha3-224",
                        type_description="sha3-224格式的校验和",
                        type_taxonomy="",
                        type_validation_regex="[a-f0-9]{56}", type_validation_expect="56 hexadecimal characters")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="sha3-256",
                        type_description="sha3-256格式的校验和",
                        type_taxonomy="",
                        type_validation_regex="[a-f0-9]{64}", type_validation_expect="64 hexadecimal characters")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="sha3-384",
                        type_description="sha3-384格式的校验和",
                        type_taxonomy="",
                        type_validation_regex="[a-f0-9]{96}", type_validation_expect="96 hexadecimal characters")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="sha3-512",
                        type_description="sha3-512格式的校验和",
                        type_taxonomy="",
                        type_validation_regex="[a-f0-9]{128}", type_validation_expect="128 hexadecimal characters")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="sha384",
                        type_description="sha-384格式的校验和",
                        type_taxonomy="",
                        type_validation_regex="[a-f0-9]{96}", type_validation_expect="96 hexadecimal characters")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="sha512",
                        type_description="sha-512格式的校验和",
                        type_taxonomy="",
                        type_validation_regex="[a-f0-9]{128}", type_validation_expect="128 hexadecimal characters")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="sha512/224",
                        type_description="sha-512/224格式的校验和",
                        type_taxonomy="",
                        type_validation_regex="[a-f0-9]{56}", type_validation_expect="56 hexadecimal characters")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="sha512/256",
                        type_description="sha-512/256格式的校验和",
                        type_taxonomy="",
                        type_validation_regex="[a-f0-9]{64}", type_validation_expect="64 hexadecimal characters")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="sigma",
                        type_description="Sigma - SIEM 系统通用签名格式", type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="size-in-bytes",
                        type_description="大小以字节表示",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="snort",
                        type_description="Snort 规则格式的 IDS 规则",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="ssdeep",
                        type_description="ssdeep格式的校验和",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="ssh-fingerprint",
                        type_description="SSH 密钥材料的指纹",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="stix2-pattern",
                        type_description="STIX 2 模式", type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="target-email",
                        type_description="攻击目标电子邮件",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="target-external",
                        type_description="受此攻击影响的外部目标组织", type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="target-location",
                        type_description="攻击目标物理位置", type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="target-machine",
                        type_description="攻击目标机器名称",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="target-org",
                        type_description="攻击目标部门或组织", type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="target-user",
                        type_description="攻击目标用户名",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="telfhash",
                        type_description="telfhash 是 ELF 文件的符号散列，就像 imphash 是 PE 文件的导入散列一样.",
                        type_taxonomy="",
                        type_validation_regex="[a-f0-9]{70}", type_validation_expect="70 hexadecimal characters")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="text",
                        type_description="姓名、身份证或参考资料", type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="threat-actor",
                        type_description="识别威胁行为者的字符串",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="tlsh",
                        type_description="趋势科技位置敏感散列格式的校验和",
                        type_taxonomy="",
                        type_validation_regex="^t?[a-f0-9]{35,}",
                        type_validation_expect="at least 35 hexadecimal characters, optionally starting with t1 instead of hexadecimal characters")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="travel-details",
                        type_description="旅行详情", type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="twitter-id",
                        type_description="Twitter ID", type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="uri",
                        type_description="统一资源标识符", type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="url", type_description="url",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="user-agent",
                        type_description="恶意软件在 HTTP 请求中使用的用户代理.", type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="vhash",
                        type_description="VirusTotal 校验和", type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="漏洞",
                        type_description="对漏洞利用中使用的漏洞的引用", type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="弱点",
                        type_description="利用漏洞时使用的弱点", type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="whois-creation-date",
                        type_description="从 WHOIS 信息中获取的域名创建日期.",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="whois-registrant-email",
                        type_description="从 WHOIS 信息中获取的域名注册人的电子邮件.",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="whois-registrant-name",
                        type_description="从 WHOIS 信息中获取的域名注册人姓名.",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="whois-registrant-org",
                        type_description="从 WHOIS 信息中获取的域名注册人的组织.",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="whois-registrant-phone",
                        type_description="域名注册人的电话号码，从 WHOIS 信息中获取.",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="whois-registrar",
                        type_description="从 WHOIS 信息中获得的域名注册商.",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="windows-scheduled-task",
                        type_description="windows 中的计划任务",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="windows-service-displayname",
                        type_description="windows服务的显示名称，不要与windows服务名称混淆。应用程序通常会将此名称显示为应用程序中的服务名称.",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="windows-service-name",
                        type_description="Windows 服务名称。这是 Windows 内部使用的名称。不要与 windows-service-显示名称混淆.",
                        type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="x509-fingerprint-md5",
                        type_description="MD5 格式的 X509 指纹", type_taxonomy="",
                        type_validation_regex="[a-f0-9]{32}", type_validation_expect="32 hexadecimal characters")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="x509-fingerprint-sha1",
                        type_description="SHA-1 格式的 X509 指纹", type_taxonomy="",
                        type_validation_regex="[a-f0-9]{40}", type_validation_expect="40 hexadecimal characters")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="x509-fingerprint-sha256",
                        type_description="SHA-256 格式的 X509 指纹", type_taxonomy="",
                        type_validation_regex="[a-f0-9]{64}", type_validation_expect="64 hexadecimal characters")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="xmr",
                        type_description="门罗币地址", type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="yara",
                        type_description="Yara签名", type_taxonomy="")
    create_safe_limited(db.session, IocType, ["type_name", "type_description"], type_name="zeek",
                        type_description="Zeek 规则格式的 NIDS 规则",
                        type_taxonomy="")


def create_safe_os_types():
    create_safe(db.session, OsType, type_name="Windows")
    create_safe(db.session, OsType, type_name="Linux")
    create_safe(db.session, OsType, type_name="AIX")
    create_safe(db.session, OsType, type_name="MacOS")
    create_safe(db.session, OsType, type_name="Apple iOS")
    create_safe(db.session, OsType, type_name="Cisco iOS")
    create_safe(db.session, OsType, type_name="Android")


def create_safe_tlp():
    create_safe(db.session, Tlp, tlp_name="red", tlp_bscolor="danger")
    create_safe(db.session, Tlp, tlp_name="amber", tlp_bscolor="warning")
    create_safe(db.session, Tlp, tlp_name="green", tlp_bscolor="success")
    create_safe(db.session, Tlp, tlp_name="clear", tlp_bscolor="black")
    create_safe(db.session, Tlp, tlp_name="amber+strict", tlp_bscolor="warning")


def create_safe_server_settings():
    if not ServerSettings.query.count():
        create_safe(db.session, ServerSettings,
                    http_proxy="", https_proxy="", prevent_post_mod_repush=False,
                    prevent_post_objects_repush=False,
                    password_policy_min_length="12", password_policy_upper_case=True,
                    password_policy_lower_case=True, password_policy_digit=True,
                    password_policy_special_chars="")


def register_modules_pipelines():
    modules = IrisModule.query.with_entities(
        IrisModule.module_name,
        IrisModule.module_config
    ).filter(
        IrisModule.has_pipeline == True
    ).all()

    for module in modules:
        module = module[0]
        inst, _ = instantiate_module_from_name(module)
        if not inst:
            continue

        inst.internal_configure(celery_decorator=celery.task,
                                evidence_storage=None,
                                mod_web_config=module[1])
        status = inst.get_tasks_for_registration()
        if status.is_failure():
            log.warning("Failed getting tasks for module {}".format(module))
            continue

        tasks = status.get_data()
        for task in tasks:
            celery.register_task(task)


def register_default_modules():
    modules = ['iris_vt_module', 'iris_misp_module', 'iris_check_module',
               'iris_webhooks_module', 'iris_intelowl_module']

    for module_name in modules:
        class_, _ = instantiate_module_from_name(module_name)
        is_ready, logs = check_module_health(class_)

        if not is_ready:
            log.info("Attempted to initiate {mod}. Got {err}".format(mod=module_name, err=",".join(logs)))
            return False

        module, logs = register_module(module_name)
        if module is None:
            log.info("Attempted to add {mod}. Got {err}".format(mod=module_name, err=logs))

        else:
            iris_module_disable_by_id(module.id)
            log.info('Successfully registered {mod}'.format(mod=module_name))


def custom_assets_symlinks():
    try:

        source_paths = glob.glob(os.path.join(app.config['ASSET_STORE_PATH'], "*"))

        for store_fullpath in source_paths:

            filename = store_fullpath.split(os.path.sep)[-1]
            show_fullpath = os.path.join(app.config['APP_PATH'], 'app',
                                         app.config['ASSET_SHOW_PATH'].strip(os.path.sep), filename)
            if not os.path.islink(show_fullpath):
                os.symlink(store_fullpath, show_fullpath)
                log.info(f"Created assets img symlink {store_fullpath} -> {show_fullpath}")

    except Exception as e:
        log.error(f"Error: {e}")
