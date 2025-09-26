# Copyright Materialize, Inc. and contributors. All rights reserved.
#
# Use of this software is governed by the Business Source License
# included in the LICENSE file at the root of this repository.
#
# As of the Change Date specified in that file, in accordance with
# the Business Source License, use of this software will be governed
# by the Apache License, Version 2.0.

"""
Tests for self-managed password authentication.
"""

from textwrap import dedent

from materialize import buildkite
from materialize.mzcompose import get_default_system_parameters
from materialize.mzcompose.composition import Composition, Service
from materialize.mzcompose.services.materialized import (
    DeploymentStatus,
    Materialized,
)
from materialize.mzcompose.services.postgres import (
    CockroachOrPostgresMetadata,
    Postgres,
)
from materialize.mzcompose.services.testdrive import Testdrive
from materialize.version_list import fetch_self_managed_versions

DEFAULT_TIMEOUT = "300s"

SYSTEM_PARAMETER_DEFAULTS = get_default_system_parameters()

MATERIALIZED_ENVIRONMENT_EXTRA = [
    "MZ_LISTENERS_CONFIG_PATH=/listener_configs/password.json",
    "MZ_EXTERNAL_LOGIN_PASSWORD_MZ_SYSTEM=password",
]

SERVICES = [
    Postgres(),
    CockroachOrPostgresMetadata(),
    Materialized(
        name="mz_old",
        sanity_restart=False,
        deploy_generation=0,
        system_parameter_defaults=SYSTEM_PARAMETER_DEFAULTS,
        external_metadata_store=True,
        environment_extra=MATERIALIZED_ENVIRONMENT_EXTRA,
    ),
    Materialized(
        name="mz_new",
        sanity_restart=False,
        deploy_generation=1,
        system_parameter_defaults=SYSTEM_PARAMETER_DEFAULTS,
        restart="on-failure",
        external_metadata_store=True,
        environment_extra=MATERIALIZED_ENVIRONMENT_EXTRA,
    ),
    Testdrive(
        materialize_url="postgres://mz_system:password@mz_old:6875",
        # Set the internal URL to the same as the external URL since password auth disables the internal port
        materialize_url_internal="postgres://mz_system:password@mz_old:6875",
        mz_service="mz_old",
        no_reset=True,
        seed=1,
        default_timeout=DEFAULT_TIMEOUT,
    ),
]


def workflow_default(c: Composition) -> None:
    workflow_self_managed_v_25_2_upgrade_oldest_to_latest_patch_release(c)


def verify_password_auth(c: Composition) -> None:
    c.testdrive(
        dedent(
            f"""
            > SELECT * FROM db1.schema1.t1
            c
            ----
            """
        )
    )


def workflow_self_managed_v_25_2_upgrade_oldest_to_latest_patch_release(
    c: Composition,
) -> None:
    """
    Test upgrading from the oldest v25.2 patch release to the latest v25.2 patch release, verifying that password
    authentication continues to work properly throughout the upgrade process.
    """
    c.down(destroy_volumes=True)

    self_managed_versions = fetch_self_managed_versions()
    v25_2_versions = sorted(
        [
            v.version
            for v in self_managed_versions
            if v.helm_version.major == 25 and v.helm_version.minor == 2
        ]
    )
    oldest_v25_2 = v25_2_versions[0]
    latest_v25_2 = v25_2_versions[-1]

    print(oldest_v25_2)
    print(latest_v25_2)

    c.override(
        Materialized(
            name="mz_old",
            image=f"materialize/materialized:{oldest_v25_2}",
        ),
        Materialized(
            name="mz_new",
            image=f"materialize/materialized:{latest_v25_2}",
        ),
    )

    c.up(
        "mz_old",
        Service("testdrive", idle=True),
    )

    print("2")

    # Setup
    c.testdrive(
        dedent(
            f"""
        > CREATE DATABASE db1
        > SET DATABASE = db1
        > CREATE SCHEMA schema1
        > SET SCHEMA = schema1
        > CREATE ROLE user1 WITH LOGIN PASSWORD 'password'
        > CREATE TABLE t1 (c int)
        """
        )
    )
    print("3")
    with c.override(
        Testdrive(
            materialize_url="postgres://user1:password@mz_old:6875",
        )
    ):
        c.up(Service("testdrive", idle=True))
        verify_password_auth(c)
    print("4")
    # Start new Materialize in a new deploy generation and upgrade
    c.up("mz_new")
    c.await_mz_deployment_status(DeploymentStatus.READY_TO_PROMOTE, "mz_new")
    c.promote_mz("mz_new")
    c.await_mz_deployment_status(DeploymentStatus.IS_LEADER, "mz_new")

    # Verify that password auth continues to work
    with c.override(
        Testdrive(
            materialize_url="postgres://materialize@mz_new:6875",
            mz_service="mz_new",
        )
    ):
        verify_password_auth(c)
